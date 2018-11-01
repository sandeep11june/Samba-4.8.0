/*
 * Copyright (C) Ralph Boehme 2017
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 */
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include "includes.h"
#include "smbd/proto.h"
#include "libcli/security/security_descriptor.h"
#include "libcli/security/security_token.h"
#include "nfs4_acls.h"
#include "nfs4acl_xattr.h"


#define OVERFLOW_CHECK(val1, val2) ((val1) + (val2) < (val1))

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

#ifdef HAVE_RPC_XDR_H
/* <rpc/xdr.h> uses TRUE and FALSE */
#ifdef TRUE
#undef TRUE
#endif

#ifdef FALSE
#undef FALSE
#endif

#include <rpc/xdr.h>
#include "nfs41acl.h"
#include "nfs4acl_xattr_xdr.h"

static unsigned nfs40acl_get_naces(nfsacl40 *nacl40)
{
	return nacl40->na40_aces.na40_aces_len;
}

static void nfs40acl_set_naces(nfsacl40 *nacl40, unsigned naces)
{
	nacl40->na40_aces.na40_aces_len = naces;
}

static nfsace40 *nfs40acl_get_ace(nfsacl40 *nacl40, size_t n)
{
	return &nacl40->na40_aces.na40_aces_val[n];
}

static unsigned nfs4acl_get_naces(nfsacl41 *nacl)
{
	return nacl->na41_aces.na41_aces_len;
}

static void nfs4acl_set_naces(nfsacl41 *nacl, unsigned naces)
{
	nacl->na41_aces.na41_aces_len = naces;
}

static unsigned nfs4acl_get_flags(nfsacl41 *nacl)
{
	return nacl->na41_flag;
}

static void nfs4acl_set_flags(nfsacl41 *nacl, unsigned flags)
{
	nacl->na41_flag = flags;
}

static size_t nfs40acl_get_xdrblob_size(nfsacl40 *nacl40)
{
	size_t acl_size;
	size_t aces_size;
	size_t identifiers_size;
	unsigned int i;

	unsigned naces = nfs40acl_get_naces(nacl40);

	/* ACE Structure minus actual identifier strings */
	struct nfsace40_size {
		acetype4 type;
		aceflag4 flag;
		acemask4 access_mask;
		u_int who_length;
	};

	/* ACL Size: Size of (ACE Count) +
	 * ACE Count * (Size of nfsace40_size) +
	 * Cumulative Length of Identifiers strings
	 */
	acl_size = sizeof(u_int);

	if (naces > NFS4ACL_XDR_MAX_ACES) {
		DBG_ERR("Too many ACEs: %u", naces);
		return 0;
	}

	aces_size = naces * sizeof(struct nfsace40_size);

	if(OVERFLOW_CHECK(acl_size, aces_size)) {
		DBG_ERR("Integer Overflow error\n");
		return 0;
	}
	acl_size += aces_size;

	DBG_DEBUG("aces_size: %ld\n", aces_size);

	identifiers_size = 0;
	for (i = 0;  i < naces; i++) {
		nfsace40 *nace40 = nfs40acl_get_ace(nacl40, i);
		size_t id_size = nace40->who.utf8string_len;
		/* UTf-8 identifier strings are aligned */
		if (nace40->who.utf8string_len % 4) {
			int alignment = (4 - (nace40->who.utf8string_len % 4));
			if (OVERFLOW_CHECK(id_size, alignment)) {
				DBG_ERR("Integer Overflow error\n");
				return 0;
			}
			id_size += alignment;
		}
		DBG_DEBUG("identifier[%d] size: %ld\n", i, id_size);

		if (OVERFLOW_CHECK(identifiers_size, id_size)) {
			DBG_ERR("Integer Overflow error\n");
			return 0;
		}
		identifiers_size += id_size;
	}

	DBG_DEBUG("total identifiers_size: %ld\n", identifiers_size);
	if (OVERFLOW_CHECK(acl_size, identifiers_size)) {
		DBG_ERR("Integer Overflow error\n");
		return 0;
	}
	acl_size += identifiers_size;

	DBG_DEBUG("acl_size: %ld\n", acl_size);
	return acl_size;
}



static size_t nfs4acl_get_xdrblob_size(nfsacl41 *nacl)
{
	size_t acl_size;
	size_t aces_size;
	unsigned naces = nfs4acl_get_naces(nacl);

	acl_size = sizeof(aclflag4) + sizeof(unsigned);

	if (naces > NFS4ACL_XDR_MAX_ACES) {
		DBG_ERR("Too many ACEs: %u", naces);
		return 0;
	}

	aces_size = naces * sizeof(struct nfsace4);
	if (acl_size + aces_size < acl_size) {
		return 0;
	}
	acl_size += aces_size;

	return acl_size;
}

static size_t nfs40acl_get_xdrblob_naces(size_t _blobsize)
{
	/* Not required */
	return -1;
}

static size_t nfs4acl_get_xdrblob_naces(size_t _blobsize)
{
	size_t blobsize = _blobsize;

	blobsize -= sizeof(aclflag4);
	blobsize -= sizeof(unsigned);
	if (blobsize > _blobsize) {
		return 0;
	}
	return (blobsize / sizeof(struct nfsace4));
}

static nfsacl40 *nfs40acl_alloc(TALLOC_CTX *mem_ctx, unsigned naces)
{

	size_t acl_size = 0, aces_size = 0;
	nfsacl40 *nacl40 = NULL;

	acl_size = sizeof(nfsacl40);

	if (naces > NFS4ACL_XDR_MAX_ACES) {
		DBG_ERR("Too many ACEs: %d\n", naces);
		return NULL;
	}

	if (OVERFLOW_CHECK(aces_size, (naces * sizeof(struct nfsace40)))) {
		DBG_ERR("Integer Overflow error\n");
		return NULL;
	}
	aces_size += (naces * sizeof(struct nfsace40));

	if (OVERFLOW_CHECK(acl_size, aces_size)) {
		DBG_ERR("Integer Overflow error\n");
		return NULL;
	}
	acl_size += aces_size;

	nacl40 = talloc_zero_size(mem_ctx, acl_size);
	if (nacl40 == NULL) {
		DBG_ERR("talloc_zero_size failed\n");
		return NULL;
	}

	nfs40acl_set_naces(nacl40, naces);
	nacl40->na40_aces.na40_aces_val =
		(nfsace40 *)((char *)nacl40 + sizeof(nfsacl40));

	return nacl40;
}


static nfsacl41 *nfs4acl_alloc(TALLOC_CTX *mem_ctx, unsigned naces)
{
	size_t acl_size = sizeof(nfsacl41) + (naces * sizeof(struct nfsace4));
	nfsacl41 *nacl = NULL;

	if (naces > NFS4ACL_XDR_MAX_ACES) {
		DBG_ERR("Too many ACEs: %d\n", naces);
		return NULL;
	}

	nacl = talloc_zero_size(mem_ctx, acl_size);
	if (nacl == NULL) {
		DBG_ERR("talloc_zero_size failed\n");
		return NULL;
	}

	nfs4acl_set_naces(nacl, naces);
	nacl->na41_aces.na41_aces_val =
		(nfsace4 *)((char *)nacl + sizeof(nfsacl41));

	return nacl;
}

static nfsace4 *nfs4acl_get_ace(nfsacl41 *nacl, size_t n)
{
	return &nacl->na41_aces.na41_aces_val[n];
}

static unsigned smb4acl_to_nfs4acl_flags(uint16_t smb4acl_flags)
{
	unsigned nfs4acl_flags = 0;

	if (smb4acl_flags & SEC_DESC_DACL_AUTO_INHERITED) {
		nfs4acl_flags |= ACL4_AUTO_INHERIT;
	}
	if (smb4acl_flags & SEC_DESC_DACL_PROTECTED) {
		nfs4acl_flags |= ACL4_PROTECTED;
	}
	if (smb4acl_flags & SEC_DESC_DACL_DEFAULTED) {
		nfs4acl_flags |= ACL4_DEFAULTED;
	}

	return nfs4acl_flags;
}

static bool create_special_id(TALLOC_CTX *mem_ctx, nfsace40 *nace40, char *id)
{
	int len = strlen(id);
	nace40->who.utf8string_val = talloc_memdup(mem_ctx, id, len);
	nace40->who.utf8string_len = len;
	if (nace40->who.utf8string_val == NULL) {
		DBG_ERR("Error talloc_memdup for %d bytes\n", len);
		return false;
	}
	return true;
}
static bool create_numeric_id(TALLOC_CTX *mem_ctx, nfsace40 *nace40, uid_t id)
{
	int id_len = snprintf( NULL, 0, "%ld", id);
	char* strid = talloc_size(mem_ctx, id_len + 1);
	if (!strid) {
		DBG_ERR("Error allocating %d bytes\n", id_len + 1);
		return false;
	}
	snprintf(strid, id_len + 1, "%ld", id);
	nace40->who.utf8string_val = talloc_memdup (mem_ctx, strid, id_len);
	nace40->who.utf8string_len = id_len;
	TALLOC_FREE(strid);
	if (nace40->who.utf8string_val == NULL) {
		DBG_ERR("Error talloc_memdup for %d bytes\n", id_len);
		return false;
	}
	return true;
}

static bool smb4acl_to_nfs40acl(vfs_handle_struct *handle,
			       TALLOC_CTX *mem_ctx,
			       struct SMB4ACL_T *smb4acl,
			       nfsacl40 **_nacl40)
{
	struct nfs4acl_config *config = NULL;
	struct SMB4ACE_T *smb4ace = NULL;
	size_t smb4naces = 0;
	nfsacl40 *nacl40 = NULL;
	uint16_t smb4acl_flags = 0;
	unsigned nacl_flags = 0;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct nfs4acl_config,
				return false);

	smb4naces = smb_get_naces(smb4acl);
	nacl40 = nfs40acl_alloc(mem_ctx, smb4naces);
	nfs40acl_set_naces(nacl40, 0);

	smb4ace = smb_first_ace4(smb4acl);
	while (smb4ace != NULL) {
		SMB_ACE4PROP_T *ace4prop = smb_get_ace4(smb4ace);
		size_t nace_count = nfs40acl_get_naces(nacl40);
		nfsace40 *nace40 = nfs40acl_get_ace(nacl40, nace_count);

		nace40->type = ace4prop->aceType;
		nace40->flag = ace4prop->aceFlags;
		nace40->access_mask = ace4prop->aceMask;

		if (ace4prop->flags & SMB_ACE4_ID_SPECIAL) {
			switch (ace4prop->who.special_id) {
			case SMB_ACE4_WHO_OWNER:
				if (!create_special_id(mem_ctx, nace40, "OWNER@")) {
					return false;
				}
				break;
			case SMB_ACE4_WHO_GROUP:
				if (!create_special_id(mem_ctx, nace40, "GROUP@")) {
					return false;
				}
				break;

			case SMB_ACE4_WHO_EVERYONE:
				if (!create_special_id(mem_ctx, nace40, "EVERYONE@")) {
					return false;
				}
				break;
			case SMB_ACE4_WHO_INTERACTIVE:
				if (!create_special_id(mem_ctx, nace40, "INTERACTIVE@")) {
					return false;
				}
				break;
			case SMB_ACE4_WHO_NETWORK:
				if (!create_special_id(mem_ctx, nace40, "NETWORK@")) {
					return false;
				}
				break;
			case SMB_ACE4_WHO_DIALUP:
				if (!create_special_id(mem_ctx, nace40, "DIALUP@")) {
					return false;
				}
				break;
			case SMB_ACE4_WHO_BATCH:
				if (!create_special_id(mem_ctx, nace40, "BATCH@")) {
					return false;
				}
				break;
			case SMB_ACE4_WHO_ANONYMOUS:
				if (!create_special_id(mem_ctx, nace40, "ANONYMOUS@")) {
					return false;
				}
				break;
			case SMB_ACE4_WHO_AUTHENTICATED:
				if (!create_special_id(mem_ctx, nace40, "AUTHENTICATED@")) {
					return false;
				}
				break;
			case SMB_ACE4_WHO_SERVICE:
				if (!create_special_id(mem_ctx, nace40, "SERVICE@")) {
					return false;
				}
				break;

			default:
				DBG_ERR("Unsupported special id [%d]\n",
					ace4prop->who.special_id);
				continue;
			}
			DBG_DEBUG("nace40->who special [%s]\n", nace40->who.utf8string_val);
		} else {
			if (ace4prop->aceFlags & SMB_ACE4_IDENTIFIER_GROUP) {
				nace40->flag |= ACE4_IDENTIFIER_GROUP;
				if (!create_numeric_id(mem_ctx, nace40, ace4prop->who.gid)) {
					return false;
				}
				DBG_DEBUG("nace40->who gid [%s]\n", nace40->who.utf8string_val);
			} else {
				if (!create_numeric_id(mem_ctx, nace40, ace4prop->who.uid)) {
					return false;
				}
				DBG_DEBUG("nace40->who uid [%s]\n", nace40->who.utf8string_val);
			}
		}

		nace_count++;
		nfs40acl_set_naces(nacl40, nace_count);
		smb4ace = smb_next_ace4(smb4ace);
	}

	*_nacl40 = nacl40;
	return true;
}


static bool smb4acl_to_nfs4acl(vfs_handle_struct *handle,
			       TALLOC_CTX *mem_ctx,
			       struct SMB4ACL_T *smb4acl,
			       nfsacl41 **_nacl)
{
	struct nfs4acl_config *config = NULL;
	struct SMB4ACE_T *smb4ace = NULL;
	size_t smb4naces = 0;
	nfsacl41 *nacl = NULL;
	uint16_t smb4acl_flags = 0;
	unsigned nacl_flags = 0;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct nfs4acl_config,
				return false);

	smb4naces = smb_get_naces(smb4acl);
	nacl = nfs4acl_alloc(mem_ctx, smb4naces);
	nfs4acl_set_naces(nacl, 0);

	if (config->nfs_version > ACL4_XATTR_VERSION_40) {
		smb4acl_flags = smbacl4_get_controlflags(smb4acl);
		nacl_flags = smb4acl_to_nfs4acl_flags(smb4acl_flags);
		nfs4acl_set_flags(nacl, nacl_flags);
	}

	smb4ace = smb_first_ace4(smb4acl);
	while (smb4ace != NULL) {
		SMB_ACE4PROP_T *ace4prop = smb_get_ace4(smb4ace);
		size_t nace_count = nfs4acl_get_naces(nacl);
		nfsace4 *nace = nfs4acl_get_ace(nacl, nace_count);

		nace->type = ace4prop->aceType;
		nace->flag = ace4prop->aceFlags;
		nace->access_mask = ace4prop->aceMask;

		if (ace4prop->flags & SMB_ACE4_ID_SPECIAL) {
			nace->iflag |= ACEI4_SPECIAL_WHO;

			switch (ace4prop->who.special_id) {
			case SMB_ACE4_WHO_OWNER:
				nace->who = ACE4_SPECIAL_OWNER;
				break;

			case SMB_ACE4_WHO_GROUP:
				nace->who = ACE4_SPECIAL_GROUP;
				break;

			case SMB_ACE4_WHO_EVERYONE:
				nace->who = ACE4_SPECIAL_EVERYONE;
				break;

			default:
				DBG_ERR("Unsupported special id [%d]\n",
					ace4prop->who.special_id);
				continue;
			}
		} else {
			if (ace4prop->aceFlags & SMB_ACE4_IDENTIFIER_GROUP) {
				nace->flag |= ACE4_IDENTIFIER_GROUP;
				nace->who = ace4prop->who.gid;
			} else {
				nace->who = ace4prop->who.uid;
			}
		}

		nace_count++;
		nfs4acl_set_naces(nacl, nace_count);
		smb4ace = smb_next_ace4(smb4ace);
	}

	*_nacl = nacl;
	return true;
}

NTSTATUS nfs40acl_smb4acl_to_xdr_blob(vfs_handle_struct *handle,
				     TALLOC_CTX *mem_ctx,
				     struct SMB4ACL_T *smb4acl,
				     DATA_BLOB *_blob)
{
	nfsacl40 *nacl40 = NULL;
	XDR xdr = {0};
	size_t aclblobsize;
	DATA_BLOB blob;
	bool ok;

	ok = smb4acl_to_nfs40acl(handle, talloc_tos(), smb4acl, &nacl40);
	if (!ok) {
		DBG_ERR("smb4acl_to_nfs4acl failed\n");
		return NT_STATUS_INTERNAL_ERROR;
	}

	aclblobsize = nfs40acl_get_xdrblob_size(nacl40);
	if (aclblobsize == 0) {
		DBG_ERR("Error calculating XDR blob size\n");
		return NT_STATUS_INTERNAL_ERROR;
	}

	blob = data_blob_talloc(mem_ctx, NULL, aclblobsize);
	if (blob.data == NULL) {
		TALLOC_FREE(nacl40);
		return NT_STATUS_NO_MEMORY;
	}
	DBG_DEBUG("blob 0x%x size %ld\n", blob.data, blob.length);

	xdrmem_create(&xdr, (char *)blob.data, blob.length, XDR_ENCODE);

	ok = xdr_nfsacl40(&xdr, nacl40);
	TALLOC_FREE(nacl40);
	if (!ok) {
		DBG_ERR("xdr_nfs4acl40 failed\n");
		return NT_STATUS_NO_MEMORY;
	}

	*_blob = blob;
	return NT_STATUS_OK;
}


NTSTATUS nfs4acl_smb4acl_to_xdr_blob(vfs_handle_struct *handle,
				     TALLOC_CTX *mem_ctx,
				     struct SMB4ACL_T *smb4acl,
				     DATA_BLOB *_blob)
{
	nfsacl41 *nacl = NULL;
	XDR xdr = {0};
	size_t aclblobsize;
	DATA_BLOB blob;
	bool ok;

	ok = smb4acl_to_nfs4acl(handle, talloc_tos(), smb4acl, &nacl);
	if (!ok) {
		DBG_ERR("smb4acl_to_nfs4acl failed\n");
		return NT_STATUS_INTERNAL_ERROR;
	}

	aclblobsize = nfs4acl_get_xdrblob_size(nacl);
	if (aclblobsize == 0) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	blob = data_blob_talloc(mem_ctx, NULL, aclblobsize);
	if (blob.data == NULL) {
		TALLOC_FREE(nacl);
		return NT_STATUS_NO_MEMORY;
	}

	xdrmem_create(&xdr, (char *)blob.data, blob.length, XDR_ENCODE);

	ok = xdr_nfsacl41(&xdr, nacl);
	TALLOC_FREE(nacl);
	if (!ok) {
		DBG_ERR("xdr_nfs4acl41 failed\n");
		return NT_STATUS_NO_MEMORY;
	}

	*_blob = blob;
	return NT_STATUS_OK;
}

static uint16_t nfs4acl_to_smb4acl_flags(unsigned nfsacl41_flags)
{
	uint16_t smb4acl_flags = SEC_DESC_SELF_RELATIVE;

	if (nfsacl41_flags & ACL4_AUTO_INHERIT) {
		smb4acl_flags |= SEC_DESC_DACL_AUTO_INHERITED;
	}
	if (nfsacl41_flags & ACL4_PROTECTED) {
		smb4acl_flags |= SEC_DESC_DACL_PROTECTED;
	}
	if (nfsacl41_flags & ACL4_DEFAULTED) {
		smb4acl_flags |= SEC_DESC_DACL_DEFAULTED;
	}

	return smb4acl_flags;
}

static NTSTATUS nfs40acl_xdr_blob_to_nfs40acl(struct vfs_handle_struct *handle,
					    TALLOC_CTX *mem_ctx,
					    DATA_BLOB *blob,
					    nfsacl40 **_nacl40)
{
	struct nfs4acl_config *config = NULL;
	nfsacl40* nacl40;
	size_t naces;
	XDR xdr = {0};
	bool ok;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct nfs4acl_config,
				return NT_STATUS_INTERNAL_ERROR);

	nacl40 = talloc_zero_size(mem_ctx, sizeof(nfsacl40));
	if (nacl40 == NULL) {
		DBG_ERR("talloc_zero_size failed\n");
		return NT_STATUS_NO_MEMORY;
	}

	xdrmem_create(&xdr, (char *)blob->data, blob->length, XDR_DECODE);

	/* XDR allocates the required memory */
	ok = xdr_nfsacl40(&xdr, nacl40);
	if (!ok) {
		DBG_ERR("xdr_nfsacl40 failed\n");
		return NT_STATUS_INTERNAL_ERROR;
	}

	/* naces is obtained by XDR decode */
	naces = nacl40->na40_aces.na40_aces_len;
	DBG_DEBUG("naces = %d \n", naces);

	*_nacl40 = nacl40;
	return NT_STATUS_OK;
}

static NTSTATUS nfs4acl_xdr_blob_to_nfs4acl(struct vfs_handle_struct *handle,
					    TALLOC_CTX *mem_ctx,
					    DATA_BLOB *blob,
					    nfsacl41 **_nacl)
{
	struct nfs4acl_config *config = NULL;
	nfsacl41 *nacl = NULL;
	size_t naces;
	XDR xdr = {0};
	bool ok;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct nfs4acl_config,
				return NT_STATUS_INTERNAL_ERROR);

	naces = nfs4acl_get_xdrblob_naces(blob->length);
	nacl = nfs4acl_alloc(mem_ctx, naces);

	xdrmem_create(&xdr, (char *)blob->data, blob->length, XDR_DECODE);

	ok = xdr_nfsacl41(&xdr, nacl);
	if (!ok) {
		DBG_ERR("xdr_nfs4acl41 failed\n");
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (config->nfs_version == ACL4_XATTR_VERSION_40) {
		nacl->na41_flag = 0;
	}

	*_nacl = nacl;
	return NT_STATUS_OK;
}

static int get_numeric_uid(char *id, uint32_t len, uint32_t *puid)
{
	char *username = NULL;
	struct passwd *password = NULL;

	/* Check if the id is in form of username@domainname */
	if (NULL == strchr (id, '@')) {
		DBG_DEBUG("ace.who is numeric identifier\n");
		char *endptr = NULL;
		uint32_t uid;
		uid = strtoul(id, &endptr, 10);
		if (endptr >= id && endptr < id + len) {
			DBG_ERR("Error converting id [%s] to numeric id\n", id);
			return -1;
		} else {
			*puid = uid;
			return 0;
		}
	}
	DBG_DEBUG("ace.who is string identifier\n");

	/* Parse the identifier to get only username. Strip off the @localdomain */
	username = strtok (id, "@");
	if (!username) {
		DBG_ERR("Error parsing the identifier");
		return -1;
	}
	DBG_DEBUG("Username in identifier: %s\n", username);
	errno = 0;

	/* Convert local user name to uid/gid */
	password = getpwnam(username);
	if (password) {
		DBG_DEBUG("getpwnam returned [%d]\n", password->pw_uid);
		*puid = password->pw_uid;
		return 0;
	} else {
		DBG_ERR("getpwnam returned error [%d]\n", errno);
		return -1;
	}
	return -1;
}

/* Use getgrnam to convert the string group identifier to numeric */
static int get_numeric_gid(char *id, uint32_t len, uint32_t *pgid)
{
	char *groupname = NULL;
	struct group *group = NULL;

	/* Check if the id is in form of groupname@domainname */
	if (NULL == strchr (id, '@')) {
		DBG_DEBUG("ace.who is numeric identifier\n");
		char *endptr = NULL;
		uint32_t gid;
		gid = strtoul(id, &endptr, 10);
		if (endptr >= id && endptr < id + len) {
			DBG_ERR("Error converting id [%s] to numeric id\n", id);
			return -1;
		} else {
			*pgid = gid;
			return 0;
		}
	}
	DBG_DEBUG("ace.who is string identifier\n");

	/* Parse the identifier to get only groupname. Strip off the @localdomain */
	groupname = strtok (id, "@");
	if (!groupname) {
		DBG_ERR("Error parsing the identifier");
		return -1;
	}
	DBG_DEBUG("Group name in identifier: %s\n", groupname);
	errno = 0;

	/* Convert local user name to uid/gid */
	group = getgrnam(groupname);
	if (group) {
		DBG_DEBUG("getgrnam returned [%d]\n", group->gr_gid);
		*pgid = group->gr_gid;
		return 0;
	} else {
		DBG_ERR("getgrnam returned error [%d]\n", errno);
		return -1;
	}
	return -1;
}
static NTSTATUS nfs40acl_to_smb4acl(struct vfs_handle_struct *handle,
				   TALLOC_CTX *mem_ctx,
				   nfsacl40 *nacl40,
				   struct SMB4ACL_T **_smb4acl)
{
	struct nfs4acl_config *config = NULL;
	struct SMB4ACL_T *smb4acl = NULL;
	unsigned nfsacl41_flag = 0;
	uint16_t smb4acl_flags = 0;
	unsigned naces = nfs40acl_get_naces(nacl40);
	unsigned int i;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct nfs4acl_config,
				return NT_STATUS_INTERNAL_ERROR);

	smb4acl = smb_create_smb4acl(mem_ctx);
	if (smb4acl == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	DBG_DEBUG("flags [%x] nace [%u]\n", smb4acl_flags, naces);

	for (i = 0; i < naces; i++) {
		nfsace40 *nace40 = nfs40acl_get_ace(nacl40, i);
		SMB_ACE4PROP_T smbace = { 0 };

		DBG_DEBUG("type [%d] flag [%x] mask [%x] who [%s]\n",
			  nace40->type, nace40->flag,
			  nace40->access_mask, nace40->who.utf8string_val);

		smbace.aceType = nace40->type;
		smbace.aceFlags = nace40->flag;
		smbace.aceMask = nace40->access_mask;

		if (0 == strncmp(nace40->who.utf8string_val, "OWNER@", nace40->who.utf8string_len)) {
			DBG_DEBUG("OWNER@\n");
			smbace.flags |= SMB_ACE4_ID_SPECIAL;
			smbace.who.special_id = SMB_ACE4_WHO_OWNER;
		} else if (0 == strncmp(nace40->who.utf8string_val, "GROUP@", nace40->who.utf8string_len)) {
			DBG_DEBUG("GROUP@\n");
			smbace.flags |= SMB_ACE4_ID_SPECIAL;
			smbace.who.special_id = SMB_ACE4_WHO_GROUP;
		} else if (0 == strncmp(nace40->who.utf8string_val, "EVERYONE@", nace40->who.utf8string_len)) {
			DBG_DEBUG("EVERYONE@\n");
			smbace.flags |= SMB_ACE4_ID_SPECIAL;
			smbace.who.special_id = SMB_ACE4_WHO_EVERYONE;
		} else if (0 == strncmp(nace40->who.utf8string_val, "INTERACTIVE@", nace40->who.utf8string_len)) {
			DBG_DEBUG("INTERACTIVE@\n");
			smbace.flags |= SMB_ACE4_ID_SPECIAL;
			smbace.who.special_id = SMB_ACE4_WHO_INTERACTIVE;
		} else if (0 == strncmp(nace40->who.utf8string_val, "NETWORK@", nace40->who.utf8string_len)) {
			DBG_DEBUG("NETWORK@\n");
			smbace.flags |= SMB_ACE4_ID_SPECIAL;
			smbace.who.special_id = SMB_ACE4_WHO_NETWORK;
		} else if (0 == strncmp(nace40->who.utf8string_val, "DIALUP@", nace40->who.utf8string_len)) {
			DBG_DEBUG("DIALUP@\n");
			smbace.flags |= SMB_ACE4_ID_SPECIAL;
			smbace.who.special_id = SMB_ACE4_WHO_DIALUP;
		} else if (0 == strncmp(nace40->who.utf8string_val, "BATCH@", nace40->who.utf8string_len)) {
			DBG_DEBUG("BATCH@\n");
			smbace.flags |= SMB_ACE4_ID_SPECIAL;
			smbace.who.special_id = SMB_ACE4_WHO_BATCH;
		} else if (0 == strncmp(nace40->who.utf8string_val, "ANONYMOUS@", nace40->who.utf8string_len)) {
			DBG_DEBUG("ANONYMOUS@\n");
			smbace.flags |= SMB_ACE4_ID_SPECIAL;
			smbace.who.special_id = SMB_ACE4_WHO_ANONYMOUS;
		} else if (0 == strncmp(nace40->who.utf8string_val, "AUTHENTICATED@", nace40->who.utf8string_len)) {
			DBG_DEBUG("AUTHENTICATED@\n");
			smbace.flags |= SMB_ACE4_ID_SPECIAL;
			smbace.who.special_id = SMB_ACE4_WHO_AUTHENTICATED;
		} else if (0 == strncmp(nace40->who.utf8string_val, "SERVICE@", nace40->who.utf8string_len)) {
			DBG_DEBUG("SERVICE@\n");
			smbace.flags |= SMB_ACE4_ID_SPECIAL;
			smbace.who.special_id = SMB_ACE4_WHO_SERVICE;

		} else {
			uint32_t numeric_id;
			char *id = NULL;
			int err;

			if (nace40->who.utf8string_len + 1 < nace40->who.utf8string_len) {
				DBG_ERR("Integer overflow error while converting NFS4 ACE\n");
				continue;
			}
			id = talloc_zero_size(mem_ctx, nace40->who.utf8string_len + 1);
			if (NULL == id) {
				DBG_ERR("talloc_zero_size failed for allocating %d bytes id\n",
					nace40->who.utf8string_len + 1);
				continue;
			}

			memcpy(id, nace40->who.utf8string_val, nace40->who.utf8string_len);

			DBG_DEBUG("converting id [%s] to numeric id \n", id);
			if (nace40->flag & ACE4_IDENTIFIER_GROUP) {
				err = get_numeric_gid(id, nace40->who.utf8string_len, &numeric_id);
				DBG_DEBUG("ACE gid [%d]\n", numeric_id);
			} else {
				err = get_numeric_uid(id, nace40->who.utf8string_len, &numeric_id);
			}

			if (err) {
				DBG_ERR("Error converting string id [%s] to numeric id\n", id);
				TALLOC_FREE(id);
				continue;
			}
			TALLOC_FREE(id);

			if (nace40->flag & ACE4_IDENTIFIER_GROUP) {
				smbace.who.gid = numeric_id;
			} else {
				smbace.who.uid = numeric_id;
			}
		}
		smb_add_ace4(smb4acl, &smbace);
	}

	*_smb4acl = smb4acl;
	return NT_STATUS_OK;
}

static NTSTATUS nfs4acl_to_smb4acl(struct vfs_handle_struct *handle,
				   TALLOC_CTX *mem_ctx,
				   nfsacl41 *nacl,
				   struct SMB4ACL_T **_smb4acl)
{
	struct nfs4acl_config *config = NULL;
	struct SMB4ACL_T *smb4acl = NULL;
	unsigned nfsacl41_flag = 0;
	uint16_t smb4acl_flags = 0;
	unsigned naces = nfs4acl_get_naces(nacl);
	int i;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct nfs4acl_config,
				return NT_STATUS_INTERNAL_ERROR);

	smb4acl = smb_create_smb4acl(mem_ctx);
	if (smb4acl == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (config->nfs_version > ACL4_XATTR_VERSION_40) {
		nfsacl41_flag = nfs4acl_get_flags(nacl);
		smb4acl_flags = nfs4acl_to_smb4acl_flags(nfsacl41_flag);
		smbacl4_set_controlflags(smb4acl, smb4acl_flags);
	}

	DBG_DEBUG("flags [%x] nace [%u]\n", smb4acl_flags, naces);

	for (i = 0; i < naces; i++) {
		nfsace4 *nace = nfs4acl_get_ace(nacl, i);
		SMB_ACE4PROP_T smbace = { 0 };

		DBG_DEBUG("type [%d] iflag [%x] flag [%x] mask [%x] who [%d]\n",
			  nace->type, nace->iflag, nace->flag,
			  nace->access_mask, nace->who);

		smbace.aceType = nace->type;
		smbace.aceFlags = nace->flag;
		smbace.aceMask = nace->access_mask;

		if (nace->iflag & ACEI4_SPECIAL_WHO) {
			smbace.flags |= SMB_ACE4_ID_SPECIAL;

			switch (nace->who) {
			case ACE4_SPECIAL_OWNER:
				smbace.who.special_id = SMB_ACE4_WHO_OWNER;
				break;

			case ACE4_SPECIAL_GROUP:
				smbace.who.special_id = SMB_ACE4_WHO_GROUP;
				break;

			case ACE4_SPECIAL_EVERYONE:
				smbace.who.special_id = SMB_ACE4_WHO_EVERYONE;
				break;

			default:
				DBG_ERR("Unknown special id [%d]\n", nace->who);
				continue;
			}
		} else {
			if (nace->flag & ACE4_IDENTIFIER_GROUP) {
				smbace.who.gid = nace->who;
			} else {
				smbace.who.uid = nace->who;
			}
		}

		smb_add_ace4(smb4acl, &smbace);
	}

	*_smb4acl = smb4acl;
	return NT_STATUS_OK;
}

NTSTATUS nfs40acl_xdr_blob_to_smb4(struct vfs_handle_struct *handle,
				  TALLOC_CTX *mem_ctx,
				  DATA_BLOB *blob,
				  struct SMB4ACL_T **_smb4acl)
{
	struct nfs4acl_config *config = NULL;
	nfsacl40 *nacl40 = NULL;
	struct SMB4ACL_T *smb4acl = NULL;
	NTSTATUS status;

	DBG_DEBUG("entered\n");

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct nfs4acl_config,
				return NT_STATUS_INTERNAL_ERROR);

	status = nfs40acl_xdr_blob_to_nfs40acl(handle, talloc_tos(), blob, &nacl40);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = nfs40acl_to_smb4acl(handle, mem_ctx, nacl40, &smb4acl);
	TALLOC_FREE(nacl40);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	*_smb4acl = smb4acl;
	return NT_STATUS_OK;
}

NTSTATUS nfs4acl_xdr_blob_to_smb4(struct vfs_handle_struct *handle,
				  TALLOC_CTX *mem_ctx,
				  DATA_BLOB *blob,
				  struct SMB4ACL_T **_smb4acl)
{
	struct nfs4acl_config *config = NULL;
	nfsacl41 *nacl = NULL;
	struct SMB4ACL_T *smb4acl = NULL;
	NTSTATUS status;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct nfs4acl_config,
				return NT_STATUS_INTERNAL_ERROR);

	status = nfs4acl_xdr_blob_to_nfs4acl(handle, talloc_tos(), blob, &nacl);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = nfs4acl_to_smb4acl(handle, mem_ctx, nacl, &smb4acl);
	TALLOC_FREE(nacl);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	*_smb4acl = smb4acl;
	return NT_STATUS_OK;
}

#else /* !HAVE_RPC_XDR_H */
#include "nfs4acl_xattr_xdr.h"
NTSTATUS nfs4acl_xdr_blob_to_smb4(struct vfs_handle_struct *handle,
				  TALLOC_CTX *mem_ctx,
				  DATA_BLOB *blob,
				  struct SMB4ACL_T **_smb4acl)
{
	return NT_STATUS_NOT_SUPPORTED;
}

NTSTATUS nfs4acl_smb4acl_to_xdr_blob(vfs_handle_struct *handle,
				     TALLOC_CTX *mem_ctx,
				     struct SMB4ACL_T *smbacl,
				     DATA_BLOB *blob)
{
	return NT_STATUS_NOT_SUPPORTED;
}
#endif /* HAVE_RPC_XDR_H */
