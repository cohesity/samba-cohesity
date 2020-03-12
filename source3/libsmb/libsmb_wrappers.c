/*
   Unix SMB/CIFS implementation.
   Wrappers for connection based SMB client library
   Copyright (C) Zheng Cai 2017

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <pthread.h>

#include "includes.h"
#include "include/ntioctl.h"
#include "lib/util/tevent_ntstatus.h"
#include "libcli/security/secdesc.h"
#include "libcli/security/security.h"
#include "libcli/smb/smbXcli_base.h"
#include "libsmb/libsmb.h"
#include "libsmb_internal.h"
#include "trans2.h"
#include "msdfs.h"

/******************************************************************************
 Static util functions
******************************************************************************/

/* The talloc frame for allocating memory for connections. */
static TALLOC_CTX* frame = NULL;

/* fnum handle mapping code */
struct smb2_hnd {
  uint64_t fid_persistent;
  uint64_t fid_volatile;
};

/*
 * Check whether 'context' is in valid state.
 *
 * @param context    The pointer to smbc_wrapper_context to check for. If it is
 *                   not in valid state, its error_msg will be set accordingly.
 *
 * @return           Whether 'context' is in valid state.
 */
static bool
smbc_wrapper_check_context_status(smbc_wrapper_context* context) {
  if (!context) {
    fprintf(stderr, "context is null!\n");
    return false;
  }

  /* Start with an unsuccessful default nt_status value. */
  context->nt_status = NT_STATUS_V(NT_STATUS_UNSUCCESSFUL);

  if (!context->conn) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "context->conn is null");
    return false;
  }

  struct cli_state* cli = (struct cli_state*)context->conn;

  if (smbXcli_conn_has_async_calls(cli->conn)) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "Can't use sync call while an async call is in flight");
    return false;
  }

  if (smbXcli_conn_protocol(cli->conn) < PROTOCOL_SMB2_02) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "The server must support protocol version >= SMBv2");
    context->nt_status = NT_STATUS_V(NT_STATUS_NOT_SUPPORTED);
    return false;
  }

  context->nt_status = NT_STATUS_V(NT_STATUS_OK);
  return true;
}

/*****************************************************************************/

/*
 * Get the smb2_hnd pointer associated with the given fnum.
 *
 * @param cli       The client connection state.
 *
 * @param fnum      The given fnum.
 *
 * @param pph       The pointer to the smb2_hnd pointer to store the result.
 *
 * @return          The corresponding NTSTATUS code if any error happens.
 */
static NTSTATUS
smbc_wrapper_map_fnum_to_smb2_handle(struct cli_state* cli,
                                     uint16_t fnum,
                                     struct smb2_hnd** pph) {
  struct idr_context* idp = cli->smb2.open_handles;

  if (idp == NULL) {
    return NT_STATUS_INVALID_PARAMETER;
  }
  *pph = (struct smb2_hnd*)idr_find(idp, fnum);
  if (*pph == NULL) {
    return NT_STATUS_INVALID_HANDLE;
  }
  return NT_STATUS_OK;
}

/*****************************************************************************/

/*
 * Query and parse the metadata for the given fnum.
 *
 * @param cli       The client connection state.
 *
 * @param fnum      The given fnum.
 *
 * @param mem_ctx   The memory context to use.
 *
 * @param md        The pointer to the metadata to store the result.
 *
 * @return          The corresponding NTSTATUS code if any error happens.
 */
static NTSTATUS
smbc_wrapper_query_entity_metadata(struct cli_state* cli,
                                   uint16_t fnum,
                                   void* mem_ctx,
                                   smbc_wrapper_entity_metadata* md) {
  NTSTATUS status;
  DATA_BLOB outbuf = data_blob_null;
  struct smb2_hnd* ph = NULL;

  status = smbc_wrapper_map_fnum_to_smb2_handle(cli, fnum, &ph);
  if (!NT_STATUS_IS_OK(status)) {
    goto fail;
  }

  /* Call getinfo on the handle with info_type SMB2_GETINFO_FILE (0x01), level
     0x12 (SMB2_FILE_ALL_INFORMATION). */
  status = smb2cli_query_info(
      cli->conn,
      cli->timeout,
      cli->smb2.session,
      cli->smb2.tcon,
      SMB2_GETINFO_FILE,                 /* in_info_type */
      (SMB_FILE_ALL_INFORMATION - 1000), /* in_file_info_class */
      0xFFFF,                            /* in_max_output_length */
      NULL,                              /* in_input_buffer */
      0,                                 /* in_additional_info */
      0,                                 /* in_flags */
      ph->fid_persistent,
      ph->fid_volatile,
      mem_ctx,
      &outbuf);

  if (!NT_STATUS_IS_OK(status)) {
    goto fail;
  }

  /* Parse the result. */
  if (outbuf.length < 0x60) {
    status = NT_STATUS_INVALID_NETWORK_RESPONSE;
    goto fail;
  }

  md->create_time_ts = interpret_long_date((const char*)outbuf.data + 0x0);
  md->access_time_ts = interpret_long_date((const char*)outbuf.data + 0x8);
  md->modify_time_ts = interpret_long_date((const char*)outbuf.data + 0x10);
  md->change_time_ts = interpret_long_date((const char*)outbuf.data + 0x18);
  md->attributes = IVAL(outbuf.data, 0x20);
  md->allocation_size = IVAL2_TO_SMB_BIG_UINT(outbuf.data + 0x28, 0);
  md->size = IVAL2_TO_SMB_BIG_UINT(outbuf.data + 0x30, 0);
  md->uid = 0;
  md->gid = 0;
  md->num_hardlinks = *((uint32_t*)(outbuf.data + 0x38));
  md->inode_id = *((uint64_t*)(outbuf.data + 0x40));

 fail:
  return status;
}

/*****************************************************************************/

/*
 * Set sparse bit for an existing file.
 *
 * @param cli       The client connection state.
 *
 * @param fnum      The given fnum.
 *
 * @return          The corresponding NTSTATUS code if any error happens.
 */
static NTSTATUS smbc_wrapper_set_sparse(struct cli_state* cli, uint16_t fnum) {
  struct smb2_hnd* ph = NULL;

  NTSTATUS status = smbc_wrapper_map_fnum_to_smb2_handle(cli, fnum, &ph);
  if (!NT_STATUS_IS_OK(status)) {
    return status;
  }

  TALLOC_CTX* frame = talloc_stackframe();
  DATA_BLOB in_input_buffer = data_blob_null;
  DATA_BLOB in_output_buffer = data_blob_null;
  DATA_BLOB out_input_buffer = data_blob_null;
  DATA_BLOB out_output_buffer = data_blob_null;

  status = smb2cli_ioctl(cli->conn,
                         cli->timeout,
                         cli->smb2.session,
                         cli->smb2.tcon,
                         ph->fid_persistent,
                         ph->fid_volatile,
                         FSCTL_SET_SPARSE,
                         0 /* in_max_input_length */,
                         &in_input_buffer,
                         0 /* in_max_output_length */,
                         &in_output_buffer,
                         SMB2_IOCTL_FLAG_IS_FSCTL,
                         frame,
                         &out_input_buffer,
                         &out_output_buffer);

  TALLOC_FREE(frame);
  return status;
}

/*****************************************************************************/

/*
 * Set END_OF_FILE_INFORMATION for a given fnum. Valid for a file.
 * Behavior:
 *   -- For regular files, when set will also modify AllocationSize in
 *   addition to EndOfFile.
 *   -- For sparse files, when set only EndOfFile is modified.
 *
 * @param cli       The client connection state.
 *
 * @param fnum      The given fnum.
 *
 * @param size      The value of size to be set for fnum.
 *
 * @return          The corresponding NTSTATUS code if any error happens.
 */
static NTSTATUS smbc_wrapper_set_end_of_file(struct cli_state* cli,
                                             uint16_t fnum,
                                             uint64_t size) {
  struct smb2_hnd* ph = NULL;
  NTSTATUS status = smbc_wrapper_map_fnum_to_smb2_handle(cli, fnum, &ph);
  if (!NT_STATUS_IS_OK(status)) {
    return status;
  }

  uint8_t inbuf_store[8];
  DATA_BLOB inbuf = data_blob_null;

  inbuf.data = inbuf_store;
  inbuf.length = sizeof(inbuf_store);
  data_blob_clear(&inbuf);

  SBVAL(inbuf.data, 0, size);

  status = smb2cli_set_info(
      cli->conn,
      cli->timeout,
      cli->smb2.session,
      cli->smb2.tcon,
      1,                                       /* in_info_type */
      SMB_FILE_END_OF_FILE_INFORMATION - 1000, /* in_file_info_class */
      &inbuf,                                  /* in_input_buffer */
      0,                                       /* in_additional_info */
      ph->fid_persistent,
      ph->fid_volatile);

  return status;
}

/*****************************************************************************/

/*
 * Set FILE_BASIC_INFORMATION for a given fnum.
 *
 * @param context   The pointer to the wrapper context which contains the SMB
 *                  share information.
 *
 * @param fnum      The given fnum.
 *
 * @param mem_ctx   The memory context to use.
 *
 * @param md        The pointer to the metadata to store the result.
 *
 * @return          The corresponding NTSTATUS code if any error happens.
 */
static NTSTATUS smbc_wrapper_set_file_basic_information(
    struct cli_state* cli,
    uint16_t fnum,
    uint32_t additional_info,
    smbc_wrapper_entity_metadata* md) {
  NTSTATUS status;
  struct smb2_hnd* ph = NULL;
  uint8_t inbuf_store[40];
  DATA_BLOB inbuf = data_blob_null;

  status = smbc_wrapper_map_fnum_to_smb2_handle(cli, fnum, &ph);
  if (!NT_STATUS_IS_OK(status)) {
    return status;
  }

  inbuf.data = inbuf_store;
  inbuf.length = sizeof(inbuf_store);
  data_blob_clear(&inbuf);

  SBVAL(inbuf.data, 0x0, unix_timespec_to_nt_time(md->create_time_ts));
  SBVAL(inbuf.data, 0x8, unix_timespec_to_nt_time(md->access_time_ts));
  SBVAL(inbuf.data, 0x10, unix_timespec_to_nt_time(md->modify_time_ts));
  SBVAL(inbuf.data, 0x18, unix_timespec_to_nt_time(md->change_time_ts));
  SIVAL(inbuf.data, 0x20, md->attributes);

  /* Set the entity's basic info on the handle. */
  status = smb2cli_set_info(
      cli->conn,
      cli->timeout,
      cli->smb2.session,
      cli->smb2.tcon,
      1,                                   /* in_info_type */
      (SMB_FILE_BASIC_INFORMATION - 1000), /* in_file_info_class */
      &inbuf,                              /* in_input_buffer */
      additional_info,
      ph->fid_persistent,
      ph->fid_volatile);

  return status;
}

/*****************************************************************************/

/*
 * Query the access control lists for the given fnum.
 *
 * @param context   The pointer to the wrapper context which contains the SMB
 *                  share information.
 *
 * @param fnum      The given fnum.
 *
 * @param mem_ctx   The memory context to use.
 *
 * @param md        The pointer to the metadata to store the result.
 *
 * @return          The corresponding NTSTATUS code if any error happens.
 */
static NTSTATUS
smbc_wrapper_query_entity_acls(struct cli_state* cli,
                               uint16_t fnum,
                               void* mem_ctx,
                               uint32_t sec_info,
                               smbc_wrapper_entity_metadata* md) {
  NTSTATUS status;
  DATA_BLOB outbuf = data_blob_null;
  struct smb2_hnd* ph = NULL;

  status = smbc_wrapper_map_fnum_to_smb2_handle(cli, fnum, &ph);
  if (!NT_STATUS_IS_OK(status)) {
    goto fail;
  }

  /* Get the entity's security info on the handle. */
  const uint32_t in_max_output_length = 65535 + 200;
  status = smb2cli_query_info(cli->conn,
                              cli->timeout,
                              cli->smb2.session,
                              cli->smb2.tcon,
                              SMB2_GETINFO_SECURITY, /* in_info_type */
                              0,                     /* in_file_info_class */
                              0xFFFF,                /* in_max_output_length */
                              NULL,                  /* in_input_buffer */
                              sec_info,              /* in_additional_info */
                              0,                     /* in_flags */
                              ph->fid_persistent,
                              ph->fid_volatile,
                              mem_ctx,
                              &outbuf);

  if (!NT_STATUS_IS_OK(status)) {
    goto fail;
  }

  /* Store the raw ACLs bytes in the entity metadata. */
  md->acls = talloc_memdup(mem_ctx, outbuf.data, outbuf.length);
  md->acls_size = outbuf.length;

 fail:
  return status;
}

/*****************************************************************************/

static NTSTATUS smbc_wrapper_set_entity_acls(
    struct cli_state* cli,
    uint16_t fnum,
    uint32_t additional_info,
    smbc_wrapper_entity_metadata* md) {
  NTSTATUS status;
  DATA_BLOB input = data_blob_null;
  struct smb2_hnd* ph = NULL;

  status = smbc_wrapper_map_fnum_to_smb2_handle(cli, fnum, &ph);
  if (!NT_STATUS_IS_OK(status)) {
    return status;
  }

  input.data = md->acls;
  input.length = md->acls_size;

  /* Set the entity's security info on the handle. */
  status = smb2cli_set_info(cli->conn,
                            cli->timeout,
                            cli->smb2.session,
                            cli->smb2.tcon,
                            3, /* SMB2_SETINFO_SEC */
                            0, /* in_file_info_class */
                            &input, /* in_input_buffer */
                            additional_info, /* in_additional_info */
                            ph->fid_persistent,
                            ph->fid_volatile);

  return status;
}

/*****************************************************************************/

/*
 * Get the parent directory's path for a given directory.
 *
 * @param mem_ctx   The memory context to allocate the result in.
 *
 * @param dir       The path of the given directory.
 *
 * @param name      The name of the given directory, to be filled in by this
 *                  function.
 *
 * @return          The parent directory's path. NULL if any error happens.
 */
static char* smbc_wrapper_get_parent_dir(TALLOC_CTX* mem_ctx,
                                         const char* dir,
                                         const char** name) {
  char* parent;
  char* p;
  ptrdiff_t len;

  /* Find final '\\', if any */
  p = strrchr_m(dir, '\\');

  if (p == NULL) {
    if (!(parent = talloc_strdup(mem_ctx, "\\"))) {
      return parent;
    }
    if (name) {
      *name = dir;
    }
    return parent;
  }

  len = p - dir;
  if (!(parent = (char*)talloc_memdup(mem_ctx, dir, len + 1))) {
    return parent;
  }
  parent[len] = '\0';

  if (name) {
    *name = p + 1;
  }
  return parent;
}

/*****************************************************************************/

/*
 * Parse and get the next child's name from 'dir_data'.
 *
 * @param mem_ctx     The memory context to allocate the result in.
 *
 * @param dir_data    The pointer that stores all the children's names.
 *
 * @param dir_data_length
 *                    The length of the 'dir_data' buffer.
 *
 * @param result      The array of char* where to store the children's names.
 *
 * @param result_idx  The location in result where this child should be stored.
 *                    Upon success and a valid child (not "." or ".."),
 *                    'result_idx' should be
 *                    increased by one.
 *
 * @param next_offset The offset in 'dir_data' for the next child. If 0, it
 *                    means the end of 'dir_data' has been reached.
 *
 * @param context     The pointer to smbc_wrapper_context to set error_msg.
 *
 * @param this_offset The offset of this name record.
 *
 * @param total_dir_data_len
 *                    The total length of the dir_data packet.
 *
 * @return            The parent directory's path. NULL if any error happens.
 */
static NTSTATUS
smbc_wrapper_parse_next_name(TALLOC_CTX* mem_ctx,
                             uint8_t* dir_data,
                             uint32_t dir_data_length,
                             char** result,
                             uint32_t* result_idx,
                             uint32_t* next_offset,
                             smbc_wrapper_context* context,
                             uint32_t this_offset,
                             uint32_t total_dir_data_len) {
  if (dir_data_length < 4) {
    snprintf(context->error_msg, SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "Not enough room for next offset, dir_data_length[%u], "
             "this_offset[%u], total_dir_data_len[%u]",
             dir_data_length, this_offset, total_dir_data_len);
    context->nt_status = NT_STATUS_V(NT_STATUS_INFO_LENGTH_MISMATCH);
    return NT_STATUS_INFO_LENGTH_MISMATCH;
  }

  *next_offset = IVAL(dir_data, 0);

  if (*next_offset > dir_data_length) {
    snprintf(context->error_msg, SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "next_offset[%u] is larger than dir_data_length[%u], "
             "this_offset[%u], total_dir_data_len[%u]",
             *next_offset, dir_data_length, this_offset, total_dir_data_len);
    context->nt_status = NT_STATUS_V(NT_STATUS_INFO_LENGTH_MISMATCH);
    return NT_STATUS_INFO_LENGTH_MISMATCH;
  }

  if (*next_offset != 0) {
    /* Ensure we only read what in this record. */
    dir_data_length = *next_offset;
  }

  if (dir_data_length < 13) {
    snprintf(context->error_msg, SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "dir_data_length[%u] is smaller than the minimal (13), "
             "this_offset[%u], total_dir_data_len[%u]",
             dir_data_length, this_offset, total_dir_data_len);
    context->nt_status = NT_STATUS_V(NT_STATUS_INFO_LENGTH_MISMATCH);
    return NT_STATUS_INFO_LENGTH_MISMATCH;
  }

  size_t namelen = IVAL(dir_data + 8, 0);
  if (namelen > (dir_data_length - 12)) {
    snprintf(context->error_msg, SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "namelen[%u] is larger than remaining data[%u], this_offset[%u], "
             "total_dir_data_len[%u]",
             namelen, dir_data_length - 12, this_offset, total_dir_data_len);
    context->nt_status = NT_STATUS_V(NT_STATUS_INFO_LENGTH_MISMATCH);
    return NT_STATUS_INFO_LENGTH_MISMATCH;
  }

  char** name_ptr = result + *result_idx;
  size_t ret = pull_string_talloc(mem_ctx, dir_data, FLAGS2_UNICODE_STRINGS,
                                  name_ptr, dir_data + 12, namelen,
                                  STR_UNICODE);
  if (ret == (size_t)-1 || !(*name_ptr)) {
    snprintf(context->error_msg, SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "pull_string_talloc returned[%u], this_offset[%u], "
             "total_dir_data_len[%u], namelen[%u], result_idx[%u]",
             ret, this_offset, total_dir_data_len, namelen, *result_idx);
    context->nt_status = NT_STATUS_V(NT_STATUS_INVALID_NETWORK_RESPONSE);
    return NT_STATUS_INVALID_NETWORK_RESPONSE;
  }

  if (strcmp(*name_ptr, ".") == 0 || strcmp(*name_ptr, "..") == 0) {
    /* Skip "." and "..". */
    TALLOC_FREE(*name_ptr);
  } else {
    ++(*result_idx);
  }

  return NT_STATUS_OK;
}

/*****************************************************************************/

/*
 * Create a SMB2 symlink (reparse point) at the given path to the target path.
 *
 * @param cli       The SMB2 client state structure.
 *
 * @param path      The path where to create the symlink.
 *
 * @param target_path
 *                  The target path of this symlink.
 *
 * @param flags     The flags to use when creating the symlink.
 *
 * @return          The corresponding NTSTATUS code if any error happens.
 */
static NTSTATUS smbc_wrapper_symlink(struct cli_state* cli,
                                     const char* path,
                                     const char* target_path,
                                     uint32_t flags) {
  uint16_t fnum;
  uint32_t desired_access = SYNCHRONIZE_ACCESS | DELETE_ACCESS |
                            FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES;
  uint32_t create_options = FILE_OPEN_REPARSE_POINT |
                            FILE_SYNCHRONOUS_IO_NONALERT |
                            FILE_NON_DIRECTORY_FILE;
  NTSTATUS status = cli_ntcreate(cli,
                                 path,
                                 0 /* CreateFlags */,
                                 desired_access,
                                 FILE_ATTRIBUTE_NORMAL,
                                 FILE_SHARE_NONE,
                                 FILE_CREATE,
                                 create_options,
                                 0 /* SecurityFlags */,
                                 &fnum,
                                 NULL /* smb_create_returns */);
  if (!NT_STATUS_IS_OK(status)) {
    return status;
  }

  struct smb2_hnd* ph = NULL;
  status = smbc_wrapper_map_fnum_to_smb2_handle(cli, fnum, &ph);
  if (!NT_STATUS_IS_OK(status)) {
    cli_smb2_close_fnum(cli, fnum);
    return status;
  }

  TALLOC_CTX* frame = talloc_stackframe();
  DATA_BLOB in_input_buffer;
  DATA_BLOB in_output_buffer = data_blob_null;
  DATA_BLOB out_input_buffer = data_blob_null;
  DATA_BLOB out_output_buffer = data_blob_null;
  const char* substitute_path = target_path;
  if ((flags & SYMLINK_FLAG_RELATIVE) == 0) {
    // If this is not a relative symlink, Generate a substitute name with
    // \??\UNC\ at the beginning, so that the symlink can be directly opened by
    // a SMB client.
    substitute_path = talloc_asprintf(frame, "\\??\\UNC%s", target_path + 1);
  }
  if (!symlink_reparse_buffer_marshall(substitute_path,
                                       target_path,
                                       flags,
                                       frame,
                                       &in_input_buffer.data,
                                       &in_input_buffer.length)) {
    TALLOC_FREE(frame);
    cli_smb2_close_fnum(cli, fnum);
    return NT_STATUS_NO_MEMORY;
  }

  status = smb2cli_ioctl(cli->conn,
                         cli->timeout,
                         cli->smb2.session,
                         cli->smb2.tcon,
                         ph->fid_persistent,
                         ph->fid_volatile,
                         FSCTL_SET_REPARSE_POINT,
                         0 /* in_max_input_length */,
                         &in_input_buffer,
                         0 /* in_max_output_length */,
                         &in_output_buffer,
                         SMB2_IOCTL_FLAG_IS_FSCTL,
                         frame,
                         &out_input_buffer,
                         &out_output_buffer);

  TALLOC_FREE(frame);
  cli_smb2_close_fnum(cli, fnum);
  return status;
}

/*****************************************************************************/

/*
 * Read the SMB2 symlink (reparse point) target path.
 *
 * @param cli       The SMB2 client state structure.
 *
 * @param path      The path to symlink.
 *
 * @param target_path
 *                  The target path of symlink returned here.
 *
 * @param flags     The flags for symlink are returned in this variable.
 *
 * @return          The corresponding NTSTATUS code if any error happens.
 */
static NTSTATUS smbc_wrapper_readsymlink(struct cli_state* cli,
                                         const char* path,
                                         void* mem_ctx,
                                         char** target_path,
                                         uint32_t* flags) {
  uint16_t fnum;
  uint32_t desired_access = FILE_READ_ATTRIBUTES;
  uint32_t create_options = FILE_OPEN_REPARSE_POINT | FILE_NON_DIRECTORY_FILE;

  NTSTATUS status =
      cli_ntcreate(cli,
                   path,
                   0 /* CreateFlags */,
                   desired_access,
                   FILE_ATTRIBUTE_NORMAL,
                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                   FILE_OPEN,
                   create_options,
                   0 /* SecurityFlags */,
                   &fnum,
                   NULL /* smb_create_returns */);
  if (!NT_STATUS_IS_OK(status)) {
    return status;
  }

  struct smb2_hnd* ph = NULL;
  status = smbc_wrapper_map_fnum_to_smb2_handle(cli, fnum, &ph);
  if (!NT_STATUS_IS_OK(status)) {
    cli_smb2_close_fnum(cli, fnum);
    return status;
  }

  DATA_BLOB in_output_buffer = data_blob_null;
  DATA_BLOB out_input_buffer = data_blob_null;
  DATA_BLOB out_output_buffer = data_blob_null;

  TALLOC_CTX* inbuf_store = talloc_stackframe();
  in_output_buffer = data_blob_talloc_zero(inbuf_store, 64 * 1024);
  status = smb2cli_ioctl(cli->conn,
                         cli->timeout,
                         cli->smb2.session,
                         cli->smb2.tcon,
                         ph->fid_persistent,
                         ph->fid_volatile,
                         FSCTL_GET_REPARSE_POINT,
                         0 /* in_max_input_length */,
                         NULL,
                         0xFFFF /* in_max_output_length */,
                         &in_output_buffer,
                         SMB2_IOCTL_FLAG_IS_FSCTL,
                         inbuf_store,
                         &out_input_buffer,
                         &out_output_buffer);

  if (!NT_STATUS_IS_OK(status)) {
    TALLOC_FREE(inbuf_store);
    cli_smb2_close_fnum(cli, fnum);
    return status;
  }

  char *print_name;
  if (!symlink_reparse_buffer_parse(out_output_buffer.data,
                                    out_output_buffer.length,
                                    mem_ctx,
                                    target_path,
                                    &print_name,
                                    flags)) {
    cli_smb2_close_fnum(cli, fnum);
    TALLOC_FREE(inbuf_store);
    return NT_STATUS_NO_MEMORY;
  }

  TALLOC_FREE(inbuf_store);
  cli_smb2_close_fnum(cli, fnum);
  return status;
}

/******************************************************************************
 Functions defined in libsmbclient.h
******************************************************************************/

void smbc_wrapper_report_full(const void* mem_ctx, FILE* f) {
  talloc_report_full((TALLOC_CTX *)mem_ctx, f);
}

/*****************************************************************************/

void smbc_wrapper_initialize() {
  /* Enable thread safety for talloc_named_const(). */
  talloc_disable_null_tracking();

  /* Allocating 64KB memory for the common state related to Samba function
     calls should be enough. */
  frame = talloc_named_const(NULL, 64 * 1024, "init");

  /* Enable thread safety for talloc_stackframe(). This two functions should be
     called before any call that could lead to a talloc_stackframe() call, for
     example, the lp_set_cmdline() call below. */
  smbc_thread_posix();
  talloc_tls_init();

  smb_init_locale();
  lp_set_cmdline("client max protocol", "SMB3");
  lp_load_global(get_dyn_CONFIGFILE());
}

/*****************************************************************************/

void smbc_wrapper_destroy() {
  TALLOC_FREE(frame);
}

/*****************************************************************************/

void smbc_wrapper_set_log_level(int level) {
  if (level < 0) {
    level = 0;
  }
  if (level > MAX_DEBUG_LEVEL) {
    level = MAX_DEBUG_LEVEL;
  }

  fprintf(stderr, "Setting debugging log level to %d\n", level);
  char level_str[5];
  snprintf(level_str, 4, "%d", level);
  lp_set_cmdline("log level", level_str);
}

/*****************************************************************************/

int smbc_wrapper_create_connection(const char* server,
                                   const char* share,
                                   const char* username,
                                   const char* password,
                                   const char* workgroup,
                                   smbc_wrapper_context* context) {
  if (!context) {
    fprintf(stderr, "context is null!\n");
    return -1;
  }

  struct cli_state* conn = NULL;
  /* Initialize the error_msg field to all zeroes. */
  memset(context->error_msg, 0, SMBC_WRAPPER_MAX_ERROR_MSG_LEN);

  /* TODO(zheng): Once we support Kerberos authentication to the server, we
     need adjust auth_info accordingly. */
  struct user_auth_info auth_info;
  memset(&auth_info, 0, sizeof(auth_info));
  auth_info.username = username;
  auth_info.domain = workgroup;
  auth_info.password = password;
  auth_info.got_pass = true;
  auth_info.signing_state = SMB_SIGNING_OFF;

  TALLOC_CTX* mem_ctx = talloc_stackframe();
  NTSTATUS nt_status = cli_cm_open(
      mem_ctx,
      NULL /* referring_cli */,
      server,
      share,
      &auth_info,
      true /* show_hdr */,
      false /* force_encrypt */,
      PROTOCOL_SMB3_00
      /* max_protocol. If we use higher versions, some SMB server might reject
         the connection request due to different reasons. Since we don't need
         the new features in PROTOCOL_SMB3_XX anyway, PROTOCOL_SMB3_00 is good
         enough. */,
      0 /* port */,
      0x20 /* name_type */,
      &conn);

  if (!NT_STATUS_IS_OK(nt_status)) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "smbc_wrapper_cli_full_connection failed: %s",
             nt_errstr(nt_status));
    context->nt_status = NT_STATUS_V(nt_status);
    TALLOC_FREE(mem_ctx);
    return -1;
  }

  context->conn = conn;
  context->max_read_size = smb2cli_conn_max_read_size(conn->conn);
  context->max_write_size = smb2cli_conn_max_write_size(conn->conn);
  context->nt_status = NT_STATUS_V(NT_STATUS_OK);
  TALLOC_FREE(mem_ctx);
  return 0;
}

/*****************************************************************************/

int smbc_wrapper_shutdown_connection(smbc_wrapper_context* context) {
  if (!smbc_wrapper_check_context_status(context)) {
    return -1;
  }

  cli_shutdown((struct cli_state*)context->conn);
  context->nt_status = NT_STATUS_V(NT_STATUS_OK);
  return 0;
}

/*****************************************************************************/

smbc_wrapper_share_size_info smbc_wrapper_get_share_size_info(
    smbc_wrapper_context* context) {
  smbc_wrapper_share_size_info result;
  result.success = false;

  if (!smbc_wrapper_check_context_status(context)) {
    return result;
  }

  struct cli_state* cli = (struct cli_state*)context->conn;

  uint16_t fnum = SMBC_WRAPPER_INVALID_FNUM;
  uint32_t desired_access = SEC_DIR_READ_ATTRIBUTE;
  /* Share all accesses (READ & WRITE & DELETE), so that if other users need to
     perform these actions, they will not be blocked by this. */
  uint32_t share_access =
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
  NTSTATUS status = cli_smb2_create_fnum(
      cli,
      "",
      0 /* create_flags */,
      desired_access,
      0 /* file attributes */,
      share_access,
      FILE_OPEN /* create_disposition */,
      0 /* create_options */,
      &fnum,
      NULL /* cr */);

  if (!NT_STATUS_IS_OK(status)) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "Failed to open share root: %s",
             nt_errstr(status));
    context->nt_status = NT_STATUS_V(status);
    return result;
  }

  struct smb2_hnd* ph = NULL;
  status = smbc_wrapper_map_fnum_to_smb2_handle(cli, fnum, &ph);
  if (!NT_STATUS_IS_OK(status)) {
    context->nt_status = NT_STATUS_V(status);
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "Unable to find fnum %u: %s",
             fnum,
             nt_errstr(status));
    cli_smb2_close_fnum(cli, fnum);
    return result;
  }

  TALLOC_CTX* mem_ctx = talloc_stackframe();
  DATA_BLOB outbuf = data_blob_null;
  /* Call getinfo on the handle with info_type SMB2_GETINFO_FS (0x02),
     level 0x07 (SMB2_FILE_FS_FULL_SIZE_INFORMATION). */
  status = smb2cli_query_info(
      cli->conn,
      cli->timeout,
      cli->smb2.session,
      cli->smb2.tcon,
      SMB2_GETINFO_FS,                       /* in_info_type */
      (SMB_FS_FULL_SIZE_INFORMATION - 1000), /* in_file_info_class */
      0xFFFF,                                /* in_max_output_length */
      NULL,                                  /* in_input_buffer */
      0,                                     /* in_additional_info */
      0,                                     /* in_flags */
      ph->fid_persistent,
      ph->fid_volatile,
      mem_ctx,
      &outbuf);

  if (!NT_STATUS_IS_OK(status)) {
    context->nt_status = NT_STATUS_V(status);
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "Unable to query SMB share file system information");
    TALLOC_FREE(mem_ctx);
    cli_smb2_close_fnum(cli, fnum);
    return result;
  }

  /* Parse the result. */
  if (outbuf.length < 32) {
    context->nt_status = NT_STATUS_V(NT_STATUS_INVALID_NETWORK_RESPONSE);
    snprintf(
        context->error_msg,
        SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
        "Response buffer size %u too small for file system full size info",
        outbuf.length);
    TALLOC_FREE(mem_ctx);
    cli_smb2_close_fnum(cli, fnum);
    return result;
  }

  result.total_allocation_units = BVAL(outbuf.data, 0);
  result.caller_available_allocation_units = BVAL(outbuf.data, 8);
  result.actual_available_allocation_units = BVAL(outbuf.data, 16);
  result.sectors_per_allocation_unit = IVAL(outbuf.data, 24);
  result.bytes_per_sector = IVAL(outbuf.data, 28);

  TALLOC_FREE(mem_ctx);
  cli_smb2_close_fnum(cli, fnum);
  context->nt_status = NT_STATUS_V(NT_STATUS_OK);
  result.success = true;
  return result;
}

/*****************************************************************************/

void* smbc_wrapper_talloc_ctx(size_t size, const char* name) {
  return talloc_named_const(NULL, size, name);
}

/*****************************************************************************/

void smbc_wrapper_free(void* ptr) {
  TALLOC_FREE(ptr);
}

/*****************************************************************************/

static NTSTATUS parse_finfo_id_both_directory_info(
    void* mem_ctx,
    uint8_t* dir_data,
    uint32_t dir_data_length,
    smbc_wrapper_entity_metadata** result,
    int *result_idx,
    uint32_t* next_offset) {
  size_t namelen = 0;
  size_t slen = 0;
  size_t ret = 0;

  if (dir_data_length < 4) {
    return NT_STATUS_INFO_LENGTH_MISMATCH;
  }

  *next_offset = IVAL(dir_data, 0);

  if (*next_offset > dir_data_length) {
    return NT_STATUS_INFO_LENGTH_MISMATCH;
  }

  if (*next_offset != 0) {
    /* Ensure we only read what in this record. */
    dir_data_length = *next_offset;
  }

  if (dir_data_length < 105) {
    return NT_STATUS_INFO_LENGTH_MISMATCH;
  }

  char *name = NULL;
  namelen = IVAL(dir_data + 60,0);
  if (namelen > (dir_data_length - 104)) {
    return NT_STATUS_INFO_LENGTH_MISMATCH;
  }

  ret = pull_string_talloc(mem_ctx,
        dir_data,
        FLAGS2_UNICODE_STRINGS,
        &name,
        dir_data + 104,
        namelen,
        STR_UNICODE);

  if (ret == (size_t)-1) {
    /* Bad conversion. */
    return NT_STATUS_INVALID_NETWORK_RESPONSE;
  }

  if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
    TALLOC_FREE(name);
    return NT_STATUS_OK;
  }

  result[*result_idx] = talloc(mem_ctx, smbc_wrapper_readirplus_entry);

  smbc_wrapper_readirplus_entry* readirplus_entry = result[*result_idx];

  readirplus_entry->name = name;

  smbc_wrapper_entity_metadata* finfo = &readirplus_entry->metadata;

  finfo->create_time_ts = interpret_long_date((const char *)dir_data + 8);
  finfo->access_time_ts = interpret_long_date((const char *)dir_data + 16);
  finfo->modify_time_ts = interpret_long_date((const char *)dir_data + 24);
  finfo->change_time_ts = interpret_long_date((const char *)dir_data + 32);
  finfo->size = IVAL2_TO_SMB_BIG_UINT(dir_data + 40, 0);
  finfo->allocation_size = IVAL2_TO_SMB_BIG_UINT(dir_data + 48, 0);
  finfo->attributes = CVAL(dir_data + 56, 0);
  finfo->inode_id = IVAL2_TO_SMB_BIG_UINT(dir_data + 96, 0);
  (*result_idx)++;
  return NT_STATUS_OK;
}

/*****************************************************************************/

char** smbc_wrapper_list_dir_helper(const char* path,
                             smbc_wrapper_context* context,
                             void* mem_ctx,
                             uint16_t* fnum,
                             uint32_t* result_size,
                             smbc_bool is_readdir_plus) {
  if (!smbc_wrapper_check_context_status(context)) {
    return NULL;
  }

  /* Start with an unsuccessful default nt_status value. */
  context->nt_status = NT_STATUS_V(NT_STATUS_UNSUCCESSFUL);

  if (!mem_ctx) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "Invalid mem_ctx provided for directory %s",
             path);
    return NULL;
  }

  struct cli_state* cli = (struct cli_state*)context->conn;

  /* Get the parent directory name. */
  const char* mask = NULL;
  char* parent_dir = smbc_wrapper_get_parent_dir(mem_ctx, path, &mask);
  if (!parent_dir) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "Memory allocation failed for getting parent_dirname");
    goto fail;
  }

  NTSTATUS status = NT_STATUS_OK;
  if (*fnum == SMBC_WRAPPER_INVALID_FNUM) {
    /* Create a new fnum if the provided one is not valid. */

    /* Share all accesses (READ & WRITE & DELETE), so that if other users need
       to perform these actions, they will not be blocked by this. */
    uint32_t share_access =
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    /* We set FILE_OPEN_FOR_BACKUP_INTENT in create_options to overide any
       security check in place for backup if possible. */
    status = cli_smb2_create_fnum(
        cli,
        parent_dir,
        0 /* create_flags */,
        SEC_DIR_LIST | SEC_DIR_READ_ATTRIBUTE /* desired_access */,
        FILE_ATTRIBUTE_DIRECTORY /* file attributes */,
        share_access,
        FILE_OPEN /* create_disposition */,
        FILE_DIRECTORY_FILE | FILE_OPEN_FOR_BACKUP_INTENT /* create_options */,
        fnum,
        NULL /* cr */);
  }
  TALLOC_FREE(parent_dir);

  if (!NT_STATUS_IS_OK(status)) {
    snprintf(context->error_msg, SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "cli_smb2_create_fnum failed: %s",
             nt_errstr(status));
    context->nt_status = NT_STATUS_V(status);
    goto fail;
  }

  struct smb2_hnd* ph = NULL;
  status = smbc_wrapper_map_fnum_to_smb2_handle(cli, *fnum, &ph);
  if (!NT_STATUS_IS_OK(status)) {
    snprintf(context->error_msg, SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "smbc_wrapper_map_fnum_to_smb2_handle failed: %s",
             nt_errstr(status));
    context->nt_status = NT_STATUS_V(status);
    goto fail;
  }

  /* How many smb2cli_query_directory calls do we want to make for each
     smbc_wrapper_list_dir. This is because it requires at least 2 calls to get
     STATUS_NO_MORE_FILES, thus it would be inefficient to let the client issue
     two calls to smbc_wrapper_list_dir every time for a small directory. */
  int calls = 2;
  uint32_t capacity = 2048;
  uint32_t result_idx = 0;
  void **result = NULL;
  if (is_readdir_plus) {
    result =
        talloc_zero_array(mem_ctx, smbc_wrapper_readirplus_entry*, capacity);
  } else {
    result = talloc_zero_array(mem_ctx, char*, capacity);
  }

  if (!result) {
    snprintf(context->error_msg, SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "Memory allocation failed for child names array");
    goto fail;
  }

  while (calls > 0) {
    uint8_t* dir_data = NULL;
    uint32_t dir_data_length = 0;
    status = smb2cli_query_directory(cli->conn,
                                     cli->timeout,
                                     cli->smb2.session,
                                     cli->smb2.tcon,
                                     is_readdir_plus
                                         ? SMB2_FIND_ID_BOTH_DIRECTORY_INFO
                                         : SMB2_FIND_NAME_INFO,
                                     0 /* flags */,
                                     0 /* file_index */,
                                     ph->fid_persistent,
                                     ph->fid_volatile,
                                     mask,
                                     32 * 1024 /* max TCP buffer size */,
                                     mem_ctx,
                                     &dir_data,
                                     &dir_data_length);
    uint8_t* dir_data_start = dir_data;
    uint32_t total_dir_data_len = dir_data_length;

    if (!NT_STATUS_IS_OK(status)) {
      if (NT_STATUS_EQUAL(status, STATUS_NO_MORE_FILES)) {
        if (*fnum != SMBC_WRAPPER_INVALID_FNUM) {
          cli_smb2_close_fnum(cli, *fnum);
          *fnum = SMBC_WRAPPER_INVALID_FNUM;
        }
        *result_size = result_idx;
        context->nt_status = NT_STATUS_V(NT_STATUS_OK);
        return result;
      }
      snprintf(context->error_msg, SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
               "smb2cli_query_directory failed: %s",
               nt_errstr(status));
      context->nt_status = NT_STATUS_V(status);
      goto fail;
    }

    uint32_t next_offset = 0;
    do {
      if (result_idx >= capacity) {
        capacity *= 2;
        if (is_readdir_plus) {
          result = talloc_realloc(
              mem_ctx, result, smbc_wrapper_entity_metadata*, capacity);
        } else {
          result = talloc_realloc(mem_ctx, result, char*, capacity);
        }
        /* Stop trying to get more children since we have already exceeded the
           capacity. */
        calls = 0;
        if (!result) {
          snprintf(context->error_msg, SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
                   "Memory reallocation failed for child names array");
          goto fail;
        }
        printf("Capacity for %s doubled to %u\n", path, capacity);
      }

      if (is_readdir_plus) {
        status = parse_finfo_id_both_directory_info(mem_ctx,
                                                    dir_data,
                                                    dir_data_length,
                                                    result,
                                                    &result_idx,
                                                    &next_offset);
      } else {
        status = smbc_wrapper_parse_next_name(mem_ctx,
                                              dir_data,
                                              dir_data_length,
                                              result,
                                              &result_idx,
                                              &next_offset,
                                              context,
                                              dir_data - dir_data_start,
                                              total_dir_data_len);
      }

      if (!NT_STATUS_IS_OK(status)) {
        printf(
            "%s failed for path: %s, "
            "dir_data_length:[%u], result_idx:[%u], next_offset:[%u], "
            "total_dir_data_len:[%u]\n",
            is_readdir_plus ? "parse_finfo_id_both_directory_info"
                            : "smbc_wrapper_parse_next_name",
            path,
            dir_data_length,
            result_idx,
            next_offset,
            total_dir_data_len);
        goto fail;
      }

      if (next_offset) {
        dir_data += next_offset;
        dir_data_length -= next_offset;
      }
    } while (next_offset != 0);

    if (result_idx == 0) {
      /* This is an empty directory (we skipped "." and ".."). */
      cli_smb2_close_fnum(cli, *fnum);
      *fnum = SMBC_WRAPPER_INVALID_FNUM;
      *result_size = result_idx;
      context->nt_status = NT_STATUS_V(NT_STATUS_OK);
      return result;
    }

    --calls;
  }

  *result_size = result_idx;
  context->nt_status = NT_STATUS_V(NT_STATUS_OK);
  return result;

 fail:
  if (*fnum != SMBC_WRAPPER_INVALID_FNUM) {
    cli_smb2_close_fnum(cli, *fnum);
    *fnum = SMBC_WRAPPER_INVALID_FNUM;
  }
  return NULL;
}

/*****************************************************************************/

char** smbc_wrapper_list_dir(const char* path,
                             smbc_wrapper_context* context,
                             void* mem_ctx,
                             uint16_t* fnum,
                             uint32_t* result_size) {
  return smbc_wrapper_list_dir_helper(
      path, context, mem_ctx, fnum, result_size, 0 /* is_readdir_plus */);
}

/*****************************************************************************/

smbc_wrapper_readirplus_entry** smbc_wrapper_list_dirplus(
    const char* path,
    smbc_wrapper_context* context,
    void* mem_ctx,
    uint16_t* fnum,
    uint32_t* result_size) {
  return smbc_wrapper_list_dir_helper(
      path, context, mem_ctx, fnum, result_size, 1 /* is_readdir_plus */);
 }

/*****************************************************************************/

void smbc_wrapper_free_names(char** names, uint32_t size) {
  if (!names) {
    return;
  }

  /* Free all the names inside the array before freeing the array itself. */
  uint32_t ii;
  for (ii = 0; ii < size; ++ii) {
    TALLOC_FREE(names[ii]);
  }

  TALLOC_FREE(names);
}

/*****************************************************************************/

smbc_wrapper_entity_metadata* smbc_wrapper_get_metadata(
    const char* path,
    smbc_wrapper_context* context,
    void* mem_ctx) {
  if (!smbc_wrapper_check_context_status(context)) {
    return NULL;
  }

  if (!mem_ctx) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "Invalid mem_ctx provided for entity %s",
             path);
    context->nt_status = NT_STATUS_V(NT_STATUS_UNSUCCESSFUL);
    return NULL;
  }

  struct cli_state* cli = (struct cli_state*)context->conn;

  uint16_t fnum = SMBC_WRAPPER_INVALID_FNUM;
  uint32_t desired_access = SEC_STD_READ_CONTROL | SEC_DIR_READ_ATTRIBUTE;
  /* Share all accesses (READ & WRITE & DELETE), so that if other users need to
     perform these actions, they will not be blocked by this. */
  uint32_t share_access =
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

  /* We set FILE_OPEN_FOR_BACKUP_INTENT in create_options to overide any
     security check in place for backup if possible.
     And also set FILE_OPEN_REPARSE_POINT so that the create response has
     FILE_ATTRIBUTE_REPARSE_POINT set, in case of reparse points. */
  uint32_t create_options =
    FILE_OPEN_FOR_BACKUP_INTENT | FILE_OPEN_REPARSE_POINT;
  NTSTATUS status = cli_smb2_create_fnum(
      cli,
      path,
      0 /* create_flags */,
      desired_access,
      0 /* file attributes */,
      share_access,
      FILE_OPEN /* create_disposition */,
      create_options,
      &fnum,
      NULL /* cr */);

  if (!NT_STATUS_IS_OK(status)) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "Failed to open: %s",
             nt_errstr(status));
    context->nt_status = NT_STATUS_V(status);
    return NULL;
  }

  /* Get the basic metadata for this entity. */
  smbc_wrapper_entity_metadata* result =
      talloc_zero(mem_ctx, smbc_wrapper_entity_metadata);
  status = smbc_wrapper_query_entity_metadata(cli, fnum, mem_ctx, result);

  if (!NT_STATUS_IS_OK(status)) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "smbc_wrapper_query_entity_metadata failed: %s",
             nt_errstr(status));
    context->nt_status = NT_STATUS_V(status);
    cli_smb2_close_fnum(cli, fnum);
    return NULL;
  }

  /* Get the ACLs for this entity. */
  uint32_t sec_info = SECINFO_OWNER | SECINFO_GROUP | SECINFO_DACL;
  status =
      smbc_wrapper_query_entity_acls(cli, fnum, mem_ctx, sec_info, result);
  cli_smb2_close_fnum(cli, fnum);
  if (!NT_STATUS_IS_OK(status)) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "Failed to query security descriptor: %s",
             nt_errstr(status));
    context->nt_status = NT_STATUS_V(status);
    return NULL;
  }

  context->nt_status = NT_STATUS_V(NT_STATUS_OK);
  return result;
}

/*****************************************************************************/

int smbc_wrapper_set_metadata(const char *path,
                              smbc_wrapper_context *context,
                              smbc_bool set_file_info,
                              smbc_bool set_acl_info,
                              uint32_t additional_info,
                              smbc_wrapper_entity_metadata *md) {
  if (!smbc_wrapper_check_context_status(context)) {
    return -1;
  }

  struct cli_state* cli = (struct cli_state*)context->conn;

  uint16_t fnum = SMBC_WRAPPER_INVALID_FNUM;
  uint32_t desired_access = FILE_WRITE_ATTRIBUTES | SEC_STD_READ_CONTROL |
                            SEC_STD_WRITE_DAC | SEC_STD_WRITE_OWNER;
  bool is_offline = md->attributes & 0x1000;
  if (is_offline) {
    // When the file is offline, we need to set its size related attributes
    // and need this additional access right.
    desired_access |= FILE_WRITE_DATA;
  }

  /* Share all accesses (READ & WRITE & DELETE), so that if other users need to
     perform these actions, they will not be blocked by this. */
  uint32_t share_access =
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

  /* We set FILE_OPEN_FOR_BACKUP_INTENT in create_options to overide any
     security check in place for backup if possible. */
  NTSTATUS status = cli_smb2_create_fnum(
      cli,
      path,
      0 /* create_flags */,
      desired_access,
      0 /* file attributes */,
      share_access,
      FILE_OPEN /* create_disposition */,
      FILE_OPEN_FOR_BACKUP_INTENT /* create_options */,
      &fnum,
      NULL /* cr */);

  if (!NT_STATUS_IS_OK(status)) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "Failed to open: %s",
             nt_errstr(status));
    context->nt_status = NT_STATUS_V(status);
    return -1;
  }

  // Set the sparse bit on destination file first as behaviour of
  // 'smbc_wrapper_set_end_of_file' depends on it.
  if (md->attributes & 0x200) {
    // If sparse bit is set, we need to set it explicitly.
    status = smbc_wrapper_set_sparse(cli, fnum);

    if (!NT_STATUS_IS_OK(status)) {
      snprintf(context->error_msg,
               SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
               "smbc_wrapper_set_sparse failed: %s",
               nt_errstr(status));
      context->nt_status = NT_STATUS_V(status);
      cli_smb2_close_fnum(cli, fnum);
      return -1;
    }
  }

  if (is_offline) {
    /* For offline files, size on disk is different than logical size. Set the
       end of file information for this entity. */
    status = smbc_wrapper_set_end_of_file(cli, fnum, md->size);

    if (!NT_STATUS_IS_OK(status)) {
      snprintf(context->error_msg,
               SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
               "smbc_wrapper_set_end_of_file failed: %s",
               nt_errstr(status));
      context->nt_status = NT_STATUS_V(status);
      cli_smb2_close_fnum(cli, fnum);
      return -1;
    }
  }

  if (set_file_info) {
    /* Set the basic file info for this entity. */
    status = smbc_wrapper_set_file_basic_information(
        cli, fnum, 0 /* additional_info */, md);

    if (!NT_STATUS_IS_OK(status)) {
      snprintf(context->error_msg,
               SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
               "smbc_wrapper_set_file_basic_information failed: %s",
               nt_errstr(status));
      context->nt_status = NT_STATUS_V(status);
      cli_smb2_close_fnum(cli, fnum);
      return -1;
    }
  }

  if (set_acl_info) {
    /* Set the security info for this entity. */
    status = smbc_wrapper_set_entity_acls(cli, fnum, additional_info, md);

    if (!NT_STATUS_IS_OK(status)) {
      snprintf(context->error_msg,
               SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
               "smbc_wrapper_set_entity_acls failed: %s",
               nt_errstr(status));
      context->nt_status = NT_STATUS_V(status);
      cli_smb2_close_fnum(cli, fnum);
      return -1;
    }
  }

  context->nt_status = NT_STATUS_V(NT_STATUS_OK);
  cli_smb2_close_fnum(cli, fnum);
  return 0;
}

/*****************************************************************************/

void smbc_wrapper_free_metadata(smbc_wrapper_entity_metadata* md) {
  if (!md) {
    return;
  }

  TALLOC_FREE(md->acls);
  TALLOC_FREE(md);
}

/*****************************************************************************/

uint8_t* smbc_wrapper_fetch_file_data(const char* path,
                                      smbc_wrapper_context* context,
                                      void* mem_ctx,
                                      uint64_t offset,
                                      uint32_t size,
                                      uint32_t* data_read,
                                      uint16_t* fnum,
                                      uint32_t timeout_msecs) {
  if (!smbc_wrapper_check_context_status(context)) {
    return NULL;
  }

  /* Start with an unsuccessful default nt_status value. */
  context->nt_status = NT_STATUS_V(NT_STATUS_UNSUCCESSFUL);

  if (!path) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "File path pointer cannot be null");
    return NULL;
  }

  if (strlen(path) == 0) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "File path cannot be empty for smbc_wrapper_fetch_file_data");
    return NULL;
  }

  if (!mem_ctx) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "Invalid mem_ctx provided for entity %s",
             path);
    return NULL;
  }

  if (size == 0) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "Size must be greater than 0 for smbc_wrapper_fetch_file_data");
    return NULL;
  }

  if (!data_read) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "data_read pointer cannot be null");
    return NULL;
  }

  struct cli_state* cli = (struct cli_state*)context->conn;

  NTSTATUS status;
  uint16_t this_fnum = SMBC_WRAPPER_INVALID_FNUM;
  if (!fnum || *fnum == SMBC_WRAPPER_INVALID_FNUM) {
    uint32_t desired_access = SEC_FILE_READ_DATA;
    /* Share all accesses (READ & WRITE & DELETE), so that if other users need
       to perform these actions, they will not be blocked by this. */
    uint32_t share_access =
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    /* We set FILE_OPEN_FOR_BACKUP_INTENT in create_options to overide any
       security check in place for backup if possible. */
    uint32_t create_options =
        FILE_NON_DIRECTORY_FILE | FILE_OPEN_FOR_BACKUP_INTENT;

    status = cli_smb2_create_fnum(cli,
                                  path,
                                  0 /* create_flags */,
                                  desired_access,
                                  0 /* file attributes */,
                                  share_access,
                                  FILE_OPEN /* create_disposition */,
                                  create_options,
                                  &this_fnum,
                                  NULL /* cr */);

    if (!NT_STATUS_IS_OK(status)) {
      snprintf(context->error_msg,
               SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
               "Failed to open: %s",
               nt_errstr(status));
      context->nt_status = NT_STATUS_V(status);
      return NULL;
    }

    if (fnum) {
      *fnum = this_fnum;
    }
  } else {
    this_fnum = *fnum;
  }

  struct smb2_hnd* ph = NULL;
  status = smbc_wrapper_map_fnum_to_smb2_handle(cli, this_fnum, &ph);
  if (!NT_STATUS_IS_OK(status)) {
    snprintf(context->error_msg, SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "smbc_wrapper_map_fnum_to_smb2_handle failed: %s.",
             nt_errstr(status));
    context->nt_status = NT_STATUS_V(status);
    // Close the fnum if there is an error. The caller should remove it from
    // the cache when seeing an error.
    cli_smb2_close_fnum(cli, this_fnum);
    return NULL;
  }

  uint8_t* data = NULL;
  status = smb2cli_read(
      cli->conn,
      timeout_msecs,
      cli->smb2.session,
      cli->smb2.tcon,
      size,
      offset,
      ph->fid_persistent,
      ph->fid_volatile,
      1 /* minimum_count */,
      0 /* remaining_bytes (to help server read ahead) */,
      mem_ctx,
      &data,
      data_read);

  // Close the fnum if this is a one time access.
  if (!fnum) {
    cli_smb2_close_fnum(cli, this_fnum);
  }

  if (!NT_STATUS_IS_OK(status)) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "smb2cli_read failed at offset %u for size %u: %s",
             offset,
             size,
             nt_errstr(status));
    context->nt_status = NT_STATUS_V(status);
    return NULL;
  }

  context->nt_status = NT_STATUS_V(NT_STATUS_OK);
  return data;
}

/*****************************************************************************/

uint32_t smbc_wrapper_write_file_data(const char* path,
                                      smbc_wrapper_context* context,
                                      uint64_t offset,
                                      uint32_t size,
                                      const uint8_t* data,
                                      uint16_t* fnum,
                                      uint32_t timeout_msecs) {
  if (!smbc_wrapper_check_context_status(context)) {
    return 0;
  }

  /* Start with an unsuccessful default nt_status value. */
  context->nt_status = NT_STATUS_V(NT_STATUS_UNSUCCESSFUL);

  if (!path) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "File path pointer cannot be null");
    return 0;
  }

  if (strlen(path) == 0) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "File path cannot be empty for smbc_wrapper_write_file_data");
    return 0;
  }

  if (size == 0) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "Size must be greater than 0 for smbc_wrapper_write_file_data");
    return 0;
  }

  if (!data)  {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "Data cannot be null for smbc_wrapper_write_file_data");
    return 0;
  }

  struct cli_state* cli = (struct cli_state*)context->conn;

  NTSTATUS status;
  uint16_t this_fnum = SMBC_WRAPPER_INVALID_FNUM;
  if (!fnum || *fnum == SMBC_WRAPPER_INVALID_FNUM) {
    uint32_t desired_access = SEC_FILE_WRITE_DATA | SEC_FILE_READ_DATA;
    // Share all accesses (READ & WRITE & DELETE), so that if other users need
    // to perform these actions, they will not be blocked by this.
    uint32_t share_access =
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

    status = cli_smb2_create_fnum(cli,
                                  path,
                                  0 /* create_flags */,
                                  desired_access,
                                  0 /* file attributes */,
                                  share_access,
                                  FILE_OPEN /* create_disposition */,
                                  0 /* create operations */,
                                  &this_fnum,
                                  NULL /* cr */);

    if (!NT_STATUS_IS_OK(status)) {
      snprintf(context->error_msg,
               SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
               "Failed to open: %s",
               nt_errstr(status));
      context->nt_status = NT_STATUS_V(status);
      return 0;
    }

    if (fnum) {
      *fnum = this_fnum;
    }
  } else {
    this_fnum = *fnum;
  }

  struct smb2_hnd* ph = NULL;
  status = smbc_wrapper_map_fnum_to_smb2_handle(cli, this_fnum, &ph);
  if (!NT_STATUS_IS_OK(status)) {
    snprintf(context->error_msg, SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "smbc_wrapper_map_fnum_to_smb2_handle failed: %s.",
             nt_errstr(status));
    context->nt_status = NT_STATUS_V(status);
    // Close the fnum if there is an error. The caller should remove it from
    // the cache when seeing an error.
    cli_smb2_close_fnum(cli, this_fnum);
    return 0;
  }

  uint32_t data_written = 0;
  status = smb2cli_write(
      cli->conn,
      timeout_msecs,
      cli->smb2.session,
      cli->smb2.tcon,
      size,
      offset,
      ph->fid_persistent,
      ph->fid_volatile,
      0 /* remaining_bytes */,
      0 /* flags */,
      data,
      &data_written);

  // Close the fnum if this is a one time access.
  if (!fnum) {
    cli_smb2_close_fnum(cli, this_fnum);
  }

  if (!NT_STATUS_IS_OK(status)) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "smb2cli_write failed at offset %u for size %u: %s",
             offset,
             size,
             nt_errstr(status));
    context->nt_status = NT_STATUS_V(status);
    return 0;
  }

  context->nt_status = NT_STATUS_V(NT_STATUS_OK);
  return data_written;
}

/*****************************************************************************/

int smbc_wrapper_close_fnum(smbc_wrapper_context* context,
                            uint16_t fnum) {
  if (!smbc_wrapper_check_context_status(context)) {
    return -1;
  }

  struct cli_state* cli = (struct cli_state*)context->conn;
  NTSTATUS status = cli_smb2_close_fnum(cli, fnum);
  if (!NT_STATUS_IS_OK(status)) {
    snprintf(context->error_msg, SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "cli_smb2_close_fnum failed for root: %s", nt_errstr(status));
    context->nt_status = NT_STATUS_V(status);
    return -1;
  }

  context->nt_status = NT_STATUS_V(NT_STATUS_OK);
  return 0;
}

/*****************************************************************************/

int smbc_wrapper_create_object(const char *path,
                               smbc_wrapper_context* context,
                               smbc_bool is_file) {
  if (!smbc_wrapper_check_context_status(context)) {
    return -1;
  }
  struct cli_state* cli = (struct cli_state*)context->conn;

  if (!path) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "Object path pointer cannot be null");
    return -1;
  }

  if (strlen(path) == 0) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "Object path cannot be empty for smbc_wrapper_create_object");
    return -1;
  }

  NTSTATUS status;

  uint16_t fnum = SMBC_WRAPPER_INVALID_FNUM;

  uint32_t desired_access = SEC_FILE_READ_DATA;

  /* Share all accesses (READ & WRITE & DELETE), so that if other users need to
     perform these actions, they will not be blocked by this. */
  uint32_t share_access =
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

  /* Open the file if it already exists; otherwise, create the file */
  uint32_t create_disposition = FILE_CREATE;

  uint32_t file_attribute = 0;
  uint32_t create_options = 0;

  if (is_file) {
    /* We set FILE_OPEN_FOR_BACKUP_INTENT in create_options to overide any
       security check in place for backup if possible. */
    create_options = FILE_NON_DIRECTORY_FILE | FILE_OPEN_FOR_BACKUP_INTENT;
  } else {
    /* This item is a directory */
    file_attribute = FILE_ATTRIBUTE_DIRECTORY;
    create_options = FILE_DIRECTORY_FILE;
  }

  status = cli_smb2_create_fnum(cli,
                                path,
                                0 /* create_flags */,
                                desired_access,
                                file_attribute,
                                share_access,
                                create_disposition,
                                create_options,
                                &fnum,
                                NULL /* cr */);

  if (!NT_STATUS_IS_OK(status)) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "Failed to open: %s",
             nt_errstr(status));
    context->nt_status = NT_STATUS_V(status);
    return -1;
  }

  return smbc_wrapper_close_fnum(context, fnum);
}

/*****************************************************************************/

int smbc_wrapper_delete_object(const char *path,
                               smbc_wrapper_context* context) {
  if (!smbc_wrapper_check_context_status(context)) {
    return -1;
  }
  struct cli_state* cli = (struct cli_state*)context->conn;

  if (!path) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "Object path pointer cannot be null");
    return -1;
  }

  if (strlen(path) == 0) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "Object path cannot be empty for smbc_wrapper_delete_object");
    return -1;
  }

  NTSTATUS status;
  status = cli_smb2_unlink(cli, path);

  if (!NT_STATUS_IS_OK(status)) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "Failed to delete: %s",
             nt_errstr(status));
    context->nt_status = NT_STATUS_V(status);
    return -1;
  }

  return 0;
}

/*****************************************************************************/

int smbc_wrapper_delete_directory(const char* path,
                                  smbc_wrapper_context* context) {
  if (!smbc_wrapper_check_context_status(context)) {
    return -1;
  }
  struct cli_state* cli = (struct cli_state*)context->conn;

  if (!path) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "Directory path pointer cannot be null");
    return -1;
  }

  if (strlen(path) == 0) {
    snprintf(
        context->error_msg,
        SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
        "Directory path cannot be empty for smbc_wrapper_delete_directory");
    return -1;
  }

  NTSTATUS status;
  status = cli_smb2_rmdir(cli, path);

  if (!NT_STATUS_IS_OK(status)) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "Failed to delete: %s",
             nt_errstr(status));
    context->nt_status = NT_STATUS_V(status);
    return -1;
  }

  return 0;
}

/*****************************************************************************/

int smbc_wrapper_rename_object(const char* old_path,
                               const char* new_path,
                               smbc_wrapper_context* context) {
  if (!smbc_wrapper_check_context_status(context)) {
    return -1;
  }
  struct cli_state* cli = (struct cli_state*)context->conn;

  if (!old_path || !new_path) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "Object path pointer cannot be null");
    return -1;
  }

  if (strlen(old_path) == 0 || strlen(new_path) == 0) {
    snprintf(
        context->error_msg,
        SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
        "Object path cannot be empty for smbc_wrapper_rename_object");
    return -1;
  }

  NTSTATUS status;
  status = cli_smb2_rename(cli, old_path, new_path);

  if (!NT_STATUS_IS_OK(status)) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "Failed to rename with error: %s",
             nt_errstr(status));
    context->nt_status = NT_STATUS_V(status);
    return -1;
  }

  return 0;
}

/*****************************************************************************/

int smbc_wrapper_create_hardlink(const char* old_path,
                                 const char* new_path,
                                 smbc_wrapper_context* context) {
  if (!smbc_wrapper_check_context_status(context)) {
    return -1;
  }

  if (!old_path || strlen(old_path) == 0) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "Old path cannot be null or empty");
    return -1;
  }

  if (!new_path || strlen(new_path) == 0) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "New path cannot be null or empty");
    return -1;
  }

  struct cli_state* cli = (struct cli_state*)context->conn;

  uint16_t fnum = SMBC_WRAPPER_INVALID_FNUM;
  uint32_t desired_access =
      SEC_STD_READ_CONTROL | SEC_STD_WRITE_DAC | SEC_STD_WRITE_OWNER;
  /* Share all accesses (READ & WRITE & DELETE), so that if other users need to
     perform these actions, they will not be blocked by this. */
  uint32_t share_access =
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

  /* We set FILE_OPEN_FOR_BACKUP_INTENT in create_options to overide any
     security check in place for backup if possible. */
  NTSTATUS status =
      cli_smb2_create_fnum(cli,
                           old_path,
                           0 /* create_flags */,
                           desired_access,
                           0 /* file attributes */,
                           share_access,
                           FILE_OPEN /* create_disposition */,
                           FILE_OPEN_FOR_BACKUP_INTENT /* create_options */,
                           &fnum,
                           NULL /* cr */);

  if (!NT_STATUS_IS_OK(status)) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "Failed to open: %s",
             nt_errstr(status));
    context->nt_status = NT_STATUS_V(status);
    return -1;
  }

  struct smb2_hnd* ph = NULL;
  status = smbc_wrapper_map_fnum_to_smb2_handle(cli, fnum, &ph);
  if (!NT_STATUS_IS_OK(status)) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "Failed to get smb2 handle: %s",
             nt_errstr(status));
    context->nt_status = NT_STATUS_V(status);
    cli_smb2_close_fnum(cli, fnum);
    return -1;
  }

  DATA_BLOB inbuf = data_blob_null;
  TALLOC_CTX* inbuf_store = talloc_stackframe();
  smb_ucs2_t *converted_str = NULL;
  size_t converted_size_bytes = 0;

  // SMB2 is pickier about pathnames. Ensure it doesn't start in a '\'.
  if (*new_path == '\\') {
    new_path++;
  }

  // SMB2 is pickier about pathnames. Ensure it doesn't end in a '\'.
  size_t namelen = strlen(new_path);
  if (namelen > 0 && new_path[namelen - 1] == '\\') {
    char* modname = talloc_strdup(inbuf_store, new_path);
    modname[namelen - 1] = '\0';
    new_path = modname;
  }

  if (!push_ucs2_talloc(
          inbuf_store, &converted_str, new_path, &converted_size_bytes)) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "Failed to convert new_path to ucs2 string: %s",
             nt_errstr(NT_STATUS_INVALID_PARAMETER));
    context->nt_status = NT_STATUS_V(NT_STATUS_INVALID_PARAMETER);
    cli_smb2_close_fnum(cli, fnum);
    TALLOC_FREE(inbuf_store);
    return -1;
  }
  // Remove last two bytes to remove null termination.
  converted_size_bytes -= 2;

  inbuf = data_blob_talloc_zero(inbuf_store, 20 + converted_size_bytes);
  if (inbuf.data == NULL) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "Failed to allocate memory: %s",
             nt_errstr(NT_STATUS_NO_MEMORY));
    context->nt_status = NT_STATUS_V(NT_STATUS_NO_MEMORY);
    cli_smb2_close_fnum(cli, fnum);
    TALLOC_FREE(inbuf_store);
    return -1;
  }

  SIVAL(inbuf.data, 0x10, converted_size_bytes);
  memcpy(inbuf.data + 0x14, converted_str, converted_size_bytes);

  /* Set file link information on the handle. */
  status = smb2cli_set_info(
      cli->conn,
      cli->timeout,
      cli->smb2.session,
      cli->smb2.tcon,
      1,                                  /* in_info_type */
      (SMB_FILE_LINK_INFORMATION - 1000), /* in_file_info_class */
      &inbuf,                             /* in_input_buffer */
      0,                                  /* in_additional_info */
      ph->fid_persistent,
      ph->fid_volatile);

  cli_smb2_close_fnum(cli, fnum);
  TALLOC_FREE(inbuf_store);

  if (!NT_STATUS_IS_OK(status)) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "Failed to create hardlink with error: %s",
             nt_errstr(status));
    context->nt_status = NT_STATUS_V(status);
    return -1;
  }

  context->nt_status = NT_STATUS_V(NT_STATUS_OK);
  return 0;
}

/*****************************************************************************/

int smbc_wrapper_create_symlink(const char* path,
                                const char* target_path,
                                smbc_wrapper_context* context,
                                uint32_t flags) {
  if (!smbc_wrapper_check_context_status(context)) {
    return -1;
  }

  if (!path || strlen(path) == 0) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "Path cannot be empty for smbc_wrapper_create_symlink");
    return -1;
  }

  if (!target_path || strlen(target_path) == 0) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "Target path cannot be empty for smbc_wrapper_create_symlink");
    return -1;
  }

  struct cli_state* cli = (struct cli_state*)context->conn;
  NTSTATUS status = smbc_wrapper_symlink(cli, path, target_path, flags);
  if (!NT_STATUS_IS_OK(status)) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "smbc_wrapper_create_symlink failed: %s",
             nt_errstr(status));
    context->nt_status = NT_STATUS_V(status);

    // Also delete the leftover link we may have created, but we don't need to
    // check for error for this case, because the link might not have been
    // created.
    smbc_wrapper_delete_object(path, context);
    return -1;
  }

  context->nt_status = NT_STATUS_V(NT_STATUS_OK);
  return 0;
}

/*****************************************************************************/

int smbc_wrapper_read_symlink(const char* path,
                              smbc_wrapper_context* context,
                              void* mem_ctx,
                              char** target_path,
                              uint32_t* flags) {
  if (!smbc_wrapper_check_context_status(context)) {
    return -1;
  }

  // Start with an unsuccessful default nt_status value.
  context->nt_status = NT_STATUS_V(NT_STATUS_UNSUCCESSFUL);

  if (!path || strlen(path) == 0) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "Path cannot be empty for smbc_wrapper_read_symlink");
    return -1;
  }
  if (!mem_ctx) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "Invalid mem_ctx provided for entity %s",
             path);
    return -1;
  }
  if (!target_path) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "Target path cannot be NULL for smbc_wrapper_read_symlink");
    return -1;
  }

  struct cli_state* cli = (struct cli_state*)context->conn;
  NTSTATUS status =
      smbc_wrapper_readsymlink(cli, path, mem_ctx, target_path, flags);
  if (!NT_STATUS_IS_OK(status)) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "smbc_wrapper_readsymlink failed: %s",
             nt_errstr(status));
    context->nt_status = NT_STATUS_V(status);
    return -1;
  }

  context->nt_status = NT_STATUS_V(NT_STATUS_OK);
  return 0;
}

/*****************************************************************************/

int smbc_wrapper_rename(const char* old_path,
                        const char* new_path,
                        smbc_entity_type entity_type,
                        smbc_bool replace_if_exists,
                        smbc_wrapper_context* context) {
  if (!smbc_wrapper_check_context_status(context)) {
    return -1;
  }

  // Verify that old_path is valid.
  if (!old_path || strlen(old_path) == 0) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "Old path cannot be null or empty");
    return -1;
  }

  // Verify that new_path is valid.
  if (!new_path || strlen(new_path) == 0) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "New path cannot be null or empty");
    return -1;
  }

  // We set FILE_OPEN_FOR_BACKUP_INTENT in create_options to overide any
  // security check in place for backup if possible.
  uint32_t create_options = FILE_OPEN_FOR_BACKUP_INTENT;

  // Set FILE_OPEN_REPARSE_POINT if the old_path is a symlink. If the flag
  // is not set, CREATE will fail with STOPPED_ON_SYMLINK error.
  if (entity_type == SMBC_ENTITY_TYPE_SYMLINK) {
    create_options |= FILE_OPEN_REPARSE_POINT;
  } else if (entity_type == SMBC_ENTITY_TYPE_DIRECTORY) {
    create_options |= FILE_DIRECTORY_FILE;
  }

  struct cli_state* cli = (struct cli_state*)context->conn;
  uint16_t fnum = SMBC_WRAPPER_INVALID_FNUM;

  NTSTATUS status = cli_smb2_create_fnum(cli,
                                         old_path,
                                         0 /* create_flags */,
                                         SEC_STD_DELETE /* desired_access */,
                                         0 /* file attributes */,
                                         0 /* share_access */,
                                         FILE_OPEN /* create_disposition */,
                                         create_options,
                                         &fnum,
                                         NULL /* cr */);

  if (!NT_STATUS_IS_OK(status)) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "Failed to open: %s",
             nt_errstr(status));
    context->nt_status = NT_STATUS_V(status);
    return -1;
  }

  struct smb2_hnd* ph = NULL;
  status = smbc_wrapper_map_fnum_to_smb2_handle(cli, fnum, &ph);
  if (!NT_STATUS_IS_OK(status)) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "Failed to get smb2 handle: %s",
             nt_errstr(status));
    context->nt_status = NT_STATUS_V(status);
    cli_smb2_close_fnum(cli, fnum);
    return -1;
  }

  DATA_BLOB inbuf = data_blob_null;
  TALLOC_CTX* inbuf_store = talloc_stackframe();
  smb_ucs2_t* converted_str = NULL;
  size_t converted_size_bytes = 0;

  // SMB2 is pickier about pathnames. Ensure it doesn't start in a '\'.
  if (*new_path == '\\') {
    new_path++;
  }

  // SMB2 is pickier about pathnames. Ensure it doesn't end in a '\'.
  size_t namelen = strlen(new_path);
  if (namelen > 0 && new_path[namelen - 1] == '\\') {
    char* modname = talloc_strdup(inbuf_store, new_path);
    modname[namelen - 1] = '\0';
    new_path = modname;
  }

  if (!push_ucs2_talloc(
          inbuf_store, &converted_str, new_path, &converted_size_bytes)) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "Failed to convert new_path to ucs2 string: %s",
             nt_errstr(NT_STATUS_INVALID_PARAMETER));
    context->nt_status = NT_STATUS_V(NT_STATUS_INVALID_PARAMETER);
    cli_smb2_close_fnum(cli, fnum);
    TALLOC_FREE(inbuf_store);
    return -1;
  }
  // Remove last two bytes to remove null termination.
  converted_size_bytes -= 2;

  inbuf = data_blob_talloc_zero(inbuf_store, 20 + converted_size_bytes);
  if (inbuf.data == NULL) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "Failed to allocate memory: %s",
             nt_errstr(NT_STATUS_NO_MEMORY));
    context->nt_status = NT_STATUS_V(NT_STATUS_NO_MEMORY);
    cli_smb2_close_fnum(cli, fnum);
    TALLOC_FREE(inbuf_store);
    return -1;
  }

  // First byte in the buffer is ReplaceIfExists
  if (replace_if_exists) {
    SCVAL(inbuf.data, 0, 1);
  }

  // File name length starts at offset 16.
  SIVAL(inbuf.data, 0x10, converted_size_bytes);

  // File path starts at offset 20.
  memcpy(inbuf.data + 0x14, converted_str, converted_size_bytes);

  // Use set_info to rename the file.
  status = smb2cli_set_info(
      cli->conn,
      cli->timeout,
      cli->smb2.session,
      cli->smb2.tcon,
      1,                                    /* in_info_type */
      (SMB_FILE_RENAME_INFORMATION - 1000), /* in_file_info_class */
      &inbuf,                               /* in_input_buffer */
      0,                                    /* in_additional_info */
      ph->fid_persistent,
      ph->fid_volatile);

  cli_smb2_close_fnum(cli, fnum);
  TALLOC_FREE(inbuf_store);

  if (!NT_STATUS_IS_OK(status)) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "Failed to rename. Error: %s",
             nt_errstr(status));
    context->nt_status = NT_STATUS_V(status);
    return -1;
  }

  context->nt_status = NT_STATUS_V(NT_STATUS_OK);
  return 0;
}

/*****************************************************************************/

int smbc_wrapper_delete_entity(const char* path,
                               smbc_entity_type entity_type,
                               smbc_wrapper_context* context,
                               smbc_bool is_exclusive) {

  if (!smbc_wrapper_check_context_status(context)) {
    return -1;
  }

  // Verify that path is valid.
  if (!path || strlen(path) == 0) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "Path cannot be null or empty");
    return -1;
  }

  // We set FILE_OPEN_FOR_BACKUP_INTENT in create_options to overide any
  // security check in place for backup if possible.
  // Set FILE_DELETE_ON_CLOSE to delete the entity.
  uint32_t create_options = FILE_OPEN_FOR_BACKUP_INTENT | FILE_DELETE_ON_CLOSE;

  // Set FILE_OPEN_REPARSE_POINT if the path is a symlink. If the flag
  // is not set, CREATE will fail with STOPPED_ON_SYMLINK error.
  if (entity_type == SMBC_ENTITY_TYPE_SYMLINK) {
    create_options |= FILE_OPEN_REPARSE_POINT;
  } else if (entity_type == SMBC_ENTITY_TYPE_DIRECTORY) {
    create_options |= FILE_DIRECTORY_FILE;
  }

  // Share all access to allow the request to succeed even if there are other
  // active opens. Delete-on-close will be performed after all the open handles
  // are closed.
  // If is_exclusive is set to true open with 0 share access.
  uint32_t share_access =
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
  if (is_exclusive){
    share_access = FILE_SHARE_NONE;
  }

  struct cli_state* cli = (struct cli_state*)context->conn;
  uint16_t fnum = SMBC_WRAPPER_INVALID_FNUM;

  NTSTATUS status = cli_smb2_create_fnum(cli,
                                         path,
                                         0 /* create_flags */,
                                         SEC_STD_DELETE /* desired_access */,
                                         0 /* file attributes */,
                                         share_access,
                                         FILE_OPEN /* create_disposition */,
                                         create_options,
                                         &fnum,
                                         NULL /* cr */);

  if (!NT_STATUS_IS_OK(status)) {
    snprintf(context->error_msg,
             SMBC_WRAPPER_MAX_ERROR_MSG_LEN,
             "Failed to open: %s",
             nt_errstr(status));
    context->nt_status = NT_STATUS_V(status);
    return -1;
  }

  cli_smb2_close_fnum(cli, fnum);
  context->nt_status = NT_STATUS_V(NT_STATUS_OK);
  return 0;
}

/*****************************************************************************/

int smbc_wrapper_is_dfs(smbc_wrapper_context* context) {
  if (!context) {
    fprintf(stderr, "context is null in smbc_wrapper_is_dfs!\n");
    return -1;
  }
  struct cli_state* cli = (struct cli_state*)context->conn;
  return smbXcli_conn_dfs_supported(cli->conn) &&
         smbXcli_tcon_is_dfs_share(cli->smb2.tcon);
}

/*****************************************************************************/

char* smbc_wrapper_get_server(smbc_wrapper_context* context) {
  if (!context) {
    fprintf(stderr, "context is null in smbc_wrapper_get_server!\n");
    return NULL;
  }
  struct cli_state* cli = (struct cli_state*)context->conn;
  return smbXcli_conn_remote_name(cli->conn);
}

/*****************************************************************************/

char* smbc_wrapper_get_share(smbc_wrapper_context* context) {
  if (!context) {
    fprintf(stderr, "context is null in smbc_wrapper_get_share!\n");
    return NULL;
  }
  struct cli_state* cli = (struct cli_state*)context->conn;
  return cli->share;
}

/*****************************************************************************/

int smbc_wrapper_get_dfs_referral(smbc_wrapper_context* context,
                                  const char* dfs_path,
                                  char** target_dfs_path,
                                  char** src_dfs_path,
                                  void* mem_ctx,
                                  const char* username,
                                  const char* password,
                                  const char* domain) {
  TALLOC_CTX* frame = talloc_stackframe();

  struct cli_state* rootcli = (struct cli_state*)context->conn;

  NTSTATUS status = cli_get_dfs_referral(mem_ctx,
                                         rootcli,
                                         dfs_path,
                                         target_dfs_path,
                                         src_dfs_path,
                                         username,
                                         password,
                                         domain);
  TALLOC_FREE(frame);

  if (!NT_STATUS_IS_OK(status)) {
    return -1;
  }

  return 0;
}

/*****************************************************************************/

int smbc_wrapper_remote_password_change(const char* remote_machine,
                                        const char* user_name,
                                        const char* old_passwd,
                                        const char* new_passwd,
                                        char** err_str) {
  TALLOC_CTX* frame = talloc_stackframe();
  lp_set_cmdline("client ipc max protocol", "SMB3_11");
  lp_set_cmdline("winbind separator", "\\");
  NTSTATUS status = remote_password_change(
      remote_machine, user_name, old_passwd, new_passwd, err_str);
  TALLOC_FREE(frame);
  if (!NT_STATUS_IS_OK(status)) {
    return -1;
  }

  return 0;
}

/*****************************************************************************/
