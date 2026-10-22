/* $OpenBSD: sftp-client.h,v 1.42 2026/09/07 20:24:22 job Exp $ */

/*
 * Copyright (c) 2001-2004 Damien Miller <djm@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* Client side of SSH2 filexfer protocol */

#ifndef _SFTP_CLIENT_H
#define _SFTP_CLIENT_H

வகைவரை கட்டமைப்பு SFTP_DIRENT SFTP_DIRENT;

கட்டமைப்பு SFTP_DIRENT {
	எழுத்து *filename;
	எழுத்து *longname;
	Attrib a;
};

/*
 * Used for statvfs responses on the wire from the server, because the
 * server's native format may be larger than the client's.
 */
கட்டமைப்பு sftp_statvfs {
	uint64_t f_bsize;
	uint64_t f_frsize;
	uint64_t f_blocks;
	uint64_t f_bfree;
	uint64_t f_bavail;
	uint64_t f_files;
	uint64_t f_ffree;
	uint64_t f_favail;
	uint64_t f_fsid;
	uint64_t f_flag;
	uint64_t f_namemax;
};

/* Used for limits response on the wire from the server */
கட்டமைப்பு sftp_limits {
	uint64_t packet_length;
	uint64_t read_length;
	uint64_t write_length;
	uint64_t open_handles;
};

/* print flag values */
#define SFTP_QUIET		0	/* be quiet during transfers */
#define SFTP_PRINT		1	/* list files and show progress bar */
#define SFTP_PROGRESS_ONLY	2	/* progress bar only */

/*
 * Initialise a SSH filexfer connection. Returns NULL on error or
 * a pointer to a initialized sftp_conn struct on success.
 */
கட்டமைப்பு sftp_conn *sftp_init(முழு, முழு, u_int, u_int, uint64_t);
வெறுமை sftp_free(கட்டமைப்பு sftp_conn *);

u_int sftp_proto_version(கட்டமைப்பு sftp_conn *);

/* Query server limits */
முழு sftp_get_limits(கட்டமைப்பு sftp_conn *, கட்டமைப்பு sftp_limits *);

/* Close file referred to by 'handle' */
முழு sftp_close(கட்டமைப்பு sftp_conn *, மாறிலி u_char *, u_int);

/* Read contents of 'path' to NULL-terminated array 'dir' */
முழு sftp_readdir(கட்டமைப்பு sftp_conn *, மாறிலி எழுத்து *, SFTP_DIRENT ***);

/* Frees a NULL-terminated array of SFTP_DIRENTs (eg. from sftp_readdir) */
வெறுமை sftp_free_dirents(SFTP_DIRENT **);

/* Delete file 'path' */
முழு sftp_rm(கட்டமைப்பு sftp_conn *, மாறிலி எழுத்து *);

/* Create directory 'path' */
முழு sftp_mkdir(கட்டமைப்பு sftp_conn *, மாறிலி எழுத்து *, Attrib *, முழு);

/* Create directory 'path' and intermediate directories as required */
முழு sftp_mkpath(கட்டமைப்பு sftp_conn *, மாறிலி எழுத்து *, Attrib *, முழு);

/* Remove directory 'path' */
முழு sftp_rmdir(கட்டமைப்பு sftp_conn *, மாறிலி எழுத்து *);

/* Get file attributes of 'path' (follows symlinks) */
முழு sftp_stat(கட்டமைப்பு sftp_conn *, மாறிலி எழுத்து *, முழு, Attrib *);

/* Get file attributes of 'path' (does not follow symlinks) */
முழு sftp_lstat(கட்டமைப்பு sftp_conn *, மாறிலி எழுத்து *, முழு, Attrib *);

/* Set file attributes of 'path' */
முழு sftp_setstat(கட்டமைப்பு sftp_conn *, மாறிலி எழுத்து *, Attrib *);

/* Set file attributes of open file 'handle' */
முழு sftp_fsetstat(கட்டமைப்பு sftp_conn *, மாறிலி u_char *, u_int, Attrib *);

/* Set file attributes of 'path', not following symlinks */
முழு sftp_lsetstat(கட்டமைப்பு sftp_conn *conn, மாறிலி எழுத்து *path, Attrib *a);

/* Canonicalise 'path' - caller must free result */
எழுத்து *sftp_realpath(கட்டமைப்பு sftp_conn *, மாறிலி எழுத்து *);

/* Canonicalisation with tilde expansion (requires server extension) */
எழுத்து *sftp_expand_path(கட்டமைப்பு sftp_conn *, மாறிலி எழுத்து *);

/* Returns non-zero if server can tilde-expand paths */
முழு sftp_can_expand_path(கட்டமைப்பு sftp_conn *);

/* Get statistics for filesystem hosting file at "path" */
முழு sftp_statvfs(கட்டமைப்பு sftp_conn *, மாறிலி எழுத்து *, கட்டமைப்பு sftp_statvfs *, முழு);

/* Rename 'oldpath' to 'newpath' */
முழு sftp_rename(கட்டமைப்பு sftp_conn *, மாறிலி எழுத்து *, மாறிலி எழுத்து *, முழு);

/* Copy 'oldpath' to 'newpath' */
முழு sftp_copy(கட்டமைப்பு sftp_conn *, மாறிலி எழுத்து *, மாறிலி எழுத்து *);

/* Link 'oldpath' to 'newpath' */
முழு sftp_hardlink(கட்டமைப்பு sftp_conn *, மாறிலி எழுத்து *, மாறிலி எழுத்து *);

/* Rename 'oldpath' to 'newpath' */
முழு sftp_symlink(கட்டமைப்பு sftp_conn *, மாறிலி எழுத்து *, மாறிலி எழுத்து *);

/* Call fsync() on open file 'handle' */
முழு sftp_fsync(கட்டமைப்பு sftp_conn *conn, u_char *, u_int);

/*
 * Download 'remote_path' to 'local_path'. Preserve permissions and times
 * if 'pflag' is set
 */
முழு sftp_download(கட்டமைப்பு sftp_conn *, மாறிலி எழுத்து *, மாறிலி எழுத்து *, Attrib *,
    முழு, முழு, முழு, முழு);

/*
 * Recursively download 'remote_directory' to 'local_directory'. Preserve
 * times if 'pflag' is set
 */
முழு sftp_download_dir(கட்டமைப்பு sftp_conn *, மாறிலி எழுத்து *, மாறிலி எழுத்து *, Attrib *,
    முழு, முழு, முழு, முழு, முழு, முழு);

/*
 * Upload 'local_path' to 'remote_path'. Preserve permissions and times
 * if 'pflag' is set
 */
முழு sftp_upload(கட்டமைப்பு sftp_conn *, மாறிலி எழுத்து *, மாறிலி எழுத்து *,
    முழு, முழு, முழு, முழு);

/*
 * Recursively upload 'local_directory' to 'remote_directory'. Preserve
 * times if 'pflag' is set
 */
முழு sftp_upload_dir(கட்டமைப்பு sftp_conn *, மாறிலி எழுத்து *, மாறிலி எழுத்து *,
    முழு, முழு, முழு, முழு, முழு, முழு);

/*
 * Download a 'from_path' from the 'from' connection and upload it to
 * to 'to' connection at 'to_path'.
 */
முழு sftp_crossload(கட்டமைப்பு sftp_conn *from, கட்டமைப்பு sftp_conn *to,
    மாறிலி எழுத்து *from_path, மாறிலி எழுத்து *to_path,
    Attrib *a, முழு preserve_flag);

/*
 * Recursively download a directory from 'from_path' from the 'from'
 * connection and upload it to 'to' connection at 'to_path'.
 */
முழு sftp_crossload_dir(கட்டமைப்பு sftp_conn *from, கட்டமைப்பு sftp_conn *to,
    மாறிலி எழுத்து *from_path, மாறிலி எழுத்து *to_path,
    Attrib *dirattrib, முழு preserve_flag, முழு print_flag,
    முழு follow_link_flag);

/*
 * User/group ID to name translation.
 */
முழு sftp_can_get_users_groups_by_id(கட்டமைப்பு sftp_conn *conn);
முழு sftp_get_users_groups_by_id(கட்டமைப்பு sftp_conn *conn,
    மாறிலி u_int *uids, u_int nuids,
    மாறிலி u_int *gids, u_int ngids,
    எழுத்து ***usernamesp, எழுத்து ***groupnamesp);

/* Concatenate paths, taking care of slashes. Caller must free result. */
எழுத்து *sftp_path_append(மாறிலி எழுத்து *, மாறிலி எழுத்து *);

/* Make absolute path if relative path and CWD is given. Does not modify
 * original if the path is already absolute. */
எழுத்து *sftp_make_absolute(எழுத்து *, மாறிலி எழுத்து *);

/* Check if remote path is directory */
முழு sftp_remote_is_dir(கட்டமைப்பு sftp_conn *conn, மாறிலி எழுத்து *path);

/* Check whether path returned from glob(..., GLOB_MARK, ...) is a directory */
முழு sftp_globpath_is_dir(மாறிலி எழுத்து *pathname);

#endif
