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

تعريفنوع بنية SFTP_DIRENT SFTP_DIRENT;

بنية SFTP_DIRENT {
	حرف *filename;
	حرف *longname;
	Attrib a;
};

/*
 * Used for statvfs responses on the wire from the server, because the
 * server's native format may be larger than the client's.
 */
بنية sftp_statvfs {
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
بنية sftp_limits {
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
بنية sftp_conn *sftp_init(صحيح, صحيح, u_int, u_int, uint64_t);
فراغ sftp_free(بنية sftp_conn *);

u_int sftp_proto_version(بنية sftp_conn *);

/* Query server limits */
صحيح sftp_get_limits(بنية sftp_conn *, بنية sftp_limits *);

/* Close file referred to by 'handle' */
صحيح sftp_close(بنية sftp_conn *, ثابت u_char *, u_int);

/* Read contents of 'path' to NULL-terminated array 'dir' */
صحيح sftp_readdir(بنية sftp_conn *, ثابت حرف *, SFTP_DIRENT ***);

/* Frees a NULL-terminated array of SFTP_DIRENTs (eg. from sftp_readdir) */
فراغ sftp_free_dirents(SFTP_DIRENT **);

/* Delete file 'path' */
صحيح sftp_rm(بنية sftp_conn *, ثابت حرف *);

/* Create directory 'path' */
صحيح sftp_mkdir(بنية sftp_conn *, ثابت حرف *, Attrib *, صحيح);

/* Create directory 'path' and intermediate directories as required */
صحيح sftp_mkpath(بنية sftp_conn *, ثابت حرف *, Attrib *, صحيح);

/* Remove directory 'path' */
صحيح sftp_rmdir(بنية sftp_conn *, ثابت حرف *);

/* Get file attributes of 'path' (follows symlinks) */
صحيح sftp_stat(بنية sftp_conn *, ثابت حرف *, صحيح, Attrib *);

/* Get file attributes of 'path' (does not follow symlinks) */
صحيح sftp_lstat(بنية sftp_conn *, ثابت حرف *, صحيح, Attrib *);

/* Set file attributes of 'path' */
صحيح sftp_setstat(بنية sftp_conn *, ثابت حرف *, Attrib *);

/* Set file attributes of open file 'handle' */
صحيح sftp_fsetstat(بنية sftp_conn *, ثابت u_char *, u_int, Attrib *);

/* Set file attributes of 'path', not following symlinks */
صحيح sftp_lsetstat(بنية sftp_conn *conn, ثابت حرف *path, Attrib *a);

/* Canonicalise 'path' - caller must free result */
حرف *sftp_realpath(بنية sftp_conn *, ثابت حرف *);

/* Canonicalisation with tilde expansion (requires server extension) */
حرف *sftp_expand_path(بنية sftp_conn *, ثابت حرف *);

/* Returns non-zero if server can tilde-expand paths */
صحيح sftp_can_expand_path(بنية sftp_conn *);

/* Get statistics for filesystem hosting file at "path" */
صحيح sftp_statvfs(بنية sftp_conn *, ثابت حرف *, بنية sftp_statvfs *, صحيح);

/* Rename 'oldpath' to 'newpath' */
صحيح sftp_rename(بنية sftp_conn *, ثابت حرف *, ثابت حرف *, صحيح);

/* Copy 'oldpath' to 'newpath' */
صحيح sftp_copy(بنية sftp_conn *, ثابت حرف *, ثابت حرف *);

/* Link 'oldpath' to 'newpath' */
صحيح sftp_hardlink(بنية sftp_conn *, ثابت حرف *, ثابت حرف *);

/* Rename 'oldpath' to 'newpath' */
صحيح sftp_symlink(بنية sftp_conn *, ثابت حرف *, ثابت حرف *);

/* Call fsync() on open file 'handle' */
صحيح sftp_fsync(بنية sftp_conn *conn, u_char *, u_int);

/*
 * Download 'remote_path' to 'local_path'. Preserve permissions and times
 * if 'pflag' is set
 */
صحيح sftp_download(بنية sftp_conn *, ثابت حرف *, ثابت حرف *, Attrib *,
    صحيح, صحيح, صحيح, صحيح);

/*
 * Recursively download 'remote_directory' to 'local_directory'. Preserve
 * times if 'pflag' is set
 */
صحيح sftp_download_dir(بنية sftp_conn *, ثابت حرف *, ثابت حرف *, Attrib *,
    صحيح, صحيح, صحيح, صحيح, صحيح, صحيح);

/*
 * Upload 'local_path' to 'remote_path'. Preserve permissions and times
 * if 'pflag' is set
 */
صحيح sftp_upload(بنية sftp_conn *, ثابت حرف *, ثابت حرف *,
    صحيح, صحيح, صحيح, صحيح);

/*
 * Recursively upload 'local_directory' to 'remote_directory'. Preserve
 * times if 'pflag' is set
 */
صحيح sftp_upload_dir(بنية sftp_conn *, ثابت حرف *, ثابت حرف *,
    صحيح, صحيح, صحيح, صحيح, صحيح, صحيح);

/*
 * Download a 'from_path' from the 'from' connection and upload it to
 * to 'to' connection at 'to_path'.
 */
صحيح sftp_crossload(بنية sftp_conn *from, بنية sftp_conn *to,
    ثابت حرف *from_path, ثابت حرف *to_path,
    Attrib *a, صحيح preserve_flag);

/*
 * Recursively download a directory from 'from_path' from the 'from'
 * connection and upload it to 'to' connection at 'to_path'.
 */
صحيح sftp_crossload_dir(بنية sftp_conn *from, بنية sftp_conn *to,
    ثابت حرف *from_path, ثابت حرف *to_path,
    Attrib *dirattrib, صحيح preserve_flag, صحيح print_flag,
    صحيح follow_link_flag);

/*
 * User/group ID to name translation.
 */
صحيح sftp_can_get_users_groups_by_id(بنية sftp_conn *conn);
صحيح sftp_get_users_groups_by_id(بنية sftp_conn *conn,
    ثابت u_int *uids, u_int nuids,
    ثابت u_int *gids, u_int ngids,
    حرف ***usernamesp, حرف ***groupnamesp);

/* Concatenate paths, taking care of slashes. Caller must free result. */
حرف *sftp_path_append(ثابت حرف *, ثابت حرف *);

/* Make absolute path if relative path and CWD is given. Does not modify
 * original if the path is already absolute. */
حرف *sftp_make_absolute(حرف *, ثابت حرف *);

/* Check if remote path is directory */
صحيح sftp_remote_is_dir(بنية sftp_conn *conn, ثابت حرف *path);

/* Check whether path returned from glob(..., GLOB_MARK, ...) is a directory */
صحيح sftp_globpath_is_dir(ثابت حرف *pathname);

#endif
