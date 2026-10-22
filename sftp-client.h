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

প্রকারনির্দেশ সংরচনা SFTP_DIRENT SFTP_DIRENT;

সংরচনা SFTP_DIRENT {
	ৱর্ণ *filename;
	ৱর্ণ *longname;
	Attrib a;
};

/*
 * Used for statvfs responses on the wire from the server, because the
 * server's native format may be larger than the client's.
 */
সংরচনা sftp_statvfs {
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
সংরচনা sftp_limits {
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
সংরচনা sftp_conn *sftp_init(পূর্ণাঙ্ক, পূর্ণাঙ্ক, u_int, u_int, uint64_t);
শূন্য sftp_free(সংরচনা sftp_conn *);

u_int sftp_proto_version(সংরচনা sftp_conn *);

/* Query server limits */
পূর্ণাঙ্ক sftp_get_limits(সংরচনা sftp_conn *, সংরচনা sftp_limits *);

/* Close file referred to by 'handle' */
পূর্ণাঙ্ক sftp_close(সংরচনা sftp_conn *, ধ্রুৱ u_char *, u_int);

/* Read contents of 'path' to NULL-terminated array 'dir' */
পূর্ণাঙ্ক sftp_readdir(সংরচনা sftp_conn *, ধ্রুৱ ৱর্ণ *, SFTP_DIRENT ***);

/* Frees a NULL-terminated array of SFTP_DIRENTs (eg. from sftp_readdir) */
শূন্য sftp_free_dirents(SFTP_DIRENT **);

/* Delete file 'path' */
পূর্ণাঙ্ক sftp_rm(সংরচনা sftp_conn *, ধ্রুৱ ৱর্ণ *);

/* Create directory 'path' */
পূর্ণাঙ্ক sftp_mkdir(সংরচনা sftp_conn *, ধ্রুৱ ৱর্ণ *, Attrib *, পূর্ণাঙ্ক);

/* Create directory 'path' and intermediate directories as required */
পূর্ণাঙ্ক sftp_mkpath(সংরচনা sftp_conn *, ধ্রুৱ ৱর্ণ *, Attrib *, পূর্ণাঙ্ক);

/* Remove directory 'path' */
পূর্ণাঙ্ক sftp_rmdir(সংরচনা sftp_conn *, ধ্রুৱ ৱর্ণ *);

/* Get file attributes of 'path' (follows symlinks) */
পূর্ণাঙ্ক sftp_stat(সংরচনা sftp_conn *, ধ্রুৱ ৱর্ণ *, পূর্ণাঙ্ক, Attrib *);

/* Get file attributes of 'path' (does not follow symlinks) */
পূর্ণাঙ্ক sftp_lstat(সংরচনা sftp_conn *, ধ্রুৱ ৱর্ণ *, পূর্ণাঙ্ক, Attrib *);

/* Set file attributes of 'path' */
পূর্ণাঙ্ক sftp_setstat(সংরচনা sftp_conn *, ধ্রুৱ ৱর্ণ *, Attrib *);

/* Set file attributes of open file 'handle' */
পূর্ণাঙ্ক sftp_fsetstat(সংরচনা sftp_conn *, ধ্রুৱ u_char *, u_int, Attrib *);

/* Set file attributes of 'path', not following symlinks */
পূর্ণাঙ্ক sftp_lsetstat(সংরচনা sftp_conn *conn, ধ্রুৱ ৱর্ণ *path, Attrib *a);

/* Canonicalise 'path' - caller must free result */
ৱর্ণ *sftp_realpath(সংরচনা sftp_conn *, ধ্রুৱ ৱর্ণ *);

/* Canonicalisation with tilde expansion (requires server extension) */
ৱর্ণ *sftp_expand_path(সংরচনা sftp_conn *, ধ্রুৱ ৱর্ণ *);

/* Returns non-zero if server can tilde-expand paths */
পূর্ণাঙ্ক sftp_can_expand_path(সংরচনা sftp_conn *);

/* Get statistics for filesystem hosting file at "path" */
পূর্ণাঙ্ক sftp_statvfs(সংরচনা sftp_conn *, ধ্রুৱ ৱর্ণ *, সংরচনা sftp_statvfs *, পূর্ণাঙ্ক);

/* Rename 'oldpath' to 'newpath' */
পূর্ণাঙ্ক sftp_rename(সংরচনা sftp_conn *, ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *, পূর্ণাঙ্ক);

/* Copy 'oldpath' to 'newpath' */
পূর্ণাঙ্ক sftp_copy(সংরচনা sftp_conn *, ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *);

/* Link 'oldpath' to 'newpath' */
পূর্ণাঙ্ক sftp_hardlink(সংরচনা sftp_conn *, ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *);

/* Rename 'oldpath' to 'newpath' */
পূর্ণাঙ্ক sftp_symlink(সংরচনা sftp_conn *, ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *);

/* Call fsync() on open file 'handle' */
পূর্ণাঙ্ক sftp_fsync(সংরচনা sftp_conn *conn, u_char *, u_int);

/*
 * Download 'remote_path' to 'local_path'. Preserve permissions and times
 * if 'pflag' is set
 */
পূর্ণাঙ্ক sftp_download(সংরচনা sftp_conn *, ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *, Attrib *,
    পূর্ণাঙ্ক, পূর্ণাঙ্ক, পূর্ণাঙ্ক, পূর্ণাঙ্ক);

/*
 * Recursively download 'remote_directory' to 'local_directory'. Preserve
 * times if 'pflag' is set
 */
পূর্ণাঙ্ক sftp_download_dir(সংরচনা sftp_conn *, ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *, Attrib *,
    পূর্ণাঙ্ক, পূর্ণাঙ্ক, পূর্ণাঙ্ক, পূর্ণাঙ্ক, পূর্ণাঙ্ক, পূর্ণাঙ্ক);

/*
 * Upload 'local_path' to 'remote_path'. Preserve permissions and times
 * if 'pflag' is set
 */
পূর্ণাঙ্ক sftp_upload(সংরচনা sftp_conn *, ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *,
    পূর্ণাঙ্ক, পূর্ণাঙ্ক, পূর্ণাঙ্ক, পূর্ণাঙ্ক);

/*
 * Recursively upload 'local_directory' to 'remote_directory'. Preserve
 * times if 'pflag' is set
 */
পূর্ণাঙ্ক sftp_upload_dir(সংরচনা sftp_conn *, ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *,
    পূর্ণাঙ্ক, পূর্ণাঙ্ক, পূর্ণাঙ্ক, পূর্ণাঙ্ক, পূর্ণাঙ্ক, পূর্ণাঙ্ক);

/*
 * Download a 'from_path' from the 'from' connection and upload it to
 * to 'to' connection at 'to_path'.
 */
পূর্ণাঙ্ক sftp_crossload(সংরচনা sftp_conn *from, সংরচনা sftp_conn *to,
    ধ্রুৱ ৱর্ণ *from_path, ধ্রুৱ ৱর্ণ *to_path,
    Attrib *a, পূর্ণাঙ্ক preserve_flag);

/*
 * Recursively download a directory from 'from_path' from the 'from'
 * connection and upload it to 'to' connection at 'to_path'.
 */
পূর্ণাঙ্ক sftp_crossload_dir(সংরচনা sftp_conn *from, সংরচনা sftp_conn *to,
    ধ্রুৱ ৱর্ণ *from_path, ধ্রুৱ ৱর্ণ *to_path,
    Attrib *dirattrib, পূর্ণাঙ্ক preserve_flag, পূর্ণাঙ্ক print_flag,
    পূর্ণাঙ্ক follow_link_flag);

/*
 * User/group ID to name translation.
 */
পূর্ণাঙ্ক sftp_can_get_users_groups_by_id(সংরচনা sftp_conn *conn);
পূর্ণাঙ্ক sftp_get_users_groups_by_id(সংরচনা sftp_conn *conn,
    ধ্রুৱ u_int *uids, u_int nuids,
    ধ্রুৱ u_int *gids, u_int ngids,
    ৱর্ণ ***usernamesp, ৱর্ণ ***groupnamesp);

/* Concatenate paths, taking care of slashes. Caller must free result. */
ৱর্ণ *sftp_path_append(ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *);

/* Make absolute path if relative path and CWD is given. Does not modify
 * original if the path is already absolute. */
ৱর্ণ *sftp_make_absolute(ৱর্ণ *, ধ্রুৱ ৱর্ণ *);

/* Check if remote path is directory */
পূর্ণাঙ্ক sftp_remote_is_dir(সংরচনা sftp_conn *conn, ধ্রুৱ ৱর্ণ *path);

/* Check whether path returned from glob(..., GLOB_MARK, ...) is a directory */
পূর্ণাঙ্ক sftp_globpath_is_dir(ধ্রুৱ ৱর্ণ *pathname);

#endif
