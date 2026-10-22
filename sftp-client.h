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

প্রকারলেখ কাঠামো SFTP_DIRENT SFTP_DIRENT;

কাঠামো SFTP_DIRENT {
	অক্ষর *filename;
	অক্ষর *longname;
	Attrib a;
};

/*
 * Used for statvfs responses on the wire from the server, because the
 * server's native format may be larger than the client's.
 */
কাঠামো sftp_statvfs {
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
কাঠামো sftp_limits {
	uint64_t packet_দৈর্ঘ্য;
	uint64_t read_দৈর্ঘ্য;
	uint64_t write_দৈর্ঘ্য;
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
কাঠামো sftp_conn *sftp_init(পূর্ণসংখ্যা, পূর্ণসংখ্যা, u_int, u_int, uint64_t);
শূন্য sftp_free(কাঠামো sftp_conn *);

u_int sftp_proto_version(কাঠামো sftp_conn *);

/* Query server limits */
পূর্ণসংখ্যা sftp_get_limits(কাঠামো sftp_conn *, কাঠামো sftp_limits *);

/* Close file referred to by 'handle' */
পূর্ণসংখ্যা sftp_close(কাঠামো sftp_conn *, ধ্রুবক u_char *, u_int);

/* Read contents of 'path' to NULL-terminated array 'dir' */
পূর্ণসংখ্যা sftp_readdir(কাঠামো sftp_conn *, ধ্রুবক অক্ষর *, SFTP_DIRENT ***);

/* Frees a NULL-terminated array of SFTP_DIRENTs (eg. from sftp_readdir) */
শূন্য sftp_free_dirents(SFTP_DIRENT **);

/* Delete file 'path' */
পূর্ণসংখ্যা sftp_rm(কাঠামো sftp_conn *, ধ্রুবক অক্ষর *);

/* Create directory 'path' */
পূর্ণসংখ্যা sftp_mkdir(কাঠামো sftp_conn *, ধ্রুবক অক্ষর *, Attrib *, পূর্ণসংখ্যা);

/* Create directory 'path' and intermediate directories as required */
পূর্ণসংখ্যা sftp_mkpath(কাঠামো sftp_conn *, ধ্রুবক অক্ষর *, Attrib *, পূর্ণসংখ্যা);

/* Remove directory 'path' */
পূর্ণসংখ্যা sftp_rmdir(কাঠামো sftp_conn *, ধ্রুবক অক্ষর *);

/* Get file attributes of 'path' (follows symlinks) */
পূর্ণসংখ্যা sftp_stat(কাঠামো sftp_conn *, ধ্রুবক অক্ষর *, পূর্ণসংখ্যা, Attrib *);

/* Get file attributes of 'path' (does not follow symlinks) */
পূর্ণসংখ্যা sftp_lstat(কাঠামো sftp_conn *, ধ্রুবক অক্ষর *, পূর্ণসংখ্যা, Attrib *);

/* Set file attributes of 'path' */
পূর্ণসংখ্যা sftp_setstat(কাঠামো sftp_conn *, ধ্রুবক অক্ষর *, Attrib *);

/* Set file attributes of open file 'handle' */
পূর্ণসংখ্যা sftp_fsetstat(কাঠামো sftp_conn *, ধ্রুবক u_char *, u_int, Attrib *);

/* Set file attributes of 'path', not following symlinks */
পূর্ণসংখ্যা sftp_lsetstat(কাঠামো sftp_conn *conn, ধ্রুবক অক্ষর *path, Attrib *a);

/* Canonicalise 'path' - caller must free result */
অক্ষর *sftp_realpath(কাঠামো sftp_conn *, ধ্রুবক অক্ষর *);

/* Canonicalisation with tilde expansion (requires server extension) */
অক্ষর *sftp_expand_path(কাঠামো sftp_conn *, ধ্রুবক অক্ষর *);

/* Returns non-zero if server can tilde-expand paths */
পূর্ণসংখ্যা sftp_can_expand_path(কাঠামো sftp_conn *);

/* Get statistics for filesystem hosting file at "path" */
পূর্ণসংখ্যা sftp_statvfs(কাঠামো sftp_conn *, ধ্রুবক অক্ষর *, কাঠামো sftp_statvfs *, পূর্ণসংখ্যা);

/* Rename 'oldpath' to 'newpath' */
পূর্ণসংখ্যা sftp_rename(কাঠামো sftp_conn *, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, পূর্ণসংখ্যা);

/* Copy 'oldpath' to 'newpath' */
পূর্ণসংখ্যা sftp_copy(কাঠামো sftp_conn *, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *);

/* Link 'oldpath' to 'newpath' */
পূর্ণসংখ্যা sftp_hardlink(কাঠামো sftp_conn *, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *);

/* Rename 'oldpath' to 'newpath' */
পূর্ণসংখ্যা sftp_symlink(কাঠামো sftp_conn *, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *);

/* Call fsync() on open file 'handle' */
পূর্ণসংখ্যা sftp_fsync(কাঠামো sftp_conn *conn, u_char *, u_int);

/*
 * Download 'remote_path' to 'local_path'. Preserve permissions and times
 * if 'pflag' is set
 */
পূর্ণসংখ্যা sftp_download(কাঠামো sftp_conn *, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, Attrib *,
    পূর্ণসংখ্যা, পূর্ণসংখ্যা, পূর্ণসংখ্যা, পূর্ণসংখ্যা);

/*
 * Recursively download 'remote_directory' to 'local_directory'. Preserve
 * times if 'pflag' is set
 */
পূর্ণসংখ্যা sftp_download_dir(কাঠামো sftp_conn *, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, Attrib *,
    পূর্ণসংখ্যা, পূর্ণসংখ্যা, পূর্ণসংখ্যা, পূর্ণসংখ্যা, পূর্ণসংখ্যা, পূর্ণসংখ্যা);

/*
 * Upload 'local_path' to 'remote_path'. Preserve permissions and times
 * if 'pflag' is set
 */
পূর্ণসংখ্যা sftp_upload(কাঠামো sftp_conn *, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *,
    পূর্ণসংখ্যা, পূর্ণসংখ্যা, পূর্ণসংখ্যা, পূর্ণসংখ্যা);

/*
 * Recursively upload 'local_directory' to 'remote_directory'. Preserve
 * times if 'pflag' is set
 */
পূর্ণসংখ্যা sftp_upload_dir(কাঠামো sftp_conn *, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *,
    পূর্ণসংখ্যা, পূর্ণসংখ্যা, পূর্ণসংখ্যা, পূর্ণসংখ্যা, পূর্ণসংখ্যা, পূর্ণসংখ্যা);

/*
 * Download a 'from_path' from the 'from' connection and upload it to
 * to 'to' connection at 'to_path'.
 */
পূর্ণসংখ্যা sftp_crossload(কাঠামো sftp_conn *from, কাঠামো sftp_conn *to,
    ধ্রুবক অক্ষর *from_path, ধ্রুবক অক্ষর *to_path,
    Attrib *a, পূর্ণসংখ্যা preserve_flag);

/*
 * Recursively download a directory from 'from_path' from the 'from'
 * connection and upload it to 'to' connection at 'to_path'.
 */
পূর্ণসংখ্যা sftp_crossload_dir(কাঠামো sftp_conn *from, কাঠামো sftp_conn *to,
    ধ্রুবক অক্ষর *from_path, ধ্রুবক অক্ষর *to_path,
    Attrib *dirattrib, পূর্ণসংখ্যা preserve_flag, পূর্ণসংখ্যা print_flag,
    পূর্ণসংখ্যা follow_link_flag);

/*
 * User/group ID to name translation.
 */
পূর্ণসংখ্যা sftp_can_get_users_groups_by_id(কাঠামো sftp_conn *conn);
পূর্ণসংখ্যা sftp_get_users_groups_by_id(কাঠামো sftp_conn *conn,
    ধ্রুবক u_int *uids, u_int nuids,
    ধ্রুবক u_int *gids, u_int ngids,
    অক্ষর ***usernamesp, অক্ষর ***groupnamesp);

/* Concatenate paths, taking care of slashes. Caller must free result. */
অক্ষর *sftp_path_append(ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *);

/* Make absolute path if relative path and CWD is given. Does not modify
 * original if the path is already absolute. */
অক্ষর *sftp_make_absolute(অক্ষর *, ধ্রুবক অক্ষর *);

/* Check if remote path is directory */
পূর্ণসংখ্যা sftp_remote_is_dir(কাঠামো sftp_conn *conn, ধ্রুবক অক্ষর *path);

/* Check whether path returned from glob(..., GLOB_MARK, ...) is a directory */
পূর্ণসংখ্যা sftp_globpath_is_dir(ধ্রুবক অক্ষর *pathname);

#endif
