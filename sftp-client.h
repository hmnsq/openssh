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

ಪ್ರಕಾರನಿರ್ದೇಶ ಸಂರಚನಾ SFTP_DIRENT SFTP_DIRENT;

ಸಂರಚನಾ SFTP_DIRENT {
	ವರ್ಣ *filename;
	ವರ್ಣ *longname;
	Attrib a;
};

/*
 * Used for statvfs responses on the wire from the server, because the
 * server's native format may be larger than the client's.
 */
ಸಂರಚನಾ sftp_statvfs {
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
ಸಂರಚನಾ sftp_limits {
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
ಸಂರಚನಾ sftp_conn *sftp_init(ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, u_int, u_int, uint64_t);
ಶೂನ್ಯ sftp_free(ಸಂರಚನಾ sftp_conn *);

u_int sftp_proto_version(ಸಂರಚನಾ sftp_conn *);

/* Query server limits */
ಪೂರ್ಣಾಙ್ಕ sftp_get_limits(ಸಂರಚನಾ sftp_conn *, ಸಂರಚನಾ sftp_limits *);

/* Close file referred to by 'handle' */
ಪೂರ್ಣಾಙ್ಕ sftp_close(ಸಂರಚನಾ sftp_conn *, ಧ್ರುವ u_char *, u_int);

/* Read contents of 'path' to NULL-terminated array 'dir' */
ಪೂರ್ಣಾಙ್ಕ sftp_readdir(ಸಂರಚನಾ sftp_conn *, ಧ್ರುವ ವರ್ಣ *, SFTP_DIRENT ***);

/* Frees a NULL-terminated array of SFTP_DIRENTs (eg. from sftp_readdir) */
ಶೂನ್ಯ sftp_free_dirents(SFTP_DIRENT **);

/* Delete file 'path' */
ಪೂರ್ಣಾಙ್ಕ sftp_rm(ಸಂರಚನಾ sftp_conn *, ಧ್ರುವ ವರ್ಣ *);

/* Create directory 'path' */
ಪೂರ್ಣಾಙ್ಕ sftp_mkdir(ಸಂರಚನಾ sftp_conn *, ಧ್ರುವ ವರ್ಣ *, Attrib *, ಪೂರ್ಣಾಙ್ಕ);

/* Create directory 'path' and intermediate directories as required */
ಪೂರ್ಣಾಙ್ಕ sftp_mkpath(ಸಂರಚನಾ sftp_conn *, ಧ್ರುವ ವರ್ಣ *, Attrib *, ಪೂರ್ಣಾಙ್ಕ);

/* Remove directory 'path' */
ಪೂರ್ಣಾಙ್ಕ sftp_rmdir(ಸಂರಚನಾ sftp_conn *, ಧ್ರುವ ವರ್ಣ *);

/* Get file attributes of 'path' (follows symlinks) */
ಪೂರ್ಣಾಙ್ಕ sftp_stat(ಸಂರಚನಾ sftp_conn *, ಧ್ರುವ ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ, Attrib *);

/* Get file attributes of 'path' (does not follow symlinks) */
ಪೂರ್ಣಾಙ್ಕ sftp_lstat(ಸಂರಚನಾ sftp_conn *, ಧ್ರುವ ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ, Attrib *);

/* Set file attributes of 'path' */
ಪೂರ್ಣಾಙ್ಕ sftp_setstat(ಸಂರಚನಾ sftp_conn *, ಧ್ರುವ ವರ್ಣ *, Attrib *);

/* Set file attributes of open file 'handle' */
ಪೂರ್ಣಾಙ್ಕ sftp_fsetstat(ಸಂರಚನಾ sftp_conn *, ಧ್ರುವ u_char *, u_int, Attrib *);

/* Set file attributes of 'path', not following symlinks */
ಪೂರ್ಣಾಙ್ಕ sftp_lsetstat(ಸಂರಚನಾ sftp_conn *conn, ಧ್ರುವ ವರ್ಣ *path, Attrib *a);

/* Canonicalise 'path' - caller must free result */
ವರ್ಣ *sftp_realpath(ಸಂರಚನಾ sftp_conn *, ಧ್ರುವ ವರ್ಣ *);

/* Canonicalisation with tilde expansion (requires server extension) */
ವರ್ಣ *sftp_expand_path(ಸಂರಚನಾ sftp_conn *, ಧ್ರುವ ವರ್ಣ *);

/* Returns non-zero if server can tilde-expand paths */
ಪೂರ್ಣಾಙ್ಕ sftp_can_expand_path(ಸಂರಚನಾ sftp_conn *);

/* Get statistics for filesystem hosting file at "path" */
ಪೂರ್ಣಾಙ್ಕ sftp_statvfs(ಸಂರಚನಾ sftp_conn *, ಧ್ರುವ ವರ್ಣ *, ಸಂರಚನಾ sftp_statvfs *, ಪೂರ್ಣಾಙ್ಕ);

/* Rename 'oldpath' to 'newpath' */
ಪೂರ್ಣಾಙ್ಕ sftp_rename(ಸಂರಚನಾ sftp_conn *, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ);

/* Copy 'oldpath' to 'newpath' */
ಪೂರ್ಣಾಙ್ಕ sftp_copy(ಸಂರಚನಾ sftp_conn *, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *);

/* Link 'oldpath' to 'newpath' */
ಪೂರ್ಣಾಙ್ಕ sftp_hardlink(ಸಂರಚನಾ sftp_conn *, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *);

/* Rename 'oldpath' to 'newpath' */
ಪೂರ್ಣಾಙ್ಕ sftp_symlink(ಸಂರಚನಾ sftp_conn *, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *);

/* Call fsync() on open file 'handle' */
ಪೂರ್ಣಾಙ್ಕ sftp_fsync(ಸಂರಚನಾ sftp_conn *conn, u_char *, u_int);

/*
 * Download 'remote_path' to 'local_path'. Preserve permissions and times
 * if 'pflag' is set
 */
ಪೂರ್ಣಾಙ್ಕ sftp_download(ಸಂರಚನಾ sftp_conn *, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, Attrib *,
    ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ);

/*
 * Recursively download 'remote_directory' to 'local_directory'. Preserve
 * times if 'pflag' is set
 */
ಪೂರ್ಣಾಙ್ಕ sftp_download_dir(ಸಂರಚನಾ sftp_conn *, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, Attrib *,
    ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ);

/*
 * Upload 'local_path' to 'remote_path'. Preserve permissions and times
 * if 'pflag' is set
 */
ಪೂರ್ಣಾಙ್ಕ sftp_upload(ಸಂರಚನಾ sftp_conn *, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *,
    ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ);

/*
 * Recursively upload 'local_directory' to 'remote_directory'. Preserve
 * times if 'pflag' is set
 */
ಪೂರ್ಣಾಙ್ಕ sftp_upload_dir(ಸಂರಚನಾ sftp_conn *, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *,
    ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ);

/*
 * Download a 'from_path' from the 'from' connection and upload it to
 * to 'to' connection at 'to_path'.
 */
ಪೂರ್ಣಾಙ್ಕ sftp_crossload(ಸಂರಚನಾ sftp_conn *from, ಸಂರಚನಾ sftp_conn *to,
    ಧ್ರುವ ವರ್ಣ *from_path, ಧ್ರುವ ವರ್ಣ *to_path,
    Attrib *a, ಪೂರ್ಣಾಙ್ಕ preserve_flag);

/*
 * Recursively download a directory from 'from_path' from the 'from'
 * connection and upload it to 'to' connection at 'to_path'.
 */
ಪೂರ್ಣಾಙ್ಕ sftp_crossload_dir(ಸಂರಚನಾ sftp_conn *from, ಸಂರಚನಾ sftp_conn *to,
    ಧ್ರುವ ವರ್ಣ *from_path, ಧ್ರುವ ವರ್ಣ *to_path,
    Attrib *dirattrib, ಪೂರ್ಣಾಙ್ಕ preserve_flag, ಪೂರ್ಣಾಙ್ಕ print_flag,
    ಪೂರ್ಣಾಙ್ಕ follow_link_flag);

/*
 * User/group ID to name translation.
 */
ಪೂರ್ಣಾಙ್ಕ sftp_can_get_users_groups_by_id(ಸಂರಚನಾ sftp_conn *conn);
ಪೂರ್ಣಾಙ್ಕ sftp_get_users_groups_by_id(ಸಂರಚನಾ sftp_conn *conn,
    ಧ್ರುವ u_int *uids, u_int nuids,
    ಧ್ರುವ u_int *gids, u_int ngids,
    ವರ್ಣ ***usernamesp, ವರ್ಣ ***groupnamesp);

/* Concatenate paths, taking care of slashes. Caller must free result. */
ವರ್ಣ *sftp_path_append(ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *);

/* Make absolute path if relative path and CWD is given. Does not modify
 * original if the path is already absolute. */
ವರ್ಣ *sftp_make_absolute(ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *);

/* Check if remote path is directory */
ಪೂರ್ಣಾಙ್ಕ sftp_remote_is_dir(ಸಂರಚನಾ sftp_conn *conn, ಧ್ರುವ ವರ್ಣ *path);

/* Check whether path returned from glob(..., GLOB_MARK, ...) is a directory */
ಪೂರ್ಣಾಙ್ಕ sftp_globpath_is_dir(ಧ್ರುವ ವರ್ಣ *pathname);

#endif
