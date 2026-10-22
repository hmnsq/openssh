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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ _SFTP_CLIENT_H
#ವ್ಯಾಖ್ಯಾನಿಸು _SFTP_CLIENT_H

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ SFTP_DIRENT SFTP_DIRENT;

ರಚನೆ SFTP_DIRENT {
	ಅಕ್ಷರ *filename;
	ಅಕ್ಷರ *longname;
	Attrib a;
};

/*
 * Used for statvfs responses on the wire from the server, because the
 * server's native format may be larger than the client's.
 */
ರಚನೆ sftp_statvfs {
	uint64_t f_bsize;
	uint64_t f_frsize;
	uint64_t f_ಖಂಡಗಳು;
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
ರಚನೆ sftp_limits {
	uint64_t packet_ಉದ್ದಳತೆ;
	uint64_t read_ಉದ್ದಳತೆ;
	uint64_t write_ಉದ್ದಳತೆ;
	uint64_t open_handles;
};

/* print flag values */
#ವ್ಯಾಖ್ಯಾನಿಸು SFTP_QUIET		0	/* be quiet during transfers */
#ವ್ಯಾಖ್ಯಾನಿಸು SFTP_PRINT		1	/* list files and show progress bar */
#ವ್ಯಾಖ್ಯಾನಿಸು SFTP_ಪ್ರಗತಿ_ONLY	2	/* progress bar only */

/*
 * Initialise a SSH filexfer connection. Returns NULL on error or
 * a pointer to a initialized sftp_conn struct on success.
 */
ರಚನೆ sftp_conn *sftp_init(ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, u_int, u_int, uint64_t);
ಶೂನ್ಯ sftp_free(ರಚನೆ sftp_conn *);

u_int sftp_proto_ಆವೃತ್ತಿ(ರಚನೆ sftp_conn *);

/* Query server limits */
ಪೂರ್ಣಾಂಕ sftp_get_limits(ರಚನೆ sftp_conn *, ರಚನೆ sftp_limits *);

/* Close file referred to by 'handle' */
ಪೂರ್ಣಾಂಕ sftp_close(ರಚನೆ sftp_conn *, ಸ್ಥಿರಾಂಕ u_char *, u_int);

/* Read contents of 'path' to NULL-terminated array 'dir' */
ಪೂರ್ಣಾಂಕ sftp_readdir(ರಚನೆ sftp_conn *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, SFTP_DIRENT ***);

/* Frees a NULL-terminated array of SFTP_DIRENTs (eg. from sftp_readdir) */
ಶೂನ್ಯ sftp_free_dirents(SFTP_DIRENT **);

/* Delete file 'path' */
ಪೂರ್ಣಾಂಕ sftp_rm(ರಚನೆ sftp_conn *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);

/* Create directory 'path' */
ಪೂರ್ಣಾಂಕ sftp_mkdir(ರಚನೆ sftp_conn *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, Attrib *, ಪೂರ್ಣಾಂಕ);

/* Create directory 'path' and intermediate directories as required */
ಪೂರ್ಣಾಂಕ sftp_mkpath(ರಚನೆ sftp_conn *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, Attrib *, ಪೂರ್ಣಾಂಕ);

/* Remove directory 'path' */
ಪೂರ್ಣಾಂಕ sftp_rmdir(ರಚನೆ sftp_conn *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);

/* Get file attributes of 'path' (follows symlinks) */
ಪೂರ್ಣಾಂಕ sftp_stat(ರಚನೆ sftp_conn *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ, Attrib *);

/* Get file attributes of 'path' (does not follow symlinks) */
ಪೂರ್ಣಾಂಕ sftp_lstat(ರಚನೆ sftp_conn *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ, Attrib *);

/* Set file attributes of 'path' */
ಪೂರ್ಣಾಂಕ sftp_setstat(ರಚನೆ sftp_conn *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, Attrib *);

/* Set file attributes of open file 'handle' */
ಪೂರ್ಣಾಂಕ sftp_fsetstat(ರಚನೆ sftp_conn *, ಸ್ಥಿರಾಂಕ u_char *, u_int, Attrib *);

/* Set file attributes of 'path', not following symlinks */
ಪೂರ್ಣಾಂಕ sftp_lsetstat(ರಚನೆ sftp_conn *conn, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, Attrib *a);

/* Canonicalise 'path' - caller must free result */
ಅಕ್ಷರ *sftp_realpath(ರಚನೆ sftp_conn *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);

/* Canonicalisation with tilde expansion (requires server extension) */
ಅಕ್ಷರ *sftp_expand_ಮಾರ್ಗ(ರಚನೆ sftp_conn *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);

/* Returns non-zero if server can tilde-expand paths */
ಪೂರ್ಣಾಂಕ sftp_can_expand_ಮಾರ್ಗ(ರಚನೆ sftp_conn *);

/* Get statistics for filesystem hosting file at "path" */
ಪೂರ್ಣಾಂಕ sftp_statvfs(ರಚನೆ sftp_conn *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ರಚನೆ sftp_statvfs *, ಪೂರ್ಣಾಂಕ);

/* Rename 'oldpath' to 'newpath' */
ಪೂರ್ಣಾಂಕ sftp_rename(ರಚನೆ sftp_conn *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ);

/* Copy 'oldpath' to 'newpath' */
ಪೂರ್ಣಾಂಕ sftp_copy(ರಚನೆ sftp_conn *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);

/* Link 'oldpath' to 'newpath' */
ಪೂರ್ಣಾಂಕ sftp_hardlink(ರಚನೆ sftp_conn *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);

/* Rename 'oldpath' to 'newpath' */
ಪೂರ್ಣಾಂಕ sftp_symlink(ರಚನೆ sftp_conn *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);

/* Call fsync() on open file 'handle' */
ಪೂರ್ಣಾಂಕ sftp_fsync(ರಚನೆ sftp_conn *conn, u_char *, u_int);

/*
 * Download 'remote_path' to 'local_path'. Preserve permissions and times
 * if 'pflag' is set
 */
ಪೂರ್ಣಾಂಕ sftp_download(ರಚನೆ sftp_conn *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, Attrib *,
    ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ);

/*
 * Recursively download 'remote_directory' to 'local_directory'. Preserve
 * times if 'pflag' is set
 */
ಪೂರ್ಣಾಂಕ sftp_download_dir(ರಚನೆ sftp_conn *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, Attrib *,
    ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ);

/*
 * Upload 'local_path' to 'remote_path'. Preserve permissions and times
 * if 'pflag' is set
 */
ಪೂರ್ಣಾಂಕ sftp_upload(ರಚನೆ sftp_conn *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *,
    ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ);

/*
 * Recursively upload 'local_directory' to 'remote_directory'. Preserve
 * times if 'pflag' is set
 */
ಪೂರ್ಣಾಂಕ sftp_upload_dir(ರಚನೆ sftp_conn *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *,
    ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ);

/*
 * Download a 'from_path' from the 'from' connection and upload it to
 * to 'to' connection at 'to_path'.
 */
ಪೂರ್ಣಾಂಕ sftp_crossload(ರಚನೆ sftp_conn *from, ರಚನೆ sftp_conn *ಗಮ್ಯ,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *from_ಮಾರ್ಗ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಗಮ್ಯ_ಮಾರ್ಗ,
    Attrib *a, ಪೂರ್ಣಾಂಕ preserve_flag);

/*
 * Recursively download a directory from 'from_path' from the 'from'
 * connection and upload it to 'to' connection at 'to_path'.
 */
ಪೂರ್ಣಾಂಕ sftp_crossload_dir(ರಚನೆ sftp_conn *from, ರಚನೆ sftp_conn *ಗಮ್ಯ,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *from_ಮಾರ್ಗ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಗಮ್ಯ_ಮಾರ್ಗ,
    Attrib *dirattrib, ಪೂರ್ಣಾಂಕ preserve_flag, ಪೂರ್ಣಾಂಕ print_flag,
    ಪೂರ್ಣಾಂಕ follow_link_flag);

/*
 * User/group ID to name translation.
 */
ಪೂರ್ಣಾಂಕ sftp_can_get_users_groups_by_id(ರಚನೆ sftp_conn *conn);
ಪೂರ್ಣಾಂಕ sftp_get_users_groups_by_id(ರಚನೆ sftp_conn *conn,
    ಸ್ಥಿರಾಂಕ u_int *uids, u_int nuids,
    ಸ್ಥಿರಾಂಕ u_int *gids, u_int ngids,
    ಅಕ್ಷರ ***usernamesp, ಅಕ್ಷರ ***groupnamesp);

/* Concatenate paths, taking care of slashes. Caller must free result. */
ಅಕ್ಷರ *sftp_ಮಾರ್ಗ_append(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);

/* Make absolute path if relative path and CWD is given. Does not modify
 * original if the path is already absolute. */
ಅಕ್ಷರ *sftp_make_absolute(ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);

/* Check if remote path is directory */
ಪೂರ್ಣಾಂಕ sftp_remote_is_dir(ರಚನೆ sftp_conn *conn, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ);

/* Check whether path returned from glob(..., GLOB_MARK, ...) is a directory */
ಪೂರ್ಣಾಂಕ sftp_globpath_is_dir(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pathname);

#ಆದರೆ_ಅಂತ್ಯ
