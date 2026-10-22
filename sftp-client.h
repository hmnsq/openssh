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

ପ୍ରକାରବ୍ୟାଖ୍ୟା ସଂରଚନା SFTP_DIRENT SFTP_DIRENT;

ସଂରଚନା SFTP_DIRENT {
	ଅକ୍ଷର *filename;
	ଅକ୍ଷର *longname;
	Attrib a;
};

/*
 * Used for statvfs responses on the wire from the server, because the
 * server's native format may be larger than the client's.
 */
ସଂରଚନା sftp_statvfs {
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
ସଂରଚନା sftp_limits {
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
ସଂରଚନା sftp_conn *sftp_init(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, u_int, u_int, uint64_t);
ଶୂନ୍ୟ sftp_free(ସଂରଚନା sftp_conn *);

u_int sftp_proto_version(ସଂରଚନା sftp_conn *);

/* Query server limits */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sftp_get_limits(ସଂରଚନା sftp_conn *, ସଂରଚନା sftp_limits *);

/* Close file referred to by 'handle' */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sftp_close(ସଂରଚନା sftp_conn *, ଅଚଳ u_char *, u_int);

/* Read contents of 'path' to NULL-terminated array 'dir' */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sftp_readdir(ସଂରଚନା sftp_conn *, ଅଚଳ ଅକ୍ଷର *, SFTP_DIRENT ***);

/* Frees a NULL-terminated array of SFTP_DIRENTs (eg. from sftp_readdir) */
ଶୂନ୍ୟ sftp_free_dirents(SFTP_DIRENT **);

/* Delete file 'path' */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sftp_rm(ସଂରଚନା sftp_conn *, ଅଚଳ ଅକ୍ଷର *);

/* Create directory 'path' */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sftp_mkdir(ସଂରଚନା sftp_conn *, ଅଚଳ ଅକ୍ଷର *, Attrib *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);

/* Create directory 'path' and intermediate directories as required */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sftp_mkpath(ସଂରଚନା sftp_conn *, ଅଚଳ ଅକ୍ଷର *, Attrib *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);

/* Remove directory 'path' */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sftp_rmdir(ସଂରଚନା sftp_conn *, ଅଚଳ ଅକ୍ଷର *);

/* Get file attributes of 'path' (follows symlinks) */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sftp_stat(ସଂରଚନା sftp_conn *, ଅଚଳ ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, Attrib *);

/* Get file attributes of 'path' (does not follow symlinks) */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sftp_lstat(ସଂରଚନା sftp_conn *, ଅଚଳ ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, Attrib *);

/* Set file attributes of 'path' */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sftp_setstat(ସଂରଚନା sftp_conn *, ଅଚଳ ଅକ୍ଷର *, Attrib *);

/* Set file attributes of open file 'handle' */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sftp_fsetstat(ସଂରଚନା sftp_conn *, ଅଚଳ u_char *, u_int, Attrib *);

/* Set file attributes of 'path', not following symlinks */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sftp_lsetstat(ସଂରଚନା sftp_conn *conn, ଅଚଳ ଅକ୍ଷର *path, Attrib *a);

/* Canonicalise 'path' - caller must free result */
ଅକ୍ଷର *sftp_realpath(ସଂରଚନା sftp_conn *, ଅଚଳ ଅକ୍ଷର *);

/* Canonicalisation with tilde expansion (requires server extension) */
ଅକ୍ଷର *sftp_expand_path(ସଂରଚନା sftp_conn *, ଅଚଳ ଅକ୍ଷର *);

/* Returns non-zero if server can tilde-expand paths */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sftp_can_expand_path(ସଂରଚନା sftp_conn *);

/* Get statistics for filesystem hosting file at "path" */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sftp_statvfs(ସଂରଚନା sftp_conn *, ଅଚଳ ଅକ୍ଷର *, ସଂରଚନା sftp_statvfs *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);

/* Rename 'oldpath' to 'newpath' */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sftp_rename(ସଂରଚନା sftp_conn *, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);

/* Copy 'oldpath' to 'newpath' */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sftp_copy(ସଂରଚନା sftp_conn *, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *);

/* Link 'oldpath' to 'newpath' */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sftp_hardlink(ସଂରଚନା sftp_conn *, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *);

/* Rename 'oldpath' to 'newpath' */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sftp_symlink(ସଂରଚନା sftp_conn *, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *);

/* Call fsync() on open file 'handle' */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sftp_fsync(ସଂରଚନା sftp_conn *conn, u_char *, u_int);

/*
 * Download 'remote_path' to 'local_path'. Preserve permissions and times
 * if 'pflag' is set
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sftp_download(ସଂରଚନା sftp_conn *, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, Attrib *,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);

/*
 * Recursively download 'remote_directory' to 'local_directory'. Preserve
 * times if 'pflag' is set
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sftp_download_dir(ସଂରଚନା sftp_conn *, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, Attrib *,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);

/*
 * Upload 'local_path' to 'remote_path'. Preserve permissions and times
 * if 'pflag' is set
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sftp_upload(ସଂରଚନା sftp_conn *, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);

/*
 * Recursively upload 'local_directory' to 'remote_directory'. Preserve
 * times if 'pflag' is set
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sftp_upload_dir(ସଂରଚନା sftp_conn *, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);

/*
 * Download a 'from_path' from the 'from' connection and upload it to
 * to 'to' connection at 'to_path'.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sftp_crossload(ସଂରଚନା sftp_conn *from, ସଂରଚନା sftp_conn *to,
    ଅଚଳ ଅକ୍ଷର *from_path, ଅଚଳ ଅକ୍ଷର *to_path,
    Attrib *a, ପୂର୍ଣ୍ଣସଂଖ୍ୟା preserve_flag);

/*
 * Recursively download a directory from 'from_path' from the 'from'
 * connection and upload it to 'to' connection at 'to_path'.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sftp_crossload_dir(ସଂରଚନା sftp_conn *from, ସଂରଚନା sftp_conn *to,
    ଅଚଳ ଅକ୍ଷର *from_path, ଅଚଳ ଅକ୍ଷର *to_path,
    Attrib *dirattrib, ପୂର୍ଣ୍ଣସଂଖ୍ୟା preserve_flag, ପୂର୍ଣ୍ଣସଂଖ୍ୟା print_flag,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା follow_link_flag);

/*
 * User/group ID to name translation.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sftp_can_get_users_groups_by_id(ସଂରଚନା sftp_conn *conn);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sftp_get_users_groups_by_id(ସଂରଚନା sftp_conn *conn,
    ଅଚଳ u_int *uids, u_int nuids,
    ଅଚଳ u_int *gids, u_int ngids,
    ଅକ୍ଷର ***usernamesp, ଅକ୍ଷର ***groupnamesp);

/* Concatenate paths, taking care of slashes. Caller must free result. */
ଅକ୍ଷର *sftp_path_append(ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *);

/* Make absolute path if relative path and CWD is given. Does not modify
 * original if the path is already absolute. */
ଅକ୍ଷର *sftp_make_absolute(ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *);

/* Check if remote path is directory */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sftp_remote_is_dir(ସଂରଚନା sftp_conn *conn, ଅଚଳ ଅକ୍ଷର *path);

/* Check whether path returned from glob(..., GLOB_MARK, ...) is a directory */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sftp_globpath_is_dir(ଅଚଳ ଅକ୍ଷର *pathname);

#endif
