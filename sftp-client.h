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

प्रकारनिर्देश संरचना SFTP_DIRENT SFTP_DIRENT;

संरचना SFTP_DIRENT {
	वर्ण *filename;
	वर्ण *longname;
	Attrib a;
};

/*
 * Used for statvfs responses on the wire from the server, because the
 * server's native format may be larger than the client's.
 */
संरचना sftp_statvfs {
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
संरचना sftp_limits {
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
संरचना sftp_conn *sftp_init(पूर्णाङ्क, पूर्णाङ्क, u_int, u_int, uint64_t);
शून्य sftp_free(संरचना sftp_conn *);

u_int sftp_proto_version(संरचना sftp_conn *);

/* Query server limits */
पूर्णाङ्क sftp_get_limits(संरचना sftp_conn *, संरचना sftp_limits *);

/* Close file referred to by 'handle' */
पूर्णाङ्क sftp_close(संरचना sftp_conn *, ध्रुव u_char *, u_int);

/* Read contents of 'path' to NULL-terminated array 'dir' */
पूर्णाङ्क sftp_readdir(संरचना sftp_conn *, ध्रुव वर्ण *, SFTP_DIRENT ***);

/* Frees a NULL-terminated array of SFTP_DIRENTs (eg. from sftp_readdir) */
शून्य sftp_free_dirents(SFTP_DIRENT **);

/* Delete file 'path' */
पूर्णाङ्क sftp_rm(संरचना sftp_conn *, ध्रुव वर्ण *);

/* Create directory 'path' */
पूर्णाङ्क sftp_mkdir(संरचना sftp_conn *, ध्रुव वर्ण *, Attrib *, पूर्णाङ्क);

/* Create directory 'path' and intermediate directories as required */
पूर्णाङ्क sftp_mkpath(संरचना sftp_conn *, ध्रुव वर्ण *, Attrib *, पूर्णाङ्क);

/* Remove directory 'path' */
पूर्णाङ्क sftp_rmdir(संरचना sftp_conn *, ध्रुव वर्ण *);

/* Get file attributes of 'path' (follows symlinks) */
पूर्णाङ्क sftp_stat(संरचना sftp_conn *, ध्रुव वर्ण *, पूर्णाङ्क, Attrib *);

/* Get file attributes of 'path' (does not follow symlinks) */
पूर्णाङ्क sftp_lstat(संरचना sftp_conn *, ध्रुव वर्ण *, पूर्णाङ्क, Attrib *);

/* Set file attributes of 'path' */
पूर्णाङ्क sftp_setstat(संरचना sftp_conn *, ध्रुव वर्ण *, Attrib *);

/* Set file attributes of open file 'handle' */
पूर्णाङ्क sftp_fsetstat(संरचना sftp_conn *, ध्रुव u_char *, u_int, Attrib *);

/* Set file attributes of 'path', not following symlinks */
पूर्णाङ्क sftp_lsetstat(संरचना sftp_conn *conn, ध्रुव वर्ण *path, Attrib *a);

/* Canonicalise 'path' - caller must free result */
वर्ण *sftp_realpath(संरचना sftp_conn *, ध्रुव वर्ण *);

/* Canonicalisation with tilde expansion (requires server extension) */
वर्ण *sftp_expand_path(संरचना sftp_conn *, ध्रुव वर्ण *);

/* Returns non-zero if server can tilde-expand paths */
पूर्णाङ्क sftp_can_expand_path(संरचना sftp_conn *);

/* Get statistics for filesystem hosting file at "path" */
पूर्णाङ्क sftp_statvfs(संरचना sftp_conn *, ध्रुव वर्ण *, संरचना sftp_statvfs *, पूर्णाङ्क);

/* Rename 'oldpath' to 'newpath' */
पूर्णाङ्क sftp_rename(संरचना sftp_conn *, ध्रुव वर्ण *, ध्रुव वर्ण *, पूर्णाङ्क);

/* Copy 'oldpath' to 'newpath' */
पूर्णाङ्क sftp_copy(संरचना sftp_conn *, ध्रुव वर्ण *, ध्रुव वर्ण *);

/* Link 'oldpath' to 'newpath' */
पूर्णाङ्क sftp_hardlink(संरचना sftp_conn *, ध्रुव वर्ण *, ध्रुव वर्ण *);

/* Rename 'oldpath' to 'newpath' */
पूर्णाङ्क sftp_symlink(संरचना sftp_conn *, ध्रुव वर्ण *, ध्रुव वर्ण *);

/* Call fsync() on open file 'handle' */
पूर्णाङ्क sftp_fsync(संरचना sftp_conn *conn, u_char *, u_int);

/*
 * Download 'remote_path' to 'local_path'. Preserve permissions and times
 * if 'pflag' is set
 */
पूर्णाङ्क sftp_download(संरचना sftp_conn *, ध्रुव वर्ण *, ध्रुव वर्ण *, Attrib *,
    पूर्णाङ्क, पूर्णाङ्क, पूर्णाङ्क, पूर्णाङ्क);

/*
 * Recursively download 'remote_directory' to 'local_directory'. Preserve
 * times if 'pflag' is set
 */
पूर्णाङ्क sftp_download_dir(संरचना sftp_conn *, ध्रुव वर्ण *, ध्रुव वर्ण *, Attrib *,
    पूर्णाङ्क, पूर्णाङ्क, पूर्णाङ्क, पूर्णाङ्क, पूर्णाङ्क, पूर्णाङ्क);

/*
 * Upload 'local_path' to 'remote_path'. Preserve permissions and times
 * if 'pflag' is set
 */
पूर्णाङ्क sftp_upload(संरचना sftp_conn *, ध्रुव वर्ण *, ध्रुव वर्ण *,
    पूर्णाङ्क, पूर्णाङ्क, पूर्णाङ्क, पूर्णाङ्क);

/*
 * Recursively upload 'local_directory' to 'remote_directory'. Preserve
 * times if 'pflag' is set
 */
पूर्णाङ्क sftp_upload_dir(संरचना sftp_conn *, ध्रुव वर्ण *, ध्रुव वर्ण *,
    पूर्णाङ्क, पूर्णाङ्क, पूर्णाङ्क, पूर्णाङ्क, पूर्णाङ्क, पूर्णाङ्क);

/*
 * Download a 'from_path' from the 'from' connection and upload it to
 * to 'to' connection at 'to_path'.
 */
पूर्णाङ्क sftp_crossload(संरचना sftp_conn *from, संरचना sftp_conn *to,
    ध्रुव वर्ण *from_path, ध्रुव वर्ण *to_path,
    Attrib *a, पूर्णाङ्क preserve_flag);

/*
 * Recursively download a directory from 'from_path' from the 'from'
 * connection and upload it to 'to' connection at 'to_path'.
 */
पूर्णाङ्क sftp_crossload_dir(संरचना sftp_conn *from, संरचना sftp_conn *to,
    ध्रुव वर्ण *from_path, ध्रुव वर्ण *to_path,
    Attrib *dirattrib, पूर्णाङ्क preserve_flag, पूर्णाङ्क print_flag,
    पूर्णाङ्क follow_link_flag);

/*
 * User/group ID to name translation.
 */
पूर्णाङ्क sftp_can_get_users_groups_by_id(संरचना sftp_conn *conn);
पूर्णाङ्क sftp_get_users_groups_by_id(संरचना sftp_conn *conn,
    ध्रुव u_int *uids, u_int nuids,
    ध्रुव u_int *gids, u_int ngids,
    वर्ण ***usernamesp, वर्ण ***groupnamesp);

/* Concatenate paths, taking care of slashes. Caller must free result. */
वर्ण *sftp_path_append(ध्रुव वर्ण *, ध्रुव वर्ण *);

/* Make absolute path if relative path and CWD is given. Does not modify
 * original if the path is already absolute. */
वर्ण *sftp_make_absolute(वर्ण *, ध्रुव वर्ण *);

/* Check if remote path is directory */
पूर्णाङ्क sftp_remote_is_dir(संरचना sftp_conn *conn, ध्रुव वर्ण *path);

/* Check whether path returned from glob(..., GLOB_MARK, ...) is a directory */
पूर्णाङ्क sftp_globpath_is_dir(ध्रुव वर्ण *pathname);

#endif
