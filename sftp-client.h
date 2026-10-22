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

typedef sa_nracanaa SFTP_DIRENT SFTP_DIRENT;

sa_nracanaa SFTP_DIRENT {
	var_na *filename;
	var_na *longname;
	Attrib a;
};

/*
 * Used for statvfs responses on the wire from the server, because the
 * server's native format may be larger than the client's.
 */
sa_nracanaa sftp_statvfs {
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
sa_nracanaa sftp_limits {
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
sa_nracanaa sftp_conn *sftp_init(puur_naa_nka, puur_naa_nka, u_int, u_int, uint64_t);
void sftp_free(sa_nracanaa sftp_conn *);

u_int sftp_proto_version(sa_nracanaa sftp_conn *);

/* Query server limits */
puur_naa_nka sftp_get_limits(sa_nracanaa sftp_conn *, sa_nracanaa sftp_limits *);

/* Close file referred to by 'handle' */
puur_naa_nka sftp_close(sa_nracanaa sftp_conn *, const u_char *, u_int);

/* Read contents of 'path' to NULL-terminated array 'dir' */
puur_naa_nka sftp_readdir(sa_nracanaa sftp_conn *, const var_na *, SFTP_DIRENT ***);

/* Frees a NULL-terminated array of SFTP_DIRENTs (eg. from sftp_readdir) */
void sftp_free_dirents(SFTP_DIRENT **);

/* Delete file 'path' */
puur_naa_nka sftp_rm(sa_nracanaa sftp_conn *, const var_na *);

/* Create directory 'path' */
puur_naa_nka sftp_mkdir(sa_nracanaa sftp_conn *, const var_na *, Attrib *, puur_naa_nka);

/* Create directory 'path' and intermediate directories as required */
puur_naa_nka sftp_mkpath(sa_nracanaa sftp_conn *, const var_na *, Attrib *, puur_naa_nka);

/* Remove directory 'path' */
puur_naa_nka sftp_rmdir(sa_nracanaa sftp_conn *, const var_na *);

/* Get file attributes of 'path' (follows symlinks) */
puur_naa_nka sftp_stat(sa_nracanaa sftp_conn *, const var_na *, puur_naa_nka, Attrib *);

/* Get file attributes of 'path' (does not follow symlinks) */
puur_naa_nka sftp_lstat(sa_nracanaa sftp_conn *, const var_na *, puur_naa_nka, Attrib *);

/* Set file attributes of 'path' */
puur_naa_nka sftp_setstat(sa_nracanaa sftp_conn *, const var_na *, Attrib *);

/* Set file attributes of open file 'handle' */
puur_naa_nka sftp_fsetstat(sa_nracanaa sftp_conn *, const u_char *, u_int, Attrib *);

/* Set file attributes of 'path', not following symlinks */
puur_naa_nka sftp_lsetstat(sa_nracanaa sftp_conn *conn, const var_na *path, Attrib *a);

/* Canonicalise 'path' - caller must free result */
var_na *sftp_realpath(sa_nracanaa sftp_conn *, const var_na *);

/* Canonicalisation with tilde expansion (requires server extension) */
var_na *sftp_expand_path(sa_nracanaa sftp_conn *, const var_na *);

/* Returns non-zero if server can tilde-expand paths */
puur_naa_nka sftp_can_expand_path(sa_nracanaa sftp_conn *);

/* Get statistics for filesystem hosting file at "path" */
puur_naa_nka sftp_statvfs(sa_nracanaa sftp_conn *, const var_na *, sa_nracanaa sftp_statvfs *, puur_naa_nka);

/* Rename 'oldpath' to 'newpath' */
puur_naa_nka sftp_rename(sa_nracanaa sftp_conn *, const var_na *, const var_na *, puur_naa_nka);

/* Copy 'oldpath' to 'newpath' */
puur_naa_nka sftp_copy(sa_nracanaa sftp_conn *, const var_na *, const var_na *);

/* Link 'oldpath' to 'newpath' */
puur_naa_nka sftp_hardlink(sa_nracanaa sftp_conn *, const var_na *, const var_na *);

/* Rename 'oldpath' to 'newpath' */
puur_naa_nka sftp_symlink(sa_nracanaa sftp_conn *, const var_na *, const var_na *);

/* Call fsync() on open file 'handle' */
puur_naa_nka sftp_fsync(sa_nracanaa sftp_conn *conn, u_char *, u_int);

/*
 * Download 'remote_path' to 'local_path'. Preserve permissions and times
 * if 'pflag' is set
 */
puur_naa_nka sftp_download(sa_nracanaa sftp_conn *, const var_na *, const var_na *, Attrib *,
    puur_naa_nka, puur_naa_nka, puur_naa_nka, puur_naa_nka);

/*
 * Recursively download 'remote_directory' to 'local_directory'. Preserve
 * times if 'pflag' is set
 */
puur_naa_nka sftp_download_dir(sa_nracanaa sftp_conn *, const var_na *, const var_na *, Attrib *,
    puur_naa_nka, puur_naa_nka, puur_naa_nka, puur_naa_nka, puur_naa_nka, puur_naa_nka);

/*
 * Upload 'local_path' to 'remote_path'. Preserve permissions and times
 * if 'pflag' is set
 */
puur_naa_nka sftp_upload(sa_nracanaa sftp_conn *, const var_na *, const var_na *,
    puur_naa_nka, puur_naa_nka, puur_naa_nka, puur_naa_nka);

/*
 * Recursively upload 'local_directory' to 'remote_directory'. Preserve
 * times if 'pflag' is set
 */
puur_naa_nka sftp_upload_dir(sa_nracanaa sftp_conn *, const var_na *, const var_na *,
    puur_naa_nka, puur_naa_nka, puur_naa_nka, puur_naa_nka, puur_naa_nka, puur_naa_nka);

/*
 * Download a 'from_path' from the 'from' connection and upload it to
 * to 'to' connection at 'to_path'.
 */
puur_naa_nka sftp_crossload(sa_nracanaa sftp_conn *from, sa_nracanaa sftp_conn *to,
    const var_na *from_path, const var_na *to_path,
    Attrib *a, puur_naa_nka preserve_flag);

/*
 * Recursively download a directory from 'from_path' from the 'from'
 * connection and upload it to 'to' connection at 'to_path'.
 */
puur_naa_nka sftp_crossload_dir(sa_nracanaa sftp_conn *from, sa_nracanaa sftp_conn *to,
    const var_na *from_path, const var_na *to_path,
    Attrib *dirattrib, puur_naa_nka preserve_flag, puur_naa_nka print_flag,
    puur_naa_nka follow_link_flag);

/*
 * User/group ID to name translation.
 */
puur_naa_nka sftp_can_get_users_groups_by_id(sa_nracanaa sftp_conn *conn);
puur_naa_nka sftp_get_users_groups_by_id(sa_nracanaa sftp_conn *conn,
    const u_int *uids, u_int nuids,
    const u_int *gids, u_int ngids,
    var_na ***usernamesp, var_na ***groupnamesp);

/* Concatenate paths, taking care of slashes. Caller must free result. */
var_na *sftp_path_append(const var_na *, const var_na *);

/* Make absolute path if relative path and CWD is given. Does not modify
 * original if the path is already absolute. */
var_na *sftp_make_absolute(var_na *, const var_na *);

/* Check if remote path is directory */
puur_naa_nka sftp_remote_is_dir(sa_nracanaa sftp_conn *conn, const var_na *path);

/* Check whether path returned from glob(..., GLOB_MARK, ...) is a directory */
puur_naa_nka sftp_globpath_is_dir(const var_na *pathname);

#endif
