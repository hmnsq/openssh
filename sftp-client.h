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

تعریفنوع ساختار SFTP_DIRENT SFTP_DIRENT;

ساختار SFTP_DIRENT {
	نویسه *filename;
	نویسه *longname;
	Attrib a;
};

/*
 * Used for statvfs responses on the wire from the server, because the
 * server's native format may be larger than the client's.
 */
ساختار sftp_statvfs {
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
ساختار sftp_limits {
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
ساختار sftp_conn *sftp_init(صحیح, صحیح, u_int, u_int, uint64_t);
تهی sftp_free(ساختار sftp_conn *);

u_int sftp_proto_version(ساختار sftp_conn *);

/* Query server limits */
صحیح sftp_get_limits(ساختار sftp_conn *, ساختار sftp_limits *);

/* Close file referred to by 'handle' */
صحیح sftp_close(ساختار sftp_conn *, ثابت u_char *, u_int);

/* Read contents of 'path' to NULL-terminated array 'dir' */
صحیح sftp_readdir(ساختار sftp_conn *, ثابت نویسه *, SFTP_DIRENT ***);

/* Frees a NULL-terminated array of SFTP_DIRENTs (eg. from sftp_readdir) */
تهی sftp_free_dirents(SFTP_DIRENT **);

/* Delete file 'path' */
صحیح sftp_rm(ساختار sftp_conn *, ثابت نویسه *);

/* Create directory 'path' */
صحیح sftp_mkdir(ساختار sftp_conn *, ثابت نویسه *, Attrib *, صحیح);

/* Create directory 'path' and intermediate directories as required */
صحیح sftp_mkpath(ساختار sftp_conn *, ثابت نویسه *, Attrib *, صحیح);

/* Remove directory 'path' */
صحیح sftp_rmdir(ساختار sftp_conn *, ثابت نویسه *);

/* Get file attributes of 'path' (follows symlinks) */
صحیح sftp_stat(ساختار sftp_conn *, ثابت نویسه *, صحیح, Attrib *);

/* Get file attributes of 'path' (does not follow symlinks) */
صحیح sftp_lstat(ساختار sftp_conn *, ثابت نویسه *, صحیح, Attrib *);

/* Set file attributes of 'path' */
صحیح sftp_setstat(ساختار sftp_conn *, ثابت نویسه *, Attrib *);

/* Set file attributes of open file 'handle' */
صحیح sftp_fsetstat(ساختار sftp_conn *, ثابت u_char *, u_int, Attrib *);

/* Set file attributes of 'path', not following symlinks */
صحیح sftp_lsetstat(ساختار sftp_conn *conn, ثابت نویسه *path, Attrib *a);

/* Canonicalise 'path' - caller must free result */
نویسه *sftp_realpath(ساختار sftp_conn *, ثابت نویسه *);

/* Canonicalisation with tilde expansion (requires server extension) */
نویسه *sftp_expand_path(ساختار sftp_conn *, ثابت نویسه *);

/* Returns non-zero if server can tilde-expand paths */
صحیح sftp_can_expand_path(ساختار sftp_conn *);

/* Get statistics for filesystem hosting file at "path" */
صحیح sftp_statvfs(ساختار sftp_conn *, ثابت نویسه *, ساختار sftp_statvfs *, صحیح);

/* Rename 'oldpath' to 'newpath' */
صحیح sftp_rename(ساختار sftp_conn *, ثابت نویسه *, ثابت نویسه *, صحیح);

/* Copy 'oldpath' to 'newpath' */
صحیح sftp_copy(ساختار sftp_conn *, ثابت نویسه *, ثابت نویسه *);

/* Link 'oldpath' to 'newpath' */
صحیح sftp_hardlink(ساختار sftp_conn *, ثابت نویسه *, ثابت نویسه *);

/* Rename 'oldpath' to 'newpath' */
صحیح sftp_symlink(ساختار sftp_conn *, ثابت نویسه *, ثابت نویسه *);

/* Call fsync() on open file 'handle' */
صحیح sftp_fsync(ساختار sftp_conn *conn, u_char *, u_int);

/*
 * Download 'remote_path' to 'local_path'. Preserve permissions and times
 * if 'pflag' is set
 */
صحیح sftp_download(ساختار sftp_conn *, ثابت نویسه *, ثابت نویسه *, Attrib *,
    صحیح, صحیح, صحیح, صحیح);

/*
 * Recursively download 'remote_directory' to 'local_directory'. Preserve
 * times if 'pflag' is set
 */
صحیح sftp_download_dir(ساختار sftp_conn *, ثابت نویسه *, ثابت نویسه *, Attrib *,
    صحیح, صحیح, صحیح, صحیح, صحیح, صحیح);

/*
 * Upload 'local_path' to 'remote_path'. Preserve permissions and times
 * if 'pflag' is set
 */
صحیح sftp_upload(ساختار sftp_conn *, ثابت نویسه *, ثابت نویسه *,
    صحیح, صحیح, صحیح, صحیح);

/*
 * Recursively upload 'local_directory' to 'remote_directory'. Preserve
 * times if 'pflag' is set
 */
صحیح sftp_upload_dir(ساختار sftp_conn *, ثابت نویسه *, ثابت نویسه *,
    صحیح, صحیح, صحیح, صحیح, صحیح, صحیح);

/*
 * Download a 'from_path' from the 'from' connection and upload it to
 * to 'to' connection at 'to_path'.
 */
صحیح sftp_crossload(ساختار sftp_conn *from, ساختار sftp_conn *to,
    ثابت نویسه *from_path, ثابت نویسه *to_path,
    Attrib *a, صحیح preserve_flag);

/*
 * Recursively download a directory from 'from_path' from the 'from'
 * connection and upload it to 'to' connection at 'to_path'.
 */
صحیح sftp_crossload_dir(ساختار sftp_conn *from, ساختار sftp_conn *to,
    ثابت نویسه *from_path, ثابت نویسه *to_path,
    Attrib *dirattrib, صحیح preserve_flag, صحیح print_flag,
    صحیح follow_link_flag);

/*
 * User/group ID to name translation.
 */
صحیح sftp_can_get_users_groups_by_id(ساختار sftp_conn *conn);
صحیح sftp_get_users_groups_by_id(ساختار sftp_conn *conn,
    ثابت u_int *uids, u_int nuids,
    ثابت u_int *gids, u_int ngids,
    نویسه ***usernamesp, نویسه ***groupnamesp);

/* Concatenate paths, taking care of slashes. Caller must free result. */
نویسه *sftp_path_append(ثابت نویسه *, ثابت نویسه *);

/* Make absolute path if relative path and CWD is given. Does not modify
 * original if the path is already absolute. */
نویسه *sftp_make_absolute(نویسه *, ثابت نویسه *);

/* Check if remote path is directory */
صحیح sftp_remote_is_dir(ساختار sftp_conn *conn, ثابت نویسه *path);

/* Check whether path returned from glob(..., GLOB_MARK, ...) is a directory */
صحیح sftp_globpath_is_dir(ثابت نویسه *pathname);

#endif
