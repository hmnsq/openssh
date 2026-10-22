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

തരനിർവചനം ഘടന SFTP_DIRENT SFTP_DIRENT;

ഘടന SFTP_DIRENT {
	അക്ഷരം *filename;
	അക്ഷരം *longname;
	Attrib a;
};

/*
 * Used for statvfs responses on the wire from the server, because the
 * server's native format may be larger than the client's.
 */
ഘടന sftp_statvfs {
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
ഘടന sftp_limits {
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
ഘടന sftp_conn *sftp_init(പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ, u_int, u_int, uint64_t);
ശൂന്യം sftp_free(ഘടന sftp_conn *);

u_int sftp_proto_version(ഘടന sftp_conn *);

/* Query server limits */
പൂർണ്ണസംഖ്യ sftp_get_limits(ഘടന sftp_conn *, ഘടന sftp_limits *);

/* Close file referred to by 'handle' */
പൂർണ്ണസംഖ്യ sftp_close(ഘടന sftp_conn *, സ്ഥിരം u_char *, u_int);

/* Read contents of 'path' to NULL-terminated array 'dir' */
പൂർണ്ണസംഖ്യ sftp_readdir(ഘടന sftp_conn *, സ്ഥിരം അക്ഷരം *, SFTP_DIRENT ***);

/* Frees a NULL-terminated array of SFTP_DIRENTs (eg. from sftp_readdir) */
ശൂന്യം sftp_free_dirents(SFTP_DIRENT **);

/* Delete file 'path' */
പൂർണ്ണസംഖ്യ sftp_rm(ഘടന sftp_conn *, സ്ഥിരം അക്ഷരം *);

/* Create directory 'path' */
പൂർണ്ണസംഖ്യ sftp_mkdir(ഘടന sftp_conn *, സ്ഥിരം അക്ഷരം *, Attrib *, പൂർണ്ണസംഖ്യ);

/* Create directory 'path' and intermediate directories as required */
പൂർണ്ണസംഖ്യ sftp_mkpath(ഘടന sftp_conn *, സ്ഥിരം അക്ഷരം *, Attrib *, പൂർണ്ണസംഖ്യ);

/* Remove directory 'path' */
പൂർണ്ണസംഖ്യ sftp_rmdir(ഘടന sftp_conn *, സ്ഥിരം അക്ഷരം *);

/* Get file attributes of 'path' (follows symlinks) */
പൂർണ്ണസംഖ്യ sftp_stat(ഘടന sftp_conn *, സ്ഥിരം അക്ഷരം *, പൂർണ്ണസംഖ്യ, Attrib *);

/* Get file attributes of 'path' (does not follow symlinks) */
പൂർണ്ണസംഖ്യ sftp_lstat(ഘടന sftp_conn *, സ്ഥിരം അക്ഷരം *, പൂർണ്ണസംഖ്യ, Attrib *);

/* Set file attributes of 'path' */
പൂർണ്ണസംഖ്യ sftp_setstat(ഘടന sftp_conn *, സ്ഥിരം അക്ഷരം *, Attrib *);

/* Set file attributes of open file 'handle' */
പൂർണ്ണസംഖ്യ sftp_fsetstat(ഘടന sftp_conn *, സ്ഥിരം u_char *, u_int, Attrib *);

/* Set file attributes of 'path', not following symlinks */
പൂർണ്ണസംഖ്യ sftp_lsetstat(ഘടന sftp_conn *conn, സ്ഥിരം അക്ഷരം *path, Attrib *a);

/* Canonicalise 'path' - caller must free result */
അക്ഷരം *sftp_realpath(ഘടന sftp_conn *, സ്ഥിരം അക്ഷരം *);

/* Canonicalisation with tilde expansion (requires server extension) */
അക്ഷരം *sftp_expand_path(ഘടന sftp_conn *, സ്ഥിരം അക്ഷരം *);

/* Returns non-zero if server can tilde-expand paths */
പൂർണ്ണസംഖ്യ sftp_can_expand_path(ഘടന sftp_conn *);

/* Get statistics for filesystem hosting file at "path" */
പൂർണ്ണസംഖ്യ sftp_statvfs(ഘടന sftp_conn *, സ്ഥിരം അക്ഷരം *, ഘടന sftp_statvfs *, പൂർണ്ണസംഖ്യ);

/* Rename 'oldpath' to 'newpath' */
പൂർണ്ണസംഖ്യ sftp_rename(ഘടന sftp_conn *, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, പൂർണ്ണസംഖ്യ);

/* Copy 'oldpath' to 'newpath' */
പൂർണ്ണസംഖ്യ sftp_copy(ഘടന sftp_conn *, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *);

/* Link 'oldpath' to 'newpath' */
പൂർണ്ണസംഖ്യ sftp_hardlink(ഘടന sftp_conn *, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *);

/* Rename 'oldpath' to 'newpath' */
പൂർണ്ണസംഖ്യ sftp_symlink(ഘടന sftp_conn *, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *);

/* Call fsync() on open file 'handle' */
പൂർണ്ണസംഖ്യ sftp_fsync(ഘടന sftp_conn *conn, u_char *, u_int);

/*
 * Download 'remote_path' to 'local_path'. Preserve permissions and times
 * if 'pflag' is set
 */
പൂർണ്ണസംഖ്യ sftp_download(ഘടന sftp_conn *, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, Attrib *,
    പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ);

/*
 * Recursively download 'remote_directory' to 'local_directory'. Preserve
 * times if 'pflag' is set
 */
പൂർണ്ണസംഖ്യ sftp_download_dir(ഘടന sftp_conn *, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, Attrib *,
    പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ);

/*
 * Upload 'local_path' to 'remote_path'. Preserve permissions and times
 * if 'pflag' is set
 */
പൂർണ്ണസംഖ്യ sftp_upload(ഘടന sftp_conn *, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *,
    പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ);

/*
 * Recursively upload 'local_directory' to 'remote_directory'. Preserve
 * times if 'pflag' is set
 */
പൂർണ്ണസംഖ്യ sftp_upload_dir(ഘടന sftp_conn *, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *,
    പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ);

/*
 * Download a 'from_path' from the 'from' connection and upload it to
 * to 'to' connection at 'to_path'.
 */
പൂർണ്ണസംഖ്യ sftp_crossload(ഘടന sftp_conn *from, ഘടന sftp_conn *to,
    സ്ഥിരം അക്ഷരം *from_path, സ്ഥിരം അക്ഷരം *to_path,
    Attrib *a, പൂർണ്ണസംഖ്യ preserve_flag);

/*
 * Recursively download a directory from 'from_path' from the 'from'
 * connection and upload it to 'to' connection at 'to_path'.
 */
പൂർണ്ണസംഖ്യ sftp_crossload_dir(ഘടന sftp_conn *from, ഘടന sftp_conn *to,
    സ്ഥിരം അക്ഷരം *from_path, സ്ഥിരം അക്ഷരം *to_path,
    Attrib *dirattrib, പൂർണ്ണസംഖ്യ preserve_flag, പൂർണ്ണസംഖ്യ print_flag,
    പൂർണ്ണസംഖ്യ follow_link_flag);

/*
 * User/group ID to name translation.
 */
പൂർണ്ണസംഖ്യ sftp_can_get_users_groups_by_id(ഘടന sftp_conn *conn);
പൂർണ്ണസംഖ്യ sftp_get_users_groups_by_id(ഘടന sftp_conn *conn,
    സ്ഥിരം u_int *uids, u_int nuids,
    സ്ഥിരം u_int *gids, u_int ngids,
    അക്ഷരം ***usernamesp, അക്ഷരം ***groupnamesp);

/* Concatenate paths, taking care of slashes. Caller must free result. */
അക്ഷരം *sftp_path_append(സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *);

/* Make absolute path if relative path and CWD is given. Does not modify
 * original if the path is already absolute. */
അക്ഷരം *sftp_make_absolute(അക്ഷരം *, സ്ഥിരം അക്ഷരം *);

/* Check if remote path is directory */
പൂർണ്ണസംഖ്യ sftp_remote_is_dir(ഘടന sftp_conn *conn, സ്ഥിരം അക്ഷരം *path);

/* Check whether path returned from glob(..., GLOB_MARK, ...) is a directory */
പൂർണ്ണസംഖ്യ sftp_globpath_is_dir(സ്ഥിരം അക്ഷരം *pathname);

#endif
