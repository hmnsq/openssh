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

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ _SFTP_CLIENT_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ _SFTP_CLIENT_H

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ SFTP_DIRENT SFTP_DIRENT;

ਬਣਤਰ SFTP_DIRENT {
	ਅੱਖਰ *filename;
	ਅੱਖਰ *longname;
	Attrib a;
};

/*
 * Used for statvfs responses on the wire from the server, because the
 * server's native format may be larger than the client's.
 */
ਬਣਤਰ sftp_statvfs {
	uint64_t f_bsize;
	uint64_t f_frsize;
	uint64_t f_ਖੰਡਾਂ;
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
ਬਣਤਰ sftp_limits {
	uint64_t packet_ਲੰਮਾਈ;
	uint64_t read_ਲੰਮਾਈ;
	uint64_t write_ਲੰਮਾਈ;
	uint64_t open_handles;
};

/* print flag values */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SFTP_QUIET		0	/* be quiet during transfers */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SFTP_PRINT		1	/* list files and show progress bar */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SFTP_ਤਰੱਕੀ_ONLY	2	/* progress bar only */

/*
 * Initialise a SSH filexfer connection. Returns NULL on error or
 * a pointer to a initialized sftp_conn struct on success.
 */
ਬਣਤਰ sftp_conn *sftp_init(ਪੂਰਨ, ਪੂਰਨ, u_int, u_int, uint64_t);
ਖਾਲੀ sftp_free(ਬਣਤਰ sftp_conn *);

u_int sftp_proto_ਸੰਸਕਰਣ(ਬਣਤਰ sftp_conn *);

/* Query server limits */
ਪੂਰਨ sftp_get_limits(ਬਣਤਰ sftp_conn *, ਬਣਤਰ sftp_limits *);

/* Close file referred to by 'handle' */
ਪੂਰਨ sftp_close(ਬਣਤਰ sftp_conn *, ਅਚਲ u_char *, u_int);

/* Read contents of 'path' to NULL-terminated array 'dir' */
ਪੂਰਨ sftp_readdir(ਬਣਤਰ sftp_conn *, ਅਚਲ ਅੱਖਰ *, SFTP_DIRENT ***);

/* Frees a NULL-terminated array of SFTP_DIRENTs (eg. from sftp_readdir) */
ਖਾਲੀ sftp_free_dirents(SFTP_DIRENT **);

/* Delete file 'path' */
ਪੂਰਨ sftp_rm(ਬਣਤਰ sftp_conn *, ਅਚਲ ਅੱਖਰ *);

/* Create directory 'path' */
ਪੂਰਨ sftp_mkdir(ਬਣਤਰ sftp_conn *, ਅਚਲ ਅੱਖਰ *, Attrib *, ਪੂਰਨ);

/* Create directory 'path' and intermediate directories as required */
ਪੂਰਨ sftp_mkpath(ਬਣਤਰ sftp_conn *, ਅਚਲ ਅੱਖਰ *, Attrib *, ਪੂਰਨ);

/* Remove directory 'path' */
ਪੂਰਨ sftp_rmdir(ਬਣਤਰ sftp_conn *, ਅਚਲ ਅੱਖਰ *);

/* Get file attributes of 'path' (follows symlinks) */
ਪੂਰਨ sftp_stat(ਬਣਤਰ sftp_conn *, ਅਚਲ ਅੱਖਰ *, ਪੂਰਨ, Attrib *);

/* Get file attributes of 'path' (does not follow symlinks) */
ਪੂਰਨ sftp_lstat(ਬਣਤਰ sftp_conn *, ਅਚਲ ਅੱਖਰ *, ਪੂਰਨ, Attrib *);

/* Set file attributes of 'path' */
ਪੂਰਨ sftp_setstat(ਬਣਤਰ sftp_conn *, ਅਚਲ ਅੱਖਰ *, Attrib *);

/* Set file attributes of open file 'handle' */
ਪੂਰਨ sftp_fsetstat(ਬਣਤਰ sftp_conn *, ਅਚਲ u_char *, u_int, Attrib *);

/* Set file attributes of 'path', not following symlinks */
ਪੂਰਨ sftp_lsetstat(ਬਣਤਰ sftp_conn *conn, ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, Attrib *a);

/* Canonicalise 'path' - caller must free result */
ਅੱਖਰ *sftp_realpath(ਬਣਤਰ sftp_conn *, ਅਚਲ ਅੱਖਰ *);

/* Canonicalisation with tilde expansion (requires server extension) */
ਅੱਖਰ *sftp_expand_ਰਸਤਾ(ਬਣਤਰ sftp_conn *, ਅਚਲ ਅੱਖਰ *);

/* Returns non-zero if server can tilde-expand paths */
ਪੂਰਨ sftp_can_expand_ਰਸਤਾ(ਬਣਤਰ sftp_conn *);

/* Get statistics for filesystem hosting file at "path" */
ਪੂਰਨ sftp_statvfs(ਬਣਤਰ sftp_conn *, ਅਚਲ ਅੱਖਰ *, ਬਣਤਰ sftp_statvfs *, ਪੂਰਨ);

/* Rename 'oldpath' to 'newpath' */
ਪੂਰਨ sftp_rename(ਬਣਤਰ sftp_conn *, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਪੂਰਨ);

/* Copy 'oldpath' to 'newpath' */
ਪੂਰਨ sftp_copy(ਬਣਤਰ sftp_conn *, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *);

/* Link 'oldpath' to 'newpath' */
ਪੂਰਨ sftp_hardlink(ਬਣਤਰ sftp_conn *, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *);

/* Rename 'oldpath' to 'newpath' */
ਪੂਰਨ sftp_symlink(ਬਣਤਰ sftp_conn *, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *);

/* Call fsync() on open file 'handle' */
ਪੂਰਨ sftp_fsync(ਬਣਤਰ sftp_conn *conn, u_char *, u_int);

/*
 * Download 'remote_path' to 'local_path'. Preserve permissions and times
 * if 'pflag' is set
 */
ਪੂਰਨ sftp_download(ਬਣਤਰ sftp_conn *, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, Attrib *,
    ਪੂਰਨ, ਪੂਰਨ, ਪੂਰਨ, ਪੂਰਨ);

/*
 * Recursively download 'remote_directory' to 'local_directory'. Preserve
 * times if 'pflag' is set
 */
ਪੂਰਨ sftp_download_dir(ਬਣਤਰ sftp_conn *, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, Attrib *,
    ਪੂਰਨ, ਪੂਰਨ, ਪੂਰਨ, ਪੂਰਨ, ਪੂਰਨ, ਪੂਰਨ);

/*
 * Upload 'local_path' to 'remote_path'. Preserve permissions and times
 * if 'pflag' is set
 */
ਪੂਰਨ sftp_upload(ਬਣਤਰ sftp_conn *, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *,
    ਪੂਰਨ, ਪੂਰਨ, ਪੂਰਨ, ਪੂਰਨ);

/*
 * Recursively upload 'local_directory' to 'remote_directory'. Preserve
 * times if 'pflag' is set
 */
ਪੂਰਨ sftp_upload_dir(ਬਣਤਰ sftp_conn *, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *,
    ਪੂਰਨ, ਪੂਰਨ, ਪੂਰਨ, ਪੂਰਨ, ਪੂਰਨ, ਪੂਰਨ);

/*
 * Download a 'from_path' from the 'from' connection and upload it to
 * to 'to' connection at 'to_path'.
 */
ਪੂਰਨ sftp_crossload(ਬਣਤਰ sftp_conn *from, ਬਣਤਰ sftp_conn *ਮੰਜ਼ਿਲ,
    ਅਚਲ ਅੱਖਰ *from_ਰਸਤਾ, ਅਚਲ ਅੱਖਰ *ਮੰਜ਼ਿਲ_ਰਸਤਾ,
    Attrib *a, ਪੂਰਨ preserve_flag);

/*
 * Recursively download a directory from 'from_path' from the 'from'
 * connection and upload it to 'to' connection at 'to_path'.
 */
ਪੂਰਨ sftp_crossload_dir(ਬਣਤਰ sftp_conn *from, ਬਣਤਰ sftp_conn *ਮੰਜ਼ਿਲ,
    ਅਚਲ ਅੱਖਰ *from_ਰਸਤਾ, ਅਚਲ ਅੱਖਰ *ਮੰਜ਼ਿਲ_ਰਸਤਾ,
    Attrib *dirattrib, ਪੂਰਨ preserve_flag, ਪੂਰਨ print_flag,
    ਪੂਰਨ follow_link_flag);

/*
 * User/group ID to name translation.
 */
ਪੂਰਨ sftp_can_get_users_groups_by_id(ਬਣਤਰ sftp_conn *conn);
ਪੂਰਨ sftp_get_users_groups_by_id(ਬਣਤਰ sftp_conn *conn,
    ਅਚਲ u_int *uids, u_int nuids,
    ਅਚਲ u_int *gids, u_int ngids,
    ਅੱਖਰ ***usernamesp, ਅੱਖਰ ***groupnamesp);

/* Concatenate paths, taking care of slashes. Caller must free result. */
ਅੱਖਰ *sftp_ਰਸਤਾ_append(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *);

/* Make absolute path if relative path and CWD is given. Does not modify
 * original if the path is already absolute. */
ਅੱਖਰ *sftp_make_absolute(ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *);

/* Check if remote path is directory */
ਪੂਰਨ sftp_remote_is_dir(ਬਣਤਰ sftp_conn *conn, ਅਚਲ ਅੱਖਰ *ਰਸਤਾ);

/* Check whether path returned from glob(..., GLOB_MARK, ...) is a directory */
ਪੂਰਨ sftp_globpath_is_dir(ਅਚਲ ਅੱਖਰ *pathname);

#ਜੇ_ਅੰਤ
