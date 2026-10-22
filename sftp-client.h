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

#اگر_غیر_تعریف_شدہ _SFTP_CLIENT_H
#تعریف_کرو _SFTP_CLIENT_H

قسمتعریف ساخت SFTP_DIRENT SFTP_DIRENT;

ساخت SFTP_DIRENT {
	حرف *filename;
	حرف *longname;
	Attrib a;
};

/*
 * Used for statvfs responses on the wire from the server, because the
 * server's native format may be larger than the client's.
 */
ساخت sftp_statvfs {
	uint64_t f_bsize;
	uint64_t f_frsize;
	uint64_t f_بلاکیں;
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
ساخت sftp_limits {
	uint64_t packet_لمبائی;
	uint64_t read_لمبائی;
	uint64_t write_لمبائی;
	uint64_t open_handles;
};

/* print flag values */
#تعریف_کرو SFTP_QUIET		0	/* be quiet during transfers */
#تعریف_کرو SFTP_PRINT		1	/* list files and show progress bar */
#تعریف_کرو SFTP_پیش_رفت_ONLY	2	/* progress bar only */

/*
 * Initialise a SSH filexfer connection. Returns NULL on error or
 * a pointer to a initialized sftp_conn struct on success.
 */
ساخت sftp_conn *sftp_init(صحیح, صحیح, u_int, u_int, uint64_t);
خالی sftp_free(ساخت sftp_conn *);

u_int sftp_proto_نسخہ(ساخت sftp_conn *);

/* Query server limits */
صحیح sftp_get_limits(ساخت sftp_conn *, ساخت sftp_limits *);

/* Close file referred to by 'handle' */
صحیح sftp_close(ساخت sftp_conn *, ثابت u_char *, u_int);

/* Read contents of 'path' to NULL-terminated array 'dir' */
صحیح sftp_readdir(ساخت sftp_conn *, ثابت حرف *, SFTP_DIRENT ***);

/* Frees a NULL-terminated array of SFTP_DIRENTs (eg. from sftp_readdir) */
خالی sftp_free_dirents(SFTP_DIRENT **);

/* Delete file 'path' */
صحیح sftp_rm(ساخت sftp_conn *, ثابت حرف *);

/* Create directory 'path' */
صحیح sftp_mkdir(ساخت sftp_conn *, ثابت حرف *, Attrib *, صحیح);

/* Create directory 'path' and intermediate directories as required */
صحیح sftp_mkpath(ساخت sftp_conn *, ثابت حرف *, Attrib *, صحیح);

/* Remove directory 'path' */
صحیح sftp_rmdir(ساخت sftp_conn *, ثابت حرف *);

/* Get file attributes of 'path' (follows symlinks) */
صحیح sftp_stat(ساخت sftp_conn *, ثابت حرف *, صحیح, Attrib *);

/* Get file attributes of 'path' (does not follow symlinks) */
صحیح sftp_lstat(ساخت sftp_conn *, ثابت حرف *, صحیح, Attrib *);

/* Set file attributes of 'path' */
صحیح sftp_setstat(ساخت sftp_conn *, ثابت حرف *, Attrib *);

/* Set file attributes of open file 'handle' */
صحیح sftp_fsetstat(ساخت sftp_conn *, ثابت u_char *, u_int, Attrib *);

/* Set file attributes of 'path', not following symlinks */
صحیح sftp_lsetstat(ساخت sftp_conn *conn, ثابت حرف *راستہ, Attrib *a);

/* Canonicalise 'path' - caller must free result */
حرف *sftp_realpath(ساخت sftp_conn *, ثابت حرف *);

/* Canonicalisation with tilde expansion (requires server extension) */
حرف *sftp_expand_راستہ(ساخت sftp_conn *, ثابت حرف *);

/* Returns non-zero if server can tilde-expand paths */
صحیح sftp_can_expand_راستہ(ساخت sftp_conn *);

/* Get statistics for filesystem hosting file at "path" */
صحیح sftp_statvfs(ساخت sftp_conn *, ثابت حرف *, ساخت sftp_statvfs *, صحیح);

/* Rename 'oldpath' to 'newpath' */
صحیح sftp_rename(ساخت sftp_conn *, ثابت حرف *, ثابت حرف *, صحیح);

/* Copy 'oldpath' to 'newpath' */
صحیح sftp_copy(ساخت sftp_conn *, ثابت حرف *, ثابت حرف *);

/* Link 'oldpath' to 'newpath' */
صحیح sftp_hardlink(ساخت sftp_conn *, ثابت حرف *, ثابت حرف *);

/* Rename 'oldpath' to 'newpath' */
صحیح sftp_symlink(ساخت sftp_conn *, ثابت حرف *, ثابت حرف *);

/* Call fsync() on open file 'handle' */
صحیح sftp_fsync(ساخت sftp_conn *conn, u_char *, u_int);

/*
 * Download 'remote_path' to 'local_path'. Preserve permissions and times
 * if 'pflag' is set
 */
صحیح sftp_download(ساخت sftp_conn *, ثابت حرف *, ثابت حرف *, Attrib *,
    صحیح, صحیح, صحیح, صحیح);

/*
 * Recursively download 'remote_directory' to 'local_directory'. Preserve
 * times if 'pflag' is set
 */
صحیح sftp_download_dir(ساخت sftp_conn *, ثابت حرف *, ثابت حرف *, Attrib *,
    صحیح, صحیح, صحیح, صحیح, صحیح, صحیح);

/*
 * Upload 'local_path' to 'remote_path'. Preserve permissions and times
 * if 'pflag' is set
 */
صحیح sftp_upload(ساخت sftp_conn *, ثابت حرف *, ثابت حرف *,
    صحیح, صحیح, صحیح, صحیح);

/*
 * Recursively upload 'local_directory' to 'remote_directory'. Preserve
 * times if 'pflag' is set
 */
صحیح sftp_upload_dir(ساخت sftp_conn *, ثابت حرف *, ثابت حرف *,
    صحیح, صحیح, صحیح, صحیح, صحیح, صحیح);

/*
 * Download a 'from_path' from the 'from' connection and upload it to
 * to 'to' connection at 'to_path'.
 */
صحیح sftp_crossload(ساخت sftp_conn *from, ساخت sftp_conn *مقصد,
    ثابت حرف *from_راستہ, ثابت حرف *مقصد_راستہ,
    Attrib *a, صحیح preserve_flag);

/*
 * Recursively download a directory from 'from_path' from the 'from'
 * connection and upload it to 'to' connection at 'to_path'.
 */
صحیح sftp_crossload_dir(ساخت sftp_conn *from, ساخت sftp_conn *مقصد,
    ثابت حرف *from_راستہ, ثابت حرف *مقصد_راستہ,
    Attrib *dirattrib, صحیح preserve_flag, صحیح print_flag,
    صحیح follow_link_flag);

/*
 * User/group ID to name translation.
 */
صحیح sftp_can_get_users_groups_by_id(ساخت sftp_conn *conn);
صحیح sftp_get_users_groups_by_id(ساخت sftp_conn *conn,
    ثابت u_int *uids, u_int nuids,
    ثابت u_int *gids, u_int ngids,
    حرف ***usernamesp, حرف ***groupnamesp);

/* Concatenate paths, taking care of slashes. Caller must free result. */
حرف *sftp_راستہ_append(ثابت حرف *, ثابت حرف *);

/* Make absolute path if relative path and CWD is given. Does not modify
 * original if the path is already absolute. */
حرف *sftp_make_absolute(حرف *, ثابت حرف *);

/* Check if remote path is directory */
صحیح sftp_remote_is_dir(ساخت sftp_conn *conn, ثابت حرف *راستہ);

/* Check whether path returned from glob(..., GLOB_MARK, ...) is a directory */
صحیح sftp_globpath_is_dir(ثابت حرف *pathname);

#اگر_ختم
