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

#अगर_अघोषित _SFTP_CLIENT_H
#घोषणा _SFTP_CLIENT_H

प्रकार काष्ठा SFTP_DIRENT SFTP_DIRENT;

काष्ठा SFTP_DIRENT {
	अक्षर *filename;
	अक्षर *longname;
	Attrib a;
};

/*
 * Used for statvfs responses on the wire from the server, because the
 * server's native format may be larger than the client's.
 */
काष्ठा sftp_statvfs {
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
काष्ठा sftp_limits {
	uint64_t packet_लंबाई;
	uint64_t read_लंबाई;
	uint64_t write_लंबाई;
	uint64_t open_handles;
};

/* print flag values */
#घोषणा SFTP_QUIET		0	/* be quiet during transfers */
#घोषणा SFTP_PRINT		1	/* list files and show progress bar */
#घोषणा SFTP_PROGRESS_ONLY	2	/* progress bar only */

/*
 * Initialise a SSH filexfer connection. Returns NULL on error or
 * a pointer to a initialized sftp_conn struct on success.
 */
काष्ठा sftp_conn *sftp_init(पूर्णांक, पूर्णांक, u_int, u_int, uint64_t);
व्योम sftp_free(काष्ठा sftp_conn *);

u_int sftp_proto_version(काष्ठा sftp_conn *);

/* Query server limits */
पूर्णांक sftp_get_limits(काष्ठा sftp_conn *, काष्ठा sftp_limits *);

/* Close file referred to by 'handle' */
पूर्णांक sftp_close(काष्ठा sftp_conn *, स्थिर u_char *, u_int);

/* Read contents of 'path' to NULL-terminated array 'dir' */
पूर्णांक sftp_readdir(काष्ठा sftp_conn *, स्थिर अक्षर *, SFTP_DIRENT ***);

/* Frees a NULL-terminated array of SFTP_DIRENTs (eg. from sftp_readdir) */
व्योम sftp_free_dirents(SFTP_DIRENT **);

/* Delete file 'path' */
पूर्णांक sftp_rm(काष्ठा sftp_conn *, स्थिर अक्षर *);

/* Create directory 'path' */
पूर्णांक sftp_mkdir(काष्ठा sftp_conn *, स्थिर अक्षर *, Attrib *, पूर्णांक);

/* Create directory 'path' and intermediate directories as required */
पूर्णांक sftp_mkpath(काष्ठा sftp_conn *, स्थिर अक्षर *, Attrib *, पूर्णांक);

/* Remove directory 'path' */
पूर्णांक sftp_rmdir(काष्ठा sftp_conn *, स्थिर अक्षर *);

/* Get file attributes of 'path' (follows symlinks) */
पूर्णांक sftp_stat(काष्ठा sftp_conn *, स्थिर अक्षर *, पूर्णांक, Attrib *);

/* Get file attributes of 'path' (does not follow symlinks) */
पूर्णांक sftp_lstat(काष्ठा sftp_conn *, स्थिर अक्षर *, पूर्णांक, Attrib *);

/* Set file attributes of 'path' */
पूर्णांक sftp_setstat(काष्ठा sftp_conn *, स्थिर अक्षर *, Attrib *);

/* Set file attributes of open file 'handle' */
पूर्णांक sftp_fsetstat(काष्ठा sftp_conn *, स्थिर u_char *, u_int, Attrib *);

/* Set file attributes of 'path', not following symlinks */
पूर्णांक sftp_lsetstat(काष्ठा sftp_conn *conn, स्थिर अक्षर *path, Attrib *a);

/* Canonicalise 'path' - caller must free result */
अक्षर *sftp_realpath(काष्ठा sftp_conn *, स्थिर अक्षर *);

/* Canonicalisation with tilde expansion (requires server extension) */
अक्षर *sftp_expand_path(काष्ठा sftp_conn *, स्थिर अक्षर *);

/* Returns non-zero if server can tilde-expand paths */
पूर्णांक sftp_can_expand_path(काष्ठा sftp_conn *);

/* Get statistics for filesystem hosting file at "path" */
पूर्णांक sftp_statvfs(काष्ठा sftp_conn *, स्थिर अक्षर *, काष्ठा sftp_statvfs *, पूर्णांक);

/* Rename 'oldpath' to 'newpath' */
पूर्णांक sftp_rename(काष्ठा sftp_conn *, स्थिर अक्षर *, स्थिर अक्षर *, पूर्णांक);

/* Copy 'oldpath' to 'newpath' */
पूर्णांक sftp_copy(काष्ठा sftp_conn *, स्थिर अक्षर *, स्थिर अक्षर *);

/* Link 'oldpath' to 'newpath' */
पूर्णांक sftp_hardlink(काष्ठा sftp_conn *, स्थिर अक्षर *, स्थिर अक्षर *);

/* Rename 'oldpath' to 'newpath' */
पूर्णांक sftp_symlink(काष्ठा sftp_conn *, स्थिर अक्षर *, स्थिर अक्षर *);

/* Call fsync() on open file 'handle' */
पूर्णांक sftp_fsync(काष्ठा sftp_conn *conn, u_char *, u_int);

/*
 * Download 'remote_path' to 'local_path'. Preserve permissions and times
 * if 'pflag' is set
 */
पूर्णांक sftp_download(काष्ठा sftp_conn *, स्थिर अक्षर *, स्थिर अक्षर *, Attrib *,
    पूर्णांक, पूर्णांक, पूर्णांक, पूर्णांक);

/*
 * Recursively download 'remote_directory' to 'local_directory'. Preserve
 * times if 'pflag' is set
 */
पूर्णांक sftp_download_dir(काष्ठा sftp_conn *, स्थिर अक्षर *, स्थिर अक्षर *, Attrib *,
    पूर्णांक, पूर्णांक, पूर्णांक, पूर्णांक, पूर्णांक, पूर्णांक);

/*
 * Upload 'local_path' to 'remote_path'. Preserve permissions and times
 * if 'pflag' is set
 */
पूर्णांक sftp_upload(काष्ठा sftp_conn *, स्थिर अक्षर *, स्थिर अक्षर *,
    पूर्णांक, पूर्णांक, पूर्णांक, पूर्णांक);

/*
 * Recursively upload 'local_directory' to 'remote_directory'. Preserve
 * times if 'pflag' is set
 */
पूर्णांक sftp_upload_dir(काष्ठा sftp_conn *, स्थिर अक्षर *, स्थिर अक्षर *,
    पूर्णांक, पूर्णांक, पूर्णांक, पूर्णांक, पूर्णांक, पूर्णांक);

/*
 * Download a 'from_path' from the 'from' connection and upload it to
 * to 'to' connection at 'to_path'.
 */
पूर्णांक sftp_crossload(काष्ठा sftp_conn *from, काष्ठा sftp_conn *to,
    स्थिर अक्षर *from_path, स्थिर अक्षर *to_path,
    Attrib *a, पूर्णांक preserve_flag);

/*
 * Recursively download a directory from 'from_path' from the 'from'
 * connection and upload it to 'to' connection at 'to_path'.
 */
पूर्णांक sftp_crossload_dir(काष्ठा sftp_conn *from, काष्ठा sftp_conn *to,
    स्थिर अक्षर *from_path, स्थिर अक्षर *to_path,
    Attrib *dirattrib, पूर्णांक preserve_flag, पूर्णांक print_flag,
    पूर्णांक follow_link_flag);

/*
 * User/group ID to name translation.
 */
पूर्णांक sftp_can_get_users_groups_by_id(काष्ठा sftp_conn *conn);
पूर्णांक sftp_get_users_groups_by_id(काष्ठा sftp_conn *conn,
    स्थिर u_int *uids, u_int nuids,
    स्थिर u_int *gids, u_int ngids,
    अक्षर ***usernamesp, अक्षर ***groupnamesp);

/* Concatenate paths, taking care of slashes. Caller must free result. */
अक्षर *sftp_path_append(स्थिर अक्षर *, स्थिर अक्षर *);

/* Make absolute path if relative path and CWD is given. Does not modify
 * original if the path is already absolute. */
अक्षर *sftp_make_absolute(अक्षर *, स्थिर अक्षर *);

/* Check if remote path is directory */
पूर्णांक sftp_remote_is_dir(काष्ठा sftp_conn *conn, स्थिर अक्षर *path);

/* Check whether path returned from glob(..., GLOB_MARK, ...) is a directory */
पूर्णांक sftp_globpath_is_dir(स्थिर अक्षर *pathname);

#पूर्ण_अगर
