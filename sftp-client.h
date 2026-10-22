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

પ્રકારવ્યાખ્યા સંરચના SFTP_DIRENT SFTP_DIRENT;

સંરચના SFTP_DIRENT {
	અક્ષર *filename;
	અક્ષર *longname;
	Attrib a;
};

/*
 * Used for statvfs responses on the wire from the server, because the
 * server's native format may be larger than the client's.
 */
સંરચના sftp_statvfs {
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
સંરચના sftp_limits {
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
સંરચના sftp_conn *sftp_init(પૂર્ણાંક, પૂર્ણાંક, u_int, u_int, uint64_t);
શૂન્ય sftp_free(સંરચના sftp_conn *);

u_int sftp_proto_version(સંરચના sftp_conn *);

/* Query server limits */
પૂર્ણાંક sftp_get_limits(સંરચના sftp_conn *, સંરચના sftp_limits *);

/* Close file referred to by 'handle' */
પૂર્ણાંક sftp_close(સંરચના sftp_conn *, અચલ u_char *, u_int);

/* Read contents of 'path' to NULL-terminated array 'dir' */
પૂર્ણાંક sftp_readdir(સંરચના sftp_conn *, અચલ અક્ષર *, SFTP_DIRENT ***);

/* Frees a NULL-terminated array of SFTP_DIRENTs (eg. from sftp_readdir) */
શૂન્ય sftp_free_dirents(SFTP_DIRENT **);

/* Delete file 'path' */
પૂર્ણાંક sftp_rm(સંરચના sftp_conn *, અચલ અક્ષર *);

/* Create directory 'path' */
પૂર્ણાંક sftp_mkdir(સંરચના sftp_conn *, અચલ અક્ષર *, Attrib *, પૂર્ણાંક);

/* Create directory 'path' and intermediate directories as required */
પૂર્ણાંક sftp_mkpath(સંરચના sftp_conn *, અચલ અક્ષર *, Attrib *, પૂર્ણાંક);

/* Remove directory 'path' */
પૂર્ણાંક sftp_rmdir(સંરચના sftp_conn *, અચલ અક્ષર *);

/* Get file attributes of 'path' (follows symlinks) */
પૂર્ણાંક sftp_stat(સંરચના sftp_conn *, અચલ અક્ષર *, પૂર્ણાંક, Attrib *);

/* Get file attributes of 'path' (does not follow symlinks) */
પૂર્ણાંક sftp_lstat(સંરચના sftp_conn *, અચલ અક્ષર *, પૂર્ણાંક, Attrib *);

/* Set file attributes of 'path' */
પૂર્ણાંક sftp_setstat(સંરચના sftp_conn *, અચલ અક્ષર *, Attrib *);

/* Set file attributes of open file 'handle' */
પૂર્ણાંક sftp_fsetstat(સંરચના sftp_conn *, અચલ u_char *, u_int, Attrib *);

/* Set file attributes of 'path', not following symlinks */
પૂર્ણાંક sftp_lsetstat(સંરચના sftp_conn *conn, અચલ અક્ષર *path, Attrib *a);

/* Canonicalise 'path' - caller must free result */
અક્ષર *sftp_realpath(સંરચના sftp_conn *, અચલ અક્ષર *);

/* Canonicalisation with tilde expansion (requires server extension) */
અક્ષર *sftp_expand_path(સંરચના sftp_conn *, અચલ અક્ષર *);

/* Returns non-zero if server can tilde-expand paths */
પૂર્ણાંક sftp_can_expand_path(સંરચના sftp_conn *);

/* Get statistics for filesystem hosting file at "path" */
પૂર્ણાંક sftp_statvfs(સંરચના sftp_conn *, અચલ અક્ષર *, સંરચના sftp_statvfs *, પૂર્ણાંક);

/* Rename 'oldpath' to 'newpath' */
પૂર્ણાંક sftp_rename(સંરચના sftp_conn *, અચલ અક્ષર *, અચલ અક્ષર *, પૂર્ણાંક);

/* Copy 'oldpath' to 'newpath' */
પૂર્ણાંક sftp_copy(સંરચના sftp_conn *, અચલ અક્ષર *, અચલ અક્ષર *);

/* Link 'oldpath' to 'newpath' */
પૂર્ણાંક sftp_hardlink(સંરચના sftp_conn *, અચલ અક્ષર *, અચલ અક્ષર *);

/* Rename 'oldpath' to 'newpath' */
પૂર્ણાંક sftp_symlink(સંરચના sftp_conn *, અચલ અક્ષર *, અચલ અક્ષર *);

/* Call fsync() on open file 'handle' */
પૂર્ણાંક sftp_fsync(સંરચના sftp_conn *conn, u_char *, u_int);

/*
 * Download 'remote_path' to 'local_path'. Preserve permissions and times
 * if 'pflag' is set
 */
પૂર્ણાંક sftp_download(સંરચના sftp_conn *, અચલ અક્ષર *, અચલ અક્ષર *, Attrib *,
    પૂર્ણાંક, પૂર્ણાંક, પૂર્ણાંક, પૂર્ણાંક);

/*
 * Recursively download 'remote_directory' to 'local_directory'. Preserve
 * times if 'pflag' is set
 */
પૂર્ણાંક sftp_download_dir(સંરચના sftp_conn *, અચલ અક્ષર *, અચલ અક્ષર *, Attrib *,
    પૂર્ણાંક, પૂર્ણાંક, પૂર્ણાંક, પૂર્ણાંક, પૂર્ણાંક, પૂર્ણાંક);

/*
 * Upload 'local_path' to 'remote_path'. Preserve permissions and times
 * if 'pflag' is set
 */
પૂર્ણાંક sftp_upload(સંરચના sftp_conn *, અચલ અક્ષર *, અચલ અક્ષર *,
    પૂર્ણાંક, પૂર્ણાંક, પૂર્ણાંક, પૂર્ણાંક);

/*
 * Recursively upload 'local_directory' to 'remote_directory'. Preserve
 * times if 'pflag' is set
 */
પૂર્ણાંક sftp_upload_dir(સંરચના sftp_conn *, અચલ અક્ષર *, અચલ અક્ષર *,
    પૂર્ણાંક, પૂર્ણાંક, પૂર્ણાંક, પૂર્ણાંક, પૂર્ણાંક, પૂર્ણાંક);

/*
 * Download a 'from_path' from the 'from' connection and upload it to
 * to 'to' connection at 'to_path'.
 */
પૂર્ણાંક sftp_crossload(સંરચના sftp_conn *from, સંરચના sftp_conn *to,
    અચલ અક્ષર *from_path, અચલ અક્ષર *to_path,
    Attrib *a, પૂર્ણાંક preserve_flag);

/*
 * Recursively download a directory from 'from_path' from the 'from'
 * connection and upload it to 'to' connection at 'to_path'.
 */
પૂર્ણાંક sftp_crossload_dir(સંરચના sftp_conn *from, સંરચના sftp_conn *to,
    અચલ અક્ષર *from_path, અચલ અક્ષર *to_path,
    Attrib *dirattrib, પૂર્ણાંક preserve_flag, પૂર્ણાંક print_flag,
    પૂર્ણાંક follow_link_flag);

/*
 * User/group ID to name translation.
 */
પૂર્ણાંક sftp_can_get_users_groups_by_id(સંરચના sftp_conn *conn);
પૂર્ણાંક sftp_get_users_groups_by_id(સંરચના sftp_conn *conn,
    અચલ u_int *uids, u_int nuids,
    અચલ u_int *gids, u_int ngids,
    અક્ષર ***usernamesp, અક્ષર ***groupnamesp);

/* Concatenate paths, taking care of slashes. Caller must free result. */
અક્ષર *sftp_path_append(અચલ અક્ષર *, અચલ અક્ષર *);

/* Make absolute path if relative path and CWD is given. Does not modify
 * original if the path is already absolute. */
અક્ષર *sftp_make_absolute(અક્ષર *, અચલ અક્ષર *);

/* Check if remote path is directory */
પૂર્ણાંક sftp_remote_is_dir(સંરચના sftp_conn *conn, અચલ અક્ષર *path);

/* Check whether path returned from glob(..., GLOB_MARK, ...) is a directory */
પૂર્ણાંક sftp_globpath_is_dir(અચલ અક્ષર *pathname);

#endif
