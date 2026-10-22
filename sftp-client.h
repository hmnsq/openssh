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

#నిర్వచితం_కాకపోతే _SFTP_CLIENT_H
#నిర్వచించు _SFTP_CLIENT_H

రకనిర్వచనం నిర్మాణం SFTP_DIRENT SFTP_DIRENT;

నిర్మాణం SFTP_DIRENT {
	అక్షరం *filename;
	అక్షరం *longname;
	Attrib a;
};

/*
 * Used for statvfs responses on the wire from the server, because the
 * server's native format may be larger than the client's.
 */
నిర్మాణం sftp_statvfs {
	uint64_t f_bsize;
	uint64_t f_frsize;
	uint64_t f_ఖండాలు;
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
నిర్మాణం sftp_limits {
	uint64_t packet_నిడివి;
	uint64_t read_నిడివి;
	uint64_t write_నిడివి;
	uint64_t open_handles;
};

/* print flag values */
#నిర్వచించు SFTP_QUIET		0	/* be quiet during transfers */
#నిర్వచించు SFTP_PRINT		1	/* list files and show progress bar */
#నిర్వచించు SFTP_పురోగతి_ONLY	2	/* progress bar only */

/*
 * Initialise a SSH filexfer connection. Returns NULL on error or
 * a pointer to a initialized sftp_conn struct on success.
 */
నిర్మాణం sftp_conn *sftp_init(పూర్ణాంకం, పూర్ణాంకం, u_int, u_int, uint64_t);
శూన్య sftp_free(నిర్మాణం sftp_conn *);

u_int sftp_proto_సంస్కరణ(నిర్మాణం sftp_conn *);

/* Query server limits */
పూర్ణాంకం sftp_get_limits(నిర్మాణం sftp_conn *, నిర్మాణం sftp_limits *);

/* Close file referred to by 'handle' */
పూర్ణాంకం sftp_close(నిర్మాణం sftp_conn *, స్థిరరాశి u_char *, u_int);

/* Read contents of 'path' to NULL-terminated array 'dir' */
పూర్ణాంకం sftp_readdir(నిర్మాణం sftp_conn *, స్థిరరాశి అక్షరం *, SFTP_DIRENT ***);

/* Frees a NULL-terminated array of SFTP_DIRENTs (eg. from sftp_readdir) */
శూన్య sftp_free_dirents(SFTP_DIRENT **);

/* Delete file 'path' */
పూర్ణాంకం sftp_rm(నిర్మాణం sftp_conn *, స్థిరరాశి అక్షరం *);

/* Create directory 'path' */
పూర్ణాంకం sftp_mkdir(నిర్మాణం sftp_conn *, స్థిరరాశి అక్షరం *, Attrib *, పూర్ణాంకం);

/* Create directory 'path' and intermediate directories as required */
పూర్ణాంకం sftp_mkpath(నిర్మాణం sftp_conn *, స్థిరరాశి అక్షరం *, Attrib *, పూర్ణాంకం);

/* Remove directory 'path' */
పూర్ణాంకం sftp_rmdir(నిర్మాణం sftp_conn *, స్థిరరాశి అక్షరం *);

/* Get file attributes of 'path' (follows symlinks) */
పూర్ణాంకం sftp_stat(నిర్మాణం sftp_conn *, స్థిరరాశి అక్షరం *, పూర్ణాంకం, Attrib *);

/* Get file attributes of 'path' (does not follow symlinks) */
పూర్ణాంకం sftp_lstat(నిర్మాణం sftp_conn *, స్థిరరాశి అక్షరం *, పూర్ణాంకం, Attrib *);

/* Set file attributes of 'path' */
పూర్ణాంకం sftp_setstat(నిర్మాణం sftp_conn *, స్థిరరాశి అక్షరం *, Attrib *);

/* Set file attributes of open file 'handle' */
పూర్ణాంకం sftp_fsetstat(నిర్మాణం sftp_conn *, స్థిరరాశి u_char *, u_int, Attrib *);

/* Set file attributes of 'path', not following symlinks */
పూర్ణాంకం sftp_lsetstat(నిర్మాణం sftp_conn *conn, స్థిరరాశి అక్షరం *మార్గం, Attrib *a);

/* Canonicalise 'path' - caller must free result */
అక్షరం *sftp_realpath(నిర్మాణం sftp_conn *, స్థిరరాశి అక్షరం *);

/* Canonicalisation with tilde expansion (requires server extension) */
అక్షరం *sftp_expand_మార్గం(నిర్మాణం sftp_conn *, స్థిరరాశి అక్షరం *);

/* Returns non-zero if server can tilde-expand paths */
పూర్ణాంకం sftp_can_expand_మార్గం(నిర్మాణం sftp_conn *);

/* Get statistics for filesystem hosting file at "path" */
పూర్ణాంకం sftp_statvfs(నిర్మాణం sftp_conn *, స్థిరరాశి అక్షరం *, నిర్మాణం sftp_statvfs *, పూర్ణాంకం);

/* Rename 'oldpath' to 'newpath' */
పూర్ణాంకం sftp_rename(నిర్మాణం sftp_conn *, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, పూర్ణాంకం);

/* Copy 'oldpath' to 'newpath' */
పూర్ణాంకం sftp_copy(నిర్మాణం sftp_conn *, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *);

/* Link 'oldpath' to 'newpath' */
పూర్ణాంకం sftp_hardlink(నిర్మాణం sftp_conn *, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *);

/* Rename 'oldpath' to 'newpath' */
పూర్ణాంకం sftp_symlink(నిర్మాణం sftp_conn *, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *);

/* Call fsync() on open file 'handle' */
పూర్ణాంకం sftp_fsync(నిర్మాణం sftp_conn *conn, u_char *, u_int);

/*
 * Download 'remote_path' to 'local_path'. Preserve permissions and times
 * if 'pflag' is set
 */
పూర్ణాంకం sftp_download(నిర్మాణం sftp_conn *, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, Attrib *,
    పూర్ణాంకం, పూర్ణాంకం, పూర్ణాంకం, పూర్ణాంకం);

/*
 * Recursively download 'remote_directory' to 'local_directory'. Preserve
 * times if 'pflag' is set
 */
పూర్ణాంకం sftp_download_dir(నిర్మాణం sftp_conn *, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, Attrib *,
    పూర్ణాంకం, పూర్ణాంకం, పూర్ణాంకం, పూర్ణాంకం, పూర్ణాంకం, పూర్ణాంకం);

/*
 * Upload 'local_path' to 'remote_path'. Preserve permissions and times
 * if 'pflag' is set
 */
పూర్ణాంకం sftp_upload(నిర్మాణం sftp_conn *, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *,
    పూర్ణాంకం, పూర్ణాంకం, పూర్ణాంకం, పూర్ణాంకం);

/*
 * Recursively upload 'local_directory' to 'remote_directory'. Preserve
 * times if 'pflag' is set
 */
పూర్ణాంకం sftp_upload_dir(నిర్మాణం sftp_conn *, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *,
    పూర్ణాంకం, పూర్ణాంకం, పూర్ణాంకం, పూర్ణాంకం, పూర్ణాంకం, పూర్ణాంకం);

/*
 * Download a 'from_path' from the 'from' connection and upload it to
 * to 'to' connection at 'to_path'.
 */
పూర్ణాంకం sftp_crossload(నిర్మాణం sftp_conn *from, నిర్మాణం sftp_conn *గమ్యం,
    స్థిరరాశి అక్షరం *from_మార్గం, స్థిరరాశి అక్షరం *గమ్యం_మార్గం,
    Attrib *a, పూర్ణాంకం preserve_flag);

/*
 * Recursively download a directory from 'from_path' from the 'from'
 * connection and upload it to 'to' connection at 'to_path'.
 */
పూర్ణాంకం sftp_crossload_dir(నిర్మాణం sftp_conn *from, నిర్మాణం sftp_conn *గమ్యం,
    స్థిరరాశి అక్షరం *from_మార్గం, స్థిరరాశి అక్షరం *గమ్యం_మార్గం,
    Attrib *dirattrib, పూర్ణాంకం preserve_flag, పూర్ణాంకం print_flag,
    పూర్ణాంకం follow_link_flag);

/*
 * User/group ID to name translation.
 */
పూర్ణాంకం sftp_can_get_users_groups_by_id(నిర్మాణం sftp_conn *conn);
పూర్ణాంకం sftp_get_users_groups_by_id(నిర్మాణం sftp_conn *conn,
    స్థిరరాశి u_int *uids, u_int nuids,
    స్థిరరాశి u_int *gids, u_int ngids,
    అక్షరం ***usernamesp, అక్షరం ***groupnamesp);

/* Concatenate paths, taking care of slashes. Caller must free result. */
అక్షరం *sftp_మార్గం_append(స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *);

/* Make absolute path if relative path and CWD is given. Does not modify
 * original if the path is already absolute. */
అక్షరం *sftp_make_absolute(అక్షరం *, స్థిరరాశి అక్షరం *);

/* Check if remote path is directory */
పూర్ణాంకం sftp_remote_is_dir(నిర్మాణం sftp_conn *conn, స్థిరరాశి అక్షరం *మార్గం);

/* Check whether path returned from glob(..., GLOB_MARK, ...) is a directory */
పూర్ణాంకం sftp_globpath_is_dir(స్థిరరాశి అక్షరం *pathname);

#అయితే_ముగింపు
