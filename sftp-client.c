/* $OpenBSD: sftp-client.c,v 1.188 2026/10/01 03:11:49 djm Exp $ */
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

/* XXX: memleaks */
/* XXX: signed vs unsigned */
/* XXX: remove all logging, only return status codes */
/* XXX: copy between two remote sites */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/queue.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>
#ಅನ್ತರ್ಭಾವ <sys/time.h>
#ಅನ್ತರ್ಭಾವ <sys/statvfs.h>
#ಅನ್ತರ್ಭಾವ <sys/uio.h>

#ಅನ್ತರ್ಭಾವ <dirent.h>
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <poll.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "atomicio.h"
#ಅನ್ತರ್ಭಾವ "progressmeter.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "utf8.h"

#ಅನ್ತರ್ಭಾವ "sftp.h"
#ಅನ್ತರ್ಭಾವ "sftp-common.h"
#ಅನ್ತರ್ಭಾವ "sftp-client.h"

ಬಾಹ್ಯ ಚಞ್ಚಲ sig_atomic_t interrupted;
ಬಾಹ್ಯ ಪೂರ್ಣಾಙ್ಕ showprogress;

/* Default size of buffer for up/download (fix sftp.1 scp.1 if changed) */
#define DEFAULT_COPY_BUFLEN	32768

/* Default number of concurrent xfer requests (fix sftp.1 scp.1 if changed) */
#define DEFAULT_ಅಂಕೆ_REQUESTS	64

/* Minimum amount of data to read at a time */
#define MIN_READ_SIZE	512

/* Maximum depth to descend in directory trees */
#define MAX_DIR_DEPTH 64

/* Directory separator characters */
#ifdef HAVE_CYGWIN
# define SFTP_DIRECTORY_CHARS      "/\\"
#ಅನ್ಯಥಾ /* HAVE_CYGWIN */
# define SFTP_DIRECTORY_CHARS      "/"
#endif /* HAVE_CYGWIN */

ಸಂರಚನಾ sftp_conn {
	ಪೂರ್ಣಾಙ್ಕ fd_in;
	ಪೂರ್ಣಾಙ್ಕ fd_out;
	u_int download_buflen;
	u_int upload_buflen;
	u_int ಅಂಕೆ_requests;
	u_int version;
	u_int ಸಂದೇಶ_id;
#define SFTP_EXT_POSIX_RENAME		0x00000001
#define SFTP_EXT_STATVFS		0x00000002
#define SFTP_EXT_FSTATVFS		0x00000004
#define SFTP_EXT_HARDLINK		0x00000008
#define SFTP_EXT_FSYNC			0x00000010
#define SFTP_EXT_LSETSTAT		0x00000020
#define SFTP_EXT_LIMITS			0x00000040
#define SFTP_EXT_PATH_EXPAND		0x00000080
#define SFTP_EXT_COPY_DATA		0x00000100
#define SFTP_EXT_GETUSERSGROUPS_BY_ID	0x00000200
	u_int exts;
	uint64_t limit_kbps;
	ಸಂರಚನಾ bwlimit bwlimit_in, bwlimit_out;
};

/* Tracks in-progress requests during file transfers */
ಸಂರಚನಾ request {
	u_int id;
	size_t len;
	uint64_t offset;
	TAILQ_ENTRY(request) tq;
};
TAILQ_HEAD(requests, request);

ಸ್ಥಿರ u_char *
get_handle(ಸಂರಚನಾ sftp_conn *conn, u_int expected_id, size_t *len,
    ಧ್ರುವ ವರ್ಣ *errfmt, ...) __attribute__((format(printf, 4, 5)));

ಸ್ಥಿರ ಸಂರಚನಾ request *
request_enqueue(ಸಂರಚನಾ requests *requests, u_int id, size_t len,
    uint64_t offset)
{
	ಸಂರಚನಾ request *req;

	req = xcalloc(1, ಪರಿಮಾಣ(*req));
	req->id = id;
	req->len = len;
	req->offset = offset;
	TAILQ_INSERT_TAIL(requests, req, tq);
	ಪ್ರತ್ಯಾಗಮ req;
}

ಸ್ಥಿರ ಸಂರಚನಾ request *
request_find(ಸಂರಚನಾ requests *requests, u_int id)
{
	ಸಂರಚನಾ request *req;

	ಪ್ರತಿ (req = TAILQ_FIRST(requests);
	    req != ರಿಕ್ತ && req->id != id;
	    req = TAILQ_NEXT(req, tq))
		;
	ಪ್ರತ್ಯಾಗಮ req;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sftpio(ಶೂನ್ಯ *_bwlimit, size_t amount)
{
	ಸಂರಚನಾ bwlimit *bwlimit = (ಸಂರಚನಾ bwlimit *)_bwlimit;

	refresh_progress_meter(0);
	ಯದಿ (bwlimit != ರಿಕ್ತ)
		bandwidth_limit(bwlimit, amount);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
send_ಸಂದೇಶ(ಸಂರಚನಾ sftp_conn *conn, ಸಂರಚನಾ sshbuf *m)
{
	u_char mlen[4];
	ಸಂರಚನಾ iovec iov[2];

	ಯದಿ (sshbuf_len(m) > SFTP_MAX_ಸಂದೇಶ_LENGTH)
		fatal("Outbound message too long %zu", sshbuf_len(m));

	/* Send length first */
	put_u32(mlen, sshbuf_len(m));
	iov[0].iov_base = mlen;
	iov[0].iov_len = ಪರಿಮಾಣ(mlen);
	iov[1].iov_base = (u_char *)sshbuf_ptr(m);
	iov[1].iov_len = sshbuf_len(m);

	ಯದಿ (atomiciov6(writev, conn->fd_out, iov, 2, sftpio,
	    conn->limit_kbps > 0 ? &conn->bwlimit_out : ರಿಕ್ತ) !=
	    sshbuf_len(m) + ಪರಿಮಾಣ(mlen))
		fatal("Couldn't send packet: %s", strerror(errno));

	sshbuf_reset(m);
}

ಸ್ಥಿರ ಶೂನ್ಯ
get_ಸಂದೇಶ_extended(ಸಂರಚನಾ sftp_conn *conn, ಸಂರಚನಾ sshbuf *m, ಪೂರ್ಣಾಙ್ಕ initial)
{
	u_int ಸಂದೇಶ_len;
	u_char *p;
	ಪೂರ್ಣಾಙ್ಕ r;

	sshbuf_reset(m);
	ಯದಿ ((r = sshbuf_reserve(m, 4, &p)) != 0)
		fatal_fr(r, "reserve");
	ಯದಿ (atomicio6(ಪಠ, conn->fd_in, p, 4, sftpio,
	    conn->limit_kbps > 0 ? &conn->bwlimit_in : ರಿಕ್ತ) != 4) {
		ಯದಿ (errno == EPIPE || errno == ECONNRESET)
			fatal("Connection closed");
		ಅನ್ಯಥಾ
			fatal("Couldn't read packet: %s", strerror(errno));
	}

	ಯದಿ ((r = sshbuf_get_u32(m, &ಸಂದೇಶ_len)) != 0)
		fatal_fr(r, "sshbuf_get_u32");
	ಯದಿ (ಸಂದೇಶ_len > SFTP_MAX_ಸಂದೇಶ_LENGTH) {
		do_log2(initial ? SYSLOG_LEVEL_ERROR : SYSLOG_LEVEL_FATAL,
		    "Received message too long %u", ಸಂದೇಶ_len);
		fatal("Ensure the remote shell produces no output "
		    "for non-interactive sessions.");
	}

	ಯದಿ ((r = sshbuf_reserve(m, ಸಂದೇಶ_len, &p)) != 0)
		fatal_fr(r, "reserve");
	ಯದಿ (atomicio6(ಪಠ, conn->fd_in, p, ಸಂದೇಶ_len, sftpio,
	    conn->limit_kbps > 0 ? &conn->bwlimit_in : ರಿಕ್ತ)
	    != ಸಂದೇಶ_len) {
		ಯದಿ (errno == EPIPE)
			fatal("Connection closed");
		ಅನ್ಯಥಾ
			fatal("Read packet: %s", strerror(errno));
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
get_ಸಂದೇಶ(ಸಂರಚನಾ sftp_conn *conn, ಸಂರಚನಾ sshbuf *m)
{
	get_ಸಂದೇಶ_extended(conn, m, 0);
}

ಸ್ಥಿರ ಶೂನ್ಯ
send_string_request(ಸಂರಚನಾ sftp_conn *conn, u_int id, u_int code, ಧ್ರುವ ವರ್ಣ *s,
    u_int len)
{
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, code)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
	    (r = sshbuf_put_string(ಸಂದೇಶ, s, len)) != 0)
		fatal_fr(r, "compose");
	send_ಸಂದೇಶ(conn, ಸಂದೇಶ);
	debug3("Sent message fd %d T:%u I:%u", conn->fd_out, code, id);
	sshbuf_free(ಸಂದೇಶ);
}

ಸ್ಥಿರ ಶೂನ್ಯ
send_string_attrs_request(ಸಂರಚನಾ sftp_conn *conn, u_int id, u_int code,
    ಧ್ರುವ ಶೂನ್ಯ *s, u_int len, Attrib *a)
{
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, code)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
	    (r = sshbuf_put_string(ಸಂದೇಶ, s, len)) != 0 ||
	    (r = encode_attrib(ಸಂದೇಶ, a)) != 0)
		fatal_fr(r, "compose");
	send_ಸಂದೇಶ(conn, ಸಂದೇಶ);
	debug3("Sent message fd %d T:%u I:%u F:0x%04x M:%05o",
	    conn->fd_out, code, id, a->flags, a->perm);
	sshbuf_free(ಸಂದೇಶ);
}

ಸ್ಥಿರ u_int
get_status(ಸಂರಚನಾ sftp_conn *conn, u_int expected_id)
{
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;
	u_char type;
	u_int id, status;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	get_ಸಂದೇಶ(conn, ಸಂದೇಶ);
	ಯದಿ ((r = sshbuf_get_u8(ಸಂದೇಶ, &type)) != 0 ||
	    (r = sshbuf_get_u32(ಸಂದೇಶ, &id)) != 0)
		fatal_fr(r, "compose");

	ಯದಿ (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	ಯದಿ (type != SSH2_FXP_STATUS)
		fatal("Expected SSH2_FXP_STATUS(%u) packet, got %u",
		    SSH2_FXP_STATUS, type);

	ಯದಿ ((r = sshbuf_get_u32(ಸಂದೇಶ, &status)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(ಸಂದೇಶ);

	debug3("SSH2_FXP_STATUS %u", status);

	ಪ್ರತ್ಯಾಗಮ status;
}

ಸ್ಥಿರ u_char *
get_handle(ಸಂರಚನಾ sftp_conn *conn, u_int expected_id, size_t *len,
    ಧ್ರುವ ವರ್ಣ *errfmt, ...)
{
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;
	u_int id, status;
	u_char type;
	u_char *handle;
	ವರ್ಣ errmsg[256];
	va_list args;
	ಪೂರ್ಣಾಙ್ಕ r;

	va_start(args, errfmt);
	ಯದಿ (errfmt != ರಿಕ್ತ)
		vsnprintf(errmsg, ಪರಿಮಾಣ(errmsg), errfmt, args);
	va_end(args);

	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	get_ಸಂದೇಶ(conn, ಸಂದೇಶ);
	ಯದಿ ((r = sshbuf_get_u8(ಸಂದೇಶ, &type)) != 0 ||
	    (r = sshbuf_get_u32(ಸಂದೇಶ, &id)) != 0)
		fatal_fr(r, "parse");

	ಯದಿ (id != expected_id)
		fatal("%s: ID mismatch (%u != %u)",
		    errfmt == ರಿಕ್ತ ? __func__ : errmsg, id, expected_id);
	ಯದಿ (type == SSH2_FXP_STATUS) {
		ಯದಿ ((r = sshbuf_get_u32(ಸಂದೇಶ, &status)) != 0)
			fatal_fr(r, "parse status");
		ಯದಿ (errfmt != ರಿಕ್ತ)
			error("%s: %s", errmsg, fx2txt(status));
		sshbuf_free(ಸಂದೇಶ);
		ಪ್ರತ್ಯಾಗಮ(ರಿಕ್ತ);
	} ಅನ್ಯಥಾ ಯದಿ (type != SSH2_FXP_HANDLE)
		fatal("%s: Expected SSH2_FXP_HANDLE(%u) packet, got %u",
		    errfmt == ರಿಕ್ತ ? __func__ : errmsg, SSH2_FXP_HANDLE, type);

	ಯದಿ ((r = sshbuf_get_string(ಸಂದೇಶ, &handle, len)) != 0)
		fatal_fr(r, "parse handle");
	sshbuf_free(ಸಂದೇಶ);

	ಪ್ರತ್ಯಾಗಮ handle;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
get_decode_stat(ಸಂರಚನಾ sftp_conn *conn, u_int expected_id, ಪೂರ್ಣಾಙ್ಕ quiet, Attrib *a)
{
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;
	u_int id;
	u_char type;
	ಪೂರ್ಣಾಙ್ಕ r;
	Attrib attr;

	ಯದಿ (a != ರಿಕ್ತ)
		memset(a, '\0', ಪರಿಮಾಣ(*a));
	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	get_ಸಂದೇಶ(conn, ಸಂದೇಶ);

	ಯದಿ ((r = sshbuf_get_u8(ಸಂದೇಶ, &type)) != 0 ||
	    (r = sshbuf_get_u32(ಸಂದೇಶ, &id)) != 0)
		fatal_fr(r, "parse");

	ಯದಿ (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	ಯದಿ (type == SSH2_FXP_STATUS) {
		u_int status;

		ಯದಿ ((r = sshbuf_get_u32(ಸಂದೇಶ, &status)) != 0)
			fatal_fr(r, "parse status");
		ಯದಿ (quiet)
			debug("stat remote: %s", fx2txt(status));
		ಅನ್ಯಥಾ
			error("stat remote: %s", fx2txt(status));
		sshbuf_free(ಸಂದೇಶ);
		ಪ್ರತ್ಯಾಗಮ -1;
	} ಅನ್ಯಥಾ ಯದಿ (type != SSH2_FXP_ATTRS) {
		fatal("Expected SSH2_FXP_ATTRS(%u) packet, got %u",
		    SSH2_FXP_ATTRS, type);
	}
	ಯದಿ ((r = decode_attrib(ಸಂದೇಶ, &attr)) != 0) {
		error_fr(r, "decode_attrib");
		sshbuf_free(ಸಂದೇಶ);
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	/* success */
	ಯದಿ (a != ರಿಕ್ತ)
		*a = attr;
	debug3("Received stat reply T:%u I:%u F:0x%04x M:%05o",
	    type, id, attr.flags, attr.perm);
	sshbuf_free(ಸಂದೇಶ);

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
get_decode_statvfs(ಸಂರಚನಾ sftp_conn *conn, ಸಂರಚನಾ sftp_statvfs *st,
    u_int expected_id, ಪೂರ್ಣಾಙ್ಕ quiet)
{
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;
	u_char type;
	u_int id;
	uint64_t flag;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	get_ಸಂದೇಶ(conn, ಸಂದೇಶ);

	ಯದಿ ((r = sshbuf_get_u8(ಸಂದೇಶ, &type)) != 0 ||
	    (r = sshbuf_get_u32(ಸಂದೇಶ, &id)) != 0)
		fatal_fr(r, "parse");

	debug3("Received statvfs reply T:%u I:%u", type, id);
	ಯದಿ (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	ಯದಿ (type == SSH2_FXP_STATUS) {
		u_int status;

		ಯದಿ ((r = sshbuf_get_u32(ಸಂದೇಶ, &status)) != 0)
			fatal_fr(r, "parse status");
		ಯದಿ (quiet)
			debug("remote statvfs: %s", fx2txt(status));
		ಅನ್ಯಥಾ
			error("remote statvfs: %s", fx2txt(status));
		sshbuf_free(ಸಂದೇಶ);
		ಪ್ರತ್ಯಾಗಮ -1;
	} ಅನ್ಯಥಾ ಯದಿ (type != SSH2_FXP_EXTENDED_REPLY) {
		fatal("Expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_REPLY, type);
	}

	memset(st, 0, ಪರಿಮಾಣ(*st));
	ಯದಿ ((r = sshbuf_get_u64(ಸಂದೇಶ, &st->f_bsize)) != 0 ||
	    (r = sshbuf_get_u64(ಸಂದೇಶ, &st->f_frsize)) != 0 ||
	    (r = sshbuf_get_u64(ಸಂದೇಶ, &st->f_blocks)) != 0 ||
	    (r = sshbuf_get_u64(ಸಂದೇಶ, &st->f_bfree)) != 0 ||
	    (r = sshbuf_get_u64(ಸಂದೇಶ, &st->f_bavail)) != 0 ||
	    (r = sshbuf_get_u64(ಸಂದೇಶ, &st->f_files)) != 0 ||
	    (r = sshbuf_get_u64(ಸಂದೇಶ, &st->f_ffree)) != 0 ||
	    (r = sshbuf_get_u64(ಸಂದೇಶ, &st->f_favail)) != 0 ||
	    (r = sshbuf_get_u64(ಸಂದೇಶ, &st->f_fsid)) != 0 ||
	    (r = sshbuf_get_u64(ಸಂದೇಶ, &flag)) != 0 ||
	    (r = sshbuf_get_u64(ಸಂದೇಶ, &st->f_namemax)) != 0)
		fatal_fr(r, "parse statvfs");

	st->f_flag = (flag & SSH2_FXE_STATVFS_ST_RDONLY) ? ST_RDONLY : 0;
	st->f_flag |= (flag & SSH2_FXE_STATVFS_ST_NOSUID) ? ST_NOSUID : 0;

	sshbuf_free(ಸಂದೇಶ);

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸಂರಚನಾ sftp_conn *
sftp_init(ಪೂರ್ಣಾಙ್ಕ fd_in, ಪೂರ್ಣಾಙ್ಕ fd_out, u_int transfer_buflen, u_int ಅಂಕೆ_requests,
    uint64_t limit_kbps)
{
	u_char type;
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;
	ಸಂರಚನಾ sftp_conn *ret;
	ಪೂರ್ಣಾಙ್ಕ r;

	ret = xcalloc(1, ಪರಿಮಾಣ(*ret));
	ret->ಸಂದೇಶ_id = 1;
	ret->fd_in = fd_in;
	ret->fd_out = fd_out;
	ret->download_buflen = ret->upload_buflen =
	    transfer_buflen ? transfer_buflen : DEFAULT_COPY_BUFLEN;
	ret->ಅಂಕೆ_requests =
	    ಅಂಕೆ_requests ? ಅಂಕೆ_requests : DEFAULT_ಅಂಕೆ_REQUESTS;
	ret->exts = 0;
	ret->limit_kbps = 0;

	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_INIT)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, SSH2_FILEXFER_VERSION)) != 0)
		fatal_fr(r, "parse");

	send_ಸಂದೇಶ(ret, ಸಂದೇಶ);

	get_ಸಂದೇಶ_extended(ret, ಸಂದೇಶ, 1);

	/* Expecting a VERSION reply */
	ಯದಿ ((r = sshbuf_get_u8(ಸಂದೇಶ, &type)) != 0)
		fatal_fr(r, "parse type");
	ಯದಿ (type != SSH2_FXP_VERSION) {
		error("Invalid packet back from SSH2_FXP_INIT (type %u)",
		    type);
		sshbuf_free(ಸಂದೇಶ);
		ಮುಕ್ತ(ret);
		ಪ್ರತ್ಯಾಗಮ(ರಿಕ್ತ);
	}
	ಯದಿ ((r = sshbuf_get_u32(ಸಂದೇಶ, &ret->version)) != 0)
		fatal_fr(r, "parse version");

	debug2("Remote version: %u", ret->version);

	/* Check for extensions */
	ಯಾವತ್ (sshbuf_len(ಸಂದೇಶ) > 0) {
		ವರ್ಣ *name;
		u_char *ಮೌಲ್ಯ;
		size_t vlen;
		ಪೂರ್ಣಾಙ್ಕ known = 0;

		ಯದಿ ((r = sshbuf_get_cstring(ಸಂದೇಶ, &name, ರಿಕ್ತ)) != 0 ||
		    (r = sshbuf_get_string(ಸಂದೇಶ, &ಮೌಲ್ಯ, &vlen)) != 0)
			fatal_fr(r, "parse extension");
		ಯದಿ (strcmp(name, "posix-rename@openssh.com") == 0 &&
		    strcmp((ವರ್ಣ *)ಮೌಲ್ಯ, "1") == 0) {
			ret->exts |= SFTP_EXT_POSIX_RENAME;
			known = 1;
		} ಅನ್ಯಥಾ ಯದಿ (strcmp(name, "statvfs@openssh.com") == 0 &&
		    strcmp((ವರ್ಣ *)ಮೌಲ್ಯ, "2") == 0) {
			ret->exts |= SFTP_EXT_STATVFS;
			known = 1;
		} ಅನ್ಯಥಾ ಯದಿ (strcmp(name, "fstatvfs@openssh.com") == 0 &&
		    strcmp((ವರ್ಣ *)ಮೌಲ್ಯ, "2") == 0) {
			ret->exts |= SFTP_EXT_FSTATVFS;
			known = 1;
		} ಅನ್ಯಥಾ ಯದಿ (strcmp(name, "hardlink@openssh.com") == 0 &&
		    strcmp((ವರ್ಣ *)ಮೌಲ್ಯ, "1") == 0) {
			ret->exts |= SFTP_EXT_HARDLINK;
			known = 1;
		} ಅನ್ಯಥಾ ಯದಿ (strcmp(name, "fsync@openssh.com") == 0 &&
		    strcmp((ವರ್ಣ *)ಮೌಲ್ಯ, "1") == 0) {
			ret->exts |= SFTP_EXT_FSYNC;
			known = 1;
		} ಅನ್ಯಥಾ ಯದಿ (strcmp(name, "lsetstat@openssh.com") == 0 &&
		    strcmp((ವರ್ಣ *)ಮೌಲ್ಯ, "1") == 0) {
			ret->exts |= SFTP_EXT_LSETSTAT;
			known = 1;
		} ಅನ್ಯಥಾ ಯದಿ (strcmp(name, "limits@openssh.com") == 0 &&
		    strcmp((ವರ್ಣ *)ಮೌಲ್ಯ, "1") == 0) {
			ret->exts |= SFTP_EXT_LIMITS;
			known = 1;
		} ಅನ್ಯಥಾ ಯದಿ (strcmp(name, "expand-path@openssh.com") == 0 &&
		    strcmp((ವರ್ಣ *)ಮೌಲ್ಯ, "1") == 0) {
			ret->exts |= SFTP_EXT_PATH_EXPAND;
			known = 1;
		} ಅನ್ಯಥಾ ಯದಿ (strcmp(name, "copy-data") == 0 &&
		    strcmp((ವರ್ಣ *)ಮೌಲ್ಯ, "1") == 0) {
			ret->exts |= SFTP_EXT_COPY_DATA;
			known = 1;
		} ಅನ್ಯಥಾ ಯದಿ (strcmp(name,
		    "users-groups-by-id@openssh.com") == 0 &&
		    strcmp((ವರ್ಣ *)ಮೌಲ್ಯ, "1") == 0) {
			ret->exts |= SFTP_EXT_GETUSERSGROUPS_BY_ID;
			known = 1;
		}
		ಯದಿ (known) {
			debug2("Server supports extension \"%s\" revision %s",
			    name, ಮೌಲ್ಯ);
		} ಅನ್ಯಥಾ {
			debug2("Unrecognised server extension \"%s\"", name);
		}
		ಮುಕ್ತ(name);
		ಮುಕ್ತ(ಮೌಲ್ಯ);
	}

	sshbuf_free(ಸಂದೇಶ);

	/* Query the server for its limits */
	ಯದಿ (ret->exts & SFTP_EXT_LIMITS) {
		ಸಂರಚನಾ sftp_limits limits;
		ಯದಿ (sftp_get_limits(ret, &limits) != 0)
			fatal_f("limits failed");

		/* If the caller did not specify, find a good value */
		ಯದಿ (transfer_buflen == 0) {
			ret->download_buflen = MINIMUM(limits.read_length,
			    SFTP_MAX_ಸಂದೇಶ_LENGTH - 1024);
			ret->upload_buflen = MINIMUM(limits.write_length,
			    SFTP_MAX_ಸಂದೇಶ_LENGTH - 1024);
			ret->download_buflen = MAXIMUM(ret->download_buflen, 64);
			ret->upload_buflen = MAXIMUM(ret->upload_buflen, 64);
			debug3("server upload/download buffer sizes "
			    "%llu / %llu; using %u / %u",
			    (unsigned long long)limits.write_length,
			    (unsigned long long)limits.read_length,
			    ret->upload_buflen, ret->download_buflen);
		}
	}

	/* Some filexfer v.0 servers don't support large packets */
	ಯದಿ (ret->version == 0) {
		ret->download_buflen = MINIMUM(ret->download_buflen, 20480);
		ret->upload_buflen = MINIMUM(ret->upload_buflen, 20480);
	}

	ret->limit_kbps = limit_kbps;
	ಯದಿ (ret->limit_kbps > 0) {
		bandwidth_limit_init(&ret->bwlimit_in, ret->limit_kbps,
		    ret->download_buflen);
		bandwidth_limit_init(&ret->bwlimit_out, ret->limit_kbps,
		    ret->upload_buflen);
	}

	ಪ್ರತ್ಯಾಗಮ ret;
}

ಶೂನ್ಯ
sftp_free(ಸಂರಚನಾ sftp_conn *conn)
{
	ಯದಿ (conn == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	freezero(conn, ಪರಿಮಾಣ(*conn));
}

u_int
sftp_proto_version(ಸಂರಚನಾ sftp_conn *conn)
{
	ಪ್ರತ್ಯಾಗಮ conn->version;
}

ಪೂರ್ಣಾಙ್ಕ
sftp_get_limits(ಸಂರಚನಾ sftp_conn *conn, ಸಂರಚನಾ sftp_limits *limits)
{
	u_int id, ಸಂದೇಶ_id;
	u_char type;
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((conn->exts & SFTP_EXT_LIMITS) == 0) {
		error("Server does not support limits@openssh.com extension");
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");

	id = conn->ಸಂದೇಶ_id++;
	ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, "limits@openssh.com")) != 0)
		fatal_fr(r, "compose");
	send_ಸಂದೇಶ(conn, ಸಂದೇಶ);
	debug3("Sent message limits@openssh.com I:%u", id);

	get_ಸಂದೇಶ(conn, ಸಂದೇಶ);

	ಯದಿ ((r = sshbuf_get_u8(ಸಂದೇಶ, &type)) != 0 ||
	    (r = sshbuf_get_u32(ಸಂದೇಶ, &ಸಂದೇಶ_id)) != 0)
		fatal_fr(r, "parse");

	debug3("Received limits reply T:%u I:%u", type, ಸಂದೇಶ_id);
	ಯದಿ (id != ಸಂದೇಶ_id)
		fatal("ID mismatch (%u != %u)", ಸಂದೇಶ_id, id);
	ಯದಿ (type != SSH2_FXP_EXTENDED_REPLY) {
		debug_f("expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_REPLY, type);
		/* Disable the limits extension */
		conn->exts &= ~SFTP_EXT_LIMITS;
		sshbuf_free(ಸಂದೇಶ);
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	memset(limits, 0, ಪರಿಮಾಣ(*limits));
	ಯದಿ ((r = sshbuf_get_u64(ಸಂದೇಶ, &limits->packet_length)) != 0 ||
	    (r = sshbuf_get_u64(ಸಂದೇಶ, &limits->read_length)) != 0 ||
	    (r = sshbuf_get_u64(ಸಂದೇಶ, &limits->write_length)) != 0 ||
	    (r = sshbuf_get_u64(ಸಂದೇಶ, &limits->open_handles)) != 0)
		fatal_fr(r, "parse limits");

	sshbuf_free(ಸಂದೇಶ);

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sftp_close(ಸಂರಚನಾ sftp_conn *conn, ಧ್ರುವ u_char *handle, u_int handle_len)
{
	u_int id, status;
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");

	id = conn->ಸಂದೇಶ_id++;
	ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_CLOSE)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
	    (r = sshbuf_put_string(ಸಂದೇಶ, handle, handle_len)) != 0)
		fatal_fr(r, "parse");
	send_ಸಂದೇಶ(conn, ಸಂದೇಶ);
	debug3("Sent message SSH2_FXP_CLOSE I:%u", id);

	status = get_status(conn, id);
	ಯದಿ (status != SSH2_FX_OK)
		error("close remote: %s", fx2txt(status));

	sshbuf_free(ಸಂದೇಶ);

	ಪ್ರತ್ಯಾಗಮ status == SSH2_FX_OK ? 0 : -1;
}


ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sftp_lsreaddir(ಸಂರಚನಾ sftp_conn *conn, ಧ್ರುವ ವರ್ಣ *path, ಪೂರ್ಣಾಙ್ಕ print_flag,
    SFTP_DIRENT ***dir)
{
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;
	u_int ಎಣಿಕೆ, id, i, expected_id, ents = 0;
	size_t handle_len;
	u_char type, *handle;
	ಪೂರ್ಣಾಙ್ಕ status = SSH2_FX_FAILURE;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (dir)
		*dir = ರಿಕ್ತ;

	id = conn->ಸಂದೇಶ_id++;

	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_OPENDIR)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, path)) != 0)
		fatal_fr(r, "compose OPENDIR");
	send_ಸಂದೇಶ(conn, ಸಂದೇಶ);

	handle = get_handle(conn, id, &handle_len,
	    "remote readdir(\"%s\")", path);
	ಯದಿ (handle == ರಿಕ್ತ) {
		sshbuf_free(ಸಂದೇಶ);
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	ಯದಿ (dir) {
		ents = 0;
		*dir = xcalloc(1, ಪರಿಮಾಣ(**dir));
		(*dir)[0] = ರಿಕ್ತ;
	}

	ಪ್ರತಿ (; !interrupted;) {
		id = expected_id = conn->ಸಂದೇಶ_id++;

		debug3("Sending SSH2_FXP_READDIR I:%u", id);

		sshbuf_reset(ಸಂದೇಶ);
		ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_READDIR)) != 0 ||
		    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
		    (r = sshbuf_put_string(ಸಂದೇಶ, handle, handle_len)) != 0)
			fatal_fr(r, "compose READDIR");
		send_ಸಂದೇಶ(conn, ಸಂದೇಶ);

		sshbuf_reset(ಸಂದೇಶ);

		get_ಸಂದೇಶ(conn, ಸಂದೇಶ);

		ಯದಿ ((r = sshbuf_get_u8(ಸಂದೇಶ, &type)) != 0 ||
		    (r = sshbuf_get_u32(ಸಂದೇಶ, &id)) != 0)
			fatal_fr(r, "parse");

		debug3("Received reply T:%u I:%u", type, id);

		ಯದಿ (id != expected_id)
			fatal("ID mismatch (%u != %u)", id, expected_id);

		ಯದಿ (type == SSH2_FXP_STATUS) {
			u_int rstatus;

			ಯದಿ ((r = sshbuf_get_u32(ಸಂದೇಶ, &rstatus)) != 0)
				fatal_fr(r, "parse status");
			debug3("Received SSH2_FXP_STATUS %d", rstatus);
			ಯದಿ (rstatus == SSH2_FX_EOF)
				ಭಙ್ಗ;
			error("Couldn't read directory: %s", fx2txt(rstatus));
			ಗಚ್ಛ out;
		} ಅನ್ಯಥಾ ಯದಿ (type != SSH2_FXP_NAME)
			fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
			    SSH2_FXP_NAME, type);

		ಯದಿ ((r = sshbuf_get_u32(ಸಂದೇಶ, &ಎಣಿಕೆ)) != 0)
			fatal_fr(r, "parse count");
		ಯದಿ (ಎಣಿಕೆ > SSHBUF_SIZE_MAX)
			fatal_f("nonsensical number of entries");
		ಯದಿ (ಎಣಿಕೆ == 0)
			ಭಙ್ಗ;
		debug3("Received %d SSH2_FXP_NAME responses", ಎಣಿಕೆ);
		ಪ್ರತಿ (i = 0; i < ಎಣಿಕೆ; i++) {
			ವರ್ಣ *filename, *longname;
			Attrib a;

			ಯದಿ ((r = sshbuf_get_cstring(ಸಂದೇಶ, &filename,
			    ರಿಕ್ತ)) != 0 ||
			    (r = sshbuf_get_cstring(ಸಂದೇಶ, &longname,
			    ರಿಕ್ತ)) != 0)
				fatal_fr(r, "parse filenames");
			ಯದಿ ((r = decode_attrib(ಸಂದೇಶ, &a)) != 0) {
				error_fr(r, "couldn't decode attrib");
				ಮುಕ್ತ(filename);
				ಮುಕ್ತ(longname);
				ಗಚ್ಛ out;
			}

			ಯದಿ (print_flag)
				mprintf("%s\n", longname);

			/*
			 * Directory entries should never contain '/'
			 * These can be used to attack recursive ops
			 * (e.g. send '../../../../etc/passwd')
			 */
			ಯದಿ (*filename == '\0' ||
			    strpbrk(filename, SFTP_DIRECTORY_CHARS) != ರಿಕ್ತ) {
				error("Server sent suspect path \"%s\" "
				    "during readdir of \"%s\"", filename, path);
			} ಅನ್ಯಥಾ ಯದಿ (dir) {
				*dir = xreallocarray(*dir, ents + 2, ಪರಿಮಾಣ(**dir));
				(*dir)[ents] = xcalloc(1, ಪರಿಮಾಣ(***dir));
				(*dir)[ents]->filename = xstrdup(filename);
				(*dir)[ents]->longname = xstrdup(longname);
				memcpy(&(*dir)[ents]->a, &a, ಪರಿಮಾಣ(a));
				(*dir)[++ents] = ರಿಕ್ತ;
			}
			ಮುಕ್ತ(filename);
			ಮುಕ್ತ(longname);
		}
	}
	status = 0;

 out:
	sshbuf_free(ಸಂದೇಶ);
	sftp_close(conn, handle, handle_len);
	ಮುಕ್ತ(handle);

	ಯದಿ (status != 0 && dir != ರಿಕ್ತ) {
		/* Don't return results on error */
		sftp_free_dirents(*dir);
		*dir = ರಿಕ್ತ;
	} ಅನ್ಯಥಾ ಯದಿ (interrupted && dir != ರಿಕ್ತ && *dir != ರಿಕ್ತ) {
		/* Don't return partial matches on interrupt */
		sftp_free_dirents(*dir);
		*dir = xcalloc(1, ಪರಿಮಾಣ(**dir));
		**dir = ರಿಕ್ತ;
	}

	ಪ್ರತ್ಯಾಗಮ status == SSH2_FX_OK ? 0 : -1;
}

ಪೂರ್ಣಾಙ್ಕ
sftp_readdir(ಸಂರಚನಾ sftp_conn *conn, ಧ್ರುವ ವರ್ಣ *path, SFTP_DIRENT ***dir)
{
	ಪ್ರತ್ಯಾಗಮ sftp_lsreaddir(conn, path, 0, dir);
}

ಶೂನ್ಯ sftp_free_dirents(SFTP_DIRENT **s)
{
	ಪೂರ್ಣಾಙ್ಕ i;

	ಯದಿ (s == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	ಪ್ರತಿ (i = 0; s[i]; i++) {
		ಮುಕ್ತ(s[i]->filename);
		ಮುಕ್ತ(s[i]->longname);
		ಮುಕ್ತ(s[i]);
	}
	ಮುಕ್ತ(s);
}

ಪೂರ್ಣಾಙ್ಕ
sftp_rm(ಸಂರಚನಾ sftp_conn *conn, ಧ್ರುವ ವರ್ಣ *path)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_REMOVE \"%s\"", path);

	id = conn->ಸಂದೇಶ_id++;
	send_string_request(conn, id, SSH2_FXP_REMOVE, path, strlen(path));
	status = get_status(conn, id);
	ಯದಿ (status != SSH2_FX_OK)
		error("remote delete %s: %s", path, fx2txt(status));
	ಪ್ರತ್ಯಾಗಮ status == SSH2_FX_OK ? 0 : -1;
}

ಪೂರ್ಣಾಙ್ಕ
sftp_mkdir(ಸಂರಚನಾ sftp_conn *conn, ಧ್ರುವ ವರ್ಣ *path, Attrib *a, ಪೂರ್ಣಾಙ್ಕ print_flag)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_MKDIR \"%s\"", path);

	id = conn->ಸಂದೇಶ_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_MKDIR, path,
	    strlen(path), a);

	status = get_status(conn, id);
	ಯದಿ (status != SSH2_FX_OK && print_flag)
		error("remote mkdir \"%s\": %s", path, fx2txt(status));

	ಪ್ರತ್ಯಾಗಮ status == SSH2_FX_OK ? 0 : -1;
}

ಪೂರ್ಣಾಙ್ಕ
sftp_mkpath(ಸಂರಚನಾ sftp_conn *conn, ಧ್ರುವ ವರ್ಣ *path, Attrib *a, ಪೂರ್ಣಾಙ್ಕ print_flag)
{
	ವರ್ಣ *slash, *tmp_path;
	ಪೂರ್ಣಾಙ್ಕ done;

	tmp_path = xstrdup(path);
	slash = tmp_path;

	ಪ್ರತಿ (;;) {
		slash += strspn(slash, "/");
		slash += strcspn(slash, "/");

		done = (*slash == '\0');
		*slash = '\0';

		ಯದಿ (!sftp_remote_is_dir(conn, tmp_path)) {
			ಯದಿ (sftp_mkdir(conn, tmp_path, a, print_flag) != 0) {
				ಮುಕ್ತ(tmp_path);
				ಪ್ರತ್ಯಾಗಮ -1;
			}
		}

		ಯದಿ (done)
			ಭಙ್ಗ;

		*slash = '/';
	}

	ಮುಕ್ತ(tmp_path);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sftp_rmdir(ಸಂರಚನಾ sftp_conn *conn, ಧ್ರುವ ವರ್ಣ *path)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_RMDIR \"%s\"", path);

	id = conn->ಸಂದೇಶ_id++;
	send_string_request(conn, id, SSH2_FXP_RMDIR, path,
	    strlen(path));

	status = get_status(conn, id);
	ಯದಿ (status != SSH2_FX_OK)
		error("remote rmdir \"%s\": %s", path, fx2txt(status));

	ಪ್ರತ್ಯಾಗಮ status == SSH2_FX_OK ? 0 : -1;
}

ಪೂರ್ಣಾಙ್ಕ
sftp_stat(ಸಂರಚನಾ sftp_conn *conn, ಧ್ರುವ ವರ್ಣ *path, ಪೂರ್ಣಾಙ್ಕ quiet, Attrib *a)
{
	u_int id;

	debug2("Sending SSH2_FXP_STAT \"%s\"", path);

	id = conn->ಸಂದೇಶ_id++;

	send_string_request(conn, id,
	    conn->version == 0 ? SSH2_FXP_STAT_VERSION_0 : SSH2_FXP_STAT,
	    path, strlen(path));

	ಪ್ರತ್ಯಾಗಮ get_decode_stat(conn, id, quiet, a);
}

ಪೂರ್ಣಾಙ್ಕ
sftp_lstat(ಸಂರಚನಾ sftp_conn *conn, ಧ್ರುವ ವರ್ಣ *path, ಪೂರ್ಣಾಙ್ಕ quiet, Attrib *a)
{
	u_int id;

	ಯದಿ (conn->version == 0) {
		do_log2(quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_INFO,
		    "Server version does not support lstat operation");
		ಪ್ರತ್ಯಾಗಮ sftp_stat(conn, path, quiet, a);
	}

	id = conn->ಸಂದೇಶ_id++;
	send_string_request(conn, id, SSH2_FXP_LSTAT, path,
	    strlen(path));

	ಪ್ರತ್ಯಾಗಮ get_decode_stat(conn, id, quiet, a);
}

#ifdef notyet
ಪೂರ್ಣಾಙ್ಕ
sftp_fstat(ಸಂರಚನಾ sftp_conn *conn, ಧ್ರುವ u_char *handle, u_int handle_len,
    ಪೂರ್ಣಾಙ್ಕ quiet, Attrib *a)
{
	u_int id;

	debug2("Sending SSH2_FXP_FSTAT \"%s\"");

	id = conn->ಸಂದೇಶ_id++;
	send_string_request(conn, id, SSH2_FXP_FSTAT, handle,
	    handle_len);

	ಪ್ರತ್ಯಾಗಮ get_decode_stat(conn, id, quiet, a);
}
#endif

ಪೂರ್ಣಾಙ್ಕ
sftp_setstat(ಸಂರಚನಾ sftp_conn *conn, ಧ್ರುವ ವರ್ಣ *path, Attrib *a)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_SETSTAT \"%s\"", path);

	id = conn->ಸಂದೇಶ_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_SETSTAT, path,
	    strlen(path), a);

	status = get_status(conn, id);
	ಯದಿ (status != SSH2_FX_OK)
		error("remote setstat \"%s\": %s", path, fx2txt(status));

	ಪ್ರತ್ಯಾಗಮ status == SSH2_FX_OK ? 0 : -1;
}

ಪೂರ್ಣಾಙ್ಕ
sftp_fsetstat(ಸಂರಚನಾ sftp_conn *conn, ಧ್ರುವ u_char *handle, u_int handle_len,
    Attrib *a)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_FSETSTAT");

	id = conn->ಸಂದೇಶ_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_FSETSTAT, handle,
	    handle_len, a);

	status = get_status(conn, id);
	ಯದಿ (status != SSH2_FX_OK)
		error("remote fsetstat: %s", fx2txt(status));

	ಪ್ರತ್ಯಾಗಮ status == SSH2_FX_OK ? 0 : -1;
}

/* Implements both the realpath and expand-path operations */
ಸ್ಥಿರ ವರ್ಣ *
sftp_realpath_expand(ಸಂರಚನಾ sftp_conn *conn, ಧ್ರುವ ವರ್ಣ *path, ಪೂರ್ಣಾಙ್ಕ expand)
{
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;
	u_int expected_id, ಎಣಿಕೆ, id;
	ವರ್ಣ *filename, *longname;
	Attrib a;
	u_char type;
	ಪೂರ್ಣಾಙ್ಕ r;
	ಧ್ರುವ ವರ್ಣ *what = "SSH2_FXP_REALPATH";

	ಯದಿ (expand)
		what = "expand-path@openssh.com";
	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");

	expected_id = id = conn->ಸಂದೇಶ_id++;
	ಯದಿ (expand) {
		debug2("Sending SSH2_FXP_EXTENDED(expand-path@openssh.com) "
		    "\"%s\"", path);
		ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_EXTENDED)) != 0 ||
		    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
		    (r = sshbuf_put_cstring(ಸಂದೇಶ,
		    "expand-path@openssh.com")) != 0 ||
		    (r = sshbuf_put_cstring(ಸಂದೇಶ, path)) != 0)
			fatal_fr(r, "compose %s", what);
		send_ಸಂದೇಶ(conn, ಸಂದೇಶ);
	} ಅನ್ಯಥಾ {
		debug2("Sending SSH2_FXP_REALPATH \"%s\"", path);
		send_string_request(conn, id, SSH2_FXP_REALPATH,
		    path, strlen(path));
	}
	get_ಸಂದೇಶ(conn, ಸಂದೇಶ);
	ಯದಿ ((r = sshbuf_get_u8(ಸಂದೇಶ, &type)) != 0 ||
	    (r = sshbuf_get_u32(ಸಂದೇಶ, &id)) != 0)
		fatal_fr(r, "parse");

	ಯದಿ (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);

	ಯದಿ (type == SSH2_FXP_STATUS) {
		u_int status;
		ವರ್ಣ *errmsg;

		ಯದಿ ((r = sshbuf_get_u32(ಸಂದೇಶ, &status)) != 0 ||
		    (r = sshbuf_get_cstring(ಸಂದೇಶ, &errmsg, ರಿಕ್ತ)) != 0)
			fatal_fr(r, "parse status");
		error("%s %s: %s", expand ? "expand" : "realpath",
		    path, *errmsg == '\0' ? fx2txt(status) : errmsg);
		ಮುಕ್ತ(errmsg);
		sshbuf_free(ಸಂದೇಶ);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	} ಅನ್ಯಥಾ ಯದಿ (type != SSH2_FXP_NAME)
		fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
		    SSH2_FXP_NAME, type);

	ಯದಿ ((r = sshbuf_get_u32(ಸಂದೇಶ, &ಎಣಿಕೆ)) != 0)
		fatal_fr(r, "parse count");
	ಯದಿ (ಎಣಿಕೆ != 1)
		fatal("Got multiple names (%d) from %s", ಎಣಿಕೆ, what);

	ಯದಿ ((r = sshbuf_get_cstring(ಸಂದೇಶ, &filename, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_cstring(ಸಂದೇಶ, &longname, ರಿಕ್ತ)) != 0 ||
	    (r = decode_attrib(ಸಂದೇಶ, &a)) != 0)
		fatal_fr(r, "parse filename/attrib");

	debug3("%s %s -> %s", what, path, filename);

	ಮುಕ್ತ(longname);

	sshbuf_free(ಸಂದೇಶ);

	ಪ್ರತ್ಯಾಗಮ(filename);
}

ವರ್ಣ *
sftp_realpath(ಸಂರಚನಾ sftp_conn *conn, ಧ್ರುವ ವರ್ಣ *path)
{
	ಪ್ರತ್ಯಾಗಮ sftp_realpath_expand(conn, path, 0);
}

ಪೂರ್ಣಾಙ್ಕ
sftp_can_expand_path(ಸಂರಚನಾ sftp_conn *conn)
{
	ಪ್ರತ್ಯಾಗಮ (conn->exts & SFTP_EXT_PATH_EXPAND) != 0;
}

ವರ್ಣ *
sftp_expand_path(ಸಂರಚನಾ sftp_conn *conn, ಧ್ರುವ ವರ್ಣ *path)
{
	ಯದಿ (!sftp_can_expand_path(conn)) {
		debug3_f("no server support, fallback to realpath");
		ಪ್ರತ್ಯಾಗಮ sftp_realpath_expand(conn, path, 0);
	}
	ಪ್ರತ್ಯಾಗಮ sftp_realpath_expand(conn, path, 1);
}

ಪೂರ್ಣಾಙ್ಕ
sftp_copy(ಸಂರಚನಾ sftp_conn *conn, ಧ್ರುವ ವರ್ಣ *oldpath, ಧ್ರುವ ವರ್ಣ *newpath)
{
	Attrib junk, attr;
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;
	u_char *old_handle, *new_handle;
	u_int mode, status, id;
	size_t old_handle_len, new_handle_len;
	ಪೂರ್ಣಾಙ್ಕ r;

	/* Return if the extension is not supported */
	ಯದಿ ((conn->exts & SFTP_EXT_COPY_DATA) == 0) {
		error("Server does not support copy-data extension");
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	/* Make sure the file exists, and we can copy its perms */
	ಯದಿ (sftp_stat(conn, oldpath, 0, &attr) != 0)
		ಪ್ರತ್ಯಾಗಮ -1;

	/* Do not preserve set[ug]id here, as we do not preserve ownership */
	ಯದಿ (attr.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		mode = attr.perm & 0777;

		ಯದಿ (!S_ISREG(attr.perm)) {
			error("Cannot copy non-regular file: %s", oldpath);
			ಪ್ರತ್ಯಾಗಮ -1;
		}
	} ಅನ್ಯಥಾ {
		/* NB: The user's umask will apply to this */
		mode = 0666;
	}

	/* Set up the new perms for the new file */
	attrib_clear(&attr);
	attr.perm = mode;
	attr.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;

	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");

	attrib_clear(&junk); /* Send empty attributes */

	/* Open the old file for reading */
	id = conn->ಸಂದೇಶ_id++;
	ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, oldpath)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, SSH2_FXF_READ)) != 0 ||
	    (r = encode_attrib(ಸಂದೇಶ, &junk)) != 0)
		fatal_fr(r, "buffer error");
	send_ಸಂದೇಶ(conn, ಸಂದೇಶ);
	debug3("Sent message SSH2_FXP_OPEN I:%u P:%s", id, oldpath);

	sshbuf_reset(ಸಂದೇಶ);

	old_handle = get_handle(conn, id, &old_handle_len,
	    "remote open(\"%s\")", oldpath);
	ಯದಿ (old_handle == ರಿಕ್ತ) {
		sshbuf_free(ಸಂದೇಶ);
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	/* Open the new file for writing */
	id = conn->ಸಂದೇಶ_id++;
	ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, newpath)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, SSH2_FXF_WRITE|SSH2_FXF_CREAT|
	    SSH2_FXF_TRUNC)) != 0 ||
	    (r = encode_attrib(ಸಂದೇಶ, &attr)) != 0)
		fatal_fr(r, "buffer error");
	send_ಸಂದೇಶ(conn, ಸಂದೇಶ);
	debug3("Sent message SSH2_FXP_OPEN I:%u P:%s", id, newpath);

	sshbuf_reset(ಸಂದೇಶ);

	new_handle = get_handle(conn, id, &new_handle_len,
	    "remote open(\"%s\")", newpath);
	ಯದಿ (new_handle == ರಿಕ್ತ) {
		sshbuf_free(ಸಂದೇಶ);
		ಮುಕ್ತ(old_handle);
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	/* Copy the file data */
	id = conn->ಸಂದೇಶ_id++;
	ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, "copy-data")) != 0 ||
	    (r = sshbuf_put_string(ಸಂದೇಶ, old_handle, old_handle_len)) != 0 ||
	    (r = sshbuf_put_u64(ಸಂದೇಶ, 0)) != 0 ||
	    (r = sshbuf_put_u64(ಸಂದೇಶ, 0)) != 0 ||
	    (r = sshbuf_put_string(ಸಂದೇಶ, new_handle, new_handle_len)) != 0 ||
	    (r = sshbuf_put_u64(ಸಂದೇಶ, 0)) != 0)
		fatal_fr(r, "buffer error");
	send_ಸಂದೇಶ(conn, ಸಂದೇಶ);
	debug3("Sent message copy-data \"%s\" 0 0 -> \"%s\" 0",
	       oldpath, newpath);

	status = get_status(conn, id);
	ಯದಿ (status != SSH2_FX_OK)
		error("Couldn't copy file \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	/* Clean up everything */
	sshbuf_free(ಸಂದೇಶ);
	sftp_close(conn, old_handle, old_handle_len);
	sftp_close(conn, new_handle, new_handle_len);
	ಮುಕ್ತ(old_handle);
	ಮುಕ್ತ(new_handle);

	ಪ್ರತ್ಯಾಗಮ status == SSH2_FX_OK ? 0 : -1;
}

ಪೂರ್ಣಾಙ್ಕ
sftp_rename(ಸಂರಚನಾ sftp_conn *conn, ಧ್ರುವ ವರ್ಣ *oldpath, ಧ್ರುವ ವರ್ಣ *newpath,
    ಪೂರ್ಣಾಙ್ಕ force_legacy)
{
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;
	u_int status, id;
	ಪೂರ್ಣಾಙ್ಕ r, use_ext = (conn->exts & SFTP_EXT_POSIX_RENAME) && !force_legacy;

	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");

	/* Send rename request */
	id = conn->ಸಂದೇಶ_id++;
	ಯದಿ (use_ext) {
		debug2("Sending SSH2_FXP_EXTENDED(posix-rename@openssh.com) "
		    "\"%s\" to \"%s\"", oldpath, newpath);
		ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_EXTENDED)) != 0 ||
		    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
		    (r = sshbuf_put_cstring(ಸಂದೇಶ,
		    "posix-rename@openssh.com")) != 0)
			fatal_fr(r, "compose posix-rename");
	} ಅನ್ಯಥಾ {
		debug2("Sending SSH2_FXP_RENAME \"%s\" to \"%s\"",
		    oldpath, newpath);
		ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_RENAME)) != 0 ||
		    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0)
			fatal_fr(r, "compose rename");
	}
	ಯದಿ ((r = sshbuf_put_cstring(ಸಂದೇಶ, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, newpath)) != 0)
		fatal_fr(r, "compose paths");
	send_ಸಂದೇಶ(conn, ಸಂದೇಶ);
	debug3("Sent message %s \"%s\" -> \"%s\"",
	    use_ext ? "posix-rename@openssh.com" :
	    "SSH2_FXP_RENAME", oldpath, newpath);
	sshbuf_free(ಸಂದೇಶ);

	status = get_status(conn, id);
	ಯದಿ (status != SSH2_FX_OK)
		error("remote rename \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	ಪ್ರತ್ಯಾಗಮ status == SSH2_FX_OK ? 0 : -1;
}

ಪೂರ್ಣಾಙ್ಕ
sftp_hardlink(ಸಂರಚನಾ sftp_conn *conn, ಧ್ರುವ ವರ್ಣ *oldpath, ಧ್ರುವ ವರ್ಣ *newpath)
{
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;
	u_int status, id;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((conn->exts & SFTP_EXT_HARDLINK) == 0) {
		error("Server does not support hardlink@openssh.com extension");
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	debug2("Sending SSH2_FXP_EXTENDED(hardlink@openssh.com) "
	    "\"%s\" to \"%s\"", oldpath, newpath);

	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");

	/* Send link request */
	id = conn->ಸಂದೇಶ_id++;
	ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, "hardlink@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, newpath)) != 0)
		fatal_fr(r, "compose");
	send_ಸಂದೇಶ(conn, ಸಂದೇಶ);
	debug3("Sent message hardlink@openssh.com \"%s\" -> \"%s\"",
	    oldpath, newpath);
	sshbuf_free(ಸಂದೇಶ);

	status = get_status(conn, id);
	ಯದಿ (status != SSH2_FX_OK)
		error("remote link \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	ಪ್ರತ್ಯಾಗಮ status == SSH2_FX_OK ? 0 : -1;
}

ಪೂರ್ಣಾಙ್ಕ
sftp_symlink(ಸಂರಚನಾ sftp_conn *conn, ಧ್ರುವ ವರ್ಣ *oldpath, ಧ್ರುವ ವರ್ಣ *newpath)
{
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;
	u_int status, id;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (conn->version < 3) {
		error("This server does not support the symlink operation");
		ಪ್ರತ್ಯಾಗಮ(SSH2_FX_OP_UNSUPPORTED);
	}
	debug2("Sending SSH2_FXP_SYMLINK \"%s\" to \"%s\"", oldpath, newpath);

	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");

	/* Send symlink request */
	id = conn->ಸಂದೇಶ_id++;
	ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_SYMLINK)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, newpath)) != 0)
		fatal_fr(r, "compose");
	send_ಸಂದೇಶ(conn, ಸಂದೇಶ);
	debug3("Sent message SSH2_FXP_SYMLINK \"%s\" -> \"%s\"", oldpath,
	    newpath);
	sshbuf_free(ಸಂದೇಶ);

	status = get_status(conn, id);
	ಯದಿ (status != SSH2_FX_OK)
		error("remote symlink file \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	ಪ್ರತ್ಯಾಗಮ status == SSH2_FX_OK ? 0 : -1;
}

ಪೂರ್ಣಾಙ್ಕ
sftp_fsync(ಸಂರಚನಾ sftp_conn *conn, u_char *handle, u_int handle_len)
{
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;
	u_int status, id;
	ಪೂರ್ಣಾಙ್ಕ r;

	/* Silently return if the extension is not supported */
	ಯದಿ ((conn->exts & SFTP_EXT_FSYNC) == 0)
		ಪ್ರತ್ಯಾಗಮ -1;
	debug2("Sending SSH2_FXP_EXTENDED(fsync@openssh.com)");

	/* Send fsync request */
	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	id = conn->ಸಂದೇಶ_id++;
	ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, "fsync@openssh.com")) != 0 ||
	    (r = sshbuf_put_string(ಸಂದೇಶ, handle, handle_len)) != 0)
		fatal_fr(r, "compose");
	send_ಸಂದೇಶ(conn, ಸಂದೇಶ);
	debug3("Sent message fsync@openssh.com I:%u", id);
	sshbuf_free(ಸಂದೇಶ);

	status = get_status(conn, id);
	ಯದಿ (status != SSH2_FX_OK)
		error("remote fsync: %s", fx2txt(status));

	ಪ್ರತ್ಯಾಗಮ status == SSH2_FX_OK ? 0 : -1;
}

#ifdef notyet
ವರ್ಣ *
sftp_readlink(ಸಂರಚನಾ sftp_conn *conn, ಧ್ರುವ ವರ್ಣ *path)
{
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;
	u_int expected_id, ಎಣಿಕೆ, id;
	ವರ್ಣ *filename, *longname;
	Attrib a;
	u_char type;
	ಪೂರ್ಣಾಙ್ಕ r;

	debug2("Sending SSH2_FXP_READLINK \"%s\"", path);

	expected_id = id = conn->ಸಂದೇಶ_id++;
	send_string_request(conn, id, SSH2_FXP_READLINK, path, strlen(path));

	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");

	get_ಸಂದೇಶ(conn, ಸಂದೇಶ);
	ಯದಿ ((r = sshbuf_get_u8(ಸಂದೇಶ, &type)) != 0 ||
	    (r = sshbuf_get_u32(ಸಂದೇಶ, &id)) != 0)
		fatal_fr(r, "parse");

	ಯದಿ (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);

	ಯದಿ (type == SSH2_FXP_STATUS) {
		u_int status;

		ಯದಿ ((r = sshbuf_get_u32(ಸಂದೇಶ, &status)) != 0)
			fatal_fr(r, "parse status");
		error("Couldn't readlink: %s", fx2txt(status));
		sshbuf_free(ಸಂದೇಶ);
		ಪ್ರತ್ಯಾಗಮ(ರಿಕ್ತ);
	} ಅನ್ಯಥಾ ಯದಿ (type != SSH2_FXP_NAME)
		fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
		    SSH2_FXP_NAME, type);

	ಯದಿ ((r = sshbuf_get_u32(ಸಂದೇಶ, &ಎಣಿಕೆ)) != 0)
		fatal_fr(r, "parse count");
	ಯದಿ (ಎಣಿಕೆ != 1)
		fatal("Got multiple names (%d) from SSH_FXP_READLINK", ಎಣಿಕೆ);

	ಯದಿ ((r = sshbuf_get_cstring(ಸಂದೇಶ, &filename, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_cstring(ಸಂದೇಶ, &longname, ರಿಕ್ತ)) != 0 ||
	    (r = decode_attrib(ಸಂದೇಶ, &a)) != 0)
		fatal_fr(r, "parse filenames/attrib");

	debug3("SSH_FXP_READLINK %s -> %s", path, filename);

	ಮುಕ್ತ(longname);

	sshbuf_free(ಸಂದೇಶ);

	ಪ್ರತ್ಯಾಗಮ filename;
}
#endif

ಪೂರ್ಣಾಙ್ಕ
sftp_statvfs(ಸಂರಚನಾ sftp_conn *conn, ಧ್ರುವ ವರ್ಣ *path, ಸಂರಚನಾ sftp_statvfs *st,
    ಪೂರ್ಣಾಙ್ಕ quiet)
{
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;
	u_int id;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((conn->exts & SFTP_EXT_STATVFS) == 0) {
		error("Server does not support statvfs@openssh.com extension");
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(statvfs@openssh.com) \"%s\"", path);

	id = conn->ಸಂದೇಶ_id++;

	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, "statvfs@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, path)) != 0)
		fatal_fr(r, "compose");
	send_ಸಂದೇಶ(conn, ಸಂದೇಶ);
	sshbuf_free(ಸಂದೇಶ);

	ಪ್ರತ್ಯಾಗಮ get_decode_statvfs(conn, st, id, quiet);
}

#ifdef notyet
ಪೂರ್ಣಾಙ್ಕ
sftp_fstatvfs(ಸಂರಚನಾ sftp_conn *conn, ಧ್ರುವ u_char *handle, u_int handle_len,
    ಸಂರಚನಾ sftp_statvfs *st, ಪೂರ್ಣಾಙ್ಕ quiet)
{
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;
	u_int id;

	ಯದಿ ((conn->exts & SFTP_EXT_FSTATVFS) == 0) {
		error("Server does not support fstatvfs@openssh.com extension");
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(fstatvfs@openssh.com)");

	id = conn->ಸಂದೇಶ_id++;

	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, "fstatvfs@openssh.com")) != 0 ||
	    (r = sshbuf_put_string(ಸಂದೇಶ, handle, handle_len)) != 0)
		fatal_fr(r, "compose");
	send_ಸಂದೇಶ(conn, ಸಂದೇಶ);
	sshbuf_free(ಸಂದೇಶ);

	ಪ್ರತ್ಯಾಗಮ get_decode_statvfs(conn, st, id, quiet);
}
#endif

ಪೂರ್ಣಾಙ್ಕ
sftp_lsetstat(ಸಂರಚನಾ sftp_conn *conn, ಧ್ರುವ ವರ್ಣ *path, Attrib *a)
{
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;
	u_int status, id;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((conn->exts & SFTP_EXT_LSETSTAT) == 0) {
		error("Server does not support lsetstat@openssh.com extension");
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(lsetstat@openssh.com) \"%s\"", path);

	id = conn->ಸಂದೇಶ_id++;
	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, "lsetstat@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, path)) != 0 ||
	    (r = encode_attrib(ಸಂದೇಶ, a)) != 0)
		fatal_fr(r, "compose");
	send_ಸಂದೇಶ(conn, ಸಂದೇಶ);
	sshbuf_free(ಸಂದೇಶ);

	status = get_status(conn, id);
	ಯದಿ (status != SSH2_FX_OK)
		error("remote lsetstat \"%s\": %s", path, fx2txt(status));

	ಪ್ರತ್ಯಾಗಮ status == SSH2_FX_OK ? 0 : -1;
}

ಸ್ಥಿರ ಶೂನ್ಯ
send_read_request(ಸಂರಚನಾ sftp_conn *conn, u_int id, uint64_t offset,
    u_int len, ಧ್ರುವ u_char *handle, u_int handle_len)
{
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_READ)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
	    (r = sshbuf_put_string(ಸಂದೇಶ, handle, handle_len)) != 0 ||
	    (r = sshbuf_put_u64(ಸಂದೇಶ, offset)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, len)) != 0)
		fatal_fr(r, "compose");
	send_ಸಂದೇಶ(conn, ಸಂದೇಶ);
	sshbuf_free(ಸಂದೇಶ);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
send_open(ಸಂರಚನಾ sftp_conn *conn, ಧ್ರುವ ವರ್ಣ *path, ಧ್ರುವ ವರ್ಣ *tag,
    u_int openmode, Attrib *a, u_char **handlep, size_t *handle_lenp)
{
	Attrib junk;
	u_char *handle;
	size_t handle_len;
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;
	ಪೂರ್ಣಾಙ್ಕ r;
	u_int id;

	debug2("Sending SSH2_FXP_OPEN \"%s\"", path);

	*handlep = ರಿಕ್ತ;
	*handle_lenp = 0;

	ಯದಿ (a == ರಿಕ್ತ) {
		attrib_clear(&junk); /* Send empty attributes */
		a = &junk;
	}
	/* Send open request */
	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	id = conn->ಸಂದೇಶ_id++;
	ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, path)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, openmode)) != 0 ||
	    (r = encode_attrib(ಸಂದೇಶ, a)) != 0)
		fatal_fr(r, "compose %s open", tag);
	send_ಸಂದೇಶ(conn, ಸಂದೇಶ);
	sshbuf_free(ಸಂದೇಶ);
	debug3("Sent %s message SSH2_FXP_OPEN I:%u P:%s M:0x%04x",
	    tag, id, path, openmode);
	ಯದಿ ((handle = get_handle(conn, id, &handle_len,
	    "%s open \"%s\"", tag, path)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ -1;
	/* success */
	*handlep = handle;
	*handle_lenp = handle_len;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ *
progress_meter_path(ಧ್ರುವ ವರ್ಣ *path)
{
	ಧ್ರುವ ವರ್ಣ *progresspath;

	ಯದಿ ((progresspath = strrchr(path, '/')) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ path;
	progresspath++;
	ಯದಿ (*progresspath == '\0')
		ಪ್ರತ್ಯಾಗಮ path;
	ಪ್ರತ್ಯಾಗಮ progresspath;
}

ಪೂರ್ಣಾಙ್ಕ
sftp_download(ಸಂರಚನಾ sftp_conn *conn, ಧ್ರುವ ವರ್ಣ *remote_path,
    ಧ್ರುವ ವರ್ಣ *local_path, Attrib *a, ಪೂರ್ಣಾಙ್ಕ preserve_flag, ಪೂರ್ಣಾಙ್ಕ resume_flag,
    ಪೂರ್ಣಾಙ್ಕ fsync_flag, ಪೂರ್ಣಾಙ್ಕ inplace_flag)
{
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;
	u_char *handle;
	ಪೂರ್ಣಾಙ್ಕ local_fd = -1, write_error, seen_zerolen = 0;
	ಪೂರ್ಣಾಙ್ಕ read_error, write_errno, lmodified = 0, reordered = 0, r;
	uint64_t offset = 0, size, highwater = 0, maxack = 0;
	u_int mode, id, buflen, ಅಂಕೆ_req, max_req, status = SSH2_FX_OK;
	off_t progress_counter;
	size_t handle_len;
	ಸಂರಚನಾ stat st;
	ಸಂರಚನಾ requests requests;
	ಸಂರಚನಾ request *req;
	u_char type;
	Attrib attr;

	debug2_f("download remote \"%s\" to local \"%s\"",
	    remote_path, local_path);

	TAILQ_INIT(&requests);

	ಯದಿ (a == ರಿಕ್ತ) {
		ಯದಿ (sftp_stat(conn, remote_path, 0, &attr) != 0)
			ಪ್ರತ್ಯಾಗಮ -1;
		a = &attr;
	}

	/* Do not preserve set[ug]id here, as we do not preserve ownership */
	ಯದಿ (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS)
		mode = a->perm & 0777;
	ಅನ್ಯಥಾ
		mode = 0666;

	ಯದಿ ((a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) &&
	    (!S_ISREG(a->perm))) {
		error("download %s: not a regular file", remote_path);
		ಪ್ರತ್ಯಾಗಮ(-1);
	}

	ಯದಿ (a->flags & SSH2_FILEXFER_ATTR_SIZE)
		size = a->size;
	ಅನ್ಯಥಾ
		size = 0;

	buflen = conn->download_buflen;

	/* Send open request */
	ಯದಿ (send_open(conn, remote_path, "remote", SSH2_FXF_READ, ರಿಕ್ತ,
	    &handle, &handle_len) != 0)
		ಪ್ರತ್ಯಾಗಮ -1;

	local_fd = open(local_path, O_WRONLY | O_CREAT |
	((resume_flag || inplace_flag) ? 0 : O_TRUNC), mode | S_IWUSR);
	ಯದಿ (local_fd == -1) {
		error("open local \"%s\": %s", local_path, strerror(errno));
		ಗಚ್ಛ fail;
	}
	ಯದಿ (resume_flag) {
		ಯದಿ (fstat(local_fd, &st) == -1) {
			error("stat local \"%s\": %s",
			    local_path, strerror(errno));
			ಗಚ್ಛ fail;
		}
		ಯದಿ (st.st_size < 0) {
			error("\"%s\" has negative size", local_path);
			ಗಚ್ಛ fail;
		}
		ಯದಿ ((uint64_t)st.st_size > size) {
			error("Unable to resume download of \"%s\": "
			    "local file is larger than remote", local_path);
 fail:
			sftp_close(conn, handle, handle_len);
			ಮುಕ್ತ(handle);
			ಯದಿ (local_fd != -1)
				close(local_fd);
			ಪ್ರತ್ಯಾಗಮ -1;
		}
		offset = highwater = maxack = st.st_size;
	}

	/* Read from remote and write to local */
	write_error = read_error = write_errno = ಅಂಕೆ_req = 0;
	max_req = 1;
	progress_counter = offset;

	ಯದಿ (showprogress && size != 0) {
		start_progress_meter(progress_meter_path(remote_path),
		    size, &progress_counter);
	}

	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");

	ಯಾವತ್ (ಅಂಕೆ_req > 0 || max_req > 0) {
		u_char *data;
		size_t len;

		/*
		 * Simulate EOF on interrupt: stop sending new requests and
		 * allow outstanding requests to drain gracefully
		 */
		ಯದಿ (interrupted) {
			ಯದಿ (ಅಂಕೆ_req == 0) /* If we haven't started yet... */
				ಭಙ್ಗ;
			max_req = 0;
		}

		/* Send some more requests */
		ಯಾವತ್ (ಅಂಕೆ_req < max_req) {
			debug3("Request range %llu -> %llu (%d/%d)",
			    (unsigned long long)offset,
			    (unsigned long long)offset + buflen - 1,
			    ಅಂಕೆ_req, max_req);
			req = request_enqueue(&requests, conn->ಸಂದೇಶ_id++,
			    buflen, offset);
			offset += buflen;
			ಅಂಕೆ_req++;
			send_read_request(conn, req->id, req->offset,
			    req->len, handle, handle_len);
		}

		sshbuf_reset(ಸಂದೇಶ);
		get_ಸಂದೇಶ(conn, ಸಂದೇಶ);
		ಯದಿ ((r = sshbuf_get_u8(ಸಂದೇಶ, &type)) != 0 ||
		    (r = sshbuf_get_u32(ಸಂದೇಶ, &id)) != 0)
			fatal_fr(r, "parse");
		debug3("Received reply T:%u I:%u R:%d", type, id, max_req);

		/* Find the request in our queue */
		ಯದಿ ((req = request_find(&requests, id)) == ರಿಕ್ತ)
			fatal("Unexpected reply %u", id);

		ವಿಕಲ್ಪ (type) {
		ಪಕ್ಷ SSH2_FXP_STATUS:
			ಯದಿ ((r = sshbuf_get_u32(ಸಂದೇಶ, &status)) != 0)
				fatal_fr(r, "parse status");
			ಯದಿ (status != SSH2_FX_EOF)
				read_error = 1;
			max_req = 0;
			TAILQ_REMOVE(&requests, req, tq);
			ಮುಕ್ತ(req);
			ಅಂಕೆ_req--;
			ಭಙ್ಗ;
		ಪಕ್ಷ SSH2_FXP_DATA:
			ಯದಿ ((r = sshbuf_get_string(ಸಂದೇಶ, &data, &len)) != 0)
				fatal_fr(r, "parse data");
			debug3("Received data %llu -> %llu",
			    (unsigned long long)req->offset,
			    (unsigned long long)req->offset + len - 1);
			ಯದಿ (len > req->len)
				fatal("Received more data than asked for "
				    "%zu > %zu", len, req->len);
			ಯದಿ (len == 0) {
				ಯದಿ (seen_zerolen)
					fatal_f("server sent zero data length");
				seen_zerolen = 1;
			}
			lmodified = 1;
			ಯದಿ ((lseek(local_fd, req->offset, SEEK_SET) == -1 ||
			    atomicio(vwrite, local_fd, data, len) != len) &&
			    !write_error) {
				write_errno = errno;
				write_error = 1;
				max_req = 0;
			} ಅನ್ಯಥಾ {
				/*
				 * Track both the highest offset acknowledged
				 * and the highest *contiguous* offset
				 * acknowledged.
				 * We'll need the latter for ftruncate()ing
				 * interrupted transfers.
				 */
				ಯದಿ (maxack < req->offset + len)
					maxack = req->offset + len;
				ಯದಿ (!reordered && req->offset <= highwater)
					highwater = maxack;
				ಅನ್ಯಥಾ ಯದಿ (!reordered && req->offset > highwater)
					reordered = 1;
			}
			progress_counter += len;
			ಮುಕ್ತ(data);

			ಯದಿ (len == req->len) {
				TAILQ_REMOVE(&requests, req, tq);
				ಮುಕ್ತ(req);
				ಅಂಕೆ_req--;
			} ಅನ್ಯಥಾ {
				/* Resend the request for the missing data */
				debug3("Short data block, re-requesting "
				    "%llu -> %llu (%2d)",
				    (unsigned long long)req->offset + len,
				    (unsigned long long)req->offset +
				    req->len - 1, ಅಂಕೆ_req);
				req->id = conn->ಸಂದೇಶ_id++;
				req->len -= len;
				req->offset += len;
				send_read_request(conn, req->id,
				    req->offset, req->len, handle, handle_len);
				/* Reduce the request size */
				ಯದಿ (len < buflen)
					buflen = MAXIMUM(MIN_READ_SIZE, len);
			}
			ಯದಿ (max_req > 0) { /* max_req = 0 iff EOF received */
				ಯದಿ (size > 0 && offset > size) {
					/* Only one request at a time
					 * after the expected EOF */
					debug3("Finish at %llu (%2d)",
					    (unsigned long long)offset,
					    ಅಂಕೆ_req);
					max_req = 1;
				} ಅನ್ಯಥಾ ಯದಿ (max_req < conn->ಅಂಕೆ_requests) {
					++max_req;
				}
			}
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			fatal("Expected SSH2_FXP_DATA(%u) packet, got %u",
			    SSH2_FXP_DATA, type);
		}
	}

	ಯದಿ (showprogress && size)
		stop_progress_meter();

	/* Sanity check */
	ಯದಿ (TAILQ_FIRST(&requests) != ರಿಕ್ತ)
		fatal("Transfer complete, but requests still in queue");

	ಯದಿ (!read_error && !write_error && !interrupted) {
		/* we got everything */
		highwater = maxack;
	}

	/*
	 * Truncate at highest contiguous point to avoid holes on interrupt,
	 * or unconditionally if writing in place.
	 */
	ಯದಿ (inplace_flag || read_error || write_error || interrupted) {
		ಯದಿ (reordered && resume_flag &&
		    (read_error || write_error || interrupted)) {
			error("Unable to resume download of \"%s\": "
			    "server reordered requests", local_path);
		}
		debug("truncating at %llu", (unsigned long long)highwater);
		ಯದಿ (ftruncate(local_fd, highwater) == -1)
			error("local ftruncate \"%s\": %s", local_path,
			    strerror(errno));
	}
	ಯದಿ (read_error) {
		error("read remote \"%s\" : %s", remote_path, fx2txt(status));
		status = -1;
		sftp_close(conn, handle, handle_len);
	} ಅನ್ಯಥಾ ಯದಿ (write_error) {
		error("write local \"%s\": %s", local_path,
		    strerror(write_errno));
		status = SSH2_FX_FAILURE;
		sftp_close(conn, handle, handle_len);
	} ಅನ್ಯಥಾ {
		ಯದಿ (sftp_close(conn, handle, handle_len) != 0 || interrupted)
			status = SSH2_FX_FAILURE;
		ಅನ್ಯಥಾ
			status = SSH2_FX_OK;
		/* Override umask and utimes if asked */
#ifdef HAVE_FCHMOD
		ಯದಿ (preserve_flag && fchmod(local_fd, mode) == -1)
#ಅನ್ಯಥಾ
		ಯದಿ (preserve_flag && chmod(local_path, mode) == -1)
#endif /* HAVE_FCHMOD */
			error("local chmod \"%s\": %s", local_path,
			    strerror(errno));
		ಯದಿ (preserve_flag &&
		    (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME)) {
			ಸಂರಚನಾ timeval tv[2];
			tv[0].tv_sec = a->atime;
			tv[1].tv_sec = a->mtime;
			tv[0].tv_usec = tv[1].tv_usec = 0;
			ಯದಿ (utimes(local_path, tv) == -1)
				error("local set times \"%s\": %s",
				    local_path, strerror(errno));
		}
		ಯದಿ (resume_flag && !lmodified)
			logit("File \"%s\" was not modified", local_path);
		ಅನ್ಯಥಾ ಯದಿ (fsync_flag) {
			debug("syncing \"%s\"", local_path);
			ಯದಿ (fsync(local_fd) == -1)
				error("local sync \"%s\": %s",
				    local_path, strerror(errno));
		}
	}
	close(local_fd);
	sshbuf_free(ಸಂದೇಶ);
	ಮುಕ್ತ(handle);

	ಪ್ರತ್ಯಾಗಮ status == SSH2_FX_OK ? 0 : -1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
download_dir_internal(ಸಂರಚನಾ sftp_conn *conn, ಧ್ರುವ ವರ್ಣ *src, ಧ್ರುವ ವರ್ಣ *dst,
    ಪೂರ್ಣಾಙ್ಕ depth, Attrib *dirattrib, ಪೂರ್ಣಾಙ್ಕ preserve_flag, ಪೂರ್ಣಾಙ್ಕ print_flag,
    ಪೂರ್ಣಾಙ್ಕ resume_flag, ಪೂರ್ಣಾಙ್ಕ fsync_flag, ಪೂರ್ಣಾಙ್ಕ follow_link_flag, ಪೂರ್ಣಾಙ್ಕ inplace_flag)
{
	ಪೂರ್ಣಾಙ್ಕ i, ret = 0;
	SFTP_DIRENT **dir_entries;
	ವರ್ಣ *filename, *new_src = ರಿಕ್ತ, *new_dst = ರಿಕ್ತ;
	mode_t mode = 0777, tmpmode = mode;
	Attrib *a, ldirattrib, lsym;

	ಯದಿ (depth >= MAX_DIR_DEPTH) {
		error("Maximum directory depth exceeded: %d levels", depth);
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	debug2_f("download dir remote \"%s\" to local \"%s\"", src, dst);

	ಯದಿ (dirattrib == ರಿಕ್ತ) {
		ಯದಿ (sftp_stat(conn, src, 1, &ldirattrib) != 0) {
			error("stat remote \"%s\" directory failed", src);
			ಪ್ರತ್ಯಾಗಮ -1;
		}
		dirattrib = &ldirattrib;
	}
	ಯದಿ (!S_ISDIR(dirattrib->perm)) {
		error("\"%s\" is not a directory", src);
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯದಿ (print_flag && print_flag != SFTP_PROGRESS_ONLY)
		mprintf("Retrieving %s\n", src);

	ಯದಿ (dirattrib->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		mode = dirattrib->perm & 01777;
		tmpmode = mode | (S_IWUSR|S_IXUSR);
	} ಅನ್ಯಥಾ {
		debug("download remote \"%s\": server "
		    "did not send permissions", dst);
	}

	ಯದಿ (mkdir(dst, tmpmode) == -1 && errno != EEXIST) {
		error("mkdir %s: %s", dst, strerror(errno));
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	ಯದಿ (sftp_readdir(conn, src, &dir_entries) == -1) {
		error("remote readdir \"%s\" failed", src);
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	ಪ್ರತಿ (i = 0; dir_entries[i] != ರಿಕ್ತ && !interrupted; i++) {
		ಮುಕ್ತ(new_dst);
		ಮುಕ್ತ(new_src);

		filename = dir_entries[i]->filename;
		new_dst = sftp_path_append(dst, filename);
		new_src = sftp_path_append(src, filename);

		a = &dir_entries[i]->a;
		ಯದಿ (S_ISLNK(a->perm)) {
			ಯದಿ (!follow_link_flag) {
				logit("download \"%s\": not a regular file",
				    new_src);
				ಅನುವರ್ತ;
			}
			/* Replace the stat contents with the symlink target */
			ಯದಿ (sftp_stat(conn, new_src, 1, &lsym) != 0) {
				logit("remote stat \"%s\" failed", new_src);
				ret = -1;
				ಅನುವರ್ತ;
			}
			a = &lsym;
		}

		ಯದಿ (S_ISDIR(a->perm)) {
			ಯದಿ (strcmp(filename, ".") == 0 ||
			    strcmp(filename, "..") == 0)
				ಅನುವರ್ತ;
			ಯದಿ (download_dir_internal(conn, new_src, new_dst,
			    depth + 1, a, preserve_flag,
			    print_flag, resume_flag,
			    fsync_flag, follow_link_flag, inplace_flag) == -1)
				ret = -1;
		} ಅನ್ಯಥಾ ಯದಿ (S_ISREG(a->perm)) {
			ಯದಿ (sftp_download(conn, new_src, new_dst, a,
			    preserve_flag, resume_flag, fsync_flag,
			    inplace_flag) == -1) {
				error("Download of file %s to %s failed",
				    new_src, new_dst);
				ret = -1;
			}
		} ಅನ್ಯಥಾ
			logit("download \"%s\": not a regular file", new_src);

	}
	ಮುಕ್ತ(new_dst);
	ಮುಕ್ತ(new_src);

	ಯದಿ (preserve_flag) {
		ಯದಿ (dirattrib->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
			ಸಂರಚನಾ timeval tv[2];
			tv[0].tv_sec = dirattrib->atime;
			tv[1].tv_sec = dirattrib->mtime;
			tv[0].tv_usec = tv[1].tv_usec = 0;
			ಯದಿ (utimes(dst, tv) == -1)
				error("local set times on \"%s\": %s",
				    dst, strerror(errno));
		} ಅನ್ಯಥಾ
			debug("Server did not send times for directory "
			    "\"%s\"", dst);
	}

	ಯದಿ (mode != tmpmode && chmod(dst, mode) == -1)
		error("local chmod directory \"%s\": %s", dst,
		    strerror(errno));

	sftp_free_dirents(dir_entries);

	ಪ್ರತ್ಯಾಗಮ ret;
}

ಪೂರ್ಣಾಙ್ಕ
sftp_download_dir(ಸಂರಚನಾ sftp_conn *conn, ಧ್ರುವ ವರ್ಣ *src, ಧ್ರುವ ವರ್ಣ *dst,
    Attrib *dirattrib, ಪೂರ್ಣಾಙ್ಕ preserve_flag, ಪೂರ್ಣಾಙ್ಕ print_flag, ಪೂರ್ಣಾಙ್ಕ resume_flag,
    ಪೂರ್ಣಾಙ್ಕ fsync_flag, ಪೂರ್ಣಾಙ್ಕ follow_link_flag, ಪೂರ್ಣಾಙ್ಕ inplace_flag)
{
	ವರ್ಣ *src_canon;
	ಪೂರ್ಣಾಙ್ಕ ret;

	ಯದಿ ((src_canon = sftp_realpath(conn, src)) == ರಿಕ್ತ) {
		error("download \"%s\": path canonicalization failed", src);
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	ret = download_dir_internal(conn, src_canon, dst, 0,
	    dirattrib, preserve_flag, print_flag, resume_flag, fsync_flag,
	    follow_link_flag, inplace_flag);
	ಮುಕ್ತ(src_canon);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಪೂರ್ಣಾಙ್ಕ
sftp_upload(ಸಂರಚನಾ sftp_conn *conn, ಧ್ರುವ ವರ್ಣ *local_path,
    ಧ್ರುವ ವರ್ಣ *remote_path, ಪೂರ್ಣಾಙ್ಕ preserve_flag, ಪೂರ್ಣಾಙ್ಕ resume,
    ಪೂರ್ಣಾಙ್ಕ fsync_flag, ಪೂರ್ಣಾಙ್ಕ inplace_flag)
{
	ಪೂರ್ಣಾಙ್ಕ r, local_fd;
	u_int openmode, id, status = SSH2_FX_OK, status2, reordered = 0;
	off_t offset, progress_counter;
	u_char type, *handle, *data;
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;
	ಸಂರಚನಾ stat sb;
	Attrib a, t, c;
	uint32_t startid, ackid;
	uint64_t highwater = 0, maxack = 0;
	ಸಂರಚನಾ request *ack = ರಿಕ್ತ;
	ಸಂರಚನಾ requests acks;
	size_t handle_len;

	debug2_f("upload local \"%s\" to remote \"%s\"",
	    local_path, remote_path);

	TAILQ_INIT(&acks);

	ಯದಿ ((local_fd = open(local_path, O_RDONLY)) == -1) {
		error("open local \"%s\": %s", local_path, strerror(errno));
		ಪ್ರತ್ಯಾಗಮ(-1);
	}
	ಯದಿ (fstat(local_fd, &sb) == -1) {
		error("fstat local \"%s\": %s", local_path, strerror(errno));
		close(local_fd);
		ಪ್ರತ್ಯಾಗಮ(-1);
	}
	ಯದಿ (!S_ISREG(sb.st_mode)) {
		error("local \"%s\" is not a regular file", local_path);
		close(local_fd);
		ಪ್ರತ್ಯಾಗಮ(-1);
	}
	stat_to_attrib(&sb, &a);

	a.flags &= ~SSH2_FILEXFER_ATTR_SIZE;
	a.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a.perm &= 0777;
	ಯದಿ (!preserve_flag)
		a.flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;

	ಯದಿ (resume) {
		/* Get remote file size if it exists */
		ಯದಿ (sftp_stat(conn, remote_path, 0, &c) != 0) {
			close(local_fd);
			ಪ್ರತ್ಯಾಗಮ -1;
		}

		ಯದಿ ((off_t)c.size >= sb.st_size) {
			error("resume \"%s\": destination file "
			    "same size or larger", local_path);
			close(local_fd);
			ಪ್ರತ್ಯಾಗಮ -1;
		}

		ಯದಿ (lseek(local_fd, (off_t)c.size, SEEK_SET) == -1) {
			close(local_fd);
			ಪ್ರತ್ಯಾಗಮ -1;
		}
		highwater = c.size;
	}

	openmode = SSH2_FXF_WRITE|SSH2_FXF_CREAT;
	ಯದಿ (resume)
		openmode |= SSH2_FXF_APPEND;
	ಅನ್ಯಥಾ ಯದಿ (!inplace_flag)
		openmode |= SSH2_FXF_TRUNC;

	/* Send open request */
	ಯದಿ (send_open(conn, remote_path, "dest", openmode, &a,
	    &handle, &handle_len) != 0) {
		close(local_fd);
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	id = conn->ಸಂದೇಶ_id;
	startid = ackid = id + 1;
	data = xmalloc(conn->upload_buflen);

	/* Read from local and write to remote */
	offset = progress_counter = (resume ? c.size : 0);
	ಯದಿ (showprogress) {
		start_progress_meter(progress_meter_path(local_path),
		    sb.st_size, &progress_counter);
	}

	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಪ್ರತಿ (;;) {
		ಪೂರ್ಣಾಙ್ಕ len;

		/*
		 * Can't use atomicio here because it returns 0 on EOF,
		 * thus losing the last block of the file.
		 * Simulate an EOF on interrupt, allowing ACKs from the
		 * server to drain.
		 */
		ಯದಿ (interrupted || status != SSH2_FX_OK)
			len = 0;
		ಅನ್ಯಥಾ ಕುರು
			len = ಪಠ(local_fd, data, conn->upload_buflen);
		ಯಾವತ್ ((len == -1) &&
		    (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK));

		ಯದಿ (len == -1) {
			fatal("read local \"%s\": %s",
			    local_path, strerror(errno));
		} ಅನ್ಯಥಾ ಯದಿ (len != 0) {
			ack = request_enqueue(&acks, ++id, len, offset);
			sshbuf_reset(ಸಂದೇಶ);
			ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_WRITE)) != 0 ||
			    (r = sshbuf_put_u32(ಸಂದೇಶ, ack->id)) != 0 ||
			    (r = sshbuf_put_string(ಸಂದೇಶ, handle,
			    handle_len)) != 0 ||
			    (r = sshbuf_put_u64(ಸಂದೇಶ, offset)) != 0 ||
			    (r = sshbuf_put_string(ಸಂದೇಶ, data, len)) != 0)
				fatal_fr(r, "compose");
			send_ಸಂದೇಶ(conn, ಸಂದೇಶ);
			debug3("Sent message SSH2_FXP_WRITE I:%u O:%llu S:%u",
			    id, (unsigned long long)offset, len);
		} ಅನ್ಯಥಾ ಯದಿ (TAILQ_FIRST(&acks) == ರಿಕ್ತ)
			ಭಙ್ಗ;

		ಯದಿ (ack == ರಿಕ್ತ)
			fatal("Unexpected ACK %u", id);

		ಯದಿ (id == startid || len == 0 ||
		    id - ackid >= conn->ಅಂಕೆ_requests) {
			u_int rid;

			sshbuf_reset(ಸಂದೇಶ);
			get_ಸಂದೇಶ(conn, ಸಂದೇಶ);
			ಯದಿ ((r = sshbuf_get_u8(ಸಂದೇಶ, &type)) != 0 ||
			    (r = sshbuf_get_u32(ಸಂದೇಶ, &rid)) != 0)
				fatal_fr(r, "parse");

			ಯದಿ (type != SSH2_FXP_STATUS)
				fatal("Expected SSH2_FXP_STATUS(%d) packet, "
				    "got %d", SSH2_FXP_STATUS, type);

			ಯದಿ ((r = sshbuf_get_u32(ಸಂದೇಶ, &status2)) != 0)
				fatal_fr(r, "parse status");
			debug3("SSH2_FXP_STATUS %u", status2);
			ಯದಿ (status2 != SSH2_FX_OK)
				status = status2; /* remember errors */

			/* Find the request in our queue */
			ಯದಿ ((ack = request_find(&acks, rid)) == ರಿಕ್ತ)
				fatal("Can't find request for ID %u", rid);
			TAILQ_REMOVE(&acks, ack, tq);
			debug3("In write loop, ack for %u %zu bytes at %lld",
			    ack->id, ack->len, (unsigned long long)ack->offset);
			++ackid;
			progress_counter += ack->len;
			/*
			 * Track both the highest offset acknowledged and the
			 * highest *contiguous* offset acknowledged.
			 * We'll need the latter for ftruncate()ing
			 * interrupted transfers.
			 */
			ಯದಿ (maxack < ack->offset + ack->len)
				maxack = ack->offset + ack->len;
			ಯದಿ (!reordered && ack->offset <= highwater)
				highwater = maxack;
			ಅನ್ಯಥಾ ಯದಿ (!reordered && ack->offset > highwater) {
				debug3_f("server reordered ACKs");
				reordered = 1;
			}
			ಮುಕ್ತ(ack);
		}
		offset += len;
		ಯದಿ (offset < 0)
			fatal_f("offset < 0");
	}
	sshbuf_free(ಸಂದೇಶ);

	ಯದಿ (showprogress)
		stop_progress_meter();
	ಮುಕ್ತ(data);

	ಯದಿ (status == SSH2_FX_OK && !interrupted) {
		/* we got everything */
		highwater = maxack;
	}
	ಯದಿ (status != SSH2_FX_OK) {
		error("write remote \"%s\": %s", remote_path, fx2txt(status));
		status = SSH2_FX_FAILURE;
	}

	ಯದಿ (inplace_flag || (resume && (status != SSH2_FX_OK || interrupted))) {
		debug("truncating at %llu", (unsigned long long)highwater);
		attrib_clear(&t);
		t.flags = SSH2_FILEXFER_ATTR_SIZE;
		t.size = highwater;
		sftp_fsetstat(conn, handle, handle_len, &t);
	}

	ಯದಿ (close(local_fd) == -1) {
		error("close local \"%s\": %s", local_path, strerror(errno));
		status = SSH2_FX_FAILURE;
	}

	/* Override umask and utimes if asked */
	ಯದಿ (preserve_flag)
		sftp_fsetstat(conn, handle, handle_len, &a);

	ಯದಿ (fsync_flag)
		(ಶೂನ್ಯ)sftp_fsync(conn, handle, handle_len);

	ಯದಿ (sftp_close(conn, handle, handle_len) != 0)
		status = SSH2_FX_FAILURE;

	ಮುಕ್ತ(handle);

	ಪ್ರತ್ಯಾಗಮ status == SSH2_FX_OK ? 0 : -1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
upload_dir_internal(ಸಂರಚನಾ sftp_conn *conn, ಧ್ರುವ ವರ್ಣ *src, ಧ್ರುವ ವರ್ಣ *dst,
    ಪೂರ್ಣಾಙ್ಕ depth, ಪೂರ್ಣಾಙ್ಕ preserve_flag, ಪೂರ್ಣಾಙ್ಕ print_flag, ಪೂರ್ಣಾಙ್ಕ resume, ಪೂರ್ಣಾಙ್ಕ fsync_flag,
    ಪೂರ್ಣಾಙ್ಕ follow_link_flag, ಪೂರ್ಣಾಙ್ಕ inplace_flag)
{
	ಪೂರ್ಣಾಙ್ಕ created = 0, ret = 0;
	DIR *dirp;
	ಸಂರಚನಾ dirent *dp;
	ವರ್ಣ *filename, *new_src = ರಿಕ್ತ, *new_dst = ರಿಕ್ತ;
	ಸಂರಚನಾ stat sb;
	Attrib a, dirattrib;
	uint32_t saved_perm;

	debug2_f("upload local dir \"%s\" to remote \"%s\"", src, dst);

	ಯದಿ (depth >= MAX_DIR_DEPTH) {
		error("Maximum directory depth exceeded: %d levels", depth);
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	ಯದಿ (stat(src, &sb) == -1) {
		error("stat local \"%s\": %s", src, strerror(errno));
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯದಿ (!S_ISDIR(sb.st_mode)) {
		error("\"%s\" is not a directory", src);
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯದಿ (print_flag && print_flag != SFTP_PROGRESS_ONLY)
		mprintf("Entering %s\n", src);

	stat_to_attrib(&sb, &a);
	a.flags &= ~SSH2_FILEXFER_ATTR_SIZE;
	a.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a.perm &= 01777;
	ಯದಿ (!preserve_flag)
		a.flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;

	/*
	 * sftp lacks a portable status value to match errno EEXIST,
	 * so if we get a failure back then we must check whether
	 * the path already existed and is a directory.  Ensure we can
	 * write to the directory we create for the duration of the transfer.
	 */
	saved_perm = a.perm;
	a.perm |= (S_IWUSR|S_IXUSR);
	ಯದಿ (sftp_mkdir(conn, dst, &a, 0) == 0)
		created = 1;
	ಅನ್ಯಥಾ {
		ಯದಿ (sftp_stat(conn, dst, 0, &dirattrib) != 0)
			ಪ್ರತ್ಯಾಗಮ -1;
		ಯದಿ (!S_ISDIR(dirattrib.perm)) {
			error("\"%s\" exists but is not a directory", dst);
			ಪ್ರತ್ಯಾಗಮ -1;
		}
	}
	a.perm = saved_perm;

	ಯದಿ ((dirp = opendir(src)) == ರಿಕ್ತ) {
		error("local opendir \"%s\": %s", src, strerror(errno));
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	ಯಾವತ್ (((dp = readdir(dirp)) != ರಿಕ್ತ) && !interrupted) {
		ಯದಿ (dp->d_ino == 0)
			ಅನುವರ್ತ;
		ಮುಕ್ತ(new_dst);
		ಮುಕ್ತ(new_src);
		filename = dp->d_name;
		new_dst = sftp_path_append(dst, filename);
		new_src = sftp_path_append(src, filename);

		ಯದಿ (strcmp(filename, ".") == 0 || strcmp(filename, "..") == 0)
			ಅನುವರ್ತ;
		ಯದಿ (lstat(new_src, &sb) == -1) {
			logit("local lstat \"%s\": %s", filename,
			    strerror(errno));
			ret = -1;
			ಅನುವರ್ತ;
		}
		ಯದಿ (S_ISLNK(sb.st_mode)) {
			ಯದಿ (!follow_link_flag) {
				logit("%s: not a regular file", filename);
				ಅನುವರ್ತ;
			}
			/* Replace the stat contents with the symlink target */
			ಯದಿ (stat(new_src, &sb) == -1) {
				logit("local stat \"%s\": %s", filename,
				    strerror(errno));
				ret = -1;
				ಅನುವರ್ತ;
			}
		}
		ಯದಿ (S_ISDIR(sb.st_mode)) {
			ಯದಿ (upload_dir_internal(conn, new_src, new_dst,
			    depth + 1, preserve_flag, print_flag, resume,
			    fsync_flag, follow_link_flag, inplace_flag) == -1)
				ret = -1;
		} ಅನ್ಯಥಾ ಯದಿ (S_ISREG(sb.st_mode)) {
			ಯದಿ (sftp_upload(conn, new_src, new_dst,
			    preserve_flag, resume, fsync_flag,
			    inplace_flag) == -1) {
				error("upload \"%s\" to \"%s\" failed",
				    new_src, new_dst);
				ret = -1;
			}
		} ಅನ್ಯಥಾ
			logit("%s: not a regular file", filename);
	}
	ಮುಕ್ತ(new_dst);
	ಮುಕ್ತ(new_src);

	ಯದಿ (created || preserve_flag)
		sftp_setstat(conn, dst, &a);

	(ಶೂನ್ಯ) closedir(dirp);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಪೂರ್ಣಾಙ್ಕ
sftp_upload_dir(ಸಂರಚನಾ sftp_conn *conn, ಧ್ರುವ ವರ್ಣ *src, ಧ್ರುವ ವರ್ಣ *dst,
    ಪೂರ್ಣಾಙ್ಕ preserve_flag, ಪೂರ್ಣಾಙ್ಕ print_flag, ಪೂರ್ಣಾಙ್ಕ resume, ಪೂರ್ಣಾಙ್ಕ fsync_flag,
    ಪೂರ್ಣಾಙ್ಕ follow_link_flag, ಪೂರ್ಣಾಙ್ಕ inplace_flag)
{
	ವರ್ಣ *dst_canon;
	ಪೂರ್ಣಾಙ್ಕ ret;

	ಯದಿ ((dst_canon = sftp_realpath(conn, dst)) == ರಿಕ್ತ) {
		error("upload \"%s\": path canonicalization failed", dst);
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	ret = upload_dir_internal(conn, src, dst_canon, 0, preserve_flag,
	    print_flag, resume, fsync_flag, follow_link_flag, inplace_flag);

	ಮುಕ್ತ(dst_canon);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಶೂನ್ಯ
handle_dest_replies(ಸಂರಚನಾ sftp_conn *to, ಧ್ರುವ ವರ್ಣ *to_path, ಪೂರ್ಣಾಙ್ಕ synchronous,
    u_int *nreqsp, u_int *write_errorp)
{
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;
	u_char type;
	u_int id, status;
	ಪೂರ್ಣಾಙ್ಕ r;
	ಸಂರಚನಾ pollfd pfd;

	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");

	/* Try to eat replies from the upload side */
	ಯಾವತ್ (*nreqsp > 0) {
		debug3_f("%u outstanding replies", *nreqsp);
		ಯದಿ (!synchronous) {
			/* Bail out if no data is ready to be read */
			pfd.fd = to->fd_in;
			pfd.events = POLLIN;
			ಯದಿ ((r = poll(&pfd, 1, 0)) == -1) {
				ಯದಿ (errno == EINTR)
					ಭಙ್ಗ;
				fatal_f("poll: %s", strerror(errno));
			} ಅನ್ಯಥಾ ಯದಿ (r == 0)
				ಭಙ್ಗ; /* fd not ready */
		}
		sshbuf_reset(ಸಂದೇಶ);
		get_ಸಂದೇಶ(to, ಸಂದೇಶ);

		ಯದಿ ((r = sshbuf_get_u8(ಸಂದೇಶ, &type)) != 0 ||
		    (r = sshbuf_get_u32(ಸಂದೇಶ, &id)) != 0)
			fatal_fr(r, "dest parse");
		debug3("Received dest reply T:%u I:%u R:%u", type, id, *nreqsp);
		ಯದಿ (type != SSH2_FXP_STATUS) {
			fatal_f("Expected SSH2_FXP_STATUS(%d) packet, got %d",
			    SSH2_FXP_STATUS, type);
		}
		ಯದಿ ((r = sshbuf_get_u32(ಸಂದೇಶ, &status)) != 0)
			fatal_fr(r, "parse dest status");
		debug3("dest SSH2_FXP_STATUS %u", status);
		ಯದಿ (status != SSH2_FX_OK) {
			/* record first error */
			ಯದಿ (*write_errorp == 0)
				*write_errorp = status;
		}
		/*
		 * XXX this doesn't do full reply matching like sftp_upload and
		 * so cannot gracefully truncate terminated uploads at a
		 * high-water mark. ATM the only caller of this function (scp)
		 * doesn't support transfer resumption, so this doesn't matter
		 * a whole lot.
		 *
		 * To be safe, sftp_crossload truncates the destination file to
		 * zero length on upload failure, since we can't trust the
		 * server not to have reordered replies that could have
		 * inserted holes where none existed in the source file.
		 *
		 * XXX we could get a more accurate progress bar if we updated
		 * the counter based on the reply from the destination...
		 */
		(*nreqsp)--;
	}
	debug3_f("done: %u outstanding replies", *nreqsp);
	sshbuf_free(ಸಂದೇಶ);
}

ಪೂರ್ಣಾಙ್ಕ
sftp_crossload(ಸಂರಚನಾ sftp_conn *from, ಸಂರಚನಾ sftp_conn *to,
    ಧ್ರುವ ವರ್ಣ *from_path, ಧ್ರುವ ವರ್ಣ *to_path,
    Attrib *a, ಪೂರ್ಣಾಙ್ಕ preserve_flag)
{
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;
	ಪೂರ್ಣಾಙ್ಕ write_error, read_error, r, seen_zerolen = 0;
	uint64_t offset = 0, size;
	u_int id, buflen, ಅಂಕೆ_req, max_req, status = SSH2_FX_OK;
	u_int ಅಂಕೆ_upload_req;
	off_t progress_counter;
	u_char *from_handle, *to_handle;
	size_t from_handle_len, to_handle_len;
	ಸಂರಚನಾ requests requests;
	ಸಂರಚನಾ request *req;
	u_char type;
	Attrib attr;

	debug2_f("crossload src \"%s\" to dst \"%s\"", from_path, to_path);

	TAILQ_INIT(&requests);

	ಯದಿ (a == ರಿಕ್ತ) {
		ಯದಿ (sftp_stat(from, from_path, 0, &attr) != 0)
			ಪ್ರತ್ಯಾಗಮ -1;
		a = &attr;
	}

	ಯದಿ ((a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) &&
	    (!S_ISREG(a->perm))) {
		error("download \"%s\": not a regular file", from_path);
		ಪ್ರತ್ಯಾಗಮ(-1);
	}
	ಯದಿ (a->flags & SSH2_FILEXFER_ATTR_SIZE)
		size = a->size;
	ಅನ್ಯಥಾ
		size = 0;

	buflen = from->download_buflen;
	ಯದಿ (buflen > to->upload_buflen)
		buflen = to->upload_buflen;

	/* Send open request to read side */
	ಯದಿ (send_open(from, from_path, "origin", SSH2_FXF_READ, ರಿಕ್ತ,
	    &from_handle, &from_handle_len) != 0)
		ಪ್ರತ್ಯಾಗಮ -1;

	/* Send open request to write side */
	a->flags &= ~SSH2_FILEXFER_ATTR_SIZE;
	a->flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a->perm &= 0777;
	ಯದಿ (!preserve_flag)
		a->flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;
	ಯದಿ (send_open(to, to_path, "dest",
	    SSH2_FXF_WRITE|SSH2_FXF_CREAT|SSH2_FXF_TRUNC, a,
	    &to_handle, &to_handle_len) != 0) {
		sftp_close(from, from_handle, from_handle_len);
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	/* Read from remote "from" and write to remote "to" */
	offset = 0;
	write_error = read_error = ಅಂಕೆ_req = ಅಂಕೆ_upload_req = 0;
	max_req = 1;
	progress_counter = 0;

	ಯದಿ (showprogress && size != 0) {
		start_progress_meter(progress_meter_path(from_path),
		    size, &progress_counter);
	}
	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯಾವತ್ (ಅಂಕೆ_req > 0 || max_req > 0) {
		u_char *data;
		size_t len;

		/*
		 * Simulate EOF on interrupt: stop sending new requests and
		 * allow outstanding requests to drain gracefully
		 */
		ಯದಿ (interrupted) {
			ಯದಿ (ಅಂಕೆ_req == 0) /* If we haven't started yet... */
				ಭಙ್ಗ;
			max_req = 0;
		}

		/* Send some more requests */
		ಯಾವತ್ (ಅಂಕೆ_req < max_req) {
			debug3("Request range %llu -> %llu (%d/%d)",
			    (unsigned long long)offset,
			    (unsigned long long)offset + buflen - 1,
			    ಅಂಕೆ_req, max_req);
			req = request_enqueue(&requests, from->ಸಂದೇಶ_id++,
			    buflen, offset);
			offset += buflen;
			ಅಂಕೆ_req++;
			send_read_request(from, req->id, req->offset,
			    req->len, from_handle, from_handle_len);
		}

		/* Try to eat replies from the upload side (nonblocking) */
		handle_dest_replies(to, to_path, 0,
		    &ಅಂಕೆ_upload_req, &write_error);

		sshbuf_reset(ಸಂದೇಶ);
		get_ಸಂದೇಶ(from, ಸಂದೇಶ);
		ಯದಿ ((r = sshbuf_get_u8(ಸಂದೇಶ, &type)) != 0 ||
		    (r = sshbuf_get_u32(ಸಂದೇಶ, &id)) != 0)
			fatal_fr(r, "parse");
		debug3("Received origin reply T:%u I:%u R:%d",
		    type, id, max_req);

		/* Find the request in our queue */
		ಯದಿ ((req = request_find(&requests, id)) == ರಿಕ್ತ)
			fatal("Unexpected reply %u", id);

		ವಿಕಲ್ಪ (type) {
		ಪಕ್ಷ SSH2_FXP_STATUS:
			ಯದಿ ((r = sshbuf_get_u32(ಸಂದೇಶ, &status)) != 0)
				fatal_fr(r, "parse status");
			ಯದಿ (status != SSH2_FX_EOF)
				read_error = 1;
			max_req = 0;
			TAILQ_REMOVE(&requests, req, tq);
			ಮುಕ್ತ(req);
			ಅಂಕೆ_req--;
			ಭಙ್ಗ;
		ಪಕ್ಷ SSH2_FXP_DATA:
			ಯದಿ ((r = sshbuf_get_string(ಸಂದೇಶ, &data, &len)) != 0)
				fatal_fr(r, "parse data");
			debug3("Received data %llu -> %llu",
			    (unsigned long long)req->offset,
			    (unsigned long long)req->offset + len - 1);
			ಯದಿ (len > req->len)
				fatal("Received more data than asked for "
				    "%zu > %zu", len, req->len);
			ಯದಿ (len == 0) {
				ಯದಿ (seen_zerolen)
					fatal_f("server sent zero data length");
				seen_zerolen = 1;
			}

			/* Write this chunk out to the destination */
			sshbuf_reset(ಸಂದೇಶ);
			ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_WRITE)) != 0 ||
			    (r = sshbuf_put_u32(ಸಂದೇಶ, to->ಸಂದೇಶ_id++)) != 0 ||
			    (r = sshbuf_put_string(ಸಂದೇಶ, to_handle,
			    to_handle_len)) != 0 ||
			    (r = sshbuf_put_u64(ಸಂದೇಶ, req->offset)) != 0 ||
			    (r = sshbuf_put_string(ಸಂದೇಶ, data, len)) != 0)
				fatal_fr(r, "compose write");
			send_ಸಂದೇಶ(to, ಸಂದೇಶ);
			debug3("Sent message SSH2_FXP_WRITE I:%u O:%llu S:%zu",
			    id, (unsigned long long)offset, len);
			ಅಂಕೆ_upload_req++;
			progress_counter += len;
			ಮುಕ್ತ(data);

			ಯದಿ (len == req->len) {
				TAILQ_REMOVE(&requests, req, tq);
				ಮುಕ್ತ(req);
				ಅಂಕೆ_req--;
			} ಅನ್ಯಥಾ {
				/* Resend the request for the missing data */
				debug3("Short data block, re-requesting "
				    "%llu -> %llu (%2d)",
				    (unsigned long long)req->offset + len,
				    (unsigned long long)req->offset +
				    req->len - 1, ಅಂಕೆ_req);
				req->id = from->ಸಂದೇಶ_id++;
				req->len -= len;
				req->offset += len;
				send_read_request(from, req->id,
				    req->offset, req->len,
				    from_handle, from_handle_len);
				/* Reduce the request size */
				ಯದಿ (len < buflen)
					buflen = MAXIMUM(MIN_READ_SIZE, len);
			}
			ಯದಿ (max_req > 0) { /* max_req = 0 iff EOF received */
				ಯದಿ (size > 0 && offset > size) {
					/* Only one request at a time
					 * after the expected EOF */
					debug3("Finish at %llu (%2d)",
					    (unsigned long long)offset,
					    ಅಂಕೆ_req);
					max_req = 1;
				} ಅನ್ಯಥಾ ಯದಿ (max_req < from->ಅಂಕೆ_requests) {
					++max_req;
				}
			}
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			fatal("Expected SSH2_FXP_DATA(%u) packet, got %u",
			    SSH2_FXP_DATA, type);
		}
	}

	ಯದಿ (showprogress && size)
		stop_progress_meter();

	/* Drain replies from the server (blocking) */
	debug3_f("waiting for %u replies from destination", ಅಂಕೆ_upload_req);
	handle_dest_replies(to, to_path, 1, &ಅಂಕೆ_upload_req, &write_error);

	/* Sanity check */
	ಯದಿ (TAILQ_FIRST(&requests) != ರಿಕ್ತ)
		fatal("Transfer complete, but requests still in queue");
	/* Truncate at 0 length on interrupt or error to avoid holes at dest */
	ಯದಿ (read_error || write_error || interrupted) {
		debug("truncating \"%s\" at 0", to_path);
		sftp_close(to, to_handle, to_handle_len);
		ಮುಕ್ತ(to_handle);
		ಯದಿ (send_open(to, to_path, "dest",
		    SSH2_FXF_WRITE|SSH2_FXF_CREAT|SSH2_FXF_TRUNC, a,
		    &to_handle, &to_handle_len) != 0) {
			error("dest truncate \"%s\" failed", to_path);
			to_handle = ರಿಕ್ತ;
		}
	}
	ಯದಿ (read_error) {
		error("read origin \"%s\": %s", from_path, fx2txt(status));
		status = -1;
		sftp_close(from, from_handle, from_handle_len);
		ಯದಿ (to_handle != ರಿಕ್ತ)
			sftp_close(to, to_handle, to_handle_len);
	} ಅನ್ಯಥಾ ಯದಿ (write_error) {
		error("write dest \"%s\": %s", to_path, fx2txt(write_error));
		status = SSH2_FX_FAILURE;
		sftp_close(from, from_handle, from_handle_len);
		ಯದಿ (to_handle != ರಿಕ್ತ)
			sftp_close(to, to_handle, to_handle_len);
	} ಅನ್ಯಥಾ {
		ಯದಿ (sftp_close(from, from_handle, from_handle_len) != 0 ||
		    interrupted)
			status = -1;
		ಅನ್ಯಥಾ
			status = SSH2_FX_OK;
		ಯದಿ (to_handle != ರಿಕ್ತ) {
			/* Need to resend utimes after write */
			ಯದಿ (preserve_flag)
				sftp_fsetstat(to, to_handle, to_handle_len, a);
			sftp_close(to, to_handle, to_handle_len);
		}
	}
	sshbuf_free(ಸಂದೇಶ);
	ಮುಕ್ತ(from_handle);
	ಮುಕ್ತ(to_handle);

	ಪ್ರತ್ಯಾಗಮ status == SSH2_FX_OK ? 0 : -1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
crossload_dir_internal(ಸಂರಚನಾ sftp_conn *from, ಸಂರಚನಾ sftp_conn *to,
    ಧ್ರುವ ವರ್ಣ *from_path, ಧ್ರುವ ವರ್ಣ *to_path,
    ಪೂರ್ಣಾಙ್ಕ depth, Attrib *dirattrib, ಪೂರ್ಣಾಙ್ಕ preserve_flag, ಪೂರ್ಣಾಙ್ಕ print_flag,
    ಪೂರ್ಣಾಙ್ಕ follow_link_flag)
{
	ಪೂರ್ಣಾಙ್ಕ i, ret = 0, created = 0;
	SFTP_DIRENT **dir_entries;
	ವರ್ಣ *filename, *new_from_path = ರಿಕ್ತ, *new_to_path = ರಿಕ್ತ;
	mode_t mode = 0777;
	Attrib *a, curdir, ldirattrib, newdir, lsym;

	debug2_f("crossload dir src \"%s\" to dst \"%s\"", from_path, to_path);

	ಯದಿ (depth >= MAX_DIR_DEPTH) {
		error("Maximum directory depth exceeded: %d levels", depth);
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	ಯದಿ (dirattrib == ರಿಕ್ತ) {
		ಯದಿ (sftp_stat(from, from_path, 1, &ldirattrib) != 0) {
			error("stat remote \"%s\" failed", from_path);
			ಪ್ರತ್ಯಾಗಮ -1;
		}
		dirattrib = &ldirattrib;
	}
	ಯದಿ (!S_ISDIR(dirattrib->perm)) {
		error("\"%s\" is not a directory", from_path);
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯದಿ (print_flag && print_flag != SFTP_PROGRESS_ONLY)
		mprintf("Retrieving %s\n", from_path);

	curdir = *dirattrib; /* dirattrib will be clobbered */
	curdir.flags &= ~SSH2_FILEXFER_ATTR_SIZE;
	curdir.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	ಯದಿ ((curdir.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) == 0) {
		debug("Origin did not send permissions for "
		    "directory \"%s\"", to_path);
		curdir.perm = S_IWUSR|S_IXUSR;
		curdir.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
	}
	/* We need to be able to write to the directory while we transfer it */
	mode = curdir.perm & 01777;
	curdir.perm = mode | (S_IWUSR|S_IXUSR);

	/*
	 * sftp lacks a portable status value to match errno EEXIST,
	 * so if we get a failure back then we must check whether
	 * the path already existed and is a directory.  Ensure we can
	 * write to the directory we create for the duration of the transfer.
	 */
	ಯದಿ (sftp_mkdir(to, to_path, &curdir, 0) == 0)
		created = 1;
	ಅನ್ಯಥಾ {
		ಯದಿ (sftp_stat(to, to_path, 0, &newdir) != 0)
			ಪ್ರತ್ಯಾಗಮ -1;
		ಯದಿ (!S_ISDIR(newdir.perm)) {
			error("\"%s\" exists but is not a directory", to_path);
			ಪ್ರತ್ಯಾಗಮ -1;
		}
	}
	curdir.perm = mode;

	ಯದಿ (sftp_readdir(from, from_path, &dir_entries) == -1) {
		error("origin readdir \"%s\" failed", from_path);
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	ಪ್ರತಿ (i = 0; dir_entries[i] != ರಿಕ್ತ && !interrupted; i++) {
		ಮುಕ್ತ(new_from_path);
		ಮುಕ್ತ(new_to_path);

		filename = dir_entries[i]->filename;
		new_from_path = sftp_path_append(from_path, filename);
		new_to_path = sftp_path_append(to_path, filename);

		a = &dir_entries[i]->a;
		ಯದಿ (S_ISLNK(a->perm)) {
			ಯದಿ (!follow_link_flag) {
				logit("%s: not a regular file", filename);
				ಅನುವರ್ತ;
			}
			/* Replace the stat contents with the symlink target */
			ಯದಿ (sftp_stat(from, new_from_path, 1, &lsym) != 0) {
				logit("remote stat \"%s\" failed",
				    new_from_path);
				ret = -1;
				ಅನುವರ್ತ;
			}
			a = &lsym;
		}
		ಯದಿ (S_ISDIR(a->perm)) {
			ಯದಿ (strcmp(filename, ".") == 0 ||
			    strcmp(filename, "..") == 0)
				ಅನುವರ್ತ;
			ಯದಿ (crossload_dir_internal(from, to,
			    new_from_path, new_to_path,
			    depth + 1, a, preserve_flag,
			    print_flag, follow_link_flag) == -1)
				ret = -1;
		} ಅನ್ಯಥಾ ಯದಿ (S_ISREG(a->perm)) {
			ಯದಿ (sftp_crossload(from, to, new_from_path,
			    new_to_path, a, preserve_flag) == -1) {
				error("crossload \"%s\" to \"%s\" failed",
				    new_from_path, new_to_path);
				ret = -1;
			}
		} ಅನ್ಯಥಾ {
			logit("origin \"%s\": not a regular file",
			    new_from_path);
		}
	}
	ಮುಕ್ತ(new_to_path);
	ಮುಕ್ತ(new_from_path);

	ಯದಿ (created || preserve_flag)
		sftp_setstat(to, to_path, &curdir);

	sftp_free_dirents(dir_entries);

	ಪ್ರತ್ಯಾಗಮ ret;
}

ಪೂರ್ಣಾಙ್ಕ
sftp_crossload_dir(ಸಂರಚನಾ sftp_conn *from, ಸಂರಚನಾ sftp_conn *to,
    ಧ್ರುವ ವರ್ಣ *from_path, ಧ್ರುವ ವರ್ಣ *to_path,
    Attrib *dirattrib, ಪೂರ್ಣಾಙ್ಕ preserve_flag, ಪೂರ್ಣಾಙ್ಕ print_flag, ಪೂರ್ಣಾಙ್ಕ follow_link_flag)
{
	ವರ್ಣ *from_path_canon;
	ಪೂರ್ಣಾಙ್ಕ ret;

	ಯದಿ ((from_path_canon = sftp_realpath(from, from_path)) == ರಿಕ್ತ) {
		error("crossload \"%s\": path canonicalization failed",
		    from_path);
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	ret = crossload_dir_internal(from, to, from_path_canon, to_path, 0,
	    dirattrib, preserve_flag, print_flag, follow_link_flag);
	ಮುಕ್ತ(from_path_canon);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಪೂರ್ಣಾಙ್ಕ
sftp_can_get_users_groups_by_id(ಸಂರಚನಾ sftp_conn *conn)
{
	ಪ್ರತ್ಯಾಗಮ (conn->exts & SFTP_EXT_GETUSERSGROUPS_BY_ID) != 0;
}

ಪೂರ್ಣಾಙ್ಕ
sftp_get_users_groups_by_id(ಸಂರಚನಾ sftp_conn *conn,
    ಧ್ರುವ u_int *uids, u_int nuids,
    ಧ್ರುವ u_int *gids, u_int ngids,
    ವರ್ಣ ***usernamesp, ವರ್ಣ ***groupnamesp)
{
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ, *uidbuf, *gidbuf;
	u_int i, expected_id, id;
	ವರ್ಣ *name, **usernames = ರಿಕ್ತ, **groupnames = ರಿಕ್ತ;
	u_char type;
	ಪೂರ್ಣಾಙ್ಕ r;

	*usernamesp = *groupnamesp = ರಿಕ್ತ;
	ಯದಿ (!sftp_can_get_users_groups_by_id(conn))
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_FEATURE_UNSUPPORTED;

	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ ||
	    (uidbuf = sshbuf_new()) == ರಿಕ್ತ ||
	    (gidbuf = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	expected_id = id = conn->ಸಂದೇಶ_id++;
	debug2("Sending SSH2_FXP_EXTENDED(users-groups-by-id@openssh.com)");
	ಪ್ರತಿ (i = 0; i < nuids; i++) {
		ಯದಿ ((r = sshbuf_put_u32(uidbuf, uids[i])) != 0)
			fatal_fr(r, "compose uids");
	}
	ಪ್ರತಿ (i = 0; i < ngids; i++) {
		ಯದಿ ((r = sshbuf_put_u32(gidbuf, gids[i])) != 0)
			fatal_fr(r, "compose gids");
	}
	ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ,
	    "users-groups-by-id@openssh.com")) != 0 ||
	    (r = sshbuf_put_stringb(ಸಂದೇಶ, uidbuf)) != 0 ||
	    (r = sshbuf_put_stringb(ಸಂದೇಶ, gidbuf)) != 0)
		fatal_fr(r, "compose");
	send_ಸಂದೇಶ(conn, ಸಂದೇಶ);
	get_ಸಂದೇಶ(conn, ಸಂದೇಶ);
	ಯದಿ ((r = sshbuf_get_u8(ಸಂದೇಶ, &type)) != 0 ||
	    (r = sshbuf_get_u32(ಸಂದೇಶ, &id)) != 0)
		fatal_fr(r, "parse");
	ಯದಿ (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	ಯದಿ (type == SSH2_FXP_STATUS) {
		u_int status;
		ವರ್ಣ *errmsg;

		ಯದಿ ((r = sshbuf_get_u32(ಸಂದೇಶ, &status)) != 0 ||
		    (r = sshbuf_get_cstring(ಸಂದೇಶ, &errmsg, ರಿಕ್ತ)) != 0)
			fatal_fr(r, "parse status");
		error("users-groups-by-id %s",
		    *errmsg == '\0' ? fx2txt(status) : errmsg);
		ಮುಕ್ತ(errmsg);
		sshbuf_free(ಸಂದೇಶ);
		sshbuf_free(uidbuf);
		sshbuf_free(gidbuf);
		ಪ್ರತ್ಯಾಗಮ -1;
	} ಅನ್ಯಥಾ ಯದಿ (type != SSH2_FXP_EXTENDED_REPLY)
		fatal("Expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_REPLY, type);

	/* reuse */
	sshbuf_free(uidbuf);
	sshbuf_free(gidbuf);
	uidbuf = gidbuf = ರಿಕ್ತ;
	ಯದಿ ((r = sshbuf_froms(ಸಂದೇಶ, &uidbuf)) != 0 ||
	    (r = sshbuf_froms(ಸಂದೇಶ, &gidbuf)) != 0)
		fatal_fr(r, "parse response");
	ಯದಿ (nuids > 0) {
		usernames = xcalloc(nuids, ಪರಿಮಾಣ(*usernames));
		ಪ್ರತಿ (i = 0; i < nuids; i++) {
			ಯದಿ ((r = sshbuf_get_cstring(uidbuf, &name, ರಿಕ್ತ)) != 0)
				fatal_fr(r, "parse user name");
			/* Handle unresolved names */
			ಯದಿ (*name == '\0') {
				ಮುಕ್ತ(name);
				name = ರಿಕ್ತ;
			}
			usernames[i] = name;
		}
	}
	ಯದಿ (ngids > 0) {
		groupnames = xcalloc(ngids, ಪರಿಮಾಣ(*groupnames));
		ಪ್ರತಿ (i = 0; i < ngids; i++) {
			ಯದಿ ((r = sshbuf_get_cstring(gidbuf, &name, ರಿಕ್ತ)) != 0)
				fatal_fr(r, "parse user name");
			/* Handle unresolved names */
			ಯದಿ (*name == '\0') {
				ಮುಕ್ತ(name);
				name = ರಿಕ್ತ;
			}
			groupnames[i] = name;
		}
	}
	ಯದಿ (sshbuf_len(uidbuf) != 0)
		fatal_f("unexpected extra username data");
	ಯದಿ (sshbuf_len(gidbuf) != 0)
		fatal_f("unexpected extra groupname data");
	sshbuf_free(uidbuf);
	sshbuf_free(gidbuf);
	sshbuf_free(ಸಂದೇಶ);
	/* success */
	*usernamesp = usernames;
	*groupnamesp = groupnames;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ವರ್ಣ *
sftp_path_append(ಧ್ರುವ ವರ್ಣ *p1, ಧ್ರುವ ವರ್ಣ *p2)
{
	ವರ್ಣ *ret;
	size_t len = strlen(p1) + strlen(p2) + 2;

	ret = xmalloc(len);
	strlcpy(ret, p1, len);
	ಯದಿ (p1[0] != '\0' && p1[strlen(p1) - 1] != '/')
		strlcat(ret, "/", len);
	strlcat(ret, p2, len);

	ಪ್ರತ್ಯಾಗಮ(ret);
}

/*
 * Arg p must be dynamically allocated.  It will either be returned or
 * freed and a replacement allocated.  Caller must free returned string.
 */
ವರ್ಣ *
sftp_make_absolute(ವರ್ಣ *p, ಧ್ರುವ ವರ್ಣ *pwd)
{
	ವರ್ಣ *abs_str;

	/* Derelativise */
	ಯದಿ (p && !path_absolute(p)) {
		abs_str = sftp_path_append(pwd, p);
		ಮುಕ್ತ(p);
		ಪ್ರತ್ಯಾಗಮ(abs_str);
	} ಅನ್ಯಥಾ
		ಪ್ರತ್ಯಾಗಮ(p);
}

ಪೂರ್ಣಾಙ್ಕ
sftp_remote_is_dir(ಸಂರಚನಾ sftp_conn *conn, ಧ್ರುವ ವರ್ಣ *path)
{
	Attrib a;

	/* XXX: report errors? */
	ಯದಿ (sftp_stat(conn, path, 1, &a) != 0)
		ಪ್ರತ್ಯಾಗಮ(0);
	ಯದಿ (!(a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS))
		ಪ್ರತ್ಯಾಗಮ(0);
	ಪ್ರತ್ಯಾಗಮ S_ISDIR(a.perm);
}


/* Check whether path returned from glob(..., GLOB_MARK, ...) is a directory */
ಪೂರ್ಣಾಙ್ಕ
sftp_globpath_is_dir(ಧ್ರುವ ವರ್ಣ *pathname)
{
	size_t l = strlen(pathname);

	ಪ್ರತ್ಯಾಗಮ l > 0 && pathname[l - 1] == '/';
}

