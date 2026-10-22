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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/queue.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/stat.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/time.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/statvfs.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/uio.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <dirent.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <poll.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "atomicio.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "progressmeter.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "utf8.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "sftp.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sftp-common.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sftp-client.h"

ਬਾਹਰੀ ਅਸਥਿਰ sig_atomic_t interrupted;
ਬਾਹਰੀ ਪੂਰਨ showprogress;

/* Default size of buffer for up/download (fix sftp.1 scp.1 if changed) */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DEFAULT_COPY_BUFLEN	32768

/* Default number of concurrent xfer requests (fix sftp.1 scp.1 if changed) */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DEFAULT_ਅੰਕ_ਬੇਨਤੀਆਂ	64

/* Minimum amount of data to read at a time */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MIN_READ_ਮਾਪ	512

/* Maximum depth to descend in directory trees */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MAX_DIR_ਡੂੰਘਾਈ 64

/* Directory separator characters */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_CYGWIN
# define SFTP_DIRECTORY_CHARS      "/\\"
#ਨਹੀਂਤਾਂ /* HAVE_CYGWIN */
# define SFTP_DIRECTORY_CHARS      "/"
#ਜੇ_ਅੰਤ /* HAVE_CYGWIN */

ਬਣਤਰ sftp_conn {
	ਪੂਰਨ fd_ਵਿੱਚ;
	ਪੂਰਨ fd_ਬਾਹਰਲਾ;
	u_int download_buflen;
	u_int upload_buflen;
	u_int ਅੰਕ_ਬੇਨਤੀਆਂ;
	u_int ਸੰਸਕਰਣ;
	u_int ਸੁਨੇਹਾ_id;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SFTP_EXT_POSIX_RENAME		0x00000001
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SFTP_EXT_STATVFS		0x00000002
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SFTP_EXT_FSTATVFS		0x00000004
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SFTP_EXT_HARDLINK		0x00000008
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SFTP_EXT_FSYNC			0x00000010
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SFTP_EXT_LSETSTAT		0x00000020
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SFTP_EXT_LIMITS			0x00000040
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SFTP_EXT_ਰਸਤਾ_EXPAND		0x00000080
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SFTP_EXT_COPY_ਅੰਕੜੇ		0x00000100
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SFTP_EXT_GETUSERSGROUPS_BY_ID	0x00000200
	u_int exts;
	uint64_t ਹੱਦਬੰਦੀ_kbps;
	ਬਣਤਰ bwlimit bwlimit_ਵਿੱਚ, bwlimit_ਬਾਹਰਲਾ;
};

/* Tracks in-progress requests during file transfers */
ਬਣਤਰ request {
	u_int id;
	ਮਾਪ_t len;
	uint64_t ਵਿੱਥ;
	TAILQ_ENTRY(request) tq;
};
TAILQ_HEAD(ਬੇਨਤੀਆਂ, request);

ਸਥਿਰ u_char *
get_handle(ਬਣਤਰ sftp_conn *conn, u_int expected_id, ਮਾਪ_t *len,
    ਅਚਲ ਅੱਖਰ *errfmt, ...) __attribute__((format(ਲਿਖੋ, 4, 5)));

ਸਥਿਰ ਬਣਤਰ request *
request_ਕਤਾਰ_ਵਿੱਚ_ਪਾਓ(ਬਣਤਰ ਬੇਨਤੀਆਂ *ਬੇਨਤੀਆਂ, u_int id, ਮਾਪ_t len,
    uint64_t ਵਿੱਥ)
{
	ਬਣਤਰ request *req;

	req = xcalloc(1, ਆਕਾਰ(*req));
	req->id = id;
	req->len = len;
	req->ਵਿੱਥ = ਵਿੱਥ;
	TAILQ_INSERT_TAIL(ਬੇਨਤੀਆਂ, req, tq);
	ਵਾਪਸ req;
}

ਸਥਿਰ ਬਣਤਰ request *
request_ਲੱਭੋ(ਬਣਤਰ ਬੇਨਤੀਆਂ *ਬੇਨਤੀਆਂ, u_int id)
{
	ਬਣਤਰ request *req;

	ਲਈ (req = TAILQ_FIRST(ਬੇਨਤੀਆਂ);
	    req != ਨਿਰਾ && req->id != id;
	    req = TAILQ_NEXT(req, tq))
		;
	ਵਾਪਸ req;
}

ਸਥਿਰ ਪੂਰਨ
sftpio(ਖਾਲੀ *_bwlimit, ਮਾਪ_t amount)
{
	ਬਣਤਰ bwlimit *bwlimit = (ਬਣਤਰ bwlimit *)_bwlimit;

	refresh_ਤਰੱਕੀ_meter(0);
	ਜੇ (bwlimit != ਨਿਰਾ)
		bandwidth_ਹੱਦਬੰਦੀ(bwlimit, amount);
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਖਾਲੀ
send_ਸੁਨੇਹਾ(ਬਣਤਰ sftp_conn *conn, ਬਣਤਰ sshbuf *m)
{
	u_char mlen[4];
	ਬਣਤਰ iovec iov[2];

	ਜੇ (sshbuf_len(m) > SFTP_MAX_ਸੁਨੇਹਾ_ਲੰਮਾਈ)
		fatal("Outbound message too long %zu", sshbuf_len(m));

	/* Send length first */
	put_u32(mlen, sshbuf_len(m));
	iov[0].iov_base = mlen;
	iov[0].iov_len = ਆਕਾਰ(mlen);
	iov[1].iov_base = (u_char *)sshbuf_ptr(m);
	iov[1].iov_len = sshbuf_len(m);

	ਜੇ (atomiciov6(writev, conn->fd_ਬਾਹਰਲਾ, iov, 2, sftpio,
	    conn->ਹੱਦਬੰਦੀ_kbps > 0 ? &conn->bwlimit_ਬਾਹਰਲਾ : ਨਿਰਾ) !=
	    sshbuf_len(m) + ਆਕਾਰ(mlen))
		fatal("Couldn't send packet: %s", strerror(errno));

	sshbuf_reset(m);
}

ਸਥਿਰ ਖਾਲੀ
get_ਸੁਨੇਹਾ_extended(ਬਣਤਰ sftp_conn *conn, ਬਣਤਰ sshbuf *m, ਪੂਰਨ initial)
{
	u_int ਸੁਨੇਹਾ_len;
	u_char *p;
	ਪੂਰਨ r;

	sshbuf_reset(m);
	ਜੇ ((r = sshbuf_reserve(m, 4, &p)) != 0)
		fatal_fr(r, "reserve");
	ਜੇ (atomicio6(ਪਠ, conn->fd_ਵਿੱਚ, p, 4, sftpio,
	    conn->ਹੱਦਬੰਦੀ_kbps > 0 ? &conn->bwlimit_ਵਿੱਚ : ਨਿਰਾ) != 4) {
		ਜੇ (errno == EPIPE || errno == ECONNRESET)
			fatal("Connection closed");
		ਨਹੀਂਤਾਂ
			fatal("Couldn't read packet: %s", strerror(errno));
	}

	ਜੇ ((r = sshbuf_get_u32(m, &ਸੁਨੇਹਾ_len)) != 0)
		fatal_fr(r, "sshbuf_get_u32");
	ਜੇ (ਸੁਨੇਹਾ_len > SFTP_MAX_ਸੁਨੇਹਾ_ਲੰਮਾਈ) {
		do_log2(initial ? SYSLOG_LEVEL_ERROR : SYSLOG_LEVEL_FATAL,
		    "Received message too long %u", ਸੁਨੇਹਾ_len);
		fatal("Ensure the remote shell produces no output "
		    "for non-interactive sessions.");
	}

	ਜੇ ((r = sshbuf_reserve(m, ਸੁਨੇਹਾ_len, &p)) != 0)
		fatal_fr(r, "reserve");
	ਜੇ (atomicio6(ਪਠ, conn->fd_ਵਿੱਚ, p, ਸੁਨੇਹਾ_len, sftpio,
	    conn->ਹੱਦਬੰਦੀ_kbps > 0 ? &conn->bwlimit_ਵਿੱਚ : ਨਿਰਾ)
	    != ਸੁਨੇਹਾ_len) {
		ਜੇ (errno == EPIPE)
			fatal("Connection closed");
		ਨਹੀਂਤਾਂ
			fatal("Read packet: %s", strerror(errno));
	}
}

ਸਥਿਰ ਖਾਲੀ
get_ਸੁਨੇਹਾ(ਬਣਤਰ sftp_conn *conn, ਬਣਤਰ sshbuf *m)
{
	get_ਸੁਨੇਹਾ_extended(conn, m, 0);
}

ਸਥਿਰ ਖਾਲੀ
send_string_request(ਬਣਤਰ sftp_conn *conn, u_int id, u_int ਕੋਡ, ਅਚਲ ਅੱਖਰ *s,
    u_int len)
{
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;
	ਪੂਰਨ r;

	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, ਕੋਡ)) != 0 ||
	    (r = sshbuf_put_u32(ਸੁਨੇਹਾ, id)) != 0 ||
	    (r = sshbuf_put_string(ਸੁਨੇਹਾ, s, len)) != 0)
		fatal_fr(r, "compose");
	send_ਸੁਨੇਹਾ(conn, ਸੁਨੇਹਾ);
	debug3("Sent message fd %d T:%u I:%u", conn->fd_ਬਾਹਰਲਾ, ਕੋਡ, id);
	sshbuf_free(ਸੁਨੇਹਾ);
}

ਸਥਿਰ ਖਾਲੀ
send_string_attrs_request(ਬਣਤਰ sftp_conn *conn, u_int id, u_int ਕੋਡ,
    ਅਚਲ ਖਾਲੀ *s, u_int len, Attrib *a)
{
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;
	ਪੂਰਨ r;

	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, ਕੋਡ)) != 0 ||
	    (r = sshbuf_put_u32(ਸੁਨੇਹਾ, id)) != 0 ||
	    (r = sshbuf_put_string(ਸੁਨੇਹਾ, s, len)) != 0 ||
	    (r = encode_attrib(ਸੁਨੇਹਾ, a)) != 0)
		fatal_fr(r, "compose");
	send_ਸੁਨੇਹਾ(conn, ਸੁਨੇਹਾ);
	debug3("Sent message fd %d T:%u I:%u F:0x%04x M:%05o",
	    conn->fd_ਬਾਹਰਲਾ, ਕੋਡ, id, a->flags, a->perm);
	sshbuf_free(ਸੁਨੇਹਾ);
}

ਸਥਿਰ u_int
get_ਸਥਿਤੀ(ਬਣਤਰ sftp_conn *conn, u_int expected_id)
{
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;
	u_char type;
	u_int id, ਸਥਿਤੀ;
	ਪੂਰਨ r;

	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	get_ਸੁਨੇਹਾ(conn, ਸੁਨੇਹਾ);
	ਜੇ ((r = sshbuf_get_u8(ਸੁਨੇਹਾ, &type)) != 0 ||
	    (r = sshbuf_get_u32(ਸੁਨੇਹਾ, &id)) != 0)
		fatal_fr(r, "compose");

	ਜੇ (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	ਜੇ (type != SSH2_FXP_ਸਥਿਤੀ)
		fatal("Expected SSH2_FXP_STATUS(%u) packet, got %u",
		    SSH2_FXP_ਸਥਿਤੀ, type);

	ਜੇ ((r = sshbuf_get_u32(ਸੁਨੇਹਾ, &ਸਥਿਤੀ)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(ਸੁਨੇਹਾ);

	debug3("SSH2_FXP_STATUS %u", ਸਥਿਤੀ);

	ਵਾਪਸ ਸਥਿਤੀ;
}

ਸਥਿਰ u_char *
get_handle(ਬਣਤਰ sftp_conn *conn, u_int expected_id, ਮਾਪ_t *len,
    ਅਚਲ ਅੱਖਰ *errfmt, ...)
{
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;
	u_int id, ਸਥਿਤੀ;
	u_char type;
	u_char *handle;
	ਅੱਖਰ errmsg[256];
	va_list ਦਲੀਲਾਂ;
	ਪੂਰਨ r;

	va_start(ਦਲੀਲਾਂ, errfmt);
	ਜੇ (errfmt != ਨਿਰਾ)
		vsnprintf(errmsg, ਆਕਾਰ(errmsg), errfmt, ਦਲੀਲਾਂ);
	va_end(ਦਲੀਲਾਂ);

	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	get_ਸੁਨੇਹਾ(conn, ਸੁਨੇਹਾ);
	ਜੇ ((r = sshbuf_get_u8(ਸੁਨੇਹਾ, &type)) != 0 ||
	    (r = sshbuf_get_u32(ਸੁਨੇਹਾ, &id)) != 0)
		fatal_fr(r, "parse");

	ਜੇ (id != expected_id)
		fatal("%s: ID mismatch (%u != %u)",
		    errfmt == ਨਿਰਾ ? __func__ : errmsg, id, expected_id);
	ਜੇ (type == SSH2_FXP_ਸਥਿਤੀ) {
		ਜੇ ((r = sshbuf_get_u32(ਸੁਨੇਹਾ, &ਸਥਿਤੀ)) != 0)
			fatal_fr(r, "parse status");
		ਜੇ (errfmt != ਨਿਰਾ)
			error("%s: %s", errmsg, fx2txt(ਸਥਿਤੀ));
		sshbuf_free(ਸੁਨੇਹਾ);
		ਵਾਪਸ(ਨਿਰਾ);
	} ਨਹੀਂਤਾਂ ਜੇ (type != SSH2_FXP_HANDLE)
		fatal("%s: Expected SSH2_FXP_HANDLE(%u) packet, got %u",
		    errfmt == ਨਿਰਾ ? __func__ : errmsg, SSH2_FXP_HANDLE, type);

	ਜੇ ((r = sshbuf_get_string(ਸੁਨੇਹਾ, &handle, len)) != 0)
		fatal_fr(r, "parse handle");
	sshbuf_free(ਸੁਨੇਹਾ);

	ਵਾਪਸ handle;
}

ਸਥਿਰ ਪੂਰਨ
get_decode_stat(ਬਣਤਰ sftp_conn *conn, u_int expected_id, ਪੂਰਨ quiet, Attrib *a)
{
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;
	u_int id;
	u_char type;
	ਪੂਰਨ r;
	Attrib attr;

	ਜੇ (a != ਨਿਰਾ)
		memset(a, '\0', ਆਕਾਰ(*a));
	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	get_ਸੁਨੇਹਾ(conn, ਸੁਨੇਹਾ);

	ਜੇ ((r = sshbuf_get_u8(ਸੁਨੇਹਾ, &type)) != 0 ||
	    (r = sshbuf_get_u32(ਸੁਨੇਹਾ, &id)) != 0)
		fatal_fr(r, "parse");

	ਜੇ (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	ਜੇ (type == SSH2_FXP_ਸਥਿਤੀ) {
		u_int ਸਥਿਤੀ;

		ਜੇ ((r = sshbuf_get_u32(ਸੁਨੇਹਾ, &ਸਥਿਤੀ)) != 0)
			fatal_fr(r, "parse status");
		ਜੇ (quiet)
			debug("stat remote: %s", fx2txt(ਸਥਿਤੀ));
		ਨਹੀਂਤਾਂ
			error("stat remote: %s", fx2txt(ਸਥਿਤੀ));
		sshbuf_free(ਸੁਨੇਹਾ);
		ਵਾਪਸ -1;
	} ਨਹੀਂਤਾਂ ਜੇ (type != SSH2_FXP_ATTRS) {
		fatal("Expected SSH2_FXP_ATTRS(%u) packet, got %u",
		    SSH2_FXP_ATTRS, type);
	}
	ਜੇ ((r = decode_attrib(ਸੁਨੇਹਾ, &attr)) != 0) {
		error_fr(r, "decode_attrib");
		sshbuf_free(ਸੁਨੇਹਾ);
		ਵਾਪਸ -1;
	}
	/* success */
	ਜੇ (a != ਨਿਰਾ)
		*a = attr;
	debug3("Received stat reply T:%u I:%u F:0x%04x M:%05o",
	    type, id, attr.flags, attr.perm);
	sshbuf_free(ਸੁਨੇਹਾ);

	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
get_decode_statvfs(ਬਣਤਰ sftp_conn *conn, ਬਣਤਰ sftp_statvfs *st,
    u_int expected_id, ਪੂਰਨ quiet)
{
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;
	u_char type;
	u_int id;
	uint64_t flag;
	ਪੂਰਨ r;

	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	get_ਸੁਨੇਹਾ(conn, ਸੁਨੇਹਾ);

	ਜੇ ((r = sshbuf_get_u8(ਸੁਨੇਹਾ, &type)) != 0 ||
	    (r = sshbuf_get_u32(ਸੁਨੇਹਾ, &id)) != 0)
		fatal_fr(r, "parse");

	debug3("Received statvfs reply T:%u I:%u", type, id);
	ਜੇ (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	ਜੇ (type == SSH2_FXP_ਸਥਿਤੀ) {
		u_int ਸਥਿਤੀ;

		ਜੇ ((r = sshbuf_get_u32(ਸੁਨੇਹਾ, &ਸਥਿਤੀ)) != 0)
			fatal_fr(r, "parse status");
		ਜੇ (quiet)
			debug("remote statvfs: %s", fx2txt(ਸਥਿਤੀ));
		ਨਹੀਂਤਾਂ
			error("remote statvfs: %s", fx2txt(ਸਥਿਤੀ));
		sshbuf_free(ਸੁਨੇਹਾ);
		ਵਾਪਸ -1;
	} ਨਹੀਂਤਾਂ ਜੇ (type != SSH2_FXP_EXTENDED_ਜਵਾਬ) {
		fatal("Expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_ਜਵਾਬ, type);
	}

	memset(st, 0, ਆਕਾਰ(*st));
	ਜੇ ((r = sshbuf_get_u64(ਸੁਨੇਹਾ, &st->f_bsize)) != 0 ||
	    (r = sshbuf_get_u64(ਸੁਨੇਹਾ, &st->f_frsize)) != 0 ||
	    (r = sshbuf_get_u64(ਸੁਨੇਹਾ, &st->f_ਖੰਡਾਂ)) != 0 ||
	    (r = sshbuf_get_u64(ਸੁਨੇਹਾ, &st->f_bfree)) != 0 ||
	    (r = sshbuf_get_u64(ਸੁਨੇਹਾ, &st->f_bavail)) != 0 ||
	    (r = sshbuf_get_u64(ਸੁਨੇਹਾ, &st->f_files)) != 0 ||
	    (r = sshbuf_get_u64(ਸੁਨੇਹਾ, &st->f_ffree)) != 0 ||
	    (r = sshbuf_get_u64(ਸੁਨੇਹਾ, &st->f_favail)) != 0 ||
	    (r = sshbuf_get_u64(ਸੁਨੇਹਾ, &st->f_fsid)) != 0 ||
	    (r = sshbuf_get_u64(ਸੁਨੇਹਾ, &flag)) != 0 ||
	    (r = sshbuf_get_u64(ਸੁਨੇਹਾ, &st->f_namemax)) != 0)
		fatal_fr(r, "parse statvfs");

	st->f_flag = (flag & SSH2_FXE_STATVFS_ST_RDONLY) ? ST_RDONLY : 0;
	st->f_flag |= (flag & SSH2_FXE_STATVFS_ST_NOSUID) ? ST_NOSUID : 0;

	sshbuf_free(ਸੁਨੇਹਾ);

	ਵਾਪਸ 0;
}

ਬਣਤਰ sftp_conn *
sftp_init(ਪੂਰਨ fd_ਵਿੱਚ, ਪੂਰਨ fd_ਬਾਹਰਲਾ, u_int transfer_buflen, u_int ਅੰਕ_ਬੇਨਤੀਆਂ,
    uint64_t ਹੱਦਬੰਦੀ_kbps)
{
	u_char type;
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;
	ਬਣਤਰ sftp_conn *ret;
	ਪੂਰਨ r;

	ret = xcalloc(1, ਆਕਾਰ(*ret));
	ret->ਸੁਨੇਹਾ_id = 1;
	ret->fd_ਵਿੱਚ = fd_ਵਿੱਚ;
	ret->fd_ਬਾਹਰਲਾ = fd_ਬਾਹਰਲਾ;
	ret->download_buflen = ret->upload_buflen =
	    transfer_buflen ? transfer_buflen : DEFAULT_COPY_BUFLEN;
	ret->ਅੰਕ_ਬੇਨਤੀਆਂ =
	    ਅੰਕ_ਬੇਨਤੀਆਂ ? ਅੰਕ_ਬੇਨਤੀਆਂ : DEFAULT_ਅੰਕ_ਬੇਨਤੀਆਂ;
	ret->exts = 0;
	ret->ਹੱਦਬੰਦੀ_kbps = 0;

	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, SSH2_FXP_INIT)) != 0 ||
	    (r = sshbuf_put_u32(ਸੁਨੇਹਾ, SSH2_FILEXFER_ਸੰਸਕਰਣ)) != 0)
		fatal_fr(r, "parse");

	send_ਸੁਨੇਹਾ(ret, ਸੁਨੇਹਾ);

	get_ਸੁਨੇਹਾ_extended(ret, ਸੁਨੇਹਾ, 1);

	/* Expecting a VERSION reply */
	ਜੇ ((r = sshbuf_get_u8(ਸੁਨੇਹਾ, &type)) != 0)
		fatal_fr(r, "parse type");
	ਜੇ (type != SSH2_FXP_ਸੰਸਕਰਣ) {
		error("Invalid packet back from SSH2_FXP_INIT (type %u)",
		    type);
		sshbuf_free(ਸੁਨੇਹਾ);
		ਮੁਕਤ(ret);
		ਵਾਪਸ(ਨਿਰਾ);
	}
	ਜੇ ((r = sshbuf_get_u32(ਸੁਨੇਹਾ, &ret->ਸੰਸਕਰਣ)) != 0)
		fatal_fr(r, "parse version");

	debug2("Remote version: %u", ret->ਸੰਸਕਰਣ);

	/* Check for extensions */
	ਜਦੋਂ (sshbuf_len(ਸੁਨੇਹਾ) > 0) {
		ਅੱਖਰ *name;
		u_char *ਮੁੱਲ;
		ਮਾਪ_t vlen;
		ਪੂਰਨ ਗਿਆਤ = 0;

		ਜੇ ((r = sshbuf_get_cstring(ਸੁਨੇਹਾ, &name, ਨਿਰਾ)) != 0 ||
		    (r = sshbuf_get_string(ਸੁਨੇਹਾ, &ਮੁੱਲ, &vlen)) != 0)
			fatal_fr(r, "parse extension");
		ਜੇ (strcmp(name, "posix-rename@openssh.com") == 0 &&
		    strcmp((ਅੱਖਰ *)ਮੁੱਲ, "1") == 0) {
			ret->exts |= SFTP_EXT_POSIX_RENAME;
			ਗਿਆਤ = 1;
		} ਨਹੀਂਤਾਂ ਜੇ (strcmp(name, "statvfs@openssh.com") == 0 &&
		    strcmp((ਅੱਖਰ *)ਮੁੱਲ, "2") == 0) {
			ret->exts |= SFTP_EXT_STATVFS;
			ਗਿਆਤ = 1;
		} ਨਹੀਂਤਾਂ ਜੇ (strcmp(name, "fstatvfs@openssh.com") == 0 &&
		    strcmp((ਅੱਖਰ *)ਮੁੱਲ, "2") == 0) {
			ret->exts |= SFTP_EXT_FSTATVFS;
			ਗਿਆਤ = 1;
		} ਨਹੀਂਤਾਂ ਜੇ (strcmp(name, "hardlink@openssh.com") == 0 &&
		    strcmp((ਅੱਖਰ *)ਮੁੱਲ, "1") == 0) {
			ret->exts |= SFTP_EXT_HARDLINK;
			ਗਿਆਤ = 1;
		} ਨਹੀਂਤਾਂ ਜੇ (strcmp(name, "fsync@openssh.com") == 0 &&
		    strcmp((ਅੱਖਰ *)ਮੁੱਲ, "1") == 0) {
			ret->exts |= SFTP_EXT_FSYNC;
			ਗਿਆਤ = 1;
		} ਨਹੀਂਤਾਂ ਜੇ (strcmp(name, "lsetstat@openssh.com") == 0 &&
		    strcmp((ਅੱਖਰ *)ਮੁੱਲ, "1") == 0) {
			ret->exts |= SFTP_EXT_LSETSTAT;
			ਗਿਆਤ = 1;
		} ਨਹੀਂਤਾਂ ਜੇ (strcmp(name, "limits@openssh.com") == 0 &&
		    strcmp((ਅੱਖਰ *)ਮੁੱਲ, "1") == 0) {
			ret->exts |= SFTP_EXT_LIMITS;
			ਗਿਆਤ = 1;
		} ਨਹੀਂਤਾਂ ਜੇ (strcmp(name, "expand-path@openssh.com") == 0 &&
		    strcmp((ਅੱਖਰ *)ਮੁੱਲ, "1") == 0) {
			ret->exts |= SFTP_EXT_ਰਸਤਾ_EXPAND;
			ਗਿਆਤ = 1;
		} ਨਹੀਂਤਾਂ ਜੇ (strcmp(name, "copy-data") == 0 &&
		    strcmp((ਅੱਖਰ *)ਮੁੱਲ, "1") == 0) {
			ret->exts |= SFTP_EXT_COPY_ਅੰਕੜੇ;
			ਗਿਆਤ = 1;
		} ਨਹੀਂਤਾਂ ਜੇ (strcmp(name,
		    "users-groups-by-id@openssh.com") == 0 &&
		    strcmp((ਅੱਖਰ *)ਮੁੱਲ, "1") == 0) {
			ret->exts |= SFTP_EXT_GETUSERSGROUPS_BY_ID;
			ਗਿਆਤ = 1;
		}
		ਜੇ (ਗਿਆਤ) {
			debug2("Server supports extension \"%s\" revision %s",
			    name, ਮੁੱਲ);
		} ਨਹੀਂਤਾਂ {
			debug2("Unrecognised server extension \"%s\"", name);
		}
		ਮੁਕਤ(name);
		ਮੁਕਤ(ਮੁੱਲ);
	}

	sshbuf_free(ਸੁਨੇਹਾ);

	/* Query the server for its limits */
	ਜੇ (ret->exts & SFTP_EXT_LIMITS) {
		ਬਣਤਰ sftp_limits limits;
		ਜੇ (sftp_get_limits(ret, &limits) != 0)
			fatal_f("limits failed");

		/* If the caller did not specify, find a good value */
		ਜੇ (transfer_buflen == 0) {
			ret->download_buflen = MINIMUM(limits.read_ਲੰਮਾਈ,
			    SFTP_MAX_ਸੁਨੇਹਾ_ਲੰਮਾਈ - 1024);
			ret->upload_buflen = MINIMUM(limits.write_ਲੰਮਾਈ,
			    SFTP_MAX_ਸੁਨੇਹਾ_ਲੰਮਾਈ - 1024);
			ret->download_buflen = ਵੱਧ_ਤੋਂ_ਵੱਧ(ret->download_buflen, 64);
			ret->upload_buflen = ਵੱਧ_ਤੋਂ_ਵੱਧ(ret->upload_buflen, 64);
			debug3("server upload/download buffer sizes "
			    "%llu / %llu; using %u / %u",
			    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)limits.write_ਲੰਮਾਈ,
			    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)limits.read_ਲੰਮਾਈ,
			    ret->upload_buflen, ret->download_buflen);
		}
	}

	/* Some filexfer v.0 servers don't support large packets */
	ਜੇ (ret->ਸੰਸਕਰਣ == 0) {
		ret->download_buflen = MINIMUM(ret->download_buflen, 20480);
		ret->upload_buflen = MINIMUM(ret->upload_buflen, 20480);
	}

	ret->ਹੱਦਬੰਦੀ_kbps = ਹੱਦਬੰਦੀ_kbps;
	ਜੇ (ret->ਹੱਦਬੰਦੀ_kbps > 0) {
		bandwidth_ਹੱਦਬੰਦੀ_init(&ret->bwlimit_ਵਿੱਚ, ret->ਹੱਦਬੰਦੀ_kbps,
		    ret->download_buflen);
		bandwidth_ਹੱਦਬੰਦੀ_init(&ret->bwlimit_ਬਾਹਰਲਾ, ret->ਹੱਦਬੰਦੀ_kbps,
		    ret->upload_buflen);
	}

	ਵਾਪਸ ret;
}

ਖਾਲੀ
sftp_free(ਬਣਤਰ sftp_conn *conn)
{
	ਜੇ (conn == ਨਿਰਾ)
		ਵਾਪਸ;
	freezero(conn, ਆਕਾਰ(*conn));
}

u_int
sftp_proto_ਸੰਸਕਰਣ(ਬਣਤਰ sftp_conn *conn)
{
	ਵਾਪਸ conn->ਸੰਸਕਰਣ;
}

ਪੂਰਨ
sftp_get_limits(ਬਣਤਰ sftp_conn *conn, ਬਣਤਰ sftp_limits *limits)
{
	u_int id, ਸੁਨੇਹਾ_id;
	u_char type;
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;
	ਪੂਰਨ r;

	ਜੇ ((conn->exts & SFTP_EXT_LIMITS) == 0) {
		error("Server does not support limits@openssh.com extension");
		ਵਾਪਸ -1;
	}

	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");

	id = conn->ਸੁਨੇਹਾ_id++;
	ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(ਸੁਨੇਹਾ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ਸੁਨੇਹਾ, "limits@openssh.com")) != 0)
		fatal_fr(r, "compose");
	send_ਸੁਨੇਹਾ(conn, ਸੁਨੇਹਾ);
	debug3("Sent message limits@openssh.com I:%u", id);

	get_ਸੁਨੇਹਾ(conn, ਸੁਨੇਹਾ);

	ਜੇ ((r = sshbuf_get_u8(ਸੁਨੇਹਾ, &type)) != 0 ||
	    (r = sshbuf_get_u32(ਸੁਨੇਹਾ, &ਸੁਨੇਹਾ_id)) != 0)
		fatal_fr(r, "parse");

	debug3("Received limits reply T:%u I:%u", type, ਸੁਨੇਹਾ_id);
	ਜੇ (id != ਸੁਨੇਹਾ_id)
		fatal("ID mismatch (%u != %u)", ਸੁਨੇਹਾ_id, id);
	ਜੇ (type != SSH2_FXP_EXTENDED_ਜਵਾਬ) {
		debug_f("expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_ਜਵਾਬ, type);
		/* Disable the limits extension */
		conn->exts &= ~SFTP_EXT_LIMITS;
		sshbuf_free(ਸੁਨੇਹਾ);
		ਵਾਪਸ -1;
	}

	memset(limits, 0, ਆਕਾਰ(*limits));
	ਜੇ ((r = sshbuf_get_u64(ਸੁਨੇਹਾ, &limits->packet_ਲੰਮਾਈ)) != 0 ||
	    (r = sshbuf_get_u64(ਸੁਨੇਹਾ, &limits->read_ਲੰਮਾਈ)) != 0 ||
	    (r = sshbuf_get_u64(ਸੁਨੇਹਾ, &limits->write_ਲੰਮਾਈ)) != 0 ||
	    (r = sshbuf_get_u64(ਸੁਨੇਹਾ, &limits->open_handles)) != 0)
		fatal_fr(r, "parse limits");

	sshbuf_free(ਸੁਨੇਹਾ);

	ਵਾਪਸ 0;
}

ਪੂਰਨ
sftp_close(ਬਣਤਰ sftp_conn *conn, ਅਚਲ u_char *handle, u_int handle_len)
{
	u_int id, ਸਥਿਤੀ;
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;
	ਪੂਰਨ r;

	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");

	id = conn->ਸੁਨੇਹਾ_id++;
	ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, SSH2_FXP_CLOSE)) != 0 ||
	    (r = sshbuf_put_u32(ਸੁਨੇਹਾ, id)) != 0 ||
	    (r = sshbuf_put_string(ਸੁਨੇਹਾ, handle, handle_len)) != 0)
		fatal_fr(r, "parse");
	send_ਸੁਨੇਹਾ(conn, ਸੁਨੇਹਾ);
	debug3("Sent message SSH2_FXP_CLOSE I:%u", id);

	ਸਥਿਤੀ = get_ਸਥਿਤੀ(conn, id);
	ਜੇ (ਸਥਿਤੀ != SSH2_FX_OK)
		error("close remote: %s", fx2txt(ਸਥਿਤੀ));

	sshbuf_free(ਸੁਨੇਹਾ);

	ਵਾਪਸ ਸਥਿਤੀ == SSH2_FX_OK ? 0 : -1;
}


ਸਥਿਰ ਪੂਰਨ
sftp_lsreaddir(ਬਣਤਰ sftp_conn *conn, ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, ਪੂਰਨ print_flag,
    SFTP_DIRENT ***dir)
{
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;
	u_int ਗਿਣਤੀ_2, id, i, expected_id, ents = 0;
	ਮਾਪ_t handle_len;
	u_char type, *handle;
	ਪੂਰਨ ਸਥਿਤੀ = SSH2_FX_FAILURE;
	ਪੂਰਨ r;

	ਜੇ (dir)
		*dir = ਨਿਰਾ;

	id = conn->ਸੁਨੇਹਾ_id++;

	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, SSH2_FXP_OPENDIR)) != 0 ||
	    (r = sshbuf_put_u32(ਸੁਨੇਹਾ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ਸੁਨੇਹਾ, ਰਸਤਾ)) != 0)
		fatal_fr(r, "compose OPENDIR");
	send_ਸੁਨੇਹਾ(conn, ਸੁਨੇਹਾ);

	handle = get_handle(conn, id, &handle_len,
	    "remote readdir(\"%s\")", ਰਸਤਾ);
	ਜੇ (handle == ਨਿਰਾ) {
		sshbuf_free(ਸੁਨੇਹਾ);
		ਵਾਪਸ -1;
	}

	ਜੇ (dir) {
		ents = 0;
		*dir = xcalloc(1, ਆਕਾਰ(**dir));
		(*dir)[0] = ਨਿਰਾ;
	}

	ਲਈ (; !interrupted;) {
		id = expected_id = conn->ਸੁਨੇਹਾ_id++;

		debug3("Sending SSH2_FXP_READDIR I:%u", id);

		sshbuf_reset(ਸੁਨੇਹਾ);
		ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, SSH2_FXP_READDIR)) != 0 ||
		    (r = sshbuf_put_u32(ਸੁਨੇਹਾ, id)) != 0 ||
		    (r = sshbuf_put_string(ਸੁਨੇਹਾ, handle, handle_len)) != 0)
			fatal_fr(r, "compose READDIR");
		send_ਸੁਨੇਹਾ(conn, ਸੁਨੇਹਾ);

		sshbuf_reset(ਸੁਨੇਹਾ);

		get_ਸੁਨੇਹਾ(conn, ਸੁਨੇਹਾ);

		ਜੇ ((r = sshbuf_get_u8(ਸੁਨੇਹਾ, &type)) != 0 ||
		    (r = sshbuf_get_u32(ਸੁਨੇਹਾ, &id)) != 0)
			fatal_fr(r, "parse");

		debug3("Received reply T:%u I:%u", type, id);

		ਜੇ (id != expected_id)
			fatal("ID mismatch (%u != %u)", id, expected_id);

		ਜੇ (type == SSH2_FXP_ਸਥਿਤੀ) {
			u_int rstatus;

			ਜੇ ((r = sshbuf_get_u32(ਸੁਨੇਹਾ, &rstatus)) != 0)
				fatal_fr(r, "parse status");
			debug3("Received SSH2_FXP_STATUS %d", rstatus);
			ਜੇ (rstatus == SSH2_FX_EOF)
				ਰੋਕੋ;
			error("Couldn't read directory: %s", fx2txt(rstatus));
			ਜਾਓ ਬਾਹਰਲਾ;
		} ਨਹੀਂਤਾਂ ਜੇ (type != SSH2_FXP_NAME)
			fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
			    SSH2_FXP_NAME, type);

		ਜੇ ((r = sshbuf_get_u32(ਸੁਨੇਹਾ, &ਗਿਣਤੀ_2)) != 0)
			fatal_fr(r, "parse count");
		ਜੇ (ਗਿਣਤੀ_2 > SSHBUF_ਮਾਪ_MAX)
			fatal_f("nonsensical number of entries");
		ਜੇ (ਗਿਣਤੀ_2 == 0)
			ਰੋਕੋ;
		debug3("Received %d SSH2_FXP_NAME responses", ਗਿਣਤੀ_2);
		ਲਈ (i = 0; i < ਗਿਣਤੀ_2; i++) {
			ਅੱਖਰ *filename, *longname;
			Attrib a;

			ਜੇ ((r = sshbuf_get_cstring(ਸੁਨੇਹਾ, &filename,
			    ਨਿਰਾ)) != 0 ||
			    (r = sshbuf_get_cstring(ਸੁਨੇਹਾ, &longname,
			    ਨਿਰਾ)) != 0)
				fatal_fr(r, "parse filenames");
			ਜੇ ((r = decode_attrib(ਸੁਨੇਹਾ, &a)) != 0) {
				error_fr(r, "couldn't decode attrib");
				ਮੁਕਤ(filename);
				ਮੁਕਤ(longname);
				ਜਾਓ ਬਾਹਰਲਾ;
			}

			ਜੇ (print_flag)
				mprintf("%s\n", longname);

			/*
			 * Directory entries should never contain '/'
			 * These can be used to attack recursive ops
			 * (e.g. send '../../../../etc/passwd')
			 */
			ਜੇ (*filename == '\0' ||
			    strpbrk(filename, SFTP_DIRECTORY_CHARS) != ਨਿਰਾ) {
				error("Server sent suspect path \"%s\" "
				    "during readdir of \"%s\"", filename, ਰਸਤਾ);
			} ਨਹੀਂਤਾਂ ਜੇ (dir) {
				*dir = xreallocarray(*dir, ents + 2, ਆਕਾਰ(**dir));
				(*dir)[ents] = xcalloc(1, ਆਕਾਰ(***dir));
				(*dir)[ents]->filename = xstrdup(filename);
				(*dir)[ents]->longname = xstrdup(longname);
				ਸਮ੍ਰਿਤੀ_ਨਕਲ(&(*dir)[ents]->a, &a, ਆਕਾਰ(a));
				(*dir)[++ents] = ਨਿਰਾ;
			}
			ਮੁਕਤ(filename);
			ਮੁਕਤ(longname);
		}
	}
	ਸਥਿਤੀ = 0;

 ਬਾਹਰਲਾ:
	sshbuf_free(ਸੁਨੇਹਾ);
	sftp_close(conn, handle, handle_len);
	ਮੁਕਤ(handle);

	ਜੇ (ਸਥਿਤੀ != 0 && dir != ਨਿਰਾ) {
		/* Don't return results on error */
		sftp_free_dirents(*dir);
		*dir = ਨਿਰਾ;
	} ਨਹੀਂਤਾਂ ਜੇ (interrupted && dir != ਨਿਰਾ && *dir != ਨਿਰਾ) {
		/* Don't return partial matches on interrupt */
		sftp_free_dirents(*dir);
		*dir = xcalloc(1, ਆਕਾਰ(**dir));
		**dir = ਨਿਰਾ;
	}

	ਵਾਪਸ ਸਥਿਤੀ == SSH2_FX_OK ? 0 : -1;
}

ਪੂਰਨ
sftp_readdir(ਬਣਤਰ sftp_conn *conn, ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, SFTP_DIRENT ***dir)
{
	ਵਾਪਸ sftp_lsreaddir(conn, ਰਸਤਾ, 0, dir);
}

ਖਾਲੀ sftp_free_dirents(SFTP_DIRENT **s)
{
	ਪੂਰਨ i;

	ਜੇ (s == ਨਿਰਾ)
		ਵਾਪਸ;
	ਲਈ (i = 0; s[i]; i++) {
		ਮੁਕਤ(s[i]->filename);
		ਮੁਕਤ(s[i]->longname);
		ਮੁਕਤ(s[i]);
	}
	ਮੁਕਤ(s);
}

ਪੂਰਨ
sftp_rm(ਬਣਤਰ sftp_conn *conn, ਅਚਲ ਅੱਖਰ *ਰਸਤਾ)
{
	u_int ਸਥਿਤੀ, id;

	debug2("Sending SSH2_FXP_REMOVE \"%s\"", ਰਸਤਾ);

	id = conn->ਸੁਨੇਹਾ_id++;
	send_string_request(conn, id, SSH2_FXP_REMOVE, ਰਸਤਾ, ਲੜੀ_ਲੰਬਾਈ(ਰਸਤਾ));
	ਸਥਿਤੀ = get_ਸਥਿਤੀ(conn, id);
	ਜੇ (ਸਥਿਤੀ != SSH2_FX_OK)
		error("remote delete %s: %s", ਰਸਤਾ, fx2txt(ਸਥਿਤੀ));
	ਵਾਪਸ ਸਥਿਤੀ == SSH2_FX_OK ? 0 : -1;
}

ਪੂਰਨ
sftp_mkdir(ਬਣਤਰ sftp_conn *conn, ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, Attrib *a, ਪੂਰਨ print_flag)
{
	u_int ਸਥਿਤੀ, id;

	debug2("Sending SSH2_FXP_MKDIR \"%s\"", ਰਸਤਾ);

	id = conn->ਸੁਨੇਹਾ_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_MKDIR, ਰਸਤਾ,
	    ਲੜੀ_ਲੰਬਾਈ(ਰਸਤਾ), a);

	ਸਥਿਤੀ = get_ਸਥਿਤੀ(conn, id);
	ਜੇ (ਸਥਿਤੀ != SSH2_FX_OK && print_flag)
		error("remote mkdir \"%s\": %s", ਰਸਤਾ, fx2txt(ਸਥਿਤੀ));

	ਵਾਪਸ ਸਥਿਤੀ == SSH2_FX_OK ? 0 : -1;
}

ਪੂਰਨ
sftp_mkpath(ਬਣਤਰ sftp_conn *conn, ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, Attrib *a, ਪੂਰਨ print_flag)
{
	ਅੱਖਰ *slash, *tmp_ਰਸਤਾ;
	ਪੂਰਨ ਪੂਰਾ;

	tmp_ਰਸਤਾ = xstrdup(ਰਸਤਾ);
	slash = tmp_ਰਸਤਾ;

	ਲਈ (;;) {
		slash += strspn(slash, "/");
		slash += strcspn(slash, "/");

		ਪੂਰਾ = (*slash == '\0');
		*slash = '\0';

		ਜੇ (!sftp_remote_is_dir(conn, tmp_ਰਸਤਾ)) {
			ਜੇ (sftp_mkdir(conn, tmp_ਰਸਤਾ, a, print_flag) != 0) {
				ਮੁਕਤ(tmp_ਰਸਤਾ);
				ਵਾਪਸ -1;
			}
		}

		ਜੇ (ਪੂਰਾ)
			ਰੋਕੋ;

		*slash = '/';
	}

	ਮੁਕਤ(tmp_ਰਸਤਾ);
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sftp_rmdir(ਬਣਤਰ sftp_conn *conn, ਅਚਲ ਅੱਖਰ *ਰਸਤਾ)
{
	u_int ਸਥਿਤੀ, id;

	debug2("Sending SSH2_FXP_RMDIR \"%s\"", ਰਸਤਾ);

	id = conn->ਸੁਨੇਹਾ_id++;
	send_string_request(conn, id, SSH2_FXP_RMDIR, ਰਸਤਾ,
	    ਲੜੀ_ਲੰਬਾਈ(ਰਸਤਾ));

	ਸਥਿਤੀ = get_ਸਥਿਤੀ(conn, id);
	ਜੇ (ਸਥਿਤੀ != SSH2_FX_OK)
		error("remote rmdir \"%s\": %s", ਰਸਤਾ, fx2txt(ਸਥਿਤੀ));

	ਵਾਪਸ ਸਥਿਤੀ == SSH2_FX_OK ? 0 : -1;
}

ਪੂਰਨ
sftp_stat(ਬਣਤਰ sftp_conn *conn, ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, ਪੂਰਨ quiet, Attrib *a)
{
	u_int id;

	debug2("Sending SSH2_FXP_STAT \"%s\"", ਰਸਤਾ);

	id = conn->ਸੁਨੇਹਾ_id++;

	send_string_request(conn, id,
	    conn->ਸੰਸਕਰਣ == 0 ? SSH2_FXP_STAT_ਸੰਸਕਰਣ_0 : SSH2_FXP_STAT,
	    ਰਸਤਾ, ਲੜੀ_ਲੰਬਾਈ(ਰਸਤਾ));

	ਵਾਪਸ get_decode_stat(conn, id, quiet, a);
}

ਪੂਰਨ
sftp_lstat(ਬਣਤਰ sftp_conn *conn, ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, ਪੂਰਨ quiet, Attrib *a)
{
	u_int id;

	ਜੇ (conn->ਸੰਸਕਰਣ == 0) {
		do_log2(quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_INFO,
		    "Server version does not support lstat operation");
		ਵਾਪਸ sftp_stat(conn, ਰਸਤਾ, quiet, a);
	}

	id = conn->ਸੁਨੇਹਾ_id++;
	send_string_request(conn, id, SSH2_FXP_LSTAT, ਰਸਤਾ,
	    ਲੜੀ_ਲੰਬਾਈ(ਰਸਤਾ));

	ਵਾਪਸ get_decode_stat(conn, id, quiet, a);
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ notyet
ਪੂਰਨ
sftp_fstat(ਬਣਤਰ sftp_conn *conn, ਅਚਲ u_char *handle, u_int handle_len,
    ਪੂਰਨ quiet, Attrib *a)
{
	u_int id;

	debug2("Sending SSH2_FXP_FSTAT \"%s\"");

	id = conn->ਸੁਨੇਹਾ_id++;
	send_string_request(conn, id, SSH2_FXP_FSTAT, handle,
	    handle_len);

	ਵਾਪਸ get_decode_stat(conn, id, quiet, a);
}
#ਜੇ_ਅੰਤ

ਪੂਰਨ
sftp_setstat(ਬਣਤਰ sftp_conn *conn, ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, Attrib *a)
{
	u_int ਸਥਿਤੀ, id;

	debug2("Sending SSH2_FXP_SETSTAT \"%s\"", ਰਸਤਾ);

	id = conn->ਸੁਨੇਹਾ_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_SETSTAT, ਰਸਤਾ,
	    ਲੜੀ_ਲੰਬਾਈ(ਰਸਤਾ), a);

	ਸਥਿਤੀ = get_ਸਥਿਤੀ(conn, id);
	ਜੇ (ਸਥਿਤੀ != SSH2_FX_OK)
		error("remote setstat \"%s\": %s", ਰਸਤਾ, fx2txt(ਸਥਿਤੀ));

	ਵਾਪਸ ਸਥਿਤੀ == SSH2_FX_OK ? 0 : -1;
}

ਪੂਰਨ
sftp_fsetstat(ਬਣਤਰ sftp_conn *conn, ਅਚਲ u_char *handle, u_int handle_len,
    Attrib *a)
{
	u_int ਸਥਿਤੀ, id;

	debug2("Sending SSH2_FXP_FSETSTAT");

	id = conn->ਸੁਨੇਹਾ_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_FSETSTAT, handle,
	    handle_len, a);

	ਸਥਿਤੀ = get_ਸਥਿਤੀ(conn, id);
	ਜੇ (ਸਥਿਤੀ != SSH2_FX_OK)
		error("remote fsetstat: %s", fx2txt(ਸਥਿਤੀ));

	ਵਾਪਸ ਸਥਿਤੀ == SSH2_FX_OK ? 0 : -1;
}

/* Implements both the realpath and expand-path operations */
ਸਥਿਰ ਅੱਖਰ *
sftp_realpath_expand(ਬਣਤਰ sftp_conn *conn, ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, ਪੂਰਨ expand)
{
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;
	u_int expected_id, ਗਿਣਤੀ_2, id;
	ਅੱਖਰ *filename, *longname;
	Attrib a;
	u_char type;
	ਪੂਰਨ r;
	ਅਚਲ ਅੱਖਰ *what = "SSH2_FXP_REALPATH";

	ਜੇ (expand)
		what = "expand-path@openssh.com";
	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");

	expected_id = id = conn->ਸੁਨੇਹਾ_id++;
	ਜੇ (expand) {
		debug2("Sending SSH2_FXP_EXTENDED(expand-path@openssh.com) "
		    "\"%s\"", ਰਸਤਾ);
		ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, SSH2_FXP_EXTENDED)) != 0 ||
		    (r = sshbuf_put_u32(ਸੁਨੇਹਾ, id)) != 0 ||
		    (r = sshbuf_put_cstring(ਸੁਨੇਹਾ,
		    "expand-path@openssh.com")) != 0 ||
		    (r = sshbuf_put_cstring(ਸੁਨੇਹਾ, ਰਸਤਾ)) != 0)
			fatal_fr(r, "compose %s", what);
		send_ਸੁਨੇਹਾ(conn, ਸੁਨੇਹਾ);
	} ਨਹੀਂਤਾਂ {
		debug2("Sending SSH2_FXP_REALPATH \"%s\"", ਰਸਤਾ);
		send_string_request(conn, id, SSH2_FXP_REALPATH,
		    ਰਸਤਾ, ਲੜੀ_ਲੰਬਾਈ(ਰਸਤਾ));
	}
	get_ਸੁਨੇਹਾ(conn, ਸੁਨੇਹਾ);
	ਜੇ ((r = sshbuf_get_u8(ਸੁਨੇਹਾ, &type)) != 0 ||
	    (r = sshbuf_get_u32(ਸੁਨੇਹਾ, &id)) != 0)
		fatal_fr(r, "parse");

	ਜੇ (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);

	ਜੇ (type == SSH2_FXP_ਸਥਿਤੀ) {
		u_int ਸਥਿਤੀ;
		ਅੱਖਰ *errmsg;

		ਜੇ ((r = sshbuf_get_u32(ਸੁਨੇਹਾ, &ਸਥਿਤੀ)) != 0 ||
		    (r = sshbuf_get_cstring(ਸੁਨੇਹਾ, &errmsg, ਨਿਰਾ)) != 0)
			fatal_fr(r, "parse status");
		error("%s %s: %s", expand ? "expand" : "realpath",
		    ਰਸਤਾ, *errmsg == '\0' ? fx2txt(ਸਥਿਤੀ) : errmsg);
		ਮੁਕਤ(errmsg);
		sshbuf_free(ਸੁਨੇਹਾ);
		ਵਾਪਸ ਨਿਰਾ;
	} ਨਹੀਂਤਾਂ ਜੇ (type != SSH2_FXP_NAME)
		fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
		    SSH2_FXP_NAME, type);

	ਜੇ ((r = sshbuf_get_u32(ਸੁਨੇਹਾ, &ਗਿਣਤੀ_2)) != 0)
		fatal_fr(r, "parse count");
	ਜੇ (ਗਿਣਤੀ_2 != 1)
		fatal("Got multiple names (%d) from %s", ਗਿਣਤੀ_2, what);

	ਜੇ ((r = sshbuf_get_cstring(ਸੁਨੇਹਾ, &filename, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_cstring(ਸੁਨੇਹਾ, &longname, ਨਿਰਾ)) != 0 ||
	    (r = decode_attrib(ਸੁਨੇਹਾ, &a)) != 0)
		fatal_fr(r, "parse filename/attrib");

	debug3("%s %s -> %s", what, ਰਸਤਾ, filename);

	ਮੁਕਤ(longname);

	sshbuf_free(ਸੁਨੇਹਾ);

	ਵਾਪਸ(filename);
}

ਅੱਖਰ *
sftp_realpath(ਬਣਤਰ sftp_conn *conn, ਅਚਲ ਅੱਖਰ *ਰਸਤਾ)
{
	ਵਾਪਸ sftp_realpath_expand(conn, ਰਸਤਾ, 0);
}

ਪੂਰਨ
sftp_can_expand_ਰਸਤਾ(ਬਣਤਰ sftp_conn *conn)
{
	ਵਾਪਸ (conn->exts & SFTP_EXT_ਰਸਤਾ_EXPAND) != 0;
}

ਅੱਖਰ *
sftp_expand_ਰਸਤਾ(ਬਣਤਰ sftp_conn *conn, ਅਚਲ ਅੱਖਰ *ਰਸਤਾ)
{
	ਜੇ (!sftp_can_expand_ਰਸਤਾ(conn)) {
		debug3_f("no server support, fallback to realpath");
		ਵਾਪਸ sftp_realpath_expand(conn, ਰਸਤਾ, 0);
	}
	ਵਾਪਸ sftp_realpath_expand(conn, ਰਸਤਾ, 1);
}

ਪੂਰਨ
sftp_copy(ਬਣਤਰ sftp_conn *conn, ਅਚਲ ਅੱਖਰ *oldpath, ਅਚਲ ਅੱਖਰ *newpath)
{
	Attrib junk, attr;
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;
	u_char *old_handle, *new_handle;
	u_int ਬਹੁਲਕ, ਸਥਿਤੀ, id;
	ਮਾਪ_t old_handle_len, new_handle_len;
	ਪੂਰਨ r;

	/* Return if the extension is not supported */
	ਜੇ ((conn->exts & SFTP_EXT_COPY_ਅੰਕੜੇ) == 0) {
		error("Server does not support copy-data extension");
		ਵਾਪਸ -1;
	}

	/* Make sure the file exists, and we can copy its perms */
	ਜੇ (sftp_stat(conn, oldpath, 0, &attr) != 0)
		ਵਾਪਸ -1;

	/* Do not preserve set[ug]id here, as we do not preserve ownership */
	ਜੇ (attr.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		ਬਹੁਲਕ = attr.perm & 0777;

		ਜੇ (!S_ISREG(attr.perm)) {
			error("Cannot copy non-regular file: %s", oldpath);
			ਵਾਪਸ -1;
		}
	} ਨਹੀਂਤਾਂ {
		/* NB: The user's umask will apply to this */
		ਬਹੁਲਕ = 0666;
	}

	/* Set up the new perms for the new file */
	attrib_clear(&attr);
	attr.perm = ਬਹੁਲਕ;
	attr.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;

	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");

	attrib_clear(&junk); /* Send empty attributes */

	/* Open the old file for reading */
	id = conn->ਸੁਨੇਹਾ_id++;
	ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(ਸੁਨੇਹਾ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ਸੁਨੇਹਾ, oldpath)) != 0 ||
	    (r = sshbuf_put_u32(ਸੁਨੇਹਾ, SSH2_FXF_READ)) != 0 ||
	    (r = encode_attrib(ਸੁਨੇਹਾ, &junk)) != 0)
		fatal_fr(r, "buffer error");
	send_ਸੁਨੇਹਾ(conn, ਸੁਨੇਹਾ);
	debug3("Sent message SSH2_FXP_OPEN I:%u P:%s", id, oldpath);

	sshbuf_reset(ਸੁਨੇਹਾ);

	old_handle = get_handle(conn, id, &old_handle_len,
	    "remote open(\"%s\")", oldpath);
	ਜੇ (old_handle == ਨਿਰਾ) {
		sshbuf_free(ਸੁਨੇਹਾ);
		ਵਾਪਸ -1;
	}

	/* Open the new file for writing */
	id = conn->ਸੁਨੇਹਾ_id++;
	ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(ਸੁਨੇਹਾ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ਸੁਨੇਹਾ, newpath)) != 0 ||
	    (r = sshbuf_put_u32(ਸੁਨੇਹਾ, SSH2_FXF_WRITE|SSH2_FXF_CREAT|
	    SSH2_FXF_TRUNC)) != 0 ||
	    (r = encode_attrib(ਸੁਨੇਹਾ, &attr)) != 0)
		fatal_fr(r, "buffer error");
	send_ਸੁਨੇਹਾ(conn, ਸੁਨੇਹਾ);
	debug3("Sent message SSH2_FXP_OPEN I:%u P:%s", id, newpath);

	sshbuf_reset(ਸੁਨੇਹਾ);

	new_handle = get_handle(conn, id, &new_handle_len,
	    "remote open(\"%s\")", newpath);
	ਜੇ (new_handle == ਨਿਰਾ) {
		sshbuf_free(ਸੁਨੇਹਾ);
		ਮੁਕਤ(old_handle);
		ਵਾਪਸ -1;
	}

	/* Copy the file data */
	id = conn->ਸੁਨੇਹਾ_id++;
	ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(ਸੁਨੇਹਾ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ਸੁਨੇਹਾ, "copy-data")) != 0 ||
	    (r = sshbuf_put_string(ਸੁਨੇਹਾ, old_handle, old_handle_len)) != 0 ||
	    (r = sshbuf_put_u64(ਸੁਨੇਹਾ, 0)) != 0 ||
	    (r = sshbuf_put_u64(ਸੁਨੇਹਾ, 0)) != 0 ||
	    (r = sshbuf_put_string(ਸੁਨੇਹਾ, new_handle, new_handle_len)) != 0 ||
	    (r = sshbuf_put_u64(ਸੁਨੇਹਾ, 0)) != 0)
		fatal_fr(r, "buffer error");
	send_ਸੁਨੇਹਾ(conn, ਸੁਨੇਹਾ);
	debug3("Sent message copy-data \"%s\" 0 0 -> \"%s\" 0",
	       oldpath, newpath);

	ਸਥਿਤੀ = get_ਸਥਿਤੀ(conn, id);
	ਜੇ (ਸਥਿਤੀ != SSH2_FX_OK)
		error("Couldn't copy file \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(ਸਥਿਤੀ));

	/* Clean up everything */
	sshbuf_free(ਸੁਨੇਹਾ);
	sftp_close(conn, old_handle, old_handle_len);
	sftp_close(conn, new_handle, new_handle_len);
	ਮੁਕਤ(old_handle);
	ਮੁਕਤ(new_handle);

	ਵਾਪਸ ਸਥਿਤੀ == SSH2_FX_OK ? 0 : -1;
}

ਪੂਰਨ
sftp_rename(ਬਣਤਰ sftp_conn *conn, ਅਚਲ ਅੱਖਰ *oldpath, ਅਚਲ ਅੱਖਰ *newpath,
    ਪੂਰਨ force_legacy)
{
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;
	u_int ਸਥਿਤੀ, id;
	ਪੂਰਨ r, use_ext = (conn->exts & SFTP_EXT_POSIX_RENAME) && !force_legacy;

	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");

	/* Send rename request */
	id = conn->ਸੁਨੇਹਾ_id++;
	ਜੇ (use_ext) {
		debug2("Sending SSH2_FXP_EXTENDED(posix-rename@openssh.com) "
		    "\"%s\" to \"%s\"", oldpath, newpath);
		ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, SSH2_FXP_EXTENDED)) != 0 ||
		    (r = sshbuf_put_u32(ਸੁਨੇਹਾ, id)) != 0 ||
		    (r = sshbuf_put_cstring(ਸੁਨੇਹਾ,
		    "posix-rename@openssh.com")) != 0)
			fatal_fr(r, "compose posix-rename");
	} ਨਹੀਂਤਾਂ {
		debug2("Sending SSH2_FXP_RENAME \"%s\" to \"%s\"",
		    oldpath, newpath);
		ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, SSH2_FXP_RENAME)) != 0 ||
		    (r = sshbuf_put_u32(ਸੁਨੇਹਾ, id)) != 0)
			fatal_fr(r, "compose rename");
	}
	ਜੇ ((r = sshbuf_put_cstring(ਸੁਨੇਹਾ, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(ਸੁਨੇਹਾ, newpath)) != 0)
		fatal_fr(r, "compose paths");
	send_ਸੁਨੇਹਾ(conn, ਸੁਨੇਹਾ);
	debug3("Sent message %s \"%s\" -> \"%s\"",
	    use_ext ? "posix-rename@openssh.com" :
	    "SSH2_FXP_RENAME", oldpath, newpath);
	sshbuf_free(ਸੁਨੇਹਾ);

	ਸਥਿਤੀ = get_ਸਥਿਤੀ(conn, id);
	ਜੇ (ਸਥਿਤੀ != SSH2_FX_OK)
		error("remote rename \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(ਸਥਿਤੀ));

	ਵਾਪਸ ਸਥਿਤੀ == SSH2_FX_OK ? 0 : -1;
}

ਪੂਰਨ
sftp_hardlink(ਬਣਤਰ sftp_conn *conn, ਅਚਲ ਅੱਖਰ *oldpath, ਅਚਲ ਅੱਖਰ *newpath)
{
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;
	u_int ਸਥਿਤੀ, id;
	ਪੂਰਨ r;

	ਜੇ ((conn->exts & SFTP_EXT_HARDLINK) == 0) {
		error("Server does not support hardlink@openssh.com extension");
		ਵਾਪਸ -1;
	}
	debug2("Sending SSH2_FXP_EXTENDED(hardlink@openssh.com) "
	    "\"%s\" to \"%s\"", oldpath, newpath);

	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");

	/* Send link request */
	id = conn->ਸੁਨੇਹਾ_id++;
	ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(ਸੁਨੇਹਾ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ਸੁਨੇਹਾ, "hardlink@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(ਸੁਨੇਹਾ, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(ਸੁਨੇਹਾ, newpath)) != 0)
		fatal_fr(r, "compose");
	send_ਸੁਨੇਹਾ(conn, ਸੁਨੇਹਾ);
	debug3("Sent message hardlink@openssh.com \"%s\" -> \"%s\"",
	    oldpath, newpath);
	sshbuf_free(ਸੁਨੇਹਾ);

	ਸਥਿਤੀ = get_ਸਥਿਤੀ(conn, id);
	ਜੇ (ਸਥਿਤੀ != SSH2_FX_OK)
		error("remote link \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(ਸਥਿਤੀ));

	ਵਾਪਸ ਸਥਿਤੀ == SSH2_FX_OK ? 0 : -1;
}

ਪੂਰਨ
sftp_symlink(ਬਣਤਰ sftp_conn *conn, ਅਚਲ ਅੱਖਰ *oldpath, ਅਚਲ ਅੱਖਰ *newpath)
{
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;
	u_int ਸਥਿਤੀ, id;
	ਪੂਰਨ r;

	ਜੇ (conn->ਸੰਸਕਰਣ < 3) {
		error("This server does not support the symlink operation");
		ਵਾਪਸ(SSH2_FX_OP_UNSUPPORTED);
	}
	debug2("Sending SSH2_FXP_SYMLINK \"%s\" to \"%s\"", oldpath, newpath);

	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");

	/* Send symlink request */
	id = conn->ਸੁਨੇਹਾ_id++;
	ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, SSH2_FXP_SYMLINK)) != 0 ||
	    (r = sshbuf_put_u32(ਸੁਨੇਹਾ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ਸੁਨੇਹਾ, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(ਸੁਨੇਹਾ, newpath)) != 0)
		fatal_fr(r, "compose");
	send_ਸੁਨੇਹਾ(conn, ਸੁਨੇਹਾ);
	debug3("Sent message SSH2_FXP_SYMLINK \"%s\" -> \"%s\"", oldpath,
	    newpath);
	sshbuf_free(ਸੁਨੇਹਾ);

	ਸਥਿਤੀ = get_ਸਥਿਤੀ(conn, id);
	ਜੇ (ਸਥਿਤੀ != SSH2_FX_OK)
		error("remote symlink file \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(ਸਥਿਤੀ));

	ਵਾਪਸ ਸਥਿਤੀ == SSH2_FX_OK ? 0 : -1;
}

ਪੂਰਨ
sftp_fsync(ਬਣਤਰ sftp_conn *conn, u_char *handle, u_int handle_len)
{
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;
	u_int ਸਥਿਤੀ, id;
	ਪੂਰਨ r;

	/* Silently return if the extension is not supported */
	ਜੇ ((conn->exts & SFTP_EXT_FSYNC) == 0)
		ਵਾਪਸ -1;
	debug2("Sending SSH2_FXP_EXTENDED(fsync@openssh.com)");

	/* Send fsync request */
	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	id = conn->ਸੁਨੇਹਾ_id++;
	ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(ਸੁਨੇਹਾ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ਸੁਨੇਹਾ, "fsync@openssh.com")) != 0 ||
	    (r = sshbuf_put_string(ਸੁਨੇਹਾ, handle, handle_len)) != 0)
		fatal_fr(r, "compose");
	send_ਸੁਨੇਹਾ(conn, ਸੁਨੇਹਾ);
	debug3("Sent message fsync@openssh.com I:%u", id);
	sshbuf_free(ਸੁਨੇਹਾ);

	ਸਥਿਤੀ = get_ਸਥਿਤੀ(conn, id);
	ਜੇ (ਸਥਿਤੀ != SSH2_FX_OK)
		error("remote fsync: %s", fx2txt(ਸਥਿਤੀ));

	ਵਾਪਸ ਸਥਿਤੀ == SSH2_FX_OK ? 0 : -1;
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ notyet
ਅੱਖਰ *
sftp_readlink(ਬਣਤਰ sftp_conn *conn, ਅਚਲ ਅੱਖਰ *ਰਸਤਾ)
{
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;
	u_int expected_id, ਗਿਣਤੀ_2, id;
	ਅੱਖਰ *filename, *longname;
	Attrib a;
	u_char type;
	ਪੂਰਨ r;

	debug2("Sending SSH2_FXP_READLINK \"%s\"", ਰਸਤਾ);

	expected_id = id = conn->ਸੁਨੇਹਾ_id++;
	send_string_request(conn, id, SSH2_FXP_READLINK, ਰਸਤਾ, ਲੜੀ_ਲੰਬਾਈ(ਰਸਤਾ));

	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");

	get_ਸੁਨੇਹਾ(conn, ਸੁਨੇਹਾ);
	ਜੇ ((r = sshbuf_get_u8(ਸੁਨੇਹਾ, &type)) != 0 ||
	    (r = sshbuf_get_u32(ਸੁਨੇਹਾ, &id)) != 0)
		fatal_fr(r, "parse");

	ਜੇ (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);

	ਜੇ (type == SSH2_FXP_ਸਥਿਤੀ) {
		u_int ਸਥਿਤੀ;

		ਜੇ ((r = sshbuf_get_u32(ਸੁਨੇਹਾ, &ਸਥਿਤੀ)) != 0)
			fatal_fr(r, "parse status");
		error("Couldn't readlink: %s", fx2txt(ਸਥਿਤੀ));
		sshbuf_free(ਸੁਨੇਹਾ);
		ਵਾਪਸ(ਨਿਰਾ);
	} ਨਹੀਂਤਾਂ ਜੇ (type != SSH2_FXP_NAME)
		fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
		    SSH2_FXP_NAME, type);

	ਜੇ ((r = sshbuf_get_u32(ਸੁਨੇਹਾ, &ਗਿਣਤੀ_2)) != 0)
		fatal_fr(r, "parse count");
	ਜੇ (ਗਿਣਤੀ_2 != 1)
		fatal("Got multiple names (%d) from SSH_FXP_READLINK", ਗਿਣਤੀ_2);

	ਜੇ ((r = sshbuf_get_cstring(ਸੁਨੇਹਾ, &filename, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_cstring(ਸੁਨੇਹਾ, &longname, ਨਿਰਾ)) != 0 ||
	    (r = decode_attrib(ਸੁਨੇਹਾ, &a)) != 0)
		fatal_fr(r, "parse filenames/attrib");

	debug3("SSH_FXP_READLINK %s -> %s", ਰਸਤਾ, filename);

	ਮੁਕਤ(longname);

	sshbuf_free(ਸੁਨੇਹਾ);

	ਵਾਪਸ filename;
}
#ਜੇ_ਅੰਤ

ਪੂਰਨ
sftp_statvfs(ਬਣਤਰ sftp_conn *conn, ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, ਬਣਤਰ sftp_statvfs *st,
    ਪੂਰਨ quiet)
{
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;
	u_int id;
	ਪੂਰਨ r;

	ਜੇ ((conn->exts & SFTP_EXT_STATVFS) == 0) {
		error("Server does not support statvfs@openssh.com extension");
		ਵਾਪਸ -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(statvfs@openssh.com) \"%s\"", ਰਸਤਾ);

	id = conn->ਸੁਨੇਹਾ_id++;

	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(ਸੁਨੇਹਾ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ਸੁਨੇਹਾ, "statvfs@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(ਸੁਨੇਹਾ, ਰਸਤਾ)) != 0)
		fatal_fr(r, "compose");
	send_ਸੁਨੇਹਾ(conn, ਸੁਨੇਹਾ);
	sshbuf_free(ਸੁਨੇਹਾ);

	ਵਾਪਸ get_decode_statvfs(conn, st, id, quiet);
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ notyet
ਪੂਰਨ
sftp_fstatvfs(ਬਣਤਰ sftp_conn *conn, ਅਚਲ u_char *handle, u_int handle_len,
    ਬਣਤਰ sftp_statvfs *st, ਪੂਰਨ quiet)
{
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;
	u_int id;

	ਜੇ ((conn->exts & SFTP_EXT_FSTATVFS) == 0) {
		error("Server does not support fstatvfs@openssh.com extension");
		ਵਾਪਸ -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(fstatvfs@openssh.com)");

	id = conn->ਸੁਨੇਹਾ_id++;

	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(ਸੁਨੇਹਾ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ਸੁਨੇਹਾ, "fstatvfs@openssh.com")) != 0 ||
	    (r = sshbuf_put_string(ਸੁਨੇਹਾ, handle, handle_len)) != 0)
		fatal_fr(r, "compose");
	send_ਸੁਨੇਹਾ(conn, ਸੁਨੇਹਾ);
	sshbuf_free(ਸੁਨੇਹਾ);

	ਵਾਪਸ get_decode_statvfs(conn, st, id, quiet);
}
#ਜੇ_ਅੰਤ

ਪੂਰਨ
sftp_lsetstat(ਬਣਤਰ sftp_conn *conn, ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, Attrib *a)
{
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;
	u_int ਸਥਿਤੀ, id;
	ਪੂਰਨ r;

	ਜੇ ((conn->exts & SFTP_EXT_LSETSTAT) == 0) {
		error("Server does not support lsetstat@openssh.com extension");
		ਵਾਪਸ -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(lsetstat@openssh.com) \"%s\"", ਰਸਤਾ);

	id = conn->ਸੁਨੇਹਾ_id++;
	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(ਸੁਨੇਹਾ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ਸੁਨੇਹਾ, "lsetstat@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(ਸੁਨੇਹਾ, ਰਸਤਾ)) != 0 ||
	    (r = encode_attrib(ਸੁਨੇਹਾ, a)) != 0)
		fatal_fr(r, "compose");
	send_ਸੁਨੇਹਾ(conn, ਸੁਨੇਹਾ);
	sshbuf_free(ਸੁਨੇਹਾ);

	ਸਥਿਤੀ = get_ਸਥਿਤੀ(conn, id);
	ਜੇ (ਸਥਿਤੀ != SSH2_FX_OK)
		error("remote lsetstat \"%s\": %s", ਰਸਤਾ, fx2txt(ਸਥਿਤੀ));

	ਵਾਪਸ ਸਥਿਤੀ == SSH2_FX_OK ? 0 : -1;
}

ਸਥਿਰ ਖਾਲੀ
send_read_request(ਬਣਤਰ sftp_conn *conn, u_int id, uint64_t ਵਿੱਥ,
    u_int len, ਅਚਲ u_char *handle, u_int handle_len)
{
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;
	ਪੂਰਨ r;

	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, SSH2_FXP_READ)) != 0 ||
	    (r = sshbuf_put_u32(ਸੁਨੇਹਾ, id)) != 0 ||
	    (r = sshbuf_put_string(ਸੁਨੇਹਾ, handle, handle_len)) != 0 ||
	    (r = sshbuf_put_u64(ਸੁਨੇਹਾ, ਵਿੱਥ)) != 0 ||
	    (r = sshbuf_put_u32(ਸੁਨੇਹਾ, len)) != 0)
		fatal_fr(r, "compose");
	send_ਸੁਨੇਹਾ(conn, ਸੁਨੇਹਾ);
	sshbuf_free(ਸੁਨੇਹਾ);
}

ਸਥਿਰ ਪੂਰਨ
send_open(ਬਣਤਰ sftp_conn *conn, ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, ਅਚਲ ਅੱਖਰ *ਟੈਗ,
    u_int openmode, Attrib *a, u_char **handlep, ਮਾਪ_t *handle_lenp)
{
	Attrib junk;
	u_char *handle;
	ਮਾਪ_t handle_len;
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;
	ਪੂਰਨ r;
	u_int id;

	debug2("Sending SSH2_FXP_OPEN \"%s\"", ਰਸਤਾ);

	*handlep = ਨਿਰਾ;
	*handle_lenp = 0;

	ਜੇ (a == ਨਿਰਾ) {
		attrib_clear(&junk); /* Send empty attributes */
		a = &junk;
	}
	/* Send open request */
	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	id = conn->ਸੁਨੇਹਾ_id++;
	ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(ਸੁਨੇਹਾ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ਸੁਨੇਹਾ, ਰਸਤਾ)) != 0 ||
	    (r = sshbuf_put_u32(ਸੁਨੇਹਾ, openmode)) != 0 ||
	    (r = encode_attrib(ਸੁਨੇਹਾ, a)) != 0)
		fatal_fr(r, "compose %s open", ਟੈਗ);
	send_ਸੁਨੇਹਾ(conn, ਸੁਨੇਹਾ);
	sshbuf_free(ਸੁਨੇਹਾ);
	debug3("Sent %s message SSH2_FXP_OPEN I:%u P:%s M:0x%04x",
	    ਟੈਗ, id, ਰਸਤਾ, openmode);
	ਜੇ ((handle = get_handle(conn, id, &handle_len,
	    "%s open \"%s\"", ਟੈਗ, ਰਸਤਾ)) == ਨਿਰਾ)
		ਵਾਪਸ -1;
	/* success */
	*handlep = handle;
	*handle_lenp = handle_len;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਅਚਲ ਅੱਖਰ *
ਤਰੱਕੀ_meter_ਰਸਤਾ(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ)
{
	ਅਚਲ ਅੱਖਰ *progresspath;

	ਜੇ ((progresspath = strrchr(ਰਸਤਾ, '/')) == ਨਿਰਾ)
		ਵਾਪਸ ਰਸਤਾ;
	progresspath++;
	ਜੇ (*progresspath == '\0')
		ਵਾਪਸ ਰਸਤਾ;
	ਵਾਪਸ progresspath;
}

ਪੂਰਨ
sftp_download(ਬਣਤਰ sftp_conn *conn, ਅਚਲ ਅੱਖਰ *remote_ਰਸਤਾ,
    ਅਚਲ ਅੱਖਰ *local_ਰਸਤਾ, Attrib *a, ਪੂਰਨ preserve_flag, ਪੂਰਨ resume_flag,
    ਪੂਰਨ fsync_flag, ਪੂਰਨ inplace_flag)
{
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;
	u_char *handle;
	ਪੂਰਨ local_fd = -1, write_error, ਵੇਖਿਆ_zerolen = 0;
	ਪੂਰਨ read_error, write_errno, lmodified = 0, reordered = 0, r;
	uint64_t ਵਿੱਥ = 0, ਮਾਪ, highwater = 0, maxack = 0;
	u_int ਬਹੁਲਕ, id, buflen, ਅੰਕ_req, max_req, ਸਥਿਤੀ = SSH2_FX_OK;
	off_t ਤਰੱਕੀ_counter;
	ਮਾਪ_t handle_len;
	ਬਣਤਰ stat st;
	ਬਣਤਰ ਬੇਨਤੀਆਂ ਬੇਨਤੀਆਂ;
	ਬਣਤਰ request *req;
	u_char type;
	Attrib attr;

	debug2_f("download remote \"%s\" to local \"%s\"",
	    remote_ਰਸਤਾ, local_ਰਸਤਾ);

	TAILQ_INIT(&ਬੇਨਤੀਆਂ);

	ਜੇ (a == ਨਿਰਾ) {
		ਜੇ (sftp_stat(conn, remote_ਰਸਤਾ, 0, &attr) != 0)
			ਵਾਪਸ -1;
		a = &attr;
	}

	/* Do not preserve set[ug]id here, as we do not preserve ownership */
	ਜੇ (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS)
		ਬਹੁਲਕ = a->perm & 0777;
	ਨਹੀਂਤਾਂ
		ਬਹੁਲਕ = 0666;

	ਜੇ ((a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) &&
	    (!S_ISREG(a->perm))) {
		error("download %s: not a regular file", remote_ਰਸਤਾ);
		ਵਾਪਸ(-1);
	}

	ਜੇ (a->flags & SSH2_FILEXFER_ATTR_ਮਾਪ)
		ਮਾਪ = a->ਮਾਪ;
	ਨਹੀਂਤਾਂ
		ਮਾਪ = 0;

	buflen = conn->download_buflen;

	/* Send open request */
	ਜੇ (send_open(conn, remote_ਰਸਤਾ, "remote", SSH2_FXF_READ, ਨਿਰਾ,
	    &handle, &handle_len) != 0)
		ਵਾਪਸ -1;

	local_fd = open(local_ਰਸਤਾ, O_WRONLY | O_CREAT |
	((resume_flag || inplace_flag) ? 0 : O_TRUNC), ਬਹੁਲਕ | S_IWUSR);
	ਜੇ (local_fd == -1) {
		error("open local \"%s\": %s", local_ਰਸਤਾ, strerror(errno));
		ਜਾਓ fail;
	}
	ਜੇ (resume_flag) {
		ਜੇ (fstat(local_fd, &st) == -1) {
			error("stat local \"%s\": %s",
			    local_ਰਸਤਾ, strerror(errno));
			ਜਾਓ fail;
		}
		ਜੇ (st.st_size < 0) {
			error("\"%s\" has negative size", local_ਰਸਤਾ);
			ਜਾਓ fail;
		}
		ਜੇ ((uint64_t)st.st_size > ਮਾਪ) {
			error("Unable to resume download of \"%s\": "
			    "local file is larger than remote", local_ਰਸਤਾ);
 fail:
			sftp_close(conn, handle, handle_len);
			ਮੁਕਤ(handle);
			ਜੇ (local_fd != -1)
				close(local_fd);
			ਵਾਪਸ -1;
		}
		ਵਿੱਥ = highwater = maxack = st.st_size;
	}

	/* Read from remote and write to local */
	write_error = read_error = write_errno = ਅੰਕ_req = 0;
	max_req = 1;
	ਤਰੱਕੀ_counter = ਵਿੱਥ;

	ਜੇ (showprogress && ਮਾਪ != 0) {
		ਸ਼ੁਰੂ_ਤਰੱਕੀ_meter(ਤਰੱਕੀ_meter_ਰਸਤਾ(remote_ਰਸਤਾ),
		    ਮਾਪ, &ਤਰੱਕੀ_counter);
	}

	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");

	ਜਦੋਂ (ਅੰਕ_req > 0 || max_req > 0) {
		u_char *ਅੰਕੜੇ;
		ਮਾਪ_t len;

		/*
		 * Simulate EOF on interrupt: stop sending new requests and
		 * allow outstanding requests to drain gracefully
		 */
		ਜੇ (interrupted) {
			ਜੇ (ਅੰਕ_req == 0) /* If we haven't started yet... */
				ਰੋਕੋ;
			max_req = 0;
		}

		/* Send some more requests */
		ਜਦੋਂ (ਅੰਕ_req < max_req) {
			debug3("Request range %llu -> %llu (%d/%d)",
			    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)ਵਿੱਥ,
			    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)ਵਿੱਥ + buflen - 1,
			    ਅੰਕ_req, max_req);
			req = request_ਕਤਾਰ_ਵਿੱਚ_ਪਾਓ(&ਬੇਨਤੀਆਂ, conn->ਸੁਨੇਹਾ_id++,
			    buflen, ਵਿੱਥ);
			ਵਿੱਥ += buflen;
			ਅੰਕ_req++;
			send_read_request(conn, req->id, req->ਵਿੱਥ,
			    req->len, handle, handle_len);
		}

		sshbuf_reset(ਸੁਨੇਹਾ);
		get_ਸੁਨੇਹਾ(conn, ਸੁਨੇਹਾ);
		ਜੇ ((r = sshbuf_get_u8(ਸੁਨੇਹਾ, &type)) != 0 ||
		    (r = sshbuf_get_u32(ਸੁਨੇਹਾ, &id)) != 0)
			fatal_fr(r, "parse");
		debug3("Received reply T:%u I:%u R:%d", type, id, max_req);

		/* Find the request in our queue */
		ਜੇ ((req = request_ਲੱਭੋ(&ਬੇਨਤੀਆਂ, id)) == ਨਿਰਾ)
			fatal("Unexpected reply %u", id);

		ਚੋਣ (type) {
		ਹਾਲਤ SSH2_FXP_ਸਥਿਤੀ:
			ਜੇ ((r = sshbuf_get_u32(ਸੁਨੇਹਾ, &ਸਥਿਤੀ)) != 0)
				fatal_fr(r, "parse status");
			ਜੇ (ਸਥਿਤੀ != SSH2_FX_EOF)
				read_error = 1;
			max_req = 0;
			TAILQ_REMOVE(&ਬੇਨਤੀਆਂ, req, tq);
			ਮੁਕਤ(req);
			ਅੰਕ_req--;
			ਰੋਕੋ;
		ਹਾਲਤ SSH2_FXP_ਅੰਕੜੇ:
			ਜੇ ((r = sshbuf_get_string(ਸੁਨੇਹਾ, &ਅੰਕੜੇ, &len)) != 0)
				fatal_fr(r, "parse data");
			debug3("Received data %llu -> %llu",
			    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)req->ਵਿੱਥ,
			    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)req->ਵਿੱਥ + len - 1);
			ਜੇ (len > req->len)
				fatal("Received more data than asked for "
				    "%zu > %zu", len, req->len);
			ਜੇ (len == 0) {
				ਜੇ (ਵੇਖਿਆ_zerolen)
					fatal_f("server sent zero data length");
				ਵੇਖਿਆ_zerolen = 1;
			}
			lmodified = 1;
			ਜੇ ((lseek(local_fd, req->ਵਿੱਥ, SEEK_SET) == -1 ||
			    atomicio(vwrite, local_fd, ਅੰਕੜੇ, len) != len) &&
			    !write_error) {
				write_errno = errno;
				write_error = 1;
				max_req = 0;
			} ਨਹੀਂਤਾਂ {
				/*
				 * Track both the highest offset acknowledged
				 * and the highest *contiguous* offset
				 * acknowledged.
				 * We'll need the latter for ftruncate()ing
				 * interrupted transfers.
				 */
				ਜੇ (maxack < req->ਵਿੱਥ + len)
					maxack = req->ਵਿੱਥ + len;
				ਜੇ (!reordered && req->ਵਿੱਥ <= highwater)
					highwater = maxack;
				ਨਹੀਂਤਾਂ ਜੇ (!reordered && req->ਵਿੱਥ > highwater)
					reordered = 1;
			}
			ਤਰੱਕੀ_counter += len;
			ਮੁਕਤ(ਅੰਕੜੇ);

			ਜੇ (len == req->len) {
				TAILQ_REMOVE(&ਬੇਨਤੀਆਂ, req, tq);
				ਮੁਕਤ(req);
				ਅੰਕ_req--;
			} ਨਹੀਂਤਾਂ {
				/* Resend the request for the missing data */
				debug3("Short data block, re-requesting "
				    "%llu -> %llu (%2d)",
				    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)req->ਵਿੱਥ + len,
				    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)req->ਵਿੱਥ +
				    req->len - 1, ਅੰਕ_req);
				req->id = conn->ਸੁਨੇਹਾ_id++;
				req->len -= len;
				req->ਵਿੱਥ += len;
				send_read_request(conn, req->id,
				    req->ਵਿੱਥ, req->len, handle, handle_len);
				/* Reduce the request size */
				ਜੇ (len < buflen)
					buflen = ਵੱਧ_ਤੋਂ_ਵੱਧ(MIN_READ_ਮਾਪ, len);
			}
			ਜੇ (max_req > 0) { /* max_req = 0 iff EOF received */
				ਜੇ (ਮਾਪ > 0 && ਵਿੱਥ > ਮਾਪ) {
					/* Only one request at a time
					 * after the expected EOF */
					debug3("Finish at %llu (%2d)",
					    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)ਵਿੱਥ,
					    ਅੰਕ_req);
					max_req = 1;
				} ਨਹੀਂਤਾਂ ਜੇ (max_req < conn->ਅੰਕ_ਬੇਨਤੀਆਂ) {
					++max_req;
				}
			}
			ਰੋਕੋ;
		ਮੂਲ:
			fatal("Expected SSH2_FXP_DATA(%u) packet, got %u",
			    SSH2_FXP_ਅੰਕੜੇ, type);
		}
	}

	ਜੇ (showprogress && ਮਾਪ)
		stop_ਤਰੱਕੀ_meter();

	/* Sanity check */
	ਜੇ (TAILQ_FIRST(&ਬੇਨਤੀਆਂ) != ਨਿਰਾ)
		fatal("Transfer complete, but requests still in queue");

	ਜੇ (!read_error && !write_error && !interrupted) {
		/* we got everything */
		highwater = maxack;
	}

	/*
	 * Truncate at highest contiguous point to avoid holes on interrupt,
	 * or unconditionally if writing in place.
	 */
	ਜੇ (inplace_flag || read_error || write_error || interrupted) {
		ਜੇ (reordered && resume_flag &&
		    (read_error || write_error || interrupted)) {
			error("Unable to resume download of \"%s\": "
			    "server reordered requests", local_ਰਸਤਾ);
		}
		debug("truncating at %llu", (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)highwater);
		ਜੇ (ftruncate(local_fd, highwater) == -1)
			error("local ftruncate \"%s\": %s", local_ਰਸਤਾ,
			    strerror(errno));
	}
	ਜੇ (read_error) {
		error("read remote \"%s\" : %s", remote_ਰਸਤਾ, fx2txt(ਸਥਿਤੀ));
		ਸਥਿਤੀ = -1;
		sftp_close(conn, handle, handle_len);
	} ਨਹੀਂਤਾਂ ਜੇ (write_error) {
		error("write local \"%s\": %s", local_ਰਸਤਾ,
		    strerror(write_errno));
		ਸਥਿਤੀ = SSH2_FX_FAILURE;
		sftp_close(conn, handle, handle_len);
	} ਨਹੀਂਤਾਂ {
		ਜੇ (sftp_close(conn, handle, handle_len) != 0 || interrupted)
			ਸਥਿਤੀ = SSH2_FX_FAILURE;
		ਨਹੀਂਤਾਂ
			ਸਥਿਤੀ = SSH2_FX_OK;
		/* Override umask and utimes if asked */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_FCHMOD
		ਜੇ (preserve_flag && fchmod(local_fd, ਬਹੁਲਕ) == -1)
#ਨਹੀਂਤਾਂ
		ਜੇ (preserve_flag && chmod(local_ਰਸਤਾ, ਬਹੁਲਕ) == -1)
#ਜੇ_ਅੰਤ /* HAVE_FCHMOD */
			error("local chmod \"%s\": %s", local_ਰਸਤਾ,
			    strerror(errno));
		ਜੇ (preserve_flag &&
		    (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME)) {
			ਬਣਤਰ timeval tv[2];
			tv[0].tv_sec = a->atime;
			tv[1].tv_sec = a->mtime;
			tv[0].tv_usec = tv[1].tv_usec = 0;
			ਜੇ (utimes(local_ਰਸਤਾ, tv) == -1)
				error("local set times \"%s\": %s",
				    local_ਰਸਤਾ, strerror(errno));
		}
		ਜੇ (resume_flag && !lmodified)
			logit("File \"%s\" was not modified", local_ਰਸਤਾ);
		ਨਹੀਂਤਾਂ ਜੇ (fsync_flag) {
			debug("syncing \"%s\"", local_ਰਸਤਾ);
			ਜੇ (fsync(local_fd) == -1)
				error("local sync \"%s\": %s",
				    local_ਰਸਤਾ, strerror(errno));
		}
	}
	close(local_fd);
	sshbuf_free(ਸੁਨੇਹਾ);
	ਮੁਕਤ(handle);

	ਵਾਪਸ ਸਥਿਤੀ == SSH2_FX_OK ? 0 : -1;
}

ਸਥਿਰ ਪੂਰਨ
download_dir_ਅੰਦਰੂਨੀ(ਬਣਤਰ sftp_conn *conn, ਅਚਲ ਅੱਖਰ *src, ਅਚਲ ਅੱਖਰ *dst,
    ਪੂਰਨ ਡੂੰਘਾਈ, Attrib *dirattrib, ਪੂਰਨ preserve_flag, ਪੂਰਨ print_flag,
    ਪੂਰਨ resume_flag, ਪੂਰਨ fsync_flag, ਪੂਰਨ follow_link_flag, ਪੂਰਨ inplace_flag)
{
	ਪੂਰਨ i, ret = 0;
	SFTP_DIRENT **dir_entries;
	ਅੱਖਰ *filename, *new_src = ਨਿਰਾ, *new_dst = ਨਿਰਾ;
	ਬਹੁਲਕ_t ਬਹੁਲਕ = 0777, tmpmode = ਬਹੁਲਕ;
	Attrib *a, ldirattrib, lsym;

	ਜੇ (ਡੂੰਘਾਈ >= MAX_DIR_ਡੂੰਘਾਈ) {
		error("Maximum directory depth exceeded: %d levels", ਡੂੰਘਾਈ);
		ਵਾਪਸ -1;
	}

	debug2_f("download dir remote \"%s\" to local \"%s\"", src, dst);

	ਜੇ (dirattrib == ਨਿਰਾ) {
		ਜੇ (sftp_stat(conn, src, 1, &ldirattrib) != 0) {
			error("stat remote \"%s\" directory failed", src);
			ਵਾਪਸ -1;
		}
		dirattrib = &ldirattrib;
	}
	ਜੇ (!S_ISDIR(dirattrib->perm)) {
		error("\"%s\" is not a directory", src);
		ਵਾਪਸ -1;
	}
	ਜੇ (print_flag && print_flag != SFTP_ਤਰੱਕੀ_ONLY)
		mprintf("Retrieving %s\n", src);

	ਜੇ (dirattrib->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		ਬਹੁਲਕ = dirattrib->perm & 01777;
		tmpmode = ਬਹੁਲਕ | (S_IWUSR|S_IXUSR);
	} ਨਹੀਂਤਾਂ {
		debug("download remote \"%s\": server "
		    "did not send permissions", dst);
	}

	ਜੇ (mkdir(dst, tmpmode) == -1 && errno != EEXIST) {
		error("mkdir %s: %s", dst, strerror(errno));
		ਵਾਪਸ -1;
	}

	ਜੇ (sftp_readdir(conn, src, &dir_entries) == -1) {
		error("remote readdir \"%s\" failed", src);
		ਵਾਪਸ -1;
	}

	ਲਈ (i = 0; dir_entries[i] != ਨਿਰਾ && !interrupted; i++) {
		ਮੁਕਤ(new_dst);
		ਮੁਕਤ(new_src);

		filename = dir_entries[i]->filename;
		new_dst = sftp_ਰਸਤਾ_append(dst, filename);
		new_src = sftp_ਰਸਤਾ_append(src, filename);

		a = &dir_entries[i]->a;
		ਜੇ (S_ISLNK(a->perm)) {
			ਜੇ (!follow_link_flag) {
				logit("download \"%s\": not a regular file",
				    new_src);
				ਜਾਰੀ;
			}
			/* Replace the stat contents with the symlink target */
			ਜੇ (sftp_stat(conn, new_src, 1, &lsym) != 0) {
				logit("remote stat \"%s\" failed", new_src);
				ret = -1;
				ਜਾਰੀ;
			}
			a = &lsym;
		}

		ਜੇ (S_ISDIR(a->perm)) {
			ਜੇ (strcmp(filename, ".") == 0 ||
			    strcmp(filename, "..") == 0)
				ਜਾਰੀ;
			ਜੇ (download_dir_ਅੰਦਰੂਨੀ(conn, new_src, new_dst,
			    ਡੂੰਘਾਈ + 1, a, preserve_flag,
			    print_flag, resume_flag,
			    fsync_flag, follow_link_flag, inplace_flag) == -1)
				ret = -1;
		} ਨਹੀਂਤਾਂ ਜੇ (S_ISREG(a->perm)) {
			ਜੇ (sftp_download(conn, new_src, new_dst, a,
			    preserve_flag, resume_flag, fsync_flag,
			    inplace_flag) == -1) {
				error("Download of file %s to %s failed",
				    new_src, new_dst);
				ret = -1;
			}
		} ਨਹੀਂਤਾਂ
			logit("download \"%s\": not a regular file", new_src);

	}
	ਮੁਕਤ(new_dst);
	ਮੁਕਤ(new_src);

	ਜੇ (preserve_flag) {
		ਜੇ (dirattrib->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
			ਬਣਤਰ timeval tv[2];
			tv[0].tv_sec = dirattrib->atime;
			tv[1].tv_sec = dirattrib->mtime;
			tv[0].tv_usec = tv[1].tv_usec = 0;
			ਜੇ (utimes(dst, tv) == -1)
				error("local set times on \"%s\": %s",
				    dst, strerror(errno));
		} ਨਹੀਂਤਾਂ
			debug("Server did not send times for directory "
			    "\"%s\"", dst);
	}

	ਜੇ (ਬਹੁਲਕ != tmpmode && chmod(dst, ਬਹੁਲਕ) == -1)
		error("local chmod directory \"%s\": %s", dst,
		    strerror(errno));

	sftp_free_dirents(dir_entries);

	ਵਾਪਸ ret;
}

ਪੂਰਨ
sftp_download_dir(ਬਣਤਰ sftp_conn *conn, ਅਚਲ ਅੱਖਰ *src, ਅਚਲ ਅੱਖਰ *dst,
    Attrib *dirattrib, ਪੂਰਨ preserve_flag, ਪੂਰਨ print_flag, ਪੂਰਨ resume_flag,
    ਪੂਰਨ fsync_flag, ਪੂਰਨ follow_link_flag, ਪੂਰਨ inplace_flag)
{
	ਅੱਖਰ *src_canon;
	ਪੂਰਨ ret;

	ਜੇ ((src_canon = sftp_realpath(conn, src)) == ਨਿਰਾ) {
		error("download \"%s\": path canonicalization failed", src);
		ਵਾਪਸ -1;
	}

	ret = download_dir_ਅੰਦਰੂਨੀ(conn, src_canon, dst, 0,
	    dirattrib, preserve_flag, print_flag, resume_flag, fsync_flag,
	    follow_link_flag, inplace_flag);
	ਮੁਕਤ(src_canon);
	ਵਾਪਸ ret;
}

ਪੂਰਨ
sftp_upload(ਬਣਤਰ sftp_conn *conn, ਅਚਲ ਅੱਖਰ *local_ਰਸਤਾ,
    ਅਚਲ ਅੱਖਰ *remote_ਰਸਤਾ, ਪੂਰਨ preserve_flag, ਪੂਰਨ resume,
    ਪੂਰਨ fsync_flag, ਪੂਰਨ inplace_flag)
{
	ਪੂਰਨ r, local_fd;
	u_int openmode, id, ਸਥਿਤੀ = SSH2_FX_OK, status2, reordered = 0;
	off_t ਵਿੱਥ, ਤਰੱਕੀ_counter;
	u_char type, *handle, *ਅੰਕੜੇ;
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;
	ਬਣਤਰ stat sb;
	Attrib a, t, c;
	uint32_t startid, ackid;
	uint64_t highwater = 0, maxack = 0;
	ਬਣਤਰ request *ack = ਨਿਰਾ;
	ਬਣਤਰ ਬੇਨਤੀਆਂ acks;
	ਮਾਪ_t handle_len;

	debug2_f("upload local \"%s\" to remote \"%s\"",
	    local_ਰਸਤਾ, remote_ਰਸਤਾ);

	TAILQ_INIT(&acks);

	ਜੇ ((local_fd = open(local_ਰਸਤਾ, O_RDONLY)) == -1) {
		error("open local \"%s\": %s", local_ਰਸਤਾ, strerror(errno));
		ਵਾਪਸ(-1);
	}
	ਜੇ (fstat(local_fd, &sb) == -1) {
		error("fstat local \"%s\": %s", local_ਰਸਤਾ, strerror(errno));
		close(local_fd);
		ਵਾਪਸ(-1);
	}
	ਜੇ (!S_ISREG(sb.st_mode)) {
		error("local \"%s\" is not a regular file", local_ਰਸਤਾ);
		close(local_fd);
		ਵਾਪਸ(-1);
	}
	stat_ਮੰਜ਼ਿਲ_attrib(&sb, &a);

	a.flags &= ~SSH2_FILEXFER_ATTR_ਮਾਪ;
	a.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a.perm &= 0777;
	ਜੇ (!preserve_flag)
		a.flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;

	ਜੇ (resume) {
		/* Get remote file size if it exists */
		ਜੇ (sftp_stat(conn, remote_ਰਸਤਾ, 0, &c) != 0) {
			close(local_fd);
			ਵਾਪਸ -1;
		}

		ਜੇ ((off_t)c.ਮਾਪ >= sb.st_size) {
			error("resume \"%s\": destination file "
			    "same size or larger", local_ਰਸਤਾ);
			close(local_fd);
			ਵਾਪਸ -1;
		}

		ਜੇ (lseek(local_fd, (off_t)c.ਮਾਪ, SEEK_SET) == -1) {
			close(local_fd);
			ਵਾਪਸ -1;
		}
		highwater = c.ਮਾਪ;
	}

	openmode = SSH2_FXF_WRITE|SSH2_FXF_CREAT;
	ਜੇ (resume)
		openmode |= SSH2_FXF_APPEND;
	ਨਹੀਂਤਾਂ ਜੇ (!inplace_flag)
		openmode |= SSH2_FXF_TRUNC;

	/* Send open request */
	ਜੇ (send_open(conn, remote_ਰਸਤਾ, "dest", openmode, &a,
	    &handle, &handle_len) != 0) {
		close(local_fd);
		ਵਾਪਸ -1;
	}

	id = conn->ਸੁਨੇਹਾ_id;
	startid = ackid = id + 1;
	ਅੰਕੜੇ = xmalloc(conn->upload_buflen);

	/* Read from local and write to remote */
	ਵਿੱਥ = ਤਰੱਕੀ_counter = (resume ? c.ਮਾਪ : 0);
	ਜੇ (showprogress) {
		ਸ਼ੁਰੂ_ਤਰੱਕੀ_meter(ਤਰੱਕੀ_meter_ਰਸਤਾ(local_ਰਸਤਾ),
		    sb.st_size, &ਤਰੱਕੀ_counter);
	}

	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਲਈ (;;) {
		ਪੂਰਨ len;

		/*
		 * Can't use atomicio here because it returns 0 on EOF,
		 * thus losing the last block of the file.
		 * Simulate an EOF on interrupt, allowing ACKs from the
		 * server to drain.
		 */
		ਜੇ (interrupted || ਸਥਿਤੀ != SSH2_FX_OK)
			len = 0;
		ਨਹੀਂਤਾਂ ਕਰੋ
			len = ਪਠ(local_fd, ਅੰਕੜੇ, conn->upload_buflen);
		ਜਦੋਂ ((len == -1) &&
		    (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK));

		ਜੇ (len == -1) {
			fatal("read local \"%s\": %s",
			    local_ਰਸਤਾ, strerror(errno));
		} ਨਹੀਂਤਾਂ ਜੇ (len != 0) {
			ack = request_ਕਤਾਰ_ਵਿੱਚ_ਪਾਓ(&acks, ++id, len, ਵਿੱਥ);
			sshbuf_reset(ਸੁਨੇਹਾ);
			ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, SSH2_FXP_WRITE)) != 0 ||
			    (r = sshbuf_put_u32(ਸੁਨੇਹਾ, ack->id)) != 0 ||
			    (r = sshbuf_put_string(ਸੁਨੇਹਾ, handle,
			    handle_len)) != 0 ||
			    (r = sshbuf_put_u64(ਸੁਨੇਹਾ, ਵਿੱਥ)) != 0 ||
			    (r = sshbuf_put_string(ਸੁਨੇਹਾ, ਅੰਕੜੇ, len)) != 0)
				fatal_fr(r, "compose");
			send_ਸੁਨੇਹਾ(conn, ਸੁਨੇਹਾ);
			debug3("Sent message SSH2_FXP_WRITE I:%u O:%llu S:%u",
			    id, (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)ਵਿੱਥ, len);
		} ਨਹੀਂਤਾਂ ਜੇ (TAILQ_FIRST(&acks) == ਨਿਰਾ)
			ਰੋਕੋ;

		ਜੇ (ack == ਨਿਰਾ)
			fatal("Unexpected ACK %u", id);

		ਜੇ (id == startid || len == 0 ||
		    id - ackid >= conn->ਅੰਕ_ਬੇਨਤੀਆਂ) {
			u_int rid;

			sshbuf_reset(ਸੁਨੇਹਾ);
			get_ਸੁਨੇਹਾ(conn, ਸੁਨੇਹਾ);
			ਜੇ ((r = sshbuf_get_u8(ਸੁਨੇਹਾ, &type)) != 0 ||
			    (r = sshbuf_get_u32(ਸੁਨੇਹਾ, &rid)) != 0)
				fatal_fr(r, "parse");

			ਜੇ (type != SSH2_FXP_ਸਥਿਤੀ)
				fatal("Expected SSH2_FXP_STATUS(%d) packet, "
				    "got %d", SSH2_FXP_ਸਥਿਤੀ, type);

			ਜੇ ((r = sshbuf_get_u32(ਸੁਨੇਹਾ, &status2)) != 0)
				fatal_fr(r, "parse status");
			debug3("SSH2_FXP_STATUS %u", status2);
			ਜੇ (status2 != SSH2_FX_OK)
				ਸਥਿਤੀ = status2; /* remember errors */

			/* Find the request in our queue */
			ਜੇ ((ack = request_ਲੱਭੋ(&acks, rid)) == ਨਿਰਾ)
				fatal("Can't find request for ID %u", rid);
			TAILQ_REMOVE(&acks, ack, tq);
			debug3("In write loop, ack for %u %zu bytes at %lld",
			    ack->id, ack->len, (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)ack->ਵਿੱਥ);
			++ackid;
			ਤਰੱਕੀ_counter += ack->len;
			/*
			 * Track both the highest offset acknowledged and the
			 * highest *contiguous* offset acknowledged.
			 * We'll need the latter for ftruncate()ing
			 * interrupted transfers.
			 */
			ਜੇ (maxack < ack->ਵਿੱਥ + ack->len)
				maxack = ack->ਵਿੱਥ + ack->len;
			ਜੇ (!reordered && ack->ਵਿੱਥ <= highwater)
				highwater = maxack;
			ਨਹੀਂਤਾਂ ਜੇ (!reordered && ack->ਵਿੱਥ > highwater) {
				debug3_f("server reordered ACKs");
				reordered = 1;
			}
			ਮੁਕਤ(ack);
		}
		ਵਿੱਥ += len;
		ਜੇ (ਵਿੱਥ < 0)
			fatal_f("offset < 0");
	}
	sshbuf_free(ਸੁਨੇਹਾ);

	ਜੇ (showprogress)
		stop_ਤਰੱਕੀ_meter();
	ਮੁਕਤ(ਅੰਕੜੇ);

	ਜੇ (ਸਥਿਤੀ == SSH2_FX_OK && !interrupted) {
		/* we got everything */
		highwater = maxack;
	}
	ਜੇ (ਸਥਿਤੀ != SSH2_FX_OK) {
		error("write remote \"%s\": %s", remote_ਰਸਤਾ, fx2txt(ਸਥਿਤੀ));
		ਸਥਿਤੀ = SSH2_FX_FAILURE;
	}

	ਜੇ (inplace_flag || (resume && (ਸਥਿਤੀ != SSH2_FX_OK || interrupted))) {
		debug("truncating at %llu", (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)highwater);
		attrib_clear(&t);
		t.flags = SSH2_FILEXFER_ATTR_ਮਾਪ;
		t.ਮਾਪ = highwater;
		sftp_fsetstat(conn, handle, handle_len, &t);
	}

	ਜੇ (close(local_fd) == -1) {
		error("close local \"%s\": %s", local_ਰਸਤਾ, strerror(errno));
		ਸਥਿਤੀ = SSH2_FX_FAILURE;
	}

	/* Override umask and utimes if asked */
	ਜੇ (preserve_flag)
		sftp_fsetstat(conn, handle, handle_len, &a);

	ਜੇ (fsync_flag)
		(ਖਾਲੀ)sftp_fsync(conn, handle, handle_len);

	ਜੇ (sftp_close(conn, handle, handle_len) != 0)
		ਸਥਿਤੀ = SSH2_FX_FAILURE;

	ਮੁਕਤ(handle);

	ਵਾਪਸ ਸਥਿਤੀ == SSH2_FX_OK ? 0 : -1;
}

ਸਥਿਰ ਪੂਰਨ
upload_dir_ਅੰਦਰੂਨੀ(ਬਣਤਰ sftp_conn *conn, ਅਚਲ ਅੱਖਰ *src, ਅਚਲ ਅੱਖਰ *dst,
    ਪੂਰਨ ਡੂੰਘਾਈ, ਪੂਰਨ preserve_flag, ਪੂਰਨ print_flag, ਪੂਰਨ resume, ਪੂਰਨ fsync_flag,
    ਪੂਰਨ follow_link_flag, ਪੂਰਨ inplace_flag)
{
	ਪੂਰਨ created = 0, ret = 0;
	DIR *dirp;
	ਬਣਤਰ dirent *dp;
	ਅੱਖਰ *filename, *new_src = ਨਿਰਾ, *new_dst = ਨਿਰਾ;
	ਬਣਤਰ stat sb;
	Attrib a, dirattrib;
	uint32_t saved_perm;

	debug2_f("upload local dir \"%s\" to remote \"%s\"", src, dst);

	ਜੇ (ਡੂੰਘਾਈ >= MAX_DIR_ਡੂੰਘਾਈ) {
		error("Maximum directory depth exceeded: %d levels", ਡੂੰਘਾਈ);
		ਵਾਪਸ -1;
	}

	ਜੇ (stat(src, &sb) == -1) {
		error("stat local \"%s\": %s", src, strerror(errno));
		ਵਾਪਸ -1;
	}
	ਜੇ (!S_ISDIR(sb.st_mode)) {
		error("\"%s\" is not a directory", src);
		ਵਾਪਸ -1;
	}
	ਜੇ (print_flag && print_flag != SFTP_ਤਰੱਕੀ_ONLY)
		mprintf("Entering %s\n", src);

	stat_ਮੰਜ਼ਿਲ_attrib(&sb, &a);
	a.flags &= ~SSH2_FILEXFER_ATTR_ਮਾਪ;
	a.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a.perm &= 01777;
	ਜੇ (!preserve_flag)
		a.flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;

	/*
	 * sftp lacks a portable status value to match errno EEXIST,
	 * so if we get a failure back then we must check whether
	 * the path already existed and is a directory.  Ensure we can
	 * write to the directory we create for the duration of the transfer.
	 */
	saved_perm = a.perm;
	a.perm |= (S_IWUSR|S_IXUSR);
	ਜੇ (sftp_mkdir(conn, dst, &a, 0) == 0)
		created = 1;
	ਨਹੀਂਤਾਂ {
		ਜੇ (sftp_stat(conn, dst, 0, &dirattrib) != 0)
			ਵਾਪਸ -1;
		ਜੇ (!S_ISDIR(dirattrib.perm)) {
			error("\"%s\" exists but is not a directory", dst);
			ਵਾਪਸ -1;
		}
	}
	a.perm = saved_perm;

	ਜੇ ((dirp = opendir(src)) == ਨਿਰਾ) {
		error("local opendir \"%s\": %s", src, strerror(errno));
		ਵਾਪਸ -1;
	}

	ਜਦੋਂ (((dp = readdir(dirp)) != ਨਿਰਾ) && !interrupted) {
		ਜੇ (dp->d_ino == 0)
			ਜਾਰੀ;
		ਮੁਕਤ(new_dst);
		ਮੁਕਤ(new_src);
		filename = dp->d_name;
		new_dst = sftp_ਰਸਤਾ_append(dst, filename);
		new_src = sftp_ਰਸਤਾ_append(src, filename);

		ਜੇ (strcmp(filename, ".") == 0 || strcmp(filename, "..") == 0)
			ਜਾਰੀ;
		ਜੇ (lstat(new_src, &sb) == -1) {
			logit("local lstat \"%s\": %s", filename,
			    strerror(errno));
			ret = -1;
			ਜਾਰੀ;
		}
		ਜੇ (S_ISLNK(sb.st_mode)) {
			ਜੇ (!follow_link_flag) {
				logit("%s: not a regular file", filename);
				ਜਾਰੀ;
			}
			/* Replace the stat contents with the symlink target */
			ਜੇ (stat(new_src, &sb) == -1) {
				logit("local stat \"%s\": %s", filename,
				    strerror(errno));
				ret = -1;
				ਜਾਰੀ;
			}
		}
		ਜੇ (S_ISDIR(sb.st_mode)) {
			ਜੇ (upload_dir_ਅੰਦਰੂਨੀ(conn, new_src, new_dst,
			    ਡੂੰਘਾਈ + 1, preserve_flag, print_flag, resume,
			    fsync_flag, follow_link_flag, inplace_flag) == -1)
				ret = -1;
		} ਨਹੀਂਤਾਂ ਜੇ (S_ISREG(sb.st_mode)) {
			ਜੇ (sftp_upload(conn, new_src, new_dst,
			    preserve_flag, resume, fsync_flag,
			    inplace_flag) == -1) {
				error("upload \"%s\" to \"%s\" failed",
				    new_src, new_dst);
				ret = -1;
			}
		} ਨਹੀਂਤਾਂ
			logit("%s: not a regular file", filename);
	}
	ਮੁਕਤ(new_dst);
	ਮੁਕਤ(new_src);

	ਜੇ (created || preserve_flag)
		sftp_setstat(conn, dst, &a);

	(ਖਾਲੀ) closedir(dirp);
	ਵਾਪਸ ret;
}

ਪੂਰਨ
sftp_upload_dir(ਬਣਤਰ sftp_conn *conn, ਅਚਲ ਅੱਖਰ *src, ਅਚਲ ਅੱਖਰ *dst,
    ਪੂਰਨ preserve_flag, ਪੂਰਨ print_flag, ਪੂਰਨ resume, ਪੂਰਨ fsync_flag,
    ਪੂਰਨ follow_link_flag, ਪੂਰਨ inplace_flag)
{
	ਅੱਖਰ *dst_canon;
	ਪੂਰਨ ret;

	ਜੇ ((dst_canon = sftp_realpath(conn, dst)) == ਨਿਰਾ) {
		error("upload \"%s\": path canonicalization failed", dst);
		ਵਾਪਸ -1;
	}

	ret = upload_dir_ਅੰਦਰੂਨੀ(conn, src, dst_canon, 0, preserve_flag,
	    print_flag, resume, fsync_flag, follow_link_flag, inplace_flag);

	ਮੁਕਤ(dst_canon);
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਖਾਲੀ
handle_dest_replies(ਬਣਤਰ sftp_conn *ਮੰਜ਼ਿਲ, ਅਚਲ ਅੱਖਰ *ਮੰਜ਼ਿਲ_ਰਸਤਾ, ਪੂਰਨ synchronous,
    u_int *nreqsp, u_int *write_errorp)
{
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;
	u_char type;
	u_int id, ਸਥਿਤੀ;
	ਪੂਰਨ r;
	ਬਣਤਰ pollfd pfd;

	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");

	/* Try to eat replies from the upload side */
	ਜਦੋਂ (*nreqsp > 0) {
		debug3_f("%u outstanding replies", *nreqsp);
		ਜੇ (!synchronous) {
			/* Bail out if no data is ready to be read */
			pfd.fd = ਮੰਜ਼ਿਲ->fd_ਵਿੱਚ;
			pfd.events = POLLIN;
			ਜੇ ((r = poll(&pfd, 1, 0)) == -1) {
				ਜੇ (errno == EINTR)
					ਰੋਕੋ;
				fatal_f("poll: %s", strerror(errno));
			} ਨਹੀਂਤਾਂ ਜੇ (r == 0)
				ਰੋਕੋ; /* fd not ready */
		}
		sshbuf_reset(ਸੁਨੇਹਾ);
		get_ਸੁਨੇਹਾ(ਮੰਜ਼ਿਲ, ਸੁਨੇਹਾ);

		ਜੇ ((r = sshbuf_get_u8(ਸੁਨੇਹਾ, &type)) != 0 ||
		    (r = sshbuf_get_u32(ਸੁਨੇਹਾ, &id)) != 0)
			fatal_fr(r, "dest parse");
		debug3("Received dest reply T:%u I:%u R:%u", type, id, *nreqsp);
		ਜੇ (type != SSH2_FXP_ਸਥਿਤੀ) {
			fatal_f("Expected SSH2_FXP_STATUS(%d) packet, got %d",
			    SSH2_FXP_ਸਥਿਤੀ, type);
		}
		ਜੇ ((r = sshbuf_get_u32(ਸੁਨੇਹਾ, &ਸਥਿਤੀ)) != 0)
			fatal_fr(r, "parse dest status");
		debug3("dest SSH2_FXP_STATUS %u", ਸਥਿਤੀ);
		ਜੇ (ਸਥਿਤੀ != SSH2_FX_OK) {
			/* record first error */
			ਜੇ (*write_errorp == 0)
				*write_errorp = ਸਥਿਤੀ;
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
	sshbuf_free(ਸੁਨੇਹਾ);
}

ਪੂਰਨ
sftp_crossload(ਬਣਤਰ sftp_conn *from, ਬਣਤਰ sftp_conn *ਮੰਜ਼ਿਲ,
    ਅਚਲ ਅੱਖਰ *from_ਰਸਤਾ, ਅਚਲ ਅੱਖਰ *ਮੰਜ਼ਿਲ_ਰਸਤਾ,
    Attrib *a, ਪੂਰਨ preserve_flag)
{
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;
	ਪੂਰਨ write_error, read_error, r, ਵੇਖਿਆ_zerolen = 0;
	uint64_t ਵਿੱਥ = 0, ਮਾਪ;
	u_int id, buflen, ਅੰਕ_req, max_req, ਸਥਿਤੀ = SSH2_FX_OK;
	u_int ਅੰਕ_upload_req;
	off_t ਤਰੱਕੀ_counter;
	u_char *from_handle, *ਮੰਜ਼ਿਲ_handle;
	ਮਾਪ_t from_handle_len, ਮੰਜ਼ਿਲ_handle_len;
	ਬਣਤਰ ਬੇਨਤੀਆਂ ਬੇਨਤੀਆਂ;
	ਬਣਤਰ request *req;
	u_char type;
	Attrib attr;

	debug2_f("crossload src \"%s\" to dst \"%s\"", from_ਰਸਤਾ, ਮੰਜ਼ਿਲ_ਰਸਤਾ);

	TAILQ_INIT(&ਬੇਨਤੀਆਂ);

	ਜੇ (a == ਨਿਰਾ) {
		ਜੇ (sftp_stat(from, from_ਰਸਤਾ, 0, &attr) != 0)
			ਵਾਪਸ -1;
		a = &attr;
	}

	ਜੇ ((a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) &&
	    (!S_ISREG(a->perm))) {
		error("download \"%s\": not a regular file", from_ਰਸਤਾ);
		ਵਾਪਸ(-1);
	}
	ਜੇ (a->flags & SSH2_FILEXFER_ATTR_ਮਾਪ)
		ਮਾਪ = a->ਮਾਪ;
	ਨਹੀਂਤਾਂ
		ਮਾਪ = 0;

	buflen = from->download_buflen;
	ਜੇ (buflen > ਮੰਜ਼ਿਲ->upload_buflen)
		buflen = ਮੰਜ਼ਿਲ->upload_buflen;

	/* Send open request to read side */
	ਜੇ (send_open(from, from_ਰਸਤਾ, "origin", SSH2_FXF_READ, ਨਿਰਾ,
	    &from_handle, &from_handle_len) != 0)
		ਵਾਪਸ -1;

	/* Send open request to write side */
	a->flags &= ~SSH2_FILEXFER_ATTR_ਮਾਪ;
	a->flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a->perm &= 0777;
	ਜੇ (!preserve_flag)
		a->flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;
	ਜੇ (send_open(ਮੰਜ਼ਿਲ, ਮੰਜ਼ਿਲ_ਰਸਤਾ, "dest",
	    SSH2_FXF_WRITE|SSH2_FXF_CREAT|SSH2_FXF_TRUNC, a,
	    &ਮੰਜ਼ਿਲ_handle, &ਮੰਜ਼ਿਲ_handle_len) != 0) {
		sftp_close(from, from_handle, from_handle_len);
		ਵਾਪਸ -1;
	}

	/* Read from remote "from" and write to remote "to" */
	ਵਿੱਥ = 0;
	write_error = read_error = ਅੰਕ_req = ਅੰਕ_upload_req = 0;
	max_req = 1;
	ਤਰੱਕੀ_counter = 0;

	ਜੇ (showprogress && ਮਾਪ != 0) {
		ਸ਼ੁਰੂ_ਤਰੱਕੀ_meter(ਤਰੱਕੀ_meter_ਰਸਤਾ(from_ਰਸਤਾ),
		    ਮਾਪ, &ਤਰੱਕੀ_counter);
	}
	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜਦੋਂ (ਅੰਕ_req > 0 || max_req > 0) {
		u_char *ਅੰਕੜੇ;
		ਮਾਪ_t len;

		/*
		 * Simulate EOF on interrupt: stop sending new requests and
		 * allow outstanding requests to drain gracefully
		 */
		ਜੇ (interrupted) {
			ਜੇ (ਅੰਕ_req == 0) /* If we haven't started yet... */
				ਰੋਕੋ;
			max_req = 0;
		}

		/* Send some more requests */
		ਜਦੋਂ (ਅੰਕ_req < max_req) {
			debug3("Request range %llu -> %llu (%d/%d)",
			    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)ਵਿੱਥ,
			    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)ਵਿੱਥ + buflen - 1,
			    ਅੰਕ_req, max_req);
			req = request_ਕਤਾਰ_ਵਿੱਚ_ਪਾਓ(&ਬੇਨਤੀਆਂ, from->ਸੁਨੇਹਾ_id++,
			    buflen, ਵਿੱਥ);
			ਵਿੱਥ += buflen;
			ਅੰਕ_req++;
			send_read_request(from, req->id, req->ਵਿੱਥ,
			    req->len, from_handle, from_handle_len);
		}

		/* Try to eat replies from the upload side (nonblocking) */
		handle_dest_replies(ਮੰਜ਼ਿਲ, ਮੰਜ਼ਿਲ_ਰਸਤਾ, 0,
		    &ਅੰਕ_upload_req, &write_error);

		sshbuf_reset(ਸੁਨੇਹਾ);
		get_ਸੁਨੇਹਾ(from, ਸੁਨੇਹਾ);
		ਜੇ ((r = sshbuf_get_u8(ਸੁਨੇਹਾ, &type)) != 0 ||
		    (r = sshbuf_get_u32(ਸੁਨੇਹਾ, &id)) != 0)
			fatal_fr(r, "parse");
		debug3("Received origin reply T:%u I:%u R:%d",
		    type, id, max_req);

		/* Find the request in our queue */
		ਜੇ ((req = request_ਲੱਭੋ(&ਬੇਨਤੀਆਂ, id)) == ਨਿਰਾ)
			fatal("Unexpected reply %u", id);

		ਚੋਣ (type) {
		ਹਾਲਤ SSH2_FXP_ਸਥਿਤੀ:
			ਜੇ ((r = sshbuf_get_u32(ਸੁਨੇਹਾ, &ਸਥਿਤੀ)) != 0)
				fatal_fr(r, "parse status");
			ਜੇ (ਸਥਿਤੀ != SSH2_FX_EOF)
				read_error = 1;
			max_req = 0;
			TAILQ_REMOVE(&ਬੇਨਤੀਆਂ, req, tq);
			ਮੁਕਤ(req);
			ਅੰਕ_req--;
			ਰੋਕੋ;
		ਹਾਲਤ SSH2_FXP_ਅੰਕੜੇ:
			ਜੇ ((r = sshbuf_get_string(ਸੁਨੇਹਾ, &ਅੰਕੜੇ, &len)) != 0)
				fatal_fr(r, "parse data");
			debug3("Received data %llu -> %llu",
			    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)req->ਵਿੱਥ,
			    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)req->ਵਿੱਥ + len - 1);
			ਜੇ (len > req->len)
				fatal("Received more data than asked for "
				    "%zu > %zu", len, req->len);
			ਜੇ (len == 0) {
				ਜੇ (ਵੇਖਿਆ_zerolen)
					fatal_f("server sent zero data length");
				ਵੇਖਿਆ_zerolen = 1;
			}

			/* Write this chunk out to the destination */
			sshbuf_reset(ਸੁਨੇਹਾ);
			ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, SSH2_FXP_WRITE)) != 0 ||
			    (r = sshbuf_put_u32(ਸੁਨੇਹਾ, ਮੰਜ਼ਿਲ->ਸੁਨੇਹਾ_id++)) != 0 ||
			    (r = sshbuf_put_string(ਸੁਨੇਹਾ, ਮੰਜ਼ਿਲ_handle,
			    ਮੰਜ਼ਿਲ_handle_len)) != 0 ||
			    (r = sshbuf_put_u64(ਸੁਨੇਹਾ, req->ਵਿੱਥ)) != 0 ||
			    (r = sshbuf_put_string(ਸੁਨੇਹਾ, ਅੰਕੜੇ, len)) != 0)
				fatal_fr(r, "compose write");
			send_ਸੁਨੇਹਾ(ਮੰਜ਼ਿਲ, ਸੁਨੇਹਾ);
			debug3("Sent message SSH2_FXP_WRITE I:%u O:%llu S:%zu",
			    id, (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)ਵਿੱਥ, len);
			ਅੰਕ_upload_req++;
			ਤਰੱਕੀ_counter += len;
			ਮੁਕਤ(ਅੰਕੜੇ);

			ਜੇ (len == req->len) {
				TAILQ_REMOVE(&ਬੇਨਤੀਆਂ, req, tq);
				ਮੁਕਤ(req);
				ਅੰਕ_req--;
			} ਨਹੀਂਤਾਂ {
				/* Resend the request for the missing data */
				debug3("Short data block, re-requesting "
				    "%llu -> %llu (%2d)",
				    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)req->ਵਿੱਥ + len,
				    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)req->ਵਿੱਥ +
				    req->len - 1, ਅੰਕ_req);
				req->id = from->ਸੁਨੇਹਾ_id++;
				req->len -= len;
				req->ਵਿੱਥ += len;
				send_read_request(from, req->id,
				    req->ਵਿੱਥ, req->len,
				    from_handle, from_handle_len);
				/* Reduce the request size */
				ਜੇ (len < buflen)
					buflen = ਵੱਧ_ਤੋਂ_ਵੱਧ(MIN_READ_ਮਾਪ, len);
			}
			ਜੇ (max_req > 0) { /* max_req = 0 iff EOF received */
				ਜੇ (ਮਾਪ > 0 && ਵਿੱਥ > ਮਾਪ) {
					/* Only one request at a time
					 * after the expected EOF */
					debug3("Finish at %llu (%2d)",
					    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)ਵਿੱਥ,
					    ਅੰਕ_req);
					max_req = 1;
				} ਨਹੀਂਤਾਂ ਜੇ (max_req < from->ਅੰਕ_ਬੇਨਤੀਆਂ) {
					++max_req;
				}
			}
			ਰੋਕੋ;
		ਮੂਲ:
			fatal("Expected SSH2_FXP_DATA(%u) packet, got %u",
			    SSH2_FXP_ਅੰਕੜੇ, type);
		}
	}

	ਜੇ (showprogress && ਮਾਪ)
		stop_ਤਰੱਕੀ_meter();

	/* Drain replies from the server (blocking) */
	debug3_f("waiting for %u replies from destination", ਅੰਕ_upload_req);
	handle_dest_replies(ਮੰਜ਼ਿਲ, ਮੰਜ਼ਿਲ_ਰਸਤਾ, 1, &ਅੰਕ_upload_req, &write_error);

	/* Sanity check */
	ਜੇ (TAILQ_FIRST(&ਬੇਨਤੀਆਂ) != ਨਿਰਾ)
		fatal("Transfer complete, but requests still in queue");
	/* Truncate at 0 length on interrupt or error to avoid holes at dest */
	ਜੇ (read_error || write_error || interrupted) {
		debug("truncating \"%s\" at 0", ਮੰਜ਼ਿਲ_ਰਸਤਾ);
		sftp_close(ਮੰਜ਼ਿਲ, ਮੰਜ਼ਿਲ_handle, ਮੰਜ਼ਿਲ_handle_len);
		ਮੁਕਤ(ਮੰਜ਼ਿਲ_handle);
		ਜੇ (send_open(ਮੰਜ਼ਿਲ, ਮੰਜ਼ਿਲ_ਰਸਤਾ, "dest",
		    SSH2_FXF_WRITE|SSH2_FXF_CREAT|SSH2_FXF_TRUNC, a,
		    &ਮੰਜ਼ਿਲ_handle, &ਮੰਜ਼ਿਲ_handle_len) != 0) {
			error("dest truncate \"%s\" failed", ਮੰਜ਼ਿਲ_ਰਸਤਾ);
			ਮੰਜ਼ਿਲ_handle = ਨਿਰਾ;
		}
	}
	ਜੇ (read_error) {
		error("read origin \"%s\": %s", from_ਰਸਤਾ, fx2txt(ਸਥਿਤੀ));
		ਸਥਿਤੀ = -1;
		sftp_close(from, from_handle, from_handle_len);
		ਜੇ (ਮੰਜ਼ਿਲ_handle != ਨਿਰਾ)
			sftp_close(ਮੰਜ਼ਿਲ, ਮੰਜ਼ਿਲ_handle, ਮੰਜ਼ਿਲ_handle_len);
	} ਨਹੀਂਤਾਂ ਜੇ (write_error) {
		error("write dest \"%s\": %s", ਮੰਜ਼ਿਲ_ਰਸਤਾ, fx2txt(write_error));
		ਸਥਿਤੀ = SSH2_FX_FAILURE;
		sftp_close(from, from_handle, from_handle_len);
		ਜੇ (ਮੰਜ਼ਿਲ_handle != ਨਿਰਾ)
			sftp_close(ਮੰਜ਼ਿਲ, ਮੰਜ਼ਿਲ_handle, ਮੰਜ਼ਿਲ_handle_len);
	} ਨਹੀਂਤਾਂ {
		ਜੇ (sftp_close(from, from_handle, from_handle_len) != 0 ||
		    interrupted)
			ਸਥਿਤੀ = -1;
		ਨਹੀਂਤਾਂ
			ਸਥਿਤੀ = SSH2_FX_OK;
		ਜੇ (ਮੰਜ਼ਿਲ_handle != ਨਿਰਾ) {
			/* Need to resend utimes after write */
			ਜੇ (preserve_flag)
				sftp_fsetstat(ਮੰਜ਼ਿਲ, ਮੰਜ਼ਿਲ_handle, ਮੰਜ਼ਿਲ_handle_len, a);
			sftp_close(ਮੰਜ਼ਿਲ, ਮੰਜ਼ਿਲ_handle, ਮੰਜ਼ਿਲ_handle_len);
		}
	}
	sshbuf_free(ਸੁਨੇਹਾ);
	ਮੁਕਤ(from_handle);
	ਮੁਕਤ(ਮੰਜ਼ਿਲ_handle);

	ਵਾਪਸ ਸਥਿਤੀ == SSH2_FX_OK ? 0 : -1;
}

ਸਥਿਰ ਪੂਰਨ
crossload_dir_ਅੰਦਰੂਨੀ(ਬਣਤਰ sftp_conn *from, ਬਣਤਰ sftp_conn *ਮੰਜ਼ਿਲ,
    ਅਚਲ ਅੱਖਰ *from_ਰਸਤਾ, ਅਚਲ ਅੱਖਰ *ਮੰਜ਼ਿਲ_ਰਸਤਾ,
    ਪੂਰਨ ਡੂੰਘਾਈ, Attrib *dirattrib, ਪੂਰਨ preserve_flag, ਪੂਰਨ print_flag,
    ਪੂਰਨ follow_link_flag)
{
	ਪੂਰਨ i, ret = 0, created = 0;
	SFTP_DIRENT **dir_entries;
	ਅੱਖਰ *filename, *new_from_ਰਸਤਾ = ਨਿਰਾ, *new_ਮੰਜ਼ਿਲ_ਰਸਤਾ = ਨਿਰਾ;
	ਬਹੁਲਕ_t ਬਹੁਲਕ = 0777;
	Attrib *a, curdir, ldirattrib, newdir, lsym;

	debug2_f("crossload dir src \"%s\" to dst \"%s\"", from_ਰਸਤਾ, ਮੰਜ਼ਿਲ_ਰਸਤਾ);

	ਜੇ (ਡੂੰਘਾਈ >= MAX_DIR_ਡੂੰਘਾਈ) {
		error("Maximum directory depth exceeded: %d levels", ਡੂੰਘਾਈ);
		ਵਾਪਸ -1;
	}

	ਜੇ (dirattrib == ਨਿਰਾ) {
		ਜੇ (sftp_stat(from, from_ਰਸਤਾ, 1, &ldirattrib) != 0) {
			error("stat remote \"%s\" failed", from_ਰਸਤਾ);
			ਵਾਪਸ -1;
		}
		dirattrib = &ldirattrib;
	}
	ਜੇ (!S_ISDIR(dirattrib->perm)) {
		error("\"%s\" is not a directory", from_ਰਸਤਾ);
		ਵਾਪਸ -1;
	}
	ਜੇ (print_flag && print_flag != SFTP_ਤਰੱਕੀ_ONLY)
		mprintf("Retrieving %s\n", from_ਰਸਤਾ);

	curdir = *dirattrib; /* dirattrib will be clobbered */
	curdir.flags &= ~SSH2_FILEXFER_ATTR_ਮਾਪ;
	curdir.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	ਜੇ ((curdir.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) == 0) {
		debug("Origin did not send permissions for "
		    "directory \"%s\"", ਮੰਜ਼ਿਲ_ਰਸਤਾ);
		curdir.perm = S_IWUSR|S_IXUSR;
		curdir.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
	}
	/* We need to be able to write to the directory while we transfer it */
	ਬਹੁਲਕ = curdir.perm & 01777;
	curdir.perm = ਬਹੁਲਕ | (S_IWUSR|S_IXUSR);

	/*
	 * sftp lacks a portable status value to match errno EEXIST,
	 * so if we get a failure back then we must check whether
	 * the path already existed and is a directory.  Ensure we can
	 * write to the directory we create for the duration of the transfer.
	 */
	ਜੇ (sftp_mkdir(ਮੰਜ਼ਿਲ, ਮੰਜ਼ਿਲ_ਰਸਤਾ, &curdir, 0) == 0)
		created = 1;
	ਨਹੀਂਤਾਂ {
		ਜੇ (sftp_stat(ਮੰਜ਼ਿਲ, ਮੰਜ਼ਿਲ_ਰਸਤਾ, 0, &newdir) != 0)
			ਵਾਪਸ -1;
		ਜੇ (!S_ISDIR(newdir.perm)) {
			error("\"%s\" exists but is not a directory", ਮੰਜ਼ਿਲ_ਰਸਤਾ);
			ਵਾਪਸ -1;
		}
	}
	curdir.perm = ਬਹੁਲਕ;

	ਜੇ (sftp_readdir(from, from_ਰਸਤਾ, &dir_entries) == -1) {
		error("origin readdir \"%s\" failed", from_ਰਸਤਾ);
		ਵਾਪਸ -1;
	}

	ਲਈ (i = 0; dir_entries[i] != ਨਿਰਾ && !interrupted; i++) {
		ਮੁਕਤ(new_from_ਰਸਤਾ);
		ਮੁਕਤ(new_ਮੰਜ਼ਿਲ_ਰਸਤਾ);

		filename = dir_entries[i]->filename;
		new_from_ਰਸਤਾ = sftp_ਰਸਤਾ_append(from_ਰਸਤਾ, filename);
		new_ਮੰਜ਼ਿਲ_ਰਸਤਾ = sftp_ਰਸਤਾ_append(ਮੰਜ਼ਿਲ_ਰਸਤਾ, filename);

		a = &dir_entries[i]->a;
		ਜੇ (S_ISLNK(a->perm)) {
			ਜੇ (!follow_link_flag) {
				logit("%s: not a regular file", filename);
				ਜਾਰੀ;
			}
			/* Replace the stat contents with the symlink target */
			ਜੇ (sftp_stat(from, new_from_ਰਸਤਾ, 1, &lsym) != 0) {
				logit("remote stat \"%s\" failed",
				    new_from_ਰਸਤਾ);
				ret = -1;
				ਜਾਰੀ;
			}
			a = &lsym;
		}
		ਜੇ (S_ISDIR(a->perm)) {
			ਜੇ (strcmp(filename, ".") == 0 ||
			    strcmp(filename, "..") == 0)
				ਜਾਰੀ;
			ਜੇ (crossload_dir_ਅੰਦਰੂਨੀ(from, ਮੰਜ਼ਿਲ,
			    new_from_ਰਸਤਾ, new_ਮੰਜ਼ਿਲ_ਰਸਤਾ,
			    ਡੂੰਘਾਈ + 1, a, preserve_flag,
			    print_flag, follow_link_flag) == -1)
				ret = -1;
		} ਨਹੀਂਤਾਂ ਜੇ (S_ISREG(a->perm)) {
			ਜੇ (sftp_crossload(from, ਮੰਜ਼ਿਲ, new_from_ਰਸਤਾ,
			    new_ਮੰਜ਼ਿਲ_ਰਸਤਾ, a, preserve_flag) == -1) {
				error("crossload \"%s\" to \"%s\" failed",
				    new_from_ਰਸਤਾ, new_ਮੰਜ਼ਿਲ_ਰਸਤਾ);
				ret = -1;
			}
		} ਨਹੀਂਤਾਂ {
			logit("origin \"%s\": not a regular file",
			    new_from_ਰਸਤਾ);
		}
	}
	ਮੁਕਤ(new_ਮੰਜ਼ਿਲ_ਰਸਤਾ);
	ਮੁਕਤ(new_from_ਰਸਤਾ);

	ਜੇ (created || preserve_flag)
		sftp_setstat(ਮੰਜ਼ਿਲ, ਮੰਜ਼ਿਲ_ਰਸਤਾ, &curdir);

	sftp_free_dirents(dir_entries);

	ਵਾਪਸ ret;
}

ਪੂਰਨ
sftp_crossload_dir(ਬਣਤਰ sftp_conn *from, ਬਣਤਰ sftp_conn *ਮੰਜ਼ਿਲ,
    ਅਚਲ ਅੱਖਰ *from_ਰਸਤਾ, ਅਚਲ ਅੱਖਰ *ਮੰਜ਼ਿਲ_ਰਸਤਾ,
    Attrib *dirattrib, ਪੂਰਨ preserve_flag, ਪੂਰਨ print_flag, ਪੂਰਨ follow_link_flag)
{
	ਅੱਖਰ *from_ਰਸਤਾ_canon;
	ਪੂਰਨ ret;

	ਜੇ ((from_ਰਸਤਾ_canon = sftp_realpath(from, from_ਰਸਤਾ)) == ਨਿਰਾ) {
		error("crossload \"%s\": path canonicalization failed",
		    from_ਰਸਤਾ);
		ਵਾਪਸ -1;
	}

	ret = crossload_dir_ਅੰਦਰੂਨੀ(from, ਮੰਜ਼ਿਲ, from_ਰਸਤਾ_canon, ਮੰਜ਼ਿਲ_ਰਸਤਾ, 0,
	    dirattrib, preserve_flag, print_flag, follow_link_flag);
	ਮੁਕਤ(from_ਰਸਤਾ_canon);
	ਵਾਪਸ ret;
}

ਪੂਰਨ
sftp_can_get_users_groups_by_id(ਬਣਤਰ sftp_conn *conn)
{
	ਵਾਪਸ (conn->exts & SFTP_EXT_GETUSERSGROUPS_BY_ID) != 0;
}

ਪੂਰਨ
sftp_get_users_groups_by_id(ਬਣਤਰ sftp_conn *conn,
    ਅਚਲ u_int *uids, u_int nuids,
    ਅਚਲ u_int *gids, u_int ngids,
    ਅੱਖਰ ***usernamesp, ਅੱਖਰ ***groupnamesp)
{
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ, *uidbuf, *gidbuf;
	u_int i, expected_id, id;
	ਅੱਖਰ *name, **usernames = ਨਿਰਾ, **groupnames = ਨਿਰਾ;
	u_char type;
	ਪੂਰਨ r;

	*usernamesp = *groupnamesp = ਨਿਰਾ;
	ਜੇ (!sftp_can_get_users_groups_by_id(conn))
		ਵਾਪਸ SSH_ERR_FEATURE_UNSUPPORTED;

	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ ||
	    (uidbuf = sshbuf_new()) == ਨਿਰਾ ||
	    (gidbuf = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	expected_id = id = conn->ਸੁਨੇਹਾ_id++;
	debug2("Sending SSH2_FXP_EXTENDED(users-groups-by-id@openssh.com)");
	ਲਈ (i = 0; i < nuids; i++) {
		ਜੇ ((r = sshbuf_put_u32(uidbuf, uids[i])) != 0)
			fatal_fr(r, "compose uids");
	}
	ਲਈ (i = 0; i < ngids; i++) {
		ਜੇ ((r = sshbuf_put_u32(gidbuf, gids[i])) != 0)
			fatal_fr(r, "compose gids");
	}
	ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(ਸੁਨੇਹਾ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ਸੁਨੇਹਾ,
	    "users-groups-by-id@openssh.com")) != 0 ||
	    (r = sshbuf_put_stringb(ਸੁਨੇਹਾ, uidbuf)) != 0 ||
	    (r = sshbuf_put_stringb(ਸੁਨੇਹਾ, gidbuf)) != 0)
		fatal_fr(r, "compose");
	send_ਸੁਨੇਹਾ(conn, ਸੁਨੇਹਾ);
	get_ਸੁਨੇਹਾ(conn, ਸੁਨੇਹਾ);
	ਜੇ ((r = sshbuf_get_u8(ਸੁਨੇਹਾ, &type)) != 0 ||
	    (r = sshbuf_get_u32(ਸੁਨੇਹਾ, &id)) != 0)
		fatal_fr(r, "parse");
	ਜੇ (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	ਜੇ (type == SSH2_FXP_ਸਥਿਤੀ) {
		u_int ਸਥਿਤੀ;
		ਅੱਖਰ *errmsg;

		ਜੇ ((r = sshbuf_get_u32(ਸੁਨੇਹਾ, &ਸਥਿਤੀ)) != 0 ||
		    (r = sshbuf_get_cstring(ਸੁਨੇਹਾ, &errmsg, ਨਿਰਾ)) != 0)
			fatal_fr(r, "parse status");
		error("users-groups-by-id %s",
		    *errmsg == '\0' ? fx2txt(ਸਥਿਤੀ) : errmsg);
		ਮੁਕਤ(errmsg);
		sshbuf_free(ਸੁਨੇਹਾ);
		sshbuf_free(uidbuf);
		sshbuf_free(gidbuf);
		ਵਾਪਸ -1;
	} ਨਹੀਂਤਾਂ ਜੇ (type != SSH2_FXP_EXTENDED_ਜਵਾਬ)
		fatal("Expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_ਜਵਾਬ, type);

	/* reuse */
	sshbuf_free(uidbuf);
	sshbuf_free(gidbuf);
	uidbuf = gidbuf = ਨਿਰਾ;
	ਜੇ ((r = sshbuf_froms(ਸੁਨੇਹਾ, &uidbuf)) != 0 ||
	    (r = sshbuf_froms(ਸੁਨੇਹਾ, &gidbuf)) != 0)
		fatal_fr(r, "parse response");
	ਜੇ (nuids > 0) {
		usernames = xcalloc(nuids, ਆਕਾਰ(*usernames));
		ਲਈ (i = 0; i < nuids; i++) {
			ਜੇ ((r = sshbuf_get_cstring(uidbuf, &name, ਨਿਰਾ)) != 0)
				fatal_fr(r, "parse user name");
			/* Handle unresolved names */
			ਜੇ (*name == '\0') {
				ਮੁਕਤ(name);
				name = ਨਿਰਾ;
			}
			usernames[i] = name;
		}
	}
	ਜੇ (ngids > 0) {
		groupnames = xcalloc(ngids, ਆਕਾਰ(*groupnames));
		ਲਈ (i = 0; i < ngids; i++) {
			ਜੇ ((r = sshbuf_get_cstring(gidbuf, &name, ਨਿਰਾ)) != 0)
				fatal_fr(r, "parse user name");
			/* Handle unresolved names */
			ਜੇ (*name == '\0') {
				ਮੁਕਤ(name);
				name = ਨਿਰਾ;
			}
			groupnames[i] = name;
		}
	}
	ਜੇ (sshbuf_len(uidbuf) != 0)
		fatal_f("unexpected extra username data");
	ਜੇ (sshbuf_len(gidbuf) != 0)
		fatal_f("unexpected extra groupname data");
	sshbuf_free(uidbuf);
	sshbuf_free(gidbuf);
	sshbuf_free(ਸੁਨੇਹਾ);
	/* success */
	*usernamesp = usernames;
	*groupnamesp = groupnames;
	ਵਾਪਸ 0;
}

ਅੱਖਰ *
sftp_ਰਸਤਾ_append(ਅਚਲ ਅੱਖਰ *p1, ਅਚਲ ਅੱਖਰ *p2)
{
	ਅੱਖਰ *ret;
	ਮਾਪ_t len = ਲੜੀ_ਲੰਬਾਈ(p1) + ਲੜੀ_ਲੰਬਾਈ(p2) + 2;

	ret = xmalloc(len);
	strlcpy(ret, p1, len);
	ਜੇ (p1[0] != '\0' && p1[ਲੜੀ_ਲੰਬਾਈ(p1) - 1] != '/')
		strlcat(ret, "/", len);
	strlcat(ret, p2, len);

	ਵਾਪਸ(ret);
}

/*
 * Arg p must be dynamically allocated.  It will either be returned or
 * freed and a replacement allocated.  Caller must free returned string.
 */
ਅੱਖਰ *
sftp_make_absolute(ਅੱਖਰ *p, ਅਚਲ ਅੱਖਰ *pwd)
{
	ਅੱਖਰ *abs_str;

	/* Derelativise */
	ਜੇ (p && !ਰਸਤਾ_absolute(p)) {
		abs_str = sftp_ਰਸਤਾ_append(pwd, p);
		ਮੁਕਤ(p);
		ਵਾਪਸ(abs_str);
	} ਨਹੀਂਤਾਂ
		ਵਾਪਸ(p);
}

ਪੂਰਨ
sftp_remote_is_dir(ਬਣਤਰ sftp_conn *conn, ਅਚਲ ਅੱਖਰ *ਰਸਤਾ)
{
	Attrib a;

	/* XXX: report errors? */
	ਜੇ (sftp_stat(conn, ਰਸਤਾ, 1, &a) != 0)
		ਵਾਪਸ(0);
	ਜੇ (!(a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS))
		ਵਾਪਸ(0);
	ਵਾਪਸ S_ISDIR(a.perm);
}


/* Check whether path returned from glob(..., GLOB_MARK, ...) is a directory */
ਪੂਰਨ
sftp_globpath_is_dir(ਅਚਲ ਅੱਖਰ *pathname)
{
	ਮਾਪ_t l = ਲੜੀ_ਲੰਬਾਈ(pathname);

	ਵਾਪਸ l > 0 && pathname[l - 1] == '/';
}

