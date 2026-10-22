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

ಬಾಹ್ಯ ಅಸ್ಥಿರ sig_atomic_t interrupted;
ಬಾಹ್ಯ ಪೂರ್ಣಾಂಕ showprogress;

/* Default size of buffer for up/download (fix sftp.1 scp.1 if changed) */
#ವ್ಯಾಖ್ಯಾನಿಸು DEFAULT_COPY_BUFLEN	32768

/* Default number of concurrent xfer requests (fix sftp.1 scp.1 if changed) */
#ವ್ಯಾಖ್ಯಾನಿಸು DEFAULT_ಅಂಕೆ_ವಿನಂತಿಗಳು	64

/* Minimum amount of data to read at a time */
#ವ್ಯಾಖ್ಯಾನಿಸು MIN_READ_ಗಾತ್ರ	512

/* Maximum depth to descend in directory trees */
#ವ್ಯಾಖ್ಯಾನಿಸು MAX_DIR_ಆಳ 64

/* Directory separator characters */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_CYGWIN
# define SFTP_DIRECTORY_CHARS      "/\\"
#ಇಲ್ಲದಿದ್ದರೆ /* HAVE_CYGWIN */
# define SFTP_DIRECTORY_CHARS      "/"
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_CYGWIN */

ರಚನೆ sftp_conn {
	ಪೂರ್ಣಾಂಕ fd_ಒಳ;
	ಪೂರ್ಣಾಂಕ fd_ಹೊರಹೋಗು;
	u_int download_buflen;
	u_int upload_buflen;
	u_int ಅಂಕೆ_ವಿನಂತಿಗಳು;
	u_int ಆವೃತ್ತಿ;
	u_int ಸಂದೇಶ_id;
#ವ್ಯಾಖ್ಯಾನಿಸು SFTP_EXT_POSIX_RENAME		0x00000001
#ವ್ಯಾಖ್ಯಾನಿಸು SFTP_EXT_STATVFS		0x00000002
#ವ್ಯಾಖ್ಯಾನಿಸು SFTP_EXT_FSTATVFS		0x00000004
#ವ್ಯಾಖ್ಯಾನಿಸು SFTP_EXT_HARDLINK		0x00000008
#ವ್ಯಾಖ್ಯಾನಿಸು SFTP_EXT_FSYNC			0x00000010
#ವ್ಯಾಖ್ಯಾನಿಸು SFTP_EXT_LSETSTAT		0x00000020
#ವ್ಯಾಖ್ಯಾನಿಸು SFTP_EXT_LIMITS			0x00000040
#ವ್ಯಾಖ್ಯಾನಿಸು SFTP_EXT_ಮಾರ್ಗ_EXPAND		0x00000080
#ವ್ಯಾಖ್ಯಾನಿಸು SFTP_EXT_COPY_ದತ್ತಾಂಶ		0x00000100
#ವ್ಯಾಖ್ಯಾನಿಸು SFTP_EXT_GETUSERSGROUPS_BY_ID	0x00000200
	u_int exts;
	uint64_t ಎಲ್ಲೆ_kbps;
	ರಚನೆ bwlimit bwlimit_ಒಳ, bwlimit_ಹೊರಹೋಗು;
};

/* Tracks in-progress requests during file transfers */
ರಚನೆ request {
	u_int id;
	ಗಾತ್ರ_t len;
	uint64_t ಸ್ಥಾನಾಂತರ;
	TAILQ_ENTRY(request) tq;
};
TAILQ_HEAD(ವಿನಂತಿಗಳು, request);

ಸ್ಥಿರ u_char *
get_handle(ರಚನೆ sftp_conn *conn, u_int expected_id, ಗಾತ್ರ_t *len,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *errfmt, ...) __attribute__((format(ಬರೆ, 4, 5)));

ಸ್ಥಿರ ರಚನೆ request *
request_ಸರತಿಗೆ_ಸೇರಿಸು(ರಚನೆ ವಿನಂತಿಗಳು *ವಿನಂತಿಗಳು, u_int id, ಗಾತ್ರ_t len,
    uint64_t ಸ್ಥಾನಾಂತರ)
{
	ರಚನೆ request *req;

	req = xcalloc(1, ಗಾತ್ರ(*req));
	req->id = id;
	req->len = len;
	req->ಸ್ಥಾನಾಂತರ = ಸ್ಥಾನಾಂತರ;
	TAILQ_INSERT_TAIL(ವಿನಂತಿಗಳು, req, tq);
	ಹಿಂತಿರುಗಿ req;
}

ಸ್ಥಿರ ರಚನೆ request *
request_ಕಂಡುಹಿಡಿ(ರಚನೆ ವಿನಂತಿಗಳು *ವಿನಂತಿಗಳು, u_int id)
{
	ರಚನೆ request *req;

	ಗಾಗಿ (req = TAILQ_FIRST(ವಿನಂತಿಗಳು);
	    req != ಖಾಲಿ && req->id != id;
	    req = TAILQ_NEXT(req, tq))
		;
	ಹಿಂತಿರುಗಿ req;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sftpio(ಶೂನ್ಯ *_bwlimit, ಗಾತ್ರ_t amount)
{
	ರಚನೆ bwlimit *bwlimit = (ರಚನೆ bwlimit *)_bwlimit;

	refresh_ಪ್ರಗತಿ_meter(0);
	ಆದರೆ (bwlimit != ಖಾಲಿ)
		bandwidth_ಎಲ್ಲೆ(bwlimit, amount);
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
send_ಸಂದೇಶ(ರಚನೆ sftp_conn *conn, ರಚನೆ sshbuf *m)
{
	u_char mlen[4];
	ರಚನೆ iovec iov[2];

	ಆದರೆ (sshbuf_len(m) > SFTP_MAX_ಸಂದೇಶ_ಉದ್ದಳತೆ)
		fatal("Outbound message too long %zu", sshbuf_len(m));

	/* Send length first */
	put_u32(mlen, sshbuf_len(m));
	iov[0].iov_base = mlen;
	iov[0].iov_len = ಗಾತ್ರ(mlen);
	iov[1].iov_base = (u_char *)sshbuf_ptr(m);
	iov[1].iov_len = sshbuf_len(m);

	ಆದರೆ (atomiciov6(writev, conn->fd_ಹೊರಹೋಗು, iov, 2, sftpio,
	    conn->ಎಲ್ಲೆ_kbps > 0 ? &conn->bwlimit_ಹೊರಹೋಗು : ಖಾಲಿ) !=
	    sshbuf_len(m) + ಗಾತ್ರ(mlen))
		fatal("Couldn't send packet: %s", strerror(errno));

	sshbuf_reset(m);
}

ಸ್ಥಿರ ಶೂನ್ಯ
get_ಸಂದೇಶ_extended(ರಚನೆ sftp_conn *conn, ರಚನೆ sshbuf *m, ಪೂರ್ಣಾಂಕ initial)
{
	u_int ಸಂದೇಶ_len;
	u_char *p;
	ಪೂರ್ಣಾಂಕ r;

	sshbuf_reset(m);
	ಆದರೆ ((r = sshbuf_reserve(m, 4, &p)) != 0)
		fatal_fr(r, "reserve");
	ಆದರೆ (atomicio6(ಪಠ, conn->fd_ಒಳ, p, 4, sftpio,
	    conn->ಎಲ್ಲೆ_kbps > 0 ? &conn->bwlimit_ಒಳ : ಖಾಲಿ) != 4) {
		ಆದರೆ (errno == EPIPE || errno == ECONNRESET)
			fatal("Connection closed");
		ಇಲ್ಲದಿದ್ದರೆ
			fatal("Couldn't read packet: %s", strerror(errno));
	}

	ಆದರೆ ((r = sshbuf_get_u32(m, &ಸಂದೇಶ_len)) != 0)
		fatal_fr(r, "sshbuf_get_u32");
	ಆದರೆ (ಸಂದೇಶ_len > SFTP_MAX_ಸಂದೇಶ_ಉದ್ದಳತೆ) {
		do_log2(initial ? SYSLOG_LEVEL_ERROR : SYSLOG_LEVEL_FATAL,
		    "Received message too long %u", ಸಂದೇಶ_len);
		fatal("Ensure the remote shell produces no output "
		    "for non-interactive sessions.");
	}

	ಆದರೆ ((r = sshbuf_reserve(m, ಸಂದೇಶ_len, &p)) != 0)
		fatal_fr(r, "reserve");
	ಆದರೆ (atomicio6(ಪಠ, conn->fd_ಒಳ, p, ಸಂದೇಶ_len, sftpio,
	    conn->ಎಲ್ಲೆ_kbps > 0 ? &conn->bwlimit_ಒಳ : ಖಾಲಿ)
	    != ಸಂದೇಶ_len) {
		ಆದರೆ (errno == EPIPE)
			fatal("Connection closed");
		ಇಲ್ಲದಿದ್ದರೆ
			fatal("Read packet: %s", strerror(errno));
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
get_ಸಂದೇಶ(ರಚನೆ sftp_conn *conn, ರಚನೆ sshbuf *m)
{
	get_ಸಂದೇಶ_extended(conn, m, 0);
}

ಸ್ಥಿರ ಶೂನ್ಯ
send_string_request(ರಚನೆ sftp_conn *conn, u_int id, u_int ಸಂಕೇತ_2, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s,
    u_int len)
{
	ರಚನೆ sshbuf *ಸಂದೇಶ;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, ಸಂಕೇತ_2)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
	    (r = sshbuf_put_string(ಸಂದೇಶ, s, len)) != 0)
		fatal_fr(r, "compose");
	send_ಸಂದೇಶ(conn, ಸಂದೇಶ);
	debug3("Sent message fd %d T:%u I:%u", conn->fd_ಹೊರಹೋಗು, ಸಂಕೇತ_2, id);
	sshbuf_free(ಸಂದೇಶ);
}

ಸ್ಥಿರ ಶೂನ್ಯ
send_string_attrs_request(ರಚನೆ sftp_conn *conn, u_int id, u_int ಸಂಕೇತ_2,
    ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *s, u_int len, Attrib *a)
{
	ರಚನೆ sshbuf *ಸಂದೇಶ;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, ಸಂಕೇತ_2)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
	    (r = sshbuf_put_string(ಸಂದೇಶ, s, len)) != 0 ||
	    (r = encode_attrib(ಸಂದೇಶ, a)) != 0)
		fatal_fr(r, "compose");
	send_ಸಂದೇಶ(conn, ಸಂದೇಶ);
	debug3("Sent message fd %d T:%u I:%u F:0x%04x M:%05o",
	    conn->fd_ಹೊರಹೋಗು, ಸಂಕೇತ_2, id, a->flags, a->perm);
	sshbuf_free(ಸಂದೇಶ);
}

ಸ್ಥಿರ u_int
get_ಸ್ಥಿತಿ(ರಚನೆ sftp_conn *conn, u_int expected_id)
{
	ರಚನೆ sshbuf *ಸಂದೇಶ;
	u_char type;
	u_int id, ಸ್ಥಿತಿ_2;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	get_ಸಂದೇಶ(conn, ಸಂದೇಶ);
	ಆದರೆ ((r = sshbuf_get_u8(ಸಂದೇಶ, &type)) != 0 ||
	    (r = sshbuf_get_u32(ಸಂದೇಶ, &id)) != 0)
		fatal_fr(r, "compose");

	ಆದರೆ (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	ಆದರೆ (type != SSH2_FXP_ಸ್ಥಿತಿ)
		fatal("Expected SSH2_FXP_STATUS(%u) packet, got %u",
		    SSH2_FXP_ಸ್ಥಿತಿ, type);

	ಆದರೆ ((r = sshbuf_get_u32(ಸಂದೇಶ, &ಸ್ಥಿತಿ_2)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(ಸಂದೇಶ);

	debug3("SSH2_FXP_STATUS %u", ಸ್ಥಿತಿ_2);

	ಹಿಂತಿರುಗಿ ಸ್ಥಿತಿ_2;
}

ಸ್ಥಿರ u_char *
get_handle(ರಚನೆ sftp_conn *conn, u_int expected_id, ಗಾತ್ರ_t *len,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *errfmt, ...)
{
	ರಚನೆ sshbuf *ಸಂದೇಶ;
	u_int id, ಸ್ಥಿತಿ_2;
	u_char type;
	u_char *handle;
	ಅಕ್ಷರ errmsg[256];
	va_list ವಾದಗಳು;
	ಪೂರ್ಣಾಂಕ r;

	va_start(ವಾದಗಳು, errfmt);
	ಆದರೆ (errfmt != ಖಾಲಿ)
		vsnprintf(errmsg, ಗಾತ್ರ(errmsg), errfmt, ವಾದಗಳು);
	va_end(ವಾದಗಳು);

	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	get_ಸಂದೇಶ(conn, ಸಂದೇಶ);
	ಆದರೆ ((r = sshbuf_get_u8(ಸಂದೇಶ, &type)) != 0 ||
	    (r = sshbuf_get_u32(ಸಂದೇಶ, &id)) != 0)
		fatal_fr(r, "parse");

	ಆದರೆ (id != expected_id)
		fatal("%s: ID mismatch (%u != %u)",
		    errfmt == ಖಾಲಿ ? __func__ : errmsg, id, expected_id);
	ಆದರೆ (type == SSH2_FXP_ಸ್ಥಿತಿ) {
		ಆದರೆ ((r = sshbuf_get_u32(ಸಂದೇಶ, &ಸ್ಥಿತಿ_2)) != 0)
			fatal_fr(r, "parse status");
		ಆದರೆ (errfmt != ಖಾಲಿ)
			error("%s: %s", errmsg, fx2txt(ಸ್ಥಿತಿ_2));
		sshbuf_free(ಸಂದೇಶ);
		ಹಿಂತಿರುಗಿ(ಖಾಲಿ);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (type != SSH2_FXP_HANDLE)
		fatal("%s: Expected SSH2_FXP_HANDLE(%u) packet, got %u",
		    errfmt == ಖಾಲಿ ? __func__ : errmsg, SSH2_FXP_HANDLE, type);

	ಆದರೆ ((r = sshbuf_get_string(ಸಂದೇಶ, &handle, len)) != 0)
		fatal_fr(r, "parse handle");
	sshbuf_free(ಸಂದೇಶ);

	ಹಿಂತಿರುಗಿ handle;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
get_decode_stat(ರಚನೆ sftp_conn *conn, u_int expected_id, ಪೂರ್ಣಾಂಕ quiet, Attrib *a)
{
	ರಚನೆ sshbuf *ಸಂದೇಶ;
	u_int id;
	u_char type;
	ಪೂರ್ಣಾಂಕ r;
	Attrib attr;

	ಆದರೆ (a != ಖಾಲಿ)
		memset(a, '\0', ಗಾತ್ರ(*a));
	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	get_ಸಂದೇಶ(conn, ಸಂದೇಶ);

	ಆದರೆ ((r = sshbuf_get_u8(ಸಂದೇಶ, &type)) != 0 ||
	    (r = sshbuf_get_u32(ಸಂದೇಶ, &id)) != 0)
		fatal_fr(r, "parse");

	ಆದರೆ (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	ಆದರೆ (type == SSH2_FXP_ಸ್ಥಿತಿ) {
		u_int ಸ್ಥಿತಿ_2;

		ಆದರೆ ((r = sshbuf_get_u32(ಸಂದೇಶ, &ಸ್ಥಿತಿ_2)) != 0)
			fatal_fr(r, "parse status");
		ಆದರೆ (quiet)
			debug("stat remote: %s", fx2txt(ಸ್ಥಿತಿ_2));
		ಇಲ್ಲದಿದ್ದರೆ
			error("stat remote: %s", fx2txt(ಸ್ಥಿತಿ_2));
		sshbuf_free(ಸಂದೇಶ);
		ಹಿಂತಿರುಗಿ -1;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (type != SSH2_FXP_ATTRS) {
		fatal("Expected SSH2_FXP_ATTRS(%u) packet, got %u",
		    SSH2_FXP_ATTRS, type);
	}
	ಆದರೆ ((r = decode_attrib(ಸಂದೇಶ, &attr)) != 0) {
		error_fr(r, "decode_attrib");
		sshbuf_free(ಸಂದೇಶ);
		ಹಿಂತಿರುಗಿ -1;
	}
	/* success */
	ಆದರೆ (a != ಖಾಲಿ)
		*a = attr;
	debug3("Received stat reply T:%u I:%u F:0x%04x M:%05o",
	    type, id, attr.flags, attr.perm);
	sshbuf_free(ಸಂದೇಶ);

	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
get_decode_statvfs(ರಚನೆ sftp_conn *conn, ರಚನೆ sftp_statvfs *st,
    u_int expected_id, ಪೂರ್ಣಾಂಕ quiet)
{
	ರಚನೆ sshbuf *ಸಂದೇಶ;
	u_char type;
	u_int id;
	uint64_t flag;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	get_ಸಂದೇಶ(conn, ಸಂದೇಶ);

	ಆದರೆ ((r = sshbuf_get_u8(ಸಂದೇಶ, &type)) != 0 ||
	    (r = sshbuf_get_u32(ಸಂದೇಶ, &id)) != 0)
		fatal_fr(r, "parse");

	debug3("Received statvfs reply T:%u I:%u", type, id);
	ಆದರೆ (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	ಆದರೆ (type == SSH2_FXP_ಸ್ಥಿತಿ) {
		u_int ಸ್ಥಿತಿ_2;

		ಆದರೆ ((r = sshbuf_get_u32(ಸಂದೇಶ, &ಸ್ಥಿತಿ_2)) != 0)
			fatal_fr(r, "parse status");
		ಆದರೆ (quiet)
			debug("remote statvfs: %s", fx2txt(ಸ್ಥಿತಿ_2));
		ಇಲ್ಲದಿದ್ದರೆ
			error("remote statvfs: %s", fx2txt(ಸ್ಥಿತಿ_2));
		sshbuf_free(ಸಂದೇಶ);
		ಹಿಂತಿರುಗಿ -1;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (type != SSH2_FXP_EXTENDED_ಉತ್ತರ) {
		fatal("Expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_ಉತ್ತರ, type);
	}

	memset(st, 0, ಗಾತ್ರ(*st));
	ಆದರೆ ((r = sshbuf_get_u64(ಸಂದೇಶ, &st->f_bsize)) != 0 ||
	    (r = sshbuf_get_u64(ಸಂದೇಶ, &st->f_frsize)) != 0 ||
	    (r = sshbuf_get_u64(ಸಂದೇಶ, &st->f_ಖಂಡಗಳು)) != 0 ||
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

	ಹಿಂತಿರುಗಿ 0;
}

ರಚನೆ sftp_conn *
sftp_init(ಪೂರ್ಣಾಂಕ fd_ಒಳ, ಪೂರ್ಣಾಂಕ fd_ಹೊರಹೋಗು, u_int transfer_buflen, u_int ಅಂಕೆ_ವಿನಂತಿಗಳು,
    uint64_t ಎಲ್ಲೆ_kbps)
{
	u_char type;
	ರಚನೆ sshbuf *ಸಂದೇಶ;
	ರಚನೆ sftp_conn *ret;
	ಪೂರ್ಣಾಂಕ r;

	ret = xcalloc(1, ಗಾತ್ರ(*ret));
	ret->ಸಂದೇಶ_id = 1;
	ret->fd_ಒಳ = fd_ಒಳ;
	ret->fd_ಹೊರಹೋಗು = fd_ಹೊರಹೋಗು;
	ret->download_buflen = ret->upload_buflen =
	    transfer_buflen ? transfer_buflen : DEFAULT_COPY_BUFLEN;
	ret->ಅಂಕೆ_ವಿನಂತಿಗಳು =
	    ಅಂಕೆ_ವಿನಂತಿಗಳು ? ಅಂಕೆ_ವಿನಂತಿಗಳು : DEFAULT_ಅಂಕೆ_ವಿನಂತಿಗಳು;
	ret->exts = 0;
	ret->ಎಲ್ಲೆ_kbps = 0;

	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_INIT)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, SSH2_FILEXFER_ಆವೃತ್ತಿ)) != 0)
		fatal_fr(r, "parse");

	send_ಸಂದೇಶ(ret, ಸಂದೇಶ);

	get_ಸಂದೇಶ_extended(ret, ಸಂದೇಶ, 1);

	/* Expecting a VERSION reply */
	ಆದರೆ ((r = sshbuf_get_u8(ಸಂದೇಶ, &type)) != 0)
		fatal_fr(r, "parse type");
	ಆದರೆ (type != SSH2_FXP_ಆವೃತ್ತಿ) {
		error("Invalid packet back from SSH2_FXP_INIT (type %u)",
		    type);
		sshbuf_free(ಸಂದೇಶ);
		ಬಿಡುಗಡೆ(ret);
		ಹಿಂತಿರುಗಿ(ಖಾಲಿ);
	}
	ಆದರೆ ((r = sshbuf_get_u32(ಸಂದೇಶ, &ret->ಆವೃತ್ತಿ)) != 0)
		fatal_fr(r, "parse version");

	debug2("Remote version: %u", ret->ಆವೃತ್ತಿ);

	/* Check for extensions */
	ಆಗ (sshbuf_len(ಸಂದೇಶ) > 0) {
		ಅಕ್ಷರ *name;
		u_char *ಮೌಲ್ಯ;
		ಗಾತ್ರ_t vlen;
		ಪೂರ್ಣಾಂಕ ತಿಳಿದ = 0;

		ಆದರೆ ((r = sshbuf_get_cstring(ಸಂದೇಶ, &name, ಖಾಲಿ)) != 0 ||
		    (r = sshbuf_get_string(ಸಂದೇಶ, &ಮೌಲ್ಯ, &vlen)) != 0)
			fatal_fr(r, "parse extension");
		ಆದರೆ (strcmp(name, "posix-rename@openssh.com") == 0 &&
		    strcmp((ಅಕ್ಷರ *)ಮೌಲ್ಯ, "1") == 0) {
			ret->exts |= SFTP_EXT_POSIX_RENAME;
			ತಿಳಿದ = 1;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(name, "statvfs@openssh.com") == 0 &&
		    strcmp((ಅಕ್ಷರ *)ಮೌಲ್ಯ, "2") == 0) {
			ret->exts |= SFTP_EXT_STATVFS;
			ತಿಳಿದ = 1;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(name, "fstatvfs@openssh.com") == 0 &&
		    strcmp((ಅಕ್ಷರ *)ಮೌಲ್ಯ, "2") == 0) {
			ret->exts |= SFTP_EXT_FSTATVFS;
			ತಿಳಿದ = 1;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(name, "hardlink@openssh.com") == 0 &&
		    strcmp((ಅಕ್ಷರ *)ಮೌಲ್ಯ, "1") == 0) {
			ret->exts |= SFTP_EXT_HARDLINK;
			ತಿಳಿದ = 1;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(name, "fsync@openssh.com") == 0 &&
		    strcmp((ಅಕ್ಷರ *)ಮೌಲ್ಯ, "1") == 0) {
			ret->exts |= SFTP_EXT_FSYNC;
			ತಿಳಿದ = 1;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(name, "lsetstat@openssh.com") == 0 &&
		    strcmp((ಅಕ್ಷರ *)ಮೌಲ್ಯ, "1") == 0) {
			ret->exts |= SFTP_EXT_LSETSTAT;
			ತಿಳಿದ = 1;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(name, "limits@openssh.com") == 0 &&
		    strcmp((ಅಕ್ಷರ *)ಮೌಲ್ಯ, "1") == 0) {
			ret->exts |= SFTP_EXT_LIMITS;
			ತಿಳಿದ = 1;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(name, "expand-path@openssh.com") == 0 &&
		    strcmp((ಅಕ್ಷರ *)ಮೌಲ್ಯ, "1") == 0) {
			ret->exts |= SFTP_EXT_ಮಾರ್ಗ_EXPAND;
			ತಿಳಿದ = 1;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(name, "copy-data") == 0 &&
		    strcmp((ಅಕ್ಷರ *)ಮೌಲ್ಯ, "1") == 0) {
			ret->exts |= SFTP_EXT_COPY_ದತ್ತಾಂಶ;
			ತಿಳಿದ = 1;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(name,
		    "users-groups-by-id@openssh.com") == 0 &&
		    strcmp((ಅಕ್ಷರ *)ಮೌಲ್ಯ, "1") == 0) {
			ret->exts |= SFTP_EXT_GETUSERSGROUPS_BY_ID;
			ತಿಳಿದ = 1;
		}
		ಆದರೆ (ತಿಳಿದ) {
			debug2("Server supports extension \"%s\" revision %s",
			    name, ಮೌಲ್ಯ);
		} ಇಲ್ಲದಿದ್ದರೆ {
			debug2("Unrecognised server extension \"%s\"", name);
		}
		ಬಿಡುಗಡೆ(name);
		ಬಿಡುಗಡೆ(ಮೌಲ್ಯ);
	}

	sshbuf_free(ಸಂದೇಶ);

	/* Query the server for its limits */
	ಆದರೆ (ret->exts & SFTP_EXT_LIMITS) {
		ರಚನೆ sftp_limits limits;
		ಆದರೆ (sftp_get_limits(ret, &limits) != 0)
			fatal_f("limits failed");

		/* If the caller did not specify, find a good value */
		ಆದರೆ (transfer_buflen == 0) {
			ret->download_buflen = MINIMUM(limits.read_ಉದ್ದಳತೆ,
			    SFTP_MAX_ಸಂದೇಶ_ಉದ್ದಳತೆ - 1024);
			ret->upload_buflen = MINIMUM(limits.write_ಉದ್ದಳತೆ,
			    SFTP_MAX_ಸಂದೇಶ_ಉದ್ದಳತೆ - 1024);
			ret->download_buflen = ಗರಿಷ್ಠ(ret->download_buflen, 64);
			ret->upload_buflen = ಗರಿಷ್ಠ(ret->upload_buflen, 64);
			debug3("server upload/download buffer sizes "
			    "%llu / %llu; using %u / %u",
			    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)limits.write_ಉದ್ದಳತೆ,
			    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)limits.read_ಉದ್ದಳತೆ,
			    ret->upload_buflen, ret->download_buflen);
		}
	}

	/* Some filexfer v.0 servers don't support large packets */
	ಆದರೆ (ret->ಆವೃತ್ತಿ == 0) {
		ret->download_buflen = MINIMUM(ret->download_buflen, 20480);
		ret->upload_buflen = MINIMUM(ret->upload_buflen, 20480);
	}

	ret->ಎಲ್ಲೆ_kbps = ಎಲ್ಲೆ_kbps;
	ಆದರೆ (ret->ಎಲ್ಲೆ_kbps > 0) {
		bandwidth_ಎಲ್ಲೆ_init(&ret->bwlimit_ಒಳ, ret->ಎಲ್ಲೆ_kbps,
		    ret->download_buflen);
		bandwidth_ಎಲ್ಲೆ_init(&ret->bwlimit_ಹೊರಹೋಗು, ret->ಎಲ್ಲೆ_kbps,
		    ret->upload_buflen);
	}

	ಹಿಂತಿರುಗಿ ret;
}

ಶೂನ್ಯ
sftp_free(ರಚನೆ sftp_conn *conn)
{
	ಆದರೆ (conn == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	freezero(conn, ಗಾತ್ರ(*conn));
}

u_int
sftp_proto_ಆವೃತ್ತಿ(ರಚನೆ sftp_conn *conn)
{
	ಹಿಂತಿರುಗಿ conn->ಆವೃತ್ತಿ;
}

ಪೂರ್ಣಾಂಕ
sftp_get_limits(ರಚನೆ sftp_conn *conn, ರಚನೆ sftp_limits *limits)
{
	u_int id, ಸಂದೇಶ_id;
	u_char type;
	ರಚನೆ sshbuf *ಸಂದೇಶ;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((conn->exts & SFTP_EXT_LIMITS) == 0) {
		error("Server does not support limits@openssh.com extension");
		ಹಿಂತಿರುಗಿ -1;
	}

	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");

	id = conn->ಸಂದೇಶ_id++;
	ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, "limits@openssh.com")) != 0)
		fatal_fr(r, "compose");
	send_ಸಂದೇಶ(conn, ಸಂದೇಶ);
	debug3("Sent message limits@openssh.com I:%u", id);

	get_ಸಂದೇಶ(conn, ಸಂದೇಶ);

	ಆದರೆ ((r = sshbuf_get_u8(ಸಂದೇಶ, &type)) != 0 ||
	    (r = sshbuf_get_u32(ಸಂದೇಶ, &ಸಂದೇಶ_id)) != 0)
		fatal_fr(r, "parse");

	debug3("Received limits reply T:%u I:%u", type, ಸಂದೇಶ_id);
	ಆದರೆ (id != ಸಂದೇಶ_id)
		fatal("ID mismatch (%u != %u)", ಸಂದೇಶ_id, id);
	ಆದರೆ (type != SSH2_FXP_EXTENDED_ಉತ್ತರ) {
		debug_f("expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_ಉತ್ತರ, type);
		/* Disable the limits extension */
		conn->exts &= ~SFTP_EXT_LIMITS;
		sshbuf_free(ಸಂದೇಶ);
		ಹಿಂತಿರುಗಿ -1;
	}

	memset(limits, 0, ಗಾತ್ರ(*limits));
	ಆದರೆ ((r = sshbuf_get_u64(ಸಂದೇಶ, &limits->packet_ಉದ್ದಳತೆ)) != 0 ||
	    (r = sshbuf_get_u64(ಸಂದೇಶ, &limits->read_ಉದ್ದಳತೆ)) != 0 ||
	    (r = sshbuf_get_u64(ಸಂದೇಶ, &limits->write_ಉದ್ದಳತೆ)) != 0 ||
	    (r = sshbuf_get_u64(ಸಂದೇಶ, &limits->open_handles)) != 0)
		fatal_fr(r, "parse limits");

	sshbuf_free(ಸಂದೇಶ);

	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sftp_close(ರಚನೆ sftp_conn *conn, ಸ್ಥಿರಾಂಕ u_char *handle, u_int handle_len)
{
	u_int id, ಸ್ಥಿತಿ_2;
	ರಚನೆ sshbuf *ಸಂದೇಶ;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");

	id = conn->ಸಂದೇಶ_id++;
	ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_CLOSE)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
	    (r = sshbuf_put_string(ಸಂದೇಶ, handle, handle_len)) != 0)
		fatal_fr(r, "parse");
	send_ಸಂದೇಶ(conn, ಸಂದೇಶ);
	debug3("Sent message SSH2_FXP_CLOSE I:%u", id);

	ಸ್ಥಿತಿ_2 = get_ಸ್ಥಿತಿ(conn, id);
	ಆದರೆ (ಸ್ಥಿತಿ_2 != SSH2_FX_OK)
		error("close remote: %s", fx2txt(ಸ್ಥಿತಿ_2));

	sshbuf_free(ಸಂದೇಶ);

	ಹಿಂತಿರುಗಿ ಸ್ಥಿತಿ_2 == SSH2_FX_OK ? 0 : -1;
}


ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sftp_lsreaddir(ರಚನೆ sftp_conn *conn, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, ಪೂರ್ಣಾಂಕ print_flag,
    SFTP_DIRENT ***dir)
{
	ರಚನೆ sshbuf *ಸಂದೇಶ;
	u_int ಎಣಿಕೆ_2, id, i, expected_id, ents = 0;
	ಗಾತ್ರ_t handle_len;
	u_char type, *handle;
	ಪೂರ್ಣಾಂಕ ಸ್ಥಿತಿ_2 = SSH2_FX_FAILURE;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (dir)
		*dir = ಖಾಲಿ;

	id = conn->ಸಂದೇಶ_id++;

	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_OPENDIR)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, ಮಾರ್ಗ)) != 0)
		fatal_fr(r, "compose OPENDIR");
	send_ಸಂದೇಶ(conn, ಸಂದೇಶ);

	handle = get_handle(conn, id, &handle_len,
	    "remote readdir(\"%s\")", ಮಾರ್ಗ);
	ಆದರೆ (handle == ಖಾಲಿ) {
		sshbuf_free(ಸಂದೇಶ);
		ಹಿಂತಿರುಗಿ -1;
	}

	ಆದರೆ (dir) {
		ents = 0;
		*dir = xcalloc(1, ಗಾತ್ರ(**dir));
		(*dir)[0] = ಖಾಲಿ;
	}

	ಗಾಗಿ (; !interrupted;) {
		id = expected_id = conn->ಸಂದೇಶ_id++;

		debug3("Sending SSH2_FXP_READDIR I:%u", id);

		sshbuf_reset(ಸಂದೇಶ);
		ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_READDIR)) != 0 ||
		    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
		    (r = sshbuf_put_string(ಸಂದೇಶ, handle, handle_len)) != 0)
			fatal_fr(r, "compose READDIR");
		send_ಸಂದೇಶ(conn, ಸಂದೇಶ);

		sshbuf_reset(ಸಂದೇಶ);

		get_ಸಂದೇಶ(conn, ಸಂದೇಶ);

		ಆದರೆ ((r = sshbuf_get_u8(ಸಂದೇಶ, &type)) != 0 ||
		    (r = sshbuf_get_u32(ಸಂದೇಶ, &id)) != 0)
			fatal_fr(r, "parse");

		debug3("Received reply T:%u I:%u", type, id);

		ಆದರೆ (id != expected_id)
			fatal("ID mismatch (%u != %u)", id, expected_id);

		ಆದರೆ (type == SSH2_FXP_ಸ್ಥಿತಿ) {
			u_int rstatus;

			ಆದರೆ ((r = sshbuf_get_u32(ಸಂದೇಶ, &rstatus)) != 0)
				fatal_fr(r, "parse status");
			debug3("Received SSH2_FXP_STATUS %d", rstatus);
			ಆದರೆ (rstatus == SSH2_FX_EOF)
				ನಿಲ್ಲಿಸು;
			error("Couldn't read directory: %s", fx2txt(rstatus));
			ಹೋಗು ಹೊರಹೋಗು;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (type != SSH2_FXP_NAME)
			fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
			    SSH2_FXP_NAME, type);

		ಆದರೆ ((r = sshbuf_get_u32(ಸಂದೇಶ, &ಎಣಿಕೆ_2)) != 0)
			fatal_fr(r, "parse count");
		ಆದರೆ (ಎಣಿಕೆ_2 > SSHBUF_ಗಾತ್ರ_MAX)
			fatal_f("nonsensical number of entries");
		ಆದರೆ (ಎಣಿಕೆ_2 == 0)
			ನಿಲ್ಲಿಸು;
		debug3("Received %d SSH2_FXP_NAME responses", ಎಣಿಕೆ_2);
		ಗಾಗಿ (i = 0; i < ಎಣಿಕೆ_2; i++) {
			ಅಕ್ಷರ *filename, *longname;
			Attrib a;

			ಆದರೆ ((r = sshbuf_get_cstring(ಸಂದೇಶ, &filename,
			    ಖಾಲಿ)) != 0 ||
			    (r = sshbuf_get_cstring(ಸಂದೇಶ, &longname,
			    ಖಾಲಿ)) != 0)
				fatal_fr(r, "parse filenames");
			ಆದರೆ ((r = decode_attrib(ಸಂದೇಶ, &a)) != 0) {
				error_fr(r, "couldn't decode attrib");
				ಬಿಡುಗಡೆ(filename);
				ಬಿಡುಗಡೆ(longname);
				ಹೋಗು ಹೊರಹೋಗು;
			}

			ಆದರೆ (print_flag)
				mprintf("%s\n", longname);

			/*
			 * Directory entries should never contain '/'
			 * These can be used to attack recursive ops
			 * (e.g. send '../../../../etc/passwd')
			 */
			ಆದರೆ (*filename == '\0' ||
			    strpbrk(filename, SFTP_DIRECTORY_CHARS) != ಖಾಲಿ) {
				error("Server sent suspect path \"%s\" "
				    "during readdir of \"%s\"", filename, ಮಾರ್ಗ);
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (dir) {
				*dir = xreallocarray(*dir, ents + 2, ಗಾತ್ರ(**dir));
				(*dir)[ents] = xcalloc(1, ಗಾತ್ರ(***dir));
				(*dir)[ents]->filename = xstrdup(filename);
				(*dir)[ents]->longname = xstrdup(longname);
				ಸ್ಮರಣೆ_ನಕಲು(&(*dir)[ents]->a, &a, ಗಾತ್ರ(a));
				(*dir)[++ents] = ಖಾಲಿ;
			}
			ಬಿಡುಗಡೆ(filename);
			ಬಿಡುಗಡೆ(longname);
		}
	}
	ಸ್ಥಿತಿ_2 = 0;

 ಹೊರಹೋಗು:
	sshbuf_free(ಸಂದೇಶ);
	sftp_close(conn, handle, handle_len);
	ಬಿಡುಗಡೆ(handle);

	ಆದರೆ (ಸ್ಥಿತಿ_2 != 0 && dir != ಖಾಲಿ) {
		/* Don't return results on error */
		sftp_free_dirents(*dir);
		*dir = ಖಾಲಿ;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (interrupted && dir != ಖಾಲಿ && *dir != ಖಾಲಿ) {
		/* Don't return partial matches on interrupt */
		sftp_free_dirents(*dir);
		*dir = xcalloc(1, ಗಾತ್ರ(**dir));
		**dir = ಖಾಲಿ;
	}

	ಹಿಂತಿರುಗಿ ಸ್ಥಿತಿ_2 == SSH2_FX_OK ? 0 : -1;
}

ಪೂರ್ಣಾಂಕ
sftp_readdir(ರಚನೆ sftp_conn *conn, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, SFTP_DIRENT ***dir)
{
	ಹಿಂತಿರುಗಿ sftp_lsreaddir(conn, ಮಾರ್ಗ, 0, dir);
}

ಶೂನ್ಯ sftp_free_dirents(SFTP_DIRENT **s)
{
	ಪೂರ್ಣಾಂಕ i;

	ಆದರೆ (s == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	ಗಾಗಿ (i = 0; s[i]; i++) {
		ಬಿಡುಗಡೆ(s[i]->filename);
		ಬಿಡುಗಡೆ(s[i]->longname);
		ಬಿಡುಗಡೆ(s[i]);
	}
	ಬಿಡುಗಡೆ(s);
}

ಪೂರ್ಣಾಂಕ
sftp_rm(ರಚನೆ sftp_conn *conn, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ)
{
	u_int ಸ್ಥಿತಿ_2, id;

	debug2("Sending SSH2_FXP_REMOVE \"%s\"", ಮಾರ್ಗ);

	id = conn->ಸಂದೇಶ_id++;
	send_string_request(conn, id, SSH2_FXP_REMOVE, ಮಾರ್ಗ, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಮಾರ್ಗ));
	ಸ್ಥಿತಿ_2 = get_ಸ್ಥಿತಿ(conn, id);
	ಆದರೆ (ಸ್ಥಿತಿ_2 != SSH2_FX_OK)
		error("remote delete %s: %s", ಮಾರ್ಗ, fx2txt(ಸ್ಥಿತಿ_2));
	ಹಿಂತಿರುಗಿ ಸ್ಥಿತಿ_2 == SSH2_FX_OK ? 0 : -1;
}

ಪೂರ್ಣಾಂಕ
sftp_mkdir(ರಚನೆ sftp_conn *conn, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, Attrib *a, ಪೂರ್ಣಾಂಕ print_flag)
{
	u_int ಸ್ಥಿತಿ_2, id;

	debug2("Sending SSH2_FXP_MKDIR \"%s\"", ಮಾರ್ಗ);

	id = conn->ಸಂದೇಶ_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_MKDIR, ಮಾರ್ಗ,
	    ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಮಾರ್ಗ), a);

	ಸ್ಥಿತಿ_2 = get_ಸ್ಥಿತಿ(conn, id);
	ಆದರೆ (ಸ್ಥಿತಿ_2 != SSH2_FX_OK && print_flag)
		error("remote mkdir \"%s\": %s", ಮಾರ್ಗ, fx2txt(ಸ್ಥಿತಿ_2));

	ಹಿಂತಿರುಗಿ ಸ್ಥಿತಿ_2 == SSH2_FX_OK ? 0 : -1;
}

ಪೂರ್ಣಾಂಕ
sftp_mkpath(ರಚನೆ sftp_conn *conn, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, Attrib *a, ಪೂರ್ಣಾಂಕ print_flag)
{
	ಅಕ್ಷರ *slash, *tmp_ಮಾರ್ಗ;
	ಪೂರ್ಣಾಂಕ ಮುಗಿದ;

	tmp_ಮಾರ್ಗ = xstrdup(ಮಾರ್ಗ);
	slash = tmp_ಮಾರ್ಗ;

	ಗಾಗಿ (;;) {
		slash += strspn(slash, "/");
		slash += strcspn(slash, "/");

		ಮುಗಿದ = (*slash == '\0');
		*slash = '\0';

		ಆದರೆ (!sftp_remote_is_dir(conn, tmp_ಮಾರ್ಗ)) {
			ಆದರೆ (sftp_mkdir(conn, tmp_ಮಾರ್ಗ, a, print_flag) != 0) {
				ಬಿಡುಗಡೆ(tmp_ಮಾರ್ಗ);
				ಹಿಂತಿರುಗಿ -1;
			}
		}

		ಆದರೆ (ಮುಗಿದ)
			ನಿಲ್ಲಿಸು;

		*slash = '/';
	}

	ಬಿಡುಗಡೆ(tmp_ಮಾರ್ಗ);
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sftp_rmdir(ರಚನೆ sftp_conn *conn, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ)
{
	u_int ಸ್ಥಿತಿ_2, id;

	debug2("Sending SSH2_FXP_RMDIR \"%s\"", ಮಾರ್ಗ);

	id = conn->ಸಂದೇಶ_id++;
	send_string_request(conn, id, SSH2_FXP_RMDIR, ಮಾರ್ಗ,
	    ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಮಾರ್ಗ));

	ಸ್ಥಿತಿ_2 = get_ಸ್ಥಿತಿ(conn, id);
	ಆದರೆ (ಸ್ಥಿತಿ_2 != SSH2_FX_OK)
		error("remote rmdir \"%s\": %s", ಮಾರ್ಗ, fx2txt(ಸ್ಥಿತಿ_2));

	ಹಿಂತಿರುಗಿ ಸ್ಥಿತಿ_2 == SSH2_FX_OK ? 0 : -1;
}

ಪೂರ್ಣಾಂಕ
sftp_stat(ರಚನೆ sftp_conn *conn, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, ಪೂರ್ಣಾಂಕ quiet, Attrib *a)
{
	u_int id;

	debug2("Sending SSH2_FXP_STAT \"%s\"", ಮಾರ್ಗ);

	id = conn->ಸಂದೇಶ_id++;

	send_string_request(conn, id,
	    conn->ಆವೃತ್ತಿ == 0 ? SSH2_FXP_STAT_ಆವೃತ್ತಿ_0 : SSH2_FXP_STAT,
	    ಮಾರ್ಗ, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಮಾರ್ಗ));

	ಹಿಂತಿರುಗಿ get_decode_stat(conn, id, quiet, a);
}

ಪೂರ್ಣಾಂಕ
sftp_lstat(ರಚನೆ sftp_conn *conn, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, ಪೂರ್ಣಾಂಕ quiet, Attrib *a)
{
	u_int id;

	ಆದರೆ (conn->ಆವೃತ್ತಿ == 0) {
		do_log2(quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_INFO,
		    "Server version does not support lstat operation");
		ಹಿಂತಿರುಗಿ sftp_stat(conn, ಮಾರ್ಗ, quiet, a);
	}

	id = conn->ಸಂದೇಶ_id++;
	send_string_request(conn, id, SSH2_FXP_LSTAT, ಮಾರ್ಗ,
	    ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಮಾರ್ಗ));

	ಹಿಂತಿರುಗಿ get_decode_stat(conn, id, quiet, a);
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ notyet
ಪೂರ್ಣಾಂಕ
sftp_fstat(ರಚನೆ sftp_conn *conn, ಸ್ಥಿರಾಂಕ u_char *handle, u_int handle_len,
    ಪೂರ್ಣಾಂಕ quiet, Attrib *a)
{
	u_int id;

	debug2("Sending SSH2_FXP_FSTAT \"%s\"");

	id = conn->ಸಂದೇಶ_id++;
	send_string_request(conn, id, SSH2_FXP_FSTAT, handle,
	    handle_len);

	ಹಿಂತಿರುಗಿ get_decode_stat(conn, id, quiet, a);
}
#ಆದರೆ_ಅಂತ್ಯ

ಪೂರ್ಣಾಂಕ
sftp_setstat(ರಚನೆ sftp_conn *conn, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, Attrib *a)
{
	u_int ಸ್ಥಿತಿ_2, id;

	debug2("Sending SSH2_FXP_SETSTAT \"%s\"", ಮಾರ್ಗ);

	id = conn->ಸಂದೇಶ_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_SETSTAT, ಮಾರ್ಗ,
	    ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಮಾರ್ಗ), a);

	ಸ್ಥಿತಿ_2 = get_ಸ್ಥಿತಿ(conn, id);
	ಆದರೆ (ಸ್ಥಿತಿ_2 != SSH2_FX_OK)
		error("remote setstat \"%s\": %s", ಮಾರ್ಗ, fx2txt(ಸ್ಥಿತಿ_2));

	ಹಿಂತಿರುಗಿ ಸ್ಥಿತಿ_2 == SSH2_FX_OK ? 0 : -1;
}

ಪೂರ್ಣಾಂಕ
sftp_fsetstat(ರಚನೆ sftp_conn *conn, ಸ್ಥಿರಾಂಕ u_char *handle, u_int handle_len,
    Attrib *a)
{
	u_int ಸ್ಥಿತಿ_2, id;

	debug2("Sending SSH2_FXP_FSETSTAT");

	id = conn->ಸಂದೇಶ_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_FSETSTAT, handle,
	    handle_len, a);

	ಸ್ಥಿತಿ_2 = get_ಸ್ಥಿತಿ(conn, id);
	ಆದರೆ (ಸ್ಥಿತಿ_2 != SSH2_FX_OK)
		error("remote fsetstat: %s", fx2txt(ಸ್ಥಿತಿ_2));

	ಹಿಂತಿರುಗಿ ಸ್ಥಿತಿ_2 == SSH2_FX_OK ? 0 : -1;
}

/* Implements both the realpath and expand-path operations */
ಸ್ಥಿರ ಅಕ್ಷರ *
sftp_realpath_expand(ರಚನೆ sftp_conn *conn, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, ಪೂರ್ಣಾಂಕ expand)
{
	ರಚನೆ sshbuf *ಸಂದೇಶ;
	u_int expected_id, ಎಣಿಕೆ_2, id;
	ಅಕ್ಷರ *filename, *longname;
	Attrib a;
	u_char type;
	ಪೂರ್ಣಾಂಕ r;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *what = "SSH2_FXP_REALPATH";

	ಆದರೆ (expand)
		what = "expand-path@openssh.com";
	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");

	expected_id = id = conn->ಸಂದೇಶ_id++;
	ಆದರೆ (expand) {
		debug2("Sending SSH2_FXP_EXTENDED(expand-path@openssh.com) "
		    "\"%s\"", ಮಾರ್ಗ);
		ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_EXTENDED)) != 0 ||
		    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
		    (r = sshbuf_put_cstring(ಸಂದೇಶ,
		    "expand-path@openssh.com")) != 0 ||
		    (r = sshbuf_put_cstring(ಸಂದೇಶ, ಮಾರ್ಗ)) != 0)
			fatal_fr(r, "compose %s", what);
		send_ಸಂದೇಶ(conn, ಸಂದೇಶ);
	} ಇಲ್ಲದಿದ್ದರೆ {
		debug2("Sending SSH2_FXP_REALPATH \"%s\"", ಮಾರ್ಗ);
		send_string_request(conn, id, SSH2_FXP_REALPATH,
		    ಮಾರ್ಗ, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಮಾರ್ಗ));
	}
	get_ಸಂದೇಶ(conn, ಸಂದೇಶ);
	ಆದರೆ ((r = sshbuf_get_u8(ಸಂದೇಶ, &type)) != 0 ||
	    (r = sshbuf_get_u32(ಸಂದೇಶ, &id)) != 0)
		fatal_fr(r, "parse");

	ಆದರೆ (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);

	ಆದರೆ (type == SSH2_FXP_ಸ್ಥಿತಿ) {
		u_int ಸ್ಥಿತಿ_2;
		ಅಕ್ಷರ *errmsg;

		ಆದರೆ ((r = sshbuf_get_u32(ಸಂದೇಶ, &ಸ್ಥಿತಿ_2)) != 0 ||
		    (r = sshbuf_get_cstring(ಸಂದೇಶ, &errmsg, ಖಾಲಿ)) != 0)
			fatal_fr(r, "parse status");
		error("%s %s: %s", expand ? "expand" : "realpath",
		    ಮಾರ್ಗ, *errmsg == '\0' ? fx2txt(ಸ್ಥಿತಿ_2) : errmsg);
		ಬಿಡುಗಡೆ(errmsg);
		sshbuf_free(ಸಂದೇಶ);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (type != SSH2_FXP_NAME)
		fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
		    SSH2_FXP_NAME, type);

	ಆದರೆ ((r = sshbuf_get_u32(ಸಂದೇಶ, &ಎಣಿಕೆ_2)) != 0)
		fatal_fr(r, "parse count");
	ಆದರೆ (ಎಣಿಕೆ_2 != 1)
		fatal("Got multiple names (%d) from %s", ಎಣಿಕೆ_2, what);

	ಆದರೆ ((r = sshbuf_get_cstring(ಸಂದೇಶ, &filename, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_cstring(ಸಂದೇಶ, &longname, ಖಾಲಿ)) != 0 ||
	    (r = decode_attrib(ಸಂದೇಶ, &a)) != 0)
		fatal_fr(r, "parse filename/attrib");

	debug3("%s %s -> %s", what, ಮಾರ್ಗ, filename);

	ಬಿಡುಗಡೆ(longname);

	sshbuf_free(ಸಂದೇಶ);

	ಹಿಂತಿರುಗಿ(filename);
}

ಅಕ್ಷರ *
sftp_realpath(ರಚನೆ sftp_conn *conn, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ)
{
	ಹಿಂತಿರುಗಿ sftp_realpath_expand(conn, ಮಾರ್ಗ, 0);
}

ಪೂರ್ಣಾಂಕ
sftp_can_expand_ಮಾರ್ಗ(ರಚನೆ sftp_conn *conn)
{
	ಹಿಂತಿರುಗಿ (conn->exts & SFTP_EXT_ಮಾರ್ಗ_EXPAND) != 0;
}

ಅಕ್ಷರ *
sftp_expand_ಮಾರ್ಗ(ರಚನೆ sftp_conn *conn, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ)
{
	ಆದರೆ (!sftp_can_expand_ಮಾರ್ಗ(conn)) {
		debug3_f("no server support, fallback to realpath");
		ಹಿಂತಿರುಗಿ sftp_realpath_expand(conn, ಮಾರ್ಗ, 0);
	}
	ಹಿಂತಿರುಗಿ sftp_realpath_expand(conn, ಮಾರ್ಗ, 1);
}

ಪೂರ್ಣಾಂಕ
sftp_copy(ರಚನೆ sftp_conn *conn, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *oldpath, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *newpath)
{
	Attrib junk, attr;
	ರಚನೆ sshbuf *ಸಂದೇಶ;
	u_char *old_handle, *new_handle;
	u_int ಬಹುಲಕ, ಸ್ಥಿತಿ_2, id;
	ಗಾತ್ರ_t old_handle_len, new_handle_len;
	ಪೂರ್ಣಾಂಕ r;

	/* Return if the extension is not supported */
	ಆದರೆ ((conn->exts & SFTP_EXT_COPY_ದತ್ತಾಂಶ) == 0) {
		error("Server does not support copy-data extension");
		ಹಿಂತಿರುಗಿ -1;
	}

	/* Make sure the file exists, and we can copy its perms */
	ಆದರೆ (sftp_stat(conn, oldpath, 0, &attr) != 0)
		ಹಿಂತಿರುಗಿ -1;

	/* Do not preserve set[ug]id here, as we do not preserve ownership */
	ಆದರೆ (attr.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		ಬಹುಲಕ = attr.perm & 0777;

		ಆದರೆ (!S_ISREG(attr.perm)) {
			error("Cannot copy non-regular file: %s", oldpath);
			ಹಿಂತಿರುಗಿ -1;
		}
	} ಇಲ್ಲದಿದ್ದರೆ {
		/* NB: The user's umask will apply to this */
		ಬಹುಲಕ = 0666;
	}

	/* Set up the new perms for the new file */
	attrib_clear(&attr);
	attr.perm = ಬಹುಲಕ;
	attr.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;

	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");

	attrib_clear(&junk); /* Send empty attributes */

	/* Open the old file for reading */
	id = conn->ಸಂದೇಶ_id++;
	ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_OPEN)) != 0 ||
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
	ಆದರೆ (old_handle == ಖಾಲಿ) {
		sshbuf_free(ಸಂದೇಶ);
		ಹಿಂತಿರುಗಿ -1;
	}

	/* Open the new file for writing */
	id = conn->ಸಂದೇಶ_id++;
	ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_OPEN)) != 0 ||
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
	ಆದರೆ (new_handle == ಖಾಲಿ) {
		sshbuf_free(ಸಂದೇಶ);
		ಬಿಡುಗಡೆ(old_handle);
		ಹಿಂತಿರುಗಿ -1;
	}

	/* Copy the file data */
	id = conn->ಸಂದೇಶ_id++;
	ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_EXTENDED)) != 0 ||
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

	ಸ್ಥಿತಿ_2 = get_ಸ್ಥಿತಿ(conn, id);
	ಆದರೆ (ಸ್ಥಿತಿ_2 != SSH2_FX_OK)
		error("Couldn't copy file \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(ಸ್ಥಿತಿ_2));

	/* Clean up everything */
	sshbuf_free(ಸಂದೇಶ);
	sftp_close(conn, old_handle, old_handle_len);
	sftp_close(conn, new_handle, new_handle_len);
	ಬಿಡುಗಡೆ(old_handle);
	ಬಿಡುಗಡೆ(new_handle);

	ಹಿಂತಿರುಗಿ ಸ್ಥಿತಿ_2 == SSH2_FX_OK ? 0 : -1;
}

ಪೂರ್ಣಾಂಕ
sftp_rename(ರಚನೆ sftp_conn *conn, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *oldpath, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *newpath,
    ಪೂರ್ಣಾಂಕ force_legacy)
{
	ರಚನೆ sshbuf *ಸಂದೇಶ;
	u_int ಸ್ಥಿತಿ_2, id;
	ಪೂರ್ಣಾಂಕ r, use_ext = (conn->exts & SFTP_EXT_POSIX_RENAME) && !force_legacy;

	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");

	/* Send rename request */
	id = conn->ಸಂದೇಶ_id++;
	ಆದರೆ (use_ext) {
		debug2("Sending SSH2_FXP_EXTENDED(posix-rename@openssh.com) "
		    "\"%s\" to \"%s\"", oldpath, newpath);
		ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_EXTENDED)) != 0 ||
		    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
		    (r = sshbuf_put_cstring(ಸಂದೇಶ,
		    "posix-rename@openssh.com")) != 0)
			fatal_fr(r, "compose posix-rename");
	} ಇಲ್ಲದಿದ್ದರೆ {
		debug2("Sending SSH2_FXP_RENAME \"%s\" to \"%s\"",
		    oldpath, newpath);
		ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_RENAME)) != 0 ||
		    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0)
			fatal_fr(r, "compose rename");
	}
	ಆದರೆ ((r = sshbuf_put_cstring(ಸಂದೇಶ, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, newpath)) != 0)
		fatal_fr(r, "compose paths");
	send_ಸಂದೇಶ(conn, ಸಂದೇಶ);
	debug3("Sent message %s \"%s\" -> \"%s\"",
	    use_ext ? "posix-rename@openssh.com" :
	    "SSH2_FXP_RENAME", oldpath, newpath);
	sshbuf_free(ಸಂದೇಶ);

	ಸ್ಥಿತಿ_2 = get_ಸ್ಥಿತಿ(conn, id);
	ಆದರೆ (ಸ್ಥಿತಿ_2 != SSH2_FX_OK)
		error("remote rename \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(ಸ್ಥಿತಿ_2));

	ಹಿಂತಿರುಗಿ ಸ್ಥಿತಿ_2 == SSH2_FX_OK ? 0 : -1;
}

ಪೂರ್ಣಾಂಕ
sftp_hardlink(ರಚನೆ sftp_conn *conn, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *oldpath, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *newpath)
{
	ರಚನೆ sshbuf *ಸಂದೇಶ;
	u_int ಸ್ಥಿತಿ_2, id;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((conn->exts & SFTP_EXT_HARDLINK) == 0) {
		error("Server does not support hardlink@openssh.com extension");
		ಹಿಂತಿರುಗಿ -1;
	}
	debug2("Sending SSH2_FXP_EXTENDED(hardlink@openssh.com) "
	    "\"%s\" to \"%s\"", oldpath, newpath);

	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");

	/* Send link request */
	id = conn->ಸಂದೇಶ_id++;
	ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, "hardlink@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, newpath)) != 0)
		fatal_fr(r, "compose");
	send_ಸಂದೇಶ(conn, ಸಂದೇಶ);
	debug3("Sent message hardlink@openssh.com \"%s\" -> \"%s\"",
	    oldpath, newpath);
	sshbuf_free(ಸಂದೇಶ);

	ಸ್ಥಿತಿ_2 = get_ಸ್ಥಿತಿ(conn, id);
	ಆದರೆ (ಸ್ಥಿತಿ_2 != SSH2_FX_OK)
		error("remote link \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(ಸ್ಥಿತಿ_2));

	ಹಿಂತಿರುಗಿ ಸ್ಥಿತಿ_2 == SSH2_FX_OK ? 0 : -1;
}

ಪೂರ್ಣಾಂಕ
sftp_symlink(ರಚನೆ sftp_conn *conn, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *oldpath, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *newpath)
{
	ರಚನೆ sshbuf *ಸಂದೇಶ;
	u_int ಸ್ಥಿತಿ_2, id;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (conn->ಆವೃತ್ತಿ < 3) {
		error("This server does not support the symlink operation");
		ಹಿಂತಿರುಗಿ(SSH2_FX_OP_UNSUPPORTED);
	}
	debug2("Sending SSH2_FXP_SYMLINK \"%s\" to \"%s\"", oldpath, newpath);

	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");

	/* Send symlink request */
	id = conn->ಸಂದೇಶ_id++;
	ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_SYMLINK)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, newpath)) != 0)
		fatal_fr(r, "compose");
	send_ಸಂದೇಶ(conn, ಸಂದೇಶ);
	debug3("Sent message SSH2_FXP_SYMLINK \"%s\" -> \"%s\"", oldpath,
	    newpath);
	sshbuf_free(ಸಂದೇಶ);

	ಸ್ಥಿತಿ_2 = get_ಸ್ಥಿತಿ(conn, id);
	ಆದರೆ (ಸ್ಥಿತಿ_2 != SSH2_FX_OK)
		error("remote symlink file \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(ಸ್ಥಿತಿ_2));

	ಹಿಂತಿರುಗಿ ಸ್ಥಿತಿ_2 == SSH2_FX_OK ? 0 : -1;
}

ಪೂರ್ಣಾಂಕ
sftp_fsync(ರಚನೆ sftp_conn *conn, u_char *handle, u_int handle_len)
{
	ರಚನೆ sshbuf *ಸಂದೇಶ;
	u_int ಸ್ಥಿತಿ_2, id;
	ಪೂರ್ಣಾಂಕ r;

	/* Silently return if the extension is not supported */
	ಆದರೆ ((conn->exts & SFTP_EXT_FSYNC) == 0)
		ಹಿಂತಿರುಗಿ -1;
	debug2("Sending SSH2_FXP_EXTENDED(fsync@openssh.com)");

	/* Send fsync request */
	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	id = conn->ಸಂದೇಶ_id++;
	ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, "fsync@openssh.com")) != 0 ||
	    (r = sshbuf_put_string(ಸಂದೇಶ, handle, handle_len)) != 0)
		fatal_fr(r, "compose");
	send_ಸಂದೇಶ(conn, ಸಂದೇಶ);
	debug3("Sent message fsync@openssh.com I:%u", id);
	sshbuf_free(ಸಂದೇಶ);

	ಸ್ಥಿತಿ_2 = get_ಸ್ಥಿತಿ(conn, id);
	ಆದರೆ (ಸ್ಥಿತಿ_2 != SSH2_FX_OK)
		error("remote fsync: %s", fx2txt(ಸ್ಥಿತಿ_2));

	ಹಿಂತಿರುಗಿ ಸ್ಥಿತಿ_2 == SSH2_FX_OK ? 0 : -1;
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ notyet
ಅಕ್ಷರ *
sftp_readlink(ರಚನೆ sftp_conn *conn, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ)
{
	ರಚನೆ sshbuf *ಸಂದೇಶ;
	u_int expected_id, ಎಣಿಕೆ_2, id;
	ಅಕ್ಷರ *filename, *longname;
	Attrib a;
	u_char type;
	ಪೂರ್ಣಾಂಕ r;

	debug2("Sending SSH2_FXP_READLINK \"%s\"", ಮಾರ್ಗ);

	expected_id = id = conn->ಸಂದೇಶ_id++;
	send_string_request(conn, id, SSH2_FXP_READLINK, ಮಾರ್ಗ, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಮಾರ್ಗ));

	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");

	get_ಸಂದೇಶ(conn, ಸಂದೇಶ);
	ಆದರೆ ((r = sshbuf_get_u8(ಸಂದೇಶ, &type)) != 0 ||
	    (r = sshbuf_get_u32(ಸಂದೇಶ, &id)) != 0)
		fatal_fr(r, "parse");

	ಆದರೆ (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);

	ಆದರೆ (type == SSH2_FXP_ಸ್ಥಿತಿ) {
		u_int ಸ್ಥಿತಿ_2;

		ಆದರೆ ((r = sshbuf_get_u32(ಸಂದೇಶ, &ಸ್ಥಿತಿ_2)) != 0)
			fatal_fr(r, "parse status");
		error("Couldn't readlink: %s", fx2txt(ಸ್ಥಿತಿ_2));
		sshbuf_free(ಸಂದೇಶ);
		ಹಿಂತಿರುಗಿ(ಖಾಲಿ);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (type != SSH2_FXP_NAME)
		fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
		    SSH2_FXP_NAME, type);

	ಆದರೆ ((r = sshbuf_get_u32(ಸಂದೇಶ, &ಎಣಿಕೆ_2)) != 0)
		fatal_fr(r, "parse count");
	ಆದರೆ (ಎಣಿಕೆ_2 != 1)
		fatal("Got multiple names (%d) from SSH_FXP_READLINK", ಎಣಿಕೆ_2);

	ಆದರೆ ((r = sshbuf_get_cstring(ಸಂದೇಶ, &filename, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_cstring(ಸಂದೇಶ, &longname, ಖಾಲಿ)) != 0 ||
	    (r = decode_attrib(ಸಂದೇಶ, &a)) != 0)
		fatal_fr(r, "parse filenames/attrib");

	debug3("SSH_FXP_READLINK %s -> %s", ಮಾರ್ಗ, filename);

	ಬಿಡುಗಡೆ(longname);

	sshbuf_free(ಸಂದೇಶ);

	ಹಿಂತಿರುಗಿ filename;
}
#ಆದರೆ_ಅಂತ್ಯ

ಪೂರ್ಣಾಂಕ
sftp_statvfs(ರಚನೆ sftp_conn *conn, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, ರಚನೆ sftp_statvfs *st,
    ಪೂರ್ಣಾಂಕ quiet)
{
	ರಚನೆ sshbuf *ಸಂದೇಶ;
	u_int id;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((conn->exts & SFTP_EXT_STATVFS) == 0) {
		error("Server does not support statvfs@openssh.com extension");
		ಹಿಂತಿರುಗಿ -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(statvfs@openssh.com) \"%s\"", ಮಾರ್ಗ);

	id = conn->ಸಂದೇಶ_id++;

	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, "statvfs@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, ಮಾರ್ಗ)) != 0)
		fatal_fr(r, "compose");
	send_ಸಂದೇಶ(conn, ಸಂದೇಶ);
	sshbuf_free(ಸಂದೇಶ);

	ಹಿಂತಿರುಗಿ get_decode_statvfs(conn, st, id, quiet);
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ notyet
ಪೂರ್ಣಾಂಕ
sftp_fstatvfs(ರಚನೆ sftp_conn *conn, ಸ್ಥಿರಾಂಕ u_char *handle, u_int handle_len,
    ರಚನೆ sftp_statvfs *st, ಪೂರ್ಣಾಂಕ quiet)
{
	ರಚನೆ sshbuf *ಸಂದೇಶ;
	u_int id;

	ಆದರೆ ((conn->exts & SFTP_EXT_FSTATVFS) == 0) {
		error("Server does not support fstatvfs@openssh.com extension");
		ಹಿಂತಿರುಗಿ -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(fstatvfs@openssh.com)");

	id = conn->ಸಂದೇಶ_id++;

	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, "fstatvfs@openssh.com")) != 0 ||
	    (r = sshbuf_put_string(ಸಂದೇಶ, handle, handle_len)) != 0)
		fatal_fr(r, "compose");
	send_ಸಂದೇಶ(conn, ಸಂದೇಶ);
	sshbuf_free(ಸಂದೇಶ);

	ಹಿಂತಿರುಗಿ get_decode_statvfs(conn, st, id, quiet);
}
#ಆದರೆ_ಅಂತ್ಯ

ಪೂರ್ಣಾಂಕ
sftp_lsetstat(ರಚನೆ sftp_conn *conn, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, Attrib *a)
{
	ರಚನೆ sshbuf *ಸಂದೇಶ;
	u_int ಸ್ಥಿತಿ_2, id;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((conn->exts & SFTP_EXT_LSETSTAT) == 0) {
		error("Server does not support lsetstat@openssh.com extension");
		ಹಿಂತಿರುಗಿ -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(lsetstat@openssh.com) \"%s\"", ಮಾರ್ಗ);

	id = conn->ಸಂದೇಶ_id++;
	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, "lsetstat@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, ಮಾರ್ಗ)) != 0 ||
	    (r = encode_attrib(ಸಂದೇಶ, a)) != 0)
		fatal_fr(r, "compose");
	send_ಸಂದೇಶ(conn, ಸಂದೇಶ);
	sshbuf_free(ಸಂದೇಶ);

	ಸ್ಥಿತಿ_2 = get_ಸ್ಥಿತಿ(conn, id);
	ಆದರೆ (ಸ್ಥಿತಿ_2 != SSH2_FX_OK)
		error("remote lsetstat \"%s\": %s", ಮಾರ್ಗ, fx2txt(ಸ್ಥಿತಿ_2));

	ಹಿಂತಿರುಗಿ ಸ್ಥಿತಿ_2 == SSH2_FX_OK ? 0 : -1;
}

ಸ್ಥಿರ ಶೂನ್ಯ
send_read_request(ರಚನೆ sftp_conn *conn, u_int id, uint64_t ಸ್ಥಾನಾಂತರ,
    u_int len, ಸ್ಥಿರಾಂಕ u_char *handle, u_int handle_len)
{
	ರಚನೆ sshbuf *ಸಂದೇಶ;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_READ)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
	    (r = sshbuf_put_string(ಸಂದೇಶ, handle, handle_len)) != 0 ||
	    (r = sshbuf_put_u64(ಸಂದೇಶ, ಸ್ಥಾನಾಂತರ)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, len)) != 0)
		fatal_fr(r, "compose");
	send_ಸಂದೇಶ(conn, ಸಂದೇಶ);
	sshbuf_free(ಸಂದೇಶ);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
send_open(ರಚನೆ sftp_conn *conn, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಟ್ಯಾಗ್,
    u_int openmode, Attrib *a, u_char **handlep, ಗಾತ್ರ_t *handle_lenp)
{
	Attrib junk;
	u_char *handle;
	ಗಾತ್ರ_t handle_len;
	ರಚನೆ sshbuf *ಸಂದೇಶ;
	ಪೂರ್ಣಾಂಕ r;
	u_int id;

	debug2("Sending SSH2_FXP_OPEN \"%s\"", ಮಾರ್ಗ);

	*handlep = ಖಾಲಿ;
	*handle_lenp = 0;

	ಆದರೆ (a == ಖಾಲಿ) {
		attrib_clear(&junk); /* Send empty attributes */
		a = &junk;
	}
	/* Send open request */
	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	id = conn->ಸಂದೇಶ_id++;
	ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, ಮಾರ್ಗ)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, openmode)) != 0 ||
	    (r = encode_attrib(ಸಂದೇಶ, a)) != 0)
		fatal_fr(r, "compose %s open", ಟ್ಯಾಗ್);
	send_ಸಂದೇಶ(conn, ಸಂದೇಶ);
	sshbuf_free(ಸಂದೇಶ);
	debug3("Sent %s message SSH2_FXP_OPEN I:%u P:%s M:0x%04x",
	    ಟ್ಯಾಗ್, id, ಮಾರ್ಗ, openmode);
	ಆದರೆ ((handle = get_handle(conn, id, &handle_len,
	    "%s open \"%s\"", ಟ್ಯಾಗ್, ಮಾರ್ಗ)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ -1;
	/* success */
	*handlep = handle;
	*handle_lenp = handle_len;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
ಪ್ರಗತಿ_meter_ಮಾರ್ಗ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ)
{
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *progresspath;

	ಆದರೆ ((progresspath = strrchr(ಮಾರ್ಗ, '/')) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಮಾರ್ಗ;
	progresspath++;
	ಆದರೆ (*progresspath == '\0')
		ಹಿಂತಿರುಗಿ ಮಾರ್ಗ;
	ಹಿಂತಿರುಗಿ progresspath;
}

ಪೂರ್ಣಾಂಕ
sftp_download(ರಚನೆ sftp_conn *conn, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *remote_ಮಾರ್ಗ,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *local_ಮಾರ್ಗ, Attrib *a, ಪೂರ್ಣಾಂಕ preserve_flag, ಪೂರ್ಣಾಂಕ resume_flag,
    ಪೂರ್ಣಾಂಕ fsync_flag, ಪೂರ್ಣಾಂಕ inplace_flag)
{
	ರಚನೆ sshbuf *ಸಂದೇಶ;
	u_char *handle;
	ಪೂರ್ಣಾಂಕ local_fd = -1, write_error, ನೋಡಿದ_zerolen = 0;
	ಪೂರ್ಣಾಂಕ read_error, write_errno, lmodified = 0, reordered = 0, r;
	uint64_t ಸ್ಥಾನಾಂತರ = 0, ಗಾತ್ರ_2, highwater = 0, maxack = 0;
	u_int ಬಹುಲಕ, id, buflen, ಅಂಕೆ_req, max_req, ಸ್ಥಿತಿ_2 = SSH2_FX_OK;
	off_t ಪ್ರಗತಿ_counter;
	ಗಾತ್ರ_t handle_len;
	ರಚನೆ stat st;
	ರಚನೆ ವಿನಂತಿಗಳು ವಿನಂತಿಗಳು;
	ರಚನೆ request *req;
	u_char type;
	Attrib attr;

	debug2_f("download remote \"%s\" to local \"%s\"",
	    remote_ಮಾರ್ಗ, local_ಮಾರ್ಗ);

	TAILQ_INIT(&ವಿನಂತಿಗಳು);

	ಆದರೆ (a == ಖಾಲಿ) {
		ಆದರೆ (sftp_stat(conn, remote_ಮಾರ್ಗ, 0, &attr) != 0)
			ಹಿಂತಿರುಗಿ -1;
		a = &attr;
	}

	/* Do not preserve set[ug]id here, as we do not preserve ownership */
	ಆದರೆ (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS)
		ಬಹುಲಕ = a->perm & 0777;
	ಇಲ್ಲದಿದ್ದರೆ
		ಬಹುಲಕ = 0666;

	ಆದರೆ ((a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) &&
	    (!S_ISREG(a->perm))) {
		error("download %s: not a regular file", remote_ಮಾರ್ಗ);
		ಹಿಂತಿರುಗಿ(-1);
	}

	ಆದರೆ (a->flags & SSH2_FILEXFER_ATTR_ಗಾತ್ರ)
		ಗಾತ್ರ_2 = a->ಗಾತ್ರ_2;
	ಇಲ್ಲದಿದ್ದರೆ
		ಗಾತ್ರ_2 = 0;

	buflen = conn->download_buflen;

	/* Send open request */
	ಆದರೆ (send_open(conn, remote_ಮಾರ್ಗ, "remote", SSH2_FXF_READ, ಖಾಲಿ,
	    &handle, &handle_len) != 0)
		ಹಿಂತಿರುಗಿ -1;

	local_fd = open(local_ಮಾರ್ಗ, O_WRONLY | O_CREAT |
	((resume_flag || inplace_flag) ? 0 : O_TRUNC), ಬಹುಲಕ | S_IWUSR);
	ಆದರೆ (local_fd == -1) {
		error("open local \"%s\": %s", local_ಮಾರ್ಗ, strerror(errno));
		ಹೋಗು fail;
	}
	ಆದರೆ (resume_flag) {
		ಆದರೆ (fstat(local_fd, &st) == -1) {
			error("stat local \"%s\": %s",
			    local_ಮಾರ್ಗ, strerror(errno));
			ಹೋಗು fail;
		}
		ಆದರೆ (st.st_size < 0) {
			error("\"%s\" has negative size", local_ಮಾರ್ಗ);
			ಹೋಗು fail;
		}
		ಆದರೆ ((uint64_t)st.st_size > ಗಾತ್ರ_2) {
			error("Unable to resume download of \"%s\": "
			    "local file is larger than remote", local_ಮಾರ್ಗ);
 fail:
			sftp_close(conn, handle, handle_len);
			ಬಿಡುಗಡೆ(handle);
			ಆದರೆ (local_fd != -1)
				close(local_fd);
			ಹಿಂತಿರುಗಿ -1;
		}
		ಸ್ಥಾನಾಂತರ = highwater = maxack = st.st_size;
	}

	/* Read from remote and write to local */
	write_error = read_error = write_errno = ಅಂಕೆ_req = 0;
	max_req = 1;
	ಪ್ರಗತಿ_counter = ಸ್ಥಾನಾಂತರ;

	ಆದರೆ (showprogress && ಗಾತ್ರ_2 != 0) {
		ಆರಂಭ_ಪ್ರಗತಿ_meter(ಪ್ರಗತಿ_meter_ಮಾರ್ಗ(remote_ಮಾರ್ಗ),
		    ಗಾತ್ರ_2, &ಪ್ರಗತಿ_counter);
	}

	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");

	ಆಗ (ಅಂಕೆ_req > 0 || max_req > 0) {
		u_char *ದತ್ತಾಂಶ;
		ಗಾತ್ರ_t len;

		/*
		 * Simulate EOF on interrupt: stop sending new requests and
		 * allow outstanding requests to drain gracefully
		 */
		ಆದರೆ (interrupted) {
			ಆದರೆ (ಅಂಕೆ_req == 0) /* If we haven't started yet... */
				ನಿಲ್ಲಿಸು;
			max_req = 0;
		}

		/* Send some more requests */
		ಆಗ (ಅಂಕೆ_req < max_req) {
			debug3("Request range %llu -> %llu (%d/%d)",
			    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ಸ್ಥಾನಾಂತರ,
			    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ಸ್ಥಾನಾಂತರ + buflen - 1,
			    ಅಂಕೆ_req, max_req);
			req = request_ಸರತಿಗೆ_ಸೇರಿಸು(&ವಿನಂತಿಗಳು, conn->ಸಂದೇಶ_id++,
			    buflen, ಸ್ಥಾನಾಂತರ);
			ಸ್ಥಾನಾಂತರ += buflen;
			ಅಂಕೆ_req++;
			send_read_request(conn, req->id, req->ಸ್ಥಾನಾಂತರ,
			    req->len, handle, handle_len);
		}

		sshbuf_reset(ಸಂದೇಶ);
		get_ಸಂದೇಶ(conn, ಸಂದೇಶ);
		ಆದರೆ ((r = sshbuf_get_u8(ಸಂದೇಶ, &type)) != 0 ||
		    (r = sshbuf_get_u32(ಸಂದೇಶ, &id)) != 0)
			fatal_fr(r, "parse");
		debug3("Received reply T:%u I:%u R:%d", type, id, max_req);

		/* Find the request in our queue */
		ಆದರೆ ((req = request_ಕಂಡುಹಿಡಿ(&ವಿನಂತಿಗಳು, id)) == ಖಾಲಿ)
			fatal("Unexpected reply %u", id);

		ಆಯ್ಕೆ (type) {
		ಸ್ಥಿತಿ SSH2_FXP_ಸ್ಥಿತಿ:
			ಆದರೆ ((r = sshbuf_get_u32(ಸಂದೇಶ, &ಸ್ಥಿತಿ_2)) != 0)
				fatal_fr(r, "parse status");
			ಆದರೆ (ಸ್ಥಿತಿ_2 != SSH2_FX_EOF)
				read_error = 1;
			max_req = 0;
			TAILQ_REMOVE(&ವಿನಂತಿಗಳು, req, tq);
			ಬಿಡುಗಡೆ(req);
			ಅಂಕೆ_req--;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ SSH2_FXP_ದತ್ತಾಂಶ:
			ಆದರೆ ((r = sshbuf_get_string(ಸಂದೇಶ, &ದತ್ತಾಂಶ, &len)) != 0)
				fatal_fr(r, "parse data");
			debug3("Received data %llu -> %llu",
			    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)req->ಸ್ಥಾನಾಂತರ,
			    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)req->ಸ್ಥಾನಾಂತರ + len - 1);
			ಆದರೆ (len > req->len)
				fatal("Received more data than asked for "
				    "%zu > %zu", len, req->len);
			ಆದರೆ (len == 0) {
				ಆದರೆ (ನೋಡಿದ_zerolen)
					fatal_f("server sent zero data length");
				ನೋಡಿದ_zerolen = 1;
			}
			lmodified = 1;
			ಆದರೆ ((lseek(local_fd, req->ಸ್ಥಾನಾಂತರ, SEEK_SET) == -1 ||
			    atomicio(vwrite, local_fd, ದತ್ತಾಂಶ, len) != len) &&
			    !write_error) {
				write_errno = errno;
				write_error = 1;
				max_req = 0;
			} ಇಲ್ಲದಿದ್ದರೆ {
				/*
				 * Track both the highest offset acknowledged
				 * and the highest *contiguous* offset
				 * acknowledged.
				 * We'll need the latter for ftruncate()ing
				 * interrupted transfers.
				 */
				ಆದರೆ (maxack < req->ಸ್ಥಾನಾಂತರ + len)
					maxack = req->ಸ್ಥಾನಾಂತರ + len;
				ಆದರೆ (!reordered && req->ಸ್ಥಾನಾಂತರ <= highwater)
					highwater = maxack;
				ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (!reordered && req->ಸ್ಥಾನಾಂತರ > highwater)
					reordered = 1;
			}
			ಪ್ರಗತಿ_counter += len;
			ಬಿಡುಗಡೆ(ದತ್ತಾಂಶ);

			ಆದರೆ (len == req->len) {
				TAILQ_REMOVE(&ವಿನಂತಿಗಳು, req, tq);
				ಬಿಡುಗಡೆ(req);
				ಅಂಕೆ_req--;
			} ಇಲ್ಲದಿದ್ದರೆ {
				/* Resend the request for the missing data */
				debug3("Short data block, re-requesting "
				    "%llu -> %llu (%2d)",
				    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)req->ಸ್ಥಾನಾಂತರ + len,
				    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)req->ಸ್ಥಾನಾಂತರ +
				    req->len - 1, ಅಂಕೆ_req);
				req->id = conn->ಸಂದೇಶ_id++;
				req->len -= len;
				req->ಸ್ಥಾನಾಂತರ += len;
				send_read_request(conn, req->id,
				    req->ಸ್ಥಾನಾಂತರ, req->len, handle, handle_len);
				/* Reduce the request size */
				ಆದರೆ (len < buflen)
					buflen = ಗರಿಷ್ಠ(MIN_READ_ಗಾತ್ರ, len);
			}
			ಆದರೆ (max_req > 0) { /* max_req = 0 iff EOF received */
				ಆದರೆ (ಗಾತ್ರ_2 > 0 && ಸ್ಥಾನಾಂತರ > ಗಾತ್ರ_2) {
					/* Only one request at a time
					 * after the expected EOF */
					debug3("Finish at %llu (%2d)",
					    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ಸ್ಥಾನಾಂತರ,
					    ಅಂಕೆ_req);
					max_req = 1;
				} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (max_req < conn->ಅಂಕೆ_ವಿನಂತಿಗಳು) {
					++max_req;
				}
			}
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			fatal("Expected SSH2_FXP_DATA(%u) packet, got %u",
			    SSH2_FXP_ದತ್ತಾಂಶ, type);
		}
	}

	ಆದರೆ (showprogress && ಗಾತ್ರ_2)
		stop_ಪ್ರಗತಿ_meter();

	/* Sanity check */
	ಆದರೆ (TAILQ_FIRST(&ವಿನಂತಿಗಳು) != ಖಾಲಿ)
		fatal("Transfer complete, but requests still in queue");

	ಆದರೆ (!read_error && !write_error && !interrupted) {
		/* we got everything */
		highwater = maxack;
	}

	/*
	 * Truncate at highest contiguous point to avoid holes on interrupt,
	 * or unconditionally if writing in place.
	 */
	ಆದರೆ (inplace_flag || read_error || write_error || interrupted) {
		ಆದರೆ (reordered && resume_flag &&
		    (read_error || write_error || interrupted)) {
			error("Unable to resume download of \"%s\": "
			    "server reordered requests", local_ಮಾರ್ಗ);
		}
		debug("truncating at %llu", (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)highwater);
		ಆದರೆ (ftruncate(local_fd, highwater) == -1)
			error("local ftruncate \"%s\": %s", local_ಮಾರ್ಗ,
			    strerror(errno));
	}
	ಆದರೆ (read_error) {
		error("read remote \"%s\" : %s", remote_ಮಾರ್ಗ, fx2txt(ಸ್ಥಿತಿ_2));
		ಸ್ಥಿತಿ_2 = -1;
		sftp_close(conn, handle, handle_len);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (write_error) {
		error("write local \"%s\": %s", local_ಮಾರ್ಗ,
		    strerror(write_errno));
		ಸ್ಥಿತಿ_2 = SSH2_FX_FAILURE;
		sftp_close(conn, handle, handle_len);
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ (sftp_close(conn, handle, handle_len) != 0 || interrupted)
			ಸ್ಥಿತಿ_2 = SSH2_FX_FAILURE;
		ಇಲ್ಲದಿದ್ದರೆ
			ಸ್ಥಿತಿ_2 = SSH2_FX_OK;
		/* Override umask and utimes if asked */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_FCHMOD
		ಆದರೆ (preserve_flag && fchmod(local_fd, ಬಹುಲಕ) == -1)
#ಇಲ್ಲದಿದ್ದರೆ
		ಆದರೆ (preserve_flag && chmod(local_ಮಾರ್ಗ, ಬಹುಲಕ) == -1)
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_FCHMOD */
			error("local chmod \"%s\": %s", local_ಮಾರ್ಗ,
			    strerror(errno));
		ಆದರೆ (preserve_flag &&
		    (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME)) {
			ರಚನೆ timeval tv[2];
			tv[0].tv_sec = a->atime;
			tv[1].tv_sec = a->mtime;
			tv[0].tv_usec = tv[1].tv_usec = 0;
			ಆದರೆ (utimes(local_ಮಾರ್ಗ, tv) == -1)
				error("local set times \"%s\": %s",
				    local_ಮಾರ್ಗ, strerror(errno));
		}
		ಆದರೆ (resume_flag && !lmodified)
			logit("File \"%s\" was not modified", local_ಮಾರ್ಗ);
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (fsync_flag) {
			debug("syncing \"%s\"", local_ಮಾರ್ಗ);
			ಆದರೆ (fsync(local_fd) == -1)
				error("local sync \"%s\": %s",
				    local_ಮಾರ್ಗ, strerror(errno));
		}
	}
	close(local_fd);
	sshbuf_free(ಸಂದೇಶ);
	ಬಿಡುಗಡೆ(handle);

	ಹಿಂತಿರುಗಿ ಸ್ಥಿತಿ_2 == SSH2_FX_OK ? 0 : -1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
download_dir_ಆಂತರಿಕ(ರಚನೆ sftp_conn *conn, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *src, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *dst,
    ಪೂರ್ಣಾಂಕ ಆಳ, Attrib *dirattrib, ಪೂರ್ಣಾಂಕ preserve_flag, ಪೂರ್ಣಾಂಕ print_flag,
    ಪೂರ್ಣಾಂಕ resume_flag, ಪೂರ್ಣಾಂಕ fsync_flag, ಪೂರ್ಣಾಂಕ follow_link_flag, ಪೂರ್ಣಾಂಕ inplace_flag)
{
	ಪೂರ್ಣಾಂಕ i, ret = 0;
	SFTP_DIRENT **dir_entries;
	ಅಕ್ಷರ *filename, *new_src = ಖಾಲಿ, *new_dst = ಖಾಲಿ;
	ಬಹುಲಕ_t ಬಹುಲಕ = 0777, tmpmode = ಬಹುಲಕ;
	Attrib *a, ldirattrib, lsym;

	ಆದರೆ (ಆಳ >= MAX_DIR_ಆಳ) {
		error("Maximum directory depth exceeded: %d levels", ಆಳ);
		ಹಿಂತಿರುಗಿ -1;
	}

	debug2_f("download dir remote \"%s\" to local \"%s\"", src, dst);

	ಆದರೆ (dirattrib == ಖಾಲಿ) {
		ಆದರೆ (sftp_stat(conn, src, 1, &ldirattrib) != 0) {
			error("stat remote \"%s\" directory failed", src);
			ಹಿಂತಿರುಗಿ -1;
		}
		dirattrib = &ldirattrib;
	}
	ಆದರೆ (!S_ISDIR(dirattrib->perm)) {
		error("\"%s\" is not a directory", src);
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ (print_flag && print_flag != SFTP_ಪ್ರಗತಿ_ONLY)
		mprintf("Retrieving %s\n", src);

	ಆದರೆ (dirattrib->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		ಬಹುಲಕ = dirattrib->perm & 01777;
		tmpmode = ಬಹುಲಕ | (S_IWUSR|S_IXUSR);
	} ಇಲ್ಲದಿದ್ದರೆ {
		debug("download remote \"%s\": server "
		    "did not send permissions", dst);
	}

	ಆದರೆ (mkdir(dst, tmpmode) == -1 && errno != EEXIST) {
		error("mkdir %s: %s", dst, strerror(errno));
		ಹಿಂತಿರುಗಿ -1;
	}

	ಆದರೆ (sftp_readdir(conn, src, &dir_entries) == -1) {
		error("remote readdir \"%s\" failed", src);
		ಹಿಂತಿರುಗಿ -1;
	}

	ಗಾಗಿ (i = 0; dir_entries[i] != ಖಾಲಿ && !interrupted; i++) {
		ಬಿಡುಗಡೆ(new_dst);
		ಬಿಡುಗಡೆ(new_src);

		filename = dir_entries[i]->filename;
		new_dst = sftp_ಮಾರ್ಗ_append(dst, filename);
		new_src = sftp_ಮಾರ್ಗ_append(src, filename);

		a = &dir_entries[i]->a;
		ಆದರೆ (S_ISLNK(a->perm)) {
			ಆದರೆ (!follow_link_flag) {
				logit("download \"%s\": not a regular file",
				    new_src);
				ಮುಂದುವರಿ;
			}
			/* Replace the stat contents with the symlink target */
			ಆದರೆ (sftp_stat(conn, new_src, 1, &lsym) != 0) {
				logit("remote stat \"%s\" failed", new_src);
				ret = -1;
				ಮುಂದುವರಿ;
			}
			a = &lsym;
		}

		ಆದರೆ (S_ISDIR(a->perm)) {
			ಆದರೆ (strcmp(filename, ".") == 0 ||
			    strcmp(filename, "..") == 0)
				ಮುಂದುವರಿ;
			ಆದರೆ (download_dir_ಆಂತರಿಕ(conn, new_src, new_dst,
			    ಆಳ + 1, a, preserve_flag,
			    print_flag, resume_flag,
			    fsync_flag, follow_link_flag, inplace_flag) == -1)
				ret = -1;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (S_ISREG(a->perm)) {
			ಆದರೆ (sftp_download(conn, new_src, new_dst, a,
			    preserve_flag, resume_flag, fsync_flag,
			    inplace_flag) == -1) {
				error("Download of file %s to %s failed",
				    new_src, new_dst);
				ret = -1;
			}
		} ಇಲ್ಲದಿದ್ದರೆ
			logit("download \"%s\": not a regular file", new_src);

	}
	ಬಿಡುಗಡೆ(new_dst);
	ಬಿಡುಗಡೆ(new_src);

	ಆದರೆ (preserve_flag) {
		ಆದರೆ (dirattrib->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
			ರಚನೆ timeval tv[2];
			tv[0].tv_sec = dirattrib->atime;
			tv[1].tv_sec = dirattrib->mtime;
			tv[0].tv_usec = tv[1].tv_usec = 0;
			ಆದರೆ (utimes(dst, tv) == -1)
				error("local set times on \"%s\": %s",
				    dst, strerror(errno));
		} ಇಲ್ಲದಿದ್ದರೆ
			debug("Server did not send times for directory "
			    "\"%s\"", dst);
	}

	ಆದರೆ (ಬಹುಲಕ != tmpmode && chmod(dst, ಬಹುಲಕ) == -1)
		error("local chmod directory \"%s\": %s", dst,
		    strerror(errno));

	sftp_free_dirents(dir_entries);

	ಹಿಂತಿರುಗಿ ret;
}

ಪೂರ್ಣಾಂಕ
sftp_download_dir(ರಚನೆ sftp_conn *conn, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *src, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *dst,
    Attrib *dirattrib, ಪೂರ್ಣಾಂಕ preserve_flag, ಪೂರ್ಣಾಂಕ print_flag, ಪೂರ್ಣಾಂಕ resume_flag,
    ಪೂರ್ಣಾಂಕ fsync_flag, ಪೂರ್ಣಾಂಕ follow_link_flag, ಪೂರ್ಣಾಂಕ inplace_flag)
{
	ಅಕ್ಷರ *src_canon;
	ಪೂರ್ಣಾಂಕ ret;

	ಆದರೆ ((src_canon = sftp_realpath(conn, src)) == ಖಾಲಿ) {
		error("download \"%s\": path canonicalization failed", src);
		ಹಿಂತಿರುಗಿ -1;
	}

	ret = download_dir_ಆಂತರಿಕ(conn, src_canon, dst, 0,
	    dirattrib, preserve_flag, print_flag, resume_flag, fsync_flag,
	    follow_link_flag, inplace_flag);
	ಬಿಡುಗಡೆ(src_canon);
	ಹಿಂತಿರುಗಿ ret;
}

ಪೂರ್ಣಾಂಕ
sftp_upload(ರಚನೆ sftp_conn *conn, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *local_ಮಾರ್ಗ,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *remote_ಮಾರ್ಗ, ಪೂರ್ಣಾಂಕ preserve_flag, ಪೂರ್ಣಾಂಕ resume,
    ಪೂರ್ಣಾಂಕ fsync_flag, ಪೂರ್ಣಾಂಕ inplace_flag)
{
	ಪೂರ್ಣಾಂಕ r, local_fd;
	u_int openmode, id, ಸ್ಥಿತಿ_2 = SSH2_FX_OK, status2, reordered = 0;
	off_t ಸ್ಥಾನಾಂತರ, ಪ್ರಗತಿ_counter;
	u_char type, *handle, *ದತ್ತಾಂಶ;
	ರಚನೆ sshbuf *ಸಂದೇಶ;
	ರಚನೆ stat sb;
	Attrib a, t, c;
	uint32_t startid, ackid;
	uint64_t highwater = 0, maxack = 0;
	ರಚನೆ request *ack = ಖಾಲಿ;
	ರಚನೆ ವಿನಂತಿಗಳು acks;
	ಗಾತ್ರ_t handle_len;

	debug2_f("upload local \"%s\" to remote \"%s\"",
	    local_ಮಾರ್ಗ, remote_ಮಾರ್ಗ);

	TAILQ_INIT(&acks);

	ಆದರೆ ((local_fd = open(local_ಮಾರ್ಗ, O_RDONLY)) == -1) {
		error("open local \"%s\": %s", local_ಮಾರ್ಗ, strerror(errno));
		ಹಿಂತಿರುಗಿ(-1);
	}
	ಆದರೆ (fstat(local_fd, &sb) == -1) {
		error("fstat local \"%s\": %s", local_ಮಾರ್ಗ, strerror(errno));
		close(local_fd);
		ಹಿಂತಿರುಗಿ(-1);
	}
	ಆದರೆ (!S_ISREG(sb.st_mode)) {
		error("local \"%s\" is not a regular file", local_ಮಾರ್ಗ);
		close(local_fd);
		ಹಿಂತಿರುಗಿ(-1);
	}
	stat_ಗಮ್ಯ_attrib(&sb, &a);

	a.flags &= ~SSH2_FILEXFER_ATTR_ಗಾತ್ರ;
	a.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a.perm &= 0777;
	ಆದರೆ (!preserve_flag)
		a.flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;

	ಆದರೆ (resume) {
		/* Get remote file size if it exists */
		ಆದರೆ (sftp_stat(conn, remote_ಮಾರ್ಗ, 0, &c) != 0) {
			close(local_fd);
			ಹಿಂತಿರುಗಿ -1;
		}

		ಆದರೆ ((off_t)c.ಗಾತ್ರ_2 >= sb.st_size) {
			error("resume \"%s\": destination file "
			    "same size or larger", local_ಮಾರ್ಗ);
			close(local_fd);
			ಹಿಂತಿರುಗಿ -1;
		}

		ಆದರೆ (lseek(local_fd, (off_t)c.ಗಾತ್ರ_2, SEEK_SET) == -1) {
			close(local_fd);
			ಹಿಂತಿರುಗಿ -1;
		}
		highwater = c.ಗಾತ್ರ_2;
	}

	openmode = SSH2_FXF_WRITE|SSH2_FXF_CREAT;
	ಆದರೆ (resume)
		openmode |= SSH2_FXF_APPEND;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (!inplace_flag)
		openmode |= SSH2_FXF_TRUNC;

	/* Send open request */
	ಆದರೆ (send_open(conn, remote_ಮಾರ್ಗ, "dest", openmode, &a,
	    &handle, &handle_len) != 0) {
		close(local_fd);
		ಹಿಂತಿರುಗಿ -1;
	}

	id = conn->ಸಂದೇಶ_id;
	startid = ackid = id + 1;
	ದತ್ತಾಂಶ = xmalloc(conn->upload_buflen);

	/* Read from local and write to remote */
	ಸ್ಥಾನಾಂತರ = ಪ್ರಗತಿ_counter = (resume ? c.ಗಾತ್ರ_2 : 0);
	ಆದರೆ (showprogress) {
		ಆರಂಭ_ಪ್ರಗತಿ_meter(ಪ್ರಗತಿ_meter_ಮಾರ್ಗ(local_ಮಾರ್ಗ),
		    sb.st_size, &ಪ್ರಗತಿ_counter);
	}

	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಗಾಗಿ (;;) {
		ಪೂರ್ಣಾಂಕ len;

		/*
		 * Can't use atomicio here because it returns 0 on EOF,
		 * thus losing the last block of the file.
		 * Simulate an EOF on interrupt, allowing ACKs from the
		 * server to drain.
		 */
		ಆದರೆ (interrupted || ಸ್ಥಿತಿ_2 != SSH2_FX_OK)
			len = 0;
		ಇಲ್ಲದಿದ್ದರೆ ಮಾಡು
			len = ಪಠ(local_fd, ದತ್ತಾಂಶ, conn->upload_buflen);
		ಆಗ ((len == -1) &&
		    (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK));

		ಆದರೆ (len == -1) {
			fatal("read local \"%s\": %s",
			    local_ಮಾರ್ಗ, strerror(errno));
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (len != 0) {
			ack = request_ಸರತಿಗೆ_ಸೇರಿಸು(&acks, ++id, len, ಸ್ಥಾನಾಂತರ);
			sshbuf_reset(ಸಂದೇಶ);
			ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_WRITE)) != 0 ||
			    (r = sshbuf_put_u32(ಸಂದೇಶ, ack->id)) != 0 ||
			    (r = sshbuf_put_string(ಸಂದೇಶ, handle,
			    handle_len)) != 0 ||
			    (r = sshbuf_put_u64(ಸಂದೇಶ, ಸ್ಥಾನಾಂತರ)) != 0 ||
			    (r = sshbuf_put_string(ಸಂದೇಶ, ದತ್ತಾಂಶ, len)) != 0)
				fatal_fr(r, "compose");
			send_ಸಂದೇಶ(conn, ಸಂದೇಶ);
			debug3("Sent message SSH2_FXP_WRITE I:%u O:%llu S:%u",
			    id, (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ಸ್ಥಾನಾಂತರ, len);
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (TAILQ_FIRST(&acks) == ಖಾಲಿ)
			ನಿಲ್ಲಿಸು;

		ಆದರೆ (ack == ಖಾಲಿ)
			fatal("Unexpected ACK %u", id);

		ಆದರೆ (id == startid || len == 0 ||
		    id - ackid >= conn->ಅಂಕೆ_ವಿನಂತಿಗಳು) {
			u_int rid;

			sshbuf_reset(ಸಂದೇಶ);
			get_ಸಂದೇಶ(conn, ಸಂದೇಶ);
			ಆದರೆ ((r = sshbuf_get_u8(ಸಂದೇಶ, &type)) != 0 ||
			    (r = sshbuf_get_u32(ಸಂದೇಶ, &rid)) != 0)
				fatal_fr(r, "parse");

			ಆದರೆ (type != SSH2_FXP_ಸ್ಥಿತಿ)
				fatal("Expected SSH2_FXP_STATUS(%d) packet, "
				    "got %d", SSH2_FXP_ಸ್ಥಿತಿ, type);

			ಆದರೆ ((r = sshbuf_get_u32(ಸಂದೇಶ, &status2)) != 0)
				fatal_fr(r, "parse status");
			debug3("SSH2_FXP_STATUS %u", status2);
			ಆದರೆ (status2 != SSH2_FX_OK)
				ಸ್ಥಿತಿ_2 = status2; /* remember errors */

			/* Find the request in our queue */
			ಆದರೆ ((ack = request_ಕಂಡುಹಿಡಿ(&acks, rid)) == ಖಾಲಿ)
				fatal("Can't find request for ID %u", rid);
			TAILQ_REMOVE(&acks, ack, tq);
			debug3("In write loop, ack for %u %zu bytes at %lld",
			    ack->id, ack->len, (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ack->ಸ್ಥಾನಾಂತರ);
			++ackid;
			ಪ್ರಗತಿ_counter += ack->len;
			/*
			 * Track both the highest offset acknowledged and the
			 * highest *contiguous* offset acknowledged.
			 * We'll need the latter for ftruncate()ing
			 * interrupted transfers.
			 */
			ಆದರೆ (maxack < ack->ಸ್ಥಾನಾಂತರ + ack->len)
				maxack = ack->ಸ್ಥಾನಾಂತರ + ack->len;
			ಆದರೆ (!reordered && ack->ಸ್ಥಾನಾಂತರ <= highwater)
				highwater = maxack;
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (!reordered && ack->ಸ್ಥಾನಾಂತರ > highwater) {
				debug3_f("server reordered ACKs");
				reordered = 1;
			}
			ಬಿಡುಗಡೆ(ack);
		}
		ಸ್ಥಾನಾಂತರ += len;
		ಆದರೆ (ಸ್ಥಾನಾಂತರ < 0)
			fatal_f("offset < 0");
	}
	sshbuf_free(ಸಂದೇಶ);

	ಆದರೆ (showprogress)
		stop_ಪ್ರಗತಿ_meter();
	ಬಿಡುಗಡೆ(ದತ್ತಾಂಶ);

	ಆದರೆ (ಸ್ಥಿತಿ_2 == SSH2_FX_OK && !interrupted) {
		/* we got everything */
		highwater = maxack;
	}
	ಆದರೆ (ಸ್ಥಿತಿ_2 != SSH2_FX_OK) {
		error("write remote \"%s\": %s", remote_ಮಾರ್ಗ, fx2txt(ಸ್ಥಿತಿ_2));
		ಸ್ಥಿತಿ_2 = SSH2_FX_FAILURE;
	}

	ಆದರೆ (inplace_flag || (resume && (ಸ್ಥಿತಿ_2 != SSH2_FX_OK || interrupted))) {
		debug("truncating at %llu", (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)highwater);
		attrib_clear(&t);
		t.flags = SSH2_FILEXFER_ATTR_ಗಾತ್ರ;
		t.ಗಾತ್ರ_2 = highwater;
		sftp_fsetstat(conn, handle, handle_len, &t);
	}

	ಆದರೆ (close(local_fd) == -1) {
		error("close local \"%s\": %s", local_ಮಾರ್ಗ, strerror(errno));
		ಸ್ಥಿತಿ_2 = SSH2_FX_FAILURE;
	}

	/* Override umask and utimes if asked */
	ಆದರೆ (preserve_flag)
		sftp_fsetstat(conn, handle, handle_len, &a);

	ಆದರೆ (fsync_flag)
		(ಶೂನ್ಯ)sftp_fsync(conn, handle, handle_len);

	ಆದರೆ (sftp_close(conn, handle, handle_len) != 0)
		ಸ್ಥಿತಿ_2 = SSH2_FX_FAILURE;

	ಬಿಡುಗಡೆ(handle);

	ಹಿಂತಿರುಗಿ ಸ್ಥಿತಿ_2 == SSH2_FX_OK ? 0 : -1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
upload_dir_ಆಂತರಿಕ(ರಚನೆ sftp_conn *conn, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *src, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *dst,
    ಪೂರ್ಣಾಂಕ ಆಳ, ಪೂರ್ಣಾಂಕ preserve_flag, ಪೂರ್ಣಾಂಕ print_flag, ಪೂರ್ಣಾಂಕ resume, ಪೂರ್ಣಾಂಕ fsync_flag,
    ಪೂರ್ಣಾಂಕ follow_link_flag, ಪೂರ್ಣಾಂಕ inplace_flag)
{
	ಪೂರ್ಣಾಂಕ created = 0, ret = 0;
	DIR *dirp;
	ರಚನೆ dirent *dp;
	ಅಕ್ಷರ *filename, *new_src = ಖಾಲಿ, *new_dst = ಖಾಲಿ;
	ರಚನೆ stat sb;
	Attrib a, dirattrib;
	uint32_t saved_perm;

	debug2_f("upload local dir \"%s\" to remote \"%s\"", src, dst);

	ಆದರೆ (ಆಳ >= MAX_DIR_ಆಳ) {
		error("Maximum directory depth exceeded: %d levels", ಆಳ);
		ಹಿಂತಿರುಗಿ -1;
	}

	ಆದರೆ (stat(src, &sb) == -1) {
		error("stat local \"%s\": %s", src, strerror(errno));
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ (!S_ISDIR(sb.st_mode)) {
		error("\"%s\" is not a directory", src);
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ (print_flag && print_flag != SFTP_ಪ್ರಗತಿ_ONLY)
		mprintf("Entering %s\n", src);

	stat_ಗಮ್ಯ_attrib(&sb, &a);
	a.flags &= ~SSH2_FILEXFER_ATTR_ಗಾತ್ರ;
	a.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a.perm &= 01777;
	ಆದರೆ (!preserve_flag)
		a.flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;

	/*
	 * sftp lacks a portable status value to match errno EEXIST,
	 * so if we get a failure back then we must check whether
	 * the path already existed and is a directory.  Ensure we can
	 * write to the directory we create for the duration of the transfer.
	 */
	saved_perm = a.perm;
	a.perm |= (S_IWUSR|S_IXUSR);
	ಆದರೆ (sftp_mkdir(conn, dst, &a, 0) == 0)
		created = 1;
	ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ (sftp_stat(conn, dst, 0, &dirattrib) != 0)
			ಹಿಂತಿರುಗಿ -1;
		ಆದರೆ (!S_ISDIR(dirattrib.perm)) {
			error("\"%s\" exists but is not a directory", dst);
			ಹಿಂತಿರುಗಿ -1;
		}
	}
	a.perm = saved_perm;

	ಆದರೆ ((dirp = opendir(src)) == ಖಾಲಿ) {
		error("local opendir \"%s\": %s", src, strerror(errno));
		ಹಿಂತಿರುಗಿ -1;
	}

	ಆಗ (((dp = readdir(dirp)) != ಖಾಲಿ) && !interrupted) {
		ಆದರೆ (dp->d_ino == 0)
			ಮುಂದುವರಿ;
		ಬಿಡುಗಡೆ(new_dst);
		ಬಿಡುಗಡೆ(new_src);
		filename = dp->d_name;
		new_dst = sftp_ಮಾರ್ಗ_append(dst, filename);
		new_src = sftp_ಮಾರ್ಗ_append(src, filename);

		ಆದರೆ (strcmp(filename, ".") == 0 || strcmp(filename, "..") == 0)
			ಮುಂದುವರಿ;
		ಆದರೆ (lstat(new_src, &sb) == -1) {
			logit("local lstat \"%s\": %s", filename,
			    strerror(errno));
			ret = -1;
			ಮುಂದುವರಿ;
		}
		ಆದರೆ (S_ISLNK(sb.st_mode)) {
			ಆದರೆ (!follow_link_flag) {
				logit("%s: not a regular file", filename);
				ಮುಂದುವರಿ;
			}
			/* Replace the stat contents with the symlink target */
			ಆದರೆ (stat(new_src, &sb) == -1) {
				logit("local stat \"%s\": %s", filename,
				    strerror(errno));
				ret = -1;
				ಮುಂದುವರಿ;
			}
		}
		ಆದರೆ (S_ISDIR(sb.st_mode)) {
			ಆದರೆ (upload_dir_ಆಂತರಿಕ(conn, new_src, new_dst,
			    ಆಳ + 1, preserve_flag, print_flag, resume,
			    fsync_flag, follow_link_flag, inplace_flag) == -1)
				ret = -1;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (S_ISREG(sb.st_mode)) {
			ಆದರೆ (sftp_upload(conn, new_src, new_dst,
			    preserve_flag, resume, fsync_flag,
			    inplace_flag) == -1) {
				error("upload \"%s\" to \"%s\" failed",
				    new_src, new_dst);
				ret = -1;
			}
		} ಇಲ್ಲದಿದ್ದರೆ
			logit("%s: not a regular file", filename);
	}
	ಬಿಡುಗಡೆ(new_dst);
	ಬಿಡುಗಡೆ(new_src);

	ಆದರೆ (created || preserve_flag)
		sftp_setstat(conn, dst, &a);

	(ಶೂನ್ಯ) closedir(dirp);
	ಹಿಂತಿರುಗಿ ret;
}

ಪೂರ್ಣಾಂಕ
sftp_upload_dir(ರಚನೆ sftp_conn *conn, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *src, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *dst,
    ಪೂರ್ಣಾಂಕ preserve_flag, ಪೂರ್ಣಾಂಕ print_flag, ಪೂರ್ಣಾಂಕ resume, ಪೂರ್ಣಾಂಕ fsync_flag,
    ಪೂರ್ಣಾಂಕ follow_link_flag, ಪೂರ್ಣಾಂಕ inplace_flag)
{
	ಅಕ್ಷರ *dst_canon;
	ಪೂರ್ಣಾಂಕ ret;

	ಆದರೆ ((dst_canon = sftp_realpath(conn, dst)) == ಖಾಲಿ) {
		error("upload \"%s\": path canonicalization failed", dst);
		ಹಿಂತಿರುಗಿ -1;
	}

	ret = upload_dir_ಆಂತರಿಕ(conn, src, dst_canon, 0, preserve_flag,
	    print_flag, resume, fsync_flag, follow_link_flag, inplace_flag);

	ಬಿಡುಗಡೆ(dst_canon);
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಶೂನ್ಯ
handle_dest_replies(ರಚನೆ sftp_conn *ಗಮ್ಯ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಗಮ್ಯ_ಮಾರ್ಗ, ಪೂರ್ಣಾಂಕ synchronous,
    u_int *nreqsp, u_int *write_errorp)
{
	ರಚನೆ sshbuf *ಸಂದೇಶ;
	u_char type;
	u_int id, ಸ್ಥಿತಿ_2;
	ಪೂರ್ಣಾಂಕ r;
	ರಚನೆ pollfd pfd;

	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");

	/* Try to eat replies from the upload side */
	ಆಗ (*nreqsp > 0) {
		debug3_f("%u outstanding replies", *nreqsp);
		ಆದರೆ (!synchronous) {
			/* Bail out if no data is ready to be read */
			pfd.fd = ಗಮ್ಯ->fd_ಒಳ;
			pfd.events = POLLIN;
			ಆದರೆ ((r = poll(&pfd, 1, 0)) == -1) {
				ಆದರೆ (errno == EINTR)
					ನಿಲ್ಲಿಸು;
				fatal_f("poll: %s", strerror(errno));
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (r == 0)
				ನಿಲ್ಲಿಸು; /* fd not ready */
		}
		sshbuf_reset(ಸಂದೇಶ);
		get_ಸಂದೇಶ(ಗಮ್ಯ, ಸಂದೇಶ);

		ಆದರೆ ((r = sshbuf_get_u8(ಸಂದೇಶ, &type)) != 0 ||
		    (r = sshbuf_get_u32(ಸಂದೇಶ, &id)) != 0)
			fatal_fr(r, "dest parse");
		debug3("Received dest reply T:%u I:%u R:%u", type, id, *nreqsp);
		ಆದರೆ (type != SSH2_FXP_ಸ್ಥಿತಿ) {
			fatal_f("Expected SSH2_FXP_STATUS(%d) packet, got %d",
			    SSH2_FXP_ಸ್ಥಿತಿ, type);
		}
		ಆದರೆ ((r = sshbuf_get_u32(ಸಂದೇಶ, &ಸ್ಥಿತಿ_2)) != 0)
			fatal_fr(r, "parse dest status");
		debug3("dest SSH2_FXP_STATUS %u", ಸ್ಥಿತಿ_2);
		ಆದರೆ (ಸ್ಥಿತಿ_2 != SSH2_FX_OK) {
			/* record first error */
			ಆದರೆ (*write_errorp == 0)
				*write_errorp = ಸ್ಥಿತಿ_2;
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

ಪೂರ್ಣಾಂಕ
sftp_crossload(ರಚನೆ sftp_conn *from, ರಚನೆ sftp_conn *ಗಮ್ಯ,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *from_ಮಾರ್ಗ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಗಮ್ಯ_ಮಾರ್ಗ,
    Attrib *a, ಪೂರ್ಣಾಂಕ preserve_flag)
{
	ರಚನೆ sshbuf *ಸಂದೇಶ;
	ಪೂರ್ಣಾಂಕ write_error, read_error, r, ನೋಡಿದ_zerolen = 0;
	uint64_t ಸ್ಥಾನಾಂತರ = 0, ಗಾತ್ರ_2;
	u_int id, buflen, ಅಂಕೆ_req, max_req, ಸ್ಥಿತಿ_2 = SSH2_FX_OK;
	u_int ಅಂಕೆ_upload_req;
	off_t ಪ್ರಗತಿ_counter;
	u_char *from_handle, *ಗಮ್ಯ_handle;
	ಗಾತ್ರ_t from_handle_len, ಗಮ್ಯ_handle_len;
	ರಚನೆ ವಿನಂತಿಗಳು ವಿನಂತಿಗಳು;
	ರಚನೆ request *req;
	u_char type;
	Attrib attr;

	debug2_f("crossload src \"%s\" to dst \"%s\"", from_ಮಾರ್ಗ, ಗಮ್ಯ_ಮಾರ್ಗ);

	TAILQ_INIT(&ವಿನಂತಿಗಳು);

	ಆದರೆ (a == ಖಾಲಿ) {
		ಆದರೆ (sftp_stat(from, from_ಮಾರ್ಗ, 0, &attr) != 0)
			ಹಿಂತಿರುಗಿ -1;
		a = &attr;
	}

	ಆದರೆ ((a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) &&
	    (!S_ISREG(a->perm))) {
		error("download \"%s\": not a regular file", from_ಮಾರ್ಗ);
		ಹಿಂತಿರುಗಿ(-1);
	}
	ಆದರೆ (a->flags & SSH2_FILEXFER_ATTR_ಗಾತ್ರ)
		ಗಾತ್ರ_2 = a->ಗಾತ್ರ_2;
	ಇಲ್ಲದಿದ್ದರೆ
		ಗಾತ್ರ_2 = 0;

	buflen = from->download_buflen;
	ಆದರೆ (buflen > ಗಮ್ಯ->upload_buflen)
		buflen = ಗಮ್ಯ->upload_buflen;

	/* Send open request to read side */
	ಆದರೆ (send_open(from, from_ಮಾರ್ಗ, "origin", SSH2_FXF_READ, ಖಾಲಿ,
	    &from_handle, &from_handle_len) != 0)
		ಹಿಂತಿರುಗಿ -1;

	/* Send open request to write side */
	a->flags &= ~SSH2_FILEXFER_ATTR_ಗಾತ್ರ;
	a->flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a->perm &= 0777;
	ಆದರೆ (!preserve_flag)
		a->flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;
	ಆದರೆ (send_open(ಗಮ್ಯ, ಗಮ್ಯ_ಮಾರ್ಗ, "dest",
	    SSH2_FXF_WRITE|SSH2_FXF_CREAT|SSH2_FXF_TRUNC, a,
	    &ಗಮ್ಯ_handle, &ಗಮ್ಯ_handle_len) != 0) {
		sftp_close(from, from_handle, from_handle_len);
		ಹಿಂತಿರುಗಿ -1;
	}

	/* Read from remote "from" and write to remote "to" */
	ಸ್ಥಾನಾಂತರ = 0;
	write_error = read_error = ಅಂಕೆ_req = ಅಂಕೆ_upload_req = 0;
	max_req = 1;
	ಪ್ರಗತಿ_counter = 0;

	ಆದರೆ (showprogress && ಗಾತ್ರ_2 != 0) {
		ಆರಂಭ_ಪ್ರಗತಿ_meter(ಪ್ರಗತಿ_meter_ಮಾರ್ಗ(from_ಮಾರ್ಗ),
		    ಗಾತ್ರ_2, &ಪ್ರಗತಿ_counter);
	}
	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆಗ (ಅಂಕೆ_req > 0 || max_req > 0) {
		u_char *ದತ್ತಾಂಶ;
		ಗಾತ್ರ_t len;

		/*
		 * Simulate EOF on interrupt: stop sending new requests and
		 * allow outstanding requests to drain gracefully
		 */
		ಆದರೆ (interrupted) {
			ಆದರೆ (ಅಂಕೆ_req == 0) /* If we haven't started yet... */
				ನಿಲ್ಲಿಸು;
			max_req = 0;
		}

		/* Send some more requests */
		ಆಗ (ಅಂಕೆ_req < max_req) {
			debug3("Request range %llu -> %llu (%d/%d)",
			    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ಸ್ಥಾನಾಂತರ,
			    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ಸ್ಥಾನಾಂತರ + buflen - 1,
			    ಅಂಕೆ_req, max_req);
			req = request_ಸರತಿಗೆ_ಸೇರಿಸು(&ವಿನಂತಿಗಳು, from->ಸಂದೇಶ_id++,
			    buflen, ಸ್ಥಾನಾಂತರ);
			ಸ್ಥಾನಾಂತರ += buflen;
			ಅಂಕೆ_req++;
			send_read_request(from, req->id, req->ಸ್ಥಾನಾಂತರ,
			    req->len, from_handle, from_handle_len);
		}

		/* Try to eat replies from the upload side (nonblocking) */
		handle_dest_replies(ಗಮ್ಯ, ಗಮ್ಯ_ಮಾರ್ಗ, 0,
		    &ಅಂಕೆ_upload_req, &write_error);

		sshbuf_reset(ಸಂದೇಶ);
		get_ಸಂದೇಶ(from, ಸಂದೇಶ);
		ಆದರೆ ((r = sshbuf_get_u8(ಸಂದೇಶ, &type)) != 0 ||
		    (r = sshbuf_get_u32(ಸಂದೇಶ, &id)) != 0)
			fatal_fr(r, "parse");
		debug3("Received origin reply T:%u I:%u R:%d",
		    type, id, max_req);

		/* Find the request in our queue */
		ಆದರೆ ((req = request_ಕಂಡುಹಿಡಿ(&ವಿನಂತಿಗಳು, id)) == ಖಾಲಿ)
			fatal("Unexpected reply %u", id);

		ಆಯ್ಕೆ (type) {
		ಸ್ಥಿತಿ SSH2_FXP_ಸ್ಥಿತಿ:
			ಆದರೆ ((r = sshbuf_get_u32(ಸಂದೇಶ, &ಸ್ಥಿತಿ_2)) != 0)
				fatal_fr(r, "parse status");
			ಆದರೆ (ಸ್ಥಿತಿ_2 != SSH2_FX_EOF)
				read_error = 1;
			max_req = 0;
			TAILQ_REMOVE(&ವಿನಂತಿಗಳು, req, tq);
			ಬಿಡುಗಡೆ(req);
			ಅಂಕೆ_req--;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ SSH2_FXP_ದತ್ತಾಂಶ:
			ಆದರೆ ((r = sshbuf_get_string(ಸಂದೇಶ, &ದತ್ತಾಂಶ, &len)) != 0)
				fatal_fr(r, "parse data");
			debug3("Received data %llu -> %llu",
			    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)req->ಸ್ಥಾನಾಂತರ,
			    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)req->ಸ್ಥಾನಾಂತರ + len - 1);
			ಆದರೆ (len > req->len)
				fatal("Received more data than asked for "
				    "%zu > %zu", len, req->len);
			ಆದರೆ (len == 0) {
				ಆದರೆ (ನೋಡಿದ_zerolen)
					fatal_f("server sent zero data length");
				ನೋಡಿದ_zerolen = 1;
			}

			/* Write this chunk out to the destination */
			sshbuf_reset(ಸಂದೇಶ);
			ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_WRITE)) != 0 ||
			    (r = sshbuf_put_u32(ಸಂದೇಶ, ಗಮ್ಯ->ಸಂದೇಶ_id++)) != 0 ||
			    (r = sshbuf_put_string(ಸಂದೇಶ, ಗಮ್ಯ_handle,
			    ಗಮ್ಯ_handle_len)) != 0 ||
			    (r = sshbuf_put_u64(ಸಂದೇಶ, req->ಸ್ಥಾನಾಂತರ)) != 0 ||
			    (r = sshbuf_put_string(ಸಂದೇಶ, ದತ್ತಾಂಶ, len)) != 0)
				fatal_fr(r, "compose write");
			send_ಸಂದೇಶ(ಗಮ್ಯ, ಸಂದೇಶ);
			debug3("Sent message SSH2_FXP_WRITE I:%u O:%llu S:%zu",
			    id, (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ಸ್ಥಾನಾಂತರ, len);
			ಅಂಕೆ_upload_req++;
			ಪ್ರಗತಿ_counter += len;
			ಬಿಡುಗಡೆ(ದತ್ತಾಂಶ);

			ಆದರೆ (len == req->len) {
				TAILQ_REMOVE(&ವಿನಂತಿಗಳು, req, tq);
				ಬಿಡುಗಡೆ(req);
				ಅಂಕೆ_req--;
			} ಇಲ್ಲದಿದ್ದರೆ {
				/* Resend the request for the missing data */
				debug3("Short data block, re-requesting "
				    "%llu -> %llu (%2d)",
				    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)req->ಸ್ಥಾನಾಂತರ + len,
				    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)req->ಸ್ಥಾನಾಂತರ +
				    req->len - 1, ಅಂಕೆ_req);
				req->id = from->ಸಂದೇಶ_id++;
				req->len -= len;
				req->ಸ್ಥಾನಾಂತರ += len;
				send_read_request(from, req->id,
				    req->ಸ್ಥಾನಾಂತರ, req->len,
				    from_handle, from_handle_len);
				/* Reduce the request size */
				ಆದರೆ (len < buflen)
					buflen = ಗರಿಷ್ಠ(MIN_READ_ಗಾತ್ರ, len);
			}
			ಆದರೆ (max_req > 0) { /* max_req = 0 iff EOF received */
				ಆದರೆ (ಗಾತ್ರ_2 > 0 && ಸ್ಥಾನಾಂತರ > ಗಾತ್ರ_2) {
					/* Only one request at a time
					 * after the expected EOF */
					debug3("Finish at %llu (%2d)",
					    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ಸ್ಥಾನಾಂತರ,
					    ಅಂಕೆ_req);
					max_req = 1;
				} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (max_req < from->ಅಂಕೆ_ವಿನಂತಿಗಳು) {
					++max_req;
				}
			}
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			fatal("Expected SSH2_FXP_DATA(%u) packet, got %u",
			    SSH2_FXP_ದತ್ತಾಂಶ, type);
		}
	}

	ಆದರೆ (showprogress && ಗಾತ್ರ_2)
		stop_ಪ್ರಗತಿ_meter();

	/* Drain replies from the server (blocking) */
	debug3_f("waiting for %u replies from destination", ಅಂಕೆ_upload_req);
	handle_dest_replies(ಗಮ್ಯ, ಗಮ್ಯ_ಮಾರ್ಗ, 1, &ಅಂಕೆ_upload_req, &write_error);

	/* Sanity check */
	ಆದರೆ (TAILQ_FIRST(&ವಿನಂತಿಗಳು) != ಖಾಲಿ)
		fatal("Transfer complete, but requests still in queue");
	/* Truncate at 0 length on interrupt or error to avoid holes at dest */
	ಆದರೆ (read_error || write_error || interrupted) {
		debug("truncating \"%s\" at 0", ಗಮ್ಯ_ಮಾರ್ಗ);
		sftp_close(ಗಮ್ಯ, ಗಮ್ಯ_handle, ಗಮ್ಯ_handle_len);
		ಬಿಡುಗಡೆ(ಗಮ್ಯ_handle);
		ಆದರೆ (send_open(ಗಮ್ಯ, ಗಮ್ಯ_ಮಾರ್ಗ, "dest",
		    SSH2_FXF_WRITE|SSH2_FXF_CREAT|SSH2_FXF_TRUNC, a,
		    &ಗಮ್ಯ_handle, &ಗಮ್ಯ_handle_len) != 0) {
			error("dest truncate \"%s\" failed", ಗಮ್ಯ_ಮಾರ್ಗ);
			ಗಮ್ಯ_handle = ಖಾಲಿ;
		}
	}
	ಆದರೆ (read_error) {
		error("read origin \"%s\": %s", from_ಮಾರ್ಗ, fx2txt(ಸ್ಥಿತಿ_2));
		ಸ್ಥಿತಿ_2 = -1;
		sftp_close(from, from_handle, from_handle_len);
		ಆದರೆ (ಗಮ್ಯ_handle != ಖಾಲಿ)
			sftp_close(ಗಮ್ಯ, ಗಮ್ಯ_handle, ಗಮ್ಯ_handle_len);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (write_error) {
		error("write dest \"%s\": %s", ಗಮ್ಯ_ಮಾರ್ಗ, fx2txt(write_error));
		ಸ್ಥಿತಿ_2 = SSH2_FX_FAILURE;
		sftp_close(from, from_handle, from_handle_len);
		ಆದರೆ (ಗಮ್ಯ_handle != ಖಾಲಿ)
			sftp_close(ಗಮ್ಯ, ಗಮ್ಯ_handle, ಗಮ್ಯ_handle_len);
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ (sftp_close(from, from_handle, from_handle_len) != 0 ||
		    interrupted)
			ಸ್ಥಿತಿ_2 = -1;
		ಇಲ್ಲದಿದ್ದರೆ
			ಸ್ಥಿತಿ_2 = SSH2_FX_OK;
		ಆದರೆ (ಗಮ್ಯ_handle != ಖಾಲಿ) {
			/* Need to resend utimes after write */
			ಆದರೆ (preserve_flag)
				sftp_fsetstat(ಗಮ್ಯ, ಗಮ್ಯ_handle, ಗಮ್ಯ_handle_len, a);
			sftp_close(ಗಮ್ಯ, ಗಮ್ಯ_handle, ಗಮ್ಯ_handle_len);
		}
	}
	sshbuf_free(ಸಂದೇಶ);
	ಬಿಡುಗಡೆ(from_handle);
	ಬಿಡುಗಡೆ(ಗಮ್ಯ_handle);

	ಹಿಂತಿರುಗಿ ಸ್ಥಿತಿ_2 == SSH2_FX_OK ? 0 : -1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
crossload_dir_ಆಂತರಿಕ(ರಚನೆ sftp_conn *from, ರಚನೆ sftp_conn *ಗಮ್ಯ,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *from_ಮಾರ್ಗ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಗಮ್ಯ_ಮಾರ್ಗ,
    ಪೂರ್ಣಾಂಕ ಆಳ, Attrib *dirattrib, ಪೂರ್ಣಾಂಕ preserve_flag, ಪೂರ್ಣಾಂಕ print_flag,
    ಪೂರ್ಣಾಂಕ follow_link_flag)
{
	ಪೂರ್ಣಾಂಕ i, ret = 0, created = 0;
	SFTP_DIRENT **dir_entries;
	ಅಕ್ಷರ *filename, *new_from_ಮಾರ್ಗ = ಖಾಲಿ, *new_ಗಮ್ಯ_ಮಾರ್ಗ = ಖಾಲಿ;
	ಬಹುಲಕ_t ಬಹುಲಕ = 0777;
	Attrib *a, curdir, ldirattrib, newdir, lsym;

	debug2_f("crossload dir src \"%s\" to dst \"%s\"", from_ಮಾರ್ಗ, ಗಮ್ಯ_ಮಾರ್ಗ);

	ಆದರೆ (ಆಳ >= MAX_DIR_ಆಳ) {
		error("Maximum directory depth exceeded: %d levels", ಆಳ);
		ಹಿಂತಿರುಗಿ -1;
	}

	ಆದರೆ (dirattrib == ಖಾಲಿ) {
		ಆದರೆ (sftp_stat(from, from_ಮಾರ್ಗ, 1, &ldirattrib) != 0) {
			error("stat remote \"%s\" failed", from_ಮಾರ್ಗ);
			ಹಿಂತಿರುಗಿ -1;
		}
		dirattrib = &ldirattrib;
	}
	ಆದರೆ (!S_ISDIR(dirattrib->perm)) {
		error("\"%s\" is not a directory", from_ಮಾರ್ಗ);
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ (print_flag && print_flag != SFTP_ಪ್ರಗತಿ_ONLY)
		mprintf("Retrieving %s\n", from_ಮಾರ್ಗ);

	curdir = *dirattrib; /* dirattrib will be clobbered */
	curdir.flags &= ~SSH2_FILEXFER_ATTR_ಗಾತ್ರ;
	curdir.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	ಆದರೆ ((curdir.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) == 0) {
		debug("Origin did not send permissions for "
		    "directory \"%s\"", ಗಮ್ಯ_ಮಾರ್ಗ);
		curdir.perm = S_IWUSR|S_IXUSR;
		curdir.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
	}
	/* We need to be able to write to the directory while we transfer it */
	ಬಹುಲಕ = curdir.perm & 01777;
	curdir.perm = ಬಹುಲಕ | (S_IWUSR|S_IXUSR);

	/*
	 * sftp lacks a portable status value to match errno EEXIST,
	 * so if we get a failure back then we must check whether
	 * the path already existed and is a directory.  Ensure we can
	 * write to the directory we create for the duration of the transfer.
	 */
	ಆದರೆ (sftp_mkdir(ಗಮ್ಯ, ಗಮ್ಯ_ಮಾರ್ಗ, &curdir, 0) == 0)
		created = 1;
	ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ (sftp_stat(ಗಮ್ಯ, ಗಮ್ಯ_ಮಾರ್ಗ, 0, &newdir) != 0)
			ಹಿಂತಿರುಗಿ -1;
		ಆದರೆ (!S_ISDIR(newdir.perm)) {
			error("\"%s\" exists but is not a directory", ಗಮ್ಯ_ಮಾರ್ಗ);
			ಹಿಂತಿರುಗಿ -1;
		}
	}
	curdir.perm = ಬಹುಲಕ;

	ಆದರೆ (sftp_readdir(from, from_ಮಾರ್ಗ, &dir_entries) == -1) {
		error("origin readdir \"%s\" failed", from_ಮಾರ್ಗ);
		ಹಿಂತಿರುಗಿ -1;
	}

	ಗಾಗಿ (i = 0; dir_entries[i] != ಖಾಲಿ && !interrupted; i++) {
		ಬಿಡುಗಡೆ(new_from_ಮಾರ್ಗ);
		ಬಿಡುಗಡೆ(new_ಗಮ್ಯ_ಮಾರ್ಗ);

		filename = dir_entries[i]->filename;
		new_from_ಮಾರ್ಗ = sftp_ಮಾರ್ಗ_append(from_ಮಾರ್ಗ, filename);
		new_ಗಮ್ಯ_ಮಾರ್ಗ = sftp_ಮಾರ್ಗ_append(ಗಮ್ಯ_ಮಾರ್ಗ, filename);

		a = &dir_entries[i]->a;
		ಆದರೆ (S_ISLNK(a->perm)) {
			ಆದರೆ (!follow_link_flag) {
				logit("%s: not a regular file", filename);
				ಮುಂದುವರಿ;
			}
			/* Replace the stat contents with the symlink target */
			ಆದರೆ (sftp_stat(from, new_from_ಮಾರ್ಗ, 1, &lsym) != 0) {
				logit("remote stat \"%s\" failed",
				    new_from_ಮಾರ್ಗ);
				ret = -1;
				ಮುಂದುವರಿ;
			}
			a = &lsym;
		}
		ಆದರೆ (S_ISDIR(a->perm)) {
			ಆದರೆ (strcmp(filename, ".") == 0 ||
			    strcmp(filename, "..") == 0)
				ಮುಂದುವರಿ;
			ಆದರೆ (crossload_dir_ಆಂತರಿಕ(from, ಗಮ್ಯ,
			    new_from_ಮಾರ್ಗ, new_ಗಮ್ಯ_ಮಾರ್ಗ,
			    ಆಳ + 1, a, preserve_flag,
			    print_flag, follow_link_flag) == -1)
				ret = -1;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (S_ISREG(a->perm)) {
			ಆದರೆ (sftp_crossload(from, ಗಮ್ಯ, new_from_ಮಾರ್ಗ,
			    new_ಗಮ್ಯ_ಮಾರ್ಗ, a, preserve_flag) == -1) {
				error("crossload \"%s\" to \"%s\" failed",
				    new_from_ಮಾರ್ಗ, new_ಗಮ್ಯ_ಮಾರ್ಗ);
				ret = -1;
			}
		} ಇಲ್ಲದಿದ್ದರೆ {
			logit("origin \"%s\": not a regular file",
			    new_from_ಮಾರ್ಗ);
		}
	}
	ಬಿಡುಗಡೆ(new_ಗಮ್ಯ_ಮಾರ್ಗ);
	ಬಿಡುಗಡೆ(new_from_ಮಾರ್ಗ);

	ಆದರೆ (created || preserve_flag)
		sftp_setstat(ಗಮ್ಯ, ಗಮ್ಯ_ಮಾರ್ಗ, &curdir);

	sftp_free_dirents(dir_entries);

	ಹಿಂತಿರುಗಿ ret;
}

ಪೂರ್ಣಾಂಕ
sftp_crossload_dir(ರಚನೆ sftp_conn *from, ರಚನೆ sftp_conn *ಗಮ್ಯ,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *from_ಮಾರ್ಗ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಗಮ್ಯ_ಮಾರ್ಗ,
    Attrib *dirattrib, ಪೂರ್ಣಾಂಕ preserve_flag, ಪೂರ್ಣಾಂಕ print_flag, ಪೂರ್ಣಾಂಕ follow_link_flag)
{
	ಅಕ್ಷರ *from_ಮಾರ್ಗ_canon;
	ಪೂರ್ಣಾಂಕ ret;

	ಆದರೆ ((from_ಮಾರ್ಗ_canon = sftp_realpath(from, from_ಮಾರ್ಗ)) == ಖಾಲಿ) {
		error("crossload \"%s\": path canonicalization failed",
		    from_ಮಾರ್ಗ);
		ಹಿಂತಿರುಗಿ -1;
	}

	ret = crossload_dir_ಆಂತರಿಕ(from, ಗಮ್ಯ, from_ಮಾರ್ಗ_canon, ಗಮ್ಯ_ಮಾರ್ಗ, 0,
	    dirattrib, preserve_flag, print_flag, follow_link_flag);
	ಬಿಡುಗಡೆ(from_ಮಾರ್ಗ_canon);
	ಹಿಂತಿರುಗಿ ret;
}

ಪೂರ್ಣಾಂಕ
sftp_can_get_users_groups_by_id(ರಚನೆ sftp_conn *conn)
{
	ಹಿಂತಿರುಗಿ (conn->exts & SFTP_EXT_GETUSERSGROUPS_BY_ID) != 0;
}

ಪೂರ್ಣಾಂಕ
sftp_get_users_groups_by_id(ರಚನೆ sftp_conn *conn,
    ಸ್ಥಿರಾಂಕ u_int *uids, u_int nuids,
    ಸ್ಥಿರಾಂಕ u_int *gids, u_int ngids,
    ಅಕ್ಷರ ***usernamesp, ಅಕ್ಷರ ***groupnamesp)
{
	ರಚನೆ sshbuf *ಸಂದೇಶ, *uidbuf, *gidbuf;
	u_int i, expected_id, id;
	ಅಕ್ಷರ *name, **usernames = ಖಾಲಿ, **groupnames = ಖಾಲಿ;
	u_char type;
	ಪೂರ್ಣಾಂಕ r;

	*usernamesp = *groupnamesp = ಖಾಲಿ;
	ಆದರೆ (!sftp_can_get_users_groups_by_id(conn))
		ಹಿಂತಿರುಗಿ SSH_ERR_FEATURE_UNSUPPORTED;

	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ ||
	    (uidbuf = sshbuf_new()) == ಖಾಲಿ ||
	    (gidbuf = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	expected_id = id = conn->ಸಂದೇಶ_id++;
	debug2("Sending SSH2_FXP_EXTENDED(users-groups-by-id@openssh.com)");
	ಗಾಗಿ (i = 0; i < nuids; i++) {
		ಆದರೆ ((r = sshbuf_put_u32(uidbuf, uids[i])) != 0)
			fatal_fr(r, "compose uids");
	}
	ಗಾಗಿ (i = 0; i < ngids; i++) {
		ಆದರೆ ((r = sshbuf_put_u32(gidbuf, gids[i])) != 0)
			fatal_fr(r, "compose gids");
	}
	ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ,
	    "users-groups-by-id@openssh.com")) != 0 ||
	    (r = sshbuf_put_stringb(ಸಂದೇಶ, uidbuf)) != 0 ||
	    (r = sshbuf_put_stringb(ಸಂದೇಶ, gidbuf)) != 0)
		fatal_fr(r, "compose");
	send_ಸಂದೇಶ(conn, ಸಂದೇಶ);
	get_ಸಂದೇಶ(conn, ಸಂದೇಶ);
	ಆದರೆ ((r = sshbuf_get_u8(ಸಂದೇಶ, &type)) != 0 ||
	    (r = sshbuf_get_u32(ಸಂದೇಶ, &id)) != 0)
		fatal_fr(r, "parse");
	ಆದರೆ (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	ಆದರೆ (type == SSH2_FXP_ಸ್ಥಿತಿ) {
		u_int ಸ್ಥಿತಿ_2;
		ಅಕ್ಷರ *errmsg;

		ಆದರೆ ((r = sshbuf_get_u32(ಸಂದೇಶ, &ಸ್ಥಿತಿ_2)) != 0 ||
		    (r = sshbuf_get_cstring(ಸಂದೇಶ, &errmsg, ಖಾಲಿ)) != 0)
			fatal_fr(r, "parse status");
		error("users-groups-by-id %s",
		    *errmsg == '\0' ? fx2txt(ಸ್ಥಿತಿ_2) : errmsg);
		ಬಿಡುಗಡೆ(errmsg);
		sshbuf_free(ಸಂದೇಶ);
		sshbuf_free(uidbuf);
		sshbuf_free(gidbuf);
		ಹಿಂತಿರುಗಿ -1;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (type != SSH2_FXP_EXTENDED_ಉತ್ತರ)
		fatal("Expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_ಉತ್ತರ, type);

	/* reuse */
	sshbuf_free(uidbuf);
	sshbuf_free(gidbuf);
	uidbuf = gidbuf = ಖಾಲಿ;
	ಆದರೆ ((r = sshbuf_froms(ಸಂದೇಶ, &uidbuf)) != 0 ||
	    (r = sshbuf_froms(ಸಂದೇಶ, &gidbuf)) != 0)
		fatal_fr(r, "parse response");
	ಆದರೆ (nuids > 0) {
		usernames = xcalloc(nuids, ಗಾತ್ರ(*usernames));
		ಗಾಗಿ (i = 0; i < nuids; i++) {
			ಆದರೆ ((r = sshbuf_get_cstring(uidbuf, &name, ಖಾಲಿ)) != 0)
				fatal_fr(r, "parse user name");
			/* Handle unresolved names */
			ಆದರೆ (*name == '\0') {
				ಬಿಡುಗಡೆ(name);
				name = ಖಾಲಿ;
			}
			usernames[i] = name;
		}
	}
	ಆದರೆ (ngids > 0) {
		groupnames = xcalloc(ngids, ಗಾತ್ರ(*groupnames));
		ಗಾಗಿ (i = 0; i < ngids; i++) {
			ಆದರೆ ((r = sshbuf_get_cstring(gidbuf, &name, ಖಾಲಿ)) != 0)
				fatal_fr(r, "parse user name");
			/* Handle unresolved names */
			ಆದರೆ (*name == '\0') {
				ಬಿಡುಗಡೆ(name);
				name = ಖಾಲಿ;
			}
			groupnames[i] = name;
		}
	}
	ಆದರೆ (sshbuf_len(uidbuf) != 0)
		fatal_f("unexpected extra username data");
	ಆದರೆ (sshbuf_len(gidbuf) != 0)
		fatal_f("unexpected extra groupname data");
	sshbuf_free(uidbuf);
	sshbuf_free(gidbuf);
	sshbuf_free(ಸಂದೇಶ);
	/* success */
	*usernamesp = usernames;
	*groupnamesp = groupnames;
	ಹಿಂತಿರುಗಿ 0;
}

ಅಕ್ಷರ *
sftp_ಮಾರ್ಗ_append(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *p1, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *p2)
{
	ಅಕ್ಷರ *ret;
	ಗಾತ್ರ_t len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(p1) + ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(p2) + 2;

	ret = xmalloc(len);
	strlcpy(ret, p1, len);
	ಆದರೆ (p1[0] != '\0' && p1[ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(p1) - 1] != '/')
		strlcat(ret, "/", len);
	strlcat(ret, p2, len);

	ಹಿಂತಿರುಗಿ(ret);
}

/*
 * Arg p must be dynamically allocated.  It will either be returned or
 * freed and a replacement allocated.  Caller must free returned string.
 */
ಅಕ್ಷರ *
sftp_make_absolute(ಅಕ್ಷರ *p, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pwd)
{
	ಅಕ್ಷರ *abs_str;

	/* Derelativise */
	ಆದರೆ (p && !ಮಾರ್ಗ_absolute(p)) {
		abs_str = sftp_ಮಾರ್ಗ_append(pwd, p);
		ಬಿಡುಗಡೆ(p);
		ಹಿಂತಿರುಗಿ(abs_str);
	} ಇಲ್ಲದಿದ್ದರೆ
		ಹಿಂತಿರುಗಿ(p);
}

ಪೂರ್ಣಾಂಕ
sftp_remote_is_dir(ರಚನೆ sftp_conn *conn, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ)
{
	Attrib a;

	/* XXX: report errors? */
	ಆದರೆ (sftp_stat(conn, ಮಾರ್ಗ, 1, &a) != 0)
		ಹಿಂತಿರುಗಿ(0);
	ಆದರೆ (!(a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS))
		ಹಿಂತಿರುಗಿ(0);
	ಹಿಂತಿರುಗಿ S_ISDIR(a.perm);
}


/* Check whether path returned from glob(..., GLOB_MARK, ...) is a directory */
ಪೂರ್ಣಾಂಕ
sftp_globpath_is_dir(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pathname)
{
	ಗಾತ್ರ_t l = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(pathname);

	ಹಿಂತಿರುಗಿ l > 0 && pathname[l - 1] == '/';
}

