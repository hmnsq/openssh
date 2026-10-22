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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/queue.h>
#അന്തര്ഭാവ <sys/stat.h>
#അന്തര്ഭാവ <sys/time.h>
#അന്തര്ഭാവ <sys/statvfs.h>
#അന്തര്ഭാവ <sys/uio.h>

#അന്തര്ഭാവ <dirent.h>
#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <fcntl.h>
#അന്തര്ഭാവ <poll.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "atomicio.h"
#അന്തര്ഭാവ "progressmeter.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "utf8.h"

#അന്തര്ഭാവ "sftp.h"
#അന്തര്ഭാവ "sftp-common.h"
#അന്തര്ഭാവ "sftp-client.h"

ബാഹ്യ അസ്ഥിര sig_atomic_t interrupted;
ബാഹ്യ പൂർണ്ണസംഖ്യ showprogress;

/* Default size of buffer for up/download (fix sftp.1 scp.1 if changed) */
#define DEFAULT_COPY_BUFLEN	32768

/* Default number of concurrent xfer requests (fix sftp.1 scp.1 if changed) */
#define DEFAULT_അക്കം_REQUESTS	64

/* Minimum amount of data to read at a time */
#define MIN_READ_SIZE	512

/* Maximum depth to descend in directory trees */
#define MAX_DIR_DEPTH 64

/* Directory separator characters */
#ifdef HAVE_CYGWIN
# define SFTP_DIRECTORY_CHARS      "/\\"
#അല്ലെങ്കിൽ /* HAVE_CYGWIN */
# define SFTP_DIRECTORY_CHARS      "/"
#endif /* HAVE_CYGWIN */

ഘടന sftp_conn {
	പൂർണ്ണസംഖ്യ fd_in;
	പൂർണ്ണസംഖ്യ fd_out;
	u_int download_buflen;
	u_int upload_buflen;
	u_int അക്കം_requests;
	u_int version;
	u_int സന്ദേശം_id;
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
	ഘടന bwlimit bwlimit_in, bwlimit_out;
};

/* Tracks in-progress requests during file transfers */
ഘടന request {
	u_int id;
	size_t len;
	uint64_t offset;
	TAILQ_ENTRY(request) tq;
};
TAILQ_HEAD(requests, request);

സ്ഥിതം u_char *
get_handle(ഘടന sftp_conn *conn, u_int expected_id, size_t *len,
    സ്ഥിരം അക്ഷരം *errfmt, ...) __attribute__((format(printf, 4, 5)));

സ്ഥിതം ഘടന request *
request_enqueue(ഘടന requests *requests, u_int id, size_t len,
    uint64_t offset)
{
	ഘടന request *req;

	req = xcalloc(1, വലുപ്പം(*req));
	req->id = id;
	req->len = len;
	req->offset = offset;
	TAILQ_INSERT_TAIL(requests, req, tq);
	തിരികെ req;
}

സ്ഥിതം ഘടന request *
request_find(ഘടന requests *requests, u_int id)
{
	ഘടന request *req;

	വേണ്ടി (req = TAILQ_FIRST(requests);
	    req != ശൂന്യ && req->id != id;
	    req = TAILQ_NEXT(req, tq))
		;
	തിരികെ req;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
sftpio(ശൂന്യം *_bwlimit, size_t amount)
{
	ഘടന bwlimit *bwlimit = (ഘടന bwlimit *)_bwlimit;

	refresh_progress_meter(0);
	എങ്കിൽ (bwlimit != ശൂന്യ)
		bandwidth_limit(bwlimit, amount);
	തിരികെ 0;
}

സ്ഥിതം ശൂന്യം
send_സന്ദേശം(ഘടന sftp_conn *conn, ഘടന sshbuf *m)
{
	u_char mlen[4];
	ഘടന iovec iov[2];

	എങ്കിൽ (sshbuf_len(m) > SFTP_MAX_സന്ദേശം_LENGTH)
		fatal("Outbound message too long %zu", sshbuf_len(m));

	/* Send length first */
	put_u32(mlen, sshbuf_len(m));
	iov[0].iov_base = mlen;
	iov[0].iov_len = വലുപ്പം(mlen);
	iov[1].iov_base = (u_char *)sshbuf_ptr(m);
	iov[1].iov_len = sshbuf_len(m);

	എങ്കിൽ (atomiciov6(writev, conn->fd_out, iov, 2, sftpio,
	    conn->limit_kbps > 0 ? &conn->bwlimit_out : ശൂന്യ) !=
	    sshbuf_len(m) + വലുപ്പം(mlen))
		fatal("Couldn't send packet: %s", strerror(errno));

	sshbuf_reset(m);
}

സ്ഥിതം ശൂന്യം
get_സന്ദേശം_extended(ഘടന sftp_conn *conn, ഘടന sshbuf *m, പൂർണ്ണസംഖ്യ initial)
{
	u_int സന്ദേശം_len;
	u_char *p;
	പൂർണ്ണസംഖ്യ r;

	sshbuf_reset(m);
	എങ്കിൽ ((r = sshbuf_reserve(m, 4, &p)) != 0)
		fatal_fr(r, "reserve");
	എങ്കിൽ (atomicio6(പഠ, conn->fd_in, p, 4, sftpio,
	    conn->limit_kbps > 0 ? &conn->bwlimit_in : ശൂന്യ) != 4) {
		എങ്കിൽ (errno == EPIPE || errno == ECONNRESET)
			fatal("Connection closed");
		അല്ലെങ്കിൽ
			fatal("Couldn't read packet: %s", strerror(errno));
	}

	എങ്കിൽ ((r = sshbuf_get_u32(m, &സന്ദേശം_len)) != 0)
		fatal_fr(r, "sshbuf_get_u32");
	എങ്കിൽ (സന്ദേശം_len > SFTP_MAX_സന്ദേശം_LENGTH) {
		do_log2(initial ? SYSLOG_LEVEL_ERROR : SYSLOG_LEVEL_FATAL,
		    "Received message too long %u", സന്ദേശം_len);
		fatal("Ensure the remote shell produces no output "
		    "for non-interactive sessions.");
	}

	എങ്കിൽ ((r = sshbuf_reserve(m, സന്ദേശം_len, &p)) != 0)
		fatal_fr(r, "reserve");
	എങ്കിൽ (atomicio6(പഠ, conn->fd_in, p, സന്ദേശം_len, sftpio,
	    conn->limit_kbps > 0 ? &conn->bwlimit_in : ശൂന്യ)
	    != സന്ദേശം_len) {
		എങ്കിൽ (errno == EPIPE)
			fatal("Connection closed");
		അല്ലെങ്കിൽ
			fatal("Read packet: %s", strerror(errno));
	}
}

സ്ഥിതം ശൂന്യം
get_സന്ദേശം(ഘടന sftp_conn *conn, ഘടന sshbuf *m)
{
	get_സന്ദേശം_extended(conn, m, 0);
}

സ്ഥിതം ശൂന്യം
send_string_request(ഘടന sftp_conn *conn, u_int id, u_int code, സ്ഥിരം അക്ഷരം *s,
    u_int len)
{
	ഘടന sshbuf *സന്ദേശം;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, code)) != 0 ||
	    (r = sshbuf_put_u32(സന്ദേശം, id)) != 0 ||
	    (r = sshbuf_put_string(സന്ദേശം, s, len)) != 0)
		fatal_fr(r, "compose");
	send_സന്ദേശം(conn, സന്ദേശം);
	debug3("Sent message fd %d T:%u I:%u", conn->fd_out, code, id);
	sshbuf_free(സന്ദേശം);
}

സ്ഥിതം ശൂന്യം
send_string_attrs_request(ഘടന sftp_conn *conn, u_int id, u_int code,
    സ്ഥിരം ശൂന്യം *s, u_int len, Attrib *a)
{
	ഘടന sshbuf *സന്ദേശം;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, code)) != 0 ||
	    (r = sshbuf_put_u32(സന്ദേശം, id)) != 0 ||
	    (r = sshbuf_put_string(സന്ദേശം, s, len)) != 0 ||
	    (r = encode_attrib(സന്ദേശം, a)) != 0)
		fatal_fr(r, "compose");
	send_സന്ദേശം(conn, സന്ദേശം);
	debug3("Sent message fd %d T:%u I:%u F:0x%04x M:%05o",
	    conn->fd_out, code, id, a->flags, a->perm);
	sshbuf_free(സന്ദേശം);
}

സ്ഥിതം u_int
get_status(ഘടന sftp_conn *conn, u_int expected_id)
{
	ഘടന sshbuf *സന്ദേശം;
	u_char type;
	u_int id, status;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	get_സന്ദേശം(conn, സന്ദേശം);
	എങ്കിൽ ((r = sshbuf_get_u8(സന്ദേശം, &type)) != 0 ||
	    (r = sshbuf_get_u32(സന്ദേശം, &id)) != 0)
		fatal_fr(r, "compose");

	എങ്കിൽ (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	എങ്കിൽ (type != SSH2_FXP_STATUS)
		fatal("Expected SSH2_FXP_STATUS(%u) packet, got %u",
		    SSH2_FXP_STATUS, type);

	എങ്കിൽ ((r = sshbuf_get_u32(സന്ദേശം, &status)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(സന്ദേശം);

	debug3("SSH2_FXP_STATUS %u", status);

	തിരികെ status;
}

സ്ഥിതം u_char *
get_handle(ഘടന sftp_conn *conn, u_int expected_id, size_t *len,
    സ്ഥിരം അക്ഷരം *errfmt, ...)
{
	ഘടന sshbuf *സന്ദേശം;
	u_int id, status;
	u_char type;
	u_char *handle;
	അക്ഷരം errmsg[256];
	va_list args;
	പൂർണ്ണസംഖ്യ r;

	va_start(args, errfmt);
	എങ്കിൽ (errfmt != ശൂന്യ)
		vsnprintf(errmsg, വലുപ്പം(errmsg), errfmt, args);
	va_end(args);

	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	get_സന്ദേശം(conn, സന്ദേശം);
	എങ്കിൽ ((r = sshbuf_get_u8(സന്ദേശം, &type)) != 0 ||
	    (r = sshbuf_get_u32(സന്ദേശം, &id)) != 0)
		fatal_fr(r, "parse");

	എങ്കിൽ (id != expected_id)
		fatal("%s: ID mismatch (%u != %u)",
		    errfmt == ശൂന്യ ? __func__ : errmsg, id, expected_id);
	എങ്കിൽ (type == SSH2_FXP_STATUS) {
		എങ്കിൽ ((r = sshbuf_get_u32(സന്ദേശം, &status)) != 0)
			fatal_fr(r, "parse status");
		എങ്കിൽ (errfmt != ശൂന്യ)
			error("%s: %s", errmsg, fx2txt(status));
		sshbuf_free(സന്ദേശം);
		തിരികെ(ശൂന്യ);
	} അല്ലെങ്കിൽ എങ്കിൽ (type != SSH2_FXP_HANDLE)
		fatal("%s: Expected SSH2_FXP_HANDLE(%u) packet, got %u",
		    errfmt == ശൂന്യ ? __func__ : errmsg, SSH2_FXP_HANDLE, type);

	എങ്കിൽ ((r = sshbuf_get_string(സന്ദേശം, &handle, len)) != 0)
		fatal_fr(r, "parse handle");
	sshbuf_free(സന്ദേശം);

	തിരികെ handle;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
get_decode_stat(ഘടന sftp_conn *conn, u_int expected_id, പൂർണ്ണസംഖ്യ quiet, Attrib *a)
{
	ഘടന sshbuf *സന്ദേശം;
	u_int id;
	u_char type;
	പൂർണ്ണസംഖ്യ r;
	Attrib attr;

	എങ്കിൽ (a != ശൂന്യ)
		memset(a, '\0', വലുപ്പം(*a));
	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	get_സന്ദേശം(conn, സന്ദേശം);

	എങ്കിൽ ((r = sshbuf_get_u8(സന്ദേശം, &type)) != 0 ||
	    (r = sshbuf_get_u32(സന്ദേശം, &id)) != 0)
		fatal_fr(r, "parse");

	എങ്കിൽ (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	എങ്കിൽ (type == SSH2_FXP_STATUS) {
		u_int status;

		എങ്കിൽ ((r = sshbuf_get_u32(സന്ദേശം, &status)) != 0)
			fatal_fr(r, "parse status");
		എങ്കിൽ (quiet)
			debug("stat remote: %s", fx2txt(status));
		അല്ലെങ്കിൽ
			error("stat remote: %s", fx2txt(status));
		sshbuf_free(സന്ദേശം);
		തിരികെ -1;
	} അല്ലെങ്കിൽ എങ്കിൽ (type != SSH2_FXP_ATTRS) {
		fatal("Expected SSH2_FXP_ATTRS(%u) packet, got %u",
		    SSH2_FXP_ATTRS, type);
	}
	എങ്കിൽ ((r = decode_attrib(സന്ദേശം, &attr)) != 0) {
		error_fr(r, "decode_attrib");
		sshbuf_free(സന്ദേശം);
		തിരികെ -1;
	}
	/* success */
	എങ്കിൽ (a != ശൂന്യ)
		*a = attr;
	debug3("Received stat reply T:%u I:%u F:0x%04x M:%05o",
	    type, id, attr.flags, attr.perm);
	sshbuf_free(സന്ദേശം);

	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
get_decode_statvfs(ഘടന sftp_conn *conn, ഘടന sftp_statvfs *st,
    u_int expected_id, പൂർണ്ണസംഖ്യ quiet)
{
	ഘടന sshbuf *സന്ദേശം;
	u_char type;
	u_int id;
	uint64_t flag;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	get_സന്ദേശം(conn, സന്ദേശം);

	എങ്കിൽ ((r = sshbuf_get_u8(സന്ദേശം, &type)) != 0 ||
	    (r = sshbuf_get_u32(സന്ദേശം, &id)) != 0)
		fatal_fr(r, "parse");

	debug3("Received statvfs reply T:%u I:%u", type, id);
	എങ്കിൽ (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	എങ്കിൽ (type == SSH2_FXP_STATUS) {
		u_int status;

		എങ്കിൽ ((r = sshbuf_get_u32(സന്ദേശം, &status)) != 0)
			fatal_fr(r, "parse status");
		എങ്കിൽ (quiet)
			debug("remote statvfs: %s", fx2txt(status));
		അല്ലെങ്കിൽ
			error("remote statvfs: %s", fx2txt(status));
		sshbuf_free(സന്ദേശം);
		തിരികെ -1;
	} അല്ലെങ്കിൽ എങ്കിൽ (type != SSH2_FXP_EXTENDED_REPLY) {
		fatal("Expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_REPLY, type);
	}

	memset(st, 0, വലുപ്പം(*st));
	എങ്കിൽ ((r = sshbuf_get_u64(സന്ദേശം, &st->f_bsize)) != 0 ||
	    (r = sshbuf_get_u64(സന്ദേശം, &st->f_frsize)) != 0 ||
	    (r = sshbuf_get_u64(സന്ദേശം, &st->f_blocks)) != 0 ||
	    (r = sshbuf_get_u64(സന്ദേശം, &st->f_bfree)) != 0 ||
	    (r = sshbuf_get_u64(സന്ദേശം, &st->f_bavail)) != 0 ||
	    (r = sshbuf_get_u64(സന്ദേശം, &st->f_files)) != 0 ||
	    (r = sshbuf_get_u64(സന്ദേശം, &st->f_ffree)) != 0 ||
	    (r = sshbuf_get_u64(സന്ദേശം, &st->f_favail)) != 0 ||
	    (r = sshbuf_get_u64(സന്ദേശം, &st->f_fsid)) != 0 ||
	    (r = sshbuf_get_u64(സന്ദേശം, &flag)) != 0 ||
	    (r = sshbuf_get_u64(സന്ദേശം, &st->f_namemax)) != 0)
		fatal_fr(r, "parse statvfs");

	st->f_flag = (flag & SSH2_FXE_STATVFS_ST_RDONLY) ? ST_RDONLY : 0;
	st->f_flag |= (flag & SSH2_FXE_STATVFS_ST_NOSUID) ? ST_NOSUID : 0;

	sshbuf_free(സന്ദേശം);

	തിരികെ 0;
}

ഘടന sftp_conn *
sftp_init(പൂർണ്ണസംഖ്യ fd_in, പൂർണ്ണസംഖ്യ fd_out, u_int transfer_buflen, u_int അക്കം_requests,
    uint64_t limit_kbps)
{
	u_char type;
	ഘടന sshbuf *സന്ദേശം;
	ഘടന sftp_conn *ret;
	പൂർണ്ണസംഖ്യ r;

	ret = xcalloc(1, വലുപ്പം(*ret));
	ret->സന്ദേശം_id = 1;
	ret->fd_in = fd_in;
	ret->fd_out = fd_out;
	ret->download_buflen = ret->upload_buflen =
	    transfer_buflen ? transfer_buflen : DEFAULT_COPY_BUFLEN;
	ret->അക്കം_requests =
	    അക്കം_requests ? അക്കം_requests : DEFAULT_അക്കം_REQUESTS;
	ret->exts = 0;
	ret->limit_kbps = 0;

	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, SSH2_FXP_INIT)) != 0 ||
	    (r = sshbuf_put_u32(സന്ദേശം, SSH2_FILEXFER_VERSION)) != 0)
		fatal_fr(r, "parse");

	send_സന്ദേശം(ret, സന്ദേശം);

	get_സന്ദേശം_extended(ret, സന്ദേശം, 1);

	/* Expecting a VERSION reply */
	എങ്കിൽ ((r = sshbuf_get_u8(സന്ദേശം, &type)) != 0)
		fatal_fr(r, "parse type");
	എങ്കിൽ (type != SSH2_FXP_VERSION) {
		error("Invalid packet back from SSH2_FXP_INIT (type %u)",
		    type);
		sshbuf_free(സന്ദേശം);
		സ്വതന്ത്രം(ret);
		തിരികെ(ശൂന്യ);
	}
	എങ്കിൽ ((r = sshbuf_get_u32(സന്ദേശം, &ret->version)) != 0)
		fatal_fr(r, "parse version");

	debug2("Remote version: %u", ret->version);

	/* Check for extensions */
	ആകുമ്പോൾ (sshbuf_len(സന്ദേശം) > 0) {
		അക്ഷരം *name;
		u_char *മൂല്യം;
		size_t vlen;
		പൂർണ്ണസംഖ്യ known = 0;

		എങ്കിൽ ((r = sshbuf_get_cstring(സന്ദേശം, &name, ശൂന്യ)) != 0 ||
		    (r = sshbuf_get_string(സന്ദേശം, &മൂല്യം, &vlen)) != 0)
			fatal_fr(r, "parse extension");
		എങ്കിൽ (strcmp(name, "posix-rename@openssh.com") == 0 &&
		    strcmp((അക്ഷരം *)മൂല്യം, "1") == 0) {
			ret->exts |= SFTP_EXT_POSIX_RENAME;
			known = 1;
		} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(name, "statvfs@openssh.com") == 0 &&
		    strcmp((അക്ഷരം *)മൂല്യം, "2") == 0) {
			ret->exts |= SFTP_EXT_STATVFS;
			known = 1;
		} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(name, "fstatvfs@openssh.com") == 0 &&
		    strcmp((അക്ഷരം *)മൂല്യം, "2") == 0) {
			ret->exts |= SFTP_EXT_FSTATVFS;
			known = 1;
		} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(name, "hardlink@openssh.com") == 0 &&
		    strcmp((അക്ഷരം *)മൂല്യം, "1") == 0) {
			ret->exts |= SFTP_EXT_HARDLINK;
			known = 1;
		} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(name, "fsync@openssh.com") == 0 &&
		    strcmp((അക്ഷരം *)മൂല്യം, "1") == 0) {
			ret->exts |= SFTP_EXT_FSYNC;
			known = 1;
		} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(name, "lsetstat@openssh.com") == 0 &&
		    strcmp((അക്ഷരം *)മൂല്യം, "1") == 0) {
			ret->exts |= SFTP_EXT_LSETSTAT;
			known = 1;
		} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(name, "limits@openssh.com") == 0 &&
		    strcmp((അക്ഷരം *)മൂല്യം, "1") == 0) {
			ret->exts |= SFTP_EXT_LIMITS;
			known = 1;
		} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(name, "expand-path@openssh.com") == 0 &&
		    strcmp((അക്ഷരം *)മൂല്യം, "1") == 0) {
			ret->exts |= SFTP_EXT_PATH_EXPAND;
			known = 1;
		} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(name, "copy-data") == 0 &&
		    strcmp((അക്ഷരം *)മൂല്യം, "1") == 0) {
			ret->exts |= SFTP_EXT_COPY_DATA;
			known = 1;
		} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(name,
		    "users-groups-by-id@openssh.com") == 0 &&
		    strcmp((അക്ഷരം *)മൂല്യം, "1") == 0) {
			ret->exts |= SFTP_EXT_GETUSERSGROUPS_BY_ID;
			known = 1;
		}
		എങ്കിൽ (known) {
			debug2("Server supports extension \"%s\" revision %s",
			    name, മൂല്യം);
		} അല്ലെങ്കിൽ {
			debug2("Unrecognised server extension \"%s\"", name);
		}
		സ്വതന്ത്രം(name);
		സ്വതന്ത്രം(മൂല്യം);
	}

	sshbuf_free(സന്ദേശം);

	/* Query the server for its limits */
	എങ്കിൽ (ret->exts & SFTP_EXT_LIMITS) {
		ഘടന sftp_limits limits;
		എങ്കിൽ (sftp_get_limits(ret, &limits) != 0)
			fatal_f("limits failed");

		/* If the caller did not specify, find a good value */
		എങ്കിൽ (transfer_buflen == 0) {
			ret->download_buflen = MINIMUM(limits.read_length,
			    SFTP_MAX_സന്ദേശം_LENGTH - 1024);
			ret->upload_buflen = MINIMUM(limits.write_length,
			    SFTP_MAX_സന്ദേശം_LENGTH - 1024);
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
	എങ്കിൽ (ret->version == 0) {
		ret->download_buflen = MINIMUM(ret->download_buflen, 20480);
		ret->upload_buflen = MINIMUM(ret->upload_buflen, 20480);
	}

	ret->limit_kbps = limit_kbps;
	എങ്കിൽ (ret->limit_kbps > 0) {
		bandwidth_limit_init(&ret->bwlimit_in, ret->limit_kbps,
		    ret->download_buflen);
		bandwidth_limit_init(&ret->bwlimit_out, ret->limit_kbps,
		    ret->upload_buflen);
	}

	തിരികെ ret;
}

ശൂന്യം
sftp_free(ഘടന sftp_conn *conn)
{
	എങ്കിൽ (conn == ശൂന്യ)
		തിരികെ;
	freezero(conn, വലുപ്പം(*conn));
}

u_int
sftp_proto_version(ഘടന sftp_conn *conn)
{
	തിരികെ conn->version;
}

പൂർണ്ണസംഖ്യ
sftp_get_limits(ഘടന sftp_conn *conn, ഘടന sftp_limits *limits)
{
	u_int id, സന്ദേശം_id;
	u_char type;
	ഘടന sshbuf *സന്ദേശം;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((conn->exts & SFTP_EXT_LIMITS) == 0) {
		error("Server does not support limits@openssh.com extension");
		തിരികെ -1;
	}

	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");

	id = conn->സന്ദേശം_id++;
	എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(സന്ദേശം, id)) != 0 ||
	    (r = sshbuf_put_cstring(സന്ദേശം, "limits@openssh.com")) != 0)
		fatal_fr(r, "compose");
	send_സന്ദേശം(conn, സന്ദേശം);
	debug3("Sent message limits@openssh.com I:%u", id);

	get_സന്ദേശം(conn, സന്ദേശം);

	എങ്കിൽ ((r = sshbuf_get_u8(സന്ദേശം, &type)) != 0 ||
	    (r = sshbuf_get_u32(സന്ദേശം, &സന്ദേശം_id)) != 0)
		fatal_fr(r, "parse");

	debug3("Received limits reply T:%u I:%u", type, സന്ദേശം_id);
	എങ്കിൽ (id != സന്ദേശം_id)
		fatal("ID mismatch (%u != %u)", സന്ദേശം_id, id);
	എങ്കിൽ (type != SSH2_FXP_EXTENDED_REPLY) {
		debug_f("expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_REPLY, type);
		/* Disable the limits extension */
		conn->exts &= ~SFTP_EXT_LIMITS;
		sshbuf_free(സന്ദേശം);
		തിരികെ -1;
	}

	memset(limits, 0, വലുപ്പം(*limits));
	എങ്കിൽ ((r = sshbuf_get_u64(സന്ദേശം, &limits->packet_length)) != 0 ||
	    (r = sshbuf_get_u64(സന്ദേശം, &limits->read_length)) != 0 ||
	    (r = sshbuf_get_u64(സന്ദേശം, &limits->write_length)) != 0 ||
	    (r = sshbuf_get_u64(സന്ദേശം, &limits->open_handles)) != 0)
		fatal_fr(r, "parse limits");

	sshbuf_free(സന്ദേശം);

	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sftp_close(ഘടന sftp_conn *conn, സ്ഥിരം u_char *handle, u_int handle_len)
{
	u_int id, status;
	ഘടന sshbuf *സന്ദേശം;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");

	id = conn->സന്ദേശം_id++;
	എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, SSH2_FXP_CLOSE)) != 0 ||
	    (r = sshbuf_put_u32(സന്ദേശം, id)) != 0 ||
	    (r = sshbuf_put_string(സന്ദേശം, handle, handle_len)) != 0)
		fatal_fr(r, "parse");
	send_സന്ദേശം(conn, സന്ദേശം);
	debug3("Sent message SSH2_FXP_CLOSE I:%u", id);

	status = get_status(conn, id);
	എങ്കിൽ (status != SSH2_FX_OK)
		error("close remote: %s", fx2txt(status));

	sshbuf_free(സന്ദേശം);

	തിരികെ status == SSH2_FX_OK ? 0 : -1;
}


സ്ഥിതം പൂർണ്ണസംഖ്യ
sftp_lsreaddir(ഘടന sftp_conn *conn, സ്ഥിരം അക്ഷരം *path, പൂർണ്ണസംഖ്യ print_flag,
    SFTP_DIRENT ***dir)
{
	ഘടന sshbuf *സന്ദേശം;
	u_int എണ്ണം, id, i, expected_id, ents = 0;
	size_t handle_len;
	u_char type, *handle;
	പൂർണ്ണസംഖ്യ status = SSH2_FX_FAILURE;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (dir)
		*dir = ശൂന്യ;

	id = conn->സന്ദേശം_id++;

	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, SSH2_FXP_OPENDIR)) != 0 ||
	    (r = sshbuf_put_u32(സന്ദേശം, id)) != 0 ||
	    (r = sshbuf_put_cstring(സന്ദേശം, path)) != 0)
		fatal_fr(r, "compose OPENDIR");
	send_സന്ദേശം(conn, സന്ദേശം);

	handle = get_handle(conn, id, &handle_len,
	    "remote readdir(\"%s\")", path);
	എങ്കിൽ (handle == ശൂന്യ) {
		sshbuf_free(സന്ദേശം);
		തിരികെ -1;
	}

	എങ്കിൽ (dir) {
		ents = 0;
		*dir = xcalloc(1, വലുപ്പം(**dir));
		(*dir)[0] = ശൂന്യ;
	}

	വേണ്ടി (; !interrupted;) {
		id = expected_id = conn->സന്ദേശം_id++;

		debug3("Sending SSH2_FXP_READDIR I:%u", id);

		sshbuf_reset(സന്ദേശം);
		എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, SSH2_FXP_READDIR)) != 0 ||
		    (r = sshbuf_put_u32(സന്ദേശം, id)) != 0 ||
		    (r = sshbuf_put_string(സന്ദേശം, handle, handle_len)) != 0)
			fatal_fr(r, "compose READDIR");
		send_സന്ദേശം(conn, സന്ദേശം);

		sshbuf_reset(സന്ദേശം);

		get_സന്ദേശം(conn, സന്ദേശം);

		എങ്കിൽ ((r = sshbuf_get_u8(സന്ദേശം, &type)) != 0 ||
		    (r = sshbuf_get_u32(സന്ദേശം, &id)) != 0)
			fatal_fr(r, "parse");

		debug3("Received reply T:%u I:%u", type, id);

		എങ്കിൽ (id != expected_id)
			fatal("ID mismatch (%u != %u)", id, expected_id);

		എങ്കിൽ (type == SSH2_FXP_STATUS) {
			u_int rstatus;

			എങ്കിൽ ((r = sshbuf_get_u32(സന്ദേശം, &rstatus)) != 0)
				fatal_fr(r, "parse status");
			debug3("Received SSH2_FXP_STATUS %d", rstatus);
			എങ്കിൽ (rstatus == SSH2_FX_EOF)
				നിർത്തുക;
			error("Couldn't read directory: %s", fx2txt(rstatus));
			പോകുക out;
		} അല്ലെങ്കിൽ എങ്കിൽ (type != SSH2_FXP_NAME)
			fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
			    SSH2_FXP_NAME, type);

		എങ്കിൽ ((r = sshbuf_get_u32(സന്ദേശം, &എണ്ണം)) != 0)
			fatal_fr(r, "parse count");
		എങ്കിൽ (എണ്ണം > SSHBUF_SIZE_MAX)
			fatal_f("nonsensical number of entries");
		എങ്കിൽ (എണ്ണം == 0)
			നിർത്തുക;
		debug3("Received %d SSH2_FXP_NAME responses", എണ്ണം);
		വേണ്ടി (i = 0; i < എണ്ണം; i++) {
			അക്ഷരം *filename, *longname;
			Attrib a;

			എങ്കിൽ ((r = sshbuf_get_cstring(സന്ദേശം, &filename,
			    ശൂന്യ)) != 0 ||
			    (r = sshbuf_get_cstring(സന്ദേശം, &longname,
			    ശൂന്യ)) != 0)
				fatal_fr(r, "parse filenames");
			എങ്കിൽ ((r = decode_attrib(സന്ദേശം, &a)) != 0) {
				error_fr(r, "couldn't decode attrib");
				സ്വതന്ത്രം(filename);
				സ്വതന്ത്രം(longname);
				പോകുക out;
			}

			എങ്കിൽ (print_flag)
				mprintf("%s\n", longname);

			/*
			 * Directory entries should never contain '/'
			 * These can be used to attack recursive ops
			 * (e.g. send '../../../../etc/passwd')
			 */
			എങ്കിൽ (*filename == '\0' ||
			    strpbrk(filename, SFTP_DIRECTORY_CHARS) != ശൂന്യ) {
				error("Server sent suspect path \"%s\" "
				    "during readdir of \"%s\"", filename, path);
			} അല്ലെങ്കിൽ എങ്കിൽ (dir) {
				*dir = xreallocarray(*dir, ents + 2, വലുപ്പം(**dir));
				(*dir)[ents] = xcalloc(1, വലുപ്പം(***dir));
				(*dir)[ents]->filename = xstrdup(filename);
				(*dir)[ents]->longname = xstrdup(longname);
				memcpy(&(*dir)[ents]->a, &a, വലുപ്പം(a));
				(*dir)[++ents] = ശൂന്യ;
			}
			സ്വതന്ത്രം(filename);
			സ്വതന്ത്രം(longname);
		}
	}
	status = 0;

 out:
	sshbuf_free(സന്ദേശം);
	sftp_close(conn, handle, handle_len);
	സ്വതന്ത്രം(handle);

	എങ്കിൽ (status != 0 && dir != ശൂന്യ) {
		/* Don't return results on error */
		sftp_free_dirents(*dir);
		*dir = ശൂന്യ;
	} അല്ലെങ്കിൽ എങ്കിൽ (interrupted && dir != ശൂന്യ && *dir != ശൂന്യ) {
		/* Don't return partial matches on interrupt */
		sftp_free_dirents(*dir);
		*dir = xcalloc(1, വലുപ്പം(**dir));
		**dir = ശൂന്യ;
	}

	തിരികെ status == SSH2_FX_OK ? 0 : -1;
}

പൂർണ്ണസംഖ്യ
sftp_readdir(ഘടന sftp_conn *conn, സ്ഥിരം അക്ഷരം *path, SFTP_DIRENT ***dir)
{
	തിരികെ sftp_lsreaddir(conn, path, 0, dir);
}

ശൂന്യം sftp_free_dirents(SFTP_DIRENT **s)
{
	പൂർണ്ണസംഖ്യ i;

	എങ്കിൽ (s == ശൂന്യ)
		തിരികെ;
	വേണ്ടി (i = 0; s[i]; i++) {
		സ്വതന്ത്രം(s[i]->filename);
		സ്വതന്ത്രം(s[i]->longname);
		സ്വതന്ത്രം(s[i]);
	}
	സ്വതന്ത്രം(s);
}

പൂർണ്ണസംഖ്യ
sftp_rm(ഘടന sftp_conn *conn, സ്ഥിരം അക്ഷരം *path)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_REMOVE \"%s\"", path);

	id = conn->സന്ദേശം_id++;
	send_string_request(conn, id, SSH2_FXP_REMOVE, path, strlen(path));
	status = get_status(conn, id);
	എങ്കിൽ (status != SSH2_FX_OK)
		error("remote delete %s: %s", path, fx2txt(status));
	തിരികെ status == SSH2_FX_OK ? 0 : -1;
}

പൂർണ്ണസംഖ്യ
sftp_mkdir(ഘടന sftp_conn *conn, സ്ഥിരം അക്ഷരം *path, Attrib *a, പൂർണ്ണസംഖ്യ print_flag)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_MKDIR \"%s\"", path);

	id = conn->സന്ദേശം_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_MKDIR, path,
	    strlen(path), a);

	status = get_status(conn, id);
	എങ്കിൽ (status != SSH2_FX_OK && print_flag)
		error("remote mkdir \"%s\": %s", path, fx2txt(status));

	തിരികെ status == SSH2_FX_OK ? 0 : -1;
}

പൂർണ്ണസംഖ്യ
sftp_mkpath(ഘടന sftp_conn *conn, സ്ഥിരം അക്ഷരം *path, Attrib *a, പൂർണ്ണസംഖ്യ print_flag)
{
	അക്ഷരം *slash, *tmp_path;
	പൂർണ്ണസംഖ്യ done;

	tmp_path = xstrdup(path);
	slash = tmp_path;

	വേണ്ടി (;;) {
		slash += strspn(slash, "/");
		slash += strcspn(slash, "/");

		done = (*slash == '\0');
		*slash = '\0';

		എങ്കിൽ (!sftp_remote_is_dir(conn, tmp_path)) {
			എങ്കിൽ (sftp_mkdir(conn, tmp_path, a, print_flag) != 0) {
				സ്വതന്ത്രം(tmp_path);
				തിരികെ -1;
			}
		}

		എങ്കിൽ (done)
			നിർത്തുക;

		*slash = '/';
	}

	സ്വതന്ത്രം(tmp_path);
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sftp_rmdir(ഘടന sftp_conn *conn, സ്ഥിരം അക്ഷരം *path)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_RMDIR \"%s\"", path);

	id = conn->സന്ദേശം_id++;
	send_string_request(conn, id, SSH2_FXP_RMDIR, path,
	    strlen(path));

	status = get_status(conn, id);
	എങ്കിൽ (status != SSH2_FX_OK)
		error("remote rmdir \"%s\": %s", path, fx2txt(status));

	തിരികെ status == SSH2_FX_OK ? 0 : -1;
}

പൂർണ്ണസംഖ്യ
sftp_stat(ഘടന sftp_conn *conn, സ്ഥിരം അക്ഷരം *path, പൂർണ്ണസംഖ്യ quiet, Attrib *a)
{
	u_int id;

	debug2("Sending SSH2_FXP_STAT \"%s\"", path);

	id = conn->സന്ദേശം_id++;

	send_string_request(conn, id,
	    conn->version == 0 ? SSH2_FXP_STAT_VERSION_0 : SSH2_FXP_STAT,
	    path, strlen(path));

	തിരികെ get_decode_stat(conn, id, quiet, a);
}

പൂർണ്ണസംഖ്യ
sftp_lstat(ഘടന sftp_conn *conn, സ്ഥിരം അക്ഷരം *path, പൂർണ്ണസംഖ്യ quiet, Attrib *a)
{
	u_int id;

	എങ്കിൽ (conn->version == 0) {
		do_log2(quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_INFO,
		    "Server version does not support lstat operation");
		തിരികെ sftp_stat(conn, path, quiet, a);
	}

	id = conn->സന്ദേശം_id++;
	send_string_request(conn, id, SSH2_FXP_LSTAT, path,
	    strlen(path));

	തിരികെ get_decode_stat(conn, id, quiet, a);
}

#ifdef notyet
പൂർണ്ണസംഖ്യ
sftp_fstat(ഘടന sftp_conn *conn, സ്ഥിരം u_char *handle, u_int handle_len,
    പൂർണ്ണസംഖ്യ quiet, Attrib *a)
{
	u_int id;

	debug2("Sending SSH2_FXP_FSTAT \"%s\"");

	id = conn->സന്ദേശം_id++;
	send_string_request(conn, id, SSH2_FXP_FSTAT, handle,
	    handle_len);

	തിരികെ get_decode_stat(conn, id, quiet, a);
}
#endif

പൂർണ്ണസംഖ്യ
sftp_setstat(ഘടന sftp_conn *conn, സ്ഥിരം അക്ഷരം *path, Attrib *a)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_SETSTAT \"%s\"", path);

	id = conn->സന്ദേശം_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_SETSTAT, path,
	    strlen(path), a);

	status = get_status(conn, id);
	എങ്കിൽ (status != SSH2_FX_OK)
		error("remote setstat \"%s\": %s", path, fx2txt(status));

	തിരികെ status == SSH2_FX_OK ? 0 : -1;
}

പൂർണ്ണസംഖ്യ
sftp_fsetstat(ഘടന sftp_conn *conn, സ്ഥിരം u_char *handle, u_int handle_len,
    Attrib *a)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_FSETSTAT");

	id = conn->സന്ദേശം_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_FSETSTAT, handle,
	    handle_len, a);

	status = get_status(conn, id);
	എങ്കിൽ (status != SSH2_FX_OK)
		error("remote fsetstat: %s", fx2txt(status));

	തിരികെ status == SSH2_FX_OK ? 0 : -1;
}

/* Implements both the realpath and expand-path operations */
സ്ഥിതം അക്ഷരം *
sftp_realpath_expand(ഘടന sftp_conn *conn, സ്ഥിരം അക്ഷരം *path, പൂർണ്ണസംഖ്യ expand)
{
	ഘടന sshbuf *സന്ദേശം;
	u_int expected_id, എണ്ണം, id;
	അക്ഷരം *filename, *longname;
	Attrib a;
	u_char type;
	പൂർണ്ണസംഖ്യ r;
	സ്ഥിരം അക്ഷരം *what = "SSH2_FXP_REALPATH";

	എങ്കിൽ (expand)
		what = "expand-path@openssh.com";
	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");

	expected_id = id = conn->സന്ദേശം_id++;
	എങ്കിൽ (expand) {
		debug2("Sending SSH2_FXP_EXTENDED(expand-path@openssh.com) "
		    "\"%s\"", path);
		എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, SSH2_FXP_EXTENDED)) != 0 ||
		    (r = sshbuf_put_u32(സന്ദേശം, id)) != 0 ||
		    (r = sshbuf_put_cstring(സന്ദേശം,
		    "expand-path@openssh.com")) != 0 ||
		    (r = sshbuf_put_cstring(സന്ദേശം, path)) != 0)
			fatal_fr(r, "compose %s", what);
		send_സന്ദേശം(conn, സന്ദേശം);
	} അല്ലെങ്കിൽ {
		debug2("Sending SSH2_FXP_REALPATH \"%s\"", path);
		send_string_request(conn, id, SSH2_FXP_REALPATH,
		    path, strlen(path));
	}
	get_സന്ദേശം(conn, സന്ദേശം);
	എങ്കിൽ ((r = sshbuf_get_u8(സന്ദേശം, &type)) != 0 ||
	    (r = sshbuf_get_u32(സന്ദേശം, &id)) != 0)
		fatal_fr(r, "parse");

	എങ്കിൽ (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);

	എങ്കിൽ (type == SSH2_FXP_STATUS) {
		u_int status;
		അക്ഷരം *errmsg;

		എങ്കിൽ ((r = sshbuf_get_u32(സന്ദേശം, &status)) != 0 ||
		    (r = sshbuf_get_cstring(സന്ദേശം, &errmsg, ശൂന്യ)) != 0)
			fatal_fr(r, "parse status");
		error("%s %s: %s", expand ? "expand" : "realpath",
		    path, *errmsg == '\0' ? fx2txt(status) : errmsg);
		സ്വതന്ത്രം(errmsg);
		sshbuf_free(സന്ദേശം);
		തിരികെ ശൂന്യ;
	} അല്ലെങ്കിൽ എങ്കിൽ (type != SSH2_FXP_NAME)
		fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
		    SSH2_FXP_NAME, type);

	എങ്കിൽ ((r = sshbuf_get_u32(സന്ദേശം, &എണ്ണം)) != 0)
		fatal_fr(r, "parse count");
	എങ്കിൽ (എണ്ണം != 1)
		fatal("Got multiple names (%d) from %s", എണ്ണം, what);

	എങ്കിൽ ((r = sshbuf_get_cstring(സന്ദേശം, &filename, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_cstring(സന്ദേശം, &longname, ശൂന്യ)) != 0 ||
	    (r = decode_attrib(സന്ദേശം, &a)) != 0)
		fatal_fr(r, "parse filename/attrib");

	debug3("%s %s -> %s", what, path, filename);

	സ്വതന്ത്രം(longname);

	sshbuf_free(സന്ദേശം);

	തിരികെ(filename);
}

അക്ഷരം *
sftp_realpath(ഘടന sftp_conn *conn, സ്ഥിരം അക്ഷരം *path)
{
	തിരികെ sftp_realpath_expand(conn, path, 0);
}

പൂർണ്ണസംഖ്യ
sftp_can_expand_path(ഘടന sftp_conn *conn)
{
	തിരികെ (conn->exts & SFTP_EXT_PATH_EXPAND) != 0;
}

അക്ഷരം *
sftp_expand_path(ഘടന sftp_conn *conn, സ്ഥിരം അക്ഷരം *path)
{
	എങ്കിൽ (!sftp_can_expand_path(conn)) {
		debug3_f("no server support, fallback to realpath");
		തിരികെ sftp_realpath_expand(conn, path, 0);
	}
	തിരികെ sftp_realpath_expand(conn, path, 1);
}

പൂർണ്ണസംഖ്യ
sftp_copy(ഘടന sftp_conn *conn, സ്ഥിരം അക്ഷരം *oldpath, സ്ഥിരം അക്ഷരം *newpath)
{
	Attrib junk, attr;
	ഘടന sshbuf *സന്ദേശം;
	u_char *old_handle, *new_handle;
	u_int mode, status, id;
	size_t old_handle_len, new_handle_len;
	പൂർണ്ണസംഖ്യ r;

	/* Return if the extension is not supported */
	എങ്കിൽ ((conn->exts & SFTP_EXT_COPY_DATA) == 0) {
		error("Server does not support copy-data extension");
		തിരികെ -1;
	}

	/* Make sure the file exists, and we can copy its perms */
	എങ്കിൽ (sftp_stat(conn, oldpath, 0, &attr) != 0)
		തിരികെ -1;

	/* Do not preserve set[ug]id here, as we do not preserve ownership */
	എങ്കിൽ (attr.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		mode = attr.perm & 0777;

		എങ്കിൽ (!S_ISREG(attr.perm)) {
			error("Cannot copy non-regular file: %s", oldpath);
			തിരികെ -1;
		}
	} അല്ലെങ്കിൽ {
		/* NB: The user's umask will apply to this */
		mode = 0666;
	}

	/* Set up the new perms for the new file */
	attrib_clear(&attr);
	attr.perm = mode;
	attr.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;

	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");

	attrib_clear(&junk); /* Send empty attributes */

	/* Open the old file for reading */
	id = conn->സന്ദേശം_id++;
	എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(സന്ദേശം, id)) != 0 ||
	    (r = sshbuf_put_cstring(സന്ദേശം, oldpath)) != 0 ||
	    (r = sshbuf_put_u32(സന്ദേശം, SSH2_FXF_READ)) != 0 ||
	    (r = encode_attrib(സന്ദേശം, &junk)) != 0)
		fatal_fr(r, "buffer error");
	send_സന്ദേശം(conn, സന്ദേശം);
	debug3("Sent message SSH2_FXP_OPEN I:%u P:%s", id, oldpath);

	sshbuf_reset(സന്ദേശം);

	old_handle = get_handle(conn, id, &old_handle_len,
	    "remote open(\"%s\")", oldpath);
	എങ്കിൽ (old_handle == ശൂന്യ) {
		sshbuf_free(സന്ദേശം);
		തിരികെ -1;
	}

	/* Open the new file for writing */
	id = conn->സന്ദേശം_id++;
	എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(സന്ദേശം, id)) != 0 ||
	    (r = sshbuf_put_cstring(സന്ദേശം, newpath)) != 0 ||
	    (r = sshbuf_put_u32(സന്ദേശം, SSH2_FXF_WRITE|SSH2_FXF_CREAT|
	    SSH2_FXF_TRUNC)) != 0 ||
	    (r = encode_attrib(സന്ദേശം, &attr)) != 0)
		fatal_fr(r, "buffer error");
	send_സന്ദേശം(conn, സന്ദേശം);
	debug3("Sent message SSH2_FXP_OPEN I:%u P:%s", id, newpath);

	sshbuf_reset(സന്ദേശം);

	new_handle = get_handle(conn, id, &new_handle_len,
	    "remote open(\"%s\")", newpath);
	എങ്കിൽ (new_handle == ശൂന്യ) {
		sshbuf_free(സന്ദേശം);
		സ്വതന്ത്രം(old_handle);
		തിരികെ -1;
	}

	/* Copy the file data */
	id = conn->സന്ദേശം_id++;
	എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(സന്ദേശം, id)) != 0 ||
	    (r = sshbuf_put_cstring(സന്ദേശം, "copy-data")) != 0 ||
	    (r = sshbuf_put_string(സന്ദേശം, old_handle, old_handle_len)) != 0 ||
	    (r = sshbuf_put_u64(സന്ദേശം, 0)) != 0 ||
	    (r = sshbuf_put_u64(സന്ദേശം, 0)) != 0 ||
	    (r = sshbuf_put_string(സന്ദേശം, new_handle, new_handle_len)) != 0 ||
	    (r = sshbuf_put_u64(സന്ദേശം, 0)) != 0)
		fatal_fr(r, "buffer error");
	send_സന്ദേശം(conn, സന്ദേശം);
	debug3("Sent message copy-data \"%s\" 0 0 -> \"%s\" 0",
	       oldpath, newpath);

	status = get_status(conn, id);
	എങ്കിൽ (status != SSH2_FX_OK)
		error("Couldn't copy file \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	/* Clean up everything */
	sshbuf_free(സന്ദേശം);
	sftp_close(conn, old_handle, old_handle_len);
	sftp_close(conn, new_handle, new_handle_len);
	സ്വതന്ത്രം(old_handle);
	സ്വതന്ത്രം(new_handle);

	തിരികെ status == SSH2_FX_OK ? 0 : -1;
}

പൂർണ്ണസംഖ്യ
sftp_rename(ഘടന sftp_conn *conn, സ്ഥിരം അക്ഷരം *oldpath, സ്ഥിരം അക്ഷരം *newpath,
    പൂർണ്ണസംഖ്യ force_legacy)
{
	ഘടന sshbuf *സന്ദേശം;
	u_int status, id;
	പൂർണ്ണസംഖ്യ r, use_ext = (conn->exts & SFTP_EXT_POSIX_RENAME) && !force_legacy;

	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");

	/* Send rename request */
	id = conn->സന്ദേശം_id++;
	എങ്കിൽ (use_ext) {
		debug2("Sending SSH2_FXP_EXTENDED(posix-rename@openssh.com) "
		    "\"%s\" to \"%s\"", oldpath, newpath);
		എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, SSH2_FXP_EXTENDED)) != 0 ||
		    (r = sshbuf_put_u32(സന്ദേശം, id)) != 0 ||
		    (r = sshbuf_put_cstring(സന്ദേശം,
		    "posix-rename@openssh.com")) != 0)
			fatal_fr(r, "compose posix-rename");
	} അല്ലെങ്കിൽ {
		debug2("Sending SSH2_FXP_RENAME \"%s\" to \"%s\"",
		    oldpath, newpath);
		എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, SSH2_FXP_RENAME)) != 0 ||
		    (r = sshbuf_put_u32(സന്ദേശം, id)) != 0)
			fatal_fr(r, "compose rename");
	}
	എങ്കിൽ ((r = sshbuf_put_cstring(സന്ദേശം, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(സന്ദേശം, newpath)) != 0)
		fatal_fr(r, "compose paths");
	send_സന്ദേശം(conn, സന്ദേശം);
	debug3("Sent message %s \"%s\" -> \"%s\"",
	    use_ext ? "posix-rename@openssh.com" :
	    "SSH2_FXP_RENAME", oldpath, newpath);
	sshbuf_free(സന്ദേശം);

	status = get_status(conn, id);
	എങ്കിൽ (status != SSH2_FX_OK)
		error("remote rename \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	തിരികെ status == SSH2_FX_OK ? 0 : -1;
}

പൂർണ്ണസംഖ്യ
sftp_hardlink(ഘടന sftp_conn *conn, സ്ഥിരം അക്ഷരം *oldpath, സ്ഥിരം അക്ഷരം *newpath)
{
	ഘടന sshbuf *സന്ദേശം;
	u_int status, id;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((conn->exts & SFTP_EXT_HARDLINK) == 0) {
		error("Server does not support hardlink@openssh.com extension");
		തിരികെ -1;
	}
	debug2("Sending SSH2_FXP_EXTENDED(hardlink@openssh.com) "
	    "\"%s\" to \"%s\"", oldpath, newpath);

	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");

	/* Send link request */
	id = conn->സന്ദേശം_id++;
	എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(സന്ദേശം, id)) != 0 ||
	    (r = sshbuf_put_cstring(സന്ദേശം, "hardlink@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(സന്ദേശം, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(സന്ദേശം, newpath)) != 0)
		fatal_fr(r, "compose");
	send_സന്ദേശം(conn, സന്ദേശം);
	debug3("Sent message hardlink@openssh.com \"%s\" -> \"%s\"",
	    oldpath, newpath);
	sshbuf_free(സന്ദേശം);

	status = get_status(conn, id);
	എങ്കിൽ (status != SSH2_FX_OK)
		error("remote link \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	തിരികെ status == SSH2_FX_OK ? 0 : -1;
}

പൂർണ്ണസംഖ്യ
sftp_symlink(ഘടന sftp_conn *conn, സ്ഥിരം അക്ഷരം *oldpath, സ്ഥിരം അക്ഷരം *newpath)
{
	ഘടന sshbuf *സന്ദേശം;
	u_int status, id;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (conn->version < 3) {
		error("This server does not support the symlink operation");
		തിരികെ(SSH2_FX_OP_UNSUPPORTED);
	}
	debug2("Sending SSH2_FXP_SYMLINK \"%s\" to \"%s\"", oldpath, newpath);

	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");

	/* Send symlink request */
	id = conn->സന്ദേശം_id++;
	എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, SSH2_FXP_SYMLINK)) != 0 ||
	    (r = sshbuf_put_u32(സന്ദേശം, id)) != 0 ||
	    (r = sshbuf_put_cstring(സന്ദേശം, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(സന്ദേശം, newpath)) != 0)
		fatal_fr(r, "compose");
	send_സന്ദേശം(conn, സന്ദേശം);
	debug3("Sent message SSH2_FXP_SYMLINK \"%s\" -> \"%s\"", oldpath,
	    newpath);
	sshbuf_free(സന്ദേശം);

	status = get_status(conn, id);
	എങ്കിൽ (status != SSH2_FX_OK)
		error("remote symlink file \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	തിരികെ status == SSH2_FX_OK ? 0 : -1;
}

പൂർണ്ണസംഖ്യ
sftp_fsync(ഘടന sftp_conn *conn, u_char *handle, u_int handle_len)
{
	ഘടന sshbuf *സന്ദേശം;
	u_int status, id;
	പൂർണ്ണസംഖ്യ r;

	/* Silently return if the extension is not supported */
	എങ്കിൽ ((conn->exts & SFTP_EXT_FSYNC) == 0)
		തിരികെ -1;
	debug2("Sending SSH2_FXP_EXTENDED(fsync@openssh.com)");

	/* Send fsync request */
	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	id = conn->സന്ദേശം_id++;
	എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(സന്ദേശം, id)) != 0 ||
	    (r = sshbuf_put_cstring(സന്ദേശം, "fsync@openssh.com")) != 0 ||
	    (r = sshbuf_put_string(സന്ദേശം, handle, handle_len)) != 0)
		fatal_fr(r, "compose");
	send_സന്ദേശം(conn, സന്ദേശം);
	debug3("Sent message fsync@openssh.com I:%u", id);
	sshbuf_free(സന്ദേശം);

	status = get_status(conn, id);
	എങ്കിൽ (status != SSH2_FX_OK)
		error("remote fsync: %s", fx2txt(status));

	തിരികെ status == SSH2_FX_OK ? 0 : -1;
}

#ifdef notyet
അക്ഷരം *
sftp_readlink(ഘടന sftp_conn *conn, സ്ഥിരം അക്ഷരം *path)
{
	ഘടന sshbuf *സന്ദേശം;
	u_int expected_id, എണ്ണം, id;
	അക്ഷരം *filename, *longname;
	Attrib a;
	u_char type;
	പൂർണ്ണസംഖ്യ r;

	debug2("Sending SSH2_FXP_READLINK \"%s\"", path);

	expected_id = id = conn->സന്ദേശം_id++;
	send_string_request(conn, id, SSH2_FXP_READLINK, path, strlen(path));

	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");

	get_സന്ദേശം(conn, സന്ദേശം);
	എങ്കിൽ ((r = sshbuf_get_u8(സന്ദേശം, &type)) != 0 ||
	    (r = sshbuf_get_u32(സന്ദേശം, &id)) != 0)
		fatal_fr(r, "parse");

	എങ്കിൽ (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);

	എങ്കിൽ (type == SSH2_FXP_STATUS) {
		u_int status;

		എങ്കിൽ ((r = sshbuf_get_u32(സന്ദേശം, &status)) != 0)
			fatal_fr(r, "parse status");
		error("Couldn't readlink: %s", fx2txt(status));
		sshbuf_free(സന്ദേശം);
		തിരികെ(ശൂന്യ);
	} അല്ലെങ്കിൽ എങ്കിൽ (type != SSH2_FXP_NAME)
		fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
		    SSH2_FXP_NAME, type);

	എങ്കിൽ ((r = sshbuf_get_u32(സന്ദേശം, &എണ്ണം)) != 0)
		fatal_fr(r, "parse count");
	എങ്കിൽ (എണ്ണം != 1)
		fatal("Got multiple names (%d) from SSH_FXP_READLINK", എണ്ണം);

	എങ്കിൽ ((r = sshbuf_get_cstring(സന്ദേശം, &filename, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_cstring(സന്ദേശം, &longname, ശൂന്യ)) != 0 ||
	    (r = decode_attrib(സന്ദേശം, &a)) != 0)
		fatal_fr(r, "parse filenames/attrib");

	debug3("SSH_FXP_READLINK %s -> %s", path, filename);

	സ്വതന്ത്രം(longname);

	sshbuf_free(സന്ദേശം);

	തിരികെ filename;
}
#endif

പൂർണ്ണസംഖ്യ
sftp_statvfs(ഘടന sftp_conn *conn, സ്ഥിരം അക്ഷരം *path, ഘടന sftp_statvfs *st,
    പൂർണ്ണസംഖ്യ quiet)
{
	ഘടന sshbuf *സന്ദേശം;
	u_int id;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((conn->exts & SFTP_EXT_STATVFS) == 0) {
		error("Server does not support statvfs@openssh.com extension");
		തിരികെ -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(statvfs@openssh.com) \"%s\"", path);

	id = conn->സന്ദേശം_id++;

	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(സന്ദേശം, id)) != 0 ||
	    (r = sshbuf_put_cstring(സന്ദേശം, "statvfs@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(സന്ദേശം, path)) != 0)
		fatal_fr(r, "compose");
	send_സന്ദേശം(conn, സന്ദേശം);
	sshbuf_free(സന്ദേശം);

	തിരികെ get_decode_statvfs(conn, st, id, quiet);
}

#ifdef notyet
പൂർണ്ണസംഖ്യ
sftp_fstatvfs(ഘടന sftp_conn *conn, സ്ഥിരം u_char *handle, u_int handle_len,
    ഘടന sftp_statvfs *st, പൂർണ്ണസംഖ്യ quiet)
{
	ഘടന sshbuf *സന്ദേശം;
	u_int id;

	എങ്കിൽ ((conn->exts & SFTP_EXT_FSTATVFS) == 0) {
		error("Server does not support fstatvfs@openssh.com extension");
		തിരികെ -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(fstatvfs@openssh.com)");

	id = conn->സന്ദേശം_id++;

	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(സന്ദേശം, id)) != 0 ||
	    (r = sshbuf_put_cstring(സന്ദേശം, "fstatvfs@openssh.com")) != 0 ||
	    (r = sshbuf_put_string(സന്ദേശം, handle, handle_len)) != 0)
		fatal_fr(r, "compose");
	send_സന്ദേശം(conn, സന്ദേശം);
	sshbuf_free(സന്ദേശം);

	തിരികെ get_decode_statvfs(conn, st, id, quiet);
}
#endif

പൂർണ്ണസംഖ്യ
sftp_lsetstat(ഘടന sftp_conn *conn, സ്ഥിരം അക്ഷരം *path, Attrib *a)
{
	ഘടന sshbuf *സന്ദേശം;
	u_int status, id;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((conn->exts & SFTP_EXT_LSETSTAT) == 0) {
		error("Server does not support lsetstat@openssh.com extension");
		തിരികെ -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(lsetstat@openssh.com) \"%s\"", path);

	id = conn->സന്ദേശം_id++;
	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(സന്ദേശം, id)) != 0 ||
	    (r = sshbuf_put_cstring(സന്ദേശം, "lsetstat@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(സന്ദേശം, path)) != 0 ||
	    (r = encode_attrib(സന്ദേശം, a)) != 0)
		fatal_fr(r, "compose");
	send_സന്ദേശം(conn, സന്ദേശം);
	sshbuf_free(സന്ദേശം);

	status = get_status(conn, id);
	എങ്കിൽ (status != SSH2_FX_OK)
		error("remote lsetstat \"%s\": %s", path, fx2txt(status));

	തിരികെ status == SSH2_FX_OK ? 0 : -1;
}

സ്ഥിതം ശൂന്യം
send_read_request(ഘടന sftp_conn *conn, u_int id, uint64_t offset,
    u_int len, സ്ഥിരം u_char *handle, u_int handle_len)
{
	ഘടന sshbuf *സന്ദേശം;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, SSH2_FXP_READ)) != 0 ||
	    (r = sshbuf_put_u32(സന്ദേശം, id)) != 0 ||
	    (r = sshbuf_put_string(സന്ദേശം, handle, handle_len)) != 0 ||
	    (r = sshbuf_put_u64(സന്ദേശം, offset)) != 0 ||
	    (r = sshbuf_put_u32(സന്ദേശം, len)) != 0)
		fatal_fr(r, "compose");
	send_സന്ദേശം(conn, സന്ദേശം);
	sshbuf_free(സന്ദേശം);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
send_open(ഘടന sftp_conn *conn, സ്ഥിരം അക്ഷരം *path, സ്ഥിരം അക്ഷരം *tag,
    u_int openmode, Attrib *a, u_char **handlep, size_t *handle_lenp)
{
	Attrib junk;
	u_char *handle;
	size_t handle_len;
	ഘടന sshbuf *സന്ദേശം;
	പൂർണ്ണസംഖ്യ r;
	u_int id;

	debug2("Sending SSH2_FXP_OPEN \"%s\"", path);

	*handlep = ശൂന്യ;
	*handle_lenp = 0;

	എങ്കിൽ (a == ശൂന്യ) {
		attrib_clear(&junk); /* Send empty attributes */
		a = &junk;
	}
	/* Send open request */
	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	id = conn->സന്ദേശം_id++;
	എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(സന്ദേശം, id)) != 0 ||
	    (r = sshbuf_put_cstring(സന്ദേശം, path)) != 0 ||
	    (r = sshbuf_put_u32(സന്ദേശം, openmode)) != 0 ||
	    (r = encode_attrib(സന്ദേശം, a)) != 0)
		fatal_fr(r, "compose %s open", tag);
	send_സന്ദേശം(conn, സന്ദേശം);
	sshbuf_free(സന്ദേശം);
	debug3("Sent %s message SSH2_FXP_OPEN I:%u P:%s M:0x%04x",
	    tag, id, path, openmode);
	എങ്കിൽ ((handle = get_handle(conn, id, &handle_len,
	    "%s open \"%s\"", tag, path)) == ശൂന്യ)
		തിരികെ -1;
	/* success */
	*handlep = handle;
	*handle_lenp = handle_len;
	തിരികെ 0;
}

സ്ഥിതം സ്ഥിരം അക്ഷരം *
progress_meter_path(സ്ഥിരം അക്ഷരം *path)
{
	സ്ഥിരം അക്ഷരം *progresspath;

	എങ്കിൽ ((progresspath = strrchr(path, '/')) == ശൂന്യ)
		തിരികെ path;
	progresspath++;
	എങ്കിൽ (*progresspath == '\0')
		തിരികെ path;
	തിരികെ progresspath;
}

പൂർണ്ണസംഖ്യ
sftp_download(ഘടന sftp_conn *conn, സ്ഥിരം അക്ഷരം *remote_path,
    സ്ഥിരം അക്ഷരം *local_path, Attrib *a, പൂർണ്ണസംഖ്യ preserve_flag, പൂർണ്ണസംഖ്യ resume_flag,
    പൂർണ്ണസംഖ്യ fsync_flag, പൂർണ്ണസംഖ്യ inplace_flag)
{
	ഘടന sshbuf *സന്ദേശം;
	u_char *handle;
	പൂർണ്ണസംഖ്യ local_fd = -1, write_error, seen_zerolen = 0;
	പൂർണ്ണസംഖ്യ read_error, write_errno, lmodified = 0, reordered = 0, r;
	uint64_t offset = 0, size, highwater = 0, maxack = 0;
	u_int mode, id, buflen, അക്കം_req, max_req, status = SSH2_FX_OK;
	off_t progress_counter;
	size_t handle_len;
	ഘടന stat st;
	ഘടന requests requests;
	ഘടന request *req;
	u_char type;
	Attrib attr;

	debug2_f("download remote \"%s\" to local \"%s\"",
	    remote_path, local_path);

	TAILQ_INIT(&requests);

	എങ്കിൽ (a == ശൂന്യ) {
		എങ്കിൽ (sftp_stat(conn, remote_path, 0, &attr) != 0)
			തിരികെ -1;
		a = &attr;
	}

	/* Do not preserve set[ug]id here, as we do not preserve ownership */
	എങ്കിൽ (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS)
		mode = a->perm & 0777;
	അല്ലെങ്കിൽ
		mode = 0666;

	എങ്കിൽ ((a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) &&
	    (!S_ISREG(a->perm))) {
		error("download %s: not a regular file", remote_path);
		തിരികെ(-1);
	}

	എങ്കിൽ (a->flags & SSH2_FILEXFER_ATTR_SIZE)
		size = a->size;
	അല്ലെങ്കിൽ
		size = 0;

	buflen = conn->download_buflen;

	/* Send open request */
	എങ്കിൽ (send_open(conn, remote_path, "remote", SSH2_FXF_READ, ശൂന്യ,
	    &handle, &handle_len) != 0)
		തിരികെ -1;

	local_fd = open(local_path, O_WRONLY | O_CREAT |
	((resume_flag || inplace_flag) ? 0 : O_TRUNC), mode | S_IWUSR);
	എങ്കിൽ (local_fd == -1) {
		error("open local \"%s\": %s", local_path, strerror(errno));
		പോകുക fail;
	}
	എങ്കിൽ (resume_flag) {
		എങ്കിൽ (fstat(local_fd, &st) == -1) {
			error("stat local \"%s\": %s",
			    local_path, strerror(errno));
			പോകുക fail;
		}
		എങ്കിൽ (st.st_size < 0) {
			error("\"%s\" has negative size", local_path);
			പോകുക fail;
		}
		എങ്കിൽ ((uint64_t)st.st_size > size) {
			error("Unable to resume download of \"%s\": "
			    "local file is larger than remote", local_path);
 fail:
			sftp_close(conn, handle, handle_len);
			സ്വതന്ത്രം(handle);
			എങ്കിൽ (local_fd != -1)
				close(local_fd);
			തിരികെ -1;
		}
		offset = highwater = maxack = st.st_size;
	}

	/* Read from remote and write to local */
	write_error = read_error = write_errno = അക്കം_req = 0;
	max_req = 1;
	progress_counter = offset;

	എങ്കിൽ (showprogress && size != 0) {
		start_progress_meter(progress_meter_path(remote_path),
		    size, &progress_counter);
	}

	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");

	ആകുമ്പോൾ (അക്കം_req > 0 || max_req > 0) {
		u_char *data;
		size_t len;

		/*
		 * Simulate EOF on interrupt: stop sending new requests and
		 * allow outstanding requests to drain gracefully
		 */
		എങ്കിൽ (interrupted) {
			എങ്കിൽ (അക്കം_req == 0) /* If we haven't started yet... */
				നിർത്തുക;
			max_req = 0;
		}

		/* Send some more requests */
		ആകുമ്പോൾ (അക്കം_req < max_req) {
			debug3("Request range %llu -> %llu (%d/%d)",
			    (unsigned long long)offset,
			    (unsigned long long)offset + buflen - 1,
			    അക്കം_req, max_req);
			req = request_enqueue(&requests, conn->സന്ദേശം_id++,
			    buflen, offset);
			offset += buflen;
			അക്കം_req++;
			send_read_request(conn, req->id, req->offset,
			    req->len, handle, handle_len);
		}

		sshbuf_reset(സന്ദേശം);
		get_സന്ദേശം(conn, സന്ദേശം);
		എങ്കിൽ ((r = sshbuf_get_u8(സന്ദേശം, &type)) != 0 ||
		    (r = sshbuf_get_u32(സന്ദേശം, &id)) != 0)
			fatal_fr(r, "parse");
		debug3("Received reply T:%u I:%u R:%d", type, id, max_req);

		/* Find the request in our queue */
		എങ്കിൽ ((req = request_find(&requests, id)) == ശൂന്യ)
			fatal("Unexpected reply %u", id);

		തിരഞ്ഞെടുപ്പ് (type) {
		അവസ്ഥ SSH2_FXP_STATUS:
			എങ്കിൽ ((r = sshbuf_get_u32(സന്ദേശം, &status)) != 0)
				fatal_fr(r, "parse status");
			എങ്കിൽ (status != SSH2_FX_EOF)
				read_error = 1;
			max_req = 0;
			TAILQ_REMOVE(&requests, req, tq);
			സ്വതന്ത്രം(req);
			അക്കം_req--;
			നിർത്തുക;
		അവസ്ഥ SSH2_FXP_DATA:
			എങ്കിൽ ((r = sshbuf_get_string(സന്ദേശം, &data, &len)) != 0)
				fatal_fr(r, "parse data");
			debug3("Received data %llu -> %llu",
			    (unsigned long long)req->offset,
			    (unsigned long long)req->offset + len - 1);
			എങ്കിൽ (len > req->len)
				fatal("Received more data than asked for "
				    "%zu > %zu", len, req->len);
			എങ്കിൽ (len == 0) {
				എങ്കിൽ (seen_zerolen)
					fatal_f("server sent zero data length");
				seen_zerolen = 1;
			}
			lmodified = 1;
			എങ്കിൽ ((lseek(local_fd, req->offset, SEEK_SET) == -1 ||
			    atomicio(vwrite, local_fd, data, len) != len) &&
			    !write_error) {
				write_errno = errno;
				write_error = 1;
				max_req = 0;
			} അല്ലെങ്കിൽ {
				/*
				 * Track both the highest offset acknowledged
				 * and the highest *contiguous* offset
				 * acknowledged.
				 * We'll need the latter for ftruncate()ing
				 * interrupted transfers.
				 */
				എങ്കിൽ (maxack < req->offset + len)
					maxack = req->offset + len;
				എങ്കിൽ (!reordered && req->offset <= highwater)
					highwater = maxack;
				അല്ലെങ്കിൽ എങ്കിൽ (!reordered && req->offset > highwater)
					reordered = 1;
			}
			progress_counter += len;
			സ്വതന്ത്രം(data);

			എങ്കിൽ (len == req->len) {
				TAILQ_REMOVE(&requests, req, tq);
				സ്വതന്ത്രം(req);
				അക്കം_req--;
			} അല്ലെങ്കിൽ {
				/* Resend the request for the missing data */
				debug3("Short data block, re-requesting "
				    "%llu -> %llu (%2d)",
				    (unsigned long long)req->offset + len,
				    (unsigned long long)req->offset +
				    req->len - 1, അക്കം_req);
				req->id = conn->സന്ദേശം_id++;
				req->len -= len;
				req->offset += len;
				send_read_request(conn, req->id,
				    req->offset, req->len, handle, handle_len);
				/* Reduce the request size */
				എങ്കിൽ (len < buflen)
					buflen = MAXIMUM(MIN_READ_SIZE, len);
			}
			എങ്കിൽ (max_req > 0) { /* max_req = 0 iff EOF received */
				എങ്കിൽ (size > 0 && offset > size) {
					/* Only one request at a time
					 * after the expected EOF */
					debug3("Finish at %llu (%2d)",
					    (unsigned long long)offset,
					    അക്കം_req);
					max_req = 1;
				} അല്ലെങ്കിൽ എങ്കിൽ (max_req < conn->അക്കം_requests) {
					++max_req;
				}
			}
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			fatal("Expected SSH2_FXP_DATA(%u) packet, got %u",
			    SSH2_FXP_DATA, type);
		}
	}

	എങ്കിൽ (showprogress && size)
		stop_progress_meter();

	/* Sanity check */
	എങ്കിൽ (TAILQ_FIRST(&requests) != ശൂന്യ)
		fatal("Transfer complete, but requests still in queue");

	എങ്കിൽ (!read_error && !write_error && !interrupted) {
		/* we got everything */
		highwater = maxack;
	}

	/*
	 * Truncate at highest contiguous point to avoid holes on interrupt,
	 * or unconditionally if writing in place.
	 */
	എങ്കിൽ (inplace_flag || read_error || write_error || interrupted) {
		എങ്കിൽ (reordered && resume_flag &&
		    (read_error || write_error || interrupted)) {
			error("Unable to resume download of \"%s\": "
			    "server reordered requests", local_path);
		}
		debug("truncating at %llu", (unsigned long long)highwater);
		എങ്കിൽ (ftruncate(local_fd, highwater) == -1)
			error("local ftruncate \"%s\": %s", local_path,
			    strerror(errno));
	}
	എങ്കിൽ (read_error) {
		error("read remote \"%s\" : %s", remote_path, fx2txt(status));
		status = -1;
		sftp_close(conn, handle, handle_len);
	} അല്ലെങ്കിൽ എങ്കിൽ (write_error) {
		error("write local \"%s\": %s", local_path,
		    strerror(write_errno));
		status = SSH2_FX_FAILURE;
		sftp_close(conn, handle, handle_len);
	} അല്ലെങ്കിൽ {
		എങ്കിൽ (sftp_close(conn, handle, handle_len) != 0 || interrupted)
			status = SSH2_FX_FAILURE;
		അല്ലെങ്കിൽ
			status = SSH2_FX_OK;
		/* Override umask and utimes if asked */
#ifdef HAVE_FCHMOD
		എങ്കിൽ (preserve_flag && fchmod(local_fd, mode) == -1)
#അല്ലെങ്കിൽ
		എങ്കിൽ (preserve_flag && chmod(local_path, mode) == -1)
#endif /* HAVE_FCHMOD */
			error("local chmod \"%s\": %s", local_path,
			    strerror(errno));
		എങ്കിൽ (preserve_flag &&
		    (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME)) {
			ഘടന timeval tv[2];
			tv[0].tv_sec = a->atime;
			tv[1].tv_sec = a->mtime;
			tv[0].tv_usec = tv[1].tv_usec = 0;
			എങ്കിൽ (utimes(local_path, tv) == -1)
				error("local set times \"%s\": %s",
				    local_path, strerror(errno));
		}
		എങ്കിൽ (resume_flag && !lmodified)
			logit("File \"%s\" was not modified", local_path);
		അല്ലെങ്കിൽ എങ്കിൽ (fsync_flag) {
			debug("syncing \"%s\"", local_path);
			എങ്കിൽ (fsync(local_fd) == -1)
				error("local sync \"%s\": %s",
				    local_path, strerror(errno));
		}
	}
	close(local_fd);
	sshbuf_free(സന്ദേശം);
	സ്വതന്ത്രം(handle);

	തിരികെ status == SSH2_FX_OK ? 0 : -1;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
download_dir_internal(ഘടന sftp_conn *conn, സ്ഥിരം അക്ഷരം *src, സ്ഥിരം അക്ഷരം *dst,
    പൂർണ്ണസംഖ്യ depth, Attrib *dirattrib, പൂർണ്ണസംഖ്യ preserve_flag, പൂർണ്ണസംഖ്യ print_flag,
    പൂർണ്ണസംഖ്യ resume_flag, പൂർണ്ണസംഖ്യ fsync_flag, പൂർണ്ണസംഖ്യ follow_link_flag, പൂർണ്ണസംഖ്യ inplace_flag)
{
	പൂർണ്ണസംഖ്യ i, ret = 0;
	SFTP_DIRENT **dir_entries;
	അക്ഷരം *filename, *new_src = ശൂന്യ, *new_dst = ശൂന്യ;
	mode_t mode = 0777, tmpmode = mode;
	Attrib *a, ldirattrib, lsym;

	എങ്കിൽ (depth >= MAX_DIR_DEPTH) {
		error("Maximum directory depth exceeded: %d levels", depth);
		തിരികെ -1;
	}

	debug2_f("download dir remote \"%s\" to local \"%s\"", src, dst);

	എങ്കിൽ (dirattrib == ശൂന്യ) {
		എങ്കിൽ (sftp_stat(conn, src, 1, &ldirattrib) != 0) {
			error("stat remote \"%s\" directory failed", src);
			തിരികെ -1;
		}
		dirattrib = &ldirattrib;
	}
	എങ്കിൽ (!S_ISDIR(dirattrib->perm)) {
		error("\"%s\" is not a directory", src);
		തിരികെ -1;
	}
	എങ്കിൽ (print_flag && print_flag != SFTP_PROGRESS_ONLY)
		mprintf("Retrieving %s\n", src);

	എങ്കിൽ (dirattrib->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		mode = dirattrib->perm & 01777;
		tmpmode = mode | (S_IWUSR|S_IXUSR);
	} അല്ലെങ്കിൽ {
		debug("download remote \"%s\": server "
		    "did not send permissions", dst);
	}

	എങ്കിൽ (mkdir(dst, tmpmode) == -1 && errno != EEXIST) {
		error("mkdir %s: %s", dst, strerror(errno));
		തിരികെ -1;
	}

	എങ്കിൽ (sftp_readdir(conn, src, &dir_entries) == -1) {
		error("remote readdir \"%s\" failed", src);
		തിരികെ -1;
	}

	വേണ്ടി (i = 0; dir_entries[i] != ശൂന്യ && !interrupted; i++) {
		സ്വതന്ത്രം(new_dst);
		സ്വതന്ത്രം(new_src);

		filename = dir_entries[i]->filename;
		new_dst = sftp_path_append(dst, filename);
		new_src = sftp_path_append(src, filename);

		a = &dir_entries[i]->a;
		എങ്കിൽ (S_ISLNK(a->perm)) {
			എങ്കിൽ (!follow_link_flag) {
				logit("download \"%s\": not a regular file",
				    new_src);
				തുടരുക;
			}
			/* Replace the stat contents with the symlink target */
			എങ്കിൽ (sftp_stat(conn, new_src, 1, &lsym) != 0) {
				logit("remote stat \"%s\" failed", new_src);
				ret = -1;
				തുടരുക;
			}
			a = &lsym;
		}

		എങ്കിൽ (S_ISDIR(a->perm)) {
			എങ്കിൽ (strcmp(filename, ".") == 0 ||
			    strcmp(filename, "..") == 0)
				തുടരുക;
			എങ്കിൽ (download_dir_internal(conn, new_src, new_dst,
			    depth + 1, a, preserve_flag,
			    print_flag, resume_flag,
			    fsync_flag, follow_link_flag, inplace_flag) == -1)
				ret = -1;
		} അല്ലെങ്കിൽ എങ്കിൽ (S_ISREG(a->perm)) {
			എങ്കിൽ (sftp_download(conn, new_src, new_dst, a,
			    preserve_flag, resume_flag, fsync_flag,
			    inplace_flag) == -1) {
				error("Download of file %s to %s failed",
				    new_src, new_dst);
				ret = -1;
			}
		} അല്ലെങ്കിൽ
			logit("download \"%s\": not a regular file", new_src);

	}
	സ്വതന്ത്രം(new_dst);
	സ്വതന്ത്രം(new_src);

	എങ്കിൽ (preserve_flag) {
		എങ്കിൽ (dirattrib->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
			ഘടന timeval tv[2];
			tv[0].tv_sec = dirattrib->atime;
			tv[1].tv_sec = dirattrib->mtime;
			tv[0].tv_usec = tv[1].tv_usec = 0;
			എങ്കിൽ (utimes(dst, tv) == -1)
				error("local set times on \"%s\": %s",
				    dst, strerror(errno));
		} അല്ലെങ്കിൽ
			debug("Server did not send times for directory "
			    "\"%s\"", dst);
	}

	എങ്കിൽ (mode != tmpmode && chmod(dst, mode) == -1)
		error("local chmod directory \"%s\": %s", dst,
		    strerror(errno));

	sftp_free_dirents(dir_entries);

	തിരികെ ret;
}

പൂർണ്ണസംഖ്യ
sftp_download_dir(ഘടന sftp_conn *conn, സ്ഥിരം അക്ഷരം *src, സ്ഥിരം അക്ഷരം *dst,
    Attrib *dirattrib, പൂർണ്ണസംഖ്യ preserve_flag, പൂർണ്ണസംഖ്യ print_flag, പൂർണ്ണസംഖ്യ resume_flag,
    പൂർണ്ണസംഖ്യ fsync_flag, പൂർണ്ണസംഖ്യ follow_link_flag, പൂർണ്ണസംഖ്യ inplace_flag)
{
	അക്ഷരം *src_canon;
	പൂർണ്ണസംഖ്യ ret;

	എങ്കിൽ ((src_canon = sftp_realpath(conn, src)) == ശൂന്യ) {
		error("download \"%s\": path canonicalization failed", src);
		തിരികെ -1;
	}

	ret = download_dir_internal(conn, src_canon, dst, 0,
	    dirattrib, preserve_flag, print_flag, resume_flag, fsync_flag,
	    follow_link_flag, inplace_flag);
	സ്വതന്ത്രം(src_canon);
	തിരികെ ret;
}

പൂർണ്ണസംഖ്യ
sftp_upload(ഘടന sftp_conn *conn, സ്ഥിരം അക്ഷരം *local_path,
    സ്ഥിരം അക്ഷരം *remote_path, പൂർണ്ണസംഖ്യ preserve_flag, പൂർണ്ണസംഖ്യ resume,
    പൂർണ്ണസംഖ്യ fsync_flag, പൂർണ്ണസംഖ്യ inplace_flag)
{
	പൂർണ്ണസംഖ്യ r, local_fd;
	u_int openmode, id, status = SSH2_FX_OK, status2, reordered = 0;
	off_t offset, progress_counter;
	u_char type, *handle, *data;
	ഘടന sshbuf *സന്ദേശം;
	ഘടന stat sb;
	Attrib a, t, c;
	uint32_t startid, ackid;
	uint64_t highwater = 0, maxack = 0;
	ഘടന request *ack = ശൂന്യ;
	ഘടന requests acks;
	size_t handle_len;

	debug2_f("upload local \"%s\" to remote \"%s\"",
	    local_path, remote_path);

	TAILQ_INIT(&acks);

	എങ്കിൽ ((local_fd = open(local_path, O_RDONLY)) == -1) {
		error("open local \"%s\": %s", local_path, strerror(errno));
		തിരികെ(-1);
	}
	എങ്കിൽ (fstat(local_fd, &sb) == -1) {
		error("fstat local \"%s\": %s", local_path, strerror(errno));
		close(local_fd);
		തിരികെ(-1);
	}
	എങ്കിൽ (!S_ISREG(sb.st_mode)) {
		error("local \"%s\" is not a regular file", local_path);
		close(local_fd);
		തിരികെ(-1);
	}
	stat_to_attrib(&sb, &a);

	a.flags &= ~SSH2_FILEXFER_ATTR_SIZE;
	a.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a.perm &= 0777;
	എങ്കിൽ (!preserve_flag)
		a.flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;

	എങ്കിൽ (resume) {
		/* Get remote file size if it exists */
		എങ്കിൽ (sftp_stat(conn, remote_path, 0, &c) != 0) {
			close(local_fd);
			തിരികെ -1;
		}

		എങ്കിൽ ((off_t)c.size >= sb.st_size) {
			error("resume \"%s\": destination file "
			    "same size or larger", local_path);
			close(local_fd);
			തിരികെ -1;
		}

		എങ്കിൽ (lseek(local_fd, (off_t)c.size, SEEK_SET) == -1) {
			close(local_fd);
			തിരികെ -1;
		}
		highwater = c.size;
	}

	openmode = SSH2_FXF_WRITE|SSH2_FXF_CREAT;
	എങ്കിൽ (resume)
		openmode |= SSH2_FXF_APPEND;
	അല്ലെങ്കിൽ എങ്കിൽ (!inplace_flag)
		openmode |= SSH2_FXF_TRUNC;

	/* Send open request */
	എങ്കിൽ (send_open(conn, remote_path, "dest", openmode, &a,
	    &handle, &handle_len) != 0) {
		close(local_fd);
		തിരികെ -1;
	}

	id = conn->സന്ദേശം_id;
	startid = ackid = id + 1;
	data = xmalloc(conn->upload_buflen);

	/* Read from local and write to remote */
	offset = progress_counter = (resume ? c.size : 0);
	എങ്കിൽ (showprogress) {
		start_progress_meter(progress_meter_path(local_path),
		    sb.st_size, &progress_counter);
	}

	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	വേണ്ടി (;;) {
		പൂർണ്ണസംഖ്യ len;

		/*
		 * Can't use atomicio here because it returns 0 on EOF,
		 * thus losing the last block of the file.
		 * Simulate an EOF on interrupt, allowing ACKs from the
		 * server to drain.
		 */
		എങ്കിൽ (interrupted || status != SSH2_FX_OK)
			len = 0;
		അല്ലെങ്കിൽ ചെയ്യുക
			len = പഠ(local_fd, data, conn->upload_buflen);
		ആകുമ്പോൾ ((len == -1) &&
		    (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK));

		എങ്കിൽ (len == -1) {
			fatal("read local \"%s\": %s",
			    local_path, strerror(errno));
		} അല്ലെങ്കിൽ എങ്കിൽ (len != 0) {
			ack = request_enqueue(&acks, ++id, len, offset);
			sshbuf_reset(സന്ദേശം);
			എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, SSH2_FXP_WRITE)) != 0 ||
			    (r = sshbuf_put_u32(സന്ദേശം, ack->id)) != 0 ||
			    (r = sshbuf_put_string(സന്ദേശം, handle,
			    handle_len)) != 0 ||
			    (r = sshbuf_put_u64(സന്ദേശം, offset)) != 0 ||
			    (r = sshbuf_put_string(സന്ദേശം, data, len)) != 0)
				fatal_fr(r, "compose");
			send_സന്ദേശം(conn, സന്ദേശം);
			debug3("Sent message SSH2_FXP_WRITE I:%u O:%llu S:%u",
			    id, (unsigned long long)offset, len);
		} അല്ലെങ്കിൽ എങ്കിൽ (TAILQ_FIRST(&acks) == ശൂന്യ)
			നിർത്തുക;

		എങ്കിൽ (ack == ശൂന്യ)
			fatal("Unexpected ACK %u", id);

		എങ്കിൽ (id == startid || len == 0 ||
		    id - ackid >= conn->അക്കം_requests) {
			u_int rid;

			sshbuf_reset(സന്ദേശം);
			get_സന്ദേശം(conn, സന്ദേശം);
			എങ്കിൽ ((r = sshbuf_get_u8(സന്ദേശം, &type)) != 0 ||
			    (r = sshbuf_get_u32(സന്ദേശം, &rid)) != 0)
				fatal_fr(r, "parse");

			എങ്കിൽ (type != SSH2_FXP_STATUS)
				fatal("Expected SSH2_FXP_STATUS(%d) packet, "
				    "got %d", SSH2_FXP_STATUS, type);

			എങ്കിൽ ((r = sshbuf_get_u32(സന്ദേശം, &status2)) != 0)
				fatal_fr(r, "parse status");
			debug3("SSH2_FXP_STATUS %u", status2);
			എങ്കിൽ (status2 != SSH2_FX_OK)
				status = status2; /* remember errors */

			/* Find the request in our queue */
			എങ്കിൽ ((ack = request_find(&acks, rid)) == ശൂന്യ)
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
			എങ്കിൽ (maxack < ack->offset + ack->len)
				maxack = ack->offset + ack->len;
			എങ്കിൽ (!reordered && ack->offset <= highwater)
				highwater = maxack;
			അല്ലെങ്കിൽ എങ്കിൽ (!reordered && ack->offset > highwater) {
				debug3_f("server reordered ACKs");
				reordered = 1;
			}
			സ്വതന്ത്രം(ack);
		}
		offset += len;
		എങ്കിൽ (offset < 0)
			fatal_f("offset < 0");
	}
	sshbuf_free(സന്ദേശം);

	എങ്കിൽ (showprogress)
		stop_progress_meter();
	സ്വതന്ത്രം(data);

	എങ്കിൽ (status == SSH2_FX_OK && !interrupted) {
		/* we got everything */
		highwater = maxack;
	}
	എങ്കിൽ (status != SSH2_FX_OK) {
		error("write remote \"%s\": %s", remote_path, fx2txt(status));
		status = SSH2_FX_FAILURE;
	}

	എങ്കിൽ (inplace_flag || (resume && (status != SSH2_FX_OK || interrupted))) {
		debug("truncating at %llu", (unsigned long long)highwater);
		attrib_clear(&t);
		t.flags = SSH2_FILEXFER_ATTR_SIZE;
		t.size = highwater;
		sftp_fsetstat(conn, handle, handle_len, &t);
	}

	എങ്കിൽ (close(local_fd) == -1) {
		error("close local \"%s\": %s", local_path, strerror(errno));
		status = SSH2_FX_FAILURE;
	}

	/* Override umask and utimes if asked */
	എങ്കിൽ (preserve_flag)
		sftp_fsetstat(conn, handle, handle_len, &a);

	എങ്കിൽ (fsync_flag)
		(ശൂന്യം)sftp_fsync(conn, handle, handle_len);

	എങ്കിൽ (sftp_close(conn, handle, handle_len) != 0)
		status = SSH2_FX_FAILURE;

	സ്വതന്ത്രം(handle);

	തിരികെ status == SSH2_FX_OK ? 0 : -1;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
upload_dir_internal(ഘടന sftp_conn *conn, സ്ഥിരം അക്ഷരം *src, സ്ഥിരം അക്ഷരം *dst,
    പൂർണ്ണസംഖ്യ depth, പൂർണ്ണസംഖ്യ preserve_flag, പൂർണ്ണസംഖ്യ print_flag, പൂർണ്ണസംഖ്യ resume, പൂർണ്ണസംഖ്യ fsync_flag,
    പൂർണ്ണസംഖ്യ follow_link_flag, പൂർണ്ണസംഖ്യ inplace_flag)
{
	പൂർണ്ണസംഖ്യ created = 0, ret = 0;
	DIR *dirp;
	ഘടന dirent *dp;
	അക്ഷരം *filename, *new_src = ശൂന്യ, *new_dst = ശൂന്യ;
	ഘടന stat sb;
	Attrib a, dirattrib;
	uint32_t saved_perm;

	debug2_f("upload local dir \"%s\" to remote \"%s\"", src, dst);

	എങ്കിൽ (depth >= MAX_DIR_DEPTH) {
		error("Maximum directory depth exceeded: %d levels", depth);
		തിരികെ -1;
	}

	എങ്കിൽ (stat(src, &sb) == -1) {
		error("stat local \"%s\": %s", src, strerror(errno));
		തിരികെ -1;
	}
	എങ്കിൽ (!S_ISDIR(sb.st_mode)) {
		error("\"%s\" is not a directory", src);
		തിരികെ -1;
	}
	എങ്കിൽ (print_flag && print_flag != SFTP_PROGRESS_ONLY)
		mprintf("Entering %s\n", src);

	stat_to_attrib(&sb, &a);
	a.flags &= ~SSH2_FILEXFER_ATTR_SIZE;
	a.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a.perm &= 01777;
	എങ്കിൽ (!preserve_flag)
		a.flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;

	/*
	 * sftp lacks a portable status value to match errno EEXIST,
	 * so if we get a failure back then we must check whether
	 * the path already existed and is a directory.  Ensure we can
	 * write to the directory we create for the duration of the transfer.
	 */
	saved_perm = a.perm;
	a.perm |= (S_IWUSR|S_IXUSR);
	എങ്കിൽ (sftp_mkdir(conn, dst, &a, 0) == 0)
		created = 1;
	അല്ലെങ്കിൽ {
		എങ്കിൽ (sftp_stat(conn, dst, 0, &dirattrib) != 0)
			തിരികെ -1;
		എങ്കിൽ (!S_ISDIR(dirattrib.perm)) {
			error("\"%s\" exists but is not a directory", dst);
			തിരികെ -1;
		}
	}
	a.perm = saved_perm;

	എങ്കിൽ ((dirp = opendir(src)) == ശൂന്യ) {
		error("local opendir \"%s\": %s", src, strerror(errno));
		തിരികെ -1;
	}

	ആകുമ്പോൾ (((dp = readdir(dirp)) != ശൂന്യ) && !interrupted) {
		എങ്കിൽ (dp->d_ino == 0)
			തുടരുക;
		സ്വതന്ത്രം(new_dst);
		സ്വതന്ത്രം(new_src);
		filename = dp->d_name;
		new_dst = sftp_path_append(dst, filename);
		new_src = sftp_path_append(src, filename);

		എങ്കിൽ (strcmp(filename, ".") == 0 || strcmp(filename, "..") == 0)
			തുടരുക;
		എങ്കിൽ (lstat(new_src, &sb) == -1) {
			logit("local lstat \"%s\": %s", filename,
			    strerror(errno));
			ret = -1;
			തുടരുക;
		}
		എങ്കിൽ (S_ISLNK(sb.st_mode)) {
			എങ്കിൽ (!follow_link_flag) {
				logit("%s: not a regular file", filename);
				തുടരുക;
			}
			/* Replace the stat contents with the symlink target */
			എങ്കിൽ (stat(new_src, &sb) == -1) {
				logit("local stat \"%s\": %s", filename,
				    strerror(errno));
				ret = -1;
				തുടരുക;
			}
		}
		എങ്കിൽ (S_ISDIR(sb.st_mode)) {
			എങ്കിൽ (upload_dir_internal(conn, new_src, new_dst,
			    depth + 1, preserve_flag, print_flag, resume,
			    fsync_flag, follow_link_flag, inplace_flag) == -1)
				ret = -1;
		} അല്ലെങ്കിൽ എങ്കിൽ (S_ISREG(sb.st_mode)) {
			എങ്കിൽ (sftp_upload(conn, new_src, new_dst,
			    preserve_flag, resume, fsync_flag,
			    inplace_flag) == -1) {
				error("upload \"%s\" to \"%s\" failed",
				    new_src, new_dst);
				ret = -1;
			}
		} അല്ലെങ്കിൽ
			logit("%s: not a regular file", filename);
	}
	സ്വതന്ത്രം(new_dst);
	സ്വതന്ത്രം(new_src);

	എങ്കിൽ (created || preserve_flag)
		sftp_setstat(conn, dst, &a);

	(ശൂന്യം) closedir(dirp);
	തിരികെ ret;
}

പൂർണ്ണസംഖ്യ
sftp_upload_dir(ഘടന sftp_conn *conn, സ്ഥിരം അക്ഷരം *src, സ്ഥിരം അക്ഷരം *dst,
    പൂർണ്ണസംഖ്യ preserve_flag, പൂർണ്ണസംഖ്യ print_flag, പൂർണ്ണസംഖ്യ resume, പൂർണ്ണസംഖ്യ fsync_flag,
    പൂർണ്ണസംഖ്യ follow_link_flag, പൂർണ്ണസംഖ്യ inplace_flag)
{
	അക്ഷരം *dst_canon;
	പൂർണ്ണസംഖ്യ ret;

	എങ്കിൽ ((dst_canon = sftp_realpath(conn, dst)) == ശൂന്യ) {
		error("upload \"%s\": path canonicalization failed", dst);
		തിരികെ -1;
	}

	ret = upload_dir_internal(conn, src, dst_canon, 0, preserve_flag,
	    print_flag, resume, fsync_flag, follow_link_flag, inplace_flag);

	സ്വതന്ത്രം(dst_canon);
	തിരികെ ret;
}

സ്ഥിതം ശൂന്യം
handle_dest_replies(ഘടന sftp_conn *to, സ്ഥിരം അക്ഷരം *to_path, പൂർണ്ണസംഖ്യ synchronous,
    u_int *nreqsp, u_int *write_errorp)
{
	ഘടന sshbuf *സന്ദേശം;
	u_char type;
	u_int id, status;
	പൂർണ്ണസംഖ്യ r;
	ഘടന pollfd pfd;

	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");

	/* Try to eat replies from the upload side */
	ആകുമ്പോൾ (*nreqsp > 0) {
		debug3_f("%u outstanding replies", *nreqsp);
		എങ്കിൽ (!synchronous) {
			/* Bail out if no data is ready to be read */
			pfd.fd = to->fd_in;
			pfd.events = POLLIN;
			എങ്കിൽ ((r = poll(&pfd, 1, 0)) == -1) {
				എങ്കിൽ (errno == EINTR)
					നിർത്തുക;
				fatal_f("poll: %s", strerror(errno));
			} അല്ലെങ്കിൽ എങ്കിൽ (r == 0)
				നിർത്തുക; /* fd not ready */
		}
		sshbuf_reset(സന്ദേശം);
		get_സന്ദേശം(to, സന്ദേശം);

		എങ്കിൽ ((r = sshbuf_get_u8(സന്ദേശം, &type)) != 0 ||
		    (r = sshbuf_get_u32(സന്ദേശം, &id)) != 0)
			fatal_fr(r, "dest parse");
		debug3("Received dest reply T:%u I:%u R:%u", type, id, *nreqsp);
		എങ്കിൽ (type != SSH2_FXP_STATUS) {
			fatal_f("Expected SSH2_FXP_STATUS(%d) packet, got %d",
			    SSH2_FXP_STATUS, type);
		}
		എങ്കിൽ ((r = sshbuf_get_u32(സന്ദേശം, &status)) != 0)
			fatal_fr(r, "parse dest status");
		debug3("dest SSH2_FXP_STATUS %u", status);
		എങ്കിൽ (status != SSH2_FX_OK) {
			/* record first error */
			എങ്കിൽ (*write_errorp == 0)
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
	sshbuf_free(സന്ദേശം);
}

പൂർണ്ണസംഖ്യ
sftp_crossload(ഘടന sftp_conn *from, ഘടന sftp_conn *to,
    സ്ഥിരം അക്ഷരം *from_path, സ്ഥിരം അക്ഷരം *to_path,
    Attrib *a, പൂർണ്ണസംഖ്യ preserve_flag)
{
	ഘടന sshbuf *സന്ദേശം;
	പൂർണ്ണസംഖ്യ write_error, read_error, r, seen_zerolen = 0;
	uint64_t offset = 0, size;
	u_int id, buflen, അക്കം_req, max_req, status = SSH2_FX_OK;
	u_int അക്കം_upload_req;
	off_t progress_counter;
	u_char *from_handle, *to_handle;
	size_t from_handle_len, to_handle_len;
	ഘടന requests requests;
	ഘടന request *req;
	u_char type;
	Attrib attr;

	debug2_f("crossload src \"%s\" to dst \"%s\"", from_path, to_path);

	TAILQ_INIT(&requests);

	എങ്കിൽ (a == ശൂന്യ) {
		എങ്കിൽ (sftp_stat(from, from_path, 0, &attr) != 0)
			തിരികെ -1;
		a = &attr;
	}

	എങ്കിൽ ((a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) &&
	    (!S_ISREG(a->perm))) {
		error("download \"%s\": not a regular file", from_path);
		തിരികെ(-1);
	}
	എങ്കിൽ (a->flags & SSH2_FILEXFER_ATTR_SIZE)
		size = a->size;
	അല്ലെങ്കിൽ
		size = 0;

	buflen = from->download_buflen;
	എങ്കിൽ (buflen > to->upload_buflen)
		buflen = to->upload_buflen;

	/* Send open request to read side */
	എങ്കിൽ (send_open(from, from_path, "origin", SSH2_FXF_READ, ശൂന്യ,
	    &from_handle, &from_handle_len) != 0)
		തിരികെ -1;

	/* Send open request to write side */
	a->flags &= ~SSH2_FILEXFER_ATTR_SIZE;
	a->flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a->perm &= 0777;
	എങ്കിൽ (!preserve_flag)
		a->flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;
	എങ്കിൽ (send_open(to, to_path, "dest",
	    SSH2_FXF_WRITE|SSH2_FXF_CREAT|SSH2_FXF_TRUNC, a,
	    &to_handle, &to_handle_len) != 0) {
		sftp_close(from, from_handle, from_handle_len);
		തിരികെ -1;
	}

	/* Read from remote "from" and write to remote "to" */
	offset = 0;
	write_error = read_error = അക്കം_req = അക്കം_upload_req = 0;
	max_req = 1;
	progress_counter = 0;

	എങ്കിൽ (showprogress && size != 0) {
		start_progress_meter(progress_meter_path(from_path),
		    size, &progress_counter);
	}
	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	ആകുമ്പോൾ (അക്കം_req > 0 || max_req > 0) {
		u_char *data;
		size_t len;

		/*
		 * Simulate EOF on interrupt: stop sending new requests and
		 * allow outstanding requests to drain gracefully
		 */
		എങ്കിൽ (interrupted) {
			എങ്കിൽ (അക്കം_req == 0) /* If we haven't started yet... */
				നിർത്തുക;
			max_req = 0;
		}

		/* Send some more requests */
		ആകുമ്പോൾ (അക്കം_req < max_req) {
			debug3("Request range %llu -> %llu (%d/%d)",
			    (unsigned long long)offset,
			    (unsigned long long)offset + buflen - 1,
			    അക്കം_req, max_req);
			req = request_enqueue(&requests, from->സന്ദേശം_id++,
			    buflen, offset);
			offset += buflen;
			അക്കം_req++;
			send_read_request(from, req->id, req->offset,
			    req->len, from_handle, from_handle_len);
		}

		/* Try to eat replies from the upload side (nonblocking) */
		handle_dest_replies(to, to_path, 0,
		    &അക്കം_upload_req, &write_error);

		sshbuf_reset(സന്ദേശം);
		get_സന്ദേശം(from, സന്ദേശം);
		എങ്കിൽ ((r = sshbuf_get_u8(സന്ദേശം, &type)) != 0 ||
		    (r = sshbuf_get_u32(സന്ദേശം, &id)) != 0)
			fatal_fr(r, "parse");
		debug3("Received origin reply T:%u I:%u R:%d",
		    type, id, max_req);

		/* Find the request in our queue */
		എങ്കിൽ ((req = request_find(&requests, id)) == ശൂന്യ)
			fatal("Unexpected reply %u", id);

		തിരഞ്ഞെടുപ്പ് (type) {
		അവസ്ഥ SSH2_FXP_STATUS:
			എങ്കിൽ ((r = sshbuf_get_u32(സന്ദേശം, &status)) != 0)
				fatal_fr(r, "parse status");
			എങ്കിൽ (status != SSH2_FX_EOF)
				read_error = 1;
			max_req = 0;
			TAILQ_REMOVE(&requests, req, tq);
			സ്വതന്ത്രം(req);
			അക്കം_req--;
			നിർത്തുക;
		അവസ്ഥ SSH2_FXP_DATA:
			എങ്കിൽ ((r = sshbuf_get_string(സന്ദേശം, &data, &len)) != 0)
				fatal_fr(r, "parse data");
			debug3("Received data %llu -> %llu",
			    (unsigned long long)req->offset,
			    (unsigned long long)req->offset + len - 1);
			എങ്കിൽ (len > req->len)
				fatal("Received more data than asked for "
				    "%zu > %zu", len, req->len);
			എങ്കിൽ (len == 0) {
				എങ്കിൽ (seen_zerolen)
					fatal_f("server sent zero data length");
				seen_zerolen = 1;
			}

			/* Write this chunk out to the destination */
			sshbuf_reset(സന്ദേശം);
			എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, SSH2_FXP_WRITE)) != 0 ||
			    (r = sshbuf_put_u32(സന്ദേശം, to->സന്ദേശം_id++)) != 0 ||
			    (r = sshbuf_put_string(സന്ദേശം, to_handle,
			    to_handle_len)) != 0 ||
			    (r = sshbuf_put_u64(സന്ദേശം, req->offset)) != 0 ||
			    (r = sshbuf_put_string(സന്ദേശം, data, len)) != 0)
				fatal_fr(r, "compose write");
			send_സന്ദേശം(to, സന്ദേശം);
			debug3("Sent message SSH2_FXP_WRITE I:%u O:%llu S:%zu",
			    id, (unsigned long long)offset, len);
			അക്കം_upload_req++;
			progress_counter += len;
			സ്വതന്ത്രം(data);

			എങ്കിൽ (len == req->len) {
				TAILQ_REMOVE(&requests, req, tq);
				സ്വതന്ത്രം(req);
				അക്കം_req--;
			} അല്ലെങ്കിൽ {
				/* Resend the request for the missing data */
				debug3("Short data block, re-requesting "
				    "%llu -> %llu (%2d)",
				    (unsigned long long)req->offset + len,
				    (unsigned long long)req->offset +
				    req->len - 1, അക്കം_req);
				req->id = from->സന്ദേശം_id++;
				req->len -= len;
				req->offset += len;
				send_read_request(from, req->id,
				    req->offset, req->len,
				    from_handle, from_handle_len);
				/* Reduce the request size */
				എങ്കിൽ (len < buflen)
					buflen = MAXIMUM(MIN_READ_SIZE, len);
			}
			എങ്കിൽ (max_req > 0) { /* max_req = 0 iff EOF received */
				എങ്കിൽ (size > 0 && offset > size) {
					/* Only one request at a time
					 * after the expected EOF */
					debug3("Finish at %llu (%2d)",
					    (unsigned long long)offset,
					    അക്കം_req);
					max_req = 1;
				} അല്ലെങ്കിൽ എങ്കിൽ (max_req < from->അക്കം_requests) {
					++max_req;
				}
			}
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			fatal("Expected SSH2_FXP_DATA(%u) packet, got %u",
			    SSH2_FXP_DATA, type);
		}
	}

	എങ്കിൽ (showprogress && size)
		stop_progress_meter();

	/* Drain replies from the server (blocking) */
	debug3_f("waiting for %u replies from destination", അക്കം_upload_req);
	handle_dest_replies(to, to_path, 1, &അക്കം_upload_req, &write_error);

	/* Sanity check */
	എങ്കിൽ (TAILQ_FIRST(&requests) != ശൂന്യ)
		fatal("Transfer complete, but requests still in queue");
	/* Truncate at 0 length on interrupt or error to avoid holes at dest */
	എങ്കിൽ (read_error || write_error || interrupted) {
		debug("truncating \"%s\" at 0", to_path);
		sftp_close(to, to_handle, to_handle_len);
		സ്വതന്ത്രം(to_handle);
		എങ്കിൽ (send_open(to, to_path, "dest",
		    SSH2_FXF_WRITE|SSH2_FXF_CREAT|SSH2_FXF_TRUNC, a,
		    &to_handle, &to_handle_len) != 0) {
			error("dest truncate \"%s\" failed", to_path);
			to_handle = ശൂന്യ;
		}
	}
	എങ്കിൽ (read_error) {
		error("read origin \"%s\": %s", from_path, fx2txt(status));
		status = -1;
		sftp_close(from, from_handle, from_handle_len);
		എങ്കിൽ (to_handle != ശൂന്യ)
			sftp_close(to, to_handle, to_handle_len);
	} അല്ലെങ്കിൽ എങ്കിൽ (write_error) {
		error("write dest \"%s\": %s", to_path, fx2txt(write_error));
		status = SSH2_FX_FAILURE;
		sftp_close(from, from_handle, from_handle_len);
		എങ്കിൽ (to_handle != ശൂന്യ)
			sftp_close(to, to_handle, to_handle_len);
	} അല്ലെങ്കിൽ {
		എങ്കിൽ (sftp_close(from, from_handle, from_handle_len) != 0 ||
		    interrupted)
			status = -1;
		അല്ലെങ്കിൽ
			status = SSH2_FX_OK;
		എങ്കിൽ (to_handle != ശൂന്യ) {
			/* Need to resend utimes after write */
			എങ്കിൽ (preserve_flag)
				sftp_fsetstat(to, to_handle, to_handle_len, a);
			sftp_close(to, to_handle, to_handle_len);
		}
	}
	sshbuf_free(സന്ദേശം);
	സ്വതന്ത്രം(from_handle);
	സ്വതന്ത്രം(to_handle);

	തിരികെ status == SSH2_FX_OK ? 0 : -1;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
crossload_dir_internal(ഘടന sftp_conn *from, ഘടന sftp_conn *to,
    സ്ഥിരം അക്ഷരം *from_path, സ്ഥിരം അക്ഷരം *to_path,
    പൂർണ്ണസംഖ്യ depth, Attrib *dirattrib, പൂർണ്ണസംഖ്യ preserve_flag, പൂർണ്ണസംഖ്യ print_flag,
    പൂർണ്ണസംഖ്യ follow_link_flag)
{
	പൂർണ്ണസംഖ്യ i, ret = 0, created = 0;
	SFTP_DIRENT **dir_entries;
	അക്ഷരം *filename, *new_from_path = ശൂന്യ, *new_to_path = ശൂന്യ;
	mode_t mode = 0777;
	Attrib *a, curdir, ldirattrib, newdir, lsym;

	debug2_f("crossload dir src \"%s\" to dst \"%s\"", from_path, to_path);

	എങ്കിൽ (depth >= MAX_DIR_DEPTH) {
		error("Maximum directory depth exceeded: %d levels", depth);
		തിരികെ -1;
	}

	എങ്കിൽ (dirattrib == ശൂന്യ) {
		എങ്കിൽ (sftp_stat(from, from_path, 1, &ldirattrib) != 0) {
			error("stat remote \"%s\" failed", from_path);
			തിരികെ -1;
		}
		dirattrib = &ldirattrib;
	}
	എങ്കിൽ (!S_ISDIR(dirattrib->perm)) {
		error("\"%s\" is not a directory", from_path);
		തിരികെ -1;
	}
	എങ്കിൽ (print_flag && print_flag != SFTP_PROGRESS_ONLY)
		mprintf("Retrieving %s\n", from_path);

	curdir = *dirattrib; /* dirattrib will be clobbered */
	curdir.flags &= ~SSH2_FILEXFER_ATTR_SIZE;
	curdir.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	എങ്കിൽ ((curdir.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) == 0) {
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
	എങ്കിൽ (sftp_mkdir(to, to_path, &curdir, 0) == 0)
		created = 1;
	അല്ലെങ്കിൽ {
		എങ്കിൽ (sftp_stat(to, to_path, 0, &newdir) != 0)
			തിരികെ -1;
		എങ്കിൽ (!S_ISDIR(newdir.perm)) {
			error("\"%s\" exists but is not a directory", to_path);
			തിരികെ -1;
		}
	}
	curdir.perm = mode;

	എങ്കിൽ (sftp_readdir(from, from_path, &dir_entries) == -1) {
		error("origin readdir \"%s\" failed", from_path);
		തിരികെ -1;
	}

	വേണ്ടി (i = 0; dir_entries[i] != ശൂന്യ && !interrupted; i++) {
		സ്വതന്ത്രം(new_from_path);
		സ്വതന്ത്രം(new_to_path);

		filename = dir_entries[i]->filename;
		new_from_path = sftp_path_append(from_path, filename);
		new_to_path = sftp_path_append(to_path, filename);

		a = &dir_entries[i]->a;
		എങ്കിൽ (S_ISLNK(a->perm)) {
			എങ്കിൽ (!follow_link_flag) {
				logit("%s: not a regular file", filename);
				തുടരുക;
			}
			/* Replace the stat contents with the symlink target */
			എങ്കിൽ (sftp_stat(from, new_from_path, 1, &lsym) != 0) {
				logit("remote stat \"%s\" failed",
				    new_from_path);
				ret = -1;
				തുടരുക;
			}
			a = &lsym;
		}
		എങ്കിൽ (S_ISDIR(a->perm)) {
			എങ്കിൽ (strcmp(filename, ".") == 0 ||
			    strcmp(filename, "..") == 0)
				തുടരുക;
			എങ്കിൽ (crossload_dir_internal(from, to,
			    new_from_path, new_to_path,
			    depth + 1, a, preserve_flag,
			    print_flag, follow_link_flag) == -1)
				ret = -1;
		} അല്ലെങ്കിൽ എങ്കിൽ (S_ISREG(a->perm)) {
			എങ്കിൽ (sftp_crossload(from, to, new_from_path,
			    new_to_path, a, preserve_flag) == -1) {
				error("crossload \"%s\" to \"%s\" failed",
				    new_from_path, new_to_path);
				ret = -1;
			}
		} അല്ലെങ്കിൽ {
			logit("origin \"%s\": not a regular file",
			    new_from_path);
		}
	}
	സ്വതന്ത്രം(new_to_path);
	സ്വതന്ത്രം(new_from_path);

	എങ്കിൽ (created || preserve_flag)
		sftp_setstat(to, to_path, &curdir);

	sftp_free_dirents(dir_entries);

	തിരികെ ret;
}

പൂർണ്ണസംഖ്യ
sftp_crossload_dir(ഘടന sftp_conn *from, ഘടന sftp_conn *to,
    സ്ഥിരം അക്ഷരം *from_path, സ്ഥിരം അക്ഷരം *to_path,
    Attrib *dirattrib, പൂർണ്ണസംഖ്യ preserve_flag, പൂർണ്ണസംഖ്യ print_flag, പൂർണ്ണസംഖ്യ follow_link_flag)
{
	അക്ഷരം *from_path_canon;
	പൂർണ്ണസംഖ്യ ret;

	എങ്കിൽ ((from_path_canon = sftp_realpath(from, from_path)) == ശൂന്യ) {
		error("crossload \"%s\": path canonicalization failed",
		    from_path);
		തിരികെ -1;
	}

	ret = crossload_dir_internal(from, to, from_path_canon, to_path, 0,
	    dirattrib, preserve_flag, print_flag, follow_link_flag);
	സ്വതന്ത്രം(from_path_canon);
	തിരികെ ret;
}

പൂർണ്ണസംഖ്യ
sftp_can_get_users_groups_by_id(ഘടന sftp_conn *conn)
{
	തിരികെ (conn->exts & SFTP_EXT_GETUSERSGROUPS_BY_ID) != 0;
}

പൂർണ്ണസംഖ്യ
sftp_get_users_groups_by_id(ഘടന sftp_conn *conn,
    സ്ഥിരം u_int *uids, u_int nuids,
    സ്ഥിരം u_int *gids, u_int ngids,
    അക്ഷരം ***usernamesp, അക്ഷരം ***groupnamesp)
{
	ഘടന sshbuf *സന്ദേശം, *uidbuf, *gidbuf;
	u_int i, expected_id, id;
	അക്ഷരം *name, **usernames = ശൂന്യ, **groupnames = ശൂന്യ;
	u_char type;
	പൂർണ്ണസംഖ്യ r;

	*usernamesp = *groupnamesp = ശൂന്യ;
	എങ്കിൽ (!sftp_can_get_users_groups_by_id(conn))
		തിരികെ SSH_ERR_FEATURE_UNSUPPORTED;

	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ ||
	    (uidbuf = sshbuf_new()) == ശൂന്യ ||
	    (gidbuf = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	expected_id = id = conn->സന്ദേശം_id++;
	debug2("Sending SSH2_FXP_EXTENDED(users-groups-by-id@openssh.com)");
	വേണ്ടി (i = 0; i < nuids; i++) {
		എങ്കിൽ ((r = sshbuf_put_u32(uidbuf, uids[i])) != 0)
			fatal_fr(r, "compose uids");
	}
	വേണ്ടി (i = 0; i < ngids; i++) {
		എങ്കിൽ ((r = sshbuf_put_u32(gidbuf, gids[i])) != 0)
			fatal_fr(r, "compose gids");
	}
	എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(സന്ദേശം, id)) != 0 ||
	    (r = sshbuf_put_cstring(സന്ദേശം,
	    "users-groups-by-id@openssh.com")) != 0 ||
	    (r = sshbuf_put_stringb(സന്ദേശം, uidbuf)) != 0 ||
	    (r = sshbuf_put_stringb(സന്ദേശം, gidbuf)) != 0)
		fatal_fr(r, "compose");
	send_സന്ദേശം(conn, സന്ദേശം);
	get_സന്ദേശം(conn, സന്ദേശം);
	എങ്കിൽ ((r = sshbuf_get_u8(സന്ദേശം, &type)) != 0 ||
	    (r = sshbuf_get_u32(സന്ദേശം, &id)) != 0)
		fatal_fr(r, "parse");
	എങ്കിൽ (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	എങ്കിൽ (type == SSH2_FXP_STATUS) {
		u_int status;
		അക്ഷരം *errmsg;

		എങ്കിൽ ((r = sshbuf_get_u32(സന്ദേശം, &status)) != 0 ||
		    (r = sshbuf_get_cstring(സന്ദേശം, &errmsg, ശൂന്യ)) != 0)
			fatal_fr(r, "parse status");
		error("users-groups-by-id %s",
		    *errmsg == '\0' ? fx2txt(status) : errmsg);
		സ്വതന്ത്രം(errmsg);
		sshbuf_free(സന്ദേശം);
		sshbuf_free(uidbuf);
		sshbuf_free(gidbuf);
		തിരികെ -1;
	} അല്ലെങ്കിൽ എങ്കിൽ (type != SSH2_FXP_EXTENDED_REPLY)
		fatal("Expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_REPLY, type);

	/* reuse */
	sshbuf_free(uidbuf);
	sshbuf_free(gidbuf);
	uidbuf = gidbuf = ശൂന്യ;
	എങ്കിൽ ((r = sshbuf_froms(സന്ദേശം, &uidbuf)) != 0 ||
	    (r = sshbuf_froms(സന്ദേശം, &gidbuf)) != 0)
		fatal_fr(r, "parse response");
	എങ്കിൽ (nuids > 0) {
		usernames = xcalloc(nuids, വലുപ്പം(*usernames));
		വേണ്ടി (i = 0; i < nuids; i++) {
			എങ്കിൽ ((r = sshbuf_get_cstring(uidbuf, &name, ശൂന്യ)) != 0)
				fatal_fr(r, "parse user name");
			/* Handle unresolved names */
			എങ്കിൽ (*name == '\0') {
				സ്വതന്ത്രം(name);
				name = ശൂന്യ;
			}
			usernames[i] = name;
		}
	}
	എങ്കിൽ (ngids > 0) {
		groupnames = xcalloc(ngids, വലുപ്പം(*groupnames));
		വേണ്ടി (i = 0; i < ngids; i++) {
			എങ്കിൽ ((r = sshbuf_get_cstring(gidbuf, &name, ശൂന്യ)) != 0)
				fatal_fr(r, "parse user name");
			/* Handle unresolved names */
			എങ്കിൽ (*name == '\0') {
				സ്വതന്ത്രം(name);
				name = ശൂന്യ;
			}
			groupnames[i] = name;
		}
	}
	എങ്കിൽ (sshbuf_len(uidbuf) != 0)
		fatal_f("unexpected extra username data");
	എങ്കിൽ (sshbuf_len(gidbuf) != 0)
		fatal_f("unexpected extra groupname data");
	sshbuf_free(uidbuf);
	sshbuf_free(gidbuf);
	sshbuf_free(സന്ദേശം);
	/* success */
	*usernamesp = usernames;
	*groupnamesp = groupnames;
	തിരികെ 0;
}

അക്ഷരം *
sftp_path_append(സ്ഥിരം അക്ഷരം *p1, സ്ഥിരം അക്ഷരം *p2)
{
	അക്ഷരം *ret;
	size_t len = strlen(p1) + strlen(p2) + 2;

	ret = xmalloc(len);
	strlcpy(ret, p1, len);
	എങ്കിൽ (p1[0] != '\0' && p1[strlen(p1) - 1] != '/')
		strlcat(ret, "/", len);
	strlcat(ret, p2, len);

	തിരികെ(ret);
}

/*
 * Arg p must be dynamically allocated.  It will either be returned or
 * freed and a replacement allocated.  Caller must free returned string.
 */
അക്ഷരം *
sftp_make_absolute(അക്ഷരം *p, സ്ഥിരം അക്ഷരം *pwd)
{
	അക്ഷരം *abs_str;

	/* Derelativise */
	എങ്കിൽ (p && !path_absolute(p)) {
		abs_str = sftp_path_append(pwd, p);
		സ്വതന്ത്രം(p);
		തിരികെ(abs_str);
	} അല്ലെങ്കിൽ
		തിരികെ(p);
}

പൂർണ്ണസംഖ്യ
sftp_remote_is_dir(ഘടന sftp_conn *conn, സ്ഥിരം അക്ഷരം *path)
{
	Attrib a;

	/* XXX: report errors? */
	എങ്കിൽ (sftp_stat(conn, path, 1, &a) != 0)
		തിരികെ(0);
	എങ്കിൽ (!(a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS))
		തിരികെ(0);
	തിരികെ S_ISDIR(a.perm);
}


/* Check whether path returned from glob(..., GLOB_MARK, ...) is a directory */
പൂർണ്ണസംഖ്യ
sftp_globpath_is_dir(സ്ഥിരം അക്ഷരം *pathname)
{
	size_t l = strlen(pathname);

	തിരികെ l > 0 && pathname[l - 1] == '/';
}

