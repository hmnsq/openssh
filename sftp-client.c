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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/queue.h>
#ଅନ୍ତର୍ଭାଵ <sys/stat.h>
#ଅନ୍ତର୍ଭାଵ <sys/time.h>
#ଅନ୍ତର୍ଭାଵ <sys/statvfs.h>
#ଅନ୍ତର୍ଭାଵ <sys/uio.h>

#ଅନ୍ତର୍ଭାଵ <dirent.h>
#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <fcntl.h>
#ଅନ୍ତର୍ଭାଵ <poll.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "atomicio.h"
#ଅନ୍ତର୍ଭାଵ "progressmeter.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "utf8.h"

#ଅନ୍ତର୍ଭାଵ "sftp.h"
#ଅନ୍ତର୍ଭାଵ "sftp-common.h"
#ଅନ୍ତର୍ଭାଵ "sftp-client.h"

ବାହ୍ୟ ଅସ୍ଥିର sig_atomic_t interrupted;
ବାହ୍ୟ ପୂର୍ଣ୍ଣସଂଖ୍ୟା showprogress;

/* Default size of buffer for up/download (fix sftp.1 scp.1 if changed) */
#define DEFAULT_COPY_BUFLEN	32768

/* Default number of concurrent xfer requests (fix sftp.1 scp.1 if changed) */
#define DEFAULT_ଅଙ୍କ_REQUESTS	64

/* Minimum amount of data to read at a time */
#define MIN_READ_SIZE	512

/* Maximum depth to descend in directory trees */
#define MAX_DIR_DEPTH 64

/* Directory separator characters */
#ifdef HAVE_CYGWIN
# define SFTP_DIRECTORY_CHARS      "/\\"
#ଅନ୍ୟଥା /* HAVE_CYGWIN */
# define SFTP_DIRECTORY_CHARS      "/"
#endif /* HAVE_CYGWIN */

ସଂରଚନା sftp_conn {
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd_in;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd_out;
	u_int download_buflen;
	u_int upload_buflen;
	u_int ଅଙ୍କ_requests;
	u_int version;
	u_int ସନ୍ଦେଶ_id;
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
	ସଂରଚନା bwlimit bwlimit_in, bwlimit_out;
};

/* Tracks in-progress requests during file transfers */
ସଂରଚନା request {
	u_int id;
	size_t len;
	uint64_t offset;
	TAILQ_ENTRY(request) tq;
};
TAILQ_HEAD(requests, request);

ସ୍ଥିର u_char *
get_handle(ସଂରଚନା sftp_conn *conn, u_int expected_id, size_t *len,
    ଅଚଳ ଅକ୍ଷର *errfmt, ...) __attribute__((format(printf, 4, 5)));

ସ୍ଥିର ସଂରଚନା request *
request_enqueue(ସଂରଚନା requests *requests, u_int id, size_t len,
    uint64_t offset)
{
	ସଂରଚନା request *req;

	req = xcalloc(1, ଆକାର(*req));
	req->id = id;
	req->len = len;
	req->offset = offset;
	TAILQ_INSERT_TAIL(requests, req, tq);
	ଫେରନ୍ତୁ req;
}

ସ୍ଥିର ସଂରଚନା request *
request_find(ସଂରଚନା requests *requests, u_int id)
{
	ସଂରଚନା request *req;

	ପାଇଁ (req = TAILQ_FIRST(requests);
	    req != ଖାଲି && req->id != id;
	    req = TAILQ_NEXT(req, tq))
		;
	ଫେରନ୍ତୁ req;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sftpio(ଶୂନ୍ୟ *_bwlimit, size_t amount)
{
	ସଂରଚନା bwlimit *bwlimit = (ସଂରଚନା bwlimit *)_bwlimit;

	refresh_progress_meter(0);
	ଯଦି (bwlimit != ଖାଲି)
		bandwidth_limit(bwlimit, amount);
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ଶୂନ୍ୟ
send_ସନ୍ଦେଶ(ସଂରଚନା sftp_conn *conn, ସଂରଚନା sshbuf *m)
{
	u_char mlen[4];
	ସଂରଚନା iovec iov[2];

	ଯଦି (sshbuf_len(m) > SFTP_MAX_ସନ୍ଦେଶ_LENGTH)
		fatal("Outbound message too long %zu", sshbuf_len(m));

	/* Send length first */
	put_u32(mlen, sshbuf_len(m));
	iov[0].iov_base = mlen;
	iov[0].iov_len = ଆକାର(mlen);
	iov[1].iov_base = (u_char *)sshbuf_ptr(m);
	iov[1].iov_len = sshbuf_len(m);

	ଯଦି (atomiciov6(writev, conn->fd_out, iov, 2, sftpio,
	    conn->limit_kbps > 0 ? &conn->bwlimit_out : ଖାଲି) !=
	    sshbuf_len(m) + ଆକାର(mlen))
		fatal("Couldn't send packet: %s", strerror(errno));

	sshbuf_reset(m);
}

ସ୍ଥିର ଶୂନ୍ୟ
get_ସନ୍ଦେଶ_extended(ସଂରଚନା sftp_conn *conn, ସଂରଚନା sshbuf *m, ପୂର୍ଣ୍ଣସଂଖ୍ୟା initial)
{
	u_int ସନ୍ଦେଶ_len;
	u_char *p;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	sshbuf_reset(m);
	ଯଦି ((r = sshbuf_reserve(m, 4, &p)) != 0)
		fatal_fr(r, "reserve");
	ଯଦି (atomicio6(ପଠ, conn->fd_in, p, 4, sftpio,
	    conn->limit_kbps > 0 ? &conn->bwlimit_in : ଖାଲି) != 4) {
		ଯଦି (errno == EPIPE || errno == ECONNRESET)
			fatal("Connection closed");
		ଅନ୍ୟଥା
			fatal("Couldn't read packet: %s", strerror(errno));
	}

	ଯଦି ((r = sshbuf_get_u32(m, &ସନ୍ଦେଶ_len)) != 0)
		fatal_fr(r, "sshbuf_get_u32");
	ଯଦି (ସନ୍ଦେଶ_len > SFTP_MAX_ସନ୍ଦେଶ_LENGTH) {
		do_log2(initial ? SYSLOG_LEVEL_ERROR : SYSLOG_LEVEL_FATAL,
		    "Received message too long %u", ସନ୍ଦେଶ_len);
		fatal("Ensure the remote shell produces no output "
		    "for non-interactive sessions.");
	}

	ଯଦି ((r = sshbuf_reserve(m, ସନ୍ଦେଶ_len, &p)) != 0)
		fatal_fr(r, "reserve");
	ଯଦି (atomicio6(ପଠ, conn->fd_in, p, ସନ୍ଦେଶ_len, sftpio,
	    conn->limit_kbps > 0 ? &conn->bwlimit_in : ଖାଲି)
	    != ସନ୍ଦେଶ_len) {
		ଯଦି (errno == EPIPE)
			fatal("Connection closed");
		ଅନ୍ୟଥା
			fatal("Read packet: %s", strerror(errno));
	}
}

ସ୍ଥିର ଶୂନ୍ୟ
get_ସନ୍ଦେଶ(ସଂରଚନା sftp_conn *conn, ସଂରଚନା sshbuf *m)
{
	get_ସନ୍ଦେଶ_extended(conn, m, 0);
}

ସ୍ଥିର ଶୂନ୍ୟ
send_string_request(ସଂରଚନା sftp_conn *conn, u_int id, u_int code, ଅଚଳ ଅକ୍ଷର *s,
    u_int len)
{
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, code)) != 0 ||
	    (r = sshbuf_put_u32(ସନ୍ଦେଶ, id)) != 0 ||
	    (r = sshbuf_put_string(ସନ୍ଦେଶ, s, len)) != 0)
		fatal_fr(r, "compose");
	send_ସନ୍ଦେଶ(conn, ସନ୍ଦେଶ);
	debug3("Sent message fd %d T:%u I:%u", conn->fd_out, code, id);
	sshbuf_free(ସନ୍ଦେଶ);
}

ସ୍ଥିର ଶୂନ୍ୟ
send_string_attrs_request(ସଂରଚନା sftp_conn *conn, u_int id, u_int code,
    ଅଚଳ ଶୂନ୍ୟ *s, u_int len, Attrib *a)
{
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, code)) != 0 ||
	    (r = sshbuf_put_u32(ସନ୍ଦେଶ, id)) != 0 ||
	    (r = sshbuf_put_string(ସନ୍ଦେଶ, s, len)) != 0 ||
	    (r = encode_attrib(ସନ୍ଦେଶ, a)) != 0)
		fatal_fr(r, "compose");
	send_ସନ୍ଦେଶ(conn, ସନ୍ଦେଶ);
	debug3("Sent message fd %d T:%u I:%u F:0x%04x M:%05o",
	    conn->fd_out, code, id, a->flags, a->perm);
	sshbuf_free(ସନ୍ଦେଶ);
}

ସ୍ଥିର u_int
get_status(ସଂରଚନା sftp_conn *conn, u_int expected_id)
{
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;
	u_char type;
	u_int id, status;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	get_ସନ୍ଦେଶ(conn, ସନ୍ଦେଶ);
	ଯଦି ((r = sshbuf_get_u8(ସନ୍ଦେଶ, &type)) != 0 ||
	    (r = sshbuf_get_u32(ସନ୍ଦେଶ, &id)) != 0)
		fatal_fr(r, "compose");

	ଯଦି (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	ଯଦି (type != SSH2_FXP_STATUS)
		fatal("Expected SSH2_FXP_STATUS(%u) packet, got %u",
		    SSH2_FXP_STATUS, type);

	ଯଦି ((r = sshbuf_get_u32(ସନ୍ଦେଶ, &status)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(ସନ୍ଦେଶ);

	debug3("SSH2_FXP_STATUS %u", status);

	ଫେରନ୍ତୁ status;
}

ସ୍ଥିର u_char *
get_handle(ସଂରଚନା sftp_conn *conn, u_int expected_id, size_t *len,
    ଅଚଳ ଅକ୍ଷର *errfmt, ...)
{
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;
	u_int id, status;
	u_char type;
	u_char *handle;
	ଅକ୍ଷର errmsg[256];
	va_list args;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	va_start(args, errfmt);
	ଯଦି (errfmt != ଖାଲି)
		vsnprintf(errmsg, ଆକାର(errmsg), errfmt, args);
	va_end(args);

	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	get_ସନ୍ଦେଶ(conn, ସନ୍ଦେଶ);
	ଯଦି ((r = sshbuf_get_u8(ସନ୍ଦେଶ, &type)) != 0 ||
	    (r = sshbuf_get_u32(ସନ୍ଦେଶ, &id)) != 0)
		fatal_fr(r, "parse");

	ଯଦି (id != expected_id)
		fatal("%s: ID mismatch (%u != %u)",
		    errfmt == ଖାଲି ? __func__ : errmsg, id, expected_id);
	ଯଦି (type == SSH2_FXP_STATUS) {
		ଯଦି ((r = sshbuf_get_u32(ସନ୍ଦେଶ, &status)) != 0)
			fatal_fr(r, "parse status");
		ଯଦି (errfmt != ଖାଲି)
			error("%s: %s", errmsg, fx2txt(status));
		sshbuf_free(ସନ୍ଦେଶ);
		ଫେରନ୍ତୁ(ଖାଲି);
	} ଅନ୍ୟଥା ଯଦି (type != SSH2_FXP_HANDLE)
		fatal("%s: Expected SSH2_FXP_HANDLE(%u) packet, got %u",
		    errfmt == ଖାଲି ? __func__ : errmsg, SSH2_FXP_HANDLE, type);

	ଯଦି ((r = sshbuf_get_string(ସନ୍ଦେଶ, &handle, len)) != 0)
		fatal_fr(r, "parse handle");
	sshbuf_free(ସନ୍ଦେଶ);

	ଫେରନ୍ତୁ handle;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
get_decode_stat(ସଂରଚନା sftp_conn *conn, u_int expected_id, ପୂର୍ଣ୍ଣସଂଖ୍ୟା quiet, Attrib *a)
{
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;
	u_int id;
	u_char type;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	Attrib attr;

	ଯଦି (a != ଖାଲି)
		memset(a, '\0', ଆକାର(*a));
	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	get_ସନ୍ଦେଶ(conn, ସନ୍ଦେଶ);

	ଯଦି ((r = sshbuf_get_u8(ସନ୍ଦେଶ, &type)) != 0 ||
	    (r = sshbuf_get_u32(ସନ୍ଦେଶ, &id)) != 0)
		fatal_fr(r, "parse");

	ଯଦି (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	ଯଦି (type == SSH2_FXP_STATUS) {
		u_int status;

		ଯଦି ((r = sshbuf_get_u32(ସନ୍ଦେଶ, &status)) != 0)
			fatal_fr(r, "parse status");
		ଯଦି (quiet)
			debug("stat remote: %s", fx2txt(status));
		ଅନ୍ୟଥା
			error("stat remote: %s", fx2txt(status));
		sshbuf_free(ସନ୍ଦେଶ);
		ଫେରନ୍ତୁ -1;
	} ଅନ୍ୟଥା ଯଦି (type != SSH2_FXP_ATTRS) {
		fatal("Expected SSH2_FXP_ATTRS(%u) packet, got %u",
		    SSH2_FXP_ATTRS, type);
	}
	ଯଦି ((r = decode_attrib(ସନ୍ଦେଶ, &attr)) != 0) {
		error_fr(r, "decode_attrib");
		sshbuf_free(ସନ୍ଦେଶ);
		ଫେରନ୍ତୁ -1;
	}
	/* success */
	ଯଦି (a != ଖାଲି)
		*a = attr;
	debug3("Received stat reply T:%u I:%u F:0x%04x M:%05o",
	    type, id, attr.flags, attr.perm);
	sshbuf_free(ସନ୍ଦେଶ);

	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
get_decode_statvfs(ସଂରଚନା sftp_conn *conn, ସଂରଚନା sftp_statvfs *st,
    u_int expected_id, ପୂର୍ଣ୍ଣସଂଖ୍ୟା quiet)
{
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;
	u_char type;
	u_int id;
	uint64_t flag;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	get_ସନ୍ଦେଶ(conn, ସନ୍ଦେଶ);

	ଯଦି ((r = sshbuf_get_u8(ସନ୍ଦେଶ, &type)) != 0 ||
	    (r = sshbuf_get_u32(ସନ୍ଦେଶ, &id)) != 0)
		fatal_fr(r, "parse");

	debug3("Received statvfs reply T:%u I:%u", type, id);
	ଯଦି (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	ଯଦି (type == SSH2_FXP_STATUS) {
		u_int status;

		ଯଦି ((r = sshbuf_get_u32(ସନ୍ଦେଶ, &status)) != 0)
			fatal_fr(r, "parse status");
		ଯଦି (quiet)
			debug("remote statvfs: %s", fx2txt(status));
		ଅନ୍ୟଥା
			error("remote statvfs: %s", fx2txt(status));
		sshbuf_free(ସନ୍ଦେଶ);
		ଫେରନ୍ତୁ -1;
	} ଅନ୍ୟଥା ଯଦି (type != SSH2_FXP_EXTENDED_REPLY) {
		fatal("Expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_REPLY, type);
	}

	memset(st, 0, ଆକାର(*st));
	ଯଦି ((r = sshbuf_get_u64(ସନ୍ଦେଶ, &st->f_bsize)) != 0 ||
	    (r = sshbuf_get_u64(ସନ୍ଦେଶ, &st->f_frsize)) != 0 ||
	    (r = sshbuf_get_u64(ସନ୍ଦେଶ, &st->f_blocks)) != 0 ||
	    (r = sshbuf_get_u64(ସନ୍ଦେଶ, &st->f_bfree)) != 0 ||
	    (r = sshbuf_get_u64(ସନ୍ଦେଶ, &st->f_bavail)) != 0 ||
	    (r = sshbuf_get_u64(ସନ୍ଦେଶ, &st->f_files)) != 0 ||
	    (r = sshbuf_get_u64(ସନ୍ଦେଶ, &st->f_ffree)) != 0 ||
	    (r = sshbuf_get_u64(ସନ୍ଦେଶ, &st->f_favail)) != 0 ||
	    (r = sshbuf_get_u64(ସନ୍ଦେଶ, &st->f_fsid)) != 0 ||
	    (r = sshbuf_get_u64(ସନ୍ଦେଶ, &flag)) != 0 ||
	    (r = sshbuf_get_u64(ସନ୍ଦେଶ, &st->f_namemax)) != 0)
		fatal_fr(r, "parse statvfs");

	st->f_flag = (flag & SSH2_FXE_STATVFS_ST_RDONLY) ? ST_RDONLY : 0;
	st->f_flag |= (flag & SSH2_FXE_STATVFS_ST_NOSUID) ? ST_NOSUID : 0;

	sshbuf_free(ସନ୍ଦେଶ);

	ଫେରନ୍ତୁ 0;
}

ସଂରଚନା sftp_conn *
sftp_init(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd_in, ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd_out, u_int transfer_buflen, u_int ଅଙ୍କ_requests,
    uint64_t limit_kbps)
{
	u_char type;
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;
	ସଂରଚନା sftp_conn *ret;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ret = xcalloc(1, ଆକାର(*ret));
	ret->ସନ୍ଦେଶ_id = 1;
	ret->fd_in = fd_in;
	ret->fd_out = fd_out;
	ret->download_buflen = ret->upload_buflen =
	    transfer_buflen ? transfer_buflen : DEFAULT_COPY_BUFLEN;
	ret->ଅଙ୍କ_requests =
	    ଅଙ୍କ_requests ? ଅଙ୍କ_requests : DEFAULT_ଅଙ୍କ_REQUESTS;
	ret->exts = 0;
	ret->limit_kbps = 0;

	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, SSH2_FXP_INIT)) != 0 ||
	    (r = sshbuf_put_u32(ସନ୍ଦେଶ, SSH2_FILEXFER_VERSION)) != 0)
		fatal_fr(r, "parse");

	send_ସନ୍ଦେଶ(ret, ସନ୍ଦେଶ);

	get_ସନ୍ଦେଶ_extended(ret, ସନ୍ଦେଶ, 1);

	/* Expecting a VERSION reply */
	ଯଦି ((r = sshbuf_get_u8(ସନ୍ଦେଶ, &type)) != 0)
		fatal_fr(r, "parse type");
	ଯଦି (type != SSH2_FXP_VERSION) {
		error("Invalid packet back from SSH2_FXP_INIT (type %u)",
		    type);
		sshbuf_free(ସନ୍ଦେଶ);
		ମୁକ୍ତ(ret);
		ଫେରନ୍ତୁ(ଖାଲି);
	}
	ଯଦି ((r = sshbuf_get_u32(ସନ୍ଦେଶ, &ret->version)) != 0)
		fatal_fr(r, "parse version");

	debug2("Remote version: %u", ret->version);

	/* Check for extensions */
	ଯେତେବେଳେ (sshbuf_len(ସନ୍ଦେଶ) > 0) {
		ଅକ୍ଷର *name;
		u_char *ମୂଲ୍ୟ;
		size_t vlen;
		ପୂର୍ଣ୍ଣସଂଖ୍ୟା known = 0;

		ଯଦି ((r = sshbuf_get_cstring(ସନ୍ଦେଶ, &name, ଖାଲି)) != 0 ||
		    (r = sshbuf_get_string(ସନ୍ଦେଶ, &ମୂଲ୍ୟ, &vlen)) != 0)
			fatal_fr(r, "parse extension");
		ଯଦି (strcmp(name, "posix-rename@openssh.com") == 0 &&
		    strcmp((ଅକ୍ଷର *)ମୂଲ୍ୟ, "1") == 0) {
			ret->exts |= SFTP_EXT_POSIX_RENAME;
			known = 1;
		} ଅନ୍ୟଥା ଯଦି (strcmp(name, "statvfs@openssh.com") == 0 &&
		    strcmp((ଅକ୍ଷର *)ମୂଲ୍ୟ, "2") == 0) {
			ret->exts |= SFTP_EXT_STATVFS;
			known = 1;
		} ଅନ୍ୟଥା ଯଦି (strcmp(name, "fstatvfs@openssh.com") == 0 &&
		    strcmp((ଅକ୍ଷର *)ମୂଲ୍ୟ, "2") == 0) {
			ret->exts |= SFTP_EXT_FSTATVFS;
			known = 1;
		} ଅନ୍ୟଥା ଯଦି (strcmp(name, "hardlink@openssh.com") == 0 &&
		    strcmp((ଅକ୍ଷର *)ମୂଲ୍ୟ, "1") == 0) {
			ret->exts |= SFTP_EXT_HARDLINK;
			known = 1;
		} ଅନ୍ୟଥା ଯଦି (strcmp(name, "fsync@openssh.com") == 0 &&
		    strcmp((ଅକ୍ଷର *)ମୂଲ୍ୟ, "1") == 0) {
			ret->exts |= SFTP_EXT_FSYNC;
			known = 1;
		} ଅନ୍ୟଥା ଯଦି (strcmp(name, "lsetstat@openssh.com") == 0 &&
		    strcmp((ଅକ୍ଷର *)ମୂଲ୍ୟ, "1") == 0) {
			ret->exts |= SFTP_EXT_LSETSTAT;
			known = 1;
		} ଅନ୍ୟଥା ଯଦି (strcmp(name, "limits@openssh.com") == 0 &&
		    strcmp((ଅକ୍ଷର *)ମୂଲ୍ୟ, "1") == 0) {
			ret->exts |= SFTP_EXT_LIMITS;
			known = 1;
		} ଅନ୍ୟଥା ଯଦି (strcmp(name, "expand-path@openssh.com") == 0 &&
		    strcmp((ଅକ୍ଷର *)ମୂଲ୍ୟ, "1") == 0) {
			ret->exts |= SFTP_EXT_PATH_EXPAND;
			known = 1;
		} ଅନ୍ୟଥା ଯଦି (strcmp(name, "copy-data") == 0 &&
		    strcmp((ଅକ୍ଷର *)ମୂଲ୍ୟ, "1") == 0) {
			ret->exts |= SFTP_EXT_COPY_DATA;
			known = 1;
		} ଅନ୍ୟଥା ଯଦି (strcmp(name,
		    "users-groups-by-id@openssh.com") == 0 &&
		    strcmp((ଅକ୍ଷର *)ମୂଲ୍ୟ, "1") == 0) {
			ret->exts |= SFTP_EXT_GETUSERSGROUPS_BY_ID;
			known = 1;
		}
		ଯଦି (known) {
			debug2("Server supports extension \"%s\" revision %s",
			    name, ମୂଲ୍ୟ);
		} ଅନ୍ୟଥା {
			debug2("Unrecognised server extension \"%s\"", name);
		}
		ମୁକ୍ତ(name);
		ମୁକ୍ତ(ମୂଲ୍ୟ);
	}

	sshbuf_free(ସନ୍ଦେଶ);

	/* Query the server for its limits */
	ଯଦି (ret->exts & SFTP_EXT_LIMITS) {
		ସଂରଚନା sftp_limits limits;
		ଯଦି (sftp_get_limits(ret, &limits) != 0)
			fatal_f("limits failed");

		/* If the caller did not specify, find a good value */
		ଯଦି (transfer_buflen == 0) {
			ret->download_buflen = MINIMUM(limits.read_length,
			    SFTP_MAX_ସନ୍ଦେଶ_LENGTH - 1024);
			ret->upload_buflen = MINIMUM(limits.write_length,
			    SFTP_MAX_ସନ୍ଦେଶ_LENGTH - 1024);
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
	ଯଦି (ret->version == 0) {
		ret->download_buflen = MINIMUM(ret->download_buflen, 20480);
		ret->upload_buflen = MINIMUM(ret->upload_buflen, 20480);
	}

	ret->limit_kbps = limit_kbps;
	ଯଦି (ret->limit_kbps > 0) {
		bandwidth_limit_init(&ret->bwlimit_in, ret->limit_kbps,
		    ret->download_buflen);
		bandwidth_limit_init(&ret->bwlimit_out, ret->limit_kbps,
		    ret->upload_buflen);
	}

	ଫେରନ୍ତୁ ret;
}

ଶୂନ୍ୟ
sftp_free(ସଂରଚନା sftp_conn *conn)
{
	ଯଦି (conn == ଖାଲି)
		ଫେରନ୍ତୁ;
	freezero(conn, ଆକାର(*conn));
}

u_int
sftp_proto_version(ସଂରଚନା sftp_conn *conn)
{
	ଫେରନ୍ତୁ conn->version;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sftp_get_limits(ସଂରଚନା sftp_conn *conn, ସଂରଚନା sftp_limits *limits)
{
	u_int id, ସନ୍ଦେଶ_id;
	u_char type;
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((conn->exts & SFTP_EXT_LIMITS) == 0) {
		error("Server does not support limits@openssh.com extension");
		ଫେରନ୍ତୁ -1;
	}

	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");

	id = conn->ସନ୍ଦେଶ_id++;
	ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(ସନ୍ଦେଶ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ସନ୍ଦେଶ, "limits@openssh.com")) != 0)
		fatal_fr(r, "compose");
	send_ସନ୍ଦେଶ(conn, ସନ୍ଦେଶ);
	debug3("Sent message limits@openssh.com I:%u", id);

	get_ସନ୍ଦେଶ(conn, ସନ୍ଦେଶ);

	ଯଦି ((r = sshbuf_get_u8(ସନ୍ଦେଶ, &type)) != 0 ||
	    (r = sshbuf_get_u32(ସନ୍ଦେଶ, &ସନ୍ଦେଶ_id)) != 0)
		fatal_fr(r, "parse");

	debug3("Received limits reply T:%u I:%u", type, ସନ୍ଦେଶ_id);
	ଯଦି (id != ସନ୍ଦେଶ_id)
		fatal("ID mismatch (%u != %u)", ସନ୍ଦେଶ_id, id);
	ଯଦି (type != SSH2_FXP_EXTENDED_REPLY) {
		debug_f("expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_REPLY, type);
		/* Disable the limits extension */
		conn->exts &= ~SFTP_EXT_LIMITS;
		sshbuf_free(ସନ୍ଦେଶ);
		ଫେରନ୍ତୁ -1;
	}

	memset(limits, 0, ଆକାର(*limits));
	ଯଦି ((r = sshbuf_get_u64(ସନ୍ଦେଶ, &limits->packet_length)) != 0 ||
	    (r = sshbuf_get_u64(ସନ୍ଦେଶ, &limits->read_length)) != 0 ||
	    (r = sshbuf_get_u64(ସନ୍ଦେଶ, &limits->write_length)) != 0 ||
	    (r = sshbuf_get_u64(ସନ୍ଦେଶ, &limits->open_handles)) != 0)
		fatal_fr(r, "parse limits");

	sshbuf_free(ସନ୍ଦେଶ);

	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sftp_close(ସଂରଚନା sftp_conn *conn, ଅଚଳ u_char *handle, u_int handle_len)
{
	u_int id, status;
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");

	id = conn->ସନ୍ଦେଶ_id++;
	ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, SSH2_FXP_CLOSE)) != 0 ||
	    (r = sshbuf_put_u32(ସନ୍ଦେଶ, id)) != 0 ||
	    (r = sshbuf_put_string(ସନ୍ଦେଶ, handle, handle_len)) != 0)
		fatal_fr(r, "parse");
	send_ସନ୍ଦେଶ(conn, ସନ୍ଦେଶ);
	debug3("Sent message SSH2_FXP_CLOSE I:%u", id);

	status = get_status(conn, id);
	ଯଦି (status != SSH2_FX_OK)
		error("close remote: %s", fx2txt(status));

	sshbuf_free(ସନ୍ଦେଶ);

	ଫେରନ୍ତୁ status == SSH2_FX_OK ? 0 : -1;
}


ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sftp_lsreaddir(ସଂରଚନା sftp_conn *conn, ଅଚଳ ଅକ୍ଷର *path, ପୂର୍ଣ୍ଣସଂଖ୍ୟା print_flag,
    SFTP_DIRENT ***dir)
{
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;
	u_int ଗଣନା_2, id, i, expected_id, ents = 0;
	size_t handle_len;
	u_char type, *handle;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା status = SSH2_FX_FAILURE;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (dir)
		*dir = ଖାଲି;

	id = conn->ସନ୍ଦେଶ_id++;

	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, SSH2_FXP_OPENDIR)) != 0 ||
	    (r = sshbuf_put_u32(ସନ୍ଦେଶ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ସନ୍ଦେଶ, path)) != 0)
		fatal_fr(r, "compose OPENDIR");
	send_ସନ୍ଦେଶ(conn, ସନ୍ଦେଶ);

	handle = get_handle(conn, id, &handle_len,
	    "remote readdir(\"%s\")", path);
	ଯଦି (handle == ଖାଲି) {
		sshbuf_free(ସନ୍ଦେଶ);
		ଫେରନ୍ତୁ -1;
	}

	ଯଦି (dir) {
		ents = 0;
		*dir = xcalloc(1, ଆକାର(**dir));
		(*dir)[0] = ଖାଲି;
	}

	ପାଇଁ (; !interrupted;) {
		id = expected_id = conn->ସନ୍ଦେଶ_id++;

		debug3("Sending SSH2_FXP_READDIR I:%u", id);

		sshbuf_reset(ସନ୍ଦେଶ);
		ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, SSH2_FXP_READDIR)) != 0 ||
		    (r = sshbuf_put_u32(ସନ୍ଦେଶ, id)) != 0 ||
		    (r = sshbuf_put_string(ସନ୍ଦେଶ, handle, handle_len)) != 0)
			fatal_fr(r, "compose READDIR");
		send_ସନ୍ଦେଶ(conn, ସନ୍ଦେଶ);

		sshbuf_reset(ସନ୍ଦେଶ);

		get_ସନ୍ଦେଶ(conn, ସନ୍ଦେଶ);

		ଯଦି ((r = sshbuf_get_u8(ସନ୍ଦେଶ, &type)) != 0 ||
		    (r = sshbuf_get_u32(ସନ୍ଦେଶ, &id)) != 0)
			fatal_fr(r, "parse");

		debug3("Received reply T:%u I:%u", type, id);

		ଯଦି (id != expected_id)
			fatal("ID mismatch (%u != %u)", id, expected_id);

		ଯଦି (type == SSH2_FXP_STATUS) {
			u_int rstatus;

			ଯଦି ((r = sshbuf_get_u32(ସନ୍ଦେଶ, &rstatus)) != 0)
				fatal_fr(r, "parse status");
			debug3("Received SSH2_FXP_STATUS %d", rstatus);
			ଯଦି (rstatus == SSH2_FX_EOF)
				ଭାଙ୍ଗ;
			error("Couldn't read directory: %s", fx2txt(rstatus));
			ଯାଅ out;
		} ଅନ୍ୟଥା ଯଦି (type != SSH2_FXP_NAME)
			fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
			    SSH2_FXP_NAME, type);

		ଯଦି ((r = sshbuf_get_u32(ସନ୍ଦେଶ, &ଗଣନା_2)) != 0)
			fatal_fr(r, "parse count");
		ଯଦି (ଗଣନା_2 > SSHBUF_SIZE_MAX)
			fatal_f("nonsensical number of entries");
		ଯଦି (ଗଣନା_2 == 0)
			ଭାଙ୍ଗ;
		debug3("Received %d SSH2_FXP_NAME responses", ଗଣନା_2);
		ପାଇଁ (i = 0; i < ଗଣନା_2; i++) {
			ଅକ୍ଷର *filename, *longname;
			Attrib a;

			ଯଦି ((r = sshbuf_get_cstring(ସନ୍ଦେଶ, &filename,
			    ଖାଲି)) != 0 ||
			    (r = sshbuf_get_cstring(ସନ୍ଦେଶ, &longname,
			    ଖାଲି)) != 0)
				fatal_fr(r, "parse filenames");
			ଯଦି ((r = decode_attrib(ସନ୍ଦେଶ, &a)) != 0) {
				error_fr(r, "couldn't decode attrib");
				ମୁକ୍ତ(filename);
				ମୁକ୍ତ(longname);
				ଯାଅ out;
			}

			ଯଦି (print_flag)
				mprintf("%s\n", longname);

			/*
			 * Directory entries should never contain '/'
			 * These can be used to attack recursive ops
			 * (e.g. send '../../../../etc/passwd')
			 */
			ଯଦି (*filename == '\0' ||
			    strpbrk(filename, SFTP_DIRECTORY_CHARS) != ଖାଲି) {
				error("Server sent suspect path \"%s\" "
				    "during readdir of \"%s\"", filename, path);
			} ଅନ୍ୟଥା ଯଦି (dir) {
				*dir = xreallocarray(*dir, ents + 2, ଆକାର(**dir));
				(*dir)[ents] = xcalloc(1, ଆକାର(***dir));
				(*dir)[ents]->filename = xstrdup(filename);
				(*dir)[ents]->longname = xstrdup(longname);
				memcpy(&(*dir)[ents]->a, &a, ଆକାର(a));
				(*dir)[++ents] = ଖାଲି;
			}
			ମୁକ୍ତ(filename);
			ମୁକ୍ତ(longname);
		}
	}
	status = 0;

 out:
	sshbuf_free(ସନ୍ଦେଶ);
	sftp_close(conn, handle, handle_len);
	ମୁକ୍ତ(handle);

	ଯଦି (status != 0 && dir != ଖାଲି) {
		/* Don't return results on error */
		sftp_free_dirents(*dir);
		*dir = ଖାଲି;
	} ଅନ୍ୟଥା ଯଦି (interrupted && dir != ଖାଲି && *dir != ଖାଲି) {
		/* Don't return partial matches on interrupt */
		sftp_free_dirents(*dir);
		*dir = xcalloc(1, ଆକାର(**dir));
		**dir = ଖାଲି;
	}

	ଫେରନ୍ତୁ status == SSH2_FX_OK ? 0 : -1;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sftp_readdir(ସଂରଚନା sftp_conn *conn, ଅଚଳ ଅକ୍ଷର *path, SFTP_DIRENT ***dir)
{
	ଫେରନ୍ତୁ sftp_lsreaddir(conn, path, 0, dir);
}

ଶୂନ୍ୟ sftp_free_dirents(SFTP_DIRENT **s)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	ଯଦି (s == ଖାଲି)
		ଫେରନ୍ତୁ;
	ପାଇଁ (i = 0; s[i]; i++) {
		ମୁକ୍ତ(s[i]->filename);
		ମୁକ୍ତ(s[i]->longname);
		ମୁକ୍ତ(s[i]);
	}
	ମୁକ୍ତ(s);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sftp_rm(ସଂରଚନା sftp_conn *conn, ଅଚଳ ଅକ୍ଷର *path)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_REMOVE \"%s\"", path);

	id = conn->ସନ୍ଦେଶ_id++;
	send_string_request(conn, id, SSH2_FXP_REMOVE, path, strlen(path));
	status = get_status(conn, id);
	ଯଦି (status != SSH2_FX_OK)
		error("remote delete %s: %s", path, fx2txt(status));
	ଫେରନ୍ତୁ status == SSH2_FX_OK ? 0 : -1;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sftp_mkdir(ସଂରଚନା sftp_conn *conn, ଅଚଳ ଅକ୍ଷର *path, Attrib *a, ପୂର୍ଣ୍ଣସଂଖ୍ୟା print_flag)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_MKDIR \"%s\"", path);

	id = conn->ସନ୍ଦେଶ_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_MKDIR, path,
	    strlen(path), a);

	status = get_status(conn, id);
	ଯଦି (status != SSH2_FX_OK && print_flag)
		error("remote mkdir \"%s\": %s", path, fx2txt(status));

	ଫେରନ୍ତୁ status == SSH2_FX_OK ? 0 : -1;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sftp_mkpath(ସଂରଚନା sftp_conn *conn, ଅଚଳ ଅକ୍ଷର *path, Attrib *a, ପୂର୍ଣ୍ଣସଂଖ୍ୟା print_flag)
{
	ଅକ୍ଷର *slash, *tmp_path;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା done;

	tmp_path = xstrdup(path);
	slash = tmp_path;

	ପାଇଁ (;;) {
		slash += strspn(slash, "/");
		slash += strcspn(slash, "/");

		done = (*slash == '\0');
		*slash = '\0';

		ଯଦି (!sftp_remote_is_dir(conn, tmp_path)) {
			ଯଦି (sftp_mkdir(conn, tmp_path, a, print_flag) != 0) {
				ମୁକ୍ତ(tmp_path);
				ଫେରନ୍ତୁ -1;
			}
		}

		ଯଦି (done)
			ଭାଙ୍ଗ;

		*slash = '/';
	}

	ମୁକ୍ତ(tmp_path);
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sftp_rmdir(ସଂରଚନା sftp_conn *conn, ଅଚଳ ଅକ୍ଷର *path)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_RMDIR \"%s\"", path);

	id = conn->ସନ୍ଦେଶ_id++;
	send_string_request(conn, id, SSH2_FXP_RMDIR, path,
	    strlen(path));

	status = get_status(conn, id);
	ଯଦି (status != SSH2_FX_OK)
		error("remote rmdir \"%s\": %s", path, fx2txt(status));

	ଫେରନ୍ତୁ status == SSH2_FX_OK ? 0 : -1;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sftp_stat(ସଂରଚନା sftp_conn *conn, ଅଚଳ ଅକ୍ଷର *path, ପୂର୍ଣ୍ଣସଂଖ୍ୟା quiet, Attrib *a)
{
	u_int id;

	debug2("Sending SSH2_FXP_STAT \"%s\"", path);

	id = conn->ସନ୍ଦେଶ_id++;

	send_string_request(conn, id,
	    conn->version == 0 ? SSH2_FXP_STAT_VERSION_0 : SSH2_FXP_STAT,
	    path, strlen(path));

	ଫେରନ୍ତୁ get_decode_stat(conn, id, quiet, a);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sftp_lstat(ସଂରଚନା sftp_conn *conn, ଅଚଳ ଅକ୍ଷର *path, ପୂର୍ଣ୍ଣସଂଖ୍ୟା quiet, Attrib *a)
{
	u_int id;

	ଯଦି (conn->version == 0) {
		do_log2(quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_INFO,
		    "Server version does not support lstat operation");
		ଫେରନ୍ତୁ sftp_stat(conn, path, quiet, a);
	}

	id = conn->ସନ୍ଦେଶ_id++;
	send_string_request(conn, id, SSH2_FXP_LSTAT, path,
	    strlen(path));

	ଫେରନ୍ତୁ get_decode_stat(conn, id, quiet, a);
}

#ifdef notyet
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sftp_fstat(ସଂରଚନା sftp_conn *conn, ଅଚଳ u_char *handle, u_int handle_len,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା quiet, Attrib *a)
{
	u_int id;

	debug2("Sending SSH2_FXP_FSTAT \"%s\"");

	id = conn->ସନ୍ଦେଶ_id++;
	send_string_request(conn, id, SSH2_FXP_FSTAT, handle,
	    handle_len);

	ଫେରନ୍ତୁ get_decode_stat(conn, id, quiet, a);
}
#endif

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sftp_setstat(ସଂରଚନା sftp_conn *conn, ଅଚଳ ଅକ୍ଷର *path, Attrib *a)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_SETSTAT \"%s\"", path);

	id = conn->ସନ୍ଦେଶ_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_SETSTAT, path,
	    strlen(path), a);

	status = get_status(conn, id);
	ଯଦି (status != SSH2_FX_OK)
		error("remote setstat \"%s\": %s", path, fx2txt(status));

	ଫେରନ୍ତୁ status == SSH2_FX_OK ? 0 : -1;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sftp_fsetstat(ସଂରଚନା sftp_conn *conn, ଅଚଳ u_char *handle, u_int handle_len,
    Attrib *a)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_FSETSTAT");

	id = conn->ସନ୍ଦେଶ_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_FSETSTAT, handle,
	    handle_len, a);

	status = get_status(conn, id);
	ଯଦି (status != SSH2_FX_OK)
		error("remote fsetstat: %s", fx2txt(status));

	ଫେରନ୍ତୁ status == SSH2_FX_OK ? 0 : -1;
}

/* Implements both the realpath and expand-path operations */
ସ୍ଥିର ଅକ୍ଷର *
sftp_realpath_expand(ସଂରଚନା sftp_conn *conn, ଅଚଳ ଅକ୍ଷର *path, ପୂର୍ଣ୍ଣସଂଖ୍ୟା expand)
{
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;
	u_int expected_id, ଗଣନା_2, id;
	ଅକ୍ଷର *filename, *longname;
	Attrib a;
	u_char type;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ଅଚଳ ଅକ୍ଷର *what = "SSH2_FXP_REALPATH";

	ଯଦି (expand)
		what = "expand-path@openssh.com";
	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");

	expected_id = id = conn->ସନ୍ଦେଶ_id++;
	ଯଦି (expand) {
		debug2("Sending SSH2_FXP_EXTENDED(expand-path@openssh.com) "
		    "\"%s\"", path);
		ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, SSH2_FXP_EXTENDED)) != 0 ||
		    (r = sshbuf_put_u32(ସନ୍ଦେଶ, id)) != 0 ||
		    (r = sshbuf_put_cstring(ସନ୍ଦେଶ,
		    "expand-path@openssh.com")) != 0 ||
		    (r = sshbuf_put_cstring(ସନ୍ଦେଶ, path)) != 0)
			fatal_fr(r, "compose %s", what);
		send_ସନ୍ଦେଶ(conn, ସନ୍ଦେଶ);
	} ଅନ୍ୟଥା {
		debug2("Sending SSH2_FXP_REALPATH \"%s\"", path);
		send_string_request(conn, id, SSH2_FXP_REALPATH,
		    path, strlen(path));
	}
	get_ସନ୍ଦେଶ(conn, ସନ୍ଦେଶ);
	ଯଦି ((r = sshbuf_get_u8(ସନ୍ଦେଶ, &type)) != 0 ||
	    (r = sshbuf_get_u32(ସନ୍ଦେଶ, &id)) != 0)
		fatal_fr(r, "parse");

	ଯଦି (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);

	ଯଦି (type == SSH2_FXP_STATUS) {
		u_int status;
		ଅକ୍ଷର *errmsg;

		ଯଦି ((r = sshbuf_get_u32(ସନ୍ଦେଶ, &status)) != 0 ||
		    (r = sshbuf_get_cstring(ସନ୍ଦେଶ, &errmsg, ଖାଲି)) != 0)
			fatal_fr(r, "parse status");
		error("%s %s: %s", expand ? "expand" : "realpath",
		    path, *errmsg == '\0' ? fx2txt(status) : errmsg);
		ମୁକ୍ତ(errmsg);
		sshbuf_free(ସନ୍ଦେଶ);
		ଫେରନ୍ତୁ ଖାଲି;
	} ଅନ୍ୟଥା ଯଦି (type != SSH2_FXP_NAME)
		fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
		    SSH2_FXP_NAME, type);

	ଯଦି ((r = sshbuf_get_u32(ସନ୍ଦେଶ, &ଗଣନା_2)) != 0)
		fatal_fr(r, "parse count");
	ଯଦି (ଗଣନା_2 != 1)
		fatal("Got multiple names (%d) from %s", ଗଣନା_2, what);

	ଯଦି ((r = sshbuf_get_cstring(ସନ୍ଦେଶ, &filename, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_cstring(ସନ୍ଦେଶ, &longname, ଖାଲି)) != 0 ||
	    (r = decode_attrib(ସନ୍ଦେଶ, &a)) != 0)
		fatal_fr(r, "parse filename/attrib");

	debug3("%s %s -> %s", what, path, filename);

	ମୁକ୍ତ(longname);

	sshbuf_free(ସନ୍ଦେଶ);

	ଫେରନ୍ତୁ(filename);
}

ଅକ୍ଷର *
sftp_realpath(ସଂରଚନା sftp_conn *conn, ଅଚଳ ଅକ୍ଷର *path)
{
	ଫେରନ୍ତୁ sftp_realpath_expand(conn, path, 0);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sftp_can_expand_path(ସଂରଚନା sftp_conn *conn)
{
	ଫେରନ୍ତୁ (conn->exts & SFTP_EXT_PATH_EXPAND) != 0;
}

ଅକ୍ଷର *
sftp_expand_path(ସଂରଚନା sftp_conn *conn, ଅଚଳ ଅକ୍ଷର *path)
{
	ଯଦି (!sftp_can_expand_path(conn)) {
		debug3_f("no server support, fallback to realpath");
		ଫେରନ୍ତୁ sftp_realpath_expand(conn, path, 0);
	}
	ଫେରନ୍ତୁ sftp_realpath_expand(conn, path, 1);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sftp_copy(ସଂରଚନା sftp_conn *conn, ଅଚଳ ଅକ୍ଷର *oldpath, ଅଚଳ ଅକ୍ଷର *newpath)
{
	Attrib junk, attr;
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;
	u_char *old_handle, *new_handle;
	u_int mode, status, id;
	size_t old_handle_len, new_handle_len;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	/* Return if the extension is not supported */
	ଯଦି ((conn->exts & SFTP_EXT_COPY_DATA) == 0) {
		error("Server does not support copy-data extension");
		ଫେରନ୍ତୁ -1;
	}

	/* Make sure the file exists, and we can copy its perms */
	ଯଦି (sftp_stat(conn, oldpath, 0, &attr) != 0)
		ଫେରନ୍ତୁ -1;

	/* Do not preserve set[ug]id here, as we do not preserve ownership */
	ଯଦି (attr.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		mode = attr.perm & 0777;

		ଯଦି (!S_ISREG(attr.perm)) {
			error("Cannot copy non-regular file: %s", oldpath);
			ଫେରନ୍ତୁ -1;
		}
	} ଅନ୍ୟଥା {
		/* NB: The user's umask will apply to this */
		mode = 0666;
	}

	/* Set up the new perms for the new file */
	attrib_clear(&attr);
	attr.perm = mode;
	attr.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;

	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");

	attrib_clear(&junk); /* Send empty attributes */

	/* Open the old file for reading */
	id = conn->ସନ୍ଦେଶ_id++;
	ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(ସନ୍ଦେଶ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ସନ୍ଦେଶ, oldpath)) != 0 ||
	    (r = sshbuf_put_u32(ସନ୍ଦେଶ, SSH2_FXF_READ)) != 0 ||
	    (r = encode_attrib(ସନ୍ଦେଶ, &junk)) != 0)
		fatal_fr(r, "buffer error");
	send_ସନ୍ଦେଶ(conn, ସନ୍ଦେଶ);
	debug3("Sent message SSH2_FXP_OPEN I:%u P:%s", id, oldpath);

	sshbuf_reset(ସନ୍ଦେଶ);

	old_handle = get_handle(conn, id, &old_handle_len,
	    "remote open(\"%s\")", oldpath);
	ଯଦି (old_handle == ଖାଲି) {
		sshbuf_free(ସନ୍ଦେଶ);
		ଫେରନ୍ତୁ -1;
	}

	/* Open the new file for writing */
	id = conn->ସନ୍ଦେଶ_id++;
	ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(ସନ୍ଦେଶ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ସନ୍ଦେଶ, newpath)) != 0 ||
	    (r = sshbuf_put_u32(ସନ୍ଦେଶ, SSH2_FXF_WRITE|SSH2_FXF_CREAT|
	    SSH2_FXF_TRUNC)) != 0 ||
	    (r = encode_attrib(ସନ୍ଦେଶ, &attr)) != 0)
		fatal_fr(r, "buffer error");
	send_ସନ୍ଦେଶ(conn, ସନ୍ଦେଶ);
	debug3("Sent message SSH2_FXP_OPEN I:%u P:%s", id, newpath);

	sshbuf_reset(ସନ୍ଦେଶ);

	new_handle = get_handle(conn, id, &new_handle_len,
	    "remote open(\"%s\")", newpath);
	ଯଦି (new_handle == ଖାଲି) {
		sshbuf_free(ସନ୍ଦେଶ);
		ମୁକ୍ତ(old_handle);
		ଫେରନ୍ତୁ -1;
	}

	/* Copy the file data */
	id = conn->ସନ୍ଦେଶ_id++;
	ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(ସନ୍ଦେଶ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ସନ୍ଦେଶ, "copy-data")) != 0 ||
	    (r = sshbuf_put_string(ସନ୍ଦେଶ, old_handle, old_handle_len)) != 0 ||
	    (r = sshbuf_put_u64(ସନ୍ଦେଶ, 0)) != 0 ||
	    (r = sshbuf_put_u64(ସନ୍ଦେଶ, 0)) != 0 ||
	    (r = sshbuf_put_string(ସନ୍ଦେଶ, new_handle, new_handle_len)) != 0 ||
	    (r = sshbuf_put_u64(ସନ୍ଦେଶ, 0)) != 0)
		fatal_fr(r, "buffer error");
	send_ସନ୍ଦେଶ(conn, ସନ୍ଦେଶ);
	debug3("Sent message copy-data \"%s\" 0 0 -> \"%s\" 0",
	       oldpath, newpath);

	status = get_status(conn, id);
	ଯଦି (status != SSH2_FX_OK)
		error("Couldn't copy file \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	/* Clean up everything */
	sshbuf_free(ସନ୍ଦେଶ);
	sftp_close(conn, old_handle, old_handle_len);
	sftp_close(conn, new_handle, new_handle_len);
	ମୁକ୍ତ(old_handle);
	ମୁକ୍ତ(new_handle);

	ଫେରନ୍ତୁ status == SSH2_FX_OK ? 0 : -1;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sftp_rename(ସଂରଚନା sftp_conn *conn, ଅଚଳ ଅକ୍ଷର *oldpath, ଅଚଳ ଅକ୍ଷର *newpath,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା force_legacy)
{
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;
	u_int status, id;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, use_ext = (conn->exts & SFTP_EXT_POSIX_RENAME) && !force_legacy;

	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");

	/* Send rename request */
	id = conn->ସନ୍ଦେଶ_id++;
	ଯଦି (use_ext) {
		debug2("Sending SSH2_FXP_EXTENDED(posix-rename@openssh.com) "
		    "\"%s\" to \"%s\"", oldpath, newpath);
		ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, SSH2_FXP_EXTENDED)) != 0 ||
		    (r = sshbuf_put_u32(ସନ୍ଦେଶ, id)) != 0 ||
		    (r = sshbuf_put_cstring(ସନ୍ଦେଶ,
		    "posix-rename@openssh.com")) != 0)
			fatal_fr(r, "compose posix-rename");
	} ଅନ୍ୟଥା {
		debug2("Sending SSH2_FXP_RENAME \"%s\" to \"%s\"",
		    oldpath, newpath);
		ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, SSH2_FXP_RENAME)) != 0 ||
		    (r = sshbuf_put_u32(ସନ୍ଦେଶ, id)) != 0)
			fatal_fr(r, "compose rename");
	}
	ଯଦି ((r = sshbuf_put_cstring(ସନ୍ଦେଶ, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(ସନ୍ଦେଶ, newpath)) != 0)
		fatal_fr(r, "compose paths");
	send_ସନ୍ଦେଶ(conn, ସନ୍ଦେଶ);
	debug3("Sent message %s \"%s\" -> \"%s\"",
	    use_ext ? "posix-rename@openssh.com" :
	    "SSH2_FXP_RENAME", oldpath, newpath);
	sshbuf_free(ସନ୍ଦେଶ);

	status = get_status(conn, id);
	ଯଦି (status != SSH2_FX_OK)
		error("remote rename \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	ଫେରନ୍ତୁ status == SSH2_FX_OK ? 0 : -1;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sftp_hardlink(ସଂରଚନା sftp_conn *conn, ଅଚଳ ଅକ୍ଷର *oldpath, ଅଚଳ ଅକ୍ଷର *newpath)
{
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;
	u_int status, id;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((conn->exts & SFTP_EXT_HARDLINK) == 0) {
		error("Server does not support hardlink@openssh.com extension");
		ଫେରନ୍ତୁ -1;
	}
	debug2("Sending SSH2_FXP_EXTENDED(hardlink@openssh.com) "
	    "\"%s\" to \"%s\"", oldpath, newpath);

	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");

	/* Send link request */
	id = conn->ସନ୍ଦେଶ_id++;
	ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(ସନ୍ଦେଶ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ସନ୍ଦେଶ, "hardlink@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(ସନ୍ଦେଶ, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(ସନ୍ଦେଶ, newpath)) != 0)
		fatal_fr(r, "compose");
	send_ସନ୍ଦେଶ(conn, ସନ୍ଦେଶ);
	debug3("Sent message hardlink@openssh.com \"%s\" -> \"%s\"",
	    oldpath, newpath);
	sshbuf_free(ସନ୍ଦେଶ);

	status = get_status(conn, id);
	ଯଦି (status != SSH2_FX_OK)
		error("remote link \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	ଫେରନ୍ତୁ status == SSH2_FX_OK ? 0 : -1;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sftp_symlink(ସଂରଚନା sftp_conn *conn, ଅଚଳ ଅକ୍ଷର *oldpath, ଅଚଳ ଅକ୍ଷର *newpath)
{
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;
	u_int status, id;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (conn->version < 3) {
		error("This server does not support the symlink operation");
		ଫେରନ୍ତୁ(SSH2_FX_OP_UNSUPPORTED);
	}
	debug2("Sending SSH2_FXP_SYMLINK \"%s\" to \"%s\"", oldpath, newpath);

	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");

	/* Send symlink request */
	id = conn->ସନ୍ଦେଶ_id++;
	ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, SSH2_FXP_SYMLINK)) != 0 ||
	    (r = sshbuf_put_u32(ସନ୍ଦେଶ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ସନ୍ଦେଶ, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(ସନ୍ଦେଶ, newpath)) != 0)
		fatal_fr(r, "compose");
	send_ସନ୍ଦେଶ(conn, ସନ୍ଦେଶ);
	debug3("Sent message SSH2_FXP_SYMLINK \"%s\" -> \"%s\"", oldpath,
	    newpath);
	sshbuf_free(ସନ୍ଦେଶ);

	status = get_status(conn, id);
	ଯଦି (status != SSH2_FX_OK)
		error("remote symlink file \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	ଫେରନ୍ତୁ status == SSH2_FX_OK ? 0 : -1;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sftp_fsync(ସଂରଚନା sftp_conn *conn, u_char *handle, u_int handle_len)
{
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;
	u_int status, id;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	/* Silently return if the extension is not supported */
	ଯଦି ((conn->exts & SFTP_EXT_FSYNC) == 0)
		ଫେରନ୍ତୁ -1;
	debug2("Sending SSH2_FXP_EXTENDED(fsync@openssh.com)");

	/* Send fsync request */
	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	id = conn->ସନ୍ଦେଶ_id++;
	ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(ସନ୍ଦେଶ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ସନ୍ଦେଶ, "fsync@openssh.com")) != 0 ||
	    (r = sshbuf_put_string(ସନ୍ଦେଶ, handle, handle_len)) != 0)
		fatal_fr(r, "compose");
	send_ସନ୍ଦେଶ(conn, ସନ୍ଦେଶ);
	debug3("Sent message fsync@openssh.com I:%u", id);
	sshbuf_free(ସନ୍ଦେଶ);

	status = get_status(conn, id);
	ଯଦି (status != SSH2_FX_OK)
		error("remote fsync: %s", fx2txt(status));

	ଫେରନ୍ତୁ status == SSH2_FX_OK ? 0 : -1;
}

#ifdef notyet
ଅକ୍ଷର *
sftp_readlink(ସଂରଚନା sftp_conn *conn, ଅଚଳ ଅକ୍ଷର *path)
{
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;
	u_int expected_id, ଗଣନା_2, id;
	ଅକ୍ଷର *filename, *longname;
	Attrib a;
	u_char type;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug2("Sending SSH2_FXP_READLINK \"%s\"", path);

	expected_id = id = conn->ସନ୍ଦେଶ_id++;
	send_string_request(conn, id, SSH2_FXP_READLINK, path, strlen(path));

	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");

	get_ସନ୍ଦେଶ(conn, ସନ୍ଦେଶ);
	ଯଦି ((r = sshbuf_get_u8(ସନ୍ଦେଶ, &type)) != 0 ||
	    (r = sshbuf_get_u32(ସନ୍ଦେଶ, &id)) != 0)
		fatal_fr(r, "parse");

	ଯଦି (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);

	ଯଦି (type == SSH2_FXP_STATUS) {
		u_int status;

		ଯଦି ((r = sshbuf_get_u32(ସନ୍ଦେଶ, &status)) != 0)
			fatal_fr(r, "parse status");
		error("Couldn't readlink: %s", fx2txt(status));
		sshbuf_free(ସନ୍ଦେଶ);
		ଫେରନ୍ତୁ(ଖାଲି);
	} ଅନ୍ୟଥା ଯଦି (type != SSH2_FXP_NAME)
		fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
		    SSH2_FXP_NAME, type);

	ଯଦି ((r = sshbuf_get_u32(ସନ୍ଦେଶ, &ଗଣନା_2)) != 0)
		fatal_fr(r, "parse count");
	ଯଦି (ଗଣନା_2 != 1)
		fatal("Got multiple names (%d) from SSH_FXP_READLINK", ଗଣନା_2);

	ଯଦି ((r = sshbuf_get_cstring(ସନ୍ଦେଶ, &filename, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_cstring(ସନ୍ଦେଶ, &longname, ଖାଲି)) != 0 ||
	    (r = decode_attrib(ସନ୍ଦେଶ, &a)) != 0)
		fatal_fr(r, "parse filenames/attrib");

	debug3("SSH_FXP_READLINK %s -> %s", path, filename);

	ମୁକ୍ତ(longname);

	sshbuf_free(ସନ୍ଦେଶ);

	ଫେରନ୍ତୁ filename;
}
#endif

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sftp_statvfs(ସଂରଚନା sftp_conn *conn, ଅଚଳ ଅକ୍ଷର *path, ସଂରଚନା sftp_statvfs *st,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା quiet)
{
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;
	u_int id;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((conn->exts & SFTP_EXT_STATVFS) == 0) {
		error("Server does not support statvfs@openssh.com extension");
		ଫେରନ୍ତୁ -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(statvfs@openssh.com) \"%s\"", path);

	id = conn->ସନ୍ଦେଶ_id++;

	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(ସନ୍ଦେଶ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ସନ୍ଦେଶ, "statvfs@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(ସନ୍ଦେଶ, path)) != 0)
		fatal_fr(r, "compose");
	send_ସନ୍ଦେଶ(conn, ସନ୍ଦେଶ);
	sshbuf_free(ସନ୍ଦେଶ);

	ଫେରନ୍ତୁ get_decode_statvfs(conn, st, id, quiet);
}

#ifdef notyet
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sftp_fstatvfs(ସଂରଚନା sftp_conn *conn, ଅଚଳ u_char *handle, u_int handle_len,
    ସଂରଚନା sftp_statvfs *st, ପୂର୍ଣ୍ଣସଂଖ୍ୟା quiet)
{
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;
	u_int id;

	ଯଦି ((conn->exts & SFTP_EXT_FSTATVFS) == 0) {
		error("Server does not support fstatvfs@openssh.com extension");
		ଫେରନ୍ତୁ -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(fstatvfs@openssh.com)");

	id = conn->ସନ୍ଦେଶ_id++;

	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(ସନ୍ଦେଶ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ସନ୍ଦେଶ, "fstatvfs@openssh.com")) != 0 ||
	    (r = sshbuf_put_string(ସନ୍ଦେଶ, handle, handle_len)) != 0)
		fatal_fr(r, "compose");
	send_ସନ୍ଦେଶ(conn, ସନ୍ଦେଶ);
	sshbuf_free(ସନ୍ଦେଶ);

	ଫେରନ୍ତୁ get_decode_statvfs(conn, st, id, quiet);
}
#endif

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sftp_lsetstat(ସଂରଚନା sftp_conn *conn, ଅଚଳ ଅକ୍ଷର *path, Attrib *a)
{
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;
	u_int status, id;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((conn->exts & SFTP_EXT_LSETSTAT) == 0) {
		error("Server does not support lsetstat@openssh.com extension");
		ଫେରନ୍ତୁ -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(lsetstat@openssh.com) \"%s\"", path);

	id = conn->ସନ୍ଦେଶ_id++;
	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(ସନ୍ଦେଶ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ସନ୍ଦେଶ, "lsetstat@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(ସନ୍ଦେଶ, path)) != 0 ||
	    (r = encode_attrib(ସନ୍ଦେଶ, a)) != 0)
		fatal_fr(r, "compose");
	send_ସନ୍ଦେଶ(conn, ସନ୍ଦେଶ);
	sshbuf_free(ସନ୍ଦେଶ);

	status = get_status(conn, id);
	ଯଦି (status != SSH2_FX_OK)
		error("remote lsetstat \"%s\": %s", path, fx2txt(status));

	ଫେରନ୍ତୁ status == SSH2_FX_OK ? 0 : -1;
}

ସ୍ଥିର ଶୂନ୍ୟ
send_read_request(ସଂରଚନା sftp_conn *conn, u_int id, uint64_t offset,
    u_int len, ଅଚଳ u_char *handle, u_int handle_len)
{
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, SSH2_FXP_READ)) != 0 ||
	    (r = sshbuf_put_u32(ସନ୍ଦେଶ, id)) != 0 ||
	    (r = sshbuf_put_string(ସନ୍ଦେଶ, handle, handle_len)) != 0 ||
	    (r = sshbuf_put_u64(ସନ୍ଦେଶ, offset)) != 0 ||
	    (r = sshbuf_put_u32(ସନ୍ଦେଶ, len)) != 0)
		fatal_fr(r, "compose");
	send_ସନ୍ଦେଶ(conn, ସନ୍ଦେଶ);
	sshbuf_free(ସନ୍ଦେଶ);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
send_open(ସଂରଚନା sftp_conn *conn, ଅଚଳ ଅକ୍ଷର *path, ଅଚଳ ଅକ୍ଷର *tag,
    u_int openmode, Attrib *a, u_char **handlep, size_t *handle_lenp)
{
	Attrib junk;
	u_char *handle;
	size_t handle_len;
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_int id;

	debug2("Sending SSH2_FXP_OPEN \"%s\"", path);

	*handlep = ଖାଲି;
	*handle_lenp = 0;

	ଯଦି (a == ଖାଲି) {
		attrib_clear(&junk); /* Send empty attributes */
		a = &junk;
	}
	/* Send open request */
	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	id = conn->ସନ୍ଦେଶ_id++;
	ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(ସନ୍ଦେଶ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ସନ୍ଦେଶ, path)) != 0 ||
	    (r = sshbuf_put_u32(ସନ୍ଦେଶ, openmode)) != 0 ||
	    (r = encode_attrib(ସନ୍ଦେଶ, a)) != 0)
		fatal_fr(r, "compose %s open", tag);
	send_ସନ୍ଦେଶ(conn, ସନ୍ଦେଶ);
	sshbuf_free(ସନ୍ଦେଶ);
	debug3("Sent %s message SSH2_FXP_OPEN I:%u P:%s M:0x%04x",
	    tag, id, path, openmode);
	ଯଦି ((handle = get_handle(conn, id, &handle_len,
	    "%s open \"%s\"", tag, path)) == ଖାଲି)
		ଫେରନ୍ତୁ -1;
	/* success */
	*handlep = handle;
	*handle_lenp = handle_len;
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ଅଚଳ ଅକ୍ଷର *
progress_meter_path(ଅଚଳ ଅକ୍ଷର *path)
{
	ଅଚଳ ଅକ୍ଷର *progresspath;

	ଯଦି ((progresspath = strrchr(path, '/')) == ଖାଲି)
		ଫେରନ୍ତୁ path;
	progresspath++;
	ଯଦି (*progresspath == '\0')
		ଫେରନ୍ତୁ path;
	ଫେରନ୍ତୁ progresspath;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sftp_download(ସଂରଚନା sftp_conn *conn, ଅଚଳ ଅକ୍ଷର *remote_path,
    ଅଚଳ ଅକ୍ଷର *local_path, Attrib *a, ପୂର୍ଣ୍ଣସଂଖ୍ୟା preserve_flag, ପୂର୍ଣ୍ଣସଂଖ୍ୟା resume_flag,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା fsync_flag, ପୂର୍ଣ୍ଣସଂଖ୍ୟା inplace_flag)
{
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;
	u_char *handle;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା local_fd = -1, write_error, seen_zerolen = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା read_error, write_errno, lmodified = 0, reordered = 0, r;
	uint64_t offset = 0, size, highwater = 0, maxack = 0;
	u_int mode, id, buflen, ଅଙ୍କ_req, max_req, status = SSH2_FX_OK;
	off_t progress_counter;
	size_t handle_len;
	ସଂରଚନା stat st;
	ସଂରଚନା requests requests;
	ସଂରଚନା request *req;
	u_char type;
	Attrib attr;

	debug2_f("download remote \"%s\" to local \"%s\"",
	    remote_path, local_path);

	TAILQ_INIT(&requests);

	ଯଦି (a == ଖାଲି) {
		ଯଦି (sftp_stat(conn, remote_path, 0, &attr) != 0)
			ଫେରନ୍ତୁ -1;
		a = &attr;
	}

	/* Do not preserve set[ug]id here, as we do not preserve ownership */
	ଯଦି (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS)
		mode = a->perm & 0777;
	ଅନ୍ୟଥା
		mode = 0666;

	ଯଦି ((a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) &&
	    (!S_ISREG(a->perm))) {
		error("download %s: not a regular file", remote_path);
		ଫେରନ୍ତୁ(-1);
	}

	ଯଦି (a->flags & SSH2_FILEXFER_ATTR_SIZE)
		size = a->size;
	ଅନ୍ୟଥା
		size = 0;

	buflen = conn->download_buflen;

	/* Send open request */
	ଯଦି (send_open(conn, remote_path, "remote", SSH2_FXF_READ, ଖାଲି,
	    &handle, &handle_len) != 0)
		ଫେରନ୍ତୁ -1;

	local_fd = open(local_path, O_WRONLY | O_CREAT |
	((resume_flag || inplace_flag) ? 0 : O_TRUNC), mode | S_IWUSR);
	ଯଦି (local_fd == -1) {
		error("open local \"%s\": %s", local_path, strerror(errno));
		ଯାଅ fail;
	}
	ଯଦି (resume_flag) {
		ଯଦି (fstat(local_fd, &st) == -1) {
			error("stat local \"%s\": %s",
			    local_path, strerror(errno));
			ଯାଅ fail;
		}
		ଯଦି (st.st_size < 0) {
			error("\"%s\" has negative size", local_path);
			ଯାଅ fail;
		}
		ଯଦି ((uint64_t)st.st_size > size) {
			error("Unable to resume download of \"%s\": "
			    "local file is larger than remote", local_path);
 fail:
			sftp_close(conn, handle, handle_len);
			ମୁକ୍ତ(handle);
			ଯଦି (local_fd != -1)
				close(local_fd);
			ଫେରନ୍ତୁ -1;
		}
		offset = highwater = maxack = st.st_size;
	}

	/* Read from remote and write to local */
	write_error = read_error = write_errno = ଅଙ୍କ_req = 0;
	max_req = 1;
	progress_counter = offset;

	ଯଦି (showprogress && size != 0) {
		start_progress_meter(progress_meter_path(remote_path),
		    size, &progress_counter);
	}

	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");

	ଯେତେବେଳେ (ଅଙ୍କ_req > 0 || max_req > 0) {
		u_char *data;
		size_t len;

		/*
		 * Simulate EOF on interrupt: stop sending new requests and
		 * allow outstanding requests to drain gracefully
		 */
		ଯଦି (interrupted) {
			ଯଦି (ଅଙ୍କ_req == 0) /* If we haven't started yet... */
				ଭାଙ୍ଗ;
			max_req = 0;
		}

		/* Send some more requests */
		ଯେତେବେଳେ (ଅଙ୍କ_req < max_req) {
			debug3("Request range %llu -> %llu (%d/%d)",
			    (unsigned long long)offset,
			    (unsigned long long)offset + buflen - 1,
			    ଅଙ୍କ_req, max_req);
			req = request_enqueue(&requests, conn->ସନ୍ଦେଶ_id++,
			    buflen, offset);
			offset += buflen;
			ଅଙ୍କ_req++;
			send_read_request(conn, req->id, req->offset,
			    req->len, handle, handle_len);
		}

		sshbuf_reset(ସନ୍ଦେଶ);
		get_ସନ୍ଦେଶ(conn, ସନ୍ଦେଶ);
		ଯଦି ((r = sshbuf_get_u8(ସନ୍ଦେଶ, &type)) != 0 ||
		    (r = sshbuf_get_u32(ସନ୍ଦେଶ, &id)) != 0)
			fatal_fr(r, "parse");
		debug3("Received reply T:%u I:%u R:%d", type, id, max_req);

		/* Find the request in our queue */
		ଯଦି ((req = request_find(&requests, id)) == ଖାଲି)
			fatal("Unexpected reply %u", id);

		ବାଛ (type) {
		ସ୍ଥିତି SSH2_FXP_STATUS:
			ଯଦି ((r = sshbuf_get_u32(ସନ୍ଦେଶ, &status)) != 0)
				fatal_fr(r, "parse status");
			ଯଦି (status != SSH2_FX_EOF)
				read_error = 1;
			max_req = 0;
			TAILQ_REMOVE(&requests, req, tq);
			ମୁକ୍ତ(req);
			ଅଙ୍କ_req--;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି SSH2_FXP_DATA:
			ଯଦି ((r = sshbuf_get_string(ସନ୍ଦେଶ, &data, &len)) != 0)
				fatal_fr(r, "parse data");
			debug3("Received data %llu -> %llu",
			    (unsigned long long)req->offset,
			    (unsigned long long)req->offset + len - 1);
			ଯଦି (len > req->len)
				fatal("Received more data than asked for "
				    "%zu > %zu", len, req->len);
			ଯଦି (len == 0) {
				ଯଦି (seen_zerolen)
					fatal_f("server sent zero data length");
				seen_zerolen = 1;
			}
			lmodified = 1;
			ଯଦି ((lseek(local_fd, req->offset, SEEK_SET) == -1 ||
			    atomicio(vwrite, local_fd, data, len) != len) &&
			    !write_error) {
				write_errno = errno;
				write_error = 1;
				max_req = 0;
			} ଅନ୍ୟଥା {
				/*
				 * Track both the highest offset acknowledged
				 * and the highest *contiguous* offset
				 * acknowledged.
				 * We'll need the latter for ftruncate()ing
				 * interrupted transfers.
				 */
				ଯଦି (maxack < req->offset + len)
					maxack = req->offset + len;
				ଯଦି (!reordered && req->offset <= highwater)
					highwater = maxack;
				ଅନ୍ୟଥା ଯଦି (!reordered && req->offset > highwater)
					reordered = 1;
			}
			progress_counter += len;
			ମୁକ୍ତ(data);

			ଯଦି (len == req->len) {
				TAILQ_REMOVE(&requests, req, tq);
				ମୁକ୍ତ(req);
				ଅଙ୍କ_req--;
			} ଅନ୍ୟଥା {
				/* Resend the request for the missing data */
				debug3("Short data block, re-requesting "
				    "%llu -> %llu (%2d)",
				    (unsigned long long)req->offset + len,
				    (unsigned long long)req->offset +
				    req->len - 1, ଅଙ୍କ_req);
				req->id = conn->ସନ୍ଦେଶ_id++;
				req->len -= len;
				req->offset += len;
				send_read_request(conn, req->id,
				    req->offset, req->len, handle, handle_len);
				/* Reduce the request size */
				ଯଦି (len < buflen)
					buflen = MAXIMUM(MIN_READ_SIZE, len);
			}
			ଯଦି (max_req > 0) { /* max_req = 0 iff EOF received */
				ଯଦି (size > 0 && offset > size) {
					/* Only one request at a time
					 * after the expected EOF */
					debug3("Finish at %llu (%2d)",
					    (unsigned long long)offset,
					    ଅଙ୍କ_req);
					max_req = 1;
				} ଅନ୍ୟଥା ଯଦି (max_req < conn->ଅଙ୍କ_requests) {
					++max_req;
				}
			}
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			fatal("Expected SSH2_FXP_DATA(%u) packet, got %u",
			    SSH2_FXP_DATA, type);
		}
	}

	ଯଦି (showprogress && size)
		stop_progress_meter();

	/* Sanity check */
	ଯଦି (TAILQ_FIRST(&requests) != ଖାଲି)
		fatal("Transfer complete, but requests still in queue");

	ଯଦି (!read_error && !write_error && !interrupted) {
		/* we got everything */
		highwater = maxack;
	}

	/*
	 * Truncate at highest contiguous point to avoid holes on interrupt,
	 * or unconditionally if writing in place.
	 */
	ଯଦି (inplace_flag || read_error || write_error || interrupted) {
		ଯଦି (reordered && resume_flag &&
		    (read_error || write_error || interrupted)) {
			error("Unable to resume download of \"%s\": "
			    "server reordered requests", local_path);
		}
		debug("truncating at %llu", (unsigned long long)highwater);
		ଯଦି (ftruncate(local_fd, highwater) == -1)
			error("local ftruncate \"%s\": %s", local_path,
			    strerror(errno));
	}
	ଯଦି (read_error) {
		error("read remote \"%s\" : %s", remote_path, fx2txt(status));
		status = -1;
		sftp_close(conn, handle, handle_len);
	} ଅନ୍ୟଥା ଯଦି (write_error) {
		error("write local \"%s\": %s", local_path,
		    strerror(write_errno));
		status = SSH2_FX_FAILURE;
		sftp_close(conn, handle, handle_len);
	} ଅନ୍ୟଥା {
		ଯଦି (sftp_close(conn, handle, handle_len) != 0 || interrupted)
			status = SSH2_FX_FAILURE;
		ଅନ୍ୟଥା
			status = SSH2_FX_OK;
		/* Override umask and utimes if asked */
#ifdef HAVE_FCHMOD
		ଯଦି (preserve_flag && fchmod(local_fd, mode) == -1)
#ଅନ୍ୟଥା
		ଯଦି (preserve_flag && chmod(local_path, mode) == -1)
#endif /* HAVE_FCHMOD */
			error("local chmod \"%s\": %s", local_path,
			    strerror(errno));
		ଯଦି (preserve_flag &&
		    (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME)) {
			ସଂରଚନା timeval tv[2];
			tv[0].tv_sec = a->atime;
			tv[1].tv_sec = a->mtime;
			tv[0].tv_usec = tv[1].tv_usec = 0;
			ଯଦି (utimes(local_path, tv) == -1)
				error("local set times \"%s\": %s",
				    local_path, strerror(errno));
		}
		ଯଦି (resume_flag && !lmodified)
			logit("File \"%s\" was not modified", local_path);
		ଅନ୍ୟଥା ଯଦି (fsync_flag) {
			debug("syncing \"%s\"", local_path);
			ଯଦି (fsync(local_fd) == -1)
				error("local sync \"%s\": %s",
				    local_path, strerror(errno));
		}
	}
	close(local_fd);
	sshbuf_free(ସନ୍ଦେଶ);
	ମୁକ୍ତ(handle);

	ଫେରନ୍ତୁ status == SSH2_FX_OK ? 0 : -1;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
download_dir_internal(ସଂରଚନା sftp_conn *conn, ଅଚଳ ଅକ୍ଷର *src, ଅଚଳ ଅକ୍ଷର *dst,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା depth, Attrib *dirattrib, ପୂର୍ଣ୍ଣସଂଖ୍ୟା preserve_flag, ପୂର୍ଣ୍ଣସଂଖ୍ୟା print_flag,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା resume_flag, ପୂର୍ଣ୍ଣସଂଖ୍ୟା fsync_flag, ପୂର୍ଣ୍ଣସଂଖ୍ୟା follow_link_flag, ପୂର୍ଣ୍ଣସଂଖ୍ୟା inplace_flag)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, ret = 0;
	SFTP_DIRENT **dir_entries;
	ଅକ୍ଷର *filename, *new_src = ଖାଲି, *new_dst = ଖାଲି;
	mode_t mode = 0777, tmpmode = mode;
	Attrib *a, ldirattrib, lsym;

	ଯଦି (depth >= MAX_DIR_DEPTH) {
		error("Maximum directory depth exceeded: %d levels", depth);
		ଫେରନ୍ତୁ -1;
	}

	debug2_f("download dir remote \"%s\" to local \"%s\"", src, dst);

	ଯଦି (dirattrib == ଖାଲି) {
		ଯଦି (sftp_stat(conn, src, 1, &ldirattrib) != 0) {
			error("stat remote \"%s\" directory failed", src);
			ଫେରନ୍ତୁ -1;
		}
		dirattrib = &ldirattrib;
	}
	ଯଦି (!S_ISDIR(dirattrib->perm)) {
		error("\"%s\" is not a directory", src);
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି (print_flag && print_flag != SFTP_PROGRESS_ONLY)
		mprintf("Retrieving %s\n", src);

	ଯଦି (dirattrib->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		mode = dirattrib->perm & 01777;
		tmpmode = mode | (S_IWUSR|S_IXUSR);
	} ଅନ୍ୟଥା {
		debug("download remote \"%s\": server "
		    "did not send permissions", dst);
	}

	ଯଦି (mkdir(dst, tmpmode) == -1 && errno != EEXIST) {
		error("mkdir %s: %s", dst, strerror(errno));
		ଫେରନ୍ତୁ -1;
	}

	ଯଦି (sftp_readdir(conn, src, &dir_entries) == -1) {
		error("remote readdir \"%s\" failed", src);
		ଫେରନ୍ତୁ -1;
	}

	ପାଇଁ (i = 0; dir_entries[i] != ଖାଲି && !interrupted; i++) {
		ମୁକ୍ତ(new_dst);
		ମୁକ୍ତ(new_src);

		filename = dir_entries[i]->filename;
		new_dst = sftp_path_append(dst, filename);
		new_src = sftp_path_append(src, filename);

		a = &dir_entries[i]->a;
		ଯଦି (S_ISLNK(a->perm)) {
			ଯଦି (!follow_link_flag) {
				logit("download \"%s\": not a regular file",
				    new_src);
				ଜାରି;
			}
			/* Replace the stat contents with the symlink target */
			ଯଦି (sftp_stat(conn, new_src, 1, &lsym) != 0) {
				logit("remote stat \"%s\" failed", new_src);
				ret = -1;
				ଜାରି;
			}
			a = &lsym;
		}

		ଯଦି (S_ISDIR(a->perm)) {
			ଯଦି (strcmp(filename, ".") == 0 ||
			    strcmp(filename, "..") == 0)
				ଜାରି;
			ଯଦି (download_dir_internal(conn, new_src, new_dst,
			    depth + 1, a, preserve_flag,
			    print_flag, resume_flag,
			    fsync_flag, follow_link_flag, inplace_flag) == -1)
				ret = -1;
		} ଅନ୍ୟଥା ଯଦି (S_ISREG(a->perm)) {
			ଯଦି (sftp_download(conn, new_src, new_dst, a,
			    preserve_flag, resume_flag, fsync_flag,
			    inplace_flag) == -1) {
				error("Download of file %s to %s failed",
				    new_src, new_dst);
				ret = -1;
			}
		} ଅନ୍ୟଥା
			logit("download \"%s\": not a regular file", new_src);

	}
	ମୁକ୍ତ(new_dst);
	ମୁକ୍ତ(new_src);

	ଯଦି (preserve_flag) {
		ଯଦି (dirattrib->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
			ସଂରଚନା timeval tv[2];
			tv[0].tv_sec = dirattrib->atime;
			tv[1].tv_sec = dirattrib->mtime;
			tv[0].tv_usec = tv[1].tv_usec = 0;
			ଯଦି (utimes(dst, tv) == -1)
				error("local set times on \"%s\": %s",
				    dst, strerror(errno));
		} ଅନ୍ୟଥା
			debug("Server did not send times for directory "
			    "\"%s\"", dst);
	}

	ଯଦି (mode != tmpmode && chmod(dst, mode) == -1)
		error("local chmod directory \"%s\": %s", dst,
		    strerror(errno));

	sftp_free_dirents(dir_entries);

	ଫେରନ୍ତୁ ret;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sftp_download_dir(ସଂରଚନା sftp_conn *conn, ଅଚଳ ଅକ୍ଷର *src, ଅଚଳ ଅକ୍ଷର *dst,
    Attrib *dirattrib, ପୂର୍ଣ୍ଣସଂଖ୍ୟା preserve_flag, ପୂର୍ଣ୍ଣସଂଖ୍ୟା print_flag, ପୂର୍ଣ୍ଣସଂଖ୍ୟା resume_flag,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା fsync_flag, ପୂର୍ଣ୍ଣସଂଖ୍ୟା follow_link_flag, ପୂର୍ଣ୍ଣସଂଖ୍ୟା inplace_flag)
{
	ଅକ୍ଷର *src_canon;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret;

	ଯଦି ((src_canon = sftp_realpath(conn, src)) == ଖାଲି) {
		error("download \"%s\": path canonicalization failed", src);
		ଫେରନ୍ତୁ -1;
	}

	ret = download_dir_internal(conn, src_canon, dst, 0,
	    dirattrib, preserve_flag, print_flag, resume_flag, fsync_flag,
	    follow_link_flag, inplace_flag);
	ମୁକ୍ତ(src_canon);
	ଫେରନ୍ତୁ ret;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sftp_upload(ସଂରଚନା sftp_conn *conn, ଅଚଳ ଅକ୍ଷର *local_path,
    ଅଚଳ ଅକ୍ଷର *remote_path, ପୂର୍ଣ୍ଣସଂଖ୍ୟା preserve_flag, ପୂର୍ଣ୍ଣସଂଖ୍ୟା resume,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା fsync_flag, ପୂର୍ଣ୍ଣସଂଖ୍ୟା inplace_flag)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, local_fd;
	u_int openmode, id, status = SSH2_FX_OK, status2, reordered = 0;
	off_t offset, progress_counter;
	u_char type, *handle, *data;
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;
	ସଂରଚନା stat sb;
	Attrib a, t, c;
	uint32_t startid, ackid;
	uint64_t highwater = 0, maxack = 0;
	ସଂରଚନା request *ack = ଖାଲି;
	ସଂରଚନା requests acks;
	size_t handle_len;

	debug2_f("upload local \"%s\" to remote \"%s\"",
	    local_path, remote_path);

	TAILQ_INIT(&acks);

	ଯଦି ((local_fd = open(local_path, O_RDONLY)) == -1) {
		error("open local \"%s\": %s", local_path, strerror(errno));
		ଫେରନ୍ତୁ(-1);
	}
	ଯଦି (fstat(local_fd, &sb) == -1) {
		error("fstat local \"%s\": %s", local_path, strerror(errno));
		close(local_fd);
		ଫେରନ୍ତୁ(-1);
	}
	ଯଦି (!S_ISREG(sb.st_mode)) {
		error("local \"%s\" is not a regular file", local_path);
		close(local_fd);
		ଫେରନ୍ତୁ(-1);
	}
	stat_to_attrib(&sb, &a);

	a.flags &= ~SSH2_FILEXFER_ATTR_SIZE;
	a.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a.perm &= 0777;
	ଯଦି (!preserve_flag)
		a.flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;

	ଯଦି (resume) {
		/* Get remote file size if it exists */
		ଯଦି (sftp_stat(conn, remote_path, 0, &c) != 0) {
			close(local_fd);
			ଫେରନ୍ତୁ -1;
		}

		ଯଦି ((off_t)c.size >= sb.st_size) {
			error("resume \"%s\": destination file "
			    "same size or larger", local_path);
			close(local_fd);
			ଫେରନ୍ତୁ -1;
		}

		ଯଦି (lseek(local_fd, (off_t)c.size, SEEK_SET) == -1) {
			close(local_fd);
			ଫେରନ୍ତୁ -1;
		}
		highwater = c.size;
	}

	openmode = SSH2_FXF_WRITE|SSH2_FXF_CREAT;
	ଯଦି (resume)
		openmode |= SSH2_FXF_APPEND;
	ଅନ୍ୟଥା ଯଦି (!inplace_flag)
		openmode |= SSH2_FXF_TRUNC;

	/* Send open request */
	ଯଦି (send_open(conn, remote_path, "dest", openmode, &a,
	    &handle, &handle_len) != 0) {
		close(local_fd);
		ଫେରନ୍ତୁ -1;
	}

	id = conn->ସନ୍ଦେଶ_id;
	startid = ackid = id + 1;
	data = xmalloc(conn->upload_buflen);

	/* Read from local and write to remote */
	offset = progress_counter = (resume ? c.size : 0);
	ଯଦି (showprogress) {
		start_progress_meter(progress_meter_path(local_path),
		    sb.st_size, &progress_counter);
	}

	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ପାଇଁ (;;) {
		ପୂର୍ଣ୍ଣସଂଖ୍ୟା len;

		/*
		 * Can't use atomicio here because it returns 0 on EOF,
		 * thus losing the last block of the file.
		 * Simulate an EOF on interrupt, allowing ACKs from the
		 * server to drain.
		 */
		ଯଦି (interrupted || status != SSH2_FX_OK)
			len = 0;
		ଅନ୍ୟଥା କର
			len = ପଠ(local_fd, data, conn->upload_buflen);
		ଯେତେବେଳେ ((len == -1) &&
		    (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK));

		ଯଦି (len == -1) {
			fatal("read local \"%s\": %s",
			    local_path, strerror(errno));
		} ଅନ୍ୟଥା ଯଦି (len != 0) {
			ack = request_enqueue(&acks, ++id, len, offset);
			sshbuf_reset(ସନ୍ଦେଶ);
			ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, SSH2_FXP_WRITE)) != 0 ||
			    (r = sshbuf_put_u32(ସନ୍ଦେଶ, ack->id)) != 0 ||
			    (r = sshbuf_put_string(ସନ୍ଦେଶ, handle,
			    handle_len)) != 0 ||
			    (r = sshbuf_put_u64(ସନ୍ଦେଶ, offset)) != 0 ||
			    (r = sshbuf_put_string(ସନ୍ଦେଶ, data, len)) != 0)
				fatal_fr(r, "compose");
			send_ସନ୍ଦେଶ(conn, ସନ୍ଦେଶ);
			debug3("Sent message SSH2_FXP_WRITE I:%u O:%llu S:%u",
			    id, (unsigned long long)offset, len);
		} ଅନ୍ୟଥା ଯଦି (TAILQ_FIRST(&acks) == ଖାଲି)
			ଭାଙ୍ଗ;

		ଯଦି (ack == ଖାଲି)
			fatal("Unexpected ACK %u", id);

		ଯଦି (id == startid || len == 0 ||
		    id - ackid >= conn->ଅଙ୍କ_requests) {
			u_int rid;

			sshbuf_reset(ସନ୍ଦେଶ);
			get_ସନ୍ଦେଶ(conn, ସନ୍ଦେଶ);
			ଯଦି ((r = sshbuf_get_u8(ସନ୍ଦେଶ, &type)) != 0 ||
			    (r = sshbuf_get_u32(ସନ୍ଦେଶ, &rid)) != 0)
				fatal_fr(r, "parse");

			ଯଦି (type != SSH2_FXP_STATUS)
				fatal("Expected SSH2_FXP_STATUS(%d) packet, "
				    "got %d", SSH2_FXP_STATUS, type);

			ଯଦି ((r = sshbuf_get_u32(ସନ୍ଦେଶ, &status2)) != 0)
				fatal_fr(r, "parse status");
			debug3("SSH2_FXP_STATUS %u", status2);
			ଯଦି (status2 != SSH2_FX_OK)
				status = status2; /* remember errors */

			/* Find the request in our queue */
			ଯଦି ((ack = request_find(&acks, rid)) == ଖାଲି)
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
			ଯଦି (maxack < ack->offset + ack->len)
				maxack = ack->offset + ack->len;
			ଯଦି (!reordered && ack->offset <= highwater)
				highwater = maxack;
			ଅନ୍ୟଥା ଯଦି (!reordered && ack->offset > highwater) {
				debug3_f("server reordered ACKs");
				reordered = 1;
			}
			ମୁକ୍ତ(ack);
		}
		offset += len;
		ଯଦି (offset < 0)
			fatal_f("offset < 0");
	}
	sshbuf_free(ସନ୍ଦେଶ);

	ଯଦି (showprogress)
		stop_progress_meter();
	ମୁକ୍ତ(data);

	ଯଦି (status == SSH2_FX_OK && !interrupted) {
		/* we got everything */
		highwater = maxack;
	}
	ଯଦି (status != SSH2_FX_OK) {
		error("write remote \"%s\": %s", remote_path, fx2txt(status));
		status = SSH2_FX_FAILURE;
	}

	ଯଦି (inplace_flag || (resume && (status != SSH2_FX_OK || interrupted))) {
		debug("truncating at %llu", (unsigned long long)highwater);
		attrib_clear(&t);
		t.flags = SSH2_FILEXFER_ATTR_SIZE;
		t.size = highwater;
		sftp_fsetstat(conn, handle, handle_len, &t);
	}

	ଯଦି (close(local_fd) == -1) {
		error("close local \"%s\": %s", local_path, strerror(errno));
		status = SSH2_FX_FAILURE;
	}

	/* Override umask and utimes if asked */
	ଯଦି (preserve_flag)
		sftp_fsetstat(conn, handle, handle_len, &a);

	ଯଦି (fsync_flag)
		(ଶୂନ୍ୟ)sftp_fsync(conn, handle, handle_len);

	ଯଦି (sftp_close(conn, handle, handle_len) != 0)
		status = SSH2_FX_FAILURE;

	ମୁକ୍ତ(handle);

	ଫେରନ୍ତୁ status == SSH2_FX_OK ? 0 : -1;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
upload_dir_internal(ସଂରଚନା sftp_conn *conn, ଅଚଳ ଅକ୍ଷର *src, ଅଚଳ ଅକ୍ଷର *dst,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା depth, ପୂର୍ଣ୍ଣସଂଖ୍ୟା preserve_flag, ପୂର୍ଣ୍ଣସଂଖ୍ୟା print_flag, ପୂର୍ଣ୍ଣସଂଖ୍ୟା resume, ପୂର୍ଣ୍ଣସଂଖ୍ୟା fsync_flag,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା follow_link_flag, ପୂର୍ଣ୍ଣସଂଖ୍ୟା inplace_flag)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା created = 0, ret = 0;
	DIR *dirp;
	ସଂରଚନା dirent *dp;
	ଅକ୍ଷର *filename, *new_src = ଖାଲି, *new_dst = ଖାଲି;
	ସଂରଚନା stat sb;
	Attrib a, dirattrib;
	uint32_t saved_perm;

	debug2_f("upload local dir \"%s\" to remote \"%s\"", src, dst);

	ଯଦି (depth >= MAX_DIR_DEPTH) {
		error("Maximum directory depth exceeded: %d levels", depth);
		ଫେରନ୍ତୁ -1;
	}

	ଯଦି (stat(src, &sb) == -1) {
		error("stat local \"%s\": %s", src, strerror(errno));
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି (!S_ISDIR(sb.st_mode)) {
		error("\"%s\" is not a directory", src);
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି (print_flag && print_flag != SFTP_PROGRESS_ONLY)
		mprintf("Entering %s\n", src);

	stat_to_attrib(&sb, &a);
	a.flags &= ~SSH2_FILEXFER_ATTR_SIZE;
	a.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a.perm &= 01777;
	ଯଦି (!preserve_flag)
		a.flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;

	/*
	 * sftp lacks a portable status value to match errno EEXIST,
	 * so if we get a failure back then we must check whether
	 * the path already existed and is a directory.  Ensure we can
	 * write to the directory we create for the duration of the transfer.
	 */
	saved_perm = a.perm;
	a.perm |= (S_IWUSR|S_IXUSR);
	ଯଦି (sftp_mkdir(conn, dst, &a, 0) == 0)
		created = 1;
	ଅନ୍ୟଥା {
		ଯଦି (sftp_stat(conn, dst, 0, &dirattrib) != 0)
			ଫେରନ୍ତୁ -1;
		ଯଦି (!S_ISDIR(dirattrib.perm)) {
			error("\"%s\" exists but is not a directory", dst);
			ଫେରନ୍ତୁ -1;
		}
	}
	a.perm = saved_perm;

	ଯଦି ((dirp = opendir(src)) == ଖାଲି) {
		error("local opendir \"%s\": %s", src, strerror(errno));
		ଫେରନ୍ତୁ -1;
	}

	ଯେତେବେଳେ (((dp = readdir(dirp)) != ଖାଲି) && !interrupted) {
		ଯଦି (dp->d_ino == 0)
			ଜାରି;
		ମୁକ୍ତ(new_dst);
		ମୁକ୍ତ(new_src);
		filename = dp->d_name;
		new_dst = sftp_path_append(dst, filename);
		new_src = sftp_path_append(src, filename);

		ଯଦି (strcmp(filename, ".") == 0 || strcmp(filename, "..") == 0)
			ଜାରି;
		ଯଦି (lstat(new_src, &sb) == -1) {
			logit("local lstat \"%s\": %s", filename,
			    strerror(errno));
			ret = -1;
			ଜାରି;
		}
		ଯଦି (S_ISLNK(sb.st_mode)) {
			ଯଦି (!follow_link_flag) {
				logit("%s: not a regular file", filename);
				ଜାରି;
			}
			/* Replace the stat contents with the symlink target */
			ଯଦି (stat(new_src, &sb) == -1) {
				logit("local stat \"%s\": %s", filename,
				    strerror(errno));
				ret = -1;
				ଜାରି;
			}
		}
		ଯଦି (S_ISDIR(sb.st_mode)) {
			ଯଦି (upload_dir_internal(conn, new_src, new_dst,
			    depth + 1, preserve_flag, print_flag, resume,
			    fsync_flag, follow_link_flag, inplace_flag) == -1)
				ret = -1;
		} ଅନ୍ୟଥା ଯଦି (S_ISREG(sb.st_mode)) {
			ଯଦି (sftp_upload(conn, new_src, new_dst,
			    preserve_flag, resume, fsync_flag,
			    inplace_flag) == -1) {
				error("upload \"%s\" to \"%s\" failed",
				    new_src, new_dst);
				ret = -1;
			}
		} ଅନ୍ୟଥା
			logit("%s: not a regular file", filename);
	}
	ମୁକ୍ତ(new_dst);
	ମୁକ୍ତ(new_src);

	ଯଦି (created || preserve_flag)
		sftp_setstat(conn, dst, &a);

	(ଶୂନ୍ୟ) closedir(dirp);
	ଫେରନ୍ତୁ ret;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sftp_upload_dir(ସଂରଚନା sftp_conn *conn, ଅଚଳ ଅକ୍ଷର *src, ଅଚଳ ଅକ୍ଷର *dst,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା preserve_flag, ପୂର୍ଣ୍ଣସଂଖ୍ୟା print_flag, ପୂର୍ଣ୍ଣସଂଖ୍ୟା resume, ପୂର୍ଣ୍ଣସଂଖ୍ୟା fsync_flag,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା follow_link_flag, ପୂର୍ଣ୍ଣସଂଖ୍ୟା inplace_flag)
{
	ଅକ୍ଷର *dst_canon;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret;

	ଯଦି ((dst_canon = sftp_realpath(conn, dst)) == ଖାଲି) {
		error("upload \"%s\": path canonicalization failed", dst);
		ଫେରନ୍ତୁ -1;
	}

	ret = upload_dir_internal(conn, src, dst_canon, 0, preserve_flag,
	    print_flag, resume, fsync_flag, follow_link_flag, inplace_flag);

	ମୁକ୍ତ(dst_canon);
	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ଶୂନ୍ୟ
handle_dest_replies(ସଂରଚନା sftp_conn *to, ଅଚଳ ଅକ୍ଷର *to_path, ପୂର୍ଣ୍ଣସଂଖ୍ୟା synchronous,
    u_int *nreqsp, u_int *write_errorp)
{
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;
	u_char type;
	u_int id, status;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ସଂରଚନା pollfd pfd;

	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");

	/* Try to eat replies from the upload side */
	ଯେତେବେଳେ (*nreqsp > 0) {
		debug3_f("%u outstanding replies", *nreqsp);
		ଯଦି (!synchronous) {
			/* Bail out if no data is ready to be read */
			pfd.fd = to->fd_in;
			pfd.events = POLLIN;
			ଯଦି ((r = poll(&pfd, 1, 0)) == -1) {
				ଯଦି (errno == EINTR)
					ଭାଙ୍ଗ;
				fatal_f("poll: %s", strerror(errno));
			} ଅନ୍ୟଥା ଯଦି (r == 0)
				ଭାଙ୍ଗ; /* fd not ready */
		}
		sshbuf_reset(ସନ୍ଦେଶ);
		get_ସନ୍ଦେଶ(to, ସନ୍ଦେଶ);

		ଯଦି ((r = sshbuf_get_u8(ସନ୍ଦେଶ, &type)) != 0 ||
		    (r = sshbuf_get_u32(ସନ୍ଦେଶ, &id)) != 0)
			fatal_fr(r, "dest parse");
		debug3("Received dest reply T:%u I:%u R:%u", type, id, *nreqsp);
		ଯଦି (type != SSH2_FXP_STATUS) {
			fatal_f("Expected SSH2_FXP_STATUS(%d) packet, got %d",
			    SSH2_FXP_STATUS, type);
		}
		ଯଦି ((r = sshbuf_get_u32(ସନ୍ଦେଶ, &status)) != 0)
			fatal_fr(r, "parse dest status");
		debug3("dest SSH2_FXP_STATUS %u", status);
		ଯଦି (status != SSH2_FX_OK) {
			/* record first error */
			ଯଦି (*write_errorp == 0)
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
	sshbuf_free(ସନ୍ଦେଶ);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sftp_crossload(ସଂରଚନା sftp_conn *from, ସଂରଚନା sftp_conn *to,
    ଅଚଳ ଅକ୍ଷର *from_path, ଅଚଳ ଅକ୍ଷର *to_path,
    Attrib *a, ପୂର୍ଣ୍ଣସଂଖ୍ୟା preserve_flag)
{
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା write_error, read_error, r, seen_zerolen = 0;
	uint64_t offset = 0, size;
	u_int id, buflen, ଅଙ୍କ_req, max_req, status = SSH2_FX_OK;
	u_int ଅଙ୍କ_upload_req;
	off_t progress_counter;
	u_char *from_handle, *to_handle;
	size_t from_handle_len, to_handle_len;
	ସଂରଚନା requests requests;
	ସଂରଚନା request *req;
	u_char type;
	Attrib attr;

	debug2_f("crossload src \"%s\" to dst \"%s\"", from_path, to_path);

	TAILQ_INIT(&requests);

	ଯଦି (a == ଖାଲି) {
		ଯଦି (sftp_stat(from, from_path, 0, &attr) != 0)
			ଫେରନ୍ତୁ -1;
		a = &attr;
	}

	ଯଦି ((a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) &&
	    (!S_ISREG(a->perm))) {
		error("download \"%s\": not a regular file", from_path);
		ଫେରନ୍ତୁ(-1);
	}
	ଯଦି (a->flags & SSH2_FILEXFER_ATTR_SIZE)
		size = a->size;
	ଅନ୍ୟଥା
		size = 0;

	buflen = from->download_buflen;
	ଯଦି (buflen > to->upload_buflen)
		buflen = to->upload_buflen;

	/* Send open request to read side */
	ଯଦି (send_open(from, from_path, "origin", SSH2_FXF_READ, ଖାଲି,
	    &from_handle, &from_handle_len) != 0)
		ଫେରନ୍ତୁ -1;

	/* Send open request to write side */
	a->flags &= ~SSH2_FILEXFER_ATTR_SIZE;
	a->flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a->perm &= 0777;
	ଯଦି (!preserve_flag)
		a->flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;
	ଯଦି (send_open(to, to_path, "dest",
	    SSH2_FXF_WRITE|SSH2_FXF_CREAT|SSH2_FXF_TRUNC, a,
	    &to_handle, &to_handle_len) != 0) {
		sftp_close(from, from_handle, from_handle_len);
		ଫେରନ୍ତୁ -1;
	}

	/* Read from remote "from" and write to remote "to" */
	offset = 0;
	write_error = read_error = ଅଙ୍କ_req = ଅଙ୍କ_upload_req = 0;
	max_req = 1;
	progress_counter = 0;

	ଯଦି (showprogress && size != 0) {
		start_progress_meter(progress_meter_path(from_path),
		    size, &progress_counter);
	}
	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯେତେବେଳେ (ଅଙ୍କ_req > 0 || max_req > 0) {
		u_char *data;
		size_t len;

		/*
		 * Simulate EOF on interrupt: stop sending new requests and
		 * allow outstanding requests to drain gracefully
		 */
		ଯଦି (interrupted) {
			ଯଦି (ଅଙ୍କ_req == 0) /* If we haven't started yet... */
				ଭାଙ୍ଗ;
			max_req = 0;
		}

		/* Send some more requests */
		ଯେତେବେଳେ (ଅଙ୍କ_req < max_req) {
			debug3("Request range %llu -> %llu (%d/%d)",
			    (unsigned long long)offset,
			    (unsigned long long)offset + buflen - 1,
			    ଅଙ୍କ_req, max_req);
			req = request_enqueue(&requests, from->ସନ୍ଦେଶ_id++,
			    buflen, offset);
			offset += buflen;
			ଅଙ୍କ_req++;
			send_read_request(from, req->id, req->offset,
			    req->len, from_handle, from_handle_len);
		}

		/* Try to eat replies from the upload side (nonblocking) */
		handle_dest_replies(to, to_path, 0,
		    &ଅଙ୍କ_upload_req, &write_error);

		sshbuf_reset(ସନ୍ଦେଶ);
		get_ସନ୍ଦେଶ(from, ସନ୍ଦେଶ);
		ଯଦି ((r = sshbuf_get_u8(ସନ୍ଦେଶ, &type)) != 0 ||
		    (r = sshbuf_get_u32(ସନ୍ଦେଶ, &id)) != 0)
			fatal_fr(r, "parse");
		debug3("Received origin reply T:%u I:%u R:%d",
		    type, id, max_req);

		/* Find the request in our queue */
		ଯଦି ((req = request_find(&requests, id)) == ଖାଲି)
			fatal("Unexpected reply %u", id);

		ବାଛ (type) {
		ସ୍ଥିତି SSH2_FXP_STATUS:
			ଯଦି ((r = sshbuf_get_u32(ସନ୍ଦେଶ, &status)) != 0)
				fatal_fr(r, "parse status");
			ଯଦି (status != SSH2_FX_EOF)
				read_error = 1;
			max_req = 0;
			TAILQ_REMOVE(&requests, req, tq);
			ମୁକ୍ତ(req);
			ଅଙ୍କ_req--;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି SSH2_FXP_DATA:
			ଯଦି ((r = sshbuf_get_string(ସନ୍ଦେଶ, &data, &len)) != 0)
				fatal_fr(r, "parse data");
			debug3("Received data %llu -> %llu",
			    (unsigned long long)req->offset,
			    (unsigned long long)req->offset + len - 1);
			ଯଦି (len > req->len)
				fatal("Received more data than asked for "
				    "%zu > %zu", len, req->len);
			ଯଦି (len == 0) {
				ଯଦି (seen_zerolen)
					fatal_f("server sent zero data length");
				seen_zerolen = 1;
			}

			/* Write this chunk out to the destination */
			sshbuf_reset(ସନ୍ଦେଶ);
			ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, SSH2_FXP_WRITE)) != 0 ||
			    (r = sshbuf_put_u32(ସନ୍ଦେଶ, to->ସନ୍ଦେଶ_id++)) != 0 ||
			    (r = sshbuf_put_string(ସନ୍ଦେଶ, to_handle,
			    to_handle_len)) != 0 ||
			    (r = sshbuf_put_u64(ସନ୍ଦେଶ, req->offset)) != 0 ||
			    (r = sshbuf_put_string(ସନ୍ଦେଶ, data, len)) != 0)
				fatal_fr(r, "compose write");
			send_ସନ୍ଦେଶ(to, ସନ୍ଦେଶ);
			debug3("Sent message SSH2_FXP_WRITE I:%u O:%llu S:%zu",
			    id, (unsigned long long)offset, len);
			ଅଙ୍କ_upload_req++;
			progress_counter += len;
			ମୁକ୍ତ(data);

			ଯଦି (len == req->len) {
				TAILQ_REMOVE(&requests, req, tq);
				ମୁକ୍ତ(req);
				ଅଙ୍କ_req--;
			} ଅନ୍ୟଥା {
				/* Resend the request for the missing data */
				debug3("Short data block, re-requesting "
				    "%llu -> %llu (%2d)",
				    (unsigned long long)req->offset + len,
				    (unsigned long long)req->offset +
				    req->len - 1, ଅଙ୍କ_req);
				req->id = from->ସନ୍ଦେଶ_id++;
				req->len -= len;
				req->offset += len;
				send_read_request(from, req->id,
				    req->offset, req->len,
				    from_handle, from_handle_len);
				/* Reduce the request size */
				ଯଦି (len < buflen)
					buflen = MAXIMUM(MIN_READ_SIZE, len);
			}
			ଯଦି (max_req > 0) { /* max_req = 0 iff EOF received */
				ଯଦି (size > 0 && offset > size) {
					/* Only one request at a time
					 * after the expected EOF */
					debug3("Finish at %llu (%2d)",
					    (unsigned long long)offset,
					    ଅଙ୍କ_req);
					max_req = 1;
				} ଅନ୍ୟଥା ଯଦି (max_req < from->ଅଙ୍କ_requests) {
					++max_req;
				}
			}
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			fatal("Expected SSH2_FXP_DATA(%u) packet, got %u",
			    SSH2_FXP_DATA, type);
		}
	}

	ଯଦି (showprogress && size)
		stop_progress_meter();

	/* Drain replies from the server (blocking) */
	debug3_f("waiting for %u replies from destination", ଅଙ୍କ_upload_req);
	handle_dest_replies(to, to_path, 1, &ଅଙ୍କ_upload_req, &write_error);

	/* Sanity check */
	ଯଦି (TAILQ_FIRST(&requests) != ଖାଲି)
		fatal("Transfer complete, but requests still in queue");
	/* Truncate at 0 length on interrupt or error to avoid holes at dest */
	ଯଦି (read_error || write_error || interrupted) {
		debug("truncating \"%s\" at 0", to_path);
		sftp_close(to, to_handle, to_handle_len);
		ମୁକ୍ତ(to_handle);
		ଯଦି (send_open(to, to_path, "dest",
		    SSH2_FXF_WRITE|SSH2_FXF_CREAT|SSH2_FXF_TRUNC, a,
		    &to_handle, &to_handle_len) != 0) {
			error("dest truncate \"%s\" failed", to_path);
			to_handle = ଖାଲି;
		}
	}
	ଯଦି (read_error) {
		error("read origin \"%s\": %s", from_path, fx2txt(status));
		status = -1;
		sftp_close(from, from_handle, from_handle_len);
		ଯଦି (to_handle != ଖାଲି)
			sftp_close(to, to_handle, to_handle_len);
	} ଅନ୍ୟଥା ଯଦି (write_error) {
		error("write dest \"%s\": %s", to_path, fx2txt(write_error));
		status = SSH2_FX_FAILURE;
		sftp_close(from, from_handle, from_handle_len);
		ଯଦି (to_handle != ଖାଲି)
			sftp_close(to, to_handle, to_handle_len);
	} ଅନ୍ୟଥା {
		ଯଦି (sftp_close(from, from_handle, from_handle_len) != 0 ||
		    interrupted)
			status = -1;
		ଅନ୍ୟଥା
			status = SSH2_FX_OK;
		ଯଦି (to_handle != ଖାଲି) {
			/* Need to resend utimes after write */
			ଯଦି (preserve_flag)
				sftp_fsetstat(to, to_handle, to_handle_len, a);
			sftp_close(to, to_handle, to_handle_len);
		}
	}
	sshbuf_free(ସନ୍ଦେଶ);
	ମୁକ୍ତ(from_handle);
	ମୁକ୍ତ(to_handle);

	ଫେରନ୍ତୁ status == SSH2_FX_OK ? 0 : -1;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
crossload_dir_internal(ସଂରଚନା sftp_conn *from, ସଂରଚନା sftp_conn *to,
    ଅଚଳ ଅକ୍ଷର *from_path, ଅଚଳ ଅକ୍ଷର *to_path,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା depth, Attrib *dirattrib, ପୂର୍ଣ୍ଣସଂଖ୍ୟା preserve_flag, ପୂର୍ଣ୍ଣସଂଖ୍ୟା print_flag,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା follow_link_flag)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, ret = 0, created = 0;
	SFTP_DIRENT **dir_entries;
	ଅକ୍ଷର *filename, *new_from_path = ଖାଲି, *new_to_path = ଖାଲି;
	mode_t mode = 0777;
	Attrib *a, curdir, ldirattrib, newdir, lsym;

	debug2_f("crossload dir src \"%s\" to dst \"%s\"", from_path, to_path);

	ଯଦି (depth >= MAX_DIR_DEPTH) {
		error("Maximum directory depth exceeded: %d levels", depth);
		ଫେରନ୍ତୁ -1;
	}

	ଯଦି (dirattrib == ଖାଲି) {
		ଯଦି (sftp_stat(from, from_path, 1, &ldirattrib) != 0) {
			error("stat remote \"%s\" failed", from_path);
			ଫେରନ୍ତୁ -1;
		}
		dirattrib = &ldirattrib;
	}
	ଯଦି (!S_ISDIR(dirattrib->perm)) {
		error("\"%s\" is not a directory", from_path);
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି (print_flag && print_flag != SFTP_PROGRESS_ONLY)
		mprintf("Retrieving %s\n", from_path);

	curdir = *dirattrib; /* dirattrib will be clobbered */
	curdir.flags &= ~SSH2_FILEXFER_ATTR_SIZE;
	curdir.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	ଯଦି ((curdir.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) == 0) {
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
	ଯଦି (sftp_mkdir(to, to_path, &curdir, 0) == 0)
		created = 1;
	ଅନ୍ୟଥା {
		ଯଦି (sftp_stat(to, to_path, 0, &newdir) != 0)
			ଫେରନ୍ତୁ -1;
		ଯଦି (!S_ISDIR(newdir.perm)) {
			error("\"%s\" exists but is not a directory", to_path);
			ଫେରନ୍ତୁ -1;
		}
	}
	curdir.perm = mode;

	ଯଦି (sftp_readdir(from, from_path, &dir_entries) == -1) {
		error("origin readdir \"%s\" failed", from_path);
		ଫେରନ୍ତୁ -1;
	}

	ପାଇଁ (i = 0; dir_entries[i] != ଖାଲି && !interrupted; i++) {
		ମୁକ୍ତ(new_from_path);
		ମୁକ୍ତ(new_to_path);

		filename = dir_entries[i]->filename;
		new_from_path = sftp_path_append(from_path, filename);
		new_to_path = sftp_path_append(to_path, filename);

		a = &dir_entries[i]->a;
		ଯଦି (S_ISLNK(a->perm)) {
			ଯଦି (!follow_link_flag) {
				logit("%s: not a regular file", filename);
				ଜାରି;
			}
			/* Replace the stat contents with the symlink target */
			ଯଦି (sftp_stat(from, new_from_path, 1, &lsym) != 0) {
				logit("remote stat \"%s\" failed",
				    new_from_path);
				ret = -1;
				ଜାରି;
			}
			a = &lsym;
		}
		ଯଦି (S_ISDIR(a->perm)) {
			ଯଦି (strcmp(filename, ".") == 0 ||
			    strcmp(filename, "..") == 0)
				ଜାରି;
			ଯଦି (crossload_dir_internal(from, to,
			    new_from_path, new_to_path,
			    depth + 1, a, preserve_flag,
			    print_flag, follow_link_flag) == -1)
				ret = -1;
		} ଅନ୍ୟଥା ଯଦି (S_ISREG(a->perm)) {
			ଯଦି (sftp_crossload(from, to, new_from_path,
			    new_to_path, a, preserve_flag) == -1) {
				error("crossload \"%s\" to \"%s\" failed",
				    new_from_path, new_to_path);
				ret = -1;
			}
		} ଅନ୍ୟଥା {
			logit("origin \"%s\": not a regular file",
			    new_from_path);
		}
	}
	ମୁକ୍ତ(new_to_path);
	ମୁକ୍ତ(new_from_path);

	ଯଦି (created || preserve_flag)
		sftp_setstat(to, to_path, &curdir);

	sftp_free_dirents(dir_entries);

	ଫେରନ୍ତୁ ret;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sftp_crossload_dir(ସଂରଚନା sftp_conn *from, ସଂରଚନା sftp_conn *to,
    ଅଚଳ ଅକ୍ଷର *from_path, ଅଚଳ ଅକ୍ଷର *to_path,
    Attrib *dirattrib, ପୂର୍ଣ୍ଣସଂଖ୍ୟା preserve_flag, ପୂର୍ଣ୍ଣସଂଖ୍ୟା print_flag, ପୂର୍ଣ୍ଣସଂଖ୍ୟା follow_link_flag)
{
	ଅକ୍ଷର *from_path_canon;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret;

	ଯଦି ((from_path_canon = sftp_realpath(from, from_path)) == ଖାଲି) {
		error("crossload \"%s\": path canonicalization failed",
		    from_path);
		ଫେରନ୍ତୁ -1;
	}

	ret = crossload_dir_internal(from, to, from_path_canon, to_path, 0,
	    dirattrib, preserve_flag, print_flag, follow_link_flag);
	ମୁକ୍ତ(from_path_canon);
	ଫେରନ୍ତୁ ret;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sftp_can_get_users_groups_by_id(ସଂରଚନା sftp_conn *conn)
{
	ଫେରନ୍ତୁ (conn->exts & SFTP_EXT_GETUSERSGROUPS_BY_ID) != 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sftp_get_users_groups_by_id(ସଂରଚନା sftp_conn *conn,
    ଅଚଳ u_int *uids, u_int nuids,
    ଅଚଳ u_int *gids, u_int ngids,
    ଅକ୍ଷର ***usernamesp, ଅକ୍ଷର ***groupnamesp)
{
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ, *uidbuf, *gidbuf;
	u_int i, expected_id, id;
	ଅକ୍ଷର *name, **usernames = ଖାଲି, **groupnames = ଖାଲି;
	u_char type;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	*usernamesp = *groupnamesp = ଖାଲି;
	ଯଦି (!sftp_can_get_users_groups_by_id(conn))
		ଫେରନ୍ତୁ SSH_ERR_FEATURE_UNSUPPORTED;

	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି ||
	    (uidbuf = sshbuf_new()) == ଖାଲି ||
	    (gidbuf = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	expected_id = id = conn->ସନ୍ଦେଶ_id++;
	debug2("Sending SSH2_FXP_EXTENDED(users-groups-by-id@openssh.com)");
	ପାଇଁ (i = 0; i < nuids; i++) {
		ଯଦି ((r = sshbuf_put_u32(uidbuf, uids[i])) != 0)
			fatal_fr(r, "compose uids");
	}
	ପାଇଁ (i = 0; i < ngids; i++) {
		ଯଦି ((r = sshbuf_put_u32(gidbuf, gids[i])) != 0)
			fatal_fr(r, "compose gids");
	}
	ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(ସନ୍ଦେଶ, id)) != 0 ||
	    (r = sshbuf_put_cstring(ସନ୍ଦେଶ,
	    "users-groups-by-id@openssh.com")) != 0 ||
	    (r = sshbuf_put_stringb(ସନ୍ଦେଶ, uidbuf)) != 0 ||
	    (r = sshbuf_put_stringb(ସନ୍ଦେଶ, gidbuf)) != 0)
		fatal_fr(r, "compose");
	send_ସନ୍ଦେଶ(conn, ସନ୍ଦେଶ);
	get_ସନ୍ଦେଶ(conn, ସନ୍ଦେଶ);
	ଯଦି ((r = sshbuf_get_u8(ସନ୍ଦେଶ, &type)) != 0 ||
	    (r = sshbuf_get_u32(ସନ୍ଦେଶ, &id)) != 0)
		fatal_fr(r, "parse");
	ଯଦି (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	ଯଦି (type == SSH2_FXP_STATUS) {
		u_int status;
		ଅକ୍ଷର *errmsg;

		ଯଦି ((r = sshbuf_get_u32(ସନ୍ଦେଶ, &status)) != 0 ||
		    (r = sshbuf_get_cstring(ସନ୍ଦେଶ, &errmsg, ଖାଲି)) != 0)
			fatal_fr(r, "parse status");
		error("users-groups-by-id %s",
		    *errmsg == '\0' ? fx2txt(status) : errmsg);
		ମୁକ୍ତ(errmsg);
		sshbuf_free(ସନ୍ଦେଶ);
		sshbuf_free(uidbuf);
		sshbuf_free(gidbuf);
		ଫେରନ୍ତୁ -1;
	} ଅନ୍ୟଥା ଯଦି (type != SSH2_FXP_EXTENDED_REPLY)
		fatal("Expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_REPLY, type);

	/* reuse */
	sshbuf_free(uidbuf);
	sshbuf_free(gidbuf);
	uidbuf = gidbuf = ଖାଲି;
	ଯଦି ((r = sshbuf_froms(ସନ୍ଦେଶ, &uidbuf)) != 0 ||
	    (r = sshbuf_froms(ସନ୍ଦେଶ, &gidbuf)) != 0)
		fatal_fr(r, "parse response");
	ଯଦି (nuids > 0) {
		usernames = xcalloc(nuids, ଆକାର(*usernames));
		ପାଇଁ (i = 0; i < nuids; i++) {
			ଯଦି ((r = sshbuf_get_cstring(uidbuf, &name, ଖାଲି)) != 0)
				fatal_fr(r, "parse user name");
			/* Handle unresolved names */
			ଯଦି (*name == '\0') {
				ମୁକ୍ତ(name);
				name = ଖାଲି;
			}
			usernames[i] = name;
		}
	}
	ଯଦି (ngids > 0) {
		groupnames = xcalloc(ngids, ଆକାର(*groupnames));
		ପାଇଁ (i = 0; i < ngids; i++) {
			ଯଦି ((r = sshbuf_get_cstring(gidbuf, &name, ଖାଲି)) != 0)
				fatal_fr(r, "parse user name");
			/* Handle unresolved names */
			ଯଦି (*name == '\0') {
				ମୁକ୍ତ(name);
				name = ଖାଲି;
			}
			groupnames[i] = name;
		}
	}
	ଯଦି (sshbuf_len(uidbuf) != 0)
		fatal_f("unexpected extra username data");
	ଯଦି (sshbuf_len(gidbuf) != 0)
		fatal_f("unexpected extra groupname data");
	sshbuf_free(uidbuf);
	sshbuf_free(gidbuf);
	sshbuf_free(ସନ୍ଦେଶ);
	/* success */
	*usernamesp = usernames;
	*groupnamesp = groupnames;
	ଫେରନ୍ତୁ 0;
}

ଅକ୍ଷର *
sftp_path_append(ଅଚଳ ଅକ୍ଷର *p1, ଅଚଳ ଅକ୍ଷର *p2)
{
	ଅକ୍ଷର *ret;
	size_t len = strlen(p1) + strlen(p2) + 2;

	ret = xmalloc(len);
	strlcpy(ret, p1, len);
	ଯଦି (p1[0] != '\0' && p1[strlen(p1) - 1] != '/')
		strlcat(ret, "/", len);
	strlcat(ret, p2, len);

	ଫେରନ୍ତୁ(ret);
}

/*
 * Arg p must be dynamically allocated.  It will either be returned or
 * freed and a replacement allocated.  Caller must free returned string.
 */
ଅକ୍ଷର *
sftp_make_absolute(ଅକ୍ଷର *p, ଅଚଳ ଅକ୍ଷର *pwd)
{
	ଅକ୍ଷର *abs_str;

	/* Derelativise */
	ଯଦି (p && !path_absolute(p)) {
		abs_str = sftp_path_append(pwd, p);
		ମୁକ୍ତ(p);
		ଫେରନ୍ତୁ(abs_str);
	} ଅନ୍ୟଥା
		ଫେରନ୍ତୁ(p);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sftp_remote_is_dir(ସଂରଚନା sftp_conn *conn, ଅଚଳ ଅକ୍ଷର *path)
{
	Attrib a;

	/* XXX: report errors? */
	ଯଦି (sftp_stat(conn, path, 1, &a) != 0)
		ଫେରନ୍ତୁ(0);
	ଯଦି (!(a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS))
		ଫେରନ୍ତୁ(0);
	ଫେରନ୍ତୁ S_ISDIR(a.perm);
}


/* Check whether path returned from glob(..., GLOB_MARK, ...) is a directory */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sftp_globpath_is_dir(ଅଚଳ ଅକ୍ଷର *pathname)
{
	size_t l = strlen(pathname);

	ଫେରନ୍ତୁ l > 0 && pathname[l - 1] == '/';
}

