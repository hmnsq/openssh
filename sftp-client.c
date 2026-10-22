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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/queue.h>
#অন্তর্ভাব <sys/stat.h>
#অন্তর্ভাব <sys/time.h>
#অন্তর্ভাব <sys/statvfs.h>
#অন্তর্ভাব <sys/uio.h>

#অন্তর্ভাব <dirent.h>
#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <fcntl.h>
#অন্তর্ভাব <poll.h>
#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>

#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "atomicio.h"
#অন্তর্ভাব "progressmeter.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "utf8.h"

#অন্তর্ভাব "sftp.h"
#অন্তর্ভাব "sftp-common.h"
#অন্তর্ভাব "sftp-client.h"

বাহ্যিক অস্থির sig_atomic_t interrupted;
বাহ্যিক পূর্ণসংখ্যা showprogress;

/* Default size of buffer for up/download (fix sftp.1 scp.1 if changed) */
#define DEFAULT_COPY_BUFLEN	32768

/* Default number of concurrent xfer requests (fix sftp.1 scp.1 if changed) */
#define DEFAULT_অঙ্ক_REQUESTS	64

/* Minimum amount of data to read at a time */
#define MIN_READ_আকার	512

/* Maximum depth to descend in directory trees */
#define MAX_DIR_DEPTH 64

/* Directory separator characters */
#ifdef HAVE_CYGWIN
# define SFTP_DIRECTORY_CHARS      "/\\"
#অন্যথা /* HAVE_CYGWIN */
# define SFTP_DIRECTORY_CHARS      "/"
#endif /* HAVE_CYGWIN */

কাঠামো sftp_conn {
	পূর্ণসংখ্যা fd_in;
	পূর্ণসংখ্যা fd_out;
	u_int download_buflen;
	u_int upload_buflen;
	u_int অঙ্ক_requests;
	u_int version;
	u_int বার্তা_id;
#define SFTP_EXT_POSIX_RENAME		0x00000001
#define SFTP_EXT_STATVFS		0x00000002
#define SFTP_EXT_FSTATVFS		0x00000004
#define SFTP_EXT_HARDLINK		0x00000008
#define SFTP_EXT_FSYNC			0x00000010
#define SFTP_EXT_LSETSTAT		0x00000020
#define SFTP_EXT_LIMITS			0x00000040
#define SFTP_EXT_PATH_EXPAND		0x00000080
#define SFTP_EXT_COPY_তথ্য		0x00000100
#define SFTP_EXT_GETUSERSGROUPS_BY_ID	0x00000200
	u_int exts;
	uint64_t limit_kbps;
	কাঠামো bwlimit bwlimit_in, bwlimit_out;
};

/* Tracks in-progress requests during file transfers */
কাঠামো request {
	u_int id;
	আকার_t len;
	uint64_t offset;
	TAILQ_ENTRY(request) tq;
};
TAILQ_HEAD(requests, request);

স্থির u_char *
get_handle(কাঠামো sftp_conn *conn, u_int expected_id, আকার_t *len,
    ধ্রুবক অক্ষর *errfmt, ...) __attribute__((format(printf, 4, 5)));

স্থির কাঠামো request *
request_enqueue(কাঠামো requests *requests, u_int id, আকার_t len,
    uint64_t offset)
{
	কাঠামো request *req;

	req = xcalloc(1, আকার(*req));
	req->id = id;
	req->len = len;
	req->offset = offset;
	TAILQ_INSERT_TAIL(requests, req, tq);
	ফেরত req;
}

স্থির কাঠামো request *
request_find(কাঠামো requests *requests, u_int id)
{
	কাঠামো request *req;

	জন্য (req = TAILQ_FIRST(requests);
	    req != ফাঁকা && req->id != id;
	    req = TAILQ_NEXT(req, tq))
		;
	ফেরত req;
}

স্থির পূর্ণসংখ্যা
sftpio(শূন্য *_bwlimit, আকার_t amount)
{
	কাঠামো bwlimit *bwlimit = (কাঠামো bwlimit *)_bwlimit;

	refresh_progress_meter(0);
	যদি (bwlimit != ফাঁকা)
		bandwidth_limit(bwlimit, amount);
	ফেরত 0;
}

স্থির শূন্য
send_বার্তা(কাঠামো sftp_conn *conn, কাঠামো sshbuf *m)
{
	u_char mlen[4];
	কাঠামো iovec iov[2];

	যদি (sshbuf_len(m) > SFTP_MAX_বার্তা_দৈর্ঘ্য)
		fatal("Outbound message too long %zu", sshbuf_len(m));

	/* Send length first */
	put_u32(mlen, sshbuf_len(m));
	iov[0].iov_base = mlen;
	iov[0].iov_len = আকার(mlen);
	iov[1].iov_base = (u_char *)sshbuf_ptr(m);
	iov[1].iov_len = sshbuf_len(m);

	যদি (atomiciov6(writev, conn->fd_out, iov, 2, sftpio,
	    conn->limit_kbps > 0 ? &conn->bwlimit_out : ফাঁকা) !=
	    sshbuf_len(m) + আকার(mlen))
		fatal("Couldn't send packet: %s", strerror(errno));

	sshbuf_reset(m);
}

স্থির শূন্য
get_বার্তা_extended(কাঠামো sftp_conn *conn, কাঠামো sshbuf *m, পূর্ণসংখ্যা initial)
{
	u_int বার্তা_len;
	u_char *p;
	পূর্ণসংখ্যা r;

	sshbuf_reset(m);
	যদি ((r = sshbuf_reserve(m, 4, &p)) != 0)
		fatal_fr(r, "reserve");
	যদি (atomicio6(পঠ, conn->fd_in, p, 4, sftpio,
	    conn->limit_kbps > 0 ? &conn->bwlimit_in : ফাঁকা) != 4) {
		যদি (errno == EPIPE || errno == ECONNRESET)
			fatal("Connection closed");
		অন্যথা
			fatal("Couldn't read packet: %s", strerror(errno));
	}

	যদি ((r = sshbuf_get_u32(m, &বার্তা_len)) != 0)
		fatal_fr(r, "sshbuf_get_u32");
	যদি (বার্তা_len > SFTP_MAX_বার্তা_দৈর্ঘ্য) {
		do_log2(initial ? SYSLOG_LEVEL_ERROR : SYSLOG_LEVEL_FATAL,
		    "Received message too long %u", বার্তা_len);
		fatal("Ensure the remote shell produces no output "
		    "for non-interactive sessions.");
	}

	যদি ((r = sshbuf_reserve(m, বার্তা_len, &p)) != 0)
		fatal_fr(r, "reserve");
	যদি (atomicio6(পঠ, conn->fd_in, p, বার্তা_len, sftpio,
	    conn->limit_kbps > 0 ? &conn->bwlimit_in : ফাঁকা)
	    != বার্তা_len) {
		যদি (errno == EPIPE)
			fatal("Connection closed");
		অন্যথা
			fatal("Read packet: %s", strerror(errno));
	}
}

স্থির শূন্য
get_বার্তা(কাঠামো sftp_conn *conn, কাঠামো sshbuf *m)
{
	get_বার্তা_extended(conn, m, 0);
}

স্থির শূন্য
send_string_request(কাঠামো sftp_conn *conn, u_int id, u_int code, ধ্রুবক অক্ষর *s,
    u_int len)
{
	কাঠামো sshbuf *বার্তা;
	পূর্ণসংখ্যা r;

	যদি ((বার্তা = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshbuf_put_u8(বার্তা, code)) != 0 ||
	    (r = sshbuf_put_u32(বার্তা, id)) != 0 ||
	    (r = sshbuf_put_string(বার্তা, s, len)) != 0)
		fatal_fr(r, "compose");
	send_বার্তা(conn, বার্তা);
	debug3("Sent message fd %d T:%u I:%u", conn->fd_out, code, id);
	sshbuf_free(বার্তা);
}

স্থির শূন্য
send_string_attrs_request(কাঠামো sftp_conn *conn, u_int id, u_int code,
    ধ্রুবক শূন্য *s, u_int len, Attrib *a)
{
	কাঠামো sshbuf *বার্তা;
	পূর্ণসংখ্যা r;

	যদি ((বার্তা = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshbuf_put_u8(বার্তা, code)) != 0 ||
	    (r = sshbuf_put_u32(বার্তা, id)) != 0 ||
	    (r = sshbuf_put_string(বার্তা, s, len)) != 0 ||
	    (r = encode_attrib(বার্তা, a)) != 0)
		fatal_fr(r, "compose");
	send_বার্তা(conn, বার্তা);
	debug3("Sent message fd %d T:%u I:%u F:0x%04x M:%05o",
	    conn->fd_out, code, id, a->flags, a->perm);
	sshbuf_free(বার্তা);
}

স্থির u_int
get_status(কাঠামো sftp_conn *conn, u_int expected_id)
{
	কাঠামো sshbuf *বার্তা;
	u_char type;
	u_int id, status;
	পূর্ণসংখ্যা r;

	যদি ((বার্তা = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");
	get_বার্তা(conn, বার্তা);
	যদি ((r = sshbuf_get_u8(বার্তা, &type)) != 0 ||
	    (r = sshbuf_get_u32(বার্তা, &id)) != 0)
		fatal_fr(r, "compose");

	যদি (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	যদি (type != SSH2_FXP_STATUS)
		fatal("Expected SSH2_FXP_STATUS(%u) packet, got %u",
		    SSH2_FXP_STATUS, type);

	যদি ((r = sshbuf_get_u32(বার্তা, &status)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(বার্তা);

	debug3("SSH2_FXP_STATUS %u", status);

	ফেরত status;
}

স্থির u_char *
get_handle(কাঠামো sftp_conn *conn, u_int expected_id, আকার_t *len,
    ধ্রুবক অক্ষর *errfmt, ...)
{
	কাঠামো sshbuf *বার্তা;
	u_int id, status;
	u_char type;
	u_char *handle;
	অক্ষর errmsg[256];
	va_list args;
	পূর্ণসংখ্যা r;

	va_start(args, errfmt);
	যদি (errfmt != ফাঁকা)
		vsnprintf(errmsg, আকার(errmsg), errfmt, args);
	va_end(args);

	যদি ((বার্তা = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");
	get_বার্তা(conn, বার্তা);
	যদি ((r = sshbuf_get_u8(বার্তা, &type)) != 0 ||
	    (r = sshbuf_get_u32(বার্তা, &id)) != 0)
		fatal_fr(r, "parse");

	যদি (id != expected_id)
		fatal("%s: ID mismatch (%u != %u)",
		    errfmt == ফাঁকা ? __func__ : errmsg, id, expected_id);
	যদি (type == SSH2_FXP_STATUS) {
		যদি ((r = sshbuf_get_u32(বার্তা, &status)) != 0)
			fatal_fr(r, "parse status");
		যদি (errfmt != ফাঁকা)
			error("%s: %s", errmsg, fx2txt(status));
		sshbuf_free(বার্তা);
		ফেরত(ফাঁকা);
	} অন্যথা যদি (type != SSH2_FXP_HANDLE)
		fatal("%s: Expected SSH2_FXP_HANDLE(%u) packet, got %u",
		    errfmt == ফাঁকা ? __func__ : errmsg, SSH2_FXP_HANDLE, type);

	যদি ((r = sshbuf_get_string(বার্তা, &handle, len)) != 0)
		fatal_fr(r, "parse handle");
	sshbuf_free(বার্তা);

	ফেরত handle;
}

স্থির পূর্ণসংখ্যা
get_decode_stat(কাঠামো sftp_conn *conn, u_int expected_id, পূর্ণসংখ্যা quiet, Attrib *a)
{
	কাঠামো sshbuf *বার্তা;
	u_int id;
	u_char type;
	পূর্ণসংখ্যা r;
	Attrib attr;

	যদি (a != ফাঁকা)
		memset(a, '\0', আকার(*a));
	যদি ((বার্তা = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");
	get_বার্তা(conn, বার্তা);

	যদি ((r = sshbuf_get_u8(বার্তা, &type)) != 0 ||
	    (r = sshbuf_get_u32(বার্তা, &id)) != 0)
		fatal_fr(r, "parse");

	যদি (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	যদি (type == SSH2_FXP_STATUS) {
		u_int status;

		যদি ((r = sshbuf_get_u32(বার্তা, &status)) != 0)
			fatal_fr(r, "parse status");
		যদি (quiet)
			debug("stat remote: %s", fx2txt(status));
		অন্যথা
			error("stat remote: %s", fx2txt(status));
		sshbuf_free(বার্তা);
		ফেরত -1;
	} অন্যথা যদি (type != SSH2_FXP_ATTRS) {
		fatal("Expected SSH2_FXP_ATTRS(%u) packet, got %u",
		    SSH2_FXP_ATTRS, type);
	}
	যদি ((r = decode_attrib(বার্তা, &attr)) != 0) {
		error_fr(r, "decode_attrib");
		sshbuf_free(বার্তা);
		ফেরত -1;
	}
	/* success */
	যদি (a != ফাঁকা)
		*a = attr;
	debug3("Received stat reply T:%u I:%u F:0x%04x M:%05o",
	    type, id, attr.flags, attr.perm);
	sshbuf_free(বার্তা);

	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
get_decode_statvfs(কাঠামো sftp_conn *conn, কাঠামো sftp_statvfs *st,
    u_int expected_id, পূর্ণসংখ্যা quiet)
{
	কাঠামো sshbuf *বার্তা;
	u_char type;
	u_int id;
	uint64_t flag;
	পূর্ণসংখ্যা r;

	যদি ((বার্তা = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");
	get_বার্তা(conn, বার্তা);

	যদি ((r = sshbuf_get_u8(বার্তা, &type)) != 0 ||
	    (r = sshbuf_get_u32(বার্তা, &id)) != 0)
		fatal_fr(r, "parse");

	debug3("Received statvfs reply T:%u I:%u", type, id);
	যদি (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	যদি (type == SSH2_FXP_STATUS) {
		u_int status;

		যদি ((r = sshbuf_get_u32(বার্তা, &status)) != 0)
			fatal_fr(r, "parse status");
		যদি (quiet)
			debug("remote statvfs: %s", fx2txt(status));
		অন্যথা
			error("remote statvfs: %s", fx2txt(status));
		sshbuf_free(বার্তা);
		ফেরত -1;
	} অন্যথা যদি (type != SSH2_FXP_EXTENDED_REPLY) {
		fatal("Expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_REPLY, type);
	}

	memset(st, 0, আকার(*st));
	যদি ((r = sshbuf_get_u64(বার্তা, &st->f_bsize)) != 0 ||
	    (r = sshbuf_get_u64(বার্তা, &st->f_frsize)) != 0 ||
	    (r = sshbuf_get_u64(বার্তা, &st->f_blocks)) != 0 ||
	    (r = sshbuf_get_u64(বার্তা, &st->f_bfree)) != 0 ||
	    (r = sshbuf_get_u64(বার্তা, &st->f_bavail)) != 0 ||
	    (r = sshbuf_get_u64(বার্তা, &st->f_files)) != 0 ||
	    (r = sshbuf_get_u64(বার্তা, &st->f_ffree)) != 0 ||
	    (r = sshbuf_get_u64(বার্তা, &st->f_favail)) != 0 ||
	    (r = sshbuf_get_u64(বার্তা, &st->f_fsid)) != 0 ||
	    (r = sshbuf_get_u64(বার্তা, &flag)) != 0 ||
	    (r = sshbuf_get_u64(বার্তা, &st->f_namemax)) != 0)
		fatal_fr(r, "parse statvfs");

	st->f_flag = (flag & SSH2_FXE_STATVFS_ST_RDONLY) ? ST_RDONLY : 0;
	st->f_flag |= (flag & SSH2_FXE_STATVFS_ST_NOSUID) ? ST_NOSUID : 0;

	sshbuf_free(বার্তা);

	ফেরত 0;
}

কাঠামো sftp_conn *
sftp_init(পূর্ণসংখ্যা fd_in, পূর্ণসংখ্যা fd_out, u_int transfer_buflen, u_int অঙ্ক_requests,
    uint64_t limit_kbps)
{
	u_char type;
	কাঠামো sshbuf *বার্তা;
	কাঠামো sftp_conn *ret;
	পূর্ণসংখ্যা r;

	ret = xcalloc(1, আকার(*ret));
	ret->বার্তা_id = 1;
	ret->fd_in = fd_in;
	ret->fd_out = fd_out;
	ret->download_buflen = ret->upload_buflen =
	    transfer_buflen ? transfer_buflen : DEFAULT_COPY_BUFLEN;
	ret->অঙ্ক_requests =
	    অঙ্ক_requests ? অঙ্ক_requests : DEFAULT_অঙ্ক_REQUESTS;
	ret->exts = 0;
	ret->limit_kbps = 0;

	যদি ((বার্তা = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshbuf_put_u8(বার্তা, SSH2_FXP_INIT)) != 0 ||
	    (r = sshbuf_put_u32(বার্তা, SSH2_FILEXFER_VERSION)) != 0)
		fatal_fr(r, "parse");

	send_বার্তা(ret, বার্তা);

	get_বার্তা_extended(ret, বার্তা, 1);

	/* Expecting a VERSION reply */
	যদি ((r = sshbuf_get_u8(বার্তা, &type)) != 0)
		fatal_fr(r, "parse type");
	যদি (type != SSH2_FXP_VERSION) {
		error("Invalid packet back from SSH2_FXP_INIT (type %u)",
		    type);
		sshbuf_free(বার্তা);
		মুক্ত(ret);
		ফেরত(ফাঁকা);
	}
	যদি ((r = sshbuf_get_u32(বার্তা, &ret->version)) != 0)
		fatal_fr(r, "parse version");

	debug2("Remote version: %u", ret->version);

	/* Check for extensions */
	যখন (sshbuf_len(বার্তা) > 0) {
		অক্ষর *name;
		u_char *মান;
		আকার_t vlen;
		পূর্ণসংখ্যা known = 0;

		যদি ((r = sshbuf_get_cstring(বার্তা, &name, ফাঁকা)) != 0 ||
		    (r = sshbuf_get_string(বার্তা, &মান, &vlen)) != 0)
			fatal_fr(r, "parse extension");
		যদি (strcmp(name, "posix-rename@openssh.com") == 0 &&
		    strcmp((অক্ষর *)মান, "1") == 0) {
			ret->exts |= SFTP_EXT_POSIX_RENAME;
			known = 1;
		} অন্যথা যদি (strcmp(name, "statvfs@openssh.com") == 0 &&
		    strcmp((অক্ষর *)মান, "2") == 0) {
			ret->exts |= SFTP_EXT_STATVFS;
			known = 1;
		} অন্যথা যদি (strcmp(name, "fstatvfs@openssh.com") == 0 &&
		    strcmp((অক্ষর *)মান, "2") == 0) {
			ret->exts |= SFTP_EXT_FSTATVFS;
			known = 1;
		} অন্যথা যদি (strcmp(name, "hardlink@openssh.com") == 0 &&
		    strcmp((অক্ষর *)মান, "1") == 0) {
			ret->exts |= SFTP_EXT_HARDLINK;
			known = 1;
		} অন্যথা যদি (strcmp(name, "fsync@openssh.com") == 0 &&
		    strcmp((অক্ষর *)মান, "1") == 0) {
			ret->exts |= SFTP_EXT_FSYNC;
			known = 1;
		} অন্যথা যদি (strcmp(name, "lsetstat@openssh.com") == 0 &&
		    strcmp((অক্ষর *)মান, "1") == 0) {
			ret->exts |= SFTP_EXT_LSETSTAT;
			known = 1;
		} অন্যথা যদি (strcmp(name, "limits@openssh.com") == 0 &&
		    strcmp((অক্ষর *)মান, "1") == 0) {
			ret->exts |= SFTP_EXT_LIMITS;
			known = 1;
		} অন্যথা যদি (strcmp(name, "expand-path@openssh.com") == 0 &&
		    strcmp((অক্ষর *)মান, "1") == 0) {
			ret->exts |= SFTP_EXT_PATH_EXPAND;
			known = 1;
		} অন্যথা যদি (strcmp(name, "copy-data") == 0 &&
		    strcmp((অক্ষর *)মান, "1") == 0) {
			ret->exts |= SFTP_EXT_COPY_তথ্য;
			known = 1;
		} অন্যথা যদি (strcmp(name,
		    "users-groups-by-id@openssh.com") == 0 &&
		    strcmp((অক্ষর *)মান, "1") == 0) {
			ret->exts |= SFTP_EXT_GETUSERSGROUPS_BY_ID;
			known = 1;
		}
		যদি (known) {
			debug2("Server supports extension \"%s\" revision %s",
			    name, মান);
		} অন্যথা {
			debug2("Unrecognised server extension \"%s\"", name);
		}
		মুক্ত(name);
		মুক্ত(মান);
	}

	sshbuf_free(বার্তা);

	/* Query the server for its limits */
	যদি (ret->exts & SFTP_EXT_LIMITS) {
		কাঠামো sftp_limits limits;
		যদি (sftp_get_limits(ret, &limits) != 0)
			fatal_f("limits failed");

		/* If the caller did not specify, find a good value */
		যদি (transfer_buflen == 0) {
			ret->download_buflen = MINIMUM(limits.read_দৈর্ঘ্য,
			    SFTP_MAX_বার্তা_দৈর্ঘ্য - 1024);
			ret->upload_buflen = MINIMUM(limits.write_দৈর্ঘ্য,
			    SFTP_MAX_বার্তা_দৈর্ঘ্য - 1024);
			ret->download_buflen = MAXIMUM(ret->download_buflen, 64);
			ret->upload_buflen = MAXIMUM(ret->upload_buflen, 64);
			debug3("server upload/download buffer sizes "
			    "%llu / %llu; using %u / %u",
			    (unsigned long long)limits.write_দৈর্ঘ্য,
			    (unsigned long long)limits.read_দৈর্ঘ্য,
			    ret->upload_buflen, ret->download_buflen);
		}
	}

	/* Some filexfer v.0 servers don't support large packets */
	যদি (ret->version == 0) {
		ret->download_buflen = MINIMUM(ret->download_buflen, 20480);
		ret->upload_buflen = MINIMUM(ret->upload_buflen, 20480);
	}

	ret->limit_kbps = limit_kbps;
	যদি (ret->limit_kbps > 0) {
		bandwidth_limit_init(&ret->bwlimit_in, ret->limit_kbps,
		    ret->download_buflen);
		bandwidth_limit_init(&ret->bwlimit_out, ret->limit_kbps,
		    ret->upload_buflen);
	}

	ফেরত ret;
}

শূন্য
sftp_free(কাঠামো sftp_conn *conn)
{
	যদি (conn == ফাঁকা)
		ফেরত;
	freezero(conn, আকার(*conn));
}

u_int
sftp_proto_version(কাঠামো sftp_conn *conn)
{
	ফেরত conn->version;
}

পূর্ণসংখ্যা
sftp_get_limits(কাঠামো sftp_conn *conn, কাঠামো sftp_limits *limits)
{
	u_int id, বার্তা_id;
	u_char type;
	কাঠামো sshbuf *বার্তা;
	পূর্ণসংখ্যা r;

	যদি ((conn->exts & SFTP_EXT_LIMITS) == 0) {
		error("Server does not support limits@openssh.com extension");
		ফেরত -1;
	}

	যদি ((বার্তা = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");

	id = conn->বার্তা_id++;
	যদি ((r = sshbuf_put_u8(বার্তা, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(বার্তা, id)) != 0 ||
	    (r = sshbuf_put_cstring(বার্তা, "limits@openssh.com")) != 0)
		fatal_fr(r, "compose");
	send_বার্তা(conn, বার্তা);
	debug3("Sent message limits@openssh.com I:%u", id);

	get_বার্তা(conn, বার্তা);

	যদি ((r = sshbuf_get_u8(বার্তা, &type)) != 0 ||
	    (r = sshbuf_get_u32(বার্তা, &বার্তা_id)) != 0)
		fatal_fr(r, "parse");

	debug3("Received limits reply T:%u I:%u", type, বার্তা_id);
	যদি (id != বার্তা_id)
		fatal("ID mismatch (%u != %u)", বার্তা_id, id);
	যদি (type != SSH2_FXP_EXTENDED_REPLY) {
		debug_f("expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_REPLY, type);
		/* Disable the limits extension */
		conn->exts &= ~SFTP_EXT_LIMITS;
		sshbuf_free(বার্তা);
		ফেরত -1;
	}

	memset(limits, 0, আকার(*limits));
	যদি ((r = sshbuf_get_u64(বার্তা, &limits->packet_দৈর্ঘ্য)) != 0 ||
	    (r = sshbuf_get_u64(বার্তা, &limits->read_দৈর্ঘ্য)) != 0 ||
	    (r = sshbuf_get_u64(বার্তা, &limits->write_দৈর্ঘ্য)) != 0 ||
	    (r = sshbuf_get_u64(বার্তা, &limits->open_handles)) != 0)
		fatal_fr(r, "parse limits");

	sshbuf_free(বার্তা);

	ফেরত 0;
}

পূর্ণসংখ্যা
sftp_close(কাঠামো sftp_conn *conn, ধ্রুবক u_char *handle, u_int handle_len)
{
	u_int id, status;
	কাঠামো sshbuf *বার্তা;
	পূর্ণসংখ্যা r;

	যদি ((বার্তা = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");

	id = conn->বার্তা_id++;
	যদি ((r = sshbuf_put_u8(বার্তা, SSH2_FXP_CLOSE)) != 0 ||
	    (r = sshbuf_put_u32(বার্তা, id)) != 0 ||
	    (r = sshbuf_put_string(বার্তা, handle, handle_len)) != 0)
		fatal_fr(r, "parse");
	send_বার্তা(conn, বার্তা);
	debug3("Sent message SSH2_FXP_CLOSE I:%u", id);

	status = get_status(conn, id);
	যদি (status != SSH2_FX_OK)
		error("close remote: %s", fx2txt(status));

	sshbuf_free(বার্তা);

	ফেরত status == SSH2_FX_OK ? 0 : -1;
}


স্থির পূর্ণসংখ্যা
sftp_lsreaddir(কাঠামো sftp_conn *conn, ধ্রুবক অক্ষর *path, পূর্ণসংখ্যা print_flag,
    SFTP_DIRENT ***dir)
{
	কাঠামো sshbuf *বার্তা;
	u_int গুনতি, id, i, expected_id, ents = 0;
	আকার_t handle_len;
	u_char type, *handle;
	পূর্ণসংখ্যা status = SSH2_FX_FAILURE;
	পূর্ণসংখ্যা r;

	যদি (dir)
		*dir = ফাঁকা;

	id = conn->বার্তা_id++;

	যদি ((বার্তা = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshbuf_put_u8(বার্তা, SSH2_FXP_OPENDIR)) != 0 ||
	    (r = sshbuf_put_u32(বার্তা, id)) != 0 ||
	    (r = sshbuf_put_cstring(বার্তা, path)) != 0)
		fatal_fr(r, "compose OPENDIR");
	send_বার্তা(conn, বার্তা);

	handle = get_handle(conn, id, &handle_len,
	    "remote readdir(\"%s\")", path);
	যদি (handle == ফাঁকা) {
		sshbuf_free(বার্তা);
		ফেরত -1;
	}

	যদি (dir) {
		ents = 0;
		*dir = xcalloc(1, আকার(**dir));
		(*dir)[0] = ফাঁকা;
	}

	জন্য (; !interrupted;) {
		id = expected_id = conn->বার্তা_id++;

		debug3("Sending SSH2_FXP_READDIR I:%u", id);

		sshbuf_reset(বার্তা);
		যদি ((r = sshbuf_put_u8(বার্তা, SSH2_FXP_READDIR)) != 0 ||
		    (r = sshbuf_put_u32(বার্তা, id)) != 0 ||
		    (r = sshbuf_put_string(বার্তা, handle, handle_len)) != 0)
			fatal_fr(r, "compose READDIR");
		send_বার্তা(conn, বার্তা);

		sshbuf_reset(বার্তা);

		get_বার্তা(conn, বার্তা);

		যদি ((r = sshbuf_get_u8(বার্তা, &type)) != 0 ||
		    (r = sshbuf_get_u32(বার্তা, &id)) != 0)
			fatal_fr(r, "parse");

		debug3("Received reply T:%u I:%u", type, id);

		যদি (id != expected_id)
			fatal("ID mismatch (%u != %u)", id, expected_id);

		যদি (type == SSH2_FXP_STATUS) {
			u_int rstatus;

			যদি ((r = sshbuf_get_u32(বার্তা, &rstatus)) != 0)
				fatal_fr(r, "parse status");
			debug3("Received SSH2_FXP_STATUS %d", rstatus);
			যদি (rstatus == SSH2_FX_EOF)
				বিরতি;
			error("Couldn't read directory: %s", fx2txt(rstatus));
			যাও out;
		} অন্যথা যদি (type != SSH2_FXP_NAME)
			fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
			    SSH2_FXP_NAME, type);

		যদি ((r = sshbuf_get_u32(বার্তা, &গুনতি)) != 0)
			fatal_fr(r, "parse count");
		যদি (গুনতি > SSHBUF_আকার_MAX)
			fatal_f("nonsensical number of entries");
		যদি (গুনতি == 0)
			বিরতি;
		debug3("Received %d SSH2_FXP_NAME responses", গুনতি);
		জন্য (i = 0; i < গুনতি; i++) {
			অক্ষর *filename, *longname;
			Attrib a;

			যদি ((r = sshbuf_get_cstring(বার্তা, &filename,
			    ফাঁকা)) != 0 ||
			    (r = sshbuf_get_cstring(বার্তা, &longname,
			    ফাঁকা)) != 0)
				fatal_fr(r, "parse filenames");
			যদি ((r = decode_attrib(বার্তা, &a)) != 0) {
				error_fr(r, "couldn't decode attrib");
				মুক্ত(filename);
				মুক্ত(longname);
				যাও out;
			}

			যদি (print_flag)
				mprintf("%s\n", longname);

			/*
			 * Directory entries should never contain '/'
			 * These can be used to attack recursive ops
			 * (e.g. send '../../../../etc/passwd')
			 */
			যদি (*filename == '\0' ||
			    strpbrk(filename, SFTP_DIRECTORY_CHARS) != ফাঁকা) {
				error("Server sent suspect path \"%s\" "
				    "during readdir of \"%s\"", filename, path);
			} অন্যথা যদি (dir) {
				*dir = xreallocarray(*dir, ents + 2, আকার(**dir));
				(*dir)[ents] = xcalloc(1, আকার(***dir));
				(*dir)[ents]->filename = xstrdup(filename);
				(*dir)[ents]->longname = xstrdup(longname);
				memcpy(&(*dir)[ents]->a, &a, আকার(a));
				(*dir)[++ents] = ফাঁকা;
			}
			মুক্ত(filename);
			মুক্ত(longname);
		}
	}
	status = 0;

 out:
	sshbuf_free(বার্তা);
	sftp_close(conn, handle, handle_len);
	মুক্ত(handle);

	যদি (status != 0 && dir != ফাঁকা) {
		/* Don't return results on error */
		sftp_free_dirents(*dir);
		*dir = ফাঁকা;
	} অন্যথা যদি (interrupted && dir != ফাঁকা && *dir != ফাঁকা) {
		/* Don't return partial matches on interrupt */
		sftp_free_dirents(*dir);
		*dir = xcalloc(1, আকার(**dir));
		**dir = ফাঁকা;
	}

	ফেরত status == SSH2_FX_OK ? 0 : -1;
}

পূর্ণসংখ্যা
sftp_readdir(কাঠামো sftp_conn *conn, ধ্রুবক অক্ষর *path, SFTP_DIRENT ***dir)
{
	ফেরত sftp_lsreaddir(conn, path, 0, dir);
}

শূন্য sftp_free_dirents(SFTP_DIRENT **s)
{
	পূর্ণসংখ্যা i;

	যদি (s == ফাঁকা)
		ফেরত;
	জন্য (i = 0; s[i]; i++) {
		মুক্ত(s[i]->filename);
		মুক্ত(s[i]->longname);
		মুক্ত(s[i]);
	}
	মুক্ত(s);
}

পূর্ণসংখ্যা
sftp_rm(কাঠামো sftp_conn *conn, ধ্রুবক অক্ষর *path)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_REMOVE \"%s\"", path);

	id = conn->বার্তা_id++;
	send_string_request(conn, id, SSH2_FXP_REMOVE, path, strlen(path));
	status = get_status(conn, id);
	যদি (status != SSH2_FX_OK)
		error("remote delete %s: %s", path, fx2txt(status));
	ফেরত status == SSH2_FX_OK ? 0 : -1;
}

পূর্ণসংখ্যা
sftp_mkdir(কাঠামো sftp_conn *conn, ধ্রুবক অক্ষর *path, Attrib *a, পূর্ণসংখ্যা print_flag)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_MKDIR \"%s\"", path);

	id = conn->বার্তা_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_MKDIR, path,
	    strlen(path), a);

	status = get_status(conn, id);
	যদি (status != SSH2_FX_OK && print_flag)
		error("remote mkdir \"%s\": %s", path, fx2txt(status));

	ফেরত status == SSH2_FX_OK ? 0 : -1;
}

পূর্ণসংখ্যা
sftp_mkpath(কাঠামো sftp_conn *conn, ধ্রুবক অক্ষর *path, Attrib *a, পূর্ণসংখ্যা print_flag)
{
	অক্ষর *slash, *tmp_path;
	পূর্ণসংখ্যা done;

	tmp_path = xstrdup(path);
	slash = tmp_path;

	জন্য (;;) {
		slash += strspn(slash, "/");
		slash += strcspn(slash, "/");

		done = (*slash == '\0');
		*slash = '\0';

		যদি (!sftp_remote_is_dir(conn, tmp_path)) {
			যদি (sftp_mkdir(conn, tmp_path, a, print_flag) != 0) {
				মুক্ত(tmp_path);
				ফেরত -1;
			}
		}

		যদি (done)
			বিরতি;

		*slash = '/';
	}

	মুক্ত(tmp_path);
	ফেরত 0;
}

পূর্ণসংখ্যা
sftp_rmdir(কাঠামো sftp_conn *conn, ধ্রুবক অক্ষর *path)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_RMDIR \"%s\"", path);

	id = conn->বার্তা_id++;
	send_string_request(conn, id, SSH2_FXP_RMDIR, path,
	    strlen(path));

	status = get_status(conn, id);
	যদি (status != SSH2_FX_OK)
		error("remote rmdir \"%s\": %s", path, fx2txt(status));

	ফেরত status == SSH2_FX_OK ? 0 : -1;
}

পূর্ণসংখ্যা
sftp_stat(কাঠামো sftp_conn *conn, ধ্রুবক অক্ষর *path, পূর্ণসংখ্যা quiet, Attrib *a)
{
	u_int id;

	debug2("Sending SSH2_FXP_STAT \"%s\"", path);

	id = conn->বার্তা_id++;

	send_string_request(conn, id,
	    conn->version == 0 ? SSH2_FXP_STAT_VERSION_0 : SSH2_FXP_STAT,
	    path, strlen(path));

	ফেরত get_decode_stat(conn, id, quiet, a);
}

পূর্ণসংখ্যা
sftp_lstat(কাঠামো sftp_conn *conn, ধ্রুবক অক্ষর *path, পূর্ণসংখ্যা quiet, Attrib *a)
{
	u_int id;

	যদি (conn->version == 0) {
		do_log2(quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_INFO,
		    "Server version does not support lstat operation");
		ফেরত sftp_stat(conn, path, quiet, a);
	}

	id = conn->বার্তা_id++;
	send_string_request(conn, id, SSH2_FXP_LSTAT, path,
	    strlen(path));

	ফেরত get_decode_stat(conn, id, quiet, a);
}

#ifdef notyet
পূর্ণসংখ্যা
sftp_fstat(কাঠামো sftp_conn *conn, ধ্রুবক u_char *handle, u_int handle_len,
    পূর্ণসংখ্যা quiet, Attrib *a)
{
	u_int id;

	debug2("Sending SSH2_FXP_FSTAT \"%s\"");

	id = conn->বার্তা_id++;
	send_string_request(conn, id, SSH2_FXP_FSTAT, handle,
	    handle_len);

	ফেরত get_decode_stat(conn, id, quiet, a);
}
#endif

পূর্ণসংখ্যা
sftp_setstat(কাঠামো sftp_conn *conn, ধ্রুবক অক্ষর *path, Attrib *a)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_SETSTAT \"%s\"", path);

	id = conn->বার্তা_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_SETSTAT, path,
	    strlen(path), a);

	status = get_status(conn, id);
	যদি (status != SSH2_FX_OK)
		error("remote setstat \"%s\": %s", path, fx2txt(status));

	ফেরত status == SSH2_FX_OK ? 0 : -1;
}

পূর্ণসংখ্যা
sftp_fsetstat(কাঠামো sftp_conn *conn, ধ্রুবক u_char *handle, u_int handle_len,
    Attrib *a)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_FSETSTAT");

	id = conn->বার্তা_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_FSETSTAT, handle,
	    handle_len, a);

	status = get_status(conn, id);
	যদি (status != SSH2_FX_OK)
		error("remote fsetstat: %s", fx2txt(status));

	ফেরত status == SSH2_FX_OK ? 0 : -1;
}

/* Implements both the realpath and expand-path operations */
স্থির অক্ষর *
sftp_realpath_expand(কাঠামো sftp_conn *conn, ধ্রুবক অক্ষর *path, পূর্ণসংখ্যা expand)
{
	কাঠামো sshbuf *বার্তা;
	u_int expected_id, গুনতি, id;
	অক্ষর *filename, *longname;
	Attrib a;
	u_char type;
	পূর্ণসংখ্যা r;
	ধ্রুবক অক্ষর *what = "SSH2_FXP_REALPATH";

	যদি (expand)
		what = "expand-path@openssh.com";
	যদি ((বার্তা = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");

	expected_id = id = conn->বার্তা_id++;
	যদি (expand) {
		debug2("Sending SSH2_FXP_EXTENDED(expand-path@openssh.com) "
		    "\"%s\"", path);
		যদি ((r = sshbuf_put_u8(বার্তা, SSH2_FXP_EXTENDED)) != 0 ||
		    (r = sshbuf_put_u32(বার্তা, id)) != 0 ||
		    (r = sshbuf_put_cstring(বার্তা,
		    "expand-path@openssh.com")) != 0 ||
		    (r = sshbuf_put_cstring(বার্তা, path)) != 0)
			fatal_fr(r, "compose %s", what);
		send_বার্তা(conn, বার্তা);
	} অন্যথা {
		debug2("Sending SSH2_FXP_REALPATH \"%s\"", path);
		send_string_request(conn, id, SSH2_FXP_REALPATH,
		    path, strlen(path));
	}
	get_বার্তা(conn, বার্তা);
	যদি ((r = sshbuf_get_u8(বার্তা, &type)) != 0 ||
	    (r = sshbuf_get_u32(বার্তা, &id)) != 0)
		fatal_fr(r, "parse");

	যদি (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);

	যদি (type == SSH2_FXP_STATUS) {
		u_int status;
		অক্ষর *errmsg;

		যদি ((r = sshbuf_get_u32(বার্তা, &status)) != 0 ||
		    (r = sshbuf_get_cstring(বার্তা, &errmsg, ফাঁকা)) != 0)
			fatal_fr(r, "parse status");
		error("%s %s: %s", expand ? "expand" : "realpath",
		    path, *errmsg == '\0' ? fx2txt(status) : errmsg);
		মুক্ত(errmsg);
		sshbuf_free(বার্তা);
		ফেরত ফাঁকা;
	} অন্যথা যদি (type != SSH2_FXP_NAME)
		fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
		    SSH2_FXP_NAME, type);

	যদি ((r = sshbuf_get_u32(বার্তা, &গুনতি)) != 0)
		fatal_fr(r, "parse count");
	যদি (গুনতি != 1)
		fatal("Got multiple names (%d) from %s", গুনতি, what);

	যদি ((r = sshbuf_get_cstring(বার্তা, &filename, ফাঁকা)) != 0 ||
	    (r = sshbuf_get_cstring(বার্তা, &longname, ফাঁকা)) != 0 ||
	    (r = decode_attrib(বার্তা, &a)) != 0)
		fatal_fr(r, "parse filename/attrib");

	debug3("%s %s -> %s", what, path, filename);

	মুক্ত(longname);

	sshbuf_free(বার্তা);

	ফেরত(filename);
}

অক্ষর *
sftp_realpath(কাঠামো sftp_conn *conn, ধ্রুবক অক্ষর *path)
{
	ফেরত sftp_realpath_expand(conn, path, 0);
}

পূর্ণসংখ্যা
sftp_can_expand_path(কাঠামো sftp_conn *conn)
{
	ফেরত (conn->exts & SFTP_EXT_PATH_EXPAND) != 0;
}

অক্ষর *
sftp_expand_path(কাঠামো sftp_conn *conn, ধ্রুবক অক্ষর *path)
{
	যদি (!sftp_can_expand_path(conn)) {
		debug3_f("no server support, fallback to realpath");
		ফেরত sftp_realpath_expand(conn, path, 0);
	}
	ফেরত sftp_realpath_expand(conn, path, 1);
}

পূর্ণসংখ্যা
sftp_copy(কাঠামো sftp_conn *conn, ধ্রুবক অক্ষর *oldpath, ধ্রুবক অক্ষর *newpath)
{
	Attrib junk, attr;
	কাঠামো sshbuf *বার্তা;
	u_char *old_handle, *new_handle;
	u_int mode, status, id;
	আকার_t old_handle_len, new_handle_len;
	পূর্ণসংখ্যা r;

	/* Return if the extension is not supported */
	যদি ((conn->exts & SFTP_EXT_COPY_তথ্য) == 0) {
		error("Server does not support copy-data extension");
		ফেরত -1;
	}

	/* Make sure the file exists, and we can copy its perms */
	যদি (sftp_stat(conn, oldpath, 0, &attr) != 0)
		ফেরত -1;

	/* Do not preserve set[ug]id here, as we do not preserve ownership */
	যদি (attr.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		mode = attr.perm & 0777;

		যদি (!S_ISREG(attr.perm)) {
			error("Cannot copy non-regular file: %s", oldpath);
			ফেরত -1;
		}
	} অন্যথা {
		/* NB: The user's umask will apply to this */
		mode = 0666;
	}

	/* Set up the new perms for the new file */
	attrib_clear(&attr);
	attr.perm = mode;
	attr.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;

	যদি ((বার্তা = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");

	attrib_clear(&junk); /* Send empty attributes */

	/* Open the old file for reading */
	id = conn->বার্তা_id++;
	যদি ((r = sshbuf_put_u8(বার্তা, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(বার্তা, id)) != 0 ||
	    (r = sshbuf_put_cstring(বার্তা, oldpath)) != 0 ||
	    (r = sshbuf_put_u32(বার্তা, SSH2_FXF_READ)) != 0 ||
	    (r = encode_attrib(বার্তা, &junk)) != 0)
		fatal_fr(r, "buffer error");
	send_বার্তা(conn, বার্তা);
	debug3("Sent message SSH2_FXP_OPEN I:%u P:%s", id, oldpath);

	sshbuf_reset(বার্তা);

	old_handle = get_handle(conn, id, &old_handle_len,
	    "remote open(\"%s\")", oldpath);
	যদি (old_handle == ফাঁকা) {
		sshbuf_free(বার্তা);
		ফেরত -1;
	}

	/* Open the new file for writing */
	id = conn->বার্তা_id++;
	যদি ((r = sshbuf_put_u8(বার্তা, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(বার্তা, id)) != 0 ||
	    (r = sshbuf_put_cstring(বার্তা, newpath)) != 0 ||
	    (r = sshbuf_put_u32(বার্তা, SSH2_FXF_WRITE|SSH2_FXF_CREAT|
	    SSH2_FXF_TRUNC)) != 0 ||
	    (r = encode_attrib(বার্তা, &attr)) != 0)
		fatal_fr(r, "buffer error");
	send_বার্তা(conn, বার্তা);
	debug3("Sent message SSH2_FXP_OPEN I:%u P:%s", id, newpath);

	sshbuf_reset(বার্তা);

	new_handle = get_handle(conn, id, &new_handle_len,
	    "remote open(\"%s\")", newpath);
	যদি (new_handle == ফাঁকা) {
		sshbuf_free(বার্তা);
		মুক্ত(old_handle);
		ফেরত -1;
	}

	/* Copy the file data */
	id = conn->বার্তা_id++;
	যদি ((r = sshbuf_put_u8(বার্তা, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(বার্তা, id)) != 0 ||
	    (r = sshbuf_put_cstring(বার্তা, "copy-data")) != 0 ||
	    (r = sshbuf_put_string(বার্তা, old_handle, old_handle_len)) != 0 ||
	    (r = sshbuf_put_u64(বার্তা, 0)) != 0 ||
	    (r = sshbuf_put_u64(বার্তা, 0)) != 0 ||
	    (r = sshbuf_put_string(বার্তা, new_handle, new_handle_len)) != 0 ||
	    (r = sshbuf_put_u64(বার্তা, 0)) != 0)
		fatal_fr(r, "buffer error");
	send_বার্তা(conn, বার্তা);
	debug3("Sent message copy-data \"%s\" 0 0 -> \"%s\" 0",
	       oldpath, newpath);

	status = get_status(conn, id);
	যদি (status != SSH2_FX_OK)
		error("Couldn't copy file \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	/* Clean up everything */
	sshbuf_free(বার্তা);
	sftp_close(conn, old_handle, old_handle_len);
	sftp_close(conn, new_handle, new_handle_len);
	মুক্ত(old_handle);
	মুক্ত(new_handle);

	ফেরত status == SSH2_FX_OK ? 0 : -1;
}

পূর্ণসংখ্যা
sftp_rename(কাঠামো sftp_conn *conn, ধ্রুবক অক্ষর *oldpath, ধ্রুবক অক্ষর *newpath,
    পূর্ণসংখ্যা force_legacy)
{
	কাঠামো sshbuf *বার্তা;
	u_int status, id;
	পূর্ণসংখ্যা r, use_ext = (conn->exts & SFTP_EXT_POSIX_RENAME) && !force_legacy;

	যদি ((বার্তা = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");

	/* Send rename request */
	id = conn->বার্তা_id++;
	যদি (use_ext) {
		debug2("Sending SSH2_FXP_EXTENDED(posix-rename@openssh.com) "
		    "\"%s\" to \"%s\"", oldpath, newpath);
		যদি ((r = sshbuf_put_u8(বার্তা, SSH2_FXP_EXTENDED)) != 0 ||
		    (r = sshbuf_put_u32(বার্তা, id)) != 0 ||
		    (r = sshbuf_put_cstring(বার্তা,
		    "posix-rename@openssh.com")) != 0)
			fatal_fr(r, "compose posix-rename");
	} অন্যথা {
		debug2("Sending SSH2_FXP_RENAME \"%s\" to \"%s\"",
		    oldpath, newpath);
		যদি ((r = sshbuf_put_u8(বার্তা, SSH2_FXP_RENAME)) != 0 ||
		    (r = sshbuf_put_u32(বার্তা, id)) != 0)
			fatal_fr(r, "compose rename");
	}
	যদি ((r = sshbuf_put_cstring(বার্তা, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(বার্তা, newpath)) != 0)
		fatal_fr(r, "compose paths");
	send_বার্তা(conn, বার্তা);
	debug3("Sent message %s \"%s\" -> \"%s\"",
	    use_ext ? "posix-rename@openssh.com" :
	    "SSH2_FXP_RENAME", oldpath, newpath);
	sshbuf_free(বার্তা);

	status = get_status(conn, id);
	যদি (status != SSH2_FX_OK)
		error("remote rename \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	ফেরত status == SSH2_FX_OK ? 0 : -1;
}

পূর্ণসংখ্যা
sftp_hardlink(কাঠামো sftp_conn *conn, ধ্রুবক অক্ষর *oldpath, ধ্রুবক অক্ষর *newpath)
{
	কাঠামো sshbuf *বার্তা;
	u_int status, id;
	পূর্ণসংখ্যা r;

	যদি ((conn->exts & SFTP_EXT_HARDLINK) == 0) {
		error("Server does not support hardlink@openssh.com extension");
		ফেরত -1;
	}
	debug2("Sending SSH2_FXP_EXTENDED(hardlink@openssh.com) "
	    "\"%s\" to \"%s\"", oldpath, newpath);

	যদি ((বার্তা = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");

	/* Send link request */
	id = conn->বার্তা_id++;
	যদি ((r = sshbuf_put_u8(বার্তা, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(বার্তা, id)) != 0 ||
	    (r = sshbuf_put_cstring(বার্তা, "hardlink@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(বার্তা, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(বার্তা, newpath)) != 0)
		fatal_fr(r, "compose");
	send_বার্তা(conn, বার্তা);
	debug3("Sent message hardlink@openssh.com \"%s\" -> \"%s\"",
	    oldpath, newpath);
	sshbuf_free(বার্তা);

	status = get_status(conn, id);
	যদি (status != SSH2_FX_OK)
		error("remote link \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	ফেরত status == SSH2_FX_OK ? 0 : -1;
}

পূর্ণসংখ্যা
sftp_symlink(কাঠামো sftp_conn *conn, ধ্রুবক অক্ষর *oldpath, ধ্রুবক অক্ষর *newpath)
{
	কাঠামো sshbuf *বার্তা;
	u_int status, id;
	পূর্ণসংখ্যা r;

	যদি (conn->version < 3) {
		error("This server does not support the symlink operation");
		ফেরত(SSH2_FX_OP_UNSUPPORTED);
	}
	debug2("Sending SSH2_FXP_SYMLINK \"%s\" to \"%s\"", oldpath, newpath);

	যদি ((বার্তা = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");

	/* Send symlink request */
	id = conn->বার্তা_id++;
	যদি ((r = sshbuf_put_u8(বার্তা, SSH2_FXP_SYMLINK)) != 0 ||
	    (r = sshbuf_put_u32(বার্তা, id)) != 0 ||
	    (r = sshbuf_put_cstring(বার্তা, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(বার্তা, newpath)) != 0)
		fatal_fr(r, "compose");
	send_বার্তা(conn, বার্তা);
	debug3("Sent message SSH2_FXP_SYMLINK \"%s\" -> \"%s\"", oldpath,
	    newpath);
	sshbuf_free(বার্তা);

	status = get_status(conn, id);
	যদি (status != SSH2_FX_OK)
		error("remote symlink file \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	ফেরত status == SSH2_FX_OK ? 0 : -1;
}

পূর্ণসংখ্যা
sftp_fsync(কাঠামো sftp_conn *conn, u_char *handle, u_int handle_len)
{
	কাঠামো sshbuf *বার্তা;
	u_int status, id;
	পূর্ণসংখ্যা r;

	/* Silently return if the extension is not supported */
	যদি ((conn->exts & SFTP_EXT_FSYNC) == 0)
		ফেরত -1;
	debug2("Sending SSH2_FXP_EXTENDED(fsync@openssh.com)");

	/* Send fsync request */
	যদি ((বার্তা = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");
	id = conn->বার্তা_id++;
	যদি ((r = sshbuf_put_u8(বার্তা, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(বার্তা, id)) != 0 ||
	    (r = sshbuf_put_cstring(বার্তা, "fsync@openssh.com")) != 0 ||
	    (r = sshbuf_put_string(বার্তা, handle, handle_len)) != 0)
		fatal_fr(r, "compose");
	send_বার্তা(conn, বার্তা);
	debug3("Sent message fsync@openssh.com I:%u", id);
	sshbuf_free(বার্তা);

	status = get_status(conn, id);
	যদি (status != SSH2_FX_OK)
		error("remote fsync: %s", fx2txt(status));

	ফেরত status == SSH2_FX_OK ? 0 : -1;
}

#ifdef notyet
অক্ষর *
sftp_readlink(কাঠামো sftp_conn *conn, ধ্রুবক অক্ষর *path)
{
	কাঠামো sshbuf *বার্তা;
	u_int expected_id, গুনতি, id;
	অক্ষর *filename, *longname;
	Attrib a;
	u_char type;
	পূর্ণসংখ্যা r;

	debug2("Sending SSH2_FXP_READLINK \"%s\"", path);

	expected_id = id = conn->বার্তা_id++;
	send_string_request(conn, id, SSH2_FXP_READLINK, path, strlen(path));

	যদি ((বার্তা = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");

	get_বার্তা(conn, বার্তা);
	যদি ((r = sshbuf_get_u8(বার্তা, &type)) != 0 ||
	    (r = sshbuf_get_u32(বার্তা, &id)) != 0)
		fatal_fr(r, "parse");

	যদি (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);

	যদি (type == SSH2_FXP_STATUS) {
		u_int status;

		যদি ((r = sshbuf_get_u32(বার্তা, &status)) != 0)
			fatal_fr(r, "parse status");
		error("Couldn't readlink: %s", fx2txt(status));
		sshbuf_free(বার্তা);
		ফেরত(ফাঁকা);
	} অন্যথা যদি (type != SSH2_FXP_NAME)
		fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
		    SSH2_FXP_NAME, type);

	যদি ((r = sshbuf_get_u32(বার্তা, &গুনতি)) != 0)
		fatal_fr(r, "parse count");
	যদি (গুনতি != 1)
		fatal("Got multiple names (%d) from SSH_FXP_READLINK", গুনতি);

	যদি ((r = sshbuf_get_cstring(বার্তা, &filename, ফাঁকা)) != 0 ||
	    (r = sshbuf_get_cstring(বার্তা, &longname, ফাঁকা)) != 0 ||
	    (r = decode_attrib(বার্তা, &a)) != 0)
		fatal_fr(r, "parse filenames/attrib");

	debug3("SSH_FXP_READLINK %s -> %s", path, filename);

	মুক্ত(longname);

	sshbuf_free(বার্তা);

	ফেরত filename;
}
#endif

পূর্ণসংখ্যা
sftp_statvfs(কাঠামো sftp_conn *conn, ধ্রুবক অক্ষর *path, কাঠামো sftp_statvfs *st,
    পূর্ণসংখ্যা quiet)
{
	কাঠামো sshbuf *বার্তা;
	u_int id;
	পূর্ণসংখ্যা r;

	যদি ((conn->exts & SFTP_EXT_STATVFS) == 0) {
		error("Server does not support statvfs@openssh.com extension");
		ফেরত -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(statvfs@openssh.com) \"%s\"", path);

	id = conn->বার্তা_id++;

	যদি ((বার্তা = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshbuf_put_u8(বার্তা, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(বার্তা, id)) != 0 ||
	    (r = sshbuf_put_cstring(বার্তা, "statvfs@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(বার্তা, path)) != 0)
		fatal_fr(r, "compose");
	send_বার্তা(conn, বার্তা);
	sshbuf_free(বার্তা);

	ফেরত get_decode_statvfs(conn, st, id, quiet);
}

#ifdef notyet
পূর্ণসংখ্যা
sftp_fstatvfs(কাঠামো sftp_conn *conn, ধ্রুবক u_char *handle, u_int handle_len,
    কাঠামো sftp_statvfs *st, পূর্ণসংখ্যা quiet)
{
	কাঠামো sshbuf *বার্তা;
	u_int id;

	যদি ((conn->exts & SFTP_EXT_FSTATVFS) == 0) {
		error("Server does not support fstatvfs@openssh.com extension");
		ফেরত -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(fstatvfs@openssh.com)");

	id = conn->বার্তা_id++;

	যদি ((বার্তা = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshbuf_put_u8(বার্তা, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(বার্তা, id)) != 0 ||
	    (r = sshbuf_put_cstring(বার্তা, "fstatvfs@openssh.com")) != 0 ||
	    (r = sshbuf_put_string(বার্তা, handle, handle_len)) != 0)
		fatal_fr(r, "compose");
	send_বার্তা(conn, বার্তা);
	sshbuf_free(বার্তা);

	ফেরত get_decode_statvfs(conn, st, id, quiet);
}
#endif

পূর্ণসংখ্যা
sftp_lsetstat(কাঠামো sftp_conn *conn, ধ্রুবক অক্ষর *path, Attrib *a)
{
	কাঠামো sshbuf *বার্তা;
	u_int status, id;
	পূর্ণসংখ্যা r;

	যদি ((conn->exts & SFTP_EXT_LSETSTAT) == 0) {
		error("Server does not support lsetstat@openssh.com extension");
		ফেরত -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(lsetstat@openssh.com) \"%s\"", path);

	id = conn->বার্তা_id++;
	যদি ((বার্তা = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshbuf_put_u8(বার্তা, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(বার্তা, id)) != 0 ||
	    (r = sshbuf_put_cstring(বার্তা, "lsetstat@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(বার্তা, path)) != 0 ||
	    (r = encode_attrib(বার্তা, a)) != 0)
		fatal_fr(r, "compose");
	send_বার্তা(conn, বার্তা);
	sshbuf_free(বার্তা);

	status = get_status(conn, id);
	যদি (status != SSH2_FX_OK)
		error("remote lsetstat \"%s\": %s", path, fx2txt(status));

	ফেরত status == SSH2_FX_OK ? 0 : -1;
}

স্থির শূন্য
send_read_request(কাঠামো sftp_conn *conn, u_int id, uint64_t offset,
    u_int len, ধ্রুবক u_char *handle, u_int handle_len)
{
	কাঠামো sshbuf *বার্তা;
	পূর্ণসংখ্যা r;

	যদি ((বার্তা = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshbuf_put_u8(বার্তা, SSH2_FXP_READ)) != 0 ||
	    (r = sshbuf_put_u32(বার্তা, id)) != 0 ||
	    (r = sshbuf_put_string(বার্তা, handle, handle_len)) != 0 ||
	    (r = sshbuf_put_u64(বার্তা, offset)) != 0 ||
	    (r = sshbuf_put_u32(বার্তা, len)) != 0)
		fatal_fr(r, "compose");
	send_বার্তা(conn, বার্তা);
	sshbuf_free(বার্তা);
}

স্থির পূর্ণসংখ্যা
send_open(কাঠামো sftp_conn *conn, ধ্রুবক অক্ষর *path, ধ্রুবক অক্ষর *tag,
    u_int openmode, Attrib *a, u_char **handlep, আকার_t *handle_lenp)
{
	Attrib junk;
	u_char *handle;
	আকার_t handle_len;
	কাঠামো sshbuf *বার্তা;
	পূর্ণসংখ্যা r;
	u_int id;

	debug2("Sending SSH2_FXP_OPEN \"%s\"", path);

	*handlep = ফাঁকা;
	*handle_lenp = 0;

	যদি (a == ফাঁকা) {
		attrib_clear(&junk); /* Send empty attributes */
		a = &junk;
	}
	/* Send open request */
	যদি ((বার্তা = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");
	id = conn->বার্তা_id++;
	যদি ((r = sshbuf_put_u8(বার্তা, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(বার্তা, id)) != 0 ||
	    (r = sshbuf_put_cstring(বার্তা, path)) != 0 ||
	    (r = sshbuf_put_u32(বার্তা, openmode)) != 0 ||
	    (r = encode_attrib(বার্তা, a)) != 0)
		fatal_fr(r, "compose %s open", tag);
	send_বার্তা(conn, বার্তা);
	sshbuf_free(বার্তা);
	debug3("Sent %s message SSH2_FXP_OPEN I:%u P:%s M:0x%04x",
	    tag, id, path, openmode);
	যদি ((handle = get_handle(conn, id, &handle_len,
	    "%s open \"%s\"", tag, path)) == ফাঁকা)
		ফেরত -1;
	/* success */
	*handlep = handle;
	*handle_lenp = handle_len;
	ফেরত 0;
}

স্থির ধ্রুবক অক্ষর *
progress_meter_path(ধ্রুবক অক্ষর *path)
{
	ধ্রুবক অক্ষর *progresspath;

	যদি ((progresspath = strrchr(path, '/')) == ফাঁকা)
		ফেরত path;
	progresspath++;
	যদি (*progresspath == '\0')
		ফেরত path;
	ফেরত progresspath;
}

পূর্ণসংখ্যা
sftp_download(কাঠামো sftp_conn *conn, ধ্রুবক অক্ষর *remote_path,
    ধ্রুবক অক্ষর *local_path, Attrib *a, পূর্ণসংখ্যা preserve_flag, পূর্ণসংখ্যা resume_flag,
    পূর্ণসংখ্যা fsync_flag, পূর্ণসংখ্যা inplace_flag)
{
	কাঠামো sshbuf *বার্তা;
	u_char *handle;
	পূর্ণসংখ্যা local_fd = -1, write_error, seen_zerolen = 0;
	পূর্ণসংখ্যা read_error, write_errno, lmodified = 0, reordered = 0, r;
	uint64_t offset = 0, আকার_2, highwater = 0, maxack = 0;
	u_int mode, id, buflen, অঙ্ক_req, max_req, status = SSH2_FX_OK;
	off_t progress_গণক;
	আকার_t handle_len;
	কাঠামো stat st;
	কাঠামো requests requests;
	কাঠামো request *req;
	u_char type;
	Attrib attr;

	debug2_f("download remote \"%s\" to local \"%s\"",
	    remote_path, local_path);

	TAILQ_INIT(&requests);

	যদি (a == ফাঁকা) {
		যদি (sftp_stat(conn, remote_path, 0, &attr) != 0)
			ফেরত -1;
		a = &attr;
	}

	/* Do not preserve set[ug]id here, as we do not preserve ownership */
	যদি (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS)
		mode = a->perm & 0777;
	অন্যথা
		mode = 0666;

	যদি ((a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) &&
	    (!S_ISREG(a->perm))) {
		error("download %s: not a regular file", remote_path);
		ফেরত(-1);
	}

	যদি (a->flags & SSH2_FILEXFER_ATTR_আকার)
		আকার_2 = a->আকার_2;
	অন্যথা
		আকার_2 = 0;

	buflen = conn->download_buflen;

	/* Send open request */
	যদি (send_open(conn, remote_path, "remote", SSH2_FXF_READ, ফাঁকা,
	    &handle, &handle_len) != 0)
		ফেরত -1;

	local_fd = open(local_path, O_WRONLY | O_CREAT |
	((resume_flag || inplace_flag) ? 0 : O_TRUNC), mode | S_IWUSR);
	যদি (local_fd == -1) {
		error("open local \"%s\": %s", local_path, strerror(errno));
		যাও fail;
	}
	যদি (resume_flag) {
		যদি (fstat(local_fd, &st) == -1) {
			error("stat local \"%s\": %s",
			    local_path, strerror(errno));
			যাও fail;
		}
		যদি (st.st_size < 0) {
			error("\"%s\" has negative size", local_path);
			যাও fail;
		}
		যদি ((uint64_t)st.st_size > আকার_2) {
			error("Unable to resume download of \"%s\": "
			    "local file is larger than remote", local_path);
 fail:
			sftp_close(conn, handle, handle_len);
			মুক্ত(handle);
			যদি (local_fd != -1)
				close(local_fd);
			ফেরত -1;
		}
		offset = highwater = maxack = st.st_size;
	}

	/* Read from remote and write to local */
	write_error = read_error = write_errno = অঙ্ক_req = 0;
	max_req = 1;
	progress_গণক = offset;

	যদি (showprogress && আকার_2 != 0) {
		start_progress_meter(progress_meter_path(remote_path),
		    আকার_2, &progress_গণক);
	}

	যদি ((বার্তা = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");

	যখন (অঙ্ক_req > 0 || max_req > 0) {
		u_char *তথ্য;
		আকার_t len;

		/*
		 * Simulate EOF on interrupt: stop sending new requests and
		 * allow outstanding requests to drain gracefully
		 */
		যদি (interrupted) {
			যদি (অঙ্ক_req == 0) /* If we haven't started yet... */
				বিরতি;
			max_req = 0;
		}

		/* Send some more requests */
		যখন (অঙ্ক_req < max_req) {
			debug3("Request range %llu -> %llu (%d/%d)",
			    (unsigned long long)offset,
			    (unsigned long long)offset + buflen - 1,
			    অঙ্ক_req, max_req);
			req = request_enqueue(&requests, conn->বার্তা_id++,
			    buflen, offset);
			offset += buflen;
			অঙ্ক_req++;
			send_read_request(conn, req->id, req->offset,
			    req->len, handle, handle_len);
		}

		sshbuf_reset(বার্তা);
		get_বার্তা(conn, বার্তা);
		যদি ((r = sshbuf_get_u8(বার্তা, &type)) != 0 ||
		    (r = sshbuf_get_u32(বার্তা, &id)) != 0)
			fatal_fr(r, "parse");
		debug3("Received reply T:%u I:%u R:%d", type, id, max_req);

		/* Find the request in our queue */
		যদি ((req = request_find(&requests, id)) == ফাঁকা)
			fatal("Unexpected reply %u", id);

		নির্বাচন (type) {
		ক্ষেত্র SSH2_FXP_STATUS:
			যদি ((r = sshbuf_get_u32(বার্তা, &status)) != 0)
				fatal_fr(r, "parse status");
			যদি (status != SSH2_FX_EOF)
				read_error = 1;
			max_req = 0;
			TAILQ_REMOVE(&requests, req, tq);
			মুক্ত(req);
			অঙ্ক_req--;
			বিরতি;
		ক্ষেত্র SSH2_FXP_তথ্য:
			যদি ((r = sshbuf_get_string(বার্তা, &তথ্য, &len)) != 0)
				fatal_fr(r, "parse data");
			debug3("Received data %llu -> %llu",
			    (unsigned long long)req->offset,
			    (unsigned long long)req->offset + len - 1);
			যদি (len > req->len)
				fatal("Received more data than asked for "
				    "%zu > %zu", len, req->len);
			যদি (len == 0) {
				যদি (seen_zerolen)
					fatal_f("server sent zero data length");
				seen_zerolen = 1;
			}
			lmodified = 1;
			যদি ((lseek(local_fd, req->offset, SEEK_SET) == -1 ||
			    atomicio(vwrite, local_fd, তথ্য, len) != len) &&
			    !write_error) {
				write_errno = errno;
				write_error = 1;
				max_req = 0;
			} অন্যথা {
				/*
				 * Track both the highest offset acknowledged
				 * and the highest *contiguous* offset
				 * acknowledged.
				 * We'll need the latter for ftruncate()ing
				 * interrupted transfers.
				 */
				যদি (maxack < req->offset + len)
					maxack = req->offset + len;
				যদি (!reordered && req->offset <= highwater)
					highwater = maxack;
				অন্যথা যদি (!reordered && req->offset > highwater)
					reordered = 1;
			}
			progress_গণক += len;
			মুক্ত(তথ্য);

			যদি (len == req->len) {
				TAILQ_REMOVE(&requests, req, tq);
				মুক্ত(req);
				অঙ্ক_req--;
			} অন্যথা {
				/* Resend the request for the missing data */
				debug3("Short data block, re-requesting "
				    "%llu -> %llu (%2d)",
				    (unsigned long long)req->offset + len,
				    (unsigned long long)req->offset +
				    req->len - 1, অঙ্ক_req);
				req->id = conn->বার্তা_id++;
				req->len -= len;
				req->offset += len;
				send_read_request(conn, req->id,
				    req->offset, req->len, handle, handle_len);
				/* Reduce the request size */
				যদি (len < buflen)
					buflen = MAXIMUM(MIN_READ_আকার, len);
			}
			যদি (max_req > 0) { /* max_req = 0 iff EOF received */
				যদি (আকার_2 > 0 && offset > আকার_2) {
					/* Only one request at a time
					 * after the expected EOF */
					debug3("Finish at %llu (%2d)",
					    (unsigned long long)offset,
					    অঙ্ক_req);
					max_req = 1;
				} অন্যথা যদি (max_req < conn->অঙ্ক_requests) {
					++max_req;
				}
			}
			বিরতি;
		পূর্বনির্ধারিত:
			fatal("Expected SSH2_FXP_DATA(%u) packet, got %u",
			    SSH2_FXP_তথ্য, type);
		}
	}

	যদি (showprogress && আকার_2)
		stop_progress_meter();

	/* Sanity check */
	যদি (TAILQ_FIRST(&requests) != ফাঁকা)
		fatal("Transfer complete, but requests still in queue");

	যদি (!read_error && !write_error && !interrupted) {
		/* we got everything */
		highwater = maxack;
	}

	/*
	 * Truncate at highest contiguous point to avoid holes on interrupt,
	 * or unconditionally if writing in place.
	 */
	যদি (inplace_flag || read_error || write_error || interrupted) {
		যদি (reordered && resume_flag &&
		    (read_error || write_error || interrupted)) {
			error("Unable to resume download of \"%s\": "
			    "server reordered requests", local_path);
		}
		debug("truncating at %llu", (unsigned long long)highwater);
		যদি (ftruncate(local_fd, highwater) == -1)
			error("local ftruncate \"%s\": %s", local_path,
			    strerror(errno));
	}
	যদি (read_error) {
		error("read remote \"%s\" : %s", remote_path, fx2txt(status));
		status = -1;
		sftp_close(conn, handle, handle_len);
	} অন্যথা যদি (write_error) {
		error("write local \"%s\": %s", local_path,
		    strerror(write_errno));
		status = SSH2_FX_FAILURE;
		sftp_close(conn, handle, handle_len);
	} অন্যথা {
		যদি (sftp_close(conn, handle, handle_len) != 0 || interrupted)
			status = SSH2_FX_FAILURE;
		অন্যথা
			status = SSH2_FX_OK;
		/* Override umask and utimes if asked */
#ifdef HAVE_FCHMOD
		যদি (preserve_flag && fchmod(local_fd, mode) == -1)
#অন্যথা
		যদি (preserve_flag && chmod(local_path, mode) == -1)
#endif /* HAVE_FCHMOD */
			error("local chmod \"%s\": %s", local_path,
			    strerror(errno));
		যদি (preserve_flag &&
		    (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME)) {
			কাঠামো timeval tv[2];
			tv[0].tv_sec = a->atime;
			tv[1].tv_sec = a->mtime;
			tv[0].tv_usec = tv[1].tv_usec = 0;
			যদি (utimes(local_path, tv) == -1)
				error("local set times \"%s\": %s",
				    local_path, strerror(errno));
		}
		যদি (resume_flag && !lmodified)
			logit("File \"%s\" was not modified", local_path);
		অন্যথা যদি (fsync_flag) {
			debug("syncing \"%s\"", local_path);
			যদি (fsync(local_fd) == -1)
				error("local sync \"%s\": %s",
				    local_path, strerror(errno));
		}
	}
	close(local_fd);
	sshbuf_free(বার্তা);
	মুক্ত(handle);

	ফেরত status == SSH2_FX_OK ? 0 : -1;
}

স্থির পূর্ণসংখ্যা
download_dir_internal(কাঠামো sftp_conn *conn, ধ্রুবক অক্ষর *src, ধ্রুবক অক্ষর *dst,
    পূর্ণসংখ্যা depth, Attrib *dirattrib, পূর্ণসংখ্যা preserve_flag, পূর্ণসংখ্যা print_flag,
    পূর্ণসংখ্যা resume_flag, পূর্ণসংখ্যা fsync_flag, পূর্ণসংখ্যা follow_link_flag, পূর্ণসংখ্যা inplace_flag)
{
	পূর্ণসংখ্যা i, ret = 0;
	SFTP_DIRENT **dir_entries;
	অক্ষর *filename, *new_src = ফাঁকা, *new_dst = ফাঁকা;
	mode_t mode = 0777, tmpmode = mode;
	Attrib *a, ldirattrib, lsym;

	যদি (depth >= MAX_DIR_DEPTH) {
		error("Maximum directory depth exceeded: %d levels", depth);
		ফেরত -1;
	}

	debug2_f("download dir remote \"%s\" to local \"%s\"", src, dst);

	যদি (dirattrib == ফাঁকা) {
		যদি (sftp_stat(conn, src, 1, &ldirattrib) != 0) {
			error("stat remote \"%s\" directory failed", src);
			ফেরত -1;
		}
		dirattrib = &ldirattrib;
	}
	যদি (!S_ISDIR(dirattrib->perm)) {
		error("\"%s\" is not a directory", src);
		ফেরত -1;
	}
	যদি (print_flag && print_flag != SFTP_PROGRESS_ONLY)
		mprintf("Retrieving %s\n", src);

	যদি (dirattrib->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		mode = dirattrib->perm & 01777;
		tmpmode = mode | (S_IWUSR|S_IXUSR);
	} অন্যথা {
		debug("download remote \"%s\": server "
		    "did not send permissions", dst);
	}

	যদি (mkdir(dst, tmpmode) == -1 && errno != EEXIST) {
		error("mkdir %s: %s", dst, strerror(errno));
		ফেরত -1;
	}

	যদি (sftp_readdir(conn, src, &dir_entries) == -1) {
		error("remote readdir \"%s\" failed", src);
		ফেরত -1;
	}

	জন্য (i = 0; dir_entries[i] != ফাঁকা && !interrupted; i++) {
		মুক্ত(new_dst);
		মুক্ত(new_src);

		filename = dir_entries[i]->filename;
		new_dst = sftp_path_append(dst, filename);
		new_src = sftp_path_append(src, filename);

		a = &dir_entries[i]->a;
		যদি (S_ISLNK(a->perm)) {
			যদি (!follow_link_flag) {
				logit("download \"%s\": not a regular file",
				    new_src);
				চালু;
			}
			/* Replace the stat contents with the symlink target */
			যদি (sftp_stat(conn, new_src, 1, &lsym) != 0) {
				logit("remote stat \"%s\" failed", new_src);
				ret = -1;
				চালু;
			}
			a = &lsym;
		}

		যদি (S_ISDIR(a->perm)) {
			যদি (strcmp(filename, ".") == 0 ||
			    strcmp(filename, "..") == 0)
				চালু;
			যদি (download_dir_internal(conn, new_src, new_dst,
			    depth + 1, a, preserve_flag,
			    print_flag, resume_flag,
			    fsync_flag, follow_link_flag, inplace_flag) == -1)
				ret = -1;
		} অন্যথা যদি (S_ISREG(a->perm)) {
			যদি (sftp_download(conn, new_src, new_dst, a,
			    preserve_flag, resume_flag, fsync_flag,
			    inplace_flag) == -1) {
				error("Download of file %s to %s failed",
				    new_src, new_dst);
				ret = -1;
			}
		} অন্যথা
			logit("download \"%s\": not a regular file", new_src);

	}
	মুক্ত(new_dst);
	মুক্ত(new_src);

	যদি (preserve_flag) {
		যদি (dirattrib->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
			কাঠামো timeval tv[2];
			tv[0].tv_sec = dirattrib->atime;
			tv[1].tv_sec = dirattrib->mtime;
			tv[0].tv_usec = tv[1].tv_usec = 0;
			যদি (utimes(dst, tv) == -1)
				error("local set times on \"%s\": %s",
				    dst, strerror(errno));
		} অন্যথা
			debug("Server did not send times for directory "
			    "\"%s\"", dst);
	}

	যদি (mode != tmpmode && chmod(dst, mode) == -1)
		error("local chmod directory \"%s\": %s", dst,
		    strerror(errno));

	sftp_free_dirents(dir_entries);

	ফেরত ret;
}

পূর্ণসংখ্যা
sftp_download_dir(কাঠামো sftp_conn *conn, ধ্রুবক অক্ষর *src, ধ্রুবক অক্ষর *dst,
    Attrib *dirattrib, পূর্ণসংখ্যা preserve_flag, পূর্ণসংখ্যা print_flag, পূর্ণসংখ্যা resume_flag,
    পূর্ণসংখ্যা fsync_flag, পূর্ণসংখ্যা follow_link_flag, পূর্ণসংখ্যা inplace_flag)
{
	অক্ষর *src_canon;
	পূর্ণসংখ্যা ret;

	যদি ((src_canon = sftp_realpath(conn, src)) == ফাঁকা) {
		error("download \"%s\": path canonicalization failed", src);
		ফেরত -1;
	}

	ret = download_dir_internal(conn, src_canon, dst, 0,
	    dirattrib, preserve_flag, print_flag, resume_flag, fsync_flag,
	    follow_link_flag, inplace_flag);
	মুক্ত(src_canon);
	ফেরত ret;
}

পূর্ণসংখ্যা
sftp_upload(কাঠামো sftp_conn *conn, ধ্রুবক অক্ষর *local_path,
    ধ্রুবক অক্ষর *remote_path, পূর্ণসংখ্যা preserve_flag, পূর্ণসংখ্যা resume,
    পূর্ণসংখ্যা fsync_flag, পূর্ণসংখ্যা inplace_flag)
{
	পূর্ণসংখ্যা r, local_fd;
	u_int openmode, id, status = SSH2_FX_OK, status2, reordered = 0;
	off_t offset, progress_গণক;
	u_char type, *handle, *তথ্য;
	কাঠামো sshbuf *বার্তা;
	কাঠামো stat sb;
	Attrib a, t, c;
	uint32_t startid, ackid;
	uint64_t highwater = 0, maxack = 0;
	কাঠামো request *ack = ফাঁকা;
	কাঠামো requests acks;
	আকার_t handle_len;

	debug2_f("upload local \"%s\" to remote \"%s\"",
	    local_path, remote_path);

	TAILQ_INIT(&acks);

	যদি ((local_fd = open(local_path, O_RDONLY)) == -1) {
		error("open local \"%s\": %s", local_path, strerror(errno));
		ফেরত(-1);
	}
	যদি (fstat(local_fd, &sb) == -1) {
		error("fstat local \"%s\": %s", local_path, strerror(errno));
		close(local_fd);
		ফেরত(-1);
	}
	যদি (!S_ISREG(sb.st_mode)) {
		error("local \"%s\" is not a regular file", local_path);
		close(local_fd);
		ফেরত(-1);
	}
	stat_to_attrib(&sb, &a);

	a.flags &= ~SSH2_FILEXFER_ATTR_আকার;
	a.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a.perm &= 0777;
	যদি (!preserve_flag)
		a.flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;

	যদি (resume) {
		/* Get remote file size if it exists */
		যদি (sftp_stat(conn, remote_path, 0, &c) != 0) {
			close(local_fd);
			ফেরত -1;
		}

		যদি ((off_t)c.আকার_2 >= sb.st_size) {
			error("resume \"%s\": destination file "
			    "same size or larger", local_path);
			close(local_fd);
			ফেরত -1;
		}

		যদি (lseek(local_fd, (off_t)c.আকার_2, SEEK_SET) == -1) {
			close(local_fd);
			ফেরত -1;
		}
		highwater = c.আকার_2;
	}

	openmode = SSH2_FXF_WRITE|SSH2_FXF_CREAT;
	যদি (resume)
		openmode |= SSH2_FXF_APPEND;
	অন্যথা যদি (!inplace_flag)
		openmode |= SSH2_FXF_TRUNC;

	/* Send open request */
	যদি (send_open(conn, remote_path, "dest", openmode, &a,
	    &handle, &handle_len) != 0) {
		close(local_fd);
		ফেরত -1;
	}

	id = conn->বার্তা_id;
	startid = ackid = id + 1;
	তথ্য = xmalloc(conn->upload_buflen);

	/* Read from local and write to remote */
	offset = progress_গণক = (resume ? c.আকার_2 : 0);
	যদি (showprogress) {
		start_progress_meter(progress_meter_path(local_path),
		    sb.st_size, &progress_গণক);
	}

	যদি ((বার্তা = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");
	জন্য (;;) {
		পূর্ণসংখ্যা len;

		/*
		 * Can't use atomicio here because it returns 0 on EOF,
		 * thus losing the last block of the file.
		 * Simulate an EOF on interrupt, allowing ACKs from the
		 * server to drain.
		 */
		যদি (interrupted || status != SSH2_FX_OK)
			len = 0;
		অন্যথা করো
			len = পঠ(local_fd, তথ্য, conn->upload_buflen);
		যখন ((len == -1) &&
		    (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK));

		যদি (len == -1) {
			fatal("read local \"%s\": %s",
			    local_path, strerror(errno));
		} অন্যথা যদি (len != 0) {
			ack = request_enqueue(&acks, ++id, len, offset);
			sshbuf_reset(বার্তা);
			যদি ((r = sshbuf_put_u8(বার্তা, SSH2_FXP_WRITE)) != 0 ||
			    (r = sshbuf_put_u32(বার্তা, ack->id)) != 0 ||
			    (r = sshbuf_put_string(বার্তা, handle,
			    handle_len)) != 0 ||
			    (r = sshbuf_put_u64(বার্তা, offset)) != 0 ||
			    (r = sshbuf_put_string(বার্তা, তথ্য, len)) != 0)
				fatal_fr(r, "compose");
			send_বার্তা(conn, বার্তা);
			debug3("Sent message SSH2_FXP_WRITE I:%u O:%llu S:%u",
			    id, (unsigned long long)offset, len);
		} অন্যথা যদি (TAILQ_FIRST(&acks) == ফাঁকা)
			বিরতি;

		যদি (ack == ফাঁকা)
			fatal("Unexpected ACK %u", id);

		যদি (id == startid || len == 0 ||
		    id - ackid >= conn->অঙ্ক_requests) {
			u_int rid;

			sshbuf_reset(বার্তা);
			get_বার্তা(conn, বার্তা);
			যদি ((r = sshbuf_get_u8(বার্তা, &type)) != 0 ||
			    (r = sshbuf_get_u32(বার্তা, &rid)) != 0)
				fatal_fr(r, "parse");

			যদি (type != SSH2_FXP_STATUS)
				fatal("Expected SSH2_FXP_STATUS(%d) packet, "
				    "got %d", SSH2_FXP_STATUS, type);

			যদি ((r = sshbuf_get_u32(বার্তা, &status2)) != 0)
				fatal_fr(r, "parse status");
			debug3("SSH2_FXP_STATUS %u", status2);
			যদি (status2 != SSH2_FX_OK)
				status = status2; /* remember errors */

			/* Find the request in our queue */
			যদি ((ack = request_find(&acks, rid)) == ফাঁকা)
				fatal("Can't find request for ID %u", rid);
			TAILQ_REMOVE(&acks, ack, tq);
			debug3("In write loop, ack for %u %zu bytes at %lld",
			    ack->id, ack->len, (unsigned long long)ack->offset);
			++ackid;
			progress_গণক += ack->len;
			/*
			 * Track both the highest offset acknowledged and the
			 * highest *contiguous* offset acknowledged.
			 * We'll need the latter for ftruncate()ing
			 * interrupted transfers.
			 */
			যদি (maxack < ack->offset + ack->len)
				maxack = ack->offset + ack->len;
			যদি (!reordered && ack->offset <= highwater)
				highwater = maxack;
			অন্যথা যদি (!reordered && ack->offset > highwater) {
				debug3_f("server reordered ACKs");
				reordered = 1;
			}
			মুক্ত(ack);
		}
		offset += len;
		যদি (offset < 0)
			fatal_f("offset < 0");
	}
	sshbuf_free(বার্তা);

	যদি (showprogress)
		stop_progress_meter();
	মুক্ত(তথ্য);

	যদি (status == SSH2_FX_OK && !interrupted) {
		/* we got everything */
		highwater = maxack;
	}
	যদি (status != SSH2_FX_OK) {
		error("write remote \"%s\": %s", remote_path, fx2txt(status));
		status = SSH2_FX_FAILURE;
	}

	যদি (inplace_flag || (resume && (status != SSH2_FX_OK || interrupted))) {
		debug("truncating at %llu", (unsigned long long)highwater);
		attrib_clear(&t);
		t.flags = SSH2_FILEXFER_ATTR_আকার;
		t.আকার_2 = highwater;
		sftp_fsetstat(conn, handle, handle_len, &t);
	}

	যদি (close(local_fd) == -1) {
		error("close local \"%s\": %s", local_path, strerror(errno));
		status = SSH2_FX_FAILURE;
	}

	/* Override umask and utimes if asked */
	যদি (preserve_flag)
		sftp_fsetstat(conn, handle, handle_len, &a);

	যদি (fsync_flag)
		(শূন্য)sftp_fsync(conn, handle, handle_len);

	যদি (sftp_close(conn, handle, handle_len) != 0)
		status = SSH2_FX_FAILURE;

	মুক্ত(handle);

	ফেরত status == SSH2_FX_OK ? 0 : -1;
}

স্থির পূর্ণসংখ্যা
upload_dir_internal(কাঠামো sftp_conn *conn, ধ্রুবক অক্ষর *src, ধ্রুবক অক্ষর *dst,
    পূর্ণসংখ্যা depth, পূর্ণসংখ্যা preserve_flag, পূর্ণসংখ্যা print_flag, পূর্ণসংখ্যা resume, পূর্ণসংখ্যা fsync_flag,
    পূর্ণসংখ্যা follow_link_flag, পূর্ণসংখ্যা inplace_flag)
{
	পূর্ণসংখ্যা created = 0, ret = 0;
	DIR *dirp;
	কাঠামো dirent *dp;
	অক্ষর *filename, *new_src = ফাঁকা, *new_dst = ফাঁকা;
	কাঠামো stat sb;
	Attrib a, dirattrib;
	uint32_t saved_perm;

	debug2_f("upload local dir \"%s\" to remote \"%s\"", src, dst);

	যদি (depth >= MAX_DIR_DEPTH) {
		error("Maximum directory depth exceeded: %d levels", depth);
		ফেরত -1;
	}

	যদি (stat(src, &sb) == -1) {
		error("stat local \"%s\": %s", src, strerror(errno));
		ফেরত -1;
	}
	যদি (!S_ISDIR(sb.st_mode)) {
		error("\"%s\" is not a directory", src);
		ফেরত -1;
	}
	যদি (print_flag && print_flag != SFTP_PROGRESS_ONLY)
		mprintf("Entering %s\n", src);

	stat_to_attrib(&sb, &a);
	a.flags &= ~SSH2_FILEXFER_ATTR_আকার;
	a.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a.perm &= 01777;
	যদি (!preserve_flag)
		a.flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;

	/*
	 * sftp lacks a portable status value to match errno EEXIST,
	 * so if we get a failure back then we must check whether
	 * the path already existed and is a directory.  Ensure we can
	 * write to the directory we create for the duration of the transfer.
	 */
	saved_perm = a.perm;
	a.perm |= (S_IWUSR|S_IXUSR);
	যদি (sftp_mkdir(conn, dst, &a, 0) == 0)
		created = 1;
	অন্যথা {
		যদি (sftp_stat(conn, dst, 0, &dirattrib) != 0)
			ফেরত -1;
		যদি (!S_ISDIR(dirattrib.perm)) {
			error("\"%s\" exists but is not a directory", dst);
			ফেরত -1;
		}
	}
	a.perm = saved_perm;

	যদি ((dirp = opendir(src)) == ফাঁকা) {
		error("local opendir \"%s\": %s", src, strerror(errno));
		ফেরত -1;
	}

	যখন (((dp = readdir(dirp)) != ফাঁকা) && !interrupted) {
		যদি (dp->d_ino == 0)
			চালু;
		মুক্ত(new_dst);
		মুক্ত(new_src);
		filename = dp->d_name;
		new_dst = sftp_path_append(dst, filename);
		new_src = sftp_path_append(src, filename);

		যদি (strcmp(filename, ".") == 0 || strcmp(filename, "..") == 0)
			চালু;
		যদি (lstat(new_src, &sb) == -1) {
			logit("local lstat \"%s\": %s", filename,
			    strerror(errno));
			ret = -1;
			চালু;
		}
		যদি (S_ISLNK(sb.st_mode)) {
			যদি (!follow_link_flag) {
				logit("%s: not a regular file", filename);
				চালু;
			}
			/* Replace the stat contents with the symlink target */
			যদি (stat(new_src, &sb) == -1) {
				logit("local stat \"%s\": %s", filename,
				    strerror(errno));
				ret = -1;
				চালু;
			}
		}
		যদি (S_ISDIR(sb.st_mode)) {
			যদি (upload_dir_internal(conn, new_src, new_dst,
			    depth + 1, preserve_flag, print_flag, resume,
			    fsync_flag, follow_link_flag, inplace_flag) == -1)
				ret = -1;
		} অন্যথা যদি (S_ISREG(sb.st_mode)) {
			যদি (sftp_upload(conn, new_src, new_dst,
			    preserve_flag, resume, fsync_flag,
			    inplace_flag) == -1) {
				error("upload \"%s\" to \"%s\" failed",
				    new_src, new_dst);
				ret = -1;
			}
		} অন্যথা
			logit("%s: not a regular file", filename);
	}
	মুক্ত(new_dst);
	মুক্ত(new_src);

	যদি (created || preserve_flag)
		sftp_setstat(conn, dst, &a);

	(শূন্য) closedir(dirp);
	ফেরত ret;
}

পূর্ণসংখ্যা
sftp_upload_dir(কাঠামো sftp_conn *conn, ধ্রুবক অক্ষর *src, ধ্রুবক অক্ষর *dst,
    পূর্ণসংখ্যা preserve_flag, পূর্ণসংখ্যা print_flag, পূর্ণসংখ্যা resume, পূর্ণসংখ্যা fsync_flag,
    পূর্ণসংখ্যা follow_link_flag, পূর্ণসংখ্যা inplace_flag)
{
	অক্ষর *dst_canon;
	পূর্ণসংখ্যা ret;

	যদি ((dst_canon = sftp_realpath(conn, dst)) == ফাঁকা) {
		error("upload \"%s\": path canonicalization failed", dst);
		ফেরত -1;
	}

	ret = upload_dir_internal(conn, src, dst_canon, 0, preserve_flag,
	    print_flag, resume, fsync_flag, follow_link_flag, inplace_flag);

	মুক্ত(dst_canon);
	ফেরত ret;
}

স্থির শূন্য
handle_dest_replies(কাঠামো sftp_conn *to, ধ্রুবক অক্ষর *to_path, পূর্ণসংখ্যা synchronous,
    u_int *nreqsp, u_int *write_errorp)
{
	কাঠামো sshbuf *বার্তা;
	u_char type;
	u_int id, status;
	পূর্ণসংখ্যা r;
	কাঠামো pollfd pfd;

	যদি ((বার্তা = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");

	/* Try to eat replies from the upload side */
	যখন (*nreqsp > 0) {
		debug3_f("%u outstanding replies", *nreqsp);
		যদি (!synchronous) {
			/* Bail out if no data is ready to be read */
			pfd.fd = to->fd_in;
			pfd.events = POLLIN;
			যদি ((r = poll(&pfd, 1, 0)) == -1) {
				যদি (errno == EINTR)
					বিরতি;
				fatal_f("poll: %s", strerror(errno));
			} অন্যথা যদি (r == 0)
				বিরতি; /* fd not ready */
		}
		sshbuf_reset(বার্তা);
		get_বার্তা(to, বার্তা);

		যদি ((r = sshbuf_get_u8(বার্তা, &type)) != 0 ||
		    (r = sshbuf_get_u32(বার্তা, &id)) != 0)
			fatal_fr(r, "dest parse");
		debug3("Received dest reply T:%u I:%u R:%u", type, id, *nreqsp);
		যদি (type != SSH2_FXP_STATUS) {
			fatal_f("Expected SSH2_FXP_STATUS(%d) packet, got %d",
			    SSH2_FXP_STATUS, type);
		}
		যদি ((r = sshbuf_get_u32(বার্তা, &status)) != 0)
			fatal_fr(r, "parse dest status");
		debug3("dest SSH2_FXP_STATUS %u", status);
		যদি (status != SSH2_FX_OK) {
			/* record first error */
			যদি (*write_errorp == 0)
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
	sshbuf_free(বার্তা);
}

পূর্ণসংখ্যা
sftp_crossload(কাঠামো sftp_conn *from, কাঠামো sftp_conn *to,
    ধ্রুবক অক্ষর *from_path, ধ্রুবক অক্ষর *to_path,
    Attrib *a, পূর্ণসংখ্যা preserve_flag)
{
	কাঠামো sshbuf *বার্তা;
	পূর্ণসংখ্যা write_error, read_error, r, seen_zerolen = 0;
	uint64_t offset = 0, আকার_2;
	u_int id, buflen, অঙ্ক_req, max_req, status = SSH2_FX_OK;
	u_int অঙ্ক_upload_req;
	off_t progress_গণক;
	u_char *from_handle, *to_handle;
	আকার_t from_handle_len, to_handle_len;
	কাঠামো requests requests;
	কাঠামো request *req;
	u_char type;
	Attrib attr;

	debug2_f("crossload src \"%s\" to dst \"%s\"", from_path, to_path);

	TAILQ_INIT(&requests);

	যদি (a == ফাঁকা) {
		যদি (sftp_stat(from, from_path, 0, &attr) != 0)
			ফেরত -1;
		a = &attr;
	}

	যদি ((a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) &&
	    (!S_ISREG(a->perm))) {
		error("download \"%s\": not a regular file", from_path);
		ফেরত(-1);
	}
	যদি (a->flags & SSH2_FILEXFER_ATTR_আকার)
		আকার_2 = a->আকার_2;
	অন্যথা
		আকার_2 = 0;

	buflen = from->download_buflen;
	যদি (buflen > to->upload_buflen)
		buflen = to->upload_buflen;

	/* Send open request to read side */
	যদি (send_open(from, from_path, "origin", SSH2_FXF_READ, ফাঁকা,
	    &from_handle, &from_handle_len) != 0)
		ফেরত -1;

	/* Send open request to write side */
	a->flags &= ~SSH2_FILEXFER_ATTR_আকার;
	a->flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a->perm &= 0777;
	যদি (!preserve_flag)
		a->flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;
	যদি (send_open(to, to_path, "dest",
	    SSH2_FXF_WRITE|SSH2_FXF_CREAT|SSH2_FXF_TRUNC, a,
	    &to_handle, &to_handle_len) != 0) {
		sftp_close(from, from_handle, from_handle_len);
		ফেরত -1;
	}

	/* Read from remote "from" and write to remote "to" */
	offset = 0;
	write_error = read_error = অঙ্ক_req = অঙ্ক_upload_req = 0;
	max_req = 1;
	progress_গণক = 0;

	যদি (showprogress && আকার_2 != 0) {
		start_progress_meter(progress_meter_path(from_path),
		    আকার_2, &progress_গণক);
	}
	যদি ((বার্তা = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");
	যখন (অঙ্ক_req > 0 || max_req > 0) {
		u_char *তথ্য;
		আকার_t len;

		/*
		 * Simulate EOF on interrupt: stop sending new requests and
		 * allow outstanding requests to drain gracefully
		 */
		যদি (interrupted) {
			যদি (অঙ্ক_req == 0) /* If we haven't started yet... */
				বিরতি;
			max_req = 0;
		}

		/* Send some more requests */
		যখন (অঙ্ক_req < max_req) {
			debug3("Request range %llu -> %llu (%d/%d)",
			    (unsigned long long)offset,
			    (unsigned long long)offset + buflen - 1,
			    অঙ্ক_req, max_req);
			req = request_enqueue(&requests, from->বার্তা_id++,
			    buflen, offset);
			offset += buflen;
			অঙ্ক_req++;
			send_read_request(from, req->id, req->offset,
			    req->len, from_handle, from_handle_len);
		}

		/* Try to eat replies from the upload side (nonblocking) */
		handle_dest_replies(to, to_path, 0,
		    &অঙ্ক_upload_req, &write_error);

		sshbuf_reset(বার্তা);
		get_বার্তা(from, বার্তা);
		যদি ((r = sshbuf_get_u8(বার্তা, &type)) != 0 ||
		    (r = sshbuf_get_u32(বার্তা, &id)) != 0)
			fatal_fr(r, "parse");
		debug3("Received origin reply T:%u I:%u R:%d",
		    type, id, max_req);

		/* Find the request in our queue */
		যদি ((req = request_find(&requests, id)) == ফাঁকা)
			fatal("Unexpected reply %u", id);

		নির্বাচন (type) {
		ক্ষেত্র SSH2_FXP_STATUS:
			যদি ((r = sshbuf_get_u32(বার্তা, &status)) != 0)
				fatal_fr(r, "parse status");
			যদি (status != SSH2_FX_EOF)
				read_error = 1;
			max_req = 0;
			TAILQ_REMOVE(&requests, req, tq);
			মুক্ত(req);
			অঙ্ক_req--;
			বিরতি;
		ক্ষেত্র SSH2_FXP_তথ্য:
			যদি ((r = sshbuf_get_string(বার্তা, &তথ্য, &len)) != 0)
				fatal_fr(r, "parse data");
			debug3("Received data %llu -> %llu",
			    (unsigned long long)req->offset,
			    (unsigned long long)req->offset + len - 1);
			যদি (len > req->len)
				fatal("Received more data than asked for "
				    "%zu > %zu", len, req->len);
			যদি (len == 0) {
				যদি (seen_zerolen)
					fatal_f("server sent zero data length");
				seen_zerolen = 1;
			}

			/* Write this chunk out to the destination */
			sshbuf_reset(বার্তা);
			যদি ((r = sshbuf_put_u8(বার্তা, SSH2_FXP_WRITE)) != 0 ||
			    (r = sshbuf_put_u32(বার্তা, to->বার্তা_id++)) != 0 ||
			    (r = sshbuf_put_string(বার্তা, to_handle,
			    to_handle_len)) != 0 ||
			    (r = sshbuf_put_u64(বার্তা, req->offset)) != 0 ||
			    (r = sshbuf_put_string(বার্তা, তথ্য, len)) != 0)
				fatal_fr(r, "compose write");
			send_বার্তা(to, বার্তা);
			debug3("Sent message SSH2_FXP_WRITE I:%u O:%llu S:%zu",
			    id, (unsigned long long)offset, len);
			অঙ্ক_upload_req++;
			progress_গণক += len;
			মুক্ত(তথ্য);

			যদি (len == req->len) {
				TAILQ_REMOVE(&requests, req, tq);
				মুক্ত(req);
				অঙ্ক_req--;
			} অন্যথা {
				/* Resend the request for the missing data */
				debug3("Short data block, re-requesting "
				    "%llu -> %llu (%2d)",
				    (unsigned long long)req->offset + len,
				    (unsigned long long)req->offset +
				    req->len - 1, অঙ্ক_req);
				req->id = from->বার্তা_id++;
				req->len -= len;
				req->offset += len;
				send_read_request(from, req->id,
				    req->offset, req->len,
				    from_handle, from_handle_len);
				/* Reduce the request size */
				যদি (len < buflen)
					buflen = MAXIMUM(MIN_READ_আকার, len);
			}
			যদি (max_req > 0) { /* max_req = 0 iff EOF received */
				যদি (আকার_2 > 0 && offset > আকার_2) {
					/* Only one request at a time
					 * after the expected EOF */
					debug3("Finish at %llu (%2d)",
					    (unsigned long long)offset,
					    অঙ্ক_req);
					max_req = 1;
				} অন্যথা যদি (max_req < from->অঙ্ক_requests) {
					++max_req;
				}
			}
			বিরতি;
		পূর্বনির্ধারিত:
			fatal("Expected SSH2_FXP_DATA(%u) packet, got %u",
			    SSH2_FXP_তথ্য, type);
		}
	}

	যদি (showprogress && আকার_2)
		stop_progress_meter();

	/* Drain replies from the server (blocking) */
	debug3_f("waiting for %u replies from destination", অঙ্ক_upload_req);
	handle_dest_replies(to, to_path, 1, &অঙ্ক_upload_req, &write_error);

	/* Sanity check */
	যদি (TAILQ_FIRST(&requests) != ফাঁকা)
		fatal("Transfer complete, but requests still in queue");
	/* Truncate at 0 length on interrupt or error to avoid holes at dest */
	যদি (read_error || write_error || interrupted) {
		debug("truncating \"%s\" at 0", to_path);
		sftp_close(to, to_handle, to_handle_len);
		মুক্ত(to_handle);
		যদি (send_open(to, to_path, "dest",
		    SSH2_FXF_WRITE|SSH2_FXF_CREAT|SSH2_FXF_TRUNC, a,
		    &to_handle, &to_handle_len) != 0) {
			error("dest truncate \"%s\" failed", to_path);
			to_handle = ফাঁকা;
		}
	}
	যদি (read_error) {
		error("read origin \"%s\": %s", from_path, fx2txt(status));
		status = -1;
		sftp_close(from, from_handle, from_handle_len);
		যদি (to_handle != ফাঁকা)
			sftp_close(to, to_handle, to_handle_len);
	} অন্যথা যদি (write_error) {
		error("write dest \"%s\": %s", to_path, fx2txt(write_error));
		status = SSH2_FX_FAILURE;
		sftp_close(from, from_handle, from_handle_len);
		যদি (to_handle != ফাঁকা)
			sftp_close(to, to_handle, to_handle_len);
	} অন্যথা {
		যদি (sftp_close(from, from_handle, from_handle_len) != 0 ||
		    interrupted)
			status = -1;
		অন্যথা
			status = SSH2_FX_OK;
		যদি (to_handle != ফাঁকা) {
			/* Need to resend utimes after write */
			যদি (preserve_flag)
				sftp_fsetstat(to, to_handle, to_handle_len, a);
			sftp_close(to, to_handle, to_handle_len);
		}
	}
	sshbuf_free(বার্তা);
	মুক্ত(from_handle);
	মুক্ত(to_handle);

	ফেরত status == SSH2_FX_OK ? 0 : -1;
}

স্থির পূর্ণসংখ্যা
crossload_dir_internal(কাঠামো sftp_conn *from, কাঠামো sftp_conn *to,
    ধ্রুবক অক্ষর *from_path, ধ্রুবক অক্ষর *to_path,
    পূর্ণসংখ্যা depth, Attrib *dirattrib, পূর্ণসংখ্যা preserve_flag, পূর্ণসংখ্যা print_flag,
    পূর্ণসংখ্যা follow_link_flag)
{
	পূর্ণসংখ্যা i, ret = 0, created = 0;
	SFTP_DIRENT **dir_entries;
	অক্ষর *filename, *new_from_path = ফাঁকা, *new_to_path = ফাঁকা;
	mode_t mode = 0777;
	Attrib *a, curdir, ldirattrib, newdir, lsym;

	debug2_f("crossload dir src \"%s\" to dst \"%s\"", from_path, to_path);

	যদি (depth >= MAX_DIR_DEPTH) {
		error("Maximum directory depth exceeded: %d levels", depth);
		ফেরত -1;
	}

	যদি (dirattrib == ফাঁকা) {
		যদি (sftp_stat(from, from_path, 1, &ldirattrib) != 0) {
			error("stat remote \"%s\" failed", from_path);
			ফেরত -1;
		}
		dirattrib = &ldirattrib;
	}
	যদি (!S_ISDIR(dirattrib->perm)) {
		error("\"%s\" is not a directory", from_path);
		ফেরত -1;
	}
	যদি (print_flag && print_flag != SFTP_PROGRESS_ONLY)
		mprintf("Retrieving %s\n", from_path);

	curdir = *dirattrib; /* dirattrib will be clobbered */
	curdir.flags &= ~SSH2_FILEXFER_ATTR_আকার;
	curdir.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	যদি ((curdir.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) == 0) {
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
	যদি (sftp_mkdir(to, to_path, &curdir, 0) == 0)
		created = 1;
	অন্যথা {
		যদি (sftp_stat(to, to_path, 0, &newdir) != 0)
			ফেরত -1;
		যদি (!S_ISDIR(newdir.perm)) {
			error("\"%s\" exists but is not a directory", to_path);
			ফেরত -1;
		}
	}
	curdir.perm = mode;

	যদি (sftp_readdir(from, from_path, &dir_entries) == -1) {
		error("origin readdir \"%s\" failed", from_path);
		ফেরত -1;
	}

	জন্য (i = 0; dir_entries[i] != ফাঁকা && !interrupted; i++) {
		মুক্ত(new_from_path);
		মুক্ত(new_to_path);

		filename = dir_entries[i]->filename;
		new_from_path = sftp_path_append(from_path, filename);
		new_to_path = sftp_path_append(to_path, filename);

		a = &dir_entries[i]->a;
		যদি (S_ISLNK(a->perm)) {
			যদি (!follow_link_flag) {
				logit("%s: not a regular file", filename);
				চালু;
			}
			/* Replace the stat contents with the symlink target */
			যদি (sftp_stat(from, new_from_path, 1, &lsym) != 0) {
				logit("remote stat \"%s\" failed",
				    new_from_path);
				ret = -1;
				চালু;
			}
			a = &lsym;
		}
		যদি (S_ISDIR(a->perm)) {
			যদি (strcmp(filename, ".") == 0 ||
			    strcmp(filename, "..") == 0)
				চালু;
			যদি (crossload_dir_internal(from, to,
			    new_from_path, new_to_path,
			    depth + 1, a, preserve_flag,
			    print_flag, follow_link_flag) == -1)
				ret = -1;
		} অন্যথা যদি (S_ISREG(a->perm)) {
			যদি (sftp_crossload(from, to, new_from_path,
			    new_to_path, a, preserve_flag) == -1) {
				error("crossload \"%s\" to \"%s\" failed",
				    new_from_path, new_to_path);
				ret = -1;
			}
		} অন্যথা {
			logit("origin \"%s\": not a regular file",
			    new_from_path);
		}
	}
	মুক্ত(new_to_path);
	মুক্ত(new_from_path);

	যদি (created || preserve_flag)
		sftp_setstat(to, to_path, &curdir);

	sftp_free_dirents(dir_entries);

	ফেরত ret;
}

পূর্ণসংখ্যা
sftp_crossload_dir(কাঠামো sftp_conn *from, কাঠামো sftp_conn *to,
    ধ্রুবক অক্ষর *from_path, ধ্রুবক অক্ষর *to_path,
    Attrib *dirattrib, পূর্ণসংখ্যা preserve_flag, পূর্ণসংখ্যা print_flag, পূর্ণসংখ্যা follow_link_flag)
{
	অক্ষর *from_path_canon;
	পূর্ণসংখ্যা ret;

	যদি ((from_path_canon = sftp_realpath(from, from_path)) == ফাঁকা) {
		error("crossload \"%s\": path canonicalization failed",
		    from_path);
		ফেরত -1;
	}

	ret = crossload_dir_internal(from, to, from_path_canon, to_path, 0,
	    dirattrib, preserve_flag, print_flag, follow_link_flag);
	মুক্ত(from_path_canon);
	ফেরত ret;
}

পূর্ণসংখ্যা
sftp_can_get_users_groups_by_id(কাঠামো sftp_conn *conn)
{
	ফেরত (conn->exts & SFTP_EXT_GETUSERSGROUPS_BY_ID) != 0;
}

পূর্ণসংখ্যা
sftp_get_users_groups_by_id(কাঠামো sftp_conn *conn,
    ধ্রুবক u_int *uids, u_int nuids,
    ধ্রুবক u_int *gids, u_int ngids,
    অক্ষর ***usernamesp, অক্ষর ***groupnamesp)
{
	কাঠামো sshbuf *বার্তা, *uidbuf, *gidbuf;
	u_int i, expected_id, id;
	অক্ষর *name, **usernames = ফাঁকা, **groupnames = ফাঁকা;
	u_char type;
	পূর্ণসংখ্যা r;

	*usernamesp = *groupnamesp = ফাঁকা;
	যদি (!sftp_can_get_users_groups_by_id(conn))
		ফেরত SSH_ERR_FEATURE_UNSUPPORTED;

	যদি ((বার্তা = sshbuf_new()) == ফাঁকা ||
	    (uidbuf = sshbuf_new()) == ফাঁকা ||
	    (gidbuf = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");
	expected_id = id = conn->বার্তা_id++;
	debug2("Sending SSH2_FXP_EXTENDED(users-groups-by-id@openssh.com)");
	জন্য (i = 0; i < nuids; i++) {
		যদি ((r = sshbuf_put_u32(uidbuf, uids[i])) != 0)
			fatal_fr(r, "compose uids");
	}
	জন্য (i = 0; i < ngids; i++) {
		যদি ((r = sshbuf_put_u32(gidbuf, gids[i])) != 0)
			fatal_fr(r, "compose gids");
	}
	যদি ((r = sshbuf_put_u8(বার্তা, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(বার্তা, id)) != 0 ||
	    (r = sshbuf_put_cstring(বার্তা,
	    "users-groups-by-id@openssh.com")) != 0 ||
	    (r = sshbuf_put_stringb(বার্তা, uidbuf)) != 0 ||
	    (r = sshbuf_put_stringb(বার্তা, gidbuf)) != 0)
		fatal_fr(r, "compose");
	send_বার্তা(conn, বার্তা);
	get_বার্তা(conn, বার্তা);
	যদি ((r = sshbuf_get_u8(বার্তা, &type)) != 0 ||
	    (r = sshbuf_get_u32(বার্তা, &id)) != 0)
		fatal_fr(r, "parse");
	যদি (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	যদি (type == SSH2_FXP_STATUS) {
		u_int status;
		অক্ষর *errmsg;

		যদি ((r = sshbuf_get_u32(বার্তা, &status)) != 0 ||
		    (r = sshbuf_get_cstring(বার্তা, &errmsg, ফাঁকা)) != 0)
			fatal_fr(r, "parse status");
		error("users-groups-by-id %s",
		    *errmsg == '\0' ? fx2txt(status) : errmsg);
		মুক্ত(errmsg);
		sshbuf_free(বার্তা);
		sshbuf_free(uidbuf);
		sshbuf_free(gidbuf);
		ফেরত -1;
	} অন্যথা যদি (type != SSH2_FXP_EXTENDED_REPLY)
		fatal("Expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_REPLY, type);

	/* reuse */
	sshbuf_free(uidbuf);
	sshbuf_free(gidbuf);
	uidbuf = gidbuf = ফাঁকা;
	যদি ((r = sshbuf_froms(বার্তা, &uidbuf)) != 0 ||
	    (r = sshbuf_froms(বার্তা, &gidbuf)) != 0)
		fatal_fr(r, "parse response");
	যদি (nuids > 0) {
		usernames = xcalloc(nuids, আকার(*usernames));
		জন্য (i = 0; i < nuids; i++) {
			যদি ((r = sshbuf_get_cstring(uidbuf, &name, ফাঁকা)) != 0)
				fatal_fr(r, "parse user name");
			/* Handle unresolved names */
			যদি (*name == '\0') {
				মুক্ত(name);
				name = ফাঁকা;
			}
			usernames[i] = name;
		}
	}
	যদি (ngids > 0) {
		groupnames = xcalloc(ngids, আকার(*groupnames));
		জন্য (i = 0; i < ngids; i++) {
			যদি ((r = sshbuf_get_cstring(gidbuf, &name, ফাঁকা)) != 0)
				fatal_fr(r, "parse user name");
			/* Handle unresolved names */
			যদি (*name == '\0') {
				মুক্ত(name);
				name = ফাঁকা;
			}
			groupnames[i] = name;
		}
	}
	যদি (sshbuf_len(uidbuf) != 0)
		fatal_f("unexpected extra username data");
	যদি (sshbuf_len(gidbuf) != 0)
		fatal_f("unexpected extra groupname data");
	sshbuf_free(uidbuf);
	sshbuf_free(gidbuf);
	sshbuf_free(বার্তা);
	/* success */
	*usernamesp = usernames;
	*groupnamesp = groupnames;
	ফেরত 0;
}

অক্ষর *
sftp_path_append(ধ্রুবক অক্ষর *p1, ধ্রুবক অক্ষর *p2)
{
	অক্ষর *ret;
	আকার_t len = strlen(p1) + strlen(p2) + 2;

	ret = xmalloc(len);
	strlcpy(ret, p1, len);
	যদি (p1[0] != '\0' && p1[strlen(p1) - 1] != '/')
		strlcat(ret, "/", len);
	strlcat(ret, p2, len);

	ফেরত(ret);
}

/*
 * Arg p must be dynamically allocated.  It will either be returned or
 * freed and a replacement allocated.  Caller must free returned string.
 */
অক্ষর *
sftp_make_absolute(অক্ষর *p, ধ্রুবক অক্ষর *pwd)
{
	অক্ষর *abs_str;

	/* Derelativise */
	যদি (p && !path_absolute(p)) {
		abs_str = sftp_path_append(pwd, p);
		মুক্ত(p);
		ফেরত(abs_str);
	} অন্যথা
		ফেরত(p);
}

পূর্ণসংখ্যা
sftp_remote_is_dir(কাঠামো sftp_conn *conn, ধ্রুবক অক্ষর *path)
{
	Attrib a;

	/* XXX: report errors? */
	যদি (sftp_stat(conn, path, 1, &a) != 0)
		ফেরত(0);
	যদি (!(a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS))
		ফেরত(0);
	ফেরত S_ISDIR(a.perm);
}


/* Check whether path returned from glob(..., GLOB_MARK, ...) is a directory */
পূর্ণসংখ্যা
sftp_globpath_is_dir(ধ্রুবক অক্ষর *pathname)
{
	আকার_t l = strlen(pathname);

	ফেরত l > 0 && pathname[l - 1] == '/';
}

