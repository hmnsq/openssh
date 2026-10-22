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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/queue.h>
#ضمن <sys/stat.h>
#ضمن <sys/time.h>
#ضمن <sys/statvfs.h>
#ضمن <sys/uio.h>

#ضمن <dirent.h>
#ضمن <errno.h>
#ضمن <fcntl.h>
#ضمن <poll.h>
#ضمن <signal.h>
#ضمن <stdarg.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <unistd.h>

#ضمن "xmalloc.h"
#ضمن "ssherr.h"
#ضمن "sshbuf.h"
#ضمن "log.h"
#ضمن "atomicio.h"
#ضمن "progressmeter.h"
#ضمن "misc.h"
#ضمن "utf8.h"

#ضمن "sftp.h"
#ضمن "sftp-common.h"
#ضمن "sftp-client.h"

خارجي متطاير sig_atomic_t interrupted;
خارجي صحيح showprogress;

/* Default size of buffer for up/download (fix sftp.1 scp.1 if changed) */
#define DEFAULT_COPY_BUFLEN	32768

/* Default number of concurrent xfer requests (fix sftp.1 scp.1 if changed) */
#define DEFAULT_رقم_REQUESTS	64

/* Minimum amount of data to read at a time */
#define MIN_READ_SIZE	512

/* Maximum depth to descend in directory trees */
#define MAX_DIR_DEPTH 64

/* Directory separator characters */
#ifdef HAVE_CYGWIN
# define SFTP_DIRECTORY_CHARS      "/\\"
#وإلا /* HAVE_CYGWIN */
# define SFTP_DIRECTORY_CHARS      "/"
#endif /* HAVE_CYGWIN */

بنية sftp_conn {
	صحيح fd_in;
	صحيح fd_out;
	u_int download_buflen;
	u_int upload_buflen;
	u_int رقم_requests;
	u_int version;
	u_int رسالة_id;
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
	بنية bwlimit bwlimit_in, bwlimit_out;
};

/* Tracks in-progress requests during file transfers */
بنية request {
	u_int id;
	size_t len;
	uint64_t offset;
	TAILQ_ENTRY(request) tq;
};
TAILQ_HEAD(requests, request);

ساكن u_char *
get_handle(بنية sftp_conn *conn, u_int expected_id, size_t *len,
    ثابت حرف *errfmt, ...) __attribute__((format(printf, 4, 5)));

ساكن بنية request *
request_enqueue(بنية requests *requests, u_int id, size_t len,
    uint64_t offset)
{
	بنية request *req;

	req = xcalloc(1, حجم(*req));
	req->id = id;
	req->len = len;
	req->offset = offset;
	TAILQ_INSERT_TAIL(requests, req, tq);
	إرجاع req;
}

ساكن بنية request *
request_find(بنية requests *requests, u_int id)
{
	بنية request *req;

	لكل (req = TAILQ_FIRST(requests);
	    req != عدم && req->id != id;
	    req = TAILQ_NEXT(req, tq))
		;
	إرجاع req;
}

ساكن صحيح
sftpio(فراغ *_bwlimit, size_t amount)
{
	بنية bwlimit *bwlimit = (بنية bwlimit *)_bwlimit;

	refresh_progress_meter(0);
	إذا (bwlimit != عدم)
		bandwidth_limit(bwlimit, amount);
	إرجاع 0;
}

ساكن فراغ
send_رسالة(بنية sftp_conn *conn, بنية sshbuf *m)
{
	u_char mlen[4];
	بنية iovec iov[2];

	إذا (sshbuf_len(m) > SFTP_MAX_رسالة_LENGTH)
		fatal("Outbound message too long %zu", sshbuf_len(m));

	/* Send length first */
	put_u32(mlen, sshbuf_len(m));
	iov[0].iov_base = mlen;
	iov[0].iov_len = حجم(mlen);
	iov[1].iov_base = (u_char *)sshbuf_ptr(m);
	iov[1].iov_len = sshbuf_len(m);

	إذا (atomiciov6(writev, conn->fd_out, iov, 2, sftpio,
	    conn->limit_kbps > 0 ? &conn->bwlimit_out : عدم) !=
	    sshbuf_len(m) + حجم(mlen))
		fatal("Couldn't send packet: %s", strerror(errno));

	sshbuf_reset(m);
}

ساكن فراغ
get_رسالة_extended(بنية sftp_conn *conn, بنية sshbuf *m, صحيح initial)
{
	u_int رسالة_len;
	u_char *p;
	صحيح r;

	sshbuf_reset(m);
	إذا ((r = sshbuf_reserve(m, 4, &p)) != 0)
		fatal_fr(r, "reserve");
	إذا (atomicio6(اقرأ, conn->fd_in, p, 4, sftpio,
	    conn->limit_kbps > 0 ? &conn->bwlimit_in : عدم) != 4) {
		إذا (errno == EPIPE || errno == ECONNRESET)
			fatal("Connection closed");
		وإلا
			fatal("Couldn't read packet: %s", strerror(errno));
	}

	إذا ((r = sshbuf_get_u32(m, &رسالة_len)) != 0)
		fatal_fr(r, "sshbuf_get_u32");
	إذا (رسالة_len > SFTP_MAX_رسالة_LENGTH) {
		do_log2(initial ? SYSLOG_LEVEL_ERROR : SYSLOG_LEVEL_FATAL,
		    "Received message too long %u", رسالة_len);
		fatal("Ensure the remote shell produces no output "
		    "for non-interactive sessions.");
	}

	إذا ((r = sshbuf_reserve(m, رسالة_len, &p)) != 0)
		fatal_fr(r, "reserve");
	إذا (atomicio6(اقرأ, conn->fd_in, p, رسالة_len, sftpio,
	    conn->limit_kbps > 0 ? &conn->bwlimit_in : عدم)
	    != رسالة_len) {
		إذا (errno == EPIPE)
			fatal("Connection closed");
		وإلا
			fatal("Read packet: %s", strerror(errno));
	}
}

ساكن فراغ
get_رسالة(بنية sftp_conn *conn, بنية sshbuf *m)
{
	get_رسالة_extended(conn, m, 0);
}

ساكن فراغ
send_string_request(بنية sftp_conn *conn, u_int id, u_int code, ثابت حرف *s,
    u_int len)
{
	بنية sshbuf *رسالة;
	صحيح r;

	إذا ((رسالة = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshbuf_put_u8(رسالة, code)) != 0 ||
	    (r = sshbuf_put_u32(رسالة, id)) != 0 ||
	    (r = sshbuf_put_string(رسالة, s, len)) != 0)
		fatal_fr(r, "compose");
	send_رسالة(conn, رسالة);
	debug3("Sent message fd %d T:%u I:%u", conn->fd_out, code, id);
	sshbuf_free(رسالة);
}

ساكن فراغ
send_string_attrs_request(بنية sftp_conn *conn, u_int id, u_int code,
    ثابت فراغ *s, u_int len, Attrib *a)
{
	بنية sshbuf *رسالة;
	صحيح r;

	إذا ((رسالة = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshbuf_put_u8(رسالة, code)) != 0 ||
	    (r = sshbuf_put_u32(رسالة, id)) != 0 ||
	    (r = sshbuf_put_string(رسالة, s, len)) != 0 ||
	    (r = encode_attrib(رسالة, a)) != 0)
		fatal_fr(r, "compose");
	send_رسالة(conn, رسالة);
	debug3("Sent message fd %d T:%u I:%u F:0x%04x M:%05o",
	    conn->fd_out, code, id, a->flags, a->perm);
	sshbuf_free(رسالة);
}

ساكن u_int
get_status(بنية sftp_conn *conn, u_int expected_id)
{
	بنية sshbuf *رسالة;
	u_char type;
	u_int id, status;
	صحيح r;

	إذا ((رسالة = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	get_رسالة(conn, رسالة);
	إذا ((r = sshbuf_get_u8(رسالة, &type)) != 0 ||
	    (r = sshbuf_get_u32(رسالة, &id)) != 0)
		fatal_fr(r, "compose");

	إذا (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	إذا (type != SSH2_FXP_STATUS)
		fatal("Expected SSH2_FXP_STATUS(%u) packet, got %u",
		    SSH2_FXP_STATUS, type);

	إذا ((r = sshbuf_get_u32(رسالة, &status)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(رسالة);

	debug3("SSH2_FXP_STATUS %u", status);

	إرجاع status;
}

ساكن u_char *
get_handle(بنية sftp_conn *conn, u_int expected_id, size_t *len,
    ثابت حرف *errfmt, ...)
{
	بنية sshbuf *رسالة;
	u_int id, status;
	u_char type;
	u_char *handle;
	حرف errmsg[256];
	va_list args;
	صحيح r;

	va_start(args, errfmt);
	إذا (errfmt != عدم)
		vsnprintf(errmsg, حجم(errmsg), errfmt, args);
	va_end(args);

	إذا ((رسالة = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	get_رسالة(conn, رسالة);
	إذا ((r = sshbuf_get_u8(رسالة, &type)) != 0 ||
	    (r = sshbuf_get_u32(رسالة, &id)) != 0)
		fatal_fr(r, "parse");

	إذا (id != expected_id)
		fatal("%s: ID mismatch (%u != %u)",
		    errfmt == عدم ? __func__ : errmsg, id, expected_id);
	إذا (type == SSH2_FXP_STATUS) {
		إذا ((r = sshbuf_get_u32(رسالة, &status)) != 0)
			fatal_fr(r, "parse status");
		إذا (errfmt != عدم)
			error("%s: %s", errmsg, fx2txt(status));
		sshbuf_free(رسالة);
		إرجاع(عدم);
	} وإلا إذا (type != SSH2_FXP_HANDLE)
		fatal("%s: Expected SSH2_FXP_HANDLE(%u) packet, got %u",
		    errfmt == عدم ? __func__ : errmsg, SSH2_FXP_HANDLE, type);

	إذا ((r = sshbuf_get_string(رسالة, &handle, len)) != 0)
		fatal_fr(r, "parse handle");
	sshbuf_free(رسالة);

	إرجاع handle;
}

ساكن صحيح
get_decode_stat(بنية sftp_conn *conn, u_int expected_id, صحيح quiet, Attrib *a)
{
	بنية sshbuf *رسالة;
	u_int id;
	u_char type;
	صحيح r;
	Attrib attr;

	إذا (a != عدم)
		memset(a, '\0', حجم(*a));
	إذا ((رسالة = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	get_رسالة(conn, رسالة);

	إذا ((r = sshbuf_get_u8(رسالة, &type)) != 0 ||
	    (r = sshbuf_get_u32(رسالة, &id)) != 0)
		fatal_fr(r, "parse");

	إذا (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	إذا (type == SSH2_FXP_STATUS) {
		u_int status;

		إذا ((r = sshbuf_get_u32(رسالة, &status)) != 0)
			fatal_fr(r, "parse status");
		إذا (quiet)
			debug("stat remote: %s", fx2txt(status));
		وإلا
			error("stat remote: %s", fx2txt(status));
		sshbuf_free(رسالة);
		إرجاع -1;
	} وإلا إذا (type != SSH2_FXP_ATTRS) {
		fatal("Expected SSH2_FXP_ATTRS(%u) packet, got %u",
		    SSH2_FXP_ATTRS, type);
	}
	إذا ((r = decode_attrib(رسالة, &attr)) != 0) {
		error_fr(r, "decode_attrib");
		sshbuf_free(رسالة);
		إرجاع -1;
	}
	/* success */
	إذا (a != عدم)
		*a = attr;
	debug3("Received stat reply T:%u I:%u F:0x%04x M:%05o",
	    type, id, attr.flags, attr.perm);
	sshbuf_free(رسالة);

	إرجاع 0;
}

ساكن صحيح
get_decode_statvfs(بنية sftp_conn *conn, بنية sftp_statvfs *st,
    u_int expected_id, صحيح quiet)
{
	بنية sshbuf *رسالة;
	u_char type;
	u_int id;
	uint64_t flag;
	صحيح r;

	إذا ((رسالة = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	get_رسالة(conn, رسالة);

	إذا ((r = sshbuf_get_u8(رسالة, &type)) != 0 ||
	    (r = sshbuf_get_u32(رسالة, &id)) != 0)
		fatal_fr(r, "parse");

	debug3("Received statvfs reply T:%u I:%u", type, id);
	إذا (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	إذا (type == SSH2_FXP_STATUS) {
		u_int status;

		إذا ((r = sshbuf_get_u32(رسالة, &status)) != 0)
			fatal_fr(r, "parse status");
		إذا (quiet)
			debug("remote statvfs: %s", fx2txt(status));
		وإلا
			error("remote statvfs: %s", fx2txt(status));
		sshbuf_free(رسالة);
		إرجاع -1;
	} وإلا إذا (type != SSH2_FXP_EXTENDED_REPLY) {
		fatal("Expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_REPLY, type);
	}

	memset(st, 0, حجم(*st));
	إذا ((r = sshbuf_get_u64(رسالة, &st->f_bsize)) != 0 ||
	    (r = sshbuf_get_u64(رسالة, &st->f_frsize)) != 0 ||
	    (r = sshbuf_get_u64(رسالة, &st->f_blocks)) != 0 ||
	    (r = sshbuf_get_u64(رسالة, &st->f_bfree)) != 0 ||
	    (r = sshbuf_get_u64(رسالة, &st->f_bavail)) != 0 ||
	    (r = sshbuf_get_u64(رسالة, &st->f_files)) != 0 ||
	    (r = sshbuf_get_u64(رسالة, &st->f_ffree)) != 0 ||
	    (r = sshbuf_get_u64(رسالة, &st->f_favail)) != 0 ||
	    (r = sshbuf_get_u64(رسالة, &st->f_fsid)) != 0 ||
	    (r = sshbuf_get_u64(رسالة, &flag)) != 0 ||
	    (r = sshbuf_get_u64(رسالة, &st->f_namemax)) != 0)
		fatal_fr(r, "parse statvfs");

	st->f_flag = (flag & SSH2_FXE_STATVFS_ST_RDONLY) ? ST_RDONLY : 0;
	st->f_flag |= (flag & SSH2_FXE_STATVFS_ST_NOSUID) ? ST_NOSUID : 0;

	sshbuf_free(رسالة);

	إرجاع 0;
}

بنية sftp_conn *
sftp_init(صحيح fd_in, صحيح fd_out, u_int transfer_buflen, u_int رقم_requests,
    uint64_t limit_kbps)
{
	u_char type;
	بنية sshbuf *رسالة;
	بنية sftp_conn *ret;
	صحيح r;

	ret = xcalloc(1, حجم(*ret));
	ret->رسالة_id = 1;
	ret->fd_in = fd_in;
	ret->fd_out = fd_out;
	ret->download_buflen = ret->upload_buflen =
	    transfer_buflen ? transfer_buflen : DEFAULT_COPY_BUFLEN;
	ret->رقم_requests =
	    رقم_requests ? رقم_requests : DEFAULT_رقم_REQUESTS;
	ret->exts = 0;
	ret->limit_kbps = 0;

	إذا ((رسالة = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshbuf_put_u8(رسالة, SSH2_FXP_INIT)) != 0 ||
	    (r = sshbuf_put_u32(رسالة, SSH2_FILEXFER_VERSION)) != 0)
		fatal_fr(r, "parse");

	send_رسالة(ret, رسالة);

	get_رسالة_extended(ret, رسالة, 1);

	/* Expecting a VERSION reply */
	إذا ((r = sshbuf_get_u8(رسالة, &type)) != 0)
		fatal_fr(r, "parse type");
	إذا (type != SSH2_FXP_VERSION) {
		error("Invalid packet back from SSH2_FXP_INIT (type %u)",
		    type);
		sshbuf_free(رسالة);
		حرر(ret);
		إرجاع(عدم);
	}
	إذا ((r = sshbuf_get_u32(رسالة, &ret->version)) != 0)
		fatal_fr(r, "parse version");

	debug2("Remote version: %u", ret->version);

	/* Check for extensions */
	بينما (sshbuf_len(رسالة) > 0) {
		حرف *name;
		u_char *قيمة;
		size_t vlen;
		صحيح known = 0;

		إذا ((r = sshbuf_get_cstring(رسالة, &name, عدم)) != 0 ||
		    (r = sshbuf_get_string(رسالة, &قيمة, &vlen)) != 0)
			fatal_fr(r, "parse extension");
		إذا (strcmp(name, "posix-rename@openssh.com") == 0 &&
		    strcmp((حرف *)قيمة, "1") == 0) {
			ret->exts |= SFTP_EXT_POSIX_RENAME;
			known = 1;
		} وإلا إذا (strcmp(name, "statvfs@openssh.com") == 0 &&
		    strcmp((حرف *)قيمة, "2") == 0) {
			ret->exts |= SFTP_EXT_STATVFS;
			known = 1;
		} وإلا إذا (strcmp(name, "fstatvfs@openssh.com") == 0 &&
		    strcmp((حرف *)قيمة, "2") == 0) {
			ret->exts |= SFTP_EXT_FSTATVFS;
			known = 1;
		} وإلا إذا (strcmp(name, "hardlink@openssh.com") == 0 &&
		    strcmp((حرف *)قيمة, "1") == 0) {
			ret->exts |= SFTP_EXT_HARDLINK;
			known = 1;
		} وإلا إذا (strcmp(name, "fsync@openssh.com") == 0 &&
		    strcmp((حرف *)قيمة, "1") == 0) {
			ret->exts |= SFTP_EXT_FSYNC;
			known = 1;
		} وإلا إذا (strcmp(name, "lsetstat@openssh.com") == 0 &&
		    strcmp((حرف *)قيمة, "1") == 0) {
			ret->exts |= SFTP_EXT_LSETSTAT;
			known = 1;
		} وإلا إذا (strcmp(name, "limits@openssh.com") == 0 &&
		    strcmp((حرف *)قيمة, "1") == 0) {
			ret->exts |= SFTP_EXT_LIMITS;
			known = 1;
		} وإلا إذا (strcmp(name, "expand-path@openssh.com") == 0 &&
		    strcmp((حرف *)قيمة, "1") == 0) {
			ret->exts |= SFTP_EXT_PATH_EXPAND;
			known = 1;
		} وإلا إذا (strcmp(name, "copy-data") == 0 &&
		    strcmp((حرف *)قيمة, "1") == 0) {
			ret->exts |= SFTP_EXT_COPY_DATA;
			known = 1;
		} وإلا إذا (strcmp(name,
		    "users-groups-by-id@openssh.com") == 0 &&
		    strcmp((حرف *)قيمة, "1") == 0) {
			ret->exts |= SFTP_EXT_GETUSERSGROUPS_BY_ID;
			known = 1;
		}
		إذا (known) {
			debug2("Server supports extension \"%s\" revision %s",
			    name, قيمة);
		} وإلا {
			debug2("Unrecognised server extension \"%s\"", name);
		}
		حرر(name);
		حرر(قيمة);
	}

	sshbuf_free(رسالة);

	/* Query the server for its limits */
	إذا (ret->exts & SFTP_EXT_LIMITS) {
		بنية sftp_limits limits;
		إذا (sftp_get_limits(ret, &limits) != 0)
			fatal_f("limits failed");

		/* If the caller did not specify, find a good value */
		إذا (transfer_buflen == 0) {
			ret->download_buflen = MINIMUM(limits.read_length,
			    SFTP_MAX_رسالة_LENGTH - 1024);
			ret->upload_buflen = MINIMUM(limits.write_length,
			    SFTP_MAX_رسالة_LENGTH - 1024);
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
	إذا (ret->version == 0) {
		ret->download_buflen = MINIMUM(ret->download_buflen, 20480);
		ret->upload_buflen = MINIMUM(ret->upload_buflen, 20480);
	}

	ret->limit_kbps = limit_kbps;
	إذا (ret->limit_kbps > 0) {
		bandwidth_limit_init(&ret->bwlimit_in, ret->limit_kbps,
		    ret->download_buflen);
		bandwidth_limit_init(&ret->bwlimit_out, ret->limit_kbps,
		    ret->upload_buflen);
	}

	إرجاع ret;
}

فراغ
sftp_free(بنية sftp_conn *conn)
{
	إذا (conn == عدم)
		إرجاع;
	freezero(conn, حجم(*conn));
}

u_int
sftp_proto_version(بنية sftp_conn *conn)
{
	إرجاع conn->version;
}

صحيح
sftp_get_limits(بنية sftp_conn *conn, بنية sftp_limits *limits)
{
	u_int id, رسالة_id;
	u_char type;
	بنية sshbuf *رسالة;
	صحيح r;

	إذا ((conn->exts & SFTP_EXT_LIMITS) == 0) {
		error("Server does not support limits@openssh.com extension");
		إرجاع -1;
	}

	إذا ((رسالة = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");

	id = conn->رسالة_id++;
	إذا ((r = sshbuf_put_u8(رسالة, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(رسالة, id)) != 0 ||
	    (r = sshbuf_put_cstring(رسالة, "limits@openssh.com")) != 0)
		fatal_fr(r, "compose");
	send_رسالة(conn, رسالة);
	debug3("Sent message limits@openssh.com I:%u", id);

	get_رسالة(conn, رسالة);

	إذا ((r = sshbuf_get_u8(رسالة, &type)) != 0 ||
	    (r = sshbuf_get_u32(رسالة, &رسالة_id)) != 0)
		fatal_fr(r, "parse");

	debug3("Received limits reply T:%u I:%u", type, رسالة_id);
	إذا (id != رسالة_id)
		fatal("ID mismatch (%u != %u)", رسالة_id, id);
	إذا (type != SSH2_FXP_EXTENDED_REPLY) {
		debug_f("expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_REPLY, type);
		/* Disable the limits extension */
		conn->exts &= ~SFTP_EXT_LIMITS;
		sshbuf_free(رسالة);
		إرجاع -1;
	}

	memset(limits, 0, حجم(*limits));
	إذا ((r = sshbuf_get_u64(رسالة, &limits->packet_length)) != 0 ||
	    (r = sshbuf_get_u64(رسالة, &limits->read_length)) != 0 ||
	    (r = sshbuf_get_u64(رسالة, &limits->write_length)) != 0 ||
	    (r = sshbuf_get_u64(رسالة, &limits->open_handles)) != 0)
		fatal_fr(r, "parse limits");

	sshbuf_free(رسالة);

	إرجاع 0;
}

صحيح
sftp_close(بنية sftp_conn *conn, ثابت u_char *handle, u_int handle_len)
{
	u_int id, status;
	بنية sshbuf *رسالة;
	صحيح r;

	إذا ((رسالة = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");

	id = conn->رسالة_id++;
	إذا ((r = sshbuf_put_u8(رسالة, SSH2_FXP_CLOSE)) != 0 ||
	    (r = sshbuf_put_u32(رسالة, id)) != 0 ||
	    (r = sshbuf_put_string(رسالة, handle, handle_len)) != 0)
		fatal_fr(r, "parse");
	send_رسالة(conn, رسالة);
	debug3("Sent message SSH2_FXP_CLOSE I:%u", id);

	status = get_status(conn, id);
	إذا (status != SSH2_FX_OK)
		error("close remote: %s", fx2txt(status));

	sshbuf_free(رسالة);

	إرجاع status == SSH2_FX_OK ? 0 : -1;
}


ساكن صحيح
sftp_lsreaddir(بنية sftp_conn *conn, ثابت حرف *path, صحيح print_flag,
    SFTP_DIRENT ***dir)
{
	بنية sshbuf *رسالة;
	u_int تعداد_2, id, i, expected_id, ents = 0;
	size_t handle_len;
	u_char type, *handle;
	صحيح status = SSH2_FX_FAILURE;
	صحيح r;

	إذا (dir)
		*dir = عدم;

	id = conn->رسالة_id++;

	إذا ((رسالة = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshbuf_put_u8(رسالة, SSH2_FXP_OPENDIR)) != 0 ||
	    (r = sshbuf_put_u32(رسالة, id)) != 0 ||
	    (r = sshbuf_put_cstring(رسالة, path)) != 0)
		fatal_fr(r, "compose OPENDIR");
	send_رسالة(conn, رسالة);

	handle = get_handle(conn, id, &handle_len,
	    "remote readdir(\"%s\")", path);
	إذا (handle == عدم) {
		sshbuf_free(رسالة);
		إرجاع -1;
	}

	إذا (dir) {
		ents = 0;
		*dir = xcalloc(1, حجم(**dir));
		(*dir)[0] = عدم;
	}

	لكل (; !interrupted;) {
		id = expected_id = conn->رسالة_id++;

		debug3("Sending SSH2_FXP_READDIR I:%u", id);

		sshbuf_reset(رسالة);
		إذا ((r = sshbuf_put_u8(رسالة, SSH2_FXP_READDIR)) != 0 ||
		    (r = sshbuf_put_u32(رسالة, id)) != 0 ||
		    (r = sshbuf_put_string(رسالة, handle, handle_len)) != 0)
			fatal_fr(r, "compose READDIR");
		send_رسالة(conn, رسالة);

		sshbuf_reset(رسالة);

		get_رسالة(conn, رسالة);

		إذا ((r = sshbuf_get_u8(رسالة, &type)) != 0 ||
		    (r = sshbuf_get_u32(رسالة, &id)) != 0)
			fatal_fr(r, "parse");

		debug3("Received reply T:%u I:%u", type, id);

		إذا (id != expected_id)
			fatal("ID mismatch (%u != %u)", id, expected_id);

		إذا (type == SSH2_FXP_STATUS) {
			u_int rstatus;

			إذا ((r = sshbuf_get_u32(رسالة, &rstatus)) != 0)
				fatal_fr(r, "parse status");
			debug3("Received SSH2_FXP_STATUS %d", rstatus);
			إذا (rstatus == SSH2_FX_EOF)
				اكسر;
			error("Couldn't read directory: %s", fx2txt(rstatus));
			اذهب out;
		} وإلا إذا (type != SSH2_FXP_NAME)
			fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
			    SSH2_FXP_NAME, type);

		إذا ((r = sshbuf_get_u32(رسالة, &تعداد_2)) != 0)
			fatal_fr(r, "parse count");
		إذا (تعداد_2 > SSHBUF_SIZE_MAX)
			fatal_f("nonsensical number of entries");
		إذا (تعداد_2 == 0)
			اكسر;
		debug3("Received %d SSH2_FXP_NAME responses", تعداد_2);
		لكل (i = 0; i < تعداد_2; i++) {
			حرف *filename, *longname;
			Attrib a;

			إذا ((r = sshbuf_get_cstring(رسالة, &filename,
			    عدم)) != 0 ||
			    (r = sshbuf_get_cstring(رسالة, &longname,
			    عدم)) != 0)
				fatal_fr(r, "parse filenames");
			إذا ((r = decode_attrib(رسالة, &a)) != 0) {
				error_fr(r, "couldn't decode attrib");
				حرر(filename);
				حرر(longname);
				اذهب out;
			}

			إذا (print_flag)
				mprintf("%s\n", longname);

			/*
			 * Directory entries should never contain '/'
			 * These can be used to attack recursive ops
			 * (e.g. send '../../../../etc/passwd')
			 */
			إذا (*filename == '\0' ||
			    strpbrk(filename, SFTP_DIRECTORY_CHARS) != عدم) {
				error("Server sent suspect path \"%s\" "
				    "during readdir of \"%s\"", filename, path);
			} وإلا إذا (dir) {
				*dir = xreallocarray(*dir, ents + 2, حجم(**dir));
				(*dir)[ents] = xcalloc(1, حجم(***dir));
				(*dir)[ents]->filename = xstrdup(filename);
				(*dir)[ents]->longname = xstrdup(longname);
				memcpy(&(*dir)[ents]->a, &a, حجم(a));
				(*dir)[++ents] = عدم;
			}
			حرر(filename);
			حرر(longname);
		}
	}
	status = 0;

 out:
	sshbuf_free(رسالة);
	sftp_close(conn, handle, handle_len);
	حرر(handle);

	إذا (status != 0 && dir != عدم) {
		/* Don't return results on error */
		sftp_free_dirents(*dir);
		*dir = عدم;
	} وإلا إذا (interrupted && dir != عدم && *dir != عدم) {
		/* Don't return partial matches on interrupt */
		sftp_free_dirents(*dir);
		*dir = xcalloc(1, حجم(**dir));
		**dir = عدم;
	}

	إرجاع status == SSH2_FX_OK ? 0 : -1;
}

صحيح
sftp_readdir(بنية sftp_conn *conn, ثابت حرف *path, SFTP_DIRENT ***dir)
{
	إرجاع sftp_lsreaddir(conn, path, 0, dir);
}

فراغ sftp_free_dirents(SFTP_DIRENT **s)
{
	صحيح i;

	إذا (s == عدم)
		إرجاع;
	لكل (i = 0; s[i]; i++) {
		حرر(s[i]->filename);
		حرر(s[i]->longname);
		حرر(s[i]);
	}
	حرر(s);
}

صحيح
sftp_rm(بنية sftp_conn *conn, ثابت حرف *path)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_REMOVE \"%s\"", path);

	id = conn->رسالة_id++;
	send_string_request(conn, id, SSH2_FXP_REMOVE, path, strlen(path));
	status = get_status(conn, id);
	إذا (status != SSH2_FX_OK)
		error("remote delete %s: %s", path, fx2txt(status));
	إرجاع status == SSH2_FX_OK ? 0 : -1;
}

صحيح
sftp_mkdir(بنية sftp_conn *conn, ثابت حرف *path, Attrib *a, صحيح print_flag)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_MKDIR \"%s\"", path);

	id = conn->رسالة_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_MKDIR, path,
	    strlen(path), a);

	status = get_status(conn, id);
	إذا (status != SSH2_FX_OK && print_flag)
		error("remote mkdir \"%s\": %s", path, fx2txt(status));

	إرجاع status == SSH2_FX_OK ? 0 : -1;
}

صحيح
sftp_mkpath(بنية sftp_conn *conn, ثابت حرف *path, Attrib *a, صحيح print_flag)
{
	حرف *slash, *tmp_path;
	صحيح done;

	tmp_path = xstrdup(path);
	slash = tmp_path;

	لكل (;;) {
		slash += strspn(slash, "/");
		slash += strcspn(slash, "/");

		done = (*slash == '\0');
		*slash = '\0';

		إذا (!sftp_remote_is_dir(conn, tmp_path)) {
			إذا (sftp_mkdir(conn, tmp_path, a, print_flag) != 0) {
				حرر(tmp_path);
				إرجاع -1;
			}
		}

		إذا (done)
			اكسر;

		*slash = '/';
	}

	حرر(tmp_path);
	إرجاع 0;
}

صحيح
sftp_rmdir(بنية sftp_conn *conn, ثابت حرف *path)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_RMDIR \"%s\"", path);

	id = conn->رسالة_id++;
	send_string_request(conn, id, SSH2_FXP_RMDIR, path,
	    strlen(path));

	status = get_status(conn, id);
	إذا (status != SSH2_FX_OK)
		error("remote rmdir \"%s\": %s", path, fx2txt(status));

	إرجاع status == SSH2_FX_OK ? 0 : -1;
}

صحيح
sftp_stat(بنية sftp_conn *conn, ثابت حرف *path, صحيح quiet, Attrib *a)
{
	u_int id;

	debug2("Sending SSH2_FXP_STAT \"%s\"", path);

	id = conn->رسالة_id++;

	send_string_request(conn, id,
	    conn->version == 0 ? SSH2_FXP_STAT_VERSION_0 : SSH2_FXP_STAT,
	    path, strlen(path));

	إرجاع get_decode_stat(conn, id, quiet, a);
}

صحيح
sftp_lstat(بنية sftp_conn *conn, ثابت حرف *path, صحيح quiet, Attrib *a)
{
	u_int id;

	إذا (conn->version == 0) {
		do_log2(quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_INFO,
		    "Server version does not support lstat operation");
		إرجاع sftp_stat(conn, path, quiet, a);
	}

	id = conn->رسالة_id++;
	send_string_request(conn, id, SSH2_FXP_LSTAT, path,
	    strlen(path));

	إرجاع get_decode_stat(conn, id, quiet, a);
}

#ifdef notyet
صحيح
sftp_fstat(بنية sftp_conn *conn, ثابت u_char *handle, u_int handle_len,
    صحيح quiet, Attrib *a)
{
	u_int id;

	debug2("Sending SSH2_FXP_FSTAT \"%s\"");

	id = conn->رسالة_id++;
	send_string_request(conn, id, SSH2_FXP_FSTAT, handle,
	    handle_len);

	إرجاع get_decode_stat(conn, id, quiet, a);
}
#endif

صحيح
sftp_setstat(بنية sftp_conn *conn, ثابت حرف *path, Attrib *a)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_SETSTAT \"%s\"", path);

	id = conn->رسالة_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_SETSTAT, path,
	    strlen(path), a);

	status = get_status(conn, id);
	إذا (status != SSH2_FX_OK)
		error("remote setstat \"%s\": %s", path, fx2txt(status));

	إرجاع status == SSH2_FX_OK ? 0 : -1;
}

صحيح
sftp_fsetstat(بنية sftp_conn *conn, ثابت u_char *handle, u_int handle_len,
    Attrib *a)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_FSETSTAT");

	id = conn->رسالة_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_FSETSTAT, handle,
	    handle_len, a);

	status = get_status(conn, id);
	إذا (status != SSH2_FX_OK)
		error("remote fsetstat: %s", fx2txt(status));

	إرجاع status == SSH2_FX_OK ? 0 : -1;
}

/* Implements both the realpath and expand-path operations */
ساكن حرف *
sftp_realpath_expand(بنية sftp_conn *conn, ثابت حرف *path, صحيح expand)
{
	بنية sshbuf *رسالة;
	u_int expected_id, تعداد_2, id;
	حرف *filename, *longname;
	Attrib a;
	u_char type;
	صحيح r;
	ثابت حرف *what = "SSH2_FXP_REALPATH";

	إذا (expand)
		what = "expand-path@openssh.com";
	إذا ((رسالة = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");

	expected_id = id = conn->رسالة_id++;
	إذا (expand) {
		debug2("Sending SSH2_FXP_EXTENDED(expand-path@openssh.com) "
		    "\"%s\"", path);
		إذا ((r = sshbuf_put_u8(رسالة, SSH2_FXP_EXTENDED)) != 0 ||
		    (r = sshbuf_put_u32(رسالة, id)) != 0 ||
		    (r = sshbuf_put_cstring(رسالة,
		    "expand-path@openssh.com")) != 0 ||
		    (r = sshbuf_put_cstring(رسالة, path)) != 0)
			fatal_fr(r, "compose %s", what);
		send_رسالة(conn, رسالة);
	} وإلا {
		debug2("Sending SSH2_FXP_REALPATH \"%s\"", path);
		send_string_request(conn, id, SSH2_FXP_REALPATH,
		    path, strlen(path));
	}
	get_رسالة(conn, رسالة);
	إذا ((r = sshbuf_get_u8(رسالة, &type)) != 0 ||
	    (r = sshbuf_get_u32(رسالة, &id)) != 0)
		fatal_fr(r, "parse");

	إذا (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);

	إذا (type == SSH2_FXP_STATUS) {
		u_int status;
		حرف *errmsg;

		إذا ((r = sshbuf_get_u32(رسالة, &status)) != 0 ||
		    (r = sshbuf_get_cstring(رسالة, &errmsg, عدم)) != 0)
			fatal_fr(r, "parse status");
		error("%s %s: %s", expand ? "expand" : "realpath",
		    path, *errmsg == '\0' ? fx2txt(status) : errmsg);
		حرر(errmsg);
		sshbuf_free(رسالة);
		إرجاع عدم;
	} وإلا إذا (type != SSH2_FXP_NAME)
		fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
		    SSH2_FXP_NAME, type);

	إذا ((r = sshbuf_get_u32(رسالة, &تعداد_2)) != 0)
		fatal_fr(r, "parse count");
	إذا (تعداد_2 != 1)
		fatal("Got multiple names (%d) from %s", تعداد_2, what);

	إذا ((r = sshbuf_get_cstring(رسالة, &filename, عدم)) != 0 ||
	    (r = sshbuf_get_cstring(رسالة, &longname, عدم)) != 0 ||
	    (r = decode_attrib(رسالة, &a)) != 0)
		fatal_fr(r, "parse filename/attrib");

	debug3("%s %s -> %s", what, path, filename);

	حرر(longname);

	sshbuf_free(رسالة);

	إرجاع(filename);
}

حرف *
sftp_realpath(بنية sftp_conn *conn, ثابت حرف *path)
{
	إرجاع sftp_realpath_expand(conn, path, 0);
}

صحيح
sftp_can_expand_path(بنية sftp_conn *conn)
{
	إرجاع (conn->exts & SFTP_EXT_PATH_EXPAND) != 0;
}

حرف *
sftp_expand_path(بنية sftp_conn *conn, ثابت حرف *path)
{
	إذا (!sftp_can_expand_path(conn)) {
		debug3_f("no server support, fallback to realpath");
		إرجاع sftp_realpath_expand(conn, path, 0);
	}
	إرجاع sftp_realpath_expand(conn, path, 1);
}

صحيح
sftp_copy(بنية sftp_conn *conn, ثابت حرف *oldpath, ثابت حرف *newpath)
{
	Attrib junk, attr;
	بنية sshbuf *رسالة;
	u_char *old_handle, *new_handle;
	u_int mode, status, id;
	size_t old_handle_len, new_handle_len;
	صحيح r;

	/* Return if the extension is not supported */
	إذا ((conn->exts & SFTP_EXT_COPY_DATA) == 0) {
		error("Server does not support copy-data extension");
		إرجاع -1;
	}

	/* Make sure the file exists, and we can copy its perms */
	إذا (sftp_stat(conn, oldpath, 0, &attr) != 0)
		إرجاع -1;

	/* Do not preserve set[ug]id here, as we do not preserve ownership */
	إذا (attr.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		mode = attr.perm & 0777;

		إذا (!S_ISREG(attr.perm)) {
			error("Cannot copy non-regular file: %s", oldpath);
			إرجاع -1;
		}
	} وإلا {
		/* NB: The user's umask will apply to this */
		mode = 0666;
	}

	/* Set up the new perms for the new file */
	attrib_clear(&attr);
	attr.perm = mode;
	attr.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;

	إذا ((رسالة = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");

	attrib_clear(&junk); /* Send empty attributes */

	/* Open the old file for reading */
	id = conn->رسالة_id++;
	إذا ((r = sshbuf_put_u8(رسالة, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(رسالة, id)) != 0 ||
	    (r = sshbuf_put_cstring(رسالة, oldpath)) != 0 ||
	    (r = sshbuf_put_u32(رسالة, SSH2_FXF_READ)) != 0 ||
	    (r = encode_attrib(رسالة, &junk)) != 0)
		fatal_fr(r, "buffer error");
	send_رسالة(conn, رسالة);
	debug3("Sent message SSH2_FXP_OPEN I:%u P:%s", id, oldpath);

	sshbuf_reset(رسالة);

	old_handle = get_handle(conn, id, &old_handle_len,
	    "remote open(\"%s\")", oldpath);
	إذا (old_handle == عدم) {
		sshbuf_free(رسالة);
		إرجاع -1;
	}

	/* Open the new file for writing */
	id = conn->رسالة_id++;
	إذا ((r = sshbuf_put_u8(رسالة, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(رسالة, id)) != 0 ||
	    (r = sshbuf_put_cstring(رسالة, newpath)) != 0 ||
	    (r = sshbuf_put_u32(رسالة, SSH2_FXF_WRITE|SSH2_FXF_CREAT|
	    SSH2_FXF_TRUNC)) != 0 ||
	    (r = encode_attrib(رسالة, &attr)) != 0)
		fatal_fr(r, "buffer error");
	send_رسالة(conn, رسالة);
	debug3("Sent message SSH2_FXP_OPEN I:%u P:%s", id, newpath);

	sshbuf_reset(رسالة);

	new_handle = get_handle(conn, id, &new_handle_len,
	    "remote open(\"%s\")", newpath);
	إذا (new_handle == عدم) {
		sshbuf_free(رسالة);
		حرر(old_handle);
		إرجاع -1;
	}

	/* Copy the file data */
	id = conn->رسالة_id++;
	إذا ((r = sshbuf_put_u8(رسالة, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(رسالة, id)) != 0 ||
	    (r = sshbuf_put_cstring(رسالة, "copy-data")) != 0 ||
	    (r = sshbuf_put_string(رسالة, old_handle, old_handle_len)) != 0 ||
	    (r = sshbuf_put_u64(رسالة, 0)) != 0 ||
	    (r = sshbuf_put_u64(رسالة, 0)) != 0 ||
	    (r = sshbuf_put_string(رسالة, new_handle, new_handle_len)) != 0 ||
	    (r = sshbuf_put_u64(رسالة, 0)) != 0)
		fatal_fr(r, "buffer error");
	send_رسالة(conn, رسالة);
	debug3("Sent message copy-data \"%s\" 0 0 -> \"%s\" 0",
	       oldpath, newpath);

	status = get_status(conn, id);
	إذا (status != SSH2_FX_OK)
		error("Couldn't copy file \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	/* Clean up everything */
	sshbuf_free(رسالة);
	sftp_close(conn, old_handle, old_handle_len);
	sftp_close(conn, new_handle, new_handle_len);
	حرر(old_handle);
	حرر(new_handle);

	إرجاع status == SSH2_FX_OK ? 0 : -1;
}

صحيح
sftp_rename(بنية sftp_conn *conn, ثابت حرف *oldpath, ثابت حرف *newpath,
    صحيح force_legacy)
{
	بنية sshbuf *رسالة;
	u_int status, id;
	صحيح r, use_ext = (conn->exts & SFTP_EXT_POSIX_RENAME) && !force_legacy;

	إذا ((رسالة = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");

	/* Send rename request */
	id = conn->رسالة_id++;
	إذا (use_ext) {
		debug2("Sending SSH2_FXP_EXTENDED(posix-rename@openssh.com) "
		    "\"%s\" to \"%s\"", oldpath, newpath);
		إذا ((r = sshbuf_put_u8(رسالة, SSH2_FXP_EXTENDED)) != 0 ||
		    (r = sshbuf_put_u32(رسالة, id)) != 0 ||
		    (r = sshbuf_put_cstring(رسالة,
		    "posix-rename@openssh.com")) != 0)
			fatal_fr(r, "compose posix-rename");
	} وإلا {
		debug2("Sending SSH2_FXP_RENAME \"%s\" to \"%s\"",
		    oldpath, newpath);
		إذا ((r = sshbuf_put_u8(رسالة, SSH2_FXP_RENAME)) != 0 ||
		    (r = sshbuf_put_u32(رسالة, id)) != 0)
			fatal_fr(r, "compose rename");
	}
	إذا ((r = sshbuf_put_cstring(رسالة, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(رسالة, newpath)) != 0)
		fatal_fr(r, "compose paths");
	send_رسالة(conn, رسالة);
	debug3("Sent message %s \"%s\" -> \"%s\"",
	    use_ext ? "posix-rename@openssh.com" :
	    "SSH2_FXP_RENAME", oldpath, newpath);
	sshbuf_free(رسالة);

	status = get_status(conn, id);
	إذا (status != SSH2_FX_OK)
		error("remote rename \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	إرجاع status == SSH2_FX_OK ? 0 : -1;
}

صحيح
sftp_hardlink(بنية sftp_conn *conn, ثابت حرف *oldpath, ثابت حرف *newpath)
{
	بنية sshbuf *رسالة;
	u_int status, id;
	صحيح r;

	إذا ((conn->exts & SFTP_EXT_HARDLINK) == 0) {
		error("Server does not support hardlink@openssh.com extension");
		إرجاع -1;
	}
	debug2("Sending SSH2_FXP_EXTENDED(hardlink@openssh.com) "
	    "\"%s\" to \"%s\"", oldpath, newpath);

	إذا ((رسالة = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");

	/* Send link request */
	id = conn->رسالة_id++;
	إذا ((r = sshbuf_put_u8(رسالة, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(رسالة, id)) != 0 ||
	    (r = sshbuf_put_cstring(رسالة, "hardlink@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(رسالة, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(رسالة, newpath)) != 0)
		fatal_fr(r, "compose");
	send_رسالة(conn, رسالة);
	debug3("Sent message hardlink@openssh.com \"%s\" -> \"%s\"",
	    oldpath, newpath);
	sshbuf_free(رسالة);

	status = get_status(conn, id);
	إذا (status != SSH2_FX_OK)
		error("remote link \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	إرجاع status == SSH2_FX_OK ? 0 : -1;
}

صحيح
sftp_symlink(بنية sftp_conn *conn, ثابت حرف *oldpath, ثابت حرف *newpath)
{
	بنية sshbuf *رسالة;
	u_int status, id;
	صحيح r;

	إذا (conn->version < 3) {
		error("This server does not support the symlink operation");
		إرجاع(SSH2_FX_OP_UNSUPPORTED);
	}
	debug2("Sending SSH2_FXP_SYMLINK \"%s\" to \"%s\"", oldpath, newpath);

	إذا ((رسالة = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");

	/* Send symlink request */
	id = conn->رسالة_id++;
	إذا ((r = sshbuf_put_u8(رسالة, SSH2_FXP_SYMLINK)) != 0 ||
	    (r = sshbuf_put_u32(رسالة, id)) != 0 ||
	    (r = sshbuf_put_cstring(رسالة, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(رسالة, newpath)) != 0)
		fatal_fr(r, "compose");
	send_رسالة(conn, رسالة);
	debug3("Sent message SSH2_FXP_SYMLINK \"%s\" -> \"%s\"", oldpath,
	    newpath);
	sshbuf_free(رسالة);

	status = get_status(conn, id);
	إذا (status != SSH2_FX_OK)
		error("remote symlink file \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	إرجاع status == SSH2_FX_OK ? 0 : -1;
}

صحيح
sftp_fsync(بنية sftp_conn *conn, u_char *handle, u_int handle_len)
{
	بنية sshbuf *رسالة;
	u_int status, id;
	صحيح r;

	/* Silently return if the extension is not supported */
	إذا ((conn->exts & SFTP_EXT_FSYNC) == 0)
		إرجاع -1;
	debug2("Sending SSH2_FXP_EXTENDED(fsync@openssh.com)");

	/* Send fsync request */
	إذا ((رسالة = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	id = conn->رسالة_id++;
	إذا ((r = sshbuf_put_u8(رسالة, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(رسالة, id)) != 0 ||
	    (r = sshbuf_put_cstring(رسالة, "fsync@openssh.com")) != 0 ||
	    (r = sshbuf_put_string(رسالة, handle, handle_len)) != 0)
		fatal_fr(r, "compose");
	send_رسالة(conn, رسالة);
	debug3("Sent message fsync@openssh.com I:%u", id);
	sshbuf_free(رسالة);

	status = get_status(conn, id);
	إذا (status != SSH2_FX_OK)
		error("remote fsync: %s", fx2txt(status));

	إرجاع status == SSH2_FX_OK ? 0 : -1;
}

#ifdef notyet
حرف *
sftp_readlink(بنية sftp_conn *conn, ثابت حرف *path)
{
	بنية sshbuf *رسالة;
	u_int expected_id, تعداد_2, id;
	حرف *filename, *longname;
	Attrib a;
	u_char type;
	صحيح r;

	debug2("Sending SSH2_FXP_READLINK \"%s\"", path);

	expected_id = id = conn->رسالة_id++;
	send_string_request(conn, id, SSH2_FXP_READLINK, path, strlen(path));

	إذا ((رسالة = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");

	get_رسالة(conn, رسالة);
	إذا ((r = sshbuf_get_u8(رسالة, &type)) != 0 ||
	    (r = sshbuf_get_u32(رسالة, &id)) != 0)
		fatal_fr(r, "parse");

	إذا (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);

	إذا (type == SSH2_FXP_STATUS) {
		u_int status;

		إذا ((r = sshbuf_get_u32(رسالة, &status)) != 0)
			fatal_fr(r, "parse status");
		error("Couldn't readlink: %s", fx2txt(status));
		sshbuf_free(رسالة);
		إرجاع(عدم);
	} وإلا إذا (type != SSH2_FXP_NAME)
		fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
		    SSH2_FXP_NAME, type);

	إذا ((r = sshbuf_get_u32(رسالة, &تعداد_2)) != 0)
		fatal_fr(r, "parse count");
	إذا (تعداد_2 != 1)
		fatal("Got multiple names (%d) from SSH_FXP_READLINK", تعداد_2);

	إذا ((r = sshbuf_get_cstring(رسالة, &filename, عدم)) != 0 ||
	    (r = sshbuf_get_cstring(رسالة, &longname, عدم)) != 0 ||
	    (r = decode_attrib(رسالة, &a)) != 0)
		fatal_fr(r, "parse filenames/attrib");

	debug3("SSH_FXP_READLINK %s -> %s", path, filename);

	حرر(longname);

	sshbuf_free(رسالة);

	إرجاع filename;
}
#endif

صحيح
sftp_statvfs(بنية sftp_conn *conn, ثابت حرف *path, بنية sftp_statvfs *st,
    صحيح quiet)
{
	بنية sshbuf *رسالة;
	u_int id;
	صحيح r;

	إذا ((conn->exts & SFTP_EXT_STATVFS) == 0) {
		error("Server does not support statvfs@openssh.com extension");
		إرجاع -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(statvfs@openssh.com) \"%s\"", path);

	id = conn->رسالة_id++;

	إذا ((رسالة = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshbuf_put_u8(رسالة, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(رسالة, id)) != 0 ||
	    (r = sshbuf_put_cstring(رسالة, "statvfs@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(رسالة, path)) != 0)
		fatal_fr(r, "compose");
	send_رسالة(conn, رسالة);
	sshbuf_free(رسالة);

	إرجاع get_decode_statvfs(conn, st, id, quiet);
}

#ifdef notyet
صحيح
sftp_fstatvfs(بنية sftp_conn *conn, ثابت u_char *handle, u_int handle_len,
    بنية sftp_statvfs *st, صحيح quiet)
{
	بنية sshbuf *رسالة;
	u_int id;

	إذا ((conn->exts & SFTP_EXT_FSTATVFS) == 0) {
		error("Server does not support fstatvfs@openssh.com extension");
		إرجاع -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(fstatvfs@openssh.com)");

	id = conn->رسالة_id++;

	إذا ((رسالة = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshbuf_put_u8(رسالة, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(رسالة, id)) != 0 ||
	    (r = sshbuf_put_cstring(رسالة, "fstatvfs@openssh.com")) != 0 ||
	    (r = sshbuf_put_string(رسالة, handle, handle_len)) != 0)
		fatal_fr(r, "compose");
	send_رسالة(conn, رسالة);
	sshbuf_free(رسالة);

	إرجاع get_decode_statvfs(conn, st, id, quiet);
}
#endif

صحيح
sftp_lsetstat(بنية sftp_conn *conn, ثابت حرف *path, Attrib *a)
{
	بنية sshbuf *رسالة;
	u_int status, id;
	صحيح r;

	إذا ((conn->exts & SFTP_EXT_LSETSTAT) == 0) {
		error("Server does not support lsetstat@openssh.com extension");
		إرجاع -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(lsetstat@openssh.com) \"%s\"", path);

	id = conn->رسالة_id++;
	إذا ((رسالة = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshbuf_put_u8(رسالة, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(رسالة, id)) != 0 ||
	    (r = sshbuf_put_cstring(رسالة, "lsetstat@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(رسالة, path)) != 0 ||
	    (r = encode_attrib(رسالة, a)) != 0)
		fatal_fr(r, "compose");
	send_رسالة(conn, رسالة);
	sshbuf_free(رسالة);

	status = get_status(conn, id);
	إذا (status != SSH2_FX_OK)
		error("remote lsetstat \"%s\": %s", path, fx2txt(status));

	إرجاع status == SSH2_FX_OK ? 0 : -1;
}

ساكن فراغ
send_read_request(بنية sftp_conn *conn, u_int id, uint64_t offset,
    u_int len, ثابت u_char *handle, u_int handle_len)
{
	بنية sshbuf *رسالة;
	صحيح r;

	إذا ((رسالة = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshbuf_put_u8(رسالة, SSH2_FXP_READ)) != 0 ||
	    (r = sshbuf_put_u32(رسالة, id)) != 0 ||
	    (r = sshbuf_put_string(رسالة, handle, handle_len)) != 0 ||
	    (r = sshbuf_put_u64(رسالة, offset)) != 0 ||
	    (r = sshbuf_put_u32(رسالة, len)) != 0)
		fatal_fr(r, "compose");
	send_رسالة(conn, رسالة);
	sshbuf_free(رسالة);
}

ساكن صحيح
send_open(بنية sftp_conn *conn, ثابت حرف *path, ثابت حرف *tag,
    u_int openmode, Attrib *a, u_char **handlep, size_t *handle_lenp)
{
	Attrib junk;
	u_char *handle;
	size_t handle_len;
	بنية sshbuf *رسالة;
	صحيح r;
	u_int id;

	debug2("Sending SSH2_FXP_OPEN \"%s\"", path);

	*handlep = عدم;
	*handle_lenp = 0;

	إذا (a == عدم) {
		attrib_clear(&junk); /* Send empty attributes */
		a = &junk;
	}
	/* Send open request */
	إذا ((رسالة = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	id = conn->رسالة_id++;
	إذا ((r = sshbuf_put_u8(رسالة, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(رسالة, id)) != 0 ||
	    (r = sshbuf_put_cstring(رسالة, path)) != 0 ||
	    (r = sshbuf_put_u32(رسالة, openmode)) != 0 ||
	    (r = encode_attrib(رسالة, a)) != 0)
		fatal_fr(r, "compose %s open", tag);
	send_رسالة(conn, رسالة);
	sshbuf_free(رسالة);
	debug3("Sent %s message SSH2_FXP_OPEN I:%u P:%s M:0x%04x",
	    tag, id, path, openmode);
	إذا ((handle = get_handle(conn, id, &handle_len,
	    "%s open \"%s\"", tag, path)) == عدم)
		إرجاع -1;
	/* success */
	*handlep = handle;
	*handle_lenp = handle_len;
	إرجاع 0;
}

ساكن ثابت حرف *
progress_meter_path(ثابت حرف *path)
{
	ثابت حرف *progresspath;

	إذا ((progresspath = strrchr(path, '/')) == عدم)
		إرجاع path;
	progresspath++;
	إذا (*progresspath == '\0')
		إرجاع path;
	إرجاع progresspath;
}

صحيح
sftp_download(بنية sftp_conn *conn, ثابت حرف *remote_path,
    ثابت حرف *local_path, Attrib *a, صحيح preserve_flag, صحيح resume_flag,
    صحيح fsync_flag, صحيح inplace_flag)
{
	بنية sshbuf *رسالة;
	u_char *handle;
	صحيح local_fd = -1, write_error, seen_zerolen = 0;
	صحيح read_error, write_errno, lmodified = 0, reordered = 0, r;
	uint64_t offset = 0, size, highwater = 0, maxack = 0;
	u_int mode, id, buflen, رقم_req, max_req, status = SSH2_FX_OK;
	off_t progress_counter;
	size_t handle_len;
	بنية stat st;
	بنية requests requests;
	بنية request *req;
	u_char type;
	Attrib attr;

	debug2_f("download remote \"%s\" to local \"%s\"",
	    remote_path, local_path);

	TAILQ_INIT(&requests);

	إذا (a == عدم) {
		إذا (sftp_stat(conn, remote_path, 0, &attr) != 0)
			إرجاع -1;
		a = &attr;
	}

	/* Do not preserve set[ug]id here, as we do not preserve ownership */
	إذا (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS)
		mode = a->perm & 0777;
	وإلا
		mode = 0666;

	إذا ((a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) &&
	    (!S_ISREG(a->perm))) {
		error("download %s: not a regular file", remote_path);
		إرجاع(-1);
	}

	إذا (a->flags & SSH2_FILEXFER_ATTR_SIZE)
		size = a->size;
	وإلا
		size = 0;

	buflen = conn->download_buflen;

	/* Send open request */
	إذا (send_open(conn, remote_path, "remote", SSH2_FXF_READ, عدم,
	    &handle, &handle_len) != 0)
		إرجاع -1;

	local_fd = open(local_path, O_WRONLY | O_CREAT |
	((resume_flag || inplace_flag) ? 0 : O_TRUNC), mode | S_IWUSR);
	إذا (local_fd == -1) {
		error("open local \"%s\": %s", local_path, strerror(errno));
		اذهب fail;
	}
	إذا (resume_flag) {
		إذا (fstat(local_fd, &st) == -1) {
			error("stat local \"%s\": %s",
			    local_path, strerror(errno));
			اذهب fail;
		}
		إذا (st.st_size < 0) {
			error("\"%s\" has negative size", local_path);
			اذهب fail;
		}
		إذا ((uint64_t)st.st_size > size) {
			error("Unable to resume download of \"%s\": "
			    "local file is larger than remote", local_path);
 fail:
			sftp_close(conn, handle, handle_len);
			حرر(handle);
			إذا (local_fd != -1)
				close(local_fd);
			إرجاع -1;
		}
		offset = highwater = maxack = st.st_size;
	}

	/* Read from remote and write to local */
	write_error = read_error = write_errno = رقم_req = 0;
	max_req = 1;
	progress_counter = offset;

	إذا (showprogress && size != 0) {
		start_progress_meter(progress_meter_path(remote_path),
		    size, &progress_counter);
	}

	إذا ((رسالة = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");

	بينما (رقم_req > 0 || max_req > 0) {
		u_char *data;
		size_t len;

		/*
		 * Simulate EOF on interrupt: stop sending new requests and
		 * allow outstanding requests to drain gracefully
		 */
		إذا (interrupted) {
			إذا (رقم_req == 0) /* If we haven't started yet... */
				اكسر;
			max_req = 0;
		}

		/* Send some more requests */
		بينما (رقم_req < max_req) {
			debug3("Request range %llu -> %llu (%d/%d)",
			    (unsigned long long)offset,
			    (unsigned long long)offset + buflen - 1,
			    رقم_req, max_req);
			req = request_enqueue(&requests, conn->رسالة_id++,
			    buflen, offset);
			offset += buflen;
			رقم_req++;
			send_read_request(conn, req->id, req->offset,
			    req->len, handle, handle_len);
		}

		sshbuf_reset(رسالة);
		get_رسالة(conn, رسالة);
		إذا ((r = sshbuf_get_u8(رسالة, &type)) != 0 ||
		    (r = sshbuf_get_u32(رسالة, &id)) != 0)
			fatal_fr(r, "parse");
		debug3("Received reply T:%u I:%u R:%d", type, id, max_req);

		/* Find the request in our queue */
		إذا ((req = request_find(&requests, id)) == عدم)
			fatal("Unexpected reply %u", id);

		بدل (type) {
		حالة SSH2_FXP_STATUS:
			إذا ((r = sshbuf_get_u32(رسالة, &status)) != 0)
				fatal_fr(r, "parse status");
			إذا (status != SSH2_FX_EOF)
				read_error = 1;
			max_req = 0;
			TAILQ_REMOVE(&requests, req, tq);
			حرر(req);
			رقم_req--;
			اكسر;
		حالة SSH2_FXP_DATA:
			إذا ((r = sshbuf_get_string(رسالة, &data, &len)) != 0)
				fatal_fr(r, "parse data");
			debug3("Received data %llu -> %llu",
			    (unsigned long long)req->offset,
			    (unsigned long long)req->offset + len - 1);
			إذا (len > req->len)
				fatal("Received more data than asked for "
				    "%zu > %zu", len, req->len);
			إذا (len == 0) {
				إذا (seen_zerolen)
					fatal_f("server sent zero data length");
				seen_zerolen = 1;
			}
			lmodified = 1;
			إذا ((lseek(local_fd, req->offset, SEEK_SET) == -1 ||
			    atomicio(vwrite, local_fd, data, len) != len) &&
			    !write_error) {
				write_errno = errno;
				write_error = 1;
				max_req = 0;
			} وإلا {
				/*
				 * Track both the highest offset acknowledged
				 * and the highest *contiguous* offset
				 * acknowledged.
				 * We'll need the latter for ftruncate()ing
				 * interrupted transfers.
				 */
				إذا (maxack < req->offset + len)
					maxack = req->offset + len;
				إذا (!reordered && req->offset <= highwater)
					highwater = maxack;
				وإلا إذا (!reordered && req->offset > highwater)
					reordered = 1;
			}
			progress_counter += len;
			حرر(data);

			إذا (len == req->len) {
				TAILQ_REMOVE(&requests, req, tq);
				حرر(req);
				رقم_req--;
			} وإلا {
				/* Resend the request for the missing data */
				debug3("Short data block, re-requesting "
				    "%llu -> %llu (%2d)",
				    (unsigned long long)req->offset + len,
				    (unsigned long long)req->offset +
				    req->len - 1, رقم_req);
				req->id = conn->رسالة_id++;
				req->len -= len;
				req->offset += len;
				send_read_request(conn, req->id,
				    req->offset, req->len, handle, handle_len);
				/* Reduce the request size */
				إذا (len < buflen)
					buflen = MAXIMUM(MIN_READ_SIZE, len);
			}
			إذا (max_req > 0) { /* max_req = 0 iff EOF received */
				إذا (size > 0 && offset > size) {
					/* Only one request at a time
					 * after the expected EOF */
					debug3("Finish at %llu (%2d)",
					    (unsigned long long)offset,
					    رقم_req);
					max_req = 1;
				} وإلا إذا (max_req < conn->رقم_requests) {
					++max_req;
				}
			}
			اكسر;
		افتراضي:
			fatal("Expected SSH2_FXP_DATA(%u) packet, got %u",
			    SSH2_FXP_DATA, type);
		}
	}

	إذا (showprogress && size)
		stop_progress_meter();

	/* Sanity check */
	إذا (TAILQ_FIRST(&requests) != عدم)
		fatal("Transfer complete, but requests still in queue");

	إذا (!read_error && !write_error && !interrupted) {
		/* we got everything */
		highwater = maxack;
	}

	/*
	 * Truncate at highest contiguous point to avoid holes on interrupt,
	 * or unconditionally if writing in place.
	 */
	إذا (inplace_flag || read_error || write_error || interrupted) {
		إذا (reordered && resume_flag &&
		    (read_error || write_error || interrupted)) {
			error("Unable to resume download of \"%s\": "
			    "server reordered requests", local_path);
		}
		debug("truncating at %llu", (unsigned long long)highwater);
		إذا (ftruncate(local_fd, highwater) == -1)
			error("local ftruncate \"%s\": %s", local_path,
			    strerror(errno));
	}
	إذا (read_error) {
		error("read remote \"%s\" : %s", remote_path, fx2txt(status));
		status = -1;
		sftp_close(conn, handle, handle_len);
	} وإلا إذا (write_error) {
		error("write local \"%s\": %s", local_path,
		    strerror(write_errno));
		status = SSH2_FX_FAILURE;
		sftp_close(conn, handle, handle_len);
	} وإلا {
		إذا (sftp_close(conn, handle, handle_len) != 0 || interrupted)
			status = SSH2_FX_FAILURE;
		وإلا
			status = SSH2_FX_OK;
		/* Override umask and utimes if asked */
#ifdef HAVE_FCHMOD
		إذا (preserve_flag && fchmod(local_fd, mode) == -1)
#وإلا
		إذا (preserve_flag && chmod(local_path, mode) == -1)
#endif /* HAVE_FCHMOD */
			error("local chmod \"%s\": %s", local_path,
			    strerror(errno));
		إذا (preserve_flag &&
		    (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME)) {
			بنية timeval tv[2];
			tv[0].tv_sec = a->atime;
			tv[1].tv_sec = a->mtime;
			tv[0].tv_usec = tv[1].tv_usec = 0;
			إذا (utimes(local_path, tv) == -1)
				error("local set times \"%s\": %s",
				    local_path, strerror(errno));
		}
		إذا (resume_flag && !lmodified)
			logit("File \"%s\" was not modified", local_path);
		وإلا إذا (fsync_flag) {
			debug("syncing \"%s\"", local_path);
			إذا (fsync(local_fd) == -1)
				error("local sync \"%s\": %s",
				    local_path, strerror(errno));
		}
	}
	close(local_fd);
	sshbuf_free(رسالة);
	حرر(handle);

	إرجاع status == SSH2_FX_OK ? 0 : -1;
}

ساكن صحيح
download_dir_internal(بنية sftp_conn *conn, ثابت حرف *src, ثابت حرف *dst,
    صحيح depth, Attrib *dirattrib, صحيح preserve_flag, صحيح print_flag,
    صحيح resume_flag, صحيح fsync_flag, صحيح follow_link_flag, صحيح inplace_flag)
{
	صحيح i, ret = 0;
	SFTP_DIRENT **dir_entries;
	حرف *filename, *new_src = عدم, *new_dst = عدم;
	mode_t mode = 0777, tmpmode = mode;
	Attrib *a, ldirattrib, lsym;

	إذا (depth >= MAX_DIR_DEPTH) {
		error("Maximum directory depth exceeded: %d levels", depth);
		إرجاع -1;
	}

	debug2_f("download dir remote \"%s\" to local \"%s\"", src, dst);

	إذا (dirattrib == عدم) {
		إذا (sftp_stat(conn, src, 1, &ldirattrib) != 0) {
			error("stat remote \"%s\" directory failed", src);
			إرجاع -1;
		}
		dirattrib = &ldirattrib;
	}
	إذا (!S_ISDIR(dirattrib->perm)) {
		error("\"%s\" is not a directory", src);
		إرجاع -1;
	}
	إذا (print_flag && print_flag != SFTP_PROGRESS_ONLY)
		mprintf("Retrieving %s\n", src);

	إذا (dirattrib->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		mode = dirattrib->perm & 01777;
		tmpmode = mode | (S_IWUSR|S_IXUSR);
	} وإلا {
		debug("download remote \"%s\": server "
		    "did not send permissions", dst);
	}

	إذا (mkdir(dst, tmpmode) == -1 && errno != EEXIST) {
		error("mkdir %s: %s", dst, strerror(errno));
		إرجاع -1;
	}

	إذا (sftp_readdir(conn, src, &dir_entries) == -1) {
		error("remote readdir \"%s\" failed", src);
		إرجاع -1;
	}

	لكل (i = 0; dir_entries[i] != عدم && !interrupted; i++) {
		حرر(new_dst);
		حرر(new_src);

		filename = dir_entries[i]->filename;
		new_dst = sftp_path_append(dst, filename);
		new_src = sftp_path_append(src, filename);

		a = &dir_entries[i]->a;
		إذا (S_ISLNK(a->perm)) {
			إذا (!follow_link_flag) {
				logit("download \"%s\": not a regular file",
				    new_src);
				استمر;
			}
			/* Replace the stat contents with the symlink target */
			إذا (sftp_stat(conn, new_src, 1, &lsym) != 0) {
				logit("remote stat \"%s\" failed", new_src);
				ret = -1;
				استمر;
			}
			a = &lsym;
		}

		إذا (S_ISDIR(a->perm)) {
			إذا (strcmp(filename, ".") == 0 ||
			    strcmp(filename, "..") == 0)
				استمر;
			إذا (download_dir_internal(conn, new_src, new_dst,
			    depth + 1, a, preserve_flag,
			    print_flag, resume_flag,
			    fsync_flag, follow_link_flag, inplace_flag) == -1)
				ret = -1;
		} وإلا إذا (S_ISREG(a->perm)) {
			إذا (sftp_download(conn, new_src, new_dst, a,
			    preserve_flag, resume_flag, fsync_flag,
			    inplace_flag) == -1) {
				error("Download of file %s to %s failed",
				    new_src, new_dst);
				ret = -1;
			}
		} وإلا
			logit("download \"%s\": not a regular file", new_src);

	}
	حرر(new_dst);
	حرر(new_src);

	إذا (preserve_flag) {
		إذا (dirattrib->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
			بنية timeval tv[2];
			tv[0].tv_sec = dirattrib->atime;
			tv[1].tv_sec = dirattrib->mtime;
			tv[0].tv_usec = tv[1].tv_usec = 0;
			إذا (utimes(dst, tv) == -1)
				error("local set times on \"%s\": %s",
				    dst, strerror(errno));
		} وإلا
			debug("Server did not send times for directory "
			    "\"%s\"", dst);
	}

	إذا (mode != tmpmode && chmod(dst, mode) == -1)
		error("local chmod directory \"%s\": %s", dst,
		    strerror(errno));

	sftp_free_dirents(dir_entries);

	إرجاع ret;
}

صحيح
sftp_download_dir(بنية sftp_conn *conn, ثابت حرف *src, ثابت حرف *dst,
    Attrib *dirattrib, صحيح preserve_flag, صحيح print_flag, صحيح resume_flag,
    صحيح fsync_flag, صحيح follow_link_flag, صحيح inplace_flag)
{
	حرف *src_canon;
	صحيح ret;

	إذا ((src_canon = sftp_realpath(conn, src)) == عدم) {
		error("download \"%s\": path canonicalization failed", src);
		إرجاع -1;
	}

	ret = download_dir_internal(conn, src_canon, dst, 0,
	    dirattrib, preserve_flag, print_flag, resume_flag, fsync_flag,
	    follow_link_flag, inplace_flag);
	حرر(src_canon);
	إرجاع ret;
}

صحيح
sftp_upload(بنية sftp_conn *conn, ثابت حرف *local_path,
    ثابت حرف *remote_path, صحيح preserve_flag, صحيح resume,
    صحيح fsync_flag, صحيح inplace_flag)
{
	صحيح r, local_fd;
	u_int openmode, id, status = SSH2_FX_OK, status2, reordered = 0;
	off_t offset, progress_counter;
	u_char type, *handle, *data;
	بنية sshbuf *رسالة;
	بنية stat sb;
	Attrib a, t, c;
	uint32_t startid, ackid;
	uint64_t highwater = 0, maxack = 0;
	بنية request *ack = عدم;
	بنية requests acks;
	size_t handle_len;

	debug2_f("upload local \"%s\" to remote \"%s\"",
	    local_path, remote_path);

	TAILQ_INIT(&acks);

	إذا ((local_fd = open(local_path, O_RDONLY)) == -1) {
		error("open local \"%s\": %s", local_path, strerror(errno));
		إرجاع(-1);
	}
	إذا (fstat(local_fd, &sb) == -1) {
		error("fstat local \"%s\": %s", local_path, strerror(errno));
		close(local_fd);
		إرجاع(-1);
	}
	إذا (!S_ISREG(sb.st_mode)) {
		error("local \"%s\" is not a regular file", local_path);
		close(local_fd);
		إرجاع(-1);
	}
	stat_to_attrib(&sb, &a);

	a.flags &= ~SSH2_FILEXFER_ATTR_SIZE;
	a.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a.perm &= 0777;
	إذا (!preserve_flag)
		a.flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;

	إذا (resume) {
		/* Get remote file size if it exists */
		إذا (sftp_stat(conn, remote_path, 0, &c) != 0) {
			close(local_fd);
			إرجاع -1;
		}

		إذا ((off_t)c.size >= sb.st_size) {
			error("resume \"%s\": destination file "
			    "same size or larger", local_path);
			close(local_fd);
			إرجاع -1;
		}

		إذا (lseek(local_fd, (off_t)c.size, SEEK_SET) == -1) {
			close(local_fd);
			إرجاع -1;
		}
		highwater = c.size;
	}

	openmode = SSH2_FXF_WRITE|SSH2_FXF_CREAT;
	إذا (resume)
		openmode |= SSH2_FXF_APPEND;
	وإلا إذا (!inplace_flag)
		openmode |= SSH2_FXF_TRUNC;

	/* Send open request */
	إذا (send_open(conn, remote_path, "dest", openmode, &a,
	    &handle, &handle_len) != 0) {
		close(local_fd);
		إرجاع -1;
	}

	id = conn->رسالة_id;
	startid = ackid = id + 1;
	data = xmalloc(conn->upload_buflen);

	/* Read from local and write to remote */
	offset = progress_counter = (resume ? c.size : 0);
	إذا (showprogress) {
		start_progress_meter(progress_meter_path(local_path),
		    sb.st_size, &progress_counter);
	}

	إذا ((رسالة = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	لكل (;;) {
		صحيح len;

		/*
		 * Can't use atomicio here because it returns 0 on EOF,
		 * thus losing the last block of the file.
		 * Simulate an EOF on interrupt, allowing ACKs from the
		 * server to drain.
		 */
		إذا (interrupted || status != SSH2_FX_OK)
			len = 0;
		وإلا افعل
			len = اقرأ(local_fd, data, conn->upload_buflen);
		بينما ((len == -1) &&
		    (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK));

		إذا (len == -1) {
			fatal("read local \"%s\": %s",
			    local_path, strerror(errno));
		} وإلا إذا (len != 0) {
			ack = request_enqueue(&acks, ++id, len, offset);
			sshbuf_reset(رسالة);
			إذا ((r = sshbuf_put_u8(رسالة, SSH2_FXP_WRITE)) != 0 ||
			    (r = sshbuf_put_u32(رسالة, ack->id)) != 0 ||
			    (r = sshbuf_put_string(رسالة, handle,
			    handle_len)) != 0 ||
			    (r = sshbuf_put_u64(رسالة, offset)) != 0 ||
			    (r = sshbuf_put_string(رسالة, data, len)) != 0)
				fatal_fr(r, "compose");
			send_رسالة(conn, رسالة);
			debug3("Sent message SSH2_FXP_WRITE I:%u O:%llu S:%u",
			    id, (unsigned long long)offset, len);
		} وإلا إذا (TAILQ_FIRST(&acks) == عدم)
			اكسر;

		إذا (ack == عدم)
			fatal("Unexpected ACK %u", id);

		إذا (id == startid || len == 0 ||
		    id - ackid >= conn->رقم_requests) {
			u_int rid;

			sshbuf_reset(رسالة);
			get_رسالة(conn, رسالة);
			إذا ((r = sshbuf_get_u8(رسالة, &type)) != 0 ||
			    (r = sshbuf_get_u32(رسالة, &rid)) != 0)
				fatal_fr(r, "parse");

			إذا (type != SSH2_FXP_STATUS)
				fatal("Expected SSH2_FXP_STATUS(%d) packet, "
				    "got %d", SSH2_FXP_STATUS, type);

			إذا ((r = sshbuf_get_u32(رسالة, &status2)) != 0)
				fatal_fr(r, "parse status");
			debug3("SSH2_FXP_STATUS %u", status2);
			إذا (status2 != SSH2_FX_OK)
				status = status2; /* remember errors */

			/* Find the request in our queue */
			إذا ((ack = request_find(&acks, rid)) == عدم)
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
			إذا (maxack < ack->offset + ack->len)
				maxack = ack->offset + ack->len;
			إذا (!reordered && ack->offset <= highwater)
				highwater = maxack;
			وإلا إذا (!reordered && ack->offset > highwater) {
				debug3_f("server reordered ACKs");
				reordered = 1;
			}
			حرر(ack);
		}
		offset += len;
		إذا (offset < 0)
			fatal_f("offset < 0");
	}
	sshbuf_free(رسالة);

	إذا (showprogress)
		stop_progress_meter();
	حرر(data);

	إذا (status == SSH2_FX_OK && !interrupted) {
		/* we got everything */
		highwater = maxack;
	}
	إذا (status != SSH2_FX_OK) {
		error("write remote \"%s\": %s", remote_path, fx2txt(status));
		status = SSH2_FX_FAILURE;
	}

	إذا (inplace_flag || (resume && (status != SSH2_FX_OK || interrupted))) {
		debug("truncating at %llu", (unsigned long long)highwater);
		attrib_clear(&t);
		t.flags = SSH2_FILEXFER_ATTR_SIZE;
		t.size = highwater;
		sftp_fsetstat(conn, handle, handle_len, &t);
	}

	إذا (close(local_fd) == -1) {
		error("close local \"%s\": %s", local_path, strerror(errno));
		status = SSH2_FX_FAILURE;
	}

	/* Override umask and utimes if asked */
	إذا (preserve_flag)
		sftp_fsetstat(conn, handle, handle_len, &a);

	إذا (fsync_flag)
		(فراغ)sftp_fsync(conn, handle, handle_len);

	إذا (sftp_close(conn, handle, handle_len) != 0)
		status = SSH2_FX_FAILURE;

	حرر(handle);

	إرجاع status == SSH2_FX_OK ? 0 : -1;
}

ساكن صحيح
upload_dir_internal(بنية sftp_conn *conn, ثابت حرف *src, ثابت حرف *dst,
    صحيح depth, صحيح preserve_flag, صحيح print_flag, صحيح resume, صحيح fsync_flag,
    صحيح follow_link_flag, صحيح inplace_flag)
{
	صحيح created = 0, ret = 0;
	DIR *dirp;
	بنية dirent *dp;
	حرف *filename, *new_src = عدم, *new_dst = عدم;
	بنية stat sb;
	Attrib a, dirattrib;
	uint32_t saved_perm;

	debug2_f("upload local dir \"%s\" to remote \"%s\"", src, dst);

	إذا (depth >= MAX_DIR_DEPTH) {
		error("Maximum directory depth exceeded: %d levels", depth);
		إرجاع -1;
	}

	إذا (stat(src, &sb) == -1) {
		error("stat local \"%s\": %s", src, strerror(errno));
		إرجاع -1;
	}
	إذا (!S_ISDIR(sb.st_mode)) {
		error("\"%s\" is not a directory", src);
		إرجاع -1;
	}
	إذا (print_flag && print_flag != SFTP_PROGRESS_ONLY)
		mprintf("Entering %s\n", src);

	stat_to_attrib(&sb, &a);
	a.flags &= ~SSH2_FILEXFER_ATTR_SIZE;
	a.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a.perm &= 01777;
	إذا (!preserve_flag)
		a.flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;

	/*
	 * sftp lacks a portable status value to match errno EEXIST,
	 * so if we get a failure back then we must check whether
	 * the path already existed and is a directory.  Ensure we can
	 * write to the directory we create for the duration of the transfer.
	 */
	saved_perm = a.perm;
	a.perm |= (S_IWUSR|S_IXUSR);
	إذا (sftp_mkdir(conn, dst, &a, 0) == 0)
		created = 1;
	وإلا {
		إذا (sftp_stat(conn, dst, 0, &dirattrib) != 0)
			إرجاع -1;
		إذا (!S_ISDIR(dirattrib.perm)) {
			error("\"%s\" exists but is not a directory", dst);
			إرجاع -1;
		}
	}
	a.perm = saved_perm;

	إذا ((dirp = opendir(src)) == عدم) {
		error("local opendir \"%s\": %s", src, strerror(errno));
		إرجاع -1;
	}

	بينما (((dp = readdir(dirp)) != عدم) && !interrupted) {
		إذا (dp->d_ino == 0)
			استمر;
		حرر(new_dst);
		حرر(new_src);
		filename = dp->d_name;
		new_dst = sftp_path_append(dst, filename);
		new_src = sftp_path_append(src, filename);

		إذا (strcmp(filename, ".") == 0 || strcmp(filename, "..") == 0)
			استمر;
		إذا (lstat(new_src, &sb) == -1) {
			logit("local lstat \"%s\": %s", filename,
			    strerror(errno));
			ret = -1;
			استمر;
		}
		إذا (S_ISLNK(sb.st_mode)) {
			إذا (!follow_link_flag) {
				logit("%s: not a regular file", filename);
				استمر;
			}
			/* Replace the stat contents with the symlink target */
			إذا (stat(new_src, &sb) == -1) {
				logit("local stat \"%s\": %s", filename,
				    strerror(errno));
				ret = -1;
				استمر;
			}
		}
		إذا (S_ISDIR(sb.st_mode)) {
			إذا (upload_dir_internal(conn, new_src, new_dst,
			    depth + 1, preserve_flag, print_flag, resume,
			    fsync_flag, follow_link_flag, inplace_flag) == -1)
				ret = -1;
		} وإلا إذا (S_ISREG(sb.st_mode)) {
			إذا (sftp_upload(conn, new_src, new_dst,
			    preserve_flag, resume, fsync_flag,
			    inplace_flag) == -1) {
				error("upload \"%s\" to \"%s\" failed",
				    new_src, new_dst);
				ret = -1;
			}
		} وإلا
			logit("%s: not a regular file", filename);
	}
	حرر(new_dst);
	حرر(new_src);

	إذا (created || preserve_flag)
		sftp_setstat(conn, dst, &a);

	(فراغ) closedir(dirp);
	إرجاع ret;
}

صحيح
sftp_upload_dir(بنية sftp_conn *conn, ثابت حرف *src, ثابت حرف *dst,
    صحيح preserve_flag, صحيح print_flag, صحيح resume, صحيح fsync_flag,
    صحيح follow_link_flag, صحيح inplace_flag)
{
	حرف *dst_canon;
	صحيح ret;

	إذا ((dst_canon = sftp_realpath(conn, dst)) == عدم) {
		error("upload \"%s\": path canonicalization failed", dst);
		إرجاع -1;
	}

	ret = upload_dir_internal(conn, src, dst_canon, 0, preserve_flag,
	    print_flag, resume, fsync_flag, follow_link_flag, inplace_flag);

	حرر(dst_canon);
	إرجاع ret;
}

ساكن فراغ
handle_dest_replies(بنية sftp_conn *to, ثابت حرف *to_path, صحيح synchronous,
    u_int *nreqsp, u_int *write_errorp)
{
	بنية sshbuf *رسالة;
	u_char type;
	u_int id, status;
	صحيح r;
	بنية pollfd pfd;

	إذا ((رسالة = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");

	/* Try to eat replies from the upload side */
	بينما (*nreqsp > 0) {
		debug3_f("%u outstanding replies", *nreqsp);
		إذا (!synchronous) {
			/* Bail out if no data is ready to be read */
			pfd.fd = to->fd_in;
			pfd.events = POLLIN;
			إذا ((r = poll(&pfd, 1, 0)) == -1) {
				إذا (errno == EINTR)
					اكسر;
				fatal_f("poll: %s", strerror(errno));
			} وإلا إذا (r == 0)
				اكسر; /* fd not ready */
		}
		sshbuf_reset(رسالة);
		get_رسالة(to, رسالة);

		إذا ((r = sshbuf_get_u8(رسالة, &type)) != 0 ||
		    (r = sshbuf_get_u32(رسالة, &id)) != 0)
			fatal_fr(r, "dest parse");
		debug3("Received dest reply T:%u I:%u R:%u", type, id, *nreqsp);
		إذا (type != SSH2_FXP_STATUS) {
			fatal_f("Expected SSH2_FXP_STATUS(%d) packet, got %d",
			    SSH2_FXP_STATUS, type);
		}
		إذا ((r = sshbuf_get_u32(رسالة, &status)) != 0)
			fatal_fr(r, "parse dest status");
		debug3("dest SSH2_FXP_STATUS %u", status);
		إذا (status != SSH2_FX_OK) {
			/* record first error */
			إذا (*write_errorp == 0)
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
	sshbuf_free(رسالة);
}

صحيح
sftp_crossload(بنية sftp_conn *from, بنية sftp_conn *to,
    ثابت حرف *from_path, ثابت حرف *to_path,
    Attrib *a, صحيح preserve_flag)
{
	بنية sshbuf *رسالة;
	صحيح write_error, read_error, r, seen_zerolen = 0;
	uint64_t offset = 0, size;
	u_int id, buflen, رقم_req, max_req, status = SSH2_FX_OK;
	u_int رقم_upload_req;
	off_t progress_counter;
	u_char *from_handle, *to_handle;
	size_t from_handle_len, to_handle_len;
	بنية requests requests;
	بنية request *req;
	u_char type;
	Attrib attr;

	debug2_f("crossload src \"%s\" to dst \"%s\"", from_path, to_path);

	TAILQ_INIT(&requests);

	إذا (a == عدم) {
		إذا (sftp_stat(from, from_path, 0, &attr) != 0)
			إرجاع -1;
		a = &attr;
	}

	إذا ((a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) &&
	    (!S_ISREG(a->perm))) {
		error("download \"%s\": not a regular file", from_path);
		إرجاع(-1);
	}
	إذا (a->flags & SSH2_FILEXFER_ATTR_SIZE)
		size = a->size;
	وإلا
		size = 0;

	buflen = from->download_buflen;
	إذا (buflen > to->upload_buflen)
		buflen = to->upload_buflen;

	/* Send open request to read side */
	إذا (send_open(from, from_path, "origin", SSH2_FXF_READ, عدم,
	    &from_handle, &from_handle_len) != 0)
		إرجاع -1;

	/* Send open request to write side */
	a->flags &= ~SSH2_FILEXFER_ATTR_SIZE;
	a->flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a->perm &= 0777;
	إذا (!preserve_flag)
		a->flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;
	إذا (send_open(to, to_path, "dest",
	    SSH2_FXF_WRITE|SSH2_FXF_CREAT|SSH2_FXF_TRUNC, a,
	    &to_handle, &to_handle_len) != 0) {
		sftp_close(from, from_handle, from_handle_len);
		إرجاع -1;
	}

	/* Read from remote "from" and write to remote "to" */
	offset = 0;
	write_error = read_error = رقم_req = رقم_upload_req = 0;
	max_req = 1;
	progress_counter = 0;

	إذا (showprogress && size != 0) {
		start_progress_meter(progress_meter_path(from_path),
		    size, &progress_counter);
	}
	إذا ((رسالة = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	بينما (رقم_req > 0 || max_req > 0) {
		u_char *data;
		size_t len;

		/*
		 * Simulate EOF on interrupt: stop sending new requests and
		 * allow outstanding requests to drain gracefully
		 */
		إذا (interrupted) {
			إذا (رقم_req == 0) /* If we haven't started yet... */
				اكسر;
			max_req = 0;
		}

		/* Send some more requests */
		بينما (رقم_req < max_req) {
			debug3("Request range %llu -> %llu (%d/%d)",
			    (unsigned long long)offset,
			    (unsigned long long)offset + buflen - 1,
			    رقم_req, max_req);
			req = request_enqueue(&requests, from->رسالة_id++,
			    buflen, offset);
			offset += buflen;
			رقم_req++;
			send_read_request(from, req->id, req->offset,
			    req->len, from_handle, from_handle_len);
		}

		/* Try to eat replies from the upload side (nonblocking) */
		handle_dest_replies(to, to_path, 0,
		    &رقم_upload_req, &write_error);

		sshbuf_reset(رسالة);
		get_رسالة(from, رسالة);
		إذا ((r = sshbuf_get_u8(رسالة, &type)) != 0 ||
		    (r = sshbuf_get_u32(رسالة, &id)) != 0)
			fatal_fr(r, "parse");
		debug3("Received origin reply T:%u I:%u R:%d",
		    type, id, max_req);

		/* Find the request in our queue */
		إذا ((req = request_find(&requests, id)) == عدم)
			fatal("Unexpected reply %u", id);

		بدل (type) {
		حالة SSH2_FXP_STATUS:
			إذا ((r = sshbuf_get_u32(رسالة, &status)) != 0)
				fatal_fr(r, "parse status");
			إذا (status != SSH2_FX_EOF)
				read_error = 1;
			max_req = 0;
			TAILQ_REMOVE(&requests, req, tq);
			حرر(req);
			رقم_req--;
			اكسر;
		حالة SSH2_FXP_DATA:
			إذا ((r = sshbuf_get_string(رسالة, &data, &len)) != 0)
				fatal_fr(r, "parse data");
			debug3("Received data %llu -> %llu",
			    (unsigned long long)req->offset,
			    (unsigned long long)req->offset + len - 1);
			إذا (len > req->len)
				fatal("Received more data than asked for "
				    "%zu > %zu", len, req->len);
			إذا (len == 0) {
				إذا (seen_zerolen)
					fatal_f("server sent zero data length");
				seen_zerolen = 1;
			}

			/* Write this chunk out to the destination */
			sshbuf_reset(رسالة);
			إذا ((r = sshbuf_put_u8(رسالة, SSH2_FXP_WRITE)) != 0 ||
			    (r = sshbuf_put_u32(رسالة, to->رسالة_id++)) != 0 ||
			    (r = sshbuf_put_string(رسالة, to_handle,
			    to_handle_len)) != 0 ||
			    (r = sshbuf_put_u64(رسالة, req->offset)) != 0 ||
			    (r = sshbuf_put_string(رسالة, data, len)) != 0)
				fatal_fr(r, "compose write");
			send_رسالة(to, رسالة);
			debug3("Sent message SSH2_FXP_WRITE I:%u O:%llu S:%zu",
			    id, (unsigned long long)offset, len);
			رقم_upload_req++;
			progress_counter += len;
			حرر(data);

			إذا (len == req->len) {
				TAILQ_REMOVE(&requests, req, tq);
				حرر(req);
				رقم_req--;
			} وإلا {
				/* Resend the request for the missing data */
				debug3("Short data block, re-requesting "
				    "%llu -> %llu (%2d)",
				    (unsigned long long)req->offset + len,
				    (unsigned long long)req->offset +
				    req->len - 1, رقم_req);
				req->id = from->رسالة_id++;
				req->len -= len;
				req->offset += len;
				send_read_request(from, req->id,
				    req->offset, req->len,
				    from_handle, from_handle_len);
				/* Reduce the request size */
				إذا (len < buflen)
					buflen = MAXIMUM(MIN_READ_SIZE, len);
			}
			إذا (max_req > 0) { /* max_req = 0 iff EOF received */
				إذا (size > 0 && offset > size) {
					/* Only one request at a time
					 * after the expected EOF */
					debug3("Finish at %llu (%2d)",
					    (unsigned long long)offset,
					    رقم_req);
					max_req = 1;
				} وإلا إذا (max_req < from->رقم_requests) {
					++max_req;
				}
			}
			اكسر;
		افتراضي:
			fatal("Expected SSH2_FXP_DATA(%u) packet, got %u",
			    SSH2_FXP_DATA, type);
		}
	}

	إذا (showprogress && size)
		stop_progress_meter();

	/* Drain replies from the server (blocking) */
	debug3_f("waiting for %u replies from destination", رقم_upload_req);
	handle_dest_replies(to, to_path, 1, &رقم_upload_req, &write_error);

	/* Sanity check */
	إذا (TAILQ_FIRST(&requests) != عدم)
		fatal("Transfer complete, but requests still in queue");
	/* Truncate at 0 length on interrupt or error to avoid holes at dest */
	إذا (read_error || write_error || interrupted) {
		debug("truncating \"%s\" at 0", to_path);
		sftp_close(to, to_handle, to_handle_len);
		حرر(to_handle);
		إذا (send_open(to, to_path, "dest",
		    SSH2_FXF_WRITE|SSH2_FXF_CREAT|SSH2_FXF_TRUNC, a,
		    &to_handle, &to_handle_len) != 0) {
			error("dest truncate \"%s\" failed", to_path);
			to_handle = عدم;
		}
	}
	إذا (read_error) {
		error("read origin \"%s\": %s", from_path, fx2txt(status));
		status = -1;
		sftp_close(from, from_handle, from_handle_len);
		إذا (to_handle != عدم)
			sftp_close(to, to_handle, to_handle_len);
	} وإلا إذا (write_error) {
		error("write dest \"%s\": %s", to_path, fx2txt(write_error));
		status = SSH2_FX_FAILURE;
		sftp_close(from, from_handle, from_handle_len);
		إذا (to_handle != عدم)
			sftp_close(to, to_handle, to_handle_len);
	} وإلا {
		إذا (sftp_close(from, from_handle, from_handle_len) != 0 ||
		    interrupted)
			status = -1;
		وإلا
			status = SSH2_FX_OK;
		إذا (to_handle != عدم) {
			/* Need to resend utimes after write */
			إذا (preserve_flag)
				sftp_fsetstat(to, to_handle, to_handle_len, a);
			sftp_close(to, to_handle, to_handle_len);
		}
	}
	sshbuf_free(رسالة);
	حرر(from_handle);
	حرر(to_handle);

	إرجاع status == SSH2_FX_OK ? 0 : -1;
}

ساكن صحيح
crossload_dir_internal(بنية sftp_conn *from, بنية sftp_conn *to,
    ثابت حرف *from_path, ثابت حرف *to_path,
    صحيح depth, Attrib *dirattrib, صحيح preserve_flag, صحيح print_flag,
    صحيح follow_link_flag)
{
	صحيح i, ret = 0, created = 0;
	SFTP_DIRENT **dir_entries;
	حرف *filename, *new_from_path = عدم, *new_to_path = عدم;
	mode_t mode = 0777;
	Attrib *a, curdir, ldirattrib, newdir, lsym;

	debug2_f("crossload dir src \"%s\" to dst \"%s\"", from_path, to_path);

	إذا (depth >= MAX_DIR_DEPTH) {
		error("Maximum directory depth exceeded: %d levels", depth);
		إرجاع -1;
	}

	إذا (dirattrib == عدم) {
		إذا (sftp_stat(from, from_path, 1, &ldirattrib) != 0) {
			error("stat remote \"%s\" failed", from_path);
			إرجاع -1;
		}
		dirattrib = &ldirattrib;
	}
	إذا (!S_ISDIR(dirattrib->perm)) {
		error("\"%s\" is not a directory", from_path);
		إرجاع -1;
	}
	إذا (print_flag && print_flag != SFTP_PROGRESS_ONLY)
		mprintf("Retrieving %s\n", from_path);

	curdir = *dirattrib; /* dirattrib will be clobbered */
	curdir.flags &= ~SSH2_FILEXFER_ATTR_SIZE;
	curdir.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	إذا ((curdir.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) == 0) {
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
	إذا (sftp_mkdir(to, to_path, &curdir, 0) == 0)
		created = 1;
	وإلا {
		إذا (sftp_stat(to, to_path, 0, &newdir) != 0)
			إرجاع -1;
		إذا (!S_ISDIR(newdir.perm)) {
			error("\"%s\" exists but is not a directory", to_path);
			إرجاع -1;
		}
	}
	curdir.perm = mode;

	إذا (sftp_readdir(from, from_path, &dir_entries) == -1) {
		error("origin readdir \"%s\" failed", from_path);
		إرجاع -1;
	}

	لكل (i = 0; dir_entries[i] != عدم && !interrupted; i++) {
		حرر(new_from_path);
		حرر(new_to_path);

		filename = dir_entries[i]->filename;
		new_from_path = sftp_path_append(from_path, filename);
		new_to_path = sftp_path_append(to_path, filename);

		a = &dir_entries[i]->a;
		إذا (S_ISLNK(a->perm)) {
			إذا (!follow_link_flag) {
				logit("%s: not a regular file", filename);
				استمر;
			}
			/* Replace the stat contents with the symlink target */
			إذا (sftp_stat(from, new_from_path, 1, &lsym) != 0) {
				logit("remote stat \"%s\" failed",
				    new_from_path);
				ret = -1;
				استمر;
			}
			a = &lsym;
		}
		إذا (S_ISDIR(a->perm)) {
			إذا (strcmp(filename, ".") == 0 ||
			    strcmp(filename, "..") == 0)
				استمر;
			إذا (crossload_dir_internal(from, to,
			    new_from_path, new_to_path,
			    depth + 1, a, preserve_flag,
			    print_flag, follow_link_flag) == -1)
				ret = -1;
		} وإلا إذا (S_ISREG(a->perm)) {
			إذا (sftp_crossload(from, to, new_from_path,
			    new_to_path, a, preserve_flag) == -1) {
				error("crossload \"%s\" to \"%s\" failed",
				    new_from_path, new_to_path);
				ret = -1;
			}
		} وإلا {
			logit("origin \"%s\": not a regular file",
			    new_from_path);
		}
	}
	حرر(new_to_path);
	حرر(new_from_path);

	إذا (created || preserve_flag)
		sftp_setstat(to, to_path, &curdir);

	sftp_free_dirents(dir_entries);

	إرجاع ret;
}

صحيح
sftp_crossload_dir(بنية sftp_conn *from, بنية sftp_conn *to,
    ثابت حرف *from_path, ثابت حرف *to_path,
    Attrib *dirattrib, صحيح preserve_flag, صحيح print_flag, صحيح follow_link_flag)
{
	حرف *from_path_canon;
	صحيح ret;

	إذا ((from_path_canon = sftp_realpath(from, from_path)) == عدم) {
		error("crossload \"%s\": path canonicalization failed",
		    from_path);
		إرجاع -1;
	}

	ret = crossload_dir_internal(from, to, from_path_canon, to_path, 0,
	    dirattrib, preserve_flag, print_flag, follow_link_flag);
	حرر(from_path_canon);
	إرجاع ret;
}

صحيح
sftp_can_get_users_groups_by_id(بنية sftp_conn *conn)
{
	إرجاع (conn->exts & SFTP_EXT_GETUSERSGROUPS_BY_ID) != 0;
}

صحيح
sftp_get_users_groups_by_id(بنية sftp_conn *conn,
    ثابت u_int *uids, u_int nuids,
    ثابت u_int *gids, u_int ngids,
    حرف ***usernamesp, حرف ***groupnamesp)
{
	بنية sshbuf *رسالة, *uidbuf, *gidbuf;
	u_int i, expected_id, id;
	حرف *name, **usernames = عدم, **groupnames = عدم;
	u_char type;
	صحيح r;

	*usernamesp = *groupnamesp = عدم;
	إذا (!sftp_can_get_users_groups_by_id(conn))
		إرجاع SSH_ERR_FEATURE_UNSUPPORTED;

	إذا ((رسالة = sshbuf_new()) == عدم ||
	    (uidbuf = sshbuf_new()) == عدم ||
	    (gidbuf = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	expected_id = id = conn->رسالة_id++;
	debug2("Sending SSH2_FXP_EXTENDED(users-groups-by-id@openssh.com)");
	لكل (i = 0; i < nuids; i++) {
		إذا ((r = sshbuf_put_u32(uidbuf, uids[i])) != 0)
			fatal_fr(r, "compose uids");
	}
	لكل (i = 0; i < ngids; i++) {
		إذا ((r = sshbuf_put_u32(gidbuf, gids[i])) != 0)
			fatal_fr(r, "compose gids");
	}
	إذا ((r = sshbuf_put_u8(رسالة, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(رسالة, id)) != 0 ||
	    (r = sshbuf_put_cstring(رسالة,
	    "users-groups-by-id@openssh.com")) != 0 ||
	    (r = sshbuf_put_stringb(رسالة, uidbuf)) != 0 ||
	    (r = sshbuf_put_stringb(رسالة, gidbuf)) != 0)
		fatal_fr(r, "compose");
	send_رسالة(conn, رسالة);
	get_رسالة(conn, رسالة);
	إذا ((r = sshbuf_get_u8(رسالة, &type)) != 0 ||
	    (r = sshbuf_get_u32(رسالة, &id)) != 0)
		fatal_fr(r, "parse");
	إذا (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	إذا (type == SSH2_FXP_STATUS) {
		u_int status;
		حرف *errmsg;

		إذا ((r = sshbuf_get_u32(رسالة, &status)) != 0 ||
		    (r = sshbuf_get_cstring(رسالة, &errmsg, عدم)) != 0)
			fatal_fr(r, "parse status");
		error("users-groups-by-id %s",
		    *errmsg == '\0' ? fx2txt(status) : errmsg);
		حرر(errmsg);
		sshbuf_free(رسالة);
		sshbuf_free(uidbuf);
		sshbuf_free(gidbuf);
		إرجاع -1;
	} وإلا إذا (type != SSH2_FXP_EXTENDED_REPLY)
		fatal("Expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_REPLY, type);

	/* reuse */
	sshbuf_free(uidbuf);
	sshbuf_free(gidbuf);
	uidbuf = gidbuf = عدم;
	إذا ((r = sshbuf_froms(رسالة, &uidbuf)) != 0 ||
	    (r = sshbuf_froms(رسالة, &gidbuf)) != 0)
		fatal_fr(r, "parse response");
	إذا (nuids > 0) {
		usernames = xcalloc(nuids, حجم(*usernames));
		لكل (i = 0; i < nuids; i++) {
			إذا ((r = sshbuf_get_cstring(uidbuf, &name, عدم)) != 0)
				fatal_fr(r, "parse user name");
			/* Handle unresolved names */
			إذا (*name == '\0') {
				حرر(name);
				name = عدم;
			}
			usernames[i] = name;
		}
	}
	إذا (ngids > 0) {
		groupnames = xcalloc(ngids, حجم(*groupnames));
		لكل (i = 0; i < ngids; i++) {
			إذا ((r = sshbuf_get_cstring(gidbuf, &name, عدم)) != 0)
				fatal_fr(r, "parse user name");
			/* Handle unresolved names */
			إذا (*name == '\0') {
				حرر(name);
				name = عدم;
			}
			groupnames[i] = name;
		}
	}
	إذا (sshbuf_len(uidbuf) != 0)
		fatal_f("unexpected extra username data");
	إذا (sshbuf_len(gidbuf) != 0)
		fatal_f("unexpected extra groupname data");
	sshbuf_free(uidbuf);
	sshbuf_free(gidbuf);
	sshbuf_free(رسالة);
	/* success */
	*usernamesp = usernames;
	*groupnamesp = groupnames;
	إرجاع 0;
}

حرف *
sftp_path_append(ثابت حرف *p1, ثابت حرف *p2)
{
	حرف *ret;
	size_t len = strlen(p1) + strlen(p2) + 2;

	ret = xmalloc(len);
	strlcpy(ret, p1, len);
	إذا (p1[0] != '\0' && p1[strlen(p1) - 1] != '/')
		strlcat(ret, "/", len);
	strlcat(ret, p2, len);

	إرجاع(ret);
}

/*
 * Arg p must be dynamically allocated.  It will either be returned or
 * freed and a replacement allocated.  Caller must free returned string.
 */
حرف *
sftp_make_absolute(حرف *p, ثابت حرف *pwd)
{
	حرف *abs_str;

	/* Derelativise */
	إذا (p && !path_absolute(p)) {
		abs_str = sftp_path_append(pwd, p);
		حرر(p);
		إرجاع(abs_str);
	} وإلا
		إرجاع(p);
}

صحيح
sftp_remote_is_dir(بنية sftp_conn *conn, ثابت حرف *path)
{
	Attrib a;

	/* XXX: report errors? */
	إذا (sftp_stat(conn, path, 1, &a) != 0)
		إرجاع(0);
	إذا (!(a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS))
		إرجاع(0);
	إرجاع S_ISDIR(a.perm);
}


/* Check whether path returned from glob(..., GLOB_MARK, ...) is a directory */
صحيح
sftp_globpath_is_dir(ثابت حرف *pathname)
{
	size_t l = strlen(pathname);

	إرجاع l > 0 && pathname[l - 1] == '/';
}

