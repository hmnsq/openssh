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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/queue.h>
#شامل <sys/stat.h>
#شامل <sys/time.h>
#شامل <sys/statvfs.h>
#شامل <sys/uio.h>

#شامل <dirent.h>
#شامل <errno.h>
#شامل <fcntl.h>
#شامل <poll.h>
#شامل <signal.h>
#شامل <stdarg.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <unistd.h>

#شامل "xmalloc.h"
#شامل "ssherr.h"
#شامل "sshbuf.h"
#شامل "log.h"
#شامل "atomicio.h"
#شامل "progressmeter.h"
#شامل "misc.h"
#شامل "utf8.h"

#شامل "sftp.h"
#شامل "sftp-common.h"
#شامل "sftp-client.h"

بیرونی فرار sig_atomic_t interrupted;
بیرونی صحیح showprogress;

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
#وگرنه /* HAVE_CYGWIN */
# define SFTP_DIRECTORY_CHARS      "/"
#endif /* HAVE_CYGWIN */

ساختار sftp_conn {
	صحیح fd_in;
	صحیح fd_out;
	u_int download_buflen;
	u_int upload_buflen;
	u_int رقم_requests;
	u_int version;
	u_int پیام_id;
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
	ساختار bwlimit bwlimit_in, bwlimit_out;
};

/* Tracks in-progress requests during file transfers */
ساختار request {
	u_int id;
	size_t len;
	uint64_t offset;
	TAILQ_ENTRY(request) tq;
};
TAILQ_HEAD(requests, request);

ایستا u_char *
get_handle(ساختار sftp_conn *conn, u_int expected_id, size_t *len,
    ثابت نویسه *errfmt, ...) __attribute__((format(printf, 4, 5)));

ایستا ساختار request *
request_enqueue(ساختار requests *requests, u_int id, size_t len,
    uint64_t offset)
{
	ساختار request *req;

	req = xcalloc(1, اندازه(*req));
	req->id = id;
	req->len = len;
	req->offset = offset;
	TAILQ_INSERT_TAIL(requests, req, tq);
	بازگشت req;
}

ایستا ساختار request *
request_find(ساختار requests *requests, u_int id)
{
	ساختار request *req;

	برای (req = TAILQ_FIRST(requests);
	    req != پوچ && req->id != id;
	    req = TAILQ_NEXT(req, tq))
		;
	بازگشت req;
}

ایستا صحیح
sftpio(تهی *_bwlimit, size_t amount)
{
	ساختار bwlimit *bwlimit = (ساختار bwlimit *)_bwlimit;

	refresh_progress_meter(0);
	اگر (bwlimit != پوچ)
		bandwidth_limit(bwlimit, amount);
	بازگشت 0;
}

ایستا تهی
send_پیام(ساختار sftp_conn *conn, ساختار sshbuf *m)
{
	u_char mlen[4];
	ساختار iovec iov[2];

	اگر (sshbuf_len(m) > SFTP_MAX_پیام_LENGTH)
		fatal("Outbound message too long %zu", sshbuf_len(m));

	/* Send length first */
	put_u32(mlen, sshbuf_len(m));
	iov[0].iov_base = mlen;
	iov[0].iov_len = اندازه(mlen);
	iov[1].iov_base = (u_char *)sshbuf_ptr(m);
	iov[1].iov_len = sshbuf_len(m);

	اگر (atomiciov6(writev, conn->fd_out, iov, 2, sftpio,
	    conn->limit_kbps > 0 ? &conn->bwlimit_out : پوچ) !=
	    sshbuf_len(m) + اندازه(mlen))
		fatal("Couldn't send packet: %s", strerror(errno));

	sshbuf_reset(m);
}

ایستا تهی
get_پیام_extended(ساختار sftp_conn *conn, ساختار sshbuf *m, صحیح initial)
{
	u_int پیام_len;
	u_char *p;
	صحیح r;

	sshbuf_reset(m);
	اگر ((r = sshbuf_reserve(m, 4, &p)) != 0)
		fatal_fr(r, "reserve");
	اگر (atomicio6(اقرأ, conn->fd_in, p, 4, sftpio,
	    conn->limit_kbps > 0 ? &conn->bwlimit_in : پوچ) != 4) {
		اگر (errno == EPIPE || errno == ECONNRESET)
			fatal("Connection closed");
		وگرنه
			fatal("Couldn't read packet: %s", strerror(errno));
	}

	اگر ((r = sshbuf_get_u32(m, &پیام_len)) != 0)
		fatal_fr(r, "sshbuf_get_u32");
	اگر (پیام_len > SFTP_MAX_پیام_LENGTH) {
		do_log2(initial ? SYSLOG_LEVEL_ERROR : SYSLOG_LEVEL_FATAL,
		    "Received message too long %u", پیام_len);
		fatal("Ensure the remote shell produces no output "
		    "for non-interactive sessions.");
	}

	اگر ((r = sshbuf_reserve(m, پیام_len, &p)) != 0)
		fatal_fr(r, "reserve");
	اگر (atomicio6(اقرأ, conn->fd_in, p, پیام_len, sftpio,
	    conn->limit_kbps > 0 ? &conn->bwlimit_in : پوچ)
	    != پیام_len) {
		اگر (errno == EPIPE)
			fatal("Connection closed");
		وگرنه
			fatal("Read packet: %s", strerror(errno));
	}
}

ایستا تهی
get_پیام(ساختار sftp_conn *conn, ساختار sshbuf *m)
{
	get_پیام_extended(conn, m, 0);
}

ایستا تهی
send_string_request(ساختار sftp_conn *conn, u_int id, u_int code, ثابت نویسه *s,
    u_int len)
{
	ساختار sshbuf *پیام;
	صحیح r;

	اگر ((پیام = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_u8(پیام, code)) != 0 ||
	    (r = sshbuf_put_u32(پیام, id)) != 0 ||
	    (r = sshbuf_put_string(پیام, s, len)) != 0)
		fatal_fr(r, "compose");
	send_پیام(conn, پیام);
	debug3("Sent message fd %d T:%u I:%u", conn->fd_out, code, id);
	sshbuf_free(پیام);
}

ایستا تهی
send_string_attrs_request(ساختار sftp_conn *conn, u_int id, u_int code,
    ثابت تهی *s, u_int len, Attrib *a)
{
	ساختار sshbuf *پیام;
	صحیح r;

	اگر ((پیام = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_u8(پیام, code)) != 0 ||
	    (r = sshbuf_put_u32(پیام, id)) != 0 ||
	    (r = sshbuf_put_string(پیام, s, len)) != 0 ||
	    (r = encode_attrib(پیام, a)) != 0)
		fatal_fr(r, "compose");
	send_پیام(conn, پیام);
	debug3("Sent message fd %d T:%u I:%u F:0x%04x M:%05o",
	    conn->fd_out, code, id, a->flags, a->perm);
	sshbuf_free(پیام);
}

ایستا u_int
get_status(ساختار sftp_conn *conn, u_int expected_id)
{
	ساختار sshbuf *پیام;
	u_char type;
	u_int id, status;
	صحیح r;

	اگر ((پیام = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	get_پیام(conn, پیام);
	اگر ((r = sshbuf_get_u8(پیام, &type)) != 0 ||
	    (r = sshbuf_get_u32(پیام, &id)) != 0)
		fatal_fr(r, "compose");

	اگر (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	اگر (type != SSH2_FXP_STATUS)
		fatal("Expected SSH2_FXP_STATUS(%u) packet, got %u",
		    SSH2_FXP_STATUS, type);

	اگر ((r = sshbuf_get_u32(پیام, &status)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(پیام);

	debug3("SSH2_FXP_STATUS %u", status);

	بازگشت status;
}

ایستا u_char *
get_handle(ساختار sftp_conn *conn, u_int expected_id, size_t *len,
    ثابت نویسه *errfmt, ...)
{
	ساختار sshbuf *پیام;
	u_int id, status;
	u_char type;
	u_char *handle;
	نویسه errmsg[256];
	va_list args;
	صحیح r;

	va_start(args, errfmt);
	اگر (errfmt != پوچ)
		vsnprintf(errmsg, اندازه(errmsg), errfmt, args);
	va_end(args);

	اگر ((پیام = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	get_پیام(conn, پیام);
	اگر ((r = sshbuf_get_u8(پیام, &type)) != 0 ||
	    (r = sshbuf_get_u32(پیام, &id)) != 0)
		fatal_fr(r, "parse");

	اگر (id != expected_id)
		fatal("%s: ID mismatch (%u != %u)",
		    errfmt == پوچ ? __func__ : errmsg, id, expected_id);
	اگر (type == SSH2_FXP_STATUS) {
		اگر ((r = sshbuf_get_u32(پیام, &status)) != 0)
			fatal_fr(r, "parse status");
		اگر (errfmt != پوچ)
			error("%s: %s", errmsg, fx2txt(status));
		sshbuf_free(پیام);
		بازگشت(پوچ);
	} وگرنه اگر (type != SSH2_FXP_HANDLE)
		fatal("%s: Expected SSH2_FXP_HANDLE(%u) packet, got %u",
		    errfmt == پوچ ? __func__ : errmsg, SSH2_FXP_HANDLE, type);

	اگر ((r = sshbuf_get_string(پیام, &handle, len)) != 0)
		fatal_fr(r, "parse handle");
	sshbuf_free(پیام);

	بازگشت handle;
}

ایستا صحیح
get_decode_stat(ساختار sftp_conn *conn, u_int expected_id, صحیح quiet, Attrib *a)
{
	ساختار sshbuf *پیام;
	u_int id;
	u_char type;
	صحیح r;
	Attrib attr;

	اگر (a != پوچ)
		memset(a, '\0', اندازه(*a));
	اگر ((پیام = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	get_پیام(conn, پیام);

	اگر ((r = sshbuf_get_u8(پیام, &type)) != 0 ||
	    (r = sshbuf_get_u32(پیام, &id)) != 0)
		fatal_fr(r, "parse");

	اگر (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	اگر (type == SSH2_FXP_STATUS) {
		u_int status;

		اگر ((r = sshbuf_get_u32(پیام, &status)) != 0)
			fatal_fr(r, "parse status");
		اگر (quiet)
			debug("stat remote: %s", fx2txt(status));
		وگرنه
			error("stat remote: %s", fx2txt(status));
		sshbuf_free(پیام);
		بازگشت -1;
	} وگرنه اگر (type != SSH2_FXP_ATTRS) {
		fatal("Expected SSH2_FXP_ATTRS(%u) packet, got %u",
		    SSH2_FXP_ATTRS, type);
	}
	اگر ((r = decode_attrib(پیام, &attr)) != 0) {
		error_fr(r, "decode_attrib");
		sshbuf_free(پیام);
		بازگشت -1;
	}
	/* success */
	اگر (a != پوچ)
		*a = attr;
	debug3("Received stat reply T:%u I:%u F:0x%04x M:%05o",
	    type, id, attr.flags, attr.perm);
	sshbuf_free(پیام);

	بازگشت 0;
}

ایستا صحیح
get_decode_statvfs(ساختار sftp_conn *conn, ساختار sftp_statvfs *st,
    u_int expected_id, صحیح quiet)
{
	ساختار sshbuf *پیام;
	u_char type;
	u_int id;
	uint64_t flag;
	صحیح r;

	اگر ((پیام = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	get_پیام(conn, پیام);

	اگر ((r = sshbuf_get_u8(پیام, &type)) != 0 ||
	    (r = sshbuf_get_u32(پیام, &id)) != 0)
		fatal_fr(r, "parse");

	debug3("Received statvfs reply T:%u I:%u", type, id);
	اگر (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	اگر (type == SSH2_FXP_STATUS) {
		u_int status;

		اگر ((r = sshbuf_get_u32(پیام, &status)) != 0)
			fatal_fr(r, "parse status");
		اگر (quiet)
			debug("remote statvfs: %s", fx2txt(status));
		وگرنه
			error("remote statvfs: %s", fx2txt(status));
		sshbuf_free(پیام);
		بازگشت -1;
	} وگرنه اگر (type != SSH2_FXP_EXTENDED_REPLY) {
		fatal("Expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_REPLY, type);
	}

	memset(st, 0, اندازه(*st));
	اگر ((r = sshbuf_get_u64(پیام, &st->f_bsize)) != 0 ||
	    (r = sshbuf_get_u64(پیام, &st->f_frsize)) != 0 ||
	    (r = sshbuf_get_u64(پیام, &st->f_blocks)) != 0 ||
	    (r = sshbuf_get_u64(پیام, &st->f_bfree)) != 0 ||
	    (r = sshbuf_get_u64(پیام, &st->f_bavail)) != 0 ||
	    (r = sshbuf_get_u64(پیام, &st->f_files)) != 0 ||
	    (r = sshbuf_get_u64(پیام, &st->f_ffree)) != 0 ||
	    (r = sshbuf_get_u64(پیام, &st->f_favail)) != 0 ||
	    (r = sshbuf_get_u64(پیام, &st->f_fsid)) != 0 ||
	    (r = sshbuf_get_u64(پیام, &flag)) != 0 ||
	    (r = sshbuf_get_u64(پیام, &st->f_namemax)) != 0)
		fatal_fr(r, "parse statvfs");

	st->f_flag = (flag & SSH2_FXE_STATVFS_ST_RDONLY) ? ST_RDONLY : 0;
	st->f_flag |= (flag & SSH2_FXE_STATVFS_ST_NOSUID) ? ST_NOSUID : 0;

	sshbuf_free(پیام);

	بازگشت 0;
}

ساختار sftp_conn *
sftp_init(صحیح fd_in, صحیح fd_out, u_int transfer_buflen, u_int رقم_requests,
    uint64_t limit_kbps)
{
	u_char type;
	ساختار sshbuf *پیام;
	ساختار sftp_conn *ret;
	صحیح r;

	ret = xcalloc(1, اندازه(*ret));
	ret->پیام_id = 1;
	ret->fd_in = fd_in;
	ret->fd_out = fd_out;
	ret->download_buflen = ret->upload_buflen =
	    transfer_buflen ? transfer_buflen : DEFAULT_COPY_BUFLEN;
	ret->رقم_requests =
	    رقم_requests ? رقم_requests : DEFAULT_رقم_REQUESTS;
	ret->exts = 0;
	ret->limit_kbps = 0;

	اگر ((پیام = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_u8(پیام, SSH2_FXP_INIT)) != 0 ||
	    (r = sshbuf_put_u32(پیام, SSH2_FILEXFER_VERSION)) != 0)
		fatal_fr(r, "parse");

	send_پیام(ret, پیام);

	get_پیام_extended(ret, پیام, 1);

	/* Expecting a VERSION reply */
	اگر ((r = sshbuf_get_u8(پیام, &type)) != 0)
		fatal_fr(r, "parse type");
	اگر (type != SSH2_FXP_VERSION) {
		error("Invalid packet back from SSH2_FXP_INIT (type %u)",
		    type);
		sshbuf_free(پیام);
		آزاد(ret);
		بازگشت(پوچ);
	}
	اگر ((r = sshbuf_get_u32(پیام, &ret->version)) != 0)
		fatal_fr(r, "parse version");

	debug2("Remote version: %u", ret->version);

	/* Check for extensions */
	وقتی (sshbuf_len(پیام) > 0) {
		نویسه *name;
		u_char *مقدار;
		size_t vlen;
		صحیح known = 0;

		اگر ((r = sshbuf_get_cstring(پیام, &name, پوچ)) != 0 ||
		    (r = sshbuf_get_string(پیام, &مقدار, &vlen)) != 0)
			fatal_fr(r, "parse extension");
		اگر (strcmp(name, "posix-rename@openssh.com") == 0 &&
		    strcmp((نویسه *)مقدار, "1") == 0) {
			ret->exts |= SFTP_EXT_POSIX_RENAME;
			known = 1;
		} وگرنه اگر (strcmp(name, "statvfs@openssh.com") == 0 &&
		    strcmp((نویسه *)مقدار, "2") == 0) {
			ret->exts |= SFTP_EXT_STATVFS;
			known = 1;
		} وگرنه اگر (strcmp(name, "fstatvfs@openssh.com") == 0 &&
		    strcmp((نویسه *)مقدار, "2") == 0) {
			ret->exts |= SFTP_EXT_FSTATVFS;
			known = 1;
		} وگرنه اگر (strcmp(name, "hardlink@openssh.com") == 0 &&
		    strcmp((نویسه *)مقدار, "1") == 0) {
			ret->exts |= SFTP_EXT_HARDLINK;
			known = 1;
		} وگرنه اگر (strcmp(name, "fsync@openssh.com") == 0 &&
		    strcmp((نویسه *)مقدار, "1") == 0) {
			ret->exts |= SFTP_EXT_FSYNC;
			known = 1;
		} وگرنه اگر (strcmp(name, "lsetstat@openssh.com") == 0 &&
		    strcmp((نویسه *)مقدار, "1") == 0) {
			ret->exts |= SFTP_EXT_LSETSTAT;
			known = 1;
		} وگرنه اگر (strcmp(name, "limits@openssh.com") == 0 &&
		    strcmp((نویسه *)مقدار, "1") == 0) {
			ret->exts |= SFTP_EXT_LIMITS;
			known = 1;
		} وگرنه اگر (strcmp(name, "expand-path@openssh.com") == 0 &&
		    strcmp((نویسه *)مقدار, "1") == 0) {
			ret->exts |= SFTP_EXT_PATH_EXPAND;
			known = 1;
		} وگرنه اگر (strcmp(name, "copy-data") == 0 &&
		    strcmp((نویسه *)مقدار, "1") == 0) {
			ret->exts |= SFTP_EXT_COPY_DATA;
			known = 1;
		} وگرنه اگر (strcmp(name,
		    "users-groups-by-id@openssh.com") == 0 &&
		    strcmp((نویسه *)مقدار, "1") == 0) {
			ret->exts |= SFTP_EXT_GETUSERSGROUPS_BY_ID;
			known = 1;
		}
		اگر (known) {
			debug2("Server supports extension \"%s\" revision %s",
			    name, مقدار);
		} وگرنه {
			debug2("Unrecognised server extension \"%s\"", name);
		}
		آزاد(name);
		آزاد(مقدار);
	}

	sshbuf_free(پیام);

	/* Query the server for its limits */
	اگر (ret->exts & SFTP_EXT_LIMITS) {
		ساختار sftp_limits limits;
		اگر (sftp_get_limits(ret, &limits) != 0)
			fatal_f("limits failed");

		/* If the caller did not specify, find a good value */
		اگر (transfer_buflen == 0) {
			ret->download_buflen = MINIMUM(limits.read_length,
			    SFTP_MAX_پیام_LENGTH - 1024);
			ret->upload_buflen = MINIMUM(limits.write_length,
			    SFTP_MAX_پیام_LENGTH - 1024);
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
	اگر (ret->version == 0) {
		ret->download_buflen = MINIMUM(ret->download_buflen, 20480);
		ret->upload_buflen = MINIMUM(ret->upload_buflen, 20480);
	}

	ret->limit_kbps = limit_kbps;
	اگر (ret->limit_kbps > 0) {
		bandwidth_limit_init(&ret->bwlimit_in, ret->limit_kbps,
		    ret->download_buflen);
		bandwidth_limit_init(&ret->bwlimit_out, ret->limit_kbps,
		    ret->upload_buflen);
	}

	بازگشت ret;
}

تهی
sftp_free(ساختار sftp_conn *conn)
{
	اگر (conn == پوچ)
		بازگشت;
	freezero(conn, اندازه(*conn));
}

u_int
sftp_proto_version(ساختار sftp_conn *conn)
{
	بازگشت conn->version;
}

صحیح
sftp_get_limits(ساختار sftp_conn *conn, ساختار sftp_limits *limits)
{
	u_int id, پیام_id;
	u_char type;
	ساختار sshbuf *پیام;
	صحیح r;

	اگر ((conn->exts & SFTP_EXT_LIMITS) == 0) {
		error("Server does not support limits@openssh.com extension");
		بازگشت -1;
	}

	اگر ((پیام = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");

	id = conn->پیام_id++;
	اگر ((r = sshbuf_put_u8(پیام, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(پیام, id)) != 0 ||
	    (r = sshbuf_put_cstring(پیام, "limits@openssh.com")) != 0)
		fatal_fr(r, "compose");
	send_پیام(conn, پیام);
	debug3("Sent message limits@openssh.com I:%u", id);

	get_پیام(conn, پیام);

	اگر ((r = sshbuf_get_u8(پیام, &type)) != 0 ||
	    (r = sshbuf_get_u32(پیام, &پیام_id)) != 0)
		fatal_fr(r, "parse");

	debug3("Received limits reply T:%u I:%u", type, پیام_id);
	اگر (id != پیام_id)
		fatal("ID mismatch (%u != %u)", پیام_id, id);
	اگر (type != SSH2_FXP_EXTENDED_REPLY) {
		debug_f("expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_REPLY, type);
		/* Disable the limits extension */
		conn->exts &= ~SFTP_EXT_LIMITS;
		sshbuf_free(پیام);
		بازگشت -1;
	}

	memset(limits, 0, اندازه(*limits));
	اگر ((r = sshbuf_get_u64(پیام, &limits->packet_length)) != 0 ||
	    (r = sshbuf_get_u64(پیام, &limits->read_length)) != 0 ||
	    (r = sshbuf_get_u64(پیام, &limits->write_length)) != 0 ||
	    (r = sshbuf_get_u64(پیام, &limits->open_handles)) != 0)
		fatal_fr(r, "parse limits");

	sshbuf_free(پیام);

	بازگشت 0;
}

صحیح
sftp_close(ساختار sftp_conn *conn, ثابت u_char *handle, u_int handle_len)
{
	u_int id, status;
	ساختار sshbuf *پیام;
	صحیح r;

	اگر ((پیام = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");

	id = conn->پیام_id++;
	اگر ((r = sshbuf_put_u8(پیام, SSH2_FXP_CLOSE)) != 0 ||
	    (r = sshbuf_put_u32(پیام, id)) != 0 ||
	    (r = sshbuf_put_string(پیام, handle, handle_len)) != 0)
		fatal_fr(r, "parse");
	send_پیام(conn, پیام);
	debug3("Sent message SSH2_FXP_CLOSE I:%u", id);

	status = get_status(conn, id);
	اگر (status != SSH2_FX_OK)
		error("close remote: %s", fx2txt(status));

	sshbuf_free(پیام);

	بازگشت status == SSH2_FX_OK ? 0 : -1;
}


ایستا صحیح
sftp_lsreaddir(ساختار sftp_conn *conn, ثابت نویسه *path, صحیح print_flag,
    SFTP_DIRENT ***dir)
{
	ساختار sshbuf *پیام;
	u_int شمار, id, i, expected_id, ents = 0;
	size_t handle_len;
	u_char type, *handle;
	صحیح status = SSH2_FX_FAILURE;
	صحیح r;

	اگر (dir)
		*dir = پوچ;

	id = conn->پیام_id++;

	اگر ((پیام = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_u8(پیام, SSH2_FXP_OPENDIR)) != 0 ||
	    (r = sshbuf_put_u32(پیام, id)) != 0 ||
	    (r = sshbuf_put_cstring(پیام, path)) != 0)
		fatal_fr(r, "compose OPENDIR");
	send_پیام(conn, پیام);

	handle = get_handle(conn, id, &handle_len,
	    "remote readdir(\"%s\")", path);
	اگر (handle == پوچ) {
		sshbuf_free(پیام);
		بازگشت -1;
	}

	اگر (dir) {
		ents = 0;
		*dir = xcalloc(1, اندازه(**dir));
		(*dir)[0] = پوچ;
	}

	برای (; !interrupted;) {
		id = expected_id = conn->پیام_id++;

		debug3("Sending SSH2_FXP_READDIR I:%u", id);

		sshbuf_reset(پیام);
		اگر ((r = sshbuf_put_u8(پیام, SSH2_FXP_READDIR)) != 0 ||
		    (r = sshbuf_put_u32(پیام, id)) != 0 ||
		    (r = sshbuf_put_string(پیام, handle, handle_len)) != 0)
			fatal_fr(r, "compose READDIR");
		send_پیام(conn, پیام);

		sshbuf_reset(پیام);

		get_پیام(conn, پیام);

		اگر ((r = sshbuf_get_u8(پیام, &type)) != 0 ||
		    (r = sshbuf_get_u32(پیام, &id)) != 0)
			fatal_fr(r, "parse");

		debug3("Received reply T:%u I:%u", type, id);

		اگر (id != expected_id)
			fatal("ID mismatch (%u != %u)", id, expected_id);

		اگر (type == SSH2_FXP_STATUS) {
			u_int rstatus;

			اگر ((r = sshbuf_get_u32(پیام, &rstatus)) != 0)
				fatal_fr(r, "parse status");
			debug3("Received SSH2_FXP_STATUS %d", rstatus);
			اگر (rstatus == SSH2_FX_EOF)
				بشکن;
			error("Couldn't read directory: %s", fx2txt(rstatus));
			برو out;
		} وگرنه اگر (type != SSH2_FXP_NAME)
			fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
			    SSH2_FXP_NAME, type);

		اگر ((r = sshbuf_get_u32(پیام, &شمار)) != 0)
			fatal_fr(r, "parse count");
		اگر (شمار > SSHBUF_SIZE_MAX)
			fatal_f("nonsensical number of entries");
		اگر (شمار == 0)
			بشکن;
		debug3("Received %d SSH2_FXP_NAME responses", شمار);
		برای (i = 0; i < شمار; i++) {
			نویسه *filename, *longname;
			Attrib a;

			اگر ((r = sshbuf_get_cstring(پیام, &filename,
			    پوچ)) != 0 ||
			    (r = sshbuf_get_cstring(پیام, &longname,
			    پوچ)) != 0)
				fatal_fr(r, "parse filenames");
			اگر ((r = decode_attrib(پیام, &a)) != 0) {
				error_fr(r, "couldn't decode attrib");
				آزاد(filename);
				آزاد(longname);
				برو out;
			}

			اگر (print_flag)
				mprintf("%s\n", longname);

			/*
			 * Directory entries should never contain '/'
			 * These can be used to attack recursive ops
			 * (e.g. send '../../../../etc/passwd')
			 */
			اگر (*filename == '\0' ||
			    strpbrk(filename, SFTP_DIRECTORY_CHARS) != پوچ) {
				error("Server sent suspect path \"%s\" "
				    "during readdir of \"%s\"", filename, path);
			} وگرنه اگر (dir) {
				*dir = xreallocarray(*dir, ents + 2, اندازه(**dir));
				(*dir)[ents] = xcalloc(1, اندازه(***dir));
				(*dir)[ents]->filename = xstrdup(filename);
				(*dir)[ents]->longname = xstrdup(longname);
				memcpy(&(*dir)[ents]->a, &a, اندازه(a));
				(*dir)[++ents] = پوچ;
			}
			آزاد(filename);
			آزاد(longname);
		}
	}
	status = 0;

 out:
	sshbuf_free(پیام);
	sftp_close(conn, handle, handle_len);
	آزاد(handle);

	اگر (status != 0 && dir != پوچ) {
		/* Don't return results on error */
		sftp_free_dirents(*dir);
		*dir = پوچ;
	} وگرنه اگر (interrupted && dir != پوچ && *dir != پوچ) {
		/* Don't return partial matches on interrupt */
		sftp_free_dirents(*dir);
		*dir = xcalloc(1, اندازه(**dir));
		**dir = پوچ;
	}

	بازگشت status == SSH2_FX_OK ? 0 : -1;
}

صحیح
sftp_readdir(ساختار sftp_conn *conn, ثابت نویسه *path, SFTP_DIRENT ***dir)
{
	بازگشت sftp_lsreaddir(conn, path, 0, dir);
}

تهی sftp_free_dirents(SFTP_DIRENT **s)
{
	صحیح i;

	اگر (s == پوچ)
		بازگشت;
	برای (i = 0; s[i]; i++) {
		آزاد(s[i]->filename);
		آزاد(s[i]->longname);
		آزاد(s[i]);
	}
	آزاد(s);
}

صحیح
sftp_rm(ساختار sftp_conn *conn, ثابت نویسه *path)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_REMOVE \"%s\"", path);

	id = conn->پیام_id++;
	send_string_request(conn, id, SSH2_FXP_REMOVE, path, strlen(path));
	status = get_status(conn, id);
	اگر (status != SSH2_FX_OK)
		error("remote delete %s: %s", path, fx2txt(status));
	بازگشت status == SSH2_FX_OK ? 0 : -1;
}

صحیح
sftp_mkdir(ساختار sftp_conn *conn, ثابت نویسه *path, Attrib *a, صحیح print_flag)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_MKDIR \"%s\"", path);

	id = conn->پیام_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_MKDIR, path,
	    strlen(path), a);

	status = get_status(conn, id);
	اگر (status != SSH2_FX_OK && print_flag)
		error("remote mkdir \"%s\": %s", path, fx2txt(status));

	بازگشت status == SSH2_FX_OK ? 0 : -1;
}

صحیح
sftp_mkpath(ساختار sftp_conn *conn, ثابت نویسه *path, Attrib *a, صحیح print_flag)
{
	نویسه *slash, *tmp_path;
	صحیح done;

	tmp_path = xstrdup(path);
	slash = tmp_path;

	برای (;;) {
		slash += strspn(slash, "/");
		slash += strcspn(slash, "/");

		done = (*slash == '\0');
		*slash = '\0';

		اگر (!sftp_remote_is_dir(conn, tmp_path)) {
			اگر (sftp_mkdir(conn, tmp_path, a, print_flag) != 0) {
				آزاد(tmp_path);
				بازگشت -1;
			}
		}

		اگر (done)
			بشکن;

		*slash = '/';
	}

	آزاد(tmp_path);
	بازگشت 0;
}

صحیح
sftp_rmdir(ساختار sftp_conn *conn, ثابت نویسه *path)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_RMDIR \"%s\"", path);

	id = conn->پیام_id++;
	send_string_request(conn, id, SSH2_FXP_RMDIR, path,
	    strlen(path));

	status = get_status(conn, id);
	اگر (status != SSH2_FX_OK)
		error("remote rmdir \"%s\": %s", path, fx2txt(status));

	بازگشت status == SSH2_FX_OK ? 0 : -1;
}

صحیح
sftp_stat(ساختار sftp_conn *conn, ثابت نویسه *path, صحیح quiet, Attrib *a)
{
	u_int id;

	debug2("Sending SSH2_FXP_STAT \"%s\"", path);

	id = conn->پیام_id++;

	send_string_request(conn, id,
	    conn->version == 0 ? SSH2_FXP_STAT_VERSION_0 : SSH2_FXP_STAT,
	    path, strlen(path));

	بازگشت get_decode_stat(conn, id, quiet, a);
}

صحیح
sftp_lstat(ساختار sftp_conn *conn, ثابت نویسه *path, صحیح quiet, Attrib *a)
{
	u_int id;

	اگر (conn->version == 0) {
		do_log2(quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_INFO,
		    "Server version does not support lstat operation");
		بازگشت sftp_stat(conn, path, quiet, a);
	}

	id = conn->پیام_id++;
	send_string_request(conn, id, SSH2_FXP_LSTAT, path,
	    strlen(path));

	بازگشت get_decode_stat(conn, id, quiet, a);
}

#ifdef notyet
صحیح
sftp_fstat(ساختار sftp_conn *conn, ثابت u_char *handle, u_int handle_len,
    صحیح quiet, Attrib *a)
{
	u_int id;

	debug2("Sending SSH2_FXP_FSTAT \"%s\"");

	id = conn->پیام_id++;
	send_string_request(conn, id, SSH2_FXP_FSTAT, handle,
	    handle_len);

	بازگشت get_decode_stat(conn, id, quiet, a);
}
#endif

صحیح
sftp_setstat(ساختار sftp_conn *conn, ثابت نویسه *path, Attrib *a)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_SETSTAT \"%s\"", path);

	id = conn->پیام_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_SETSTAT, path,
	    strlen(path), a);

	status = get_status(conn, id);
	اگر (status != SSH2_FX_OK)
		error("remote setstat \"%s\": %s", path, fx2txt(status));

	بازگشت status == SSH2_FX_OK ? 0 : -1;
}

صحیح
sftp_fsetstat(ساختار sftp_conn *conn, ثابت u_char *handle, u_int handle_len,
    Attrib *a)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_FSETSTAT");

	id = conn->پیام_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_FSETSTAT, handle,
	    handle_len, a);

	status = get_status(conn, id);
	اگر (status != SSH2_FX_OK)
		error("remote fsetstat: %s", fx2txt(status));

	بازگشت status == SSH2_FX_OK ? 0 : -1;
}

/* Implements both the realpath and expand-path operations */
ایستا نویسه *
sftp_realpath_expand(ساختار sftp_conn *conn, ثابت نویسه *path, صحیح expand)
{
	ساختار sshbuf *پیام;
	u_int expected_id, شمار, id;
	نویسه *filename, *longname;
	Attrib a;
	u_char type;
	صحیح r;
	ثابت نویسه *what = "SSH2_FXP_REALPATH";

	اگر (expand)
		what = "expand-path@openssh.com";
	اگر ((پیام = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");

	expected_id = id = conn->پیام_id++;
	اگر (expand) {
		debug2("Sending SSH2_FXP_EXTENDED(expand-path@openssh.com) "
		    "\"%s\"", path);
		اگر ((r = sshbuf_put_u8(پیام, SSH2_FXP_EXTENDED)) != 0 ||
		    (r = sshbuf_put_u32(پیام, id)) != 0 ||
		    (r = sshbuf_put_cstring(پیام,
		    "expand-path@openssh.com")) != 0 ||
		    (r = sshbuf_put_cstring(پیام, path)) != 0)
			fatal_fr(r, "compose %s", what);
		send_پیام(conn, پیام);
	} وگرنه {
		debug2("Sending SSH2_FXP_REALPATH \"%s\"", path);
		send_string_request(conn, id, SSH2_FXP_REALPATH,
		    path, strlen(path));
	}
	get_پیام(conn, پیام);
	اگر ((r = sshbuf_get_u8(پیام, &type)) != 0 ||
	    (r = sshbuf_get_u32(پیام, &id)) != 0)
		fatal_fr(r, "parse");

	اگر (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);

	اگر (type == SSH2_FXP_STATUS) {
		u_int status;
		نویسه *errmsg;

		اگر ((r = sshbuf_get_u32(پیام, &status)) != 0 ||
		    (r = sshbuf_get_cstring(پیام, &errmsg, پوچ)) != 0)
			fatal_fr(r, "parse status");
		error("%s %s: %s", expand ? "expand" : "realpath",
		    path, *errmsg == '\0' ? fx2txt(status) : errmsg);
		آزاد(errmsg);
		sshbuf_free(پیام);
		بازگشت پوچ;
	} وگرنه اگر (type != SSH2_FXP_NAME)
		fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
		    SSH2_FXP_NAME, type);

	اگر ((r = sshbuf_get_u32(پیام, &شمار)) != 0)
		fatal_fr(r, "parse count");
	اگر (شمار != 1)
		fatal("Got multiple names (%d) from %s", شمار, what);

	اگر ((r = sshbuf_get_cstring(پیام, &filename, پوچ)) != 0 ||
	    (r = sshbuf_get_cstring(پیام, &longname, پوچ)) != 0 ||
	    (r = decode_attrib(پیام, &a)) != 0)
		fatal_fr(r, "parse filename/attrib");

	debug3("%s %s -> %s", what, path, filename);

	آزاد(longname);

	sshbuf_free(پیام);

	بازگشت(filename);
}

نویسه *
sftp_realpath(ساختار sftp_conn *conn, ثابت نویسه *path)
{
	بازگشت sftp_realpath_expand(conn, path, 0);
}

صحیح
sftp_can_expand_path(ساختار sftp_conn *conn)
{
	بازگشت (conn->exts & SFTP_EXT_PATH_EXPAND) != 0;
}

نویسه *
sftp_expand_path(ساختار sftp_conn *conn, ثابت نویسه *path)
{
	اگر (!sftp_can_expand_path(conn)) {
		debug3_f("no server support, fallback to realpath");
		بازگشت sftp_realpath_expand(conn, path, 0);
	}
	بازگشت sftp_realpath_expand(conn, path, 1);
}

صحیح
sftp_copy(ساختار sftp_conn *conn, ثابت نویسه *oldpath, ثابت نویسه *newpath)
{
	Attrib junk, attr;
	ساختار sshbuf *پیام;
	u_char *old_handle, *new_handle;
	u_int mode, status, id;
	size_t old_handle_len, new_handle_len;
	صحیح r;

	/* Return if the extension is not supported */
	اگر ((conn->exts & SFTP_EXT_COPY_DATA) == 0) {
		error("Server does not support copy-data extension");
		بازگشت -1;
	}

	/* Make sure the file exists, and we can copy its perms */
	اگر (sftp_stat(conn, oldpath, 0, &attr) != 0)
		بازگشت -1;

	/* Do not preserve set[ug]id here, as we do not preserve ownership */
	اگر (attr.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		mode = attr.perm & 0777;

		اگر (!S_ISREG(attr.perm)) {
			error("Cannot copy non-regular file: %s", oldpath);
			بازگشت -1;
		}
	} وگرنه {
		/* NB: The user's umask will apply to this */
		mode = 0666;
	}

	/* Set up the new perms for the new file */
	attrib_clear(&attr);
	attr.perm = mode;
	attr.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;

	اگر ((پیام = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");

	attrib_clear(&junk); /* Send empty attributes */

	/* Open the old file for reading */
	id = conn->پیام_id++;
	اگر ((r = sshbuf_put_u8(پیام, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(پیام, id)) != 0 ||
	    (r = sshbuf_put_cstring(پیام, oldpath)) != 0 ||
	    (r = sshbuf_put_u32(پیام, SSH2_FXF_READ)) != 0 ||
	    (r = encode_attrib(پیام, &junk)) != 0)
		fatal_fr(r, "buffer error");
	send_پیام(conn, پیام);
	debug3("Sent message SSH2_FXP_OPEN I:%u P:%s", id, oldpath);

	sshbuf_reset(پیام);

	old_handle = get_handle(conn, id, &old_handle_len,
	    "remote open(\"%s\")", oldpath);
	اگر (old_handle == پوچ) {
		sshbuf_free(پیام);
		بازگشت -1;
	}

	/* Open the new file for writing */
	id = conn->پیام_id++;
	اگر ((r = sshbuf_put_u8(پیام, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(پیام, id)) != 0 ||
	    (r = sshbuf_put_cstring(پیام, newpath)) != 0 ||
	    (r = sshbuf_put_u32(پیام, SSH2_FXF_WRITE|SSH2_FXF_CREAT|
	    SSH2_FXF_TRUNC)) != 0 ||
	    (r = encode_attrib(پیام, &attr)) != 0)
		fatal_fr(r, "buffer error");
	send_پیام(conn, پیام);
	debug3("Sent message SSH2_FXP_OPEN I:%u P:%s", id, newpath);

	sshbuf_reset(پیام);

	new_handle = get_handle(conn, id, &new_handle_len,
	    "remote open(\"%s\")", newpath);
	اگر (new_handle == پوچ) {
		sshbuf_free(پیام);
		آزاد(old_handle);
		بازگشت -1;
	}

	/* Copy the file data */
	id = conn->پیام_id++;
	اگر ((r = sshbuf_put_u8(پیام, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(پیام, id)) != 0 ||
	    (r = sshbuf_put_cstring(پیام, "copy-data")) != 0 ||
	    (r = sshbuf_put_string(پیام, old_handle, old_handle_len)) != 0 ||
	    (r = sshbuf_put_u64(پیام, 0)) != 0 ||
	    (r = sshbuf_put_u64(پیام, 0)) != 0 ||
	    (r = sshbuf_put_string(پیام, new_handle, new_handle_len)) != 0 ||
	    (r = sshbuf_put_u64(پیام, 0)) != 0)
		fatal_fr(r, "buffer error");
	send_پیام(conn, پیام);
	debug3("Sent message copy-data \"%s\" 0 0 -> \"%s\" 0",
	       oldpath, newpath);

	status = get_status(conn, id);
	اگر (status != SSH2_FX_OK)
		error("Couldn't copy file \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	/* Clean up everything */
	sshbuf_free(پیام);
	sftp_close(conn, old_handle, old_handle_len);
	sftp_close(conn, new_handle, new_handle_len);
	آزاد(old_handle);
	آزاد(new_handle);

	بازگشت status == SSH2_FX_OK ? 0 : -1;
}

صحیح
sftp_rename(ساختار sftp_conn *conn, ثابت نویسه *oldpath, ثابت نویسه *newpath,
    صحیح force_legacy)
{
	ساختار sshbuf *پیام;
	u_int status, id;
	صحیح r, use_ext = (conn->exts & SFTP_EXT_POSIX_RENAME) && !force_legacy;

	اگر ((پیام = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");

	/* Send rename request */
	id = conn->پیام_id++;
	اگر (use_ext) {
		debug2("Sending SSH2_FXP_EXTENDED(posix-rename@openssh.com) "
		    "\"%s\" to \"%s\"", oldpath, newpath);
		اگر ((r = sshbuf_put_u8(پیام, SSH2_FXP_EXTENDED)) != 0 ||
		    (r = sshbuf_put_u32(پیام, id)) != 0 ||
		    (r = sshbuf_put_cstring(پیام,
		    "posix-rename@openssh.com")) != 0)
			fatal_fr(r, "compose posix-rename");
	} وگرنه {
		debug2("Sending SSH2_FXP_RENAME \"%s\" to \"%s\"",
		    oldpath, newpath);
		اگر ((r = sshbuf_put_u8(پیام, SSH2_FXP_RENAME)) != 0 ||
		    (r = sshbuf_put_u32(پیام, id)) != 0)
			fatal_fr(r, "compose rename");
	}
	اگر ((r = sshbuf_put_cstring(پیام, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(پیام, newpath)) != 0)
		fatal_fr(r, "compose paths");
	send_پیام(conn, پیام);
	debug3("Sent message %s \"%s\" -> \"%s\"",
	    use_ext ? "posix-rename@openssh.com" :
	    "SSH2_FXP_RENAME", oldpath, newpath);
	sshbuf_free(پیام);

	status = get_status(conn, id);
	اگر (status != SSH2_FX_OK)
		error("remote rename \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	بازگشت status == SSH2_FX_OK ? 0 : -1;
}

صحیح
sftp_hardlink(ساختار sftp_conn *conn, ثابت نویسه *oldpath, ثابت نویسه *newpath)
{
	ساختار sshbuf *پیام;
	u_int status, id;
	صحیح r;

	اگر ((conn->exts & SFTP_EXT_HARDLINK) == 0) {
		error("Server does not support hardlink@openssh.com extension");
		بازگشت -1;
	}
	debug2("Sending SSH2_FXP_EXTENDED(hardlink@openssh.com) "
	    "\"%s\" to \"%s\"", oldpath, newpath);

	اگر ((پیام = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");

	/* Send link request */
	id = conn->پیام_id++;
	اگر ((r = sshbuf_put_u8(پیام, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(پیام, id)) != 0 ||
	    (r = sshbuf_put_cstring(پیام, "hardlink@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(پیام, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(پیام, newpath)) != 0)
		fatal_fr(r, "compose");
	send_پیام(conn, پیام);
	debug3("Sent message hardlink@openssh.com \"%s\" -> \"%s\"",
	    oldpath, newpath);
	sshbuf_free(پیام);

	status = get_status(conn, id);
	اگر (status != SSH2_FX_OK)
		error("remote link \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	بازگشت status == SSH2_FX_OK ? 0 : -1;
}

صحیح
sftp_symlink(ساختار sftp_conn *conn, ثابت نویسه *oldpath, ثابت نویسه *newpath)
{
	ساختار sshbuf *پیام;
	u_int status, id;
	صحیح r;

	اگر (conn->version < 3) {
		error("This server does not support the symlink operation");
		بازگشت(SSH2_FX_OP_UNSUPPORTED);
	}
	debug2("Sending SSH2_FXP_SYMLINK \"%s\" to \"%s\"", oldpath, newpath);

	اگر ((پیام = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");

	/* Send symlink request */
	id = conn->پیام_id++;
	اگر ((r = sshbuf_put_u8(پیام, SSH2_FXP_SYMLINK)) != 0 ||
	    (r = sshbuf_put_u32(پیام, id)) != 0 ||
	    (r = sshbuf_put_cstring(پیام, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(پیام, newpath)) != 0)
		fatal_fr(r, "compose");
	send_پیام(conn, پیام);
	debug3("Sent message SSH2_FXP_SYMLINK \"%s\" -> \"%s\"", oldpath,
	    newpath);
	sshbuf_free(پیام);

	status = get_status(conn, id);
	اگر (status != SSH2_FX_OK)
		error("remote symlink file \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	بازگشت status == SSH2_FX_OK ? 0 : -1;
}

صحیح
sftp_fsync(ساختار sftp_conn *conn, u_char *handle, u_int handle_len)
{
	ساختار sshbuf *پیام;
	u_int status, id;
	صحیح r;

	/* Silently return if the extension is not supported */
	اگر ((conn->exts & SFTP_EXT_FSYNC) == 0)
		بازگشت -1;
	debug2("Sending SSH2_FXP_EXTENDED(fsync@openssh.com)");

	/* Send fsync request */
	اگر ((پیام = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	id = conn->پیام_id++;
	اگر ((r = sshbuf_put_u8(پیام, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(پیام, id)) != 0 ||
	    (r = sshbuf_put_cstring(پیام, "fsync@openssh.com")) != 0 ||
	    (r = sshbuf_put_string(پیام, handle, handle_len)) != 0)
		fatal_fr(r, "compose");
	send_پیام(conn, پیام);
	debug3("Sent message fsync@openssh.com I:%u", id);
	sshbuf_free(پیام);

	status = get_status(conn, id);
	اگر (status != SSH2_FX_OK)
		error("remote fsync: %s", fx2txt(status));

	بازگشت status == SSH2_FX_OK ? 0 : -1;
}

#ifdef notyet
نویسه *
sftp_readlink(ساختار sftp_conn *conn, ثابت نویسه *path)
{
	ساختار sshbuf *پیام;
	u_int expected_id, شمار, id;
	نویسه *filename, *longname;
	Attrib a;
	u_char type;
	صحیح r;

	debug2("Sending SSH2_FXP_READLINK \"%s\"", path);

	expected_id = id = conn->پیام_id++;
	send_string_request(conn, id, SSH2_FXP_READLINK, path, strlen(path));

	اگر ((پیام = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");

	get_پیام(conn, پیام);
	اگر ((r = sshbuf_get_u8(پیام, &type)) != 0 ||
	    (r = sshbuf_get_u32(پیام, &id)) != 0)
		fatal_fr(r, "parse");

	اگر (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);

	اگر (type == SSH2_FXP_STATUS) {
		u_int status;

		اگر ((r = sshbuf_get_u32(پیام, &status)) != 0)
			fatal_fr(r, "parse status");
		error("Couldn't readlink: %s", fx2txt(status));
		sshbuf_free(پیام);
		بازگشت(پوچ);
	} وگرنه اگر (type != SSH2_FXP_NAME)
		fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
		    SSH2_FXP_NAME, type);

	اگر ((r = sshbuf_get_u32(پیام, &شمار)) != 0)
		fatal_fr(r, "parse count");
	اگر (شمار != 1)
		fatal("Got multiple names (%d) from SSH_FXP_READLINK", شمار);

	اگر ((r = sshbuf_get_cstring(پیام, &filename, پوچ)) != 0 ||
	    (r = sshbuf_get_cstring(پیام, &longname, پوچ)) != 0 ||
	    (r = decode_attrib(پیام, &a)) != 0)
		fatal_fr(r, "parse filenames/attrib");

	debug3("SSH_FXP_READLINK %s -> %s", path, filename);

	آزاد(longname);

	sshbuf_free(پیام);

	بازگشت filename;
}
#endif

صحیح
sftp_statvfs(ساختار sftp_conn *conn, ثابت نویسه *path, ساختار sftp_statvfs *st,
    صحیح quiet)
{
	ساختار sshbuf *پیام;
	u_int id;
	صحیح r;

	اگر ((conn->exts & SFTP_EXT_STATVFS) == 0) {
		error("Server does not support statvfs@openssh.com extension");
		بازگشت -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(statvfs@openssh.com) \"%s\"", path);

	id = conn->پیام_id++;

	اگر ((پیام = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_u8(پیام, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(پیام, id)) != 0 ||
	    (r = sshbuf_put_cstring(پیام, "statvfs@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(پیام, path)) != 0)
		fatal_fr(r, "compose");
	send_پیام(conn, پیام);
	sshbuf_free(پیام);

	بازگشت get_decode_statvfs(conn, st, id, quiet);
}

#ifdef notyet
صحیح
sftp_fstatvfs(ساختار sftp_conn *conn, ثابت u_char *handle, u_int handle_len,
    ساختار sftp_statvfs *st, صحیح quiet)
{
	ساختار sshbuf *پیام;
	u_int id;

	اگر ((conn->exts & SFTP_EXT_FSTATVFS) == 0) {
		error("Server does not support fstatvfs@openssh.com extension");
		بازگشت -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(fstatvfs@openssh.com)");

	id = conn->پیام_id++;

	اگر ((پیام = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_u8(پیام, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(پیام, id)) != 0 ||
	    (r = sshbuf_put_cstring(پیام, "fstatvfs@openssh.com")) != 0 ||
	    (r = sshbuf_put_string(پیام, handle, handle_len)) != 0)
		fatal_fr(r, "compose");
	send_پیام(conn, پیام);
	sshbuf_free(پیام);

	بازگشت get_decode_statvfs(conn, st, id, quiet);
}
#endif

صحیح
sftp_lsetstat(ساختار sftp_conn *conn, ثابت نویسه *path, Attrib *a)
{
	ساختار sshbuf *پیام;
	u_int status, id;
	صحیح r;

	اگر ((conn->exts & SFTP_EXT_LSETSTAT) == 0) {
		error("Server does not support lsetstat@openssh.com extension");
		بازگشت -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(lsetstat@openssh.com) \"%s\"", path);

	id = conn->پیام_id++;
	اگر ((پیام = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_u8(پیام, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(پیام, id)) != 0 ||
	    (r = sshbuf_put_cstring(پیام, "lsetstat@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(پیام, path)) != 0 ||
	    (r = encode_attrib(پیام, a)) != 0)
		fatal_fr(r, "compose");
	send_پیام(conn, پیام);
	sshbuf_free(پیام);

	status = get_status(conn, id);
	اگر (status != SSH2_FX_OK)
		error("remote lsetstat \"%s\": %s", path, fx2txt(status));

	بازگشت status == SSH2_FX_OK ? 0 : -1;
}

ایستا تهی
send_read_request(ساختار sftp_conn *conn, u_int id, uint64_t offset,
    u_int len, ثابت u_char *handle, u_int handle_len)
{
	ساختار sshbuf *پیام;
	صحیح r;

	اگر ((پیام = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_u8(پیام, SSH2_FXP_READ)) != 0 ||
	    (r = sshbuf_put_u32(پیام, id)) != 0 ||
	    (r = sshbuf_put_string(پیام, handle, handle_len)) != 0 ||
	    (r = sshbuf_put_u64(پیام, offset)) != 0 ||
	    (r = sshbuf_put_u32(پیام, len)) != 0)
		fatal_fr(r, "compose");
	send_پیام(conn, پیام);
	sshbuf_free(پیام);
}

ایستا صحیح
send_open(ساختار sftp_conn *conn, ثابت نویسه *path, ثابت نویسه *tag,
    u_int openmode, Attrib *a, u_char **handlep, size_t *handle_lenp)
{
	Attrib junk;
	u_char *handle;
	size_t handle_len;
	ساختار sshbuf *پیام;
	صحیح r;
	u_int id;

	debug2("Sending SSH2_FXP_OPEN \"%s\"", path);

	*handlep = پوچ;
	*handle_lenp = 0;

	اگر (a == پوچ) {
		attrib_clear(&junk); /* Send empty attributes */
		a = &junk;
	}
	/* Send open request */
	اگر ((پیام = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	id = conn->پیام_id++;
	اگر ((r = sshbuf_put_u8(پیام, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(پیام, id)) != 0 ||
	    (r = sshbuf_put_cstring(پیام, path)) != 0 ||
	    (r = sshbuf_put_u32(پیام, openmode)) != 0 ||
	    (r = encode_attrib(پیام, a)) != 0)
		fatal_fr(r, "compose %s open", tag);
	send_پیام(conn, پیام);
	sshbuf_free(پیام);
	debug3("Sent %s message SSH2_FXP_OPEN I:%u P:%s M:0x%04x",
	    tag, id, path, openmode);
	اگر ((handle = get_handle(conn, id, &handle_len,
	    "%s open \"%s\"", tag, path)) == پوچ)
		بازگشت -1;
	/* success */
	*handlep = handle;
	*handle_lenp = handle_len;
	بازگشت 0;
}

ایستا ثابت نویسه *
progress_meter_path(ثابت نویسه *path)
{
	ثابت نویسه *progresspath;

	اگر ((progresspath = strrchr(path, '/')) == پوچ)
		بازگشت path;
	progresspath++;
	اگر (*progresspath == '\0')
		بازگشت path;
	بازگشت progresspath;
}

صحیح
sftp_download(ساختار sftp_conn *conn, ثابت نویسه *remote_path,
    ثابت نویسه *local_path, Attrib *a, صحیح preserve_flag, صحیح resume_flag,
    صحیح fsync_flag, صحیح inplace_flag)
{
	ساختار sshbuf *پیام;
	u_char *handle;
	صحیح local_fd = -1, write_error, seen_zerolen = 0;
	صحیح read_error, write_errno, lmodified = 0, reordered = 0, r;
	uint64_t offset = 0, size, highwater = 0, maxack = 0;
	u_int mode, id, buflen, رقم_req, max_req, status = SSH2_FX_OK;
	off_t progress_counter;
	size_t handle_len;
	ساختار stat st;
	ساختار requests requests;
	ساختار request *req;
	u_char type;
	Attrib attr;

	debug2_f("download remote \"%s\" to local \"%s\"",
	    remote_path, local_path);

	TAILQ_INIT(&requests);

	اگر (a == پوچ) {
		اگر (sftp_stat(conn, remote_path, 0, &attr) != 0)
			بازگشت -1;
		a = &attr;
	}

	/* Do not preserve set[ug]id here, as we do not preserve ownership */
	اگر (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS)
		mode = a->perm & 0777;
	وگرنه
		mode = 0666;

	اگر ((a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) &&
	    (!S_ISREG(a->perm))) {
		error("download %s: not a regular file", remote_path);
		بازگشت(-1);
	}

	اگر (a->flags & SSH2_FILEXFER_ATTR_SIZE)
		size = a->size;
	وگرنه
		size = 0;

	buflen = conn->download_buflen;

	/* Send open request */
	اگر (send_open(conn, remote_path, "remote", SSH2_FXF_READ, پوچ,
	    &handle, &handle_len) != 0)
		بازگشت -1;

	local_fd = open(local_path, O_WRONLY | O_CREAT |
	((resume_flag || inplace_flag) ? 0 : O_TRUNC), mode | S_IWUSR);
	اگر (local_fd == -1) {
		error("open local \"%s\": %s", local_path, strerror(errno));
		برو fail;
	}
	اگر (resume_flag) {
		اگر (fstat(local_fd, &st) == -1) {
			error("stat local \"%s\": %s",
			    local_path, strerror(errno));
			برو fail;
		}
		اگر (st.st_size < 0) {
			error("\"%s\" has negative size", local_path);
			برو fail;
		}
		اگر ((uint64_t)st.st_size > size) {
			error("Unable to resume download of \"%s\": "
			    "local file is larger than remote", local_path);
 fail:
			sftp_close(conn, handle, handle_len);
			آزاد(handle);
			اگر (local_fd != -1)
				close(local_fd);
			بازگشت -1;
		}
		offset = highwater = maxack = st.st_size;
	}

	/* Read from remote and write to local */
	write_error = read_error = write_errno = رقم_req = 0;
	max_req = 1;
	progress_counter = offset;

	اگر (showprogress && size != 0) {
		start_progress_meter(progress_meter_path(remote_path),
		    size, &progress_counter);
	}

	اگر ((پیام = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");

	وقتی (رقم_req > 0 || max_req > 0) {
		u_char *data;
		size_t len;

		/*
		 * Simulate EOF on interrupt: stop sending new requests and
		 * allow outstanding requests to drain gracefully
		 */
		اگر (interrupted) {
			اگر (رقم_req == 0) /* If we haven't started yet... */
				بشکن;
			max_req = 0;
		}

		/* Send some more requests */
		وقتی (رقم_req < max_req) {
			debug3("Request range %llu -> %llu (%d/%d)",
			    (unsigned long long)offset,
			    (unsigned long long)offset + buflen - 1,
			    رقم_req, max_req);
			req = request_enqueue(&requests, conn->پیام_id++,
			    buflen, offset);
			offset += buflen;
			رقم_req++;
			send_read_request(conn, req->id, req->offset,
			    req->len, handle, handle_len);
		}

		sshbuf_reset(پیام);
		get_پیام(conn, پیام);
		اگر ((r = sshbuf_get_u8(پیام, &type)) != 0 ||
		    (r = sshbuf_get_u32(پیام, &id)) != 0)
			fatal_fr(r, "parse");
		debug3("Received reply T:%u I:%u R:%d", type, id, max_req);

		/* Find the request in our queue */
		اگر ((req = request_find(&requests, id)) == پوچ)
			fatal("Unexpected reply %u", id);

		انتخاب (type) {
		حالت SSH2_FXP_STATUS:
			اگر ((r = sshbuf_get_u32(پیام, &status)) != 0)
				fatal_fr(r, "parse status");
			اگر (status != SSH2_FX_EOF)
				read_error = 1;
			max_req = 0;
			TAILQ_REMOVE(&requests, req, tq);
			آزاد(req);
			رقم_req--;
			بشکن;
		حالت SSH2_FXP_DATA:
			اگر ((r = sshbuf_get_string(پیام, &data, &len)) != 0)
				fatal_fr(r, "parse data");
			debug3("Received data %llu -> %llu",
			    (unsigned long long)req->offset,
			    (unsigned long long)req->offset + len - 1);
			اگر (len > req->len)
				fatal("Received more data than asked for "
				    "%zu > %zu", len, req->len);
			اگر (len == 0) {
				اگر (seen_zerolen)
					fatal_f("server sent zero data length");
				seen_zerolen = 1;
			}
			lmodified = 1;
			اگر ((lseek(local_fd, req->offset, SEEK_SET) == -1 ||
			    atomicio(vwrite, local_fd, data, len) != len) &&
			    !write_error) {
				write_errno = errno;
				write_error = 1;
				max_req = 0;
			} وگرنه {
				/*
				 * Track both the highest offset acknowledged
				 * and the highest *contiguous* offset
				 * acknowledged.
				 * We'll need the latter for ftruncate()ing
				 * interrupted transfers.
				 */
				اگر (maxack < req->offset + len)
					maxack = req->offset + len;
				اگر (!reordered && req->offset <= highwater)
					highwater = maxack;
				وگرنه اگر (!reordered && req->offset > highwater)
					reordered = 1;
			}
			progress_counter += len;
			آزاد(data);

			اگر (len == req->len) {
				TAILQ_REMOVE(&requests, req, tq);
				آزاد(req);
				رقم_req--;
			} وگرنه {
				/* Resend the request for the missing data */
				debug3("Short data block, re-requesting "
				    "%llu -> %llu (%2d)",
				    (unsigned long long)req->offset + len,
				    (unsigned long long)req->offset +
				    req->len - 1, رقم_req);
				req->id = conn->پیام_id++;
				req->len -= len;
				req->offset += len;
				send_read_request(conn, req->id,
				    req->offset, req->len, handle, handle_len);
				/* Reduce the request size */
				اگر (len < buflen)
					buflen = MAXIMUM(MIN_READ_SIZE, len);
			}
			اگر (max_req > 0) { /* max_req = 0 iff EOF received */
				اگر (size > 0 && offset > size) {
					/* Only one request at a time
					 * after the expected EOF */
					debug3("Finish at %llu (%2d)",
					    (unsigned long long)offset,
					    رقم_req);
					max_req = 1;
				} وگرنه اگر (max_req < conn->رقم_requests) {
					++max_req;
				}
			}
			بشکن;
		پیشفرض:
			fatal("Expected SSH2_FXP_DATA(%u) packet, got %u",
			    SSH2_FXP_DATA, type);
		}
	}

	اگر (showprogress && size)
		stop_progress_meter();

	/* Sanity check */
	اگر (TAILQ_FIRST(&requests) != پوچ)
		fatal("Transfer complete, but requests still in queue");

	اگر (!read_error && !write_error && !interrupted) {
		/* we got everything */
		highwater = maxack;
	}

	/*
	 * Truncate at highest contiguous point to avoid holes on interrupt,
	 * or unconditionally if writing in place.
	 */
	اگر (inplace_flag || read_error || write_error || interrupted) {
		اگر (reordered && resume_flag &&
		    (read_error || write_error || interrupted)) {
			error("Unable to resume download of \"%s\": "
			    "server reordered requests", local_path);
		}
		debug("truncating at %llu", (unsigned long long)highwater);
		اگر (ftruncate(local_fd, highwater) == -1)
			error("local ftruncate \"%s\": %s", local_path,
			    strerror(errno));
	}
	اگر (read_error) {
		error("read remote \"%s\" : %s", remote_path, fx2txt(status));
		status = -1;
		sftp_close(conn, handle, handle_len);
	} وگرنه اگر (write_error) {
		error("write local \"%s\": %s", local_path,
		    strerror(write_errno));
		status = SSH2_FX_FAILURE;
		sftp_close(conn, handle, handle_len);
	} وگرنه {
		اگر (sftp_close(conn, handle, handle_len) != 0 || interrupted)
			status = SSH2_FX_FAILURE;
		وگرنه
			status = SSH2_FX_OK;
		/* Override umask and utimes if asked */
#ifdef HAVE_FCHMOD
		اگر (preserve_flag && fchmod(local_fd, mode) == -1)
#وگرنه
		اگر (preserve_flag && chmod(local_path, mode) == -1)
#endif /* HAVE_FCHMOD */
			error("local chmod \"%s\": %s", local_path,
			    strerror(errno));
		اگر (preserve_flag &&
		    (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME)) {
			ساختار timeval tv[2];
			tv[0].tv_sec = a->atime;
			tv[1].tv_sec = a->mtime;
			tv[0].tv_usec = tv[1].tv_usec = 0;
			اگر (utimes(local_path, tv) == -1)
				error("local set times \"%s\": %s",
				    local_path, strerror(errno));
		}
		اگر (resume_flag && !lmodified)
			logit("File \"%s\" was not modified", local_path);
		وگرنه اگر (fsync_flag) {
			debug("syncing \"%s\"", local_path);
			اگر (fsync(local_fd) == -1)
				error("local sync \"%s\": %s",
				    local_path, strerror(errno));
		}
	}
	close(local_fd);
	sshbuf_free(پیام);
	آزاد(handle);

	بازگشت status == SSH2_FX_OK ? 0 : -1;
}

ایستا صحیح
download_dir_internal(ساختار sftp_conn *conn, ثابت نویسه *src, ثابت نویسه *dst,
    صحیح depth, Attrib *dirattrib, صحیح preserve_flag, صحیح print_flag,
    صحیح resume_flag, صحیح fsync_flag, صحیح follow_link_flag, صحیح inplace_flag)
{
	صحیح i, ret = 0;
	SFTP_DIRENT **dir_entries;
	نویسه *filename, *new_src = پوچ, *new_dst = پوچ;
	mode_t mode = 0777, tmpmode = mode;
	Attrib *a, ldirattrib, lsym;

	اگر (depth >= MAX_DIR_DEPTH) {
		error("Maximum directory depth exceeded: %d levels", depth);
		بازگشت -1;
	}

	debug2_f("download dir remote \"%s\" to local \"%s\"", src, dst);

	اگر (dirattrib == پوچ) {
		اگر (sftp_stat(conn, src, 1, &ldirattrib) != 0) {
			error("stat remote \"%s\" directory failed", src);
			بازگشت -1;
		}
		dirattrib = &ldirattrib;
	}
	اگر (!S_ISDIR(dirattrib->perm)) {
		error("\"%s\" is not a directory", src);
		بازگشت -1;
	}
	اگر (print_flag && print_flag != SFTP_PROGRESS_ONLY)
		mprintf("Retrieving %s\n", src);

	اگر (dirattrib->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		mode = dirattrib->perm & 01777;
		tmpmode = mode | (S_IWUSR|S_IXUSR);
	} وگرنه {
		debug("download remote \"%s\": server "
		    "did not send permissions", dst);
	}

	اگر (mkdir(dst, tmpmode) == -1 && errno != EEXIST) {
		error("mkdir %s: %s", dst, strerror(errno));
		بازگشت -1;
	}

	اگر (sftp_readdir(conn, src, &dir_entries) == -1) {
		error("remote readdir \"%s\" failed", src);
		بازگشت -1;
	}

	برای (i = 0; dir_entries[i] != پوچ && !interrupted; i++) {
		آزاد(new_dst);
		آزاد(new_src);

		filename = dir_entries[i]->filename;
		new_dst = sftp_path_append(dst, filename);
		new_src = sftp_path_append(src, filename);

		a = &dir_entries[i]->a;
		اگر (S_ISLNK(a->perm)) {
			اگر (!follow_link_flag) {
				logit("download \"%s\": not a regular file",
				    new_src);
				ادامه;
			}
			/* Replace the stat contents with the symlink target */
			اگر (sftp_stat(conn, new_src, 1, &lsym) != 0) {
				logit("remote stat \"%s\" failed", new_src);
				ret = -1;
				ادامه;
			}
			a = &lsym;
		}

		اگر (S_ISDIR(a->perm)) {
			اگر (strcmp(filename, ".") == 0 ||
			    strcmp(filename, "..") == 0)
				ادامه;
			اگر (download_dir_internal(conn, new_src, new_dst,
			    depth + 1, a, preserve_flag,
			    print_flag, resume_flag,
			    fsync_flag, follow_link_flag, inplace_flag) == -1)
				ret = -1;
		} وگرنه اگر (S_ISREG(a->perm)) {
			اگر (sftp_download(conn, new_src, new_dst, a,
			    preserve_flag, resume_flag, fsync_flag,
			    inplace_flag) == -1) {
				error("Download of file %s to %s failed",
				    new_src, new_dst);
				ret = -1;
			}
		} وگرنه
			logit("download \"%s\": not a regular file", new_src);

	}
	آزاد(new_dst);
	آزاد(new_src);

	اگر (preserve_flag) {
		اگر (dirattrib->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
			ساختار timeval tv[2];
			tv[0].tv_sec = dirattrib->atime;
			tv[1].tv_sec = dirattrib->mtime;
			tv[0].tv_usec = tv[1].tv_usec = 0;
			اگر (utimes(dst, tv) == -1)
				error("local set times on \"%s\": %s",
				    dst, strerror(errno));
		} وگرنه
			debug("Server did not send times for directory "
			    "\"%s\"", dst);
	}

	اگر (mode != tmpmode && chmod(dst, mode) == -1)
		error("local chmod directory \"%s\": %s", dst,
		    strerror(errno));

	sftp_free_dirents(dir_entries);

	بازگشت ret;
}

صحیح
sftp_download_dir(ساختار sftp_conn *conn, ثابت نویسه *src, ثابت نویسه *dst,
    Attrib *dirattrib, صحیح preserve_flag, صحیح print_flag, صحیح resume_flag,
    صحیح fsync_flag, صحیح follow_link_flag, صحیح inplace_flag)
{
	نویسه *src_canon;
	صحیح ret;

	اگر ((src_canon = sftp_realpath(conn, src)) == پوچ) {
		error("download \"%s\": path canonicalization failed", src);
		بازگشت -1;
	}

	ret = download_dir_internal(conn, src_canon, dst, 0,
	    dirattrib, preserve_flag, print_flag, resume_flag, fsync_flag,
	    follow_link_flag, inplace_flag);
	آزاد(src_canon);
	بازگشت ret;
}

صحیح
sftp_upload(ساختار sftp_conn *conn, ثابت نویسه *local_path,
    ثابت نویسه *remote_path, صحیح preserve_flag, صحیح resume,
    صحیح fsync_flag, صحیح inplace_flag)
{
	صحیح r, local_fd;
	u_int openmode, id, status = SSH2_FX_OK, status2, reordered = 0;
	off_t offset, progress_counter;
	u_char type, *handle, *data;
	ساختار sshbuf *پیام;
	ساختار stat sb;
	Attrib a, t, c;
	uint32_t startid, ackid;
	uint64_t highwater = 0, maxack = 0;
	ساختار request *ack = پوچ;
	ساختار requests acks;
	size_t handle_len;

	debug2_f("upload local \"%s\" to remote \"%s\"",
	    local_path, remote_path);

	TAILQ_INIT(&acks);

	اگر ((local_fd = open(local_path, O_RDONLY)) == -1) {
		error("open local \"%s\": %s", local_path, strerror(errno));
		بازگشت(-1);
	}
	اگر (fstat(local_fd, &sb) == -1) {
		error("fstat local \"%s\": %s", local_path, strerror(errno));
		close(local_fd);
		بازگشت(-1);
	}
	اگر (!S_ISREG(sb.st_mode)) {
		error("local \"%s\" is not a regular file", local_path);
		close(local_fd);
		بازگشت(-1);
	}
	stat_to_attrib(&sb, &a);

	a.flags &= ~SSH2_FILEXFER_ATTR_SIZE;
	a.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a.perm &= 0777;
	اگر (!preserve_flag)
		a.flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;

	اگر (resume) {
		/* Get remote file size if it exists */
		اگر (sftp_stat(conn, remote_path, 0, &c) != 0) {
			close(local_fd);
			بازگشت -1;
		}

		اگر ((off_t)c.size >= sb.st_size) {
			error("resume \"%s\": destination file "
			    "same size or larger", local_path);
			close(local_fd);
			بازگشت -1;
		}

		اگر (lseek(local_fd, (off_t)c.size, SEEK_SET) == -1) {
			close(local_fd);
			بازگشت -1;
		}
		highwater = c.size;
	}

	openmode = SSH2_FXF_WRITE|SSH2_FXF_CREAT;
	اگر (resume)
		openmode |= SSH2_FXF_APPEND;
	وگرنه اگر (!inplace_flag)
		openmode |= SSH2_FXF_TRUNC;

	/* Send open request */
	اگر (send_open(conn, remote_path, "dest", openmode, &a,
	    &handle, &handle_len) != 0) {
		close(local_fd);
		بازگشت -1;
	}

	id = conn->پیام_id;
	startid = ackid = id + 1;
	data = xmalloc(conn->upload_buflen);

	/* Read from local and write to remote */
	offset = progress_counter = (resume ? c.size : 0);
	اگر (showprogress) {
		start_progress_meter(progress_meter_path(local_path),
		    sb.st_size, &progress_counter);
	}

	اگر ((پیام = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	برای (;;) {
		صحیح len;

		/*
		 * Can't use atomicio here because it returns 0 on EOF,
		 * thus losing the last block of the file.
		 * Simulate an EOF on interrupt, allowing ACKs from the
		 * server to drain.
		 */
		اگر (interrupted || status != SSH2_FX_OK)
			len = 0;
		وگرنه انجامبده
			len = اقرأ(local_fd, data, conn->upload_buflen);
		وقتی ((len == -1) &&
		    (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK));

		اگر (len == -1) {
			fatal("read local \"%s\": %s",
			    local_path, strerror(errno));
		} وگرنه اگر (len != 0) {
			ack = request_enqueue(&acks, ++id, len, offset);
			sshbuf_reset(پیام);
			اگر ((r = sshbuf_put_u8(پیام, SSH2_FXP_WRITE)) != 0 ||
			    (r = sshbuf_put_u32(پیام, ack->id)) != 0 ||
			    (r = sshbuf_put_string(پیام, handle,
			    handle_len)) != 0 ||
			    (r = sshbuf_put_u64(پیام, offset)) != 0 ||
			    (r = sshbuf_put_string(پیام, data, len)) != 0)
				fatal_fr(r, "compose");
			send_پیام(conn, پیام);
			debug3("Sent message SSH2_FXP_WRITE I:%u O:%llu S:%u",
			    id, (unsigned long long)offset, len);
		} وگرنه اگر (TAILQ_FIRST(&acks) == پوچ)
			بشکن;

		اگر (ack == پوچ)
			fatal("Unexpected ACK %u", id);

		اگر (id == startid || len == 0 ||
		    id - ackid >= conn->رقم_requests) {
			u_int rid;

			sshbuf_reset(پیام);
			get_پیام(conn, پیام);
			اگر ((r = sshbuf_get_u8(پیام, &type)) != 0 ||
			    (r = sshbuf_get_u32(پیام, &rid)) != 0)
				fatal_fr(r, "parse");

			اگر (type != SSH2_FXP_STATUS)
				fatal("Expected SSH2_FXP_STATUS(%d) packet, "
				    "got %d", SSH2_FXP_STATUS, type);

			اگر ((r = sshbuf_get_u32(پیام, &status2)) != 0)
				fatal_fr(r, "parse status");
			debug3("SSH2_FXP_STATUS %u", status2);
			اگر (status2 != SSH2_FX_OK)
				status = status2; /* remember errors */

			/* Find the request in our queue */
			اگر ((ack = request_find(&acks, rid)) == پوچ)
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
			اگر (maxack < ack->offset + ack->len)
				maxack = ack->offset + ack->len;
			اگر (!reordered && ack->offset <= highwater)
				highwater = maxack;
			وگرنه اگر (!reordered && ack->offset > highwater) {
				debug3_f("server reordered ACKs");
				reordered = 1;
			}
			آزاد(ack);
		}
		offset += len;
		اگر (offset < 0)
			fatal_f("offset < 0");
	}
	sshbuf_free(پیام);

	اگر (showprogress)
		stop_progress_meter();
	آزاد(data);

	اگر (status == SSH2_FX_OK && !interrupted) {
		/* we got everything */
		highwater = maxack;
	}
	اگر (status != SSH2_FX_OK) {
		error("write remote \"%s\": %s", remote_path, fx2txt(status));
		status = SSH2_FX_FAILURE;
	}

	اگر (inplace_flag || (resume && (status != SSH2_FX_OK || interrupted))) {
		debug("truncating at %llu", (unsigned long long)highwater);
		attrib_clear(&t);
		t.flags = SSH2_FILEXFER_ATTR_SIZE;
		t.size = highwater;
		sftp_fsetstat(conn, handle, handle_len, &t);
	}

	اگر (close(local_fd) == -1) {
		error("close local \"%s\": %s", local_path, strerror(errno));
		status = SSH2_FX_FAILURE;
	}

	/* Override umask and utimes if asked */
	اگر (preserve_flag)
		sftp_fsetstat(conn, handle, handle_len, &a);

	اگر (fsync_flag)
		(تهی)sftp_fsync(conn, handle, handle_len);

	اگر (sftp_close(conn, handle, handle_len) != 0)
		status = SSH2_FX_FAILURE;

	آزاد(handle);

	بازگشت status == SSH2_FX_OK ? 0 : -1;
}

ایستا صحیح
upload_dir_internal(ساختار sftp_conn *conn, ثابت نویسه *src, ثابت نویسه *dst,
    صحیح depth, صحیح preserve_flag, صحیح print_flag, صحیح resume, صحیح fsync_flag,
    صحیح follow_link_flag, صحیح inplace_flag)
{
	صحیح created = 0, ret = 0;
	DIR *dirp;
	ساختار dirent *dp;
	نویسه *filename, *new_src = پوچ, *new_dst = پوچ;
	ساختار stat sb;
	Attrib a, dirattrib;
	uint32_t saved_perm;

	debug2_f("upload local dir \"%s\" to remote \"%s\"", src, dst);

	اگر (depth >= MAX_DIR_DEPTH) {
		error("Maximum directory depth exceeded: %d levels", depth);
		بازگشت -1;
	}

	اگر (stat(src, &sb) == -1) {
		error("stat local \"%s\": %s", src, strerror(errno));
		بازگشت -1;
	}
	اگر (!S_ISDIR(sb.st_mode)) {
		error("\"%s\" is not a directory", src);
		بازگشت -1;
	}
	اگر (print_flag && print_flag != SFTP_PROGRESS_ONLY)
		mprintf("Entering %s\n", src);

	stat_to_attrib(&sb, &a);
	a.flags &= ~SSH2_FILEXFER_ATTR_SIZE;
	a.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a.perm &= 01777;
	اگر (!preserve_flag)
		a.flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;

	/*
	 * sftp lacks a portable status value to match errno EEXIST,
	 * so if we get a failure back then we must check whether
	 * the path already existed and is a directory.  Ensure we can
	 * write to the directory we create for the duration of the transfer.
	 */
	saved_perm = a.perm;
	a.perm |= (S_IWUSR|S_IXUSR);
	اگر (sftp_mkdir(conn, dst, &a, 0) == 0)
		created = 1;
	وگرنه {
		اگر (sftp_stat(conn, dst, 0, &dirattrib) != 0)
			بازگشت -1;
		اگر (!S_ISDIR(dirattrib.perm)) {
			error("\"%s\" exists but is not a directory", dst);
			بازگشت -1;
		}
	}
	a.perm = saved_perm;

	اگر ((dirp = opendir(src)) == پوچ) {
		error("local opendir \"%s\": %s", src, strerror(errno));
		بازگشت -1;
	}

	وقتی (((dp = readdir(dirp)) != پوچ) && !interrupted) {
		اگر (dp->d_ino == 0)
			ادامه;
		آزاد(new_dst);
		آزاد(new_src);
		filename = dp->d_name;
		new_dst = sftp_path_append(dst, filename);
		new_src = sftp_path_append(src, filename);

		اگر (strcmp(filename, ".") == 0 || strcmp(filename, "..") == 0)
			ادامه;
		اگر (lstat(new_src, &sb) == -1) {
			logit("local lstat \"%s\": %s", filename,
			    strerror(errno));
			ret = -1;
			ادامه;
		}
		اگر (S_ISLNK(sb.st_mode)) {
			اگر (!follow_link_flag) {
				logit("%s: not a regular file", filename);
				ادامه;
			}
			/* Replace the stat contents with the symlink target */
			اگر (stat(new_src, &sb) == -1) {
				logit("local stat \"%s\": %s", filename,
				    strerror(errno));
				ret = -1;
				ادامه;
			}
		}
		اگر (S_ISDIR(sb.st_mode)) {
			اگر (upload_dir_internal(conn, new_src, new_dst,
			    depth + 1, preserve_flag, print_flag, resume,
			    fsync_flag, follow_link_flag, inplace_flag) == -1)
				ret = -1;
		} وگرنه اگر (S_ISREG(sb.st_mode)) {
			اگر (sftp_upload(conn, new_src, new_dst,
			    preserve_flag, resume, fsync_flag,
			    inplace_flag) == -1) {
				error("upload \"%s\" to \"%s\" failed",
				    new_src, new_dst);
				ret = -1;
			}
		} وگرنه
			logit("%s: not a regular file", filename);
	}
	آزاد(new_dst);
	آزاد(new_src);

	اگر (created || preserve_flag)
		sftp_setstat(conn, dst, &a);

	(تهی) closedir(dirp);
	بازگشت ret;
}

صحیح
sftp_upload_dir(ساختار sftp_conn *conn, ثابت نویسه *src, ثابت نویسه *dst,
    صحیح preserve_flag, صحیح print_flag, صحیح resume, صحیح fsync_flag,
    صحیح follow_link_flag, صحیح inplace_flag)
{
	نویسه *dst_canon;
	صحیح ret;

	اگر ((dst_canon = sftp_realpath(conn, dst)) == پوچ) {
		error("upload \"%s\": path canonicalization failed", dst);
		بازگشت -1;
	}

	ret = upload_dir_internal(conn, src, dst_canon, 0, preserve_flag,
	    print_flag, resume, fsync_flag, follow_link_flag, inplace_flag);

	آزاد(dst_canon);
	بازگشت ret;
}

ایستا تهی
handle_dest_replies(ساختار sftp_conn *to, ثابت نویسه *to_path, صحیح synchronous,
    u_int *nreqsp, u_int *write_errorp)
{
	ساختار sshbuf *پیام;
	u_char type;
	u_int id, status;
	صحیح r;
	ساختار pollfd pfd;

	اگر ((پیام = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");

	/* Try to eat replies from the upload side */
	وقتی (*nreqsp > 0) {
		debug3_f("%u outstanding replies", *nreqsp);
		اگر (!synchronous) {
			/* Bail out if no data is ready to be read */
			pfd.fd = to->fd_in;
			pfd.events = POLLIN;
			اگر ((r = poll(&pfd, 1, 0)) == -1) {
				اگر (errno == EINTR)
					بشکن;
				fatal_f("poll: %s", strerror(errno));
			} وگرنه اگر (r == 0)
				بشکن; /* fd not ready */
		}
		sshbuf_reset(پیام);
		get_پیام(to, پیام);

		اگر ((r = sshbuf_get_u8(پیام, &type)) != 0 ||
		    (r = sshbuf_get_u32(پیام, &id)) != 0)
			fatal_fr(r, "dest parse");
		debug3("Received dest reply T:%u I:%u R:%u", type, id, *nreqsp);
		اگر (type != SSH2_FXP_STATUS) {
			fatal_f("Expected SSH2_FXP_STATUS(%d) packet, got %d",
			    SSH2_FXP_STATUS, type);
		}
		اگر ((r = sshbuf_get_u32(پیام, &status)) != 0)
			fatal_fr(r, "parse dest status");
		debug3("dest SSH2_FXP_STATUS %u", status);
		اگر (status != SSH2_FX_OK) {
			/* record first error */
			اگر (*write_errorp == 0)
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
	sshbuf_free(پیام);
}

صحیح
sftp_crossload(ساختار sftp_conn *from, ساختار sftp_conn *to,
    ثابت نویسه *from_path, ثابت نویسه *to_path,
    Attrib *a, صحیح preserve_flag)
{
	ساختار sshbuf *پیام;
	صحیح write_error, read_error, r, seen_zerolen = 0;
	uint64_t offset = 0, size;
	u_int id, buflen, رقم_req, max_req, status = SSH2_FX_OK;
	u_int رقم_upload_req;
	off_t progress_counter;
	u_char *from_handle, *to_handle;
	size_t from_handle_len, to_handle_len;
	ساختار requests requests;
	ساختار request *req;
	u_char type;
	Attrib attr;

	debug2_f("crossload src \"%s\" to dst \"%s\"", from_path, to_path);

	TAILQ_INIT(&requests);

	اگر (a == پوچ) {
		اگر (sftp_stat(from, from_path, 0, &attr) != 0)
			بازگشت -1;
		a = &attr;
	}

	اگر ((a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) &&
	    (!S_ISREG(a->perm))) {
		error("download \"%s\": not a regular file", from_path);
		بازگشت(-1);
	}
	اگر (a->flags & SSH2_FILEXFER_ATTR_SIZE)
		size = a->size;
	وگرنه
		size = 0;

	buflen = from->download_buflen;
	اگر (buflen > to->upload_buflen)
		buflen = to->upload_buflen;

	/* Send open request to read side */
	اگر (send_open(from, from_path, "origin", SSH2_FXF_READ, پوچ,
	    &from_handle, &from_handle_len) != 0)
		بازگشت -1;

	/* Send open request to write side */
	a->flags &= ~SSH2_FILEXFER_ATTR_SIZE;
	a->flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a->perm &= 0777;
	اگر (!preserve_flag)
		a->flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;
	اگر (send_open(to, to_path, "dest",
	    SSH2_FXF_WRITE|SSH2_FXF_CREAT|SSH2_FXF_TRUNC, a,
	    &to_handle, &to_handle_len) != 0) {
		sftp_close(from, from_handle, from_handle_len);
		بازگشت -1;
	}

	/* Read from remote "from" and write to remote "to" */
	offset = 0;
	write_error = read_error = رقم_req = رقم_upload_req = 0;
	max_req = 1;
	progress_counter = 0;

	اگر (showprogress && size != 0) {
		start_progress_meter(progress_meter_path(from_path),
		    size, &progress_counter);
	}
	اگر ((پیام = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	وقتی (رقم_req > 0 || max_req > 0) {
		u_char *data;
		size_t len;

		/*
		 * Simulate EOF on interrupt: stop sending new requests and
		 * allow outstanding requests to drain gracefully
		 */
		اگر (interrupted) {
			اگر (رقم_req == 0) /* If we haven't started yet... */
				بشکن;
			max_req = 0;
		}

		/* Send some more requests */
		وقتی (رقم_req < max_req) {
			debug3("Request range %llu -> %llu (%d/%d)",
			    (unsigned long long)offset,
			    (unsigned long long)offset + buflen - 1,
			    رقم_req, max_req);
			req = request_enqueue(&requests, from->پیام_id++,
			    buflen, offset);
			offset += buflen;
			رقم_req++;
			send_read_request(from, req->id, req->offset,
			    req->len, from_handle, from_handle_len);
		}

		/* Try to eat replies from the upload side (nonblocking) */
		handle_dest_replies(to, to_path, 0,
		    &رقم_upload_req, &write_error);

		sshbuf_reset(پیام);
		get_پیام(from, پیام);
		اگر ((r = sshbuf_get_u8(پیام, &type)) != 0 ||
		    (r = sshbuf_get_u32(پیام, &id)) != 0)
			fatal_fr(r, "parse");
		debug3("Received origin reply T:%u I:%u R:%d",
		    type, id, max_req);

		/* Find the request in our queue */
		اگر ((req = request_find(&requests, id)) == پوچ)
			fatal("Unexpected reply %u", id);

		انتخاب (type) {
		حالت SSH2_FXP_STATUS:
			اگر ((r = sshbuf_get_u32(پیام, &status)) != 0)
				fatal_fr(r, "parse status");
			اگر (status != SSH2_FX_EOF)
				read_error = 1;
			max_req = 0;
			TAILQ_REMOVE(&requests, req, tq);
			آزاد(req);
			رقم_req--;
			بشکن;
		حالت SSH2_FXP_DATA:
			اگر ((r = sshbuf_get_string(پیام, &data, &len)) != 0)
				fatal_fr(r, "parse data");
			debug3("Received data %llu -> %llu",
			    (unsigned long long)req->offset,
			    (unsigned long long)req->offset + len - 1);
			اگر (len > req->len)
				fatal("Received more data than asked for "
				    "%zu > %zu", len, req->len);
			اگر (len == 0) {
				اگر (seen_zerolen)
					fatal_f("server sent zero data length");
				seen_zerolen = 1;
			}

			/* Write this chunk out to the destination */
			sshbuf_reset(پیام);
			اگر ((r = sshbuf_put_u8(پیام, SSH2_FXP_WRITE)) != 0 ||
			    (r = sshbuf_put_u32(پیام, to->پیام_id++)) != 0 ||
			    (r = sshbuf_put_string(پیام, to_handle,
			    to_handle_len)) != 0 ||
			    (r = sshbuf_put_u64(پیام, req->offset)) != 0 ||
			    (r = sshbuf_put_string(پیام, data, len)) != 0)
				fatal_fr(r, "compose write");
			send_پیام(to, پیام);
			debug3("Sent message SSH2_FXP_WRITE I:%u O:%llu S:%zu",
			    id, (unsigned long long)offset, len);
			رقم_upload_req++;
			progress_counter += len;
			آزاد(data);

			اگر (len == req->len) {
				TAILQ_REMOVE(&requests, req, tq);
				آزاد(req);
				رقم_req--;
			} وگرنه {
				/* Resend the request for the missing data */
				debug3("Short data block, re-requesting "
				    "%llu -> %llu (%2d)",
				    (unsigned long long)req->offset + len,
				    (unsigned long long)req->offset +
				    req->len - 1, رقم_req);
				req->id = from->پیام_id++;
				req->len -= len;
				req->offset += len;
				send_read_request(from, req->id,
				    req->offset, req->len,
				    from_handle, from_handle_len);
				/* Reduce the request size */
				اگر (len < buflen)
					buflen = MAXIMUM(MIN_READ_SIZE, len);
			}
			اگر (max_req > 0) { /* max_req = 0 iff EOF received */
				اگر (size > 0 && offset > size) {
					/* Only one request at a time
					 * after the expected EOF */
					debug3("Finish at %llu (%2d)",
					    (unsigned long long)offset,
					    رقم_req);
					max_req = 1;
				} وگرنه اگر (max_req < from->رقم_requests) {
					++max_req;
				}
			}
			بشکن;
		پیشفرض:
			fatal("Expected SSH2_FXP_DATA(%u) packet, got %u",
			    SSH2_FXP_DATA, type);
		}
	}

	اگر (showprogress && size)
		stop_progress_meter();

	/* Drain replies from the server (blocking) */
	debug3_f("waiting for %u replies from destination", رقم_upload_req);
	handle_dest_replies(to, to_path, 1, &رقم_upload_req, &write_error);

	/* Sanity check */
	اگر (TAILQ_FIRST(&requests) != پوچ)
		fatal("Transfer complete, but requests still in queue");
	/* Truncate at 0 length on interrupt or error to avoid holes at dest */
	اگر (read_error || write_error || interrupted) {
		debug("truncating \"%s\" at 0", to_path);
		sftp_close(to, to_handle, to_handle_len);
		آزاد(to_handle);
		اگر (send_open(to, to_path, "dest",
		    SSH2_FXF_WRITE|SSH2_FXF_CREAT|SSH2_FXF_TRUNC, a,
		    &to_handle, &to_handle_len) != 0) {
			error("dest truncate \"%s\" failed", to_path);
			to_handle = پوچ;
		}
	}
	اگر (read_error) {
		error("read origin \"%s\": %s", from_path, fx2txt(status));
		status = -1;
		sftp_close(from, from_handle, from_handle_len);
		اگر (to_handle != پوچ)
			sftp_close(to, to_handle, to_handle_len);
	} وگرنه اگر (write_error) {
		error("write dest \"%s\": %s", to_path, fx2txt(write_error));
		status = SSH2_FX_FAILURE;
		sftp_close(from, from_handle, from_handle_len);
		اگر (to_handle != پوچ)
			sftp_close(to, to_handle, to_handle_len);
	} وگرنه {
		اگر (sftp_close(from, from_handle, from_handle_len) != 0 ||
		    interrupted)
			status = -1;
		وگرنه
			status = SSH2_FX_OK;
		اگر (to_handle != پوچ) {
			/* Need to resend utimes after write */
			اگر (preserve_flag)
				sftp_fsetstat(to, to_handle, to_handle_len, a);
			sftp_close(to, to_handle, to_handle_len);
		}
	}
	sshbuf_free(پیام);
	آزاد(from_handle);
	آزاد(to_handle);

	بازگشت status == SSH2_FX_OK ? 0 : -1;
}

ایستا صحیح
crossload_dir_internal(ساختار sftp_conn *from, ساختار sftp_conn *to,
    ثابت نویسه *from_path, ثابت نویسه *to_path,
    صحیح depth, Attrib *dirattrib, صحیح preserve_flag, صحیح print_flag,
    صحیح follow_link_flag)
{
	صحیح i, ret = 0, created = 0;
	SFTP_DIRENT **dir_entries;
	نویسه *filename, *new_from_path = پوچ, *new_to_path = پوچ;
	mode_t mode = 0777;
	Attrib *a, curdir, ldirattrib, newdir, lsym;

	debug2_f("crossload dir src \"%s\" to dst \"%s\"", from_path, to_path);

	اگر (depth >= MAX_DIR_DEPTH) {
		error("Maximum directory depth exceeded: %d levels", depth);
		بازگشت -1;
	}

	اگر (dirattrib == پوچ) {
		اگر (sftp_stat(from, from_path, 1, &ldirattrib) != 0) {
			error("stat remote \"%s\" failed", from_path);
			بازگشت -1;
		}
		dirattrib = &ldirattrib;
	}
	اگر (!S_ISDIR(dirattrib->perm)) {
		error("\"%s\" is not a directory", from_path);
		بازگشت -1;
	}
	اگر (print_flag && print_flag != SFTP_PROGRESS_ONLY)
		mprintf("Retrieving %s\n", from_path);

	curdir = *dirattrib; /* dirattrib will be clobbered */
	curdir.flags &= ~SSH2_FILEXFER_ATTR_SIZE;
	curdir.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	اگر ((curdir.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) == 0) {
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
	اگر (sftp_mkdir(to, to_path, &curdir, 0) == 0)
		created = 1;
	وگرنه {
		اگر (sftp_stat(to, to_path, 0, &newdir) != 0)
			بازگشت -1;
		اگر (!S_ISDIR(newdir.perm)) {
			error("\"%s\" exists but is not a directory", to_path);
			بازگشت -1;
		}
	}
	curdir.perm = mode;

	اگر (sftp_readdir(from, from_path, &dir_entries) == -1) {
		error("origin readdir \"%s\" failed", from_path);
		بازگشت -1;
	}

	برای (i = 0; dir_entries[i] != پوچ && !interrupted; i++) {
		آزاد(new_from_path);
		آزاد(new_to_path);

		filename = dir_entries[i]->filename;
		new_from_path = sftp_path_append(from_path, filename);
		new_to_path = sftp_path_append(to_path, filename);

		a = &dir_entries[i]->a;
		اگر (S_ISLNK(a->perm)) {
			اگر (!follow_link_flag) {
				logit("%s: not a regular file", filename);
				ادامه;
			}
			/* Replace the stat contents with the symlink target */
			اگر (sftp_stat(from, new_from_path, 1, &lsym) != 0) {
				logit("remote stat \"%s\" failed",
				    new_from_path);
				ret = -1;
				ادامه;
			}
			a = &lsym;
		}
		اگر (S_ISDIR(a->perm)) {
			اگر (strcmp(filename, ".") == 0 ||
			    strcmp(filename, "..") == 0)
				ادامه;
			اگر (crossload_dir_internal(from, to,
			    new_from_path, new_to_path,
			    depth + 1, a, preserve_flag,
			    print_flag, follow_link_flag) == -1)
				ret = -1;
		} وگرنه اگر (S_ISREG(a->perm)) {
			اگر (sftp_crossload(from, to, new_from_path,
			    new_to_path, a, preserve_flag) == -1) {
				error("crossload \"%s\" to \"%s\" failed",
				    new_from_path, new_to_path);
				ret = -1;
			}
		} وگرنه {
			logit("origin \"%s\": not a regular file",
			    new_from_path);
		}
	}
	آزاد(new_to_path);
	آزاد(new_from_path);

	اگر (created || preserve_flag)
		sftp_setstat(to, to_path, &curdir);

	sftp_free_dirents(dir_entries);

	بازگشت ret;
}

صحیح
sftp_crossload_dir(ساختار sftp_conn *from, ساختار sftp_conn *to,
    ثابت نویسه *from_path, ثابت نویسه *to_path,
    Attrib *dirattrib, صحیح preserve_flag, صحیح print_flag, صحیح follow_link_flag)
{
	نویسه *from_path_canon;
	صحیح ret;

	اگر ((from_path_canon = sftp_realpath(from, from_path)) == پوچ) {
		error("crossload \"%s\": path canonicalization failed",
		    from_path);
		بازگشت -1;
	}

	ret = crossload_dir_internal(from, to, from_path_canon, to_path, 0,
	    dirattrib, preserve_flag, print_flag, follow_link_flag);
	آزاد(from_path_canon);
	بازگشت ret;
}

صحیح
sftp_can_get_users_groups_by_id(ساختار sftp_conn *conn)
{
	بازگشت (conn->exts & SFTP_EXT_GETUSERSGROUPS_BY_ID) != 0;
}

صحیح
sftp_get_users_groups_by_id(ساختار sftp_conn *conn,
    ثابت u_int *uids, u_int nuids,
    ثابت u_int *gids, u_int ngids,
    نویسه ***usernamesp, نویسه ***groupnamesp)
{
	ساختار sshbuf *پیام, *uidbuf, *gidbuf;
	u_int i, expected_id, id;
	نویسه *name, **usernames = پوچ, **groupnames = پوچ;
	u_char type;
	صحیح r;

	*usernamesp = *groupnamesp = پوچ;
	اگر (!sftp_can_get_users_groups_by_id(conn))
		بازگشت SSH_ERR_FEATURE_UNSUPPORTED;

	اگر ((پیام = sshbuf_new()) == پوچ ||
	    (uidbuf = sshbuf_new()) == پوچ ||
	    (gidbuf = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	expected_id = id = conn->پیام_id++;
	debug2("Sending SSH2_FXP_EXTENDED(users-groups-by-id@openssh.com)");
	برای (i = 0; i < nuids; i++) {
		اگر ((r = sshbuf_put_u32(uidbuf, uids[i])) != 0)
			fatal_fr(r, "compose uids");
	}
	برای (i = 0; i < ngids; i++) {
		اگر ((r = sshbuf_put_u32(gidbuf, gids[i])) != 0)
			fatal_fr(r, "compose gids");
	}
	اگر ((r = sshbuf_put_u8(پیام, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(پیام, id)) != 0 ||
	    (r = sshbuf_put_cstring(پیام,
	    "users-groups-by-id@openssh.com")) != 0 ||
	    (r = sshbuf_put_stringb(پیام, uidbuf)) != 0 ||
	    (r = sshbuf_put_stringb(پیام, gidbuf)) != 0)
		fatal_fr(r, "compose");
	send_پیام(conn, پیام);
	get_پیام(conn, پیام);
	اگر ((r = sshbuf_get_u8(پیام, &type)) != 0 ||
	    (r = sshbuf_get_u32(پیام, &id)) != 0)
		fatal_fr(r, "parse");
	اگر (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	اگر (type == SSH2_FXP_STATUS) {
		u_int status;
		نویسه *errmsg;

		اگر ((r = sshbuf_get_u32(پیام, &status)) != 0 ||
		    (r = sshbuf_get_cstring(پیام, &errmsg, پوچ)) != 0)
			fatal_fr(r, "parse status");
		error("users-groups-by-id %s",
		    *errmsg == '\0' ? fx2txt(status) : errmsg);
		آزاد(errmsg);
		sshbuf_free(پیام);
		sshbuf_free(uidbuf);
		sshbuf_free(gidbuf);
		بازگشت -1;
	} وگرنه اگر (type != SSH2_FXP_EXTENDED_REPLY)
		fatal("Expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_REPLY, type);

	/* reuse */
	sshbuf_free(uidbuf);
	sshbuf_free(gidbuf);
	uidbuf = gidbuf = پوچ;
	اگر ((r = sshbuf_froms(پیام, &uidbuf)) != 0 ||
	    (r = sshbuf_froms(پیام, &gidbuf)) != 0)
		fatal_fr(r, "parse response");
	اگر (nuids > 0) {
		usernames = xcalloc(nuids, اندازه(*usernames));
		برای (i = 0; i < nuids; i++) {
			اگر ((r = sshbuf_get_cstring(uidbuf, &name, پوچ)) != 0)
				fatal_fr(r, "parse user name");
			/* Handle unresolved names */
			اگر (*name == '\0') {
				آزاد(name);
				name = پوچ;
			}
			usernames[i] = name;
		}
	}
	اگر (ngids > 0) {
		groupnames = xcalloc(ngids, اندازه(*groupnames));
		برای (i = 0; i < ngids; i++) {
			اگر ((r = sshbuf_get_cstring(gidbuf, &name, پوچ)) != 0)
				fatal_fr(r, "parse user name");
			/* Handle unresolved names */
			اگر (*name == '\0') {
				آزاد(name);
				name = پوچ;
			}
			groupnames[i] = name;
		}
	}
	اگر (sshbuf_len(uidbuf) != 0)
		fatal_f("unexpected extra username data");
	اگر (sshbuf_len(gidbuf) != 0)
		fatal_f("unexpected extra groupname data");
	sshbuf_free(uidbuf);
	sshbuf_free(gidbuf);
	sshbuf_free(پیام);
	/* success */
	*usernamesp = usernames;
	*groupnamesp = groupnames;
	بازگشت 0;
}

نویسه *
sftp_path_append(ثابت نویسه *p1, ثابت نویسه *p2)
{
	نویسه *ret;
	size_t len = strlen(p1) + strlen(p2) + 2;

	ret = xmalloc(len);
	strlcpy(ret, p1, len);
	اگر (p1[0] != '\0' && p1[strlen(p1) - 1] != '/')
		strlcat(ret, "/", len);
	strlcat(ret, p2, len);

	بازگشت(ret);
}

/*
 * Arg p must be dynamically allocated.  It will either be returned or
 * freed and a replacement allocated.  Caller must free returned string.
 */
نویسه *
sftp_make_absolute(نویسه *p, ثابت نویسه *pwd)
{
	نویسه *abs_str;

	/* Derelativise */
	اگر (p && !path_absolute(p)) {
		abs_str = sftp_path_append(pwd, p);
		آزاد(p);
		بازگشت(abs_str);
	} وگرنه
		بازگشت(p);
}

صحیح
sftp_remote_is_dir(ساختار sftp_conn *conn, ثابت نویسه *path)
{
	Attrib a;

	/* XXX: report errors? */
	اگر (sftp_stat(conn, path, 1, &a) != 0)
		بازگشت(0);
	اگر (!(a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS))
		بازگشت(0);
	بازگشت S_ISDIR(a.perm);
}


/* Check whether path returned from glob(..., GLOB_MARK, ...) is a directory */
صحیح
sftp_globpath_is_dir(ثابت نویسه *pathname)
{
	size_t l = strlen(pathname);

	بازگشت l > 0 && pathname[l - 1] == '/';
}

