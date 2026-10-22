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

#include "includes.h"

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/statvfs.h>
#include <sys/uio.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "xmalloc.h"
#include "ssherr.h"
#include "sshbuf.h"
#include "log.h"
#include "atomicio.h"
#include "progressmeter.h"
#include "misc.h"
#include "utf8.h"

#include "sftp.h"
#include "sftp-common.h"
#include "sftp-client.h"

extern ca_ncala sig_atomic_t interrupted;
extern පූර්ණ_සංඛ්‍යා showprogress;

/* Default size of buffer for up/download (fix sftp.1 scp.1 if changed) */
#define DEFAULT_COPY_BUFLEN	32768

/* Default number of concurrent xfer requests (fix sftp.1 scp.1 if changed) */
#define DEFAULT_NUM_REQUESTS	64

/* Minimum amount of data to read at a time */
#define MIN_READ_SIZE	512

/* Maximum depth to descend in directory trees */
#define MAX_DIR_DEPTH 64

/* Directory separator characters */
#ifdef HAVE_CYGWIN
# define SFTP_DIRECTORY_CHARS      "/\\"
#නැතහොත් /* HAVE_CYGWIN */
# define SFTP_DIRECTORY_CHARS      "/"
#endif /* HAVE_CYGWIN */

sa_nracanaa sftp_conn {
	පූර්ණ_සංඛ්‍යා fd_in;
	පූර්ණ_සංඛ්‍යා fd_out;
	u_int download_buflen;
	u_int upload_buflen;
	u_int num_requests;
	u_int version;
	u_int msg_id;
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
	sa_nracanaa bwlimit bwlimit_in, bwlimit_out;
};

/* Tracks in-progress requests during file transfers */
sa_nracanaa request {
	u_int id;
	size_t len;
	uint64_t offset;
	TAILQ_ENTRY(request) tq;
};
TAILQ_HEAD(requests, request);

static u_char *
get_handle(sa_nracanaa sftp_conn *conn, u_int expected_id, size_t *len,
    const var_na *errfmt, ...) __attribute__((format(printf, 4, 5)));

static sa_nracanaa request *
request_enqueue(sa_nracanaa requests *requests, u_int id, size_t len,
    uint64_t offset)
{
	sa_nracanaa request *req;

	req = xcalloc(1, parimaa_na(*req));
	req->id = id;
	req->len = len;
	req->offset = offset;
	TAILQ_INSERT_TAIL(requests, req, tq);
	ආපසු req;
}

static sa_nracanaa request *
request_find(sa_nracanaa requests *requests, u_int id)
{
	sa_nracanaa request *req;

	සඳහා (req = TAILQ_FIRST(requests);
	    req != NULL && req->id != id;
	    req = TAILQ_NEXT(req, tq))
		;
	ආපසු req;
}

static පූර්ණ_සංඛ්‍යා
sftpio(void *_bwlimit, size_t amount)
{
	sa_nracanaa bwlimit *bwlimit = (sa_nracanaa bwlimit *)_bwlimit;

	refresh_progress_meter(0);
	නම් (bwlimit != NULL)
		bandwidth_limit(bwlimit, amount);
	ආපසු 0;
}

static void
send_msg(sa_nracanaa sftp_conn *conn, sa_nracanaa sshbuf *m)
{
	u_char mlen[4];
	sa_nracanaa iovec iov[2];

	නම් (sshbuf_len(m) > SFTP_MAX_MSG_LENGTH)
		fatal("Outbound message too long %zu", sshbuf_len(m));

	/* Send length first */
	put_u32(mlen, sshbuf_len(m));
	iov[0].iov_base = mlen;
	iov[0].iov_len = parimaa_na(mlen);
	iov[1].iov_base = (u_char *)sshbuf_ptr(m);
	iov[1].iov_len = sshbuf_len(m);

	නම් (atomiciov6(writev, conn->fd_out, iov, 2, sftpio,
	    conn->limit_kbps > 0 ? &conn->bwlimit_out : NULL) !=
	    sshbuf_len(m) + parimaa_na(mlen))
		fatal("Couldn't send packet: %s", strerror(errno));

	sshbuf_reset(m);
}

static void
get_msg_extended(sa_nracanaa sftp_conn *conn, sa_nracanaa sshbuf *m, පූර්ණ_සංඛ්‍යා initial)
{
	u_int msg_len;
	u_char *p;
	පූර්ණ_සංඛ්‍යා r;

	sshbuf_reset(m);
	නම් ((r = sshbuf_reserve(m, 4, &p)) != 0)
		fatal_fr(r, "reserve");
	නම් (atomicio6(read, conn->fd_in, p, 4, sftpio,
	    conn->limit_kbps > 0 ? &conn->bwlimit_in : NULL) != 4) {
		නම් (errno == EPIPE || errno == ECONNRESET)
			fatal("Connection closed");
		නැතහොත්
			fatal("Couldn't read packet: %s", strerror(errno));
	}

	නම් ((r = sshbuf_get_u32(m, &msg_len)) != 0)
		fatal_fr(r, "sshbuf_get_u32");
	නම් (msg_len > SFTP_MAX_MSG_LENGTH) {
		do_log2(initial ? SYSLOG_LEVEL_ERROR : SYSLOG_LEVEL_FATAL,
		    "Received message too long %u", msg_len);
		fatal("Ensure the remote shell produces no output "
		    "for non-interactive sessions.");
	}

	නම් ((r = sshbuf_reserve(m, msg_len, &p)) != 0)
		fatal_fr(r, "reserve");
	නම් (atomicio6(read, conn->fd_in, p, msg_len, sftpio,
	    conn->limit_kbps > 0 ? &conn->bwlimit_in : NULL)
	    != msg_len) {
		නම් (errno == EPIPE)
			fatal("Connection closed");
		නැතහොත්
			fatal("Read packet: %s", strerror(errno));
	}
}

static void
get_msg(sa_nracanaa sftp_conn *conn, sa_nracanaa sshbuf *m)
{
	get_msg_extended(conn, m, 0);
}

static void
send_string_request(sa_nracanaa sftp_conn *conn, u_int id, u_int code, const var_na *s,
    u_int len)
{
	sa_nracanaa sshbuf *msg;
	පූර්ණ_සංඛ්‍යා r;

	නම් ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	නම් ((r = sshbuf_put_u8(msg, code)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_string(msg, s, len)) != 0)
		fatal_fr(r, "compose");
	send_msg(conn, msg);
	debug3("Sent message fd %d T:%u I:%u", conn->fd_out, code, id);
	sshbuf_free(msg);
}

static void
send_string_attrs_request(sa_nracanaa sftp_conn *conn, u_int id, u_int code,
    const void *s, u_int len, Attrib *a)
{
	sa_nracanaa sshbuf *msg;
	පූර්ණ_සංඛ්‍යා r;

	නම් ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	නම් ((r = sshbuf_put_u8(msg, code)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_string(msg, s, len)) != 0 ||
	    (r = encode_attrib(msg, a)) != 0)
		fatal_fr(r, "compose");
	send_msg(conn, msg);
	debug3("Sent message fd %d T:%u I:%u F:0x%04x M:%05o",
	    conn->fd_out, code, id, a->flags, a->perm);
	sshbuf_free(msg);
}

static u_int
get_status(sa_nracanaa sftp_conn *conn, u_int expected_id)
{
	sa_nracanaa sshbuf *msg;
	u_char type;
	u_int id, status;
	පූර්ණ_සංඛ්‍යා r;

	නම් ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	get_msg(conn, msg);
	නම් ((r = sshbuf_get_u8(msg, &type)) != 0 ||
	    (r = sshbuf_get_u32(msg, &id)) != 0)
		fatal_fr(r, "compose");

	නම් (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	නම් (type != SSH2_FXP_STATUS)
		fatal("Expected SSH2_FXP_STATUS(%u) packet, got %u",
		    SSH2_FXP_STATUS, type);

	නම් ((r = sshbuf_get_u32(msg, &status)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(msg);

	debug3("SSH2_FXP_STATUS %u", status);

	ආපසු status;
}

static u_char *
get_handle(sa_nracanaa sftp_conn *conn, u_int expected_id, size_t *len,
    const var_na *errfmt, ...)
{
	sa_nracanaa sshbuf *msg;
	u_int id, status;
	u_char type;
	u_char *handle;
	var_na errmsg[256];
	va_list args;
	පූර්ණ_සංඛ්‍යා r;

	va_start(args, errfmt);
	නම් (errfmt != NULL)
		vsnprintf(errmsg, parimaa_na(errmsg), errfmt, args);
	va_end(args);

	නම් ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	get_msg(conn, msg);
	නම් ((r = sshbuf_get_u8(msg, &type)) != 0 ||
	    (r = sshbuf_get_u32(msg, &id)) != 0)
		fatal_fr(r, "parse");

	නම් (id != expected_id)
		fatal("%s: ID mismatch (%u != %u)",
		    errfmt == NULL ? __func__ : errmsg, id, expected_id);
	නම් (type == SSH2_FXP_STATUS) {
		නම් ((r = sshbuf_get_u32(msg, &status)) != 0)
			fatal_fr(r, "parse status");
		නම් (errfmt != NULL)
			error("%s: %s", errmsg, fx2txt(status));
		sshbuf_free(msg);
		ආපසු(NULL);
	} නැතහොත් නම් (type != SSH2_FXP_HANDLE)
		fatal("%s: Expected SSH2_FXP_HANDLE(%u) packet, got %u",
		    errfmt == NULL ? __func__ : errmsg, SSH2_FXP_HANDLE, type);

	නම් ((r = sshbuf_get_string(msg, &handle, len)) != 0)
		fatal_fr(r, "parse handle");
	sshbuf_free(msg);

	ආපසු handle;
}

static පූර්ණ_සංඛ්‍යා
get_decode_stat(sa_nracanaa sftp_conn *conn, u_int expected_id, පූර්ණ_සංඛ්‍යා quiet, Attrib *a)
{
	sa_nracanaa sshbuf *msg;
	u_int id;
	u_char type;
	පූර්ණ_සංඛ්‍යා r;
	Attrib attr;

	නම් (a != NULL)
		memset(a, '\0', parimaa_na(*a));
	නම් ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	get_msg(conn, msg);

	නම් ((r = sshbuf_get_u8(msg, &type)) != 0 ||
	    (r = sshbuf_get_u32(msg, &id)) != 0)
		fatal_fr(r, "parse");

	නම් (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	නම් (type == SSH2_FXP_STATUS) {
		u_int status;

		නම් ((r = sshbuf_get_u32(msg, &status)) != 0)
			fatal_fr(r, "parse status");
		නම් (quiet)
			debug("stat remote: %s", fx2txt(status));
		නැතහොත්
			error("stat remote: %s", fx2txt(status));
		sshbuf_free(msg);
		ආපසු -1;
	} නැතහොත් නම් (type != SSH2_FXP_ATTRS) {
		fatal("Expected SSH2_FXP_ATTRS(%u) packet, got %u",
		    SSH2_FXP_ATTRS, type);
	}
	නම් ((r = decode_attrib(msg, &attr)) != 0) {
		error_fr(r, "decode_attrib");
		sshbuf_free(msg);
		ආපසු -1;
	}
	/* success */
	නම් (a != NULL)
		*a = attr;
	debug3("Received stat reply T:%u I:%u F:0x%04x M:%05o",
	    type, id, attr.flags, attr.perm);
	sshbuf_free(msg);

	ආපසු 0;
}

static පූර්ණ_සංඛ්‍යා
get_decode_statvfs(sa_nracanaa sftp_conn *conn, sa_nracanaa sftp_statvfs *st,
    u_int expected_id, පූර්ණ_සංඛ්‍යා quiet)
{
	sa_nracanaa sshbuf *msg;
	u_char type;
	u_int id;
	uint64_t flag;
	පූර්ණ_සංඛ්‍යා r;

	නම් ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	get_msg(conn, msg);

	නම් ((r = sshbuf_get_u8(msg, &type)) != 0 ||
	    (r = sshbuf_get_u32(msg, &id)) != 0)
		fatal_fr(r, "parse");

	debug3("Received statvfs reply T:%u I:%u", type, id);
	නම් (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	නම් (type == SSH2_FXP_STATUS) {
		u_int status;

		නම් ((r = sshbuf_get_u32(msg, &status)) != 0)
			fatal_fr(r, "parse status");
		නම් (quiet)
			debug("remote statvfs: %s", fx2txt(status));
		නැතහොත්
			error("remote statvfs: %s", fx2txt(status));
		sshbuf_free(msg);
		ආපසු -1;
	} නැතහොත් නම් (type != SSH2_FXP_EXTENDED_REPLY) {
		fatal("Expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_REPLY, type);
	}

	memset(st, 0, parimaa_na(*st));
	නම් ((r = sshbuf_get_u64(msg, &st->f_bsize)) != 0 ||
	    (r = sshbuf_get_u64(msg, &st->f_frsize)) != 0 ||
	    (r = sshbuf_get_u64(msg, &st->f_blocks)) != 0 ||
	    (r = sshbuf_get_u64(msg, &st->f_bfree)) != 0 ||
	    (r = sshbuf_get_u64(msg, &st->f_bavail)) != 0 ||
	    (r = sshbuf_get_u64(msg, &st->f_files)) != 0 ||
	    (r = sshbuf_get_u64(msg, &st->f_ffree)) != 0 ||
	    (r = sshbuf_get_u64(msg, &st->f_favail)) != 0 ||
	    (r = sshbuf_get_u64(msg, &st->f_fsid)) != 0 ||
	    (r = sshbuf_get_u64(msg, &flag)) != 0 ||
	    (r = sshbuf_get_u64(msg, &st->f_namemax)) != 0)
		fatal_fr(r, "parse statvfs");

	st->f_flag = (flag & SSH2_FXE_STATVFS_ST_RDONLY) ? ST_RDONLY : 0;
	st->f_flag |= (flag & SSH2_FXE_STATVFS_ST_NOSUID) ? ST_NOSUID : 0;

	sshbuf_free(msg);

	ආපසු 0;
}

sa_nracanaa sftp_conn *
sftp_init(පූර්ණ_සංඛ්‍යා fd_in, පූර්ණ_සංඛ්‍යා fd_out, u_int transfer_buflen, u_int num_requests,
    uint64_t limit_kbps)
{
	u_char type;
	sa_nracanaa sshbuf *msg;
	sa_nracanaa sftp_conn *ret;
	පූර්ණ_සංඛ්‍යා r;

	ret = xcalloc(1, parimaa_na(*ret));
	ret->msg_id = 1;
	ret->fd_in = fd_in;
	ret->fd_out = fd_out;
	ret->download_buflen = ret->upload_buflen =
	    transfer_buflen ? transfer_buflen : DEFAULT_COPY_BUFLEN;
	ret->num_requests =
	    num_requests ? num_requests : DEFAULT_NUM_REQUESTS;
	ret->exts = 0;
	ret->limit_kbps = 0;

	නම් ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	නම් ((r = sshbuf_put_u8(msg, SSH2_FXP_INIT)) != 0 ||
	    (r = sshbuf_put_u32(msg, SSH2_FILEXFER_VERSION)) != 0)
		fatal_fr(r, "parse");

	send_msg(ret, msg);

	get_msg_extended(ret, msg, 1);

	/* Expecting a VERSION reply */
	නම් ((r = sshbuf_get_u8(msg, &type)) != 0)
		fatal_fr(r, "parse type");
	නම් (type != SSH2_FXP_VERSION) {
		error("Invalid packet back from SSH2_FXP_INIT (type %u)",
		    type);
		sshbuf_free(msg);
		free(ret);
		ආපසු(NULL);
	}
	නම් ((r = sshbuf_get_u32(msg, &ret->version)) != 0)
		fatal_fr(r, "parse version");

	debug2("Remote version: %u", ret->version);

	/* Check for extensions */
	අතරතුර (sshbuf_len(msg) > 0) {
		var_na *name;
		u_char *value;
		size_t vlen;
		පූර්ණ_සංඛ්‍යා known = 0;

		නම් ((r = sshbuf_get_cstring(msg, &name, NULL)) != 0 ||
		    (r = sshbuf_get_string(msg, &value, &vlen)) != 0)
			fatal_fr(r, "parse extension");
		නම් (strcmp(name, "posix-rename@openssh.com") == 0 &&
		    strcmp((var_na *)value, "1") == 0) {
			ret->exts |= SFTP_EXT_POSIX_RENAME;
			known = 1;
		} නැතහොත් නම් (strcmp(name, "statvfs@openssh.com") == 0 &&
		    strcmp((var_na *)value, "2") == 0) {
			ret->exts |= SFTP_EXT_STATVFS;
			known = 1;
		} නැතහොත් නම් (strcmp(name, "fstatvfs@openssh.com") == 0 &&
		    strcmp((var_na *)value, "2") == 0) {
			ret->exts |= SFTP_EXT_FSTATVFS;
			known = 1;
		} නැතහොත් නම් (strcmp(name, "hardlink@openssh.com") == 0 &&
		    strcmp((var_na *)value, "1") == 0) {
			ret->exts |= SFTP_EXT_HARDLINK;
			known = 1;
		} නැතහොත් නම් (strcmp(name, "fsync@openssh.com") == 0 &&
		    strcmp((var_na *)value, "1") == 0) {
			ret->exts |= SFTP_EXT_FSYNC;
			known = 1;
		} නැතහොත් නම් (strcmp(name, "lsetstat@openssh.com") == 0 &&
		    strcmp((var_na *)value, "1") == 0) {
			ret->exts |= SFTP_EXT_LSETSTAT;
			known = 1;
		} නැතහොත් නම් (strcmp(name, "limits@openssh.com") == 0 &&
		    strcmp((var_na *)value, "1") == 0) {
			ret->exts |= SFTP_EXT_LIMITS;
			known = 1;
		} නැතහොත් නම් (strcmp(name, "expand-path@openssh.com") == 0 &&
		    strcmp((var_na *)value, "1") == 0) {
			ret->exts |= SFTP_EXT_PATH_EXPAND;
			known = 1;
		} නැතහොත් නම් (strcmp(name, "copy-data") == 0 &&
		    strcmp((var_na *)value, "1") == 0) {
			ret->exts |= SFTP_EXT_COPY_DATA;
			known = 1;
		} නැතහොත් නම් (strcmp(name,
		    "users-groups-by-id@openssh.com") == 0 &&
		    strcmp((var_na *)value, "1") == 0) {
			ret->exts |= SFTP_EXT_GETUSERSGROUPS_BY_ID;
			known = 1;
		}
		නම් (known) {
			debug2("Server supports extension \"%s\" revision %s",
			    name, value);
		} නැතහොත් {
			debug2("Unrecognised server extension \"%s\"", name);
		}
		free(name);
		free(value);
	}

	sshbuf_free(msg);

	/* Query the server for its limits */
	නම් (ret->exts & SFTP_EXT_LIMITS) {
		sa_nracanaa sftp_limits limits;
		නම් (sftp_get_limits(ret, &limits) != 0)
			fatal_f("limits failed");

		/* If the caller did not specify, find a good value */
		නම් (transfer_buflen == 0) {
			ret->download_buflen = MINIMUM(limits.read_length,
			    SFTP_MAX_MSG_LENGTH - 1024);
			ret->upload_buflen = MINIMUM(limits.write_length,
			    SFTP_MAX_MSG_LENGTH - 1024);
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
	නම් (ret->version == 0) {
		ret->download_buflen = MINIMUM(ret->download_buflen, 20480);
		ret->upload_buflen = MINIMUM(ret->upload_buflen, 20480);
	}

	ret->limit_kbps = limit_kbps;
	නම් (ret->limit_kbps > 0) {
		bandwidth_limit_init(&ret->bwlimit_in, ret->limit_kbps,
		    ret->download_buflen);
		bandwidth_limit_init(&ret->bwlimit_out, ret->limit_kbps,
		    ret->upload_buflen);
	}

	ආපසු ret;
}

void
sftp_free(sa_nracanaa sftp_conn *conn)
{
	නම් (conn == NULL)
		ආපසු;
	freezero(conn, parimaa_na(*conn));
}

u_int
sftp_proto_version(sa_nracanaa sftp_conn *conn)
{
	ආපසු conn->version;
}

පූර්ණ_සංඛ්‍යා
sftp_get_limits(sa_nracanaa sftp_conn *conn, sa_nracanaa sftp_limits *limits)
{
	u_int id, msg_id;
	u_char type;
	sa_nracanaa sshbuf *msg;
	පූර්ණ_සංඛ්‍යා r;

	නම් ((conn->exts & SFTP_EXT_LIMITS) == 0) {
		error("Server does not support limits@openssh.com extension");
		ආපසු -1;
	}

	නම් ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	id = conn->msg_id++;
	නම් ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, "limits@openssh.com")) != 0)
		fatal_fr(r, "compose");
	send_msg(conn, msg);
	debug3("Sent message limits@openssh.com I:%u", id);

	get_msg(conn, msg);

	නම් ((r = sshbuf_get_u8(msg, &type)) != 0 ||
	    (r = sshbuf_get_u32(msg, &msg_id)) != 0)
		fatal_fr(r, "parse");

	debug3("Received limits reply T:%u I:%u", type, msg_id);
	නම් (id != msg_id)
		fatal("ID mismatch (%u != %u)", msg_id, id);
	නම් (type != SSH2_FXP_EXTENDED_REPLY) {
		debug_f("expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_REPLY, type);
		/* Disable the limits extension */
		conn->exts &= ~SFTP_EXT_LIMITS;
		sshbuf_free(msg);
		ආපසු -1;
	}

	memset(limits, 0, parimaa_na(*limits));
	නම් ((r = sshbuf_get_u64(msg, &limits->packet_length)) != 0 ||
	    (r = sshbuf_get_u64(msg, &limits->read_length)) != 0 ||
	    (r = sshbuf_get_u64(msg, &limits->write_length)) != 0 ||
	    (r = sshbuf_get_u64(msg, &limits->open_handles)) != 0)
		fatal_fr(r, "parse limits");

	sshbuf_free(msg);

	ආපසු 0;
}

පූර්ණ_සංඛ්‍යා
sftp_close(sa_nracanaa sftp_conn *conn, const u_char *handle, u_int handle_len)
{
	u_int id, status;
	sa_nracanaa sshbuf *msg;
	පූර්ණ_සංඛ්‍යා r;

	නම් ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	id = conn->msg_id++;
	නම් ((r = sshbuf_put_u8(msg, SSH2_FXP_CLOSE)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_string(msg, handle, handle_len)) != 0)
		fatal_fr(r, "parse");
	send_msg(conn, msg);
	debug3("Sent message SSH2_FXP_CLOSE I:%u", id);

	status = get_status(conn, id);
	නම් (status != SSH2_FX_OK)
		error("close remote: %s", fx2txt(status));

	sshbuf_free(msg);

	ආපසු status == SSH2_FX_OK ? 0 : -1;
}


static පූර්ණ_සංඛ්‍යා
sftp_lsreaddir(sa_nracanaa sftp_conn *conn, const var_na *path, පූර්ණ_සංඛ්‍යා print_flag,
    SFTP_DIRENT ***dir)
{
	sa_nracanaa sshbuf *msg;
	u_int count, id, i, expected_id, ents = 0;
	size_t handle_len;
	u_char type, *handle;
	පූර්ණ_සංඛ්‍යා status = SSH2_FX_FAILURE;
	පූර්ණ_සංඛ්‍යා r;

	නම් (dir)
		*dir = NULL;

	id = conn->msg_id++;

	නම් ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	නම් ((r = sshbuf_put_u8(msg, SSH2_FXP_OPENDIR)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, path)) != 0)
		fatal_fr(r, "compose OPENDIR");
	send_msg(conn, msg);

	handle = get_handle(conn, id, &handle_len,
	    "remote readdir(\"%s\")", path);
	නම් (handle == NULL) {
		sshbuf_free(msg);
		ආපසු -1;
	}

	නම් (dir) {
		ents = 0;
		*dir = xcalloc(1, parimaa_na(**dir));
		(*dir)[0] = NULL;
	}

	සඳහා (; !interrupted;) {
		id = expected_id = conn->msg_id++;

		debug3("Sending SSH2_FXP_READDIR I:%u", id);

		sshbuf_reset(msg);
		නම් ((r = sshbuf_put_u8(msg, SSH2_FXP_READDIR)) != 0 ||
		    (r = sshbuf_put_u32(msg, id)) != 0 ||
		    (r = sshbuf_put_string(msg, handle, handle_len)) != 0)
			fatal_fr(r, "compose READDIR");
		send_msg(conn, msg);

		sshbuf_reset(msg);

		get_msg(conn, msg);

		නම් ((r = sshbuf_get_u8(msg, &type)) != 0 ||
		    (r = sshbuf_get_u32(msg, &id)) != 0)
			fatal_fr(r, "parse");

		debug3("Received reply T:%u I:%u", type, id);

		නම් (id != expected_id)
			fatal("ID mismatch (%u != %u)", id, expected_id);

		නම් (type == SSH2_FXP_STATUS) {
			u_int rstatus;

			නම් ((r = sshbuf_get_u32(msg, &rstatus)) != 0)
				fatal_fr(r, "parse status");
			debug3("Received SSH2_FXP_STATUS %d", rstatus);
			නම් (rstatus == SSH2_FX_EOF)
				bha_nga;
			error("Couldn't read directory: %s", fx2txt(rstatus));
			goto out;
		} නැතහොත් නම් (type != SSH2_FXP_NAME)
			fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
			    SSH2_FXP_NAME, type);

		නම් ((r = sshbuf_get_u32(msg, &count)) != 0)
			fatal_fr(r, "parse count");
		නම් (count > SSHBUF_SIZE_MAX)
			fatal_f("nonsensical number of entries");
		නම් (count == 0)
			bha_nga;
		debug3("Received %d SSH2_FXP_NAME responses", count);
		සඳහා (i = 0; i < count; i++) {
			var_na *filename, *longname;
			Attrib a;

			නම් ((r = sshbuf_get_cstring(msg, &filename,
			    NULL)) != 0 ||
			    (r = sshbuf_get_cstring(msg, &longname,
			    NULL)) != 0)
				fatal_fr(r, "parse filenames");
			නම් ((r = decode_attrib(msg, &a)) != 0) {
				error_fr(r, "couldn't decode attrib");
				free(filename);
				free(longname);
				goto out;
			}

			නම් (print_flag)
				mprintf("%s\n", longname);

			/*
			 * Directory entries should never contain '/'
			 * These can be used to attack recursive ops
			 * (e.g. send '../../../../etc/passwd')
			 */
			නම් (*filename == '\0' ||
			    strpbrk(filename, SFTP_DIRECTORY_CHARS) != NULL) {
				error("Server sent suspect path \"%s\" "
				    "during readdir of \"%s\"", filename, path);
			} නැතහොත් නම් (dir) {
				*dir = xreallocarray(*dir, ents + 2, parimaa_na(**dir));
				(*dir)[ents] = xcalloc(1, parimaa_na(***dir));
				(*dir)[ents]->filename = xstrdup(filename);
				(*dir)[ents]->longname = xstrdup(longname);
				memcpy(&(*dir)[ents]->a, &a, parimaa_na(a));
				(*dir)[++ents] = NULL;
			}
			free(filename);
			free(longname);
		}
	}
	status = 0;

 out:
	sshbuf_free(msg);
	sftp_close(conn, handle, handle_len);
	free(handle);

	නම් (status != 0 && dir != NULL) {
		/* Don't return results on error */
		sftp_free_dirents(*dir);
		*dir = NULL;
	} නැතහොත් නම් (interrupted && dir != NULL && *dir != NULL) {
		/* Don't return partial matches on interrupt */
		sftp_free_dirents(*dir);
		*dir = xcalloc(1, parimaa_na(**dir));
		**dir = NULL;
	}

	ආපසු status == SSH2_FX_OK ? 0 : -1;
}

පූර්ණ_සංඛ්‍යා
sftp_readdir(sa_nracanaa sftp_conn *conn, const var_na *path, SFTP_DIRENT ***dir)
{
	ආපසු sftp_lsreaddir(conn, path, 0, dir);
}

void sftp_free_dirents(SFTP_DIRENT **s)
{
	පූර්ණ_සංඛ්‍යා i;

	නම් (s == NULL)
		ආපසු;
	සඳහා (i = 0; s[i]; i++) {
		free(s[i]->filename);
		free(s[i]->longname);
		free(s[i]);
	}
	free(s);
}

පූර්ණ_සංඛ්‍යා
sftp_rm(sa_nracanaa sftp_conn *conn, const var_na *path)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_REMOVE \"%s\"", path);

	id = conn->msg_id++;
	send_string_request(conn, id, SSH2_FXP_REMOVE, path, strlen(path));
	status = get_status(conn, id);
	නම් (status != SSH2_FX_OK)
		error("remote delete %s: %s", path, fx2txt(status));
	ආපසු status == SSH2_FX_OK ? 0 : -1;
}

පූර්ණ_සංඛ්‍යා
sftp_mkdir(sa_nracanaa sftp_conn *conn, const var_na *path, Attrib *a, පූර්ණ_සංඛ්‍යා print_flag)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_MKDIR \"%s\"", path);

	id = conn->msg_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_MKDIR, path,
	    strlen(path), a);

	status = get_status(conn, id);
	නම් (status != SSH2_FX_OK && print_flag)
		error("remote mkdir \"%s\": %s", path, fx2txt(status));

	ආපසු status == SSH2_FX_OK ? 0 : -1;
}

පූර්ණ_සංඛ්‍යා
sftp_mkpath(sa_nracanaa sftp_conn *conn, const var_na *path, Attrib *a, පූර්ණ_සංඛ්‍යා print_flag)
{
	var_na *slash, *tmp_path;
	පූර්ණ_සංඛ්‍යා done;

	tmp_path = xstrdup(path);
	slash = tmp_path;

	සඳහා (;;) {
		slash += strspn(slash, "/");
		slash += strcspn(slash, "/");

		done = (*slash == '\0');
		*slash = '\0';

		නම් (!sftp_remote_is_dir(conn, tmp_path)) {
			නම් (sftp_mkdir(conn, tmp_path, a, print_flag) != 0) {
				free(tmp_path);
				ආපසු -1;
			}
		}

		නම් (done)
			bha_nga;

		*slash = '/';
	}

	free(tmp_path);
	ආපසු 0;
}

පූර්ණ_සංඛ්‍යා
sftp_rmdir(sa_nracanaa sftp_conn *conn, const var_na *path)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_RMDIR \"%s\"", path);

	id = conn->msg_id++;
	send_string_request(conn, id, SSH2_FXP_RMDIR, path,
	    strlen(path));

	status = get_status(conn, id);
	නම් (status != SSH2_FX_OK)
		error("remote rmdir \"%s\": %s", path, fx2txt(status));

	ආපසු status == SSH2_FX_OK ? 0 : -1;
}

පූර්ණ_සංඛ්‍යා
sftp_stat(sa_nracanaa sftp_conn *conn, const var_na *path, පූර්ණ_සංඛ්‍යා quiet, Attrib *a)
{
	u_int id;

	debug2("Sending SSH2_FXP_STAT \"%s\"", path);

	id = conn->msg_id++;

	send_string_request(conn, id,
	    conn->version == 0 ? SSH2_FXP_STAT_VERSION_0 : SSH2_FXP_STAT,
	    path, strlen(path));

	ආපසු get_decode_stat(conn, id, quiet, a);
}

පූර්ණ_සංඛ්‍යා
sftp_lstat(sa_nracanaa sftp_conn *conn, const var_na *path, පූර්ණ_සංඛ්‍යා quiet, Attrib *a)
{
	u_int id;

	නම් (conn->version == 0) {
		do_log2(quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_INFO,
		    "Server version does not support lstat operation");
		ආපසු sftp_stat(conn, path, quiet, a);
	}

	id = conn->msg_id++;
	send_string_request(conn, id, SSH2_FXP_LSTAT, path,
	    strlen(path));

	ආපසු get_decode_stat(conn, id, quiet, a);
}

#ifdef notyet
පූර්ණ_සංඛ්‍යා
sftp_fstat(sa_nracanaa sftp_conn *conn, const u_char *handle, u_int handle_len,
    පූර්ණ_සංඛ්‍යා quiet, Attrib *a)
{
	u_int id;

	debug2("Sending SSH2_FXP_FSTAT \"%s\"");

	id = conn->msg_id++;
	send_string_request(conn, id, SSH2_FXP_FSTAT, handle,
	    handle_len);

	ආපසු get_decode_stat(conn, id, quiet, a);
}
#endif

පූර්ණ_සංඛ්‍යා
sftp_setstat(sa_nracanaa sftp_conn *conn, const var_na *path, Attrib *a)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_SETSTAT \"%s\"", path);

	id = conn->msg_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_SETSTAT, path,
	    strlen(path), a);

	status = get_status(conn, id);
	නම් (status != SSH2_FX_OK)
		error("remote setstat \"%s\": %s", path, fx2txt(status));

	ආපසු status == SSH2_FX_OK ? 0 : -1;
}

පූර්ණ_සංඛ්‍යා
sftp_fsetstat(sa_nracanaa sftp_conn *conn, const u_char *handle, u_int handle_len,
    Attrib *a)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_FSETSTAT");

	id = conn->msg_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_FSETSTAT, handle,
	    handle_len, a);

	status = get_status(conn, id);
	නම් (status != SSH2_FX_OK)
		error("remote fsetstat: %s", fx2txt(status));

	ආපසු status == SSH2_FX_OK ? 0 : -1;
}

/* Implements both the realpath and expand-path operations */
static var_na *
sftp_realpath_expand(sa_nracanaa sftp_conn *conn, const var_na *path, පූර්ණ_සංඛ්‍යා expand)
{
	sa_nracanaa sshbuf *msg;
	u_int expected_id, count, id;
	var_na *filename, *longname;
	Attrib a;
	u_char type;
	පූර්ණ_සංඛ්‍යා r;
	const var_na *what = "SSH2_FXP_REALPATH";

	නම් (expand)
		what = "expand-path@openssh.com";
	නම් ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	expected_id = id = conn->msg_id++;
	නම් (expand) {
		debug2("Sending SSH2_FXP_EXTENDED(expand-path@openssh.com) "
		    "\"%s\"", path);
		නම් ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED)) != 0 ||
		    (r = sshbuf_put_u32(msg, id)) != 0 ||
		    (r = sshbuf_put_cstring(msg,
		    "expand-path@openssh.com")) != 0 ||
		    (r = sshbuf_put_cstring(msg, path)) != 0)
			fatal_fr(r, "compose %s", what);
		send_msg(conn, msg);
	} නැතහොත් {
		debug2("Sending SSH2_FXP_REALPATH \"%s\"", path);
		send_string_request(conn, id, SSH2_FXP_REALPATH,
		    path, strlen(path));
	}
	get_msg(conn, msg);
	නම් ((r = sshbuf_get_u8(msg, &type)) != 0 ||
	    (r = sshbuf_get_u32(msg, &id)) != 0)
		fatal_fr(r, "parse");

	නම් (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);

	නම් (type == SSH2_FXP_STATUS) {
		u_int status;
		var_na *errmsg;

		නම් ((r = sshbuf_get_u32(msg, &status)) != 0 ||
		    (r = sshbuf_get_cstring(msg, &errmsg, NULL)) != 0)
			fatal_fr(r, "parse status");
		error("%s %s: %s", expand ? "expand" : "realpath",
		    path, *errmsg == '\0' ? fx2txt(status) : errmsg);
		free(errmsg);
		sshbuf_free(msg);
		ආපසු NULL;
	} නැතහොත් නම් (type != SSH2_FXP_NAME)
		fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
		    SSH2_FXP_NAME, type);

	නම් ((r = sshbuf_get_u32(msg, &count)) != 0)
		fatal_fr(r, "parse count");
	නම් (count != 1)
		fatal("Got multiple names (%d) from %s", count, what);

	නම් ((r = sshbuf_get_cstring(msg, &filename, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(msg, &longname, NULL)) != 0 ||
	    (r = decode_attrib(msg, &a)) != 0)
		fatal_fr(r, "parse filename/attrib");

	debug3("%s %s -> %s", what, path, filename);

	free(longname);

	sshbuf_free(msg);

	ආපසු(filename);
}

var_na *
sftp_realpath(sa_nracanaa sftp_conn *conn, const var_na *path)
{
	ආපසු sftp_realpath_expand(conn, path, 0);
}

පූර්ණ_සංඛ්‍යා
sftp_can_expand_path(sa_nracanaa sftp_conn *conn)
{
	ආපසු (conn->exts & SFTP_EXT_PATH_EXPAND) != 0;
}

var_na *
sftp_expand_path(sa_nracanaa sftp_conn *conn, const var_na *path)
{
	නම් (!sftp_can_expand_path(conn)) {
		debug3_f("no server support, fallback to realpath");
		ආපසු sftp_realpath_expand(conn, path, 0);
	}
	ආපසු sftp_realpath_expand(conn, path, 1);
}

පූර්ණ_සංඛ්‍යා
sftp_copy(sa_nracanaa sftp_conn *conn, const var_na *oldpath, const var_na *newpath)
{
	Attrib junk, attr;
	sa_nracanaa sshbuf *msg;
	u_char *old_handle, *new_handle;
	u_int mode, status, id;
	size_t old_handle_len, new_handle_len;
	පූර්ණ_සංඛ්‍යා r;

	/* Return if the extension is not supported */
	නම් ((conn->exts & SFTP_EXT_COPY_DATA) == 0) {
		error("Server does not support copy-data extension");
		ආපසු -1;
	}

	/* Make sure the file exists, and we can copy its perms */
	නම් (sftp_stat(conn, oldpath, 0, &attr) != 0)
		ආපසු -1;

	/* Do not preserve set[ug]id here, as we do not preserve ownership */
	නම් (attr.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		mode = attr.perm & 0777;

		නම් (!S_ISREG(attr.perm)) {
			error("Cannot copy non-regular file: %s", oldpath);
			ආපසු -1;
		}
	} නැතහොත් {
		/* NB: The user's umask will apply to this */
		mode = 0666;
	}

	/* Set up the new perms for the new file */
	attrib_clear(&attr);
	attr.perm = mode;
	attr.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;

	නම් ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	attrib_clear(&junk); /* Send empty attributes */

	/* Open the old file for reading */
	id = conn->msg_id++;
	නම් ((r = sshbuf_put_u8(msg, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, oldpath)) != 0 ||
	    (r = sshbuf_put_u32(msg, SSH2_FXF_READ)) != 0 ||
	    (r = encode_attrib(msg, &junk)) != 0)
		fatal_fr(r, "buffer error");
	send_msg(conn, msg);
	debug3("Sent message SSH2_FXP_OPEN I:%u P:%s", id, oldpath);

	sshbuf_reset(msg);

	old_handle = get_handle(conn, id, &old_handle_len,
	    "remote open(\"%s\")", oldpath);
	නම් (old_handle == NULL) {
		sshbuf_free(msg);
		ආපසු -1;
	}

	/* Open the new file for writing */
	id = conn->msg_id++;
	නම් ((r = sshbuf_put_u8(msg, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, newpath)) != 0 ||
	    (r = sshbuf_put_u32(msg, SSH2_FXF_WRITE|SSH2_FXF_CREAT|
	    SSH2_FXF_TRUNC)) != 0 ||
	    (r = encode_attrib(msg, &attr)) != 0)
		fatal_fr(r, "buffer error");
	send_msg(conn, msg);
	debug3("Sent message SSH2_FXP_OPEN I:%u P:%s", id, newpath);

	sshbuf_reset(msg);

	new_handle = get_handle(conn, id, &new_handle_len,
	    "remote open(\"%s\")", newpath);
	නම් (new_handle == NULL) {
		sshbuf_free(msg);
		free(old_handle);
		ආපසු -1;
	}

	/* Copy the file data */
	id = conn->msg_id++;
	නම් ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, "copy-data")) != 0 ||
	    (r = sshbuf_put_string(msg, old_handle, old_handle_len)) != 0 ||
	    (r = sshbuf_put_u64(msg, 0)) != 0 ||
	    (r = sshbuf_put_u64(msg, 0)) != 0 ||
	    (r = sshbuf_put_string(msg, new_handle, new_handle_len)) != 0 ||
	    (r = sshbuf_put_u64(msg, 0)) != 0)
		fatal_fr(r, "buffer error");
	send_msg(conn, msg);
	debug3("Sent message copy-data \"%s\" 0 0 -> \"%s\" 0",
	       oldpath, newpath);

	status = get_status(conn, id);
	නම් (status != SSH2_FX_OK)
		error("Couldn't copy file \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	/* Clean up everything */
	sshbuf_free(msg);
	sftp_close(conn, old_handle, old_handle_len);
	sftp_close(conn, new_handle, new_handle_len);
	free(old_handle);
	free(new_handle);

	ආපසු status == SSH2_FX_OK ? 0 : -1;
}

පූර්ණ_සංඛ්‍යා
sftp_rename(sa_nracanaa sftp_conn *conn, const var_na *oldpath, const var_na *newpath,
    පූර්ණ_සංඛ්‍යා force_legacy)
{
	sa_nracanaa sshbuf *msg;
	u_int status, id;
	පූර්ණ_සංඛ්‍යා r, use_ext = (conn->exts & SFTP_EXT_POSIX_RENAME) && !force_legacy;

	නම් ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	/* Send rename request */
	id = conn->msg_id++;
	නම් (use_ext) {
		debug2("Sending SSH2_FXP_EXTENDED(posix-rename@openssh.com) "
		    "\"%s\" to \"%s\"", oldpath, newpath);
		නම් ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED)) != 0 ||
		    (r = sshbuf_put_u32(msg, id)) != 0 ||
		    (r = sshbuf_put_cstring(msg,
		    "posix-rename@openssh.com")) != 0)
			fatal_fr(r, "compose posix-rename");
	} නැතහොත් {
		debug2("Sending SSH2_FXP_RENAME \"%s\" to \"%s\"",
		    oldpath, newpath);
		නම් ((r = sshbuf_put_u8(msg, SSH2_FXP_RENAME)) != 0 ||
		    (r = sshbuf_put_u32(msg, id)) != 0)
			fatal_fr(r, "compose rename");
	}
	නම් ((r = sshbuf_put_cstring(msg, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(msg, newpath)) != 0)
		fatal_fr(r, "compose paths");
	send_msg(conn, msg);
	debug3("Sent message %s \"%s\" -> \"%s\"",
	    use_ext ? "posix-rename@openssh.com" :
	    "SSH2_FXP_RENAME", oldpath, newpath);
	sshbuf_free(msg);

	status = get_status(conn, id);
	නම් (status != SSH2_FX_OK)
		error("remote rename \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	ආපසු status == SSH2_FX_OK ? 0 : -1;
}

පූර්ණ_සංඛ්‍යා
sftp_hardlink(sa_nracanaa sftp_conn *conn, const var_na *oldpath, const var_na *newpath)
{
	sa_nracanaa sshbuf *msg;
	u_int status, id;
	පූර්ණ_සංඛ්‍යා r;

	නම් ((conn->exts & SFTP_EXT_HARDLINK) == 0) {
		error("Server does not support hardlink@openssh.com extension");
		ආපසු -1;
	}
	debug2("Sending SSH2_FXP_EXTENDED(hardlink@openssh.com) "
	    "\"%s\" to \"%s\"", oldpath, newpath);

	නම් ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	/* Send link request */
	id = conn->msg_id++;
	නම් ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, "hardlink@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(msg, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(msg, newpath)) != 0)
		fatal_fr(r, "compose");
	send_msg(conn, msg);
	debug3("Sent message hardlink@openssh.com \"%s\" -> \"%s\"",
	    oldpath, newpath);
	sshbuf_free(msg);

	status = get_status(conn, id);
	නම් (status != SSH2_FX_OK)
		error("remote link \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	ආපසු status == SSH2_FX_OK ? 0 : -1;
}

පූර්ණ_සංඛ්‍යා
sftp_symlink(sa_nracanaa sftp_conn *conn, const var_na *oldpath, const var_na *newpath)
{
	sa_nracanaa sshbuf *msg;
	u_int status, id;
	පූර්ණ_සංඛ්‍යා r;

	නම් (conn->version < 3) {
		error("This server does not support the symlink operation");
		ආපසු(SSH2_FX_OP_UNSUPPORTED);
	}
	debug2("Sending SSH2_FXP_SYMLINK \"%s\" to \"%s\"", oldpath, newpath);

	නම් ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	/* Send symlink request */
	id = conn->msg_id++;
	නම් ((r = sshbuf_put_u8(msg, SSH2_FXP_SYMLINK)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(msg, newpath)) != 0)
		fatal_fr(r, "compose");
	send_msg(conn, msg);
	debug3("Sent message SSH2_FXP_SYMLINK \"%s\" -> \"%s\"", oldpath,
	    newpath);
	sshbuf_free(msg);

	status = get_status(conn, id);
	නම් (status != SSH2_FX_OK)
		error("remote symlink file \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	ආපසු status == SSH2_FX_OK ? 0 : -1;
}

පූර්ණ_සංඛ්‍යා
sftp_fsync(sa_nracanaa sftp_conn *conn, u_char *handle, u_int handle_len)
{
	sa_nracanaa sshbuf *msg;
	u_int status, id;
	පූර්ණ_සංඛ්‍යා r;

	/* Silently return if the extension is not supported */
	නම් ((conn->exts & SFTP_EXT_FSYNC) == 0)
		ආපසු -1;
	debug2("Sending SSH2_FXP_EXTENDED(fsync@openssh.com)");

	/* Send fsync request */
	නම් ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	id = conn->msg_id++;
	නම් ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, "fsync@openssh.com")) != 0 ||
	    (r = sshbuf_put_string(msg, handle, handle_len)) != 0)
		fatal_fr(r, "compose");
	send_msg(conn, msg);
	debug3("Sent message fsync@openssh.com I:%u", id);
	sshbuf_free(msg);

	status = get_status(conn, id);
	නම් (status != SSH2_FX_OK)
		error("remote fsync: %s", fx2txt(status));

	ආපසු status == SSH2_FX_OK ? 0 : -1;
}

#ifdef notyet
var_na *
sftp_readlink(sa_nracanaa sftp_conn *conn, const var_na *path)
{
	sa_nracanaa sshbuf *msg;
	u_int expected_id, count, id;
	var_na *filename, *longname;
	Attrib a;
	u_char type;
	පූර්ණ_සංඛ්‍යා r;

	debug2("Sending SSH2_FXP_READLINK \"%s\"", path);

	expected_id = id = conn->msg_id++;
	send_string_request(conn, id, SSH2_FXP_READLINK, path, strlen(path));

	නම් ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	get_msg(conn, msg);
	නම් ((r = sshbuf_get_u8(msg, &type)) != 0 ||
	    (r = sshbuf_get_u32(msg, &id)) != 0)
		fatal_fr(r, "parse");

	නම් (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);

	නම් (type == SSH2_FXP_STATUS) {
		u_int status;

		නම් ((r = sshbuf_get_u32(msg, &status)) != 0)
			fatal_fr(r, "parse status");
		error("Couldn't readlink: %s", fx2txt(status));
		sshbuf_free(msg);
		ආපසු(NULL);
	} නැතහොත් නම් (type != SSH2_FXP_NAME)
		fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
		    SSH2_FXP_NAME, type);

	නම් ((r = sshbuf_get_u32(msg, &count)) != 0)
		fatal_fr(r, "parse count");
	නම් (count != 1)
		fatal("Got multiple names (%d) from SSH_FXP_READLINK", count);

	නම් ((r = sshbuf_get_cstring(msg, &filename, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(msg, &longname, NULL)) != 0 ||
	    (r = decode_attrib(msg, &a)) != 0)
		fatal_fr(r, "parse filenames/attrib");

	debug3("SSH_FXP_READLINK %s -> %s", path, filename);

	free(longname);

	sshbuf_free(msg);

	ආපසු filename;
}
#endif

පූර්ණ_සංඛ්‍යා
sftp_statvfs(sa_nracanaa sftp_conn *conn, const var_na *path, sa_nracanaa sftp_statvfs *st,
    පූර්ණ_සංඛ්‍යා quiet)
{
	sa_nracanaa sshbuf *msg;
	u_int id;
	පූර්ණ_සංඛ්‍යා r;

	නම් ((conn->exts & SFTP_EXT_STATVFS) == 0) {
		error("Server does not support statvfs@openssh.com extension");
		ආපසු -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(statvfs@openssh.com) \"%s\"", path);

	id = conn->msg_id++;

	නම් ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	නම් ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, "statvfs@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(msg, path)) != 0)
		fatal_fr(r, "compose");
	send_msg(conn, msg);
	sshbuf_free(msg);

	ආපසු get_decode_statvfs(conn, st, id, quiet);
}

#ifdef notyet
පූර්ණ_සංඛ්‍යා
sftp_fstatvfs(sa_nracanaa sftp_conn *conn, const u_char *handle, u_int handle_len,
    sa_nracanaa sftp_statvfs *st, පූර්ණ_සංඛ්‍යා quiet)
{
	sa_nracanaa sshbuf *msg;
	u_int id;

	නම් ((conn->exts & SFTP_EXT_FSTATVFS) == 0) {
		error("Server does not support fstatvfs@openssh.com extension");
		ආපසු -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(fstatvfs@openssh.com)");

	id = conn->msg_id++;

	නම් ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	නම් ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, "fstatvfs@openssh.com")) != 0 ||
	    (r = sshbuf_put_string(msg, handle, handle_len)) != 0)
		fatal_fr(r, "compose");
	send_msg(conn, msg);
	sshbuf_free(msg);

	ආපසු get_decode_statvfs(conn, st, id, quiet);
}
#endif

පූර්ණ_සංඛ්‍යා
sftp_lsetstat(sa_nracanaa sftp_conn *conn, const var_na *path, Attrib *a)
{
	sa_nracanaa sshbuf *msg;
	u_int status, id;
	පූර්ණ_සංඛ්‍යා r;

	නම් ((conn->exts & SFTP_EXT_LSETSTAT) == 0) {
		error("Server does not support lsetstat@openssh.com extension");
		ආපසු -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(lsetstat@openssh.com) \"%s\"", path);

	id = conn->msg_id++;
	නම් ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	නම් ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, "lsetstat@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(msg, path)) != 0 ||
	    (r = encode_attrib(msg, a)) != 0)
		fatal_fr(r, "compose");
	send_msg(conn, msg);
	sshbuf_free(msg);

	status = get_status(conn, id);
	නම් (status != SSH2_FX_OK)
		error("remote lsetstat \"%s\": %s", path, fx2txt(status));

	ආපසු status == SSH2_FX_OK ? 0 : -1;
}

static void
send_read_request(sa_nracanaa sftp_conn *conn, u_int id, uint64_t offset,
    u_int len, const u_char *handle, u_int handle_len)
{
	sa_nracanaa sshbuf *msg;
	පූර්ණ_සංඛ්‍යා r;

	නම් ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	නම් ((r = sshbuf_put_u8(msg, SSH2_FXP_READ)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_string(msg, handle, handle_len)) != 0 ||
	    (r = sshbuf_put_u64(msg, offset)) != 0 ||
	    (r = sshbuf_put_u32(msg, len)) != 0)
		fatal_fr(r, "compose");
	send_msg(conn, msg);
	sshbuf_free(msg);
}

static පූර්ණ_සංඛ්‍යා
send_open(sa_nracanaa sftp_conn *conn, const var_na *path, const var_na *tag,
    u_int openmode, Attrib *a, u_char **handlep, size_t *handle_lenp)
{
	Attrib junk;
	u_char *handle;
	size_t handle_len;
	sa_nracanaa sshbuf *msg;
	පූර්ණ_සංඛ්‍යා r;
	u_int id;

	debug2("Sending SSH2_FXP_OPEN \"%s\"", path);

	*handlep = NULL;
	*handle_lenp = 0;

	නම් (a == NULL) {
		attrib_clear(&junk); /* Send empty attributes */
		a = &junk;
	}
	/* Send open request */
	නම් ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	id = conn->msg_id++;
	නම් ((r = sshbuf_put_u8(msg, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, path)) != 0 ||
	    (r = sshbuf_put_u32(msg, openmode)) != 0 ||
	    (r = encode_attrib(msg, a)) != 0)
		fatal_fr(r, "compose %s open", tag);
	send_msg(conn, msg);
	sshbuf_free(msg);
	debug3("Sent %s message SSH2_FXP_OPEN I:%u P:%s M:0x%04x",
	    tag, id, path, openmode);
	නම් ((handle = get_handle(conn, id, &handle_len,
	    "%s open \"%s\"", tag, path)) == NULL)
		ආපසු -1;
	/* success */
	*handlep = handle;
	*handle_lenp = handle_len;
	ආපසු 0;
}

static const var_na *
progress_meter_path(const var_na *path)
{
	const var_na *progresspath;

	නම් ((progresspath = strrchr(path, '/')) == NULL)
		ආපසු path;
	progresspath++;
	නම් (*progresspath == '\0')
		ආපසු path;
	ආපසු progresspath;
}

පූර්ණ_සංඛ්‍යා
sftp_download(sa_nracanaa sftp_conn *conn, const var_na *remote_path,
    const var_na *local_path, Attrib *a, පූර්ණ_සංඛ්‍යා preserve_flag, පූර්ණ_සංඛ්‍යා resume_flag,
    පූර්ණ_සංඛ්‍යා fsync_flag, පූර්ණ_සංඛ්‍යා inplace_flag)
{
	sa_nracanaa sshbuf *msg;
	u_char *handle;
	පූර්ණ_සංඛ්‍යා local_fd = -1, write_error, seen_zerolen = 0;
	පූර්ණ_සංඛ්‍යා read_error, write_errno, lmodified = 0, reordered = 0, r;
	uint64_t offset = 0, size, highwater = 0, maxack = 0;
	u_int mode, id, buflen, num_req, max_req, status = SSH2_FX_OK;
	off_t progress_counter;
	size_t handle_len;
	sa_nracanaa stat st;
	sa_nracanaa requests requests;
	sa_nracanaa request *req;
	u_char type;
	Attrib attr;

	debug2_f("download remote \"%s\" to local \"%s\"",
	    remote_path, local_path);

	TAILQ_INIT(&requests);

	නම් (a == NULL) {
		නම් (sftp_stat(conn, remote_path, 0, &attr) != 0)
			ආපසු -1;
		a = &attr;
	}

	/* Do not preserve set[ug]id here, as we do not preserve ownership */
	නම් (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS)
		mode = a->perm & 0777;
	නැතහොත්
		mode = 0666;

	නම් ((a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) &&
	    (!S_ISREG(a->perm))) {
		error("download %s: not a regular file", remote_path);
		ආපසු(-1);
	}

	නම් (a->flags & SSH2_FILEXFER_ATTR_SIZE)
		size = a->size;
	නැතහොත්
		size = 0;

	buflen = conn->download_buflen;

	/* Send open request */
	නම් (send_open(conn, remote_path, "remote", SSH2_FXF_READ, NULL,
	    &handle, &handle_len) != 0)
		ආපසු -1;

	local_fd = open(local_path, O_WRONLY | O_CREAT |
	((resume_flag || inplace_flag) ? 0 : O_TRUNC), mode | S_IWUSR);
	නම් (local_fd == -1) {
		error("open local \"%s\": %s", local_path, strerror(errno));
		goto fail;
	}
	නම් (resume_flag) {
		නම් (fstat(local_fd, &st) == -1) {
			error("stat local \"%s\": %s",
			    local_path, strerror(errno));
			goto fail;
		}
		නම් (st.st_size < 0) {
			error("\"%s\" has negative size", local_path);
			goto fail;
		}
		නම් ((uint64_t)st.st_size > size) {
			error("Unable to resume download of \"%s\": "
			    "local file is larger than remote", local_path);
 fail:
			sftp_close(conn, handle, handle_len);
			free(handle);
			නම් (local_fd != -1)
				close(local_fd);
			ආපසු -1;
		}
		offset = highwater = maxack = st.st_size;
	}

	/* Read from remote and write to local */
	write_error = read_error = write_errno = num_req = 0;
	max_req = 1;
	progress_counter = offset;

	නම් (showprogress && size != 0) {
		start_progress_meter(progress_meter_path(remote_path),
		    size, &progress_counter);
	}

	නම් ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	අතරතුර (num_req > 0 || max_req > 0) {
		u_char *data;
		size_t len;

		/*
		 * Simulate EOF on interrupt: stop sending new requests and
		 * allow outstanding requests to drain gracefully
		 */
		නම් (interrupted) {
			නම් (num_req == 0) /* If we haven't started yet... */
				bha_nga;
			max_req = 0;
		}

		/* Send some more requests */
		අතරතුර (num_req < max_req) {
			debug3("Request range %llu -> %llu (%d/%d)",
			    (unsigned long long)offset,
			    (unsigned long long)offset + buflen - 1,
			    num_req, max_req);
			req = request_enqueue(&requests, conn->msg_id++,
			    buflen, offset);
			offset += buflen;
			num_req++;
			send_read_request(conn, req->id, req->offset,
			    req->len, handle, handle_len);
		}

		sshbuf_reset(msg);
		get_msg(conn, msg);
		නම් ((r = sshbuf_get_u8(msg, &type)) != 0 ||
		    (r = sshbuf_get_u32(msg, &id)) != 0)
			fatal_fr(r, "parse");
		debug3("Received reply T:%u I:%u R:%d", type, id, max_req);

		/* Find the request in our queue */
		නම් ((req = request_find(&requests, id)) == NULL)
			fatal("Unexpected reply %u", id);

		switch (type) {
		pak_sa SSH2_FXP_STATUS:
			නම් ((r = sshbuf_get_u32(msg, &status)) != 0)
				fatal_fr(r, "parse status");
			නම් (status != SSH2_FX_EOF)
				read_error = 1;
			max_req = 0;
			TAILQ_REMOVE(&requests, req, tq);
			free(req);
			num_req--;
			bha_nga;
		pak_sa SSH2_FXP_DATA:
			නම් ((r = sshbuf_get_string(msg, &data, &len)) != 0)
				fatal_fr(r, "parse data");
			debug3("Received data %llu -> %llu",
			    (unsigned long long)req->offset,
			    (unsigned long long)req->offset + len - 1);
			නම් (len > req->len)
				fatal("Received more data than asked for "
				    "%zu > %zu", len, req->len);
			නම් (len == 0) {
				නම් (seen_zerolen)
					fatal_f("server sent zero data length");
				seen_zerolen = 1;
			}
			lmodified = 1;
			නම් ((lseek(local_fd, req->offset, SEEK_SET) == -1 ||
			    atomicio(vwrite, local_fd, data, len) != len) &&
			    !write_error) {
				write_errno = errno;
				write_error = 1;
				max_req = 0;
			} නැතහොත් {
				/*
				 * Track both the highest offset acknowledged
				 * and the highest *contiguous* offset
				 * acknowledged.
				 * We'll need the latter for ftruncate()ing
				 * interrupted transfers.
				 */
				නම් (maxack < req->offset + len)
					maxack = req->offset + len;
				නම් (!reordered && req->offset <= highwater)
					highwater = maxack;
				නැතහොත් නම් (!reordered && req->offset > highwater)
					reordered = 1;
			}
			progress_counter += len;
			free(data);

			නම් (len == req->len) {
				TAILQ_REMOVE(&requests, req, tq);
				free(req);
				num_req--;
			} නැතහොත් {
				/* Resend the request for the missing data */
				debug3("Short data block, re-requesting "
				    "%llu -> %llu (%2d)",
				    (unsigned long long)req->offset + len,
				    (unsigned long long)req->offset +
				    req->len - 1, num_req);
				req->id = conn->msg_id++;
				req->len -= len;
				req->offset += len;
				send_read_request(conn, req->id,
				    req->offset, req->len, handle, handle_len);
				/* Reduce the request size */
				නම් (len < buflen)
					buflen = MAXIMUM(MIN_READ_SIZE, len);
			}
			නම් (max_req > 0) { /* max_req = 0 iff EOF received */
				නම් (size > 0 && offset > size) {
					/* Only one request at a time
					 * after the expected EOF */
					debug3("Finish at %llu (%2d)",
					    (unsigned long long)offset,
					    num_req);
					max_req = 1;
				} නැතහොත් නම් (max_req < conn->num_requests) {
					++max_req;
				}
			}
			bha_nga;
		default:
			fatal("Expected SSH2_FXP_DATA(%u) packet, got %u",
			    SSH2_FXP_DATA, type);
		}
	}

	නම් (showprogress && size)
		stop_progress_meter();

	/* Sanity check */
	නම් (TAILQ_FIRST(&requests) != NULL)
		fatal("Transfer complete, but requests still in queue");

	නම් (!read_error && !write_error && !interrupted) {
		/* we got everything */
		highwater = maxack;
	}

	/*
	 * Truncate at highest contiguous point to avoid holes on interrupt,
	 * or unconditionally if writing in place.
	 */
	නම් (inplace_flag || read_error || write_error || interrupted) {
		නම් (reordered && resume_flag &&
		    (read_error || write_error || interrupted)) {
			error("Unable to resume download of \"%s\": "
			    "server reordered requests", local_path);
		}
		debug("truncating at %llu", (unsigned long long)highwater);
		නම් (ftruncate(local_fd, highwater) == -1)
			error("local ftruncate \"%s\": %s", local_path,
			    strerror(errno));
	}
	නම් (read_error) {
		error("read remote \"%s\" : %s", remote_path, fx2txt(status));
		status = -1;
		sftp_close(conn, handle, handle_len);
	} නැතහොත් නම් (write_error) {
		error("write local \"%s\": %s", local_path,
		    strerror(write_errno));
		status = SSH2_FX_FAILURE;
		sftp_close(conn, handle, handle_len);
	} නැතහොත් {
		නම් (sftp_close(conn, handle, handle_len) != 0 || interrupted)
			status = SSH2_FX_FAILURE;
		නැතහොත්
			status = SSH2_FX_OK;
		/* Override umask and utimes if asked */
#ifdef HAVE_FCHMOD
		නම් (preserve_flag && fchmod(local_fd, mode) == -1)
#නැතහොත්
		නම් (preserve_flag && chmod(local_path, mode) == -1)
#endif /* HAVE_FCHMOD */
			error("local chmod \"%s\": %s", local_path,
			    strerror(errno));
		නම් (preserve_flag &&
		    (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME)) {
			sa_nracanaa timeval tv[2];
			tv[0].tv_sec = a->atime;
			tv[1].tv_sec = a->mtime;
			tv[0].tv_usec = tv[1].tv_usec = 0;
			නම් (utimes(local_path, tv) == -1)
				error("local set times \"%s\": %s",
				    local_path, strerror(errno));
		}
		නම් (resume_flag && !lmodified)
			logit("File \"%s\" was not modified", local_path);
		නැතහොත් නම් (fsync_flag) {
			debug("syncing \"%s\"", local_path);
			නම් (fsync(local_fd) == -1)
				error("local sync \"%s\": %s",
				    local_path, strerror(errno));
		}
	}
	close(local_fd);
	sshbuf_free(msg);
	free(handle);

	ආපසු status == SSH2_FX_OK ? 0 : -1;
}

static පූර්ණ_සංඛ්‍යා
download_dir_internal(sa_nracanaa sftp_conn *conn, const var_na *src, const var_na *dst,
    පූර්ණ_සංඛ්‍යා depth, Attrib *dirattrib, පූර්ණ_සංඛ්‍යා preserve_flag, පූර්ණ_සංඛ්‍යා print_flag,
    පූර්ණ_සංඛ්‍යා resume_flag, පූර්ණ_සංඛ්‍යා fsync_flag, පූර්ණ_සංඛ්‍යා follow_link_flag, පූර්ණ_සංඛ්‍යා inplace_flag)
{
	පූර්ණ_සංඛ්‍යා i, ret = 0;
	SFTP_DIRENT **dir_entries;
	var_na *filename, *new_src = NULL, *new_dst = NULL;
	mode_t mode = 0777, tmpmode = mode;
	Attrib *a, ldirattrib, lsym;

	නම් (depth >= MAX_DIR_DEPTH) {
		error("Maximum directory depth exceeded: %d levels", depth);
		ආපසු -1;
	}

	debug2_f("download dir remote \"%s\" to local \"%s\"", src, dst);

	නම් (dirattrib == NULL) {
		නම් (sftp_stat(conn, src, 1, &ldirattrib) != 0) {
			error("stat remote \"%s\" directory failed", src);
			ආපසු -1;
		}
		dirattrib = &ldirattrib;
	}
	නම් (!S_ISDIR(dirattrib->perm)) {
		error("\"%s\" is not a directory", src);
		ආපසු -1;
	}
	නම් (print_flag && print_flag != SFTP_PROGRESS_ONLY)
		mprintf("Retrieving %s\n", src);

	නම් (dirattrib->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		mode = dirattrib->perm & 01777;
		tmpmode = mode | (S_IWUSR|S_IXUSR);
	} නැතහොත් {
		debug("download remote \"%s\": server "
		    "did not send permissions", dst);
	}

	නම් (mkdir(dst, tmpmode) == -1 && errno != EEXIST) {
		error("mkdir %s: %s", dst, strerror(errno));
		ආපසු -1;
	}

	නම් (sftp_readdir(conn, src, &dir_entries) == -1) {
		error("remote readdir \"%s\" failed", src);
		ආපසු -1;
	}

	සඳහා (i = 0; dir_entries[i] != NULL && !interrupted; i++) {
		free(new_dst);
		free(new_src);

		filename = dir_entries[i]->filename;
		new_dst = sftp_path_append(dst, filename);
		new_src = sftp_path_append(src, filename);

		a = &dir_entries[i]->a;
		නම් (S_ISLNK(a->perm)) {
			නම් (!follow_link_flag) {
				logit("download \"%s\": not a regular file",
				    new_src);
				continue;
			}
			/* Replace the stat contents with the symlink target */
			නම් (sftp_stat(conn, new_src, 1, &lsym) != 0) {
				logit("remote stat \"%s\" failed", new_src);
				ret = -1;
				continue;
			}
			a = &lsym;
		}

		නම් (S_ISDIR(a->perm)) {
			නම් (strcmp(filename, ".") == 0 ||
			    strcmp(filename, "..") == 0)
				continue;
			නම් (download_dir_internal(conn, new_src, new_dst,
			    depth + 1, a, preserve_flag,
			    print_flag, resume_flag,
			    fsync_flag, follow_link_flag, inplace_flag) == -1)
				ret = -1;
		} නැතහොත් නම් (S_ISREG(a->perm)) {
			නම් (sftp_download(conn, new_src, new_dst, a,
			    preserve_flag, resume_flag, fsync_flag,
			    inplace_flag) == -1) {
				error("Download of file %s to %s failed",
				    new_src, new_dst);
				ret = -1;
			}
		} නැතහොත්
			logit("download \"%s\": not a regular file", new_src);

	}
	free(new_dst);
	free(new_src);

	නම් (preserve_flag) {
		නම් (dirattrib->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
			sa_nracanaa timeval tv[2];
			tv[0].tv_sec = dirattrib->atime;
			tv[1].tv_sec = dirattrib->mtime;
			tv[0].tv_usec = tv[1].tv_usec = 0;
			නම් (utimes(dst, tv) == -1)
				error("local set times on \"%s\": %s",
				    dst, strerror(errno));
		} නැතහොත්
			debug("Server did not send times for directory "
			    "\"%s\"", dst);
	}

	නම් (mode != tmpmode && chmod(dst, mode) == -1)
		error("local chmod directory \"%s\": %s", dst,
		    strerror(errno));

	sftp_free_dirents(dir_entries);

	ආපසු ret;
}

පූර්ණ_සංඛ්‍යා
sftp_download_dir(sa_nracanaa sftp_conn *conn, const var_na *src, const var_na *dst,
    Attrib *dirattrib, පූර්ණ_සංඛ්‍යා preserve_flag, පූර්ණ_සංඛ්‍යා print_flag, පූර්ණ_සංඛ්‍යා resume_flag,
    පූර්ණ_සංඛ්‍යා fsync_flag, පූර්ණ_සංඛ්‍යා follow_link_flag, පූර්ණ_සංඛ්‍යා inplace_flag)
{
	var_na *src_canon;
	පූර්ණ_සංඛ්‍යා ret;

	නම් ((src_canon = sftp_realpath(conn, src)) == NULL) {
		error("download \"%s\": path canonicalization failed", src);
		ආපසු -1;
	}

	ret = download_dir_internal(conn, src_canon, dst, 0,
	    dirattrib, preserve_flag, print_flag, resume_flag, fsync_flag,
	    follow_link_flag, inplace_flag);
	free(src_canon);
	ආපසු ret;
}

පූර්ණ_සංඛ්‍යා
sftp_upload(sa_nracanaa sftp_conn *conn, const var_na *local_path,
    const var_na *remote_path, පූර්ණ_සංඛ්‍යා preserve_flag, පූර්ණ_සංඛ්‍යා resume,
    පූර්ණ_සංඛ්‍යා fsync_flag, පූර්ණ_සංඛ්‍යා inplace_flag)
{
	පූර්ණ_සංඛ්‍යා r, local_fd;
	u_int openmode, id, status = SSH2_FX_OK, status2, reordered = 0;
	off_t offset, progress_counter;
	u_char type, *handle, *data;
	sa_nracanaa sshbuf *msg;
	sa_nracanaa stat sb;
	Attrib a, t, c;
	uint32_t startid, ackid;
	uint64_t highwater = 0, maxack = 0;
	sa_nracanaa request *ack = NULL;
	sa_nracanaa requests acks;
	size_t handle_len;

	debug2_f("upload local \"%s\" to remote \"%s\"",
	    local_path, remote_path);

	TAILQ_INIT(&acks);

	නම් ((local_fd = open(local_path, O_RDONLY)) == -1) {
		error("open local \"%s\": %s", local_path, strerror(errno));
		ආපසු(-1);
	}
	නම් (fstat(local_fd, &sb) == -1) {
		error("fstat local \"%s\": %s", local_path, strerror(errno));
		close(local_fd);
		ආපසු(-1);
	}
	නම් (!S_ISREG(sb.st_mode)) {
		error("local \"%s\" is not a regular file", local_path);
		close(local_fd);
		ආපසු(-1);
	}
	stat_to_attrib(&sb, &a);

	a.flags &= ~SSH2_FILEXFER_ATTR_SIZE;
	a.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a.perm &= 0777;
	නම් (!preserve_flag)
		a.flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;

	නම් (resume) {
		/* Get remote file size if it exists */
		නම් (sftp_stat(conn, remote_path, 0, &c) != 0) {
			close(local_fd);
			ආපසු -1;
		}

		නම් ((off_t)c.size >= sb.st_size) {
			error("resume \"%s\": destination file "
			    "same size or larger", local_path);
			close(local_fd);
			ආපසු -1;
		}

		නම් (lseek(local_fd, (off_t)c.size, SEEK_SET) == -1) {
			close(local_fd);
			ආපසු -1;
		}
		highwater = c.size;
	}

	openmode = SSH2_FXF_WRITE|SSH2_FXF_CREAT;
	නම් (resume)
		openmode |= SSH2_FXF_APPEND;
	නැතහොත් නම් (!inplace_flag)
		openmode |= SSH2_FXF_TRUNC;

	/* Send open request */
	නම් (send_open(conn, remote_path, "dest", openmode, &a,
	    &handle, &handle_len) != 0) {
		close(local_fd);
		ආපසු -1;
	}

	id = conn->msg_id;
	startid = ackid = id + 1;
	data = xmalloc(conn->upload_buflen);

	/* Read from local and write to remote */
	offset = progress_counter = (resume ? c.size : 0);
	නම් (showprogress) {
		start_progress_meter(progress_meter_path(local_path),
		    sb.st_size, &progress_counter);
	}

	නම් ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	සඳහා (;;) {
		පූර්ණ_සංඛ්‍යා len;

		/*
		 * Can't use atomicio here because it returns 0 on EOF,
		 * thus losing the last block of the file.
		 * Simulate an EOF on interrupt, allowing ACKs from the
		 * server to drain.
		 */
		නම් (interrupted || status != SSH2_FX_OK)
			len = 0;
		නැතහොත් do
			len = read(local_fd, data, conn->upload_buflen);
		අතරතුර ((len == -1) &&
		    (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK));

		නම් (len == -1) {
			fatal("read local \"%s\": %s",
			    local_path, strerror(errno));
		} නැතහොත් නම් (len != 0) {
			ack = request_enqueue(&acks, ++id, len, offset);
			sshbuf_reset(msg);
			නම් ((r = sshbuf_put_u8(msg, SSH2_FXP_WRITE)) != 0 ||
			    (r = sshbuf_put_u32(msg, ack->id)) != 0 ||
			    (r = sshbuf_put_string(msg, handle,
			    handle_len)) != 0 ||
			    (r = sshbuf_put_u64(msg, offset)) != 0 ||
			    (r = sshbuf_put_string(msg, data, len)) != 0)
				fatal_fr(r, "compose");
			send_msg(conn, msg);
			debug3("Sent message SSH2_FXP_WRITE I:%u O:%llu S:%u",
			    id, (unsigned long long)offset, len);
		} නැතහොත් නම් (TAILQ_FIRST(&acks) == NULL)
			bha_nga;

		නම් (ack == NULL)
			fatal("Unexpected ACK %u", id);

		නම් (id == startid || len == 0 ||
		    id - ackid >= conn->num_requests) {
			u_int rid;

			sshbuf_reset(msg);
			get_msg(conn, msg);
			නම් ((r = sshbuf_get_u8(msg, &type)) != 0 ||
			    (r = sshbuf_get_u32(msg, &rid)) != 0)
				fatal_fr(r, "parse");

			නම් (type != SSH2_FXP_STATUS)
				fatal("Expected SSH2_FXP_STATUS(%d) packet, "
				    "got %d", SSH2_FXP_STATUS, type);

			නම් ((r = sshbuf_get_u32(msg, &status2)) != 0)
				fatal_fr(r, "parse status");
			debug3("SSH2_FXP_STATUS %u", status2);
			නම් (status2 != SSH2_FX_OK)
				status = status2; /* remember errors */

			/* Find the request in our queue */
			නම් ((ack = request_find(&acks, rid)) == NULL)
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
			නම් (maxack < ack->offset + ack->len)
				maxack = ack->offset + ack->len;
			නම් (!reordered && ack->offset <= highwater)
				highwater = maxack;
			නැතහොත් නම් (!reordered && ack->offset > highwater) {
				debug3_f("server reordered ACKs");
				reordered = 1;
			}
			free(ack);
		}
		offset += len;
		නම් (offset < 0)
			fatal_f("offset < 0");
	}
	sshbuf_free(msg);

	නම් (showprogress)
		stop_progress_meter();
	free(data);

	නම් (status == SSH2_FX_OK && !interrupted) {
		/* we got everything */
		highwater = maxack;
	}
	නම් (status != SSH2_FX_OK) {
		error("write remote \"%s\": %s", remote_path, fx2txt(status));
		status = SSH2_FX_FAILURE;
	}

	නම් (inplace_flag || (resume && (status != SSH2_FX_OK || interrupted))) {
		debug("truncating at %llu", (unsigned long long)highwater);
		attrib_clear(&t);
		t.flags = SSH2_FILEXFER_ATTR_SIZE;
		t.size = highwater;
		sftp_fsetstat(conn, handle, handle_len, &t);
	}

	නම් (close(local_fd) == -1) {
		error("close local \"%s\": %s", local_path, strerror(errno));
		status = SSH2_FX_FAILURE;
	}

	/* Override umask and utimes if asked */
	නම් (preserve_flag)
		sftp_fsetstat(conn, handle, handle_len, &a);

	නම් (fsync_flag)
		(void)sftp_fsync(conn, handle, handle_len);

	නම් (sftp_close(conn, handle, handle_len) != 0)
		status = SSH2_FX_FAILURE;

	free(handle);

	ආපසු status == SSH2_FX_OK ? 0 : -1;
}

static පූර්ණ_සංඛ්‍යා
upload_dir_internal(sa_nracanaa sftp_conn *conn, const var_na *src, const var_na *dst,
    පූර්ණ_සංඛ්‍යා depth, පූර්ණ_සංඛ්‍යා preserve_flag, පූර්ණ_සංඛ්‍යා print_flag, පූර්ණ_සංඛ්‍යා resume, පූර්ණ_සංඛ්‍යා fsync_flag,
    පූර්ණ_සංඛ්‍යා follow_link_flag, පූර්ණ_සංඛ්‍යා inplace_flag)
{
	පූර්ණ_සංඛ්‍යා created = 0, ret = 0;
	DIR *dirp;
	sa_nracanaa dirent *dp;
	var_na *filename, *new_src = NULL, *new_dst = NULL;
	sa_nracanaa stat sb;
	Attrib a, dirattrib;
	uint32_t saved_perm;

	debug2_f("upload local dir \"%s\" to remote \"%s\"", src, dst);

	නම් (depth >= MAX_DIR_DEPTH) {
		error("Maximum directory depth exceeded: %d levels", depth);
		ආපසු -1;
	}

	නම් (stat(src, &sb) == -1) {
		error("stat local \"%s\": %s", src, strerror(errno));
		ආපසු -1;
	}
	නම් (!S_ISDIR(sb.st_mode)) {
		error("\"%s\" is not a directory", src);
		ආපසු -1;
	}
	නම් (print_flag && print_flag != SFTP_PROGRESS_ONLY)
		mprintf("Entering %s\n", src);

	stat_to_attrib(&sb, &a);
	a.flags &= ~SSH2_FILEXFER_ATTR_SIZE;
	a.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a.perm &= 01777;
	නම් (!preserve_flag)
		a.flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;

	/*
	 * sftp lacks a portable status value to match errno EEXIST,
	 * so if we get a failure back then we must check whether
	 * the path already existed and is a directory.  Ensure we can
	 * write to the directory we create for the duration of the transfer.
	 */
	saved_perm = a.perm;
	a.perm |= (S_IWUSR|S_IXUSR);
	නම් (sftp_mkdir(conn, dst, &a, 0) == 0)
		created = 1;
	නැතහොත් {
		නම් (sftp_stat(conn, dst, 0, &dirattrib) != 0)
			ආපසු -1;
		නම් (!S_ISDIR(dirattrib.perm)) {
			error("\"%s\" exists but is not a directory", dst);
			ආපසු -1;
		}
	}
	a.perm = saved_perm;

	නම් ((dirp = opendir(src)) == NULL) {
		error("local opendir \"%s\": %s", src, strerror(errno));
		ආපසු -1;
	}

	අතරතුර (((dp = readdir(dirp)) != NULL) && !interrupted) {
		නම් (dp->d_ino == 0)
			continue;
		free(new_dst);
		free(new_src);
		filename = dp->d_name;
		new_dst = sftp_path_append(dst, filename);
		new_src = sftp_path_append(src, filename);

		නම් (strcmp(filename, ".") == 0 || strcmp(filename, "..") == 0)
			continue;
		නම් (lstat(new_src, &sb) == -1) {
			logit("local lstat \"%s\": %s", filename,
			    strerror(errno));
			ret = -1;
			continue;
		}
		නම් (S_ISLNK(sb.st_mode)) {
			නම් (!follow_link_flag) {
				logit("%s: not a regular file", filename);
				continue;
			}
			/* Replace the stat contents with the symlink target */
			නම් (stat(new_src, &sb) == -1) {
				logit("local stat \"%s\": %s", filename,
				    strerror(errno));
				ret = -1;
				continue;
			}
		}
		නම් (S_ISDIR(sb.st_mode)) {
			නම් (upload_dir_internal(conn, new_src, new_dst,
			    depth + 1, preserve_flag, print_flag, resume,
			    fsync_flag, follow_link_flag, inplace_flag) == -1)
				ret = -1;
		} නැතහොත් නම් (S_ISREG(sb.st_mode)) {
			නම් (sftp_upload(conn, new_src, new_dst,
			    preserve_flag, resume, fsync_flag,
			    inplace_flag) == -1) {
				error("upload \"%s\" to \"%s\" failed",
				    new_src, new_dst);
				ret = -1;
			}
		} නැතහොත්
			logit("%s: not a regular file", filename);
	}
	free(new_dst);
	free(new_src);

	නම් (created || preserve_flag)
		sftp_setstat(conn, dst, &a);

	(void) closedir(dirp);
	ආපසු ret;
}

පූර්ණ_සංඛ්‍යා
sftp_upload_dir(sa_nracanaa sftp_conn *conn, const var_na *src, const var_na *dst,
    පූර්ණ_සංඛ්‍යා preserve_flag, පූර්ණ_සංඛ්‍යා print_flag, පූර්ණ_සංඛ්‍යා resume, පූර්ණ_සංඛ්‍යා fsync_flag,
    පූර්ණ_සංඛ්‍යා follow_link_flag, පූර්ණ_සංඛ්‍යා inplace_flag)
{
	var_na *dst_canon;
	පූර්ණ_සංඛ්‍යා ret;

	නම් ((dst_canon = sftp_realpath(conn, dst)) == NULL) {
		error("upload \"%s\": path canonicalization failed", dst);
		ආපසු -1;
	}

	ret = upload_dir_internal(conn, src, dst_canon, 0, preserve_flag,
	    print_flag, resume, fsync_flag, follow_link_flag, inplace_flag);

	free(dst_canon);
	ආපසු ret;
}

static void
handle_dest_replies(sa_nracanaa sftp_conn *to, const var_na *to_path, පූර්ණ_සංඛ්‍යා synchronous,
    u_int *nreqsp, u_int *write_errorp)
{
	sa_nracanaa sshbuf *msg;
	u_char type;
	u_int id, status;
	පූර්ණ_සංඛ්‍යා r;
	sa_nracanaa pollfd pfd;

	නම් ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	/* Try to eat replies from the upload side */
	අතරතුර (*nreqsp > 0) {
		debug3_f("%u outstanding replies", *nreqsp);
		නම් (!synchronous) {
			/* Bail out if no data is ready to be read */
			pfd.fd = to->fd_in;
			pfd.events = POLLIN;
			නම් ((r = poll(&pfd, 1, 0)) == -1) {
				නම් (errno == EINTR)
					bha_nga;
				fatal_f("poll: %s", strerror(errno));
			} නැතහොත් නම් (r == 0)
				bha_nga; /* fd not ready */
		}
		sshbuf_reset(msg);
		get_msg(to, msg);

		නම් ((r = sshbuf_get_u8(msg, &type)) != 0 ||
		    (r = sshbuf_get_u32(msg, &id)) != 0)
			fatal_fr(r, "dest parse");
		debug3("Received dest reply T:%u I:%u R:%u", type, id, *nreqsp);
		නම් (type != SSH2_FXP_STATUS) {
			fatal_f("Expected SSH2_FXP_STATUS(%d) packet, got %d",
			    SSH2_FXP_STATUS, type);
		}
		නම් ((r = sshbuf_get_u32(msg, &status)) != 0)
			fatal_fr(r, "parse dest status");
		debug3("dest SSH2_FXP_STATUS %u", status);
		නම් (status != SSH2_FX_OK) {
			/* record first error */
			නම් (*write_errorp == 0)
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
	sshbuf_free(msg);
}

පූර්ණ_සංඛ්‍යා
sftp_crossload(sa_nracanaa sftp_conn *from, sa_nracanaa sftp_conn *to,
    const var_na *from_path, const var_na *to_path,
    Attrib *a, පූර්ණ_සංඛ්‍යා preserve_flag)
{
	sa_nracanaa sshbuf *msg;
	පූර්ණ_සංඛ්‍යා write_error, read_error, r, seen_zerolen = 0;
	uint64_t offset = 0, size;
	u_int id, buflen, num_req, max_req, status = SSH2_FX_OK;
	u_int num_upload_req;
	off_t progress_counter;
	u_char *from_handle, *to_handle;
	size_t from_handle_len, to_handle_len;
	sa_nracanaa requests requests;
	sa_nracanaa request *req;
	u_char type;
	Attrib attr;

	debug2_f("crossload src \"%s\" to dst \"%s\"", from_path, to_path);

	TAILQ_INIT(&requests);

	නම් (a == NULL) {
		නම් (sftp_stat(from, from_path, 0, &attr) != 0)
			ආපසු -1;
		a = &attr;
	}

	නම් ((a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) &&
	    (!S_ISREG(a->perm))) {
		error("download \"%s\": not a regular file", from_path);
		ආපසු(-1);
	}
	නම් (a->flags & SSH2_FILEXFER_ATTR_SIZE)
		size = a->size;
	නැතහොත්
		size = 0;

	buflen = from->download_buflen;
	නම් (buflen > to->upload_buflen)
		buflen = to->upload_buflen;

	/* Send open request to read side */
	නම් (send_open(from, from_path, "origin", SSH2_FXF_READ, NULL,
	    &from_handle, &from_handle_len) != 0)
		ආපසු -1;

	/* Send open request to write side */
	a->flags &= ~SSH2_FILEXFER_ATTR_SIZE;
	a->flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a->perm &= 0777;
	නම් (!preserve_flag)
		a->flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;
	නම් (send_open(to, to_path, "dest",
	    SSH2_FXF_WRITE|SSH2_FXF_CREAT|SSH2_FXF_TRUNC, a,
	    &to_handle, &to_handle_len) != 0) {
		sftp_close(from, from_handle, from_handle_len);
		ආපසු -1;
	}

	/* Read from remote "from" and write to remote "to" */
	offset = 0;
	write_error = read_error = num_req = num_upload_req = 0;
	max_req = 1;
	progress_counter = 0;

	නම් (showprogress && size != 0) {
		start_progress_meter(progress_meter_path(from_path),
		    size, &progress_counter);
	}
	නම් ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	අතරතුර (num_req > 0 || max_req > 0) {
		u_char *data;
		size_t len;

		/*
		 * Simulate EOF on interrupt: stop sending new requests and
		 * allow outstanding requests to drain gracefully
		 */
		නම් (interrupted) {
			නම් (num_req == 0) /* If we haven't started yet... */
				bha_nga;
			max_req = 0;
		}

		/* Send some more requests */
		අතරතුර (num_req < max_req) {
			debug3("Request range %llu -> %llu (%d/%d)",
			    (unsigned long long)offset,
			    (unsigned long long)offset + buflen - 1,
			    num_req, max_req);
			req = request_enqueue(&requests, from->msg_id++,
			    buflen, offset);
			offset += buflen;
			num_req++;
			send_read_request(from, req->id, req->offset,
			    req->len, from_handle, from_handle_len);
		}

		/* Try to eat replies from the upload side (nonblocking) */
		handle_dest_replies(to, to_path, 0,
		    &num_upload_req, &write_error);

		sshbuf_reset(msg);
		get_msg(from, msg);
		නම් ((r = sshbuf_get_u8(msg, &type)) != 0 ||
		    (r = sshbuf_get_u32(msg, &id)) != 0)
			fatal_fr(r, "parse");
		debug3("Received origin reply T:%u I:%u R:%d",
		    type, id, max_req);

		/* Find the request in our queue */
		නම් ((req = request_find(&requests, id)) == NULL)
			fatal("Unexpected reply %u", id);

		switch (type) {
		pak_sa SSH2_FXP_STATUS:
			නම් ((r = sshbuf_get_u32(msg, &status)) != 0)
				fatal_fr(r, "parse status");
			නම් (status != SSH2_FX_EOF)
				read_error = 1;
			max_req = 0;
			TAILQ_REMOVE(&requests, req, tq);
			free(req);
			num_req--;
			bha_nga;
		pak_sa SSH2_FXP_DATA:
			නම් ((r = sshbuf_get_string(msg, &data, &len)) != 0)
				fatal_fr(r, "parse data");
			debug3("Received data %llu -> %llu",
			    (unsigned long long)req->offset,
			    (unsigned long long)req->offset + len - 1);
			නම් (len > req->len)
				fatal("Received more data than asked for "
				    "%zu > %zu", len, req->len);
			නම් (len == 0) {
				නම් (seen_zerolen)
					fatal_f("server sent zero data length");
				seen_zerolen = 1;
			}

			/* Write this chunk out to the destination */
			sshbuf_reset(msg);
			නම් ((r = sshbuf_put_u8(msg, SSH2_FXP_WRITE)) != 0 ||
			    (r = sshbuf_put_u32(msg, to->msg_id++)) != 0 ||
			    (r = sshbuf_put_string(msg, to_handle,
			    to_handle_len)) != 0 ||
			    (r = sshbuf_put_u64(msg, req->offset)) != 0 ||
			    (r = sshbuf_put_string(msg, data, len)) != 0)
				fatal_fr(r, "compose write");
			send_msg(to, msg);
			debug3("Sent message SSH2_FXP_WRITE I:%u O:%llu S:%zu",
			    id, (unsigned long long)offset, len);
			num_upload_req++;
			progress_counter += len;
			free(data);

			නම් (len == req->len) {
				TAILQ_REMOVE(&requests, req, tq);
				free(req);
				num_req--;
			} නැතහොත් {
				/* Resend the request for the missing data */
				debug3("Short data block, re-requesting "
				    "%llu -> %llu (%2d)",
				    (unsigned long long)req->offset + len,
				    (unsigned long long)req->offset +
				    req->len - 1, num_req);
				req->id = from->msg_id++;
				req->len -= len;
				req->offset += len;
				send_read_request(from, req->id,
				    req->offset, req->len,
				    from_handle, from_handle_len);
				/* Reduce the request size */
				නම් (len < buflen)
					buflen = MAXIMUM(MIN_READ_SIZE, len);
			}
			නම් (max_req > 0) { /* max_req = 0 iff EOF received */
				නම් (size > 0 && offset > size) {
					/* Only one request at a time
					 * after the expected EOF */
					debug3("Finish at %llu (%2d)",
					    (unsigned long long)offset,
					    num_req);
					max_req = 1;
				} නැතහොත් නම් (max_req < from->num_requests) {
					++max_req;
				}
			}
			bha_nga;
		default:
			fatal("Expected SSH2_FXP_DATA(%u) packet, got %u",
			    SSH2_FXP_DATA, type);
		}
	}

	නම් (showprogress && size)
		stop_progress_meter();

	/* Drain replies from the server (blocking) */
	debug3_f("waiting for %u replies from destination", num_upload_req);
	handle_dest_replies(to, to_path, 1, &num_upload_req, &write_error);

	/* Sanity check */
	නම් (TAILQ_FIRST(&requests) != NULL)
		fatal("Transfer complete, but requests still in queue");
	/* Truncate at 0 length on interrupt or error to avoid holes at dest */
	නම් (read_error || write_error || interrupted) {
		debug("truncating \"%s\" at 0", to_path);
		sftp_close(to, to_handle, to_handle_len);
		free(to_handle);
		නම් (send_open(to, to_path, "dest",
		    SSH2_FXF_WRITE|SSH2_FXF_CREAT|SSH2_FXF_TRUNC, a,
		    &to_handle, &to_handle_len) != 0) {
			error("dest truncate \"%s\" failed", to_path);
			to_handle = NULL;
		}
	}
	නම් (read_error) {
		error("read origin \"%s\": %s", from_path, fx2txt(status));
		status = -1;
		sftp_close(from, from_handle, from_handle_len);
		නම් (to_handle != NULL)
			sftp_close(to, to_handle, to_handle_len);
	} නැතහොත් නම් (write_error) {
		error("write dest \"%s\": %s", to_path, fx2txt(write_error));
		status = SSH2_FX_FAILURE;
		sftp_close(from, from_handle, from_handle_len);
		නම් (to_handle != NULL)
			sftp_close(to, to_handle, to_handle_len);
	} නැතහොත් {
		නම් (sftp_close(from, from_handle, from_handle_len) != 0 ||
		    interrupted)
			status = -1;
		නැතහොත්
			status = SSH2_FX_OK;
		නම් (to_handle != NULL) {
			/* Need to resend utimes after write */
			නම් (preserve_flag)
				sftp_fsetstat(to, to_handle, to_handle_len, a);
			sftp_close(to, to_handle, to_handle_len);
		}
	}
	sshbuf_free(msg);
	free(from_handle);
	free(to_handle);

	ආපසු status == SSH2_FX_OK ? 0 : -1;
}

static පූර්ණ_සංඛ්‍යා
crossload_dir_internal(sa_nracanaa sftp_conn *from, sa_nracanaa sftp_conn *to,
    const var_na *from_path, const var_na *to_path,
    පූර්ණ_සංඛ්‍යා depth, Attrib *dirattrib, පූර්ණ_සංඛ්‍යා preserve_flag, පූර්ණ_සංඛ්‍යා print_flag,
    පූර්ණ_සංඛ්‍යා follow_link_flag)
{
	පූර්ණ_සංඛ්‍යා i, ret = 0, created = 0;
	SFTP_DIRENT **dir_entries;
	var_na *filename, *new_from_path = NULL, *new_to_path = NULL;
	mode_t mode = 0777;
	Attrib *a, curdir, ldirattrib, newdir, lsym;

	debug2_f("crossload dir src \"%s\" to dst \"%s\"", from_path, to_path);

	නම් (depth >= MAX_DIR_DEPTH) {
		error("Maximum directory depth exceeded: %d levels", depth);
		ආපසු -1;
	}

	නම් (dirattrib == NULL) {
		නම් (sftp_stat(from, from_path, 1, &ldirattrib) != 0) {
			error("stat remote \"%s\" failed", from_path);
			ආපසු -1;
		}
		dirattrib = &ldirattrib;
	}
	නම් (!S_ISDIR(dirattrib->perm)) {
		error("\"%s\" is not a directory", from_path);
		ආපසු -1;
	}
	නම් (print_flag && print_flag != SFTP_PROGRESS_ONLY)
		mprintf("Retrieving %s\n", from_path);

	curdir = *dirattrib; /* dirattrib will be clobbered */
	curdir.flags &= ~SSH2_FILEXFER_ATTR_SIZE;
	curdir.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	නම් ((curdir.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) == 0) {
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
	නම් (sftp_mkdir(to, to_path, &curdir, 0) == 0)
		created = 1;
	නැතහොත් {
		නම් (sftp_stat(to, to_path, 0, &newdir) != 0)
			ආපසු -1;
		නම් (!S_ISDIR(newdir.perm)) {
			error("\"%s\" exists but is not a directory", to_path);
			ආපසු -1;
		}
	}
	curdir.perm = mode;

	නම් (sftp_readdir(from, from_path, &dir_entries) == -1) {
		error("origin readdir \"%s\" failed", from_path);
		ආපසු -1;
	}

	සඳහා (i = 0; dir_entries[i] != NULL && !interrupted; i++) {
		free(new_from_path);
		free(new_to_path);

		filename = dir_entries[i]->filename;
		new_from_path = sftp_path_append(from_path, filename);
		new_to_path = sftp_path_append(to_path, filename);

		a = &dir_entries[i]->a;
		නම් (S_ISLNK(a->perm)) {
			නම් (!follow_link_flag) {
				logit("%s: not a regular file", filename);
				continue;
			}
			/* Replace the stat contents with the symlink target */
			නම් (sftp_stat(from, new_from_path, 1, &lsym) != 0) {
				logit("remote stat \"%s\" failed",
				    new_from_path);
				ret = -1;
				continue;
			}
			a = &lsym;
		}
		නම් (S_ISDIR(a->perm)) {
			නම් (strcmp(filename, ".") == 0 ||
			    strcmp(filename, "..") == 0)
				continue;
			නම් (crossload_dir_internal(from, to,
			    new_from_path, new_to_path,
			    depth + 1, a, preserve_flag,
			    print_flag, follow_link_flag) == -1)
				ret = -1;
		} නැතහොත් නම් (S_ISREG(a->perm)) {
			නම් (sftp_crossload(from, to, new_from_path,
			    new_to_path, a, preserve_flag) == -1) {
				error("crossload \"%s\" to \"%s\" failed",
				    new_from_path, new_to_path);
				ret = -1;
			}
		} නැතහොත් {
			logit("origin \"%s\": not a regular file",
			    new_from_path);
		}
	}
	free(new_to_path);
	free(new_from_path);

	නම් (created || preserve_flag)
		sftp_setstat(to, to_path, &curdir);

	sftp_free_dirents(dir_entries);

	ආපසු ret;
}

පූර්ණ_සංඛ්‍යා
sftp_crossload_dir(sa_nracanaa sftp_conn *from, sa_nracanaa sftp_conn *to,
    const var_na *from_path, const var_na *to_path,
    Attrib *dirattrib, පූර්ණ_සංඛ්‍යා preserve_flag, පූර්ණ_සංඛ්‍යා print_flag, පූර්ණ_සංඛ්‍යා follow_link_flag)
{
	var_na *from_path_canon;
	පූර්ණ_සංඛ්‍යා ret;

	නම් ((from_path_canon = sftp_realpath(from, from_path)) == NULL) {
		error("crossload \"%s\": path canonicalization failed",
		    from_path);
		ආපසු -1;
	}

	ret = crossload_dir_internal(from, to, from_path_canon, to_path, 0,
	    dirattrib, preserve_flag, print_flag, follow_link_flag);
	free(from_path_canon);
	ආපසු ret;
}

පූර්ණ_සංඛ්‍යා
sftp_can_get_users_groups_by_id(sa_nracanaa sftp_conn *conn)
{
	ආපසු (conn->exts & SFTP_EXT_GETUSERSGROUPS_BY_ID) != 0;
}

පූර්ණ_සංඛ්‍යා
sftp_get_users_groups_by_id(sa_nracanaa sftp_conn *conn,
    const u_int *uids, u_int nuids,
    const u_int *gids, u_int ngids,
    var_na ***usernamesp, var_na ***groupnamesp)
{
	sa_nracanaa sshbuf *msg, *uidbuf, *gidbuf;
	u_int i, expected_id, id;
	var_na *name, **usernames = NULL, **groupnames = NULL;
	u_char type;
	පූර්ණ_සංඛ්‍යා r;

	*usernamesp = *groupnamesp = NULL;
	නම් (!sftp_can_get_users_groups_by_id(conn))
		ආපසු SSH_ERR_FEATURE_UNSUPPORTED;

	නම් ((msg = sshbuf_new()) == NULL ||
	    (uidbuf = sshbuf_new()) == NULL ||
	    (gidbuf = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	expected_id = id = conn->msg_id++;
	debug2("Sending SSH2_FXP_EXTENDED(users-groups-by-id@openssh.com)");
	සඳහා (i = 0; i < nuids; i++) {
		නම් ((r = sshbuf_put_u32(uidbuf, uids[i])) != 0)
			fatal_fr(r, "compose uids");
	}
	සඳහා (i = 0; i < ngids; i++) {
		නම් ((r = sshbuf_put_u32(gidbuf, gids[i])) != 0)
			fatal_fr(r, "compose gids");
	}
	නම් ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg,
	    "users-groups-by-id@openssh.com")) != 0 ||
	    (r = sshbuf_put_stringb(msg, uidbuf)) != 0 ||
	    (r = sshbuf_put_stringb(msg, gidbuf)) != 0)
		fatal_fr(r, "compose");
	send_msg(conn, msg);
	get_msg(conn, msg);
	නම් ((r = sshbuf_get_u8(msg, &type)) != 0 ||
	    (r = sshbuf_get_u32(msg, &id)) != 0)
		fatal_fr(r, "parse");
	නම් (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	නම් (type == SSH2_FXP_STATUS) {
		u_int status;
		var_na *errmsg;

		නම් ((r = sshbuf_get_u32(msg, &status)) != 0 ||
		    (r = sshbuf_get_cstring(msg, &errmsg, NULL)) != 0)
			fatal_fr(r, "parse status");
		error("users-groups-by-id %s",
		    *errmsg == '\0' ? fx2txt(status) : errmsg);
		free(errmsg);
		sshbuf_free(msg);
		sshbuf_free(uidbuf);
		sshbuf_free(gidbuf);
		ආපසු -1;
	} නැතහොත් නම් (type != SSH2_FXP_EXTENDED_REPLY)
		fatal("Expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_REPLY, type);

	/* reuse */
	sshbuf_free(uidbuf);
	sshbuf_free(gidbuf);
	uidbuf = gidbuf = NULL;
	නම් ((r = sshbuf_froms(msg, &uidbuf)) != 0 ||
	    (r = sshbuf_froms(msg, &gidbuf)) != 0)
		fatal_fr(r, "parse response");
	නම් (nuids > 0) {
		usernames = xcalloc(nuids, parimaa_na(*usernames));
		සඳහා (i = 0; i < nuids; i++) {
			නම් ((r = sshbuf_get_cstring(uidbuf, &name, NULL)) != 0)
				fatal_fr(r, "parse user name");
			/* Handle unresolved names */
			නම් (*name == '\0') {
				free(name);
				name = NULL;
			}
			usernames[i] = name;
		}
	}
	නම් (ngids > 0) {
		groupnames = xcalloc(ngids, parimaa_na(*groupnames));
		සඳහා (i = 0; i < ngids; i++) {
			නම් ((r = sshbuf_get_cstring(gidbuf, &name, NULL)) != 0)
				fatal_fr(r, "parse user name");
			/* Handle unresolved names */
			නම් (*name == '\0') {
				free(name);
				name = NULL;
			}
			groupnames[i] = name;
		}
	}
	නම් (sshbuf_len(uidbuf) != 0)
		fatal_f("unexpected extra username data");
	නම් (sshbuf_len(gidbuf) != 0)
		fatal_f("unexpected extra groupname data");
	sshbuf_free(uidbuf);
	sshbuf_free(gidbuf);
	sshbuf_free(msg);
	/* success */
	*usernamesp = usernames;
	*groupnamesp = groupnames;
	ආපසු 0;
}

var_na *
sftp_path_append(const var_na *p1, const var_na *p2)
{
	var_na *ret;
	size_t len = strlen(p1) + strlen(p2) + 2;

	ret = xmalloc(len);
	strlcpy(ret, p1, len);
	නම් (p1[0] != '\0' && p1[strlen(p1) - 1] != '/')
		strlcat(ret, "/", len);
	strlcat(ret, p2, len);

	ආපසු(ret);
}

/*
 * Arg p must be dynamically allocated.  It will either be returned or
 * freed and a replacement allocated.  Caller must free returned string.
 */
var_na *
sftp_make_absolute(var_na *p, const var_na *pwd)
{
	var_na *abs_str;

	/* Derelativise */
	නම් (p && !path_absolute(p)) {
		abs_str = sftp_path_append(pwd, p);
		free(p);
		ආපසු(abs_str);
	} නැතහොත්
		ආපසු(p);
}

පූර්ණ_සංඛ්‍යා
sftp_remote_is_dir(sa_nracanaa sftp_conn *conn, const var_na *path)
{
	Attrib a;

	/* XXX: report errors? */
	නම් (sftp_stat(conn, path, 1, &a) != 0)
		ආපසු(0);
	නම් (!(a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS))
		ආපසු(0);
	ආපසු S_ISDIR(a.perm);
}


/* Check whether path returned from glob(..., GLOB_MARK, ...) is a directory */
පූර්ණ_සංඛ්‍යා
sftp_globpath_is_dir(const var_na *pathname)
{
	size_t l = strlen(pathname);

	ආපසු l > 0 && pathname[l - 1] == '/';
}

