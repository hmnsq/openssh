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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/queue.h>
#அந்தர்பாவ <sys/stat.h>
#அந்தர்பாவ <sys/time.h>
#அந்தர்பாவ <sys/statvfs.h>
#அந்தர்பாவ <sys/uio.h>

#அந்தர்பாவ <dirent.h>
#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <fcntl.h>
#அந்தர்பாவ <poll.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "atomicio.h"
#அந்தர்பாவ "progressmeter.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "utf8.h"

#அந்தர்பாவ "sftp.h"
#அந்தர்பாவ "sftp-common.h"
#அந்தர்பாவ "sftp-client.h"

வெளி நிலையற்ற sig_atomic_t interrupted;
வெளி முழு showprogress;

/* Default size of buffer for up/download (fix sftp.1 scp.1 if changed) */
#define DEFAULT_COPY_BUFLEN	32768

/* Default number of concurrent xfer requests (fix sftp.1 scp.1 if changed) */
#define DEFAULT_இலக்கம்_REQUESTS	64

/* Minimum amount of data to read at a time */
#define MIN_READ_SIZE	512

/* Maximum depth to descend in directory trees */
#define MAX_DIR_DEPTH 64

/* Directory separator characters */
#ifdef HAVE_CYGWIN
# define SFTP_DIRECTORY_CHARS      "/\\"
#இல்லையெனில் /* HAVE_CYGWIN */
# define SFTP_DIRECTORY_CHARS      "/"
#endif /* HAVE_CYGWIN */

கட்டமைப்பு sftp_conn {
	முழு fd_in;
	முழு fd_out;
	u_int download_buflen;
	u_int upload_buflen;
	u_int இலக்கம்_requests;
	u_int version;
	u_int செய்தி_id;
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
	கட்டமைப்பு bwlimit bwlimit_in, bwlimit_out;
};

/* Tracks in-progress requests during file transfers */
கட்டமைப்பு request {
	u_int id;
	size_t len;
	uint64_t offset;
	TAILQ_ENTRY(request) tq;
};
TAILQ_HEAD(requests, request);

நிலையான u_char *
get_handle(கட்டமைப்பு sftp_conn *conn, u_int expected_id, size_t *len,
    மாறிலி எழுத்து *errfmt, ...) __attribute__((format(printf, 4, 5)));

நிலையான கட்டமைப்பு request *
request_enqueue(கட்டமைப்பு requests *requests, u_int id, size_t len,
    uint64_t offset)
{
	கட்டமைப்பு request *req;

	req = xcalloc(1, அளவு(*req));
	req->id = id;
	req->len = len;
	req->offset = offset;
	TAILQ_INSERT_TAIL(requests, req, tq);
	திரும்பு req;
}

நிலையான கட்டமைப்பு request *
request_find(கட்டமைப்பு requests *requests, u_int id)
{
	கட்டமைப்பு request *req;

	க்கு (req = TAILQ_FIRST(requests);
	    req != வெற்று && req->id != id;
	    req = TAILQ_NEXT(req, tq))
		;
	திரும்பு req;
}

நிலையான முழு
sftpio(வெறுமை *_bwlimit, size_t amount)
{
	கட்டமைப்பு bwlimit *bwlimit = (கட்டமைப்பு bwlimit *)_bwlimit;

	refresh_progress_meter(0);
	எனில் (bwlimit != வெற்று)
		bandwidth_limit(bwlimit, amount);
	திரும்பு 0;
}

நிலையான வெறுமை
send_செய்தி(கட்டமைப்பு sftp_conn *conn, கட்டமைப்பு sshbuf *m)
{
	u_char mlen[4];
	கட்டமைப்பு iovec iov[2];

	எனில் (sshbuf_len(m) > SFTP_MAX_செய்தி_LENGTH)
		fatal("Outbound message too long %zu", sshbuf_len(m));

	/* Send length first */
	put_u32(mlen, sshbuf_len(m));
	iov[0].iov_base = mlen;
	iov[0].iov_len = அளவு(mlen);
	iov[1].iov_base = (u_char *)sshbuf_ptr(m);
	iov[1].iov_len = sshbuf_len(m);

	எனில் (atomiciov6(writev, conn->fd_out, iov, 2, sftpio,
	    conn->limit_kbps > 0 ? &conn->bwlimit_out : வெற்று) !=
	    sshbuf_len(m) + அளவு(mlen))
		fatal("Couldn't send packet: %s", strerror(errno));

	sshbuf_reset(m);
}

நிலையான வெறுமை
get_செய்தி_extended(கட்டமைப்பு sftp_conn *conn, கட்டமைப்பு sshbuf *m, முழு initial)
{
	u_int செய்தி_len;
	u_char *p;
	முழு r;

	sshbuf_reset(m);
	எனில் ((r = sshbuf_reserve(m, 4, &p)) != 0)
		fatal_fr(r, "reserve");
	எனில் (atomicio6(பட, conn->fd_in, p, 4, sftpio,
	    conn->limit_kbps > 0 ? &conn->bwlimit_in : வெற்று) != 4) {
		எனில் (errno == EPIPE || errno == ECONNRESET)
			fatal("Connection closed");
		இல்லையெனில்
			fatal("Couldn't read packet: %s", strerror(errno));
	}

	எனில் ((r = sshbuf_get_u32(m, &செய்தி_len)) != 0)
		fatal_fr(r, "sshbuf_get_u32");
	எனில் (செய்தி_len > SFTP_MAX_செய்தி_LENGTH) {
		do_log2(initial ? SYSLOG_LEVEL_ERROR : SYSLOG_LEVEL_FATAL,
		    "Received message too long %u", செய்தி_len);
		fatal("Ensure the remote shell produces no output "
		    "for non-interactive sessions.");
	}

	எனில் ((r = sshbuf_reserve(m, செய்தி_len, &p)) != 0)
		fatal_fr(r, "reserve");
	எனில் (atomicio6(பட, conn->fd_in, p, செய்தி_len, sftpio,
	    conn->limit_kbps > 0 ? &conn->bwlimit_in : வெற்று)
	    != செய்தி_len) {
		எனில் (errno == EPIPE)
			fatal("Connection closed");
		இல்லையெனில்
			fatal("Read packet: %s", strerror(errno));
	}
}

நிலையான வெறுமை
get_செய்தி(கட்டமைப்பு sftp_conn *conn, கட்டமைப்பு sshbuf *m)
{
	get_செய்தி_extended(conn, m, 0);
}

நிலையான வெறுமை
send_string_request(கட்டமைப்பு sftp_conn *conn, u_int id, u_int code, மாறிலி எழுத்து *s,
    u_int len)
{
	கட்டமைப்பு sshbuf *செய்தி;
	முழு r;

	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = sshbuf_put_u8(செய்தி, code)) != 0 ||
	    (r = sshbuf_put_u32(செய்தி, id)) != 0 ||
	    (r = sshbuf_put_string(செய்தி, s, len)) != 0)
		fatal_fr(r, "compose");
	send_செய்தி(conn, செய்தி);
	debug3("Sent message fd %d T:%u I:%u", conn->fd_out, code, id);
	sshbuf_free(செய்தி);
}

நிலையான வெறுமை
send_string_attrs_request(கட்டமைப்பு sftp_conn *conn, u_int id, u_int code,
    மாறிலி வெறுமை *s, u_int len, Attrib *a)
{
	கட்டமைப்பு sshbuf *செய்தி;
	முழு r;

	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = sshbuf_put_u8(செய்தி, code)) != 0 ||
	    (r = sshbuf_put_u32(செய்தி, id)) != 0 ||
	    (r = sshbuf_put_string(செய்தி, s, len)) != 0 ||
	    (r = encode_attrib(செய்தி, a)) != 0)
		fatal_fr(r, "compose");
	send_செய்தி(conn, செய்தி);
	debug3("Sent message fd %d T:%u I:%u F:0x%04x M:%05o",
	    conn->fd_out, code, id, a->flags, a->perm);
	sshbuf_free(செய்தி);
}

நிலையான u_int
get_status(கட்டமைப்பு sftp_conn *conn, u_int expected_id)
{
	கட்டமைப்பு sshbuf *செய்தி;
	u_char type;
	u_int id, status;
	முழு r;

	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	get_செய்தி(conn, செய்தி);
	எனில் ((r = sshbuf_get_u8(செய்தி, &type)) != 0 ||
	    (r = sshbuf_get_u32(செய்தி, &id)) != 0)
		fatal_fr(r, "compose");

	எனில் (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	எனில் (type != SSH2_FXP_STATUS)
		fatal("Expected SSH2_FXP_STATUS(%u) packet, got %u",
		    SSH2_FXP_STATUS, type);

	எனில் ((r = sshbuf_get_u32(செய்தி, &status)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(செய்தி);

	debug3("SSH2_FXP_STATUS %u", status);

	திரும்பு status;
}

நிலையான u_char *
get_handle(கட்டமைப்பு sftp_conn *conn, u_int expected_id, size_t *len,
    மாறிலி எழுத்து *errfmt, ...)
{
	கட்டமைப்பு sshbuf *செய்தி;
	u_int id, status;
	u_char type;
	u_char *handle;
	எழுத்து errmsg[256];
	va_list args;
	முழு r;

	va_start(args, errfmt);
	எனில் (errfmt != வெற்று)
		vsnprintf(errmsg, அளவு(errmsg), errfmt, args);
	va_end(args);

	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	get_செய்தி(conn, செய்தி);
	எனில் ((r = sshbuf_get_u8(செய்தி, &type)) != 0 ||
	    (r = sshbuf_get_u32(செய்தி, &id)) != 0)
		fatal_fr(r, "parse");

	எனில் (id != expected_id)
		fatal("%s: ID mismatch (%u != %u)",
		    errfmt == வெற்று ? __func__ : errmsg, id, expected_id);
	எனில் (type == SSH2_FXP_STATUS) {
		எனில் ((r = sshbuf_get_u32(செய்தி, &status)) != 0)
			fatal_fr(r, "parse status");
		எனில் (errfmt != வெற்று)
			error("%s: %s", errmsg, fx2txt(status));
		sshbuf_free(செய்தி);
		திரும்பு(வெற்று);
	} இல்லையெனில் எனில் (type != SSH2_FXP_HANDLE)
		fatal("%s: Expected SSH2_FXP_HANDLE(%u) packet, got %u",
		    errfmt == வெற்று ? __func__ : errmsg, SSH2_FXP_HANDLE, type);

	எனில் ((r = sshbuf_get_string(செய்தி, &handle, len)) != 0)
		fatal_fr(r, "parse handle");
	sshbuf_free(செய்தி);

	திரும்பு handle;
}

நிலையான முழு
get_decode_stat(கட்டமைப்பு sftp_conn *conn, u_int expected_id, முழு quiet, Attrib *a)
{
	கட்டமைப்பு sshbuf *செய்தி;
	u_int id;
	u_char type;
	முழு r;
	Attrib attr;

	எனில் (a != வெற்று)
		memset(a, '\0', அளவு(*a));
	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	get_செய்தி(conn, செய்தி);

	எனில் ((r = sshbuf_get_u8(செய்தி, &type)) != 0 ||
	    (r = sshbuf_get_u32(செய்தி, &id)) != 0)
		fatal_fr(r, "parse");

	எனில் (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	எனில் (type == SSH2_FXP_STATUS) {
		u_int status;

		எனில் ((r = sshbuf_get_u32(செய்தி, &status)) != 0)
			fatal_fr(r, "parse status");
		எனில் (quiet)
			debug("stat remote: %s", fx2txt(status));
		இல்லையெனில்
			error("stat remote: %s", fx2txt(status));
		sshbuf_free(செய்தி);
		திரும்பு -1;
	} இல்லையெனில் எனில் (type != SSH2_FXP_ATTRS) {
		fatal("Expected SSH2_FXP_ATTRS(%u) packet, got %u",
		    SSH2_FXP_ATTRS, type);
	}
	எனில் ((r = decode_attrib(செய்தி, &attr)) != 0) {
		error_fr(r, "decode_attrib");
		sshbuf_free(செய்தி);
		திரும்பு -1;
	}
	/* success */
	எனில் (a != வெற்று)
		*a = attr;
	debug3("Received stat reply T:%u I:%u F:0x%04x M:%05o",
	    type, id, attr.flags, attr.perm);
	sshbuf_free(செய்தி);

	திரும்பு 0;
}

நிலையான முழு
get_decode_statvfs(கட்டமைப்பு sftp_conn *conn, கட்டமைப்பு sftp_statvfs *st,
    u_int expected_id, முழு quiet)
{
	கட்டமைப்பு sshbuf *செய்தி;
	u_char type;
	u_int id;
	uint64_t flag;
	முழு r;

	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	get_செய்தி(conn, செய்தி);

	எனில் ((r = sshbuf_get_u8(செய்தி, &type)) != 0 ||
	    (r = sshbuf_get_u32(செய்தி, &id)) != 0)
		fatal_fr(r, "parse");

	debug3("Received statvfs reply T:%u I:%u", type, id);
	எனில் (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	எனில் (type == SSH2_FXP_STATUS) {
		u_int status;

		எனில் ((r = sshbuf_get_u32(செய்தி, &status)) != 0)
			fatal_fr(r, "parse status");
		எனில் (quiet)
			debug("remote statvfs: %s", fx2txt(status));
		இல்லையெனில்
			error("remote statvfs: %s", fx2txt(status));
		sshbuf_free(செய்தி);
		திரும்பு -1;
	} இல்லையெனில் எனில் (type != SSH2_FXP_EXTENDED_REPLY) {
		fatal("Expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_REPLY, type);
	}

	memset(st, 0, அளவு(*st));
	எனில் ((r = sshbuf_get_u64(செய்தி, &st->f_bsize)) != 0 ||
	    (r = sshbuf_get_u64(செய்தி, &st->f_frsize)) != 0 ||
	    (r = sshbuf_get_u64(செய்தி, &st->f_blocks)) != 0 ||
	    (r = sshbuf_get_u64(செய்தி, &st->f_bfree)) != 0 ||
	    (r = sshbuf_get_u64(செய்தி, &st->f_bavail)) != 0 ||
	    (r = sshbuf_get_u64(செய்தி, &st->f_files)) != 0 ||
	    (r = sshbuf_get_u64(செய்தி, &st->f_ffree)) != 0 ||
	    (r = sshbuf_get_u64(செய்தி, &st->f_favail)) != 0 ||
	    (r = sshbuf_get_u64(செய்தி, &st->f_fsid)) != 0 ||
	    (r = sshbuf_get_u64(செய்தி, &flag)) != 0 ||
	    (r = sshbuf_get_u64(செய்தி, &st->f_namemax)) != 0)
		fatal_fr(r, "parse statvfs");

	st->f_flag = (flag & SSH2_FXE_STATVFS_ST_RDONLY) ? ST_RDONLY : 0;
	st->f_flag |= (flag & SSH2_FXE_STATVFS_ST_NOSUID) ? ST_NOSUID : 0;

	sshbuf_free(செய்தி);

	திரும்பு 0;
}

கட்டமைப்பு sftp_conn *
sftp_init(முழு fd_in, முழு fd_out, u_int transfer_buflen, u_int இலக்கம்_requests,
    uint64_t limit_kbps)
{
	u_char type;
	கட்டமைப்பு sshbuf *செய்தி;
	கட்டமைப்பு sftp_conn *ret;
	முழு r;

	ret = xcalloc(1, அளவு(*ret));
	ret->செய்தி_id = 1;
	ret->fd_in = fd_in;
	ret->fd_out = fd_out;
	ret->download_buflen = ret->upload_buflen =
	    transfer_buflen ? transfer_buflen : DEFAULT_COPY_BUFLEN;
	ret->இலக்கம்_requests =
	    இலக்கம்_requests ? இலக்கம்_requests : DEFAULT_இலக்கம்_REQUESTS;
	ret->exts = 0;
	ret->limit_kbps = 0;

	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = sshbuf_put_u8(செய்தி, SSH2_FXP_INIT)) != 0 ||
	    (r = sshbuf_put_u32(செய்தி, SSH2_FILEXFER_VERSION)) != 0)
		fatal_fr(r, "parse");

	send_செய்தி(ret, செய்தி);

	get_செய்தி_extended(ret, செய்தி, 1);

	/* Expecting a VERSION reply */
	எனில் ((r = sshbuf_get_u8(செய்தி, &type)) != 0)
		fatal_fr(r, "parse type");
	எனில் (type != SSH2_FXP_VERSION) {
		error("Invalid packet back from SSH2_FXP_INIT (type %u)",
		    type);
		sshbuf_free(செய்தி);
		விடுவி(ret);
		திரும்பு(வெற்று);
	}
	எனில் ((r = sshbuf_get_u32(செய்தி, &ret->version)) != 0)
		fatal_fr(r, "parse version");

	debug2("Remote version: %u", ret->version);

	/* Check for extensions */
	போது (sshbuf_len(செய்தி) > 0) {
		எழுத்து *name;
		u_char *மதிப்பு;
		size_t vlen;
		முழு known = 0;

		எனில் ((r = sshbuf_get_cstring(செய்தி, &name, வெற்று)) != 0 ||
		    (r = sshbuf_get_string(செய்தி, &மதிப்பு, &vlen)) != 0)
			fatal_fr(r, "parse extension");
		எனில் (strcmp(name, "posix-rename@openssh.com") == 0 &&
		    strcmp((எழுத்து *)மதிப்பு, "1") == 0) {
			ret->exts |= SFTP_EXT_POSIX_RENAME;
			known = 1;
		} இல்லையெனில் எனில் (strcmp(name, "statvfs@openssh.com") == 0 &&
		    strcmp((எழுத்து *)மதிப்பு, "2") == 0) {
			ret->exts |= SFTP_EXT_STATVFS;
			known = 1;
		} இல்லையெனில் எனில் (strcmp(name, "fstatvfs@openssh.com") == 0 &&
		    strcmp((எழுத்து *)மதிப்பு, "2") == 0) {
			ret->exts |= SFTP_EXT_FSTATVFS;
			known = 1;
		} இல்லையெனில் எனில் (strcmp(name, "hardlink@openssh.com") == 0 &&
		    strcmp((எழுத்து *)மதிப்பு, "1") == 0) {
			ret->exts |= SFTP_EXT_HARDLINK;
			known = 1;
		} இல்லையெனில் எனில் (strcmp(name, "fsync@openssh.com") == 0 &&
		    strcmp((எழுத்து *)மதிப்பு, "1") == 0) {
			ret->exts |= SFTP_EXT_FSYNC;
			known = 1;
		} இல்லையெனில் எனில் (strcmp(name, "lsetstat@openssh.com") == 0 &&
		    strcmp((எழுத்து *)மதிப்பு, "1") == 0) {
			ret->exts |= SFTP_EXT_LSETSTAT;
			known = 1;
		} இல்லையெனில் எனில் (strcmp(name, "limits@openssh.com") == 0 &&
		    strcmp((எழுத்து *)மதிப்பு, "1") == 0) {
			ret->exts |= SFTP_EXT_LIMITS;
			known = 1;
		} இல்லையெனில் எனில் (strcmp(name, "expand-path@openssh.com") == 0 &&
		    strcmp((எழுத்து *)மதிப்பு, "1") == 0) {
			ret->exts |= SFTP_EXT_PATH_EXPAND;
			known = 1;
		} இல்லையெனில் எனில் (strcmp(name, "copy-data") == 0 &&
		    strcmp((எழுத்து *)மதிப்பு, "1") == 0) {
			ret->exts |= SFTP_EXT_COPY_DATA;
			known = 1;
		} இல்லையெனில் எனில் (strcmp(name,
		    "users-groups-by-id@openssh.com") == 0 &&
		    strcmp((எழுத்து *)மதிப்பு, "1") == 0) {
			ret->exts |= SFTP_EXT_GETUSERSGROUPS_BY_ID;
			known = 1;
		}
		எனில் (known) {
			debug2("Server supports extension \"%s\" revision %s",
			    name, மதிப்பு);
		} இல்லையெனில் {
			debug2("Unrecognised server extension \"%s\"", name);
		}
		விடுவி(name);
		விடுவி(மதிப்பு);
	}

	sshbuf_free(செய்தி);

	/* Query the server for its limits */
	எனில் (ret->exts & SFTP_EXT_LIMITS) {
		கட்டமைப்பு sftp_limits limits;
		எனில் (sftp_get_limits(ret, &limits) != 0)
			fatal_f("limits failed");

		/* If the caller did not specify, find a good value */
		எனில் (transfer_buflen == 0) {
			ret->download_buflen = MINIMUM(limits.read_length,
			    SFTP_MAX_செய்தி_LENGTH - 1024);
			ret->upload_buflen = MINIMUM(limits.write_length,
			    SFTP_MAX_செய்தி_LENGTH - 1024);
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
	எனில் (ret->version == 0) {
		ret->download_buflen = MINIMUM(ret->download_buflen, 20480);
		ret->upload_buflen = MINIMUM(ret->upload_buflen, 20480);
	}

	ret->limit_kbps = limit_kbps;
	எனில் (ret->limit_kbps > 0) {
		bandwidth_limit_init(&ret->bwlimit_in, ret->limit_kbps,
		    ret->download_buflen);
		bandwidth_limit_init(&ret->bwlimit_out, ret->limit_kbps,
		    ret->upload_buflen);
	}

	திரும்பு ret;
}

வெறுமை
sftp_free(கட்டமைப்பு sftp_conn *conn)
{
	எனில் (conn == வெற்று)
		திரும்பு;
	freezero(conn, அளவு(*conn));
}

u_int
sftp_proto_version(கட்டமைப்பு sftp_conn *conn)
{
	திரும்பு conn->version;
}

முழு
sftp_get_limits(கட்டமைப்பு sftp_conn *conn, கட்டமைப்பு sftp_limits *limits)
{
	u_int id, செய்தி_id;
	u_char type;
	கட்டமைப்பு sshbuf *செய்தி;
	முழு r;

	எனில் ((conn->exts & SFTP_EXT_LIMITS) == 0) {
		error("Server does not support limits@openssh.com extension");
		திரும்பு -1;
	}

	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");

	id = conn->செய்தி_id++;
	எனில் ((r = sshbuf_put_u8(செய்தி, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(செய்தி, id)) != 0 ||
	    (r = sshbuf_put_cstring(செய்தி, "limits@openssh.com")) != 0)
		fatal_fr(r, "compose");
	send_செய்தி(conn, செய்தி);
	debug3("Sent message limits@openssh.com I:%u", id);

	get_செய்தி(conn, செய்தி);

	எனில் ((r = sshbuf_get_u8(செய்தி, &type)) != 0 ||
	    (r = sshbuf_get_u32(செய்தி, &செய்தி_id)) != 0)
		fatal_fr(r, "parse");

	debug3("Received limits reply T:%u I:%u", type, செய்தி_id);
	எனில் (id != செய்தி_id)
		fatal("ID mismatch (%u != %u)", செய்தி_id, id);
	எனில் (type != SSH2_FXP_EXTENDED_REPLY) {
		debug_f("expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_REPLY, type);
		/* Disable the limits extension */
		conn->exts &= ~SFTP_EXT_LIMITS;
		sshbuf_free(செய்தி);
		திரும்பு -1;
	}

	memset(limits, 0, அளவு(*limits));
	எனில் ((r = sshbuf_get_u64(செய்தி, &limits->packet_length)) != 0 ||
	    (r = sshbuf_get_u64(செய்தி, &limits->read_length)) != 0 ||
	    (r = sshbuf_get_u64(செய்தி, &limits->write_length)) != 0 ||
	    (r = sshbuf_get_u64(செய்தி, &limits->open_handles)) != 0)
		fatal_fr(r, "parse limits");

	sshbuf_free(செய்தி);

	திரும்பு 0;
}

முழு
sftp_close(கட்டமைப்பு sftp_conn *conn, மாறிலி u_char *handle, u_int handle_len)
{
	u_int id, status;
	கட்டமைப்பு sshbuf *செய்தி;
	முழு r;

	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");

	id = conn->செய்தி_id++;
	எனில் ((r = sshbuf_put_u8(செய்தி, SSH2_FXP_CLOSE)) != 0 ||
	    (r = sshbuf_put_u32(செய்தி, id)) != 0 ||
	    (r = sshbuf_put_string(செய்தி, handle, handle_len)) != 0)
		fatal_fr(r, "parse");
	send_செய்தி(conn, செய்தி);
	debug3("Sent message SSH2_FXP_CLOSE I:%u", id);

	status = get_status(conn, id);
	எனில் (status != SSH2_FX_OK)
		error("close remote: %s", fx2txt(status));

	sshbuf_free(செய்தி);

	திரும்பு status == SSH2_FX_OK ? 0 : -1;
}


நிலையான முழு
sftp_lsreaddir(கட்டமைப்பு sftp_conn *conn, மாறிலி எழுத்து *path, முழு print_flag,
    SFTP_DIRENT ***dir)
{
	கட்டமைப்பு sshbuf *செய்தி;
	u_int மொத்தம், id, i, expected_id, ents = 0;
	size_t handle_len;
	u_char type, *handle;
	முழு status = SSH2_FX_FAILURE;
	முழு r;

	எனில் (dir)
		*dir = வெற்று;

	id = conn->செய்தி_id++;

	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = sshbuf_put_u8(செய்தி, SSH2_FXP_OPENDIR)) != 0 ||
	    (r = sshbuf_put_u32(செய்தி, id)) != 0 ||
	    (r = sshbuf_put_cstring(செய்தி, path)) != 0)
		fatal_fr(r, "compose OPENDIR");
	send_செய்தி(conn, செய்தி);

	handle = get_handle(conn, id, &handle_len,
	    "remote readdir(\"%s\")", path);
	எனில் (handle == வெற்று) {
		sshbuf_free(செய்தி);
		திரும்பு -1;
	}

	எனில் (dir) {
		ents = 0;
		*dir = xcalloc(1, அளவு(**dir));
		(*dir)[0] = வெற்று;
	}

	க்கு (; !interrupted;) {
		id = expected_id = conn->செய்தி_id++;

		debug3("Sending SSH2_FXP_READDIR I:%u", id);

		sshbuf_reset(செய்தி);
		எனில் ((r = sshbuf_put_u8(செய்தி, SSH2_FXP_READDIR)) != 0 ||
		    (r = sshbuf_put_u32(செய்தி, id)) != 0 ||
		    (r = sshbuf_put_string(செய்தி, handle, handle_len)) != 0)
			fatal_fr(r, "compose READDIR");
		send_செய்தி(conn, செய்தி);

		sshbuf_reset(செய்தி);

		get_செய்தி(conn, செய்தி);

		எனில் ((r = sshbuf_get_u8(செய்தி, &type)) != 0 ||
		    (r = sshbuf_get_u32(செய்தி, &id)) != 0)
			fatal_fr(r, "parse");

		debug3("Received reply T:%u I:%u", type, id);

		எனில் (id != expected_id)
			fatal("ID mismatch (%u != %u)", id, expected_id);

		எனில் (type == SSH2_FXP_STATUS) {
			u_int rstatus;

			எனில் ((r = sshbuf_get_u32(செய்தி, &rstatus)) != 0)
				fatal_fr(r, "parse status");
			debug3("Received SSH2_FXP_STATUS %d", rstatus);
			எனில் (rstatus == SSH2_FX_EOF)
				நிறுத்து;
			error("Couldn't read directory: %s", fx2txt(rstatus));
			செல் out;
		} இல்லையெனில் எனில் (type != SSH2_FXP_NAME)
			fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
			    SSH2_FXP_NAME, type);

		எனில் ((r = sshbuf_get_u32(செய்தி, &மொத்தம்)) != 0)
			fatal_fr(r, "parse count");
		எனில் (மொத்தம் > SSHBUF_SIZE_MAX)
			fatal_f("nonsensical number of entries");
		எனில் (மொத்தம் == 0)
			நிறுத்து;
		debug3("Received %d SSH2_FXP_NAME responses", மொத்தம்);
		க்கு (i = 0; i < மொத்தம்; i++) {
			எழுத்து *filename, *longname;
			Attrib a;

			எனில் ((r = sshbuf_get_cstring(செய்தி, &filename,
			    வெற்று)) != 0 ||
			    (r = sshbuf_get_cstring(செய்தி, &longname,
			    வெற்று)) != 0)
				fatal_fr(r, "parse filenames");
			எனில் ((r = decode_attrib(செய்தி, &a)) != 0) {
				error_fr(r, "couldn't decode attrib");
				விடுவி(filename);
				விடுவி(longname);
				செல் out;
			}

			எனில் (print_flag)
				mprintf("%s\n", longname);

			/*
			 * Directory entries should never contain '/'
			 * These can be used to attack recursive ops
			 * (e.g. send '../../../../etc/passwd')
			 */
			எனில் (*filename == '\0' ||
			    strpbrk(filename, SFTP_DIRECTORY_CHARS) != வெற்று) {
				error("Server sent suspect path \"%s\" "
				    "during readdir of \"%s\"", filename, path);
			} இல்லையெனில் எனில் (dir) {
				*dir = xreallocarray(*dir, ents + 2, அளவு(**dir));
				(*dir)[ents] = xcalloc(1, அளவு(***dir));
				(*dir)[ents]->filename = xstrdup(filename);
				(*dir)[ents]->longname = xstrdup(longname);
				memcpy(&(*dir)[ents]->a, &a, அளவு(a));
				(*dir)[++ents] = வெற்று;
			}
			விடுவி(filename);
			விடுவி(longname);
		}
	}
	status = 0;

 out:
	sshbuf_free(செய்தி);
	sftp_close(conn, handle, handle_len);
	விடுவி(handle);

	எனில் (status != 0 && dir != வெற்று) {
		/* Don't return results on error */
		sftp_free_dirents(*dir);
		*dir = வெற்று;
	} இல்லையெனில் எனில் (interrupted && dir != வெற்று && *dir != வெற்று) {
		/* Don't return partial matches on interrupt */
		sftp_free_dirents(*dir);
		*dir = xcalloc(1, அளவு(**dir));
		**dir = வெற்று;
	}

	திரும்பு status == SSH2_FX_OK ? 0 : -1;
}

முழு
sftp_readdir(கட்டமைப்பு sftp_conn *conn, மாறிலி எழுத்து *path, SFTP_DIRENT ***dir)
{
	திரும்பு sftp_lsreaddir(conn, path, 0, dir);
}

வெறுமை sftp_free_dirents(SFTP_DIRENT **s)
{
	முழு i;

	எனில் (s == வெற்று)
		திரும்பு;
	க்கு (i = 0; s[i]; i++) {
		விடுவி(s[i]->filename);
		விடுவி(s[i]->longname);
		விடுவி(s[i]);
	}
	விடுவி(s);
}

முழு
sftp_rm(கட்டமைப்பு sftp_conn *conn, மாறிலி எழுத்து *path)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_REMOVE \"%s\"", path);

	id = conn->செய்தி_id++;
	send_string_request(conn, id, SSH2_FXP_REMOVE, path, strlen(path));
	status = get_status(conn, id);
	எனில் (status != SSH2_FX_OK)
		error("remote delete %s: %s", path, fx2txt(status));
	திரும்பு status == SSH2_FX_OK ? 0 : -1;
}

முழு
sftp_mkdir(கட்டமைப்பு sftp_conn *conn, மாறிலி எழுத்து *path, Attrib *a, முழு print_flag)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_MKDIR \"%s\"", path);

	id = conn->செய்தி_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_MKDIR, path,
	    strlen(path), a);

	status = get_status(conn, id);
	எனில் (status != SSH2_FX_OK && print_flag)
		error("remote mkdir \"%s\": %s", path, fx2txt(status));

	திரும்பு status == SSH2_FX_OK ? 0 : -1;
}

முழு
sftp_mkpath(கட்டமைப்பு sftp_conn *conn, மாறிலி எழுத்து *path, Attrib *a, முழு print_flag)
{
	எழுத்து *slash, *tmp_path;
	முழு done;

	tmp_path = xstrdup(path);
	slash = tmp_path;

	க்கு (;;) {
		slash += strspn(slash, "/");
		slash += strcspn(slash, "/");

		done = (*slash == '\0');
		*slash = '\0';

		எனில் (!sftp_remote_is_dir(conn, tmp_path)) {
			எனில் (sftp_mkdir(conn, tmp_path, a, print_flag) != 0) {
				விடுவி(tmp_path);
				திரும்பு -1;
			}
		}

		எனில் (done)
			நிறுத்து;

		*slash = '/';
	}

	விடுவி(tmp_path);
	திரும்பு 0;
}

முழு
sftp_rmdir(கட்டமைப்பு sftp_conn *conn, மாறிலி எழுத்து *path)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_RMDIR \"%s\"", path);

	id = conn->செய்தி_id++;
	send_string_request(conn, id, SSH2_FXP_RMDIR, path,
	    strlen(path));

	status = get_status(conn, id);
	எனில் (status != SSH2_FX_OK)
		error("remote rmdir \"%s\": %s", path, fx2txt(status));

	திரும்பு status == SSH2_FX_OK ? 0 : -1;
}

முழு
sftp_stat(கட்டமைப்பு sftp_conn *conn, மாறிலி எழுத்து *path, முழு quiet, Attrib *a)
{
	u_int id;

	debug2("Sending SSH2_FXP_STAT \"%s\"", path);

	id = conn->செய்தி_id++;

	send_string_request(conn, id,
	    conn->version == 0 ? SSH2_FXP_STAT_VERSION_0 : SSH2_FXP_STAT,
	    path, strlen(path));

	திரும்பு get_decode_stat(conn, id, quiet, a);
}

முழு
sftp_lstat(கட்டமைப்பு sftp_conn *conn, மாறிலி எழுத்து *path, முழு quiet, Attrib *a)
{
	u_int id;

	எனில் (conn->version == 0) {
		do_log2(quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_INFO,
		    "Server version does not support lstat operation");
		திரும்பு sftp_stat(conn, path, quiet, a);
	}

	id = conn->செய்தி_id++;
	send_string_request(conn, id, SSH2_FXP_LSTAT, path,
	    strlen(path));

	திரும்பு get_decode_stat(conn, id, quiet, a);
}

#ifdef notyet
முழு
sftp_fstat(கட்டமைப்பு sftp_conn *conn, மாறிலி u_char *handle, u_int handle_len,
    முழு quiet, Attrib *a)
{
	u_int id;

	debug2("Sending SSH2_FXP_FSTAT \"%s\"");

	id = conn->செய்தி_id++;
	send_string_request(conn, id, SSH2_FXP_FSTAT, handle,
	    handle_len);

	திரும்பு get_decode_stat(conn, id, quiet, a);
}
#endif

முழு
sftp_setstat(கட்டமைப்பு sftp_conn *conn, மாறிலி எழுத்து *path, Attrib *a)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_SETSTAT \"%s\"", path);

	id = conn->செய்தி_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_SETSTAT, path,
	    strlen(path), a);

	status = get_status(conn, id);
	எனில் (status != SSH2_FX_OK)
		error("remote setstat \"%s\": %s", path, fx2txt(status));

	திரும்பு status == SSH2_FX_OK ? 0 : -1;
}

முழு
sftp_fsetstat(கட்டமைப்பு sftp_conn *conn, மாறிலி u_char *handle, u_int handle_len,
    Attrib *a)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_FSETSTAT");

	id = conn->செய்தி_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_FSETSTAT, handle,
	    handle_len, a);

	status = get_status(conn, id);
	எனில் (status != SSH2_FX_OK)
		error("remote fsetstat: %s", fx2txt(status));

	திரும்பு status == SSH2_FX_OK ? 0 : -1;
}

/* Implements both the realpath and expand-path operations */
நிலையான எழுத்து *
sftp_realpath_expand(கட்டமைப்பு sftp_conn *conn, மாறிலி எழுத்து *path, முழு expand)
{
	கட்டமைப்பு sshbuf *செய்தி;
	u_int expected_id, மொத்தம், id;
	எழுத்து *filename, *longname;
	Attrib a;
	u_char type;
	முழு r;
	மாறிலி எழுத்து *what = "SSH2_FXP_REALPATH";

	எனில் (expand)
		what = "expand-path@openssh.com";
	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");

	expected_id = id = conn->செய்தி_id++;
	எனில் (expand) {
		debug2("Sending SSH2_FXP_EXTENDED(expand-path@openssh.com) "
		    "\"%s\"", path);
		எனில் ((r = sshbuf_put_u8(செய்தி, SSH2_FXP_EXTENDED)) != 0 ||
		    (r = sshbuf_put_u32(செய்தி, id)) != 0 ||
		    (r = sshbuf_put_cstring(செய்தி,
		    "expand-path@openssh.com")) != 0 ||
		    (r = sshbuf_put_cstring(செய்தி, path)) != 0)
			fatal_fr(r, "compose %s", what);
		send_செய்தி(conn, செய்தி);
	} இல்லையெனில் {
		debug2("Sending SSH2_FXP_REALPATH \"%s\"", path);
		send_string_request(conn, id, SSH2_FXP_REALPATH,
		    path, strlen(path));
	}
	get_செய்தி(conn, செய்தி);
	எனில் ((r = sshbuf_get_u8(செய்தி, &type)) != 0 ||
	    (r = sshbuf_get_u32(செய்தி, &id)) != 0)
		fatal_fr(r, "parse");

	எனில் (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);

	எனில் (type == SSH2_FXP_STATUS) {
		u_int status;
		எழுத்து *errmsg;

		எனில் ((r = sshbuf_get_u32(செய்தி, &status)) != 0 ||
		    (r = sshbuf_get_cstring(செய்தி, &errmsg, வெற்று)) != 0)
			fatal_fr(r, "parse status");
		error("%s %s: %s", expand ? "expand" : "realpath",
		    path, *errmsg == '\0' ? fx2txt(status) : errmsg);
		விடுவி(errmsg);
		sshbuf_free(செய்தி);
		திரும்பு வெற்று;
	} இல்லையெனில் எனில் (type != SSH2_FXP_NAME)
		fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
		    SSH2_FXP_NAME, type);

	எனில் ((r = sshbuf_get_u32(செய்தி, &மொத்தம்)) != 0)
		fatal_fr(r, "parse count");
	எனில் (மொத்தம் != 1)
		fatal("Got multiple names (%d) from %s", மொத்தம், what);

	எனில் ((r = sshbuf_get_cstring(செய்தி, &filename, வெற்று)) != 0 ||
	    (r = sshbuf_get_cstring(செய்தி, &longname, வெற்று)) != 0 ||
	    (r = decode_attrib(செய்தி, &a)) != 0)
		fatal_fr(r, "parse filename/attrib");

	debug3("%s %s -> %s", what, path, filename);

	விடுவி(longname);

	sshbuf_free(செய்தி);

	திரும்பு(filename);
}

எழுத்து *
sftp_realpath(கட்டமைப்பு sftp_conn *conn, மாறிலி எழுத்து *path)
{
	திரும்பு sftp_realpath_expand(conn, path, 0);
}

முழு
sftp_can_expand_path(கட்டமைப்பு sftp_conn *conn)
{
	திரும்பு (conn->exts & SFTP_EXT_PATH_EXPAND) != 0;
}

எழுத்து *
sftp_expand_path(கட்டமைப்பு sftp_conn *conn, மாறிலி எழுத்து *path)
{
	எனில் (!sftp_can_expand_path(conn)) {
		debug3_f("no server support, fallback to realpath");
		திரும்பு sftp_realpath_expand(conn, path, 0);
	}
	திரும்பு sftp_realpath_expand(conn, path, 1);
}

முழு
sftp_copy(கட்டமைப்பு sftp_conn *conn, மாறிலி எழுத்து *oldpath, மாறிலி எழுத்து *newpath)
{
	Attrib junk, attr;
	கட்டமைப்பு sshbuf *செய்தி;
	u_char *old_handle, *new_handle;
	u_int mode, status, id;
	size_t old_handle_len, new_handle_len;
	முழு r;

	/* Return if the extension is not supported */
	எனில் ((conn->exts & SFTP_EXT_COPY_DATA) == 0) {
		error("Server does not support copy-data extension");
		திரும்பு -1;
	}

	/* Make sure the file exists, and we can copy its perms */
	எனில் (sftp_stat(conn, oldpath, 0, &attr) != 0)
		திரும்பு -1;

	/* Do not preserve set[ug]id here, as we do not preserve ownership */
	எனில் (attr.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		mode = attr.perm & 0777;

		எனில் (!S_ISREG(attr.perm)) {
			error("Cannot copy non-regular file: %s", oldpath);
			திரும்பு -1;
		}
	} இல்லையெனில் {
		/* NB: The user's umask will apply to this */
		mode = 0666;
	}

	/* Set up the new perms for the new file */
	attrib_clear(&attr);
	attr.perm = mode;
	attr.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;

	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");

	attrib_clear(&junk); /* Send empty attributes */

	/* Open the old file for reading */
	id = conn->செய்தி_id++;
	எனில் ((r = sshbuf_put_u8(செய்தி, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(செய்தி, id)) != 0 ||
	    (r = sshbuf_put_cstring(செய்தி, oldpath)) != 0 ||
	    (r = sshbuf_put_u32(செய்தி, SSH2_FXF_READ)) != 0 ||
	    (r = encode_attrib(செய்தி, &junk)) != 0)
		fatal_fr(r, "buffer error");
	send_செய்தி(conn, செய்தி);
	debug3("Sent message SSH2_FXP_OPEN I:%u P:%s", id, oldpath);

	sshbuf_reset(செய்தி);

	old_handle = get_handle(conn, id, &old_handle_len,
	    "remote open(\"%s\")", oldpath);
	எனில் (old_handle == வெற்று) {
		sshbuf_free(செய்தி);
		திரும்பு -1;
	}

	/* Open the new file for writing */
	id = conn->செய்தி_id++;
	எனில் ((r = sshbuf_put_u8(செய்தி, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(செய்தி, id)) != 0 ||
	    (r = sshbuf_put_cstring(செய்தி, newpath)) != 0 ||
	    (r = sshbuf_put_u32(செய்தி, SSH2_FXF_WRITE|SSH2_FXF_CREAT|
	    SSH2_FXF_TRUNC)) != 0 ||
	    (r = encode_attrib(செய்தி, &attr)) != 0)
		fatal_fr(r, "buffer error");
	send_செய்தி(conn, செய்தி);
	debug3("Sent message SSH2_FXP_OPEN I:%u P:%s", id, newpath);

	sshbuf_reset(செய்தி);

	new_handle = get_handle(conn, id, &new_handle_len,
	    "remote open(\"%s\")", newpath);
	எனில் (new_handle == வெற்று) {
		sshbuf_free(செய்தி);
		விடுவி(old_handle);
		திரும்பு -1;
	}

	/* Copy the file data */
	id = conn->செய்தி_id++;
	எனில் ((r = sshbuf_put_u8(செய்தி, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(செய்தி, id)) != 0 ||
	    (r = sshbuf_put_cstring(செய்தி, "copy-data")) != 0 ||
	    (r = sshbuf_put_string(செய்தி, old_handle, old_handle_len)) != 0 ||
	    (r = sshbuf_put_u64(செய்தி, 0)) != 0 ||
	    (r = sshbuf_put_u64(செய்தி, 0)) != 0 ||
	    (r = sshbuf_put_string(செய்தி, new_handle, new_handle_len)) != 0 ||
	    (r = sshbuf_put_u64(செய்தி, 0)) != 0)
		fatal_fr(r, "buffer error");
	send_செய்தி(conn, செய்தி);
	debug3("Sent message copy-data \"%s\" 0 0 -> \"%s\" 0",
	       oldpath, newpath);

	status = get_status(conn, id);
	எனில் (status != SSH2_FX_OK)
		error("Couldn't copy file \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	/* Clean up everything */
	sshbuf_free(செய்தி);
	sftp_close(conn, old_handle, old_handle_len);
	sftp_close(conn, new_handle, new_handle_len);
	விடுவி(old_handle);
	விடுவி(new_handle);

	திரும்பு status == SSH2_FX_OK ? 0 : -1;
}

முழு
sftp_rename(கட்டமைப்பு sftp_conn *conn, மாறிலி எழுத்து *oldpath, மாறிலி எழுத்து *newpath,
    முழு force_legacy)
{
	கட்டமைப்பு sshbuf *செய்தி;
	u_int status, id;
	முழு r, use_ext = (conn->exts & SFTP_EXT_POSIX_RENAME) && !force_legacy;

	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");

	/* Send rename request */
	id = conn->செய்தி_id++;
	எனில் (use_ext) {
		debug2("Sending SSH2_FXP_EXTENDED(posix-rename@openssh.com) "
		    "\"%s\" to \"%s\"", oldpath, newpath);
		எனில் ((r = sshbuf_put_u8(செய்தி, SSH2_FXP_EXTENDED)) != 0 ||
		    (r = sshbuf_put_u32(செய்தி, id)) != 0 ||
		    (r = sshbuf_put_cstring(செய்தி,
		    "posix-rename@openssh.com")) != 0)
			fatal_fr(r, "compose posix-rename");
	} இல்லையெனில் {
		debug2("Sending SSH2_FXP_RENAME \"%s\" to \"%s\"",
		    oldpath, newpath);
		எனில் ((r = sshbuf_put_u8(செய்தி, SSH2_FXP_RENAME)) != 0 ||
		    (r = sshbuf_put_u32(செய்தி, id)) != 0)
			fatal_fr(r, "compose rename");
	}
	எனில் ((r = sshbuf_put_cstring(செய்தி, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(செய்தி, newpath)) != 0)
		fatal_fr(r, "compose paths");
	send_செய்தி(conn, செய்தி);
	debug3("Sent message %s \"%s\" -> \"%s\"",
	    use_ext ? "posix-rename@openssh.com" :
	    "SSH2_FXP_RENAME", oldpath, newpath);
	sshbuf_free(செய்தி);

	status = get_status(conn, id);
	எனில் (status != SSH2_FX_OK)
		error("remote rename \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	திரும்பு status == SSH2_FX_OK ? 0 : -1;
}

முழு
sftp_hardlink(கட்டமைப்பு sftp_conn *conn, மாறிலி எழுத்து *oldpath, மாறிலி எழுத்து *newpath)
{
	கட்டமைப்பு sshbuf *செய்தி;
	u_int status, id;
	முழு r;

	எனில் ((conn->exts & SFTP_EXT_HARDLINK) == 0) {
		error("Server does not support hardlink@openssh.com extension");
		திரும்பு -1;
	}
	debug2("Sending SSH2_FXP_EXTENDED(hardlink@openssh.com) "
	    "\"%s\" to \"%s\"", oldpath, newpath);

	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");

	/* Send link request */
	id = conn->செய்தி_id++;
	எனில் ((r = sshbuf_put_u8(செய்தி, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(செய்தி, id)) != 0 ||
	    (r = sshbuf_put_cstring(செய்தி, "hardlink@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(செய்தி, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(செய்தி, newpath)) != 0)
		fatal_fr(r, "compose");
	send_செய்தி(conn, செய்தி);
	debug3("Sent message hardlink@openssh.com \"%s\" -> \"%s\"",
	    oldpath, newpath);
	sshbuf_free(செய்தி);

	status = get_status(conn, id);
	எனில் (status != SSH2_FX_OK)
		error("remote link \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	திரும்பு status == SSH2_FX_OK ? 0 : -1;
}

முழு
sftp_symlink(கட்டமைப்பு sftp_conn *conn, மாறிலி எழுத்து *oldpath, மாறிலி எழுத்து *newpath)
{
	கட்டமைப்பு sshbuf *செய்தி;
	u_int status, id;
	முழு r;

	எனில் (conn->version < 3) {
		error("This server does not support the symlink operation");
		திரும்பு(SSH2_FX_OP_UNSUPPORTED);
	}
	debug2("Sending SSH2_FXP_SYMLINK \"%s\" to \"%s\"", oldpath, newpath);

	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");

	/* Send symlink request */
	id = conn->செய்தி_id++;
	எனில் ((r = sshbuf_put_u8(செய்தி, SSH2_FXP_SYMLINK)) != 0 ||
	    (r = sshbuf_put_u32(செய்தி, id)) != 0 ||
	    (r = sshbuf_put_cstring(செய்தி, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(செய்தி, newpath)) != 0)
		fatal_fr(r, "compose");
	send_செய்தி(conn, செய்தி);
	debug3("Sent message SSH2_FXP_SYMLINK \"%s\" -> \"%s\"", oldpath,
	    newpath);
	sshbuf_free(செய்தி);

	status = get_status(conn, id);
	எனில் (status != SSH2_FX_OK)
		error("remote symlink file \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	திரும்பு status == SSH2_FX_OK ? 0 : -1;
}

முழு
sftp_fsync(கட்டமைப்பு sftp_conn *conn, u_char *handle, u_int handle_len)
{
	கட்டமைப்பு sshbuf *செய்தி;
	u_int status, id;
	முழு r;

	/* Silently return if the extension is not supported */
	எனில் ((conn->exts & SFTP_EXT_FSYNC) == 0)
		திரும்பு -1;
	debug2("Sending SSH2_FXP_EXTENDED(fsync@openssh.com)");

	/* Send fsync request */
	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	id = conn->செய்தி_id++;
	எனில் ((r = sshbuf_put_u8(செய்தி, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(செய்தி, id)) != 0 ||
	    (r = sshbuf_put_cstring(செய்தி, "fsync@openssh.com")) != 0 ||
	    (r = sshbuf_put_string(செய்தி, handle, handle_len)) != 0)
		fatal_fr(r, "compose");
	send_செய்தி(conn, செய்தி);
	debug3("Sent message fsync@openssh.com I:%u", id);
	sshbuf_free(செய்தி);

	status = get_status(conn, id);
	எனில் (status != SSH2_FX_OK)
		error("remote fsync: %s", fx2txt(status));

	திரும்பு status == SSH2_FX_OK ? 0 : -1;
}

#ifdef notyet
எழுத்து *
sftp_readlink(கட்டமைப்பு sftp_conn *conn, மாறிலி எழுத்து *path)
{
	கட்டமைப்பு sshbuf *செய்தி;
	u_int expected_id, மொத்தம், id;
	எழுத்து *filename, *longname;
	Attrib a;
	u_char type;
	முழு r;

	debug2("Sending SSH2_FXP_READLINK \"%s\"", path);

	expected_id = id = conn->செய்தி_id++;
	send_string_request(conn, id, SSH2_FXP_READLINK, path, strlen(path));

	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");

	get_செய்தி(conn, செய்தி);
	எனில் ((r = sshbuf_get_u8(செய்தி, &type)) != 0 ||
	    (r = sshbuf_get_u32(செய்தி, &id)) != 0)
		fatal_fr(r, "parse");

	எனில் (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);

	எனில் (type == SSH2_FXP_STATUS) {
		u_int status;

		எனில் ((r = sshbuf_get_u32(செய்தி, &status)) != 0)
			fatal_fr(r, "parse status");
		error("Couldn't readlink: %s", fx2txt(status));
		sshbuf_free(செய்தி);
		திரும்பு(வெற்று);
	} இல்லையெனில் எனில் (type != SSH2_FXP_NAME)
		fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
		    SSH2_FXP_NAME, type);

	எனில் ((r = sshbuf_get_u32(செய்தி, &மொத்தம்)) != 0)
		fatal_fr(r, "parse count");
	எனில் (மொத்தம் != 1)
		fatal("Got multiple names (%d) from SSH_FXP_READLINK", மொத்தம்);

	எனில் ((r = sshbuf_get_cstring(செய்தி, &filename, வெற்று)) != 0 ||
	    (r = sshbuf_get_cstring(செய்தி, &longname, வெற்று)) != 0 ||
	    (r = decode_attrib(செய்தி, &a)) != 0)
		fatal_fr(r, "parse filenames/attrib");

	debug3("SSH_FXP_READLINK %s -> %s", path, filename);

	விடுவி(longname);

	sshbuf_free(செய்தி);

	திரும்பு filename;
}
#endif

முழு
sftp_statvfs(கட்டமைப்பு sftp_conn *conn, மாறிலி எழுத்து *path, கட்டமைப்பு sftp_statvfs *st,
    முழு quiet)
{
	கட்டமைப்பு sshbuf *செய்தி;
	u_int id;
	முழு r;

	எனில் ((conn->exts & SFTP_EXT_STATVFS) == 0) {
		error("Server does not support statvfs@openssh.com extension");
		திரும்பு -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(statvfs@openssh.com) \"%s\"", path);

	id = conn->செய்தி_id++;

	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = sshbuf_put_u8(செய்தி, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(செய்தி, id)) != 0 ||
	    (r = sshbuf_put_cstring(செய்தி, "statvfs@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(செய்தி, path)) != 0)
		fatal_fr(r, "compose");
	send_செய்தி(conn, செய்தி);
	sshbuf_free(செய்தி);

	திரும்பு get_decode_statvfs(conn, st, id, quiet);
}

#ifdef notyet
முழு
sftp_fstatvfs(கட்டமைப்பு sftp_conn *conn, மாறிலி u_char *handle, u_int handle_len,
    கட்டமைப்பு sftp_statvfs *st, முழு quiet)
{
	கட்டமைப்பு sshbuf *செய்தி;
	u_int id;

	எனில் ((conn->exts & SFTP_EXT_FSTATVFS) == 0) {
		error("Server does not support fstatvfs@openssh.com extension");
		திரும்பு -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(fstatvfs@openssh.com)");

	id = conn->செய்தி_id++;

	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = sshbuf_put_u8(செய்தி, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(செய்தி, id)) != 0 ||
	    (r = sshbuf_put_cstring(செய்தி, "fstatvfs@openssh.com")) != 0 ||
	    (r = sshbuf_put_string(செய்தி, handle, handle_len)) != 0)
		fatal_fr(r, "compose");
	send_செய்தி(conn, செய்தி);
	sshbuf_free(செய்தி);

	திரும்பு get_decode_statvfs(conn, st, id, quiet);
}
#endif

முழு
sftp_lsetstat(கட்டமைப்பு sftp_conn *conn, மாறிலி எழுத்து *path, Attrib *a)
{
	கட்டமைப்பு sshbuf *செய்தி;
	u_int status, id;
	முழு r;

	எனில் ((conn->exts & SFTP_EXT_LSETSTAT) == 0) {
		error("Server does not support lsetstat@openssh.com extension");
		திரும்பு -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(lsetstat@openssh.com) \"%s\"", path);

	id = conn->செய்தி_id++;
	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = sshbuf_put_u8(செய்தி, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(செய்தி, id)) != 0 ||
	    (r = sshbuf_put_cstring(செய்தி, "lsetstat@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(செய்தி, path)) != 0 ||
	    (r = encode_attrib(செய்தி, a)) != 0)
		fatal_fr(r, "compose");
	send_செய்தி(conn, செய்தி);
	sshbuf_free(செய்தி);

	status = get_status(conn, id);
	எனில் (status != SSH2_FX_OK)
		error("remote lsetstat \"%s\": %s", path, fx2txt(status));

	திரும்பு status == SSH2_FX_OK ? 0 : -1;
}

நிலையான வெறுமை
send_read_request(கட்டமைப்பு sftp_conn *conn, u_int id, uint64_t offset,
    u_int len, மாறிலி u_char *handle, u_int handle_len)
{
	கட்டமைப்பு sshbuf *செய்தி;
	முழு r;

	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = sshbuf_put_u8(செய்தி, SSH2_FXP_READ)) != 0 ||
	    (r = sshbuf_put_u32(செய்தி, id)) != 0 ||
	    (r = sshbuf_put_string(செய்தி, handle, handle_len)) != 0 ||
	    (r = sshbuf_put_u64(செய்தி, offset)) != 0 ||
	    (r = sshbuf_put_u32(செய்தி, len)) != 0)
		fatal_fr(r, "compose");
	send_செய்தி(conn, செய்தி);
	sshbuf_free(செய்தி);
}

நிலையான முழு
send_open(கட்டமைப்பு sftp_conn *conn, மாறிலி எழுத்து *path, மாறிலி எழுத்து *tag,
    u_int openmode, Attrib *a, u_char **handlep, size_t *handle_lenp)
{
	Attrib junk;
	u_char *handle;
	size_t handle_len;
	கட்டமைப்பு sshbuf *செய்தி;
	முழு r;
	u_int id;

	debug2("Sending SSH2_FXP_OPEN \"%s\"", path);

	*handlep = வெற்று;
	*handle_lenp = 0;

	எனில் (a == வெற்று) {
		attrib_clear(&junk); /* Send empty attributes */
		a = &junk;
	}
	/* Send open request */
	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	id = conn->செய்தி_id++;
	எனில் ((r = sshbuf_put_u8(செய்தி, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(செய்தி, id)) != 0 ||
	    (r = sshbuf_put_cstring(செய்தி, path)) != 0 ||
	    (r = sshbuf_put_u32(செய்தி, openmode)) != 0 ||
	    (r = encode_attrib(செய்தி, a)) != 0)
		fatal_fr(r, "compose %s open", tag);
	send_செய்தி(conn, செய்தி);
	sshbuf_free(செய்தி);
	debug3("Sent %s message SSH2_FXP_OPEN I:%u P:%s M:0x%04x",
	    tag, id, path, openmode);
	எனில் ((handle = get_handle(conn, id, &handle_len,
	    "%s open \"%s\"", tag, path)) == வெற்று)
		திரும்பு -1;
	/* success */
	*handlep = handle;
	*handle_lenp = handle_len;
	திரும்பு 0;
}

நிலையான மாறிலி எழுத்து *
progress_meter_path(மாறிலி எழுத்து *path)
{
	மாறிலி எழுத்து *progresspath;

	எனில் ((progresspath = strrchr(path, '/')) == வெற்று)
		திரும்பு path;
	progresspath++;
	எனில் (*progresspath == '\0')
		திரும்பு path;
	திரும்பு progresspath;
}

முழு
sftp_download(கட்டமைப்பு sftp_conn *conn, மாறிலி எழுத்து *remote_path,
    மாறிலி எழுத்து *local_path, Attrib *a, முழு preserve_flag, முழு resume_flag,
    முழு fsync_flag, முழு inplace_flag)
{
	கட்டமைப்பு sshbuf *செய்தி;
	u_char *handle;
	முழு local_fd = -1, write_error, seen_zerolen = 0;
	முழு read_error, write_errno, lmodified = 0, reordered = 0, r;
	uint64_t offset = 0, size, highwater = 0, maxack = 0;
	u_int mode, id, buflen, இலக்கம்_req, max_req, status = SSH2_FX_OK;
	off_t progress_counter;
	size_t handle_len;
	கட்டமைப்பு stat st;
	கட்டமைப்பு requests requests;
	கட்டமைப்பு request *req;
	u_char type;
	Attrib attr;

	debug2_f("download remote \"%s\" to local \"%s\"",
	    remote_path, local_path);

	TAILQ_INIT(&requests);

	எனில் (a == வெற்று) {
		எனில் (sftp_stat(conn, remote_path, 0, &attr) != 0)
			திரும்பு -1;
		a = &attr;
	}

	/* Do not preserve set[ug]id here, as we do not preserve ownership */
	எனில் (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS)
		mode = a->perm & 0777;
	இல்லையெனில்
		mode = 0666;

	எனில் ((a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) &&
	    (!S_ISREG(a->perm))) {
		error("download %s: not a regular file", remote_path);
		திரும்பு(-1);
	}

	எனில் (a->flags & SSH2_FILEXFER_ATTR_SIZE)
		size = a->size;
	இல்லையெனில்
		size = 0;

	buflen = conn->download_buflen;

	/* Send open request */
	எனில் (send_open(conn, remote_path, "remote", SSH2_FXF_READ, வெற்று,
	    &handle, &handle_len) != 0)
		திரும்பு -1;

	local_fd = open(local_path, O_WRONLY | O_CREAT |
	((resume_flag || inplace_flag) ? 0 : O_TRUNC), mode | S_IWUSR);
	எனில் (local_fd == -1) {
		error("open local \"%s\": %s", local_path, strerror(errno));
		செல் fail;
	}
	எனில் (resume_flag) {
		எனில் (fstat(local_fd, &st) == -1) {
			error("stat local \"%s\": %s",
			    local_path, strerror(errno));
			செல் fail;
		}
		எனில் (st.st_size < 0) {
			error("\"%s\" has negative size", local_path);
			செல் fail;
		}
		எனில் ((uint64_t)st.st_size > size) {
			error("Unable to resume download of \"%s\": "
			    "local file is larger than remote", local_path);
 fail:
			sftp_close(conn, handle, handle_len);
			விடுவி(handle);
			எனில் (local_fd != -1)
				close(local_fd);
			திரும்பு -1;
		}
		offset = highwater = maxack = st.st_size;
	}

	/* Read from remote and write to local */
	write_error = read_error = write_errno = இலக்கம்_req = 0;
	max_req = 1;
	progress_counter = offset;

	எனில் (showprogress && size != 0) {
		start_progress_meter(progress_meter_path(remote_path),
		    size, &progress_counter);
	}

	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");

	போது (இலக்கம்_req > 0 || max_req > 0) {
		u_char *data;
		size_t len;

		/*
		 * Simulate EOF on interrupt: stop sending new requests and
		 * allow outstanding requests to drain gracefully
		 */
		எனில் (interrupted) {
			எனில் (இலக்கம்_req == 0) /* If we haven't started yet... */
				நிறுத்து;
			max_req = 0;
		}

		/* Send some more requests */
		போது (இலக்கம்_req < max_req) {
			debug3("Request range %llu -> %llu (%d/%d)",
			    (unsigned long long)offset,
			    (unsigned long long)offset + buflen - 1,
			    இலக்கம்_req, max_req);
			req = request_enqueue(&requests, conn->செய்தி_id++,
			    buflen, offset);
			offset += buflen;
			இலக்கம்_req++;
			send_read_request(conn, req->id, req->offset,
			    req->len, handle, handle_len);
		}

		sshbuf_reset(செய்தி);
		get_செய்தி(conn, செய்தி);
		எனில் ((r = sshbuf_get_u8(செய்தி, &type)) != 0 ||
		    (r = sshbuf_get_u32(செய்தி, &id)) != 0)
			fatal_fr(r, "parse");
		debug3("Received reply T:%u I:%u R:%d", type, id, max_req);

		/* Find the request in our queue */
		எனில் ((req = request_find(&requests, id)) == வெற்று)
			fatal("Unexpected reply %u", id);

		தேர்வு (type) {
		நிலை SSH2_FXP_STATUS:
			எனில் ((r = sshbuf_get_u32(செய்தி, &status)) != 0)
				fatal_fr(r, "parse status");
			எனில் (status != SSH2_FX_EOF)
				read_error = 1;
			max_req = 0;
			TAILQ_REMOVE(&requests, req, tq);
			விடுவி(req);
			இலக்கம்_req--;
			நிறுத்து;
		நிலை SSH2_FXP_DATA:
			எனில் ((r = sshbuf_get_string(செய்தி, &data, &len)) != 0)
				fatal_fr(r, "parse data");
			debug3("Received data %llu -> %llu",
			    (unsigned long long)req->offset,
			    (unsigned long long)req->offset + len - 1);
			எனில் (len > req->len)
				fatal("Received more data than asked for "
				    "%zu > %zu", len, req->len);
			எனில் (len == 0) {
				எனில் (seen_zerolen)
					fatal_f("server sent zero data length");
				seen_zerolen = 1;
			}
			lmodified = 1;
			எனில் ((lseek(local_fd, req->offset, SEEK_SET) == -1 ||
			    atomicio(vwrite, local_fd, data, len) != len) &&
			    !write_error) {
				write_errno = errno;
				write_error = 1;
				max_req = 0;
			} இல்லையெனில் {
				/*
				 * Track both the highest offset acknowledged
				 * and the highest *contiguous* offset
				 * acknowledged.
				 * We'll need the latter for ftruncate()ing
				 * interrupted transfers.
				 */
				எனில் (maxack < req->offset + len)
					maxack = req->offset + len;
				எனில் (!reordered && req->offset <= highwater)
					highwater = maxack;
				இல்லையெனில் எனில் (!reordered && req->offset > highwater)
					reordered = 1;
			}
			progress_counter += len;
			விடுவி(data);

			எனில் (len == req->len) {
				TAILQ_REMOVE(&requests, req, tq);
				விடுவி(req);
				இலக்கம்_req--;
			} இல்லையெனில் {
				/* Resend the request for the missing data */
				debug3("Short data block, re-requesting "
				    "%llu -> %llu (%2d)",
				    (unsigned long long)req->offset + len,
				    (unsigned long long)req->offset +
				    req->len - 1, இலக்கம்_req);
				req->id = conn->செய்தி_id++;
				req->len -= len;
				req->offset += len;
				send_read_request(conn, req->id,
				    req->offset, req->len, handle, handle_len);
				/* Reduce the request size */
				எனில் (len < buflen)
					buflen = MAXIMUM(MIN_READ_SIZE, len);
			}
			எனில் (max_req > 0) { /* max_req = 0 iff EOF received */
				எனில் (size > 0 && offset > size) {
					/* Only one request at a time
					 * after the expected EOF */
					debug3("Finish at %llu (%2d)",
					    (unsigned long long)offset,
					    இலக்கம்_req);
					max_req = 1;
				} இல்லையெனில் எனில் (max_req < conn->இலக்கம்_requests) {
					++max_req;
				}
			}
			நிறுத்து;
		இயல்பு:
			fatal("Expected SSH2_FXP_DATA(%u) packet, got %u",
			    SSH2_FXP_DATA, type);
		}
	}

	எனில் (showprogress && size)
		stop_progress_meter();

	/* Sanity check */
	எனில் (TAILQ_FIRST(&requests) != வெற்று)
		fatal("Transfer complete, but requests still in queue");

	எனில் (!read_error && !write_error && !interrupted) {
		/* we got everything */
		highwater = maxack;
	}

	/*
	 * Truncate at highest contiguous point to avoid holes on interrupt,
	 * or unconditionally if writing in place.
	 */
	எனில் (inplace_flag || read_error || write_error || interrupted) {
		எனில் (reordered && resume_flag &&
		    (read_error || write_error || interrupted)) {
			error("Unable to resume download of \"%s\": "
			    "server reordered requests", local_path);
		}
		debug("truncating at %llu", (unsigned long long)highwater);
		எனில் (ftruncate(local_fd, highwater) == -1)
			error("local ftruncate \"%s\": %s", local_path,
			    strerror(errno));
	}
	எனில் (read_error) {
		error("read remote \"%s\" : %s", remote_path, fx2txt(status));
		status = -1;
		sftp_close(conn, handle, handle_len);
	} இல்லையெனில் எனில் (write_error) {
		error("write local \"%s\": %s", local_path,
		    strerror(write_errno));
		status = SSH2_FX_FAILURE;
		sftp_close(conn, handle, handle_len);
	} இல்லையெனில் {
		எனில் (sftp_close(conn, handle, handle_len) != 0 || interrupted)
			status = SSH2_FX_FAILURE;
		இல்லையெனில்
			status = SSH2_FX_OK;
		/* Override umask and utimes if asked */
#ifdef HAVE_FCHMOD
		எனில் (preserve_flag && fchmod(local_fd, mode) == -1)
#இல்லையெனில்
		எனில் (preserve_flag && chmod(local_path, mode) == -1)
#endif /* HAVE_FCHMOD */
			error("local chmod \"%s\": %s", local_path,
			    strerror(errno));
		எனில் (preserve_flag &&
		    (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME)) {
			கட்டமைப்பு timeval tv[2];
			tv[0].tv_sec = a->atime;
			tv[1].tv_sec = a->mtime;
			tv[0].tv_usec = tv[1].tv_usec = 0;
			எனில் (utimes(local_path, tv) == -1)
				error("local set times \"%s\": %s",
				    local_path, strerror(errno));
		}
		எனில் (resume_flag && !lmodified)
			logit("File \"%s\" was not modified", local_path);
		இல்லையெனில் எனில் (fsync_flag) {
			debug("syncing \"%s\"", local_path);
			எனில் (fsync(local_fd) == -1)
				error("local sync \"%s\": %s",
				    local_path, strerror(errno));
		}
	}
	close(local_fd);
	sshbuf_free(செய்தி);
	விடுவி(handle);

	திரும்பு status == SSH2_FX_OK ? 0 : -1;
}

நிலையான முழு
download_dir_internal(கட்டமைப்பு sftp_conn *conn, மாறிலி எழுத்து *src, மாறிலி எழுத்து *dst,
    முழு depth, Attrib *dirattrib, முழு preserve_flag, முழு print_flag,
    முழு resume_flag, முழு fsync_flag, முழு follow_link_flag, முழு inplace_flag)
{
	முழு i, ret = 0;
	SFTP_DIRENT **dir_entries;
	எழுத்து *filename, *new_src = வெற்று, *new_dst = வெற்று;
	mode_t mode = 0777, tmpmode = mode;
	Attrib *a, ldirattrib, lsym;

	எனில் (depth >= MAX_DIR_DEPTH) {
		error("Maximum directory depth exceeded: %d levels", depth);
		திரும்பு -1;
	}

	debug2_f("download dir remote \"%s\" to local \"%s\"", src, dst);

	எனில் (dirattrib == வெற்று) {
		எனில் (sftp_stat(conn, src, 1, &ldirattrib) != 0) {
			error("stat remote \"%s\" directory failed", src);
			திரும்பு -1;
		}
		dirattrib = &ldirattrib;
	}
	எனில் (!S_ISDIR(dirattrib->perm)) {
		error("\"%s\" is not a directory", src);
		திரும்பு -1;
	}
	எனில் (print_flag && print_flag != SFTP_PROGRESS_ONLY)
		mprintf("Retrieving %s\n", src);

	எனில் (dirattrib->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		mode = dirattrib->perm & 01777;
		tmpmode = mode | (S_IWUSR|S_IXUSR);
	} இல்லையெனில் {
		debug("download remote \"%s\": server "
		    "did not send permissions", dst);
	}

	எனில் (mkdir(dst, tmpmode) == -1 && errno != EEXIST) {
		error("mkdir %s: %s", dst, strerror(errno));
		திரும்பு -1;
	}

	எனில் (sftp_readdir(conn, src, &dir_entries) == -1) {
		error("remote readdir \"%s\" failed", src);
		திரும்பு -1;
	}

	க்கு (i = 0; dir_entries[i] != வெற்று && !interrupted; i++) {
		விடுவி(new_dst);
		விடுவி(new_src);

		filename = dir_entries[i]->filename;
		new_dst = sftp_path_append(dst, filename);
		new_src = sftp_path_append(src, filename);

		a = &dir_entries[i]->a;
		எனில் (S_ISLNK(a->perm)) {
			எனில் (!follow_link_flag) {
				logit("download \"%s\": not a regular file",
				    new_src);
				தொடர்;
			}
			/* Replace the stat contents with the symlink target */
			எனில் (sftp_stat(conn, new_src, 1, &lsym) != 0) {
				logit("remote stat \"%s\" failed", new_src);
				ret = -1;
				தொடர்;
			}
			a = &lsym;
		}

		எனில் (S_ISDIR(a->perm)) {
			எனில் (strcmp(filename, ".") == 0 ||
			    strcmp(filename, "..") == 0)
				தொடர்;
			எனில் (download_dir_internal(conn, new_src, new_dst,
			    depth + 1, a, preserve_flag,
			    print_flag, resume_flag,
			    fsync_flag, follow_link_flag, inplace_flag) == -1)
				ret = -1;
		} இல்லையெனில் எனில் (S_ISREG(a->perm)) {
			எனில் (sftp_download(conn, new_src, new_dst, a,
			    preserve_flag, resume_flag, fsync_flag,
			    inplace_flag) == -1) {
				error("Download of file %s to %s failed",
				    new_src, new_dst);
				ret = -1;
			}
		} இல்லையெனில்
			logit("download \"%s\": not a regular file", new_src);

	}
	விடுவி(new_dst);
	விடுவி(new_src);

	எனில் (preserve_flag) {
		எனில் (dirattrib->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
			கட்டமைப்பு timeval tv[2];
			tv[0].tv_sec = dirattrib->atime;
			tv[1].tv_sec = dirattrib->mtime;
			tv[0].tv_usec = tv[1].tv_usec = 0;
			எனில் (utimes(dst, tv) == -1)
				error("local set times on \"%s\": %s",
				    dst, strerror(errno));
		} இல்லையெனில்
			debug("Server did not send times for directory "
			    "\"%s\"", dst);
	}

	எனில் (mode != tmpmode && chmod(dst, mode) == -1)
		error("local chmod directory \"%s\": %s", dst,
		    strerror(errno));

	sftp_free_dirents(dir_entries);

	திரும்பு ret;
}

முழு
sftp_download_dir(கட்டமைப்பு sftp_conn *conn, மாறிலி எழுத்து *src, மாறிலி எழுத்து *dst,
    Attrib *dirattrib, முழு preserve_flag, முழு print_flag, முழு resume_flag,
    முழு fsync_flag, முழு follow_link_flag, முழு inplace_flag)
{
	எழுத்து *src_canon;
	முழு ret;

	எனில் ((src_canon = sftp_realpath(conn, src)) == வெற்று) {
		error("download \"%s\": path canonicalization failed", src);
		திரும்பு -1;
	}

	ret = download_dir_internal(conn, src_canon, dst, 0,
	    dirattrib, preserve_flag, print_flag, resume_flag, fsync_flag,
	    follow_link_flag, inplace_flag);
	விடுவி(src_canon);
	திரும்பு ret;
}

முழு
sftp_upload(கட்டமைப்பு sftp_conn *conn, மாறிலி எழுத்து *local_path,
    மாறிலி எழுத்து *remote_path, முழு preserve_flag, முழு resume,
    முழு fsync_flag, முழு inplace_flag)
{
	முழு r, local_fd;
	u_int openmode, id, status = SSH2_FX_OK, status2, reordered = 0;
	off_t offset, progress_counter;
	u_char type, *handle, *data;
	கட்டமைப்பு sshbuf *செய்தி;
	கட்டமைப்பு stat sb;
	Attrib a, t, c;
	uint32_t startid, ackid;
	uint64_t highwater = 0, maxack = 0;
	கட்டமைப்பு request *ack = வெற்று;
	கட்டமைப்பு requests acks;
	size_t handle_len;

	debug2_f("upload local \"%s\" to remote \"%s\"",
	    local_path, remote_path);

	TAILQ_INIT(&acks);

	எனில் ((local_fd = open(local_path, O_RDONLY)) == -1) {
		error("open local \"%s\": %s", local_path, strerror(errno));
		திரும்பு(-1);
	}
	எனில் (fstat(local_fd, &sb) == -1) {
		error("fstat local \"%s\": %s", local_path, strerror(errno));
		close(local_fd);
		திரும்பு(-1);
	}
	எனில் (!S_ISREG(sb.st_mode)) {
		error("local \"%s\" is not a regular file", local_path);
		close(local_fd);
		திரும்பு(-1);
	}
	stat_to_attrib(&sb, &a);

	a.flags &= ~SSH2_FILEXFER_ATTR_SIZE;
	a.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a.perm &= 0777;
	எனில் (!preserve_flag)
		a.flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;

	எனில் (resume) {
		/* Get remote file size if it exists */
		எனில் (sftp_stat(conn, remote_path, 0, &c) != 0) {
			close(local_fd);
			திரும்பு -1;
		}

		எனில் ((off_t)c.size >= sb.st_size) {
			error("resume \"%s\": destination file "
			    "same size or larger", local_path);
			close(local_fd);
			திரும்பு -1;
		}

		எனில் (lseek(local_fd, (off_t)c.size, SEEK_SET) == -1) {
			close(local_fd);
			திரும்பு -1;
		}
		highwater = c.size;
	}

	openmode = SSH2_FXF_WRITE|SSH2_FXF_CREAT;
	எனில் (resume)
		openmode |= SSH2_FXF_APPEND;
	இல்லையெனில் எனில் (!inplace_flag)
		openmode |= SSH2_FXF_TRUNC;

	/* Send open request */
	எனில் (send_open(conn, remote_path, "dest", openmode, &a,
	    &handle, &handle_len) != 0) {
		close(local_fd);
		திரும்பு -1;
	}

	id = conn->செய்தி_id;
	startid = ackid = id + 1;
	data = xmalloc(conn->upload_buflen);

	/* Read from local and write to remote */
	offset = progress_counter = (resume ? c.size : 0);
	எனில் (showprogress) {
		start_progress_meter(progress_meter_path(local_path),
		    sb.st_size, &progress_counter);
	}

	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	க்கு (;;) {
		முழு len;

		/*
		 * Can't use atomicio here because it returns 0 on EOF,
		 * thus losing the last block of the file.
		 * Simulate an EOF on interrupt, allowing ACKs from the
		 * server to drain.
		 */
		எனில் (interrupted || status != SSH2_FX_OK)
			len = 0;
		இல்லையெனில் செய்
			len = பட(local_fd, data, conn->upload_buflen);
		போது ((len == -1) &&
		    (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK));

		எனில் (len == -1) {
			fatal("read local \"%s\": %s",
			    local_path, strerror(errno));
		} இல்லையெனில் எனில் (len != 0) {
			ack = request_enqueue(&acks, ++id, len, offset);
			sshbuf_reset(செய்தி);
			எனில் ((r = sshbuf_put_u8(செய்தி, SSH2_FXP_WRITE)) != 0 ||
			    (r = sshbuf_put_u32(செய்தி, ack->id)) != 0 ||
			    (r = sshbuf_put_string(செய்தி, handle,
			    handle_len)) != 0 ||
			    (r = sshbuf_put_u64(செய்தி, offset)) != 0 ||
			    (r = sshbuf_put_string(செய்தி, data, len)) != 0)
				fatal_fr(r, "compose");
			send_செய்தி(conn, செய்தி);
			debug3("Sent message SSH2_FXP_WRITE I:%u O:%llu S:%u",
			    id, (unsigned long long)offset, len);
		} இல்லையெனில் எனில் (TAILQ_FIRST(&acks) == வெற்று)
			நிறுத்து;

		எனில் (ack == வெற்று)
			fatal("Unexpected ACK %u", id);

		எனில் (id == startid || len == 0 ||
		    id - ackid >= conn->இலக்கம்_requests) {
			u_int rid;

			sshbuf_reset(செய்தி);
			get_செய்தி(conn, செய்தி);
			எனில் ((r = sshbuf_get_u8(செய்தி, &type)) != 0 ||
			    (r = sshbuf_get_u32(செய்தி, &rid)) != 0)
				fatal_fr(r, "parse");

			எனில் (type != SSH2_FXP_STATUS)
				fatal("Expected SSH2_FXP_STATUS(%d) packet, "
				    "got %d", SSH2_FXP_STATUS, type);

			எனில் ((r = sshbuf_get_u32(செய்தி, &status2)) != 0)
				fatal_fr(r, "parse status");
			debug3("SSH2_FXP_STATUS %u", status2);
			எனில் (status2 != SSH2_FX_OK)
				status = status2; /* remember errors */

			/* Find the request in our queue */
			எனில் ((ack = request_find(&acks, rid)) == வெற்று)
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
			எனில் (maxack < ack->offset + ack->len)
				maxack = ack->offset + ack->len;
			எனில் (!reordered && ack->offset <= highwater)
				highwater = maxack;
			இல்லையெனில் எனில் (!reordered && ack->offset > highwater) {
				debug3_f("server reordered ACKs");
				reordered = 1;
			}
			விடுவி(ack);
		}
		offset += len;
		எனில் (offset < 0)
			fatal_f("offset < 0");
	}
	sshbuf_free(செய்தி);

	எனில் (showprogress)
		stop_progress_meter();
	விடுவி(data);

	எனில் (status == SSH2_FX_OK && !interrupted) {
		/* we got everything */
		highwater = maxack;
	}
	எனில் (status != SSH2_FX_OK) {
		error("write remote \"%s\": %s", remote_path, fx2txt(status));
		status = SSH2_FX_FAILURE;
	}

	எனில் (inplace_flag || (resume && (status != SSH2_FX_OK || interrupted))) {
		debug("truncating at %llu", (unsigned long long)highwater);
		attrib_clear(&t);
		t.flags = SSH2_FILEXFER_ATTR_SIZE;
		t.size = highwater;
		sftp_fsetstat(conn, handle, handle_len, &t);
	}

	எனில் (close(local_fd) == -1) {
		error("close local \"%s\": %s", local_path, strerror(errno));
		status = SSH2_FX_FAILURE;
	}

	/* Override umask and utimes if asked */
	எனில் (preserve_flag)
		sftp_fsetstat(conn, handle, handle_len, &a);

	எனில் (fsync_flag)
		(வெறுமை)sftp_fsync(conn, handle, handle_len);

	எனில் (sftp_close(conn, handle, handle_len) != 0)
		status = SSH2_FX_FAILURE;

	விடுவி(handle);

	திரும்பு status == SSH2_FX_OK ? 0 : -1;
}

நிலையான முழு
upload_dir_internal(கட்டமைப்பு sftp_conn *conn, மாறிலி எழுத்து *src, மாறிலி எழுத்து *dst,
    முழு depth, முழு preserve_flag, முழு print_flag, முழு resume, முழு fsync_flag,
    முழு follow_link_flag, முழு inplace_flag)
{
	முழு created = 0, ret = 0;
	DIR *dirp;
	கட்டமைப்பு dirent *dp;
	எழுத்து *filename, *new_src = வெற்று, *new_dst = வெற்று;
	கட்டமைப்பு stat sb;
	Attrib a, dirattrib;
	uint32_t saved_perm;

	debug2_f("upload local dir \"%s\" to remote \"%s\"", src, dst);

	எனில் (depth >= MAX_DIR_DEPTH) {
		error("Maximum directory depth exceeded: %d levels", depth);
		திரும்பு -1;
	}

	எனில் (stat(src, &sb) == -1) {
		error("stat local \"%s\": %s", src, strerror(errno));
		திரும்பு -1;
	}
	எனில் (!S_ISDIR(sb.st_mode)) {
		error("\"%s\" is not a directory", src);
		திரும்பு -1;
	}
	எனில் (print_flag && print_flag != SFTP_PROGRESS_ONLY)
		mprintf("Entering %s\n", src);

	stat_to_attrib(&sb, &a);
	a.flags &= ~SSH2_FILEXFER_ATTR_SIZE;
	a.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a.perm &= 01777;
	எனில் (!preserve_flag)
		a.flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;

	/*
	 * sftp lacks a portable status value to match errno EEXIST,
	 * so if we get a failure back then we must check whether
	 * the path already existed and is a directory.  Ensure we can
	 * write to the directory we create for the duration of the transfer.
	 */
	saved_perm = a.perm;
	a.perm |= (S_IWUSR|S_IXUSR);
	எனில் (sftp_mkdir(conn, dst, &a, 0) == 0)
		created = 1;
	இல்லையெனில் {
		எனில் (sftp_stat(conn, dst, 0, &dirattrib) != 0)
			திரும்பு -1;
		எனில் (!S_ISDIR(dirattrib.perm)) {
			error("\"%s\" exists but is not a directory", dst);
			திரும்பு -1;
		}
	}
	a.perm = saved_perm;

	எனில் ((dirp = opendir(src)) == வெற்று) {
		error("local opendir \"%s\": %s", src, strerror(errno));
		திரும்பு -1;
	}

	போது (((dp = readdir(dirp)) != வெற்று) && !interrupted) {
		எனில் (dp->d_ino == 0)
			தொடர்;
		விடுவி(new_dst);
		விடுவி(new_src);
		filename = dp->d_name;
		new_dst = sftp_path_append(dst, filename);
		new_src = sftp_path_append(src, filename);

		எனில் (strcmp(filename, ".") == 0 || strcmp(filename, "..") == 0)
			தொடர்;
		எனில் (lstat(new_src, &sb) == -1) {
			logit("local lstat \"%s\": %s", filename,
			    strerror(errno));
			ret = -1;
			தொடர்;
		}
		எனில் (S_ISLNK(sb.st_mode)) {
			எனில் (!follow_link_flag) {
				logit("%s: not a regular file", filename);
				தொடர்;
			}
			/* Replace the stat contents with the symlink target */
			எனில் (stat(new_src, &sb) == -1) {
				logit("local stat \"%s\": %s", filename,
				    strerror(errno));
				ret = -1;
				தொடர்;
			}
		}
		எனில் (S_ISDIR(sb.st_mode)) {
			எனில் (upload_dir_internal(conn, new_src, new_dst,
			    depth + 1, preserve_flag, print_flag, resume,
			    fsync_flag, follow_link_flag, inplace_flag) == -1)
				ret = -1;
		} இல்லையெனில் எனில் (S_ISREG(sb.st_mode)) {
			எனில் (sftp_upload(conn, new_src, new_dst,
			    preserve_flag, resume, fsync_flag,
			    inplace_flag) == -1) {
				error("upload \"%s\" to \"%s\" failed",
				    new_src, new_dst);
				ret = -1;
			}
		} இல்லையெனில்
			logit("%s: not a regular file", filename);
	}
	விடுவி(new_dst);
	விடுவி(new_src);

	எனில் (created || preserve_flag)
		sftp_setstat(conn, dst, &a);

	(வெறுமை) closedir(dirp);
	திரும்பு ret;
}

முழு
sftp_upload_dir(கட்டமைப்பு sftp_conn *conn, மாறிலி எழுத்து *src, மாறிலி எழுத்து *dst,
    முழு preserve_flag, முழு print_flag, முழு resume, முழு fsync_flag,
    முழு follow_link_flag, முழு inplace_flag)
{
	எழுத்து *dst_canon;
	முழு ret;

	எனில் ((dst_canon = sftp_realpath(conn, dst)) == வெற்று) {
		error("upload \"%s\": path canonicalization failed", dst);
		திரும்பு -1;
	}

	ret = upload_dir_internal(conn, src, dst_canon, 0, preserve_flag,
	    print_flag, resume, fsync_flag, follow_link_flag, inplace_flag);

	விடுவி(dst_canon);
	திரும்பு ret;
}

நிலையான வெறுமை
handle_dest_replies(கட்டமைப்பு sftp_conn *to, மாறிலி எழுத்து *to_path, முழு synchronous,
    u_int *nreqsp, u_int *write_errorp)
{
	கட்டமைப்பு sshbuf *செய்தி;
	u_char type;
	u_int id, status;
	முழு r;
	கட்டமைப்பு pollfd pfd;

	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");

	/* Try to eat replies from the upload side */
	போது (*nreqsp > 0) {
		debug3_f("%u outstanding replies", *nreqsp);
		எனில் (!synchronous) {
			/* Bail out if no data is ready to be read */
			pfd.fd = to->fd_in;
			pfd.events = POLLIN;
			எனில் ((r = poll(&pfd, 1, 0)) == -1) {
				எனில் (errno == EINTR)
					நிறுத்து;
				fatal_f("poll: %s", strerror(errno));
			} இல்லையெனில் எனில் (r == 0)
				நிறுத்து; /* fd not ready */
		}
		sshbuf_reset(செய்தி);
		get_செய்தி(to, செய்தி);

		எனில் ((r = sshbuf_get_u8(செய்தி, &type)) != 0 ||
		    (r = sshbuf_get_u32(செய்தி, &id)) != 0)
			fatal_fr(r, "dest parse");
		debug3("Received dest reply T:%u I:%u R:%u", type, id, *nreqsp);
		எனில் (type != SSH2_FXP_STATUS) {
			fatal_f("Expected SSH2_FXP_STATUS(%d) packet, got %d",
			    SSH2_FXP_STATUS, type);
		}
		எனில் ((r = sshbuf_get_u32(செய்தி, &status)) != 0)
			fatal_fr(r, "parse dest status");
		debug3("dest SSH2_FXP_STATUS %u", status);
		எனில் (status != SSH2_FX_OK) {
			/* record first error */
			எனில் (*write_errorp == 0)
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
	sshbuf_free(செய்தி);
}

முழு
sftp_crossload(கட்டமைப்பு sftp_conn *from, கட்டமைப்பு sftp_conn *to,
    மாறிலி எழுத்து *from_path, மாறிலி எழுத்து *to_path,
    Attrib *a, முழு preserve_flag)
{
	கட்டமைப்பு sshbuf *செய்தி;
	முழு write_error, read_error, r, seen_zerolen = 0;
	uint64_t offset = 0, size;
	u_int id, buflen, இலக்கம்_req, max_req, status = SSH2_FX_OK;
	u_int இலக்கம்_upload_req;
	off_t progress_counter;
	u_char *from_handle, *to_handle;
	size_t from_handle_len, to_handle_len;
	கட்டமைப்பு requests requests;
	கட்டமைப்பு request *req;
	u_char type;
	Attrib attr;

	debug2_f("crossload src \"%s\" to dst \"%s\"", from_path, to_path);

	TAILQ_INIT(&requests);

	எனில் (a == வெற்று) {
		எனில் (sftp_stat(from, from_path, 0, &attr) != 0)
			திரும்பு -1;
		a = &attr;
	}

	எனில் ((a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) &&
	    (!S_ISREG(a->perm))) {
		error("download \"%s\": not a regular file", from_path);
		திரும்பு(-1);
	}
	எனில் (a->flags & SSH2_FILEXFER_ATTR_SIZE)
		size = a->size;
	இல்லையெனில்
		size = 0;

	buflen = from->download_buflen;
	எனில் (buflen > to->upload_buflen)
		buflen = to->upload_buflen;

	/* Send open request to read side */
	எனில் (send_open(from, from_path, "origin", SSH2_FXF_READ, வெற்று,
	    &from_handle, &from_handle_len) != 0)
		திரும்பு -1;

	/* Send open request to write side */
	a->flags &= ~SSH2_FILEXFER_ATTR_SIZE;
	a->flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a->perm &= 0777;
	எனில் (!preserve_flag)
		a->flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;
	எனில் (send_open(to, to_path, "dest",
	    SSH2_FXF_WRITE|SSH2_FXF_CREAT|SSH2_FXF_TRUNC, a,
	    &to_handle, &to_handle_len) != 0) {
		sftp_close(from, from_handle, from_handle_len);
		திரும்பு -1;
	}

	/* Read from remote "from" and write to remote "to" */
	offset = 0;
	write_error = read_error = இலக்கம்_req = இலக்கம்_upload_req = 0;
	max_req = 1;
	progress_counter = 0;

	எனில் (showprogress && size != 0) {
		start_progress_meter(progress_meter_path(from_path),
		    size, &progress_counter);
	}
	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	போது (இலக்கம்_req > 0 || max_req > 0) {
		u_char *data;
		size_t len;

		/*
		 * Simulate EOF on interrupt: stop sending new requests and
		 * allow outstanding requests to drain gracefully
		 */
		எனில் (interrupted) {
			எனில் (இலக்கம்_req == 0) /* If we haven't started yet... */
				நிறுத்து;
			max_req = 0;
		}

		/* Send some more requests */
		போது (இலக்கம்_req < max_req) {
			debug3("Request range %llu -> %llu (%d/%d)",
			    (unsigned long long)offset,
			    (unsigned long long)offset + buflen - 1,
			    இலக்கம்_req, max_req);
			req = request_enqueue(&requests, from->செய்தி_id++,
			    buflen, offset);
			offset += buflen;
			இலக்கம்_req++;
			send_read_request(from, req->id, req->offset,
			    req->len, from_handle, from_handle_len);
		}

		/* Try to eat replies from the upload side (nonblocking) */
		handle_dest_replies(to, to_path, 0,
		    &இலக்கம்_upload_req, &write_error);

		sshbuf_reset(செய்தி);
		get_செய்தி(from, செய்தி);
		எனில் ((r = sshbuf_get_u8(செய்தி, &type)) != 0 ||
		    (r = sshbuf_get_u32(செய்தி, &id)) != 0)
			fatal_fr(r, "parse");
		debug3("Received origin reply T:%u I:%u R:%d",
		    type, id, max_req);

		/* Find the request in our queue */
		எனில் ((req = request_find(&requests, id)) == வெற்று)
			fatal("Unexpected reply %u", id);

		தேர்வு (type) {
		நிலை SSH2_FXP_STATUS:
			எனில் ((r = sshbuf_get_u32(செய்தி, &status)) != 0)
				fatal_fr(r, "parse status");
			எனில் (status != SSH2_FX_EOF)
				read_error = 1;
			max_req = 0;
			TAILQ_REMOVE(&requests, req, tq);
			விடுவி(req);
			இலக்கம்_req--;
			நிறுத்து;
		நிலை SSH2_FXP_DATA:
			எனில் ((r = sshbuf_get_string(செய்தி, &data, &len)) != 0)
				fatal_fr(r, "parse data");
			debug3("Received data %llu -> %llu",
			    (unsigned long long)req->offset,
			    (unsigned long long)req->offset + len - 1);
			எனில் (len > req->len)
				fatal("Received more data than asked for "
				    "%zu > %zu", len, req->len);
			எனில் (len == 0) {
				எனில் (seen_zerolen)
					fatal_f("server sent zero data length");
				seen_zerolen = 1;
			}

			/* Write this chunk out to the destination */
			sshbuf_reset(செய்தி);
			எனில் ((r = sshbuf_put_u8(செய்தி, SSH2_FXP_WRITE)) != 0 ||
			    (r = sshbuf_put_u32(செய்தி, to->செய்தி_id++)) != 0 ||
			    (r = sshbuf_put_string(செய்தி, to_handle,
			    to_handle_len)) != 0 ||
			    (r = sshbuf_put_u64(செய்தி, req->offset)) != 0 ||
			    (r = sshbuf_put_string(செய்தி, data, len)) != 0)
				fatal_fr(r, "compose write");
			send_செய்தி(to, செய்தி);
			debug3("Sent message SSH2_FXP_WRITE I:%u O:%llu S:%zu",
			    id, (unsigned long long)offset, len);
			இலக்கம்_upload_req++;
			progress_counter += len;
			விடுவி(data);

			எனில் (len == req->len) {
				TAILQ_REMOVE(&requests, req, tq);
				விடுவி(req);
				இலக்கம்_req--;
			} இல்லையெனில் {
				/* Resend the request for the missing data */
				debug3("Short data block, re-requesting "
				    "%llu -> %llu (%2d)",
				    (unsigned long long)req->offset + len,
				    (unsigned long long)req->offset +
				    req->len - 1, இலக்கம்_req);
				req->id = from->செய்தி_id++;
				req->len -= len;
				req->offset += len;
				send_read_request(from, req->id,
				    req->offset, req->len,
				    from_handle, from_handle_len);
				/* Reduce the request size */
				எனில் (len < buflen)
					buflen = MAXIMUM(MIN_READ_SIZE, len);
			}
			எனில் (max_req > 0) { /* max_req = 0 iff EOF received */
				எனில் (size > 0 && offset > size) {
					/* Only one request at a time
					 * after the expected EOF */
					debug3("Finish at %llu (%2d)",
					    (unsigned long long)offset,
					    இலக்கம்_req);
					max_req = 1;
				} இல்லையெனில் எனில் (max_req < from->இலக்கம்_requests) {
					++max_req;
				}
			}
			நிறுத்து;
		இயல்பு:
			fatal("Expected SSH2_FXP_DATA(%u) packet, got %u",
			    SSH2_FXP_DATA, type);
		}
	}

	எனில் (showprogress && size)
		stop_progress_meter();

	/* Drain replies from the server (blocking) */
	debug3_f("waiting for %u replies from destination", இலக்கம்_upload_req);
	handle_dest_replies(to, to_path, 1, &இலக்கம்_upload_req, &write_error);

	/* Sanity check */
	எனில் (TAILQ_FIRST(&requests) != வெற்று)
		fatal("Transfer complete, but requests still in queue");
	/* Truncate at 0 length on interrupt or error to avoid holes at dest */
	எனில் (read_error || write_error || interrupted) {
		debug("truncating \"%s\" at 0", to_path);
		sftp_close(to, to_handle, to_handle_len);
		விடுவி(to_handle);
		எனில் (send_open(to, to_path, "dest",
		    SSH2_FXF_WRITE|SSH2_FXF_CREAT|SSH2_FXF_TRUNC, a,
		    &to_handle, &to_handle_len) != 0) {
			error("dest truncate \"%s\" failed", to_path);
			to_handle = வெற்று;
		}
	}
	எனில் (read_error) {
		error("read origin \"%s\": %s", from_path, fx2txt(status));
		status = -1;
		sftp_close(from, from_handle, from_handle_len);
		எனில் (to_handle != வெற்று)
			sftp_close(to, to_handle, to_handle_len);
	} இல்லையெனில் எனில் (write_error) {
		error("write dest \"%s\": %s", to_path, fx2txt(write_error));
		status = SSH2_FX_FAILURE;
		sftp_close(from, from_handle, from_handle_len);
		எனில் (to_handle != வெற்று)
			sftp_close(to, to_handle, to_handle_len);
	} இல்லையெனில் {
		எனில் (sftp_close(from, from_handle, from_handle_len) != 0 ||
		    interrupted)
			status = -1;
		இல்லையெனில்
			status = SSH2_FX_OK;
		எனில் (to_handle != வெற்று) {
			/* Need to resend utimes after write */
			எனில் (preserve_flag)
				sftp_fsetstat(to, to_handle, to_handle_len, a);
			sftp_close(to, to_handle, to_handle_len);
		}
	}
	sshbuf_free(செய்தி);
	விடுவி(from_handle);
	விடுவி(to_handle);

	திரும்பு status == SSH2_FX_OK ? 0 : -1;
}

நிலையான முழு
crossload_dir_internal(கட்டமைப்பு sftp_conn *from, கட்டமைப்பு sftp_conn *to,
    மாறிலி எழுத்து *from_path, மாறிலி எழுத்து *to_path,
    முழு depth, Attrib *dirattrib, முழு preserve_flag, முழு print_flag,
    முழு follow_link_flag)
{
	முழு i, ret = 0, created = 0;
	SFTP_DIRENT **dir_entries;
	எழுத்து *filename, *new_from_path = வெற்று, *new_to_path = வெற்று;
	mode_t mode = 0777;
	Attrib *a, curdir, ldirattrib, newdir, lsym;

	debug2_f("crossload dir src \"%s\" to dst \"%s\"", from_path, to_path);

	எனில் (depth >= MAX_DIR_DEPTH) {
		error("Maximum directory depth exceeded: %d levels", depth);
		திரும்பு -1;
	}

	எனில் (dirattrib == வெற்று) {
		எனில் (sftp_stat(from, from_path, 1, &ldirattrib) != 0) {
			error("stat remote \"%s\" failed", from_path);
			திரும்பு -1;
		}
		dirattrib = &ldirattrib;
	}
	எனில் (!S_ISDIR(dirattrib->perm)) {
		error("\"%s\" is not a directory", from_path);
		திரும்பு -1;
	}
	எனில் (print_flag && print_flag != SFTP_PROGRESS_ONLY)
		mprintf("Retrieving %s\n", from_path);

	curdir = *dirattrib; /* dirattrib will be clobbered */
	curdir.flags &= ~SSH2_FILEXFER_ATTR_SIZE;
	curdir.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	எனில் ((curdir.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) == 0) {
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
	எனில் (sftp_mkdir(to, to_path, &curdir, 0) == 0)
		created = 1;
	இல்லையெனில் {
		எனில் (sftp_stat(to, to_path, 0, &newdir) != 0)
			திரும்பு -1;
		எனில் (!S_ISDIR(newdir.perm)) {
			error("\"%s\" exists but is not a directory", to_path);
			திரும்பு -1;
		}
	}
	curdir.perm = mode;

	எனில் (sftp_readdir(from, from_path, &dir_entries) == -1) {
		error("origin readdir \"%s\" failed", from_path);
		திரும்பு -1;
	}

	க்கு (i = 0; dir_entries[i] != வெற்று && !interrupted; i++) {
		விடுவி(new_from_path);
		விடுவி(new_to_path);

		filename = dir_entries[i]->filename;
		new_from_path = sftp_path_append(from_path, filename);
		new_to_path = sftp_path_append(to_path, filename);

		a = &dir_entries[i]->a;
		எனில் (S_ISLNK(a->perm)) {
			எனில் (!follow_link_flag) {
				logit("%s: not a regular file", filename);
				தொடர்;
			}
			/* Replace the stat contents with the symlink target */
			எனில் (sftp_stat(from, new_from_path, 1, &lsym) != 0) {
				logit("remote stat \"%s\" failed",
				    new_from_path);
				ret = -1;
				தொடர்;
			}
			a = &lsym;
		}
		எனில் (S_ISDIR(a->perm)) {
			எனில் (strcmp(filename, ".") == 0 ||
			    strcmp(filename, "..") == 0)
				தொடர்;
			எனில் (crossload_dir_internal(from, to,
			    new_from_path, new_to_path,
			    depth + 1, a, preserve_flag,
			    print_flag, follow_link_flag) == -1)
				ret = -1;
		} இல்லையெனில் எனில் (S_ISREG(a->perm)) {
			எனில் (sftp_crossload(from, to, new_from_path,
			    new_to_path, a, preserve_flag) == -1) {
				error("crossload \"%s\" to \"%s\" failed",
				    new_from_path, new_to_path);
				ret = -1;
			}
		} இல்லையெனில் {
			logit("origin \"%s\": not a regular file",
			    new_from_path);
		}
	}
	விடுவி(new_to_path);
	விடுவி(new_from_path);

	எனில் (created || preserve_flag)
		sftp_setstat(to, to_path, &curdir);

	sftp_free_dirents(dir_entries);

	திரும்பு ret;
}

முழு
sftp_crossload_dir(கட்டமைப்பு sftp_conn *from, கட்டமைப்பு sftp_conn *to,
    மாறிலி எழுத்து *from_path, மாறிலி எழுத்து *to_path,
    Attrib *dirattrib, முழு preserve_flag, முழு print_flag, முழு follow_link_flag)
{
	எழுத்து *from_path_canon;
	முழு ret;

	எனில் ((from_path_canon = sftp_realpath(from, from_path)) == வெற்று) {
		error("crossload \"%s\": path canonicalization failed",
		    from_path);
		திரும்பு -1;
	}

	ret = crossload_dir_internal(from, to, from_path_canon, to_path, 0,
	    dirattrib, preserve_flag, print_flag, follow_link_flag);
	விடுவி(from_path_canon);
	திரும்பு ret;
}

முழு
sftp_can_get_users_groups_by_id(கட்டமைப்பு sftp_conn *conn)
{
	திரும்பு (conn->exts & SFTP_EXT_GETUSERSGROUPS_BY_ID) != 0;
}

முழு
sftp_get_users_groups_by_id(கட்டமைப்பு sftp_conn *conn,
    மாறிலி u_int *uids, u_int nuids,
    மாறிலி u_int *gids, u_int ngids,
    எழுத்து ***usernamesp, எழுத்து ***groupnamesp)
{
	கட்டமைப்பு sshbuf *செய்தி, *uidbuf, *gidbuf;
	u_int i, expected_id, id;
	எழுத்து *name, **usernames = வெற்று, **groupnames = வெற்று;
	u_char type;
	முழு r;

	*usernamesp = *groupnamesp = வெற்று;
	எனில் (!sftp_can_get_users_groups_by_id(conn))
		திரும்பு SSH_ERR_FEATURE_UNSUPPORTED;

	எனில் ((செய்தி = sshbuf_new()) == வெற்று ||
	    (uidbuf = sshbuf_new()) == வெற்று ||
	    (gidbuf = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	expected_id = id = conn->செய்தி_id++;
	debug2("Sending SSH2_FXP_EXTENDED(users-groups-by-id@openssh.com)");
	க்கு (i = 0; i < nuids; i++) {
		எனில் ((r = sshbuf_put_u32(uidbuf, uids[i])) != 0)
			fatal_fr(r, "compose uids");
	}
	க்கு (i = 0; i < ngids; i++) {
		எனில் ((r = sshbuf_put_u32(gidbuf, gids[i])) != 0)
			fatal_fr(r, "compose gids");
	}
	எனில் ((r = sshbuf_put_u8(செய்தி, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(செய்தி, id)) != 0 ||
	    (r = sshbuf_put_cstring(செய்தி,
	    "users-groups-by-id@openssh.com")) != 0 ||
	    (r = sshbuf_put_stringb(செய்தி, uidbuf)) != 0 ||
	    (r = sshbuf_put_stringb(செய்தி, gidbuf)) != 0)
		fatal_fr(r, "compose");
	send_செய்தி(conn, செய்தி);
	get_செய்தி(conn, செய்தி);
	எனில் ((r = sshbuf_get_u8(செய்தி, &type)) != 0 ||
	    (r = sshbuf_get_u32(செய்தி, &id)) != 0)
		fatal_fr(r, "parse");
	எனில் (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	எனில் (type == SSH2_FXP_STATUS) {
		u_int status;
		எழுத்து *errmsg;

		எனில் ((r = sshbuf_get_u32(செய்தி, &status)) != 0 ||
		    (r = sshbuf_get_cstring(செய்தி, &errmsg, வெற்று)) != 0)
			fatal_fr(r, "parse status");
		error("users-groups-by-id %s",
		    *errmsg == '\0' ? fx2txt(status) : errmsg);
		விடுவி(errmsg);
		sshbuf_free(செய்தி);
		sshbuf_free(uidbuf);
		sshbuf_free(gidbuf);
		திரும்பு -1;
	} இல்லையெனில் எனில் (type != SSH2_FXP_EXTENDED_REPLY)
		fatal("Expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_REPLY, type);

	/* reuse */
	sshbuf_free(uidbuf);
	sshbuf_free(gidbuf);
	uidbuf = gidbuf = வெற்று;
	எனில் ((r = sshbuf_froms(செய்தி, &uidbuf)) != 0 ||
	    (r = sshbuf_froms(செய்தி, &gidbuf)) != 0)
		fatal_fr(r, "parse response");
	எனில் (nuids > 0) {
		usernames = xcalloc(nuids, அளவு(*usernames));
		க்கு (i = 0; i < nuids; i++) {
			எனில் ((r = sshbuf_get_cstring(uidbuf, &name, வெற்று)) != 0)
				fatal_fr(r, "parse user name");
			/* Handle unresolved names */
			எனில் (*name == '\0') {
				விடுவி(name);
				name = வெற்று;
			}
			usernames[i] = name;
		}
	}
	எனில் (ngids > 0) {
		groupnames = xcalloc(ngids, அளவு(*groupnames));
		க்கு (i = 0; i < ngids; i++) {
			எனில் ((r = sshbuf_get_cstring(gidbuf, &name, வெற்று)) != 0)
				fatal_fr(r, "parse user name");
			/* Handle unresolved names */
			எனில் (*name == '\0') {
				விடுவி(name);
				name = வெற்று;
			}
			groupnames[i] = name;
		}
	}
	எனில் (sshbuf_len(uidbuf) != 0)
		fatal_f("unexpected extra username data");
	எனில் (sshbuf_len(gidbuf) != 0)
		fatal_f("unexpected extra groupname data");
	sshbuf_free(uidbuf);
	sshbuf_free(gidbuf);
	sshbuf_free(செய்தி);
	/* success */
	*usernamesp = usernames;
	*groupnamesp = groupnames;
	திரும்பு 0;
}

எழுத்து *
sftp_path_append(மாறிலி எழுத்து *p1, மாறிலி எழுத்து *p2)
{
	எழுத்து *ret;
	size_t len = strlen(p1) + strlen(p2) + 2;

	ret = xmalloc(len);
	strlcpy(ret, p1, len);
	எனில் (p1[0] != '\0' && p1[strlen(p1) - 1] != '/')
		strlcat(ret, "/", len);
	strlcat(ret, p2, len);

	திரும்பு(ret);
}

/*
 * Arg p must be dynamically allocated.  It will either be returned or
 * freed and a replacement allocated.  Caller must free returned string.
 */
எழுத்து *
sftp_make_absolute(எழுத்து *p, மாறிலி எழுத்து *pwd)
{
	எழுத்து *abs_str;

	/* Derelativise */
	எனில் (p && !path_absolute(p)) {
		abs_str = sftp_path_append(pwd, p);
		விடுவி(p);
		திரும்பு(abs_str);
	} இல்லையெனில்
		திரும்பு(p);
}

முழு
sftp_remote_is_dir(கட்டமைப்பு sftp_conn *conn, மாறிலி எழுத்து *path)
{
	Attrib a;

	/* XXX: report errors? */
	எனில் (sftp_stat(conn, path, 1, &a) != 0)
		திரும்பு(0);
	எனில் (!(a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS))
		திரும்பு(0);
	திரும்பு S_ISDIR(a.perm);
}


/* Check whether path returned from glob(..., GLOB_MARK, ...) is a directory */
முழு
sftp_globpath_is_dir(மாறிலி எழுத்து *pathname)
{
	size_t l = strlen(pathname);

	திரும்பு l > 0 && pathname[l - 1] == '/';
}

