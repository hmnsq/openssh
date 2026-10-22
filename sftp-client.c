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

خارجی متلون sig_atomic_t interrupted;
خارجی صحیح showprogress;

/* Default size of buffer for up/download (fix sftp.1 scp.1 if changed) */
#تعریف_کرو DEFAULT_COPY_BUFLEN	32768

/* Default number of concurrent xfer requests (fix sftp.1 scp.1 if changed) */
#تعریف_کرو DEFAULT_عدد_درخواستیں	64

/* Minimum amount of data to read at a time */
#تعریف_کرو MIN_READ_سائز	512

/* Maximum depth to descend in directory trees */
#تعریف_کرو MAX_DIR_گہرائی 64

/* Directory separator characters */
#اگر_تعریف_شدہ HAVE_CYGWIN
# define SFTP_DIRECTORY_CHARS      "/\\"
#ورنہ /* HAVE_CYGWIN */
# define SFTP_DIRECTORY_CHARS      "/"
#اگر_ختم /* HAVE_CYGWIN */

ساخت sftp_conn {
	صحیح fd_اندر;
	صحیح fd_برآمد;
	u_int download_buflen;
	u_int upload_buflen;
	u_int عدد_درخواستیں;
	u_int نسخہ;
	u_int پیغام_id;
#تعریف_کرو SFTP_EXT_POSIX_RENAME		0x00000001
#تعریف_کرو SFTP_EXT_STATVFS		0x00000002
#تعریف_کرو SFTP_EXT_FSTATVFS		0x00000004
#تعریف_کرو SFTP_EXT_HARDLINK		0x00000008
#تعریف_کرو SFTP_EXT_FSYNC			0x00000010
#تعریف_کرو SFTP_EXT_LSETSTAT		0x00000020
#تعریف_کرو SFTP_EXT_LIMITS			0x00000040
#تعریف_کرو SFTP_EXT_راستہ_EXPAND		0x00000080
#تعریف_کرو SFTP_EXT_COPY_ڈیٹا		0x00000100
#تعریف_کرو SFTP_EXT_GETUSERSGROUPS_BY_ID	0x00000200
	u_int exts;
	uint64_t حد_بندی_kbps;
	ساخت bwlimit bwlimit_اندر, bwlimit_برآمد;
};

/* Tracks in-progress requests during file transfers */
ساخت request {
	u_int id;
	سائز_t len;
	uint64_t انحراف;
	TAILQ_ENTRY(request) tq;
};
TAILQ_HEAD(درخواستیں, request);

ساکن u_char *
get_handle(ساخت sftp_conn *conn, u_int expected_id, سائز_t *len,
    ثابت حرف *errfmt, ...) __attribute__((format(لکھو, 4, 5)));

ساکن ساخت request *
request_قطار_میں_ڈالو(ساخت درخواستیں *درخواستیں, u_int id, سائز_t len,
    uint64_t انحراف)
{
	ساخت request *req;

	req = xcalloc(1, حجم(*req));
	req->id = id;
	req->len = len;
	req->انحراف = انحراف;
	TAILQ_INSERT_TAIL(درخواستیں, req, tq);
	واپس req;
}

ساکن ساخت request *
request_ڈھونڈو(ساخت درخواستیں *درخواستیں, u_int id)
{
	ساخت request *req;

	برائے (req = TAILQ_FIRST(درخواستیں);
	    req != تہی && req->id != id;
	    req = TAILQ_NEXT(req, tq))
		;
	واپس req;
}

ساکن صحیح
sftpio(خالی *_bwlimit, سائز_t amount)
{
	ساخت bwlimit *bwlimit = (ساخت bwlimit *)_bwlimit;

	refresh_پیش_رفت_meter(0);
	اگر (bwlimit != تہی)
		bandwidth_حد_بندی(bwlimit, amount);
	واپس 0;
}

ساکن خالی
send_پیغام(ساخت sftp_conn *conn, ساخت sshbuf *m)
{
	u_char mlen[4];
	ساخت iovec iov[2];

	اگر (sshbuf_len(m) > SFTP_MAX_پیغام_لمبائی)
		fatal("Outbound message too long %zu", sshbuf_len(m));

	/* Send length first */
	put_u32(mlen, sshbuf_len(m));
	iov[0].iov_base = mlen;
	iov[0].iov_len = حجم(mlen);
	iov[1].iov_base = (u_char *)sshbuf_ptr(m);
	iov[1].iov_len = sshbuf_len(m);

	اگر (atomiciov6(writev, conn->fd_برآمد, iov, 2, sftpio,
	    conn->حد_بندی_kbps > 0 ? &conn->bwlimit_برآمد : تہی) !=
	    sshbuf_len(m) + حجم(mlen))
		fatal("Couldn't send packet: %s", strerror(errno));

	sshbuf_reset(m);
}

ساکن خالی
get_پیغام_extended(ساخت sftp_conn *conn, ساخت sshbuf *m, صحیح initial)
{
	u_int پیغام_len;
	u_char *p;
	صحیح r;

	sshbuf_reset(m);
	اگر ((r = sshbuf_reserve(m, 4, &p)) != 0)
		fatal_fr(r, "reserve");
	اگر (atomicio6(اقرأ, conn->fd_اندر, p, 4, sftpio,
	    conn->حد_بندی_kbps > 0 ? &conn->bwlimit_اندر : تہی) != 4) {
		اگر (errno == EPIPE || errno == ECONNRESET)
			fatal("Connection closed");
		ورنہ
			fatal("Couldn't read packet: %s", strerror(errno));
	}

	اگر ((r = sshbuf_get_u32(m, &پیغام_len)) != 0)
		fatal_fr(r, "sshbuf_get_u32");
	اگر (پیغام_len > SFTP_MAX_پیغام_لمبائی) {
		do_log2(initial ? SYSLOG_LEVEL_ERROR : SYSLOG_LEVEL_FATAL,
		    "Received message too long %u", پیغام_len);
		fatal("Ensure the remote shell produces no output "
		    "for non-interactive sessions.");
	}

	اگر ((r = sshbuf_reserve(m, پیغام_len, &p)) != 0)
		fatal_fr(r, "reserve");
	اگر (atomicio6(اقرأ, conn->fd_اندر, p, پیغام_len, sftpio,
	    conn->حد_بندی_kbps > 0 ? &conn->bwlimit_اندر : تہی)
	    != پیغام_len) {
		اگر (errno == EPIPE)
			fatal("Connection closed");
		ورنہ
			fatal("Read packet: %s", strerror(errno));
	}
}

ساکن خالی
get_پیغام(ساخت sftp_conn *conn, ساخت sshbuf *m)
{
	get_پیغام_extended(conn, m, 0);
}

ساکن خالی
send_string_request(ساخت sftp_conn *conn, u_int id, u_int رمز, ثابت حرف *s,
    u_int len)
{
	ساخت sshbuf *پیغام;
	صحیح r;

	اگر ((پیغام = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_u8(پیغام, رمز)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, id)) != 0 ||
	    (r = sshbuf_put_string(پیغام, s, len)) != 0)
		fatal_fr(r, "compose");
	send_پیغام(conn, پیغام);
	debug3("Sent message fd %d T:%u I:%u", conn->fd_برآمد, رمز, id);
	sshbuf_free(پیغام);
}

ساکن خالی
send_string_attrs_request(ساخت sftp_conn *conn, u_int id, u_int رمز,
    ثابت خالی *s, u_int len, Attrib *a)
{
	ساخت sshbuf *پیغام;
	صحیح r;

	اگر ((پیغام = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_u8(پیغام, رمز)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, id)) != 0 ||
	    (r = sshbuf_put_string(پیغام, s, len)) != 0 ||
	    (r = encode_attrib(پیغام, a)) != 0)
		fatal_fr(r, "compose");
	send_پیغام(conn, پیغام);
	debug3("Sent message fd %d T:%u I:%u F:0x%04x M:%05o",
	    conn->fd_برآمد, رمز, id, a->flags, a->perm);
	sshbuf_free(پیغام);
}

ساکن u_int
get_حالت(ساخت sftp_conn *conn, u_int expected_id)
{
	ساخت sshbuf *پیغام;
	u_char type;
	u_int id, حالت_2;
	صحیح r;

	اگر ((پیغام = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	get_پیغام(conn, پیغام);
	اگر ((r = sshbuf_get_u8(پیغام, &type)) != 0 ||
	    (r = sshbuf_get_u32(پیغام, &id)) != 0)
		fatal_fr(r, "compose");

	اگر (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	اگر (type != SSH2_FXP_حالت)
		fatal("Expected SSH2_FXP_STATUS(%u) packet, got %u",
		    SSH2_FXP_حالت, type);

	اگر ((r = sshbuf_get_u32(پیغام, &حالت_2)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(پیغام);

	debug3("SSH2_FXP_STATUS %u", حالت_2);

	واپس حالت_2;
}

ساکن u_char *
get_handle(ساخت sftp_conn *conn, u_int expected_id, سائز_t *len,
    ثابت حرف *errfmt, ...)
{
	ساخت sshbuf *پیغام;
	u_int id, حالت_2;
	u_char type;
	u_char *handle;
	حرف errmsg[256];
	va_list دلائل;
	صحیح r;

	va_start(دلائل, errfmt);
	اگر (errfmt != تہی)
		vsnprintf(errmsg, حجم(errmsg), errfmt, دلائل);
	va_end(دلائل);

	اگر ((پیغام = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	get_پیغام(conn, پیغام);
	اگر ((r = sshbuf_get_u8(پیغام, &type)) != 0 ||
	    (r = sshbuf_get_u32(پیغام, &id)) != 0)
		fatal_fr(r, "parse");

	اگر (id != expected_id)
		fatal("%s: ID mismatch (%u != %u)",
		    errfmt == تہی ? __func__ : errmsg, id, expected_id);
	اگر (type == SSH2_FXP_حالت) {
		اگر ((r = sshbuf_get_u32(پیغام, &حالت_2)) != 0)
			fatal_fr(r, "parse status");
		اگر (errfmt != تہی)
			error("%s: %s", errmsg, fx2txt(حالت_2));
		sshbuf_free(پیغام);
		واپس(تہی);
	} ورنہ اگر (type != SSH2_FXP_HANDLE)
		fatal("%s: Expected SSH2_FXP_HANDLE(%u) packet, got %u",
		    errfmt == تہی ? __func__ : errmsg, SSH2_FXP_HANDLE, type);

	اگر ((r = sshbuf_get_string(پیغام, &handle, len)) != 0)
		fatal_fr(r, "parse handle");
	sshbuf_free(پیغام);

	واپس handle;
}

ساکن صحیح
get_decode_stat(ساخت sftp_conn *conn, u_int expected_id, صحیح quiet, Attrib *a)
{
	ساخت sshbuf *پیغام;
	u_int id;
	u_char type;
	صحیح r;
	Attrib attr;

	اگر (a != تہی)
		memset(a, '\0', حجم(*a));
	اگر ((پیغام = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	get_پیغام(conn, پیغام);

	اگر ((r = sshbuf_get_u8(پیغام, &type)) != 0 ||
	    (r = sshbuf_get_u32(پیغام, &id)) != 0)
		fatal_fr(r, "parse");

	اگر (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	اگر (type == SSH2_FXP_حالت) {
		u_int حالت_2;

		اگر ((r = sshbuf_get_u32(پیغام, &حالت_2)) != 0)
			fatal_fr(r, "parse status");
		اگر (quiet)
			debug("stat remote: %s", fx2txt(حالت_2));
		ورنہ
			error("stat remote: %s", fx2txt(حالت_2));
		sshbuf_free(پیغام);
		واپس -1;
	} ورنہ اگر (type != SSH2_FXP_ATTRS) {
		fatal("Expected SSH2_FXP_ATTRS(%u) packet, got %u",
		    SSH2_FXP_ATTRS, type);
	}
	اگر ((r = decode_attrib(پیغام, &attr)) != 0) {
		error_fr(r, "decode_attrib");
		sshbuf_free(پیغام);
		واپس -1;
	}
	/* success */
	اگر (a != تہی)
		*a = attr;
	debug3("Received stat reply T:%u I:%u F:0x%04x M:%05o",
	    type, id, attr.flags, attr.perm);
	sshbuf_free(پیغام);

	واپس 0;
}

ساکن صحیح
get_decode_statvfs(ساخت sftp_conn *conn, ساخت sftp_statvfs *st,
    u_int expected_id, صحیح quiet)
{
	ساخت sshbuf *پیغام;
	u_char type;
	u_int id;
	uint64_t flag;
	صحیح r;

	اگر ((پیغام = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	get_پیغام(conn, پیغام);

	اگر ((r = sshbuf_get_u8(پیغام, &type)) != 0 ||
	    (r = sshbuf_get_u32(پیغام, &id)) != 0)
		fatal_fr(r, "parse");

	debug3("Received statvfs reply T:%u I:%u", type, id);
	اگر (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	اگر (type == SSH2_FXP_حالت) {
		u_int حالت_2;

		اگر ((r = sshbuf_get_u32(پیغام, &حالت_2)) != 0)
			fatal_fr(r, "parse status");
		اگر (quiet)
			debug("remote statvfs: %s", fx2txt(حالت_2));
		ورنہ
			error("remote statvfs: %s", fx2txt(حالت_2));
		sshbuf_free(پیغام);
		واپس -1;
	} ورنہ اگر (type != SSH2_FXP_EXTENDED_جواب) {
		fatal("Expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_جواب, type);
	}

	memset(st, 0, حجم(*st));
	اگر ((r = sshbuf_get_u64(پیغام, &st->f_bsize)) != 0 ||
	    (r = sshbuf_get_u64(پیغام, &st->f_frsize)) != 0 ||
	    (r = sshbuf_get_u64(پیغام, &st->f_بلاکیں)) != 0 ||
	    (r = sshbuf_get_u64(پیغام, &st->f_bfree)) != 0 ||
	    (r = sshbuf_get_u64(پیغام, &st->f_bavail)) != 0 ||
	    (r = sshbuf_get_u64(پیغام, &st->f_files)) != 0 ||
	    (r = sshbuf_get_u64(پیغام, &st->f_ffree)) != 0 ||
	    (r = sshbuf_get_u64(پیغام, &st->f_favail)) != 0 ||
	    (r = sshbuf_get_u64(پیغام, &st->f_fsid)) != 0 ||
	    (r = sshbuf_get_u64(پیغام, &flag)) != 0 ||
	    (r = sshbuf_get_u64(پیغام, &st->f_namemax)) != 0)
		fatal_fr(r, "parse statvfs");

	st->f_flag = (flag & SSH2_FXE_STATVFS_ST_RDONLY) ? ST_RDONLY : 0;
	st->f_flag |= (flag & SSH2_FXE_STATVFS_ST_NOSUID) ? ST_NOSUID : 0;

	sshbuf_free(پیغام);

	واپس 0;
}

ساخت sftp_conn *
sftp_init(صحیح fd_اندر, صحیح fd_برآمد, u_int transfer_buflen, u_int عدد_درخواستیں,
    uint64_t حد_بندی_kbps)
{
	u_char type;
	ساخت sshbuf *پیغام;
	ساخت sftp_conn *ret;
	صحیح r;

	ret = xcalloc(1, حجم(*ret));
	ret->پیغام_id = 1;
	ret->fd_اندر = fd_اندر;
	ret->fd_برآمد = fd_برآمد;
	ret->download_buflen = ret->upload_buflen =
	    transfer_buflen ? transfer_buflen : DEFAULT_COPY_BUFLEN;
	ret->عدد_درخواستیں =
	    عدد_درخواستیں ? عدد_درخواستیں : DEFAULT_عدد_درخواستیں;
	ret->exts = 0;
	ret->حد_بندی_kbps = 0;

	اگر ((پیغام = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_u8(پیغام, SSH2_FXP_INIT)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, SSH2_FILEXFER_نسخہ)) != 0)
		fatal_fr(r, "parse");

	send_پیغام(ret, پیغام);

	get_پیغام_extended(ret, پیغام, 1);

	/* Expecting a VERSION reply */
	اگر ((r = sshbuf_get_u8(پیغام, &type)) != 0)
		fatal_fr(r, "parse type");
	اگر (type != SSH2_FXP_نسخہ) {
		error("Invalid packet back from SSH2_FXP_INIT (type %u)",
		    type);
		sshbuf_free(پیغام);
		آزاد(ret);
		واپس(تہی);
	}
	اگر ((r = sshbuf_get_u32(پیغام, &ret->نسخہ)) != 0)
		fatal_fr(r, "parse version");

	debug2("Remote version: %u", ret->نسخہ);

	/* Check for extensions */
	جب (sshbuf_len(پیغام) > 0) {
		حرف *name;
		u_char *قدر;
		سائز_t vlen;
		صحیح معلوم = 0;

		اگر ((r = sshbuf_get_cstring(پیغام, &name, تہی)) != 0 ||
		    (r = sshbuf_get_string(پیغام, &قدر, &vlen)) != 0)
			fatal_fr(r, "parse extension");
		اگر (strcmp(name, "posix-rename@openssh.com") == 0 &&
		    strcmp((حرف *)قدر, "1") == 0) {
			ret->exts |= SFTP_EXT_POSIX_RENAME;
			معلوم = 1;
		} ورنہ اگر (strcmp(name, "statvfs@openssh.com") == 0 &&
		    strcmp((حرف *)قدر, "2") == 0) {
			ret->exts |= SFTP_EXT_STATVFS;
			معلوم = 1;
		} ورنہ اگر (strcmp(name, "fstatvfs@openssh.com") == 0 &&
		    strcmp((حرف *)قدر, "2") == 0) {
			ret->exts |= SFTP_EXT_FSTATVFS;
			معلوم = 1;
		} ورنہ اگر (strcmp(name, "hardlink@openssh.com") == 0 &&
		    strcmp((حرف *)قدر, "1") == 0) {
			ret->exts |= SFTP_EXT_HARDLINK;
			معلوم = 1;
		} ورنہ اگر (strcmp(name, "fsync@openssh.com") == 0 &&
		    strcmp((حرف *)قدر, "1") == 0) {
			ret->exts |= SFTP_EXT_FSYNC;
			معلوم = 1;
		} ورنہ اگر (strcmp(name, "lsetstat@openssh.com") == 0 &&
		    strcmp((حرف *)قدر, "1") == 0) {
			ret->exts |= SFTP_EXT_LSETSTAT;
			معلوم = 1;
		} ورنہ اگر (strcmp(name, "limits@openssh.com") == 0 &&
		    strcmp((حرف *)قدر, "1") == 0) {
			ret->exts |= SFTP_EXT_LIMITS;
			معلوم = 1;
		} ورنہ اگر (strcmp(name, "expand-path@openssh.com") == 0 &&
		    strcmp((حرف *)قدر, "1") == 0) {
			ret->exts |= SFTP_EXT_راستہ_EXPAND;
			معلوم = 1;
		} ورنہ اگر (strcmp(name, "copy-data") == 0 &&
		    strcmp((حرف *)قدر, "1") == 0) {
			ret->exts |= SFTP_EXT_COPY_ڈیٹا;
			معلوم = 1;
		} ورنہ اگر (strcmp(name,
		    "users-groups-by-id@openssh.com") == 0 &&
		    strcmp((حرف *)قدر, "1") == 0) {
			ret->exts |= SFTP_EXT_GETUSERSGROUPS_BY_ID;
			معلوم = 1;
		}
		اگر (معلوم) {
			debug2("Server supports extension \"%s\" revision %s",
			    name, قدر);
		} ورنہ {
			debug2("Unrecognised server extension \"%s\"", name);
		}
		آزاد(name);
		آزاد(قدر);
	}

	sshbuf_free(پیغام);

	/* Query the server for its limits */
	اگر (ret->exts & SFTP_EXT_LIMITS) {
		ساخت sftp_limits limits;
		اگر (sftp_get_limits(ret, &limits) != 0)
			fatal_f("limits failed");

		/* If the caller did not specify, find a good value */
		اگر (transfer_buflen == 0) {
			ret->download_buflen = MINIMUM(limits.read_لمبائی,
			    SFTP_MAX_پیغام_لمبائی - 1024);
			ret->upload_buflen = MINIMUM(limits.write_لمبائی,
			    SFTP_MAX_پیغام_لمبائی - 1024);
			ret->download_buflen = زیادہ_سے_زیادہ(ret->download_buflen, 64);
			ret->upload_buflen = زیادہ_سے_زیادہ(ret->upload_buflen, 64);
			debug3("server upload/download buffer sizes "
			    "%llu / %llu; using %u / %u",
			    (غیرعلامتی طویل طویل)limits.write_لمبائی,
			    (غیرعلامتی طویل طویل)limits.read_لمبائی,
			    ret->upload_buflen, ret->download_buflen);
		}
	}

	/* Some filexfer v.0 servers don't support large packets */
	اگر (ret->نسخہ == 0) {
		ret->download_buflen = MINIMUM(ret->download_buflen, 20480);
		ret->upload_buflen = MINIMUM(ret->upload_buflen, 20480);
	}

	ret->حد_بندی_kbps = حد_بندی_kbps;
	اگر (ret->حد_بندی_kbps > 0) {
		bandwidth_حد_بندی_init(&ret->bwlimit_اندر, ret->حد_بندی_kbps,
		    ret->download_buflen);
		bandwidth_حد_بندی_init(&ret->bwlimit_برآمد, ret->حد_بندی_kbps,
		    ret->upload_buflen);
	}

	واپس ret;
}

خالی
sftp_free(ساخت sftp_conn *conn)
{
	اگر (conn == تہی)
		واپس;
	freezero(conn, حجم(*conn));
}

u_int
sftp_proto_نسخہ(ساخت sftp_conn *conn)
{
	واپس conn->نسخہ;
}

صحیح
sftp_get_limits(ساخت sftp_conn *conn, ساخت sftp_limits *limits)
{
	u_int id, پیغام_id;
	u_char type;
	ساخت sshbuf *پیغام;
	صحیح r;

	اگر ((conn->exts & SFTP_EXT_LIMITS) == 0) {
		error("Server does not support limits@openssh.com extension");
		واپس -1;
	}

	اگر ((پیغام = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");

	id = conn->پیغام_id++;
	اگر ((r = sshbuf_put_u8(پیغام, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, id)) != 0 ||
	    (r = sshbuf_put_cstring(پیغام, "limits@openssh.com")) != 0)
		fatal_fr(r, "compose");
	send_پیغام(conn, پیغام);
	debug3("Sent message limits@openssh.com I:%u", id);

	get_پیغام(conn, پیغام);

	اگر ((r = sshbuf_get_u8(پیغام, &type)) != 0 ||
	    (r = sshbuf_get_u32(پیغام, &پیغام_id)) != 0)
		fatal_fr(r, "parse");

	debug3("Received limits reply T:%u I:%u", type, پیغام_id);
	اگر (id != پیغام_id)
		fatal("ID mismatch (%u != %u)", پیغام_id, id);
	اگر (type != SSH2_FXP_EXTENDED_جواب) {
		debug_f("expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_جواب, type);
		/* Disable the limits extension */
		conn->exts &= ~SFTP_EXT_LIMITS;
		sshbuf_free(پیغام);
		واپس -1;
	}

	memset(limits, 0, حجم(*limits));
	اگر ((r = sshbuf_get_u64(پیغام, &limits->packet_لمبائی)) != 0 ||
	    (r = sshbuf_get_u64(پیغام, &limits->read_لمبائی)) != 0 ||
	    (r = sshbuf_get_u64(پیغام, &limits->write_لمبائی)) != 0 ||
	    (r = sshbuf_get_u64(پیغام, &limits->open_handles)) != 0)
		fatal_fr(r, "parse limits");

	sshbuf_free(پیغام);

	واپس 0;
}

صحیح
sftp_close(ساخت sftp_conn *conn, ثابت u_char *handle, u_int handle_len)
{
	u_int id, حالت_2;
	ساخت sshbuf *پیغام;
	صحیح r;

	اگر ((پیغام = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");

	id = conn->پیغام_id++;
	اگر ((r = sshbuf_put_u8(پیغام, SSH2_FXP_CLOSE)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, id)) != 0 ||
	    (r = sshbuf_put_string(پیغام, handle, handle_len)) != 0)
		fatal_fr(r, "parse");
	send_پیغام(conn, پیغام);
	debug3("Sent message SSH2_FXP_CLOSE I:%u", id);

	حالت_2 = get_حالت(conn, id);
	اگر (حالت_2 != SSH2_FX_OK)
		error("close remote: %s", fx2txt(حالت_2));

	sshbuf_free(پیغام);

	واپس حالت_2 == SSH2_FX_OK ? 0 : -1;
}


ساکن صحیح
sftp_lsreaddir(ساخت sftp_conn *conn, ثابت حرف *راستہ, صحیح print_flag,
    SFTP_DIRENT ***dir)
{
	ساخت sshbuf *پیغام;
	u_int گنتی, id, i, expected_id, ents = 0;
	سائز_t handle_len;
	u_char type, *handle;
	صحیح حالت_2 = SSH2_FX_FAILURE;
	صحیح r;

	اگر (dir)
		*dir = تہی;

	id = conn->پیغام_id++;

	اگر ((پیغام = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_u8(پیغام, SSH2_FXP_OPENDIR)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, id)) != 0 ||
	    (r = sshbuf_put_cstring(پیغام, راستہ)) != 0)
		fatal_fr(r, "compose OPENDIR");
	send_پیغام(conn, پیغام);

	handle = get_handle(conn, id, &handle_len,
	    "remote readdir(\"%s\")", راستہ);
	اگر (handle == تہی) {
		sshbuf_free(پیغام);
		واپس -1;
	}

	اگر (dir) {
		ents = 0;
		*dir = xcalloc(1, حجم(**dir));
		(*dir)[0] = تہی;
	}

	برائے (; !interrupted;) {
		id = expected_id = conn->پیغام_id++;

		debug3("Sending SSH2_FXP_READDIR I:%u", id);

		sshbuf_reset(پیغام);
		اگر ((r = sshbuf_put_u8(پیغام, SSH2_FXP_READDIR)) != 0 ||
		    (r = sshbuf_put_u32(پیغام, id)) != 0 ||
		    (r = sshbuf_put_string(پیغام, handle, handle_len)) != 0)
			fatal_fr(r, "compose READDIR");
		send_پیغام(conn, پیغام);

		sshbuf_reset(پیغام);

		get_پیغام(conn, پیغام);

		اگر ((r = sshbuf_get_u8(پیغام, &type)) != 0 ||
		    (r = sshbuf_get_u32(پیغام, &id)) != 0)
			fatal_fr(r, "parse");

		debug3("Received reply T:%u I:%u", type, id);

		اگر (id != expected_id)
			fatal("ID mismatch (%u != %u)", id, expected_id);

		اگر (type == SSH2_FXP_حالت) {
			u_int rstatus;

			اگر ((r = sshbuf_get_u32(پیغام, &rstatus)) != 0)
				fatal_fr(r, "parse status");
			debug3("Received SSH2_FXP_STATUS %d", rstatus);
			اگر (rstatus == SSH2_FX_EOF)
				توڑو;
			error("Couldn't read directory: %s", fx2txt(rstatus));
			جاؤ برآمد;
		} ورنہ اگر (type != SSH2_FXP_NAME)
			fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
			    SSH2_FXP_NAME, type);

		اگر ((r = sshbuf_get_u32(پیغام, &گنتی)) != 0)
			fatal_fr(r, "parse count");
		اگر (گنتی > SSHBUF_سائز_MAX)
			fatal_f("nonsensical number of entries");
		اگر (گنتی == 0)
			توڑو;
		debug3("Received %d SSH2_FXP_NAME responses", گنتی);
		برائے (i = 0; i < گنتی; i++) {
			حرف *filename, *longname;
			Attrib a;

			اگر ((r = sshbuf_get_cstring(پیغام, &filename,
			    تہی)) != 0 ||
			    (r = sshbuf_get_cstring(پیغام, &longname,
			    تہی)) != 0)
				fatal_fr(r, "parse filenames");
			اگر ((r = decode_attrib(پیغام, &a)) != 0) {
				error_fr(r, "couldn't decode attrib");
				آزاد(filename);
				آزاد(longname);
				جاؤ برآمد;
			}

			اگر (print_flag)
				mprintf("%s\n", longname);

			/*
			 * Directory entries should never contain '/'
			 * These can be used to attack recursive ops
			 * (e.g. send '../../../../etc/passwd')
			 */
			اگر (*filename == '\0' ||
			    strpbrk(filename, SFTP_DIRECTORY_CHARS) != تہی) {
				error("Server sent suspect path \"%s\" "
				    "during readdir of \"%s\"", filename, راستہ);
			} ورنہ اگر (dir) {
				*dir = xreallocarray(*dir, ents + 2, حجم(**dir));
				(*dir)[ents] = xcalloc(1, حجم(***dir));
				(*dir)[ents]->filename = xstrdup(filename);
				(*dir)[ents]->longname = xstrdup(longname);
				حافظہ_نقل(&(*dir)[ents]->a, &a, حجم(a));
				(*dir)[++ents] = تہی;
			}
			آزاد(filename);
			آزاد(longname);
		}
	}
	حالت_2 = 0;

 برآمد:
	sshbuf_free(پیغام);
	sftp_close(conn, handle, handle_len);
	آزاد(handle);

	اگر (حالت_2 != 0 && dir != تہی) {
		/* Don't return results on error */
		sftp_free_dirents(*dir);
		*dir = تہی;
	} ورنہ اگر (interrupted && dir != تہی && *dir != تہی) {
		/* Don't return partial matches on interrupt */
		sftp_free_dirents(*dir);
		*dir = xcalloc(1, حجم(**dir));
		**dir = تہی;
	}

	واپس حالت_2 == SSH2_FX_OK ? 0 : -1;
}

صحیح
sftp_readdir(ساخت sftp_conn *conn, ثابت حرف *راستہ, SFTP_DIRENT ***dir)
{
	واپس sftp_lsreaddir(conn, راستہ, 0, dir);
}

خالی sftp_free_dirents(SFTP_DIRENT **s)
{
	صحیح i;

	اگر (s == تہی)
		واپس;
	برائے (i = 0; s[i]; i++) {
		آزاد(s[i]->filename);
		آزاد(s[i]->longname);
		آزاد(s[i]);
	}
	آزاد(s);
}

صحیح
sftp_rm(ساخت sftp_conn *conn, ثابت حرف *راستہ)
{
	u_int حالت_2, id;

	debug2("Sending SSH2_FXP_REMOVE \"%s\"", راستہ);

	id = conn->پیغام_id++;
	send_string_request(conn, id, SSH2_FXP_REMOVE, راستہ, لڑی_لمبائی(راستہ));
	حالت_2 = get_حالت(conn, id);
	اگر (حالت_2 != SSH2_FX_OK)
		error("remote delete %s: %s", راستہ, fx2txt(حالت_2));
	واپس حالت_2 == SSH2_FX_OK ? 0 : -1;
}

صحیح
sftp_mkdir(ساخت sftp_conn *conn, ثابت حرف *راستہ, Attrib *a, صحیح print_flag)
{
	u_int حالت_2, id;

	debug2("Sending SSH2_FXP_MKDIR \"%s\"", راستہ);

	id = conn->پیغام_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_MKDIR, راستہ,
	    لڑی_لمبائی(راستہ), a);

	حالت_2 = get_حالت(conn, id);
	اگر (حالت_2 != SSH2_FX_OK && print_flag)
		error("remote mkdir \"%s\": %s", راستہ, fx2txt(حالت_2));

	واپس حالت_2 == SSH2_FX_OK ? 0 : -1;
}

صحیح
sftp_mkpath(ساخت sftp_conn *conn, ثابت حرف *راستہ, Attrib *a, صحیح print_flag)
{
	حرف *slash, *tmp_راستہ;
	صحیح مکمل;

	tmp_راستہ = xstrdup(راستہ);
	slash = tmp_راستہ;

	برائے (;;) {
		slash += strspn(slash, "/");
		slash += strcspn(slash, "/");

		مکمل = (*slash == '\0');
		*slash = '\0';

		اگر (!sftp_remote_is_dir(conn, tmp_راستہ)) {
			اگر (sftp_mkdir(conn, tmp_راستہ, a, print_flag) != 0) {
				آزاد(tmp_راستہ);
				واپس -1;
			}
		}

		اگر (مکمل)
			توڑو;

		*slash = '/';
	}

	آزاد(tmp_راستہ);
	واپس 0;
}

صحیح
sftp_rmdir(ساخت sftp_conn *conn, ثابت حرف *راستہ)
{
	u_int حالت_2, id;

	debug2("Sending SSH2_FXP_RMDIR \"%s\"", راستہ);

	id = conn->پیغام_id++;
	send_string_request(conn, id, SSH2_FXP_RMDIR, راستہ,
	    لڑی_لمبائی(راستہ));

	حالت_2 = get_حالت(conn, id);
	اگر (حالت_2 != SSH2_FX_OK)
		error("remote rmdir \"%s\": %s", راستہ, fx2txt(حالت_2));

	واپس حالت_2 == SSH2_FX_OK ? 0 : -1;
}

صحیح
sftp_stat(ساخت sftp_conn *conn, ثابت حرف *راستہ, صحیح quiet, Attrib *a)
{
	u_int id;

	debug2("Sending SSH2_FXP_STAT \"%s\"", راستہ);

	id = conn->پیغام_id++;

	send_string_request(conn, id,
	    conn->نسخہ == 0 ? SSH2_FXP_STAT_نسخہ_0 : SSH2_FXP_STAT,
	    راستہ, لڑی_لمبائی(راستہ));

	واپس get_decode_stat(conn, id, quiet, a);
}

صحیح
sftp_lstat(ساخت sftp_conn *conn, ثابت حرف *راستہ, صحیح quiet, Attrib *a)
{
	u_int id;

	اگر (conn->نسخہ == 0) {
		do_log2(quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_INFO,
		    "Server version does not support lstat operation");
		واپس sftp_stat(conn, راستہ, quiet, a);
	}

	id = conn->پیغام_id++;
	send_string_request(conn, id, SSH2_FXP_LSTAT, راستہ,
	    لڑی_لمبائی(راستہ));

	واپس get_decode_stat(conn, id, quiet, a);
}

#اگر_تعریف_شدہ notyet
صحیح
sftp_fstat(ساخت sftp_conn *conn, ثابت u_char *handle, u_int handle_len,
    صحیح quiet, Attrib *a)
{
	u_int id;

	debug2("Sending SSH2_FXP_FSTAT \"%s\"");

	id = conn->پیغام_id++;
	send_string_request(conn, id, SSH2_FXP_FSTAT, handle,
	    handle_len);

	واپس get_decode_stat(conn, id, quiet, a);
}
#اگر_ختم

صحیح
sftp_setstat(ساخت sftp_conn *conn, ثابت حرف *راستہ, Attrib *a)
{
	u_int حالت_2, id;

	debug2("Sending SSH2_FXP_SETSTAT \"%s\"", راستہ);

	id = conn->پیغام_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_SETSTAT, راستہ,
	    لڑی_لمبائی(راستہ), a);

	حالت_2 = get_حالت(conn, id);
	اگر (حالت_2 != SSH2_FX_OK)
		error("remote setstat \"%s\": %s", راستہ, fx2txt(حالت_2));

	واپس حالت_2 == SSH2_FX_OK ? 0 : -1;
}

صحیح
sftp_fsetstat(ساخت sftp_conn *conn, ثابت u_char *handle, u_int handle_len,
    Attrib *a)
{
	u_int حالت_2, id;

	debug2("Sending SSH2_FXP_FSETSTAT");

	id = conn->پیغام_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_FSETSTAT, handle,
	    handle_len, a);

	حالت_2 = get_حالت(conn, id);
	اگر (حالت_2 != SSH2_FX_OK)
		error("remote fsetstat: %s", fx2txt(حالت_2));

	واپس حالت_2 == SSH2_FX_OK ? 0 : -1;
}

/* Implements both the realpath and expand-path operations */
ساکن حرف *
sftp_realpath_expand(ساخت sftp_conn *conn, ثابت حرف *راستہ, صحیح expand)
{
	ساخت sshbuf *پیغام;
	u_int expected_id, گنتی, id;
	حرف *filename, *longname;
	Attrib a;
	u_char type;
	صحیح r;
	ثابت حرف *what = "SSH2_FXP_REALPATH";

	اگر (expand)
		what = "expand-path@openssh.com";
	اگر ((پیغام = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");

	expected_id = id = conn->پیغام_id++;
	اگر (expand) {
		debug2("Sending SSH2_FXP_EXTENDED(expand-path@openssh.com) "
		    "\"%s\"", راستہ);
		اگر ((r = sshbuf_put_u8(پیغام, SSH2_FXP_EXTENDED)) != 0 ||
		    (r = sshbuf_put_u32(پیغام, id)) != 0 ||
		    (r = sshbuf_put_cstring(پیغام,
		    "expand-path@openssh.com")) != 0 ||
		    (r = sshbuf_put_cstring(پیغام, راستہ)) != 0)
			fatal_fr(r, "compose %s", what);
		send_پیغام(conn, پیغام);
	} ورنہ {
		debug2("Sending SSH2_FXP_REALPATH \"%s\"", راستہ);
		send_string_request(conn, id, SSH2_FXP_REALPATH,
		    راستہ, لڑی_لمبائی(راستہ));
	}
	get_پیغام(conn, پیغام);
	اگر ((r = sshbuf_get_u8(پیغام, &type)) != 0 ||
	    (r = sshbuf_get_u32(پیغام, &id)) != 0)
		fatal_fr(r, "parse");

	اگر (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);

	اگر (type == SSH2_FXP_حالت) {
		u_int حالت_2;
		حرف *errmsg;

		اگر ((r = sshbuf_get_u32(پیغام, &حالت_2)) != 0 ||
		    (r = sshbuf_get_cstring(پیغام, &errmsg, تہی)) != 0)
			fatal_fr(r, "parse status");
		error("%s %s: %s", expand ? "expand" : "realpath",
		    راستہ, *errmsg == '\0' ? fx2txt(حالت_2) : errmsg);
		آزاد(errmsg);
		sshbuf_free(پیغام);
		واپس تہی;
	} ورنہ اگر (type != SSH2_FXP_NAME)
		fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
		    SSH2_FXP_NAME, type);

	اگر ((r = sshbuf_get_u32(پیغام, &گنتی)) != 0)
		fatal_fr(r, "parse count");
	اگر (گنتی != 1)
		fatal("Got multiple names (%d) from %s", گنتی, what);

	اگر ((r = sshbuf_get_cstring(پیغام, &filename, تہی)) != 0 ||
	    (r = sshbuf_get_cstring(پیغام, &longname, تہی)) != 0 ||
	    (r = decode_attrib(پیغام, &a)) != 0)
		fatal_fr(r, "parse filename/attrib");

	debug3("%s %s -> %s", what, راستہ, filename);

	آزاد(longname);

	sshbuf_free(پیغام);

	واپس(filename);
}

حرف *
sftp_realpath(ساخت sftp_conn *conn, ثابت حرف *راستہ)
{
	واپس sftp_realpath_expand(conn, راستہ, 0);
}

صحیح
sftp_can_expand_راستہ(ساخت sftp_conn *conn)
{
	واپس (conn->exts & SFTP_EXT_راستہ_EXPAND) != 0;
}

حرف *
sftp_expand_راستہ(ساخت sftp_conn *conn, ثابت حرف *راستہ)
{
	اگر (!sftp_can_expand_راستہ(conn)) {
		debug3_f("no server support, fallback to realpath");
		واپس sftp_realpath_expand(conn, راستہ, 0);
	}
	واپس sftp_realpath_expand(conn, راستہ, 1);
}

صحیح
sftp_copy(ساخت sftp_conn *conn, ثابت حرف *oldpath, ثابت حرف *newpath)
{
	Attrib junk, attr;
	ساخت sshbuf *پیغام;
	u_char *old_handle, *new_handle;
	u_int منوال, حالت_2, id;
	سائز_t old_handle_len, new_handle_len;
	صحیح r;

	/* Return if the extension is not supported */
	اگر ((conn->exts & SFTP_EXT_COPY_ڈیٹا) == 0) {
		error("Server does not support copy-data extension");
		واپس -1;
	}

	/* Make sure the file exists, and we can copy its perms */
	اگر (sftp_stat(conn, oldpath, 0, &attr) != 0)
		واپس -1;

	/* Do not preserve set[ug]id here, as we do not preserve ownership */
	اگر (attr.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		منوال = attr.perm & 0777;

		اگر (!S_ISREG(attr.perm)) {
			error("Cannot copy non-regular file: %s", oldpath);
			واپس -1;
		}
	} ورنہ {
		/* NB: The user's umask will apply to this */
		منوال = 0666;
	}

	/* Set up the new perms for the new file */
	attrib_clear(&attr);
	attr.perm = منوال;
	attr.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;

	اگر ((پیغام = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");

	attrib_clear(&junk); /* Send empty attributes */

	/* Open the old file for reading */
	id = conn->پیغام_id++;
	اگر ((r = sshbuf_put_u8(پیغام, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, id)) != 0 ||
	    (r = sshbuf_put_cstring(پیغام, oldpath)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, SSH2_FXF_READ)) != 0 ||
	    (r = encode_attrib(پیغام, &junk)) != 0)
		fatal_fr(r, "buffer error");
	send_پیغام(conn, پیغام);
	debug3("Sent message SSH2_FXP_OPEN I:%u P:%s", id, oldpath);

	sshbuf_reset(پیغام);

	old_handle = get_handle(conn, id, &old_handle_len,
	    "remote open(\"%s\")", oldpath);
	اگر (old_handle == تہی) {
		sshbuf_free(پیغام);
		واپس -1;
	}

	/* Open the new file for writing */
	id = conn->پیغام_id++;
	اگر ((r = sshbuf_put_u8(پیغام, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, id)) != 0 ||
	    (r = sshbuf_put_cstring(پیغام, newpath)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, SSH2_FXF_WRITE|SSH2_FXF_CREAT|
	    SSH2_FXF_TRUNC)) != 0 ||
	    (r = encode_attrib(پیغام, &attr)) != 0)
		fatal_fr(r, "buffer error");
	send_پیغام(conn, پیغام);
	debug3("Sent message SSH2_FXP_OPEN I:%u P:%s", id, newpath);

	sshbuf_reset(پیغام);

	new_handle = get_handle(conn, id, &new_handle_len,
	    "remote open(\"%s\")", newpath);
	اگر (new_handle == تہی) {
		sshbuf_free(پیغام);
		آزاد(old_handle);
		واپس -1;
	}

	/* Copy the file data */
	id = conn->پیغام_id++;
	اگر ((r = sshbuf_put_u8(پیغام, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, id)) != 0 ||
	    (r = sshbuf_put_cstring(پیغام, "copy-data")) != 0 ||
	    (r = sshbuf_put_string(پیغام, old_handle, old_handle_len)) != 0 ||
	    (r = sshbuf_put_u64(پیغام, 0)) != 0 ||
	    (r = sshbuf_put_u64(پیغام, 0)) != 0 ||
	    (r = sshbuf_put_string(پیغام, new_handle, new_handle_len)) != 0 ||
	    (r = sshbuf_put_u64(پیغام, 0)) != 0)
		fatal_fr(r, "buffer error");
	send_پیغام(conn, پیغام);
	debug3("Sent message copy-data \"%s\" 0 0 -> \"%s\" 0",
	       oldpath, newpath);

	حالت_2 = get_حالت(conn, id);
	اگر (حالت_2 != SSH2_FX_OK)
		error("Couldn't copy file \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(حالت_2));

	/* Clean up everything */
	sshbuf_free(پیغام);
	sftp_close(conn, old_handle, old_handle_len);
	sftp_close(conn, new_handle, new_handle_len);
	آزاد(old_handle);
	آزاد(new_handle);

	واپس حالت_2 == SSH2_FX_OK ? 0 : -1;
}

صحیح
sftp_rename(ساخت sftp_conn *conn, ثابت حرف *oldpath, ثابت حرف *newpath,
    صحیح force_legacy)
{
	ساخت sshbuf *پیغام;
	u_int حالت_2, id;
	صحیح r, use_ext = (conn->exts & SFTP_EXT_POSIX_RENAME) && !force_legacy;

	اگر ((پیغام = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");

	/* Send rename request */
	id = conn->پیغام_id++;
	اگر (use_ext) {
		debug2("Sending SSH2_FXP_EXTENDED(posix-rename@openssh.com) "
		    "\"%s\" to \"%s\"", oldpath, newpath);
		اگر ((r = sshbuf_put_u8(پیغام, SSH2_FXP_EXTENDED)) != 0 ||
		    (r = sshbuf_put_u32(پیغام, id)) != 0 ||
		    (r = sshbuf_put_cstring(پیغام,
		    "posix-rename@openssh.com")) != 0)
			fatal_fr(r, "compose posix-rename");
	} ورنہ {
		debug2("Sending SSH2_FXP_RENAME \"%s\" to \"%s\"",
		    oldpath, newpath);
		اگر ((r = sshbuf_put_u8(پیغام, SSH2_FXP_RENAME)) != 0 ||
		    (r = sshbuf_put_u32(پیغام, id)) != 0)
			fatal_fr(r, "compose rename");
	}
	اگر ((r = sshbuf_put_cstring(پیغام, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(پیغام, newpath)) != 0)
		fatal_fr(r, "compose paths");
	send_پیغام(conn, پیغام);
	debug3("Sent message %s \"%s\" -> \"%s\"",
	    use_ext ? "posix-rename@openssh.com" :
	    "SSH2_FXP_RENAME", oldpath, newpath);
	sshbuf_free(پیغام);

	حالت_2 = get_حالت(conn, id);
	اگر (حالت_2 != SSH2_FX_OK)
		error("remote rename \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(حالت_2));

	واپس حالت_2 == SSH2_FX_OK ? 0 : -1;
}

صحیح
sftp_hardlink(ساخت sftp_conn *conn, ثابت حرف *oldpath, ثابت حرف *newpath)
{
	ساخت sshbuf *پیغام;
	u_int حالت_2, id;
	صحیح r;

	اگر ((conn->exts & SFTP_EXT_HARDLINK) == 0) {
		error("Server does not support hardlink@openssh.com extension");
		واپس -1;
	}
	debug2("Sending SSH2_FXP_EXTENDED(hardlink@openssh.com) "
	    "\"%s\" to \"%s\"", oldpath, newpath);

	اگر ((پیغام = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");

	/* Send link request */
	id = conn->پیغام_id++;
	اگر ((r = sshbuf_put_u8(پیغام, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, id)) != 0 ||
	    (r = sshbuf_put_cstring(پیغام, "hardlink@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(پیغام, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(پیغام, newpath)) != 0)
		fatal_fr(r, "compose");
	send_پیغام(conn, پیغام);
	debug3("Sent message hardlink@openssh.com \"%s\" -> \"%s\"",
	    oldpath, newpath);
	sshbuf_free(پیغام);

	حالت_2 = get_حالت(conn, id);
	اگر (حالت_2 != SSH2_FX_OK)
		error("remote link \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(حالت_2));

	واپس حالت_2 == SSH2_FX_OK ? 0 : -1;
}

صحیح
sftp_symlink(ساخت sftp_conn *conn, ثابت حرف *oldpath, ثابت حرف *newpath)
{
	ساخت sshbuf *پیغام;
	u_int حالت_2, id;
	صحیح r;

	اگر (conn->نسخہ < 3) {
		error("This server does not support the symlink operation");
		واپس(SSH2_FX_OP_UNSUPPORTED);
	}
	debug2("Sending SSH2_FXP_SYMLINK \"%s\" to \"%s\"", oldpath, newpath);

	اگر ((پیغام = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");

	/* Send symlink request */
	id = conn->پیغام_id++;
	اگر ((r = sshbuf_put_u8(پیغام, SSH2_FXP_SYMLINK)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, id)) != 0 ||
	    (r = sshbuf_put_cstring(پیغام, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(پیغام, newpath)) != 0)
		fatal_fr(r, "compose");
	send_پیغام(conn, پیغام);
	debug3("Sent message SSH2_FXP_SYMLINK \"%s\" -> \"%s\"", oldpath,
	    newpath);
	sshbuf_free(پیغام);

	حالت_2 = get_حالت(conn, id);
	اگر (حالت_2 != SSH2_FX_OK)
		error("remote symlink file \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(حالت_2));

	واپس حالت_2 == SSH2_FX_OK ? 0 : -1;
}

صحیح
sftp_fsync(ساخت sftp_conn *conn, u_char *handle, u_int handle_len)
{
	ساخت sshbuf *پیغام;
	u_int حالت_2, id;
	صحیح r;

	/* Silently return if the extension is not supported */
	اگر ((conn->exts & SFTP_EXT_FSYNC) == 0)
		واپس -1;
	debug2("Sending SSH2_FXP_EXTENDED(fsync@openssh.com)");

	/* Send fsync request */
	اگر ((پیغام = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	id = conn->پیغام_id++;
	اگر ((r = sshbuf_put_u8(پیغام, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, id)) != 0 ||
	    (r = sshbuf_put_cstring(پیغام, "fsync@openssh.com")) != 0 ||
	    (r = sshbuf_put_string(پیغام, handle, handle_len)) != 0)
		fatal_fr(r, "compose");
	send_پیغام(conn, پیغام);
	debug3("Sent message fsync@openssh.com I:%u", id);
	sshbuf_free(پیغام);

	حالت_2 = get_حالت(conn, id);
	اگر (حالت_2 != SSH2_FX_OK)
		error("remote fsync: %s", fx2txt(حالت_2));

	واپس حالت_2 == SSH2_FX_OK ? 0 : -1;
}

#اگر_تعریف_شدہ notyet
حرف *
sftp_readlink(ساخت sftp_conn *conn, ثابت حرف *راستہ)
{
	ساخت sshbuf *پیغام;
	u_int expected_id, گنتی, id;
	حرف *filename, *longname;
	Attrib a;
	u_char type;
	صحیح r;

	debug2("Sending SSH2_FXP_READLINK \"%s\"", راستہ);

	expected_id = id = conn->پیغام_id++;
	send_string_request(conn, id, SSH2_FXP_READLINK, راستہ, لڑی_لمبائی(راستہ));

	اگر ((پیغام = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");

	get_پیغام(conn, پیغام);
	اگر ((r = sshbuf_get_u8(پیغام, &type)) != 0 ||
	    (r = sshbuf_get_u32(پیغام, &id)) != 0)
		fatal_fr(r, "parse");

	اگر (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);

	اگر (type == SSH2_FXP_حالت) {
		u_int حالت_2;

		اگر ((r = sshbuf_get_u32(پیغام, &حالت_2)) != 0)
			fatal_fr(r, "parse status");
		error("Couldn't readlink: %s", fx2txt(حالت_2));
		sshbuf_free(پیغام);
		واپس(تہی);
	} ورنہ اگر (type != SSH2_FXP_NAME)
		fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
		    SSH2_FXP_NAME, type);

	اگر ((r = sshbuf_get_u32(پیغام, &گنتی)) != 0)
		fatal_fr(r, "parse count");
	اگر (گنتی != 1)
		fatal("Got multiple names (%d) from SSH_FXP_READLINK", گنتی);

	اگر ((r = sshbuf_get_cstring(پیغام, &filename, تہی)) != 0 ||
	    (r = sshbuf_get_cstring(پیغام, &longname, تہی)) != 0 ||
	    (r = decode_attrib(پیغام, &a)) != 0)
		fatal_fr(r, "parse filenames/attrib");

	debug3("SSH_FXP_READLINK %s -> %s", راستہ, filename);

	آزاد(longname);

	sshbuf_free(پیغام);

	واپس filename;
}
#اگر_ختم

صحیح
sftp_statvfs(ساخت sftp_conn *conn, ثابت حرف *راستہ, ساخت sftp_statvfs *st,
    صحیح quiet)
{
	ساخت sshbuf *پیغام;
	u_int id;
	صحیح r;

	اگر ((conn->exts & SFTP_EXT_STATVFS) == 0) {
		error("Server does not support statvfs@openssh.com extension");
		واپس -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(statvfs@openssh.com) \"%s\"", راستہ);

	id = conn->پیغام_id++;

	اگر ((پیغام = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_u8(پیغام, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, id)) != 0 ||
	    (r = sshbuf_put_cstring(پیغام, "statvfs@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(پیغام, راستہ)) != 0)
		fatal_fr(r, "compose");
	send_پیغام(conn, پیغام);
	sshbuf_free(پیغام);

	واپس get_decode_statvfs(conn, st, id, quiet);
}

#اگر_تعریف_شدہ notyet
صحیح
sftp_fstatvfs(ساخت sftp_conn *conn, ثابت u_char *handle, u_int handle_len,
    ساخت sftp_statvfs *st, صحیح quiet)
{
	ساخت sshbuf *پیغام;
	u_int id;

	اگر ((conn->exts & SFTP_EXT_FSTATVFS) == 0) {
		error("Server does not support fstatvfs@openssh.com extension");
		واپس -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(fstatvfs@openssh.com)");

	id = conn->پیغام_id++;

	اگر ((پیغام = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_u8(پیغام, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, id)) != 0 ||
	    (r = sshbuf_put_cstring(پیغام, "fstatvfs@openssh.com")) != 0 ||
	    (r = sshbuf_put_string(پیغام, handle, handle_len)) != 0)
		fatal_fr(r, "compose");
	send_پیغام(conn, پیغام);
	sshbuf_free(پیغام);

	واپس get_decode_statvfs(conn, st, id, quiet);
}
#اگر_ختم

صحیح
sftp_lsetstat(ساخت sftp_conn *conn, ثابت حرف *راستہ, Attrib *a)
{
	ساخت sshbuf *پیغام;
	u_int حالت_2, id;
	صحیح r;

	اگر ((conn->exts & SFTP_EXT_LSETSTAT) == 0) {
		error("Server does not support lsetstat@openssh.com extension");
		واپس -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(lsetstat@openssh.com) \"%s\"", راستہ);

	id = conn->پیغام_id++;
	اگر ((پیغام = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_u8(پیغام, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, id)) != 0 ||
	    (r = sshbuf_put_cstring(پیغام, "lsetstat@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(پیغام, راستہ)) != 0 ||
	    (r = encode_attrib(پیغام, a)) != 0)
		fatal_fr(r, "compose");
	send_پیغام(conn, پیغام);
	sshbuf_free(پیغام);

	حالت_2 = get_حالت(conn, id);
	اگر (حالت_2 != SSH2_FX_OK)
		error("remote lsetstat \"%s\": %s", راستہ, fx2txt(حالت_2));

	واپس حالت_2 == SSH2_FX_OK ? 0 : -1;
}

ساکن خالی
send_read_request(ساخت sftp_conn *conn, u_int id, uint64_t انحراف,
    u_int len, ثابت u_char *handle, u_int handle_len)
{
	ساخت sshbuf *پیغام;
	صحیح r;

	اگر ((پیغام = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_u8(پیغام, SSH2_FXP_READ)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, id)) != 0 ||
	    (r = sshbuf_put_string(پیغام, handle, handle_len)) != 0 ||
	    (r = sshbuf_put_u64(پیغام, انحراف)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, len)) != 0)
		fatal_fr(r, "compose");
	send_پیغام(conn, پیغام);
	sshbuf_free(پیغام);
}

ساکن صحیح
send_open(ساخت sftp_conn *conn, ثابت حرف *راستہ, ثابت حرف *لیبل,
    u_int openmode, Attrib *a, u_char **handlep, سائز_t *handle_lenp)
{
	Attrib junk;
	u_char *handle;
	سائز_t handle_len;
	ساخت sshbuf *پیغام;
	صحیح r;
	u_int id;

	debug2("Sending SSH2_FXP_OPEN \"%s\"", راستہ);

	*handlep = تہی;
	*handle_lenp = 0;

	اگر (a == تہی) {
		attrib_clear(&junk); /* Send empty attributes */
		a = &junk;
	}
	/* Send open request */
	اگر ((پیغام = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	id = conn->پیغام_id++;
	اگر ((r = sshbuf_put_u8(پیغام, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, id)) != 0 ||
	    (r = sshbuf_put_cstring(پیغام, راستہ)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, openmode)) != 0 ||
	    (r = encode_attrib(پیغام, a)) != 0)
		fatal_fr(r, "compose %s open", لیبل);
	send_پیغام(conn, پیغام);
	sshbuf_free(پیغام);
	debug3("Sent %s message SSH2_FXP_OPEN I:%u P:%s M:0x%04x",
	    لیبل, id, راستہ, openmode);
	اگر ((handle = get_handle(conn, id, &handle_len,
	    "%s open \"%s\"", لیبل, راستہ)) == تہی)
		واپس -1;
	/* success */
	*handlep = handle;
	*handle_lenp = handle_len;
	واپس 0;
}

ساکن ثابت حرف *
پیش_رفت_meter_راستہ(ثابت حرف *راستہ)
{
	ثابت حرف *progresspath;

	اگر ((progresspath = strrchr(راستہ, '/')) == تہی)
		واپس راستہ;
	progresspath++;
	اگر (*progresspath == '\0')
		واپس راستہ;
	واپس progresspath;
}

صحیح
sftp_download(ساخت sftp_conn *conn, ثابت حرف *remote_راستہ,
    ثابت حرف *local_راستہ, Attrib *a, صحیح preserve_flag, صحیح resume_flag,
    صحیح fsync_flag, صحیح inplace_flag)
{
	ساخت sshbuf *پیغام;
	u_char *handle;
	صحیح local_fd = -1, write_error, نظر_آیا_zerolen = 0;
	صحیح read_error, write_errno, lmodified = 0, reordered = 0, r;
	uint64_t انحراف = 0, سائز, highwater = 0, maxack = 0;
	u_int منوال, id, buflen, عدد_req, max_req, حالت_2 = SSH2_FX_OK;
	off_t پیش_رفت_شمار;
	سائز_t handle_len;
	ساخت stat st;
	ساخت درخواستیں درخواستیں;
	ساخت request *req;
	u_char type;
	Attrib attr;

	debug2_f("download remote \"%s\" to local \"%s\"",
	    remote_راستہ, local_راستہ);

	TAILQ_INIT(&درخواستیں);

	اگر (a == تہی) {
		اگر (sftp_stat(conn, remote_راستہ, 0, &attr) != 0)
			واپس -1;
		a = &attr;
	}

	/* Do not preserve set[ug]id here, as we do not preserve ownership */
	اگر (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS)
		منوال = a->perm & 0777;
	ورنہ
		منوال = 0666;

	اگر ((a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) &&
	    (!S_ISREG(a->perm))) {
		error("download %s: not a regular file", remote_راستہ);
		واپس(-1);
	}

	اگر (a->flags & SSH2_FILEXFER_ATTR_سائز)
		سائز = a->سائز;
	ورنہ
		سائز = 0;

	buflen = conn->download_buflen;

	/* Send open request */
	اگر (send_open(conn, remote_راستہ, "remote", SSH2_FXF_READ, تہی,
	    &handle, &handle_len) != 0)
		واپس -1;

	local_fd = open(local_راستہ, O_WRONLY | O_CREAT |
	((resume_flag || inplace_flag) ? 0 : O_TRUNC), منوال | S_IWUSR);
	اگر (local_fd == -1) {
		error("open local \"%s\": %s", local_راستہ, strerror(errno));
		جاؤ fail;
	}
	اگر (resume_flag) {
		اگر (fstat(local_fd, &st) == -1) {
			error("stat local \"%s\": %s",
			    local_راستہ, strerror(errno));
			جاؤ fail;
		}
		اگر (st.st_size < 0) {
			error("\"%s\" has negative size", local_راستہ);
			جاؤ fail;
		}
		اگر ((uint64_t)st.st_size > سائز) {
			error("Unable to resume download of \"%s\": "
			    "local file is larger than remote", local_راستہ);
 fail:
			sftp_close(conn, handle, handle_len);
			آزاد(handle);
			اگر (local_fd != -1)
				close(local_fd);
			واپس -1;
		}
		انحراف = highwater = maxack = st.st_size;
	}

	/* Read from remote and write to local */
	write_error = read_error = write_errno = عدد_req = 0;
	max_req = 1;
	پیش_رفت_شمار = انحراف;

	اگر (showprogress && سائز != 0) {
		آغاز_پیش_رفت_meter(پیش_رفت_meter_راستہ(remote_راستہ),
		    سائز, &پیش_رفت_شمار);
	}

	اگر ((پیغام = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");

	جب (عدد_req > 0 || max_req > 0) {
		u_char *ڈیٹا;
		سائز_t len;

		/*
		 * Simulate EOF on interrupt: stop sending new requests and
		 * allow outstanding requests to drain gracefully
		 */
		اگر (interrupted) {
			اگر (عدد_req == 0) /* If we haven't started yet... */
				توڑو;
			max_req = 0;
		}

		/* Send some more requests */
		جب (عدد_req < max_req) {
			debug3("Request range %llu -> %llu (%d/%d)",
			    (غیرعلامتی طویل طویل)انحراف,
			    (غیرعلامتی طویل طویل)انحراف + buflen - 1,
			    عدد_req, max_req);
			req = request_قطار_میں_ڈالو(&درخواستیں, conn->پیغام_id++,
			    buflen, انحراف);
			انحراف += buflen;
			عدد_req++;
			send_read_request(conn, req->id, req->انحراف,
			    req->len, handle, handle_len);
		}

		sshbuf_reset(پیغام);
		get_پیغام(conn, پیغام);
		اگر ((r = sshbuf_get_u8(پیغام, &type)) != 0 ||
		    (r = sshbuf_get_u32(پیغام, &id)) != 0)
			fatal_fr(r, "parse");
		debug3("Received reply T:%u I:%u R:%d", type, id, max_req);

		/* Find the request in our queue */
		اگر ((req = request_ڈھونڈو(&درخواستیں, id)) == تہی)
			fatal("Unexpected reply %u", id);

		انتخاب (type) {
		حالت SSH2_FXP_حالت:
			اگر ((r = sshbuf_get_u32(پیغام, &حالت_2)) != 0)
				fatal_fr(r, "parse status");
			اگر (حالت_2 != SSH2_FX_EOF)
				read_error = 1;
			max_req = 0;
			TAILQ_REMOVE(&درخواستیں, req, tq);
			آزاد(req);
			عدد_req--;
			توڑو;
		حالت SSH2_FXP_ڈیٹا:
			اگر ((r = sshbuf_get_string(پیغام, &ڈیٹا, &len)) != 0)
				fatal_fr(r, "parse data");
			debug3("Received data %llu -> %llu",
			    (غیرعلامتی طویل طویل)req->انحراف,
			    (غیرعلامتی طویل طویل)req->انحراف + len - 1);
			اگر (len > req->len)
				fatal("Received more data than asked for "
				    "%zu > %zu", len, req->len);
			اگر (len == 0) {
				اگر (نظر_آیا_zerolen)
					fatal_f("server sent zero data length");
				نظر_آیا_zerolen = 1;
			}
			lmodified = 1;
			اگر ((lseek(local_fd, req->انحراف, SEEK_SET) == -1 ||
			    atomicio(vwrite, local_fd, ڈیٹا, len) != len) &&
			    !write_error) {
				write_errno = errno;
				write_error = 1;
				max_req = 0;
			} ورنہ {
				/*
				 * Track both the highest offset acknowledged
				 * and the highest *contiguous* offset
				 * acknowledged.
				 * We'll need the latter for ftruncate()ing
				 * interrupted transfers.
				 */
				اگر (maxack < req->انحراف + len)
					maxack = req->انحراف + len;
				اگر (!reordered && req->انحراف <= highwater)
					highwater = maxack;
				ورنہ اگر (!reordered && req->انحراف > highwater)
					reordered = 1;
			}
			پیش_رفت_شمار += len;
			آزاد(ڈیٹا);

			اگر (len == req->len) {
				TAILQ_REMOVE(&درخواستیں, req, tq);
				آزاد(req);
				عدد_req--;
			} ورنہ {
				/* Resend the request for the missing data */
				debug3("Short data block, re-requesting "
				    "%llu -> %llu (%2d)",
				    (غیرعلامتی طویل طویل)req->انحراف + len,
				    (غیرعلامتی طویل طویل)req->انحراف +
				    req->len - 1, عدد_req);
				req->id = conn->پیغام_id++;
				req->len -= len;
				req->انحراف += len;
				send_read_request(conn, req->id,
				    req->انحراف, req->len, handle, handle_len);
				/* Reduce the request size */
				اگر (len < buflen)
					buflen = زیادہ_سے_زیادہ(MIN_READ_سائز, len);
			}
			اگر (max_req > 0) { /* max_req = 0 iff EOF received */
				اگر (سائز > 0 && انحراف > سائز) {
					/* Only one request at a time
					 * after the expected EOF */
					debug3("Finish at %llu (%2d)",
					    (غیرعلامتی طویل طویل)انحراف,
					    عدد_req);
					max_req = 1;
				} ورنہ اگر (max_req < conn->عدد_درخواستیں) {
					++max_req;
				}
			}
			توڑو;
		طےشدہ:
			fatal("Expected SSH2_FXP_DATA(%u) packet, got %u",
			    SSH2_FXP_ڈیٹا, type);
		}
	}

	اگر (showprogress && سائز)
		stop_پیش_رفت_meter();

	/* Sanity check */
	اگر (TAILQ_FIRST(&درخواستیں) != تہی)
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
			    "server reordered requests", local_راستہ);
		}
		debug("truncating at %llu", (غیرعلامتی طویل طویل)highwater);
		اگر (ftruncate(local_fd, highwater) == -1)
			error("local ftruncate \"%s\": %s", local_راستہ,
			    strerror(errno));
	}
	اگر (read_error) {
		error("read remote \"%s\" : %s", remote_راستہ, fx2txt(حالت_2));
		حالت_2 = -1;
		sftp_close(conn, handle, handle_len);
	} ورنہ اگر (write_error) {
		error("write local \"%s\": %s", local_راستہ,
		    strerror(write_errno));
		حالت_2 = SSH2_FX_FAILURE;
		sftp_close(conn, handle, handle_len);
	} ورنہ {
		اگر (sftp_close(conn, handle, handle_len) != 0 || interrupted)
			حالت_2 = SSH2_FX_FAILURE;
		ورنہ
			حالت_2 = SSH2_FX_OK;
		/* Override umask and utimes if asked */
#اگر_تعریف_شدہ HAVE_FCHMOD
		اگر (preserve_flag && fchmod(local_fd, منوال) == -1)
#ورنہ
		اگر (preserve_flag && chmod(local_راستہ, منوال) == -1)
#اگر_ختم /* HAVE_FCHMOD */
			error("local chmod \"%s\": %s", local_راستہ,
			    strerror(errno));
		اگر (preserve_flag &&
		    (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME)) {
			ساخت timeval tv[2];
			tv[0].tv_sec = a->atime;
			tv[1].tv_sec = a->mtime;
			tv[0].tv_usec = tv[1].tv_usec = 0;
			اگر (utimes(local_راستہ, tv) == -1)
				error("local set times \"%s\": %s",
				    local_راستہ, strerror(errno));
		}
		اگر (resume_flag && !lmodified)
			logit("File \"%s\" was not modified", local_راستہ);
		ورنہ اگر (fsync_flag) {
			debug("syncing \"%s\"", local_راستہ);
			اگر (fsync(local_fd) == -1)
				error("local sync \"%s\": %s",
				    local_راستہ, strerror(errno));
		}
	}
	close(local_fd);
	sshbuf_free(پیغام);
	آزاد(handle);

	واپس حالت_2 == SSH2_FX_OK ? 0 : -1;
}

ساکن صحیح
download_dir_اندرونی(ساخت sftp_conn *conn, ثابت حرف *src, ثابت حرف *dst,
    صحیح گہرائی, Attrib *dirattrib, صحیح preserve_flag, صحیح print_flag,
    صحیح resume_flag, صحیح fsync_flag, صحیح follow_link_flag, صحیح inplace_flag)
{
	صحیح i, ret = 0;
	SFTP_DIRENT **dir_entries;
	حرف *filename, *new_src = تہی, *new_dst = تہی;
	منوال_t منوال = 0777, tmpmode = منوال;
	Attrib *a, ldirattrib, lsym;

	اگر (گہرائی >= MAX_DIR_گہرائی) {
		error("Maximum directory depth exceeded: %d levels", گہرائی);
		واپس -1;
	}

	debug2_f("download dir remote \"%s\" to local \"%s\"", src, dst);

	اگر (dirattrib == تہی) {
		اگر (sftp_stat(conn, src, 1, &ldirattrib) != 0) {
			error("stat remote \"%s\" directory failed", src);
			واپس -1;
		}
		dirattrib = &ldirattrib;
	}
	اگر (!S_ISDIR(dirattrib->perm)) {
		error("\"%s\" is not a directory", src);
		واپس -1;
	}
	اگر (print_flag && print_flag != SFTP_پیش_رفت_ONLY)
		mprintf("Retrieving %s\n", src);

	اگر (dirattrib->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		منوال = dirattrib->perm & 01777;
		tmpmode = منوال | (S_IWUSR|S_IXUSR);
	} ورنہ {
		debug("download remote \"%s\": server "
		    "did not send permissions", dst);
	}

	اگر (mkdir(dst, tmpmode) == -1 && errno != EEXIST) {
		error("mkdir %s: %s", dst, strerror(errno));
		واپس -1;
	}

	اگر (sftp_readdir(conn, src, &dir_entries) == -1) {
		error("remote readdir \"%s\" failed", src);
		واپس -1;
	}

	برائے (i = 0; dir_entries[i] != تہی && !interrupted; i++) {
		آزاد(new_dst);
		آزاد(new_src);

		filename = dir_entries[i]->filename;
		new_dst = sftp_راستہ_append(dst, filename);
		new_src = sftp_راستہ_append(src, filename);

		a = &dir_entries[i]->a;
		اگر (S_ISLNK(a->perm)) {
			اگر (!follow_link_flag) {
				logit("download \"%s\": not a regular file",
				    new_src);
				جاری;
			}
			/* Replace the stat contents with the symlink target */
			اگر (sftp_stat(conn, new_src, 1, &lsym) != 0) {
				logit("remote stat \"%s\" failed", new_src);
				ret = -1;
				جاری;
			}
			a = &lsym;
		}

		اگر (S_ISDIR(a->perm)) {
			اگر (strcmp(filename, ".") == 0 ||
			    strcmp(filename, "..") == 0)
				جاری;
			اگر (download_dir_اندرونی(conn, new_src, new_dst,
			    گہرائی + 1, a, preserve_flag,
			    print_flag, resume_flag,
			    fsync_flag, follow_link_flag, inplace_flag) == -1)
				ret = -1;
		} ورنہ اگر (S_ISREG(a->perm)) {
			اگر (sftp_download(conn, new_src, new_dst, a,
			    preserve_flag, resume_flag, fsync_flag,
			    inplace_flag) == -1) {
				error("Download of file %s to %s failed",
				    new_src, new_dst);
				ret = -1;
			}
		} ورنہ
			logit("download \"%s\": not a regular file", new_src);

	}
	آزاد(new_dst);
	آزاد(new_src);

	اگر (preserve_flag) {
		اگر (dirattrib->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
			ساخت timeval tv[2];
			tv[0].tv_sec = dirattrib->atime;
			tv[1].tv_sec = dirattrib->mtime;
			tv[0].tv_usec = tv[1].tv_usec = 0;
			اگر (utimes(dst, tv) == -1)
				error("local set times on \"%s\": %s",
				    dst, strerror(errno));
		} ورنہ
			debug("Server did not send times for directory "
			    "\"%s\"", dst);
	}

	اگر (منوال != tmpmode && chmod(dst, منوال) == -1)
		error("local chmod directory \"%s\": %s", dst,
		    strerror(errno));

	sftp_free_dirents(dir_entries);

	واپس ret;
}

صحیح
sftp_download_dir(ساخت sftp_conn *conn, ثابت حرف *src, ثابت حرف *dst,
    Attrib *dirattrib, صحیح preserve_flag, صحیح print_flag, صحیح resume_flag,
    صحیح fsync_flag, صحیح follow_link_flag, صحیح inplace_flag)
{
	حرف *src_canon;
	صحیح ret;

	اگر ((src_canon = sftp_realpath(conn, src)) == تہی) {
		error("download \"%s\": path canonicalization failed", src);
		واپس -1;
	}

	ret = download_dir_اندرونی(conn, src_canon, dst, 0,
	    dirattrib, preserve_flag, print_flag, resume_flag, fsync_flag,
	    follow_link_flag, inplace_flag);
	آزاد(src_canon);
	واپس ret;
}

صحیح
sftp_upload(ساخت sftp_conn *conn, ثابت حرف *local_راستہ,
    ثابت حرف *remote_راستہ, صحیح preserve_flag, صحیح resume,
    صحیح fsync_flag, صحیح inplace_flag)
{
	صحیح r, local_fd;
	u_int openmode, id, حالت_2 = SSH2_FX_OK, status2, reordered = 0;
	off_t انحراف, پیش_رفت_شمار;
	u_char type, *handle, *ڈیٹا;
	ساخت sshbuf *پیغام;
	ساخت stat sb;
	Attrib a, t, c;
	uint32_t startid, ackid;
	uint64_t highwater = 0, maxack = 0;
	ساخت request *ack = تہی;
	ساخت درخواستیں acks;
	سائز_t handle_len;

	debug2_f("upload local \"%s\" to remote \"%s\"",
	    local_راستہ, remote_راستہ);

	TAILQ_INIT(&acks);

	اگر ((local_fd = open(local_راستہ, O_RDONLY)) == -1) {
		error("open local \"%s\": %s", local_راستہ, strerror(errno));
		واپس(-1);
	}
	اگر (fstat(local_fd, &sb) == -1) {
		error("fstat local \"%s\": %s", local_راستہ, strerror(errno));
		close(local_fd);
		واپس(-1);
	}
	اگر (!S_ISREG(sb.st_mode)) {
		error("local \"%s\" is not a regular file", local_راستہ);
		close(local_fd);
		واپس(-1);
	}
	stat_مقصد_attrib(&sb, &a);

	a.flags &= ~SSH2_FILEXFER_ATTR_سائز;
	a.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a.perm &= 0777;
	اگر (!preserve_flag)
		a.flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;

	اگر (resume) {
		/* Get remote file size if it exists */
		اگر (sftp_stat(conn, remote_راستہ, 0, &c) != 0) {
			close(local_fd);
			واپس -1;
		}

		اگر ((off_t)c.سائز >= sb.st_size) {
			error("resume \"%s\": destination file "
			    "same size or larger", local_راستہ);
			close(local_fd);
			واپس -1;
		}

		اگر (lseek(local_fd, (off_t)c.سائز, SEEK_SET) == -1) {
			close(local_fd);
			واپس -1;
		}
		highwater = c.سائز;
	}

	openmode = SSH2_FXF_WRITE|SSH2_FXF_CREAT;
	اگر (resume)
		openmode |= SSH2_FXF_APPEND;
	ورنہ اگر (!inplace_flag)
		openmode |= SSH2_FXF_TRUNC;

	/* Send open request */
	اگر (send_open(conn, remote_راستہ, "dest", openmode, &a,
	    &handle, &handle_len) != 0) {
		close(local_fd);
		واپس -1;
	}

	id = conn->پیغام_id;
	startid = ackid = id + 1;
	ڈیٹا = xmalloc(conn->upload_buflen);

	/* Read from local and write to remote */
	انحراف = پیش_رفت_شمار = (resume ? c.سائز : 0);
	اگر (showprogress) {
		آغاز_پیش_رفت_meter(پیش_رفت_meter_راستہ(local_راستہ),
		    sb.st_size, &پیش_رفت_شمار);
	}

	اگر ((پیغام = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	برائے (;;) {
		صحیح len;

		/*
		 * Can't use atomicio here because it returns 0 on EOF,
		 * thus losing the last block of the file.
		 * Simulate an EOF on interrupt, allowing ACKs from the
		 * server to drain.
		 */
		اگر (interrupted || حالت_2 != SSH2_FX_OK)
			len = 0;
		ورنہ کرو
			len = اقرأ(local_fd, ڈیٹا, conn->upload_buflen);
		جب ((len == -1) &&
		    (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK));

		اگر (len == -1) {
			fatal("read local \"%s\": %s",
			    local_راستہ, strerror(errno));
		} ورنہ اگر (len != 0) {
			ack = request_قطار_میں_ڈالو(&acks, ++id, len, انحراف);
			sshbuf_reset(پیغام);
			اگر ((r = sshbuf_put_u8(پیغام, SSH2_FXP_WRITE)) != 0 ||
			    (r = sshbuf_put_u32(پیغام, ack->id)) != 0 ||
			    (r = sshbuf_put_string(پیغام, handle,
			    handle_len)) != 0 ||
			    (r = sshbuf_put_u64(پیغام, انحراف)) != 0 ||
			    (r = sshbuf_put_string(پیغام, ڈیٹا, len)) != 0)
				fatal_fr(r, "compose");
			send_پیغام(conn, پیغام);
			debug3("Sent message SSH2_FXP_WRITE I:%u O:%llu S:%u",
			    id, (غیرعلامتی طویل طویل)انحراف, len);
		} ورنہ اگر (TAILQ_FIRST(&acks) == تہی)
			توڑو;

		اگر (ack == تہی)
			fatal("Unexpected ACK %u", id);

		اگر (id == startid || len == 0 ||
		    id - ackid >= conn->عدد_درخواستیں) {
			u_int rid;

			sshbuf_reset(پیغام);
			get_پیغام(conn, پیغام);
			اگر ((r = sshbuf_get_u8(پیغام, &type)) != 0 ||
			    (r = sshbuf_get_u32(پیغام, &rid)) != 0)
				fatal_fr(r, "parse");

			اگر (type != SSH2_FXP_حالت)
				fatal("Expected SSH2_FXP_STATUS(%d) packet, "
				    "got %d", SSH2_FXP_حالت, type);

			اگر ((r = sshbuf_get_u32(پیغام, &status2)) != 0)
				fatal_fr(r, "parse status");
			debug3("SSH2_FXP_STATUS %u", status2);
			اگر (status2 != SSH2_FX_OK)
				حالت_2 = status2; /* remember errors */

			/* Find the request in our queue */
			اگر ((ack = request_ڈھونڈو(&acks, rid)) == تہی)
				fatal("Can't find request for ID %u", rid);
			TAILQ_REMOVE(&acks, ack, tq);
			debug3("In write loop, ack for %u %zu bytes at %lld",
			    ack->id, ack->len, (غیرعلامتی طویل طویل)ack->انحراف);
			++ackid;
			پیش_رفت_شمار += ack->len;
			/*
			 * Track both the highest offset acknowledged and the
			 * highest *contiguous* offset acknowledged.
			 * We'll need the latter for ftruncate()ing
			 * interrupted transfers.
			 */
			اگر (maxack < ack->انحراف + ack->len)
				maxack = ack->انحراف + ack->len;
			اگر (!reordered && ack->انحراف <= highwater)
				highwater = maxack;
			ورنہ اگر (!reordered && ack->انحراف > highwater) {
				debug3_f("server reordered ACKs");
				reordered = 1;
			}
			آزاد(ack);
		}
		انحراف += len;
		اگر (انحراف < 0)
			fatal_f("offset < 0");
	}
	sshbuf_free(پیغام);

	اگر (showprogress)
		stop_پیش_رفت_meter();
	آزاد(ڈیٹا);

	اگر (حالت_2 == SSH2_FX_OK && !interrupted) {
		/* we got everything */
		highwater = maxack;
	}
	اگر (حالت_2 != SSH2_FX_OK) {
		error("write remote \"%s\": %s", remote_راستہ, fx2txt(حالت_2));
		حالت_2 = SSH2_FX_FAILURE;
	}

	اگر (inplace_flag || (resume && (حالت_2 != SSH2_FX_OK || interrupted))) {
		debug("truncating at %llu", (غیرعلامتی طویل طویل)highwater);
		attrib_clear(&t);
		t.flags = SSH2_FILEXFER_ATTR_سائز;
		t.سائز = highwater;
		sftp_fsetstat(conn, handle, handle_len, &t);
	}

	اگر (close(local_fd) == -1) {
		error("close local \"%s\": %s", local_راستہ, strerror(errno));
		حالت_2 = SSH2_FX_FAILURE;
	}

	/* Override umask and utimes if asked */
	اگر (preserve_flag)
		sftp_fsetstat(conn, handle, handle_len, &a);

	اگر (fsync_flag)
		(خالی)sftp_fsync(conn, handle, handle_len);

	اگر (sftp_close(conn, handle, handle_len) != 0)
		حالت_2 = SSH2_FX_FAILURE;

	آزاد(handle);

	واپس حالت_2 == SSH2_FX_OK ? 0 : -1;
}

ساکن صحیح
upload_dir_اندرونی(ساخت sftp_conn *conn, ثابت حرف *src, ثابت حرف *dst,
    صحیح گہرائی, صحیح preserve_flag, صحیح print_flag, صحیح resume, صحیح fsync_flag,
    صحیح follow_link_flag, صحیح inplace_flag)
{
	صحیح created = 0, ret = 0;
	DIR *dirp;
	ساخت dirent *dp;
	حرف *filename, *new_src = تہی, *new_dst = تہی;
	ساخت stat sb;
	Attrib a, dirattrib;
	uint32_t saved_perm;

	debug2_f("upload local dir \"%s\" to remote \"%s\"", src, dst);

	اگر (گہرائی >= MAX_DIR_گہرائی) {
		error("Maximum directory depth exceeded: %d levels", گہرائی);
		واپس -1;
	}

	اگر (stat(src, &sb) == -1) {
		error("stat local \"%s\": %s", src, strerror(errno));
		واپس -1;
	}
	اگر (!S_ISDIR(sb.st_mode)) {
		error("\"%s\" is not a directory", src);
		واپس -1;
	}
	اگر (print_flag && print_flag != SFTP_پیش_رفت_ONLY)
		mprintf("Entering %s\n", src);

	stat_مقصد_attrib(&sb, &a);
	a.flags &= ~SSH2_FILEXFER_ATTR_سائز;
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
	ورنہ {
		اگر (sftp_stat(conn, dst, 0, &dirattrib) != 0)
			واپس -1;
		اگر (!S_ISDIR(dirattrib.perm)) {
			error("\"%s\" exists but is not a directory", dst);
			واپس -1;
		}
	}
	a.perm = saved_perm;

	اگر ((dirp = opendir(src)) == تہی) {
		error("local opendir \"%s\": %s", src, strerror(errno));
		واپس -1;
	}

	جب (((dp = readdir(dirp)) != تہی) && !interrupted) {
		اگر (dp->d_ino == 0)
			جاری;
		آزاد(new_dst);
		آزاد(new_src);
		filename = dp->d_name;
		new_dst = sftp_راستہ_append(dst, filename);
		new_src = sftp_راستہ_append(src, filename);

		اگر (strcmp(filename, ".") == 0 || strcmp(filename, "..") == 0)
			جاری;
		اگر (lstat(new_src, &sb) == -1) {
			logit("local lstat \"%s\": %s", filename,
			    strerror(errno));
			ret = -1;
			جاری;
		}
		اگر (S_ISLNK(sb.st_mode)) {
			اگر (!follow_link_flag) {
				logit("%s: not a regular file", filename);
				جاری;
			}
			/* Replace the stat contents with the symlink target */
			اگر (stat(new_src, &sb) == -1) {
				logit("local stat \"%s\": %s", filename,
				    strerror(errno));
				ret = -1;
				جاری;
			}
		}
		اگر (S_ISDIR(sb.st_mode)) {
			اگر (upload_dir_اندرونی(conn, new_src, new_dst,
			    گہرائی + 1, preserve_flag, print_flag, resume,
			    fsync_flag, follow_link_flag, inplace_flag) == -1)
				ret = -1;
		} ورنہ اگر (S_ISREG(sb.st_mode)) {
			اگر (sftp_upload(conn, new_src, new_dst,
			    preserve_flag, resume, fsync_flag,
			    inplace_flag) == -1) {
				error("upload \"%s\" to \"%s\" failed",
				    new_src, new_dst);
				ret = -1;
			}
		} ورنہ
			logit("%s: not a regular file", filename);
	}
	آزاد(new_dst);
	آزاد(new_src);

	اگر (created || preserve_flag)
		sftp_setstat(conn, dst, &a);

	(خالی) closedir(dirp);
	واپس ret;
}

صحیح
sftp_upload_dir(ساخت sftp_conn *conn, ثابت حرف *src, ثابت حرف *dst,
    صحیح preserve_flag, صحیح print_flag, صحیح resume, صحیح fsync_flag,
    صحیح follow_link_flag, صحیح inplace_flag)
{
	حرف *dst_canon;
	صحیح ret;

	اگر ((dst_canon = sftp_realpath(conn, dst)) == تہی) {
		error("upload \"%s\": path canonicalization failed", dst);
		واپس -1;
	}

	ret = upload_dir_اندرونی(conn, src, dst_canon, 0, preserve_flag,
	    print_flag, resume, fsync_flag, follow_link_flag, inplace_flag);

	آزاد(dst_canon);
	واپس ret;
}

ساکن خالی
handle_dest_replies(ساخت sftp_conn *مقصد, ثابت حرف *مقصد_راستہ, صحیح synchronous,
    u_int *nreqsp, u_int *write_errorp)
{
	ساخت sshbuf *پیغام;
	u_char type;
	u_int id, حالت_2;
	صحیح r;
	ساخت pollfd pfd;

	اگر ((پیغام = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");

	/* Try to eat replies from the upload side */
	جب (*nreqsp > 0) {
		debug3_f("%u outstanding replies", *nreqsp);
		اگر (!synchronous) {
			/* Bail out if no data is ready to be read */
			pfd.fd = مقصد->fd_اندر;
			pfd.events = POLLIN;
			اگر ((r = poll(&pfd, 1, 0)) == -1) {
				اگر (errno == EINTR)
					توڑو;
				fatal_f("poll: %s", strerror(errno));
			} ورنہ اگر (r == 0)
				توڑو; /* fd not ready */
		}
		sshbuf_reset(پیغام);
		get_پیغام(مقصد, پیغام);

		اگر ((r = sshbuf_get_u8(پیغام, &type)) != 0 ||
		    (r = sshbuf_get_u32(پیغام, &id)) != 0)
			fatal_fr(r, "dest parse");
		debug3("Received dest reply T:%u I:%u R:%u", type, id, *nreqsp);
		اگر (type != SSH2_FXP_حالت) {
			fatal_f("Expected SSH2_FXP_STATUS(%d) packet, got %d",
			    SSH2_FXP_حالت, type);
		}
		اگر ((r = sshbuf_get_u32(پیغام, &حالت_2)) != 0)
			fatal_fr(r, "parse dest status");
		debug3("dest SSH2_FXP_STATUS %u", حالت_2);
		اگر (حالت_2 != SSH2_FX_OK) {
			/* record first error */
			اگر (*write_errorp == 0)
				*write_errorp = حالت_2;
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
	sshbuf_free(پیغام);
}

صحیح
sftp_crossload(ساخت sftp_conn *from, ساخت sftp_conn *مقصد,
    ثابت حرف *from_راستہ, ثابت حرف *مقصد_راستہ,
    Attrib *a, صحیح preserve_flag)
{
	ساخت sshbuf *پیغام;
	صحیح write_error, read_error, r, نظر_آیا_zerolen = 0;
	uint64_t انحراف = 0, سائز;
	u_int id, buflen, عدد_req, max_req, حالت_2 = SSH2_FX_OK;
	u_int عدد_upload_req;
	off_t پیش_رفت_شمار;
	u_char *from_handle, *مقصد_handle;
	سائز_t from_handle_len, مقصد_handle_len;
	ساخت درخواستیں درخواستیں;
	ساخت request *req;
	u_char type;
	Attrib attr;

	debug2_f("crossload src \"%s\" to dst \"%s\"", from_راستہ, مقصد_راستہ);

	TAILQ_INIT(&درخواستیں);

	اگر (a == تہی) {
		اگر (sftp_stat(from, from_راستہ, 0, &attr) != 0)
			واپس -1;
		a = &attr;
	}

	اگر ((a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) &&
	    (!S_ISREG(a->perm))) {
		error("download \"%s\": not a regular file", from_راستہ);
		واپس(-1);
	}
	اگر (a->flags & SSH2_FILEXFER_ATTR_سائز)
		سائز = a->سائز;
	ورنہ
		سائز = 0;

	buflen = from->download_buflen;
	اگر (buflen > مقصد->upload_buflen)
		buflen = مقصد->upload_buflen;

	/* Send open request to read side */
	اگر (send_open(from, from_راستہ, "origin", SSH2_FXF_READ, تہی,
	    &from_handle, &from_handle_len) != 0)
		واپس -1;

	/* Send open request to write side */
	a->flags &= ~SSH2_FILEXFER_ATTR_سائز;
	a->flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a->perm &= 0777;
	اگر (!preserve_flag)
		a->flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;
	اگر (send_open(مقصد, مقصد_راستہ, "dest",
	    SSH2_FXF_WRITE|SSH2_FXF_CREAT|SSH2_FXF_TRUNC, a,
	    &مقصد_handle, &مقصد_handle_len) != 0) {
		sftp_close(from, from_handle, from_handle_len);
		واپس -1;
	}

	/* Read from remote "from" and write to remote "to" */
	انحراف = 0;
	write_error = read_error = عدد_req = عدد_upload_req = 0;
	max_req = 1;
	پیش_رفت_شمار = 0;

	اگر (showprogress && سائز != 0) {
		آغاز_پیش_رفت_meter(پیش_رفت_meter_راستہ(from_راستہ),
		    سائز, &پیش_رفت_شمار);
	}
	اگر ((پیغام = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	جب (عدد_req > 0 || max_req > 0) {
		u_char *ڈیٹا;
		سائز_t len;

		/*
		 * Simulate EOF on interrupt: stop sending new requests and
		 * allow outstanding requests to drain gracefully
		 */
		اگر (interrupted) {
			اگر (عدد_req == 0) /* If we haven't started yet... */
				توڑو;
			max_req = 0;
		}

		/* Send some more requests */
		جب (عدد_req < max_req) {
			debug3("Request range %llu -> %llu (%d/%d)",
			    (غیرعلامتی طویل طویل)انحراف,
			    (غیرعلامتی طویل طویل)انحراف + buflen - 1,
			    عدد_req, max_req);
			req = request_قطار_میں_ڈالو(&درخواستیں, from->پیغام_id++,
			    buflen, انحراف);
			انحراف += buflen;
			عدد_req++;
			send_read_request(from, req->id, req->انحراف,
			    req->len, from_handle, from_handle_len);
		}

		/* Try to eat replies from the upload side (nonblocking) */
		handle_dest_replies(مقصد, مقصد_راستہ, 0,
		    &عدد_upload_req, &write_error);

		sshbuf_reset(پیغام);
		get_پیغام(from, پیغام);
		اگر ((r = sshbuf_get_u8(پیغام, &type)) != 0 ||
		    (r = sshbuf_get_u32(پیغام, &id)) != 0)
			fatal_fr(r, "parse");
		debug3("Received origin reply T:%u I:%u R:%d",
		    type, id, max_req);

		/* Find the request in our queue */
		اگر ((req = request_ڈھونڈو(&درخواستیں, id)) == تہی)
			fatal("Unexpected reply %u", id);

		انتخاب (type) {
		حالت SSH2_FXP_حالت:
			اگر ((r = sshbuf_get_u32(پیغام, &حالت_2)) != 0)
				fatal_fr(r, "parse status");
			اگر (حالت_2 != SSH2_FX_EOF)
				read_error = 1;
			max_req = 0;
			TAILQ_REMOVE(&درخواستیں, req, tq);
			آزاد(req);
			عدد_req--;
			توڑو;
		حالت SSH2_FXP_ڈیٹا:
			اگر ((r = sshbuf_get_string(پیغام, &ڈیٹا, &len)) != 0)
				fatal_fr(r, "parse data");
			debug3("Received data %llu -> %llu",
			    (غیرعلامتی طویل طویل)req->انحراف,
			    (غیرعلامتی طویل طویل)req->انحراف + len - 1);
			اگر (len > req->len)
				fatal("Received more data than asked for "
				    "%zu > %zu", len, req->len);
			اگر (len == 0) {
				اگر (نظر_آیا_zerolen)
					fatal_f("server sent zero data length");
				نظر_آیا_zerolen = 1;
			}

			/* Write this chunk out to the destination */
			sshbuf_reset(پیغام);
			اگر ((r = sshbuf_put_u8(پیغام, SSH2_FXP_WRITE)) != 0 ||
			    (r = sshbuf_put_u32(پیغام, مقصد->پیغام_id++)) != 0 ||
			    (r = sshbuf_put_string(پیغام, مقصد_handle,
			    مقصد_handle_len)) != 0 ||
			    (r = sshbuf_put_u64(پیغام, req->انحراف)) != 0 ||
			    (r = sshbuf_put_string(پیغام, ڈیٹا, len)) != 0)
				fatal_fr(r, "compose write");
			send_پیغام(مقصد, پیغام);
			debug3("Sent message SSH2_FXP_WRITE I:%u O:%llu S:%zu",
			    id, (غیرعلامتی طویل طویل)انحراف, len);
			عدد_upload_req++;
			پیش_رفت_شمار += len;
			آزاد(ڈیٹا);

			اگر (len == req->len) {
				TAILQ_REMOVE(&درخواستیں, req, tq);
				آزاد(req);
				عدد_req--;
			} ورنہ {
				/* Resend the request for the missing data */
				debug3("Short data block, re-requesting "
				    "%llu -> %llu (%2d)",
				    (غیرعلامتی طویل طویل)req->انحراف + len,
				    (غیرعلامتی طویل طویل)req->انحراف +
				    req->len - 1, عدد_req);
				req->id = from->پیغام_id++;
				req->len -= len;
				req->انحراف += len;
				send_read_request(from, req->id,
				    req->انحراف, req->len,
				    from_handle, from_handle_len);
				/* Reduce the request size */
				اگر (len < buflen)
					buflen = زیادہ_سے_زیادہ(MIN_READ_سائز, len);
			}
			اگر (max_req > 0) { /* max_req = 0 iff EOF received */
				اگر (سائز > 0 && انحراف > سائز) {
					/* Only one request at a time
					 * after the expected EOF */
					debug3("Finish at %llu (%2d)",
					    (غیرعلامتی طویل طویل)انحراف,
					    عدد_req);
					max_req = 1;
				} ورنہ اگر (max_req < from->عدد_درخواستیں) {
					++max_req;
				}
			}
			توڑو;
		طےشدہ:
			fatal("Expected SSH2_FXP_DATA(%u) packet, got %u",
			    SSH2_FXP_ڈیٹا, type);
		}
	}

	اگر (showprogress && سائز)
		stop_پیش_رفت_meter();

	/* Drain replies from the server (blocking) */
	debug3_f("waiting for %u replies from destination", عدد_upload_req);
	handle_dest_replies(مقصد, مقصد_راستہ, 1, &عدد_upload_req, &write_error);

	/* Sanity check */
	اگر (TAILQ_FIRST(&درخواستیں) != تہی)
		fatal("Transfer complete, but requests still in queue");
	/* Truncate at 0 length on interrupt or error to avoid holes at dest */
	اگر (read_error || write_error || interrupted) {
		debug("truncating \"%s\" at 0", مقصد_راستہ);
		sftp_close(مقصد, مقصد_handle, مقصد_handle_len);
		آزاد(مقصد_handle);
		اگر (send_open(مقصد, مقصد_راستہ, "dest",
		    SSH2_FXF_WRITE|SSH2_FXF_CREAT|SSH2_FXF_TRUNC, a,
		    &مقصد_handle, &مقصد_handle_len) != 0) {
			error("dest truncate \"%s\" failed", مقصد_راستہ);
			مقصد_handle = تہی;
		}
	}
	اگر (read_error) {
		error("read origin \"%s\": %s", from_راستہ, fx2txt(حالت_2));
		حالت_2 = -1;
		sftp_close(from, from_handle, from_handle_len);
		اگر (مقصد_handle != تہی)
			sftp_close(مقصد, مقصد_handle, مقصد_handle_len);
	} ورنہ اگر (write_error) {
		error("write dest \"%s\": %s", مقصد_راستہ, fx2txt(write_error));
		حالت_2 = SSH2_FX_FAILURE;
		sftp_close(from, from_handle, from_handle_len);
		اگر (مقصد_handle != تہی)
			sftp_close(مقصد, مقصد_handle, مقصد_handle_len);
	} ورنہ {
		اگر (sftp_close(from, from_handle, from_handle_len) != 0 ||
		    interrupted)
			حالت_2 = -1;
		ورنہ
			حالت_2 = SSH2_FX_OK;
		اگر (مقصد_handle != تہی) {
			/* Need to resend utimes after write */
			اگر (preserve_flag)
				sftp_fsetstat(مقصد, مقصد_handle, مقصد_handle_len, a);
			sftp_close(مقصد, مقصد_handle, مقصد_handle_len);
		}
	}
	sshbuf_free(پیغام);
	آزاد(from_handle);
	آزاد(مقصد_handle);

	واپس حالت_2 == SSH2_FX_OK ? 0 : -1;
}

ساکن صحیح
crossload_dir_اندرونی(ساخت sftp_conn *from, ساخت sftp_conn *مقصد,
    ثابت حرف *from_راستہ, ثابت حرف *مقصد_راستہ,
    صحیح گہرائی, Attrib *dirattrib, صحیح preserve_flag, صحیح print_flag,
    صحیح follow_link_flag)
{
	صحیح i, ret = 0, created = 0;
	SFTP_DIRENT **dir_entries;
	حرف *filename, *new_from_راستہ = تہی, *new_مقصد_راستہ = تہی;
	منوال_t منوال = 0777;
	Attrib *a, curdir, ldirattrib, newdir, lsym;

	debug2_f("crossload dir src \"%s\" to dst \"%s\"", from_راستہ, مقصد_راستہ);

	اگر (گہرائی >= MAX_DIR_گہرائی) {
		error("Maximum directory depth exceeded: %d levels", گہرائی);
		واپس -1;
	}

	اگر (dirattrib == تہی) {
		اگر (sftp_stat(from, from_راستہ, 1, &ldirattrib) != 0) {
			error("stat remote \"%s\" failed", from_راستہ);
			واپس -1;
		}
		dirattrib = &ldirattrib;
	}
	اگر (!S_ISDIR(dirattrib->perm)) {
		error("\"%s\" is not a directory", from_راستہ);
		واپس -1;
	}
	اگر (print_flag && print_flag != SFTP_پیش_رفت_ONLY)
		mprintf("Retrieving %s\n", from_راستہ);

	curdir = *dirattrib; /* dirattrib will be clobbered */
	curdir.flags &= ~SSH2_FILEXFER_ATTR_سائز;
	curdir.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	اگر ((curdir.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) == 0) {
		debug("Origin did not send permissions for "
		    "directory \"%s\"", مقصد_راستہ);
		curdir.perm = S_IWUSR|S_IXUSR;
		curdir.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
	}
	/* We need to be able to write to the directory while we transfer it */
	منوال = curdir.perm & 01777;
	curdir.perm = منوال | (S_IWUSR|S_IXUSR);

	/*
	 * sftp lacks a portable status value to match errno EEXIST,
	 * so if we get a failure back then we must check whether
	 * the path already existed and is a directory.  Ensure we can
	 * write to the directory we create for the duration of the transfer.
	 */
	اگر (sftp_mkdir(مقصد, مقصد_راستہ, &curdir, 0) == 0)
		created = 1;
	ورنہ {
		اگر (sftp_stat(مقصد, مقصد_راستہ, 0, &newdir) != 0)
			واپس -1;
		اگر (!S_ISDIR(newdir.perm)) {
			error("\"%s\" exists but is not a directory", مقصد_راستہ);
			واپس -1;
		}
	}
	curdir.perm = منوال;

	اگر (sftp_readdir(from, from_راستہ, &dir_entries) == -1) {
		error("origin readdir \"%s\" failed", from_راستہ);
		واپس -1;
	}

	برائے (i = 0; dir_entries[i] != تہی && !interrupted; i++) {
		آزاد(new_from_راستہ);
		آزاد(new_مقصد_راستہ);

		filename = dir_entries[i]->filename;
		new_from_راستہ = sftp_راستہ_append(from_راستہ, filename);
		new_مقصد_راستہ = sftp_راستہ_append(مقصد_راستہ, filename);

		a = &dir_entries[i]->a;
		اگر (S_ISLNK(a->perm)) {
			اگر (!follow_link_flag) {
				logit("%s: not a regular file", filename);
				جاری;
			}
			/* Replace the stat contents with the symlink target */
			اگر (sftp_stat(from, new_from_راستہ, 1, &lsym) != 0) {
				logit("remote stat \"%s\" failed",
				    new_from_راستہ);
				ret = -1;
				جاری;
			}
			a = &lsym;
		}
		اگر (S_ISDIR(a->perm)) {
			اگر (strcmp(filename, ".") == 0 ||
			    strcmp(filename, "..") == 0)
				جاری;
			اگر (crossload_dir_اندرونی(from, مقصد,
			    new_from_راستہ, new_مقصد_راستہ,
			    گہرائی + 1, a, preserve_flag,
			    print_flag, follow_link_flag) == -1)
				ret = -1;
		} ورنہ اگر (S_ISREG(a->perm)) {
			اگر (sftp_crossload(from, مقصد, new_from_راستہ,
			    new_مقصد_راستہ, a, preserve_flag) == -1) {
				error("crossload \"%s\" to \"%s\" failed",
				    new_from_راستہ, new_مقصد_راستہ);
				ret = -1;
			}
		} ورنہ {
			logit("origin \"%s\": not a regular file",
			    new_from_راستہ);
		}
	}
	آزاد(new_مقصد_راستہ);
	آزاد(new_from_راستہ);

	اگر (created || preserve_flag)
		sftp_setstat(مقصد, مقصد_راستہ, &curdir);

	sftp_free_dirents(dir_entries);

	واپس ret;
}

صحیح
sftp_crossload_dir(ساخت sftp_conn *from, ساخت sftp_conn *مقصد,
    ثابت حرف *from_راستہ, ثابت حرف *مقصد_راستہ,
    Attrib *dirattrib, صحیح preserve_flag, صحیح print_flag, صحیح follow_link_flag)
{
	حرف *from_راستہ_canon;
	صحیح ret;

	اگر ((from_راستہ_canon = sftp_realpath(from, from_راستہ)) == تہی) {
		error("crossload \"%s\": path canonicalization failed",
		    from_راستہ);
		واپس -1;
	}

	ret = crossload_dir_اندرونی(from, مقصد, from_راستہ_canon, مقصد_راستہ, 0,
	    dirattrib, preserve_flag, print_flag, follow_link_flag);
	آزاد(from_راستہ_canon);
	واپس ret;
}

صحیح
sftp_can_get_users_groups_by_id(ساخت sftp_conn *conn)
{
	واپس (conn->exts & SFTP_EXT_GETUSERSGROUPS_BY_ID) != 0;
}

صحیح
sftp_get_users_groups_by_id(ساخت sftp_conn *conn,
    ثابت u_int *uids, u_int nuids,
    ثابت u_int *gids, u_int ngids,
    حرف ***usernamesp, حرف ***groupnamesp)
{
	ساخت sshbuf *پیغام, *uidbuf, *gidbuf;
	u_int i, expected_id, id;
	حرف *name, **usernames = تہی, **groupnames = تہی;
	u_char type;
	صحیح r;

	*usernamesp = *groupnamesp = تہی;
	اگر (!sftp_can_get_users_groups_by_id(conn))
		واپس SSH_ERR_FEATURE_UNSUPPORTED;

	اگر ((پیغام = sshbuf_new()) == تہی ||
	    (uidbuf = sshbuf_new()) == تہی ||
	    (gidbuf = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	expected_id = id = conn->پیغام_id++;
	debug2("Sending SSH2_FXP_EXTENDED(users-groups-by-id@openssh.com)");
	برائے (i = 0; i < nuids; i++) {
		اگر ((r = sshbuf_put_u32(uidbuf, uids[i])) != 0)
			fatal_fr(r, "compose uids");
	}
	برائے (i = 0; i < ngids; i++) {
		اگر ((r = sshbuf_put_u32(gidbuf, gids[i])) != 0)
			fatal_fr(r, "compose gids");
	}
	اگر ((r = sshbuf_put_u8(پیغام, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, id)) != 0 ||
	    (r = sshbuf_put_cstring(پیغام,
	    "users-groups-by-id@openssh.com")) != 0 ||
	    (r = sshbuf_put_stringb(پیغام, uidbuf)) != 0 ||
	    (r = sshbuf_put_stringb(پیغام, gidbuf)) != 0)
		fatal_fr(r, "compose");
	send_پیغام(conn, پیغام);
	get_پیغام(conn, پیغام);
	اگر ((r = sshbuf_get_u8(پیغام, &type)) != 0 ||
	    (r = sshbuf_get_u32(پیغام, &id)) != 0)
		fatal_fr(r, "parse");
	اگر (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	اگر (type == SSH2_FXP_حالت) {
		u_int حالت_2;
		حرف *errmsg;

		اگر ((r = sshbuf_get_u32(پیغام, &حالت_2)) != 0 ||
		    (r = sshbuf_get_cstring(پیغام, &errmsg, تہی)) != 0)
			fatal_fr(r, "parse status");
		error("users-groups-by-id %s",
		    *errmsg == '\0' ? fx2txt(حالت_2) : errmsg);
		آزاد(errmsg);
		sshbuf_free(پیغام);
		sshbuf_free(uidbuf);
		sshbuf_free(gidbuf);
		واپس -1;
	} ورنہ اگر (type != SSH2_FXP_EXTENDED_جواب)
		fatal("Expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_جواب, type);

	/* reuse */
	sshbuf_free(uidbuf);
	sshbuf_free(gidbuf);
	uidbuf = gidbuf = تہی;
	اگر ((r = sshbuf_froms(پیغام, &uidbuf)) != 0 ||
	    (r = sshbuf_froms(پیغام, &gidbuf)) != 0)
		fatal_fr(r, "parse response");
	اگر (nuids > 0) {
		usernames = xcalloc(nuids, حجم(*usernames));
		برائے (i = 0; i < nuids; i++) {
			اگر ((r = sshbuf_get_cstring(uidbuf, &name, تہی)) != 0)
				fatal_fr(r, "parse user name");
			/* Handle unresolved names */
			اگر (*name == '\0') {
				آزاد(name);
				name = تہی;
			}
			usernames[i] = name;
		}
	}
	اگر (ngids > 0) {
		groupnames = xcalloc(ngids, حجم(*groupnames));
		برائے (i = 0; i < ngids; i++) {
			اگر ((r = sshbuf_get_cstring(gidbuf, &name, تہی)) != 0)
				fatal_fr(r, "parse user name");
			/* Handle unresolved names */
			اگر (*name == '\0') {
				آزاد(name);
				name = تہی;
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
	sshbuf_free(پیغام);
	/* success */
	*usernamesp = usernames;
	*groupnamesp = groupnames;
	واپس 0;
}

حرف *
sftp_راستہ_append(ثابت حرف *p1, ثابت حرف *p2)
{
	حرف *ret;
	سائز_t len = لڑی_لمبائی(p1) + لڑی_لمبائی(p2) + 2;

	ret = xmalloc(len);
	strlcpy(ret, p1, len);
	اگر (p1[0] != '\0' && p1[لڑی_لمبائی(p1) - 1] != '/')
		strlcat(ret, "/", len);
	strlcat(ret, p2, len);

	واپس(ret);
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
	اگر (p && !راستہ_absolute(p)) {
		abs_str = sftp_راستہ_append(pwd, p);
		آزاد(p);
		واپس(abs_str);
	} ورنہ
		واپس(p);
}

صحیح
sftp_remote_is_dir(ساخت sftp_conn *conn, ثابت حرف *راستہ)
{
	Attrib a;

	/* XXX: report errors? */
	اگر (sftp_stat(conn, راستہ, 1, &a) != 0)
		واپس(0);
	اگر (!(a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS))
		واپس(0);
	واپس S_ISDIR(a.perm);
}


/* Check whether path returned from glob(..., GLOB_MARK, ...) is a directory */
صحیح
sftp_globpath_is_dir(ثابت حرف *pathname)
{
	سائز_t l = لڑی_لمبائی(pathname);

	واپس l > 0 && pathname[l - 1] == '/';
}

