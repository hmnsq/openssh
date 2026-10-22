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
#تعریف_کرو DEFAULT_COPY_BUFLEN	32768

/* Default number of concurrent xfer requests (fix sftp.1 scp.1 if changed) */
#تعریف_کرو DEFAULT_عدد_بینتیاں	64

/* Minimum amount of data to read at a time */
#تعریف_کرو MIN_READ_ناپ	512

/* Maximum depth to descend in directory trees */
#تعریف_کرو MAX_DIR_ڈونگھائی 64

/* Directory separator characters */
#جے_تعریف_شدہ HAVE_CYGWIN
# define SFTP_DIRECTORY_CHARS      "/\\"
#وإلا /* HAVE_CYGWIN */
# define SFTP_DIRECTORY_CHARS      "/"
#جے_انت /* HAVE_CYGWIN */

بنية sftp_conn {
	صحيح fd_وچ;
	صحيح fd_باہرلا;
	u_int download_buflen;
	u_int upload_buflen;
	u_int عدد_بینتیاں;
	u_int نسخہ;
	u_int پیغام_id;
#تعریف_کرو SFTP_EXT_POSIX_RENAME		0x00000001
#تعریف_کرو SFTP_EXT_STATVFS		0x00000002
#تعریف_کرو SFTP_EXT_FSTATVFS		0x00000004
#تعریف_کرو SFTP_EXT_HARDLINK		0x00000008
#تعریف_کرو SFTP_EXT_FSYNC			0x00000010
#تعریف_کرو SFTP_EXT_LSETSTAT		0x00000020
#تعریف_کرو SFTP_EXT_LIMITS			0x00000040
#تعریف_کرو SFTP_EXT_رستہ_EXPAND		0x00000080
#تعریف_کرو SFTP_EXT_COPY_انکڑے		0x00000100
#تعریف_کرو SFTP_EXT_GETUSERSGROUPS_BY_ID	0x00000200
	u_int exts;
	uint64_t حد_بندی_kbps;
	بنية bwlimit bwlimit_وچ, bwlimit_باہرلا;
};

/* Tracks in-progress requests during file transfers */
بنية request {
	u_int id;
	ناپ_t len;
	uint64_t وتھ;
	TAILQ_ENTRY(request) tq;
};
TAILQ_HEAD(بینتیاں, request);

ساكن u_char *
get_handle(بنية sftp_conn *conn, u_int expected_id, ناپ_t *len,
    ثابت حرف *errfmt, ...) __attribute__((format(لکھو, 4, 5)));

ساكن بنية request *
request_قطار_وچ_پاؤ(بنية بینتیاں *بینتیاں, u_int id, ناپ_t len,
    uint64_t وتھ)
{
	بنية request *req;

	req = xcalloc(1, حجم(*req));
	req->id = id;
	req->len = len;
	req->وتھ = وتھ;
	TAILQ_INSERT_TAIL(بینتیاں, req, tq);
	أرجع req;
}

ساكن بنية request *
request_لبھو(بنية بینتیاں *بینتیاں, u_int id)
{
	بنية request *req;

	لكل (req = TAILQ_FIRST(بینتیاں);
	    req != عدم && req->id != id;
	    req = TAILQ_NEXT(req, tq))
		;
	أرجع req;
}

ساكن صحيح
sftpio(فراغ *_bwlimit, ناپ_t amount)
{
	بنية bwlimit *bwlimit = (بنية bwlimit *)_bwlimit;

	refresh_ترقی_meter(0);
	إذا (bwlimit != عدم)
		bandwidth_حد_بندی(bwlimit, amount);
	أرجع 0;
}

ساكن فراغ
send_پیغام(بنية sftp_conn *conn, بنية sshbuf *m)
{
	u_char mlen[4];
	بنية iovec iov[2];

	إذا (sshbuf_len(m) > SFTP_MAX_پیغام_لمائی)
		fatal("Outbound message too long %zu", sshbuf_len(m));

	/* Send length first */
	put_u32(mlen, sshbuf_len(m));
	iov[0].iov_base = mlen;
	iov[0].iov_len = حجم(mlen);
	iov[1].iov_base = (u_char *)sshbuf_ptr(m);
	iov[1].iov_len = sshbuf_len(m);

	إذا (atomiciov6(writev, conn->fd_باہرلا, iov, 2, sftpio,
	    conn->حد_بندی_kbps > 0 ? &conn->bwlimit_باہرلا : عدم) !=
	    sshbuf_len(m) + حجم(mlen))
		fatal("Couldn't send packet: %s", strerror(errno));

	sshbuf_reset(m);
}

ساكن فراغ
get_پیغام_extended(بنية sftp_conn *conn, بنية sshbuf *m, صحيح initial)
{
	u_int پیغام_len;
	u_char *p;
	صحيح r;

	sshbuf_reset(m);
	إذا ((r = sshbuf_reserve(m, 4, &p)) != 0)
		fatal_fr(r, "reserve");
	إذا (atomicio6(اقرأ, conn->fd_وچ, p, 4, sftpio,
	    conn->حد_بندی_kbps > 0 ? &conn->bwlimit_وچ : عدم) != 4) {
		إذا (errno == EPIPE || errno == ECONNRESET)
			fatal("Connection closed");
		وإلا
			fatal("Couldn't read packet: %s", strerror(errno));
	}

	إذا ((r = sshbuf_get_u32(m, &پیغام_len)) != 0)
		fatal_fr(r, "sshbuf_get_u32");
	إذا (پیغام_len > SFTP_MAX_پیغام_لمائی) {
		do_log2(initial ? SYSLOG_LEVEL_ERROR : SYSLOG_LEVEL_FATAL,
		    "Received message too long %u", پیغام_len);
		fatal("Ensure the remote shell produces no output "
		    "for non-interactive sessions.");
	}

	إذا ((r = sshbuf_reserve(m, پیغام_len, &p)) != 0)
		fatal_fr(r, "reserve");
	إذا (atomicio6(اقرأ, conn->fd_وچ, p, پیغام_len, sftpio,
	    conn->حد_بندی_kbps > 0 ? &conn->bwlimit_وچ : عدم)
	    != پیغام_len) {
		إذا (errno == EPIPE)
			fatal("Connection closed");
		وإلا
			fatal("Read packet: %s", strerror(errno));
	}
}

ساكن فراغ
get_پیغام(بنية sftp_conn *conn, بنية sshbuf *m)
{
	get_پیغام_extended(conn, m, 0);
}

ساكن فراغ
send_string_request(بنية sftp_conn *conn, u_int id, u_int کوڈ, ثابت حرف *s,
    u_int len)
{
	بنية sshbuf *پیغام;
	صحيح r;

	إذا ((پیغام = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshbuf_put_u8(پیغام, کوڈ)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, id)) != 0 ||
	    (r = sshbuf_put_string(پیغام, s, len)) != 0)
		fatal_fr(r, "compose");
	send_پیغام(conn, پیغام);
	debug3("Sent message fd %d T:%u I:%u", conn->fd_باہرلا, کوڈ, id);
	sshbuf_free(پیغام);
}

ساكن فراغ
send_string_attrs_request(بنية sftp_conn *conn, u_int id, u_int کوڈ,
    ثابت فراغ *s, u_int len, Attrib *a)
{
	بنية sshbuf *پیغام;
	صحيح r;

	إذا ((پیغام = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshbuf_put_u8(پیغام, کوڈ)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, id)) != 0 ||
	    (r = sshbuf_put_string(پیغام, s, len)) != 0 ||
	    (r = encode_attrib(پیغام, a)) != 0)
		fatal_fr(r, "compose");
	send_پیغام(conn, پیغام);
	debug3("Sent message fd %d T:%u I:%u F:0x%04x M:%05o",
	    conn->fd_باہرلا, کوڈ, id, a->flags, a->perm);
	sshbuf_free(پیغام);
}

ساكن u_int
get_حالت(بنية sftp_conn *conn, u_int expected_id)
{
	بنية sshbuf *پیغام;
	u_char type;
	u_int id, حالت;
	صحيح r;

	إذا ((پیغام = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	get_پیغام(conn, پیغام);
	إذا ((r = sshbuf_get_u8(پیغام, &type)) != 0 ||
	    (r = sshbuf_get_u32(پیغام, &id)) != 0)
		fatal_fr(r, "compose");

	إذا (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	إذا (type != SSH2_FXP_حالت)
		fatal("Expected SSH2_FXP_STATUS(%u) packet, got %u",
		    SSH2_FXP_حالت, type);

	إذا ((r = sshbuf_get_u32(پیغام, &حالت)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(پیغام);

	debug3("SSH2_FXP_STATUS %u", حالت);

	أرجع حالت;
}

ساكن u_char *
get_handle(بنية sftp_conn *conn, u_int expected_id, ناپ_t *len,
    ثابت حرف *errfmt, ...)
{
	بنية sshbuf *پیغام;
	u_int id, حالت;
	u_char type;
	u_char *handle;
	حرف errmsg[256];
	va_list دلیلاں;
	صحيح r;

	va_start(دلیلاں, errfmt);
	إذا (errfmt != عدم)
		vsnprintf(errmsg, حجم(errmsg), errfmt, دلیلاں);
	va_end(دلیلاں);

	إذا ((پیغام = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	get_پیغام(conn, پیغام);
	إذا ((r = sshbuf_get_u8(پیغام, &type)) != 0 ||
	    (r = sshbuf_get_u32(پیغام, &id)) != 0)
		fatal_fr(r, "parse");

	إذا (id != expected_id)
		fatal("%s: ID mismatch (%u != %u)",
		    errfmt == عدم ? __func__ : errmsg, id, expected_id);
	إذا (type == SSH2_FXP_حالت) {
		إذا ((r = sshbuf_get_u32(پیغام, &حالت)) != 0)
			fatal_fr(r, "parse status");
		إذا (errfmt != عدم)
			error("%s: %s", errmsg, fx2txt(حالت));
		sshbuf_free(پیغام);
		أرجع(عدم);
	} وإلا إذا (type != SSH2_FXP_HANDLE)
		fatal("%s: Expected SSH2_FXP_HANDLE(%u) packet, got %u",
		    errfmt == عدم ? __func__ : errmsg, SSH2_FXP_HANDLE, type);

	إذا ((r = sshbuf_get_string(پیغام, &handle, len)) != 0)
		fatal_fr(r, "parse handle");
	sshbuf_free(پیغام);

	أرجع handle;
}

ساكن صحيح
get_decode_stat(بنية sftp_conn *conn, u_int expected_id, صحيح quiet, Attrib *a)
{
	بنية sshbuf *پیغام;
	u_int id;
	u_char type;
	صحيح r;
	Attrib attr;

	إذا (a != عدم)
		memset(a, '\0', حجم(*a));
	إذا ((پیغام = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	get_پیغام(conn, پیغام);

	إذا ((r = sshbuf_get_u8(پیغام, &type)) != 0 ||
	    (r = sshbuf_get_u32(پیغام, &id)) != 0)
		fatal_fr(r, "parse");

	إذا (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	إذا (type == SSH2_FXP_حالت) {
		u_int حالت;

		إذا ((r = sshbuf_get_u32(پیغام, &حالت)) != 0)
			fatal_fr(r, "parse status");
		إذا (quiet)
			debug("stat remote: %s", fx2txt(حالت));
		وإلا
			error("stat remote: %s", fx2txt(حالت));
		sshbuf_free(پیغام);
		أرجع -1;
	} وإلا إذا (type != SSH2_FXP_ATTRS) {
		fatal("Expected SSH2_FXP_ATTRS(%u) packet, got %u",
		    SSH2_FXP_ATTRS, type);
	}
	إذا ((r = decode_attrib(پیغام, &attr)) != 0) {
		error_fr(r, "decode_attrib");
		sshbuf_free(پیغام);
		أرجع -1;
	}
	/* success */
	إذا (a != عدم)
		*a = attr;
	debug3("Received stat reply T:%u I:%u F:0x%04x M:%05o",
	    type, id, attr.flags, attr.perm);
	sshbuf_free(پیغام);

	أرجع 0;
}

ساكن صحيح
get_decode_statvfs(بنية sftp_conn *conn, بنية sftp_statvfs *st,
    u_int expected_id, صحيح quiet)
{
	بنية sshbuf *پیغام;
	u_char type;
	u_int id;
	uint64_t flag;
	صحيح r;

	إذا ((پیغام = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	get_پیغام(conn, پیغام);

	إذا ((r = sshbuf_get_u8(پیغام, &type)) != 0 ||
	    (r = sshbuf_get_u32(پیغام, &id)) != 0)
		fatal_fr(r, "parse");

	debug3("Received statvfs reply T:%u I:%u", type, id);
	إذا (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	إذا (type == SSH2_FXP_حالت) {
		u_int حالت;

		إذا ((r = sshbuf_get_u32(پیغام, &حالت)) != 0)
			fatal_fr(r, "parse status");
		إذا (quiet)
			debug("remote statvfs: %s", fx2txt(حالت));
		وإلا
			error("remote statvfs: %s", fx2txt(حالت));
		sshbuf_free(پیغام);
		أرجع -1;
	} وإلا إذا (type != SSH2_FXP_EXTENDED_جواب) {
		fatal("Expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_جواب, type);
	}

	memset(st, 0, حجم(*st));
	إذا ((r = sshbuf_get_u64(پیغام, &st->f_bsize)) != 0 ||
	    (r = sshbuf_get_u64(پیغام, &st->f_frsize)) != 0 ||
	    (r = sshbuf_get_u64(پیغام, &st->f_بلاکاں)) != 0 ||
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

	أرجع 0;
}

بنية sftp_conn *
sftp_init(صحيح fd_وچ, صحيح fd_باہرلا, u_int transfer_buflen, u_int عدد_بینتیاں,
    uint64_t حد_بندی_kbps)
{
	u_char type;
	بنية sshbuf *پیغام;
	بنية sftp_conn *ret;
	صحيح r;

	ret = xcalloc(1, حجم(*ret));
	ret->پیغام_id = 1;
	ret->fd_وچ = fd_وچ;
	ret->fd_باہرلا = fd_باہرلا;
	ret->download_buflen = ret->upload_buflen =
	    transfer_buflen ? transfer_buflen : DEFAULT_COPY_BUFLEN;
	ret->عدد_بینتیاں =
	    عدد_بینتیاں ? عدد_بینتیاں : DEFAULT_عدد_بینتیاں;
	ret->exts = 0;
	ret->حد_بندی_kbps = 0;

	إذا ((پیغام = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshbuf_put_u8(پیغام, SSH2_FXP_INIT)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, SSH2_FILEXFER_نسخہ)) != 0)
		fatal_fr(r, "parse");

	send_پیغام(ret, پیغام);

	get_پیغام_extended(ret, پیغام, 1);

	/* Expecting a VERSION reply */
	إذا ((r = sshbuf_get_u8(پیغام, &type)) != 0)
		fatal_fr(r, "parse type");
	إذا (type != SSH2_FXP_نسخہ) {
		error("Invalid packet back from SSH2_FXP_INIT (type %u)",
		    type);
		sshbuf_free(پیغام);
		حرر(ret);
		أرجع(عدم);
	}
	إذا ((r = sshbuf_get_u32(پیغام, &ret->نسخہ)) != 0)
		fatal_fr(r, "parse version");

	debug2("Remote version: %u", ret->نسخہ);

	/* Check for extensions */
	طالما (sshbuf_len(پیغام) > 0) {
		حرف *name;
		u_char *قدر;
		ناپ_t vlen;
		صحيح معلوم = 0;

		إذا ((r = sshbuf_get_cstring(پیغام, &name, عدم)) != 0 ||
		    (r = sshbuf_get_string(پیغام, &قدر, &vlen)) != 0)
			fatal_fr(r, "parse extension");
		إذا (strcmp(name, "posix-rename@openssh.com") == 0 &&
		    strcmp((حرف *)قدر, "1") == 0) {
			ret->exts |= SFTP_EXT_POSIX_RENAME;
			معلوم = 1;
		} وإلا إذا (strcmp(name, "statvfs@openssh.com") == 0 &&
		    strcmp((حرف *)قدر, "2") == 0) {
			ret->exts |= SFTP_EXT_STATVFS;
			معلوم = 1;
		} وإلا إذا (strcmp(name, "fstatvfs@openssh.com") == 0 &&
		    strcmp((حرف *)قدر, "2") == 0) {
			ret->exts |= SFTP_EXT_FSTATVFS;
			معلوم = 1;
		} وإلا إذا (strcmp(name, "hardlink@openssh.com") == 0 &&
		    strcmp((حرف *)قدر, "1") == 0) {
			ret->exts |= SFTP_EXT_HARDLINK;
			معلوم = 1;
		} وإلا إذا (strcmp(name, "fsync@openssh.com") == 0 &&
		    strcmp((حرف *)قدر, "1") == 0) {
			ret->exts |= SFTP_EXT_FSYNC;
			معلوم = 1;
		} وإلا إذا (strcmp(name, "lsetstat@openssh.com") == 0 &&
		    strcmp((حرف *)قدر, "1") == 0) {
			ret->exts |= SFTP_EXT_LSETSTAT;
			معلوم = 1;
		} وإلا إذا (strcmp(name, "limits@openssh.com") == 0 &&
		    strcmp((حرف *)قدر, "1") == 0) {
			ret->exts |= SFTP_EXT_LIMITS;
			معلوم = 1;
		} وإلا إذا (strcmp(name, "expand-path@openssh.com") == 0 &&
		    strcmp((حرف *)قدر, "1") == 0) {
			ret->exts |= SFTP_EXT_رستہ_EXPAND;
			معلوم = 1;
		} وإلا إذا (strcmp(name, "copy-data") == 0 &&
		    strcmp((حرف *)قدر, "1") == 0) {
			ret->exts |= SFTP_EXT_COPY_انکڑے;
			معلوم = 1;
		} وإلا إذا (strcmp(name,
		    "users-groups-by-id@openssh.com") == 0 &&
		    strcmp((حرف *)قدر, "1") == 0) {
			ret->exts |= SFTP_EXT_GETUSERSGROUPS_BY_ID;
			معلوم = 1;
		}
		إذا (معلوم) {
			debug2("Server supports extension \"%s\" revision %s",
			    name, قدر);
		} وإلا {
			debug2("Unrecognised server extension \"%s\"", name);
		}
		حرر(name);
		حرر(قدر);
	}

	sshbuf_free(پیغام);

	/* Query the server for its limits */
	إذا (ret->exts & SFTP_EXT_LIMITS) {
		بنية sftp_limits limits;
		إذا (sftp_get_limits(ret, &limits) != 0)
			fatal_f("limits failed");

		/* If the caller did not specify, find a good value */
		إذا (transfer_buflen == 0) {
			ret->download_buflen = MINIMUM(limits.read_لمائی,
			    SFTP_MAX_پیغام_لمائی - 1024);
			ret->upload_buflen = MINIMUM(limits.write_لمائی,
			    SFTP_MAX_پیغام_لمائی - 1024);
			ret->download_buflen = ودھ_توں_ودھ(ret->download_buflen, 64);
			ret->upload_buflen = ودھ_توں_ودھ(ret->upload_buflen, 64);
			debug3("server upload/download buffer sizes "
			    "%llu / %llu; using %u / %u",
			    (بنانشانی لما لما)limits.write_لمائی,
			    (بنانشانی لما لما)limits.read_لمائی,
			    ret->upload_buflen, ret->download_buflen);
		}
	}

	/* Some filexfer v.0 servers don't support large packets */
	إذا (ret->نسخہ == 0) {
		ret->download_buflen = MINIMUM(ret->download_buflen, 20480);
		ret->upload_buflen = MINIMUM(ret->upload_buflen, 20480);
	}

	ret->حد_بندی_kbps = حد_بندی_kbps;
	إذا (ret->حد_بندی_kbps > 0) {
		bandwidth_حد_بندی_init(&ret->bwlimit_وچ, ret->حد_بندی_kbps,
		    ret->download_buflen);
		bandwidth_حد_بندی_init(&ret->bwlimit_باہرلا, ret->حد_بندی_kbps,
		    ret->upload_buflen);
	}

	أرجع ret;
}

فراغ
sftp_free(بنية sftp_conn *conn)
{
	إذا (conn == عدم)
		أرجع;
	freezero(conn, حجم(*conn));
}

u_int
sftp_proto_نسخہ(بنية sftp_conn *conn)
{
	أرجع conn->نسخہ;
}

صحيح
sftp_get_limits(بنية sftp_conn *conn, بنية sftp_limits *limits)
{
	u_int id, پیغام_id;
	u_char type;
	بنية sshbuf *پیغام;
	صحيح r;

	إذا ((conn->exts & SFTP_EXT_LIMITS) == 0) {
		error("Server does not support limits@openssh.com extension");
		أرجع -1;
	}

	إذا ((پیغام = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");

	id = conn->پیغام_id++;
	إذا ((r = sshbuf_put_u8(پیغام, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, id)) != 0 ||
	    (r = sshbuf_put_cstring(پیغام, "limits@openssh.com")) != 0)
		fatal_fr(r, "compose");
	send_پیغام(conn, پیغام);
	debug3("Sent message limits@openssh.com I:%u", id);

	get_پیغام(conn, پیغام);

	إذا ((r = sshbuf_get_u8(پیغام, &type)) != 0 ||
	    (r = sshbuf_get_u32(پیغام, &پیغام_id)) != 0)
		fatal_fr(r, "parse");

	debug3("Received limits reply T:%u I:%u", type, پیغام_id);
	إذا (id != پیغام_id)
		fatal("ID mismatch (%u != %u)", پیغام_id, id);
	إذا (type != SSH2_FXP_EXTENDED_جواب) {
		debug_f("expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_جواب, type);
		/* Disable the limits extension */
		conn->exts &= ~SFTP_EXT_LIMITS;
		sshbuf_free(پیغام);
		أرجع -1;
	}

	memset(limits, 0, حجم(*limits));
	إذا ((r = sshbuf_get_u64(پیغام, &limits->packet_لمائی)) != 0 ||
	    (r = sshbuf_get_u64(پیغام, &limits->read_لمائی)) != 0 ||
	    (r = sshbuf_get_u64(پیغام, &limits->write_لمائی)) != 0 ||
	    (r = sshbuf_get_u64(پیغام, &limits->open_handles)) != 0)
		fatal_fr(r, "parse limits");

	sshbuf_free(پیغام);

	أرجع 0;
}

صحيح
sftp_close(بنية sftp_conn *conn, ثابت u_char *handle, u_int handle_len)
{
	u_int id, حالت;
	بنية sshbuf *پیغام;
	صحيح r;

	إذا ((پیغام = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");

	id = conn->پیغام_id++;
	إذا ((r = sshbuf_put_u8(پیغام, SSH2_FXP_CLOSE)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, id)) != 0 ||
	    (r = sshbuf_put_string(پیغام, handle, handle_len)) != 0)
		fatal_fr(r, "parse");
	send_پیغام(conn, پیغام);
	debug3("Sent message SSH2_FXP_CLOSE I:%u", id);

	حالت = get_حالت(conn, id);
	إذا (حالت != SSH2_FX_OK)
		error("close remote: %s", fx2txt(حالت));

	sshbuf_free(پیغام);

	أرجع حالت == SSH2_FX_OK ? 0 : -1;
}


ساكن صحيح
sftp_lsreaddir(بنية sftp_conn *conn, ثابت حرف *رستہ, صحيح print_flag,
    SFTP_DIRENT ***dir)
{
	بنية sshbuf *پیغام;
	u_int گنتی, id, i, expected_id, ents = 0;
	ناپ_t handle_len;
	u_char type, *handle;
	صحيح حالت = SSH2_FX_FAILURE;
	صحيح r;

	إذا (dir)
		*dir = عدم;

	id = conn->پیغام_id++;

	إذا ((پیغام = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshbuf_put_u8(پیغام, SSH2_FXP_OPENDIR)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, id)) != 0 ||
	    (r = sshbuf_put_cstring(پیغام, رستہ)) != 0)
		fatal_fr(r, "compose OPENDIR");
	send_پیغام(conn, پیغام);

	handle = get_handle(conn, id, &handle_len,
	    "remote readdir(\"%s\")", رستہ);
	إذا (handle == عدم) {
		sshbuf_free(پیغام);
		أرجع -1;
	}

	إذا (dir) {
		ents = 0;
		*dir = xcalloc(1, حجم(**dir));
		(*dir)[0] = عدم;
	}

	لكل (; !interrupted;) {
		id = expected_id = conn->پیغام_id++;

		debug3("Sending SSH2_FXP_READDIR I:%u", id);

		sshbuf_reset(پیغام);
		إذا ((r = sshbuf_put_u8(پیغام, SSH2_FXP_READDIR)) != 0 ||
		    (r = sshbuf_put_u32(پیغام, id)) != 0 ||
		    (r = sshbuf_put_string(پیغام, handle, handle_len)) != 0)
			fatal_fr(r, "compose READDIR");
		send_پیغام(conn, پیغام);

		sshbuf_reset(پیغام);

		get_پیغام(conn, پیغام);

		إذا ((r = sshbuf_get_u8(پیغام, &type)) != 0 ||
		    (r = sshbuf_get_u32(پیغام, &id)) != 0)
			fatal_fr(r, "parse");

		debug3("Received reply T:%u I:%u", type, id);

		إذا (id != expected_id)
			fatal("ID mismatch (%u != %u)", id, expected_id);

		إذا (type == SSH2_FXP_حالت) {
			u_int rstatus;

			إذا ((r = sshbuf_get_u32(پیغام, &rstatus)) != 0)
				fatal_fr(r, "parse status");
			debug3("Received SSH2_FXP_STATUS %d", rstatus);
			إذا (rstatus == SSH2_FX_EOF)
				اكسر;
			error("Couldn't read directory: %s", fx2txt(rstatus));
			اذهب باہرلا;
		} وإلا إذا (type != SSH2_FXP_NAME)
			fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
			    SSH2_FXP_NAME, type);

		إذا ((r = sshbuf_get_u32(پیغام, &گنتی)) != 0)
			fatal_fr(r, "parse count");
		إذا (گنتی > SSHBUF_ناپ_MAX)
			fatal_f("nonsensical number of entries");
		إذا (گنتی == 0)
			اكسر;
		debug3("Received %d SSH2_FXP_NAME responses", گنتی);
		لكل (i = 0; i < گنتی; i++) {
			حرف *filename, *longname;
			Attrib a;

			إذا ((r = sshbuf_get_cstring(پیغام, &filename,
			    عدم)) != 0 ||
			    (r = sshbuf_get_cstring(پیغام, &longname,
			    عدم)) != 0)
				fatal_fr(r, "parse filenames");
			إذا ((r = decode_attrib(پیغام, &a)) != 0) {
				error_fr(r, "couldn't decode attrib");
				حرر(filename);
				حرر(longname);
				اذهب باہرلا;
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
				    "during readdir of \"%s\"", filename, رستہ);
			} وإلا إذا (dir) {
				*dir = xreallocarray(*dir, ents + 2, حجم(**dir));
				(*dir)[ents] = xcalloc(1, حجم(***dir));
				(*dir)[ents]->filename = xstrdup(filename);
				(*dir)[ents]->longname = xstrdup(longname);
				حافظہ_نقل(&(*dir)[ents]->a, &a, حجم(a));
				(*dir)[++ents] = عدم;
			}
			حرر(filename);
			حرر(longname);
		}
	}
	حالت = 0;

 باہرلا:
	sshbuf_free(پیغام);
	sftp_close(conn, handle, handle_len);
	حرر(handle);

	إذا (حالت != 0 && dir != عدم) {
		/* Don't return results on error */
		sftp_free_dirents(*dir);
		*dir = عدم;
	} وإلا إذا (interrupted && dir != عدم && *dir != عدم) {
		/* Don't return partial matches on interrupt */
		sftp_free_dirents(*dir);
		*dir = xcalloc(1, حجم(**dir));
		**dir = عدم;
	}

	أرجع حالت == SSH2_FX_OK ? 0 : -1;
}

صحيح
sftp_readdir(بنية sftp_conn *conn, ثابت حرف *رستہ, SFTP_DIRENT ***dir)
{
	أرجع sftp_lsreaddir(conn, رستہ, 0, dir);
}

فراغ sftp_free_dirents(SFTP_DIRENT **s)
{
	صحيح i;

	إذا (s == عدم)
		أرجع;
	لكل (i = 0; s[i]; i++) {
		حرر(s[i]->filename);
		حرر(s[i]->longname);
		حرر(s[i]);
	}
	حرر(s);
}

صحيح
sftp_rm(بنية sftp_conn *conn, ثابت حرف *رستہ)
{
	u_int حالت, id;

	debug2("Sending SSH2_FXP_REMOVE \"%s\"", رستہ);

	id = conn->پیغام_id++;
	send_string_request(conn, id, SSH2_FXP_REMOVE, رستہ, لڑی_لمبائی(رستہ));
	حالت = get_حالت(conn, id);
	إذا (حالت != SSH2_FX_OK)
		error("remote delete %s: %s", رستہ, fx2txt(حالت));
	أرجع حالت == SSH2_FX_OK ? 0 : -1;
}

صحيح
sftp_mkdir(بنية sftp_conn *conn, ثابت حرف *رستہ, Attrib *a, صحيح print_flag)
{
	u_int حالت, id;

	debug2("Sending SSH2_FXP_MKDIR \"%s\"", رستہ);

	id = conn->پیغام_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_MKDIR, رستہ,
	    لڑی_لمبائی(رستہ), a);

	حالت = get_حالت(conn, id);
	إذا (حالت != SSH2_FX_OK && print_flag)
		error("remote mkdir \"%s\": %s", رستہ, fx2txt(حالت));

	أرجع حالت == SSH2_FX_OK ? 0 : -1;
}

صحيح
sftp_mkpath(بنية sftp_conn *conn, ثابت حرف *رستہ, Attrib *a, صحيح print_flag)
{
	حرف *slash, *tmp_رستہ;
	صحيح پورا;

	tmp_رستہ = xstrdup(رستہ);
	slash = tmp_رستہ;

	لكل (;;) {
		slash += strspn(slash, "/");
		slash += strcspn(slash, "/");

		پورا = (*slash == '\0');
		*slash = '\0';

		إذا (!sftp_remote_is_dir(conn, tmp_رستہ)) {
			إذا (sftp_mkdir(conn, tmp_رستہ, a, print_flag) != 0) {
				حرر(tmp_رستہ);
				أرجع -1;
			}
		}

		إذا (پورا)
			اكسر;

		*slash = '/';
	}

	حرر(tmp_رستہ);
	أرجع 0;
}

صحيح
sftp_rmdir(بنية sftp_conn *conn, ثابت حرف *رستہ)
{
	u_int حالت, id;

	debug2("Sending SSH2_FXP_RMDIR \"%s\"", رستہ);

	id = conn->پیغام_id++;
	send_string_request(conn, id, SSH2_FXP_RMDIR, رستہ,
	    لڑی_لمبائی(رستہ));

	حالت = get_حالت(conn, id);
	إذا (حالت != SSH2_FX_OK)
		error("remote rmdir \"%s\": %s", رستہ, fx2txt(حالت));

	أرجع حالت == SSH2_FX_OK ? 0 : -1;
}

صحيح
sftp_stat(بنية sftp_conn *conn, ثابت حرف *رستہ, صحيح quiet, Attrib *a)
{
	u_int id;

	debug2("Sending SSH2_FXP_STAT \"%s\"", رستہ);

	id = conn->پیغام_id++;

	send_string_request(conn, id,
	    conn->نسخہ == 0 ? SSH2_FXP_STAT_نسخہ_0 : SSH2_FXP_STAT,
	    رستہ, لڑی_لمبائی(رستہ));

	أرجع get_decode_stat(conn, id, quiet, a);
}

صحيح
sftp_lstat(بنية sftp_conn *conn, ثابت حرف *رستہ, صحيح quiet, Attrib *a)
{
	u_int id;

	إذا (conn->نسخہ == 0) {
		do_log2(quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_INFO,
		    "Server version does not support lstat operation");
		أرجع sftp_stat(conn, رستہ, quiet, a);
	}

	id = conn->پیغام_id++;
	send_string_request(conn, id, SSH2_FXP_LSTAT, رستہ,
	    لڑی_لمبائی(رستہ));

	أرجع get_decode_stat(conn, id, quiet, a);
}

#جے_تعریف_شدہ notyet
صحيح
sftp_fstat(بنية sftp_conn *conn, ثابت u_char *handle, u_int handle_len,
    صحيح quiet, Attrib *a)
{
	u_int id;

	debug2("Sending SSH2_FXP_FSTAT \"%s\"");

	id = conn->پیغام_id++;
	send_string_request(conn, id, SSH2_FXP_FSTAT, handle,
	    handle_len);

	أرجع get_decode_stat(conn, id, quiet, a);
}
#جے_انت

صحيح
sftp_setstat(بنية sftp_conn *conn, ثابت حرف *رستہ, Attrib *a)
{
	u_int حالت, id;

	debug2("Sending SSH2_FXP_SETSTAT \"%s\"", رستہ);

	id = conn->پیغام_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_SETSTAT, رستہ,
	    لڑی_لمبائی(رستہ), a);

	حالت = get_حالت(conn, id);
	إذا (حالت != SSH2_FX_OK)
		error("remote setstat \"%s\": %s", رستہ, fx2txt(حالت));

	أرجع حالت == SSH2_FX_OK ? 0 : -1;
}

صحيح
sftp_fsetstat(بنية sftp_conn *conn, ثابت u_char *handle, u_int handle_len,
    Attrib *a)
{
	u_int حالت, id;

	debug2("Sending SSH2_FXP_FSETSTAT");

	id = conn->پیغام_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_FSETSTAT, handle,
	    handle_len, a);

	حالت = get_حالت(conn, id);
	إذا (حالت != SSH2_FX_OK)
		error("remote fsetstat: %s", fx2txt(حالت));

	أرجع حالت == SSH2_FX_OK ? 0 : -1;
}

/* Implements both the realpath and expand-path operations */
ساكن حرف *
sftp_realpath_expand(بنية sftp_conn *conn, ثابت حرف *رستہ, صحيح expand)
{
	بنية sshbuf *پیغام;
	u_int expected_id, گنتی, id;
	حرف *filename, *longname;
	Attrib a;
	u_char type;
	صحيح r;
	ثابت حرف *what = "SSH2_FXP_REALPATH";

	إذا (expand)
		what = "expand-path@openssh.com";
	إذا ((پیغام = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");

	expected_id = id = conn->پیغام_id++;
	إذا (expand) {
		debug2("Sending SSH2_FXP_EXTENDED(expand-path@openssh.com) "
		    "\"%s\"", رستہ);
		إذا ((r = sshbuf_put_u8(پیغام, SSH2_FXP_EXTENDED)) != 0 ||
		    (r = sshbuf_put_u32(پیغام, id)) != 0 ||
		    (r = sshbuf_put_cstring(پیغام,
		    "expand-path@openssh.com")) != 0 ||
		    (r = sshbuf_put_cstring(پیغام, رستہ)) != 0)
			fatal_fr(r, "compose %s", what);
		send_پیغام(conn, پیغام);
	} وإلا {
		debug2("Sending SSH2_FXP_REALPATH \"%s\"", رستہ);
		send_string_request(conn, id, SSH2_FXP_REALPATH,
		    رستہ, لڑی_لمبائی(رستہ));
	}
	get_پیغام(conn, پیغام);
	إذا ((r = sshbuf_get_u8(پیغام, &type)) != 0 ||
	    (r = sshbuf_get_u32(پیغام, &id)) != 0)
		fatal_fr(r, "parse");

	إذا (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);

	إذا (type == SSH2_FXP_حالت) {
		u_int حالت;
		حرف *errmsg;

		إذا ((r = sshbuf_get_u32(پیغام, &حالت)) != 0 ||
		    (r = sshbuf_get_cstring(پیغام, &errmsg, عدم)) != 0)
			fatal_fr(r, "parse status");
		error("%s %s: %s", expand ? "expand" : "realpath",
		    رستہ, *errmsg == '\0' ? fx2txt(حالت) : errmsg);
		حرر(errmsg);
		sshbuf_free(پیغام);
		أرجع عدم;
	} وإلا إذا (type != SSH2_FXP_NAME)
		fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
		    SSH2_FXP_NAME, type);

	إذا ((r = sshbuf_get_u32(پیغام, &گنتی)) != 0)
		fatal_fr(r, "parse count");
	إذا (گنتی != 1)
		fatal("Got multiple names (%d) from %s", گنتی, what);

	إذا ((r = sshbuf_get_cstring(پیغام, &filename, عدم)) != 0 ||
	    (r = sshbuf_get_cstring(پیغام, &longname, عدم)) != 0 ||
	    (r = decode_attrib(پیغام, &a)) != 0)
		fatal_fr(r, "parse filename/attrib");

	debug3("%s %s -> %s", what, رستہ, filename);

	حرر(longname);

	sshbuf_free(پیغام);

	أرجع(filename);
}

حرف *
sftp_realpath(بنية sftp_conn *conn, ثابت حرف *رستہ)
{
	أرجع sftp_realpath_expand(conn, رستہ, 0);
}

صحيح
sftp_can_expand_رستہ(بنية sftp_conn *conn)
{
	أرجع (conn->exts & SFTP_EXT_رستہ_EXPAND) != 0;
}

حرف *
sftp_expand_رستہ(بنية sftp_conn *conn, ثابت حرف *رستہ)
{
	إذا (!sftp_can_expand_رستہ(conn)) {
		debug3_f("no server support, fallback to realpath");
		أرجع sftp_realpath_expand(conn, رستہ, 0);
	}
	أرجع sftp_realpath_expand(conn, رستہ, 1);
}

صحيح
sftp_copy(بنية sftp_conn *conn, ثابت حرف *oldpath, ثابت حرف *newpath)
{
	Attrib junk, attr;
	بنية sshbuf *پیغام;
	u_char *old_handle, *new_handle;
	u_int منوال, حالت, id;
	ناپ_t old_handle_len, new_handle_len;
	صحيح r;

	/* Return if the extension is not supported */
	إذا ((conn->exts & SFTP_EXT_COPY_انکڑے) == 0) {
		error("Server does not support copy-data extension");
		أرجع -1;
	}

	/* Make sure the file exists, and we can copy its perms */
	إذا (sftp_stat(conn, oldpath, 0, &attr) != 0)
		أرجع -1;

	/* Do not preserve set[ug]id here, as we do not preserve ownership */
	إذا (attr.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		منوال = attr.perm & 0777;

		إذا (!S_ISREG(attr.perm)) {
			error("Cannot copy non-regular file: %s", oldpath);
			أرجع -1;
		}
	} وإلا {
		/* NB: The user's umask will apply to this */
		منوال = 0666;
	}

	/* Set up the new perms for the new file */
	attrib_clear(&attr);
	attr.perm = منوال;
	attr.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;

	إذا ((پیغام = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");

	attrib_clear(&junk); /* Send empty attributes */

	/* Open the old file for reading */
	id = conn->پیغام_id++;
	إذا ((r = sshbuf_put_u8(پیغام, SSH2_FXP_OPEN)) != 0 ||
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
	إذا (old_handle == عدم) {
		sshbuf_free(پیغام);
		أرجع -1;
	}

	/* Open the new file for writing */
	id = conn->پیغام_id++;
	إذا ((r = sshbuf_put_u8(پیغام, SSH2_FXP_OPEN)) != 0 ||
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
	إذا (new_handle == عدم) {
		sshbuf_free(پیغام);
		حرر(old_handle);
		أرجع -1;
	}

	/* Copy the file data */
	id = conn->پیغام_id++;
	إذا ((r = sshbuf_put_u8(پیغام, SSH2_FXP_EXTENDED)) != 0 ||
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

	حالت = get_حالت(conn, id);
	إذا (حالت != SSH2_FX_OK)
		error("Couldn't copy file \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(حالت));

	/* Clean up everything */
	sshbuf_free(پیغام);
	sftp_close(conn, old_handle, old_handle_len);
	sftp_close(conn, new_handle, new_handle_len);
	حرر(old_handle);
	حرر(new_handle);

	أرجع حالت == SSH2_FX_OK ? 0 : -1;
}

صحيح
sftp_rename(بنية sftp_conn *conn, ثابت حرف *oldpath, ثابت حرف *newpath,
    صحيح force_legacy)
{
	بنية sshbuf *پیغام;
	u_int حالت, id;
	صحيح r, use_ext = (conn->exts & SFTP_EXT_POSIX_RENAME) && !force_legacy;

	إذا ((پیغام = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");

	/* Send rename request */
	id = conn->پیغام_id++;
	إذا (use_ext) {
		debug2("Sending SSH2_FXP_EXTENDED(posix-rename@openssh.com) "
		    "\"%s\" to \"%s\"", oldpath, newpath);
		إذا ((r = sshbuf_put_u8(پیغام, SSH2_FXP_EXTENDED)) != 0 ||
		    (r = sshbuf_put_u32(پیغام, id)) != 0 ||
		    (r = sshbuf_put_cstring(پیغام,
		    "posix-rename@openssh.com")) != 0)
			fatal_fr(r, "compose posix-rename");
	} وإلا {
		debug2("Sending SSH2_FXP_RENAME \"%s\" to \"%s\"",
		    oldpath, newpath);
		إذا ((r = sshbuf_put_u8(پیغام, SSH2_FXP_RENAME)) != 0 ||
		    (r = sshbuf_put_u32(پیغام, id)) != 0)
			fatal_fr(r, "compose rename");
	}
	إذا ((r = sshbuf_put_cstring(پیغام, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(پیغام, newpath)) != 0)
		fatal_fr(r, "compose paths");
	send_پیغام(conn, پیغام);
	debug3("Sent message %s \"%s\" -> \"%s\"",
	    use_ext ? "posix-rename@openssh.com" :
	    "SSH2_FXP_RENAME", oldpath, newpath);
	sshbuf_free(پیغام);

	حالت = get_حالت(conn, id);
	إذا (حالت != SSH2_FX_OK)
		error("remote rename \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(حالت));

	أرجع حالت == SSH2_FX_OK ? 0 : -1;
}

صحيح
sftp_hardlink(بنية sftp_conn *conn, ثابت حرف *oldpath, ثابت حرف *newpath)
{
	بنية sshbuf *پیغام;
	u_int حالت, id;
	صحيح r;

	إذا ((conn->exts & SFTP_EXT_HARDLINK) == 0) {
		error("Server does not support hardlink@openssh.com extension");
		أرجع -1;
	}
	debug2("Sending SSH2_FXP_EXTENDED(hardlink@openssh.com) "
	    "\"%s\" to \"%s\"", oldpath, newpath);

	إذا ((پیغام = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");

	/* Send link request */
	id = conn->پیغام_id++;
	إذا ((r = sshbuf_put_u8(پیغام, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, id)) != 0 ||
	    (r = sshbuf_put_cstring(پیغام, "hardlink@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(پیغام, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(پیغام, newpath)) != 0)
		fatal_fr(r, "compose");
	send_پیغام(conn, پیغام);
	debug3("Sent message hardlink@openssh.com \"%s\" -> \"%s\"",
	    oldpath, newpath);
	sshbuf_free(پیغام);

	حالت = get_حالت(conn, id);
	إذا (حالت != SSH2_FX_OK)
		error("remote link \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(حالت));

	أرجع حالت == SSH2_FX_OK ? 0 : -1;
}

صحيح
sftp_symlink(بنية sftp_conn *conn, ثابت حرف *oldpath, ثابت حرف *newpath)
{
	بنية sshbuf *پیغام;
	u_int حالت, id;
	صحيح r;

	إذا (conn->نسخہ < 3) {
		error("This server does not support the symlink operation");
		أرجع(SSH2_FX_OP_UNSUPPORTED);
	}
	debug2("Sending SSH2_FXP_SYMLINK \"%s\" to \"%s\"", oldpath, newpath);

	إذا ((پیغام = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");

	/* Send symlink request */
	id = conn->پیغام_id++;
	إذا ((r = sshbuf_put_u8(پیغام, SSH2_FXP_SYMLINK)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, id)) != 0 ||
	    (r = sshbuf_put_cstring(پیغام, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(پیغام, newpath)) != 0)
		fatal_fr(r, "compose");
	send_پیغام(conn, پیغام);
	debug3("Sent message SSH2_FXP_SYMLINK \"%s\" -> \"%s\"", oldpath,
	    newpath);
	sshbuf_free(پیغام);

	حالت = get_حالت(conn, id);
	إذا (حالت != SSH2_FX_OK)
		error("remote symlink file \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(حالت));

	أرجع حالت == SSH2_FX_OK ? 0 : -1;
}

صحيح
sftp_fsync(بنية sftp_conn *conn, u_char *handle, u_int handle_len)
{
	بنية sshbuf *پیغام;
	u_int حالت, id;
	صحيح r;

	/* Silently return if the extension is not supported */
	إذا ((conn->exts & SFTP_EXT_FSYNC) == 0)
		أرجع -1;
	debug2("Sending SSH2_FXP_EXTENDED(fsync@openssh.com)");

	/* Send fsync request */
	إذا ((پیغام = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	id = conn->پیغام_id++;
	إذا ((r = sshbuf_put_u8(پیغام, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, id)) != 0 ||
	    (r = sshbuf_put_cstring(پیغام, "fsync@openssh.com")) != 0 ||
	    (r = sshbuf_put_string(پیغام, handle, handle_len)) != 0)
		fatal_fr(r, "compose");
	send_پیغام(conn, پیغام);
	debug3("Sent message fsync@openssh.com I:%u", id);
	sshbuf_free(پیغام);

	حالت = get_حالت(conn, id);
	إذا (حالت != SSH2_FX_OK)
		error("remote fsync: %s", fx2txt(حالت));

	أرجع حالت == SSH2_FX_OK ? 0 : -1;
}

#جے_تعریف_شدہ notyet
حرف *
sftp_readlink(بنية sftp_conn *conn, ثابت حرف *رستہ)
{
	بنية sshbuf *پیغام;
	u_int expected_id, گنتی, id;
	حرف *filename, *longname;
	Attrib a;
	u_char type;
	صحيح r;

	debug2("Sending SSH2_FXP_READLINK \"%s\"", رستہ);

	expected_id = id = conn->پیغام_id++;
	send_string_request(conn, id, SSH2_FXP_READLINK, رستہ, لڑی_لمبائی(رستہ));

	إذا ((پیغام = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");

	get_پیغام(conn, پیغام);
	إذا ((r = sshbuf_get_u8(پیغام, &type)) != 0 ||
	    (r = sshbuf_get_u32(پیغام, &id)) != 0)
		fatal_fr(r, "parse");

	إذا (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);

	إذا (type == SSH2_FXP_حالت) {
		u_int حالت;

		إذا ((r = sshbuf_get_u32(پیغام, &حالت)) != 0)
			fatal_fr(r, "parse status");
		error("Couldn't readlink: %s", fx2txt(حالت));
		sshbuf_free(پیغام);
		أرجع(عدم);
	} وإلا إذا (type != SSH2_FXP_NAME)
		fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
		    SSH2_FXP_NAME, type);

	إذا ((r = sshbuf_get_u32(پیغام, &گنتی)) != 0)
		fatal_fr(r, "parse count");
	إذا (گنتی != 1)
		fatal("Got multiple names (%d) from SSH_FXP_READLINK", گنتی);

	إذا ((r = sshbuf_get_cstring(پیغام, &filename, عدم)) != 0 ||
	    (r = sshbuf_get_cstring(پیغام, &longname, عدم)) != 0 ||
	    (r = decode_attrib(پیغام, &a)) != 0)
		fatal_fr(r, "parse filenames/attrib");

	debug3("SSH_FXP_READLINK %s -> %s", رستہ, filename);

	حرر(longname);

	sshbuf_free(پیغام);

	أرجع filename;
}
#جے_انت

صحيح
sftp_statvfs(بنية sftp_conn *conn, ثابت حرف *رستہ, بنية sftp_statvfs *st,
    صحيح quiet)
{
	بنية sshbuf *پیغام;
	u_int id;
	صحيح r;

	إذا ((conn->exts & SFTP_EXT_STATVFS) == 0) {
		error("Server does not support statvfs@openssh.com extension");
		أرجع -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(statvfs@openssh.com) \"%s\"", رستہ);

	id = conn->پیغام_id++;

	إذا ((پیغام = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshbuf_put_u8(پیغام, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, id)) != 0 ||
	    (r = sshbuf_put_cstring(پیغام, "statvfs@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(پیغام, رستہ)) != 0)
		fatal_fr(r, "compose");
	send_پیغام(conn, پیغام);
	sshbuf_free(پیغام);

	أرجع get_decode_statvfs(conn, st, id, quiet);
}

#جے_تعریف_شدہ notyet
صحيح
sftp_fstatvfs(بنية sftp_conn *conn, ثابت u_char *handle, u_int handle_len,
    بنية sftp_statvfs *st, صحيح quiet)
{
	بنية sshbuf *پیغام;
	u_int id;

	إذا ((conn->exts & SFTP_EXT_FSTATVFS) == 0) {
		error("Server does not support fstatvfs@openssh.com extension");
		أرجع -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(fstatvfs@openssh.com)");

	id = conn->پیغام_id++;

	إذا ((پیغام = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshbuf_put_u8(پیغام, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, id)) != 0 ||
	    (r = sshbuf_put_cstring(پیغام, "fstatvfs@openssh.com")) != 0 ||
	    (r = sshbuf_put_string(پیغام, handle, handle_len)) != 0)
		fatal_fr(r, "compose");
	send_پیغام(conn, پیغام);
	sshbuf_free(پیغام);

	أرجع get_decode_statvfs(conn, st, id, quiet);
}
#جے_انت

صحيح
sftp_lsetstat(بنية sftp_conn *conn, ثابت حرف *رستہ, Attrib *a)
{
	بنية sshbuf *پیغام;
	u_int حالت, id;
	صحيح r;

	إذا ((conn->exts & SFTP_EXT_LSETSTAT) == 0) {
		error("Server does not support lsetstat@openssh.com extension");
		أرجع -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(lsetstat@openssh.com) \"%s\"", رستہ);

	id = conn->پیغام_id++;
	إذا ((پیغام = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshbuf_put_u8(پیغام, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, id)) != 0 ||
	    (r = sshbuf_put_cstring(پیغام, "lsetstat@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(پیغام, رستہ)) != 0 ||
	    (r = encode_attrib(پیغام, a)) != 0)
		fatal_fr(r, "compose");
	send_پیغام(conn, پیغام);
	sshbuf_free(پیغام);

	حالت = get_حالت(conn, id);
	إذا (حالت != SSH2_FX_OK)
		error("remote lsetstat \"%s\": %s", رستہ, fx2txt(حالت));

	أرجع حالت == SSH2_FX_OK ? 0 : -1;
}

ساكن فراغ
send_read_request(بنية sftp_conn *conn, u_int id, uint64_t وتھ,
    u_int len, ثابت u_char *handle, u_int handle_len)
{
	بنية sshbuf *پیغام;
	صحيح r;

	إذا ((پیغام = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshbuf_put_u8(پیغام, SSH2_FXP_READ)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, id)) != 0 ||
	    (r = sshbuf_put_string(پیغام, handle, handle_len)) != 0 ||
	    (r = sshbuf_put_u64(پیغام, وتھ)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, len)) != 0)
		fatal_fr(r, "compose");
	send_پیغام(conn, پیغام);
	sshbuf_free(پیغام);
}

ساكن صحيح
send_open(بنية sftp_conn *conn, ثابت حرف *رستہ, ثابت حرف *ٹیگ,
    u_int openmode, Attrib *a, u_char **handlep, ناپ_t *handle_lenp)
{
	Attrib junk;
	u_char *handle;
	ناپ_t handle_len;
	بنية sshbuf *پیغام;
	صحيح r;
	u_int id;

	debug2("Sending SSH2_FXP_OPEN \"%s\"", رستہ);

	*handlep = عدم;
	*handle_lenp = 0;

	إذا (a == عدم) {
		attrib_clear(&junk); /* Send empty attributes */
		a = &junk;
	}
	/* Send open request */
	إذا ((پیغام = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	id = conn->پیغام_id++;
	إذا ((r = sshbuf_put_u8(پیغام, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, id)) != 0 ||
	    (r = sshbuf_put_cstring(پیغام, رستہ)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, openmode)) != 0 ||
	    (r = encode_attrib(پیغام, a)) != 0)
		fatal_fr(r, "compose %s open", ٹیگ);
	send_پیغام(conn, پیغام);
	sshbuf_free(پیغام);
	debug3("Sent %s message SSH2_FXP_OPEN I:%u P:%s M:0x%04x",
	    ٹیگ, id, رستہ, openmode);
	إذا ((handle = get_handle(conn, id, &handle_len,
	    "%s open \"%s\"", ٹیگ, رستہ)) == عدم)
		أرجع -1;
	/* success */
	*handlep = handle;
	*handle_lenp = handle_len;
	أرجع 0;
}

ساكن ثابت حرف *
ترقی_meter_رستہ(ثابت حرف *رستہ)
{
	ثابت حرف *progresspath;

	إذا ((progresspath = strrchr(رستہ, '/')) == عدم)
		أرجع رستہ;
	progresspath++;
	إذا (*progresspath == '\0')
		أرجع رستہ;
	أرجع progresspath;
}

صحيح
sftp_download(بنية sftp_conn *conn, ثابت حرف *remote_رستہ,
    ثابت حرف *local_رستہ, Attrib *a, صحيح preserve_flag, صحيح resume_flag,
    صحيح fsync_flag, صحيح inplace_flag)
{
	بنية sshbuf *پیغام;
	u_char *handle;
	صحيح local_fd = -1, write_error, تکیا_zerolen = 0;
	صحيح read_error, write_errno, lmodified = 0, reordered = 0, r;
	uint64_t وتھ = 0, ناپ, highwater = 0, maxack = 0;
	u_int منوال, id, buflen, عدد_req, max_req, حالت = SSH2_FX_OK;
	off_t ترقی_counter;
	ناپ_t handle_len;
	بنية stat st;
	بنية بینتیاں بینتیاں;
	بنية request *req;
	u_char type;
	Attrib attr;

	debug2_f("download remote \"%s\" to local \"%s\"",
	    remote_رستہ, local_رستہ);

	TAILQ_INIT(&بینتیاں);

	إذا (a == عدم) {
		إذا (sftp_stat(conn, remote_رستہ, 0, &attr) != 0)
			أرجع -1;
		a = &attr;
	}

	/* Do not preserve set[ug]id here, as we do not preserve ownership */
	إذا (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS)
		منوال = a->perm & 0777;
	وإلا
		منوال = 0666;

	إذا ((a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) &&
	    (!S_ISREG(a->perm))) {
		error("download %s: not a regular file", remote_رستہ);
		أرجع(-1);
	}

	إذا (a->flags & SSH2_FILEXFER_ATTR_ناپ)
		ناپ = a->ناپ;
	وإلا
		ناپ = 0;

	buflen = conn->download_buflen;

	/* Send open request */
	إذا (send_open(conn, remote_رستہ, "remote", SSH2_FXF_READ, عدم,
	    &handle, &handle_len) != 0)
		أرجع -1;

	local_fd = open(local_رستہ, O_WRONLY | O_CREAT |
	((resume_flag || inplace_flag) ? 0 : O_TRUNC), منوال | S_IWUSR);
	إذا (local_fd == -1) {
		error("open local \"%s\": %s", local_رستہ, strerror(errno));
		اذهب fail;
	}
	إذا (resume_flag) {
		إذا (fstat(local_fd, &st) == -1) {
			error("stat local \"%s\": %s",
			    local_رستہ, strerror(errno));
			اذهب fail;
		}
		إذا (st.st_size < 0) {
			error("\"%s\" has negative size", local_رستہ);
			اذهب fail;
		}
		إذا ((uint64_t)st.st_size > ناپ) {
			error("Unable to resume download of \"%s\": "
			    "local file is larger than remote", local_رستہ);
 fail:
			sftp_close(conn, handle, handle_len);
			حرر(handle);
			إذا (local_fd != -1)
				close(local_fd);
			أرجع -1;
		}
		وتھ = highwater = maxack = st.st_size;
	}

	/* Read from remote and write to local */
	write_error = read_error = write_errno = عدد_req = 0;
	max_req = 1;
	ترقی_counter = وتھ;

	إذا (showprogress && ناپ != 0) {
		شروع_ترقی_meter(ترقی_meter_رستہ(remote_رستہ),
		    ناپ, &ترقی_counter);
	}

	إذا ((پیغام = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");

	طالما (عدد_req > 0 || max_req > 0) {
		u_char *انکڑے;
		ناپ_t len;

		/*
		 * Simulate EOF on interrupt: stop sending new requests and
		 * allow outstanding requests to drain gracefully
		 */
		إذا (interrupted) {
			إذا (عدد_req == 0) /* If we haven't started yet... */
				اكسر;
			max_req = 0;
		}

		/* Send some more requests */
		طالما (عدد_req < max_req) {
			debug3("Request range %llu -> %llu (%d/%d)",
			    (بنانشانی لما لما)وتھ,
			    (بنانشانی لما لما)وتھ + buflen - 1,
			    عدد_req, max_req);
			req = request_قطار_وچ_پاؤ(&بینتیاں, conn->پیغام_id++,
			    buflen, وتھ);
			وتھ += buflen;
			عدد_req++;
			send_read_request(conn, req->id, req->وتھ,
			    req->len, handle, handle_len);
		}

		sshbuf_reset(پیغام);
		get_پیغام(conn, پیغام);
		إذا ((r = sshbuf_get_u8(پیغام, &type)) != 0 ||
		    (r = sshbuf_get_u32(پیغام, &id)) != 0)
			fatal_fr(r, "parse");
		debug3("Received reply T:%u I:%u R:%d", type, id, max_req);

		/* Find the request in our queue */
		إذا ((req = request_لبھو(&بینتیاں, id)) == عدم)
			fatal("Unexpected reply %u", id);

		بدل (type) {
		حالة SSH2_FXP_حالت:
			إذا ((r = sshbuf_get_u32(پیغام, &حالت)) != 0)
				fatal_fr(r, "parse status");
			إذا (حالت != SSH2_FX_EOF)
				read_error = 1;
			max_req = 0;
			TAILQ_REMOVE(&بینتیاں, req, tq);
			حرر(req);
			عدد_req--;
			اكسر;
		حالة SSH2_FXP_انکڑے:
			إذا ((r = sshbuf_get_string(پیغام, &انکڑے, &len)) != 0)
				fatal_fr(r, "parse data");
			debug3("Received data %llu -> %llu",
			    (بنانشانی لما لما)req->وتھ,
			    (بنانشانی لما لما)req->وتھ + len - 1);
			إذا (len > req->len)
				fatal("Received more data than asked for "
				    "%zu > %zu", len, req->len);
			إذا (len == 0) {
				إذا (تکیا_zerolen)
					fatal_f("server sent zero data length");
				تکیا_zerolen = 1;
			}
			lmodified = 1;
			إذا ((lseek(local_fd, req->وتھ, SEEK_SET) == -1 ||
			    atomicio(vwrite, local_fd, انکڑے, len) != len) &&
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
				إذا (maxack < req->وتھ + len)
					maxack = req->وتھ + len;
				إذا (!reordered && req->وتھ <= highwater)
					highwater = maxack;
				وإلا إذا (!reordered && req->وتھ > highwater)
					reordered = 1;
			}
			ترقی_counter += len;
			حرر(انکڑے);

			إذا (len == req->len) {
				TAILQ_REMOVE(&بینتیاں, req, tq);
				حرر(req);
				عدد_req--;
			} وإلا {
				/* Resend the request for the missing data */
				debug3("Short data block, re-requesting "
				    "%llu -> %llu (%2d)",
				    (بنانشانی لما لما)req->وتھ + len,
				    (بنانشانی لما لما)req->وتھ +
				    req->len - 1, عدد_req);
				req->id = conn->پیغام_id++;
				req->len -= len;
				req->وتھ += len;
				send_read_request(conn, req->id,
				    req->وتھ, req->len, handle, handle_len);
				/* Reduce the request size */
				إذا (len < buflen)
					buflen = ودھ_توں_ودھ(MIN_READ_ناپ, len);
			}
			إذا (max_req > 0) { /* max_req = 0 iff EOF received */
				إذا (ناپ > 0 && وتھ > ناپ) {
					/* Only one request at a time
					 * after the expected EOF */
					debug3("Finish at %llu (%2d)",
					    (بنانشانی لما لما)وتھ,
					    عدد_req);
					max_req = 1;
				} وإلا إذا (max_req < conn->عدد_بینتیاں) {
					++max_req;
				}
			}
			اكسر;
		افتراضي:
			fatal("Expected SSH2_FXP_DATA(%u) packet, got %u",
			    SSH2_FXP_انکڑے, type);
		}
	}

	إذا (showprogress && ناپ)
		stop_ترقی_meter();

	/* Sanity check */
	إذا (TAILQ_FIRST(&بینتیاں) != عدم)
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
			    "server reordered requests", local_رستہ);
		}
		debug("truncating at %llu", (بنانشانی لما لما)highwater);
		إذا (ftruncate(local_fd, highwater) == -1)
			error("local ftruncate \"%s\": %s", local_رستہ,
			    strerror(errno));
	}
	إذا (read_error) {
		error("read remote \"%s\" : %s", remote_رستہ, fx2txt(حالت));
		حالت = -1;
		sftp_close(conn, handle, handle_len);
	} وإلا إذا (write_error) {
		error("write local \"%s\": %s", local_رستہ,
		    strerror(write_errno));
		حالت = SSH2_FX_FAILURE;
		sftp_close(conn, handle, handle_len);
	} وإلا {
		إذا (sftp_close(conn, handle, handle_len) != 0 || interrupted)
			حالت = SSH2_FX_FAILURE;
		وإلا
			حالت = SSH2_FX_OK;
		/* Override umask and utimes if asked */
#جے_تعریف_شدہ HAVE_FCHMOD
		إذا (preserve_flag && fchmod(local_fd, منوال) == -1)
#وإلا
		إذا (preserve_flag && chmod(local_رستہ, منوال) == -1)
#جے_انت /* HAVE_FCHMOD */
			error("local chmod \"%s\": %s", local_رستہ,
			    strerror(errno));
		إذا (preserve_flag &&
		    (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME)) {
			بنية timeval tv[2];
			tv[0].tv_sec = a->atime;
			tv[1].tv_sec = a->mtime;
			tv[0].tv_usec = tv[1].tv_usec = 0;
			إذا (utimes(local_رستہ, tv) == -1)
				error("local set times \"%s\": %s",
				    local_رستہ, strerror(errno));
		}
		إذا (resume_flag && !lmodified)
			logit("File \"%s\" was not modified", local_رستہ);
		وإلا إذا (fsync_flag) {
			debug("syncing \"%s\"", local_رستہ);
			إذا (fsync(local_fd) == -1)
				error("local sync \"%s\": %s",
				    local_رستہ, strerror(errno));
		}
	}
	close(local_fd);
	sshbuf_free(پیغام);
	حرر(handle);

	أرجع حالت == SSH2_FX_OK ? 0 : -1;
}

ساكن صحيح
download_dir_اندرونی(بنية sftp_conn *conn, ثابت حرف *src, ثابت حرف *dst,
    صحيح ڈونگھائی, Attrib *dirattrib, صحيح preserve_flag, صحيح print_flag,
    صحيح resume_flag, صحيح fsync_flag, صحيح follow_link_flag, صحيح inplace_flag)
{
	صحيح i, ret = 0;
	SFTP_DIRENT **dir_entries;
	حرف *filename, *new_src = عدم, *new_dst = عدم;
	منوال_t منوال = 0777, tmpmode = منوال;
	Attrib *a, ldirattrib, lsym;

	إذا (ڈونگھائی >= MAX_DIR_ڈونگھائی) {
		error("Maximum directory depth exceeded: %d levels", ڈونگھائی);
		أرجع -1;
	}

	debug2_f("download dir remote \"%s\" to local \"%s\"", src, dst);

	إذا (dirattrib == عدم) {
		إذا (sftp_stat(conn, src, 1, &ldirattrib) != 0) {
			error("stat remote \"%s\" directory failed", src);
			أرجع -1;
		}
		dirattrib = &ldirattrib;
	}
	إذا (!S_ISDIR(dirattrib->perm)) {
		error("\"%s\" is not a directory", src);
		أرجع -1;
	}
	إذا (print_flag && print_flag != SFTP_ترقی_ONLY)
		mprintf("Retrieving %s\n", src);

	إذا (dirattrib->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		منوال = dirattrib->perm & 01777;
		tmpmode = منوال | (S_IWUSR|S_IXUSR);
	} وإلا {
		debug("download remote \"%s\": server "
		    "did not send permissions", dst);
	}

	إذا (mkdir(dst, tmpmode) == -1 && errno != EEXIST) {
		error("mkdir %s: %s", dst, strerror(errno));
		أرجع -1;
	}

	إذا (sftp_readdir(conn, src, &dir_entries) == -1) {
		error("remote readdir \"%s\" failed", src);
		أرجع -1;
	}

	لكل (i = 0; dir_entries[i] != عدم && !interrupted; i++) {
		حرر(new_dst);
		حرر(new_src);

		filename = dir_entries[i]->filename;
		new_dst = sftp_رستہ_append(dst, filename);
		new_src = sftp_رستہ_append(src, filename);

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
			إذا (download_dir_اندرونی(conn, new_src, new_dst,
			    ڈونگھائی + 1, a, preserve_flag,
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

	إذا (منوال != tmpmode && chmod(dst, منوال) == -1)
		error("local chmod directory \"%s\": %s", dst,
		    strerror(errno));

	sftp_free_dirents(dir_entries);

	أرجع ret;
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
		أرجع -1;
	}

	ret = download_dir_اندرونی(conn, src_canon, dst, 0,
	    dirattrib, preserve_flag, print_flag, resume_flag, fsync_flag,
	    follow_link_flag, inplace_flag);
	حرر(src_canon);
	أرجع ret;
}

صحيح
sftp_upload(بنية sftp_conn *conn, ثابت حرف *local_رستہ,
    ثابت حرف *remote_رستہ, صحيح preserve_flag, صحيح resume,
    صحيح fsync_flag, صحيح inplace_flag)
{
	صحيح r, local_fd;
	u_int openmode, id, حالت = SSH2_FX_OK, status2, reordered = 0;
	off_t وتھ, ترقی_counter;
	u_char type, *handle, *انکڑے;
	بنية sshbuf *پیغام;
	بنية stat sb;
	Attrib a, t, c;
	uint32_t startid, ackid;
	uint64_t highwater = 0, maxack = 0;
	بنية request *ack = عدم;
	بنية بینتیاں acks;
	ناپ_t handle_len;

	debug2_f("upload local \"%s\" to remote \"%s\"",
	    local_رستہ, remote_رستہ);

	TAILQ_INIT(&acks);

	إذا ((local_fd = open(local_رستہ, O_RDONLY)) == -1) {
		error("open local \"%s\": %s", local_رستہ, strerror(errno));
		أرجع(-1);
	}
	إذا (fstat(local_fd, &sb) == -1) {
		error("fstat local \"%s\": %s", local_رستہ, strerror(errno));
		close(local_fd);
		أرجع(-1);
	}
	إذا (!S_ISREG(sb.st_mode)) {
		error("local \"%s\" is not a regular file", local_رستہ);
		close(local_fd);
		أرجع(-1);
	}
	stat_منزل_attrib(&sb, &a);

	a.flags &= ~SSH2_FILEXFER_ATTR_ناپ;
	a.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a.perm &= 0777;
	إذا (!preserve_flag)
		a.flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;

	إذا (resume) {
		/* Get remote file size if it exists */
		إذا (sftp_stat(conn, remote_رستہ, 0, &c) != 0) {
			close(local_fd);
			أرجع -1;
		}

		إذا ((off_t)c.ناپ >= sb.st_size) {
			error("resume \"%s\": destination file "
			    "same size or larger", local_رستہ);
			close(local_fd);
			أرجع -1;
		}

		إذا (lseek(local_fd, (off_t)c.ناپ, SEEK_SET) == -1) {
			close(local_fd);
			أرجع -1;
		}
		highwater = c.ناپ;
	}

	openmode = SSH2_FXF_WRITE|SSH2_FXF_CREAT;
	إذا (resume)
		openmode |= SSH2_FXF_APPEND;
	وإلا إذا (!inplace_flag)
		openmode |= SSH2_FXF_TRUNC;

	/* Send open request */
	إذا (send_open(conn, remote_رستہ, "dest", openmode, &a,
	    &handle, &handle_len) != 0) {
		close(local_fd);
		أرجع -1;
	}

	id = conn->پیغام_id;
	startid = ackid = id + 1;
	انکڑے = xmalloc(conn->upload_buflen);

	/* Read from local and write to remote */
	وتھ = ترقی_counter = (resume ? c.ناپ : 0);
	إذا (showprogress) {
		شروع_ترقی_meter(ترقی_meter_رستہ(local_رستہ),
		    sb.st_size, &ترقی_counter);
	}

	إذا ((پیغام = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	لكل (;;) {
		صحيح len;

		/*
		 * Can't use atomicio here because it returns 0 on EOF,
		 * thus losing the last block of the file.
		 * Simulate an EOF on interrupt, allowing ACKs from the
		 * server to drain.
		 */
		إذا (interrupted || حالت != SSH2_FX_OK)
			len = 0;
		وإلا افعل
			len = اقرأ(local_fd, انکڑے, conn->upload_buflen);
		طالما ((len == -1) &&
		    (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK));

		إذا (len == -1) {
			fatal("read local \"%s\": %s",
			    local_رستہ, strerror(errno));
		} وإلا إذا (len != 0) {
			ack = request_قطار_وچ_پاؤ(&acks, ++id, len, وتھ);
			sshbuf_reset(پیغام);
			إذا ((r = sshbuf_put_u8(پیغام, SSH2_FXP_WRITE)) != 0 ||
			    (r = sshbuf_put_u32(پیغام, ack->id)) != 0 ||
			    (r = sshbuf_put_string(پیغام, handle,
			    handle_len)) != 0 ||
			    (r = sshbuf_put_u64(پیغام, وتھ)) != 0 ||
			    (r = sshbuf_put_string(پیغام, انکڑے, len)) != 0)
				fatal_fr(r, "compose");
			send_پیغام(conn, پیغام);
			debug3("Sent message SSH2_FXP_WRITE I:%u O:%llu S:%u",
			    id, (بنانشانی لما لما)وتھ, len);
		} وإلا إذا (TAILQ_FIRST(&acks) == عدم)
			اكسر;

		إذا (ack == عدم)
			fatal("Unexpected ACK %u", id);

		إذا (id == startid || len == 0 ||
		    id - ackid >= conn->عدد_بینتیاں) {
			u_int rid;

			sshbuf_reset(پیغام);
			get_پیغام(conn, پیغام);
			إذا ((r = sshbuf_get_u8(پیغام, &type)) != 0 ||
			    (r = sshbuf_get_u32(پیغام, &rid)) != 0)
				fatal_fr(r, "parse");

			إذا (type != SSH2_FXP_حالت)
				fatal("Expected SSH2_FXP_STATUS(%d) packet, "
				    "got %d", SSH2_FXP_حالت, type);

			إذا ((r = sshbuf_get_u32(پیغام, &status2)) != 0)
				fatal_fr(r, "parse status");
			debug3("SSH2_FXP_STATUS %u", status2);
			إذا (status2 != SSH2_FX_OK)
				حالت = status2; /* remember errors */

			/* Find the request in our queue */
			إذا ((ack = request_لبھو(&acks, rid)) == عدم)
				fatal("Can't find request for ID %u", rid);
			TAILQ_REMOVE(&acks, ack, tq);
			debug3("In write loop, ack for %u %zu bytes at %lld",
			    ack->id, ack->len, (بنانشانی لما لما)ack->وتھ);
			++ackid;
			ترقی_counter += ack->len;
			/*
			 * Track both the highest offset acknowledged and the
			 * highest *contiguous* offset acknowledged.
			 * We'll need the latter for ftruncate()ing
			 * interrupted transfers.
			 */
			إذا (maxack < ack->وتھ + ack->len)
				maxack = ack->وتھ + ack->len;
			إذا (!reordered && ack->وتھ <= highwater)
				highwater = maxack;
			وإلا إذا (!reordered && ack->وتھ > highwater) {
				debug3_f("server reordered ACKs");
				reordered = 1;
			}
			حرر(ack);
		}
		وتھ += len;
		إذا (وتھ < 0)
			fatal_f("offset < 0");
	}
	sshbuf_free(پیغام);

	إذا (showprogress)
		stop_ترقی_meter();
	حرر(انکڑے);

	إذا (حالت == SSH2_FX_OK && !interrupted) {
		/* we got everything */
		highwater = maxack;
	}
	إذا (حالت != SSH2_FX_OK) {
		error("write remote \"%s\": %s", remote_رستہ, fx2txt(حالت));
		حالت = SSH2_FX_FAILURE;
	}

	إذا (inplace_flag || (resume && (حالت != SSH2_FX_OK || interrupted))) {
		debug("truncating at %llu", (بنانشانی لما لما)highwater);
		attrib_clear(&t);
		t.flags = SSH2_FILEXFER_ATTR_ناپ;
		t.ناپ = highwater;
		sftp_fsetstat(conn, handle, handle_len, &t);
	}

	إذا (close(local_fd) == -1) {
		error("close local \"%s\": %s", local_رستہ, strerror(errno));
		حالت = SSH2_FX_FAILURE;
	}

	/* Override umask and utimes if asked */
	إذا (preserve_flag)
		sftp_fsetstat(conn, handle, handle_len, &a);

	إذا (fsync_flag)
		(فراغ)sftp_fsync(conn, handle, handle_len);

	إذا (sftp_close(conn, handle, handle_len) != 0)
		حالت = SSH2_FX_FAILURE;

	حرر(handle);

	أرجع حالت == SSH2_FX_OK ? 0 : -1;
}

ساكن صحيح
upload_dir_اندرونی(بنية sftp_conn *conn, ثابت حرف *src, ثابت حرف *dst,
    صحيح ڈونگھائی, صحيح preserve_flag, صحيح print_flag, صحيح resume, صحيح fsync_flag,
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

	إذا (ڈونگھائی >= MAX_DIR_ڈونگھائی) {
		error("Maximum directory depth exceeded: %d levels", ڈونگھائی);
		أرجع -1;
	}

	إذا (stat(src, &sb) == -1) {
		error("stat local \"%s\": %s", src, strerror(errno));
		أرجع -1;
	}
	إذا (!S_ISDIR(sb.st_mode)) {
		error("\"%s\" is not a directory", src);
		أرجع -1;
	}
	إذا (print_flag && print_flag != SFTP_ترقی_ONLY)
		mprintf("Entering %s\n", src);

	stat_منزل_attrib(&sb, &a);
	a.flags &= ~SSH2_FILEXFER_ATTR_ناپ;
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
			أرجع -1;
		إذا (!S_ISDIR(dirattrib.perm)) {
			error("\"%s\" exists but is not a directory", dst);
			أرجع -1;
		}
	}
	a.perm = saved_perm;

	إذا ((dirp = opendir(src)) == عدم) {
		error("local opendir \"%s\": %s", src, strerror(errno));
		أرجع -1;
	}

	طالما (((dp = readdir(dirp)) != عدم) && !interrupted) {
		إذا (dp->d_ino == 0)
			استمر;
		حرر(new_dst);
		حرر(new_src);
		filename = dp->d_name;
		new_dst = sftp_رستہ_append(dst, filename);
		new_src = sftp_رستہ_append(src, filename);

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
			إذا (upload_dir_اندرونی(conn, new_src, new_dst,
			    ڈونگھائی + 1, preserve_flag, print_flag, resume,
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
	أرجع ret;
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
		أرجع -1;
	}

	ret = upload_dir_اندرونی(conn, src, dst_canon, 0, preserve_flag,
	    print_flag, resume, fsync_flag, follow_link_flag, inplace_flag);

	حرر(dst_canon);
	أرجع ret;
}

ساكن فراغ
handle_dest_replies(بنية sftp_conn *منزل, ثابت حرف *منزل_رستہ, صحيح synchronous,
    u_int *nreqsp, u_int *write_errorp)
{
	بنية sshbuf *پیغام;
	u_char type;
	u_int id, حالت;
	صحيح r;
	بنية pollfd pfd;

	إذا ((پیغام = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");

	/* Try to eat replies from the upload side */
	طالما (*nreqsp > 0) {
		debug3_f("%u outstanding replies", *nreqsp);
		إذا (!synchronous) {
			/* Bail out if no data is ready to be read */
			pfd.fd = منزل->fd_وچ;
			pfd.events = POLLIN;
			إذا ((r = poll(&pfd, 1, 0)) == -1) {
				إذا (errno == EINTR)
					اكسر;
				fatal_f("poll: %s", strerror(errno));
			} وإلا إذا (r == 0)
				اكسر; /* fd not ready */
		}
		sshbuf_reset(پیغام);
		get_پیغام(منزل, پیغام);

		إذا ((r = sshbuf_get_u8(پیغام, &type)) != 0 ||
		    (r = sshbuf_get_u32(پیغام, &id)) != 0)
			fatal_fr(r, "dest parse");
		debug3("Received dest reply T:%u I:%u R:%u", type, id, *nreqsp);
		إذا (type != SSH2_FXP_حالت) {
			fatal_f("Expected SSH2_FXP_STATUS(%d) packet, got %d",
			    SSH2_FXP_حالت, type);
		}
		إذا ((r = sshbuf_get_u32(پیغام, &حالت)) != 0)
			fatal_fr(r, "parse dest status");
		debug3("dest SSH2_FXP_STATUS %u", حالت);
		إذا (حالت != SSH2_FX_OK) {
			/* record first error */
			إذا (*write_errorp == 0)
				*write_errorp = حالت;
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

صحيح
sftp_crossload(بنية sftp_conn *from, بنية sftp_conn *منزل,
    ثابت حرف *from_رستہ, ثابت حرف *منزل_رستہ,
    Attrib *a, صحيح preserve_flag)
{
	بنية sshbuf *پیغام;
	صحيح write_error, read_error, r, تکیا_zerolen = 0;
	uint64_t وتھ = 0, ناپ;
	u_int id, buflen, عدد_req, max_req, حالت = SSH2_FX_OK;
	u_int عدد_upload_req;
	off_t ترقی_counter;
	u_char *from_handle, *منزل_handle;
	ناپ_t from_handle_len, منزل_handle_len;
	بنية بینتیاں بینتیاں;
	بنية request *req;
	u_char type;
	Attrib attr;

	debug2_f("crossload src \"%s\" to dst \"%s\"", from_رستہ, منزل_رستہ);

	TAILQ_INIT(&بینتیاں);

	إذا (a == عدم) {
		إذا (sftp_stat(from, from_رستہ, 0, &attr) != 0)
			أرجع -1;
		a = &attr;
	}

	إذا ((a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) &&
	    (!S_ISREG(a->perm))) {
		error("download \"%s\": not a regular file", from_رستہ);
		أرجع(-1);
	}
	إذا (a->flags & SSH2_FILEXFER_ATTR_ناپ)
		ناپ = a->ناپ;
	وإلا
		ناپ = 0;

	buflen = from->download_buflen;
	إذا (buflen > منزل->upload_buflen)
		buflen = منزل->upload_buflen;

	/* Send open request to read side */
	إذا (send_open(from, from_رستہ, "origin", SSH2_FXF_READ, عدم,
	    &from_handle, &from_handle_len) != 0)
		أرجع -1;

	/* Send open request to write side */
	a->flags &= ~SSH2_FILEXFER_ATTR_ناپ;
	a->flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a->perm &= 0777;
	إذا (!preserve_flag)
		a->flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;
	إذا (send_open(منزل, منزل_رستہ, "dest",
	    SSH2_FXF_WRITE|SSH2_FXF_CREAT|SSH2_FXF_TRUNC, a,
	    &منزل_handle, &منزل_handle_len) != 0) {
		sftp_close(from, from_handle, from_handle_len);
		أرجع -1;
	}

	/* Read from remote "from" and write to remote "to" */
	وتھ = 0;
	write_error = read_error = عدد_req = عدد_upload_req = 0;
	max_req = 1;
	ترقی_counter = 0;

	إذا (showprogress && ناپ != 0) {
		شروع_ترقی_meter(ترقی_meter_رستہ(from_رستہ),
		    ناپ, &ترقی_counter);
	}
	إذا ((پیغام = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	طالما (عدد_req > 0 || max_req > 0) {
		u_char *انکڑے;
		ناپ_t len;

		/*
		 * Simulate EOF on interrupt: stop sending new requests and
		 * allow outstanding requests to drain gracefully
		 */
		إذا (interrupted) {
			إذا (عدد_req == 0) /* If we haven't started yet... */
				اكسر;
			max_req = 0;
		}

		/* Send some more requests */
		طالما (عدد_req < max_req) {
			debug3("Request range %llu -> %llu (%d/%d)",
			    (بنانشانی لما لما)وتھ,
			    (بنانشانی لما لما)وتھ + buflen - 1,
			    عدد_req, max_req);
			req = request_قطار_وچ_پاؤ(&بینتیاں, from->پیغام_id++,
			    buflen, وتھ);
			وتھ += buflen;
			عدد_req++;
			send_read_request(from, req->id, req->وتھ,
			    req->len, from_handle, from_handle_len);
		}

		/* Try to eat replies from the upload side (nonblocking) */
		handle_dest_replies(منزل, منزل_رستہ, 0,
		    &عدد_upload_req, &write_error);

		sshbuf_reset(پیغام);
		get_پیغام(from, پیغام);
		إذا ((r = sshbuf_get_u8(پیغام, &type)) != 0 ||
		    (r = sshbuf_get_u32(پیغام, &id)) != 0)
			fatal_fr(r, "parse");
		debug3("Received origin reply T:%u I:%u R:%d",
		    type, id, max_req);

		/* Find the request in our queue */
		إذا ((req = request_لبھو(&بینتیاں, id)) == عدم)
			fatal("Unexpected reply %u", id);

		بدل (type) {
		حالة SSH2_FXP_حالت:
			إذا ((r = sshbuf_get_u32(پیغام, &حالت)) != 0)
				fatal_fr(r, "parse status");
			إذا (حالت != SSH2_FX_EOF)
				read_error = 1;
			max_req = 0;
			TAILQ_REMOVE(&بینتیاں, req, tq);
			حرر(req);
			عدد_req--;
			اكسر;
		حالة SSH2_FXP_انکڑے:
			إذا ((r = sshbuf_get_string(پیغام, &انکڑے, &len)) != 0)
				fatal_fr(r, "parse data");
			debug3("Received data %llu -> %llu",
			    (بنانشانی لما لما)req->وتھ,
			    (بنانشانی لما لما)req->وتھ + len - 1);
			إذا (len > req->len)
				fatal("Received more data than asked for "
				    "%zu > %zu", len, req->len);
			إذا (len == 0) {
				إذا (تکیا_zerolen)
					fatal_f("server sent zero data length");
				تکیا_zerolen = 1;
			}

			/* Write this chunk out to the destination */
			sshbuf_reset(پیغام);
			إذا ((r = sshbuf_put_u8(پیغام, SSH2_FXP_WRITE)) != 0 ||
			    (r = sshbuf_put_u32(پیغام, منزل->پیغام_id++)) != 0 ||
			    (r = sshbuf_put_string(پیغام, منزل_handle,
			    منزل_handle_len)) != 0 ||
			    (r = sshbuf_put_u64(پیغام, req->وتھ)) != 0 ||
			    (r = sshbuf_put_string(پیغام, انکڑے, len)) != 0)
				fatal_fr(r, "compose write");
			send_پیغام(منزل, پیغام);
			debug3("Sent message SSH2_FXP_WRITE I:%u O:%llu S:%zu",
			    id, (بنانشانی لما لما)وتھ, len);
			عدد_upload_req++;
			ترقی_counter += len;
			حرر(انکڑے);

			إذا (len == req->len) {
				TAILQ_REMOVE(&بینتیاں, req, tq);
				حرر(req);
				عدد_req--;
			} وإلا {
				/* Resend the request for the missing data */
				debug3("Short data block, re-requesting "
				    "%llu -> %llu (%2d)",
				    (بنانشانی لما لما)req->وتھ + len,
				    (بنانشانی لما لما)req->وتھ +
				    req->len - 1, عدد_req);
				req->id = from->پیغام_id++;
				req->len -= len;
				req->وتھ += len;
				send_read_request(from, req->id,
				    req->وتھ, req->len,
				    from_handle, from_handle_len);
				/* Reduce the request size */
				إذا (len < buflen)
					buflen = ودھ_توں_ودھ(MIN_READ_ناپ, len);
			}
			إذا (max_req > 0) { /* max_req = 0 iff EOF received */
				إذا (ناپ > 0 && وتھ > ناپ) {
					/* Only one request at a time
					 * after the expected EOF */
					debug3("Finish at %llu (%2d)",
					    (بنانشانی لما لما)وتھ,
					    عدد_req);
					max_req = 1;
				} وإلا إذا (max_req < from->عدد_بینتیاں) {
					++max_req;
				}
			}
			اكسر;
		افتراضي:
			fatal("Expected SSH2_FXP_DATA(%u) packet, got %u",
			    SSH2_FXP_انکڑے, type);
		}
	}

	إذا (showprogress && ناپ)
		stop_ترقی_meter();

	/* Drain replies from the server (blocking) */
	debug3_f("waiting for %u replies from destination", عدد_upload_req);
	handle_dest_replies(منزل, منزل_رستہ, 1, &عدد_upload_req, &write_error);

	/* Sanity check */
	إذا (TAILQ_FIRST(&بینتیاں) != عدم)
		fatal("Transfer complete, but requests still in queue");
	/* Truncate at 0 length on interrupt or error to avoid holes at dest */
	إذا (read_error || write_error || interrupted) {
		debug("truncating \"%s\" at 0", منزل_رستہ);
		sftp_close(منزل, منزل_handle, منزل_handle_len);
		حرر(منزل_handle);
		إذا (send_open(منزل, منزل_رستہ, "dest",
		    SSH2_FXF_WRITE|SSH2_FXF_CREAT|SSH2_FXF_TRUNC, a,
		    &منزل_handle, &منزل_handle_len) != 0) {
			error("dest truncate \"%s\" failed", منزل_رستہ);
			منزل_handle = عدم;
		}
	}
	إذا (read_error) {
		error("read origin \"%s\": %s", from_رستہ, fx2txt(حالت));
		حالت = -1;
		sftp_close(from, from_handle, from_handle_len);
		إذا (منزل_handle != عدم)
			sftp_close(منزل, منزل_handle, منزل_handle_len);
	} وإلا إذا (write_error) {
		error("write dest \"%s\": %s", منزل_رستہ, fx2txt(write_error));
		حالت = SSH2_FX_FAILURE;
		sftp_close(from, from_handle, from_handle_len);
		إذا (منزل_handle != عدم)
			sftp_close(منزل, منزل_handle, منزل_handle_len);
	} وإلا {
		إذا (sftp_close(from, from_handle, from_handle_len) != 0 ||
		    interrupted)
			حالت = -1;
		وإلا
			حالت = SSH2_FX_OK;
		إذا (منزل_handle != عدم) {
			/* Need to resend utimes after write */
			إذا (preserve_flag)
				sftp_fsetstat(منزل, منزل_handle, منزل_handle_len, a);
			sftp_close(منزل, منزل_handle, منزل_handle_len);
		}
	}
	sshbuf_free(پیغام);
	حرر(from_handle);
	حرر(منزل_handle);

	أرجع حالت == SSH2_FX_OK ? 0 : -1;
}

ساكن صحيح
crossload_dir_اندرونی(بنية sftp_conn *from, بنية sftp_conn *منزل,
    ثابت حرف *from_رستہ, ثابت حرف *منزل_رستہ,
    صحيح ڈونگھائی, Attrib *dirattrib, صحيح preserve_flag, صحيح print_flag,
    صحيح follow_link_flag)
{
	صحيح i, ret = 0, created = 0;
	SFTP_DIRENT **dir_entries;
	حرف *filename, *new_from_رستہ = عدم, *new_منزل_رستہ = عدم;
	منوال_t منوال = 0777;
	Attrib *a, curdir, ldirattrib, newdir, lsym;

	debug2_f("crossload dir src \"%s\" to dst \"%s\"", from_رستہ, منزل_رستہ);

	إذا (ڈونگھائی >= MAX_DIR_ڈونگھائی) {
		error("Maximum directory depth exceeded: %d levels", ڈونگھائی);
		أرجع -1;
	}

	إذا (dirattrib == عدم) {
		إذا (sftp_stat(from, from_رستہ, 1, &ldirattrib) != 0) {
			error("stat remote \"%s\" failed", from_رستہ);
			أرجع -1;
		}
		dirattrib = &ldirattrib;
	}
	إذا (!S_ISDIR(dirattrib->perm)) {
		error("\"%s\" is not a directory", from_رستہ);
		أرجع -1;
	}
	إذا (print_flag && print_flag != SFTP_ترقی_ONLY)
		mprintf("Retrieving %s\n", from_رستہ);

	curdir = *dirattrib; /* dirattrib will be clobbered */
	curdir.flags &= ~SSH2_FILEXFER_ATTR_ناپ;
	curdir.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	إذا ((curdir.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) == 0) {
		debug("Origin did not send permissions for "
		    "directory \"%s\"", منزل_رستہ);
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
	إذا (sftp_mkdir(منزل, منزل_رستہ, &curdir, 0) == 0)
		created = 1;
	وإلا {
		إذا (sftp_stat(منزل, منزل_رستہ, 0, &newdir) != 0)
			أرجع -1;
		إذا (!S_ISDIR(newdir.perm)) {
			error("\"%s\" exists but is not a directory", منزل_رستہ);
			أرجع -1;
		}
	}
	curdir.perm = منوال;

	إذا (sftp_readdir(from, from_رستہ, &dir_entries) == -1) {
		error("origin readdir \"%s\" failed", from_رستہ);
		أرجع -1;
	}

	لكل (i = 0; dir_entries[i] != عدم && !interrupted; i++) {
		حرر(new_from_رستہ);
		حرر(new_منزل_رستہ);

		filename = dir_entries[i]->filename;
		new_from_رستہ = sftp_رستہ_append(from_رستہ, filename);
		new_منزل_رستہ = sftp_رستہ_append(منزل_رستہ, filename);

		a = &dir_entries[i]->a;
		إذا (S_ISLNK(a->perm)) {
			إذا (!follow_link_flag) {
				logit("%s: not a regular file", filename);
				استمر;
			}
			/* Replace the stat contents with the symlink target */
			إذا (sftp_stat(from, new_from_رستہ, 1, &lsym) != 0) {
				logit("remote stat \"%s\" failed",
				    new_from_رستہ);
				ret = -1;
				استمر;
			}
			a = &lsym;
		}
		إذا (S_ISDIR(a->perm)) {
			إذا (strcmp(filename, ".") == 0 ||
			    strcmp(filename, "..") == 0)
				استمر;
			إذا (crossload_dir_اندرونی(from, منزل,
			    new_from_رستہ, new_منزل_رستہ,
			    ڈونگھائی + 1, a, preserve_flag,
			    print_flag, follow_link_flag) == -1)
				ret = -1;
		} وإلا إذا (S_ISREG(a->perm)) {
			إذا (sftp_crossload(from, منزل, new_from_رستہ,
			    new_منزل_رستہ, a, preserve_flag) == -1) {
				error("crossload \"%s\" to \"%s\" failed",
				    new_from_رستہ, new_منزل_رستہ);
				ret = -1;
			}
		} وإلا {
			logit("origin \"%s\": not a regular file",
			    new_from_رستہ);
		}
	}
	حرر(new_منزل_رستہ);
	حرر(new_from_رستہ);

	إذا (created || preserve_flag)
		sftp_setstat(منزل, منزل_رستہ, &curdir);

	sftp_free_dirents(dir_entries);

	أرجع ret;
}

صحيح
sftp_crossload_dir(بنية sftp_conn *from, بنية sftp_conn *منزل,
    ثابت حرف *from_رستہ, ثابت حرف *منزل_رستہ,
    Attrib *dirattrib, صحيح preserve_flag, صحيح print_flag, صحيح follow_link_flag)
{
	حرف *from_رستہ_canon;
	صحيح ret;

	إذا ((from_رستہ_canon = sftp_realpath(from, from_رستہ)) == عدم) {
		error("crossload \"%s\": path canonicalization failed",
		    from_رستہ);
		أرجع -1;
	}

	ret = crossload_dir_اندرونی(from, منزل, from_رستہ_canon, منزل_رستہ, 0,
	    dirattrib, preserve_flag, print_flag, follow_link_flag);
	حرر(from_رستہ_canon);
	أرجع ret;
}

صحيح
sftp_can_get_users_groups_by_id(بنية sftp_conn *conn)
{
	أرجع (conn->exts & SFTP_EXT_GETUSERSGROUPS_BY_ID) != 0;
}

صحيح
sftp_get_users_groups_by_id(بنية sftp_conn *conn,
    ثابت u_int *uids, u_int nuids,
    ثابت u_int *gids, u_int ngids,
    حرف ***usernamesp, حرف ***groupnamesp)
{
	بنية sshbuf *پیغام, *uidbuf, *gidbuf;
	u_int i, expected_id, id;
	حرف *name, **usernames = عدم, **groupnames = عدم;
	u_char type;
	صحيح r;

	*usernamesp = *groupnamesp = عدم;
	إذا (!sftp_can_get_users_groups_by_id(conn))
		أرجع SSH_ERR_FEATURE_UNSUPPORTED;

	إذا ((پیغام = sshbuf_new()) == عدم ||
	    (uidbuf = sshbuf_new()) == عدم ||
	    (gidbuf = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	expected_id = id = conn->پیغام_id++;
	debug2("Sending SSH2_FXP_EXTENDED(users-groups-by-id@openssh.com)");
	لكل (i = 0; i < nuids; i++) {
		إذا ((r = sshbuf_put_u32(uidbuf, uids[i])) != 0)
			fatal_fr(r, "compose uids");
	}
	لكل (i = 0; i < ngids; i++) {
		إذا ((r = sshbuf_put_u32(gidbuf, gids[i])) != 0)
			fatal_fr(r, "compose gids");
	}
	إذا ((r = sshbuf_put_u8(پیغام, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, id)) != 0 ||
	    (r = sshbuf_put_cstring(پیغام,
	    "users-groups-by-id@openssh.com")) != 0 ||
	    (r = sshbuf_put_stringb(پیغام, uidbuf)) != 0 ||
	    (r = sshbuf_put_stringb(پیغام, gidbuf)) != 0)
		fatal_fr(r, "compose");
	send_پیغام(conn, پیغام);
	get_پیغام(conn, پیغام);
	إذا ((r = sshbuf_get_u8(پیغام, &type)) != 0 ||
	    (r = sshbuf_get_u32(پیغام, &id)) != 0)
		fatal_fr(r, "parse");
	إذا (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	إذا (type == SSH2_FXP_حالت) {
		u_int حالت;
		حرف *errmsg;

		إذا ((r = sshbuf_get_u32(پیغام, &حالت)) != 0 ||
		    (r = sshbuf_get_cstring(پیغام, &errmsg, عدم)) != 0)
			fatal_fr(r, "parse status");
		error("users-groups-by-id %s",
		    *errmsg == '\0' ? fx2txt(حالت) : errmsg);
		حرر(errmsg);
		sshbuf_free(پیغام);
		sshbuf_free(uidbuf);
		sshbuf_free(gidbuf);
		أرجع -1;
	} وإلا إذا (type != SSH2_FXP_EXTENDED_جواب)
		fatal("Expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_جواب, type);

	/* reuse */
	sshbuf_free(uidbuf);
	sshbuf_free(gidbuf);
	uidbuf = gidbuf = عدم;
	إذا ((r = sshbuf_froms(پیغام, &uidbuf)) != 0 ||
	    (r = sshbuf_froms(پیغام, &gidbuf)) != 0)
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
	sshbuf_free(پیغام);
	/* success */
	*usernamesp = usernames;
	*groupnamesp = groupnames;
	أرجع 0;
}

حرف *
sftp_رستہ_append(ثابت حرف *p1, ثابت حرف *p2)
{
	حرف *ret;
	ناپ_t len = لڑی_لمبائی(p1) + لڑی_لمبائی(p2) + 2;

	ret = xmalloc(len);
	strlcpy(ret, p1, len);
	إذا (p1[0] != '\0' && p1[لڑی_لمبائی(p1) - 1] != '/')
		strlcat(ret, "/", len);
	strlcat(ret, p2, len);

	أرجع(ret);
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
	إذا (p && !رستہ_absolute(p)) {
		abs_str = sftp_رستہ_append(pwd, p);
		حرر(p);
		أرجع(abs_str);
	} وإلا
		أرجع(p);
}

صحيح
sftp_remote_is_dir(بنية sftp_conn *conn, ثابت حرف *رستہ)
{
	Attrib a;

	/* XXX: report errors? */
	إذا (sftp_stat(conn, رستہ, 1, &a) != 0)
		أرجع(0);
	إذا (!(a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS))
		أرجع(0);
	أرجع S_ISDIR(a.perm);
}


/* Check whether path returned from glob(..., GLOB_MARK, ...) is a directory */
صحيح
sftp_globpath_is_dir(ثابت حرف *pathname)
{
	ناپ_t l = لڑی_لمبائی(pathname);

	أرجع l > 0 && pathname[l - 1] == '/';
}

