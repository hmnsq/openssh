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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/queue.h>
#અન્તર્ભાવ <sys/stat.h>
#અન્તર્ભાવ <sys/time.h>
#અન્તર્ભાવ <sys/statvfs.h>
#અન્તર્ભાવ <sys/uio.h>

#અન્તર્ભાવ <dirent.h>
#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <fcntl.h>
#અન્તર્ભાવ <poll.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "atomicio.h"
#અન્તર્ભાવ "progressmeter.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "utf8.h"

#અન્તર્ભાવ "sftp.h"
#અન્તર્ભાવ "sftp-common.h"
#અન્તર્ભાવ "sftp-client.h"

બાહ્ય અસ્થિર sig_atomic_t interrupted;
બાહ્ય પૂર્ણાંક showprogress;

/* Default size of buffer for up/download (fix sftp.1 scp.1 if changed) */
#define DEFAULT_COPY_BUFLEN	32768

/* Default number of concurrent xfer requests (fix sftp.1 scp.1 if changed) */
#define DEFAULT_અંક_REQUESTS	64

/* Minimum amount of data to read at a time */
#define MIN_READ_SIZE	512

/* Maximum depth to descend in directory trees */
#define MAX_DIR_DEPTH 64

/* Directory separator characters */
#ifdef HAVE_CYGWIN
# define SFTP_DIRECTORY_CHARS      "/\\"
#નહીંતર /* HAVE_CYGWIN */
# define SFTP_DIRECTORY_CHARS      "/"
#endif /* HAVE_CYGWIN */

સંરચના sftp_conn {
	પૂર્ણાંક fd_in;
	પૂર્ણાંક fd_out;
	u_int download_buflen;
	u_int upload_buflen;
	u_int અંક_requests;
	u_int version;
	u_int સંદેશ_id;
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
	સંરચના bwlimit bwlimit_in, bwlimit_out;
};

/* Tracks in-progress requests during file transfers */
સંરચના request {
	u_int id;
	size_t len;
	uint64_t offset;
	TAILQ_ENTRY(request) tq;
};
TAILQ_HEAD(requests, request);

સ્થિર u_char *
get_handle(સંરચના sftp_conn *conn, u_int expected_id, size_t *len,
    અચલ અક્ષર *errfmt, ...) __attribute__((format(printf, 4, 5)));

સ્થિર સંરચના request *
request_enqueue(સંરચના requests *requests, u_int id, size_t len,
    uint64_t offset)
{
	સંરચના request *req;

	req = xcalloc(1, કદ(*req));
	req->id = id;
	req->len = len;
	req->offset = offset;
	TAILQ_INSERT_TAIL(requests, req, tq);
	પાછા req;
}

સ્થિર સંરચના request *
request_find(સંરચના requests *requests, u_int id)
{
	સંરચના request *req;

	માટે (req = TAILQ_FIRST(requests);
	    req != ખાલી && req->id != id;
	    req = TAILQ_NEXT(req, tq))
		;
	પાછા req;
}

સ્થિર પૂર્ણાંક
sftpio(શૂન્ય *_bwlimit, size_t amount)
{
	સંરચના bwlimit *bwlimit = (સંરચના bwlimit *)_bwlimit;

	refresh_progress_meter(0);
	જો (bwlimit != ખાલી)
		bandwidth_limit(bwlimit, amount);
	પાછા 0;
}

સ્થિર શૂન્ય
send_સંદેશ(સંરચના sftp_conn *conn, સંરચના sshbuf *m)
{
	u_char mlen[4];
	સંરચના iovec iov[2];

	જો (sshbuf_len(m) > SFTP_MAX_સંદેશ_LENGTH)
		fatal("Outbound message too long %zu", sshbuf_len(m));

	/* Send length first */
	put_u32(mlen, sshbuf_len(m));
	iov[0].iov_base = mlen;
	iov[0].iov_len = કદ(mlen);
	iov[1].iov_base = (u_char *)sshbuf_ptr(m);
	iov[1].iov_len = sshbuf_len(m);

	જો (atomiciov6(writev, conn->fd_out, iov, 2, sftpio,
	    conn->limit_kbps > 0 ? &conn->bwlimit_out : ખાલી) !=
	    sshbuf_len(m) + કદ(mlen))
		fatal("Couldn't send packet: %s", strerror(errno));

	sshbuf_reset(m);
}

સ્થિર શૂન્ય
get_સંદેશ_extended(સંરચના sftp_conn *conn, સંરચના sshbuf *m, પૂર્ણાંક initial)
{
	u_int સંદેશ_len;
	u_char *p;
	પૂર્ણાંક r;

	sshbuf_reset(m);
	જો ((r = sshbuf_reserve(m, 4, &p)) != 0)
		fatal_fr(r, "reserve");
	જો (atomicio6(પઠ, conn->fd_in, p, 4, sftpio,
	    conn->limit_kbps > 0 ? &conn->bwlimit_in : ખાલી) != 4) {
		જો (errno == EPIPE || errno == ECONNRESET)
			fatal("Connection closed");
		નહીંતર
			fatal("Couldn't read packet: %s", strerror(errno));
	}

	જો ((r = sshbuf_get_u32(m, &સંદેશ_len)) != 0)
		fatal_fr(r, "sshbuf_get_u32");
	જો (સંદેશ_len > SFTP_MAX_સંદેશ_LENGTH) {
		do_log2(initial ? SYSLOG_LEVEL_ERROR : SYSLOG_LEVEL_FATAL,
		    "Received message too long %u", સંદેશ_len);
		fatal("Ensure the remote shell produces no output "
		    "for non-interactive sessions.");
	}

	જો ((r = sshbuf_reserve(m, સંદેશ_len, &p)) != 0)
		fatal_fr(r, "reserve");
	જો (atomicio6(પઠ, conn->fd_in, p, સંદેશ_len, sftpio,
	    conn->limit_kbps > 0 ? &conn->bwlimit_in : ખાલી)
	    != સંદેશ_len) {
		જો (errno == EPIPE)
			fatal("Connection closed");
		નહીંતર
			fatal("Read packet: %s", strerror(errno));
	}
}

સ્થિર શૂન્ય
get_સંદેશ(સંરચના sftp_conn *conn, સંરચના sshbuf *m)
{
	get_સંદેશ_extended(conn, m, 0);
}

સ્થિર શૂન્ય
send_string_request(સંરચના sftp_conn *conn, u_int id, u_int code, અચલ અક્ષર *s,
    u_int len)
{
	સંરચના sshbuf *સંદેશ;
	પૂર્ણાંક r;

	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = sshbuf_put_u8(સંદેશ, code)) != 0 ||
	    (r = sshbuf_put_u32(સંદેશ, id)) != 0 ||
	    (r = sshbuf_put_string(સંદેશ, s, len)) != 0)
		fatal_fr(r, "compose");
	send_સંદેશ(conn, સંદેશ);
	debug3("Sent message fd %d T:%u I:%u", conn->fd_out, code, id);
	sshbuf_free(સંદેશ);
}

સ્થિર શૂન્ય
send_string_attrs_request(સંરચના sftp_conn *conn, u_int id, u_int code,
    અચલ શૂન્ય *s, u_int len, Attrib *a)
{
	સંરચના sshbuf *સંદેશ;
	પૂર્ણાંક r;

	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = sshbuf_put_u8(સંદેશ, code)) != 0 ||
	    (r = sshbuf_put_u32(સંદેશ, id)) != 0 ||
	    (r = sshbuf_put_string(સંદેશ, s, len)) != 0 ||
	    (r = encode_attrib(સંદેશ, a)) != 0)
		fatal_fr(r, "compose");
	send_સંદેશ(conn, સંદેશ);
	debug3("Sent message fd %d T:%u I:%u F:0x%04x M:%05o",
	    conn->fd_out, code, id, a->flags, a->perm);
	sshbuf_free(સંદેશ);
}

સ્થિર u_int
get_status(સંરચના sftp_conn *conn, u_int expected_id)
{
	સંરચના sshbuf *સંદેશ;
	u_char type;
	u_int id, status;
	પૂર્ણાંક r;

	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	get_સંદેશ(conn, સંદેશ);
	જો ((r = sshbuf_get_u8(સંદેશ, &type)) != 0 ||
	    (r = sshbuf_get_u32(સંદેશ, &id)) != 0)
		fatal_fr(r, "compose");

	જો (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	જો (type != SSH2_FXP_STATUS)
		fatal("Expected SSH2_FXP_STATUS(%u) packet, got %u",
		    SSH2_FXP_STATUS, type);

	જો ((r = sshbuf_get_u32(સંદેશ, &status)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(સંદેશ);

	debug3("SSH2_FXP_STATUS %u", status);

	પાછા status;
}

સ્થિર u_char *
get_handle(સંરચના sftp_conn *conn, u_int expected_id, size_t *len,
    અચલ અક્ષર *errfmt, ...)
{
	સંરચના sshbuf *સંદેશ;
	u_int id, status;
	u_char type;
	u_char *handle;
	અક્ષર errmsg[256];
	va_list args;
	પૂર્ણાંક r;

	va_start(args, errfmt);
	જો (errfmt != ખાલી)
		vsnprintf(errmsg, કદ(errmsg), errfmt, args);
	va_end(args);

	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	get_સંદેશ(conn, સંદેશ);
	જો ((r = sshbuf_get_u8(સંદેશ, &type)) != 0 ||
	    (r = sshbuf_get_u32(સંદેશ, &id)) != 0)
		fatal_fr(r, "parse");

	જો (id != expected_id)
		fatal("%s: ID mismatch (%u != %u)",
		    errfmt == ખાલી ? __func__ : errmsg, id, expected_id);
	જો (type == SSH2_FXP_STATUS) {
		જો ((r = sshbuf_get_u32(સંદેશ, &status)) != 0)
			fatal_fr(r, "parse status");
		જો (errfmt != ખાલી)
			error("%s: %s", errmsg, fx2txt(status));
		sshbuf_free(સંદેશ);
		પાછા(ખાલી);
	} નહીંતર જો (type != SSH2_FXP_HANDLE)
		fatal("%s: Expected SSH2_FXP_HANDLE(%u) packet, got %u",
		    errfmt == ખાલી ? __func__ : errmsg, SSH2_FXP_HANDLE, type);

	જો ((r = sshbuf_get_string(સંદેશ, &handle, len)) != 0)
		fatal_fr(r, "parse handle");
	sshbuf_free(સંદેશ);

	પાછા handle;
}

સ્થિર પૂર્ણાંક
get_decode_stat(સંરચના sftp_conn *conn, u_int expected_id, પૂર્ણાંક quiet, Attrib *a)
{
	સંરચના sshbuf *સંદેશ;
	u_int id;
	u_char type;
	પૂર્ણાંક r;
	Attrib attr;

	જો (a != ખાલી)
		memset(a, '\0', કદ(*a));
	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	get_સંદેશ(conn, સંદેશ);

	જો ((r = sshbuf_get_u8(સંદેશ, &type)) != 0 ||
	    (r = sshbuf_get_u32(સંદેશ, &id)) != 0)
		fatal_fr(r, "parse");

	જો (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	જો (type == SSH2_FXP_STATUS) {
		u_int status;

		જો ((r = sshbuf_get_u32(સંદેશ, &status)) != 0)
			fatal_fr(r, "parse status");
		જો (quiet)
			debug("stat remote: %s", fx2txt(status));
		નહીંતર
			error("stat remote: %s", fx2txt(status));
		sshbuf_free(સંદેશ);
		પાછા -1;
	} નહીંતર જો (type != SSH2_FXP_ATTRS) {
		fatal("Expected SSH2_FXP_ATTRS(%u) packet, got %u",
		    SSH2_FXP_ATTRS, type);
	}
	જો ((r = decode_attrib(સંદેશ, &attr)) != 0) {
		error_fr(r, "decode_attrib");
		sshbuf_free(સંદેશ);
		પાછા -1;
	}
	/* success */
	જો (a != ખાલી)
		*a = attr;
	debug3("Received stat reply T:%u I:%u F:0x%04x M:%05o",
	    type, id, attr.flags, attr.perm);
	sshbuf_free(સંદેશ);

	પાછા 0;
}

સ્થિર પૂર્ણાંક
get_decode_statvfs(સંરચના sftp_conn *conn, સંરચના sftp_statvfs *st,
    u_int expected_id, પૂર્ણાંક quiet)
{
	સંરચના sshbuf *સંદેશ;
	u_char type;
	u_int id;
	uint64_t flag;
	પૂર્ણાંક r;

	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	get_સંદેશ(conn, સંદેશ);

	જો ((r = sshbuf_get_u8(સંદેશ, &type)) != 0 ||
	    (r = sshbuf_get_u32(સંદેશ, &id)) != 0)
		fatal_fr(r, "parse");

	debug3("Received statvfs reply T:%u I:%u", type, id);
	જો (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	જો (type == SSH2_FXP_STATUS) {
		u_int status;

		જો ((r = sshbuf_get_u32(સંદેશ, &status)) != 0)
			fatal_fr(r, "parse status");
		જો (quiet)
			debug("remote statvfs: %s", fx2txt(status));
		નહીંતર
			error("remote statvfs: %s", fx2txt(status));
		sshbuf_free(સંદેશ);
		પાછા -1;
	} નહીંતર જો (type != SSH2_FXP_EXTENDED_REPLY) {
		fatal("Expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_REPLY, type);
	}

	memset(st, 0, કદ(*st));
	જો ((r = sshbuf_get_u64(સંદેશ, &st->f_bsize)) != 0 ||
	    (r = sshbuf_get_u64(સંદેશ, &st->f_frsize)) != 0 ||
	    (r = sshbuf_get_u64(સંદેશ, &st->f_blocks)) != 0 ||
	    (r = sshbuf_get_u64(સંદેશ, &st->f_bfree)) != 0 ||
	    (r = sshbuf_get_u64(સંદેશ, &st->f_bavail)) != 0 ||
	    (r = sshbuf_get_u64(સંદેશ, &st->f_files)) != 0 ||
	    (r = sshbuf_get_u64(સંદેશ, &st->f_ffree)) != 0 ||
	    (r = sshbuf_get_u64(સંદેશ, &st->f_favail)) != 0 ||
	    (r = sshbuf_get_u64(સંદેશ, &st->f_fsid)) != 0 ||
	    (r = sshbuf_get_u64(સંદેશ, &flag)) != 0 ||
	    (r = sshbuf_get_u64(સંદેશ, &st->f_namemax)) != 0)
		fatal_fr(r, "parse statvfs");

	st->f_flag = (flag & SSH2_FXE_STATVFS_ST_RDONLY) ? ST_RDONLY : 0;
	st->f_flag |= (flag & SSH2_FXE_STATVFS_ST_NOSUID) ? ST_NOSUID : 0;

	sshbuf_free(સંદેશ);

	પાછા 0;
}

સંરચના sftp_conn *
sftp_init(પૂર્ણાંક fd_in, પૂર્ણાંક fd_out, u_int transfer_buflen, u_int અંક_requests,
    uint64_t limit_kbps)
{
	u_char type;
	સંરચના sshbuf *સંદેશ;
	સંરચના sftp_conn *ret;
	પૂર્ણાંક r;

	ret = xcalloc(1, કદ(*ret));
	ret->સંદેશ_id = 1;
	ret->fd_in = fd_in;
	ret->fd_out = fd_out;
	ret->download_buflen = ret->upload_buflen =
	    transfer_buflen ? transfer_buflen : DEFAULT_COPY_BUFLEN;
	ret->અંક_requests =
	    અંક_requests ? અંક_requests : DEFAULT_અંક_REQUESTS;
	ret->exts = 0;
	ret->limit_kbps = 0;

	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = sshbuf_put_u8(સંદેશ, SSH2_FXP_INIT)) != 0 ||
	    (r = sshbuf_put_u32(સંદેશ, SSH2_FILEXFER_VERSION)) != 0)
		fatal_fr(r, "parse");

	send_સંદેશ(ret, સંદેશ);

	get_સંદેશ_extended(ret, સંદેશ, 1);

	/* Expecting a VERSION reply */
	જો ((r = sshbuf_get_u8(સંદેશ, &type)) != 0)
		fatal_fr(r, "parse type");
	જો (type != SSH2_FXP_VERSION) {
		error("Invalid packet back from SSH2_FXP_INIT (type %u)",
		    type);
		sshbuf_free(સંદેશ);
		મુક્ત(ret);
		પાછા(ખાલી);
	}
	જો ((r = sshbuf_get_u32(સંદેશ, &ret->version)) != 0)
		fatal_fr(r, "parse version");

	debug2("Remote version: %u", ret->version);

	/* Check for extensions */
	જ્યારે (sshbuf_len(સંદેશ) > 0) {
		અક્ષર *name;
		u_char *કિંમત;
		size_t vlen;
		પૂર્ણાંક known = 0;

		જો ((r = sshbuf_get_cstring(સંદેશ, &name, ખાલી)) != 0 ||
		    (r = sshbuf_get_string(સંદેશ, &કિંમત, &vlen)) != 0)
			fatal_fr(r, "parse extension");
		જો (strcmp(name, "posix-rename@openssh.com") == 0 &&
		    strcmp((અક્ષર *)કિંમત, "1") == 0) {
			ret->exts |= SFTP_EXT_POSIX_RENAME;
			known = 1;
		} નહીંતર જો (strcmp(name, "statvfs@openssh.com") == 0 &&
		    strcmp((અક્ષર *)કિંમત, "2") == 0) {
			ret->exts |= SFTP_EXT_STATVFS;
			known = 1;
		} નહીંતર જો (strcmp(name, "fstatvfs@openssh.com") == 0 &&
		    strcmp((અક્ષર *)કિંમત, "2") == 0) {
			ret->exts |= SFTP_EXT_FSTATVFS;
			known = 1;
		} નહીંતર જો (strcmp(name, "hardlink@openssh.com") == 0 &&
		    strcmp((અક્ષર *)કિંમત, "1") == 0) {
			ret->exts |= SFTP_EXT_HARDLINK;
			known = 1;
		} નહીંતર જો (strcmp(name, "fsync@openssh.com") == 0 &&
		    strcmp((અક્ષર *)કિંમત, "1") == 0) {
			ret->exts |= SFTP_EXT_FSYNC;
			known = 1;
		} નહીંતર જો (strcmp(name, "lsetstat@openssh.com") == 0 &&
		    strcmp((અક્ષર *)કિંમત, "1") == 0) {
			ret->exts |= SFTP_EXT_LSETSTAT;
			known = 1;
		} નહીંતર જો (strcmp(name, "limits@openssh.com") == 0 &&
		    strcmp((અક્ષર *)કિંમત, "1") == 0) {
			ret->exts |= SFTP_EXT_LIMITS;
			known = 1;
		} નહીંતર જો (strcmp(name, "expand-path@openssh.com") == 0 &&
		    strcmp((અક્ષર *)કિંમત, "1") == 0) {
			ret->exts |= SFTP_EXT_PATH_EXPAND;
			known = 1;
		} નહીંતર જો (strcmp(name, "copy-data") == 0 &&
		    strcmp((અક્ષર *)કિંમત, "1") == 0) {
			ret->exts |= SFTP_EXT_COPY_DATA;
			known = 1;
		} નહીંતર જો (strcmp(name,
		    "users-groups-by-id@openssh.com") == 0 &&
		    strcmp((અક્ષર *)કિંમત, "1") == 0) {
			ret->exts |= SFTP_EXT_GETUSERSGROUPS_BY_ID;
			known = 1;
		}
		જો (known) {
			debug2("Server supports extension \"%s\" revision %s",
			    name, કિંમત);
		} નહીંતર {
			debug2("Unrecognised server extension \"%s\"", name);
		}
		મુક્ત(name);
		મુક્ત(કિંમત);
	}

	sshbuf_free(સંદેશ);

	/* Query the server for its limits */
	જો (ret->exts & SFTP_EXT_LIMITS) {
		સંરચના sftp_limits limits;
		જો (sftp_get_limits(ret, &limits) != 0)
			fatal_f("limits failed");

		/* If the caller did not specify, find a good value */
		જો (transfer_buflen == 0) {
			ret->download_buflen = MINIMUM(limits.read_length,
			    SFTP_MAX_સંદેશ_LENGTH - 1024);
			ret->upload_buflen = MINIMUM(limits.write_length,
			    SFTP_MAX_સંદેશ_LENGTH - 1024);
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
	જો (ret->version == 0) {
		ret->download_buflen = MINIMUM(ret->download_buflen, 20480);
		ret->upload_buflen = MINIMUM(ret->upload_buflen, 20480);
	}

	ret->limit_kbps = limit_kbps;
	જો (ret->limit_kbps > 0) {
		bandwidth_limit_init(&ret->bwlimit_in, ret->limit_kbps,
		    ret->download_buflen);
		bandwidth_limit_init(&ret->bwlimit_out, ret->limit_kbps,
		    ret->upload_buflen);
	}

	પાછા ret;
}

શૂન્ય
sftp_free(સંરચના sftp_conn *conn)
{
	જો (conn == ખાલી)
		પાછા;
	freezero(conn, કદ(*conn));
}

u_int
sftp_proto_version(સંરચના sftp_conn *conn)
{
	પાછા conn->version;
}

પૂર્ણાંક
sftp_get_limits(સંરચના sftp_conn *conn, સંરચના sftp_limits *limits)
{
	u_int id, સંદેશ_id;
	u_char type;
	સંરચના sshbuf *સંદેશ;
	પૂર્ણાંક r;

	જો ((conn->exts & SFTP_EXT_LIMITS) == 0) {
		error("Server does not support limits@openssh.com extension");
		પાછા -1;
	}

	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");

	id = conn->સંદેશ_id++;
	જો ((r = sshbuf_put_u8(સંદેશ, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(સંદેશ, id)) != 0 ||
	    (r = sshbuf_put_cstring(સંદેશ, "limits@openssh.com")) != 0)
		fatal_fr(r, "compose");
	send_સંદેશ(conn, સંદેશ);
	debug3("Sent message limits@openssh.com I:%u", id);

	get_સંદેશ(conn, સંદેશ);

	જો ((r = sshbuf_get_u8(સંદેશ, &type)) != 0 ||
	    (r = sshbuf_get_u32(સંદેશ, &સંદેશ_id)) != 0)
		fatal_fr(r, "parse");

	debug3("Received limits reply T:%u I:%u", type, સંદેશ_id);
	જો (id != સંદેશ_id)
		fatal("ID mismatch (%u != %u)", સંદેશ_id, id);
	જો (type != SSH2_FXP_EXTENDED_REPLY) {
		debug_f("expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_REPLY, type);
		/* Disable the limits extension */
		conn->exts &= ~SFTP_EXT_LIMITS;
		sshbuf_free(સંદેશ);
		પાછા -1;
	}

	memset(limits, 0, કદ(*limits));
	જો ((r = sshbuf_get_u64(સંદેશ, &limits->packet_length)) != 0 ||
	    (r = sshbuf_get_u64(સંદેશ, &limits->read_length)) != 0 ||
	    (r = sshbuf_get_u64(સંદેશ, &limits->write_length)) != 0 ||
	    (r = sshbuf_get_u64(સંદેશ, &limits->open_handles)) != 0)
		fatal_fr(r, "parse limits");

	sshbuf_free(સંદેશ);

	પાછા 0;
}

પૂર્ણાંક
sftp_close(સંરચના sftp_conn *conn, અચલ u_char *handle, u_int handle_len)
{
	u_int id, status;
	સંરચના sshbuf *સંદેશ;
	પૂર્ણાંક r;

	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");

	id = conn->સંદેશ_id++;
	જો ((r = sshbuf_put_u8(સંદેશ, SSH2_FXP_CLOSE)) != 0 ||
	    (r = sshbuf_put_u32(સંદેશ, id)) != 0 ||
	    (r = sshbuf_put_string(સંદેશ, handle, handle_len)) != 0)
		fatal_fr(r, "parse");
	send_સંદેશ(conn, સંદેશ);
	debug3("Sent message SSH2_FXP_CLOSE I:%u", id);

	status = get_status(conn, id);
	જો (status != SSH2_FX_OK)
		error("close remote: %s", fx2txt(status));

	sshbuf_free(સંદેશ);

	પાછા status == SSH2_FX_OK ? 0 : -1;
}


સ્થિર પૂર્ણાંક
sftp_lsreaddir(સંરચના sftp_conn *conn, અચલ અક્ષર *path, પૂર્ણાંક print_flag,
    SFTP_DIRENT ***dir)
{
	સંરચના sshbuf *સંદેશ;
	u_int ગણતરી, id, i, expected_id, ents = 0;
	size_t handle_len;
	u_char type, *handle;
	પૂર્ણાંક status = SSH2_FX_FAILURE;
	પૂર્ણાંક r;

	જો (dir)
		*dir = ખાલી;

	id = conn->સંદેશ_id++;

	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = sshbuf_put_u8(સંદેશ, SSH2_FXP_OPENDIR)) != 0 ||
	    (r = sshbuf_put_u32(સંદેશ, id)) != 0 ||
	    (r = sshbuf_put_cstring(સંદેશ, path)) != 0)
		fatal_fr(r, "compose OPENDIR");
	send_સંદેશ(conn, સંદેશ);

	handle = get_handle(conn, id, &handle_len,
	    "remote readdir(\"%s\")", path);
	જો (handle == ખાલી) {
		sshbuf_free(સંદેશ);
		પાછા -1;
	}

	જો (dir) {
		ents = 0;
		*dir = xcalloc(1, કદ(**dir));
		(*dir)[0] = ખાલી;
	}

	માટે (; !interrupted;) {
		id = expected_id = conn->સંદેશ_id++;

		debug3("Sending SSH2_FXP_READDIR I:%u", id);

		sshbuf_reset(સંદેશ);
		જો ((r = sshbuf_put_u8(સંદેશ, SSH2_FXP_READDIR)) != 0 ||
		    (r = sshbuf_put_u32(સંદેશ, id)) != 0 ||
		    (r = sshbuf_put_string(સંદેશ, handle, handle_len)) != 0)
			fatal_fr(r, "compose READDIR");
		send_સંદેશ(conn, સંદેશ);

		sshbuf_reset(સંદેશ);

		get_સંદેશ(conn, સંદેશ);

		જો ((r = sshbuf_get_u8(સંદેશ, &type)) != 0 ||
		    (r = sshbuf_get_u32(સંદેશ, &id)) != 0)
			fatal_fr(r, "parse");

		debug3("Received reply T:%u I:%u", type, id);

		જો (id != expected_id)
			fatal("ID mismatch (%u != %u)", id, expected_id);

		જો (type == SSH2_FXP_STATUS) {
			u_int rstatus;

			જો ((r = sshbuf_get_u32(સંદેશ, &rstatus)) != 0)
				fatal_fr(r, "parse status");
			debug3("Received SSH2_FXP_STATUS %d", rstatus);
			જો (rstatus == SSH2_FX_EOF)
				તોડો;
			error("Couldn't read directory: %s", fx2txt(rstatus));
			જાઓ out;
		} નહીંતર જો (type != SSH2_FXP_NAME)
			fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
			    SSH2_FXP_NAME, type);

		જો ((r = sshbuf_get_u32(સંદેશ, &ગણતરી)) != 0)
			fatal_fr(r, "parse count");
		જો (ગણતરી > SSHBUF_SIZE_MAX)
			fatal_f("nonsensical number of entries");
		જો (ગણતરી == 0)
			તોડો;
		debug3("Received %d SSH2_FXP_NAME responses", ગણતરી);
		માટે (i = 0; i < ગણતરી; i++) {
			અક્ષર *filename, *longname;
			Attrib a;

			જો ((r = sshbuf_get_cstring(સંદેશ, &filename,
			    ખાલી)) != 0 ||
			    (r = sshbuf_get_cstring(સંદેશ, &longname,
			    ખાલી)) != 0)
				fatal_fr(r, "parse filenames");
			જો ((r = decode_attrib(સંદેશ, &a)) != 0) {
				error_fr(r, "couldn't decode attrib");
				મુક્ત(filename);
				મુક્ત(longname);
				જાઓ out;
			}

			જો (print_flag)
				mprintf("%s\n", longname);

			/*
			 * Directory entries should never contain '/'
			 * These can be used to attack recursive ops
			 * (e.g. send '../../../../etc/passwd')
			 */
			જો (*filename == '\0' ||
			    strpbrk(filename, SFTP_DIRECTORY_CHARS) != ખાલી) {
				error("Server sent suspect path \"%s\" "
				    "during readdir of \"%s\"", filename, path);
			} નહીંતર જો (dir) {
				*dir = xreallocarray(*dir, ents + 2, કદ(**dir));
				(*dir)[ents] = xcalloc(1, કદ(***dir));
				(*dir)[ents]->filename = xstrdup(filename);
				(*dir)[ents]->longname = xstrdup(longname);
				memcpy(&(*dir)[ents]->a, &a, કદ(a));
				(*dir)[++ents] = ખાલી;
			}
			મુક્ત(filename);
			મુક્ત(longname);
		}
	}
	status = 0;

 out:
	sshbuf_free(સંદેશ);
	sftp_close(conn, handle, handle_len);
	મુક્ત(handle);

	જો (status != 0 && dir != ખાલી) {
		/* Don't return results on error */
		sftp_free_dirents(*dir);
		*dir = ખાલી;
	} નહીંતર જો (interrupted && dir != ખાલી && *dir != ખાલી) {
		/* Don't return partial matches on interrupt */
		sftp_free_dirents(*dir);
		*dir = xcalloc(1, કદ(**dir));
		**dir = ખાલી;
	}

	પાછા status == SSH2_FX_OK ? 0 : -1;
}

પૂર્ણાંક
sftp_readdir(સંરચના sftp_conn *conn, અચલ અક્ષર *path, SFTP_DIRENT ***dir)
{
	પાછા sftp_lsreaddir(conn, path, 0, dir);
}

શૂન્ય sftp_free_dirents(SFTP_DIRENT **s)
{
	પૂર્ણાંક i;

	જો (s == ખાલી)
		પાછા;
	માટે (i = 0; s[i]; i++) {
		મુક્ત(s[i]->filename);
		મુક્ત(s[i]->longname);
		મુક્ત(s[i]);
	}
	મુક્ત(s);
}

પૂર્ણાંક
sftp_rm(સંરચના sftp_conn *conn, અચલ અક્ષર *path)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_REMOVE \"%s\"", path);

	id = conn->સંદેશ_id++;
	send_string_request(conn, id, SSH2_FXP_REMOVE, path, strlen(path));
	status = get_status(conn, id);
	જો (status != SSH2_FX_OK)
		error("remote delete %s: %s", path, fx2txt(status));
	પાછા status == SSH2_FX_OK ? 0 : -1;
}

પૂર્ણાંક
sftp_mkdir(સંરચના sftp_conn *conn, અચલ અક્ષર *path, Attrib *a, પૂર્ણાંક print_flag)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_MKDIR \"%s\"", path);

	id = conn->સંદેશ_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_MKDIR, path,
	    strlen(path), a);

	status = get_status(conn, id);
	જો (status != SSH2_FX_OK && print_flag)
		error("remote mkdir \"%s\": %s", path, fx2txt(status));

	પાછા status == SSH2_FX_OK ? 0 : -1;
}

પૂર્ણાંક
sftp_mkpath(સંરચના sftp_conn *conn, અચલ અક્ષર *path, Attrib *a, પૂર્ણાંક print_flag)
{
	અક્ષર *slash, *tmp_path;
	પૂર્ણાંક done;

	tmp_path = xstrdup(path);
	slash = tmp_path;

	માટે (;;) {
		slash += strspn(slash, "/");
		slash += strcspn(slash, "/");

		done = (*slash == '\0');
		*slash = '\0';

		જો (!sftp_remote_is_dir(conn, tmp_path)) {
			જો (sftp_mkdir(conn, tmp_path, a, print_flag) != 0) {
				મુક્ત(tmp_path);
				પાછા -1;
			}
		}

		જો (done)
			તોડો;

		*slash = '/';
	}

	મુક્ત(tmp_path);
	પાછા 0;
}

પૂર્ણાંક
sftp_rmdir(સંરચના sftp_conn *conn, અચલ અક્ષર *path)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_RMDIR \"%s\"", path);

	id = conn->સંદેશ_id++;
	send_string_request(conn, id, SSH2_FXP_RMDIR, path,
	    strlen(path));

	status = get_status(conn, id);
	જો (status != SSH2_FX_OK)
		error("remote rmdir \"%s\": %s", path, fx2txt(status));

	પાછા status == SSH2_FX_OK ? 0 : -1;
}

પૂર્ણાંક
sftp_stat(સંરચના sftp_conn *conn, અચલ અક્ષર *path, પૂર્ણાંક quiet, Attrib *a)
{
	u_int id;

	debug2("Sending SSH2_FXP_STAT \"%s\"", path);

	id = conn->સંદેશ_id++;

	send_string_request(conn, id,
	    conn->version == 0 ? SSH2_FXP_STAT_VERSION_0 : SSH2_FXP_STAT,
	    path, strlen(path));

	પાછા get_decode_stat(conn, id, quiet, a);
}

પૂર્ણાંક
sftp_lstat(સંરચના sftp_conn *conn, અચલ અક્ષર *path, પૂર્ણાંક quiet, Attrib *a)
{
	u_int id;

	જો (conn->version == 0) {
		do_log2(quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_INFO,
		    "Server version does not support lstat operation");
		પાછા sftp_stat(conn, path, quiet, a);
	}

	id = conn->સંદેશ_id++;
	send_string_request(conn, id, SSH2_FXP_LSTAT, path,
	    strlen(path));

	પાછા get_decode_stat(conn, id, quiet, a);
}

#ifdef notyet
પૂર્ણાંક
sftp_fstat(સંરચના sftp_conn *conn, અચલ u_char *handle, u_int handle_len,
    પૂર્ણાંક quiet, Attrib *a)
{
	u_int id;

	debug2("Sending SSH2_FXP_FSTAT \"%s\"");

	id = conn->સંદેશ_id++;
	send_string_request(conn, id, SSH2_FXP_FSTAT, handle,
	    handle_len);

	પાછા get_decode_stat(conn, id, quiet, a);
}
#endif

પૂર્ણાંક
sftp_setstat(સંરચના sftp_conn *conn, અચલ અક્ષર *path, Attrib *a)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_SETSTAT \"%s\"", path);

	id = conn->સંદેશ_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_SETSTAT, path,
	    strlen(path), a);

	status = get_status(conn, id);
	જો (status != SSH2_FX_OK)
		error("remote setstat \"%s\": %s", path, fx2txt(status));

	પાછા status == SSH2_FX_OK ? 0 : -1;
}

પૂર્ણાંક
sftp_fsetstat(સંરચના sftp_conn *conn, અચલ u_char *handle, u_int handle_len,
    Attrib *a)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_FSETSTAT");

	id = conn->સંદેશ_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_FSETSTAT, handle,
	    handle_len, a);

	status = get_status(conn, id);
	જો (status != SSH2_FX_OK)
		error("remote fsetstat: %s", fx2txt(status));

	પાછા status == SSH2_FX_OK ? 0 : -1;
}

/* Implements both the realpath and expand-path operations */
સ્થિર અક્ષર *
sftp_realpath_expand(સંરચના sftp_conn *conn, અચલ અક્ષર *path, પૂર્ણાંક expand)
{
	સંરચના sshbuf *સંદેશ;
	u_int expected_id, ગણતરી, id;
	અક્ષર *filename, *longname;
	Attrib a;
	u_char type;
	પૂર્ણાંક r;
	અચલ અક્ષર *what = "SSH2_FXP_REALPATH";

	જો (expand)
		what = "expand-path@openssh.com";
	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");

	expected_id = id = conn->સંદેશ_id++;
	જો (expand) {
		debug2("Sending SSH2_FXP_EXTENDED(expand-path@openssh.com) "
		    "\"%s\"", path);
		જો ((r = sshbuf_put_u8(સંદેશ, SSH2_FXP_EXTENDED)) != 0 ||
		    (r = sshbuf_put_u32(સંદેશ, id)) != 0 ||
		    (r = sshbuf_put_cstring(સંદેશ,
		    "expand-path@openssh.com")) != 0 ||
		    (r = sshbuf_put_cstring(સંદેશ, path)) != 0)
			fatal_fr(r, "compose %s", what);
		send_સંદેશ(conn, સંદેશ);
	} નહીંતર {
		debug2("Sending SSH2_FXP_REALPATH \"%s\"", path);
		send_string_request(conn, id, SSH2_FXP_REALPATH,
		    path, strlen(path));
	}
	get_સંદેશ(conn, સંદેશ);
	જો ((r = sshbuf_get_u8(સંદેશ, &type)) != 0 ||
	    (r = sshbuf_get_u32(સંદેશ, &id)) != 0)
		fatal_fr(r, "parse");

	જો (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);

	જો (type == SSH2_FXP_STATUS) {
		u_int status;
		અક્ષર *errmsg;

		જો ((r = sshbuf_get_u32(સંદેશ, &status)) != 0 ||
		    (r = sshbuf_get_cstring(સંદેશ, &errmsg, ખાલી)) != 0)
			fatal_fr(r, "parse status");
		error("%s %s: %s", expand ? "expand" : "realpath",
		    path, *errmsg == '\0' ? fx2txt(status) : errmsg);
		મુક્ત(errmsg);
		sshbuf_free(સંદેશ);
		પાછા ખાલી;
	} નહીંતર જો (type != SSH2_FXP_NAME)
		fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
		    SSH2_FXP_NAME, type);

	જો ((r = sshbuf_get_u32(સંદેશ, &ગણતરી)) != 0)
		fatal_fr(r, "parse count");
	જો (ગણતરી != 1)
		fatal("Got multiple names (%d) from %s", ગણતરી, what);

	જો ((r = sshbuf_get_cstring(સંદેશ, &filename, ખાલી)) != 0 ||
	    (r = sshbuf_get_cstring(સંદેશ, &longname, ખાલી)) != 0 ||
	    (r = decode_attrib(સંદેશ, &a)) != 0)
		fatal_fr(r, "parse filename/attrib");

	debug3("%s %s -> %s", what, path, filename);

	મુક્ત(longname);

	sshbuf_free(સંદેશ);

	પાછા(filename);
}

અક્ષર *
sftp_realpath(સંરચના sftp_conn *conn, અચલ અક્ષર *path)
{
	પાછા sftp_realpath_expand(conn, path, 0);
}

પૂર્ણાંક
sftp_can_expand_path(સંરચના sftp_conn *conn)
{
	પાછા (conn->exts & SFTP_EXT_PATH_EXPAND) != 0;
}

અક્ષર *
sftp_expand_path(સંરચના sftp_conn *conn, અચલ અક્ષર *path)
{
	જો (!sftp_can_expand_path(conn)) {
		debug3_f("no server support, fallback to realpath");
		પાછા sftp_realpath_expand(conn, path, 0);
	}
	પાછા sftp_realpath_expand(conn, path, 1);
}

પૂર્ણાંક
sftp_copy(સંરચના sftp_conn *conn, અચલ અક્ષર *oldpath, અચલ અક્ષર *newpath)
{
	Attrib junk, attr;
	સંરચના sshbuf *સંદેશ;
	u_char *old_handle, *new_handle;
	u_int mode, status, id;
	size_t old_handle_len, new_handle_len;
	પૂર્ણાંક r;

	/* Return if the extension is not supported */
	જો ((conn->exts & SFTP_EXT_COPY_DATA) == 0) {
		error("Server does not support copy-data extension");
		પાછા -1;
	}

	/* Make sure the file exists, and we can copy its perms */
	જો (sftp_stat(conn, oldpath, 0, &attr) != 0)
		પાછા -1;

	/* Do not preserve set[ug]id here, as we do not preserve ownership */
	જો (attr.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		mode = attr.perm & 0777;

		જો (!S_ISREG(attr.perm)) {
			error("Cannot copy non-regular file: %s", oldpath);
			પાછા -1;
		}
	} નહીંતર {
		/* NB: The user's umask will apply to this */
		mode = 0666;
	}

	/* Set up the new perms for the new file */
	attrib_clear(&attr);
	attr.perm = mode;
	attr.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;

	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");

	attrib_clear(&junk); /* Send empty attributes */

	/* Open the old file for reading */
	id = conn->સંદેશ_id++;
	જો ((r = sshbuf_put_u8(સંદેશ, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(સંદેશ, id)) != 0 ||
	    (r = sshbuf_put_cstring(સંદેશ, oldpath)) != 0 ||
	    (r = sshbuf_put_u32(સંદેશ, SSH2_FXF_READ)) != 0 ||
	    (r = encode_attrib(સંદેશ, &junk)) != 0)
		fatal_fr(r, "buffer error");
	send_સંદેશ(conn, સંદેશ);
	debug3("Sent message SSH2_FXP_OPEN I:%u P:%s", id, oldpath);

	sshbuf_reset(સંદેશ);

	old_handle = get_handle(conn, id, &old_handle_len,
	    "remote open(\"%s\")", oldpath);
	જો (old_handle == ખાલી) {
		sshbuf_free(સંદેશ);
		પાછા -1;
	}

	/* Open the new file for writing */
	id = conn->સંદેશ_id++;
	જો ((r = sshbuf_put_u8(સંદેશ, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(સંદેશ, id)) != 0 ||
	    (r = sshbuf_put_cstring(સંદેશ, newpath)) != 0 ||
	    (r = sshbuf_put_u32(સંદેશ, SSH2_FXF_WRITE|SSH2_FXF_CREAT|
	    SSH2_FXF_TRUNC)) != 0 ||
	    (r = encode_attrib(સંદેશ, &attr)) != 0)
		fatal_fr(r, "buffer error");
	send_સંદેશ(conn, સંદેશ);
	debug3("Sent message SSH2_FXP_OPEN I:%u P:%s", id, newpath);

	sshbuf_reset(સંદેશ);

	new_handle = get_handle(conn, id, &new_handle_len,
	    "remote open(\"%s\")", newpath);
	જો (new_handle == ખાલી) {
		sshbuf_free(સંદેશ);
		મુક્ત(old_handle);
		પાછા -1;
	}

	/* Copy the file data */
	id = conn->સંદેશ_id++;
	જો ((r = sshbuf_put_u8(સંદેશ, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(સંદેશ, id)) != 0 ||
	    (r = sshbuf_put_cstring(સંદેશ, "copy-data")) != 0 ||
	    (r = sshbuf_put_string(સંદેશ, old_handle, old_handle_len)) != 0 ||
	    (r = sshbuf_put_u64(સંદેશ, 0)) != 0 ||
	    (r = sshbuf_put_u64(સંદેશ, 0)) != 0 ||
	    (r = sshbuf_put_string(સંદેશ, new_handle, new_handle_len)) != 0 ||
	    (r = sshbuf_put_u64(સંદેશ, 0)) != 0)
		fatal_fr(r, "buffer error");
	send_સંદેશ(conn, સંદેશ);
	debug3("Sent message copy-data \"%s\" 0 0 -> \"%s\" 0",
	       oldpath, newpath);

	status = get_status(conn, id);
	જો (status != SSH2_FX_OK)
		error("Couldn't copy file \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	/* Clean up everything */
	sshbuf_free(સંદેશ);
	sftp_close(conn, old_handle, old_handle_len);
	sftp_close(conn, new_handle, new_handle_len);
	મુક્ત(old_handle);
	મુક્ત(new_handle);

	પાછા status == SSH2_FX_OK ? 0 : -1;
}

પૂર્ણાંક
sftp_rename(સંરચના sftp_conn *conn, અચલ અક્ષર *oldpath, અચલ અક્ષર *newpath,
    પૂર્ણાંક force_legacy)
{
	સંરચના sshbuf *સંદેશ;
	u_int status, id;
	પૂર્ણાંક r, use_ext = (conn->exts & SFTP_EXT_POSIX_RENAME) && !force_legacy;

	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");

	/* Send rename request */
	id = conn->સંદેશ_id++;
	જો (use_ext) {
		debug2("Sending SSH2_FXP_EXTENDED(posix-rename@openssh.com) "
		    "\"%s\" to \"%s\"", oldpath, newpath);
		જો ((r = sshbuf_put_u8(સંદેશ, SSH2_FXP_EXTENDED)) != 0 ||
		    (r = sshbuf_put_u32(સંદેશ, id)) != 0 ||
		    (r = sshbuf_put_cstring(સંદેશ,
		    "posix-rename@openssh.com")) != 0)
			fatal_fr(r, "compose posix-rename");
	} નહીંતર {
		debug2("Sending SSH2_FXP_RENAME \"%s\" to \"%s\"",
		    oldpath, newpath);
		જો ((r = sshbuf_put_u8(સંદેશ, SSH2_FXP_RENAME)) != 0 ||
		    (r = sshbuf_put_u32(સંદેશ, id)) != 0)
			fatal_fr(r, "compose rename");
	}
	જો ((r = sshbuf_put_cstring(સંદેશ, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(સંદેશ, newpath)) != 0)
		fatal_fr(r, "compose paths");
	send_સંદેશ(conn, સંદેશ);
	debug3("Sent message %s \"%s\" -> \"%s\"",
	    use_ext ? "posix-rename@openssh.com" :
	    "SSH2_FXP_RENAME", oldpath, newpath);
	sshbuf_free(સંદેશ);

	status = get_status(conn, id);
	જો (status != SSH2_FX_OK)
		error("remote rename \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	પાછા status == SSH2_FX_OK ? 0 : -1;
}

પૂર્ણાંક
sftp_hardlink(સંરચના sftp_conn *conn, અચલ અક્ષર *oldpath, અચલ અક્ષર *newpath)
{
	સંરચના sshbuf *સંદેશ;
	u_int status, id;
	પૂર્ણાંક r;

	જો ((conn->exts & SFTP_EXT_HARDLINK) == 0) {
		error("Server does not support hardlink@openssh.com extension");
		પાછા -1;
	}
	debug2("Sending SSH2_FXP_EXTENDED(hardlink@openssh.com) "
	    "\"%s\" to \"%s\"", oldpath, newpath);

	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");

	/* Send link request */
	id = conn->સંદેશ_id++;
	જો ((r = sshbuf_put_u8(સંદેશ, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(સંદેશ, id)) != 0 ||
	    (r = sshbuf_put_cstring(સંદેશ, "hardlink@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(સંદેશ, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(સંદેશ, newpath)) != 0)
		fatal_fr(r, "compose");
	send_સંદેશ(conn, સંદેશ);
	debug3("Sent message hardlink@openssh.com \"%s\" -> \"%s\"",
	    oldpath, newpath);
	sshbuf_free(સંદેશ);

	status = get_status(conn, id);
	જો (status != SSH2_FX_OK)
		error("remote link \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	પાછા status == SSH2_FX_OK ? 0 : -1;
}

પૂર્ણાંક
sftp_symlink(સંરચના sftp_conn *conn, અચલ અક્ષર *oldpath, અચલ અક્ષર *newpath)
{
	સંરચના sshbuf *સંદેશ;
	u_int status, id;
	પૂર્ણાંક r;

	જો (conn->version < 3) {
		error("This server does not support the symlink operation");
		પાછા(SSH2_FX_OP_UNSUPPORTED);
	}
	debug2("Sending SSH2_FXP_SYMLINK \"%s\" to \"%s\"", oldpath, newpath);

	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");

	/* Send symlink request */
	id = conn->સંદેશ_id++;
	જો ((r = sshbuf_put_u8(સંદેશ, SSH2_FXP_SYMLINK)) != 0 ||
	    (r = sshbuf_put_u32(સંદેશ, id)) != 0 ||
	    (r = sshbuf_put_cstring(સંદેશ, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(સંદેશ, newpath)) != 0)
		fatal_fr(r, "compose");
	send_સંદેશ(conn, સંદેશ);
	debug3("Sent message SSH2_FXP_SYMLINK \"%s\" -> \"%s\"", oldpath,
	    newpath);
	sshbuf_free(સંદેશ);

	status = get_status(conn, id);
	જો (status != SSH2_FX_OK)
		error("remote symlink file \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	પાછા status == SSH2_FX_OK ? 0 : -1;
}

પૂર્ણાંક
sftp_fsync(સંરચના sftp_conn *conn, u_char *handle, u_int handle_len)
{
	સંરચના sshbuf *સંદેશ;
	u_int status, id;
	પૂર્ણાંક r;

	/* Silently return if the extension is not supported */
	જો ((conn->exts & SFTP_EXT_FSYNC) == 0)
		પાછા -1;
	debug2("Sending SSH2_FXP_EXTENDED(fsync@openssh.com)");

	/* Send fsync request */
	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	id = conn->સંદેશ_id++;
	જો ((r = sshbuf_put_u8(સંદેશ, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(સંદેશ, id)) != 0 ||
	    (r = sshbuf_put_cstring(સંદેશ, "fsync@openssh.com")) != 0 ||
	    (r = sshbuf_put_string(સંદેશ, handle, handle_len)) != 0)
		fatal_fr(r, "compose");
	send_સંદેશ(conn, સંદેશ);
	debug3("Sent message fsync@openssh.com I:%u", id);
	sshbuf_free(સંદેશ);

	status = get_status(conn, id);
	જો (status != SSH2_FX_OK)
		error("remote fsync: %s", fx2txt(status));

	પાછા status == SSH2_FX_OK ? 0 : -1;
}

#ifdef notyet
અક્ષર *
sftp_readlink(સંરચના sftp_conn *conn, અચલ અક્ષર *path)
{
	સંરચના sshbuf *સંદેશ;
	u_int expected_id, ગણતરી, id;
	અક્ષર *filename, *longname;
	Attrib a;
	u_char type;
	પૂર્ણાંક r;

	debug2("Sending SSH2_FXP_READLINK \"%s\"", path);

	expected_id = id = conn->સંદેશ_id++;
	send_string_request(conn, id, SSH2_FXP_READLINK, path, strlen(path));

	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");

	get_સંદેશ(conn, સંદેશ);
	જો ((r = sshbuf_get_u8(સંદેશ, &type)) != 0 ||
	    (r = sshbuf_get_u32(સંદેશ, &id)) != 0)
		fatal_fr(r, "parse");

	જો (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);

	જો (type == SSH2_FXP_STATUS) {
		u_int status;

		જો ((r = sshbuf_get_u32(સંદેશ, &status)) != 0)
			fatal_fr(r, "parse status");
		error("Couldn't readlink: %s", fx2txt(status));
		sshbuf_free(સંદેશ);
		પાછા(ખાલી);
	} નહીંતર જો (type != SSH2_FXP_NAME)
		fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
		    SSH2_FXP_NAME, type);

	જો ((r = sshbuf_get_u32(સંદેશ, &ગણતરી)) != 0)
		fatal_fr(r, "parse count");
	જો (ગણતરી != 1)
		fatal("Got multiple names (%d) from SSH_FXP_READLINK", ગણતરી);

	જો ((r = sshbuf_get_cstring(સંદેશ, &filename, ખાલી)) != 0 ||
	    (r = sshbuf_get_cstring(સંદેશ, &longname, ખાલી)) != 0 ||
	    (r = decode_attrib(સંદેશ, &a)) != 0)
		fatal_fr(r, "parse filenames/attrib");

	debug3("SSH_FXP_READLINK %s -> %s", path, filename);

	મુક્ત(longname);

	sshbuf_free(સંદેશ);

	પાછા filename;
}
#endif

પૂર્ણાંક
sftp_statvfs(સંરચના sftp_conn *conn, અચલ અક્ષર *path, સંરચના sftp_statvfs *st,
    પૂર્ણાંક quiet)
{
	સંરચના sshbuf *સંદેશ;
	u_int id;
	પૂર્ણાંક r;

	જો ((conn->exts & SFTP_EXT_STATVFS) == 0) {
		error("Server does not support statvfs@openssh.com extension");
		પાછા -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(statvfs@openssh.com) \"%s\"", path);

	id = conn->સંદેશ_id++;

	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = sshbuf_put_u8(સંદેશ, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(સંદેશ, id)) != 0 ||
	    (r = sshbuf_put_cstring(સંદેશ, "statvfs@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(સંદેશ, path)) != 0)
		fatal_fr(r, "compose");
	send_સંદેશ(conn, સંદેશ);
	sshbuf_free(સંદેશ);

	પાછા get_decode_statvfs(conn, st, id, quiet);
}

#ifdef notyet
પૂર્ણાંક
sftp_fstatvfs(સંરચના sftp_conn *conn, અચલ u_char *handle, u_int handle_len,
    સંરચના sftp_statvfs *st, પૂર્ણાંક quiet)
{
	સંરચના sshbuf *સંદેશ;
	u_int id;

	જો ((conn->exts & SFTP_EXT_FSTATVFS) == 0) {
		error("Server does not support fstatvfs@openssh.com extension");
		પાછા -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(fstatvfs@openssh.com)");

	id = conn->સંદેશ_id++;

	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = sshbuf_put_u8(સંદેશ, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(સંદેશ, id)) != 0 ||
	    (r = sshbuf_put_cstring(સંદેશ, "fstatvfs@openssh.com")) != 0 ||
	    (r = sshbuf_put_string(સંદેશ, handle, handle_len)) != 0)
		fatal_fr(r, "compose");
	send_સંદેશ(conn, સંદેશ);
	sshbuf_free(સંદેશ);

	પાછા get_decode_statvfs(conn, st, id, quiet);
}
#endif

પૂર્ણાંક
sftp_lsetstat(સંરચના sftp_conn *conn, અચલ અક્ષર *path, Attrib *a)
{
	સંરચના sshbuf *સંદેશ;
	u_int status, id;
	પૂર્ણાંક r;

	જો ((conn->exts & SFTP_EXT_LSETSTAT) == 0) {
		error("Server does not support lsetstat@openssh.com extension");
		પાછા -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(lsetstat@openssh.com) \"%s\"", path);

	id = conn->સંદેશ_id++;
	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = sshbuf_put_u8(સંદેશ, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(સંદેશ, id)) != 0 ||
	    (r = sshbuf_put_cstring(સંદેશ, "lsetstat@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(સંદેશ, path)) != 0 ||
	    (r = encode_attrib(સંદેશ, a)) != 0)
		fatal_fr(r, "compose");
	send_સંદેશ(conn, સંદેશ);
	sshbuf_free(સંદેશ);

	status = get_status(conn, id);
	જો (status != SSH2_FX_OK)
		error("remote lsetstat \"%s\": %s", path, fx2txt(status));

	પાછા status == SSH2_FX_OK ? 0 : -1;
}

સ્થિર શૂન્ય
send_read_request(સંરચના sftp_conn *conn, u_int id, uint64_t offset,
    u_int len, અચલ u_char *handle, u_int handle_len)
{
	સંરચના sshbuf *સંદેશ;
	પૂર્ણાંક r;

	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = sshbuf_put_u8(સંદેશ, SSH2_FXP_READ)) != 0 ||
	    (r = sshbuf_put_u32(સંદેશ, id)) != 0 ||
	    (r = sshbuf_put_string(સંદેશ, handle, handle_len)) != 0 ||
	    (r = sshbuf_put_u64(સંદેશ, offset)) != 0 ||
	    (r = sshbuf_put_u32(સંદેશ, len)) != 0)
		fatal_fr(r, "compose");
	send_સંદેશ(conn, સંદેશ);
	sshbuf_free(સંદેશ);
}

સ્થિર પૂર્ણાંક
send_open(સંરચના sftp_conn *conn, અચલ અક્ષર *path, અચલ અક્ષર *tag,
    u_int openmode, Attrib *a, u_char **handlep, size_t *handle_lenp)
{
	Attrib junk;
	u_char *handle;
	size_t handle_len;
	સંરચના sshbuf *સંદેશ;
	પૂર્ણાંક r;
	u_int id;

	debug2("Sending SSH2_FXP_OPEN \"%s\"", path);

	*handlep = ખાલી;
	*handle_lenp = 0;

	જો (a == ખાલી) {
		attrib_clear(&junk); /* Send empty attributes */
		a = &junk;
	}
	/* Send open request */
	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	id = conn->સંદેશ_id++;
	જો ((r = sshbuf_put_u8(સંદેશ, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(સંદેશ, id)) != 0 ||
	    (r = sshbuf_put_cstring(સંદેશ, path)) != 0 ||
	    (r = sshbuf_put_u32(સંદેશ, openmode)) != 0 ||
	    (r = encode_attrib(સંદેશ, a)) != 0)
		fatal_fr(r, "compose %s open", tag);
	send_સંદેશ(conn, સંદેશ);
	sshbuf_free(સંદેશ);
	debug3("Sent %s message SSH2_FXP_OPEN I:%u P:%s M:0x%04x",
	    tag, id, path, openmode);
	જો ((handle = get_handle(conn, id, &handle_len,
	    "%s open \"%s\"", tag, path)) == ખાલી)
		પાછા -1;
	/* success */
	*handlep = handle;
	*handle_lenp = handle_len;
	પાછા 0;
}

સ્થિર અચલ અક્ષર *
progress_meter_path(અચલ અક્ષર *path)
{
	અચલ અક્ષર *progresspath;

	જો ((progresspath = strrchr(path, '/')) == ખાલી)
		પાછા path;
	progresspath++;
	જો (*progresspath == '\0')
		પાછા path;
	પાછા progresspath;
}

પૂર્ણાંક
sftp_download(સંરચના sftp_conn *conn, અચલ અક્ષર *remote_path,
    અચલ અક્ષર *local_path, Attrib *a, પૂર્ણાંક preserve_flag, પૂર્ણાંક resume_flag,
    પૂર્ણાંક fsync_flag, પૂર્ણાંક inplace_flag)
{
	સંરચના sshbuf *સંદેશ;
	u_char *handle;
	પૂર્ણાંક local_fd = -1, write_error, seen_zerolen = 0;
	પૂર્ણાંક read_error, write_errno, lmodified = 0, reordered = 0, r;
	uint64_t offset = 0, size, highwater = 0, maxack = 0;
	u_int mode, id, buflen, અંક_req, max_req, status = SSH2_FX_OK;
	off_t progress_counter;
	size_t handle_len;
	સંરચના stat st;
	સંરચના requests requests;
	સંરચના request *req;
	u_char type;
	Attrib attr;

	debug2_f("download remote \"%s\" to local \"%s\"",
	    remote_path, local_path);

	TAILQ_INIT(&requests);

	જો (a == ખાલી) {
		જો (sftp_stat(conn, remote_path, 0, &attr) != 0)
			પાછા -1;
		a = &attr;
	}

	/* Do not preserve set[ug]id here, as we do not preserve ownership */
	જો (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS)
		mode = a->perm & 0777;
	નહીંતર
		mode = 0666;

	જો ((a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) &&
	    (!S_ISREG(a->perm))) {
		error("download %s: not a regular file", remote_path);
		પાછા(-1);
	}

	જો (a->flags & SSH2_FILEXFER_ATTR_SIZE)
		size = a->size;
	નહીંતર
		size = 0;

	buflen = conn->download_buflen;

	/* Send open request */
	જો (send_open(conn, remote_path, "remote", SSH2_FXF_READ, ખાલી,
	    &handle, &handle_len) != 0)
		પાછા -1;

	local_fd = open(local_path, O_WRONLY | O_CREAT |
	((resume_flag || inplace_flag) ? 0 : O_TRUNC), mode | S_IWUSR);
	જો (local_fd == -1) {
		error("open local \"%s\": %s", local_path, strerror(errno));
		જાઓ fail;
	}
	જો (resume_flag) {
		જો (fstat(local_fd, &st) == -1) {
			error("stat local \"%s\": %s",
			    local_path, strerror(errno));
			જાઓ fail;
		}
		જો (st.st_size < 0) {
			error("\"%s\" has negative size", local_path);
			જાઓ fail;
		}
		જો ((uint64_t)st.st_size > size) {
			error("Unable to resume download of \"%s\": "
			    "local file is larger than remote", local_path);
 fail:
			sftp_close(conn, handle, handle_len);
			મુક્ત(handle);
			જો (local_fd != -1)
				close(local_fd);
			પાછા -1;
		}
		offset = highwater = maxack = st.st_size;
	}

	/* Read from remote and write to local */
	write_error = read_error = write_errno = અંક_req = 0;
	max_req = 1;
	progress_counter = offset;

	જો (showprogress && size != 0) {
		start_progress_meter(progress_meter_path(remote_path),
		    size, &progress_counter);
	}

	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");

	જ્યારે (અંક_req > 0 || max_req > 0) {
		u_char *data;
		size_t len;

		/*
		 * Simulate EOF on interrupt: stop sending new requests and
		 * allow outstanding requests to drain gracefully
		 */
		જો (interrupted) {
			જો (અંક_req == 0) /* If we haven't started yet... */
				તોડો;
			max_req = 0;
		}

		/* Send some more requests */
		જ્યારે (અંક_req < max_req) {
			debug3("Request range %llu -> %llu (%d/%d)",
			    (unsigned long long)offset,
			    (unsigned long long)offset + buflen - 1,
			    અંક_req, max_req);
			req = request_enqueue(&requests, conn->સંદેશ_id++,
			    buflen, offset);
			offset += buflen;
			અંક_req++;
			send_read_request(conn, req->id, req->offset,
			    req->len, handle, handle_len);
		}

		sshbuf_reset(સંદેશ);
		get_સંદેશ(conn, સંદેશ);
		જો ((r = sshbuf_get_u8(સંદેશ, &type)) != 0 ||
		    (r = sshbuf_get_u32(સંદેશ, &id)) != 0)
			fatal_fr(r, "parse");
		debug3("Received reply T:%u I:%u R:%d", type, id, max_req);

		/* Find the request in our queue */
		જો ((req = request_find(&requests, id)) == ખાલી)
			fatal("Unexpected reply %u", id);

		પસંદગી (type) {
		સ્થિતિ SSH2_FXP_STATUS:
			જો ((r = sshbuf_get_u32(સંદેશ, &status)) != 0)
				fatal_fr(r, "parse status");
			જો (status != SSH2_FX_EOF)
				read_error = 1;
			max_req = 0;
			TAILQ_REMOVE(&requests, req, tq);
			મુક્ત(req);
			અંક_req--;
			તોડો;
		સ્થિતિ SSH2_FXP_DATA:
			જો ((r = sshbuf_get_string(સંદેશ, &data, &len)) != 0)
				fatal_fr(r, "parse data");
			debug3("Received data %llu -> %llu",
			    (unsigned long long)req->offset,
			    (unsigned long long)req->offset + len - 1);
			જો (len > req->len)
				fatal("Received more data than asked for "
				    "%zu > %zu", len, req->len);
			જો (len == 0) {
				જો (seen_zerolen)
					fatal_f("server sent zero data length");
				seen_zerolen = 1;
			}
			lmodified = 1;
			જો ((lseek(local_fd, req->offset, SEEK_SET) == -1 ||
			    atomicio(vwrite, local_fd, data, len) != len) &&
			    !write_error) {
				write_errno = errno;
				write_error = 1;
				max_req = 0;
			} નહીંતર {
				/*
				 * Track both the highest offset acknowledged
				 * and the highest *contiguous* offset
				 * acknowledged.
				 * We'll need the latter for ftruncate()ing
				 * interrupted transfers.
				 */
				જો (maxack < req->offset + len)
					maxack = req->offset + len;
				જો (!reordered && req->offset <= highwater)
					highwater = maxack;
				નહીંતર જો (!reordered && req->offset > highwater)
					reordered = 1;
			}
			progress_counter += len;
			મુક્ત(data);

			જો (len == req->len) {
				TAILQ_REMOVE(&requests, req, tq);
				મુક્ત(req);
				અંક_req--;
			} નહીંતર {
				/* Resend the request for the missing data */
				debug3("Short data block, re-requesting "
				    "%llu -> %llu (%2d)",
				    (unsigned long long)req->offset + len,
				    (unsigned long long)req->offset +
				    req->len - 1, અંક_req);
				req->id = conn->સંદેશ_id++;
				req->len -= len;
				req->offset += len;
				send_read_request(conn, req->id,
				    req->offset, req->len, handle, handle_len);
				/* Reduce the request size */
				જો (len < buflen)
					buflen = MAXIMUM(MIN_READ_SIZE, len);
			}
			જો (max_req > 0) { /* max_req = 0 iff EOF received */
				જો (size > 0 && offset > size) {
					/* Only one request at a time
					 * after the expected EOF */
					debug3("Finish at %llu (%2d)",
					    (unsigned long long)offset,
					    અંક_req);
					max_req = 1;
				} નહીંતર જો (max_req < conn->અંક_requests) {
					++max_req;
				}
			}
			તોડો;
		મૂળભૂત:
			fatal("Expected SSH2_FXP_DATA(%u) packet, got %u",
			    SSH2_FXP_DATA, type);
		}
	}

	જો (showprogress && size)
		stop_progress_meter();

	/* Sanity check */
	જો (TAILQ_FIRST(&requests) != ખાલી)
		fatal("Transfer complete, but requests still in queue");

	જો (!read_error && !write_error && !interrupted) {
		/* we got everything */
		highwater = maxack;
	}

	/*
	 * Truncate at highest contiguous point to avoid holes on interrupt,
	 * or unconditionally if writing in place.
	 */
	જો (inplace_flag || read_error || write_error || interrupted) {
		જો (reordered && resume_flag &&
		    (read_error || write_error || interrupted)) {
			error("Unable to resume download of \"%s\": "
			    "server reordered requests", local_path);
		}
		debug("truncating at %llu", (unsigned long long)highwater);
		જો (ftruncate(local_fd, highwater) == -1)
			error("local ftruncate \"%s\": %s", local_path,
			    strerror(errno));
	}
	જો (read_error) {
		error("read remote \"%s\" : %s", remote_path, fx2txt(status));
		status = -1;
		sftp_close(conn, handle, handle_len);
	} નહીંતર જો (write_error) {
		error("write local \"%s\": %s", local_path,
		    strerror(write_errno));
		status = SSH2_FX_FAILURE;
		sftp_close(conn, handle, handle_len);
	} નહીંતર {
		જો (sftp_close(conn, handle, handle_len) != 0 || interrupted)
			status = SSH2_FX_FAILURE;
		નહીંતર
			status = SSH2_FX_OK;
		/* Override umask and utimes if asked */
#ifdef HAVE_FCHMOD
		જો (preserve_flag && fchmod(local_fd, mode) == -1)
#નહીંતર
		જો (preserve_flag && chmod(local_path, mode) == -1)
#endif /* HAVE_FCHMOD */
			error("local chmod \"%s\": %s", local_path,
			    strerror(errno));
		જો (preserve_flag &&
		    (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME)) {
			સંરચના timeval tv[2];
			tv[0].tv_sec = a->atime;
			tv[1].tv_sec = a->mtime;
			tv[0].tv_usec = tv[1].tv_usec = 0;
			જો (utimes(local_path, tv) == -1)
				error("local set times \"%s\": %s",
				    local_path, strerror(errno));
		}
		જો (resume_flag && !lmodified)
			logit("File \"%s\" was not modified", local_path);
		નહીંતર જો (fsync_flag) {
			debug("syncing \"%s\"", local_path);
			જો (fsync(local_fd) == -1)
				error("local sync \"%s\": %s",
				    local_path, strerror(errno));
		}
	}
	close(local_fd);
	sshbuf_free(સંદેશ);
	મુક્ત(handle);

	પાછા status == SSH2_FX_OK ? 0 : -1;
}

સ્થિર પૂર્ણાંક
download_dir_internal(સંરચના sftp_conn *conn, અચલ અક્ષર *src, અચલ અક્ષર *dst,
    પૂર્ણાંક depth, Attrib *dirattrib, પૂર્ણાંક preserve_flag, પૂર્ણાંક print_flag,
    પૂર્ણાંક resume_flag, પૂર્ણાંક fsync_flag, પૂર્ણાંક follow_link_flag, પૂર્ણાંક inplace_flag)
{
	પૂર્ણાંક i, ret = 0;
	SFTP_DIRENT **dir_entries;
	અક્ષર *filename, *new_src = ખાલી, *new_dst = ખાલી;
	mode_t mode = 0777, tmpmode = mode;
	Attrib *a, ldirattrib, lsym;

	જો (depth >= MAX_DIR_DEPTH) {
		error("Maximum directory depth exceeded: %d levels", depth);
		પાછા -1;
	}

	debug2_f("download dir remote \"%s\" to local \"%s\"", src, dst);

	જો (dirattrib == ખાલી) {
		જો (sftp_stat(conn, src, 1, &ldirattrib) != 0) {
			error("stat remote \"%s\" directory failed", src);
			પાછા -1;
		}
		dirattrib = &ldirattrib;
	}
	જો (!S_ISDIR(dirattrib->perm)) {
		error("\"%s\" is not a directory", src);
		પાછા -1;
	}
	જો (print_flag && print_flag != SFTP_PROGRESS_ONLY)
		mprintf("Retrieving %s\n", src);

	જો (dirattrib->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		mode = dirattrib->perm & 01777;
		tmpmode = mode | (S_IWUSR|S_IXUSR);
	} નહીંતર {
		debug("download remote \"%s\": server "
		    "did not send permissions", dst);
	}

	જો (mkdir(dst, tmpmode) == -1 && errno != EEXIST) {
		error("mkdir %s: %s", dst, strerror(errno));
		પાછા -1;
	}

	જો (sftp_readdir(conn, src, &dir_entries) == -1) {
		error("remote readdir \"%s\" failed", src);
		પાછા -1;
	}

	માટે (i = 0; dir_entries[i] != ખાલી && !interrupted; i++) {
		મુક્ત(new_dst);
		મુક્ત(new_src);

		filename = dir_entries[i]->filename;
		new_dst = sftp_path_append(dst, filename);
		new_src = sftp_path_append(src, filename);

		a = &dir_entries[i]->a;
		જો (S_ISLNK(a->perm)) {
			જો (!follow_link_flag) {
				logit("download \"%s\": not a regular file",
				    new_src);
				ચાલુ;
			}
			/* Replace the stat contents with the symlink target */
			જો (sftp_stat(conn, new_src, 1, &lsym) != 0) {
				logit("remote stat \"%s\" failed", new_src);
				ret = -1;
				ચાલુ;
			}
			a = &lsym;
		}

		જો (S_ISDIR(a->perm)) {
			જો (strcmp(filename, ".") == 0 ||
			    strcmp(filename, "..") == 0)
				ચાલુ;
			જો (download_dir_internal(conn, new_src, new_dst,
			    depth + 1, a, preserve_flag,
			    print_flag, resume_flag,
			    fsync_flag, follow_link_flag, inplace_flag) == -1)
				ret = -1;
		} નહીંતર જો (S_ISREG(a->perm)) {
			જો (sftp_download(conn, new_src, new_dst, a,
			    preserve_flag, resume_flag, fsync_flag,
			    inplace_flag) == -1) {
				error("Download of file %s to %s failed",
				    new_src, new_dst);
				ret = -1;
			}
		} નહીંતર
			logit("download \"%s\": not a regular file", new_src);

	}
	મુક્ત(new_dst);
	મુક્ત(new_src);

	જો (preserve_flag) {
		જો (dirattrib->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
			સંરચના timeval tv[2];
			tv[0].tv_sec = dirattrib->atime;
			tv[1].tv_sec = dirattrib->mtime;
			tv[0].tv_usec = tv[1].tv_usec = 0;
			જો (utimes(dst, tv) == -1)
				error("local set times on \"%s\": %s",
				    dst, strerror(errno));
		} નહીંતર
			debug("Server did not send times for directory "
			    "\"%s\"", dst);
	}

	જો (mode != tmpmode && chmod(dst, mode) == -1)
		error("local chmod directory \"%s\": %s", dst,
		    strerror(errno));

	sftp_free_dirents(dir_entries);

	પાછા ret;
}

પૂર્ણાંક
sftp_download_dir(સંરચના sftp_conn *conn, અચલ અક્ષર *src, અચલ અક્ષર *dst,
    Attrib *dirattrib, પૂર્ણાંક preserve_flag, પૂર્ણાંક print_flag, પૂર્ણાંક resume_flag,
    પૂર્ણાંક fsync_flag, પૂર્ણાંક follow_link_flag, પૂર્ણાંક inplace_flag)
{
	અક્ષર *src_canon;
	પૂર્ણાંક ret;

	જો ((src_canon = sftp_realpath(conn, src)) == ખાલી) {
		error("download \"%s\": path canonicalization failed", src);
		પાછા -1;
	}

	ret = download_dir_internal(conn, src_canon, dst, 0,
	    dirattrib, preserve_flag, print_flag, resume_flag, fsync_flag,
	    follow_link_flag, inplace_flag);
	મુક્ત(src_canon);
	પાછા ret;
}

પૂર્ણાંક
sftp_upload(સંરચના sftp_conn *conn, અચલ અક્ષર *local_path,
    અચલ અક્ષર *remote_path, પૂર્ણાંક preserve_flag, પૂર્ણાંક resume,
    પૂર્ણાંક fsync_flag, પૂર્ણાંક inplace_flag)
{
	પૂર્ણાંક r, local_fd;
	u_int openmode, id, status = SSH2_FX_OK, status2, reordered = 0;
	off_t offset, progress_counter;
	u_char type, *handle, *data;
	સંરચના sshbuf *સંદેશ;
	સંરચના stat sb;
	Attrib a, t, c;
	uint32_t startid, ackid;
	uint64_t highwater = 0, maxack = 0;
	સંરચના request *ack = ખાલી;
	સંરચના requests acks;
	size_t handle_len;

	debug2_f("upload local \"%s\" to remote \"%s\"",
	    local_path, remote_path);

	TAILQ_INIT(&acks);

	જો ((local_fd = open(local_path, O_RDONLY)) == -1) {
		error("open local \"%s\": %s", local_path, strerror(errno));
		પાછા(-1);
	}
	જો (fstat(local_fd, &sb) == -1) {
		error("fstat local \"%s\": %s", local_path, strerror(errno));
		close(local_fd);
		પાછા(-1);
	}
	જો (!S_ISREG(sb.st_mode)) {
		error("local \"%s\" is not a regular file", local_path);
		close(local_fd);
		પાછા(-1);
	}
	stat_to_attrib(&sb, &a);

	a.flags &= ~SSH2_FILEXFER_ATTR_SIZE;
	a.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a.perm &= 0777;
	જો (!preserve_flag)
		a.flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;

	જો (resume) {
		/* Get remote file size if it exists */
		જો (sftp_stat(conn, remote_path, 0, &c) != 0) {
			close(local_fd);
			પાછા -1;
		}

		જો ((off_t)c.size >= sb.st_size) {
			error("resume \"%s\": destination file "
			    "same size or larger", local_path);
			close(local_fd);
			પાછા -1;
		}

		જો (lseek(local_fd, (off_t)c.size, SEEK_SET) == -1) {
			close(local_fd);
			પાછા -1;
		}
		highwater = c.size;
	}

	openmode = SSH2_FXF_WRITE|SSH2_FXF_CREAT;
	જો (resume)
		openmode |= SSH2_FXF_APPEND;
	નહીંતર જો (!inplace_flag)
		openmode |= SSH2_FXF_TRUNC;

	/* Send open request */
	જો (send_open(conn, remote_path, "dest", openmode, &a,
	    &handle, &handle_len) != 0) {
		close(local_fd);
		પાછા -1;
	}

	id = conn->સંદેશ_id;
	startid = ackid = id + 1;
	data = xmalloc(conn->upload_buflen);

	/* Read from local and write to remote */
	offset = progress_counter = (resume ? c.size : 0);
	જો (showprogress) {
		start_progress_meter(progress_meter_path(local_path),
		    sb.st_size, &progress_counter);
	}

	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	માટે (;;) {
		પૂર્ણાંક len;

		/*
		 * Can't use atomicio here because it returns 0 on EOF,
		 * thus losing the last block of the file.
		 * Simulate an EOF on interrupt, allowing ACKs from the
		 * server to drain.
		 */
		જો (interrupted || status != SSH2_FX_OK)
			len = 0;
		નહીંતર કરો
			len = પઠ(local_fd, data, conn->upload_buflen);
		જ્યારે ((len == -1) &&
		    (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK));

		જો (len == -1) {
			fatal("read local \"%s\": %s",
			    local_path, strerror(errno));
		} નહીંતર જો (len != 0) {
			ack = request_enqueue(&acks, ++id, len, offset);
			sshbuf_reset(સંદેશ);
			જો ((r = sshbuf_put_u8(સંદેશ, SSH2_FXP_WRITE)) != 0 ||
			    (r = sshbuf_put_u32(સંદેશ, ack->id)) != 0 ||
			    (r = sshbuf_put_string(સંદેશ, handle,
			    handle_len)) != 0 ||
			    (r = sshbuf_put_u64(સંદેશ, offset)) != 0 ||
			    (r = sshbuf_put_string(સંદેશ, data, len)) != 0)
				fatal_fr(r, "compose");
			send_સંદેશ(conn, સંદેશ);
			debug3("Sent message SSH2_FXP_WRITE I:%u O:%llu S:%u",
			    id, (unsigned long long)offset, len);
		} નહીંતર જો (TAILQ_FIRST(&acks) == ખાલી)
			તોડો;

		જો (ack == ખાલી)
			fatal("Unexpected ACK %u", id);

		જો (id == startid || len == 0 ||
		    id - ackid >= conn->અંક_requests) {
			u_int rid;

			sshbuf_reset(સંદેશ);
			get_સંદેશ(conn, સંદેશ);
			જો ((r = sshbuf_get_u8(સંદેશ, &type)) != 0 ||
			    (r = sshbuf_get_u32(સંદેશ, &rid)) != 0)
				fatal_fr(r, "parse");

			જો (type != SSH2_FXP_STATUS)
				fatal("Expected SSH2_FXP_STATUS(%d) packet, "
				    "got %d", SSH2_FXP_STATUS, type);

			જો ((r = sshbuf_get_u32(સંદેશ, &status2)) != 0)
				fatal_fr(r, "parse status");
			debug3("SSH2_FXP_STATUS %u", status2);
			જો (status2 != SSH2_FX_OK)
				status = status2; /* remember errors */

			/* Find the request in our queue */
			જો ((ack = request_find(&acks, rid)) == ખાલી)
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
			જો (maxack < ack->offset + ack->len)
				maxack = ack->offset + ack->len;
			જો (!reordered && ack->offset <= highwater)
				highwater = maxack;
			નહીંતર જો (!reordered && ack->offset > highwater) {
				debug3_f("server reordered ACKs");
				reordered = 1;
			}
			મુક્ત(ack);
		}
		offset += len;
		જો (offset < 0)
			fatal_f("offset < 0");
	}
	sshbuf_free(સંદેશ);

	જો (showprogress)
		stop_progress_meter();
	મુક્ત(data);

	જો (status == SSH2_FX_OK && !interrupted) {
		/* we got everything */
		highwater = maxack;
	}
	જો (status != SSH2_FX_OK) {
		error("write remote \"%s\": %s", remote_path, fx2txt(status));
		status = SSH2_FX_FAILURE;
	}

	જો (inplace_flag || (resume && (status != SSH2_FX_OK || interrupted))) {
		debug("truncating at %llu", (unsigned long long)highwater);
		attrib_clear(&t);
		t.flags = SSH2_FILEXFER_ATTR_SIZE;
		t.size = highwater;
		sftp_fsetstat(conn, handle, handle_len, &t);
	}

	જો (close(local_fd) == -1) {
		error("close local \"%s\": %s", local_path, strerror(errno));
		status = SSH2_FX_FAILURE;
	}

	/* Override umask and utimes if asked */
	જો (preserve_flag)
		sftp_fsetstat(conn, handle, handle_len, &a);

	જો (fsync_flag)
		(શૂન્ય)sftp_fsync(conn, handle, handle_len);

	જો (sftp_close(conn, handle, handle_len) != 0)
		status = SSH2_FX_FAILURE;

	મુક્ત(handle);

	પાછા status == SSH2_FX_OK ? 0 : -1;
}

સ્થિર પૂર્ણાંક
upload_dir_internal(સંરચના sftp_conn *conn, અચલ અક્ષર *src, અચલ અક્ષર *dst,
    પૂર્ણાંક depth, પૂર્ણાંક preserve_flag, પૂર્ણાંક print_flag, પૂર્ણાંક resume, પૂર્ણાંક fsync_flag,
    પૂર્ણાંક follow_link_flag, પૂર્ણાંક inplace_flag)
{
	પૂર્ણાંક created = 0, ret = 0;
	DIR *dirp;
	સંરચના dirent *dp;
	અક્ષર *filename, *new_src = ખાલી, *new_dst = ખાલી;
	સંરચના stat sb;
	Attrib a, dirattrib;
	uint32_t saved_perm;

	debug2_f("upload local dir \"%s\" to remote \"%s\"", src, dst);

	જો (depth >= MAX_DIR_DEPTH) {
		error("Maximum directory depth exceeded: %d levels", depth);
		પાછા -1;
	}

	જો (stat(src, &sb) == -1) {
		error("stat local \"%s\": %s", src, strerror(errno));
		પાછા -1;
	}
	જો (!S_ISDIR(sb.st_mode)) {
		error("\"%s\" is not a directory", src);
		પાછા -1;
	}
	જો (print_flag && print_flag != SFTP_PROGRESS_ONLY)
		mprintf("Entering %s\n", src);

	stat_to_attrib(&sb, &a);
	a.flags &= ~SSH2_FILEXFER_ATTR_SIZE;
	a.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a.perm &= 01777;
	જો (!preserve_flag)
		a.flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;

	/*
	 * sftp lacks a portable status value to match errno EEXIST,
	 * so if we get a failure back then we must check whether
	 * the path already existed and is a directory.  Ensure we can
	 * write to the directory we create for the duration of the transfer.
	 */
	saved_perm = a.perm;
	a.perm |= (S_IWUSR|S_IXUSR);
	જો (sftp_mkdir(conn, dst, &a, 0) == 0)
		created = 1;
	નહીંતર {
		જો (sftp_stat(conn, dst, 0, &dirattrib) != 0)
			પાછા -1;
		જો (!S_ISDIR(dirattrib.perm)) {
			error("\"%s\" exists but is not a directory", dst);
			પાછા -1;
		}
	}
	a.perm = saved_perm;

	જો ((dirp = opendir(src)) == ખાલી) {
		error("local opendir \"%s\": %s", src, strerror(errno));
		પાછા -1;
	}

	જ્યારે (((dp = readdir(dirp)) != ખાલી) && !interrupted) {
		જો (dp->d_ino == 0)
			ચાલુ;
		મુક્ત(new_dst);
		મુક્ત(new_src);
		filename = dp->d_name;
		new_dst = sftp_path_append(dst, filename);
		new_src = sftp_path_append(src, filename);

		જો (strcmp(filename, ".") == 0 || strcmp(filename, "..") == 0)
			ચાલુ;
		જો (lstat(new_src, &sb) == -1) {
			logit("local lstat \"%s\": %s", filename,
			    strerror(errno));
			ret = -1;
			ચાલુ;
		}
		જો (S_ISLNK(sb.st_mode)) {
			જો (!follow_link_flag) {
				logit("%s: not a regular file", filename);
				ચાલુ;
			}
			/* Replace the stat contents with the symlink target */
			જો (stat(new_src, &sb) == -1) {
				logit("local stat \"%s\": %s", filename,
				    strerror(errno));
				ret = -1;
				ચાલુ;
			}
		}
		જો (S_ISDIR(sb.st_mode)) {
			જો (upload_dir_internal(conn, new_src, new_dst,
			    depth + 1, preserve_flag, print_flag, resume,
			    fsync_flag, follow_link_flag, inplace_flag) == -1)
				ret = -1;
		} નહીંતર જો (S_ISREG(sb.st_mode)) {
			જો (sftp_upload(conn, new_src, new_dst,
			    preserve_flag, resume, fsync_flag,
			    inplace_flag) == -1) {
				error("upload \"%s\" to \"%s\" failed",
				    new_src, new_dst);
				ret = -1;
			}
		} નહીંતર
			logit("%s: not a regular file", filename);
	}
	મુક્ત(new_dst);
	મુક્ત(new_src);

	જો (created || preserve_flag)
		sftp_setstat(conn, dst, &a);

	(શૂન્ય) closedir(dirp);
	પાછા ret;
}

પૂર્ણાંક
sftp_upload_dir(સંરચના sftp_conn *conn, અચલ અક્ષર *src, અચલ અક્ષર *dst,
    પૂર્ણાંક preserve_flag, પૂર્ણાંક print_flag, પૂર્ણાંક resume, પૂર્ણાંક fsync_flag,
    પૂર્ણાંક follow_link_flag, પૂર્ણાંક inplace_flag)
{
	અક્ષર *dst_canon;
	પૂર્ણાંક ret;

	જો ((dst_canon = sftp_realpath(conn, dst)) == ખાલી) {
		error("upload \"%s\": path canonicalization failed", dst);
		પાછા -1;
	}

	ret = upload_dir_internal(conn, src, dst_canon, 0, preserve_flag,
	    print_flag, resume, fsync_flag, follow_link_flag, inplace_flag);

	મુક્ત(dst_canon);
	પાછા ret;
}

સ્થિર શૂન્ય
handle_dest_replies(સંરચના sftp_conn *to, અચલ અક્ષર *to_path, પૂર્ણાંક synchronous,
    u_int *nreqsp, u_int *write_errorp)
{
	સંરચના sshbuf *સંદેશ;
	u_char type;
	u_int id, status;
	પૂર્ણાંક r;
	સંરચના pollfd pfd;

	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");

	/* Try to eat replies from the upload side */
	જ્યારે (*nreqsp > 0) {
		debug3_f("%u outstanding replies", *nreqsp);
		જો (!synchronous) {
			/* Bail out if no data is ready to be read */
			pfd.fd = to->fd_in;
			pfd.events = POLLIN;
			જો ((r = poll(&pfd, 1, 0)) == -1) {
				જો (errno == EINTR)
					તોડો;
				fatal_f("poll: %s", strerror(errno));
			} નહીંતર જો (r == 0)
				તોડો; /* fd not ready */
		}
		sshbuf_reset(સંદેશ);
		get_સંદેશ(to, સંદેશ);

		જો ((r = sshbuf_get_u8(સંદેશ, &type)) != 0 ||
		    (r = sshbuf_get_u32(સંદેશ, &id)) != 0)
			fatal_fr(r, "dest parse");
		debug3("Received dest reply T:%u I:%u R:%u", type, id, *nreqsp);
		જો (type != SSH2_FXP_STATUS) {
			fatal_f("Expected SSH2_FXP_STATUS(%d) packet, got %d",
			    SSH2_FXP_STATUS, type);
		}
		જો ((r = sshbuf_get_u32(સંદેશ, &status)) != 0)
			fatal_fr(r, "parse dest status");
		debug3("dest SSH2_FXP_STATUS %u", status);
		જો (status != SSH2_FX_OK) {
			/* record first error */
			જો (*write_errorp == 0)
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
	sshbuf_free(સંદેશ);
}

પૂર્ણાંક
sftp_crossload(સંરચના sftp_conn *from, સંરચના sftp_conn *to,
    અચલ અક્ષર *from_path, અચલ અક્ષર *to_path,
    Attrib *a, પૂર્ણાંક preserve_flag)
{
	સંરચના sshbuf *સંદેશ;
	પૂર્ણાંક write_error, read_error, r, seen_zerolen = 0;
	uint64_t offset = 0, size;
	u_int id, buflen, અંક_req, max_req, status = SSH2_FX_OK;
	u_int અંક_upload_req;
	off_t progress_counter;
	u_char *from_handle, *to_handle;
	size_t from_handle_len, to_handle_len;
	સંરચના requests requests;
	સંરચના request *req;
	u_char type;
	Attrib attr;

	debug2_f("crossload src \"%s\" to dst \"%s\"", from_path, to_path);

	TAILQ_INIT(&requests);

	જો (a == ખાલી) {
		જો (sftp_stat(from, from_path, 0, &attr) != 0)
			પાછા -1;
		a = &attr;
	}

	જો ((a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) &&
	    (!S_ISREG(a->perm))) {
		error("download \"%s\": not a regular file", from_path);
		પાછા(-1);
	}
	જો (a->flags & SSH2_FILEXFER_ATTR_SIZE)
		size = a->size;
	નહીંતર
		size = 0;

	buflen = from->download_buflen;
	જો (buflen > to->upload_buflen)
		buflen = to->upload_buflen;

	/* Send open request to read side */
	જો (send_open(from, from_path, "origin", SSH2_FXF_READ, ખાલી,
	    &from_handle, &from_handle_len) != 0)
		પાછા -1;

	/* Send open request to write side */
	a->flags &= ~SSH2_FILEXFER_ATTR_SIZE;
	a->flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a->perm &= 0777;
	જો (!preserve_flag)
		a->flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;
	જો (send_open(to, to_path, "dest",
	    SSH2_FXF_WRITE|SSH2_FXF_CREAT|SSH2_FXF_TRUNC, a,
	    &to_handle, &to_handle_len) != 0) {
		sftp_close(from, from_handle, from_handle_len);
		પાછા -1;
	}

	/* Read from remote "from" and write to remote "to" */
	offset = 0;
	write_error = read_error = અંક_req = અંક_upload_req = 0;
	max_req = 1;
	progress_counter = 0;

	જો (showprogress && size != 0) {
		start_progress_meter(progress_meter_path(from_path),
		    size, &progress_counter);
	}
	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જ્યારે (અંક_req > 0 || max_req > 0) {
		u_char *data;
		size_t len;

		/*
		 * Simulate EOF on interrupt: stop sending new requests and
		 * allow outstanding requests to drain gracefully
		 */
		જો (interrupted) {
			જો (અંક_req == 0) /* If we haven't started yet... */
				તોડો;
			max_req = 0;
		}

		/* Send some more requests */
		જ્યારે (અંક_req < max_req) {
			debug3("Request range %llu -> %llu (%d/%d)",
			    (unsigned long long)offset,
			    (unsigned long long)offset + buflen - 1,
			    અંક_req, max_req);
			req = request_enqueue(&requests, from->સંદેશ_id++,
			    buflen, offset);
			offset += buflen;
			અંક_req++;
			send_read_request(from, req->id, req->offset,
			    req->len, from_handle, from_handle_len);
		}

		/* Try to eat replies from the upload side (nonblocking) */
		handle_dest_replies(to, to_path, 0,
		    &અંક_upload_req, &write_error);

		sshbuf_reset(સંદેશ);
		get_સંદેશ(from, સંદેશ);
		જો ((r = sshbuf_get_u8(સંદેશ, &type)) != 0 ||
		    (r = sshbuf_get_u32(સંદેશ, &id)) != 0)
			fatal_fr(r, "parse");
		debug3("Received origin reply T:%u I:%u R:%d",
		    type, id, max_req);

		/* Find the request in our queue */
		જો ((req = request_find(&requests, id)) == ખાલી)
			fatal("Unexpected reply %u", id);

		પસંદગી (type) {
		સ્થિતિ SSH2_FXP_STATUS:
			જો ((r = sshbuf_get_u32(સંદેશ, &status)) != 0)
				fatal_fr(r, "parse status");
			જો (status != SSH2_FX_EOF)
				read_error = 1;
			max_req = 0;
			TAILQ_REMOVE(&requests, req, tq);
			મુક્ત(req);
			અંક_req--;
			તોડો;
		સ્થિતિ SSH2_FXP_DATA:
			જો ((r = sshbuf_get_string(સંદેશ, &data, &len)) != 0)
				fatal_fr(r, "parse data");
			debug3("Received data %llu -> %llu",
			    (unsigned long long)req->offset,
			    (unsigned long long)req->offset + len - 1);
			જો (len > req->len)
				fatal("Received more data than asked for "
				    "%zu > %zu", len, req->len);
			જો (len == 0) {
				જો (seen_zerolen)
					fatal_f("server sent zero data length");
				seen_zerolen = 1;
			}

			/* Write this chunk out to the destination */
			sshbuf_reset(સંદેશ);
			જો ((r = sshbuf_put_u8(સંદેશ, SSH2_FXP_WRITE)) != 0 ||
			    (r = sshbuf_put_u32(સંદેશ, to->સંદેશ_id++)) != 0 ||
			    (r = sshbuf_put_string(સંદેશ, to_handle,
			    to_handle_len)) != 0 ||
			    (r = sshbuf_put_u64(સંદેશ, req->offset)) != 0 ||
			    (r = sshbuf_put_string(સંદેશ, data, len)) != 0)
				fatal_fr(r, "compose write");
			send_સંદેશ(to, સંદેશ);
			debug3("Sent message SSH2_FXP_WRITE I:%u O:%llu S:%zu",
			    id, (unsigned long long)offset, len);
			અંક_upload_req++;
			progress_counter += len;
			મુક્ત(data);

			જો (len == req->len) {
				TAILQ_REMOVE(&requests, req, tq);
				મુક્ત(req);
				અંક_req--;
			} નહીંતર {
				/* Resend the request for the missing data */
				debug3("Short data block, re-requesting "
				    "%llu -> %llu (%2d)",
				    (unsigned long long)req->offset + len,
				    (unsigned long long)req->offset +
				    req->len - 1, અંક_req);
				req->id = from->સંદેશ_id++;
				req->len -= len;
				req->offset += len;
				send_read_request(from, req->id,
				    req->offset, req->len,
				    from_handle, from_handle_len);
				/* Reduce the request size */
				જો (len < buflen)
					buflen = MAXIMUM(MIN_READ_SIZE, len);
			}
			જો (max_req > 0) { /* max_req = 0 iff EOF received */
				જો (size > 0 && offset > size) {
					/* Only one request at a time
					 * after the expected EOF */
					debug3("Finish at %llu (%2d)",
					    (unsigned long long)offset,
					    અંક_req);
					max_req = 1;
				} નહીંતર જો (max_req < from->અંક_requests) {
					++max_req;
				}
			}
			તોડો;
		મૂળભૂત:
			fatal("Expected SSH2_FXP_DATA(%u) packet, got %u",
			    SSH2_FXP_DATA, type);
		}
	}

	જો (showprogress && size)
		stop_progress_meter();

	/* Drain replies from the server (blocking) */
	debug3_f("waiting for %u replies from destination", અંક_upload_req);
	handle_dest_replies(to, to_path, 1, &અંક_upload_req, &write_error);

	/* Sanity check */
	જો (TAILQ_FIRST(&requests) != ખાલી)
		fatal("Transfer complete, but requests still in queue");
	/* Truncate at 0 length on interrupt or error to avoid holes at dest */
	જો (read_error || write_error || interrupted) {
		debug("truncating \"%s\" at 0", to_path);
		sftp_close(to, to_handle, to_handle_len);
		મુક્ત(to_handle);
		જો (send_open(to, to_path, "dest",
		    SSH2_FXF_WRITE|SSH2_FXF_CREAT|SSH2_FXF_TRUNC, a,
		    &to_handle, &to_handle_len) != 0) {
			error("dest truncate \"%s\" failed", to_path);
			to_handle = ખાલી;
		}
	}
	જો (read_error) {
		error("read origin \"%s\": %s", from_path, fx2txt(status));
		status = -1;
		sftp_close(from, from_handle, from_handle_len);
		જો (to_handle != ખાલી)
			sftp_close(to, to_handle, to_handle_len);
	} નહીંતર જો (write_error) {
		error("write dest \"%s\": %s", to_path, fx2txt(write_error));
		status = SSH2_FX_FAILURE;
		sftp_close(from, from_handle, from_handle_len);
		જો (to_handle != ખાલી)
			sftp_close(to, to_handle, to_handle_len);
	} નહીંતર {
		જો (sftp_close(from, from_handle, from_handle_len) != 0 ||
		    interrupted)
			status = -1;
		નહીંતર
			status = SSH2_FX_OK;
		જો (to_handle != ખાલી) {
			/* Need to resend utimes after write */
			જો (preserve_flag)
				sftp_fsetstat(to, to_handle, to_handle_len, a);
			sftp_close(to, to_handle, to_handle_len);
		}
	}
	sshbuf_free(સંદેશ);
	મુક્ત(from_handle);
	મુક્ત(to_handle);

	પાછા status == SSH2_FX_OK ? 0 : -1;
}

સ્થિર પૂર્ણાંક
crossload_dir_internal(સંરચના sftp_conn *from, સંરચના sftp_conn *to,
    અચલ અક્ષર *from_path, અચલ અક્ષર *to_path,
    પૂર્ણાંક depth, Attrib *dirattrib, પૂર્ણાંક preserve_flag, પૂર્ણાંક print_flag,
    પૂર્ણાંક follow_link_flag)
{
	પૂર્ણાંક i, ret = 0, created = 0;
	SFTP_DIRENT **dir_entries;
	અક્ષર *filename, *new_from_path = ખાલી, *new_to_path = ખાલી;
	mode_t mode = 0777;
	Attrib *a, curdir, ldirattrib, newdir, lsym;

	debug2_f("crossload dir src \"%s\" to dst \"%s\"", from_path, to_path);

	જો (depth >= MAX_DIR_DEPTH) {
		error("Maximum directory depth exceeded: %d levels", depth);
		પાછા -1;
	}

	જો (dirattrib == ખાલી) {
		જો (sftp_stat(from, from_path, 1, &ldirattrib) != 0) {
			error("stat remote \"%s\" failed", from_path);
			પાછા -1;
		}
		dirattrib = &ldirattrib;
	}
	જો (!S_ISDIR(dirattrib->perm)) {
		error("\"%s\" is not a directory", from_path);
		પાછા -1;
	}
	જો (print_flag && print_flag != SFTP_PROGRESS_ONLY)
		mprintf("Retrieving %s\n", from_path);

	curdir = *dirattrib; /* dirattrib will be clobbered */
	curdir.flags &= ~SSH2_FILEXFER_ATTR_SIZE;
	curdir.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	જો ((curdir.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) == 0) {
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
	જો (sftp_mkdir(to, to_path, &curdir, 0) == 0)
		created = 1;
	નહીંતર {
		જો (sftp_stat(to, to_path, 0, &newdir) != 0)
			પાછા -1;
		જો (!S_ISDIR(newdir.perm)) {
			error("\"%s\" exists but is not a directory", to_path);
			પાછા -1;
		}
	}
	curdir.perm = mode;

	જો (sftp_readdir(from, from_path, &dir_entries) == -1) {
		error("origin readdir \"%s\" failed", from_path);
		પાછા -1;
	}

	માટે (i = 0; dir_entries[i] != ખાલી && !interrupted; i++) {
		મુક્ત(new_from_path);
		મુક્ત(new_to_path);

		filename = dir_entries[i]->filename;
		new_from_path = sftp_path_append(from_path, filename);
		new_to_path = sftp_path_append(to_path, filename);

		a = &dir_entries[i]->a;
		જો (S_ISLNK(a->perm)) {
			જો (!follow_link_flag) {
				logit("%s: not a regular file", filename);
				ચાલુ;
			}
			/* Replace the stat contents with the symlink target */
			જો (sftp_stat(from, new_from_path, 1, &lsym) != 0) {
				logit("remote stat \"%s\" failed",
				    new_from_path);
				ret = -1;
				ચાલુ;
			}
			a = &lsym;
		}
		જો (S_ISDIR(a->perm)) {
			જો (strcmp(filename, ".") == 0 ||
			    strcmp(filename, "..") == 0)
				ચાલુ;
			જો (crossload_dir_internal(from, to,
			    new_from_path, new_to_path,
			    depth + 1, a, preserve_flag,
			    print_flag, follow_link_flag) == -1)
				ret = -1;
		} નહીંતર જો (S_ISREG(a->perm)) {
			જો (sftp_crossload(from, to, new_from_path,
			    new_to_path, a, preserve_flag) == -1) {
				error("crossload \"%s\" to \"%s\" failed",
				    new_from_path, new_to_path);
				ret = -1;
			}
		} નહીંતર {
			logit("origin \"%s\": not a regular file",
			    new_from_path);
		}
	}
	મુક્ત(new_to_path);
	મુક્ત(new_from_path);

	જો (created || preserve_flag)
		sftp_setstat(to, to_path, &curdir);

	sftp_free_dirents(dir_entries);

	પાછા ret;
}

પૂર્ણાંક
sftp_crossload_dir(સંરચના sftp_conn *from, સંરચના sftp_conn *to,
    અચલ અક્ષર *from_path, અચલ અક્ષર *to_path,
    Attrib *dirattrib, પૂર્ણાંક preserve_flag, પૂર્ણાંક print_flag, પૂર્ણાંક follow_link_flag)
{
	અક્ષર *from_path_canon;
	પૂર્ણાંક ret;

	જો ((from_path_canon = sftp_realpath(from, from_path)) == ખાલી) {
		error("crossload \"%s\": path canonicalization failed",
		    from_path);
		પાછા -1;
	}

	ret = crossload_dir_internal(from, to, from_path_canon, to_path, 0,
	    dirattrib, preserve_flag, print_flag, follow_link_flag);
	મુક્ત(from_path_canon);
	પાછા ret;
}

પૂર્ણાંક
sftp_can_get_users_groups_by_id(સંરચના sftp_conn *conn)
{
	પાછા (conn->exts & SFTP_EXT_GETUSERSGROUPS_BY_ID) != 0;
}

પૂર્ણાંક
sftp_get_users_groups_by_id(સંરચના sftp_conn *conn,
    અચલ u_int *uids, u_int nuids,
    અચલ u_int *gids, u_int ngids,
    અક્ષર ***usernamesp, અક્ષર ***groupnamesp)
{
	સંરચના sshbuf *સંદેશ, *uidbuf, *gidbuf;
	u_int i, expected_id, id;
	અક્ષર *name, **usernames = ખાલી, **groupnames = ખાલી;
	u_char type;
	પૂર્ણાંક r;

	*usernamesp = *groupnamesp = ખાલી;
	જો (!sftp_can_get_users_groups_by_id(conn))
		પાછા SSH_ERR_FEATURE_UNSUPPORTED;

	જો ((સંદેશ = sshbuf_new()) == ખાલી ||
	    (uidbuf = sshbuf_new()) == ખાલી ||
	    (gidbuf = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	expected_id = id = conn->સંદેશ_id++;
	debug2("Sending SSH2_FXP_EXTENDED(users-groups-by-id@openssh.com)");
	માટે (i = 0; i < nuids; i++) {
		જો ((r = sshbuf_put_u32(uidbuf, uids[i])) != 0)
			fatal_fr(r, "compose uids");
	}
	માટે (i = 0; i < ngids; i++) {
		જો ((r = sshbuf_put_u32(gidbuf, gids[i])) != 0)
			fatal_fr(r, "compose gids");
	}
	જો ((r = sshbuf_put_u8(સંદેશ, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(સંદેશ, id)) != 0 ||
	    (r = sshbuf_put_cstring(સંદેશ,
	    "users-groups-by-id@openssh.com")) != 0 ||
	    (r = sshbuf_put_stringb(સંદેશ, uidbuf)) != 0 ||
	    (r = sshbuf_put_stringb(સંદેશ, gidbuf)) != 0)
		fatal_fr(r, "compose");
	send_સંદેશ(conn, સંદેશ);
	get_સંદેશ(conn, સંદેશ);
	જો ((r = sshbuf_get_u8(સંદેશ, &type)) != 0 ||
	    (r = sshbuf_get_u32(સંદેશ, &id)) != 0)
		fatal_fr(r, "parse");
	જો (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	જો (type == SSH2_FXP_STATUS) {
		u_int status;
		અક્ષર *errmsg;

		જો ((r = sshbuf_get_u32(સંદેશ, &status)) != 0 ||
		    (r = sshbuf_get_cstring(સંદેશ, &errmsg, ખાલી)) != 0)
			fatal_fr(r, "parse status");
		error("users-groups-by-id %s",
		    *errmsg == '\0' ? fx2txt(status) : errmsg);
		મુક્ત(errmsg);
		sshbuf_free(સંદેશ);
		sshbuf_free(uidbuf);
		sshbuf_free(gidbuf);
		પાછા -1;
	} નહીંતર જો (type != SSH2_FXP_EXTENDED_REPLY)
		fatal("Expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_REPLY, type);

	/* reuse */
	sshbuf_free(uidbuf);
	sshbuf_free(gidbuf);
	uidbuf = gidbuf = ખાલી;
	જો ((r = sshbuf_froms(સંદેશ, &uidbuf)) != 0 ||
	    (r = sshbuf_froms(સંદેશ, &gidbuf)) != 0)
		fatal_fr(r, "parse response");
	જો (nuids > 0) {
		usernames = xcalloc(nuids, કદ(*usernames));
		માટે (i = 0; i < nuids; i++) {
			જો ((r = sshbuf_get_cstring(uidbuf, &name, ખાલી)) != 0)
				fatal_fr(r, "parse user name");
			/* Handle unresolved names */
			જો (*name == '\0') {
				મુક્ત(name);
				name = ખાલી;
			}
			usernames[i] = name;
		}
	}
	જો (ngids > 0) {
		groupnames = xcalloc(ngids, કદ(*groupnames));
		માટે (i = 0; i < ngids; i++) {
			જો ((r = sshbuf_get_cstring(gidbuf, &name, ખાલી)) != 0)
				fatal_fr(r, "parse user name");
			/* Handle unresolved names */
			જો (*name == '\0') {
				મુક્ત(name);
				name = ખાલી;
			}
			groupnames[i] = name;
		}
	}
	જો (sshbuf_len(uidbuf) != 0)
		fatal_f("unexpected extra username data");
	જો (sshbuf_len(gidbuf) != 0)
		fatal_f("unexpected extra groupname data");
	sshbuf_free(uidbuf);
	sshbuf_free(gidbuf);
	sshbuf_free(સંદેશ);
	/* success */
	*usernamesp = usernames;
	*groupnamesp = groupnames;
	પાછા 0;
}

અક્ષર *
sftp_path_append(અચલ અક્ષર *p1, અચલ અક્ષર *p2)
{
	અક્ષર *ret;
	size_t len = strlen(p1) + strlen(p2) + 2;

	ret = xmalloc(len);
	strlcpy(ret, p1, len);
	જો (p1[0] != '\0' && p1[strlen(p1) - 1] != '/')
		strlcat(ret, "/", len);
	strlcat(ret, p2, len);

	પાછા(ret);
}

/*
 * Arg p must be dynamically allocated.  It will either be returned or
 * freed and a replacement allocated.  Caller must free returned string.
 */
અક્ષર *
sftp_make_absolute(અક્ષર *p, અચલ અક્ષર *pwd)
{
	અક્ષર *abs_str;

	/* Derelativise */
	જો (p && !path_absolute(p)) {
		abs_str = sftp_path_append(pwd, p);
		મુક્ત(p);
		પાછા(abs_str);
	} નહીંતર
		પાછા(p);
}

પૂર્ણાંક
sftp_remote_is_dir(સંરચના sftp_conn *conn, અચલ અક્ષર *path)
{
	Attrib a;

	/* XXX: report errors? */
	જો (sftp_stat(conn, path, 1, &a) != 0)
		પાછા(0);
	જો (!(a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS))
		પાછા(0);
	પાછા S_ISDIR(a.perm);
}


/* Check whether path returned from glob(..., GLOB_MARK, ...) is a directory */
પૂર્ણાંક
sftp_globpath_is_dir(અચલ અક્ષર *pathname)
{
	size_t l = strlen(pathname);

	પાછા l > 0 && pathname[l - 1] == '/';
}

