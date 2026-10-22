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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/queue.h>
#అన్తర్భావ <sys/stat.h>
#అన్తర్భావ <sys/time.h>
#అన్తర్భావ <sys/statvfs.h>
#అన్తర్భావ <sys/uio.h>

#అన్తర్భావ <dirent.h>
#అన్తర్భావ <errno.h>
#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <poll.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "atomicio.h"
#అన్తర్భావ "progressmeter.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "utf8.h"

#అన్తర్భావ "sftp.h"
#అన్తర్భావ "sftp-common.h"
#అన్తర్భావ "sftp-client.h"

బాహ్య అస్థిర sig_atomic_t interrupted;
బాహ్య పూర్ణాంకం showprogress;

/* Default size of buffer for up/download (fix sftp.1 scp.1 if changed) */
#నిర్వచించు DEFAULT_COPY_BUFLEN	32768

/* Default number of concurrent xfer requests (fix sftp.1 scp.1 if changed) */
#నిర్వచించు DEFAULT_అంకె_అభ్యర్థనలు	64

/* Minimum amount of data to read at a time */
#నిర్వచించు MIN_READ_కొలత	512

/* Maximum depth to descend in directory trees */
#నిర్వచించు MAX_DIR_లోతు 64

/* Directory separator characters */
#నిర్వచితమైతే HAVE_CYGWIN
# define SFTP_DIRECTORY_CHARS      "/\\"
#లేకపోతే /* HAVE_CYGWIN */
# define SFTP_DIRECTORY_CHARS      "/"
#అయితే_ముగింపు /* HAVE_CYGWIN */

నిర్మాణం sftp_conn {
	పూర్ణాంకం fd_లోపల;
	పూర్ణాంకం fd_బహిర్గతం;
	u_int download_buflen;
	u_int upload_buflen;
	u_int అంకె_అభ్యర్థనలు;
	u_int సంస్కరణ;
	u_int సందేశం_id;
#నిర్వచించు SFTP_EXT_POSIX_RENAME		0x00000001
#నిర్వచించు SFTP_EXT_STATVFS		0x00000002
#నిర్వచించు SFTP_EXT_FSTATVFS		0x00000004
#నిర్వచించు SFTP_EXT_HARDLINK		0x00000008
#నిర్వచించు SFTP_EXT_FSYNC			0x00000010
#నిర్వచించు SFTP_EXT_LSETSTAT		0x00000020
#నిర్వచించు SFTP_EXT_LIMITS			0x00000040
#నిర్వచించు SFTP_EXT_మార్గం_EXPAND		0x00000080
#నిర్వచించు SFTP_EXT_COPY_దత్తాంశం		0x00000100
#నిర్వచించు SFTP_EXT_GETUSERSGROUPS_BY_ID	0x00000200
	u_int exts;
	uint64_t హద్దు_kbps;
	నిర్మాణం bwlimit bwlimit_లోపల, bwlimit_బహిర్గతం;
};

/* Tracks in-progress requests during file transfers */
నిర్మాణం request {
	u_int id;
	కొలత_t len;
	uint64_t స్థానభ్రంశం;
	TAILQ_ENTRY(request) tq;
};
TAILQ_HEAD(అభ్యర్థనలు, request);

స్థిర u_char *
get_handle(నిర్మాణం sftp_conn *conn, u_int expected_id, కొలత_t *len,
    స్థిరరాశి అక్షరం *errfmt, ...) __attribute__((format(రాయి, 4, 5)));

స్థిర నిర్మాణం request *
request_వరుసలో_చేర్చు(నిర్మాణం అభ్యర్థనలు *అభ్యర్థనలు, u_int id, కొలత_t len,
    uint64_t స్థానభ్రంశం)
{
	నిర్మాణం request *req;

	req = xcalloc(1, పరిమాణం(*req));
	req->id = id;
	req->len = len;
	req->స్థానభ్రంశం = స్థానభ్రంశం;
	TAILQ_INSERT_TAIL(అభ్యర్థనలు, req, tq);
	తిరిగి req;
}

స్థిర నిర్మాణం request *
request_కనుగొను(నిర్మాణం అభ్యర్థనలు *అభ్యర్థనలు, u_int id)
{
	నిర్మాణం request *req;

	కొరకు (req = TAILQ_FIRST(అభ్యర్థనలు);
	    req != ఖాళీ && req->id != id;
	    req = TAILQ_NEXT(req, tq))
		;
	తిరిగి req;
}

స్థిర పూర్ణాంకం
sftpio(శూన్య *_bwlimit, కొలత_t amount)
{
	నిర్మాణం bwlimit *bwlimit = (నిర్మాణం bwlimit *)_bwlimit;

	refresh_పురోగతి_meter(0);
	ఒకవేళ (bwlimit != ఖాళీ)
		bandwidth_హద్దు(bwlimit, amount);
	తిరిగి 0;
}

స్థిర శూన్య
send_సందేశం(నిర్మాణం sftp_conn *conn, నిర్మాణం sshbuf *m)
{
	u_char mlen[4];
	నిర్మాణం iovec iov[2];

	ఒకవేళ (sshbuf_len(m) > SFTP_MAX_సందేశం_నిడివి)
		fatal("Outbound message too long %zu", sshbuf_len(m));

	/* Send length first */
	put_u32(mlen, sshbuf_len(m));
	iov[0].iov_base = mlen;
	iov[0].iov_len = పరిమాణం(mlen);
	iov[1].iov_base = (u_char *)sshbuf_ptr(m);
	iov[1].iov_len = sshbuf_len(m);

	ఒకవేళ (atomiciov6(writev, conn->fd_బహిర్గతం, iov, 2, sftpio,
	    conn->హద్దు_kbps > 0 ? &conn->bwlimit_బహిర్గతం : ఖాళీ) !=
	    sshbuf_len(m) + పరిమాణం(mlen))
		fatal("Couldn't send packet: %s", strerror(errno));

	sshbuf_reset(m);
}

స్థిర శూన్య
get_సందేశం_extended(నిర్మాణం sftp_conn *conn, నిర్మాణం sshbuf *m, పూర్ణాంకం initial)
{
	u_int సందేశం_len;
	u_char *p;
	పూర్ణాంకం r;

	sshbuf_reset(m);
	ఒకవేళ ((r = sshbuf_reserve(m, 4, &p)) != 0)
		fatal_fr(r, "reserve");
	ఒకవేళ (atomicio6(పఠ, conn->fd_లోపల, p, 4, sftpio,
	    conn->హద్దు_kbps > 0 ? &conn->bwlimit_లోపల : ఖాళీ) != 4) {
		ఒకవేళ (errno == EPIPE || errno == ECONNRESET)
			fatal("Connection closed");
		లేకపోతే
			fatal("Couldn't read packet: %s", strerror(errno));
	}

	ఒకవేళ ((r = sshbuf_get_u32(m, &సందేశం_len)) != 0)
		fatal_fr(r, "sshbuf_get_u32");
	ఒకవేళ (సందేశం_len > SFTP_MAX_సందేశం_నిడివి) {
		do_log2(initial ? SYSLOG_LEVEL_ERROR : SYSLOG_LEVEL_FATAL,
		    "Received message too long %u", సందేశం_len);
		fatal("Ensure the remote shell produces no output "
		    "for non-interactive sessions.");
	}

	ఒకవేళ ((r = sshbuf_reserve(m, సందేశం_len, &p)) != 0)
		fatal_fr(r, "reserve");
	ఒకవేళ (atomicio6(పఠ, conn->fd_లోపల, p, సందేశం_len, sftpio,
	    conn->హద్దు_kbps > 0 ? &conn->bwlimit_లోపల : ఖాళీ)
	    != సందేశం_len) {
		ఒకవేళ (errno == EPIPE)
			fatal("Connection closed");
		లేకపోతే
			fatal("Read packet: %s", strerror(errno));
	}
}

స్థిర శూన్య
get_సందేశం(నిర్మాణం sftp_conn *conn, నిర్మాణం sshbuf *m)
{
	get_సందేశం_extended(conn, m, 0);
}

స్థిర శూన్య
send_string_request(నిర్మాణం sftp_conn *conn, u_int id, u_int సంకేతం_2, స్థిరరాశి అక్షరం *s,
    u_int len)
{
	నిర్మాణం sshbuf *సందేశం;
	పూర్ణాంకం r;

	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = sshbuf_put_u8(సందేశం, సంకేతం_2)) != 0 ||
	    (r = sshbuf_put_u32(సందేశం, id)) != 0 ||
	    (r = sshbuf_put_string(సందేశం, s, len)) != 0)
		fatal_fr(r, "compose");
	send_సందేశం(conn, సందేశం);
	debug3("Sent message fd %d T:%u I:%u", conn->fd_బహిర్గతం, సంకేతం_2, id);
	sshbuf_free(సందేశం);
}

స్థిర శూన్య
send_string_attrs_request(నిర్మాణం sftp_conn *conn, u_int id, u_int సంకేతం_2,
    స్థిరరాశి శూన్య *s, u_int len, Attrib *a)
{
	నిర్మాణం sshbuf *సందేశం;
	పూర్ణాంకం r;

	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = sshbuf_put_u8(సందేశం, సంకేతం_2)) != 0 ||
	    (r = sshbuf_put_u32(సందేశం, id)) != 0 ||
	    (r = sshbuf_put_string(సందేశం, s, len)) != 0 ||
	    (r = encode_attrib(సందేశం, a)) != 0)
		fatal_fr(r, "compose");
	send_సందేశం(conn, సందేశం);
	debug3("Sent message fd %d T:%u I:%u F:0x%04x M:%05o",
	    conn->fd_బహిర్గతం, సంకేతం_2, id, a->flags, a->perm);
	sshbuf_free(సందేశం);
}

స్థిర u_int
get_స్థితి(నిర్మాణం sftp_conn *conn, u_int expected_id)
{
	నిర్మాణం sshbuf *సందేశం;
	u_char type;
	u_int id, స్థితి_2;
	పూర్ణాంకం r;

	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	get_సందేశం(conn, సందేశం);
	ఒకవేళ ((r = sshbuf_get_u8(సందేశం, &type)) != 0 ||
	    (r = sshbuf_get_u32(సందేశం, &id)) != 0)
		fatal_fr(r, "compose");

	ఒకవేళ (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	ఒకవేళ (type != SSH2_FXP_స్థితి)
		fatal("Expected SSH2_FXP_STATUS(%u) packet, got %u",
		    SSH2_FXP_స్థితి, type);

	ఒకవేళ ((r = sshbuf_get_u32(సందేశం, &స్థితి_2)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(సందేశం);

	debug3("SSH2_FXP_STATUS %u", స్థితి_2);

	తిరిగి స్థితి_2;
}

స్థిర u_char *
get_handle(నిర్మాణం sftp_conn *conn, u_int expected_id, కొలత_t *len,
    స్థిరరాశి అక్షరం *errfmt, ...)
{
	నిర్మాణం sshbuf *సందేశం;
	u_int id, స్థితి_2;
	u_char type;
	u_char *handle;
	అక్షరం errmsg[256];
	va_list వాదనలు;
	పూర్ణాంకం r;

	va_start(వాదనలు, errfmt);
	ఒకవేళ (errfmt != ఖాళీ)
		vsnprintf(errmsg, పరిమాణం(errmsg), errfmt, వాదనలు);
	va_end(వాదనలు);

	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	get_సందేశం(conn, సందేశం);
	ఒకవేళ ((r = sshbuf_get_u8(సందేశం, &type)) != 0 ||
	    (r = sshbuf_get_u32(సందేశం, &id)) != 0)
		fatal_fr(r, "parse");

	ఒకవేళ (id != expected_id)
		fatal("%s: ID mismatch (%u != %u)",
		    errfmt == ఖాళీ ? __func__ : errmsg, id, expected_id);
	ఒకవేళ (type == SSH2_FXP_స్థితి) {
		ఒకవేళ ((r = sshbuf_get_u32(సందేశం, &స్థితి_2)) != 0)
			fatal_fr(r, "parse status");
		ఒకవేళ (errfmt != ఖాళీ)
			error("%s: %s", errmsg, fx2txt(స్థితి_2));
		sshbuf_free(సందేశం);
		తిరిగి(ఖాళీ);
	} లేకపోతే ఒకవేళ (type != SSH2_FXP_HANDLE)
		fatal("%s: Expected SSH2_FXP_HANDLE(%u) packet, got %u",
		    errfmt == ఖాళీ ? __func__ : errmsg, SSH2_FXP_HANDLE, type);

	ఒకవేళ ((r = sshbuf_get_string(సందేశం, &handle, len)) != 0)
		fatal_fr(r, "parse handle");
	sshbuf_free(సందేశం);

	తిరిగి handle;
}

స్థిర పూర్ణాంకం
get_decode_stat(నిర్మాణం sftp_conn *conn, u_int expected_id, పూర్ణాంకం quiet, Attrib *a)
{
	నిర్మాణం sshbuf *సందేశం;
	u_int id;
	u_char type;
	పూర్ణాంకం r;
	Attrib attr;

	ఒకవేళ (a != ఖాళీ)
		memset(a, '\0', పరిమాణం(*a));
	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	get_సందేశం(conn, సందేశం);

	ఒకవేళ ((r = sshbuf_get_u8(సందేశం, &type)) != 0 ||
	    (r = sshbuf_get_u32(సందేశం, &id)) != 0)
		fatal_fr(r, "parse");

	ఒకవేళ (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	ఒకవేళ (type == SSH2_FXP_స్థితి) {
		u_int స్థితి_2;

		ఒకవేళ ((r = sshbuf_get_u32(సందేశం, &స్థితి_2)) != 0)
			fatal_fr(r, "parse status");
		ఒకవేళ (quiet)
			debug("stat remote: %s", fx2txt(స్థితి_2));
		లేకపోతే
			error("stat remote: %s", fx2txt(స్థితి_2));
		sshbuf_free(సందేశం);
		తిరిగి -1;
	} లేకపోతే ఒకవేళ (type != SSH2_FXP_ATTRS) {
		fatal("Expected SSH2_FXP_ATTRS(%u) packet, got %u",
		    SSH2_FXP_ATTRS, type);
	}
	ఒకవేళ ((r = decode_attrib(సందేశం, &attr)) != 0) {
		error_fr(r, "decode_attrib");
		sshbuf_free(సందేశం);
		తిరిగి -1;
	}
	/* success */
	ఒకవేళ (a != ఖాళీ)
		*a = attr;
	debug3("Received stat reply T:%u I:%u F:0x%04x M:%05o",
	    type, id, attr.flags, attr.perm);
	sshbuf_free(సందేశం);

	తిరిగి 0;
}

స్థిర పూర్ణాంకం
get_decode_statvfs(నిర్మాణం sftp_conn *conn, నిర్మాణం sftp_statvfs *st,
    u_int expected_id, పూర్ణాంకం quiet)
{
	నిర్మాణం sshbuf *సందేశం;
	u_char type;
	u_int id;
	uint64_t flag;
	పూర్ణాంకం r;

	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	get_సందేశం(conn, సందేశం);

	ఒకవేళ ((r = sshbuf_get_u8(సందేశం, &type)) != 0 ||
	    (r = sshbuf_get_u32(సందేశం, &id)) != 0)
		fatal_fr(r, "parse");

	debug3("Received statvfs reply T:%u I:%u", type, id);
	ఒకవేళ (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	ఒకవేళ (type == SSH2_FXP_స్థితి) {
		u_int స్థితి_2;

		ఒకవేళ ((r = sshbuf_get_u32(సందేశం, &స్థితి_2)) != 0)
			fatal_fr(r, "parse status");
		ఒకవేళ (quiet)
			debug("remote statvfs: %s", fx2txt(స్థితి_2));
		లేకపోతే
			error("remote statvfs: %s", fx2txt(స్థితి_2));
		sshbuf_free(సందేశం);
		తిరిగి -1;
	} లేకపోతే ఒకవేళ (type != SSH2_FXP_EXTENDED_జవాబు) {
		fatal("Expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_జవాబు, type);
	}

	memset(st, 0, పరిమాణం(*st));
	ఒకవేళ ((r = sshbuf_get_u64(సందేశం, &st->f_bsize)) != 0 ||
	    (r = sshbuf_get_u64(సందేశం, &st->f_frsize)) != 0 ||
	    (r = sshbuf_get_u64(సందేశం, &st->f_ఖండాలు)) != 0 ||
	    (r = sshbuf_get_u64(సందేశం, &st->f_bfree)) != 0 ||
	    (r = sshbuf_get_u64(సందేశం, &st->f_bavail)) != 0 ||
	    (r = sshbuf_get_u64(సందేశం, &st->f_files)) != 0 ||
	    (r = sshbuf_get_u64(సందేశం, &st->f_ffree)) != 0 ||
	    (r = sshbuf_get_u64(సందేశం, &st->f_favail)) != 0 ||
	    (r = sshbuf_get_u64(సందేశం, &st->f_fsid)) != 0 ||
	    (r = sshbuf_get_u64(సందేశం, &flag)) != 0 ||
	    (r = sshbuf_get_u64(సందేశం, &st->f_namemax)) != 0)
		fatal_fr(r, "parse statvfs");

	st->f_flag = (flag & SSH2_FXE_STATVFS_ST_RDONLY) ? ST_RDONLY : 0;
	st->f_flag |= (flag & SSH2_FXE_STATVFS_ST_NOSUID) ? ST_NOSUID : 0;

	sshbuf_free(సందేశం);

	తిరిగి 0;
}

నిర్మాణం sftp_conn *
sftp_init(పూర్ణాంకం fd_లోపల, పూర్ణాంకం fd_బహిర్గతం, u_int transfer_buflen, u_int అంకె_అభ్యర్థనలు,
    uint64_t హద్దు_kbps)
{
	u_char type;
	నిర్మాణం sshbuf *సందేశం;
	నిర్మాణం sftp_conn *ret;
	పూర్ణాంకం r;

	ret = xcalloc(1, పరిమాణం(*ret));
	ret->సందేశం_id = 1;
	ret->fd_లోపల = fd_లోపల;
	ret->fd_బహిర్గతం = fd_బహిర్గతం;
	ret->download_buflen = ret->upload_buflen =
	    transfer_buflen ? transfer_buflen : DEFAULT_COPY_BUFLEN;
	ret->అంకె_అభ్యర్థనలు =
	    అంకె_అభ్యర్థనలు ? అంకె_అభ్యర్థనలు : DEFAULT_అంకె_అభ్యర్థనలు;
	ret->exts = 0;
	ret->హద్దు_kbps = 0;

	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = sshbuf_put_u8(సందేశం, SSH2_FXP_INIT)) != 0 ||
	    (r = sshbuf_put_u32(సందేశం, SSH2_FILEXFER_సంస్కరణ)) != 0)
		fatal_fr(r, "parse");

	send_సందేశం(ret, సందేశం);

	get_సందేశం_extended(ret, సందేశం, 1);

	/* Expecting a VERSION reply */
	ఒకవేళ ((r = sshbuf_get_u8(సందేశం, &type)) != 0)
		fatal_fr(r, "parse type");
	ఒకవేళ (type != SSH2_FXP_సంస్కరణ) {
		error("Invalid packet back from SSH2_FXP_INIT (type %u)",
		    type);
		sshbuf_free(సందేశం);
		విడుదల(ret);
		తిరిగి(ఖాళీ);
	}
	ఒకవేళ ((r = sshbuf_get_u32(సందేశం, &ret->సంస్కరణ)) != 0)
		fatal_fr(r, "parse version");

	debug2("Remote version: %u", ret->సంస్కరణ);

	/* Check for extensions */
	అయితే (sshbuf_len(సందేశం) > 0) {
		అక్షరం *name;
		u_char *విలువ;
		కొలత_t vlen;
		పూర్ణాంకం తెలిసిన = 0;

		ఒకవేళ ((r = sshbuf_get_cstring(సందేశం, &name, ఖాళీ)) != 0 ||
		    (r = sshbuf_get_string(సందేశం, &విలువ, &vlen)) != 0)
			fatal_fr(r, "parse extension");
		ఒకవేళ (strcmp(name, "posix-rename@openssh.com") == 0 &&
		    strcmp((అక్షరం *)విలువ, "1") == 0) {
			ret->exts |= SFTP_EXT_POSIX_RENAME;
			తెలిసిన = 1;
		} లేకపోతే ఒకవేళ (strcmp(name, "statvfs@openssh.com") == 0 &&
		    strcmp((అక్షరం *)విలువ, "2") == 0) {
			ret->exts |= SFTP_EXT_STATVFS;
			తెలిసిన = 1;
		} లేకపోతే ఒకవేళ (strcmp(name, "fstatvfs@openssh.com") == 0 &&
		    strcmp((అక్షరం *)విలువ, "2") == 0) {
			ret->exts |= SFTP_EXT_FSTATVFS;
			తెలిసిన = 1;
		} లేకపోతే ఒకవేళ (strcmp(name, "hardlink@openssh.com") == 0 &&
		    strcmp((అక్షరం *)విలువ, "1") == 0) {
			ret->exts |= SFTP_EXT_HARDLINK;
			తెలిసిన = 1;
		} లేకపోతే ఒకవేళ (strcmp(name, "fsync@openssh.com") == 0 &&
		    strcmp((అక్షరం *)విలువ, "1") == 0) {
			ret->exts |= SFTP_EXT_FSYNC;
			తెలిసిన = 1;
		} లేకపోతే ఒకవేళ (strcmp(name, "lsetstat@openssh.com") == 0 &&
		    strcmp((అక్షరం *)విలువ, "1") == 0) {
			ret->exts |= SFTP_EXT_LSETSTAT;
			తెలిసిన = 1;
		} లేకపోతే ఒకవేళ (strcmp(name, "limits@openssh.com") == 0 &&
		    strcmp((అక్షరం *)విలువ, "1") == 0) {
			ret->exts |= SFTP_EXT_LIMITS;
			తెలిసిన = 1;
		} లేకపోతే ఒకవేళ (strcmp(name, "expand-path@openssh.com") == 0 &&
		    strcmp((అక్షరం *)విలువ, "1") == 0) {
			ret->exts |= SFTP_EXT_మార్గం_EXPAND;
			తెలిసిన = 1;
		} లేకపోతే ఒకవేళ (strcmp(name, "copy-data") == 0 &&
		    strcmp((అక్షరం *)విలువ, "1") == 0) {
			ret->exts |= SFTP_EXT_COPY_దత్తాంశం;
			తెలిసిన = 1;
		} లేకపోతే ఒకవేళ (strcmp(name,
		    "users-groups-by-id@openssh.com") == 0 &&
		    strcmp((అక్షరం *)విలువ, "1") == 0) {
			ret->exts |= SFTP_EXT_GETUSERSGROUPS_BY_ID;
			తెలిసిన = 1;
		}
		ఒకవేళ (తెలిసిన) {
			debug2("Server supports extension \"%s\" revision %s",
			    name, విలువ);
		} లేకపోతే {
			debug2("Unrecognised server extension \"%s\"", name);
		}
		విడుదల(name);
		విడుదల(విలువ);
	}

	sshbuf_free(సందేశం);

	/* Query the server for its limits */
	ఒకవేళ (ret->exts & SFTP_EXT_LIMITS) {
		నిర్మాణం sftp_limits limits;
		ఒకవేళ (sftp_get_limits(ret, &limits) != 0)
			fatal_f("limits failed");

		/* If the caller did not specify, find a good value */
		ఒకవేళ (transfer_buflen == 0) {
			ret->download_buflen = MINIMUM(limits.read_నిడివి,
			    SFTP_MAX_సందేశం_నిడివి - 1024);
			ret->upload_buflen = MINIMUM(limits.write_నిడివి,
			    SFTP_MAX_సందేశం_నిడివి - 1024);
			ret->download_buflen = గరిష్ఠ(ret->download_buflen, 64);
			ret->upload_buflen = గరిష్ఠ(ret->upload_buflen, 64);
			debug3("server upload/download buffer sizes "
			    "%llu / %llu; using %u / %u",
			    (గుర్తులేని దీర్ఘ దీర్ఘ)limits.write_నిడివి,
			    (గుర్తులేని దీర్ఘ దీర్ఘ)limits.read_నిడివి,
			    ret->upload_buflen, ret->download_buflen);
		}
	}

	/* Some filexfer v.0 servers don't support large packets */
	ఒకవేళ (ret->సంస్కరణ == 0) {
		ret->download_buflen = MINIMUM(ret->download_buflen, 20480);
		ret->upload_buflen = MINIMUM(ret->upload_buflen, 20480);
	}

	ret->హద్దు_kbps = హద్దు_kbps;
	ఒకవేళ (ret->హద్దు_kbps > 0) {
		bandwidth_హద్దు_init(&ret->bwlimit_లోపల, ret->హద్దు_kbps,
		    ret->download_buflen);
		bandwidth_హద్దు_init(&ret->bwlimit_బహిర్గతం, ret->హద్దు_kbps,
		    ret->upload_buflen);
	}

	తిరిగి ret;
}

శూన్య
sftp_free(నిర్మాణం sftp_conn *conn)
{
	ఒకవేళ (conn == ఖాళీ)
		తిరిగి;
	freezero(conn, పరిమాణం(*conn));
}

u_int
sftp_proto_సంస్కరణ(నిర్మాణం sftp_conn *conn)
{
	తిరిగి conn->సంస్కరణ;
}

పూర్ణాంకం
sftp_get_limits(నిర్మాణం sftp_conn *conn, నిర్మాణం sftp_limits *limits)
{
	u_int id, సందేశం_id;
	u_char type;
	నిర్మాణం sshbuf *సందేశం;
	పూర్ణాంకం r;

	ఒకవేళ ((conn->exts & SFTP_EXT_LIMITS) == 0) {
		error("Server does not support limits@openssh.com extension");
		తిరిగి -1;
	}

	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");

	id = conn->సందేశం_id++;
	ఒకవేళ ((r = sshbuf_put_u8(సందేశం, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(సందేశం, id)) != 0 ||
	    (r = sshbuf_put_cstring(సందేశం, "limits@openssh.com")) != 0)
		fatal_fr(r, "compose");
	send_సందేశం(conn, సందేశం);
	debug3("Sent message limits@openssh.com I:%u", id);

	get_సందేశం(conn, సందేశం);

	ఒకవేళ ((r = sshbuf_get_u8(సందేశం, &type)) != 0 ||
	    (r = sshbuf_get_u32(సందేశం, &సందేశం_id)) != 0)
		fatal_fr(r, "parse");

	debug3("Received limits reply T:%u I:%u", type, సందేశం_id);
	ఒకవేళ (id != సందేశం_id)
		fatal("ID mismatch (%u != %u)", సందేశం_id, id);
	ఒకవేళ (type != SSH2_FXP_EXTENDED_జవాబు) {
		debug_f("expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_జవాబు, type);
		/* Disable the limits extension */
		conn->exts &= ~SFTP_EXT_LIMITS;
		sshbuf_free(సందేశం);
		తిరిగి -1;
	}

	memset(limits, 0, పరిమాణం(*limits));
	ఒకవేళ ((r = sshbuf_get_u64(సందేశం, &limits->packet_నిడివి)) != 0 ||
	    (r = sshbuf_get_u64(సందేశం, &limits->read_నిడివి)) != 0 ||
	    (r = sshbuf_get_u64(సందేశం, &limits->write_నిడివి)) != 0 ||
	    (r = sshbuf_get_u64(సందేశం, &limits->open_handles)) != 0)
		fatal_fr(r, "parse limits");

	sshbuf_free(సందేశం);

	తిరిగి 0;
}

పూర్ణాంకం
sftp_close(నిర్మాణం sftp_conn *conn, స్థిరరాశి u_char *handle, u_int handle_len)
{
	u_int id, స్థితి_2;
	నిర్మాణం sshbuf *సందేశం;
	పూర్ణాంకం r;

	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");

	id = conn->సందేశం_id++;
	ఒకవేళ ((r = sshbuf_put_u8(సందేశం, SSH2_FXP_CLOSE)) != 0 ||
	    (r = sshbuf_put_u32(సందేశం, id)) != 0 ||
	    (r = sshbuf_put_string(సందేశం, handle, handle_len)) != 0)
		fatal_fr(r, "parse");
	send_సందేశం(conn, సందేశం);
	debug3("Sent message SSH2_FXP_CLOSE I:%u", id);

	స్థితి_2 = get_స్థితి(conn, id);
	ఒకవేళ (స్థితి_2 != SSH2_FX_OK)
		error("close remote: %s", fx2txt(స్థితి_2));

	sshbuf_free(సందేశం);

	తిరిగి స్థితి_2 == SSH2_FX_OK ? 0 : -1;
}


స్థిర పూర్ణాంకం
sftp_lsreaddir(నిర్మాణం sftp_conn *conn, స్థిరరాశి అక్షరం *మార్గం, పూర్ణాంకం print_flag,
    SFTP_DIRENT ***dir)
{
	నిర్మాణం sshbuf *సందేశం;
	u_int లెక్క, id, i, expected_id, ents = 0;
	కొలత_t handle_len;
	u_char type, *handle;
	పూర్ణాంకం స్థితి_2 = SSH2_FX_FAILURE;
	పూర్ణాంకం r;

	ఒకవేళ (dir)
		*dir = ఖాళీ;

	id = conn->సందేశం_id++;

	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = sshbuf_put_u8(సందేశం, SSH2_FXP_OPENDIR)) != 0 ||
	    (r = sshbuf_put_u32(సందేశం, id)) != 0 ||
	    (r = sshbuf_put_cstring(సందేశం, మార్గం)) != 0)
		fatal_fr(r, "compose OPENDIR");
	send_సందేశం(conn, సందేశం);

	handle = get_handle(conn, id, &handle_len,
	    "remote readdir(\"%s\")", మార్గం);
	ఒకవేళ (handle == ఖాళీ) {
		sshbuf_free(సందేశం);
		తిరిగి -1;
	}

	ఒకవేళ (dir) {
		ents = 0;
		*dir = xcalloc(1, పరిమాణం(**dir));
		(*dir)[0] = ఖాళీ;
	}

	కొరకు (; !interrupted;) {
		id = expected_id = conn->సందేశం_id++;

		debug3("Sending SSH2_FXP_READDIR I:%u", id);

		sshbuf_reset(సందేశం);
		ఒకవేళ ((r = sshbuf_put_u8(సందేశం, SSH2_FXP_READDIR)) != 0 ||
		    (r = sshbuf_put_u32(సందేశం, id)) != 0 ||
		    (r = sshbuf_put_string(సందేశం, handle, handle_len)) != 0)
			fatal_fr(r, "compose READDIR");
		send_సందేశం(conn, సందేశం);

		sshbuf_reset(సందేశం);

		get_సందేశం(conn, సందేశం);

		ఒకవేళ ((r = sshbuf_get_u8(సందేశం, &type)) != 0 ||
		    (r = sshbuf_get_u32(సందేశం, &id)) != 0)
			fatal_fr(r, "parse");

		debug3("Received reply T:%u I:%u", type, id);

		ఒకవేళ (id != expected_id)
			fatal("ID mismatch (%u != %u)", id, expected_id);

		ఒకవేళ (type == SSH2_FXP_స్థితి) {
			u_int rstatus;

			ఒకవేళ ((r = sshbuf_get_u32(సందేశం, &rstatus)) != 0)
				fatal_fr(r, "parse status");
			debug3("Received SSH2_FXP_STATUS %d", rstatus);
			ఒకవేళ (rstatus == SSH2_FX_EOF)
				ఆపు;
			error("Couldn't read directory: %s", fx2txt(rstatus));
			వెళ్ళు బహిర్గతం;
		} లేకపోతే ఒకవేళ (type != SSH2_FXP_NAME)
			fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
			    SSH2_FXP_NAME, type);

		ఒకవేళ ((r = sshbuf_get_u32(సందేశం, &లెక్క)) != 0)
			fatal_fr(r, "parse count");
		ఒకవేళ (లెక్క > SSHBUF_కొలత_MAX)
			fatal_f("nonsensical number of entries");
		ఒకవేళ (లెక్క == 0)
			ఆపు;
		debug3("Received %d SSH2_FXP_NAME responses", లెక్క);
		కొరకు (i = 0; i < లెక్క; i++) {
			అక్షరం *filename, *longname;
			Attrib a;

			ఒకవేళ ((r = sshbuf_get_cstring(సందేశం, &filename,
			    ఖాళీ)) != 0 ||
			    (r = sshbuf_get_cstring(సందేశం, &longname,
			    ఖాళీ)) != 0)
				fatal_fr(r, "parse filenames");
			ఒకవేళ ((r = decode_attrib(సందేశం, &a)) != 0) {
				error_fr(r, "couldn't decode attrib");
				విడుదల(filename);
				విడుదల(longname);
				వెళ్ళు బహిర్గతం;
			}

			ఒకవేళ (print_flag)
				mprintf("%s\n", longname);

			/*
			 * Directory entries should never contain '/'
			 * These can be used to attack recursive ops
			 * (e.g. send '../../../../etc/passwd')
			 */
			ఒకవేళ (*filename == '\0' ||
			    strpbrk(filename, SFTP_DIRECTORY_CHARS) != ఖాళీ) {
				error("Server sent suspect path \"%s\" "
				    "during readdir of \"%s\"", filename, మార్గం);
			} లేకపోతే ఒకవేళ (dir) {
				*dir = xreallocarray(*dir, ents + 2, పరిమాణం(**dir));
				(*dir)[ents] = xcalloc(1, పరిమాణం(***dir));
				(*dir)[ents]->filename = xstrdup(filename);
				(*dir)[ents]->longname = xstrdup(longname);
				జ్ఞాపకం_నకలు(&(*dir)[ents]->a, &a, పరిమాణం(a));
				(*dir)[++ents] = ఖాళీ;
			}
			విడుదల(filename);
			విడుదల(longname);
		}
	}
	స్థితి_2 = 0;

 బహిర్గతం:
	sshbuf_free(సందేశం);
	sftp_close(conn, handle, handle_len);
	విడుదల(handle);

	ఒకవేళ (స్థితి_2 != 0 && dir != ఖాళీ) {
		/* Don't return results on error */
		sftp_free_dirents(*dir);
		*dir = ఖాళీ;
	} లేకపోతే ఒకవేళ (interrupted && dir != ఖాళీ && *dir != ఖాళీ) {
		/* Don't return partial matches on interrupt */
		sftp_free_dirents(*dir);
		*dir = xcalloc(1, పరిమాణం(**dir));
		**dir = ఖాళీ;
	}

	తిరిగి స్థితి_2 == SSH2_FX_OK ? 0 : -1;
}

పూర్ణాంకం
sftp_readdir(నిర్మాణం sftp_conn *conn, స్థిరరాశి అక్షరం *మార్గం, SFTP_DIRENT ***dir)
{
	తిరిగి sftp_lsreaddir(conn, మార్గం, 0, dir);
}

శూన్య sftp_free_dirents(SFTP_DIRENT **s)
{
	పూర్ణాంకం i;

	ఒకవేళ (s == ఖాళీ)
		తిరిగి;
	కొరకు (i = 0; s[i]; i++) {
		విడుదల(s[i]->filename);
		విడుదల(s[i]->longname);
		విడుదల(s[i]);
	}
	విడుదల(s);
}

పూర్ణాంకం
sftp_rm(నిర్మాణం sftp_conn *conn, స్థిరరాశి అక్షరం *మార్గం)
{
	u_int స్థితి_2, id;

	debug2("Sending SSH2_FXP_REMOVE \"%s\"", మార్గం);

	id = conn->సందేశం_id++;
	send_string_request(conn, id, SSH2_FXP_REMOVE, మార్గం, అక్షరశ్రేణి_పొడవు(మార్గం));
	స్థితి_2 = get_స్థితి(conn, id);
	ఒకవేళ (స్థితి_2 != SSH2_FX_OK)
		error("remote delete %s: %s", మార్గం, fx2txt(స్థితి_2));
	తిరిగి స్థితి_2 == SSH2_FX_OK ? 0 : -1;
}

పూర్ణాంకం
sftp_mkdir(నిర్మాణం sftp_conn *conn, స్థిరరాశి అక్షరం *మార్గం, Attrib *a, పూర్ణాంకం print_flag)
{
	u_int స్థితి_2, id;

	debug2("Sending SSH2_FXP_MKDIR \"%s\"", మార్గం);

	id = conn->సందేశం_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_MKDIR, మార్గం,
	    అక్షరశ్రేణి_పొడవు(మార్గం), a);

	స్థితి_2 = get_స్థితి(conn, id);
	ఒకవేళ (స్థితి_2 != SSH2_FX_OK && print_flag)
		error("remote mkdir \"%s\": %s", మార్గం, fx2txt(స్థితి_2));

	తిరిగి స్థితి_2 == SSH2_FX_OK ? 0 : -1;
}

పూర్ణాంకం
sftp_mkpath(నిర్మాణం sftp_conn *conn, స్థిరరాశి అక్షరం *మార్గం, Attrib *a, పూర్ణాంకం print_flag)
{
	అక్షరం *slash, *tmp_మార్గం;
	పూర్ణాంకం పూర్తి;

	tmp_మార్గం = xstrdup(మార్గం);
	slash = tmp_మార్గం;

	కొరకు (;;) {
		slash += strspn(slash, "/");
		slash += strcspn(slash, "/");

		పూర్తి = (*slash == '\0');
		*slash = '\0';

		ఒకవేళ (!sftp_remote_is_dir(conn, tmp_మార్గం)) {
			ఒకవేళ (sftp_mkdir(conn, tmp_మార్గం, a, print_flag) != 0) {
				విడుదల(tmp_మార్గం);
				తిరిగి -1;
			}
		}

		ఒకవేళ (పూర్తి)
			ఆపు;

		*slash = '/';
	}

	విడుదల(tmp_మార్గం);
	తిరిగి 0;
}

పూర్ణాంకం
sftp_rmdir(నిర్మాణం sftp_conn *conn, స్థిరరాశి అక్షరం *మార్గం)
{
	u_int స్థితి_2, id;

	debug2("Sending SSH2_FXP_RMDIR \"%s\"", మార్గం);

	id = conn->సందేశం_id++;
	send_string_request(conn, id, SSH2_FXP_RMDIR, మార్గం,
	    అక్షరశ్రేణి_పొడవు(మార్గం));

	స్థితి_2 = get_స్థితి(conn, id);
	ఒకవేళ (స్థితి_2 != SSH2_FX_OK)
		error("remote rmdir \"%s\": %s", మార్గం, fx2txt(స్థితి_2));

	తిరిగి స్థితి_2 == SSH2_FX_OK ? 0 : -1;
}

పూర్ణాంకం
sftp_stat(నిర్మాణం sftp_conn *conn, స్థిరరాశి అక్షరం *మార్గం, పూర్ణాంకం quiet, Attrib *a)
{
	u_int id;

	debug2("Sending SSH2_FXP_STAT \"%s\"", మార్గం);

	id = conn->సందేశం_id++;

	send_string_request(conn, id,
	    conn->సంస్కరణ == 0 ? SSH2_FXP_STAT_సంస్కరణ_0 : SSH2_FXP_STAT,
	    మార్గం, అక్షరశ్రేణి_పొడవు(మార్గం));

	తిరిగి get_decode_stat(conn, id, quiet, a);
}

పూర్ణాంకం
sftp_lstat(నిర్మాణం sftp_conn *conn, స్థిరరాశి అక్షరం *మార్గం, పూర్ణాంకం quiet, Attrib *a)
{
	u_int id;

	ఒకవేళ (conn->సంస్కరణ == 0) {
		do_log2(quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_INFO,
		    "Server version does not support lstat operation");
		తిరిగి sftp_stat(conn, మార్గం, quiet, a);
	}

	id = conn->సందేశం_id++;
	send_string_request(conn, id, SSH2_FXP_LSTAT, మార్గం,
	    అక్షరశ్రేణి_పొడవు(మార్గం));

	తిరిగి get_decode_stat(conn, id, quiet, a);
}

#నిర్వచితమైతే notyet
పూర్ణాంకం
sftp_fstat(నిర్మాణం sftp_conn *conn, స్థిరరాశి u_char *handle, u_int handle_len,
    పూర్ణాంకం quiet, Attrib *a)
{
	u_int id;

	debug2("Sending SSH2_FXP_FSTAT \"%s\"");

	id = conn->సందేశం_id++;
	send_string_request(conn, id, SSH2_FXP_FSTAT, handle,
	    handle_len);

	తిరిగి get_decode_stat(conn, id, quiet, a);
}
#అయితే_ముగింపు

పూర్ణాంకం
sftp_setstat(నిర్మాణం sftp_conn *conn, స్థిరరాశి అక్షరం *మార్గం, Attrib *a)
{
	u_int స్థితి_2, id;

	debug2("Sending SSH2_FXP_SETSTAT \"%s\"", మార్గం);

	id = conn->సందేశం_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_SETSTAT, మార్గం,
	    అక్షరశ్రేణి_పొడవు(మార్గం), a);

	స్థితి_2 = get_స్థితి(conn, id);
	ఒకవేళ (స్థితి_2 != SSH2_FX_OK)
		error("remote setstat \"%s\": %s", మార్గం, fx2txt(స్థితి_2));

	తిరిగి స్థితి_2 == SSH2_FX_OK ? 0 : -1;
}

పూర్ణాంకం
sftp_fsetstat(నిర్మాణం sftp_conn *conn, స్థిరరాశి u_char *handle, u_int handle_len,
    Attrib *a)
{
	u_int స్థితి_2, id;

	debug2("Sending SSH2_FXP_FSETSTAT");

	id = conn->సందేశం_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_FSETSTAT, handle,
	    handle_len, a);

	స్థితి_2 = get_స్థితి(conn, id);
	ఒకవేళ (స్థితి_2 != SSH2_FX_OK)
		error("remote fsetstat: %s", fx2txt(స్థితి_2));

	తిరిగి స్థితి_2 == SSH2_FX_OK ? 0 : -1;
}

/* Implements both the realpath and expand-path operations */
స్థిర అక్షరం *
sftp_realpath_expand(నిర్మాణం sftp_conn *conn, స్థిరరాశి అక్షరం *మార్గం, పూర్ణాంకం expand)
{
	నిర్మాణం sshbuf *సందేశం;
	u_int expected_id, లెక్క, id;
	అక్షరం *filename, *longname;
	Attrib a;
	u_char type;
	పూర్ణాంకం r;
	స్థిరరాశి అక్షరం *what = "SSH2_FXP_REALPATH";

	ఒకవేళ (expand)
		what = "expand-path@openssh.com";
	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");

	expected_id = id = conn->సందేశం_id++;
	ఒకవేళ (expand) {
		debug2("Sending SSH2_FXP_EXTENDED(expand-path@openssh.com) "
		    "\"%s\"", మార్గం);
		ఒకవేళ ((r = sshbuf_put_u8(సందేశం, SSH2_FXP_EXTENDED)) != 0 ||
		    (r = sshbuf_put_u32(సందేశం, id)) != 0 ||
		    (r = sshbuf_put_cstring(సందేశం,
		    "expand-path@openssh.com")) != 0 ||
		    (r = sshbuf_put_cstring(సందేశం, మార్గం)) != 0)
			fatal_fr(r, "compose %s", what);
		send_సందేశం(conn, సందేశం);
	} లేకపోతే {
		debug2("Sending SSH2_FXP_REALPATH \"%s\"", మార్గం);
		send_string_request(conn, id, SSH2_FXP_REALPATH,
		    మార్గం, అక్షరశ్రేణి_పొడవు(మార్గం));
	}
	get_సందేశం(conn, సందేశం);
	ఒకవేళ ((r = sshbuf_get_u8(సందేశం, &type)) != 0 ||
	    (r = sshbuf_get_u32(సందేశం, &id)) != 0)
		fatal_fr(r, "parse");

	ఒకవేళ (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);

	ఒకవేళ (type == SSH2_FXP_స్థితి) {
		u_int స్థితి_2;
		అక్షరం *errmsg;

		ఒకవేళ ((r = sshbuf_get_u32(సందేశం, &స్థితి_2)) != 0 ||
		    (r = sshbuf_get_cstring(సందేశం, &errmsg, ఖాళీ)) != 0)
			fatal_fr(r, "parse status");
		error("%s %s: %s", expand ? "expand" : "realpath",
		    మార్గం, *errmsg == '\0' ? fx2txt(స్థితి_2) : errmsg);
		విడుదల(errmsg);
		sshbuf_free(సందేశం);
		తిరిగి ఖాళీ;
	} లేకపోతే ఒకవేళ (type != SSH2_FXP_NAME)
		fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
		    SSH2_FXP_NAME, type);

	ఒకవేళ ((r = sshbuf_get_u32(సందేశం, &లెక్క)) != 0)
		fatal_fr(r, "parse count");
	ఒకవేళ (లెక్క != 1)
		fatal("Got multiple names (%d) from %s", లెక్క, what);

	ఒకవేళ ((r = sshbuf_get_cstring(సందేశం, &filename, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_cstring(సందేశం, &longname, ఖాళీ)) != 0 ||
	    (r = decode_attrib(సందేశం, &a)) != 0)
		fatal_fr(r, "parse filename/attrib");

	debug3("%s %s -> %s", what, మార్గం, filename);

	విడుదల(longname);

	sshbuf_free(సందేశం);

	తిరిగి(filename);
}

అక్షరం *
sftp_realpath(నిర్మాణం sftp_conn *conn, స్థిరరాశి అక్షరం *మార్గం)
{
	తిరిగి sftp_realpath_expand(conn, మార్గం, 0);
}

పూర్ణాంకం
sftp_can_expand_మార్గం(నిర్మాణం sftp_conn *conn)
{
	తిరిగి (conn->exts & SFTP_EXT_మార్గం_EXPAND) != 0;
}

అక్షరం *
sftp_expand_మార్గం(నిర్మాణం sftp_conn *conn, స్థిరరాశి అక్షరం *మార్గం)
{
	ఒకవేళ (!sftp_can_expand_మార్గం(conn)) {
		debug3_f("no server support, fallback to realpath");
		తిరిగి sftp_realpath_expand(conn, మార్గం, 0);
	}
	తిరిగి sftp_realpath_expand(conn, మార్గం, 1);
}

పూర్ణాంకం
sftp_copy(నిర్మాణం sftp_conn *conn, స్థిరరాశి అక్షరం *oldpath, స్థిరరాశి అక్షరం *newpath)
{
	Attrib junk, attr;
	నిర్మాణం sshbuf *సందేశం;
	u_char *old_handle, *new_handle;
	u_int బహుళకం, స్థితి_2, id;
	కొలత_t old_handle_len, new_handle_len;
	పూర్ణాంకం r;

	/* Return if the extension is not supported */
	ఒకవేళ ((conn->exts & SFTP_EXT_COPY_దత్తాంశం) == 0) {
		error("Server does not support copy-data extension");
		తిరిగి -1;
	}

	/* Make sure the file exists, and we can copy its perms */
	ఒకవేళ (sftp_stat(conn, oldpath, 0, &attr) != 0)
		తిరిగి -1;

	/* Do not preserve set[ug]id here, as we do not preserve ownership */
	ఒకవేళ (attr.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		బహుళకం = attr.perm & 0777;

		ఒకవేళ (!S_ISREG(attr.perm)) {
			error("Cannot copy non-regular file: %s", oldpath);
			తిరిగి -1;
		}
	} లేకపోతే {
		/* NB: The user's umask will apply to this */
		బహుళకం = 0666;
	}

	/* Set up the new perms for the new file */
	attrib_clear(&attr);
	attr.perm = బహుళకం;
	attr.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;

	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");

	attrib_clear(&junk); /* Send empty attributes */

	/* Open the old file for reading */
	id = conn->సందేశం_id++;
	ఒకవేళ ((r = sshbuf_put_u8(సందేశం, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(సందేశం, id)) != 0 ||
	    (r = sshbuf_put_cstring(సందేశం, oldpath)) != 0 ||
	    (r = sshbuf_put_u32(సందేశం, SSH2_FXF_READ)) != 0 ||
	    (r = encode_attrib(సందేశం, &junk)) != 0)
		fatal_fr(r, "buffer error");
	send_సందేశం(conn, సందేశం);
	debug3("Sent message SSH2_FXP_OPEN I:%u P:%s", id, oldpath);

	sshbuf_reset(సందేశం);

	old_handle = get_handle(conn, id, &old_handle_len,
	    "remote open(\"%s\")", oldpath);
	ఒకవేళ (old_handle == ఖాళీ) {
		sshbuf_free(సందేశం);
		తిరిగి -1;
	}

	/* Open the new file for writing */
	id = conn->సందేశం_id++;
	ఒకవేళ ((r = sshbuf_put_u8(సందేశం, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(సందేశం, id)) != 0 ||
	    (r = sshbuf_put_cstring(సందేశం, newpath)) != 0 ||
	    (r = sshbuf_put_u32(సందేశం, SSH2_FXF_WRITE|SSH2_FXF_CREAT|
	    SSH2_FXF_TRUNC)) != 0 ||
	    (r = encode_attrib(సందేశం, &attr)) != 0)
		fatal_fr(r, "buffer error");
	send_సందేశం(conn, సందేశం);
	debug3("Sent message SSH2_FXP_OPEN I:%u P:%s", id, newpath);

	sshbuf_reset(సందేశం);

	new_handle = get_handle(conn, id, &new_handle_len,
	    "remote open(\"%s\")", newpath);
	ఒకవేళ (new_handle == ఖాళీ) {
		sshbuf_free(సందేశం);
		విడుదల(old_handle);
		తిరిగి -1;
	}

	/* Copy the file data */
	id = conn->సందేశం_id++;
	ఒకవేళ ((r = sshbuf_put_u8(సందేశం, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(సందేశం, id)) != 0 ||
	    (r = sshbuf_put_cstring(సందేశం, "copy-data")) != 0 ||
	    (r = sshbuf_put_string(సందేశం, old_handle, old_handle_len)) != 0 ||
	    (r = sshbuf_put_u64(సందేశం, 0)) != 0 ||
	    (r = sshbuf_put_u64(సందేశం, 0)) != 0 ||
	    (r = sshbuf_put_string(సందేశం, new_handle, new_handle_len)) != 0 ||
	    (r = sshbuf_put_u64(సందేశం, 0)) != 0)
		fatal_fr(r, "buffer error");
	send_సందేశం(conn, సందేశం);
	debug3("Sent message copy-data \"%s\" 0 0 -> \"%s\" 0",
	       oldpath, newpath);

	స్థితి_2 = get_స్థితి(conn, id);
	ఒకవేళ (స్థితి_2 != SSH2_FX_OK)
		error("Couldn't copy file \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(స్థితి_2));

	/* Clean up everything */
	sshbuf_free(సందేశం);
	sftp_close(conn, old_handle, old_handle_len);
	sftp_close(conn, new_handle, new_handle_len);
	విడుదల(old_handle);
	విడుదల(new_handle);

	తిరిగి స్థితి_2 == SSH2_FX_OK ? 0 : -1;
}

పూర్ణాంకం
sftp_rename(నిర్మాణం sftp_conn *conn, స్థిరరాశి అక్షరం *oldpath, స్థిరరాశి అక్షరం *newpath,
    పూర్ణాంకం force_legacy)
{
	నిర్మాణం sshbuf *సందేశం;
	u_int స్థితి_2, id;
	పూర్ణాంకం r, use_ext = (conn->exts & SFTP_EXT_POSIX_RENAME) && !force_legacy;

	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");

	/* Send rename request */
	id = conn->సందేశం_id++;
	ఒకవేళ (use_ext) {
		debug2("Sending SSH2_FXP_EXTENDED(posix-rename@openssh.com) "
		    "\"%s\" to \"%s\"", oldpath, newpath);
		ఒకవేళ ((r = sshbuf_put_u8(సందేశం, SSH2_FXP_EXTENDED)) != 0 ||
		    (r = sshbuf_put_u32(సందేశం, id)) != 0 ||
		    (r = sshbuf_put_cstring(సందేశం,
		    "posix-rename@openssh.com")) != 0)
			fatal_fr(r, "compose posix-rename");
	} లేకపోతే {
		debug2("Sending SSH2_FXP_RENAME \"%s\" to \"%s\"",
		    oldpath, newpath);
		ఒకవేళ ((r = sshbuf_put_u8(సందేశం, SSH2_FXP_RENAME)) != 0 ||
		    (r = sshbuf_put_u32(సందేశం, id)) != 0)
			fatal_fr(r, "compose rename");
	}
	ఒకవేళ ((r = sshbuf_put_cstring(సందేశం, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(సందేశం, newpath)) != 0)
		fatal_fr(r, "compose paths");
	send_సందేశం(conn, సందేశం);
	debug3("Sent message %s \"%s\" -> \"%s\"",
	    use_ext ? "posix-rename@openssh.com" :
	    "SSH2_FXP_RENAME", oldpath, newpath);
	sshbuf_free(సందేశం);

	స్థితి_2 = get_స్థితి(conn, id);
	ఒకవేళ (స్థితి_2 != SSH2_FX_OK)
		error("remote rename \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(స్థితి_2));

	తిరిగి స్థితి_2 == SSH2_FX_OK ? 0 : -1;
}

పూర్ణాంకం
sftp_hardlink(నిర్మాణం sftp_conn *conn, స్థిరరాశి అక్షరం *oldpath, స్థిరరాశి అక్షరం *newpath)
{
	నిర్మాణం sshbuf *సందేశం;
	u_int స్థితి_2, id;
	పూర్ణాంకం r;

	ఒకవేళ ((conn->exts & SFTP_EXT_HARDLINK) == 0) {
		error("Server does not support hardlink@openssh.com extension");
		తిరిగి -1;
	}
	debug2("Sending SSH2_FXP_EXTENDED(hardlink@openssh.com) "
	    "\"%s\" to \"%s\"", oldpath, newpath);

	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");

	/* Send link request */
	id = conn->సందేశం_id++;
	ఒకవేళ ((r = sshbuf_put_u8(సందేశం, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(సందేశం, id)) != 0 ||
	    (r = sshbuf_put_cstring(సందేశం, "hardlink@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(సందేశం, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(సందేశం, newpath)) != 0)
		fatal_fr(r, "compose");
	send_సందేశం(conn, సందేశం);
	debug3("Sent message hardlink@openssh.com \"%s\" -> \"%s\"",
	    oldpath, newpath);
	sshbuf_free(సందేశం);

	స్థితి_2 = get_స్థితి(conn, id);
	ఒకవేళ (స్థితి_2 != SSH2_FX_OK)
		error("remote link \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(స్థితి_2));

	తిరిగి స్థితి_2 == SSH2_FX_OK ? 0 : -1;
}

పూర్ణాంకం
sftp_symlink(నిర్మాణం sftp_conn *conn, స్థిరరాశి అక్షరం *oldpath, స్థిరరాశి అక్షరం *newpath)
{
	నిర్మాణం sshbuf *సందేశం;
	u_int స్థితి_2, id;
	పూర్ణాంకం r;

	ఒకవేళ (conn->సంస్కరణ < 3) {
		error("This server does not support the symlink operation");
		తిరిగి(SSH2_FX_OP_UNSUPPORTED);
	}
	debug2("Sending SSH2_FXP_SYMLINK \"%s\" to \"%s\"", oldpath, newpath);

	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");

	/* Send symlink request */
	id = conn->సందేశం_id++;
	ఒకవేళ ((r = sshbuf_put_u8(సందేశం, SSH2_FXP_SYMLINK)) != 0 ||
	    (r = sshbuf_put_u32(సందేశం, id)) != 0 ||
	    (r = sshbuf_put_cstring(సందేశం, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(సందేశం, newpath)) != 0)
		fatal_fr(r, "compose");
	send_సందేశం(conn, సందేశం);
	debug3("Sent message SSH2_FXP_SYMLINK \"%s\" -> \"%s\"", oldpath,
	    newpath);
	sshbuf_free(సందేశం);

	స్థితి_2 = get_స్థితి(conn, id);
	ఒకవేళ (స్థితి_2 != SSH2_FX_OK)
		error("remote symlink file \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(స్థితి_2));

	తిరిగి స్థితి_2 == SSH2_FX_OK ? 0 : -1;
}

పూర్ణాంకం
sftp_fsync(నిర్మాణం sftp_conn *conn, u_char *handle, u_int handle_len)
{
	నిర్మాణం sshbuf *సందేశం;
	u_int స్థితి_2, id;
	పూర్ణాంకం r;

	/* Silently return if the extension is not supported */
	ఒకవేళ ((conn->exts & SFTP_EXT_FSYNC) == 0)
		తిరిగి -1;
	debug2("Sending SSH2_FXP_EXTENDED(fsync@openssh.com)");

	/* Send fsync request */
	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	id = conn->సందేశం_id++;
	ఒకవేళ ((r = sshbuf_put_u8(సందేశం, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(సందేశం, id)) != 0 ||
	    (r = sshbuf_put_cstring(సందేశం, "fsync@openssh.com")) != 0 ||
	    (r = sshbuf_put_string(సందేశం, handle, handle_len)) != 0)
		fatal_fr(r, "compose");
	send_సందేశం(conn, సందేశం);
	debug3("Sent message fsync@openssh.com I:%u", id);
	sshbuf_free(సందేశం);

	స్థితి_2 = get_స్థితి(conn, id);
	ఒకవేళ (స్థితి_2 != SSH2_FX_OK)
		error("remote fsync: %s", fx2txt(స్థితి_2));

	తిరిగి స్థితి_2 == SSH2_FX_OK ? 0 : -1;
}

#నిర్వచితమైతే notyet
అక్షరం *
sftp_readlink(నిర్మాణం sftp_conn *conn, స్థిరరాశి అక్షరం *మార్గం)
{
	నిర్మాణం sshbuf *సందేశం;
	u_int expected_id, లెక్క, id;
	అక్షరం *filename, *longname;
	Attrib a;
	u_char type;
	పూర్ణాంకం r;

	debug2("Sending SSH2_FXP_READLINK \"%s\"", మార్గం);

	expected_id = id = conn->సందేశం_id++;
	send_string_request(conn, id, SSH2_FXP_READLINK, మార్గం, అక్షరశ్రేణి_పొడవు(మార్గం));

	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");

	get_సందేశం(conn, సందేశం);
	ఒకవేళ ((r = sshbuf_get_u8(సందేశం, &type)) != 0 ||
	    (r = sshbuf_get_u32(సందేశం, &id)) != 0)
		fatal_fr(r, "parse");

	ఒకవేళ (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);

	ఒకవేళ (type == SSH2_FXP_స్థితి) {
		u_int స్థితి_2;

		ఒకవేళ ((r = sshbuf_get_u32(సందేశం, &స్థితి_2)) != 0)
			fatal_fr(r, "parse status");
		error("Couldn't readlink: %s", fx2txt(స్థితి_2));
		sshbuf_free(సందేశం);
		తిరిగి(ఖాళీ);
	} లేకపోతే ఒకవేళ (type != SSH2_FXP_NAME)
		fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
		    SSH2_FXP_NAME, type);

	ఒకవేళ ((r = sshbuf_get_u32(సందేశం, &లెక్క)) != 0)
		fatal_fr(r, "parse count");
	ఒకవేళ (లెక్క != 1)
		fatal("Got multiple names (%d) from SSH_FXP_READLINK", లెక్క);

	ఒకవేళ ((r = sshbuf_get_cstring(సందేశం, &filename, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_cstring(సందేశం, &longname, ఖాళీ)) != 0 ||
	    (r = decode_attrib(సందేశం, &a)) != 0)
		fatal_fr(r, "parse filenames/attrib");

	debug3("SSH_FXP_READLINK %s -> %s", మార్గం, filename);

	విడుదల(longname);

	sshbuf_free(సందేశం);

	తిరిగి filename;
}
#అయితే_ముగింపు

పూర్ణాంకం
sftp_statvfs(నిర్మాణం sftp_conn *conn, స్థిరరాశి అక్షరం *మార్గం, నిర్మాణం sftp_statvfs *st,
    పూర్ణాంకం quiet)
{
	నిర్మాణం sshbuf *సందేశం;
	u_int id;
	పూర్ణాంకం r;

	ఒకవేళ ((conn->exts & SFTP_EXT_STATVFS) == 0) {
		error("Server does not support statvfs@openssh.com extension");
		తిరిగి -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(statvfs@openssh.com) \"%s\"", మార్గం);

	id = conn->సందేశం_id++;

	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = sshbuf_put_u8(సందేశం, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(సందేశం, id)) != 0 ||
	    (r = sshbuf_put_cstring(సందేశం, "statvfs@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(సందేశం, మార్గం)) != 0)
		fatal_fr(r, "compose");
	send_సందేశం(conn, సందేశం);
	sshbuf_free(సందేశం);

	తిరిగి get_decode_statvfs(conn, st, id, quiet);
}

#నిర్వచితమైతే notyet
పూర్ణాంకం
sftp_fstatvfs(నిర్మాణం sftp_conn *conn, స్థిరరాశి u_char *handle, u_int handle_len,
    నిర్మాణం sftp_statvfs *st, పూర్ణాంకం quiet)
{
	నిర్మాణం sshbuf *సందేశం;
	u_int id;

	ఒకవేళ ((conn->exts & SFTP_EXT_FSTATVFS) == 0) {
		error("Server does not support fstatvfs@openssh.com extension");
		తిరిగి -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(fstatvfs@openssh.com)");

	id = conn->సందేశం_id++;

	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = sshbuf_put_u8(సందేశం, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(సందేశం, id)) != 0 ||
	    (r = sshbuf_put_cstring(సందేశం, "fstatvfs@openssh.com")) != 0 ||
	    (r = sshbuf_put_string(సందేశం, handle, handle_len)) != 0)
		fatal_fr(r, "compose");
	send_సందేశం(conn, సందేశం);
	sshbuf_free(సందేశం);

	తిరిగి get_decode_statvfs(conn, st, id, quiet);
}
#అయితే_ముగింపు

పూర్ణాంకం
sftp_lsetstat(నిర్మాణం sftp_conn *conn, స్థిరరాశి అక్షరం *మార్గం, Attrib *a)
{
	నిర్మాణం sshbuf *సందేశం;
	u_int స్థితి_2, id;
	పూర్ణాంకం r;

	ఒకవేళ ((conn->exts & SFTP_EXT_LSETSTAT) == 0) {
		error("Server does not support lsetstat@openssh.com extension");
		తిరిగి -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(lsetstat@openssh.com) \"%s\"", మార్గం);

	id = conn->సందేశం_id++;
	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = sshbuf_put_u8(సందేశం, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(సందేశం, id)) != 0 ||
	    (r = sshbuf_put_cstring(సందేశం, "lsetstat@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(సందేశం, మార్గం)) != 0 ||
	    (r = encode_attrib(సందేశం, a)) != 0)
		fatal_fr(r, "compose");
	send_సందేశం(conn, సందేశం);
	sshbuf_free(సందేశం);

	స్థితి_2 = get_స్థితి(conn, id);
	ఒకవేళ (స్థితి_2 != SSH2_FX_OK)
		error("remote lsetstat \"%s\": %s", మార్గం, fx2txt(స్థితి_2));

	తిరిగి స్థితి_2 == SSH2_FX_OK ? 0 : -1;
}

స్థిర శూన్య
send_read_request(నిర్మాణం sftp_conn *conn, u_int id, uint64_t స్థానభ్రంశం,
    u_int len, స్థిరరాశి u_char *handle, u_int handle_len)
{
	నిర్మాణం sshbuf *సందేశం;
	పూర్ణాంకం r;

	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = sshbuf_put_u8(సందేశం, SSH2_FXP_READ)) != 0 ||
	    (r = sshbuf_put_u32(సందేశం, id)) != 0 ||
	    (r = sshbuf_put_string(సందేశం, handle, handle_len)) != 0 ||
	    (r = sshbuf_put_u64(సందేశం, స్థానభ్రంశం)) != 0 ||
	    (r = sshbuf_put_u32(సందేశం, len)) != 0)
		fatal_fr(r, "compose");
	send_సందేశం(conn, సందేశం);
	sshbuf_free(సందేశం);
}

స్థిర పూర్ణాంకం
send_open(నిర్మాణం sftp_conn *conn, స్థిరరాశి అక్షరం *మార్గం, స్థిరరాశి అక్షరం *ట్యాగ్,
    u_int openmode, Attrib *a, u_char **handlep, కొలత_t *handle_lenp)
{
	Attrib junk;
	u_char *handle;
	కొలత_t handle_len;
	నిర్మాణం sshbuf *సందేశం;
	పూర్ణాంకం r;
	u_int id;

	debug2("Sending SSH2_FXP_OPEN \"%s\"", మార్గం);

	*handlep = ఖాళీ;
	*handle_lenp = 0;

	ఒకవేళ (a == ఖాళీ) {
		attrib_clear(&junk); /* Send empty attributes */
		a = &junk;
	}
	/* Send open request */
	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	id = conn->సందేశం_id++;
	ఒకవేళ ((r = sshbuf_put_u8(సందేశం, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(సందేశం, id)) != 0 ||
	    (r = sshbuf_put_cstring(సందేశం, మార్గం)) != 0 ||
	    (r = sshbuf_put_u32(సందేశం, openmode)) != 0 ||
	    (r = encode_attrib(సందేశం, a)) != 0)
		fatal_fr(r, "compose %s open", ట్యాగ్);
	send_సందేశం(conn, సందేశం);
	sshbuf_free(సందేశం);
	debug3("Sent %s message SSH2_FXP_OPEN I:%u P:%s M:0x%04x",
	    ట్యాగ్, id, మార్గం, openmode);
	ఒకవేళ ((handle = get_handle(conn, id, &handle_len,
	    "%s open \"%s\"", ట్యాగ్, మార్గం)) == ఖాళీ)
		తిరిగి -1;
	/* success */
	*handlep = handle;
	*handle_lenp = handle_len;
	తిరిగి 0;
}

స్థిర స్థిరరాశి అక్షరం *
పురోగతి_meter_మార్గం(స్థిరరాశి అక్షరం *మార్గం)
{
	స్థిరరాశి అక్షరం *progresspath;

	ఒకవేళ ((progresspath = strrchr(మార్గం, '/')) == ఖాళీ)
		తిరిగి మార్గం;
	progresspath++;
	ఒకవేళ (*progresspath == '\0')
		తిరిగి మార్గం;
	తిరిగి progresspath;
}

పూర్ణాంకం
sftp_download(నిర్మాణం sftp_conn *conn, స్థిరరాశి అక్షరం *remote_మార్గం,
    స్థిరరాశి అక్షరం *local_మార్గం, Attrib *a, పూర్ణాంకం preserve_flag, పూర్ణాంకం resume_flag,
    పూర్ణాంకం fsync_flag, పూర్ణాంకం inplace_flag)
{
	నిర్మాణం sshbuf *సందేశం;
	u_char *handle;
	పూర్ణాంకం local_fd = -1, write_error, చూసిన_zerolen = 0;
	పూర్ణాంకం read_error, write_errno, lmodified = 0, reordered = 0, r;
	uint64_t స్థానభ్రంశం = 0, కొలత, highwater = 0, maxack = 0;
	u_int బహుళకం, id, buflen, అంకె_req, max_req, స్థితి_2 = SSH2_FX_OK;
	off_t పురోగతి_counter;
	కొలత_t handle_len;
	నిర్మాణం stat st;
	నిర్మాణం అభ్యర్థనలు అభ్యర్థనలు;
	నిర్మాణం request *req;
	u_char type;
	Attrib attr;

	debug2_f("download remote \"%s\" to local \"%s\"",
	    remote_మార్గం, local_మార్గం);

	TAILQ_INIT(&అభ్యర్థనలు);

	ఒకవేళ (a == ఖాళీ) {
		ఒకవేళ (sftp_stat(conn, remote_మార్గం, 0, &attr) != 0)
			తిరిగి -1;
		a = &attr;
	}

	/* Do not preserve set[ug]id here, as we do not preserve ownership */
	ఒకవేళ (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS)
		బహుళకం = a->perm & 0777;
	లేకపోతే
		బహుళకం = 0666;

	ఒకవేళ ((a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) &&
	    (!S_ISREG(a->perm))) {
		error("download %s: not a regular file", remote_మార్గం);
		తిరిగి(-1);
	}

	ఒకవేళ (a->flags & SSH2_FILEXFER_ATTR_కొలత)
		కొలత = a->కొలత;
	లేకపోతే
		కొలత = 0;

	buflen = conn->download_buflen;

	/* Send open request */
	ఒకవేళ (send_open(conn, remote_మార్గం, "remote", SSH2_FXF_READ, ఖాళీ,
	    &handle, &handle_len) != 0)
		తిరిగి -1;

	local_fd = open(local_మార్గం, O_WRONLY | O_CREAT |
	((resume_flag || inplace_flag) ? 0 : O_TRUNC), బహుళకం | S_IWUSR);
	ఒకవేళ (local_fd == -1) {
		error("open local \"%s\": %s", local_మార్గం, strerror(errno));
		వెళ్ళు fail;
	}
	ఒకవేళ (resume_flag) {
		ఒకవేళ (fstat(local_fd, &st) == -1) {
			error("stat local \"%s\": %s",
			    local_మార్గం, strerror(errno));
			వెళ్ళు fail;
		}
		ఒకవేళ (st.st_size < 0) {
			error("\"%s\" has negative size", local_మార్గం);
			వెళ్ళు fail;
		}
		ఒకవేళ ((uint64_t)st.st_size > కొలత) {
			error("Unable to resume download of \"%s\": "
			    "local file is larger than remote", local_మార్గం);
 fail:
			sftp_close(conn, handle, handle_len);
			విడుదల(handle);
			ఒకవేళ (local_fd != -1)
				close(local_fd);
			తిరిగి -1;
		}
		స్థానభ్రంశం = highwater = maxack = st.st_size;
	}

	/* Read from remote and write to local */
	write_error = read_error = write_errno = అంకె_req = 0;
	max_req = 1;
	పురోగతి_counter = స్థానభ్రంశం;

	ఒకవేళ (showprogress && కొలత != 0) {
		ప్రారంభం_పురోగతి_meter(పురోగతి_meter_మార్గం(remote_మార్గం),
		    కొలత, &పురోగతి_counter);
	}

	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");

	అయితే (అంకె_req > 0 || max_req > 0) {
		u_char *దత్తాంశం;
		కొలత_t len;

		/*
		 * Simulate EOF on interrupt: stop sending new requests and
		 * allow outstanding requests to drain gracefully
		 */
		ఒకవేళ (interrupted) {
			ఒకవేళ (అంకె_req == 0) /* If we haven't started yet... */
				ఆపు;
			max_req = 0;
		}

		/* Send some more requests */
		అయితే (అంకె_req < max_req) {
			debug3("Request range %llu -> %llu (%d/%d)",
			    (గుర్తులేని దీర్ఘ దీర్ఘ)స్థానభ్రంశం,
			    (గుర్తులేని దీర్ఘ దీర్ఘ)స్థానభ్రంశం + buflen - 1,
			    అంకె_req, max_req);
			req = request_వరుసలో_చేర్చు(&అభ్యర్థనలు, conn->సందేశం_id++,
			    buflen, స్థానభ్రంశం);
			స్థానభ్రంశం += buflen;
			అంకె_req++;
			send_read_request(conn, req->id, req->స్థానభ్రంశం,
			    req->len, handle, handle_len);
		}

		sshbuf_reset(సందేశం);
		get_సందేశం(conn, సందేశం);
		ఒకవేళ ((r = sshbuf_get_u8(సందేశం, &type)) != 0 ||
		    (r = sshbuf_get_u32(సందేశం, &id)) != 0)
			fatal_fr(r, "parse");
		debug3("Received reply T:%u I:%u R:%d", type, id, max_req);

		/* Find the request in our queue */
		ఒకవేళ ((req = request_కనుగొను(&అభ్యర్థనలు, id)) == ఖాళీ)
			fatal("Unexpected reply %u", id);

		ఎంపిక (type) {
		స్థితి SSH2_FXP_స్థితి:
			ఒకవేళ ((r = sshbuf_get_u32(సందేశం, &స్థితి_2)) != 0)
				fatal_fr(r, "parse status");
			ఒకవేళ (స్థితి_2 != SSH2_FX_EOF)
				read_error = 1;
			max_req = 0;
			TAILQ_REMOVE(&అభ్యర్థనలు, req, tq);
			విడుదల(req);
			అంకె_req--;
			ఆపు;
		స్థితి SSH2_FXP_దత్తాంశం:
			ఒకవేళ ((r = sshbuf_get_string(సందేశం, &దత్తాంశం, &len)) != 0)
				fatal_fr(r, "parse data");
			debug3("Received data %llu -> %llu",
			    (గుర్తులేని దీర్ఘ దీర్ఘ)req->స్థానభ్రంశం,
			    (గుర్తులేని దీర్ఘ దీర్ఘ)req->స్థానభ్రంశం + len - 1);
			ఒకవేళ (len > req->len)
				fatal("Received more data than asked for "
				    "%zu > %zu", len, req->len);
			ఒకవేళ (len == 0) {
				ఒకవేళ (చూసిన_zerolen)
					fatal_f("server sent zero data length");
				చూసిన_zerolen = 1;
			}
			lmodified = 1;
			ఒకవేళ ((lseek(local_fd, req->స్థానభ్రంశం, SEEK_SET) == -1 ||
			    atomicio(vwrite, local_fd, దత్తాంశం, len) != len) &&
			    !write_error) {
				write_errno = errno;
				write_error = 1;
				max_req = 0;
			} లేకపోతే {
				/*
				 * Track both the highest offset acknowledged
				 * and the highest *contiguous* offset
				 * acknowledged.
				 * We'll need the latter for ftruncate()ing
				 * interrupted transfers.
				 */
				ఒకవేళ (maxack < req->స్థానభ్రంశం + len)
					maxack = req->స్థానభ్రంశం + len;
				ఒకవేళ (!reordered && req->స్థానభ్రంశం <= highwater)
					highwater = maxack;
				లేకపోతే ఒకవేళ (!reordered && req->స్థానభ్రంశం > highwater)
					reordered = 1;
			}
			పురోగతి_counter += len;
			విడుదల(దత్తాంశం);

			ఒకవేళ (len == req->len) {
				TAILQ_REMOVE(&అభ్యర్థనలు, req, tq);
				విడుదల(req);
				అంకె_req--;
			} లేకపోతే {
				/* Resend the request for the missing data */
				debug3("Short data block, re-requesting "
				    "%llu -> %llu (%2d)",
				    (గుర్తులేని దీర్ఘ దీర్ఘ)req->స్థానభ్రంశం + len,
				    (గుర్తులేని దీర్ఘ దీర్ఘ)req->స్థానభ్రంశం +
				    req->len - 1, అంకె_req);
				req->id = conn->సందేశం_id++;
				req->len -= len;
				req->స్థానభ్రంశం += len;
				send_read_request(conn, req->id,
				    req->స్థానభ్రంశం, req->len, handle, handle_len);
				/* Reduce the request size */
				ఒకవేళ (len < buflen)
					buflen = గరిష్ఠ(MIN_READ_కొలత, len);
			}
			ఒకవేళ (max_req > 0) { /* max_req = 0 iff EOF received */
				ఒకవేళ (కొలత > 0 && స్థానభ్రంశం > కొలత) {
					/* Only one request at a time
					 * after the expected EOF */
					debug3("Finish at %llu (%2d)",
					    (గుర్తులేని దీర్ఘ దీర్ఘ)స్థానభ్రంశం,
					    అంకె_req);
					max_req = 1;
				} లేకపోతే ఒకవేళ (max_req < conn->అంకె_అభ్యర్థనలు) {
					++max_req;
				}
			}
			ఆపు;
		అప్రమేయ:
			fatal("Expected SSH2_FXP_DATA(%u) packet, got %u",
			    SSH2_FXP_దత్తాంశం, type);
		}
	}

	ఒకవేళ (showprogress && కొలత)
		stop_పురోగతి_meter();

	/* Sanity check */
	ఒకవేళ (TAILQ_FIRST(&అభ్యర్థనలు) != ఖాళీ)
		fatal("Transfer complete, but requests still in queue");

	ఒకవేళ (!read_error && !write_error && !interrupted) {
		/* we got everything */
		highwater = maxack;
	}

	/*
	 * Truncate at highest contiguous point to avoid holes on interrupt,
	 * or unconditionally if writing in place.
	 */
	ఒకవేళ (inplace_flag || read_error || write_error || interrupted) {
		ఒకవేళ (reordered && resume_flag &&
		    (read_error || write_error || interrupted)) {
			error("Unable to resume download of \"%s\": "
			    "server reordered requests", local_మార్గం);
		}
		debug("truncating at %llu", (గుర్తులేని దీర్ఘ దీర్ఘ)highwater);
		ఒకవేళ (ftruncate(local_fd, highwater) == -1)
			error("local ftruncate \"%s\": %s", local_మార్గం,
			    strerror(errno));
	}
	ఒకవేళ (read_error) {
		error("read remote \"%s\" : %s", remote_మార్గం, fx2txt(స్థితి_2));
		స్థితి_2 = -1;
		sftp_close(conn, handle, handle_len);
	} లేకపోతే ఒకవేళ (write_error) {
		error("write local \"%s\": %s", local_మార్గం,
		    strerror(write_errno));
		స్థితి_2 = SSH2_FX_FAILURE;
		sftp_close(conn, handle, handle_len);
	} లేకపోతే {
		ఒకవేళ (sftp_close(conn, handle, handle_len) != 0 || interrupted)
			స్థితి_2 = SSH2_FX_FAILURE;
		లేకపోతే
			స్థితి_2 = SSH2_FX_OK;
		/* Override umask and utimes if asked */
#నిర్వచితమైతే HAVE_FCHMOD
		ఒకవేళ (preserve_flag && fchmod(local_fd, బహుళకం) == -1)
#లేకపోతే
		ఒకవేళ (preserve_flag && chmod(local_మార్గం, బహుళకం) == -1)
#అయితే_ముగింపు /* HAVE_FCHMOD */
			error("local chmod \"%s\": %s", local_మార్గం,
			    strerror(errno));
		ఒకవేళ (preserve_flag &&
		    (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME)) {
			నిర్మాణం timeval tv[2];
			tv[0].tv_sec = a->atime;
			tv[1].tv_sec = a->mtime;
			tv[0].tv_usec = tv[1].tv_usec = 0;
			ఒకవేళ (utimes(local_మార్గం, tv) == -1)
				error("local set times \"%s\": %s",
				    local_మార్గం, strerror(errno));
		}
		ఒకవేళ (resume_flag && !lmodified)
			logit("File \"%s\" was not modified", local_మార్గం);
		లేకపోతే ఒకవేళ (fsync_flag) {
			debug("syncing \"%s\"", local_మార్గం);
			ఒకవేళ (fsync(local_fd) == -1)
				error("local sync \"%s\": %s",
				    local_మార్గం, strerror(errno));
		}
	}
	close(local_fd);
	sshbuf_free(సందేశం);
	విడుదల(handle);

	తిరిగి స్థితి_2 == SSH2_FX_OK ? 0 : -1;
}

స్థిర పూర్ణాంకం
download_dir_అంతర్గత(నిర్మాణం sftp_conn *conn, స్థిరరాశి అక్షరం *src, స్థిరరాశి అక్షరం *dst,
    పూర్ణాంకం లోతు, Attrib *dirattrib, పూర్ణాంకం preserve_flag, పూర్ణాంకం print_flag,
    పూర్ణాంకం resume_flag, పూర్ణాంకం fsync_flag, పూర్ణాంకం follow_link_flag, పూర్ణాంకం inplace_flag)
{
	పూర్ణాంకం i, ret = 0;
	SFTP_DIRENT **dir_entries;
	అక్షరం *filename, *new_src = ఖాళీ, *new_dst = ఖాళీ;
	బహుళకం_t బహుళకం = 0777, tmpmode = బహుళకం;
	Attrib *a, ldirattrib, lsym;

	ఒకవేళ (లోతు >= MAX_DIR_లోతు) {
		error("Maximum directory depth exceeded: %d levels", లోతు);
		తిరిగి -1;
	}

	debug2_f("download dir remote \"%s\" to local \"%s\"", src, dst);

	ఒకవేళ (dirattrib == ఖాళీ) {
		ఒకవేళ (sftp_stat(conn, src, 1, &ldirattrib) != 0) {
			error("stat remote \"%s\" directory failed", src);
			తిరిగి -1;
		}
		dirattrib = &ldirattrib;
	}
	ఒకవేళ (!S_ISDIR(dirattrib->perm)) {
		error("\"%s\" is not a directory", src);
		తిరిగి -1;
	}
	ఒకవేళ (print_flag && print_flag != SFTP_పురోగతి_ONLY)
		mprintf("Retrieving %s\n", src);

	ఒకవేళ (dirattrib->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		బహుళకం = dirattrib->perm & 01777;
		tmpmode = బహుళకం | (S_IWUSR|S_IXUSR);
	} లేకపోతే {
		debug("download remote \"%s\": server "
		    "did not send permissions", dst);
	}

	ఒకవేళ (mkdir(dst, tmpmode) == -1 && errno != EEXIST) {
		error("mkdir %s: %s", dst, strerror(errno));
		తిరిగి -1;
	}

	ఒకవేళ (sftp_readdir(conn, src, &dir_entries) == -1) {
		error("remote readdir \"%s\" failed", src);
		తిరిగి -1;
	}

	కొరకు (i = 0; dir_entries[i] != ఖాళీ && !interrupted; i++) {
		విడుదల(new_dst);
		విడుదల(new_src);

		filename = dir_entries[i]->filename;
		new_dst = sftp_మార్గం_append(dst, filename);
		new_src = sftp_మార్గం_append(src, filename);

		a = &dir_entries[i]->a;
		ఒకవేళ (S_ISLNK(a->perm)) {
			ఒకవేళ (!follow_link_flag) {
				logit("download \"%s\": not a regular file",
				    new_src);
				కొనసాగు;
			}
			/* Replace the stat contents with the symlink target */
			ఒకవేళ (sftp_stat(conn, new_src, 1, &lsym) != 0) {
				logit("remote stat \"%s\" failed", new_src);
				ret = -1;
				కొనసాగు;
			}
			a = &lsym;
		}

		ఒకవేళ (S_ISDIR(a->perm)) {
			ఒకవేళ (strcmp(filename, ".") == 0 ||
			    strcmp(filename, "..") == 0)
				కొనసాగు;
			ఒకవేళ (download_dir_అంతర్గత(conn, new_src, new_dst,
			    లోతు + 1, a, preserve_flag,
			    print_flag, resume_flag,
			    fsync_flag, follow_link_flag, inplace_flag) == -1)
				ret = -1;
		} లేకపోతే ఒకవేళ (S_ISREG(a->perm)) {
			ఒకవేళ (sftp_download(conn, new_src, new_dst, a,
			    preserve_flag, resume_flag, fsync_flag,
			    inplace_flag) == -1) {
				error("Download of file %s to %s failed",
				    new_src, new_dst);
				ret = -1;
			}
		} లేకపోతే
			logit("download \"%s\": not a regular file", new_src);

	}
	విడుదల(new_dst);
	విడుదల(new_src);

	ఒకవేళ (preserve_flag) {
		ఒకవేళ (dirattrib->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
			నిర్మాణం timeval tv[2];
			tv[0].tv_sec = dirattrib->atime;
			tv[1].tv_sec = dirattrib->mtime;
			tv[0].tv_usec = tv[1].tv_usec = 0;
			ఒకవేళ (utimes(dst, tv) == -1)
				error("local set times on \"%s\": %s",
				    dst, strerror(errno));
		} లేకపోతే
			debug("Server did not send times for directory "
			    "\"%s\"", dst);
	}

	ఒకవేళ (బహుళకం != tmpmode && chmod(dst, బహుళకం) == -1)
		error("local chmod directory \"%s\": %s", dst,
		    strerror(errno));

	sftp_free_dirents(dir_entries);

	తిరిగి ret;
}

పూర్ణాంకం
sftp_download_dir(నిర్మాణం sftp_conn *conn, స్థిరరాశి అక్షరం *src, స్థిరరాశి అక్షరం *dst,
    Attrib *dirattrib, పూర్ణాంకం preserve_flag, పూర్ణాంకం print_flag, పూర్ణాంకం resume_flag,
    పూర్ణాంకం fsync_flag, పూర్ణాంకం follow_link_flag, పూర్ణాంకం inplace_flag)
{
	అక్షరం *src_canon;
	పూర్ణాంకం ret;

	ఒకవేళ ((src_canon = sftp_realpath(conn, src)) == ఖాళీ) {
		error("download \"%s\": path canonicalization failed", src);
		తిరిగి -1;
	}

	ret = download_dir_అంతర్గత(conn, src_canon, dst, 0,
	    dirattrib, preserve_flag, print_flag, resume_flag, fsync_flag,
	    follow_link_flag, inplace_flag);
	విడుదల(src_canon);
	తిరిగి ret;
}

పూర్ణాంకం
sftp_upload(నిర్మాణం sftp_conn *conn, స్థిరరాశి అక్షరం *local_మార్గం,
    స్థిరరాశి అక్షరం *remote_మార్గం, పూర్ణాంకం preserve_flag, పూర్ణాంకం resume,
    పూర్ణాంకం fsync_flag, పూర్ణాంకం inplace_flag)
{
	పూర్ణాంకం r, local_fd;
	u_int openmode, id, స్థితి_2 = SSH2_FX_OK, status2, reordered = 0;
	off_t స్థానభ్రంశం, పురోగతి_counter;
	u_char type, *handle, *దత్తాంశం;
	నిర్మాణం sshbuf *సందేశం;
	నిర్మాణం stat sb;
	Attrib a, t, c;
	uint32_t startid, ackid;
	uint64_t highwater = 0, maxack = 0;
	నిర్మాణం request *ack = ఖాళీ;
	నిర్మాణం అభ్యర్థనలు acks;
	కొలత_t handle_len;

	debug2_f("upload local \"%s\" to remote \"%s\"",
	    local_మార్గం, remote_మార్గం);

	TAILQ_INIT(&acks);

	ఒకవేళ ((local_fd = open(local_మార్గం, O_RDONLY)) == -1) {
		error("open local \"%s\": %s", local_మార్గం, strerror(errno));
		తిరిగి(-1);
	}
	ఒకవేళ (fstat(local_fd, &sb) == -1) {
		error("fstat local \"%s\": %s", local_మార్గం, strerror(errno));
		close(local_fd);
		తిరిగి(-1);
	}
	ఒకవేళ (!S_ISREG(sb.st_mode)) {
		error("local \"%s\" is not a regular file", local_మార్గం);
		close(local_fd);
		తిరిగి(-1);
	}
	stat_గమ్యం_attrib(&sb, &a);

	a.flags &= ~SSH2_FILEXFER_ATTR_కొలత;
	a.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a.perm &= 0777;
	ఒకవేళ (!preserve_flag)
		a.flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;

	ఒకవేళ (resume) {
		/* Get remote file size if it exists */
		ఒకవేళ (sftp_stat(conn, remote_మార్గం, 0, &c) != 0) {
			close(local_fd);
			తిరిగి -1;
		}

		ఒకవేళ ((off_t)c.కొలత >= sb.st_size) {
			error("resume \"%s\": destination file "
			    "same size or larger", local_మార్గం);
			close(local_fd);
			తిరిగి -1;
		}

		ఒకవేళ (lseek(local_fd, (off_t)c.కొలత, SEEK_SET) == -1) {
			close(local_fd);
			తిరిగి -1;
		}
		highwater = c.కొలత;
	}

	openmode = SSH2_FXF_WRITE|SSH2_FXF_CREAT;
	ఒకవేళ (resume)
		openmode |= SSH2_FXF_APPEND;
	లేకపోతే ఒకవేళ (!inplace_flag)
		openmode |= SSH2_FXF_TRUNC;

	/* Send open request */
	ఒకవేళ (send_open(conn, remote_మార్గం, "dest", openmode, &a,
	    &handle, &handle_len) != 0) {
		close(local_fd);
		తిరిగి -1;
	}

	id = conn->సందేశం_id;
	startid = ackid = id + 1;
	దత్తాంశం = xmalloc(conn->upload_buflen);

	/* Read from local and write to remote */
	స్థానభ్రంశం = పురోగతి_counter = (resume ? c.కొలత : 0);
	ఒకవేళ (showprogress) {
		ప్రారంభం_పురోగతి_meter(పురోగతి_meter_మార్గం(local_మార్గం),
		    sb.st_size, &పురోగతి_counter);
	}

	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	కొరకు (;;) {
		పూర్ణాంకం len;

		/*
		 * Can't use atomicio here because it returns 0 on EOF,
		 * thus losing the last block of the file.
		 * Simulate an EOF on interrupt, allowing ACKs from the
		 * server to drain.
		 */
		ఒకవేళ (interrupted || స్థితి_2 != SSH2_FX_OK)
			len = 0;
		లేకపోతే చేయి
			len = పఠ(local_fd, దత్తాంశం, conn->upload_buflen);
		అయితే ((len == -1) &&
		    (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK));

		ఒకవేళ (len == -1) {
			fatal("read local \"%s\": %s",
			    local_మార్గం, strerror(errno));
		} లేకపోతే ఒకవేళ (len != 0) {
			ack = request_వరుసలో_చేర్చు(&acks, ++id, len, స్థానభ్రంశం);
			sshbuf_reset(సందేశం);
			ఒకవేళ ((r = sshbuf_put_u8(సందేశం, SSH2_FXP_WRITE)) != 0 ||
			    (r = sshbuf_put_u32(సందేశం, ack->id)) != 0 ||
			    (r = sshbuf_put_string(సందేశం, handle,
			    handle_len)) != 0 ||
			    (r = sshbuf_put_u64(సందేశం, స్థానభ్రంశం)) != 0 ||
			    (r = sshbuf_put_string(సందేశం, దత్తాంశం, len)) != 0)
				fatal_fr(r, "compose");
			send_సందేశం(conn, సందేశం);
			debug3("Sent message SSH2_FXP_WRITE I:%u O:%llu S:%u",
			    id, (గుర్తులేని దీర్ఘ దీర్ఘ)స్థానభ్రంశం, len);
		} లేకపోతే ఒకవేళ (TAILQ_FIRST(&acks) == ఖాళీ)
			ఆపు;

		ఒకవేళ (ack == ఖాళీ)
			fatal("Unexpected ACK %u", id);

		ఒకవేళ (id == startid || len == 0 ||
		    id - ackid >= conn->అంకె_అభ్యర్థనలు) {
			u_int rid;

			sshbuf_reset(సందేశం);
			get_సందేశం(conn, సందేశం);
			ఒకవేళ ((r = sshbuf_get_u8(సందేశం, &type)) != 0 ||
			    (r = sshbuf_get_u32(సందేశం, &rid)) != 0)
				fatal_fr(r, "parse");

			ఒకవేళ (type != SSH2_FXP_స్థితి)
				fatal("Expected SSH2_FXP_STATUS(%d) packet, "
				    "got %d", SSH2_FXP_స్థితి, type);

			ఒకవేళ ((r = sshbuf_get_u32(సందేశం, &status2)) != 0)
				fatal_fr(r, "parse status");
			debug3("SSH2_FXP_STATUS %u", status2);
			ఒకవేళ (status2 != SSH2_FX_OK)
				స్థితి_2 = status2; /* remember errors */

			/* Find the request in our queue */
			ఒకవేళ ((ack = request_కనుగొను(&acks, rid)) == ఖాళీ)
				fatal("Can't find request for ID %u", rid);
			TAILQ_REMOVE(&acks, ack, tq);
			debug3("In write loop, ack for %u %zu bytes at %lld",
			    ack->id, ack->len, (గుర్తులేని దీర్ఘ దీర్ఘ)ack->స్థానభ్రంశం);
			++ackid;
			పురోగతి_counter += ack->len;
			/*
			 * Track both the highest offset acknowledged and the
			 * highest *contiguous* offset acknowledged.
			 * We'll need the latter for ftruncate()ing
			 * interrupted transfers.
			 */
			ఒకవేళ (maxack < ack->స్థానభ్రంశం + ack->len)
				maxack = ack->స్థానభ్రంశం + ack->len;
			ఒకవేళ (!reordered && ack->స్థానభ్రంశం <= highwater)
				highwater = maxack;
			లేకపోతే ఒకవేళ (!reordered && ack->స్థానభ్రంశం > highwater) {
				debug3_f("server reordered ACKs");
				reordered = 1;
			}
			విడుదల(ack);
		}
		స్థానభ్రంశం += len;
		ఒకవేళ (స్థానభ్రంశం < 0)
			fatal_f("offset < 0");
	}
	sshbuf_free(సందేశం);

	ఒకవేళ (showprogress)
		stop_పురోగతి_meter();
	విడుదల(దత్తాంశం);

	ఒకవేళ (స్థితి_2 == SSH2_FX_OK && !interrupted) {
		/* we got everything */
		highwater = maxack;
	}
	ఒకవేళ (స్థితి_2 != SSH2_FX_OK) {
		error("write remote \"%s\": %s", remote_మార్గం, fx2txt(స్థితి_2));
		స్థితి_2 = SSH2_FX_FAILURE;
	}

	ఒకవేళ (inplace_flag || (resume && (స్థితి_2 != SSH2_FX_OK || interrupted))) {
		debug("truncating at %llu", (గుర్తులేని దీర్ఘ దీర్ఘ)highwater);
		attrib_clear(&t);
		t.flags = SSH2_FILEXFER_ATTR_కొలత;
		t.కొలత = highwater;
		sftp_fsetstat(conn, handle, handle_len, &t);
	}

	ఒకవేళ (close(local_fd) == -1) {
		error("close local \"%s\": %s", local_మార్గం, strerror(errno));
		స్థితి_2 = SSH2_FX_FAILURE;
	}

	/* Override umask and utimes if asked */
	ఒకవేళ (preserve_flag)
		sftp_fsetstat(conn, handle, handle_len, &a);

	ఒకవేళ (fsync_flag)
		(శూన్య)sftp_fsync(conn, handle, handle_len);

	ఒకవేళ (sftp_close(conn, handle, handle_len) != 0)
		స్థితి_2 = SSH2_FX_FAILURE;

	విడుదల(handle);

	తిరిగి స్థితి_2 == SSH2_FX_OK ? 0 : -1;
}

స్థిర పూర్ణాంకం
upload_dir_అంతర్గత(నిర్మాణం sftp_conn *conn, స్థిరరాశి అక్షరం *src, స్థిరరాశి అక్షరం *dst,
    పూర్ణాంకం లోతు, పూర్ణాంకం preserve_flag, పూర్ణాంకం print_flag, పూర్ణాంకం resume, పూర్ణాంకం fsync_flag,
    పూర్ణాంకం follow_link_flag, పూర్ణాంకం inplace_flag)
{
	పూర్ణాంకం created = 0, ret = 0;
	DIR *dirp;
	నిర్మాణం dirent *dp;
	అక్షరం *filename, *new_src = ఖాళీ, *new_dst = ఖాళీ;
	నిర్మాణం stat sb;
	Attrib a, dirattrib;
	uint32_t saved_perm;

	debug2_f("upload local dir \"%s\" to remote \"%s\"", src, dst);

	ఒకవేళ (లోతు >= MAX_DIR_లోతు) {
		error("Maximum directory depth exceeded: %d levels", లోతు);
		తిరిగి -1;
	}

	ఒకవేళ (stat(src, &sb) == -1) {
		error("stat local \"%s\": %s", src, strerror(errno));
		తిరిగి -1;
	}
	ఒకవేళ (!S_ISDIR(sb.st_mode)) {
		error("\"%s\" is not a directory", src);
		తిరిగి -1;
	}
	ఒకవేళ (print_flag && print_flag != SFTP_పురోగతి_ONLY)
		mprintf("Entering %s\n", src);

	stat_గమ్యం_attrib(&sb, &a);
	a.flags &= ~SSH2_FILEXFER_ATTR_కొలత;
	a.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a.perm &= 01777;
	ఒకవేళ (!preserve_flag)
		a.flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;

	/*
	 * sftp lacks a portable status value to match errno EEXIST,
	 * so if we get a failure back then we must check whether
	 * the path already existed and is a directory.  Ensure we can
	 * write to the directory we create for the duration of the transfer.
	 */
	saved_perm = a.perm;
	a.perm |= (S_IWUSR|S_IXUSR);
	ఒకవేళ (sftp_mkdir(conn, dst, &a, 0) == 0)
		created = 1;
	లేకపోతే {
		ఒకవేళ (sftp_stat(conn, dst, 0, &dirattrib) != 0)
			తిరిగి -1;
		ఒకవేళ (!S_ISDIR(dirattrib.perm)) {
			error("\"%s\" exists but is not a directory", dst);
			తిరిగి -1;
		}
	}
	a.perm = saved_perm;

	ఒకవేళ ((dirp = opendir(src)) == ఖాళీ) {
		error("local opendir \"%s\": %s", src, strerror(errno));
		తిరిగి -1;
	}

	అయితే (((dp = readdir(dirp)) != ఖాళీ) && !interrupted) {
		ఒకవేళ (dp->d_ino == 0)
			కొనసాగు;
		విడుదల(new_dst);
		విడుదల(new_src);
		filename = dp->d_name;
		new_dst = sftp_మార్గం_append(dst, filename);
		new_src = sftp_మార్గం_append(src, filename);

		ఒకవేళ (strcmp(filename, ".") == 0 || strcmp(filename, "..") == 0)
			కొనసాగు;
		ఒకవేళ (lstat(new_src, &sb) == -1) {
			logit("local lstat \"%s\": %s", filename,
			    strerror(errno));
			ret = -1;
			కొనసాగు;
		}
		ఒకవేళ (S_ISLNK(sb.st_mode)) {
			ఒకవేళ (!follow_link_flag) {
				logit("%s: not a regular file", filename);
				కొనసాగు;
			}
			/* Replace the stat contents with the symlink target */
			ఒకవేళ (stat(new_src, &sb) == -1) {
				logit("local stat \"%s\": %s", filename,
				    strerror(errno));
				ret = -1;
				కొనసాగు;
			}
		}
		ఒకవేళ (S_ISDIR(sb.st_mode)) {
			ఒకవేళ (upload_dir_అంతర్గత(conn, new_src, new_dst,
			    లోతు + 1, preserve_flag, print_flag, resume,
			    fsync_flag, follow_link_flag, inplace_flag) == -1)
				ret = -1;
		} లేకపోతే ఒకవేళ (S_ISREG(sb.st_mode)) {
			ఒకవేళ (sftp_upload(conn, new_src, new_dst,
			    preserve_flag, resume, fsync_flag,
			    inplace_flag) == -1) {
				error("upload \"%s\" to \"%s\" failed",
				    new_src, new_dst);
				ret = -1;
			}
		} లేకపోతే
			logit("%s: not a regular file", filename);
	}
	విడుదల(new_dst);
	విడుదల(new_src);

	ఒకవేళ (created || preserve_flag)
		sftp_setstat(conn, dst, &a);

	(శూన్య) closedir(dirp);
	తిరిగి ret;
}

పూర్ణాంకం
sftp_upload_dir(నిర్మాణం sftp_conn *conn, స్థిరరాశి అక్షరం *src, స్థిరరాశి అక్షరం *dst,
    పూర్ణాంకం preserve_flag, పూర్ణాంకం print_flag, పూర్ణాంకం resume, పూర్ణాంకం fsync_flag,
    పూర్ణాంకం follow_link_flag, పూర్ణాంకం inplace_flag)
{
	అక్షరం *dst_canon;
	పూర్ణాంకం ret;

	ఒకవేళ ((dst_canon = sftp_realpath(conn, dst)) == ఖాళీ) {
		error("upload \"%s\": path canonicalization failed", dst);
		తిరిగి -1;
	}

	ret = upload_dir_అంతర్గత(conn, src, dst_canon, 0, preserve_flag,
	    print_flag, resume, fsync_flag, follow_link_flag, inplace_flag);

	విడుదల(dst_canon);
	తిరిగి ret;
}

స్థిర శూన్య
handle_dest_replies(నిర్మాణం sftp_conn *గమ్యం, స్థిరరాశి అక్షరం *గమ్యం_మార్గం, పూర్ణాంకం synchronous,
    u_int *nreqsp, u_int *write_errorp)
{
	నిర్మాణం sshbuf *సందేశం;
	u_char type;
	u_int id, స్థితి_2;
	పూర్ణాంకం r;
	నిర్మాణం pollfd pfd;

	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");

	/* Try to eat replies from the upload side */
	అయితే (*nreqsp > 0) {
		debug3_f("%u outstanding replies", *nreqsp);
		ఒకవేళ (!synchronous) {
			/* Bail out if no data is ready to be read */
			pfd.fd = గమ్యం->fd_లోపల;
			pfd.events = POLLIN;
			ఒకవేళ ((r = poll(&pfd, 1, 0)) == -1) {
				ఒకవేళ (errno == EINTR)
					ఆపు;
				fatal_f("poll: %s", strerror(errno));
			} లేకపోతే ఒకవేళ (r == 0)
				ఆపు; /* fd not ready */
		}
		sshbuf_reset(సందేశం);
		get_సందేశం(గమ్యం, సందేశం);

		ఒకవేళ ((r = sshbuf_get_u8(సందేశం, &type)) != 0 ||
		    (r = sshbuf_get_u32(సందేశం, &id)) != 0)
			fatal_fr(r, "dest parse");
		debug3("Received dest reply T:%u I:%u R:%u", type, id, *nreqsp);
		ఒకవేళ (type != SSH2_FXP_స్థితి) {
			fatal_f("Expected SSH2_FXP_STATUS(%d) packet, got %d",
			    SSH2_FXP_స్థితి, type);
		}
		ఒకవేళ ((r = sshbuf_get_u32(సందేశం, &స్థితి_2)) != 0)
			fatal_fr(r, "parse dest status");
		debug3("dest SSH2_FXP_STATUS %u", స్థితి_2);
		ఒకవేళ (స్థితి_2 != SSH2_FX_OK) {
			/* record first error */
			ఒకవేళ (*write_errorp == 0)
				*write_errorp = స్థితి_2;
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
	sshbuf_free(సందేశం);
}

పూర్ణాంకం
sftp_crossload(నిర్మాణం sftp_conn *from, నిర్మాణం sftp_conn *గమ్యం,
    స్థిరరాశి అక్షరం *from_మార్గం, స్థిరరాశి అక్షరం *గమ్యం_మార్గం,
    Attrib *a, పూర్ణాంకం preserve_flag)
{
	నిర్మాణం sshbuf *సందేశం;
	పూర్ణాంకం write_error, read_error, r, చూసిన_zerolen = 0;
	uint64_t స్థానభ్రంశం = 0, కొలత;
	u_int id, buflen, అంకె_req, max_req, స్థితి_2 = SSH2_FX_OK;
	u_int అంకె_upload_req;
	off_t పురోగతి_counter;
	u_char *from_handle, *గమ్యం_handle;
	కొలత_t from_handle_len, గమ్యం_handle_len;
	నిర్మాణం అభ్యర్థనలు అభ్యర్థనలు;
	నిర్మాణం request *req;
	u_char type;
	Attrib attr;

	debug2_f("crossload src \"%s\" to dst \"%s\"", from_మార్గం, గమ్యం_మార్గం);

	TAILQ_INIT(&అభ్యర్థనలు);

	ఒకవేళ (a == ఖాళీ) {
		ఒకవేళ (sftp_stat(from, from_మార్గం, 0, &attr) != 0)
			తిరిగి -1;
		a = &attr;
	}

	ఒకవేళ ((a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) &&
	    (!S_ISREG(a->perm))) {
		error("download \"%s\": not a regular file", from_మార్గం);
		తిరిగి(-1);
	}
	ఒకవేళ (a->flags & SSH2_FILEXFER_ATTR_కొలత)
		కొలత = a->కొలత;
	లేకపోతే
		కొలత = 0;

	buflen = from->download_buflen;
	ఒకవేళ (buflen > గమ్యం->upload_buflen)
		buflen = గమ్యం->upload_buflen;

	/* Send open request to read side */
	ఒకవేళ (send_open(from, from_మార్గం, "origin", SSH2_FXF_READ, ఖాళీ,
	    &from_handle, &from_handle_len) != 0)
		తిరిగి -1;

	/* Send open request to write side */
	a->flags &= ~SSH2_FILEXFER_ATTR_కొలత;
	a->flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a->perm &= 0777;
	ఒకవేళ (!preserve_flag)
		a->flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;
	ఒకవేళ (send_open(గమ్యం, గమ్యం_మార్గం, "dest",
	    SSH2_FXF_WRITE|SSH2_FXF_CREAT|SSH2_FXF_TRUNC, a,
	    &గమ్యం_handle, &గమ్యం_handle_len) != 0) {
		sftp_close(from, from_handle, from_handle_len);
		తిరిగి -1;
	}

	/* Read from remote "from" and write to remote "to" */
	స్థానభ్రంశం = 0;
	write_error = read_error = అంకె_req = అంకె_upload_req = 0;
	max_req = 1;
	పురోగతి_counter = 0;

	ఒకవేళ (showprogress && కొలత != 0) {
		ప్రారంభం_పురోగతి_meter(పురోగతి_meter_మార్గం(from_మార్గం),
		    కొలత, &పురోగతి_counter);
	}
	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	అయితే (అంకె_req > 0 || max_req > 0) {
		u_char *దత్తాంశం;
		కొలత_t len;

		/*
		 * Simulate EOF on interrupt: stop sending new requests and
		 * allow outstanding requests to drain gracefully
		 */
		ఒకవేళ (interrupted) {
			ఒకవేళ (అంకె_req == 0) /* If we haven't started yet... */
				ఆపు;
			max_req = 0;
		}

		/* Send some more requests */
		అయితే (అంకె_req < max_req) {
			debug3("Request range %llu -> %llu (%d/%d)",
			    (గుర్తులేని దీర్ఘ దీర్ఘ)స్థానభ్రంశం,
			    (గుర్తులేని దీర్ఘ దీర్ఘ)స్థానభ్రంశం + buflen - 1,
			    అంకె_req, max_req);
			req = request_వరుసలో_చేర్చు(&అభ్యర్థనలు, from->సందేశం_id++,
			    buflen, స్థానభ్రంశం);
			స్థానభ్రంశం += buflen;
			అంకె_req++;
			send_read_request(from, req->id, req->స్థానభ్రంశం,
			    req->len, from_handle, from_handle_len);
		}

		/* Try to eat replies from the upload side (nonblocking) */
		handle_dest_replies(గమ్యం, గమ్యం_మార్గం, 0,
		    &అంకె_upload_req, &write_error);

		sshbuf_reset(సందేశం);
		get_సందేశం(from, సందేశం);
		ఒకవేళ ((r = sshbuf_get_u8(సందేశం, &type)) != 0 ||
		    (r = sshbuf_get_u32(సందేశం, &id)) != 0)
			fatal_fr(r, "parse");
		debug3("Received origin reply T:%u I:%u R:%d",
		    type, id, max_req);

		/* Find the request in our queue */
		ఒకవేళ ((req = request_కనుగొను(&అభ్యర్థనలు, id)) == ఖాళీ)
			fatal("Unexpected reply %u", id);

		ఎంపిక (type) {
		స్థితి SSH2_FXP_స్థితి:
			ఒకవేళ ((r = sshbuf_get_u32(సందేశం, &స్థితి_2)) != 0)
				fatal_fr(r, "parse status");
			ఒకవేళ (స్థితి_2 != SSH2_FX_EOF)
				read_error = 1;
			max_req = 0;
			TAILQ_REMOVE(&అభ్యర్థనలు, req, tq);
			విడుదల(req);
			అంకె_req--;
			ఆపు;
		స్థితి SSH2_FXP_దత్తాంశం:
			ఒకవేళ ((r = sshbuf_get_string(సందేశం, &దత్తాంశం, &len)) != 0)
				fatal_fr(r, "parse data");
			debug3("Received data %llu -> %llu",
			    (గుర్తులేని దీర్ఘ దీర్ఘ)req->స్థానభ్రంశం,
			    (గుర్తులేని దీర్ఘ దీర్ఘ)req->స్థానభ్రంశం + len - 1);
			ఒకవేళ (len > req->len)
				fatal("Received more data than asked for "
				    "%zu > %zu", len, req->len);
			ఒకవేళ (len == 0) {
				ఒకవేళ (చూసిన_zerolen)
					fatal_f("server sent zero data length");
				చూసిన_zerolen = 1;
			}

			/* Write this chunk out to the destination */
			sshbuf_reset(సందేశం);
			ఒకవేళ ((r = sshbuf_put_u8(సందేశం, SSH2_FXP_WRITE)) != 0 ||
			    (r = sshbuf_put_u32(సందేశం, గమ్యం->సందేశం_id++)) != 0 ||
			    (r = sshbuf_put_string(సందేశం, గమ్యం_handle,
			    గమ్యం_handle_len)) != 0 ||
			    (r = sshbuf_put_u64(సందేశం, req->స్థానభ్రంశం)) != 0 ||
			    (r = sshbuf_put_string(సందేశం, దత్తాంశం, len)) != 0)
				fatal_fr(r, "compose write");
			send_సందేశం(గమ్యం, సందేశం);
			debug3("Sent message SSH2_FXP_WRITE I:%u O:%llu S:%zu",
			    id, (గుర్తులేని దీర్ఘ దీర్ఘ)స్థానభ్రంశం, len);
			అంకె_upload_req++;
			పురోగతి_counter += len;
			విడుదల(దత్తాంశం);

			ఒకవేళ (len == req->len) {
				TAILQ_REMOVE(&అభ్యర్థనలు, req, tq);
				విడుదల(req);
				అంకె_req--;
			} లేకపోతే {
				/* Resend the request for the missing data */
				debug3("Short data block, re-requesting "
				    "%llu -> %llu (%2d)",
				    (గుర్తులేని దీర్ఘ దీర్ఘ)req->స్థానభ్రంశం + len,
				    (గుర్తులేని దీర్ఘ దీర్ఘ)req->స్థానభ్రంశం +
				    req->len - 1, అంకె_req);
				req->id = from->సందేశం_id++;
				req->len -= len;
				req->స్థానభ్రంశం += len;
				send_read_request(from, req->id,
				    req->స్థానభ్రంశం, req->len,
				    from_handle, from_handle_len);
				/* Reduce the request size */
				ఒకవేళ (len < buflen)
					buflen = గరిష్ఠ(MIN_READ_కొలత, len);
			}
			ఒకవేళ (max_req > 0) { /* max_req = 0 iff EOF received */
				ఒకవేళ (కొలత > 0 && స్థానభ్రంశం > కొలత) {
					/* Only one request at a time
					 * after the expected EOF */
					debug3("Finish at %llu (%2d)",
					    (గుర్తులేని దీర్ఘ దీర్ఘ)స్థానభ్రంశం,
					    అంకె_req);
					max_req = 1;
				} లేకపోతే ఒకవేళ (max_req < from->అంకె_అభ్యర్థనలు) {
					++max_req;
				}
			}
			ఆపు;
		అప్రమేయ:
			fatal("Expected SSH2_FXP_DATA(%u) packet, got %u",
			    SSH2_FXP_దత్తాంశం, type);
		}
	}

	ఒకవేళ (showprogress && కొలత)
		stop_పురోగతి_meter();

	/* Drain replies from the server (blocking) */
	debug3_f("waiting for %u replies from destination", అంకె_upload_req);
	handle_dest_replies(గమ్యం, గమ్యం_మార్గం, 1, &అంకె_upload_req, &write_error);

	/* Sanity check */
	ఒకవేళ (TAILQ_FIRST(&అభ్యర్థనలు) != ఖాళీ)
		fatal("Transfer complete, but requests still in queue");
	/* Truncate at 0 length on interrupt or error to avoid holes at dest */
	ఒకవేళ (read_error || write_error || interrupted) {
		debug("truncating \"%s\" at 0", గమ్యం_మార్గం);
		sftp_close(గమ్యం, గమ్యం_handle, గమ్యం_handle_len);
		విడుదల(గమ్యం_handle);
		ఒకవేళ (send_open(గమ్యం, గమ్యం_మార్గం, "dest",
		    SSH2_FXF_WRITE|SSH2_FXF_CREAT|SSH2_FXF_TRUNC, a,
		    &గమ్యం_handle, &గమ్యం_handle_len) != 0) {
			error("dest truncate \"%s\" failed", గమ్యం_మార్గం);
			గమ్యం_handle = ఖాళీ;
		}
	}
	ఒకవేళ (read_error) {
		error("read origin \"%s\": %s", from_మార్గం, fx2txt(స్థితి_2));
		స్థితి_2 = -1;
		sftp_close(from, from_handle, from_handle_len);
		ఒకవేళ (గమ్యం_handle != ఖాళీ)
			sftp_close(గమ్యం, గమ్యం_handle, గమ్యం_handle_len);
	} లేకపోతే ఒకవేళ (write_error) {
		error("write dest \"%s\": %s", గమ్యం_మార్గం, fx2txt(write_error));
		స్థితి_2 = SSH2_FX_FAILURE;
		sftp_close(from, from_handle, from_handle_len);
		ఒకవేళ (గమ్యం_handle != ఖాళీ)
			sftp_close(గమ్యం, గమ్యం_handle, గమ్యం_handle_len);
	} లేకపోతే {
		ఒకవేళ (sftp_close(from, from_handle, from_handle_len) != 0 ||
		    interrupted)
			స్థితి_2 = -1;
		లేకపోతే
			స్థితి_2 = SSH2_FX_OK;
		ఒకవేళ (గమ్యం_handle != ఖాళీ) {
			/* Need to resend utimes after write */
			ఒకవేళ (preserve_flag)
				sftp_fsetstat(గమ్యం, గమ్యం_handle, గమ్యం_handle_len, a);
			sftp_close(గమ్యం, గమ్యం_handle, గమ్యం_handle_len);
		}
	}
	sshbuf_free(సందేశం);
	విడుదల(from_handle);
	విడుదల(గమ్యం_handle);

	తిరిగి స్థితి_2 == SSH2_FX_OK ? 0 : -1;
}

స్థిర పూర్ణాంకం
crossload_dir_అంతర్గత(నిర్మాణం sftp_conn *from, నిర్మాణం sftp_conn *గమ్యం,
    స్థిరరాశి అక్షరం *from_మార్గం, స్థిరరాశి అక్షరం *గమ్యం_మార్గం,
    పూర్ణాంకం లోతు, Attrib *dirattrib, పూర్ణాంకం preserve_flag, పూర్ణాంకం print_flag,
    పూర్ణాంకం follow_link_flag)
{
	పూర్ణాంకం i, ret = 0, created = 0;
	SFTP_DIRENT **dir_entries;
	అక్షరం *filename, *new_from_మార్గం = ఖాళీ, *new_గమ్యం_మార్గం = ఖాళీ;
	బహుళకం_t బహుళకం = 0777;
	Attrib *a, curdir, ldirattrib, newdir, lsym;

	debug2_f("crossload dir src \"%s\" to dst \"%s\"", from_మార్గం, గమ్యం_మార్గం);

	ఒకవేళ (లోతు >= MAX_DIR_లోతు) {
		error("Maximum directory depth exceeded: %d levels", లోతు);
		తిరిగి -1;
	}

	ఒకవేళ (dirattrib == ఖాళీ) {
		ఒకవేళ (sftp_stat(from, from_మార్గం, 1, &ldirattrib) != 0) {
			error("stat remote \"%s\" failed", from_మార్గం);
			తిరిగి -1;
		}
		dirattrib = &ldirattrib;
	}
	ఒకవేళ (!S_ISDIR(dirattrib->perm)) {
		error("\"%s\" is not a directory", from_మార్గం);
		తిరిగి -1;
	}
	ఒకవేళ (print_flag && print_flag != SFTP_పురోగతి_ONLY)
		mprintf("Retrieving %s\n", from_మార్గం);

	curdir = *dirattrib; /* dirattrib will be clobbered */
	curdir.flags &= ~SSH2_FILEXFER_ATTR_కొలత;
	curdir.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	ఒకవేళ ((curdir.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) == 0) {
		debug("Origin did not send permissions for "
		    "directory \"%s\"", గమ్యం_మార్గం);
		curdir.perm = S_IWUSR|S_IXUSR;
		curdir.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
	}
	/* We need to be able to write to the directory while we transfer it */
	బహుళకం = curdir.perm & 01777;
	curdir.perm = బహుళకం | (S_IWUSR|S_IXUSR);

	/*
	 * sftp lacks a portable status value to match errno EEXIST,
	 * so if we get a failure back then we must check whether
	 * the path already existed and is a directory.  Ensure we can
	 * write to the directory we create for the duration of the transfer.
	 */
	ఒకవేళ (sftp_mkdir(గమ్యం, గమ్యం_మార్గం, &curdir, 0) == 0)
		created = 1;
	లేకపోతే {
		ఒకవేళ (sftp_stat(గమ్యం, గమ్యం_మార్గం, 0, &newdir) != 0)
			తిరిగి -1;
		ఒకవేళ (!S_ISDIR(newdir.perm)) {
			error("\"%s\" exists but is not a directory", గమ్యం_మార్గం);
			తిరిగి -1;
		}
	}
	curdir.perm = బహుళకం;

	ఒకవేళ (sftp_readdir(from, from_మార్గం, &dir_entries) == -1) {
		error("origin readdir \"%s\" failed", from_మార్గం);
		తిరిగి -1;
	}

	కొరకు (i = 0; dir_entries[i] != ఖాళీ && !interrupted; i++) {
		విడుదల(new_from_మార్గం);
		విడుదల(new_గమ్యం_మార్గం);

		filename = dir_entries[i]->filename;
		new_from_మార్గం = sftp_మార్గం_append(from_మార్గం, filename);
		new_గమ్యం_మార్గం = sftp_మార్గం_append(గమ్యం_మార్గం, filename);

		a = &dir_entries[i]->a;
		ఒకవేళ (S_ISLNK(a->perm)) {
			ఒకవేళ (!follow_link_flag) {
				logit("%s: not a regular file", filename);
				కొనసాగు;
			}
			/* Replace the stat contents with the symlink target */
			ఒకవేళ (sftp_stat(from, new_from_మార్గం, 1, &lsym) != 0) {
				logit("remote stat \"%s\" failed",
				    new_from_మార్గం);
				ret = -1;
				కొనసాగు;
			}
			a = &lsym;
		}
		ఒకవేళ (S_ISDIR(a->perm)) {
			ఒకవేళ (strcmp(filename, ".") == 0 ||
			    strcmp(filename, "..") == 0)
				కొనసాగు;
			ఒకవేళ (crossload_dir_అంతర్గత(from, గమ్యం,
			    new_from_మార్గం, new_గమ్యం_మార్గం,
			    లోతు + 1, a, preserve_flag,
			    print_flag, follow_link_flag) == -1)
				ret = -1;
		} లేకపోతే ఒకవేళ (S_ISREG(a->perm)) {
			ఒకవేళ (sftp_crossload(from, గమ్యం, new_from_మార్గం,
			    new_గమ్యం_మార్గం, a, preserve_flag) == -1) {
				error("crossload \"%s\" to \"%s\" failed",
				    new_from_మార్గం, new_గమ్యం_మార్గం);
				ret = -1;
			}
		} లేకపోతే {
			logit("origin \"%s\": not a regular file",
			    new_from_మార్గం);
		}
	}
	విడుదల(new_గమ్యం_మార్గం);
	విడుదల(new_from_మార్గం);

	ఒకవేళ (created || preserve_flag)
		sftp_setstat(గమ్యం, గమ్యం_మార్గం, &curdir);

	sftp_free_dirents(dir_entries);

	తిరిగి ret;
}

పూర్ణాంకం
sftp_crossload_dir(నిర్మాణం sftp_conn *from, నిర్మాణం sftp_conn *గమ్యం,
    స్థిరరాశి అక్షరం *from_మార్గం, స్థిరరాశి అక్షరం *గమ్యం_మార్గం,
    Attrib *dirattrib, పూర్ణాంకం preserve_flag, పూర్ణాంకం print_flag, పూర్ణాంకం follow_link_flag)
{
	అక్షరం *from_మార్గం_canon;
	పూర్ణాంకం ret;

	ఒకవేళ ((from_మార్గం_canon = sftp_realpath(from, from_మార్గం)) == ఖాళీ) {
		error("crossload \"%s\": path canonicalization failed",
		    from_మార్గం);
		తిరిగి -1;
	}

	ret = crossload_dir_అంతర్గత(from, గమ్యం, from_మార్గం_canon, గమ్యం_మార్గం, 0,
	    dirattrib, preserve_flag, print_flag, follow_link_flag);
	విడుదల(from_మార్గం_canon);
	తిరిగి ret;
}

పూర్ణాంకం
sftp_can_get_users_groups_by_id(నిర్మాణం sftp_conn *conn)
{
	తిరిగి (conn->exts & SFTP_EXT_GETUSERSGROUPS_BY_ID) != 0;
}

పూర్ణాంకం
sftp_get_users_groups_by_id(నిర్మాణం sftp_conn *conn,
    స్థిరరాశి u_int *uids, u_int nuids,
    స్థిరరాశి u_int *gids, u_int ngids,
    అక్షరం ***usernamesp, అక్షరం ***groupnamesp)
{
	నిర్మాణం sshbuf *సందేశం, *uidbuf, *gidbuf;
	u_int i, expected_id, id;
	అక్షరం *name, **usernames = ఖాళీ, **groupnames = ఖాళీ;
	u_char type;
	పూర్ణాంకం r;

	*usernamesp = *groupnamesp = ఖాళీ;
	ఒకవేళ (!sftp_can_get_users_groups_by_id(conn))
		తిరిగి SSH_ERR_FEATURE_UNSUPPORTED;

	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ ||
	    (uidbuf = sshbuf_new()) == ఖాళీ ||
	    (gidbuf = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	expected_id = id = conn->సందేశం_id++;
	debug2("Sending SSH2_FXP_EXTENDED(users-groups-by-id@openssh.com)");
	కొరకు (i = 0; i < nuids; i++) {
		ఒకవేళ ((r = sshbuf_put_u32(uidbuf, uids[i])) != 0)
			fatal_fr(r, "compose uids");
	}
	కొరకు (i = 0; i < ngids; i++) {
		ఒకవేళ ((r = sshbuf_put_u32(gidbuf, gids[i])) != 0)
			fatal_fr(r, "compose gids");
	}
	ఒకవేళ ((r = sshbuf_put_u8(సందేశం, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(సందేశం, id)) != 0 ||
	    (r = sshbuf_put_cstring(సందేశం,
	    "users-groups-by-id@openssh.com")) != 0 ||
	    (r = sshbuf_put_stringb(సందేశం, uidbuf)) != 0 ||
	    (r = sshbuf_put_stringb(సందేశం, gidbuf)) != 0)
		fatal_fr(r, "compose");
	send_సందేశం(conn, సందేశం);
	get_సందేశం(conn, సందేశం);
	ఒకవేళ ((r = sshbuf_get_u8(సందేశం, &type)) != 0 ||
	    (r = sshbuf_get_u32(సందేశం, &id)) != 0)
		fatal_fr(r, "parse");
	ఒకవేళ (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	ఒకవేళ (type == SSH2_FXP_స్థితి) {
		u_int స్థితి_2;
		అక్షరం *errmsg;

		ఒకవేళ ((r = sshbuf_get_u32(సందేశం, &స్థితి_2)) != 0 ||
		    (r = sshbuf_get_cstring(సందేశం, &errmsg, ఖాళీ)) != 0)
			fatal_fr(r, "parse status");
		error("users-groups-by-id %s",
		    *errmsg == '\0' ? fx2txt(స్థితి_2) : errmsg);
		విడుదల(errmsg);
		sshbuf_free(సందేశం);
		sshbuf_free(uidbuf);
		sshbuf_free(gidbuf);
		తిరిగి -1;
	} లేకపోతే ఒకవేళ (type != SSH2_FXP_EXTENDED_జవాబు)
		fatal("Expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_జవాబు, type);

	/* reuse */
	sshbuf_free(uidbuf);
	sshbuf_free(gidbuf);
	uidbuf = gidbuf = ఖాళీ;
	ఒకవేళ ((r = sshbuf_froms(సందేశం, &uidbuf)) != 0 ||
	    (r = sshbuf_froms(సందేశం, &gidbuf)) != 0)
		fatal_fr(r, "parse response");
	ఒకవేళ (nuids > 0) {
		usernames = xcalloc(nuids, పరిమాణం(*usernames));
		కొరకు (i = 0; i < nuids; i++) {
			ఒకవేళ ((r = sshbuf_get_cstring(uidbuf, &name, ఖాళీ)) != 0)
				fatal_fr(r, "parse user name");
			/* Handle unresolved names */
			ఒకవేళ (*name == '\0') {
				విడుదల(name);
				name = ఖాళీ;
			}
			usernames[i] = name;
		}
	}
	ఒకవేళ (ngids > 0) {
		groupnames = xcalloc(ngids, పరిమాణం(*groupnames));
		కొరకు (i = 0; i < ngids; i++) {
			ఒకవేళ ((r = sshbuf_get_cstring(gidbuf, &name, ఖాళీ)) != 0)
				fatal_fr(r, "parse user name");
			/* Handle unresolved names */
			ఒకవేళ (*name == '\0') {
				విడుదల(name);
				name = ఖాళీ;
			}
			groupnames[i] = name;
		}
	}
	ఒకవేళ (sshbuf_len(uidbuf) != 0)
		fatal_f("unexpected extra username data");
	ఒకవేళ (sshbuf_len(gidbuf) != 0)
		fatal_f("unexpected extra groupname data");
	sshbuf_free(uidbuf);
	sshbuf_free(gidbuf);
	sshbuf_free(సందేశం);
	/* success */
	*usernamesp = usernames;
	*groupnamesp = groupnames;
	తిరిగి 0;
}

అక్షరం *
sftp_మార్గం_append(స్థిరరాశి అక్షరం *p1, స్థిరరాశి అక్షరం *p2)
{
	అక్షరం *ret;
	కొలత_t len = అక్షరశ్రేణి_పొడవు(p1) + అక్షరశ్రేణి_పొడవు(p2) + 2;

	ret = xmalloc(len);
	strlcpy(ret, p1, len);
	ఒకవేళ (p1[0] != '\0' && p1[అక్షరశ్రేణి_పొడవు(p1) - 1] != '/')
		strlcat(ret, "/", len);
	strlcat(ret, p2, len);

	తిరిగి(ret);
}

/*
 * Arg p must be dynamically allocated.  It will either be returned or
 * freed and a replacement allocated.  Caller must free returned string.
 */
అక్షరం *
sftp_make_absolute(అక్షరం *p, స్థిరరాశి అక్షరం *pwd)
{
	అక్షరం *abs_str;

	/* Derelativise */
	ఒకవేళ (p && !మార్గం_absolute(p)) {
		abs_str = sftp_మార్గం_append(pwd, p);
		విడుదల(p);
		తిరిగి(abs_str);
	} లేకపోతే
		తిరిగి(p);
}

పూర్ణాంకం
sftp_remote_is_dir(నిర్మాణం sftp_conn *conn, స్థిరరాశి అక్షరం *మార్గం)
{
	Attrib a;

	/* XXX: report errors? */
	ఒకవేళ (sftp_stat(conn, మార్గం, 1, &a) != 0)
		తిరిగి(0);
	ఒకవేళ (!(a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS))
		తిరిగి(0);
	తిరిగి S_ISDIR(a.perm);
}


/* Check whether path returned from glob(..., GLOB_MARK, ...) is a directory */
పూర్ణాంకం
sftp_globpath_is_dir(స్థిరరాశి అక్షరం *pathname)
{
	కొలత_t l = అక్షరశ్రేణి_పొడవు(pathname);

	తిరిగి l > 0 && pathname[l - 1] == '/';
}

