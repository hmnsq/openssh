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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/queue.h>
#अन्तर्भाव <sys/stat.h>
#अन्तर्भाव <sys/time.h>
#अन्तर्भाव <sys/statvfs.h>
#अन्तर्भाव <sys/uio.h>

#अन्तर्भाव <dirent.h>
#अन्तर्भाव <errno.h>
#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <poll.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "atomicio.h"
#अन्तर्भाव "progressmeter.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "utf8.h"

#अन्तर्भाव "sftp.h"
#अन्तर्भाव "sftp-common.h"
#अन्तर्भाव "sftp-client.h"

बाह्य चञ्चल sig_atomic_t interrupted;
बाह्य पूर्णाङ्क showprogress;

/* Default size of buffer for up/download (fix sftp.1 scp.1 if changed) */
#परिभाषय DEFAULT_COPY_BUFLEN	32768

/* Default number of concurrent xfer requests (fix sftp.1 scp.1 if changed) */
#परिभाषय DEFAULT_अङ्कः_अनुरोधाः	64

/* Minimum amount of data to read at a time */
#परिभाषय MIN_READ_आकार	512

/* Maximum depth to descend in directory trees */
#परिभाषय MAX_DIR_गभीरता 64

/* Directory separator characters */
#यदि_परिभाषितम् HAVE_CYGWIN
# define SFTP_DIRECTORY_CHARS      "/\\"
#अन्यथा /* HAVE_CYGWIN */
# define SFTP_DIRECTORY_CHARS      "/"
#यदि_अन्तः /* HAVE_CYGWIN */

संरचना sftp_conn {
	पूर्णाङ्क fd_अन्तर्;
	पूर्णाङ्क fd_बहिर्गमनम्;
	u_int download_buflen;
	u_int upload_buflen;
	u_int अङ्कः_अनुरोधाः;
	u_int संस्करणम्;
	u_int सन्देशः_id;
#परिभाषय SFTP_EXT_POSIX_RENAME		0x00000001
#परिभाषय SFTP_EXT_STATVFS		0x00000002
#परिभाषय SFTP_EXT_FSTATVFS		0x00000004
#परिभाषय SFTP_EXT_HARDLINK		0x00000008
#परिभाषय SFTP_EXT_FSYNC			0x00000010
#परिभाषय SFTP_EXT_LSETSTAT		0x00000020
#परिभाषय SFTP_EXT_LIMITS			0x00000040
#परिभाषय SFTP_EXT_मार्गः_EXPAND		0x00000080
#परिभाषय SFTP_EXT_COPY_दत्त		0x00000100
#परिभाषय SFTP_EXT_GETUSERSGROUPS_BY_ID	0x00000200
	u_int exts;
	uint64_t सीमा_kbps;
	संरचना bwlimit bwlimit_अन्तर्, bwlimit_बहिर्गमनम्;
};

/* Tracks in-progress requests during file transfers */
संरचना request {
	u_int id;
	आकार_t len;
	uint64_t विस्थापनम्;
	TAILQ_ENTRY(request) tq;
};
TAILQ_HEAD(अनुरोधाः, request);

स्थिर u_char *
get_handle(संरचना sftp_conn *conn, u_int expected_id, आकार_t *len,
    ध्रुव वर्ण *errfmt, ...) __attribute__((format(प्रारूप_लिख, 4, 5)));

स्थिर संरचना request *
request_पङ्क्तौ_निक्षिप(संरचना अनुरोधाः *अनुरोधाः, u_int id, आकार_t len,
    uint64_t विस्थापनम्)
{
	संरचना request *req;

	req = xcalloc(1, परिमाण(*req));
	req->id = id;
	req->len = len;
	req->विस्थापनम् = विस्थापनम्;
	TAILQ_INSERT_TAIL(अनुरोधाः, req, tq);
	प्रत्यागम req;
}

स्थिर संरचना request *
request_find(संरचना अनुरोधाः *अनुरोधाः, u_int id)
{
	संरचना request *req;

	प्रति (req = TAILQ_FIRST(अनुरोधाः);
	    req != रिक्त && req->id != id;
	    req = TAILQ_NEXT(req, tq))
		;
	प्रत्यागम req;
}

स्थिर पूर्णाङ्क
sftpio(शून्य *_bwlimit, आकार_t amount)
{
	संरचना bwlimit *bwlimit = (संरचना bwlimit *)_bwlimit;

	refresh_प्रगतिः_meter(0);
	यदि (bwlimit != रिक्त)
		bandwidth_सीमा(bwlimit, amount);
	प्रत्यागम 0;
}

स्थिर शून्य
send_सन्देशः(संरचना sftp_conn *conn, संरचना sshbuf *m)
{
	u_char mlen[4];
	संरचना iovec iov[2];

	यदि (sshbuf_len(m) > SFTP_MAX_सन्देशः_दीर्घता)
		fatal("Outbound message too long %zu", sshbuf_len(m));

	/* Send length first */
	put_u32(mlen, sshbuf_len(m));
	iov[0].iov_base = mlen;
	iov[0].iov_len = परिमाण(mlen);
	iov[1].iov_base = (u_char *)sshbuf_ptr(m);
	iov[1].iov_len = sshbuf_len(m);

	यदि (atomiciov6(writev, conn->fd_बहिर्गमनम्, iov, 2, sftpio,
	    conn->सीमा_kbps > 0 ? &conn->bwlimit_बहिर्गमनम् : रिक्त) !=
	    sshbuf_len(m) + परिमाण(mlen))
		fatal("Couldn't send packet: %s", strerror(errno));

	sshbuf_reset(m);
}

स्थिर शून्य
get_सन्देशः_extended(संरचना sftp_conn *conn, संरचना sshbuf *m, पूर्णाङ्क initial)
{
	u_int सन्देशः_len;
	u_char *p;
	पूर्णाङ्क r;

	sshbuf_reset(m);
	यदि ((r = sshbuf_reserve(m, 4, &p)) != 0)
		fatal_fr(r, "reserve");
	यदि (atomicio6(पठ, conn->fd_अन्तर्, p, 4, sftpio,
	    conn->सीमा_kbps > 0 ? &conn->bwlimit_अन्तर् : रिक्त) != 4) {
		यदि (errno == EPIPE || errno == ECONNRESET)
			fatal("Connection closed");
		अन्यथा
			fatal("Couldn't read packet: %s", strerror(errno));
	}

	यदि ((r = sshbuf_get_u32(m, &सन्देशः_len)) != 0)
		fatal_fr(r, "sshbuf_get_u32");
	यदि (सन्देशः_len > SFTP_MAX_सन्देशः_दीर्घता) {
		do_log2(initial ? SYSLOG_LEVEL_ERROR : SYSLOG_LEVEL_FATAL,
		    "Received message too long %u", सन्देशः_len);
		fatal("Ensure the remote shell produces no output "
		    "for non-interactive sessions.");
	}

	यदि ((r = sshbuf_reserve(m, सन्देशः_len, &p)) != 0)
		fatal_fr(r, "reserve");
	यदि (atomicio6(पठ, conn->fd_अन्तर्, p, सन्देशः_len, sftpio,
	    conn->सीमा_kbps > 0 ? &conn->bwlimit_अन्तर् : रिक्त)
	    != सन्देशः_len) {
		यदि (errno == EPIPE)
			fatal("Connection closed");
		अन्यथा
			fatal("Read packet: %s", strerror(errno));
	}
}

स्थिर शून्य
get_सन्देशः(संरचना sftp_conn *conn, संरचना sshbuf *m)
{
	get_सन्देशः_extended(conn, m, 0);
}

स्थिर शून्य
send_string_request(संरचना sftp_conn *conn, u_int id, u_int संहिता, ध्रुव वर्ण *s,
    u_int len)
{
	संरचना sshbuf *सन्देशः;
	पूर्णाङ्क r;

	यदि ((सन्देशः = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshbuf_put_u8(सन्देशः, संहिता)) != 0 ||
	    (r = sshbuf_put_u32(सन्देशः, id)) != 0 ||
	    (r = sshbuf_put_string(सन्देशः, s, len)) != 0)
		fatal_fr(r, "compose");
	send_सन्देशः(conn, सन्देशः);
	debug3("Sent message fd %d T:%u I:%u", conn->fd_बहिर्गमनम्, संहिता, id);
	sshbuf_free(सन्देशः);
}

स्थिर शून्य
send_string_attrs_request(संरचना sftp_conn *conn, u_int id, u_int संहिता,
    ध्रुव शून्य *s, u_int len, Attrib *a)
{
	संरचना sshbuf *सन्देशः;
	पूर्णाङ्क r;

	यदि ((सन्देशः = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshbuf_put_u8(सन्देशः, संहिता)) != 0 ||
	    (r = sshbuf_put_u32(सन्देशः, id)) != 0 ||
	    (r = sshbuf_put_string(सन्देशः, s, len)) != 0 ||
	    (r = encode_attrib(सन्देशः, a)) != 0)
		fatal_fr(r, "compose");
	send_सन्देशः(conn, सन्देशः);
	debug3("Sent message fd %d T:%u I:%u F:0x%04x M:%05o",
	    conn->fd_बहिर्गमनम्, संहिता, id, a->flags, a->perm);
	sshbuf_free(सन्देशः);
}

स्थिर u_int
get_स्थितिः(संरचना sftp_conn *conn, u_int expected_id)
{
	संरचना sshbuf *सन्देशः;
	u_char type;
	u_int id, स्थितिः;
	पूर्णाङ्क r;

	यदि ((सन्देशः = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	get_सन्देशः(conn, सन्देशः);
	यदि ((r = sshbuf_get_u8(सन्देशः, &type)) != 0 ||
	    (r = sshbuf_get_u32(सन्देशः, &id)) != 0)
		fatal_fr(r, "compose");

	यदि (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	यदि (type != SSH2_FXP_स्थितिः)
		fatal("Expected SSH2_FXP_STATUS(%u) packet, got %u",
		    SSH2_FXP_स्थितिः, type);

	यदि ((r = sshbuf_get_u32(सन्देशः, &स्थितिः)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(सन्देशः);

	debug3("SSH2_FXP_STATUS %u", स्थितिः);

	प्रत्यागम स्थितिः;
}

स्थिर u_char *
get_handle(संरचना sftp_conn *conn, u_int expected_id, आकार_t *len,
    ध्रुव वर्ण *errfmt, ...)
{
	संरचना sshbuf *सन्देशः;
	u_int id, स्थितिः;
	u_char type;
	u_char *handle;
	वर्ण errmsg[256];
	va_list तर्काः;
	पूर्णाङ्क r;

	va_start(तर्काः, errfmt);
	यदि (errfmt != रिक्त)
		vsnprintf(errmsg, परिमाण(errmsg), errfmt, तर्काः);
	va_end(तर्काः);

	यदि ((सन्देशः = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	get_सन्देशः(conn, सन्देशः);
	यदि ((r = sshbuf_get_u8(सन्देशः, &type)) != 0 ||
	    (r = sshbuf_get_u32(सन्देशः, &id)) != 0)
		fatal_fr(r, "parse");

	यदि (id != expected_id)
		fatal("%s: ID mismatch (%u != %u)",
		    errfmt == रिक्त ? __func__ : errmsg, id, expected_id);
	यदि (type == SSH2_FXP_स्थितिः) {
		यदि ((r = sshbuf_get_u32(सन्देशः, &स्थितिः)) != 0)
			fatal_fr(r, "parse status");
		यदि (errfmt != रिक्त)
			error("%s: %s", errmsg, fx2txt(स्थितिः));
		sshbuf_free(सन्देशः);
		प्रत्यागम(रिक्त);
	} अन्यथा यदि (type != SSH2_FXP_HANDLE)
		fatal("%s: Expected SSH2_FXP_HANDLE(%u) packet, got %u",
		    errfmt == रिक्त ? __func__ : errmsg, SSH2_FXP_HANDLE, type);

	यदि ((r = sshbuf_get_string(सन्देशः, &handle, len)) != 0)
		fatal_fr(r, "parse handle");
	sshbuf_free(सन्देशः);

	प्रत्यागम handle;
}

स्थिर पूर्णाङ्क
get_decode_stat(संरचना sftp_conn *conn, u_int expected_id, पूर्णाङ्क quiet, Attrib *a)
{
	संरचना sshbuf *सन्देशः;
	u_int id;
	u_char type;
	पूर्णाङ्क r;
	Attrib attr;

	यदि (a != रिक्त)
		स्मृतिं_पूरय(a, '\0', परिमाण(*a));
	यदि ((सन्देशः = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	get_सन्देशः(conn, सन्देशः);

	यदि ((r = sshbuf_get_u8(सन्देशः, &type)) != 0 ||
	    (r = sshbuf_get_u32(सन्देशः, &id)) != 0)
		fatal_fr(r, "parse");

	यदि (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	यदि (type == SSH2_FXP_स्थितिः) {
		u_int स्थितिः;

		यदि ((r = sshbuf_get_u32(सन्देशः, &स्थितिः)) != 0)
			fatal_fr(r, "parse status");
		यदि (quiet)
			debug("stat remote: %s", fx2txt(स्थितिः));
		अन्यथा
			error("stat remote: %s", fx2txt(स्थितिः));
		sshbuf_free(सन्देशः);
		प्रत्यागम -1;
	} अन्यथा यदि (type != SSH2_FXP_ATTRS) {
		fatal("Expected SSH2_FXP_ATTRS(%u) packet, got %u",
		    SSH2_FXP_ATTRS, type);
	}
	यदि ((r = decode_attrib(सन्देशः, &attr)) != 0) {
		error_fr(r, "decode_attrib");
		sshbuf_free(सन्देशः);
		प्रत्यागम -1;
	}
	/* success */
	यदि (a != रिक्त)
		*a = attr;
	debug3("Received stat reply T:%u I:%u F:0x%04x M:%05o",
	    type, id, attr.flags, attr.perm);
	sshbuf_free(सन्देशः);

	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
get_decode_statvfs(संरचना sftp_conn *conn, संरचना sftp_statvfs *st,
    u_int expected_id, पूर्णाङ्क quiet)
{
	संरचना sshbuf *सन्देशः;
	u_char type;
	u_int id;
	uint64_t flag;
	पूर्णाङ्क r;

	यदि ((सन्देशः = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	get_सन्देशः(conn, सन्देशः);

	यदि ((r = sshbuf_get_u8(सन्देशः, &type)) != 0 ||
	    (r = sshbuf_get_u32(सन्देशः, &id)) != 0)
		fatal_fr(r, "parse");

	debug3("Received statvfs reply T:%u I:%u", type, id);
	यदि (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	यदि (type == SSH2_FXP_स्थितिः) {
		u_int स्थितिः;

		यदि ((r = sshbuf_get_u32(सन्देशः, &स्थितिः)) != 0)
			fatal_fr(r, "parse status");
		यदि (quiet)
			debug("remote statvfs: %s", fx2txt(स्थितिः));
		अन्यथा
			error("remote statvfs: %s", fx2txt(स्थितिः));
		sshbuf_free(सन्देशः);
		प्रत्यागम -1;
	} अन्यथा यदि (type != SSH2_FXP_EXTENDED_प्रत्युत्तरम्) {
		fatal("Expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_प्रत्युत्तरम्, type);
	}

	स्मृतिं_पूरय(st, 0, परिमाण(*st));
	यदि ((r = sshbuf_get_u64(सन्देशः, &st->f_bsize)) != 0 ||
	    (r = sshbuf_get_u64(सन्देशः, &st->f_frsize)) != 0 ||
	    (r = sshbuf_get_u64(सन्देशः, &st->f_खण्डानि)) != 0 ||
	    (r = sshbuf_get_u64(सन्देशः, &st->f_bfree)) != 0 ||
	    (r = sshbuf_get_u64(सन्देशः, &st->f_bavail)) != 0 ||
	    (r = sshbuf_get_u64(सन्देशः, &st->f_files)) != 0 ||
	    (r = sshbuf_get_u64(सन्देशः, &st->f_ffree)) != 0 ||
	    (r = sshbuf_get_u64(सन्देशः, &st->f_favail)) != 0 ||
	    (r = sshbuf_get_u64(सन्देशः, &st->f_fsid)) != 0 ||
	    (r = sshbuf_get_u64(सन्देशः, &flag)) != 0 ||
	    (r = sshbuf_get_u64(सन्देशः, &st->f_namemax)) != 0)
		fatal_fr(r, "parse statvfs");

	st->f_flag = (flag & SSH2_FXE_STATVFS_ST_RDONLY) ? ST_RDONLY : 0;
	st->f_flag |= (flag & SSH2_FXE_STATVFS_ST_NOSUID) ? ST_NOSUID : 0;

	sshbuf_free(सन्देशः);

	प्रत्यागम 0;
}

संरचना sftp_conn *
sftp_init(पूर्णाङ्क fd_अन्तर्, पूर्णाङ्क fd_बहिर्गमनम्, u_int transfer_buflen, u_int अङ्कः_अनुरोधाः,
    uint64_t सीमा_kbps)
{
	u_char type;
	संरचना sshbuf *सन्देशः;
	संरचना sftp_conn *ret;
	पूर्णाङ्क r;

	ret = xcalloc(1, परिमाण(*ret));
	ret->सन्देशः_id = 1;
	ret->fd_अन्तर् = fd_अन्तर्;
	ret->fd_बहिर्गमनम् = fd_बहिर्गमनम्;
	ret->download_buflen = ret->upload_buflen =
	    transfer_buflen ? transfer_buflen : DEFAULT_COPY_BUFLEN;
	ret->अङ्कः_अनुरोधाः =
	    अङ्कः_अनुरोधाः ? अङ्कः_अनुरोधाः : DEFAULT_अङ्कः_अनुरोधाः;
	ret->exts = 0;
	ret->सीमा_kbps = 0;

	यदि ((सन्देशः = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshbuf_put_u8(सन्देशः, SSH2_FXP_INIT)) != 0 ||
	    (r = sshbuf_put_u32(सन्देशः, SSH2_FILEXFER_संस्करणम्)) != 0)
		fatal_fr(r, "parse");

	send_सन्देशः(ret, सन्देशः);

	get_सन्देशः_extended(ret, सन्देशः, 1);

	/* Expecting a VERSION reply */
	यदि ((r = sshbuf_get_u8(सन्देशः, &type)) != 0)
		fatal_fr(r, "parse type");
	यदि (type != SSH2_FXP_संस्करणम्) {
		error("Invalid packet back from SSH2_FXP_INIT (type %u)",
		    type);
		sshbuf_free(सन्देशः);
		मुक्त(ret);
		प्रत्यागम(रिक्त);
	}
	यदि ((r = sshbuf_get_u32(सन्देशः, &ret->संस्करणम्)) != 0)
		fatal_fr(r, "parse version");

	debug2("Remote version: %u", ret->संस्करणम्);

	/* Check for extensions */
	यावत् (sshbuf_len(सन्देशः) > 0) {
		वर्ण *name;
		u_char *मानम्;
		आकार_t vlen;
		पूर्णाङ्क ज्ञातम् = 0;

		यदि ((r = sshbuf_get_cstring(सन्देशः, &name, रिक्त)) != 0 ||
		    (r = sshbuf_get_string(सन्देशः, &मानम्, &vlen)) != 0)
			fatal_fr(r, "parse extension");
		यदि (वाक्यं_तुलय(name, "posix-rename@openssh.com") == 0 &&
		    वाक्यं_तुलय((वर्ण *)मानम्, "1") == 0) {
			ret->exts |= SFTP_EXT_POSIX_RENAME;
			ज्ञातम् = 1;
		} अन्यथा यदि (वाक्यं_तुलय(name, "statvfs@openssh.com") == 0 &&
		    वाक्यं_तुलय((वर्ण *)मानम्, "2") == 0) {
			ret->exts |= SFTP_EXT_STATVFS;
			ज्ञातम् = 1;
		} अन्यथा यदि (वाक्यं_तुलय(name, "fstatvfs@openssh.com") == 0 &&
		    वाक्यं_तुलय((वर्ण *)मानम्, "2") == 0) {
			ret->exts |= SFTP_EXT_FSTATVFS;
			ज्ञातम् = 1;
		} अन्यथा यदि (वाक्यं_तुलय(name, "hardlink@openssh.com") == 0 &&
		    वाक्यं_तुलय((वर्ण *)मानम्, "1") == 0) {
			ret->exts |= SFTP_EXT_HARDLINK;
			ज्ञातम् = 1;
		} अन्यथा यदि (वाक्यं_तुलय(name, "fsync@openssh.com") == 0 &&
		    वाक्यं_तुलय((वर्ण *)मानम्, "1") == 0) {
			ret->exts |= SFTP_EXT_FSYNC;
			ज्ञातम् = 1;
		} अन्यथा यदि (वाक्यं_तुलय(name, "lsetstat@openssh.com") == 0 &&
		    वाक्यं_तुलय((वर्ण *)मानम्, "1") == 0) {
			ret->exts |= SFTP_EXT_LSETSTAT;
			ज्ञातम् = 1;
		} अन्यथा यदि (वाक्यं_तुलय(name, "limits@openssh.com") == 0 &&
		    वाक्यं_तुलय((वर्ण *)मानम्, "1") == 0) {
			ret->exts |= SFTP_EXT_LIMITS;
			ज्ञातम् = 1;
		} अन्यथा यदि (वाक्यं_तुलय(name, "expand-path@openssh.com") == 0 &&
		    वाक्यं_तुलय((वर्ण *)मानम्, "1") == 0) {
			ret->exts |= SFTP_EXT_मार्गः_EXPAND;
			ज्ञातम् = 1;
		} अन्यथा यदि (वाक्यं_तुलय(name, "copy-data") == 0 &&
		    वाक्यं_तुलय((वर्ण *)मानम्, "1") == 0) {
			ret->exts |= SFTP_EXT_COPY_दत्त;
			ज्ञातम् = 1;
		} अन्यथा यदि (वाक्यं_तुलय(name,
		    "users-groups-by-id@openssh.com") == 0 &&
		    वाक्यं_तुलय((वर्ण *)मानम्, "1") == 0) {
			ret->exts |= SFTP_EXT_GETUSERSGROUPS_BY_ID;
			ज्ञातम् = 1;
		}
		यदि (ज्ञातम्) {
			debug2("Server supports extension \"%s\" revision %s",
			    name, मानम्);
		} अन्यथा {
			debug2("Unrecognised server extension \"%s\"", name);
		}
		मुक्त(name);
		मुक्त(मानम्);
	}

	sshbuf_free(सन्देशः);

	/* Query the server for its limits */
	यदि (ret->exts & SFTP_EXT_LIMITS) {
		संरचना sftp_limits limits;
		यदि (sftp_get_limits(ret, &limits) != 0)
			fatal_f("limits failed");

		/* If the caller did not specify, find a good value */
		यदि (transfer_buflen == 0) {
			ret->download_buflen = MINIMUM(limits.read_दीर्घता,
			    SFTP_MAX_सन्देशः_दीर्घता - 1024);
			ret->upload_buflen = MINIMUM(limits.write_दीर्घता,
			    SFTP_MAX_सन्देशः_दीर्घता - 1024);
			ret->download_buflen = अधिकतमम्(ret->download_buflen, 64);
			ret->upload_buflen = अधिकतमम्(ret->upload_buflen, 64);
			debug3("server upload/download buffer sizes "
			    "%llu / %llu; using %u / %u",
			    (अचिह्नित दीर्घ दीर्घ)limits.write_दीर्घता,
			    (अचिह्नित दीर्घ दीर्घ)limits.read_दीर्घता,
			    ret->upload_buflen, ret->download_buflen);
		}
	}

	/* Some filexfer v.0 servers don't support large packets */
	यदि (ret->संस्करणम् == 0) {
		ret->download_buflen = MINIMUM(ret->download_buflen, 20480);
		ret->upload_buflen = MINIMUM(ret->upload_buflen, 20480);
	}

	ret->सीमा_kbps = सीमा_kbps;
	यदि (ret->सीमा_kbps > 0) {
		bandwidth_सीमा_init(&ret->bwlimit_अन्तर्, ret->सीमा_kbps,
		    ret->download_buflen);
		bandwidth_सीमा_init(&ret->bwlimit_बहिर्गमनम्, ret->सीमा_kbps,
		    ret->upload_buflen);
	}

	प्रत्यागम ret;
}

शून्य
sftp_free(संरचना sftp_conn *conn)
{
	यदि (conn == रिक्त)
		प्रत्यागम;
	freezero(conn, परिमाण(*conn));
}

u_int
sftp_proto_संस्करणम्(संरचना sftp_conn *conn)
{
	प्रत्यागम conn->संस्करणम्;
}

पूर्णाङ्क
sftp_get_limits(संरचना sftp_conn *conn, संरचना sftp_limits *limits)
{
	u_int id, सन्देशः_id;
	u_char type;
	संरचना sshbuf *सन्देशः;
	पूर्णाङ्क r;

	यदि ((conn->exts & SFTP_EXT_LIMITS) == 0) {
		error("Server does not support limits@openssh.com extension");
		प्रत्यागम -1;
	}

	यदि ((सन्देशः = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");

	id = conn->सन्देशः_id++;
	यदि ((r = sshbuf_put_u8(सन्देशः, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(सन्देशः, id)) != 0 ||
	    (r = sshbuf_put_cstring(सन्देशः, "limits@openssh.com")) != 0)
		fatal_fr(r, "compose");
	send_सन्देशः(conn, सन्देशः);
	debug3("Sent message limits@openssh.com I:%u", id);

	get_सन्देशः(conn, सन्देशः);

	यदि ((r = sshbuf_get_u8(सन्देशः, &type)) != 0 ||
	    (r = sshbuf_get_u32(सन्देशः, &सन्देशः_id)) != 0)
		fatal_fr(r, "parse");

	debug3("Received limits reply T:%u I:%u", type, सन्देशः_id);
	यदि (id != सन्देशः_id)
		fatal("ID mismatch (%u != %u)", सन्देशः_id, id);
	यदि (type != SSH2_FXP_EXTENDED_प्रत्युत्तरम्) {
		debug_f("expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_प्रत्युत्तरम्, type);
		/* Disable the limits extension */
		conn->exts &= ~SFTP_EXT_LIMITS;
		sshbuf_free(सन्देशः);
		प्रत्यागम -1;
	}

	स्मृतिं_पूरय(limits, 0, परिमाण(*limits));
	यदि ((r = sshbuf_get_u64(सन्देशः, &limits->packet_दीर्घता)) != 0 ||
	    (r = sshbuf_get_u64(सन्देशः, &limits->read_दीर्घता)) != 0 ||
	    (r = sshbuf_get_u64(सन्देशः, &limits->write_दीर्घता)) != 0 ||
	    (r = sshbuf_get_u64(सन्देशः, &limits->open_handles)) != 0)
		fatal_fr(r, "parse limits");

	sshbuf_free(सन्देशः);

	प्रत्यागम 0;
}

पूर्णाङ्क
sftp_close(संरचना sftp_conn *conn, ध्रुव u_char *handle, u_int handle_len)
{
	u_int id, स्थितिः;
	संरचना sshbuf *सन्देशः;
	पूर्णाङ्क r;

	यदि ((सन्देशः = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");

	id = conn->सन्देशः_id++;
	यदि ((r = sshbuf_put_u8(सन्देशः, SSH2_FXP_CLOSE)) != 0 ||
	    (r = sshbuf_put_u32(सन्देशः, id)) != 0 ||
	    (r = sshbuf_put_string(सन्देशः, handle, handle_len)) != 0)
		fatal_fr(r, "parse");
	send_सन्देशः(conn, सन्देशः);
	debug3("Sent message SSH2_FXP_CLOSE I:%u", id);

	स्थितिः = get_स्थितिः(conn, id);
	यदि (स्थितिः != SSH2_FX_OK)
		error("close remote: %s", fx2txt(स्थितिः));

	sshbuf_free(सन्देशः);

	प्रत्यागम स्थितिः == SSH2_FX_OK ? 0 : -1;
}


स्थिर पूर्णाङ्क
sftp_lsreaddir(संरचना sftp_conn *conn, ध्रुव वर्ण *मार्गः, पूर्णाङ्क print_flag,
    SFTP_DIRENT ***dir)
{
	संरचना sshbuf *सन्देशः;
	u_int गणनम्, id, i, expected_id, ents = 0;
	आकार_t handle_len;
	u_char type, *handle;
	पूर्णाङ्क स्थितिः = SSH2_FX_FAILURE;
	पूर्णाङ्क r;

	यदि (dir)
		*dir = रिक्त;

	id = conn->सन्देशः_id++;

	यदि ((सन्देशः = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshbuf_put_u8(सन्देशः, SSH2_FXP_OPENDIR)) != 0 ||
	    (r = sshbuf_put_u32(सन्देशः, id)) != 0 ||
	    (r = sshbuf_put_cstring(सन्देशः, मार्गः)) != 0)
		fatal_fr(r, "compose OPENDIR");
	send_सन्देशः(conn, सन्देशः);

	handle = get_handle(conn, id, &handle_len,
	    "remote readdir(\"%s\")", मार्गः);
	यदि (handle == रिक्त) {
		sshbuf_free(सन्देशः);
		प्रत्यागम -1;
	}

	यदि (dir) {
		ents = 0;
		*dir = xcalloc(1, परिमाण(**dir));
		(*dir)[0] = रिक्त;
	}

	प्रति (; !interrupted;) {
		id = expected_id = conn->सन्देशः_id++;

		debug3("Sending SSH2_FXP_READDIR I:%u", id);

		sshbuf_reset(सन्देशः);
		यदि ((r = sshbuf_put_u8(सन्देशः, SSH2_FXP_READDIR)) != 0 ||
		    (r = sshbuf_put_u32(सन्देशः, id)) != 0 ||
		    (r = sshbuf_put_string(सन्देशः, handle, handle_len)) != 0)
			fatal_fr(r, "compose READDIR");
		send_सन्देशः(conn, सन्देशः);

		sshbuf_reset(सन्देशः);

		get_सन्देशः(conn, सन्देशः);

		यदि ((r = sshbuf_get_u8(सन्देशः, &type)) != 0 ||
		    (r = sshbuf_get_u32(सन्देशः, &id)) != 0)
			fatal_fr(r, "parse");

		debug3("Received reply T:%u I:%u", type, id);

		यदि (id != expected_id)
			fatal("ID mismatch (%u != %u)", id, expected_id);

		यदि (type == SSH2_FXP_स्थितिः) {
			u_int rstatus;

			यदि ((r = sshbuf_get_u32(सन्देशः, &rstatus)) != 0)
				fatal_fr(r, "parse status");
			debug3("Received SSH2_FXP_STATUS %d", rstatus);
			यदि (rstatus == SSH2_FX_EOF)
				भङ्ग;
			error("Couldn't read directory: %s", fx2txt(rstatus));
			गच्छ बहिर्गमनम्;
		} अन्यथा यदि (type != SSH2_FXP_NAME)
			fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
			    SSH2_FXP_NAME, type);

		यदि ((r = sshbuf_get_u32(सन्देशः, &गणनम्)) != 0)
			fatal_fr(r, "parse count");
		यदि (गणनम् > SSHBUF_आकार_MAX)
			fatal_f("nonsensical number of entries");
		यदि (गणनम् == 0)
			भङ्ग;
		debug3("Received %d SSH2_FXP_NAME responses", गणनम्);
		प्रति (i = 0; i < गणनम्; i++) {
			वर्ण *filename, *longname;
			Attrib a;

			यदि ((r = sshbuf_get_cstring(सन्देशः, &filename,
			    रिक्त)) != 0 ||
			    (r = sshbuf_get_cstring(सन्देशः, &longname,
			    रिक्त)) != 0)
				fatal_fr(r, "parse filenames");
			यदि ((r = decode_attrib(सन्देशः, &a)) != 0) {
				error_fr(r, "couldn't decode attrib");
				मुक्त(filename);
				मुक्त(longname);
				गच्छ बहिर्गमनम्;
			}

			यदि (print_flag)
				mprintf("%s\n", longname);

			/*
			 * Directory entries should never contain '/'
			 * These can be used to attack recursive ops
			 * (e.g. send '../../../../etc/passwd')
			 */
			यदि (*filename == '\0' ||
			    strpbrk(filename, SFTP_DIRECTORY_CHARS) != रिक्त) {
				error("Server sent suspect path \"%s\" "
				    "during readdir of \"%s\"", filename, मार्गः);
			} अन्यथा यदि (dir) {
				*dir = xreallocarray(*dir, ents + 2, परिमाण(**dir));
				(*dir)[ents] = xcalloc(1, परिमाण(***dir));
				(*dir)[ents]->filename = xstrdup(filename);
				(*dir)[ents]->longname = xstrdup(longname);
				स्मृतिं_प्रतिलिख(&(*dir)[ents]->a, &a, परिमाण(a));
				(*dir)[++ents] = रिक्त;
			}
			मुक्त(filename);
			मुक्त(longname);
		}
	}
	स्थितिः = 0;

 बहिर्गमनम्:
	sshbuf_free(सन्देशः);
	sftp_close(conn, handle, handle_len);
	मुक्त(handle);

	यदि (स्थितिः != 0 && dir != रिक्त) {
		/* Don't return results on error */
		sftp_free_dirents(*dir);
		*dir = रिक्त;
	} अन्यथा यदि (interrupted && dir != रिक्त && *dir != रिक्त) {
		/* Don't return partial matches on interrupt */
		sftp_free_dirents(*dir);
		*dir = xcalloc(1, परिमाण(**dir));
		**dir = रिक्त;
	}

	प्रत्यागम स्थितिः == SSH2_FX_OK ? 0 : -1;
}

पूर्णाङ्क
sftp_readdir(संरचना sftp_conn *conn, ध्रुव वर्ण *मार्गः, SFTP_DIRENT ***dir)
{
	प्रत्यागम sftp_lsreaddir(conn, मार्गः, 0, dir);
}

शून्य sftp_free_dirents(SFTP_DIRENT **s)
{
	पूर्णाङ्क i;

	यदि (s == रिक्त)
		प्रत्यागम;
	प्रति (i = 0; s[i]; i++) {
		मुक्त(s[i]->filename);
		मुक्त(s[i]->longname);
		मुक्त(s[i]);
	}
	मुक्त(s);
}

पूर्णाङ्क
sftp_rm(संरचना sftp_conn *conn, ध्रुव वर्ण *मार्गः)
{
	u_int स्थितिः, id;

	debug2("Sending SSH2_FXP_REMOVE \"%s\"", मार्गः);

	id = conn->सन्देशः_id++;
	send_string_request(conn, id, SSH2_FXP_REMOVE, मार्गः, वाक्यदैर्घ्यम्(मार्गः));
	स्थितिः = get_स्थितिः(conn, id);
	यदि (स्थितिः != SSH2_FX_OK)
		error("remote delete %s: %s", मार्गः, fx2txt(स्थितिः));
	प्रत्यागम स्थितिः == SSH2_FX_OK ? 0 : -1;
}

पूर्णाङ्क
sftp_mkdir(संरचना sftp_conn *conn, ध्रुव वर्ण *मार्गः, Attrib *a, पूर्णाङ्क print_flag)
{
	u_int स्थितिः, id;

	debug2("Sending SSH2_FXP_MKDIR \"%s\"", मार्गः);

	id = conn->सन्देशः_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_MKDIR, मार्गः,
	    वाक्यदैर्घ्यम्(मार्गः), a);

	स्थितिः = get_स्थितिः(conn, id);
	यदि (स्थितिः != SSH2_FX_OK && print_flag)
		error("remote mkdir \"%s\": %s", मार्गः, fx2txt(स्थितिः));

	प्रत्यागम स्थितिः == SSH2_FX_OK ? 0 : -1;
}

पूर्णाङ्क
sftp_mkpath(संरचना sftp_conn *conn, ध्रुव वर्ण *मार्गः, Attrib *a, पूर्णाङ्क print_flag)
{
	वर्ण *slash, *tmp_मार्गः;
	पूर्णाङ्क समाप्तम्;

	tmp_मार्गः = xstrdup(मार्गः);
	slash = tmp_मार्गः;

	प्रति (;;) {
		slash += strspn(slash, "/");
		slash += strcspn(slash, "/");

		समाप्तम् = (*slash == '\0');
		*slash = '\0';

		यदि (!sftp_remote_is_dir(conn, tmp_मार्गः)) {
			यदि (sftp_mkdir(conn, tmp_मार्गः, a, print_flag) != 0) {
				मुक्त(tmp_मार्गः);
				प्रत्यागम -1;
			}
		}

		यदि (समाप्तम्)
			भङ्ग;

		*slash = '/';
	}

	मुक्त(tmp_मार्गः);
	प्रत्यागम 0;
}

पूर्णाङ्क
sftp_rmdir(संरचना sftp_conn *conn, ध्रुव वर्ण *मार्गः)
{
	u_int स्थितिः, id;

	debug2("Sending SSH2_FXP_RMDIR \"%s\"", मार्गः);

	id = conn->सन्देशः_id++;
	send_string_request(conn, id, SSH2_FXP_RMDIR, मार्गः,
	    वाक्यदैर्घ्यम्(मार्गः));

	स्थितिः = get_स्थितिः(conn, id);
	यदि (स्थितिः != SSH2_FX_OK)
		error("remote rmdir \"%s\": %s", मार्गः, fx2txt(स्थितिः));

	प्रत्यागम स्थितिः == SSH2_FX_OK ? 0 : -1;
}

पूर्णाङ्क
sftp_stat(संरचना sftp_conn *conn, ध्रुव वर्ण *मार्गः, पूर्णाङ्क quiet, Attrib *a)
{
	u_int id;

	debug2("Sending SSH2_FXP_STAT \"%s\"", मार्गः);

	id = conn->सन्देशः_id++;

	send_string_request(conn, id,
	    conn->संस्करणम् == 0 ? SSH2_FXP_STAT_संस्करणम्_0 : SSH2_FXP_STAT,
	    मार्गः, वाक्यदैर्घ्यम्(मार्गः));

	प्रत्यागम get_decode_stat(conn, id, quiet, a);
}

पूर्णाङ्क
sftp_lstat(संरचना sftp_conn *conn, ध्रुव वर्ण *मार्गः, पूर्णाङ्क quiet, Attrib *a)
{
	u_int id;

	यदि (conn->संस्करणम् == 0) {
		do_log2(quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_INFO,
		    "Server version does not support lstat operation");
		प्रत्यागम sftp_stat(conn, मार्गः, quiet, a);
	}

	id = conn->सन्देशः_id++;
	send_string_request(conn, id, SSH2_FXP_LSTAT, मार्गः,
	    वाक्यदैर्घ्यम्(मार्गः));

	प्रत्यागम get_decode_stat(conn, id, quiet, a);
}

#यदि_परिभाषितम् notyet
पूर्णाङ्क
sftp_fstat(संरचना sftp_conn *conn, ध्रुव u_char *handle, u_int handle_len,
    पूर्णाङ्क quiet, Attrib *a)
{
	u_int id;

	debug2("Sending SSH2_FXP_FSTAT \"%s\"");

	id = conn->सन्देशः_id++;
	send_string_request(conn, id, SSH2_FXP_FSTAT, handle,
	    handle_len);

	प्रत्यागम get_decode_stat(conn, id, quiet, a);
}
#यदि_अन्तः

पूर्णाङ्क
sftp_setstat(संरचना sftp_conn *conn, ध्रुव वर्ण *मार्गः, Attrib *a)
{
	u_int स्थितिः, id;

	debug2("Sending SSH2_FXP_SETSTAT \"%s\"", मार्गः);

	id = conn->सन्देशः_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_SETSTAT, मार्गः,
	    वाक्यदैर्घ्यम्(मार्गः), a);

	स्थितिः = get_स्थितिः(conn, id);
	यदि (स्थितिः != SSH2_FX_OK)
		error("remote setstat \"%s\": %s", मार्गः, fx2txt(स्थितिः));

	प्रत्यागम स्थितिः == SSH2_FX_OK ? 0 : -1;
}

पूर्णाङ्क
sftp_fsetstat(संरचना sftp_conn *conn, ध्रुव u_char *handle, u_int handle_len,
    Attrib *a)
{
	u_int स्थितिः, id;

	debug2("Sending SSH2_FXP_FSETSTAT");

	id = conn->सन्देशः_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_FSETSTAT, handle,
	    handle_len, a);

	स्थितिः = get_स्थितिः(conn, id);
	यदि (स्थितिः != SSH2_FX_OK)
		error("remote fsetstat: %s", fx2txt(स्थितिः));

	प्रत्यागम स्थितिः == SSH2_FX_OK ? 0 : -1;
}

/* Implements both the realpath and expand-path operations */
स्थिर वर्ण *
sftp_realpath_expand(संरचना sftp_conn *conn, ध्रुव वर्ण *मार्गः, पूर्णाङ्क expand)
{
	संरचना sshbuf *सन्देशः;
	u_int expected_id, गणनम्, id;
	वर्ण *filename, *longname;
	Attrib a;
	u_char type;
	पूर्णाङ्क r;
	ध्रुव वर्ण *what = "SSH2_FXP_REALPATH";

	यदि (expand)
		what = "expand-path@openssh.com";
	यदि ((सन्देशः = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");

	expected_id = id = conn->सन्देशः_id++;
	यदि (expand) {
		debug2("Sending SSH2_FXP_EXTENDED(expand-path@openssh.com) "
		    "\"%s\"", मार्गः);
		यदि ((r = sshbuf_put_u8(सन्देशः, SSH2_FXP_EXTENDED)) != 0 ||
		    (r = sshbuf_put_u32(सन्देशः, id)) != 0 ||
		    (r = sshbuf_put_cstring(सन्देशः,
		    "expand-path@openssh.com")) != 0 ||
		    (r = sshbuf_put_cstring(सन्देशः, मार्गः)) != 0)
			fatal_fr(r, "compose %s", what);
		send_सन्देशः(conn, सन्देशः);
	} अन्यथा {
		debug2("Sending SSH2_FXP_REALPATH \"%s\"", मार्गः);
		send_string_request(conn, id, SSH2_FXP_REALPATH,
		    मार्गः, वाक्यदैर्घ्यम्(मार्गः));
	}
	get_सन्देशः(conn, सन्देशः);
	यदि ((r = sshbuf_get_u8(सन्देशः, &type)) != 0 ||
	    (r = sshbuf_get_u32(सन्देशः, &id)) != 0)
		fatal_fr(r, "parse");

	यदि (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);

	यदि (type == SSH2_FXP_स्थितिः) {
		u_int स्थितिः;
		वर्ण *errmsg;

		यदि ((r = sshbuf_get_u32(सन्देशः, &स्थितिः)) != 0 ||
		    (r = sshbuf_get_cstring(सन्देशः, &errmsg, रिक्त)) != 0)
			fatal_fr(r, "parse status");
		error("%s %s: %s", expand ? "expand" : "realpath",
		    मार्गः, *errmsg == '\0' ? fx2txt(स्थितिः) : errmsg);
		मुक्त(errmsg);
		sshbuf_free(सन्देशः);
		प्रत्यागम रिक्त;
	} अन्यथा यदि (type != SSH2_FXP_NAME)
		fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
		    SSH2_FXP_NAME, type);

	यदि ((r = sshbuf_get_u32(सन्देशः, &गणनम्)) != 0)
		fatal_fr(r, "parse count");
	यदि (गणनम् != 1)
		fatal("Got multiple names (%d) from %s", गणनम्, what);

	यदि ((r = sshbuf_get_cstring(सन्देशः, &filename, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(सन्देशः, &longname, रिक्त)) != 0 ||
	    (r = decode_attrib(सन्देशः, &a)) != 0)
		fatal_fr(r, "parse filename/attrib");

	debug3("%s %s -> %s", what, मार्गः, filename);

	मुक्त(longname);

	sshbuf_free(सन्देशः);

	प्रत्यागम(filename);
}

वर्ण *
sftp_realpath(संरचना sftp_conn *conn, ध्रुव वर्ण *मार्गः)
{
	प्रत्यागम sftp_realpath_expand(conn, मार्गः, 0);
}

पूर्णाङ्क
sftp_can_expand_मार्गः(संरचना sftp_conn *conn)
{
	प्रत्यागम (conn->exts & SFTP_EXT_मार्गः_EXPAND) != 0;
}

वर्ण *
sftp_expand_मार्गः(संरचना sftp_conn *conn, ध्रुव वर्ण *मार्गः)
{
	यदि (!sftp_can_expand_मार्गः(conn)) {
		debug3_f("no server support, fallback to realpath");
		प्रत्यागम sftp_realpath_expand(conn, मार्गः, 0);
	}
	प्रत्यागम sftp_realpath_expand(conn, मार्गः, 1);
}

पूर्णाङ्क
sftp_copy(संरचना sftp_conn *conn, ध्रुव वर्ण *oldpath, ध्रुव वर्ण *newpath)
{
	Attrib junk, attr;
	संरचना sshbuf *सन्देशः;
	u_char *old_handle, *new_handle;
	u_int बहुलकम्, स्थितिः, id;
	आकार_t old_handle_len, new_handle_len;
	पूर्णाङ्क r;

	/* Return if the extension is not supported */
	यदि ((conn->exts & SFTP_EXT_COPY_दत्त) == 0) {
		error("Server does not support copy-data extension");
		प्रत्यागम -1;
	}

	/* Make sure the file exists, and we can copy its perms */
	यदि (sftp_stat(conn, oldpath, 0, &attr) != 0)
		प्रत्यागम -1;

	/* Do not preserve set[ug]id here, as we do not preserve ownership */
	यदि (attr.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		बहुलकम् = attr.perm & 0777;

		यदि (!S_ISREG(attr.perm)) {
			error("Cannot copy non-regular file: %s", oldpath);
			प्रत्यागम -1;
		}
	} अन्यथा {
		/* NB: The user's umask will apply to this */
		बहुलकम् = 0666;
	}

	/* Set up the new perms for the new file */
	attrib_clear(&attr);
	attr.perm = बहुलकम्;
	attr.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;

	यदि ((सन्देशः = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");

	attrib_clear(&junk); /* Send empty attributes */

	/* Open the old file for reading */
	id = conn->सन्देशः_id++;
	यदि ((r = sshbuf_put_u8(सन्देशः, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(सन्देशः, id)) != 0 ||
	    (r = sshbuf_put_cstring(सन्देशः, oldpath)) != 0 ||
	    (r = sshbuf_put_u32(सन्देशः, SSH2_FXF_READ)) != 0 ||
	    (r = encode_attrib(सन्देशः, &junk)) != 0)
		fatal_fr(r, "buffer error");
	send_सन्देशः(conn, सन्देशः);
	debug3("Sent message SSH2_FXP_OPEN I:%u P:%s", id, oldpath);

	sshbuf_reset(सन्देशः);

	old_handle = get_handle(conn, id, &old_handle_len,
	    "remote open(\"%s\")", oldpath);
	यदि (old_handle == रिक्त) {
		sshbuf_free(सन्देशः);
		प्रत्यागम -1;
	}

	/* Open the new file for writing */
	id = conn->सन्देशः_id++;
	यदि ((r = sshbuf_put_u8(सन्देशः, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(सन्देशः, id)) != 0 ||
	    (r = sshbuf_put_cstring(सन्देशः, newpath)) != 0 ||
	    (r = sshbuf_put_u32(सन्देशः, SSH2_FXF_WRITE|SSH2_FXF_CREAT|
	    SSH2_FXF_TRUNC)) != 0 ||
	    (r = encode_attrib(सन्देशः, &attr)) != 0)
		fatal_fr(r, "buffer error");
	send_सन्देशः(conn, सन्देशः);
	debug3("Sent message SSH2_FXP_OPEN I:%u P:%s", id, newpath);

	sshbuf_reset(सन्देशः);

	new_handle = get_handle(conn, id, &new_handle_len,
	    "remote open(\"%s\")", newpath);
	यदि (new_handle == रिक्त) {
		sshbuf_free(सन्देशः);
		मुक्त(old_handle);
		प्रत्यागम -1;
	}

	/* Copy the file data */
	id = conn->सन्देशः_id++;
	यदि ((r = sshbuf_put_u8(सन्देशः, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(सन्देशः, id)) != 0 ||
	    (r = sshbuf_put_cstring(सन्देशः, "copy-data")) != 0 ||
	    (r = sshbuf_put_string(सन्देशः, old_handle, old_handle_len)) != 0 ||
	    (r = sshbuf_put_u64(सन्देशः, 0)) != 0 ||
	    (r = sshbuf_put_u64(सन्देशः, 0)) != 0 ||
	    (r = sshbuf_put_string(सन्देशः, new_handle, new_handle_len)) != 0 ||
	    (r = sshbuf_put_u64(सन्देशः, 0)) != 0)
		fatal_fr(r, "buffer error");
	send_सन्देशः(conn, सन्देशः);
	debug3("Sent message copy-data \"%s\" 0 0 -> \"%s\" 0",
	       oldpath, newpath);

	स्थितिः = get_स्थितिः(conn, id);
	यदि (स्थितिः != SSH2_FX_OK)
		error("Couldn't copy file \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(स्थितिः));

	/* Clean up everything */
	sshbuf_free(सन्देशः);
	sftp_close(conn, old_handle, old_handle_len);
	sftp_close(conn, new_handle, new_handle_len);
	मुक्त(old_handle);
	मुक्त(new_handle);

	प्रत्यागम स्थितिः == SSH2_FX_OK ? 0 : -1;
}

पूर्णाङ्क
sftp_rename(संरचना sftp_conn *conn, ध्रुव वर्ण *oldpath, ध्रुव वर्ण *newpath,
    पूर्णाङ्क force_legacy)
{
	संरचना sshbuf *सन्देशः;
	u_int स्थितिः, id;
	पूर्णाङ्क r, use_ext = (conn->exts & SFTP_EXT_POSIX_RENAME) && !force_legacy;

	यदि ((सन्देशः = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");

	/* Send rename request */
	id = conn->सन्देशः_id++;
	यदि (use_ext) {
		debug2("Sending SSH2_FXP_EXTENDED(posix-rename@openssh.com) "
		    "\"%s\" to \"%s\"", oldpath, newpath);
		यदि ((r = sshbuf_put_u8(सन्देशः, SSH2_FXP_EXTENDED)) != 0 ||
		    (r = sshbuf_put_u32(सन्देशः, id)) != 0 ||
		    (r = sshbuf_put_cstring(सन्देशः,
		    "posix-rename@openssh.com")) != 0)
			fatal_fr(r, "compose posix-rename");
	} अन्यथा {
		debug2("Sending SSH2_FXP_RENAME \"%s\" to \"%s\"",
		    oldpath, newpath);
		यदि ((r = sshbuf_put_u8(सन्देशः, SSH2_FXP_RENAME)) != 0 ||
		    (r = sshbuf_put_u32(सन्देशः, id)) != 0)
			fatal_fr(r, "compose rename");
	}
	यदि ((r = sshbuf_put_cstring(सन्देशः, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(सन्देशः, newpath)) != 0)
		fatal_fr(r, "compose paths");
	send_सन्देशः(conn, सन्देशः);
	debug3("Sent message %s \"%s\" -> \"%s\"",
	    use_ext ? "posix-rename@openssh.com" :
	    "SSH2_FXP_RENAME", oldpath, newpath);
	sshbuf_free(सन्देशः);

	स्थितिः = get_स्थितिः(conn, id);
	यदि (स्थितिः != SSH2_FX_OK)
		error("remote rename \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(स्थितिः));

	प्रत्यागम स्थितिः == SSH2_FX_OK ? 0 : -1;
}

पूर्णाङ्क
sftp_hardlink(संरचना sftp_conn *conn, ध्रुव वर्ण *oldpath, ध्रुव वर्ण *newpath)
{
	संरचना sshbuf *सन्देशः;
	u_int स्थितिः, id;
	पूर्णाङ्क r;

	यदि ((conn->exts & SFTP_EXT_HARDLINK) == 0) {
		error("Server does not support hardlink@openssh.com extension");
		प्रत्यागम -1;
	}
	debug2("Sending SSH2_FXP_EXTENDED(hardlink@openssh.com) "
	    "\"%s\" to \"%s\"", oldpath, newpath);

	यदि ((सन्देशः = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");

	/* Send link request */
	id = conn->सन्देशः_id++;
	यदि ((r = sshbuf_put_u8(सन्देशः, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(सन्देशः, id)) != 0 ||
	    (r = sshbuf_put_cstring(सन्देशः, "hardlink@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(सन्देशः, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(सन्देशः, newpath)) != 0)
		fatal_fr(r, "compose");
	send_सन्देशः(conn, सन्देशः);
	debug3("Sent message hardlink@openssh.com \"%s\" -> \"%s\"",
	    oldpath, newpath);
	sshbuf_free(सन्देशः);

	स्थितिः = get_स्थितिः(conn, id);
	यदि (स्थितिः != SSH2_FX_OK)
		error("remote link \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(स्थितिः));

	प्रत्यागम स्थितिः == SSH2_FX_OK ? 0 : -1;
}

पूर्णाङ्क
sftp_symlink(संरचना sftp_conn *conn, ध्रुव वर्ण *oldpath, ध्रुव वर्ण *newpath)
{
	संरचना sshbuf *सन्देशः;
	u_int स्थितिः, id;
	पूर्णाङ्क r;

	यदि (conn->संस्करणम् < 3) {
		error("This server does not support the symlink operation");
		प्रत्यागम(SSH2_FX_OP_UNSUPPORTED);
	}
	debug2("Sending SSH2_FXP_SYMLINK \"%s\" to \"%s\"", oldpath, newpath);

	यदि ((सन्देशः = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");

	/* Send symlink request */
	id = conn->सन्देशः_id++;
	यदि ((r = sshbuf_put_u8(सन्देशः, SSH2_FXP_SYMLINK)) != 0 ||
	    (r = sshbuf_put_u32(सन्देशः, id)) != 0 ||
	    (r = sshbuf_put_cstring(सन्देशः, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(सन्देशः, newpath)) != 0)
		fatal_fr(r, "compose");
	send_सन्देशः(conn, सन्देशः);
	debug3("Sent message SSH2_FXP_SYMLINK \"%s\" -> \"%s\"", oldpath,
	    newpath);
	sshbuf_free(सन्देशः);

	स्थितिः = get_स्थितिः(conn, id);
	यदि (स्थितिः != SSH2_FX_OK)
		error("remote symlink file \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(स्थितिः));

	प्रत्यागम स्थितिः == SSH2_FX_OK ? 0 : -1;
}

पूर्णाङ्क
sftp_fsync(संरचना sftp_conn *conn, u_char *handle, u_int handle_len)
{
	संरचना sshbuf *सन्देशः;
	u_int स्थितिः, id;
	पूर्णाङ्क r;

	/* Silently return if the extension is not supported */
	यदि ((conn->exts & SFTP_EXT_FSYNC) == 0)
		प्रत्यागम -1;
	debug2("Sending SSH2_FXP_EXTENDED(fsync@openssh.com)");

	/* Send fsync request */
	यदि ((सन्देशः = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	id = conn->सन्देशः_id++;
	यदि ((r = sshbuf_put_u8(सन्देशः, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(सन्देशः, id)) != 0 ||
	    (r = sshbuf_put_cstring(सन्देशः, "fsync@openssh.com")) != 0 ||
	    (r = sshbuf_put_string(सन्देशः, handle, handle_len)) != 0)
		fatal_fr(r, "compose");
	send_सन्देशः(conn, सन्देशः);
	debug3("Sent message fsync@openssh.com I:%u", id);
	sshbuf_free(सन्देशः);

	स्थितिः = get_स्थितिः(conn, id);
	यदि (स्थितिः != SSH2_FX_OK)
		error("remote fsync: %s", fx2txt(स्थितिः));

	प्रत्यागम स्थितिः == SSH2_FX_OK ? 0 : -1;
}

#यदि_परिभाषितम् notyet
वर्ण *
sftp_readlink(संरचना sftp_conn *conn, ध्रुव वर्ण *मार्गः)
{
	संरचना sshbuf *सन्देशः;
	u_int expected_id, गणनम्, id;
	वर्ण *filename, *longname;
	Attrib a;
	u_char type;
	पूर्णाङ्क r;

	debug2("Sending SSH2_FXP_READLINK \"%s\"", मार्गः);

	expected_id = id = conn->सन्देशः_id++;
	send_string_request(conn, id, SSH2_FXP_READLINK, मार्गः, वाक्यदैर्घ्यम्(मार्गः));

	यदि ((सन्देशः = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");

	get_सन्देशः(conn, सन्देशः);
	यदि ((r = sshbuf_get_u8(सन्देशः, &type)) != 0 ||
	    (r = sshbuf_get_u32(सन्देशः, &id)) != 0)
		fatal_fr(r, "parse");

	यदि (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);

	यदि (type == SSH2_FXP_स्थितिः) {
		u_int स्थितिः;

		यदि ((r = sshbuf_get_u32(सन्देशः, &स्थितिः)) != 0)
			fatal_fr(r, "parse status");
		error("Couldn't readlink: %s", fx2txt(स्थितिः));
		sshbuf_free(सन्देशः);
		प्रत्यागम(रिक्त);
	} अन्यथा यदि (type != SSH2_FXP_NAME)
		fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
		    SSH2_FXP_NAME, type);

	यदि ((r = sshbuf_get_u32(सन्देशः, &गणनम्)) != 0)
		fatal_fr(r, "parse count");
	यदि (गणनम् != 1)
		fatal("Got multiple names (%d) from SSH_FXP_READLINK", गणनम्);

	यदि ((r = sshbuf_get_cstring(सन्देशः, &filename, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(सन्देशः, &longname, रिक्त)) != 0 ||
	    (r = decode_attrib(सन्देशः, &a)) != 0)
		fatal_fr(r, "parse filenames/attrib");

	debug3("SSH_FXP_READLINK %s -> %s", मार्गः, filename);

	मुक्त(longname);

	sshbuf_free(सन्देशः);

	प्रत्यागम filename;
}
#यदि_अन्तः

पूर्णाङ्क
sftp_statvfs(संरचना sftp_conn *conn, ध्रुव वर्ण *मार्गः, संरचना sftp_statvfs *st,
    पूर्णाङ्क quiet)
{
	संरचना sshbuf *सन्देशः;
	u_int id;
	पूर्णाङ्क r;

	यदि ((conn->exts & SFTP_EXT_STATVFS) == 0) {
		error("Server does not support statvfs@openssh.com extension");
		प्रत्यागम -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(statvfs@openssh.com) \"%s\"", मार्गः);

	id = conn->सन्देशः_id++;

	यदि ((सन्देशः = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshbuf_put_u8(सन्देशः, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(सन्देशः, id)) != 0 ||
	    (r = sshbuf_put_cstring(सन्देशः, "statvfs@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(सन्देशः, मार्गः)) != 0)
		fatal_fr(r, "compose");
	send_सन्देशः(conn, सन्देशः);
	sshbuf_free(सन्देशः);

	प्रत्यागम get_decode_statvfs(conn, st, id, quiet);
}

#यदि_परिभाषितम् notyet
पूर्णाङ्क
sftp_fstatvfs(संरचना sftp_conn *conn, ध्रुव u_char *handle, u_int handle_len,
    संरचना sftp_statvfs *st, पूर्णाङ्क quiet)
{
	संरचना sshbuf *सन्देशः;
	u_int id;

	यदि ((conn->exts & SFTP_EXT_FSTATVFS) == 0) {
		error("Server does not support fstatvfs@openssh.com extension");
		प्रत्यागम -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(fstatvfs@openssh.com)");

	id = conn->सन्देशः_id++;

	यदि ((सन्देशः = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshbuf_put_u8(सन्देशः, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(सन्देशः, id)) != 0 ||
	    (r = sshbuf_put_cstring(सन्देशः, "fstatvfs@openssh.com")) != 0 ||
	    (r = sshbuf_put_string(सन्देशः, handle, handle_len)) != 0)
		fatal_fr(r, "compose");
	send_सन्देशः(conn, सन्देशः);
	sshbuf_free(सन्देशः);

	प्रत्यागम get_decode_statvfs(conn, st, id, quiet);
}
#यदि_अन्तः

पूर्णाङ्क
sftp_lsetstat(संरचना sftp_conn *conn, ध्रुव वर्ण *मार्गः, Attrib *a)
{
	संरचना sshbuf *सन्देशः;
	u_int स्थितिः, id;
	पूर्णाङ्क r;

	यदि ((conn->exts & SFTP_EXT_LSETSTAT) == 0) {
		error("Server does not support lsetstat@openssh.com extension");
		प्रत्यागम -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(lsetstat@openssh.com) \"%s\"", मार्गः);

	id = conn->सन्देशः_id++;
	यदि ((सन्देशः = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshbuf_put_u8(सन्देशः, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(सन्देशः, id)) != 0 ||
	    (r = sshbuf_put_cstring(सन्देशः, "lsetstat@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(सन्देशः, मार्गः)) != 0 ||
	    (r = encode_attrib(सन्देशः, a)) != 0)
		fatal_fr(r, "compose");
	send_सन्देशः(conn, सन्देशः);
	sshbuf_free(सन्देशः);

	स्थितिः = get_स्थितिः(conn, id);
	यदि (स्थितिः != SSH2_FX_OK)
		error("remote lsetstat \"%s\": %s", मार्गः, fx2txt(स्थितिः));

	प्रत्यागम स्थितिः == SSH2_FX_OK ? 0 : -1;
}

स्थिर शून्य
send_read_request(संरचना sftp_conn *conn, u_int id, uint64_t विस्थापनम्,
    u_int len, ध्रुव u_char *handle, u_int handle_len)
{
	संरचना sshbuf *सन्देशः;
	पूर्णाङ्क r;

	यदि ((सन्देशः = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshbuf_put_u8(सन्देशः, SSH2_FXP_READ)) != 0 ||
	    (r = sshbuf_put_u32(सन्देशः, id)) != 0 ||
	    (r = sshbuf_put_string(सन्देशः, handle, handle_len)) != 0 ||
	    (r = sshbuf_put_u64(सन्देशः, विस्थापनम्)) != 0 ||
	    (r = sshbuf_put_u32(सन्देशः, len)) != 0)
		fatal_fr(r, "compose");
	send_सन्देशः(conn, सन्देशः);
	sshbuf_free(सन्देशः);
}

स्थिर पूर्णाङ्क
send_open(संरचना sftp_conn *conn, ध्रुव वर्ण *मार्गः, ध्रुव वर्ण *चिह्नकम्,
    u_int openmode, Attrib *a, u_char **handlep, आकार_t *handle_lenp)
{
	Attrib junk;
	u_char *handle;
	आकार_t handle_len;
	संरचना sshbuf *सन्देशः;
	पूर्णाङ्क r;
	u_int id;

	debug2("Sending SSH2_FXP_OPEN \"%s\"", मार्गः);

	*handlep = रिक्त;
	*handle_lenp = 0;

	यदि (a == रिक्त) {
		attrib_clear(&junk); /* Send empty attributes */
		a = &junk;
	}
	/* Send open request */
	यदि ((सन्देशः = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	id = conn->सन्देशः_id++;
	यदि ((r = sshbuf_put_u8(सन्देशः, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(सन्देशः, id)) != 0 ||
	    (r = sshbuf_put_cstring(सन्देशः, मार्गः)) != 0 ||
	    (r = sshbuf_put_u32(सन्देशः, openmode)) != 0 ||
	    (r = encode_attrib(सन्देशः, a)) != 0)
		fatal_fr(r, "compose %s open", चिह्नकम्);
	send_सन्देशः(conn, सन्देशः);
	sshbuf_free(सन्देशः);
	debug3("Sent %s message SSH2_FXP_OPEN I:%u P:%s M:0x%04x",
	    चिह्नकम्, id, मार्गः, openmode);
	यदि ((handle = get_handle(conn, id, &handle_len,
	    "%s open \"%s\"", चिह्नकम्, मार्गः)) == रिक्त)
		प्रत्यागम -1;
	/* success */
	*handlep = handle;
	*handle_lenp = handle_len;
	प्रत्यागम 0;
}

स्थिर ध्रुव वर्ण *
प्रगतिः_meter_मार्गः(ध्रुव वर्ण *मार्गः)
{
	ध्रुव वर्ण *progresspath;

	यदि ((progresspath = strrchr(मार्गः, '/')) == रिक्त)
		प्रत्यागम मार्गः;
	progresspath++;
	यदि (*progresspath == '\0')
		प्रत्यागम मार्गः;
	प्रत्यागम progresspath;
}

पूर्णाङ्क
sftp_download(संरचना sftp_conn *conn, ध्रुव वर्ण *remote_मार्गः,
    ध्रुव वर्ण *local_मार्गः, Attrib *a, पूर्णाङ्क preserve_flag, पूर्णाङ्क resume_flag,
    पूर्णाङ्क fsync_flag, पूर्णाङ्क inplace_flag)
{
	संरचना sshbuf *सन्देशः;
	u_char *handle;
	पूर्णाङ्क local_fd = -1, write_error, आलोकितम्_zerolen = 0;
	पूर्णाङ्क read_error, write_errno, lmodified = 0, reordered = 0, r;
	uint64_t विस्थापनम् = 0, आकार, highwater = 0, maxack = 0;
	u_int बहुलकम्, id, buflen, अङ्कः_req, max_req, स्थितिः = SSH2_FX_OK;
	off_t प्रगतिः_गणक;
	आकार_t handle_len;
	संरचना stat st;
	संरचना अनुरोधाः अनुरोधाः;
	संरचना request *req;
	u_char type;
	Attrib attr;

	debug2_f("download remote \"%s\" to local \"%s\"",
	    remote_मार्गः, local_मार्गः);

	TAILQ_INIT(&अनुरोधाः);

	यदि (a == रिक्त) {
		यदि (sftp_stat(conn, remote_मार्गः, 0, &attr) != 0)
			प्रत्यागम -1;
		a = &attr;
	}

	/* Do not preserve set[ug]id here, as we do not preserve ownership */
	यदि (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS)
		बहुलकम् = a->perm & 0777;
	अन्यथा
		बहुलकम् = 0666;

	यदि ((a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) &&
	    (!S_ISREG(a->perm))) {
		error("download %s: not a regular file", remote_मार्गः);
		प्रत्यागम(-1);
	}

	यदि (a->flags & SSH2_FILEXFER_ATTR_आकार)
		आकार = a->आकार;
	अन्यथा
		आकार = 0;

	buflen = conn->download_buflen;

	/* Send open request */
	यदि (send_open(conn, remote_मार्गः, "remote", SSH2_FXF_READ, रिक्त,
	    &handle, &handle_len) != 0)
		प्रत्यागम -1;

	local_fd = उद्घाटय(local_मार्गः, O_WRONLY | O_CREAT |
	((resume_flag || inplace_flag) ? 0 : O_TRUNC), बहुलकम् | S_IWUSR);
	यदि (local_fd == -1) {
		error("open local \"%s\": %s", local_मार्गः, strerror(errno));
		गच्छ fail;
	}
	यदि (resume_flag) {
		यदि (fstat(local_fd, &st) == -1) {
			error("stat local \"%s\": %s",
			    local_मार्गः, strerror(errno));
			गच्छ fail;
		}
		यदि (st.st_size < 0) {
			error("\"%s\" has negative size", local_मार्गः);
			गच्छ fail;
		}
		यदि ((uint64_t)st.st_size > आकार) {
			error("Unable to resume download of \"%s\": "
			    "local file is larger than remote", local_मार्गः);
 fail:
			sftp_close(conn, handle, handle_len);
			मुक्त(handle);
			यदि (local_fd != -1)
				close(local_fd);
			प्रत्यागम -1;
		}
		विस्थापनम् = highwater = maxack = st.st_size;
	}

	/* Read from remote and write to local */
	write_error = read_error = write_errno = अङ्कः_req = 0;
	max_req = 1;
	प्रगतिः_गणक = विस्थापनम्;

	यदि (showprogress && आकार != 0) {
		start_प्रगतिः_meter(प्रगतिः_meter_मार्गः(remote_मार्गः),
		    आकार, &प्रगतिः_गणक);
	}

	यदि ((सन्देशः = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");

	यावत् (अङ्कः_req > 0 || max_req > 0) {
		u_char *दत्त;
		आकार_t len;

		/*
		 * Simulate EOF on interrupt: stop sending new requests and
		 * allow outstanding requests to drain gracefully
		 */
		यदि (interrupted) {
			यदि (अङ्कः_req == 0) /* If we haven't started yet... */
				भङ्ग;
			max_req = 0;
		}

		/* Send some more requests */
		यावत् (अङ्कः_req < max_req) {
			debug3("Request range %llu -> %llu (%d/%d)",
			    (अचिह्नित दीर्घ दीर्घ)विस्थापनम्,
			    (अचिह्नित दीर्घ दीर्घ)विस्थापनम् + buflen - 1,
			    अङ्कः_req, max_req);
			req = request_पङ्क्तौ_निक्षिप(&अनुरोधाः, conn->सन्देशः_id++,
			    buflen, विस्थापनम्);
			विस्थापनम् += buflen;
			अङ्कः_req++;
			send_read_request(conn, req->id, req->विस्थापनम्,
			    req->len, handle, handle_len);
		}

		sshbuf_reset(सन्देशः);
		get_सन्देशः(conn, सन्देशः);
		यदि ((r = sshbuf_get_u8(सन्देशः, &type)) != 0 ||
		    (r = sshbuf_get_u32(सन्देशः, &id)) != 0)
			fatal_fr(r, "parse");
		debug3("Received reply T:%u I:%u R:%d", type, id, max_req);

		/* Find the request in our queue */
		यदि ((req = request_find(&अनुरोधाः, id)) == रिक्त)
			fatal("Unexpected reply %u", id);

		विकल्प (type) {
		पक्ष SSH2_FXP_स्थितिः:
			यदि ((r = sshbuf_get_u32(सन्देशः, &स्थितिः)) != 0)
				fatal_fr(r, "parse status");
			यदि (स्थितिः != SSH2_FX_EOF)
				read_error = 1;
			max_req = 0;
			TAILQ_REMOVE(&अनुरोधाः, req, tq);
			मुक्त(req);
			अङ्कः_req--;
			भङ्ग;
		पक्ष SSH2_FXP_दत्त:
			यदि ((r = sshbuf_get_string(सन्देशः, &दत्त, &len)) != 0)
				fatal_fr(r, "parse data");
			debug3("Received data %llu -> %llu",
			    (अचिह्नित दीर्घ दीर्घ)req->विस्थापनम्,
			    (अचिह्नित दीर्घ दीर्घ)req->विस्थापनम् + len - 1);
			यदि (len > req->len)
				fatal("Received more data than asked for "
				    "%zu > %zu", len, req->len);
			यदि (len == 0) {
				यदि (आलोकितम्_zerolen)
					fatal_f("server sent zero data length");
				आलोकितम्_zerolen = 1;
			}
			lmodified = 1;
			यदि ((lseek(local_fd, req->विस्थापनम्, SEEK_SET) == -1 ||
			    atomicio(vwrite, local_fd, दत्त, len) != len) &&
			    !write_error) {
				write_errno = errno;
				write_error = 1;
				max_req = 0;
			} अन्यथा {
				/*
				 * Track both the highest offset acknowledged
				 * and the highest *contiguous* offset
				 * acknowledged.
				 * We'll need the latter for ftruncate()ing
				 * interrupted transfers.
				 */
				यदि (maxack < req->विस्थापनम् + len)
					maxack = req->विस्थापनम् + len;
				यदि (!reordered && req->विस्थापनम् <= highwater)
					highwater = maxack;
				अन्यथा यदि (!reordered && req->विस्थापनम् > highwater)
					reordered = 1;
			}
			प्रगतिः_गणक += len;
			मुक्त(दत्त);

			यदि (len == req->len) {
				TAILQ_REMOVE(&अनुरोधाः, req, tq);
				मुक्त(req);
				अङ्कः_req--;
			} अन्यथा {
				/* Resend the request for the missing data */
				debug3("Short data block, re-requesting "
				    "%llu -> %llu (%2d)",
				    (अचिह्नित दीर्घ दीर्घ)req->विस्थापनम् + len,
				    (अचिह्नित दीर्घ दीर्घ)req->विस्थापनम् +
				    req->len - 1, अङ्कः_req);
				req->id = conn->सन्देशः_id++;
				req->len -= len;
				req->विस्थापनम् += len;
				send_read_request(conn, req->id,
				    req->विस्थापनम्, req->len, handle, handle_len);
				/* Reduce the request size */
				यदि (len < buflen)
					buflen = अधिकतमम्(MIN_READ_आकार, len);
			}
			यदि (max_req > 0) { /* max_req = 0 iff EOF received */
				यदि (आकार > 0 && विस्थापनम् > आकार) {
					/* Only one request at a time
					 * after the expected EOF */
					debug3("Finish at %llu (%2d)",
					    (अचिह्नित दीर्घ दीर्घ)विस्थापनम्,
					    अङ्कः_req);
					max_req = 1;
				} अन्यथा यदि (max_req < conn->अङ्कः_अनुरोधाः) {
					++max_req;
				}
			}
			भङ्ग;
		स्वभाव:
			fatal("Expected SSH2_FXP_DATA(%u) packet, got %u",
			    SSH2_FXP_दत्त, type);
		}
	}

	यदि (showprogress && आकार)
		stop_प्रगतिः_meter();

	/* Sanity check */
	यदि (TAILQ_FIRST(&अनुरोधाः) != रिक्त)
		fatal("Transfer complete, but requests still in queue");

	यदि (!read_error && !write_error && !interrupted) {
		/* we got everything */
		highwater = maxack;
	}

	/*
	 * Truncate at highest contiguous point to avoid holes on interrupt,
	 * or unconditionally if writing in place.
	 */
	यदि (inplace_flag || read_error || write_error || interrupted) {
		यदि (reordered && resume_flag &&
		    (read_error || write_error || interrupted)) {
			error("Unable to resume download of \"%s\": "
			    "server reordered requests", local_मार्गः);
		}
		debug("truncating at %llu", (अचिह्नित दीर्घ दीर्घ)highwater);
		यदि (ftruncate(local_fd, highwater) == -1)
			error("local ftruncate \"%s\": %s", local_मार्गः,
			    strerror(errno));
	}
	यदि (read_error) {
		error("read remote \"%s\" : %s", remote_मार्गः, fx2txt(स्थितिः));
		स्थितिः = -1;
		sftp_close(conn, handle, handle_len);
	} अन्यथा यदि (write_error) {
		error("write local \"%s\": %s", local_मार्गः,
		    strerror(write_errno));
		स्थितिः = SSH2_FX_FAILURE;
		sftp_close(conn, handle, handle_len);
	} अन्यथा {
		यदि (sftp_close(conn, handle, handle_len) != 0 || interrupted)
			स्थितिः = SSH2_FX_FAILURE;
		अन्यथा
			स्थितिः = SSH2_FX_OK;
		/* Override umask and utimes if asked */
#यदि_परिभाषितम् HAVE_FCHMOD
		यदि (preserve_flag && fchmod(local_fd, बहुलकम्) == -1)
#अन्यथा
		यदि (preserve_flag && chmod(local_मार्गः, बहुलकम्) == -1)
#यदि_अन्तः /* HAVE_FCHMOD */
			error("local chmod \"%s\": %s", local_मार्गः,
			    strerror(errno));
		यदि (preserve_flag &&
		    (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME)) {
			संरचना timeval tv[2];
			tv[0].tv_sec = a->atime;
			tv[1].tv_sec = a->mtime;
			tv[0].tv_usec = tv[1].tv_usec = 0;
			यदि (utimes(local_मार्गः, tv) == -1)
				error("local set times \"%s\": %s",
				    local_मार्गः, strerror(errno));
		}
		यदि (resume_flag && !lmodified)
			logit("File \"%s\" was not modified", local_मार्गः);
		अन्यथा यदि (fsync_flag) {
			debug("syncing \"%s\"", local_मार्गः);
			यदि (fsync(local_fd) == -1)
				error("local sync \"%s\": %s",
				    local_मार्गः, strerror(errno));
		}
	}
	close(local_fd);
	sshbuf_free(सन्देशः);
	मुक्त(handle);

	प्रत्यागम स्थितिः == SSH2_FX_OK ? 0 : -1;
}

स्थिर पूर्णाङ्क
download_dir_आन्तरिकम्(संरचना sftp_conn *conn, ध्रुव वर्ण *src, ध्रुव वर्ण *dst,
    पूर्णाङ्क गभीरता, Attrib *dirattrib, पूर्णाङ्क preserve_flag, पूर्णाङ्क print_flag,
    पूर्णाङ्क resume_flag, पूर्णाङ्क fsync_flag, पूर्णाङ्क follow_link_flag, पूर्णाङ्क inplace_flag)
{
	पूर्णाङ्क i, ret = 0;
	SFTP_DIRENT **dir_entries;
	वर्ण *filename, *new_src = रिक्त, *new_dst = रिक्त;
	बहुलकम्_t बहुलकम् = 0777, tmpmode = बहुलकम्;
	Attrib *a, ldirattrib, lsym;

	यदि (गभीरता >= MAX_DIR_गभीरता) {
		error("Maximum directory depth exceeded: %d levels", गभीरता);
		प्रत्यागम -1;
	}

	debug2_f("download dir remote \"%s\" to local \"%s\"", src, dst);

	यदि (dirattrib == रिक्त) {
		यदि (sftp_stat(conn, src, 1, &ldirattrib) != 0) {
			error("stat remote \"%s\" directory failed", src);
			प्रत्यागम -1;
		}
		dirattrib = &ldirattrib;
	}
	यदि (!S_ISDIR(dirattrib->perm)) {
		error("\"%s\" is not a directory", src);
		प्रत्यागम -1;
	}
	यदि (print_flag && print_flag != SFTP_प्रगतिः_ONLY)
		mprintf("Retrieving %s\n", src);

	यदि (dirattrib->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		बहुलकम् = dirattrib->perm & 01777;
		tmpmode = बहुलकम् | (S_IWUSR|S_IXUSR);
	} अन्यथा {
		debug("download remote \"%s\": server "
		    "did not send permissions", dst);
	}

	यदि (mkdir(dst, tmpmode) == -1 && errno != EEXIST) {
		error("mkdir %s: %s", dst, strerror(errno));
		प्रत्यागम -1;
	}

	यदि (sftp_readdir(conn, src, &dir_entries) == -1) {
		error("remote readdir \"%s\" failed", src);
		प्रत्यागम -1;
	}

	प्रति (i = 0; dir_entries[i] != रिक्त && !interrupted; i++) {
		मुक्त(new_dst);
		मुक्त(new_src);

		filename = dir_entries[i]->filename;
		new_dst = sftp_मार्गः_append(dst, filename);
		new_src = sftp_मार्गः_append(src, filename);

		a = &dir_entries[i]->a;
		यदि (S_ISLNK(a->perm)) {
			यदि (!follow_link_flag) {
				logit("download \"%s\": not a regular file",
				    new_src);
				अनुवर्त;
			}
			/* Replace the stat contents with the symlink target */
			यदि (sftp_stat(conn, new_src, 1, &lsym) != 0) {
				logit("remote stat \"%s\" failed", new_src);
				ret = -1;
				अनुवर्त;
			}
			a = &lsym;
		}

		यदि (S_ISDIR(a->perm)) {
			यदि (वाक्यं_तुलय(filename, ".") == 0 ||
			    वाक्यं_तुलय(filename, "..") == 0)
				अनुवर्त;
			यदि (download_dir_आन्तरिकम्(conn, new_src, new_dst,
			    गभीरता + 1, a, preserve_flag,
			    print_flag, resume_flag,
			    fsync_flag, follow_link_flag, inplace_flag) == -1)
				ret = -1;
		} अन्यथा यदि (S_ISREG(a->perm)) {
			यदि (sftp_download(conn, new_src, new_dst, a,
			    preserve_flag, resume_flag, fsync_flag,
			    inplace_flag) == -1) {
				error("Download of file %s to %s failed",
				    new_src, new_dst);
				ret = -1;
			}
		} अन्यथा
			logit("download \"%s\": not a regular file", new_src);

	}
	मुक्त(new_dst);
	मुक्त(new_src);

	यदि (preserve_flag) {
		यदि (dirattrib->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
			संरचना timeval tv[2];
			tv[0].tv_sec = dirattrib->atime;
			tv[1].tv_sec = dirattrib->mtime;
			tv[0].tv_usec = tv[1].tv_usec = 0;
			यदि (utimes(dst, tv) == -1)
				error("local set times on \"%s\": %s",
				    dst, strerror(errno));
		} अन्यथा
			debug("Server did not send times for directory "
			    "\"%s\"", dst);
	}

	यदि (बहुलकम् != tmpmode && chmod(dst, बहुलकम्) == -1)
		error("local chmod directory \"%s\": %s", dst,
		    strerror(errno));

	sftp_free_dirents(dir_entries);

	प्रत्यागम ret;
}

पूर्णाङ्क
sftp_download_dir(संरचना sftp_conn *conn, ध्रुव वर्ण *src, ध्रुव वर्ण *dst,
    Attrib *dirattrib, पूर्णाङ्क preserve_flag, पूर्णाङ्क print_flag, पूर्णाङ्क resume_flag,
    पूर्णाङ्क fsync_flag, पूर्णाङ्क follow_link_flag, पूर्णाङ्क inplace_flag)
{
	वर्ण *src_canon;
	पूर्णाङ्क ret;

	यदि ((src_canon = sftp_realpath(conn, src)) == रिक्त) {
		error("download \"%s\": path canonicalization failed", src);
		प्रत्यागम -1;
	}

	ret = download_dir_आन्तरिकम्(conn, src_canon, dst, 0,
	    dirattrib, preserve_flag, print_flag, resume_flag, fsync_flag,
	    follow_link_flag, inplace_flag);
	मुक्त(src_canon);
	प्रत्यागम ret;
}

पूर्णाङ्क
sftp_upload(संरचना sftp_conn *conn, ध्रुव वर्ण *local_मार्गः,
    ध्रुव वर्ण *remote_मार्गः, पूर्णाङ्क preserve_flag, पूर्णाङ्क resume,
    पूर्णाङ्क fsync_flag, पूर्णाङ्क inplace_flag)
{
	पूर्णाङ्क r, local_fd;
	u_int openmode, id, स्थितिः = SSH2_FX_OK, status2, reordered = 0;
	off_t विस्थापनम्, प्रगतिः_गणक;
	u_char type, *handle, *दत्त;
	संरचना sshbuf *सन्देशः;
	संरचना stat sb;
	Attrib a, t, c;
	uint32_t startid, ackid;
	uint64_t highwater = 0, maxack = 0;
	संरचना request *ack = रिक्त;
	संरचना अनुरोधाः acks;
	आकार_t handle_len;

	debug2_f("upload local \"%s\" to remote \"%s\"",
	    local_मार्गः, remote_मार्गः);

	TAILQ_INIT(&acks);

	यदि ((local_fd = उद्घाटय(local_मार्गः, O_RDONLY)) == -1) {
		error("open local \"%s\": %s", local_मार्गः, strerror(errno));
		प्रत्यागम(-1);
	}
	यदि (fstat(local_fd, &sb) == -1) {
		error("fstat local \"%s\": %s", local_मार्गः, strerror(errno));
		close(local_fd);
		प्रत्यागम(-1);
	}
	यदि (!S_ISREG(sb.st_mode)) {
		error("local \"%s\" is not a regular file", local_मार्गः);
		close(local_fd);
		प्रत्यागम(-1);
	}
	stat_गन्तव्यम्_attrib(&sb, &a);

	a.flags &= ~SSH2_FILEXFER_ATTR_आकार;
	a.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a.perm &= 0777;
	यदि (!preserve_flag)
		a.flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;

	यदि (resume) {
		/* Get remote file size if it exists */
		यदि (sftp_stat(conn, remote_मार्गः, 0, &c) != 0) {
			close(local_fd);
			प्रत्यागम -1;
		}

		यदि ((off_t)c.आकार >= sb.st_size) {
			error("resume \"%s\": destination file "
			    "same size or larger", local_मार्गः);
			close(local_fd);
			प्रत्यागम -1;
		}

		यदि (lseek(local_fd, (off_t)c.आकार, SEEK_SET) == -1) {
			close(local_fd);
			प्रत्यागम -1;
		}
		highwater = c.आकार;
	}

	openmode = SSH2_FXF_WRITE|SSH2_FXF_CREAT;
	यदि (resume)
		openmode |= SSH2_FXF_APPEND;
	अन्यथा यदि (!inplace_flag)
		openmode |= SSH2_FXF_TRUNC;

	/* Send open request */
	यदि (send_open(conn, remote_मार्गः, "dest", openmode, &a,
	    &handle, &handle_len) != 0) {
		close(local_fd);
		प्रत्यागम -1;
	}

	id = conn->सन्देशः_id;
	startid = ackid = id + 1;
	दत्त = xmalloc(conn->upload_buflen);

	/* Read from local and write to remote */
	विस्थापनम् = प्रगतिः_गणक = (resume ? c.आकार : 0);
	यदि (showprogress) {
		start_प्रगतिः_meter(प्रगतिः_meter_मार्गः(local_मार्गः),
		    sb.st_size, &प्रगतिः_गणक);
	}

	यदि ((सन्देशः = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	प्रति (;;) {
		पूर्णाङ्क len;

		/*
		 * Can't use atomicio here because it returns 0 on EOF,
		 * thus losing the last block of the file.
		 * Simulate an EOF on interrupt, allowing ACKs from the
		 * server to drain.
		 */
		यदि (interrupted || स्थितिः != SSH2_FX_OK)
			len = 0;
		अन्यथा कुरु
			len = पठ(local_fd, दत्त, conn->upload_buflen);
		यावत् ((len == -1) &&
		    (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK));

		यदि (len == -1) {
			fatal("read local \"%s\": %s",
			    local_मार्गः, strerror(errno));
		} अन्यथा यदि (len != 0) {
			ack = request_पङ्क्तौ_निक्षिप(&acks, ++id, len, विस्थापनम्);
			sshbuf_reset(सन्देशः);
			यदि ((r = sshbuf_put_u8(सन्देशः, SSH2_FXP_WRITE)) != 0 ||
			    (r = sshbuf_put_u32(सन्देशः, ack->id)) != 0 ||
			    (r = sshbuf_put_string(सन्देशः, handle,
			    handle_len)) != 0 ||
			    (r = sshbuf_put_u64(सन्देशः, विस्थापनम्)) != 0 ||
			    (r = sshbuf_put_string(सन्देशः, दत्त, len)) != 0)
				fatal_fr(r, "compose");
			send_सन्देशः(conn, सन्देशः);
			debug3("Sent message SSH2_FXP_WRITE I:%u O:%llu S:%u",
			    id, (अचिह्नित दीर्घ दीर्घ)विस्थापनम्, len);
		} अन्यथा यदि (TAILQ_FIRST(&acks) == रिक्त)
			भङ्ग;

		यदि (ack == रिक्त)
			fatal("Unexpected ACK %u", id);

		यदि (id == startid || len == 0 ||
		    id - ackid >= conn->अङ्कः_अनुरोधाः) {
			u_int rid;

			sshbuf_reset(सन्देशः);
			get_सन्देशः(conn, सन्देशः);
			यदि ((r = sshbuf_get_u8(सन्देशः, &type)) != 0 ||
			    (r = sshbuf_get_u32(सन्देशः, &rid)) != 0)
				fatal_fr(r, "parse");

			यदि (type != SSH2_FXP_स्थितिः)
				fatal("Expected SSH2_FXP_STATUS(%d) packet, "
				    "got %d", SSH2_FXP_स्थितिः, type);

			यदि ((r = sshbuf_get_u32(सन्देशः, &status2)) != 0)
				fatal_fr(r, "parse status");
			debug3("SSH2_FXP_STATUS %u", status2);
			यदि (status2 != SSH2_FX_OK)
				स्थितिः = status2; /* remember errors */

			/* Find the request in our queue */
			यदि ((ack = request_find(&acks, rid)) == रिक्त)
				fatal("Can't find request for ID %u", rid);
			TAILQ_REMOVE(&acks, ack, tq);
			debug3("In write loop, ack for %u %zu bytes at %lld",
			    ack->id, ack->len, (अचिह्नित दीर्घ दीर्घ)ack->विस्थापनम्);
			++ackid;
			प्रगतिः_गणक += ack->len;
			/*
			 * Track both the highest offset acknowledged and the
			 * highest *contiguous* offset acknowledged.
			 * We'll need the latter for ftruncate()ing
			 * interrupted transfers.
			 */
			यदि (maxack < ack->विस्थापनम् + ack->len)
				maxack = ack->विस्थापनम् + ack->len;
			यदि (!reordered && ack->विस्थापनम् <= highwater)
				highwater = maxack;
			अन्यथा यदि (!reordered && ack->विस्थापनम् > highwater) {
				debug3_f("server reordered ACKs");
				reordered = 1;
			}
			मुक्त(ack);
		}
		विस्थापनम् += len;
		यदि (विस्थापनम् < 0)
			fatal_f("offset < 0");
	}
	sshbuf_free(सन्देशः);

	यदि (showprogress)
		stop_प्रगतिः_meter();
	मुक्त(दत्त);

	यदि (स्थितिः == SSH2_FX_OK && !interrupted) {
		/* we got everything */
		highwater = maxack;
	}
	यदि (स्थितिः != SSH2_FX_OK) {
		error("write remote \"%s\": %s", remote_मार्गः, fx2txt(स्थितिः));
		स्थितिः = SSH2_FX_FAILURE;
	}

	यदि (inplace_flag || (resume && (स्थितिः != SSH2_FX_OK || interrupted))) {
		debug("truncating at %llu", (अचिह्नित दीर्घ दीर्घ)highwater);
		attrib_clear(&t);
		t.flags = SSH2_FILEXFER_ATTR_आकार;
		t.आकार = highwater;
		sftp_fsetstat(conn, handle, handle_len, &t);
	}

	यदि (close(local_fd) == -1) {
		error("close local \"%s\": %s", local_मार्गः, strerror(errno));
		स्थितिः = SSH2_FX_FAILURE;
	}

	/* Override umask and utimes if asked */
	यदि (preserve_flag)
		sftp_fsetstat(conn, handle, handle_len, &a);

	यदि (fsync_flag)
		(शून्य)sftp_fsync(conn, handle, handle_len);

	यदि (sftp_close(conn, handle, handle_len) != 0)
		स्थितिः = SSH2_FX_FAILURE;

	मुक्त(handle);

	प्रत्यागम स्थितिः == SSH2_FX_OK ? 0 : -1;
}

स्थिर पूर्णाङ्क
upload_dir_आन्तरिकम्(संरचना sftp_conn *conn, ध्रुव वर्ण *src, ध्रुव वर्ण *dst,
    पूर्णाङ्क गभीरता, पूर्णाङ्क preserve_flag, पूर्णाङ्क print_flag, पूर्णाङ्क resume, पूर्णाङ्क fsync_flag,
    पूर्णाङ्क follow_link_flag, पूर्णाङ्क inplace_flag)
{
	पूर्णाङ्क created = 0, ret = 0;
	DIR *dirp;
	संरचना dirent *dp;
	वर्ण *filename, *new_src = रिक्त, *new_dst = रिक्त;
	संरचना stat sb;
	Attrib a, dirattrib;
	uint32_t saved_perm;

	debug2_f("upload local dir \"%s\" to remote \"%s\"", src, dst);

	यदि (गभीरता >= MAX_DIR_गभीरता) {
		error("Maximum directory depth exceeded: %d levels", गभीरता);
		प्रत्यागम -1;
	}

	यदि (stat(src, &sb) == -1) {
		error("stat local \"%s\": %s", src, strerror(errno));
		प्रत्यागम -1;
	}
	यदि (!S_ISDIR(sb.st_mode)) {
		error("\"%s\" is not a directory", src);
		प्रत्यागम -1;
	}
	यदि (print_flag && print_flag != SFTP_प्रगतिः_ONLY)
		mprintf("Entering %s\n", src);

	stat_गन्तव्यम्_attrib(&sb, &a);
	a.flags &= ~SSH2_FILEXFER_ATTR_आकार;
	a.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a.perm &= 01777;
	यदि (!preserve_flag)
		a.flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;

	/*
	 * sftp lacks a portable status value to match errno EEXIST,
	 * so if we get a failure back then we must check whether
	 * the path already existed and is a directory.  Ensure we can
	 * write to the directory we create for the duration of the transfer.
	 */
	saved_perm = a.perm;
	a.perm |= (S_IWUSR|S_IXUSR);
	यदि (sftp_mkdir(conn, dst, &a, 0) == 0)
		created = 1;
	अन्यथा {
		यदि (sftp_stat(conn, dst, 0, &dirattrib) != 0)
			प्रत्यागम -1;
		यदि (!S_ISDIR(dirattrib.perm)) {
			error("\"%s\" exists but is not a directory", dst);
			प्रत्यागम -1;
		}
	}
	a.perm = saved_perm;

	यदि ((dirp = opendir(src)) == रिक्त) {
		error("local opendir \"%s\": %s", src, strerror(errno));
		प्रत्यागम -1;
	}

	यावत् (((dp = readdir(dirp)) != रिक्त) && !interrupted) {
		यदि (dp->d_ino == 0)
			अनुवर्त;
		मुक्त(new_dst);
		मुक्त(new_src);
		filename = dp->d_name;
		new_dst = sftp_मार्गः_append(dst, filename);
		new_src = sftp_मार्गः_append(src, filename);

		यदि (वाक्यं_तुलय(filename, ".") == 0 || वाक्यं_तुलय(filename, "..") == 0)
			अनुवर्त;
		यदि (lstat(new_src, &sb) == -1) {
			logit("local lstat \"%s\": %s", filename,
			    strerror(errno));
			ret = -1;
			अनुवर्त;
		}
		यदि (S_ISLNK(sb.st_mode)) {
			यदि (!follow_link_flag) {
				logit("%s: not a regular file", filename);
				अनुवर्त;
			}
			/* Replace the stat contents with the symlink target */
			यदि (stat(new_src, &sb) == -1) {
				logit("local stat \"%s\": %s", filename,
				    strerror(errno));
				ret = -1;
				अनुवर्त;
			}
		}
		यदि (S_ISDIR(sb.st_mode)) {
			यदि (upload_dir_आन्तरिकम्(conn, new_src, new_dst,
			    गभीरता + 1, preserve_flag, print_flag, resume,
			    fsync_flag, follow_link_flag, inplace_flag) == -1)
				ret = -1;
		} अन्यथा यदि (S_ISREG(sb.st_mode)) {
			यदि (sftp_upload(conn, new_src, new_dst,
			    preserve_flag, resume, fsync_flag,
			    inplace_flag) == -1) {
				error("upload \"%s\" to \"%s\" failed",
				    new_src, new_dst);
				ret = -1;
			}
		} अन्यथा
			logit("%s: not a regular file", filename);
	}
	मुक्त(new_dst);
	मुक्त(new_src);

	यदि (created || preserve_flag)
		sftp_setstat(conn, dst, &a);

	(शून्य) closedir(dirp);
	प्रत्यागम ret;
}

पूर्णाङ्क
sftp_upload_dir(संरचना sftp_conn *conn, ध्रुव वर्ण *src, ध्रुव वर्ण *dst,
    पूर्णाङ्क preserve_flag, पूर्णाङ्क print_flag, पूर्णाङ्क resume, पूर्णाङ्क fsync_flag,
    पूर्णाङ्क follow_link_flag, पूर्णाङ्क inplace_flag)
{
	वर्ण *dst_canon;
	पूर्णाङ्क ret;

	यदि ((dst_canon = sftp_realpath(conn, dst)) == रिक्त) {
		error("upload \"%s\": path canonicalization failed", dst);
		प्रत्यागम -1;
	}

	ret = upload_dir_आन्तरिकम्(conn, src, dst_canon, 0, preserve_flag,
	    print_flag, resume, fsync_flag, follow_link_flag, inplace_flag);

	मुक्त(dst_canon);
	प्रत्यागम ret;
}

स्थिर शून्य
handle_dest_replies(संरचना sftp_conn *गन्तव्यम्, ध्रुव वर्ण *गन्तव्यम्_मार्गः, पूर्णाङ्क synchronous,
    u_int *nreqsp, u_int *write_errorp)
{
	संरचना sshbuf *सन्देशः;
	u_char type;
	u_int id, स्थितिः;
	पूर्णाङ्क r;
	संरचना pollfd pfd;

	यदि ((सन्देशः = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");

	/* Try to eat replies from the upload side */
	यावत् (*nreqsp > 0) {
		debug3_f("%u outstanding replies", *nreqsp);
		यदि (!synchronous) {
			/* Bail out if no data is ready to be read */
			pfd.fd = गन्तव्यम्->fd_अन्तर्;
			pfd.events = POLLIN;
			यदि ((r = poll(&pfd, 1, 0)) == -1) {
				यदि (errno == EINTR)
					भङ्ग;
				fatal_f("poll: %s", strerror(errno));
			} अन्यथा यदि (r == 0)
				भङ्ग; /* fd not ready */
		}
		sshbuf_reset(सन्देशः);
		get_सन्देशः(गन्तव्यम्, सन्देशः);

		यदि ((r = sshbuf_get_u8(सन्देशः, &type)) != 0 ||
		    (r = sshbuf_get_u32(सन्देशः, &id)) != 0)
			fatal_fr(r, "dest parse");
		debug3("Received dest reply T:%u I:%u R:%u", type, id, *nreqsp);
		यदि (type != SSH2_FXP_स्थितिः) {
			fatal_f("Expected SSH2_FXP_STATUS(%d) packet, got %d",
			    SSH2_FXP_स्थितिः, type);
		}
		यदि ((r = sshbuf_get_u32(सन्देशः, &स्थितिः)) != 0)
			fatal_fr(r, "parse dest status");
		debug3("dest SSH2_FXP_STATUS %u", स्थितिः);
		यदि (स्थितिः != SSH2_FX_OK) {
			/* record first error */
			यदि (*write_errorp == 0)
				*write_errorp = स्थितिः;
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
	sshbuf_free(सन्देशः);
}

पूर्णाङ्क
sftp_crossload(संरचना sftp_conn *from, संरचना sftp_conn *गन्तव्यम्,
    ध्रुव वर्ण *from_मार्गः, ध्रुव वर्ण *गन्तव्यम्_मार्गः,
    Attrib *a, पूर्णाङ्क preserve_flag)
{
	संरचना sshbuf *सन्देशः;
	पूर्णाङ्क write_error, read_error, r, आलोकितम्_zerolen = 0;
	uint64_t विस्थापनम् = 0, आकार;
	u_int id, buflen, अङ्कः_req, max_req, स्थितिः = SSH2_FX_OK;
	u_int अङ्कः_upload_req;
	off_t प्रगतिः_गणक;
	u_char *from_handle, *गन्तव्यम्_handle;
	आकार_t from_handle_len, गन्तव्यम्_handle_len;
	संरचना अनुरोधाः अनुरोधाः;
	संरचना request *req;
	u_char type;
	Attrib attr;

	debug2_f("crossload src \"%s\" to dst \"%s\"", from_मार्गः, गन्तव्यम्_मार्गः);

	TAILQ_INIT(&अनुरोधाः);

	यदि (a == रिक्त) {
		यदि (sftp_stat(from, from_मार्गः, 0, &attr) != 0)
			प्रत्यागम -1;
		a = &attr;
	}

	यदि ((a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) &&
	    (!S_ISREG(a->perm))) {
		error("download \"%s\": not a regular file", from_मार्गः);
		प्रत्यागम(-1);
	}
	यदि (a->flags & SSH2_FILEXFER_ATTR_आकार)
		आकार = a->आकार;
	अन्यथा
		आकार = 0;

	buflen = from->download_buflen;
	यदि (buflen > गन्तव्यम्->upload_buflen)
		buflen = गन्तव्यम्->upload_buflen;

	/* Send open request to read side */
	यदि (send_open(from, from_मार्गः, "origin", SSH2_FXF_READ, रिक्त,
	    &from_handle, &from_handle_len) != 0)
		प्रत्यागम -1;

	/* Send open request to write side */
	a->flags &= ~SSH2_FILEXFER_ATTR_आकार;
	a->flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a->perm &= 0777;
	यदि (!preserve_flag)
		a->flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;
	यदि (send_open(गन्तव्यम्, गन्तव्यम्_मार्गः, "dest",
	    SSH2_FXF_WRITE|SSH2_FXF_CREAT|SSH2_FXF_TRUNC, a,
	    &गन्तव्यम्_handle, &गन्तव्यम्_handle_len) != 0) {
		sftp_close(from, from_handle, from_handle_len);
		प्रत्यागम -1;
	}

	/* Read from remote "from" and write to remote "to" */
	विस्थापनम् = 0;
	write_error = read_error = अङ्कः_req = अङ्कः_upload_req = 0;
	max_req = 1;
	प्रगतिः_गणक = 0;

	यदि (showprogress && आकार != 0) {
		start_प्रगतिः_meter(प्रगतिः_meter_मार्गः(from_मार्गः),
		    आकार, &प्रगतिः_गणक);
	}
	यदि ((सन्देशः = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यावत् (अङ्कः_req > 0 || max_req > 0) {
		u_char *दत्त;
		आकार_t len;

		/*
		 * Simulate EOF on interrupt: stop sending new requests and
		 * allow outstanding requests to drain gracefully
		 */
		यदि (interrupted) {
			यदि (अङ्कः_req == 0) /* If we haven't started yet... */
				भङ्ग;
			max_req = 0;
		}

		/* Send some more requests */
		यावत् (अङ्कः_req < max_req) {
			debug3("Request range %llu -> %llu (%d/%d)",
			    (अचिह्नित दीर्घ दीर्घ)विस्थापनम्,
			    (अचिह्नित दीर्घ दीर्घ)विस्थापनम् + buflen - 1,
			    अङ्कः_req, max_req);
			req = request_पङ्क्तौ_निक्षिप(&अनुरोधाः, from->सन्देशः_id++,
			    buflen, विस्थापनम्);
			विस्थापनम् += buflen;
			अङ्कः_req++;
			send_read_request(from, req->id, req->विस्थापनम्,
			    req->len, from_handle, from_handle_len);
		}

		/* Try to eat replies from the upload side (nonblocking) */
		handle_dest_replies(गन्तव्यम्, गन्तव्यम्_मार्गः, 0,
		    &अङ्कः_upload_req, &write_error);

		sshbuf_reset(सन्देशः);
		get_सन्देशः(from, सन्देशः);
		यदि ((r = sshbuf_get_u8(सन्देशः, &type)) != 0 ||
		    (r = sshbuf_get_u32(सन्देशः, &id)) != 0)
			fatal_fr(r, "parse");
		debug3("Received origin reply T:%u I:%u R:%d",
		    type, id, max_req);

		/* Find the request in our queue */
		यदि ((req = request_find(&अनुरोधाः, id)) == रिक्त)
			fatal("Unexpected reply %u", id);

		विकल्प (type) {
		पक्ष SSH2_FXP_स्थितिः:
			यदि ((r = sshbuf_get_u32(सन्देशः, &स्थितिः)) != 0)
				fatal_fr(r, "parse status");
			यदि (स्थितिः != SSH2_FX_EOF)
				read_error = 1;
			max_req = 0;
			TAILQ_REMOVE(&अनुरोधाः, req, tq);
			मुक्त(req);
			अङ्कः_req--;
			भङ्ग;
		पक्ष SSH2_FXP_दत्त:
			यदि ((r = sshbuf_get_string(सन्देशः, &दत्त, &len)) != 0)
				fatal_fr(r, "parse data");
			debug3("Received data %llu -> %llu",
			    (अचिह्नित दीर्घ दीर्घ)req->विस्थापनम्,
			    (अचिह्नित दीर्घ दीर्घ)req->विस्थापनम् + len - 1);
			यदि (len > req->len)
				fatal("Received more data than asked for "
				    "%zu > %zu", len, req->len);
			यदि (len == 0) {
				यदि (आलोकितम्_zerolen)
					fatal_f("server sent zero data length");
				आलोकितम्_zerolen = 1;
			}

			/* Write this chunk out to the destination */
			sshbuf_reset(सन्देशः);
			यदि ((r = sshbuf_put_u8(सन्देशः, SSH2_FXP_WRITE)) != 0 ||
			    (r = sshbuf_put_u32(सन्देशः, गन्तव्यम्->सन्देशः_id++)) != 0 ||
			    (r = sshbuf_put_string(सन्देशः, गन्तव्यम्_handle,
			    गन्तव्यम्_handle_len)) != 0 ||
			    (r = sshbuf_put_u64(सन्देशः, req->विस्थापनम्)) != 0 ||
			    (r = sshbuf_put_string(सन्देशः, दत्त, len)) != 0)
				fatal_fr(r, "compose write");
			send_सन्देशः(गन्तव्यम्, सन्देशः);
			debug3("Sent message SSH2_FXP_WRITE I:%u O:%llu S:%zu",
			    id, (अचिह्नित दीर्घ दीर्घ)विस्थापनम्, len);
			अङ्कः_upload_req++;
			प्रगतिः_गणक += len;
			मुक्त(दत्त);

			यदि (len == req->len) {
				TAILQ_REMOVE(&अनुरोधाः, req, tq);
				मुक्त(req);
				अङ्कः_req--;
			} अन्यथा {
				/* Resend the request for the missing data */
				debug3("Short data block, re-requesting "
				    "%llu -> %llu (%2d)",
				    (अचिह्नित दीर्घ दीर्घ)req->विस्थापनम् + len,
				    (अचिह्नित दीर्घ दीर्घ)req->विस्थापनम् +
				    req->len - 1, अङ्कः_req);
				req->id = from->सन्देशः_id++;
				req->len -= len;
				req->विस्थापनम् += len;
				send_read_request(from, req->id,
				    req->विस्थापनम्, req->len,
				    from_handle, from_handle_len);
				/* Reduce the request size */
				यदि (len < buflen)
					buflen = अधिकतमम्(MIN_READ_आकार, len);
			}
			यदि (max_req > 0) { /* max_req = 0 iff EOF received */
				यदि (आकार > 0 && विस्थापनम् > आकार) {
					/* Only one request at a time
					 * after the expected EOF */
					debug3("Finish at %llu (%2d)",
					    (अचिह्नित दीर्घ दीर्घ)विस्थापनम्,
					    अङ्कः_req);
					max_req = 1;
				} अन्यथा यदि (max_req < from->अङ्कः_अनुरोधाः) {
					++max_req;
				}
			}
			भङ्ग;
		स्वभाव:
			fatal("Expected SSH2_FXP_DATA(%u) packet, got %u",
			    SSH2_FXP_दत्त, type);
		}
	}

	यदि (showprogress && आकार)
		stop_प्रगतिः_meter();

	/* Drain replies from the server (blocking) */
	debug3_f("waiting for %u replies from destination", अङ्कः_upload_req);
	handle_dest_replies(गन्तव्यम्, गन्तव्यम्_मार्गः, 1, &अङ्कः_upload_req, &write_error);

	/* Sanity check */
	यदि (TAILQ_FIRST(&अनुरोधाः) != रिक्त)
		fatal("Transfer complete, but requests still in queue");
	/* Truncate at 0 length on interrupt or error to avoid holes at dest */
	यदि (read_error || write_error || interrupted) {
		debug("truncating \"%s\" at 0", गन्तव्यम्_मार्गः);
		sftp_close(गन्तव्यम्, गन्तव्यम्_handle, गन्तव्यम्_handle_len);
		मुक्त(गन्तव्यम्_handle);
		यदि (send_open(गन्तव्यम्, गन्तव्यम्_मार्गः, "dest",
		    SSH2_FXF_WRITE|SSH2_FXF_CREAT|SSH2_FXF_TRUNC, a,
		    &गन्तव्यम्_handle, &गन्तव्यम्_handle_len) != 0) {
			error("dest truncate \"%s\" failed", गन्तव्यम्_मार्गः);
			गन्तव्यम्_handle = रिक्त;
		}
	}
	यदि (read_error) {
		error("read origin \"%s\": %s", from_मार्गः, fx2txt(स्थितिः));
		स्थितिः = -1;
		sftp_close(from, from_handle, from_handle_len);
		यदि (गन्तव्यम्_handle != रिक्त)
			sftp_close(गन्तव्यम्, गन्तव्यम्_handle, गन्तव्यम्_handle_len);
	} अन्यथा यदि (write_error) {
		error("write dest \"%s\": %s", गन्तव्यम्_मार्गः, fx2txt(write_error));
		स्थितिः = SSH2_FX_FAILURE;
		sftp_close(from, from_handle, from_handle_len);
		यदि (गन्तव्यम्_handle != रिक्त)
			sftp_close(गन्तव्यम्, गन्तव्यम्_handle, गन्तव्यम्_handle_len);
	} अन्यथा {
		यदि (sftp_close(from, from_handle, from_handle_len) != 0 ||
		    interrupted)
			स्थितिः = -1;
		अन्यथा
			स्थितिः = SSH2_FX_OK;
		यदि (गन्तव्यम्_handle != रिक्त) {
			/* Need to resend utimes after write */
			यदि (preserve_flag)
				sftp_fsetstat(गन्तव्यम्, गन्तव्यम्_handle, गन्तव्यम्_handle_len, a);
			sftp_close(गन्तव्यम्, गन्तव्यम्_handle, गन्तव्यम्_handle_len);
		}
	}
	sshbuf_free(सन्देशः);
	मुक्त(from_handle);
	मुक्त(गन्तव्यम्_handle);

	प्रत्यागम स्थितिः == SSH2_FX_OK ? 0 : -1;
}

स्थिर पूर्णाङ्क
crossload_dir_आन्तरिकम्(संरचना sftp_conn *from, संरचना sftp_conn *गन्तव्यम्,
    ध्रुव वर्ण *from_मार्गः, ध्रुव वर्ण *गन्तव्यम्_मार्गः,
    पूर्णाङ्क गभीरता, Attrib *dirattrib, पूर्णाङ्क preserve_flag, पूर्णाङ्क print_flag,
    पूर्णाङ्क follow_link_flag)
{
	पूर्णाङ्क i, ret = 0, created = 0;
	SFTP_DIRENT **dir_entries;
	वर्ण *filename, *new_from_मार्गः = रिक्त, *new_गन्तव्यम्_मार्गः = रिक्त;
	बहुलकम्_t बहुलकम् = 0777;
	Attrib *a, curdir, ldirattrib, newdir, lsym;

	debug2_f("crossload dir src \"%s\" to dst \"%s\"", from_मार्गः, गन्तव्यम्_मार्गः);

	यदि (गभीरता >= MAX_DIR_गभीरता) {
		error("Maximum directory depth exceeded: %d levels", गभीरता);
		प्रत्यागम -1;
	}

	यदि (dirattrib == रिक्त) {
		यदि (sftp_stat(from, from_मार्गः, 1, &ldirattrib) != 0) {
			error("stat remote \"%s\" failed", from_मार्गः);
			प्रत्यागम -1;
		}
		dirattrib = &ldirattrib;
	}
	यदि (!S_ISDIR(dirattrib->perm)) {
		error("\"%s\" is not a directory", from_मार्गः);
		प्रत्यागम -1;
	}
	यदि (print_flag && print_flag != SFTP_प्रगतिः_ONLY)
		mprintf("Retrieving %s\n", from_मार्गः);

	curdir = *dirattrib; /* dirattrib will be clobbered */
	curdir.flags &= ~SSH2_FILEXFER_ATTR_आकार;
	curdir.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	यदि ((curdir.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) == 0) {
		debug("Origin did not send permissions for "
		    "directory \"%s\"", गन्तव्यम्_मार्गः);
		curdir.perm = S_IWUSR|S_IXUSR;
		curdir.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
	}
	/* We need to be able to write to the directory while we transfer it */
	बहुलकम् = curdir.perm & 01777;
	curdir.perm = बहुलकम् | (S_IWUSR|S_IXUSR);

	/*
	 * sftp lacks a portable status value to match errno EEXIST,
	 * so if we get a failure back then we must check whether
	 * the path already existed and is a directory.  Ensure we can
	 * write to the directory we create for the duration of the transfer.
	 */
	यदि (sftp_mkdir(गन्तव्यम्, गन्तव्यम्_मार्गः, &curdir, 0) == 0)
		created = 1;
	अन्यथा {
		यदि (sftp_stat(गन्तव्यम्, गन्तव्यम्_मार्गः, 0, &newdir) != 0)
			प्रत्यागम -1;
		यदि (!S_ISDIR(newdir.perm)) {
			error("\"%s\" exists but is not a directory", गन्तव्यम्_मार्गः);
			प्रत्यागम -1;
		}
	}
	curdir.perm = बहुलकम्;

	यदि (sftp_readdir(from, from_मार्गः, &dir_entries) == -1) {
		error("origin readdir \"%s\" failed", from_मार्गः);
		प्रत्यागम -1;
	}

	प्रति (i = 0; dir_entries[i] != रिक्त && !interrupted; i++) {
		मुक्त(new_from_मार्गः);
		मुक्त(new_गन्तव्यम्_मार्गः);

		filename = dir_entries[i]->filename;
		new_from_मार्गः = sftp_मार्गः_append(from_मार्गः, filename);
		new_गन्तव्यम्_मार्गः = sftp_मार्गः_append(गन्तव्यम्_मार्गः, filename);

		a = &dir_entries[i]->a;
		यदि (S_ISLNK(a->perm)) {
			यदि (!follow_link_flag) {
				logit("%s: not a regular file", filename);
				अनुवर्त;
			}
			/* Replace the stat contents with the symlink target */
			यदि (sftp_stat(from, new_from_मार्गः, 1, &lsym) != 0) {
				logit("remote stat \"%s\" failed",
				    new_from_मार्गः);
				ret = -1;
				अनुवर्त;
			}
			a = &lsym;
		}
		यदि (S_ISDIR(a->perm)) {
			यदि (वाक्यं_तुलय(filename, ".") == 0 ||
			    वाक्यं_तुलय(filename, "..") == 0)
				अनुवर्त;
			यदि (crossload_dir_आन्तरिकम्(from, गन्तव्यम्,
			    new_from_मार्गः, new_गन्तव्यम्_मार्गः,
			    गभीरता + 1, a, preserve_flag,
			    print_flag, follow_link_flag) == -1)
				ret = -1;
		} अन्यथा यदि (S_ISREG(a->perm)) {
			यदि (sftp_crossload(from, गन्तव्यम्, new_from_मार्गः,
			    new_गन्तव्यम्_मार्गः, a, preserve_flag) == -1) {
				error("crossload \"%s\" to \"%s\" failed",
				    new_from_मार्गः, new_गन्तव्यम्_मार्गः);
				ret = -1;
			}
		} अन्यथा {
			logit("origin \"%s\": not a regular file",
			    new_from_मार्गः);
		}
	}
	मुक्त(new_गन्तव्यम्_मार्गः);
	मुक्त(new_from_मार्गः);

	यदि (created || preserve_flag)
		sftp_setstat(गन्तव्यम्, गन्तव्यम्_मार्गः, &curdir);

	sftp_free_dirents(dir_entries);

	प्रत्यागम ret;
}

पूर्णाङ्क
sftp_crossload_dir(संरचना sftp_conn *from, संरचना sftp_conn *गन्तव्यम्,
    ध्रुव वर्ण *from_मार्गः, ध्रुव वर्ण *गन्तव्यम्_मार्गः,
    Attrib *dirattrib, पूर्णाङ्क preserve_flag, पूर्णाङ्क print_flag, पूर्णाङ्क follow_link_flag)
{
	वर्ण *from_मार्गः_canon;
	पूर्णाङ्क ret;

	यदि ((from_मार्गः_canon = sftp_realpath(from, from_मार्गः)) == रिक्त) {
		error("crossload \"%s\": path canonicalization failed",
		    from_मार्गः);
		प्रत्यागम -1;
	}

	ret = crossload_dir_आन्तरिकम्(from, गन्तव्यम्, from_मार्गः_canon, गन्तव्यम्_मार्गः, 0,
	    dirattrib, preserve_flag, print_flag, follow_link_flag);
	मुक्त(from_मार्गः_canon);
	प्रत्यागम ret;
}

पूर्णाङ्क
sftp_can_get_users_groups_by_id(संरचना sftp_conn *conn)
{
	प्रत्यागम (conn->exts & SFTP_EXT_GETUSERSGROUPS_BY_ID) != 0;
}

पूर्णाङ्क
sftp_get_users_groups_by_id(संरचना sftp_conn *conn,
    ध्रुव u_int *uids, u_int nuids,
    ध्रुव u_int *gids, u_int ngids,
    वर्ण ***usernamesp, वर्ण ***groupnamesp)
{
	संरचना sshbuf *सन्देशः, *uidbuf, *gidbuf;
	u_int i, expected_id, id;
	वर्ण *name, **usernames = रिक्त, **groupnames = रिक्त;
	u_char type;
	पूर्णाङ्क r;

	*usernamesp = *groupnamesp = रिक्त;
	यदि (!sftp_can_get_users_groups_by_id(conn))
		प्रत्यागम SSH_ERR_FEATURE_UNSUPPORTED;

	यदि ((सन्देशः = sshbuf_new()) == रिक्त ||
	    (uidbuf = sshbuf_new()) == रिक्त ||
	    (gidbuf = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	expected_id = id = conn->सन्देशः_id++;
	debug2("Sending SSH2_FXP_EXTENDED(users-groups-by-id@openssh.com)");
	प्रति (i = 0; i < nuids; i++) {
		यदि ((r = sshbuf_put_u32(uidbuf, uids[i])) != 0)
			fatal_fr(r, "compose uids");
	}
	प्रति (i = 0; i < ngids; i++) {
		यदि ((r = sshbuf_put_u32(gidbuf, gids[i])) != 0)
			fatal_fr(r, "compose gids");
	}
	यदि ((r = sshbuf_put_u8(सन्देशः, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(सन्देशः, id)) != 0 ||
	    (r = sshbuf_put_cstring(सन्देशः,
	    "users-groups-by-id@openssh.com")) != 0 ||
	    (r = sshbuf_put_stringb(सन्देशः, uidbuf)) != 0 ||
	    (r = sshbuf_put_stringb(सन्देशः, gidbuf)) != 0)
		fatal_fr(r, "compose");
	send_सन्देशः(conn, सन्देशः);
	get_सन्देशः(conn, सन्देशः);
	यदि ((r = sshbuf_get_u8(सन्देशः, &type)) != 0 ||
	    (r = sshbuf_get_u32(सन्देशः, &id)) != 0)
		fatal_fr(r, "parse");
	यदि (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	यदि (type == SSH2_FXP_स्थितिः) {
		u_int स्थितिः;
		वर्ण *errmsg;

		यदि ((r = sshbuf_get_u32(सन्देशः, &स्थितिः)) != 0 ||
		    (r = sshbuf_get_cstring(सन्देशः, &errmsg, रिक्त)) != 0)
			fatal_fr(r, "parse status");
		error("users-groups-by-id %s",
		    *errmsg == '\0' ? fx2txt(स्थितिः) : errmsg);
		मुक्त(errmsg);
		sshbuf_free(सन्देशः);
		sshbuf_free(uidbuf);
		sshbuf_free(gidbuf);
		प्रत्यागम -1;
	} अन्यथा यदि (type != SSH2_FXP_EXTENDED_प्रत्युत्तरम्)
		fatal("Expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_प्रत्युत्तरम्, type);

	/* reuse */
	sshbuf_free(uidbuf);
	sshbuf_free(gidbuf);
	uidbuf = gidbuf = रिक्त;
	यदि ((r = sshbuf_froms(सन्देशः, &uidbuf)) != 0 ||
	    (r = sshbuf_froms(सन्देशः, &gidbuf)) != 0)
		fatal_fr(r, "parse response");
	यदि (nuids > 0) {
		usernames = xcalloc(nuids, परिमाण(*usernames));
		प्रति (i = 0; i < nuids; i++) {
			यदि ((r = sshbuf_get_cstring(uidbuf, &name, रिक्त)) != 0)
				fatal_fr(r, "parse user name");
			/* Handle unresolved names */
			यदि (*name == '\0') {
				मुक्त(name);
				name = रिक्त;
			}
			usernames[i] = name;
		}
	}
	यदि (ngids > 0) {
		groupnames = xcalloc(ngids, परिमाण(*groupnames));
		प्रति (i = 0; i < ngids; i++) {
			यदि ((r = sshbuf_get_cstring(gidbuf, &name, रिक्त)) != 0)
				fatal_fr(r, "parse user name");
			/* Handle unresolved names */
			यदि (*name == '\0') {
				मुक्त(name);
				name = रिक्त;
			}
			groupnames[i] = name;
		}
	}
	यदि (sshbuf_len(uidbuf) != 0)
		fatal_f("unexpected extra username data");
	यदि (sshbuf_len(gidbuf) != 0)
		fatal_f("unexpected extra groupname data");
	sshbuf_free(uidbuf);
	sshbuf_free(gidbuf);
	sshbuf_free(सन्देशः);
	/* success */
	*usernamesp = usernames;
	*groupnamesp = groupnames;
	प्रत्यागम 0;
}

वर्ण *
sftp_मार्गः_append(ध्रुव वर्ण *p1, ध्रुव वर्ण *p2)
{
	वर्ण *ret;
	आकार_t len = वाक्यदैर्घ्यम्(p1) + वाक्यदैर्घ्यम्(p2) + 2;

	ret = xmalloc(len);
	strlcpy(ret, p1, len);
	यदि (p1[0] != '\0' && p1[वाक्यदैर्घ्यम्(p1) - 1] != '/')
		strlcat(ret, "/", len);
	strlcat(ret, p2, len);

	प्रत्यागम(ret);
}

/*
 * Arg p must be dynamically allocated.  It will either be returned or
 * freed and a replacement allocated.  Caller must free returned string.
 */
वर्ण *
sftp_make_absolute(वर्ण *p, ध्रुव वर्ण *pwd)
{
	वर्ण *abs_str;

	/* Derelativise */
	यदि (p && !मार्गः_absolute(p)) {
		abs_str = sftp_मार्गः_append(pwd, p);
		मुक्त(p);
		प्रत्यागम(abs_str);
	} अन्यथा
		प्रत्यागम(p);
}

पूर्णाङ्क
sftp_remote_is_dir(संरचना sftp_conn *conn, ध्रुव वर्ण *मार्गः)
{
	Attrib a;

	/* XXX: report errors? */
	यदि (sftp_stat(conn, मार्गः, 1, &a) != 0)
		प्रत्यागम(0);
	यदि (!(a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS))
		प्रत्यागम(0);
	प्रत्यागम S_ISDIR(a.perm);
}


/* Check whether path returned from glob(..., GLOB_MARK, ...) is a directory */
पूर्णाङ्क
sftp_globpath_is_dir(ध्रुव वर्ण *pathname)
{
	आकार_t l = वाक्यदैर्घ्यम्(pathname);

	प्रत्यागम l > 0 && pathname[l - 1] == '/';
}

