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

बाह्य चञ्चल संक_पूर्ण_प्रकार interrupted;
बाह्य पूर्णाङ्क showprogress;

/* Default size of buffer for up/download (fix sftp.1 scp.1 if changed) */
#define DEFAULT_COPY_BUFLEN	32768

/* Default number of concurrent xfer requests (fix sftp.1 scp.1 if changed) */
#define DEFAULT_अंक_REQUESTS	64

/* Minimum amount of data to read at a time */
#define MIN_READ_SIZE	512

/* Maximum depth to descend in directory trees */
#define MAX_DIR_DEPTH 64

/* Directory separator characters */
#ifdef HAVE_CYGWIN
# define SFTP_DIRECTORY_CHARS      "/\\"
#अन्यथा /* HAVE_CYGWIN */
# define SFTP_DIRECTORY_CHARS      "/"
#endif /* HAVE_CYGWIN */

संरचना sftp_conn {
	पूर्णाङ्क fd_in;
	पूर्णाङ्क fd_out;
	u_int download_buflen;
	u_int upload_buflen;
	u_int अंक_requests;
	u_int version;
	u_int संदेश_id;
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
	संरचना bwlimit bwlimit_in, bwlimit_out;
};

/* Tracks in-progress requests during file transfers */
संरचना request {
	u_int id;
	माप_प्रकार len;
	uint64_t offset;
	TAILQ_ENTRY(request) tq;
};
TAILQ_HEAD(requests, request);

स्थिर u_char *
get_handle(संरचना sftp_conn *conn, u_int expected_id, माप_प्रकार *len,
    ध्रुव वर्ण *errfmt, ...) __attribute__((format(म_लिखो, 4, 5)));

स्थिर संरचना request *
request_enqueue(संरचना requests *requests, u_int id, माप_प्रकार len,
    uint64_t offset)
{
	संरचना request *req;

	req = xcalloc(1, परिमाण(*req));
	req->id = id;
	req->len = len;
	req->offset = offset;
	TAILQ_INSERT_TAIL(requests, req, tq);
	प्रत्यागम req;
}

स्थिर संरचना request *
request_find(संरचना requests *requests, u_int id)
{
	संरचना request *req;

	प्रति (req = TAILQ_FIRST(requests);
	    req != रिक्त && req->id != id;
	    req = TAILQ_NEXT(req, tq))
		;
	प्रत्यागम req;
}

स्थिर पूर्णाङ्क
sftpio(शून्य *_bwlimit, माप_प्रकार amount)
{
	संरचना bwlimit *bwlimit = (संरचना bwlimit *)_bwlimit;

	refresh_progress_meter(0);
	यदि (bwlimit != रिक्त)
		bandwidth_limit(bwlimit, amount);
	प्रत्यागम 0;
}

स्थिर शून्य
send_संदेश(संरचना sftp_conn *conn, संरचना sshbuf *m)
{
	u_char mlen[4];
	संरचना iovec iov[2];

	यदि (sshbuf_len(m) > SFTP_MAX_संदेश_LENGTH)
		fatal("Outbound message too long %zu", sshbuf_len(m));

	/* Send length first */
	put_u32(mlen, sshbuf_len(m));
	iov[0].iov_base = mlen;
	iov[0].iov_len = परिमाण(mlen);
	iov[1].iov_base = (u_char *)sshbuf_ptr(m);
	iov[1].iov_len = sshbuf_len(m);

	यदि (atomiciov6(writev, conn->fd_out, iov, 2, sftpio,
	    conn->limit_kbps > 0 ? &conn->bwlimit_out : रिक्त) !=
	    sshbuf_len(m) + परिमाण(mlen))
		fatal("Couldn't send packet: %s", म_त्रुटि(त्रुटि_सं));

	sshbuf_reset(m);
}

स्थिर शून्य
get_संदेश_extended(संरचना sftp_conn *conn, संरचना sshbuf *m, पूर्णाङ्क initial)
{
	u_int संदेश_len;
	u_char *p;
	पूर्णाङ्क r;

	sshbuf_reset(m);
	यदि ((r = sshbuf_reserve(m, 4, &p)) != 0)
		fatal_fr(r, "reserve");
	यदि (atomicio6(पठ, conn->fd_in, p, 4, sftpio,
	    conn->limit_kbps > 0 ? &conn->bwlimit_in : रिक्त) != 4) {
		यदि (त्रुटि_सं == EPIPE || त्रुटि_सं == ECONNRESET)
			fatal("Connection closed");
		अन्यथा
			fatal("Couldn't read packet: %s", म_त्रुटि(त्रुटि_सं));
	}

	यदि ((r = sshbuf_get_u32(m, &संदेश_len)) != 0)
		fatal_fr(r, "sshbuf_get_u32");
	यदि (संदेश_len > SFTP_MAX_संदेश_LENGTH) {
		do_log2(initial ? SYSLOG_LEVEL_ERROR : SYSLOG_LEVEL_FATAL,
		    "Received message too long %u", संदेश_len);
		fatal("Ensure the remote shell produces no output "
		    "for non-interactive sessions.");
	}

	यदि ((r = sshbuf_reserve(m, संदेश_len, &p)) != 0)
		fatal_fr(r, "reserve");
	यदि (atomicio6(पठ, conn->fd_in, p, संदेश_len, sftpio,
	    conn->limit_kbps > 0 ? &conn->bwlimit_in : रिक्त)
	    != संदेश_len) {
		यदि (त्रुटि_सं == EPIPE)
			fatal("Connection closed");
		अन्यथा
			fatal("Read packet: %s", म_त्रुटि(त्रुटि_सं));
	}
}

स्थिर शून्य
get_संदेश(संरचना sftp_conn *conn, संरचना sshbuf *m)
{
	get_संदेश_extended(conn, m, 0);
}

स्थिर शून्य
send_string_request(संरचना sftp_conn *conn, u_int id, u_int code, ध्रुव वर्ण *s,
    u_int len)
{
	संरचना sshbuf *संदेश;
	पूर्णाङ्क r;

	यदि ((संदेश = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshbuf_put_u8(संदेश, code)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, id)) != 0 ||
	    (r = sshbuf_put_string(संदेश, s, len)) != 0)
		fatal_fr(r, "compose");
	send_संदेश(conn, संदेश);
	debug3("Sent message fd %d T:%u I:%u", conn->fd_out, code, id);
	sshbuf_free(संदेश);
}

स्थिर शून्य
send_string_attrs_request(संरचना sftp_conn *conn, u_int id, u_int code,
    ध्रुव शून्य *s, u_int len, Attrib *a)
{
	संरचना sshbuf *संदेश;
	पूर्णाङ्क r;

	यदि ((संदेश = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshbuf_put_u8(संदेश, code)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, id)) != 0 ||
	    (r = sshbuf_put_string(संदेश, s, len)) != 0 ||
	    (r = encode_attrib(संदेश, a)) != 0)
		fatal_fr(r, "compose");
	send_संदेश(conn, संदेश);
	debug3("Sent message fd %d T:%u I:%u F:0x%04x M:%05o",
	    conn->fd_out, code, id, a->flags, a->perm);
	sshbuf_free(संदेश);
}

स्थिर u_int
get_status(संरचना sftp_conn *conn, u_int expected_id)
{
	संरचना sshbuf *संदेश;
	u_char type;
	u_int id, status;
	पूर्णाङ्क r;

	यदि ((संदेश = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	get_संदेश(conn, संदेश);
	यदि ((r = sshbuf_get_u8(संदेश, &type)) != 0 ||
	    (r = sshbuf_get_u32(संदेश, &id)) != 0)
		fatal_fr(r, "compose");

	यदि (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	यदि (type != SSH2_FXP_STATUS)
		fatal("Expected SSH2_FXP_STATUS(%u) packet, got %u",
		    SSH2_FXP_STATUS, type);

	यदि ((r = sshbuf_get_u32(संदेश, &status)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(संदेश);

	debug3("SSH2_FXP_STATUS %u", status);

	प्रत्यागम status;
}

स्थिर u_char *
get_handle(संरचना sftp_conn *conn, u_int expected_id, माप_प्रकार *len,
    ध्रुव वर्ण *errfmt, ...)
{
	संरचना sshbuf *संदेश;
	u_int id, status;
	u_char type;
	u_char *handle;
	वर्ण errmsg[256];
	बहु_सूची args;
	पूर्णाङ्क r;

	बहु_शुरू(args, errfmt);
	यदि (errfmt != रिक्त)
		vsnprintf(errmsg, परिमाण(errmsg), errfmt, args);
	बहु_पूर्ण(args);

	यदि ((संदेश = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	get_संदेश(conn, संदेश);
	यदि ((r = sshbuf_get_u8(संदेश, &type)) != 0 ||
	    (r = sshbuf_get_u32(संदेश, &id)) != 0)
		fatal_fr(r, "parse");

	यदि (id != expected_id)
		fatal("%s: ID mismatch (%u != %u)",
		    errfmt == रिक्त ? __func__ : errmsg, id, expected_id);
	यदि (type == SSH2_FXP_STATUS) {
		यदि ((r = sshbuf_get_u32(संदेश, &status)) != 0)
			fatal_fr(r, "parse status");
		यदि (errfmt != रिक्त)
			error("%s: %s", errmsg, fx2txt(status));
		sshbuf_free(संदेश);
		प्रत्यागम(रिक्त);
	} अन्यथा यदि (type != SSH2_FXP_HANDLE)
		fatal("%s: Expected SSH2_FXP_HANDLE(%u) packet, got %u",
		    errfmt == रिक्त ? __func__ : errmsg, SSH2_FXP_HANDLE, type);

	यदि ((r = sshbuf_get_string(संदेश, &handle, len)) != 0)
		fatal_fr(r, "parse handle");
	sshbuf_free(संदेश);

	प्रत्यागम handle;
}

स्थिर पूर्णाङ्क
get_decode_stat(संरचना sftp_conn *conn, u_int expected_id, पूर्णाङ्क quiet, Attrib *a)
{
	संरचना sshbuf *संदेश;
	u_int id;
	u_char type;
	पूर्णाङ्क r;
	Attrib attr;

	यदि (a != रिक्त)
		स_रखो(a, '\0', परिमाण(*a));
	यदि ((संदेश = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	get_संदेश(conn, संदेश);

	यदि ((r = sshbuf_get_u8(संदेश, &type)) != 0 ||
	    (r = sshbuf_get_u32(संदेश, &id)) != 0)
		fatal_fr(r, "parse");

	यदि (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	यदि (type == SSH2_FXP_STATUS) {
		u_int status;

		यदि ((r = sshbuf_get_u32(संदेश, &status)) != 0)
			fatal_fr(r, "parse status");
		यदि (quiet)
			debug("stat remote: %s", fx2txt(status));
		अन्यथा
			error("stat remote: %s", fx2txt(status));
		sshbuf_free(संदेश);
		प्रत्यागम -1;
	} अन्यथा यदि (type != SSH2_FXP_ATTRS) {
		fatal("Expected SSH2_FXP_ATTRS(%u) packet, got %u",
		    SSH2_FXP_ATTRS, type);
	}
	यदि ((r = decode_attrib(संदेश, &attr)) != 0) {
		error_fr(r, "decode_attrib");
		sshbuf_free(संदेश);
		प्रत्यागम -1;
	}
	/* success */
	यदि (a != रिक्त)
		*a = attr;
	debug3("Received stat reply T:%u I:%u F:0x%04x M:%05o",
	    type, id, attr.flags, attr.perm);
	sshbuf_free(संदेश);

	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
get_decode_statvfs(संरचना sftp_conn *conn, संरचना sftp_statvfs *st,
    u_int expected_id, पूर्णाङ्क quiet)
{
	संरचना sshbuf *संदेश;
	u_char type;
	u_int id;
	uint64_t flag;
	पूर्णाङ्क r;

	यदि ((संदेश = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	get_संदेश(conn, संदेश);

	यदि ((r = sshbuf_get_u8(संदेश, &type)) != 0 ||
	    (r = sshbuf_get_u32(संदेश, &id)) != 0)
		fatal_fr(r, "parse");

	debug3("Received statvfs reply T:%u I:%u", type, id);
	यदि (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	यदि (type == SSH2_FXP_STATUS) {
		u_int status;

		यदि ((r = sshbuf_get_u32(संदेश, &status)) != 0)
			fatal_fr(r, "parse status");
		यदि (quiet)
			debug("remote statvfs: %s", fx2txt(status));
		अन्यथा
			error("remote statvfs: %s", fx2txt(status));
		sshbuf_free(संदेश);
		प्रत्यागम -1;
	} अन्यथा यदि (type != SSH2_FXP_EXTENDED_REPLY) {
		fatal("Expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_REPLY, type);
	}

	स_रखो(st, 0, परिमाण(*st));
	यदि ((r = sshbuf_get_u64(संदेश, &st->f_bsize)) != 0 ||
	    (r = sshbuf_get_u64(संदेश, &st->f_frsize)) != 0 ||
	    (r = sshbuf_get_u64(संदेश, &st->f_blocks)) != 0 ||
	    (r = sshbuf_get_u64(संदेश, &st->f_bfree)) != 0 ||
	    (r = sshbuf_get_u64(संदेश, &st->f_bavail)) != 0 ||
	    (r = sshbuf_get_u64(संदेश, &st->f_files)) != 0 ||
	    (r = sshbuf_get_u64(संदेश, &st->f_ffree)) != 0 ||
	    (r = sshbuf_get_u64(संदेश, &st->f_favail)) != 0 ||
	    (r = sshbuf_get_u64(संदेश, &st->f_fsid)) != 0 ||
	    (r = sshbuf_get_u64(संदेश, &flag)) != 0 ||
	    (r = sshbuf_get_u64(संदेश, &st->f_namemax)) != 0)
		fatal_fr(r, "parse statvfs");

	st->f_flag = (flag & SSH2_FXE_STATVFS_ST_RDONLY) ? ST_RDONLY : 0;
	st->f_flag |= (flag & SSH2_FXE_STATVFS_ST_NOSUID) ? ST_NOSUID : 0;

	sshbuf_free(संदेश);

	प्रत्यागम 0;
}

संरचना sftp_conn *
sftp_init(पूर्णाङ्क fd_in, पूर्णाङ्क fd_out, u_int transfer_buflen, u_int अंक_requests,
    uint64_t limit_kbps)
{
	u_char type;
	संरचना sshbuf *संदेश;
	संरचना sftp_conn *ret;
	पूर्णाङ्क r;

	ret = xcalloc(1, परिमाण(*ret));
	ret->संदेश_id = 1;
	ret->fd_in = fd_in;
	ret->fd_out = fd_out;
	ret->download_buflen = ret->upload_buflen =
	    transfer_buflen ? transfer_buflen : DEFAULT_COPY_BUFLEN;
	ret->अंक_requests =
	    अंक_requests ? अंक_requests : DEFAULT_अंक_REQUESTS;
	ret->exts = 0;
	ret->limit_kbps = 0;

	यदि ((संदेश = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshbuf_put_u8(संदेश, SSH2_FXP_INIT)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, SSH2_FILEXFER_VERSION)) != 0)
		fatal_fr(r, "parse");

	send_संदेश(ret, संदेश);

	get_संदेश_extended(ret, संदेश, 1);

	/* Expecting a VERSION reply */
	यदि ((r = sshbuf_get_u8(संदेश, &type)) != 0)
		fatal_fr(r, "parse type");
	यदि (type != SSH2_FXP_VERSION) {
		error("Invalid packet back from SSH2_FXP_INIT (type %u)",
		    type);
		sshbuf_free(संदेश);
		मुक्त(ret);
		प्रत्यागम(रिक्त);
	}
	यदि ((r = sshbuf_get_u32(संदेश, &ret->version)) != 0)
		fatal_fr(r, "parse version");

	debug2("Remote version: %u", ret->version);

	/* Check for extensions */
	यावत् (sshbuf_len(संदेश) > 0) {
		वर्ण *name;
		u_char *मूल्य;
		माप_प्रकार vlen;
		पूर्णाङ्क known = 0;

		यदि ((r = sshbuf_get_cstring(संदेश, &name, रिक्त)) != 0 ||
		    (r = sshbuf_get_string(संदेश, &मूल्य, &vlen)) != 0)
			fatal_fr(r, "parse extension");
		यदि (म_भेद(name, "posix-rename@openssh.com") == 0 &&
		    म_भेद((वर्ण *)मूल्य, "1") == 0) {
			ret->exts |= SFTP_EXT_POSIX_RENAME;
			known = 1;
		} अन्यथा यदि (म_भेद(name, "statvfs@openssh.com") == 0 &&
		    म_भेद((वर्ण *)मूल्य, "2") == 0) {
			ret->exts |= SFTP_EXT_STATVFS;
			known = 1;
		} अन्यथा यदि (म_भेद(name, "fstatvfs@openssh.com") == 0 &&
		    म_भेद((वर्ण *)मूल्य, "2") == 0) {
			ret->exts |= SFTP_EXT_FSTATVFS;
			known = 1;
		} अन्यथा यदि (म_भेद(name, "hardlink@openssh.com") == 0 &&
		    म_भेद((वर्ण *)मूल्य, "1") == 0) {
			ret->exts |= SFTP_EXT_HARDLINK;
			known = 1;
		} अन्यथा यदि (म_भेद(name, "fsync@openssh.com") == 0 &&
		    म_भेद((वर्ण *)मूल्य, "1") == 0) {
			ret->exts |= SFTP_EXT_FSYNC;
			known = 1;
		} अन्यथा यदि (म_भेद(name, "lsetstat@openssh.com") == 0 &&
		    म_भेद((वर्ण *)मूल्य, "1") == 0) {
			ret->exts |= SFTP_EXT_LSETSTAT;
			known = 1;
		} अन्यथा यदि (म_भेद(name, "limits@openssh.com") == 0 &&
		    म_भेद((वर्ण *)मूल्य, "1") == 0) {
			ret->exts |= SFTP_EXT_LIMITS;
			known = 1;
		} अन्यथा यदि (म_भेद(name, "expand-path@openssh.com") == 0 &&
		    म_भेद((वर्ण *)मूल्य, "1") == 0) {
			ret->exts |= SFTP_EXT_PATH_EXPAND;
			known = 1;
		} अन्यथा यदि (म_भेद(name, "copy-data") == 0 &&
		    म_भेद((वर्ण *)मूल्य, "1") == 0) {
			ret->exts |= SFTP_EXT_COPY_DATA;
			known = 1;
		} अन्यथा यदि (म_भेद(name,
		    "users-groups-by-id@openssh.com") == 0 &&
		    म_भेद((वर्ण *)मूल्य, "1") == 0) {
			ret->exts |= SFTP_EXT_GETUSERSGROUPS_BY_ID;
			known = 1;
		}
		यदि (known) {
			debug2("Server supports extension \"%s\" revision %s",
			    name, मूल्य);
		} अन्यथा {
			debug2("Unrecognised server extension \"%s\"", name);
		}
		मुक्त(name);
		मुक्त(मूल्य);
	}

	sshbuf_free(संदेश);

	/* Query the server for its limits */
	यदि (ret->exts & SFTP_EXT_LIMITS) {
		संरचना sftp_limits limits;
		यदि (sftp_get_limits(ret, &limits) != 0)
			fatal_f("limits failed");

		/* If the caller did not specify, find a good value */
		यदि (transfer_buflen == 0) {
			ret->download_buflen = MINIMUM(limits.read_length,
			    SFTP_MAX_संदेश_LENGTH - 1024);
			ret->upload_buflen = MINIMUM(limits.write_length,
			    SFTP_MAX_संदेश_LENGTH - 1024);
			ret->download_buflen = MAXIMUM(ret->download_buflen, 64);
			ret->upload_buflen = MAXIMUM(ret->upload_buflen, 64);
			debug3("server upload/download buffer sizes "
			    "%llu / %llu; using %u / %u",
			    (अचिन्हित दीर्घ दीर्घ)limits.write_length,
			    (अचिन्हित दीर्घ दीर्घ)limits.read_length,
			    ret->upload_buflen, ret->download_buflen);
		}
	}

	/* Some filexfer v.0 servers don't support large packets */
	यदि (ret->version == 0) {
		ret->download_buflen = MINIMUM(ret->download_buflen, 20480);
		ret->upload_buflen = MINIMUM(ret->upload_buflen, 20480);
	}

	ret->limit_kbps = limit_kbps;
	यदि (ret->limit_kbps > 0) {
		bandwidth_limit_init(&ret->bwlimit_in, ret->limit_kbps,
		    ret->download_buflen);
		bandwidth_limit_init(&ret->bwlimit_out, ret->limit_kbps,
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
sftp_proto_version(संरचना sftp_conn *conn)
{
	प्रत्यागम conn->version;
}

पूर्णाङ्क
sftp_get_limits(संरचना sftp_conn *conn, संरचना sftp_limits *limits)
{
	u_int id, संदेश_id;
	u_char type;
	संरचना sshbuf *संदेश;
	पूर्णाङ्क r;

	यदि ((conn->exts & SFTP_EXT_LIMITS) == 0) {
		error("Server does not support limits@openssh.com extension");
		प्रत्यागम -1;
	}

	यदि ((संदेश = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");

	id = conn->संदेश_id++;
	यदि ((r = sshbuf_put_u8(संदेश, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, id)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, "limits@openssh.com")) != 0)
		fatal_fr(r, "compose");
	send_संदेश(conn, संदेश);
	debug3("Sent message limits@openssh.com I:%u", id);

	get_संदेश(conn, संदेश);

	यदि ((r = sshbuf_get_u8(संदेश, &type)) != 0 ||
	    (r = sshbuf_get_u32(संदेश, &संदेश_id)) != 0)
		fatal_fr(r, "parse");

	debug3("Received limits reply T:%u I:%u", type, संदेश_id);
	यदि (id != संदेश_id)
		fatal("ID mismatch (%u != %u)", संदेश_id, id);
	यदि (type != SSH2_FXP_EXTENDED_REPLY) {
		debug_f("expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_REPLY, type);
		/* Disable the limits extension */
		conn->exts &= ~SFTP_EXT_LIMITS;
		sshbuf_free(संदेश);
		प्रत्यागम -1;
	}

	स_रखो(limits, 0, परिमाण(*limits));
	यदि ((r = sshbuf_get_u64(संदेश, &limits->packet_length)) != 0 ||
	    (r = sshbuf_get_u64(संदेश, &limits->read_length)) != 0 ||
	    (r = sshbuf_get_u64(संदेश, &limits->write_length)) != 0 ||
	    (r = sshbuf_get_u64(संदेश, &limits->open_handles)) != 0)
		fatal_fr(r, "parse limits");

	sshbuf_free(संदेश);

	प्रत्यागम 0;
}

पूर्णाङ्क
sftp_close(संरचना sftp_conn *conn, ध्रुव u_char *handle, u_int handle_len)
{
	u_int id, status;
	संरचना sshbuf *संदेश;
	पूर्णाङ्क r;

	यदि ((संदेश = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");

	id = conn->संदेश_id++;
	यदि ((r = sshbuf_put_u8(संदेश, SSH2_FXP_CLOSE)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, id)) != 0 ||
	    (r = sshbuf_put_string(संदेश, handle, handle_len)) != 0)
		fatal_fr(r, "parse");
	send_संदेश(conn, संदेश);
	debug3("Sent message SSH2_FXP_CLOSE I:%u", id);

	status = get_status(conn, id);
	यदि (status != SSH2_FX_OK)
		error("close remote: %s", fx2txt(status));

	sshbuf_free(संदेश);

	प्रत्यागम status == SSH2_FX_OK ? 0 : -1;
}


स्थिर पूर्णाङ्क
sftp_lsreaddir(संरचना sftp_conn *conn, ध्रुव वर्ण *path, पूर्णाङ्क print_flag,
    SFTP_DIRENT ***dir)
{
	संरचना sshbuf *संदेश;
	u_int गिनती, id, i, expected_id, ents = 0;
	माप_प्रकार handle_len;
	u_char type, *handle;
	पूर्णाङ्क status = SSH2_FX_FAILURE;
	पूर्णाङ्क r;

	यदि (dir)
		*dir = रिक्त;

	id = conn->संदेश_id++;

	यदि ((संदेश = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshbuf_put_u8(संदेश, SSH2_FXP_OPENDIR)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, id)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, path)) != 0)
		fatal_fr(r, "compose OPENDIR");
	send_संदेश(conn, संदेश);

	handle = get_handle(conn, id, &handle_len,
	    "remote readdir(\"%s\")", path);
	यदि (handle == रिक्त) {
		sshbuf_free(संदेश);
		प्रत्यागम -1;
	}

	यदि (dir) {
		ents = 0;
		*dir = xcalloc(1, परिमाण(**dir));
		(*dir)[0] = रिक्त;
	}

	प्रति (; !interrupted;) {
		id = expected_id = conn->संदेश_id++;

		debug3("Sending SSH2_FXP_READDIR I:%u", id);

		sshbuf_reset(संदेश);
		यदि ((r = sshbuf_put_u8(संदेश, SSH2_FXP_READDIR)) != 0 ||
		    (r = sshbuf_put_u32(संदेश, id)) != 0 ||
		    (r = sshbuf_put_string(संदेश, handle, handle_len)) != 0)
			fatal_fr(r, "compose READDIR");
		send_संदेश(conn, संदेश);

		sshbuf_reset(संदेश);

		get_संदेश(conn, संदेश);

		यदि ((r = sshbuf_get_u8(संदेश, &type)) != 0 ||
		    (r = sshbuf_get_u32(संदेश, &id)) != 0)
			fatal_fr(r, "parse");

		debug3("Received reply T:%u I:%u", type, id);

		यदि (id != expected_id)
			fatal("ID mismatch (%u != %u)", id, expected_id);

		यदि (type == SSH2_FXP_STATUS) {
			u_int rstatus;

			यदि ((r = sshbuf_get_u32(संदेश, &rstatus)) != 0)
				fatal_fr(r, "parse status");
			debug3("Received SSH2_FXP_STATUS %d", rstatus);
			यदि (rstatus == SSH2_FX_EOF)
				भङ्ग;
			error("Couldn't read directory: %s", fx2txt(rstatus));
			गच्छ out;
		} अन्यथा यदि (type != SSH2_FXP_NAME)
			fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
			    SSH2_FXP_NAME, type);

		यदि ((r = sshbuf_get_u32(संदेश, &गिनती)) != 0)
			fatal_fr(r, "parse count");
		यदि (गिनती > SSHBUF_SIZE_MAX)
			fatal_f("nonsensical number of entries");
		यदि (गिनती == 0)
			भङ्ग;
		debug3("Received %d SSH2_FXP_NAME responses", गिनती);
		प्रति (i = 0; i < गिनती; i++) {
			वर्ण *filename, *longname;
			Attrib a;

			यदि ((r = sshbuf_get_cstring(संदेश, &filename,
			    रिक्त)) != 0 ||
			    (r = sshbuf_get_cstring(संदेश, &longname,
			    रिक्त)) != 0)
				fatal_fr(r, "parse filenames");
			यदि ((r = decode_attrib(संदेश, &a)) != 0) {
				error_fr(r, "couldn't decode attrib");
				मुक्त(filename);
				मुक्त(longname);
				गच्छ out;
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
				    "during readdir of \"%s\"", filename, path);
			} अन्यथा यदि (dir) {
				*dir = xreallocarray(*dir, ents + 2, परिमाण(**dir));
				(*dir)[ents] = xcalloc(1, परिमाण(***dir));
				(*dir)[ents]->filename = xstrdup(filename);
				(*dir)[ents]->longname = xstrdup(longname);
				स_नकल(&(*dir)[ents]->a, &a, परिमाण(a));
				(*dir)[++ents] = रिक्त;
			}
			मुक्त(filename);
			मुक्त(longname);
		}
	}
	status = 0;

 out:
	sshbuf_free(संदेश);
	sftp_close(conn, handle, handle_len);
	मुक्त(handle);

	यदि (status != 0 && dir != रिक्त) {
		/* Don't return results on error */
		sftp_free_dirents(*dir);
		*dir = रिक्त;
	} अन्यथा यदि (interrupted && dir != रिक्त && *dir != रिक्त) {
		/* Don't return partial matches on interrupt */
		sftp_free_dirents(*dir);
		*dir = xcalloc(1, परिमाण(**dir));
		**dir = रिक्त;
	}

	प्रत्यागम status == SSH2_FX_OK ? 0 : -1;
}

पूर्णाङ्क
sftp_readdir(संरचना sftp_conn *conn, ध्रुव वर्ण *path, SFTP_DIRENT ***dir)
{
	प्रत्यागम sftp_lsreaddir(conn, path, 0, dir);
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
sftp_rm(संरचना sftp_conn *conn, ध्रुव वर्ण *path)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_REMOVE \"%s\"", path);

	id = conn->संदेश_id++;
	send_string_request(conn, id, SSH2_FXP_REMOVE, path, म_माप(path));
	status = get_status(conn, id);
	यदि (status != SSH2_FX_OK)
		error("remote delete %s: %s", path, fx2txt(status));
	प्रत्यागम status == SSH2_FX_OK ? 0 : -1;
}

पूर्णाङ्क
sftp_mkdir(संरचना sftp_conn *conn, ध्रुव वर्ण *path, Attrib *a, पूर्णाङ्क print_flag)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_MKDIR \"%s\"", path);

	id = conn->संदेश_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_MKDIR, path,
	    म_माप(path), a);

	status = get_status(conn, id);
	यदि (status != SSH2_FX_OK && print_flag)
		error("remote mkdir \"%s\": %s", path, fx2txt(status));

	प्रत्यागम status == SSH2_FX_OK ? 0 : -1;
}

पूर्णाङ्क
sftp_mkpath(संरचना sftp_conn *conn, ध्रुव वर्ण *path, Attrib *a, पूर्णाङ्क print_flag)
{
	वर्ण *slash, *tmp_path;
	पूर्णाङ्क done;

	tmp_path = xstrdup(path);
	slash = tmp_path;

	प्रति (;;) {
		slash += म_अखोज(slash, "/");
		slash += म_खोज(slash, "/");

		done = (*slash == '\0');
		*slash = '\0';

		यदि (!sftp_remote_is_dir(conn, tmp_path)) {
			यदि (sftp_mkdir(conn, tmp_path, a, print_flag) != 0) {
				मुक्त(tmp_path);
				प्रत्यागम -1;
			}
		}

		यदि (done)
			भङ्ग;

		*slash = '/';
	}

	मुक्त(tmp_path);
	प्रत्यागम 0;
}

पूर्णाङ्क
sftp_rmdir(संरचना sftp_conn *conn, ध्रुव वर्ण *path)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_RMDIR \"%s\"", path);

	id = conn->संदेश_id++;
	send_string_request(conn, id, SSH2_FXP_RMDIR, path,
	    म_माप(path));

	status = get_status(conn, id);
	यदि (status != SSH2_FX_OK)
		error("remote rmdir \"%s\": %s", path, fx2txt(status));

	प्रत्यागम status == SSH2_FX_OK ? 0 : -1;
}

पूर्णाङ्क
sftp_stat(संरचना sftp_conn *conn, ध्रुव वर्ण *path, पूर्णाङ्क quiet, Attrib *a)
{
	u_int id;

	debug2("Sending SSH2_FXP_STAT \"%s\"", path);

	id = conn->संदेश_id++;

	send_string_request(conn, id,
	    conn->version == 0 ? SSH2_FXP_STAT_VERSION_0 : SSH2_FXP_STAT,
	    path, म_माप(path));

	प्रत्यागम get_decode_stat(conn, id, quiet, a);
}

पूर्णाङ्क
sftp_lstat(संरचना sftp_conn *conn, ध्रुव वर्ण *path, पूर्णाङ्क quiet, Attrib *a)
{
	u_int id;

	यदि (conn->version == 0) {
		do_log2(quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_INFO,
		    "Server version does not support lstat operation");
		प्रत्यागम sftp_stat(conn, path, quiet, a);
	}

	id = conn->संदेश_id++;
	send_string_request(conn, id, SSH2_FXP_LSTAT, path,
	    म_माप(path));

	प्रत्यागम get_decode_stat(conn, id, quiet, a);
}

#ifdef notyet
पूर्णाङ्क
sftp_fstat(संरचना sftp_conn *conn, ध्रुव u_char *handle, u_int handle_len,
    पूर्णाङ्क quiet, Attrib *a)
{
	u_int id;

	debug2("Sending SSH2_FXP_FSTAT \"%s\"");

	id = conn->संदेश_id++;
	send_string_request(conn, id, SSH2_FXP_FSTAT, handle,
	    handle_len);

	प्रत्यागम get_decode_stat(conn, id, quiet, a);
}
#endif

पूर्णाङ्क
sftp_setstat(संरचना sftp_conn *conn, ध्रुव वर्ण *path, Attrib *a)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_SETSTAT \"%s\"", path);

	id = conn->संदेश_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_SETSTAT, path,
	    म_माप(path), a);

	status = get_status(conn, id);
	यदि (status != SSH2_FX_OK)
		error("remote setstat \"%s\": %s", path, fx2txt(status));

	प्रत्यागम status == SSH2_FX_OK ? 0 : -1;
}

पूर्णाङ्क
sftp_fsetstat(संरचना sftp_conn *conn, ध्रुव u_char *handle, u_int handle_len,
    Attrib *a)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_FSETSTAT");

	id = conn->संदेश_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_FSETSTAT, handle,
	    handle_len, a);

	status = get_status(conn, id);
	यदि (status != SSH2_FX_OK)
		error("remote fsetstat: %s", fx2txt(status));

	प्रत्यागम status == SSH2_FX_OK ? 0 : -1;
}

/* Implements both the realpath and expand-path operations */
स्थिर वर्ण *
sftp_realpath_expand(संरचना sftp_conn *conn, ध्रुव वर्ण *path, पूर्णाङ्क expand)
{
	संरचना sshbuf *संदेश;
	u_int expected_id, गिनती, id;
	वर्ण *filename, *longname;
	Attrib a;
	u_char type;
	पूर्णाङ्क r;
	ध्रुव वर्ण *what = "SSH2_FXP_REALPATH";

	यदि (expand)
		what = "expand-path@openssh.com";
	यदि ((संदेश = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");

	expected_id = id = conn->संदेश_id++;
	यदि (expand) {
		debug2("Sending SSH2_FXP_EXTENDED(expand-path@openssh.com) "
		    "\"%s\"", path);
		यदि ((r = sshbuf_put_u8(संदेश, SSH2_FXP_EXTENDED)) != 0 ||
		    (r = sshbuf_put_u32(संदेश, id)) != 0 ||
		    (r = sshbuf_put_cstring(संदेश,
		    "expand-path@openssh.com")) != 0 ||
		    (r = sshbuf_put_cstring(संदेश, path)) != 0)
			fatal_fr(r, "compose %s", what);
		send_संदेश(conn, संदेश);
	} अन्यथा {
		debug2("Sending SSH2_FXP_REALPATH \"%s\"", path);
		send_string_request(conn, id, SSH2_FXP_REALPATH,
		    path, म_माप(path));
	}
	get_संदेश(conn, संदेश);
	यदि ((r = sshbuf_get_u8(संदेश, &type)) != 0 ||
	    (r = sshbuf_get_u32(संदेश, &id)) != 0)
		fatal_fr(r, "parse");

	यदि (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);

	यदि (type == SSH2_FXP_STATUS) {
		u_int status;
		वर्ण *errmsg;

		यदि ((r = sshbuf_get_u32(संदेश, &status)) != 0 ||
		    (r = sshbuf_get_cstring(संदेश, &errmsg, रिक्त)) != 0)
			fatal_fr(r, "parse status");
		error("%s %s: %s", expand ? "expand" : "realpath",
		    path, *errmsg == '\0' ? fx2txt(status) : errmsg);
		मुक्त(errmsg);
		sshbuf_free(संदेश);
		प्रत्यागम रिक्त;
	} अन्यथा यदि (type != SSH2_FXP_NAME)
		fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
		    SSH2_FXP_NAME, type);

	यदि ((r = sshbuf_get_u32(संदेश, &गिनती)) != 0)
		fatal_fr(r, "parse count");
	यदि (गिनती != 1)
		fatal("Got multiple names (%d) from %s", गिनती, what);

	यदि ((r = sshbuf_get_cstring(संदेश, &filename, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(संदेश, &longname, रिक्त)) != 0 ||
	    (r = decode_attrib(संदेश, &a)) != 0)
		fatal_fr(r, "parse filename/attrib");

	debug3("%s %s -> %s", what, path, filename);

	मुक्त(longname);

	sshbuf_free(संदेश);

	प्रत्यागम(filename);
}

वर्ण *
sftp_realpath(संरचना sftp_conn *conn, ध्रुव वर्ण *path)
{
	प्रत्यागम sftp_realpath_expand(conn, path, 0);
}

पूर्णाङ्क
sftp_can_expand_path(संरचना sftp_conn *conn)
{
	प्रत्यागम (conn->exts & SFTP_EXT_PATH_EXPAND) != 0;
}

वर्ण *
sftp_expand_path(संरचना sftp_conn *conn, ध्रुव वर्ण *path)
{
	यदि (!sftp_can_expand_path(conn)) {
		debug3_f("no server support, fallback to realpath");
		प्रत्यागम sftp_realpath_expand(conn, path, 0);
	}
	प्रत्यागम sftp_realpath_expand(conn, path, 1);
}

पूर्णाङ्क
sftp_copy(संरचना sftp_conn *conn, ध्रुव वर्ण *oldpath, ध्रुव वर्ण *newpath)
{
	Attrib junk, attr;
	संरचना sshbuf *संदेश;
	u_char *old_handle, *new_handle;
	u_int mode, status, id;
	माप_प्रकार old_handle_len, new_handle_len;
	पूर्णाङ्क r;

	/* Return if the extension is not supported */
	यदि ((conn->exts & SFTP_EXT_COPY_DATA) == 0) {
		error("Server does not support copy-data extension");
		प्रत्यागम -1;
	}

	/* Make sure the file exists, and we can copy its perms */
	यदि (sftp_stat(conn, oldpath, 0, &attr) != 0)
		प्रत्यागम -1;

	/* Do not preserve set[ug]id here, as we do not preserve ownership */
	यदि (attr.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		mode = attr.perm & 0777;

		यदि (!S_ISREG(attr.perm)) {
			error("Cannot copy non-regular file: %s", oldpath);
			प्रत्यागम -1;
		}
	} अन्यथा {
		/* NB: The user's umask will apply to this */
		mode = 0666;
	}

	/* Set up the new perms for the new file */
	attrib_clear(&attr);
	attr.perm = mode;
	attr.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;

	यदि ((संदेश = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");

	attrib_clear(&junk); /* Send empty attributes */

	/* Open the old file for reading */
	id = conn->संदेश_id++;
	यदि ((r = sshbuf_put_u8(संदेश, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, id)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, oldpath)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, SSH2_FXF_READ)) != 0 ||
	    (r = encode_attrib(संदेश, &junk)) != 0)
		fatal_fr(r, "buffer error");
	send_संदेश(conn, संदेश);
	debug3("Sent message SSH2_FXP_OPEN I:%u P:%s", id, oldpath);

	sshbuf_reset(संदेश);

	old_handle = get_handle(conn, id, &old_handle_len,
	    "remote open(\"%s\")", oldpath);
	यदि (old_handle == रिक्त) {
		sshbuf_free(संदेश);
		प्रत्यागम -1;
	}

	/* Open the new file for writing */
	id = conn->संदेश_id++;
	यदि ((r = sshbuf_put_u8(संदेश, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, id)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, newpath)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, SSH2_FXF_WRITE|SSH2_FXF_CREAT|
	    SSH2_FXF_TRUNC)) != 0 ||
	    (r = encode_attrib(संदेश, &attr)) != 0)
		fatal_fr(r, "buffer error");
	send_संदेश(conn, संदेश);
	debug3("Sent message SSH2_FXP_OPEN I:%u P:%s", id, newpath);

	sshbuf_reset(संदेश);

	new_handle = get_handle(conn, id, &new_handle_len,
	    "remote open(\"%s\")", newpath);
	यदि (new_handle == रिक्त) {
		sshbuf_free(संदेश);
		मुक्त(old_handle);
		प्रत्यागम -1;
	}

	/* Copy the file data */
	id = conn->संदेश_id++;
	यदि ((r = sshbuf_put_u8(संदेश, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, id)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, "copy-data")) != 0 ||
	    (r = sshbuf_put_string(संदेश, old_handle, old_handle_len)) != 0 ||
	    (r = sshbuf_put_u64(संदेश, 0)) != 0 ||
	    (r = sshbuf_put_u64(संदेश, 0)) != 0 ||
	    (r = sshbuf_put_string(संदेश, new_handle, new_handle_len)) != 0 ||
	    (r = sshbuf_put_u64(संदेश, 0)) != 0)
		fatal_fr(r, "buffer error");
	send_संदेश(conn, संदेश);
	debug3("Sent message copy-data \"%s\" 0 0 -> \"%s\" 0",
	       oldpath, newpath);

	status = get_status(conn, id);
	यदि (status != SSH2_FX_OK)
		error("Couldn't copy file \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	/* Clean up everything */
	sshbuf_free(संदेश);
	sftp_close(conn, old_handle, old_handle_len);
	sftp_close(conn, new_handle, new_handle_len);
	मुक्त(old_handle);
	मुक्त(new_handle);

	प्रत्यागम status == SSH2_FX_OK ? 0 : -1;
}

पूर्णाङ्क
sftp_rename(संरचना sftp_conn *conn, ध्रुव वर्ण *oldpath, ध्रुव वर्ण *newpath,
    पूर्णाङ्क force_legacy)
{
	संरचना sshbuf *संदेश;
	u_int status, id;
	पूर्णाङ्क r, use_ext = (conn->exts & SFTP_EXT_POSIX_RENAME) && !force_legacy;

	यदि ((संदेश = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");

	/* Send rename request */
	id = conn->संदेश_id++;
	यदि (use_ext) {
		debug2("Sending SSH2_FXP_EXTENDED(posix-rename@openssh.com) "
		    "\"%s\" to \"%s\"", oldpath, newpath);
		यदि ((r = sshbuf_put_u8(संदेश, SSH2_FXP_EXTENDED)) != 0 ||
		    (r = sshbuf_put_u32(संदेश, id)) != 0 ||
		    (r = sshbuf_put_cstring(संदेश,
		    "posix-rename@openssh.com")) != 0)
			fatal_fr(r, "compose posix-rename");
	} अन्यथा {
		debug2("Sending SSH2_FXP_RENAME \"%s\" to \"%s\"",
		    oldpath, newpath);
		यदि ((r = sshbuf_put_u8(संदेश, SSH2_FXP_RENAME)) != 0 ||
		    (r = sshbuf_put_u32(संदेश, id)) != 0)
			fatal_fr(r, "compose rename");
	}
	यदि ((r = sshbuf_put_cstring(संदेश, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, newpath)) != 0)
		fatal_fr(r, "compose paths");
	send_संदेश(conn, संदेश);
	debug3("Sent message %s \"%s\" -> \"%s\"",
	    use_ext ? "posix-rename@openssh.com" :
	    "SSH2_FXP_RENAME", oldpath, newpath);
	sshbuf_free(संदेश);

	status = get_status(conn, id);
	यदि (status != SSH2_FX_OK)
		error("remote rename \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	प्रत्यागम status == SSH2_FX_OK ? 0 : -1;
}

पूर्णाङ्क
sftp_hardlink(संरचना sftp_conn *conn, ध्रुव वर्ण *oldpath, ध्रुव वर्ण *newpath)
{
	संरचना sshbuf *संदेश;
	u_int status, id;
	पूर्णाङ्क r;

	यदि ((conn->exts & SFTP_EXT_HARDLINK) == 0) {
		error("Server does not support hardlink@openssh.com extension");
		प्रत्यागम -1;
	}
	debug2("Sending SSH2_FXP_EXTENDED(hardlink@openssh.com) "
	    "\"%s\" to \"%s\"", oldpath, newpath);

	यदि ((संदेश = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");

	/* Send link request */
	id = conn->संदेश_id++;
	यदि ((r = sshbuf_put_u8(संदेश, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, id)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, "hardlink@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, newpath)) != 0)
		fatal_fr(r, "compose");
	send_संदेश(conn, संदेश);
	debug3("Sent message hardlink@openssh.com \"%s\" -> \"%s\"",
	    oldpath, newpath);
	sshbuf_free(संदेश);

	status = get_status(conn, id);
	यदि (status != SSH2_FX_OK)
		error("remote link \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	प्रत्यागम status == SSH2_FX_OK ? 0 : -1;
}

पूर्णाङ्क
sftp_symlink(संरचना sftp_conn *conn, ध्रुव वर्ण *oldpath, ध्रुव वर्ण *newpath)
{
	संरचना sshbuf *संदेश;
	u_int status, id;
	पूर्णाङ्क r;

	यदि (conn->version < 3) {
		error("This server does not support the symlink operation");
		प्रत्यागम(SSH2_FX_OP_UNSUPPORTED);
	}
	debug2("Sending SSH2_FXP_SYMLINK \"%s\" to \"%s\"", oldpath, newpath);

	यदि ((संदेश = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");

	/* Send symlink request */
	id = conn->संदेश_id++;
	यदि ((r = sshbuf_put_u8(संदेश, SSH2_FXP_SYMLINK)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, id)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, newpath)) != 0)
		fatal_fr(r, "compose");
	send_संदेश(conn, संदेश);
	debug3("Sent message SSH2_FXP_SYMLINK \"%s\" -> \"%s\"", oldpath,
	    newpath);
	sshbuf_free(संदेश);

	status = get_status(conn, id);
	यदि (status != SSH2_FX_OK)
		error("remote symlink file \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	प्रत्यागम status == SSH2_FX_OK ? 0 : -1;
}

पूर्णाङ्क
sftp_fsync(संरचना sftp_conn *conn, u_char *handle, u_int handle_len)
{
	संरचना sshbuf *संदेश;
	u_int status, id;
	पूर्णाङ्क r;

	/* Silently return if the extension is not supported */
	यदि ((conn->exts & SFTP_EXT_FSYNC) == 0)
		प्रत्यागम -1;
	debug2("Sending SSH2_FXP_EXTENDED(fsync@openssh.com)");

	/* Send fsync request */
	यदि ((संदेश = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	id = conn->संदेश_id++;
	यदि ((r = sshbuf_put_u8(संदेश, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, id)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, "fsync@openssh.com")) != 0 ||
	    (r = sshbuf_put_string(संदेश, handle, handle_len)) != 0)
		fatal_fr(r, "compose");
	send_संदेश(conn, संदेश);
	debug3("Sent message fsync@openssh.com I:%u", id);
	sshbuf_free(संदेश);

	status = get_status(conn, id);
	यदि (status != SSH2_FX_OK)
		error("remote fsync: %s", fx2txt(status));

	प्रत्यागम status == SSH2_FX_OK ? 0 : -1;
}

#ifdef notyet
वर्ण *
sftp_readlink(संरचना sftp_conn *conn, ध्रुव वर्ण *path)
{
	संरचना sshbuf *संदेश;
	u_int expected_id, गिनती, id;
	वर्ण *filename, *longname;
	Attrib a;
	u_char type;
	पूर्णाङ्क r;

	debug2("Sending SSH2_FXP_READLINK \"%s\"", path);

	expected_id = id = conn->संदेश_id++;
	send_string_request(conn, id, SSH2_FXP_READLINK, path, म_माप(path));

	यदि ((संदेश = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");

	get_संदेश(conn, संदेश);
	यदि ((r = sshbuf_get_u8(संदेश, &type)) != 0 ||
	    (r = sshbuf_get_u32(संदेश, &id)) != 0)
		fatal_fr(r, "parse");

	यदि (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);

	यदि (type == SSH2_FXP_STATUS) {
		u_int status;

		यदि ((r = sshbuf_get_u32(संदेश, &status)) != 0)
			fatal_fr(r, "parse status");
		error("Couldn't readlink: %s", fx2txt(status));
		sshbuf_free(संदेश);
		प्रत्यागम(रिक्त);
	} अन्यथा यदि (type != SSH2_FXP_NAME)
		fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
		    SSH2_FXP_NAME, type);

	यदि ((r = sshbuf_get_u32(संदेश, &गिनती)) != 0)
		fatal_fr(r, "parse count");
	यदि (गिनती != 1)
		fatal("Got multiple names (%d) from SSH_FXP_READLINK", गिनती);

	यदि ((r = sshbuf_get_cstring(संदेश, &filename, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(संदेश, &longname, रिक्त)) != 0 ||
	    (r = decode_attrib(संदेश, &a)) != 0)
		fatal_fr(r, "parse filenames/attrib");

	debug3("SSH_FXP_READLINK %s -> %s", path, filename);

	मुक्त(longname);

	sshbuf_free(संदेश);

	प्रत्यागम filename;
}
#endif

पूर्णाङ्क
sftp_statvfs(संरचना sftp_conn *conn, ध्रुव वर्ण *path, संरचना sftp_statvfs *st,
    पूर्णाङ्क quiet)
{
	संरचना sshbuf *संदेश;
	u_int id;
	पूर्णाङ्क r;

	यदि ((conn->exts & SFTP_EXT_STATVFS) == 0) {
		error("Server does not support statvfs@openssh.com extension");
		प्रत्यागम -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(statvfs@openssh.com) \"%s\"", path);

	id = conn->संदेश_id++;

	यदि ((संदेश = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshbuf_put_u8(संदेश, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, id)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, "statvfs@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, path)) != 0)
		fatal_fr(r, "compose");
	send_संदेश(conn, संदेश);
	sshbuf_free(संदेश);

	प्रत्यागम get_decode_statvfs(conn, st, id, quiet);
}

#ifdef notyet
पूर्णाङ्क
sftp_fstatvfs(संरचना sftp_conn *conn, ध्रुव u_char *handle, u_int handle_len,
    संरचना sftp_statvfs *st, पूर्णाङ्क quiet)
{
	संरचना sshbuf *संदेश;
	u_int id;

	यदि ((conn->exts & SFTP_EXT_FSTATVFS) == 0) {
		error("Server does not support fstatvfs@openssh.com extension");
		प्रत्यागम -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(fstatvfs@openssh.com)");

	id = conn->संदेश_id++;

	यदि ((संदेश = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshbuf_put_u8(संदेश, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, id)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, "fstatvfs@openssh.com")) != 0 ||
	    (r = sshbuf_put_string(संदेश, handle, handle_len)) != 0)
		fatal_fr(r, "compose");
	send_संदेश(conn, संदेश);
	sshbuf_free(संदेश);

	प्रत्यागम get_decode_statvfs(conn, st, id, quiet);
}
#endif

पूर्णाङ्क
sftp_lsetstat(संरचना sftp_conn *conn, ध्रुव वर्ण *path, Attrib *a)
{
	संरचना sshbuf *संदेश;
	u_int status, id;
	पूर्णाङ्क r;

	यदि ((conn->exts & SFTP_EXT_LSETSTAT) == 0) {
		error("Server does not support lsetstat@openssh.com extension");
		प्रत्यागम -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(lsetstat@openssh.com) \"%s\"", path);

	id = conn->संदेश_id++;
	यदि ((संदेश = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshbuf_put_u8(संदेश, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, id)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, "lsetstat@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, path)) != 0 ||
	    (r = encode_attrib(संदेश, a)) != 0)
		fatal_fr(r, "compose");
	send_संदेश(conn, संदेश);
	sshbuf_free(संदेश);

	status = get_status(conn, id);
	यदि (status != SSH2_FX_OK)
		error("remote lsetstat \"%s\": %s", path, fx2txt(status));

	प्रत्यागम status == SSH2_FX_OK ? 0 : -1;
}

स्थिर शून्य
send_read_request(संरचना sftp_conn *conn, u_int id, uint64_t offset,
    u_int len, ध्रुव u_char *handle, u_int handle_len)
{
	संरचना sshbuf *संदेश;
	पूर्णाङ्क r;

	यदि ((संदेश = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshbuf_put_u8(संदेश, SSH2_FXP_READ)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, id)) != 0 ||
	    (r = sshbuf_put_string(संदेश, handle, handle_len)) != 0 ||
	    (r = sshbuf_put_u64(संदेश, offset)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, len)) != 0)
		fatal_fr(r, "compose");
	send_संदेश(conn, संदेश);
	sshbuf_free(संदेश);
}

स्थिर पूर्णाङ्क
send_open(संरचना sftp_conn *conn, ध्रुव वर्ण *path, ध्रुव वर्ण *tag,
    u_int openmode, Attrib *a, u_char **handlep, माप_प्रकार *handle_lenp)
{
	Attrib junk;
	u_char *handle;
	माप_प्रकार handle_len;
	संरचना sshbuf *संदेश;
	पूर्णाङ्क r;
	u_int id;

	debug2("Sending SSH2_FXP_OPEN \"%s\"", path);

	*handlep = रिक्त;
	*handle_lenp = 0;

	यदि (a == रिक्त) {
		attrib_clear(&junk); /* Send empty attributes */
		a = &junk;
	}
	/* Send open request */
	यदि ((संदेश = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	id = conn->संदेश_id++;
	यदि ((r = sshbuf_put_u8(संदेश, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, id)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, path)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, openmode)) != 0 ||
	    (r = encode_attrib(संदेश, a)) != 0)
		fatal_fr(r, "compose %s open", tag);
	send_संदेश(conn, संदेश);
	sshbuf_free(संदेश);
	debug3("Sent %s message SSH2_FXP_OPEN I:%u P:%s M:0x%04x",
	    tag, id, path, openmode);
	यदि ((handle = get_handle(conn, id, &handle_len,
	    "%s open \"%s\"", tag, path)) == रिक्त)
		प्रत्यागम -1;
	/* success */
	*handlep = handle;
	*handle_lenp = handle_len;
	प्रत्यागम 0;
}

स्थिर ध्रुव वर्ण *
progress_meter_path(ध्रुव वर्ण *path)
{
	ध्रुव वर्ण *progresspath;

	यदि ((progresspath = म_खोजप(path, '/')) == रिक्त)
		प्रत्यागम path;
	progresspath++;
	यदि (*progresspath == '\0')
		प्रत्यागम path;
	प्रत्यागम progresspath;
}

पूर्णाङ्क
sftp_download(संरचना sftp_conn *conn, ध्रुव वर्ण *remote_path,
    ध्रुव वर्ण *local_path, Attrib *a, पूर्णाङ्क preserve_flag, पूर्णाङ्क resume_flag,
    पूर्णाङ्क fsync_flag, पूर्णाङ्क inplace_flag)
{
	संरचना sshbuf *संदेश;
	u_char *handle;
	पूर्णाङ्क local_fd = -1, write_error, seen_zerolen = 0;
	पूर्णाङ्क read_error, write_errno, lmodified = 0, reordered = 0, r;
	uint64_t offset = 0, size, highwater = 0, maxack = 0;
	u_int mode, id, buflen, अंक_req, max_req, status = SSH2_FX_OK;
	off_t progress_counter;
	माप_प्रकार handle_len;
	संरचना stat st;
	संरचना requests requests;
	संरचना request *req;
	u_char type;
	Attrib attr;

	debug2_f("download remote \"%s\" to local \"%s\"",
	    remote_path, local_path);

	TAILQ_INIT(&requests);

	यदि (a == रिक्त) {
		यदि (sftp_stat(conn, remote_path, 0, &attr) != 0)
			प्रत्यागम -1;
		a = &attr;
	}

	/* Do not preserve set[ug]id here, as we do not preserve ownership */
	यदि (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS)
		mode = a->perm & 0777;
	अन्यथा
		mode = 0666;

	यदि ((a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) &&
	    (!S_ISREG(a->perm))) {
		error("download %s: not a regular file", remote_path);
		प्रत्यागम(-1);
	}

	यदि (a->flags & SSH2_FILEXFER_ATTR_SIZE)
		size = a->size;
	अन्यथा
		size = 0;

	buflen = conn->download_buflen;

	/* Send open request */
	यदि (send_open(conn, remote_path, "remote", SSH2_FXF_READ, रिक्त,
	    &handle, &handle_len) != 0)
		प्रत्यागम -1;

	local_fd = खोलो(local_path, O_WRONLY | O_CREAT |
	((resume_flag || inplace_flag) ? 0 : O_TRUNC), mode | S_IWUSR);
	यदि (local_fd == -1) {
		error("open local \"%s\": %s", local_path, म_त्रुटि(त्रुटि_सं));
		गच्छ fail;
	}
	यदि (resume_flag) {
		यदि (ख_स्थिति(local_fd, &st) == -1) {
			error("stat local \"%s\": %s",
			    local_path, म_त्रुटि(त्रुटि_सं));
			गच्छ fail;
		}
		यदि (st.st_size < 0) {
			error("\"%s\" has negative size", local_path);
			गच्छ fail;
		}
		यदि ((uint64_t)st.st_size > size) {
			error("Unable to resume download of \"%s\": "
			    "local file is larger than remote", local_path);
 fail:
			sftp_close(conn, handle, handle_len);
			मुक्त(handle);
			यदि (local_fd != -1)
				बंद(local_fd);
			प्रत्यागम -1;
		}
		offset = highwater = maxack = st.st_size;
	}

	/* Read from remote and write to local */
	write_error = read_error = write_errno = अंक_req = 0;
	max_req = 1;
	progress_counter = offset;

	यदि (showprogress && size != 0) {
		start_progress_meter(progress_meter_path(remote_path),
		    size, &progress_counter);
	}

	यदि ((संदेश = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");

	यावत् (अंक_req > 0 || max_req > 0) {
		u_char *data;
		माप_प्रकार len;

		/*
		 * Simulate EOF on interrupt: stop sending new requests and
		 * allow outstanding requests to drain gracefully
		 */
		यदि (interrupted) {
			यदि (अंक_req == 0) /* If we haven't started yet... */
				भङ्ग;
			max_req = 0;
		}

		/* Send some more requests */
		यावत् (अंक_req < max_req) {
			debug3("Request range %llu -> %llu (%d/%d)",
			    (अचिन्हित दीर्घ दीर्घ)offset,
			    (अचिन्हित दीर्घ दीर्घ)offset + buflen - 1,
			    अंक_req, max_req);
			req = request_enqueue(&requests, conn->संदेश_id++,
			    buflen, offset);
			offset += buflen;
			अंक_req++;
			send_read_request(conn, req->id, req->offset,
			    req->len, handle, handle_len);
		}

		sshbuf_reset(संदेश);
		get_संदेश(conn, संदेश);
		यदि ((r = sshbuf_get_u8(संदेश, &type)) != 0 ||
		    (r = sshbuf_get_u32(संदेश, &id)) != 0)
			fatal_fr(r, "parse");
		debug3("Received reply T:%u I:%u R:%d", type, id, max_req);

		/* Find the request in our queue */
		यदि ((req = request_find(&requests, id)) == रिक्त)
			fatal("Unexpected reply %u", id);

		विकल्प (type) {
		पक्ष SSH2_FXP_STATUS:
			यदि ((r = sshbuf_get_u32(संदेश, &status)) != 0)
				fatal_fr(r, "parse status");
			यदि (status != SSH2_FX_EOF)
				read_error = 1;
			max_req = 0;
			TAILQ_REMOVE(&requests, req, tq);
			मुक्त(req);
			अंक_req--;
			भङ्ग;
		पक्ष SSH2_FXP_DATA:
			यदि ((r = sshbuf_get_string(संदेश, &data, &len)) != 0)
				fatal_fr(r, "parse data");
			debug3("Received data %llu -> %llu",
			    (अचिन्हित दीर्घ दीर्घ)req->offset,
			    (अचिन्हित दीर्घ दीर्घ)req->offset + len - 1);
			यदि (len > req->len)
				fatal("Received more data than asked for "
				    "%zu > %zu", len, req->len);
			यदि (len == 0) {
				यदि (seen_zerolen)
					fatal_f("server sent zero data length");
				seen_zerolen = 1;
			}
			lmodified = 1;
			यदि ((lseek(local_fd, req->offset, शुरू_से) == -1 ||
			    atomicio(vwrite, local_fd, data, len) != len) &&
			    !write_error) {
				write_errno = त्रुटि_सं;
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
				यदि (maxack < req->offset + len)
					maxack = req->offset + len;
				यदि (!reordered && req->offset <= highwater)
					highwater = maxack;
				अन्यथा यदि (!reordered && req->offset > highwater)
					reordered = 1;
			}
			progress_counter += len;
			मुक्त(data);

			यदि (len == req->len) {
				TAILQ_REMOVE(&requests, req, tq);
				मुक्त(req);
				अंक_req--;
			} अन्यथा {
				/* Resend the request for the missing data */
				debug3("Short data block, re-requesting "
				    "%llu -> %llu (%2d)",
				    (अचिन्हित दीर्घ दीर्घ)req->offset + len,
				    (अचिन्हित दीर्घ दीर्घ)req->offset +
				    req->len - 1, अंक_req);
				req->id = conn->संदेश_id++;
				req->len -= len;
				req->offset += len;
				send_read_request(conn, req->id,
				    req->offset, req->len, handle, handle_len);
				/* Reduce the request size */
				यदि (len < buflen)
					buflen = MAXIMUM(MIN_READ_SIZE, len);
			}
			यदि (max_req > 0) { /* max_req = 0 iff EOF received */
				यदि (size > 0 && offset > size) {
					/* Only one request at a time
					 * after the expected EOF */
					debug3("Finish at %llu (%2d)",
					    (अचिन्हित दीर्घ दीर्घ)offset,
					    अंक_req);
					max_req = 1;
				} अन्यथा यदि (max_req < conn->अंक_requests) {
					++max_req;
				}
			}
			भङ्ग;
		स्वभाव:
			fatal("Expected SSH2_FXP_DATA(%u) packet, got %u",
			    SSH2_FXP_DATA, type);
		}
	}

	यदि (showprogress && size)
		stop_progress_meter();

	/* Sanity check */
	यदि (TAILQ_FIRST(&requests) != रिक्त)
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
			    "server reordered requests", local_path);
		}
		debug("truncating at %llu", (अचिन्हित दीर्घ दीर्घ)highwater);
		यदि (ftruncate(local_fd, highwater) == -1)
			error("local ftruncate \"%s\": %s", local_path,
			    म_त्रुटि(त्रुटि_सं));
	}
	यदि (read_error) {
		error("read remote \"%s\" : %s", remote_path, fx2txt(status));
		status = -1;
		sftp_close(conn, handle, handle_len);
	} अन्यथा यदि (write_error) {
		error("write local \"%s\": %s", local_path,
		    म_त्रुटि(write_errno));
		status = SSH2_FX_FAILURE;
		sftp_close(conn, handle, handle_len);
	} अन्यथा {
		यदि (sftp_close(conn, handle, handle_len) != 0 || interrupted)
			status = SSH2_FX_FAILURE;
		अन्यथा
			status = SSH2_FX_OK;
		/* Override umask and utimes if asked */
#ifdef HAVE_FCHMOD
		यदि (preserve_flag && fchmod(local_fd, mode) == -1)
#अन्यथा
		यदि (preserve_flag && chmod(local_path, mode) == -1)
#endif /* HAVE_FCHMOD */
			error("local chmod \"%s\": %s", local_path,
			    म_त्रुटि(त्रुटि_सं));
		यदि (preserve_flag &&
		    (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME)) {
			संरचना timeval tv[2];
			tv[0].tv_sec = a->atime;
			tv[1].tv_sec = a->mtime;
			tv[0].tv_usec = tv[1].tv_usec = 0;
			यदि (utimes(local_path, tv) == -1)
				error("local set times \"%s\": %s",
				    local_path, म_त्रुटि(त्रुटि_सं));
		}
		यदि (resume_flag && !lmodified)
			logit("File \"%s\" was not modified", local_path);
		अन्यथा यदि (fsync_flag) {
			debug("syncing \"%s\"", local_path);
			यदि (fsync(local_fd) == -1)
				error("local sync \"%s\": %s",
				    local_path, म_त्रुटि(त्रुटि_सं));
		}
	}
	बंद(local_fd);
	sshbuf_free(संदेश);
	मुक्त(handle);

	प्रत्यागम status == SSH2_FX_OK ? 0 : -1;
}

स्थिर पूर्णाङ्क
download_dir_internal(संरचना sftp_conn *conn, ध्रुव वर्ण *src, ध्रुव वर्ण *dst,
    पूर्णाङ्क depth, Attrib *dirattrib, पूर्णाङ्क preserve_flag, पूर्णाङ्क print_flag,
    पूर्णाङ्क resume_flag, पूर्णाङ्क fsync_flag, पूर्णाङ्क follow_link_flag, पूर्णाङ्क inplace_flag)
{
	पूर्णाङ्क i, ret = 0;
	SFTP_DIRENT **dir_entries;
	वर्ण *filename, *new_src = रिक्त, *new_dst = रिक्त;
	mode_t mode = 0777, tmpmode = mode;
	Attrib *a, ldirattrib, lsym;

	यदि (depth >= MAX_DIR_DEPTH) {
		error("Maximum directory depth exceeded: %d levels", depth);
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
	यदि (print_flag && print_flag != SFTP_PROGRESS_ONLY)
		mprintf("Retrieving %s\n", src);

	यदि (dirattrib->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		mode = dirattrib->perm & 01777;
		tmpmode = mode | (S_IWUSR|S_IXUSR);
	} अन्यथा {
		debug("download remote \"%s\": server "
		    "did not send permissions", dst);
	}

	यदि (सूची_गढ़ो(dst, tmpmode) == -1 && त्रुटि_सं != EEXIST) {
		error("mkdir %s: %s", dst, म_त्रुटि(त्रुटि_सं));
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
		new_dst = sftp_path_append(dst, filename);
		new_src = sftp_path_append(src, filename);

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
			यदि (म_भेद(filename, ".") == 0 ||
			    म_भेद(filename, "..") == 0)
				अनुवर्त;
			यदि (download_dir_internal(conn, new_src, new_dst,
			    depth + 1, a, preserve_flag,
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
				    dst, म_त्रुटि(त्रुटि_सं));
		} अन्यथा
			debug("Server did not send times for directory "
			    "\"%s\"", dst);
	}

	यदि (mode != tmpmode && chmod(dst, mode) == -1)
		error("local chmod directory \"%s\": %s", dst,
		    म_त्रुटि(त्रुटि_सं));

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

	ret = download_dir_internal(conn, src_canon, dst, 0,
	    dirattrib, preserve_flag, print_flag, resume_flag, fsync_flag,
	    follow_link_flag, inplace_flag);
	मुक्त(src_canon);
	प्रत्यागम ret;
}

पूर्णाङ्क
sftp_upload(संरचना sftp_conn *conn, ध्रुव वर्ण *local_path,
    ध्रुव वर्ण *remote_path, पूर्णाङ्क preserve_flag, पूर्णाङ्क resume,
    पूर्णाङ्क fsync_flag, पूर्णाङ्क inplace_flag)
{
	पूर्णाङ्क r, local_fd;
	u_int openmode, id, status = SSH2_FX_OK, status2, reordered = 0;
	off_t offset, progress_counter;
	u_char type, *handle, *data;
	संरचना sshbuf *संदेश;
	संरचना stat sb;
	Attrib a, t, c;
	uint32_t startid, ackid;
	uint64_t highwater = 0, maxack = 0;
	संरचना request *ack = रिक्त;
	संरचना requests acks;
	माप_प्रकार handle_len;

	debug2_f("upload local \"%s\" to remote \"%s\"",
	    local_path, remote_path);

	TAILQ_INIT(&acks);

	यदि ((local_fd = खोलो(local_path, O_RDONLY)) == -1) {
		error("open local \"%s\": %s", local_path, म_त्रुटि(त्रुटि_सं));
		प्रत्यागम(-1);
	}
	यदि (ख_स्थिति(local_fd, &sb) == -1) {
		error("fstat local \"%s\": %s", local_path, म_त्रुटि(त्रुटि_सं));
		बंद(local_fd);
		प्रत्यागम(-1);
	}
	यदि (!S_ISREG(sb.st_mode)) {
		error("local \"%s\" is not a regular file", local_path);
		बंद(local_fd);
		प्रत्यागम(-1);
	}
	stat_to_attrib(&sb, &a);

	a.flags &= ~SSH2_FILEXFER_ATTR_SIZE;
	a.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a.perm &= 0777;
	यदि (!preserve_flag)
		a.flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;

	यदि (resume) {
		/* Get remote file size if it exists */
		यदि (sftp_stat(conn, remote_path, 0, &c) != 0) {
			बंद(local_fd);
			प्रत्यागम -1;
		}

		यदि ((off_t)c.size >= sb.st_size) {
			error("resume \"%s\": destination file "
			    "same size or larger", local_path);
			बंद(local_fd);
			प्रत्यागम -1;
		}

		यदि (lseek(local_fd, (off_t)c.size, शुरू_से) == -1) {
			बंद(local_fd);
			प्रत्यागम -1;
		}
		highwater = c.size;
	}

	openmode = SSH2_FXF_WRITE|SSH2_FXF_CREAT;
	यदि (resume)
		openmode |= SSH2_FXF_APPEND;
	अन्यथा यदि (!inplace_flag)
		openmode |= SSH2_FXF_TRUNC;

	/* Send open request */
	यदि (send_open(conn, remote_path, "dest", openmode, &a,
	    &handle, &handle_len) != 0) {
		बंद(local_fd);
		प्रत्यागम -1;
	}

	id = conn->संदेश_id;
	startid = ackid = id + 1;
	data = xmalloc(conn->upload_buflen);

	/* Read from local and write to remote */
	offset = progress_counter = (resume ? c.size : 0);
	यदि (showprogress) {
		start_progress_meter(progress_meter_path(local_path),
		    sb.st_size, &progress_counter);
	}

	यदि ((संदेश = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	प्रति (;;) {
		पूर्णाङ्क len;

		/*
		 * Can't use atomicio here because it returns 0 on EOF,
		 * thus losing the last block of the file.
		 * Simulate an EOF on interrupt, allowing ACKs from the
		 * server to drain.
		 */
		यदि (interrupted || status != SSH2_FX_OK)
			len = 0;
		अन्यथा कुरु
			len = पठ(local_fd, data, conn->upload_buflen);
		यावत् ((len == -1) &&
		    (त्रुटि_सं == EINTR || त्रुटि_सं == EAGAIN || त्रुटि_सं == EWOULDBLOCK));

		यदि (len == -1) {
			fatal("read local \"%s\": %s",
			    local_path, म_त्रुटि(त्रुटि_सं));
		} अन्यथा यदि (len != 0) {
			ack = request_enqueue(&acks, ++id, len, offset);
			sshbuf_reset(संदेश);
			यदि ((r = sshbuf_put_u8(संदेश, SSH2_FXP_WRITE)) != 0 ||
			    (r = sshbuf_put_u32(संदेश, ack->id)) != 0 ||
			    (r = sshbuf_put_string(संदेश, handle,
			    handle_len)) != 0 ||
			    (r = sshbuf_put_u64(संदेश, offset)) != 0 ||
			    (r = sshbuf_put_string(संदेश, data, len)) != 0)
				fatal_fr(r, "compose");
			send_संदेश(conn, संदेश);
			debug3("Sent message SSH2_FXP_WRITE I:%u O:%llu S:%u",
			    id, (अचिन्हित दीर्घ दीर्घ)offset, len);
		} अन्यथा यदि (TAILQ_FIRST(&acks) == रिक्त)
			भङ्ग;

		यदि (ack == रिक्त)
			fatal("Unexpected ACK %u", id);

		यदि (id == startid || len == 0 ||
		    id - ackid >= conn->अंक_requests) {
			u_int rid;

			sshbuf_reset(संदेश);
			get_संदेश(conn, संदेश);
			यदि ((r = sshbuf_get_u8(संदेश, &type)) != 0 ||
			    (r = sshbuf_get_u32(संदेश, &rid)) != 0)
				fatal_fr(r, "parse");

			यदि (type != SSH2_FXP_STATUS)
				fatal("Expected SSH2_FXP_STATUS(%d) packet, "
				    "got %d", SSH2_FXP_STATUS, type);

			यदि ((r = sshbuf_get_u32(संदेश, &status2)) != 0)
				fatal_fr(r, "parse status");
			debug3("SSH2_FXP_STATUS %u", status2);
			यदि (status2 != SSH2_FX_OK)
				status = status2; /* remember errors */

			/* Find the request in our queue */
			यदि ((ack = request_find(&acks, rid)) == रिक्त)
				fatal("Can't find request for ID %u", rid);
			TAILQ_REMOVE(&acks, ack, tq);
			debug3("In write loop, ack for %u %zu bytes at %lld",
			    ack->id, ack->len, (अचिन्हित दीर्घ दीर्घ)ack->offset);
			++ackid;
			progress_counter += ack->len;
			/*
			 * Track both the highest offset acknowledged and the
			 * highest *contiguous* offset acknowledged.
			 * We'll need the latter for ftruncate()ing
			 * interrupted transfers.
			 */
			यदि (maxack < ack->offset + ack->len)
				maxack = ack->offset + ack->len;
			यदि (!reordered && ack->offset <= highwater)
				highwater = maxack;
			अन्यथा यदि (!reordered && ack->offset > highwater) {
				debug3_f("server reordered ACKs");
				reordered = 1;
			}
			मुक्त(ack);
		}
		offset += len;
		यदि (offset < 0)
			fatal_f("offset < 0");
	}
	sshbuf_free(संदेश);

	यदि (showprogress)
		stop_progress_meter();
	मुक्त(data);

	यदि (status == SSH2_FX_OK && !interrupted) {
		/* we got everything */
		highwater = maxack;
	}
	यदि (status != SSH2_FX_OK) {
		error("write remote \"%s\": %s", remote_path, fx2txt(status));
		status = SSH2_FX_FAILURE;
	}

	यदि (inplace_flag || (resume && (status != SSH2_FX_OK || interrupted))) {
		debug("truncating at %llu", (अचिन्हित दीर्घ दीर्घ)highwater);
		attrib_clear(&t);
		t.flags = SSH2_FILEXFER_ATTR_SIZE;
		t.size = highwater;
		sftp_fsetstat(conn, handle, handle_len, &t);
	}

	यदि (बंद(local_fd) == -1) {
		error("close local \"%s\": %s", local_path, म_त्रुटि(त्रुटि_सं));
		status = SSH2_FX_FAILURE;
	}

	/* Override umask and utimes if asked */
	यदि (preserve_flag)
		sftp_fsetstat(conn, handle, handle_len, &a);

	यदि (fsync_flag)
		(शून्य)sftp_fsync(conn, handle, handle_len);

	यदि (sftp_close(conn, handle, handle_len) != 0)
		status = SSH2_FX_FAILURE;

	मुक्त(handle);

	प्रत्यागम status == SSH2_FX_OK ? 0 : -1;
}

स्थिर पूर्णाङ्क
upload_dir_internal(संरचना sftp_conn *conn, ध्रुव वर्ण *src, ध्रुव वर्ण *dst,
    पूर्णाङ्क depth, पूर्णाङ्क preserve_flag, पूर्णाङ्क print_flag, पूर्णाङ्क resume, पूर्णाङ्क fsync_flag,
    पूर्णाङ्क follow_link_flag, पूर्णाङ्क inplace_flag)
{
	पूर्णाङ्क created = 0, ret = 0;
	सूची *dirp;
	संरचना dirent *dp;
	वर्ण *filename, *new_src = रिक्त, *new_dst = रिक्त;
	संरचना stat sb;
	Attrib a, dirattrib;
	uint32_t saved_perm;

	debug2_f("upload local dir \"%s\" to remote \"%s\"", src, dst);

	यदि (depth >= MAX_DIR_DEPTH) {
		error("Maximum directory depth exceeded: %d levels", depth);
		प्रत्यागम -1;
	}

	यदि (stat(src, &sb) == -1) {
		error("stat local \"%s\": %s", src, म_त्रुटि(त्रुटि_सं));
		प्रत्यागम -1;
	}
	यदि (!S_ISDIR(sb.st_mode)) {
		error("\"%s\" is not a directory", src);
		प्रत्यागम -1;
	}
	यदि (print_flag && print_flag != SFTP_PROGRESS_ONLY)
		mprintf("Entering %s\n", src);

	stat_to_attrib(&sb, &a);
	a.flags &= ~SSH2_FILEXFER_ATTR_SIZE;
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

	यदि ((dirp = सूची_खोलो(src)) == रिक्त) {
		error("local opendir \"%s\": %s", src, म_त्रुटि(त्रुटि_सं));
		प्रत्यागम -1;
	}

	यावत् (((dp = सूची_पढ़ो(dirp)) != रिक्त) && !interrupted) {
		यदि (dp->d_ino == 0)
			अनुवर्त;
		मुक्त(new_dst);
		मुक्त(new_src);
		filename = dp->d_name;
		new_dst = sftp_path_append(dst, filename);
		new_src = sftp_path_append(src, filename);

		यदि (म_भेद(filename, ".") == 0 || म_भेद(filename, "..") == 0)
			अनुवर्त;
		यदि (lstat(new_src, &sb) == -1) {
			logit("local lstat \"%s\": %s", filename,
			    म_त्रुटि(त्रुटि_सं));
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
				    म_त्रुटि(त्रुटि_सं));
				ret = -1;
				अनुवर्त;
			}
		}
		यदि (S_ISDIR(sb.st_mode)) {
			यदि (upload_dir_internal(conn, new_src, new_dst,
			    depth + 1, preserve_flag, print_flag, resume,
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

	(शून्य) बंद_सूची(dirp);
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

	ret = upload_dir_internal(conn, src, dst_canon, 0, preserve_flag,
	    print_flag, resume, fsync_flag, follow_link_flag, inplace_flag);

	मुक्त(dst_canon);
	प्रत्यागम ret;
}

स्थिर शून्य
handle_dest_replies(संरचना sftp_conn *to, ध्रुव वर्ण *to_path, पूर्णाङ्क synchronous,
    u_int *nreqsp, u_int *write_errorp)
{
	संरचना sshbuf *संदेश;
	u_char type;
	u_int id, status;
	पूर्णाङ्क r;
	संरचना pollfd pfd;

	यदि ((संदेश = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");

	/* Try to eat replies from the upload side */
	यावत् (*nreqsp > 0) {
		debug3_f("%u outstanding replies", *nreqsp);
		यदि (!synchronous) {
			/* Bail out if no data is ready to be read */
			pfd.fd = to->fd_in;
			pfd.events = POLLIN;
			यदि ((r = poll(&pfd, 1, 0)) == -1) {
				यदि (त्रुटि_सं == EINTR)
					भङ्ग;
				fatal_f("poll: %s", म_त्रुटि(त्रुटि_सं));
			} अन्यथा यदि (r == 0)
				भङ्ग; /* fd not ready */
		}
		sshbuf_reset(संदेश);
		get_संदेश(to, संदेश);

		यदि ((r = sshbuf_get_u8(संदेश, &type)) != 0 ||
		    (r = sshbuf_get_u32(संदेश, &id)) != 0)
			fatal_fr(r, "dest parse");
		debug3("Received dest reply T:%u I:%u R:%u", type, id, *nreqsp);
		यदि (type != SSH2_FXP_STATUS) {
			fatal_f("Expected SSH2_FXP_STATUS(%d) packet, got %d",
			    SSH2_FXP_STATUS, type);
		}
		यदि ((r = sshbuf_get_u32(संदेश, &status)) != 0)
			fatal_fr(r, "parse dest status");
		debug3("dest SSH2_FXP_STATUS %u", status);
		यदि (status != SSH2_FX_OK) {
			/* record first error */
			यदि (*write_errorp == 0)
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
	sshbuf_free(संदेश);
}

पूर्णाङ्क
sftp_crossload(संरचना sftp_conn *from, संरचना sftp_conn *to,
    ध्रुव वर्ण *from_path, ध्रुव वर्ण *to_path,
    Attrib *a, पूर्णाङ्क preserve_flag)
{
	संरचना sshbuf *संदेश;
	पूर्णाङ्क write_error, read_error, r, seen_zerolen = 0;
	uint64_t offset = 0, size;
	u_int id, buflen, अंक_req, max_req, status = SSH2_FX_OK;
	u_int अंक_upload_req;
	off_t progress_counter;
	u_char *from_handle, *to_handle;
	माप_प्रकार from_handle_len, to_handle_len;
	संरचना requests requests;
	संरचना request *req;
	u_char type;
	Attrib attr;

	debug2_f("crossload src \"%s\" to dst \"%s\"", from_path, to_path);

	TAILQ_INIT(&requests);

	यदि (a == रिक्त) {
		यदि (sftp_stat(from, from_path, 0, &attr) != 0)
			प्रत्यागम -1;
		a = &attr;
	}

	यदि ((a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) &&
	    (!S_ISREG(a->perm))) {
		error("download \"%s\": not a regular file", from_path);
		प्रत्यागम(-1);
	}
	यदि (a->flags & SSH2_FILEXFER_ATTR_SIZE)
		size = a->size;
	अन्यथा
		size = 0;

	buflen = from->download_buflen;
	यदि (buflen > to->upload_buflen)
		buflen = to->upload_buflen;

	/* Send open request to read side */
	यदि (send_open(from, from_path, "origin", SSH2_FXF_READ, रिक्त,
	    &from_handle, &from_handle_len) != 0)
		प्रत्यागम -1;

	/* Send open request to write side */
	a->flags &= ~SSH2_FILEXFER_ATTR_SIZE;
	a->flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a->perm &= 0777;
	यदि (!preserve_flag)
		a->flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;
	यदि (send_open(to, to_path, "dest",
	    SSH2_FXF_WRITE|SSH2_FXF_CREAT|SSH2_FXF_TRUNC, a,
	    &to_handle, &to_handle_len) != 0) {
		sftp_close(from, from_handle, from_handle_len);
		प्रत्यागम -1;
	}

	/* Read from remote "from" and write to remote "to" */
	offset = 0;
	write_error = read_error = अंक_req = अंक_upload_req = 0;
	max_req = 1;
	progress_counter = 0;

	यदि (showprogress && size != 0) {
		start_progress_meter(progress_meter_path(from_path),
		    size, &progress_counter);
	}
	यदि ((संदेश = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यावत् (अंक_req > 0 || max_req > 0) {
		u_char *data;
		माप_प्रकार len;

		/*
		 * Simulate EOF on interrupt: stop sending new requests and
		 * allow outstanding requests to drain gracefully
		 */
		यदि (interrupted) {
			यदि (अंक_req == 0) /* If we haven't started yet... */
				भङ्ग;
			max_req = 0;
		}

		/* Send some more requests */
		यावत् (अंक_req < max_req) {
			debug3("Request range %llu -> %llu (%d/%d)",
			    (अचिन्हित दीर्घ दीर्घ)offset,
			    (अचिन्हित दीर्घ दीर्घ)offset + buflen - 1,
			    अंक_req, max_req);
			req = request_enqueue(&requests, from->संदेश_id++,
			    buflen, offset);
			offset += buflen;
			अंक_req++;
			send_read_request(from, req->id, req->offset,
			    req->len, from_handle, from_handle_len);
		}

		/* Try to eat replies from the upload side (nonblocking) */
		handle_dest_replies(to, to_path, 0,
		    &अंक_upload_req, &write_error);

		sshbuf_reset(संदेश);
		get_संदेश(from, संदेश);
		यदि ((r = sshbuf_get_u8(संदेश, &type)) != 0 ||
		    (r = sshbuf_get_u32(संदेश, &id)) != 0)
			fatal_fr(r, "parse");
		debug3("Received origin reply T:%u I:%u R:%d",
		    type, id, max_req);

		/* Find the request in our queue */
		यदि ((req = request_find(&requests, id)) == रिक्त)
			fatal("Unexpected reply %u", id);

		विकल्प (type) {
		पक्ष SSH2_FXP_STATUS:
			यदि ((r = sshbuf_get_u32(संदेश, &status)) != 0)
				fatal_fr(r, "parse status");
			यदि (status != SSH2_FX_EOF)
				read_error = 1;
			max_req = 0;
			TAILQ_REMOVE(&requests, req, tq);
			मुक्त(req);
			अंक_req--;
			भङ्ग;
		पक्ष SSH2_FXP_DATA:
			यदि ((r = sshbuf_get_string(संदेश, &data, &len)) != 0)
				fatal_fr(r, "parse data");
			debug3("Received data %llu -> %llu",
			    (अचिन्हित दीर्घ दीर्घ)req->offset,
			    (अचिन्हित दीर्घ दीर्घ)req->offset + len - 1);
			यदि (len > req->len)
				fatal("Received more data than asked for "
				    "%zu > %zu", len, req->len);
			यदि (len == 0) {
				यदि (seen_zerolen)
					fatal_f("server sent zero data length");
				seen_zerolen = 1;
			}

			/* Write this chunk out to the destination */
			sshbuf_reset(संदेश);
			यदि ((r = sshbuf_put_u8(संदेश, SSH2_FXP_WRITE)) != 0 ||
			    (r = sshbuf_put_u32(संदेश, to->संदेश_id++)) != 0 ||
			    (r = sshbuf_put_string(संदेश, to_handle,
			    to_handle_len)) != 0 ||
			    (r = sshbuf_put_u64(संदेश, req->offset)) != 0 ||
			    (r = sshbuf_put_string(संदेश, data, len)) != 0)
				fatal_fr(r, "compose write");
			send_संदेश(to, संदेश);
			debug3("Sent message SSH2_FXP_WRITE I:%u O:%llu S:%zu",
			    id, (अचिन्हित दीर्घ दीर्घ)offset, len);
			अंक_upload_req++;
			progress_counter += len;
			मुक्त(data);

			यदि (len == req->len) {
				TAILQ_REMOVE(&requests, req, tq);
				मुक्त(req);
				अंक_req--;
			} अन्यथा {
				/* Resend the request for the missing data */
				debug3("Short data block, re-requesting "
				    "%llu -> %llu (%2d)",
				    (अचिन्हित दीर्घ दीर्घ)req->offset + len,
				    (अचिन्हित दीर्घ दीर्घ)req->offset +
				    req->len - 1, अंक_req);
				req->id = from->संदेश_id++;
				req->len -= len;
				req->offset += len;
				send_read_request(from, req->id,
				    req->offset, req->len,
				    from_handle, from_handle_len);
				/* Reduce the request size */
				यदि (len < buflen)
					buflen = MAXIMUM(MIN_READ_SIZE, len);
			}
			यदि (max_req > 0) { /* max_req = 0 iff EOF received */
				यदि (size > 0 && offset > size) {
					/* Only one request at a time
					 * after the expected EOF */
					debug3("Finish at %llu (%2d)",
					    (अचिन्हित दीर्घ दीर्घ)offset,
					    अंक_req);
					max_req = 1;
				} अन्यथा यदि (max_req < from->अंक_requests) {
					++max_req;
				}
			}
			भङ्ग;
		स्वभाव:
			fatal("Expected SSH2_FXP_DATA(%u) packet, got %u",
			    SSH2_FXP_DATA, type);
		}
	}

	यदि (showprogress && size)
		stop_progress_meter();

	/* Drain replies from the server (blocking) */
	debug3_f("waiting for %u replies from destination", अंक_upload_req);
	handle_dest_replies(to, to_path, 1, &अंक_upload_req, &write_error);

	/* Sanity check */
	यदि (TAILQ_FIRST(&requests) != रिक्त)
		fatal("Transfer complete, but requests still in queue");
	/* Truncate at 0 length on interrupt or error to avoid holes at dest */
	यदि (read_error || write_error || interrupted) {
		debug("truncating \"%s\" at 0", to_path);
		sftp_close(to, to_handle, to_handle_len);
		मुक्त(to_handle);
		यदि (send_open(to, to_path, "dest",
		    SSH2_FXF_WRITE|SSH2_FXF_CREAT|SSH2_FXF_TRUNC, a,
		    &to_handle, &to_handle_len) != 0) {
			error("dest truncate \"%s\" failed", to_path);
			to_handle = रिक्त;
		}
	}
	यदि (read_error) {
		error("read origin \"%s\": %s", from_path, fx2txt(status));
		status = -1;
		sftp_close(from, from_handle, from_handle_len);
		यदि (to_handle != रिक्त)
			sftp_close(to, to_handle, to_handle_len);
	} अन्यथा यदि (write_error) {
		error("write dest \"%s\": %s", to_path, fx2txt(write_error));
		status = SSH2_FX_FAILURE;
		sftp_close(from, from_handle, from_handle_len);
		यदि (to_handle != रिक्त)
			sftp_close(to, to_handle, to_handle_len);
	} अन्यथा {
		यदि (sftp_close(from, from_handle, from_handle_len) != 0 ||
		    interrupted)
			status = -1;
		अन्यथा
			status = SSH2_FX_OK;
		यदि (to_handle != रिक्त) {
			/* Need to resend utimes after write */
			यदि (preserve_flag)
				sftp_fsetstat(to, to_handle, to_handle_len, a);
			sftp_close(to, to_handle, to_handle_len);
		}
	}
	sshbuf_free(संदेश);
	मुक्त(from_handle);
	मुक्त(to_handle);

	प्रत्यागम status == SSH2_FX_OK ? 0 : -1;
}

स्थिर पूर्णाङ्क
crossload_dir_internal(संरचना sftp_conn *from, संरचना sftp_conn *to,
    ध्रुव वर्ण *from_path, ध्रुव वर्ण *to_path,
    पूर्णाङ्क depth, Attrib *dirattrib, पूर्णाङ्क preserve_flag, पूर्णाङ्क print_flag,
    पूर्णाङ्क follow_link_flag)
{
	पूर्णाङ्क i, ret = 0, created = 0;
	SFTP_DIRENT **dir_entries;
	वर्ण *filename, *new_from_path = रिक्त, *new_to_path = रिक्त;
	mode_t mode = 0777;
	Attrib *a, curdir, ldirattrib, newdir, lsym;

	debug2_f("crossload dir src \"%s\" to dst \"%s\"", from_path, to_path);

	यदि (depth >= MAX_DIR_DEPTH) {
		error("Maximum directory depth exceeded: %d levels", depth);
		प्रत्यागम -1;
	}

	यदि (dirattrib == रिक्त) {
		यदि (sftp_stat(from, from_path, 1, &ldirattrib) != 0) {
			error("stat remote \"%s\" failed", from_path);
			प्रत्यागम -1;
		}
		dirattrib = &ldirattrib;
	}
	यदि (!S_ISDIR(dirattrib->perm)) {
		error("\"%s\" is not a directory", from_path);
		प्रत्यागम -1;
	}
	यदि (print_flag && print_flag != SFTP_PROGRESS_ONLY)
		mprintf("Retrieving %s\n", from_path);

	curdir = *dirattrib; /* dirattrib will be clobbered */
	curdir.flags &= ~SSH2_FILEXFER_ATTR_SIZE;
	curdir.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	यदि ((curdir.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) == 0) {
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
	यदि (sftp_mkdir(to, to_path, &curdir, 0) == 0)
		created = 1;
	अन्यथा {
		यदि (sftp_stat(to, to_path, 0, &newdir) != 0)
			प्रत्यागम -1;
		यदि (!S_ISDIR(newdir.perm)) {
			error("\"%s\" exists but is not a directory", to_path);
			प्रत्यागम -1;
		}
	}
	curdir.perm = mode;

	यदि (sftp_readdir(from, from_path, &dir_entries) == -1) {
		error("origin readdir \"%s\" failed", from_path);
		प्रत्यागम -1;
	}

	प्रति (i = 0; dir_entries[i] != रिक्त && !interrupted; i++) {
		मुक्त(new_from_path);
		मुक्त(new_to_path);

		filename = dir_entries[i]->filename;
		new_from_path = sftp_path_append(from_path, filename);
		new_to_path = sftp_path_append(to_path, filename);

		a = &dir_entries[i]->a;
		यदि (S_ISLNK(a->perm)) {
			यदि (!follow_link_flag) {
				logit("%s: not a regular file", filename);
				अनुवर्त;
			}
			/* Replace the stat contents with the symlink target */
			यदि (sftp_stat(from, new_from_path, 1, &lsym) != 0) {
				logit("remote stat \"%s\" failed",
				    new_from_path);
				ret = -1;
				अनुवर्त;
			}
			a = &lsym;
		}
		यदि (S_ISDIR(a->perm)) {
			यदि (म_भेद(filename, ".") == 0 ||
			    म_भेद(filename, "..") == 0)
				अनुवर्त;
			यदि (crossload_dir_internal(from, to,
			    new_from_path, new_to_path,
			    depth + 1, a, preserve_flag,
			    print_flag, follow_link_flag) == -1)
				ret = -1;
		} अन्यथा यदि (S_ISREG(a->perm)) {
			यदि (sftp_crossload(from, to, new_from_path,
			    new_to_path, a, preserve_flag) == -1) {
				error("crossload \"%s\" to \"%s\" failed",
				    new_from_path, new_to_path);
				ret = -1;
			}
		} अन्यथा {
			logit("origin \"%s\": not a regular file",
			    new_from_path);
		}
	}
	मुक्त(new_to_path);
	मुक्त(new_from_path);

	यदि (created || preserve_flag)
		sftp_setstat(to, to_path, &curdir);

	sftp_free_dirents(dir_entries);

	प्रत्यागम ret;
}

पूर्णाङ्क
sftp_crossload_dir(संरचना sftp_conn *from, संरचना sftp_conn *to,
    ध्रुव वर्ण *from_path, ध्रुव वर्ण *to_path,
    Attrib *dirattrib, पूर्णाङ्क preserve_flag, पूर्णाङ्क print_flag, पूर्णाङ्क follow_link_flag)
{
	वर्ण *from_path_canon;
	पूर्णाङ्क ret;

	यदि ((from_path_canon = sftp_realpath(from, from_path)) == रिक्त) {
		error("crossload \"%s\": path canonicalization failed",
		    from_path);
		प्रत्यागम -1;
	}

	ret = crossload_dir_internal(from, to, from_path_canon, to_path, 0,
	    dirattrib, preserve_flag, print_flag, follow_link_flag);
	मुक्त(from_path_canon);
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
	संरचना sshbuf *संदेश, *uidbuf, *gidbuf;
	u_int i, expected_id, id;
	वर्ण *name, **usernames = रिक्त, **groupnames = रिक्त;
	u_char type;
	पूर्णाङ्क r;

	*usernamesp = *groupnamesp = रिक्त;
	यदि (!sftp_can_get_users_groups_by_id(conn))
		प्रत्यागम SSH_ERR_FEATURE_UNSUPPORTED;

	यदि ((संदेश = sshbuf_new()) == रिक्त ||
	    (uidbuf = sshbuf_new()) == रिक्त ||
	    (gidbuf = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	expected_id = id = conn->संदेश_id++;
	debug2("Sending SSH2_FXP_EXTENDED(users-groups-by-id@openssh.com)");
	प्रति (i = 0; i < nuids; i++) {
		यदि ((r = sshbuf_put_u32(uidbuf, uids[i])) != 0)
			fatal_fr(r, "compose uids");
	}
	प्रति (i = 0; i < ngids; i++) {
		यदि ((r = sshbuf_put_u32(gidbuf, gids[i])) != 0)
			fatal_fr(r, "compose gids");
	}
	यदि ((r = sshbuf_put_u8(संदेश, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, id)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश,
	    "users-groups-by-id@openssh.com")) != 0 ||
	    (r = sshbuf_put_stringb(संदेश, uidbuf)) != 0 ||
	    (r = sshbuf_put_stringb(संदेश, gidbuf)) != 0)
		fatal_fr(r, "compose");
	send_संदेश(conn, संदेश);
	get_संदेश(conn, संदेश);
	यदि ((r = sshbuf_get_u8(संदेश, &type)) != 0 ||
	    (r = sshbuf_get_u32(संदेश, &id)) != 0)
		fatal_fr(r, "parse");
	यदि (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	यदि (type == SSH2_FXP_STATUS) {
		u_int status;
		वर्ण *errmsg;

		यदि ((r = sshbuf_get_u32(संदेश, &status)) != 0 ||
		    (r = sshbuf_get_cstring(संदेश, &errmsg, रिक्त)) != 0)
			fatal_fr(r, "parse status");
		error("users-groups-by-id %s",
		    *errmsg == '\0' ? fx2txt(status) : errmsg);
		मुक्त(errmsg);
		sshbuf_free(संदेश);
		sshbuf_free(uidbuf);
		sshbuf_free(gidbuf);
		प्रत्यागम -1;
	} अन्यथा यदि (type != SSH2_FXP_EXTENDED_REPLY)
		fatal("Expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_REPLY, type);

	/* reuse */
	sshbuf_free(uidbuf);
	sshbuf_free(gidbuf);
	uidbuf = gidbuf = रिक्त;
	यदि ((r = sshbuf_froms(संदेश, &uidbuf)) != 0 ||
	    (r = sshbuf_froms(संदेश, &gidbuf)) != 0)
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
	sshbuf_free(संदेश);
	/* success */
	*usernamesp = usernames;
	*groupnamesp = groupnames;
	प्रत्यागम 0;
}

वर्ण *
sftp_path_append(ध्रुव वर्ण *p1, ध्रुव वर्ण *p2)
{
	वर्ण *ret;
	माप_प्रकार len = म_माप(p1) + म_माप(p2) + 2;

	ret = xmalloc(len);
	strlcpy(ret, p1, len);
	यदि (p1[0] != '\0' && p1[म_माप(p1) - 1] != '/')
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
	यदि (p && !path_absolute(p)) {
		abs_str = sftp_path_append(pwd, p);
		मुक्त(p);
		प्रत्यागम(abs_str);
	} अन्यथा
		प्रत्यागम(p);
}

पूर्णाङ्क
sftp_remote_is_dir(संरचना sftp_conn *conn, ध्रुव वर्ण *path)
{
	Attrib a;

	/* XXX: report errors? */
	यदि (sftp_stat(conn, path, 1, &a) != 0)
		प्रत्यागम(0);
	यदि (!(a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS))
		प्रत्यागम(0);
	प्रत्यागम S_ISDIR(a.perm);
}


/* Check whether path returned from glob(..., GLOB_MARK, ...) is a directory */
पूर्णाङ्क
sftp_globpath_is_dir(ध्रुव वर्ण *pathname)
{
	माप_प्रकार l = म_माप(pathname);

	प्रत्यागम l > 0 && pathname[l - 1] == '/';
}

