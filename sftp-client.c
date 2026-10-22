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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/queue.h>
#समावेश <sys/stat.h>
#समावेश <sys/time.h>
#समावेश <sys/statvfs.h>
#समावेश <sys/uio.h>

#समावेश <dirent.h>
#समावेश <errno.h>
#समावेश <fcntl.h>
#समावेश <poll.h>
#समावेश <signal.h>
#समावेश <stdarg.h>
#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <unistd.h>

#समावेश "xmalloc.h"
#समावेश "ssherr.h"
#समावेश "sshbuf.h"
#समावेश "log.h"
#समावेश "atomicio.h"
#समावेश "progressmeter.h"
#समावेश "misc.h"
#समावेश "utf8.h"

#समावेश "sftp.h"
#समावेश "sftp-common.h"
#समावेश "sftp-client.h"

बाह्य अस्थिर संक_पूर्ण_प्रकार interrupted;
बाह्य पूर्णांक showprogress;

/* Default size of buffer for up/download (fix sftp.1 scp.1 if changed) */
#घोषणा DEFAULT_COPY_BUFLEN	32768

/* Default number of concurrent xfer requests (fix sftp.1 scp.1 if changed) */
#घोषणा DEFAULT_अंक_REQUESTS	64

/* Minimum amount of data to read at a time */
#घोषणा MIN_READ_आकार	512

/* Maximum depth to descend in directory trees */
#घोषणा MAX_DIR_DEPTH 64

/* Directory separator characters */
#अगर_घोषित HAVE_CYGWIN
# define SFTP_DIRECTORY_CHARS      "/\\"
#अन्यथा /* HAVE_CYGWIN */
# define SFTP_DIRECTORY_CHARS      "/"
#पूर्ण_अगर /* HAVE_CYGWIN */

काष्ठा sftp_conn {
	पूर्णांक fd_in;
	पूर्णांक fd_out;
	u_int download_buflen;
	u_int upload_buflen;
	u_int अंक_requests;
	u_int version;
	u_int संदेश_id;
#घोषणा SFTP_EXT_POSIX_RENAME		0x00000001
#घोषणा SFTP_EXT_STATVFS		0x00000002
#घोषणा SFTP_EXT_FSTATVFS		0x00000004
#घोषणा SFTP_EXT_HARDLINK		0x00000008
#घोषणा SFTP_EXT_FSYNC			0x00000010
#घोषणा SFTP_EXT_LSETSTAT		0x00000020
#घोषणा SFTP_EXT_LIMITS			0x00000040
#घोषणा SFTP_EXT_PATH_EXPAND		0x00000080
#घोषणा SFTP_EXT_COPY_तथ्य		0x00000100
#घोषणा SFTP_EXT_GETUSERSGROUPS_BY_ID	0x00000200
	u_int exts;
	uint64_t limit_kbps;
	काष्ठा bwlimit bwlimit_in, bwlimit_out;
};

/* Tracks in-progress requests during file transfers */
काष्ठा request {
	u_int id;
	माप_प्रकार len;
	uint64_t offset;
	TAILQ_ENTRY(request) tq;
};
TAILQ_HEAD(requests, request);

अटल u_char *
get_handle(काष्ठा sftp_conn *conn, u_int expected_id, माप_प्रकार *len,
    स्थिर अक्षर *errfmt, ...) __attribute__((format(म_लिखो, 4, 5)));

अटल काष्ठा request *
request_enqueue(काष्ठा requests *requests, u_int id, माप_प्रकार len,
    uint64_t offset)
{
	काष्ठा request *req;

	req = xcalloc(1, माप(*req));
	req->id = id;
	req->len = len;
	req->offset = offset;
	TAILQ_INSERT_TAIL(requests, req, tq);
	वापस req;
}

अटल काष्ठा request *
request_find(काष्ठा requests *requests, u_int id)
{
	काष्ठा request *req;

	क्रम (req = TAILQ_FIRST(requests);
	    req != शून्य && req->id != id;
	    req = TAILQ_NEXT(req, tq))
		;
	वापस req;
}

अटल पूर्णांक
sftpio(व्योम *_bwlimit, माप_प्रकार amount)
{
	काष्ठा bwlimit *bwlimit = (काष्ठा bwlimit *)_bwlimit;

	refresh_progress_meter(0);
	अगर (bwlimit != शून्य)
		bandwidth_limit(bwlimit, amount);
	वापस 0;
}

अटल व्योम
send_संदेश(काष्ठा sftp_conn *conn, काष्ठा sshbuf *m)
{
	u_char mlen[4];
	काष्ठा iovec iov[2];

	अगर (sshbuf_len(m) > SFTP_MAX_संदेश_लंबाई)
		fatal("Outbound message too long %zu", sshbuf_len(m));

	/* Send length first */
	put_u32(mlen, sshbuf_len(m));
	iov[0].iov_base = mlen;
	iov[0].iov_len = माप(mlen);
	iov[1].iov_base = (u_char *)sshbuf_ptr(m);
	iov[1].iov_len = sshbuf_len(m);

	अगर (atomiciov6(writev, conn->fd_out, iov, 2, sftpio,
	    conn->limit_kbps > 0 ? &conn->bwlimit_out : शून्य) !=
	    sshbuf_len(m) + माप(mlen))
		fatal("Couldn't send packet: %s", म_त्रुटि(त्रुटि_सं));

	sshbuf_reset(m);
}

अटल व्योम
get_संदेश_extended(काष्ठा sftp_conn *conn, काष्ठा sshbuf *m, पूर्णांक initial)
{
	u_int संदेश_len;
	u_char *p;
	पूर्णांक r;

	sshbuf_reset(m);
	अगर ((r = sshbuf_reserve(m, 4, &p)) != 0)
		fatal_fr(r, "reserve");
	अगर (atomicio6(पढ़ो, conn->fd_in, p, 4, sftpio,
	    conn->limit_kbps > 0 ? &conn->bwlimit_in : शून्य) != 4) {
		अगर (त्रुटि_सं == EPIPE || त्रुटि_सं == ECONNRESET)
			fatal("Connection closed");
		अन्यथा
			fatal("Couldn't read packet: %s", म_त्रुटि(त्रुटि_सं));
	}

	अगर ((r = sshbuf_get_u32(m, &संदेश_len)) != 0)
		fatal_fr(r, "sshbuf_get_u32");
	अगर (संदेश_len > SFTP_MAX_संदेश_लंबाई) {
		do_log2(initial ? SYSLOG_LEVEL_ERROR : SYSLOG_LEVEL_FATAL,
		    "Received message too long %u", संदेश_len);
		fatal("Ensure the remote shell produces no output "
		    "for non-interactive sessions.");
	}

	अगर ((r = sshbuf_reserve(m, संदेश_len, &p)) != 0)
		fatal_fr(r, "reserve");
	अगर (atomicio6(पढ़ो, conn->fd_in, p, संदेश_len, sftpio,
	    conn->limit_kbps > 0 ? &conn->bwlimit_in : शून्य)
	    != संदेश_len) {
		अगर (त्रुटि_सं == EPIPE)
			fatal("Connection closed");
		अन्यथा
			fatal("Read packet: %s", म_त्रुटि(त्रुटि_सं));
	}
}

अटल व्योम
get_संदेश(काष्ठा sftp_conn *conn, काष्ठा sshbuf *m)
{
	get_संदेश_extended(conn, m, 0);
}

अटल व्योम
send_string_request(काष्ठा sftp_conn *conn, u_int id, u_int code, स्थिर अक्षर *s,
    u_int len)
{
	काष्ठा sshbuf *संदेश;
	पूर्णांक r;

	अगर ((संदेश = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = sshbuf_put_u8(संदेश, code)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, id)) != 0 ||
	    (r = sshbuf_put_string(संदेश, s, len)) != 0)
		fatal_fr(r, "compose");
	send_संदेश(conn, संदेश);
	debug3("Sent message fd %d T:%u I:%u", conn->fd_out, code, id);
	sshbuf_free(संदेश);
}

अटल व्योम
send_string_attrs_request(काष्ठा sftp_conn *conn, u_int id, u_int code,
    स्थिर व्योम *s, u_int len, Attrib *a)
{
	काष्ठा sshbuf *संदेश;
	पूर्णांक r;

	अगर ((संदेश = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = sshbuf_put_u8(संदेश, code)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, id)) != 0 ||
	    (r = sshbuf_put_string(संदेश, s, len)) != 0 ||
	    (r = encode_attrib(संदेश, a)) != 0)
		fatal_fr(r, "compose");
	send_संदेश(conn, संदेश);
	debug3("Sent message fd %d T:%u I:%u F:0x%04x M:%05o",
	    conn->fd_out, code, id, a->flags, a->perm);
	sshbuf_free(संदेश);
}

अटल u_int
get_status(काष्ठा sftp_conn *conn, u_int expected_id)
{
	काष्ठा sshbuf *संदेश;
	u_char type;
	u_int id, status;
	पूर्णांक r;

	अगर ((संदेश = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	get_संदेश(conn, संदेश);
	अगर ((r = sshbuf_get_u8(संदेश, &type)) != 0 ||
	    (r = sshbuf_get_u32(संदेश, &id)) != 0)
		fatal_fr(r, "compose");

	अगर (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	अगर (type != SSH2_FXP_STATUS)
		fatal("Expected SSH2_FXP_STATUS(%u) packet, got %u",
		    SSH2_FXP_STATUS, type);

	अगर ((r = sshbuf_get_u32(संदेश, &status)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(संदेश);

	debug3("SSH2_FXP_STATUS %u", status);

	वापस status;
}

अटल u_char *
get_handle(काष्ठा sftp_conn *conn, u_int expected_id, माप_प्रकार *len,
    स्थिर अक्षर *errfmt, ...)
{
	काष्ठा sshbuf *संदेश;
	u_int id, status;
	u_char type;
	u_char *handle;
	अक्षर errmsg[256];
	बहु_सूची args;
	पूर्णांक r;

	बहु_शुरू(args, errfmt);
	अगर (errfmt != शून्य)
		vsnprintf(errmsg, माप(errmsg), errfmt, args);
	बहु_पूर्ण(args);

	अगर ((संदेश = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	get_संदेश(conn, संदेश);
	अगर ((r = sshbuf_get_u8(संदेश, &type)) != 0 ||
	    (r = sshbuf_get_u32(संदेश, &id)) != 0)
		fatal_fr(r, "parse");

	अगर (id != expected_id)
		fatal("%s: ID mismatch (%u != %u)",
		    errfmt == शून्य ? __func__ : errmsg, id, expected_id);
	अगर (type == SSH2_FXP_STATUS) {
		अगर ((r = sshbuf_get_u32(संदेश, &status)) != 0)
			fatal_fr(r, "parse status");
		अगर (errfmt != शून्य)
			error("%s: %s", errmsg, fx2txt(status));
		sshbuf_free(संदेश);
		वापस(शून्य);
	} अन्यथा अगर (type != SSH2_FXP_HANDLE)
		fatal("%s: Expected SSH2_FXP_HANDLE(%u) packet, got %u",
		    errfmt == शून्य ? __func__ : errmsg, SSH2_FXP_HANDLE, type);

	अगर ((r = sshbuf_get_string(संदेश, &handle, len)) != 0)
		fatal_fr(r, "parse handle");
	sshbuf_free(संदेश);

	वापस handle;
}

अटल पूर्णांक
get_decode_stat(काष्ठा sftp_conn *conn, u_int expected_id, पूर्णांक quiet, Attrib *a)
{
	काष्ठा sshbuf *संदेश;
	u_int id;
	u_char type;
	पूर्णांक r;
	Attrib attr;

	अगर (a != शून्य)
		स_रखो(a, '\0', माप(*a));
	अगर ((संदेश = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	get_संदेश(conn, संदेश);

	अगर ((r = sshbuf_get_u8(संदेश, &type)) != 0 ||
	    (r = sshbuf_get_u32(संदेश, &id)) != 0)
		fatal_fr(r, "parse");

	अगर (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	अगर (type == SSH2_FXP_STATUS) {
		u_int status;

		अगर ((r = sshbuf_get_u32(संदेश, &status)) != 0)
			fatal_fr(r, "parse status");
		अगर (quiet)
			debug("stat remote: %s", fx2txt(status));
		अन्यथा
			error("stat remote: %s", fx2txt(status));
		sshbuf_free(संदेश);
		वापस -1;
	} अन्यथा अगर (type != SSH2_FXP_ATTRS) {
		fatal("Expected SSH2_FXP_ATTRS(%u) packet, got %u",
		    SSH2_FXP_ATTRS, type);
	}
	अगर ((r = decode_attrib(संदेश, &attr)) != 0) {
		error_fr(r, "decode_attrib");
		sshbuf_free(संदेश);
		वापस -1;
	}
	/* success */
	अगर (a != शून्य)
		*a = attr;
	debug3("Received stat reply T:%u I:%u F:0x%04x M:%05o",
	    type, id, attr.flags, attr.perm);
	sshbuf_free(संदेश);

	वापस 0;
}

अटल पूर्णांक
get_decode_statvfs(काष्ठा sftp_conn *conn, काष्ठा sftp_statvfs *st,
    u_int expected_id, पूर्णांक quiet)
{
	काष्ठा sshbuf *संदेश;
	u_char type;
	u_int id;
	uint64_t flag;
	पूर्णांक r;

	अगर ((संदेश = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	get_संदेश(conn, संदेश);

	अगर ((r = sshbuf_get_u8(संदेश, &type)) != 0 ||
	    (r = sshbuf_get_u32(संदेश, &id)) != 0)
		fatal_fr(r, "parse");

	debug3("Received statvfs reply T:%u I:%u", type, id);
	अगर (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	अगर (type == SSH2_FXP_STATUS) {
		u_int status;

		अगर ((r = sshbuf_get_u32(संदेश, &status)) != 0)
			fatal_fr(r, "parse status");
		अगर (quiet)
			debug("remote statvfs: %s", fx2txt(status));
		अन्यथा
			error("remote statvfs: %s", fx2txt(status));
		sshbuf_free(संदेश);
		वापस -1;
	} अन्यथा अगर (type != SSH2_FXP_EXTENDED_REPLY) {
		fatal("Expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_REPLY, type);
	}

	स_रखो(st, 0, माप(*st));
	अगर ((r = sshbuf_get_u64(संदेश, &st->f_bsize)) != 0 ||
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

	वापस 0;
}

काष्ठा sftp_conn *
sftp_init(पूर्णांक fd_in, पूर्णांक fd_out, u_int transfer_buflen, u_int अंक_requests,
    uint64_t limit_kbps)
{
	u_char type;
	काष्ठा sshbuf *संदेश;
	काष्ठा sftp_conn *ret;
	पूर्णांक r;

	ret = xcalloc(1, माप(*ret));
	ret->संदेश_id = 1;
	ret->fd_in = fd_in;
	ret->fd_out = fd_out;
	ret->download_buflen = ret->upload_buflen =
	    transfer_buflen ? transfer_buflen : DEFAULT_COPY_BUFLEN;
	ret->अंक_requests =
	    अंक_requests ? अंक_requests : DEFAULT_अंक_REQUESTS;
	ret->exts = 0;
	ret->limit_kbps = 0;

	अगर ((संदेश = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = sshbuf_put_u8(संदेश, SSH2_FXP_INIT)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, SSH2_FILEXFER_VERSION)) != 0)
		fatal_fr(r, "parse");

	send_संदेश(ret, संदेश);

	get_संदेश_extended(ret, संदेश, 1);

	/* Expecting a VERSION reply */
	अगर ((r = sshbuf_get_u8(संदेश, &type)) != 0)
		fatal_fr(r, "parse type");
	अगर (type != SSH2_FXP_VERSION) {
		error("Invalid packet back from SSH2_FXP_INIT (type %u)",
		    type);
		sshbuf_free(संदेश);
		मुक्त(ret);
		वापस(शून्य);
	}
	अगर ((r = sshbuf_get_u32(संदेश, &ret->version)) != 0)
		fatal_fr(r, "parse version");

	debug2("Remote version: %u", ret->version);

	/* Check for extensions */
	जबतक (sshbuf_len(संदेश) > 0) {
		अक्षर *name;
		u_char *मूल्य;
		माप_प्रकार vlen;
		पूर्णांक known = 0;

		अगर ((r = sshbuf_get_cstring(संदेश, &name, शून्य)) != 0 ||
		    (r = sshbuf_get_string(संदेश, &मूल्य, &vlen)) != 0)
			fatal_fr(r, "parse extension");
		अगर (म_भेद(name, "posix-rename@openssh.com") == 0 &&
		    म_भेद((अक्षर *)मूल्य, "1") == 0) {
			ret->exts |= SFTP_EXT_POSIX_RENAME;
			known = 1;
		} अन्यथा अगर (म_भेद(name, "statvfs@openssh.com") == 0 &&
		    म_भेद((अक्षर *)मूल्य, "2") == 0) {
			ret->exts |= SFTP_EXT_STATVFS;
			known = 1;
		} अन्यथा अगर (म_भेद(name, "fstatvfs@openssh.com") == 0 &&
		    म_भेद((अक्षर *)मूल्य, "2") == 0) {
			ret->exts |= SFTP_EXT_FSTATVFS;
			known = 1;
		} अन्यथा अगर (म_भेद(name, "hardlink@openssh.com") == 0 &&
		    म_भेद((अक्षर *)मूल्य, "1") == 0) {
			ret->exts |= SFTP_EXT_HARDLINK;
			known = 1;
		} अन्यथा अगर (म_भेद(name, "fsync@openssh.com") == 0 &&
		    म_भेद((अक्षर *)मूल्य, "1") == 0) {
			ret->exts |= SFTP_EXT_FSYNC;
			known = 1;
		} अन्यथा अगर (म_भेद(name, "lsetstat@openssh.com") == 0 &&
		    म_भेद((अक्षर *)मूल्य, "1") == 0) {
			ret->exts |= SFTP_EXT_LSETSTAT;
			known = 1;
		} अन्यथा अगर (म_भेद(name, "limits@openssh.com") == 0 &&
		    म_भेद((अक्षर *)मूल्य, "1") == 0) {
			ret->exts |= SFTP_EXT_LIMITS;
			known = 1;
		} अन्यथा अगर (म_भेद(name, "expand-path@openssh.com") == 0 &&
		    म_भेद((अक्षर *)मूल्य, "1") == 0) {
			ret->exts |= SFTP_EXT_PATH_EXPAND;
			known = 1;
		} अन्यथा अगर (म_भेद(name, "copy-data") == 0 &&
		    म_भेद((अक्षर *)मूल्य, "1") == 0) {
			ret->exts |= SFTP_EXT_COPY_तथ्य;
			known = 1;
		} अन्यथा अगर (म_भेद(name,
		    "users-groups-by-id@openssh.com") == 0 &&
		    म_भेद((अक्षर *)मूल्य, "1") == 0) {
			ret->exts |= SFTP_EXT_GETUSERSGROUPS_BY_ID;
			known = 1;
		}
		अगर (known) {
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
	अगर (ret->exts & SFTP_EXT_LIMITS) {
		काष्ठा sftp_limits limits;
		अगर (sftp_get_limits(ret, &limits) != 0)
			fatal_f("limits failed");

		/* If the caller did not specify, find a good value */
		अगर (transfer_buflen == 0) {
			ret->download_buflen = MINIMUM(limits.read_लंबाई,
			    SFTP_MAX_संदेश_लंबाई - 1024);
			ret->upload_buflen = MINIMUM(limits.write_लंबाई,
			    SFTP_MAX_संदेश_लंबाई - 1024);
			ret->download_buflen = MAXIMUM(ret->download_buflen, 64);
			ret->upload_buflen = MAXIMUM(ret->upload_buflen, 64);
			debug3("server upload/download buffer sizes "
			    "%llu / %llu; using %u / %u",
			    (अचिन्हित दीर्घ दीर्घ)limits.write_लंबाई,
			    (अचिन्हित दीर्घ दीर्घ)limits.read_लंबाई,
			    ret->upload_buflen, ret->download_buflen);
		}
	}

	/* Some filexfer v.0 servers don't support large packets */
	अगर (ret->version == 0) {
		ret->download_buflen = MINIMUM(ret->download_buflen, 20480);
		ret->upload_buflen = MINIMUM(ret->upload_buflen, 20480);
	}

	ret->limit_kbps = limit_kbps;
	अगर (ret->limit_kbps > 0) {
		bandwidth_limit_init(&ret->bwlimit_in, ret->limit_kbps,
		    ret->download_buflen);
		bandwidth_limit_init(&ret->bwlimit_out, ret->limit_kbps,
		    ret->upload_buflen);
	}

	वापस ret;
}

व्योम
sftp_free(काष्ठा sftp_conn *conn)
{
	अगर (conn == शून्य)
		वापस;
	freezero(conn, माप(*conn));
}

u_int
sftp_proto_version(काष्ठा sftp_conn *conn)
{
	वापस conn->version;
}

पूर्णांक
sftp_get_limits(काष्ठा sftp_conn *conn, काष्ठा sftp_limits *limits)
{
	u_int id, संदेश_id;
	u_char type;
	काष्ठा sshbuf *संदेश;
	पूर्णांक r;

	अगर ((conn->exts & SFTP_EXT_LIMITS) == 0) {
		error("Server does not support limits@openssh.com extension");
		वापस -1;
	}

	अगर ((संदेश = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");

	id = conn->संदेश_id++;
	अगर ((r = sshbuf_put_u8(संदेश, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, id)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, "limits@openssh.com")) != 0)
		fatal_fr(r, "compose");
	send_संदेश(conn, संदेश);
	debug3("Sent message limits@openssh.com I:%u", id);

	get_संदेश(conn, संदेश);

	अगर ((r = sshbuf_get_u8(संदेश, &type)) != 0 ||
	    (r = sshbuf_get_u32(संदेश, &संदेश_id)) != 0)
		fatal_fr(r, "parse");

	debug3("Received limits reply T:%u I:%u", type, संदेश_id);
	अगर (id != संदेश_id)
		fatal("ID mismatch (%u != %u)", संदेश_id, id);
	अगर (type != SSH2_FXP_EXTENDED_REPLY) {
		debug_f("expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_REPLY, type);
		/* Disable the limits extension */
		conn->exts &= ~SFTP_EXT_LIMITS;
		sshbuf_free(संदेश);
		वापस -1;
	}

	स_रखो(limits, 0, माप(*limits));
	अगर ((r = sshbuf_get_u64(संदेश, &limits->packet_लंबाई)) != 0 ||
	    (r = sshbuf_get_u64(संदेश, &limits->read_लंबाई)) != 0 ||
	    (r = sshbuf_get_u64(संदेश, &limits->write_लंबाई)) != 0 ||
	    (r = sshbuf_get_u64(संदेश, &limits->open_handles)) != 0)
		fatal_fr(r, "parse limits");

	sshbuf_free(संदेश);

	वापस 0;
}

पूर्णांक
sftp_close(काष्ठा sftp_conn *conn, स्थिर u_char *handle, u_int handle_len)
{
	u_int id, status;
	काष्ठा sshbuf *संदेश;
	पूर्णांक r;

	अगर ((संदेश = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");

	id = conn->संदेश_id++;
	अगर ((r = sshbuf_put_u8(संदेश, SSH2_FXP_CLOSE)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, id)) != 0 ||
	    (r = sshbuf_put_string(संदेश, handle, handle_len)) != 0)
		fatal_fr(r, "parse");
	send_संदेश(conn, संदेश);
	debug3("Sent message SSH2_FXP_CLOSE I:%u", id);

	status = get_status(conn, id);
	अगर (status != SSH2_FX_OK)
		error("close remote: %s", fx2txt(status));

	sshbuf_free(संदेश);

	वापस status == SSH2_FX_OK ? 0 : -1;
}


अटल पूर्णांक
sftp_lsreaddir(काष्ठा sftp_conn *conn, स्थिर अक्षर *path, पूर्णांक print_flag,
    SFTP_DIRENT ***dir)
{
	काष्ठा sshbuf *संदेश;
	u_int गिनती, id, i, expected_id, ents = 0;
	माप_प्रकार handle_len;
	u_char type, *handle;
	पूर्णांक status = SSH2_FX_FAILURE;
	पूर्णांक r;

	अगर (dir)
		*dir = शून्य;

	id = conn->संदेश_id++;

	अगर ((संदेश = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = sshbuf_put_u8(संदेश, SSH2_FXP_OPENDIR)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, id)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, path)) != 0)
		fatal_fr(r, "compose OPENDIR");
	send_संदेश(conn, संदेश);

	handle = get_handle(conn, id, &handle_len,
	    "remote readdir(\"%s\")", path);
	अगर (handle == शून्य) {
		sshbuf_free(संदेश);
		वापस -1;
	}

	अगर (dir) {
		ents = 0;
		*dir = xcalloc(1, माप(**dir));
		(*dir)[0] = शून्य;
	}

	क्रम (; !interrupted;) {
		id = expected_id = conn->संदेश_id++;

		debug3("Sending SSH2_FXP_READDIR I:%u", id);

		sshbuf_reset(संदेश);
		अगर ((r = sshbuf_put_u8(संदेश, SSH2_FXP_READDIR)) != 0 ||
		    (r = sshbuf_put_u32(संदेश, id)) != 0 ||
		    (r = sshbuf_put_string(संदेश, handle, handle_len)) != 0)
			fatal_fr(r, "compose READDIR");
		send_संदेश(conn, संदेश);

		sshbuf_reset(संदेश);

		get_संदेश(conn, संदेश);

		अगर ((r = sshbuf_get_u8(संदेश, &type)) != 0 ||
		    (r = sshbuf_get_u32(संदेश, &id)) != 0)
			fatal_fr(r, "parse");

		debug3("Received reply T:%u I:%u", type, id);

		अगर (id != expected_id)
			fatal("ID mismatch (%u != %u)", id, expected_id);

		अगर (type == SSH2_FXP_STATUS) {
			u_int rstatus;

			अगर ((r = sshbuf_get_u32(संदेश, &rstatus)) != 0)
				fatal_fr(r, "parse status");
			debug3("Received SSH2_FXP_STATUS %d", rstatus);
			अगर (rstatus == SSH2_FX_EOF)
				अवरोध;
			error("Couldn't read directory: %s", fx2txt(rstatus));
			जाओ out;
		} अन्यथा अगर (type != SSH2_FXP_NAME)
			fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
			    SSH2_FXP_NAME, type);

		अगर ((r = sshbuf_get_u32(संदेश, &गिनती)) != 0)
			fatal_fr(r, "parse count");
		अगर (गिनती > SSHBUF_आकार_MAX)
			fatal_f("nonsensical number of entries");
		अगर (गिनती == 0)
			अवरोध;
		debug3("Received %d SSH2_FXP_NAME responses", गिनती);
		क्रम (i = 0; i < गिनती; i++) {
			अक्षर *filename, *longname;
			Attrib a;

			अगर ((r = sshbuf_get_cstring(संदेश, &filename,
			    शून्य)) != 0 ||
			    (r = sshbuf_get_cstring(संदेश, &longname,
			    शून्य)) != 0)
				fatal_fr(r, "parse filenames");
			अगर ((r = decode_attrib(संदेश, &a)) != 0) {
				error_fr(r, "couldn't decode attrib");
				मुक्त(filename);
				मुक्त(longname);
				जाओ out;
			}

			अगर (print_flag)
				mprintf("%s\n", longname);

			/*
			 * Directory entries should never contain '/'
			 * These can be used to attack recursive ops
			 * (e.g. send '../../../../etc/passwd')
			 */
			अगर (*filename == '\0' ||
			    strpbrk(filename, SFTP_DIRECTORY_CHARS) != शून्य) {
				error("Server sent suspect path \"%s\" "
				    "during readdir of \"%s\"", filename, path);
			} अन्यथा अगर (dir) {
				*dir = xreallocarray(*dir, ents + 2, माप(**dir));
				(*dir)[ents] = xcalloc(1, माप(***dir));
				(*dir)[ents]->filename = xstrdup(filename);
				(*dir)[ents]->longname = xstrdup(longname);
				स_नकल(&(*dir)[ents]->a, &a, माप(a));
				(*dir)[++ents] = शून्य;
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

	अगर (status != 0 && dir != शून्य) {
		/* Don't return results on error */
		sftp_free_dirents(*dir);
		*dir = शून्य;
	} अन्यथा अगर (interrupted && dir != शून्य && *dir != शून्य) {
		/* Don't return partial matches on interrupt */
		sftp_free_dirents(*dir);
		*dir = xcalloc(1, माप(**dir));
		**dir = शून्य;
	}

	वापस status == SSH2_FX_OK ? 0 : -1;
}

पूर्णांक
sftp_readdir(काष्ठा sftp_conn *conn, स्थिर अक्षर *path, SFTP_DIRENT ***dir)
{
	वापस sftp_lsreaddir(conn, path, 0, dir);
}

व्योम sftp_free_dirents(SFTP_DIRENT **s)
{
	पूर्णांक i;

	अगर (s == शून्य)
		वापस;
	क्रम (i = 0; s[i]; i++) {
		मुक्त(s[i]->filename);
		मुक्त(s[i]->longname);
		मुक्त(s[i]);
	}
	मुक्त(s);
}

पूर्णांक
sftp_rm(काष्ठा sftp_conn *conn, स्थिर अक्षर *path)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_REMOVE \"%s\"", path);

	id = conn->संदेश_id++;
	send_string_request(conn, id, SSH2_FXP_REMOVE, path, म_माप(path));
	status = get_status(conn, id);
	अगर (status != SSH2_FX_OK)
		error("remote delete %s: %s", path, fx2txt(status));
	वापस status == SSH2_FX_OK ? 0 : -1;
}

पूर्णांक
sftp_mkdir(काष्ठा sftp_conn *conn, स्थिर अक्षर *path, Attrib *a, पूर्णांक print_flag)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_MKDIR \"%s\"", path);

	id = conn->संदेश_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_MKDIR, path,
	    म_माप(path), a);

	status = get_status(conn, id);
	अगर (status != SSH2_FX_OK && print_flag)
		error("remote mkdir \"%s\": %s", path, fx2txt(status));

	वापस status == SSH2_FX_OK ? 0 : -1;
}

पूर्णांक
sftp_mkpath(काष्ठा sftp_conn *conn, स्थिर अक्षर *path, Attrib *a, पूर्णांक print_flag)
{
	अक्षर *slash, *tmp_path;
	पूर्णांक done;

	tmp_path = xstrdup(path);
	slash = tmp_path;

	क्रम (;;) {
		slash += म_अखोज(slash, "/");
		slash += म_खोज(slash, "/");

		done = (*slash == '\0');
		*slash = '\0';

		अगर (!sftp_remote_is_dir(conn, tmp_path)) {
			अगर (sftp_mkdir(conn, tmp_path, a, print_flag) != 0) {
				मुक्त(tmp_path);
				वापस -1;
			}
		}

		अगर (done)
			अवरोध;

		*slash = '/';
	}

	मुक्त(tmp_path);
	वापस 0;
}

पूर्णांक
sftp_rmdir(काष्ठा sftp_conn *conn, स्थिर अक्षर *path)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_RMDIR \"%s\"", path);

	id = conn->संदेश_id++;
	send_string_request(conn, id, SSH2_FXP_RMDIR, path,
	    म_माप(path));

	status = get_status(conn, id);
	अगर (status != SSH2_FX_OK)
		error("remote rmdir \"%s\": %s", path, fx2txt(status));

	वापस status == SSH2_FX_OK ? 0 : -1;
}

पूर्णांक
sftp_stat(काष्ठा sftp_conn *conn, स्थिर अक्षर *path, पूर्णांक quiet, Attrib *a)
{
	u_int id;

	debug2("Sending SSH2_FXP_STAT \"%s\"", path);

	id = conn->संदेश_id++;

	send_string_request(conn, id,
	    conn->version == 0 ? SSH2_FXP_STAT_VERSION_0 : SSH2_FXP_STAT,
	    path, म_माप(path));

	वापस get_decode_stat(conn, id, quiet, a);
}

पूर्णांक
sftp_lstat(काष्ठा sftp_conn *conn, स्थिर अक्षर *path, पूर्णांक quiet, Attrib *a)
{
	u_int id;

	अगर (conn->version == 0) {
		do_log2(quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_INFO,
		    "Server version does not support lstat operation");
		वापस sftp_stat(conn, path, quiet, a);
	}

	id = conn->संदेश_id++;
	send_string_request(conn, id, SSH2_FXP_LSTAT, path,
	    म_माप(path));

	वापस get_decode_stat(conn, id, quiet, a);
}

#अगर_घोषित notyet
पूर्णांक
sftp_fstat(काष्ठा sftp_conn *conn, स्थिर u_char *handle, u_int handle_len,
    पूर्णांक quiet, Attrib *a)
{
	u_int id;

	debug2("Sending SSH2_FXP_FSTAT \"%s\"");

	id = conn->संदेश_id++;
	send_string_request(conn, id, SSH2_FXP_FSTAT, handle,
	    handle_len);

	वापस get_decode_stat(conn, id, quiet, a);
}
#पूर्ण_अगर

पूर्णांक
sftp_setstat(काष्ठा sftp_conn *conn, स्थिर अक्षर *path, Attrib *a)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_SETSTAT \"%s\"", path);

	id = conn->संदेश_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_SETSTAT, path,
	    म_माप(path), a);

	status = get_status(conn, id);
	अगर (status != SSH2_FX_OK)
		error("remote setstat \"%s\": %s", path, fx2txt(status));

	वापस status == SSH2_FX_OK ? 0 : -1;
}

पूर्णांक
sftp_fsetstat(काष्ठा sftp_conn *conn, स्थिर u_char *handle, u_int handle_len,
    Attrib *a)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_FSETSTAT");

	id = conn->संदेश_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_FSETSTAT, handle,
	    handle_len, a);

	status = get_status(conn, id);
	अगर (status != SSH2_FX_OK)
		error("remote fsetstat: %s", fx2txt(status));

	वापस status == SSH2_FX_OK ? 0 : -1;
}

/* Implements both the realpath and expand-path operations */
अटल अक्षर *
sftp_realpath_expand(काष्ठा sftp_conn *conn, स्थिर अक्षर *path, पूर्णांक expand)
{
	काष्ठा sshbuf *संदेश;
	u_int expected_id, गिनती, id;
	अक्षर *filename, *longname;
	Attrib a;
	u_char type;
	पूर्णांक r;
	स्थिर अक्षर *what = "SSH2_FXP_REALPATH";

	अगर (expand)
		what = "expand-path@openssh.com";
	अगर ((संदेश = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");

	expected_id = id = conn->संदेश_id++;
	अगर (expand) {
		debug2("Sending SSH2_FXP_EXTENDED(expand-path@openssh.com) "
		    "\"%s\"", path);
		अगर ((r = sshbuf_put_u8(संदेश, SSH2_FXP_EXTENDED)) != 0 ||
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
	अगर ((r = sshbuf_get_u8(संदेश, &type)) != 0 ||
	    (r = sshbuf_get_u32(संदेश, &id)) != 0)
		fatal_fr(r, "parse");

	अगर (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);

	अगर (type == SSH2_FXP_STATUS) {
		u_int status;
		अक्षर *errmsg;

		अगर ((r = sshbuf_get_u32(संदेश, &status)) != 0 ||
		    (r = sshbuf_get_cstring(संदेश, &errmsg, शून्य)) != 0)
			fatal_fr(r, "parse status");
		error("%s %s: %s", expand ? "expand" : "realpath",
		    path, *errmsg == '\0' ? fx2txt(status) : errmsg);
		मुक्त(errmsg);
		sshbuf_free(संदेश);
		वापस शून्य;
	} अन्यथा अगर (type != SSH2_FXP_NAME)
		fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
		    SSH2_FXP_NAME, type);

	अगर ((r = sshbuf_get_u32(संदेश, &गिनती)) != 0)
		fatal_fr(r, "parse count");
	अगर (गिनती != 1)
		fatal("Got multiple names (%d) from %s", गिनती, what);

	अगर ((r = sshbuf_get_cstring(संदेश, &filename, शून्य)) != 0 ||
	    (r = sshbuf_get_cstring(संदेश, &longname, शून्य)) != 0 ||
	    (r = decode_attrib(संदेश, &a)) != 0)
		fatal_fr(r, "parse filename/attrib");

	debug3("%s %s -> %s", what, path, filename);

	मुक्त(longname);

	sshbuf_free(संदेश);

	वापस(filename);
}

अक्षर *
sftp_realpath(काष्ठा sftp_conn *conn, स्थिर अक्षर *path)
{
	वापस sftp_realpath_expand(conn, path, 0);
}

पूर्णांक
sftp_can_expand_path(काष्ठा sftp_conn *conn)
{
	वापस (conn->exts & SFTP_EXT_PATH_EXPAND) != 0;
}

अक्षर *
sftp_expand_path(काष्ठा sftp_conn *conn, स्थिर अक्षर *path)
{
	अगर (!sftp_can_expand_path(conn)) {
		debug3_f("no server support, fallback to realpath");
		वापस sftp_realpath_expand(conn, path, 0);
	}
	वापस sftp_realpath_expand(conn, path, 1);
}

पूर्णांक
sftp_copy(काष्ठा sftp_conn *conn, स्थिर अक्षर *oldpath, स्थिर अक्षर *newpath)
{
	Attrib junk, attr;
	काष्ठा sshbuf *संदेश;
	u_char *old_handle, *new_handle;
	u_int mode, status, id;
	माप_प्रकार old_handle_len, new_handle_len;
	पूर्णांक r;

	/* Return if the extension is not supported */
	अगर ((conn->exts & SFTP_EXT_COPY_तथ्य) == 0) {
		error("Server does not support copy-data extension");
		वापस -1;
	}

	/* Make sure the file exists, and we can copy its perms */
	अगर (sftp_stat(conn, oldpath, 0, &attr) != 0)
		वापस -1;

	/* Do not preserve set[ug]id here, as we do not preserve ownership */
	अगर (attr.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		mode = attr.perm & 0777;

		अगर (!S_ISREG(attr.perm)) {
			error("Cannot copy non-regular file: %s", oldpath);
			वापस -1;
		}
	} अन्यथा {
		/* NB: The user's umask will apply to this */
		mode = 0666;
	}

	/* Set up the new perms for the new file */
	attrib_clear(&attr);
	attr.perm = mode;
	attr.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;

	अगर ((संदेश = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");

	attrib_clear(&junk); /* Send empty attributes */

	/* Open the old file for reading */
	id = conn->संदेश_id++;
	अगर ((r = sshbuf_put_u8(संदेश, SSH2_FXP_OPEN)) != 0 ||
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
	अगर (old_handle == शून्य) {
		sshbuf_free(संदेश);
		वापस -1;
	}

	/* Open the new file for writing */
	id = conn->संदेश_id++;
	अगर ((r = sshbuf_put_u8(संदेश, SSH2_FXP_OPEN)) != 0 ||
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
	अगर (new_handle == शून्य) {
		sshbuf_free(संदेश);
		मुक्त(old_handle);
		वापस -1;
	}

	/* Copy the file data */
	id = conn->संदेश_id++;
	अगर ((r = sshbuf_put_u8(संदेश, SSH2_FXP_EXTENDED)) != 0 ||
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
	अगर (status != SSH2_FX_OK)
		error("Couldn't copy file \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	/* Clean up everything */
	sshbuf_free(संदेश);
	sftp_close(conn, old_handle, old_handle_len);
	sftp_close(conn, new_handle, new_handle_len);
	मुक्त(old_handle);
	मुक्त(new_handle);

	वापस status == SSH2_FX_OK ? 0 : -1;
}

पूर्णांक
sftp_rename(काष्ठा sftp_conn *conn, स्थिर अक्षर *oldpath, स्थिर अक्षर *newpath,
    पूर्णांक force_legacy)
{
	काष्ठा sshbuf *संदेश;
	u_int status, id;
	पूर्णांक r, use_ext = (conn->exts & SFTP_EXT_POSIX_RENAME) && !force_legacy;

	अगर ((संदेश = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");

	/* Send rename request */
	id = conn->संदेश_id++;
	अगर (use_ext) {
		debug2("Sending SSH2_FXP_EXTENDED(posix-rename@openssh.com) "
		    "\"%s\" to \"%s\"", oldpath, newpath);
		अगर ((r = sshbuf_put_u8(संदेश, SSH2_FXP_EXTENDED)) != 0 ||
		    (r = sshbuf_put_u32(संदेश, id)) != 0 ||
		    (r = sshbuf_put_cstring(संदेश,
		    "posix-rename@openssh.com")) != 0)
			fatal_fr(r, "compose posix-rename");
	} अन्यथा {
		debug2("Sending SSH2_FXP_RENAME \"%s\" to \"%s\"",
		    oldpath, newpath);
		अगर ((r = sshbuf_put_u8(संदेश, SSH2_FXP_RENAME)) != 0 ||
		    (r = sshbuf_put_u32(संदेश, id)) != 0)
			fatal_fr(r, "compose rename");
	}
	अगर ((r = sshbuf_put_cstring(संदेश, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, newpath)) != 0)
		fatal_fr(r, "compose paths");
	send_संदेश(conn, संदेश);
	debug3("Sent message %s \"%s\" -> \"%s\"",
	    use_ext ? "posix-rename@openssh.com" :
	    "SSH2_FXP_RENAME", oldpath, newpath);
	sshbuf_free(संदेश);

	status = get_status(conn, id);
	अगर (status != SSH2_FX_OK)
		error("remote rename \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	वापस status == SSH2_FX_OK ? 0 : -1;
}

पूर्णांक
sftp_hardlink(काष्ठा sftp_conn *conn, स्थिर अक्षर *oldpath, स्थिर अक्षर *newpath)
{
	काष्ठा sshbuf *संदेश;
	u_int status, id;
	पूर्णांक r;

	अगर ((conn->exts & SFTP_EXT_HARDLINK) == 0) {
		error("Server does not support hardlink@openssh.com extension");
		वापस -1;
	}
	debug2("Sending SSH2_FXP_EXTENDED(hardlink@openssh.com) "
	    "\"%s\" to \"%s\"", oldpath, newpath);

	अगर ((संदेश = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");

	/* Send link request */
	id = conn->संदेश_id++;
	अगर ((r = sshbuf_put_u8(संदेश, SSH2_FXP_EXTENDED)) != 0 ||
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
	अगर (status != SSH2_FX_OK)
		error("remote link \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	वापस status == SSH2_FX_OK ? 0 : -1;
}

पूर्णांक
sftp_symlink(काष्ठा sftp_conn *conn, स्थिर अक्षर *oldpath, स्थिर अक्षर *newpath)
{
	काष्ठा sshbuf *संदेश;
	u_int status, id;
	पूर्णांक r;

	अगर (conn->version < 3) {
		error("This server does not support the symlink operation");
		वापस(SSH2_FX_OP_UNSUPPORTED);
	}
	debug2("Sending SSH2_FXP_SYMLINK \"%s\" to \"%s\"", oldpath, newpath);

	अगर ((संदेश = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");

	/* Send symlink request */
	id = conn->संदेश_id++;
	अगर ((r = sshbuf_put_u8(संदेश, SSH2_FXP_SYMLINK)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, id)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, newpath)) != 0)
		fatal_fr(r, "compose");
	send_संदेश(conn, संदेश);
	debug3("Sent message SSH2_FXP_SYMLINK \"%s\" -> \"%s\"", oldpath,
	    newpath);
	sshbuf_free(संदेश);

	status = get_status(conn, id);
	अगर (status != SSH2_FX_OK)
		error("remote symlink file \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	वापस status == SSH2_FX_OK ? 0 : -1;
}

पूर्णांक
sftp_fsync(काष्ठा sftp_conn *conn, u_char *handle, u_int handle_len)
{
	काष्ठा sshbuf *संदेश;
	u_int status, id;
	पूर्णांक r;

	/* Silently return if the extension is not supported */
	अगर ((conn->exts & SFTP_EXT_FSYNC) == 0)
		वापस -1;
	debug2("Sending SSH2_FXP_EXTENDED(fsync@openssh.com)");

	/* Send fsync request */
	अगर ((संदेश = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	id = conn->संदेश_id++;
	अगर ((r = sshbuf_put_u8(संदेश, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, id)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, "fsync@openssh.com")) != 0 ||
	    (r = sshbuf_put_string(संदेश, handle, handle_len)) != 0)
		fatal_fr(r, "compose");
	send_संदेश(conn, संदेश);
	debug3("Sent message fsync@openssh.com I:%u", id);
	sshbuf_free(संदेश);

	status = get_status(conn, id);
	अगर (status != SSH2_FX_OK)
		error("remote fsync: %s", fx2txt(status));

	वापस status == SSH2_FX_OK ? 0 : -1;
}

#अगर_घोषित notyet
अक्षर *
sftp_readlink(काष्ठा sftp_conn *conn, स्थिर अक्षर *path)
{
	काष्ठा sshbuf *संदेश;
	u_int expected_id, गिनती, id;
	अक्षर *filename, *longname;
	Attrib a;
	u_char type;
	पूर्णांक r;

	debug2("Sending SSH2_FXP_READLINK \"%s\"", path);

	expected_id = id = conn->संदेश_id++;
	send_string_request(conn, id, SSH2_FXP_READLINK, path, म_माप(path));

	अगर ((संदेश = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");

	get_संदेश(conn, संदेश);
	अगर ((r = sshbuf_get_u8(संदेश, &type)) != 0 ||
	    (r = sshbuf_get_u32(संदेश, &id)) != 0)
		fatal_fr(r, "parse");

	अगर (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);

	अगर (type == SSH2_FXP_STATUS) {
		u_int status;

		अगर ((r = sshbuf_get_u32(संदेश, &status)) != 0)
			fatal_fr(r, "parse status");
		error("Couldn't readlink: %s", fx2txt(status));
		sshbuf_free(संदेश);
		वापस(शून्य);
	} अन्यथा अगर (type != SSH2_FXP_NAME)
		fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
		    SSH2_FXP_NAME, type);

	अगर ((r = sshbuf_get_u32(संदेश, &गिनती)) != 0)
		fatal_fr(r, "parse count");
	अगर (गिनती != 1)
		fatal("Got multiple names (%d) from SSH_FXP_READLINK", गिनती);

	अगर ((r = sshbuf_get_cstring(संदेश, &filename, शून्य)) != 0 ||
	    (r = sshbuf_get_cstring(संदेश, &longname, शून्य)) != 0 ||
	    (r = decode_attrib(संदेश, &a)) != 0)
		fatal_fr(r, "parse filenames/attrib");

	debug3("SSH_FXP_READLINK %s -> %s", path, filename);

	मुक्त(longname);

	sshbuf_free(संदेश);

	वापस filename;
}
#पूर्ण_अगर

पूर्णांक
sftp_statvfs(काष्ठा sftp_conn *conn, स्थिर अक्षर *path, काष्ठा sftp_statvfs *st,
    पूर्णांक quiet)
{
	काष्ठा sshbuf *संदेश;
	u_int id;
	पूर्णांक r;

	अगर ((conn->exts & SFTP_EXT_STATVFS) == 0) {
		error("Server does not support statvfs@openssh.com extension");
		वापस -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(statvfs@openssh.com) \"%s\"", path);

	id = conn->संदेश_id++;

	अगर ((संदेश = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = sshbuf_put_u8(संदेश, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, id)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, "statvfs@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, path)) != 0)
		fatal_fr(r, "compose");
	send_संदेश(conn, संदेश);
	sshbuf_free(संदेश);

	वापस get_decode_statvfs(conn, st, id, quiet);
}

#अगर_घोषित notyet
पूर्णांक
sftp_fstatvfs(काष्ठा sftp_conn *conn, स्थिर u_char *handle, u_int handle_len,
    काष्ठा sftp_statvfs *st, पूर्णांक quiet)
{
	काष्ठा sshbuf *संदेश;
	u_int id;

	अगर ((conn->exts & SFTP_EXT_FSTATVFS) == 0) {
		error("Server does not support fstatvfs@openssh.com extension");
		वापस -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(fstatvfs@openssh.com)");

	id = conn->संदेश_id++;

	अगर ((संदेश = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = sshbuf_put_u8(संदेश, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, id)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, "fstatvfs@openssh.com")) != 0 ||
	    (r = sshbuf_put_string(संदेश, handle, handle_len)) != 0)
		fatal_fr(r, "compose");
	send_संदेश(conn, संदेश);
	sshbuf_free(संदेश);

	वापस get_decode_statvfs(conn, st, id, quiet);
}
#पूर्ण_अगर

पूर्णांक
sftp_lsetstat(काष्ठा sftp_conn *conn, स्थिर अक्षर *path, Attrib *a)
{
	काष्ठा sshbuf *संदेश;
	u_int status, id;
	पूर्णांक r;

	अगर ((conn->exts & SFTP_EXT_LSETSTAT) == 0) {
		error("Server does not support lsetstat@openssh.com extension");
		वापस -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(lsetstat@openssh.com) \"%s\"", path);

	id = conn->संदेश_id++;
	अगर ((संदेश = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = sshbuf_put_u8(संदेश, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, id)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, "lsetstat@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, path)) != 0 ||
	    (r = encode_attrib(संदेश, a)) != 0)
		fatal_fr(r, "compose");
	send_संदेश(conn, संदेश);
	sshbuf_free(संदेश);

	status = get_status(conn, id);
	अगर (status != SSH2_FX_OK)
		error("remote lsetstat \"%s\": %s", path, fx2txt(status));

	वापस status == SSH2_FX_OK ? 0 : -1;
}

अटल व्योम
send_read_request(काष्ठा sftp_conn *conn, u_int id, uint64_t offset,
    u_int len, स्थिर u_char *handle, u_int handle_len)
{
	काष्ठा sshbuf *संदेश;
	पूर्णांक r;

	अगर ((संदेश = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = sshbuf_put_u8(संदेश, SSH2_FXP_READ)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, id)) != 0 ||
	    (r = sshbuf_put_string(संदेश, handle, handle_len)) != 0 ||
	    (r = sshbuf_put_u64(संदेश, offset)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, len)) != 0)
		fatal_fr(r, "compose");
	send_संदेश(conn, संदेश);
	sshbuf_free(संदेश);
}

अटल पूर्णांक
send_open(काष्ठा sftp_conn *conn, स्थिर अक्षर *path, स्थिर अक्षर *tag,
    u_int openmode, Attrib *a, u_char **handlep, माप_प्रकार *handle_lenp)
{
	Attrib junk;
	u_char *handle;
	माप_प्रकार handle_len;
	काष्ठा sshbuf *संदेश;
	पूर्णांक r;
	u_int id;

	debug2("Sending SSH2_FXP_OPEN \"%s\"", path);

	*handlep = शून्य;
	*handle_lenp = 0;

	अगर (a == शून्य) {
		attrib_clear(&junk); /* Send empty attributes */
		a = &junk;
	}
	/* Send open request */
	अगर ((संदेश = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	id = conn->संदेश_id++;
	अगर ((r = sshbuf_put_u8(संदेश, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, id)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, path)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, openmode)) != 0 ||
	    (r = encode_attrib(संदेश, a)) != 0)
		fatal_fr(r, "compose %s open", tag);
	send_संदेश(conn, संदेश);
	sshbuf_free(संदेश);
	debug3("Sent %s message SSH2_FXP_OPEN I:%u P:%s M:0x%04x",
	    tag, id, path, openmode);
	अगर ((handle = get_handle(conn, id, &handle_len,
	    "%s open \"%s\"", tag, path)) == शून्य)
		वापस -1;
	/* success */
	*handlep = handle;
	*handle_lenp = handle_len;
	वापस 0;
}

अटल स्थिर अक्षर *
progress_meter_path(स्थिर अक्षर *path)
{
	स्थिर अक्षर *progresspath;

	अगर ((progresspath = म_खोजप(path, '/')) == शून्य)
		वापस path;
	progresspath++;
	अगर (*progresspath == '\0')
		वापस path;
	वापस progresspath;
}

पूर्णांक
sftp_download(काष्ठा sftp_conn *conn, स्थिर अक्षर *remote_path,
    स्थिर अक्षर *local_path, Attrib *a, पूर्णांक preserve_flag, पूर्णांक resume_flag,
    पूर्णांक fsync_flag, पूर्णांक inplace_flag)
{
	काष्ठा sshbuf *संदेश;
	u_char *handle;
	पूर्णांक local_fd = -1, write_error, seen_zerolen = 0;
	पूर्णांक read_error, write_errno, lmodified = 0, reordered = 0, r;
	uint64_t offset = 0, आकार, highwater = 0, maxack = 0;
	u_int mode, id, buflen, अंक_req, max_req, status = SSH2_FX_OK;
	off_t progress_गणक;
	माप_प्रकार handle_len;
	काष्ठा stat st;
	काष्ठा requests requests;
	काष्ठा request *req;
	u_char type;
	Attrib attr;

	debug2_f("download remote \"%s\" to local \"%s\"",
	    remote_path, local_path);

	TAILQ_INIT(&requests);

	अगर (a == शून्य) {
		अगर (sftp_stat(conn, remote_path, 0, &attr) != 0)
			वापस -1;
		a = &attr;
	}

	/* Do not preserve set[ug]id here, as we do not preserve ownership */
	अगर (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS)
		mode = a->perm & 0777;
	अन्यथा
		mode = 0666;

	अगर ((a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) &&
	    (!S_ISREG(a->perm))) {
		error("download %s: not a regular file", remote_path);
		वापस(-1);
	}

	अगर (a->flags & SSH2_FILEXFER_ATTR_आकार)
		आकार = a->आकार;
	अन्यथा
		आकार = 0;

	buflen = conn->download_buflen;

	/* Send open request */
	अगर (send_open(conn, remote_path, "remote", SSH2_FXF_READ, शून्य,
	    &handle, &handle_len) != 0)
		वापस -1;

	local_fd = खोलो(local_path, O_WRONLY | O_CREAT |
	((resume_flag || inplace_flag) ? 0 : O_TRUNC), mode | S_IWUSR);
	अगर (local_fd == -1) {
		error("open local \"%s\": %s", local_path, म_त्रुटि(त्रुटि_सं));
		जाओ fail;
	}
	अगर (resume_flag) {
		अगर (ख_स्थिति(local_fd, &st) == -1) {
			error("stat local \"%s\": %s",
			    local_path, म_त्रुटि(त्रुटि_सं));
			जाओ fail;
		}
		अगर (st.st_size < 0) {
			error("\"%s\" has negative size", local_path);
			जाओ fail;
		}
		अगर ((uint64_t)st.st_size > आकार) {
			error("Unable to resume download of \"%s\": "
			    "local file is larger than remote", local_path);
 fail:
			sftp_close(conn, handle, handle_len);
			मुक्त(handle);
			अगर (local_fd != -1)
				बंद(local_fd);
			वापस -1;
		}
		offset = highwater = maxack = st.st_size;
	}

	/* Read from remote and write to local */
	write_error = read_error = write_errno = अंक_req = 0;
	max_req = 1;
	progress_गणक = offset;

	अगर (showprogress && आकार != 0) {
		start_progress_meter(progress_meter_path(remote_path),
		    आकार, &progress_गणक);
	}

	अगर ((संदेश = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");

	जबतक (अंक_req > 0 || max_req > 0) {
		u_char *तथ्य;
		माप_प्रकार len;

		/*
		 * Simulate EOF on interrupt: stop sending new requests and
		 * allow outstanding requests to drain gracefully
		 */
		अगर (interrupted) {
			अगर (अंक_req == 0) /* If we haven't started yet... */
				अवरोध;
			max_req = 0;
		}

		/* Send some more requests */
		जबतक (अंक_req < max_req) {
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
		अगर ((r = sshbuf_get_u8(संदेश, &type)) != 0 ||
		    (r = sshbuf_get_u32(संदेश, &id)) != 0)
			fatal_fr(r, "parse");
		debug3("Received reply T:%u I:%u R:%d", type, id, max_req);

		/* Find the request in our queue */
		अगर ((req = request_find(&requests, id)) == शून्य)
			fatal("Unexpected reply %u", id);

		चयन (type) {
		हाल SSH2_FXP_STATUS:
			अगर ((r = sshbuf_get_u32(संदेश, &status)) != 0)
				fatal_fr(r, "parse status");
			अगर (status != SSH2_FX_EOF)
				read_error = 1;
			max_req = 0;
			TAILQ_REMOVE(&requests, req, tq);
			मुक्त(req);
			अंक_req--;
			अवरोध;
		हाल SSH2_FXP_तथ्य:
			अगर ((r = sshbuf_get_string(संदेश, &तथ्य, &len)) != 0)
				fatal_fr(r, "parse data");
			debug3("Received data %llu -> %llu",
			    (अचिन्हित दीर्घ दीर्घ)req->offset,
			    (अचिन्हित दीर्घ दीर्घ)req->offset + len - 1);
			अगर (len > req->len)
				fatal("Received more data than asked for "
				    "%zu > %zu", len, req->len);
			अगर (len == 0) {
				अगर (seen_zerolen)
					fatal_f("server sent zero data length");
				seen_zerolen = 1;
			}
			lmodified = 1;
			अगर ((lseek(local_fd, req->offset, शुरू_से) == -1 ||
			    atomicio(vwrite, local_fd, तथ्य, len) != len) &&
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
				अगर (maxack < req->offset + len)
					maxack = req->offset + len;
				अगर (!reordered && req->offset <= highwater)
					highwater = maxack;
				अन्यथा अगर (!reordered && req->offset > highwater)
					reordered = 1;
			}
			progress_गणक += len;
			मुक्त(तथ्य);

			अगर (len == req->len) {
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
				अगर (len < buflen)
					buflen = MAXIMUM(MIN_READ_आकार, len);
			}
			अगर (max_req > 0) { /* max_req = 0 iff EOF received */
				अगर (आकार > 0 && offset > आकार) {
					/* Only one request at a time
					 * after the expected EOF */
					debug3("Finish at %llu (%2d)",
					    (अचिन्हित दीर्घ दीर्घ)offset,
					    अंक_req);
					max_req = 1;
				} अन्यथा अगर (max_req < conn->अंक_requests) {
					++max_req;
				}
			}
			अवरोध;
		शेष:
			fatal("Expected SSH2_FXP_DATA(%u) packet, got %u",
			    SSH2_FXP_तथ्य, type);
		}
	}

	अगर (showprogress && आकार)
		stop_progress_meter();

	/* Sanity check */
	अगर (TAILQ_FIRST(&requests) != शून्य)
		fatal("Transfer complete, but requests still in queue");

	अगर (!read_error && !write_error && !interrupted) {
		/* we got everything */
		highwater = maxack;
	}

	/*
	 * Truncate at highest contiguous point to avoid holes on interrupt,
	 * or unconditionally if writing in place.
	 */
	अगर (inplace_flag || read_error || write_error || interrupted) {
		अगर (reordered && resume_flag &&
		    (read_error || write_error || interrupted)) {
			error("Unable to resume download of \"%s\": "
			    "server reordered requests", local_path);
		}
		debug("truncating at %llu", (अचिन्हित दीर्घ दीर्घ)highwater);
		अगर (ftruncate(local_fd, highwater) == -1)
			error("local ftruncate \"%s\": %s", local_path,
			    म_त्रुटि(त्रुटि_सं));
	}
	अगर (read_error) {
		error("read remote \"%s\" : %s", remote_path, fx2txt(status));
		status = -1;
		sftp_close(conn, handle, handle_len);
	} अन्यथा अगर (write_error) {
		error("write local \"%s\": %s", local_path,
		    म_त्रुटि(write_errno));
		status = SSH2_FX_FAILURE;
		sftp_close(conn, handle, handle_len);
	} अन्यथा {
		अगर (sftp_close(conn, handle, handle_len) != 0 || interrupted)
			status = SSH2_FX_FAILURE;
		अन्यथा
			status = SSH2_FX_OK;
		/* Override umask and utimes if asked */
#अगर_घोषित HAVE_FCHMOD
		अगर (preserve_flag && fchmod(local_fd, mode) == -1)
#अन्यथा
		अगर (preserve_flag && chmod(local_path, mode) == -1)
#पूर्ण_अगर /* HAVE_FCHMOD */
			error("local chmod \"%s\": %s", local_path,
			    म_त्रुटि(त्रुटि_सं));
		अगर (preserve_flag &&
		    (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME)) {
			काष्ठा timeval tv[2];
			tv[0].tv_sec = a->atime;
			tv[1].tv_sec = a->mtime;
			tv[0].tv_usec = tv[1].tv_usec = 0;
			अगर (utimes(local_path, tv) == -1)
				error("local set times \"%s\": %s",
				    local_path, म_त्रुटि(त्रुटि_सं));
		}
		अगर (resume_flag && !lmodified)
			logit("File \"%s\" was not modified", local_path);
		अन्यथा अगर (fsync_flag) {
			debug("syncing \"%s\"", local_path);
			अगर (fsync(local_fd) == -1)
				error("local sync \"%s\": %s",
				    local_path, म_त्रुटि(त्रुटि_सं));
		}
	}
	बंद(local_fd);
	sshbuf_free(संदेश);
	मुक्त(handle);

	वापस status == SSH2_FX_OK ? 0 : -1;
}

अटल पूर्णांक
download_dir_internal(काष्ठा sftp_conn *conn, स्थिर अक्षर *src, स्थिर अक्षर *dst,
    पूर्णांक depth, Attrib *dirattrib, पूर्णांक preserve_flag, पूर्णांक print_flag,
    पूर्णांक resume_flag, पूर्णांक fsync_flag, पूर्णांक follow_link_flag, पूर्णांक inplace_flag)
{
	पूर्णांक i, ret = 0;
	SFTP_DIRENT **dir_entries;
	अक्षर *filename, *new_src = शून्य, *new_dst = शून्य;
	mode_t mode = 0777, tmpmode = mode;
	Attrib *a, ldirattrib, lsym;

	अगर (depth >= MAX_DIR_DEPTH) {
		error("Maximum directory depth exceeded: %d levels", depth);
		वापस -1;
	}

	debug2_f("download dir remote \"%s\" to local \"%s\"", src, dst);

	अगर (dirattrib == शून्य) {
		अगर (sftp_stat(conn, src, 1, &ldirattrib) != 0) {
			error("stat remote \"%s\" directory failed", src);
			वापस -1;
		}
		dirattrib = &ldirattrib;
	}
	अगर (!S_ISDIR(dirattrib->perm)) {
		error("\"%s\" is not a directory", src);
		वापस -1;
	}
	अगर (print_flag && print_flag != SFTP_PROGRESS_ONLY)
		mprintf("Retrieving %s\n", src);

	अगर (dirattrib->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		mode = dirattrib->perm & 01777;
		tmpmode = mode | (S_IWUSR|S_IXUSR);
	} अन्यथा {
		debug("download remote \"%s\": server "
		    "did not send permissions", dst);
	}

	अगर (सूची_गढ़ो(dst, tmpmode) == -1 && त्रुटि_सं != EEXIST) {
		error("mkdir %s: %s", dst, म_त्रुटि(त्रुटि_सं));
		वापस -1;
	}

	अगर (sftp_readdir(conn, src, &dir_entries) == -1) {
		error("remote readdir \"%s\" failed", src);
		वापस -1;
	}

	क्रम (i = 0; dir_entries[i] != शून्य && !interrupted; i++) {
		मुक्त(new_dst);
		मुक्त(new_src);

		filename = dir_entries[i]->filename;
		new_dst = sftp_path_append(dst, filename);
		new_src = sftp_path_append(src, filename);

		a = &dir_entries[i]->a;
		अगर (S_ISLNK(a->perm)) {
			अगर (!follow_link_flag) {
				logit("download \"%s\": not a regular file",
				    new_src);
				जारी;
			}
			/* Replace the stat contents with the symlink target */
			अगर (sftp_stat(conn, new_src, 1, &lsym) != 0) {
				logit("remote stat \"%s\" failed", new_src);
				ret = -1;
				जारी;
			}
			a = &lsym;
		}

		अगर (S_ISDIR(a->perm)) {
			अगर (म_भेद(filename, ".") == 0 ||
			    म_भेद(filename, "..") == 0)
				जारी;
			अगर (download_dir_internal(conn, new_src, new_dst,
			    depth + 1, a, preserve_flag,
			    print_flag, resume_flag,
			    fsync_flag, follow_link_flag, inplace_flag) == -1)
				ret = -1;
		} अन्यथा अगर (S_ISREG(a->perm)) {
			अगर (sftp_download(conn, new_src, new_dst, a,
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

	अगर (preserve_flag) {
		अगर (dirattrib->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
			काष्ठा timeval tv[2];
			tv[0].tv_sec = dirattrib->atime;
			tv[1].tv_sec = dirattrib->mtime;
			tv[0].tv_usec = tv[1].tv_usec = 0;
			अगर (utimes(dst, tv) == -1)
				error("local set times on \"%s\": %s",
				    dst, म_त्रुटि(त्रुटि_सं));
		} अन्यथा
			debug("Server did not send times for directory "
			    "\"%s\"", dst);
	}

	अगर (mode != tmpmode && chmod(dst, mode) == -1)
		error("local chmod directory \"%s\": %s", dst,
		    म_त्रुटि(त्रुटि_सं));

	sftp_free_dirents(dir_entries);

	वापस ret;
}

पूर्णांक
sftp_download_dir(काष्ठा sftp_conn *conn, स्थिर अक्षर *src, स्थिर अक्षर *dst,
    Attrib *dirattrib, पूर्णांक preserve_flag, पूर्णांक print_flag, पूर्णांक resume_flag,
    पूर्णांक fsync_flag, पूर्णांक follow_link_flag, पूर्णांक inplace_flag)
{
	अक्षर *src_canon;
	पूर्णांक ret;

	अगर ((src_canon = sftp_realpath(conn, src)) == शून्य) {
		error("download \"%s\": path canonicalization failed", src);
		वापस -1;
	}

	ret = download_dir_internal(conn, src_canon, dst, 0,
	    dirattrib, preserve_flag, print_flag, resume_flag, fsync_flag,
	    follow_link_flag, inplace_flag);
	मुक्त(src_canon);
	वापस ret;
}

पूर्णांक
sftp_upload(काष्ठा sftp_conn *conn, स्थिर अक्षर *local_path,
    स्थिर अक्षर *remote_path, पूर्णांक preserve_flag, पूर्णांक resume,
    पूर्णांक fsync_flag, पूर्णांक inplace_flag)
{
	पूर्णांक r, local_fd;
	u_int openmode, id, status = SSH2_FX_OK, status2, reordered = 0;
	off_t offset, progress_गणक;
	u_char type, *handle, *तथ्य;
	काष्ठा sshbuf *संदेश;
	काष्ठा stat sb;
	Attrib a, t, c;
	uint32_t startid, ackid;
	uint64_t highwater = 0, maxack = 0;
	काष्ठा request *ack = शून्य;
	काष्ठा requests acks;
	माप_प्रकार handle_len;

	debug2_f("upload local \"%s\" to remote \"%s\"",
	    local_path, remote_path);

	TAILQ_INIT(&acks);

	अगर ((local_fd = खोलो(local_path, O_RDONLY)) == -1) {
		error("open local \"%s\": %s", local_path, म_त्रुटि(त्रुटि_सं));
		वापस(-1);
	}
	अगर (ख_स्थिति(local_fd, &sb) == -1) {
		error("fstat local \"%s\": %s", local_path, म_त्रुटि(त्रुटि_सं));
		बंद(local_fd);
		वापस(-1);
	}
	अगर (!S_ISREG(sb.st_mode)) {
		error("local \"%s\" is not a regular file", local_path);
		बंद(local_fd);
		वापस(-1);
	}
	stat_to_attrib(&sb, &a);

	a.flags &= ~SSH2_FILEXFER_ATTR_आकार;
	a.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a.perm &= 0777;
	अगर (!preserve_flag)
		a.flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;

	अगर (resume) {
		/* Get remote file size if it exists */
		अगर (sftp_stat(conn, remote_path, 0, &c) != 0) {
			बंद(local_fd);
			वापस -1;
		}

		अगर ((off_t)c.आकार >= sb.st_size) {
			error("resume \"%s\": destination file "
			    "same size or larger", local_path);
			बंद(local_fd);
			वापस -1;
		}

		अगर (lseek(local_fd, (off_t)c.आकार, शुरू_से) == -1) {
			बंद(local_fd);
			वापस -1;
		}
		highwater = c.आकार;
	}

	openmode = SSH2_FXF_WRITE|SSH2_FXF_CREAT;
	अगर (resume)
		openmode |= SSH2_FXF_APPEND;
	अन्यथा अगर (!inplace_flag)
		openmode |= SSH2_FXF_TRUNC;

	/* Send open request */
	अगर (send_open(conn, remote_path, "dest", openmode, &a,
	    &handle, &handle_len) != 0) {
		बंद(local_fd);
		वापस -1;
	}

	id = conn->संदेश_id;
	startid = ackid = id + 1;
	तथ्य = xmalloc(conn->upload_buflen);

	/* Read from local and write to remote */
	offset = progress_गणक = (resume ? c.आकार : 0);
	अगर (showprogress) {
		start_progress_meter(progress_meter_path(local_path),
		    sb.st_size, &progress_गणक);
	}

	अगर ((संदेश = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	क्रम (;;) {
		पूर्णांक len;

		/*
		 * Can't use atomicio here because it returns 0 on EOF,
		 * thus losing the last block of the file.
		 * Simulate an EOF on interrupt, allowing ACKs from the
		 * server to drain.
		 */
		अगर (interrupted || status != SSH2_FX_OK)
			len = 0;
		अन्यथा करो
			len = पढ़ो(local_fd, तथ्य, conn->upload_buflen);
		जबतक ((len == -1) &&
		    (त्रुटि_सं == EINTR || त्रुटि_सं == EAGAIN || त्रुटि_सं == EWOULDBLOCK));

		अगर (len == -1) {
			fatal("read local \"%s\": %s",
			    local_path, म_त्रुटि(त्रुटि_सं));
		} अन्यथा अगर (len != 0) {
			ack = request_enqueue(&acks, ++id, len, offset);
			sshbuf_reset(संदेश);
			अगर ((r = sshbuf_put_u8(संदेश, SSH2_FXP_WRITE)) != 0 ||
			    (r = sshbuf_put_u32(संदेश, ack->id)) != 0 ||
			    (r = sshbuf_put_string(संदेश, handle,
			    handle_len)) != 0 ||
			    (r = sshbuf_put_u64(संदेश, offset)) != 0 ||
			    (r = sshbuf_put_string(संदेश, तथ्य, len)) != 0)
				fatal_fr(r, "compose");
			send_संदेश(conn, संदेश);
			debug3("Sent message SSH2_FXP_WRITE I:%u O:%llu S:%u",
			    id, (अचिन्हित दीर्घ दीर्घ)offset, len);
		} अन्यथा अगर (TAILQ_FIRST(&acks) == शून्य)
			अवरोध;

		अगर (ack == शून्य)
			fatal("Unexpected ACK %u", id);

		अगर (id == startid || len == 0 ||
		    id - ackid >= conn->अंक_requests) {
			u_int rid;

			sshbuf_reset(संदेश);
			get_संदेश(conn, संदेश);
			अगर ((r = sshbuf_get_u8(संदेश, &type)) != 0 ||
			    (r = sshbuf_get_u32(संदेश, &rid)) != 0)
				fatal_fr(r, "parse");

			अगर (type != SSH2_FXP_STATUS)
				fatal("Expected SSH2_FXP_STATUS(%d) packet, "
				    "got %d", SSH2_FXP_STATUS, type);

			अगर ((r = sshbuf_get_u32(संदेश, &status2)) != 0)
				fatal_fr(r, "parse status");
			debug3("SSH2_FXP_STATUS %u", status2);
			अगर (status2 != SSH2_FX_OK)
				status = status2; /* remember errors */

			/* Find the request in our queue */
			अगर ((ack = request_find(&acks, rid)) == शून्य)
				fatal("Can't find request for ID %u", rid);
			TAILQ_REMOVE(&acks, ack, tq);
			debug3("In write loop, ack for %u %zu bytes at %lld",
			    ack->id, ack->len, (अचिन्हित दीर्घ दीर्घ)ack->offset);
			++ackid;
			progress_गणक += ack->len;
			/*
			 * Track both the highest offset acknowledged and the
			 * highest *contiguous* offset acknowledged.
			 * We'll need the latter for ftruncate()ing
			 * interrupted transfers.
			 */
			अगर (maxack < ack->offset + ack->len)
				maxack = ack->offset + ack->len;
			अगर (!reordered && ack->offset <= highwater)
				highwater = maxack;
			अन्यथा अगर (!reordered && ack->offset > highwater) {
				debug3_f("server reordered ACKs");
				reordered = 1;
			}
			मुक्त(ack);
		}
		offset += len;
		अगर (offset < 0)
			fatal_f("offset < 0");
	}
	sshbuf_free(संदेश);

	अगर (showprogress)
		stop_progress_meter();
	मुक्त(तथ्य);

	अगर (status == SSH2_FX_OK && !interrupted) {
		/* we got everything */
		highwater = maxack;
	}
	अगर (status != SSH2_FX_OK) {
		error("write remote \"%s\": %s", remote_path, fx2txt(status));
		status = SSH2_FX_FAILURE;
	}

	अगर (inplace_flag || (resume && (status != SSH2_FX_OK || interrupted))) {
		debug("truncating at %llu", (अचिन्हित दीर्घ दीर्घ)highwater);
		attrib_clear(&t);
		t.flags = SSH2_FILEXFER_ATTR_आकार;
		t.आकार = highwater;
		sftp_fsetstat(conn, handle, handle_len, &t);
	}

	अगर (बंद(local_fd) == -1) {
		error("close local \"%s\": %s", local_path, म_त्रुटि(त्रुटि_सं));
		status = SSH2_FX_FAILURE;
	}

	/* Override umask and utimes if asked */
	अगर (preserve_flag)
		sftp_fsetstat(conn, handle, handle_len, &a);

	अगर (fsync_flag)
		(व्योम)sftp_fsync(conn, handle, handle_len);

	अगर (sftp_close(conn, handle, handle_len) != 0)
		status = SSH2_FX_FAILURE;

	मुक्त(handle);

	वापस status == SSH2_FX_OK ? 0 : -1;
}

अटल पूर्णांक
upload_dir_internal(काष्ठा sftp_conn *conn, स्थिर अक्षर *src, स्थिर अक्षर *dst,
    पूर्णांक depth, पूर्णांक preserve_flag, पूर्णांक print_flag, पूर्णांक resume, पूर्णांक fsync_flag,
    पूर्णांक follow_link_flag, पूर्णांक inplace_flag)
{
	पूर्णांक created = 0, ret = 0;
	सूची *dirp;
	काष्ठा dirent *dp;
	अक्षर *filename, *new_src = शून्य, *new_dst = शून्य;
	काष्ठा stat sb;
	Attrib a, dirattrib;
	uint32_t saved_perm;

	debug2_f("upload local dir \"%s\" to remote \"%s\"", src, dst);

	अगर (depth >= MAX_DIR_DEPTH) {
		error("Maximum directory depth exceeded: %d levels", depth);
		वापस -1;
	}

	अगर (stat(src, &sb) == -1) {
		error("stat local \"%s\": %s", src, म_त्रुटि(त्रुटि_सं));
		वापस -1;
	}
	अगर (!S_ISDIR(sb.st_mode)) {
		error("\"%s\" is not a directory", src);
		वापस -1;
	}
	अगर (print_flag && print_flag != SFTP_PROGRESS_ONLY)
		mprintf("Entering %s\n", src);

	stat_to_attrib(&sb, &a);
	a.flags &= ~SSH2_FILEXFER_ATTR_आकार;
	a.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a.perm &= 01777;
	अगर (!preserve_flag)
		a.flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;

	/*
	 * sftp lacks a portable status value to match errno EEXIST,
	 * so if we get a failure back then we must check whether
	 * the path already existed and is a directory.  Ensure we can
	 * write to the directory we create for the duration of the transfer.
	 */
	saved_perm = a.perm;
	a.perm |= (S_IWUSR|S_IXUSR);
	अगर (sftp_mkdir(conn, dst, &a, 0) == 0)
		created = 1;
	अन्यथा {
		अगर (sftp_stat(conn, dst, 0, &dirattrib) != 0)
			वापस -1;
		अगर (!S_ISDIR(dirattrib.perm)) {
			error("\"%s\" exists but is not a directory", dst);
			वापस -1;
		}
	}
	a.perm = saved_perm;

	अगर ((dirp = सूची_खोलो(src)) == शून्य) {
		error("local opendir \"%s\": %s", src, म_त्रुटि(त्रुटि_सं));
		वापस -1;
	}

	जबतक (((dp = सूची_पढ़ो(dirp)) != शून्य) && !interrupted) {
		अगर (dp->d_ino == 0)
			जारी;
		मुक्त(new_dst);
		मुक्त(new_src);
		filename = dp->d_name;
		new_dst = sftp_path_append(dst, filename);
		new_src = sftp_path_append(src, filename);

		अगर (म_भेद(filename, ".") == 0 || म_भेद(filename, "..") == 0)
			जारी;
		अगर (lstat(new_src, &sb) == -1) {
			logit("local lstat \"%s\": %s", filename,
			    म_त्रुटि(त्रुटि_सं));
			ret = -1;
			जारी;
		}
		अगर (S_ISLNK(sb.st_mode)) {
			अगर (!follow_link_flag) {
				logit("%s: not a regular file", filename);
				जारी;
			}
			/* Replace the stat contents with the symlink target */
			अगर (stat(new_src, &sb) == -1) {
				logit("local stat \"%s\": %s", filename,
				    म_त्रुटि(त्रुटि_सं));
				ret = -1;
				जारी;
			}
		}
		अगर (S_ISDIR(sb.st_mode)) {
			अगर (upload_dir_internal(conn, new_src, new_dst,
			    depth + 1, preserve_flag, print_flag, resume,
			    fsync_flag, follow_link_flag, inplace_flag) == -1)
				ret = -1;
		} अन्यथा अगर (S_ISREG(sb.st_mode)) {
			अगर (sftp_upload(conn, new_src, new_dst,
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

	अगर (created || preserve_flag)
		sftp_setstat(conn, dst, &a);

	(व्योम) बंद_सूची(dirp);
	वापस ret;
}

पूर्णांक
sftp_upload_dir(काष्ठा sftp_conn *conn, स्थिर अक्षर *src, स्थिर अक्षर *dst,
    पूर्णांक preserve_flag, पूर्णांक print_flag, पूर्णांक resume, पूर्णांक fsync_flag,
    पूर्णांक follow_link_flag, पूर्णांक inplace_flag)
{
	अक्षर *dst_canon;
	पूर्णांक ret;

	अगर ((dst_canon = sftp_realpath(conn, dst)) == शून्य) {
		error("upload \"%s\": path canonicalization failed", dst);
		वापस -1;
	}

	ret = upload_dir_internal(conn, src, dst_canon, 0, preserve_flag,
	    print_flag, resume, fsync_flag, follow_link_flag, inplace_flag);

	मुक्त(dst_canon);
	वापस ret;
}

अटल व्योम
handle_dest_replies(काष्ठा sftp_conn *to, स्थिर अक्षर *to_path, पूर्णांक synchronous,
    u_int *nreqsp, u_int *write_errorp)
{
	काष्ठा sshbuf *संदेश;
	u_char type;
	u_int id, status;
	पूर्णांक r;
	काष्ठा pollfd pfd;

	अगर ((संदेश = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");

	/* Try to eat replies from the upload side */
	जबतक (*nreqsp > 0) {
		debug3_f("%u outstanding replies", *nreqsp);
		अगर (!synchronous) {
			/* Bail out if no data is ready to be read */
			pfd.fd = to->fd_in;
			pfd.events = POLLIN;
			अगर ((r = poll(&pfd, 1, 0)) == -1) {
				अगर (त्रुटि_सं == EINTR)
					अवरोध;
				fatal_f("poll: %s", म_त्रुटि(त्रुटि_सं));
			} अन्यथा अगर (r == 0)
				अवरोध; /* fd not ready */
		}
		sshbuf_reset(संदेश);
		get_संदेश(to, संदेश);

		अगर ((r = sshbuf_get_u8(संदेश, &type)) != 0 ||
		    (r = sshbuf_get_u32(संदेश, &id)) != 0)
			fatal_fr(r, "dest parse");
		debug3("Received dest reply T:%u I:%u R:%u", type, id, *nreqsp);
		अगर (type != SSH2_FXP_STATUS) {
			fatal_f("Expected SSH2_FXP_STATUS(%d) packet, got %d",
			    SSH2_FXP_STATUS, type);
		}
		अगर ((r = sshbuf_get_u32(संदेश, &status)) != 0)
			fatal_fr(r, "parse dest status");
		debug3("dest SSH2_FXP_STATUS %u", status);
		अगर (status != SSH2_FX_OK) {
			/* record first error */
			अगर (*write_errorp == 0)
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

पूर्णांक
sftp_crossload(काष्ठा sftp_conn *from, काष्ठा sftp_conn *to,
    स्थिर अक्षर *from_path, स्थिर अक्षर *to_path,
    Attrib *a, पूर्णांक preserve_flag)
{
	काष्ठा sshbuf *संदेश;
	पूर्णांक write_error, read_error, r, seen_zerolen = 0;
	uint64_t offset = 0, आकार;
	u_int id, buflen, अंक_req, max_req, status = SSH2_FX_OK;
	u_int अंक_upload_req;
	off_t progress_गणक;
	u_char *from_handle, *to_handle;
	माप_प्रकार from_handle_len, to_handle_len;
	काष्ठा requests requests;
	काष्ठा request *req;
	u_char type;
	Attrib attr;

	debug2_f("crossload src \"%s\" to dst \"%s\"", from_path, to_path);

	TAILQ_INIT(&requests);

	अगर (a == शून्य) {
		अगर (sftp_stat(from, from_path, 0, &attr) != 0)
			वापस -1;
		a = &attr;
	}

	अगर ((a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) &&
	    (!S_ISREG(a->perm))) {
		error("download \"%s\": not a regular file", from_path);
		वापस(-1);
	}
	अगर (a->flags & SSH2_FILEXFER_ATTR_आकार)
		आकार = a->आकार;
	अन्यथा
		आकार = 0;

	buflen = from->download_buflen;
	अगर (buflen > to->upload_buflen)
		buflen = to->upload_buflen;

	/* Send open request to read side */
	अगर (send_open(from, from_path, "origin", SSH2_FXF_READ, शून्य,
	    &from_handle, &from_handle_len) != 0)
		वापस -1;

	/* Send open request to write side */
	a->flags &= ~SSH2_FILEXFER_ATTR_आकार;
	a->flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a->perm &= 0777;
	अगर (!preserve_flag)
		a->flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;
	अगर (send_open(to, to_path, "dest",
	    SSH2_FXF_WRITE|SSH2_FXF_CREAT|SSH2_FXF_TRUNC, a,
	    &to_handle, &to_handle_len) != 0) {
		sftp_close(from, from_handle, from_handle_len);
		वापस -1;
	}

	/* Read from remote "from" and write to remote "to" */
	offset = 0;
	write_error = read_error = अंक_req = अंक_upload_req = 0;
	max_req = 1;
	progress_गणक = 0;

	अगर (showprogress && आकार != 0) {
		start_progress_meter(progress_meter_path(from_path),
		    आकार, &progress_गणक);
	}
	अगर ((संदेश = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	जबतक (अंक_req > 0 || max_req > 0) {
		u_char *तथ्य;
		माप_प्रकार len;

		/*
		 * Simulate EOF on interrupt: stop sending new requests and
		 * allow outstanding requests to drain gracefully
		 */
		अगर (interrupted) {
			अगर (अंक_req == 0) /* If we haven't started yet... */
				अवरोध;
			max_req = 0;
		}

		/* Send some more requests */
		जबतक (अंक_req < max_req) {
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
		अगर ((r = sshbuf_get_u8(संदेश, &type)) != 0 ||
		    (r = sshbuf_get_u32(संदेश, &id)) != 0)
			fatal_fr(r, "parse");
		debug3("Received origin reply T:%u I:%u R:%d",
		    type, id, max_req);

		/* Find the request in our queue */
		अगर ((req = request_find(&requests, id)) == शून्य)
			fatal("Unexpected reply %u", id);

		चयन (type) {
		हाल SSH2_FXP_STATUS:
			अगर ((r = sshbuf_get_u32(संदेश, &status)) != 0)
				fatal_fr(r, "parse status");
			अगर (status != SSH2_FX_EOF)
				read_error = 1;
			max_req = 0;
			TAILQ_REMOVE(&requests, req, tq);
			मुक्त(req);
			अंक_req--;
			अवरोध;
		हाल SSH2_FXP_तथ्य:
			अगर ((r = sshbuf_get_string(संदेश, &तथ्य, &len)) != 0)
				fatal_fr(r, "parse data");
			debug3("Received data %llu -> %llu",
			    (अचिन्हित दीर्घ दीर्घ)req->offset,
			    (अचिन्हित दीर्घ दीर्घ)req->offset + len - 1);
			अगर (len > req->len)
				fatal("Received more data than asked for "
				    "%zu > %zu", len, req->len);
			अगर (len == 0) {
				अगर (seen_zerolen)
					fatal_f("server sent zero data length");
				seen_zerolen = 1;
			}

			/* Write this chunk out to the destination */
			sshbuf_reset(संदेश);
			अगर ((r = sshbuf_put_u8(संदेश, SSH2_FXP_WRITE)) != 0 ||
			    (r = sshbuf_put_u32(संदेश, to->संदेश_id++)) != 0 ||
			    (r = sshbuf_put_string(संदेश, to_handle,
			    to_handle_len)) != 0 ||
			    (r = sshbuf_put_u64(संदेश, req->offset)) != 0 ||
			    (r = sshbuf_put_string(संदेश, तथ्य, len)) != 0)
				fatal_fr(r, "compose write");
			send_संदेश(to, संदेश);
			debug3("Sent message SSH2_FXP_WRITE I:%u O:%llu S:%zu",
			    id, (अचिन्हित दीर्घ दीर्घ)offset, len);
			अंक_upload_req++;
			progress_गणक += len;
			मुक्त(तथ्य);

			अगर (len == req->len) {
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
				अगर (len < buflen)
					buflen = MAXIMUM(MIN_READ_आकार, len);
			}
			अगर (max_req > 0) { /* max_req = 0 iff EOF received */
				अगर (आकार > 0 && offset > आकार) {
					/* Only one request at a time
					 * after the expected EOF */
					debug3("Finish at %llu (%2d)",
					    (अचिन्हित दीर्घ दीर्घ)offset,
					    अंक_req);
					max_req = 1;
				} अन्यथा अगर (max_req < from->अंक_requests) {
					++max_req;
				}
			}
			अवरोध;
		शेष:
			fatal("Expected SSH2_FXP_DATA(%u) packet, got %u",
			    SSH2_FXP_तथ्य, type);
		}
	}

	अगर (showprogress && आकार)
		stop_progress_meter();

	/* Drain replies from the server (blocking) */
	debug3_f("waiting for %u replies from destination", अंक_upload_req);
	handle_dest_replies(to, to_path, 1, &अंक_upload_req, &write_error);

	/* Sanity check */
	अगर (TAILQ_FIRST(&requests) != शून्य)
		fatal("Transfer complete, but requests still in queue");
	/* Truncate at 0 length on interrupt or error to avoid holes at dest */
	अगर (read_error || write_error || interrupted) {
		debug("truncating \"%s\" at 0", to_path);
		sftp_close(to, to_handle, to_handle_len);
		मुक्त(to_handle);
		अगर (send_open(to, to_path, "dest",
		    SSH2_FXF_WRITE|SSH2_FXF_CREAT|SSH2_FXF_TRUNC, a,
		    &to_handle, &to_handle_len) != 0) {
			error("dest truncate \"%s\" failed", to_path);
			to_handle = शून्य;
		}
	}
	अगर (read_error) {
		error("read origin \"%s\": %s", from_path, fx2txt(status));
		status = -1;
		sftp_close(from, from_handle, from_handle_len);
		अगर (to_handle != शून्य)
			sftp_close(to, to_handle, to_handle_len);
	} अन्यथा अगर (write_error) {
		error("write dest \"%s\": %s", to_path, fx2txt(write_error));
		status = SSH2_FX_FAILURE;
		sftp_close(from, from_handle, from_handle_len);
		अगर (to_handle != शून्य)
			sftp_close(to, to_handle, to_handle_len);
	} अन्यथा {
		अगर (sftp_close(from, from_handle, from_handle_len) != 0 ||
		    interrupted)
			status = -1;
		अन्यथा
			status = SSH2_FX_OK;
		अगर (to_handle != शून्य) {
			/* Need to resend utimes after write */
			अगर (preserve_flag)
				sftp_fsetstat(to, to_handle, to_handle_len, a);
			sftp_close(to, to_handle, to_handle_len);
		}
	}
	sshbuf_free(संदेश);
	मुक्त(from_handle);
	मुक्त(to_handle);

	वापस status == SSH2_FX_OK ? 0 : -1;
}

अटल पूर्णांक
crossload_dir_internal(काष्ठा sftp_conn *from, काष्ठा sftp_conn *to,
    स्थिर अक्षर *from_path, स्थिर अक्षर *to_path,
    पूर्णांक depth, Attrib *dirattrib, पूर्णांक preserve_flag, पूर्णांक print_flag,
    पूर्णांक follow_link_flag)
{
	पूर्णांक i, ret = 0, created = 0;
	SFTP_DIRENT **dir_entries;
	अक्षर *filename, *new_from_path = शून्य, *new_to_path = शून्य;
	mode_t mode = 0777;
	Attrib *a, curdir, ldirattrib, newdir, lsym;

	debug2_f("crossload dir src \"%s\" to dst \"%s\"", from_path, to_path);

	अगर (depth >= MAX_DIR_DEPTH) {
		error("Maximum directory depth exceeded: %d levels", depth);
		वापस -1;
	}

	अगर (dirattrib == शून्य) {
		अगर (sftp_stat(from, from_path, 1, &ldirattrib) != 0) {
			error("stat remote \"%s\" failed", from_path);
			वापस -1;
		}
		dirattrib = &ldirattrib;
	}
	अगर (!S_ISDIR(dirattrib->perm)) {
		error("\"%s\" is not a directory", from_path);
		वापस -1;
	}
	अगर (print_flag && print_flag != SFTP_PROGRESS_ONLY)
		mprintf("Retrieving %s\n", from_path);

	curdir = *dirattrib; /* dirattrib will be clobbered */
	curdir.flags &= ~SSH2_FILEXFER_ATTR_आकार;
	curdir.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	अगर ((curdir.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) == 0) {
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
	अगर (sftp_mkdir(to, to_path, &curdir, 0) == 0)
		created = 1;
	अन्यथा {
		अगर (sftp_stat(to, to_path, 0, &newdir) != 0)
			वापस -1;
		अगर (!S_ISDIR(newdir.perm)) {
			error("\"%s\" exists but is not a directory", to_path);
			वापस -1;
		}
	}
	curdir.perm = mode;

	अगर (sftp_readdir(from, from_path, &dir_entries) == -1) {
		error("origin readdir \"%s\" failed", from_path);
		वापस -1;
	}

	क्रम (i = 0; dir_entries[i] != शून्य && !interrupted; i++) {
		मुक्त(new_from_path);
		मुक्त(new_to_path);

		filename = dir_entries[i]->filename;
		new_from_path = sftp_path_append(from_path, filename);
		new_to_path = sftp_path_append(to_path, filename);

		a = &dir_entries[i]->a;
		अगर (S_ISLNK(a->perm)) {
			अगर (!follow_link_flag) {
				logit("%s: not a regular file", filename);
				जारी;
			}
			/* Replace the stat contents with the symlink target */
			अगर (sftp_stat(from, new_from_path, 1, &lsym) != 0) {
				logit("remote stat \"%s\" failed",
				    new_from_path);
				ret = -1;
				जारी;
			}
			a = &lsym;
		}
		अगर (S_ISDIR(a->perm)) {
			अगर (म_भेद(filename, ".") == 0 ||
			    म_भेद(filename, "..") == 0)
				जारी;
			अगर (crossload_dir_internal(from, to,
			    new_from_path, new_to_path,
			    depth + 1, a, preserve_flag,
			    print_flag, follow_link_flag) == -1)
				ret = -1;
		} अन्यथा अगर (S_ISREG(a->perm)) {
			अगर (sftp_crossload(from, to, new_from_path,
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

	अगर (created || preserve_flag)
		sftp_setstat(to, to_path, &curdir);

	sftp_free_dirents(dir_entries);

	वापस ret;
}

पूर्णांक
sftp_crossload_dir(काष्ठा sftp_conn *from, काष्ठा sftp_conn *to,
    स्थिर अक्षर *from_path, स्थिर अक्षर *to_path,
    Attrib *dirattrib, पूर्णांक preserve_flag, पूर्णांक print_flag, पूर्णांक follow_link_flag)
{
	अक्षर *from_path_canon;
	पूर्णांक ret;

	अगर ((from_path_canon = sftp_realpath(from, from_path)) == शून्य) {
		error("crossload \"%s\": path canonicalization failed",
		    from_path);
		वापस -1;
	}

	ret = crossload_dir_internal(from, to, from_path_canon, to_path, 0,
	    dirattrib, preserve_flag, print_flag, follow_link_flag);
	मुक्त(from_path_canon);
	वापस ret;
}

पूर्णांक
sftp_can_get_users_groups_by_id(काष्ठा sftp_conn *conn)
{
	वापस (conn->exts & SFTP_EXT_GETUSERSGROUPS_BY_ID) != 0;
}

पूर्णांक
sftp_get_users_groups_by_id(काष्ठा sftp_conn *conn,
    स्थिर u_int *uids, u_int nuids,
    स्थिर u_int *gids, u_int ngids,
    अक्षर ***usernamesp, अक्षर ***groupnamesp)
{
	काष्ठा sshbuf *संदेश, *uidbuf, *gidbuf;
	u_int i, expected_id, id;
	अक्षर *name, **usernames = शून्य, **groupnames = शून्य;
	u_char type;
	पूर्णांक r;

	*usernamesp = *groupnamesp = शून्य;
	अगर (!sftp_can_get_users_groups_by_id(conn))
		वापस SSH_ERR_FEATURE_UNSUPPORTED;

	अगर ((संदेश = sshbuf_new()) == शून्य ||
	    (uidbuf = sshbuf_new()) == शून्य ||
	    (gidbuf = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	expected_id = id = conn->संदेश_id++;
	debug2("Sending SSH2_FXP_EXTENDED(users-groups-by-id@openssh.com)");
	क्रम (i = 0; i < nuids; i++) {
		अगर ((r = sshbuf_put_u32(uidbuf, uids[i])) != 0)
			fatal_fr(r, "compose uids");
	}
	क्रम (i = 0; i < ngids; i++) {
		अगर ((r = sshbuf_put_u32(gidbuf, gids[i])) != 0)
			fatal_fr(r, "compose gids");
	}
	अगर ((r = sshbuf_put_u8(संदेश, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, id)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश,
	    "users-groups-by-id@openssh.com")) != 0 ||
	    (r = sshbuf_put_stringb(संदेश, uidbuf)) != 0 ||
	    (r = sshbuf_put_stringb(संदेश, gidbuf)) != 0)
		fatal_fr(r, "compose");
	send_संदेश(conn, संदेश);
	get_संदेश(conn, संदेश);
	अगर ((r = sshbuf_get_u8(संदेश, &type)) != 0 ||
	    (r = sshbuf_get_u32(संदेश, &id)) != 0)
		fatal_fr(r, "parse");
	अगर (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);
	अगर (type == SSH2_FXP_STATUS) {
		u_int status;
		अक्षर *errmsg;

		अगर ((r = sshbuf_get_u32(संदेश, &status)) != 0 ||
		    (r = sshbuf_get_cstring(संदेश, &errmsg, शून्य)) != 0)
			fatal_fr(r, "parse status");
		error("users-groups-by-id %s",
		    *errmsg == '\0' ? fx2txt(status) : errmsg);
		मुक्त(errmsg);
		sshbuf_free(संदेश);
		sshbuf_free(uidbuf);
		sshbuf_free(gidbuf);
		वापस -1;
	} अन्यथा अगर (type != SSH2_FXP_EXTENDED_REPLY)
		fatal("Expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_REPLY, type);

	/* reuse */
	sshbuf_free(uidbuf);
	sshbuf_free(gidbuf);
	uidbuf = gidbuf = शून्य;
	अगर ((r = sshbuf_froms(संदेश, &uidbuf)) != 0 ||
	    (r = sshbuf_froms(संदेश, &gidbuf)) != 0)
		fatal_fr(r, "parse response");
	अगर (nuids > 0) {
		usernames = xcalloc(nuids, माप(*usernames));
		क्रम (i = 0; i < nuids; i++) {
			अगर ((r = sshbuf_get_cstring(uidbuf, &name, शून्य)) != 0)
				fatal_fr(r, "parse user name");
			/* Handle unresolved names */
			अगर (*name == '\0') {
				मुक्त(name);
				name = शून्य;
			}
			usernames[i] = name;
		}
	}
	अगर (ngids > 0) {
		groupnames = xcalloc(ngids, माप(*groupnames));
		क्रम (i = 0; i < ngids; i++) {
			अगर ((r = sshbuf_get_cstring(gidbuf, &name, शून्य)) != 0)
				fatal_fr(r, "parse user name");
			/* Handle unresolved names */
			अगर (*name == '\0') {
				मुक्त(name);
				name = शून्य;
			}
			groupnames[i] = name;
		}
	}
	अगर (sshbuf_len(uidbuf) != 0)
		fatal_f("unexpected extra username data");
	अगर (sshbuf_len(gidbuf) != 0)
		fatal_f("unexpected extra groupname data");
	sshbuf_free(uidbuf);
	sshbuf_free(gidbuf);
	sshbuf_free(संदेश);
	/* success */
	*usernamesp = usernames;
	*groupnamesp = groupnames;
	वापस 0;
}

अक्षर *
sftp_path_append(स्थिर अक्षर *p1, स्थिर अक्षर *p2)
{
	अक्षर *ret;
	माप_प्रकार len = म_माप(p1) + म_माप(p2) + 2;

	ret = xmalloc(len);
	strlcpy(ret, p1, len);
	अगर (p1[0] != '\0' && p1[म_माप(p1) - 1] != '/')
		strlcat(ret, "/", len);
	strlcat(ret, p2, len);

	वापस(ret);
}

/*
 * Arg p must be dynamically allocated.  It will either be returned or
 * freed and a replacement allocated.  Caller must free returned string.
 */
अक्षर *
sftp_make_absolute(अक्षर *p, स्थिर अक्षर *pwd)
{
	अक्षर *abs_str;

	/* Derelativise */
	अगर (p && !path_absolute(p)) {
		abs_str = sftp_path_append(pwd, p);
		मुक्त(p);
		वापस(abs_str);
	} अन्यथा
		वापस(p);
}

पूर्णांक
sftp_remote_is_dir(काष्ठा sftp_conn *conn, स्थिर अक्षर *path)
{
	Attrib a;

	/* XXX: report errors? */
	अगर (sftp_stat(conn, path, 1, &a) != 0)
		वापस(0);
	अगर (!(a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS))
		वापस(0);
	वापस S_ISDIR(a.perm);
}


/* Check whether path returned from glob(..., GLOB_MARK, ...) is a directory */
पूर्णांक
sftp_globpath_is_dir(स्थिर अक्षर *pathname)
{
	माप_प्रकार l = म_माप(pathname);

	वापस l > 0 && pathname[l - 1] == '/';
}

