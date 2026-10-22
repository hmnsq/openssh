/* $OpenBSD: sftp-common.c,v 1.36 2026/02/11 17:05:32 dtucker Exp $ */
/*
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
 * Copyright (c) 2001 Damien Miller.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/stat.h>

#समावेश <grp.h>
#समावेश <pwd.h>
#समावेश <stdio.h>
#समावेश <string.h>
#समावेश <stdarg.h>
#समावेश <stdlib.h>
#समावेश <time.h>
#समावेश <unistd.h>
#समावेश <util.h>

#समावेश "xmalloc.h"
#समावेश "ssherr.h"
#समावेश "sshbuf.h"
#समावेश "log.h"
#समावेश "misc.h"

#समावेश "sftp.h"
#समावेश "sftp-common.h"

/* Clear contents of attributes structure */
व्योम
attrib_clear(Attrib *a)
{
	a->flags = 0;
	a->आकार = 0;
	a->uid = 0;
	a->gid = 0;
	a->perm = 0;
	a->atime = 0;
	a->mtime = 0;
}

/* Convert from struct stat to filexfer attribs */
व्योम
stat_to_attrib(स्थिर काष्ठा stat *st, Attrib *a)
{
	attrib_clear(a);
	a->flags = 0;
	a->flags |= SSH2_FILEXFER_ATTR_आकार;
	a->आकार = st->st_size;
	a->flags |= SSH2_FILEXFER_ATTR_UIDGID;
	a->uid = st->st_uid;
	a->gid = st->st_gid;
	a->flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
	a->perm = st->st_mode;
	a->flags |= SSH2_FILEXFER_ATTR_ACMODTIME;
	a->atime = st->st_atime;
	a->mtime = st->st_mtime;
}

/* Convert from filexfer attribs to struct stat */
व्योम
attrib_to_stat(स्थिर Attrib *a, काष्ठा stat *st)
{
	स_रखो(st, 0, माप(*st));

	अगर (a->flags & SSH2_FILEXFER_ATTR_आकार)
		st->st_size = a->आकार;
	अगर (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		st->st_uid = a->uid;
		st->st_gid = a->gid;
	}
	अगर (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS)
		st->st_mode = a->perm;
	अगर (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		st->st_atime = a->atime;
		st->st_mtime = a->mtime;
	}
}

/* Decode attributes in buffer */
पूर्णांक
decode_attrib(काष्ठा sshbuf *b, Attrib *a)
{
	पूर्णांक r;

	attrib_clear(a);
	अगर ((r = sshbuf_get_u32(b, &a->flags)) != 0)
		वापस r;
	अगर (a->flags & SSH2_FILEXFER_ATTR_आकार) {
		अगर ((r = sshbuf_get_u64(b, &a->आकार)) != 0)
			वापस r;
	}
	अगर (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		अगर ((r = sshbuf_get_u32(b, &a->uid)) != 0 ||
		    (r = sshbuf_get_u32(b, &a->gid)) != 0)
			वापस r;
	}
	अगर (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		अगर ((r = sshbuf_get_u32(b, &a->perm)) != 0)
			वापस r;
	}
	अगर (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		अगर ((r = sshbuf_get_u32(b, &a->atime)) != 0 ||
		    (r = sshbuf_get_u32(b, &a->mtime)) != 0)
			वापस r;
	}
	/* vendor-specific extensions */
	अगर (a->flags & SSH2_FILEXFER_ATTR_EXTENDED) {
		अक्षर *type;
		u_char *तथ्य;
		माप_प्रकार dlen;
		u_int i, गिनती;

		अगर ((r = sshbuf_get_u32(b, &गिनती)) != 0)
			वापस r;
		अगर (गिनती > 0x100000)
			वापस SSH_ERR_INVALID_FORMAT;
		क्रम (i = 0; i < गिनती; i++) {
			अगर ((r = sshbuf_get_cstring(b, &type, शून्य)) != 0 ||
			    (r = sshbuf_get_string(b, &तथ्य, &dlen)) != 0)
				वापस r;
			debug3("Got file attribute \"%.100s\" len %zu",
			    type, dlen);
			मुक्त(type);
			मुक्त(तथ्य);
		}
	}
	वापस 0;
}

/* Encode attributes to buffer */
पूर्णांक
encode_attrib(काष्ठा sshbuf *b, स्थिर Attrib *a)
{
	पूर्णांक r;

	अगर ((r = sshbuf_put_u32(b, a->flags)) != 0)
		वापस r;
	अगर (a->flags & SSH2_FILEXFER_ATTR_आकार) {
		अगर ((r = sshbuf_put_u64(b, a->आकार)) != 0)
			वापस r;
	}
	अगर (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		अगर ((r = sshbuf_put_u32(b, a->uid)) != 0 ||
		    (r = sshbuf_put_u32(b, a->gid)) != 0)
			वापस r;
	}
	अगर (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		अगर ((r = sshbuf_put_u32(b, a->perm)) != 0)
			वापस r;
	}
	अगर (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		अगर ((r = sshbuf_put_u32(b, a->atime)) != 0 ||
		    (r = sshbuf_put_u32(b, a->mtime)) != 0)
			वापस r;
	}
	वापस 0;
}

/* Convert from SSH2_FX_ status to text error message */
स्थिर अक्षर *
fx2txt(पूर्णांक status)
{
	चयन (status) {
	हाल SSH2_FX_OK:
		वापस("No error");
	हाल SSH2_FX_EOF:
		वापस("End of file");
	हाल SSH2_FX_NO_SUCH_FILE:
		वापस("No such file or directory");
	हाल SSH2_FX_PERMISSION_DENIED:
		वापस("Permission denied");
	हाल SSH2_FX_FAILURE:
		वापस("Failure");
	हाल SSH2_FX_BAD_MESSAGE:
		वापस("Bad message");
	हाल SSH2_FX_NO_CONNECTION:
		वापस("No connection");
	हाल SSH2_FX_CONNECTION_LOST:
		वापस("Connection lost");
	हाल SSH2_FX_OP_UNSUPPORTED:
		वापस("Operation unsupported");
	शेष:
		वापस("Unknown status");
	}
	/* NOTREACHED */
}

/*
 * drwxr-xr-x    5 markus   markus       1024 Jan 13 18:39 .ssh
 */
अक्षर *
ls_file(स्थिर अक्षर *name, स्थिर काष्ठा stat *st, पूर्णांक remote, पूर्णांक si_units,
    स्थिर अक्षर *user, स्थिर अक्षर *group)
{
	पूर्णांक ulen, glen, sz = 0;
	काष्ठा पंचांग *ltime = स_स्थानीय(&st->st_mtime);
	अक्षर buf[1024], lc[8], mode[11+1], tbuf[12+1], ubuf[11+1], gbuf[11+1];
	अक्षर sbuf[FMT_SCALED_STRSIZE];
	समय_प्रकार now;

	strmode(st->st_mode, mode);
	अगर (remote) {
		अगर (user == शून्य) {
			snprintf(ubuf, माप ubuf, "%u", (u_int)st->st_uid);
			user = ubuf;
		}
		अगर (group == शून्य) {
			snprintf(gbuf, माप gbuf, "%u", (u_int)st->st_gid);
			group = gbuf;
		}
		strlcpy(lc, "?", माप(lc));
	} अन्यथा {
		user = user_from_uid(st->st_uid, 0);
		group = group_from_gid(st->st_gid, 0);
		snprintf(lc, माप(lc), "%u", (u_int)st->st_nlink);
	}
	अगर (ltime != शून्य) {
		now = समय(शून्य);
		अगर (now - (365*24*60*60)/2 < st->st_mtime &&
		    now >= st->st_mtime)
			sz = स_माला(tbuf, माप tbuf, "%b %e %H:%M", ltime);
		अन्यथा
			sz = स_माला(tbuf, माप tbuf, "%b %e  %Y", ltime);
	}
	अगर (sz == 0)
		tbuf[0] = '\0';
	ulen = MAXIMUM(म_माप(user), 8);
	glen = MAXIMUM(म_माप(group), 8);
	अगर (si_units) {
		fmt_scaled((दीर्घ दीर्घ)st->st_size, sbuf);
		snprintf(buf, माप buf, "%s %3s %-*s %-*s %8s %s %s",
		    mode, lc, ulen, user, glen, group,
		    sbuf, tbuf, name);
	} अन्यथा {
		snprintf(buf, माप buf, "%s %3s %-*s %-*s %8llu %s %s",
		    mode, lc, ulen, user, glen, group,
		    (अचिन्हित दीर्घ दीर्घ)st->st_size, tbuf, name);
	}
	वापस xstrdup(buf);
}
