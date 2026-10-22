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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/stat.h>

#अन्तर्भाव <grp.h>
#अन्तर्भाव <pwd.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <time.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <util.h>

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "misc.h"

#अन्तर्भाव "sftp.h"
#अन्तर्भाव "sftp-common.h"

/* Clear contents of attributes structure */
शून्य
attrib_clear(Attrib *a)
{
	a->flags = 0;
	a->size = 0;
	a->uid = 0;
	a->gid = 0;
	a->perm = 0;
	a->atime = 0;
	a->mtime = 0;
}

/* Convert from struct stat to filexfer attribs */
शून्य
stat_to_attrib(स्थिरांक संरचना stat *st, Attrib *a)
{
	attrib_clear(a);
	a->flags = 0;
	a->flags |= SSH2_FILEXFER_ATTR_SIZE;
	a->size = st->st_size;
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
शून्य
attrib_to_stat(स्थिरांक Attrib *a, संरचना stat *st)
{
	स_रखो(st, 0, आकार(*st));

	जर (a->flags & SSH2_FILEXFER_ATTR_SIZE)
		st->st_size = a->size;
	जर (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		st->st_uid = a->uid;
		st->st_gid = a->gid;
	}
	जर (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS)
		st->st_mode = a->perm;
	जर (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		st->st_atime = a->atime;
		st->st_mtime = a->mtime;
	}
}

/* Decode attributes in buffer */
पूर्णांक
decode_attrib(संरचना sshbuf *b, Attrib *a)
{
	पूर्णांक r;

	attrib_clear(a);
	जर ((r = sshbuf_get_u32(b, &a->flags)) != 0)
		परत r;
	जर (a->flags & SSH2_FILEXFER_ATTR_SIZE) {
		जर ((r = sshbuf_get_u64(b, &a->size)) != 0)
			परत r;
	}
	जर (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		जर ((r = sshbuf_get_u32(b, &a->uid)) != 0 ||
		    (r = sshbuf_get_u32(b, &a->gid)) != 0)
			परत r;
	}
	जर (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		जर ((r = sshbuf_get_u32(b, &a->perm)) != 0)
			परत r;
	}
	जर (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		जर ((r = sshbuf_get_u32(b, &a->atime)) != 0 ||
		    (r = sshbuf_get_u32(b, &a->mtime)) != 0)
			परत r;
	}
	/* vendor-specific extensions */
	जर (a->flags & SSH2_FILEXFER_ATTR_EXTENDED) {
		अक्षर *type;
		u_char *data;
		माप_प्रकार dlen;
		u_int i, मोजणी;

		जर ((r = sshbuf_get_u32(b, &मोजणी)) != 0)
			परत r;
		जर (मोजणी > 0x100000)
			परत SSH_ERR_INVALID_FORMAT;
		साठी (i = 0; i < मोजणी; i++) {
			जर ((r = sshbuf_get_cstring(b, &type, रिक्त)) != 0 ||
			    (r = sshbuf_get_string(b, &data, &dlen)) != 0)
				परत r;
			debug3("Got file attribute \"%.100s\" len %zu",
			    type, dlen);
			मुक्त(type);
			मुक्त(data);
		}
	}
	परत 0;
}

/* Encode attributes to buffer */
पूर्णांक
encode_attrib(संरचना sshbuf *b, स्थिरांक Attrib *a)
{
	पूर्णांक r;

	जर ((r = sshbuf_put_u32(b, a->flags)) != 0)
		परत r;
	जर (a->flags & SSH2_FILEXFER_ATTR_SIZE) {
		जर ((r = sshbuf_put_u64(b, a->size)) != 0)
			परत r;
	}
	जर (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		जर ((r = sshbuf_put_u32(b, a->uid)) != 0 ||
		    (r = sshbuf_put_u32(b, a->gid)) != 0)
			परत r;
	}
	जर (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		जर ((r = sshbuf_put_u32(b, a->perm)) != 0)
			परत r;
	}
	जर (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		जर ((r = sshbuf_put_u32(b, a->atime)) != 0 ||
		    (r = sshbuf_put_u32(b, a->mtime)) != 0)
			परत r;
	}
	परत 0;
}

/* Convert from SSH2_FX_ status to text error message */
स्थिरांक अक्षर *
fx2txt(पूर्णांक status)
{
	निवड (status) {
	स्थिती SSH2_FX_OK:
		परत("No error");
	स्थिती SSH2_FX_EOF:
		परत("End of file");
	स्थिती SSH2_FX_NO_SUCH_FILE:
		परत("No such file or directory");
	स्थिती SSH2_FX_PERMISSION_DENIED:
		परत("Permission denied");
	स्थिती SSH2_FX_FAILURE:
		परत("Failure");
	स्थिती SSH2_FX_BAD_MESSAGE:
		परत("Bad message");
	स्थिती SSH2_FX_NO_CONNECTION:
		परत("No connection");
	स्थिती SSH2_FX_CONNECTION_LOST:
		परत("Connection lost");
	स्थिती SSH2_FX_OP_UNSUPPORTED:
		परत("Operation unsupported");
	पूर्वनिर्धारित:
		परत("Unknown status");
	}
	/* NOTREACHED */
}

/*
 * drwxr-xr-x    5 markus   markus       1024 Jan 13 18:39 .ssh
 */
अक्षर *
ls_file(स्थिरांक अक्षर *name, स्थिरांक संरचना stat *st, पूर्णांक remote, पूर्णांक si_units,
    स्थिरांक अक्षर *user, स्थिरांक अक्षर *group)
{
	पूर्णांक ulen, glen, sz = 0;
	संरचना पंचांग *ltime = स_स्थानीय(&st->st_mtime);
	अक्षर buf[1024], lc[8], mode[11+1], tbuf[12+1], ubuf[11+1], gbuf[11+1];
	अक्षर sbuf[FMT_SCALED_STRSIZE];
	समय_प्रकार now;

	strmode(st->st_mode, mode);
	जर (remote) {
		जर (user == रिक्त) {
			snprintf(ubuf, आकार ubuf, "%u", (u_int)st->st_uid);
			user = ubuf;
		}
		जर (group == रिक्त) {
			snprintf(gbuf, आकार gbuf, "%u", (u_int)st->st_gid);
			group = gbuf;
		}
		strlcpy(lc, "?", आकार(lc));
	} अन्यथा {
		user = user_from_uid(st->st_uid, 0);
		group = group_from_gid(st->st_gid, 0);
		snprintf(lc, आकार(lc), "%u", (u_int)st->st_nlink);
	}
	जर (ltime != रिक्त) {
		now = समय(रिक्त);
		जर (now - (365*24*60*60)/2 < st->st_mtime &&
		    now >= st->st_mtime)
			sz = स_माला(tbuf, आकार tbuf, "%b %e %H:%M", ltime);
		अन्यथा
			sz = स_माला(tbuf, आकार tbuf, "%b %e  %Y", ltime);
	}
	जर (sz == 0)
		tbuf[0] = '\0';
	ulen = MAXIMUM(म_माप(user), 8);
	glen = MAXIMUM(म_माप(group), 8);
	जर (si_units) {
		fmt_scaled((दीर्घ दीर्घ)st->st_size, sbuf);
		snprintf(buf, आकार buf, "%s %3s %-*s %-*s %8s %s %s",
		    mode, lc, ulen, user, glen, group,
		    sbuf, tbuf, name);
	} अन्यथा {
		snprintf(buf, आकार buf, "%s %3s %-*s %-*s %8llu %s %s",
		    mode, lc, ulen, user, glen, group,
		    (अचिन्हित दीर्घ दीर्घ)st->st_size, tbuf, name);
	}
	परत xstrdup(buf);
}
