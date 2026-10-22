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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/stat.h>

#شامل <grp.h>
#شامل <pwd.h>
#شامل <stdio.h>
#شامل <string.h>
#شامل <stdarg.h>
#شامل <stdlib.h>
#شامل <time.h>
#شامل <unistd.h>
#شامل <util.h>

#شامل "xmalloc.h"
#شامل "ssherr.h"
#شامل "sshbuf.h"
#شامل "log.h"
#شامل "misc.h"

#شامل "sftp.h"
#شامل "sftp-common.h"

/* Clear contents of attributes structure */
خالی
attrib_clear(Attrib *a)
{
	a->flags = 0;
	a->سائز = 0;
	a->uid = 0;
	a->gid = 0;
	a->perm = 0;
	a->atime = 0;
	a->mtime = 0;
}

/* Convert from struct stat to filexfer attribs */
خالی
stat_مقصد_attrib(ثابت ساخت stat *st, Attrib *a)
{
	attrib_clear(a);
	a->flags = 0;
	a->flags |= SSH2_FILEXFER_ATTR_سائز;
	a->سائز = st->st_size;
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
خالی
attrib_مقصد_stat(ثابت Attrib *a, ساخت stat *st)
{
	memset(st, 0, حجم(*st));

	اگر (a->flags & SSH2_FILEXFER_ATTR_سائز)
		st->st_size = a->سائز;
	اگر (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		st->st_uid = a->uid;
		st->st_gid = a->gid;
	}
	اگر (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS)
		st->st_mode = a->perm;
	اگر (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		st->st_atime = a->atime;
		st->st_mtime = a->mtime;
	}
}

/* Decode attributes in buffer */
صحیح
decode_attrib(ساخت sshbuf *b, Attrib *a)
{
	صحیح r;

	attrib_clear(a);
	اگر ((r = sshbuf_get_u32(b, &a->flags)) != 0)
		واپس r;
	اگر (a->flags & SSH2_FILEXFER_ATTR_سائز) {
		اگر ((r = sshbuf_get_u64(b, &a->سائز)) != 0)
			واپس r;
	}
	اگر (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		اگر ((r = sshbuf_get_u32(b, &a->uid)) != 0 ||
		    (r = sshbuf_get_u32(b, &a->gid)) != 0)
			واپس r;
	}
	اگر (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		اگر ((r = sshbuf_get_u32(b, &a->perm)) != 0)
			واپس r;
	}
	اگر (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		اگر ((r = sshbuf_get_u32(b, &a->atime)) != 0 ||
		    (r = sshbuf_get_u32(b, &a->mtime)) != 0)
			واپس r;
	}
	/* vendor-specific extensions */
	اگر (a->flags & SSH2_FILEXFER_ATTR_EXTENDED) {
		حرف *type;
		u_char *ڈیٹا;
		سائز_t dlen;
		u_int i, گنتی;

		اگر ((r = sshbuf_get_u32(b, &گنتی)) != 0)
			واپس r;
		اگر (گنتی > 0x100000)
			واپس SSH_ERR_INVALID_FORMAT;
		برائے (i = 0; i < گنتی; i++) {
			اگر ((r = sshbuf_get_cstring(b, &type, تہی)) != 0 ||
			    (r = sshbuf_get_string(b, &ڈیٹا, &dlen)) != 0)
				واپس r;
			debug3("Got file attribute \"%.100s\" len %zu",
			    type, dlen);
			آزاد(type);
			آزاد(ڈیٹا);
		}
	}
	واپس 0;
}

/* Encode attributes to buffer */
صحیح
encode_attrib(ساخت sshbuf *b, ثابت Attrib *a)
{
	صحیح r;

	اگر ((r = sshbuf_put_u32(b, a->flags)) != 0)
		واپس r;
	اگر (a->flags & SSH2_FILEXFER_ATTR_سائز) {
		اگر ((r = sshbuf_put_u64(b, a->سائز)) != 0)
			واپس r;
	}
	اگر (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		اگر ((r = sshbuf_put_u32(b, a->uid)) != 0 ||
		    (r = sshbuf_put_u32(b, a->gid)) != 0)
			واپس r;
	}
	اگر (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		اگر ((r = sshbuf_put_u32(b, a->perm)) != 0)
			واپس r;
	}
	اگر (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		اگر ((r = sshbuf_put_u32(b, a->atime)) != 0 ||
		    (r = sshbuf_put_u32(b, a->mtime)) != 0)
			واپس r;
	}
	واپس 0;
}

/* Convert from SSH2_FX_ status to text error message */
ثابت حرف *
fx2txt(صحیح حالت_2)
{
	انتخاب (حالت_2) {
	حالت SSH2_FX_OK:
		واپس("No error");
	حالت SSH2_FX_EOF:
		واپس("End of file");
	حالت SSH2_FX_NO_SUCH_FILE:
		واپس("No such file or directory");
	حالت SSH2_FX_PERMISSION_DENIED:
		واپس("Permission denied");
	حالت SSH2_FX_FAILURE:
		واپس("Failure");
	حالت SSH2_FX_BAD_پیغام:
		واپس("Bad message");
	حالت SSH2_FX_NO_CONNECTION:
		واپس("No connection");
	حالت SSH2_FX_CONNECTION_گمشدہ:
		واپس("Connection lost");
	حالت SSH2_FX_OP_UNSUPPORTED:
		واپس("Operation unsupported");
	طےشدہ:
		واپس("Unknown status");
	}
	/* NOTREACHED */
}

/*
 * drwxr-xr-x    5 markus   markus       1024 Jan 13 18:39 .ssh
 */
حرف *
ls_file(ثابت حرف *name, ثابت ساخت stat *st, صحیح remote, صحیح si_units,
    ثابت حرف *user, ثابت حرف *گروہ)
{
	صحیح ulen, glen, sz = 0;
	ساخت tm *ltime = localtime(&st->st_mtime);
	حرف buf[1024], lc[8], منوال[11+1], tbuf[12+1], ubuf[11+1], gbuf[11+1];
	حرف sbuf[FMT_SCALED_STRSIZE];
	time_t now;

	strmode(st->st_mode, منوال);
	اگر (remote) {
		اگر (user == تہی) {
			snprintf(ubuf, حجم ubuf, "%u", (u_int)st->st_uid);
			user = ubuf;
		}
		اگر (گروہ == تہی) {
			snprintf(gbuf, حجم gbuf, "%u", (u_int)st->st_gid);
			گروہ = gbuf;
		}
		strlcpy(lc, "?", حجم(lc));
	} ورنہ {
		user = user_from_uid(st->st_uid, 0);
		گروہ = گروہ_from_gid(st->st_gid, 0);
		snprintf(lc, حجم(lc), "%u", (u_int)st->st_nlink);
	}
	اگر (ltime != تہی) {
		now = time(تہی);
		اگر (now - (365*24*60*60)/2 < st->st_mtime &&
		    now >= st->st_mtime)
			sz = strftime(tbuf, حجم tbuf, "%b %e %H:%M", ltime);
		ورنہ
			sz = strftime(tbuf, حجم tbuf, "%b %e  %Y", ltime);
	}
	اگر (sz == 0)
		tbuf[0] = '\0';
	ulen = زیادہ_سے_زیادہ(لڑی_لمبائی(user), 8);
	glen = زیادہ_سے_زیادہ(لڑی_لمبائی(گروہ), 8);
	اگر (si_units) {
		fmt_scaled((طویل طویل)st->st_size, sbuf);
		snprintf(buf, حجم buf, "%s %3s %-*s %-*s %8s %s %s",
		    منوال, lc, ulen, user, glen, گروہ,
		    sbuf, tbuf, name);
	} ورنہ {
		snprintf(buf, حجم buf, "%s %3s %-*s %-*s %8llu %s %s",
		    منوال, lc, ulen, user, glen, گروہ,
		    (غیرعلامتی طویل طویل)st->st_size, tbuf, name);
	}
	واپس xstrdup(buf);
}
