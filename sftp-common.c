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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/stat.h>

#ضمن <grp.h>
#ضمن <pwd.h>
#ضمن <stdio.h>
#ضمن <string.h>
#ضمن <stdarg.h>
#ضمن <stdlib.h>
#ضمن <time.h>
#ضمن <unistd.h>
#ضمن <util.h>

#ضمن "xmalloc.h"
#ضمن "ssherr.h"
#ضمن "sshbuf.h"
#ضمن "log.h"
#ضمن "misc.h"

#ضمن "sftp.h"
#ضمن "sftp-common.h"

/* Clear contents of attributes structure */
فراغ
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
فراغ
stat_to_attrib(ثابت بنية stat *st, Attrib *a)
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
فراغ
attrib_to_stat(ثابت Attrib *a, بنية stat *st)
{
	memset(st, 0, حجم(*st));

	אם (a->flags & SSH2_FILEXFER_ATTR_SIZE)
		st->st_size = a->size;
	אם (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		st->st_uid = a->uid;
		st->st_gid = a->gid;
	}
	אם (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS)
		st->st_mode = a->perm;
	אם (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		st->st_atime = a->atime;
		st->st_mtime = a->mtime;
	}
}

/* Decode attributes in buffer */
صحيح
decode_attrib(بنية sshbuf *b, Attrib *a)
{
	صحيح r;

	attrib_clear(a);
	אם ((r = sshbuf_get_u32(b, &a->flags)) != 0)
		החזר r;
	אם (a->flags & SSH2_FILEXFER_ATTR_SIZE) {
		אם ((r = sshbuf_get_u64(b, &a->size)) != 0)
			החזר r;
	}
	אם (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		אם ((r = sshbuf_get_u32(b, &a->uid)) != 0 ||
		    (r = sshbuf_get_u32(b, &a->gid)) != 0)
			החזר r;
	}
	אם (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		אם ((r = sshbuf_get_u32(b, &a->perm)) != 0)
			החזר r;
	}
	אם (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		אם ((r = sshbuf_get_u32(b, &a->atime)) != 0 ||
		    (r = sshbuf_get_u32(b, &a->mtime)) != 0)
			החזר r;
	}
	/* vendor-specific extensions */
	אם (a->flags & SSH2_FILEXFER_ATTR_EXTENDED) {
		حرف *type;
		u_char *data;
		size_t dlen;
		u_int i, count;

		אם ((r = sshbuf_get_u32(b, &count)) != 0)
			החזר r;
		אם (count > 0x100000)
			החזר SSH_ERR_INVALID_FORMAT;
		עבור (i = 0; i < count; i++) {
			אם ((r = sshbuf_get_cstring(b, &type, عدم)) != 0 ||
			    (r = sshbuf_get_string(b, &data, &dlen)) != 0)
				החזר r;
			debug3("Got file attribute \"%.100s\" len %zu",
			    type, dlen);
			حرر(type);
			حرر(data);
		}
	}
	החזר 0;
}

/* Encode attributes to buffer */
صحيح
encode_attrib(بنية sshbuf *b, ثابت Attrib *a)
{
	صحيح r;

	אם ((r = sshbuf_put_u32(b, a->flags)) != 0)
		החזר r;
	אם (a->flags & SSH2_FILEXFER_ATTR_SIZE) {
		אם ((r = sshbuf_put_u64(b, a->size)) != 0)
			החזר r;
	}
	אם (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		אם ((r = sshbuf_put_u32(b, a->uid)) != 0 ||
		    (r = sshbuf_put_u32(b, a->gid)) != 0)
			החזר r;
	}
	אם (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		אם ((r = sshbuf_put_u32(b, a->perm)) != 0)
			החזר r;
	}
	אם (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		אם ((r = sshbuf_put_u32(b, a->atime)) != 0 ||
		    (r = sshbuf_put_u32(b, a->mtime)) != 0)
			החזר r;
	}
	החזר 0;
}

/* Convert from SSH2_FX_ status to text error message */
ثابت حرف *
fx2txt(صحيح status)
{
	بدل (status) {
	حالة SSH2_FX_OK:
		החזר("No error");
	حالة SSH2_FX_EOF:
		החזר("End of file");
	حالة SSH2_FX_NO_SUCH_FILE:
		החזר("No such file or directory");
	حالة SSH2_FX_PERMISSION_DENIED:
		החזר("Permission denied");
	حالة SSH2_FX_FAILURE:
		החזר("Failure");
	حالة SSH2_FX_BAD_MESSAGE:
		החזר("Bad message");
	حالة SSH2_FX_NO_CONNECTION:
		החזר("No connection");
	حالة SSH2_FX_CONNECTION_LOST:
		החזר("Connection lost");
	حالة SSH2_FX_OP_UNSUPPORTED:
		החזר("Operation unsupported");
	افتراضي:
		החזר("Unknown status");
	}
	/* NOTREACHED */
}

/*
 * drwxr-xr-x    5 markus   markus       1024 Jan 13 18:39 .ssh
 */
حرف *
ls_file(ثابت حرف *name, ثابت بنية stat *st, صحيح remote, صحيح si_units,
    ثابت حرف *user, ثابت حرف *group)
{
	صحيح ulen, glen, sz = 0;
	بنية tm *ltime = localtime(&st->st_mtime);
	حرف buf[1024], lc[8], mode[11+1], tbuf[12+1], ubuf[11+1], gbuf[11+1];
	حرف sbuf[FMT_SCALED_STRSIZE];
	time_t now;

	strmode(st->st_mode, mode);
	אם (remote) {
		אם (user == عدم) {
			snprintf(ubuf, حجم ubuf, "%u", (u_int)st->st_uid);
			user = ubuf;
		}
		אם (group == عدم) {
			snprintf(gbuf, حجم gbuf, "%u", (u_int)st->st_gid);
			group = gbuf;
		}
		strlcpy(lc, "?", حجم(lc));
	} אחרת {
		user = user_from_uid(st->st_uid, 0);
		group = group_from_gid(st->st_gid, 0);
		snprintf(lc, حجم(lc), "%u", (u_int)st->st_nlink);
	}
	אם (ltime != عدم) {
		now = time(عدم);
		אם (now - (365*24*60*60)/2 < st->st_mtime &&
		    now >= st->st_mtime)
			sz = strftime(tbuf, حجم tbuf, "%b %e %H:%M", ltime);
		אחרת
			sz = strftime(tbuf, حجم tbuf, "%b %e  %Y", ltime);
	}
	אם (sz == 0)
		tbuf[0] = '\0';
	ulen = MAXIMUM(strlen(user), 8);
	glen = MAXIMUM(strlen(group), 8);
	אם (si_units) {
		fmt_scaled((long long)st->st_size, sbuf);
		snprintf(buf, حجم buf, "%s %3s %-*s %-*s %8s %s %s",
		    mode, lc, ulen, user, glen, group,
		    sbuf, tbuf, name);
	} אחרת {
		snprintf(buf, حجم buf, "%s %3s %-*s %-*s %8llu %s %s",
		    mode, lc, ulen, user, glen, group,
		    (unsigned long long)st->st_size, tbuf, name);
	}
	החזר xstrdup(buf);
}
