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
تهی
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
تهی
stat_to_attrib(ثابت ساختار stat *st, Attrib *a)
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
تهی
attrib_to_stat(ثابت Attrib *a, ساختار stat *st)
{
	memset(st, 0, اندازه(*st));

	اگر (a->flags & SSH2_FILEXFER_ATTR_SIZE)
		st->st_size = a->size;
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
decode_attrib(ساختار sshbuf *b, Attrib *a)
{
	صحیح r;

	attrib_clear(a);
	اگر ((r = sshbuf_get_u32(b, &a->flags)) != 0)
		بازگشت r;
	اگر (a->flags & SSH2_FILEXFER_ATTR_SIZE) {
		اگر ((r = sshbuf_get_u64(b, &a->size)) != 0)
			بازگشت r;
	}
	اگر (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		اگر ((r = sshbuf_get_u32(b, &a->uid)) != 0 ||
		    (r = sshbuf_get_u32(b, &a->gid)) != 0)
			بازگشت r;
	}
	اگر (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		اگر ((r = sshbuf_get_u32(b, &a->perm)) != 0)
			بازگشت r;
	}
	اگر (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		اگر ((r = sshbuf_get_u32(b, &a->atime)) != 0 ||
		    (r = sshbuf_get_u32(b, &a->mtime)) != 0)
			بازگشت r;
	}
	/* vendor-specific extensions */
	اگر (a->flags & SSH2_FILEXFER_ATTR_EXTENDED) {
		نویسه *type;
		u_char *data;
		size_t dlen;
		u_int i, شمار;

		اگر ((r = sshbuf_get_u32(b, &شمار)) != 0)
			بازگشت r;
		اگر (شمار > 0x100000)
			بازگشت SSH_ERR_INVALID_FORMAT;
		برای (i = 0; i < شمار; i++) {
			اگر ((r = sshbuf_get_cstring(b, &type, پوچ)) != 0 ||
			    (r = sshbuf_get_string(b, &data, &dlen)) != 0)
				بازگشت r;
			debug3("Got file attribute \"%.100s\" len %zu",
			    type, dlen);
			آزاد(type);
			آزاد(data);
		}
	}
	بازگشت 0;
}

/* Encode attributes to buffer */
صحیح
encode_attrib(ساختار sshbuf *b, ثابت Attrib *a)
{
	صحیح r;

	اگر ((r = sshbuf_put_u32(b, a->flags)) != 0)
		بازگشت r;
	اگر (a->flags & SSH2_FILEXFER_ATTR_SIZE) {
		اگر ((r = sshbuf_put_u64(b, a->size)) != 0)
			بازگشت r;
	}
	اگر (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		اگر ((r = sshbuf_put_u32(b, a->uid)) != 0 ||
		    (r = sshbuf_put_u32(b, a->gid)) != 0)
			بازگشت r;
	}
	اگر (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		اگر ((r = sshbuf_put_u32(b, a->perm)) != 0)
			بازگشت r;
	}
	اگر (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		اگر ((r = sshbuf_put_u32(b, a->atime)) != 0 ||
		    (r = sshbuf_put_u32(b, a->mtime)) != 0)
			بازگشت r;
	}
	بازگشت 0;
}

/* Convert from SSH2_FX_ status to text error message */
ثابت نویسه *
fx2txt(صحیح status)
{
	انتخاب (status) {
	حالت SSH2_FX_OK:
		بازگشت("No error");
	حالت SSH2_FX_EOF:
		بازگشت("End of file");
	حالت SSH2_FX_NO_SUCH_FILE:
		بازگشت("No such file or directory");
	حالت SSH2_FX_PERMISSION_DENIED:
		بازگشت("Permission denied");
	حالت SSH2_FX_FAILURE:
		بازگشت("Failure");
	حالت SSH2_FX_BAD_MESSAGE:
		بازگشت("Bad message");
	حالت SSH2_FX_NO_CONNECTION:
		بازگشت("No connection");
	حالت SSH2_FX_CONNECTION_LOST:
		بازگشت("Connection lost");
	حالت SSH2_FX_OP_UNSUPPORTED:
		بازگشت("Operation unsupported");
	پیشفرض:
		بازگشت("Unknown status");
	}
	/* NOTREACHED */
}

/*
 * drwxr-xr-x    5 markus   markus       1024 Jan 13 18:39 .ssh
 */
نویسه *
ls_file(ثابت نویسه *name, ثابت ساختار stat *st, صحیح remote, صحیح si_units,
    ثابت نویسه *user, ثابت نویسه *group)
{
	صحیح ulen, glen, sz = 0;
	ساختار tm *ltime = localtime(&st->st_mtime);
	نویسه buf[1024], lc[8], mode[11+1], tbuf[12+1], ubuf[11+1], gbuf[11+1];
	نویسه sbuf[FMT_SCALED_STRSIZE];
	time_t now;

	strmode(st->st_mode, mode);
	اگر (remote) {
		اگر (user == پوچ) {
			snprintf(ubuf, اندازه ubuf, "%u", (u_int)st->st_uid);
			user = ubuf;
		}
		اگر (group == پوچ) {
			snprintf(gbuf, اندازه gbuf, "%u", (u_int)st->st_gid);
			group = gbuf;
		}
		strlcpy(lc, "?", اندازه(lc));
	} وگرنه {
		user = user_from_uid(st->st_uid, 0);
		group = group_from_gid(st->st_gid, 0);
		snprintf(lc, اندازه(lc), "%u", (u_int)st->st_nlink);
	}
	اگر (ltime != پوچ) {
		now = time(پوچ);
		اگر (now - (365*24*60*60)/2 < st->st_mtime &&
		    now >= st->st_mtime)
			sz = strftime(tbuf, اندازه tbuf, "%b %e %H:%M", ltime);
		وگرنه
			sz = strftime(tbuf, اندازه tbuf, "%b %e  %Y", ltime);
	}
	اگر (sz == 0)
		tbuf[0] = '\0';
	ulen = MAXIMUM(strlen(user), 8);
	glen = MAXIMUM(strlen(group), 8);
	اگر (si_units) {
		fmt_scaled((long long)st->st_size, sbuf);
		snprintf(buf, اندازه buf, "%s %3s %-*s %-*s %8s %s %s",
		    mode, lc, ulen, user, glen, group,
		    sbuf, tbuf, name);
	} وگرنه {
		snprintf(buf, اندازه buf, "%s %3s %-*s %-*s %8llu %s %s",
		    mode, lc, ulen, user, glen, group,
		    (unsigned long long)st->st_size, tbuf, name);
	}
	بازگشت xstrdup(buf);
}
