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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/stat.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <grp.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <pwd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <time.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <util.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "sftp.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sftp-common.h"

/* Clear contents of attributes structure */
ਖਾਲੀ
attrib_clear(Attrib *a)
{
	a->flags = 0;
	a->ਮਾਪ = 0;
	a->uid = 0;
	a->gid = 0;
	a->perm = 0;
	a->atime = 0;
	a->mtime = 0;
}

/* Convert from struct stat to filexfer attribs */
ਖਾਲੀ
stat_ਮੰਜ਼ਿਲ_attrib(ਅਚਲ ਬਣਤਰ stat *st, Attrib *a)
{
	attrib_clear(a);
	a->flags = 0;
	a->flags |= SSH2_FILEXFER_ATTR_ਮਾਪ;
	a->ਮਾਪ = st->st_size;
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
ਖਾਲੀ
attrib_ਮੰਜ਼ਿਲ_stat(ਅਚਲ Attrib *a, ਬਣਤਰ stat *st)
{
	memset(st, 0, ਆਕਾਰ(*st));

	ਜੇ (a->flags & SSH2_FILEXFER_ATTR_ਮਾਪ)
		st->st_size = a->ਮਾਪ;
	ਜੇ (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		st->st_uid = a->uid;
		st->st_gid = a->gid;
	}
	ਜੇ (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS)
		st->st_mode = a->perm;
	ਜੇ (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		st->st_atime = a->atime;
		st->st_mtime = a->mtime;
	}
}

/* Decode attributes in buffer */
ਪੂਰਨ
decode_attrib(ਬਣਤਰ sshbuf *b, Attrib *a)
{
	ਪੂਰਨ r;

	attrib_clear(a);
	ਜੇ ((r = sshbuf_get_u32(b, &a->flags)) != 0)
		ਵਾਪਸ r;
	ਜੇ (a->flags & SSH2_FILEXFER_ATTR_ਮਾਪ) {
		ਜੇ ((r = sshbuf_get_u64(b, &a->ਮਾਪ)) != 0)
			ਵਾਪਸ r;
	}
	ਜੇ (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		ਜੇ ((r = sshbuf_get_u32(b, &a->uid)) != 0 ||
		    (r = sshbuf_get_u32(b, &a->gid)) != 0)
			ਵਾਪਸ r;
	}
	ਜੇ (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		ਜੇ ((r = sshbuf_get_u32(b, &a->perm)) != 0)
			ਵਾਪਸ r;
	}
	ਜੇ (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		ਜੇ ((r = sshbuf_get_u32(b, &a->atime)) != 0 ||
		    (r = sshbuf_get_u32(b, &a->mtime)) != 0)
			ਵਾਪਸ r;
	}
	/* vendor-specific extensions */
	ਜੇ (a->flags & SSH2_FILEXFER_ATTR_EXTENDED) {
		ਅੱਖਰ *type;
		u_char *ਅੰਕੜੇ;
		ਮਾਪ_t dlen;
		u_int i, ਗਿਣਤੀ_2;

		ਜੇ ((r = sshbuf_get_u32(b, &ਗਿਣਤੀ_2)) != 0)
			ਵਾਪਸ r;
		ਜੇ (ਗਿਣਤੀ_2 > 0x100000)
			ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
		ਲਈ (i = 0; i < ਗਿਣਤੀ_2; i++) {
			ਜੇ ((r = sshbuf_get_cstring(b, &type, ਨਿਰਾ)) != 0 ||
			    (r = sshbuf_get_string(b, &ਅੰਕੜੇ, &dlen)) != 0)
				ਵਾਪਸ r;
			debug3("Got file attribute \"%.100s\" len %zu",
			    type, dlen);
			ਮੁਕਤ(type);
			ਮੁਕਤ(ਅੰਕੜੇ);
		}
	}
	ਵਾਪਸ 0;
}

/* Encode attributes to buffer */
ਪੂਰਨ
encode_attrib(ਬਣਤਰ sshbuf *b, ਅਚਲ Attrib *a)
{
	ਪੂਰਨ r;

	ਜੇ ((r = sshbuf_put_u32(b, a->flags)) != 0)
		ਵਾਪਸ r;
	ਜੇ (a->flags & SSH2_FILEXFER_ATTR_ਮਾਪ) {
		ਜੇ ((r = sshbuf_put_u64(b, a->ਮਾਪ)) != 0)
			ਵਾਪਸ r;
	}
	ਜੇ (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		ਜੇ ((r = sshbuf_put_u32(b, a->uid)) != 0 ||
		    (r = sshbuf_put_u32(b, a->gid)) != 0)
			ਵਾਪਸ r;
	}
	ਜੇ (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		ਜੇ ((r = sshbuf_put_u32(b, a->perm)) != 0)
			ਵਾਪਸ r;
	}
	ਜੇ (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		ਜੇ ((r = sshbuf_put_u32(b, a->atime)) != 0 ||
		    (r = sshbuf_put_u32(b, a->mtime)) != 0)
			ਵਾਪਸ r;
	}
	ਵਾਪਸ 0;
}

/* Convert from SSH2_FX_ status to text error message */
ਅਚਲ ਅੱਖਰ *
fx2txt(ਪੂਰਨ ਸਥਿਤੀ)
{
	ਚੋਣ (ਸਥਿਤੀ) {
	ਹਾਲਤ SSH2_FX_OK:
		ਵਾਪਸ("No error");
	ਹਾਲਤ SSH2_FX_EOF:
		ਵਾਪਸ("End of file");
	ਹਾਲਤ SSH2_FX_NO_SUCH_FILE:
		ਵਾਪਸ("No such file or directory");
	ਹਾਲਤ SSH2_FX_PERMISSION_DENIED:
		ਵਾਪਸ("Permission denied");
	ਹਾਲਤ SSH2_FX_FAILURE:
		ਵਾਪਸ("Failure");
	ਹਾਲਤ SSH2_FX_BAD_ਸੁਨੇਹਾ:
		ਵਾਪਸ("Bad message");
	ਹਾਲਤ SSH2_FX_NO_CONNECTION:
		ਵਾਪਸ("No connection");
	ਹਾਲਤ SSH2_FX_CONNECTION_ਗੁਆਚਾ:
		ਵਾਪਸ("Connection lost");
	ਹਾਲਤ SSH2_FX_OP_UNSUPPORTED:
		ਵਾਪਸ("Operation unsupported");
	ਮੂਲ:
		ਵਾਪਸ("Unknown status");
	}
	/* NOTREACHED */
}

/*
 * drwxr-xr-x    5 markus   markus       1024 Jan 13 18:39 .ssh
 */
ਅੱਖਰ *
ls_file(ਅਚਲ ਅੱਖਰ *name, ਅਚਲ ਬਣਤਰ stat *st, ਪੂਰਨ remote, ਪੂਰਨ si_units,
    ਅਚਲ ਅੱਖਰ *user, ਅਚਲ ਅੱਖਰ *ਸਮੂਹ)
{
	ਪੂਰਨ ulen, glen, sz = 0;
	ਬਣਤਰ tm *ltime = localtime(&st->st_mtime);
	ਅੱਖਰ buf[1024], lc[8], ਬਹੁਲਕ[11+1], tbuf[12+1], ubuf[11+1], gbuf[11+1];
	ਅੱਖਰ sbuf[FMT_SCALED_STRSIZE];
	time_t now;

	strmode(st->st_mode, ਬਹੁਲਕ);
	ਜੇ (remote) {
		ਜੇ (user == ਨਿਰਾ) {
			snprintf(ubuf, ਆਕਾਰ ubuf, "%u", (u_int)st->st_uid);
			user = ubuf;
		}
		ਜੇ (ਸਮੂਹ == ਨਿਰਾ) {
			snprintf(gbuf, ਆਕਾਰ gbuf, "%u", (u_int)st->st_gid);
			ਸਮੂਹ = gbuf;
		}
		strlcpy(lc, "?", ਆਕਾਰ(lc));
	} ਨਹੀਂਤਾਂ {
		user = user_from_uid(st->st_uid, 0);
		ਸਮੂਹ = ਸਮੂਹ_from_gid(st->st_gid, 0);
		snprintf(lc, ਆਕਾਰ(lc), "%u", (u_int)st->st_nlink);
	}
	ਜੇ (ltime != ਨਿਰਾ) {
		now = time(ਨਿਰਾ);
		ਜੇ (now - (365*24*60*60)/2 < st->st_mtime &&
		    now >= st->st_mtime)
			sz = strftime(tbuf, ਆਕਾਰ tbuf, "%b %e %H:%M", ltime);
		ਨਹੀਂਤਾਂ
			sz = strftime(tbuf, ਆਕਾਰ tbuf, "%b %e  %Y", ltime);
	}
	ਜੇ (sz == 0)
		tbuf[0] = '\0';
	ulen = ਵੱਧ_ਤੋਂ_ਵੱਧ(ਲੜੀ_ਲੰਬਾਈ(user), 8);
	glen = ਵੱਧ_ਤੋਂ_ਵੱਧ(ਲੜੀ_ਲੰਬਾਈ(ਸਮੂਹ), 8);
	ਜੇ (si_units) {
		fmt_scaled((ਲੰਮਾ ਲੰਮਾ)st->st_size, sbuf);
		snprintf(buf, ਆਕਾਰ buf, "%s %3s %-*s %-*s %8s %s %s",
		    ਬਹੁਲਕ, lc, ulen, user, glen, ਸਮੂਹ,
		    sbuf, tbuf, name);
	} ਨਹੀਂਤਾਂ {
		snprintf(buf, ਆਕਾਰ buf, "%s %3s %-*s %-*s %8llu %s %s",
		    ਬਹੁਲਕ, lc, ulen, user, glen, ਸਮੂਹ,
		    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)st->st_size, tbuf, name);
	}
	ਵਾਪਸ xstrdup(buf);
}
