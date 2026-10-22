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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/stat.h>

#અન્તર્ભાવ <grp.h>
#અન્તર્ભાવ <pwd.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <time.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <util.h>

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "misc.h"

#અન્તર્ભાવ "sftp.h"
#અન્તર્ભાવ "sftp-common.h"

/* Clear contents of attributes structure */
શૂન્ય
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
શૂન્ય
stat_to_attrib(અચલ સંરચના stat *st, Attrib *a)
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
શૂન્ય
attrib_to_stat(અચલ Attrib *a, સંરચના stat *st)
{
	memset(st, 0, કદ(*st));

	જો (a->flags & SSH2_FILEXFER_ATTR_SIZE)
		st->st_size = a->size;
	જો (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		st->st_uid = a->uid;
		st->st_gid = a->gid;
	}
	જો (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS)
		st->st_mode = a->perm;
	જો (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		st->st_atime = a->atime;
		st->st_mtime = a->mtime;
	}
}

/* Decode attributes in buffer */
પૂર્ણાંક
decode_attrib(સંરચના sshbuf *b, Attrib *a)
{
	પૂર્ણાંક r;

	attrib_clear(a);
	જો ((r = sshbuf_get_u32(b, &a->flags)) != 0)
		પાછા r;
	જો (a->flags & SSH2_FILEXFER_ATTR_SIZE) {
		જો ((r = sshbuf_get_u64(b, &a->size)) != 0)
			પાછા r;
	}
	જો (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		જો ((r = sshbuf_get_u32(b, &a->uid)) != 0 ||
		    (r = sshbuf_get_u32(b, &a->gid)) != 0)
			પાછા r;
	}
	જો (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		જો ((r = sshbuf_get_u32(b, &a->perm)) != 0)
			પાછા r;
	}
	જો (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		જો ((r = sshbuf_get_u32(b, &a->atime)) != 0 ||
		    (r = sshbuf_get_u32(b, &a->mtime)) != 0)
			પાછા r;
	}
	/* vendor-specific extensions */
	જો (a->flags & SSH2_FILEXFER_ATTR_EXTENDED) {
		અક્ષર *type;
		u_char *data;
		size_t dlen;
		u_int i, ગણતરી;

		જો ((r = sshbuf_get_u32(b, &ગણતરી)) != 0)
			પાછા r;
		જો (ગણતરી > 0x100000)
			પાછા SSH_ERR_INVALID_FORMAT;
		માટે (i = 0; i < ગણતરી; i++) {
			જો ((r = sshbuf_get_cstring(b, &type, ખાલી)) != 0 ||
			    (r = sshbuf_get_string(b, &data, &dlen)) != 0)
				પાછા r;
			debug3("Got file attribute \"%.100s\" len %zu",
			    type, dlen);
			મુક્ત(type);
			મુક્ત(data);
		}
	}
	પાછા 0;
}

/* Encode attributes to buffer */
પૂર્ણાંક
encode_attrib(સંરચના sshbuf *b, અચલ Attrib *a)
{
	પૂર્ણાંક r;

	જો ((r = sshbuf_put_u32(b, a->flags)) != 0)
		પાછા r;
	જો (a->flags & SSH2_FILEXFER_ATTR_SIZE) {
		જો ((r = sshbuf_put_u64(b, a->size)) != 0)
			પાછા r;
	}
	જો (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		જો ((r = sshbuf_put_u32(b, a->uid)) != 0 ||
		    (r = sshbuf_put_u32(b, a->gid)) != 0)
			પાછા r;
	}
	જો (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		જો ((r = sshbuf_put_u32(b, a->perm)) != 0)
			પાછા r;
	}
	જો (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		જો ((r = sshbuf_put_u32(b, a->atime)) != 0 ||
		    (r = sshbuf_put_u32(b, a->mtime)) != 0)
			પાછા r;
	}
	પાછા 0;
}

/* Convert from SSH2_FX_ status to text error message */
અચલ અક્ષર *
fx2txt(પૂર્ણાંક status)
{
	પસંદગી (status) {
	સ્થિતિ SSH2_FX_OK:
		પાછા("No error");
	સ્થિતિ SSH2_FX_EOF:
		પાછા("End of file");
	સ્થિતિ SSH2_FX_NO_SUCH_FILE:
		પાછા("No such file or directory");
	સ્થિતિ SSH2_FX_PERMISSION_DENIED:
		પાછા("Permission denied");
	સ્થિતિ SSH2_FX_FAILURE:
		પાછા("Failure");
	સ્થિતિ SSH2_FX_BAD_MESSAGE:
		પાછા("Bad message");
	સ્થિતિ SSH2_FX_NO_CONNECTION:
		પાછા("No connection");
	સ્થિતિ SSH2_FX_CONNECTION_LOST:
		પાછા("Connection lost");
	સ્થિતિ SSH2_FX_OP_UNSUPPORTED:
		પાછા("Operation unsupported");
	મૂળભૂત:
		પાછા("Unknown status");
	}
	/* NOTREACHED */
}

/*
 * drwxr-xr-x    5 markus   markus       1024 Jan 13 18:39 .ssh
 */
અક્ષર *
ls_file(અચલ અક્ષર *name, અચલ સંરચના stat *st, પૂર્ણાંક remote, પૂર્ણાંક si_units,
    અચલ અક્ષર *user, અચલ અક્ષર *group)
{
	પૂર્ણાંક ulen, glen, sz = 0;
	સંરચના tm *ltime = localtime(&st->st_mtime);
	અક્ષર buf[1024], lc[8], mode[11+1], tbuf[12+1], ubuf[11+1], gbuf[11+1];
	અક્ષર sbuf[FMT_SCALED_STRSIZE];
	time_t now;

	strmode(st->st_mode, mode);
	જો (remote) {
		જો (user == ખાલી) {
			snprintf(ubuf, કદ ubuf, "%u", (u_int)st->st_uid);
			user = ubuf;
		}
		જો (group == ખાલી) {
			snprintf(gbuf, કદ gbuf, "%u", (u_int)st->st_gid);
			group = gbuf;
		}
		strlcpy(lc, "?", કદ(lc));
	} નહીંતર {
		user = user_from_uid(st->st_uid, 0);
		group = group_from_gid(st->st_gid, 0);
		snprintf(lc, કદ(lc), "%u", (u_int)st->st_nlink);
	}
	જો (ltime != ખાલી) {
		now = time(ખાલી);
		જો (now - (365*24*60*60)/2 < st->st_mtime &&
		    now >= st->st_mtime)
			sz = strftime(tbuf, કદ tbuf, "%b %e %H:%M", ltime);
		નહીંતર
			sz = strftime(tbuf, કદ tbuf, "%b %e  %Y", ltime);
	}
	જો (sz == 0)
		tbuf[0] = '\0';
	ulen = MAXIMUM(strlen(user), 8);
	glen = MAXIMUM(strlen(group), 8);
	જો (si_units) {
		fmt_scaled((long long)st->st_size, sbuf);
		snprintf(buf, કદ buf, "%s %3s %-*s %-*s %8s %s %s",
		    mode, lc, ulen, user, glen, group,
		    sbuf, tbuf, name);
	} નહીંતર {
		snprintf(buf, કદ buf, "%s %3s %-*s %-*s %8llu %s %s",
		    mode, lc, ulen, user, glen, group,
		    (unsigned long long)st->st_size, tbuf, name);
	}
	પાછા xstrdup(buf);
}
