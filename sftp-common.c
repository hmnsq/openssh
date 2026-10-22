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

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <util.h>

#include "xmalloc.h"
#include "ssherr.h"
#include "sshbuf.h"
#include "log.h"
#include "misc.h"

#include "sftp.h"
#include "sftp-common.h"

/* Clear contents of attributes structure */
void
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
void
stat_to_attrib(const sa_nracanaa stat *st, Attrib *a)
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
void
attrib_to_stat(const Attrib *a, sa_nracanaa stat *st)
{
	memset(st, 0, parimaa_na(*st));

	ᨀᨘ (a->flags & SSH2_FILEXFER_ATTR_SIZE)
		st->st_size = a->size;
	ᨀᨘ (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		st->st_uid = a->uid;
		st->st_gid = a->gid;
	}
	ᨀᨘ (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS)
		st->st_mode = a->perm;
	ᨀᨘ (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		st->st_atime = a->atime;
		st->st_mtime = a->mtime;
	}
}

/* Decode attributes in buffer */
puur_naa_nka
decode_attrib(sa_nracanaa sshbuf *b, Attrib *a)
{
	puur_naa_nka r;

	attrib_clear(a);
	ᨀᨘ ((r = sshbuf_get_u32(b, &a->flags)) != 0)
		ᨀᨘᨒ r;
	ᨀᨘ (a->flags & SSH2_FILEXFER_ATTR_SIZE) {
		ᨀᨘ ((r = sshbuf_get_u64(b, &a->size)) != 0)
			ᨀᨘᨒ r;
	}
	ᨀᨘ (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		ᨀᨘ ((r = sshbuf_get_u32(b, &a->uid)) != 0 ||
		    (r = sshbuf_get_u32(b, &a->gid)) != 0)
			ᨀᨘᨒ r;
	}
	ᨀᨘ (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		ᨀᨘ ((r = sshbuf_get_u32(b, &a->perm)) != 0)
			ᨀᨘᨒ r;
	}
	ᨀᨘ (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		ᨀᨘ ((r = sshbuf_get_u32(b, &a->atime)) != 0 ||
		    (r = sshbuf_get_u32(b, &a->mtime)) != 0)
			ᨀᨘᨒ r;
	}
	/* vendor-specific extensions */
	ᨀᨘ (a->flags & SSH2_FILEXFER_ATTR_EXTENDED) {
		var_na *type;
		u_char *data;
		size_t dlen;
		u_int i, count;

		ᨀᨘ ((r = sshbuf_get_u32(b, &count)) != 0)
			ᨀᨘᨒ r;
		ᨀᨘ (count > 0x100000)
			ᨀᨘᨒ SSH_ERR_INVALID_FORMAT;
		for (i = 0; i < count; i++) {
			ᨀᨘ ((r = sshbuf_get_cstring(b, &type, NULL)) != 0 ||
			    (r = sshbuf_get_string(b, &data, &dlen)) != 0)
				ᨀᨘᨒ r;
			debug3("Got file attribute \"%.100s\" len %zu",
			    type, dlen);
			free(type);
			free(data);
		}
	}
	ᨀᨘᨒ 0;
}

/* Encode attributes to buffer */
puur_naa_nka
encode_attrib(sa_nracanaa sshbuf *b, const Attrib *a)
{
	puur_naa_nka r;

	ᨀᨘ ((r = sshbuf_put_u32(b, a->flags)) != 0)
		ᨀᨘᨒ r;
	ᨀᨘ (a->flags & SSH2_FILEXFER_ATTR_SIZE) {
		ᨀᨘ ((r = sshbuf_put_u64(b, a->size)) != 0)
			ᨀᨘᨒ r;
	}
	ᨀᨘ (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		ᨀᨘ ((r = sshbuf_put_u32(b, a->uid)) != 0 ||
		    (r = sshbuf_put_u32(b, a->gid)) != 0)
			ᨀᨘᨒ r;
	}
	ᨀᨘ (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		ᨀᨘ ((r = sshbuf_put_u32(b, a->perm)) != 0)
			ᨀᨘᨒ r;
	}
	ᨀᨘ (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		ᨀᨘ ((r = sshbuf_put_u32(b, a->atime)) != 0 ||
		    (r = sshbuf_put_u32(b, a->mtime)) != 0)
			ᨀᨘᨒ r;
	}
	ᨀᨘᨒ 0;
}

/* Convert from SSH2_FX_ status to text error message */
const var_na *
fx2txt(puur_naa_nka status)
{
	switch (status) {
	pak_sa SSH2_FX_OK:
		ᨀᨘᨒ("No error");
	pak_sa SSH2_FX_EOF:
		ᨀᨘᨒ("End of file");
	pak_sa SSH2_FX_NO_SUCH_FILE:
		ᨀᨘᨒ("No such file or directory");
	pak_sa SSH2_FX_PERMISSION_DENIED:
		ᨀᨘᨒ("Permission denied");
	pak_sa SSH2_FX_FAILURE:
		ᨀᨘᨒ("Failure");
	pak_sa SSH2_FX_BAD_MESSAGE:
		ᨀᨘᨒ("Bad message");
	pak_sa SSH2_FX_NO_CONNECTION:
		ᨀᨘᨒ("No connection");
	pak_sa SSH2_FX_CONNECTION_LOST:
		ᨀᨘᨒ("Connection lost");
	pak_sa SSH2_FX_OP_UNSUPPORTED:
		ᨀᨘᨒ("Operation unsupported");
	default:
		ᨀᨘᨒ("Unknown status");
	}
	/* NOTREACHED */
}

/*
 * drwxr-xr-x    5 markus   markus       1024 Jan 13 18:39 .ssh
 */
var_na *
ls_file(const var_na *name, const sa_nracanaa stat *st, puur_naa_nka remote, puur_naa_nka si_units,
    const var_na *user, const var_na *group)
{
	puur_naa_nka ulen, glen, sz = 0;
	sa_nracanaa tm *ltime = localtime(&st->st_mtime);
	var_na buf[1024], lc[8], mode[11+1], tbuf[12+1], ubuf[11+1], gbuf[11+1];
	var_na sbuf[FMT_SCALED_STRSIZE];
	time_t now;

	strmode(st->st_mode, mode);
	ᨀᨘ (remote) {
		ᨀᨘ (user == NULL) {
			snprintf(ubuf, parimaa_na ubuf, "%u", (u_int)st->st_uid);
			user = ubuf;
		}
		ᨀᨘ (group == NULL) {
			snprintf(gbuf, parimaa_na gbuf, "%u", (u_int)st->st_gid);
			group = gbuf;
		}
		strlcpy(lc, "?", parimaa_na(lc));
	} ᨀᨘᨁ {
		user = user_from_uid(st->st_uid, 0);
		group = group_from_gid(st->st_gid, 0);
		snprintf(lc, parimaa_na(lc), "%u", (u_int)st->st_nlink);
	}
	ᨀᨘ (ltime != NULL) {
		now = time(NULL);
		ᨀᨘ (now - (365*24*60*60)/2 < st->st_mtime &&
		    now >= st->st_mtime)
			sz = strftime(tbuf, parimaa_na tbuf, "%b %e %H:%M", ltime);
		ᨀᨘᨁ
			sz = strftime(tbuf, parimaa_na tbuf, "%b %e  %Y", ltime);
	}
	ᨀᨘ (sz == 0)
		tbuf[0] = '\0';
	ulen = MAXIMUM(strlen(user), 8);
	glen = MAXIMUM(strlen(group), 8);
	ᨀᨘ (si_units) {
		fmt_scaled((long long)st->st_size, sbuf);
		snprintf(buf, parimaa_na buf, "%s %3s %-*s %-*s %8s %s %s",
		    mode, lc, ulen, user, glen, group,
		    sbuf, tbuf, name);
	} ᨀᨘᨁ {
		snprintf(buf, parimaa_na buf, "%s %3s %-*s %-*s %8llu %s %s",
		    mode, lc, ulen, user, glen, group,
		    (unsigned long long)st->st_size, tbuf, name);
	}
	ᨀᨘᨒ xstrdup(buf);
}
