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
stat_to_attrib(const struct stat *st, Attrib *a)
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
attrib_to_stat(const Attrib *a, struct stat *st)
{
	memset(st, 0, sizeof(*st));

	如果 (a->flags & SSH2_FILEXFER_ATTR_SIZE)
		st->st_size = a->size;
	如果 (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		st->st_uid = a->uid;
		st->st_gid = a->gid;
	}
	如果 (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS)
		st->st_mode = a->perm;
	如果 (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		st->st_atime = a->atime;
		st->st_mtime = a->mtime;
	}
}

/* Decode attributes in buffer */
整数
decode_attrib(struct sshbuf *b, Attrib *a)
{
	整数 r;

	attrib_clear(a);
	如果 ((r = sshbuf_get_u32(b, &a->flags)) != 0)
		返回 r;
	如果 (a->flags & SSH2_FILEXFER_ATTR_SIZE) {
		如果 ((r = sshbuf_get_u64(b, &a->size)) != 0)
			返回 r;
	}
	如果 (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		如果 ((r = sshbuf_get_u32(b, &a->uid)) != 0 ||
		    (r = sshbuf_get_u32(b, &a->gid)) != 0)
			返回 r;
	}
	如果 (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		如果 ((r = sshbuf_get_u32(b, &a->perm)) != 0)
			返回 r;
	}
	如果 (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		如果 ((r = sshbuf_get_u32(b, &a->atime)) != 0 ||
		    (r = sshbuf_get_u32(b, &a->mtime)) != 0)
			返回 r;
	}
	/* vendor-specific extensions */
	如果 (a->flags & SSH2_FILEXFER_ATTR_EXTENDED) {
		char *type;
		u_char *data;
		size_t dlen;
		u_int i, count;

		如果 ((r = sshbuf_get_u32(b, &count)) != 0)
			返回 r;
		如果 (count > 0x100000)
			返回 SSH_ERR_INVALID_FORMAT;
		为 (i = 0; i < count; i++) {
			如果 ((r = sshbuf_get_cstring(b, &type, NULL)) != 0 ||
			    (r = sshbuf_get_string(b, &data, &dlen)) != 0)
				返回 r;
			debug3("Got file attribute \"%.100s\" len %zu",
			    type, dlen);
			free(type);
			free(data);
		}
	}
	返回 0;
}

/* Encode attributes to buffer */
整数
encode_attrib(struct sshbuf *b, const Attrib *a)
{
	整数 r;

	如果 ((r = sshbuf_put_u32(b, a->flags)) != 0)
		返回 r;
	如果 (a->flags & SSH2_FILEXFER_ATTR_SIZE) {
		如果 ((r = sshbuf_put_u64(b, a->size)) != 0)
			返回 r;
	}
	如果 (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		如果 ((r = sshbuf_put_u32(b, a->uid)) != 0 ||
		    (r = sshbuf_put_u32(b, a->gid)) != 0)
			返回 r;
	}
	如果 (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		如果 ((r = sshbuf_put_u32(b, a->perm)) != 0)
			返回 r;
	}
	如果 (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		如果 ((r = sshbuf_put_u32(b, a->atime)) != 0 ||
		    (r = sshbuf_put_u32(b, a->mtime)) != 0)
			返回 r;
	}
	返回 0;
}

/* Convert from SSH2_FX_ status to text error message */
const char *
fx2txt(整数 status)
{
	switch (status) {
	case SSH2_FX_OK:
		返回("No error");
	case SSH2_FX_EOF:
		返回("End of file");
	case SSH2_FX_NO_SUCH_FILE:
		返回("No such file or directory");
	case SSH2_FX_PERMISSION_DENIED:
		返回("Permission denied");
	case SSH2_FX_FAILURE:
		返回("Failure");
	case SSH2_FX_BAD_MESSAGE:
		返回("Bad message");
	case SSH2_FX_NO_CONNECTION:
		返回("No connection");
	case SSH2_FX_CONNECTION_LOST:
		返回("Connection lost");
	case SSH2_FX_OP_UNSUPPORTED:
		返回("Operation unsupported");
	default:
		返回("Unknown status");
	}
	/* NOTREACHED */
}

/*
 * drwxr-xr-x    5 markus   markus       1024 Jan 13 18:39 .ssh
 */
char *
ls_file(const char *name, const struct stat *st, 整数 remote, 整数 si_units,
    const char *user, const char *group)
{
	整数 ulen, glen, sz = 0;
	struct tm *ltime = localtime(&st->st_mtime);
	char buf[1024], lc[8], mode[11+1], tbuf[12+1], ubuf[11+1], gbuf[11+1];
	char sbuf[FMT_SCALED_STRSIZE];
	time_t now;

	strmode(st->st_mode, mode);
	如果 (remote) {
		如果 (user == NULL) {
			snprintf(ubuf, sizeof ubuf, "%u", (u_int)st->st_uid);
			user = ubuf;
		}
		如果 (group == NULL) {
			snprintf(gbuf, sizeof gbuf, "%u", (u_int)st->st_gid);
			group = gbuf;
		}
		strlcpy(lc, "?", sizeof(lc));
	} 否则 {
		user = user_from_uid(st->st_uid, 0);
		group = group_from_gid(st->st_gid, 0);
		snprintf(lc, sizeof(lc), "%u", (u_int)st->st_nlink);
	}
	如果 (ltime != NULL) {
		now = time(NULL);
		如果 (now - (365*24*60*60)/2 < st->st_mtime &&
		    now >= st->st_mtime)
			sz = strftime(tbuf, sizeof tbuf, "%b %e %H:%M", ltime);
		否则
			sz = strftime(tbuf, sizeof tbuf, "%b %e  %Y", ltime);
	}
	如果 (sz == 0)
		tbuf[0] = '\0';
	ulen = MAXIMUM(strlen(user), 8);
	glen = MAXIMUM(strlen(group), 8);
	如果 (si_units) {
		fmt_scaled((long long)st->st_size, sbuf);
		snprintf(buf, sizeof buf, "%s %3s %-*s %-*s %8s %s %s",
		    mode, lc, ulen, user, glen, group,
		    sbuf, tbuf, name);
	} 否则 {
		snprintf(buf, sizeof buf, "%s %3s %-*s %-*s %8llu %s %s",
		    mode, lc, ulen, user, glen, group,
		    (unsigned long long)st->st_size, tbuf, name);
	}
	返回 xstrdup(buf);
}
