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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/stat.h>

#അന്തര്ഭാവ <grp.h>
#അന്തര്ഭാവ <pwd.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <time.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <util.h>

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "misc.h"

#അന്തര്ഭാവ "sftp.h"
#അന്തര്ഭാവ "sftp-common.h"

/* Clear contents of attributes structure */
ശൂന്യം
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
ശൂന്യം
stat_to_attrib(സ്ഥിരം ഘടന stat *st, Attrib *a)
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
ശൂന്യം
attrib_to_stat(സ്ഥിരം Attrib *a, ഘടന stat *st)
{
	memset(st, 0, വലുപ്പം(*st));

	എങ്കിൽ (a->flags & SSH2_FILEXFER_ATTR_SIZE)
		st->st_size = a->size;
	എങ്കിൽ (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		st->st_uid = a->uid;
		st->st_gid = a->gid;
	}
	എങ്കിൽ (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS)
		st->st_mode = a->perm;
	എങ്കിൽ (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		st->st_atime = a->atime;
		st->st_mtime = a->mtime;
	}
}

/* Decode attributes in buffer */
പൂർണ്ണസംഖ്യ
decode_attrib(ഘടന sshbuf *b, Attrib *a)
{
	പൂർണ്ണസംഖ്യ r;

	attrib_clear(a);
	എങ്കിൽ ((r = sshbuf_get_u32(b, &a->flags)) != 0)
		തിരികെ r;
	എങ്കിൽ (a->flags & SSH2_FILEXFER_ATTR_SIZE) {
		എങ്കിൽ ((r = sshbuf_get_u64(b, &a->size)) != 0)
			തിരികെ r;
	}
	എങ്കിൽ (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		എങ്കിൽ ((r = sshbuf_get_u32(b, &a->uid)) != 0 ||
		    (r = sshbuf_get_u32(b, &a->gid)) != 0)
			തിരികെ r;
	}
	എങ്കിൽ (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		എങ്കിൽ ((r = sshbuf_get_u32(b, &a->perm)) != 0)
			തിരികെ r;
	}
	എങ്കിൽ (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		എങ്കിൽ ((r = sshbuf_get_u32(b, &a->atime)) != 0 ||
		    (r = sshbuf_get_u32(b, &a->mtime)) != 0)
			തിരികെ r;
	}
	/* vendor-specific extensions */
	എങ്കിൽ (a->flags & SSH2_FILEXFER_ATTR_EXTENDED) {
		അക്ഷരം *type;
		u_char *data;
		size_t dlen;
		u_int i, എണ്ണം;

		എങ്കിൽ ((r = sshbuf_get_u32(b, &എണ്ണം)) != 0)
			തിരികെ r;
		എങ്കിൽ (എണ്ണം > 0x100000)
			തിരികെ SSH_ERR_INVALID_FORMAT;
		വേണ്ടി (i = 0; i < എണ്ണം; i++) {
			എങ്കിൽ ((r = sshbuf_get_cstring(b, &type, ശൂന്യ)) != 0 ||
			    (r = sshbuf_get_string(b, &data, &dlen)) != 0)
				തിരികെ r;
			debug3("Got file attribute \"%.100s\" len %zu",
			    type, dlen);
			സ്വതന്ത്രം(type);
			സ്വതന്ത്രം(data);
		}
	}
	തിരികെ 0;
}

/* Encode attributes to buffer */
പൂർണ്ണസംഖ്യ
encode_attrib(ഘടന sshbuf *b, സ്ഥിരം Attrib *a)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshbuf_put_u32(b, a->flags)) != 0)
		തിരികെ r;
	എങ്കിൽ (a->flags & SSH2_FILEXFER_ATTR_SIZE) {
		എങ്കിൽ ((r = sshbuf_put_u64(b, a->size)) != 0)
			തിരികെ r;
	}
	എങ്കിൽ (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		എങ്കിൽ ((r = sshbuf_put_u32(b, a->uid)) != 0 ||
		    (r = sshbuf_put_u32(b, a->gid)) != 0)
			തിരികെ r;
	}
	എങ്കിൽ (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		എങ്കിൽ ((r = sshbuf_put_u32(b, a->perm)) != 0)
			തിരികെ r;
	}
	എങ്കിൽ (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		എങ്കിൽ ((r = sshbuf_put_u32(b, a->atime)) != 0 ||
		    (r = sshbuf_put_u32(b, a->mtime)) != 0)
			തിരികെ r;
	}
	തിരികെ 0;
}

/* Convert from SSH2_FX_ status to text error message */
സ്ഥിരം അക്ഷരം *
fx2txt(പൂർണ്ണസംഖ്യ status)
{
	തിരഞ്ഞെടുപ്പ് (status) {
	അവസ്ഥ SSH2_FX_OK:
		തിരികെ("No error");
	അവസ്ഥ SSH2_FX_EOF:
		തിരികെ("End of file");
	അവസ്ഥ SSH2_FX_NO_SUCH_FILE:
		തിരികെ("No such file or directory");
	അവസ്ഥ SSH2_FX_PERMISSION_DENIED:
		തിരികെ("Permission denied");
	അവസ്ഥ SSH2_FX_FAILURE:
		തിരികെ("Failure");
	അവസ്ഥ SSH2_FX_BAD_MESSAGE:
		തിരികെ("Bad message");
	അവസ്ഥ SSH2_FX_NO_CONNECTION:
		തിരികെ("No connection");
	അവസ്ഥ SSH2_FX_CONNECTION_LOST:
		തിരികെ("Connection lost");
	അവസ്ഥ SSH2_FX_OP_UNSUPPORTED:
		തിരികെ("Operation unsupported");
	സ്ഥിരസ്ഥിതി:
		തിരികെ("Unknown status");
	}
	/* NOTREACHED */
}

/*
 * drwxr-xr-x    5 markus   markus       1024 Jan 13 18:39 .ssh
 */
അക്ഷരം *
ls_file(സ്ഥിരം അക്ഷരം *name, സ്ഥിരം ഘടന stat *st, പൂർണ്ണസംഖ്യ remote, പൂർണ്ണസംഖ്യ si_units,
    സ്ഥിരം അക്ഷരം *user, സ്ഥിരം അക്ഷരം *group)
{
	പൂർണ്ണസംഖ്യ ulen, glen, sz = 0;
	ഘടന tm *ltime = localtime(&st->st_mtime);
	അക്ഷരം buf[1024], lc[8], mode[11+1], tbuf[12+1], ubuf[11+1], gbuf[11+1];
	അക്ഷരം sbuf[FMT_SCALED_STRSIZE];
	time_t now;

	strmode(st->st_mode, mode);
	എങ്കിൽ (remote) {
		എങ്കിൽ (user == ശൂന്യ) {
			snprintf(ubuf, വലുപ്പം ubuf, "%u", (u_int)st->st_uid);
			user = ubuf;
		}
		എങ്കിൽ (group == ശൂന്യ) {
			snprintf(gbuf, വലുപ്പം gbuf, "%u", (u_int)st->st_gid);
			group = gbuf;
		}
		strlcpy(lc, "?", വലുപ്പം(lc));
	} അല്ലെങ്കിൽ {
		user = user_from_uid(st->st_uid, 0);
		group = group_from_gid(st->st_gid, 0);
		snprintf(lc, വലുപ്പം(lc), "%u", (u_int)st->st_nlink);
	}
	എങ്കിൽ (ltime != ശൂന്യ) {
		now = time(ശൂന്യ);
		എങ്കിൽ (now - (365*24*60*60)/2 < st->st_mtime &&
		    now >= st->st_mtime)
			sz = strftime(tbuf, വലുപ്പം tbuf, "%b %e %H:%M", ltime);
		അല്ലെങ്കിൽ
			sz = strftime(tbuf, വലുപ്പം tbuf, "%b %e  %Y", ltime);
	}
	എങ്കിൽ (sz == 0)
		tbuf[0] = '\0';
	ulen = MAXIMUM(strlen(user), 8);
	glen = MAXIMUM(strlen(group), 8);
	എങ്കിൽ (si_units) {
		fmt_scaled((long long)st->st_size, sbuf);
		snprintf(buf, വലുപ്പം buf, "%s %3s %-*s %-*s %8s %s %s",
		    mode, lc, ulen, user, glen, group,
		    sbuf, tbuf, name);
	} അല്ലെങ്കിൽ {
		snprintf(buf, വലുപ്പം buf, "%s %3s %-*s %-*s %8llu %s %s",
		    mode, lc, ulen, user, glen, group,
		    (unsigned long long)st->st_size, tbuf, name);
	}
	തിരികെ xstrdup(buf);
}
