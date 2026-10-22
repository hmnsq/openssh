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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/stat.h>

#அந்தர்பாவ <grp.h>
#அந்தர்பாவ <pwd.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <time.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <util.h>

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "misc.h"

#அந்தர்பாவ "sftp.h"
#அந்தர்பாவ "sftp-common.h"

/* Clear contents of attributes structure */
வெறுமை
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
வெறுமை
stat_to_attrib(மாறிலி கட்டமைப்பு stat *st, Attrib *a)
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
வெறுமை
attrib_to_stat(மாறிலி Attrib *a, கட்டமைப்பு stat *st)
{
	memset(st, 0, அளவு(*st));

	எனில் (a->flags & SSH2_FILEXFER_ATTR_SIZE)
		st->st_size = a->size;
	எனில் (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		st->st_uid = a->uid;
		st->st_gid = a->gid;
	}
	எனில் (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS)
		st->st_mode = a->perm;
	எனில் (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		st->st_atime = a->atime;
		st->st_mtime = a->mtime;
	}
}

/* Decode attributes in buffer */
முழு
decode_attrib(கட்டமைப்பு sshbuf *b, Attrib *a)
{
	முழு r;

	attrib_clear(a);
	எனில் ((r = sshbuf_get_u32(b, &a->flags)) != 0)
		திரும்பு r;
	எனில் (a->flags & SSH2_FILEXFER_ATTR_SIZE) {
		எனில் ((r = sshbuf_get_u64(b, &a->size)) != 0)
			திரும்பு r;
	}
	எனில் (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		எனில் ((r = sshbuf_get_u32(b, &a->uid)) != 0 ||
		    (r = sshbuf_get_u32(b, &a->gid)) != 0)
			திரும்பு r;
	}
	எனில் (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		எனில் ((r = sshbuf_get_u32(b, &a->perm)) != 0)
			திரும்பு r;
	}
	எனில் (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		எனில் ((r = sshbuf_get_u32(b, &a->atime)) != 0 ||
		    (r = sshbuf_get_u32(b, &a->mtime)) != 0)
			திரும்பு r;
	}
	/* vendor-specific extensions */
	எனில் (a->flags & SSH2_FILEXFER_ATTR_EXTENDED) {
		எழுத்து *type;
		u_char *data;
		size_t dlen;
		u_int i, மொத்தம்;

		எனில் ((r = sshbuf_get_u32(b, &மொத்தம்)) != 0)
			திரும்பு r;
		எனில் (மொத்தம் > 0x100000)
			திரும்பு SSH_ERR_INVALID_FORMAT;
		க்கு (i = 0; i < மொத்தம்; i++) {
			எனில் ((r = sshbuf_get_cstring(b, &type, வெற்று)) != 0 ||
			    (r = sshbuf_get_string(b, &data, &dlen)) != 0)
				திரும்பு r;
			debug3("Got file attribute \"%.100s\" len %zu",
			    type, dlen);
			விடுவி(type);
			விடுவி(data);
		}
	}
	திரும்பு 0;
}

/* Encode attributes to buffer */
முழு
encode_attrib(கட்டமைப்பு sshbuf *b, மாறிலி Attrib *a)
{
	முழு r;

	எனில் ((r = sshbuf_put_u32(b, a->flags)) != 0)
		திரும்பு r;
	எனில் (a->flags & SSH2_FILEXFER_ATTR_SIZE) {
		எனில் ((r = sshbuf_put_u64(b, a->size)) != 0)
			திரும்பு r;
	}
	எனில் (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		எனில் ((r = sshbuf_put_u32(b, a->uid)) != 0 ||
		    (r = sshbuf_put_u32(b, a->gid)) != 0)
			திரும்பு r;
	}
	எனில் (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		எனில் ((r = sshbuf_put_u32(b, a->perm)) != 0)
			திரும்பு r;
	}
	எனில் (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		எனில் ((r = sshbuf_put_u32(b, a->atime)) != 0 ||
		    (r = sshbuf_put_u32(b, a->mtime)) != 0)
			திரும்பு r;
	}
	திரும்பு 0;
}

/* Convert from SSH2_FX_ status to text error message */
மாறிலி எழுத்து *
fx2txt(முழு status)
{
	தேர்வு (status) {
	நிலை SSH2_FX_OK:
		திரும்பு("No error");
	நிலை SSH2_FX_EOF:
		திரும்பு("End of file");
	நிலை SSH2_FX_NO_SUCH_FILE:
		திரும்பு("No such file or directory");
	நிலை SSH2_FX_PERMISSION_DENIED:
		திரும்பு("Permission denied");
	நிலை SSH2_FX_FAILURE:
		திரும்பு("Failure");
	நிலை SSH2_FX_BAD_MESSAGE:
		திரும்பு("Bad message");
	நிலை SSH2_FX_NO_CONNECTION:
		திரும்பு("No connection");
	நிலை SSH2_FX_CONNECTION_LOST:
		திரும்பு("Connection lost");
	நிலை SSH2_FX_OP_UNSUPPORTED:
		திரும்பு("Operation unsupported");
	இயல்பு:
		திரும்பு("Unknown status");
	}
	/* NOTREACHED */
}

/*
 * drwxr-xr-x    5 markus   markus       1024 Jan 13 18:39 .ssh
 */
எழுத்து *
ls_file(மாறிலி எழுத்து *name, மாறிலி கட்டமைப்பு stat *st, முழு remote, முழு si_units,
    மாறிலி எழுத்து *user, மாறிலி எழுத்து *group)
{
	முழு ulen, glen, sz = 0;
	கட்டமைப்பு tm *ltime = localtime(&st->st_mtime);
	எழுத்து buf[1024], lc[8], mode[11+1], tbuf[12+1], ubuf[11+1], gbuf[11+1];
	எழுத்து sbuf[FMT_SCALED_STRSIZE];
	time_t now;

	strmode(st->st_mode, mode);
	எனில் (remote) {
		எனில் (user == வெற்று) {
			snprintf(ubuf, அளவு ubuf, "%u", (u_int)st->st_uid);
			user = ubuf;
		}
		எனில் (group == வெற்று) {
			snprintf(gbuf, அளவு gbuf, "%u", (u_int)st->st_gid);
			group = gbuf;
		}
		strlcpy(lc, "?", அளவு(lc));
	} இல்லையெனில் {
		user = user_from_uid(st->st_uid, 0);
		group = group_from_gid(st->st_gid, 0);
		snprintf(lc, அளவு(lc), "%u", (u_int)st->st_nlink);
	}
	எனில் (ltime != வெற்று) {
		now = time(வெற்று);
		எனில் (now - (365*24*60*60)/2 < st->st_mtime &&
		    now >= st->st_mtime)
			sz = strftime(tbuf, அளவு tbuf, "%b %e %H:%M", ltime);
		இல்லையெனில்
			sz = strftime(tbuf, அளவு tbuf, "%b %e  %Y", ltime);
	}
	எனில் (sz == 0)
		tbuf[0] = '\0';
	ulen = MAXIMUM(strlen(user), 8);
	glen = MAXIMUM(strlen(group), 8);
	எனில் (si_units) {
		fmt_scaled((long long)st->st_size, sbuf);
		snprintf(buf, அளவு buf, "%s %3s %-*s %-*s %8s %s %s",
		    mode, lc, ulen, user, glen, group,
		    sbuf, tbuf, name);
	} இல்லையெனில் {
		snprintf(buf, அளவு buf, "%s %3s %-*s %-*s %8llu %s %s",
		    mode, lc, ulen, user, glen, group,
		    (unsigned long long)st->st_size, tbuf, name);
	}
	திரும்பு xstrdup(buf);
}
