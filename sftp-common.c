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

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <sys/stat.h>

#অন্তর্ভাৱ <grp.h>
#অন্তর্ভাৱ <pwd.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <stdarg.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <time.h>
#অন্তর্ভাৱ <unistd.h>
#অন্তর্ভাৱ <util.h>

#অন্তর্ভাৱ "xmalloc.h"
#অন্তর্ভাৱ "ssherr.h"
#অন্তর্ভাৱ "sshbuf.h"
#অন্তর্ভাৱ "log.h"
#অন্তর্ভাৱ "misc.h"

#অন্তর্ভাৱ "sftp.h"
#অন্তর্ভাৱ "sftp-common.h"

/* Clear contents of attributes structure */
শূন্য
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
শূন্য
stat_to_attrib(ধ্রুৱ সংরচনা stat *st, Attrib *a)
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
শূন্য
attrib_to_stat(ধ্রুৱ Attrib *a, সংরচনা stat *st)
{
	memset(st, 0, পরিমাণ(*st));

	যদি (a->flags & SSH2_FILEXFER_ATTR_SIZE)
		st->st_size = a->size;
	যদি (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		st->st_uid = a->uid;
		st->st_gid = a->gid;
	}
	যদি (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS)
		st->st_mode = a->perm;
	যদি (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		st->st_atime = a->atime;
		st->st_mtime = a->mtime;
	}
}

/* Decode attributes in buffer */
পূর্ণাঙ্ক
decode_attrib(সংরচনা sshbuf *b, Attrib *a)
{
	পূর্ণাঙ্ক r;

	attrib_clear(a);
	যদি ((r = sshbuf_get_u32(b, &a->flags)) != 0)
		ঘূৰাই r;
	যদি (a->flags & SSH2_FILEXFER_ATTR_SIZE) {
		যদি ((r = sshbuf_get_u64(b, &a->size)) != 0)
			ঘূৰাই r;
	}
	যদি (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		যদি ((r = sshbuf_get_u32(b, &a->uid)) != 0 ||
		    (r = sshbuf_get_u32(b, &a->gid)) != 0)
			ঘূৰাই r;
	}
	যদি (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		যদি ((r = sshbuf_get_u32(b, &a->perm)) != 0)
			ঘূৰাই r;
	}
	যদি (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		যদি ((r = sshbuf_get_u32(b, &a->atime)) != 0 ||
		    (r = sshbuf_get_u32(b, &a->mtime)) != 0)
			ঘূৰাই r;
	}
	/* vendor-specific extensions */
	যদি (a->flags & SSH2_FILEXFER_ATTR_EXTENDED) {
		ৱর্ণ *type;
		u_char *data;
		size_t dlen;
		u_int i, গুনতি;

		যদি ((r = sshbuf_get_u32(b, &গুনতি)) != 0)
			ঘূৰাই r;
		যদি (গুনতি > 0x100000)
			ঘূৰাই SSH_ERR_INVALID_FORMAT;
		বাবে (i = 0; i < গুনতি; i++) {
			যদি ((r = sshbuf_get_cstring(b, &type, রিক্ত)) != 0 ||
			    (r = sshbuf_get_string(b, &data, &dlen)) != 0)
				ঘূৰাই r;
			debug3("Got file attribute \"%.100s\" len %zu",
			    type, dlen);
			মুক্ত(type);
			মুক্ত(data);
		}
	}
	ঘূৰাই 0;
}

/* Encode attributes to buffer */
পূর্ণাঙ্ক
encode_attrib(সংরচনা sshbuf *b, ধ্রুৱ Attrib *a)
{
	পূর্ণাঙ্ক r;

	যদি ((r = sshbuf_put_u32(b, a->flags)) != 0)
		ঘূৰাই r;
	যদি (a->flags & SSH2_FILEXFER_ATTR_SIZE) {
		যদি ((r = sshbuf_put_u64(b, a->size)) != 0)
			ঘূৰাই r;
	}
	যদি (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		যদি ((r = sshbuf_put_u32(b, a->uid)) != 0 ||
		    (r = sshbuf_put_u32(b, a->gid)) != 0)
			ঘূৰাই r;
	}
	যদি (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		যদি ((r = sshbuf_put_u32(b, a->perm)) != 0)
			ঘূৰাই r;
	}
	যদি (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		যদি ((r = sshbuf_put_u32(b, a->atime)) != 0 ||
		    (r = sshbuf_put_u32(b, a->mtime)) != 0)
			ঘূৰাই r;
	}
	ঘূৰাই 0;
}

/* Convert from SSH2_FX_ status to text error message */
ধ্রুৱ ৱর্ণ *
fx2txt(পূর্ণাঙ্ক status)
{
	ৱিকল্প (status) {
	পক্ষ SSH2_FX_OK:
		ঘূৰাই("No error");
	পক্ষ SSH2_FX_EOF:
		ঘূৰাই("End of file");
	পক্ষ SSH2_FX_NO_SUCH_FILE:
		ঘূৰাই("No such file or directory");
	পক্ষ SSH2_FX_PERMISSION_DENIED:
		ঘূৰাই("Permission denied");
	পক্ষ SSH2_FX_FAILURE:
		ঘূৰাই("Failure");
	পক্ষ SSH2_FX_BAD_MESSAGE:
		ঘূৰাই("Bad message");
	পক্ষ SSH2_FX_NO_CONNECTION:
		ঘূৰাই("No connection");
	পক্ষ SSH2_FX_CONNECTION_LOST:
		ঘূৰাই("Connection lost");
	পক্ষ SSH2_FX_OP_UNSUPPORTED:
		ঘূৰাই("Operation unsupported");
	স্ৱভাৱ:
		ঘূৰাই("Unknown status");
	}
	/* NOTREACHED */
}

/*
 * drwxr-xr-x    5 markus   markus       1024 Jan 13 18:39 .ssh
 */
ৱর্ণ *
ls_file(ধ্রুৱ ৱর্ণ *name, ধ্রুৱ সংরচনা stat *st, পূর্ণাঙ্ক remote, পূর্ণাঙ্ক si_units,
    ধ্রুৱ ৱর্ণ *user, ধ্রুৱ ৱর্ণ *group)
{
	পূর্ণাঙ্ক ulen, glen, sz = 0;
	সংরচনা tm *ltime = localtime(&st->st_mtime);
	ৱর্ণ buf[1024], lc[8], mode[11+1], tbuf[12+1], ubuf[11+1], gbuf[11+1];
	ৱর্ণ sbuf[FMT_SCALED_STRSIZE];
	time_t now;

	strmode(st->st_mode, mode);
	যদি (remote) {
		যদি (user == রিক্ত) {
			snprintf(ubuf, পরিমাণ ubuf, "%u", (u_int)st->st_uid);
			user = ubuf;
		}
		যদি (group == রিক্ত) {
			snprintf(gbuf, পরিমাণ gbuf, "%u", (u_int)st->st_gid);
			group = gbuf;
		}
		strlcpy(lc, "?", পরিমাণ(lc));
	} অন্যথা {
		user = user_from_uid(st->st_uid, 0);
		group = group_from_gid(st->st_gid, 0);
		snprintf(lc, পরিমাণ(lc), "%u", (u_int)st->st_nlink);
	}
	যদি (ltime != রিক্ত) {
		now = time(রিক্ত);
		যদি (now - (365*24*60*60)/2 < st->st_mtime &&
		    now >= st->st_mtime)
			sz = strftime(tbuf, পরিমাণ tbuf, "%b %e %H:%M", ltime);
		অন্যথা
			sz = strftime(tbuf, পরিমাণ tbuf, "%b %e  %Y", ltime);
	}
	যদি (sz == 0)
		tbuf[0] = '\0';
	ulen = MAXIMUM(strlen(user), 8);
	glen = MAXIMUM(strlen(group), 8);
	যদি (si_units) {
		fmt_scaled((long long)st->st_size, sbuf);
		snprintf(buf, পরিমাণ buf, "%s %3s %-*s %-*s %8s %s %s",
		    mode, lc, ulen, user, glen, group,
		    sbuf, tbuf, name);
	} অন্যথা {
		snprintf(buf, পরিমাণ buf, "%s %3s %-*s %-*s %8llu %s %s",
		    mode, lc, ulen, user, glen, group,
		    (unsigned long long)st->st_size, tbuf, name);
	}
	ঘূৰাই xstrdup(buf);
}
