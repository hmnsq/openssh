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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/stat.h>

#অন্তর্ভাব <grp.h>
#অন্তর্ভাব <pwd.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <time.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <util.h>

#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "misc.h"

#অন্তর্ভাব "sftp.h"
#অন্তর্ভাব "sftp-common.h"

/* Clear contents of attributes structure */
শূন্য
attrib_clear(Attrib *a)
{
	a->flags = 0;
	a->আকার_2 = 0;
	a->uid = 0;
	a->gid = 0;
	a->perm = 0;
	a->atime = 0;
	a->mtime = 0;
}

/* Convert from struct stat to filexfer attribs */
শূন্য
stat_to_attrib(ধ্রুবক কাঠামো stat *st, Attrib *a)
{
	attrib_clear(a);
	a->flags = 0;
	a->flags |= SSH2_FILEXFER_ATTR_আকার;
	a->আকার_2 = st->st_size;
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
attrib_to_stat(ধ্রুবক Attrib *a, কাঠামো stat *st)
{
	memset(st, 0, আকার(*st));

	যদি (a->flags & SSH2_FILEXFER_ATTR_আকার)
		st->st_size = a->আকার_2;
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
পূর্ণসংখ্যা
decode_attrib(কাঠামো sshbuf *b, Attrib *a)
{
	পূর্ণসংখ্যা r;

	attrib_clear(a);
	যদি ((r = sshbuf_get_u32(b, &a->flags)) != 0)
		ফেরত r;
	যদি (a->flags & SSH2_FILEXFER_ATTR_আকার) {
		যদি ((r = sshbuf_get_u64(b, &a->আকার_2)) != 0)
			ফেরত r;
	}
	যদি (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		যদি ((r = sshbuf_get_u32(b, &a->uid)) != 0 ||
		    (r = sshbuf_get_u32(b, &a->gid)) != 0)
			ফেরত r;
	}
	যদি (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		যদি ((r = sshbuf_get_u32(b, &a->perm)) != 0)
			ফেরত r;
	}
	যদি (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		যদি ((r = sshbuf_get_u32(b, &a->atime)) != 0 ||
		    (r = sshbuf_get_u32(b, &a->mtime)) != 0)
			ফেরত r;
	}
	/* vendor-specific extensions */
	যদি (a->flags & SSH2_FILEXFER_ATTR_EXTENDED) {
		অক্ষর *type;
		u_char *তথ্য;
		আকার_t dlen;
		u_int i, গুনতি;

		যদি ((r = sshbuf_get_u32(b, &গুনতি)) != 0)
			ফেরত r;
		যদি (গুনতি > 0x100000)
			ফেরত SSH_ERR_INVALID_FORMAT;
		জন্য (i = 0; i < গুনতি; i++) {
			যদি ((r = sshbuf_get_cstring(b, &type, ফাঁকা)) != 0 ||
			    (r = sshbuf_get_string(b, &তথ্য, &dlen)) != 0)
				ফেরত r;
			debug3("Got file attribute \"%.100s\" len %zu",
			    type, dlen);
			মুক্ত(type);
			মুক্ত(তথ্য);
		}
	}
	ফেরত 0;
}

/* Encode attributes to buffer */
পূর্ণসংখ্যা
encode_attrib(কাঠামো sshbuf *b, ধ্রুবক Attrib *a)
{
	পূর্ণসংখ্যা r;

	যদি ((r = sshbuf_put_u32(b, a->flags)) != 0)
		ফেরত r;
	যদি (a->flags & SSH2_FILEXFER_ATTR_আকার) {
		যদি ((r = sshbuf_put_u64(b, a->আকার_2)) != 0)
			ফেরত r;
	}
	যদি (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		যদি ((r = sshbuf_put_u32(b, a->uid)) != 0 ||
		    (r = sshbuf_put_u32(b, a->gid)) != 0)
			ফেরত r;
	}
	যদি (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		যদি ((r = sshbuf_put_u32(b, a->perm)) != 0)
			ফেরত r;
	}
	যদি (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		যদি ((r = sshbuf_put_u32(b, a->atime)) != 0 ||
		    (r = sshbuf_put_u32(b, a->mtime)) != 0)
			ফেরত r;
	}
	ফেরত 0;
}

/* Convert from SSH2_FX_ status to text error message */
ধ্রুবক অক্ষর *
fx2txt(পূর্ণসংখ্যা status)
{
	নির্বাচন (status) {
	ক্ষেত্র SSH2_FX_OK:
		ফেরত("No error");
	ক্ষেত্র SSH2_FX_EOF:
		ফেরত("End of file");
	ক্ষেত্র SSH2_FX_NO_SUCH_FILE:
		ফেরত("No such file or directory");
	ক্ষেত্র SSH2_FX_PERMISSION_DENIED:
		ফেরত("Permission denied");
	ক্ষেত্র SSH2_FX_FAILURE:
		ফেরত("Failure");
	ক্ষেত্র SSH2_FX_BAD_MESSAGE:
		ফেরত("Bad message");
	ক্ষেত্র SSH2_FX_NO_CONNECTION:
		ফেরত("No connection");
	ক্ষেত্র SSH2_FX_CONNECTION_LOST:
		ফেরত("Connection lost");
	ক্ষেত্র SSH2_FX_OP_UNSUPPORTED:
		ফেরত("Operation unsupported");
	পূর্বনির্ধারিত:
		ফেরত("Unknown status");
	}
	/* NOTREACHED */
}

/*
 * drwxr-xr-x    5 markus   markus       1024 Jan 13 18:39 .ssh
 */
অক্ষর *
ls_file(ধ্রুবক অক্ষর *name, ধ্রুবক কাঠামো stat *st, পূর্ণসংখ্যা remote, পূর্ণসংখ্যা si_units,
    ধ্রুবক অক্ষর *user, ধ্রুবক অক্ষর *group)
{
	পূর্ণসংখ্যা ulen, glen, sz = 0;
	কাঠামো tm *ltime = localtime(&st->st_mtime);
	অক্ষর buf[1024], lc[8], mode[11+1], tbuf[12+1], ubuf[11+1], gbuf[11+1];
	অক্ষর sbuf[FMT_SCALED_STRSIZE];
	time_t now;

	strmode(st->st_mode, mode);
	যদি (remote) {
		যদি (user == ফাঁকা) {
			snprintf(ubuf, আকার ubuf, "%u", (u_int)st->st_uid);
			user = ubuf;
		}
		যদি (group == ফাঁকা) {
			snprintf(gbuf, আকার gbuf, "%u", (u_int)st->st_gid);
			group = gbuf;
		}
		strlcpy(lc, "?", আকার(lc));
	} অন্যথা {
		user = user_from_uid(st->st_uid, 0);
		group = group_from_gid(st->st_gid, 0);
		snprintf(lc, আকার(lc), "%u", (u_int)st->st_nlink);
	}
	যদি (ltime != ফাঁকা) {
		now = time(ফাঁকা);
		যদি (now - (365*24*60*60)/2 < st->st_mtime &&
		    now >= st->st_mtime)
			sz = strftime(tbuf, আকার tbuf, "%b %e %H:%M", ltime);
		অন্যথা
			sz = strftime(tbuf, আকার tbuf, "%b %e  %Y", ltime);
	}
	যদি (sz == 0)
		tbuf[0] = '\0';
	ulen = MAXIMUM(strlen(user), 8);
	glen = MAXIMUM(strlen(group), 8);
	যদি (si_units) {
		fmt_scaled((long long)st->st_size, sbuf);
		snprintf(buf, আকার buf, "%s %3s %-*s %-*s %8s %s %s",
		    mode, lc, ulen, user, glen, group,
		    sbuf, tbuf, name);
	} অন্যথা {
		snprintf(buf, আকার buf, "%s %3s %-*s %-*s %8llu %s %s",
		    mode, lc, ulen, user, glen, group,
		    (unsigned long long)st->st_size, tbuf, name);
	}
	ফেরত xstrdup(buf);
}
