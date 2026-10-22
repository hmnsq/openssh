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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/stat.h>

#ଅନ୍ତର୍ଭାଵ <grp.h>
#ଅନ୍ତର୍ଭାଵ <pwd.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <time.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <util.h>

#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"

#ଅନ୍ତର୍ଭାଵ "sftp.h"
#ଅନ୍ତର୍ଭାଵ "sftp-common.h"

/* Clear contents of attributes structure */
ଶୂନ୍ୟ
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
ଶୂନ୍ୟ
stat_to_attrib(ଅଚଳ ସଂରଚନା stat *st, Attrib *a)
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
ଶୂନ୍ୟ
attrib_to_stat(ଅଚଳ Attrib *a, ସଂରଚନା stat *st)
{
	memset(st, 0, ଆକାର(*st));

	ଯଦି (a->flags & SSH2_FILEXFER_ATTR_SIZE)
		st->st_size = a->size;
	ଯଦି (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		st->st_uid = a->uid;
		st->st_gid = a->gid;
	}
	ଯଦି (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS)
		st->st_mode = a->perm;
	ଯଦି (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		st->st_atime = a->atime;
		st->st_mtime = a->mtime;
	}
}

/* Decode attributes in buffer */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
decode_attrib(ସଂରଚନା sshbuf *b, Attrib *a)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	attrib_clear(a);
	ଯଦି ((r = sshbuf_get_u32(b, &a->flags)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି (a->flags & SSH2_FILEXFER_ATTR_SIZE) {
		ଯଦି ((r = sshbuf_get_u64(b, &a->size)) != 0)
			ଫେରନ୍ତୁ r;
	}
	ଯଦି (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		ଯଦି ((r = sshbuf_get_u32(b, &a->uid)) != 0 ||
		    (r = sshbuf_get_u32(b, &a->gid)) != 0)
			ଫେରନ୍ତୁ r;
	}
	ଯଦି (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		ଯଦି ((r = sshbuf_get_u32(b, &a->perm)) != 0)
			ଫେରନ୍ତୁ r;
	}
	ଯଦି (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		ଯଦି ((r = sshbuf_get_u32(b, &a->atime)) != 0 ||
		    (r = sshbuf_get_u32(b, &a->mtime)) != 0)
			ଫେରନ୍ତୁ r;
	}
	/* vendor-specific extensions */
	ଯଦି (a->flags & SSH2_FILEXFER_ATTR_EXTENDED) {
		ଅକ୍ଷର *type;
		u_char *data;
		size_t dlen;
		u_int i, ଗଣନା_2;

		ଯଦି ((r = sshbuf_get_u32(b, &ଗଣନା_2)) != 0)
			ଫେରନ୍ତୁ r;
		ଯଦି (ଗଣନା_2 > 0x100000)
			ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
		ପାଇଁ (i = 0; i < ଗଣନା_2; i++) {
			ଯଦି ((r = sshbuf_get_cstring(b, &type, ଖାଲି)) != 0 ||
			    (r = sshbuf_get_string(b, &data, &dlen)) != 0)
				ଫେରନ୍ତୁ r;
			debug3("Got file attribute \"%.100s\" len %zu",
			    type, dlen);
			ମୁକ୍ତ(type);
			ମୁକ୍ତ(data);
		}
	}
	ଫେରନ୍ତୁ 0;
}

/* Encode attributes to buffer */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
encode_attrib(ସଂରଚନା sshbuf *b, ଅଚଳ Attrib *a)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshbuf_put_u32(b, a->flags)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି (a->flags & SSH2_FILEXFER_ATTR_SIZE) {
		ଯଦି ((r = sshbuf_put_u64(b, a->size)) != 0)
			ଫେରନ୍ତୁ r;
	}
	ଯଦି (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		ଯଦି ((r = sshbuf_put_u32(b, a->uid)) != 0 ||
		    (r = sshbuf_put_u32(b, a->gid)) != 0)
			ଫେରନ୍ତୁ r;
	}
	ଯଦି (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		ଯଦି ((r = sshbuf_put_u32(b, a->perm)) != 0)
			ଫେରନ୍ତୁ r;
	}
	ଯଦି (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		ଯଦି ((r = sshbuf_put_u32(b, a->atime)) != 0 ||
		    (r = sshbuf_put_u32(b, a->mtime)) != 0)
			ଫେରନ୍ତୁ r;
	}
	ଫେରନ୍ତୁ 0;
}

/* Convert from SSH2_FX_ status to text error message */
ଅଚଳ ଅକ୍ଷର *
fx2txt(ପୂର୍ଣ୍ଣସଂଖ୍ୟା status)
{
	ବାଛ (status) {
	ସ୍ଥିତି SSH2_FX_OK:
		ଫେରନ୍ତୁ("No error");
	ସ୍ଥିତି SSH2_FX_EOF:
		ଫେରନ୍ତୁ("End of file");
	ସ୍ଥିତି SSH2_FX_NO_SUCH_FILE:
		ଫେରନ୍ତୁ("No such file or directory");
	ସ୍ଥିତି SSH2_FX_PERMISSION_DENIED:
		ଫେରନ୍ତୁ("Permission denied");
	ସ୍ଥିତି SSH2_FX_FAILURE:
		ଫେରନ୍ତୁ("Failure");
	ସ୍ଥିତି SSH2_FX_BAD_MESSAGE:
		ଫେରନ୍ତୁ("Bad message");
	ସ୍ଥିତି SSH2_FX_NO_CONNECTION:
		ଫେରନ୍ତୁ("No connection");
	ସ୍ଥିତି SSH2_FX_CONNECTION_LOST:
		ଫେରନ୍ତୁ("Connection lost");
	ସ୍ଥିତି SSH2_FX_OP_UNSUPPORTED:
		ଫେରନ୍ତୁ("Operation unsupported");
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ("Unknown status");
	}
	/* NOTREACHED */
}

/*
 * drwxr-xr-x    5 markus   markus       1024 Jan 13 18:39 .ssh
 */
ଅକ୍ଷର *
ls_file(ଅଚଳ ଅକ୍ଷର *name, ଅଚଳ ସଂରଚନା stat *st, ପୂର୍ଣ୍ଣସଂଖ୍ୟା remote, ପୂର୍ଣ୍ଣସଂଖ୍ୟା si_units,
    ଅଚଳ ଅକ୍ଷର *user, ଅଚଳ ଅକ୍ଷର *group)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ulen, glen, sz = 0;
	ସଂରଚନା tm *ltime = localtime(&st->st_mtime);
	ଅକ୍ଷର buf[1024], lc[8], mode[11+1], tbuf[12+1], ubuf[11+1], gbuf[11+1];
	ଅକ୍ଷର sbuf[FMT_SCALED_STRSIZE];
	time_t now;

	strmode(st->st_mode, mode);
	ଯଦି (remote) {
		ଯଦି (user == ଖାଲି) {
			snprintf(ubuf, ଆକାର ubuf, "%u", (u_int)st->st_uid);
			user = ubuf;
		}
		ଯଦି (group == ଖାଲି) {
			snprintf(gbuf, ଆକାର gbuf, "%u", (u_int)st->st_gid);
			group = gbuf;
		}
		strlcpy(lc, "?", ଆକାର(lc));
	} ଅନ୍ୟଥା {
		user = user_from_uid(st->st_uid, 0);
		group = group_from_gid(st->st_gid, 0);
		snprintf(lc, ଆକାର(lc), "%u", (u_int)st->st_nlink);
	}
	ଯଦି (ltime != ଖାଲି) {
		now = time(ଖାଲି);
		ଯଦି (now - (365*24*60*60)/2 < st->st_mtime &&
		    now >= st->st_mtime)
			sz = strftime(tbuf, ଆକାର tbuf, "%b %e %H:%M", ltime);
		ଅନ୍ୟଥା
			sz = strftime(tbuf, ଆକାର tbuf, "%b %e  %Y", ltime);
	}
	ଯଦି (sz == 0)
		tbuf[0] = '\0';
	ulen = MAXIMUM(strlen(user), 8);
	glen = MAXIMUM(strlen(group), 8);
	ଯଦି (si_units) {
		fmt_scaled((long long)st->st_size, sbuf);
		snprintf(buf, ଆକାର buf, "%s %3s %-*s %-*s %8s %s %s",
		    mode, lc, ulen, user, glen, group,
		    sbuf, tbuf, name);
	} ଅନ୍ୟଥା {
		snprintf(buf, ଆକାର buf, "%s %3s %-*s %-*s %8llu %s %s",
		    mode, lc, ulen, user, glen, group,
		    (unsigned long long)st->st_size, tbuf, name);
	}
	ଫେରନ୍ତୁ xstrdup(buf);
}
