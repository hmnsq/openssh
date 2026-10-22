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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/stat.h>

#అన్తర్భావ <grp.h>
#అన్తర్భావ <pwd.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <time.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <util.h>

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "misc.h"

#అన్తర్భావ "sftp.h"
#అన్తర్భావ "sftp-common.h"

/* Clear contents of attributes structure */
శూన్య
attrib_clear(Attrib *a)
{
	a->flags = 0;
	a->కొలత = 0;
	a->uid = 0;
	a->gid = 0;
	a->perm = 0;
	a->atime = 0;
	a->mtime = 0;
}

/* Convert from struct stat to filexfer attribs */
శూన్య
stat_గమ్యం_attrib(స్థిరరాశి నిర్మాణం stat *st, Attrib *a)
{
	attrib_clear(a);
	a->flags = 0;
	a->flags |= SSH2_FILEXFER_ATTR_కొలత;
	a->కొలత = st->st_size;
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
శూన్య
attrib_గమ్యం_stat(స్థిరరాశి Attrib *a, నిర్మాణం stat *st)
{
	memset(st, 0, పరిమాణం(*st));

	ఒకవేళ (a->flags & SSH2_FILEXFER_ATTR_కొలత)
		st->st_size = a->కొలత;
	ఒకవేళ (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		st->st_uid = a->uid;
		st->st_gid = a->gid;
	}
	ఒకవేళ (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS)
		st->st_mode = a->perm;
	ఒకవేళ (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		st->st_atime = a->atime;
		st->st_mtime = a->mtime;
	}
}

/* Decode attributes in buffer */
పూర్ణాంకం
decode_attrib(నిర్మాణం sshbuf *b, Attrib *a)
{
	పూర్ణాంకం r;

	attrib_clear(a);
	ఒకవేళ ((r = sshbuf_get_u32(b, &a->flags)) != 0)
		తిరిగి r;
	ఒకవేళ (a->flags & SSH2_FILEXFER_ATTR_కొలత) {
		ఒకవేళ ((r = sshbuf_get_u64(b, &a->కొలత)) != 0)
			తిరిగి r;
	}
	ఒకవేళ (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		ఒకవేళ ((r = sshbuf_get_u32(b, &a->uid)) != 0 ||
		    (r = sshbuf_get_u32(b, &a->gid)) != 0)
			తిరిగి r;
	}
	ఒకవేళ (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		ఒకవేళ ((r = sshbuf_get_u32(b, &a->perm)) != 0)
			తిరిగి r;
	}
	ఒకవేళ (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		ఒకవేళ ((r = sshbuf_get_u32(b, &a->atime)) != 0 ||
		    (r = sshbuf_get_u32(b, &a->mtime)) != 0)
			తిరిగి r;
	}
	/* vendor-specific extensions */
	ఒకవేళ (a->flags & SSH2_FILEXFER_ATTR_EXTENDED) {
		అక్షరం *type;
		u_char *దత్తాంశం;
		కొలత_t dlen;
		u_int i, లెక్క;

		ఒకవేళ ((r = sshbuf_get_u32(b, &లెక్క)) != 0)
			తిరిగి r;
		ఒకవేళ (లెక్క > 0x100000)
			తిరిగి SSH_ERR_INVALID_FORMAT;
		కొరకు (i = 0; i < లెక్క; i++) {
			ఒకవేళ ((r = sshbuf_get_cstring(b, &type, ఖాళీ)) != 0 ||
			    (r = sshbuf_get_string(b, &దత్తాంశం, &dlen)) != 0)
				తిరిగి r;
			debug3("Got file attribute \"%.100s\" len %zu",
			    type, dlen);
			విడుదల(type);
			విడుదల(దత్తాంశం);
		}
	}
	తిరిగి 0;
}

/* Encode attributes to buffer */
పూర్ణాంకం
encode_attrib(నిర్మాణం sshbuf *b, స్థిరరాశి Attrib *a)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshbuf_put_u32(b, a->flags)) != 0)
		తిరిగి r;
	ఒకవేళ (a->flags & SSH2_FILEXFER_ATTR_కొలత) {
		ఒకవేళ ((r = sshbuf_put_u64(b, a->కొలత)) != 0)
			తిరిగి r;
	}
	ఒకవేళ (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		ఒకవేళ ((r = sshbuf_put_u32(b, a->uid)) != 0 ||
		    (r = sshbuf_put_u32(b, a->gid)) != 0)
			తిరిగి r;
	}
	ఒకవేళ (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		ఒకవేళ ((r = sshbuf_put_u32(b, a->perm)) != 0)
			తిరిగి r;
	}
	ఒకవేళ (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		ఒకవేళ ((r = sshbuf_put_u32(b, a->atime)) != 0 ||
		    (r = sshbuf_put_u32(b, a->mtime)) != 0)
			తిరిగి r;
	}
	తిరిగి 0;
}

/* Convert from SSH2_FX_ status to text error message */
స్థిరరాశి అక్షరం *
fx2txt(పూర్ణాంకం స్థితి_2)
{
	ఎంపిక (స్థితి_2) {
	స్థితి SSH2_FX_OK:
		తిరిగి("No error");
	స్థితి SSH2_FX_EOF:
		తిరిగి("End of file");
	స్థితి SSH2_FX_NO_SUCH_FILE:
		తిరిగి("No such file or directory");
	స్థితి SSH2_FX_PERMISSION_DENIED:
		తిరిగి("Permission denied");
	స్థితి SSH2_FX_FAILURE:
		తిరిగి("Failure");
	స్థితి SSH2_FX_BAD_సందేశం:
		తిరిగి("Bad message");
	స్థితి SSH2_FX_NO_CONNECTION:
		తిరిగి("No connection");
	స్థితి SSH2_FX_CONNECTION_కోల్పోయిన:
		తిరిగి("Connection lost");
	స్థితి SSH2_FX_OP_UNSUPPORTED:
		తిరిగి("Operation unsupported");
	అప్రమేయ:
		తిరిగి("Unknown status");
	}
	/* NOTREACHED */
}

/*
 * drwxr-xr-x    5 markus   markus       1024 Jan 13 18:39 .ssh
 */
అక్షరం *
ls_file(స్థిరరాశి అక్షరం *name, స్థిరరాశి నిర్మాణం stat *st, పూర్ణాంకం remote, పూర్ణాంకం si_units,
    స్థిరరాశి అక్షరం *user, స్థిరరాశి అక్షరం *సమూహం)
{
	పూర్ణాంకం ulen, glen, sz = 0;
	నిర్మాణం tm *ltime = localtime(&st->st_mtime);
	అక్షరం buf[1024], lc[8], బహుళకం[11+1], tbuf[12+1], ubuf[11+1], gbuf[11+1];
	అక్షరం sbuf[FMT_SCALED_STRSIZE];
	time_t now;

	strmode(st->st_mode, బహుళకం);
	ఒకవేళ (remote) {
		ఒకవేళ (user == ఖాళీ) {
			snprintf(ubuf, పరిమాణం ubuf, "%u", (u_int)st->st_uid);
			user = ubuf;
		}
		ఒకవేళ (సమూహం == ఖాళీ) {
			snprintf(gbuf, పరిమాణం gbuf, "%u", (u_int)st->st_gid);
			సమూహం = gbuf;
		}
		strlcpy(lc, "?", పరిమాణం(lc));
	} లేకపోతే {
		user = user_from_uid(st->st_uid, 0);
		సమూహం = సమూహం_from_gid(st->st_gid, 0);
		snprintf(lc, పరిమాణం(lc), "%u", (u_int)st->st_nlink);
	}
	ఒకవేళ (ltime != ఖాళీ) {
		now = time(ఖాళీ);
		ఒకవేళ (now - (365*24*60*60)/2 < st->st_mtime &&
		    now >= st->st_mtime)
			sz = strftime(tbuf, పరిమాణం tbuf, "%b %e %H:%M", ltime);
		లేకపోతే
			sz = strftime(tbuf, పరిమాణం tbuf, "%b %e  %Y", ltime);
	}
	ఒకవేళ (sz == 0)
		tbuf[0] = '\0';
	ulen = గరిష్ఠ(అక్షరశ్రేణి_పొడవు(user), 8);
	glen = గరిష్ఠ(అక్షరశ్రేణి_పొడవు(సమూహం), 8);
	ఒకవేళ (si_units) {
		fmt_scaled((దీర్ఘ దీర్ఘ)st->st_size, sbuf);
		snprintf(buf, పరిమాణం buf, "%s %3s %-*s %-*s %8s %s %s",
		    బహుళకం, lc, ulen, user, glen, సమూహం,
		    sbuf, tbuf, name);
	} లేకపోతే {
		snprintf(buf, పరిమాణం buf, "%s %3s %-*s %-*s %8llu %s %s",
		    బహుళకం, lc, ulen, user, glen, సమూహం,
		    (గుర్తులేని దీర్ఘ దీర్ఘ)st->st_size, tbuf, name);
	}
	తిరిగి xstrdup(buf);
}
