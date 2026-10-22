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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>

#ಅನ್ತರ್ಭಾವ <grp.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <time.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <util.h>

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "misc.h"

#ಅನ್ತರ್ಭಾವ "sftp.h"
#ಅನ್ತರ್ಭಾವ "sftp-common.h"

/* Clear contents of attributes structure */
ಶೂನ್ಯ
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
ಶೂನ್ಯ
stat_to_attrib(ಧ್ರುವ ಸಂರಚನಾ stat *st, Attrib *a)
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
ಶೂನ್ಯ
attrib_to_stat(ಧ್ರುವ Attrib *a, ಸಂರಚನಾ stat *st)
{
	memset(st, 0, ಪರಿಮಾಣ(*st));

	ಯದಿ (a->flags & SSH2_FILEXFER_ATTR_SIZE)
		st->st_size = a->size;
	ಯದಿ (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		st->st_uid = a->uid;
		st->st_gid = a->gid;
	}
	ಯದಿ (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS)
		st->st_mode = a->perm;
	ಯದಿ (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		st->st_atime = a->atime;
		st->st_mtime = a->mtime;
	}
}

/* Decode attributes in buffer */
ಪೂರ್ಣಾಙ್ಕ
decode_attrib(ಸಂರಚನಾ sshbuf *b, Attrib *a)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	attrib_clear(a);
	ಯದಿ ((r = sshbuf_get_u32(b, &a->flags)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ (a->flags & SSH2_FILEXFER_ATTR_SIZE) {
		ಯದಿ ((r = sshbuf_get_u64(b, &a->size)) != 0)
			ಪ್ರತ್ಯಾಗಮ r;
	}
	ಯದಿ (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		ಯದಿ ((r = sshbuf_get_u32(b, &a->uid)) != 0 ||
		    (r = sshbuf_get_u32(b, &a->gid)) != 0)
			ಪ್ರತ್ಯಾಗಮ r;
	}
	ಯದಿ (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		ಯದಿ ((r = sshbuf_get_u32(b, &a->perm)) != 0)
			ಪ್ರತ್ಯಾಗಮ r;
	}
	ಯದಿ (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		ಯದಿ ((r = sshbuf_get_u32(b, &a->atime)) != 0 ||
		    (r = sshbuf_get_u32(b, &a->mtime)) != 0)
			ಪ್ರತ್ಯಾಗಮ r;
	}
	/* vendor-specific extensions */
	ಯದಿ (a->flags & SSH2_FILEXFER_ATTR_EXTENDED) {
		ವರ್ಣ *type;
		u_char *data;
		size_t dlen;
		u_int i, ಎಣಿಕೆ;

		ಯದಿ ((r = sshbuf_get_u32(b, &ಎಣಿಕೆ)) != 0)
			ಪ್ರತ್ಯಾಗಮ r;
		ಯದಿ (ಎಣಿಕೆ > 0x100000)
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
		ಪ್ರತಿ (i = 0; i < ಎಣಿಕೆ; i++) {
			ಯದಿ ((r = sshbuf_get_cstring(b, &type, ರಿಕ್ತ)) != 0 ||
			    (r = sshbuf_get_string(b, &data, &dlen)) != 0)
				ಪ್ರತ್ಯಾಗಮ r;
			debug3("Got file attribute \"%.100s\" len %zu",
			    type, dlen);
			ಮುಕ್ತ(type);
			ಮುಕ್ತ(data);
		}
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

/* Encode attributes to buffer */
ಪೂರ್ಣಾಙ್ಕ
encode_attrib(ಸಂರಚನಾ sshbuf *b, ಧ್ರುವ Attrib *a)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshbuf_put_u32(b, a->flags)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ (a->flags & SSH2_FILEXFER_ATTR_SIZE) {
		ಯದಿ ((r = sshbuf_put_u64(b, a->size)) != 0)
			ಪ್ರತ್ಯಾಗಮ r;
	}
	ಯದಿ (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		ಯದಿ ((r = sshbuf_put_u32(b, a->uid)) != 0 ||
		    (r = sshbuf_put_u32(b, a->gid)) != 0)
			ಪ್ರತ್ಯಾಗಮ r;
	}
	ಯದಿ (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		ಯದಿ ((r = sshbuf_put_u32(b, a->perm)) != 0)
			ಪ್ರತ್ಯಾಗಮ r;
	}
	ಯದಿ (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		ಯದಿ ((r = sshbuf_put_u32(b, a->atime)) != 0 ||
		    (r = sshbuf_put_u32(b, a->mtime)) != 0)
			ಪ್ರತ್ಯಾಗಮ r;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

/* Convert from SSH2_FX_ status to text error message */
ಧ್ರುವ ವರ್ಣ *
fx2txt(ಪೂರ್ಣಾಙ್ಕ status)
{
	ವಿಕಲ್ಪ (status) {
	ಪಕ್ಷ SSH2_FX_OK:
		ಪ್ರತ್ಯಾಗಮ("No error");
	ಪಕ್ಷ SSH2_FX_EOF:
		ಪ್ರತ್ಯಾಗಮ("End of file");
	ಪಕ್ಷ SSH2_FX_NO_SUCH_FILE:
		ಪ್ರತ್ಯಾಗಮ("No such file or directory");
	ಪಕ್ಷ SSH2_FX_PERMISSION_DENIED:
		ಪ್ರತ್ಯಾಗಮ("Permission denied");
	ಪಕ್ಷ SSH2_FX_FAILURE:
		ಪ್ರತ್ಯಾಗಮ("Failure");
	ಪಕ್ಷ SSH2_FX_BAD_MESSAGE:
		ಪ್ರತ್ಯಾಗಮ("Bad message");
	ಪಕ್ಷ SSH2_FX_NO_CONNECTION:
		ಪ್ರತ್ಯಾಗಮ("No connection");
	ಪಕ್ಷ SSH2_FX_CONNECTION_LOST:
		ಪ್ರತ್ಯಾಗಮ("Connection lost");
	ಪಕ್ಷ SSH2_FX_OP_UNSUPPORTED:
		ಪ್ರತ್ಯಾಗಮ("Operation unsupported");
	ಸ್ವಭಾವ:
		ಪ್ರತ್ಯಾಗಮ("Unknown status");
	}
	/* NOTREACHED */
}

/*
 * drwxr-xr-x    5 markus   markus       1024 Jan 13 18:39 .ssh
 */
ವರ್ಣ *
ls_file(ಧ್ರುವ ವರ್ಣ *name, ಧ್ರುವ ಸಂರಚನಾ stat *st, ಪೂರ್ಣಾಙ್ಕ remote, ಪೂರ್ಣಾಙ್ಕ si_units,
    ಧ್ರುವ ವರ್ಣ *user, ಧ್ರುವ ವರ್ಣ *group)
{
	ಪೂರ್ಣಾಙ್ಕ ulen, glen, sz = 0;
	ಸಂರಚನಾ tm *ltime = localtime(&st->st_mtime);
	ವರ್ಣ buf[1024], lc[8], mode[11+1], tbuf[12+1], ubuf[11+1], gbuf[11+1];
	ವರ್ಣ sbuf[FMT_SCALED_STRSIZE];
	time_t now;

	strmode(st->st_mode, mode);
	ಯದಿ (remote) {
		ಯದಿ (user == ರಿಕ್ತ) {
			snprintf(ubuf, ಪರಿಮಾಣ ubuf, "%u", (u_int)st->st_uid);
			user = ubuf;
		}
		ಯದಿ (group == ರಿಕ್ತ) {
			snprintf(gbuf, ಪರಿಮಾಣ gbuf, "%u", (u_int)st->st_gid);
			group = gbuf;
		}
		strlcpy(lc, "?", ಪರಿಮಾಣ(lc));
	} ಅನ್ಯಥಾ {
		user = user_from_uid(st->st_uid, 0);
		group = group_from_gid(st->st_gid, 0);
		snprintf(lc, ಪರಿಮಾಣ(lc), "%u", (u_int)st->st_nlink);
	}
	ಯದಿ (ltime != ರಿಕ್ತ) {
		now = time(ರಿಕ್ತ);
		ಯದಿ (now - (365*24*60*60)/2 < st->st_mtime &&
		    now >= st->st_mtime)
			sz = strftime(tbuf, ಪರಿಮಾಣ tbuf, "%b %e %H:%M", ltime);
		ಅನ್ಯಥಾ
			sz = strftime(tbuf, ಪರಿಮಾಣ tbuf, "%b %e  %Y", ltime);
	}
	ಯದಿ (sz == 0)
		tbuf[0] = '\0';
	ulen = MAXIMUM(strlen(user), 8);
	glen = MAXIMUM(strlen(group), 8);
	ಯದಿ (si_units) {
		fmt_scaled((long long)st->st_size, sbuf);
		snprintf(buf, ಪರಿಮಾಣ buf, "%s %3s %-*s %-*s %8s %s %s",
		    mode, lc, ulen, user, glen, group,
		    sbuf, tbuf, name);
	} ಅನ್ಯಥಾ {
		snprintf(buf, ಪರಿಮಾಣ buf, "%s %3s %-*s %-*s %8llu %s %s",
		    mode, lc, ulen, user, glen, group,
		    (unsigned long long)st->st_size, tbuf, name);
	}
	ಪ್ರತ್ಯಾಗಮ xstrdup(buf);
}
