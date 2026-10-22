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
	a->ಗಾತ್ರ_2 = 0;
	a->uid = 0;
	a->gid = 0;
	a->perm = 0;
	a->atime = 0;
	a->mtime = 0;
}

/* Convert from struct stat to filexfer attribs */
ಶೂನ್ಯ
stat_ಗಮ್ಯ_attrib(ಸ್ಥಿರಾಂಕ ರಚನೆ stat *st, Attrib *a)
{
	attrib_clear(a);
	a->flags = 0;
	a->flags |= SSH2_FILEXFER_ATTR_ಗಾತ್ರ;
	a->ಗಾತ್ರ_2 = st->st_size;
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
attrib_ಗಮ್ಯ_stat(ಸ್ಥಿರಾಂಕ Attrib *a, ರಚನೆ stat *st)
{
	memset(st, 0, ಗಾತ್ರ(*st));

	ಆದರೆ (a->flags & SSH2_FILEXFER_ATTR_ಗಾತ್ರ)
		st->st_size = a->ಗಾತ್ರ_2;
	ಆದರೆ (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		st->st_uid = a->uid;
		st->st_gid = a->gid;
	}
	ಆದರೆ (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS)
		st->st_mode = a->perm;
	ಆದರೆ (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		st->st_atime = a->atime;
		st->st_mtime = a->mtime;
	}
}

/* Decode attributes in buffer */
ಪೂರ್ಣಾಂಕ
decode_attrib(ರಚನೆ sshbuf *b, Attrib *a)
{
	ಪೂರ್ಣಾಂಕ r;

	attrib_clear(a);
	ಆದರೆ ((r = sshbuf_get_u32(b, &a->flags)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (a->flags & SSH2_FILEXFER_ATTR_ಗಾತ್ರ) {
		ಆದರೆ ((r = sshbuf_get_u64(b, &a->ಗಾತ್ರ_2)) != 0)
			ಹಿಂತಿರುಗಿ r;
	}
	ಆದರೆ (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		ಆದರೆ ((r = sshbuf_get_u32(b, &a->uid)) != 0 ||
		    (r = sshbuf_get_u32(b, &a->gid)) != 0)
			ಹಿಂತಿರುಗಿ r;
	}
	ಆದರೆ (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		ಆದರೆ ((r = sshbuf_get_u32(b, &a->perm)) != 0)
			ಹಿಂತಿರುಗಿ r;
	}
	ಆದರೆ (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		ಆದರೆ ((r = sshbuf_get_u32(b, &a->atime)) != 0 ||
		    (r = sshbuf_get_u32(b, &a->mtime)) != 0)
			ಹಿಂತಿರುಗಿ r;
	}
	/* vendor-specific extensions */
	ಆದರೆ (a->flags & SSH2_FILEXFER_ATTR_EXTENDED) {
		ಅಕ್ಷರ *type;
		u_char *ದತ್ತಾಂಶ;
		ಗಾತ್ರ_t dlen;
		u_int i, ಎಣಿಕೆ_2;

		ಆದರೆ ((r = sshbuf_get_u32(b, &ಎಣಿಕೆ_2)) != 0)
			ಹಿಂತಿರುಗಿ r;
		ಆದರೆ (ಎಣಿಕೆ_2 > 0x100000)
			ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
		ಗಾಗಿ (i = 0; i < ಎಣಿಕೆ_2; i++) {
			ಆದರೆ ((r = sshbuf_get_cstring(b, &type, ಖಾಲಿ)) != 0 ||
			    (r = sshbuf_get_string(b, &ದತ್ತಾಂಶ, &dlen)) != 0)
				ಹಿಂತಿರುಗಿ r;
			debug3("Got file attribute \"%.100s\" len %zu",
			    type, dlen);
			ಬಿಡುಗಡೆ(type);
			ಬಿಡುಗಡೆ(ದತ್ತಾಂಶ);
		}
	}
	ಹಿಂತಿರುಗಿ 0;
}

/* Encode attributes to buffer */
ಪೂರ್ಣಾಂಕ
encode_attrib(ರಚನೆ sshbuf *b, ಸ್ಥಿರಾಂಕ Attrib *a)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshbuf_put_u32(b, a->flags)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (a->flags & SSH2_FILEXFER_ATTR_ಗಾತ್ರ) {
		ಆದರೆ ((r = sshbuf_put_u64(b, a->ಗಾತ್ರ_2)) != 0)
			ಹಿಂತಿರುಗಿ r;
	}
	ಆದರೆ (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		ಆದರೆ ((r = sshbuf_put_u32(b, a->uid)) != 0 ||
		    (r = sshbuf_put_u32(b, a->gid)) != 0)
			ಹಿಂತಿರುಗಿ r;
	}
	ಆದರೆ (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		ಆದರೆ ((r = sshbuf_put_u32(b, a->perm)) != 0)
			ಹಿಂತಿರುಗಿ r;
	}
	ಆದರೆ (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		ಆದರೆ ((r = sshbuf_put_u32(b, a->atime)) != 0 ||
		    (r = sshbuf_put_u32(b, a->mtime)) != 0)
			ಹಿಂತಿರುಗಿ r;
	}
	ಹಿಂತಿರುಗಿ 0;
}

/* Convert from SSH2_FX_ status to text error message */
ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
fx2txt(ಪೂರ್ಣಾಂಕ ಸ್ಥಿತಿ_2)
{
	ಆಯ್ಕೆ (ಸ್ಥಿತಿ_2) {
	ಸ್ಥಿತಿ SSH2_FX_OK:
		ಹಿಂತಿರುಗಿ("No error");
	ಸ್ಥಿತಿ SSH2_FX_EOF:
		ಹಿಂತಿರುಗಿ("End of file");
	ಸ್ಥಿತಿ SSH2_FX_NO_SUCH_FILE:
		ಹಿಂತಿರುಗಿ("No such file or directory");
	ಸ್ಥಿತಿ SSH2_FX_PERMISSION_DENIED:
		ಹಿಂತಿರುಗಿ("Permission denied");
	ಸ್ಥಿತಿ SSH2_FX_FAILURE:
		ಹಿಂತಿರುಗಿ("Failure");
	ಸ್ಥಿತಿ SSH2_FX_BAD_ಸಂದೇಶ:
		ಹಿಂತಿರುಗಿ("Bad message");
	ಸ್ಥಿತಿ SSH2_FX_NO_CONNECTION:
		ಹಿಂತಿರುಗಿ("No connection");
	ಸ್ಥಿತಿ SSH2_FX_CONNECTION_ಕಳೆದುಹೋದ:
		ಹಿಂತಿರುಗಿ("Connection lost");
	ಸ್ಥಿತಿ SSH2_FX_OP_UNSUPPORTED:
		ಹಿಂತಿರುಗಿ("Operation unsupported");
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ("Unknown status");
	}
	/* NOTREACHED */
}

/*
 * drwxr-xr-x    5 markus   markus       1024 Jan 13 18:39 .ssh
 */
ಅಕ್ಷರ *
ls_file(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name, ಸ್ಥಿರಾಂಕ ರಚನೆ stat *st, ಪೂರ್ಣಾಂಕ remote, ಪೂರ್ಣಾಂಕ si_units,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *user, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಗುಂಪು)
{
	ಪೂರ್ಣಾಂಕ ulen, glen, sz = 0;
	ರಚನೆ tm *ltime = localtime(&st->st_mtime);
	ಅಕ್ಷರ buf[1024], lc[8], ಬಹುಲಕ[11+1], tbuf[12+1], ubuf[11+1], gbuf[11+1];
	ಅಕ್ಷರ sbuf[FMT_SCALED_STRSIZE];
	time_t now;

	strmode(st->st_mode, ಬಹುಲಕ);
	ಆದರೆ (remote) {
		ಆದರೆ (user == ಖಾಲಿ) {
			snprintf(ubuf, ಗಾತ್ರ ubuf, "%u", (u_int)st->st_uid);
			user = ubuf;
		}
		ಆದರೆ (ಗುಂಪು == ಖಾಲಿ) {
			snprintf(gbuf, ಗಾತ್ರ gbuf, "%u", (u_int)st->st_gid);
			ಗುಂಪು = gbuf;
		}
		strlcpy(lc, "?", ಗಾತ್ರ(lc));
	} ಇಲ್ಲದಿದ್ದರೆ {
		user = user_from_uid(st->st_uid, 0);
		ಗುಂಪು = ಗುಂಪು_from_gid(st->st_gid, 0);
		snprintf(lc, ಗಾತ್ರ(lc), "%u", (u_int)st->st_nlink);
	}
	ಆದರೆ (ltime != ಖಾಲಿ) {
		now = time(ಖಾಲಿ);
		ಆದರೆ (now - (365*24*60*60)/2 < st->st_mtime &&
		    now >= st->st_mtime)
			sz = strftime(tbuf, ಗಾತ್ರ tbuf, "%b %e %H:%M", ltime);
		ಇಲ್ಲದಿದ್ದರೆ
			sz = strftime(tbuf, ಗಾತ್ರ tbuf, "%b %e  %Y", ltime);
	}
	ಆದರೆ (sz == 0)
		tbuf[0] = '\0';
	ulen = ಗರಿಷ್ಠ(ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(user), 8);
	glen = ಗರಿಷ್ಠ(ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಗುಂಪು), 8);
	ಆದರೆ (si_units) {
		fmt_scaled((ದೀರ್ಘ ದೀರ್ಘ)st->st_size, sbuf);
		snprintf(buf, ಗಾತ್ರ buf, "%s %3s %-*s %-*s %8s %s %s",
		    ಬಹುಲಕ, lc, ulen, user, glen, ಗುಂಪು,
		    sbuf, tbuf, name);
	} ಇಲ್ಲದಿದ್ದರೆ {
		snprintf(buf, ಗಾತ್ರ buf, "%s %3s %-*s %-*s %8llu %s %s",
		    ಬಹುಲಕ, lc, ulen, user, glen, ಗುಂಪು,
		    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)st->st_size, tbuf, name);
	}
	ಹಿಂತಿರುಗಿ xstrdup(buf);
}
