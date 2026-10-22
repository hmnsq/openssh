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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/stat.h>

#अन्तर्भाव <grp.h>
#अन्तर्भाव <pwd.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <time.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <util.h>

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "misc.h"

#अन्तर्भाव "sftp.h"
#अन्तर्भाव "sftp-common.h"

/* Clear contents of attributes structure */
शून्य
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
शून्य
stat_to_attrib(ध्रुव संरचना stat *st, Attrib *a)
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
शून्य
attrib_to_stat(ध्रुव Attrib *a, संरचना stat *st)
{
	memset(st, 0, परिमाण(*st));

	जइ (a->flags & SSH2_FILEXFER_ATTR_SIZE)
		st->st_size = a->size;
	जइ (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		st->st_uid = a->uid;
		st->st_gid = a->gid;
	}
	जइ (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS)
		st->st_mode = a->perm;
	जइ (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		st->st_atime = a->atime;
		st->st_mtime = a->mtime;
	}
}

/* Decode attributes in buffer */
पूर्णाङ्क
decode_attrib(संरचना sshbuf *b, Attrib *a)
{
	पूर्णाङ्क r;

	attrib_clear(a);
	जइ ((r = sshbuf_get_u32(b, &a->flags)) != 0)
		प्रत्यागम r;
	जइ (a->flags & SSH2_FILEXFER_ATTR_SIZE) {
		जइ ((r = sshbuf_get_u64(b, &a->size)) != 0)
			प्रत्यागम r;
	}
	जइ (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		जइ ((r = sshbuf_get_u32(b, &a->uid)) != 0 ||
		    (r = sshbuf_get_u32(b, &a->gid)) != 0)
			प्रत्यागम r;
	}
	जइ (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		जइ ((r = sshbuf_get_u32(b, &a->perm)) != 0)
			प्रत्यागम r;
	}
	जइ (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		जइ ((r = sshbuf_get_u32(b, &a->atime)) != 0 ||
		    (r = sshbuf_get_u32(b, &a->mtime)) != 0)
			प्रत्यागम r;
	}
	/* vendor-specific extensions */
	जइ (a->flags & SSH2_FILEXFER_ATTR_EXTENDED) {
		वर्ण *type;
		u_char *data;
		size_t dlen;
		u_int i, गणनम्;

		जइ ((r = sshbuf_get_u32(b, &गणनम्)) != 0)
			प्रत्यागम r;
		जइ (गणनम् > 0x100000)
			प्रत्यागम SSH_ERR_INVALID_FORMAT;
		प्रति (i = 0; i < गणनम्; i++) {
			जइ ((r = sshbuf_get_cstring(b, &type, रिक्त)) != 0 ||
			    (r = sshbuf_get_string(b, &data, &dlen)) != 0)
				प्रत्यागम r;
			debug3("Got file attribute \"%.100s\" len %zu",
			    type, dlen);
			मुक्त(type);
			मुक्त(data);
		}
	}
	प्रत्यागम 0;
}

/* Encode attributes to buffer */
पूर्णाङ्क
encode_attrib(संरचना sshbuf *b, ध्रुव Attrib *a)
{
	पूर्णाङ्क r;

	जइ ((r = sshbuf_put_u32(b, a->flags)) != 0)
		प्रत्यागम r;
	जइ (a->flags & SSH2_FILEXFER_ATTR_SIZE) {
		जइ ((r = sshbuf_put_u64(b, a->size)) != 0)
			प्रत्यागम r;
	}
	जइ (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		जइ ((r = sshbuf_put_u32(b, a->uid)) != 0 ||
		    (r = sshbuf_put_u32(b, a->gid)) != 0)
			प्रत्यागम r;
	}
	जइ (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		जइ ((r = sshbuf_put_u32(b, a->perm)) != 0)
			प्रत्यागम r;
	}
	जइ (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		जइ ((r = sshbuf_put_u32(b, a->atime)) != 0 ||
		    (r = sshbuf_put_u32(b, a->mtime)) != 0)
			प्रत्यागम r;
	}
	प्रत्यागम 0;
}

/* Convert from SSH2_FX_ status to text error message */
ध्रुव वर्ण *
fx2txt(पूर्णाङ्क status)
{
	विकल्प (status) {
	पक्ष SSH2_FX_OK:
		प्रत्यागम("No error");
	पक्ष SSH2_FX_EOF:
		प्रत्यागम("End of file");
	पक्ष SSH2_FX_NO_SUCH_FILE:
		प्रत्यागम("No such file or directory");
	पक्ष SSH2_FX_PERMISSION_DENIED:
		प्रत्यागम("Permission denied");
	पक्ष SSH2_FX_FAILURE:
		प्रत्यागम("Failure");
	पक्ष SSH2_FX_BAD_MESSAGE:
		प्रत्यागम("Bad message");
	पक्ष SSH2_FX_NO_CONNECTION:
		प्रत्यागम("No connection");
	पक्ष SSH2_FX_CONNECTION_LOST:
		प्रत्यागम("Connection lost");
	पक्ष SSH2_FX_OP_UNSUPPORTED:
		प्रत्यागम("Operation unsupported");
	स्वभाव:
		प्रत्यागम("Unknown status");
	}
	/* NOTREACHED */
}

/*
 * drwxr-xr-x    5 markus   markus       1024 Jan 13 18:39 .ssh
 */
वर्ण *
ls_file(ध्रुव वर्ण *name, ध्रुव संरचना stat *st, पूर्णाङ्क remote, पूर्णाङ्क si_units,
    ध्रुव वर्ण *user, ध्रुव वर्ण *group)
{
	पूर्णाङ्क ulen, glen, sz = 0;
	संरचना tm *ltime = localtime(&st->st_mtime);
	वर्ण buf[1024], lc[8], mode[11+1], tbuf[12+1], ubuf[11+1], gbuf[11+1];
	वर्ण sbuf[FMT_SCALED_STRSIZE];
	time_t now;

	strmode(st->st_mode, mode);
	जइ (remote) {
		जइ (user == रिक्त) {
			snprintf(ubuf, परिमाण ubuf, "%u", (u_int)st->st_uid);
			user = ubuf;
		}
		जइ (group == रिक्त) {
			snprintf(gbuf, परिमाण gbuf, "%u", (u_int)st->st_gid);
			group = gbuf;
		}
		strlcpy(lc, "?", परिमाण(lc));
	} अण्णहा {
		user = user_from_uid(st->st_uid, 0);
		group = group_from_gid(st->st_gid, 0);
		snprintf(lc, परिमाण(lc), "%u", (u_int)st->st_nlink);
	}
	जइ (ltime != रिक्त) {
		now = time(रिक्त);
		जइ (now - (365*24*60*60)/2 < st->st_mtime &&
		    now >= st->st_mtime)
			sz = strftime(tbuf, परिमाण tbuf, "%b %e %H:%M", ltime);
		अण्णहा
			sz = strftime(tbuf, परिमाण tbuf, "%b %e  %Y", ltime);
	}
	जइ (sz == 0)
		tbuf[0] = '\0';
	ulen = MAXIMUM(strlen(user), 8);
	glen = MAXIMUM(strlen(group), 8);
	जइ (si_units) {
		fmt_scaled((long long)st->st_size, sbuf);
		snprintf(buf, परिमाण buf, "%s %3s %-*s %-*s %8s %s %s",
		    mode, lc, ulen, user, glen, group,
		    sbuf, tbuf, name);
	} अण्णहा {
		snprintf(buf, परिमाण buf, "%s %3s %-*s %-*s %8llu %s %s",
		    mode, lc, ulen, user, glen, group,
		    (unsigned long long)st->st_size, tbuf, name);
	}
	प्रत्यागम xstrdup(buf);
}
