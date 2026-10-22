/* $OpenBSD: sftp-glob.c,v 1.33 2023/09/10 23:12:32 djm Exp $ */
/*
 * Copyright (c) 2001-2004 Damien Miller <djm@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/stat.h>

#अन्तर्भाव <dirent.h>
#अन्तर्भाव <glob.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdarg.h>

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "sftp.h"
#अन्तर्भाव "sftp-common.h"
#अन्तर्भाव "sftp-client.h"

पूर्णाङ्क sftp_glob(संरचना sftp_conn *, ध्रुव वर्ण *, पूर्णाङ्क,
    पूर्णाङ्क (*)(ध्रुव वर्ण *, पूर्णाङ्क), glob_t *);

संरचना SFTP_OPENDIR {
	SFTP_DIRENT **dir;
	पूर्णाङ्क offset;
};

स्थिर संरचना {
	संरचना sftp_conn *conn;
} cur;

स्थिर शून्य *
fudge_opendir(ध्रुव वर्ण *path)
{
	संरचना SFTP_OPENDIR *r;

	r = xcalloc(1, परिमाण(*r));

	जइ (sftp_readdir(cur.conn, path, &r->dir)) {
		मुक्त(r);
		प्रत्यागम(रिक्त);
	}

	r->offset = 0;

	प्रत्यागम((शून्य *)r);
}

स्थिर संरचना dirent *
fudge_readdir(संरचना SFTP_OPENDIR *od)
{
	/* Solaris needs sizeof(dirent) + path length (see below) */
	स्थिर वर्ण buf[परिमाण(संरचना dirent) + MAXPATHLEN];
	संरचना dirent *ret = (संरचना dirent *)buf;
#ifdef __GNU_LIBRARY__
	स्थिर पूर्णाङ्क inum = 1;
#endif /* __GNU_LIBRARY__ */

	जइ (od->dir[od->offset] == रिक्त)
		प्रत्यागम(रिक्त);

	memset(buf, 0, परिमाण(buf));

	/*
	 * Solaris defines dirent->d_name as a one byte array and expects
	 * you to hack around it.
	 */
#ifdef BROKEN_ONE_BYTE_DIRENT_D_NAME
	strlcpy(ret->d_name, od->dir[od->offset++]->filename, MAXPATHLEN);
#अण्णहा
	strlcpy(ret->d_name, od->dir[od->offset++]->filename,
	    परिमाण(ret->d_name));
#endif
#ifdef __GNU_LIBRARY__
	/*
	 * Idiot glibc uses extensions to struct dirent for readdir with
	 * ALTDIRFUNCs. Not that this is documented anywhere but the
	 * source... Fake an inode number to appease it.
	 */
	ret->d_ino = inum++;
	जइ (!inum)
		inum = 1;
#endif /* __GNU_LIBRARY__ */

	प्रत्यागम(ret);
}

स्थिर शून्य
fudge_closedir(संरचना SFTP_OPENDIR *od)
{
	sftp_free_dirents(od->dir);
	मुक्त(od);
}

स्थिर पूर्णाङ्क
fudge_lstat(ध्रुव वर्ण *path, संरचना stat *st)
{
	Attrib a;

	जइ (sftp_lstat(cur.conn, path, 1, &a) != 0)
		प्रत्यागम -1;

	attrib_to_stat(&a, st);

	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
fudge_stat(ध्रुव वर्ण *path, संरचना stat *st)
{
	Attrib a;

	जइ (sftp_stat(cur.conn, path, 1, &a) != 0)
		प्रत्यागम -1;

	attrib_to_stat(&a, st);

	प्रत्यागम(0);
}

पूर्णाङ्क
sftp_glob(संरचना sftp_conn *conn, ध्रुव वर्ण *pattern, पूर्णाङ्क flags,
    पूर्णाङ्क (*errfunc)(ध्रुव वर्ण *, पूर्णाङ्क), glob_t *pglob)
{
	पूर्णाङ्क r;
	size_t l;
	वर्ण *s;
	संरचना stat sb;

	pglob->gl_opendir = fudge_opendir;
	pglob->gl_readdir = (संरचना dirent *(*)(शून्य *))fudge_readdir;
	pglob->gl_closedir = (शून्य (*)(शून्य *))fudge_closedir;
	pglob->gl_lstat = fudge_lstat;
	pglob->gl_stat = fudge_stat;

	memset(&cur, 0, परिमाण(cur));
	cur.conn = conn;

	जइ ((r = glob(pattern, flags | GLOB_ALTDIRFUNC, errfunc, pglob)) != 0)
		प्रत्यागम r;
	/*
	 * When both GLOB_NOCHECK and GLOB_MARK are active, a single gl_pathv
	 * entry has been returned and that entry has not already been marked,
	 * then check whether it needs a '/' appended as a directory mark.
	 *
	 * This ensures that a NOCHECK result is annotated as a directory.
	 * The glob(3) spec doesn't promise to mark NOCHECK entries, but doing
	 * it simplifies our callers (sftp/scp) considerably.
	 *
	 * XXX doesn't try to handle gl_offs.
	 */
	जइ ((flags & (GLOB_NOCHECK|GLOB_MARK)) == (GLOB_NOCHECK|GLOB_MARK) &&
	    pglob->gl_matchc == 0 && pglob->gl_offs == 0 &&
	    pglob->gl_pathc == 1 && (s = pglob->gl_pathv[0]) != रिक्त &&
	    (l = strlen(s)) > 0 && s[l-1] != '/') {
		जइ (fudge_stat(s, &sb) == 0 && S_ISDIR(sb.st_mode)) {
			/* NOCHECK on a directory; annotate */
			जइ ((s = realloc(s, l + 2)) != रिक्त) {
				memcpy(s + l, "/", 2);
				pglob->gl_pathv[0] = s;
			}
		}
	}
	प्रत्यागम 0;
}
