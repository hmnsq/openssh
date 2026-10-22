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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/stat.h>

#అన్తర్భావ <dirent.h>
#అన్తర్భావ <glob.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <stdarg.h>

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "sftp.h"
#అన్తర్భావ "sftp-common.h"
#అన్తర్భావ "sftp-client.h"

పూర్ణాంకం sftp_glob(నిర్మాణం sftp_conn *, స్థిరరాశి అక్షరం *, పూర్ణాంకం,
    పూర్ణాంకం (*)(స్థిరరాశి అక్షరం *, పూర్ణాంకం), glob_t *);

నిర్మాణం SFTP_OPENDIR {
	SFTP_DIRENT **dir;
	పూర్ణాంకం స్థానభ్రంశం;
};

స్థిర నిర్మాణం {
	నిర్మాణం sftp_conn *conn;
} cur;

స్థిర శూన్య *
fudge_opendir(స్థిరరాశి అక్షరం *మార్గం)
{
	నిర్మాణం SFTP_OPENDIR *r;

	r = xcalloc(1, పరిమాణం(*r));

	ఒకవేళ (sftp_readdir(cur.conn, మార్గం, &r->dir)) {
		విడుదల(r);
		తిరిగి(ఖాళీ);
	}

	r->స్థానభ్రంశం = 0;

	తిరిగి((శూన్య *)r);
}

స్థిర నిర్మాణం dirent *
fudge_readdir(నిర్మాణం SFTP_OPENDIR *od)
{
	/* Solaris needs sizeof(dirent) + path length (see below) */
	స్థిర అక్షరం buf[పరిమాణం(నిర్మాణం dirent) + MAXPATHLEN];
	నిర్మాణం dirent *ret = (నిర్మాణం dirent *)buf;
#నిర్వచితమైతే __GNU_LIBRARY__
	స్థిర పూర్ణాంకం inum = 1;
#అయితే_ముగింపు /* __GNU_LIBRARY__ */

	ఒకవేళ (od->dir[od->స్థానభ్రంశం] == ఖాళీ)
		తిరిగి(ఖాళీ);

	memset(buf, 0, పరిమాణం(buf));

	/*
	 * Solaris defines dirent->d_name as a one byte array and expects
	 * you to hack around it.
	 */
#నిర్వచితమైతే BROKEN_ONE_BYTE_DIRENT_D_NAME
	strlcpy(ret->d_name, od->dir[od->స్థానభ్రంశం++]->filename, MAXPATHLEN);
#లేకపోతే
	strlcpy(ret->d_name, od->dir[od->స్థానభ్రంశం++]->filename,
	    పరిమాణం(ret->d_name));
#అయితే_ముగింపు
#నిర్వచితమైతే __GNU_LIBRARY__
	/*
	 * Idiot glibc uses extensions to struct dirent for readdir with
	 * ALTDIRFUNCs. Not that this is documented anywhere but the
	 * source... Fake an inode number to appease it.
	 */
	ret->d_ino = inum++;
	ఒకవేళ (!inum)
		inum = 1;
#అయితే_ముగింపు /* __GNU_LIBRARY__ */

	తిరిగి(ret);
}

స్థిర శూన్య
fudge_closedir(నిర్మాణం SFTP_OPENDIR *od)
{
	sftp_free_dirents(od->dir);
	విడుదల(od);
}

స్థిర పూర్ణాంకం
fudge_lstat(స్థిరరాశి అక్షరం *మార్గం, నిర్మాణం stat *st)
{
	Attrib a;

	ఒకవేళ (sftp_lstat(cur.conn, మార్గం, 1, &a) != 0)
		తిరిగి -1;

	attrib_గమ్యం_stat(&a, st);

	తిరిగి 0;
}

స్థిర పూర్ణాంకం
fudge_stat(స్థిరరాశి అక్షరం *మార్గం, నిర్మాణం stat *st)
{
	Attrib a;

	ఒకవేళ (sftp_stat(cur.conn, మార్గం, 1, &a) != 0)
		తిరిగి -1;

	attrib_గమ్యం_stat(&a, st);

	తిరిగి(0);
}

పూర్ణాంకం
sftp_glob(నిర్మాణం sftp_conn *conn, స్థిరరాశి అక్షరం *నమూనా, పూర్ణాంకం flags,
    పూర్ణాంకం (*errfunc)(స్థిరరాశి అక్షరం *, పూర్ణాంకం), glob_t *pglob)
{
	పూర్ణాంకం r;
	కొలత_t l;
	అక్షరం *s;
	నిర్మాణం stat sb;

	pglob->gl_opendir = fudge_opendir;
	pglob->gl_readdir = (నిర్మాణం dirent *(*)(శూన్య *))fudge_readdir;
	pglob->gl_closedir = (శూన్య (*)(శూన్య *))fudge_closedir;
	pglob->gl_lstat = fudge_lstat;
	pglob->gl_stat = fudge_stat;

	memset(&cur, 0, పరిమాణం(cur));
	cur.conn = conn;

	ఒకవేళ ((r = glob(నమూనా, flags | GLOB_ALTDIRFUNC, errfunc, pglob)) != 0)
		తిరిగి r;
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
	ఒకవేళ ((flags & (GLOB_NOCHECK|GLOB_MARK)) == (GLOB_NOCHECK|GLOB_MARK) &&
	    pglob->gl_matchc == 0 && pglob->gl_offs == 0 &&
	    pglob->gl_pathc == 1 && (s = pglob->gl_pathv[0]) != ఖాళీ &&
	    (l = అక్షరశ్రేణి_పొడవు(s)) > 0 && s[l-1] != '/') {
		ఒకవేళ (fudge_stat(s, &sb) == 0 && S_ISDIR(sb.st_mode)) {
			/* NOCHECK on a directory; annotate */
			ఒకవేళ ((s = realloc(s, l + 2)) != ఖాళీ) {
				జ్ఞాపకం_నకలు(s + l, "/", 2);
				pglob->gl_pathv[0] = s;
			}
		}
	}
	తిరిగి 0;
}
