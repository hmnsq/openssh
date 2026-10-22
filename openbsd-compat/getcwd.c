/*	$OpenBSD: getcwd.c,v 1.14 2005/08/08 08:05:34 espie Exp */
/*
 * Copyright (c) 1989, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* OPENBSD ORIGINAL: lib/libc/gen/getcwd.c */

#అన్తర్భావ "includes.h"

#ఒకవేళ !defined(HAVE_GETCWD)

#అన్తర్భావ <sys/stat.h>
#అన్తర్భావ <errno.h>
#అన్తర్భావ <dirent.h>
#అన్తర్భావ <sys/dir.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ "includes.h"

#నిర్వచించు	ISDOT(dp) \
	(dp->d_name[0] == '.' && (dp->d_name[1] == '\0' || \
	    (dp->d_name[1] == '.' && dp->d_name[2] == '\0')))

అక్షరం *
getcwd(అక్షరం *pt, కొలత_t కొలత)
{
	నిర్మాణం dirent *dp;
	DIR *dir = ఖాళీ;
	dev_t dev;
	ino_t ino;
	పూర్ణాంకం మొదటి;
	అక్షరం *bpt, *bup;
	నిర్మాణం stat s;
	dev_t మూలం_dev;
	ino_t మూలం_ino;
	కొలత_t ptsize, upsize;
	పూర్ణాంకం save_errno;
	అక్షరం *ept, *eup, *పైకి;

	/*
	 * If no buffer specified by the user, allocate one as necessary.
	 * If a buffer is specified, the size has to be non-zero.  The path
	 * is built from the end of the buffer backwards.
	 */
	ఒకవేళ (pt) {
		ptsize = 0;
		ఒకవేళ (కొలత == 0) {
			errno = EINVAL;
			తిరిగి (ఖాళీ);
		} లేకపోతే ఒకవేళ (కొలత == 1) {
			errno = ERANGE;
			తిరిగి (ఖాళీ);
		}
		ept = pt + కొలత;
	} లేకపోతే {
		ఒకవేళ ((pt = జ్ఞాపకం_ఇవ్వు(ptsize = MAXPATHLEN)) == ఖాళీ)
			తిరిగి (ఖాళీ);
		ept = pt + ptsize;
	}
	bpt = ept - 1;
	*bpt = '\0';

	/*
	 * Allocate bytes for the string of "../"'s.
	 * Should always be enough (it's 340 levels).  If it's not, allocate
	 * as necessary.  Special * case the first stat, it's ".", not "..".
	 */
	ఒకవేళ ((పైకి = జ్ఞాపకం_ఇవ్వు(upsize = MAXPATHLEN)) == ఖాళీ)
		వెళ్ళు err;
	eup = పైకి + upsize;
	bup = పైకి;
	పైకి[0] = '.';
	పైకి[1] = '\0';

	/* Save root values, so know when to stop. */
	ఒకవేళ (stat("/", &s))
		వెళ్ళు err;
	మూలం_dev = s.st_dev;
	మూలం_ino = s.st_ino;

	errno = 0;			/* XXX readdir has no error return. */

	కొరకు (మొదటి = 1;; మొదటి = 0) {
		/* Stat the current level. */
		ఒకవేళ (lstat(పైకి, &s))
			వెళ్ళు err;

		/* Save current node values. */
		ino = s.st_ino;
		dev = s.st_dev;

		/* Check for reaching root. */
		ఒకవేళ (మూలం_dev == dev && మూలం_ino == ino) {
			*--bpt = '/';
			/*
			 * It's unclear that it's a requirement to copy the
			 * path to the beginning of the buffer, but it's always
			 * been that way and stuff would probably break.
			 */
			memmove(pt, bpt, ept - bpt);
			విడుదల(పైకి);
			తిరిగి (pt);
		}

		/*
		 * Build pointer to the parent directory, allocating memory
		 * as necessary.  Max length is 3 for "../", the largest
		 * possible component name, plus a trailing NUL.
		 */
		ఒకవేళ (bup + 3  + MAXNAMLEN + 1 >= eup) {
			అక్షరం *nup;

			ఒకవేళ ((nup = realloc(పైకి, upsize *= 2)) == ఖాళీ)
				వెళ్ళు err;
			bup = nup + (bup - పైకి);
			పైకి = nup;
			eup = పైకి + upsize;
		}
		*bup++ = '.';
		*bup++ = '.';
		*bup = '\0';

		/* Open and stat parent directory. */
		ఒకవేళ (!(dir = opendir(పైకి)) || fstat(dirfd(dir), &s))
			వెళ్ళు err;

		/* Add trailing slash for next directory. */
		*bup++ = '/';

		/*
		 * If it's a mount point, have to stat each element because
		 * the inode number in the directory is for the entry in the
		 * parent directory, not the inode number of the mounted file.
		 */
		save_errno = 0;
		ఒకవేళ (s.st_dev == dev) {
			కొరకు (;;) {
				ఒకవేళ (!(dp = readdir(dir)))
					వెళ్ళు notfound;
				ఒకవేళ (dp->d_fileno == ino)
					ఆపు;
			}
		} లేకపోతే
			కొరకు (;;) {
				ఒకవేళ (!(dp = readdir(dir)))
					వెళ్ళు notfound;
				ఒకవేళ (ISDOT(dp))
					కొనసాగు;
				జ్ఞాపకం_నకలు(bup, dp->d_name, dp->d_namlen + 1);

				/* Save the first error for later. */
				ఒకవేళ (lstat(పైకి, &s)) {
					ఒకవేళ (!save_errno)
						save_errno = errno;
					errno = 0;
					కొనసాగు;
				}
				ఒకవేళ (s.st_dev == dev && s.st_ino == ino)
					ఆపు;
			}

		/*
		 * Check for length of the current name, preceding slash,
		 * leading slash.
		 */
		ఒకవేళ (bpt - pt < dp->d_namlen + (మొదటి ? 1 : 2)) {
			కొలత_t len;
			అక్షరం *npt;

			ఒకవేళ (!ptsize) {
				errno = ERANGE;
				వెళ్ళు err;
			}
			len = ept - bpt;
			ఒకవేళ ((npt = realloc(pt, ptsize *= 2)) == ఖాళీ)
				వెళ్ళు err;
			bpt = npt + (bpt - pt);
			pt = npt;
			ept = pt + ptsize;
			memmove(ept - len, bpt, len);
			bpt = ept - len;
		}
		ఒకవేళ (!మొదటి)
			*--bpt = '/';
		bpt -= dp->d_namlen;
		జ్ఞాపకం_నకలు(bpt, dp->d_name, dp->d_namlen);
		(శూన్య)closedir(dir);

		/* Truncate any file name. */
		*bup = '\0';
	}

notfound:
	/*
	 * If readdir set errno, use it, not any saved error; otherwise,
	 * didn't find the current directory in its parent directory, set
	 * errno to ENOENT.
	 */
	ఒకవేళ (!errno)
		errno = save_errno ? save_errno : ENOENT;
	/* FALLTHROUGH */
err:
	save_errno = errno;

	ఒకవేళ (ptsize)
		విడుదల(pt);
	విడుదల(పైకి);
	ఒకవేళ (dir)
		(శూన్య)closedir(dir);

	errno = save_errno;

	తిరిగి (ఖాళీ);
}

#అయితే_ముగింపు /* !defined(HAVE_GETCWD) */
