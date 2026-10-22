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

#অন্তর্ভাব "includes.h"

#যদি !defined(HAVE_GETCWD)

#অন্তর্ভাব <sys/stat.h>
#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <dirent.h>
#অন্তর্ভাব <sys/dir.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব "includes.h"

#define	ISDOT(dp) \
	(dp->d_name[0] == '.' && (dp->d_name[1] == '\0' || \
	    (dp->d_name[1] == '.' && dp->d_name[2] == '\0')))

বর্ণ *
getcwd(বর্ণ *pt, size_t size)
{
	সংরচনা dirent *dp;
	DIR *dir = রিক্ত;
	dev_t dev;
	ino_t ino;
	পূর্ণাঙ্ক first;
	বর্ণ *bpt, *bup;
	সংরচনা stat s;
	dev_t মূল_dev;
	ino_t মূল_ino;
	size_t ptsize, upsize;
	পূর্ণাঙ্ক save_errno;
	বর্ণ *ept, *eup, *up;

	/*
	 * If no buffer specified by the user, allocate one as necessary.
	 * If a buffer is specified, the size has to be non-zero.  The path
	 * is built from the end of the buffer backwards.
	 */
	যদি (pt) {
		ptsize = 0;
		যদি (size == 0) {
			errno = EINVAL;
			প্রত্যাগম (রিক্ত);
		} অন্যথা যদি (size == 1) {
			errno = ERANGE;
			প্রত্যাগম (রিক্ত);
		}
		ept = pt + size;
	} অন্যথা {
		যদি ((pt = malloc(ptsize = MAXPATHLEN)) == রিক্ত)
			প্রত্যাগম (রিক্ত);
		ept = pt + ptsize;
	}
	bpt = ept - 1;
	*bpt = '\0';

	/*
	 * Allocate bytes for the string of "../"'s.
	 * Should always be enough (it's 340 levels).  If it's not, allocate
	 * as necessary.  Special * case the first stat, it's ".", not "..".
	 */
	যদি ((up = malloc(upsize = MAXPATHLEN)) == রিক্ত)
		গচ্ছ err;
	eup = up + upsize;
	bup = up;
	up[0] = '.';
	up[1] = '\0';

	/* Save root values, so know when to stop. */
	যদি (stat("/", &s))
		গচ্ছ err;
	মূল_dev = s.st_dev;
	মূল_ino = s.st_ino;

	errno = 0;			/* XXX readdir has no error return. */

	প্রতি (first = 1;; first = 0) {
		/* Stat the current level. */
		যদি (lstat(up, &s))
			গচ্ছ err;

		/* Save current node values. */
		ino = s.st_ino;
		dev = s.st_dev;

		/* Check for reaching root. */
		যদি (মূল_dev == dev && মূল_ino == ino) {
			*--bpt = '/';
			/*
			 * It's unclear that it's a requirement to copy the
			 * path to the beginning of the buffer, but it's always
			 * been that way and stuff would probably break.
			 */
			memmove(pt, bpt, ept - bpt);
			মুক্ত(up);
			প্রত্যাগম (pt);
		}

		/*
		 * Build pointer to the parent directory, allocating memory
		 * as necessary.  Max length is 3 for "../", the largest
		 * possible component name, plus a trailing NUL.
		 */
		যদি (bup + 3  + MAXNAMLEN + 1 >= eup) {
			বর্ণ *nup;

			যদি ((nup = realloc(up, upsize *= 2)) == রিক্ত)
				গচ্ছ err;
			bup = nup + (bup - up);
			up = nup;
			eup = up + upsize;
		}
		*bup++ = '.';
		*bup++ = '.';
		*bup = '\0';

		/* Open and stat parent directory. */
		যদি (!(dir = opendir(up)) || fstat(dirfd(dir), &s))
			গচ্ছ err;

		/* Add trailing slash for next directory. */
		*bup++ = '/';

		/*
		 * If it's a mount point, have to stat each element because
		 * the inode number in the directory is for the entry in the
		 * parent directory, not the inode number of the mounted file.
		 */
		save_errno = 0;
		যদি (s.st_dev == dev) {
			প্রতি (;;) {
				যদি (!(dp = readdir(dir)))
					গচ্ছ notfound;
				যদি (dp->d_fileno == ino)
					ভঙ্গ;
			}
		} অন্যথা
			প্রতি (;;) {
				যদি (!(dp = readdir(dir)))
					গচ্ছ notfound;
				যদি (ISDOT(dp))
					অনুবর্ত;
				memcpy(bup, dp->d_name, dp->d_namlen + 1);

				/* Save the first error for later. */
				যদি (lstat(up, &s)) {
					যদি (!save_errno)
						save_errno = errno;
					errno = 0;
					অনুবর্ত;
				}
				যদি (s.st_dev == dev && s.st_ino == ino)
					ভঙ্গ;
			}

		/*
		 * Check for length of the current name, preceding slash,
		 * leading slash.
		 */
		যদি (bpt - pt < dp->d_namlen + (first ? 1 : 2)) {
			size_t len;
			বর্ণ *npt;

			যদি (!ptsize) {
				errno = ERANGE;
				গচ্ছ err;
			}
			len = ept - bpt;
			যদি ((npt = realloc(pt, ptsize *= 2)) == রিক্ত)
				গচ্ছ err;
			bpt = npt + (bpt - pt);
			pt = npt;
			ept = pt + ptsize;
			memmove(ept - len, bpt, len);
			bpt = ept - len;
		}
		যদি (!first)
			*--bpt = '/';
		bpt -= dp->d_namlen;
		memcpy(bpt, dp->d_name, dp->d_namlen);
		(শূন্য)closedir(dir);

		/* Truncate any file name. */
		*bup = '\0';
	}

notfound:
	/*
	 * If readdir set errno, use it, not any saved error; otherwise,
	 * didn't find the current directory in its parent directory, set
	 * errno to ENOENT.
	 */
	যদি (!errno)
		errno = save_errno ? save_errno : ENOENT;
	/* FALLTHROUGH */
err:
	save_errno = errno;

	যদি (ptsize)
		মুক্ত(pt);
	মুক্ত(up);
	যদি (dir)
		(শূন্য)closedir(dir);

	errno = save_errno;

	প্রত্যাগম (রিক্ত);
}

#endif /* !defined(HAVE_GETCWD) */
