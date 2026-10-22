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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଯଦି !defined(HAVE_GETCWD)

#ଅନ୍ତର୍ଭାଵ <sys/stat.h>
#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <dirent.h>
#ଅନ୍ତର୍ଭାଵ <sys/dir.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ "includes.h"

#define	ISDOT(dp) \
	(dp->d_name[0] == '.' && (dp->d_name[1] == '\0' || \
	    (dp->d_name[1] == '.' && dp->d_name[2] == '\0')))

ଅକ୍ଷର *
getcwd(ଅକ୍ଷର *pt, size_t size)
{
	ସଂରଚନା dirent *dp;
	DIR *dir = ଖାଲି;
	dev_t dev;
	ino_t ino;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା first;
	ଅକ୍ଷର *bpt, *bup;
	ସଂରଚନା stat s;
	dev_t ମୂଳ_dev;
	ino_t ମୂଳ_ino;
	size_t ptsize, upsize;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା save_errno;
	ଅକ୍ଷର *ept, *eup, *up;

	/*
	 * If no buffer specified by the user, allocate one as necessary.
	 * If a buffer is specified, the size has to be non-zero.  The path
	 * is built from the end of the buffer backwards.
	 */
	ଯଦି (pt) {
		ptsize = 0;
		ଯଦି (size == 0) {
			errno = EINVAL;
			ଫେରନ୍ତୁ (ଖାଲି);
		} ଅନ୍ୟଥା ଯଦି (size == 1) {
			errno = ERANGE;
			ଫେରନ୍ତୁ (ଖାଲି);
		}
		ept = pt + size;
	} ଅନ୍ୟଥା {
		ଯଦି ((pt = malloc(ptsize = MAXPATHLEN)) == ଖାଲି)
			ଫେରନ୍ତୁ (ଖାଲି);
		ept = pt + ptsize;
	}
	bpt = ept - 1;
	*bpt = '\0';

	/*
	 * Allocate bytes for the string of "../"'s.
	 * Should always be enough (it's 340 levels).  If it's not, allocate
	 * as necessary.  Special * case the first stat, it's ".", not "..".
	 */
	ଯଦି ((up = malloc(upsize = MAXPATHLEN)) == ଖାଲି)
		ଯାଅ err;
	eup = up + upsize;
	bup = up;
	up[0] = '.';
	up[1] = '\0';

	/* Save root values, so know when to stop. */
	ଯଦି (stat("/", &s))
		ଯାଅ err;
	ମୂଳ_dev = s.st_dev;
	ମୂଳ_ino = s.st_ino;

	errno = 0;			/* XXX readdir has no error return. */

	ପାଇଁ (first = 1;; first = 0) {
		/* Stat the current level. */
		ଯଦି (lstat(up, &s))
			ଯାଅ err;

		/* Save current node values. */
		ino = s.st_ino;
		dev = s.st_dev;

		/* Check for reaching root. */
		ଯଦି (ମୂଳ_dev == dev && ମୂଳ_ino == ino) {
			*--bpt = '/';
			/*
			 * It's unclear that it's a requirement to copy the
			 * path to the beginning of the buffer, but it's always
			 * been that way and stuff would probably break.
			 */
			memmove(pt, bpt, ept - bpt);
			ମୁକ୍ତ(up);
			ଫେରନ୍ତୁ (pt);
		}

		/*
		 * Build pointer to the parent directory, allocating memory
		 * as necessary.  Max length is 3 for "../", the largest
		 * possible component name, plus a trailing NUL.
		 */
		ଯଦି (bup + 3  + MAXNAMLEN + 1 >= eup) {
			ଅକ୍ଷର *nup;

			ଯଦି ((nup = realloc(up, upsize *= 2)) == ଖାଲି)
				ଯାଅ err;
			bup = nup + (bup - up);
			up = nup;
			eup = up + upsize;
		}
		*bup++ = '.';
		*bup++ = '.';
		*bup = '\0';

		/* Open and stat parent directory. */
		ଯଦି (!(dir = opendir(up)) || fstat(dirfd(dir), &s))
			ଯାଅ err;

		/* Add trailing slash for next directory. */
		*bup++ = '/';

		/*
		 * If it's a mount point, have to stat each element because
		 * the inode number in the directory is for the entry in the
		 * parent directory, not the inode number of the mounted file.
		 */
		save_errno = 0;
		ଯଦି (s.st_dev == dev) {
			ପାଇଁ (;;) {
				ଯଦି (!(dp = readdir(dir)))
					ଯାଅ notfound;
				ଯଦି (dp->d_fileno == ino)
					ଭାଙ୍ଗ;
			}
		} ଅନ୍ୟଥା
			ପାଇଁ (;;) {
				ଯଦି (!(dp = readdir(dir)))
					ଯାଅ notfound;
				ଯଦି (ISDOT(dp))
					ଜାରି;
				memcpy(bup, dp->d_name, dp->d_namlen + 1);

				/* Save the first error for later. */
				ଯଦି (lstat(up, &s)) {
					ଯଦି (!save_errno)
						save_errno = errno;
					errno = 0;
					ଜାରି;
				}
				ଯଦି (s.st_dev == dev && s.st_ino == ino)
					ଭାଙ୍ଗ;
			}

		/*
		 * Check for length of the current name, preceding slash,
		 * leading slash.
		 */
		ଯଦି (bpt - pt < dp->d_namlen + (first ? 1 : 2)) {
			size_t len;
			ଅକ୍ଷର *npt;

			ଯଦି (!ptsize) {
				errno = ERANGE;
				ଯାଅ err;
			}
			len = ept - bpt;
			ଯଦି ((npt = realloc(pt, ptsize *= 2)) == ଖାଲି)
				ଯାଅ err;
			bpt = npt + (bpt - pt);
			pt = npt;
			ept = pt + ptsize;
			memmove(ept - len, bpt, len);
			bpt = ept - len;
		}
		ଯଦି (!first)
			*--bpt = '/';
		bpt -= dp->d_namlen;
		memcpy(bpt, dp->d_name, dp->d_namlen);
		(ଶୂନ୍ୟ)closedir(dir);

		/* Truncate any file name. */
		*bup = '\0';
	}

notfound:
	/*
	 * If readdir set errno, use it, not any saved error; otherwise,
	 * didn't find the current directory in its parent directory, set
	 * errno to ENOENT.
	 */
	ଯଦି (!errno)
		errno = save_errno ? save_errno : ENOENT;
	/* FALLTHROUGH */
err:
	save_errno = errno;

	ଯଦି (ptsize)
		ମୁକ୍ତ(pt);
	ମୁକ୍ତ(up);
	ଯଦି (dir)
		(ଶୂନ୍ୟ)closedir(dir);

	errno = save_errno;

	ଫେରନ୍ତୁ (ଖାଲି);
}

#endif /* !defined(HAVE_GETCWD) */
