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

#அந்தர்பாவ "includes.h"

#எனில் !defined(HAVE_GETCWD)

#அந்தர்பாவ <sys/stat.h>
#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <dirent.h>
#அந்தர்பாவ <sys/dir.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ "includes.h"

#define	ISDOT(dp) \
	(dp->d_name[0] == '.' && (dp->d_name[1] == '\0' || \
	    (dp->d_name[1] == '.' && dp->d_name[2] == '\0')))

எழுத்து *
getcwd(எழுத்து *pt, size_t size)
{
	கட்டமைப்பு dirent *dp;
	DIR *dir = வெற்று;
	dev_t dev;
	ino_t ino;
	முழு first;
	எழுத்து *bpt, *bup;
	கட்டமைப்பு stat s;
	dev_t வேர்_dev;
	ino_t வேர்_ino;
	size_t ptsize, upsize;
	முழு save_errno;
	எழுத்து *ept, *eup, *up;

	/*
	 * If no buffer specified by the user, allocate one as necessary.
	 * If a buffer is specified, the size has to be non-zero.  The path
	 * is built from the end of the buffer backwards.
	 */
	எனில் (pt) {
		ptsize = 0;
		எனில் (size == 0) {
			errno = EINVAL;
			திரும்பு (வெற்று);
		} இல்லையெனில் எனில் (size == 1) {
			errno = ERANGE;
			திரும்பு (வெற்று);
		}
		ept = pt + size;
	} இல்லையெனில் {
		எனில் ((pt = malloc(ptsize = MAXPATHLEN)) == வெற்று)
			திரும்பு (வெற்று);
		ept = pt + ptsize;
	}
	bpt = ept - 1;
	*bpt = '\0';

	/*
	 * Allocate bytes for the string of "../"'s.
	 * Should always be enough (it's 340 levels).  If it's not, allocate
	 * as necessary.  Special * case the first stat, it's ".", not "..".
	 */
	எனில் ((up = malloc(upsize = MAXPATHLEN)) == வெற்று)
		செல் err;
	eup = up + upsize;
	bup = up;
	up[0] = '.';
	up[1] = '\0';

	/* Save root values, so know when to stop. */
	எனில் (stat("/", &s))
		செல் err;
	வேர்_dev = s.st_dev;
	வேர்_ino = s.st_ino;

	errno = 0;			/* XXX readdir has no error return. */

	க்கு (first = 1;; first = 0) {
		/* Stat the current level. */
		எனில் (lstat(up, &s))
			செல் err;

		/* Save current node values. */
		ino = s.st_ino;
		dev = s.st_dev;

		/* Check for reaching root. */
		எனில் (வேர்_dev == dev && வேர்_ino == ino) {
			*--bpt = '/';
			/*
			 * It's unclear that it's a requirement to copy the
			 * path to the beginning of the buffer, but it's always
			 * been that way and stuff would probably break.
			 */
			memmove(pt, bpt, ept - bpt);
			விடுவி(up);
			திரும்பு (pt);
		}

		/*
		 * Build pointer to the parent directory, allocating memory
		 * as necessary.  Max length is 3 for "../", the largest
		 * possible component name, plus a trailing NUL.
		 */
		எனில் (bup + 3  + MAXNAMLEN + 1 >= eup) {
			எழுத்து *nup;

			எனில் ((nup = realloc(up, upsize *= 2)) == வெற்று)
				செல் err;
			bup = nup + (bup - up);
			up = nup;
			eup = up + upsize;
		}
		*bup++ = '.';
		*bup++ = '.';
		*bup = '\0';

		/* Open and stat parent directory. */
		எனில் (!(dir = opendir(up)) || fstat(dirfd(dir), &s))
			செல் err;

		/* Add trailing slash for next directory. */
		*bup++ = '/';

		/*
		 * If it's a mount point, have to stat each element because
		 * the inode number in the directory is for the entry in the
		 * parent directory, not the inode number of the mounted file.
		 */
		save_errno = 0;
		எனில் (s.st_dev == dev) {
			க்கு (;;) {
				எனில் (!(dp = readdir(dir)))
					செல் notfound;
				எனில் (dp->d_fileno == ino)
					நிறுத்து;
			}
		} இல்லையெனில்
			க்கு (;;) {
				எனில் (!(dp = readdir(dir)))
					செல் notfound;
				எனில் (ISDOT(dp))
					தொடர்;
				memcpy(bup, dp->d_name, dp->d_namlen + 1);

				/* Save the first error for later. */
				எனில் (lstat(up, &s)) {
					எனில் (!save_errno)
						save_errno = errno;
					errno = 0;
					தொடர்;
				}
				எனில் (s.st_dev == dev && s.st_ino == ino)
					நிறுத்து;
			}

		/*
		 * Check for length of the current name, preceding slash,
		 * leading slash.
		 */
		எனில் (bpt - pt < dp->d_namlen + (first ? 1 : 2)) {
			size_t len;
			எழுத்து *npt;

			எனில் (!ptsize) {
				errno = ERANGE;
				செல் err;
			}
			len = ept - bpt;
			எனில் ((npt = realloc(pt, ptsize *= 2)) == வெற்று)
				செல் err;
			bpt = npt + (bpt - pt);
			pt = npt;
			ept = pt + ptsize;
			memmove(ept - len, bpt, len);
			bpt = ept - len;
		}
		எனில் (!first)
			*--bpt = '/';
		bpt -= dp->d_namlen;
		memcpy(bpt, dp->d_name, dp->d_namlen);
		(வெறுமை)closedir(dir);

		/* Truncate any file name. */
		*bup = '\0';
	}

notfound:
	/*
	 * If readdir set errno, use it, not any saved error; otherwise,
	 * didn't find the current directory in its parent directory, set
	 * errno to ENOENT.
	 */
	எனில் (!errno)
		errno = save_errno ? save_errno : ENOENT;
	/* FALLTHROUGH */
err:
	save_errno = errno;

	எனில் (ptsize)
		விடுவி(pt);
	விடுவி(up);
	எனில் (dir)
		(வெறுமை)closedir(dir);

	errno = save_errno;

	திரும்பு (வெற்று);
}

#endif /* !defined(HAVE_GETCWD) */
