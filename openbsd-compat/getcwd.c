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

#અન્તર્ભાવ "includes.h"

#જો !defined(HAVE_GETCWD)

#અન્તર્ભાવ <sys/stat.h>
#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <dirent.h>
#અન્તર્ભાવ <sys/dir.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ "includes.h"

#define	ISDOT(dp) \
	(dp->d_name[0] == '.' && (dp->d_name[1] == '\0' || \
	    (dp->d_name[1] == '.' && dp->d_name[2] == '\0')))

અક્ષર *
getcwd(અક્ષર *pt, size_t size)
{
	સંરચના dirent *dp;
	DIR *dir = ખાલી;
	dev_t dev;
	ino_t ino;
	પૂર્ણાંક first;
	અક્ષર *bpt, *bup;
	સંરચના stat s;
	dev_t મૂળ_dev;
	ino_t મૂળ_ino;
	size_t ptsize, upsize;
	પૂર્ણાંક save_errno;
	અક્ષર *ept, *eup, *up;

	/*
	 * If no buffer specified by the user, allocate one as necessary.
	 * If a buffer is specified, the size has to be non-zero.  The path
	 * is built from the end of the buffer backwards.
	 */
	જો (pt) {
		ptsize = 0;
		જો (size == 0) {
			errno = EINVAL;
			પાછા (ખાલી);
		} નહીંતર જો (size == 1) {
			errno = ERANGE;
			પાછા (ખાલી);
		}
		ept = pt + size;
	} નહીંતર {
		જો ((pt = malloc(ptsize = MAXPATHLEN)) == ખાલી)
			પાછા (ખાલી);
		ept = pt + ptsize;
	}
	bpt = ept - 1;
	*bpt = '\0';

	/*
	 * Allocate bytes for the string of "../"'s.
	 * Should always be enough (it's 340 levels).  If it's not, allocate
	 * as necessary.  Special * case the first stat, it's ".", not "..".
	 */
	જો ((up = malloc(upsize = MAXPATHLEN)) == ખાલી)
		જાઓ err;
	eup = up + upsize;
	bup = up;
	up[0] = '.';
	up[1] = '\0';

	/* Save root values, so know when to stop. */
	જો (stat("/", &s))
		જાઓ err;
	મૂળ_dev = s.st_dev;
	મૂળ_ino = s.st_ino;

	errno = 0;			/* XXX readdir has no error return. */

	માટે (first = 1;; first = 0) {
		/* Stat the current level. */
		જો (lstat(up, &s))
			જાઓ err;

		/* Save current node values. */
		ino = s.st_ino;
		dev = s.st_dev;

		/* Check for reaching root. */
		જો (મૂળ_dev == dev && મૂળ_ino == ino) {
			*--bpt = '/';
			/*
			 * It's unclear that it's a requirement to copy the
			 * path to the beginning of the buffer, but it's always
			 * been that way and stuff would probably break.
			 */
			memmove(pt, bpt, ept - bpt);
			મુક્ત(up);
			પાછા (pt);
		}

		/*
		 * Build pointer to the parent directory, allocating memory
		 * as necessary.  Max length is 3 for "../", the largest
		 * possible component name, plus a trailing NUL.
		 */
		જો (bup + 3  + MAXNAMLEN + 1 >= eup) {
			અક્ષર *nup;

			જો ((nup = realloc(up, upsize *= 2)) == ખાલી)
				જાઓ err;
			bup = nup + (bup - up);
			up = nup;
			eup = up + upsize;
		}
		*bup++ = '.';
		*bup++ = '.';
		*bup = '\0';

		/* Open and stat parent directory. */
		જો (!(dir = opendir(up)) || fstat(dirfd(dir), &s))
			જાઓ err;

		/* Add trailing slash for next directory. */
		*bup++ = '/';

		/*
		 * If it's a mount point, have to stat each element because
		 * the inode number in the directory is for the entry in the
		 * parent directory, not the inode number of the mounted file.
		 */
		save_errno = 0;
		જો (s.st_dev == dev) {
			માટે (;;) {
				જો (!(dp = readdir(dir)))
					જાઓ notfound;
				જો (dp->d_fileno == ino)
					તોડો;
			}
		} નહીંતર
			માટે (;;) {
				જો (!(dp = readdir(dir)))
					જાઓ notfound;
				જો (ISDOT(dp))
					ચાલુ;
				memcpy(bup, dp->d_name, dp->d_namlen + 1);

				/* Save the first error for later. */
				જો (lstat(up, &s)) {
					જો (!save_errno)
						save_errno = errno;
					errno = 0;
					ચાલુ;
				}
				જો (s.st_dev == dev && s.st_ino == ino)
					તોડો;
			}

		/*
		 * Check for length of the current name, preceding slash,
		 * leading slash.
		 */
		જો (bpt - pt < dp->d_namlen + (first ? 1 : 2)) {
			size_t len;
			અક્ષર *npt;

			જો (!ptsize) {
				errno = ERANGE;
				જાઓ err;
			}
			len = ept - bpt;
			જો ((npt = realloc(pt, ptsize *= 2)) == ખાલી)
				જાઓ err;
			bpt = npt + (bpt - pt);
			pt = npt;
			ept = pt + ptsize;
			memmove(ept - len, bpt, len);
			bpt = ept - len;
		}
		જો (!first)
			*--bpt = '/';
		bpt -= dp->d_namlen;
		memcpy(bpt, dp->d_name, dp->d_namlen);
		(શૂન્ય)closedir(dir);

		/* Truncate any file name. */
		*bup = '\0';
	}

notfound:
	/*
	 * If readdir set errno, use it, not any saved error; otherwise,
	 * didn't find the current directory in its parent directory, set
	 * errno to ENOENT.
	 */
	જો (!errno)
		errno = save_errno ? save_errno : ENOENT;
	/* FALLTHROUGH */
err:
	save_errno = errno;

	જો (ptsize)
		મુક્ત(pt);
	મુક્ત(up);
	જો (dir)
		(શૂન્ય)closedir(dir);

	errno = save_errno;

	પાછા (ખાલી);
}

#endif /* !defined(HAVE_GETCWD) */
