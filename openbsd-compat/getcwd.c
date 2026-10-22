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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ !defined(HAVE_GETCWD)

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/stat.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <dirent.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/dir.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	ISDOT(dp) \
	(dp->d_name[0] == '.' && (dp->d_name[1] == '\0' || \
	    (dp->d_name[1] == '.' && dp->d_name[2] == '\0')))

ਅੱਖਰ *
getcwd(ਅੱਖਰ *pt, ਮਾਪ_t ਮਾਪ)
{
	ਬਣਤਰ dirent *dp;
	DIR *dir = ਨਿਰਾ;
	dev_t dev;
	ino_t ino;
	ਪੂਰਨ ਪਹਿਲਾ;
	ਅੱਖਰ *bpt, *bup;
	ਬਣਤਰ stat s;
	dev_t ਜੜ੍ਹ_dev;
	ino_t ਜੜ੍ਹ_ino;
	ਮਾਪ_t ptsize, upsize;
	ਪੂਰਨ save_errno;
	ਅੱਖਰ *ept, *eup, *ਉੱਪਰ;

	/*
	 * If no buffer specified by the user, allocate one as necessary.
	 * If a buffer is specified, the size has to be non-zero.  The path
	 * is built from the end of the buffer backwards.
	 */
	ਜੇ (pt) {
		ptsize = 0;
		ਜੇ (ਮਾਪ == 0) {
			errno = EINVAL;
			ਵਾਪਸ (ਨਿਰਾ);
		} ਨਹੀਂਤਾਂ ਜੇ (ਮਾਪ == 1) {
			errno = ERANGE;
			ਵਾਪਸ (ਨਿਰਾ);
		}
		ept = pt + ਮਾਪ;
	} ਨਹੀਂਤਾਂ {
		ਜੇ ((pt = ਸਮ੍ਰਿਤੀ_ਦਿਓ(ptsize = MAXPATHLEN)) == ਨਿਰਾ)
			ਵਾਪਸ (ਨਿਰਾ);
		ept = pt + ptsize;
	}
	bpt = ept - 1;
	*bpt = '\0';

	/*
	 * Allocate bytes for the string of "../"'s.
	 * Should always be enough (it's 340 levels).  If it's not, allocate
	 * as necessary.  Special * case the first stat, it's ".", not "..".
	 */
	ਜੇ ((ਉੱਪਰ = ਸਮ੍ਰਿਤੀ_ਦਿਓ(upsize = MAXPATHLEN)) == ਨਿਰਾ)
		ਜਾਓ err;
	eup = ਉੱਪਰ + upsize;
	bup = ਉੱਪਰ;
	ਉੱਪਰ[0] = '.';
	ਉੱਪਰ[1] = '\0';

	/* Save root values, so know when to stop. */
	ਜੇ (stat("/", &s))
		ਜਾਓ err;
	ਜੜ੍ਹ_dev = s.st_dev;
	ਜੜ੍ਹ_ino = s.st_ino;

	errno = 0;			/* XXX readdir has no error return. */

	ਲਈ (ਪਹਿਲਾ = 1;; ਪਹਿਲਾ = 0) {
		/* Stat the current level. */
		ਜੇ (lstat(ਉੱਪਰ, &s))
			ਜਾਓ err;

		/* Save current node values. */
		ino = s.st_ino;
		dev = s.st_dev;

		/* Check for reaching root. */
		ਜੇ (ਜੜ੍ਹ_dev == dev && ਜੜ੍ਹ_ino == ino) {
			*--bpt = '/';
			/*
			 * It's unclear that it's a requirement to copy the
			 * path to the beginning of the buffer, but it's always
			 * been that way and stuff would probably break.
			 */
			memmove(pt, bpt, ept - bpt);
			ਮੁਕਤ(ਉੱਪਰ);
			ਵਾਪਸ (pt);
		}

		/*
		 * Build pointer to the parent directory, allocating memory
		 * as necessary.  Max length is 3 for "../", the largest
		 * possible component name, plus a trailing NUL.
		 */
		ਜੇ (bup + 3  + MAXNAMLEN + 1 >= eup) {
			ਅੱਖਰ *nup;

			ਜੇ ((nup = realloc(ਉੱਪਰ, upsize *= 2)) == ਨਿਰਾ)
				ਜਾਓ err;
			bup = nup + (bup - ਉੱਪਰ);
			ਉੱਪਰ = nup;
			eup = ਉੱਪਰ + upsize;
		}
		*bup++ = '.';
		*bup++ = '.';
		*bup = '\0';

		/* Open and stat parent directory. */
		ਜੇ (!(dir = opendir(ਉੱਪਰ)) || fstat(dirfd(dir), &s))
			ਜਾਓ err;

		/* Add trailing slash for next directory. */
		*bup++ = '/';

		/*
		 * If it's a mount point, have to stat each element because
		 * the inode number in the directory is for the entry in the
		 * parent directory, not the inode number of the mounted file.
		 */
		save_errno = 0;
		ਜੇ (s.st_dev == dev) {
			ਲਈ (;;) {
				ਜੇ (!(dp = readdir(dir)))
					ਜਾਓ notfound;
				ਜੇ (dp->d_fileno == ino)
					ਰੋਕੋ;
			}
		} ਨਹੀਂਤਾਂ
			ਲਈ (;;) {
				ਜੇ (!(dp = readdir(dir)))
					ਜਾਓ notfound;
				ਜੇ (ISDOT(dp))
					ਜਾਰੀ;
				ਸਮ੍ਰਿਤੀ_ਨਕਲ(bup, dp->d_name, dp->d_namlen + 1);

				/* Save the first error for later. */
				ਜੇ (lstat(ਉੱਪਰ, &s)) {
					ਜੇ (!save_errno)
						save_errno = errno;
					errno = 0;
					ਜਾਰੀ;
				}
				ਜੇ (s.st_dev == dev && s.st_ino == ino)
					ਰੋਕੋ;
			}

		/*
		 * Check for length of the current name, preceding slash,
		 * leading slash.
		 */
		ਜੇ (bpt - pt < dp->d_namlen + (ਪਹਿਲਾ ? 1 : 2)) {
			ਮਾਪ_t len;
			ਅੱਖਰ *npt;

			ਜੇ (!ptsize) {
				errno = ERANGE;
				ਜਾਓ err;
			}
			len = ept - bpt;
			ਜੇ ((npt = realloc(pt, ptsize *= 2)) == ਨਿਰਾ)
				ਜਾਓ err;
			bpt = npt + (bpt - pt);
			pt = npt;
			ept = pt + ptsize;
			memmove(ept - len, bpt, len);
			bpt = ept - len;
		}
		ਜੇ (!ਪਹਿਲਾ)
			*--bpt = '/';
		bpt -= dp->d_namlen;
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(bpt, dp->d_name, dp->d_namlen);
		(ਖਾਲੀ)closedir(dir);

		/* Truncate any file name. */
		*bup = '\0';
	}

notfound:
	/*
	 * If readdir set errno, use it, not any saved error; otherwise,
	 * didn't find the current directory in its parent directory, set
	 * errno to ENOENT.
	 */
	ਜੇ (!errno)
		errno = save_errno ? save_errno : ENOENT;
	/* FALLTHROUGH */
err:
	save_errno = errno;

	ਜੇ (ptsize)
		ਮੁਕਤ(pt);
	ਮੁਕਤ(ਉੱਪਰ);
	ਜੇ (dir)
		(ਖਾਲੀ)closedir(dir);

	errno = save_errno;

	ਵਾਪਸ (ਨਿਰਾ);
}

#ਜੇ_ਅੰਤ /* !defined(HAVE_GETCWD) */
