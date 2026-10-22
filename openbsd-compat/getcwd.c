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

#ضمن "includes.h"

#إذا !defined(HAVE_GETCWD)

#ضمن <sys/stat.h>
#ضمن <errno.h>
#ضمن <dirent.h>
#ضمن <sys/dir.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن "includes.h"

#تعریف_کرو	ISDOT(dp) \
	(dp->d_name[0] == '.' && (dp->d_name[1] == '\0' || \
	    (dp->d_name[1] == '.' && dp->d_name[2] == '\0')))

حرف *
getcwd(حرف *pt, ناپ_t ناپ)
{
	بنية dirent *dp;
	DIR *dir = عدم;
	dev_t dev;
	ino_t ino;
	صحيح پہلا;
	حرف *bpt, *bup;
	بنية stat s;
	dev_t جڑ_dev;
	ino_t جڑ_ino;
	ناپ_t ptsize, upsize;
	صحيح save_errno;
	حرف *ept, *eup, *اتے;

	/*
	 * If no buffer specified by the user, allocate one as necessary.
	 * If a buffer is specified, the size has to be non-zero.  The path
	 * is built from the end of the buffer backwards.
	 */
	إذا (pt) {
		ptsize = 0;
		إذا (ناپ == 0) {
			errno = EINVAL;
			أرجع (عدم);
		} وإلا إذا (ناپ == 1) {
			errno = ERANGE;
			أرجع (عدم);
		}
		ept = pt + ناپ;
	} وإلا {
		إذا ((pt = حافظہ_دیو(ptsize = MAXPATHLEN)) == عدم)
			أرجع (عدم);
		ept = pt + ptsize;
	}
	bpt = ept - 1;
	*bpt = '\0';

	/*
	 * Allocate bytes for the string of "../"'s.
	 * Should always be enough (it's 340 levels).  If it's not, allocate
	 * as necessary.  Special * case the first stat, it's ".", not "..".
	 */
	إذا ((اتے = حافظہ_دیو(upsize = MAXPATHLEN)) == عدم)
		اذهب err;
	eup = اتے + upsize;
	bup = اتے;
	اتے[0] = '.';
	اتے[1] = '\0';

	/* Save root values, so know when to stop. */
	إذا (stat("/", &s))
		اذهب err;
	جڑ_dev = s.st_dev;
	جڑ_ino = s.st_ino;

	errno = 0;			/* XXX readdir has no error return. */

	لكل (پہلا = 1;; پہلا = 0) {
		/* Stat the current level. */
		إذا (lstat(اتے, &s))
			اذهب err;

		/* Save current node values. */
		ino = s.st_ino;
		dev = s.st_dev;

		/* Check for reaching root. */
		إذا (جڑ_dev == dev && جڑ_ino == ino) {
			*--bpt = '/';
			/*
			 * It's unclear that it's a requirement to copy the
			 * path to the beginning of the buffer, but it's always
			 * been that way and stuff would probably break.
			 */
			memmove(pt, bpt, ept - bpt);
			حرر(اتے);
			أرجع (pt);
		}

		/*
		 * Build pointer to the parent directory, allocating memory
		 * as necessary.  Max length is 3 for "../", the largest
		 * possible component name, plus a trailing NUL.
		 */
		إذا (bup + 3  + MAXNAMLEN + 1 >= eup) {
			حرف *nup;

			إذا ((nup = realloc(اتے, upsize *= 2)) == عدم)
				اذهب err;
			bup = nup + (bup - اتے);
			اتے = nup;
			eup = اتے + upsize;
		}
		*bup++ = '.';
		*bup++ = '.';
		*bup = '\0';

		/* Open and stat parent directory. */
		إذا (!(dir = opendir(اتے)) || fstat(dirfd(dir), &s))
			اذهب err;

		/* Add trailing slash for next directory. */
		*bup++ = '/';

		/*
		 * If it's a mount point, have to stat each element because
		 * the inode number in the directory is for the entry in the
		 * parent directory, not the inode number of the mounted file.
		 */
		save_errno = 0;
		إذا (s.st_dev == dev) {
			لكل (;;) {
				إذا (!(dp = readdir(dir)))
					اذهب notfound;
				إذا (dp->d_fileno == ino)
					اكسر;
			}
		} وإلا
			لكل (;;) {
				إذا (!(dp = readdir(dir)))
					اذهب notfound;
				إذا (ISDOT(dp))
					استمر;
				حافظہ_نقل(bup, dp->d_name, dp->d_namlen + 1);

				/* Save the first error for later. */
				إذا (lstat(اتے, &s)) {
					إذا (!save_errno)
						save_errno = errno;
					errno = 0;
					استمر;
				}
				إذا (s.st_dev == dev && s.st_ino == ino)
					اكسر;
			}

		/*
		 * Check for length of the current name, preceding slash,
		 * leading slash.
		 */
		إذا (bpt - pt < dp->d_namlen + (پہلا ? 1 : 2)) {
			ناپ_t len;
			حرف *npt;

			إذا (!ptsize) {
				errno = ERANGE;
				اذهب err;
			}
			len = ept - bpt;
			إذا ((npt = realloc(pt, ptsize *= 2)) == عدم)
				اذهب err;
			bpt = npt + (bpt - pt);
			pt = npt;
			ept = pt + ptsize;
			memmove(ept - len, bpt, len);
			bpt = ept - len;
		}
		إذا (!پہلا)
			*--bpt = '/';
		bpt -= dp->d_namlen;
		حافظہ_نقل(bpt, dp->d_name, dp->d_namlen);
		(فراغ)closedir(dir);

		/* Truncate any file name. */
		*bup = '\0';
	}

notfound:
	/*
	 * If readdir set errno, use it, not any saved error; otherwise,
	 * didn't find the current directory in its parent directory, set
	 * errno to ENOENT.
	 */
	إذا (!errno)
		errno = save_errno ? save_errno : ENOENT;
	/* FALLTHROUGH */
err:
	save_errno = errno;

	إذا (ptsize)
		حرر(pt);
	حرر(اتے);
	إذا (dir)
		(فراغ)closedir(dir);

	errno = save_errno;

	أرجع (عدم);
}

#جے_انت /* !defined(HAVE_GETCWD) */
