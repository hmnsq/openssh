/*	$OpenBSD: strmode.c,v 1.7 2005/08/08 08:05:37 espie Exp $ */
/*-
 * Copyright (c) 1990 The Regents of the University of California.
 * All rights reserved.
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

/* OPENBSD ORIGINAL: lib/libc/string/strmode.c */

#ಅನ್ತರ್ಭಾವ "includes.h"
#ifndef HAVE_STRMODE

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>
#ಅನ್ತರ್ಭಾವ <string.h>

/* XXX mode should be mode_t */

ಶೂನ್ಯ
strmode(ಪೂರ್ಣಾಙ್ಕ mode, ವರ್ಣ *p)
{
	 /* print type */
	ವಿಕಲ್ಪ (mode & S_IFMT) {
	ಪಕ್ಷ S_IFDIR:			/* directory */
		*p++ = 'd';
		ಭಙ್ಗ;
	ಪಕ್ಷ S_IFCHR:			/* character special */
		*p++ = 'c';
		ಭಙ್ಗ;
	ಪಕ್ಷ S_IFBLK:			/* block special */
		*p++ = 'b';
		ಭಙ್ಗ;
	ಪಕ್ಷ S_IFREG:			/* regular */
		*p++ = '-';
		ಭಙ್ಗ;
	ಪಕ್ಷ S_IFLNK:			/* symbolic link */
		*p++ = 'l';
		ಭಙ್ಗ;
#ifdef S_IFSOCK
	ಪಕ್ಷ S_IFSOCK:			/* socket */
		*p++ = 's';
		ಭಙ್ಗ;
#endif
#ifdef S_IFIFO
	ಪಕ್ಷ S_IFIFO:			/* fifo */
		*p++ = 'p';
		ಭಙ್ಗ;
#endif
	ಸ್ವಭಾವ:			/* unknown */
		*p++ = '?';
		ಭಙ್ಗ;
	}
	/* usr */
	ಯದಿ (mode & S_IRUSR)
		*p++ = 'r';
	ಅನ್ಯಥಾ
		*p++ = '-';
	ಯದಿ (mode & S_IWUSR)
		*p++ = 'w';
	ಅನ್ಯಥಾ
		*p++ = '-';
	ವಿಕಲ್ಪ (mode & (S_IXUSR | S_ISUID)) {
	ಪಕ್ಷ 0:
		*p++ = '-';
		ಭಙ್ಗ;
	ಪಕ್ಷ S_IXUSR:
		*p++ = 'x';
		ಭಙ್ಗ;
	ಪಕ್ಷ S_ISUID:
		*p++ = 'S';
		ಭಙ್ಗ;
	ಪಕ್ಷ S_IXUSR | S_ISUID:
		*p++ = 's';
		ಭಙ್ಗ;
	}
	/* group */
	ಯದಿ (mode & S_IRGRP)
		*p++ = 'r';
	ಅನ್ಯಥಾ
		*p++ = '-';
	ಯದಿ (mode & S_IWGRP)
		*p++ = 'w';
	ಅನ್ಯಥಾ
		*p++ = '-';
	ವಿಕಲ್ಪ (mode & (S_IXGRP | S_ISGID)) {
	ಪಕ್ಷ 0:
		*p++ = '-';
		ಭಙ್ಗ;
	ಪಕ್ಷ S_IXGRP:
		*p++ = 'x';
		ಭಙ್ಗ;
	ಪಕ್ಷ S_ISGID:
		*p++ = 'S';
		ಭಙ್ಗ;
	ಪಕ್ಷ S_IXGRP | S_ISGID:
		*p++ = 's';
		ಭಙ್ಗ;
	}
	/* other */
	ಯದಿ (mode & S_IROTH)
		*p++ = 'r';
	ಅನ್ಯಥಾ
		*p++ = '-';
	ಯದಿ (mode & S_IWOTH)
		*p++ = 'w';
	ಅನ್ಯಥಾ
		*p++ = '-';
	ವಿಕಲ್ಪ (mode & (S_IXOTH | S_ISVTX)) {
	ಪಕ್ಷ 0:
		*p++ = '-';
		ಭಙ್ಗ;
	ಪಕ್ಷ S_IXOTH:
		*p++ = 'x';
		ಭಙ್ಗ;
	ಪಕ್ಷ S_ISVTX:
		*p++ = 'T';
		ಭಙ್ಗ;
	ಪಕ್ಷ S_IXOTH | S_ISVTX:
		*p++ = 't';
		ಭಙ್ಗ;
	}
	*p++ = ' ';		/* will be a '+' if ACL's implemented */
	*p = '\0';
}
#endif
