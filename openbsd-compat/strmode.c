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

#અન્તર્ભાવ "includes.h"
#ifndef HAVE_STRMODE

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/stat.h>
#અન્તર્ભાવ <string.h>

/* XXX mode should be mode_t */

શૂન્ય
strmode(પૂર્ણાંક mode, અક્ષર *p)
{
	 /* print type */
	પસંદગી (mode & S_IFMT) {
	સ્થિતિ S_IFDIR:			/* directory */
		*p++ = 'd';
		તોડો;
	સ્થિતિ S_IFCHR:			/* character special */
		*p++ = 'c';
		તોડો;
	સ્થિતિ S_IFBLK:			/* block special */
		*p++ = 'b';
		તોડો;
	સ્થિતિ S_IFREG:			/* regular */
		*p++ = '-';
		તોડો;
	સ્થિતિ S_IFLNK:			/* symbolic link */
		*p++ = 'l';
		તોડો;
#ifdef S_IFSOCK
	સ્થિતિ S_IFSOCK:			/* socket */
		*p++ = 's';
		તોડો;
#endif
#ifdef S_IFIFO
	સ્થિતિ S_IFIFO:			/* fifo */
		*p++ = 'p';
		તોડો;
#endif
	મૂળભૂત:			/* unknown */
		*p++ = '?';
		તોડો;
	}
	/* usr */
	જો (mode & S_IRUSR)
		*p++ = 'r';
	નહીંતર
		*p++ = '-';
	જો (mode & S_IWUSR)
		*p++ = 'w';
	નહીંતર
		*p++ = '-';
	પસંદગી (mode & (S_IXUSR | S_ISUID)) {
	સ્થિતિ 0:
		*p++ = '-';
		તોડો;
	સ્થિતિ S_IXUSR:
		*p++ = 'x';
		તોડો;
	સ્થિતિ S_ISUID:
		*p++ = 'S';
		તોડો;
	સ્થિતિ S_IXUSR | S_ISUID:
		*p++ = 's';
		તોડો;
	}
	/* group */
	જો (mode & S_IRGRP)
		*p++ = 'r';
	નહીંતર
		*p++ = '-';
	જો (mode & S_IWGRP)
		*p++ = 'w';
	નહીંતર
		*p++ = '-';
	પસંદગી (mode & (S_IXGRP | S_ISGID)) {
	સ્થિતિ 0:
		*p++ = '-';
		તોડો;
	સ્થિતિ S_IXGRP:
		*p++ = 'x';
		તોડો;
	સ્થિતિ S_ISGID:
		*p++ = 'S';
		તોડો;
	સ્થિતિ S_IXGRP | S_ISGID:
		*p++ = 's';
		તોડો;
	}
	/* other */
	જો (mode & S_IROTH)
		*p++ = 'r';
	નહીંતર
		*p++ = '-';
	જો (mode & S_IWOTH)
		*p++ = 'w';
	નહીંતર
		*p++ = '-';
	પસંદગી (mode & (S_IXOTH | S_ISVTX)) {
	સ્થિતિ 0:
		*p++ = '-';
		તોડો;
	સ્થિતિ S_IXOTH:
		*p++ = 'x';
		તોડો;
	સ્થિતિ S_ISVTX:
		*p++ = 'T';
		તોડો;
	સ્થિતિ S_IXOTH | S_ISVTX:
		*p++ = 't';
		તોડો;
	}
	*p++ = ' ';		/* will be a '+' if ACL's implemented */
	*p = '\0';
}
#endif
