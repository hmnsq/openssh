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

#ଅନ୍ତର୍ଭାଵ "includes.h"
#ifndef HAVE_STRMODE

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/stat.h>
#ଅନ୍ତର୍ଭାଵ <string.h>

/* XXX mode should be mode_t */

ଶୂନ୍ୟ
strmode(ପୂର୍ଣ୍ଣସଂଖ୍ୟା mode, ଅକ୍ଷର *p)
{
	 /* print type */
	ବାଛ (mode & S_IFMT) {
	ସ୍ଥିତି S_IFDIR:			/* directory */
		*p++ = 'd';
		ଭାଙ୍ଗ;
	ସ୍ଥିତି S_IFCHR:			/* character special */
		*p++ = 'c';
		ଭାଙ୍ଗ;
	ସ୍ଥିତି S_IFBLK:			/* block special */
		*p++ = 'b';
		ଭାଙ୍ଗ;
	ସ୍ଥିତି S_IFREG:			/* regular */
		*p++ = '-';
		ଭାଙ୍ଗ;
	ସ୍ଥିତି S_IFLNK:			/* symbolic link */
		*p++ = 'l';
		ଭାଙ୍ଗ;
#ifdef S_IFSOCK
	ସ୍ଥିତି S_IFSOCK:			/* socket */
		*p++ = 's';
		ଭାଙ୍ଗ;
#endif
#ifdef S_IFIFO
	ସ୍ଥିତି S_IFIFO:			/* fifo */
		*p++ = 'p';
		ଭାଙ୍ଗ;
#endif
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:			/* unknown */
		*p++ = '?';
		ଭାଙ୍ଗ;
	}
	/* usr */
	ଯଦି (mode & S_IRUSR)
		*p++ = 'r';
	ଅନ୍ୟଥା
		*p++ = '-';
	ଯଦି (mode & S_IWUSR)
		*p++ = 'w';
	ଅନ୍ୟଥା
		*p++ = '-';
	ବାଛ (mode & (S_IXUSR | S_ISUID)) {
	ସ୍ଥିତି 0:
		*p++ = '-';
		ଭାଙ୍ଗ;
	ସ୍ଥିତି S_IXUSR:
		*p++ = 'x';
		ଭାଙ୍ଗ;
	ସ୍ଥିତି S_ISUID:
		*p++ = 'S';
		ଭାଙ୍ଗ;
	ସ୍ଥିତି S_IXUSR | S_ISUID:
		*p++ = 's';
		ଭାଙ୍ଗ;
	}
	/* group */
	ଯଦି (mode & S_IRGRP)
		*p++ = 'r';
	ଅନ୍ୟଥା
		*p++ = '-';
	ଯଦି (mode & S_IWGRP)
		*p++ = 'w';
	ଅନ୍ୟଥା
		*p++ = '-';
	ବାଛ (mode & (S_IXGRP | S_ISGID)) {
	ସ୍ଥିତି 0:
		*p++ = '-';
		ଭାଙ୍ଗ;
	ସ୍ଥିତି S_IXGRP:
		*p++ = 'x';
		ଭାଙ୍ଗ;
	ସ୍ଥିତି S_ISGID:
		*p++ = 'S';
		ଭାଙ୍ଗ;
	ସ୍ଥିତି S_IXGRP | S_ISGID:
		*p++ = 's';
		ଭାଙ୍ଗ;
	}
	/* other */
	ଯଦି (mode & S_IROTH)
		*p++ = 'r';
	ଅନ୍ୟଥା
		*p++ = '-';
	ଯଦି (mode & S_IWOTH)
		*p++ = 'w';
	ଅନ୍ୟଥା
		*p++ = '-';
	ବାଛ (mode & (S_IXOTH | S_ISVTX)) {
	ସ୍ଥିତି 0:
		*p++ = '-';
		ଭାଙ୍ଗ;
	ସ୍ଥିତି S_IXOTH:
		*p++ = 'x';
		ଭାଙ୍ଗ;
	ସ୍ଥିତି S_ISVTX:
		*p++ = 'T';
		ଭାଙ୍ଗ;
	ସ୍ଥିତି S_IXOTH | S_ISVTX:
		*p++ = 't';
		ଭାଙ୍ଗ;
	}
	*p++ = ' ';		/* will be a '+' if ACL's implemented */
	*p = '\0';
}
#endif
