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

#అన్తర్భావ "includes.h"
#నిర్వచితం_కాకపోతే HAVE_STRMODE

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/stat.h>
#అన్తర్భావ <string.h>

/* XXX mode should be mode_t */

శూన్య
strmode(పూర్ణాంకం బహుళకం, అక్షరం *p)
{
	 /* print type */
	ఎంపిక (బహుళకం & S_IFMT) {
	స్థితి S_IFDIR:			/* directory */
		*p++ = 'd';
		ఆపు;
	స్థితి S_IFCHR:			/* character special */
		*p++ = 'c';
		ఆపు;
	స్థితి S_IFBLK:			/* block special */
		*p++ = 'b';
		ఆపు;
	స్థితి S_IFREG:			/* regular */
		*p++ = '-';
		ఆపు;
	స్థితి S_IFLNK:			/* symbolic link */
		*p++ = 'l';
		ఆపు;
#నిర్వచితమైతే S_IFSOCK
	స్థితి S_IFSOCK:			/* socket */
		*p++ = 's';
		ఆపు;
#అయితే_ముగింపు
#నిర్వచితమైతే S_IFIFO
	స్థితి S_IFIFO:			/* fifo */
		*p++ = 'p';
		ఆపు;
#అయితే_ముగింపు
	అప్రమేయ:			/* unknown */
		*p++ = '?';
		ఆపు;
	}
	/* usr */
	ఒకవేళ (బహుళకం & S_IRUSR)
		*p++ = 'r';
	లేకపోతే
		*p++ = '-';
	ఒకవేళ (బహుళకం & S_IWUSR)
		*p++ = 'w';
	లేకపోతే
		*p++ = '-';
	ఎంపిక (బహుళకం & (S_IXUSR | S_ISUID)) {
	స్థితి 0:
		*p++ = '-';
		ఆపు;
	స్థితి S_IXUSR:
		*p++ = 'x';
		ఆపు;
	స్థితి S_ISUID:
		*p++ = 'S';
		ఆపు;
	స్థితి S_IXUSR | S_ISUID:
		*p++ = 's';
		ఆపు;
	}
	/*సమూహం*/
	ఒకవేళ (బహుళకం & S_IRGRP)
		*p++ = 'r';
	లేకపోతే
		*p++ = '-';
	ఒకవేళ (బహుళకం & S_IWGRP)
		*p++ = 'w';
	లేకపోతే
		*p++ = '-';
	ఎంపిక (బహుళకం & (S_IXGRP | S_ISGID)) {
	స్థితి 0:
		*p++ = '-';
		ఆపు;
	స్థితి S_IXGRP:
		*p++ = 'x';
		ఆపు;
	స్థితి S_ISGID:
		*p++ = 'S';
		ఆపు;
	స్థితి S_IXGRP | S_ISGID:
		*p++ = 's';
		ఆపు;
	}
	/* other */
	ఒకవేళ (బహుళకం & S_IROTH)
		*p++ = 'r';
	లేకపోతే
		*p++ = '-';
	ఒకవేళ (బహుళకం & S_IWOTH)
		*p++ = 'w';
	లేకపోతే
		*p++ = '-';
	ఎంపిక (బహుళకం & (S_IXOTH | S_ISVTX)) {
	స్థితి 0:
		*p++ = '-';
		ఆపు;
	స్థితి S_IXOTH:
		*p++ = 'x';
		ఆపు;
	స్థితి S_ISVTX:
		*p++ = 'T';
		ఆపు;
	స్థితి S_IXOTH | S_ISVTX:
		*p++ = 't';
		ఆపు;
	}
	*p++ = ' ';		/* will be a '+' if ACL's implemented */
	*p = '\0';
}
#అయితే_ముగింపు
