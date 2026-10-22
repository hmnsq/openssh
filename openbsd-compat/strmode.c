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

#ضمن "includes.h"
#که_نه_تعریف_شوی HAVE_STRMODE

#ضمن <sys/types.h>
#ضمن <sys/stat.h>
#ضمن <string.h>

/* XXX mode should be mode_t */

فراغ
strmode(صحيح ډېرپېښ, حرف *p)
{
	 /* print type */
	بدل (ډېرپېښ & S_IFMT) {
	حالة S_IFDIR:			/* directory */
		*p++ = 'd';
		اكسر;
	حالة S_IFCHR:			/* character special */
		*p++ = 'c';
		اكسر;
	حالة S_IFBLK:			/* block special */
		*p++ = 'b';
		اكسر;
	حالة S_IFREG:			/* regular */
		*p++ = '-';
		اكسر;
	حالة S_IFLNK:			/* symbolic link */
		*p++ = 'l';
		اكسر;
#که_تعریف_شوی S_IFSOCK
	حالة S_IFSOCK:			/* socket */
		*p++ = 's';
		اكسر;
#د_که_پای
#که_تعریف_شوی S_IFIFO
	حالة S_IFIFO:			/* fifo */
		*p++ = 'p';
		اكسر;
#د_که_پای
	افتراضي:			/* unknown */
		*p++ = '?';
		اكسر;
	}
	/* usr */
	إذا (ډېرپېښ & S_IRUSR)
		*p++ = 'r';
	وإلا
		*p++ = '-';
	إذا (ډېرپېښ & S_IWUSR)
		*p++ = 'w';
	وإلا
		*p++ = '-';
	بدل (ډېرپېښ & (S_IXUSR | S_ISUID)) {
	حالة 0:
		*p++ = '-';
		اكسر;
	حالة S_IXUSR:
		*p++ = 'x';
		اكسر;
	حالة S_ISUID:
		*p++ = 'S';
		اكسر;
	حالة S_IXUSR | S_ISUID:
		*p++ = 's';
		اكسر;
	}
	/*ډله*/
	إذا (ډېرپېښ & S_IRGRP)
		*p++ = 'r';
	وإلا
		*p++ = '-';
	إذا (ډېرپېښ & S_IWGRP)
		*p++ = 'w';
	وإلا
		*p++ = '-';
	بدل (ډېرپېښ & (S_IXGRP | S_ISGID)) {
	حالة 0:
		*p++ = '-';
		اكسر;
	حالة S_IXGRP:
		*p++ = 'x';
		اكسر;
	حالة S_ISGID:
		*p++ = 'S';
		اكسر;
	حالة S_IXGRP | S_ISGID:
		*p++ = 's';
		اكسر;
	}
	/* other */
	إذا (ډېرپېښ & S_IROTH)
		*p++ = 'r';
	وإلا
		*p++ = '-';
	إذا (ډېرپېښ & S_IWOTH)
		*p++ = 'w';
	وإلا
		*p++ = '-';
	بدل (ډېرپېښ & (S_IXOTH | S_ISVTX)) {
	حالة 0:
		*p++ = '-';
		اكسر;
	حالة S_IXOTH:
		*p++ = 'x';
		اكسر;
	حالة S_ISVTX:
		*p++ = 'T';
		اكسر;
	حالة S_IXOTH | S_ISVTX:
		*p++ = 't';
		اكسر;
	}
	*p++ = ' ';		/* will be a '+' if ACL's implemented */
	*p = '\0';
}
#د_که_پای
