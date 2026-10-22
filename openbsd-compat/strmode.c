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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_STRMODE

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/stat.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

/* XXX mode should be mode_t */

ਖਾਲੀ
strmode(ਪੂਰਨ ਬਹੁਲਕ, ਅੱਖਰ *p)
{
	 /* print type */
	ਚੋਣ (ਬਹੁਲਕ & S_IFMT) {
	ਹਾਲਤ S_IFDIR:			/* directory */
		*p++ = 'd';
		ਰੋਕੋ;
	ਹਾਲਤ S_IFCHR:			/* character special */
		*p++ = 'c';
		ਰੋਕੋ;
	ਹਾਲਤ S_IFBLK:			/* block special */
		*p++ = 'b';
		ਰੋਕੋ;
	ਹਾਲਤ S_IFREG:			/* regular */
		*p++ = '-';
		ਰੋਕੋ;
	ਹਾਲਤ S_IFLNK:			/* symbolic link */
		*p++ = 'l';
		ਰੋਕੋ;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ S_IFSOCK
	ਹਾਲਤ S_IFSOCK:			/* socket */
		*p++ = 's';
		ਰੋਕੋ;
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ S_IFIFO
	ਹਾਲਤ S_IFIFO:			/* fifo */
		*p++ = 'p';
		ਰੋਕੋ;
#ਜੇ_ਅੰਤ
	ਮੂਲ:			/* unknown */
		*p++ = '?';
		ਰੋਕੋ;
	}
	/* usr */
	ਜੇ (ਬਹੁਲਕ & S_IRUSR)
		*p++ = 'r';
	ਨਹੀਂਤਾਂ
		*p++ = '-';
	ਜੇ (ਬਹੁਲਕ & S_IWUSR)
		*p++ = 'w';
	ਨਹੀਂਤਾਂ
		*p++ = '-';
	ਚੋਣ (ਬਹੁਲਕ & (S_IXUSR | S_ISUID)) {
	ਹਾਲਤ 0:
		*p++ = '-';
		ਰੋਕੋ;
	ਹਾਲਤ S_IXUSR:
		*p++ = 'x';
		ਰੋਕੋ;
	ਹਾਲਤ S_ISUID:
		*p++ = 'S';
		ਰੋਕੋ;
	ਹਾਲਤ S_IXUSR | S_ISUID:
		*p++ = 's';
		ਰੋਕੋ;
	}
	/*ਸਮੂਹ*/
	ਜੇ (ਬਹੁਲਕ & S_IRGRP)
		*p++ = 'r';
	ਨਹੀਂਤਾਂ
		*p++ = '-';
	ਜੇ (ਬਹੁਲਕ & S_IWGRP)
		*p++ = 'w';
	ਨਹੀਂਤਾਂ
		*p++ = '-';
	ਚੋਣ (ਬਹੁਲਕ & (S_IXGRP | S_ISGID)) {
	ਹਾਲਤ 0:
		*p++ = '-';
		ਰੋਕੋ;
	ਹਾਲਤ S_IXGRP:
		*p++ = 'x';
		ਰੋਕੋ;
	ਹਾਲਤ S_ISGID:
		*p++ = 'S';
		ਰੋਕੋ;
	ਹਾਲਤ S_IXGRP | S_ISGID:
		*p++ = 's';
		ਰੋਕੋ;
	}
	/* other */
	ਜੇ (ਬਹੁਲਕ & S_IROTH)
		*p++ = 'r';
	ਨਹੀਂਤਾਂ
		*p++ = '-';
	ਜੇ (ਬਹੁਲਕ & S_IWOTH)
		*p++ = 'w';
	ਨਹੀਂਤਾਂ
		*p++ = '-';
	ਚੋਣ (ਬਹੁਲਕ & (S_IXOTH | S_ISVTX)) {
	ਹਾਲਤ 0:
		*p++ = '-';
		ਰੋਕੋ;
	ਹਾਲਤ S_IXOTH:
		*p++ = 'x';
		ਰੋਕੋ;
	ਹਾਲਤ S_ISVTX:
		*p++ = 'T';
		ਰੋਕੋ;
	ਹਾਲਤ S_IXOTH | S_ISVTX:
		*p++ = 't';
		ਰੋਕੋ;
	}
	*p++ = ' ';		/* will be a '+' if ACL's implemented */
	*p = '\0';
}
#ਜੇ_ਅੰਤ
