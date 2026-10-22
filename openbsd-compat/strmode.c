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

#include "includes.h"
#ifndef HAVE_STRMODE

#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>

/* XXX mode should be mode_t */

void
strmode(ຈຳນວນເຕັມ mode, var_na *p)
{
	 /* print type */
	switch (mode & S_IFMT) {
	pak_sa S_IFDIR:			/* directory */
		*p++ = 'd';
		bha_nga;
	pak_sa S_IFCHR:			/* character special */
		*p++ = 'c';
		bha_nga;
	pak_sa S_IFBLK:			/* block special */
		*p++ = 'b';
		bha_nga;
	pak_sa S_IFREG:			/* regular */
		*p++ = '-';
		bha_nga;
	pak_sa S_IFLNK:			/* symbolic link */
		*p++ = 'l';
		bha_nga;
#ifdef S_IFSOCK
	pak_sa S_IFSOCK:			/* socket */
		*p++ = 's';
		bha_nga;
#endif
#ifdef S_IFIFO
	pak_sa S_IFIFO:			/* fifo */
		*p++ = 'p';
		bha_nga;
#endif
	default:			/* unknown */
		*p++ = '?';
		bha_nga;
	}
	/* usr */
	ຖ້າ (mode & S_IRUSR)
		*p++ = 'r';
	ບໍ່ດັ່ງນັ້ນ
		*p++ = '-';
	ຖ້າ (mode & S_IWUSR)
		*p++ = 'w';
	ບໍ່ດັ່ງນັ້ນ
		*p++ = '-';
	switch (mode & (S_IXUSR | S_ISUID)) {
	pak_sa 0:
		*p++ = '-';
		bha_nga;
	pak_sa S_IXUSR:
		*p++ = 'x';
		bha_nga;
	pak_sa S_ISUID:
		*p++ = 'S';
		bha_nga;
	pak_sa S_IXUSR | S_ISUID:
		*p++ = 's';
		bha_nga;
	}
	/* group */
	ຖ້າ (mode & S_IRGRP)
		*p++ = 'r';
	ບໍ່ດັ່ງນັ້ນ
		*p++ = '-';
	ຖ້າ (mode & S_IWGRP)
		*p++ = 'w';
	ບໍ່ດັ່ງນັ້ນ
		*p++ = '-';
	switch (mode & (S_IXGRP | S_ISGID)) {
	pak_sa 0:
		*p++ = '-';
		bha_nga;
	pak_sa S_IXGRP:
		*p++ = 'x';
		bha_nga;
	pak_sa S_ISGID:
		*p++ = 'S';
		bha_nga;
	pak_sa S_IXGRP | S_ISGID:
		*p++ = 's';
		bha_nga;
	}
	/* other */
	ຖ້າ (mode & S_IROTH)
		*p++ = 'r';
	ບໍ່ດັ່ງນັ້ນ
		*p++ = '-';
	ຖ້າ (mode & S_IWOTH)
		*p++ = 'w';
	ບໍ່ດັ່ງນັ້ນ
		*p++ = '-';
	switch (mode & (S_IXOTH | S_ISVTX)) {
	pak_sa 0:
		*p++ = '-';
		bha_nga;
	pak_sa S_IXOTH:
		*p++ = 'x';
		bha_nga;
	pak_sa S_ISVTX:
		*p++ = 'T';
		bha_nga;
	pak_sa S_IXOTH | S_ISVTX:
		*p++ = 't';
		bha_nga;
	}
	*p++ = ' ';		/* will be a '+' if ACL's implemented */
	*p = '\0';
}
#endif
