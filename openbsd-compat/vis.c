/*	$OpenBSD: vis.c,v 1.25 2015/09/13 11:32:51 guenther Exp $ */
/*-
 * Copyright (c) 1989, 1993
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

/* OPENBSD ORIGINAL: lib/libc/gen/vis.c */

#include "includes.h"
#만약 !defined(HAVE_STRNVIS) || defined(BROKEN_STRNVIS)

#include <sys/types.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>

#include "vis.h"

#define	isoctal(c)	(((u_char)(c)) >= '0' && ((u_char)(c)) <= '7')
#define	isvisible(c,flag)						\
	(((c) == '\\' || (flag & VIS_ALL) == 0) &&			\
	(((u_int)(c) <= UCHAR_MAX && isascii((u_char)(c)) &&		\
	(((c) != '*' && (c) != '?' && (c) != '[' && (c) != '#') ||	\
		(flag & VIS_GLOB) == 0) && isgraph((u_char)(c))) ||	\
	((flag & VIS_SP) == 0 && (c) == ' ') ||				\
	((flag & VIS_TAB) == 0 && (c) == '\t') ||			\
	((flag & VIS_NL) == 0 && (c) == '\n') ||			\
	((flag & VIS_SAFE) && ((c) == '\b' ||				\
		(c) == '\007' || (c) == '\r' ||				\
		isgraph((u_char)(c))))))

/*
 * vis - visually encode characters
 */
char *
vis(char *dst, 정수 c, 정수 flag, 정수 nextc)
{
	만약 (isvisible(c, flag)) {
		만약 ((c == '"' && (flag & VIS_DQ) != 0) ||
		    (c == '\\' && (flag & VIS_NOSLASH) == 0))
			*dst++ = '\\';
		*dst++ = c;
		*dst = '\0';
		반환 (dst);
	}

	만약 (flag & VIS_CSTYLE) {
		switch(c) {
		case '\n':
			*dst++ = '\\';
			*dst++ = 'n';
			goto done;
		case '\r':
			*dst++ = '\\';
			*dst++ = 'r';
			goto done;
		case '\b':
			*dst++ = '\\';
			*dst++ = 'b';
			goto done;
		case '\a':
			*dst++ = '\\';
			*dst++ = 'a';
			goto done;
		case '\v':
			*dst++ = '\\';
			*dst++ = 'v';
			goto done;
		case '\t':
			*dst++ = '\\';
			*dst++ = 't';
			goto done;
		case '\f':
			*dst++ = '\\';
			*dst++ = 'f';
			goto done;
		case ' ':
			*dst++ = '\\';
			*dst++ = 's';
			goto done;
		case '\0':
			*dst++ = '\\';
			*dst++ = '0';
			만약 (isoctal(nextc)) {
				*dst++ = '0';
				*dst++ = '0';
			}
			goto done;
		}
	}
	만약 (((c & 0177) == ' ') || (flag & VIS_OCTAL) ||
	    ((flag & VIS_GLOB) && (c == '*' || c == '?' || c == '[' || c == '#'))) {
		*dst++ = '\\';
		*dst++ = ((u_char)c >> 6 & 07) + '0';
		*dst++ = ((u_char)c >> 3 & 07) + '0';
		*dst++ = ((u_char)c & 07) + '0';
		goto done;
	}
	만약 ((flag & VIS_NOSLASH) == 0)
		*dst++ = '\\';
	만약 (c & 0200) {
		c &= 0177;
		*dst++ = 'M';
	}
	만약 (iscntrl((u_char)c)) {
		*dst++ = '^';
		만약 (c == 0177)
			*dst++ = '?';
		아니면
			*dst++ = c + '@';
	} 아니면 {
		*dst++ = '-';
		*dst++ = c;
	}
done:
	*dst = '\0';
	반환 (dst);
}
DEF_WEAK(vis);

/*
 * strvis, strnvis, strvisx - visually encode characters from src into dst
 *	
 *	Dst must be 4 times the size of src to account for possible
 *	expansion.  The length of dst, not including the trailing NULL,
 *	is returned. 
 *
 *	Strnvis will write no more than siz-1 bytes (and will NULL terminate).
 *	The number of bytes needed to fully encode the string is returned.
 *
 *	Strvisx encodes exactly len bytes from src into dst.
 *	This is useful for encoding a block of data.
 */
정수
strvis(char *dst, const char *src, 정수 flag)
{
	char c;
	char *start;

	위해 (start = dst; (c = *src);)
		dst = vis(dst, c, flag, *++src);
	*dst = '\0';
	반환 (dst - start);
}
DEF_WEAK(strvis);

정수
strnvis(char *dst, const char *src, size_t siz, 정수 flag)
{
	char *start, *end;
	char tbuf[5];
	정수 c, i;

	i = 0;
	위해 (start = dst, end = start + siz - 1; (c = *src) && dst < end; ) {
		만약 (isvisible(c, flag)) {
			만약 ((c == '"' && (flag & VIS_DQ) != 0) ||
			    (c == '\\' && (flag & VIS_NOSLASH) == 0)) {
				/* need space for the extra '\\' */
				만약 (dst + 1 >= end) {
					i = 2;
					break;
				}
				*dst++ = '\\';
			}
			i = 1;
			*dst++ = c;
			src++;
		} 아니면 {
			i = vis(tbuf, c, flag, *++src) - tbuf;
			만약 (dst + i <= end) {
				memcpy(dst, tbuf, i);
				dst += i;
			} 아니면 {
				src--;
				break;
			}
		}
	}
	만약 (siz > 0)
		*dst = '\0';
	만약 (dst + i > end) {
		/* adjust return value for truncation */
		동안 ((c = *src))
			dst += vis(tbuf, c, flag, *++src) - tbuf;
	}
	반환 (dst - start);
}

#만약 0 /* unused in OpenSSH */
정수
stravis(char **outp, const char *src, 정수 flag)
{
	char *buf;
	정수 len, serrno;

	buf = reallocarray(NULL, 4, strlen(src) + 1);
	만약 (buf == NULL)
		반환 -1;
	len = strvis(buf, src, flag);
	serrno = errno;
	*outp = realloc(buf, len + 1);
	만약 (*outp == NULL) {
		*outp = buf;
		errno = serrno;
	}
	반환 (len);
}

정수
strvisx(char *dst, const char *src, size_t len, 정수 flag)
{
	char c;
	char *start;

	위해 (start = dst; len > 1; len--) {
		c = *src;
		dst = vis(dst, c, flag, *++src);
	}
	만약 (len)
		dst = vis(dst, *src, flag, '\0');
	*dst = '\0';
	반환 (dst - start);
}
#endif /* unused */

#endif
