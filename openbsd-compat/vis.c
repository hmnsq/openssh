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

#ضمن "includes.h"
#𐤀𐤌 !defined(HAVE_STRNVIS) || defined(BROKEN_STRNVIS)

#ضمن <sys/types.h>
#ضمن <errno.h>
#ضمن <ctype.h>
#ضمن <limits.h>
#ضمن <string.h>
#ضمن <stdlib.h>

#ضمن "vis.h"

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
حرف *
vis(حرف *dst, صحيح c, صحيح flag, صحيح nextc)
{
	𐤀𐤌 (isvisible(c, flag)) {
		𐤀𐤌 ((c == '"' && (flag & VIS_DQ) != 0) ||
		    (c == '\\' && (flag & VIS_NOSLASH) == 0))
			*dst++ = '\\';
		*dst++ = c;
		*dst = '\0';
		أرجع (dst);
	}

	𐤀𐤌 (flag & VIS_CSTYLE) {
		بدل(c) {
		حالة '\n':
			*dst++ = '\\';
			*dst++ = 'n';
			اذهب done;
		حالة '\r':
			*dst++ = '\\';
			*dst++ = 'r';
			اذهب done;
		حالة '\b':
			*dst++ = '\\';
			*dst++ = 'b';
			اذهب done;
		حالة '\a':
			*dst++ = '\\';
			*dst++ = 'a';
			اذهب done;
		حالة '\v':
			*dst++ = '\\';
			*dst++ = 'v';
			اذهب done;
		حالة '\t':
			*dst++ = '\\';
			*dst++ = 't';
			اذهب done;
		حالة '\f':
			*dst++ = '\\';
			*dst++ = 'f';
			اذهب done;
		حالة ' ':
			*dst++ = '\\';
			*dst++ = 's';
			اذهب done;
		حالة '\0':
			*dst++ = '\\';
			*dst++ = '0';
			𐤀𐤌 (isoctal(nextc)) {
				*dst++ = '0';
				*dst++ = '0';
			}
			اذهب done;
		}
	}
	𐤀𐤌 (((c & 0177) == ' ') || (flag & VIS_OCTAL) ||
	    ((flag & VIS_GLOB) && (c == '*' || c == '?' || c == '[' || c == '#'))) {
		*dst++ = '\\';
		*dst++ = ((u_char)c >> 6 & 07) + '0';
		*dst++ = ((u_char)c >> 3 & 07) + '0';
		*dst++ = ((u_char)c & 07) + '0';
		اذهب done;
	}
	𐤀𐤌 ((flag & VIS_NOSLASH) == 0)
		*dst++ = '\\';
	𐤀𐤌 (c & 0200) {
		c &= 0177;
		*dst++ = 'M';
	}
	𐤀𐤌 (iscntrl((u_char)c)) {
		*dst++ = '^';
		𐤀𐤌 (c == 0177)
			*dst++ = '?';
		وإلا
			*dst++ = c + '@';
	} وإلا {
		*dst++ = '-';
		*dst++ = c;
	}
done:
	*dst = '\0';
	أرجع (dst);
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
صحيح
strvis(حرف *dst, ثابت حرف *src, صحيح flag)
{
	حرف c;
	حرف *start;

	لكل (start = dst; (c = *src);)
		dst = vis(dst, c, flag, *++src);
	*dst = '\0';
	أرجع (dst - start);
}
DEF_WEAK(strvis);

صحيح
strnvis(حرف *dst, ثابت حرف *src, size_t siz, صحيح flag)
{
	حرف *start, *end;
	حرف tbuf[5];
	صحيح c, i;

	i = 0;
	لكل (start = dst, end = start + siz - 1; (c = *src) && dst < end; ) {
		𐤀𐤌 (isvisible(c, flag)) {
			𐤀𐤌 ((c == '"' && (flag & VIS_DQ) != 0) ||
			    (c == '\\' && (flag & VIS_NOSLASH) == 0)) {
				/* need space for the extra '\\' */
				𐤀𐤌 (dst + 1 >= end) {
					i = 2;
					اكسر;
				}
				*dst++ = '\\';
			}
			i = 1;
			*dst++ = c;
			src++;
		} وإلا {
			i = vis(tbuf, c, flag, *++src) - tbuf;
			𐤀𐤌 (dst + i <= end) {
				memcpy(dst, tbuf, i);
				dst += i;
			} وإلا {
				src--;
				اكسر;
			}
		}
	}
	𐤀𐤌 (siz > 0)
		*dst = '\0';
	𐤀𐤌 (dst + i > end) {
		/* adjust return value for truncation */
		طالما ((c = *src))
			dst += vis(tbuf, c, flag, *++src) - tbuf;
	}
	أرجع (dst - start);
}

#𐤀𐤌 0 /* unused in OpenSSH */
صحيح
stravis(حرف **outp, ثابت حرف *src, صحيح flag)
{
	حرف *buf;
	صحيح len, serrno;

	buf = reallocarray(عدم, 4, strlen(src) + 1);
	𐤀𐤌 (buf == عدم)
		أرجع -1;
	len = strvis(buf, src, flag);
	serrno = errno;
	*outp = realloc(buf, len + 1);
	𐤀𐤌 (*outp == عدم) {
		*outp = buf;
		errno = serrno;
	}
	أرجع (len);
}

صحيح
strvisx(حرف *dst, ثابت حرف *src, size_t len, صحيح flag)
{
	حرف c;
	حرف *start;

	لكل (start = dst; len > 1; len--) {
		c = *src;
		dst = vis(dst, c, flag, *++src);
	}
	𐤀𐤌 (len)
		dst = vis(dst, *src, flag, '\0');
	*dst = '\0';
	أرجع (dst - start);
}
#endif /* unused */

#endif
