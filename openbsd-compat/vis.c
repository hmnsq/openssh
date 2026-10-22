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
#إذا !defined(HAVE_STRNVIS) || defined(BROKEN_STRNVIS)

#ضمن <sys/types.h>
#ضمن <errno.h>
#ضمن <ctype.h>
#ضمن <limits.h>
#ضمن <string.h>
#ضمن <stdlib.h>

#ضمن "vis.h"

#وصف_ڪريو	isoctal(c)	(((u_char)(c)) >= '0' && ((u_char)(c)) <= '7')
#وصف_ڪريو	isvisible(c,flag)						\
	(((c) == '\\' || (flag & VIS_ALL) == 0) &&			\
	(((u_int)(c) <= UCHAR_MAX && isascii((u_char)(c)) &&		\
	(((c) != '*' && (c) != '?' && (c) != '[' && (c) != '#') ||	\
		(flag & VIS_GLOB) == 0) && isgraph((u_char)(c))) ||	\
	((flag & VIS_SP) == 0 && (c) == ' ') ||				\
	((flag & VIS_TAB) == 0 && (c) == '\t') ||			\
	((flag & VIS_NL) == 0 && (c) == '\n') ||			\
	((flag & VIS_محفوظ) && ((c) == '\b' ||				\
		(c) == '\007' || (c) == '\r' ||				\
		isgraph((u_char)(c))))))

/*
 * vis - visually encode characters
 */
حرف *
vis(حرف *dst, صحيح c, صحيح flag, صحيح nextc)
{
	إذا (isvisible(c, flag)) {
		إذا ((c == '"' && (flag & VIS_DQ) != 0) ||
		    (c == '\\' && (flag & VIS_NOSLASH) == 0))
			*dst++ = '\\';
		*dst++ = c;
		*dst = '\0';
		أرجع (dst);
	}

	إذا (flag & VIS_CSTYLE) {
		بدل(c) {
		حالة '\n':
			*dst++ = '\\';
			*dst++ = 'n';
			اذهب پورو;
		حالة '\r':
			*dst++ = '\\';
			*dst++ = 'r';
			اذهب پورو;
		حالة '\b':
			*dst++ = '\\';
			*dst++ = 'b';
			اذهب پورو;
		حالة '\a':
			*dst++ = '\\';
			*dst++ = 'a';
			اذهب پورو;
		حالة '\v':
			*dst++ = '\\';
			*dst++ = 'v';
			اذهب پورو;
		حالة '\t':
			*dst++ = '\\';
			*dst++ = 't';
			اذهب پورو;
		حالة '\f':
			*dst++ = '\\';
			*dst++ = 'f';
			اذهب پورو;
		حالة ' ':
			*dst++ = '\\';
			*dst++ = 's';
			اذهب پورو;
		حالة '\0':
			*dst++ = '\\';
			*dst++ = '0';
			إذا (isoctal(nextc)) {
				*dst++ = '0';
				*dst++ = '0';
			}
			اذهب پورو;
		}
	}
	إذا (((c & 0177) == ' ') || (flag & VIS_OCTAL) ||
	    ((flag & VIS_GLOB) && (c == '*' || c == '?' || c == '[' || c == '#'))) {
		*dst++ = '\\';
		*dst++ = ((u_char)c >> 6 & 07) + '0';
		*dst++ = ((u_char)c >> 3 & 07) + '0';
		*dst++ = ((u_char)c & 07) + '0';
		اذهب پورو;
	}
	إذا ((flag & VIS_NOSLASH) == 0)
		*dst++ = '\\';
	إذا (c & 0200) {
		c &= 0177;
		*dst++ = 'M';
	}
	إذا (iscntrl((u_char)c)) {
		*dst++ = '^';
		إذا (c == 0177)
			*dst++ = '?';
		وإلا
			*dst++ = c + '@';
	} وإلا {
		*dst++ = '-';
		*dst++ = c;
	}
پورو:
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
	حرف *شروعات;

	لكل (شروعات = dst; (c = *src);)
		dst = vis(dst, c, flag, *++src);
	*dst = '\0';
	أرجع (dst - شروعات);
}
DEF_WEAK(strvis);

صحيح
strnvis(حرف *dst, ثابت حرف *src, سائيز_t siz, صحيح flag)
{
	حرف *شروعات, *پڇاڙي;
	حرف tbuf[5];
	صحيح c, i;

	i = 0;
	لكل (شروعات = dst, پڇاڙي = شروعات + siz - 1; (c = *src) && dst < پڇاڙي; ) {
		إذا (isvisible(c, flag)) {
			إذا ((c == '"' && (flag & VIS_DQ) != 0) ||
			    (c == '\\' && (flag & VIS_NOSLASH) == 0)) {
				/* need space for the extra '\\' */
				إذا (dst + 1 >= پڇاڙي) {
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
			إذا (dst + i <= پڇاڙي) {
				يادگيري_نقل(dst, tbuf, i);
				dst += i;
			} وإلا {
				src--;
				اكسر;
			}
		}
	}
	إذا (siz > 0)
		*dst = '\0';
	إذا (dst + i > پڇاڙي) {
		/* adjust return value for truncation */
		طالما ((c = *src))
			dst += vis(tbuf, c, flag, *++src) - tbuf;
	}
	أرجع (dst - شروعات);
}

#إذا 0 /* unused in OpenSSH */
صحيح
stravis(حرف **outp, ثابت حرف *src, صحيح flag)
{
	حرف *buf;
	صحيح len, serrno;

	buf = reallocarray(عدم, 4, لڙي_ڊيگهه(src) + 1);
	إذا (buf == عدم)
		أرجع -1;
	len = strvis(buf, src, flag);
	serrno = errno;
	*outp = realloc(buf, len + 1);
	إذا (*outp == عدم) {
		*outp = buf;
		errno = serrno;
	}
	أرجع (len);
}

صحيح
strvisx(حرف *dst, ثابت حرف *src, سائيز_t len, صحيح flag)
{
	حرف c;
	حرف *شروعات;

	لكل (شروعات = dst; len > 1; len--) {
		c = *src;
		dst = vis(dst, c, flag, *++src);
	}
	إذا (len)
		dst = vis(dst, *src, flag, '\0');
	*dst = '\0';
	أرجع (dst - شروعات);
}
#جيڪڏهن_پورو /*اڻ_استعمال_ٿيل*/

#جيڪڏهن_پورو
