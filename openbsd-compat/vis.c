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

#شامل "includes.h"
#اگر !defined(HAVE_STRNVIS) || defined(BROKEN_STRNVIS)

#شامل <sys/types.h>
#شامل <errno.h>
#شامل <ctype.h>
#شامل <limits.h>
#شامل <string.h>
#شامل <stdlib.h>

#شامل "vis.h"

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
نویسه *
vis(نویسه *dst, صحیح c, صحیح flag, صحیح nextc)
{
	اگر (isvisible(c, flag)) {
		اگر ((c == '"' && (flag & VIS_DQ) != 0) ||
		    (c == '\\' && (flag & VIS_NOSLASH) == 0))
			*dst++ = '\\';
		*dst++ = c;
		*dst = '\0';
		بازگشت (dst);
	}

	اگر (flag & VIS_CSTYLE) {
		انتخاب(c) {
		حالت '\n':
			*dst++ = '\\';
			*dst++ = 'n';
			برو done;
		حالت '\r':
			*dst++ = '\\';
			*dst++ = 'r';
			برو done;
		حالت '\b':
			*dst++ = '\\';
			*dst++ = 'b';
			برو done;
		حالت '\a':
			*dst++ = '\\';
			*dst++ = 'a';
			برو done;
		حالت '\v':
			*dst++ = '\\';
			*dst++ = 'v';
			برو done;
		حالت '\t':
			*dst++ = '\\';
			*dst++ = 't';
			برو done;
		حالت '\f':
			*dst++ = '\\';
			*dst++ = 'f';
			برو done;
		حالت ' ':
			*dst++ = '\\';
			*dst++ = 's';
			برو done;
		حالت '\0':
			*dst++ = '\\';
			*dst++ = '0';
			اگر (isoctal(nextc)) {
				*dst++ = '0';
				*dst++ = '0';
			}
			برو done;
		}
	}
	اگر (((c & 0177) == ' ') || (flag & VIS_OCTAL) ||
	    ((flag & VIS_GLOB) && (c == '*' || c == '?' || c == '[' || c == '#'))) {
		*dst++ = '\\';
		*dst++ = ((u_char)c >> 6 & 07) + '0';
		*dst++ = ((u_char)c >> 3 & 07) + '0';
		*dst++ = ((u_char)c & 07) + '0';
		برو done;
	}
	اگر ((flag & VIS_NOSLASH) == 0)
		*dst++ = '\\';
	اگر (c & 0200) {
		c &= 0177;
		*dst++ = 'M';
	}
	اگر (iscntrl((u_char)c)) {
		*dst++ = '^';
		اگر (c == 0177)
			*dst++ = '?';
		وگرنه
			*dst++ = c + '@';
	} وگرنه {
		*dst++ = '-';
		*dst++ = c;
	}
done:
	*dst = '\0';
	بازگشت (dst);
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
صحیح
strvis(نویسه *dst, ثابت نویسه *src, صحیح flag)
{
	نویسه c;
	نویسه *start;

	برای (start = dst; (c = *src);)
		dst = vis(dst, c, flag, *++src);
	*dst = '\0';
	بازگشت (dst - start);
}
DEF_WEAK(strvis);

صحیح
strnvis(نویسه *dst, ثابت نویسه *src, size_t siz, صحیح flag)
{
	نویسه *start, *end;
	نویسه tbuf[5];
	صحیح c, i;

	i = 0;
	برای (start = dst, end = start + siz - 1; (c = *src) && dst < end; ) {
		اگر (isvisible(c, flag)) {
			اگر ((c == '"' && (flag & VIS_DQ) != 0) ||
			    (c == '\\' && (flag & VIS_NOSLASH) == 0)) {
				/* need space for the extra '\\' */
				اگر (dst + 1 >= end) {
					i = 2;
					بشکن;
				}
				*dst++ = '\\';
			}
			i = 1;
			*dst++ = c;
			src++;
		} وگرنه {
			i = vis(tbuf, c, flag, *++src) - tbuf;
			اگر (dst + i <= end) {
				memcpy(dst, tbuf, i);
				dst += i;
			} وگرنه {
				src--;
				بشکن;
			}
		}
	}
	اگر (siz > 0)
		*dst = '\0';
	اگر (dst + i > end) {
		/* adjust return value for truncation */
		وقتی ((c = *src))
			dst += vis(tbuf, c, flag, *++src) - tbuf;
	}
	بازگشت (dst - start);
}

#اگر 0 /* unused in OpenSSH */
صحیح
stravis(نویسه **outp, ثابت نویسه *src, صحیح flag)
{
	نویسه *buf;
	صحیح len, serrno;

	buf = reallocarray(پوچ, 4, strlen(src) + 1);
	اگر (buf == پوچ)
		بازگشت -1;
	len = strvis(buf, src, flag);
	serrno = errno;
	*outp = realloc(buf, len + 1);
	اگر (*outp == پوچ) {
		*outp = buf;
		errno = serrno;
	}
	بازگشت (len);
}

صحیح
strvisx(نویسه *dst, ثابت نویسه *src, size_t len, صحیح flag)
{
	نویسه c;
	نویسه *start;

	برای (start = dst; len > 1; len--) {
		c = *src;
		dst = vis(dst, c, flag, *++src);
	}
	اگر (len)
		dst = vis(dst, *src, flag, '\0');
	*dst = '\0';
	بازگشت (dst - start);
}
#endif /* unused */

#endif
