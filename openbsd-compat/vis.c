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

#অন্তর্ভাব "includes.h"
#যদি !defined(HAVE_STRNVIS) || defined(BROKEN_STRNVIS)

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <ctype.h>
#অন্তর্ভাব <limits.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <stdlib.h>

#অন্তর্ভাব "vis.h"

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
বর্ণ *
vis(বর্ণ *dst, পূর্ণাঙ্ক c, পূর্ণাঙ্ক flag, পূর্ণাঙ্ক nextc)
{
	যদি (isvisible(c, flag)) {
		যদি ((c == '"' && (flag & VIS_DQ) != 0) ||
		    (c == '\\' && (flag & VIS_NOSLASH) == 0))
			*dst++ = '\\';
		*dst++ = c;
		*dst = '\0';
		প্রত্যাগম (dst);
	}

	যদি (flag & VIS_CSTYLE) {
		বিকল্প(c) {
		পক্ষ '\n':
			*dst++ = '\\';
			*dst++ = 'n';
			গচ্ছ done;
		পক্ষ '\r':
			*dst++ = '\\';
			*dst++ = 'r';
			গচ্ছ done;
		পক্ষ '\b':
			*dst++ = '\\';
			*dst++ = 'b';
			গচ্ছ done;
		পক্ষ '\a':
			*dst++ = '\\';
			*dst++ = 'a';
			গচ্ছ done;
		পক্ষ '\v':
			*dst++ = '\\';
			*dst++ = 'v';
			গচ্ছ done;
		পক্ষ '\t':
			*dst++ = '\\';
			*dst++ = 't';
			গচ্ছ done;
		পক্ষ '\f':
			*dst++ = '\\';
			*dst++ = 'f';
			গচ্ছ done;
		পক্ষ ' ':
			*dst++ = '\\';
			*dst++ = 's';
			গচ্ছ done;
		পক্ষ '\0':
			*dst++ = '\\';
			*dst++ = '0';
			যদি (isoctal(nextc)) {
				*dst++ = '0';
				*dst++ = '0';
			}
			গচ্ছ done;
		}
	}
	যদি (((c & 0177) == ' ') || (flag & VIS_OCTAL) ||
	    ((flag & VIS_GLOB) && (c == '*' || c == '?' || c == '[' || c == '#'))) {
		*dst++ = '\\';
		*dst++ = ((u_char)c >> 6 & 07) + '0';
		*dst++ = ((u_char)c >> 3 & 07) + '0';
		*dst++ = ((u_char)c & 07) + '0';
		গচ্ছ done;
	}
	যদি ((flag & VIS_NOSLASH) == 0)
		*dst++ = '\\';
	যদি (c & 0200) {
		c &= 0177;
		*dst++ = 'M';
	}
	যদি (iscntrl((u_char)c)) {
		*dst++ = '^';
		যদি (c == 0177)
			*dst++ = '?';
		অন্যথা
			*dst++ = c + '@';
	} অন্যথা {
		*dst++ = '-';
		*dst++ = c;
	}
done:
	*dst = '\0';
	প্রত্যাগম (dst);
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
পূর্ণাঙ্ক
strvis(বর্ণ *dst, ধ্রুব বর্ণ *src, পূর্ণাঙ্ক flag)
{
	বর্ণ c;
	বর্ণ *start;

	প্রতি (start = dst; (c = *src);)
		dst = vis(dst, c, flag, *++src);
	*dst = '\0';
	প্রত্যাগম (dst - start);
}
DEF_WEAK(strvis);

পূর্ণাঙ্ক
strnvis(বর্ণ *dst, ধ্রুব বর্ণ *src, size_t siz, পূর্ণাঙ্ক flag)
{
	বর্ণ *start, *end;
	বর্ণ tbuf[5];
	পূর্ণাঙ্ক c, i;

	i = 0;
	প্রতি (start = dst, end = start + siz - 1; (c = *src) && dst < end; ) {
		যদি (isvisible(c, flag)) {
			যদি ((c == '"' && (flag & VIS_DQ) != 0) ||
			    (c == '\\' && (flag & VIS_NOSLASH) == 0)) {
				/* need space for the extra '\\' */
				যদি (dst + 1 >= end) {
					i = 2;
					ভঙ্গ;
				}
				*dst++ = '\\';
			}
			i = 1;
			*dst++ = c;
			src++;
		} অন্যথা {
			i = vis(tbuf, c, flag, *++src) - tbuf;
			যদি (dst + i <= end) {
				memcpy(dst, tbuf, i);
				dst += i;
			} অন্যথা {
				src--;
				ভঙ্গ;
			}
		}
	}
	যদি (siz > 0)
		*dst = '\0';
	যদি (dst + i > end) {
		/* adjust return value for truncation */
		যাবত্ ((c = *src))
			dst += vis(tbuf, c, flag, *++src) - tbuf;
	}
	প্রত্যাগম (dst - start);
}

#যদি 0 /* unused in OpenSSH */
পূর্ণাঙ্ক
stravis(বর্ণ **outp, ধ্রুব বর্ণ *src, পূর্ণাঙ্ক flag)
{
	বর্ণ *buf;
	পূর্ণাঙ্ক len, serrno;

	buf = reallocarray(রিক্ত, 4, strlen(src) + 1);
	যদি (buf == রিক্ত)
		প্রত্যাগম -1;
	len = strvis(buf, src, flag);
	serrno = errno;
	*outp = realloc(buf, len + 1);
	যদি (*outp == রিক্ত) {
		*outp = buf;
		errno = serrno;
	}
	প্রত্যাগম (len);
}

পূর্ণাঙ্ক
strvisx(বর্ণ *dst, ধ্রুব বর্ণ *src, size_t len, পূর্ণাঙ্ক flag)
{
	বর্ণ c;
	বর্ণ *start;

	প্রতি (start = dst; len > 1; len--) {
		c = *src;
		dst = vis(dst, c, flag, *++src);
	}
	যদি (len)
		dst = vis(dst, *src, flag, '\0');
	*dst = '\0';
	প্রত্যাগম (dst - start);
}
#endif /* unused */

#endif
