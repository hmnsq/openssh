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

#अन्तर्भाव "includes.h"
#यदि !defined(HAVE_STRNVIS) || defined(BROKEN_STRNVIS)

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <errno.h>
#अन्तर्भाव <ctype.h>
#अन्तर्भाव <limits.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdlib.h>

#अन्तर्भाव "vis.h"

#परिभाषय	isoctal(c)	(((u_char)(c)) >= '0' && ((u_char)(c)) <= '7')
#परिभाषय	isvisible(c,flag)						\
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
वर्ण *
vis(वर्ण *dst, पूर्णाङ्क c, पूर्णाङ्क flag, पूर्णाङ्क nextc)
{
	यदि (isvisible(c, flag)) {
		यदि ((c == '"' && (flag & VIS_DQ) != 0) ||
		    (c == '\\' && (flag & VIS_NOSLASH) == 0))
			*dst++ = '\\';
		*dst++ = c;
		*dst = '\0';
		प्रत्यागम (dst);
	}

	यदि (flag & VIS_CSTYLE) {
		विकल्प(c) {
		पक्ष '\n':
			*dst++ = '\\';
			*dst++ = 'n';
			गच्छ समाप्तम्;
		पक्ष '\r':
			*dst++ = '\\';
			*dst++ = 'r';
			गच्छ समाप्तम्;
		पक्ष '\b':
			*dst++ = '\\';
			*dst++ = 'b';
			गच्छ समाप्तम्;
		पक्ष '\a':
			*dst++ = '\\';
			*dst++ = 'a';
			गच्छ समाप्तम्;
		पक्ष '\v':
			*dst++ = '\\';
			*dst++ = 'v';
			गच्छ समाप्तम्;
		पक्ष '\t':
			*dst++ = '\\';
			*dst++ = 't';
			गच्छ समाप्तम्;
		पक्ष '\f':
			*dst++ = '\\';
			*dst++ = 'f';
			गच्छ समाप्तम्;
		पक्ष ' ':
			*dst++ = '\\';
			*dst++ = 's';
			गच्छ समाप्तम्;
		पक्ष '\0':
			*dst++ = '\\';
			*dst++ = '0';
			यदि (isoctal(nextc)) {
				*dst++ = '0';
				*dst++ = '0';
			}
			गच्छ समाप्तम्;
		}
	}
	यदि (((c & 0177) == ' ') || (flag & VIS_OCTAL) ||
	    ((flag & VIS_GLOB) && (c == '*' || c == '?' || c == '[' || c == '#'))) {
		*dst++ = '\\';
		*dst++ = ((u_char)c >> 6 & 07) + '0';
		*dst++ = ((u_char)c >> 3 & 07) + '0';
		*dst++ = ((u_char)c & 07) + '0';
		गच्छ समाप्तम्;
	}
	यदि ((flag & VIS_NOSLASH) == 0)
		*dst++ = '\\';
	यदि (c & 0200) {
		c &= 0177;
		*dst++ = 'M';
	}
	यदि (iscntrl((u_char)c)) {
		*dst++ = '^';
		यदि (c == 0177)
			*dst++ = '?';
		अन्यथा
			*dst++ = c + '@';
	} अन्यथा {
		*dst++ = '-';
		*dst++ = c;
	}
समाप्तम्:
	*dst = '\0';
	प्रत्यागम (dst);
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
पूर्णाङ्क
strvis(वर्ण *dst, ध्रुव वर्ण *src, पूर्णाङ्क flag)
{
	वर्ण c;
	वर्ण *start;

	प्रति (start = dst; (c = *src);)
		dst = vis(dst, c, flag, *++src);
	*dst = '\0';
	प्रत्यागम (dst - start);
}
DEF_WEAK(strvis);

पूर्णाङ्क
strnvis(वर्ण *dst, ध्रुव वर्ण *src, आकार_t siz, पूर्णाङ्क flag)
{
	वर्ण *start, *अन्तः;
	वर्ण tbuf[5];
	पूर्णाङ्क c, i;

	i = 0;
	प्रति (start = dst, अन्तः = start + siz - 1; (c = *src) && dst < अन्तः; ) {
		यदि (isvisible(c, flag)) {
			यदि ((c == '"' && (flag & VIS_DQ) != 0) ||
			    (c == '\\' && (flag & VIS_NOSLASH) == 0)) {
				/* need space for the extra '\\' */
				यदि (dst + 1 >= अन्तः) {
					i = 2;
					भङ्ग;
				}
				*dst++ = '\\';
			}
			i = 1;
			*dst++ = c;
			src++;
		} अन्यथा {
			i = vis(tbuf, c, flag, *++src) - tbuf;
			यदि (dst + i <= अन्तः) {
				स्मृतिं_प्रतिलिख(dst, tbuf, i);
				dst += i;
			} अन्यथा {
				src--;
				भङ्ग;
			}
		}
	}
	यदि (siz > 0)
		*dst = '\0';
	यदि (dst + i > अन्तः) {
		/* adjust return value for truncation */
		यावत् ((c = *src))
			dst += vis(tbuf, c, flag, *++src) - tbuf;
	}
	प्रत्यागम (dst - start);
}

#यदि 0 /* unused in OpenSSH */
पूर्णाङ्क
stravis(वर्ण **outp, ध्रुव वर्ण *src, पूर्णाङ्क flag)
{
	वर्ण *buf;
	पूर्णाङ्क len, serrno;

	buf = reallocarray(रिक्त, 4, वाक्यदैर्घ्यम्(src) + 1);
	यदि (buf == रिक्त)
		प्रत्यागम -1;
	len = strvis(buf, src, flag);
	serrno = errno;
	*outp = realloc(buf, len + 1);
	यदि (*outp == रिक्त) {
		*outp = buf;
		errno = serrno;
	}
	प्रत्यागम (len);
}

पूर्णाङ्क
strvisx(वर्ण *dst, ध्रुव वर्ण *src, आकार_t len, पूर्णाङ्क flag)
{
	वर्ण c;
	वर्ण *start;

	प्रति (start = dst; len > 1; len--) {
		c = *src;
		dst = vis(dst, c, flag, *++src);
	}
	यदि (len)
		dst = vis(dst, *src, flag, '\0');
	*dst = '\0';
	प्रत्यागम (dst - start);
}
#यदि_अन्तः /*अप्रयुक्तम्*/

#यदि_अन्तः
