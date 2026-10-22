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

#ଅନ୍ତର୍ଭାଵ "includes.h"
#ଯଦି !defined(HAVE_STRNVIS) || defined(BROKEN_STRNVIS)

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <ctype.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>

#ଅନ୍ତର୍ଭାଵ "vis.h"

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
ଅକ୍ଷର *
vis(ଅକ୍ଷର *dst, ପୂର୍ଣ୍ଣସଂଖ୍ୟା c, ପୂର୍ଣ୍ଣସଂଖ୍ୟା flag, ପୂର୍ଣ୍ଣସଂଖ୍ୟା nextc)
{
	ଯଦି (isvisible(c, flag)) {
		ଯଦି ((c == '"' && (flag & VIS_DQ) != 0) ||
		    (c == '\\' && (flag & VIS_NOSLASH) == 0))
			*dst++ = '\\';
		*dst++ = c;
		*dst = '\0';
		ଫେରନ୍ତୁ (dst);
	}

	ଯଦି (flag & VIS_CSTYLE) {
		ବାଛ(c) {
		ସ୍ଥିତି '\n':
			*dst++ = '\\';
			*dst++ = 'n';
			ଯାଅ done;
		ସ୍ଥିତି '\r':
			*dst++ = '\\';
			*dst++ = 'r';
			ଯାଅ done;
		ସ୍ଥିତି '\b':
			*dst++ = '\\';
			*dst++ = 'b';
			ଯାଅ done;
		ସ୍ଥିତି '\a':
			*dst++ = '\\';
			*dst++ = 'a';
			ଯାଅ done;
		ସ୍ଥିତି '\v':
			*dst++ = '\\';
			*dst++ = 'v';
			ଯାଅ done;
		ସ୍ଥିତି '\t':
			*dst++ = '\\';
			*dst++ = 't';
			ଯାଅ done;
		ସ୍ଥିତି '\f':
			*dst++ = '\\';
			*dst++ = 'f';
			ଯାଅ done;
		ସ୍ଥିତି ' ':
			*dst++ = '\\';
			*dst++ = 's';
			ଯାଅ done;
		ସ୍ଥିତି '\0':
			*dst++ = '\\';
			*dst++ = '0';
			ଯଦି (isoctal(nextc)) {
				*dst++ = '0';
				*dst++ = '0';
			}
			ଯାଅ done;
		}
	}
	ଯଦି (((c & 0177) == ' ') || (flag & VIS_OCTAL) ||
	    ((flag & VIS_GLOB) && (c == '*' || c == '?' || c == '[' || c == '#'))) {
		*dst++ = '\\';
		*dst++ = ((u_char)c >> 6 & 07) + '0';
		*dst++ = ((u_char)c >> 3 & 07) + '0';
		*dst++ = ((u_char)c & 07) + '0';
		ଯାଅ done;
	}
	ଯଦି ((flag & VIS_NOSLASH) == 0)
		*dst++ = '\\';
	ଯଦି (c & 0200) {
		c &= 0177;
		*dst++ = 'M';
	}
	ଯଦି (iscntrl((u_char)c)) {
		*dst++ = '^';
		ଯଦି (c == 0177)
			*dst++ = '?';
		ଅନ୍ୟଥା
			*dst++ = c + '@';
	} ଅନ୍ୟଥା {
		*dst++ = '-';
		*dst++ = c;
	}
done:
	*dst = '\0';
	ଫେରନ୍ତୁ (dst);
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
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
strvis(ଅକ୍ଷର *dst, ଅଚଳ ଅକ୍ଷର *src, ପୂର୍ଣ୍ଣସଂଖ୍ୟା flag)
{
	ଅକ୍ଷର c;
	ଅକ୍ଷର *start;

	ପାଇଁ (start = dst; (c = *src);)
		dst = vis(dst, c, flag, *++src);
	*dst = '\0';
	ଫେରନ୍ତୁ (dst - start);
}
DEF_WEAK(strvis);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
strnvis(ଅକ୍ଷର *dst, ଅଚଳ ଅକ୍ଷର *src, size_t siz, ପୂର୍ଣ୍ଣସଂଖ୍ୟା flag)
{
	ଅକ୍ଷର *start, *end;
	ଅକ୍ଷର tbuf[5];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା c, i;

	i = 0;
	ପାଇଁ (start = dst, end = start + siz - 1; (c = *src) && dst < end; ) {
		ଯଦି (isvisible(c, flag)) {
			ଯଦି ((c == '"' && (flag & VIS_DQ) != 0) ||
			    (c == '\\' && (flag & VIS_NOSLASH) == 0)) {
				/* need space for the extra '\\' */
				ଯଦି (dst + 1 >= end) {
					i = 2;
					ଭାଙ୍ଗ;
				}
				*dst++ = '\\';
			}
			i = 1;
			*dst++ = c;
			src++;
		} ଅନ୍ୟଥା {
			i = vis(tbuf, c, flag, *++src) - tbuf;
			ଯଦି (dst + i <= end) {
				memcpy(dst, tbuf, i);
				dst += i;
			} ଅନ୍ୟଥା {
				src--;
				ଭାଙ୍ଗ;
			}
		}
	}
	ଯଦି (siz > 0)
		*dst = '\0';
	ଯଦି (dst + i > end) {
		/* adjust return value for truncation */
		ଯେତେବେଳେ ((c = *src))
			dst += vis(tbuf, c, flag, *++src) - tbuf;
	}
	ଫେରନ୍ତୁ (dst - start);
}

#ଯଦି 0 /* unused in OpenSSH */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
stravis(ଅକ୍ଷର **outp, ଅଚଳ ଅକ୍ଷର *src, ପୂର୍ଣ୍ଣସଂଖ୍ୟା flag)
{
	ଅକ୍ଷର *buf;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା len, serrno;

	buf = reallocarray(ଖାଲି, 4, strlen(src) + 1);
	ଯଦି (buf == ଖାଲି)
		ଫେରନ୍ତୁ -1;
	len = strvis(buf, src, flag);
	serrno = errno;
	*outp = realloc(buf, len + 1);
	ଯଦି (*outp == ଖାଲି) {
		*outp = buf;
		errno = serrno;
	}
	ଫେରନ୍ତୁ (len);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
strvisx(ଅକ୍ଷର *dst, ଅଚଳ ଅକ୍ଷର *src, size_t len, ପୂର୍ଣ୍ଣସଂଖ୍ୟା flag)
{
	ଅକ୍ଷର c;
	ଅକ୍ଷର *start;

	ପାଇଁ (start = dst; len > 1; len--) {
		c = *src;
		dst = vis(dst, c, flag, *++src);
	}
	ଯଦି (len)
		dst = vis(dst, *src, flag, '\0');
	*dst = '\0';
	ଫେରନ୍ତୁ (dst - start);
}
#endif /* unused */

#endif
