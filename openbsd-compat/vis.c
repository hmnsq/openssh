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

#അന്തര്ഭാവ "includes.h"
#എങ്കിൽ !defined(HAVE_STRNVIS) || defined(BROKEN_STRNVIS)

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <ctype.h>
#അന്തര്ഭാവ <limits.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <stdlib.h>

#അന്തര്ഭാവ "vis.h"

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
അക്ഷരം *
vis(അക്ഷരം *dst, പൂർണ്ണസംഖ്യ c, പൂർണ്ണസംഖ്യ flag, പൂർണ്ണസംഖ്യ nextc)
{
	എങ്കിൽ (isvisible(c, flag)) {
		എങ്കിൽ ((c == '"' && (flag & VIS_DQ) != 0) ||
		    (c == '\\' && (flag & VIS_NOSLASH) == 0))
			*dst++ = '\\';
		*dst++ = c;
		*dst = '\0';
		തിരികെ (dst);
	}

	എങ്കിൽ (flag & VIS_CSTYLE) {
		തിരഞ്ഞെടുപ്പ്(c) {
		അവസ്ഥ '\n':
			*dst++ = '\\';
			*dst++ = 'n';
			പോകുക done;
		അവസ്ഥ '\r':
			*dst++ = '\\';
			*dst++ = 'r';
			പോകുക done;
		അവസ്ഥ '\b':
			*dst++ = '\\';
			*dst++ = 'b';
			പോകുക done;
		അവസ്ഥ '\a':
			*dst++ = '\\';
			*dst++ = 'a';
			പോകുക done;
		അവസ്ഥ '\v':
			*dst++ = '\\';
			*dst++ = 'v';
			പോകുക done;
		അവസ്ഥ '\t':
			*dst++ = '\\';
			*dst++ = 't';
			പോകുക done;
		അവസ്ഥ '\f':
			*dst++ = '\\';
			*dst++ = 'f';
			പോകുക done;
		അവസ്ഥ ' ':
			*dst++ = '\\';
			*dst++ = 's';
			പോകുക done;
		അവസ്ഥ '\0':
			*dst++ = '\\';
			*dst++ = '0';
			എങ്കിൽ (isoctal(nextc)) {
				*dst++ = '0';
				*dst++ = '0';
			}
			പോകുക done;
		}
	}
	എങ്കിൽ (((c & 0177) == ' ') || (flag & VIS_OCTAL) ||
	    ((flag & VIS_GLOB) && (c == '*' || c == '?' || c == '[' || c == '#'))) {
		*dst++ = '\\';
		*dst++ = ((u_char)c >> 6 & 07) + '0';
		*dst++ = ((u_char)c >> 3 & 07) + '0';
		*dst++ = ((u_char)c & 07) + '0';
		പോകുക done;
	}
	എങ്കിൽ ((flag & VIS_NOSLASH) == 0)
		*dst++ = '\\';
	എങ്കിൽ (c & 0200) {
		c &= 0177;
		*dst++ = 'M';
	}
	എങ്കിൽ (iscntrl((u_char)c)) {
		*dst++ = '^';
		എങ്കിൽ (c == 0177)
			*dst++ = '?';
		അല്ലെങ്കിൽ
			*dst++ = c + '@';
	} അല്ലെങ്കിൽ {
		*dst++ = '-';
		*dst++ = c;
	}
done:
	*dst = '\0';
	തിരികെ (dst);
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
പൂർണ്ണസംഖ്യ
strvis(അക്ഷരം *dst, സ്ഥിരം അക്ഷരം *src, പൂർണ്ണസംഖ്യ flag)
{
	അക്ഷരം c;
	അക്ഷരം *start;

	വേണ്ടി (start = dst; (c = *src);)
		dst = vis(dst, c, flag, *++src);
	*dst = '\0';
	തിരികെ (dst - start);
}
DEF_WEAK(strvis);

പൂർണ്ണസംഖ്യ
strnvis(അക്ഷരം *dst, സ്ഥിരം അക്ഷരം *src, size_t siz, പൂർണ്ണസംഖ്യ flag)
{
	അക്ഷരം *start, *end;
	അക്ഷരം tbuf[5];
	പൂർണ്ണസംഖ്യ c, i;

	i = 0;
	വേണ്ടി (start = dst, end = start + siz - 1; (c = *src) && dst < end; ) {
		എങ്കിൽ (isvisible(c, flag)) {
			എങ്കിൽ ((c == '"' && (flag & VIS_DQ) != 0) ||
			    (c == '\\' && (flag & VIS_NOSLASH) == 0)) {
				/* need space for the extra '\\' */
				എങ്കിൽ (dst + 1 >= end) {
					i = 2;
					നിർത്തുക;
				}
				*dst++ = '\\';
			}
			i = 1;
			*dst++ = c;
			src++;
		} അല്ലെങ്കിൽ {
			i = vis(tbuf, c, flag, *++src) - tbuf;
			എങ്കിൽ (dst + i <= end) {
				memcpy(dst, tbuf, i);
				dst += i;
			} അല്ലെങ്കിൽ {
				src--;
				നിർത്തുക;
			}
		}
	}
	എങ്കിൽ (siz > 0)
		*dst = '\0';
	എങ്കിൽ (dst + i > end) {
		/* adjust return value for truncation */
		ആകുമ്പോൾ ((c = *src))
			dst += vis(tbuf, c, flag, *++src) - tbuf;
	}
	തിരികെ (dst - start);
}

#എങ്കിൽ 0 /* unused in OpenSSH */
പൂർണ്ണസംഖ്യ
stravis(അക്ഷരം **outp, സ്ഥിരം അക്ഷരം *src, പൂർണ്ണസംഖ്യ flag)
{
	അക്ഷരം *buf;
	പൂർണ്ണസംഖ്യ len, serrno;

	buf = reallocarray(ശൂന്യ, 4, strlen(src) + 1);
	എങ്കിൽ (buf == ശൂന്യ)
		തിരികെ -1;
	len = strvis(buf, src, flag);
	serrno = errno;
	*outp = realloc(buf, len + 1);
	എങ്കിൽ (*outp == ശൂന്യ) {
		*outp = buf;
		errno = serrno;
	}
	തിരികെ (len);
}

പൂർണ്ണസംഖ്യ
strvisx(അക്ഷരം *dst, സ്ഥിരം അക്ഷരം *src, size_t len, പൂർണ്ണസംഖ്യ flag)
{
	അക്ഷരം c;
	അക്ഷരം *start;

	വേണ്ടി (start = dst; len > 1; len--) {
		c = *src;
		dst = vis(dst, c, flag, *++src);
	}
	എങ്കിൽ (len)
		dst = vis(dst, *src, flag, '\0');
	*dst = '\0';
	തിരികെ (dst - start);
}
#endif /* unused */

#endif
