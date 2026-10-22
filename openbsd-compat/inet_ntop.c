/*	$OpenBSD: inet_ntop.c,v 1.8 2008/12/09 19:38:38 otto Exp $	*/

/* Copyright (c) 1996 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

/* OPENBSD ORIGINAL: lib/libc/net/inet_ntop.c */

#അന്തര്ഭാവ "includes.h"

#ifndef HAVE_INET_NTOP

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/socket.h>
#അന്തര്ഭാവ <netinet/in.h>
#അന്തര്ഭാവ <arpa/inet.h>
#അന്തര്ഭാവ <arpa/nameser.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <stdio.h>

#ifndef IN6ADDRSZ
#define IN6ADDRSZ   16   /* IPv6 T_AAAA */                 
#endif

#ifndef INT16SZ
#define INT16SZ     2    /* for systems without 16-bit ints */
#endif

/*
 * WARNING: Don't even consider trying to compile this on a system where
 * sizeof(int) < 4.  sizeof(int) > 4 is fine; all the world's not a VAX.
 */

സ്ഥിതം സ്ഥിരം അക്ഷരം *inet_ntop4(സ്ഥിരം u_char *src, അക്ഷരം *dst, size_t size);
സ്ഥിതം സ്ഥിരം അക്ഷരം *inet_ntop6(സ്ഥിരം u_char *src, അക്ഷരം *dst, size_t size);

/* char *
 * inet_ntop(af, src, dst, size)
 *	convert a network format address to presentation format.
 * return:
 *	pointer to presentation format address (`dst'), or NULL (see errno).
 * author:
 *	Paul Vixie, 1996.
 */
സ്ഥിരം അക്ഷരം *
inet_ntop(പൂർണ്ണസംഖ്യ af, സ്ഥിരം ശൂന്യം *src, അക്ഷരം *dst, socklen_t size)
{
	തിരഞ്ഞെടുപ്പ് (af) {
	അവസ്ഥ AF_INET:
		തിരികെ (inet_ntop4(src, dst, (size_t)size));
	അവസ്ഥ AF_INET6:
		തിരികെ (inet_ntop6(src, dst, (size_t)size));
	സ്ഥിരസ്ഥിതി:
		errno = EAFNOSUPPORT;
		തിരികെ (ശൂന്യ);
	}
	/* NOTREACHED */
}

/* const char *
 * inet_ntop4(src, dst, size)
 *	format an IPv4 address, more or less like inet_ntoa()
 * return:
 *	`dst' (as a const)
 * notes:
 *	(1) uses no statics
 *	(2) takes a u_char* not an in_addr as input
 * author:
 *	Paul Vixie, 1996.
 */
സ്ഥിതം സ്ഥിരം അക്ഷരം *
inet_ntop4(സ്ഥിരം u_char *src, അക്ഷരം *dst, size_t size)
{
	സ്ഥിതം സ്ഥിരം അക്ഷരം fmt[] = "%u.%u.%u.%u";
	അക്ഷരം tmp[വലുപ്പം "255.255.255.255"];
	പൂർണ്ണസംഖ്യ l;

	l = snprintf(tmp, size, fmt, src[0], src[1], src[2], src[3]);
	എങ്കിൽ (l <= 0 || l >= size) {
		errno = ENOSPC;
		തിരികെ (ശൂന്യ);
	}
	strlcpy(dst, tmp, size);
	തിരികെ (dst);
}

/* const char *
 * inet_ntop6(src, dst, size)
 *	convert IPv6 binary address into presentation (printable) format
 * author:
 *	Paul Vixie, 1996.
 */
സ്ഥിതം സ്ഥിരം അക്ഷരം *
inet_ntop6(സ്ഥിരം u_char *src, അക്ഷരം *dst, size_t size)
{
	/*
	 * Note that int32_t and int16_t need only be "at least" large enough
	 * to contain a value of the specified size.  On some systems, like
	 * Crays, there is no such thing as an integer variable with 16 bits.
	 * Keep this in mind if you think this function should have been coded
	 * to use pointer overlays.  All the world's not a VAX.
	 */
	അക്ഷരം tmp[വലുപ്പം "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"];
	അക്ഷരം *tp, *ep;
	ഘടന { പൂർണ്ണസംഖ്യ base, len; } best, cur;
	u_int വാക്കുകൾ[IN6ADDRSZ / INT16SZ];
	പൂർണ്ണസംഖ്യ i;
	പൂർണ്ണസംഖ്യ advance;

	/*
	 * Preprocess:
	 *	Copy the input (bytewise) array into a wordwise array.
	 *	Find the longest run of 0x00's in src[] for :: shorthanding.
	 */
	memset(വാക്കുകൾ, '\0', വലുപ്പം വാക്കുകൾ);
	വേണ്ടി (i = 0; i < IN6ADDRSZ; i++)
		വാക്കുകൾ[i / 2] |= (src[i] << ((1 - (i % 2)) << 3));
	best.base = -1;
	cur.base = -1;
	വേണ്ടി (i = 0; i < (IN6ADDRSZ / INT16SZ); i++) {
		എങ്കിൽ (വാക്കുകൾ[i] == 0) {
			എങ്കിൽ (cur.base == -1)
				cur.base = i, cur.len = 1;
			അല്ലെങ്കിൽ
				cur.len++;
		} അല്ലെങ്കിൽ {
			എങ്കിൽ (cur.base != -1) {
				എങ്കിൽ (best.base == -1 || cur.len > best.len)
					best = cur;
				cur.base = -1;
			}
		}
	}
	എങ്കിൽ (cur.base != -1) {
		എങ്കിൽ (best.base == -1 || cur.len > best.len)
			best = cur;
	}
	എങ്കിൽ (best.base != -1 && best.len < 2)
		best.base = -1;

	/*
	 * Format the result.
	 */
	tp = tmp;
	ep = tmp + വലുപ്പം(tmp);
	വേണ്ടി (i = 0; i < (IN6ADDRSZ / INT16SZ) && tp < ep; i++) {
		/* Are we inside the best run of 0x00's? */
		എങ്കിൽ (best.base != -1 && i >= best.base &&
		    i < (best.base + best.len)) {
			എങ്കിൽ (i == best.base) {
				എങ്കിൽ (tp + 1 >= ep)
					തിരികെ (ശൂന്യ);
				*tp++ = ':';
			}
			തുടരുക;
		}
		/* Are we following an initial run of 0x00s or any real hex? */
		എങ്കിൽ (i != 0) {
			എങ്കിൽ (tp + 1 >= ep)
				തിരികെ (ശൂന്യ);
			*tp++ = ':';
		}
		/* Is this address an encapsulated IPv4? */
		എങ്കിൽ (i == 6 && best.base == 0 &&
		    (best.len == 6 || (best.len == 5 && വാക്കുകൾ[5] == 0xffff))) {
			എങ്കിൽ (!inet_ntop4(src+12, tp, (size_t)(ep - tp)))
				തിരികെ (ശൂന്യ);
			tp += strlen(tp);
			നിർത്തുക;
		}
		advance = snprintf(tp, ep - tp, "%x", വാക്കുകൾ[i]);
		എങ്കിൽ (advance <= 0 || advance >= ep - tp)
			തിരികെ (ശൂന്യ);
		tp += advance;
	}
	/* Was it a trailing run of 0x00's? */
	എങ്കിൽ (best.base != -1 && (best.base + best.len) == (IN6ADDRSZ / INT16SZ)) {
		എങ്കിൽ (tp + 1 >= ep)
			തിരികെ (ശൂന്യ);
		*tp++ = ':';
	}
	എങ്കിൽ (tp + 1 >= ep)
		തിരികെ (ശൂന്യ);
	*tp++ = '\0';

	/*
	 * Check for overflow, copy, and we're done.
	 */
	എങ്കിൽ ((size_t)(tp - tmp) > size) {
		errno = ENOSPC;
		തിരികെ (ശൂന്യ);
	}
	strlcpy(dst, tmp, size);
	തിരികെ (dst);
}

#endif /* !HAVE_INET_NTOP */
