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

#அந்தர்பாவ "includes.h"

#ifndef HAVE_INET_NTOP

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/socket.h>
#அந்தர்பாவ <netinet/in.h>
#அந்தர்பாவ <arpa/inet.h>
#அந்தர்பாவ <arpa/nameser.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <stdio.h>

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

நிலையான மாறிலி எழுத்து *inet_ntop4(மாறிலி u_char *src, எழுத்து *dst, size_t size);
நிலையான மாறிலி எழுத்து *inet_ntop6(மாறிலி u_char *src, எழுத்து *dst, size_t size);

/* char *
 * inet_ntop(af, src, dst, size)
 *	convert a network format address to presentation format.
 * return:
 *	pointer to presentation format address (`dst'), or NULL (see errno).
 * author:
 *	Paul Vixie, 1996.
 */
மாறிலி எழுத்து *
inet_ntop(முழு af, மாறிலி வெறுமை *src, எழுத்து *dst, socklen_t size)
{
	தேர்வு (af) {
	நிலை AF_INET:
		திரும்பு (inet_ntop4(src, dst, (size_t)size));
	நிலை AF_INET6:
		திரும்பு (inet_ntop6(src, dst, (size_t)size));
	இயல்பு:
		errno = EAFNOSUPPORT;
		திரும்பு (வெற்று);
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
நிலையான மாறிலி எழுத்து *
inet_ntop4(மாறிலி u_char *src, எழுத்து *dst, size_t size)
{
	நிலையான மாறிலி எழுத்து fmt[] = "%u.%u.%u.%u";
	எழுத்து tmp[அளவு "255.255.255.255"];
	முழு l;

	l = snprintf(tmp, size, fmt, src[0], src[1], src[2], src[3]);
	எனில் (l <= 0 || l >= size) {
		errno = ENOSPC;
		திரும்பு (வெற்று);
	}
	strlcpy(dst, tmp, size);
	திரும்பு (dst);
}

/* const char *
 * inet_ntop6(src, dst, size)
 *	convert IPv6 binary address into presentation (printable) format
 * author:
 *	Paul Vixie, 1996.
 */
நிலையான மாறிலி எழுத்து *
inet_ntop6(மாறிலி u_char *src, எழுத்து *dst, size_t size)
{
	/*
	 * Note that int32_t and int16_t need only be "at least" large enough
	 * to contain a value of the specified size.  On some systems, like
	 * Crays, there is no such thing as an integer variable with 16 bits.
	 * Keep this in mind if you think this function should have been coded
	 * to use pointer overlays.  All the world's not a VAX.
	 */
	எழுத்து tmp[அளவு "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"];
	எழுத்து *tp, *ep;
	கட்டமைப்பு { முழு base, len; } best, cur;
	u_int சொற்கள்[IN6ADDRSZ / INT16SZ];
	முழு i;
	முழு advance;

	/*
	 * Preprocess:
	 *	Copy the input (bytewise) array into a wordwise array.
	 *	Find the longest run of 0x00's in src[] for :: shorthanding.
	 */
	memset(சொற்கள், '\0', அளவு சொற்கள்);
	க்கு (i = 0; i < IN6ADDRSZ; i++)
		சொற்கள்[i / 2] |= (src[i] << ((1 - (i % 2)) << 3));
	best.base = -1;
	cur.base = -1;
	க்கு (i = 0; i < (IN6ADDRSZ / INT16SZ); i++) {
		எனில் (சொற்கள்[i] == 0) {
			எனில் (cur.base == -1)
				cur.base = i, cur.len = 1;
			இல்லையெனில்
				cur.len++;
		} இல்லையெனில் {
			எனில் (cur.base != -1) {
				எனில் (best.base == -1 || cur.len > best.len)
					best = cur;
				cur.base = -1;
			}
		}
	}
	எனில் (cur.base != -1) {
		எனில் (best.base == -1 || cur.len > best.len)
			best = cur;
	}
	எனில் (best.base != -1 && best.len < 2)
		best.base = -1;

	/*
	 * Format the result.
	 */
	tp = tmp;
	ep = tmp + அளவு(tmp);
	க்கு (i = 0; i < (IN6ADDRSZ / INT16SZ) && tp < ep; i++) {
		/* Are we inside the best run of 0x00's? */
		எனில் (best.base != -1 && i >= best.base &&
		    i < (best.base + best.len)) {
			எனில் (i == best.base) {
				எனில் (tp + 1 >= ep)
					திரும்பு (வெற்று);
				*tp++ = ':';
			}
			தொடர்;
		}
		/* Are we following an initial run of 0x00s or any real hex? */
		எனில் (i != 0) {
			எனில் (tp + 1 >= ep)
				திரும்பு (வெற்று);
			*tp++ = ':';
		}
		/* Is this address an encapsulated IPv4? */
		எனில் (i == 6 && best.base == 0 &&
		    (best.len == 6 || (best.len == 5 && சொற்கள்[5] == 0xffff))) {
			எனில் (!inet_ntop4(src+12, tp, (size_t)(ep - tp)))
				திரும்பு (வெற்று);
			tp += strlen(tp);
			நிறுத்து;
		}
		advance = snprintf(tp, ep - tp, "%x", சொற்கள்[i]);
		எனில் (advance <= 0 || advance >= ep - tp)
			திரும்பு (வெற்று);
		tp += advance;
	}
	/* Was it a trailing run of 0x00's? */
	எனில் (best.base != -1 && (best.base + best.len) == (IN6ADDRSZ / INT16SZ)) {
		எனில் (tp + 1 >= ep)
			திரும்பு (வெற்று);
		*tp++ = ':';
	}
	எனில் (tp + 1 >= ep)
		திரும்பு (வெற்று);
	*tp++ = '\0';

	/*
	 * Check for overflow, copy, and we're done.
	 */
	எனில் ((size_t)(tp - tmp) > size) {
		errno = ENOSPC;
		திரும்பு (வெற்று);
	}
	strlcpy(dst, tmp, size);
	திரும்பு (dst);
}

#endif /* !HAVE_INET_NTOP */
