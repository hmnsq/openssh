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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ifndef HAVE_INET_NTOP

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>
#ಅನ್ತರ್ಭಾವ <netinet/in.h>
#ಅನ್ತರ್ಭಾವ <arpa/inet.h>
#ಅನ್ತರ್ಭಾವ <arpa/nameser.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>

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

ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ *inet_ntop4(ಧ್ರುವ u_char *src, ವರ್ಣ *dst, size_t size);
ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ *inet_ntop6(ಧ್ರುವ u_char *src, ವರ್ಣ *dst, size_t size);

/* char *
 * inet_ntop(af, src, dst, size)
 *	convert a network format address to presentation format.
 * return:
 *	pointer to presentation format address (`dst'), or NULL (see errno).
 * author:
 *	Paul Vixie, 1996.
 */
ಧ್ರುವ ವರ್ಣ *
inet_ntop(ಪೂರ್ಣಾಙ್ಕ af, ಧ್ರುವ ಶೂನ್ಯ *src, ವರ್ಣ *dst, socklen_t size)
{
	ವಿಕಲ್ಪ (af) {
	ಪಕ್ಷ AF_INET:
		ಪ್ರತ್ಯಾಗಮ (inet_ntop4(src, dst, (size_t)size));
	ಪಕ್ಷ AF_INET6:
		ಪ್ರತ್ಯಾಗಮ (inet_ntop6(src, dst, (size_t)size));
	ಸ್ವಭಾವ:
		errno = EAFNOSUPPORT;
		ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
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
ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ *
inet_ntop4(ಧ್ರುವ u_char *src, ವರ್ಣ *dst, size_t size)
{
	ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ fmt[] = "%u.%u.%u.%u";
	ವರ್ಣ tmp[ಪರಿಮಾಣ "255.255.255.255"];
	ಪೂರ್ಣಾಙ್ಕ l;

	l = snprintf(tmp, size, fmt, src[0], src[1], src[2], src[3]);
	ಯದಿ (l <= 0 || l >= size) {
		errno = ENOSPC;
		ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
	}
	strlcpy(dst, tmp, size);
	ಪ್ರತ್ಯಾಗಮ (dst);
}

/* const char *
 * inet_ntop6(src, dst, size)
 *	convert IPv6 binary address into presentation (printable) format
 * author:
 *	Paul Vixie, 1996.
 */
ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ *
inet_ntop6(ಧ್ರುವ u_char *src, ವರ್ಣ *dst, size_t size)
{
	/*
	 * Note that int32_t and int16_t need only be "at least" large enough
	 * to contain a value of the specified size.  On some systems, like
	 * Crays, there is no such thing as an integer variable with 16 bits.
	 * Keep this in mind if you think this function should have been coded
	 * to use pointer overlays.  All the world's not a VAX.
	 */
	ವರ್ಣ tmp[ಪರಿಮಾಣ "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"];
	ವರ್ಣ *tp, *ep;
	ಸಂರಚನಾ { ಪೂರ್ಣಾಙ್ಕ base, len; } best, cur;
	u_int ಪದಗಳು[IN6ADDRSZ / INT16SZ];
	ಪೂರ್ಣಾಙ್ಕ i;
	ಪೂರ್ಣಾಙ್ಕ advance;

	/*
	 * Preprocess:
	 *	Copy the input (bytewise) array into a wordwise array.
	 *	Find the longest run of 0x00's in src[] for :: shorthanding.
	 */
	memset(ಪದಗಳು, '\0', ಪರಿಮಾಣ ಪದಗಳು);
	ಪ್ರತಿ (i = 0; i < IN6ADDRSZ; i++)
		ಪದಗಳು[i / 2] |= (src[i] << ((1 - (i % 2)) << 3));
	best.base = -1;
	cur.base = -1;
	ಪ್ರತಿ (i = 0; i < (IN6ADDRSZ / INT16SZ); i++) {
		ಯದಿ (ಪದಗಳು[i] == 0) {
			ಯದಿ (cur.base == -1)
				cur.base = i, cur.len = 1;
			ಅನ್ಯಥಾ
				cur.len++;
		} ಅನ್ಯಥಾ {
			ಯದಿ (cur.base != -1) {
				ಯದಿ (best.base == -1 || cur.len > best.len)
					best = cur;
				cur.base = -1;
			}
		}
	}
	ಯದಿ (cur.base != -1) {
		ಯದಿ (best.base == -1 || cur.len > best.len)
			best = cur;
	}
	ಯದಿ (best.base != -1 && best.len < 2)
		best.base = -1;

	/*
	 * Format the result.
	 */
	tp = tmp;
	ep = tmp + ಪರಿಮಾಣ(tmp);
	ಪ್ರತಿ (i = 0; i < (IN6ADDRSZ / INT16SZ) && tp < ep; i++) {
		/* Are we inside the best run of 0x00's? */
		ಯದಿ (best.base != -1 && i >= best.base &&
		    i < (best.base + best.len)) {
			ಯದಿ (i == best.base) {
				ಯದಿ (tp + 1 >= ep)
					ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
				*tp++ = ':';
			}
			ಅನುವರ್ತ;
		}
		/* Are we following an initial run of 0x00s or any real hex? */
		ಯದಿ (i != 0) {
			ಯದಿ (tp + 1 >= ep)
				ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
			*tp++ = ':';
		}
		/* Is this address an encapsulated IPv4? */
		ಯದಿ (i == 6 && best.base == 0 &&
		    (best.len == 6 || (best.len == 5 && ಪದಗಳು[5] == 0xffff))) {
			ಯದಿ (!inet_ntop4(src+12, tp, (size_t)(ep - tp)))
				ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
			tp += strlen(tp);
			ಭಙ್ಗ;
		}
		advance = snprintf(tp, ep - tp, "%x", ಪದಗಳು[i]);
		ಯದಿ (advance <= 0 || advance >= ep - tp)
			ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
		tp += advance;
	}
	/* Was it a trailing run of 0x00's? */
	ಯದಿ (best.base != -1 && (best.base + best.len) == (IN6ADDRSZ / INT16SZ)) {
		ಯದಿ (tp + 1 >= ep)
			ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
		*tp++ = ':';
	}
	ಯದಿ (tp + 1 >= ep)
		ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
	*tp++ = '\0';

	/*
	 * Check for overflow, copy, and we're done.
	 */
	ಯದಿ ((size_t)(tp - tmp) > size) {
		errno = ENOSPC;
		ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
	}
	strlcpy(dst, tmp, size);
	ಪ್ರತ್ಯಾಗಮ (dst);
}

#endif /* !HAVE_INET_NTOP */
