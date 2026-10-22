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

#అన్తర్భావ "includes.h"

#నిర్వచితం_కాకపోతే HAVE_INET_NTOP

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/socket.h>
#అన్తర్భావ <netinet/in.h>
#అన్తర్భావ <arpa/inet.h>
#అన్తర్భావ <arpa/nameser.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <errno.h>
#అన్తర్భావ <stdio.h>

#నిర్వచితం_కాకపోతే IN6ADDRSZ
#నిర్వచించు IN6ADDRSZ   16   /* IPv6 T_AAAA */                 
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే INT16SZ
#నిర్వచించు INT16SZ     2    /* for systems without 16-bit ints */
#అయితే_ముగింపు

/*
 * WARNING: Don't even consider trying to compile this on a system where
 * sizeof(int) < 4.  sizeof(int) > 4 is fine; all the world's not a VAX.
 */

స్థిర స్థిరరాశి అక్షరం *inet_ntop4(స్థిరరాశి u_char *src, అక్షరం *dst, కొలత_t కొలత);
స్థిర స్థిరరాశి అక్షరం *inet_ntop6(స్థిరరాశి u_char *src, అక్షరం *dst, కొలత_t కొలత);

/* char *
 * inet_ntop(af, src, dst, size)
 *	convert a network format address to presentation format.
 * return:
 *	pointer to presentation format address (`dst'), or NULL (see errno).
 * author:
 *	Paul Vixie, 1996.
 */
స్థిరరాశి అక్షరం *
inet_ntop(పూర్ణాంకం af, స్థిరరాశి శూన్య *src, అక్షరం *dst, socklen_t కొలత)
{
	ఎంపిక (af) {
	స్థితి AF_INET:
		తిరిగి (inet_ntop4(src, dst, (కొలత_t)కొలత));
	స్థితి AF_INET6:
		తిరిగి (inet_ntop6(src, dst, (కొలత_t)కొలత));
	అప్రమేయ:
		errno = EAFNOSUPPORT;
		తిరిగి (ఖాళీ);
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
స్థిర స్థిరరాశి అక్షరం *
inet_ntop4(స్థిరరాశి u_char *src, అక్షరం *dst, కొలత_t కొలత)
{
	స్థిర స్థిరరాశి అక్షరం fmt[] = "%u.%u.%u.%u";
	అక్షరం tmp[పరిమాణం "255.255.255.255"];
	పూర్ణాంకం l;

	l = snprintf(tmp, కొలత, fmt, src[0], src[1], src[2], src[3]);
	ఒకవేళ (l <= 0 || l >= కొలత) {
		errno = ENOSPC;
		తిరిగి (ఖాళీ);
	}
	strlcpy(dst, tmp, కొలత);
	తిరిగి (dst);
}

/* const char *
 * inet_ntop6(src, dst, size)
 *	convert IPv6 binary address into presentation (printable) format
 * author:
 *	Paul Vixie, 1996.
 */
స్థిర స్థిరరాశి అక్షరం *
inet_ntop6(స్థిరరాశి u_char *src, అక్షరం *dst, కొలత_t కొలత)
{
	/*
	 * Note that int32_t and int16_t need only be "at least" large enough
	 * to contain a value of the specified size.  On some systems, like
	 * Crays, there is no such thing as an integer variable with 16 bits.
	 * Keep this in mind if you think this function should have been coded
	 * to use pointer overlays.  All the world's not a VAX.
	 */
	అక్షరం tmp[పరిమాణం "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"];
	అక్షరం *tp, *ep;
	నిర్మాణం { పూర్ణాంకం పునాది, len; } ఉత్తమ, cur;
	u_int పదాలు[IN6ADDRSZ / INT16SZ];
	పూర్ణాంకం i;
	పూర్ణాంకం advance;

	/*
	 * Preprocess:
	 *	Copy the input (bytewise) array into a wordwise array.
	 *	Find the longest run of 0x00's in src[] for :: shorthanding.
	 */
	memset(పదాలు, '\0', పరిమాణం పదాలు);
	కొరకు (i = 0; i < IN6ADDRSZ; i++)
		పదాలు[i / 2] |= (src[i] << ((1 - (i % 2)) << 3));
	ఉత్తమ.పునాది = -1;
	cur.పునాది = -1;
	కొరకు (i = 0; i < (IN6ADDRSZ / INT16SZ); i++) {
		ఒకవేళ (పదాలు[i] == 0) {
			ఒకవేళ (cur.పునాది == -1)
				cur.పునాది = i, cur.len = 1;
			లేకపోతే
				cur.len++;
		} లేకపోతే {
			ఒకవేళ (cur.పునాది != -1) {
				ఒకవేళ (ఉత్తమ.పునాది == -1 || cur.len > ఉత్తమ.len)
					ఉత్తమ = cur;
				cur.పునాది = -1;
			}
		}
	}
	ఒకవేళ (cur.పునాది != -1) {
		ఒకవేళ (ఉత్తమ.పునాది == -1 || cur.len > ఉత్తమ.len)
			ఉత్తమ = cur;
	}
	ఒకవేళ (ఉత్తమ.పునాది != -1 && ఉత్తమ.len < 2)
		ఉత్తమ.పునాది = -1;

	/*
	 * Format the result.
	 */
	tp = tmp;
	ep = tmp + పరిమాణం(tmp);
	కొరకు (i = 0; i < (IN6ADDRSZ / INT16SZ) && tp < ep; i++) {
		/* Are we inside the best run of 0x00's? */
		ఒకవేళ (ఉత్తమ.పునాది != -1 && i >= ఉత్తమ.పునాది &&
		    i < (ఉత్తమ.పునాది + ఉత్తమ.len)) {
			ఒకవేళ (i == ఉత్తమ.పునాది) {
				ఒకవేళ (tp + 1 >= ep)
					తిరిగి (ఖాళీ);
				*tp++ = ':';
			}
			కొనసాగు;
		}
		/* Are we following an initial run of 0x00s or any real hex? */
		ఒకవేళ (i != 0) {
			ఒకవేళ (tp + 1 >= ep)
				తిరిగి (ఖాళీ);
			*tp++ = ':';
		}
		/* Is this address an encapsulated IPv4? */
		ఒకవేళ (i == 6 && ఉత్తమ.పునాది == 0 &&
		    (ఉత్తమ.len == 6 || (ఉత్తమ.len == 5 && పదాలు[5] == 0xffff))) {
			ఒకవేళ (!inet_ntop4(src+12, tp, (కొలత_t)(ep - tp)))
				తిరిగి (ఖాళీ);
			tp += అక్షరశ్రేణి_పొడవు(tp);
			ఆపు;
		}
		advance = snprintf(tp, ep - tp, "%x", పదాలు[i]);
		ఒకవేళ (advance <= 0 || advance >= ep - tp)
			తిరిగి (ఖాళీ);
		tp += advance;
	}
	/* Was it a trailing run of 0x00's? */
	ఒకవేళ (ఉత్తమ.పునాది != -1 && (ఉత్తమ.పునాది + ఉత్తమ.len) == (IN6ADDRSZ / INT16SZ)) {
		ఒకవేళ (tp + 1 >= ep)
			తిరిగి (ఖాళీ);
		*tp++ = ':';
	}
	ఒకవేళ (tp + 1 >= ep)
		తిరిగి (ఖాళీ);
	*tp++ = '\0';

	/*
	 * Check for overflow, copy, and we're done.
	 */
	ఒకవేళ ((కొలత_t)(tp - tmp) > కొలత) {
		errno = ENOSPC;
		తిరిగి (ఖాళీ);
	}
	strlcpy(dst, tmp, కొలత);
	తిరిగి (dst);
}

#అయితే_ముగింపు /* !HAVE_INET_NTOP */
