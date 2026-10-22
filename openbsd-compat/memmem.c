/*	$OpenBSD: memmem.c,v 1.5 2020/04/16 12:39:28 claudio Exp $ */

/*
 * Copyright (c) 2005-2020 Rich Felker, et al.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/* OPENBSD ORIGINAL: lib/libc/string/memmem.c */

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ifndef HAVE_MEMMEM

#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>

ସ୍ଥିର ଅକ୍ଷର *
twobyte_memmem(ଅଚଳ unsigned ଅକ୍ଷର *h, size_t k, ଅଚଳ unsigned ଅକ୍ଷର *n)
{
	uint16_t nw = n[0]<<8 | n[1], hw = h[0]<<8 | h[1];
	ପାଇଁ (h+=2, k-=2; k; k--, hw = hw<<8 | *h++)
		ଯଦି (hw == nw) ଫେରନ୍ତୁ (ଅକ୍ଷର *)h-2;
	ଫେରନ୍ତୁ hw == nw ? (ଅକ୍ଷର *)h-2 : 0;
}

ସ୍ଥିର ଅକ୍ଷର *
threebyte_memmem(ଅଚଳ unsigned ଅକ୍ଷର *h, size_t k, ଅଚଳ unsigned ଅକ୍ଷର *n)
{
	uint32_t nw = n[0]<<24 | n[1]<<16 | n[2]<<8;
	uint32_t hw = h[0]<<24 | h[1]<<16 | h[2]<<8;
	ପାଇଁ (h+=3, k-=3; k; k--, hw = (hw|*h++)<<8)
		ଯଦି (hw == nw) ଫେରନ୍ତୁ (ଅକ୍ଷର *)h-3;
	ଫେରନ୍ତୁ hw == nw ? (ଅକ୍ଷର *)h-3 : 0;
}

ସ୍ଥିର ଅକ୍ଷର *
fourbyte_memmem(ଅଚଳ unsigned ଅକ୍ଷର *h, size_t k, ଅଚଳ unsigned ଅକ୍ଷର *n)
{
	uint32_t nw = n[0]<<24 | n[1]<<16 | n[2]<<8 | n[3];
	uint32_t hw = h[0]<<24 | h[1]<<16 | h[2]<<8 | h[3];
	ପାଇଁ (h+=4, k-=4; k; k--, hw = hw<<8 | *h++)
		ଯଦି (hw == nw) ଫେରନ୍ତୁ (ଅକ୍ଷର *)h-4;
	ଫେରନ୍ତୁ hw == nw ? (ଅକ୍ଷର *)h-4 : 0;
}

#ଯଦି 0
/* In -portable, defines.h ensures that these are already defined. */
#define MAX(a,b) ((a)>(b)?(a):(b))
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif

#define BITOP(a,b,op) \
 ((a)[(size_t)(b)/(8*ଆକାର *(a))] op (size_t)1<<((size_t)(b)%(8*ଆକାର *(a))))

/*
 * Maxime Crochemore and Dominique Perrin, Two-way string-matching,
 * Journal of the ACM, 38(3):651-675, July 1991.
 */
ସ୍ଥିର ଅକ୍ଷର *
twoway_memmem(ଅଚଳ unsigned ଅକ୍ଷର *h, ଅଚଳ unsigned ଅକ୍ଷର *z,
    ଅଚଳ unsigned ଅକ୍ଷର *n, size_t l)
{
	size_t i, ip, jp, k, p, ms, p0, mem, mem0;
	size_t byteset[32 / ଆକାର(size_t)] = { 0 };
	size_t shift[256];

	/* Computing length of needle and fill shift table */
	ପାଇଁ (i=0; i<l; i++)
		BITOP(byteset, n[i], |=), shift[n[i]] = i+1;

	/* Compute maximal suffix */
	ip = -1; jp = 0; k = p = 1;
	ଯେତେବେଳେ (jp+k<l) {
		ଯଦି (n[ip+k] == n[jp+k]) {
			ଯଦି (k == p) {
				jp += p;
				k = 1;
			} ଅନ୍ୟଥା k++;
		} ଅନ୍ୟଥା ଯଦି (n[ip+k] > n[jp+k]) {
			jp += k;
			k = 1;
			p = jp - ip;
		} ଅନ୍ୟଥା {
			ip = jp++;
			k = p = 1;
		}
	}
	ms = ip;
	p0 = p;

	/* And with the opposite comparison */
	ip = -1; jp = 0; k = p = 1;
	ଯେତେବେଳେ (jp+k<l) {
		ଯଦି (n[ip+k] == n[jp+k]) {
			ଯଦି (k == p) {
				jp += p;
				k = 1;
			} ଅନ୍ୟଥା k++;
		} ଅନ୍ୟଥା ଯଦି (n[ip+k] < n[jp+k]) {
			jp += k;
			k = 1;
			p = jp - ip;
		} ଅନ୍ୟଥା {
			ip = jp++;
			k = p = 1;
		}
	}
	ଯଦି (ip+1 > ms+1) ms = ip;
	ଅନ୍ୟଥା p = p0;

	/* Periodic needle? */
	ଯଦି (memcmp(n, n+p, ms+1)) {
		mem0 = 0;
		p = MAX(ms, l-ms-1) + 1;
	} ଅନ୍ୟଥା mem0 = l-p;
	mem = 0;

	/* Search loop */
	ପାଇଁ (;;) {
		/* If remainder of haystack is shorter than needle, done */
		ଯଦି (z-h < l) ଫେରନ୍ତୁ 0;

		/* Check last byte first; advance by shift on mismatch */
		ଯଦି (BITOP(byteset, h[l-1], &)) {
			k = l-shift[h[l-1]];
			ଯଦି (k) {
				ଯଦି (k < mem) k = mem;
				h += k;
				mem = 0;
				ଜାରି;
			}
		} ଅନ୍ୟଥା {
			h += l;
			mem = 0;
			ଜାରି;
		}

		/* Compare right half */
		ପାଇଁ (k=MAX(ms+1,mem); k<l && n[k] == h[k]; k++);
		ଯଦି (k < l) {
			h += k-ms;
			mem = 0;
			ଜାରି;
		}
		/* Compare left half */
		ପାଇଁ (k=ms+1; k>mem && n[k-1] == h[k-1]; k--);
		ଯଦି (k <= mem) ଫେରନ୍ତୁ (ଅକ୍ଷର *)h;
		h += p;
		mem = mem0;
	}
}

ଶୂନ୍ୟ *
memmem(ଅଚଳ ଶୂନ୍ୟ *h0, size_t k, ଅଚଳ ଶୂନ୍ୟ *n0, size_t l)
{
	ଅଚଳ unsigned ଅକ୍ଷର *h = h0, *n = n0;

	/* Return immediately on empty needle */
	ଯଦି (!l) ଫେରନ୍ତୁ (ଶୂନ୍ୟ *)h;

	/* Return immediately when needle is longer than haystack */
	ଯଦି (k<l) ଫେରନ୍ତୁ 0;

	/* Use faster algorithms for short needles */
	h = memchr(h0, *n, k);
	ଯଦି (!h || l==1) ଫେରନ୍ତୁ (ଶୂନ୍ୟ *)h;
	k -= h - (ଅଚଳ unsigned ଅକ୍ଷର *)h0;
	ଯଦି (k<l) ଫେରନ୍ତୁ 0;
	ଯଦି (l==2) ଫେରନ୍ତୁ twobyte_memmem(h, k, n);
	ଯଦି (l==3) ଫେରନ୍ତୁ threebyte_memmem(h, k, n);
	ଯଦି (l==4) ଫେରନ୍ତୁ fourbyte_memmem(h, k, n);

	ଫେରନ୍ତୁ twoway_memmem(h, h+k, n, l);
}
DEF_WEAK(memmem);
#endif /* HAVE_MEMMEM */
