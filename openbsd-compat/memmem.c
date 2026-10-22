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

#அந்தர்பாவ "includes.h"

#ifndef HAVE_MEMMEM

#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdint.h>

நிலையான எழுத்து *
twobyte_memmem(மாறிலி unsigned எழுத்து *h, size_t k, மாறிலி unsigned எழுத்து *n)
{
	uint16_t nw = n[0]<<8 | n[1], hw = h[0]<<8 | h[1];
	க்கு (h+=2, k-=2; k; k--, hw = hw<<8 | *h++)
		எனில் (hw == nw) திரும்பு (எழுத்து *)h-2;
	திரும்பு hw == nw ? (எழுத்து *)h-2 : 0;
}

நிலையான எழுத்து *
threebyte_memmem(மாறிலி unsigned எழுத்து *h, size_t k, மாறிலி unsigned எழுத்து *n)
{
	uint32_t nw = n[0]<<24 | n[1]<<16 | n[2]<<8;
	uint32_t hw = h[0]<<24 | h[1]<<16 | h[2]<<8;
	க்கு (h+=3, k-=3; k; k--, hw = (hw|*h++)<<8)
		எனில் (hw == nw) திரும்பு (எழுத்து *)h-3;
	திரும்பு hw == nw ? (எழுத்து *)h-3 : 0;
}

நிலையான எழுத்து *
fourbyte_memmem(மாறிலி unsigned எழுத்து *h, size_t k, மாறிலி unsigned எழுத்து *n)
{
	uint32_t nw = n[0]<<24 | n[1]<<16 | n[2]<<8 | n[3];
	uint32_t hw = h[0]<<24 | h[1]<<16 | h[2]<<8 | h[3];
	க்கு (h+=4, k-=4; k; k--, hw = hw<<8 | *h++)
		எனில் (hw == nw) திரும்பு (எழுத்து *)h-4;
	திரும்பு hw == nw ? (எழுத்து *)h-4 : 0;
}

#எனில் 0
/* In -portable, defines.h ensures that these are already defined. */
#define MAX(a,b) ((a)>(b)?(a):(b))
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif

#define BITOP(a,b,op) \
 ((a)[(size_t)(b)/(8*அளவு *(a))] op (size_t)1<<((size_t)(b)%(8*அளவு *(a))))

/*
 * Maxime Crochemore and Dominique Perrin, Two-way string-matching,
 * Journal of the ACM, 38(3):651-675, July 1991.
 */
நிலையான எழுத்து *
twoway_memmem(மாறிலி unsigned எழுத்து *h, மாறிலி unsigned எழுத்து *z,
    மாறிலி unsigned எழுத்து *n, size_t l)
{
	size_t i, ip, jp, k, p, ms, p0, mem, mem0;
	size_t byteset[32 / அளவு(size_t)] = { 0 };
	size_t shift[256];

	/* Computing length of needle and fill shift table */
	க்கு (i=0; i<l; i++)
		BITOP(byteset, n[i], |=), shift[n[i]] = i+1;

	/* Compute maximal suffix */
	ip = -1; jp = 0; k = p = 1;
	போது (jp+k<l) {
		எனில் (n[ip+k] == n[jp+k]) {
			எனில் (k == p) {
				jp += p;
				k = 1;
			} இல்லையெனில் k++;
		} இல்லையெனில் எனில் (n[ip+k] > n[jp+k]) {
			jp += k;
			k = 1;
			p = jp - ip;
		} இல்லையெனில் {
			ip = jp++;
			k = p = 1;
		}
	}
	ms = ip;
	p0 = p;

	/* And with the opposite comparison */
	ip = -1; jp = 0; k = p = 1;
	போது (jp+k<l) {
		எனில் (n[ip+k] == n[jp+k]) {
			எனில் (k == p) {
				jp += p;
				k = 1;
			} இல்லையெனில் k++;
		} இல்லையெனில் எனில் (n[ip+k] < n[jp+k]) {
			jp += k;
			k = 1;
			p = jp - ip;
		} இல்லையெனில் {
			ip = jp++;
			k = p = 1;
		}
	}
	எனில் (ip+1 > ms+1) ms = ip;
	இல்லையெனில் p = p0;

	/* Periodic needle? */
	எனில் (memcmp(n, n+p, ms+1)) {
		mem0 = 0;
		p = MAX(ms, l-ms-1) + 1;
	} இல்லையெனில் mem0 = l-p;
	mem = 0;

	/* Search loop */
	க்கு (;;) {
		/* If remainder of haystack is shorter than needle, done */
		எனில் (z-h < l) திரும்பு 0;

		/* Check last byte first; advance by shift on mismatch */
		எனில் (BITOP(byteset, h[l-1], &)) {
			k = l-shift[h[l-1]];
			எனில் (k) {
				எனில் (k < mem) k = mem;
				h += k;
				mem = 0;
				தொடர்;
			}
		} இல்லையெனில் {
			h += l;
			mem = 0;
			தொடர்;
		}

		/* Compare right half */
		க்கு (k=MAX(ms+1,mem); k<l && n[k] == h[k]; k++);
		எனில் (k < l) {
			h += k-ms;
			mem = 0;
			தொடர்;
		}
		/* Compare left half */
		க்கு (k=ms+1; k>mem && n[k-1] == h[k-1]; k--);
		எனில் (k <= mem) திரும்பு (எழுத்து *)h;
		h += p;
		mem = mem0;
	}
}

வெறுமை *
memmem(மாறிலி வெறுமை *h0, size_t k, மாறிலி வெறுமை *n0, size_t l)
{
	மாறிலி unsigned எழுத்து *h = h0, *n = n0;

	/* Return immediately on empty needle */
	எனில் (!l) திரும்பு (வெறுமை *)h;

	/* Return immediately when needle is longer than haystack */
	எனில் (k<l) திரும்பு 0;

	/* Use faster algorithms for short needles */
	h = memchr(h0, *n, k);
	எனில் (!h || l==1) திரும்பு (வெறுமை *)h;
	k -= h - (மாறிலி unsigned எழுத்து *)h0;
	எனில் (k<l) திரும்பு 0;
	எனில் (l==2) திரும்பு twobyte_memmem(h, k, n);
	எனில் (l==3) திரும்பு threebyte_memmem(h, k, n);
	எனில் (l==4) திரும்பு fourbyte_memmem(h, k, n);

	திரும்பு twoway_memmem(h, h+k, n, l);
}
DEF_WEAK(memmem);
#endif /* HAVE_MEMMEM */
