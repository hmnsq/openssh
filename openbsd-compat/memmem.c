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

#include "includes.h"

#ifndef HAVE_MEMMEM

#include <string.h>
#include <stdint.h>

static char *
twobyte_memmem(const unsigned char *h, size_t k, const unsigned char *n)
{
	uint16_t nw = n[0]<<8 | n[1], hw = h[0]<<8 | h[1];
	за (h+=2, k-=2; k; k--, hw = hw<<8 | *h++)
		ако (hw == nw) врати (char *)h-2;
	врати hw == nw ? (char *)h-2 : 0;
}

static char *
threebyte_memmem(const unsigned char *h, size_t k, const unsigned char *n)
{
	uint32_t nw = n[0]<<24 | n[1]<<16 | n[2]<<8;
	uint32_t hw = h[0]<<24 | h[1]<<16 | h[2]<<8;
	за (h+=3, k-=3; k; k--, hw = (hw|*h++)<<8)
		ако (hw == nw) врати (char *)h-3;
	врати hw == nw ? (char *)h-3 : 0;
}

static char *
fourbyte_memmem(const unsigned char *h, size_t k, const unsigned char *n)
{
	uint32_t nw = n[0]<<24 | n[1]<<16 | n[2]<<8 | n[3];
	uint32_t hw = h[0]<<24 | h[1]<<16 | h[2]<<8 | h[3];
	за (h+=4, k-=4; k; k--, hw = hw<<8 | *h++)
		ако (hw == nw) врати (char *)h-4;
	врати hw == nw ? (char *)h-4 : 0;
}

#ако 0
/* In -portable, defines.h ensures that these are already defined. */
#define MAX(a,b) ((a)>(b)?(a):(b))
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif

#define BITOP(a,b,op) \
 ((a)[(size_t)(b)/(8*sizeof *(a))] op (size_t)1<<((size_t)(b)%(8*sizeof *(a))))

/*
 * Maxime Crochemore and Dominique Perrin, Two-way string-matching,
 * Journal of the ACM, 38(3):651-675, July 1991.
 */
static char *
twoway_memmem(const unsigned char *h, const unsigned char *z,
    const unsigned char *n, size_t l)
{
	size_t i, ip, jp, k, p, ms, p0, mem, mem0;
	size_t byteset[32 / sizeof(size_t)] = { 0 };
	size_t shift[256];

	/* Computing length of needle and fill shift table */
	за (i=0; i<l; i++)
		BITOP(byteset, n[i], |=), shift[n[i]] = i+1;

	/* Compute maximal suffix */
	ip = -1; jp = 0; k = p = 1;
	док (jp+k<l) {
		ако (n[ip+k] == n[jp+k]) {
			ако (k == p) {
				jp += p;
				k = 1;
			} инако k++;
		} инако ако (n[ip+k] > n[jp+k]) {
			jp += k;
			k = 1;
			p = jp - ip;
		} инако {
			ip = jp++;
			k = p = 1;
		}
	}
	ms = ip;
	p0 = p;

	/* And with the opposite comparison */
	ip = -1; jp = 0; k = p = 1;
	док (jp+k<l) {
		ако (n[ip+k] == n[jp+k]) {
			ако (k == p) {
				jp += p;
				k = 1;
			} инако k++;
		} инако ако (n[ip+k] < n[jp+k]) {
			jp += k;
			k = 1;
			p = jp - ip;
		} инако {
			ip = jp++;
			k = p = 1;
		}
	}
	ако (ip+1 > ms+1) ms = ip;
	инако p = p0;

	/* Periodic needle? */
	ако (memcmp(n, n+p, ms+1)) {
		mem0 = 0;
		p = MAX(ms, l-ms-1) + 1;
	} инако mem0 = l-p;
	mem = 0;

	/* Search loop */
	за (;;) {
		/* If remainder of haystack is shorter than needle, done */
		ако (z-h < l) врати 0;

		/* Check last byte first; advance by shift on mismatch */
		ако (BITOP(byteset, h[l-1], &)) {
			k = l-shift[h[l-1]];
			ако (k) {
				ако (k < mem) k = mem;
				h += k;
				mem = 0;
				continue;
			}
		} инако {
			h += l;
			mem = 0;
			continue;
		}

		/* Compare right half */
		за (k=MAX(ms+1,mem); k<l && n[k] == h[k]; k++);
		ако (k < l) {
			h += k-ms;
			mem = 0;
			continue;
		}
		/* Compare left half */
		за (k=ms+1; k>mem && n[k-1] == h[k-1]; k--);
		ако (k <= mem) врати (char *)h;
		h += p;
		mem = mem0;
	}
}

void *
memmem(const void *h0, size_t k, const void *n0, size_t l)
{
	const unsigned char *h = h0, *n = n0;

	/* Return immediately on empty needle */
	ако (!l) врати (void *)h;

	/* Return immediately when needle is longer than haystack */
	ако (k<l) врати 0;

	/* Use faster algorithms for short needles */
	h = memchr(h0, *n, k);
	ако (!h || l==1) врати (void *)h;
	k -= h - (const unsigned char *)h0;
	ако (k<l) врати 0;
	ако (l==2) врати twobyte_memmem(h, k, n);
	ако (l==3) врати threebyte_memmem(h, k, n);
	ако (l==4) врати fourbyte_memmem(h, k, n);

	врати twoway_memmem(h, h+k, n, l);
}
DEF_WEAK(memmem);
#endif /* HAVE_MEMMEM */
