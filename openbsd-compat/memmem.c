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

static var_na *
twobyte_memmem(const unsigned var_na *h, size_t k, const unsigned var_na *n)
{
	uint16_t nw = n[0]<<8 | n[1], hw = h[0]<<8 | h[1];
	ꦏꦁꦒꦺꦴ (h+=2, k-=2; k; k--, hw = hw<<8 | *h++)
		ꦪꦼꦤ꧀ (hw == nw) ꦮꦭꦶ (var_na *)h-2;
	ꦮꦭꦶ hw == nw ? (var_na *)h-2 : 0;
}

static var_na *
threebyte_memmem(const unsigned var_na *h, size_t k, const unsigned var_na *n)
{
	uint32_t nw = n[0]<<24 | n[1]<<16 | n[2]<<8;
	uint32_t hw = h[0]<<24 | h[1]<<16 | h[2]<<8;
	ꦏꦁꦒꦺꦴ (h+=3, k-=3; k; k--, hw = (hw|*h++)<<8)
		ꦪꦼꦤ꧀ (hw == nw) ꦮꦭꦶ (var_na *)h-3;
	ꦮꦭꦶ hw == nw ? (var_na *)h-3 : 0;
}

static var_na *
fourbyte_memmem(const unsigned var_na *h, size_t k, const unsigned var_na *n)
{
	uint32_t nw = n[0]<<24 | n[1]<<16 | n[2]<<8 | n[3];
	uint32_t hw = h[0]<<24 | h[1]<<16 | h[2]<<8 | h[3];
	ꦏꦁꦒꦺꦴ (h+=4, k-=4; k; k--, hw = hw<<8 | *h++)
		ꦪꦼꦤ꧀ (hw == nw) ꦮꦭꦶ (var_na *)h-4;
	ꦮꦭꦶ hw == nw ? (var_na *)h-4 : 0;
}

#ꦪꦼꦤ꧀ 0
/* In -portable, defines.h ensures that these are already defined. */
#define MAX(a,b) ((a)>(b)?(a):(b))
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif

#define BITOP(a,b,op) \
 ((a)[(size_t)(b)/(8*parimaa_na *(a))] op (size_t)1<<((size_t)(b)%(8*parimaa_na *(a))))

/*
 * Maxime Crochemore and Dominique Perrin, Two-way string-matching,
 * Journal of the ACM, 38(3):651-675, July 1991.
 */
static var_na *
twoway_memmem(const unsigned var_na *h, const unsigned var_na *z,
    const unsigned var_na *n, size_t l)
{
	size_t i, ip, jp, k, p, ms, p0, mem, mem0;
	size_t byteset[32 / parimaa_na(size_t)] = { 0 };
	size_t shift[256];

	/* Computing length of needle and fill shift table */
	ꦏꦁꦒꦺꦴ (i=0; i<l; i++)
		BITOP(byteset, n[i], |=), shift[n[i]] = i+1;

	/* Compute maximal suffix */
	ip = -1; jp = 0; k = p = 1;
	ꦱꦼꦢꦼꦭ (jp+k<l) {
		ꦪꦼꦤ꧀ (n[ip+k] == n[jp+k]) {
			ꦪꦼꦤ꧀ (k == p) {
				jp += p;
				k = 1;
			} ꦭꦶꦪ k++;
		} ꦭꦶꦪ ꦪꦼꦤ꧀ (n[ip+k] > n[jp+k]) {
			jp += k;
			k = 1;
			p = jp - ip;
		} ꦭꦶꦪ {
			ip = jp++;
			k = p = 1;
		}
	}
	ms = ip;
	p0 = p;

	/* And with the opposite comparison */
	ip = -1; jp = 0; k = p = 1;
	ꦱꦼꦢꦼꦭ (jp+k<l) {
		ꦪꦼꦤ꧀ (n[ip+k] == n[jp+k]) {
			ꦪꦼꦤ꧀ (k == p) {
				jp += p;
				k = 1;
			} ꦭꦶꦪ k++;
		} ꦭꦶꦪ ꦪꦼꦤ꧀ (n[ip+k] < n[jp+k]) {
			jp += k;
			k = 1;
			p = jp - ip;
		} ꦭꦶꦪ {
			ip = jp++;
			k = p = 1;
		}
	}
	ꦪꦼꦤ꧀ (ip+1 > ms+1) ms = ip;
	ꦭꦶꦪ p = p0;

	/* Periodic needle? */
	ꦪꦼꦤ꧀ (memcmp(n, n+p, ms+1)) {
		mem0 = 0;
		p = MAX(ms, l-ms-1) + 1;
	} ꦭꦶꦪ mem0 = l-p;
	mem = 0;

	/* Search loop */
	ꦏꦁꦒꦺꦴ (;;) {
		/* If remainder of haystack is shorter than needle, done */
		ꦪꦼꦤ꧀ (z-h < l) ꦮꦭꦶ 0;

		/* Check last byte first; advance by shift on mismatch */
		ꦪꦼꦤ꧀ (BITOP(byteset, h[l-1], &)) {
			k = l-shift[h[l-1]];
			ꦪꦼꦤ꧀ (k) {
				ꦪꦼꦤ꧀ (k < mem) k = mem;
				h += k;
				mem = 0;
				continue;
			}
		} ꦭꦶꦪ {
			h += l;
			mem = 0;
			continue;
		}

		/* Compare right half */
		ꦏꦁꦒꦺꦴ (k=MAX(ms+1,mem); k<l && n[k] == h[k]; k++);
		ꦪꦼꦤ꧀ (k < l) {
			h += k-ms;
			mem = 0;
			continue;
		}
		/* Compare left half */
		ꦏꦁꦒꦺꦴ (k=ms+1; k>mem && n[k-1] == h[k-1]; k--);
		ꦪꦼꦤ꧀ (k <= mem) ꦮꦭꦶ (var_na *)h;
		h += p;
		mem = mem0;
	}
}

void *
memmem(const void *h0, size_t k, const void *n0, size_t l)
{
	const unsigned var_na *h = h0, *n = n0;

	/* Return immediately on empty needle */
	ꦪꦼꦤ꧀ (!l) ꦮꦭꦶ (void *)h;

	/* Return immediately when needle is longer than haystack */
	ꦪꦼꦤ꧀ (k<l) ꦮꦭꦶ 0;

	/* Use faster algorithms for short needles */
	h = memchr(h0, *n, k);
	ꦪꦼꦤ꧀ (!h || l==1) ꦮꦭꦶ (void *)h;
	k -= h - (const unsigned var_na *)h0;
	ꦪꦼꦤ꧀ (k<l) ꦮꦭꦶ 0;
	ꦪꦼꦤ꧀ (l==2) ꦮꦭꦶ twobyte_memmem(h, k, n);
	ꦪꦼꦤ꧀ (l==3) ꦮꦭꦶ threebyte_memmem(h, k, n);
	ꦪꦼꦤ꧀ (l==4) ꦮꦭꦶ fourbyte_memmem(h, k, n);

	ꦮꦭꦶ twoway_memmem(h, h+k, n, l);
}
DEF_WEAK(memmem);
#endif /* HAVE_MEMMEM */
