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

#అన్తర్భావ "includes.h"

#నిర్వచితం_కాకపోతే HAVE_MEMMEM

#అన్తర్భావ <string.h>
#అన్తర్భావ <stdint.h>

స్థిర అక్షరం *
twobyte_memmem(స్థిరరాశి గుర్తులేని అక్షరం *h, కొలత_t k, స్థిరరాశి గుర్తులేని అక్షరం *n)
{
	uint16_t nw = n[0]<<8 | n[1], hw = h[0]<<8 | h[1];
	కొరకు (h+=2, k-=2; k; k--, hw = hw<<8 | *h++)
		ఒకవేళ (hw == nw) తిరిగి (అక్షరం *)h-2;
	తిరిగి hw == nw ? (అక్షరం *)h-2 : 0;
}

స్థిర అక్షరం *
threebyte_memmem(స్థిరరాశి గుర్తులేని అక్షరం *h, కొలత_t k, స్థిరరాశి గుర్తులేని అక్షరం *n)
{
	uint32_t nw = n[0]<<24 | n[1]<<16 | n[2]<<8;
	uint32_t hw = h[0]<<24 | h[1]<<16 | h[2]<<8;
	కొరకు (h+=3, k-=3; k; k--, hw = (hw|*h++)<<8)
		ఒకవేళ (hw == nw) తిరిగి (అక్షరం *)h-3;
	తిరిగి hw == nw ? (అక్షరం *)h-3 : 0;
}

స్థిర అక్షరం *
fourbyte_memmem(స్థిరరాశి గుర్తులేని అక్షరం *h, కొలత_t k, స్థిరరాశి గుర్తులేని అక్షరం *n)
{
	uint32_t nw = n[0]<<24 | n[1]<<16 | n[2]<<8 | n[3];
	uint32_t hw = h[0]<<24 | h[1]<<16 | h[2]<<8 | h[3];
	కొరకు (h+=4, k-=4; k; k--, hw = hw<<8 | *h++)
		ఒకవేళ (hw == nw) తిరిగి (అక్షరం *)h-4;
	తిరిగి hw == nw ? (అక్షరం *)h-4 : 0;
}

#ఒకవేళ 0
/* In -portable, defines.h ensures that these are already defined. */
#నిర్వచించు MAX(a,b) ((a)>(b)?(a):(b))
#నిర్వచించు MIN(a,b) ((a)<(b)?(a):(b))
#అయితే_ముగింపు

#నిర్వచించు BITOP(a,b,op) \
 ((a)[(కొలత_t)(b)/(8*పరిమాణం *(a))] op (కొలత_t)1<<((కొలత_t)(b)%(8*పరిమాణం *(a))))

/*
 * Maxime Crochemore and Dominique Perrin, Two-way string-matching,
 * Journal of the ACM, 38(3):651-675, July 1991.
 */
స్థిర అక్షరం *
twoway_memmem(స్థిరరాశి గుర్తులేని అక్షరం *h, స్థిరరాశి గుర్తులేని అక్షరం *z,
    స్థిరరాశి గుర్తులేని అక్షరం *n, కొలత_t l)
{
	కొలత_t i, ip, jp, k, p, ms, p0, mem, mem0;
	కొలత_t byteset[32 / పరిమాణం(కొలత_t)] = { 0 };
	కొలత_t జరుపు[256];

	/* Computing length of needle and fill shift table */
	కొరకు (i=0; i<l; i++)
		BITOP(byteset, n[i], |=), జరుపు[n[i]] = i+1;

	/* Compute maximal suffix */
	ip = -1; jp = 0; k = p = 1;
	అయితే (jp+k<l) {
		ఒకవేళ (n[ip+k] == n[jp+k]) {
			ఒకవేళ (k == p) {
				jp += p;
				k = 1;
			} లేకపోతే k++;
		} లేకపోతే ఒకవేళ (n[ip+k] > n[jp+k]) {
			jp += k;
			k = 1;
			p = jp - ip;
		} లేకపోతే {
			ip = jp++;
			k = p = 1;
		}
	}
	ms = ip;
	p0 = p;

	/* And with the opposite comparison */
	ip = -1; jp = 0; k = p = 1;
	అయితే (jp+k<l) {
		ఒకవేళ (n[ip+k] == n[jp+k]) {
			ఒకవేళ (k == p) {
				jp += p;
				k = 1;
			} లేకపోతే k++;
		} లేకపోతే ఒకవేళ (n[ip+k] < n[jp+k]) {
			jp += k;
			k = 1;
			p = jp - ip;
		} లేకపోతే {
			ip = jp++;
			k = p = 1;
		}
	}
	ఒకవేళ (ip+1 > ms+1) ms = ip;
	లేకపోతే p = p0;

	/* Periodic needle? */
	ఒకవేళ (memcmp(n, n+p, ms+1)) {
		mem0 = 0;
		p = MAX(ms, l-ms-1) + 1;
	} లేకపోతే mem0 = l-p;
	mem = 0;

	/* Search loop */
	కొరకు (;;) {
		/* If remainder of haystack is shorter than needle, done */
		ఒకవేళ (z-h < l) తిరిగి 0;

		/* Check last byte first; advance by shift on mismatch */
		ఒకవేళ (BITOP(byteset, h[l-1], &)) {
			k = l-జరుపు[h[l-1]];
			ఒకవేళ (k) {
				ఒకవేళ (k < mem) k = mem;
				h += k;
				mem = 0;
				కొనసాగు;
			}
		} లేకపోతే {
			h += l;
			mem = 0;
			కొనసాగు;
		}

		/* Compare right half */
		కొరకు (k=MAX(ms+1,mem); k<l && n[k] == h[k]; k++);
		ఒకవేళ (k < l) {
			h += k-ms;
			mem = 0;
			కొనసాగు;
		}
		/* Compare left half */
		కొరకు (k=ms+1; k>mem && n[k-1] == h[k-1]; k--);
		ఒకవేళ (k <= mem) తిరిగి (అక్షరం *)h;
		h += p;
		mem = mem0;
	}
}

శూన్య *
memmem(స్థిరరాశి శూన్య *h0, కొలత_t k, స్థిరరాశి శూన్య *n0, కొలత_t l)
{
	స్థిరరాశి గుర్తులేని అక్షరం *h = h0, *n = n0;

	/* Return immediately on empty needle */
	ఒకవేళ (!l) తిరిగి (శూన్య *)h;

	/* Return immediately when needle is longer than haystack */
	ఒకవేళ (k<l) తిరిగి 0;

	/* Use faster algorithms for short needles */
	h = memchr(h0, *n, k);
	ఒకవేళ (!h || l==1) తిరిగి (శూన్య *)h;
	k -= h - (స్థిరరాశి గుర్తులేని అక్షరం *)h0;
	ఒకవేళ (k<l) తిరిగి 0;
	ఒకవేళ (l==2) తిరిగి twobyte_memmem(h, k, n);
	ఒకవేళ (l==3) తిరిగి threebyte_memmem(h, k, n);
	ఒకవేళ (l==4) తిరిగి fourbyte_memmem(h, k, n);

	తిరిగి twoway_memmem(h, h+k, n, l);
}
DEF_WEAK(memmem);
#అయితే_ముగింపు /* HAVE_MEMMEM */
