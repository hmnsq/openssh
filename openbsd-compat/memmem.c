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

#અન્તર્ભાવ "includes.h"

#ifndef HAVE_MEMMEM

#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <stdint.h>

સ્થિર અક્ષર *
twobyte_memmem(અચલ unsigned અક્ષર *h, size_t k, અચલ unsigned અક્ષર *n)
{
	uint16_t nw = n[0]<<8 | n[1], hw = h[0]<<8 | h[1];
	માટે (h+=2, k-=2; k; k--, hw = hw<<8 | *h++)
		જો (hw == nw) પાછા (અક્ષર *)h-2;
	પાછા hw == nw ? (અક્ષર *)h-2 : 0;
}

સ્થિર અક્ષર *
threebyte_memmem(અચલ unsigned અક્ષર *h, size_t k, અચલ unsigned અક્ષર *n)
{
	uint32_t nw = n[0]<<24 | n[1]<<16 | n[2]<<8;
	uint32_t hw = h[0]<<24 | h[1]<<16 | h[2]<<8;
	માટે (h+=3, k-=3; k; k--, hw = (hw|*h++)<<8)
		જો (hw == nw) પાછા (અક્ષર *)h-3;
	પાછા hw == nw ? (અક્ષર *)h-3 : 0;
}

સ્થિર અક્ષર *
fourbyte_memmem(અચલ unsigned અક્ષર *h, size_t k, અચલ unsigned અક્ષર *n)
{
	uint32_t nw = n[0]<<24 | n[1]<<16 | n[2]<<8 | n[3];
	uint32_t hw = h[0]<<24 | h[1]<<16 | h[2]<<8 | h[3];
	માટે (h+=4, k-=4; k; k--, hw = hw<<8 | *h++)
		જો (hw == nw) પાછા (અક્ષર *)h-4;
	પાછા hw == nw ? (અક્ષર *)h-4 : 0;
}

#જો 0
/* In -portable, defines.h ensures that these are already defined. */
#define MAX(a,b) ((a)>(b)?(a):(b))
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif

#define BITOP(a,b,op) \
 ((a)[(size_t)(b)/(8*કદ *(a))] op (size_t)1<<((size_t)(b)%(8*કદ *(a))))

/*
 * Maxime Crochemore and Dominique Perrin, Two-way string-matching,
 * Journal of the ACM, 38(3):651-675, July 1991.
 */
સ્થિર અક્ષર *
twoway_memmem(અચલ unsigned અક્ષર *h, અચલ unsigned અક્ષર *z,
    અચલ unsigned અક્ષર *n, size_t l)
{
	size_t i, ip, jp, k, p, ms, p0, mem, mem0;
	size_t byteset[32 / કદ(size_t)] = { 0 };
	size_t shift[256];

	/* Computing length of needle and fill shift table */
	માટે (i=0; i<l; i++)
		BITOP(byteset, n[i], |=), shift[n[i]] = i+1;

	/* Compute maximal suffix */
	ip = -1; jp = 0; k = p = 1;
	જ્યારે (jp+k<l) {
		જો (n[ip+k] == n[jp+k]) {
			જો (k == p) {
				jp += p;
				k = 1;
			} નહીંતર k++;
		} નહીંતર જો (n[ip+k] > n[jp+k]) {
			jp += k;
			k = 1;
			p = jp - ip;
		} નહીંતર {
			ip = jp++;
			k = p = 1;
		}
	}
	ms = ip;
	p0 = p;

	/* And with the opposite comparison */
	ip = -1; jp = 0; k = p = 1;
	જ્યારે (jp+k<l) {
		જો (n[ip+k] == n[jp+k]) {
			જો (k == p) {
				jp += p;
				k = 1;
			} નહીંતર k++;
		} નહીંતર જો (n[ip+k] < n[jp+k]) {
			jp += k;
			k = 1;
			p = jp - ip;
		} નહીંતર {
			ip = jp++;
			k = p = 1;
		}
	}
	જો (ip+1 > ms+1) ms = ip;
	નહીંતર p = p0;

	/* Periodic needle? */
	જો (memcmp(n, n+p, ms+1)) {
		mem0 = 0;
		p = MAX(ms, l-ms-1) + 1;
	} નહીંતર mem0 = l-p;
	mem = 0;

	/* Search loop */
	માટે (;;) {
		/* If remainder of haystack is shorter than needle, done */
		જો (z-h < l) પાછા 0;

		/* Check last byte first; advance by shift on mismatch */
		જો (BITOP(byteset, h[l-1], &)) {
			k = l-shift[h[l-1]];
			જો (k) {
				જો (k < mem) k = mem;
				h += k;
				mem = 0;
				ચાલુ;
			}
		} નહીંતર {
			h += l;
			mem = 0;
			ચાલુ;
		}

		/* Compare right half */
		માટે (k=MAX(ms+1,mem); k<l && n[k] == h[k]; k++);
		જો (k < l) {
			h += k-ms;
			mem = 0;
			ચાલુ;
		}
		/* Compare left half */
		માટે (k=ms+1; k>mem && n[k-1] == h[k-1]; k--);
		જો (k <= mem) પાછા (અક્ષર *)h;
		h += p;
		mem = mem0;
	}
}

શૂન્ય *
memmem(અચલ શૂન્ય *h0, size_t k, અચલ શૂન્ય *n0, size_t l)
{
	અચલ unsigned અક્ષર *h = h0, *n = n0;

	/* Return immediately on empty needle */
	જો (!l) પાછા (શૂન્ય *)h;

	/* Return immediately when needle is longer than haystack */
	જો (k<l) પાછા 0;

	/* Use faster algorithms for short needles */
	h = memchr(h0, *n, k);
	જો (!h || l==1) પાછા (શૂન્ય *)h;
	k -= h - (અચલ unsigned અક્ષર *)h0;
	જો (k<l) પાછા 0;
	જો (l==2) પાછા twobyte_memmem(h, k, n);
	જો (l==3) પાછા threebyte_memmem(h, k, n);
	જો (l==4) પાછા fourbyte_memmem(h, k, n);

	પાછા twoway_memmem(h, h+k, n, l);
}
DEF_WEAK(memmem);
#endif /* HAVE_MEMMEM */
