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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_MEMMEM

#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>

ಸ್ಥಿರ ಅಕ್ಷರ *
twobyte_memmem(ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *h, ಗಾತ್ರ_t k, ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *n)
{
	uint16_t nw = n[0]<<8 | n[1], hw = h[0]<<8 | h[1];
	ಗಾಗಿ (h+=2, k-=2; k; k--, hw = hw<<8 | *h++)
		ಆದರೆ (hw == nw) ಹಿಂತಿರುಗಿ (ಅಕ್ಷರ *)h-2;
	ಹಿಂತಿರುಗಿ hw == nw ? (ಅಕ್ಷರ *)h-2 : 0;
}

ಸ್ಥಿರ ಅಕ್ಷರ *
threebyte_memmem(ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *h, ಗಾತ್ರ_t k, ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *n)
{
	uint32_t nw = n[0]<<24 | n[1]<<16 | n[2]<<8;
	uint32_t hw = h[0]<<24 | h[1]<<16 | h[2]<<8;
	ಗಾಗಿ (h+=3, k-=3; k; k--, hw = (hw|*h++)<<8)
		ಆದರೆ (hw == nw) ಹಿಂತಿರುಗಿ (ಅಕ್ಷರ *)h-3;
	ಹಿಂತಿರುಗಿ hw == nw ? (ಅಕ್ಷರ *)h-3 : 0;
}

ಸ್ಥಿರ ಅಕ್ಷರ *
fourbyte_memmem(ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *h, ಗಾತ್ರ_t k, ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *n)
{
	uint32_t nw = n[0]<<24 | n[1]<<16 | n[2]<<8 | n[3];
	uint32_t hw = h[0]<<24 | h[1]<<16 | h[2]<<8 | h[3];
	ಗಾಗಿ (h+=4, k-=4; k; k--, hw = hw<<8 | *h++)
		ಆದರೆ (hw == nw) ಹಿಂತಿರುಗಿ (ಅಕ್ಷರ *)h-4;
	ಹಿಂತಿರುಗಿ hw == nw ? (ಅಕ್ಷರ *)h-4 : 0;
}

#ಆದರೆ 0
/* In -portable, defines.h ensures that these are already defined. */
#ವ್ಯಾಖ್ಯಾನಿಸು MAX(a,b) ((a)>(b)?(a):(b))
#ವ್ಯಾಖ್ಯಾನಿಸು MIN(a,b) ((a)<(b)?(a):(b))
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿಸು BITOP(a,b,op) \
 ((a)[(ಗಾತ್ರ_t)(b)/(8*ಗಾತ್ರ *(a))] op (ಗಾತ್ರ_t)1<<((ಗಾತ್ರ_t)(b)%(8*ಗಾತ್ರ *(a))))

/*
 * Maxime Crochemore and Dominique Perrin, Two-way string-matching,
 * Journal of the ACM, 38(3):651-675, July 1991.
 */
ಸ್ಥಿರ ಅಕ್ಷರ *
twoway_memmem(ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *h, ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *z,
    ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *n, ಗಾತ್ರ_t l)
{
	ಗಾತ್ರ_t i, ip, jp, k, p, ms, p0, mem, mem0;
	ಗಾತ್ರ_t byteset[32 / ಗಾತ್ರ(ಗಾತ್ರ_t)] = { 0 };
	ಗಾತ್ರ_t ಸರಿಸು[256];

	/* Computing length of needle and fill shift table */
	ಗಾಗಿ (i=0; i<l; i++)
		BITOP(byteset, n[i], |=), ಸರಿಸು[n[i]] = i+1;

	/* Compute maximal suffix */
	ip = -1; jp = 0; k = p = 1;
	ಆಗ (jp+k<l) {
		ಆದರೆ (n[ip+k] == n[jp+k]) {
			ಆದರೆ (k == p) {
				jp += p;
				k = 1;
			} ಇಲ್ಲದಿದ್ದರೆ k++;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (n[ip+k] > n[jp+k]) {
			jp += k;
			k = 1;
			p = jp - ip;
		} ಇಲ್ಲದಿದ್ದರೆ {
			ip = jp++;
			k = p = 1;
		}
	}
	ms = ip;
	p0 = p;

	/* And with the opposite comparison */
	ip = -1; jp = 0; k = p = 1;
	ಆಗ (jp+k<l) {
		ಆದರೆ (n[ip+k] == n[jp+k]) {
			ಆದರೆ (k == p) {
				jp += p;
				k = 1;
			} ಇಲ್ಲದಿದ್ದರೆ k++;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (n[ip+k] < n[jp+k]) {
			jp += k;
			k = 1;
			p = jp - ip;
		} ಇಲ್ಲದಿದ್ದರೆ {
			ip = jp++;
			k = p = 1;
		}
	}
	ಆದರೆ (ip+1 > ms+1) ms = ip;
	ಇಲ್ಲದಿದ್ದರೆ p = p0;

	/* Periodic needle? */
	ಆದರೆ (memcmp(n, n+p, ms+1)) {
		mem0 = 0;
		p = MAX(ms, l-ms-1) + 1;
	} ಇಲ್ಲದಿದ್ದರೆ mem0 = l-p;
	mem = 0;

	/* Search loop */
	ಗಾಗಿ (;;) {
		/* If remainder of haystack is shorter than needle, done */
		ಆದರೆ (z-h < l) ಹಿಂತಿರುಗಿ 0;

		/* Check last byte first; advance by shift on mismatch */
		ಆದರೆ (BITOP(byteset, h[l-1], &)) {
			k = l-ಸರಿಸು[h[l-1]];
			ಆದರೆ (k) {
				ಆದರೆ (k < mem) k = mem;
				h += k;
				mem = 0;
				ಮುಂದುವರಿ;
			}
		} ಇಲ್ಲದಿದ್ದರೆ {
			h += l;
			mem = 0;
			ಮುಂದುವರಿ;
		}

		/* Compare right half */
		ಗಾಗಿ (k=MAX(ms+1,mem); k<l && n[k] == h[k]; k++);
		ಆದರೆ (k < l) {
			h += k-ms;
			mem = 0;
			ಮುಂದುವರಿ;
		}
		/* Compare left half */
		ಗಾಗಿ (k=ms+1; k>mem && n[k-1] == h[k-1]; k--);
		ಆದರೆ (k <= mem) ಹಿಂತಿರುಗಿ (ಅಕ್ಷರ *)h;
		h += p;
		mem = mem0;
	}
}

ಶೂನ್ಯ *
memmem(ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *h0, ಗಾತ್ರ_t k, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *n0, ಗಾತ್ರ_t l)
{
	ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *h = h0, *n = n0;

	/* Return immediately on empty needle */
	ಆದರೆ (!l) ಹಿಂತಿರುಗಿ (ಶೂನ್ಯ *)h;

	/* Return immediately when needle is longer than haystack */
	ಆದರೆ (k<l) ಹಿಂತಿರುಗಿ 0;

	/* Use faster algorithms for short needles */
	h = memchr(h0, *n, k);
	ಆದರೆ (!h || l==1) ಹಿಂತಿರುಗಿ (ಶೂನ್ಯ *)h;
	k -= h - (ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *)h0;
	ಆದರೆ (k<l) ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (l==2) ಹಿಂತಿರುಗಿ twobyte_memmem(h, k, n);
	ಆದರೆ (l==3) ಹಿಂತಿರುಗಿ threebyte_memmem(h, k, n);
	ಆದರೆ (l==4) ಹಿಂತಿರುಗಿ fourbyte_memmem(h, k, n);

	ಹಿಂತಿರುಗಿ twoway_memmem(h, h+k, n, l);
}
DEF_WEAK(memmem);
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_MEMMEM */
