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

#अन्तर्भाव "includes.h"

#ifndef HAVE_MEMMEM

#अन्तर्भाव <string.h>
#अन्तर्भाव <stdint.h>

स्थिर वर्ण *
twobyte_memmem(अचर अचिन्हित वर्ण *h, माप_प्रकार k, अचर अचिन्हित वर्ण *n)
{
	uint16_t nw = n[0]<<8 | n[1], hw = h[0]<<8 | h[1];
	लागि (h+=2, k-=2; k; k--, hw = hw<<8 | *h++)
		यदि (hw == nw) फर्काऊ (वर्ण *)h-2;
	फर्काऊ hw == nw ? (वर्ण *)h-2 : 0;
}

स्थिर वर्ण *
threebyte_memmem(अचर अचिन्हित वर्ण *h, माप_प्रकार k, अचर अचिन्हित वर्ण *n)
{
	uint32_t nw = n[0]<<24 | n[1]<<16 | n[2]<<8;
	uint32_t hw = h[0]<<24 | h[1]<<16 | h[2]<<8;
	लागि (h+=3, k-=3; k; k--, hw = (hw|*h++)<<8)
		यदि (hw == nw) फर्काऊ (वर्ण *)h-3;
	फर्काऊ hw == nw ? (वर्ण *)h-3 : 0;
}

स्थिर वर्ण *
fourbyte_memmem(अचर अचिन्हित वर्ण *h, माप_प्रकार k, अचर अचिन्हित वर्ण *n)
{
	uint32_t nw = n[0]<<24 | n[1]<<16 | n[2]<<8 | n[3];
	uint32_t hw = h[0]<<24 | h[1]<<16 | h[2]<<8 | h[3];
	लागि (h+=4, k-=4; k; k--, hw = hw<<8 | *h++)
		यदि (hw == nw) फर्काऊ (वर्ण *)h-4;
	फर्काऊ hw == nw ? (वर्ण *)h-4 : 0;
}

#यदि 0
/* In -portable, defines.h ensures that these are already defined. */
#define MAX(a,b) ((a)>(b)?(a):(b))
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif

#define BITOP(a,b,op) \
 ((a)[(माप_प्रकार)(b)/(8*परिमाण *(a))] op (माप_प्रकार)1<<((माप_प्रकार)(b)%(8*परिमाण *(a))))

/*
 * Maxime Crochemore and Dominique Perrin, Two-way string-matching,
 * Journal of the ACM, 38(3):651-675, July 1991.
 */
स्थिर वर्ण *
twoway_memmem(अचर अचिन्हित वर्ण *h, अचर अचिन्हित वर्ण *z,
    अचर अचिन्हित वर्ण *n, माप_प्रकार l)
{
	माप_प्रकार i, ip, jp, k, p, ms, p0, mem, mem0;
	माप_प्रकार byteset[32 / परिमाण(माप_प्रकार)] = { 0 };
	माप_प्रकार shift[256];

	/* Computing length of needle and fill shift table */
	लागि (i=0; i<l; i++)
		BITOP(byteset, n[i], |=), shift[n[i]] = i+1;

	/* Compute maximal suffix */
	ip = -1; jp = 0; k = p = 1;
	जबसम्म (jp+k<l) {
		यदि (n[ip+k] == n[jp+k]) {
			यदि (k == p) {
				jp += p;
				k = 1;
			} अन्यथा k++;
		} अन्यथा यदि (n[ip+k] > n[jp+k]) {
			jp += k;
			k = 1;
			p = jp - ip;
		} अन्यथा {
			ip = jp++;
			k = p = 1;
		}
	}
	ms = ip;
	p0 = p;

	/* And with the opposite comparison */
	ip = -1; jp = 0; k = p = 1;
	जबसम्म (jp+k<l) {
		यदि (n[ip+k] == n[jp+k]) {
			यदि (k == p) {
				jp += p;
				k = 1;
			} अन्यथा k++;
		} अन्यथा यदि (n[ip+k] < n[jp+k]) {
			jp += k;
			k = 1;
			p = jp - ip;
		} अन्यथा {
			ip = jp++;
			k = p = 1;
		}
	}
	यदि (ip+1 > ms+1) ms = ip;
	अन्यथा p = p0;

	/* Periodic needle? */
	यदि (स_भेद(n, n+p, ms+1)) {
		mem0 = 0;
		p = MAX(ms, l-ms-1) + 1;
	} अन्यथा mem0 = l-p;
	mem = 0;

	/* Search loop */
	लागि (;;) {
		/* If remainder of haystack is shorter than needle, done */
		यदि (z-h < l) फर्काऊ 0;

		/* Check last byte first; advance by shift on mismatch */
		यदि (BITOP(byteset, h[l-1], &)) {
			k = l-shift[h[l-1]];
			यदि (k) {
				यदि (k < mem) k = mem;
				h += k;
				mem = 0;
				जारी;
			}
		} अन्यथा {
			h += l;
			mem = 0;
			जारी;
		}

		/* Compare right half */
		लागि (k=MAX(ms+1,mem); k<l && n[k] == h[k]; k++);
		यदि (k < l) {
			h += k-ms;
			mem = 0;
			जारी;
		}
		/* Compare left half */
		लागि (k=ms+1; k>mem && n[k-1] == h[k-1]; k--);
		यदि (k <= mem) फर्काऊ (वर्ण *)h;
		h += p;
		mem = mem0;
	}
}

शून्य *
memmem(अचर शून्य *h0, माप_प्रकार k, अचर शून्य *n0, माप_प्रकार l)
{
	अचर अचिन्हित वर्ण *h = h0, *n = n0;

	/* Return immediately on empty needle */
	यदि (!l) फर्काऊ (शून्य *)h;

	/* Return immediately when needle is longer than haystack */
	यदि (k<l) फर्काऊ 0;

	/* Use faster algorithms for short needles */
	h = स_प्रथम(h0, *n, k);
	यदि (!h || l==1) फर्काऊ (शून्य *)h;
	k -= h - (अचर अचिन्हित वर्ण *)h0;
	यदि (k<l) फर्काऊ 0;
	यदि (l==2) फर्काऊ twobyte_memmem(h, k, n);
	यदि (l==3) फर्काऊ threebyte_memmem(h, k, n);
	यदि (l==4) फर्काऊ fourbyte_memmem(h, k, n);

	फर्काऊ twoway_memmem(h, h+k, n, l);
}
DEF_WEAK(memmem);
#endif /* HAVE_MEMMEM */
