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

स्थिर अक्षर *
twobyte_memmem(स्थिरांक अचिन्हित अक्षर *h, माप_प्रकार k, स्थिरांक अचिन्हित अक्षर *n)
{
	uint16_t nw = n[0]<<8 | n[1], hw = h[0]<<8 | h[1];
	साठी (h+=2, k-=2; k; k--, hw = hw<<8 | *h++)
		जर (hw == nw) परत (अक्षर *)h-2;
	परत hw == nw ? (अक्षर *)h-2 : 0;
}

स्थिर अक्षर *
threebyte_memmem(स्थिरांक अचिन्हित अक्षर *h, माप_प्रकार k, स्थिरांक अचिन्हित अक्षर *n)
{
	uint32_t nw = n[0]<<24 | n[1]<<16 | n[2]<<8;
	uint32_t hw = h[0]<<24 | h[1]<<16 | h[2]<<8;
	साठी (h+=3, k-=3; k; k--, hw = (hw|*h++)<<8)
		जर (hw == nw) परत (अक्षर *)h-3;
	परत hw == nw ? (अक्षर *)h-3 : 0;
}

स्थिर अक्षर *
fourbyte_memmem(स्थिरांक अचिन्हित अक्षर *h, माप_प्रकार k, स्थिरांक अचिन्हित अक्षर *n)
{
	uint32_t nw = n[0]<<24 | n[1]<<16 | n[2]<<8 | n[3];
	uint32_t hw = h[0]<<24 | h[1]<<16 | h[2]<<8 | h[3];
	साठी (h+=4, k-=4; k; k--, hw = hw<<8 | *h++)
		जर (hw == nw) परत (अक्षर *)h-4;
	परत hw == nw ? (अक्षर *)h-4 : 0;
}

#जर 0
/* In -portable, defines.h ensures that these are already defined. */
#define MAX(a,b) ((a)>(b)?(a):(b))
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif

#define BITOP(a,b,op) \
 ((a)[(माप_प्रकार)(b)/(8*आकार *(a))] op (माप_प्रकार)1<<((माप_प्रकार)(b)%(8*आकार *(a))))

/*
 * Maxime Crochemore and Dominique Perrin, Two-way string-matching,
 * Journal of the ACM, 38(3):651-675, July 1991.
 */
स्थिर अक्षर *
twoway_memmem(स्थिरांक अचिन्हित अक्षर *h, स्थिरांक अचिन्हित अक्षर *z,
    स्थिरांक अचिन्हित अक्षर *n, माप_प्रकार l)
{
	माप_प्रकार i, ip, jp, k, p, ms, p0, mem, mem0;
	माप_प्रकार byteset[32 / आकार(माप_प्रकार)] = { 0 };
	माप_प्रकार shift[256];

	/* Computing length of needle and fill shift table */
	साठी (i=0; i<l; i++)
		BITOP(byteset, n[i], |=), shift[n[i]] = i+1;

	/* Compute maximal suffix */
	ip = -1; jp = 0; k = p = 1;
	पर्यंत (jp+k<l) {
		जर (n[ip+k] == n[jp+k]) {
			जर (k == p) {
				jp += p;
				k = 1;
			} अन्यथा k++;
		} अन्यथा जर (n[ip+k] > n[jp+k]) {
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
	पर्यंत (jp+k<l) {
		जर (n[ip+k] == n[jp+k]) {
			जर (k == p) {
				jp += p;
				k = 1;
			} अन्यथा k++;
		} अन्यथा जर (n[ip+k] < n[jp+k]) {
			jp += k;
			k = 1;
			p = jp - ip;
		} अन्यथा {
			ip = jp++;
			k = p = 1;
		}
	}
	जर (ip+1 > ms+1) ms = ip;
	अन्यथा p = p0;

	/* Periodic needle? */
	जर (स_भेद(n, n+p, ms+1)) {
		mem0 = 0;
		p = MAX(ms, l-ms-1) + 1;
	} अन्यथा mem0 = l-p;
	mem = 0;

	/* Search loop */
	साठी (;;) {
		/* If remainder of haystack is shorter than needle, done */
		जर (z-h < l) परत 0;

		/* Check last byte first; advance by shift on mismatch */
		जर (BITOP(byteset, h[l-1], &)) {
			k = l-shift[h[l-1]];
			जर (k) {
				जर (k < mem) k = mem;
				h += k;
				mem = 0;
				सुरूठेवा;
			}
		} अन्यथा {
			h += l;
			mem = 0;
			सुरूठेवा;
		}

		/* Compare right half */
		साठी (k=MAX(ms+1,mem); k<l && n[k] == h[k]; k++);
		जर (k < l) {
			h += k-ms;
			mem = 0;
			सुरूठेवा;
		}
		/* Compare left half */
		साठी (k=ms+1; k>mem && n[k-1] == h[k-1]; k--);
		जर (k <= mem) परत (अक्षर *)h;
		h += p;
		mem = mem0;
	}
}

शून्य *
memmem(स्थिरांक शून्य *h0, माप_प्रकार k, स्थिरांक शून्य *n0, माप_प्रकार l)
{
	स्थिरांक अचिन्हित अक्षर *h = h0, *n = n0;

	/* Return immediately on empty needle */
	जर (!l) परत (शून्य *)h;

	/* Return immediately when needle is longer than haystack */
	जर (k<l) परत 0;

	/* Use faster algorithms for short needles */
	h = स_प्रथम(h0, *n, k);
	जर (!h || l==1) परत (शून्य *)h;
	k -= h - (स्थिरांक अचिन्हित अक्षर *)h0;
	जर (k<l) परत 0;
	जर (l==2) परत twobyte_memmem(h, k, n);
	जर (l==3) परत threebyte_memmem(h, k, n);
	जर (l==4) परत fourbyte_memmem(h, k, n);

	परत twoway_memmem(h, h+k, n, l);
}
DEF_WEAK(memmem);
#endif /* HAVE_MEMMEM */
