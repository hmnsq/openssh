/*	$OpenBSD: recallocarray.c,v 1.1 2017/03/06 18:44:21 otto Exp $	*/
/*
 * Copyright (c) 2008, 2017 Otto Moerbeek <otto@drijf.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* OPENBSD ORIGINAL: lib/libc/stdlib/recallocarray.c */

#अन्तर्भाव "includes.h"
#ifndef HAVE_RECALLOCARRAY

#अन्तर्भाव <errno.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>

/*
 * This is sqrt(SIZE_MAX+1), as s1*s2 <= SIZE_MAX
 * if both s1 < MUL_NO_OVERFLOW and s2 < MUL_NO_OVERFLOW
 */
#define MUL_NO_OVERFLOW ((माप_प्रकार)1 << (आकार(माप_प्रकार) * 4))

शून्य *
recallocarray(शून्य *ptr, माप_प्रकार oldnmemb, माप_प्रकार newnmemb, माप_प्रकार size)
{
	माप_प्रकार oldsize, newsize;
	शून्य *newptr;

	जर (ptr == रिक्त)
		परत सुस्मृति(newnmemb, size);

	जर ((newnmemb >= MUL_NO_OVERFLOW || size >= MUL_NO_OVERFLOW) &&
	    newnmemb > 0 && SIZE_MAX / newnmemb < size) {
		त्रुटि_सं = ENOMEM;
		परत रिक्त;
	}
	newsize = newnmemb * size;

	जर ((oldnmemb >= MUL_NO_OVERFLOW || size >= MUL_NO_OVERFLOW) &&
	    oldnmemb > 0 && SIZE_MAX / oldnmemb < size) {
		त्रुटि_सं = EINVAL;
		परत रिक्त;
	}
	oldsize = oldnmemb * size;
	
	/*
	 * Don't bother too much if we're shrinking just a bit,
	 * we do not shrink for series of small steps, oh well.
	 */
	जर (newsize <= oldsize) {
		माप_प्रकार d = oldsize - newsize;

		जर (d < oldsize / 2 && d < (माप_प्रकार)getpagesize()) {
			स_रखो((अक्षर *)ptr + newsize, 0, d);
			परत ptr;
		}
	}

	newptr = दो_स्मृति(newsize);
	जर (newptr == रिक्त)
		परत रिक्त;

	जर (newsize > oldsize) {
		स_नकल(newptr, ptr, oldsize);
		स_रखो((अक्षर *)newptr + oldsize, 0, newsize - oldsize);
	} अन्यथा
		स_नकल(newptr, ptr, newsize);

	explicit_bzero(ptr, oldsize);
	मुक्त(ptr);

	परत newptr;
}
/* DEF_WEAK(recallocarray); */

#endif /* HAVE_RECALLOCARRAY */
