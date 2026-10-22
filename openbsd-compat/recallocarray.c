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

#समावेश "includes.h"
#अगर_अघोषित HAVE_RECALLOCARRAY

#समावेश <errno.h>
#समावेश <stdlib.h>
#समावेश <stdint.h>
#समावेश <string.h>
#समावेश <unistd.h>

/*
 * This is sqrt(SIZE_MAX+1), as s1*s2 <= SIZE_MAX
 * if both s1 < MUL_NO_OVERFLOW and s2 < MUL_NO_OVERFLOW
 */
#घोषणा MUL_NO_OVERFLOW ((माप_प्रकार)1 << (माप(माप_प्रकार) * 4))

व्योम *
recallocarray(व्योम *ptr, माप_प्रकार oldnmemb, माप_प्रकार newnmemb, माप_प्रकार आकार)
{
	माप_प्रकार oldsize, newsize;
	व्योम *newptr;

	अगर (ptr == शून्य)
		वापस सुस्मृति(newnmemb, आकार);

	अगर ((newnmemb >= MUL_NO_OVERFLOW || आकार >= MUL_NO_OVERFLOW) &&
	    newnmemb > 0 && SIZE_MAX / newnmemb < आकार) {
		त्रुटि_सं = ENOMEM;
		वापस शून्य;
	}
	newsize = newnmemb * आकार;

	अगर ((oldnmemb >= MUL_NO_OVERFLOW || आकार >= MUL_NO_OVERFLOW) &&
	    oldnmemb > 0 && SIZE_MAX / oldnmemb < आकार) {
		त्रुटि_सं = EINVAL;
		वापस शून्य;
	}
	oldsize = oldnmemb * आकार;
	
	/*
	 * Don't bother too much if we're shrinking just a bit,
	 * we do not shrink for series of small steps, oh well.
	 */
	अगर (newsize <= oldsize) {
		माप_प्रकार d = oldsize - newsize;

		अगर (d < oldsize / 2 && d < (माप_प्रकार)getpagesize()) {
			स_रखो((अक्षर *)ptr + newsize, 0, d);
			वापस ptr;
		}
	}

	newptr = दो_स्मृति(newsize);
	अगर (newptr == शून्य)
		वापस शून्य;

	अगर (newsize > oldsize) {
		स_नकल(newptr, ptr, oldsize);
		स_रखो((अक्षर *)newptr + oldsize, 0, newsize - oldsize);
	} अन्यथा
		स_नकल(newptr, ptr, newsize);

	explicit_bzero(ptr, oldsize);
	मुक्त(ptr);

	वापस newptr;
}
/* DEF_WEAK(recallocarray); */

#पूर्ण_अगर /* HAVE_RECALLOCARRAY */
