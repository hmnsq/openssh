/* $OpenBSD: xmalloc.c,v 1.38 2025/05/23 00:40:45 deraadt Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Versions of malloc and friends that check their results, and never return
 * failure (they call fatal if they encounter an error).
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#समावेश "includes.h"

#समावेश <stdarg.h>
#समावेश <stdint.h>
#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <string.h>

#समावेश "xmalloc.h"
#समावेश "log.h"

#अगर defined(__OpenBSD__)
स्थिर अक्षर * स्थिर malloc_options = "S";
#पूर्ण_अगर /* __OpenBSD__ */

व्योम *
xmalloc(माप_प्रकार आकार)
{
	व्योम *ptr;

	अगर (आकार == 0)
		fatal("xmalloc: zero size");
	ptr = दो_स्मृति(आकार);
	अगर (ptr == शून्य)
		fatal("xmalloc: out of memory (allocating %zu bytes)", आकार);
	वापस ptr;
}

व्योम *
xcalloc(माप_प्रकार nmemb, माप_प्रकार आकार)
{
	व्योम *ptr;

	अगर (आकार == 0 || nmemb == 0)
		fatal("xcalloc: zero size");
	अगर (SIZE_MAX / nmemb < आकार)
		fatal("xcalloc: nmemb * size > SIZE_MAX");
	ptr = सुस्मृति(nmemb, आकार);
	अगर (ptr == शून्य)
		fatal("xcalloc: out of memory (allocating %zu bytes)",
		    आकार * nmemb);
	वापस ptr;
}

व्योम *
xreallocarray(व्योम *ptr, माप_प्रकार nmemb, माप_प्रकार आकार)
{
	व्योम *new_ptr;

	new_ptr = reallocarray(ptr, nmemb, आकार);
	अगर (new_ptr == शून्य)
		fatal("xreallocarray: out of memory (%zu elements of %zu bytes)",
		    nmemb, आकार);
	वापस new_ptr;
}

व्योम *
xrecallocarray(व्योम *ptr, माप_प्रकार onmemb, माप_प्रकार nmemb, माप_प्रकार आकार)
{
	व्योम *new_ptr;

	new_ptr = recallocarray(ptr, onmemb, nmemb, आकार);
	अगर (new_ptr == शून्य)
		fatal("xrecallocarray: out of memory (%zu elements of %zu bytes)",
		    nmemb, आकार);
	वापस new_ptr;
}

अक्षर *
xstrdup(स्थिर अक्षर *str)
{
	माप_प्रकार len;
	अक्षर *cp;

	len = म_माप(str) + 1;
	cp = xmalloc(len);
	वापस स_नकल(cp, str, len);
}

पूर्णांक
xvasprintf(अक्षर **ret, स्थिर अक्षर *fmt, बहु_सूची ap)
{
	पूर्णांक i;

	i = vasprintf(ret, fmt, ap);
	अगर (i < 0 || *ret == शून्य)
		fatal("xvasprintf: could not allocate memory");
	वापस i;
}

पूर्णांक
xasprintf(अक्षर **ret, स्थिर अक्षर *fmt, ...)
{
	बहु_सूची ap;
	पूर्णांक i;

	बहु_शुरू(ap, fmt);
	i = xvasprintf(ret, fmt, ap);
	बहु_पूर्ण(ap);
	वापस i;
}
