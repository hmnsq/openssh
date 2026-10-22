/*
 * Copyright (c) 2015 Tim Rice <tim@multitalents.net>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *   derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#अन्तर्भाव "includes.h"

#अन्तर्भाव <errno.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>

#ifndef HAVE_ERR
शून्य
err(पूर्णांक r, स्थिरांक अक्षर *fmt, ...)
{
	बहु_सूची args;

	बहु_शुरू(args, fmt);
	ख_लिखो(मानक_त्रुटि, "%s: ", म_त्रुटि(त्रुटि_सं));
	भख_लिखो(मानक_त्रुटि, fmt, args);
	ख_अक्षर_दो('\n', मानक_त्रुटि);
	बहु_पूर्ण(args);
	निकास(r);
}
#endif

#ifndef HAVE_ERRX
शून्य
errx(पूर्णांक r, स्थिरांक अक्षर *fmt, ...)
{
	बहु_सूची args;

	बहु_शुरू(args, fmt);
	भख_लिखो(मानक_त्रुटि, fmt, args);
	ख_अक्षर_दो('\n', मानक_त्रुटि);
	बहु_पूर्ण(args);
	निकास(r);
}
#endif

#ifndef HAVE_WARN
शून्य
warn(स्थिरांक अक्षर *fmt, ...)
{
	बहु_सूची args;

	बहु_शुरू(args, fmt);
	ख_लिखो(मानक_त्रुटि, "%s: ", म_त्रुटि(त्रुटि_सं));
	भख_लिखो(मानक_त्रुटि, fmt, args);
	ख_अक्षर_दो('\n', मानक_त्रुटि);
	बहु_पूर्ण(args);
}
#endif
