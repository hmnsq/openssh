/* $OpenBSD: utf8.h,v 1.4 2021/04/03 06:18:41 djm Exp $ */
/*
 * Copyright (c) 2016 Ingo Schwarze <schwarze@openbsd.org>
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

पूर्णांक	 vasnmprintf(अक्षर **, माप_प्रकार, पूर्णांक *, स्थिरांक अक्षर *, बहु_सूची);
पूर्णांक	 mprintf(स्थिरांक अक्षर *, ...)
	    __attribute__((format(म_लिखो, 1, 2)));
पूर्णांक	 fmprintf(खाता *, स्थिरांक अक्षर *, ...)
	    __attribute__((format(म_लिखो, 2, 3)));
पूर्णांक	 vfmprintf(खाता *, स्थिरांक अक्षर *, बहु_सूची);
पूर्णांक	 snmprintf(अक्षर *, माप_प्रकार, पूर्णांक *, स्थिरांक अक्षर *, ...)
	    __attribute__((format(म_लिखो, 4, 5)));
पूर्णांक	 asmprintf(अक्षर **, माप_प्रकार, पूर्णांक *, स्थिरांक अक्षर *, ...)
	    __attribute__((format(म_लिखो, 4, 5)));
शून्य	 msetlocale(शून्य);
