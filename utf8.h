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

पूर्णाङ्क	 vasnmprintf(वर्ण **, माप_प्रकार, पूर्णाङ्क *, अचर वर्ण *, बहु_सूची);
पूर्णाङ्क	 mprintf(अचर वर्ण *, ...)
	    __attribute__((format(म_लिखो, 1, 2)));
पूर्णाङ्क	 fmprintf(खाता *, अचर वर्ण *, ...)
	    __attribute__((format(म_लिखो, 2, 3)));
पूर्णाङ्क	 vfmprintf(खाता *, अचर वर्ण *, बहु_सूची);
पूर्णाङ्क	 snmprintf(वर्ण *, माप_प्रकार, पूर्णाङ्क *, अचर वर्ण *, ...)
	    __attribute__((format(म_लिखो, 4, 5)));
पूर्णाङ्क	 asmprintf(वर्ण **, माप_प्रकार, पूर्णाङ्क *, अचर वर्ण *, ...)
	    __attribute__((format(म_लिखो, 4, 5)));
शून्य	 msetlocale(शून्य);
