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

صحيح	 vasnmprintf(حرف **, size_t, صحيح *, ثابت حرف *, va_list);
صحيح	 mprintf(ثابت حرف *, ...)
	    __attribute__((format(printf, 1, 2)));
صحيح	 fmprintf(FILE *, ثابت حرف *, ...)
	    __attribute__((format(printf, 2, 3)));
صحيح	 vfmprintf(FILE *, ثابت حرف *, va_list);
صحيح	 snmprintf(حرف *, size_t, صحيح *, ثابت حرف *, ...)
	    __attribute__((format(printf, 4, 5)));
صحيح	 asmprintf(حرف **, size_t, صحيح *, ثابت حرف *, ...)
	    __attribute__((format(printf, 4, 5)));
فراغ	 msetlocale(فراغ);
