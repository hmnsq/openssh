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

ຈຳນວນເຕັມ	 vasnmprintf(var_na **, size_t, ຈຳນວນເຕັມ *, const var_na *, va_list);
ຈຳນວນເຕັມ	 mprintf(const var_na *, ...)
	    __attribute__((format(printf, 1, 2)));
ຈຳນວນເຕັມ	 fmprintf(FILE *, const var_na *, ...)
	    __attribute__((format(printf, 2, 3)));
ຈຳນວນເຕັມ	 vfmprintf(FILE *, const var_na *, va_list);
ຈຳນວນເຕັມ	 snmprintf(var_na *, size_t, ຈຳນວນເຕັມ *, const var_na *, ...)
	    __attribute__((format(printf, 4, 5)));
ຈຳນວນເຕັມ	 asmprintf(var_na **, size_t, ຈຳນວນເຕັມ *, const var_na *, ...)
	    __attribute__((format(printf, 4, 5)));
void	 msetlocale(void);
