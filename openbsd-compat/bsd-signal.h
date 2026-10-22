/*
 * Copyright (c) 1999-2004 Damien Miller <djm@mindrot.org>
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

#اگر_غیر_تعریف_شدہ _BSD_SIGNAL_H
#تعریف_کرو _BSD_SIGNAL_H

#شامل "includes.h"

#شامل <signal.h>

#اگر_غیر_تعریف_شدہ _NSIG
# ifdef NSIG
#  define _NSIG NSIG
# ورنہ
#  define _NSIG 128
# endif
#اگر_ختم

#اگر !defined(HAVE_STRSIGNAL)
حرف *strsignal(صحیح);
#اگر_ختم

#اگر_ختم /* _BSD_SIGNAL_H */
