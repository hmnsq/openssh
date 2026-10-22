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

#यदि_अपरिभाषितम् _BSD_SIGNAL_H
#परिभाषय _BSD_SIGNAL_H

#अन्तर्भाव "includes.h"

#अन्तर्भाव <signal.h>

#यदि_अपरिभाषितम् _NSIG
# ifdef NSIG
#  define _NSIG NSIG
# अन्यथा
#  define _NSIG 128
# endif
#यदि_अन्तः

#यदि !defined(HAVE_STRSIGNAL)
वर्ण *strsignal(पूर्णाङ्क);
#यदि_अन्तः

#यदि_अन्तः /* _BSD_SIGNAL_H */
