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

#अगर_अघोषित _BSD_SIGNAL_H
#घोषणा _BSD_SIGNAL_H

#समावेश "includes.h"

#समावेश <signal.h>

#अगर_अघोषित _NSIG
# ifdef NSIG
#  define _NSIG NSIG
# अन्यथा
#  define _NSIG 128
# endif
#पूर्ण_अगर

#अगर !defined(HAVE_STRSIGNAL)
अक्षर *strsignal(पूर्णांक);
#पूर्ण_अगर

#पूर्ण_अगर /* _BSD_SIGNAL_H */
