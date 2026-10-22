/*	$OpenBSD: readpassphrase.h,v 1.5 2003/06/17 21:56:23 millert Exp $	*/

/*
 * Copyright (c) 2000, 2002 Todd C. Miller <Todd.Miller@courtesan.com>
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
 *
 * Sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F39502-99-1-0512.
 */

/* OPENBSD ORIGINAL: include/readpassphrase.h */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ _READPASSPHRASE_H_
#ವ್ಯಾಖ್ಯಾನಿಸು _READPASSPHRASE_H_

#ಅನ್ತರ್ಭಾವ "includes.h"

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_READPASSPHRASE

#ವ್ಯಾಖ್ಯಾನಿಸು RPP_ECHO_OFF    0x00		/* Turn off echo (default). */
#ವ್ಯಾಖ್ಯಾನಿಸು RPP_ECHO_ON     0x01		/* Leave echo on. */
#ವ್ಯಾಖ್ಯಾನಿಸು RPP_REQUIRE_TTY 0x02		/* Fail if there is no tty. */
#ವ್ಯಾಖ್ಯಾನಿಸು RPP_FORCELOWER  0x04		/* Force input to lower case. */
#ವ್ಯಾಖ್ಯಾನಿಸು RPP_FORCEUPPER  0x08		/* Force input to upper case. */
#ವ್ಯಾಖ್ಯಾನಿಸು RPP_SEVENBIT    0x10		/* Strip the high bit from input. */
#ವ್ಯಾಖ್ಯಾನಿಸು RPP_STDIN       0x20		/* Read from stdin, not /dev/tty */

ಅಕ್ಷರ * readpassphrase(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಅಕ್ಷರ *, ಗಾತ್ರ_t, ಪೂರ್ಣಾಂಕ);

#ಆದರೆ_ಅಂತ್ಯ /* HAVE_READPASSPHRASE */

#ಆದರೆ_ಅಂತ್ಯ /* !_READPASSPHRASE_H_ */
