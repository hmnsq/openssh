/*
 * Copyright (c) 1996, David Mazieres <dm@uun.org>
 * Copyright (c) 2008, Damien Miller <djm@openbsd.org>
 * Copyright (c) 2013, Markus Friedl <markus@openbsd.org>
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

#అన్తర్భావ "includes.h"

#నిర్వచితం_కాకపోతే SSH_RANDOM_DEV
# define SSH_RANDOM_DEV "/dev/urandom"
#అయితే_ముగింపు /* SSH_RANDOM_DEV */

#అన్తర్భావ <sys/types.h>
#నిర్వచితమైతే HAVE_SYS_RANDOM_H
# include <sys/random.h>
#అయితే_ముగింపు

#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>
#నిర్వచితమైతే WITH_OPENSSL
#అన్తర్భావ <openssl/rand.h>
#అన్తర్భావ <openssl/err.h>
#అయితే_ముగింపు

#అన్తర్భావ "log.h"

పూర్ణాంకం
_ssh_compat_getentropy(శూన్య *s, కొలత_t len)
{
#ఒకవేళ defined(WITH_OPENSSL) && defined(OPENSSL_PRNG_ONLY)
	ఒకవేళ (RAND_బైట్లు(s, len) <= 0)
		fatal("Couldn't obtain random bytes (error 0x%lx)",
		    (గుర్తులేని దీర్ఘ)ERR_get_error());
#లేకపోతే
	పూర్ణాంకం fd, save_errno;
	ssize_t r;
	కొలత_t o = 0;

#నిర్వచితమైతే WITH_OPENSSL
	ఒకవేళ (RAND_బైట్లు(s, len) == 1)
		తిరిగి 0;
#అయితే_ముగింపు
#నిర్వచితమైతే HAVE_GETENTROPY
	ఒకవేళ ((r = getentropy(s, len)) == 0)
		తిరిగి 0;
#అయితే_ముగింపు /* HAVE_GETENTROPY */
#నిర్వచితమైతే HAVE_GETRANDOM
	ఒకవేళ ((r = getrandom(s, len, 0)) > 0 && (కొలత_t)r == len)
		తిరిగి 0;
#అయితే_ముగింపు /* HAVE_GETRANDOM */

	ఒకవేళ ((fd = open(SSH_RANDOM_DEV, O_RDONLY)) == -1) {
		save_errno = errno;
		/* Try egd/prngd before giving up. */
		ఒకవేళ (విత్తనం_from_prngd(s, len) == 0)
			తిరిగి 0;
		fatal("Couldn't open %s: %s", SSH_RANDOM_DEV,
		    strerror(save_errno));
	}
	అయితే (o < len) {
		r = పఠ(fd, (u_char *)s + o, len - o);
		ఒకవేళ (r < 0) {
			ఒకవేళ (errno == EAGAIN || errno == EINTR ||
			    errno == EWOULDBLOCK)
				కొనసాగు;
			fatal("read %s: %s", SSH_RANDOM_DEV, strerror(errno));
		}
		o += r;
	}
	close(fd);
#అయితే_ముగింపు /* WITH_OPENSSL */
	తిరిగి 0;
}
