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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ SSH_RANDOM_DEV
# define SSH_RANDOM_DEV "/dev/urandom"
#ಆದರೆ_ಅಂತ್ಯ /* SSH_RANDOM_DEV */

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_SYS_RANDOM_H
# include <sys/random.h>
#ಆದರೆ_ಅಂತ್ಯ

#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/rand.h>
#ಅನ್ತರ್ಭಾವ <openssl/err.h>
#ಆದರೆ_ಅಂತ್ಯ

#ಅನ್ತರ್ಭಾವ "log.h"

ಪೂರ್ಣಾಂಕ
_ssh_compat_getentropy(ಶೂನ್ಯ *s, ಗಾತ್ರ_t len)
{
#ಆದರೆ defined(WITH_OPENSSL) && defined(OPENSSL_PRNG_ONLY)
	ಆದರೆ (RAND_ಬೈಟುಗಳು(s, len) <= 0)
		fatal("Couldn't obtain random bytes (error 0x%lx)",
		    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ)ERR_get_error());
#ಇಲ್ಲದಿದ್ದರೆ
	ಪೂರ್ಣಾಂಕ fd, save_errno;
	ssize_t r;
	ಗಾತ್ರ_t o = 0;

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	ಆದರೆ (RAND_ಬೈಟುಗಳು(s, len) == 1)
		ಹಿಂತಿರುಗಿ 0;
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_GETENTROPY
	ಆದರೆ ((r = getentropy(s, len)) == 0)
		ಹಿಂತಿರುಗಿ 0;
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_GETENTROPY */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_GETRANDOM
	ಆದರೆ ((r = getrandom(s, len, 0)) > 0 && (ಗಾತ್ರ_t)r == len)
		ಹಿಂತಿರುಗಿ 0;
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_GETRANDOM */

	ಆದರೆ ((fd = open(SSH_RANDOM_DEV, O_RDONLY)) == -1) {
		save_errno = errno;
		/* Try egd/prngd before giving up. */
		ಆದರೆ (ಬೀಜ_from_prngd(s, len) == 0)
			ಹಿಂತಿರುಗಿ 0;
		fatal("Couldn't open %s: %s", SSH_RANDOM_DEV,
		    strerror(save_errno));
	}
	ಆಗ (o < len) {
		r = ಪಠ(fd, (u_char *)s + o, len - o);
		ಆದರೆ (r < 0) {
			ಆದರೆ (errno == EAGAIN || errno == EINTR ||
			    errno == EWOULDBLOCK)
				ಮುಂದುವರಿ;
			fatal("read %s: %s", SSH_RANDOM_DEV, strerror(errno));
		}
		o += r;
	}
	close(fd);
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
	ಹಿಂತಿರುಗಿ 0;
}
