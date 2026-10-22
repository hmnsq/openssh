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

#ifndef SSH_RANDOM_DEV
# define SSH_RANDOM_DEV "/dev/urandom"
#endif /* SSH_RANDOM_DEV */

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ifdef HAVE_SYS_RANDOM_H
# include <sys/random.h>
#endif

#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ifdef WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/rand.h>
#ಅನ್ತರ್ಭಾವ <openssl/err.h>
#endif

#ಅನ್ತರ್ಭಾವ "log.h"

ಪೂರ್ಣಾಙ್ಕ
_ssh_compat_getentropy(ಶೂನ್ಯ *s, size_t len)
{
#ಯದಿ defined(WITH_OPENSSL) && defined(OPENSSL_PRNG_ONLY)
	ಯದಿ (RAND_bytes(s, len) <= 0)
		fatal("Couldn't obtain random bytes (error 0x%lx)",
		    (unsigned long)ERR_get_error());
#ಅನ್ಯಥಾ
	ಪೂರ್ಣಾಙ್ಕ fd, save_errno;
	ssize_t r;
	size_t o = 0;

#ifdef WITH_OPENSSL
	ಯದಿ (RAND_bytes(s, len) == 1)
		ಪ್ರತ್ಯಾಗಮ 0;
#endif
#ifdef HAVE_GETENTROPY
	ಯದಿ ((r = getentropy(s, len)) == 0)
		ಪ್ರತ್ಯಾಗಮ 0;
#endif /* HAVE_GETENTROPY */
#ifdef HAVE_GETRANDOM
	ಯದಿ ((r = getrandom(s, len, 0)) > 0 && (size_t)r == len)
		ಪ್ರತ್ಯಾಗಮ 0;
#endif /* HAVE_GETRANDOM */

	ಯದಿ ((fd = open(SSH_RANDOM_DEV, O_RDONLY)) == -1) {
		save_errno = errno;
		/* Try egd/prngd before giving up. */
		ಯದಿ (seed_from_prngd(s, len) == 0)
			ಪ್ರತ್ಯಾಗಮ 0;
		fatal("Couldn't open %s: %s", SSH_RANDOM_DEV,
		    strerror(save_errno));
	}
	ಯಾವತ್ (o < len) {
		r = ಪಠ(fd, (u_char *)s + o, len - o);
		ಯದಿ (r < 0) {
			ಯದಿ (errno == EAGAIN || errno == EINTR ||
			    errno == EWOULDBLOCK)
				ಅನುವರ್ತ;
			fatal("read %s: %s", SSH_RANDOM_DEV, strerror(errno));
		}
		o += r;
	}
	close(fd);
#endif /* WITH_OPENSSL */
	ಪ್ರತ್ಯಾಗಮ 0;
}
