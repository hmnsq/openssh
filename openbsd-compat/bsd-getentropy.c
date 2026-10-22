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

#அந்தர்பாவ "includes.h"

#ifndef SSH_RANDOM_DEV
# define SSH_RANDOM_DEV "/dev/urandom"
#endif /* SSH_RANDOM_DEV */

#அந்தர்பாவ <sys/types.h>
#ifdef HAVE_SYS_RANDOM_H
# include <sys/random.h>
#endif

#அந்தர்பாவ <fcntl.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>
#ifdef WITH_OPENSSL
#அந்தர்பாவ <openssl/rand.h>
#அந்தர்பாவ <openssl/err.h>
#endif

#அந்தர்பாவ "log.h"

முழு
_ssh_compat_getentropy(வெறுமை *s, size_t len)
{
#எனில் defined(WITH_OPENSSL) && defined(OPENSSL_PRNG_ONLY)
	எனில் (RAND_bytes(s, len) <= 0)
		fatal("Couldn't obtain random bytes (error 0x%lx)",
		    (unsigned long)ERR_get_error());
#இல்லையெனில்
	முழு fd, save_errno;
	ssize_t r;
	size_t o = 0;

#ifdef WITH_OPENSSL
	எனில் (RAND_bytes(s, len) == 1)
		திரும்பு 0;
#endif
#ifdef HAVE_GETENTROPY
	எனில் ((r = getentropy(s, len)) == 0)
		திரும்பு 0;
#endif /* HAVE_GETENTROPY */
#ifdef HAVE_GETRANDOM
	எனில் ((r = getrandom(s, len, 0)) > 0 && (size_t)r == len)
		திரும்பு 0;
#endif /* HAVE_GETRANDOM */

	எனில் ((fd = open(SSH_RANDOM_DEV, O_RDONLY)) == -1) {
		save_errno = errno;
		/* Try egd/prngd before giving up. */
		எனில் (seed_from_prngd(s, len) == 0)
			திரும்பு 0;
		fatal("Couldn't open %s: %s", SSH_RANDOM_DEV,
		    strerror(save_errno));
	}
	போது (o < len) {
		r = பட(fd, (u_char *)s + o, len - o);
		எனில் (r < 0) {
			எனில் (errno == EAGAIN || errno == EINTR ||
			    errno == EWOULDBLOCK)
				தொடர்;
			fatal("read %s: %s", SSH_RANDOM_DEV, strerror(errno));
		}
		o += r;
	}
	close(fd);
#endif /* WITH_OPENSSL */
	திரும்பு 0;
}
