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

#अन्तर्भाव "includes.h"

#ifndef SSH_RANDOM_DEV
# define SSH_RANDOM_DEV "/dev/urandom"
#endif /* SSH_RANDOM_DEV */

#अन्तर्भाव <sys/types.h>
#ifdef HAVE_SYS_RANDOM_H
# include <sys/random.h>
#endif

#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>
#ifdef WITH_OPENSSL
#अन्तर्भाव <openssl/rand.h>
#अन्तर्भाव <openssl/err.h>
#endif

#अन्तर्भाव "log.h"

पूर्णाङ्क
_ssh_compat_getentropy(शून्य *s, size_t len)
{
#सचे defined(WITH_OPENSSL) && defined(OPENSSL_PRNG_ONLY)
	सचे (RAND_bytes(s, len) <= 0)
		fatal("Couldn't obtain random bytes (error 0x%lx)",
		    (unsigned long)ERR_get_error());
#अञ्ञथा
	पूर्णाङ्क fd, save_errno;
	ssize_t r;
	size_t o = 0;

#ifdef WITH_OPENSSL
	सचे (RAND_bytes(s, len) == 1)
		पटिनिवत्त 0;
#endif
#ifdef HAVE_GETENTROPY
	सचे ((r = getentropy(s, len)) == 0)
		पटिनिवत्त 0;
#endif /* HAVE_GETENTROPY */
#ifdef HAVE_GETRANDOM
	सचे ((r = getrandom(s, len, 0)) > 0 && (size_t)r == len)
		पटिनिवत्त 0;
#endif /* HAVE_GETRANDOM */

	सचे ((fd = open(SSH_RANDOM_DEV, O_RDONLY)) == -1) {
		save_errno = errno;
		/* Try egd/prngd before giving up. */
		सचे (seed_from_prngd(s, len) == 0)
			पटिनिवत्त 0;
		fatal("Couldn't open %s: %s", SSH_RANDOM_DEV,
		    strerror(save_errno));
	}
	याव (o < len) {
		r = पठ(fd, (u_char *)s + o, len - o);
		सचे (r < 0) {
			सचे (errno == EAGAIN || errno == EINTR ||
			    errno == EWOULDBLOCK)
				अनुवर्त;
			fatal("read %s: %s", SSH_RANDOM_DEV, strerror(errno));
		}
		o += r;
	}
	close(fd);
#endif /* WITH_OPENSSL */
	पटिनिवत्त 0;
}
