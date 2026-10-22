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

#ضمن "includes.h"

#ifndef SSH_RANDOM_DEV
# define SSH_RANDOM_DEV "/dev/urandom"
#endif /* SSH_RANDOM_DEV */

#ضمن <sys/types.h>
#ifdef HAVE_SYS_RANDOM_H
# include <sys/random.h>
#endif

#ضمن <fcntl.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <unistd.h>
#ifdef WITH_OPENSSL
#ضمن <openssl/rand.h>
#ضمن <openssl/err.h>
#endif

#ضمن "log.h"

صحيح
_ssh_compat_getentropy(فراغ *s, size_t len)
{
#ܐܢ defined(WITH_OPENSSL) && defined(OPENSSL_PRNG_ONLY)
	ܐܢ (RAND_bytes(s, len) <= 0)
		fatal("Couldn't obtain random bytes (error 0x%lx)",
		    (unsigned long)ERR_get_error());
#ܐܚܪܢܐ
	صحيح fd, save_errno;
	ssize_t r;
	size_t o = 0;

#ifdef WITH_OPENSSL
	ܐܢ (RAND_bytes(s, len) == 1)
		ܦܢܐ 0;
#endif
#ifdef HAVE_GETENTROPY
	ܐܢ ((r = getentropy(s, len)) == 0)
		ܦܢܐ 0;
#endif /* HAVE_GETENTROPY */
#ifdef HAVE_GETRANDOM
	ܐܢ ((r = getrandom(s, len, 0)) > 0 && (size_t)r == len)
		ܦܢܐ 0;
#endif /* HAVE_GETRANDOM */

	ܐܢ ((fd = open(SSH_RANDOM_DEV, O_RDONLY)) == -1) {
		save_errno = errno;
		/* Try egd/prngd before giving up. */
		ܐܢ (seed_from_prngd(s, len) == 0)
			ܦܢܐ 0;
		fatal("Couldn't open %s: %s", SSH_RANDOM_DEV,
		    strerror(save_errno));
	}
	ܟܡܐ (o < len) {
		r = اقرأ(fd, (u_char *)s + o, len - o);
		ܐܢ (r < 0) {
			ܐܢ (errno == EAGAIN || errno == EINTR ||
			    errno == EWOULDBLOCK)
				استمر;
			fatal("read %s: %s", SSH_RANDOM_DEV, strerror(errno));
		}
		o += r;
	}
	close(fd);
#endif /* WITH_OPENSSL */
	ܦܢܐ 0;
}
