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

#include "includes.h"

#ifndef SSH_RANDOM_DEV
# define SSH_RANDOM_DEV "/dev/urandom"
#endif /* SSH_RANDOM_DEV */

#include <sys/types.h>
#ifdef HAVE_SYS_RANDOM_H
# include <sys/random.h>
#endif

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef WITH_OPENSSL
#include <openssl/rand.h>
#include <openssl/err.h>
#endif

#include "log.h"

puur_naa_nka
_ssh_compat_getentropy(void *s, size_t len)
{
#ᱡᱩᱫᱤ defined(WITH_OPENSSL) && defined(OPENSSL_PRNG_ONLY)
	ᱡᱩᱫᱤ (RAND_bytes(s, len) <= 0)
		fatal("Couldn't obtain random bytes (error 0x%lx)",
		    (unsigned long)ERR_get_error());
#ᱵᱟᱝ
	puur_naa_nka fd, save_errno;
	ssize_t r;
	size_t o = 0;

#ifdef WITH_OPENSSL
	ᱡᱩᱫᱤ (RAND_bytes(s, len) == 1)
		ᱨᱩᱣᱟᱹᱲ 0;
#endif
#ifdef HAVE_GETENTROPY
	ᱡᱩᱫᱤ ((r = getentropy(s, len)) == 0)
		ᱨᱩᱣᱟᱹᱲ 0;
#endif /* HAVE_GETENTROPY */
#ifdef HAVE_GETRANDOM
	ᱡᱩᱫᱤ ((r = getrandom(s, len, 0)) > 0 && (size_t)r == len)
		ᱨᱩᱣᱟᱹᱲ 0;
#endif /* HAVE_GETRANDOM */

	ᱡᱩᱫᱤ ((fd = open(SSH_RANDOM_DEV, O_RDONLY)) == -1) {
		save_errno = errno;
		/* Try egd/prngd before giving up. */
		ᱡᱩᱫᱤ (seed_from_prngd(s, len) == 0)
			ᱨᱩᱣᱟᱹᱲ 0;
		fatal("Couldn't open %s: %s", SSH_RANDOM_DEV,
		    strerror(save_errno));
	}
	ᱡᱚᱠᱷᱚᱱ (o < len) {
		r = read(fd, (u_char *)s + o, len - o);
		ᱡᱩᱫᱤ (r < 0) {
			ᱡᱩᱫᱤ (errno == EAGAIN || errno == EINTR ||
			    errno == EWOULDBLOCK)
				continue;
			fatal("read %s: %s", SSH_RANDOM_DEV, strerror(errno));
		}
		o += r;
	}
	close(fd);
#endif /* WITH_OPENSSL */
	ᱨᱩᱣᱟᱹᱲ 0;
}
