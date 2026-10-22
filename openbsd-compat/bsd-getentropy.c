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

#অন্তর্ভাব "includes.h"

#ifndef SSH_RANDOM_DEV
# define SSH_RANDOM_DEV "/dev/urandom"
#endif /* SSH_RANDOM_DEV */

#অন্তর্ভাব <sys/types.h>
#ifdef HAVE_SYS_RANDOM_H
# include <sys/random.h>
#endif

#অন্তর্ভাব <fcntl.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>
#ifdef WITH_OPENSSL
#অন্তর্ভাব <openssl/rand.h>
#অন্তর্ভাব <openssl/err.h>
#endif

#অন্তর্ভাব "log.h"

পূর্ণসংখ্যা
_ssh_compat_getentropy(শূন্য *s, আকার_t len)
{
#যদি defined(WITH_OPENSSL) && defined(OPENSSL_PRNG_ONLY)
	যদি (RAND_bytes(s, len) <= 0)
		fatal("Couldn't obtain random bytes (error 0x%lx)",
		    (unsigned long)ERR_get_error());
#অন্যথা
	পূর্ণসংখ্যা fd, save_errno;
	ssize_t r;
	আকার_t o = 0;

#ifdef WITH_OPENSSL
	যদি (RAND_bytes(s, len) == 1)
		ফেরত 0;
#endif
#ifdef HAVE_GETENTROPY
	যদি ((r = getentropy(s, len)) == 0)
		ফেরত 0;
#endif /* HAVE_GETENTROPY */
#ifdef HAVE_GETRANDOM
	যদি ((r = getrandom(s, len, 0)) > 0 && (আকার_t)r == len)
		ফেরত 0;
#endif /* HAVE_GETRANDOM */

	যদি ((fd = open(SSH_RANDOM_DEV, O_RDONLY)) == -1) {
		save_errno = errno;
		/* Try egd/prngd before giving up. */
		যদি (seed_from_prngd(s, len) == 0)
			ফেরত 0;
		fatal("Couldn't open %s: %s", SSH_RANDOM_DEV,
		    strerror(save_errno));
	}
	যখন (o < len) {
		r = পঠ(fd, (u_char *)s + o, len - o);
		যদি (r < 0) {
			যদি (errno == EAGAIN || errno == EINTR ||
			    errno == EWOULDBLOCK)
				চালু;
			fatal("read %s: %s", SSH_RANDOM_DEV, strerror(errno));
		}
		o += r;
	}
	close(fd);
#endif /* WITH_OPENSSL */
	ফেরত 0;
}
