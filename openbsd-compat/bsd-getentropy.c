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

#شامل "includes.h"

#اگر_غیر_تعریف_شدہ SSH_RANDOM_DEV
# define SSH_RANDOM_DEV "/dev/urandom"
#اگر_ختم /* SSH_RANDOM_DEV */

#شامل <sys/types.h>
#اگر_تعریف_شدہ HAVE_SYS_RANDOM_H
# include <sys/random.h>
#اگر_ختم

#شامل <fcntl.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <unistd.h>
#اگر_تعریف_شدہ WITH_OPENSSL
#شامل <openssl/rand.h>
#شامل <openssl/err.h>
#اگر_ختم

#شامل "log.h"

صحیح
_ssh_compat_getentropy(خالی *s, سائز_t len)
{
#اگر defined(WITH_OPENSSL) && defined(OPENSSL_PRNG_ONLY)
	اگر (RAND_بائٹیں(s, len) <= 0)
		fatal("Couldn't obtain random bytes (error 0x%lx)",
		    (غیرعلامتی طویل)ERR_get_error());
#ورنہ
	صحیح fd, save_errno;
	ssize_t r;
	سائز_t o = 0;

#اگر_تعریف_شدہ WITH_OPENSSL
	اگر (RAND_بائٹیں(s, len) == 1)
		واپس 0;
#اگر_ختم
#اگر_تعریف_شدہ HAVE_GETENTROPY
	اگر ((r = getentropy(s, len)) == 0)
		واپس 0;
#اگر_ختم /* HAVE_GETENTROPY */
#اگر_تعریف_شدہ HAVE_GETRANDOM
	اگر ((r = getrandom(s, len, 0)) > 0 && (سائز_t)r == len)
		واپس 0;
#اگر_ختم /* HAVE_GETRANDOM */

	اگر ((fd = open(SSH_RANDOM_DEV, O_RDONLY)) == -1) {
		save_errno = errno;
		/* Try egd/prngd before giving up. */
		اگر (بیج_from_prngd(s, len) == 0)
			واپس 0;
		fatal("Couldn't open %s: %s", SSH_RANDOM_DEV,
		    strerror(save_errno));
	}
	جب (o < len) {
		r = اقرأ(fd, (u_char *)s + o, len - o);
		اگر (r < 0) {
			اگر (errno == EAGAIN || errno == EINTR ||
			    errno == EWOULDBLOCK)
				جاری;
			fatal("read %s: %s", SSH_RANDOM_DEV, strerror(errno));
		}
		o += r;
	}
	close(fd);
#اگر_ختم /* WITH_OPENSSL */
	واپس 0;
}
