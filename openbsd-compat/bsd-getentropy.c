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

#جيڪڏهن_وصف_نه_ٿيل SSH_RANDOM_DEV
# define SSH_RANDOM_DEV "/dev/urandom"
#جيڪڏهن_پورو /* SSH_RANDOM_DEV */

#ضمن <sys/types.h>
#جيڪڏهن_وصف_ٿيل HAVE_SYS_RANDOM_H
# include <sys/random.h>
#جيڪڏهن_پورو

#ضمن <fcntl.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <unistd.h>
#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
#ضمن <openssl/rand.h>
#ضمن <openssl/err.h>
#جيڪڏهن_پورو

#ضمن "log.h"

صحيح
_ssh_compat_getentropy(فراغ *s, سائيز_t len)
{
#إذا defined(WITH_OPENSSL) && defined(OPENSSL_PRNG_ONLY)
	إذا (RAND_بائيٽون(s, len) <= 0)
		fatal("Couldn't obtain random bytes (error 0x%lx)",
		    (بنانشان ڊگهو)ERR_get_error());
#وإلا
	صحيح fd, save_errno;
	ssize_t r;
	سائيز_t o = 0;

#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
	إذا (RAND_بائيٽون(s, len) == 1)
		أرجع 0;
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل HAVE_GETENTROPY
	إذا ((r = getentropy(s, len)) == 0)
		أرجع 0;
#جيڪڏهن_پورو /* HAVE_GETENTROPY */
#جيڪڏهن_وصف_ٿيل HAVE_GETRANDOM
	إذا ((r = getrandom(s, len, 0)) > 0 && (سائيز_t)r == len)
		أرجع 0;
#جيڪڏهن_پورو /* HAVE_GETRANDOM */

	إذا ((fd = open(SSH_RANDOM_DEV, O_RDONLY)) == -1) {
		save_errno = errno;
		/* Try egd/prngd before giving up. */
		إذا (ٻج_from_prngd(s, len) == 0)
			أرجع 0;
		fatal("Couldn't open %s: %s", SSH_RANDOM_DEV,
		    strerror(save_errno));
	}
	طالما (o < len) {
		r = اقرأ(fd, (u_char *)s + o, len - o);
		إذا (r < 0) {
			إذا (errno == EAGAIN || errno == EINTR ||
			    errno == EWOULDBLOCK)
				استمر;
			fatal("read %s: %s", SSH_RANDOM_DEV, strerror(errno));
		}
		o += r;
	}
	close(fd);
#جيڪڏهن_پورو /* WITH_OPENSSL */
	أرجع 0;
}
