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

#समावेश "includes.h"

#अगर_अघोषित SSH_RANDOM_DEV
# define SSH_RANDOM_DEV "/dev/urandom"
#पूर्ण_अगर /* SSH_RANDOM_DEV */

#समावेश <sys/types.h>
#अगर_घोषित HAVE_SYS_RANDOM_H
# include <sys/random.h>
#पूर्ण_अगर

#समावेश <fcntl.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <unistd.h>
#अगर_घोषित WITH_OPENSSL
#समावेश <openssl/rand.h>
#समावेश <openssl/err.h>
#पूर्ण_अगर

#समावेश "log.h"

पूर्णांक
_ssh_compat_getentropy(व्योम *s, माप_प्रकार len)
{
#अगर defined(WITH_OPENSSL) && defined(OPENSSL_PRNG_ONLY)
	अगर (RAND_bytes(s, len) <= 0)
		fatal("Couldn't obtain random bytes (error 0x%lx)",
		    (अचिन्हित दीर्घ)ERR_get_error());
#अन्यथा
	पूर्णांक fd, save_errno;
	ssize_t r;
	माप_प्रकार o = 0;

#अगर_घोषित WITH_OPENSSL
	अगर (RAND_bytes(s, len) == 1)
		वापस 0;
#पूर्ण_अगर
#अगर_घोषित HAVE_GETENTROPY
	अगर ((r = getentropy(s, len)) == 0)
		वापस 0;
#पूर्ण_अगर /* HAVE_GETENTROPY */
#अगर_घोषित HAVE_GETRANDOM
	अगर ((r = getrandom(s, len, 0)) > 0 && (माप_प्रकार)r == len)
		वापस 0;
#पूर्ण_अगर /* HAVE_GETRANDOM */

	अगर ((fd = खोलो(SSH_RANDOM_DEV, O_RDONLY)) == -1) {
		save_errno = त्रुटि_सं;
		/* Try egd/prngd before giving up. */
		अगर (seed_from_prngd(s, len) == 0)
			वापस 0;
		fatal("Couldn't open %s: %s", SSH_RANDOM_DEV,
		    म_त्रुटि(save_errno));
	}
	जबतक (o < len) {
		r = पढ़ो(fd, (u_char *)s + o, len - o);
		अगर (r < 0) {
			अगर (त्रुटि_सं == EAGAIN || त्रुटि_सं == EINTR ||
			    त्रुटि_सं == EWOULDBLOCK)
				जारी;
			fatal("read %s: %s", SSH_RANDOM_DEV, म_त्रुटि(त्रुटि_सं));
		}
		o += r;
	}
	बंद(fd);
#पूर्ण_अगर /* WITH_OPENSSL */
	वापस 0;
}
