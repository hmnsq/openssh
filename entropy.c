/*
 * Copyright (c) 2001 Damien Miller.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RANDOM_ਬੀਜ_ਮਾਪ 48

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/rand.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/crypto.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/err.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "openbsd-compat/openssl-compat.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "ssh.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "atomicio.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "pathnames.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"

/*
 * Portable OpenSSH PRNG seeding:
 * If OpenSSL has not "internally seeded" itself (e.g. pulled data from
 * /dev/random), then collect RANDOM_SEED_SIZE bytes of randomness from
 * PRNGd.
 */

ਖਾਲੀ
ਬੀਜ_rng(ਖਾਲੀ)
{
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ buf[RANDOM_ਬੀਜ_ਮਾਪ];

	/* Initialise libcrypto */
	ਜੇ (ssh_libcrypto_init() != 1)
		fatal("libcrypto failed to initialize.");

	ਜੇ (!ssh_compatible_openssl(OPENSSL_ਸੰਸਕਰਣ_ਸੰਖਿਆ,
	    Open_SSL_ਸੰਸਕਰਣ_ਅੰਕ()))
		fatal("OpenSSL version mismatch. Built against %lx, you "
		    "have %lx", (u_long)OPENSSL_ਸੰਸਕਰਣ_ਸੰਖਿਆ,
		    Open_SSL_ਸੰਸਕਰਣ_ਅੰਕ());

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ OPENSSL_PRNG_ONLY
	ਜੇ (RAND_ਸਥਿਤੀ() == 1)
		debug3("RNG is ready, skipping seeding");
	ਨਹੀਂਤਾਂ {
		ਜੇ (ਬੀਜ_from_prngd(buf, ਆਕਾਰ(buf)) == -1)
			fatal("Could not obtain seed from PRNGd");
		RAND_ਜੋੜੋ(buf, ਆਕਾਰ(buf), ਆਕਾਰ(buf));
	}
#ਜੇ_ਅੰਤ /* OPENSSL_PRNG_ONLY */

	ਜੇ (RAND_ਸਥਿਤੀ() != 1)
		fatal("PRNG is not seeded");

	/* Ensure arc4random() is primed */
	arc4random_buf(buf, ਆਕਾਰ(buf));
	explicit_bzero(buf, ਆਕਾਰ(buf));
}

#ਨਹੀਂਤਾਂ /* WITH_OPENSSL */

#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

/* Actual initialisation is handled in arc4random() */
ਖਾਲੀ
ਬੀਜ_rng(ਖਾਲੀ)
{
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ buf[RANDOM_ਬੀਜ_ਮਾਪ];

	/* Ensure arc4random() is primed */
	arc4random_buf(buf, ਆਕਾਰ(buf));
	explicit_bzero(buf, ਆਕਾਰ(buf));
}

#ਜੇ_ਅੰਤ /* WITH_OPENSSL */

ਖਾਲੀ
reseed_prngs(ਖਾਲੀ)
{
	uint32_t rnd[256];

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	RAND_poll();
#ਜੇ_ਅੰਤ
	arc4random_stir(); /* noop on recent arc4random() implementations */
	arc4random_buf(rnd, ਆਕਾਰ(rnd)); /* let arc4random notice PID change */

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	RAND_ਬੀਜ(rnd, ਆਕਾਰ(rnd));
	/* give libcrypto a chance to notice the PID change */
	ਜੇ ((RAND_ਬਾਈਟਾਂ((u_char *)rnd, 1)) != 1)
		fatal_f("RAND_bytes failed");
#ਜੇ_ਅੰਤ

	explicit_bzero(rnd, ਆਕਾਰ(rnd));
}
