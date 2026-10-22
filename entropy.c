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

#ಅನ್ತರ್ಭಾವ "includes.h"

#define RANDOM_SEED_SIZE 48

#ifdef WITH_OPENSSL

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ಅನ್ತರ್ಭಾವ <openssl/rand.h>
#ಅನ್ತರ್ಭಾವ <openssl/crypto.h>
#ಅನ್ತರ್ಭಾವ <openssl/err.h>

#ಅನ್ತರ್ಭಾವ "openbsd-compat/openssl-compat.h"

#ಅನ್ತರ್ಭಾವ "ssh.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "atomicio.h"
#ಅನ್ತರ್ಭಾವ "pathnames.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"

/*
 * Portable OpenSSH PRNG seeding:
 * If OpenSSL has not "internally seeded" itself (e.g. pulled data from
 * /dev/random), then collect RANDOM_SEED_SIZE bytes of randomness from
 * PRNGd.
 */

ಶೂನ್ಯ
seed_rng(ಶೂನ್ಯ)
{
	unsigned ವರ್ಣ buf[RANDOM_SEED_SIZE];

	/* Initialise libcrypto */
	ಯದಿ (ssh_libcrypto_init() != 1)
		fatal("libcrypto failed to initialize.");

	ಯದಿ (!ssh_compatible_openssl(OPENSSL_VERSION_ಸಂಖ್ಯೆ,
	    Open_SSL_version_ಅಂಕೆ()))
		fatal("OpenSSL version mismatch. Built against %lx, you "
		    "have %lx", (u_long)OPENSSL_VERSION_ಸಂಖ್ಯೆ,
		    Open_SSL_version_ಅಂಕೆ());

#ifndef OPENSSL_PRNG_ONLY
	ಯದಿ (RAND_status() == 1)
		debug3("RNG is ready, skipping seeding");
	ಅನ್ಯಥಾ {
		ಯದಿ (seed_from_prngd(buf, ಪರಿಮಾಣ(buf)) == -1)
			fatal("Could not obtain seed from PRNGd");
		RAND_add(buf, ಪರಿಮಾಣ(buf), ಪರಿಮಾಣ(buf));
	}
#endif /* OPENSSL_PRNG_ONLY */

	ಯದಿ (RAND_status() != 1)
		fatal("PRNG is not seeded");

	/* Ensure arc4random() is primed */
	arc4random_buf(buf, ಪರಿಮಾಣ(buf));
	explicit_bzero(buf, ಪರಿಮಾಣ(buf));
}

#ಅನ್ಯಥಾ /* WITH_OPENSSL */

#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

/* Actual initialisation is handled in arc4random() */
ಶೂನ್ಯ
seed_rng(ಶೂನ್ಯ)
{
	unsigned ವರ್ಣ buf[RANDOM_SEED_SIZE];

	/* Ensure arc4random() is primed */
	arc4random_buf(buf, ಪರಿಮಾಣ(buf));
	explicit_bzero(buf, ಪರಿಮಾಣ(buf));
}

#endif /* WITH_OPENSSL */

ಶೂನ್ಯ
reseed_prngs(ಶೂನ್ಯ)
{
	uint32_t rnd[256];

#ifdef WITH_OPENSSL
	RAND_poll();
#endif
	arc4random_stir(); /* noop on recent arc4random() implementations */
	arc4random_buf(rnd, ಪರಿಮಾಣ(rnd)); /* let arc4random notice PID change */

#ifdef WITH_OPENSSL
	RAND_seed(rnd, ಪರಿಮಾಣ(rnd));
	/* give libcrypto a chance to notice the PID change */
	ಯದಿ ((RAND_bytes((u_char *)rnd, 1)) != 1)
		fatal_f("RAND_bytes failed");
#endif

	explicit_bzero(rnd, ಪರಿಮಾಣ(rnd));
}
