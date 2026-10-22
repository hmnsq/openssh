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

#അന്തര്ഭാവ "includes.h"

#define RANDOM_SEED_SIZE 48

#ifdef WITH_OPENSSL

#അന്തര്ഭാവ <sys/types.h>

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>

#അന്തര്ഭാവ <openssl/rand.h>
#അന്തര്ഭാവ <openssl/crypto.h>
#അന്തര്ഭാവ <openssl/err.h>

#അന്തര്ഭാവ "openbsd-compat/openssl-compat.h"

#അന്തര്ഭാവ "ssh.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "atomicio.h"
#അന്തര്ഭാവ "pathnames.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "ssherr.h"

/*
 * Portable OpenSSH PRNG seeding:
 * If OpenSSL has not "internally seeded" itself (e.g. pulled data from
 * /dev/random), then collect RANDOM_SEED_SIZE bytes of randomness from
 * PRNGd.
 */

ശൂന്യം
seed_rng(ശൂന്യം)
{
	unsigned അക്ഷരം buf[RANDOM_SEED_SIZE];

	/* Initialise libcrypto */
	എങ്കിൽ (ssh_libcrypto_init() != 1)
		fatal("libcrypto failed to initialize.");

	എങ്കിൽ (!ssh_compatible_openssl(OPENSSL_VERSION_സംഖ്യ,
	    Open_SSL_version_അക്കം()))
		fatal("OpenSSL version mismatch. Built against %lx, you "
		    "have %lx", (u_long)OPENSSL_VERSION_സംഖ്യ,
		    Open_SSL_version_അക്കം());

#ifndef OPENSSL_PRNG_ONLY
	എങ്കിൽ (RAND_status() == 1)
		debug3("RNG is ready, skipping seeding");
	അല്ലെങ്കിൽ {
		എങ്കിൽ (seed_from_prngd(buf, വലുപ്പം(buf)) == -1)
			fatal("Could not obtain seed from PRNGd");
		RAND_add(buf, വലുപ്പം(buf), വലുപ്പം(buf));
	}
#endif /* OPENSSL_PRNG_ONLY */

	എങ്കിൽ (RAND_status() != 1)
		fatal("PRNG is not seeded");

	/* Ensure arc4random() is primed */
	arc4random_buf(buf, വലുപ്പം(buf));
	explicit_bzero(buf, വലുപ്പം(buf));
}

#അല്ലെങ്കിൽ /* WITH_OPENSSL */

#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>

/* Actual initialisation is handled in arc4random() */
ശൂന്യം
seed_rng(ശൂന്യം)
{
	unsigned അക്ഷരം buf[RANDOM_SEED_SIZE];

	/* Ensure arc4random() is primed */
	arc4random_buf(buf, വലുപ്പം(buf));
	explicit_bzero(buf, വലുപ്പം(buf));
}

#endif /* WITH_OPENSSL */

ശൂന്യം
reseed_prngs(ശൂന്യം)
{
	uint32_t rnd[256];

#ifdef WITH_OPENSSL
	RAND_poll();
#endif
	arc4random_stir(); /* noop on recent arc4random() implementations */
	arc4random_buf(rnd, വലുപ്പം(rnd)); /* let arc4random notice PID change */

#ifdef WITH_OPENSSL
	RAND_seed(rnd, വലുപ്പം(rnd));
	/* give libcrypto a chance to notice the PID change */
	എങ്കിൽ ((RAND_bytes((u_char *)rnd, 1)) != 1)
		fatal_f("RAND_bytes failed");
#endif

	explicit_bzero(rnd, വലുപ്പം(rnd));
}
