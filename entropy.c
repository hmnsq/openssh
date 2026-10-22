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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#define RANDOM_SEED_SIZE 48

#ifdef WITH_OPENSSL

#ଅନ୍ତର୍ଭାଵ <sys/types.h>

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

#ଅନ୍ତର୍ଭାଵ <openssl/rand.h>
#ଅନ୍ତର୍ଭାଵ <openssl/crypto.h>
#ଅନ୍ତର୍ଭାଵ <openssl/err.h>

#ଅନ୍ତର୍ଭାଵ "openbsd-compat/openssl-compat.h"

#ଅନ୍ତର୍ଭାଵ "ssh.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "atomicio.h"
#ଅନ୍ତର୍ଭାଵ "pathnames.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"

/*
 * Portable OpenSSH PRNG seeding:
 * If OpenSSL has not "internally seeded" itself (e.g. pulled data from
 * /dev/random), then collect RANDOM_SEED_SIZE bytes of randomness from
 * PRNGd.
 */

ଶୂନ୍ୟ
seed_rng(ଶୂନ୍ୟ)
{
	unsigned ଅକ୍ଷର buf[RANDOM_SEED_SIZE];

	/* Initialise libcrypto */
	ଯଦି (ssh_libcrypto_init() != 1)
		fatal("libcrypto failed to initialize.");

	ଯଦି (!ssh_compatible_openssl(OPENSSL_VERSION_ସଂଖ୍ୟା,
	    Open_SSL_version_ଅଙ୍କ()))
		fatal("OpenSSL version mismatch. Built against %lx, you "
		    "have %lx", (u_long)OPENSSL_VERSION_ସଂଖ୍ୟା,
		    Open_SSL_version_ଅଙ୍କ());

#ifndef OPENSSL_PRNG_ONLY
	ଯଦି (RAND_status() == 1)
		debug3("RNG is ready, skipping seeding");
	ଅନ୍ୟଥା {
		ଯଦି (seed_from_prngd(buf, ଆକାର(buf)) == -1)
			fatal("Could not obtain seed from PRNGd");
		RAND_add(buf, ଆକାର(buf), ଆକାର(buf));
	}
#endif /* OPENSSL_PRNG_ONLY */

	ଯଦି (RAND_status() != 1)
		fatal("PRNG is not seeded");

	/* Ensure arc4random() is primed */
	arc4random_buf(buf, ଆକାର(buf));
	explicit_bzero(buf, ଆକାର(buf));
}

#ଅନ୍ୟଥା /* WITH_OPENSSL */

#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>

/* Actual initialisation is handled in arc4random() */
ଶୂନ୍ୟ
seed_rng(ଶୂନ୍ୟ)
{
	unsigned ଅକ୍ଷର buf[RANDOM_SEED_SIZE];

	/* Ensure arc4random() is primed */
	arc4random_buf(buf, ଆକାର(buf));
	explicit_bzero(buf, ଆକାର(buf));
}

#endif /* WITH_OPENSSL */

ଶୂନ୍ୟ
reseed_prngs(ଶୂନ୍ୟ)
{
	uint32_t rnd[256];

#ifdef WITH_OPENSSL
	RAND_poll();
#endif
	arc4random_stir(); /* noop on recent arc4random() implementations */
	arc4random_buf(rnd, ଆକାର(rnd)); /* let arc4random notice PID change */

#ifdef WITH_OPENSSL
	RAND_seed(rnd, ଆକାର(rnd));
	/* give libcrypto a chance to notice the PID change */
	ଯଦି ((RAND_bytes((u_char *)rnd, 1)) != 1)
		fatal_f("RAND_bytes failed");
#endif

	explicit_bzero(rnd, ଆକାର(rnd));
}
