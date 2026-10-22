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

#ضمن "includes.h"

#define RANDOM_SEED_SIZE 48

#ifdef WITH_OPENSSL

#ضمن <sys/types.h>

#ضمن <errno.h>
#ضمن <signal.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <unistd.h>

#ضمن <openssl/rand.h>
#ضمن <openssl/crypto.h>
#ضمن <openssl/err.h>

#ضمن "openbsd-compat/openssl-compat.h"

#ضمن "ssh.h"
#ضمن "misc.h"
#ضمن "xmalloc.h"
#ضمن "atomicio.h"
#ضمن "pathnames.h"
#ضمن "log.h"
#ضمن "sshbuf.h"
#ضمن "ssherr.h"

/*
 * Portable OpenSSH PRNG seeding:
 * If OpenSSL has not "internally seeded" itself (e.g. pulled data from
 * /dev/random), then collect RANDOM_SEED_SIZE bytes of randomness from
 * PRNGd.
 */

فراغ
seed_rng(فراغ)
{
	unsigned حرف buf[RANDOM_SEED_SIZE];

	/* Initialise libcrypto */
	إذا (ssh_libcrypto_init() != 1)
		fatal("libcrypto failed to initialize.");

	إذا (!ssh_compatible_openssl(OPENSSL_VERSION_نمبر,
	    Open_SSL_version_عدد()))
		fatal("OpenSSL version mismatch. Built against %lx, you "
		    "have %lx", (u_long)OPENSSL_VERSION_نمبر,
		    Open_SSL_version_عدد());

#ifndef OPENSSL_PRNG_ONLY
	إذا (RAND_status() == 1)
		debug3("RNG is ready, skipping seeding");
	وإلا {
		إذا (seed_from_prngd(buf, حجم(buf)) == -1)
			fatal("Could not obtain seed from PRNGd");
		RAND_add(buf, حجم(buf), حجم(buf));
	}
#endif /* OPENSSL_PRNG_ONLY */

	إذا (RAND_status() != 1)
		fatal("PRNG is not seeded");

	/* Ensure arc4random() is primed */
	arc4random_buf(buf, حجم(buf));
	explicit_bzero(buf, حجم(buf));
}

#وإلا /* WITH_OPENSSL */

#ضمن <stdlib.h>
#ضمن <string.h>

/* Actual initialisation is handled in arc4random() */
فراغ
seed_rng(فراغ)
{
	unsigned حرف buf[RANDOM_SEED_SIZE];

	/* Ensure arc4random() is primed */
	arc4random_buf(buf, حجم(buf));
	explicit_bzero(buf, حجم(buf));
}

#endif /* WITH_OPENSSL */

فراغ
reseed_prngs(فراغ)
{
	uint32_t rnd[256];

#ifdef WITH_OPENSSL
	RAND_poll();
#endif
	arc4random_stir(); /* noop on recent arc4random() implementations */
	arc4random_buf(rnd, حجم(rnd)); /* let arc4random notice PID change */

#ifdef WITH_OPENSSL
	RAND_seed(rnd, حجم(rnd));
	/* give libcrypto a chance to notice the PID change */
	إذا ((RAND_bytes((u_char *)rnd, 1)) != 1)
		fatal_f("RAND_bytes failed");
#endif

	explicit_bzero(rnd, حجم(rnd));
}
