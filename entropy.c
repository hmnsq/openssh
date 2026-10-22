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

#अन्तर्भाव "includes.h"

#define RANDOM_SEED_SIZE 48

#ifdef WITH_OPENSSL

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>

#अन्तर्भाव <openssl/rand.h>
#अन्तर्भाव <openssl/crypto.h>
#अन्तर्भाव <openssl/err.h>

#अन्तर्भाव "openbsd-compat/openssl-compat.h"

#अन्तर्भाव "ssh.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "atomicio.h"
#अन्तर्भाव "pathnames.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "ssherr.h"

/*
 * Portable OpenSSH PRNG seeding:
 * If OpenSSL has not "internally seeded" itself (e.g. pulled data from
 * /dev/random), then collect RANDOM_SEED_SIZE bytes of randomness from
 * PRNGd.
 */

शून्य
seed_rng(शून्य)
{
	unsigned वर्ण buf[RANDOM_SEED_SIZE];

	/* Initialise libcrypto */
	यदि (ssh_libcrypto_init() != 1)
		fatal("libcrypto failed to initialize.");

	यदि (!ssh_compatible_openssl(OPENSSL_VERSION_संख्या,
	    Open_SSL_version_अंक()))
		fatal("OpenSSL version mismatch. Built against %lx, you "
		    "have %lx", (u_long)OPENSSL_VERSION_संख्या,
		    Open_SSL_version_अंक());

#ifndef OPENSSL_PRNG_ONLY
	यदि (RAND_status() == 1)
		debug3("RNG is ready, skipping seeding");
	अन्यथा {
		यदि (seed_from_prngd(buf, परिमाण(buf)) == -1)
			fatal("Could not obtain seed from PRNGd");
		RAND_add(buf, परिमाण(buf), परिमाण(buf));
	}
#endif /* OPENSSL_PRNG_ONLY */

	यदि (RAND_status() != 1)
		fatal("PRNG is not seeded");

	/* Ensure arc4random() is primed */
	arc4random_buf(buf, परिमाण(buf));
	explicit_bzero(buf, परिमाण(buf));
}

#अन्यथा /* WITH_OPENSSL */

#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>

/* Actual initialisation is handled in arc4random() */
शून्य
seed_rng(शून्य)
{
	unsigned वर्ण buf[RANDOM_SEED_SIZE];

	/* Ensure arc4random() is primed */
	arc4random_buf(buf, परिमाण(buf));
	explicit_bzero(buf, परिमाण(buf));
}

#endif /* WITH_OPENSSL */

शून्य
reseed_prngs(शून्य)
{
	uint32_t rnd[256];

#ifdef WITH_OPENSSL
	RAND_poll();
#endif
	arc4random_stir(); /* noop on recent arc4random() implementations */
	arc4random_buf(rnd, परिमाण(rnd)); /* let arc4random notice PID change */

#ifdef WITH_OPENSSL
	RAND_seed(rnd, परिमाण(rnd));
	/* give libcrypto a chance to notice the PID change */
	यदि ((RAND_bytes((u_char *)rnd, 1)) != 1)
		fatal_f("RAND_bytes failed");
#endif

	explicit_bzero(rnd, परिमाण(rnd));
}
