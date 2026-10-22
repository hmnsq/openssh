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

#شامل "includes.h"

#define RANDOM_SEED_SIZE 48

#ifdef WITH_OPENSSL

#شامل <sys/types.h>

#شامل <errno.h>
#شامل <signal.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <unistd.h>

#شامل <openssl/rand.h>
#شامل <openssl/crypto.h>
#شامل <openssl/err.h>

#شامل "openbsd-compat/openssl-compat.h"

#شامل "ssh.h"
#شامل "misc.h"
#شامل "xmalloc.h"
#شامل "atomicio.h"
#شامل "pathnames.h"
#شامل "log.h"
#شامل "sshbuf.h"
#شامل "ssherr.h"

/*
 * Portable OpenSSH PRNG seeding:
 * If OpenSSL has not "internally seeded" itself (e.g. pulled data from
 * /dev/random), then collect RANDOM_SEED_SIZE bytes of randomness from
 * PRNGd.
 */

تهی
seed_rng(تهی)
{
	unsigned نویسه buf[RANDOM_SEED_SIZE];

	/* Initialise libcrypto */
	اگر (ssh_libcrypto_init() != 1)
		fatal("libcrypto failed to initialize.");

	اگر (!ssh_compatible_openssl(OPENSSL_VERSION_عدد,
	    Open_SSL_version_رقم()))
		fatal("OpenSSL version mismatch. Built against %lx, you "
		    "have %lx", (u_long)OPENSSL_VERSION_عدد,
		    Open_SSL_version_رقم());

#ifndef OPENSSL_PRNG_ONLY
	اگر (RAND_status() == 1)
		debug3("RNG is ready, skipping seeding");
	وگرنه {
		اگر (seed_from_prngd(buf, اندازه(buf)) == -1)
			fatal("Could not obtain seed from PRNGd");
		RAND_add(buf, اندازه(buf), اندازه(buf));
	}
#endif /* OPENSSL_PRNG_ONLY */

	اگر (RAND_status() != 1)
		fatal("PRNG is not seeded");

	/* Ensure arc4random() is primed */
	arc4random_buf(buf, اندازه(buf));
	explicit_bzero(buf, اندازه(buf));
}

#وگرنه /* WITH_OPENSSL */

#شامل <stdlib.h>
#شامل <string.h>

/* Actual initialisation is handled in arc4random() */
تهی
seed_rng(تهی)
{
	unsigned نویسه buf[RANDOM_SEED_SIZE];

	/* Ensure arc4random() is primed */
	arc4random_buf(buf, اندازه(buf));
	explicit_bzero(buf, اندازه(buf));
}

#endif /* WITH_OPENSSL */

تهی
reseed_prngs(تهی)
{
	uint32_t rnd[256];

#ifdef WITH_OPENSSL
	RAND_poll();
#endif
	arc4random_stir(); /* noop on recent arc4random() implementations */
	arc4random_buf(rnd, اندازه(rnd)); /* let arc4random notice PID change */

#ifdef WITH_OPENSSL
	RAND_seed(rnd, اندازه(rnd));
	/* give libcrypto a chance to notice the PID change */
	اگر ((RAND_bytes((u_char *)rnd, 1)) != 1)
		fatal_f("RAND_bytes failed");
#endif

	explicit_bzero(rnd, اندازه(rnd));
}
