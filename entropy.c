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

#অন্তর্ভাব "includes.h"

#define RANDOM_SEED_SIZE 48

#ifdef WITH_OPENSSL

#অন্তর্ভাব <sys/types.h>

#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>

#অন্তর্ভাব <openssl/rand.h>
#অন্তর্ভাব <openssl/crypto.h>
#অন্তর্ভাব <openssl/err.h>

#অন্তর্ভাব "openbsd-compat/openssl-compat.h"

#অন্তর্ভাব "ssh.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "atomicio.h"
#অন্তর্ভাব "pathnames.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "ssherr.h"

/*
 * Portable OpenSSH PRNG seeding:
 * If OpenSSL has not "internally seeded" itself (e.g. pulled data from
 * /dev/random), then collect RANDOM_SEED_SIZE bytes of randomness from
 * PRNGd.
 */

শূন্য
seed_rng(শূন্য)
{
	unsigned বর্ণ buf[RANDOM_SEED_SIZE];

	/* Initialise libcrypto */
	যদি (ssh_libcrypto_init() != 1)
		fatal("libcrypto failed to initialize.");

	যদি (!ssh_compatible_openssl(OPENSSL_VERSION_সংখ্যা,
	    Open_SSL_version_অঙ্ক()))
		fatal("OpenSSL version mismatch. Built against %lx, you "
		    "have %lx", (u_long)OPENSSL_VERSION_সংখ্যা,
		    Open_SSL_version_অঙ্ক());

#ifndef OPENSSL_PRNG_ONLY
	যদি (RAND_status() == 1)
		debug3("RNG is ready, skipping seeding");
	অন্যথা {
		যদি (seed_from_prngd(buf, পরিমাণ(buf)) == -1)
			fatal("Could not obtain seed from PRNGd");
		RAND_add(buf, পরিমাণ(buf), পরিমাণ(buf));
	}
#endif /* OPENSSL_PRNG_ONLY */

	যদি (RAND_status() != 1)
		fatal("PRNG is not seeded");

	/* Ensure arc4random() is primed */
	arc4random_buf(buf, পরিমাণ(buf));
	explicit_bzero(buf, পরিমাণ(buf));
}

#অন্যথা /* WITH_OPENSSL */

#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>

/* Actual initialisation is handled in arc4random() */
শূন্য
seed_rng(শূন্য)
{
	unsigned বর্ণ buf[RANDOM_SEED_SIZE];

	/* Ensure arc4random() is primed */
	arc4random_buf(buf, পরিমাণ(buf));
	explicit_bzero(buf, পরিমাণ(buf));
}

#endif /* WITH_OPENSSL */

শূন্য
reseed_prngs(শূন্য)
{
	uint32_t rnd[256];

#ifdef WITH_OPENSSL
	RAND_poll();
#endif
	arc4random_stir(); /* noop on recent arc4random() implementations */
	arc4random_buf(rnd, পরিমাণ(rnd)); /* let arc4random notice PID change */

#ifdef WITH_OPENSSL
	RAND_seed(rnd, পরিমাণ(rnd));
	/* give libcrypto a chance to notice the PID change */
	যদি ((RAND_bytes((u_char *)rnd, 1)) != 1)
		fatal_f("RAND_bytes failed");
#endif

	explicit_bzero(rnd, পরিমাণ(rnd));
}
