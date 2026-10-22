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

#அந்தர்பாவ "includes.h"

#define RANDOM_SEED_SIZE 48

#ifdef WITH_OPENSSL

#அந்தர்பாவ <sys/types.h>

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>

#அந்தர்பாவ <openssl/rand.h>
#அந்தர்பாவ <openssl/crypto.h>
#அந்தர்பாவ <openssl/err.h>

#அந்தர்பாவ "openbsd-compat/openssl-compat.h"

#அந்தர்பாவ "ssh.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "atomicio.h"
#அந்தர்பாவ "pathnames.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "ssherr.h"

/*
 * Portable OpenSSH PRNG seeding:
 * If OpenSSL has not "internally seeded" itself (e.g. pulled data from
 * /dev/random), then collect RANDOM_SEED_SIZE bytes of randomness from
 * PRNGd.
 */

வெறுமை
seed_rng(வெறுமை)
{
	unsigned எழுத்து buf[RANDOM_SEED_SIZE];

	/* Initialise libcrypto */
	எனில் (ssh_libcrypto_init() != 1)
		fatal("libcrypto failed to initialize.");

	எனில் (!ssh_compatible_openssl(OPENSSL_VERSION_எண்,
	    Open_SSL_version_இலக்கம்()))
		fatal("OpenSSL version mismatch. Built against %lx, you "
		    "have %lx", (u_long)OPENSSL_VERSION_எண்,
		    Open_SSL_version_இலக்கம்());

#ifndef OPENSSL_PRNG_ONLY
	எனில் (RAND_status() == 1)
		debug3("RNG is ready, skipping seeding");
	இல்லையெனில் {
		எனில் (seed_from_prngd(buf, அளவு(buf)) == -1)
			fatal("Could not obtain seed from PRNGd");
		RAND_add(buf, அளவு(buf), அளவு(buf));
	}
#endif /* OPENSSL_PRNG_ONLY */

	எனில் (RAND_status() != 1)
		fatal("PRNG is not seeded");

	/* Ensure arc4random() is primed */
	arc4random_buf(buf, அளவு(buf));
	explicit_bzero(buf, அளவு(buf));
}

#இல்லையெனில் /* WITH_OPENSSL */

#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>

/* Actual initialisation is handled in arc4random() */
வெறுமை
seed_rng(வெறுமை)
{
	unsigned எழுத்து buf[RANDOM_SEED_SIZE];

	/* Ensure arc4random() is primed */
	arc4random_buf(buf, அளவு(buf));
	explicit_bzero(buf, அளவு(buf));
}

#endif /* WITH_OPENSSL */

வெறுமை
reseed_prngs(வெறுமை)
{
	uint32_t rnd[256];

#ifdef WITH_OPENSSL
	RAND_poll();
#endif
	arc4random_stir(); /* noop on recent arc4random() implementations */
	arc4random_buf(rnd, அளவு(rnd)); /* let arc4random notice PID change */

#ifdef WITH_OPENSSL
	RAND_seed(rnd, அளவு(rnd));
	/* give libcrypto a chance to notice the PID change */
	எனில் ((RAND_bytes((u_char *)rnd, 1)) != 1)
		fatal_f("RAND_bytes failed");
#endif

	explicit_bzero(rnd, அளவு(rnd));
}
