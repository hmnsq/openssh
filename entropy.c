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

#અન્તર્ભાવ "includes.h"

#define RANDOM_SEED_SIZE 48

#ifdef WITH_OPENSSL

#અન્તર્ભાવ <sys/types.h>

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>

#અન્તર્ભાવ <openssl/rand.h>
#અન્તર્ભાવ <openssl/crypto.h>
#અન્તર્ભાવ <openssl/err.h>

#અન્તર્ભાવ "openbsd-compat/openssl-compat.h"

#અન્તર્ભાવ "ssh.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "atomicio.h"
#અન્તર્ભાવ "pathnames.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "ssherr.h"

/*
 * Portable OpenSSH PRNG seeding:
 * If OpenSSL has not "internally seeded" itself (e.g. pulled data from
 * /dev/random), then collect RANDOM_SEED_SIZE bytes of randomness from
 * PRNGd.
 */

શૂન્ય
seed_rng(શૂન્ય)
{
	unsigned અક્ષર buf[RANDOM_SEED_SIZE];

	/* Initialise libcrypto */
	જો (ssh_libcrypto_init() != 1)
		fatal("libcrypto failed to initialize.");

	જો (!ssh_compatible_openssl(OPENSSL_VERSION_સંખ્યા,
	    Open_SSL_version_અંક()))
		fatal("OpenSSL version mismatch. Built against %lx, you "
		    "have %lx", (u_long)OPENSSL_VERSION_સંખ્યા,
		    Open_SSL_version_અંક());

#ifndef OPENSSL_PRNG_ONLY
	જો (RAND_status() == 1)
		debug3("RNG is ready, skipping seeding");
	નહીંતર {
		જો (seed_from_prngd(buf, કદ(buf)) == -1)
			fatal("Could not obtain seed from PRNGd");
		RAND_add(buf, કદ(buf), કદ(buf));
	}
#endif /* OPENSSL_PRNG_ONLY */

	જો (RAND_status() != 1)
		fatal("PRNG is not seeded");

	/* Ensure arc4random() is primed */
	arc4random_buf(buf, કદ(buf));
	explicit_bzero(buf, કદ(buf));
}

#નહીંતર /* WITH_OPENSSL */

#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>

/* Actual initialisation is handled in arc4random() */
શૂન્ય
seed_rng(શૂન્ય)
{
	unsigned અક્ષર buf[RANDOM_SEED_SIZE];

	/* Ensure arc4random() is primed */
	arc4random_buf(buf, કદ(buf));
	explicit_bzero(buf, કદ(buf));
}

#endif /* WITH_OPENSSL */

શૂન્ય
reseed_prngs(શૂન્ય)
{
	uint32_t rnd[256];

#ifdef WITH_OPENSSL
	RAND_poll();
#endif
	arc4random_stir(); /* noop on recent arc4random() implementations */
	arc4random_buf(rnd, કદ(rnd)); /* let arc4random notice PID change */

#ifdef WITH_OPENSSL
	RAND_seed(rnd, કદ(rnd));
	/* give libcrypto a chance to notice the PID change */
	જો ((RAND_bytes((u_char *)rnd, 1)) != 1)
		fatal_f("RAND_bytes failed");
#endif

	explicit_bzero(rnd, કદ(rnd));
}
