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

#समावेश "includes.h"

#घोषणा RANDOM_SEED_आकार 48

#अगर_घोषित WITH_OPENSSL

#समावेश <sys/types.h>

#समावेश <errno.h>
#समावेश <signal.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <unistd.h>

#समावेश <openssl/rand.h>
#समावेश <openssl/crypto.h>
#समावेश <openssl/err.h>

#समावेश "openbsd-compat/openssl-compat.h"

#समावेश "ssh.h"
#समावेश "misc.h"
#समावेश "xmalloc.h"
#समावेश "atomicio.h"
#समावेश "pathnames.h"
#समावेश "log.h"
#समावेश "sshbuf.h"
#समावेश "ssherr.h"

/*
 * Portable OpenSSH PRNG seeding:
 * If OpenSSL has not "internally seeded" itself (e.g. pulled data from
 * /dev/random), then collect RANDOM_SEED_SIZE bytes of randomness from
 * PRNGd.
 */

व्योम
seed_rng(व्योम)
{
	अचिन्हित अक्षर buf[RANDOM_SEED_आकार];

	/* Initialise libcrypto */
	अगर (ssh_libcrypto_init() != 1)
		fatal("libcrypto failed to initialize.");

	अगर (!ssh_compatible_openssl(OPENSSL_VERSION_संख्या,
	    Open_SSL_version_अंक()))
		fatal("OpenSSL version mismatch. Built against %lx, you "
		    "have %lx", (u_long)OPENSSL_VERSION_संख्या,
		    Open_SSL_version_अंक());

#अगर_अघोषित OPENSSL_PRNG_ONLY
	अगर (RAND_status() == 1)
		debug3("RNG is ready, skipping seeding");
	अन्यथा {
		अगर (seed_from_prngd(buf, माप(buf)) == -1)
			fatal("Could not obtain seed from PRNGd");
		RAND_add(buf, माप(buf), माप(buf));
	}
#पूर्ण_अगर /* OPENSSL_PRNG_ONLY */

	अगर (RAND_status() != 1)
		fatal("PRNG is not seeded");

	/* Ensure arc4random() is primed */
	arc4random_buf(buf, माप(buf));
	explicit_bzero(buf, माप(buf));
}

#अन्यथा /* WITH_OPENSSL */

#समावेश <stdlib.h>
#समावेश <string.h>

/* Actual initialisation is handled in arc4random() */
व्योम
seed_rng(व्योम)
{
	अचिन्हित अक्षर buf[RANDOM_SEED_आकार];

	/* Ensure arc4random() is primed */
	arc4random_buf(buf, माप(buf));
	explicit_bzero(buf, माप(buf));
}

#पूर्ण_अगर /* WITH_OPENSSL */

व्योम
reseed_prngs(व्योम)
{
	uint32_t rnd[256];

#अगर_घोषित WITH_OPENSSL
	RAND_poll();
#पूर्ण_अगर
	arc4random_stir(); /* noop on recent arc4random() implementations */
	arc4random_buf(rnd, माप(rnd)); /* let arc4random notice PID change */

#अगर_घोषित WITH_OPENSSL
	RAND_seed(rnd, माप(rnd));
	/* give libcrypto a chance to notice the PID change */
	अगर ((RAND_bytes((u_char *)rnd, 1)) != 1)
		fatal_f("RAND_bytes failed");
#पूर्ण_अगर

	explicit_bzero(rnd, माप(rnd));
}
