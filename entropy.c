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

#అన్తర్భావ "includes.h"

#నిర్వచించు RANDOM_విత్తనం_కొలత 48

#నిర్వచితమైతే WITH_OPENSSL

#అన్తర్భావ <sys/types.h>

#అన్తర్భావ <errno.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>

#అన్తర్భావ <openssl/rand.h>
#అన్తర్భావ <openssl/crypto.h>
#అన్తర్భావ <openssl/err.h>

#అన్తర్భావ "openbsd-compat/openssl-compat.h"

#అన్తర్భావ "ssh.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "atomicio.h"
#అన్తర్భావ "pathnames.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "ssherr.h"

/*
 * Portable OpenSSH PRNG seeding:
 * If OpenSSL has not "internally seeded" itself (e.g. pulled data from
 * /dev/random), then collect RANDOM_SEED_SIZE bytes of randomness from
 * PRNGd.
 */

శూన్య
విత్తనం_rng(శూన్య)
{
	గుర్తులేని అక్షరం buf[RANDOM_విత్తనం_కొలత];

	/* Initialise libcrypto */
	ఒకవేళ (ssh_libcrypto_init() != 1)
		fatal("libcrypto failed to initialize.");

	ఒకవేళ (!ssh_compatible_openssl(OPENSSL_సంస్కరణ_సంఖ్య,
	    Open_SSL_సంస్కరణ_అంకె()))
		fatal("OpenSSL version mismatch. Built against %lx, you "
		    "have %lx", (u_long)OPENSSL_సంస్కరణ_సంఖ్య,
		    Open_SSL_సంస్కరణ_అంకె());

#నిర్వచితం_కాకపోతే OPENSSL_PRNG_ONLY
	ఒకవేళ (RAND_స్థితి() == 1)
		debug3("RNG is ready, skipping seeding");
	లేకపోతే {
		ఒకవేళ (విత్తనం_from_prngd(buf, పరిమాణం(buf)) == -1)
			fatal("Could not obtain seed from PRNGd");
		RAND_కూడు(buf, పరిమాణం(buf), పరిమాణం(buf));
	}
#అయితే_ముగింపు /* OPENSSL_PRNG_ONLY */

	ఒకవేళ (RAND_స్థితి() != 1)
		fatal("PRNG is not seeded");

	/* Ensure arc4random() is primed */
	arc4random_buf(buf, పరిమాణం(buf));
	explicit_bzero(buf, పరిమాణం(buf));
}

#లేకపోతే /* WITH_OPENSSL */

#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>

/* Actual initialisation is handled in arc4random() */
శూన్య
విత్తనం_rng(శూన్య)
{
	గుర్తులేని అక్షరం buf[RANDOM_విత్తనం_కొలత];

	/* Ensure arc4random() is primed */
	arc4random_buf(buf, పరిమాణం(buf));
	explicit_bzero(buf, పరిమాణం(buf));
}

#అయితే_ముగింపు /* WITH_OPENSSL */

శూన్య
reseed_prngs(శూన్య)
{
	uint32_t rnd[256];

#నిర్వచితమైతే WITH_OPENSSL
	RAND_poll();
#అయితే_ముగింపు
	arc4random_stir(); /* noop on recent arc4random() implementations */
	arc4random_buf(rnd, పరిమాణం(rnd)); /* let arc4random notice PID change */

#నిర్వచితమైతే WITH_OPENSSL
	RAND_విత్తనం(rnd, పరిమాణం(rnd));
	/* give libcrypto a chance to notice the PID change */
	ఒకవేళ ((RAND_బైట్లు((u_char *)rnd, 1)) != 1)
		fatal_f("RAND_bytes failed");
#అయితే_ముగింపు

	explicit_bzero(rnd, పరిమాణం(rnd));
}
