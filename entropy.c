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

#تعریف_کرو RANDOM_بیج_سائز 48

#اگر_تعریف_شدہ WITH_OPENSSL

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

خالی
بیج_rng(خالی)
{
	غیرعلامتی حرف buf[RANDOM_بیج_سائز];

	/* Initialise libcrypto */
	اگر (ssh_libcrypto_init() != 1)
		fatal("libcrypto failed to initialize.");

	اگر (!ssh_compatible_openssl(OPENSSL_نسخہ_نمبر,
	    Open_SSL_نسخہ_عدد()))
		fatal("OpenSSL version mismatch. Built against %lx, you "
		    "have %lx", (u_long)OPENSSL_نسخہ_نمبر,
		    Open_SSL_نسخہ_عدد());

#اگر_غیر_تعریف_شدہ OPENSSL_PRNG_ONLY
	اگر (RAND_حالت() == 1)
		debug3("RNG is ready, skipping seeding");
	ورنہ {
		اگر (بیج_from_prngd(buf, حجم(buf)) == -1)
			fatal("Could not obtain seed from PRNGd");
		RAND_جوڑو(buf, حجم(buf), حجم(buf));
	}
#اگر_ختم /* OPENSSL_PRNG_ONLY */

	اگر (RAND_حالت() != 1)
		fatal("PRNG is not seeded");

	/* Ensure arc4random() is primed */
	arc4random_buf(buf, حجم(buf));
	explicit_bzero(buf, حجم(buf));
}

#ورنہ /* WITH_OPENSSL */

#شامل <stdlib.h>
#شامل <string.h>

/* Actual initialisation is handled in arc4random() */
خالی
بیج_rng(خالی)
{
	غیرعلامتی حرف buf[RANDOM_بیج_سائز];

	/* Ensure arc4random() is primed */
	arc4random_buf(buf, حجم(buf));
	explicit_bzero(buf, حجم(buf));
}

#اگر_ختم /* WITH_OPENSSL */

خالی
reseed_prngs(خالی)
{
	uint32_t rnd[256];

#اگر_تعریف_شدہ WITH_OPENSSL
	RAND_poll();
#اگر_ختم
	arc4random_stir(); /* noop on recent arc4random() implementations */
	arc4random_buf(rnd, حجم(rnd)); /* let arc4random notice PID change */

#اگر_تعریف_شدہ WITH_OPENSSL
	RAND_بیج(rnd, حجم(rnd));
	/* give libcrypto a chance to notice the PID change */
	اگر ((RAND_بائٹیں((u_char *)rnd, 1)) != 1)
		fatal_f("RAND_bytes failed");
#اگر_ختم

	explicit_bzero(rnd, حجم(rnd));
}
