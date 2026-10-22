/* $OpenBSD: kexgex.c,v 1.33 2026/02/14 00:18:34 jsg Exp $ */
/*
 * Copyright (c) 2000 Niels Provos.  All rights reserved.
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <openssl/evp.h>
#ಅನ್ತರ್ಭಾವ <signal.h>

#ಅನ್ತರ್ಭಾವ "openbsd-compat/openssl-compat.h"

#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "cipher.h"
#ಅನ್ತರ್ಭಾವ "kex.h"
#ಅನ್ತರ್ಭಾವ "ssh2.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "digest.h"

ಪೂರ್ಣಾಂಕ
kexgex_hash(
    ಪೂರ್ಣಾಂಕ hash_alg,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *client_ಆವೃತ್ತಿ,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *server_ಆವೃತ್ತಿ,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *client_kexinit,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *server_kexinit,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *server_host_ಕೀಲಿ_blob,
    ಪೂರ್ಣಾಂಕ min, ಪೂರ್ಣಾಂಕ wantbits, ಪೂರ್ಣಾಂಕ max,
    ಸ್ಥಿರಾಂಕ BIGNUM *ಅವಿಭಾಜ್ಯ,
    ಸ್ಥಿರಾಂಕ BIGNUM *gen,
    ಸ್ಥಿರಾಂಕ BIGNUM *client_dh_pub,
    ಸ್ಥಿರಾಂಕ BIGNUM *server_dh_pub,
    ಸ್ಥಿರಾಂಕ u_char *shared_secret, ಗಾತ್ರ_t secretlen,
    u_char *hash, ಗಾತ್ರ_t *hashlen)
{
	ರಚನೆ sshbuf *b;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (*hashlen < ssh_digest_ಬೈಟುಗಳು(SSH_DIGEST_SHA1))
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	ಆದರೆ ((b = sshbuf_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ ((r = sshbuf_put_stringb(b, client_ಆವೃತ್ತಿ)) < 0 ||
	    (r = sshbuf_put_stringb(b, server_ಆವೃತ್ತಿ)) < 0 ||
	    /* kexinit messages: fake header: len+SSH2_MSG_KEXINIT */
	    (r = sshbuf_put_u32(b, sshbuf_len(client_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_ಸಂದೇಶ_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, client_kexinit)) != 0 ||
	    (r = sshbuf_put_u32(b, sshbuf_len(server_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_ಸಂದೇಶ_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, server_kexinit)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_host_ಕೀಲಿ_blob)) != 0 ||
	    (min != -1 && (r = sshbuf_put_u32(b, min)) != 0) ||
	    (r = sshbuf_put_u32(b, wantbits)) != 0 ||
	    (max != -1 && (r = sshbuf_put_u32(b, max)) != 0) ||
	    (r = sshbuf_put_bignum2(b, ಅವಿಭಾಜ್ಯ)) != 0 ||
	    (r = sshbuf_put_bignum2(b, gen)) != 0 ||
	    (r = sshbuf_put_bignum2(b, client_dh_pub)) != 0 ||
	    (r = sshbuf_put_bignum2(b, server_dh_pub)) != 0 ||
	    (r = sshbuf_put(b, shared_secret, secretlen)) != 0) {
		sshbuf_free(b);
		ಹಿಂತಿರುಗಿ r;
	}
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_KEXDH
	sshbuf_dump(b, stderr);
#ಆದರೆ_ಅಂತ್ಯ
	ಆದರೆ (ssh_digest_ಬಫರ್(hash_alg, b, hash, *hashlen) != 0) {
		sshbuf_free(b);
		ಹಿಂತಿರುಗಿ SSH_ERR_LIBCRYPTO_ERROR;
	}
	sshbuf_free(b);
	*hashlen = ssh_digest_ಬೈಟುಗಳು(hash_alg);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_KEXDH
	dump_digest("hash", hash, *hashlen);
#ಆದರೆ_ಅಂತ್ಯ
	ಹಿಂತಿರುಗಿ 0;
}
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
