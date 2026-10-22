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

#अन्तर्भाव "includes.h"

#ifdef WITH_OPENSSL

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <openssl/evp.h>
#अन्तर्भाव <signal.h>

#अन्तर्भाव "openbsd-compat/openssl-compat.h"

#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "cipher.h"
#अन्तर्भाव "kex.h"
#अन्तर्भाव "ssh2.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "digest.h"

पूर्णाङ्क
kexgex_hash(
    पूर्णाङ्क hash_alg,
    अचर संरचना sshbuf *client_version,
    अचर संरचना sshbuf *server_version,
    अचर संरचना sshbuf *client_kexinit,
    अचर संरचना sshbuf *server_kexinit,
    अचर संरचना sshbuf *server_host_साँचो_blob,
    पूर्णाङ्क min, पूर्णाङ्क wantbits, पूर्णाङ्क max,
    अचर BIGNUM *अविभाज्य,
    अचर BIGNUM *gen,
    अचर BIGNUM *client_dh_pub,
    अचर BIGNUM *server_dh_pub,
    अचर u_char *shared_secret, माप_प्रकार secretlen,
    u_char *hash, माप_प्रकार *hashlen)
{
	संरचना sshbuf *b;
	पूर्णाङ्क r;

	यदि (*hashlen < ssh_digest_bytes(SSH_DIGEST_SHA1))
		फर्काऊ SSH_ERR_INVALID_ARGUMENT;
	यदि ((b = sshbuf_new()) == रिक्त)
		फर्काऊ SSH_ERR_ALLOC_FAIL;
	यदि ((r = sshbuf_put_stringb(b, client_version)) < 0 ||
	    (r = sshbuf_put_stringb(b, server_version)) < 0 ||
	    /* kexinit messages: fake header: len+SSH2_MSG_KEXINIT */
	    (r = sshbuf_put_u32(b, sshbuf_len(client_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_सन्देश_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, client_kexinit)) != 0 ||
	    (r = sshbuf_put_u32(b, sshbuf_len(server_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_सन्देश_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, server_kexinit)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_host_साँचो_blob)) != 0 ||
	    (min != -1 && (r = sshbuf_put_u32(b, min)) != 0) ||
	    (r = sshbuf_put_u32(b, wantbits)) != 0 ||
	    (max != -1 && (r = sshbuf_put_u32(b, max)) != 0) ||
	    (r = sshbuf_put_bignum2(b, अविभाज्य)) != 0 ||
	    (r = sshbuf_put_bignum2(b, gen)) != 0 ||
	    (r = sshbuf_put_bignum2(b, client_dh_pub)) != 0 ||
	    (r = sshbuf_put_bignum2(b, server_dh_pub)) != 0 ||
	    (r = sshbuf_put(b, shared_secret, secretlen)) != 0) {
		sshbuf_free(b);
		फर्काऊ r;
	}
#ifdef DEBUG_KEXDH
	sshbuf_dump(b, मानक_त्रुटि);
#endif
	यदि (ssh_digest_buffer(hash_alg, b, hash, *hashlen) != 0) {
		sshbuf_free(b);
		फर्काऊ SSH_ERR_LIBCRYPTO_ERROR;
	}
	sshbuf_free(b);
	*hashlen = ssh_digest_bytes(hash_alg);
#ifdef DEBUG_KEXDH
	dump_digest("hash", hash, *hashlen);
#endif
	फर्काऊ 0;
}
#endif /* WITH_OPENSSL */
