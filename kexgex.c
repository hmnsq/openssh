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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/evp.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "openbsd-compat/openssl-compat.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "cipher.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "kex.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh2.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "digest.h"

ਪੂਰਨ
kexgex_hash(
    ਪੂਰਨ hash_alg,
    ਅਚਲ ਬਣਤਰ sshbuf *client_ਸੰਸਕਰਣ,
    ਅਚਲ ਬਣਤਰ sshbuf *server_ਸੰਸਕਰਣ,
    ਅਚਲ ਬਣਤਰ sshbuf *client_kexinit,
    ਅਚਲ ਬਣਤਰ sshbuf *server_kexinit,
    ਅਚਲ ਬਣਤਰ sshbuf *server_host_ਕੁੰਜੀ_blob,
    ਪੂਰਨ min, ਪੂਰਨ wantbits, ਪੂਰਨ max,
    ਅਚਲ BIGNUM *ਅਭਾਜ,
    ਅਚਲ BIGNUM *gen,
    ਅਚਲ BIGNUM *client_dh_pub,
    ਅਚਲ BIGNUM *server_dh_pub,
    ਅਚਲ u_char *shared_secret, ਮਾਪ_t secretlen,
    u_char *hash, ਮਾਪ_t *hashlen)
{
	ਬਣਤਰ sshbuf *b;
	ਪੂਰਨ r;

	ਜੇ (*hashlen < ssh_digest_ਬਾਈਟਾਂ(SSH_DIGEST_SHA1))
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	ਜੇ ((b = sshbuf_new()) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ ((r = sshbuf_put_stringb(b, client_ਸੰਸਕਰਣ)) < 0 ||
	    (r = sshbuf_put_stringb(b, server_ਸੰਸਕਰਣ)) < 0 ||
	    /* kexinit messages: fake header: len+SSH2_MSG_KEXINIT */
	    (r = sshbuf_put_u32(b, sshbuf_len(client_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_ਸੁਨੇਹਾ_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, client_kexinit)) != 0 ||
	    (r = sshbuf_put_u32(b, sshbuf_len(server_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_ਸੁਨੇਹਾ_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, server_kexinit)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_host_ਕੁੰਜੀ_blob)) != 0 ||
	    (min != -1 && (r = sshbuf_put_u32(b, min)) != 0) ||
	    (r = sshbuf_put_u32(b, wantbits)) != 0 ||
	    (max != -1 && (r = sshbuf_put_u32(b, max)) != 0) ||
	    (r = sshbuf_put_bignum2(b, ਅਭਾਜ)) != 0 ||
	    (r = sshbuf_put_bignum2(b, gen)) != 0 ||
	    (r = sshbuf_put_bignum2(b, client_dh_pub)) != 0 ||
	    (r = sshbuf_put_bignum2(b, server_dh_pub)) != 0 ||
	    (r = sshbuf_put(b, shared_secret, secretlen)) != 0) {
		sshbuf_free(b);
		ਵਾਪਸ r;
	}
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_KEXDH
	sshbuf_dump(b, stderr);
#ਜੇ_ਅੰਤ
	ਜੇ (ssh_digest_ਬਫਰ(hash_alg, b, hash, *hashlen) != 0) {
		sshbuf_free(b);
		ਵਾਪਸ SSH_ERR_LIBCRYPTO_ERROR;
	}
	sshbuf_free(b);
	*hashlen = ssh_digest_ਬਾਈਟਾਂ(hash_alg);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_KEXDH
	dump_digest("hash", hash, *hashlen);
#ਜੇ_ਅੰਤ
	ਵਾਪਸ 0;
}
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
