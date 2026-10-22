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

#ضمن "includes.h"

#ifdef WITH_OPENSSL

#ضمن <sys/types.h>

#ضمن <openssl/evp.h>
#ضمن <signal.h>

#ضمن "openbsd-compat/openssl-compat.h"

#ضمن "sshkey.h"
#ضمن "cipher.h"
#ضمن "kex.h"
#ضمن "ssh2.h"
#ضمن "ssherr.h"
#ضمن "sshbuf.h"
#ضمن "digest.h"

صحيح
kexgex_hash(
    صحيح hash_alg,
    ثابت بنية sshbuf *client_version,
    ثابت بنية sshbuf *server_version,
    ثابت بنية sshbuf *client_kexinit,
    ثابت بنية sshbuf *server_kexinit,
    ثابت بنية sshbuf *server_host_key_blob,
    صحيح min, صحيح wantbits, صحيح max,
    ثابت BIGNUM *prime,
    ثابت BIGNUM *gen,
    ثابت BIGNUM *client_dh_pub,
    ثابت BIGNUM *server_dh_pub,
    ثابت u_char *shared_secret, size_t secretlen,
    u_char *hash, size_t *hashlen)
{
	بنية sshbuf *b;
	صحيح r;

	אם (*hashlen < ssh_digest_bytes(SSH_DIGEST_SHA1))
		החזר SSH_ERR_INVALID_ARGUMENT;
	אם ((b = sshbuf_new()) == عدم)
		החזר SSH_ERR_ALLOC_FAIL;
	אם ((r = sshbuf_put_stringb(b, client_version)) < 0 ||
	    (r = sshbuf_put_stringb(b, server_version)) < 0 ||
	    /* kexinit messages: fake header: len+SSH2_MSG_KEXINIT */
	    (r = sshbuf_put_u32(b, sshbuf_len(client_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_MSG_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, client_kexinit)) != 0 ||
	    (r = sshbuf_put_u32(b, sshbuf_len(server_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_MSG_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, server_kexinit)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_host_key_blob)) != 0 ||
	    (min != -1 && (r = sshbuf_put_u32(b, min)) != 0) ||
	    (r = sshbuf_put_u32(b, wantbits)) != 0 ||
	    (max != -1 && (r = sshbuf_put_u32(b, max)) != 0) ||
	    (r = sshbuf_put_bignum2(b, prime)) != 0 ||
	    (r = sshbuf_put_bignum2(b, gen)) != 0 ||
	    (r = sshbuf_put_bignum2(b, client_dh_pub)) != 0 ||
	    (r = sshbuf_put_bignum2(b, server_dh_pub)) != 0 ||
	    (r = sshbuf_put(b, shared_secret, secretlen)) != 0) {
		sshbuf_free(b);
		החזר r;
	}
#ifdef DEBUG_KEXDH
	sshbuf_dump(b, stderr);
#endif
	אם (ssh_digest_buffer(hash_alg, b, hash, *hashlen) != 0) {
		sshbuf_free(b);
		החזר SSH_ERR_LIBCRYPTO_ERROR;
	}
	sshbuf_free(b);
	*hashlen = ssh_digest_bytes(hash_alg);
#ifdef DEBUG_KEXDH
	dump_digest("hash", hash, *hashlen);
#endif
	החזר 0;
}
#endif /* WITH_OPENSSL */
