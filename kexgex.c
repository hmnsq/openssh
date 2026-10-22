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

#شامل "includes.h"

#ifdef WITH_OPENSSL

#شامل <sys/types.h>

#شامل <openssl/evp.h>
#شامل <signal.h>

#شامل "openbsd-compat/openssl-compat.h"

#شامل "sshkey.h"
#شامل "cipher.h"
#شامل "kex.h"
#شامل "ssh2.h"
#شامل "ssherr.h"
#شامل "sshbuf.h"
#شامل "digest.h"

صحیح
kexgex_hash(
    صحیح hash_alg,
    ثابت ساختار sshbuf *client_version,
    ثابت ساختار sshbuf *server_version,
    ثابت ساختار sshbuf *client_kexinit,
    ثابت ساختار sshbuf *server_kexinit,
    ثابت ساختار sshbuf *server_host_کلید_blob,
    صحیح min, صحیح wantbits, صحیح max,
    ثابت BIGNUM *اول,
    ثابت BIGNUM *gen,
    ثابت BIGNUM *client_dh_pub,
    ثابت BIGNUM *server_dh_pub,
    ثابت u_char *shared_secret, size_t secretlen,
    u_char *hash, size_t *hashlen)
{
	ساختار sshbuf *b;
	صحیح r;

	اگر (*hashlen < ssh_digest_bytes(SSH_DIGEST_SHA1))
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	اگر ((b = sshbuf_new()) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshbuf_put_stringb(b, client_version)) < 0 ||
	    (r = sshbuf_put_stringb(b, server_version)) < 0 ||
	    /* kexinit messages: fake header: len+SSH2_MSG_KEXINIT */
	    (r = sshbuf_put_u32(b, sshbuf_len(client_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_پیام_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, client_kexinit)) != 0 ||
	    (r = sshbuf_put_u32(b, sshbuf_len(server_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_پیام_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, server_kexinit)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_host_کلید_blob)) != 0 ||
	    (min != -1 && (r = sshbuf_put_u32(b, min)) != 0) ||
	    (r = sshbuf_put_u32(b, wantbits)) != 0 ||
	    (max != -1 && (r = sshbuf_put_u32(b, max)) != 0) ||
	    (r = sshbuf_put_bignum2(b, اول)) != 0 ||
	    (r = sshbuf_put_bignum2(b, gen)) != 0 ||
	    (r = sshbuf_put_bignum2(b, client_dh_pub)) != 0 ||
	    (r = sshbuf_put_bignum2(b, server_dh_pub)) != 0 ||
	    (r = sshbuf_put(b, shared_secret, secretlen)) != 0) {
		sshbuf_free(b);
		بازگشت r;
	}
#ifdef DEBUG_KEXDH
	sshbuf_dump(b, stderr);
#endif
	اگر (ssh_digest_buffer(hash_alg, b, hash, *hashlen) != 0) {
		sshbuf_free(b);
		بازگشت SSH_ERR_LIBCRYPTO_ERROR;
	}
	sshbuf_free(b);
	*hashlen = ssh_digest_bytes(hash_alg);
#ifdef DEBUG_KEXDH
	dump_digest("hash", hash, *hashlen);
#endif
	بازگشت 0;
}
#endif /* WITH_OPENSSL */
