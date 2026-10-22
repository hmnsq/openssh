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

#اگر_تعریف_شدہ WITH_OPENSSL

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
    ثابت ساخت sshbuf *client_نسخہ,
    ثابت ساخت sshbuf *server_نسخہ,
    ثابت ساخت sshbuf *client_kexinit,
    ثابت ساخت sshbuf *server_kexinit,
    ثابت ساخت sshbuf *server_host_کلید_blob,
    صحیح min, صحیح wantbits, صحیح max,
    ثابت BIGNUM *مفرد,
    ثابت BIGNUM *gen,
    ثابت BIGNUM *client_dh_pub,
    ثابت BIGNUM *server_dh_pub,
    ثابت u_char *shared_secret, سائز_t secretlen,
    u_char *hash, سائز_t *hashlen)
{
	ساخت sshbuf *b;
	صحیح r;

	اگر (*hashlen < ssh_digest_بائٹیں(SSH_DIGEST_SHA1))
		واپس SSH_ERR_INVALID_دلیل;
	اگر ((b = sshbuf_new()) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshbuf_put_stringb(b, client_نسخہ)) < 0 ||
	    (r = sshbuf_put_stringb(b, server_نسخہ)) < 0 ||
	    /* kexinit messages: fake header: len+SSH2_MSG_KEXINIT */
	    (r = sshbuf_put_u32(b, sshbuf_len(client_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_پیغام_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, client_kexinit)) != 0 ||
	    (r = sshbuf_put_u32(b, sshbuf_len(server_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_پیغام_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, server_kexinit)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_host_کلید_blob)) != 0 ||
	    (min != -1 && (r = sshbuf_put_u32(b, min)) != 0) ||
	    (r = sshbuf_put_u32(b, wantbits)) != 0 ||
	    (max != -1 && (r = sshbuf_put_u32(b, max)) != 0) ||
	    (r = sshbuf_put_bignum2(b, مفرد)) != 0 ||
	    (r = sshbuf_put_bignum2(b, gen)) != 0 ||
	    (r = sshbuf_put_bignum2(b, client_dh_pub)) != 0 ||
	    (r = sshbuf_put_bignum2(b, server_dh_pub)) != 0 ||
	    (r = sshbuf_put(b, shared_secret, secretlen)) != 0) {
		sshbuf_free(b);
		واپس r;
	}
#اگر_تعریف_شدہ DEBUG_KEXDH
	sshbuf_dump(b, stderr);
#اگر_ختم
	اگر (ssh_digest_بفر(hash_alg, b, hash, *hashlen) != 0) {
		sshbuf_free(b);
		واپس SSH_ERR_LIBCRYPTO_ERROR;
	}
	sshbuf_free(b);
	*hashlen = ssh_digest_بائٹیں(hash_alg);
#اگر_تعریف_شدہ DEBUG_KEXDH
	dump_digest("hash", hash, *hashlen);
#اگر_ختم
	واپس 0;
}
#اگر_ختم /* WITH_OPENSSL */
