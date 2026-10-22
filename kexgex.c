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

#அந்தர்பாவ "includes.h"

#ifdef WITH_OPENSSL

#அந்தர்பாவ <sys/types.h>

#அந்தர்பாவ <openssl/evp.h>
#அந்தர்பாவ <signal.h>

#அந்தர்பாவ "openbsd-compat/openssl-compat.h"

#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "cipher.h"
#அந்தர்பாவ "kex.h"
#அந்தர்பாவ "ssh2.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "digest.h"

முழு
kexgex_hash(
    முழு hash_alg,
    மாறிலி கட்டமைப்பு sshbuf *client_version,
    மாறிலி கட்டமைப்பு sshbuf *server_version,
    மாறிலி கட்டமைப்பு sshbuf *client_kexinit,
    மாறிலி கட்டமைப்பு sshbuf *server_kexinit,
    மாறிலி கட்டமைப்பு sshbuf *server_host_சாவி_blob,
    முழு min, முழு wantbits, முழு max,
    மாறிலி BIGNUM *பகாஎண்,
    மாறிலி BIGNUM *gen,
    மாறிலி BIGNUM *client_dh_pub,
    மாறிலி BIGNUM *server_dh_pub,
    மாறிலி u_char *shared_secret, size_t secretlen,
    u_char *hash, size_t *hashlen)
{
	கட்டமைப்பு sshbuf *b;
	முழு r;

	எனில் (*hashlen < ssh_digest_bytes(SSH_DIGEST_SHA1))
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	எனில் ((b = sshbuf_new()) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் ((r = sshbuf_put_stringb(b, client_version)) < 0 ||
	    (r = sshbuf_put_stringb(b, server_version)) < 0 ||
	    /* kexinit messages: fake header: len+SSH2_MSG_KEXINIT */
	    (r = sshbuf_put_u32(b, sshbuf_len(client_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_செய்தி_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, client_kexinit)) != 0 ||
	    (r = sshbuf_put_u32(b, sshbuf_len(server_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_செய்தி_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, server_kexinit)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_host_சாவி_blob)) != 0 ||
	    (min != -1 && (r = sshbuf_put_u32(b, min)) != 0) ||
	    (r = sshbuf_put_u32(b, wantbits)) != 0 ||
	    (max != -1 && (r = sshbuf_put_u32(b, max)) != 0) ||
	    (r = sshbuf_put_bignum2(b, பகாஎண்)) != 0 ||
	    (r = sshbuf_put_bignum2(b, gen)) != 0 ||
	    (r = sshbuf_put_bignum2(b, client_dh_pub)) != 0 ||
	    (r = sshbuf_put_bignum2(b, server_dh_pub)) != 0 ||
	    (r = sshbuf_put(b, shared_secret, secretlen)) != 0) {
		sshbuf_free(b);
		திரும்பு r;
	}
#ifdef DEBUG_KEXDH
	sshbuf_dump(b, stderr);
#endif
	எனில் (ssh_digest_buffer(hash_alg, b, hash, *hashlen) != 0) {
		sshbuf_free(b);
		திரும்பு SSH_ERR_LIBCRYPTO_ERROR;
	}
	sshbuf_free(b);
	*hashlen = ssh_digest_bytes(hash_alg);
#ifdef DEBUG_KEXDH
	dump_digest("hash", hash, *hashlen);
#endif
	திரும்பு 0;
}
#endif /* WITH_OPENSSL */
