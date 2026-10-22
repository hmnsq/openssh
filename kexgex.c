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

#અન્તર્ભાવ "includes.h"

#ifdef WITH_OPENSSL

#અન્તર્ભાવ <sys/types.h>

#અન્તર્ભાવ <openssl/evp.h>
#અન્તર્ભાવ <signal.h>

#અન્તર્ભાવ "openbsd-compat/openssl-compat.h"

#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "cipher.h"
#અન્તર્ભાવ "kex.h"
#અન્તર્ભાવ "ssh2.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "digest.h"

પૂર્ણાંક
kexgex_hash(
    પૂર્ણાંક hash_alg,
    અચલ સંરચના sshbuf *client_version,
    અચલ સંરચના sshbuf *server_version,
    અચલ સંરચના sshbuf *client_kexinit,
    અચલ સંરચના sshbuf *server_kexinit,
    અચલ સંરચના sshbuf *server_host_ચાવી_blob,
    પૂર્ણાંક min, પૂર્ણાંક wantbits, પૂર્ણાંક max,
    અચલ BIGNUM *અવિભાજ્ય,
    અચલ BIGNUM *gen,
    અચલ BIGNUM *client_dh_pub,
    અચલ BIGNUM *server_dh_pub,
    અચલ u_char *shared_secret, size_t secretlen,
    u_char *hash, size_t *hashlen)
{
	સંરચના sshbuf *b;
	પૂર્ણાંક r;

	જો (*hashlen < ssh_digest_bytes(SSH_DIGEST_SHA1))
		પાછા SSH_ERR_INVALID_ARGUMENT;
	જો ((b = sshbuf_new()) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો ((r = sshbuf_put_stringb(b, client_version)) < 0 ||
	    (r = sshbuf_put_stringb(b, server_version)) < 0 ||
	    /* kexinit messages: fake header: len+SSH2_MSG_KEXINIT */
	    (r = sshbuf_put_u32(b, sshbuf_len(client_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_સંદેશ_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, client_kexinit)) != 0 ||
	    (r = sshbuf_put_u32(b, sshbuf_len(server_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_સંદેશ_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, server_kexinit)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_host_ચાવી_blob)) != 0 ||
	    (min != -1 && (r = sshbuf_put_u32(b, min)) != 0) ||
	    (r = sshbuf_put_u32(b, wantbits)) != 0 ||
	    (max != -1 && (r = sshbuf_put_u32(b, max)) != 0) ||
	    (r = sshbuf_put_bignum2(b, અવિભાજ્ય)) != 0 ||
	    (r = sshbuf_put_bignum2(b, gen)) != 0 ||
	    (r = sshbuf_put_bignum2(b, client_dh_pub)) != 0 ||
	    (r = sshbuf_put_bignum2(b, server_dh_pub)) != 0 ||
	    (r = sshbuf_put(b, shared_secret, secretlen)) != 0) {
		sshbuf_free(b);
		પાછા r;
	}
#ifdef DEBUG_KEXDH
	sshbuf_dump(b, stderr);
#endif
	જો (ssh_digest_buffer(hash_alg, b, hash, *hashlen) != 0) {
		sshbuf_free(b);
		પાછા SSH_ERR_LIBCRYPTO_ERROR;
	}
	sshbuf_free(b);
	*hashlen = ssh_digest_bytes(hash_alg);
#ifdef DEBUG_KEXDH
	dump_digest("hash", hash, *hashlen);
#endif
	પાછા 0;
}
#endif /* WITH_OPENSSL */
