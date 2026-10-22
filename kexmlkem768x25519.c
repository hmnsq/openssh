/* $OpenBSD: kexmlkem768x25519.c,v 1.3 2026/06/14 03:59:34 djm Exp $ */
/*
 * Copyright (c) 2023 Markus Friedl.  All rights reserved.
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

#અન્તર્ભાવ <sys/types.h>

#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <stdbool.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <endian.h>

#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "kex.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "digest.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "log.h"

#અન્તર્ભાવ "crypto_api.h"

#ifdef USE_MLKEM768X25519

પૂર્ણાંક
kex_kem_mlkem768x25519_keypair(સંરચના kex *kex)
{
	સંરચના sshbuf *buf = ખાલી;
	u_char *cp = ખાલી;
	size_t need;
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;

	જો ((buf = sshbuf_new()) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	need = MLKEM768_PUBLICKEYBYTES + CURVE25519_SIZE;
	જો ((r = sshbuf_reserve(buf, need, &cp)) != 0)
		જાઓ out;
	જો (crypto_kem_mlkem768_keypair(cp, kex->mlkem768_client_ચાવી) != 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		જાઓ out;
	}
#ifdef DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", cp,
	    MLKEM768_PUBLICKEYBYTES);
#endif
	cp += MLKEM768_PUBLICKEYBYTES;
	kexc25519_keygen(kex->c25519_client_ચાવી, cp);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key c25519:", cp, CURVE25519_SIZE);
#endif
	/* success */
	r = 0;
	kex->client_pub = buf;
	buf = ખાલી;
 out:
	sshbuf_free(buf);
	પાછા r;
}

પૂર્ણાંક
kex_kem_mlkem768x25519_enc(સંરચના kex *kex,
   અચલ સંરચના sshbuf *client_blob, સંરચના sshbuf **server_blobp,
   સંરચના sshbuf **shared_secretp)
{
	સંરચના sshbuf *server_blob = ખાલી;
	સંરચના sshbuf *buf = ખાલી;
	અચલ u_char *client_pub;
	u_char server_pub[CURVE25519_SIZE], server_ચાવી[CURVE25519_SIZE];
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	u_char ct[MLKEM768_CIPHERTEXTBYTES];
	u_char shared_secret[MLKEM768_BYTES];
	size_t need;
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;

	*server_blobp = ખાલી;
	*shared_secretp = ખાલી;

	/* client_blob contains both KEM and ECDH client pubkeys */
	need = MLKEM768_PUBLICKEYBYTES + CURVE25519_SIZE;
	જો (sshbuf_len(client_blob) != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		જાઓ out;
	}
	client_pub = sshbuf_ptr(client_blob);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", client_pub,
	    MLKEM768_PUBLICKEYBYTES);
	dump_digest("client public key 25519:",
	    client_pub + MLKEM768_PUBLICKEYBYTES,
	    CURVE25519_SIZE);
#endif

	/* allocate buffer for concatenation of KEM key and ECDH shared key */
	/* the buffer will be hashed and the result is the shared secret */
	જો ((buf = sshbuf_new()) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	/* allocate space for encrypted KEM key and ECDH pub key */
	જો ((server_blob = sshbuf_new()) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	/* generate and encrypt KEM key with client key */
	જો (crypto_kem_mlkem768_enc(ct, shared_secret, client_pub) != 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		જાઓ out;
	}
	/* generate ECDH key pair, store server pubkey after ciphertext */
	kexc25519_keygen(server_ચાવી, server_pub);
	જો ((r = sshbuf_put(buf, shared_secret, કદ(shared_secret))) != 0 ||
	    (r = sshbuf_put(server_blob, ct, કદ(ct))) != 0 ||
	    (r = sshbuf_put(server_blob, server_pub, કદ(server_pub))) != 0)
		જાઓ out;
	/* append ECDH shared key */
	client_pub += MLKEM768_PUBLICKEYBYTES;
	જો ((r = kexc25519_shared_ચાવી_ext(server_ચાવી, client_pub, buf, 1)) < 0)
		જાઓ out;
	જો ((r = ssh_digest_buffer(kex->hash_alg, buf,
	    hash, કદ(hash))) != 0)
		જાઓ out;
#ifdef DEBUG_KEXECDH
	dump_digest("server public key 25519:", server_pub, CURVE25519_SIZE);
	dump_digest("server cipher text:", ct, કદ(ct));
	dump_digest("server kem key:", shared_secret, કદ(shared_secret));
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	/* string-encoded hash is resulting shared secret */
	sshbuf_reset(buf);
	જો ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_bytes(kex->hash_alg))) != 0)
		જાઓ out;
#ifdef DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	/* success */
	r = 0;
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = ખાલી;
	buf = ખાલી;
 out:
	explicit_bzero(hash, કદ(hash));
	explicit_bzero(server_ચાવી, કદ(server_ચાવી));
	explicit_bzero(shared_secret, કદ(shared_secret));
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	પાછા r;
}

પૂર્ણાંક
kex_kem_mlkem768x25519_dec(સંરચના kex *kex,
    અચલ સંરચના sshbuf *server_blob, સંરચના sshbuf **shared_secretp)
{
	સંરચના sshbuf *buf = ખાલી;
	u_char shared_secret[MLKEM768_BYTES];
	અચલ u_char *ciphertext, *server_pub;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t need;
	પૂર્ણાંક r;

	*shared_secretp = ખાલી;

	need = MLKEM768_CIPHERTEXTBYTES + CURVE25519_SIZE;
	જો (sshbuf_len(server_blob) != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		જાઓ out;
	}
	ciphertext = sshbuf_ptr(server_blob);
	server_pub = ciphertext + MLKEM768_CIPHERTEXTBYTES;
	/* hash concatenation of KEM key and ECDH shared key */
	જો ((buf = sshbuf_new()) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
#ifdef DEBUG_KEXECDH
	dump_digest("server cipher text:", ciphertext,
	    MLKEM768_CIPHERTEXTBYTES);
	dump_digest("server public key c25519:", server_pub, CURVE25519_SIZE);
#endif
	જો (crypto_kem_mlkem768_dec(shared_secret, ciphertext,
	    kex->mlkem768_client_ચાવી) != 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		જાઓ out;
	}
	જો ((r = sshbuf_put(buf, shared_secret, કદ(shared_secret))) != 0)
		જાઓ out;
	જો ((r = kexc25519_shared_ચાવી_ext(kex->c25519_client_ચાવી, server_pub,
	    buf, 1)) < 0)
		જાઓ out;
	જો ((r = ssh_digest_buffer(kex->hash_alg, buf,
	    hash, કદ(hash))) != 0)
		જાઓ out;
#ifdef DEBUG_KEXECDH
	dump_digest("client kem key:", shared_secret, કદ(shared_secret));
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	sshbuf_reset(buf);
	જો ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_bytes(kex->hash_alg))) != 0)
		જાઓ out;
#ifdef DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	/* success */
	r = 0;
	*shared_secretp = buf;
	buf = ખાલી;
 out:
	explicit_bzero(hash, કદ(hash));
	explicit_bzero(shared_secret, કદ(shared_secret));
	sshbuf_free(buf);
	પાછા r;
}
#નહીંતર /* USE_MLKEM768X25519 */
પૂર્ણાંક
kex_kem_mlkem768x25519_keypair(સંરચના kex *kex)
{
	પાછા SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

પૂર્ણાંક
kex_kem_mlkem768x25519_enc(સંરચના kex *kex,
   અચલ સંરચના sshbuf *client_blob, સંરચના sshbuf **server_blobp,
   સંરચના sshbuf **shared_secretp)
{
	પાછા SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

પૂર્ણાંક
kex_kem_mlkem768x25519_dec(સંરચના kex *kex,
    અચલ સંરચના sshbuf *server_blob, સંરચના sshbuf **shared_secretp)
{
	પાછા SSH_ERR_SIGN_ALG_UNSUPPORTED;
}
#endif /* USE_MLKEM768X25519 */
