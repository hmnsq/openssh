/* $OpenBSD: kexmlkem768ecdh.c,v 1.4 2026/08/03 06:43:16 djm Exp $ */
/*
 * Copyright (c) 2025 Markus Friedl.  All rights reserved.
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

#ifdef WITH_OPENSSL
પૂર્ણાંક
kex_kem_mlkem768ecdh_keypair(સંરચના kex *kex)
{
	સંરચના sshbuf *buf = ખાલી;
	સંરચના sshbuf *ec_blob = ખાલી;
	EC_ચાવી *client_ચાવી = ખાલી;
	અચલ EC_GROUP *group;
	અચલ EC_POINT *public_ચાવી;
	u_char *cp = ખાલી;
	size_t need;
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;

	જો ((buf = sshbuf_new()) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	need = MLKEM768_PUBLICKEYBYTES;
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
	જો ((client_ચાવી = EC_ચાવી_new_by_curve_name(kex->ec_nid)) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો (EC_ચાવી_generate_ચાવી(client_ચાવી) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		જાઓ out;
	}
	group = EC_ચાવી_get0_group(client_ચાવી);
	public_ચાવી = EC_ચાવી_get0_public_ચાવી(client_ચાવી);

	જો ((ec_blob = sshbuf_new()) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો ((r = sshbuf_put_ec(ec_blob, public_ચાવી, group)) != 0 ||
	    (r = sshbuf_get_u32(ec_blob, ખાલી)) != 0 ||
	    (r = sshbuf_putb(buf, ec_blob)) != 0)
		જાઓ out;
#ifdef DEBUG_KEXECDH
	fputs("client private key EC:\n", stderr);
	sshkey_dump_ec_ચાવી(client_ચાવી);
#endif
	/* success */
	r = 0;
	kex->ec_client_ચાવી = client_ચાવી;
	kex->ec_group = group;
	client_ચાવી = ખાલી;	/* owned by the kex */
	kex->client_pub = buf;
	buf = ખાલી;
 out:
	sshbuf_free(buf);
	sshbuf_free(ec_blob);
	EC_ચાવી_free(client_ચાવી);
	પાછા r;
}

પૂર્ણાંક
kex_kem_mlkem768ecdh_enc(સંરચના kex *kex,
   અચલ સંરચના sshbuf *client_blob, સંરચના sshbuf **server_blobp,
   સંરચના sshbuf **shared_secretp)
{
	અચલ EC_GROUP *group;
	અચલ EC_POINT *pub_ચાવી;
	EC_ચાવી *server_ચાવી = ખાલી;
	સંરચના sshbuf *ec_pub = ખાલી;
	સંરચના sshbuf *ec_blob = ખાલી;
	સંરચના sshbuf *ec_shared = ખાલી;
	સંરચના sshbuf *server_blob = ખાલી;
	સંરચના sshbuf *buf = ખાલી;
	અચલ u_char *client_pub;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	u_char ct[MLKEM768_CIPHERTEXTBYTES];
	u_char shared_secret[MLKEM768_BYTES];
	size_t need;
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;

	*server_blobp = ખાલી;
	*shared_secretp = ખાલી;

	/* client_blob contains both KEM and ECDH client pubkeys */
	need = MLKEM768_PUBLICKEYBYTES;
	જો (sshbuf_len(client_blob) <= need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		જાઓ out;
	}
	client_pub = sshbuf_ptr(client_blob);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", client_pub,
	    MLKEM768_PUBLICKEYBYTES);
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
	જો ((r = sshbuf_put(buf, shared_secret, કદ(shared_secret))) != 0 ||
	    (r = sshbuf_put(server_blob, ct, કદ(ct))) != 0)
		જાઓ out;

	client_pub += MLKEM768_PUBLICKEYBYTES;
	જો ((ec_pub = sshbuf_from(client_pub, sshbuf_len(client_blob) -
	    MLKEM768_PUBLICKEYBYTES)) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	/* generate ECDH key pair */
	જો ((server_ચાવી = EC_ચાવી_new_by_curve_name(kex->ec_nid)) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો (EC_ચાવી_generate_ચાવી(server_ચાવી) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		જાઓ out;
	}
	group = EC_ચાવી_get0_group(server_ચાવી);
#ifdef DEBUG_KEXECDH
	fputs("server private key EC:\n", stderr);
	sshkey_dump_ec_ચાવી(server_ચાવી);
#endif
	/* store server pubkey after ciphertext */
	pub_ચાવી = EC_ચાવી_get0_public_ચાવી(server_ચાવી);
	જો ((ec_blob = sshbuf_new()) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો ((r = sshbuf_put_ec(ec_blob, pub_ચાવી, group)) != 0 ||
	    (r = sshbuf_get_u32(ec_blob, ખાલી)) != 0 ||
	    (r = sshbuf_putb(server_blob, ec_blob)) != 0)
		જાઓ out;

	/* append ECDH shared key */
	જો ((r = kex_ecdh_dec_ચાવી_group(kex, ec_pub, server_ચાવી, group,
	    1, &ec_shared)) != 0 ||
	    (r = sshbuf_putb(buf, ec_shared)) != 0)
		જાઓ out;

	જો ((r = ssh_digest_buffer(kex->hash_alg, buf, hash, કદ(hash))) != 0)
		જાઓ out;
#ifdef DEBUG_KEXECDH
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
	explicit_bzero(shared_secret, કદ(shared_secret));
	EC_ચાવી_free(server_ચાવી);
	sshbuf_free(ec_pub);
	sshbuf_free(ec_blob);
	sshbuf_free(ec_shared);
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	પાછા r;
}

પૂર્ણાંક
kex_kem_mlkem768ecdh_dec(સંરચના kex *kex,
    અચલ સંરચના sshbuf *server_blob, સંરચના sshbuf **shared_secretp)
{
	સંરચના sshbuf *buf = ખાલી;
	સંરચના sshbuf *ec_pub = ખાલી;
	સંરચના sshbuf *ec_shared = ખાલી;
	u_char shared_secret[MLKEM768_BYTES];
	અચલ u_char *ciphertext, *server_pub;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t need;
	પૂર્ણાંક r;

	*shared_secretp = ખાલી;

	need = MLKEM768_CIPHERTEXTBYTES;
	જો (sshbuf_len(server_blob) <= need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		જાઓ out;
	}
	ciphertext = sshbuf_ptr(server_blob);
	server_pub = ciphertext + MLKEM768_CIPHERTEXTBYTES;
#ifdef DEBUG_KEXECDH
	dump_digest("server cipher text (dec):", ciphertext,
	    MLKEM768_CIPHERTEXTBYTES);
#endif
	/* hash concatenation of KEM key and ECDH shared key */
	જો ((buf = sshbuf_new()) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો (crypto_kem_mlkem768_dec(shared_secret, ciphertext,
	    kex->mlkem768_client_ચાવી) != 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		જાઓ out;
	}
	જો ((r = sshbuf_put(buf, shared_secret, કદ(shared_secret))) != 0)
		જાઓ out;
	જો ((ec_pub = sshbuf_from(server_pub, sshbuf_len(server_blob) - need))
	    == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો ((r = kex_ecdh_dec_ચાવી_group(kex, ec_pub, kex->ec_client_ચાવી,
	    kex->ec_group, 1, &ec_shared)) != 0 ||
	    (r = sshbuf_putb(buf, ec_shared)) != 0)
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
	EC_ચાવી_free(kex->ec_client_ચાવી);
	kex->ec_client_ચાવી = ખાલી;
	sshbuf_free(ec_pub);
	sshbuf_free(ec_shared);
	sshbuf_free(buf);
	પાછા r;
}
#endif	/* WITH_OPENSSL */
