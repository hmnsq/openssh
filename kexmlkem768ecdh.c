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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdbool.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <endian.h>

#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "kex.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "digest.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
ಪೂರ್ಣಾಂಕ
kex_kem_mlkem768ecdh_keypair(ರಚನೆ kex *kex)
{
	ರಚನೆ sshbuf *buf = ಖಾಲಿ;
	ರಚನೆ sshbuf *ec_blob = ಖಾಲಿ;
	EC_ಕೀಲಿ *client_ಕೀಲಿ = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ EC_ಗುಂಪು *ಗುಂಪು;
	ಸ್ಥಿರಾಂಕ EC_ಬಿಂದು *ಬಹಿರಂಗ_ಕೀಲಿ;
	u_char *cp = ಖಾಲಿ;
	ಗಾತ್ರ_t need;
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;

	ಆದರೆ ((buf = sshbuf_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	need = MLKEM768_PUBLICKEYBYTES;
	ಆದರೆ ((r = sshbuf_reserve(buf, need, &cp)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ (crypto_kem_mlkem768_keypair(cp, kex->mlkem768_client_ಕೀಲಿ) != 0) {
		r = SSH_ERR_ಆಂತರಿಕ_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", cp,
	    MLKEM768_PUBLICKEYBYTES);
#ಆದರೆ_ಅಂತ್ಯ
	ಆದರೆ ((client_ಕೀಲಿ = EC_ಕೀಲಿ_new_by_ವಕ್ರ_name(kex->ec_nid)) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (EC_ಕೀಲಿ_generate_ಕೀಲಿ(client_ಕೀಲಿ) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಗುಂಪು = EC_ಕೀಲಿ_get0_ಗುಂಪು(client_ಕೀಲಿ);
	ಬಹಿರಂಗ_ಕೀಲಿ = EC_ಕೀಲಿ_get0_ಬಹಿರಂಗ_ಕೀಲಿ(client_ಕೀಲಿ);

	ಆದರೆ ((ec_blob = sshbuf_new()) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshbuf_put_ec(ec_blob, ಬಹಿರಂಗ_ಕೀಲಿ, ಗುಂಪು)) != 0 ||
	    (r = sshbuf_get_u32(ec_blob, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_putb(buf, ec_blob)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_KEXECDH
	fputs("client private key EC:\n", stderr);
	sshkey_dump_ec_ಕೀಲಿ(client_ಕೀಲಿ);
#ಆದರೆ_ಅಂತ್ಯ
	/* success */
	r = 0;
	kex->ec_client_ಕೀಲಿ = client_ಕೀಲಿ;
	kex->ec_ಗುಂಪು = ಗುಂಪು;
	client_ಕೀಲಿ = ಖಾಲಿ;	/* owned by the kex */
	kex->client_pub = buf;
	buf = ಖಾಲಿ;
 ಹೊರಹೋಗು:
	sshbuf_free(buf);
	sshbuf_free(ec_blob);
	EC_ಕೀಲಿ_free(client_ಕೀಲಿ);
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
kex_kem_mlkem768ecdh_enc(ರಚನೆ kex *kex,
   ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *client_blob, ರಚನೆ sshbuf **server_blobp,
   ರಚನೆ sshbuf **shared_secretp)
{
	ಸ್ಥಿರಾಂಕ EC_ಗುಂಪು *ಗುಂಪು;
	ಸ್ಥಿರಾಂಕ EC_ಬಿಂದು *pub_ಕೀಲಿ;
	EC_ಕೀಲಿ *server_ಕೀಲಿ = ಖಾಲಿ;
	ರಚನೆ sshbuf *ec_pub = ಖಾಲಿ;
	ರಚನೆ sshbuf *ec_blob = ಖಾಲಿ;
	ರಚನೆ sshbuf *ec_shared = ಖಾಲಿ;
	ರಚನೆ sshbuf *server_blob = ಖಾಲಿ;
	ರಚನೆ sshbuf *buf = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ u_char *client_pub;
	u_char hash[SSH_DIGEST_MAX_ಉದ್ದಳತೆ];
	u_char ct[MLKEM768_CIPHERTEXTBYTES];
	u_char shared_secret[MLKEM768_ಬೈಟುಗಳು];
	ಗಾತ್ರ_t need;
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;

	*server_blobp = ಖಾಲಿ;
	*shared_secretp = ಖಾಲಿ;

	/* client_blob contains both KEM and ECDH client pubkeys */
	need = MLKEM768_PUBLICKEYBYTES;
	ಆದರೆ (sshbuf_len(client_blob) <= need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	client_pub = sshbuf_ptr(client_blob);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", client_pub,
	    MLKEM768_PUBLICKEYBYTES);
#ಆದರೆ_ಅಂತ್ಯ

	/* allocate buffer for concatenation of KEM key and ECDH shared key */
	/* the buffer will be hashed and the result is the shared secret */
	ಆದರೆ ((buf = sshbuf_new()) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* allocate space for encrypted KEM key and ECDH pub key */
	ಆದರೆ ((server_blob = sshbuf_new()) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* generate and encrypt KEM key with client key */
	ಆದರೆ (crypto_kem_mlkem768_enc(ct, shared_secret, client_pub) != 0) {
		r = SSH_ERR_ಆಂತರಿಕ_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshbuf_put(buf, shared_secret, ಗಾತ್ರ(shared_secret))) != 0 ||
	    (r = sshbuf_put(server_blob, ct, ಗಾತ್ರ(ct))) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	client_pub += MLKEM768_PUBLICKEYBYTES;
	ಆದರೆ ((ec_pub = sshbuf_from(client_pub, sshbuf_len(client_blob) -
	    MLKEM768_PUBLICKEYBYTES)) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* generate ECDH key pair */
	ಆದರೆ ((server_ಕೀಲಿ = EC_ಕೀಲಿ_new_by_ವಕ್ರ_name(kex->ec_nid)) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (EC_ಕೀಲಿ_generate_ಕೀಲಿ(server_ಕೀಲಿ) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಗುಂಪು = EC_ಕೀಲಿ_get0_ಗುಂಪು(server_ಕೀಲಿ);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_KEXECDH
	fputs("server private key EC:\n", stderr);
	sshkey_dump_ec_ಕೀಲಿ(server_ಕೀಲಿ);
#ಆದರೆ_ಅಂತ್ಯ
	/* store server pubkey after ciphertext */
	pub_ಕೀಲಿ = EC_ಕೀಲಿ_get0_ಬಹಿರಂಗ_ಕೀಲಿ(server_ಕೀಲಿ);
	ಆದರೆ ((ec_blob = sshbuf_new()) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshbuf_put_ec(ec_blob, pub_ಕೀಲಿ, ಗುಂಪು)) != 0 ||
	    (r = sshbuf_get_u32(ec_blob, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_putb(server_blob, ec_blob)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* append ECDH shared key */
	ಆದರೆ ((r = kex_ecdh_dec_ಕೀಲಿ_ಗುಂಪು(kex, ec_pub, server_ಕೀಲಿ, ಗುಂಪು,
	    1, &ec_shared)) != 0 ||
	    (r = sshbuf_putb(buf, ec_shared)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	ಆದರೆ ((r = ssh_digest_ಬಫರ್(kex->hash_alg, buf, hash, ಗಾತ್ರ(hash))) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_KEXECDH
	dump_digest("server cipher text:", ct, ಗಾತ್ರ(ct));
	dump_digest("server kem key:", shared_secret, ಗಾತ್ರ(shared_secret));
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#ಆದರೆ_ಅಂತ್ಯ
	/* string-encoded hash is resulting shared secret */
	sshbuf_reset(buf);
	ಆದರೆ ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_ಬೈಟುಗಳು(kex->hash_alg))) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#ಆದರೆ_ಅಂತ್ಯ
	/* success */
	r = 0;
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = ಖಾಲಿ;
	buf = ಖಾಲಿ;
 ಹೊರಹೋಗು:
	explicit_bzero(hash, ಗಾತ್ರ(hash));
	explicit_bzero(shared_secret, ಗಾತ್ರ(shared_secret));
	EC_ಕೀಲಿ_free(server_ಕೀಲಿ);
	sshbuf_free(ec_pub);
	sshbuf_free(ec_blob);
	sshbuf_free(ec_shared);
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
kex_kem_mlkem768ecdh_dec(ರಚನೆ kex *kex,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *server_blob, ರಚನೆ sshbuf **shared_secretp)
{
	ರಚನೆ sshbuf *buf = ಖಾಲಿ;
	ರಚನೆ sshbuf *ec_pub = ಖಾಲಿ;
	ರಚನೆ sshbuf *ec_shared = ಖಾಲಿ;
	u_char shared_secret[MLKEM768_ಬೈಟುಗಳು];
	ಸ್ಥಿರಾಂಕ u_char *ciphertext, *server_pub;
	u_char hash[SSH_DIGEST_MAX_ಉದ್ದಳತೆ];
	ಗಾತ್ರ_t need;
	ಪೂರ್ಣಾಂಕ r;

	*shared_secretp = ಖಾಲಿ;

	need = MLKEM768_CIPHERTEXTBYTES;
	ಆದರೆ (sshbuf_len(server_blob) <= need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ciphertext = sshbuf_ptr(server_blob);
	server_pub = ciphertext + MLKEM768_CIPHERTEXTBYTES;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_KEXECDH
	dump_digest("server cipher text (dec):", ciphertext,
	    MLKEM768_CIPHERTEXTBYTES);
#ಆದರೆ_ಅಂತ್ಯ
	/* hash concatenation of KEM key and ECDH shared key */
	ಆದರೆ ((buf = sshbuf_new()) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (crypto_kem_mlkem768_dec(shared_secret, ciphertext,
	    kex->mlkem768_client_ಕೀಲಿ) != 0) {
		r = SSH_ERR_ಆಂತರಿಕ_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshbuf_put(buf, shared_secret, ಗಾತ್ರ(shared_secret))) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ ((ec_pub = sshbuf_from(server_pub, sshbuf_len(server_blob) - need))
	    == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = kex_ecdh_dec_ಕೀಲಿ_ಗುಂಪು(kex, ec_pub, kex->ec_client_ಕೀಲಿ,
	    kex->ec_ಗುಂಪು, 1, &ec_shared)) != 0 ||
	    (r = sshbuf_putb(buf, ec_shared)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ ((r = ssh_digest_ಬಫರ್(kex->hash_alg, buf,
	    hash, ಗಾತ್ರ(hash))) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_KEXECDH
	dump_digest("client kem key:", shared_secret, ಗಾತ್ರ(shared_secret));
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#ಆದರೆ_ಅಂತ್ಯ
	sshbuf_reset(buf);
	ಆದರೆ ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_ಬೈಟುಗಳು(kex->hash_alg))) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#ಆದರೆ_ಅಂತ್ಯ
	/* success */
	r = 0;
	*shared_secretp = buf;
	buf = ಖಾಲಿ;
 ಹೊರಹೋಗು:
	explicit_bzero(hash, ಗಾತ್ರ(hash));
	explicit_bzero(shared_secret, ಗಾತ್ರ(shared_secret));
	EC_ಕೀಲಿ_free(kex->ec_client_ಕೀಲಿ);
	kex->ec_client_ಕೀಲಿ = ಖಾಲಿ;
	sshbuf_free(ec_pub);
	sshbuf_free(ec_shared);
	sshbuf_free(buf);
	ಹಿಂತಿರುಗಿ r;
}
#ಆದರೆ_ಅಂತ್ಯ	/* WITH_OPENSSL */
