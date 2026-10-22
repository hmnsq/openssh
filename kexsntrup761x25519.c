/* $OpenBSD: kexsntrup761x25519.c,v 1.3 2024/09/15 02:20:51 djm Exp $ */
/*
 * Copyright (c) 2019 Markus Friedl.  All rights reserved.
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

#ifdef USE_SNTRUP761X25519

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <signal.h>

#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "kex.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "digest.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"

ಚಞ್ಚಲ crypto_int16 crypto_int16_optblocker = 0;
ಚಞ್ಚಲ crypto_int32 crypto_int32_optblocker = 0;
ಚಞ್ಚಲ crypto_int64 crypto_int64_optblocker = 0;

ಪೂರ್ಣಾಙ್ಕ
kex_kem_sntrup761x25519_keypair(ಸಂರಚನಾ kex *kex)
{
	ಸಂರಚನಾ sshbuf *buf = ರಿಕ್ತ;
	u_char *cp = ರಿಕ್ತ;
	size_t need;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((buf = sshbuf_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	need = crypto_kem_sntrup761_PUBLICKEYBYTES + CURVE25519_SIZE;
	ಯದಿ ((r = sshbuf_reserve(buf, need, &cp)) != 0)
		ಗಚ್ಛ out;
	crypto_kem_sntrup761_keypair(cp, kex->sntrup761_client_ಕೀಲಿ);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key sntrup761:", cp,
	    crypto_kem_sntrup761_PUBLICKEYBYTES);
#endif
	cp += crypto_kem_sntrup761_PUBLICKEYBYTES;
	kexc25519_keygen(kex->c25519_client_ಕೀಲಿ, cp);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key c25519:", cp, CURVE25519_SIZE);
#endif
	kex->client_pub = buf;
	buf = ರಿಕ್ತ;
 out:
	sshbuf_free(buf);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
kex_kem_sntrup761x25519_enc(ಸಂರಚನಾ kex *kex,
   ಧ್ರುವ ಸಂರಚನಾ sshbuf *client_blob, ಸಂರಚನಾ sshbuf **server_blobp,
   ಸಂರಚನಾ sshbuf **shared_secretp)
{
	ಸಂರಚನಾ sshbuf *server_blob = ರಿಕ್ತ;
	ಸಂರಚನಾ sshbuf *buf = ರಿಕ್ತ;
	ಧ್ರುವ u_char *client_pub;
	u_char *kem_ಕೀಲಿ, *ciphertext, *server_pub;
	u_char server_ಕೀಲಿ[CURVE25519_SIZE];
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t need;
	ಪೂರ್ಣಾಙ್ಕ r;

	*server_blobp = ರಿಕ್ತ;
	*shared_secretp = ರಿಕ್ತ;

	/* client_blob contains both KEM and ECDH client pubkeys */
	need = crypto_kem_sntrup761_PUBLICKEYBYTES + CURVE25519_SIZE;
	ಯದಿ (sshbuf_len(client_blob) != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		ಗಚ್ಛ out;
	}
	client_pub = sshbuf_ptr(client_blob);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key sntrup761:", client_pub,
	    crypto_kem_sntrup761_PUBLICKEYBYTES);
	dump_digest("client public key 25519:",
	    client_pub + crypto_kem_sntrup761_PUBLICKEYBYTES,
	    CURVE25519_SIZE);
#endif
	/* allocate buffer for concatenation of KEM key and ECDH shared key */
	/* the buffer will be hashed and the result is the shared secret */
	ಯದಿ ((buf = sshbuf_new()) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshbuf_reserve(buf, crypto_kem_sntrup761_BYTES,
	    &kem_ಕೀಲಿ)) != 0)
		ಗಚ್ಛ out;
	/* allocate space for encrypted KEM key and ECDH pub key */
	ಯದಿ ((server_blob = sshbuf_new()) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	need = crypto_kem_sntrup761_CIPHERTEXTBYTES + CURVE25519_SIZE;
	ಯದಿ ((r = sshbuf_reserve(server_blob, need, &ciphertext)) != 0)
		ಗಚ್ಛ out;
	/* generate and encrypt KEM key with client key */
	crypto_kem_sntrup761_enc(ciphertext, kem_ಕೀಲಿ, client_pub);
	/* generate ECDH key pair, store server pubkey after ciphertext */
	server_pub = ciphertext + crypto_kem_sntrup761_CIPHERTEXTBYTES;
	kexc25519_keygen(server_ಕೀಲಿ, server_pub);
	/* append ECDH shared key */
	client_pub += crypto_kem_sntrup761_PUBLICKEYBYTES;
	ಯದಿ ((r = kexc25519_shared_ಕೀಲಿ_ext(server_ಕೀಲಿ, client_pub, buf, 1)) < 0)
		ಗಚ್ಛ out;
	ಯದಿ ((r = ssh_digest_buffer(kex->hash_alg, buf, hash, ಪರಿಮಾಣ(hash))) != 0)
		ಗಚ್ಛ out;
#ifdef DEBUG_KEXECDH
	dump_digest("server public key 25519:", server_pub, CURVE25519_SIZE);
	dump_digest("server cipher text:", ciphertext,
	    crypto_kem_sntrup761_CIPHERTEXTBYTES);
	dump_digest("server kem key:", kem_ಕೀಲಿ, crypto_kem_sntrup761_BYTES);
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	/* string-encoded hash is resulting shared secret */
	sshbuf_reset(buf);
	ಯದಿ ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_bytes(kex->hash_alg))) != 0)
		ಗಚ್ಛ out;
#ifdef DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = ರಿಕ್ತ;
	buf = ರಿಕ್ತ;
 out:
	explicit_bzero(hash, ಪರಿಮಾಣ(hash));
	explicit_bzero(server_ಕೀಲಿ, ಪರಿಮಾಣ(server_ಕೀಲಿ));
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
kex_kem_sntrup761x25519_dec(ಸಂರಚನಾ kex *kex,
    ಧ್ರುವ ಸಂರಚನಾ sshbuf *server_blob, ಸಂರಚನಾ sshbuf **shared_secretp)
{
	ಸಂರಚನಾ sshbuf *buf = ರಿಕ್ತ;
	u_char *kem_ಕೀಲಿ = ರಿಕ್ತ;
	ಧ್ರುವ u_char *ciphertext, *server_pub;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t need;
	ಪೂರ್ಣಾಙ್ಕ r, decoded;

	*shared_secretp = ರಿಕ್ತ;

	need = crypto_kem_sntrup761_CIPHERTEXTBYTES + CURVE25519_SIZE;
	ಯದಿ (sshbuf_len(server_blob) != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		ಗಚ್ಛ out;
	}
	ciphertext = sshbuf_ptr(server_blob);
	server_pub = ciphertext + crypto_kem_sntrup761_CIPHERTEXTBYTES;
#ifdef DEBUG_KEXECDH
	dump_digest("server cipher text:", ciphertext,
	    crypto_kem_sntrup761_CIPHERTEXTBYTES);
	dump_digest("server public key c25519:", server_pub, CURVE25519_SIZE);
#endif
	/* hash concatenation of KEM key and ECDH shared key */
	ಯದಿ ((buf = sshbuf_new()) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshbuf_reserve(buf, crypto_kem_sntrup761_BYTES,
	    &kem_ಕೀಲಿ)) != 0)
		ಗಚ್ಛ out;
	decoded = crypto_kem_sntrup761_dec(kem_ಕೀಲಿ, ciphertext,
	    kex->sntrup761_client_ಕೀಲಿ);
	ಯದಿ ((r = kexc25519_shared_ಕೀಲಿ_ext(kex->c25519_client_ಕೀಲಿ, server_pub,
	    buf, 1)) < 0)
		ಗಚ್ಛ out;
	ಯದಿ ((r = ssh_digest_buffer(kex->hash_alg, buf, hash, ಪರಿಮಾಣ(hash))) != 0)
		ಗಚ್ಛ out;
#ifdef DEBUG_KEXECDH
	dump_digest("client kem key:", kem_ಕೀಲಿ, crypto_kem_sntrup761_BYTES);
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	sshbuf_reset(buf);
	ಯದಿ ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_bytes(kex->hash_alg))) != 0)
		ಗಚ್ಛ out;
#ifdef DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	ಯದಿ (decoded != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		ಗಚ್ಛ out;
	}
	*shared_secretp = buf;
	buf = ರಿಕ್ತ;
 out:
	explicit_bzero(hash, ಪರಿಮಾಣ(hash));
	sshbuf_free(buf);
	ಪ್ರತ್ಯಾಗಮ r;
}

#ಅನ್ಯಥಾ

#ಅನ್ತರ್ಭಾವ "ssherr.h"

ಸಂರಚನಾ kex;
ಸಂರಚನಾ sshbuf;
ಸಂರಚನಾ sshkey;

ಪೂರ್ಣಾಙ್ಕ
kex_kem_sntrup761x25519_keypair(ಸಂರಚನಾ kex *kex)
{
	ಪ್ರತ್ಯಾಗಮ SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

ಪೂರ್ಣಾಙ್ಕ
kex_kem_sntrup761x25519_enc(ಸಂರಚನಾ kex *kex,
   ಧ್ರುವ ಸಂರಚನಾ sshbuf *client_blob, ಸಂರಚನಾ sshbuf **server_blobp,
   ಸಂರಚನಾ sshbuf **shared_secretp)
{
	ಪ್ರತ್ಯಾಗಮ SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

ಪೂರ್ಣಾಙ್ಕ
kex_kem_sntrup761x25519_dec(ಸಂರಚನಾ kex *kex,
    ಧ್ರುವ ಸಂರಚನಾ sshbuf *server_blob, ಸಂರಚನಾ sshbuf **shared_secretp)
{
	ಪ್ರತ್ಯಾಗಮ SSH_ERR_SIGN_ALG_UNSUPPORTED;
}
#endif /* USE_SNTRUP761X25519 */
