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

#அந்தர்பாவ "includes.h"

#ifdef USE_SNTRUP761X25519

#அந்தர்பாவ <sys/types.h>

#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <signal.h>

#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "kex.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "digest.h"
#அந்தர்பாவ "ssherr.h"

நிலையற்ற crypto_int16 crypto_int16_optblocker = 0;
நிலையற்ற crypto_int32 crypto_int32_optblocker = 0;
நிலையற்ற crypto_int64 crypto_int64_optblocker = 0;

முழு
kex_kem_sntrup761x25519_keypair(கட்டமைப்பு kex *kex)
{
	கட்டமைப்பு sshbuf *buf = வெற்று;
	u_char *cp = வெற்று;
	size_t need;
	முழு r;

	எனில் ((buf = sshbuf_new()) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	need = crypto_kem_sntrup761_PUBLICKEYBYTES + CURVE25519_SIZE;
	எனில் ((r = sshbuf_reserve(buf, need, &cp)) != 0)
		செல் out;
	crypto_kem_sntrup761_keypair(cp, kex->sntrup761_client_சாவி);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key sntrup761:", cp,
	    crypto_kem_sntrup761_PUBLICKEYBYTES);
#endif
	cp += crypto_kem_sntrup761_PUBLICKEYBYTES;
	kexc25519_keygen(kex->c25519_client_சாவி, cp);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key c25519:", cp, CURVE25519_SIZE);
#endif
	kex->client_pub = buf;
	buf = வெற்று;
 out:
	sshbuf_free(buf);
	திரும்பு r;
}

முழு
kex_kem_sntrup761x25519_enc(கட்டமைப்பு kex *kex,
   மாறிலி கட்டமைப்பு sshbuf *client_blob, கட்டமைப்பு sshbuf **server_blobp,
   கட்டமைப்பு sshbuf **shared_secretp)
{
	கட்டமைப்பு sshbuf *server_blob = வெற்று;
	கட்டமைப்பு sshbuf *buf = வெற்று;
	மாறிலி u_char *client_pub;
	u_char *kem_சாவி, *ciphertext, *server_pub;
	u_char server_சாவி[CURVE25519_SIZE];
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t need;
	முழு r;

	*server_blobp = வெற்று;
	*shared_secretp = வெற்று;

	/* client_blob contains both KEM and ECDH client pubkeys */
	need = crypto_kem_sntrup761_PUBLICKEYBYTES + CURVE25519_SIZE;
	எனில் (sshbuf_len(client_blob) != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		செல் out;
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
	எனில் ((buf = sshbuf_new()) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் ((r = sshbuf_reserve(buf, crypto_kem_sntrup761_BYTES,
	    &kem_சாவி)) != 0)
		செல் out;
	/* allocate space for encrypted KEM key and ECDH pub key */
	எனில் ((server_blob = sshbuf_new()) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	need = crypto_kem_sntrup761_CIPHERTEXTBYTES + CURVE25519_SIZE;
	எனில் ((r = sshbuf_reserve(server_blob, need, &ciphertext)) != 0)
		செல் out;
	/* generate and encrypt KEM key with client key */
	crypto_kem_sntrup761_enc(ciphertext, kem_சாவி, client_pub);
	/* generate ECDH key pair, store server pubkey after ciphertext */
	server_pub = ciphertext + crypto_kem_sntrup761_CIPHERTEXTBYTES;
	kexc25519_keygen(server_சாவி, server_pub);
	/* append ECDH shared key */
	client_pub += crypto_kem_sntrup761_PUBLICKEYBYTES;
	எனில் ((r = kexc25519_shared_சாவி_ext(server_சாவி, client_pub, buf, 1)) < 0)
		செல் out;
	எனில் ((r = ssh_digest_buffer(kex->hash_alg, buf, hash, அளவு(hash))) != 0)
		செல் out;
#ifdef DEBUG_KEXECDH
	dump_digest("server public key 25519:", server_pub, CURVE25519_SIZE);
	dump_digest("server cipher text:", ciphertext,
	    crypto_kem_sntrup761_CIPHERTEXTBYTES);
	dump_digest("server kem key:", kem_சாவி, crypto_kem_sntrup761_BYTES);
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	/* string-encoded hash is resulting shared secret */
	sshbuf_reset(buf);
	எனில் ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_bytes(kex->hash_alg))) != 0)
		செல் out;
#ifdef DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = வெற்று;
	buf = வெற்று;
 out:
	explicit_bzero(hash, அளவு(hash));
	explicit_bzero(server_சாவி, அளவு(server_சாவி));
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	திரும்பு r;
}

முழு
kex_kem_sntrup761x25519_dec(கட்டமைப்பு kex *kex,
    மாறிலி கட்டமைப்பு sshbuf *server_blob, கட்டமைப்பு sshbuf **shared_secretp)
{
	கட்டமைப்பு sshbuf *buf = வெற்று;
	u_char *kem_சாவி = வெற்று;
	மாறிலி u_char *ciphertext, *server_pub;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t need;
	முழு r, decoded;

	*shared_secretp = வெற்று;

	need = crypto_kem_sntrup761_CIPHERTEXTBYTES + CURVE25519_SIZE;
	எனில் (sshbuf_len(server_blob) != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		செல் out;
	}
	ciphertext = sshbuf_ptr(server_blob);
	server_pub = ciphertext + crypto_kem_sntrup761_CIPHERTEXTBYTES;
#ifdef DEBUG_KEXECDH
	dump_digest("server cipher text:", ciphertext,
	    crypto_kem_sntrup761_CIPHERTEXTBYTES);
	dump_digest("server public key c25519:", server_pub, CURVE25519_SIZE);
#endif
	/* hash concatenation of KEM key and ECDH shared key */
	எனில் ((buf = sshbuf_new()) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் ((r = sshbuf_reserve(buf, crypto_kem_sntrup761_BYTES,
	    &kem_சாவி)) != 0)
		செல் out;
	decoded = crypto_kem_sntrup761_dec(kem_சாவி, ciphertext,
	    kex->sntrup761_client_சாவி);
	எனில் ((r = kexc25519_shared_சாவி_ext(kex->c25519_client_சாவி, server_pub,
	    buf, 1)) < 0)
		செல் out;
	எனில் ((r = ssh_digest_buffer(kex->hash_alg, buf, hash, அளவு(hash))) != 0)
		செல் out;
#ifdef DEBUG_KEXECDH
	dump_digest("client kem key:", kem_சாவி, crypto_kem_sntrup761_BYTES);
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	sshbuf_reset(buf);
	எனில் ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_bytes(kex->hash_alg))) != 0)
		செல் out;
#ifdef DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	எனில் (decoded != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		செல் out;
	}
	*shared_secretp = buf;
	buf = வெற்று;
 out:
	explicit_bzero(hash, அளவு(hash));
	sshbuf_free(buf);
	திரும்பு r;
}

#இல்லையெனில்

#அந்தர்பாவ "ssherr.h"

கட்டமைப்பு kex;
கட்டமைப்பு sshbuf;
கட்டமைப்பு sshkey;

முழு
kex_kem_sntrup761x25519_keypair(கட்டமைப்பு kex *kex)
{
	திரும்பு SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

முழு
kex_kem_sntrup761x25519_enc(கட்டமைப்பு kex *kex,
   மாறிலி கட்டமைப்பு sshbuf *client_blob, கட்டமைப்பு sshbuf **server_blobp,
   கட்டமைப்பு sshbuf **shared_secretp)
{
	திரும்பு SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

முழு
kex_kem_sntrup761x25519_dec(கட்டமைப்பு kex *kex,
    மாறிலி கட்டமைப்பு sshbuf *server_blob, கட்டமைப்பு sshbuf **shared_secretp)
{
	திரும்பு SSH_ERR_SIGN_ALG_UNSUPPORTED;
}
#endif /* USE_SNTRUP761X25519 */
