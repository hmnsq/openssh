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

#অন্তর্ভাব "includes.h"

#ifdef USE_SNTRUP761X25519

#অন্তর্ভাব <sys/types.h>

#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <signal.h>

#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "kex.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "digest.h"
#অন্তর্ভাব "ssherr.h"

অস্থির crypto_int16 crypto_int16_optblocker = 0;
অস্থির crypto_int32 crypto_int32_optblocker = 0;
অস্থির crypto_int64 crypto_int64_optblocker = 0;

পূর্ণসংখ্যা
kex_kem_sntrup761x25519_keypair(কাঠামো kex *kex)
{
	কাঠামো sshbuf *buf = ফাঁকা;
	u_char *cp = ফাঁকা;
	আকার_t need;
	পূর্ণসংখ্যা r;

	যদি ((buf = sshbuf_new()) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	need = crypto_kem_sntrup761_PUBLICKEYBYTES + CURVE25519_আকার;
	যদি ((r = sshbuf_reserve(buf, need, &cp)) != 0)
		যাও out;
	crypto_kem_sntrup761_keypair(cp, kex->sntrup761_client_চাবি);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key sntrup761:", cp,
	    crypto_kem_sntrup761_PUBLICKEYBYTES);
#endif
	cp += crypto_kem_sntrup761_PUBLICKEYBYTES;
	kexc25519_keygen(kex->c25519_client_চাবি, cp);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key c25519:", cp, CURVE25519_আকার);
#endif
	kex->client_pub = buf;
	buf = ফাঁকা;
 out:
	sshbuf_free(buf);
	ফেরত r;
}

পূর্ণসংখ্যা
kex_kem_sntrup761x25519_enc(কাঠামো kex *kex,
   ধ্রুবক কাঠামো sshbuf *client_blob, কাঠামো sshbuf **server_blobp,
   কাঠামো sshbuf **shared_secretp)
{
	কাঠামো sshbuf *server_blob = ফাঁকা;
	কাঠামো sshbuf *buf = ফাঁকা;
	ধ্রুবক u_char *client_pub;
	u_char *kem_চাবি, *ciphertext, *server_pub;
	u_char server_চাবি[CURVE25519_আকার];
	u_char hash[SSH_DIGEST_MAX_দৈর্ঘ্য];
	আকার_t need;
	পূর্ণসংখ্যা r;

	*server_blobp = ফাঁকা;
	*shared_secretp = ফাঁকা;

	/* client_blob contains both KEM and ECDH client pubkeys */
	need = crypto_kem_sntrup761_PUBLICKEYBYTES + CURVE25519_আকার;
	যদি (sshbuf_len(client_blob) != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		যাও out;
	}
	client_pub = sshbuf_ptr(client_blob);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key sntrup761:", client_pub,
	    crypto_kem_sntrup761_PUBLICKEYBYTES);
	dump_digest("client public key 25519:",
	    client_pub + crypto_kem_sntrup761_PUBLICKEYBYTES,
	    CURVE25519_আকার);
#endif
	/* allocate buffer for concatenation of KEM key and ECDH shared key */
	/* the buffer will be hashed and the result is the shared secret */
	যদি ((buf = sshbuf_new()) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি ((r = sshbuf_reserve(buf, crypto_kem_sntrup761_BYTES,
	    &kem_চাবি)) != 0)
		যাও out;
	/* allocate space for encrypted KEM key and ECDH pub key */
	যদি ((server_blob = sshbuf_new()) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	need = crypto_kem_sntrup761_CIPHERTEXTBYTES + CURVE25519_আকার;
	যদি ((r = sshbuf_reserve(server_blob, need, &ciphertext)) != 0)
		যাও out;
	/* generate and encrypt KEM key with client key */
	crypto_kem_sntrup761_enc(ciphertext, kem_চাবি, client_pub);
	/* generate ECDH key pair, store server pubkey after ciphertext */
	server_pub = ciphertext + crypto_kem_sntrup761_CIPHERTEXTBYTES;
	kexc25519_keygen(server_চাবি, server_pub);
	/* append ECDH shared key */
	client_pub += crypto_kem_sntrup761_PUBLICKEYBYTES;
	যদি ((r = kexc25519_shared_চাবি_ext(server_চাবি, client_pub, buf, 1)) < 0)
		যাও out;
	যদি ((r = ssh_digest_বাফার(kex->hash_alg, buf, hash, আকার(hash))) != 0)
		যাও out;
#ifdef DEBUG_KEXECDH
	dump_digest("server public key 25519:", server_pub, CURVE25519_আকার);
	dump_digest("server cipher text:", ciphertext,
	    crypto_kem_sntrup761_CIPHERTEXTBYTES);
	dump_digest("server kem key:", kem_চাবি, crypto_kem_sntrup761_BYTES);
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	/* string-encoded hash is resulting shared secret */
	sshbuf_reset(buf);
	যদি ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_bytes(kex->hash_alg))) != 0)
		যাও out;
#ifdef DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = ফাঁকা;
	buf = ফাঁকা;
 out:
	explicit_bzero(hash, আকার(hash));
	explicit_bzero(server_চাবি, আকার(server_চাবি));
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	ফেরত r;
}

পূর্ণসংখ্যা
kex_kem_sntrup761x25519_dec(কাঠামো kex *kex,
    ধ্রুবক কাঠামো sshbuf *server_blob, কাঠামো sshbuf **shared_secretp)
{
	কাঠামো sshbuf *buf = ফাঁকা;
	u_char *kem_চাবি = ফাঁকা;
	ধ্রুবক u_char *ciphertext, *server_pub;
	u_char hash[SSH_DIGEST_MAX_দৈর্ঘ্য];
	আকার_t need;
	পূর্ণসংখ্যা r, decoded;

	*shared_secretp = ফাঁকা;

	need = crypto_kem_sntrup761_CIPHERTEXTBYTES + CURVE25519_আকার;
	যদি (sshbuf_len(server_blob) != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		যাও out;
	}
	ciphertext = sshbuf_ptr(server_blob);
	server_pub = ciphertext + crypto_kem_sntrup761_CIPHERTEXTBYTES;
#ifdef DEBUG_KEXECDH
	dump_digest("server cipher text:", ciphertext,
	    crypto_kem_sntrup761_CIPHERTEXTBYTES);
	dump_digest("server public key c25519:", server_pub, CURVE25519_আকার);
#endif
	/* hash concatenation of KEM key and ECDH shared key */
	যদি ((buf = sshbuf_new()) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি ((r = sshbuf_reserve(buf, crypto_kem_sntrup761_BYTES,
	    &kem_চাবি)) != 0)
		যাও out;
	decoded = crypto_kem_sntrup761_dec(kem_চাবি, ciphertext,
	    kex->sntrup761_client_চাবি);
	যদি ((r = kexc25519_shared_চাবি_ext(kex->c25519_client_চাবি, server_pub,
	    buf, 1)) < 0)
		যাও out;
	যদি ((r = ssh_digest_বাফার(kex->hash_alg, buf, hash, আকার(hash))) != 0)
		যাও out;
#ifdef DEBUG_KEXECDH
	dump_digest("client kem key:", kem_চাবি, crypto_kem_sntrup761_BYTES);
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	sshbuf_reset(buf);
	যদি ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_bytes(kex->hash_alg))) != 0)
		যাও out;
#ifdef DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	যদি (decoded != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		যাও out;
	}
	*shared_secretp = buf;
	buf = ফাঁকা;
 out:
	explicit_bzero(hash, আকার(hash));
	sshbuf_free(buf);
	ফেরত r;
}

#অন্যথা

#অন্তর্ভাব "ssherr.h"

কাঠামো kex;
কাঠামো sshbuf;
কাঠামো sshkey;

পূর্ণসংখ্যা
kex_kem_sntrup761x25519_keypair(কাঠামো kex *kex)
{
	ফেরত SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

পূর্ণসংখ্যা
kex_kem_sntrup761x25519_enc(কাঠামো kex *kex,
   ধ্রুবক কাঠামো sshbuf *client_blob, কাঠামো sshbuf **server_blobp,
   কাঠামো sshbuf **shared_secretp)
{
	ফেরত SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

পূর্ণসংখ্যা
kex_kem_sntrup761x25519_dec(কাঠামো kex *kex,
    ধ্রুবক কাঠামো sshbuf *server_blob, কাঠামো sshbuf **shared_secretp)
{
	ফেরত SSH_ERR_SIGN_ALG_UNSUPPORTED;
}
#endif /* USE_SNTRUP761X25519 */
