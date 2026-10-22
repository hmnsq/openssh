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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>

#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <stdbool.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <endian.h>

#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "kex.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "digest.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "log.h"

#অন্তর্ভাব "crypto_api.h"

#ifdef USE_MLKEM768X25519

পূর্ণাঙ্ক
kex_kem_mlkem768x25519_keypair(সংরচনা kex *kex)
{
	সংরচনা sshbuf *buf = রিক্ত;
	u_char *cp = রিক্ত;
	size_t need;
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;

	যদি ((buf = sshbuf_new()) == রিক্ত)
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	need = MLKEM768_PUBLICKEYBYTES + CURVE25519_SIZE;
	যদি ((r = sshbuf_reserve(buf, need, &cp)) != 0)
		গচ্ছ out;
	যদি (crypto_kem_mlkem768_keypair(cp, kex->mlkem768_client_চাবি) != 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		গচ্ছ out;
	}
#ifdef DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", cp,
	    MLKEM768_PUBLICKEYBYTES);
#endif
	cp += MLKEM768_PUBLICKEYBYTES;
	kexc25519_keygen(kex->c25519_client_চাবি, cp);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key c25519:", cp, CURVE25519_SIZE);
#endif
	/* success */
	r = 0;
	kex->client_pub = buf;
	buf = রিক্ত;
 out:
	sshbuf_free(buf);
	প্রত্যাগম r;
}

পূর্ণাঙ্ক
kex_kem_mlkem768x25519_enc(সংরচনা kex *kex,
   ধ্রুব সংরচনা sshbuf *client_blob, সংরচনা sshbuf **server_blobp,
   সংরচনা sshbuf **shared_secretp)
{
	সংরচনা sshbuf *server_blob = রিক্ত;
	সংরচনা sshbuf *buf = রিক্ত;
	ধ্রুব u_char *client_pub;
	u_char server_pub[CURVE25519_SIZE], server_চাবি[CURVE25519_SIZE];
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	u_char ct[MLKEM768_CIPHERTEXTBYTES];
	u_char shared_secret[MLKEM768_BYTES];
	size_t need;
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;

	*server_blobp = রিক্ত;
	*shared_secretp = রিক্ত;

	/* client_blob contains both KEM and ECDH client pubkeys */
	need = MLKEM768_PUBLICKEYBYTES + CURVE25519_SIZE;
	যদি (sshbuf_len(client_blob) != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		গচ্ছ out;
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
	যদি ((buf = sshbuf_new()) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	/* allocate space for encrypted KEM key and ECDH pub key */
	যদি ((server_blob = sshbuf_new()) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	/* generate and encrypt KEM key with client key */
	যদি (crypto_kem_mlkem768_enc(ct, shared_secret, client_pub) != 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		গচ্ছ out;
	}
	/* generate ECDH key pair, store server pubkey after ciphertext */
	kexc25519_keygen(server_চাবি, server_pub);
	যদি ((r = sshbuf_put(buf, shared_secret, পরিমাণ(shared_secret))) != 0 ||
	    (r = sshbuf_put(server_blob, ct, পরিমাণ(ct))) != 0 ||
	    (r = sshbuf_put(server_blob, server_pub, পরিমাণ(server_pub))) != 0)
		গচ্ছ out;
	/* append ECDH shared key */
	client_pub += MLKEM768_PUBLICKEYBYTES;
	যদি ((r = kexc25519_shared_চাবি_ext(server_চাবি, client_pub, buf, 1)) < 0)
		গচ্ছ out;
	যদি ((r = ssh_digest_buffer(kex->hash_alg, buf,
	    hash, পরিমাণ(hash))) != 0)
		গচ্ছ out;
#ifdef DEBUG_KEXECDH
	dump_digest("server public key 25519:", server_pub, CURVE25519_SIZE);
	dump_digest("server cipher text:", ct, পরিমাণ(ct));
	dump_digest("server kem key:", shared_secret, পরিমাণ(shared_secret));
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	/* string-encoded hash is resulting shared secret */
	sshbuf_reset(buf);
	যদি ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_bytes(kex->hash_alg))) != 0)
		গচ্ছ out;
#ifdef DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	/* success */
	r = 0;
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = রিক্ত;
	buf = রিক্ত;
 out:
	explicit_bzero(hash, পরিমাণ(hash));
	explicit_bzero(server_চাবি, পরিমাণ(server_চাবি));
	explicit_bzero(shared_secret, পরিমাণ(shared_secret));
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	প্রত্যাগম r;
}

পূর্ণাঙ্ক
kex_kem_mlkem768x25519_dec(সংরচনা kex *kex,
    ধ্রুব সংরচনা sshbuf *server_blob, সংরচনা sshbuf **shared_secretp)
{
	সংরচনা sshbuf *buf = রিক্ত;
	u_char shared_secret[MLKEM768_BYTES];
	ধ্রুব u_char *ciphertext, *server_pub;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t need;
	পূর্ণাঙ্ক r;

	*shared_secretp = রিক্ত;

	need = MLKEM768_CIPHERTEXTBYTES + CURVE25519_SIZE;
	যদি (sshbuf_len(server_blob) != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		গচ্ছ out;
	}
	ciphertext = sshbuf_ptr(server_blob);
	server_pub = ciphertext + MLKEM768_CIPHERTEXTBYTES;
	/* hash concatenation of KEM key and ECDH shared key */
	যদি ((buf = sshbuf_new()) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
#ifdef DEBUG_KEXECDH
	dump_digest("server cipher text:", ciphertext,
	    MLKEM768_CIPHERTEXTBYTES);
	dump_digest("server public key c25519:", server_pub, CURVE25519_SIZE);
#endif
	যদি (crypto_kem_mlkem768_dec(shared_secret, ciphertext,
	    kex->mlkem768_client_চাবি) != 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		গচ্ছ out;
	}
	যদি ((r = sshbuf_put(buf, shared_secret, পরিমাণ(shared_secret))) != 0)
		গচ্ছ out;
	যদি ((r = kexc25519_shared_চাবি_ext(kex->c25519_client_চাবি, server_pub,
	    buf, 1)) < 0)
		গচ্ছ out;
	যদি ((r = ssh_digest_buffer(kex->hash_alg, buf,
	    hash, পরিমাণ(hash))) != 0)
		গচ্ছ out;
#ifdef DEBUG_KEXECDH
	dump_digest("client kem key:", shared_secret, পরিমাণ(shared_secret));
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	sshbuf_reset(buf);
	যদি ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_bytes(kex->hash_alg))) != 0)
		গচ্ছ out;
#ifdef DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	/* success */
	r = 0;
	*shared_secretp = buf;
	buf = রিক্ত;
 out:
	explicit_bzero(hash, পরিমাণ(hash));
	explicit_bzero(shared_secret, পরিমাণ(shared_secret));
	sshbuf_free(buf);
	প্রত্যাগম r;
}
#অন্যথা /* USE_MLKEM768X25519 */
পূর্ণাঙ্ক
kex_kem_mlkem768x25519_keypair(সংরচনা kex *kex)
{
	প্রত্যাগম SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

পূর্ণাঙ্ক
kex_kem_mlkem768x25519_enc(সংরচনা kex *kex,
   ধ্রুব সংরচনা sshbuf *client_blob, সংরচনা sshbuf **server_blobp,
   সংরচনা sshbuf **shared_secretp)
{
	প্রত্যাগম SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

পূর্ণাঙ্ক
kex_kem_mlkem768x25519_dec(সংরচনা kex *kex,
    ধ্রুব সংরচনা sshbuf *server_blob, সংরচনা sshbuf **shared_secretp)
{
	প্রত্যাগম SSH_ERR_SIGN_ALG_UNSUPPORTED;
}
#endif /* USE_MLKEM768X25519 */
