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

#समावेश "includes.h"

#अगर_घोषित USE_SNTRUP761X25519

#समावेश <sys/types.h>

#समावेश <stdio.h>
#समावेश <string.h>
#समावेश <signal.h>

#समावेश "sshkey.h"
#समावेश "kex.h"
#समावेश "sshbuf.h"
#समावेश "digest.h"
#समावेश "ssherr.h"

अस्थिर crypto_int16 crypto_int16_optblocker = 0;
अस्थिर crypto_int32 crypto_int32_optblocker = 0;
अस्थिर crypto_int64 crypto_int64_optblocker = 0;

पूर्णांक
kex_kem_sntrup761x25519_keypair(काष्ठा kex *kex)
{
	काष्ठा sshbuf *buf = शून्य;
	u_char *cp = शून्य;
	माप_प्रकार need;
	पूर्णांक r;

	अगर ((buf = sshbuf_new()) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	need = crypto_kem_sntrup761_PUBLICKEYBYTES + CURVE25519_आकार;
	अगर ((r = sshbuf_reserve(buf, need, &cp)) != 0)
		जाओ out;
	crypto_kem_sntrup761_keypair(cp, kex->sntrup761_client_कुंजी);
#अगर_घोषित DEBUG_KEXECDH
	dump_digest("client public key sntrup761:", cp,
	    crypto_kem_sntrup761_PUBLICKEYBYTES);
#पूर्ण_अगर
	cp += crypto_kem_sntrup761_PUBLICKEYBYTES;
	kexc25519_keygen(kex->c25519_client_कुंजी, cp);
#अगर_घोषित DEBUG_KEXECDH
	dump_digest("client public key c25519:", cp, CURVE25519_आकार);
#पूर्ण_अगर
	kex->client_pub = buf;
	buf = शून्य;
 out:
	sshbuf_free(buf);
	वापस r;
}

पूर्णांक
kex_kem_sntrup761x25519_enc(काष्ठा kex *kex,
   स्थिर काष्ठा sshbuf *client_blob, काष्ठा sshbuf **server_blobp,
   काष्ठा sshbuf **shared_secretp)
{
	काष्ठा sshbuf *server_blob = शून्य;
	काष्ठा sshbuf *buf = शून्य;
	स्थिर u_char *client_pub;
	u_char *kem_कुंजी, *ciphertext, *server_pub;
	u_char server_कुंजी[CURVE25519_आकार];
	u_char hash[SSH_DIGEST_MAX_लंबाई];
	माप_प्रकार need;
	पूर्णांक r;

	*server_blobp = शून्य;
	*shared_secretp = शून्य;

	/* client_blob contains both KEM and ECDH client pubkeys */
	need = crypto_kem_sntrup761_PUBLICKEYBYTES + CURVE25519_आकार;
	अगर (sshbuf_len(client_blob) != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		जाओ out;
	}
	client_pub = sshbuf_ptr(client_blob);
#अगर_घोषित DEBUG_KEXECDH
	dump_digest("client public key sntrup761:", client_pub,
	    crypto_kem_sntrup761_PUBLICKEYBYTES);
	dump_digest("client public key 25519:",
	    client_pub + crypto_kem_sntrup761_PUBLICKEYBYTES,
	    CURVE25519_आकार);
#पूर्ण_अगर
	/* allocate buffer for concatenation of KEM key and ECDH shared key */
	/* the buffer will be hashed and the result is the shared secret */
	अगर ((buf = sshbuf_new()) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर ((r = sshbuf_reserve(buf, crypto_kem_sntrup761_BYTES,
	    &kem_कुंजी)) != 0)
		जाओ out;
	/* allocate space for encrypted KEM key and ECDH pub key */
	अगर ((server_blob = sshbuf_new()) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	need = crypto_kem_sntrup761_CIPHERTEXTBYTES + CURVE25519_आकार;
	अगर ((r = sshbuf_reserve(server_blob, need, &ciphertext)) != 0)
		जाओ out;
	/* generate and encrypt KEM key with client key */
	crypto_kem_sntrup761_enc(ciphertext, kem_कुंजी, client_pub);
	/* generate ECDH key pair, store server pubkey after ciphertext */
	server_pub = ciphertext + crypto_kem_sntrup761_CIPHERTEXTBYTES;
	kexc25519_keygen(server_कुंजी, server_pub);
	/* append ECDH shared key */
	client_pub += crypto_kem_sntrup761_PUBLICKEYBYTES;
	अगर ((r = kexc25519_shared_कुंजी_ext(server_कुंजी, client_pub, buf, 1)) < 0)
		जाओ out;
	अगर ((r = ssh_digest_बफर(kex->hash_alg, buf, hash, माप(hash))) != 0)
		जाओ out;
#अगर_घोषित DEBUG_KEXECDH
	dump_digest("server public key 25519:", server_pub, CURVE25519_आकार);
	dump_digest("server cipher text:", ciphertext,
	    crypto_kem_sntrup761_CIPHERTEXTBYTES);
	dump_digest("server kem key:", kem_कुंजी, crypto_kem_sntrup761_BYTES);
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#पूर्ण_अगर
	/* string-encoded hash is resulting shared secret */
	sshbuf_reset(buf);
	अगर ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_bytes(kex->hash_alg))) != 0)
		जाओ out;
#अगर_घोषित DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#पूर्ण_अगर
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = शून्य;
	buf = शून्य;
 out:
	explicit_bzero(hash, माप(hash));
	explicit_bzero(server_कुंजी, माप(server_कुंजी));
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	वापस r;
}

पूर्णांक
kex_kem_sntrup761x25519_dec(काष्ठा kex *kex,
    स्थिर काष्ठा sshbuf *server_blob, काष्ठा sshbuf **shared_secretp)
{
	काष्ठा sshbuf *buf = शून्य;
	u_char *kem_कुंजी = शून्य;
	स्थिर u_char *ciphertext, *server_pub;
	u_char hash[SSH_DIGEST_MAX_लंबाई];
	माप_प्रकार need;
	पूर्णांक r, decoded;

	*shared_secretp = शून्य;

	need = crypto_kem_sntrup761_CIPHERTEXTBYTES + CURVE25519_आकार;
	अगर (sshbuf_len(server_blob) != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		जाओ out;
	}
	ciphertext = sshbuf_ptr(server_blob);
	server_pub = ciphertext + crypto_kem_sntrup761_CIPHERTEXTBYTES;
#अगर_घोषित DEBUG_KEXECDH
	dump_digest("server cipher text:", ciphertext,
	    crypto_kem_sntrup761_CIPHERTEXTBYTES);
	dump_digest("server public key c25519:", server_pub, CURVE25519_आकार);
#पूर्ण_अगर
	/* hash concatenation of KEM key and ECDH shared key */
	अगर ((buf = sshbuf_new()) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर ((r = sshbuf_reserve(buf, crypto_kem_sntrup761_BYTES,
	    &kem_कुंजी)) != 0)
		जाओ out;
	decoded = crypto_kem_sntrup761_dec(kem_कुंजी, ciphertext,
	    kex->sntrup761_client_कुंजी);
	अगर ((r = kexc25519_shared_कुंजी_ext(kex->c25519_client_कुंजी, server_pub,
	    buf, 1)) < 0)
		जाओ out;
	अगर ((r = ssh_digest_बफर(kex->hash_alg, buf, hash, माप(hash))) != 0)
		जाओ out;
#अगर_घोषित DEBUG_KEXECDH
	dump_digest("client kem key:", kem_कुंजी, crypto_kem_sntrup761_BYTES);
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#पूर्ण_अगर
	sshbuf_reset(buf);
	अगर ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_bytes(kex->hash_alg))) != 0)
		जाओ out;
#अगर_घोषित DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#पूर्ण_अगर
	अगर (decoded != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		जाओ out;
	}
	*shared_secretp = buf;
	buf = शून्य;
 out:
	explicit_bzero(hash, माप(hash));
	sshbuf_free(buf);
	वापस r;
}

#अन्यथा

#समावेश "ssherr.h"

काष्ठा kex;
काष्ठा sshbuf;
काष्ठा sshkey;

पूर्णांक
kex_kem_sntrup761x25519_keypair(काष्ठा kex *kex)
{
	वापस SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

पूर्णांक
kex_kem_sntrup761x25519_enc(काष्ठा kex *kex,
   स्थिर काष्ठा sshbuf *client_blob, काष्ठा sshbuf **server_blobp,
   काष्ठा sshbuf **shared_secretp)
{
	वापस SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

पूर्णांक
kex_kem_sntrup761x25519_dec(काष्ठा kex *kex,
    स्थिर काष्ठा sshbuf *server_blob, काष्ठा sshbuf **shared_secretp)
{
	वापस SSH_ERR_SIGN_ALG_UNSUPPORTED;
}
#पूर्ण_अगर /* USE_SNTRUP761X25519 */
