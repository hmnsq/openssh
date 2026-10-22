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

#समावेश "includes.h"

#समावेश <sys/types.h>

#समावेश <stdio.h>
#समावेश <stdint.h>
#समावेश <stdbool.h>
#समावेश <string.h>
#समावेश <signal.h>
#समावेश <endian.h>

#समावेश "sshkey.h"
#समावेश "kex.h"
#समावेश "sshbuf.h"
#समावेश "digest.h"
#समावेश "ssherr.h"

#अगर_घोषित WITH_OPENSSL
पूर्णांक
kex_kem_mlkem768ecdh_keypair(काष्ठा kex *kex)
{
	काष्ठा sshbuf *buf = शून्य;
	काष्ठा sshbuf *ec_blob = शून्य;
	EC_कुंजी *client_कुंजी = शून्य;
	स्थिर EC_GROUP *group;
	स्थिर EC_POINT *public_कुंजी;
	u_char *cp = शून्य;
	माप_प्रकार need;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	अगर ((buf = sshbuf_new()) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	need = MLKEM768_PUBLICKEYBYTES;
	अगर ((r = sshbuf_reserve(buf, need, &cp)) != 0)
		जाओ out;
	अगर (crypto_kem_mlkem768_keypair(cp, kex->mlkem768_client_कुंजी) != 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		जाओ out;
	}
#अगर_घोषित DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", cp,
	    MLKEM768_PUBLICKEYBYTES);
#पूर्ण_अगर
	अगर ((client_कुंजी = EC_कुंजी_new_by_curve_name(kex->ec_nid)) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर (EC_कुंजी_generate_कुंजी(client_कुंजी) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		जाओ out;
	}
	group = EC_कुंजी_get0_group(client_कुंजी);
	public_कुंजी = EC_कुंजी_get0_public_कुंजी(client_कुंजी);

	अगर ((ec_blob = sshbuf_new()) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर ((r = sshbuf_put_ec(ec_blob, public_कुंजी, group)) != 0 ||
	    (r = sshbuf_get_u32(ec_blob, शून्य)) != 0 ||
	    (r = sshbuf_putb(buf, ec_blob)) != 0)
		जाओ out;
#अगर_घोषित DEBUG_KEXECDH
	ख_माला_दो("client private key EC:\n", मानक_त्रुटि);
	sshkey_dump_ec_कुंजी(client_कुंजी);
#पूर्ण_अगर
	/* success */
	r = 0;
	kex->ec_client_कुंजी = client_कुंजी;
	kex->ec_group = group;
	client_कुंजी = शून्य;	/* owned by the kex */
	kex->client_pub = buf;
	buf = शून्य;
 out:
	sshbuf_free(buf);
	sshbuf_free(ec_blob);
	EC_कुंजी_free(client_कुंजी);
	वापस r;
}

पूर्णांक
kex_kem_mlkem768ecdh_enc(काष्ठा kex *kex,
   स्थिर काष्ठा sshbuf *client_blob, काष्ठा sshbuf **server_blobp,
   काष्ठा sshbuf **shared_secretp)
{
	स्थिर EC_GROUP *group;
	स्थिर EC_POINT *pub_कुंजी;
	EC_कुंजी *server_कुंजी = शून्य;
	काष्ठा sshbuf *ec_pub = शून्य;
	काष्ठा sshbuf *ec_blob = शून्य;
	काष्ठा sshbuf *ec_shared = शून्य;
	काष्ठा sshbuf *server_blob = शून्य;
	काष्ठा sshbuf *buf = शून्य;
	स्थिर u_char *client_pub;
	u_char hash[SSH_DIGEST_MAX_लंबाई];
	u_char ct[MLKEM768_CIPHERTEXTBYTES];
	u_char shared_secret[MLKEM768_BYTES];
	माप_प्रकार need;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	*server_blobp = शून्य;
	*shared_secretp = शून्य;

	/* client_blob contains both KEM and ECDH client pubkeys */
	need = MLKEM768_PUBLICKEYBYTES;
	अगर (sshbuf_len(client_blob) <= need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		जाओ out;
	}
	client_pub = sshbuf_ptr(client_blob);
#अगर_घोषित DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", client_pub,
	    MLKEM768_PUBLICKEYBYTES);
#पूर्ण_अगर

	/* allocate buffer for concatenation of KEM key and ECDH shared key */
	/* the buffer will be hashed and the result is the shared secret */
	अगर ((buf = sshbuf_new()) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	/* allocate space for encrypted KEM key and ECDH pub key */
	अगर ((server_blob = sshbuf_new()) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	/* generate and encrypt KEM key with client key */
	अगर (crypto_kem_mlkem768_enc(ct, shared_secret, client_pub) != 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		जाओ out;
	}
	अगर ((r = sshbuf_put(buf, shared_secret, माप(shared_secret))) != 0 ||
	    (r = sshbuf_put(server_blob, ct, माप(ct))) != 0)
		जाओ out;

	client_pub += MLKEM768_PUBLICKEYBYTES;
	अगर ((ec_pub = sshbuf_from(client_pub, sshbuf_len(client_blob) -
	    MLKEM768_PUBLICKEYBYTES)) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	/* generate ECDH key pair */
	अगर ((server_कुंजी = EC_कुंजी_new_by_curve_name(kex->ec_nid)) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर (EC_कुंजी_generate_कुंजी(server_कुंजी) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		जाओ out;
	}
	group = EC_कुंजी_get0_group(server_कुंजी);
#अगर_घोषित DEBUG_KEXECDH
	ख_माला_दो("server private key EC:\n", मानक_त्रुटि);
	sshkey_dump_ec_कुंजी(server_कुंजी);
#पूर्ण_अगर
	/* store server pubkey after ciphertext */
	pub_कुंजी = EC_कुंजी_get0_public_कुंजी(server_कुंजी);
	अगर ((ec_blob = sshbuf_new()) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर ((r = sshbuf_put_ec(ec_blob, pub_कुंजी, group)) != 0 ||
	    (r = sshbuf_get_u32(ec_blob, शून्य)) != 0 ||
	    (r = sshbuf_putb(server_blob, ec_blob)) != 0)
		जाओ out;

	/* append ECDH shared key */
	अगर ((r = kex_ecdh_dec_कुंजी_group(kex, ec_pub, server_कुंजी, group,
	    1, &ec_shared)) != 0 ||
	    (r = sshbuf_putb(buf, ec_shared)) != 0)
		जाओ out;

	अगर ((r = ssh_digest_बफर(kex->hash_alg, buf, hash, माप(hash))) != 0)
		जाओ out;
#अगर_घोषित DEBUG_KEXECDH
	dump_digest("server cipher text:", ct, माप(ct));
	dump_digest("server kem key:", shared_secret, माप(shared_secret));
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
	/* success */
	r = 0;
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = शून्य;
	buf = शून्य;
 out:
	explicit_bzero(hash, माप(hash));
	explicit_bzero(shared_secret, माप(shared_secret));
	EC_कुंजी_free(server_कुंजी);
	sshbuf_free(ec_pub);
	sshbuf_free(ec_blob);
	sshbuf_free(ec_shared);
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	वापस r;
}

पूर्णांक
kex_kem_mlkem768ecdh_dec(काष्ठा kex *kex,
    स्थिर काष्ठा sshbuf *server_blob, काष्ठा sshbuf **shared_secretp)
{
	काष्ठा sshbuf *buf = शून्य;
	काष्ठा sshbuf *ec_pub = शून्य;
	काष्ठा sshbuf *ec_shared = शून्य;
	u_char shared_secret[MLKEM768_BYTES];
	स्थिर u_char *ciphertext, *server_pub;
	u_char hash[SSH_DIGEST_MAX_लंबाई];
	माप_प्रकार need;
	पूर्णांक r;

	*shared_secretp = शून्य;

	need = MLKEM768_CIPHERTEXTBYTES;
	अगर (sshbuf_len(server_blob) <= need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		जाओ out;
	}
	ciphertext = sshbuf_ptr(server_blob);
	server_pub = ciphertext + MLKEM768_CIPHERTEXTBYTES;
#अगर_घोषित DEBUG_KEXECDH
	dump_digest("server cipher text (dec):", ciphertext,
	    MLKEM768_CIPHERTEXTBYTES);
#पूर्ण_अगर
	/* hash concatenation of KEM key and ECDH shared key */
	अगर ((buf = sshbuf_new()) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर (crypto_kem_mlkem768_dec(shared_secret, ciphertext,
	    kex->mlkem768_client_कुंजी) != 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		जाओ out;
	}
	अगर ((r = sshbuf_put(buf, shared_secret, माप(shared_secret))) != 0)
		जाओ out;
	अगर ((ec_pub = sshbuf_from(server_pub, sshbuf_len(server_blob) - need))
	    == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर ((r = kex_ecdh_dec_कुंजी_group(kex, ec_pub, kex->ec_client_कुंजी,
	    kex->ec_group, 1, &ec_shared)) != 0 ||
	    (r = sshbuf_putb(buf, ec_shared)) != 0)
		जाओ out;
	अगर ((r = ssh_digest_बफर(kex->hash_alg, buf,
	    hash, माप(hash))) != 0)
		जाओ out;
#अगर_घोषित DEBUG_KEXECDH
	dump_digest("client kem key:", shared_secret, माप(shared_secret));
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
	/* success */
	r = 0;
	*shared_secretp = buf;
	buf = शून्य;
 out:
	explicit_bzero(hash, माप(hash));
	explicit_bzero(shared_secret, माप(shared_secret));
	EC_कुंजी_free(kex->ec_client_कुंजी);
	kex->ec_client_कुंजी = शून्य;
	sshbuf_free(ec_pub);
	sshbuf_free(ec_shared);
	sshbuf_free(buf);
	वापस r;
}
#पूर्ण_अगर	/* WITH_OPENSSL */
