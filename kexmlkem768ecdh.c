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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdbool.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <endian.h>

#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "kex.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "digest.h"
#अन्तर्भाव "ssherr.h"

#ifdef WITH_OPENSSL
पूर्णांक
kex_kem_mlkem768ecdh_keypair(संरचना kex *kex)
{
	संरचना sshbuf *buf = रिक्त;
	संरचना sshbuf *ec_blob = रिक्त;
	EC_किल्ली *client_किल्ली = रिक्त;
	स्थिरांक EC_GROUP *group;
	स्थिरांक EC_POINT *public_किल्ली;
	u_char *cp = रिक्त;
	माप_प्रकार need;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	जर ((buf = sshbuf_new()) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;
	need = MLKEM768_PUBLICKEYBYTES;
	जर ((r = sshbuf_reserve(buf, need, &cp)) != 0)
		जा out;
	जर (crypto_kem_mlkem768_keypair(cp, kex->mlkem768_client_किल्ली) != 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		जा out;
	}
#ifdef DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", cp,
	    MLKEM768_PUBLICKEYBYTES);
#endif
	जर ((client_किल्ली = EC_किल्ली_new_by_curve_name(kex->ec_nid)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	जर (EC_किल्ली_generate_किल्ली(client_किल्ली) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		जा out;
	}
	group = EC_किल्ली_get0_group(client_किल्ली);
	public_किल्ली = EC_किल्ली_get0_public_किल्ली(client_किल्ली);

	जर ((ec_blob = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	जर ((r = sshbuf_put_ec(ec_blob, public_किल्ली, group)) != 0 ||
	    (r = sshbuf_get_u32(ec_blob, रिक्त)) != 0 ||
	    (r = sshbuf_putb(buf, ec_blob)) != 0)
		जा out;
#ifdef DEBUG_KEXECDH
	ख_माला_दो("client private key EC:\n", मानक_त्रुटि);
	sshkey_dump_ec_किल्ली(client_किल्ली);
#endif
	/* success */
	r = 0;
	kex->ec_client_किल्ली = client_किल्ली;
	kex->ec_group = group;
	client_किल्ली = रिक्त;	/* owned by the kex */
	kex->client_pub = buf;
	buf = रिक्त;
 out:
	sshbuf_free(buf);
	sshbuf_free(ec_blob);
	EC_किल्ली_free(client_किल्ली);
	परत r;
}

पूर्णांक
kex_kem_mlkem768ecdh_enc(संरचना kex *kex,
   स्थिरांक संरचना sshbuf *client_blob, संरचना sshbuf **server_blobp,
   संरचना sshbuf **shared_secretp)
{
	स्थिरांक EC_GROUP *group;
	स्थिरांक EC_POINT *pub_किल्ली;
	EC_किल्ली *server_किल्ली = रिक्त;
	संरचना sshbuf *ec_pub = रिक्त;
	संरचना sshbuf *ec_blob = रिक्त;
	संरचना sshbuf *ec_shared = रिक्त;
	संरचना sshbuf *server_blob = रिक्त;
	संरचना sshbuf *buf = रिक्त;
	स्थिरांक u_char *client_pub;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	u_char ct[MLKEM768_CIPHERTEXTBYTES];
	u_char shared_secret[MLKEM768_BYTES];
	माप_प्रकार need;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	*server_blobp = रिक्त;
	*shared_secretp = रिक्त;

	/* client_blob contains both KEM and ECDH client pubkeys */
	need = MLKEM768_PUBLICKEYBYTES;
	जर (sshbuf_len(client_blob) <= need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		जा out;
	}
	client_pub = sshbuf_ptr(client_blob);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", client_pub,
	    MLKEM768_PUBLICKEYBYTES);
#endif

	/* allocate buffer for concatenation of KEM key and ECDH shared key */
	/* the buffer will be hashed and the result is the shared secret */
	जर ((buf = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	/* allocate space for encrypted KEM key and ECDH pub key */
	जर ((server_blob = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	/* generate and encrypt KEM key with client key */
	जर (crypto_kem_mlkem768_enc(ct, shared_secret, client_pub) != 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		जा out;
	}
	जर ((r = sshbuf_put(buf, shared_secret, आकार(shared_secret))) != 0 ||
	    (r = sshbuf_put(server_blob, ct, आकार(ct))) != 0)
		जा out;

	client_pub += MLKEM768_PUBLICKEYBYTES;
	जर ((ec_pub = sshbuf_from(client_pub, sshbuf_len(client_blob) -
	    MLKEM768_PUBLICKEYBYTES)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	/* generate ECDH key pair */
	जर ((server_किल्ली = EC_किल्ली_new_by_curve_name(kex->ec_nid)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	जर (EC_किल्ली_generate_किल्ली(server_किल्ली) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		जा out;
	}
	group = EC_किल्ली_get0_group(server_किल्ली);
#ifdef DEBUG_KEXECDH
	ख_माला_दो("server private key EC:\n", मानक_त्रुटि);
	sshkey_dump_ec_किल्ली(server_किल्ली);
#endif
	/* store server pubkey after ciphertext */
	pub_किल्ली = EC_किल्ली_get0_public_किल्ली(server_किल्ली);
	जर ((ec_blob = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	जर ((r = sshbuf_put_ec(ec_blob, pub_किल्ली, group)) != 0 ||
	    (r = sshbuf_get_u32(ec_blob, रिक्त)) != 0 ||
	    (r = sshbuf_putb(server_blob, ec_blob)) != 0)
		जा out;

	/* append ECDH shared key */
	जर ((r = kex_ecdh_dec_किल्ली_group(kex, ec_pub, server_किल्ली, group,
	    1, &ec_shared)) != 0 ||
	    (r = sshbuf_putb(buf, ec_shared)) != 0)
		जा out;

	जर ((r = ssh_digest_buffer(kex->hash_alg, buf, hash, आकार(hash))) != 0)
		जा out;
#ifdef DEBUG_KEXECDH
	dump_digest("server cipher text:", ct, आकार(ct));
	dump_digest("server kem key:", shared_secret, आकार(shared_secret));
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	/* string-encoded hash is resulting shared secret */
	sshbuf_reset(buf);
	जर ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_bytes(kex->hash_alg))) != 0)
		जा out;
#ifdef DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	/* success */
	r = 0;
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = रिक्त;
	buf = रिक्त;
 out:
	explicit_bzero(hash, आकार(hash));
	explicit_bzero(shared_secret, आकार(shared_secret));
	EC_किल्ली_free(server_किल्ली);
	sshbuf_free(ec_pub);
	sshbuf_free(ec_blob);
	sshbuf_free(ec_shared);
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	परत r;
}

पूर्णांक
kex_kem_mlkem768ecdh_dec(संरचना kex *kex,
    स्थिरांक संरचना sshbuf *server_blob, संरचना sshbuf **shared_secretp)
{
	संरचना sshbuf *buf = रिक्त;
	संरचना sshbuf *ec_pub = रिक्त;
	संरचना sshbuf *ec_shared = रिक्त;
	u_char shared_secret[MLKEM768_BYTES];
	स्थिरांक u_char *ciphertext, *server_pub;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	माप_प्रकार need;
	पूर्णांक r;

	*shared_secretp = रिक्त;

	need = MLKEM768_CIPHERTEXTBYTES;
	जर (sshbuf_len(server_blob) <= need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		जा out;
	}
	ciphertext = sshbuf_ptr(server_blob);
	server_pub = ciphertext + MLKEM768_CIPHERTEXTBYTES;
#ifdef DEBUG_KEXECDH
	dump_digest("server cipher text (dec):", ciphertext,
	    MLKEM768_CIPHERTEXTBYTES);
#endif
	/* hash concatenation of KEM key and ECDH shared key */
	जर ((buf = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	जर (crypto_kem_mlkem768_dec(shared_secret, ciphertext,
	    kex->mlkem768_client_किल्ली) != 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		जा out;
	}
	जर ((r = sshbuf_put(buf, shared_secret, आकार(shared_secret))) != 0)
		जा out;
	जर ((ec_pub = sshbuf_from(server_pub, sshbuf_len(server_blob) - need))
	    == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	जर ((r = kex_ecdh_dec_किल्ली_group(kex, ec_pub, kex->ec_client_किल्ली,
	    kex->ec_group, 1, &ec_shared)) != 0 ||
	    (r = sshbuf_putb(buf, ec_shared)) != 0)
		जा out;
	जर ((r = ssh_digest_buffer(kex->hash_alg, buf,
	    hash, आकार(hash))) != 0)
		जा out;
#ifdef DEBUG_KEXECDH
	dump_digest("client kem key:", shared_secret, आकार(shared_secret));
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	sshbuf_reset(buf);
	जर ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_bytes(kex->hash_alg))) != 0)
		जा out;
#ifdef DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	/* success */
	r = 0;
	*shared_secretp = buf;
	buf = रिक्त;
 out:
	explicit_bzero(hash, आकार(hash));
	explicit_bzero(shared_secret, आकार(shared_secret));
	EC_किल्ली_free(kex->ec_client_किल्ली);
	kex->ec_client_किल्ली = रिक्त;
	sshbuf_free(ec_pub);
	sshbuf_free(ec_shared);
	sshbuf_free(buf);
	परत r;
}
#endif	/* WITH_OPENSSL */
