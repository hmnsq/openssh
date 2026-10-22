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
पूर्णाङ्क
kex_kem_mlkem768ecdh_keypair(संरचना kex *kex)
{
	संरचना sshbuf *buf = रिक्त;
	संरचना sshbuf *ec_blob = रिक्त;
	EC_कुञ्चिका *client_कुञ्चिका = रिक्त;
	ध्रुव EC_GROUP *group;
	ध्रुव EC_POINT *public_कुञ्चिका;
	u_char *cp = रिक्त;
	size_t need;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;

	जइ ((buf = sshbuf_new()) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	need = MLKEM768_PUBLICKEYBYTES;
	जइ ((r = sshbuf_reserve(buf, need, &cp)) != 0)
		गच्छ out;
	जइ (crypto_kem_mlkem768_keypair(cp, kex->mlkem768_client_कुञ्चिका) != 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		गच्छ out;
	}
#ifdef DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", cp,
	    MLKEM768_PUBLICKEYBYTES);
#endif
	जइ ((client_कुञ्चिका = EC_कुञ्चिका_new_by_curve_name(kex->ec_nid)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	जइ (EC_कुञ्चिका_generate_कुञ्चिका(client_कुञ्चिका) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	group = EC_कुञ्चिका_get0_group(client_कुञ्चिका);
	public_कुञ्चिका = EC_कुञ्चिका_get0_public_कुञ्चिका(client_कुञ्चिका);

	जइ ((ec_blob = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	जइ ((r = sshbuf_put_ec(ec_blob, public_कुञ्चिका, group)) != 0 ||
	    (r = sshbuf_get_u32(ec_blob, रिक्त)) != 0 ||
	    (r = sshbuf_putb(buf, ec_blob)) != 0)
		गच्छ out;
#ifdef DEBUG_KEXECDH
	fputs("client private key EC:\n", stderr);
	sshkey_dump_ec_कुञ्चिका(client_कुञ्चिका);
#endif
	/* success */
	r = 0;
	kex->ec_client_कुञ्चिका = client_कुञ्चिका;
	kex->ec_group = group;
	client_कुञ्चिका = रिक्त;	/* owned by the kex */
	kex->client_pub = buf;
	buf = रिक्त;
 out:
	sshbuf_free(buf);
	sshbuf_free(ec_blob);
	EC_कुञ्चिका_free(client_कुञ्चिका);
	प्रत्यागम r;
}

पूर्णाङ्क
kex_kem_mlkem768ecdh_enc(संरचना kex *kex,
   ध्रुव संरचना sshbuf *client_blob, संरचना sshbuf **server_blobp,
   संरचना sshbuf **shared_secretp)
{
	ध्रुव EC_GROUP *group;
	ध्रुव EC_POINT *pub_कुञ्चिका;
	EC_कुञ्चिका *server_कुञ्चिका = रिक्त;
	संरचना sshbuf *ec_pub = रिक्त;
	संरचना sshbuf *ec_blob = रिक्त;
	संरचना sshbuf *ec_shared = रिक्त;
	संरचना sshbuf *server_blob = रिक्त;
	संरचना sshbuf *buf = रिक्त;
	ध्रुव u_char *client_pub;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	u_char ct[MLKEM768_CIPHERTEXTBYTES];
	u_char shared_secret[MLKEM768_BYTES];
	size_t need;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;

	*server_blobp = रिक्त;
	*shared_secretp = रिक्त;

	/* client_blob contains both KEM and ECDH client pubkeys */
	need = MLKEM768_PUBLICKEYBYTES;
	जइ (sshbuf_len(client_blob) <= need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		गच्छ out;
	}
	client_pub = sshbuf_ptr(client_blob);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", client_pub,
	    MLKEM768_PUBLICKEYBYTES);
#endif

	/* allocate buffer for concatenation of KEM key and ECDH shared key */
	/* the buffer will be hashed and the result is the shared secret */
	जइ ((buf = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	/* allocate space for encrypted KEM key and ECDH pub key */
	जइ ((server_blob = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	/* generate and encrypt KEM key with client key */
	जइ (crypto_kem_mlkem768_enc(ct, shared_secret, client_pub) != 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		गच्छ out;
	}
	जइ ((r = sshbuf_put(buf, shared_secret, परिमाण(shared_secret))) != 0 ||
	    (r = sshbuf_put(server_blob, ct, परिमाण(ct))) != 0)
		गच्छ out;

	client_pub += MLKEM768_PUBLICKEYBYTES;
	जइ ((ec_pub = sshbuf_from(client_pub, sshbuf_len(client_blob) -
	    MLKEM768_PUBLICKEYBYTES)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	/* generate ECDH key pair */
	जइ ((server_कुञ्चिका = EC_कुञ्चिका_new_by_curve_name(kex->ec_nid)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	जइ (EC_कुञ्चिका_generate_कुञ्चिका(server_कुञ्चिका) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	group = EC_कुञ्चिका_get0_group(server_कुञ्चिका);
#ifdef DEBUG_KEXECDH
	fputs("server private key EC:\n", stderr);
	sshkey_dump_ec_कुञ्चिका(server_कुञ्चिका);
#endif
	/* store server pubkey after ciphertext */
	pub_कुञ्चिका = EC_कुञ्चिका_get0_public_कुञ्चिका(server_कुञ्चिका);
	जइ ((ec_blob = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	जइ ((r = sshbuf_put_ec(ec_blob, pub_कुञ्चिका, group)) != 0 ||
	    (r = sshbuf_get_u32(ec_blob, रिक्त)) != 0 ||
	    (r = sshbuf_putb(server_blob, ec_blob)) != 0)
		गच्छ out;

	/* append ECDH shared key */
	जइ ((r = kex_ecdh_dec_कुञ्चिका_group(kex, ec_pub, server_कुञ्चिका, group,
	    1, &ec_shared)) != 0 ||
	    (r = sshbuf_putb(buf, ec_shared)) != 0)
		गच्छ out;

	जइ ((r = ssh_digest_buffer(kex->hash_alg, buf, hash, परिमाण(hash))) != 0)
		गच्छ out;
#ifdef DEBUG_KEXECDH
	dump_digest("server cipher text:", ct, परिमाण(ct));
	dump_digest("server kem key:", shared_secret, परिमाण(shared_secret));
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	/* string-encoded hash is resulting shared secret */
	sshbuf_reset(buf);
	जइ ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_bytes(kex->hash_alg))) != 0)
		गच्छ out;
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
	explicit_bzero(hash, परिमाण(hash));
	explicit_bzero(shared_secret, परिमाण(shared_secret));
	EC_कुञ्चिका_free(server_कुञ्चिका);
	sshbuf_free(ec_pub);
	sshbuf_free(ec_blob);
	sshbuf_free(ec_shared);
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	प्रत्यागम r;
}

पूर्णाङ्क
kex_kem_mlkem768ecdh_dec(संरचना kex *kex,
    ध्रुव संरचना sshbuf *server_blob, संरचना sshbuf **shared_secretp)
{
	संरचना sshbuf *buf = रिक्त;
	संरचना sshbuf *ec_pub = रिक्त;
	संरचना sshbuf *ec_shared = रिक्त;
	u_char shared_secret[MLKEM768_BYTES];
	ध्रुव u_char *ciphertext, *server_pub;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t need;
	पूर्णाङ्क r;

	*shared_secretp = रिक्त;

	need = MLKEM768_CIPHERTEXTBYTES;
	जइ (sshbuf_len(server_blob) <= need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		गच्छ out;
	}
	ciphertext = sshbuf_ptr(server_blob);
	server_pub = ciphertext + MLKEM768_CIPHERTEXTBYTES;
#ifdef DEBUG_KEXECDH
	dump_digest("server cipher text (dec):", ciphertext,
	    MLKEM768_CIPHERTEXTBYTES);
#endif
	/* hash concatenation of KEM key and ECDH shared key */
	जइ ((buf = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	जइ (crypto_kem_mlkem768_dec(shared_secret, ciphertext,
	    kex->mlkem768_client_कुञ्चिका) != 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		गच्छ out;
	}
	जइ ((r = sshbuf_put(buf, shared_secret, परिमाण(shared_secret))) != 0)
		गच्छ out;
	जइ ((ec_pub = sshbuf_from(server_pub, sshbuf_len(server_blob) - need))
	    == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	जइ ((r = kex_ecdh_dec_कुञ्चिका_group(kex, ec_pub, kex->ec_client_कुञ्चिका,
	    kex->ec_group, 1, &ec_shared)) != 0 ||
	    (r = sshbuf_putb(buf, ec_shared)) != 0)
		गच्छ out;
	जइ ((r = ssh_digest_buffer(kex->hash_alg, buf,
	    hash, परिमाण(hash))) != 0)
		गच्छ out;
#ifdef DEBUG_KEXECDH
	dump_digest("client kem key:", shared_secret, परिमाण(shared_secret));
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	sshbuf_reset(buf);
	जइ ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_bytes(kex->hash_alg))) != 0)
		गच्छ out;
#ifdef DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	/* success */
	r = 0;
	*shared_secretp = buf;
	buf = रिक्त;
 out:
	explicit_bzero(hash, परिमाण(hash));
	explicit_bzero(shared_secret, परिमाण(shared_secret));
	EC_कुञ्चिका_free(kex->ec_client_कुञ्चिका);
	kex->ec_client_कुञ्चिका = रिक्त;
	sshbuf_free(ec_pub);
	sshbuf_free(ec_shared);
	sshbuf_free(buf);
	प्रत्यागम r;
}
#endif	/* WITH_OPENSSL */
