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

#यदि_परिभाषितम् WITH_OPENSSL
पूर्णाङ्क
kex_kem_mlkem768ecdh_keypair(संरचना kex *kex)
{
	संरचना sshbuf *buf = रिक्त;
	संरचना sshbuf *ec_blob = रिक्त;
	EC_कुञ्चिका *client_कुञ्चिका = रिक्त;
	ध्रुव EC_गणः *गणः;
	ध्रुव EC_POINT *लौकिकम्_कुञ्चिका;
	u_char *cp = रिक्त;
	आकार_t need;
	पूर्णाङ्क r = SSH_ERR_आन्तरिकम्_ERROR;

	यदि ((buf = sshbuf_new()) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	need = MLKEM768_PUBLICKEYBYTES;
	यदि ((r = sshbuf_reserve(buf, need, &cp)) != 0)
		गच्छ बहिर्गमनम्;
	यदि (crypto_kem_mlkem768_keypair(cp, kex->mlkem768_client_कुञ्चिका) != 0) {
		r = SSH_ERR_आन्तरिकम्_ERROR;
		गच्छ बहिर्गमनम्;
	}
#यदि_परिभाषितम् DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", cp,
	    MLKEM768_PUBLICKEYBYTES);
#यदि_अन्तः
	यदि ((client_कुञ्चिका = EC_कुञ्चिका_new_by_वक्रम्_name(kex->ec_nid)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	यदि (EC_कुञ्चिका_generate_कुञ्चिका(client_कुञ्चिका) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ बहिर्गमनम्;
	}
	गणः = EC_कुञ्चिका_get0_गणः(client_कुञ्चिका);
	लौकिकम्_कुञ्चिका = EC_कुञ्चिका_get0_लौकिकम्_कुञ्चिका(client_कुञ्चिका);

	यदि ((ec_blob = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = sshbuf_put_ec(ec_blob, लौकिकम्_कुञ्चिका, गणः)) != 0 ||
	    (r = sshbuf_get_u32(ec_blob, रिक्त)) != 0 ||
	    (r = sshbuf_putb(buf, ec_blob)) != 0)
		गच्छ बहिर्गमनम्;
#यदि_परिभाषितम् DEBUG_KEXECDH
	fputs("client private key EC:\n", stderr);
	sshkey_dump_ec_कुञ्चिका(client_कुञ्चिका);
#यदि_अन्तः
	/* success */
	r = 0;
	kex->ec_client_कुञ्चिका = client_कुञ्चिका;
	kex->ec_गणः = गणः;
	client_कुञ्चिका = रिक्त;	/* owned by the kex */
	kex->client_pub = buf;
	buf = रिक्त;
 बहिर्गमनम्:
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
	ध्रुव EC_गणः *गणः;
	ध्रुव EC_POINT *pub_कुञ्चिका;
	EC_कुञ्चिका *server_कुञ्चिका = रिक्त;
	संरचना sshbuf *ec_pub = रिक्त;
	संरचना sshbuf *ec_blob = रिक्त;
	संरचना sshbuf *ec_shared = रिक्त;
	संरचना sshbuf *server_blob = रिक्त;
	संरचना sshbuf *buf = रिक्त;
	ध्रुव u_char *client_pub;
	u_char hash[SSH_DIGEST_MAX_दीर्घता];
	u_char ct[MLKEM768_CIPHERTEXTBYTES];
	u_char shared_secret[MLKEM768_अष्टकानि];
	आकार_t need;
	पूर्णाङ्क r = SSH_ERR_आन्तरिकम्_ERROR;

	*server_blobp = रिक्त;
	*shared_secretp = रिक्त;

	/* client_blob contains both KEM and ECDH client pubkeys */
	need = MLKEM768_PUBLICKEYBYTES;
	यदि (sshbuf_len(client_blob) <= need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		गच्छ बहिर्गमनम्;
	}
	client_pub = sshbuf_ptr(client_blob);
#यदि_परिभाषितम् DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", client_pub,
	    MLKEM768_PUBLICKEYBYTES);
#यदि_अन्तः

	/* allocate buffer for concatenation of KEM key and ECDH shared key */
	/* the buffer will be hashed and the result is the shared secret */
	यदि ((buf = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	/* allocate space for encrypted KEM key and ECDH pub key */
	यदि ((server_blob = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	/* generate and encrypt KEM key with client key */
	यदि (crypto_kem_mlkem768_enc(ct, shared_secret, client_pub) != 0) {
		r = SSH_ERR_आन्तरिकम्_ERROR;
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = sshbuf_put(buf, shared_secret, परिमाण(shared_secret))) != 0 ||
	    (r = sshbuf_put(server_blob, ct, परिमाण(ct))) != 0)
		गच्छ बहिर्गमनम्;

	client_pub += MLKEM768_PUBLICKEYBYTES;
	यदि ((ec_pub = sshbuf_from(client_pub, sshbuf_len(client_blob) -
	    MLKEM768_PUBLICKEYBYTES)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	/* generate ECDH key pair */
	यदि ((server_कुञ्चिका = EC_कुञ्चिका_new_by_वक्रम्_name(kex->ec_nid)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	यदि (EC_कुञ्चिका_generate_कुञ्चिका(server_कुञ्चिका) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ बहिर्गमनम्;
	}
	गणः = EC_कुञ्चिका_get0_गणः(server_कुञ्चिका);
#यदि_परिभाषितम् DEBUG_KEXECDH
	fputs("server private key EC:\n", stderr);
	sshkey_dump_ec_कुञ्चिका(server_कुञ्चिका);
#यदि_अन्तः
	/* store server pubkey after ciphertext */
	pub_कुञ्चिका = EC_कुञ्चिका_get0_लौकिकम्_कुञ्चिका(server_कुञ्चिका);
	यदि ((ec_blob = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = sshbuf_put_ec(ec_blob, pub_कुञ्चिका, गणः)) != 0 ||
	    (r = sshbuf_get_u32(ec_blob, रिक्त)) != 0 ||
	    (r = sshbuf_putb(server_blob, ec_blob)) != 0)
		गच्छ बहिर्गमनम्;

	/* append ECDH shared key */
	यदि ((r = kex_ecdh_dec_कुञ्चिका_गणः(kex, ec_pub, server_कुञ्चिका, गणः,
	    1, &ec_shared)) != 0 ||
	    (r = sshbuf_putb(buf, ec_shared)) != 0)
		गच्छ बहिर्गमनम्;

	यदि ((r = ssh_digest_बफर(kex->hash_alg, buf, hash, परिमाण(hash))) != 0)
		गच्छ बहिर्गमनम्;
#यदि_परिभाषितम् DEBUG_KEXECDH
	dump_digest("server cipher text:", ct, परिमाण(ct));
	dump_digest("server kem key:", shared_secret, परिमाण(shared_secret));
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#यदि_अन्तः
	/* string-encoded hash is resulting shared secret */
	sshbuf_reset(buf);
	यदि ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_अष्टकानि(kex->hash_alg))) != 0)
		गच्छ बहिर्गमनम्;
#यदि_परिभाषितम् DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#यदि_अन्तः
	/* success */
	r = 0;
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = रिक्त;
	buf = रिक्त;
 बहिर्गमनम्:
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
	u_char shared_secret[MLKEM768_अष्टकानि];
	ध्रुव u_char *ciphertext, *server_pub;
	u_char hash[SSH_DIGEST_MAX_दीर्घता];
	आकार_t need;
	पूर्णाङ्क r;

	*shared_secretp = रिक्त;

	need = MLKEM768_CIPHERTEXTBYTES;
	यदि (sshbuf_len(server_blob) <= need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		गच्छ बहिर्गमनम्;
	}
	ciphertext = sshbuf_ptr(server_blob);
	server_pub = ciphertext + MLKEM768_CIPHERTEXTBYTES;
#यदि_परिभाषितम् DEBUG_KEXECDH
	dump_digest("server cipher text (dec):", ciphertext,
	    MLKEM768_CIPHERTEXTBYTES);
#यदि_अन्तः
	/* hash concatenation of KEM key and ECDH shared key */
	यदि ((buf = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	यदि (crypto_kem_mlkem768_dec(shared_secret, ciphertext,
	    kex->mlkem768_client_कुञ्चिका) != 0) {
		r = SSH_ERR_आन्तरिकम्_ERROR;
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = sshbuf_put(buf, shared_secret, परिमाण(shared_secret))) != 0)
		गच्छ बहिर्गमनम्;
	यदि ((ec_pub = sshbuf_from(server_pub, sshbuf_len(server_blob) - need))
	    == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = kex_ecdh_dec_कुञ्चिका_गणः(kex, ec_pub, kex->ec_client_कुञ्चिका,
	    kex->ec_गणः, 1, &ec_shared)) != 0 ||
	    (r = sshbuf_putb(buf, ec_shared)) != 0)
		गच्छ बहिर्गमनम्;
	यदि ((r = ssh_digest_बफर(kex->hash_alg, buf,
	    hash, परिमाण(hash))) != 0)
		गच्छ बहिर्गमनम्;
#यदि_परिभाषितम् DEBUG_KEXECDH
	dump_digest("client kem key:", shared_secret, परिमाण(shared_secret));
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#यदि_अन्तः
	sshbuf_reset(buf);
	यदि ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_अष्टकानि(kex->hash_alg))) != 0)
		गच्छ बहिर्गमनम्;
#यदि_परिभाषितम् DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#यदि_अन्तः
	/* success */
	r = 0;
	*shared_secretp = buf;
	buf = रिक्त;
 बहिर्गमनम्:
	explicit_bzero(hash, परिमाण(hash));
	explicit_bzero(shared_secret, परिमाण(shared_secret));
	EC_कुञ्चिका_free(kex->ec_client_कुञ्चिका);
	kex->ec_client_कुञ्चिका = रिक्त;
	sshbuf_free(ec_pub);
	sshbuf_free(ec_shared);
	sshbuf_free(buf);
	प्रत्यागम r;
}
#यदि_अन्तः	/* WITH_OPENSSL */
