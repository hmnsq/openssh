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
#अन्तर्भाव "log.h"

#अन्तर्भाव "crypto_api.h"

#यदि_परिभाषितम् USE_MLKEM768X25519

पूर्णाङ्क
kex_kem_mlkem768x25519_keypair(संरचना kex *kex)
{
	संरचना sshbuf *buf = रिक्त;
	u_char *cp = रिक्त;
	आकार_t need;
	पूर्णाङ्क r = SSH_ERR_आन्तरिकम्_ERROR;

	यदि ((buf = sshbuf_new()) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	need = MLKEM768_PUBLICKEYBYTES + CURVE25519_आकार;
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
	cp += MLKEM768_PUBLICKEYBYTES;
	kexc25519_keygen(kex->c25519_client_कुञ्चिका, cp);
#यदि_परिभाषितम् DEBUG_KEXECDH
	dump_digest("client public key c25519:", cp, CURVE25519_आकार);
#यदि_अन्तः
	/* success */
	r = 0;
	kex->client_pub = buf;
	buf = रिक्त;
 बहिर्गमनम्:
	sshbuf_free(buf);
	प्रत्यागम r;
}

पूर्णाङ्क
kex_kem_mlkem768x25519_enc(संरचना kex *kex,
   ध्रुव संरचना sshbuf *client_blob, संरचना sshbuf **server_blobp,
   संरचना sshbuf **shared_secretp)
{
	संरचना sshbuf *server_blob = रिक्त;
	संरचना sshbuf *buf = रिक्त;
	ध्रुव u_char *client_pub;
	u_char server_pub[CURVE25519_आकार], server_कुञ्चिका[CURVE25519_आकार];
	u_char hash[SSH_DIGEST_MAX_दीर्घता];
	u_char ct[MLKEM768_CIPHERTEXTBYTES];
	u_char shared_secret[MLKEM768_अष्टकानि];
	आकार_t need;
	पूर्णाङ्क r = SSH_ERR_आन्तरिकम्_ERROR;

	*server_blobp = रिक्त;
	*shared_secretp = रिक्त;

	/* client_blob contains both KEM and ECDH client pubkeys */
	need = MLKEM768_PUBLICKEYBYTES + CURVE25519_आकार;
	यदि (sshbuf_len(client_blob) != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		गच्छ बहिर्गमनम्;
	}
	client_pub = sshbuf_ptr(client_blob);
#यदि_परिभाषितम् DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", client_pub,
	    MLKEM768_PUBLICKEYBYTES);
	dump_digest("client public key 25519:",
	    client_pub + MLKEM768_PUBLICKEYBYTES,
	    CURVE25519_आकार);
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
	/* generate ECDH key pair, store server pubkey after ciphertext */
	kexc25519_keygen(server_कुञ्चिका, server_pub);
	यदि ((r = sshbuf_put(buf, shared_secret, परिमाण(shared_secret))) != 0 ||
	    (r = sshbuf_put(server_blob, ct, परिमाण(ct))) != 0 ||
	    (r = sshbuf_put(server_blob, server_pub, परिमाण(server_pub))) != 0)
		गच्छ बहिर्गमनम्;
	/* append ECDH shared key */
	client_pub += MLKEM768_PUBLICKEYBYTES;
	यदि ((r = kexc25519_shared_कुञ्चिका_ext(server_कुञ्चिका, client_pub, buf, 1)) < 0)
		गच्छ बहिर्गमनम्;
	यदि ((r = ssh_digest_बफर(kex->hash_alg, buf,
	    hash, परिमाण(hash))) != 0)
		गच्छ बहिर्गमनम्;
#यदि_परिभाषितम् DEBUG_KEXECDH
	dump_digest("server public key 25519:", server_pub, CURVE25519_आकार);
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
	explicit_bzero(server_कुञ्चिका, परिमाण(server_कुञ्चिका));
	explicit_bzero(shared_secret, परिमाण(shared_secret));
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	प्रत्यागम r;
}

पूर्णाङ्क
kex_kem_mlkem768x25519_dec(संरचना kex *kex,
    ध्रुव संरचना sshbuf *server_blob, संरचना sshbuf **shared_secretp)
{
	संरचना sshbuf *buf = रिक्त;
	u_char shared_secret[MLKEM768_अष्टकानि];
	ध्रुव u_char *ciphertext, *server_pub;
	u_char hash[SSH_DIGEST_MAX_दीर्घता];
	आकार_t need;
	पूर्णाङ्क r;

	*shared_secretp = रिक्त;

	need = MLKEM768_CIPHERTEXTBYTES + CURVE25519_आकार;
	यदि (sshbuf_len(server_blob) != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		गच्छ बहिर्गमनम्;
	}
	ciphertext = sshbuf_ptr(server_blob);
	server_pub = ciphertext + MLKEM768_CIPHERTEXTBYTES;
	/* hash concatenation of KEM key and ECDH shared key */
	यदि ((buf = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
#यदि_परिभाषितम् DEBUG_KEXECDH
	dump_digest("server cipher text:", ciphertext,
	    MLKEM768_CIPHERTEXTBYTES);
	dump_digest("server public key c25519:", server_pub, CURVE25519_आकार);
#यदि_अन्तः
	यदि (crypto_kem_mlkem768_dec(shared_secret, ciphertext,
	    kex->mlkem768_client_कुञ्चिका) != 0) {
		r = SSH_ERR_आन्तरिकम्_ERROR;
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = sshbuf_put(buf, shared_secret, परिमाण(shared_secret))) != 0)
		गच्छ बहिर्गमनम्;
	यदि ((r = kexc25519_shared_कुञ्चिका_ext(kex->c25519_client_कुञ्चिका, server_pub,
	    buf, 1)) < 0)
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
	sshbuf_free(buf);
	प्रत्यागम r;
}
#अन्यथा /* USE_MLKEM768X25519 */
पूर्णाङ्क
kex_kem_mlkem768x25519_keypair(संरचना kex *kex)
{
	प्रत्यागम SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

पूर्णाङ्क
kex_kem_mlkem768x25519_enc(संरचना kex *kex,
   ध्रुव संरचना sshbuf *client_blob, संरचना sshbuf **server_blobp,
   संरचना sshbuf **shared_secretp)
{
	प्रत्यागम SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

पूर्णाङ्क
kex_kem_mlkem768x25519_dec(संरचना kex *kex,
    ध्रुव संरचना sshbuf *server_blob, संरचना sshbuf **shared_secretp)
{
	प्रत्यागम SSH_ERR_SIGN_ALG_UNSUPPORTED;
}
#यदि_अन्तः /* USE_MLKEM768X25519 */
