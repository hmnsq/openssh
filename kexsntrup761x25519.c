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

#अन्तर्भाव "includes.h"

#ifdef USE_SNTRUP761X25519

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <stdio.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <signal.h>

#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "kex.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "digest.h"
#अन्तर्भाव "ssherr.h"

अस्थिर crypto_int16 crypto_int16_optblocker = 0;
अस्थिर crypto_int32 crypto_int32_optblocker = 0;
अस्थिर crypto_int64 crypto_int64_optblocker = 0;

पूर्णांक
kex_kem_sntrup761x25519_keypair(संरचना kex *kex)
{
	संरचना sshbuf *buf = रिक्त;
	u_char *cp = रिक्त;
	माप_प्रकार need;
	पूर्णांक r;

	जर ((buf = sshbuf_new()) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;
	need = crypto_kem_sntrup761_PUBLICKEYBYTES + CURVE25519_SIZE;
	जर ((r = sshbuf_reserve(buf, need, &cp)) != 0)
		जा out;
	crypto_kem_sntrup761_keypair(cp, kex->sntrup761_client_किल्ली);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key sntrup761:", cp,
	    crypto_kem_sntrup761_PUBLICKEYBYTES);
#endif
	cp += crypto_kem_sntrup761_PUBLICKEYBYTES;
	kexc25519_keygen(kex->c25519_client_किल्ली, cp);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key c25519:", cp, CURVE25519_SIZE);
#endif
	kex->client_pub = buf;
	buf = रिक्त;
 out:
	sshbuf_free(buf);
	परत r;
}

पूर्णांक
kex_kem_sntrup761x25519_enc(संरचना kex *kex,
   स्थिरांक संरचना sshbuf *client_blob, संरचना sshbuf **server_blobp,
   संरचना sshbuf **shared_secretp)
{
	संरचना sshbuf *server_blob = रिक्त;
	संरचना sshbuf *buf = रिक्त;
	स्थिरांक u_char *client_pub;
	u_char *kem_किल्ली, *ciphertext, *server_pub;
	u_char server_किल्ली[CURVE25519_SIZE];
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	माप_प्रकार need;
	पूर्णांक r;

	*server_blobp = रिक्त;
	*shared_secretp = रिक्त;

	/* client_blob contains both KEM and ECDH client pubkeys */
	need = crypto_kem_sntrup761_PUBLICKEYBYTES + CURVE25519_SIZE;
	जर (sshbuf_len(client_blob) != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		जा out;
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
	जर ((buf = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	जर ((r = sshbuf_reserve(buf, crypto_kem_sntrup761_BYTES,
	    &kem_किल्ली)) != 0)
		जा out;
	/* allocate space for encrypted KEM key and ECDH pub key */
	जर ((server_blob = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	need = crypto_kem_sntrup761_CIPHERTEXTBYTES + CURVE25519_SIZE;
	जर ((r = sshbuf_reserve(server_blob, need, &ciphertext)) != 0)
		जा out;
	/* generate and encrypt KEM key with client key */
	crypto_kem_sntrup761_enc(ciphertext, kem_किल्ली, client_pub);
	/* generate ECDH key pair, store server pubkey after ciphertext */
	server_pub = ciphertext + crypto_kem_sntrup761_CIPHERTEXTBYTES;
	kexc25519_keygen(server_किल्ली, server_pub);
	/* append ECDH shared key */
	client_pub += crypto_kem_sntrup761_PUBLICKEYBYTES;
	जर ((r = kexc25519_shared_किल्ली_ext(server_किल्ली, client_pub, buf, 1)) < 0)
		जा out;
	जर ((r = ssh_digest_buffer(kex->hash_alg, buf, hash, आकार(hash))) != 0)
		जा out;
#ifdef DEBUG_KEXECDH
	dump_digest("server public key 25519:", server_pub, CURVE25519_SIZE);
	dump_digest("server cipher text:", ciphertext,
	    crypto_kem_sntrup761_CIPHERTEXTBYTES);
	dump_digest("server kem key:", kem_किल्ली, crypto_kem_sntrup761_BYTES);
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
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = रिक्त;
	buf = रिक्त;
 out:
	explicit_bzero(hash, आकार(hash));
	explicit_bzero(server_किल्ली, आकार(server_किल्ली));
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	परत r;
}

पूर्णांक
kex_kem_sntrup761x25519_dec(संरचना kex *kex,
    स्थिरांक संरचना sshbuf *server_blob, संरचना sshbuf **shared_secretp)
{
	संरचना sshbuf *buf = रिक्त;
	u_char *kem_किल्ली = रिक्त;
	स्थिरांक u_char *ciphertext, *server_pub;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	माप_प्रकार need;
	पूर्णांक r, decoded;

	*shared_secretp = रिक्त;

	need = crypto_kem_sntrup761_CIPHERTEXTBYTES + CURVE25519_SIZE;
	जर (sshbuf_len(server_blob) != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		जा out;
	}
	ciphertext = sshbuf_ptr(server_blob);
	server_pub = ciphertext + crypto_kem_sntrup761_CIPHERTEXTBYTES;
#ifdef DEBUG_KEXECDH
	dump_digest("server cipher text:", ciphertext,
	    crypto_kem_sntrup761_CIPHERTEXTBYTES);
	dump_digest("server public key c25519:", server_pub, CURVE25519_SIZE);
#endif
	/* hash concatenation of KEM key and ECDH shared key */
	जर ((buf = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	जर ((r = sshbuf_reserve(buf, crypto_kem_sntrup761_BYTES,
	    &kem_किल्ली)) != 0)
		जा out;
	decoded = crypto_kem_sntrup761_dec(kem_किल्ली, ciphertext,
	    kex->sntrup761_client_किल्ली);
	जर ((r = kexc25519_shared_किल्ली_ext(kex->c25519_client_किल्ली, server_pub,
	    buf, 1)) < 0)
		जा out;
	जर ((r = ssh_digest_buffer(kex->hash_alg, buf, hash, आकार(hash))) != 0)
		जा out;
#ifdef DEBUG_KEXECDH
	dump_digest("client kem key:", kem_किल्ली, crypto_kem_sntrup761_BYTES);
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
	जर (decoded != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		जा out;
	}
	*shared_secretp = buf;
	buf = रिक्त;
 out:
	explicit_bzero(hash, आकार(hash));
	sshbuf_free(buf);
	परत r;
}

#अन्यथा

#अन्तर्भाव "ssherr.h"

संरचना kex;
संरचना sshbuf;
संरचना sshkey;

पूर्णांक
kex_kem_sntrup761x25519_keypair(संरचना kex *kex)
{
	परत SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

पूर्णांक
kex_kem_sntrup761x25519_enc(संरचना kex *kex,
   स्थिरांक संरचना sshbuf *client_blob, संरचना sshbuf **server_blobp,
   संरचना sshbuf **shared_secretp)
{
	परत SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

पूर्णांक
kex_kem_sntrup761x25519_dec(संरचना kex *kex,
    स्थिरांक संरचना sshbuf *server_blob, संरचना sshbuf **shared_secretp)
{
	परत SSH_ERR_SIGN_ALG_UNSUPPORTED;
}
#endif /* USE_SNTRUP761X25519 */
