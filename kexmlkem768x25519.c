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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>

#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdbool.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <endian.h>

#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "kex.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "digest.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "log.h"

#അന്തര്ഭാവ "crypto_api.h"

#ifdef USE_MLKEM768X25519

പൂർണ്ണസംഖ്യ
kex_kem_mlkem768x25519_keypair(ഘടന kex *kex)
{
	ഘടന sshbuf *buf = ശൂന്യ;
	u_char *cp = ശൂന്യ;
	size_t need;
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;

	എങ്കിൽ ((buf = sshbuf_new()) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	need = MLKEM768_PUBLICKEYBYTES + CURVE25519_SIZE;
	എങ്കിൽ ((r = sshbuf_reserve(buf, need, &cp)) != 0)
		പോകുക out;
	എങ്കിൽ (crypto_kem_mlkem768_keypair(cp, kex->mlkem768_client_താക്കോൽ) != 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		പോകുക out;
	}
#ifdef DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", cp,
	    MLKEM768_PUBLICKEYBYTES);
#endif
	cp += MLKEM768_PUBLICKEYBYTES;
	kexc25519_keygen(kex->c25519_client_താക്കോൽ, cp);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key c25519:", cp, CURVE25519_SIZE);
#endif
	/* success */
	r = 0;
	kex->client_pub = buf;
	buf = ശൂന്യ;
 out:
	sshbuf_free(buf);
	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
kex_kem_mlkem768x25519_enc(ഘടന kex *kex,
   സ്ഥിരം ഘടന sshbuf *client_blob, ഘടന sshbuf **server_blobp,
   ഘടന sshbuf **shared_secretp)
{
	ഘടന sshbuf *server_blob = ശൂന്യ;
	ഘടന sshbuf *buf = ശൂന്യ;
	സ്ഥിരം u_char *client_pub;
	u_char server_pub[CURVE25519_SIZE], server_താക്കോൽ[CURVE25519_SIZE];
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	u_char ct[MLKEM768_CIPHERTEXTBYTES];
	u_char shared_secret[MLKEM768_BYTES];
	size_t need;
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;

	*server_blobp = ശൂന്യ;
	*shared_secretp = ശൂന്യ;

	/* client_blob contains both KEM and ECDH client pubkeys */
	need = MLKEM768_PUBLICKEYBYTES + CURVE25519_SIZE;
	എങ്കിൽ (sshbuf_len(client_blob) != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		പോകുക out;
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
	എങ്കിൽ ((buf = sshbuf_new()) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	/* allocate space for encrypted KEM key and ECDH pub key */
	എങ്കിൽ ((server_blob = sshbuf_new()) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	/* generate and encrypt KEM key with client key */
	എങ്കിൽ (crypto_kem_mlkem768_enc(ct, shared_secret, client_pub) != 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		പോകുക out;
	}
	/* generate ECDH key pair, store server pubkey after ciphertext */
	kexc25519_keygen(server_താക്കോൽ, server_pub);
	എങ്കിൽ ((r = sshbuf_put(buf, shared_secret, വലുപ്പം(shared_secret))) != 0 ||
	    (r = sshbuf_put(server_blob, ct, വലുപ്പം(ct))) != 0 ||
	    (r = sshbuf_put(server_blob, server_pub, വലുപ്പം(server_pub))) != 0)
		പോകുക out;
	/* append ECDH shared key */
	client_pub += MLKEM768_PUBLICKEYBYTES;
	എങ്കിൽ ((r = kexc25519_shared_താക്കോൽ_ext(server_താക്കോൽ, client_pub, buf, 1)) < 0)
		പോകുക out;
	എങ്കിൽ ((r = ssh_digest_buffer(kex->hash_alg, buf,
	    hash, വലുപ്പം(hash))) != 0)
		പോകുക out;
#ifdef DEBUG_KEXECDH
	dump_digest("server public key 25519:", server_pub, CURVE25519_SIZE);
	dump_digest("server cipher text:", ct, വലുപ്പം(ct));
	dump_digest("server kem key:", shared_secret, വലുപ്പം(shared_secret));
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	/* string-encoded hash is resulting shared secret */
	sshbuf_reset(buf);
	എങ്കിൽ ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_bytes(kex->hash_alg))) != 0)
		പോകുക out;
#ifdef DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	/* success */
	r = 0;
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = ശൂന്യ;
	buf = ശൂന്യ;
 out:
	explicit_bzero(hash, വലുപ്പം(hash));
	explicit_bzero(server_താക്കോൽ, വലുപ്പം(server_താക്കോൽ));
	explicit_bzero(shared_secret, വലുപ്പം(shared_secret));
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
kex_kem_mlkem768x25519_dec(ഘടന kex *kex,
    സ്ഥിരം ഘടന sshbuf *server_blob, ഘടന sshbuf **shared_secretp)
{
	ഘടന sshbuf *buf = ശൂന്യ;
	u_char shared_secret[MLKEM768_BYTES];
	സ്ഥിരം u_char *ciphertext, *server_pub;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t need;
	പൂർണ്ണസംഖ്യ r;

	*shared_secretp = ശൂന്യ;

	need = MLKEM768_CIPHERTEXTBYTES + CURVE25519_SIZE;
	എങ്കിൽ (sshbuf_len(server_blob) != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		പോകുക out;
	}
	ciphertext = sshbuf_ptr(server_blob);
	server_pub = ciphertext + MLKEM768_CIPHERTEXTBYTES;
	/* hash concatenation of KEM key and ECDH shared key */
	എങ്കിൽ ((buf = sshbuf_new()) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
#ifdef DEBUG_KEXECDH
	dump_digest("server cipher text:", ciphertext,
	    MLKEM768_CIPHERTEXTBYTES);
	dump_digest("server public key c25519:", server_pub, CURVE25519_SIZE);
#endif
	എങ്കിൽ (crypto_kem_mlkem768_dec(shared_secret, ciphertext,
	    kex->mlkem768_client_താക്കോൽ) != 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		പോകുക out;
	}
	എങ്കിൽ ((r = sshbuf_put(buf, shared_secret, വലുപ്പം(shared_secret))) != 0)
		പോകുക out;
	എങ്കിൽ ((r = kexc25519_shared_താക്കോൽ_ext(kex->c25519_client_താക്കോൽ, server_pub,
	    buf, 1)) < 0)
		പോകുക out;
	എങ്കിൽ ((r = ssh_digest_buffer(kex->hash_alg, buf,
	    hash, വലുപ്പം(hash))) != 0)
		പോകുക out;
#ifdef DEBUG_KEXECDH
	dump_digest("client kem key:", shared_secret, വലുപ്പം(shared_secret));
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	sshbuf_reset(buf);
	എങ്കിൽ ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_bytes(kex->hash_alg))) != 0)
		പോകുക out;
#ifdef DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	/* success */
	r = 0;
	*shared_secretp = buf;
	buf = ശൂന്യ;
 out:
	explicit_bzero(hash, വലുപ്പം(hash));
	explicit_bzero(shared_secret, വലുപ്പം(shared_secret));
	sshbuf_free(buf);
	തിരികെ r;
}
#അല്ലെങ്കിൽ /* USE_MLKEM768X25519 */
പൂർണ്ണസംഖ്യ
kex_kem_mlkem768x25519_keypair(ഘടന kex *kex)
{
	തിരികെ SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

പൂർണ്ണസംഖ്യ
kex_kem_mlkem768x25519_enc(ഘടന kex *kex,
   സ്ഥിരം ഘടന sshbuf *client_blob, ഘടന sshbuf **server_blobp,
   ഘടന sshbuf **shared_secretp)
{
	തിരികെ SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

പൂർണ്ണസംഖ്യ
kex_kem_mlkem768x25519_dec(ഘടന kex *kex,
    സ്ഥിരം ഘടന sshbuf *server_blob, ഘടന sshbuf **shared_secretp)
{
	തിരികെ SSH_ERR_SIGN_ALG_UNSUPPORTED;
}
#endif /* USE_MLKEM768X25519 */
