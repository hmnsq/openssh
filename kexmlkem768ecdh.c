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

#ifdef WITH_OPENSSL
പൂർണ്ണസംഖ്യ
kex_kem_mlkem768ecdh_keypair(ഘടന kex *kex)
{
	ഘടന sshbuf *buf = ശൂന്യ;
	ഘടന sshbuf *ec_blob = ശൂന്യ;
	EC_താക്കോൽ *client_താക്കോൽ = ശൂന്യ;
	സ്ഥിരം EC_GROUP *group;
	സ്ഥിരം EC_POINT *public_താക്കോൽ;
	u_char *cp = ശൂന്യ;
	size_t need;
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;

	എങ്കിൽ ((buf = sshbuf_new()) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	need = MLKEM768_PUBLICKEYBYTES;
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
	എങ്കിൽ ((client_താക്കോൽ = EC_താക്കോൽ_new_by_curve_name(kex->ec_nid)) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ (EC_താക്കോൽ_generate_താക്കോൽ(client_താക്കോൽ) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		പോകുക out;
	}
	group = EC_താക്കോൽ_get0_group(client_താക്കോൽ);
	public_താക്കോൽ = EC_താക്കോൽ_get0_public_താക്കോൽ(client_താക്കോൽ);

	എങ്കിൽ ((ec_blob = sshbuf_new()) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ ((r = sshbuf_put_ec(ec_blob, public_താക്കോൽ, group)) != 0 ||
	    (r = sshbuf_get_u32(ec_blob, ശൂന്യ)) != 0 ||
	    (r = sshbuf_putb(buf, ec_blob)) != 0)
		പോകുക out;
#ifdef DEBUG_KEXECDH
	fputs("client private key EC:\n", stderr);
	sshkey_dump_ec_താക്കോൽ(client_താക്കോൽ);
#endif
	/* success */
	r = 0;
	kex->ec_client_താക്കോൽ = client_താക്കോൽ;
	kex->ec_group = group;
	client_താക്കോൽ = ശൂന്യ;	/* owned by the kex */
	kex->client_pub = buf;
	buf = ശൂന്യ;
 out:
	sshbuf_free(buf);
	sshbuf_free(ec_blob);
	EC_താക്കോൽ_free(client_താക്കോൽ);
	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
kex_kem_mlkem768ecdh_enc(ഘടന kex *kex,
   സ്ഥിരം ഘടന sshbuf *client_blob, ഘടന sshbuf **server_blobp,
   ഘടന sshbuf **shared_secretp)
{
	സ്ഥിരം EC_GROUP *group;
	സ്ഥിരം EC_POINT *pub_താക്കോൽ;
	EC_താക്കോൽ *server_താക്കോൽ = ശൂന്യ;
	ഘടന sshbuf *ec_pub = ശൂന്യ;
	ഘടന sshbuf *ec_blob = ശൂന്യ;
	ഘടന sshbuf *ec_shared = ശൂന്യ;
	ഘടന sshbuf *server_blob = ശൂന്യ;
	ഘടന sshbuf *buf = ശൂന്യ;
	സ്ഥിരം u_char *client_pub;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	u_char ct[MLKEM768_CIPHERTEXTBYTES];
	u_char shared_secret[MLKEM768_BYTES];
	size_t need;
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;

	*server_blobp = ശൂന്യ;
	*shared_secretp = ശൂന്യ;

	/* client_blob contains both KEM and ECDH client pubkeys */
	need = MLKEM768_PUBLICKEYBYTES;
	എങ്കിൽ (sshbuf_len(client_blob) <= need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		പോകുക out;
	}
	client_pub = sshbuf_ptr(client_blob);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", client_pub,
	    MLKEM768_PUBLICKEYBYTES);
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
	എങ്കിൽ ((r = sshbuf_put(buf, shared_secret, വലുപ്പം(shared_secret))) != 0 ||
	    (r = sshbuf_put(server_blob, ct, വലുപ്പം(ct))) != 0)
		പോകുക out;

	client_pub += MLKEM768_PUBLICKEYBYTES;
	എങ്കിൽ ((ec_pub = sshbuf_from(client_pub, sshbuf_len(client_blob) -
	    MLKEM768_PUBLICKEYBYTES)) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	/* generate ECDH key pair */
	എങ്കിൽ ((server_താക്കോൽ = EC_താക്കോൽ_new_by_curve_name(kex->ec_nid)) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ (EC_താക്കോൽ_generate_താക്കോൽ(server_താക്കോൽ) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		പോകുക out;
	}
	group = EC_താക്കോൽ_get0_group(server_താക്കോൽ);
#ifdef DEBUG_KEXECDH
	fputs("server private key EC:\n", stderr);
	sshkey_dump_ec_താക്കോൽ(server_താക്കോൽ);
#endif
	/* store server pubkey after ciphertext */
	pub_താക്കോൽ = EC_താക്കോൽ_get0_public_താക്കോൽ(server_താക്കോൽ);
	എങ്കിൽ ((ec_blob = sshbuf_new()) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ ((r = sshbuf_put_ec(ec_blob, pub_താക്കോൽ, group)) != 0 ||
	    (r = sshbuf_get_u32(ec_blob, ശൂന്യ)) != 0 ||
	    (r = sshbuf_putb(server_blob, ec_blob)) != 0)
		പോകുക out;

	/* append ECDH shared key */
	എങ്കിൽ ((r = kex_ecdh_dec_താക്കോൽ_group(kex, ec_pub, server_താക്കോൽ, group,
	    1, &ec_shared)) != 0 ||
	    (r = sshbuf_putb(buf, ec_shared)) != 0)
		പോകുക out;

	എങ്കിൽ ((r = ssh_digest_buffer(kex->hash_alg, buf, hash, വലുപ്പം(hash))) != 0)
		പോകുക out;
#ifdef DEBUG_KEXECDH
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
	explicit_bzero(shared_secret, വലുപ്പം(shared_secret));
	EC_താക്കോൽ_free(server_താക്കോൽ);
	sshbuf_free(ec_pub);
	sshbuf_free(ec_blob);
	sshbuf_free(ec_shared);
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
kex_kem_mlkem768ecdh_dec(ഘടന kex *kex,
    സ്ഥിരം ഘടന sshbuf *server_blob, ഘടന sshbuf **shared_secretp)
{
	ഘടന sshbuf *buf = ശൂന്യ;
	ഘടന sshbuf *ec_pub = ശൂന്യ;
	ഘടന sshbuf *ec_shared = ശൂന്യ;
	u_char shared_secret[MLKEM768_BYTES];
	സ്ഥിരം u_char *ciphertext, *server_pub;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t need;
	പൂർണ്ണസംഖ്യ r;

	*shared_secretp = ശൂന്യ;

	need = MLKEM768_CIPHERTEXTBYTES;
	എങ്കിൽ (sshbuf_len(server_blob) <= need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		പോകുക out;
	}
	ciphertext = sshbuf_ptr(server_blob);
	server_pub = ciphertext + MLKEM768_CIPHERTEXTBYTES;
#ifdef DEBUG_KEXECDH
	dump_digest("server cipher text (dec):", ciphertext,
	    MLKEM768_CIPHERTEXTBYTES);
#endif
	/* hash concatenation of KEM key and ECDH shared key */
	എങ്കിൽ ((buf = sshbuf_new()) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ (crypto_kem_mlkem768_dec(shared_secret, ciphertext,
	    kex->mlkem768_client_താക്കോൽ) != 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		പോകുക out;
	}
	എങ്കിൽ ((r = sshbuf_put(buf, shared_secret, വലുപ്പം(shared_secret))) != 0)
		പോകുക out;
	എങ്കിൽ ((ec_pub = sshbuf_from(server_pub, sshbuf_len(server_blob) - need))
	    == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ ((r = kex_ecdh_dec_താക്കോൽ_group(kex, ec_pub, kex->ec_client_താക്കോൽ,
	    kex->ec_group, 1, &ec_shared)) != 0 ||
	    (r = sshbuf_putb(buf, ec_shared)) != 0)
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
	EC_താക്കോൽ_free(kex->ec_client_താക്കോൽ);
	kex->ec_client_താക്കോൽ = ശൂന്യ;
	sshbuf_free(ec_pub);
	sshbuf_free(ec_shared);
	sshbuf_free(buf);
	തിരികെ r;
}
#endif	/* WITH_OPENSSL */
