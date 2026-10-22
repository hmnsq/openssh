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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>

#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdbool.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <endian.h>

#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "kex.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "digest.h"
#அந்தர்பாவ "ssherr.h"

#ifdef WITH_OPENSSL
முழு
kex_kem_mlkem768ecdh_keypair(கட்டமைப்பு kex *kex)
{
	கட்டமைப்பு sshbuf *buf = வெற்று;
	கட்டமைப்பு sshbuf *ec_blob = வெற்று;
	EC_சாவி *client_சாவி = வெற்று;
	மாறிலி EC_GROUP *group;
	மாறிலி EC_POINT *public_சாவி;
	u_char *cp = வெற்று;
	size_t need;
	முழு r = SSH_ERR_INTERNAL_ERROR;

	எனில் ((buf = sshbuf_new()) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	need = MLKEM768_PUBLICKEYBYTES;
	எனில் ((r = sshbuf_reserve(buf, need, &cp)) != 0)
		செல் out;
	எனில் (crypto_kem_mlkem768_keypair(cp, kex->mlkem768_client_சாவி) != 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		செல் out;
	}
#ifdef DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", cp,
	    MLKEM768_PUBLICKEYBYTES);
#endif
	எனில் ((client_சாவி = EC_சாவி_new_by_curve_name(kex->ec_nid)) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் (EC_சாவி_generate_சாவி(client_சாவி) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		செல் out;
	}
	group = EC_சாவி_get0_group(client_சாவி);
	public_சாவி = EC_சாவி_get0_public_சாவி(client_சாவி);

	எனில் ((ec_blob = sshbuf_new()) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் ((r = sshbuf_put_ec(ec_blob, public_சாவி, group)) != 0 ||
	    (r = sshbuf_get_u32(ec_blob, வெற்று)) != 0 ||
	    (r = sshbuf_putb(buf, ec_blob)) != 0)
		செல் out;
#ifdef DEBUG_KEXECDH
	fputs("client private key EC:\n", stderr);
	sshkey_dump_ec_சாவி(client_சாவி);
#endif
	/* success */
	r = 0;
	kex->ec_client_சாவி = client_சாவி;
	kex->ec_group = group;
	client_சாவி = வெற்று;	/* owned by the kex */
	kex->client_pub = buf;
	buf = வெற்று;
 out:
	sshbuf_free(buf);
	sshbuf_free(ec_blob);
	EC_சாவி_free(client_சாவி);
	திரும்பு r;
}

முழு
kex_kem_mlkem768ecdh_enc(கட்டமைப்பு kex *kex,
   மாறிலி கட்டமைப்பு sshbuf *client_blob, கட்டமைப்பு sshbuf **server_blobp,
   கட்டமைப்பு sshbuf **shared_secretp)
{
	மாறிலி EC_GROUP *group;
	மாறிலி EC_POINT *pub_சாவி;
	EC_சாவி *server_சாவி = வெற்று;
	கட்டமைப்பு sshbuf *ec_pub = வெற்று;
	கட்டமைப்பு sshbuf *ec_blob = வெற்று;
	கட்டமைப்பு sshbuf *ec_shared = வெற்று;
	கட்டமைப்பு sshbuf *server_blob = வெற்று;
	கட்டமைப்பு sshbuf *buf = வெற்று;
	மாறிலி u_char *client_pub;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	u_char ct[MLKEM768_CIPHERTEXTBYTES];
	u_char shared_secret[MLKEM768_BYTES];
	size_t need;
	முழு r = SSH_ERR_INTERNAL_ERROR;

	*server_blobp = வெற்று;
	*shared_secretp = வெற்று;

	/* client_blob contains both KEM and ECDH client pubkeys */
	need = MLKEM768_PUBLICKEYBYTES;
	எனில் (sshbuf_len(client_blob) <= need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		செல் out;
	}
	client_pub = sshbuf_ptr(client_blob);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", client_pub,
	    MLKEM768_PUBLICKEYBYTES);
#endif

	/* allocate buffer for concatenation of KEM key and ECDH shared key */
	/* the buffer will be hashed and the result is the shared secret */
	எனில் ((buf = sshbuf_new()) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	/* allocate space for encrypted KEM key and ECDH pub key */
	எனில் ((server_blob = sshbuf_new()) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	/* generate and encrypt KEM key with client key */
	எனில் (crypto_kem_mlkem768_enc(ct, shared_secret, client_pub) != 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		செல் out;
	}
	எனில் ((r = sshbuf_put(buf, shared_secret, அளவு(shared_secret))) != 0 ||
	    (r = sshbuf_put(server_blob, ct, அளவு(ct))) != 0)
		செல் out;

	client_pub += MLKEM768_PUBLICKEYBYTES;
	எனில் ((ec_pub = sshbuf_from(client_pub, sshbuf_len(client_blob) -
	    MLKEM768_PUBLICKEYBYTES)) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	/* generate ECDH key pair */
	எனில் ((server_சாவி = EC_சாவி_new_by_curve_name(kex->ec_nid)) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் (EC_சாவி_generate_சாவி(server_சாவி) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		செல் out;
	}
	group = EC_சாவி_get0_group(server_சாவி);
#ifdef DEBUG_KEXECDH
	fputs("server private key EC:\n", stderr);
	sshkey_dump_ec_சாவி(server_சாவி);
#endif
	/* store server pubkey after ciphertext */
	pub_சாவி = EC_சாவி_get0_public_சாவி(server_சாவி);
	எனில் ((ec_blob = sshbuf_new()) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் ((r = sshbuf_put_ec(ec_blob, pub_சாவி, group)) != 0 ||
	    (r = sshbuf_get_u32(ec_blob, வெற்று)) != 0 ||
	    (r = sshbuf_putb(server_blob, ec_blob)) != 0)
		செல் out;

	/* append ECDH shared key */
	எனில் ((r = kex_ecdh_dec_சாவி_group(kex, ec_pub, server_சாவி, group,
	    1, &ec_shared)) != 0 ||
	    (r = sshbuf_putb(buf, ec_shared)) != 0)
		செல் out;

	எனில் ((r = ssh_digest_buffer(kex->hash_alg, buf, hash, அளவு(hash))) != 0)
		செல் out;
#ifdef DEBUG_KEXECDH
	dump_digest("server cipher text:", ct, அளவு(ct));
	dump_digest("server kem key:", shared_secret, அளவு(shared_secret));
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	/* string-encoded hash is resulting shared secret */
	sshbuf_reset(buf);
	எனில் ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_bytes(kex->hash_alg))) != 0)
		செல் out;
#ifdef DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	/* success */
	r = 0;
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = வெற்று;
	buf = வெற்று;
 out:
	explicit_bzero(hash, அளவு(hash));
	explicit_bzero(shared_secret, அளவு(shared_secret));
	EC_சாவி_free(server_சாவி);
	sshbuf_free(ec_pub);
	sshbuf_free(ec_blob);
	sshbuf_free(ec_shared);
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	திரும்பு r;
}

முழு
kex_kem_mlkem768ecdh_dec(கட்டமைப்பு kex *kex,
    மாறிலி கட்டமைப்பு sshbuf *server_blob, கட்டமைப்பு sshbuf **shared_secretp)
{
	கட்டமைப்பு sshbuf *buf = வெற்று;
	கட்டமைப்பு sshbuf *ec_pub = வெற்று;
	கட்டமைப்பு sshbuf *ec_shared = வெற்று;
	u_char shared_secret[MLKEM768_BYTES];
	மாறிலி u_char *ciphertext, *server_pub;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t need;
	முழு r;

	*shared_secretp = வெற்று;

	need = MLKEM768_CIPHERTEXTBYTES;
	எனில் (sshbuf_len(server_blob) <= need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		செல் out;
	}
	ciphertext = sshbuf_ptr(server_blob);
	server_pub = ciphertext + MLKEM768_CIPHERTEXTBYTES;
#ifdef DEBUG_KEXECDH
	dump_digest("server cipher text (dec):", ciphertext,
	    MLKEM768_CIPHERTEXTBYTES);
#endif
	/* hash concatenation of KEM key and ECDH shared key */
	எனில் ((buf = sshbuf_new()) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் (crypto_kem_mlkem768_dec(shared_secret, ciphertext,
	    kex->mlkem768_client_சாவி) != 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		செல் out;
	}
	எனில் ((r = sshbuf_put(buf, shared_secret, அளவு(shared_secret))) != 0)
		செல் out;
	எனில் ((ec_pub = sshbuf_from(server_pub, sshbuf_len(server_blob) - need))
	    == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் ((r = kex_ecdh_dec_சாவி_group(kex, ec_pub, kex->ec_client_சாவி,
	    kex->ec_group, 1, &ec_shared)) != 0 ||
	    (r = sshbuf_putb(buf, ec_shared)) != 0)
		செல் out;
	எனில் ((r = ssh_digest_buffer(kex->hash_alg, buf,
	    hash, அளவு(hash))) != 0)
		செல் out;
#ifdef DEBUG_KEXECDH
	dump_digest("client kem key:", shared_secret, அளவு(shared_secret));
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	sshbuf_reset(buf);
	எனில் ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_bytes(kex->hash_alg))) != 0)
		செல் out;
#ifdef DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	/* success */
	r = 0;
	*shared_secretp = buf;
	buf = வெற்று;
 out:
	explicit_bzero(hash, அளவு(hash));
	explicit_bzero(shared_secret, அளவு(shared_secret));
	EC_சாவி_free(kex->ec_client_சாவி);
	kex->ec_client_சாவி = வெற்று;
	sshbuf_free(ec_pub);
	sshbuf_free(ec_shared);
	sshbuf_free(buf);
	திரும்பு r;
}
#endif	/* WITH_OPENSSL */
