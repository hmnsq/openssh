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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>

#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <stdbool.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <endian.h>

#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "kex.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "digest.h"
#অন্তর্ভাব "ssherr.h"

#ifdef WITH_OPENSSL
পূর্ণসংখ্যা
kex_kem_mlkem768ecdh_keypair(কাঠামো kex *kex)
{
	কাঠামো sshbuf *buf = ফাঁকা;
	কাঠামো sshbuf *ec_blob = ফাঁকা;
	EC_চাবি *client_চাবি = ফাঁকা;
	ধ্রুবক EC_GROUP *group;
	ধ্রুবক EC_POINT *public_চাবি;
	u_char *cp = ফাঁকা;
	আকার_t need;
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;

	যদি ((buf = sshbuf_new()) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	need = MLKEM768_PUBLICKEYBYTES;
	যদি ((r = sshbuf_reserve(buf, need, &cp)) != 0)
		যাও out;
	যদি (crypto_kem_mlkem768_keypair(cp, kex->mlkem768_client_চাবি) != 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		যাও out;
	}
#ifdef DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", cp,
	    MLKEM768_PUBLICKEYBYTES);
#endif
	যদি ((client_চাবি = EC_চাবি_new_by_curve_name(kex->ec_nid)) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি (EC_চাবি_generate_চাবি(client_চাবি) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		যাও out;
	}
	group = EC_চাবি_get0_group(client_চাবি);
	public_চাবি = EC_চাবি_get0_public_চাবি(client_চাবি);

	যদি ((ec_blob = sshbuf_new()) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি ((r = sshbuf_put_ec(ec_blob, public_চাবি, group)) != 0 ||
	    (r = sshbuf_get_u32(ec_blob, ফাঁকা)) != 0 ||
	    (r = sshbuf_putb(buf, ec_blob)) != 0)
		যাও out;
#ifdef DEBUG_KEXECDH
	fputs("client private key EC:\n", stderr);
	sshkey_dump_ec_চাবি(client_চাবি);
#endif
	/* success */
	r = 0;
	kex->ec_client_চাবি = client_চাবি;
	kex->ec_group = group;
	client_চাবি = ফাঁকা;	/* owned by the kex */
	kex->client_pub = buf;
	buf = ফাঁকা;
 out:
	sshbuf_free(buf);
	sshbuf_free(ec_blob);
	EC_চাবি_free(client_চাবি);
	ফেরত r;
}

পূর্ণসংখ্যা
kex_kem_mlkem768ecdh_enc(কাঠামো kex *kex,
   ধ্রুবক কাঠামো sshbuf *client_blob, কাঠামো sshbuf **server_blobp,
   কাঠামো sshbuf **shared_secretp)
{
	ধ্রুবক EC_GROUP *group;
	ধ্রুবক EC_POINT *pub_চাবি;
	EC_চাবি *server_চাবি = ফাঁকা;
	কাঠামো sshbuf *ec_pub = ফাঁকা;
	কাঠামো sshbuf *ec_blob = ফাঁকা;
	কাঠামো sshbuf *ec_shared = ফাঁকা;
	কাঠামো sshbuf *server_blob = ফাঁকা;
	কাঠামো sshbuf *buf = ফাঁকা;
	ধ্রুবক u_char *client_pub;
	u_char hash[SSH_DIGEST_MAX_দৈর্ঘ্য];
	u_char ct[MLKEM768_CIPHERTEXTBYTES];
	u_char shared_secret[MLKEM768_BYTES];
	আকার_t need;
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;

	*server_blobp = ফাঁকা;
	*shared_secretp = ফাঁকা;

	/* client_blob contains both KEM and ECDH client pubkeys */
	need = MLKEM768_PUBLICKEYBYTES;
	যদি (sshbuf_len(client_blob) <= need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		যাও out;
	}
	client_pub = sshbuf_ptr(client_blob);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", client_pub,
	    MLKEM768_PUBLICKEYBYTES);
#endif

	/* allocate buffer for concatenation of KEM key and ECDH shared key */
	/* the buffer will be hashed and the result is the shared secret */
	যদি ((buf = sshbuf_new()) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	/* allocate space for encrypted KEM key and ECDH pub key */
	যদি ((server_blob = sshbuf_new()) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	/* generate and encrypt KEM key with client key */
	যদি (crypto_kem_mlkem768_enc(ct, shared_secret, client_pub) != 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		যাও out;
	}
	যদি ((r = sshbuf_put(buf, shared_secret, আকার(shared_secret))) != 0 ||
	    (r = sshbuf_put(server_blob, ct, আকার(ct))) != 0)
		যাও out;

	client_pub += MLKEM768_PUBLICKEYBYTES;
	যদি ((ec_pub = sshbuf_from(client_pub, sshbuf_len(client_blob) -
	    MLKEM768_PUBLICKEYBYTES)) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	/* generate ECDH key pair */
	যদি ((server_চাবি = EC_চাবি_new_by_curve_name(kex->ec_nid)) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি (EC_চাবি_generate_চাবি(server_চাবি) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		যাও out;
	}
	group = EC_চাবি_get0_group(server_চাবি);
#ifdef DEBUG_KEXECDH
	fputs("server private key EC:\n", stderr);
	sshkey_dump_ec_চাবি(server_চাবি);
#endif
	/* store server pubkey after ciphertext */
	pub_চাবি = EC_চাবি_get0_public_চাবি(server_চাবি);
	যদি ((ec_blob = sshbuf_new()) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি ((r = sshbuf_put_ec(ec_blob, pub_চাবি, group)) != 0 ||
	    (r = sshbuf_get_u32(ec_blob, ফাঁকা)) != 0 ||
	    (r = sshbuf_putb(server_blob, ec_blob)) != 0)
		যাও out;

	/* append ECDH shared key */
	যদি ((r = kex_ecdh_dec_চাবি_group(kex, ec_pub, server_চাবি, group,
	    1, &ec_shared)) != 0 ||
	    (r = sshbuf_putb(buf, ec_shared)) != 0)
		যাও out;

	যদি ((r = ssh_digest_বাফার(kex->hash_alg, buf, hash, আকার(hash))) != 0)
		যাও out;
#ifdef DEBUG_KEXECDH
	dump_digest("server cipher text:", ct, আকার(ct));
	dump_digest("server kem key:", shared_secret, আকার(shared_secret));
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	/* string-encoded hash is resulting shared secret */
	sshbuf_reset(buf);
	যদি ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_bytes(kex->hash_alg))) != 0)
		যাও out;
#ifdef DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	/* success */
	r = 0;
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = ফাঁকা;
	buf = ফাঁকা;
 out:
	explicit_bzero(hash, আকার(hash));
	explicit_bzero(shared_secret, আকার(shared_secret));
	EC_চাবি_free(server_চাবি);
	sshbuf_free(ec_pub);
	sshbuf_free(ec_blob);
	sshbuf_free(ec_shared);
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	ফেরত r;
}

পূর্ণসংখ্যা
kex_kem_mlkem768ecdh_dec(কাঠামো kex *kex,
    ধ্রুবক কাঠামো sshbuf *server_blob, কাঠামো sshbuf **shared_secretp)
{
	কাঠামো sshbuf *buf = ফাঁকা;
	কাঠামো sshbuf *ec_pub = ফাঁকা;
	কাঠামো sshbuf *ec_shared = ফাঁকা;
	u_char shared_secret[MLKEM768_BYTES];
	ধ্রুবক u_char *ciphertext, *server_pub;
	u_char hash[SSH_DIGEST_MAX_দৈর্ঘ্য];
	আকার_t need;
	পূর্ণসংখ্যা r;

	*shared_secretp = ফাঁকা;

	need = MLKEM768_CIPHERTEXTBYTES;
	যদি (sshbuf_len(server_blob) <= need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		যাও out;
	}
	ciphertext = sshbuf_ptr(server_blob);
	server_pub = ciphertext + MLKEM768_CIPHERTEXTBYTES;
#ifdef DEBUG_KEXECDH
	dump_digest("server cipher text (dec):", ciphertext,
	    MLKEM768_CIPHERTEXTBYTES);
#endif
	/* hash concatenation of KEM key and ECDH shared key */
	যদি ((buf = sshbuf_new()) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি (crypto_kem_mlkem768_dec(shared_secret, ciphertext,
	    kex->mlkem768_client_চাবি) != 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		যাও out;
	}
	যদি ((r = sshbuf_put(buf, shared_secret, আকার(shared_secret))) != 0)
		যাও out;
	যদি ((ec_pub = sshbuf_from(server_pub, sshbuf_len(server_blob) - need))
	    == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি ((r = kex_ecdh_dec_চাবি_group(kex, ec_pub, kex->ec_client_চাবি,
	    kex->ec_group, 1, &ec_shared)) != 0 ||
	    (r = sshbuf_putb(buf, ec_shared)) != 0)
		যাও out;
	যদি ((r = ssh_digest_বাফার(kex->hash_alg, buf,
	    hash, আকার(hash))) != 0)
		যাও out;
#ifdef DEBUG_KEXECDH
	dump_digest("client kem key:", shared_secret, আকার(shared_secret));
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	sshbuf_reset(buf);
	যদি ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_bytes(kex->hash_alg))) != 0)
		যাও out;
#ifdef DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	/* success */
	r = 0;
	*shared_secretp = buf;
	buf = ফাঁকা;
 out:
	explicit_bzero(hash, আকার(hash));
	explicit_bzero(shared_secret, আকার(shared_secret));
	EC_চাবি_free(kex->ec_client_চাবি);
	kex->ec_client_চাবি = ফাঁকা;
	sshbuf_free(ec_pub);
	sshbuf_free(ec_shared);
	sshbuf_free(buf);
	ফেরত r;
}
#endif	/* WITH_OPENSSL */
