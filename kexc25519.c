/* $OpenBSD: kexc25519.c,v 1.18 2024/09/02 12:13:56 djm Exp $ */
/*
 * Copyright (c) 2019 Markus Friedl.  All rights reserved.
 * Copyright (c) 2010 Damien Miller.  All rights reserved.
 * Copyright (c) 2013 Aris Adamantiadis.  All rights reserved.
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
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <signal.h>

#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "kex.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "digest.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "ssh2.h"

வெளி முழு crypto_scalarmult_curve25519(u_char a[CURVE25519_SIZE],
    மாறிலி u_char b[CURVE25519_SIZE], மாறிலி u_char c[CURVE25519_SIZE])
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_SIZE)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_SIZE)))
	__attribute__((__bounded__(__minbytes__, 3, CURVE25519_SIZE)));

வெறுமை
kexc25519_keygen(u_char சாவி[CURVE25519_SIZE], u_char pub[CURVE25519_SIZE])
{
	நிலையான மாறிலி u_char basepoint[CURVE25519_SIZE] = {9};

	arc4random_buf(சாவி, CURVE25519_SIZE);
	crypto_scalarmult_curve25519(pub, சாவி, basepoint);
}

முழு
kexc25519_shared_சாவி_ext(மாறிலி u_char சாவி[CURVE25519_SIZE],
    மாறிலி u_char pub[CURVE25519_SIZE], கட்டமைப்பு sshbuf *out, முழு raw)
{
	u_char shared_சாவி[CURVE25519_SIZE];
	u_char zero[CURVE25519_SIZE];
	முழு r;

	crypto_scalarmult_curve25519(shared_சாவி, சாவி, pub);

	/* Check for all-zero shared secret */
	explicit_bzero(zero, CURVE25519_SIZE);
	எனில் (timingsafe_bcmp(zero, shared_சாவி, CURVE25519_SIZE) == 0)
		திரும்பு SSH_ERR_சாவி_INVALID_EC_மதிப்பு;

#ifdef DEBUG_KEXECDH
	dump_digest("shared secret 25519", shared_சாவி, CURVE25519_SIZE);
#endif
	எனில் (raw)
		r = sshbuf_put(out, shared_சாவி, CURVE25519_SIZE);
	இல்லையெனில்
		r = sshbuf_put_bignum2_bytes(out, shared_சாவி, CURVE25519_SIZE);
	explicit_bzero(shared_சாவி, CURVE25519_SIZE);
	திரும்பு r;
}

முழு
kexc25519_shared_சாவி(மாறிலி u_char சாவி[CURVE25519_SIZE],
    மாறிலி u_char pub[CURVE25519_SIZE], கட்டமைப்பு sshbuf *out)
{
	திரும்பு kexc25519_shared_சாவி_ext(சாவி, pub, out, 0);
}

முழு
kex_c25519_keypair(கட்டமைப்பு kex *kex)
{
	கட்டமைப்பு sshbuf *buf = வெற்று;
	u_char *cp = வெற்று;
	முழு r;

	எனில் ((buf = sshbuf_new()) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் ((r = sshbuf_reserve(buf, CURVE25519_SIZE, &cp)) != 0)
		செல் out;
	kexc25519_keygen(kex->c25519_client_சாவி, cp);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key c25519:", cp, CURVE25519_SIZE);
#endif
	kex->client_pub = buf;
	buf = வெற்று;
 out:
	sshbuf_free(buf);
	திரும்பு r;
}

முழு
kex_c25519_enc(கட்டமைப்பு kex *kex, மாறிலி கட்டமைப்பு sshbuf *client_blob,
   கட்டமைப்பு sshbuf **server_blobp, கட்டமைப்பு sshbuf **shared_secretp)
{
	கட்டமைப்பு sshbuf *server_blob = வெற்று;
	கட்டமைப்பு sshbuf *buf = வெற்று;
	மாறிலி u_char *client_pub;
	u_char *server_pub;
	u_char server_சாவி[CURVE25519_SIZE];
	முழு r;

	*server_blobp = வெற்று;
	*shared_secretp = வெற்று;

	எனில் (sshbuf_len(client_blob) != CURVE25519_SIZE) {
		r = SSH_ERR_SIGNATURE_INVALID;
		செல் out;
	}
	client_pub = sshbuf_ptr(client_blob);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key 25519:", client_pub, CURVE25519_SIZE);
#endif
	/* allocate space for encrypted KEM key and ECDH pub key */
	எனில் ((server_blob = sshbuf_new()) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் ((r = sshbuf_reserve(server_blob, CURVE25519_SIZE, &server_pub)) != 0)
		செல் out;
	kexc25519_keygen(server_சாவி, server_pub);
	/* allocate shared secret */
	எனில் ((buf = sshbuf_new()) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் ((r = kexc25519_shared_சாவி_ext(server_சாவி, client_pub, buf, 0)) < 0)
		செல் out;
#ifdef DEBUG_KEXECDH
	dump_digest("server public key 25519:", server_pub, CURVE25519_SIZE);
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = வெற்று;
	buf = வெற்று;
 out:
	explicit_bzero(server_சாவி, அளவு(server_சாவி));
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	திரும்பு r;
}

முழு
kex_c25519_dec(கட்டமைப்பு kex *kex, மாறிலி கட்டமைப்பு sshbuf *server_blob,
    கட்டமைப்பு sshbuf **shared_secretp)
{
	கட்டமைப்பு sshbuf *buf = வெற்று;
	மாறிலி u_char *server_pub;
	முழு r;

	*shared_secretp = வெற்று;

	எனில் (sshbuf_len(server_blob) != CURVE25519_SIZE) {
		r = SSH_ERR_SIGNATURE_INVALID;
		செல் out;
	}
	server_pub = sshbuf_ptr(server_blob);
#ifdef DEBUG_KEXECDH
	dump_digest("server public key c25519:", server_pub, CURVE25519_SIZE);
#endif
	/* shared secret */
	எனில் ((buf = sshbuf_new()) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் ((r = kexc25519_shared_சாவி_ext(kex->c25519_client_சாவி, server_pub,
	    buf, 0)) < 0)
		செல் out;
#ifdef DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	*shared_secretp = buf;
	buf = வெற்று;
 out:
	sshbuf_free(buf);
	திரும்பு r;
}
