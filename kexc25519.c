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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>

#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>

#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "kex.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "digest.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "ssh2.h"

ବାହ୍ୟ ପୂର୍ଣ୍ଣସଂଖ୍ୟା crypto_scalarmult_curve25519(u_char a[CURVE25519_SIZE],
    ଅଚଳ u_char b[CURVE25519_SIZE], ଅଚଳ u_char c[CURVE25519_SIZE])
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_SIZE)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_SIZE)))
	__attribute__((__bounded__(__minbytes__, 3, CURVE25519_SIZE)));

ଶୂନ୍ୟ
kexc25519_keygen(u_char ଚାବି[CURVE25519_SIZE], u_char pub[CURVE25519_SIZE])
{
	ସ୍ଥିର ଅଚଳ u_char basepoint[CURVE25519_SIZE] = {9};

	arc4random_buf(ଚାବି, CURVE25519_SIZE);
	crypto_scalarmult_curve25519(pub, ଚାବି, basepoint);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kexc25519_shared_ଚାବି_ext(ଅଚଳ u_char ଚାବି[CURVE25519_SIZE],
    ଅଚଳ u_char pub[CURVE25519_SIZE], ସଂରଚନା sshbuf *out, ପୂର୍ଣ୍ଣସଂଖ୍ୟା raw)
{
	u_char shared_ଚାବି[CURVE25519_SIZE];
	u_char zero[CURVE25519_SIZE];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	crypto_scalarmult_curve25519(shared_ଚାବି, ଚାବି, pub);

	/* Check for all-zero shared secret */
	explicit_bzero(zero, CURVE25519_SIZE);
	ଯଦି (timingsafe_bcmp(zero, shared_ଚାବି, CURVE25519_SIZE) == 0)
		ଫେରନ୍ତୁ SSH_ERR_ଚାବି_INVALID_EC_ମୂଲ୍ୟ;

#ifdef DEBUG_KEXECDH
	dump_digest("shared secret 25519", shared_ଚାବି, CURVE25519_SIZE);
#endif
	ଯଦି (raw)
		r = sshbuf_put(out, shared_ଚାବି, CURVE25519_SIZE);
	ଅନ୍ୟଥା
		r = sshbuf_put_bignum2_bytes(out, shared_ଚାବି, CURVE25519_SIZE);
	explicit_bzero(shared_ଚାବି, CURVE25519_SIZE);
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kexc25519_shared_ଚାବି(ଅଚଳ u_char ଚାବି[CURVE25519_SIZE],
    ଅଚଳ u_char pub[CURVE25519_SIZE], ସଂରଚନା sshbuf *out)
{
	ଫେରନ୍ତୁ kexc25519_shared_ଚାବି_ext(ଚାବି, pub, out, 0);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_c25519_keypair(ସଂରଚନା kex *kex)
{
	ସଂରଚନା sshbuf *buf = ଖାଲି;
	u_char *cp = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((buf = sshbuf_new()) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି ((r = sshbuf_reserve(buf, CURVE25519_SIZE, &cp)) != 0)
		ଯାଅ out;
	kexc25519_keygen(kex->c25519_client_ଚାବି, cp);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key c25519:", cp, CURVE25519_SIZE);
#endif
	kex->client_pub = buf;
	buf = ଖାଲି;
 out:
	sshbuf_free(buf);
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_c25519_enc(ସଂରଚନା kex *kex, ଅଚଳ ସଂରଚନା sshbuf *client_blob,
   ସଂରଚନା sshbuf **server_blobp, ସଂରଚନା sshbuf **shared_secretp)
{
	ସଂରଚନା sshbuf *server_blob = ଖାଲି;
	ସଂରଚନା sshbuf *buf = ଖାଲି;
	ଅଚଳ u_char *client_pub;
	u_char *server_pub;
	u_char server_ଚାବି[CURVE25519_SIZE];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	*server_blobp = ଖାଲି;
	*shared_secretp = ଖାଲି;

	ଯଦି (sshbuf_len(client_blob) != CURVE25519_SIZE) {
		r = SSH_ERR_SIGNATURE_INVALID;
		ଯାଅ out;
	}
	client_pub = sshbuf_ptr(client_blob);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key 25519:", client_pub, CURVE25519_SIZE);
#endif
	/* allocate space for encrypted KEM key and ECDH pub key */
	ଯଦି ((server_blob = sshbuf_new()) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି ((r = sshbuf_reserve(server_blob, CURVE25519_SIZE, &server_pub)) != 0)
		ଯାଅ out;
	kexc25519_keygen(server_ଚାବି, server_pub);
	/* allocate shared secret */
	ଯଦି ((buf = sshbuf_new()) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି ((r = kexc25519_shared_ଚାବି_ext(server_ଚାବି, client_pub, buf, 0)) < 0)
		ଯାଅ out;
#ifdef DEBUG_KEXECDH
	dump_digest("server public key 25519:", server_pub, CURVE25519_SIZE);
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = ଖାଲି;
	buf = ଖାଲି;
 out:
	explicit_bzero(server_ଚାବି, ଆକାର(server_ଚାବି));
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_c25519_dec(ସଂରଚନା kex *kex, ଅଚଳ ସଂରଚନା sshbuf *server_blob,
    ସଂରଚନା sshbuf **shared_secretp)
{
	ସଂରଚନା sshbuf *buf = ଖାଲି;
	ଅଚଳ u_char *server_pub;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	*shared_secretp = ଖାଲି;

	ଯଦି (sshbuf_len(server_blob) != CURVE25519_SIZE) {
		r = SSH_ERR_SIGNATURE_INVALID;
		ଯାଅ out;
	}
	server_pub = sshbuf_ptr(server_blob);
#ifdef DEBUG_KEXECDH
	dump_digest("server public key c25519:", server_pub, CURVE25519_SIZE);
#endif
	/* shared secret */
	ଯଦି ((buf = sshbuf_new()) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି ((r = kexc25519_shared_ଚାବି_ext(kex->c25519_client_ଚାବି, server_pub,
	    buf, 0)) < 0)
		ଯାଅ out;
#ifdef DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	*shared_secretp = buf;
	buf = ଖାଲି;
 out:
	sshbuf_free(buf);
	ଫେରନ୍ତୁ r;
}
