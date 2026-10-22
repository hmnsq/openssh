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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <stdio.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <signal.h>

#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "kex.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "digest.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "ssh2.h"

बाह्य पूर्णाङ्क crypto_scalarmult_curve25519(u_char a[CURVE25519_आकार],
    ध्रुव u_char b[CURVE25519_आकार], ध्रुव u_char c[CURVE25519_आकार])
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_आकार)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_आकार)))
	__attribute__((__bounded__(__minbytes__, 3, CURVE25519_आकार)));

शून्य
kexc25519_keygen(u_char कुञ्चिका[CURVE25519_आकार], u_char pub[CURVE25519_आकार])
{
	स्थिर ध्रुव u_char basepoint[CURVE25519_आकार] = {9};

	arc4random_buf(कुञ्चिका, CURVE25519_आकार);
	crypto_scalarmult_curve25519(pub, कुञ्चिका, basepoint);
}

पूर्णाङ्क
kexc25519_shared_कुञ्चिका_ext(ध्रुव u_char कुञ्चिका[CURVE25519_आकार],
    ध्रुव u_char pub[CURVE25519_आकार], संरचना sshbuf *बहिर्गमनम्, पूर्णाङ्क raw)
{
	u_char shared_कुञ्चिका[CURVE25519_आकार];
	u_char zero[CURVE25519_आकार];
	पूर्णाङ्क r;

	crypto_scalarmult_curve25519(shared_कुञ्चिका, कुञ्चिका, pub);

	/* Check for all-zero shared secret */
	explicit_bzero(zero, CURVE25519_आकार);
	यदि (timingsafe_bcmp(zero, shared_कुञ्चिका, CURVE25519_आकार) == 0)
		प्रत्यागम SSH_ERR_कुञ्चिका_INVALID_EC_मानम्;

#यदि_परिभाषितम् DEBUG_KEXECDH
	dump_digest("shared secret 25519", shared_कुञ्चिका, CURVE25519_आकार);
#यदि_अन्तः
	यदि (raw)
		r = sshbuf_put(बहिर्गमनम्, shared_कुञ्चिका, CURVE25519_आकार);
	अन्यथा
		r = sshbuf_put_bignum2_अष्टकानि(बहिर्गमनम्, shared_कुञ्चिका, CURVE25519_आकार);
	explicit_bzero(shared_कुञ्चिका, CURVE25519_आकार);
	प्रत्यागम r;
}

पूर्णाङ्क
kexc25519_shared_कुञ्चिका(ध्रुव u_char कुञ्चिका[CURVE25519_आकार],
    ध्रुव u_char pub[CURVE25519_आकार], संरचना sshbuf *बहिर्गमनम्)
{
	प्रत्यागम kexc25519_shared_कुञ्चिका_ext(कुञ्चिका, pub, बहिर्गमनम्, 0);
}

पूर्णाङ्क
kex_c25519_keypair(संरचना kex *kex)
{
	संरचना sshbuf *buf = रिक्त;
	u_char *cp = रिक्त;
	पूर्णाङ्क r;

	यदि ((buf = sshbuf_new()) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	यदि ((r = sshbuf_reserve(buf, CURVE25519_आकार, &cp)) != 0)
		गच्छ बहिर्गमनम्;
	kexc25519_keygen(kex->c25519_client_कुञ्चिका, cp);
#यदि_परिभाषितम् DEBUG_KEXECDH
	dump_digest("client public key c25519:", cp, CURVE25519_आकार);
#यदि_अन्तः
	kex->client_pub = buf;
	buf = रिक्त;
 बहिर्गमनम्:
	sshbuf_free(buf);
	प्रत्यागम r;
}

पूर्णाङ्क
kex_c25519_enc(संरचना kex *kex, ध्रुव संरचना sshbuf *client_blob,
   संरचना sshbuf **server_blobp, संरचना sshbuf **shared_secretp)
{
	संरचना sshbuf *server_blob = रिक्त;
	संरचना sshbuf *buf = रिक्त;
	ध्रुव u_char *client_pub;
	u_char *server_pub;
	u_char server_कुञ्चिका[CURVE25519_आकार];
	पूर्णाङ्क r;

	*server_blobp = रिक्त;
	*shared_secretp = रिक्त;

	यदि (sshbuf_len(client_blob) != CURVE25519_आकार) {
		r = SSH_ERR_SIGNATURE_INVALID;
		गच्छ बहिर्गमनम्;
	}
	client_pub = sshbuf_ptr(client_blob);
#यदि_परिभाषितम् DEBUG_KEXECDH
	dump_digest("client public key 25519:", client_pub, CURVE25519_आकार);
#यदि_अन्तः
	/* allocate space for encrypted KEM key and ECDH pub key */
	यदि ((server_blob = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = sshbuf_reserve(server_blob, CURVE25519_आकार, &server_pub)) != 0)
		गच्छ बहिर्गमनम्;
	kexc25519_keygen(server_कुञ्चिका, server_pub);
	/* allocate shared secret */
	यदि ((buf = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = kexc25519_shared_कुञ्चिका_ext(server_कुञ्चिका, client_pub, buf, 0)) < 0)
		गच्छ बहिर्गमनम्;
#यदि_परिभाषितम् DEBUG_KEXECDH
	dump_digest("server public key 25519:", server_pub, CURVE25519_आकार);
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#यदि_अन्तः
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = रिक्त;
	buf = रिक्त;
 बहिर्गमनम्:
	explicit_bzero(server_कुञ्चिका, परिमाण(server_कुञ्चिका));
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	प्रत्यागम r;
}

पूर्णाङ्क
kex_c25519_dec(संरचना kex *kex, ध्रुव संरचना sshbuf *server_blob,
    संरचना sshbuf **shared_secretp)
{
	संरचना sshbuf *buf = रिक्त;
	ध्रुव u_char *server_pub;
	पूर्णाङ्क r;

	*shared_secretp = रिक्त;

	यदि (sshbuf_len(server_blob) != CURVE25519_आकार) {
		r = SSH_ERR_SIGNATURE_INVALID;
		गच्छ बहिर्गमनम्;
	}
	server_pub = sshbuf_ptr(server_blob);
#यदि_परिभाषितम् DEBUG_KEXECDH
	dump_digest("server public key c25519:", server_pub, CURVE25519_आकार);
#यदि_अन्तः
	/* shared secret */
	यदि ((buf = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = kexc25519_shared_कुञ्चिका_ext(kex->c25519_client_कुञ्चिका, server_pub,
	    buf, 0)) < 0)
		गच्छ बहिर्गमनम्;
#यदि_परिभाषितम् DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#यदि_अन्तः
	*shared_secretp = buf;
	buf = रिक्त;
 बहिर्गमनम्:
	sshbuf_free(buf);
	प्रत्यागम r;
}
