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

#समावेश "includes.h"

#समावेश <sys/types.h>

#समावेश <stdio.h>
#समावेश <string.h>
#समावेश <signal.h>

#समावेश "sshkey.h"
#समावेश "kex.h"
#समावेश "sshbuf.h"
#समावेश "digest.h"
#समावेश "ssherr.h"
#समावेश "ssh2.h"

बाह्य पूर्णांक crypto_scalarmult_curve25519(u_char a[CURVE25519_आकार],
    स्थिर u_char b[CURVE25519_आकार], स्थिर u_char c[CURVE25519_आकार])
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_आकार)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_आकार)))
	__attribute__((__bounded__(__minbytes__, 3, CURVE25519_आकार)));

व्योम
kexc25519_keygen(u_char कुंजी[CURVE25519_आकार], u_char pub[CURVE25519_आकार])
{
	अटल स्थिर u_char basepoint[CURVE25519_आकार] = {9};

	arc4random_buf(कुंजी, CURVE25519_आकार);
	crypto_scalarmult_curve25519(pub, कुंजी, basepoint);
}

पूर्णांक
kexc25519_shared_कुंजी_ext(स्थिर u_char कुंजी[CURVE25519_आकार],
    स्थिर u_char pub[CURVE25519_आकार], काष्ठा sshbuf *out, पूर्णांक raw)
{
	u_char shared_कुंजी[CURVE25519_आकार];
	u_char zero[CURVE25519_आकार];
	पूर्णांक r;

	crypto_scalarmult_curve25519(shared_कुंजी, कुंजी, pub);

	/* Check for all-zero shared secret */
	explicit_bzero(zero, CURVE25519_आकार);
	अगर (timingsafe_bcmp(zero, shared_कुंजी, CURVE25519_आकार) == 0)
		वापस SSH_ERR_कुंजी_INVALID_EC_मूल्य;

#अगर_घोषित DEBUG_KEXECDH
	dump_digest("shared secret 25519", shared_कुंजी, CURVE25519_आकार);
#पूर्ण_अगर
	अगर (raw)
		r = sshbuf_put(out, shared_कुंजी, CURVE25519_आकार);
	अन्यथा
		r = sshbuf_put_bignum2_bytes(out, shared_कुंजी, CURVE25519_आकार);
	explicit_bzero(shared_कुंजी, CURVE25519_आकार);
	वापस r;
}

पूर्णांक
kexc25519_shared_कुंजी(स्थिर u_char कुंजी[CURVE25519_आकार],
    स्थिर u_char pub[CURVE25519_आकार], काष्ठा sshbuf *out)
{
	वापस kexc25519_shared_कुंजी_ext(कुंजी, pub, out, 0);
}

पूर्णांक
kex_c25519_keypair(काष्ठा kex *kex)
{
	काष्ठा sshbuf *buf = शून्य;
	u_char *cp = शून्य;
	पूर्णांक r;

	अगर ((buf = sshbuf_new()) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर ((r = sshbuf_reserve(buf, CURVE25519_आकार, &cp)) != 0)
		जाओ out;
	kexc25519_keygen(kex->c25519_client_कुंजी, cp);
#अगर_घोषित DEBUG_KEXECDH
	dump_digest("client public key c25519:", cp, CURVE25519_आकार);
#पूर्ण_अगर
	kex->client_pub = buf;
	buf = शून्य;
 out:
	sshbuf_free(buf);
	वापस r;
}

पूर्णांक
kex_c25519_enc(काष्ठा kex *kex, स्थिर काष्ठा sshbuf *client_blob,
   काष्ठा sshbuf **server_blobp, काष्ठा sshbuf **shared_secretp)
{
	काष्ठा sshbuf *server_blob = शून्य;
	काष्ठा sshbuf *buf = शून्य;
	स्थिर u_char *client_pub;
	u_char *server_pub;
	u_char server_कुंजी[CURVE25519_आकार];
	पूर्णांक r;

	*server_blobp = शून्य;
	*shared_secretp = शून्य;

	अगर (sshbuf_len(client_blob) != CURVE25519_आकार) {
		r = SSH_ERR_SIGNATURE_INVALID;
		जाओ out;
	}
	client_pub = sshbuf_ptr(client_blob);
#अगर_घोषित DEBUG_KEXECDH
	dump_digest("client public key 25519:", client_pub, CURVE25519_आकार);
#पूर्ण_अगर
	/* allocate space for encrypted KEM key and ECDH pub key */
	अगर ((server_blob = sshbuf_new()) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर ((r = sshbuf_reserve(server_blob, CURVE25519_आकार, &server_pub)) != 0)
		जाओ out;
	kexc25519_keygen(server_कुंजी, server_pub);
	/* allocate shared secret */
	अगर ((buf = sshbuf_new()) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर ((r = kexc25519_shared_कुंजी_ext(server_कुंजी, client_pub, buf, 0)) < 0)
		जाओ out;
#अगर_घोषित DEBUG_KEXECDH
	dump_digest("server public key 25519:", server_pub, CURVE25519_आकार);
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#पूर्ण_अगर
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = शून्य;
	buf = शून्य;
 out:
	explicit_bzero(server_कुंजी, माप(server_कुंजी));
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	वापस r;
}

पूर्णांक
kex_c25519_dec(काष्ठा kex *kex, स्थिर काष्ठा sshbuf *server_blob,
    काष्ठा sshbuf **shared_secretp)
{
	काष्ठा sshbuf *buf = शून्य;
	स्थिर u_char *server_pub;
	पूर्णांक r;

	*shared_secretp = शून्य;

	अगर (sshbuf_len(server_blob) != CURVE25519_आकार) {
		r = SSH_ERR_SIGNATURE_INVALID;
		जाओ out;
	}
	server_pub = sshbuf_ptr(server_blob);
#अगर_घोषित DEBUG_KEXECDH
	dump_digest("server public key c25519:", server_pub, CURVE25519_आकार);
#पूर्ण_अगर
	/* shared secret */
	अगर ((buf = sshbuf_new()) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर ((r = kexc25519_shared_कुंजी_ext(kex->c25519_client_कुंजी, server_pub,
	    buf, 0)) < 0)
		जाओ out;
#अगर_घोषित DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#पूर्ण_अगर
	*shared_secretp = buf;
	buf = शून्य;
 out:
	sshbuf_free(buf);
	वापस r;
}
