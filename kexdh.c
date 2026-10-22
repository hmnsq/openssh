/* $OpenBSD: kexdh.c,v 1.36 2026/02/14 00:18:34 jsg Exp $ */
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

#समावेश "includes.h"

#अगर_घोषित WITH_OPENSSL
#समावेश "openbsd-compat/openssl-compat.h"

#समावेश <sys/types.h>

#समावेश <stdio.h>
#समावेश <signal.h>

#समावेश <openssl/bn.h>
#समावेश <openssl/dh.h>

#समावेश "kex.h"
#समावेश "sshbuf.h"
#समावेश "ssherr.h"
#समावेश "dh.h"
#समावेश "log.h"

पूर्णांक
kex_dh_keygen(काष्ठा kex *kex)
{
	चयन (kex->kex_type) {
	हाल KEX_DH_GRP1_SHA1:
		kex->dh = dh_new_group1();
		अवरोध;
	हाल KEX_DH_GRP14_SHA1:
	हाल KEX_DH_GRP14_SHA256:
		kex->dh = dh_new_group14();
		अवरोध;
	हाल KEX_DH_GRP16_SHA512:
		kex->dh = dh_new_group16();
		अवरोध;
	हाल KEX_DH_GRP18_SHA512:
		kex->dh = dh_new_group18();
		अवरोध;
	शेष:
		वापस SSH_ERR_INVALID_ARGUMENT;
	}
	अगर (kex->dh == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	वापस (dh_gen_कुंजी(kex->dh, kex->we_need * 8));
}

पूर्णांक
kex_dh_compute_कुंजी(काष्ठा kex *kex, BIGNUM *dh_pub, काष्ठा sshbuf *out)
{
	BIGNUM *shared_secret = शून्य;
	u_char *kbuf = शून्य;
	माप_प्रकार klen = 0;
	पूर्णांक kout, r;

#अगर_घोषित DEBUG_KEXDH
	ख_लिखो(मानक_त्रुटि, "dh_pub= ");
	BN_print_fp(मानक_त्रुटि, dh_pub);
	ख_लिखो(मानक_त्रुटि, "\n");
	debug("bits %d", BN_अंक_bits(dh_pub));
	DHparams_print_fp(मानक_त्रुटि, kex->dh);
	ख_लिखो(मानक_त्रुटि, "\n");
#पूर्ण_अगर

	अगर (!dh_pub_is_valid(kex->dh, dh_pub)) {
		r = SSH_ERR_MESSAGE_INCOMPLETE;
		जाओ out;
	}
	klen = DH_आकार(kex->dh);
	अगर ((kbuf = दो_स्मृति(klen)) == शून्य ||
	    (shared_secret = BN_new()) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर ((kout = DH_compute_कुंजी(kbuf, dh_pub, kex->dh)) < 0 ||
	    BN_bin2bn(kbuf, kout, shared_secret) == शून्य) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		जाओ out;
	}
#अगर_घोषित DEBUG_KEXDH
	dump_digest("shared secret", kbuf, kout);
#पूर्ण_अगर
	r = sshbuf_put_bignum2(out, shared_secret);
 out:
	freezero(kbuf, klen);
	BN_clear_free(shared_secret);
	वापस r;
}

पूर्णांक
kex_dh_keypair(काष्ठा kex *kex)
{
	स्थिर BIGNUM *pub_कुंजी;
	काष्ठा sshbuf *buf = शून्य;
	पूर्णांक r;

	अगर ((r = kex_dh_keygen(kex)) != 0)
		वापस r;
	DH_get0_कुंजी(kex->dh, &pub_कुंजी, शून्य);
	अगर ((buf = sshbuf_new()) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर ((r = sshbuf_put_bignum2(buf, pub_कुंजी)) != 0 ||
	    (r = sshbuf_get_u32(buf, शून्य)) != 0)
		जाओ out;
#अगर_घोषित DEBUG_KEXDH
	DHparams_print_fp(मानक_त्रुटि, kex->dh);
	ख_लिखो(मानक_त्रुटि, "pub= ");
	BN_print_fp(मानक_त्रुटि, pub_कुंजी);
	ख_लिखो(मानक_त्रुटि, "\n");
#पूर्ण_अगर
	kex->client_pub = buf;
	buf = शून्य;
 out:
	sshbuf_free(buf);
	वापस r;
}

पूर्णांक
kex_dh_enc(काष्ठा kex *kex, स्थिर काष्ठा sshbuf *client_blob,
    काष्ठा sshbuf **server_blobp, काष्ठा sshbuf **shared_secretp)
{
	स्थिर BIGNUM *pub_कुंजी;
	काष्ठा sshbuf *server_blob = शून्य;
	पूर्णांक r;

	*server_blobp = शून्य;
	*shared_secretp = शून्य;

	अगर ((r = kex_dh_keygen(kex)) != 0)
		जाओ out;
	DH_get0_कुंजी(kex->dh, &pub_कुंजी, शून्य);
	अगर ((server_blob = sshbuf_new()) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर ((r = sshbuf_put_bignum2(server_blob, pub_कुंजी)) != 0 ||
	    (r = sshbuf_get_u32(server_blob, शून्य)) != 0)
		जाओ out;
	अगर ((r = kex_dh_dec(kex, client_blob, shared_secretp)) != 0)
		जाओ out;
	*server_blobp = server_blob;
	server_blob = शून्य;
 out:
	DH_free(kex->dh);
	kex->dh = शून्य;
	sshbuf_free(server_blob);
	वापस r;
}

पूर्णांक
kex_dh_dec(काष्ठा kex *kex, स्थिर काष्ठा sshbuf *dh_blob,
    काष्ठा sshbuf **shared_secretp)
{
	काष्ठा sshbuf *buf = शून्य;
	BIGNUM *dh_pub = शून्य;
	पूर्णांक r;

	*shared_secretp = शून्य;

	अगर ((buf = sshbuf_new()) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर ((r = sshbuf_put_stringb(buf, dh_blob)) != 0 ||
	    (r = sshbuf_get_bignum2(buf, &dh_pub)) != 0)
		जाओ out;
	sshbuf_reset(buf);
	अगर ((r = kex_dh_compute_कुंजी(kex, dh_pub, buf)) != 0)
		जाओ out;
	*shared_secretp = buf;
	buf = शून्य;
 out:
	BN_free(dh_pub);
	DH_free(kex->dh);
	kex->dh = शून्य;
	sshbuf_free(buf);
	वापस r;
}
#पूर्ण_अगर /* WITH_OPENSSL */
