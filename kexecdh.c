/* $OpenBSD: kexecdh.c,v 1.14 2026/08/03 06:43:16 djm Exp $ */
/*
 * Copyright (c) 2010 Damien Miller.  All rights reserved.
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

#अगर defined(WITH_OPENSSL)

#समावेश <sys/types.h>

#समावेश <stdio.h>
#समावेश <signal.h>

#समावेश <openssl/bn.h>
#समावेश <openssl/ecdh.h>

#समावेश "sshkey.h"
#समावेश "kex.h"
#समावेश "sshbuf.h"
#समावेश "ssherr.h"

पूर्णांक
kex_ecdh_keypair(काष्ठा kex *kex)
{
	EC_कुंजी *client_कुंजी = शून्य;
	स्थिर EC_GROUP *group;
	स्थिर EC_POINT *public_कुंजी;
	काष्ठा sshbuf *buf = शून्य;
	पूर्णांक r;

	अगर ((client_कुंजी = EC_कुंजी_new_by_curve_name(kex->ec_nid)) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर (EC_कुंजी_generate_कुंजी(client_कुंजी) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		जाओ out;
	}
	group = EC_कुंजी_get0_group(client_कुंजी);
	public_कुंजी = EC_कुंजी_get0_public_कुंजी(client_कुंजी);

	अगर ((buf = sshbuf_new()) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर ((r = sshbuf_put_ec(buf, public_कुंजी, group)) != 0 ||
	    (r = sshbuf_get_u32(buf, शून्य)) != 0)
		जाओ out;
#अगर_घोषित DEBUG_KEXECDH
	ख_माला_दो("client private key:\n", मानक_त्रुटि);
	sshkey_dump_ec_कुंजी(client_कुंजी);
#पूर्ण_अगर
	kex->ec_client_कुंजी = client_कुंजी;
	kex->ec_group = group;
	client_कुंजी = शून्य;	/* owned by the kex */
	kex->client_pub = buf;
	buf = शून्य;
 out:
	EC_कुंजी_free(client_कुंजी);
	sshbuf_free(buf);
	वापस r;
}

पूर्णांक
kex_ecdh_enc(काष्ठा kex *kex, स्थिर काष्ठा sshbuf *client_blob,
    काष्ठा sshbuf **server_blobp, काष्ठा sshbuf **shared_secretp)
{
	स्थिर EC_GROUP *group;
	स्थिर EC_POINT *pub_कुंजी;
	EC_कुंजी *server_कुंजी = शून्य;
	काष्ठा sshbuf *server_blob = शून्य;
	पूर्णांक r;

	*server_blobp = शून्य;
	*shared_secretp = शून्य;

	अगर ((server_कुंजी = EC_कुंजी_new_by_curve_name(kex->ec_nid)) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर (EC_कुंजी_generate_कुंजी(server_कुंजी) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		जाओ out;
	}
	group = EC_कुंजी_get0_group(server_कुंजी);

#अगर_घोषित DEBUG_KEXECDH
	ख_माला_दो("server private key:\n", मानक_त्रुटि);
	sshkey_dump_ec_कुंजी(server_कुंजी);
#पूर्ण_अगर
	pub_कुंजी = EC_कुंजी_get0_public_कुंजी(server_कुंजी);
	अगर ((server_blob = sshbuf_new()) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर ((r = sshbuf_put_ec(server_blob, pub_कुंजी, group)) != 0 ||
	    (r = sshbuf_get_u32(server_blob, शून्य)) != 0)
		जाओ out;
	अगर ((r = kex_ecdh_dec_कुंजी_group(kex, client_blob, server_कुंजी, group,
	    0, shared_secretp)) != 0)
		जाओ out;
	*server_blobp = server_blob;
	server_blob = शून्य;
 out:
	EC_कुंजी_free(server_कुंजी);
	sshbuf_free(server_blob);
	वापस r;
}

पूर्णांक
kex_ecdh_dec_कुंजी_group(काष्ठा kex *kex, स्थिर काष्ठा sshbuf *ec_blob,
    EC_कुंजी *कुंजी, स्थिर EC_GROUP *group, पूर्णांक raw, काष्ठा sshbuf **shared_secretp)
{
	काष्ठा sshbuf *buf = शून्य;
	BIGNUM *shared_secret = शून्य;
	EC_POINT *dh_pub = शून्य;
	u_char *kbuf = शून्य;
	माप_प्रकार klen = 0;
	पूर्णांक r;

	*shared_secretp = शून्य;

	अगर ((buf = sshbuf_new()) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर ((r = sshbuf_put_stringb(buf, ec_blob)) != 0)
		जाओ out;
	अगर ((dh_pub = EC_POINT_new(group)) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर ((r = sshbuf_get_ec(buf, dh_pub, group)) != 0) {
		जाओ out;
	}
	sshbuf_reset(buf);

#अगर_घोषित DEBUG_KEXECDH
	ख_माला_दो("public key:\n", मानक_त्रुटि);
	sshkey_dump_ec_point(group, dh_pub);
#पूर्ण_अगर
	अगर (sshkey_ec_validate_public(group, dh_pub) != 0) {
		r = SSH_ERR_MESSAGE_INCOMPLETE;
		जाओ out;
	}
	klen = (EC_GROUP_get_degree(group) + 7) / 8;
	अगर ((kbuf = दो_स्मृति(klen)) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर (ECDH_compute_कुंजी(kbuf, klen, dh_pub, कुंजी, शून्य) != (पूर्णांक)klen) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		जाओ out;
	}
#अगर_घोषित DEBUG_KEXECDH
	dump_digest("shared secret", kbuf, klen);
#पूर्ण_अगर
	अगर (raw) {
		अगर ((r = sshbuf_put(buf, kbuf, klen)) != 0)
			जाओ out;
	} अन्यथा {
		अगर ((shared_secret = BN_new()) == शून्य) {
			r = SSH_ERR_ALLOC_FAIL;
			जाओ out;
		}
		अगर (BN_bin2bn(kbuf, klen, shared_secret) == शून्य) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			जाओ out;
		}
		अगर ((r = sshbuf_put_bignum2(buf, shared_secret)) != 0)
			जाओ out;
	}
	*shared_secretp = buf;
	buf = शून्य;
 out:
	EC_POINT_clear_free(dh_pub);
	BN_clear_free(shared_secret);
	freezero(kbuf, klen);
	sshbuf_free(buf);
	वापस r;
}

पूर्णांक
kex_ecdh_dec(काष्ठा kex *kex, स्थिर काष्ठा sshbuf *server_blob,
    काष्ठा sshbuf **shared_secretp)
{
	पूर्णांक r;

	r = kex_ecdh_dec_कुंजी_group(kex, server_blob, kex->ec_client_कुंजी,
	    kex->ec_group, 0, shared_secretp);
	EC_कुंजी_free(kex->ec_client_कुंजी);
	kex->ec_client_कुंजी = शून्य;
	वापस r;
}

#पूर्ण_अगर /* WITH_OPENSSL */
