/* $OpenBSD: kexgex.c,v 1.33 2026/02/14 00:18:34 jsg Exp $ */
/*
 * Copyright (c) 2000 Niels Provos.  All rights reserved.
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
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

#समावेश <sys/types.h>

#समावेश <openssl/evp.h>
#समावेश <signal.h>

#समावेश "openbsd-compat/openssl-compat.h"

#समावेश "sshkey.h"
#समावेश "cipher.h"
#समावेश "kex.h"
#समावेश "ssh2.h"
#समावेश "ssherr.h"
#समावेश "sshbuf.h"
#समावेश "digest.h"

पूर्णांक
kexgex_hash(
    पूर्णांक hash_alg,
    स्थिर काष्ठा sshbuf *client_version,
    स्थिर काष्ठा sshbuf *server_version,
    स्थिर काष्ठा sshbuf *client_kexinit,
    स्थिर काष्ठा sshbuf *server_kexinit,
    स्थिर काष्ठा sshbuf *server_host_कुंजी_blob,
    पूर्णांक min, पूर्णांक wantbits, पूर्णांक max,
    स्थिर BIGNUM *अभाज्य,
    स्थिर BIGNUM *gen,
    स्थिर BIGNUM *client_dh_pub,
    स्थिर BIGNUM *server_dh_pub,
    स्थिर u_char *shared_secret, माप_प्रकार secretlen,
    u_char *hash, माप_प्रकार *hashlen)
{
	काष्ठा sshbuf *b;
	पूर्णांक r;

	अगर (*hashlen < ssh_digest_bytes(SSH_DIGEST_SHA1))
		वापस SSH_ERR_INVALID_ARGUMENT;
	अगर ((b = sshbuf_new()) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर ((r = sshbuf_put_stringb(b, client_version)) < 0 ||
	    (r = sshbuf_put_stringb(b, server_version)) < 0 ||
	    /* kexinit messages: fake header: len+SSH2_MSG_KEXINIT */
	    (r = sshbuf_put_u32(b, sshbuf_len(client_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_संदेश_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, client_kexinit)) != 0 ||
	    (r = sshbuf_put_u32(b, sshbuf_len(server_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_संदेश_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, server_kexinit)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_host_कुंजी_blob)) != 0 ||
	    (min != -1 && (r = sshbuf_put_u32(b, min)) != 0) ||
	    (r = sshbuf_put_u32(b, wantbits)) != 0 ||
	    (max != -1 && (r = sshbuf_put_u32(b, max)) != 0) ||
	    (r = sshbuf_put_bignum2(b, अभाज्य)) != 0 ||
	    (r = sshbuf_put_bignum2(b, gen)) != 0 ||
	    (r = sshbuf_put_bignum2(b, client_dh_pub)) != 0 ||
	    (r = sshbuf_put_bignum2(b, server_dh_pub)) != 0 ||
	    (r = sshbuf_put(b, shared_secret, secretlen)) != 0) {
		sshbuf_free(b);
		वापस r;
	}
#अगर_घोषित DEBUG_KEXDH
	sshbuf_dump(b, मानक_त्रुटि);
#पूर्ण_अगर
	अगर (ssh_digest_बफर(hash_alg, b, hash, *hashlen) != 0) {
		sshbuf_free(b);
		वापस SSH_ERR_LIBCRYPTO_ERROR;
	}
	sshbuf_free(b);
	*hashlen = ssh_digest_bytes(hash_alg);
#अगर_घोषित DEBUG_KEXDH
	dump_digest("hash", hash, *hashlen);
#पूर्ण_अगर
	वापस 0;
}
#पूर्ण_अगर /* WITH_OPENSSL */
