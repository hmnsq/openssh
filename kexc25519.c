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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>

#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <signal.h>

#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "kex.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "digest.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "ssh2.h"

ബാഹ്യ പൂർണ്ണസംഖ്യ crypto_scalarmult_curve25519(u_char a[CURVE25519_SIZE],
    സ്ഥിരം u_char b[CURVE25519_SIZE], സ്ഥിരം u_char c[CURVE25519_SIZE])
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_SIZE)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_SIZE)))
	__attribute__((__bounded__(__minbytes__, 3, CURVE25519_SIZE)));

ശൂന്യം
kexc25519_keygen(u_char താക്കോൽ[CURVE25519_SIZE], u_char pub[CURVE25519_SIZE])
{
	സ്ഥിതം സ്ഥിരം u_char basepoint[CURVE25519_SIZE] = {9};

	arc4random_buf(താക്കോൽ, CURVE25519_SIZE);
	crypto_scalarmult_curve25519(pub, താക്കോൽ, basepoint);
}

പൂർണ്ണസംഖ്യ
kexc25519_shared_താക്കോൽ_ext(സ്ഥിരം u_char താക്കോൽ[CURVE25519_SIZE],
    സ്ഥിരം u_char pub[CURVE25519_SIZE], ഘടന sshbuf *out, പൂർണ്ണസംഖ്യ raw)
{
	u_char shared_താക്കോൽ[CURVE25519_SIZE];
	u_char zero[CURVE25519_SIZE];
	പൂർണ്ണസംഖ്യ r;

	crypto_scalarmult_curve25519(shared_താക്കോൽ, താക്കോൽ, pub);

	/* Check for all-zero shared secret */
	explicit_bzero(zero, CURVE25519_SIZE);
	എങ്കിൽ (timingsafe_bcmp(zero, shared_താക്കോൽ, CURVE25519_SIZE) == 0)
		തിരികെ SSH_ERR_താക്കോൽ_INVALID_EC_മൂല്യം;

#ifdef DEBUG_KEXECDH
	dump_digest("shared secret 25519", shared_താക്കോൽ, CURVE25519_SIZE);
#endif
	എങ്കിൽ (raw)
		r = sshbuf_put(out, shared_താക്കോൽ, CURVE25519_SIZE);
	അല്ലെങ്കിൽ
		r = sshbuf_put_bignum2_bytes(out, shared_താക്കോൽ, CURVE25519_SIZE);
	explicit_bzero(shared_താക്കോൽ, CURVE25519_SIZE);
	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
kexc25519_shared_താക്കോൽ(സ്ഥിരം u_char താക്കോൽ[CURVE25519_SIZE],
    സ്ഥിരം u_char pub[CURVE25519_SIZE], ഘടന sshbuf *out)
{
	തിരികെ kexc25519_shared_താക്കോൽ_ext(താക്കോൽ, pub, out, 0);
}

പൂർണ്ണസംഖ്യ
kex_c25519_keypair(ഘടന kex *kex)
{
	ഘടന sshbuf *buf = ശൂന്യ;
	u_char *cp = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((buf = sshbuf_new()) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	എങ്കിൽ ((r = sshbuf_reserve(buf, CURVE25519_SIZE, &cp)) != 0)
		പോകുക out;
	kexc25519_keygen(kex->c25519_client_താക്കോൽ, cp);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key c25519:", cp, CURVE25519_SIZE);
#endif
	kex->client_pub = buf;
	buf = ശൂന്യ;
 out:
	sshbuf_free(buf);
	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
kex_c25519_enc(ഘടന kex *kex, സ്ഥിരം ഘടന sshbuf *client_blob,
   ഘടന sshbuf **server_blobp, ഘടന sshbuf **shared_secretp)
{
	ഘടന sshbuf *server_blob = ശൂന്യ;
	ഘടന sshbuf *buf = ശൂന്യ;
	സ്ഥിരം u_char *client_pub;
	u_char *server_pub;
	u_char server_താക്കോൽ[CURVE25519_SIZE];
	പൂർണ്ണസംഖ്യ r;

	*server_blobp = ശൂന്യ;
	*shared_secretp = ശൂന്യ;

	എങ്കിൽ (sshbuf_len(client_blob) != CURVE25519_SIZE) {
		r = SSH_ERR_SIGNATURE_INVALID;
		പോകുക out;
	}
	client_pub = sshbuf_ptr(client_blob);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key 25519:", client_pub, CURVE25519_SIZE);
#endif
	/* allocate space for encrypted KEM key and ECDH pub key */
	എങ്കിൽ ((server_blob = sshbuf_new()) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ ((r = sshbuf_reserve(server_blob, CURVE25519_SIZE, &server_pub)) != 0)
		പോകുക out;
	kexc25519_keygen(server_താക്കോൽ, server_pub);
	/* allocate shared secret */
	എങ്കിൽ ((buf = sshbuf_new()) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ ((r = kexc25519_shared_താക്കോൽ_ext(server_താക്കോൽ, client_pub, buf, 0)) < 0)
		പോകുക out;
#ifdef DEBUG_KEXECDH
	dump_digest("server public key 25519:", server_pub, CURVE25519_SIZE);
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = ശൂന്യ;
	buf = ശൂന്യ;
 out:
	explicit_bzero(server_താക്കോൽ, വലുപ്പം(server_താക്കോൽ));
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
kex_c25519_dec(ഘടന kex *kex, സ്ഥിരം ഘടന sshbuf *server_blob,
    ഘടന sshbuf **shared_secretp)
{
	ഘടന sshbuf *buf = ശൂന്യ;
	സ്ഥിരം u_char *server_pub;
	പൂർണ്ണസംഖ്യ r;

	*shared_secretp = ശൂന്യ;

	എങ്കിൽ (sshbuf_len(server_blob) != CURVE25519_SIZE) {
		r = SSH_ERR_SIGNATURE_INVALID;
		പോകുക out;
	}
	server_pub = sshbuf_ptr(server_blob);
#ifdef DEBUG_KEXECDH
	dump_digest("server public key c25519:", server_pub, CURVE25519_SIZE);
#endif
	/* shared secret */
	എങ്കിൽ ((buf = sshbuf_new()) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ ((r = kexc25519_shared_താക്കോൽ_ext(kex->c25519_client_താക്കോൽ, server_pub,
	    buf, 0)) < 0)
		പോകുക out;
#ifdef DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	*shared_secretp = buf;
	buf = ശൂന്യ;
 out:
	sshbuf_free(buf);
	തിരികെ r;
}
