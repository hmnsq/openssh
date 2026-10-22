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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>

#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <signal.h>

#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "kex.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "digest.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "ssh2.h"

બાહ્ય પૂર્ણાંક crypto_scalarmult_curve25519(u_char a[CURVE25519_SIZE],
    અચલ u_char b[CURVE25519_SIZE], અચલ u_char c[CURVE25519_SIZE])
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_SIZE)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_SIZE)))
	__attribute__((__bounded__(__minbytes__, 3, CURVE25519_SIZE)));

શૂન્ય
kexc25519_keygen(u_char ચાવી[CURVE25519_SIZE], u_char pub[CURVE25519_SIZE])
{
	સ્થિર અચલ u_char basepoint[CURVE25519_SIZE] = {9};

	arc4random_buf(ચાવી, CURVE25519_SIZE);
	crypto_scalarmult_curve25519(pub, ચાવી, basepoint);
}

પૂર્ણાંક
kexc25519_shared_ચાવી_ext(અચલ u_char ચાવી[CURVE25519_SIZE],
    અચલ u_char pub[CURVE25519_SIZE], સંરચના sshbuf *out, પૂર્ણાંક raw)
{
	u_char shared_ચાવી[CURVE25519_SIZE];
	u_char zero[CURVE25519_SIZE];
	પૂર્ણાંક r;

	crypto_scalarmult_curve25519(shared_ચાવી, ચાવી, pub);

	/* Check for all-zero shared secret */
	explicit_bzero(zero, CURVE25519_SIZE);
	જો (timingsafe_bcmp(zero, shared_ચાવી, CURVE25519_SIZE) == 0)
		પાછા SSH_ERR_ચાવી_INVALID_EC_કિંમત;

#ifdef DEBUG_KEXECDH
	dump_digest("shared secret 25519", shared_ચાવી, CURVE25519_SIZE);
#endif
	જો (raw)
		r = sshbuf_put(out, shared_ચાવી, CURVE25519_SIZE);
	નહીંતર
		r = sshbuf_put_bignum2_bytes(out, shared_ચાવી, CURVE25519_SIZE);
	explicit_bzero(shared_ચાવી, CURVE25519_SIZE);
	પાછા r;
}

પૂર્ણાંક
kexc25519_shared_ચાવી(અચલ u_char ચાવી[CURVE25519_SIZE],
    અચલ u_char pub[CURVE25519_SIZE], સંરચના sshbuf *out)
{
	પાછા kexc25519_shared_ચાવી_ext(ચાવી, pub, out, 0);
}

પૂર્ણાંક
kex_c25519_keypair(સંરચના kex *kex)
{
	સંરચના sshbuf *buf = ખાલી;
	u_char *cp = ખાલી;
	પૂર્ણાંક r;

	જો ((buf = sshbuf_new()) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો ((r = sshbuf_reserve(buf, CURVE25519_SIZE, &cp)) != 0)
		જાઓ out;
	kexc25519_keygen(kex->c25519_client_ચાવી, cp);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key c25519:", cp, CURVE25519_SIZE);
#endif
	kex->client_pub = buf;
	buf = ખાલી;
 out:
	sshbuf_free(buf);
	પાછા r;
}

પૂર્ણાંક
kex_c25519_enc(સંરચના kex *kex, અચલ સંરચના sshbuf *client_blob,
   સંરચના sshbuf **server_blobp, સંરચના sshbuf **shared_secretp)
{
	સંરચના sshbuf *server_blob = ખાલી;
	સંરચના sshbuf *buf = ખાલી;
	અચલ u_char *client_pub;
	u_char *server_pub;
	u_char server_ચાવી[CURVE25519_SIZE];
	પૂર્ણાંક r;

	*server_blobp = ખાલી;
	*shared_secretp = ખાલી;

	જો (sshbuf_len(client_blob) != CURVE25519_SIZE) {
		r = SSH_ERR_SIGNATURE_INVALID;
		જાઓ out;
	}
	client_pub = sshbuf_ptr(client_blob);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key 25519:", client_pub, CURVE25519_SIZE);
#endif
	/* allocate space for encrypted KEM key and ECDH pub key */
	જો ((server_blob = sshbuf_new()) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો ((r = sshbuf_reserve(server_blob, CURVE25519_SIZE, &server_pub)) != 0)
		જાઓ out;
	kexc25519_keygen(server_ચાવી, server_pub);
	/* allocate shared secret */
	જો ((buf = sshbuf_new()) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો ((r = kexc25519_shared_ચાવી_ext(server_ચાવી, client_pub, buf, 0)) < 0)
		જાઓ out;
#ifdef DEBUG_KEXECDH
	dump_digest("server public key 25519:", server_pub, CURVE25519_SIZE);
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = ખાલી;
	buf = ખાલી;
 out:
	explicit_bzero(server_ચાવી, કદ(server_ચાવી));
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	પાછા r;
}

પૂર્ણાંક
kex_c25519_dec(સંરચના kex *kex, અચલ સંરચના sshbuf *server_blob,
    સંરચના sshbuf **shared_secretp)
{
	સંરચના sshbuf *buf = ખાલી;
	અચલ u_char *server_pub;
	પૂર્ણાંક r;

	*shared_secretp = ખાલી;

	જો (sshbuf_len(server_blob) != CURVE25519_SIZE) {
		r = SSH_ERR_SIGNATURE_INVALID;
		જાઓ out;
	}
	server_pub = sshbuf_ptr(server_blob);
#ifdef DEBUG_KEXECDH
	dump_digest("server public key c25519:", server_pub, CURVE25519_SIZE);
#endif
	/* shared secret */
	જો ((buf = sshbuf_new()) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો ((r = kexc25519_shared_ચાવી_ext(kex->c25519_client_ચાવી, server_pub,
	    buf, 0)) < 0)
		જાઓ out;
#ifdef DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	*shared_secretp = buf;
	buf = ખાલી;
 out:
	sshbuf_free(buf);
	પાછા r;
}
