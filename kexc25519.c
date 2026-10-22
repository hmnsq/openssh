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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>

#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <signal.h>

#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "kex.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "digest.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "ssh2.h"

বাহ্য পূর্ণাঙ্ক crypto_scalarmult_curve25519(u_char a[CURVE25519_SIZE],
    ধ্রুব u_char b[CURVE25519_SIZE], ধ্রুব u_char c[CURVE25519_SIZE])
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_SIZE)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_SIZE)))
	__attribute__((__bounded__(__minbytes__, 3, CURVE25519_SIZE)));

শূন্য
kexc25519_keygen(u_char চাবি[CURVE25519_SIZE], u_char pub[CURVE25519_SIZE])
{
	স্থির ধ্রুব u_char basepoint[CURVE25519_SIZE] = {9};

	arc4random_buf(চাবি, CURVE25519_SIZE);
	crypto_scalarmult_curve25519(pub, চাবি, basepoint);
}

পূর্ণাঙ্ক
kexc25519_shared_চাবি_ext(ধ্রুব u_char চাবি[CURVE25519_SIZE],
    ধ্রুব u_char pub[CURVE25519_SIZE], সংরচনা sshbuf *out, পূর্ণাঙ্ক raw)
{
	u_char shared_চাবি[CURVE25519_SIZE];
	u_char zero[CURVE25519_SIZE];
	পূর্ণাঙ্ক r;

	crypto_scalarmult_curve25519(shared_চাবি, চাবি, pub);

	/* Check for all-zero shared secret */
	explicit_bzero(zero, CURVE25519_SIZE);
	যদি (timingsafe_bcmp(zero, shared_চাবি, CURVE25519_SIZE) == 0)
		প্রত্যাগম SSH_ERR_চাবি_INVALID_EC_মান;

#ifdef DEBUG_KEXECDH
	dump_digest("shared secret 25519", shared_চাবি, CURVE25519_SIZE);
#endif
	যদি (raw)
		r = sshbuf_put(out, shared_চাবি, CURVE25519_SIZE);
	অন্যথা
		r = sshbuf_put_bignum2_bytes(out, shared_চাবি, CURVE25519_SIZE);
	explicit_bzero(shared_চাবি, CURVE25519_SIZE);
	প্রত্যাগম r;
}

পূর্ণাঙ্ক
kexc25519_shared_চাবি(ধ্রুব u_char চাবি[CURVE25519_SIZE],
    ধ্রুব u_char pub[CURVE25519_SIZE], সংরচনা sshbuf *out)
{
	প্রত্যাগম kexc25519_shared_চাবি_ext(চাবি, pub, out, 0);
}

পূর্ণাঙ্ক
kex_c25519_keypair(সংরচনা kex *kex)
{
	সংরচনা sshbuf *buf = রিক্ত;
	u_char *cp = রিক্ত;
	পূর্ণাঙ্ক r;

	যদি ((buf = sshbuf_new()) == রিক্ত)
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshbuf_reserve(buf, CURVE25519_SIZE, &cp)) != 0)
		গচ্ছ out;
	kexc25519_keygen(kex->c25519_client_চাবি, cp);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key c25519:", cp, CURVE25519_SIZE);
#endif
	kex->client_pub = buf;
	buf = রিক্ত;
 out:
	sshbuf_free(buf);
	প্রত্যাগম r;
}

পূর্ণাঙ্ক
kex_c25519_enc(সংরচনা kex *kex, ধ্রুব সংরচনা sshbuf *client_blob,
   সংরচনা sshbuf **server_blobp, সংরচনা sshbuf **shared_secretp)
{
	সংরচনা sshbuf *server_blob = রিক্ত;
	সংরচনা sshbuf *buf = রিক্ত;
	ধ্রুব u_char *client_pub;
	u_char *server_pub;
	u_char server_চাবি[CURVE25519_SIZE];
	পূর্ণাঙ্ক r;

	*server_blobp = রিক্ত;
	*shared_secretp = রিক্ত;

	যদি (sshbuf_len(client_blob) != CURVE25519_SIZE) {
		r = SSH_ERR_SIGNATURE_INVALID;
		গচ্ছ out;
	}
	client_pub = sshbuf_ptr(client_blob);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key 25519:", client_pub, CURVE25519_SIZE);
#endif
	/* allocate space for encrypted KEM key and ECDH pub key */
	যদি ((server_blob = sshbuf_new()) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি ((r = sshbuf_reserve(server_blob, CURVE25519_SIZE, &server_pub)) != 0)
		গচ্ছ out;
	kexc25519_keygen(server_চাবি, server_pub);
	/* allocate shared secret */
	যদি ((buf = sshbuf_new()) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি ((r = kexc25519_shared_চাবি_ext(server_চাবি, client_pub, buf, 0)) < 0)
		গচ্ছ out;
#ifdef DEBUG_KEXECDH
	dump_digest("server public key 25519:", server_pub, CURVE25519_SIZE);
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = রিক্ত;
	buf = রিক্ত;
 out:
	explicit_bzero(server_চাবি, পরিমাণ(server_চাবি));
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	প্রত্যাগম r;
}

পূর্ণাঙ্ক
kex_c25519_dec(সংরচনা kex *kex, ধ্রুব সংরচনা sshbuf *server_blob,
    সংরচনা sshbuf **shared_secretp)
{
	সংরচনা sshbuf *buf = রিক্ত;
	ধ্রুব u_char *server_pub;
	পূর্ণাঙ্ক r;

	*shared_secretp = রিক্ত;

	যদি (sshbuf_len(server_blob) != CURVE25519_SIZE) {
		r = SSH_ERR_SIGNATURE_INVALID;
		গচ্ছ out;
	}
	server_pub = sshbuf_ptr(server_blob);
#ifdef DEBUG_KEXECDH
	dump_digest("server public key c25519:", server_pub, CURVE25519_SIZE);
#endif
	/* shared secret */
	যদি ((buf = sshbuf_new()) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি ((r = kexc25519_shared_চাবি_ext(kex->c25519_client_চাবি, server_pub,
	    buf, 0)) < 0)
		গচ্ছ out;
#ifdef DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	*shared_secretp = buf;
	buf = রিক্ত;
 out:
	sshbuf_free(buf);
	প্রত্যাগম r;
}
