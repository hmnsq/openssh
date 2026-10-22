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

#അന്തര്ഭാവ "includes.h"

#ifdef WITH_OPENSSL
#അന്തര്ഭാവ "openbsd-compat/openssl-compat.h"

#അന്തര്ഭാവ <sys/types.h>

#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <signal.h>

#അന്തര്ഭാവ <openssl/bn.h>
#അന്തര്ഭാവ <openssl/dh.h>

#അന്തര്ഭാവ "kex.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "dh.h"
#അന്തര്ഭാവ "log.h"

പൂർണ്ണസംഖ്യ
kex_dh_keygen(ഘടന kex *kex)
{
	തിരഞ്ഞെടുപ്പ് (kex->kex_type) {
	അവസ്ഥ KEX_DH_GRP1_SHA1:
		kex->dh = dh_new_group1();
		നിർത്തുക;
	അവസ്ഥ KEX_DH_GRP14_SHA1:
	അവസ്ഥ KEX_DH_GRP14_SHA256:
		kex->dh = dh_new_group14();
		നിർത്തുക;
	അവസ്ഥ KEX_DH_GRP16_SHA512:
		kex->dh = dh_new_group16();
		നിർത്തുക;
	അവസ്ഥ KEX_DH_GRP18_SHA512:
		kex->dh = dh_new_group18();
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	}
	എങ്കിൽ (kex->dh == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	തിരികെ (dh_gen_താക്കോൽ(kex->dh, kex->we_need * 8));
}

പൂർണ്ണസംഖ്യ
kex_dh_compute_താക്കോൽ(ഘടന kex *kex, BIGNUM *dh_pub, ഘടന sshbuf *out)
{
	BIGNUM *shared_secret = ശൂന്യ;
	u_char *kbuf = ശൂന്യ;
	size_t klen = 0;
	പൂർണ്ണസംഖ്യ kout, r;

#ifdef DEBUG_KEXDH
	fprintf(stderr, "dh_pub= ");
	BN_print_fp(stderr, dh_pub);
	fprintf(stderr, "\n");
	debug("bits %d", BN_അക്കം_bits(dh_pub));
	DHparams_print_fp(stderr, kex->dh);
	fprintf(stderr, "\n");
#endif

	എങ്കിൽ (!dh_pub_is_valid(kex->dh, dh_pub)) {
		r = SSH_ERR_MESSAGE_INCOMPLETE;
		പോകുക out;
	}
	klen = DH_size(kex->dh);
	എങ്കിൽ ((kbuf = malloc(klen)) == ശൂന്യ ||
	    (shared_secret = BN_new()) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ ((kout = DH_compute_താക്കോൽ(kbuf, dh_pub, kex->dh)) < 0 ||
	    BN_bin2bn(kbuf, kout, shared_secret) == ശൂന്യ) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		പോകുക out;
	}
#ifdef DEBUG_KEXDH
	dump_digest("shared secret", kbuf, kout);
#endif
	r = sshbuf_put_bignum2(out, shared_secret);
 out:
	freezero(kbuf, klen);
	BN_clear_free(shared_secret);
	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
kex_dh_keypair(ഘടന kex *kex)
{
	സ്ഥിരം BIGNUM *pub_താക്കോൽ;
	ഘടന sshbuf *buf = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = kex_dh_keygen(kex)) != 0)
		തിരികെ r;
	DH_get0_താക്കോൽ(kex->dh, &pub_താക്കോൽ, ശൂന്യ);
	എങ്കിൽ ((buf = sshbuf_new()) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	എങ്കിൽ ((r = sshbuf_put_bignum2(buf, pub_താക്കോൽ)) != 0 ||
	    (r = sshbuf_get_u32(buf, ശൂന്യ)) != 0)
		പോകുക out;
#ifdef DEBUG_KEXDH
	DHparams_print_fp(stderr, kex->dh);
	fprintf(stderr, "pub= ");
	BN_print_fp(stderr, pub_താക്കോൽ);
	fprintf(stderr, "\n");
#endif
	kex->client_pub = buf;
	buf = ശൂന്യ;
 out:
	sshbuf_free(buf);
	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
kex_dh_enc(ഘടന kex *kex, സ്ഥിരം ഘടന sshbuf *client_blob,
    ഘടന sshbuf **server_blobp, ഘടന sshbuf **shared_secretp)
{
	സ്ഥിരം BIGNUM *pub_താക്കോൽ;
	ഘടന sshbuf *server_blob = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r;

	*server_blobp = ശൂന്യ;
	*shared_secretp = ശൂന്യ;

	എങ്കിൽ ((r = kex_dh_keygen(kex)) != 0)
		പോകുക out;
	DH_get0_താക്കോൽ(kex->dh, &pub_താക്കോൽ, ശൂന്യ);
	എങ്കിൽ ((server_blob = sshbuf_new()) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ ((r = sshbuf_put_bignum2(server_blob, pub_താക്കോൽ)) != 0 ||
	    (r = sshbuf_get_u32(server_blob, ശൂന്യ)) != 0)
		പോകുക out;
	എങ്കിൽ ((r = kex_dh_dec(kex, client_blob, shared_secretp)) != 0)
		പോകുക out;
	*server_blobp = server_blob;
	server_blob = ശൂന്യ;
 out:
	DH_free(kex->dh);
	kex->dh = ശൂന്യ;
	sshbuf_free(server_blob);
	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
kex_dh_dec(ഘടന kex *kex, സ്ഥിരം ഘടന sshbuf *dh_blob,
    ഘടന sshbuf **shared_secretp)
{
	ഘടന sshbuf *buf = ശൂന്യ;
	BIGNUM *dh_pub = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r;

	*shared_secretp = ശൂന്യ;

	എങ്കിൽ ((buf = sshbuf_new()) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ ((r = sshbuf_put_stringb(buf, dh_blob)) != 0 ||
	    (r = sshbuf_get_bignum2(buf, &dh_pub)) != 0)
		പോകുക out;
	sshbuf_reset(buf);
	എങ്കിൽ ((r = kex_dh_compute_താക്കോൽ(kex, dh_pub, buf)) != 0)
		പോകുക out;
	*shared_secretp = buf;
	buf = ശൂന്യ;
 out:
	BN_free(dh_pub);
	DH_free(kex->dh);
	kex->dh = ശൂന്യ;
	sshbuf_free(buf);
	തിരികെ r;
}
#endif /* WITH_OPENSSL */
