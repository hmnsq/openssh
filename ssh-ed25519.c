/* $OpenBSD: ssh-ed25519.c,v 1.24 2026/09/16 00:43:00 djm Exp $ */
/*
 * Copyright (c) 2013 Markus Friedl <markus@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <limits.h>

#অন্তর্ভাব "crypto_api.h"

#অন্তর্ভাব <string.h>
#অন্তর্ভাব <stdarg.h>

#অন্তর্ভাব "log.h"
#অন্তর্ভাব "sshbuf.h"
#define SSHKEY_INTERNAL
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "ssherr.h"

স্থির শূন্য
ssh_ed25519_cleanup(কাঠামো sshkey *k)
{
	freezero(k->ed25519_pk, ED25519_PK_SZ);
	freezero(k->ed25519_sk, ED25519_SK_SZ);
	k->ed25519_pk = ফাঁকা;
	k->ed25519_sk = ফাঁকা;
}

স্থির পূর্ণসংখ্যা
ssh_ed25519_equal(ধ্রুবক কাঠামো sshkey *a, ধ্রুবক কাঠামো sshkey *b)
{
	যদি (a->ed25519_pk == ফাঁকা || b->ed25519_pk == ফাঁকা)
		ফেরত 0;
	যদি (memcmp(a->ed25519_pk, b->ed25519_pk, ED25519_PK_SZ) != 0)
		ফেরত 0;
	ফেরত 1;
}

স্থির পূর্ণসংখ্যা
ssh_ed25519_serialize_public(ধ্রুবক কাঠামো sshkey *চাবি, কাঠামো sshbuf *b,
    গণনা sshkey_serialize_rep opts)
{
	পূর্ণসংখ্যা r;

	যদি (চাবি->ed25519_pk == ফাঁকা)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	যদি ((r = sshbuf_put_string(b, চাবি->ed25519_pk, ED25519_PK_SZ)) != 0)
		ফেরত r;

	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
ssh_ed25519_serialize_private(ধ্রুবক কাঠামো sshkey *চাবি, কাঠামো sshbuf *b,
    গণনা sshkey_serialize_rep opts)
{
	পূর্ণসংখ্যা r;

	যদি ((r = sshbuf_put_string(b, চাবি->ed25519_pk, ED25519_PK_SZ)) != 0 ||
	    (r = sshbuf_put_string(b, চাবি->ed25519_sk, ED25519_SK_SZ)) != 0)
		ফেরত r;

	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
ssh_ed25519_generate(কাঠামো sshkey *k, পূর্ণসংখ্যা bits)
{
	যদি ((k->ed25519_pk = malloc(ED25519_PK_SZ)) == ফাঁকা ||
	    (k->ed25519_sk = malloc(ED25519_SK_SZ)) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	যদি (crypto_sign_ed25519_keypair(k->ed25519_pk, k->ed25519_sk) != 0)
		ফেরত SSH_ERR_CRYPTO_ERROR;
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
ssh_ed25519_copy_public(ধ্রুবক কাঠামো sshkey *from, কাঠামো sshkey *to)
{
	যদি (from->ed25519_pk == ফাঁকা)
		ফেরত 0; /* XXX SSH_ERR_INTERNAL_ERROR ? */
	যদি ((to->ed25519_pk = malloc(ED25519_PK_SZ)) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	memcpy(to->ed25519_pk, from->ed25519_pk, ED25519_PK_SZ);
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
ssh_ed25519_deserialize_public(ধ্রুবক অক্ষর *ktype, কাঠামো sshbuf *b,
    কাঠামো sshkey *চাবি)
{
	u_char *pk = ফাঁকা;
	আকার_t len = 0;
	পূর্ণসংখ্যা r;

	যদি ((r = sshbuf_get_string(b, &pk, &len)) != 0)
		ফেরত r;
	যদি (len != ED25519_PK_SZ) {
		freezero(pk, len);
		ফেরত SSH_ERR_INVALID_FORMAT;
	}
	চাবি->ed25519_pk = pk;
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
ssh_ed25519_deserialize_private(ধ্রুবক অক্ষর *ktype, কাঠামো sshbuf *b,
    কাঠামো sshkey *চাবি)
{
	পূর্ণসংখ্যা r;
	আকার_t sklen = 0;
	u_char *ed25519_sk = ফাঁকা;

	যদি ((r = ssh_ed25519_deserialize_public(ফাঁকা, b, চাবি)) != 0)
		যাও out;
	যদি ((r = sshbuf_get_string(b, &ed25519_sk, &sklen)) != 0)
		যাও out;
	যদি (sklen != ED25519_SK_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	চাবি->ed25519_sk = ed25519_sk;
	ed25519_sk = ফাঁকা; /* transferred */
	/* success */
	r = 0;
 out:
	freezero(ed25519_sk, sklen);
	ফেরত r;
}

স্থির পূর্ণসংখ্যা
ssh_ed25519_sign(কাঠামো sshkey *চাবি,
    u_char **sigp, আকার_t *lenp,
    ধ্রুবক u_char *তথ্য, আকার_t datalen,
    ধ্রুবক অক্ষর *alg, ধ্রুবক অক্ষর *sk_provider, ধ্রুবক অক্ষর *sk_pin, u_int compat)
{
	u_char sig[crypto_sign_ed25519_BYTES];
	unsigned long long siglen = 0;
	পূর্ণসংখ্যা r, ret;

	যদি (lenp != ফাঁকা)
		*lenp = 0;
	যদি (sigp != ফাঁকা)
		*sigp = ফাঁকা;

	যদি (চাবি == ফাঁকা ||
	    sshkey_type_plain(চাবি->type) != চাবি_ED25519 ||
	    চাবি->ed25519_sk == ফাঁকা)
		ফেরত SSH_ERR_INVALID_ARGUMENT;

	যদি ((ret = crypto_sign_ed25519_detached(sig, &siglen, তথ্য, datalen,
	    চাবি->ed25519_sk)) != 0 || siglen != আকার(sig)) {
		r = SSH_ERR_INVALID_ARGUMENT; /* XXX better error? */
		যাও out;
	}
	যদি ((r = ssh_ed25519_encode_store_sig(sig, siglen,
	    sigp, lenp)) != 0)
		যাও out;

	/* success */
	r = 0;
 out:
	explicit_bzero(sig, আকার(sig));
	ফেরত r;
}

পূর্ণসংখ্যা
ssh_ed25519_encode_store_sig(ধ্রুবক u_char *sig, আকার_t slen,
    u_char **sigp, আকার_t *lenp)
{
	কাঠামো sshbuf *b = ফাঁকা;
	পূর্ণসংখ্যা r = -1;
	আকার_t len;

	যদি (lenp != ফাঁকা)
		*lenp = 0;
	যদি (sigp != ফাঁকা)
		*sigp = ফাঁকা;

	যদি (slen != crypto_sign_ed25519_BYTES)
		ফেরত SSH_ERR_INVALID_ARGUMENT;

	/* encode signature */
	যদি ((b = sshbuf_new()) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি ((r = sshbuf_put_cstring(b, "ssh-ed25519")) != 0 ||
	    (r = sshbuf_put_string(b, sig, slen)) != 0)
		যাও out;
	len = sshbuf_len(b);
	যদি (sigp != ফাঁকা) {
		যদি ((*sigp = malloc(len)) == ফাঁকা) {
			r = SSH_ERR_ALLOC_FAIL;
			যাও out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	যদি (lenp != ফাঁকা)
		*lenp = len;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	ফেরত r;
}

স্থির পূর্ণসংখ্যা
ssh_ed25519_verify(ধ্রুবক কাঠামো sshkey *চাবি,
    ধ্রুবক u_char *sig, আকার_t siglen,
    ধ্রুবক u_char *তথ্য, আকার_t dlen, ধ্রুবক অক্ষর *alg, u_int compat,
    কাঠামো sshkey_sig_details **detailsp)
{
	কাঠামো sshbuf *b = ফাঁকা;
	অক্ষর *ktype = ফাঁকা;
	ধ্রুবক u_char *sigblob;
	আকার_t len;
	পূর্ণসংখ্যা r, ret;

	যদি (চাবি == ফাঁকা ||
	    sshkey_type_plain(চাবি->type) != চাবি_ED25519 ||
	    চাবি->ed25519_pk == ফাঁকা ||
	    sig == ফাঁকা || siglen == 0)
		ফেরত SSH_ERR_INVALID_ARGUMENT;

	যদি ((b = sshbuf_from(sig, siglen)) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshbuf_get_cstring(b, &ktype, ফাঁকা)) != 0 ||
	    (r = sshbuf_get_string_direct(b, &sigblob, &len)) != 0)
		যাও out;
	যদি (strcmp("ssh-ed25519", ktype) != 0) {
		r = SSH_ERR_চাবি_TYPE_MISMATCH;
		যাও out;
	}
	যদি (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_তথ্য;
		যাও out;
	}
	যদি (len != crypto_sign_ed25519_BYTES) {
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	যদি ((ret = crypto_sign_ed25519_verify_detached(sigblob, তথ্য, dlen,
	    চাবি->ed25519_pk)) != 0) {
		debug2_f("crypto_sign_ed25519_verify_detached failed: %d", ret);
	}
	যদি (ret != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		যাও out;
	}
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	মুক্ত(ktype);
	ফেরত r;
}

/* NB. not static; used by ED25519-SK */
ধ্রুবক কাঠামো sshkey_impl_funcs sshkey_ed25519_funcs = {
	/* .size = */		ফাঁকা,
	/* .alloc = */		ফাঁকা,
	/* .cleanup = */	ssh_ed25519_cleanup,
	/* .equal = */		ssh_ed25519_equal,
	/* .ssh_serialize_public = */ ssh_ed25519_serialize_public,
	/* .ssh_deserialize_public = */ ssh_ed25519_deserialize_public,
	/* .ssh_serialize_private = */ ssh_ed25519_serialize_private,
	/* .ssh_deserialize_private = */ ssh_ed25519_deserialize_private,
	/* .generate = */	ssh_ed25519_generate,
	/* .copy_public = */	ssh_ed25519_copy_public,
	/* .sign = */		ssh_ed25519_sign,
	/* .verify = */		ssh_ed25519_verify,
};

ধ্রুবক কাঠামো sshkey_impl sshkey_ed25519_impl = {
	/* .name = */		"ssh-ed25519",
	/* .shortname = */	"ED25519",
	/* .sigalg = */		ফাঁকা,
	/* .type = */		চাবি_ED25519,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_funcs,
};

ধ্রুবক কাঠামো sshkey_impl sshkey_ed25519_cert_impl = {
	/* .name = */		"ssh-ed25519-cert-v01@openssh.com",
	/* .shortname = */	"ED25519-CERT",
	/* .sigalg = */		ফাঁকা,
	/* .type = */		চাবি_ED25519_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_funcs,
};
