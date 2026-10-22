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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <limits.h>

#समावेश "crypto_api.h"

#समावेश <string.h>
#समावेश <stdarg.h>

#समावेश "log.h"
#समावेश "sshbuf.h"
#घोषणा SSHKEY_INTERNAL
#समावेश "sshkey.h"
#समावेश "ssherr.h"

अटल व्योम
ssh_ed25519_cleanup(काष्ठा sshkey *k)
{
	freezero(k->ed25519_pk, ED25519_PK_SZ);
	freezero(k->ed25519_sk, ED25519_SK_SZ);
	k->ed25519_pk = शून्य;
	k->ed25519_sk = शून्य;
}

अटल पूर्णांक
ssh_ed25519_equal(स्थिर काष्ठा sshkey *a, स्थिर काष्ठा sshkey *b)
{
	अगर (a->ed25519_pk == शून्य || b->ed25519_pk == शून्य)
		वापस 0;
	अगर (स_भेद(a->ed25519_pk, b->ed25519_pk, ED25519_PK_SZ) != 0)
		वापस 0;
	वापस 1;
}

अटल पूर्णांक
ssh_ed25519_serialize_public(स्थिर काष्ठा sshkey *कुंजी, काष्ठा sshbuf *b,
    क्रमागत sshkey_serialize_rep opts)
{
	पूर्णांक r;

	अगर (कुंजी->ed25519_pk == शून्य)
		वापस SSH_ERR_INVALID_ARGUMENT;
	अगर ((r = sshbuf_put_string(b, कुंजी->ed25519_pk, ED25519_PK_SZ)) != 0)
		वापस r;

	वापस 0;
}

अटल पूर्णांक
ssh_ed25519_serialize_private(स्थिर काष्ठा sshkey *कुंजी, काष्ठा sshbuf *b,
    क्रमागत sshkey_serialize_rep opts)
{
	पूर्णांक r;

	अगर ((r = sshbuf_put_string(b, कुंजी->ed25519_pk, ED25519_PK_SZ)) != 0 ||
	    (r = sshbuf_put_string(b, कुंजी->ed25519_sk, ED25519_SK_SZ)) != 0)
		वापस r;

	वापस 0;
}

अटल पूर्णांक
ssh_ed25519_generate(काष्ठा sshkey *k, पूर्णांक bits)
{
	अगर ((k->ed25519_pk = दो_स्मृति(ED25519_PK_SZ)) == शून्य ||
	    (k->ed25519_sk = दो_स्मृति(ED25519_SK_SZ)) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर (crypto_sign_ed25519_keypair(k->ed25519_pk, k->ed25519_sk) != 0)
		वापस SSH_ERR_CRYPTO_ERROR;
	वापस 0;
}

अटल पूर्णांक
ssh_ed25519_copy_public(स्थिर काष्ठा sshkey *from, काष्ठा sshkey *to)
{
	अगर (from->ed25519_pk == शून्य)
		वापस 0; /* XXX SSH_ERR_INTERNAL_ERROR ? */
	अगर ((to->ed25519_pk = दो_स्मृति(ED25519_PK_SZ)) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	स_नकल(to->ed25519_pk, from->ed25519_pk, ED25519_PK_SZ);
	वापस 0;
}

अटल पूर्णांक
ssh_ed25519_deserialize_public(स्थिर अक्षर *ktype, काष्ठा sshbuf *b,
    काष्ठा sshkey *कुंजी)
{
	u_char *pk = शून्य;
	माप_प्रकार len = 0;
	पूर्णांक r;

	अगर ((r = sshbuf_get_string(b, &pk, &len)) != 0)
		वापस r;
	अगर (len != ED25519_PK_SZ) {
		freezero(pk, len);
		वापस SSH_ERR_INVALID_FORMAT;
	}
	कुंजी->ed25519_pk = pk;
	वापस 0;
}

अटल पूर्णांक
ssh_ed25519_deserialize_private(स्थिर अक्षर *ktype, काष्ठा sshbuf *b,
    काष्ठा sshkey *कुंजी)
{
	पूर्णांक r;
	माप_प्रकार sklen = 0;
	u_char *ed25519_sk = शून्य;

	अगर ((r = ssh_ed25519_deserialize_public(शून्य, b, कुंजी)) != 0)
		जाओ out;
	अगर ((r = sshbuf_get_string(b, &ed25519_sk, &sklen)) != 0)
		जाओ out;
	अगर (sklen != ED25519_SK_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	कुंजी->ed25519_sk = ed25519_sk;
	ed25519_sk = शून्य; /* transferred */
	/* success */
	r = 0;
 out:
	freezero(ed25519_sk, sklen);
	वापस r;
}

अटल पूर्णांक
ssh_ed25519_sign(काष्ठा sshkey *कुंजी,
    u_char **sigp, माप_प्रकार *lenp,
    स्थिर u_char *तथ्य, माप_प्रकार datalen,
    स्थिर अक्षर *alg, स्थिर अक्षर *sk_provider, स्थिर अक्षर *sk_pin, u_int compat)
{
	u_char sig[crypto_sign_ed25519_BYTES];
	अचिन्हित दीर्घ दीर्घ siglen = 0;
	पूर्णांक r, ret;

	अगर (lenp != शून्य)
		*lenp = 0;
	अगर (sigp != शून्य)
		*sigp = शून्य;

	अगर (कुंजी == शून्य ||
	    sshkey_type_plain(कुंजी->type) != कुंजी_ED25519 ||
	    कुंजी->ed25519_sk == शून्य)
		वापस SSH_ERR_INVALID_ARGUMENT;

	अगर ((ret = crypto_sign_ed25519_detached(sig, &siglen, तथ्य, datalen,
	    कुंजी->ed25519_sk)) != 0 || siglen != माप(sig)) {
		r = SSH_ERR_INVALID_ARGUMENT; /* XXX better error? */
		जाओ out;
	}
	अगर ((r = ssh_ed25519_encode_store_sig(sig, siglen,
	    sigp, lenp)) != 0)
		जाओ out;

	/* success */
	r = 0;
 out:
	explicit_bzero(sig, माप(sig));
	वापस r;
}

पूर्णांक
ssh_ed25519_encode_store_sig(स्थिर u_char *sig, माप_प्रकार slen,
    u_char **sigp, माप_प्रकार *lenp)
{
	काष्ठा sshbuf *b = शून्य;
	पूर्णांक r = -1;
	माप_प्रकार len;

	अगर (lenp != शून्य)
		*lenp = 0;
	अगर (sigp != शून्य)
		*sigp = शून्य;

	अगर (slen != crypto_sign_ed25519_BYTES)
		वापस SSH_ERR_INVALID_ARGUMENT;

	/* encode signature */
	अगर ((b = sshbuf_new()) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर ((r = sshbuf_put_cstring(b, "ssh-ed25519")) != 0 ||
	    (r = sshbuf_put_string(b, sig, slen)) != 0)
		जाओ out;
	len = sshbuf_len(b);
	अगर (sigp != शून्य) {
		अगर ((*sigp = दो_स्मृति(len)) == शून्य) {
			r = SSH_ERR_ALLOC_FAIL;
			जाओ out;
		}
		स_नकल(*sigp, sshbuf_ptr(b), len);
	}
	अगर (lenp != शून्य)
		*lenp = len;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	वापस r;
}

अटल पूर्णांक
ssh_ed25519_verify(स्थिर काष्ठा sshkey *कुंजी,
    स्थिर u_char *sig, माप_प्रकार siglen,
    स्थिर u_char *तथ्य, माप_प्रकार dlen, स्थिर अक्षर *alg, u_int compat,
    काष्ठा sshkey_sig_details **detailsp)
{
	काष्ठा sshbuf *b = शून्य;
	अक्षर *ktype = शून्य;
	स्थिर u_char *sigblob;
	माप_प्रकार len;
	पूर्णांक r, ret;

	अगर (कुंजी == शून्य ||
	    sshkey_type_plain(कुंजी->type) != कुंजी_ED25519 ||
	    कुंजी->ed25519_pk == शून्य ||
	    sig == शून्य || siglen == 0)
		वापस SSH_ERR_INVALID_ARGUMENT;

	अगर ((b = sshbuf_from(sig, siglen)) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर ((r = sshbuf_get_cstring(b, &ktype, शून्य)) != 0 ||
	    (r = sshbuf_get_string_direct(b, &sigblob, &len)) != 0)
		जाओ out;
	अगर (म_भेद("ssh-ed25519", ktype) != 0) {
		r = SSH_ERR_कुंजी_TYPE_MISMATCH;
		जाओ out;
	}
	अगर (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_तथ्य;
		जाओ out;
	}
	अगर (len != crypto_sign_ed25519_BYTES) {
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	अगर ((ret = crypto_sign_ed25519_verify_detached(sigblob, तथ्य, dlen,
	    कुंजी->ed25519_pk)) != 0) {
		debug2_f("crypto_sign_ed25519_verify_detached failed: %d", ret);
	}
	अगर (ret != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		जाओ out;
	}
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	मुक्त(ktype);
	वापस r;
}

/* NB. not static; used by ED25519-SK */
स्थिर काष्ठा sshkey_impl_funcs sshkey_ed25519_funcs = {
	/* .size = */		शून्य,
	/* .alloc = */		शून्य,
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

स्थिर काष्ठा sshkey_impl sshkey_ed25519_impl = {
	/* .name = */		"ssh-ed25519",
	/* .shortname = */	"ED25519",
	/* .sigalg = */		शून्य,
	/* .type = */		कुंजी_ED25519,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_funcs,
};

स्थिर काष्ठा sshkey_impl sshkey_ed25519_cert_impl = {
	/* .name = */		"ssh-ed25519-cert-v01@openssh.com",
	/* .shortname = */	"ED25519-CERT",
	/* .sigalg = */		शून्य,
	/* .type = */		कुंजी_ED25519_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_funcs,
};
