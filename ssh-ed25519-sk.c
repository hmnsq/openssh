/* $OpenBSD: ssh-ed25519-sk.c,v 1.17 2026/09/16 00:43:00 djm Exp $ */
/*
 * Copyright (c) 2019 Markus Friedl.  All rights reserved.
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

/* #define DEBUG_SK 1 */

#समावेश "includes.h"

#घोषणा SSHKEY_INTERNAL
#समावेश <sys/types.h>

#समावेश "crypto_api.h"

#समावेश <string.h>
#समावेश <stdarg.h>

#समावेश "log.h"
#समावेश "sshbuf.h"
#समावेश "sshkey.h"
#समावेश "ssherr.h"
#समावेश "digest.h"

/* Reuse some ED25519 internals */
बाह्य काष्ठा sshkey_impl_funcs sshkey_ed25519_funcs;

अटल व्योम
ssh_ed25519_sk_cleanup(काष्ठा sshkey *k)
{
	sshkey_sk_cleanup(k);
	sshkey_ed25519_funcs.cleanup(k);
}

अटल पूर्णांक
ssh_ed25519_sk_equal(स्थिर काष्ठा sshkey *a, स्थिर काष्ठा sshkey *b)
{
	अगर (!sshkey_sk_fields_equal(a, b))
		वापस 0;
	अगर (!sshkey_ed25519_funcs.equal(a, b))
		वापस 0;
	वापस 1;
}

अटल पूर्णांक
ssh_ed25519_sk_serialize_public(स्थिर काष्ठा sshkey *कुंजी, काष्ठा sshbuf *b,
    क्रमागत sshkey_serialize_rep opts)
{
	पूर्णांक r;

	अगर ((r = sshkey_ed25519_funcs.serialize_public(कुंजी, b, opts)) != 0)
		वापस r;
	अगर ((r = sshkey_serialize_sk(कुंजी, b)) != 0)
		वापस r;

	वापस 0;
}

अटल पूर्णांक
ssh_ed25519_sk_serialize_private(स्थिर काष्ठा sshkey *कुंजी, काष्ठा sshbuf *b,
    क्रमागत sshkey_serialize_rep opts)
{
	पूर्णांक r;

	अगर ((r = sshkey_ed25519_funcs.serialize_public(कुंजी, b, opts)) != 0)
		वापस r;
	अगर ((r = sshkey_serialize_private_sk(कुंजी, b)) != 0)
		वापस r;

	वापस 0;
}

अटल पूर्णांक
ssh_ed25519_sk_copy_public(स्थिर काष्ठा sshkey *from, काष्ठा sshkey *to)
{
	पूर्णांक r;

	अगर ((r = sshkey_ed25519_funcs.copy_public(from, to)) != 0)
		वापस r;
	अगर ((r = sshkey_copy_public_sk(from, to)) != 0)
		वापस r;
	वापस 0;
}

अटल पूर्णांक
ssh_ed25519_sk_deserialize_public(स्थिर अक्षर *ktype, काष्ठा sshbuf *b,
    काष्ठा sshkey *कुंजी)
{
	पूर्णांक r;

	अगर ((r = sshkey_ed25519_funcs.deserialize_public(ktype, b, कुंजी)) != 0)
		वापस r;
	अगर ((r = sshkey_deserialize_sk(b, कुंजी)) != 0)
		वापस r;
	वापस 0;
}

अटल पूर्णांक
ssh_ed25519_sk_deserialize_private(स्थिर अक्षर *ktype, काष्ठा sshbuf *b,
    काष्ठा sshkey *कुंजी)
{
	पूर्णांक r;

	अगर ((r = sshkey_ed25519_funcs.deserialize_public(ktype, b, कुंजी)) != 0)
		वापस r;
	अगर ((r = sshkey_private_deserialize_sk(b, कुंजी)) != 0)
		वापस r;
	वापस 0;
}

अटल पूर्णांक
ssh_ed25519_sk_verify(स्थिर काष्ठा sshkey *कुंजी,
    स्थिर u_char *sig, माप_प्रकार siglen,
    स्थिर u_char *तथ्य, माप_प्रकार dlen, स्थिर अक्षर *alg, u_int compat,
    काष्ठा sshkey_sig_details **detailsp)
{
	काष्ठा sshbuf *b = शून्य;
	काष्ठा sshbuf *encoded = शून्य;
	अक्षर *ktype = शून्य;
	स्थिर u_char *sigblob;
	u_char apphash[32];
	u_char msghash[32];
	u_char sig_flags;
	u_int sig_गणक;
	माप_प्रकार len;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;
	पूर्णांक ret;
	काष्ठा sshkey_sig_details *details = शून्य;

	अगर (detailsp != शून्य)
		*detailsp = शून्य;

	अगर (कुंजी == शून्य ||
	    sshkey_type_plain(कुंजी->type) != कुंजी_ED25519_SK ||
	    कुंजी->ed25519_pk == शून्य ||
	    sig == शून्य || siglen == 0)
		वापस SSH_ERR_INVALID_ARGUMENT;

	अगर ((b = sshbuf_from(sig, siglen)) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर (sshbuf_get_cstring(b, &ktype, शून्य) != 0 ||
	    sshbuf_get_string_direct(b, &sigblob, &len) != 0 ||
	    sshbuf_get_u8(b, &sig_flags) != 0 ||
	    sshbuf_get_u32(b, &sig_गणक) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
#अगर_घोषित DEBUG_SK
	ख_लिखो(मानक_त्रुटि, "%s: data:\n", __func__);
	/* sshbuf_dump_data(data, datalen, stderr); */
	ख_लिखो(मानक_त्रुटि, "%s: sigblob:\n", __func__);
	sshbuf_dump_तथ्य(sigblob, len, मानक_त्रुटि);
	ख_लिखो(मानक_त्रुटि, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, sig_flags, sig_गणक);
#पूर्ण_अगर
	अगर (म_भेद(sshkey_ssh_name_plain(कुंजी), ktype) != 0) {
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
	अगर (ssh_digest_memory(SSH_DIGEST_SHA256, कुंजी->sk_application,
	    म_माप(कुंजी->sk_application), apphash, माप(apphash)) != 0 ||
	    ssh_digest_memory(SSH_DIGEST_SHA256, तथ्य, dlen,
	    msghash, माप(msghash)) != 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		जाओ out;
	}
#अगर_घोषित DEBUG_SK
	ख_लिखो(मानक_त्रुटि, "%s: hashed application:\n", __func__);
	sshbuf_dump_तथ्य(apphash, माप(apphash), मानक_त्रुटि);
	ख_लिखो(मानक_त्रुटि, "%s: hashed message:\n", __func__);
	sshbuf_dump_तथ्य(msghash, माप(msghash), मानक_त्रुटि);
#पूर्ण_अगर
	अगर ((details = सुस्मृति(1, माप(*details))) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	details->sk_गणक = sig_गणक;
	details->sk_flags = sig_flags;
	अगर ((encoded = sshbuf_new()) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर (sshbuf_put(encoded, apphash, माप(apphash)) != 0 ||
	    sshbuf_put_u8(encoded, sig_flags) != 0 ||
	    sshbuf_put_u32(encoded, sig_गणक) != 0 ||
	    sshbuf_put(encoded, msghash, माप(msghash)) != 0) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
#अगर_घोषित DEBUG_SK
	ख_लिखो(मानक_त्रुटि, "%s: signed buf:\n", __func__);
	sshbuf_dump(encoded, मानक_त्रुटि);
#पूर्ण_अगर
	अगर ((ret = crypto_sign_ed25519_verify_detached(sigblob,
	    sshbuf_ptr(encoded), sshbuf_len(encoded),
	    कुंजी->ed25519_pk)) != 0) {
		debug2_f("crypto_sign_ed25519_verify_detached failed: %d", ret);
	}
	अगर (ret != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		जाओ out;
	}
	/* success */
	r = 0;
	अगर (detailsp != शून्य) {
		*detailsp = details;
		details = शून्य;
	}
 out:
	sshkey_sig_details_free(details);
	sshbuf_free(b);
	sshbuf_free(encoded);
	मुक्त(ktype);
	वापस r;
}

अटल स्थिर काष्ठा sshkey_impl_funcs sshkey_ed25519_sk_funcs = {
	/* .size = */		शून्य,
	/* .alloc = */		शून्य,
	/* .cleanup = */	ssh_ed25519_sk_cleanup,
	/* .equal = */		ssh_ed25519_sk_equal,
	/* .ssh_serialize_public = */ ssh_ed25519_sk_serialize_public,
	/* .ssh_deserialize_public = */ ssh_ed25519_sk_deserialize_public,
	/* .ssh_serialize_private = */ ssh_ed25519_sk_serialize_private,
	/* .ssh_deserialize_private = */ ssh_ed25519_sk_deserialize_private,
	/* .generate = */	शून्य,
	/* .copy_public = */	ssh_ed25519_sk_copy_public,
	/* .sign = */		शून्य,
	/* .verify = */		ssh_ed25519_sk_verify,
};

स्थिर काष्ठा sshkey_impl sshkey_ed25519_sk_impl = {
	/* .name = */		"sk-ssh-ed25519@openssh.com",
	/* .shortname = */	"ED25519-SK",
	/* .sigalg = */		शून्य,
	/* .type = */		कुंजी_ED25519_SK,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_sk_funcs,
};

स्थिर काष्ठा sshkey_impl sshkey_ed25519_sk_cert_impl = {
	/* .name = */		"sk-ssh-ed25519-cert-v01@openssh.com",
	/* .shortname = */	"ED25519-SK-CERT",
	/* .sigalg = */		शून्य,
	/* .type = */		कुंजी_ED25519_SK_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_sk_funcs,
};
