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

#अन्तर्भाव "includes.h"

#define SSHKEY_INTERNAL
#अन्तर्भाव <sys/types.h>

#अन्तर्भाव "crypto_api.h"

#अन्तर्भाव <string.h>
#अन्तर्भाव <stdarg.h>

#अन्तर्भाव "log.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "digest.h"

/* Reuse some ED25519 internals */
बाह्य संरचना sshkey_impl_funcs sshkey_ed25519_funcs;

स्थिर शून्य
ssh_ed25519_sk_cleanup(संरचना sshkey *k)
{
	sshkey_sk_cleanup(k);
	sshkey_ed25519_funcs.cleanup(k);
}

स्थिर पूर्णांक
ssh_ed25519_sk_equal(स्थिरांक संरचना sshkey *a, स्थिरांक संरचना sshkey *b)
{
	जर (!sshkey_sk_fields_equal(a, b))
		परत 0;
	जर (!sshkey_ed25519_funcs.equal(a, b))
		परत 0;
	परत 1;
}

स्थिर पूर्णांक
ssh_ed25519_sk_serialize_public(स्थिरांक संरचना sshkey *किल्ली, संरचना sshbuf *b,
    गणना sshkey_serialize_rep opts)
{
	पूर्णांक r;

	जर ((r = sshkey_ed25519_funcs.serialize_public(किल्ली, b, opts)) != 0)
		परत r;
	जर ((r = sshkey_serialize_sk(किल्ली, b)) != 0)
		परत r;

	परत 0;
}

स्थिर पूर्णांक
ssh_ed25519_sk_serialize_private(स्थिरांक संरचना sshkey *किल्ली, संरचना sshbuf *b,
    गणना sshkey_serialize_rep opts)
{
	पूर्णांक r;

	जर ((r = sshkey_ed25519_funcs.serialize_public(किल्ली, b, opts)) != 0)
		परत r;
	जर ((r = sshkey_serialize_private_sk(किल्ली, b)) != 0)
		परत r;

	परत 0;
}

स्थिर पूर्णांक
ssh_ed25519_sk_copy_public(स्थिरांक संरचना sshkey *from, संरचना sshkey *to)
{
	पूर्णांक r;

	जर ((r = sshkey_ed25519_funcs.copy_public(from, to)) != 0)
		परत r;
	जर ((r = sshkey_copy_public_sk(from, to)) != 0)
		परत r;
	परत 0;
}

स्थिर पूर्णांक
ssh_ed25519_sk_deserialize_public(स्थिरांक अक्षर *ktype, संरचना sshbuf *b,
    संरचना sshkey *किल्ली)
{
	पूर्णांक r;

	जर ((r = sshkey_ed25519_funcs.deserialize_public(ktype, b, किल्ली)) != 0)
		परत r;
	जर ((r = sshkey_deserialize_sk(b, किल्ली)) != 0)
		परत r;
	परत 0;
}

स्थिर पूर्णांक
ssh_ed25519_sk_deserialize_private(स्थिरांक अक्षर *ktype, संरचना sshbuf *b,
    संरचना sshkey *किल्ली)
{
	पूर्णांक r;

	जर ((r = sshkey_ed25519_funcs.deserialize_public(ktype, b, किल्ली)) != 0)
		परत r;
	जर ((r = sshkey_private_deserialize_sk(b, किल्ली)) != 0)
		परत r;
	परत 0;
}

स्थिर पूर्णांक
ssh_ed25519_sk_verify(स्थिरांक संरचना sshkey *किल्ली,
    स्थिरांक u_char *sig, माप_प्रकार siglen,
    स्थिरांक u_char *data, माप_प्रकार dlen, स्थिरांक अक्षर *alg, u_int compat,
    संरचना sshkey_sig_details **detailsp)
{
	संरचना sshbuf *b = रिक्त;
	संरचना sshbuf *encoded = रिक्त;
	अक्षर *ktype = रिक्त;
	स्थिरांक u_char *sigblob;
	u_char apphash[32];
	u_char msghash[32];
	u_char sig_flags;
	u_int sig_counter;
	माप_प्रकार len;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;
	पूर्णांक ret;
	संरचना sshkey_sig_details *details = रिक्त;

	जर (detailsp != रिक्त)
		*detailsp = रिक्त;

	जर (किल्ली == रिक्त ||
	    sshkey_type_plain(किल्ली->type) != किल्ली_ED25519_SK ||
	    किल्ली->ed25519_pk == रिक्त ||
	    sig == रिक्त || siglen == 0)
		परत SSH_ERR_INVALID_ARGUMENT;

	जर ((b = sshbuf_from(sig, siglen)) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;
	जर (sshbuf_get_cstring(b, &ktype, रिक्त) != 0 ||
	    sshbuf_get_string_direct(b, &sigblob, &len) != 0 ||
	    sshbuf_get_u8(b, &sig_flags) != 0 ||
	    sshbuf_get_u32(b, &sig_counter) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		जा out;
	}
#ifdef DEBUG_SK
	ख_लिखो(मानक_त्रुटि, "%s: data:\n", __func__);
	/* sshbuf_dump_data(data, datalen, stderr); */
	ख_लिखो(मानक_त्रुटि, "%s: sigblob:\n", __func__);
	sshbuf_dump_data(sigblob, len, मानक_त्रुटि);
	ख_लिखो(मानक_त्रुटि, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, sig_flags, sig_counter);
#endif
	जर (म_भेद(sshkey_ssh_name_plain(किल्ली), ktype) != 0) {
		r = SSH_ERR_किल्ली_TYPE_MISMATCH;
		जा out;
	}
	जर (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		जा out;
	}
	जर (len != crypto_sign_ed25519_BYTES) {
		r = SSH_ERR_INVALID_FORMAT;
		जा out;
	}
	जर (ssh_digest_memory(SSH_DIGEST_SHA256, किल्ली->sk_application,
	    म_माप(किल्ली->sk_application), apphash, आकार(apphash)) != 0 ||
	    ssh_digest_memory(SSH_DIGEST_SHA256, data, dlen,
	    msghash, आकार(msghash)) != 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		जा out;
	}
#ifdef DEBUG_SK
	ख_लिखो(मानक_त्रुटि, "%s: hashed application:\n", __func__);
	sshbuf_dump_data(apphash, आकार(apphash), मानक_त्रुटि);
	ख_लिखो(मानक_त्रुटि, "%s: hashed message:\n", __func__);
	sshbuf_dump_data(msghash, आकार(msghash), मानक_त्रुटि);
#endif
	जर ((details = सुस्मृति(1, आकार(*details))) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	details->sk_counter = sig_counter;
	details->sk_flags = sig_flags;
	जर ((encoded = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	जर (sshbuf_put(encoded, apphash, आकार(apphash)) != 0 ||
	    sshbuf_put_u8(encoded, sig_flags) != 0 ||
	    sshbuf_put_u32(encoded, sig_counter) != 0 ||
	    sshbuf_put(encoded, msghash, आकार(msghash)) != 0) {
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
#ifdef DEBUG_SK
	ख_लिखो(मानक_त्रुटि, "%s: signed buf:\n", __func__);
	sshbuf_dump(encoded, मानक_त्रुटि);
#endif
	जर ((ret = crypto_sign_ed25519_verify_detached(sigblob,
	    sshbuf_ptr(encoded), sshbuf_len(encoded),
	    किल्ली->ed25519_pk)) != 0) {
		debug2_f("crypto_sign_ed25519_verify_detached failed: %d", ret);
	}
	जर (ret != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		जा out;
	}
	/* success */
	r = 0;
	जर (detailsp != रिक्त) {
		*detailsp = details;
		details = रिक्त;
	}
 out:
	sshkey_sig_details_free(details);
	sshbuf_free(b);
	sshbuf_free(encoded);
	मुक्त(ktype);
	परत r;
}

स्थिर स्थिरांक संरचना sshkey_impl_funcs sshkey_ed25519_sk_funcs = {
	/* .size = */		रिक्त,
	/* .alloc = */		रिक्त,
	/* .cleanup = */	ssh_ed25519_sk_cleanup,
	/* .equal = */		ssh_ed25519_sk_equal,
	/* .ssh_serialize_public = */ ssh_ed25519_sk_serialize_public,
	/* .ssh_deserialize_public = */ ssh_ed25519_sk_deserialize_public,
	/* .ssh_serialize_private = */ ssh_ed25519_sk_serialize_private,
	/* .ssh_deserialize_private = */ ssh_ed25519_sk_deserialize_private,
	/* .generate = */	रिक्त,
	/* .copy_public = */	ssh_ed25519_sk_copy_public,
	/* .sign = */		रिक्त,
	/* .verify = */		ssh_ed25519_sk_verify,
};

स्थिरांक संरचना sshkey_impl sshkey_ed25519_sk_impl = {
	/* .name = */		"sk-ssh-ed25519@openssh.com",
	/* .shortname = */	"ED25519-SK",
	/* .sigalg = */		रिक्त,
	/* .type = */		किल्ली_ED25519_SK,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_sk_funcs,
};

स्थिरांक संरचना sshkey_impl sshkey_ed25519_sk_cert_impl = {
	/* .name = */		"sk-ssh-ed25519-cert-v01@openssh.com",
	/* .shortname = */	"ED25519-SK-CERT",
	/* .sigalg = */		रिक्त,
	/* .type = */		किल्ली_ED25519_SK_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_sk_funcs,
};
