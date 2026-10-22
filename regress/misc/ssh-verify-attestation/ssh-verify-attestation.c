/* $OpenBSD: ssh-verify-attestation.c,v 1.4 2026/06/29 07:46:22 djm Exp $ */
/*
 * Copyright (c) 2022-2024 Damien Miller
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

/*
 * This is a small program to verify FIDO attestation objects that
 * ssh-keygen(1) can record when enrolling a FIDO key. It requires that
 * the attestation object and challenge used when creating the key be
 * recorded.
 *
 * Example usage:
 *
 * $ # Generate a random challenge.
 * $ dd if=/dev/urandom of=key_ecdsa_sk.challenge bs=32 count=1
 * $ # Generate a key, record the attestation blob.
 * $ ssh-keygen -f key_ecdsa_sk -t ecdsa-sk \
 *       -Ochallenge=key_ecdsa_sk.challenge \
 *       -Owrite-attestation=key_ecdsa_sk.attest -N ''
 * $ # Validate the challenge (-A = print attestation CA cert)
 * $ ./obj/ssh-verify-attestation -A key_ecdsa_sk key_ecdsa_sk.challenge \
 *       key_ecdsa_sk.attest
 *
 * Limitations/TODO:
 *
 * 1) It doesn't automatically detect the attestation statement format. It
 *    assumes the "packed" format used by FIDO2 keys. If that doesn't work,
 *    then try using the -U option to select the "fido-u2f" format.
 * 2) It makes assumptions about RK, UV, etc status of the key/cred.
 * 3) Probably bugs.
 *
 * Thanks to Markus Friedl and Pedro Martelletto for help getting this
 * working.
 */

#समावेश "includes.h"

#समावेश <stdint.h>
#समावेश <inttypes.h>
#समावेश <stdlib.h>
#समावेश <stdio.h>
#समावेश <unistd.h>
#समावेश <stdarg.h>

#समावेश "xmalloc.h"
#समावेश "log.h"
#समावेश "sshbuf.h"
#समावेश "sshkey.h"
#समावेश "authfile.h"
#समावेश "ssherr.h"
#समावेश "misc.h"
#समावेश "digest.h"
#समावेश "crypto_api.h"

#समावेश <fido.h>
#समावेश <openssl/x509.h>
#समावेश <openssl/x509v3.h>
#समावेश <openssl/bio.h>
#समावेश <openssl/err.h>
#समावेश <openssl/pem.h>
#समावेश "openbsd-compat/openssl-compat.h"

बाह्य अक्षर *__progname;

#घोषणा ATTEST_MAGIC	"ssh-sk-attest-v01"

अटल पूर्णांक
prepare_fido_cred(fido_cred_t *cred, पूर्णांक credtype, स्थिर अक्षर *attfmt,
    स्थिर अक्षर *rp_id, काष्ठा sshbuf *b, स्थिर काष्ठा sshbuf *challenge,
    काष्ठा sshbuf **attestation_certp)
{
	काष्ठा sshbuf *attestation_cert = शून्य, *sig = शून्य, *authdata = शून्य;
	अक्षर *magic = शून्य;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	*attestation_certp = शून्य;

	/* Make sure it's the format we're expecting */
	अगर ((r = sshbuf_get_cstring(b, &magic, शून्य)) != 0) {
		error_fr(r, "parse header");
		जाओ out;
	}
	अगर (म_भेद(magic, ATTEST_MAGIC) != 0) {
		error_f("unsupported format");
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	/* Parse the remaining fields */
	अगर ((r = sshbuf_froms(b, &attestation_cert)) != 0 ||
	    (r = sshbuf_froms(b, &sig)) != 0 ||
	    (r = sshbuf_froms(b, &authdata)) != 0 ||
	    (r = sshbuf_get_u32(b, शून्य)) != 0 || /* reserved flags */
	    (r = sshbuf_get_string_direct(b, शून्य, शून्य)) != 0) { /* reserved */
		error_fr(r, "parse body");
		जाओ out;
	}
	debug3_f("attestation cert len=%zu, sig len=%zu, "
	    "authdata len=%zu challenge len=%zu", sshbuf_len(attestation_cert),
	    sshbuf_len(sig), sshbuf_len(authdata), sshbuf_len(challenge));

	fido_cred_set_type(cred, credtype);
	fido_cred_set_fmt(cred, attfmt);
	fido_cred_set_clientdata(cred, sshbuf_ptr(challenge),
	    sshbuf_len(challenge));
	fido_cred_set_rp(cred, rp_id, शून्य);
	fido_cred_set_authdata(cred, sshbuf_ptr(authdata),
	    sshbuf_len(authdata));
	/* XXX set_extensions, set_rk, set_uv */
	fido_cred_set_x509(cred, sshbuf_ptr(attestation_cert),
	    sshbuf_len(attestation_cert));
	fido_cred_set_sig(cred, sshbuf_ptr(sig), sshbuf_len(sig));

	/* success */
	*attestation_certp = attestation_cert;
	attestation_cert = शून्य;
	r = 0;
 out:
	मुक्त(magic);
	sshbuf_free(attestation_cert);
	sshbuf_free(sig);
	sshbuf_free(authdata);
	वापस r;
}

अटल uint8_t *
get_pubkey_from_cred_ecdsa(स्थिर fido_cred_t *cred, माप_प्रकार *pubkey_len)
{
	स्थिर uint8_t *ptr;
	uint8_t *pubkey = शून्य, *ret = शून्य;
	BIGNUM *x = शून्य, *y = शून्य;
	EC_POINT *q = शून्य;
	EC_GROUP *g = शून्य;

	अगर ((x = BN_new()) == शून्य ||
	    (y = BN_new()) == शून्य ||
	    (g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) == शून्य ||
	    (q = EC_POINT_new(g)) == शून्य) {
		error_f("libcrypto setup failed");
		जाओ out;
	}
	अगर ((ptr = fido_cred_pubkey_ptr(cred)) == शून्य) {
		error_f("fido_cred_pubkey_ptr failed");
		जाओ out;
	}
	अगर (fido_cred_pubkey_len(cred) != 64) {
		error_f("bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		जाओ out;
	}

	अगर (BN_bin2bn(ptr, 32, x) == शून्य ||
	    BN_bin2bn(ptr + 32, 32, y) == शून्य) {
		error_f("BN_bin2bn failed");
		जाओ out;
	}
	अगर (EC_POINT_set_affine_coordinates(g, q, x, y, शून्य) != 1) {
		error_f("EC_POINT_set_affine_coordinates failed");
		जाओ out;
	}
	*pubkey_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, शून्य, 0, शून्य);
	अगर (*pubkey_len == 0 || *pubkey_len > 2048) {
		error_f("bad pubkey length %zu", *pubkey_len);
		जाओ out;
	}
	अगर ((pubkey = दो_स्मृति(*pubkey_len)) == शून्य) {
		error_f("malloc pubkey failed");
		जाओ out;
	}
	अगर (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    pubkey, *pubkey_len, शून्य) == 0) {
		error_f("EC_POINT_point2oct failed");
		जाओ out;
	}
	/* success */
	ret = pubkey;
	pubkey = शून्य;
 out:
	मुक्त(pubkey);
	EC_POINT_free(q);
	EC_GROUP_free(g);
	BN_clear_free(x);
	BN_clear_free(y);
	वापस ret;
}

/* copied from sshsk_ecdsa_assemble() */
अटल पूर्णांक
cred_matches_कुंजी_ecdsa(स्थिर fido_cred_t *cred, स्थिर काष्ठा sshkey *k)
{
	काष्ठा sshkey *कुंजी = शून्य;
	काष्ठा sshbuf *b = शून्य;
	EC_कुंजी *ec = शून्य;
	uint8_t *pubkey = शून्य;
	माप_प्रकार pubkey_len;
	पूर्णांक r;

	अगर ((कुंजी = sshkey_new(कुंजी_ECDSA_SK)) == शून्य) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	कुंजी->ecdsa_nid = NID_X9_62_prime256v1;
	अगर ((कुंजी->pkey = EVP_PKEY_new()) == शून्य ||
	    (ec = EC_कुंजी_new_by_curve_name(कुंजी->ecdsa_nid)) == शून्य ||
	    (b = sshbuf_new()) == शून्य) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर ((pubkey = get_pubkey_from_cred_ecdsa(cred, &pubkey_len)) == शून्य) {
		error_f("get_pubkey_from_cred_ecdsa failed");
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	अगर ((r = sshbuf_put_string(b, pubkey, pubkey_len)) != 0) {
		error_fr(r, "sshbuf_put_string");
		जाओ out;
	}
	अगर ((r = sshbuf_get_eckey(b, ec)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	अगर (sshkey_ec_validate_public(EC_कुंजी_get0_group(ec),
	    EC_कुंजी_get0_public_कुंजी(ec)) != 0) {
		error("Authenticator returned invalid ECDSA key");
		r = SSH_ERR_कुंजी_INVALID_EC_मूल्य;
		जाओ out;
	}
	अगर (EVP_PKEY_set1_EC_कुंजी(कुंजी->pkey, ec) != 1) {
		/* XXX assume it is a allocation error */
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	कुंजी->sk_application = xstrdup(k->sk_application); /* XXX */
	अगर (!sshkey_equal_public(कुंजी, k)) {
		error("sshkey_equal_public failed");
		r = SSH_ERR_INVALID_ARGUMENT;
		जाओ out;
	}
	r = 0; /* success */
 out:
	EC_कुंजी_free(ec);
	मुक्त(pubkey);
	sshkey_free(कुंजी);
	sshbuf_free(b);
	वापस r;
}


/* copied from sshsk_ed25519_assemble() */
अटल पूर्णांक
cred_matches_कुंजी_ed25519(स्थिर fido_cred_t *cred, स्थिर काष्ठा sshkey *k)
{
	काष्ठा sshkey *कुंजी = शून्य;
	स्थिर uint8_t *ptr;
	पूर्णांक r = -1;

	अगर ((ptr = fido_cred_pubkey_ptr(cred)) == शून्य) {
		error_f("fido_cred_pubkey_ptr failed");
		जाओ out;
	}
	अगर (fido_cred_pubkey_len(cred) != ED25519_PK_SZ) {
		error_f("bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		जाओ out;
	}

	अगर ((कुंजी = sshkey_new(कुंजी_ED25519_SK)) == शून्य) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर ((कुंजी->ed25519_pk = दो_स्मृति(ED25519_PK_SZ)) == शून्य) {
		error_f("malloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	स_नकल(कुंजी->ed25519_pk, ptr, ED25519_PK_SZ);
	कुंजी->sk_application = xstrdup(k->sk_application); /* XXX */
	अगर (!sshkey_equal_public(कुंजी, k)) {
		error("sshkey_equal_public failed");
		r = SSH_ERR_INVALID_ARGUMENT;
		जाओ out;
	}
	r = 0; /* success */
 out:
	sshkey_free(कुंजी);
	वापस r;
}

अटल पूर्णांक
cred_matches_कुंजी(स्थिर fido_cred_t *cred, स्थिर काष्ठा sshkey *k)
{
	चयन (sshkey_type_plain(k->type)) {
	हाल कुंजी_ECDSA_SK:
		चयन (k->ecdsa_nid) {
		हाल NID_X9_62_prime256v1:
			वापस cred_matches_कुंजी_ecdsa(cred, k);
			अवरोध;
		शेष:
			fatal("Unsupported ECDSA key size");
		}
		अवरोध;
	हाल कुंजी_ED25519_SK:
		वापस cred_matches_कुंजी_ed25519(cred, k);
	शेष:
		error_f("key type %s not supported", sshkey_type(k));
		वापस -1;
	}
}

पूर्णांक
मुख्य(पूर्णांक argc, अक्षर **argv)
{
	LogLevel log_level = SYSLOG_LEVEL_INFO;
	पूर्णांक r, ch, credtype = -1;
	काष्ठा sshkey *k = शून्य;
	काष्ठा sshbuf *attestation = शून्य, *challenge = शून्य;
	काष्ठा sshbuf *attestation_cert = शून्य;
	अक्षर *fp;
	स्थिर अक्षर *attfmt = "packed", *style = शून्य;
	fido_cred_t *cred = शून्य;
	पूर्णांक write_attestation_cert = 0;
	बाह्य पूर्णांक optind;
	/* extern char *optarg; */

	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, शून्य);

	sanitise_stdfd();
	log_init(__progname, log_level, SYSLOG_FACILITY_AUTH, 1);

	जबतक ((ch = getopt(argc, argv, "UAv")) != -1) {
		चयन (ch) {
		हाल 'U':
			attfmt = "fido-u2f";
			अवरोध;
		हाल 'A':
			write_attestation_cert = 1;
			अवरोध;
		हाल 'v':
			अगर (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			अन्यथा अगर (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			अवरोध;
		शेष:
			जाओ usage;
		}
	}
	log_init(__progname, log_level, SYSLOG_FACILITY_AUTH, 1);
	argv += optind;
	argc -= optind;

	अगर (argc < 3) {
 usage:
		ख_लिखो(मानक_त्रुटि, "usage: %s [-vAU] "
		   "pubkey challenge attestation-blob\n", __progname);
		निकास(1);
	}
	अगर ((r = sshkey_load_public(argv[0], &k, शून्य)) != 0)
		fatal_r(r, "load key %s", argv[0]);
	अगर ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == शून्य)
		fatal("sshkey_fingerprint failed");
	debug2("key %s: %s %s", argv[2], sshkey_type(k), fp);
	मुक्त(fp);
	अगर ((r = sshbuf_load_file(argv[1], &challenge)) != 0)
		fatal_r(r, "load challenge %s", argv[1]);
	अगर ((r = sshbuf_load_file(argv[2], &attestation)) != 0)
		fatal_r(r, "load attestation %s", argv[2]);
	अगर ((cred = fido_cred_new()) == शून्य)
		fatal("fido_cred_new failed");

	चयन (sshkey_type_plain(k->type)) {
	हाल कुंजी_ECDSA_SK:
		चयन (k->ecdsa_nid) {
		हाल NID_X9_62_prime256v1:
			credtype = COSE_ES256;
			अवरोध;
		शेष:
			fatal("Unsupported ECDSA key size");
		}
		अवरोध;
	हाल कुंजी_ED25519_SK:
		credtype = COSE_EDDSA;
		अवरोध;
	शेष:
		fatal("unsupported key type %s", sshkey_type(k));
	}

	अगर ((r = prepare_fido_cred(cred, credtype, attfmt, k->sk_application,
	    attestation, challenge, &attestation_cert)) != 0)
		fatal_r(r, "prepare_fido_cred %s", argv[2]);
	अगर (fido_cred_x5c_ptr(cred) != शून्य) {
		debug("basic attestation");
		अगर ((r = fido_cred_verify(cred)) != FIDO_OK)
			fatal("basic attestation failed");
		style = "basic";
	} अन्यथा {
		debug("self attestation");
		अगर ((r = fido_cred_verify_self(cred)) != FIDO_OK)
			fatal("self attestation failed");
		style = "self";
	}
	अगर (cred_matches_कुंजी(cred, k) != 0)
		fatal("cred authdata does not match key");

	fido_cred_free(&cred);

	अगर (write_attestation_cert) {
		PEM_write(मानक_निकास, "CERTIFICATE", शून्य,
		    sshbuf_ptr(attestation_cert), sshbuf_len(attestation_cert));
	}
	sshbuf_free(attestation_cert);

	logit("%s: verified %s attestation", argv[2], style);

	वापस (0);
}
