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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <stdint.h>
#अन्तर्भाव <inttypes.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <stdarg.h>

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "authfile.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "digest.h"
#अन्तर्भाव "crypto_api.h"

#अन्तर्भाव <fido.h>
#अन्तर्भाव <openssl/x509.h>
#अन्तर्भाव <openssl/x509v3.h>
#अन्तर्भाव <openssl/bio.h>
#अन्तर्भाव <openssl/err.h>
#अन्तर्भाव <openssl/pem.h>
#अन्तर्भाव "openbsd-compat/openssl-compat.h"

बाह्य वर्ण *__progname;

#परिभाषय ATTEST_MAGIC	"ssh-sk-attest-v01"

स्थिर पूर्णाङ्क
prepare_fido_cred(fido_cred_t *cred, पूर्णाङ्क credtype, ध्रुव वर्ण *attfmt,
    ध्रुव वर्ण *rp_id, संरचना sshbuf *b, ध्रुव संरचना sshbuf *challenge,
    संरचना sshbuf **attestation_certp)
{
	संरचना sshbuf *attestation_cert = रिक्त, *sig = रिक्त, *authdata = रिक्त;
	वर्ण *magic = रिक्त;
	पूर्णाङ्क r = SSH_ERR_आन्तरिकम्_ERROR;

	*attestation_certp = रिक्त;

	/* Make sure it's the format we're expecting */
	यदि ((r = sshbuf_get_cstring(b, &magic, रिक्त)) != 0) {
		error_fr(r, "parse header");
		गच्छ बहिर्गमनम्;
	}
	यदि (वाक्यं_तुलय(magic, ATTEST_MAGIC) != 0) {
		error_f("unsupported format");
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ बहिर्गमनम्;
	}
	/* Parse the remaining fields */
	यदि ((r = sshbuf_froms(b, &attestation_cert)) != 0 ||
	    (r = sshbuf_froms(b, &sig)) != 0 ||
	    (r = sshbuf_froms(b, &authdata)) != 0 ||
	    (r = sshbuf_get_u32(b, रिक्त)) != 0 || /* reserved flags */
	    (r = sshbuf_get_string_प्रत्यक्षम्(b, रिक्त, रिक्त)) != 0) { /* reserved */
		error_fr(r, "parse body");
		गच्छ बहिर्गमनम्;
	}
	debug3_f("attestation cert len=%zu, sig len=%zu, "
	    "authdata len=%zu challenge len=%zu", sshbuf_len(attestation_cert),
	    sshbuf_len(sig), sshbuf_len(authdata), sshbuf_len(challenge));

	fido_cred_समुच्चयः_type(cred, credtype);
	fido_cred_समुच्चयः_fmt(cred, attfmt);
	fido_cred_समुच्चयः_clientdata(cred, sshbuf_ptr(challenge),
	    sshbuf_len(challenge));
	fido_cred_समुच्चयः_rp(cred, rp_id, रिक्त);
	fido_cred_समुच्चयः_authdata(cred, sshbuf_ptr(authdata),
	    sshbuf_len(authdata));
	/* XXX set_extensions, set_rk, set_uv */
	fido_cred_समुच्चयः_x509(cred, sshbuf_ptr(attestation_cert),
	    sshbuf_len(attestation_cert));
	fido_cred_समुच्चयः_sig(cred, sshbuf_ptr(sig), sshbuf_len(sig));

	/* success */
	*attestation_certp = attestation_cert;
	attestation_cert = रिक्त;
	r = 0;
 बहिर्गमनम्:
	मुक्त(magic);
	sshbuf_free(attestation_cert);
	sshbuf_free(sig);
	sshbuf_free(authdata);
	प्रत्यागम r;
}

स्थिर uint8_t *
get_pubkey_from_cred_ecdsa(ध्रुव fido_cred_t *cred, आकार_t *pubkey_len)
{
	ध्रुव uint8_t *ptr;
	uint8_t *pubkey = रिक्त, *ret = रिक्त;
	BIGNUM *x = रिक्त, *y = रिक्त;
	EC_POINT *q = रिक्त;
	EC_गणः *g = रिक्त;

	यदि ((x = BN_new()) == रिक्त ||
	    (y = BN_new()) == रिक्त ||
	    (g = EC_गणः_new_by_वक्रम्_name(NID_X9_62_prime256v1)) == रिक्त ||
	    (q = EC_POINT_new(g)) == रिक्त) {
		error_f("libcrypto setup failed");
		गच्छ बहिर्गमनम्;
	}
	यदि ((ptr = fido_cred_pubkey_ptr(cred)) == रिक्त) {
		error_f("fido_cred_pubkey_ptr failed");
		गच्छ बहिर्गमनम्;
	}
	यदि (fido_cred_pubkey_len(cred) != 64) {
		error_f("bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		गच्छ बहिर्गमनम्;
	}

	यदि (BN_bin2bn(ptr, 32, x) == रिक्त ||
	    BN_bin2bn(ptr + 32, 32, y) == रिक्त) {
		error_f("BN_bin2bn failed");
		गच्छ बहिर्गमनम्;
	}
	यदि (EC_POINT_समुच्चयः_affine_coordinates(g, q, x, y, रिक्त) != 1) {
		error_f("EC_POINT_set_affine_coordinates failed");
		गच्छ बहिर्गमनम्;
	}
	*pubkey_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, रिक्त, 0, रिक्त);
	यदि (*pubkey_len == 0 || *pubkey_len > 2048) {
		error_f("bad pubkey length %zu", *pubkey_len);
		गच्छ बहिर्गमनम्;
	}
	यदि ((pubkey = स्मृतिं_देहि(*pubkey_len)) == रिक्त) {
		error_f("malloc pubkey failed");
		गच्छ बहिर्गमनम्;
	}
	यदि (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    pubkey, *pubkey_len, रिक्त) == 0) {
		error_f("EC_POINT_point2oct failed");
		गच्छ बहिर्गमनम्;
	}
	/* success */
	ret = pubkey;
	pubkey = रिक्त;
 बहिर्गमनम्:
	मुक्त(pubkey);
	EC_POINT_free(q);
	EC_गणः_free(g);
	BN_clear_free(x);
	BN_clear_free(y);
	प्रत्यागम ret;
}

/* copied from sshsk_ecdsa_assemble() */
स्थिर पूर्णाङ्क
cred_matches_कुञ्चिका_ecdsa(ध्रुव fido_cred_t *cred, ध्रुव संरचना sshkey *k)
{
	संरचना sshkey *कुञ्चिका = रिक्त;
	संरचना sshbuf *b = रिक्त;
	EC_कुञ्चिका *ec = रिक्त;
	uint8_t *pubkey = रिक्त;
	आकार_t pubkey_len;
	पूर्णाङ्क r;

	यदि ((कुञ्चिका = sshkey_new(कुञ्चिका_ECDSA_SK)) == रिक्त) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	कुञ्चिका->ecdsa_nid = NID_X9_62_prime256v1;
	यदि ((कुञ्चिका->pkey = EVP_PKEY_new()) == रिक्त ||
	    (ec = EC_कुञ्चिका_new_by_वक्रम्_name(कुञ्चिका->ecdsa_nid)) == रिक्त ||
	    (b = sshbuf_new()) == रिक्त) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	यदि ((pubkey = get_pubkey_from_cred_ecdsa(cred, &pubkey_len)) == रिक्त) {
		error_f("get_pubkey_from_cred_ecdsa failed");
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = sshbuf_put_string(b, pubkey, pubkey_len)) != 0) {
		error_fr(r, "sshbuf_put_string");
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = sshbuf_get_eckey(b, ec)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ बहिर्गमनम्;
	}
	यदि (sshkey_ec_validate_लौकिकम्(EC_कुञ्चिका_get0_गणः(ec),
	    EC_कुञ्चिका_get0_लौकिकम्_कुञ्चिका(ec)) != 0) {
		error("Authenticator returned invalid ECDSA key");
		r = SSH_ERR_कुञ्चिका_INVALID_EC_मानम्;
		गच्छ बहिर्गमनम्;
	}
	यदि (EVP_PKEY_set1_EC_कुञ्चिका(कुञ्चिका->pkey, ec) != 1) {
		/* XXX assume it is a allocation error */
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	कुञ्चिका->sk_application = xstrdup(k->sk_application); /* XXX */
	यदि (!sshkey_equal_लौकिकम्(कुञ्चिका, k)) {
		error("sshkey_equal_public failed");
		r = SSH_ERR_INVALID_तर्कः;
		गच्छ बहिर्गमनम्;
	}
	r = 0; /* success */
 बहिर्गमनम्:
	EC_कुञ्चिका_free(ec);
	मुक्त(pubkey);
	sshkey_free(कुञ्चिका);
	sshbuf_free(b);
	प्रत्यागम r;
}


/* copied from sshsk_ed25519_assemble() */
स्थिर पूर्णाङ्क
cred_matches_कुञ्चिका_ed25519(ध्रुव fido_cred_t *cred, ध्रुव संरचना sshkey *k)
{
	संरचना sshkey *कुञ्चिका = रिक्त;
	ध्रुव uint8_t *ptr;
	पूर्णाङ्क r = -1;

	यदि ((ptr = fido_cred_pubkey_ptr(cred)) == रिक्त) {
		error_f("fido_cred_pubkey_ptr failed");
		गच्छ बहिर्गमनम्;
	}
	यदि (fido_cred_pubkey_len(cred) != ED25519_PK_SZ) {
		error_f("bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		गच्छ बहिर्गमनम्;
	}

	यदि ((कुञ्चिका = sshkey_new(कुञ्चिका_ED25519_SK)) == रिक्त) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	यदि ((कुञ्चिका->ed25519_pk = स्मृतिं_देहि(ED25519_PK_SZ)) == रिक्त) {
		error_f("malloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	स्मृतिं_प्रतिलिख(कुञ्चिका->ed25519_pk, ptr, ED25519_PK_SZ);
	कुञ्चिका->sk_application = xstrdup(k->sk_application); /* XXX */
	यदि (!sshkey_equal_लौकिकम्(कुञ्चिका, k)) {
		error("sshkey_equal_public failed");
		r = SSH_ERR_INVALID_तर्कः;
		गच्छ बहिर्गमनम्;
	}
	r = 0; /* success */
 बहिर्गमनम्:
	sshkey_free(कुञ्चिका);
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
cred_matches_कुञ्चिका(ध्रुव fido_cred_t *cred, ध्रुव संरचना sshkey *k)
{
	विकल्प (sshkey_type_plain(k->type)) {
	पक्ष कुञ्चिका_ECDSA_SK:
		विकल्प (k->ecdsa_nid) {
		पक्ष NID_X9_62_prime256v1:
			प्रत्यागम cred_matches_कुञ्चिका_ecdsa(cred, k);
			भङ्ग;
		स्वभाव:
			fatal("Unsupported ECDSA key size");
		}
		भङ्ग;
	पक्ष कुञ्चिका_ED25519_SK:
		प्रत्यागम cred_matches_कुञ्चिका_ed25519(cred, k);
	स्वभाव:
		error_f("key type %s not supported", sshkey_type(k));
		प्रत्यागम -1;
	}
}

पूर्णाङ्क
मुख्यम्(पूर्णाङ्क argc, वर्ण **argv)
{
	LogLevel log_level = SYSLOG_LEVEL_INFO;
	पूर्णाङ्क r, ch, credtype = -1;
	संरचना sshkey *k = रिक्त;
	संरचना sshbuf *attestation = रिक्त, *challenge = रिक्त;
	संरचना sshbuf *attestation_cert = रिक्त;
	वर्ण *fp;
	ध्रुव वर्ण *attfmt = "packed", *style = रिक्त;
	fido_cred_t *cred = रिक्त;
	पूर्णाङ्क write_attestation_cert = 0;
	बाह्य पूर्णाङ्क optind;
	/* extern char *optarg; */

	OPENSSL_init_crypto(OPENSSL_INIT_आरोपय_CRYPTO_वाक्यानि, रिक्त);

	sanitise_stdfd();
	log_init(__progname, log_level, SYSLOG_FACILITY_AUTH, 1);

	यावत् ((ch = getopt(argc, argv, "UAv")) != -1) {
		विकल्प (ch) {
		पक्ष 'U':
			attfmt = "fido-u2f";
			भङ्ग;
		पक्ष 'A':
			write_attestation_cert = 1;
			भङ्ग;
		पक्ष 'v':
			यदि (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			अन्यथा यदि (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			भङ्ग;
		स्वभाव:
			गच्छ usage;
		}
	}
	log_init(__progname, log_level, SYSLOG_FACILITY_AUTH, 1);
	argv += optind;
	argc -= optind;

	यदि (argc < 3) {
 usage:
		fprintf(stderr, "usage: %s [-vAU] "
		   "pubkey challenge attestation-blob\n", __progname);
		निर्गच्छ(1);
	}
	यदि ((r = sshkey_आरोपय_लौकिकम्(argv[0], &k, रिक्त)) != 0)
		fatal_r(r, "load key %s", argv[0]);
	यदि ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == रिक्त)
		fatal("sshkey_fingerprint failed");
	debug2("key %s: %s %s", argv[2], sshkey_type(k), fp);
	मुक्त(fp);
	यदि ((r = sshbuf_आरोपय_file(argv[1], &challenge)) != 0)
		fatal_r(r, "load challenge %s", argv[1]);
	यदि ((r = sshbuf_आरोपय_file(argv[2], &attestation)) != 0)
		fatal_r(r, "load attestation %s", argv[2]);
	यदि ((cred = fido_cred_new()) == रिक्त)
		fatal("fido_cred_new failed");

	विकल्प (sshkey_type_plain(k->type)) {
	पक्ष कुञ्चिका_ECDSA_SK:
		विकल्प (k->ecdsa_nid) {
		पक्ष NID_X9_62_prime256v1:
			credtype = COSE_ES256;
			भङ्ग;
		स्वभाव:
			fatal("Unsupported ECDSA key size");
		}
		भङ्ग;
	पक्ष कुञ्चिका_ED25519_SK:
		credtype = COSE_EDDSA;
		भङ्ग;
	स्वभाव:
		fatal("unsupported key type %s", sshkey_type(k));
	}

	यदि ((r = prepare_fido_cred(cred, credtype, attfmt, k->sk_application,
	    attestation, challenge, &attestation_cert)) != 0)
		fatal_r(r, "prepare_fido_cred %s", argv[2]);
	यदि (fido_cred_x5c_ptr(cred) != रिक्त) {
		debug("basic attestation");
		यदि ((r = fido_cred_verify(cred)) != FIDO_OK)
			fatal("basic attestation failed");
		style = "basic";
	} अन्यथा {
		debug("self attestation");
		यदि ((r = fido_cred_verify_self(cred)) != FIDO_OK)
			fatal("self attestation failed");
		style = "self";
	}
	यदि (cred_matches_कुञ्चिका(cred, k) != 0)
		fatal("cred authdata does not match key");

	fido_cred_free(&cred);

	यदि (write_attestation_cert) {
		PEM_write(stdout, "CERTIFICATE", रिक्त,
		    sshbuf_ptr(attestation_cert), sshbuf_len(attestation_cert));
	}
	sshbuf_free(attestation_cert);

	logit("%s: verified %s attestation", argv[2], style);

	प्रत्यागम (0);
}
