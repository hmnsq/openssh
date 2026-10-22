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

#define ATTEST_MAGIC	"ssh-sk-attest-v01"

स्थिर पूर्णाङ्क
prepare_fido_cred(fido_cred_t *cred, पूर्णाङ्क credtype, अचर वर्ण *attfmt,
    अचर वर्ण *rp_id, संरचना sshbuf *b, अचर संरचना sshbuf *challenge,
    संरचना sshbuf **attestation_certp)
{
	संरचना sshbuf *attestation_cert = रिक्त, *sig = रिक्त, *authdata = रिक्त;
	वर्ण *magic = रिक्त;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;

	*attestation_certp = रिक्त;

	/* Make sure it's the format we're expecting */
	यदि ((r = sshbuf_get_cstring(b, &magic, रिक्त)) != 0) {
		error_fr(r, "parse header");
		गच्छ out;
	}
	यदि (म_भेद(magic, ATTEST_MAGIC) != 0) {
		error_f("unsupported format");
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	/* Parse the remaining fields */
	यदि ((r = sshbuf_froms(b, &attestation_cert)) != 0 ||
	    (r = sshbuf_froms(b, &sig)) != 0 ||
	    (r = sshbuf_froms(b, &authdata)) != 0 ||
	    (r = sshbuf_get_u32(b, रिक्त)) != 0 || /* reserved flags */
	    (r = sshbuf_get_string_direct(b, रिक्त, रिक्त)) != 0) { /* reserved */
		error_fr(r, "parse body");
		गच्छ out;
	}
	debug3_f("attestation cert len=%zu, sig len=%zu, "
	    "authdata len=%zu challenge len=%zu", sshbuf_len(attestation_cert),
	    sshbuf_len(sig), sshbuf_len(authdata), sshbuf_len(challenge));

	fido_cred_set_type(cred, credtype);
	fido_cred_set_fmt(cred, attfmt);
	fido_cred_set_clientdata(cred, sshbuf_ptr(challenge),
	    sshbuf_len(challenge));
	fido_cred_set_rp(cred, rp_id, रिक्त);
	fido_cred_set_authdata(cred, sshbuf_ptr(authdata),
	    sshbuf_len(authdata));
	/* XXX set_extensions, set_rk, set_uv */
	fido_cred_set_x509(cred, sshbuf_ptr(attestation_cert),
	    sshbuf_len(attestation_cert));
	fido_cred_set_sig(cred, sshbuf_ptr(sig), sshbuf_len(sig));

	/* success */
	*attestation_certp = attestation_cert;
	attestation_cert = रिक्त;
	r = 0;
 out:
	मुक्त(magic);
	sshbuf_free(attestation_cert);
	sshbuf_free(sig);
	sshbuf_free(authdata);
	फर्काऊ r;
}

स्थिर uint8_t *
get_pubkey_from_cred_ecdsa(अचर fido_cred_t *cred, माप_प्रकार *pubkey_len)
{
	अचर uint8_t *ptr;
	uint8_t *pubkey = रिक्त, *ret = रिक्त;
	BIGNUM *x = रिक्त, *y = रिक्त;
	EC_POINT *q = रिक्त;
	EC_GROUP *g = रिक्त;

	यदि ((x = BN_new()) == रिक्त ||
	    (y = BN_new()) == रिक्त ||
	    (g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) == रिक्त ||
	    (q = EC_POINT_new(g)) == रिक्त) {
		error_f("libcrypto setup failed");
		गच्छ out;
	}
	यदि ((ptr = fido_cred_pubkey_ptr(cred)) == रिक्त) {
		error_f("fido_cred_pubkey_ptr failed");
		गच्छ out;
	}
	यदि (fido_cred_pubkey_len(cred) != 64) {
		error_f("bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		गच्छ out;
	}

	यदि (BN_bin2bn(ptr, 32, x) == रिक्त ||
	    BN_bin2bn(ptr + 32, 32, y) == रिक्त) {
		error_f("BN_bin2bn failed");
		गच्छ out;
	}
	यदि (EC_POINT_set_affine_coordinates(g, q, x, y, रिक्त) != 1) {
		error_f("EC_POINT_set_affine_coordinates failed");
		गच्छ out;
	}
	*pubkey_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, रिक्त, 0, रिक्त);
	यदि (*pubkey_len == 0 || *pubkey_len > 2048) {
		error_f("bad pubkey length %zu", *pubkey_len);
		गच्छ out;
	}
	यदि ((pubkey = दो_स्मृति(*pubkey_len)) == रिक्त) {
		error_f("malloc pubkey failed");
		गच्छ out;
	}
	यदि (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    pubkey, *pubkey_len, रिक्त) == 0) {
		error_f("EC_POINT_point2oct failed");
		गच्छ out;
	}
	/* success */
	ret = pubkey;
	pubkey = रिक्त;
 out:
	मुक्त(pubkey);
	EC_POINT_free(q);
	EC_GROUP_free(g);
	BN_clear_free(x);
	BN_clear_free(y);
	फर्काऊ ret;
}

/* copied from sshsk_ecdsa_assemble() */
स्थिर पूर्णाङ्क
cred_matches_साँचो_ecdsa(अचर fido_cred_t *cred, अचर संरचना sshkey *k)
{
	संरचना sshkey *साँचो = रिक्त;
	संरचना sshbuf *b = रिक्त;
	EC_साँचो *ec = रिक्त;
	uint8_t *pubkey = रिक्त;
	माप_प्रकार pubkey_len;
	पूर्णाङ्क r;

	यदि ((साँचो = sshkey_new(साँचो_ECDSA_SK)) == रिक्त) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	साँचो->ecdsa_nid = NID_X9_62_prime256v1;
	यदि ((साँचो->pkey = EVP_PKEY_new()) == रिक्त ||
	    (ec = EC_साँचो_new_by_curve_name(साँचो->ecdsa_nid)) == रिक्त ||
	    (b = sshbuf_new()) == रिक्त) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि ((pubkey = get_pubkey_from_cred_ecdsa(cred, &pubkey_len)) == रिक्त) {
		error_f("get_pubkey_from_cred_ecdsa failed");
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	यदि ((r = sshbuf_put_string(b, pubkey, pubkey_len)) != 0) {
		error_fr(r, "sshbuf_put_string");
		गच्छ out;
	}
	यदि ((r = sshbuf_get_eckey(b, ec)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	यदि (sshkey_ec_validate_public(EC_साँचो_get0_group(ec),
	    EC_साँचो_get0_public_साँचो(ec)) != 0) {
		error("Authenticator returned invalid ECDSA key");
		r = SSH_ERR_साँचो_INVALID_EC_मान;
		गच्छ out;
	}
	यदि (EVP_PKEY_set1_EC_साँचो(साँचो->pkey, ec) != 1) {
		/* XXX assume it is a allocation error */
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	साँचो->sk_application = xstrdup(k->sk_application); /* XXX */
	यदि (!sshkey_equal_public(साँचो, k)) {
		error("sshkey_equal_public failed");
		r = SSH_ERR_INVALID_ARGUMENT;
		गच्छ out;
	}
	r = 0; /* success */
 out:
	EC_साँचो_free(ec);
	मुक्त(pubkey);
	sshkey_free(साँचो);
	sshbuf_free(b);
	फर्काऊ r;
}


/* copied from sshsk_ed25519_assemble() */
स्थिर पूर्णाङ्क
cred_matches_साँचो_ed25519(अचर fido_cred_t *cred, अचर संरचना sshkey *k)
{
	संरचना sshkey *साँचो = रिक्त;
	अचर uint8_t *ptr;
	पूर्णाङ्क r = -1;

	यदि ((ptr = fido_cred_pubkey_ptr(cred)) == रिक्त) {
		error_f("fido_cred_pubkey_ptr failed");
		गच्छ out;
	}
	यदि (fido_cred_pubkey_len(cred) != ED25519_PK_SZ) {
		error_f("bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		गच्छ out;
	}

	यदि ((साँचो = sshkey_new(साँचो_ED25519_SK)) == रिक्त) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि ((साँचो->ed25519_pk = दो_स्मृति(ED25519_PK_SZ)) == रिक्त) {
		error_f("malloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	स_नकल(साँचो->ed25519_pk, ptr, ED25519_PK_SZ);
	साँचो->sk_application = xstrdup(k->sk_application); /* XXX */
	यदि (!sshkey_equal_public(साँचो, k)) {
		error("sshkey_equal_public failed");
		r = SSH_ERR_INVALID_ARGUMENT;
		गच्छ out;
	}
	r = 0; /* success */
 out:
	sshkey_free(साँचो);
	फर्काऊ r;
}

स्थिर पूर्णाङ्क
cred_matches_साँचो(अचर fido_cred_t *cred, अचर संरचना sshkey *k)
{
	विकल्प (sshkey_type_plain(k->type)) {
	पक्ष साँचो_ECDSA_SK:
		विकल्प (k->ecdsa_nid) {
		पक्ष NID_X9_62_prime256v1:
			फर्काऊ cred_matches_साँचो_ecdsa(cred, k);
			रोक;
		स्वभाव:
			fatal("Unsupported ECDSA key size");
		}
		रोक;
	पक्ष साँचो_ED25519_SK:
		फर्काऊ cred_matches_साँचो_ed25519(cred, k);
	स्वभाव:
		error_f("key type %s not supported", sshkey_type(k));
		फर्काऊ -1;
	}
}

पूर्णाङ्क
main(पूर्णाङ्क argc, वर्ण **argv)
{
	LogLevel log_level = SYSLOG_LEVEL_INFO;
	पूर्णाङ्क r, ch, credtype = -1;
	संरचना sshkey *k = रिक्त;
	संरचना sshbuf *attestation = रिक्त, *challenge = रिक्त;
	संरचना sshbuf *attestation_cert = रिक्त;
	वर्ण *fp;
	अचर वर्ण *attfmt = "packed", *style = रिक्त;
	fido_cred_t *cred = रिक्त;
	पूर्णाङ्क write_attestation_cert = 0;
	बाह्य पूर्णाङ्क optind;
	/* extern char *optarg; */

	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, रिक्त);

	sanitise_stdfd();
	log_init(__progname, log_level, SYSLOG_FACILITY_AUTH, 1);

	जबसम्म ((ch = getopt(argc, argv, "UAv")) != -1) {
		विकल्प (ch) {
		पक्ष 'U':
			attfmt = "fido-u2f";
			रोक;
		पक्ष 'A':
			write_attestation_cert = 1;
			रोक;
		पक्ष 'v':
			यदि (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			अन्यथा यदि (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			रोक;
		स्वभाव:
			गच्छ usage;
		}
	}
	log_init(__progname, log_level, SYSLOG_FACILITY_AUTH, 1);
	argv += optind;
	argc -= optind;

	यदि (argc < 3) {
 usage:
		ख_लिखो(मानक_त्रुटि, "usage: %s [-vAU] "
		   "pubkey challenge attestation-blob\n", __progname);
		निकास(1);
	}
	यदि ((r = sshkey_load_public(argv[0], &k, रिक्त)) != 0)
		fatal_r(r, "load key %s", argv[0]);
	यदि ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == रिक्त)
		fatal("sshkey_fingerprint failed");
	debug2("key %s: %s %s", argv[2], sshkey_type(k), fp);
	मुक्त(fp);
	यदि ((r = sshbuf_load_file(argv[1], &challenge)) != 0)
		fatal_r(r, "load challenge %s", argv[1]);
	यदि ((r = sshbuf_load_file(argv[2], &attestation)) != 0)
		fatal_r(r, "load attestation %s", argv[2]);
	यदि ((cred = fido_cred_new()) == रिक्त)
		fatal("fido_cred_new failed");

	विकल्प (sshkey_type_plain(k->type)) {
	पक्ष साँचो_ECDSA_SK:
		विकल्प (k->ecdsa_nid) {
		पक्ष NID_X9_62_prime256v1:
			credtype = COSE_ES256;
			रोक;
		स्वभाव:
			fatal("Unsupported ECDSA key size");
		}
		रोक;
	पक्ष साँचो_ED25519_SK:
		credtype = COSE_EDDSA;
		रोक;
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
	यदि (cred_matches_साँचो(cred, k) != 0)
		fatal("cred authdata does not match key");

	fido_cred_free(&cred);

	यदि (write_attestation_cert) {
		PEM_write(मानक_निकास, "CERTIFICATE", रिक्त,
		    sshbuf_ptr(attestation_cert), sshbuf_len(attestation_cert));
	}
	sshbuf_free(attestation_cert);

	logit("%s: verified %s attestation", argv[2], style);

	फर्काऊ (0);
}
