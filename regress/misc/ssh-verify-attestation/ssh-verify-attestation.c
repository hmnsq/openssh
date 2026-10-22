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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <inttypes.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <stdarg.h>

#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "authfile.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "digest.h"
#অন্তর্ভাব "crypto_api.h"

#অন্তর্ভাব <fido.h>
#অন্তর্ভাব <openssl/x509.h>
#অন্তর্ভাব <openssl/x509v3.h>
#অন্তর্ভাব <openssl/bio.h>
#অন্তর্ভাব <openssl/err.h>
#অন্তর্ভাব <openssl/pem.h>
#অন্তর্ভাব "openbsd-compat/openssl-compat.h"

বাহ্য বর্ণ *__progname;

#define ATTEST_MAGIC	"ssh-sk-attest-v01"

স্থির পূর্ণাঙ্ক
prepare_fido_cred(fido_cred_t *cred, পূর্ণাঙ্ক credtype, ধ্রুব বর্ণ *attfmt,
    ধ্রুব বর্ণ *rp_id, সংরচনা sshbuf *b, ধ্রুব সংরচনা sshbuf *challenge,
    সংরচনা sshbuf **attestation_certp)
{
	সংরচনা sshbuf *attestation_cert = রিক্ত, *sig = রিক্ত, *authdata = রিক্ত;
	বর্ণ *magic = রিক্ত;
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;

	*attestation_certp = রিক্ত;

	/* Make sure it's the format we're expecting */
	যদি ((r = sshbuf_get_cstring(b, &magic, রিক্ত)) != 0) {
		error_fr(r, "parse header");
		গচ্ছ out;
	}
	যদি (strcmp(magic, ATTEST_MAGIC) != 0) {
		error_f("unsupported format");
		r = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}
	/* Parse the remaining fields */
	যদি ((r = sshbuf_froms(b, &attestation_cert)) != 0 ||
	    (r = sshbuf_froms(b, &sig)) != 0 ||
	    (r = sshbuf_froms(b, &authdata)) != 0 ||
	    (r = sshbuf_get_u32(b, রিক্ত)) != 0 || /* reserved flags */
	    (r = sshbuf_get_string_direct(b, রিক্ত, রিক্ত)) != 0) { /* reserved */
		error_fr(r, "parse body");
		গচ্ছ out;
	}
	debug3_f("attestation cert len=%zu, sig len=%zu, "
	    "authdata len=%zu challenge len=%zu", sshbuf_len(attestation_cert),
	    sshbuf_len(sig), sshbuf_len(authdata), sshbuf_len(challenge));

	fido_cred_set_type(cred, credtype);
	fido_cred_set_fmt(cred, attfmt);
	fido_cred_set_clientdata(cred, sshbuf_ptr(challenge),
	    sshbuf_len(challenge));
	fido_cred_set_rp(cred, rp_id, রিক্ত);
	fido_cred_set_authdata(cred, sshbuf_ptr(authdata),
	    sshbuf_len(authdata));
	/* XXX set_extensions, set_rk, set_uv */
	fido_cred_set_x509(cred, sshbuf_ptr(attestation_cert),
	    sshbuf_len(attestation_cert));
	fido_cred_set_sig(cred, sshbuf_ptr(sig), sshbuf_len(sig));

	/* success */
	*attestation_certp = attestation_cert;
	attestation_cert = রিক্ত;
	r = 0;
 out:
	মুক্ত(magic);
	sshbuf_free(attestation_cert);
	sshbuf_free(sig);
	sshbuf_free(authdata);
	প্রত্যাগম r;
}

স্থির uint8_t *
get_pubkey_from_cred_ecdsa(ধ্রুব fido_cred_t *cred, size_t *pubkey_len)
{
	ধ্রুব uint8_t *ptr;
	uint8_t *pubkey = রিক্ত, *ret = রিক্ত;
	BIGNUM *x = রিক্ত, *y = রিক্ত;
	EC_POINT *q = রিক্ত;
	EC_GROUP *g = রিক্ত;

	যদি ((x = BN_new()) == রিক্ত ||
	    (y = BN_new()) == রিক্ত ||
	    (g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) == রিক্ত ||
	    (q = EC_POINT_new(g)) == রিক্ত) {
		error_f("libcrypto setup failed");
		গচ্ছ out;
	}
	যদি ((ptr = fido_cred_pubkey_ptr(cred)) == রিক্ত) {
		error_f("fido_cred_pubkey_ptr failed");
		গচ্ছ out;
	}
	যদি (fido_cred_pubkey_len(cred) != 64) {
		error_f("bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		গচ্ছ out;
	}

	যদি (BN_bin2bn(ptr, 32, x) == রিক্ত ||
	    BN_bin2bn(ptr + 32, 32, y) == রিক্ত) {
		error_f("BN_bin2bn failed");
		গচ্ছ out;
	}
	যদি (EC_POINT_set_affine_coordinates(g, q, x, y, রিক্ত) != 1) {
		error_f("EC_POINT_set_affine_coordinates failed");
		গচ্ছ out;
	}
	*pubkey_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, রিক্ত, 0, রিক্ত);
	যদি (*pubkey_len == 0 || *pubkey_len > 2048) {
		error_f("bad pubkey length %zu", *pubkey_len);
		গচ্ছ out;
	}
	যদি ((pubkey = malloc(*pubkey_len)) == রিক্ত) {
		error_f("malloc pubkey failed");
		গচ্ছ out;
	}
	যদি (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    pubkey, *pubkey_len, রিক্ত) == 0) {
		error_f("EC_POINT_point2oct failed");
		গচ্ছ out;
	}
	/* success */
	ret = pubkey;
	pubkey = রিক্ত;
 out:
	মুক্ত(pubkey);
	EC_POINT_free(q);
	EC_GROUP_free(g);
	BN_clear_free(x);
	BN_clear_free(y);
	প্রত্যাগম ret;
}

/* copied from sshsk_ecdsa_assemble() */
স্থির পূর্ণাঙ্ক
cred_matches_চাবি_ecdsa(ধ্রুব fido_cred_t *cred, ধ্রুব সংরচনা sshkey *k)
{
	সংরচনা sshkey *চাবি = রিক্ত;
	সংরচনা sshbuf *b = রিক্ত;
	EC_চাবি *ec = রিক্ত;
	uint8_t *pubkey = রিক্ত;
	size_t pubkey_len;
	পূর্ণাঙ্ক r;

	যদি ((চাবি = sshkey_new(চাবি_ECDSA_SK)) == রিক্ত) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	চাবি->ecdsa_nid = NID_X9_62_prime256v1;
	যদি ((চাবি->pkey = EVP_PKEY_new()) == রিক্ত ||
	    (ec = EC_চাবি_new_by_curve_name(চাবি->ecdsa_nid)) == রিক্ত ||
	    (b = sshbuf_new()) == রিক্ত) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি ((pubkey = get_pubkey_from_cred_ecdsa(cred, &pubkey_len)) == রিক্ত) {
		error_f("get_pubkey_from_cred_ecdsa failed");
		r = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}
	যদি ((r = sshbuf_put_string(b, pubkey, pubkey_len)) != 0) {
		error_fr(r, "sshbuf_put_string");
		গচ্ছ out;
	}
	যদি ((r = sshbuf_get_eckey(b, ec)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}
	যদি (sshkey_ec_validate_public(EC_চাবি_get0_group(ec),
	    EC_চাবি_get0_public_চাবি(ec)) != 0) {
		error("Authenticator returned invalid ECDSA key");
		r = SSH_ERR_চাবি_INVALID_EC_মান;
		গচ্ছ out;
	}
	যদি (EVP_PKEY_set1_EC_চাবি(চাবি->pkey, ec) != 1) {
		/* XXX assume it is a allocation error */
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	চাবি->sk_application = xstrdup(k->sk_application); /* XXX */
	যদি (!sshkey_equal_public(চাবি, k)) {
		error("sshkey_equal_public failed");
		r = SSH_ERR_INVALID_ARGUMENT;
		গচ্ছ out;
	}
	r = 0; /* success */
 out:
	EC_চাবি_free(ec);
	মুক্ত(pubkey);
	sshkey_free(চাবি);
	sshbuf_free(b);
	প্রত্যাগম r;
}


/* copied from sshsk_ed25519_assemble() */
স্থির পূর্ণাঙ্ক
cred_matches_চাবি_ed25519(ধ্রুব fido_cred_t *cred, ধ্রুব সংরচনা sshkey *k)
{
	সংরচনা sshkey *চাবি = রিক্ত;
	ধ্রুব uint8_t *ptr;
	পূর্ণাঙ্ক r = -1;

	যদি ((ptr = fido_cred_pubkey_ptr(cred)) == রিক্ত) {
		error_f("fido_cred_pubkey_ptr failed");
		গচ্ছ out;
	}
	যদি (fido_cred_pubkey_len(cred) != ED25519_PK_SZ) {
		error_f("bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		গচ্ছ out;
	}

	যদি ((চাবি = sshkey_new(চাবি_ED25519_SK)) == রিক্ত) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি ((চাবি->ed25519_pk = malloc(ED25519_PK_SZ)) == রিক্ত) {
		error_f("malloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	memcpy(চাবি->ed25519_pk, ptr, ED25519_PK_SZ);
	চাবি->sk_application = xstrdup(k->sk_application); /* XXX */
	যদি (!sshkey_equal_public(চাবি, k)) {
		error("sshkey_equal_public failed");
		r = SSH_ERR_INVALID_ARGUMENT;
		গচ্ছ out;
	}
	r = 0; /* success */
 out:
	sshkey_free(চাবি);
	প্রত্যাগম r;
}

স্থির পূর্ণাঙ্ক
cred_matches_চাবি(ধ্রুব fido_cred_t *cred, ধ্রুব সংরচনা sshkey *k)
{
	বিকল্প (sshkey_type_plain(k->type)) {
	পক্ষ চাবি_ECDSA_SK:
		বিকল্প (k->ecdsa_nid) {
		পক্ষ NID_X9_62_prime256v1:
			প্রত্যাগম cred_matches_চাবি_ecdsa(cred, k);
			ভঙ্গ;
		স্বভাব:
			fatal("Unsupported ECDSA key size");
		}
		ভঙ্গ;
	পক্ষ চাবি_ED25519_SK:
		প্রত্যাগম cred_matches_চাবি_ed25519(cred, k);
	স্বভাব:
		error_f("key type %s not supported", sshkey_type(k));
		প্রত্যাগম -1;
	}
}

পূর্ণাঙ্ক
main(পূর্ণাঙ্ক argc, বর্ণ **argv)
{
	LogLevel log_level = SYSLOG_LEVEL_INFO;
	পূর্ণাঙ্ক r, ch, credtype = -1;
	সংরচনা sshkey *k = রিক্ত;
	সংরচনা sshbuf *attestation = রিক্ত, *challenge = রিক্ত;
	সংরচনা sshbuf *attestation_cert = রিক্ত;
	বর্ণ *fp;
	ধ্রুব বর্ণ *attfmt = "packed", *style = রিক্ত;
	fido_cred_t *cred = রিক্ত;
	পূর্ণাঙ্ক write_attestation_cert = 0;
	বাহ্য পূর্ণাঙ্ক optind;
	/* extern char *optarg; */

	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, রিক্ত);

	sanitise_stdfd();
	log_init(__progname, log_level, SYSLOG_FACILITY_AUTH, 1);

	যাবত্ ((ch = getopt(argc, argv, "UAv")) != -1) {
		বিকল্প (ch) {
		পক্ষ 'U':
			attfmt = "fido-u2f";
			ভঙ্গ;
		পক্ষ 'A':
			write_attestation_cert = 1;
			ভঙ্গ;
		পক্ষ 'v':
			যদি (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			অন্যথা যদি (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			ভঙ্গ;
		স্বভাব:
			গচ্ছ usage;
		}
	}
	log_init(__progname, log_level, SYSLOG_FACILITY_AUTH, 1);
	argv += optind;
	argc -= optind;

	যদি (argc < 3) {
 usage:
		fprintf(stderr, "usage: %s [-vAU] "
		   "pubkey challenge attestation-blob\n", __progname);
		exit(1);
	}
	যদি ((r = sshkey_load_public(argv[0], &k, রিক্ত)) != 0)
		fatal_r(r, "load key %s", argv[0]);
	যদি ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == রিক্ত)
		fatal("sshkey_fingerprint failed");
	debug2("key %s: %s %s", argv[2], sshkey_type(k), fp);
	মুক্ত(fp);
	যদি ((r = sshbuf_load_file(argv[1], &challenge)) != 0)
		fatal_r(r, "load challenge %s", argv[1]);
	যদি ((r = sshbuf_load_file(argv[2], &attestation)) != 0)
		fatal_r(r, "load attestation %s", argv[2]);
	যদি ((cred = fido_cred_new()) == রিক্ত)
		fatal("fido_cred_new failed");

	বিকল্প (sshkey_type_plain(k->type)) {
	পক্ষ চাবি_ECDSA_SK:
		বিকল্প (k->ecdsa_nid) {
		পক্ষ NID_X9_62_prime256v1:
			credtype = COSE_ES256;
			ভঙ্গ;
		স্বভাব:
			fatal("Unsupported ECDSA key size");
		}
		ভঙ্গ;
	পক্ষ চাবি_ED25519_SK:
		credtype = COSE_EDDSA;
		ভঙ্গ;
	স্বভাব:
		fatal("unsupported key type %s", sshkey_type(k));
	}

	যদি ((r = prepare_fido_cred(cred, credtype, attfmt, k->sk_application,
	    attestation, challenge, &attestation_cert)) != 0)
		fatal_r(r, "prepare_fido_cred %s", argv[2]);
	যদি (fido_cred_x5c_ptr(cred) != রিক্ত) {
		debug("basic attestation");
		যদি ((r = fido_cred_verify(cred)) != FIDO_OK)
			fatal("basic attestation failed");
		style = "basic";
	} অন্যথা {
		debug("self attestation");
		যদি ((r = fido_cred_verify_self(cred)) != FIDO_OK)
			fatal("self attestation failed");
		style = "self";
	}
	যদি (cred_matches_চাবি(cred, k) != 0)
		fatal("cred authdata does not match key");

	fido_cred_free(&cred);

	যদি (write_attestation_cert) {
		PEM_write(stdout, "CERTIFICATE", রিক্ত,
		    sshbuf_ptr(attestation_cert), sshbuf_len(attestation_cert));
	}
	sshbuf_free(attestation_cert);

	logit("%s: verified %s attestation", argv[2], style);

	প্রত্যাগম (0);
}
