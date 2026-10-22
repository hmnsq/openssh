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

বাহ্যিক অক্ষর *__progname;

#define ATTEST_MAGIC	"ssh-sk-attest-v01"

স্থির পূর্ণসংখ্যা
prepare_fido_cred(fido_cred_t *cred, পূর্ণসংখ্যা credtype, ধ্রুবক অক্ষর *attfmt,
    ধ্রুবক অক্ষর *rp_id, কাঠামো sshbuf *b, ধ্রুবক কাঠামো sshbuf *challenge,
    কাঠামো sshbuf **attestation_certp)
{
	কাঠামো sshbuf *attestation_cert = ফাঁকা, *sig = ফাঁকা, *authdata = ফাঁকা;
	অক্ষর *magic = ফাঁকা;
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;

	*attestation_certp = ফাঁকা;

	/* Make sure it's the format we're expecting */
	যদি ((r = sshbuf_get_cstring(b, &magic, ফাঁকা)) != 0) {
		error_fr(r, "parse header");
		যাও out;
	}
	যদি (strcmp(magic, ATTEST_MAGIC) != 0) {
		error_f("unsupported format");
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	/* Parse the remaining fields */
	যদি ((r = sshbuf_froms(b, &attestation_cert)) != 0 ||
	    (r = sshbuf_froms(b, &sig)) != 0 ||
	    (r = sshbuf_froms(b, &authdata)) != 0 ||
	    (r = sshbuf_get_u32(b, ফাঁকা)) != 0 || /* reserved flags */
	    (r = sshbuf_get_string_direct(b, ফাঁকা, ফাঁকা)) != 0) { /* reserved */
		error_fr(r, "parse body");
		যাও out;
	}
	debug3_f("attestation cert len=%zu, sig len=%zu, "
	    "authdata len=%zu challenge len=%zu", sshbuf_len(attestation_cert),
	    sshbuf_len(sig), sshbuf_len(authdata), sshbuf_len(challenge));

	fido_cred_set_type(cred, credtype);
	fido_cred_set_fmt(cred, attfmt);
	fido_cred_set_clientdata(cred, sshbuf_ptr(challenge),
	    sshbuf_len(challenge));
	fido_cred_set_rp(cred, rp_id, ফাঁকা);
	fido_cred_set_authdata(cred, sshbuf_ptr(authdata),
	    sshbuf_len(authdata));
	/* XXX set_extensions, set_rk, set_uv */
	fido_cred_set_x509(cred, sshbuf_ptr(attestation_cert),
	    sshbuf_len(attestation_cert));
	fido_cred_set_sig(cred, sshbuf_ptr(sig), sshbuf_len(sig));

	/* success */
	*attestation_certp = attestation_cert;
	attestation_cert = ফাঁকা;
	r = 0;
 out:
	মুক্ত(magic);
	sshbuf_free(attestation_cert);
	sshbuf_free(sig);
	sshbuf_free(authdata);
	ফেরত r;
}

স্থির uint8_t *
get_pubkey_from_cred_ecdsa(ধ্রুবক fido_cred_t *cred, আকার_t *pubkey_len)
{
	ধ্রুবক uint8_t *ptr;
	uint8_t *pubkey = ফাঁকা, *ret = ফাঁকা;
	BIGNUM *x = ফাঁকা, *y = ফাঁকা;
	EC_POINT *q = ফাঁকা;
	EC_GROUP *g = ফাঁকা;

	যদি ((x = BN_new()) == ফাঁকা ||
	    (y = BN_new()) == ফাঁকা ||
	    (g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) == ফাঁকা ||
	    (q = EC_POINT_new(g)) == ফাঁকা) {
		error_f("libcrypto setup failed");
		যাও out;
	}
	যদি ((ptr = fido_cred_pubkey_ptr(cred)) == ফাঁকা) {
		error_f("fido_cred_pubkey_ptr failed");
		যাও out;
	}
	যদি (fido_cred_pubkey_len(cred) != 64) {
		error_f("bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		যাও out;
	}

	যদি (BN_bin2bn(ptr, 32, x) == ফাঁকা ||
	    BN_bin2bn(ptr + 32, 32, y) == ফাঁকা) {
		error_f("BN_bin2bn failed");
		যাও out;
	}
	যদি (EC_POINT_set_affine_coordinates(g, q, x, y, ফাঁকা) != 1) {
		error_f("EC_POINT_set_affine_coordinates failed");
		যাও out;
	}
	*pubkey_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, ফাঁকা, 0, ফাঁকা);
	যদি (*pubkey_len == 0 || *pubkey_len > 2048) {
		error_f("bad pubkey length %zu", *pubkey_len);
		যাও out;
	}
	যদি ((pubkey = malloc(*pubkey_len)) == ফাঁকা) {
		error_f("malloc pubkey failed");
		যাও out;
	}
	যদি (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    pubkey, *pubkey_len, ফাঁকা) == 0) {
		error_f("EC_POINT_point2oct failed");
		যাও out;
	}
	/* success */
	ret = pubkey;
	pubkey = ফাঁকা;
 out:
	মুক্ত(pubkey);
	EC_POINT_free(q);
	EC_GROUP_free(g);
	BN_clear_free(x);
	BN_clear_free(y);
	ফেরত ret;
}

/* copied from sshsk_ecdsa_assemble() */
স্থির পূর্ণসংখ্যা
cred_matches_চাবি_ecdsa(ধ্রুবক fido_cred_t *cred, ধ্রুবক কাঠামো sshkey *k)
{
	কাঠামো sshkey *চাবি = ফাঁকা;
	কাঠামো sshbuf *b = ফাঁকা;
	EC_চাবি *ec = ফাঁকা;
	uint8_t *pubkey = ফাঁকা;
	আকার_t pubkey_len;
	পূর্ণসংখ্যা r;

	যদি ((চাবি = sshkey_new(চাবি_ECDSA_SK)) == ফাঁকা) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	চাবি->ecdsa_nid = NID_X9_62_prime256v1;
	যদি ((চাবি->pkey = EVP_PKEY_new()) == ফাঁকা ||
	    (ec = EC_চাবি_new_by_curve_name(চাবি->ecdsa_nid)) == ফাঁকা ||
	    (b = sshbuf_new()) == ফাঁকা) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি ((pubkey = get_pubkey_from_cred_ecdsa(cred, &pubkey_len)) == ফাঁকা) {
		error_f("get_pubkey_from_cred_ecdsa failed");
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	যদি ((r = sshbuf_put_string(b, pubkey, pubkey_len)) != 0) {
		error_fr(r, "sshbuf_put_string");
		যাও out;
	}
	যদি ((r = sshbuf_get_eckey(b, ec)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	যদি (sshkey_ec_validate_public(EC_চাবি_get0_group(ec),
	    EC_চাবি_get0_public_চাবি(ec)) != 0) {
		error("Authenticator returned invalid ECDSA key");
		r = SSH_ERR_চাবি_INVALID_EC_মান;
		যাও out;
	}
	যদি (EVP_PKEY_set1_EC_চাবি(চাবি->pkey, ec) != 1) {
		/* XXX assume it is a allocation error */
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	চাবি->sk_application = xstrdup(k->sk_application); /* XXX */
	যদি (!sshkey_equal_public(চাবি, k)) {
		error("sshkey_equal_public failed");
		r = SSH_ERR_INVALID_ARGUMENT;
		যাও out;
	}
	r = 0; /* success */
 out:
	EC_চাবি_free(ec);
	মুক্ত(pubkey);
	sshkey_free(চাবি);
	sshbuf_free(b);
	ফেরত r;
}


/* copied from sshsk_ed25519_assemble() */
স্থির পূর্ণসংখ্যা
cred_matches_চাবি_ed25519(ধ্রুবক fido_cred_t *cred, ধ্রুবক কাঠামো sshkey *k)
{
	কাঠামো sshkey *চাবি = ফাঁকা;
	ধ্রুবক uint8_t *ptr;
	পূর্ণসংখ্যা r = -1;

	যদি ((ptr = fido_cred_pubkey_ptr(cred)) == ফাঁকা) {
		error_f("fido_cred_pubkey_ptr failed");
		যাও out;
	}
	যদি (fido_cred_pubkey_len(cred) != ED25519_PK_SZ) {
		error_f("bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		যাও out;
	}

	যদি ((চাবি = sshkey_new(চাবি_ED25519_SK)) == ফাঁকা) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি ((চাবি->ed25519_pk = malloc(ED25519_PK_SZ)) == ফাঁকা) {
		error_f("malloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	memcpy(চাবি->ed25519_pk, ptr, ED25519_PK_SZ);
	চাবি->sk_application = xstrdup(k->sk_application); /* XXX */
	যদি (!sshkey_equal_public(চাবি, k)) {
		error("sshkey_equal_public failed");
		r = SSH_ERR_INVALID_ARGUMENT;
		যাও out;
	}
	r = 0; /* success */
 out:
	sshkey_free(চাবি);
	ফেরত r;
}

স্থির পূর্ণসংখ্যা
cred_matches_চাবি(ধ্রুবক fido_cred_t *cred, ধ্রুবক কাঠামো sshkey *k)
{
	নির্বাচন (sshkey_type_plain(k->type)) {
	ক্ষেত্র চাবি_ECDSA_SK:
		নির্বাচন (k->ecdsa_nid) {
		ক্ষেত্র NID_X9_62_prime256v1:
			ফেরত cred_matches_চাবি_ecdsa(cred, k);
			বিরতি;
		পূর্বনির্ধারিত:
			fatal("Unsupported ECDSA key size");
		}
		বিরতি;
	ক্ষেত্র চাবি_ED25519_SK:
		ফেরত cred_matches_চাবি_ed25519(cred, k);
	পূর্বনির্ধারিত:
		error_f("key type %s not supported", sshkey_type(k));
		ফেরত -1;
	}
}

পূর্ণসংখ্যা
প্রধান(পূর্ণসংখ্যা argc, অক্ষর **argv)
{
	LogLevel log_level = SYSLOG_LEVEL_INFO;
	পূর্ণসংখ্যা r, ch, credtype = -1;
	কাঠামো sshkey *k = ফাঁকা;
	কাঠামো sshbuf *attestation = ফাঁকা, *challenge = ফাঁকা;
	কাঠামো sshbuf *attestation_cert = ফাঁকা;
	অক্ষর *fp;
	ধ্রুবক অক্ষর *attfmt = "packed", *style = ফাঁকা;
	fido_cred_t *cred = ফাঁকা;
	পূর্ণসংখ্যা write_attestation_cert = 0;
	বাহ্যিক পূর্ণসংখ্যা optind;
	/* extern char *optarg; */

	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, ফাঁকা);

	sanitise_stdfd();
	log_init(__progname, log_level, SYSLOG_FACILITY_AUTH, 1);

	যখন ((ch = getopt(argc, argv, "UAv")) != -1) {
		নির্বাচন (ch) {
		ক্ষেত্র 'U':
			attfmt = "fido-u2f";
			বিরতি;
		ক্ষেত্র 'A':
			write_attestation_cert = 1;
			বিরতি;
		ক্ষেত্র 'v':
			যদি (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			অন্যথা যদি (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			বিরতি;
		পূর্বনির্ধারিত:
			যাও usage;
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
	যদি ((r = sshkey_load_public(argv[0], &k, ফাঁকা)) != 0)
		fatal_r(r, "load key %s", argv[0]);
	যদি ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ফাঁকা)
		fatal("sshkey_fingerprint failed");
	debug2("key %s: %s %s", argv[2], sshkey_type(k), fp);
	মুক্ত(fp);
	যদি ((r = sshbuf_load_file(argv[1], &challenge)) != 0)
		fatal_r(r, "load challenge %s", argv[1]);
	যদি ((r = sshbuf_load_file(argv[2], &attestation)) != 0)
		fatal_r(r, "load attestation %s", argv[2]);
	যদি ((cred = fido_cred_new()) == ফাঁকা)
		fatal("fido_cred_new failed");

	নির্বাচন (sshkey_type_plain(k->type)) {
	ক্ষেত্র চাবি_ECDSA_SK:
		নির্বাচন (k->ecdsa_nid) {
		ক্ষেত্র NID_X9_62_prime256v1:
			credtype = COSE_ES256;
			বিরতি;
		পূর্বনির্ধারিত:
			fatal("Unsupported ECDSA key size");
		}
		বিরতি;
	ক্ষেত্র চাবি_ED25519_SK:
		credtype = COSE_EDDSA;
		বিরতি;
	পূর্বনির্ধারিত:
		fatal("unsupported key type %s", sshkey_type(k));
	}

	যদি ((r = prepare_fido_cred(cred, credtype, attfmt, k->sk_application,
	    attestation, challenge, &attestation_cert)) != 0)
		fatal_r(r, "prepare_fido_cred %s", argv[2]);
	যদি (fido_cred_x5c_ptr(cred) != ফাঁকা) {
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
		PEM_write(stdout, "CERTIFICATE", ফাঁকা,
		    sshbuf_ptr(attestation_cert), sshbuf_len(attestation_cert));
	}
	sshbuf_free(attestation_cert);

	logit("%s: verified %s attestation", argv[2], style);

	ফেরত (0);
}
