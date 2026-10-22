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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <inttypes.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>

#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "authfile.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "digest.h"
#ଅନ୍ତର୍ଭାଵ "crypto_api.h"

#ଅନ୍ତର୍ଭାଵ <fido.h>
#ଅନ୍ତର୍ଭାଵ <openssl/x509.h>
#ଅନ୍ତର୍ଭାଵ <openssl/x509v3.h>
#ଅନ୍ତର୍ଭାଵ <openssl/bio.h>
#ଅନ୍ତର୍ଭାଵ <openssl/err.h>
#ଅନ୍ତର୍ଭାଵ <openssl/pem.h>
#ଅନ୍ତର୍ଭାଵ "openbsd-compat/openssl-compat.h"

ବାହ୍ୟ ଅକ୍ଷର *__progname;

#define ATTEST_MAGIC	"ssh-sk-attest-v01"

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
prepare_fido_cred(fido_cred_t *cred, ପୂର୍ଣ୍ଣସଂଖ୍ୟା credtype, ଅଚଳ ଅକ୍ଷର *attfmt,
    ଅଚଳ ଅକ୍ଷର *rp_id, ସଂରଚନା sshbuf *b, ଅଚଳ ସଂରଚନା sshbuf *challenge,
    ସଂରଚନା sshbuf **attestation_certp)
{
	ସଂରଚନା sshbuf *attestation_cert = ଖାଲି, *sig = ଖାଲି, *authdata = ଖାଲି;
	ଅକ୍ଷର *magic = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;

	*attestation_certp = ଖାଲି;

	/* Make sure it's the format we're expecting */
	ଯଦି ((r = sshbuf_get_cstring(b, &magic, ଖାଲି)) != 0) {
		error_fr(r, "parse header");
		ଯାଅ out;
	}
	ଯଦି (strcmp(magic, ATTEST_MAGIC) != 0) {
		error_f("unsupported format");
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	/* Parse the remaining fields */
	ଯଦି ((r = sshbuf_froms(b, &attestation_cert)) != 0 ||
	    (r = sshbuf_froms(b, &sig)) != 0 ||
	    (r = sshbuf_froms(b, &authdata)) != 0 ||
	    (r = sshbuf_get_u32(b, ଖାଲି)) != 0 || /* reserved flags */
	    (r = sshbuf_get_string_direct(b, ଖାଲି, ଖାଲି)) != 0) { /* reserved */
		error_fr(r, "parse body");
		ଯାଅ out;
	}
	debug3_f("attestation cert len=%zu, sig len=%zu, "
	    "authdata len=%zu challenge len=%zu", sshbuf_len(attestation_cert),
	    sshbuf_len(sig), sshbuf_len(authdata), sshbuf_len(challenge));

	fido_cred_set_type(cred, credtype);
	fido_cred_set_fmt(cred, attfmt);
	fido_cred_set_clientdata(cred, sshbuf_ptr(challenge),
	    sshbuf_len(challenge));
	fido_cred_set_rp(cred, rp_id, ଖାଲି);
	fido_cred_set_authdata(cred, sshbuf_ptr(authdata),
	    sshbuf_len(authdata));
	/* XXX set_extensions, set_rk, set_uv */
	fido_cred_set_x509(cred, sshbuf_ptr(attestation_cert),
	    sshbuf_len(attestation_cert));
	fido_cred_set_sig(cred, sshbuf_ptr(sig), sshbuf_len(sig));

	/* success */
	*attestation_certp = attestation_cert;
	attestation_cert = ଖାଲି;
	r = 0;
 out:
	ମୁକ୍ତ(magic);
	sshbuf_free(attestation_cert);
	sshbuf_free(sig);
	sshbuf_free(authdata);
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର uint8_t *
get_pubkey_from_cred_ecdsa(ଅଚଳ fido_cred_t *cred, size_t *pubkey_len)
{
	ଅଚଳ uint8_t *ptr;
	uint8_t *pubkey = ଖାଲି, *ret = ଖାଲି;
	BIGNUM *x = ଖାଲି, *y = ଖାଲି;
	EC_POINT *q = ଖାଲି;
	EC_GROUP *g = ଖାଲି;

	ଯଦି ((x = BN_new()) == ଖାଲି ||
	    (y = BN_new()) == ଖାଲି ||
	    (g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) == ଖାଲି ||
	    (q = EC_POINT_new(g)) == ଖାଲି) {
		error_f("libcrypto setup failed");
		ଯାଅ out;
	}
	ଯଦି ((ptr = fido_cred_pubkey_ptr(cred)) == ଖାଲି) {
		error_f("fido_cred_pubkey_ptr failed");
		ଯାଅ out;
	}
	ଯଦି (fido_cred_pubkey_len(cred) != 64) {
		error_f("bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		ଯାଅ out;
	}

	ଯଦି (BN_bin2bn(ptr, 32, x) == ଖାଲି ||
	    BN_bin2bn(ptr + 32, 32, y) == ଖାଲି) {
		error_f("BN_bin2bn failed");
		ଯାଅ out;
	}
	ଯଦି (EC_POINT_set_affine_coordinates(g, q, x, y, ଖାଲି) != 1) {
		error_f("EC_POINT_set_affine_coordinates failed");
		ଯାଅ out;
	}
	*pubkey_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, ଖାଲି, 0, ଖାଲି);
	ଯଦି (*pubkey_len == 0 || *pubkey_len > 2048) {
		error_f("bad pubkey length %zu", *pubkey_len);
		ଯାଅ out;
	}
	ଯଦି ((pubkey = malloc(*pubkey_len)) == ଖାଲି) {
		error_f("malloc pubkey failed");
		ଯାଅ out;
	}
	ଯଦି (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    pubkey, *pubkey_len, ଖାଲି) == 0) {
		error_f("EC_POINT_point2oct failed");
		ଯାଅ out;
	}
	/* success */
	ret = pubkey;
	pubkey = ଖାଲି;
 out:
	ମୁକ୍ତ(pubkey);
	EC_POINT_free(q);
	EC_GROUP_free(g);
	BN_clear_free(x);
	BN_clear_free(y);
	ଫେରନ୍ତୁ ret;
}

/* copied from sshsk_ecdsa_assemble() */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
cred_matches_ଚାବି_ecdsa(ଅଚଳ fido_cred_t *cred, ଅଚଳ ସଂରଚନା sshkey *k)
{
	ସଂରଚନା sshkey *ଚାବି = ଖାଲି;
	ସଂରଚନା sshbuf *b = ଖାଲି;
	EC_ଚାବି *ec = ଖାଲି;
	uint8_t *pubkey = ଖାଲି;
	size_t pubkey_len;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((ଚାବି = sshkey_new(ଚାବି_ECDSA_SK)) == ଖାଲି) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଚାବି->ecdsa_nid = NID_X9_62_prime256v1;
	ଯଦି ((ଚାବି->pkey = EVP_PKEY_new()) == ଖାଲି ||
	    (ec = EC_ଚାବି_new_by_curve_name(ଚାବି->ecdsa_nid)) == ଖାଲି ||
	    (b = sshbuf_new()) == ଖାଲି) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି ((pubkey = get_pubkey_from_cred_ecdsa(cred, &pubkey_len)) == ଖାଲି) {
		error_f("get_pubkey_from_cred_ecdsa failed");
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	ଯଦି ((r = sshbuf_put_string(b, pubkey, pubkey_len)) != 0) {
		error_fr(r, "sshbuf_put_string");
		ଯାଅ out;
	}
	ଯଦି ((r = sshbuf_get_eckey(b, ec)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	ଯଦି (sshkey_ec_validate_public(EC_ଚାବି_get0_group(ec),
	    EC_ଚାବି_get0_public_ଚାବି(ec)) != 0) {
		error("Authenticator returned invalid ECDSA key");
		r = SSH_ERR_ଚାବି_INVALID_EC_ମୂଲ୍ୟ;
		ଯାଅ out;
	}
	ଯଦି (EVP_PKEY_set1_EC_ଚାବି(ଚାବି->pkey, ec) != 1) {
		/* XXX assume it is a allocation error */
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଚାବି->sk_application = xstrdup(k->sk_application); /* XXX */
	ଯଦି (!sshkey_equal_public(ଚାବି, k)) {
		error("sshkey_equal_public failed");
		r = SSH_ERR_INVALID_ARGUMENT;
		ଯାଅ out;
	}
	r = 0; /* success */
 out:
	EC_ଚାବି_free(ec);
	ମୁକ୍ତ(pubkey);
	sshkey_free(ଚାବି);
	sshbuf_free(b);
	ଫେରନ୍ତୁ r;
}


/* copied from sshsk_ed25519_assemble() */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
cred_matches_ଚାବି_ed25519(ଅଚଳ fido_cred_t *cred, ଅଚଳ ସଂରଚନା sshkey *k)
{
	ସଂରଚନା sshkey *ଚାବି = ଖାଲି;
	ଅଚଳ uint8_t *ptr;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = -1;

	ଯଦି ((ptr = fido_cred_pubkey_ptr(cred)) == ଖାଲି) {
		error_f("fido_cred_pubkey_ptr failed");
		ଯାଅ out;
	}
	ଯଦି (fido_cred_pubkey_len(cred) != ED25519_PK_SZ) {
		error_f("bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		ଯାଅ out;
	}

	ଯଦି ((ଚାବି = sshkey_new(ଚାବି_ED25519_SK)) == ଖାଲି) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି ((ଚାବି->ed25519_pk = malloc(ED25519_PK_SZ)) == ଖାଲି) {
		error_f("malloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	memcpy(ଚାବି->ed25519_pk, ptr, ED25519_PK_SZ);
	ଚାବି->sk_application = xstrdup(k->sk_application); /* XXX */
	ଯଦି (!sshkey_equal_public(ଚାବି, k)) {
		error("sshkey_equal_public failed");
		r = SSH_ERR_INVALID_ARGUMENT;
		ଯାଅ out;
	}
	r = 0; /* success */
 out:
	sshkey_free(ଚାବି);
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
cred_matches_ଚାବି(ଅଚଳ fido_cred_t *cred, ଅଚଳ ସଂରଚନା sshkey *k)
{
	ବାଛ (sshkey_type_plain(k->type)) {
	ସ୍ଥିତି ଚାବି_ECDSA_SK:
		ବାଛ (k->ecdsa_nid) {
		ସ୍ଥିତି NID_X9_62_prime256v1:
			ଫେରନ୍ତୁ cred_matches_ଚାବି_ecdsa(cred, k);
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			fatal("Unsupported ECDSA key size");
		}
		ଭାଙ୍ଗ;
	ସ୍ଥିତି ଚାବି_ED25519_SK:
		ଫେରନ୍ତୁ cred_matches_ଚାବି_ed25519(cred, k);
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		error_f("key type %s not supported", sshkey_type(k));
		ଫେରନ୍ତୁ -1;
	}
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ମୁଖ୍ୟ(ପୂର୍ଣ୍ଣସଂଖ୍ୟା argc, ଅକ୍ଷର **argv)
{
	LogLevel log_level = SYSLOG_LEVEL_INFO;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, ch, credtype = -1;
	ସଂରଚନା sshkey *k = ଖାଲି;
	ସଂରଚନା sshbuf *attestation = ଖାଲି, *challenge = ଖାଲି;
	ସଂରଚନା sshbuf *attestation_cert = ଖାଲି;
	ଅକ୍ଷର *fp;
	ଅଚଳ ଅକ୍ଷର *attfmt = "packed", *style = ଖାଲି;
	fido_cred_t *cred = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା write_attestation_cert = 0;
	ବାହ୍ୟ ପୂର୍ଣ୍ଣସଂଖ୍ୟା optind;
	/* extern char *optarg; */

	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, ଖାଲି);

	sanitise_stdfd();
	log_init(__progname, log_level, SYSLOG_FACILITY_AUTH, 1);

	ଯେତେବେଳେ ((ch = getopt(argc, argv, "UAv")) != -1) {
		ବାଛ (ch) {
		ସ୍ଥିତି 'U':
			attfmt = "fido-u2f";
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'A':
			write_attestation_cert = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'v':
			ଯଦି (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			ଅନ୍ୟଥା ଯଦି (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			ଯାଅ usage;
		}
	}
	log_init(__progname, log_level, SYSLOG_FACILITY_AUTH, 1);
	argv += optind;
	argc -= optind;

	ଯଦି (argc < 3) {
 usage:
		fprintf(stderr, "usage: %s [-vAU] "
		   "pubkey challenge attestation-blob\n", __progname);
		exit(1);
	}
	ଯଦି ((r = sshkey_load_public(argv[0], &k, ଖାଲି)) != 0)
		fatal_r(r, "load key %s", argv[0]);
	ଯଦି ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ଖାଲି)
		fatal("sshkey_fingerprint failed");
	debug2("key %s: %s %s", argv[2], sshkey_type(k), fp);
	ମୁକ୍ତ(fp);
	ଯଦି ((r = sshbuf_load_file(argv[1], &challenge)) != 0)
		fatal_r(r, "load challenge %s", argv[1]);
	ଯଦି ((r = sshbuf_load_file(argv[2], &attestation)) != 0)
		fatal_r(r, "load attestation %s", argv[2]);
	ଯଦି ((cred = fido_cred_new()) == ଖାଲି)
		fatal("fido_cred_new failed");

	ବାଛ (sshkey_type_plain(k->type)) {
	ସ୍ଥିତି ଚାବି_ECDSA_SK:
		ବାଛ (k->ecdsa_nid) {
		ସ୍ଥିତି NID_X9_62_prime256v1:
			credtype = COSE_ES256;
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			fatal("Unsupported ECDSA key size");
		}
		ଭାଙ୍ଗ;
	ସ୍ଥିତି ଚାବି_ED25519_SK:
		credtype = COSE_EDDSA;
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		fatal("unsupported key type %s", sshkey_type(k));
	}

	ଯଦି ((r = prepare_fido_cred(cred, credtype, attfmt, k->sk_application,
	    attestation, challenge, &attestation_cert)) != 0)
		fatal_r(r, "prepare_fido_cred %s", argv[2]);
	ଯଦି (fido_cred_x5c_ptr(cred) != ଖାଲି) {
		debug("basic attestation");
		ଯଦି ((r = fido_cred_verify(cred)) != FIDO_OK)
			fatal("basic attestation failed");
		style = "basic";
	} ଅନ୍ୟଥା {
		debug("self attestation");
		ଯଦି ((r = fido_cred_verify_self(cred)) != FIDO_OK)
			fatal("self attestation failed");
		style = "self";
	}
	ଯଦି (cred_matches_ଚାବି(cred, k) != 0)
		fatal("cred authdata does not match key");

	fido_cred_free(&cred);

	ଯଦି (write_attestation_cert) {
		PEM_write(stdout, "CERTIFICATE", ଖାଲି,
		    sshbuf_ptr(attestation_cert), sshbuf_len(attestation_cert));
	}
	sshbuf_free(attestation_cert);

	logit("%s: verified %s attestation", argv[2], style);

	ଫେରନ୍ତୁ (0);
}
