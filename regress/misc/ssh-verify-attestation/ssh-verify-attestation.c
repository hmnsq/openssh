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

#شامل "includes.h"

#شامل <stdint.h>
#شامل <inttypes.h>
#شامل <stdlib.h>
#شامل <stdio.h>
#شامل <unistd.h>
#شامل <stdarg.h>

#شامل "xmalloc.h"
#شامل "log.h"
#شامل "sshbuf.h"
#شامل "sshkey.h"
#شامل "authfile.h"
#شامل "ssherr.h"
#شامل "misc.h"
#شامل "digest.h"
#شامل "crypto_api.h"

#شامل <fido.h>
#شامل <openssl/x509.h>
#شامل <openssl/x509v3.h>
#شامل <openssl/bio.h>
#شامل <openssl/err.h>
#شامل <openssl/pem.h>
#شامل "openbsd-compat/openssl-compat.h"

بیرونی نویسه *__progname;

#define ATTEST_MAGIC	"ssh-sk-attest-v01"

ایستا صحیح
prepare_fido_cred(fido_cred_t *cred, صحیح credtype, ثابت نویسه *attfmt,
    ثابت نویسه *rp_id, ساختار sshbuf *b, ثابت ساختار sshbuf *challenge,
    ساختار sshbuf **attestation_certp)
{
	ساختار sshbuf *attestation_cert = پوچ, *sig = پوچ, *authdata = پوچ;
	نویسه *magic = پوچ;
	صحیح r = SSH_ERR_INTERNAL_ERROR;

	*attestation_certp = پوچ;

	/* Make sure it's the format we're expecting */
	اگر ((r = sshbuf_get_cstring(b, &magic, پوچ)) != 0) {
		error_fr(r, "parse header");
		برو out;
	}
	اگر (strcmp(magic, ATTEST_MAGIC) != 0) {
		error_f("unsupported format");
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	/* Parse the remaining fields */
	اگر ((r = sshbuf_froms(b, &attestation_cert)) != 0 ||
	    (r = sshbuf_froms(b, &sig)) != 0 ||
	    (r = sshbuf_froms(b, &authdata)) != 0 ||
	    (r = sshbuf_get_u32(b, پوچ)) != 0 || /* reserved flags */
	    (r = sshbuf_get_string_direct(b, پوچ, پوچ)) != 0) { /* reserved */
		error_fr(r, "parse body");
		برو out;
	}
	debug3_f("attestation cert len=%zu, sig len=%zu, "
	    "authdata len=%zu challenge len=%zu", sshbuf_len(attestation_cert),
	    sshbuf_len(sig), sshbuf_len(authdata), sshbuf_len(challenge));

	fido_cred_set_type(cred, credtype);
	fido_cred_set_fmt(cred, attfmt);
	fido_cred_set_clientdata(cred, sshbuf_ptr(challenge),
	    sshbuf_len(challenge));
	fido_cred_set_rp(cred, rp_id, پوچ);
	fido_cred_set_authdata(cred, sshbuf_ptr(authdata),
	    sshbuf_len(authdata));
	/* XXX set_extensions, set_rk, set_uv */
	fido_cred_set_x509(cred, sshbuf_ptr(attestation_cert),
	    sshbuf_len(attestation_cert));
	fido_cred_set_sig(cred, sshbuf_ptr(sig), sshbuf_len(sig));

	/* success */
	*attestation_certp = attestation_cert;
	attestation_cert = پوچ;
	r = 0;
 out:
	آزاد(magic);
	sshbuf_free(attestation_cert);
	sshbuf_free(sig);
	sshbuf_free(authdata);
	بازگشت r;
}

ایستا uint8_t *
get_pubkey_from_cred_ecdsa(ثابت fido_cred_t *cred, size_t *pubkey_len)
{
	ثابت uint8_t *ptr;
	uint8_t *pubkey = پوچ, *ret = پوچ;
	BIGNUM *x = پوچ, *y = پوچ;
	EC_POINT *q = پوچ;
	EC_GROUP *g = پوچ;

	اگر ((x = BN_new()) == پوچ ||
	    (y = BN_new()) == پوچ ||
	    (g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) == پوچ ||
	    (q = EC_POINT_new(g)) == پوچ) {
		error_f("libcrypto setup failed");
		برو out;
	}
	اگر ((ptr = fido_cred_pubkey_ptr(cred)) == پوچ) {
		error_f("fido_cred_pubkey_ptr failed");
		برو out;
	}
	اگر (fido_cred_pubkey_len(cred) != 64) {
		error_f("bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		برو out;
	}

	اگر (BN_bin2bn(ptr, 32, x) == پوچ ||
	    BN_bin2bn(ptr + 32, 32, y) == پوچ) {
		error_f("BN_bin2bn failed");
		برو out;
	}
	اگر (EC_POINT_set_affine_coordinates(g, q, x, y, پوچ) != 1) {
		error_f("EC_POINT_set_affine_coordinates failed");
		برو out;
	}
	*pubkey_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, پوچ, 0, پوچ);
	اگر (*pubkey_len == 0 || *pubkey_len > 2048) {
		error_f("bad pubkey length %zu", *pubkey_len);
		برو out;
	}
	اگر ((pubkey = malloc(*pubkey_len)) == پوچ) {
		error_f("malloc pubkey failed");
		برو out;
	}
	اگر (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    pubkey, *pubkey_len, پوچ) == 0) {
		error_f("EC_POINT_point2oct failed");
		برو out;
	}
	/* success */
	ret = pubkey;
	pubkey = پوچ;
 out:
	آزاد(pubkey);
	EC_POINT_free(q);
	EC_GROUP_free(g);
	BN_clear_free(x);
	BN_clear_free(y);
	بازگشت ret;
}

/* copied from sshsk_ecdsa_assemble() */
ایستا صحیح
cred_matches_کلید_ecdsa(ثابت fido_cred_t *cred, ثابت ساختار sshkey *k)
{
	ساختار sshkey *کلید = پوچ;
	ساختار sshbuf *b = پوچ;
	EC_کلید *ec = پوچ;
	uint8_t *pubkey = پوچ;
	size_t pubkey_len;
	صحیح r;

	اگر ((کلید = sshkey_new(کلید_ECDSA_SK)) == پوچ) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	کلید->ecdsa_nid = NID_X9_62_prime256v1;
	اگر ((کلید->pkey = EVP_PKEY_new()) == پوچ ||
	    (ec = EC_کلید_new_by_curve_name(کلید->ecdsa_nid)) == پوچ ||
	    (b = sshbuf_new()) == پوچ) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر ((pubkey = get_pubkey_from_cred_ecdsa(cred, &pubkey_len)) == پوچ) {
		error_f("get_pubkey_from_cred_ecdsa failed");
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	اگر ((r = sshbuf_put_string(b, pubkey, pubkey_len)) != 0) {
		error_fr(r, "sshbuf_put_string");
		برو out;
	}
	اگر ((r = sshbuf_get_eckey(b, ec)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	اگر (sshkey_ec_validate_public(EC_کلید_get0_group(ec),
	    EC_کلید_get0_public_کلید(ec)) != 0) {
		error("Authenticator returned invalid ECDSA key");
		r = SSH_ERR_کلید_INVALID_EC_مقدار;
		برو out;
	}
	اگر (EVP_PKEY_set1_EC_کلید(کلید->pkey, ec) != 1) {
		/* XXX assume it is a allocation error */
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	کلید->sk_application = xstrdup(k->sk_application); /* XXX */
	اگر (!sshkey_equal_public(کلید, k)) {
		error("sshkey_equal_public failed");
		r = SSH_ERR_INVALID_ARGUMENT;
		برو out;
	}
	r = 0; /* success */
 out:
	EC_کلید_free(ec);
	آزاد(pubkey);
	sshkey_free(کلید);
	sshbuf_free(b);
	بازگشت r;
}


/* copied from sshsk_ed25519_assemble() */
ایستا صحیح
cred_matches_کلید_ed25519(ثابت fido_cred_t *cred, ثابت ساختار sshkey *k)
{
	ساختار sshkey *کلید = پوچ;
	ثابت uint8_t *ptr;
	صحیح r = -1;

	اگر ((ptr = fido_cred_pubkey_ptr(cred)) == پوچ) {
		error_f("fido_cred_pubkey_ptr failed");
		برو out;
	}
	اگر (fido_cred_pubkey_len(cred) != ED25519_PK_SZ) {
		error_f("bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		برو out;
	}

	اگر ((کلید = sshkey_new(کلید_ED25519_SK)) == پوچ) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر ((کلید->ed25519_pk = malloc(ED25519_PK_SZ)) == پوچ) {
		error_f("malloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	memcpy(کلید->ed25519_pk, ptr, ED25519_PK_SZ);
	کلید->sk_application = xstrdup(k->sk_application); /* XXX */
	اگر (!sshkey_equal_public(کلید, k)) {
		error("sshkey_equal_public failed");
		r = SSH_ERR_INVALID_ARGUMENT;
		برو out;
	}
	r = 0; /* success */
 out:
	sshkey_free(کلید);
	بازگشت r;
}

ایستا صحیح
cred_matches_کلید(ثابت fido_cred_t *cred, ثابت ساختار sshkey *k)
{
	انتخاب (sshkey_type_plain(k->type)) {
	حالت کلید_ECDSA_SK:
		انتخاب (k->ecdsa_nid) {
		حالت NID_X9_62_prime256v1:
			بازگشت cred_matches_کلید_ecdsa(cred, k);
			بشکن;
		پیشفرض:
			fatal("Unsupported ECDSA key size");
		}
		بشکن;
	حالت کلید_ED25519_SK:
		بازگشت cred_matches_کلید_ed25519(cred, k);
	پیشفرض:
		error_f("key type %s not supported", sshkey_type(k));
		بازگشت -1;
	}
}

صحیح
اصلی(صحیح argc, نویسه **argv)
{
	LogLevel log_level = SYSLOG_LEVEL_INFO;
	صحیح r, ch, credtype = -1;
	ساختار sshkey *k = پوچ;
	ساختار sshbuf *attestation = پوچ, *challenge = پوچ;
	ساختار sshbuf *attestation_cert = پوچ;
	نویسه *fp;
	ثابت نویسه *attfmt = "packed", *style = پوچ;
	fido_cred_t *cred = پوچ;
	صحیح write_attestation_cert = 0;
	بیرونی صحیح optind;
	/* extern char *optarg; */

	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, پوچ);

	sanitise_stdfd();
	log_init(__progname, log_level, SYSLOG_FACILITY_AUTH, 1);

	وقتی ((ch = getopt(argc, argv, "UAv")) != -1) {
		انتخاب (ch) {
		حالت 'U':
			attfmt = "fido-u2f";
			بشکن;
		حالت 'A':
			write_attestation_cert = 1;
			بشکن;
		حالت 'v':
			اگر (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			وگرنه اگر (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			بشکن;
		پیشفرض:
			برو usage;
		}
	}
	log_init(__progname, log_level, SYSLOG_FACILITY_AUTH, 1);
	argv += optind;
	argc -= optind;

	اگر (argc < 3) {
 usage:
		fprintf(stderr, "usage: %s [-vAU] "
		   "pubkey challenge attestation-blob\n", __progname);
		exit(1);
	}
	اگر ((r = sshkey_load_public(argv[0], &k, پوچ)) != 0)
		fatal_r(r, "load key %s", argv[0]);
	اگر ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == پوچ)
		fatal("sshkey_fingerprint failed");
	debug2("key %s: %s %s", argv[2], sshkey_type(k), fp);
	آزاد(fp);
	اگر ((r = sshbuf_load_file(argv[1], &challenge)) != 0)
		fatal_r(r, "load challenge %s", argv[1]);
	اگر ((r = sshbuf_load_file(argv[2], &attestation)) != 0)
		fatal_r(r, "load attestation %s", argv[2]);
	اگر ((cred = fido_cred_new()) == پوچ)
		fatal("fido_cred_new failed");

	انتخاب (sshkey_type_plain(k->type)) {
	حالت کلید_ECDSA_SK:
		انتخاب (k->ecdsa_nid) {
		حالت NID_X9_62_prime256v1:
			credtype = COSE_ES256;
			بشکن;
		پیشفرض:
			fatal("Unsupported ECDSA key size");
		}
		بشکن;
	حالت کلید_ED25519_SK:
		credtype = COSE_EDDSA;
		بشکن;
	پیشفرض:
		fatal("unsupported key type %s", sshkey_type(k));
	}

	اگر ((r = prepare_fido_cred(cred, credtype, attfmt, k->sk_application,
	    attestation, challenge, &attestation_cert)) != 0)
		fatal_r(r, "prepare_fido_cred %s", argv[2]);
	اگر (fido_cred_x5c_ptr(cred) != پوچ) {
		debug("basic attestation");
		اگر ((r = fido_cred_verify(cred)) != FIDO_OK)
			fatal("basic attestation failed");
		style = "basic";
	} وگرنه {
		debug("self attestation");
		اگر ((r = fido_cred_verify_self(cred)) != FIDO_OK)
			fatal("self attestation failed");
		style = "self";
	}
	اگر (cred_matches_کلید(cred, k) != 0)
		fatal("cred authdata does not match key");

	fido_cred_free(&cred);

	اگر (write_attestation_cert) {
		PEM_write(stdout, "CERTIFICATE", پوچ,
		    sshbuf_ptr(attestation_cert), sshbuf_len(attestation_cert));
	}
	sshbuf_free(attestation_cert);

	logit("%s: verified %s attestation", argv[2], style);

	بازگشت (0);
}
