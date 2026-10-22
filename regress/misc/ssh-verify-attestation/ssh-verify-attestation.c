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

#ضمن "includes.h"

#ضمن <stdint.h>
#ضمن <inttypes.h>
#ضمن <stdlib.h>
#ضمن <stdio.h>
#ضمن <unistd.h>
#ضمن <stdarg.h>

#ضمن "xmalloc.h"
#ضمن "log.h"
#ضمن "sshbuf.h"
#ضمن "sshkey.h"
#ضمن "authfile.h"
#ضمن "ssherr.h"
#ضمن "misc.h"
#ضمن "digest.h"
#ضمن "crypto_api.h"

#ضمن <fido.h>
#ضمن <openssl/x509.h>
#ضمن <openssl/x509v3.h>
#ضمن <openssl/bio.h>
#ضمن <openssl/err.h>
#ضمن <openssl/pem.h>
#ضمن "openbsd-compat/openssl-compat.h"

خارجي حرف *__progname;

#define ATTEST_MAGIC	"ssh-sk-attest-v01"

ساكن صحيح
prepare_fido_cred(fido_cred_t *cred, صحيح credtype, ثابت حرف *attfmt,
    ثابت حرف *rp_id, بنية sshbuf *b, ثابت بنية sshbuf *challenge,
    بنية sshbuf **attestation_certp)
{
	بنية sshbuf *attestation_cert = عدم, *sig = عدم, *authdata = عدم;
	حرف *magic = عدم;
	صحيح r = SSH_ERR_INTERNAL_ERROR;

	*attestation_certp = عدم;

	/* Make sure it's the format we're expecting */
	𐤀𐤌 ((r = sshbuf_get_cstring(b, &magic, عدم)) != 0) {
		error_fr(r, "parse header");
		اذهب out;
	}
	𐤀𐤌 (strcmp(magic, ATTEST_MAGIC) != 0) {
		error_f("unsupported format");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	/* Parse the remaining fields */
	𐤀𐤌 ((r = sshbuf_froms(b, &attestation_cert)) != 0 ||
	    (r = sshbuf_froms(b, &sig)) != 0 ||
	    (r = sshbuf_froms(b, &authdata)) != 0 ||
	    (r = sshbuf_get_u32(b, عدم)) != 0 || /* reserved flags */
	    (r = sshbuf_get_string_direct(b, عدم, عدم)) != 0) { /* reserved */
		error_fr(r, "parse body");
		اذهب out;
	}
	debug3_f("attestation cert len=%zu, sig len=%zu, "
	    "authdata len=%zu challenge len=%zu", sshbuf_len(attestation_cert),
	    sshbuf_len(sig), sshbuf_len(authdata), sshbuf_len(challenge));

	fido_cred_set_type(cred, credtype);
	fido_cred_set_fmt(cred, attfmt);
	fido_cred_set_clientdata(cred, sshbuf_ptr(challenge),
	    sshbuf_len(challenge));
	fido_cred_set_rp(cred, rp_id, عدم);
	fido_cred_set_authdata(cred, sshbuf_ptr(authdata),
	    sshbuf_len(authdata));
	/* XXX set_extensions, set_rk, set_uv */
	fido_cred_set_x509(cred, sshbuf_ptr(attestation_cert),
	    sshbuf_len(attestation_cert));
	fido_cred_set_sig(cred, sshbuf_ptr(sig), sshbuf_len(sig));

	/* success */
	*attestation_certp = attestation_cert;
	attestation_cert = عدم;
	r = 0;
 out:
	حرر(magic);
	sshbuf_free(attestation_cert);
	sshbuf_free(sig);
	sshbuf_free(authdata);
	أرجع r;
}

ساكن uint8_t *
get_pubkey_from_cred_ecdsa(ثابت fido_cred_t *cred, size_t *pubkey_len)
{
	ثابت uint8_t *ptr;
	uint8_t *pubkey = عدم, *ret = عدم;
	BIGNUM *x = عدم, *y = عدم;
	EC_POINT *q = عدم;
	EC_GROUP *g = عدم;

	𐤀𐤌 ((x = BN_new()) == عدم ||
	    (y = BN_new()) == عدم ||
	    (g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) == عدم ||
	    (q = EC_POINT_new(g)) == عدم) {
		error_f("libcrypto setup failed");
		اذهب out;
	}
	𐤀𐤌 ((ptr = fido_cred_pubkey_ptr(cred)) == عدم) {
		error_f("fido_cred_pubkey_ptr failed");
		اذهب out;
	}
	𐤀𐤌 (fido_cred_pubkey_len(cred) != 64) {
		error_f("bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		اذهب out;
	}

	𐤀𐤌 (BN_bin2bn(ptr, 32, x) == عدم ||
	    BN_bin2bn(ptr + 32, 32, y) == عدم) {
		error_f("BN_bin2bn failed");
		اذهب out;
	}
	𐤀𐤌 (EC_POINT_set_affine_coordinates(g, q, x, y, عدم) != 1) {
		error_f("EC_POINT_set_affine_coordinates failed");
		اذهب out;
	}
	*pubkey_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, عدم, 0, عدم);
	𐤀𐤌 (*pubkey_len == 0 || *pubkey_len > 2048) {
		error_f("bad pubkey length %zu", *pubkey_len);
		اذهب out;
	}
	𐤀𐤌 ((pubkey = malloc(*pubkey_len)) == عدم) {
		error_f("malloc pubkey failed");
		اذهب out;
	}
	𐤀𐤌 (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    pubkey, *pubkey_len, عدم) == 0) {
		error_f("EC_POINT_point2oct failed");
		اذهب out;
	}
	/* success */
	ret = pubkey;
	pubkey = عدم;
 out:
	حرر(pubkey);
	EC_POINT_free(q);
	EC_GROUP_free(g);
	BN_clear_free(x);
	BN_clear_free(y);
	أرجع ret;
}

/* copied from sshsk_ecdsa_assemble() */
ساكن صحيح
cred_matches_key_ecdsa(ثابت fido_cred_t *cred, ثابت بنية sshkey *k)
{
	بنية sshkey *key = عدم;
	بنية sshbuf *b = عدم;
	EC_KEY *ec = عدم;
	uint8_t *pubkey = عدم;
	size_t pubkey_len;
	صحيح r;

	𐤀𐤌 ((key = sshkey_new(KEY_ECDSA_SK)) == عدم) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	key->ecdsa_nid = NID_X9_62_prime256v1;
	𐤀𐤌 ((key->pkey = EVP_PKEY_new()) == عدم ||
	    (ec = EC_KEY_new_by_curve_name(key->ecdsa_nid)) == عدم ||
	    (b = sshbuf_new()) == عدم) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	𐤀𐤌 ((pubkey = get_pubkey_from_cred_ecdsa(cred, &pubkey_len)) == عدم) {
		error_f("get_pubkey_from_cred_ecdsa failed");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	𐤀𐤌 ((r = sshbuf_put_string(b, pubkey, pubkey_len)) != 0) {
		error_fr(r, "sshbuf_put_string");
		اذهب out;
	}
	𐤀𐤌 ((r = sshbuf_get_eckey(b, ec)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	𐤀𐤌 (sshkey_ec_validate_public(EC_KEY_get0_group(ec),
	    EC_KEY_get0_public_key(ec)) != 0) {
		error("Authenticator returned invalid ECDSA key");
		r = SSH_ERR_KEY_INVALID_EC_VALUE;
		اذهب out;
	}
	𐤀𐤌 (EVP_PKEY_set1_EC_KEY(key->pkey, ec) != 1) {
		/* XXX assume it is a allocation error */
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	key->sk_application = xstrdup(k->sk_application); /* XXX */
	𐤀𐤌 (!sshkey_equal_public(key, k)) {
		error("sshkey_equal_public failed");
		r = SSH_ERR_INVALID_ARGUMENT;
		اذهب out;
	}
	r = 0; /* success */
 out:
	EC_KEY_free(ec);
	حرر(pubkey);
	sshkey_free(key);
	sshbuf_free(b);
	أرجع r;
}


/* copied from sshsk_ed25519_assemble() */
ساكن صحيح
cred_matches_key_ed25519(ثابت fido_cred_t *cred, ثابت بنية sshkey *k)
{
	بنية sshkey *key = عدم;
	ثابت uint8_t *ptr;
	صحيح r = -1;

	𐤀𐤌 ((ptr = fido_cred_pubkey_ptr(cred)) == عدم) {
		error_f("fido_cred_pubkey_ptr failed");
		اذهب out;
	}
	𐤀𐤌 (fido_cred_pubkey_len(cred) != ED25519_PK_SZ) {
		error_f("bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		اذهب out;
	}

	𐤀𐤌 ((key = sshkey_new(KEY_ED25519_SK)) == عدم) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	𐤀𐤌 ((key->ed25519_pk = malloc(ED25519_PK_SZ)) == عدم) {
		error_f("malloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	memcpy(key->ed25519_pk, ptr, ED25519_PK_SZ);
	key->sk_application = xstrdup(k->sk_application); /* XXX */
	𐤀𐤌 (!sshkey_equal_public(key, k)) {
		error("sshkey_equal_public failed");
		r = SSH_ERR_INVALID_ARGUMENT;
		اذهب out;
	}
	r = 0; /* success */
 out:
	sshkey_free(key);
	أرجع r;
}

ساكن صحيح
cred_matches_key(ثابت fido_cred_t *cred, ثابت بنية sshkey *k)
{
	بدل (sshkey_type_plain(k->type)) {
	حالة KEY_ECDSA_SK:
		بدل (k->ecdsa_nid) {
		حالة NID_X9_62_prime256v1:
			أرجع cred_matches_key_ecdsa(cred, k);
			اكسر;
		افتراضي:
			fatal("Unsupported ECDSA key size");
		}
		اكسر;
	حالة KEY_ED25519_SK:
		أرجع cred_matches_key_ed25519(cred, k);
	افتراضي:
		error_f("key type %s not supported", sshkey_type(k));
		أرجع -1;
	}
}

صحيح
main(صحيح argc, حرف **argv)
{
	LogLevel log_level = SYSLOG_LEVEL_INFO;
	صحيح r, ch, credtype = -1;
	بنية sshkey *k = عدم;
	بنية sshbuf *attestation = عدم, *challenge = عدم;
	بنية sshbuf *attestation_cert = عدم;
	حرف *fp;
	ثابت حرف *attfmt = "packed", *style = عدم;
	fido_cred_t *cred = عدم;
	صحيح write_attestation_cert = 0;
	خارجي صحيح optind;
	/* extern char *optarg; */

	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, عدم);

	sanitise_stdfd();
	log_init(__progname, log_level, SYSLOG_FACILITY_AUTH, 1);

	طالما ((ch = getopt(argc, argv, "UAv")) != -1) {
		بدل (ch) {
		حالة 'U':
			attfmt = "fido-u2f";
			اكسر;
		حالة 'A':
			write_attestation_cert = 1;
			اكسر;
		حالة 'v':
			𐤀𐤌 (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			وإلا 𐤀𐤌 (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			اكسر;
		افتراضي:
			اذهب usage;
		}
	}
	log_init(__progname, log_level, SYSLOG_FACILITY_AUTH, 1);
	argv += optind;
	argc -= optind;

	𐤀𐤌 (argc < 3) {
 usage:
		fprintf(stderr, "usage: %s [-vAU] "
		   "pubkey challenge attestation-blob\n", __progname);
		exit(1);
	}
	𐤀𐤌 ((r = sshkey_load_public(argv[0], &k, عدم)) != 0)
		fatal_r(r, "load key %s", argv[0]);
	𐤀𐤌 ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == عدم)
		fatal("sshkey_fingerprint failed");
	debug2("key %s: %s %s", argv[2], sshkey_type(k), fp);
	حرر(fp);
	𐤀𐤌 ((r = sshbuf_load_file(argv[1], &challenge)) != 0)
		fatal_r(r, "load challenge %s", argv[1]);
	𐤀𐤌 ((r = sshbuf_load_file(argv[2], &attestation)) != 0)
		fatal_r(r, "load attestation %s", argv[2]);
	𐤀𐤌 ((cred = fido_cred_new()) == عدم)
		fatal("fido_cred_new failed");

	بدل (sshkey_type_plain(k->type)) {
	حالة KEY_ECDSA_SK:
		بدل (k->ecdsa_nid) {
		حالة NID_X9_62_prime256v1:
			credtype = COSE_ES256;
			اكسر;
		افتراضي:
			fatal("Unsupported ECDSA key size");
		}
		اكسر;
	حالة KEY_ED25519_SK:
		credtype = COSE_EDDSA;
		اكسر;
	افتراضي:
		fatal("unsupported key type %s", sshkey_type(k));
	}

	𐤀𐤌 ((r = prepare_fido_cred(cred, credtype, attfmt, k->sk_application,
	    attestation, challenge, &attestation_cert)) != 0)
		fatal_r(r, "prepare_fido_cred %s", argv[2]);
	𐤀𐤌 (fido_cred_x5c_ptr(cred) != عدم) {
		debug("basic attestation");
		𐤀𐤌 ((r = fido_cred_verify(cred)) != FIDO_OK)
			fatal("basic attestation failed");
		style = "basic";
	} وإلا {
		debug("self attestation");
		𐤀𐤌 ((r = fido_cred_verify_self(cred)) != FIDO_OK)
			fatal("self attestation failed");
		style = "self";
	}
	𐤀𐤌 (cred_matches_key(cred, k) != 0)
		fatal("cred authdata does not match key");

	fido_cred_free(&cred);

	𐤀𐤌 (write_attestation_cert) {
		PEM_write(stdout, "CERTIFICATE", عدم,
		    sshbuf_ptr(attestation_cert), sshbuf_len(attestation_cert));
	}
	sshbuf_free(attestation_cert);

	logit("%s: verified %s attestation", argv[2], style);

	أرجع (0);
}
