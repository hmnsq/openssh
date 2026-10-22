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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <inttypes.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "authfile.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "digest.h"
#ಅನ್ತರ್ಭಾವ "crypto_api.h"

#ಅನ್ತರ್ಭಾವ <fido.h>
#ಅನ್ತರ್ಭಾವ <openssl/x509.h>
#ಅನ್ತರ್ಭಾವ <openssl/x509v3.h>
#ಅನ್ತರ್ಭಾವ <openssl/bio.h>
#ಅನ್ತರ್ಭಾವ <openssl/err.h>
#ಅನ್ತರ್ಭಾವ <openssl/pem.h>
#ಅನ್ತರ್ಭಾವ "openbsd-compat/openssl-compat.h"

ಬಾಹ್ಯ ವರ್ಣ *__progname;

#define ATTEST_MAGIC	"ssh-sk-attest-v01"

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
prepare_fido_cred(fido_cred_t *cred, ಪೂರ್ಣಾಙ್ಕ credtype, ಧ್ರುವ ವರ್ಣ *attfmt,
    ಧ್ರುವ ವರ್ಣ *rp_id, ಸಂರಚನಾ sshbuf *b, ಧ್ರುವ ಸಂರಚನಾ sshbuf *challenge,
    ಸಂರಚನಾ sshbuf **attestation_certp)
{
	ಸಂರಚನಾ sshbuf *attestation_cert = ರಿಕ್ತ, *sig = ರಿಕ್ತ, *authdata = ರಿಕ್ತ;
	ವರ್ಣ *magic = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;

	*attestation_certp = ರಿಕ್ತ;

	/* Make sure it's the format we're expecting */
	ಯದಿ ((r = sshbuf_get_cstring(b, &magic, ರಿಕ್ತ)) != 0) {
		error_fr(r, "parse header");
		ಗಚ್ಛ out;
	}
	ಯದಿ (strcmp(magic, ATTEST_MAGIC) != 0) {
		error_f("unsupported format");
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	/* Parse the remaining fields */
	ಯದಿ ((r = sshbuf_froms(b, &attestation_cert)) != 0 ||
	    (r = sshbuf_froms(b, &sig)) != 0 ||
	    (r = sshbuf_froms(b, &authdata)) != 0 ||
	    (r = sshbuf_get_u32(b, ರಿಕ್ತ)) != 0 || /* reserved flags */
	    (r = sshbuf_get_string_direct(b, ರಿಕ್ತ, ರಿಕ್ತ)) != 0) { /* reserved */
		error_fr(r, "parse body");
		ಗಚ್ಛ out;
	}
	debug3_f("attestation cert len=%zu, sig len=%zu, "
	    "authdata len=%zu challenge len=%zu", sshbuf_len(attestation_cert),
	    sshbuf_len(sig), sshbuf_len(authdata), sshbuf_len(challenge));

	fido_cred_set_type(cred, credtype);
	fido_cred_set_fmt(cred, attfmt);
	fido_cred_set_clientdata(cred, sshbuf_ptr(challenge),
	    sshbuf_len(challenge));
	fido_cred_set_rp(cred, rp_id, ರಿಕ್ತ);
	fido_cred_set_authdata(cred, sshbuf_ptr(authdata),
	    sshbuf_len(authdata));
	/* XXX set_extensions, set_rk, set_uv */
	fido_cred_set_x509(cred, sshbuf_ptr(attestation_cert),
	    sshbuf_len(attestation_cert));
	fido_cred_set_sig(cred, sshbuf_ptr(sig), sshbuf_len(sig));

	/* success */
	*attestation_certp = attestation_cert;
	attestation_cert = ರಿಕ್ತ;
	r = 0;
 out:
	ಮುಕ್ತ(magic);
	sshbuf_free(attestation_cert);
	sshbuf_free(sig);
	sshbuf_free(authdata);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ uint8_t *
get_pubkey_from_cred_ecdsa(ಧ್ರುವ fido_cred_t *cred, size_t *pubkey_len)
{
	ಧ್ರುವ uint8_t *ptr;
	uint8_t *pubkey = ರಿಕ್ತ, *ret = ರಿಕ್ತ;
	BIGNUM *x = ರಿಕ್ತ, *y = ರಿಕ್ತ;
	EC_POINT *q = ರಿಕ್ತ;
	EC_GROUP *g = ರಿಕ್ತ;

	ಯದಿ ((x = BN_new()) == ರಿಕ್ತ ||
	    (y = BN_new()) == ರಿಕ್ತ ||
	    (g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) == ರಿಕ್ತ ||
	    (q = EC_POINT_new(g)) == ರಿಕ್ತ) {
		error_f("libcrypto setup failed");
		ಗಚ್ಛ out;
	}
	ಯದಿ ((ptr = fido_cred_pubkey_ptr(cred)) == ರಿಕ್ತ) {
		error_f("fido_cred_pubkey_ptr failed");
		ಗಚ್ಛ out;
	}
	ಯದಿ (fido_cred_pubkey_len(cred) != 64) {
		error_f("bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		ಗಚ್ಛ out;
	}

	ಯದಿ (BN_bin2bn(ptr, 32, x) == ರಿಕ್ತ ||
	    BN_bin2bn(ptr + 32, 32, y) == ರಿಕ್ತ) {
		error_f("BN_bin2bn failed");
		ಗಚ್ಛ out;
	}
	ಯದಿ (EC_POINT_set_affine_coordinates(g, q, x, y, ರಿಕ್ತ) != 1) {
		error_f("EC_POINT_set_affine_coordinates failed");
		ಗಚ್ಛ out;
	}
	*pubkey_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, ರಿಕ್ತ, 0, ರಿಕ್ತ);
	ಯದಿ (*pubkey_len == 0 || *pubkey_len > 2048) {
		error_f("bad pubkey length %zu", *pubkey_len);
		ಗಚ್ಛ out;
	}
	ಯದಿ ((pubkey = malloc(*pubkey_len)) == ರಿಕ್ತ) {
		error_f("malloc pubkey failed");
		ಗಚ್ಛ out;
	}
	ಯದಿ (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    pubkey, *pubkey_len, ರಿಕ್ತ) == 0) {
		error_f("EC_POINT_point2oct failed");
		ಗಚ್ಛ out;
	}
	/* success */
	ret = pubkey;
	pubkey = ರಿಕ್ತ;
 out:
	ಮುಕ್ತ(pubkey);
	EC_POINT_free(q);
	EC_GROUP_free(g);
	BN_clear_free(x);
	BN_clear_free(y);
	ಪ್ರತ್ಯಾಗಮ ret;
}

/* copied from sshsk_ecdsa_assemble() */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
cred_matches_ಕೀಲಿ_ecdsa(ಧ್ರುವ fido_cred_t *cred, ಧ್ರುವ ಸಂರಚನಾ sshkey *k)
{
	ಸಂರಚನಾ sshkey *ಕೀಲಿ = ರಿಕ್ತ;
	ಸಂರಚನಾ sshbuf *b = ರಿಕ್ತ;
	EC_ಕೀಲಿ *ec = ರಿಕ್ತ;
	uint8_t *pubkey = ರಿಕ್ತ;
	size_t pubkey_len;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((ಕೀಲಿ = sshkey_new(ಕೀಲಿ_ECDSA_SK)) == ರಿಕ್ತ) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಕೀಲಿ->ecdsa_nid = NID_X9_62_prime256v1;
	ಯದಿ ((ಕೀಲಿ->pkey = EVP_PKEY_new()) == ರಿಕ್ತ ||
	    (ec = EC_ಕೀಲಿ_new_by_curve_name(ಕೀಲಿ->ecdsa_nid)) == ರಿಕ್ತ ||
	    (b = sshbuf_new()) == ರಿಕ್ತ) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((pubkey = get_pubkey_from_cred_ecdsa(cred, &pubkey_len)) == ರಿಕ್ತ) {
		error_f("get_pubkey_from_cred_ecdsa failed");
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshbuf_put_string(b, pubkey, pubkey_len)) != 0) {
		error_fr(r, "sshbuf_put_string");
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshbuf_get_eckey(b, ec)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	ಯದಿ (sshkey_ec_validate_public(EC_ಕೀಲಿ_get0_group(ec),
	    EC_ಕೀಲಿ_get0_public_ಕೀಲಿ(ec)) != 0) {
		error("Authenticator returned invalid ECDSA key");
		r = SSH_ERR_ಕೀಲಿ_INVALID_EC_ಮೌಲ್ಯ;
		ಗಚ್ಛ out;
	}
	ಯದಿ (EVP_PKEY_set1_EC_ಕೀಲಿ(ಕೀಲಿ->pkey, ec) != 1) {
		/* XXX assume it is a allocation error */
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಕೀಲಿ->sk_application = xstrdup(k->sk_application); /* XXX */
	ಯದಿ (!sshkey_equal_public(ಕೀಲಿ, k)) {
		error("sshkey_equal_public failed");
		r = SSH_ERR_INVALID_ARGUMENT;
		ಗಚ್ಛ out;
	}
	r = 0; /* success */
 out:
	EC_ಕೀಲಿ_free(ec);
	ಮುಕ್ತ(pubkey);
	sshkey_free(ಕೀಲಿ);
	sshbuf_free(b);
	ಪ್ರತ್ಯಾಗಮ r;
}


/* copied from sshsk_ed25519_assemble() */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
cred_matches_ಕೀಲಿ_ed25519(ಧ್ರುವ fido_cred_t *cred, ಧ್ರುವ ಸಂರಚನಾ sshkey *k)
{
	ಸಂರಚನಾ sshkey *ಕೀಲಿ = ರಿಕ್ತ;
	ಧ್ರುವ uint8_t *ptr;
	ಪೂರ್ಣಾಙ್ಕ r = -1;

	ಯದಿ ((ptr = fido_cred_pubkey_ptr(cred)) == ರಿಕ್ತ) {
		error_f("fido_cred_pubkey_ptr failed");
		ಗಚ್ಛ out;
	}
	ಯದಿ (fido_cred_pubkey_len(cred) != ED25519_PK_SZ) {
		error_f("bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		ಗಚ್ಛ out;
	}

	ಯದಿ ((ಕೀಲಿ = sshkey_new(ಕೀಲಿ_ED25519_SK)) == ರಿಕ್ತ) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((ಕೀಲಿ->ed25519_pk = malloc(ED25519_PK_SZ)) == ರಿಕ್ತ) {
		error_f("malloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	memcpy(ಕೀಲಿ->ed25519_pk, ptr, ED25519_PK_SZ);
	ಕೀಲಿ->sk_application = xstrdup(k->sk_application); /* XXX */
	ಯದಿ (!sshkey_equal_public(ಕೀಲಿ, k)) {
		error("sshkey_equal_public failed");
		r = SSH_ERR_INVALID_ARGUMENT;
		ಗಚ್ಛ out;
	}
	r = 0; /* success */
 out:
	sshkey_free(ಕೀಲಿ);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
cred_matches_ಕೀಲಿ(ಧ್ರುವ fido_cred_t *cred, ಧ್ರುವ ಸಂರಚನಾ sshkey *k)
{
	ವಿಕಲ್ಪ (sshkey_type_plain(k->type)) {
	ಪಕ್ಷ ಕೀಲಿ_ECDSA_SK:
		ವಿಕಲ್ಪ (k->ecdsa_nid) {
		ಪಕ್ಷ NID_X9_62_prime256v1:
			ಪ್ರತ್ಯಾಗಮ cred_matches_ಕೀಲಿ_ecdsa(cred, k);
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			fatal("Unsupported ECDSA key size");
		}
		ಭಙ್ಗ;
	ಪಕ್ಷ ಕೀಲಿ_ED25519_SK:
		ಪ್ರತ್ಯಾಗಮ cred_matches_ಕೀಲಿ_ed25519(cred, k);
	ಸ್ವಭಾವ:
		error_f("key type %s not supported", sshkey_type(k));
		ಪ್ರತ್ಯಾಗಮ -1;
	}
}

ಪೂರ್ಣಾಙ್ಕ
main(ಪೂರ್ಣಾಙ್ಕ argc, ವರ್ಣ **argv)
{
	LogLevel log_level = SYSLOG_LEVEL_INFO;
	ಪೂರ್ಣಾಙ್ಕ r, ch, credtype = -1;
	ಸಂರಚನಾ sshkey *k = ರಿಕ್ತ;
	ಸಂರಚನಾ sshbuf *attestation = ರಿಕ್ತ, *challenge = ರಿಕ್ತ;
	ಸಂರಚನಾ sshbuf *attestation_cert = ರಿಕ್ತ;
	ವರ್ಣ *fp;
	ಧ್ರುವ ವರ್ಣ *attfmt = "packed", *style = ರಿಕ್ತ;
	fido_cred_t *cred = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ write_attestation_cert = 0;
	ಬಾಹ್ಯ ಪೂರ್ಣಾಙ್ಕ optind;
	/* extern char *optarg; */

	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, ರಿಕ್ತ);

	sanitise_stdfd();
	log_init(__progname, log_level, SYSLOG_FACILITY_AUTH, 1);

	ಯಾವತ್ ((ch = getopt(argc, argv, "UAv")) != -1) {
		ವಿಕಲ್ಪ (ch) {
		ಪಕ್ಷ 'U':
			attfmt = "fido-u2f";
			ಭಙ್ಗ;
		ಪಕ್ಷ 'A':
			write_attestation_cert = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'v':
			ಯದಿ (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			ಅನ್ಯಥಾ ಯದಿ (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			ಗಚ್ಛ usage;
		}
	}
	log_init(__progname, log_level, SYSLOG_FACILITY_AUTH, 1);
	argv += optind;
	argc -= optind;

	ಯದಿ (argc < 3) {
 usage:
		fprintf(stderr, "usage: %s [-vAU] "
		   "pubkey challenge attestation-blob\n", __progname);
		exit(1);
	}
	ಯದಿ ((r = sshkey_load_public(argv[0], &k, ರಿಕ್ತ)) != 0)
		fatal_r(r, "load key %s", argv[0]);
	ಯದಿ ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ರಿಕ್ತ)
		fatal("sshkey_fingerprint failed");
	debug2("key %s: %s %s", argv[2], sshkey_type(k), fp);
	ಮುಕ್ತ(fp);
	ಯದಿ ((r = sshbuf_load_file(argv[1], &challenge)) != 0)
		fatal_r(r, "load challenge %s", argv[1]);
	ಯದಿ ((r = sshbuf_load_file(argv[2], &attestation)) != 0)
		fatal_r(r, "load attestation %s", argv[2]);
	ಯದಿ ((cred = fido_cred_new()) == ರಿಕ್ತ)
		fatal("fido_cred_new failed");

	ವಿಕಲ್ಪ (sshkey_type_plain(k->type)) {
	ಪಕ್ಷ ಕೀಲಿ_ECDSA_SK:
		ವಿಕಲ್ಪ (k->ecdsa_nid) {
		ಪಕ್ಷ NID_X9_62_prime256v1:
			credtype = COSE_ES256;
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			fatal("Unsupported ECDSA key size");
		}
		ಭಙ್ಗ;
	ಪಕ್ಷ ಕೀಲಿ_ED25519_SK:
		credtype = COSE_EDDSA;
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		fatal("unsupported key type %s", sshkey_type(k));
	}

	ಯದಿ ((r = prepare_fido_cred(cred, credtype, attfmt, k->sk_application,
	    attestation, challenge, &attestation_cert)) != 0)
		fatal_r(r, "prepare_fido_cred %s", argv[2]);
	ಯದಿ (fido_cred_x5c_ptr(cred) != ರಿಕ್ತ) {
		debug("basic attestation");
		ಯದಿ ((r = fido_cred_verify(cred)) != FIDO_OK)
			fatal("basic attestation failed");
		style = "basic";
	} ಅನ್ಯಥಾ {
		debug("self attestation");
		ಯದಿ ((r = fido_cred_verify_self(cred)) != FIDO_OK)
			fatal("self attestation failed");
		style = "self";
	}
	ಯದಿ (cred_matches_ಕೀಲಿ(cred, k) != 0)
		fatal("cred authdata does not match key");

	fido_cred_free(&cred);

	ಯದಿ (write_attestation_cert) {
		PEM_write(stdout, "CERTIFICATE", ರಿಕ್ತ,
		    sshbuf_ptr(attestation_cert), sshbuf_len(attestation_cert));
	}
	sshbuf_free(attestation_cert);

	logit("%s: verified %s attestation", argv[2], style);

	ಪ್ರತ್ಯಾಗಮ (0);
}
