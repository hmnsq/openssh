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

ಬಾಹ್ಯ ಅಕ್ಷರ *__progname;

#ವ್ಯಾಖ್ಯಾನಿಸು ATTEST_MAGIC	"ssh-sk-attest-v01"

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
prepare_fido_cred(fido_cred_t *cred, ಪೂರ್ಣಾಂಕ credtype, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *attfmt,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *rp_id, ರಚನೆ sshbuf *b, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *challenge,
    ರಚನೆ sshbuf **attestation_certp)
{
	ರಚನೆ sshbuf *attestation_cert = ಖಾಲಿ, *sig = ಖಾಲಿ, *authdata = ಖಾಲಿ;
	ಅಕ್ಷರ *magic = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;

	*attestation_certp = ಖಾಲಿ;

	/* Make sure it's the format we're expecting */
	ಆದರೆ ((r = sshbuf_get_cstring(b, &magic, ಖಾಲಿ)) != 0) {
		error_fr(r, "parse header");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (strcmp(magic, ATTEST_MAGIC) != 0) {
		error_f("unsupported format");
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* Parse the remaining fields */
	ಆದರೆ ((r = sshbuf_froms(b, &attestation_cert)) != 0 ||
	    (r = sshbuf_froms(b, &sig)) != 0 ||
	    (r = sshbuf_froms(b, &authdata)) != 0 ||
	    (r = sshbuf_get_u32(b, ಖಾಲಿ)) != 0 || /* reserved flags */
	    (r = sshbuf_get_string_ನೇರ(b, ಖಾಲಿ, ಖಾಲಿ)) != 0) { /* reserved */
		error_fr(r, "parse body");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	debug3_f("attestation cert len=%zu, sig len=%zu, "
	    "authdata len=%zu challenge len=%zu", sshbuf_len(attestation_cert),
	    sshbuf_len(sig), sshbuf_len(authdata), sshbuf_len(challenge));

	fido_cred_ಗಣ_type(cred, credtype);
	fido_cred_ಗಣ_fmt(cred, attfmt);
	fido_cred_ಗಣ_clientdata(cred, sshbuf_ptr(challenge),
	    sshbuf_len(challenge));
	fido_cred_ಗಣ_rp(cred, rp_id, ಖಾಲಿ);
	fido_cred_ಗಣ_authdata(cred, sshbuf_ptr(authdata),
	    sshbuf_len(authdata));
	/* XXX set_extensions, set_rk, set_uv */
	fido_cred_ಗಣ_x509(cred, sshbuf_ptr(attestation_cert),
	    sshbuf_len(attestation_cert));
	fido_cred_ಗಣ_sig(cred, sshbuf_ptr(sig), sshbuf_len(sig));

	/* success */
	*attestation_certp = attestation_cert;
	attestation_cert = ಖಾಲಿ;
	r = 0;
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(magic);
	sshbuf_free(attestation_cert);
	sshbuf_free(sig);
	sshbuf_free(authdata);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ uint8_t *
get_pubkey_from_cred_ecdsa(ಸ್ಥಿರಾಂಕ fido_cred_t *cred, ಗಾತ್ರ_t *pubkey_len)
{
	ಸ್ಥಿರಾಂಕ uint8_t *ptr;
	uint8_t *pubkey = ಖಾಲಿ, *ret = ಖಾಲಿ;
	BIGNUM *x = ಖಾಲಿ, *y = ಖಾಲಿ;
	EC_ಬಿಂದು *q = ಖಾಲಿ;
	EC_ಗುಂಪು *g = ಖಾಲಿ;

	ಆದರೆ ((x = BN_new()) == ಖಾಲಿ ||
	    (y = BN_new()) == ಖಾಲಿ ||
	    (g = EC_ಗುಂಪು_new_by_ವಕ್ರ_name(NID_X9_62_prime256v1)) == ಖಾಲಿ ||
	    (q = EC_ಬಿಂದು_new(g)) == ಖಾಲಿ) {
		error_f("libcrypto setup failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((ptr = fido_cred_pubkey_ptr(cred)) == ಖಾಲಿ) {
		error_f("fido_cred_pubkey_ptr failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (fido_cred_pubkey_len(cred) != 64) {
		error_f("bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ (BN_bin2bn(ptr, 32, x) == ಖಾಲಿ ||
	    BN_bin2bn(ptr + 32, 32, y) == ಖಾಲಿ) {
		error_f("BN_bin2bn failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (EC_ಬಿಂದು_ಗಣ_affine_coordinates(g, q, x, y, ಖಾಲಿ) != 1) {
		error_f("EC_POINT_set_affine_coordinates failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	*pubkey_len = EC_ಬಿಂದು_point2oct(g, q,
	    ಬಿಂದು_CONVERSION_UNCOMPRESSED, ಖಾಲಿ, 0, ಖಾಲಿ);
	ಆದರೆ (*pubkey_len == 0 || *pubkey_len > 2048) {
		error_f("bad pubkey length %zu", *pubkey_len);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((pubkey = ಸ್ಮರಣೆ_ಕೊಡು(*pubkey_len)) == ಖಾಲಿ) {
		error_f("malloc pubkey failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (EC_ಬಿಂದು_point2oct(g, q, ಬಿಂದು_CONVERSION_UNCOMPRESSED,
	    pubkey, *pubkey_len, ಖಾಲಿ) == 0) {
		error_f("EC_POINT_point2oct failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* success */
	ret = pubkey;
	pubkey = ಖಾಲಿ;
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(pubkey);
	EC_ಬಿಂದು_free(q);
	EC_ಗುಂಪು_free(g);
	BN_clear_free(x);
	BN_clear_free(y);
	ಹಿಂತಿರುಗಿ ret;
}

/* copied from sshsk_ecdsa_assemble() */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
cred_matches_ಕೀಲಿ_ecdsa(ಸ್ಥಿರಾಂಕ fido_cred_t *cred, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *k)
{
	ರಚನೆ sshkey *ಕೀಲಿ = ಖಾಲಿ;
	ರಚನೆ sshbuf *b = ಖಾಲಿ;
	EC_ಕೀಲಿ *ec = ಖಾಲಿ;
	uint8_t *pubkey = ಖಾಲಿ;
	ಗಾತ್ರ_t pubkey_len;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((ಕೀಲಿ = sshkey_new(ಕೀಲಿ_ECDSA_SK)) == ಖಾಲಿ) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಕೀಲಿ->ecdsa_nid = NID_X9_62_prime256v1;
	ಆದರೆ ((ಕೀಲಿ->pkey = EVP_PKEY_new()) == ಖಾಲಿ ||
	    (ec = EC_ಕೀಲಿ_new_by_ವಕ್ರ_name(ಕೀಲಿ->ecdsa_nid)) == ಖಾಲಿ ||
	    (b = sshbuf_new()) == ಖಾಲಿ) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((pubkey = get_pubkey_from_cred_ecdsa(cred, &pubkey_len)) == ಖಾಲಿ) {
		error_f("get_pubkey_from_cred_ecdsa failed");
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshbuf_put_string(b, pubkey, pubkey_len)) != 0) {
		error_fr(r, "sshbuf_put_string");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshbuf_get_eckey(b, ec)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (sshkey_ec_validate_ಬಹಿರಂಗ(EC_ಕೀಲಿ_get0_ಗುಂಪು(ec),
	    EC_ಕೀಲಿ_get0_ಬಹಿರಂಗ_ಕೀಲಿ(ec)) != 0) {
		error("Authenticator returned invalid ECDSA key");
		r = SSH_ERR_ಕೀಲಿ_INVALID_EC_ಮೌಲ್ಯ;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (EVP_PKEY_set1_EC_ಕೀಲಿ(ಕೀಲಿ->pkey, ec) != 1) {
		/* XXX assume it is a allocation error */
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಕೀಲಿ->sk_application = xstrdup(k->sk_application); /* XXX */
	ಆದರೆ (!sshkey_equal_ಬಹಿರಂಗ(ಕೀಲಿ, k)) {
		error("sshkey_equal_public failed");
		r = SSH_ERR_INVALID_ವಾದ;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	r = 0; /* success */
 ಹೊರಹೋಗು:
	EC_ಕೀಲಿ_free(ec);
	ಬಿಡುಗಡೆ(pubkey);
	sshkey_free(ಕೀಲಿ);
	sshbuf_free(b);
	ಹಿಂತಿರುಗಿ r;
}


/* copied from sshsk_ed25519_assemble() */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
cred_matches_ಕೀಲಿ_ed25519(ಸ್ಥಿರಾಂಕ fido_cred_t *cred, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *k)
{
	ರಚನೆ sshkey *ಕೀಲಿ = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ uint8_t *ptr;
	ಪೂರ್ಣಾಂಕ r = -1;

	ಆದರೆ ((ptr = fido_cred_pubkey_ptr(cred)) == ಖಾಲಿ) {
		error_f("fido_cred_pubkey_ptr failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (fido_cred_pubkey_len(cred) != ED25519_PK_SZ) {
		error_f("bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ ((ಕೀಲಿ = sshkey_new(ಕೀಲಿ_ED25519_SK)) == ಖಾಲಿ) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((ಕೀಲಿ->ed25519_pk = ಸ್ಮರಣೆ_ಕೊಡು(ED25519_PK_SZ)) == ಖಾಲಿ) {
		error_f("malloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಸ್ಮರಣೆ_ನಕಲು(ಕೀಲಿ->ed25519_pk, ptr, ED25519_PK_SZ);
	ಕೀಲಿ->sk_application = xstrdup(k->sk_application); /* XXX */
	ಆದರೆ (!sshkey_equal_ಬಹಿರಂಗ(ಕೀಲಿ, k)) {
		error("sshkey_equal_public failed");
		r = SSH_ERR_INVALID_ವಾದ;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	r = 0; /* success */
 ಹೊರಹೋಗು:
	sshkey_free(ಕೀಲಿ);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
cred_matches_ಕೀಲಿ(ಸ್ಥಿರಾಂಕ fido_cred_t *cred, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *k)
{
	ಆಯ್ಕೆ (sshkey_type_plain(k->type)) {
	ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA_SK:
		ಆಯ್ಕೆ (k->ecdsa_nid) {
		ಸ್ಥಿತಿ NID_X9_62_prime256v1:
			ಹಿಂತಿರುಗಿ cred_matches_ಕೀಲಿ_ecdsa(cred, k);
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			fatal("Unsupported ECDSA key size");
		}
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ ಕೀಲಿ_ED25519_SK:
		ಹಿಂತಿರುಗಿ cred_matches_ಕೀಲಿ_ed25519(cred, k);
	ಪೂರ್ವನಿಯೋಜಿತ:
		error_f("key type %s not supported", sshkey_type(k));
		ಹಿಂತಿರುಗಿ -1;
	}
}

ಪೂರ್ಣಾಂಕ
ಮುಖ್ಯ(ಪೂರ್ಣಾಂಕ argc, ಅಕ್ಷರ **argv)
{
	LogLevel log_level = SYSLOG_LEVEL_INFO;
	ಪೂರ್ಣಾಂಕ r, ch, credtype = -1;
	ರಚನೆ sshkey *k = ಖಾಲಿ;
	ರಚನೆ sshbuf *attestation = ಖಾಲಿ, *challenge = ಖಾಲಿ;
	ರಚನೆ sshbuf *attestation_cert = ಖಾಲಿ;
	ಅಕ್ಷರ *fp;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *attfmt = "packed", *style = ಖಾಲಿ;
	fido_cred_t *cred = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ write_attestation_cert = 0;
	ಬಾಹ್ಯ ಪೂರ್ಣಾಂಕ optind;
	/* extern char *optarg; */

	OPENSSL_init_crypto(OPENSSL_INIT_ತುಂಬು_CRYPTO_ಅಕ್ಷರಸರಣಿಗಳು, ಖಾಲಿ);

	sanitise_stdfd();
	log_init(__progname, log_level, SYSLOG_FACILITY_AUTH, 1);

	ಆಗ ((ch = getopt(argc, argv, "UAv")) != -1) {
		ಆಯ್ಕೆ (ch) {
		ಸ್ಥಿತಿ 'U':
			attfmt = "fido-u2f";
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'A':
			write_attestation_cert = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'v':
			ಆದರೆ (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			ಹೋಗು usage;
		}
	}
	log_init(__progname, log_level, SYSLOG_FACILITY_AUTH, 1);
	argv += optind;
	argc -= optind;

	ಆದರೆ (argc < 3) {
 usage:
		fprintf(stderr, "usage: %s [-vAU] "
		   "pubkey challenge attestation-blob\n", __progname);
		ನಿರ್ಗಮಿಸು(1);
	}
	ಆದರೆ ((r = sshkey_ತುಂಬು_ಬಹಿರಂಗ(argv[0], &k, ಖಾಲಿ)) != 0)
		fatal_r(r, "load key %s", argv[0]);
	ಆದರೆ ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ಖಾಲಿ)
		fatal("sshkey_fingerprint failed");
	debug2("key %s: %s %s", argv[2], sshkey_type(k), fp);
	ಬಿಡುಗಡೆ(fp);
	ಆದರೆ ((r = sshbuf_ತುಂಬು_file(argv[1], &challenge)) != 0)
		fatal_r(r, "load challenge %s", argv[1]);
	ಆದರೆ ((r = sshbuf_ತುಂಬು_file(argv[2], &attestation)) != 0)
		fatal_r(r, "load attestation %s", argv[2]);
	ಆದರೆ ((cred = fido_cred_new()) == ಖಾಲಿ)
		fatal("fido_cred_new failed");

	ಆಯ್ಕೆ (sshkey_type_plain(k->type)) {
	ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA_SK:
		ಆಯ್ಕೆ (k->ecdsa_nid) {
		ಸ್ಥಿತಿ NID_X9_62_prime256v1:
			credtype = COSE_ES256;
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			fatal("Unsupported ECDSA key size");
		}
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ ಕೀಲಿ_ED25519_SK:
		credtype = COSE_EDDSA;
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		fatal("unsupported key type %s", sshkey_type(k));
	}

	ಆದರೆ ((r = prepare_fido_cred(cred, credtype, attfmt, k->sk_application,
	    attestation, challenge, &attestation_cert)) != 0)
		fatal_r(r, "prepare_fido_cred %s", argv[2]);
	ಆದರೆ (fido_cred_x5c_ptr(cred) != ಖಾಲಿ) {
		debug("basic attestation");
		ಆದರೆ ((r = fido_cred_verify(cred)) != FIDO_OK)
			fatal("basic attestation failed");
		style = "basic";
	} ಇಲ್ಲದಿದ್ದರೆ {
		debug("self attestation");
		ಆದರೆ ((r = fido_cred_verify_self(cred)) != FIDO_OK)
			fatal("self attestation failed");
		style = "self";
	}
	ಆದರೆ (cred_matches_ಕೀಲಿ(cred, k) != 0)
		fatal("cred authdata does not match key");

	fido_cred_free(&cred);

	ಆದರೆ (write_attestation_cert) {
		PEM_write(stdout, "CERTIFICATE", ಖಾಲಿ,
		    sshbuf_ptr(attestation_cert), sshbuf_len(attestation_cert));
	}
	sshbuf_free(attestation_cert);

	logit("%s: verified %s attestation", argv[2], style);

	ಹಿಂತಿರುಗಿ (0);
}
