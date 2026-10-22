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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <inttypes.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <stdarg.h>

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "authfile.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "digest.h"
#અન્તર્ભાવ "crypto_api.h"

#અન્તર્ભાવ <fido.h>
#અન્તર્ભાવ <openssl/x509.h>
#અન્તર્ભાવ <openssl/x509v3.h>
#અન્તર્ભાવ <openssl/bio.h>
#અન્તર્ભાવ <openssl/err.h>
#અન્તર્ભાવ <openssl/pem.h>
#અન્તર્ભાવ "openbsd-compat/openssl-compat.h"

બાહ્ય અક્ષર *__progname;

#define ATTEST_MAGIC	"ssh-sk-attest-v01"

સ્થિર પૂર્ણાંક
prepare_fido_cred(fido_cred_t *cred, પૂર્ણાંક credtype, અચલ અક્ષર *attfmt,
    અચલ અક્ષર *rp_id, સંરચના sshbuf *b, અચલ સંરચના sshbuf *challenge,
    સંરચના sshbuf **attestation_certp)
{
	સંરચના sshbuf *attestation_cert = ખાલી, *sig = ખાલી, *authdata = ખાલી;
	અક્ષર *magic = ખાલી;
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;

	*attestation_certp = ખાલી;

	/* Make sure it's the format we're expecting */
	જો ((r = sshbuf_get_cstring(b, &magic, ખાલી)) != 0) {
		error_fr(r, "parse header");
		જાઓ out;
	}
	જો (strcmp(magic, ATTEST_MAGIC) != 0) {
		error_f("unsupported format");
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	/* Parse the remaining fields */
	જો ((r = sshbuf_froms(b, &attestation_cert)) != 0 ||
	    (r = sshbuf_froms(b, &sig)) != 0 ||
	    (r = sshbuf_froms(b, &authdata)) != 0 ||
	    (r = sshbuf_get_u32(b, ખાલી)) != 0 || /* reserved flags */
	    (r = sshbuf_get_string_direct(b, ખાલી, ખાલી)) != 0) { /* reserved */
		error_fr(r, "parse body");
		જાઓ out;
	}
	debug3_f("attestation cert len=%zu, sig len=%zu, "
	    "authdata len=%zu challenge len=%zu", sshbuf_len(attestation_cert),
	    sshbuf_len(sig), sshbuf_len(authdata), sshbuf_len(challenge));

	fido_cred_set_type(cred, credtype);
	fido_cred_set_fmt(cred, attfmt);
	fido_cred_set_clientdata(cred, sshbuf_ptr(challenge),
	    sshbuf_len(challenge));
	fido_cred_set_rp(cred, rp_id, ખાલી);
	fido_cred_set_authdata(cred, sshbuf_ptr(authdata),
	    sshbuf_len(authdata));
	/* XXX set_extensions, set_rk, set_uv */
	fido_cred_set_x509(cred, sshbuf_ptr(attestation_cert),
	    sshbuf_len(attestation_cert));
	fido_cred_set_sig(cred, sshbuf_ptr(sig), sshbuf_len(sig));

	/* success */
	*attestation_certp = attestation_cert;
	attestation_cert = ખાલી;
	r = 0;
 out:
	મુક્ત(magic);
	sshbuf_free(attestation_cert);
	sshbuf_free(sig);
	sshbuf_free(authdata);
	પાછા r;
}

સ્થિર uint8_t *
get_pubkey_from_cred_ecdsa(અચલ fido_cred_t *cred, size_t *pubkey_len)
{
	અચલ uint8_t *ptr;
	uint8_t *pubkey = ખાલી, *ret = ખાલી;
	BIGNUM *x = ખાલી, *y = ખાલી;
	EC_POINT *q = ખાલી;
	EC_GROUP *g = ખાલી;

	જો ((x = BN_new()) == ખાલી ||
	    (y = BN_new()) == ખાલી ||
	    (g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) == ખાલી ||
	    (q = EC_POINT_new(g)) == ખાલી) {
		error_f("libcrypto setup failed");
		જાઓ out;
	}
	જો ((ptr = fido_cred_pubkey_ptr(cred)) == ખાલી) {
		error_f("fido_cred_pubkey_ptr failed");
		જાઓ out;
	}
	જો (fido_cred_pubkey_len(cred) != 64) {
		error_f("bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		જાઓ out;
	}

	જો (BN_bin2bn(ptr, 32, x) == ખાલી ||
	    BN_bin2bn(ptr + 32, 32, y) == ખાલી) {
		error_f("BN_bin2bn failed");
		જાઓ out;
	}
	જો (EC_POINT_set_affine_coordinates(g, q, x, y, ખાલી) != 1) {
		error_f("EC_POINT_set_affine_coordinates failed");
		જાઓ out;
	}
	*pubkey_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, ખાલી, 0, ખાલી);
	જો (*pubkey_len == 0 || *pubkey_len > 2048) {
		error_f("bad pubkey length %zu", *pubkey_len);
		જાઓ out;
	}
	જો ((pubkey = malloc(*pubkey_len)) == ખાલી) {
		error_f("malloc pubkey failed");
		જાઓ out;
	}
	જો (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    pubkey, *pubkey_len, ખાલી) == 0) {
		error_f("EC_POINT_point2oct failed");
		જાઓ out;
	}
	/* success */
	ret = pubkey;
	pubkey = ખાલી;
 out:
	મુક્ત(pubkey);
	EC_POINT_free(q);
	EC_GROUP_free(g);
	BN_clear_free(x);
	BN_clear_free(y);
	પાછા ret;
}

/* copied from sshsk_ecdsa_assemble() */
સ્થિર પૂર્ણાંક
cred_matches_ચાવી_ecdsa(અચલ fido_cred_t *cred, અચલ સંરચના sshkey *k)
{
	સંરચના sshkey *ચાવી = ખાલી;
	સંરચના sshbuf *b = ખાલી;
	EC_ચાવી *ec = ખાલી;
	uint8_t *pubkey = ખાલી;
	size_t pubkey_len;
	પૂર્ણાંક r;

	જો ((ચાવી = sshkey_new(ચાવી_ECDSA_SK)) == ખાલી) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	ચાવી->ecdsa_nid = NID_X9_62_prime256v1;
	જો ((ચાવી->pkey = EVP_PKEY_new()) == ખાલી ||
	    (ec = EC_ચાવી_new_by_curve_name(ચાવી->ecdsa_nid)) == ખાલી ||
	    (b = sshbuf_new()) == ખાલી) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો ((pubkey = get_pubkey_from_cred_ecdsa(cred, &pubkey_len)) == ખાલી) {
		error_f("get_pubkey_from_cred_ecdsa failed");
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	જો ((r = sshbuf_put_string(b, pubkey, pubkey_len)) != 0) {
		error_fr(r, "sshbuf_put_string");
		જાઓ out;
	}
	જો ((r = sshbuf_get_eckey(b, ec)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	જો (sshkey_ec_validate_public(EC_ચાવી_get0_group(ec),
	    EC_ચાવી_get0_public_ચાવી(ec)) != 0) {
		error("Authenticator returned invalid ECDSA key");
		r = SSH_ERR_ચાવી_INVALID_EC_કિંમત;
		જાઓ out;
	}
	જો (EVP_PKEY_set1_EC_ચાવી(ચાવી->pkey, ec) != 1) {
		/* XXX assume it is a allocation error */
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	ચાવી->sk_application = xstrdup(k->sk_application); /* XXX */
	જો (!sshkey_equal_public(ચાવી, k)) {
		error("sshkey_equal_public failed");
		r = SSH_ERR_INVALID_ARGUMENT;
		જાઓ out;
	}
	r = 0; /* success */
 out:
	EC_ચાવી_free(ec);
	મુક્ત(pubkey);
	sshkey_free(ચાવી);
	sshbuf_free(b);
	પાછા r;
}


/* copied from sshsk_ed25519_assemble() */
સ્થિર પૂર્ણાંક
cred_matches_ચાવી_ed25519(અચલ fido_cred_t *cred, અચલ સંરચના sshkey *k)
{
	સંરચના sshkey *ચાવી = ખાલી;
	અચલ uint8_t *ptr;
	પૂર્ણાંક r = -1;

	જો ((ptr = fido_cred_pubkey_ptr(cred)) == ખાલી) {
		error_f("fido_cred_pubkey_ptr failed");
		જાઓ out;
	}
	જો (fido_cred_pubkey_len(cred) != ED25519_PK_SZ) {
		error_f("bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		જાઓ out;
	}

	જો ((ચાવી = sshkey_new(ચાવી_ED25519_SK)) == ખાલી) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો ((ચાવી->ed25519_pk = malloc(ED25519_PK_SZ)) == ખાલી) {
		error_f("malloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	memcpy(ચાવી->ed25519_pk, ptr, ED25519_PK_SZ);
	ચાવી->sk_application = xstrdup(k->sk_application); /* XXX */
	જો (!sshkey_equal_public(ચાવી, k)) {
		error("sshkey_equal_public failed");
		r = SSH_ERR_INVALID_ARGUMENT;
		જાઓ out;
	}
	r = 0; /* success */
 out:
	sshkey_free(ચાવી);
	પાછા r;
}

સ્થિર પૂર્ણાંક
cred_matches_ચાવી(અચલ fido_cred_t *cred, અચલ સંરચના sshkey *k)
{
	પસંદગી (sshkey_type_plain(k->type)) {
	સ્થિતિ ચાવી_ECDSA_SK:
		પસંદગી (k->ecdsa_nid) {
		સ્થિતિ NID_X9_62_prime256v1:
			પાછા cred_matches_ચાવી_ecdsa(cred, k);
			તોડો;
		મૂળભૂત:
			fatal("Unsupported ECDSA key size");
		}
		તોડો;
	સ્થિતિ ચાવી_ED25519_SK:
		પાછા cred_matches_ચાવી_ed25519(cred, k);
	મૂળભૂત:
		error_f("key type %s not supported", sshkey_type(k));
		પાછા -1;
	}
}

પૂર્ણાંક
મુખ્ય(પૂર્ણાંક argc, અક્ષર **argv)
{
	LogLevel log_level = SYSLOG_LEVEL_INFO;
	પૂર્ણાંક r, ch, credtype = -1;
	સંરચના sshkey *k = ખાલી;
	સંરચના sshbuf *attestation = ખાલી, *challenge = ખાલી;
	સંરચના sshbuf *attestation_cert = ખાલી;
	અક્ષર *fp;
	અચલ અક્ષર *attfmt = "packed", *style = ખાલી;
	fido_cred_t *cred = ખાલી;
	પૂર્ણાંક write_attestation_cert = 0;
	બાહ્ય પૂર્ણાંક optind;
	/* extern char *optarg; */

	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, ખાલી);

	sanitise_stdfd();
	log_init(__progname, log_level, SYSLOG_FACILITY_AUTH, 1);

	જ્યારે ((ch = getopt(argc, argv, "UAv")) != -1) {
		પસંદગી (ch) {
		સ્થિતિ 'U':
			attfmt = "fido-u2f";
			તોડો;
		સ્થિતિ 'A':
			write_attestation_cert = 1;
			તોડો;
		સ્થિતિ 'v':
			જો (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			નહીંતર જો (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			તોડો;
		મૂળભૂત:
			જાઓ usage;
		}
	}
	log_init(__progname, log_level, SYSLOG_FACILITY_AUTH, 1);
	argv += optind;
	argc -= optind;

	જો (argc < 3) {
 usage:
		fprintf(stderr, "usage: %s [-vAU] "
		   "pubkey challenge attestation-blob\n", __progname);
		exit(1);
	}
	જો ((r = sshkey_load_public(argv[0], &k, ખાલી)) != 0)
		fatal_r(r, "load key %s", argv[0]);
	જો ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ખાલી)
		fatal("sshkey_fingerprint failed");
	debug2("key %s: %s %s", argv[2], sshkey_type(k), fp);
	મુક્ત(fp);
	જો ((r = sshbuf_load_file(argv[1], &challenge)) != 0)
		fatal_r(r, "load challenge %s", argv[1]);
	જો ((r = sshbuf_load_file(argv[2], &attestation)) != 0)
		fatal_r(r, "load attestation %s", argv[2]);
	જો ((cred = fido_cred_new()) == ખાલી)
		fatal("fido_cred_new failed");

	પસંદગી (sshkey_type_plain(k->type)) {
	સ્થિતિ ચાવી_ECDSA_SK:
		પસંદગી (k->ecdsa_nid) {
		સ્થિતિ NID_X9_62_prime256v1:
			credtype = COSE_ES256;
			તોડો;
		મૂળભૂત:
			fatal("Unsupported ECDSA key size");
		}
		તોડો;
	સ્થિતિ ચાવી_ED25519_SK:
		credtype = COSE_EDDSA;
		તોડો;
	મૂળભૂત:
		fatal("unsupported key type %s", sshkey_type(k));
	}

	જો ((r = prepare_fido_cred(cred, credtype, attfmt, k->sk_application,
	    attestation, challenge, &attestation_cert)) != 0)
		fatal_r(r, "prepare_fido_cred %s", argv[2]);
	જો (fido_cred_x5c_ptr(cred) != ખાલી) {
		debug("basic attestation");
		જો ((r = fido_cred_verify(cred)) != FIDO_OK)
			fatal("basic attestation failed");
		style = "basic";
	} નહીંતર {
		debug("self attestation");
		જો ((r = fido_cred_verify_self(cred)) != FIDO_OK)
			fatal("self attestation failed");
		style = "self";
	}
	જો (cred_matches_ચાવી(cred, k) != 0)
		fatal("cred authdata does not match key");

	fido_cred_free(&cred);

	જો (write_attestation_cert) {
		PEM_write(stdout, "CERTIFICATE", ખાલી,
		    sshbuf_ptr(attestation_cert), sshbuf_len(attestation_cert));
	}
	sshbuf_free(attestation_cert);

	logit("%s: verified %s attestation", argv[2], style);

	પાછા (0);
}
