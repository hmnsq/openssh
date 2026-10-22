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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <inttypes.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <stdarg.h>

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "authfile.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "digest.h"
#അന്തര്ഭാവ "crypto_api.h"

#അന്തര്ഭാവ <fido.h>
#അന്തര്ഭാവ <openssl/x509.h>
#അന്തര്ഭാവ <openssl/x509v3.h>
#അന്തര്ഭാവ <openssl/bio.h>
#അന്തര്ഭാവ <openssl/err.h>
#അന്തര്ഭാവ <openssl/pem.h>
#അന്തര്ഭാവ "openbsd-compat/openssl-compat.h"

ബാഹ്യ അക്ഷരം *__progname;

#define ATTEST_MAGIC	"ssh-sk-attest-v01"

സ്ഥിതം പൂർണ്ണസംഖ്യ
prepare_fido_cred(fido_cred_t *cred, പൂർണ്ണസംഖ്യ credtype, സ്ഥിരം അക്ഷരം *attfmt,
    സ്ഥിരം അക്ഷരം *rp_id, ഘടന sshbuf *b, സ്ഥിരം ഘടന sshbuf *challenge,
    ഘടന sshbuf **attestation_certp)
{
	ഘടന sshbuf *attestation_cert = ശൂന്യ, *sig = ശൂന്യ, *authdata = ശൂന്യ;
	അക്ഷരം *magic = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;

	*attestation_certp = ശൂന്യ;

	/* Make sure it's the format we're expecting */
	എങ്കിൽ ((r = sshbuf_get_cstring(b, &magic, ശൂന്യ)) != 0) {
		error_fr(r, "parse header");
		പോകുക out;
	}
	എങ്കിൽ (strcmp(magic, ATTEST_MAGIC) != 0) {
		error_f("unsupported format");
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	/* Parse the remaining fields */
	എങ്കിൽ ((r = sshbuf_froms(b, &attestation_cert)) != 0 ||
	    (r = sshbuf_froms(b, &sig)) != 0 ||
	    (r = sshbuf_froms(b, &authdata)) != 0 ||
	    (r = sshbuf_get_u32(b, ശൂന്യ)) != 0 || /* reserved flags */
	    (r = sshbuf_get_string_direct(b, ശൂന്യ, ശൂന്യ)) != 0) { /* reserved */
		error_fr(r, "parse body");
		പോകുക out;
	}
	debug3_f("attestation cert len=%zu, sig len=%zu, "
	    "authdata len=%zu challenge len=%zu", sshbuf_len(attestation_cert),
	    sshbuf_len(sig), sshbuf_len(authdata), sshbuf_len(challenge));

	fido_cred_set_type(cred, credtype);
	fido_cred_set_fmt(cred, attfmt);
	fido_cred_set_clientdata(cred, sshbuf_ptr(challenge),
	    sshbuf_len(challenge));
	fido_cred_set_rp(cred, rp_id, ശൂന്യ);
	fido_cred_set_authdata(cred, sshbuf_ptr(authdata),
	    sshbuf_len(authdata));
	/* XXX set_extensions, set_rk, set_uv */
	fido_cred_set_x509(cred, sshbuf_ptr(attestation_cert),
	    sshbuf_len(attestation_cert));
	fido_cred_set_sig(cred, sshbuf_ptr(sig), sshbuf_len(sig));

	/* success */
	*attestation_certp = attestation_cert;
	attestation_cert = ശൂന്യ;
	r = 0;
 out:
	സ്വതന്ത്രം(magic);
	sshbuf_free(attestation_cert);
	sshbuf_free(sig);
	sshbuf_free(authdata);
	തിരികെ r;
}

സ്ഥിതം uint8_t *
get_pubkey_from_cred_ecdsa(സ്ഥിരം fido_cred_t *cred, size_t *pubkey_len)
{
	സ്ഥിരം uint8_t *ptr;
	uint8_t *pubkey = ശൂന്യ, *ret = ശൂന്യ;
	BIGNUM *x = ശൂന്യ, *y = ശൂന്യ;
	EC_POINT *q = ശൂന്യ;
	EC_GROUP *g = ശൂന്യ;

	എങ്കിൽ ((x = BN_new()) == ശൂന്യ ||
	    (y = BN_new()) == ശൂന്യ ||
	    (g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) == ശൂന്യ ||
	    (q = EC_POINT_new(g)) == ശൂന്യ) {
		error_f("libcrypto setup failed");
		പോകുക out;
	}
	എങ്കിൽ ((ptr = fido_cred_pubkey_ptr(cred)) == ശൂന്യ) {
		error_f("fido_cred_pubkey_ptr failed");
		പോകുക out;
	}
	എങ്കിൽ (fido_cred_pubkey_len(cred) != 64) {
		error_f("bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		പോകുക out;
	}

	എങ്കിൽ (BN_bin2bn(ptr, 32, x) == ശൂന്യ ||
	    BN_bin2bn(ptr + 32, 32, y) == ശൂന്യ) {
		error_f("BN_bin2bn failed");
		പോകുക out;
	}
	എങ്കിൽ (EC_POINT_set_affine_coordinates(g, q, x, y, ശൂന്യ) != 1) {
		error_f("EC_POINT_set_affine_coordinates failed");
		പോകുക out;
	}
	*pubkey_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, ശൂന്യ, 0, ശൂന്യ);
	എങ്കിൽ (*pubkey_len == 0 || *pubkey_len > 2048) {
		error_f("bad pubkey length %zu", *pubkey_len);
		പോകുക out;
	}
	എങ്കിൽ ((pubkey = malloc(*pubkey_len)) == ശൂന്യ) {
		error_f("malloc pubkey failed");
		പോകുക out;
	}
	എങ്കിൽ (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    pubkey, *pubkey_len, ശൂന്യ) == 0) {
		error_f("EC_POINT_point2oct failed");
		പോകുക out;
	}
	/* success */
	ret = pubkey;
	pubkey = ശൂന്യ;
 out:
	സ്വതന്ത്രം(pubkey);
	EC_POINT_free(q);
	EC_GROUP_free(g);
	BN_clear_free(x);
	BN_clear_free(y);
	തിരികെ ret;
}

/* copied from sshsk_ecdsa_assemble() */
സ്ഥിതം പൂർണ്ണസംഖ്യ
cred_matches_താക്കോൽ_ecdsa(സ്ഥിരം fido_cred_t *cred, സ്ഥിരം ഘടന sshkey *k)
{
	ഘടന sshkey *താക്കോൽ = ശൂന്യ;
	ഘടന sshbuf *b = ശൂന്യ;
	EC_താക്കോൽ *ec = ശൂന്യ;
	uint8_t *pubkey = ശൂന്യ;
	size_t pubkey_len;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((താക്കോൽ = sshkey_new(താക്കോൽ_ECDSA_SK)) == ശൂന്യ) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	താക്കോൽ->ecdsa_nid = NID_X9_62_prime256v1;
	എങ്കിൽ ((താക്കോൽ->pkey = EVP_PKEY_new()) == ശൂന്യ ||
	    (ec = EC_താക്കോൽ_new_by_curve_name(താക്കോൽ->ecdsa_nid)) == ശൂന്യ ||
	    (b = sshbuf_new()) == ശൂന്യ) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ ((pubkey = get_pubkey_from_cred_ecdsa(cred, &pubkey_len)) == ശൂന്യ) {
		error_f("get_pubkey_from_cred_ecdsa failed");
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	എങ്കിൽ ((r = sshbuf_put_string(b, pubkey, pubkey_len)) != 0) {
		error_fr(r, "sshbuf_put_string");
		പോകുക out;
	}
	എങ്കിൽ ((r = sshbuf_get_eckey(b, ec)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	എങ്കിൽ (sshkey_ec_validate_public(EC_താക്കോൽ_get0_group(ec),
	    EC_താക്കോൽ_get0_public_താക്കോൽ(ec)) != 0) {
		error("Authenticator returned invalid ECDSA key");
		r = SSH_ERR_താക്കോൽ_INVALID_EC_മൂല്യം;
		പോകുക out;
	}
	എങ്കിൽ (EVP_PKEY_set1_EC_താക്കോൽ(താക്കോൽ->pkey, ec) != 1) {
		/* XXX assume it is a allocation error */
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	താക്കോൽ->sk_application = xstrdup(k->sk_application); /* XXX */
	എങ്കിൽ (!sshkey_equal_public(താക്കോൽ, k)) {
		error("sshkey_equal_public failed");
		r = SSH_ERR_INVALID_ARGUMENT;
		പോകുക out;
	}
	r = 0; /* success */
 out:
	EC_താക്കോൽ_free(ec);
	സ്വതന്ത്രം(pubkey);
	sshkey_free(താക്കോൽ);
	sshbuf_free(b);
	തിരികെ r;
}


/* copied from sshsk_ed25519_assemble() */
സ്ഥിതം പൂർണ്ണസംഖ്യ
cred_matches_താക്കോൽ_ed25519(സ്ഥിരം fido_cred_t *cred, സ്ഥിരം ഘടന sshkey *k)
{
	ഘടന sshkey *താക്കോൽ = ശൂന്യ;
	സ്ഥിരം uint8_t *ptr;
	പൂർണ്ണസംഖ്യ r = -1;

	എങ്കിൽ ((ptr = fido_cred_pubkey_ptr(cred)) == ശൂന്യ) {
		error_f("fido_cred_pubkey_ptr failed");
		പോകുക out;
	}
	എങ്കിൽ (fido_cred_pubkey_len(cred) != ED25519_PK_SZ) {
		error_f("bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		പോകുക out;
	}

	എങ്കിൽ ((താക്കോൽ = sshkey_new(താക്കോൽ_ED25519_SK)) == ശൂന്യ) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ ((താക്കോൽ->ed25519_pk = malloc(ED25519_PK_SZ)) == ശൂന്യ) {
		error_f("malloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	memcpy(താക്കോൽ->ed25519_pk, ptr, ED25519_PK_SZ);
	താക്കോൽ->sk_application = xstrdup(k->sk_application); /* XXX */
	എങ്കിൽ (!sshkey_equal_public(താക്കോൽ, k)) {
		error("sshkey_equal_public failed");
		r = SSH_ERR_INVALID_ARGUMENT;
		പോകുക out;
	}
	r = 0; /* success */
 out:
	sshkey_free(താക്കോൽ);
	തിരികെ r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
cred_matches_താക്കോൽ(സ്ഥിരം fido_cred_t *cred, സ്ഥിരം ഘടന sshkey *k)
{
	തിരഞ്ഞെടുപ്പ് (sshkey_type_plain(k->type)) {
	അവസ്ഥ താക്കോൽ_ECDSA_SK:
		തിരഞ്ഞെടുപ്പ് (k->ecdsa_nid) {
		അവസ്ഥ NID_X9_62_prime256v1:
			തിരികെ cred_matches_താക്കോൽ_ecdsa(cred, k);
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			fatal("Unsupported ECDSA key size");
		}
		നിർത്തുക;
	അവസ്ഥ താക്കോൽ_ED25519_SK:
		തിരികെ cred_matches_താക്കോൽ_ed25519(cred, k);
	സ്ഥിരസ്ഥിതി:
		error_f("key type %s not supported", sshkey_type(k));
		തിരികെ -1;
	}
}

പൂർണ്ണസംഖ്യ
പ്രധാന(പൂർണ്ണസംഖ്യ argc, അക്ഷരം **argv)
{
	LogLevel log_level = SYSLOG_LEVEL_INFO;
	പൂർണ്ണസംഖ്യ r, ch, credtype = -1;
	ഘടന sshkey *k = ശൂന്യ;
	ഘടന sshbuf *attestation = ശൂന്യ, *challenge = ശൂന്യ;
	ഘടന sshbuf *attestation_cert = ശൂന്യ;
	അക്ഷരം *fp;
	സ്ഥിരം അക്ഷരം *attfmt = "packed", *style = ശൂന്യ;
	fido_cred_t *cred = ശൂന്യ;
	പൂർണ്ണസംഖ്യ write_attestation_cert = 0;
	ബാഹ്യ പൂർണ്ണസംഖ്യ optind;
	/* extern char *optarg; */

	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, ശൂന്യ);

	sanitise_stdfd();
	log_init(__progname, log_level, SYSLOG_FACILITY_AUTH, 1);

	ആകുമ്പോൾ ((ch = getopt(argc, argv, "UAv")) != -1) {
		തിരഞ്ഞെടുപ്പ് (ch) {
		അവസ്ഥ 'U':
			attfmt = "fido-u2f";
			നിർത്തുക;
		അവസ്ഥ 'A':
			write_attestation_cert = 1;
			നിർത്തുക;
		അവസ്ഥ 'v':
			എങ്കിൽ (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			അല്ലെങ്കിൽ എങ്കിൽ (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			പോകുക usage;
		}
	}
	log_init(__progname, log_level, SYSLOG_FACILITY_AUTH, 1);
	argv += optind;
	argc -= optind;

	എങ്കിൽ (argc < 3) {
 usage:
		fprintf(stderr, "usage: %s [-vAU] "
		   "pubkey challenge attestation-blob\n", __progname);
		exit(1);
	}
	എങ്കിൽ ((r = sshkey_load_public(argv[0], &k, ശൂന്യ)) != 0)
		fatal_r(r, "load key %s", argv[0]);
	എങ്കിൽ ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ശൂന്യ)
		fatal("sshkey_fingerprint failed");
	debug2("key %s: %s %s", argv[2], sshkey_type(k), fp);
	സ്വതന്ത്രം(fp);
	എങ്കിൽ ((r = sshbuf_load_file(argv[1], &challenge)) != 0)
		fatal_r(r, "load challenge %s", argv[1]);
	എങ്കിൽ ((r = sshbuf_load_file(argv[2], &attestation)) != 0)
		fatal_r(r, "load attestation %s", argv[2]);
	എങ്കിൽ ((cred = fido_cred_new()) == ശൂന്യ)
		fatal("fido_cred_new failed");

	തിരഞ്ഞെടുപ്പ് (sshkey_type_plain(k->type)) {
	അവസ്ഥ താക്കോൽ_ECDSA_SK:
		തിരഞ്ഞെടുപ്പ് (k->ecdsa_nid) {
		അവസ്ഥ NID_X9_62_prime256v1:
			credtype = COSE_ES256;
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			fatal("Unsupported ECDSA key size");
		}
		നിർത്തുക;
	അവസ്ഥ താക്കോൽ_ED25519_SK:
		credtype = COSE_EDDSA;
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		fatal("unsupported key type %s", sshkey_type(k));
	}

	എങ്കിൽ ((r = prepare_fido_cred(cred, credtype, attfmt, k->sk_application,
	    attestation, challenge, &attestation_cert)) != 0)
		fatal_r(r, "prepare_fido_cred %s", argv[2]);
	എങ്കിൽ (fido_cred_x5c_ptr(cred) != ശൂന്യ) {
		debug("basic attestation");
		എങ്കിൽ ((r = fido_cred_verify(cred)) != FIDO_OK)
			fatal("basic attestation failed");
		style = "basic";
	} അല്ലെങ്കിൽ {
		debug("self attestation");
		എങ്കിൽ ((r = fido_cred_verify_self(cred)) != FIDO_OK)
			fatal("self attestation failed");
		style = "self";
	}
	എങ്കിൽ (cred_matches_താക്കോൽ(cred, k) != 0)
		fatal("cred authdata does not match key");

	fido_cred_free(&cred);

	എങ്കിൽ (write_attestation_cert) {
		PEM_write(stdout, "CERTIFICATE", ശൂന്യ,
		    sshbuf_ptr(attestation_cert), sshbuf_len(attestation_cert));
	}
	sshbuf_free(attestation_cert);

	logit("%s: verified %s attestation", argv[2], style);

	തിരികെ (0);
}
