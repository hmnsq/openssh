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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <inttypes.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <stdarg.h>

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "authfile.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "digest.h"
#அந்தர்பாவ "crypto_api.h"

#அந்தர்பாவ <fido.h>
#அந்தர்பாவ <openssl/x509.h>
#அந்தர்பாவ <openssl/x509v3.h>
#அந்தர்பாவ <openssl/bio.h>
#அந்தர்பாவ <openssl/err.h>
#அந்தர்பாவ <openssl/pem.h>
#அந்தர்பாவ "openbsd-compat/openssl-compat.h"

வெளி எழுத்து *__progname;

#define ATTEST_MAGIC	"ssh-sk-attest-v01"

நிலையான முழு
prepare_fido_cred(fido_cred_t *cred, முழு credtype, மாறிலி எழுத்து *attfmt,
    மாறிலி எழுத்து *rp_id, கட்டமைப்பு sshbuf *b, மாறிலி கட்டமைப்பு sshbuf *challenge,
    கட்டமைப்பு sshbuf **attestation_certp)
{
	கட்டமைப்பு sshbuf *attestation_cert = வெற்று, *sig = வெற்று, *authdata = வெற்று;
	எழுத்து *magic = வெற்று;
	முழு r = SSH_ERR_INTERNAL_ERROR;

	*attestation_certp = வெற்று;

	/* Make sure it's the format we're expecting */
	எனில் ((r = sshbuf_get_cstring(b, &magic, வெற்று)) != 0) {
		error_fr(r, "parse header");
		செல் out;
	}
	எனில் (strcmp(magic, ATTEST_MAGIC) != 0) {
		error_f("unsupported format");
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	/* Parse the remaining fields */
	எனில் ((r = sshbuf_froms(b, &attestation_cert)) != 0 ||
	    (r = sshbuf_froms(b, &sig)) != 0 ||
	    (r = sshbuf_froms(b, &authdata)) != 0 ||
	    (r = sshbuf_get_u32(b, வெற்று)) != 0 || /* reserved flags */
	    (r = sshbuf_get_string_direct(b, வெற்று, வெற்று)) != 0) { /* reserved */
		error_fr(r, "parse body");
		செல் out;
	}
	debug3_f("attestation cert len=%zu, sig len=%zu, "
	    "authdata len=%zu challenge len=%zu", sshbuf_len(attestation_cert),
	    sshbuf_len(sig), sshbuf_len(authdata), sshbuf_len(challenge));

	fido_cred_set_type(cred, credtype);
	fido_cred_set_fmt(cred, attfmt);
	fido_cred_set_clientdata(cred, sshbuf_ptr(challenge),
	    sshbuf_len(challenge));
	fido_cred_set_rp(cred, rp_id, வெற்று);
	fido_cred_set_authdata(cred, sshbuf_ptr(authdata),
	    sshbuf_len(authdata));
	/* XXX set_extensions, set_rk, set_uv */
	fido_cred_set_x509(cred, sshbuf_ptr(attestation_cert),
	    sshbuf_len(attestation_cert));
	fido_cred_set_sig(cred, sshbuf_ptr(sig), sshbuf_len(sig));

	/* success */
	*attestation_certp = attestation_cert;
	attestation_cert = வெற்று;
	r = 0;
 out:
	விடுவி(magic);
	sshbuf_free(attestation_cert);
	sshbuf_free(sig);
	sshbuf_free(authdata);
	திரும்பு r;
}

நிலையான uint8_t *
get_pubkey_from_cred_ecdsa(மாறிலி fido_cred_t *cred, size_t *pubkey_len)
{
	மாறிலி uint8_t *ptr;
	uint8_t *pubkey = வெற்று, *ret = வெற்று;
	BIGNUM *x = வெற்று, *y = வெற்று;
	EC_POINT *q = வெற்று;
	EC_GROUP *g = வெற்று;

	எனில் ((x = BN_new()) == வெற்று ||
	    (y = BN_new()) == வெற்று ||
	    (g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) == வெற்று ||
	    (q = EC_POINT_new(g)) == வெற்று) {
		error_f("libcrypto setup failed");
		செல் out;
	}
	எனில் ((ptr = fido_cred_pubkey_ptr(cred)) == வெற்று) {
		error_f("fido_cred_pubkey_ptr failed");
		செல் out;
	}
	எனில் (fido_cred_pubkey_len(cred) != 64) {
		error_f("bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		செல் out;
	}

	எனில் (BN_bin2bn(ptr, 32, x) == வெற்று ||
	    BN_bin2bn(ptr + 32, 32, y) == வெற்று) {
		error_f("BN_bin2bn failed");
		செல் out;
	}
	எனில் (EC_POINT_set_affine_coordinates(g, q, x, y, வெற்று) != 1) {
		error_f("EC_POINT_set_affine_coordinates failed");
		செல் out;
	}
	*pubkey_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, வெற்று, 0, வெற்று);
	எனில் (*pubkey_len == 0 || *pubkey_len > 2048) {
		error_f("bad pubkey length %zu", *pubkey_len);
		செல் out;
	}
	எனில் ((pubkey = malloc(*pubkey_len)) == வெற்று) {
		error_f("malloc pubkey failed");
		செல் out;
	}
	எனில் (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    pubkey, *pubkey_len, வெற்று) == 0) {
		error_f("EC_POINT_point2oct failed");
		செல் out;
	}
	/* success */
	ret = pubkey;
	pubkey = வெற்று;
 out:
	விடுவி(pubkey);
	EC_POINT_free(q);
	EC_GROUP_free(g);
	BN_clear_free(x);
	BN_clear_free(y);
	திரும்பு ret;
}

/* copied from sshsk_ecdsa_assemble() */
நிலையான முழு
cred_matches_சாவி_ecdsa(மாறிலி fido_cred_t *cred, மாறிலி கட்டமைப்பு sshkey *k)
{
	கட்டமைப்பு sshkey *சாவி = வெற்று;
	கட்டமைப்பு sshbuf *b = வெற்று;
	EC_சாவி *ec = வெற்று;
	uint8_t *pubkey = வெற்று;
	size_t pubkey_len;
	முழு r;

	எனில் ((சாவி = sshkey_new(சாவி_ECDSA_SK)) == வெற்று) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	சாவி->ecdsa_nid = NID_X9_62_prime256v1;
	எனில் ((சாவி->pkey = EVP_PKEY_new()) == வெற்று ||
	    (ec = EC_சாவி_new_by_curve_name(சாவி->ecdsa_nid)) == வெற்று ||
	    (b = sshbuf_new()) == வெற்று) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் ((pubkey = get_pubkey_from_cred_ecdsa(cred, &pubkey_len)) == வெற்று) {
		error_f("get_pubkey_from_cred_ecdsa failed");
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	எனில் ((r = sshbuf_put_string(b, pubkey, pubkey_len)) != 0) {
		error_fr(r, "sshbuf_put_string");
		செல் out;
	}
	எனில் ((r = sshbuf_get_eckey(b, ec)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	எனில் (sshkey_ec_validate_public(EC_சாவி_get0_group(ec),
	    EC_சாவி_get0_public_சாவி(ec)) != 0) {
		error("Authenticator returned invalid ECDSA key");
		r = SSH_ERR_சாவி_INVALID_EC_மதிப்பு;
		செல் out;
	}
	எனில் (EVP_PKEY_set1_EC_சாவி(சாவி->pkey, ec) != 1) {
		/* XXX assume it is a allocation error */
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	சாவி->sk_application = xstrdup(k->sk_application); /* XXX */
	எனில் (!sshkey_equal_public(சாவி, k)) {
		error("sshkey_equal_public failed");
		r = SSH_ERR_INVALID_ARGUMENT;
		செல் out;
	}
	r = 0; /* success */
 out:
	EC_சாவி_free(ec);
	விடுவி(pubkey);
	sshkey_free(சாவி);
	sshbuf_free(b);
	திரும்பு r;
}


/* copied from sshsk_ed25519_assemble() */
நிலையான முழு
cred_matches_சாவி_ed25519(மாறிலி fido_cred_t *cred, மாறிலி கட்டமைப்பு sshkey *k)
{
	கட்டமைப்பு sshkey *சாவி = வெற்று;
	மாறிலி uint8_t *ptr;
	முழு r = -1;

	எனில் ((ptr = fido_cred_pubkey_ptr(cred)) == வெற்று) {
		error_f("fido_cred_pubkey_ptr failed");
		செல் out;
	}
	எனில் (fido_cred_pubkey_len(cred) != ED25519_PK_SZ) {
		error_f("bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		செல் out;
	}

	எனில் ((சாவி = sshkey_new(சாவி_ED25519_SK)) == வெற்று) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் ((சாவி->ed25519_pk = malloc(ED25519_PK_SZ)) == வெற்று) {
		error_f("malloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	memcpy(சாவி->ed25519_pk, ptr, ED25519_PK_SZ);
	சாவி->sk_application = xstrdup(k->sk_application); /* XXX */
	எனில் (!sshkey_equal_public(சாவி, k)) {
		error("sshkey_equal_public failed");
		r = SSH_ERR_INVALID_ARGUMENT;
		செல் out;
	}
	r = 0; /* success */
 out:
	sshkey_free(சாவி);
	திரும்பு r;
}

நிலையான முழு
cred_matches_சாவி(மாறிலி fido_cred_t *cred, மாறிலி கட்டமைப்பு sshkey *k)
{
	தேர்வு (sshkey_type_plain(k->type)) {
	நிலை சாவி_ECDSA_SK:
		தேர்வு (k->ecdsa_nid) {
		நிலை NID_X9_62_prime256v1:
			திரும்பு cred_matches_சாவி_ecdsa(cred, k);
			நிறுத்து;
		இயல்பு:
			fatal("Unsupported ECDSA key size");
		}
		நிறுத்து;
	நிலை சாவி_ED25519_SK:
		திரும்பு cred_matches_சாவி_ed25519(cred, k);
	இயல்பு:
		error_f("key type %s not supported", sshkey_type(k));
		திரும்பு -1;
	}
}

முழு
முதன்மை(முழு argc, எழுத்து **argv)
{
	LogLevel log_level = SYSLOG_LEVEL_INFO;
	முழு r, ch, credtype = -1;
	கட்டமைப்பு sshkey *k = வெற்று;
	கட்டமைப்பு sshbuf *attestation = வெற்று, *challenge = வெற்று;
	கட்டமைப்பு sshbuf *attestation_cert = வெற்று;
	எழுத்து *fp;
	மாறிலி எழுத்து *attfmt = "packed", *style = வெற்று;
	fido_cred_t *cred = வெற்று;
	முழு write_attestation_cert = 0;
	வெளி முழு optind;
	/* extern char *optarg; */

	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, வெற்று);

	sanitise_stdfd();
	log_init(__progname, log_level, SYSLOG_FACILITY_AUTH, 1);

	போது ((ch = getopt(argc, argv, "UAv")) != -1) {
		தேர்வு (ch) {
		நிலை 'U':
			attfmt = "fido-u2f";
			நிறுத்து;
		நிலை 'A':
			write_attestation_cert = 1;
			நிறுத்து;
		நிலை 'v':
			எனில் (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			இல்லையெனில் எனில் (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			நிறுத்து;
		இயல்பு:
			செல் usage;
		}
	}
	log_init(__progname, log_level, SYSLOG_FACILITY_AUTH, 1);
	argv += optind;
	argc -= optind;

	எனில் (argc < 3) {
 usage:
		fprintf(stderr, "usage: %s [-vAU] "
		   "pubkey challenge attestation-blob\n", __progname);
		exit(1);
	}
	எனில் ((r = sshkey_load_public(argv[0], &k, வெற்று)) != 0)
		fatal_r(r, "load key %s", argv[0]);
	எனில் ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == வெற்று)
		fatal("sshkey_fingerprint failed");
	debug2("key %s: %s %s", argv[2], sshkey_type(k), fp);
	விடுவி(fp);
	எனில் ((r = sshbuf_load_file(argv[1], &challenge)) != 0)
		fatal_r(r, "load challenge %s", argv[1]);
	எனில் ((r = sshbuf_load_file(argv[2], &attestation)) != 0)
		fatal_r(r, "load attestation %s", argv[2]);
	எனில் ((cred = fido_cred_new()) == வெற்று)
		fatal("fido_cred_new failed");

	தேர்வு (sshkey_type_plain(k->type)) {
	நிலை சாவி_ECDSA_SK:
		தேர்வு (k->ecdsa_nid) {
		நிலை NID_X9_62_prime256v1:
			credtype = COSE_ES256;
			நிறுத்து;
		இயல்பு:
			fatal("Unsupported ECDSA key size");
		}
		நிறுத்து;
	நிலை சாவி_ED25519_SK:
		credtype = COSE_EDDSA;
		நிறுத்து;
	இயல்பு:
		fatal("unsupported key type %s", sshkey_type(k));
	}

	எனில் ((r = prepare_fido_cred(cred, credtype, attfmt, k->sk_application,
	    attestation, challenge, &attestation_cert)) != 0)
		fatal_r(r, "prepare_fido_cred %s", argv[2]);
	எனில் (fido_cred_x5c_ptr(cred) != வெற்று) {
		debug("basic attestation");
		எனில் ((r = fido_cred_verify(cred)) != FIDO_OK)
			fatal("basic attestation failed");
		style = "basic";
	} இல்லையெனில் {
		debug("self attestation");
		எனில் ((r = fido_cred_verify_self(cred)) != FIDO_OK)
			fatal("self attestation failed");
		style = "self";
	}
	எனில் (cred_matches_சாவி(cred, k) != 0)
		fatal("cred authdata does not match key");

	fido_cred_free(&cred);

	எனில் (write_attestation_cert) {
		PEM_write(stdout, "CERTIFICATE", வெற்று,
		    sshbuf_ptr(attestation_cert), sshbuf_len(attestation_cert));
	}
	sshbuf_free(attestation_cert);

	logit("%s: verified %s attestation", argv[2], style);

	திரும்பு (0);
}
