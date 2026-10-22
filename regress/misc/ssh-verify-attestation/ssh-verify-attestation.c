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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <inttypes.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "authfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "digest.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "crypto_api.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <fido.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/x509.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/x509v3.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/bio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/err.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/pem.h>
#ਅਨ੍ਤਰ੍ਭਾਵ "openbsd-compat/openssl-compat.h"

ਬਾਹਰੀ ਅੱਖਰ *__progname;

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ATTEST_MAGIC	"ssh-sk-attest-v01"

ਸਥਿਰ ਪੂਰਨ
prepare_fido_cred(fido_cred_t *cred, ਪੂਰਨ credtype, ਅਚਲ ਅੱਖਰ *attfmt,
    ਅਚਲ ਅੱਖਰ *rp_id, ਬਣਤਰ sshbuf *b, ਅਚਲ ਬਣਤਰ sshbuf *challenge,
    ਬਣਤਰ sshbuf **attestation_certp)
{
	ਬਣਤਰ sshbuf *attestation_cert = ਨਿਰਾ, *sig = ਨਿਰਾ, *authdata = ਨਿਰਾ;
	ਅੱਖਰ *magic = ਨਿਰਾ;
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

	*attestation_certp = ਨਿਰਾ;

	/* Make sure it's the format we're expecting */
	ਜੇ ((r = sshbuf_get_cstring(b, &magic, ਨਿਰਾ)) != 0) {
		error_fr(r, "parse header");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (strcmp(magic, ATTEST_MAGIC) != 0) {
		error_f("unsupported format");
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* Parse the remaining fields */
	ਜੇ ((r = sshbuf_froms(b, &attestation_cert)) != 0 ||
	    (r = sshbuf_froms(b, &sig)) != 0 ||
	    (r = sshbuf_froms(b, &authdata)) != 0 ||
	    (r = sshbuf_get_u32(b, ਨਿਰਾ)) != 0 || /* reserved flags */
	    (r = sshbuf_get_string_ਸਿੱਧਾ(b, ਨਿਰਾ, ਨਿਰਾ)) != 0) { /* reserved */
		error_fr(r, "parse body");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	debug3_f("attestation cert len=%zu, sig len=%zu, "
	    "authdata len=%zu challenge len=%zu", sshbuf_len(attestation_cert),
	    sshbuf_len(sig), sshbuf_len(authdata), sshbuf_len(challenge));

	fido_cred_ਸੈੱਟ_type(cred, credtype);
	fido_cred_ਸੈੱਟ_fmt(cred, attfmt);
	fido_cred_ਸੈੱਟ_clientdata(cred, sshbuf_ptr(challenge),
	    sshbuf_len(challenge));
	fido_cred_ਸੈੱਟ_rp(cred, rp_id, ਨਿਰਾ);
	fido_cred_ਸੈੱਟ_authdata(cred, sshbuf_ptr(authdata),
	    sshbuf_len(authdata));
	/* XXX set_extensions, set_rk, set_uv */
	fido_cred_ਸੈੱਟ_x509(cred, sshbuf_ptr(attestation_cert),
	    sshbuf_len(attestation_cert));
	fido_cred_ਸੈੱਟ_sig(cred, sshbuf_ptr(sig), sshbuf_len(sig));

	/* success */
	*attestation_certp = attestation_cert;
	attestation_cert = ਨਿਰਾ;
	r = 0;
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(magic);
	sshbuf_free(attestation_cert);
	sshbuf_free(sig);
	sshbuf_free(authdata);
	ਵਾਪਸ r;
}

ਸਥਿਰ uint8_t *
get_pubkey_from_cred_ecdsa(ਅਚਲ fido_cred_t *cred, ਮਾਪ_t *pubkey_len)
{
	ਅਚਲ uint8_t *ptr;
	uint8_t *pubkey = ਨਿਰਾ, *ret = ਨਿਰਾ;
	BIGNUM *x = ਨਿਰਾ, *y = ਨਿਰਾ;
	EC_ਬਿੰਦੂ *q = ਨਿਰਾ;
	EC_ਸਮੂਹ *g = ਨਿਰਾ;

	ਜੇ ((x = BN_new()) == ਨਿਰਾ ||
	    (y = BN_new()) == ਨਿਰਾ ||
	    (g = EC_ਸਮੂਹ_new_by_ਵਕਰ_name(NID_X9_62_prime256v1)) == ਨਿਰਾ ||
	    (q = EC_ਬਿੰਦੂ_new(g)) == ਨਿਰਾ) {
		error_f("libcrypto setup failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((ptr = fido_cred_pubkey_ptr(cred)) == ਨਿਰਾ) {
		error_f("fido_cred_pubkey_ptr failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (fido_cred_pubkey_len(cred) != 64) {
		error_f("bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ (BN_bin2bn(ptr, 32, x) == ਨਿਰਾ ||
	    BN_bin2bn(ptr + 32, 32, y) == ਨਿਰਾ) {
		error_f("BN_bin2bn failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (EC_ਬਿੰਦੂ_ਸੈੱਟ_affine_coordinates(g, q, x, y, ਨਿਰਾ) != 1) {
		error_f("EC_POINT_set_affine_coordinates failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	*pubkey_len = EC_ਬਿੰਦੂ_point2oct(g, q,
	    ਬਿੰਦੂ_CONVERSION_UNCOMPRESSED, ਨਿਰਾ, 0, ਨਿਰਾ);
	ਜੇ (*pubkey_len == 0 || *pubkey_len > 2048) {
		error_f("bad pubkey length %zu", *pubkey_len);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((pubkey = ਸਮ੍ਰਿਤੀ_ਦਿਓ(*pubkey_len)) == ਨਿਰਾ) {
		error_f("malloc pubkey failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (EC_ਬਿੰਦੂ_point2oct(g, q, ਬਿੰਦੂ_CONVERSION_UNCOMPRESSED,
	    pubkey, *pubkey_len, ਨਿਰਾ) == 0) {
		error_f("EC_POINT_point2oct failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* success */
	ret = pubkey;
	pubkey = ਨਿਰਾ;
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(pubkey);
	EC_ਬਿੰਦੂ_free(q);
	EC_ਸਮੂਹ_free(g);
	BN_clear_free(x);
	BN_clear_free(y);
	ਵਾਪਸ ret;
}

/* copied from sshsk_ecdsa_assemble() */
ਸਥਿਰ ਪੂਰਨ
cred_matches_ਕੁੰਜੀ_ecdsa(ਅਚਲ fido_cred_t *cred, ਅਚਲ ਬਣਤਰ sshkey *k)
{
	ਬਣਤਰ sshkey *ਕੁੰਜੀ = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *b = ਨਿਰਾ;
	EC_ਕੁੰਜੀ *ec = ਨਿਰਾ;
	uint8_t *pubkey = ਨਿਰਾ;
	ਮਾਪ_t pubkey_len;
	ਪੂਰਨ r;

	ਜੇ ((ਕੁੰਜੀ = sshkey_new(ਕੁੰਜੀ_ECDSA_SK)) == ਨਿਰਾ) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਕੁੰਜੀ->ecdsa_nid = NID_X9_62_prime256v1;
	ਜੇ ((ਕੁੰਜੀ->pkey = EVP_PKEY_new()) == ਨਿਰਾ ||
	    (ec = EC_ਕੁੰਜੀ_new_by_ਵਕਰ_name(ਕੁੰਜੀ->ecdsa_nid)) == ਨਿਰਾ ||
	    (b = sshbuf_new()) == ਨਿਰਾ) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((pubkey = get_pubkey_from_cred_ecdsa(cred, &pubkey_len)) == ਨਿਰਾ) {
		error_f("get_pubkey_from_cred_ecdsa failed");
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_put_string(b, pubkey, pubkey_len)) != 0) {
		error_fr(r, "sshbuf_put_string");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_get_eckey(b, ec)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (sshkey_ec_validate_ਜਨਤਕ(EC_ਕੁੰਜੀ_get0_ਸਮੂਹ(ec),
	    EC_ਕੁੰਜੀ_get0_ਜਨਤਕ_ਕੁੰਜੀ(ec)) != 0) {
		error("Authenticator returned invalid ECDSA key");
		r = SSH_ERR_ਕੁੰਜੀ_INVALID_EC_ਮੁੱਲ;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (EVP_PKEY_set1_EC_ਕੁੰਜੀ(ਕੁੰਜੀ->pkey, ec) != 1) {
		/* XXX assume it is a allocation error */
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਕੁੰਜੀ->sk_application = xstrdup(k->sk_application); /* XXX */
	ਜੇ (!sshkey_equal_ਜਨਤਕ(ਕੁੰਜੀ, k)) {
		error("sshkey_equal_public failed");
		r = SSH_ERR_INVALID_ਦਲੀਲ;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	r = 0; /* success */
 ਬਾਹਰਲਾ:
	EC_ਕੁੰਜੀ_free(ec);
	ਮੁਕਤ(pubkey);
	sshkey_free(ਕੁੰਜੀ);
	sshbuf_free(b);
	ਵਾਪਸ r;
}


/* copied from sshsk_ed25519_assemble() */
ਸਥਿਰ ਪੂਰਨ
cred_matches_ਕੁੰਜੀ_ed25519(ਅਚਲ fido_cred_t *cred, ਅਚਲ ਬਣਤਰ sshkey *k)
{
	ਬਣਤਰ sshkey *ਕੁੰਜੀ = ਨਿਰਾ;
	ਅਚਲ uint8_t *ptr;
	ਪੂਰਨ r = -1;

	ਜੇ ((ptr = fido_cred_pubkey_ptr(cred)) == ਨਿਰਾ) {
		error_f("fido_cred_pubkey_ptr failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (fido_cred_pubkey_len(cred) != ED25519_PK_SZ) {
		error_f("bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ ((ਕੁੰਜੀ = sshkey_new(ਕੁੰਜੀ_ED25519_SK)) == ਨਿਰਾ) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((ਕੁੰਜੀ->ed25519_pk = ਸਮ੍ਰਿਤੀ_ਦਿਓ(ED25519_PK_SZ)) == ਨਿਰਾ) {
		error_f("malloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(ਕੁੰਜੀ->ed25519_pk, ptr, ED25519_PK_SZ);
	ਕੁੰਜੀ->sk_application = xstrdup(k->sk_application); /* XXX */
	ਜੇ (!sshkey_equal_ਜਨਤਕ(ਕੁੰਜੀ, k)) {
		error("sshkey_equal_public failed");
		r = SSH_ERR_INVALID_ਦਲੀਲ;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	r = 0; /* success */
 ਬਾਹਰਲਾ:
	sshkey_free(ਕੁੰਜੀ);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਪੂਰਨ
cred_matches_ਕੁੰਜੀ(ਅਚਲ fido_cred_t *cred, ਅਚਲ ਬਣਤਰ sshkey *k)
{
	ਚੋਣ (sshkey_type_plain(k->type)) {
	ਹਾਲਤ ਕੁੰਜੀ_ECDSA_SK:
		ਚੋਣ (k->ecdsa_nid) {
		ਹਾਲਤ NID_X9_62_prime256v1:
			ਵਾਪਸ cred_matches_ਕੁੰਜੀ_ecdsa(cred, k);
			ਰੋਕੋ;
		ਮੂਲ:
			fatal("Unsupported ECDSA key size");
		}
		ਰੋਕੋ;
	ਹਾਲਤ ਕੁੰਜੀ_ED25519_SK:
		ਵਾਪਸ cred_matches_ਕੁੰਜੀ_ed25519(cred, k);
	ਮੂਲ:
		error_f("key type %s not supported", sshkey_type(k));
		ਵਾਪਸ -1;
	}
}

ਪੂਰਨ
ਮੁੱਖ(ਪੂਰਨ argc, ਅੱਖਰ **argv)
{
	LogLevel log_level = SYSLOG_LEVEL_INFO;
	ਪੂਰਨ r, ch, credtype = -1;
	ਬਣਤਰ sshkey *k = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *attestation = ਨਿਰਾ, *challenge = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *attestation_cert = ਨਿਰਾ;
	ਅੱਖਰ *fp;
	ਅਚਲ ਅੱਖਰ *attfmt = "packed", *style = ਨਿਰਾ;
	fido_cred_t *cred = ਨਿਰਾ;
	ਪੂਰਨ write_attestation_cert = 0;
	ਬਾਹਰੀ ਪੂਰਨ optind;
	/* extern char *optarg; */

	OPENSSL_init_crypto(OPENSSL_INIT_ਲੱਦੋ_CRYPTO_ਲੜੀਆਂ, ਨਿਰਾ);

	sanitise_stdfd();
	log_init(__progname, log_level, SYSLOG_FACILITY_AUTH, 1);

	ਜਦੋਂ ((ch = getopt(argc, argv, "UAv")) != -1) {
		ਚੋਣ (ch) {
		ਹਾਲਤ 'U':
			attfmt = "fido-u2f";
			ਰੋਕੋ;
		ਹਾਲਤ 'A':
			write_attestation_cert = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'v':
			ਜੇ (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			ਨਹੀਂਤਾਂ ਜੇ (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			ਰੋਕੋ;
		ਮੂਲ:
			ਜਾਓ usage;
		}
	}
	log_init(__progname, log_level, SYSLOG_FACILITY_AUTH, 1);
	argv += optind;
	argc -= optind;

	ਜੇ (argc < 3) {
 usage:
		fprintf(stderr, "usage: %s [-vAU] "
		   "pubkey challenge attestation-blob\n", __progname);
		ਬਾਹਰ_ਨਿਕਲੋ(1);
	}
	ਜੇ ((r = sshkey_ਲੱਦੋ_ਜਨਤਕ(argv[0], &k, ਨਿਰਾ)) != 0)
		fatal_r(r, "load key %s", argv[0]);
	ਜੇ ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ਨਿਰਾ)
		fatal("sshkey_fingerprint failed");
	debug2("key %s: %s %s", argv[2], sshkey_type(k), fp);
	ਮੁਕਤ(fp);
	ਜੇ ((r = sshbuf_ਲੱਦੋ_file(argv[1], &challenge)) != 0)
		fatal_r(r, "load challenge %s", argv[1]);
	ਜੇ ((r = sshbuf_ਲੱਦੋ_file(argv[2], &attestation)) != 0)
		fatal_r(r, "load attestation %s", argv[2]);
	ਜੇ ((cred = fido_cred_new()) == ਨਿਰਾ)
		fatal("fido_cred_new failed");

	ਚੋਣ (sshkey_type_plain(k->type)) {
	ਹਾਲਤ ਕੁੰਜੀ_ECDSA_SK:
		ਚੋਣ (k->ecdsa_nid) {
		ਹਾਲਤ NID_X9_62_prime256v1:
			credtype = COSE_ES256;
			ਰੋਕੋ;
		ਮੂਲ:
			fatal("Unsupported ECDSA key size");
		}
		ਰੋਕੋ;
	ਹਾਲਤ ਕੁੰਜੀ_ED25519_SK:
		credtype = COSE_EDDSA;
		ਰੋਕੋ;
	ਮੂਲ:
		fatal("unsupported key type %s", sshkey_type(k));
	}

	ਜੇ ((r = prepare_fido_cred(cred, credtype, attfmt, k->sk_application,
	    attestation, challenge, &attestation_cert)) != 0)
		fatal_r(r, "prepare_fido_cred %s", argv[2]);
	ਜੇ (fido_cred_x5c_ptr(cred) != ਨਿਰਾ) {
		debug("basic attestation");
		ਜੇ ((r = fido_cred_verify(cred)) != FIDO_OK)
			fatal("basic attestation failed");
		style = "basic";
	} ਨਹੀਂਤਾਂ {
		debug("self attestation");
		ਜੇ ((r = fido_cred_verify_self(cred)) != FIDO_OK)
			fatal("self attestation failed");
		style = "self";
	}
	ਜੇ (cred_matches_ਕੁੰਜੀ(cred, k) != 0)
		fatal("cred authdata does not match key");

	fido_cred_free(&cred);

	ਜੇ (write_attestation_cert) {
		PEM_write(stdout, "CERTIFICATE", ਨਿਰਾ,
		    sshbuf_ptr(attestation_cert), sshbuf_len(attestation_cert));
	}
	sshbuf_free(attestation_cert);

	logit("%s: verified %s attestation", argv[2], style);

	ਵਾਪਸ (0);
}
