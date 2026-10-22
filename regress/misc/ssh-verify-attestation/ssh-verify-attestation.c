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

خارجی حرف *__progname;

#تعریف_کرو ATTEST_MAGIC	"ssh-sk-attest-v01"

ساکن صحیح
prepare_fido_cred(fido_cred_t *cred, صحیح credtype, ثابت حرف *attfmt,
    ثابت حرف *rp_id, ساخت sshbuf *b, ثابت ساخت sshbuf *challenge,
    ساخت sshbuf **attestation_certp)
{
	ساخت sshbuf *attestation_cert = تہی, *sig = تہی, *authdata = تہی;
	حرف *magic = تہی;
	صحیح r = SSH_ERR_اندرونی_ERROR;

	*attestation_certp = تہی;

	/* Make sure it's the format we're expecting */
	اگر ((r = sshbuf_get_cstring(b, &magic, تہی)) != 0) {
		error_fr(r, "parse header");
		جاؤ برآمد;
	}
	اگر (strcmp(magic, ATTEST_MAGIC) != 0) {
		error_f("unsupported format");
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	/* Parse the remaining fields */
	اگر ((r = sshbuf_froms(b, &attestation_cert)) != 0 ||
	    (r = sshbuf_froms(b, &sig)) != 0 ||
	    (r = sshbuf_froms(b, &authdata)) != 0 ||
	    (r = sshbuf_get_u32(b, تہی)) != 0 || /* reserved flags */
	    (r = sshbuf_get_string_براہ_راست(b, تہی, تہی)) != 0) { /* reserved */
		error_fr(r, "parse body");
		جاؤ برآمد;
	}
	debug3_f("attestation cert len=%zu, sig len=%zu, "
	    "authdata len=%zu challenge len=%zu", sshbuf_len(attestation_cert),
	    sshbuf_len(sig), sshbuf_len(authdata), sshbuf_len(challenge));

	fido_cred_سیٹ_type(cred, credtype);
	fido_cred_سیٹ_fmt(cred, attfmt);
	fido_cred_سیٹ_clientdata(cred, sshbuf_ptr(challenge),
	    sshbuf_len(challenge));
	fido_cred_سیٹ_rp(cred, rp_id, تہی);
	fido_cred_سیٹ_authdata(cred, sshbuf_ptr(authdata),
	    sshbuf_len(authdata));
	/* XXX set_extensions, set_rk, set_uv */
	fido_cred_سیٹ_x509(cred, sshbuf_ptr(attestation_cert),
	    sshbuf_len(attestation_cert));
	fido_cred_سیٹ_sig(cred, sshbuf_ptr(sig), sshbuf_len(sig));

	/* success */
	*attestation_certp = attestation_cert;
	attestation_cert = تہی;
	r = 0;
 برآمد:
	آزاد(magic);
	sshbuf_free(attestation_cert);
	sshbuf_free(sig);
	sshbuf_free(authdata);
	واپس r;
}

ساکن uint8_t *
get_pubkey_from_cred_ecdsa(ثابت fido_cred_t *cred, سائز_t *pubkey_len)
{
	ثابت uint8_t *ptr;
	uint8_t *pubkey = تہی, *ret = تہی;
	BIGNUM *x = تہی, *y = تہی;
	EC_نقطہ *q = تہی;
	EC_گروہ *g = تہی;

	اگر ((x = BN_new()) == تہی ||
	    (y = BN_new()) == تہی ||
	    (g = EC_گروہ_new_by_خم_name(NID_X9_62_prime256v1)) == تہی ||
	    (q = EC_نقطہ_new(g)) == تہی) {
		error_f("libcrypto setup failed");
		جاؤ برآمد;
	}
	اگر ((ptr = fido_cred_pubkey_ptr(cred)) == تہی) {
		error_f("fido_cred_pubkey_ptr failed");
		جاؤ برآمد;
	}
	اگر (fido_cred_pubkey_len(cred) != 64) {
		error_f("bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		جاؤ برآمد;
	}

	اگر (BN_bin2bn(ptr, 32, x) == تہی ||
	    BN_bin2bn(ptr + 32, 32, y) == تہی) {
		error_f("BN_bin2bn failed");
		جاؤ برآمد;
	}
	اگر (EC_نقطہ_سیٹ_affine_coordinates(g, q, x, y, تہی) != 1) {
		error_f("EC_POINT_set_affine_coordinates failed");
		جاؤ برآمد;
	}
	*pubkey_len = EC_نقطہ_point2oct(g, q,
	    نقطہ_CONVERSION_UNCOMPRESSED, تہی, 0, تہی);
	اگر (*pubkey_len == 0 || *pubkey_len > 2048) {
		error_f("bad pubkey length %zu", *pubkey_len);
		جاؤ برآمد;
	}
	اگر ((pubkey = حافظہ_دو(*pubkey_len)) == تہی) {
		error_f("malloc pubkey failed");
		جاؤ برآمد;
	}
	اگر (EC_نقطہ_point2oct(g, q, نقطہ_CONVERSION_UNCOMPRESSED,
	    pubkey, *pubkey_len, تہی) == 0) {
		error_f("EC_POINT_point2oct failed");
		جاؤ برآمد;
	}
	/* success */
	ret = pubkey;
	pubkey = تہی;
 برآمد:
	آزاد(pubkey);
	EC_نقطہ_free(q);
	EC_گروہ_free(g);
	BN_clear_free(x);
	BN_clear_free(y);
	واپس ret;
}

/* copied from sshsk_ecdsa_assemble() */
ساکن صحیح
cred_matches_کلید_ecdsa(ثابت fido_cred_t *cred, ثابت ساخت sshkey *k)
{
	ساخت sshkey *کلید = تہی;
	ساخت sshbuf *b = تہی;
	EC_کلید *ec = تہی;
	uint8_t *pubkey = تہی;
	سائز_t pubkey_len;
	صحیح r;

	اگر ((کلید = sshkey_new(کلید_ECDSA_SK)) == تہی) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	کلید->ecdsa_nid = NID_X9_62_prime256v1;
	اگر ((کلید->pkey = EVP_PKEY_new()) == تہی ||
	    (ec = EC_کلید_new_by_خم_name(کلید->ecdsa_nid)) == تہی ||
	    (b = sshbuf_new()) == تہی) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر ((pubkey = get_pubkey_from_cred_ecdsa(cred, &pubkey_len)) == تہی) {
		error_f("get_pubkey_from_cred_ecdsa failed");
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	اگر ((r = sshbuf_put_string(b, pubkey, pubkey_len)) != 0) {
		error_fr(r, "sshbuf_put_string");
		جاؤ برآمد;
	}
	اگر ((r = sshbuf_get_eckey(b, ec)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	اگر (sshkey_ec_validate_عوامی(EC_کلید_get0_گروہ(ec),
	    EC_کلید_get0_عوامی_کلید(ec)) != 0) {
		error("Authenticator returned invalid ECDSA key");
		r = SSH_ERR_کلید_INVALID_EC_قدر;
		جاؤ برآمد;
	}
	اگر (EVP_PKEY_set1_EC_کلید(کلید->pkey, ec) != 1) {
		/* XXX assume it is a allocation error */
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	کلید->sk_application = xstrdup(k->sk_application); /* XXX */
	اگر (!sshkey_equal_عوامی(کلید, k)) {
		error("sshkey_equal_public failed");
		r = SSH_ERR_INVALID_دلیل;
		جاؤ برآمد;
	}
	r = 0; /* success */
 برآمد:
	EC_کلید_free(ec);
	آزاد(pubkey);
	sshkey_free(کلید);
	sshbuf_free(b);
	واپس r;
}


/* copied from sshsk_ed25519_assemble() */
ساکن صحیح
cred_matches_کلید_ed25519(ثابت fido_cred_t *cred, ثابت ساخت sshkey *k)
{
	ساخت sshkey *کلید = تہی;
	ثابت uint8_t *ptr;
	صحیح r = -1;

	اگر ((ptr = fido_cred_pubkey_ptr(cred)) == تہی) {
		error_f("fido_cred_pubkey_ptr failed");
		جاؤ برآمد;
	}
	اگر (fido_cred_pubkey_len(cred) != ED25519_PK_SZ) {
		error_f("bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		جاؤ برآمد;
	}

	اگر ((کلید = sshkey_new(کلید_ED25519_SK)) == تہی) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر ((کلید->ed25519_pk = حافظہ_دو(ED25519_PK_SZ)) == تہی) {
		error_f("malloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	حافظہ_نقل(کلید->ed25519_pk, ptr, ED25519_PK_SZ);
	کلید->sk_application = xstrdup(k->sk_application); /* XXX */
	اگر (!sshkey_equal_عوامی(کلید, k)) {
		error("sshkey_equal_public failed");
		r = SSH_ERR_INVALID_دلیل;
		جاؤ برآمد;
	}
	r = 0; /* success */
 برآمد:
	sshkey_free(کلید);
	واپس r;
}

ساکن صحیح
cred_matches_کلید(ثابت fido_cred_t *cred, ثابت ساخت sshkey *k)
{
	انتخاب (sshkey_type_plain(k->type)) {
	حالت کلید_ECDSA_SK:
		انتخاب (k->ecdsa_nid) {
		حالت NID_X9_62_prime256v1:
			واپس cred_matches_کلید_ecdsa(cred, k);
			توڑو;
		طےشدہ:
			fatal("Unsupported ECDSA key size");
		}
		توڑو;
	حالت کلید_ED25519_SK:
		واپس cred_matches_کلید_ed25519(cred, k);
	طےشدہ:
		error_f("key type %s not supported", sshkey_type(k));
		واپس -1;
	}
}

صحیح
مین(صحیح argc, حرف **argv)
{
	LogLevel log_level = SYSLOG_LEVEL_INFO;
	صحیح r, ch, credtype = -1;
	ساخت sshkey *k = تہی;
	ساخت sshbuf *attestation = تہی, *challenge = تہی;
	ساخت sshbuf *attestation_cert = تہی;
	حرف *fp;
	ثابت حرف *attfmt = "packed", *style = تہی;
	fido_cred_t *cred = تہی;
	صحیح write_attestation_cert = 0;
	خارجی صحیح optind;
	/* extern char *optarg; */

	OPENSSL_init_crypto(OPENSSL_INIT_بھرو_CRYPTO_لڑیاں, تہی);

	sanitise_stdfd();
	log_init(__progname, log_level, SYSLOG_FACILITY_AUTH, 1);

	جب ((ch = getopt(argc, argv, "UAv")) != -1) {
		انتخاب (ch) {
		حالت 'U':
			attfmt = "fido-u2f";
			توڑو;
		حالت 'A':
			write_attestation_cert = 1;
			توڑو;
		حالت 'v':
			اگر (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			ورنہ اگر (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			توڑو;
		طےشدہ:
			جاؤ usage;
		}
	}
	log_init(__progname, log_level, SYSLOG_FACILITY_AUTH, 1);
	argv += optind;
	argc -= optind;

	اگر (argc < 3) {
 usage:
		fprintf(stderr, "usage: %s [-vAU] "
		   "pubkey challenge attestation-blob\n", __progname);
		باہر_نکلو(1);
	}
	اگر ((r = sshkey_بھرو_عوامی(argv[0], &k, تہی)) != 0)
		fatal_r(r, "load key %s", argv[0]);
	اگر ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == تہی)
		fatal("sshkey_fingerprint failed");
	debug2("key %s: %s %s", argv[2], sshkey_type(k), fp);
	آزاد(fp);
	اگر ((r = sshbuf_بھرو_file(argv[1], &challenge)) != 0)
		fatal_r(r, "load challenge %s", argv[1]);
	اگر ((r = sshbuf_بھرو_file(argv[2], &attestation)) != 0)
		fatal_r(r, "load attestation %s", argv[2]);
	اگر ((cred = fido_cred_new()) == تہی)
		fatal("fido_cred_new failed");

	انتخاب (sshkey_type_plain(k->type)) {
	حالت کلید_ECDSA_SK:
		انتخاب (k->ecdsa_nid) {
		حالت NID_X9_62_prime256v1:
			credtype = COSE_ES256;
			توڑو;
		طےشدہ:
			fatal("Unsupported ECDSA key size");
		}
		توڑو;
	حالت کلید_ED25519_SK:
		credtype = COSE_EDDSA;
		توڑو;
	طےشدہ:
		fatal("unsupported key type %s", sshkey_type(k));
	}

	اگر ((r = prepare_fido_cred(cred, credtype, attfmt, k->sk_application,
	    attestation, challenge, &attestation_cert)) != 0)
		fatal_r(r, "prepare_fido_cred %s", argv[2]);
	اگر (fido_cred_x5c_ptr(cred) != تہی) {
		debug("basic attestation");
		اگر ((r = fido_cred_verify(cred)) != FIDO_OK)
			fatal("basic attestation failed");
		style = "basic";
	} ورنہ {
		debug("self attestation");
		اگر ((r = fido_cred_verify_self(cred)) != FIDO_OK)
			fatal("self attestation failed");
		style = "self";
	}
	اگر (cred_matches_کلید(cred, k) != 0)
		fatal("cred authdata does not match key");

	fido_cred_free(&cred);

	اگر (write_attestation_cert) {
		PEM_write(stdout, "CERTIFICATE", تہی,
		    sshbuf_ptr(attestation_cert), sshbuf_len(attestation_cert));
	}
	sshbuf_free(attestation_cert);

	logit("%s: verified %s attestation", argv[2], style);

	واپس (0);
}
