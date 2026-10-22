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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <stdint.h>
#అన్తర్భావ <inttypes.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <stdarg.h>

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "authfile.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "digest.h"
#అన్తర్భావ "crypto_api.h"

#అన్తర్భావ <fido.h>
#అన్తర్భావ <openssl/x509.h>
#అన్తర్భావ <openssl/x509v3.h>
#అన్తర్భావ <openssl/bio.h>
#అన్తర్భావ <openssl/err.h>
#అన్తర్భావ <openssl/pem.h>
#అన్తర్భావ "openbsd-compat/openssl-compat.h"

బాహ్య అక్షరం *__progname;

#నిర్వచించు ATTEST_MAGIC	"ssh-sk-attest-v01"

స్థిర పూర్ణాంకం
prepare_fido_cred(fido_cred_t *cred, పూర్ణాంకం credtype, స్థిరరాశి అక్షరం *attfmt,
    స్థిరరాశి అక్షరం *rp_id, నిర్మాణం sshbuf *b, స్థిరరాశి నిర్మాణం sshbuf *challenge,
    నిర్మాణం sshbuf **attestation_certp)
{
	నిర్మాణం sshbuf *attestation_cert = ఖాళీ, *sig = ఖాళీ, *authdata = ఖాళీ;
	అక్షరం *magic = ఖాళీ;
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;

	*attestation_certp = ఖాళీ;

	/* Make sure it's the format we're expecting */
	ఒకవేళ ((r = sshbuf_get_cstring(b, &magic, ఖాళీ)) != 0) {
		error_fr(r, "parse header");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (strcmp(magic, ATTEST_MAGIC) != 0) {
		error_f("unsupported format");
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	/* Parse the remaining fields */
	ఒకవేళ ((r = sshbuf_froms(b, &attestation_cert)) != 0 ||
	    (r = sshbuf_froms(b, &sig)) != 0 ||
	    (r = sshbuf_froms(b, &authdata)) != 0 ||
	    (r = sshbuf_get_u32(b, ఖాళీ)) != 0 || /* reserved flags */
	    (r = sshbuf_get_string_ప్రత్యక్ష(b, ఖాళీ, ఖాళీ)) != 0) { /* reserved */
		error_fr(r, "parse body");
		వెళ్ళు బహిర్గతం;
	}
	debug3_f("attestation cert len=%zu, sig len=%zu, "
	    "authdata len=%zu challenge len=%zu", sshbuf_len(attestation_cert),
	    sshbuf_len(sig), sshbuf_len(authdata), sshbuf_len(challenge));

	fido_cred_సమితి_type(cred, credtype);
	fido_cred_సమితి_fmt(cred, attfmt);
	fido_cred_సమితి_clientdata(cred, sshbuf_ptr(challenge),
	    sshbuf_len(challenge));
	fido_cred_సమితి_rp(cred, rp_id, ఖాళీ);
	fido_cred_సమితి_authdata(cred, sshbuf_ptr(authdata),
	    sshbuf_len(authdata));
	/* XXX set_extensions, set_rk, set_uv */
	fido_cred_సమితి_x509(cred, sshbuf_ptr(attestation_cert),
	    sshbuf_len(attestation_cert));
	fido_cred_సమితి_sig(cred, sshbuf_ptr(sig), sshbuf_len(sig));

	/* success */
	*attestation_certp = attestation_cert;
	attestation_cert = ఖాళీ;
	r = 0;
 బహిర్గతం:
	విడుదల(magic);
	sshbuf_free(attestation_cert);
	sshbuf_free(sig);
	sshbuf_free(authdata);
	తిరిగి r;
}

స్థిర uint8_t *
get_pubkey_from_cred_ecdsa(స్థిరరాశి fido_cred_t *cred, కొలత_t *pubkey_len)
{
	స్థిరరాశి uint8_t *ptr;
	uint8_t *pubkey = ఖాళీ, *ret = ఖాళీ;
	BIGNUM *x = ఖాళీ, *y = ఖాళీ;
	EC_బిందువు *q = ఖాళీ;
	EC_సమూహం *g = ఖాళీ;

	ఒకవేళ ((x = BN_new()) == ఖాళీ ||
	    (y = BN_new()) == ఖాళీ ||
	    (g = EC_సమూహం_new_by_వక్రం_name(NID_X9_62_prime256v1)) == ఖాళీ ||
	    (q = EC_బిందువు_new(g)) == ఖాళీ) {
		error_f("libcrypto setup failed");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((ptr = fido_cred_pubkey_ptr(cred)) == ఖాళీ) {
		error_f("fido_cred_pubkey_ptr failed");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (fido_cred_pubkey_len(cred) != 64) {
		error_f("bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ (BN_bin2bn(ptr, 32, x) == ఖాళీ ||
	    BN_bin2bn(ptr + 32, 32, y) == ఖాళీ) {
		error_f("BN_bin2bn failed");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (EC_బిందువు_సమితి_affine_coordinates(g, q, x, y, ఖాళీ) != 1) {
		error_f("EC_POINT_set_affine_coordinates failed");
		వెళ్ళు బహిర్గతం;
	}
	*pubkey_len = EC_బిందువు_point2oct(g, q,
	    బిందువు_CONVERSION_UNCOMPRESSED, ఖాళీ, 0, ఖాళీ);
	ఒకవేళ (*pubkey_len == 0 || *pubkey_len > 2048) {
		error_f("bad pubkey length %zu", *pubkey_len);
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((pubkey = జ్ఞాపకం_ఇవ్వు(*pubkey_len)) == ఖాళీ) {
		error_f("malloc pubkey failed");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (EC_బిందువు_point2oct(g, q, బిందువు_CONVERSION_UNCOMPRESSED,
	    pubkey, *pubkey_len, ఖాళీ) == 0) {
		error_f("EC_POINT_point2oct failed");
		వెళ్ళు బహిర్గతం;
	}
	/* success */
	ret = pubkey;
	pubkey = ఖాళీ;
 బహిర్గతం:
	విడుదల(pubkey);
	EC_బిందువు_free(q);
	EC_సమూహం_free(g);
	BN_clear_free(x);
	BN_clear_free(y);
	తిరిగి ret;
}

/* copied from sshsk_ecdsa_assemble() */
స్థిర పూర్ణాంకం
cred_matches_కీలకం_ecdsa(స్థిరరాశి fido_cred_t *cred, స్థిరరాశి నిర్మాణం sshkey *k)
{
	నిర్మాణం sshkey *కీలకం = ఖాళీ;
	నిర్మాణం sshbuf *b = ఖాళీ;
	EC_కీలకం *ec = ఖాళీ;
	uint8_t *pubkey = ఖాళీ;
	కొలత_t pubkey_len;
	పూర్ణాంకం r;

	ఒకవేళ ((కీలకం = sshkey_new(కీలకం_ECDSA_SK)) == ఖాళీ) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	కీలకం->ecdsa_nid = NID_X9_62_prime256v1;
	ఒకవేళ ((కీలకం->pkey = EVP_PKEY_new()) == ఖాళీ ||
	    (ec = EC_కీలకం_new_by_వక్రం_name(కీలకం->ecdsa_nid)) == ఖాళీ ||
	    (b = sshbuf_new()) == ఖాళీ) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((pubkey = get_pubkey_from_cred_ecdsa(cred, &pubkey_len)) == ఖాళీ) {
		error_f("get_pubkey_from_cred_ecdsa failed");
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_put_string(b, pubkey, pubkey_len)) != 0) {
		error_fr(r, "sshbuf_put_string");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_get_eckey(b, ec)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (sshkey_ec_validate_ప్రజా(EC_కీలకం_get0_సమూహం(ec),
	    EC_కీలకం_get0_ప్రజా_కీలకం(ec)) != 0) {
		error("Authenticator returned invalid ECDSA key");
		r = SSH_ERR_కీలకం_INVALID_EC_విలువ;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (EVP_PKEY_set1_EC_కీలకం(కీలకం->pkey, ec) != 1) {
		/* XXX assume it is a allocation error */
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	కీలకం->sk_application = xstrdup(k->sk_application); /* XXX */
	ఒకవేళ (!sshkey_equal_ప్రజా(కీలకం, k)) {
		error("sshkey_equal_public failed");
		r = SSH_ERR_INVALID_వాదం;
		వెళ్ళు బహిర్గతం;
	}
	r = 0; /* success */
 బహిర్గతం:
	EC_కీలకం_free(ec);
	విడుదల(pubkey);
	sshkey_free(కీలకం);
	sshbuf_free(b);
	తిరిగి r;
}


/* copied from sshsk_ed25519_assemble() */
స్థిర పూర్ణాంకం
cred_matches_కీలకం_ed25519(స్థిరరాశి fido_cred_t *cred, స్థిరరాశి నిర్మాణం sshkey *k)
{
	నిర్మాణం sshkey *కీలకం = ఖాళీ;
	స్థిరరాశి uint8_t *ptr;
	పూర్ణాంకం r = -1;

	ఒకవేళ ((ptr = fido_cred_pubkey_ptr(cred)) == ఖాళీ) {
		error_f("fido_cred_pubkey_ptr failed");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (fido_cred_pubkey_len(cred) != ED25519_PK_SZ) {
		error_f("bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ ((కీలకం = sshkey_new(కీలకం_ED25519_SK)) == ఖాళీ) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((కీలకం->ed25519_pk = జ్ఞాపకం_ఇవ్వు(ED25519_PK_SZ)) == ఖాళీ) {
		error_f("malloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	జ్ఞాపకం_నకలు(కీలకం->ed25519_pk, ptr, ED25519_PK_SZ);
	కీలకం->sk_application = xstrdup(k->sk_application); /* XXX */
	ఒకవేళ (!sshkey_equal_ప్రజా(కీలకం, k)) {
		error("sshkey_equal_public failed");
		r = SSH_ERR_INVALID_వాదం;
		వెళ్ళు బహిర్గతం;
	}
	r = 0; /* success */
 బహిర్గతం:
	sshkey_free(కీలకం);
	తిరిగి r;
}

స్థిర పూర్ణాంకం
cred_matches_కీలకం(స్థిరరాశి fido_cred_t *cred, స్థిరరాశి నిర్మాణం sshkey *k)
{
	ఎంపిక (sshkey_type_plain(k->type)) {
	స్థితి కీలకం_ECDSA_SK:
		ఎంపిక (k->ecdsa_nid) {
		స్థితి NID_X9_62_prime256v1:
			తిరిగి cred_matches_కీలకం_ecdsa(cred, k);
			ఆపు;
		అప్రమేయ:
			fatal("Unsupported ECDSA key size");
		}
		ఆపు;
	స్థితి కీలకం_ED25519_SK:
		తిరిగి cred_matches_కీలకం_ed25519(cred, k);
	అప్రమేయ:
		error_f("key type %s not supported", sshkey_type(k));
		తిరిగి -1;
	}
}

పూర్ణాంకం
ప్రధాన(పూర్ణాంకం argc, అక్షరం **argv)
{
	LogLevel log_level = SYSLOG_LEVEL_INFO;
	పూర్ణాంకం r, ch, credtype = -1;
	నిర్మాణం sshkey *k = ఖాళీ;
	నిర్మాణం sshbuf *attestation = ఖాళీ, *challenge = ఖాళీ;
	నిర్మాణం sshbuf *attestation_cert = ఖాళీ;
	అక్షరం *fp;
	స్థిరరాశి అక్షరం *attfmt = "packed", *style = ఖాళీ;
	fido_cred_t *cred = ఖాళీ;
	పూర్ణాంకం write_attestation_cert = 0;
	బాహ్య పూర్ణాంకం optind;
	/* extern char *optarg; */

	OPENSSL_init_crypto(OPENSSL_INIT_ఎక్కించు_CRYPTO_అక్షరశ్రేణులు, ఖాళీ);

	sanitise_stdfd();
	log_init(__progname, log_level, SYSLOG_FACILITY_AUTH, 1);

	అయితే ((ch = getopt(argc, argv, "UAv")) != -1) {
		ఎంపిక (ch) {
		స్థితి 'U':
			attfmt = "fido-u2f";
			ఆపు;
		స్థితి 'A':
			write_attestation_cert = 1;
			ఆపు;
		స్థితి 'v':
			ఒకవేళ (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			లేకపోతే ఒకవేళ (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			ఆపు;
		అప్రమేయ:
			వెళ్ళు usage;
		}
	}
	log_init(__progname, log_level, SYSLOG_FACILITY_AUTH, 1);
	argv += optind;
	argc -= optind;

	ఒకవేళ (argc < 3) {
 usage:
		fprintf(stderr, "usage: %s [-vAU] "
		   "pubkey challenge attestation-blob\n", __progname);
		నిష్క్రమించు(1);
	}
	ఒకవేళ ((r = sshkey_ఎక్కించు_ప్రజా(argv[0], &k, ఖాళీ)) != 0)
		fatal_r(r, "load key %s", argv[0]);
	ఒకవేళ ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ఖాళీ)
		fatal("sshkey_fingerprint failed");
	debug2("key %s: %s %s", argv[2], sshkey_type(k), fp);
	విడుదల(fp);
	ఒకవేళ ((r = sshbuf_ఎక్కించు_file(argv[1], &challenge)) != 0)
		fatal_r(r, "load challenge %s", argv[1]);
	ఒకవేళ ((r = sshbuf_ఎక్కించు_file(argv[2], &attestation)) != 0)
		fatal_r(r, "load attestation %s", argv[2]);
	ఒకవేళ ((cred = fido_cred_new()) == ఖాళీ)
		fatal("fido_cred_new failed");

	ఎంపిక (sshkey_type_plain(k->type)) {
	స్థితి కీలకం_ECDSA_SK:
		ఎంపిక (k->ecdsa_nid) {
		స్థితి NID_X9_62_prime256v1:
			credtype = COSE_ES256;
			ఆపు;
		అప్రమేయ:
			fatal("Unsupported ECDSA key size");
		}
		ఆపు;
	స్థితి కీలకం_ED25519_SK:
		credtype = COSE_EDDSA;
		ఆపు;
	అప్రమేయ:
		fatal("unsupported key type %s", sshkey_type(k));
	}

	ఒకవేళ ((r = prepare_fido_cred(cred, credtype, attfmt, k->sk_application,
	    attestation, challenge, &attestation_cert)) != 0)
		fatal_r(r, "prepare_fido_cred %s", argv[2]);
	ఒకవేళ (fido_cred_x5c_ptr(cred) != ఖాళీ) {
		debug("basic attestation");
		ఒకవేళ ((r = fido_cred_verify(cred)) != FIDO_OK)
			fatal("basic attestation failed");
		style = "basic";
	} లేకపోతే {
		debug("self attestation");
		ఒకవేళ ((r = fido_cred_verify_self(cred)) != FIDO_OK)
			fatal("self attestation failed");
		style = "self";
	}
	ఒకవేళ (cred_matches_కీలకం(cred, k) != 0)
		fatal("cred authdata does not match key");

	fido_cred_free(&cred);

	ఒకవేళ (write_attestation_cert) {
		PEM_write(stdout, "CERTIFICATE", ఖాళీ,
		    sshbuf_ptr(attestation_cert), sshbuf_len(attestation_cert));
	}
	sshbuf_free(attestation_cert);

	logit("%s: verified %s attestation", argv[2], style);

	తిరిగి (0);
}
