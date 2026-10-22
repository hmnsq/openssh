/* $OpenBSD: ssh-keygen.c,v 1.496 2026/09/15 08:00:01 djm Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1994 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Identity and host key generation and maintenance.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/socket.h>
#అన్తర్భావ <sys/stat.h>

#నిర్వచితమైతే WITH_OPENSSL
#అన్తర్భావ "openbsd-compat/openssl-compat.h"
#అన్తర్భావ <openssl/bn.h>
#అన్తర్భావ <openssl/evp.h>
#అన్తర్భావ <openssl/pem.h>
#అయితే_ముగింపు

#అన్తర్భావ <stdint.h>
#అన్తర్భావ <errno.h>
#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <netdb.h>
#అన్తర్భావ <paths.h>
#అన్తర్భావ <pwd.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <limits.h>
#అన్తర్భావ <locale.h>
#అన్తర్భావ <time.h>

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "authfile.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "pathnames.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "match.h"
#అన్తర్భావ "hostfile.h"
#అన్తర్భావ "dns.h"
#అన్తర్భావ "ssh.h"
#అన్తర్భావ "ssh2.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "atomicio.h"
#అన్తర్భావ "krl.h"
#అన్తర్భావ "digest.h"
#అన్తర్భావ "utf8.h"
#అన్తర్భావ "authfd.h"
#అన్తర్భావ "sshsig.h"
#అన్తర్భావ "ssh-sk.h"
#అన్తర్భావ "sk-api.h" /* XXX for SSH_SK_USER_PRESENCE_REQD; remove */
#అన్తర్భావ "cipher.h"

#నిర్వచితమైతే ENABLE_PKCS11
#అన్తర్భావ "ssh-pkcs11.h"
#అయితే_ముగింపు

#నిర్వచించు DEFAULT_కీలకం_TYPE_NAME "ed25519"

/*
 * Default number of bits in the RSA and ECDSA keys.  These value can be
 * overridden on the command line.
 *
 * These values provide security equivalent to at least 128 bits of security
 * according to NIST Special Publication 800-57: Recommendation for Key
 * Management Part 1 rev 4 section 5.6.1.
 */
#నిర్వచించు DEFAULT_బిట్లు		3072
#నిర్వచించు DEFAULT_బిట్లు_ECDSA	256

#నిర్వచించు కీలకం_COMMENT_MAX		(NI_MAXHOST + 1024)

స్థిర పూర్ణాంకం quiet = 0;

/* Flag indicating that we just want to see the key fingerprint */
స్థిర పూర్ణాంకం print_fingerprint = 0;
స్థిర పూర్ణాంకం print_bubblebabble = 0;

/* Hash algorithm to use for fingerprints. */
స్థిర పూర్ణాంకం fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* The identity file name, given on the command line or entered by the user. */
స్థిర అక్షరం తటస్థం_file[PATH_MAX];
స్థిర పూర్ణాంకం have_తటస్థం = 0;

/* This is set to the passphrase if given on the command line. */
స్థిర అక్షరం *తటస్థం_passphrase = ఖాళీ;

/* This is set to the new passphrase if given on the command line. */
స్థిర అక్షరం *తటస్థం_new_passphrase = ఖాళీ;

/* Key type when certifying */
స్థిర u_int cert_కీలకం_type = SSH2_CERT_TYPE_USER;

/* "key ID" of signed key */
స్థిర అక్షరం *cert_కీలకం_id = ఖాళీ;

/* Comma-separated list of principal names for certifying keys */
స్థిర అక్షరం *cert_principals = ఖాళీ;

/* Validity period for certificates */
స్థిర uint64_t cert_valid_from = 0;
స్థిర uint64_t cert_valid_గమ్యం = ~0ULL;

/* Certificate options */
#నిర్వచించు CERTOPT_X_FWD				(1)
#నిర్వచించు CERTOPT_AGENT_FWD			(1<<1)
#నిర్వచించు CERTOPT_పోర్టు_FWD			(1<<2)
#నిర్వచించు CERTOPT_PTY				(1<<3)
#నిర్వచించు CERTOPT_USER_RC				(1<<4)
#నిర్వచించు CERTOPT_NO_REQUIRE_USER_PRESENCE	(1<<5)
#నిర్వచించు CERTOPT_REQUIRE_VERIFY			(1<<6)
#నిర్వచించు CERTOPT_DEFAULT	(CERTOPT_X_FWD|CERTOPT_AGENT_FWD| \
			 CERTOPT_పోర్టు_FWD|CERTOPT_PTY|CERTOPT_USER_RC)
స్థిర uint32_t certflags_flags = CERTOPT_DEFAULT;
స్థిర అక్షరం *certflags_command = ఖాళీ;
స్థిర అక్షరం *certflags_src_addr = ఖాళీ;

/* Arbitrary extensions specified by user */
నిర్మాణం cert_ext {
	అక్షరం *కీలకం;
	అక్షరం *val;
	పూర్ణాంకం crit;
};
స్థిర నిర్మాణం cert_ext *cert_ext;
స్థిర కొలత_t ncert_ext;

/* Conversion to/from various formats */
గణన {
	FMT_RFC4716,
	FMT_PKCS8,
	FMT_PEM,
	FMT_HEXDUMP
} convert_format = FMT_RFC4716;

స్థిర అక్షరం *కీలకం_type_name = ఖాళీ;

/* Load key from this PKCS#11 provider */
స్థిర అక్షరం *pkcs11provider = ఖాళీ;

/* FIDO/U2F provider to use */
స్థిర అక్షరం *sk_provider = ఖాళీ;

/* Format for writing private keys */
స్థిర పూర్ణాంకం వ్యక్తిగత_కీలకం_format = SSHKEY_వ్యక్తిగత_OPENSSH;

/* Cipher for new-format private keys */
స్థిర అక్షరం *openssh_format_cipher = ఖాళీ;

/* Number of KDF rounds to derive new format keys. */
స్థిర పూర్ణాంకం విడతలు = 0;

/* argv0 */
బాహ్య అక్షరం *__progname;

స్థిర అక్షరం hostname[NI_MAXHOST];

#నిర్వచితమైతే WITH_OPENSSL
/* moduli.c */
పూర్ణాంకం gen_candidates(FILE *, uint32_t, BIGNUM *);
పూర్ణాంకం ప్రధానసంఖ్య_test(FILE *, FILE *, uint32_t, uint32_t, అక్షరం *, గుర్తులేని దీర్ఘ,
    గుర్తులేని దీర్ఘ);
#అయితే_ముగింపు

స్థిర శూన్య
type_బిట్లు_valid(పూర్ణాంకం type, స్థిరరాశి అక్షరం *name, uint32_t *bitsp)
{
	ఒకవేళ (type == కీలకం_UNSPEC)
		fatal("unknown key type %s", కీలకం_type_name);
	ఒకవేళ (*bitsp == 0) {
#నిర్వచితమైతే WITH_OPENSSL
		పూర్ణాంకం nid;

		ఎంపిక(type) {
		స్థితి కీలకం_ECDSA:
			ఒకవేళ (name != ఖాళీ &&
			    (nid = sshkey_ecdsa_nid_from_name(name)) > 0)
				*bitsp = sshkey_వక్రం_nid_గమ్యం_బిట్లు(nid);
			ఒకవేళ (*bitsp == 0)
				*bitsp = DEFAULT_బిట్లు_ECDSA;
			ఆపు;
		స్థితి కీలకం_RSA:
			*bitsp = DEFAULT_బిట్లు;
			ఆపు;
		}
#అయితే_ముగింపు
	}
#నిర్వచితమైతే WITH_OPENSSL
	ఎంపిక (type) {
	స్థితి కీలకం_RSA:
		ఒకవేళ (*bitsp < SSH_RSA_MINIMUM_MODULUS_కొలత)
			fatal("Invalid RSA key length: minimum is %d bits",
			    SSH_RSA_MINIMUM_MODULUS_కొలత);
		లేకపోతే ఒకవేళ (*bitsp > OPENSSL_RSA_MAX_MODULUS_బిట్లు)
			fatal("Invalid RSA key length: maximum is %d bits",
			    OPENSSL_RSA_MAX_MODULUS_బిట్లు);
		ఆపు;
	స్థితి కీలకం_ECDSA:
		ఒకవేళ (sshkey_ecdsa_బిట్లు_గమ్యం_nid(*bitsp) == -1)
			fatal("Invalid ECDSA key length: valid lengths are "
			    "256, 384 or 521 bits");
	}
#అయితే_ముగింపు
}

/*
 * Checks whether a file exists and, if so, asks the user whether they wish
 * to overwrite it.
 * Returns nonzero if the file does not already exist or if the user agrees to
 * overwrite, or zero otherwise.
 */
స్థిర పూర్ణాంకం
confirm_overwrite(స్థిరరాశి అక్షరం *filename)
{
	అక్షరం yesno[3];
	నిర్మాణం stat st;

	ఒకవేళ (stat(filename, &st) != 0)
		తిరిగి 1;
	రాయి("%s already exists.\n", filename);
	రాయి("Overwrite (y/n)? ");
	fflush(stdout);
	ఒకవేళ (fgets(yesno, పరిమాణం(yesno), stdin) == ఖాళీ)
		తిరిగి 0;
	ఒకవేళ (yesno[0] != 'y' && yesno[0] != 'Y')
		తిరిగి 0;
	తిరిగి 1;
}

స్థిర శూన్య
ask_filename(నిర్మాణం passwd *pw, స్థిరరాశి అక్షరం *prompt)
{
	అక్షరం buf[1024];
	అక్షరం *name = ఖాళీ;

	ఒకవేళ (కీలకం_type_name == ఖాళీ)
		name = మార్గం_SSH_CLIENT_ID_ED25519;
	లేకపోతే {
		ఎంపిక (sshkey_type_from_shortname(కీలకం_type_name)) {
		స్థితి కీలకం_ECDSA_CERT:
		స్థితి కీలకం_ECDSA:
			name = మార్గం_SSH_CLIENT_ID_ECDSA;
			ఆపు;
		స్థితి కీలకం_ECDSA_SK_CERT:
		స్థితి కీలకం_ECDSA_SK:
			name = మార్గం_SSH_CLIENT_ID_ECDSA_SK;
			ఆపు;
		స్థితి కీలకం_RSA_CERT:
		స్థితి కీలకం_RSA:
			name = మార్గం_SSH_CLIENT_ID_RSA;
			ఆపు;
		స్థితి కీలకం_ED25519:
		స్థితి కీలకం_ED25519_CERT:
			name = మార్గం_SSH_CLIENT_ID_ED25519;
			ఆపు;
		స్థితి కీలకం_ED25519_SK:
		స్థితి కీలకం_ED25519_SK_CERT:
			name = మార్గం_SSH_CLIENT_ID_ED25519_SK;
			ఆపు;
		స్థితి కీలకం_MLDSA44_ED25519:
		స్థితి కీలకం_MLDSA44_ED25519_CERT:
			name = మార్గం_SSH_CLIENT_ID_MLDSA44_ED25519;
			ఆపు;
		అప్రమేయ:
			fatal("bad key type");
		}
	}
	snprintf(తటస్థం_file, పరిమాణం(తటస్థం_file),
	    "%s/%s", pw->pw_dir, name);
	రాయి("%s (%s): ", prompt, తటస్థం_file);
	fflush(stdout);
	ఒకవేళ (fgets(buf, పరిమాణం(buf), stdin) == ఖాళీ)
		నిష్క్రమించు(1);
	buf[strcspn(buf, "\n")] = '\0';
	ఒకవేళ (strcmp(buf, "") != 0)
		strlcpy(తటస్థం_file, buf, పరిమాణం(తటస్థం_file));
	have_తటస్థం = 1;
}

స్థిర నిర్మాణం sshkey *
ఎక్కించు_తటస్థం(స్థిరరాశి అక్షరం *filename, అక్షరం **commentp)
{
	అక్షరం *prompt, *pass;
	నిర్మాణం sshkey *prv;
	పూర్ణాంకం r;

	ఒకవేళ (commentp != ఖాళీ)
		*commentp = ఖాళీ;
	ఒకవేళ ((r = sshkey_ఎక్కించు_వ్యక్తిగత(filename, "", &prv, commentp)) == 0)
		తిరిగి prv;
	ఒకవేళ (r != SSH_ERR_కీలకం_WRONG_PASSPHRASE)
		fatal_r(r, "Load key \"%s\"", filename);
	ఒకవేళ (తటస్థం_passphrase)
		pass = xstrdup(తటస్థం_passphrase);
	లేకపోతే {
		xasprintf(&prompt, "Enter passphrase for \"%s\": ", filename);
		pass = read_passphrase(prompt, RP_ALLOW_STDIN);
		విడుదల(prompt);
	}
	r = sshkey_ఎక్కించు_వ్యక్తిగత(filename, pass, &prv, commentp);
	freezero(pass, అక్షరశ్రేణి_పొడవు(pass));
	ఒకవేళ (r != 0)
		fatal_r(r, "Load key \"%s\"", filename);
	తిరిగి prv;
}

#నిర్వచించు SSH_COM_ప్రజా_BEGIN		"---- BEGIN SSH2 PUBLIC KEY ----"
#నిర్వచించు SSH_COM_ప్రజా_చివర		"---- END SSH2 PUBLIC KEY ----"
#నిర్వచించు SSH_COM_వ్యక్తిగత_BEGIN		"---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----"
#నిర్వచించు	SSH_COM_వ్యక్తిగత_కీలకం_MAGIC	0x3f6ff9eb

#నిర్వచితమైతే WITH_OPENSSL
స్థిర శూన్య
do_convert_గమ్యం_ssh2(నిర్మాణం passwd *pw, నిర్మాణం sshkey *k)
{
	నిర్మాణం sshbuf *b;
	అక్షరం comment[61], *b64;
	పూర్ణాంకం r;

	ఒకవేళ ((b = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = sshkey_putb(k, b)) != 0)
		fatal_fr(r, "put key");
	ఒకవేళ ((b64 = sshbuf_dtob64_string(b, 1)) == ఖాళీ)
		fatal_f("sshbuf_dtob64_string failed");

	/* Comment + surrounds must fit into 72 chars (RFC 4716 sec 3.3) */
	snprintf(comment, పరిమాణం(comment),
	    "%u-bit %s, converted by %s@%s from OpenSSH",
	    sshkey_కొలత(k), sshkey_type(k),
	    pw->pw_name, hostname);

	sshkey_free(k);
	sshbuf_free(b);

	fprintf(stdout, "%s\n", SSH_COM_ప్రజా_BEGIN);
	fprintf(stdout, "Comment: \"%s\"\n%s", comment, b64);
	fprintf(stdout, "%s\n", SSH_COM_ప్రజా_చివర);
	విడుదల(b64);
}

స్థిర శూన్య
do_convert_గమ్యం_pkcs8(నిర్మాణం sshkey *k)
{
	ఎంపిక (sshkey_type_plain(k->type)) {
	స్థితి కీలకం_RSA:
		ఒకవేళ (!PEM_write_RSA_PUBKEY(stdout,
		    EVP_PKEY_get0_RSA(k->pkey)))
			fatal("PEM_write_RSA_PUBKEY failed");
		ఆపు;
	స్థితి కీలకం_ECDSA:
		ఒకవేళ (!PEM_write_EC_PUBKEY(stdout,
		    EVP_PKEY_get0_EC_కీలకం(k->pkey)))
			fatal("PEM_write_EC_PUBKEY failed");
		ఆపు;
	అప్రమేయ:
		fatal_f("unsupported key type %s", sshkey_type(k));
	}
}

స్థిర శూన్య
do_convert_గమ్యం_pem(నిర్మాణం sshkey *k)
{
	ఎంపిక (sshkey_type_plain(k->type)) {
	స్థితి కీలకం_RSA:
		ఒకవేళ (!PEM_write_RSAPublic_కీలకం(stdout,
		    EVP_PKEY_get0_RSA(k->pkey)))
			fatal("PEM_write_RSAPublicKey failed");
		ఆపు;
	స్థితి కీలకం_ECDSA:
		ఒకవేళ (!PEM_write_EC_PUBKEY(stdout,
		    EVP_PKEY_get0_EC_కీలకం(k->pkey)))
			fatal("PEM_write_EC_PUBKEY failed");
		ఆపు;
	అప్రమేయ:
		fatal_f("unsupported key type %s", sshkey_type(k));
	}
}

స్థిర శూన్య
do_convert_గమ్యం_hexdump(నిర్మాణం sshkey *k)
{
	నిర్మాణం sshbuf *b;
	పూర్ణాంకం r;

	ఒకవేళ ((b = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	/* pubkey */
	ఒకవేళ ((r = sshkey_putb(k, b)) != 0)
		fatal_fr(r, "serialise private");
	రాయి("Public %s key:\n", sshkey_type(k));
	sshbuf_dump(b, stdout);
	sshbuf_reset(b);
	ఒకవేళ ((r = sshkey_వ్యక్తిగత_serialize(k, b)) != 0) {
		debug_fr(r, "serialise private");
		వెళ్ళు బహిర్గతం;
	}
	రాయి("\nPrivate %s key:\n", sshkey_type(k));
	sshbuf_dump(b, stdout);
 బహిర్గతం:
	sshbuf_free(b);
}

స్థిర శూన్య
do_convert_గమ్యం(నిర్మాణం passwd *pw)
{
	నిర్మాణం sshkey *k = ఖాళీ;
	నిర్మాణం stat st;
	పూర్ణాంకం r;

	ఒకవేళ (!have_తటస్థం)
		ask_filename(pw, "Enter file in which the key is");
	ఒకవేళ (stat(తటస్థం_file, &st) == -1)
		fatal("%s: %s: %s", __progname, తటస్థం_file, strerror(errno));

	/* If we're trying to hexdump, then prefer the private key */
	ఒకవేళ (convert_format == FMT_HEXDUMP) {
		ఒకవేళ ((r = sshkey_ఎక్కించు_వ్యక్తిగత(తటస్థం_file,
		    ఖాళీ, &k, ఖాళీ)) != 0 &&
		    r == SSH_ERR_కీలకం_WRONG_PASSPHRASE)
			k = ఎక్కించు_తటస్థం(తటస్థం_file, ఖాళీ);
	}
	ఒకవేళ (k == ఖాళీ && (r = sshkey_ఎక్కించు_ప్రజా(తటస్థం_file, &k, ఖాళీ)) != 0)
		k = ఎక్కించు_తటస్థం(తటస్థం_file, ఖాళీ);

	ఎంపిక (convert_format) {
	స్థితి FMT_RFC4716:
		do_convert_గమ్యం_ssh2(pw, k);
		ఆపు;
	స్థితి FMT_PKCS8:
		do_convert_గమ్యం_pkcs8(k);
		ఆపు;
	స్థితి FMT_PEM:
		do_convert_గమ్యం_pem(k);
		ఆపు;
	స్థితి FMT_HEXDUMP:
		do_convert_గమ్యం_hexdump(k);
		ఆపు;
	అప్రమేయ:
		fatal_f("unknown key format %d", convert_format);
	}
}

/*
 * This is almost exactly the bignum1 encoding, but with 32 bit for length
 * instead of 16.
 */
స్థిర శూన్య
బఫరు_get_bignum_బిట్లు(నిర్మాణం sshbuf *b, BIGNUM *విలువ)
{
	u_int బైట్లు, bignum_బిట్లు;
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshbuf_get_u32(b, &bignum_బిట్లు)) != 0)
		fatal_fr(r, "parse");
	బైట్లు = (bignum_బిట్లు + 7) / 8;
	ఒకవేళ (sshbuf_len(b) < బైట్లు)
		fatal_f("input buffer too small: need %d have %zu",
		    బైట్లు, sshbuf_len(b));
	ఒకవేళ (BN_bin2bn(sshbuf_ptr(b), బైట్లు, విలువ) == ఖాళీ)
		fatal_f("BN_bin2bn failed");
	ఒకవేళ ((r = sshbuf_consume(b, బైట్లు)) != 0)
		fatal_fr(r, "consume");
}

స్థిర నిర్మాణం sshkey *
do_convert_వ్యక్తిగత_ssh2(నిర్మాణం sshbuf *b)
{
	నిర్మాణం sshkey *కీలకం = ఖాళీ;
	అక్షరం *type, *cipher;
	స్థిరరాశి అక్షరం *alg = ఖాళీ;
	u_char e1, e2, e3, *sig = ఖాళీ, దత్తాంశం[] = "abcde12345";
	పూర్ణాంకం r, rlen, ktype;
	u_int magic, i1, i2, i3, i4;
	కొలత_t slen;
	u_long e;
	BIGNUM *rsa_n = ఖాళీ, *rsa_e = ఖాళీ, *rsa_d = ఖాళీ;
	BIGNUM *rsa_p = ఖాళీ, *rsa_q = ఖాళీ, *rsa_iqmp = ఖాళీ;
	BIGNUM *rsa_dmp1 = ఖాళీ, *rsa_dmq1 = ఖాళీ;
	RSA *rsa = ఖాళీ;

	ఒకవేళ ((r = sshbuf_get_u32(b, &magic)) != 0)
		fatal_fr(r, "parse magic");

	ఒకవేళ (magic != SSH_COM_వ్యక్తిగత_కీలకం_MAGIC) {
		error("bad magic 0x%x != 0x%x", magic,
		    SSH_COM_వ్యక్తిగత_కీలకం_MAGIC);
		తిరిగి ఖాళీ;
	}
	ఒకవేళ ((r = sshbuf_get_u32(b, &i1)) != 0 ||
	    (r = sshbuf_get_cstring(b, &type, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_cstring(b, &cipher, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_u32(b, &i2)) != 0 ||
	    (r = sshbuf_get_u32(b, &i3)) != 0 ||
	    (r = sshbuf_get_u32(b, &i4)) != 0)
		fatal_fr(r, "parse");
	debug("ignore (%d %d %d %d)", i1, i2, i3, i4);
	ఒకవేళ (strcmp(cipher, "none") != 0) {
		error("unsupported cipher %s", cipher);
		విడుదల(cipher);
		విడుదల(type);
		తిరిగి ఖాళీ;
	}
	విడుదల(cipher);

	ఒకవేళ (అక్షరశ్రేణి_శోధన(type, "rsa")) {
		ktype = కీలకం_RSA;
	} లేకపోతే {
		విడుదల(type);
		తిరిగి ఖాళీ;
	}
	ఒకవేళ ((కీలకం = sshkey_new(ktype)) == ఖాళీ)
		fatal("sshkey_new failed");
	విడుదల(type);

	ఎంపిక (కీలకం->type) {
	స్థితి కీలకం_RSA:
		ఒకవేళ ((r = sshbuf_get_u8(b, &e1)) != 0 ||
		    (e1 < 30 && (r = sshbuf_get_u8(b, &e2)) != 0) ||
		    (e1 < 30 && (r = sshbuf_get_u8(b, &e3)) != 0))
			fatal_fr(r, "parse RSA");
		e = e1;
		debug("e %lx", e);
		ఒకవేళ (e < 30) {
			e <<= 8;
			e += e2;
			debug("e %lx", e);
			e <<= 8;
			e += e3;
			debug("e %lx", e);
		}
		ఒకవేళ ((rsa_e = BN_new()) == ఖాళీ)
			fatal_f("BN_new");
		ఒకవేళ (!BN_సమితి_మాట(rsa_e, e)) {
			BN_clear_free(rsa_e);
			sshkey_free(కీలకం);
			తిరిగి ఖాళీ;
		}
		ఒకవేళ ((rsa_n = BN_new()) == ఖాళీ ||
		    (rsa_d = BN_new()) == ఖాళీ ||
		    (rsa_p = BN_new()) == ఖాళీ ||
		    (rsa_q = BN_new()) == ఖాళీ ||
		    (rsa_iqmp = BN_new()) == ఖాళీ)
			fatal_f("BN_new");
		బఫరు_get_bignum_బిట్లు(b, rsa_d);
		బఫరు_get_bignum_బిట్లు(b, rsa_n);
		బఫరు_get_bignum_బిట్లు(b, rsa_iqmp);
		బఫరు_get_bignum_బిట్లు(b, rsa_q);
		బఫరు_get_bignum_బిట్లు(b, rsa_p);
		ఒకవేళ ((r = ssh_rsa_complete_crt_parameters(rsa_d, rsa_p, rsa_q,
		    rsa_iqmp, &rsa_dmp1, &rsa_dmq1)) != 0)
			fatal_fr(r, "generate RSA CRT parameters");
		EVP_PKEY_free(కీలకం->pkey);
		ఒకవేళ ((కీలకం->pkey = EVP_PKEY_new()) == ఖాళీ)
			fatal_f("EVP_PKEY_new failed");
		ఒకవేళ ((rsa = RSA_new()) == ఖాళీ)
			fatal_f("RSA_new failed");
		ఒకవేళ (!RSA_set0_కీలకం(rsa, rsa_n, rsa_e, rsa_d))
			fatal_f("RSA_set0_key failed");
		rsa_n = rsa_e = rsa_d = ఖాళీ; /* transferred */
		ఒకవేళ (!RSA_set0_factors(rsa, rsa_p, rsa_q))
			fatal_f("RSA_set0_factors failed");
		rsa_p = rsa_q = ఖాళీ; /* transferred */
		ఒకవేళ (RSA_set0_crt_params(rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp) != 1)
			fatal_f("RSA_set0_crt_params failed");
		rsa_dmp1 = rsa_dmq1 = rsa_iqmp = ఖాళీ;
		ఒకవేళ (EVP_PKEY_set1_RSA(కీలకం->pkey, rsa) != 1)
			fatal_f("EVP_PKEY_set1_RSA failed");
		RSA_free(rsa);
		alg = "rsa-sha2-256";
		ఆపు;
	}
	rlen = sshbuf_len(b);
	ఒకవేళ (rlen != 0)
		error_f("remaining bytes in key blob %d", rlen);

	/* try the key */
	ఒకవేళ ((r = sshkey_sign(కీలకం, &sig, &slen, దత్తాంశం, పరిమాణం(దత్తాంశం),
	    alg, ఖాళీ, ఖాళీ, 0)) != 0)
		error_fr(r, "signing with converted key failed");
	లేకపోతే ఒకవేళ ((r = sshkey_verify(కీలకం, sig, slen, దత్తాంశం, పరిమాణం(దత్తాంశం),
	    alg, 0, ఖాళీ)) != 0)
		error_fr(r, "verification with converted key failed");
	ఒకవేళ (r != 0) {
		sshkey_free(కీలకం);
		విడుదల(sig);
		తిరిగి ఖాళీ;
	}
	విడుదల(sig);
	తిరిగి కీలకం;
}

స్థిర పూర్ణాంకం
get_పంక్తి(FILE *fp, అక్షరం *పంక్తి, కొలత_t len)
{
	పూర్ణాంకం c;
	కొలత_t pos = 0;

	పంక్తి[0] = '\0';
	అయితే ((c = fgetc(fp)) != EOF) {
		ఒకవేళ (pos >= len - 1)
			fatal("input line too long.");
		ఎంపిక (c) {
		స్థితి '\r':
			c = fgetc(fp);
			ఒకవేళ (c != EOF && c != '\n' && ungetc(c, fp) == EOF)
				fatal("unget: %s", strerror(errno));
			తిరిగి pos;
		స్థితి '\n':
			తిరిగి pos;
		}
		పంక్తి[pos++] = c;
		పంక్తి[pos] = '\0';
	}
	/* We reached EOF */
	తిరిగి -1;
}

స్థిర శూన్య
do_convert_from_ssh2(నిర్మాణం passwd *pw, నిర్మాణం sshkey **k, పూర్ణాంకం *అంతరంగ)
{
	పూర్ణాంకం r, blen, escaped = 0;
	u_int len;
	అక్షరం పంక్తి[1024];
	నిర్మాణం sshbuf *buf;
	అక్షరం encoded[8096];
	FILE *fp;

	ఒకవేళ ((buf = sshbuf_new()) == ఖాళీ)
		fatal("sshbuf_new failed");
	ఒకవేళ ((fp = fopen(తటస్థం_file, "r")) == ఖాళీ)
		fatal("%s: %s: %s", __progname, తటస్థం_file, strerror(errno));
	encoded[0] = '\0';
	అయితే ((blen = get_పంక్తి(fp, పంక్తి, పరిమాణం(పంక్తి))) != -1) {
		ఒకవేళ (blen > 0 && పంక్తి[blen - 1] == '\\')
			escaped++;
		ఒకవేళ (అక్షరశ్రేణి_పోలిక(పంక్తి, "----", 4) == 0 ||
		    అక్షరశ్రేణి_శోధన(పంక్తి, ": ") != ఖాళీ) {
			ఒకవేళ (అక్షరశ్రేణి_శోధన(పంక్తి, SSH_COM_వ్యక్తిగత_BEGIN) != ఖాళీ)
				*అంతరంగ = 1;
			ఒకవేళ (అక్షరశ్రేణి_శోధన(పంక్తి, " END ") != ఖాళీ) {
				ఆపు;
			}
			/* fprintf(stderr, "ignore: %s", line); */
			కొనసాగు;
		}
		ఒకవేళ (escaped) {
			escaped--;
			/* fprintf(stderr, "escaped: %s", line); */
			కొనసాగు;
		}
		strlcat(encoded, పంక్తి, పరిమాణం(encoded));
	}
	len = అక్షరశ్రేణి_పొడవు(encoded);
	ఒకవేళ (((len % 4) == 3) &&
	    (encoded[len-1] == '=') &&
	    (encoded[len-2] == '=') &&
	    (encoded[len-3] == '='))
		encoded[len-3] = '\0';
	ఒకవేళ ((r = sshbuf_b64tod(buf, encoded)) != 0)
		fatal_fr(r, "base64 decode");
	ఒకవేళ (*అంతరంగ) {
		ఒకవేళ ((*k = do_convert_వ్యక్తిగత_ssh2(buf)) == ఖాళీ)
			fatal_f("private key conversion failed");
	} లేకపోతే ఒకవేళ ((r = sshkey_fromb(buf, k)) != 0)
		fatal_fr(r, "parse key");
	sshbuf_free(buf);
	fclose(fp);
}

స్థిర శూన్య
do_convert_from_pkcs8(నిర్మాణం sshkey **k, పూర్ణాంకం *అంతరంగ)
{
	EVP_PKEY *pubkey;
	FILE *fp;

	ఒకవేళ ((fp = fopen(తటస్థం_file, "r")) == ఖాళీ)
		fatal("%s: %s: %s", __progname, తటస్థం_file, strerror(errno));
	ఒకవేళ ((pubkey = PEM_read_PUBKEY(fp, ఖాళీ, ఖాళీ, ఖాళీ)) == ఖాళీ) {
		fatal_f("%s is not a recognised public key format",
		    తటస్థం_file);
	}
	fclose(fp);
	ఎంపిక (EVP_PKEY_పునాది_id(pubkey)) {
	స్థితి EVP_PKEY_RSA:
		ఒకవేళ ((*k = sshkey_new(కీలకం_UNSPEC)) == ఖాళీ)
			fatal("sshkey_new failed");
		(*k)->type = కీలకం_RSA;
		(*k)->pkey = pubkey;
		pubkey = ఖాళీ;
		ఆపు;
	స్థితి EVP_PKEY_EC:
		ఒకవేళ ((*k = sshkey_new(కీలకం_UNSPEC)) == ఖాళీ)
			fatal("sshkey_new failed");
		ఒకవేళ (((*k)->ecdsa_nid = sshkey_ecdsa_fixup_సమూహం(pubkey)) == -1)
			fatal("sshkey_ecdsa_fixup_group failed");
		(*k)->type = కీలకం_ECDSA;
		(*k)->pkey = pubkey;
		pubkey = ఖాళీ;
		ఆపు;
	అప్రమేయ:
		fatal_f("unsupported pubkey type %d",
		    EVP_PKEY_పునాది_id(pubkey));
	}
	EVP_PKEY_free(pubkey);
}

స్థిర శూన్య
do_convert_from_pem(నిర్మాణం sshkey **k, పూర్ణాంకం *అంతరంగ)
{
	FILE *fp;
	RSA *rsa;

	ఒకవేళ ((fp = fopen(తటస్థం_file, "r")) == ఖాళీ)
		fatal("%s: %s: %s", __progname, తటస్థం_file, strerror(errno));
	ఒకవేళ ((rsa = PEM_read_RSAPublic_కీలకం(fp, ఖాళీ, ఖాళీ, ఖాళీ)) != ఖాళీ) {
		ఒకవేళ ((*k = sshkey_new(కీలకం_UNSPEC)) == ఖాళీ)
			fatal("sshkey_new failed");
		ఒకవేళ (((*k)->pkey = EVP_PKEY_new()) == ఖాళీ)
			fatal("EVP_PKEY_new failed");
		(*k)->type = కీలకం_RSA;
		ఒకవేళ (EVP_PKEY_set1_RSA((*k)->pkey, rsa) != 1)
			fatal("EVP_PKEY_set1_RSA failed");
		RSA_free(rsa);
		fclose(fp);
		తిరిగి;
	}
	fatal_f("unrecognised raw private key format");
}

స్థిర శూన్య
do_convert_from(నిర్మాణం passwd *pw)
{
	నిర్మాణం sshkey *k = ఖాళీ;
	పూర్ణాంకం r, అంతరంగ = 0, ok = 0;
	నిర్మాణం stat st;

	ఒకవేళ (!have_తటస్థం)
		ask_filename(pw, "Enter file in which the key is");
	ఒకవేళ (stat(తటస్థం_file, &st) == -1)
		fatal("%s: %s: %s", __progname, తటస్థం_file, strerror(errno));

	ఎంపిక (convert_format) {
	స్థితి FMT_RFC4716:
		do_convert_from_ssh2(pw, &k, &అంతరంగ);
		ఆపు;
	స్థితి FMT_PKCS8:
		do_convert_from_pkcs8(&k, &అంతరంగ);
		ఆపు;
	స్థితి FMT_PEM:
		do_convert_from_pem(&k, &అంతరంగ);
		ఆపు;
	అప్రమేయ:
		fatal_f("unknown key format %d", convert_format);
	}

	ఒకవేళ (!అంతరంగ) {
		ఒకవేళ ((r = sshkey_write(k, stdout)) == 0)
			ok = 1;
		ఒకవేళ (ok)
			fprintf(stdout, "\n");
	} లేకపోతే {
		ఎంపిక (k->type) {
		స్థితి కీలకం_ECDSA:
			ok = PEM_write_ECPrivate_కీలకం(stdout,
			    EVP_PKEY_get0_EC_కీలకం(k->pkey), ఖాళీ, ఖాళీ, 0,
			    ఖాళీ, ఖాళీ);
			ఆపు;
		స్థితి కీలకం_RSA:
			ok = PEM_write_RSAPrivate_కీలకం(stdout,
			    EVP_PKEY_get0_RSA(k->pkey), ఖాళీ, ఖాళీ, 0,
			    ఖాళీ, ఖాళీ);
			ఆపు;
		అప్రమేయ:
			fatal_f("unsupported key type %s", sshkey_type(k));
		}
	}

	ఒకవేళ (!ok)
		fatal("key write failed");
	sshkey_free(k);
}
#అయితే_ముగింపు

స్థిర శూన్య
do_print_ప్రజా(నిర్మాణం passwd *pw)
{
	నిర్మాణం sshkey *prv;
	నిర్మాణం stat st;
	పూర్ణాంకం r;
	అక్షరం *comment = ఖాళీ;

	ఒకవేళ (!have_తటస్థం)
		ask_filename(pw, "Enter file in which the key is");
	ఒకవేళ (stat(తటస్థం_file, &st) == -1)
		fatal("%s: %s", తటస్థం_file, strerror(errno));
	prv = ఎక్కించు_తటస్థం(తటస్థం_file, &comment);
	ఒకవేళ ((r = sshkey_write(prv, stdout)) != 0)
		fatal_fr(r, "write key");
	ఒకవేళ (comment != ఖాళీ && *comment != '\0')
		fprintf(stdout, " %s", comment);
	fprintf(stdout, "\n");
	ఒకవేళ (sshkey_is_sk(prv)) {
		debug("sk_application: \"%s\", sk_flags 0x%02x",
			prv->sk_application, prv->sk_flags);
	}
	sshkey_free(prv);
	విడుదల(comment);
	నిష్క్రమించు(0);
}

స్థిర శూన్య
do_download(నిర్మాణం passwd *pw)
{
#నిర్వచితమైతే ENABLE_PKCS11
	నిర్మాణం sshkey **కీలకాలు = ఖాళీ;
	పూర్ణాంకం i, nkeys;
	గణన sshkey_fp_rep rep;
	పూర్ణాంకం fptype;
	అక్షరం *fp, *ra, **comments = ఖాళీ;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;

	pkcs11_init(1);
	nkeys = pkcs11_కూడు_provider(pkcs11provider, ఖాళీ, &కీలకాలు, &comments);
	ఒకవేళ (nkeys <= 0)
		fatal("cannot read public key from pkcs11");
	కొరకు (i = 0; i < nkeys; i++) {
		ఒకవేళ (print_fingerprint) {
			fp = sshkey_fingerprint(కీలకాలు[i], fptype, rep);
			ra = sshkey_fingerprint(కీలకాలు[i], fingerprint_hash,
			    SSH_FP_RANDOMART);
			ఒకవేళ (fp == ఖాళీ || ra == ఖాళీ)
				fatal_f("sshkey_fingerprint fail");
			రాయి("%u %s %s (PKCS11 key)\n", sshkey_కొలత(కీలకాలు[i]),
			    fp, sshkey_type(కీలకాలు[i]));
			ఒకవేళ (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
				రాయి("%s\n", ra);
			విడుదల(ra);
			విడుదల(fp);
		} లేకపోతే {
			(శూన్య) sshkey_write(కీలకాలు[i], stdout); /* XXX check */
			fprintf(stdout, "%s%s\n",
			    *(comments[i]) == '\0' ? "" : " ", comments[i]);
		}
		విడుదల(comments[i]);
		sshkey_free(కీలకాలు[i]);
	}
	విడుదల(comments);
	విడుదల(కీలకాలు);
	pkcs11_terminate();
	నిష్క్రమించు(0);
#లేకపోతే
	fatal("no pkcs11 support");
#అయితే_ముగింపు /* ENABLE_PKCS11 */
}

స్థిర నిర్మాణం sshkey *
try_read_కీలకం(అక్షరం **cpp)
{
	నిర్మాణం sshkey *ret;
	పూర్ణాంకం r;

	ఒకవేళ ((ret = sshkey_new(కీలకం_UNSPEC)) == ఖాళీ)
		fatal("sshkey_new failed");
	ఒకవేళ ((r = sshkey_read(ret, cpp)) == 0)
		తిరిగి ret;
	/* Not a key */
	sshkey_free(ret);
	తిరిగి ఖాళీ;
}

స్థిర శూన్య
fingerprint_one_కీలకం(స్థిరరాశి నిర్మాణం sshkey *బహిరంగ, స్థిరరాశి అక్షరం *comment)
{
	అక్షరం *fp = ఖాళీ, *ra = ఖాళీ;
	గణన sshkey_fp_rep rep;
	పూర్ణాంకం fptype;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;
	fp = sshkey_fingerprint(బహిరంగ, fptype, rep);
	ra = sshkey_fingerprint(బహిరంగ, fingerprint_hash, SSH_FP_RANDOMART);
	ఒకవేళ (fp == ఖాళీ || ra == ఖాళీ)
		fatal_f("sshkey_fingerprint failed");
	mprintf("%u %s %s (%s)\n", sshkey_కొలత(బహిరంగ), fp,
	    comment ? comment : "no comment", sshkey_type(బహిరంగ));
	ఒకవేళ (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
		రాయి("%s\n", ra);
	విడుదల(ra);
	విడుదల(fp);
}

స్థిర శూన్య
fingerprint_వ్యక్తిగత(స్థిరరాశి అక్షరం *మార్గం)
{
	నిర్మాణం stat st;
	అక్షరం *comment = ఖాళీ;
	నిర్మాణం sshkey *privkey = ఖాళీ, *pubkey = ఖాళీ;
	పూర్ణాంకం r;

	ఒకవేళ (stat(తటస్థం_file, &st) == -1)
		fatal("%s: %s", మార్గం, strerror(errno));
	ఒకవేళ ((r = sshkey_ఎక్కించు_ప్రజా(మార్గం, &pubkey, &comment)) != 0)
		debug_r(r, "load public \"%s\"", మార్గం);
	ఒకవేళ (pubkey == ఖాళీ || comment == ఖాళీ || *comment == '\0') {
		విడుదల(comment);
		ఒకవేళ ((r = sshkey_ఎక్కించు_వ్యక్తిగత(మార్గం, ఖాళీ,
		    &privkey, &comment)) != 0)
			debug_r(r, "load private \"%s\"", మార్గం);
	}
	ఒకవేళ (pubkey == ఖాళీ && privkey == ఖాళీ)
		fatal("%s is not a key file.", మార్గం);

	fingerprint_one_కీలకం(pubkey == ఖాళీ ? privkey : pubkey, comment);
	sshkey_free(pubkey);
	sshkey_free(privkey);
	విడుదల(comment);
}

స్థిర శూన్య
do_fingerprint(నిర్మాణం passwd *pw)
{
	FILE *f;
	నిర్మాణం sshkey *బహిరంగ = ఖాళీ;
	అక్షరం *comment = ఖాళీ, *cp, *ep, *పంక్తి = ఖాళీ;
	కొలత_t linesize = 0;
	పూర్ణాంకం i, invalid = 1;
	స్థిరరాశి అక్షరం *మార్గం;
	u_long lnum = 0;

	ఒకవేళ (!have_తటస్థం)
		ask_filename(pw, "Enter file in which the key is");
	మార్గం = తటస్థం_file;

	ఒకవేళ (strcmp(తటస్థం_file, "-") == 0) {
		f = stdin;
		మార్గం = "(stdin)";
	} లేకపోతే ఒకవేళ ((f = fopen(మార్గం, "r")) == ఖాళీ)
		fatal("%s: %s: %s", __progname, మార్గం, strerror(errno));

	అయితే (getline(&పంక్తి, &linesize, f) != -1) {
		lnum++;
		cp = పంక్తి;
		cp[strcspn(cp, "\r\n")] = '\0';
		/* Trim leading space and comments */
		cp = పంక్తి + strspn(పంక్తి, " \t");
		ఒకవేళ (*cp == '#' || *cp == '\0')
			కొనసాగు;

		/*
		 * Input may be plain keys, private keys, authorized_keys
		 * or known_hosts.
		 */

		/*
		 * Try private keys first. Assume a key is private if
		 * "SSH PRIVATE KEY" appears on the first line and we're
		 * not reading from stdin (XXX support private keys on stdin).
		 */
		ఒకవేళ (lnum == 1 && strcmp(తటస్థం_file, "-") != 0 &&
		    అక్షరశ్రేణి_శోధన(cp, "PRIVATE KEY") != ఖాళీ) {
			విడుదల(పంక్తి);
			fclose(f);
			fingerprint_వ్యక్తిగత(మార్గం);
			నిష్క్రమించు(0);
		}

		/*
		 * If it's not a private key, then this must be prepared to
		 * accept a public key prefixed with a hostname or options.
		 * Try a bare key first, otherwise skip the leading stuff.
		 */
		comment = ఖాళీ;
		ఒకవేళ ((బహిరంగ = try_read_కీలకం(&cp)) == ఖాళీ) {
			i = strtol(cp, &ep, 10);
			ఒకవేళ (i == 0 || ep == ఖాళీ ||
			    (*ep != ' ' && *ep != '\t')) {
				పూర్ణాంకం quoted = 0;

				comment = cp;
				కొరకు (; *cp && (quoted || (*cp != ' ' &&
				    *cp != '\t')); cp++) {
					ఒకవేళ (*cp == '\\' && cp[1] == '"')
						cp++;	/* Skip both */
					లేకపోతే ఒకవేళ (*cp == '"')
						quoted = !quoted;
				}
				ఒకవేళ (!*cp)
					కొనసాగు;
				*cp++ = '\0';
			}
		}
		/* Retry after parsing leading hostname/key options */
		ఒకవేళ (బహిరంగ == ఖాళీ && (బహిరంగ = try_read_కీలకం(&cp)) == ఖాళీ) {
			debug("%s:%lu: not a public key", మార్గం, lnum);
			కొనసాగు;
		}

		/* Find trailing comment, if any */
		కొరకు (; *cp == ' ' || *cp == '\t'; cp++)
			;
		ఒకవేళ (*cp != '\0' && *cp != '#')
			comment = cp;

		fingerprint_one_కీలకం(బహిరంగ, comment);
		sshkey_free(బహిరంగ);
		invalid = 0; /* One good key in the file is sufficient */
	}
	fclose(f);
	విడుదల(పంక్తి);

	ఒకవేళ (invalid)
		fatal("%s is not a public key file.", మార్గం);
	నిష్క్రమించు(0);
}

స్థిర శూన్య
do_gen_all_hostkeys(నిర్మాణం passwd *pw)
{
	నిర్మాణం {
		అక్షరం *కీలకం_type;
		అక్షరం *కీలకం_type_display;
		అక్షరం *మార్గం;
	} కీలకం_types[] = {
#నిర్వచితమైతే WITH_OPENSSL
		{ "rsa", "RSA" ,మార్గం_HOST_RSA_కీలకం_FILE },
		{ "ecdsa", "ECDSA",మార్గం_HOST_ECDSA_కీలకం_FILE },
#అయితే_ముగింపు /* WITH_OPENSSL */
		{ "ed25519", "ED25519",మార్గం_HOST_ED25519_కీలకం_FILE },
#నిర్వచితమైతే USE_MLDSA
		{ "mldsa44-ed25519", "MLDSA44-ED25519",
		     మార్గం_HOST_MLDSA44_ED25519_కీలకం_FILE },
#అయితే_ముగింపు
		{ ఖాళీ, ఖాళీ, ఖాళీ }
	};

	uint32_t బిట్లు = 0;
	పూర్ణాంకం మొదటి = 0;
	నిర్మాణం stat st;
	నిర్మాణం sshkey *అంతరంగ, *బహిరంగ;
	అక్షరం comment[కీలకం_COMMENT_MAX], *prv_tmp, *pub_tmp, *prv_file, *pub_file;
	పూర్ణాంకం i, type, fd, r;

	కొరకు (i = 0; కీలకం_types[i].కీలకం_type; i++) {
		బహిరంగ = అంతరంగ = ఖాళీ;
		prv_tmp = pub_tmp = prv_file = pub_file = ఖాళీ;

		xasprintf(&prv_file, "%s%s",
		    తటస్థం_file, కీలకం_types[i].మార్గం);

		/* Check whether private key exists and is not zero-length */
		ఒకవేళ (stat(prv_file, &st) == 0) {
			ఒకవేళ (st.st_size != 0)
				వెళ్ళు తదుపరి;
		} లేకపోతే ఒకవేళ (errno != ENOENT) {
			error("Could not stat %s: %s", కీలకం_types[i].మార్గం,
			    strerror(errno));
			వెళ్ళు failnext;
		}

		/*
		 * Private key doesn't exist or is invalid; proceed with
		 * key generation.
		 */
		xasprintf(&prv_tmp, "%s%s.XXXXXXXXXX",
		    తటస్థం_file, కీలకం_types[i].మార్గం);
		xasprintf(&pub_tmp, "%s%s.pub.XXXXXXXXXX",
		    తటస్థం_file, కీలకం_types[i].మార్గం);
		xasprintf(&pub_file, "%s%s.pub",
		    తటస్థం_file, కీలకం_types[i].మార్గం);

		ఒకవేళ (మొదటి == 0) {
			మొదటి = 1;
			రాయి("%s: generating new host keys: ", __progname);
		}
		రాయి("%s ", కీలకం_types[i].కీలకం_type_display);
		fflush(stdout);
		type = sshkey_type_from_shortname(కీలకం_types[i].కీలకం_type);
		ఒకవేళ ((fd = mkstemp(prv_tmp)) == -1) {
			error("Could not save your private key in %s: %s",
			    prv_tmp, strerror(errno));
			వెళ్ళు failnext;
		}
		(శూన్య)close(fd); /* just using mkstemp() to reserve a name */
		బిట్లు = 0;
		type_బిట్లు_valid(type, ఖాళీ, &బిట్లు);
		ఒకవేళ ((r = sshkey_generate(type, బిట్లు, &అంతరంగ)) != 0) {
			error_r(r, "sshkey_generate failed");
			వెళ్ళు failnext;
		}
		ఒకవేళ ((r = sshkey_from_వ్యక్తిగత(అంతరంగ, &బహిరంగ)) != 0)
			fatal_fr(r, "sshkey_from_private");
		snprintf(comment, పరిమాణం comment, "%s@%s", pw->pw_name,
		    hostname);
		ఒకవేళ ((r = sshkey_save_వ్యక్తిగత(అంతరంగ, prv_tmp, "",
		    comment, వ్యక్తిగత_కీలకం_format, openssh_format_cipher,
		    విడతలు)) != 0) {
			error_r(r, "Saving key \"%s\" failed", prv_tmp);
			వెళ్ళు failnext;
		}
		ఒకవేళ ((fd = mkstemp(pub_tmp)) == -1) {
			error("Could not save your public key in %s: %s",
			    pub_tmp, strerror(errno));
			వెళ్ళు failnext;
		}
		(శూన్య)fchmod(fd, 0644);
		(శూన్య)close(fd);
		ఒకవేళ ((r = sshkey_save_ప్రజా(బహిరంగ, pub_tmp, comment)) != 0) {
			error_r(r, "Unable to save public key to %s",
			    తటస్థం_file);
			వెళ్ళు failnext;
		}

		/* Rename temporary files to their permanent locations. */
		ఒకవేళ (rename(pub_tmp, pub_file) != 0) {
			error("Unable to move %s into position: %s",
			    pub_file, strerror(errno));
			వెళ్ళు failnext;
		}
		ఒకవేళ (rename(prv_tmp, prv_file) != 0) {
			error("Unable to move %s into position: %s",
			    కీలకం_types[i].మార్గం, strerror(errno));
 failnext:
			మొదటి = 0;
			వెళ్ళు తదుపరి;
		}
 తదుపరి:
		sshkey_free(అంతరంగ);
		sshkey_free(బహిరంగ);
		విడుదల(prv_tmp);
		విడుదల(pub_tmp);
		విడుదల(prv_file);
		విడుదల(pub_file);
	}
	ఒకవేళ (మొదటి != 0)
		రాయి("\n");
}

నిర్మాణం తెలిసిన_hosts_ctx {
	స్థిరరాశి అక్షరం *host;	/* Hostname searched for in find/delete case */
	FILE *బహిర్గతం;		/* Output file, stdout for find_hosts case */
	పూర్ణాంకం has_unhashed;	/* When hashing, original had unhashed hosts */
	పూర్ణాంకం దొరికింది_కీలకం;		/* For find/delete, host was found */
	పూర్ణాంకం invalid;		/* File contained invalid items; don't delete */
	పూర్ణాంకం hash_hosts;		/* Hash hostnames as we go */
	పూర్ణాంకం కనుగొను_host;		/* Search for specific hostname */
	పూర్ణాంకం delete_host;	/* Delete host from known_hosts */
};

స్థిర పూర్ణాంకం
తెలిసిన_hosts_hash(నిర్మాణం hostkey_foreach_పంక్తి *l, శూన్య *_ctx)
{
	నిర్మాణం తెలిసిన_hosts_ctx *ctx = (నిర్మాణం తెలిసిన_hosts_ctx *)_ctx;
	అక్షరం *hashed, *cp, *hosts, *ohosts;
	పూర్ణాంకం has_wild = l->hosts && strcspn(l->hosts, "*?!") != అక్షరశ్రేణి_పొడవు(l->hosts);
	పూర్ణాంకం was_hashed = l->hosts && l->hosts[0] == HASH_DELIM;

	ఎంపిక (l->స్థితి_2) {
	స్థితి HKF_స్థితి_OK:
	స్థితి HKF_స్థితి_MATCHED:
		/*
		 * Don't hash hosts already hashed, with wildcard
		 * characters or a CA/revocation marker.
		 */
		ఒకవేళ (was_hashed || has_wild || l->marker != MRK_NONE) {
			fprintf(ctx->బహిర్గతం, "%s\n", l->పంక్తి);
			ఒకవేళ (has_wild && !ctx->కనుగొను_host) {
				logit("%s:%lu: ignoring host name "
				    "with wildcard: %.64s", l->మార్గం,
				    l->linenum, l->hosts);
			}
			తిరిగి 0;
		}
		/*
		 * Split any comma-separated hostnames from the host list,
		 * hash and store separately.
		 */
		ohosts = hosts = xstrdup(l->hosts);
		అయితే ((cp = strsep(&hosts, ",")) != ఖాళీ && *cp != '\0') {
			lowercase(cp);
			ఒకవేళ ((hashed = host_hash(cp, ఖాళీ, 0)) == ఖాళీ)
				fatal("hash_host failed");
			fprintf(ctx->బహిర్గతం, "%s %s\n", hashed, l->rawkey);
			విడుదల(hashed);
			ctx->has_unhashed = 1;
		}
		విడుదల(ohosts);
		తిరిగి 0;
	స్థితి HKF_స్థితి_INVALID:
		/* Retain invalid lines, but mark file as invalid. */
		ctx->invalid = 1;
		logit("%s:%lu: invalid line", l->మార్గం, l->linenum);
		/* FALLTHROUGH */
	అప్రమేయ:
		fprintf(ctx->బహిర్గతం, "%s\n", l->పంక్తి);
		తిరిగి 0;
	}
	/* NOTREACHED */
	తిరిగి -1;
}

స్థిర పూర్ణాంకం
తెలిసిన_hosts_కనుగొను_delete(నిర్మాణం hostkey_foreach_పంక్తి *l, శూన్య *_ctx)
{
	నిర్మాణం తెలిసిన_hosts_ctx *ctx = (నిర్మాణం తెలిసిన_hosts_ctx *)_ctx;
	గణన sshkey_fp_rep rep;
	పూర్ణాంకం fptype;
	అక్షరం *fp = ఖాళీ, *ra = ఖాళీ;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;

	ఒకవేళ (l->స్థితి_2 == HKF_స్థితి_MATCHED) {
		ఒకవేళ (ctx->delete_host) {
			ఒకవేళ (l->marker != MRK_NONE) {
				/* Don't remove CA and revocation lines */
				fprintf(ctx->బహిర్గతం, "%s\n", l->పంక్తి);
			} లేకపోతే {
				/*
				 * Hostname matches and has no CA/revoke
				 * marker, delete it by *not* writing the
				 * line to ctx->out.
				 */
				ctx->దొరికింది_కీలకం = 1;
				ఒకవేళ (!quiet)
					రాయి("# Host %s found: line %lu\n",
					    ctx->host, l->linenum);
			}
			తిరిగి 0;
		} లేకపోతే ఒకవేళ (ctx->కనుగొను_host) {
			ctx->దొరికింది_కీలకం = 1;
			ఒకవేళ (!quiet) {
				రాయి("# Host %s found: line %lu %s\n",
				    ctx->host,
				    l->linenum, l->marker == MRK_CA ? "CA" :
				    (l->marker == MRK_REVOKE ? "REVOKED" : ""));
			}
			ఒకవేళ (ctx->hash_hosts)
				తెలిసిన_hosts_hash(l, ctx);
			లేకపోతే ఒకవేళ (print_fingerprint) {
				fp = sshkey_fingerprint(l->కీలకం, fptype, rep);
				ra = sshkey_fingerprint(l->కీలకం,
				    fingerprint_hash, SSH_FP_RANDOMART);
				ఒకవేళ (fp == ఖాళీ || ra == ఖాళీ)
					fatal_f("sshkey_fingerprint failed");
				mprintf("%s %s %s%s%s\n", ctx->host,
				    sshkey_type(l->కీలకం), fp,
				    l->comment[0] ? " " : "",
				    l->comment);
				ఒకవేళ (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
					రాయి("%s\n", ra);
				విడుదల(ra);
				విడుదల(fp);
			} లేకపోతే
				fprintf(ctx->బహిర్గతం, "%s\n", l->పంక్తి);
			తిరిగి 0;
		}
	} లేకపోతే ఒకవేళ (ctx->delete_host) {
		/* Retain non-matching hosts when deleting */
		ఒకవేళ (l->స్థితి_2 == HKF_స్థితి_INVALID) {
			ctx->invalid = 1;
			logit("%s:%lu: invalid line", l->మార్గం, l->linenum);
		}
		fprintf(ctx->బహిర్గతం, "%s\n", l->పంక్తి);
	}
	తిరిగి 0;
}

స్థిర శూన్య
do_తెలిసిన_hosts(నిర్మాణం passwd *pw, స్థిరరాశి అక్షరం *name, పూర్ణాంకం కనుగొను_host,
    పూర్ణాంకం delete_host, పూర్ణాంకం hash_hosts)
{
	అక్షరం *cp, tmp[PATH_MAX], old[PATH_MAX];
	పూర్ణాంకం r, fd, oerrno, inplace = 0;
	నిర్మాణం తెలిసిన_hosts_ctx ctx;
	u_int foreach_options;
	నిర్మాణం stat sb;

	ఒకవేళ (!have_తటస్థం) {
		cp = tilde_expand_filename(మార్గం_SSH_USER_HOSTFILE, pw->pw_uid);
		ఒకవేళ (strlcpy(తటస్థం_file, cp, పరిమాణం(తటస్థం_file)) >=
		    పరిమాణం(తటస్థం_file))
			fatal("Specified known hosts path too long");
		విడుదల(cp);
		have_తటస్థం = 1;
	}
	ఒకవేళ (stat(తటస్థం_file, &sb) != 0)
		fatal("Cannot stat %s: %s", తటస్థం_file, strerror(errno));

	memset(&ctx, 0, పరిమాణం(ctx));
	ctx.బహిర్గతం = stdout;
	ctx.host = name;
	ctx.hash_hosts = hash_hosts;
	ctx.కనుగొను_host = కనుగొను_host;
	ctx.delete_host = delete_host;

	/*
	 * Find hosts goes to stdout, hash and deletions happen in-place
	 * A corner case is ssh-keygen -HF foo, which should go to stdout
	 */
	ఒకవేళ (!కనుగొను_host && (hash_hosts || delete_host)) {
		ఒకవేళ (strlcpy(tmp, తటస్థం_file, పరిమాణం(tmp)) >= పరిమాణం(tmp) ||
		    strlcat(tmp, ".XXXXXXXXXX", పరిమాణం(tmp)) >= పరిమాణం(tmp) ||
		    strlcpy(old, తటస్థం_file, పరిమాణం(old)) >= పరిమాణం(old) ||
		    strlcat(old, ".old", పరిమాణం(old)) >= పరిమాణం(old))
			fatal("known_hosts path too long");
		umask(077);
		ఒకవేళ ((fd = mkstemp(tmp)) == -1)
			fatal("mkstemp: %s", strerror(errno));
		ఒకవేళ ((ctx.బహిర్గతం = fdopen(fd, "w")) == ఖాళీ) {
			oerrno = errno;
			unlink(tmp);
			fatal("fdopen: %s", strerror(oerrno));
		}
		(శూన్య)fchmod(fd, sb.st_mode & 0644);
		inplace = 1;
	}
	/* XXX support identity_file == "-" for stdin */
	foreach_options = కనుగొను_host ? HKF_WANT_సరిపోలిక : 0;
	foreach_options |= print_fingerprint ? HKF_WANT_PARSE_కీలకం : 0;
	ఒకవేళ ((r = hostkeys_foreach(తటస్థం_file, (కనుగొను_host || !hash_hosts) ?
	    తెలిసిన_hosts_కనుగొను_delete : తెలిసిన_hosts_hash, &ctx, name, ఖాళీ,
	    foreach_options, 0)) != 0) {
		ఒకవేళ (inplace)
			unlink(tmp);
		fatal_fr(r, "hostkeys_foreach");
	}

	ఒకవేళ (inplace)
		fclose(ctx.బహిర్గతం);

	ఒకవేళ (ctx.invalid) {
		error("%s is not a valid known_hosts file.", తటస్థం_file);
		ఒకవేళ (inplace) {
			error("Not replacing existing known_hosts "
			    "file because of errors");
			unlink(tmp);
		}
		నిష్క్రమించు(1);
	} లేకపోతే ఒకవేళ (delete_host && !ctx.దొరికింది_కీలకం) {
		logit("Host %s not found in %s", name, తటస్థం_file);
		ఒకవేళ (inplace)
			unlink(tmp);
	} లేకపోతే ఒకవేళ (inplace) {
		/* Backup existing file */
		ఒకవేళ (unlink(old) == -1 && errno != ENOENT)
			fatal("unlink %.100s: %s", old, strerror(errno));
		ఒకవేళ (link(తటస్థం_file, old) == -1)
			fatal("link %.100s to %.100s: %s", తటస్థం_file, old,
			    strerror(errno));
		/* Move new one into place */
		ఒకవేళ (rename(tmp, తటస్థం_file) == -1) {
			error("rename\"%s\" to \"%s\": %s", tmp, తటస్థం_file,
			    strerror(errno));
			unlink(tmp);
			unlink(old);
			నిష్క్రమించు(1);
		}

		రాయి("%s updated.\n", తటస్థం_file);
		రాయి("Original contents retained as %s\n", old);
		ఒకవేళ (ctx.has_unhashed) {
			logit("WARNING: %s contains unhashed entries", old);
			logit("Delete this file to ensure privacy "
			    "of hostnames");
		}
	}

	నిష్క్రమించు (కనుగొను_host && !ctx.దొరికింది_కీలకం);
}

/*
 * Perform changing a passphrase.  The argument is the passwd structure
 * for the current user.
 */
స్థిర శూన్య
do_change_passphrase(నిర్మాణం passwd *pw, అక్షరం * స్థిరరాశి *opts, కొలత_t nopts)
{
	అక్షరం *comment;
	అక్షరం *old_passphrase, *passphrase1, *passphrase2;
	నిర్మాణం stat st;
	నిర్మాణం sshkey *అంతరంగ;
	పూర్ణాంకం r;
	కొలత_t i;

	ఒకవేళ (!have_తటస్థం)
		ask_filename(pw, "Enter file in which the key is");
	ఒకవేళ (stat(తటస్థం_file, &st) == -1)
		fatal("%s: %s", తటస్థం_file, strerror(errno));
	/* Try to load the file with empty passphrase. */
	r = sshkey_ఎక్కించు_వ్యక్తిగత(తటస్థం_file, "", &అంతరంగ, &comment);
	ఒకవేళ (r == SSH_ERR_కీలకం_WRONG_PASSPHRASE) {
		ఒకవేళ (తటస్థం_passphrase)
			old_passphrase = xstrdup(తటస్థం_passphrase);
		లేకపోతే
			old_passphrase =
			    read_passphrase("Enter old passphrase: ",
			    RP_ALLOW_STDIN);
		r = sshkey_ఎక్కించు_వ్యక్తిగత(తటస్థం_file, old_passphrase,
		    &అంతరంగ, &comment);
		freezero(old_passphrase, అక్షరశ్రేణి_పొడవు(old_passphrase));
		ఒకవేళ (r != 0)
			వెళ్ళు badkey;
	} లేకపోతే ఒకవేళ (r != 0) {
 badkey:
		fatal_r(r, "Failed to load key %s", తటస్థం_file);
	}
	ఒకవేళ (comment)
		mprintf("Key has comment '%s'\n", comment);

	/* All current -O options relate to FIDO keys only */
	ఒకవేళ (nopts != 0 && !sshkey_is_sk(అంతరంగ)) {
		fatal("FIDO-specific option requested for non-FIDO key %s",
		    తటస్థం_file);
	}
	ఒకవేళ (sshkey_is_sk(అంతరంగ)) {
		debug_f("%s: original FIDO key flags: "
		    "%stouch-required %sverify-required", తటస్థం_file,
		    (అంతరంగ->sk_flags & SSH_SK_USER_PRESENCE_REQD) ? "": "no-",
		    (అంతరంగ->sk_flags & SSH_SK_USER_VERIFICATION_REQD) ? "" : "no-");
	}
	కొరకు (i = 0; i < nopts; i++) {
		ఒకవేళ (strcasecmp(opts[i], "touch-required") == 0)
			అంతరంగ->sk_flags |= SSH_SK_USER_PRESENCE_REQD;
		లేకపోతే ఒకవేళ (strcasecmp(opts[i], "no-touch-required") == 0)
			అంతరంగ->sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
		లేకపోతే ఒకవేళ (strcasecmp(opts[i], "verify-required") == 0)
			అంతరంగ->sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
		లేకపోతే ఒకవేళ (strcasecmp(opts[i], "no-verify-required") == 0)
			అంతరంగ->sk_flags &= ~SSH_SK_USER_VERIFICATION_REQD;
		లేకపోతే {
			fatal("Option \"%s\" is unsupported for "
			    "key passphrase change", opts[i]);
		}
	}
	ఒకవేళ (sshkey_is_sk(అంతరంగ) && nopts != 0) {
		debug_f("%s: updated FIDO key flags: "
		    "%stouch-required %sverify-required", తటస్థం_file,
		    (అంతరంగ->sk_flags & SSH_SK_USER_PRESENCE_REQD) ? "": "no-",
		    (అంతరంగ->sk_flags & SSH_SK_USER_VERIFICATION_REQD) ? "" : "no-");
	}

	/* Ask the new passphrase (twice). */
	ఒకవేళ (తటస్థం_new_passphrase) {
		passphrase1 = xstrdup(తటస్థం_new_passphrase);
		passphrase2 = ఖాళీ;
	} లేకపోతే {
		passphrase1 =
			read_passphrase("Enter new passphrase (empty for no "
			    "passphrase): ", RP_ALLOW_STDIN);
		passphrase2 = read_passphrase("Enter same passphrase again: ",
		    RP_ALLOW_STDIN);

		/* Verify that they are the same. */
		ఒకవేళ (strcmp(passphrase1, passphrase2) != 0) {
			explicit_bzero(passphrase1, అక్షరశ్రేణి_పొడవు(passphrase1));
			explicit_bzero(passphrase2, అక్షరశ్రేణి_పొడవు(passphrase2));
			విడుదల(passphrase1);
			విడుదల(passphrase2);
			రాయి("Pass phrases do not match.  Try again.\n");
			నిష్క్రమించు(1);
		}
		/* Destroy the other copy. */
		freezero(passphrase2, అక్షరశ్రేణి_పొడవు(passphrase2));
	}

	/* Save the file using the new passphrase. */
	ఒకవేళ ((r = sshkey_save_వ్యక్తిగత(అంతరంగ, తటస్థం_file, passphrase1,
	    comment, వ్యక్తిగత_కీలకం_format, openssh_format_cipher, విడతలు)) != 0) {
		error_r(r, "Saving key \"%s\" failed", తటస్థం_file);
		freezero(passphrase1, అక్షరశ్రేణి_పొడవు(passphrase1));
		sshkey_free(అంతరంగ);
		విడుదల(comment);
		నిష్క్రమించు(1);
	}
	/* Destroy the passphrase and the copy of the key in memory. */
	freezero(passphrase1, అక్షరశ్రేణి_పొడవు(passphrase1));
	sshkey_free(అంతరంగ);		 /* Destroys contents */
	విడుదల(comment);

	రాయి("Your identification has been saved with the new passphrase.\n");
	నిష్క్రమించు(0);
}

/*
 * Print the SSHFP RR.
 */
స్థిర పూర్ణాంకం
do_print_resource_రికార్డు(నిర్మాణం passwd *pw, అక్షరం *fname, అక్షరం *hname,
    పూర్ణాంకం print_generic, అక్షరం * స్థిరరాశి *opts, కొలత_t nopts)
{
	నిర్మాణం sshkey *బహిరంగ;
	అక్షరం *comment = ఖాళీ;
	స్థిరరాశి అక్షరం *p;
	నిర్మాణం stat st;
	పూర్ణాంకం r, hash = -1;
	కొలత_t i;

	కొరకు (i = 0; i < nopts; i++) {
		ఒకవేళ ((p = strprefix(opts[i], "hashalg=", 1)) != ఖాళీ) {
			ఒకవేళ ((hash = ssh_digest_alg_by_name(p)) == -1)
				fatal("Unsupported hash algorithm");
		} లేకపోతే {
			error("Invalid option \"%s\"", opts[i]);
			తిరిగి SSH_ERR_INVALID_వాదం;
		}
	}
	ఒకవేళ (fname == ఖాళీ)
		fatal_f("no filename");
	ఒకవేళ (stat(fname, &st) == -1) {
		ఒకవేళ (errno == ENOENT)
			తిరిగి 0;
		fatal("%s: %s", fname, strerror(errno));
	}
	ఒకవేళ ((r = sshkey_ఎక్కించు_ప్రజా(fname, &బహిరంగ, &comment)) != 0)
		fatal_r(r, "Failed to read v2 public key from \"%s\"", fname);
	export_dns_rr(hname, బహిరంగ, stdout, print_generic, hash);
	sshkey_free(బహిరంగ);
	విడుదల(comment);
	తిరిగి 1;
}

/*
 * Change the comment of a private key file.
 */
స్థిర శూన్య
do_change_comment(నిర్మాణం passwd *pw, స్థిరరాశి అక్షరం *తటస్థం_comment)
{
	అక్షరం new_comment[కీలకం_COMMENT_MAX], *comment, *passphrase;
	నిర్మాణం sshkey *అంతరంగ;
	నిర్మాణం sshkey *బహిరంగ;
	నిర్మాణం stat st;
	పూర్ణాంకం r;

	ఒకవేళ (!have_తటస్థం)
		ask_filename(pw, "Enter file in which the key is");
	ఒకవేళ (stat(తటస్థం_file, &st) == -1)
		fatal("%s: %s", తటస్థం_file, strerror(errno));
	ఒకవేళ ((r = sshkey_ఎక్కించు_వ్యక్తిగత(తటస్థం_file, "",
	    &అంతరంగ, &comment)) == 0)
		passphrase = xstrdup("");
	లేకపోతే ఒకవేళ (r != SSH_ERR_కీలకం_WRONG_PASSPHRASE)
		fatal_r(r, "Cannot load private key \"%s\"", తటస్థం_file);
	లేకపోతే {
		ఒకవేళ (తటస్థం_passphrase)
			passphrase = xstrdup(తటస్థం_passphrase);
		లేకపోతే ఒకవేళ (తటస్థం_new_passphrase)
			passphrase = xstrdup(తటస్థం_new_passphrase);
		లేకపోతే
			passphrase = read_passphrase("Enter passphrase: ",
			    RP_ALLOW_STDIN);
		/* Try to load using the passphrase. */
		ఒకవేళ ((r = sshkey_ఎక్కించు_వ్యక్తిగత(తటస్థం_file, passphrase,
		    &అంతరంగ, &comment)) != 0) {
			freezero(passphrase, అక్షరశ్రేణి_పొడవు(passphrase));
			fatal_r(r, "Cannot load private key \"%s\"",
			    తటస్థం_file);
		}
	}

	ఒకవేళ (అంతరంగ->type != కీలకం_ED25519 &&
	    వ్యక్తిగత_కీలకం_format != SSHKEY_వ్యక్తిగత_OPENSSH) {
		error("Comments are only supported for keys stored in "
		    "the new format (-o).");
		explicit_bzero(passphrase, అక్షరశ్రేణి_పొడవు(passphrase));
		sshkey_free(అంతరంగ);
		నిష్క్రమించు(1);
	}
	ఒకవేళ (comment)
		రాయి("Old comment: %s\n", comment);
	లేకపోతే
		రాయి("No existing comment\n");

	ఒకవేళ (తటస్థం_comment) {
		strlcpy(new_comment, తటస్థం_comment, పరిమాణం(new_comment));
	} లేకపోతే {
		రాయి("New comment: ");
		fflush(stdout);
		ఒకవేళ (!fgets(new_comment, పరిమాణం(new_comment), stdin)) {
			explicit_bzero(passphrase, అక్షరశ్రేణి_పొడవు(passphrase));
			sshkey_free(అంతరంగ);
			నిష్క్రమించు(1);
		}
		new_comment[strcspn(new_comment, "\n")] = '\0';
	}
	ఒకవేళ (comment != ఖాళీ && strcmp(comment, new_comment) == 0) {
		రాయి("No change to comment\n");
		విడుదల(passphrase);
		sshkey_free(అంతరంగ);
		విడుదల(comment);
		నిష్క్రమించు(0);
	}

	/* Save the file using the new passphrase. */
	ఒకవేళ ((r = sshkey_save_వ్యక్తిగత(అంతరంగ, తటస్థం_file, passphrase,
	    new_comment, వ్యక్తిగత_కీలకం_format, openssh_format_cipher,
	    విడతలు)) != 0) {
		error_r(r, "Saving key \"%s\" failed", తటస్థం_file);
		freezero(passphrase, అక్షరశ్రేణి_పొడవు(passphrase));
		sshkey_free(అంతరంగ);
		విడుదల(comment);
		నిష్క్రమించు(1);
	}
	freezero(passphrase, అక్షరశ్రేణి_పొడవు(passphrase));
	ఒకవేళ ((r = sshkey_from_వ్యక్తిగత(అంతరంగ, &బహిరంగ)) != 0)
		fatal_fr(r, "sshkey_from_private");
	sshkey_free(అంతరంగ);

	strlcat(తటస్థం_file, ".pub", పరిమాణం(తటస్థం_file));
	ఒకవేళ ((r = sshkey_save_ప్రజా(బహిరంగ, తటస్థం_file, new_comment)) != 0)
		fatal_r(r, "Unable to save public key to %s", తటస్థం_file);
	sshkey_free(బహిరంగ);
	విడుదల(comment);

	ఒకవేళ (అక్షరశ్రేణి_పొడవు(new_comment) > 0)
		రాయి("Comment '%s' applied\n", new_comment);
	లేకపోతే
		రాయి("Comment removed\n");

	నిష్క్రమించు(0);
}

స్థిర శూన్య
cert_ext_కూడు(స్థిరరాశి అక్షరం *కీలకం, స్థిరరాశి అక్షరం *విలువ, పూర్ణాంకం iscrit)
{
	cert_ext = xreallocarray(cert_ext, ncert_ext + 1, పరిమాణం(*cert_ext));
	cert_ext[ncert_ext].కీలకం = xstrdup(కీలకం);
	cert_ext[ncert_ext].val = విలువ == ఖాళీ ? ఖాళీ : xstrdup(విలువ);
	cert_ext[ncert_ext].crit = iscrit;
	ncert_ext++;
}

/* qsort(3) comparison function for certificate extensions */
స్థిర పూర్ణాంకం
cert_ext_cmp(స్థిరరాశి శూన్య *_a, స్థిరరాశి శూన్య *_b)
{
	స్థిరరాశి నిర్మాణం cert_ext *a = (స్థిరరాశి నిర్మాణం cert_ext *)_a;
	స్థిరరాశి నిర్మాణం cert_ext *b = (స్థిరరాశి నిర్మాణం cert_ext *)_b;
	పూర్ణాంకం r;

	ఒకవేళ (a->crit != b->crit)
		తిరిగి (a->crit < b->crit) ? -1 : 1;
	ఒకవేళ ((r = strcmp(a->కీలకం, b->కీలకం)) != 0)
		తిరిగి r;
	ఒకవేళ ((a->val == ఖాళీ) != (b->val == ఖాళీ))
		తిరిగి (a->val == ఖాళీ) ? -1 : 1;
	ఒకవేళ (a->val != ఖాళీ && (r = strcmp(a->val, b->val)) != 0)
		తిరిగి r;
	తిరిగి 0;
}

#నిర్వచించు OPTIONS_CRITICAL	1
#నిర్వచించు OPTIONS_EXTENSIONS	2
స్థిర శూన్య
prepare_options_buf(నిర్మాణం sshbuf *c, పూర్ణాంకం which)
{
	నిర్మాణం sshbuf *b;
	కొలత_t i;
	పూర్ణాంకం r;
	స్థిరరాశి నిర్మాణం cert_ext *ext;

	ఒకవేళ ((b = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	sshbuf_reset(c);
	కొరకు (i = 0; i < ncert_ext; i++) {
		ext = &cert_ext[i];
		ఒకవేళ ((ext->crit && (which & OPTIONS_EXTENSIONS)) ||
		    (!ext->crit && (which & OPTIONS_CRITICAL)))
			కొనసాగు;
		ఒకవేళ (ext->val == ఖాళీ) {
			/* flag option */
			debug3_f("%s", ext->కీలకం);
			ఒకవేళ ((r = sshbuf_put_cstring(c, ext->కీలకం)) != 0 ||
			    (r = sshbuf_put_string(c, ఖాళీ, 0)) != 0)
				fatal_fr(r, "prepare flag");
		} లేకపోతే {
			/* key/value option */
			debug3_f("%s=%s", ext->కీలకం, ext->val);
			sshbuf_reset(b);
			ఒకవేళ ((r = sshbuf_put_cstring(c, ext->కీలకం)) != 0 ||
			    (r = sshbuf_put_cstring(b, ext->val)) != 0 ||
			    (r = sshbuf_put_stringb(c, b)) != 0)
				fatal_fr(r, "prepare k/v");
		}
	}
	sshbuf_free(b);
}

స్థిర శూన్య
finalise_cert_exts(శూన్య)
{
	/* critical options */
	ఒకవేళ (certflags_command != ఖాళీ)
		cert_ext_కూడు("force-command", certflags_command, 1);
	ఒకవేళ (certflags_src_addr != ఖాళీ)
		cert_ext_కూడు("source-address", certflags_src_addr, 1);
	ఒకవేళ ((certflags_flags & CERTOPT_REQUIRE_VERIFY) != 0)
		cert_ext_కూడు("verify-required", ఖాళీ, 1);
	/* extensions */
	ఒకవేళ ((certflags_flags & CERTOPT_X_FWD) != 0)
		cert_ext_కూడు("permit-X11-forwarding", ఖాళీ, 0);
	ఒకవేళ ((certflags_flags & CERTOPT_AGENT_FWD) != 0)
		cert_ext_కూడు("permit-agent-forwarding", ఖాళీ, 0);
	ఒకవేళ ((certflags_flags & CERTOPT_పోర్టు_FWD) != 0)
		cert_ext_కూడు("permit-port-forwarding", ఖాళీ, 0);
	ఒకవేళ ((certflags_flags & CERTOPT_PTY) != 0)
		cert_ext_కూడు("permit-pty", ఖాళీ, 0);
	ఒకవేళ ((certflags_flags & CERTOPT_USER_RC) != 0)
		cert_ext_కూడు("permit-user-rc", ఖాళీ, 0);
	ఒకవేళ ((certflags_flags & CERTOPT_NO_REQUIRE_USER_PRESENCE) != 0)
		cert_ext_కూడు("no-touch-required", ఖాళీ, 0);
	/* order lexically by key */
	ఒకవేళ (ncert_ext > 0)
		qsort(cert_ext, ncert_ext, పరిమాణం(*cert_ext), cert_ext_cmp);
}

స్థిర నిర్మాణం sshkey *
ఎక్కించు_pkcs11_కీలకం(అక్షరం *మార్గం)
{
#నిర్వచితమైతే ENABLE_PKCS11
	నిర్మాణం sshkey **కీలకాలు = ఖాళీ, *బహిరంగ, *అంతరంగ = ఖాళీ;
	పూర్ణాంకం r, i, nkeys;

	ఒకవేళ ((r = sshkey_ఎక్కించు_ప్రజా(మార్గం, &బహిరంగ, ఖాళీ)) != 0)
		fatal_r(r, "Couldn't load CA public key \"%s\"", మార్గం);

	nkeys = pkcs11_కూడు_provider(pkcs11provider, తటస్థం_passphrase,
	    &కీలకాలు, ఖాళీ);
	debug3_f("%d keys", nkeys);
	ఒకవేళ (nkeys <= 0)
		fatal("cannot read public key from pkcs11");
	కొరకు (i = 0; i < nkeys; i++) {
		ఒకవేళ (sshkey_equal_ప్రజా(బహిరంగ, కీలకాలు[i])) {
			అంతరంగ = కీలకాలు[i];
			కొనసాగు;
		}
		sshkey_free(కీలకాలు[i]);
	}
	విడుదల(కీలకాలు);
	sshkey_free(బహిరంగ);
	తిరిగి అంతరంగ;
#లేకపోతే
	fatal("no pkcs11 support");
#అయితే_ముగింపు /* ENABLE_PKCS11 */
}

/* Signer for sshkey_certify_custom that uses the agent */
స్థిర పూర్ణాంకం
agent_signer(నిర్మాణం sshkey *కీలకం, u_char **sigp, కొలత_t *lenp,
    స్థిరరాశి u_char *దత్తాంశం, కొలత_t datalen,
    స్థిరరాశి అక్షరం *alg, స్థిరరాశి అక్షరం *provider, స్థిరరాశి అక్షరం *pin,
    u_int compat, శూన్య *ctx)
{
	పూర్ణాంకం *agent_fdp = (పూర్ణాంకం *)ctx;

	తిరిగి ssh_agent_sign(*agent_fdp, కీలకం, sigp, lenp,
	    దత్తాంశం, datalen, alg, compat);
}

స్థిర శూన్య
do_ca_sign(నిర్మాణం passwd *pw, స్థిరరాశి అక్షరం *ca_కీలకం_మార్గం, పూర్ణాంకం prefer_agent,
    గుర్తులేని దీర్ఘ దీర్ఘ cert_serial, పూర్ణాంకం cert_serial_autoinc,
    పూర్ణాంకం argc, అక్షరం **argv)
{
	పూర్ణాంకం r, i, కీలకం_లోపల_agent = 0, agent_fd = -1;
	u_int n;
	నిర్మాణం sshkey *ca, *బహిరంగ;
	అక్షరం valid[64], *otmp, *tmp, *cp, *బహిర్గతం, *comment;
	అక్షరం *ca_fp = ఖాళీ, **plist = ఖాళీ, *pin = ఖాళీ;
	నిర్మాణం ssh_identitylist *agent_ids;
	కొలత_t j;
	నిర్మాణం notifier_ctx *notifier = ఖాళీ;

#నిర్వచితమైతే ENABLE_PKCS11
	pkcs11_init(1);
#అయితే_ముగింపు
	tmp = tilde_expand_filename(ca_కీలకం_మార్గం, pw->pw_uid);
	ఒకవేళ (pkcs11provider != ఖాళీ) {
		/* If a PKCS#11 token was specified then try to use it */
		ఒకవేళ ((ca = ఎక్కించు_pkcs11_కీలకం(tmp)) == ఖాళీ)
			fatal("No PKCS#11 key matching %s found", ca_కీలకం_మార్గం);
	} లేకపోతే ఒకవేళ (prefer_agent) {
		/*
		 * Agent signature requested. Try to use agent after making
		 * sure the public key specified is actually present in the
		 * agent.
		 */
		ఒకవేళ ((r = sshkey_ఎక్కించు_ప్రజా(tmp, &ca, ఖాళీ)) != 0)
			fatal_r(r, "Cannot load CA public key %s", tmp);
		ఒకవేళ ((r = ssh_get_authentication_socket(&agent_fd)) != 0)
			fatal_r(r, "Cannot use public key for CA signature");
		ఒకవేళ ((r = ssh_fetch_identitylist(agent_fd, &agent_ids)) != 0)
			fatal_r(r, "Retrieve agent key list");
		కొరకు (j = 0; j < agent_ids->nkeys; j++) {
			ఒకవేళ (sshkey_equal(ca, agent_ids->కీలకాలు[j])) {
				కీలకం_లోపల_agent = 1;
				/* Replace the CA key with the agent one */
				sshkey_free(ca);
				ca = agent_ids->కీలకాలు[j];
				agent_ids->కీలకాలు[j] = ఖాళీ;
				ఆపు;
			}
		}
		ఒకవేళ (!కీలకం_లోపల_agent)
			fatal("CA key %s not found in agent", tmp);
		ssh_free_identitylist(agent_ids);
	} లేకపోతే {
		/* CA key is assumed to be a private key on the filesystem */
		ca = ఎక్కించు_తటస్థం(tmp, ఖాళీ);
		ఒకవేళ (sshkey_is_sk(ca) &&
		    (ca->sk_flags & SSH_SK_USER_VERIFICATION_REQD)) {
			ఒకవేళ ((pin = read_passphrase("Enter PIN for CA key: ",
			    RP_ALLOW_STDIN)) == ఖాళీ)
				fatal_f("couldn't read PIN");
		}
	}
	విడుదల(tmp);

	ఒకవేళ (కీలకం_type_name != ఖాళీ) {
		ఒకవేళ (sshkey_type_from_shortname(కీలకం_type_name) != ca->type) {
			fatal("CA key type %s doesn't match specified %s",
			    sshkey_ssh_name(ca), కీలకం_type_name);
		}
	} లేకపోతే ఒకవేళ (ca->type == కీలకం_RSA) {
		/* Default to a good signature algorithm */
		కీలకం_type_name = "rsa-sha2-512";
	}
	ca_fp = sshkey_fingerprint(ca, fingerprint_hash, SSH_FP_DEFAULT);

	finalise_cert_exts();
	కొరకు (i = 0; i < argc; i++) {
		/* Split list of principals */
		n = 0;
		ఒకవేళ (cert_principals != ఖాళీ) {
			otmp = tmp = xstrdup(cert_principals);
			plist = ఖాళీ;
			కొరకు (; (cp = strsep(&tmp, ",")) != ఖాళీ; n++) {
				plist = xreallocarray(plist, n + 1, పరిమాణం(*plist));
				ఒకవేళ (*(plist[n] = xstrdup(cp)) == '\0')
					fatal("Empty principal name");
			}
			విడుదల(otmp);
		}
		ఒకవేళ (n > SSHKEY_CERT_MAX_PRINCIPALS)
			fatal("Too many certificate principals specified");

		tmp = tilde_expand_filename(argv[i], pw->pw_uid);
		ఒకవేళ ((r = sshkey_ఎక్కించు_ప్రజా(tmp, &బహిరంగ, &comment)) != 0)
			fatal_r(r, "load pubkey \"%s\"", tmp);
		ఒకవేళ (sshkey_is_cert(బహిరంగ))
			fatal_f("key \"%s\" type %s cannot be certified",
			    tmp, sshkey_type(బహిరంగ));

		/* Prepare certificate to sign */
		ఒకవేళ ((r = sshkey_గమ్యం_certified(బహిరంగ)) != 0)
			fatal_r(r, "Could not upgrade key %s to certificate", tmp);
		బహిరంగ->cert->type = cert_కీలకం_type;
		బహిరంగ->cert->serial = (uint64_t)cert_serial;
		బహిరంగ->cert->కీలకం_id = xstrdup(cert_కీలకం_id);
		బహిరంగ->cert->nprincipals = n;
		బహిరంగ->cert->principals = plist;
		బహిరంగ->cert->valid_after = cert_valid_from;
		బహిరంగ->cert->valid_before = cert_valid_గమ్యం;
		prepare_options_buf(బహిరంగ->cert->critical, OPTIONS_CRITICAL);
		prepare_options_buf(బహిరంగ->cert->extensions,
		    OPTIONS_EXTENSIONS);
		ఒకవేళ ((r = sshkey_from_వ్యక్తిగత(ca,
		    &బహిరంగ->cert->signature_కీలకం)) != 0)
			fatal_r(r, "sshkey_from_private (ca key)");

		ఒకవేళ (కీలకం_లోపల_agent) {
			ఒకవేళ ((r = sshkey_certify_custom(బహిరంగ, ca,
			    కీలకం_type_name, sk_provider, ఖాళీ, agent_signer,
			    &agent_fd)) != 0)
				fatal_r(r, "Couldn't certify %s via agent", tmp);
		} లేకపోతే {
			ఒకవేళ (sshkey_is_sk(ca) &&
			    (ca->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
				notifier = notify_ప్రారంభం(0,
				    "Confirm user presence for key %s %s",
				    sshkey_type(ca), ca_fp);
			}
			r = sshkey_certify(బహిరంగ, ca, కీలకం_type_name,
			    sk_provider, pin);
			notify_complete(notifier, "User presence confirmed");
			ఒకవేళ (r != 0)
				fatal_r(r, "Couldn't certify key %s", tmp);
		}

		ఒకవేళ ((cp = strrchr(tmp, '.')) != ఖాళీ && strcmp(cp, ".pub") == 0)
			*cp = '\0';
		xasprintf(&బహిర్గతం, "%s-cert.pub", tmp);
		విడుదల(tmp);

		ఒకవేళ ((r = sshkey_save_ప్రజా(బహిరంగ, బహిర్గతం, comment)) != 0) {
			fatal_r(r, "Unable to save public key to %s",
			    తటస్థం_file);
		}

		ఒకవేళ (!quiet) {
			sshkey_format_cert_validity(బహిరంగ->cert,
			    valid, పరిమాణం(valid));
			logit("Signed %s key %s: id \"%s\" serial %llu%s%s "
			    "valid %s", sshkey_cert_type(బహిరంగ),
			    బహిర్గతం, బహిరంగ->cert->కీలకం_id,
			    (గుర్తులేని దీర్ఘ దీర్ఘ)బహిరంగ->cert->serial,
			    cert_principals != ఖాళీ ? " for " : "",
			    cert_principals != ఖాళీ ? cert_principals : "",
			    valid);
		}

		sshkey_free(బహిరంగ);
		విడుదల(బహిర్గతం);
		విడుదల(comment);
		ఒకవేళ (cert_serial_autoinc)
			cert_serial++;
	}
	ఒకవేళ (pin != ఖాళీ)
		freezero(pin, అక్షరశ్రేణి_పొడవు(pin));
	sshkey_free(ca);
	విడుదల(ca_fp);
#నిర్వచితమైతే ENABLE_PKCS11
	pkcs11_terminate();
#అయితే_ముగింపు
}

స్థిర uint64_t
parse_relative_సమయం(స్థిరరాశి అక్షరం *s, time_t now)
{
	int64_t mul, secs;

	mul = *s == '-' ? -1 : 1;

	ఒకవేళ ((secs = convtime(s + 1)) == -1)
		fatal("Invalid relative certificate time %s", s);
	ఒకవేళ (mul == -1 && secs > now)
		fatal("Certificate time %s cannot be represented", s);
	తిరిగి now + (uint64_t)(secs * mul);
}

స్థిర శూన్య
parse_hex_u64(స్థిరరాశి అక్షరం *s, uint64_t *పైకి)
{
	అక్షరం *ep;
	గుర్తులేని దీర్ఘ దీర్ఘ ull;

	errno = 0;
	ull = strtoull(s, &ep, 16);
	ఒకవేళ (*s == '\0' || *ep != '\0')
		fatal("Invalid certificate time: not a number");
	ఒకవేళ (errno == ERANGE && ull == ULONG_MAX)
		fatal_fr(SSH_ERR_SYSTEM_ERROR, "Invalid certificate time");
	*పైకి = (uint64_t)ull;
}

స్థిర శూన్య
parse_cert_times(అక్షరం *timespec)
{
	అక్షరం *from, *గమ్యం;
	time_t now = time(ఖాళీ);
	int64_t secs;

	/* +timespec relative to now */
	ఒకవేళ (*timespec == '+' && strchr(timespec, ':') == ఖాళీ) {
		ఒకవేళ ((secs = convtime(timespec + 1)) == -1)
			fatal("Invalid relative certificate life %s", timespec);
		cert_valid_గమ్యం = now + secs;
		/*
		 * Backdate certificate one minute to avoid problems on hosts
		 * with poorly-synchronised clocks.
		 */
		cert_valid_from = ((now - 59)/ 60) * 60;
		తిరిగి;
	}

	/*
	 * from:to, where
	 * from := [+-]timespec | YYYYMMDD | YYYYMMDDHHMMSS | 0x... | "always"
	 *   to := [+-]timespec | YYYYMMDD | YYYYMMDDHHMMSS | 0x... | "forever"
	 */
	from = xstrdup(timespec);
	గమ్యం = strchr(from, ':');
	ఒకవేళ (గమ్యం == ఖాళీ || from == గమ్యం || *(గమ్యం + 1) == '\0')
		fatal("Invalid certificate life specification %s", timespec);
	*గమ్యం++ = '\0';

	ఒకవేళ (*from == '-' || *from == '+')
		cert_valid_from = parse_relative_సమయం(from, now);
	లేకపోతే ఒకవేళ (strcmp(from, "always") == 0)
		cert_valid_from = 0;
	లేకపోతే ఒకవేళ (అక్షరశ్రేణి_పోలిక(from, "0x", 2) == 0)
		parse_hex_u64(from, &cert_valid_from);
	లేకపోతే ఒకవేళ (parse_absolute_సమయం(from, &cert_valid_from) != 0)
		fatal("Invalid from time \"%s\"", from);

	ఒకవేళ (*గమ్యం == '-' || *గమ్యం == '+')
		cert_valid_గమ్యం = parse_relative_సమయం(గమ్యం, now);
	లేకపోతే ఒకవేళ (strcmp(గమ్యం, "forever") == 0)
		cert_valid_గమ్యం = ~(uint64_t)0;
	లేకపోతే ఒకవేళ (అక్షరశ్రేణి_పోలిక(గమ్యం, "0x", 2) == 0)
		parse_hex_u64(గమ్యం, &cert_valid_గమ్యం);
	లేకపోతే ఒకవేళ (parse_absolute_సమయం(గమ్యం, &cert_valid_గమ్యం) != 0)
		fatal("Invalid to time \"%s\"", గమ్యం);

	ఒకవేళ (cert_valid_గమ్యం <= cert_valid_from)
		fatal("Empty certificate validity interval");
	విడుదల(from);
}

స్థిర శూన్య
కూడు_cert_option(అక్షరం *opt)
{
	అక్షరం *val, *cp;
	స్థిరరాశి అక్షరం *p;
	పూర్ణాంకం iscrit = 0;

	ఒకవేళ (strcasecmp(opt, "clear") == 0)
		certflags_flags = 0;
	లేకపోతే ఒకవేళ (strcasecmp(opt, "no-x11-forwarding") == 0)
		certflags_flags &= ~CERTOPT_X_FWD;
	లేకపోతే ఒకవేళ (strcasecmp(opt, "permit-x11-forwarding") == 0)
		certflags_flags |= CERTOPT_X_FWD;
	లేకపోతే ఒకవేళ (strcasecmp(opt, "no-agent-forwarding") == 0)
		certflags_flags &= ~CERTOPT_AGENT_FWD;
	లేకపోతే ఒకవేళ (strcasecmp(opt, "permit-agent-forwarding") == 0)
		certflags_flags |= CERTOPT_AGENT_FWD;
	లేకపోతే ఒకవేళ (strcasecmp(opt, "no-port-forwarding") == 0)
		certflags_flags &= ~CERTOPT_పోర్టు_FWD;
	లేకపోతే ఒకవేళ (strcasecmp(opt, "permit-port-forwarding") == 0)
		certflags_flags |= CERTOPT_పోర్టు_FWD;
	లేకపోతే ఒకవేళ (strcasecmp(opt, "no-pty") == 0)
		certflags_flags &= ~CERTOPT_PTY;
	లేకపోతే ఒకవేళ (strcasecmp(opt, "permit-pty") == 0)
		certflags_flags |= CERTOPT_PTY;
	లేకపోతే ఒకవేళ (strcasecmp(opt, "no-user-rc") == 0)
		certflags_flags &= ~CERTOPT_USER_RC;
	లేకపోతే ఒకవేళ (strcasecmp(opt, "permit-user-rc") == 0)
		certflags_flags |= CERTOPT_USER_RC;
	లేకపోతే ఒకవేళ (strcasecmp(opt, "touch-required") == 0)
		certflags_flags &= ~CERTOPT_NO_REQUIRE_USER_PRESENCE;
	లేకపోతే ఒకవేళ (strcasecmp(opt, "no-touch-required") == 0)
		certflags_flags |= CERTOPT_NO_REQUIRE_USER_PRESENCE;
	లేకపోతే ఒకవేళ (strcasecmp(opt, "no-verify-required") == 0)
		certflags_flags &= ~CERTOPT_REQUIRE_VERIFY;
	లేకపోతే ఒకవేళ (strcasecmp(opt, "verify-required") == 0)
		certflags_flags |= CERTOPT_REQUIRE_VERIFY;
	లేకపోతే ఒకవేళ ((p = strprefix(opt, "force-command=", 1)) != ఖాళీ) {
		ఒకవేళ (*p == '\0')
			fatal("Empty force-command option");
		ఒకవేళ (certflags_command != ఖాళీ)
			fatal("force-command already specified");
		certflags_command = xstrdup(p);
	} లేకపోతే ఒకవేళ ((p = strprefix(opt, "source-address=", 1)) != ఖాళీ) {
		ఒకవేళ (*p == '\0')
			fatal("Empty source-address option");
		ఒకవేళ (certflags_src_addr != ఖాళీ)
			fatal("source-address already specified");
		ఒకవేళ (addr_సరిపోలిక_cidr_list(ఖాళీ, p) != 0)
			fatal("Invalid source-address list");
		certflags_src_addr = xstrdup(p);
	} లేకపోతే ఒకవేళ (strprefix(opt, "extension:", 1) != ఖాళీ ||
		    (iscrit = (strprefix(opt, "critical:", 1) != ఖాళీ))) {
		val = xstrdup(strchr(opt, ':') + 1);
		ఒకవేళ ((cp = strchr(val, '=')) != ఖాళీ)
			*cp++ = '\0';
		cert_ext_కూడు(val, cp, iscrit);
		విడుదల(val);
	} లేకపోతే
		fatal("Unsupported certificate option \"%s\"", opt);
}

స్థిర శూన్య
show_options(నిర్మాణం sshbuf *optbuf, పూర్ణాంకం లోపల_critical)
{
	అక్షరం *name, *arg, *hex;
	నిర్మాణం sshbuf *options, *option = ఖాళీ;
	పూర్ణాంకం r;

	ఒకవేళ ((options = sshbuf_fromb(optbuf)) == ఖాళీ)
		fatal_f("sshbuf_fromb failed");
	అయితే (sshbuf_len(options) != 0) {
		sshbuf_free(option);
		option = ఖాళీ;
		ఒకవేళ ((r = sshbuf_get_cstring(options, &name, ఖాళీ)) != 0 ||
		    (r = sshbuf_froms(options, &option)) != 0)
			fatal_fr(r, "parse option");
		రాయి("                %s", name);
		ఒకవేళ (!లోపల_critical &&
		    (strcmp(name, "permit-X11-forwarding") == 0 ||
		    strcmp(name, "permit-agent-forwarding") == 0 ||
		    strcmp(name, "permit-port-forwarding") == 0 ||
		    strcmp(name, "permit-pty") == 0 ||
		    strcmp(name, "permit-user-rc") == 0 ||
		    strcmp(name, "no-touch-required") == 0)) {
			రాయి("\n");
		} లేకపోతే ఒకవేళ (లోపల_critical &&
		    (strcmp(name, "force-command") == 0 ||
		    strcmp(name, "source-address") == 0)) {
			ఒకవేళ ((r = sshbuf_get_cstring(option, &arg, ఖాళీ)) != 0)
				fatal_fr(r, "parse critical");
			రాయి(" %s\n", arg);
			విడుదల(arg);
		} లేకపోతే ఒకవేళ (లోపల_critical &&
		    strcmp(name, "verify-required") == 0) {
			రాయి("\n");
		} లేకపోతే ఒకవేళ (sshbuf_len(option) > 0) {
			hex = sshbuf_dtob16(option);
			రాయి(" UNKNOWN OPTION: %s (len %zu)\n",
			    hex, sshbuf_len(option));
			sshbuf_reset(option);
			విడుదల(hex);
		} లేకపోతే
			రాయి(" UNKNOWN FLAG OPTION\n");
		విడుదల(name);
		ఒకవేళ (sshbuf_len(option) != 0)
			fatal("Option corrupt: extra data at end");
	}
	sshbuf_free(option);
	sshbuf_free(options);
}

స్థిర శూన్య
print_cert(నిర్మాణం sshkey *కీలకం)
{
	అక్షరం valid[64], *కీలకం_fp, *ca_fp;
	u_int i;

	కీలకం_fp = sshkey_fingerprint(కీలకం, fingerprint_hash, SSH_FP_DEFAULT);
	ca_fp = sshkey_fingerprint(కీలకం->cert->signature_కీలకం,
	    fingerprint_hash, SSH_FP_DEFAULT);
	ఒకవేళ (కీలకం_fp == ఖాళీ || ca_fp == ఖాళీ)
		fatal_f("sshkey_fingerprint fail");
	sshkey_format_cert_validity(కీలకం->cert, valid, పరిమాణం(valid));

	రాయి("        Type: %s %s certificate\n", sshkey_ssh_name(కీలకం),
	    sshkey_cert_type(కీలకం));
	రాయి("        Public key: %s %s\n", sshkey_type(కీలకం), కీలకం_fp);
	రాయి("        Signing CA: %s %s (using %s)\n",
	    sshkey_type(కీలకం->cert->signature_కీలకం), ca_fp,
	    కీలకం->cert->signature_type);
	రాయి("        Key ID: \"%s\"\n", కీలకం->cert->కీలకం_id);
	రాయి("        Serial: %llu\n", (గుర్తులేని దీర్ఘ దీర్ఘ)కీలకం->cert->serial);
	రాయి("        Valid: %s\n", valid);
	రాయి("        Principals: ");
	ఒకవేళ (కీలకం->cert->nprincipals == 0)
		రాయి("(none)\n");
	లేకపోతే {
		కొరకు (i = 0; i < కీలకం->cert->nprincipals; i++)
			రాయి("\n                %s",
			    కీలకం->cert->principals[i]);
		రాయి("\n");
	}
	రాయి("        Critical Options: ");
	ఒకవేళ (sshbuf_len(కీలకం->cert->critical) == 0)
		రాయి("(none)\n");
	లేకపోతే {
		రాయి("\n");
		show_options(కీలకం->cert->critical, 1);
	}
	రాయి("        Extensions: ");
	ఒకవేళ (sshbuf_len(కీలకం->cert->extensions) == 0)
		రాయి("(none)\n");
	లేకపోతే {
		రాయి("\n");
		show_options(కీలకం->cert->extensions, 0);
	}
	విడుదల(కీలకం_fp);
	విడుదల(ca_fp);
}

స్థిర శూన్య
do_show_cert(నిర్మాణం passwd *pw)
{
	నిర్మాణం sshkey *కీలకం = ఖాళీ;
	నిర్మాణం stat st;
	పూర్ణాంకం r, is_stdin = 0, ok = 0;
	FILE *f;
	అక్షరం *cp, *పంక్తి = ఖాళీ;
	స్థిరరాశి అక్షరం *మార్గం;
	కొలత_t linesize = 0;
	u_long lnum = 0;

	ఒకవేళ (!have_తటస్థం)
		ask_filename(pw, "Enter file in which the key is");
	ఒకవేళ (strcmp(తటస్థం_file, "-") != 0 && stat(తటస్థం_file, &st) == -1)
		fatal("%s: %s: %s", __progname, తటస్థం_file, strerror(errno));

	మార్గం = తటస్థం_file;
	ఒకవేళ (strcmp(మార్గం, "-") == 0) {
		f = stdin;
		మార్గం = "(stdin)";
		is_stdin = 1;
	} లేకపోతే ఒకవేళ ((f = fopen(తటస్థం_file, "r")) == ఖాళీ)
		fatal("fopen %s: %s", తటస్థం_file, strerror(errno));

	అయితే (getline(&పంక్తి, &linesize, f) != -1) {
		lnum++;
		sshkey_free(కీలకం);
		కీలకం = ఖాళీ;
		/* Trim leading space and comments */
		cp = పంక్తి + strspn(పంక్తి, " \t");
		ఒకవేళ (*cp == '#' || *cp == '\0')
			కొనసాగు;
		ఒకవేళ ((కీలకం = sshkey_new(కీలకం_UNSPEC)) == ఖాళీ)
			fatal("sshkey_new");
		ఒకవేళ ((r = sshkey_read(కీలకం, &cp)) != 0) {
			error_r(r, "%s:%lu: invalid key", మార్గం, lnum);
			కొనసాగు;
		}
		ఒకవేళ (!sshkey_is_cert(కీలకం)) {
			error("%s:%lu is not a certificate", మార్గం, lnum);
			కొనసాగు;
		}
		ok = 1;
		ఒకవేళ (!is_stdin && lnum == 1)
			రాయి("%s:\n", మార్గం);
		లేకపోతే
			రాయి("%s:%lu:\n", మార్గం, lnum);
		print_cert(కీలకం);
	}
	విడుదల(పంక్తి);
	sshkey_free(కీలకం);
	fclose(f);
	నిష్క్రమించు(ok ? 0 : 1);
}

స్థిర శూన్య
ఎక్కించు_krl(స్థిరరాశి అక్షరం *మార్గం, నిర్మాణం ssh_krl **krlp)
{
	నిర్మాణం sshbuf *krlbuf;
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshbuf_ఎక్కించు_file(మార్గం, &krlbuf)) != 0)
		fatal_r(r, "Unable to load KRL %s", మార్గం);
	/* XXX check sigs */
	ఒకవేళ ((r = ssh_krl_from_blob(krlbuf, krlp)) != 0 ||
	    *krlp == ఖాళీ)
		fatal_r(r, "Invalid KRL file %s", మార్గం);
	sshbuf_free(krlbuf);
}

స్థిర శూన్య
hash_గమ్యం_blob(స్థిరరాశి అక్షరం *cp, u_char **blobp, కొలత_t *lenp,
    స్థిరరాశి అక్షరం *file, u_long lnum)
{
	అక్షరం *tmp;
	కొలత_t tlen;
	నిర్మాణం sshbuf *b;
	పూర్ణాంకం r;

	ఒకవేళ ((cp = strprefix(cp, "SHA256:", 0)) == ఖాళీ)
		fatal("%s:%lu: unsupported hash algorithm", file, lnum);

	/*
	 * OpenSSH base64 hashes omit trailing '='
	 * characters; put them back for decode.
	 */
	ఒకవేళ ((tlen = అక్షరశ్రేణి_పొడవు(cp)) >= SIZE_MAX - 5)
		fatal_f("hash too long: %zu bytes", tlen);
	tmp = xmalloc(tlen + 4 + 1);
	strlcpy(tmp, cp, tlen + 1);
	అయితే ((tlen % 4) != 0) {
		tmp[tlen++] = '=';
		tmp[tlen] = '\0';
	}
	ఒకవేళ ((b = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = sshbuf_b64tod(b, tmp)) != 0)
		fatal_r(r, "%s:%lu: decode hash failed", file, lnum);
	విడుదల(tmp);
	*lenp = sshbuf_len(b);
	*blobp = xmalloc(*lenp);
	జ్ఞాపకం_నకలు(*blobp, sshbuf_ptr(b), *lenp);
	sshbuf_free(b);
}

స్థిర శూన్య
update_krl_from_file(నిర్మాణం passwd *pw, స్థిరరాశి అక్షరం *file, పూర్ణాంకం wild_ca,
    స్థిరరాశి నిర్మాణం sshkey *ca, నిర్మాణం ssh_krl *krl)
{
	నిర్మాణం sshkey *కీలకం = ఖాళీ;
	u_long lnum = 0;
	అక్షరం *మార్గం, *cp, *ep, *పంక్తి = ఖాళీ;
	u_char *blob = ఖాళీ;
	కొలత_t blen = 0, linesize = 0;
	గుర్తులేని దీర్ఘ దీర్ఘ serial, serial2;
	పూర్ణాంకం i, was_explicit_కీలకం, was_sha1, was_sha256, was_hash, r;
	FILE *krl_spec;

	మార్గం = tilde_expand_filename(file, pw->pw_uid);
	ఒకవేళ (strcmp(మార్గం, "-") == 0) {
		krl_spec = stdin;
		విడుదల(మార్గం);
		మార్గం = xstrdup("(standard input)");
	} లేకపోతే ఒకవేళ ((krl_spec = fopen(మార్గం, "r")) == ఖాళీ)
		fatal("fopen %s: %s", మార్గం, strerror(errno));

	ఒకవేళ (!quiet)
		రాయి("Revoking from %s\n", మార్గం);
	అయితే (getline(&పంక్తి, &linesize, krl_spec) != -1) {
		ఒకవేళ (linesize >= గరిష్ఠ_పూర్ణాంకం) {
			fatal_f("%s contains unparsable line, len=%zu",
			    మార్గం, linesize);
		}
		lnum++;
		was_explicit_కీలకం = was_sha1 = was_sha256 = was_hash = 0;
		cp = పంక్తి + strspn(పంక్తి, " \t");
		/* Trim trailing space, comments and strip \n */
		కొరకు (i = 0, r = -1; cp[i] != '\0'; i++) {
			ఒకవేళ (cp[i] == '#' || cp[i] == '\n') {
				cp[i] = '\0';
				ఆపు;
			}
			ఒకవేళ (cp[i] == ' ' || cp[i] == '\t') {
				/* Remember the start of a span of whitespace */
				ఒకవేళ (r == -1)
					r = i;
			} లేకపోతే
				r = -1;
		}
		ఒకవేళ (r != -1)
			cp[r] = '\0';
		ఒకవేళ (*cp == '\0')
			కొనసాగు;
		ఒకవేళ (strncasecmp(cp, "serial:", 7) == 0) {
			ఒకవేళ (ca == ఖాళీ && !wild_ca) {
				fatal("revoking certificates by serial number "
				    "requires specification of a CA key");
			}
			cp += 7;
			cp = cp + strspn(cp, " \t");
			errno = 0;
			serial = strtoull(cp, &ep, 0);
			ఒకవేళ (*cp == '\0' || (*ep != '\0' && *ep != '-'))
				fatal("%s:%lu: invalid serial \"%s\"",
				    మార్గం, lnum, cp);
			ఒకవేళ (errno == ERANGE && serial == ULLONG_MAX)
				fatal("%s:%lu: serial out of range",
				    మార్గం, lnum);
			serial2 = serial;
			ఒకవేళ (*ep == '-') {
				cp = ep + 1;
				errno = 0;
				serial2 = strtoull(cp, &ep, 0);
				ఒకవేళ (*cp == '\0' || *ep != '\0')
					fatal("%s:%lu: invalid serial \"%s\"",
					    మార్గం, lnum, cp);
				ఒకవేళ (errno == ERANGE && serial2 == ULLONG_MAX)
					fatal("%s:%lu: serial out of range",
					    మార్గం, lnum);
				ఒకవేళ (serial2 <= serial)
					fatal("%s:%lu: invalid serial range "
					    "%llu:%llu", మార్గం, lnum,
					    (గుర్తులేని దీర్ఘ దీర్ఘ)serial,
					    (గుర్తులేని దీర్ఘ దీర్ఘ)serial2);
			}
			ఒకవేళ (ssh_krl_revoke_cert_by_serial_range(krl,
			    ca, serial, serial2) != 0) {
				fatal_f("revoke serial failed");
			}
		} లేకపోతే ఒకవేళ (strncasecmp(cp, "id:", 3) == 0) {
			ఒకవేళ (ca == ఖాళీ && !wild_ca) {
				fatal("revoking certificates by key ID "
				    "requires specification of a CA key");
			}
			cp += 3;
			cp = cp + strspn(cp, " \t");
			ఒకవేళ (ssh_krl_revoke_cert_by_కీలకం_id(krl, ca, cp) != 0)
				fatal_f("revoke key ID failed");
		} లేకపోతే ఒకవేళ (strncasecmp(cp, "hash:", 5) == 0) {
			cp += 5;
			cp = cp + strspn(cp, " \t");
			hash_గమ్యం_blob(cp, &blob, &blen, file, lnum);
			ఒకవేళ ((r = ssh_krl_revoke_కీలకం_sha256(krl,
			    blob, blen)) != 0)
				fatal_fr(r, "revoke key failed");
			విడుదల(blob);
			blob = ఖాళీ;
			blen = 0;
		} లేకపోతే {
			ఒకవేళ (strncasecmp(cp, "key:", 4) == 0) {
				cp += 4;
				cp = cp + strspn(cp, " \t");
				was_explicit_కీలకం = 1;
			} లేకపోతే ఒకవేళ (strncasecmp(cp, "sha1:", 5) == 0) {
				cp += 5;
				cp = cp + strspn(cp, " \t");
				was_sha1 = 1;
			} లేకపోతే ఒకవేళ (strncasecmp(cp, "sha256:", 7) == 0) {
				cp += 7;
				cp = cp + strspn(cp, " \t");
				was_sha256 = 1;
				/*
				 * Just try to process the line as a key.
				 * Parsing will fail if it isn't.
				 */
			}
			ఒకవేళ ((కీలకం = sshkey_new(కీలకం_UNSPEC)) == ఖాళీ)
				fatal("sshkey_new");
			ఒకవేళ ((r = sshkey_read(కీలకం, &cp)) != 0)
				fatal_r(r, "%s:%lu: invalid key", మార్గం, lnum);
			ఒకవేళ (was_explicit_కీలకం)
				r = ssh_krl_revoke_కీలకం_explicit(krl, కీలకం);
			లేకపోతే ఒకవేళ (was_sha1) {
				ఒకవేళ (sshkey_fingerprint_raw(కీలకం,
				    SSH_DIGEST_SHA1, &blob, &blen) != 0) {
					fatal("%s:%lu: fingerprint failed",
					    file, lnum);
				}
				r = ssh_krl_revoke_కీలకం_sha1(krl, blob, blen);
			} లేకపోతే ఒకవేళ (was_sha256) {
				ఒకవేళ (sshkey_fingerprint_raw(కీలకం,
				    SSH_DIGEST_SHA256, &blob, &blen) != 0) {
					fatal("%s:%lu: fingerprint failed",
					    file, lnum);
				}
				r = ssh_krl_revoke_కీలకం_sha256(krl, blob, blen);
			} లేకపోతే
				r = ssh_krl_revoke_కీలకం(krl, కీలకం);
			ఒకవేళ (r != 0)
				fatal_fr(r, "revoke key failed");
			freezero(blob, blen);
			blob = ఖాళీ;
			blen = 0;
			sshkey_free(కీలకం);
		}
	}
	ఒకవేళ (strcmp(మార్గం, "-") != 0)
		fclose(krl_spec);
	విడుదల(పంక్తి);
	విడుదల(మార్గం);
}

స్థిర శూన్య
do_gen_krl(నిర్మాణం passwd *pw, పూర్ణాంకం updating, స్థిరరాశి అక్షరం *ca_కీలకం_మార్గం,
    గుర్తులేని దీర్ఘ దీర్ఘ krl_సంస్కరణ, స్థిరరాశి అక్షరం *krl_comment,
    పూర్ణాంకం argc, అక్షరం **argv)
{
	నిర్మాణం ssh_krl *krl;
	నిర్మాణం stat sb;
	నిర్మాణం sshkey *ca = ఖాళీ;
	పూర్ణాంకం i, r, wild_ca = 0;
	అక్షరం *tmp;
	నిర్మాణం sshbuf *kbuf;

	ఒకవేళ (*తటస్థం_file == '\0')
		fatal("KRL generation requires an output file");
	ఒకవేళ (stat(తటస్థం_file, &sb) == -1) {
		ఒకవేళ (errno != ENOENT)
			fatal("Cannot access KRL \"%s\": %s",
			    తటస్థం_file, strerror(errno));
		ఒకవేళ (updating)
			fatal("KRL \"%s\" does not exist", తటస్థం_file);
	}
	ఒకవేళ (ca_కీలకం_మార్గం != ఖాళీ) {
		ఒకవేళ (strcasecmp(ca_కీలకం_మార్గం, "none") == 0)
			wild_ca = 1;
		లేకపోతే {
			tmp = tilde_expand_filename(ca_కీలకం_మార్గం, pw->pw_uid);
			ఒకవేళ ((r = sshkey_ఎక్కించు_ప్రజా(tmp, &ca, ఖాళీ)) != 0)
				fatal_r(r, "Cannot load CA public key %s", tmp);
			విడుదల(tmp);
		}
	}

	ఒకవేళ (updating)
		ఎక్కించు_krl(తటస్థం_file, &krl);
	లేకపోతే ఒకవేళ ((krl = ssh_krl_init()) == ఖాళీ)
		fatal("couldn't create KRL");

	ఒకవేళ (krl_సంస్కరణ != 0)
		ssh_krl_సమితి_సంస్కరణ(krl, krl_సంస్కరణ);
	ఒకవేళ (krl_comment != ఖాళీ)
		ssh_krl_సమితి_comment(krl, krl_comment);

	కొరకు (i = 0; i < argc; i++)
		update_krl_from_file(pw, argv[i], wild_ca, ca, krl);

	ఒకవేళ ((kbuf = sshbuf_new()) == ఖాళీ)
		fatal("sshbuf_new failed");
	ఒకవేళ (ssh_krl_గమ్యం_blob(krl, kbuf) != 0)
		fatal("Couldn't generate KRL");
	ఒకవేళ ((r = sshbuf_write_file(తటస్థం_file, kbuf)) != 0)
		fatal("write %s: %s", తటస్థం_file, strerror(errno));
	sshbuf_free(kbuf);
	ssh_krl_free(krl);
	sshkey_free(ca);
}

స్థిర శూన్య
do_check_krl(నిర్మాణం passwd *pw, పూర్ణాంకం print_krl, పూర్ణాంకం argc, అక్షరం **argv)
{
	పూర్ణాంకం i, r, ret = 0;
	అక్షరం *comment;
	నిర్మాణం ssh_krl *krl;
	నిర్మాణం sshkey *k;

	ఒకవేళ (*తటస్థం_file == '\0')
		fatal("KRL checking requires an input file");
	ఎక్కించు_krl(తటస్థం_file, &krl);
	ఒకవేళ (print_krl)
		krl_dump(krl, stdout);
	కొరకు (i = 0; i < argc; i++) {
		ఒకవేళ ((r = sshkey_ఎక్కించు_ప్రజా(argv[i], &k, &comment)) != 0)
			fatal_r(r, "Cannot load public key %s", argv[i]);
		r = ssh_krl_check_కీలకం(krl, k);
		రాయి("%s%s%s%s: %s\n", argv[i],
		    *comment ? " (" : "", comment, *comment ? ")" : "",
		    r == 0 ? "ok" : "REVOKED");
		ఒకవేళ (r != 0)
			ret = 1;
		sshkey_free(k);
		విడుదల(comment);
	}
	ssh_krl_free(krl);
	నిష్క్రమించు(ret);
}

స్థిర నిర్మాణం sshkey *
ఎక్కించు_sign_కీలకం(స్థిరరాశి అక్షరం *keypath, స్థిరరాశి నిర్మాణం sshkey *pubkey)
{
	కొలత_t i, slen, plen = అక్షరశ్రేణి_పొడవు(keypath);
	అక్షరం *privpath = xstrdup(keypath);
	స్థిర స్థిరరాశి అక్షరం * స్థిరరాశి suffixes[] = { "-cert.pub", ".pub", ఖాళీ };
	నిర్మాణం sshkey *ret = ఖాళీ, *privkey = ఖాళీ;
	పూర్ణాంకం r, waspub = 0;
	నిర్మాణం stat st;

	/*
	 * If passed a public key filename, then try to locate the corresponding
	 * private key. This lets us specify certificates on the command-line
	 * and have ssh-keygen find the appropriate private key.
	 */
	కొరకు (i = 0; suffixes[i]; i++) {
		slen = అక్షరశ్రేణి_పొడవు(suffixes[i]);
		ఒకవేళ (plen <= slen ||
		    strcmp(privpath + plen - slen, suffixes[i]) != 0)
			కొనసాగు;
		privpath[plen - slen] = '\0';
		debug_f("%s looks like a public key, using private key "
		    "path %s instead", keypath, privpath);
		waspub = 1;
	}
	ఒకవేళ (waspub && stat(privpath, &st) != 0 && errno == ENOENT)
		fatal("No private key found for public key \"%s\"", keypath);
	ఒకవేళ ((r = sshkey_ఎక్కించు_వ్యక్తిగత(privpath, "", &privkey, ఖాళీ)) != 0 &&
	    (r != SSH_ERR_కీలకం_WRONG_PASSPHRASE)) {
		debug_fr(r, "load private key \"%s\"", privpath);
		fatal("No private key found for \"%s\"", privpath);
	} లేకపోతే ఒకవేళ (privkey == ఖాళీ)
		privkey = ఎక్కించు_తటస్థం(privpath, ఖాళీ);

	ఒకవేళ (!sshkey_equal_ప్రజా(pubkey, privkey)) {
		error("Public key %s doesn't match private %s",
		    keypath, privpath);
		వెళ్ళు పూర్తి;
	}
	ఒకవేళ (sshkey_is_cert(pubkey) && !sshkey_is_cert(privkey)) {
		/*
		 * Graft the certificate onto the private key to make
		 * it capable of signing.
		 */
		ఒకవేళ ((r = sshkey_గమ్యం_certified(privkey)) != 0) {
			error_fr(r, "sshkey_to_certified");
			వెళ్ళు పూర్తి;
		}
		ఒకవేళ ((r = sshkey_cert_copy(pubkey, privkey)) != 0) {
			error_fr(r, "sshkey_cert_copy");
			వెళ్ళు పూర్తి;
		}
	}
	/* success */
	ret = privkey;
	privkey = ఖాళీ;
 పూర్తి:
	sshkey_free(privkey);
	విడుదల(privpath);
	తిరిగి ret;
}

స్థిర పూర్ణాంకం
sign_one(నిర్మాణం sshkey *signkey, స్థిరరాశి అక్షరం *filename, పూర్ణాంకం fd,
    స్థిరరాశి అక్షరం *sig_namespace, స్థిరరాశి అక్షరం *hashalg, sshsig_signer *signer,
    శూన్య *signer_ctx)
{
	నిర్మాణం sshbuf *sigbuf = ఖాళీ, *abuf = ఖాళీ;
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR, wfd = -1, oerrno;
	అక్షరం *wfile = ఖాళీ, *asig = ఖాళీ, *fp = ఖాళీ;
	అక్షరం *pin = ఖాళీ, *prompt = ఖాళీ;

	ఒకవేళ (!quiet) {
		ఒకవేళ (fd == STDIN_FILENO)
			fprintf(stderr, "Signing data on standard input\n");
		లేకపోతే
			fprintf(stderr, "Signing file %s\n", filename);
	}
	ఒకవేళ (signer == ఖాళీ && sshkey_is_sk(signkey)) {
		ఒకవేళ ((signkey->sk_flags & SSH_SK_USER_VERIFICATION_REQD)) {
			xasprintf(&prompt, "Enter PIN for %s key: ",
			    sshkey_type(signkey));
			ఒకవేళ ((pin = read_passphrase(prompt,
			    RP_ALLOW_STDIN)) == ఖాళీ)
				fatal_f("couldn't read PIN");
		}
		ఒకవేళ ((signkey->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
			ఒకవేళ ((fp = sshkey_fingerprint(signkey, fingerprint_hash,
			    SSH_FP_DEFAULT)) == ఖాళీ)
				fatal_f("fingerprint failed");
			fprintf(stderr, "Confirm user presence for key %s %s\n",
			    sshkey_type(signkey), fp);
			విడుదల(fp);
		}
	}
	ఒకవేళ ((r = sshsig_sign_fd(signkey, hashalg, sk_provider, pin,
	    fd, sig_namespace, &sigbuf, signer, signer_ctx)) != 0) {
		error_r(r, "Signing %s failed", filename);
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshsig_armor(sigbuf, &abuf)) != 0) {
		error_fr(r, "sshsig_armor");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((asig = sshbuf_dup_string(abuf)) == ఖాళీ) {
		error_f("buffer error");
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ (fd == STDIN_FILENO) {
		fputs(asig, stdout);
		fflush(stdout);
	} లేకపోతే {
		xasprintf(&wfile, "%s.sig", filename);
		ఒకవేళ (confirm_overwrite(wfile)) {
			ఒకవేళ ((wfd = open(wfile, O_WRONLY|O_CREAT|O_TRUNC,
			    0666)) == -1) {
				oerrno = errno;
				error("Cannot open %s: %s",
				    wfile, strerror(errno));
				errno = oerrno;
				r = SSH_ERR_SYSTEM_ERROR;
				వెళ్ళు బహిర్గతం;
			}
			ఒకవేళ (atomicio(vwrite, wfd, asig,
			    అక్షరశ్రేణి_పొడవు(asig)) != అక్షరశ్రేణి_పొడవు(asig)) {
				oerrno = errno;
				error("Cannot write to %s: %s",
				    wfile, strerror(errno));
				errno = oerrno;
				r = SSH_ERR_SYSTEM_ERROR;
				వెళ్ళు బహిర్గతం;
			}
			ఒకవేళ (!quiet) {
				fprintf(stderr, "Write signature to %s\n",
				    wfile);
			}
		}
	}
	/* success */
	r = 0;
 బహిర్గతం:
	విడుదల(wfile);
	విడుదల(prompt);
	విడుదల(asig);
	ఒకవేళ (pin != ఖాళీ)
		freezero(pin, అక్షరశ్రేణి_పొడవు(pin));
	sshbuf_free(abuf);
	sshbuf_free(sigbuf);
	ఒకవేళ (wfd != -1)
		close(wfd);
	తిరిగి r;
}

స్థిర పూర్ణాంకం
sig_process_opts(అక్షరం * స్థిరరాశి *opts, కొలత_t nopts, అక్షరం **hashalgp,
    uint64_t *verify_timep, పూర్ణాంకం *print_pubkey)
{
	కొలత_t i;
	time_t now;
	స్థిరరాశి అక్షరం *p;

	ఒకవేళ (verify_timep != ఖాళీ)
		*verify_timep = 0;
	ఒకవేళ (print_pubkey != ఖాళీ)
		*print_pubkey = 0;
	ఒకవేళ (hashalgp != ఖాళీ)
		*hashalgp = ఖాళీ;
	కొరకు (i = 0; i < nopts; i++) {
		ఒకవేళ (hashalgp != ఖాళీ &&
		    (p = strprefix(opts[i], "hashalg=", 1)) != ఖాళీ) {
			*hashalgp = xstrdup(p);
		} లేకపోతే ఒకవేళ (verify_timep &&
		    (p = strprefix(opts[i], "verify-time=", 1)) != ఖాళీ) {
			ఒకవేళ (parse_absolute_సమయం(p, verify_timep) != 0 ||
			    *verify_timep == 0) {
				error("Invalid \"verify-time\" option");
				తిరిగి SSH_ERR_INVALID_వాదం;
			}
		} లేకపోతే ఒకవేళ (print_pubkey &&
		    strcasecmp(opts[i], "print-pubkey") == 0) {
			*print_pubkey = 1;
		} లేకపోతే {
			error("Invalid option \"%s\"", opts[i]);
			తిరిగి SSH_ERR_INVALID_వాదం;
		}
	}
	ఒకవేళ (verify_timep && *verify_timep == 0) {
		ఒకవేళ ((now = time(ఖాళీ)) < 0) {
			error("Time is before epoch");
			తిరిగి SSH_ERR_INVALID_వాదం;
		}
		*verify_timep = (uint64_t)now;
	}
	తిరిగి 0;
}


స్థిర పూర్ణాంకం
sig_sign(స్థిరరాశి అక్షరం *keypath, స్థిరరాశి అక్షరం *sig_namespace, పూర్ణాంకం require_agent,
    పూర్ణాంకం argc, అక్షరం **argv, అక్షరం * స్థిరరాశి *opts, కొలత_t nopts)
{
	పూర్ణాంకం i, fd = -1, r, ret = -1;
	పూర్ణాంకం agent_fd = -1;
	నిర్మాణం sshkey *pubkey = ఖాళీ, *privkey = ఖాళీ, *signkey = ఖాళీ;
	sshsig_signer *signer = ఖాళీ;
	అక్షరం *hashalg = ఖాళీ;

	/* Check file arguments. */
	కొరకు (i = 0; i < argc; i++) {
		ఒకవేళ (strcmp(argv[i], "-") != 0)
			కొనసాగు;
		ఒకవేళ (i > 0 || argc > 1)
			fatal("Cannot sign mix of paths and standard input");
	}

	ఒకవేళ (sig_process_opts(opts, nopts, &hashalg, ఖాళీ, ఖాళీ) != 0)
		వెళ్ళు పూర్తి; /* error already logged */

	ఒకవేళ ((r = sshkey_ఎక్కించు_ప్రజా(keypath, &pubkey, ఖాళీ)) != 0) {
		error_r(r, "Couldn't load public key %s", keypath);
		వెళ్ళు పూర్తి;
	}

	ఒకవేళ ((r = ssh_get_authentication_socket(&agent_fd)) != 0) {
		ఒకవేళ (require_agent)
			fatal("Couldn't get agent socket");
		debug_r(r, "Couldn't get agent socket");
	} లేకపోతే {
		ఒకవేళ ((r = ssh_agent_has_కీలకం(agent_fd, pubkey)) == 0)
			signer = agent_signer;
		లేకపోతే {
			ఒకవేళ (require_agent)
				fatal("Couldn't find key in agent");
			debug_r(r, "Couldn't find key in agent");
		}
	}

	ఒకవేళ (signer == ఖాళీ) {
		/* Not using agent - try to load private key */
		ఒకవేళ ((privkey = ఎక్కించు_sign_కీలకం(keypath, pubkey)) == ఖాళీ)
			వెళ్ళు పూర్తి;
		signkey = privkey;
	} లేకపోతే {
		/* Will use key in agent */
		signkey = pubkey;
	}

	ఒకవేళ (argc == 0) {
		ఒకవేళ ((r = sign_one(signkey, "(stdin)", STDIN_FILENO,
		    sig_namespace, hashalg, signer, &agent_fd)) != 0)
			వెళ్ళు పూర్తి;
	} లేకపోతే {
		కొరకు (i = 0; i < argc; i++) {
			ఒకవేళ (strcmp(argv[i], "-") == 0)
				fd = STDIN_FILENO;
			లేకపోతే ఒకవేళ ((fd = open(argv[i], O_RDONLY)) == -1) {
				error("Cannot open %s for signing: %s",
				    argv[i], strerror(errno));
				వెళ్ళు పూర్తి;
			}
			ఒకవేళ ((r = sign_one(signkey, argv[i], fd, sig_namespace,
			    hashalg, signer, &agent_fd)) != 0)
				వెళ్ళు పూర్తి;
			ఒకవేళ (fd != STDIN_FILENO)
				close(fd);
			fd = -1;
		}
	}

	ret = 0;
పూర్తి:
	ఒకవేళ (fd != -1 && fd != STDIN_FILENO)
		close(fd);
	sshkey_free(pubkey);
	sshkey_free(privkey);
	విడుదల(hashalg);
	తిరిగి ret;
}

స్థిర పూర్ణాంకం
sig_verify(స్థిరరాశి అక్షరం *signature, స్థిరరాశి అక్షరం *sig_namespace,
    స్థిరరాశి అక్షరం *principal, స్థిరరాశి అక్షరం *allowed_కీలకాలు, స్థిరరాశి అక్షరం *revoked_కీలకాలు,
    అక్షరం * స్థిరరాశి *opts, కొలత_t nopts)
{
	పూర్ణాంకం r, ret = -1;
	పూర్ణాంకం print_pubkey = 0;
	నిర్మాణం sshbuf *sigbuf = ఖాళీ, *abuf = ఖాళీ;
	నిర్మాణం sshkey *sign_కీలకం = ఖాళీ;
	అక్షరం *fp = ఖాళీ;
	నిర్మాణం sshkey_sig_details *sig_details = ఖాళీ;
	uint64_t verify_సమయం = 0;

	ఒకవేళ (sig_process_opts(opts, nopts, ఖాళీ, &verify_సమయం,
	    &print_pubkey) != 0)
		వెళ్ళు పూర్తి; /* error already logged */

	memset(&sig_details, 0, పరిమాణం(sig_details));
	ఒకవేళ ((r = sshbuf_ఎక్కించు_file(signature, &abuf)) != 0) {
		error_r(r, "Couldn't read signature file");
		వెళ్ళు పూర్తి;
	}

	ఒకవేళ ((r = sshsig_dearmor(abuf, &sigbuf)) != 0) {
		error_fr(r, "sshsig_armor");
		వెళ్ళు పూర్తి;
	}
	ఒకవేళ ((r = sshsig_verify_fd(sigbuf, STDIN_FILENO, sig_namespace,
	    &sign_కీలకం, &sig_details)) != 0)
		వెళ్ళు పూర్తి; /* sshsig_verify() prints error */

	ఒకవేళ ((fp = sshkey_fingerprint(sign_కీలకం, fingerprint_hash,
	    SSH_FP_DEFAULT)) == ఖాళీ)
		fatal_f("sshkey_fingerprint failed");
	debug("Valid (unverified) signature from key %s", fp);
	ఒకవేళ (sig_details != ఖాళీ) {
		debug2_f("signature details: counter = %u, flags = 0x%02x",
		    sig_details->sk_counter, sig_details->sk_flags);
	}
	విడుదల(fp);
	fp = ఖాళీ;

	ఒకవేళ (revoked_కీలకాలు != ఖాళీ) {
		ఒకవేళ ((r = sshkey_check_revoked(sign_కీలకం, revoked_కీలకాలు)) != 0) {
			debug3_fr(r, "sshkey_check_revoked");
			వెళ్ళు పూర్తి;
		}
	}

	ఒకవేళ (allowed_కీలకాలు != ఖాళీ && (r = sshsig_check_allowed_కీలకాలు(allowed_కీలకాలు,
	    sign_కీలకం, principal, sig_namespace, verify_సమయం)) != 0) {
		debug3_fr(r, "sshsig_check_allowed_keys");
		వెళ్ళు పూర్తి;
	}
	/* success */
	ret = 0;
పూర్తి:
	ఒకవేళ (!quiet) {
		ఒకవేళ (ret == 0) {
			ఒకవేళ ((fp = sshkey_fingerprint(sign_కీలకం, fingerprint_hash,
			    SSH_FP_DEFAULT)) == ఖాళీ)
				fatal_f("sshkey_fingerprint failed");
			ఒకవేళ (principal == ఖాళీ) {
				రాయి("Good \"%s\" signature with %s key %s\n",
				    sig_namespace, sshkey_type(sign_కీలకం), fp);

			} లేకపోతే {
				రాయి("Good \"%s\" signature for %s with %s key %s\n",
				    sig_namespace, principal,
				    sshkey_type(sign_కీలకం), fp);
			}
		} లేకపోతే {
			రాయి("Could not verify signature.\n");
		}
	}
	/* Print the signature key if requested */
	ఒకవేళ (ret == 0 && print_pubkey && sign_కీలకం != ఖాళీ) {
		ఒకవేళ ((r = sshkey_write(sign_కీలకం, stdout)) == 0)
			fputc('\n', stdout);
		లేకపోతే {
			error_r(r, "Could not print public key.\n");
			ret = -1;
		}
	}
	sshbuf_free(sigbuf);
	sshbuf_free(abuf);
	sshkey_free(sign_కీలకం);
	sshkey_sig_details_free(sig_details);
	విడుదల(fp);
	తిరిగి ret;
}

స్థిర పూర్ణాంకం
sig_కనుగొను_principals(స్థిరరాశి అక్షరం *signature, స్థిరరాశి అక్షరం *allowed_కీలకాలు,
    అక్షరం * స్థిరరాశి *opts, కొలత_t nopts)
{
	పూర్ణాంకం r, ret = -1;
	నిర్మాణం sshbuf *sigbuf = ఖాళీ, *abuf = ఖాళీ;
	నిర్మాణం sshkey *sign_కీలకం = ఖాళీ;
	అక్షరం *principals = ఖాళీ, *cp, *tmp;
	uint64_t verify_సమయం = 0;

	ఒకవేళ (sig_process_opts(opts, nopts, ఖాళీ, &verify_సమయం, ఖాళీ) != 0)
		వెళ్ళు పూర్తి; /* error already logged */

	ఒకవేళ ((r = sshbuf_ఎక్కించు_file(signature, &abuf)) != 0) {
		error_r(r, "Couldn't read signature file");
		వెళ్ళు పూర్తి;
	}
	ఒకవేళ ((r = sshsig_dearmor(abuf, &sigbuf)) != 0) {
		error_fr(r, "sshsig_armor");
		వెళ్ళు పూర్తి;
	}
	ఒకవేళ ((r = sshsig_get_pubkey(sigbuf, &sign_కీలకం)) != 0) {
		error_fr(r, "sshsig_get_pubkey");
		వెళ్ళు పూర్తి;
	}
	ఒకవేళ ((r = sshsig_కనుగొను_principals(allowed_కీలకాలు, sign_కీలకం,
	    verify_సమయం, &principals)) != 0) {
		ఒకవేళ (r != SSH_ERR_కీలకం_NOT_దొరికింది)
			error_fr(r, "sshsig_find_principal");
		వెళ్ళు పూర్తి;
	}
	ret = 0;
పూర్తి:
	ఒకవేళ (ret == 0 ) {
		/* Emit matching principals one per line */
		tmp = principals;
		అయితే ((cp = strsep(&tmp, ",")) != ఖాళీ && *cp != '\0')
			puts(cp);
	} లేకపోతే {
		fprintf(stderr, "No principal matched.\n");
	}
	sshbuf_free(sigbuf);
	sshbuf_free(abuf);
	sshkey_free(sign_కీలకం);
	విడుదల(principals);
	తిరిగి ret;
}

స్థిర పూర్ణాంకం
sig_సరిపోలిక_principals(స్థిరరాశి అక్షరం *allowed_కీలకాలు, అక్షరం *principal,
	అక్షరం * స్థిరరాశి *opts, కొలత_t nopts)
{
	పూర్ణాంకం r;
	అక్షరం **principals = ఖాళీ;
	కొలత_t i, nprincipals = 0;

	ఒకవేళ ((r = sig_process_opts(opts, nopts, ఖాళీ, ఖాళీ, ఖాళీ)) != 0)
		తిరిగి r; /* error already logged */

	ఒకవేళ ((r = sshsig_సరిపోలిక_principals(allowed_కీలకాలు, principal,
	    &principals, &nprincipals)) != 0) {
		debug_f("match: %s", ssh_err(r));
		fprintf(stderr, "No principal matched.\n");
		తిరిగి r;
	}
	కొరకు (i = 0; i < nprincipals; i++) {
		రాయి("%s\n", principals[i]);
		విడుదల(principals[i]);
	}
	విడుదల(principals);

	తిరిగి 0;
}

స్థిర శూన్య
do_moduli_gen(స్థిరరాశి అక్షరం *బహిర్గతం_file, అక్షరం **opts, కొలత_t nopts)
{
#నిర్వచితమైతే WITH_OPENSSL
	/* Moduli generation/screening */
	BIGNUM *ప్రారంభం = ఖాళీ;
	పూర్ణాంకం moduli_బిట్లు = 0;
	FILE *బహిర్గతం;
	కొలత_t i;
	స్థిరరాశి అక్షరం *errstr, *p;

	/* Parse options */
	కొరకు (i = 0; i < nopts; i++) {
		ఒకవేళ ((p = strprefix(opts[i], "start=", 0)) != ఖాళీ) {
			/* XXX - also compare length against bits */
			ఒకవేళ (BN_hex2bn(&ప్రారంభం, p) == 0)
				fatal("Invalid start point.");
		} లేకపోతే ఒకవేళ ((p = strprefix(opts[i], "bits=", 0)) != ఖాళీ) {
			moduli_బిట్లు = (పూర్ణాంకం)strtonum(p, 1, గరిష్ఠ_పూర్ణాంకం, &errstr);
			ఒకవేళ (errstr) {
				fatal("Invalid number: %s (%s)", p, errstr);
			}
		} లేకపోతే {
			fatal("Option \"%s\" is unsupported for moduli "
			    "generation", opts[i]);
		}
	}

	ఒకవేళ (strcmp(బహిర్గతం_file, "-") == 0)
		బహిర్గతం = stdout;
	లేకపోతే ఒకవేళ ((బహిర్గతం = fopen(బహిర్గతం_file, "w")) == ఖాళీ) {
		fatal("Couldn't open modulus candidate file \"%s\": %s",
		    బహిర్గతం_file, strerror(errno));
	}
	setvbuf(బహిర్గతం, ఖాళీ, _IOLBF, 0);

	ఒకవేళ (moduli_బిట్లు == 0)
		moduli_బిట్లు = DEFAULT_బిట్లు;
	ఒకవేళ (gen_candidates(బహిర్గతం, moduli_బిట్లు, ప్రారంభం) != 0)
		fatal("modulus candidate generation failed");
#లేకపోతే /* WITH_OPENSSL */
	fatal("Moduli generation is not supported");
#అయితే_ముగింపు /* WITH_OPENSSL */
}

స్థిర శూన్య
do_moduli_screen(స్థిరరాశి అక్షరం *బహిర్గతం_file, అక్షరం **opts, కొలత_t nopts)
{
#నిర్వచితమైతే WITH_OPENSSL
	/* Moduli generation/screening */
	అక్షరం *checkpoint = ఖాళీ;
	uint32_t generator_wanted = 0;
	గుర్తులేని దీర్ఘ ప్రారంభం_lineno = 0, పంక్తులు_గమ్యం_process = 0;
	పూర్ణాంకం ప్రధానసంఖ్య_tests = 0;
	FILE *బహిర్గతం, *లోపల = stdin;
	కొలత_t i;
	స్థిరరాశి అక్షరం *errstr, *p;

	/* Parse options */
	కొరకు (i = 0; i < nopts; i++) {
		ఒకవేళ ((p = strprefix(opts[i], "lines=", 0)) != ఖాళీ) {
			పంక్తులు_గమ్యం_process = strtoul(p, ఖాళీ, 10);
		} లేకపోతే ఒకవేళ ((p = strprefix(opts[i], "start-line=", 0)) != ఖాళీ) {
			ప్రారంభం_lineno = strtoul(p, ఖాళీ, 10);
		} లేకపోతే ఒకవేళ ((p = strprefix(opts[i], "checkpoint=", 0)) != ఖాళీ) {
			విడుదల(checkpoint);
			checkpoint = xstrdup(p);
		} లేకపోతే ఒకవేళ ((p = strprefix(opts[i], "generator=", 0)) != ఖాళీ) {
			generator_wanted = (uint32_t)strtonum(p, 1, UINT_MAX,
			    &errstr);
			ఒకవేళ (errstr != ఖాళీ) {
				fatal("Generator invalid: %s (%s)", p, errstr);
			}
		} లేకపోతే ఒకవేళ ((p = strprefix(opts[i], "prime-tests=", 0)) != ఖాళీ) {
			ప్రధానసంఖ్య_tests = (పూర్ణాంకం)strtonum(p, 1, గరిష్ఠ_పూర్ణాంకం, &errstr);
			ఒకవేళ (errstr) {
				fatal("Invalid number: %s (%s)", p, errstr);
			}
		} లేకపోతే {
			fatal("Option \"%s\" is unsupported for moduli "
			    "screening", opts[i]);
		}
	}

	ఒకవేళ (have_తటస్థం && strcmp(తటస్థం_file, "-") != 0) {
		ఒకవేళ ((లోపల = fopen(తటస్థం_file, "r")) == ఖాళీ) {
			fatal("Couldn't open modulus candidate "
			    "file \"%s\": %s", తటస్థం_file,
			    strerror(errno));
		}
	}

	ఒకవేళ (strcmp(బహిర్గతం_file, "-") == 0)
		బహిర్గతం = stdout;
	లేకపోతే ఒకవేళ ((బహిర్గతం = fopen(బహిర్గతం_file, "a")) == ఖాళీ) {
		fatal("Couldn't open moduli file \"%s\": %s",
		    బహిర్గతం_file, strerror(errno));
	}
	setvbuf(బహిర్గతం, ఖాళీ, _IOLBF, 0);
	ఒకవేళ (ప్రధానసంఖ్య_test(లోపల, బహిర్గతం, ప్రధానసంఖ్య_tests == 0 ? 100 : ప్రధానసంఖ్య_tests,
	    generator_wanted, checkpoint,
	    ప్రారంభం_lineno, పంక్తులు_గమ్యం_process) != 0)
		fatal("modulus screening failed");
	ఒకవేళ (లోపల != stdin)
		(శూన్య)fclose(లోపల);
	విడుదల(checkpoint);
#లేకపోతే /* WITH_OPENSSL */
	fatal("Moduli screening is not supported");
#అయితే_ముగింపు /* WITH_OPENSSL */
}

/* Read and confirm a passphrase */
స్థిర అక్షరం *
read_check_passphrase(స్థిరరాశి అక్షరం *prompt1, స్థిరరాశి అక్షరం *prompt2,
    స్థిరరాశి అక్షరం *retry_prompt)
{
	అక్షరం *passphrase1, *passphrase2;

	కొరకు (;;) {
		passphrase1 = read_passphrase(prompt1, RP_ALLOW_STDIN);
		passphrase2 = read_passphrase(prompt2, RP_ALLOW_STDIN);
		ఒకవేళ (strcmp(passphrase1, passphrase2) == 0) {
			freezero(passphrase2, అక్షరశ్రేణి_పొడవు(passphrase2));
			తిరిగి passphrase1;
		}
		/* The passphrases do not match. Clear them and retry. */
		freezero(passphrase1, అక్షరశ్రేణి_పొడవు(passphrase1));
		freezero(passphrase2, అక్షరశ్రేణి_పొడవు(passphrase2));
		fputs(retry_prompt, stdout);
		fputc('\n', stdout);
		fflush(stdout);
	}
	/* NOTREACHED */
	తిరిగి ఖాళీ;
}

స్థిర అక్షరం *
వ్యక్తిగత_కీలకం_passphrase(స్థిరరాశి అక్షరం *మార్గం)
{
	అక్షరం *prompt, *ret;

	ఒకవేళ (తటస్థం_passphrase)
		తిరిగి xstrdup(తటస్థం_passphrase);
	ఒకవేళ (తటస్థం_new_passphrase)
		తిరిగి xstrdup(తటస్థం_new_passphrase);

	xasprintf(&prompt, "Enter passphrase for \"%s\" "
	    "(empty for no passphrase): ", మార్గం);
	ret = read_check_passphrase(prompt,
	    "Enter same passphrase again: ",
	    "Passphrases do not match.  Try again.");
	విడుదల(prompt);
	తిరిగి ret;
}

స్థిర అక్షరం *
sk_suffix(స్థిరరాశి అక్షరం *application, స్థిరరాశి uint8_t *user, కొలత_t userlen)
{
	అక్షరం *ret, *cp;
	స్థిరరాశి అక్షరం *p;
	కొలత_t slen, i;

	/* Trim off URL-like preamble */
	ఒకవేళ ((p = strprefix(application, "ssh://", 0)) != ఖాళీ)
		ret =  xstrdup(p);
	లేకపోతే ఒకవేళ ((p = strprefix(application, "ssh:", 0)) != ఖాళీ)
		ret =  xstrdup(p);
	లేకపోతే
		ret = xstrdup(application);

	/* Count trailing zeros in user */
	కొరకు (i = 0; i < userlen; i++) {
		ఒకవేళ (user[userlen - i - 1] != 0)
			ఆపు;
	}
	ఒకవేళ (i >= userlen)
		తిరిగి ret; /* user-id was default all-zeros */

	/* Append user-id, escaping non-UTF-8 characters */
	slen = userlen - i;
	ఒకవేళ (asmprintf(&cp, గరిష్ఠ_పూర్ణాంకం, ఖాళీ, "%.*s", (పూర్ణాంకం)slen, user) == -1)
		fatal_f("asmprintf failed");
	/* Don't emit a user-id that contains path or control characters */
	ఒకవేళ (strchr(cp, '/') != ఖాళీ || అక్షరశ్రేణి_శోధన(cp, "..") != ఖాళీ ||
	    strchr(cp, '\\') != ఖాళీ) {
		విడుదల(cp);
		cp = tohex(user, slen);
	}
	xextendf(&ret, "_", "%s", cp);
	విడుదల(cp);
	తిరిగి ret;
}

స్థిర పూర్ణాంకం
do_download_sk(స్థిరరాశి అక్షరం *skprovider, స్థిరరాశి అక్షరం *device)
{
	నిర్మాణం sshsk_resident_కీలకం **srks;
	కొలత_t nsrks, i;
	పూర్ణాంకం r, ret = -1;
	అక్షరం *fp, *pin = ఖాళీ, *pass = ఖాళీ, *మార్గం, *pubpath;
	స్థిరరాశి అక్షరం *ext;
	నిర్మాణం sshkey *కీలకం;

	ఒకవేళ (skprovider == ఖాళీ)
		fatal("Cannot download keys without provider");

	pin = read_passphrase("Enter PIN for authenticator: ", RP_ALLOW_STDIN);
	ఒకవేళ (!quiet) {
		రాయి("You may need to touch your authenticator "
		    "to authorize key download.\n");
	}
	ఒకవేళ ((r = sshsk_ఎక్కించు_resident(skprovider, device, pin, 0,
	    &srks, &nsrks)) != 0) {
		ఒకవేళ (pin != ఖాళీ)
			freezero(pin, అక్షరశ్రేణి_పొడవు(pin));
		error_r(r, "Unable to load resident keys");
		తిరిగి -1;
	}
	ఒకవేళ (nsrks == 0)
		logit("No keys to download");
	ఒకవేళ (pin != ఖాళీ)
		freezero(pin, అక్షరశ్రేణి_పొడవు(pin));

	కొరకు (i = 0; i < nsrks; i++) {
		కీలకం = srks[i]->కీలకం;
		ఒకవేళ (కీలకం->type != కీలకం_ECDSA_SK && కీలకం->type != కీలకం_ED25519_SK) {
			error("Unsupported key type %s (%d)",
			    sshkey_type(కీలకం), కీలకం->type);
			కొనసాగు;
		}
		ఒకవేళ ((fp = sshkey_fingerprint(కీలకం, fingerprint_hash,
		    SSH_FP_DEFAULT)) == ఖాళీ)
			fatal_f("sshkey_fingerprint failed");
		debug_f("key %zu: %s %s %s (flags 0x%02x)", i,
		    sshkey_type(కీలకం), fp, కీలకం->sk_application, కీలకం->sk_flags);
		ext = sk_suffix(కీలకం->sk_application,
		    srks[i]->user_id, srks[i]->user_id_len);
		xasprintf(&మార్గం, "id_%s_rk%s%s",
		    కీలకం->type == కీలకం_ECDSA_SK ? "ecdsa_sk" : "ed25519_sk",
		    *ext == '\0' ? "" : "_", ext);

		/* If the file already exists, ask the user to confirm. */
		ఒకవేళ (!confirm_overwrite(మార్గం)) {
			విడుదల(మార్గం);
			ఆపు;
		}

		/* Save the key with the application string as the comment */
		ఒకవేళ (pass == ఖాళీ)
			pass = వ్యక్తిగత_కీలకం_passphrase(మార్గం);
		ఒకవేళ ((r = sshkey_save_వ్యక్తిగత(కీలకం, మార్గం, pass,
		    కీలకం->sk_application, వ్యక్తిగత_కీలకం_format,
		    openssh_format_cipher, విడతలు)) != 0) {
			error_r(r, "Saving key \"%s\" failed", మార్గం);
			విడుదల(మార్గం);
			ఆపు;
		}
		ఒకవేళ (!quiet) {
			రాయి("Saved %s key%s%s to %s\n", sshkey_type(కీలకం),
			    *ext != '\0' ? " " : "",
			    *ext != '\0' ? కీలకం->sk_application : "",
			    మార్గం);
		}

		/* Save public key too */
		xasprintf(&pubpath, "%s.pub", మార్గం);
		విడుదల(మార్గం);
		ఒకవేళ ((r = sshkey_save_ప్రజా(కీలకం, pubpath,
		    కీలకం->sk_application)) != 0) {
			error_r(r, "Saving public key \"%s\" failed", pubpath);
			విడుదల(pubpath);
			ఆపు;
		}
		విడుదల(pubpath);
	}

	ఒకవేళ (i >= nsrks)
		ret = 0; /* success */
	ఒకవేళ (pass != ఖాళీ)
		freezero(pass, అక్షరశ్రేణి_పొడవు(pass));
	sshsk_free_resident_కీలకాలు(srks, nsrks);
	తిరిగి ret;
}

స్థిర శూన్య
save_attestation(నిర్మాణం sshbuf *attest, స్థిరరాశి అక్షరం *మార్గం)
{
	బహుళకం_t omask;
	పూర్ణాంకం r;

	ఒకవేళ (మార్గం == ఖాళీ)
		తిరిగి; /* nothing to do */
	ఒకవేళ (attest == ఖాళీ || sshbuf_len(attest) == 0)
		fatal("Enrollment did not return attestation data");
	omask = umask(077);
	r = sshbuf_write_file(మార్గం, attest);
	umask(omask);
	ఒకవేళ (r != 0)
		fatal_r(r, "Unable to write attestation data \"%s\"", మార్గం);
	ఒకవేళ (!quiet)
		రాయి("Your FIDO attestation certificate has been saved in "
		    "%s\n", మార్గం);
}

స్థిర పూర్ణాంకం
confirm_sk_overwrite(స్థిరరాశి అక్షరం *application, స్థిరరాశి అక్షరం *user)
{
	అక్షరం yesno[3];

	రాయి("A resident key scoped to '%s' with user id '%s' already "
	    "exists.\n", application == ఖాళీ ? "ssh:" : application,
	    user == ఖాళీ ? "null" : user);
	రాయి("Overwrite key in token (y/n)? ");
	fflush(stdout);
	ఒకవేళ (fgets(yesno, పరిమాణం(yesno), stdin) == ఖాళీ)
		తిరిగి 0;
	ఒకవేళ (yesno[0] != 'y' && yesno[0] != 'Y')
		తిరిగి 0;
	తిరిగి 1;
}

స్థిర శూన్య
usage(శూన్య)
{
	fprintf(stderr,
	    "usage: ssh-keygen [-q] [-a rounds] [-b bits] [-C comment] [-f output_keyfile]\n"
	    "                  [-m format] [-N new_passphrase] [-O option]\n"
	    "                  [-t ecdsa|ecdsa-sk|ed25519|ed25519-sk|mldsa44-ed25519|rsa]\n"
	    "                  [-w provider] [-Z cipher]\n"
	    "       ssh-keygen -p [-a rounds] [-f keyfile] [-m format] [-N new_passphrase]\n"
	    "                   [-P old_passphrase] [-Z cipher]\n"
#నిర్వచితమైతే WITH_OPENSSL
	    "       ssh-keygen -i [-f input_keyfile] [-m key_format]\n"
	    "       ssh-keygen -e [-f input_keyfile] [-m key_format]\n"
#అయితే_ముగింపు
	    "       ssh-keygen -y [-f input_keyfile]\n"
	    "       ssh-keygen -c [-a rounds] [-C comment] [-f keyfile] [-P passphrase]\n"
	    "       ssh-keygen -l [-v] [-E fingerprint_hash] [-f input_keyfile]\n"
	    "       ssh-keygen -B [-f input_keyfile]\n");
#నిర్వచితమైతే ENABLE_PKCS11
	fprintf(stderr,
	    "       ssh-keygen -D pkcs11\n");
#అయితే_ముగింపు
	fprintf(stderr,
	    "       ssh-keygen -F hostname [-lv] [-f known_hosts_file]\n"
	    "       ssh-keygen -H [-f known_hosts_file]\n"
	    "       ssh-keygen -K [-a rounds] [-w provider]\n"
	    "       ssh-keygen -R hostname [-f known_hosts_file]\n"
	    "       ssh-keygen -r hostname [-g] [-f input_keyfile]\n"
#నిర్వచితమైతే WITH_OPENSSL
	    "       ssh-keygen -M generate [-O option] output_file\n"
	    "       ssh-keygen -M screen [-f input_file] [-O option] output_file\n"
#అయితే_ముగింపు
	    "       ssh-keygen -I certificate_identity -s ca_key [-hU] [-D pkcs11_provider]\n"
	    "                  [-n principals] [-O option] [-V validity_interval]\n"
	    "                  [-z serial_number] file ...\n"
	    "       ssh-keygen -L [-f input_keyfile]\n"
	    "       ssh-keygen -A [-a rounds] [-f prefix_path]\n"
	    "       ssh-keygen -k -f krl_file [-u] [-s ca_public] [-z version_number]\n"
	    "                  file ...\n"
	    "       ssh-keygen -Q [-l] -f krl_file [file ...]\n"
	    "       ssh-keygen -Y find-principals -s signature_file -f allowed_signers_file\n"
	    "       ssh-keygen -Y match-principals -I signer_identity -f allowed_signers_file\n"
	    "       ssh-keygen -Y check-novalidate -n namespace -s signature_file\n"
	    "       ssh-keygen -Y sign -f key_file -n namespace file [-O option] ...\n"
	    "       ssh-keygen -Y verify -f allowed_signers_file -I signer_identity\n"
	    "                  -n namespace -s signature_file [-r krl_file] [-O option]\n");
	నిష్క్రమించు(1);
}

/*
 * Main program for key management.
 */
పూర్ణాంకం
ప్రధాన(పూర్ణాంకం argc, అక్షరం **argv)
{
	అక్షరం comment[కీలకం_COMMENT_MAX], *passphrase = ఖాళీ;
	అక్షరం *rr_hostname = ఖాళీ, *ep, *fp, *ra;
	నిర్మాణం sshkey *అంతరంగ = ఖాళీ, *బహిరంగ = ఖాళీ;
	నిర్మాణం passwd *pw;
	పూర్ణాంకం ret = 0, r, opt, type;
	పూర్ణాంకం change_passphrase = 0, change_comment = 0, show_cert = 0;
	పూర్ణాంకం కనుగొను_host = 0, delete_host = 0, hash_hosts = 0;
	పూర్ణాంకం gen_all_hostkeys = 0, gen_krl = 0, update_krl = 0, check_krl = 0;
	పూర్ణాంకం prefer_agent = 0, convert_గమ్యం = 0, convert_from = 0;
	పూర్ణాంకం print_ప్రజా = 0, print_generic = 0, cert_serial_autoinc = 0;
	పూర్ణాంకం do_gen_candidates = 0, do_screen_candidates = 0, download_sk = 0;
	గుర్తులేని దీర్ఘ దీర్ఘ cert_serial = 0;
	అక్షరం *తటస్థం_comment = ఖాళీ, *ca_కీలకం_మార్గం = ఖాళీ, **opts = ఖాళీ;
	అక్షరం *sk_application = ఖాళీ, *sk_device = ఖాళీ, *sk_user = ఖాళీ;
	అక్షరం *sk_attestation_మార్గం = ఖాళీ;
	నిర్మాణం sshbuf *challenge = ఖాళీ, *attest = ఖాళీ;
	కొలత_t i, nopts = 0;
	uint32_t బిట్లు = 0;
	uint8_t sk_flags = SSH_SK_USER_PRESENCE_REQD;
	స్థిరరాశి అక్షరం *errstr, *p;
	పూర్ణాంకం log_level = SYSLOG_LEVEL_INFO;
	అక్షరం *sign_op = ఖాళీ;

	బాహ్య పూర్ణాంకం optind;
	బాహ్య అక్షరం *optarg;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	__progname = ssh_get_progname(argv[0]);

	విత్తనం_rng();

	log_init(argv[0], SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_USER, 1);

	msetlocale();

	/* we need this for the home * directory.  */
	pw = getpwuid(getuid());
	ఒకవేళ (!pw)
		fatal("No user exists for uid %lu", (u_long)getuid());
	pw = pwcopy(pw);
	ఒకవేళ (gethostname(hostname, పరిమాణం(hostname)) == -1)
		fatal("gethostname: %s", strerror(errno));

	sk_provider = getenv("SSH_SK_PROVIDER");

	/* Remaining characters: dGjJSTWx */
	అయితే ((opt = getopt(argc, argv, "ABHKLQUXceghiklopquvy"
	    "C:D:E:F:I:M:N:O:P:R:V:Y:Z:"
	    "a:b:f:g:m:n:r:s:t:w:z:")) != -1) {
		ఎంపిక (opt) {
		స్థితి 'A':
			gen_all_hostkeys = 1;
			ఆపు;
		స్థితి 'b':
			బిట్లు = (uint32_t)strtonum(optarg, 1, UINT32_MAX,
			    &errstr);
			ఒకవేళ (errstr)
				fatal("Bits has bad value %s (%s)",
					optarg, errstr);
			ఆపు;
		స్థితి 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			ఒకవేళ (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			ఆపు;
		స్థితి 'F':
			కనుగొను_host = 1;
			rr_hostname = optarg;
			ఆపు;
		స్థితి 'H':
			hash_hosts = 1;
			ఆపు;
		స్థితి 'I':
			cert_కీలకం_id = optarg;
			ఆపు;
		స్థితి 'R':
			delete_host = 1;
			rr_hostname = optarg;
			ఆపు;
		స్థితి 'L':
			show_cert = 1;
			ఆపు;
		స్థితి 'l':
			print_fingerprint = 1;
			ఆపు;
		స్థితి 'B':
			print_bubblebabble = 1;
			ఆపు;
		స్థితి 'm':
			ఒకవేళ (strcasecmp(optarg, "RFC4716") == 0 ||
			    strcasecmp(optarg, "ssh2") == 0) {
				convert_format = FMT_RFC4716;
				ఆపు;
			}
			ఒకవేళ (strcasecmp(optarg, "PKCS8") == 0) {
				convert_format = FMT_PKCS8;
				వ్యక్తిగత_కీలకం_format = SSHKEY_వ్యక్తిగత_PKCS8;
				ఆపు;
			}
			ఒకవేళ (strcasecmp(optarg, "PEM") == 0) {
				convert_format = FMT_PEM;
				వ్యక్తిగత_కీలకం_format = SSHKEY_వ్యక్తిగత_PEM;
				ఆపు;
			}
			ఒకవేళ (strcasecmp(optarg, "hexdump") == 0) {
				convert_format = FMT_HEXDUMP;
				ఆపు;
			}
			fatal("Unsupported conversion format \"%s\"", optarg);
		స్థితి 'n':
			cert_principals = optarg;
			ఆపు;
		స్థితి 'o':
			/* no-op; new format is already the default */
			ఆపు;
		స్థితి 'p':
			change_passphrase = 1;
			ఆపు;
		స్థితి 'c':
			change_comment = 1;
			ఆపు;
		స్థితి 'f':
			ఒకవేళ (strlcpy(తటస్థం_file, optarg,
			    పరిమాణం(తటస్థం_file)) >= పరిమాణం(తటస్థం_file))
				fatal("Identity filename too long");
			have_తటస్థం = 1;
			ఆపు;
		స్థితి 'g':
			print_generic = 1;
			ఆపు;
		స్థితి 'K':
			download_sk = 1;
			ఆపు;
		స్థితి 'P':
			తటస్థం_passphrase = optarg;
			ఆపు;
		స్థితి 'N':
			తటస్థం_new_passphrase = optarg;
			ఆపు;
		స్థితి 'Q':
			check_krl = 1;
			ఆపు;
		స్థితి 'O':
			opts = xrecallocarray(opts, nopts, nopts + 1,
			    పరిమాణం(*opts));
			opts[nopts++] = xstrdup(optarg);
			ఆపు;
		స్థితి 'Z':
			openssh_format_cipher = optarg;
			ఒకవేళ (cipher_by_name(openssh_format_cipher) == ఖాళీ)
				fatal("Invalid OpenSSH-format cipher '%s'",
				    openssh_format_cipher);
			ఆపు;
		స్థితి 'C':
			తటస్థం_comment = optarg;
			ఆపు;
		స్థితి 'q':
			quiet = 1;
			ఆపు;
		స్థితి 'e':
			/* export key */
			convert_గమ్యం = 1;
			ఆపు;
		స్థితి 'h':
			cert_కీలకం_type = SSH2_CERT_TYPE_HOST;
			certflags_flags = 0;
			ఆపు;
		స్థితి 'k':
			gen_krl = 1;
			ఆపు;
		స్థితి 'i':
		స్థితి 'X':
			/* import key */
			convert_from = 1;
			ఆపు;
		స్థితి 'y':
			print_ప్రజా = 1;
			ఆపు;
		స్థితి 's':
			ca_కీలకం_మార్గం = optarg;
			ఆపు;
		స్థితి 't':
			కీలకం_type_name = optarg;
			ఆపు;
		స్థితి 'D':
			pkcs11provider = optarg;
			ఆపు;
		స్థితి 'U':
			prefer_agent = 1;
			ఆపు;
		స్థితి 'u':
			update_krl = 1;
			ఆపు;
		స్థితి 'v':
			ఒకవేళ (log_level == SYSLOG_LEVEL_INFO)
				log_level = SYSLOG_LEVEL_DEBUG1;
			లేకపోతే {
				ఒకవేళ (log_level >= SYSLOG_LEVEL_DEBUG1 &&
				    log_level < SYSLOG_LEVEL_DEBUG3)
					log_level++;
			}
			ఆపు;
		స్థితి 'r':
			rr_hostname = optarg;
			ఆపు;
		స్థితి 'a':
			విడతలు = (పూర్ణాంకం)strtonum(optarg, 1, గరిష్ఠ_పూర్ణాంకం, &errstr);
			ఒకవేళ (errstr)
				fatal("Invalid number: %s (%s)",
					optarg, errstr);
			ఆపు;
		స్థితి 'V':
			parse_cert_times(optarg);
			ఆపు;
		స్థితి 'Y':
			sign_op = optarg;
			ఆపు;
		స్థితి 'w':
			sk_provider = optarg;
			ఆపు;
		స్థితి 'z':
			errno = 0;
			ఒకవేళ (*optarg == '+') {
				cert_serial_autoinc = 1;
				optarg++;
			}
			cert_serial = strtoull(optarg, &ep, 10);
			ఒకవేళ (*optarg < '0' || *optarg > '9' || *ep != '\0' ||
			    (errno == ERANGE && cert_serial == ULLONG_MAX))
				fatal("Invalid serial number \"%s\"", optarg);
			ఆపు;
		స్థితి 'M':
			ఒకవేళ (strcmp(optarg, "generate") == 0)
				do_gen_candidates = 1;
			లేకపోతే ఒకవేళ (strcmp(optarg, "screen") == 0)
				do_screen_candidates = 1;
			లేకపోతే
				fatal("Unsupported moduli option %s", optarg);
			ఆపు;
		అప్రమేయ:
			usage();
		}
	}

#నిర్వచితమైతే ENABLE_SK_అంతర్గత
	ఒకవేళ (sk_provider == ఖాళీ)
		sk_provider = "internal";
#అయితే_ముగింపు

	/* reinit */
	log_init(argv[0], log_level, SYSLOG_FACILITY_USER, 1);

	argv += optind;
	argc -= optind;

	ఒకవేళ (sign_op != ఖాళీ) {
		ఒకవేళ (strprefix(sign_op, "find-principals", 0) != ఖాళీ) {
			ఒకవేళ (ca_కీలకం_మార్గం == ఖాళీ) {
				error("Too few arguments for find-principals:"
				    "missing signature file");
				నిష్క్రమించు(1);
			}
			ఒకవేళ (!have_తటస్థం) {
				error("Too few arguments for find-principals:"
				    "missing allowed keys file");
				నిష్క్రమించు(1);
			}
			ret = sig_కనుగొను_principals(ca_కీలకం_మార్గం, తటస్థం_file,
			    opts, nopts);
			వెళ్ళు పూర్తి;
		} లేకపోతే ఒకవేళ (strprefix(sign_op, "match-principals", 0) != ఖాళీ) {
			ఒకవేళ (!have_తటస్థం) {
				error("Too few arguments for match-principals:"
				    "missing allowed keys file");
				నిష్క్రమించు(1);
			}
			ఒకవేళ (cert_కీలకం_id == ఖాళీ) {
				error("Too few arguments for match-principals: "
				    "missing principal ID");
				నిష్క్రమించు(1);
			}
			ret = sig_సరిపోలిక_principals(తటస్థం_file, cert_కీలకం_id,
			    opts, nopts);
			వెళ్ళు పూర్తి;
		} లేకపోతే ఒకవేళ (strprefix(sign_op, "sign", 0) != ఖాళీ) {
			/* NB. cert_principals is actually namespace, via -n */
			ఒకవేళ (cert_principals == ఖాళీ ||
			    *cert_principals == '\0') {
				error("Too few arguments for sign: "
				    "missing namespace");
				నిష్క్రమించు(1);
			}
			ఒకవేళ (!have_తటస్థం) {
				error("Too few arguments for sign: "
				    "missing key");
				నిష్క్రమించు(1);
			}
			ret = sig_sign(తటస్థం_file, cert_principals,
			    prefer_agent, argc, argv, opts, nopts);
			వెళ్ళు పూర్తి;
		} లేకపోతే ఒకవేళ (strprefix(sign_op, "check-novalidate", 0) != ఖాళీ) {
			/* NB. cert_principals is actually namespace, via -n */
			ఒకవేళ (cert_principals == ఖాళీ ||
			    *cert_principals == '\0') {
				error("Too few arguments for check-novalidate: "
				    "missing namespace");
				నిష్క్రమించు(1);
			}
			ఒకవేళ (ca_కీలకం_మార్గం == ఖాళీ) {
				error("Too few arguments for check-novalidate: "
				    "missing signature file");
				నిష్క్రమించు(1);
			}
			ret = sig_verify(ca_కీలకం_మార్గం, cert_principals,
			    ఖాళీ, ఖాళీ, ఖాళీ, opts, nopts);
			వెళ్ళు పూర్తి;
		} లేకపోతే ఒకవేళ (strprefix(sign_op, "verify", 0) != ఖాళీ) {
			/* NB. cert_principals is actually namespace, via -n */
			ఒకవేళ (cert_principals == ఖాళీ ||
			    *cert_principals == '\0') {
				error("Too few arguments for verify: "
				    "missing namespace");
				నిష్క్రమించు(1);
			}
			ఒకవేళ (ca_కీలకం_మార్గం == ఖాళీ) {
				error("Too few arguments for verify: "
				    "missing signature file");
				నిష్క్రమించు(1);
			}
			ఒకవేళ (!have_తటస్థం) {
				error("Too few arguments for sign: "
				    "missing allowed keys file");
				నిష్క్రమించు(1);
			}
			ఒకవేళ (cert_కీలకం_id == ఖాళీ) {
				error("Too few arguments for verify: "
				    "missing principal identity");
				నిష్క్రమించు(1);
			}
			ret = sig_verify(ca_కీలకం_మార్గం, cert_principals,
			    cert_కీలకం_id, తటస్థం_file, rr_hostname,
			    opts, nopts);
			వెళ్ళు పూర్తి;
		}
		error("Unsupported operation for -Y: \"%s\"", sign_op);
		usage();
		/* NOTREACHED */
	}

	ఒకవేళ (ca_కీలకం_మార్గం != ఖాళీ) {
		ఒకవేళ (argc < 1 && !gen_krl) {
			error("Too few arguments.");
			usage();
		}
	} లేకపోతే ఒకవేళ (argc > 0 && !gen_krl && !check_krl &&
	    !do_gen_candidates && !do_screen_candidates) {
		error("Too many arguments.");
		usage();
	}
	ఒకవేళ (change_passphrase && change_comment) {
		error("Can only have one of -p and -c.");
		usage();
	}
	ఒకవేళ (print_fingerprint && (delete_host || hash_hosts)) {
		error("Cannot use -l with -H or -R.");
		usage();
	}
	ఒకవేళ (gen_krl) {
		do_gen_krl(pw, update_krl, ca_కీలకం_మార్గం,
		    cert_serial, తటస్థం_comment, argc, argv);
		వెళ్ళు పూర్తి;
	}
	ఒకవేళ (check_krl) {
		do_check_krl(pw, print_fingerprint, argc, argv);
		వెళ్ళు పూర్తి;
	}
	ఒకవేళ (ca_కీలకం_మార్గం != ఖాళీ) {
		ఒకవేళ (cert_కీలకం_id == ఖాళీ)
			fatal("Must specify key id (-I) when certifying");
		ఒకవేళ (cert_principals == ఖాళీ) {
			/*
			 * Ideally this would be a fatal(), but we need to
			 * be able to generate such certificates for testing
			 * even though they will be rejected.
			 */
			error("Warning: certificate will contain no "
			    "principals (-n)");
		}
		కొరకు (i = 0; i < nopts; i++)
			కూడు_cert_option(opts[i]);
		do_ca_sign(pw, ca_కీలకం_మార్గం, prefer_agent,
		    cert_serial, cert_serial_autoinc, argc, argv);
		వెళ్ళు పూర్తి;
	}
	ఒకవేళ (show_cert)
		do_show_cert(pw);
	ఒకవేళ (delete_host || hash_hosts || కనుగొను_host) {
		do_తెలిసిన_hosts(pw, rr_hostname, కనుగొను_host,
		    delete_host, hash_hosts);
	}
	ఒకవేళ (pkcs11provider != ఖాళీ)
		do_download(pw);
	ఒకవేళ (download_sk) {
		కొరకు (i = 0; i < nopts; i++) {
			ఒకవేళ ((p = strprefix(opts[i], "device=", 1)) != ఖాళీ) {
				sk_device = xstrdup(p);
			} లేకపోతే {
				fatal("Option \"%s\" is unsupported for "
				    "FIDO authenticator download", opts[i]);
			}
		}
		ret = do_download_sk(sk_provider, sk_device);
		వెళ్ళు పూర్తి;
	}
	ఒకవేళ (print_fingerprint || print_bubblebabble)
		do_fingerprint(pw);
	ఒకవేళ (change_passphrase)
		do_change_passphrase(pw, opts, nopts);
	ఒకవేళ (change_comment)
		do_change_comment(pw, తటస్థం_comment);
#నిర్వచితమైతే WITH_OPENSSL
	ఒకవేళ (convert_గమ్యం) {
		do_convert_గమ్యం(pw);
		వెళ్ళు పూర్తి;
	}
	ఒకవేళ (convert_from) {
		do_convert_from(pw);
		వెళ్ళు పూర్తి;
	}
#లేకపోతే /* WITH_OPENSSL */
	ఒకవేళ (convert_గమ్యం || convert_from)
		fatal("key conversion disabled at compile time");
#అయితే_ముగింపు /* WITH_OPENSSL */
	ఒకవేళ (print_ప్రజా)
		do_print_ప్రజా(pw);
	ఒకవేళ (rr_hostname != ఖాళీ) {
		గుర్తులేని పూర్ణాంకం n = 0;

		ఒకవేళ (have_తటస్థం) {
			n = do_print_resource_రికార్డు(pw, తటస్థం_file,
			    rr_hostname, print_generic, opts, nopts);
			ఒకవేళ (n == 0)
				fatal("%s: %s", తటస్థం_file, strerror(errno));
			నిష్క్రమించు(0);
		} లేకపోతే {

			n += do_print_resource_రికార్డు(pw,
			    మార్గం_HOST_RSA_కీలకం_FILE, rr_hostname,
			    print_generic, opts, nopts);
			n += do_print_resource_రికార్డు(pw,
			    మార్గం_HOST_ECDSA_కీలకం_FILE, rr_hostname,
			    print_generic, opts, nopts);
			n += do_print_resource_రికార్డు(pw,
			    మార్గం_HOST_ED25519_కీలకం_FILE, rr_hostname,
			    print_generic, opts, nopts);
			ఒకవేళ (n == 0)
				fatal("no keys found.");
			నిష్క్రమించు(0);
		}
	}

	ఒకవేళ (do_gen_candidates || do_screen_candidates) {
		ఒకవేళ (argc <= 0)
			fatal("No output file specified");
		లేకపోతే ఒకవేళ (argc > 1)
			fatal("Too many output files specified");
	}
	ఒకవేళ (do_gen_candidates) {
		do_moduli_gen(argv[0], opts, nopts);
		వెళ్ళు పూర్తి;
	}
	ఒకవేళ (do_screen_candidates) {
		do_moduli_screen(argv[0], opts, nopts);
		వెళ్ళు పూర్తి;
	}

	ఒకవేళ (gen_all_hostkeys) {
		do_gen_all_hostkeys(pw);
		వెళ్ళు పూర్తి;
	}

	ఒకవేళ (కీలకం_type_name == ఖాళీ)
		కీలకం_type_name = DEFAULT_కీలకం_TYPE_NAME;

	type = sshkey_type_from_shortname(కీలకం_type_name);
	type_బిట్లు_valid(type, కీలకం_type_name, &బిట్లు);

	ఒకవేళ (!quiet)
		రాయి("Generating public/private %s key pair.\n",
		    కీలకం_type_name);
	ఎంపిక (type) {
	స్థితి కీలకం_ECDSA_SK:
	స్థితి కీలకం_ED25519_SK:
		కొరకు (i = 0; i < nopts; i++) {
			ఒకవేళ (strcasecmp(opts[i], "no-touch-required") == 0) {
				sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
			} లేకపోతే ఒకవేళ (strcasecmp(opts[i], "verify-required") == 0) {
				sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
			} లేకపోతే ఒకవేళ (strcasecmp(opts[i], "resident") == 0) {
				sk_flags |= SSH_SK_RESIDENT_కీలకం;
			} లేకపోతే ఒకవేళ ((p = strprefix(opts[i], "device=", 1))
			    != ఖాళీ ) {
				sk_device = xstrdup(p);
			} లేకపోతే ఒకవేళ ((p = strprefix(opts[i], "user=", 1))
			    != ఖాళీ) {
				sk_user = xstrdup(p);
			} లేకపోతే ఒకవేళ ((p = strprefix(opts[i], "challenge=", 1))
			    != ఖాళీ) {
				ఒకవేళ ((r = sshbuf_ఎక్కించు_file(p,
				    &challenge)) != 0) {
					fatal_r(r, "Unable to load FIDO "
					    "enrollment challenge \"%s\"", p);
				}
			} లేకపోతే ఒకవేళ (strncasecmp(opts[i],
			    "write-attestation=", 18) == 0) {
				sk_attestation_మార్గం = opts[i] + 18;
			} లేకపోతే ఒకవేళ (strncasecmp(opts[i],
			    "application=", 12) == 0) {
				sk_application = xstrdup(opts[i] + 12);
				ఒకవేళ (అక్షరశ్రేణి_పోలిక(sk_application, "ssh:", 4) != 0) {
					fatal("FIDO application string must "
					    "begin with \"ssh:\"");
				}
			} లేకపోతే {
				fatal("Option \"%s\" is unsupported for "
				    "FIDO authenticator enrollment", opts[i]);
			}
		}
		ఒకవేళ ((attest = sshbuf_new()) == ఖాళీ)
			fatal("sshbuf_new failed");
		r = 0;
		కొరకు (i = 0 ;;) {
			ఒకవేళ (!quiet) {
				రాయి("You may need to touch your "
				    "authenticator%s to authorize key "
				    "generation.\n",
				    r == 0 ? "" : " again");
			}
			fflush(stdout);
			r = sshsk_enroll(type, sk_provider, sk_device,
			    sk_application == ఖాళీ ? "ssh:" : sk_application,
			    sk_user, sk_flags, passphrase, challenge,
			    &అంతరంగ, attest);
			ఒకవేళ (r == 0)
				ఆపు;
			ఒకవేళ (r == SSH_ERR_కీలకం_BAD_PERMISSIONS &&
			    (sk_flags & SSH_SK_RESIDENT_కీలకం) != 0 &&
			    (sk_flags & SSH_SK_FORCE_OPERATION) == 0 &&
			    confirm_sk_overwrite(sk_application, sk_user)) {
				sk_flags |= SSH_SK_FORCE_OPERATION;
				కొనసాగు;
			}
			ఒకవేళ (r != SSH_ERR_కీలకం_WRONG_PASSPHRASE)
				fatal_r(r, "Key enrollment failed");
			లేకపోతే ఒకవేళ (passphrase != ఖాళీ) {
				error("PIN incorrect");
				freezero(passphrase, అక్షరశ్రేణి_పొడవు(passphrase));
				passphrase = ఖాళీ;
			}
			ఒకవేళ (++i >= 3)
				fatal("Too many incorrect PINs");
			passphrase = read_passphrase("Enter PIN for "
			    "authenticator: ", RP_ALLOW_STDIN);
		}
		ఒకవేళ (passphrase != ఖాళీ) {
			freezero(passphrase, అక్షరశ్రేణి_పొడవు(passphrase));
			passphrase = ఖాళీ;
		}
		ఆపు;
	అప్రమేయ:
		ఒకవేళ ((r = sshkey_generate(type, బిట్లు, &అంతరంగ)) != 0)
			fatal("sshkey_generate failed");
		ఆపు;
	}
	ఒకవేళ ((r = sshkey_from_వ్యక్తిగత(అంతరంగ, &బహిరంగ)) != 0)
		fatal_r(r, "sshkey_from_private");

	ఒకవేళ (!have_తటస్థం)
		ask_filename(pw, "Enter file in which to save the key");

	/* Create ~/.ssh directory if it doesn't already exist. */
	hostfile_create_user_ssh_dir(తటస్థం_file, !quiet);

	/* If the file already exists, ask the user to confirm. */
	ఒకవేళ (!confirm_overwrite(తటస్థం_file))
		నిష్క్రమించు(1);

	/* Determine the passphrase for the private key */
	passphrase = వ్యక్తిగత_కీలకం_passphrase(తటస్థం_file);
	ఒకవేళ (తటస్థం_comment) {
		strlcpy(comment, తటస్థం_comment, పరిమాణం(comment));
	} లేకపోతే {
		/* Create default comment field for the passphrase. */
		snprintf(comment, పరిమాణం comment, "%s@%s", pw->pw_name, hostname);
	}



	/* Save the key with the given passphrase and comment. */
	ఒకవేళ ((r = sshkey_save_వ్యక్తిగత(అంతరంగ, తటస్థం_file, passphrase,
	    comment, వ్యక్తిగత_కీలకం_format, openssh_format_cipher, విడతలు)) != 0) {
		error_r(r, "Saving key \"%s\" failed", తటస్థం_file);
		freezero(passphrase, అక్షరశ్రేణి_పొడవు(passphrase));
		నిష్క్రమించు(1);
	}
	freezero(passphrase, అక్షరశ్రేణి_పొడవు(passphrase));
	sshkey_free(అంతరంగ);

	ఒకవేళ (!quiet) {
		రాయి("Your identification has been saved in %s\n",
		    తటస్థం_file);
	}

	strlcat(తటస్థం_file, ".pub", పరిమాణం(తటస్థం_file));
	ఒకవేళ ((r = sshkey_save_ప్రజా(బహిరంగ, తటస్థం_file, comment)) != 0)
		fatal_r(r, "Unable to save public key to %s", తటస్థం_file);

	ఒకవేళ (!quiet) {
		fp = sshkey_fingerprint(బహిరంగ, fingerprint_hash,
		    SSH_FP_DEFAULT);
		ra = sshkey_fingerprint(బహిరంగ, fingerprint_hash,
		    SSH_FP_RANDOMART);
		ఒకవేళ (fp == ఖాళీ || ra == ఖాళీ)
			fatal("sshkey_fingerprint failed");
		రాయి("Your public key has been saved in %s\n",
		    తటస్థం_file);
		రాయి("The key fingerprint is:\n");
		రాయి("%s %s\n", fp, comment);
		రాయి("The key's randomart image is:\n");
		రాయి("%s\n", ra);
		విడుదల(ra);
		విడుదల(fp);
	}

	ఒకవేళ (sk_attestation_మార్గం != ఖాళీ)
		save_attestation(attest, sk_attestation_మార్గం);

 పూర్తి:
	sshbuf_free(attest);
	sshkey_free(బహిరంగ);
	pwfree(pw);
	నిష్క్రమించు(ret);
}
