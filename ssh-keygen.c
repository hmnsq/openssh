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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/socket.h>
#অন্তর্ভাব <sys/stat.h>

#ifdef WITH_OPENSSL
#অন্তর্ভাব "openbsd-compat/openssl-compat.h"
#অন্তর্ভাব <openssl/bn.h>
#অন্তর্ভাব <openssl/evp.h>
#অন্তর্ভাব <openssl/pem.h>
#endif

#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <fcntl.h>
#অন্তর্ভাব <netdb.h>
#অন্তর্ভাব <paths.h>
#অন্তর্ভাব <pwd.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <limits.h>
#অন্তর্ভাব <locale.h>
#অন্তর্ভাব <time.h>

#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "authfile.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "pathnames.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "match.h"
#অন্তর্ভাব "hostfile.h"
#অন্তর্ভাব "dns.h"
#অন্তর্ভাব "ssh.h"
#অন্তর্ভাব "ssh2.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "atomicio.h"
#অন্তর্ভাব "krl.h"
#অন্তর্ভাব "digest.h"
#অন্তর্ভাব "utf8.h"
#অন্তর্ভাব "authfd.h"
#অন্তর্ভাব "sshsig.h"
#অন্তর্ভাব "ssh-sk.h"
#অন্তর্ভাব "sk-api.h" /* XXX for SSH_SK_USER_PRESENCE_REQD; remove */
#অন্তর্ভাব "cipher.h"

#ifdef ENABLE_PKCS11
#অন্তর্ভাব "ssh-pkcs11.h"
#endif

#define DEFAULT_চাবি_TYPE_NAME "ed25519"

/*
 * Default number of bits in the RSA and ECDSA keys.  These value can be
 * overridden on the command line.
 *
 * These values provide security equivalent to at least 128 bits of security
 * according to NIST Special Publication 800-57: Recommendation for Key
 * Management Part 1 rev 4 section 5.6.1.
 */
#define DEFAULT_BITS		3072
#define DEFAULT_BITS_ECDSA	256

#define চাবি_COMMENT_MAX		(NI_MAXHOST + 1024)

স্থির পূর্ণসংখ্যা quiet = 0;

/* Flag indicating that we just want to see the key fingerprint */
স্থির পূর্ণসংখ্যা print_fingerprint = 0;
স্থির পূর্ণসংখ্যা print_bubblebabble = 0;

/* Hash algorithm to use for fingerprints. */
স্থির পূর্ণসংখ্যা fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* The identity file name, given on the command line or entered by the user. */
স্থির অক্ষর identity_file[PATH_MAX];
স্থির পূর্ণসংখ্যা have_identity = 0;

/* This is set to the passphrase if given on the command line. */
স্থির অক্ষর *identity_passphrase = ফাঁকা;

/* This is set to the new passphrase if given on the command line. */
স্থির অক্ষর *identity_new_passphrase = ফাঁকা;

/* Key type when certifying */
স্থির u_int cert_চাবি_type = SSH2_CERT_TYPE_USER;

/* "key ID" of signed key */
স্থির অক্ষর *cert_চাবি_id = ফাঁকা;

/* Comma-separated list of principal names for certifying keys */
স্থির অক্ষর *cert_principals = ফাঁকা;

/* Validity period for certificates */
স্থির uint64_t cert_valid_from = 0;
স্থির uint64_t cert_valid_to = ~0ULL;

/* Certificate options */
#define CERTOPT_X_FWD				(1)
#define CERTOPT_AGENT_FWD			(1<<1)
#define CERTOPT_PORT_FWD			(1<<2)
#define CERTOPT_PTY				(1<<3)
#define CERTOPT_USER_RC				(1<<4)
#define CERTOPT_NO_REQUIRE_USER_PRESENCE	(1<<5)
#define CERTOPT_REQUIRE_VERIFY			(1<<6)
#define CERTOPT_DEFAULT	(CERTOPT_X_FWD|CERTOPT_AGENT_FWD| \
			 CERTOPT_PORT_FWD|CERTOPT_PTY|CERTOPT_USER_RC)
স্থির uint32_t certflags_flags = CERTOPT_DEFAULT;
স্থির অক্ষর *certflags_command = ফাঁকা;
স্থির অক্ষর *certflags_src_addr = ফাঁকা;

/* Arbitrary extensions specified by user */
কাঠামো cert_ext {
	অক্ষর *চাবি;
	অক্ষর *val;
	পূর্ণসংখ্যা crit;
};
স্থির কাঠামো cert_ext *cert_ext;
স্থির আকার_t ncert_ext;

/* Conversion to/from various formats */
গণনা {
	FMT_RFC4716,
	FMT_PKCS8,
	FMT_PEM,
	FMT_HEXDUMP
} convert_format = FMT_RFC4716;

স্থির অক্ষর *চাবি_type_name = ফাঁকা;

/* Load key from this PKCS#11 provider */
স্থির অক্ষর *pkcs11provider = ফাঁকা;

/* FIDO/U2F provider to use */
স্থির অক্ষর *sk_provider = ফাঁকা;

/* Format for writing private keys */
স্থির পূর্ণসংখ্যা private_চাবি_format = SSHKEY_PRIVATE_OPENSSH;

/* Cipher for new-format private keys */
স্থির অক্ষর *openssh_format_cipher = ফাঁকা;

/* Number of KDF rounds to derive new format keys. */
স্থির পূর্ণসংখ্যা rounds = 0;

/* argv0 */
বাহ্যিক অক্ষর *__progname;

স্থির অক্ষর hostname[NI_MAXHOST];

#ifdef WITH_OPENSSL
/* moduli.c */
পূর্ণসংখ্যা gen_candidates(FILE *, uint32_t, BIGNUM *);
পূর্ণসংখ্যা মৌলিক_test(FILE *, FILE *, uint32_t, uint32_t, অক্ষর *, unsigned long,
    unsigned long);
#endif

স্থির শূন্য
type_bits_valid(পূর্ণসংখ্যা type, ধ্রুবক অক্ষর *name, uint32_t *bitsp)
{
	যদি (type == চাবি_UNSPEC)
		fatal("unknown key type %s", চাবি_type_name);
	যদি (*bitsp == 0) {
#ifdef WITH_OPENSSL
		পূর্ণসংখ্যা nid;

		নির্বাচন(type) {
		ক্ষেত্র চাবি_ECDSA:
			যদি (name != ফাঁকা &&
			    (nid = sshkey_ecdsa_nid_from_name(name)) > 0)
				*bitsp = sshkey_curve_nid_to_bits(nid);
			যদি (*bitsp == 0)
				*bitsp = DEFAULT_BITS_ECDSA;
			বিরতি;
		ক্ষেত্র চাবি_RSA:
			*bitsp = DEFAULT_BITS;
			বিরতি;
		}
#endif
	}
#ifdef WITH_OPENSSL
	নির্বাচন (type) {
	ক্ষেত্র চাবি_RSA:
		যদি (*bitsp < SSH_RSA_MINIMUM_MODULUS_আকার)
			fatal("Invalid RSA key length: minimum is %d bits",
			    SSH_RSA_MINIMUM_MODULUS_আকার);
		অন্যথা যদি (*bitsp > OPENSSL_RSA_MAX_MODULUS_BITS)
			fatal("Invalid RSA key length: maximum is %d bits",
			    OPENSSL_RSA_MAX_MODULUS_BITS);
		বিরতি;
	ক্ষেত্র চাবি_ECDSA:
		যদি (sshkey_ecdsa_bits_to_nid(*bitsp) == -1)
			fatal("Invalid ECDSA key length: valid lengths are "
			    "256, 384 or 521 bits");
	}
#endif
}

/*
 * Checks whether a file exists and, if so, asks the user whether they wish
 * to overwrite it.
 * Returns nonzero if the file does not already exist or if the user agrees to
 * overwrite, or zero otherwise.
 */
স্থির পূর্ণসংখ্যা
confirm_overwrite(ধ্রুবক অক্ষর *filename)
{
	অক্ষর yesno[3];
	কাঠামো stat st;

	যদি (stat(filename, &st) != 0)
		ফেরত 1;
	printf("%s already exists.\n", filename);
	printf("Overwrite (y/n)? ");
	fflush(stdout);
	যদি (fgets(yesno, আকার(yesno), stdin) == ফাঁকা)
		ফেরত 0;
	যদি (yesno[0] != 'y' && yesno[0] != 'Y')
		ফেরত 0;
	ফেরত 1;
}

স্থির শূন্য
ask_filename(কাঠামো passwd *pw, ধ্রুবক অক্ষর *prompt)
{
	অক্ষর buf[1024];
	অক্ষর *name = ফাঁকা;

	যদি (চাবি_type_name == ফাঁকা)
		name = _PATH_SSH_CLIENT_ID_ED25519;
	অন্যথা {
		নির্বাচন (sshkey_type_from_shortname(চাবি_type_name)) {
		ক্ষেত্র চাবি_ECDSA_CERT:
		ক্ষেত্র চাবি_ECDSA:
			name = _PATH_SSH_CLIENT_ID_ECDSA;
			বিরতি;
		ক্ষেত্র চাবি_ECDSA_SK_CERT:
		ক্ষেত্র চাবি_ECDSA_SK:
			name = _PATH_SSH_CLIENT_ID_ECDSA_SK;
			বিরতি;
		ক্ষেত্র চাবি_RSA_CERT:
		ক্ষেত্র চাবি_RSA:
			name = _PATH_SSH_CLIENT_ID_RSA;
			বিরতি;
		ক্ষেত্র চাবি_ED25519:
		ক্ষেত্র চাবি_ED25519_CERT:
			name = _PATH_SSH_CLIENT_ID_ED25519;
			বিরতি;
		ক্ষেত্র চাবি_ED25519_SK:
		ক্ষেত্র চাবি_ED25519_SK_CERT:
			name = _PATH_SSH_CLIENT_ID_ED25519_SK;
			বিরতি;
		ক্ষেত্র চাবি_MLDSA44_ED25519:
		ক্ষেত্র চাবি_MLDSA44_ED25519_CERT:
			name = _PATH_SSH_CLIENT_ID_MLDSA44_ED25519;
			বিরতি;
		পূর্বনির্ধারিত:
			fatal("bad key type");
		}
	}
	snprintf(identity_file, আকার(identity_file),
	    "%s/%s", pw->pw_dir, name);
	printf("%s (%s): ", prompt, identity_file);
	fflush(stdout);
	যদি (fgets(buf, আকার(buf), stdin) == ফাঁকা)
		exit(1);
	buf[strcspn(buf, "\n")] = '\0';
	যদি (strcmp(buf, "") != 0)
		strlcpy(identity_file, buf, আকার(identity_file));
	have_identity = 1;
}

স্থির কাঠামো sshkey *
load_identity(ধ্রুবক অক্ষর *filename, অক্ষর **commentp)
{
	অক্ষর *prompt, *pass;
	কাঠামো sshkey *prv;
	পূর্ণসংখ্যা r;

	যদি (commentp != ফাঁকা)
		*commentp = ফাঁকা;
	যদি ((r = sshkey_load_private(filename, "", &prv, commentp)) == 0)
		ফেরত prv;
	যদি (r != SSH_ERR_চাবি_WRONG_PASSPHRASE)
		fatal_r(r, "Load key \"%s\"", filename);
	যদি (identity_passphrase)
		pass = xstrdup(identity_passphrase);
	অন্যথা {
		xasprintf(&prompt, "Enter passphrase for \"%s\": ", filename);
		pass = read_passphrase(prompt, RP_ALLOW_STDIN);
		মুক্ত(prompt);
	}
	r = sshkey_load_private(filename, pass, &prv, commentp);
	freezero(pass, strlen(pass));
	যদি (r != 0)
		fatal_r(r, "Load key \"%s\"", filename);
	ফেরত prv;
}

#define SSH_COM_PUBLIC_BEGIN		"---- BEGIN SSH2 PUBLIC KEY ----"
#define SSH_COM_PUBLIC_END		"---- END SSH2 PUBLIC KEY ----"
#define SSH_COM_PRIVATE_BEGIN		"---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----"
#define	SSH_COM_PRIVATE_চাবি_MAGIC	0x3f6ff9eb

#ifdef WITH_OPENSSL
স্থির শূন্য
do_convert_to_ssh2(কাঠামো passwd *pw, কাঠামো sshkey *k)
{
	কাঠামো sshbuf *b;
	অক্ষর comment[61], *b64;
	পূর্ণসংখ্যা r;

	যদি ((b = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshkey_putb(k, b)) != 0)
		fatal_fr(r, "put key");
	যদি ((b64 = sshbuf_dtob64_string(b, 1)) == ফাঁকা)
		fatal_f("sshbuf_dtob64_string failed");

	/* Comment + surrounds must fit into 72 chars (RFC 4716 sec 3.3) */
	snprintf(comment, আকার(comment),
	    "%u-bit %s, converted by %s@%s from OpenSSH",
	    sshkey_আকার(k), sshkey_type(k),
	    pw->pw_name, hostname);

	sshkey_free(k);
	sshbuf_free(b);

	fprintf(stdout, "%s\n", SSH_COM_PUBLIC_BEGIN);
	fprintf(stdout, "Comment: \"%s\"\n%s", comment, b64);
	fprintf(stdout, "%s\n", SSH_COM_PUBLIC_END);
	মুক্ত(b64);
}

স্থির শূন্য
do_convert_to_pkcs8(কাঠামো sshkey *k)
{
	নির্বাচন (sshkey_type_plain(k->type)) {
	ক্ষেত্র চাবি_RSA:
		যদি (!PEM_write_RSA_PUBKEY(stdout,
		    EVP_PKEY_get0_RSA(k->pkey)))
			fatal("PEM_write_RSA_PUBKEY failed");
		বিরতি;
	ক্ষেত্র চাবি_ECDSA:
		যদি (!PEM_write_EC_PUBKEY(stdout,
		    EVP_PKEY_get0_EC_চাবি(k->pkey)))
			fatal("PEM_write_EC_PUBKEY failed");
		বিরতি;
	পূর্বনির্ধারিত:
		fatal_f("unsupported key type %s", sshkey_type(k));
	}
}

স্থির শূন্য
do_convert_to_pem(কাঠামো sshkey *k)
{
	নির্বাচন (sshkey_type_plain(k->type)) {
	ক্ষেত্র চাবি_RSA:
		যদি (!PEM_write_RSAPublic_চাবি(stdout,
		    EVP_PKEY_get0_RSA(k->pkey)))
			fatal("PEM_write_RSAPublicKey failed");
		বিরতি;
	ক্ষেত্র চাবি_ECDSA:
		যদি (!PEM_write_EC_PUBKEY(stdout,
		    EVP_PKEY_get0_EC_চাবি(k->pkey)))
			fatal("PEM_write_EC_PUBKEY failed");
		বিরতি;
	পূর্বনির্ধারিত:
		fatal_f("unsupported key type %s", sshkey_type(k));
	}
}

স্থির শূন্য
do_convert_to_hexdump(কাঠামো sshkey *k)
{
	কাঠামো sshbuf *b;
	পূর্ণসংখ্যা r;

	যদি ((b = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");
	/* pubkey */
	যদি ((r = sshkey_putb(k, b)) != 0)
		fatal_fr(r, "serialise private");
	printf("Public %s key:\n", sshkey_type(k));
	sshbuf_dump(b, stdout);
	sshbuf_reset(b);
	যদি ((r = sshkey_private_serialize(k, b)) != 0) {
		debug_fr(r, "serialise private");
		যাও out;
	}
	printf("\nPrivate %s key:\n", sshkey_type(k));
	sshbuf_dump(b, stdout);
 out:
	sshbuf_free(b);
}

স্থির শূন্য
do_convert_to(কাঠামো passwd *pw)
{
	কাঠামো sshkey *k = ফাঁকা;
	কাঠামো stat st;
	পূর্ণসংখ্যা r;

	যদি (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	যদি (stat(identity_file, &st) == -1)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));

	/* If we're trying to hexdump, then prefer the private key */
	যদি (convert_format == FMT_HEXDUMP) {
		যদি ((r = sshkey_load_private(identity_file,
		    ফাঁকা, &k, ফাঁকা)) != 0 &&
		    r == SSH_ERR_চাবি_WRONG_PASSPHRASE)
			k = load_identity(identity_file, ফাঁকা);
	}
	যদি (k == ফাঁকা && (r = sshkey_load_public(identity_file, &k, ফাঁকা)) != 0)
		k = load_identity(identity_file, ফাঁকা);

	নির্বাচন (convert_format) {
	ক্ষেত্র FMT_RFC4716:
		do_convert_to_ssh2(pw, k);
		বিরতি;
	ক্ষেত্র FMT_PKCS8:
		do_convert_to_pkcs8(k);
		বিরতি;
	ক্ষেত্র FMT_PEM:
		do_convert_to_pem(k);
		বিরতি;
	ক্ষেত্র FMT_HEXDUMP:
		do_convert_to_hexdump(k);
		বিরতি;
	পূর্বনির্ধারিত:
		fatal_f("unknown key format %d", convert_format);
	}
}

/*
 * This is almost exactly the bignum1 encoding, but with 32 bit for length
 * instead of 16.
 */
স্থির শূন্য
বাফার_get_bignum_bits(কাঠামো sshbuf *b, BIGNUM *মান)
{
	u_int bytes, bignum_bits;
	পূর্ণসংখ্যা r;

	যদি ((r = sshbuf_get_u32(b, &bignum_bits)) != 0)
		fatal_fr(r, "parse");
	bytes = (bignum_bits + 7) / 8;
	যদি (sshbuf_len(b) < bytes)
		fatal_f("input buffer too small: need %d have %zu",
		    bytes, sshbuf_len(b));
	যদি (BN_bin2bn(sshbuf_ptr(b), bytes, মান) == ফাঁকা)
		fatal_f("BN_bin2bn failed");
	যদি ((r = sshbuf_consume(b, bytes)) != 0)
		fatal_fr(r, "consume");
}

স্থির কাঠামো sshkey *
do_convert_private_ssh2(কাঠামো sshbuf *b)
{
	কাঠামো sshkey *চাবি = ফাঁকা;
	অক্ষর *type, *cipher;
	ধ্রুবক অক্ষর *alg = ফাঁকা;
	u_char e1, e2, e3, *sig = ফাঁকা, তথ্য[] = "abcde12345";
	পূর্ণসংখ্যা r, rlen, ktype;
	u_int magic, i1, i2, i3, i4;
	আকার_t slen;
	u_long e;
	BIGNUM *rsa_n = ফাঁকা, *rsa_e = ফাঁকা, *rsa_d = ফাঁকা;
	BIGNUM *rsa_p = ফাঁকা, *rsa_q = ফাঁকা, *rsa_iqmp = ফাঁকা;
	BIGNUM *rsa_dmp1 = ফাঁকা, *rsa_dmq1 = ফাঁকা;
	RSA *rsa = ফাঁকা;

	যদি ((r = sshbuf_get_u32(b, &magic)) != 0)
		fatal_fr(r, "parse magic");

	যদি (magic != SSH_COM_PRIVATE_চাবি_MAGIC) {
		error("bad magic 0x%x != 0x%x", magic,
		    SSH_COM_PRIVATE_চাবি_MAGIC);
		ফেরত ফাঁকা;
	}
	যদি ((r = sshbuf_get_u32(b, &i1)) != 0 ||
	    (r = sshbuf_get_cstring(b, &type, ফাঁকা)) != 0 ||
	    (r = sshbuf_get_cstring(b, &cipher, ফাঁকা)) != 0 ||
	    (r = sshbuf_get_u32(b, &i2)) != 0 ||
	    (r = sshbuf_get_u32(b, &i3)) != 0 ||
	    (r = sshbuf_get_u32(b, &i4)) != 0)
		fatal_fr(r, "parse");
	debug("ignore (%d %d %d %d)", i1, i2, i3, i4);
	যদি (strcmp(cipher, "none") != 0) {
		error("unsupported cipher %s", cipher);
		মুক্ত(cipher);
		মুক্ত(type);
		ফেরত ফাঁকা;
	}
	মুক্ত(cipher);

	যদি (strstr(type, "rsa")) {
		ktype = চাবি_RSA;
	} অন্যথা {
		মুক্ত(type);
		ফেরত ফাঁকা;
	}
	যদি ((চাবি = sshkey_new(ktype)) == ফাঁকা)
		fatal("sshkey_new failed");
	মুক্ত(type);

	নির্বাচন (চাবি->type) {
	ক্ষেত্র চাবি_RSA:
		যদি ((r = sshbuf_get_u8(b, &e1)) != 0 ||
		    (e1 < 30 && (r = sshbuf_get_u8(b, &e2)) != 0) ||
		    (e1 < 30 && (r = sshbuf_get_u8(b, &e3)) != 0))
			fatal_fr(r, "parse RSA");
		e = e1;
		debug("e %lx", e);
		যদি (e < 30) {
			e <<= 8;
			e += e2;
			debug("e %lx", e);
			e <<= 8;
			e += e3;
			debug("e %lx", e);
		}
		যদি ((rsa_e = BN_new()) == ফাঁকা)
			fatal_f("BN_new");
		যদি (!BN_set_word(rsa_e, e)) {
			BN_clear_free(rsa_e);
			sshkey_free(চাবি);
			ফেরত ফাঁকা;
		}
		যদি ((rsa_n = BN_new()) == ফাঁকা ||
		    (rsa_d = BN_new()) == ফাঁকা ||
		    (rsa_p = BN_new()) == ফাঁকা ||
		    (rsa_q = BN_new()) == ফাঁকা ||
		    (rsa_iqmp = BN_new()) == ফাঁকা)
			fatal_f("BN_new");
		বাফার_get_bignum_bits(b, rsa_d);
		বাফার_get_bignum_bits(b, rsa_n);
		বাফার_get_bignum_bits(b, rsa_iqmp);
		বাফার_get_bignum_bits(b, rsa_q);
		বাফার_get_bignum_bits(b, rsa_p);
		যদি ((r = ssh_rsa_complete_crt_parameters(rsa_d, rsa_p, rsa_q,
		    rsa_iqmp, &rsa_dmp1, &rsa_dmq1)) != 0)
			fatal_fr(r, "generate RSA CRT parameters");
		EVP_PKEY_free(চাবি->pkey);
		যদি ((চাবি->pkey = EVP_PKEY_new()) == ফাঁকা)
			fatal_f("EVP_PKEY_new failed");
		যদি ((rsa = RSA_new()) == ফাঁকা)
			fatal_f("RSA_new failed");
		যদি (!RSA_set0_চাবি(rsa, rsa_n, rsa_e, rsa_d))
			fatal_f("RSA_set0_key failed");
		rsa_n = rsa_e = rsa_d = ফাঁকা; /* transferred */
		যদি (!RSA_set0_factors(rsa, rsa_p, rsa_q))
			fatal_f("RSA_set0_factors failed");
		rsa_p = rsa_q = ফাঁকা; /* transferred */
		যদি (RSA_set0_crt_params(rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp) != 1)
			fatal_f("RSA_set0_crt_params failed");
		rsa_dmp1 = rsa_dmq1 = rsa_iqmp = ফাঁকা;
		যদি (EVP_PKEY_set1_RSA(চাবি->pkey, rsa) != 1)
			fatal_f("EVP_PKEY_set1_RSA failed");
		RSA_free(rsa);
		alg = "rsa-sha2-256";
		বিরতি;
	}
	rlen = sshbuf_len(b);
	যদি (rlen != 0)
		error_f("remaining bytes in key blob %d", rlen);

	/* try the key */
	যদি ((r = sshkey_sign(চাবি, &sig, &slen, তথ্য, আকার(তথ্য),
	    alg, ফাঁকা, ফাঁকা, 0)) != 0)
		error_fr(r, "signing with converted key failed");
	অন্যথা যদি ((r = sshkey_verify(চাবি, sig, slen, তথ্য, আকার(তথ্য),
	    alg, 0, ফাঁকা)) != 0)
		error_fr(r, "verification with converted key failed");
	যদি (r != 0) {
		sshkey_free(চাবি);
		মুক্ত(sig);
		ফেরত ফাঁকা;
	}
	মুক্ত(sig);
	ফেরত চাবি;
}

স্থির পূর্ণসংখ্যা
get_সারি(FILE *fp, অক্ষর *সারি, আকার_t len)
{
	পূর্ণসংখ্যা c;
	আকার_t pos = 0;

	সারি[0] = '\0';
	যখন ((c = fgetc(fp)) != EOF) {
		যদি (pos >= len - 1)
			fatal("input line too long.");
		নির্বাচন (c) {
		ক্ষেত্র '\r':
			c = fgetc(fp);
			যদি (c != EOF && c != '\n' && ungetc(c, fp) == EOF)
				fatal("unget: %s", strerror(errno));
			ফেরত pos;
		ক্ষেত্র '\n':
			ফেরত pos;
		}
		সারি[pos++] = c;
		সারি[pos] = '\0';
	}
	/* We reached EOF */
	ফেরত -1;
}

স্থির শূন্য
do_convert_from_ssh2(কাঠামো passwd *pw, কাঠামো sshkey **k, পূর্ণসংখ্যা *ব্যক্তিগত)
{
	পূর্ণসংখ্যা r, blen, escaped = 0;
	u_int len;
	অক্ষর সারি[1024];
	কাঠামো sshbuf *buf;
	অক্ষর encoded[8096];
	FILE *fp;

	যদি ((buf = sshbuf_new()) == ফাঁকা)
		fatal("sshbuf_new failed");
	যদি ((fp = fopen(identity_file, "r")) == ফাঁকা)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));
	encoded[0] = '\0';
	যখন ((blen = get_সারি(fp, সারি, আকার(সারি))) != -1) {
		যদি (blen > 0 && সারি[blen - 1] == '\\')
			escaped++;
		যদি (strncmp(সারি, "----", 4) == 0 ||
		    strstr(সারি, ": ") != ফাঁকা) {
			যদি (strstr(সারি, SSH_COM_PRIVATE_BEGIN) != ফাঁকা)
				*ব্যক্তিগত = 1;
			যদি (strstr(সারি, " END ") != ফাঁকা) {
				বিরতি;
			}
			/* fprintf(stderr, "ignore: %s", line); */
			চালু;
		}
		যদি (escaped) {
			escaped--;
			/* fprintf(stderr, "escaped: %s", line); */
			চালু;
		}
		strlcat(encoded, সারি, আকার(encoded));
	}
	len = strlen(encoded);
	যদি (((len % 4) == 3) &&
	    (encoded[len-1] == '=') &&
	    (encoded[len-2] == '=') &&
	    (encoded[len-3] == '='))
		encoded[len-3] = '\0';
	যদি ((r = sshbuf_b64tod(buf, encoded)) != 0)
		fatal_fr(r, "base64 decode");
	যদি (*ব্যক্তিগত) {
		যদি ((*k = do_convert_private_ssh2(buf)) == ফাঁকা)
			fatal_f("private key conversion failed");
	} অন্যথা যদি ((r = sshkey_fromb(buf, k)) != 0)
		fatal_fr(r, "parse key");
	sshbuf_free(buf);
	fclose(fp);
}

স্থির শূন্য
do_convert_from_pkcs8(কাঠামো sshkey **k, পূর্ণসংখ্যা *ব্যক্তিগত)
{
	EVP_PKEY *pubkey;
	FILE *fp;

	যদি ((fp = fopen(identity_file, "r")) == ফাঁকা)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));
	যদি ((pubkey = PEM_read_PUBKEY(fp, ফাঁকা, ফাঁকা, ফাঁকা)) == ফাঁকা) {
		fatal_f("%s is not a recognised public key format",
		    identity_file);
	}
	fclose(fp);
	নির্বাচন (EVP_PKEY_base_id(pubkey)) {
	ক্ষেত্র EVP_PKEY_RSA:
		যদি ((*k = sshkey_new(চাবি_UNSPEC)) == ফাঁকা)
			fatal("sshkey_new failed");
		(*k)->type = চাবি_RSA;
		(*k)->pkey = pubkey;
		pubkey = ফাঁকা;
		বিরতি;
	ক্ষেত্র EVP_PKEY_EC:
		যদি ((*k = sshkey_new(চাবি_UNSPEC)) == ফাঁকা)
			fatal("sshkey_new failed");
		যদি (((*k)->ecdsa_nid = sshkey_ecdsa_fixup_group(pubkey)) == -1)
			fatal("sshkey_ecdsa_fixup_group failed");
		(*k)->type = চাবি_ECDSA;
		(*k)->pkey = pubkey;
		pubkey = ফাঁকা;
		বিরতি;
	পূর্বনির্ধারিত:
		fatal_f("unsupported pubkey type %d",
		    EVP_PKEY_base_id(pubkey));
	}
	EVP_PKEY_free(pubkey);
}

স্থির শূন্য
do_convert_from_pem(কাঠামো sshkey **k, পূর্ণসংখ্যা *ব্যক্তিগত)
{
	FILE *fp;
	RSA *rsa;

	যদি ((fp = fopen(identity_file, "r")) == ফাঁকা)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));
	যদি ((rsa = PEM_read_RSAPublic_চাবি(fp, ফাঁকা, ফাঁকা, ফাঁকা)) != ফাঁকা) {
		যদি ((*k = sshkey_new(চাবি_UNSPEC)) == ফাঁকা)
			fatal("sshkey_new failed");
		যদি (((*k)->pkey = EVP_PKEY_new()) == ফাঁকা)
			fatal("EVP_PKEY_new failed");
		(*k)->type = চাবি_RSA;
		যদি (EVP_PKEY_set1_RSA((*k)->pkey, rsa) != 1)
			fatal("EVP_PKEY_set1_RSA failed");
		RSA_free(rsa);
		fclose(fp);
		ফেরত;
	}
	fatal_f("unrecognised raw private key format");
}

স্থির শূন্য
do_convert_from(কাঠামো passwd *pw)
{
	কাঠামো sshkey *k = ফাঁকা;
	পূর্ণসংখ্যা r, ব্যক্তিগত = 0, ok = 0;
	কাঠামো stat st;

	যদি (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	যদি (stat(identity_file, &st) == -1)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));

	নির্বাচন (convert_format) {
	ক্ষেত্র FMT_RFC4716:
		do_convert_from_ssh2(pw, &k, &ব্যক্তিগত);
		বিরতি;
	ক্ষেত্র FMT_PKCS8:
		do_convert_from_pkcs8(&k, &ব্যক্তিগত);
		বিরতি;
	ক্ষেত্র FMT_PEM:
		do_convert_from_pem(&k, &ব্যক্তিগত);
		বিরতি;
	পূর্বনির্ধারিত:
		fatal_f("unknown key format %d", convert_format);
	}

	যদি (!ব্যক্তিগত) {
		যদি ((r = sshkey_write(k, stdout)) == 0)
			ok = 1;
		যদি (ok)
			fprintf(stdout, "\n");
	} অন্যথা {
		নির্বাচন (k->type) {
		ক্ষেত্র চাবি_ECDSA:
			ok = PEM_write_ECPrivate_চাবি(stdout,
			    EVP_PKEY_get0_EC_চাবি(k->pkey), ফাঁকা, ফাঁকা, 0,
			    ফাঁকা, ফাঁকা);
			বিরতি;
		ক্ষেত্র চাবি_RSA:
			ok = PEM_write_RSAPrivate_চাবি(stdout,
			    EVP_PKEY_get0_RSA(k->pkey), ফাঁকা, ফাঁকা, 0,
			    ফাঁকা, ফাঁকা);
			বিরতি;
		পূর্বনির্ধারিত:
			fatal_f("unsupported key type %s", sshkey_type(k));
		}
	}

	যদি (!ok)
		fatal("key write failed");
	sshkey_free(k);
}
#endif

স্থির শূন্য
do_print_public(কাঠামো passwd *pw)
{
	কাঠামো sshkey *prv;
	কাঠামো stat st;
	পূর্ণসংখ্যা r;
	অক্ষর *comment = ফাঁকা;

	যদি (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	যদি (stat(identity_file, &st) == -1)
		fatal("%s: %s", identity_file, strerror(errno));
	prv = load_identity(identity_file, &comment);
	যদি ((r = sshkey_write(prv, stdout)) != 0)
		fatal_fr(r, "write key");
	যদি (comment != ফাঁকা && *comment != '\0')
		fprintf(stdout, " %s", comment);
	fprintf(stdout, "\n");
	যদি (sshkey_is_sk(prv)) {
		debug("sk_application: \"%s\", sk_flags 0x%02x",
			prv->sk_application, prv->sk_flags);
	}
	sshkey_free(prv);
	মুক্ত(comment);
	exit(0);
}

স্থির শূন্য
do_download(কাঠামো passwd *pw)
{
#ifdef ENABLE_PKCS11
	কাঠামো sshkey **চাবিগুলি = ফাঁকা;
	পূর্ণসংখ্যা i, nkeys;
	গণনা sshkey_fp_rep rep;
	পূর্ণসংখ্যা fptype;
	অক্ষর *fp, *ra, **comments = ফাঁকা;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;

	pkcs11_init(1);
	nkeys = pkcs11_add_provider(pkcs11provider, ফাঁকা, &চাবিগুলি, &comments);
	যদি (nkeys <= 0)
		fatal("cannot read public key from pkcs11");
	জন্য (i = 0; i < nkeys; i++) {
		যদি (print_fingerprint) {
			fp = sshkey_fingerprint(চাবিগুলি[i], fptype, rep);
			ra = sshkey_fingerprint(চাবিগুলি[i], fingerprint_hash,
			    SSH_FP_RANDOMART);
			যদি (fp == ফাঁকা || ra == ফাঁকা)
				fatal_f("sshkey_fingerprint fail");
			printf("%u %s %s (PKCS11 key)\n", sshkey_আকার(চাবিগুলি[i]),
			    fp, sshkey_type(চাবিগুলি[i]));
			যদি (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
				printf("%s\n", ra);
			মুক্ত(ra);
			মুক্ত(fp);
		} অন্যথা {
			(শূন্য) sshkey_write(চাবিগুলি[i], stdout); /* XXX check */
			fprintf(stdout, "%s%s\n",
			    *(comments[i]) == '\0' ? "" : " ", comments[i]);
		}
		মুক্ত(comments[i]);
		sshkey_free(চাবিগুলি[i]);
	}
	মুক্ত(comments);
	মুক্ত(চাবিগুলি);
	pkcs11_terminate();
	exit(0);
#অন্যথা
	fatal("no pkcs11 support");
#endif /* ENABLE_PKCS11 */
}

স্থির কাঠামো sshkey *
try_read_চাবি(অক্ষর **cpp)
{
	কাঠামো sshkey *ret;
	পূর্ণসংখ্যা r;

	যদি ((ret = sshkey_new(চাবি_UNSPEC)) == ফাঁকা)
		fatal("sshkey_new failed");
	যদি ((r = sshkey_read(ret, cpp)) == 0)
		ফেরত ret;
	/* Not a key */
	sshkey_free(ret);
	ফেরত ফাঁকা;
}

স্থির শূন্য
fingerprint_one_চাবি(ধ্রুবক কাঠামো sshkey *সর্বজনীন, ধ্রুবক অক্ষর *comment)
{
	অক্ষর *fp = ফাঁকা, *ra = ফাঁকা;
	গণনা sshkey_fp_rep rep;
	পূর্ণসংখ্যা fptype;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;
	fp = sshkey_fingerprint(সর্বজনীন, fptype, rep);
	ra = sshkey_fingerprint(সর্বজনীন, fingerprint_hash, SSH_FP_RANDOMART);
	যদি (fp == ফাঁকা || ra == ফাঁকা)
		fatal_f("sshkey_fingerprint failed");
	mprintf("%u %s %s (%s)\n", sshkey_আকার(সর্বজনীন), fp,
	    comment ? comment : "no comment", sshkey_type(সর্বজনীন));
	যদি (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
		printf("%s\n", ra);
	মুক্ত(ra);
	মুক্ত(fp);
}

স্থির শূন্য
fingerprint_private(ধ্রুবক অক্ষর *path)
{
	কাঠামো stat st;
	অক্ষর *comment = ফাঁকা;
	কাঠামো sshkey *privkey = ফাঁকা, *pubkey = ফাঁকা;
	পূর্ণসংখ্যা r;

	যদি (stat(identity_file, &st) == -1)
		fatal("%s: %s", path, strerror(errno));
	যদি ((r = sshkey_load_public(path, &pubkey, &comment)) != 0)
		debug_r(r, "load public \"%s\"", path);
	যদি (pubkey == ফাঁকা || comment == ফাঁকা || *comment == '\0') {
		মুক্ত(comment);
		যদি ((r = sshkey_load_private(path, ফাঁকা,
		    &privkey, &comment)) != 0)
			debug_r(r, "load private \"%s\"", path);
	}
	যদি (pubkey == ফাঁকা && privkey == ফাঁকা)
		fatal("%s is not a key file.", path);

	fingerprint_one_চাবি(pubkey == ফাঁকা ? privkey : pubkey, comment);
	sshkey_free(pubkey);
	sshkey_free(privkey);
	মুক্ত(comment);
}

স্থির শূন্য
do_fingerprint(কাঠামো passwd *pw)
{
	FILE *f;
	কাঠামো sshkey *সর্বজনীন = ফাঁকা;
	অক্ষর *comment = ফাঁকা, *cp, *ep, *সারি = ফাঁকা;
	আকার_t linesize = 0;
	পূর্ণসংখ্যা i, invalid = 1;
	ধ্রুবক অক্ষর *path;
	u_long lnum = 0;

	যদি (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	path = identity_file;

	যদি (strcmp(identity_file, "-") == 0) {
		f = stdin;
		path = "(stdin)";
	} অন্যথা যদি ((f = fopen(path, "r")) == ফাঁকা)
		fatal("%s: %s: %s", __progname, path, strerror(errno));

	যখন (getline(&সারি, &linesize, f) != -1) {
		lnum++;
		cp = সারি;
		cp[strcspn(cp, "\r\n")] = '\0';
		/* Trim leading space and comments */
		cp = সারি + strspn(সারি, " \t");
		যদি (*cp == '#' || *cp == '\0')
			চালু;

		/*
		 * Input may be plain keys, private keys, authorized_keys
		 * or known_hosts.
		 */

		/*
		 * Try private keys first. Assume a key is private if
		 * "SSH PRIVATE KEY" appears on the first line and we're
		 * not reading from stdin (XXX support private keys on stdin).
		 */
		যদি (lnum == 1 && strcmp(identity_file, "-") != 0 &&
		    strstr(cp, "PRIVATE KEY") != ফাঁকা) {
			মুক্ত(সারি);
			fclose(f);
			fingerprint_private(path);
			exit(0);
		}

		/*
		 * If it's not a private key, then this must be prepared to
		 * accept a public key prefixed with a hostname or options.
		 * Try a bare key first, otherwise skip the leading stuff.
		 */
		comment = ফাঁকা;
		যদি ((সর্বজনীন = try_read_চাবি(&cp)) == ফাঁকা) {
			i = strtol(cp, &ep, 10);
			যদি (i == 0 || ep == ফাঁকা ||
			    (*ep != ' ' && *ep != '\t')) {
				পূর্ণসংখ্যা quoted = 0;

				comment = cp;
				জন্য (; *cp && (quoted || (*cp != ' ' &&
				    *cp != '\t')); cp++) {
					যদি (*cp == '\\' && cp[1] == '"')
						cp++;	/* Skip both */
					অন্যথা যদি (*cp == '"')
						quoted = !quoted;
				}
				যদি (!*cp)
					চালু;
				*cp++ = '\0';
			}
		}
		/* Retry after parsing leading hostname/key options */
		যদি (সর্বজনীন == ফাঁকা && (সর্বজনীন = try_read_চাবি(&cp)) == ফাঁকা) {
			debug("%s:%lu: not a public key", path, lnum);
			চালু;
		}

		/* Find trailing comment, if any */
		জন্য (; *cp == ' ' || *cp == '\t'; cp++)
			;
		যদি (*cp != '\0' && *cp != '#')
			comment = cp;

		fingerprint_one_চাবি(সর্বজনীন, comment);
		sshkey_free(সর্বজনীন);
		invalid = 0; /* One good key in the file is sufficient */
	}
	fclose(f);
	মুক্ত(সারি);

	যদি (invalid)
		fatal("%s is not a public key file.", path);
	exit(0);
}

স্থির শূন্য
do_gen_all_hostkeys(কাঠামো passwd *pw)
{
	কাঠামো {
		অক্ষর *চাবি_type;
		অক্ষর *চাবি_type_display;
		অক্ষর *path;
	} চাবি_types[] = {
#ifdef WITH_OPENSSL
		{ "rsa", "RSA" ,PATH_HOST_RSA_চাবি_FILE },
		{ "ecdsa", "ECDSA",PATH_HOST_ECDSA_চাবি_FILE },
#endif /* WITH_OPENSSL */
		{ "ed25519", "ED25519",PATH_HOST_ED25519_চাবি_FILE },
#ifdef USE_MLDSA
		{ "mldsa44-ed25519", "MLDSA44-ED25519",
		     PATH_HOST_MLDSA44_ED25519_চাবি_FILE },
#endif
		{ ফাঁকা, ফাঁকা, ফাঁকা }
	};

	uint32_t bits = 0;
	পূর্ণসংখ্যা first = 0;
	কাঠামো stat st;
	কাঠামো sshkey *ব্যক্তিগত, *সর্বজনীন;
	অক্ষর comment[চাবি_COMMENT_MAX], *prv_tmp, *pub_tmp, *prv_file, *pub_file;
	পূর্ণসংখ্যা i, type, fd, r;

	জন্য (i = 0; চাবি_types[i].চাবি_type; i++) {
		সর্বজনীন = ব্যক্তিগত = ফাঁকা;
		prv_tmp = pub_tmp = prv_file = pub_file = ফাঁকা;

		xasprintf(&prv_file, "%s%s",
		    identity_file, চাবি_types[i].path);

		/* Check whether private key exists and is not zero-length */
		যদি (stat(prv_file, &st) == 0) {
			যদি (st.st_size != 0)
				যাও পরবর্তী;
		} অন্যথা যদি (errno != ENOENT) {
			error("Could not stat %s: %s", চাবি_types[i].path,
			    strerror(errno));
			যাও failnext;
		}

		/*
		 * Private key doesn't exist or is invalid; proceed with
		 * key generation.
		 */
		xasprintf(&prv_tmp, "%s%s.XXXXXXXXXX",
		    identity_file, চাবি_types[i].path);
		xasprintf(&pub_tmp, "%s%s.pub.XXXXXXXXXX",
		    identity_file, চাবি_types[i].path);
		xasprintf(&pub_file, "%s%s.pub",
		    identity_file, চাবি_types[i].path);

		যদি (first == 0) {
			first = 1;
			printf("%s: generating new host keys: ", __progname);
		}
		printf("%s ", চাবি_types[i].চাবি_type_display);
		fflush(stdout);
		type = sshkey_type_from_shortname(চাবি_types[i].চাবি_type);
		যদি ((fd = mkstemp(prv_tmp)) == -1) {
			error("Could not save your private key in %s: %s",
			    prv_tmp, strerror(errno));
			যাও failnext;
		}
		(শূন্য)close(fd); /* just using mkstemp() to reserve a name */
		bits = 0;
		type_bits_valid(type, ফাঁকা, &bits);
		যদি ((r = sshkey_generate(type, bits, &ব্যক্তিগত)) != 0) {
			error_r(r, "sshkey_generate failed");
			যাও failnext;
		}
		যদি ((r = sshkey_from_private(ব্যক্তিগত, &সর্বজনীন)) != 0)
			fatal_fr(r, "sshkey_from_private");
		snprintf(comment, আকার comment, "%s@%s", pw->pw_name,
		    hostname);
		যদি ((r = sshkey_save_private(ব্যক্তিগত, prv_tmp, "",
		    comment, private_চাবি_format, openssh_format_cipher,
		    rounds)) != 0) {
			error_r(r, "Saving key \"%s\" failed", prv_tmp);
			যাও failnext;
		}
		যদি ((fd = mkstemp(pub_tmp)) == -1) {
			error("Could not save your public key in %s: %s",
			    pub_tmp, strerror(errno));
			যাও failnext;
		}
		(শূন্য)fchmod(fd, 0644);
		(শূন্য)close(fd);
		যদি ((r = sshkey_save_public(সর্বজনীন, pub_tmp, comment)) != 0) {
			error_r(r, "Unable to save public key to %s",
			    identity_file);
			যাও failnext;
		}

		/* Rename temporary files to their permanent locations. */
		যদি (rename(pub_tmp, pub_file) != 0) {
			error("Unable to move %s into position: %s",
			    pub_file, strerror(errno));
			যাও failnext;
		}
		যদি (rename(prv_tmp, prv_file) != 0) {
			error("Unable to move %s into position: %s",
			    চাবি_types[i].path, strerror(errno));
 failnext:
			first = 0;
			যাও পরবর্তী;
		}
 পরবর্তী:
		sshkey_free(ব্যক্তিগত);
		sshkey_free(সর্বজনীন);
		মুক্ত(prv_tmp);
		মুক্ত(pub_tmp);
		মুক্ত(prv_file);
		মুক্ত(pub_file);
	}
	যদি (first != 0)
		printf("\n");
}

কাঠামো known_hosts_ctx {
	ধ্রুবক অক্ষর *host;	/* Hostname searched for in find/delete case */
	FILE *out;		/* Output file, stdout for find_hosts case */
	পূর্ণসংখ্যা has_unhashed;	/* When hashing, original had unhashed hosts */
	পূর্ণসংখ্যা found_চাবি;		/* For find/delete, host was found */
	পূর্ণসংখ্যা invalid;		/* File contained invalid items; don't delete */
	পূর্ণসংখ্যা hash_hosts;		/* Hash hostnames as we go */
	পূর্ণসংখ্যা find_host;		/* Search for specific hostname */
	পূর্ণসংখ্যা delete_host;	/* Delete host from known_hosts */
};

স্থির পূর্ণসংখ্যা
known_hosts_hash(কাঠামো hostkey_foreach_সারি *l, শূন্য *_ctx)
{
	কাঠামো known_hosts_ctx *ctx = (কাঠামো known_hosts_ctx *)_ctx;
	অক্ষর *hashed, *cp, *hosts, *ohosts;
	পূর্ণসংখ্যা has_wild = l->hosts && strcspn(l->hosts, "*?!") != strlen(l->hosts);
	পূর্ণসংখ্যা was_hashed = l->hosts && l->hosts[0] == HASH_DELIM;

	নির্বাচন (l->status) {
	ক্ষেত্র HKF_STATUS_OK:
	ক্ষেত্র HKF_STATUS_MATCHED:
		/*
		 * Don't hash hosts already hashed, with wildcard
		 * characters or a CA/revocation marker.
		 */
		যদি (was_hashed || has_wild || l->marker != MRK_NONE) {
			fprintf(ctx->out, "%s\n", l->সারি);
			যদি (has_wild && !ctx->find_host) {
				logit("%s:%lu: ignoring host name "
				    "with wildcard: %.64s", l->path,
				    l->linenum, l->hosts);
			}
			ফেরত 0;
		}
		/*
		 * Split any comma-separated hostnames from the host list,
		 * hash and store separately.
		 */
		ohosts = hosts = xstrdup(l->hosts);
		যখন ((cp = strsep(&hosts, ",")) != ফাঁকা && *cp != '\0') {
			lowercase(cp);
			যদি ((hashed = host_hash(cp, ফাঁকা, 0)) == ফাঁকা)
				fatal("hash_host failed");
			fprintf(ctx->out, "%s %s\n", hashed, l->rawkey);
			মুক্ত(hashed);
			ctx->has_unhashed = 1;
		}
		মুক্ত(ohosts);
		ফেরত 0;
	ক্ষেত্র HKF_STATUS_INVALID:
		/* Retain invalid lines, but mark file as invalid. */
		ctx->invalid = 1;
		logit("%s:%lu: invalid line", l->path, l->linenum);
		/* FALLTHROUGH */
	পূর্বনির্ধারিত:
		fprintf(ctx->out, "%s\n", l->সারি);
		ফেরত 0;
	}
	/* NOTREACHED */
	ফেরত -1;
}

স্থির পূর্ণসংখ্যা
known_hosts_find_delete(কাঠামো hostkey_foreach_সারি *l, শূন্য *_ctx)
{
	কাঠামো known_hosts_ctx *ctx = (কাঠামো known_hosts_ctx *)_ctx;
	গণনা sshkey_fp_rep rep;
	পূর্ণসংখ্যা fptype;
	অক্ষর *fp = ফাঁকা, *ra = ফাঁকা;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;

	যদি (l->status == HKF_STATUS_MATCHED) {
		যদি (ctx->delete_host) {
			যদি (l->marker != MRK_NONE) {
				/* Don't remove CA and revocation lines */
				fprintf(ctx->out, "%s\n", l->সারি);
			} অন্যথা {
				/*
				 * Hostname matches and has no CA/revoke
				 * marker, delete it by *not* writing the
				 * line to ctx->out.
				 */
				ctx->found_চাবি = 1;
				যদি (!quiet)
					printf("# Host %s found: line %lu\n",
					    ctx->host, l->linenum);
			}
			ফেরত 0;
		} অন্যথা যদি (ctx->find_host) {
			ctx->found_চাবি = 1;
			যদি (!quiet) {
				printf("# Host %s found: line %lu %s\n",
				    ctx->host,
				    l->linenum, l->marker == MRK_CA ? "CA" :
				    (l->marker == MRK_REVOKE ? "REVOKED" : ""));
			}
			যদি (ctx->hash_hosts)
				known_hosts_hash(l, ctx);
			অন্যথা যদি (print_fingerprint) {
				fp = sshkey_fingerprint(l->চাবি, fptype, rep);
				ra = sshkey_fingerprint(l->চাবি,
				    fingerprint_hash, SSH_FP_RANDOMART);
				যদি (fp == ফাঁকা || ra == ফাঁকা)
					fatal_f("sshkey_fingerprint failed");
				mprintf("%s %s %s%s%s\n", ctx->host,
				    sshkey_type(l->চাবি), fp,
				    l->comment[0] ? " " : "",
				    l->comment);
				যদি (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
					printf("%s\n", ra);
				মুক্ত(ra);
				মুক্ত(fp);
			} অন্যথা
				fprintf(ctx->out, "%s\n", l->সারি);
			ফেরত 0;
		}
	} অন্যথা যদি (ctx->delete_host) {
		/* Retain non-matching hosts when deleting */
		যদি (l->status == HKF_STATUS_INVALID) {
			ctx->invalid = 1;
			logit("%s:%lu: invalid line", l->path, l->linenum);
		}
		fprintf(ctx->out, "%s\n", l->সারি);
	}
	ফেরত 0;
}

স্থির শূন্য
do_known_hosts(কাঠামো passwd *pw, ধ্রুবক অক্ষর *name, পূর্ণসংখ্যা find_host,
    পূর্ণসংখ্যা delete_host, পূর্ণসংখ্যা hash_hosts)
{
	অক্ষর *cp, tmp[PATH_MAX], old[PATH_MAX];
	পূর্ণসংখ্যা r, fd, oerrno, inplace = 0;
	কাঠামো known_hosts_ctx ctx;
	u_int foreach_options;
	কাঠামো stat sb;

	যদি (!have_identity) {
		cp = tilde_expand_filename(_PATH_SSH_USER_HOSTFILE, pw->pw_uid);
		যদি (strlcpy(identity_file, cp, আকার(identity_file)) >=
		    আকার(identity_file))
			fatal("Specified known hosts path too long");
		মুক্ত(cp);
		have_identity = 1;
	}
	যদি (stat(identity_file, &sb) != 0)
		fatal("Cannot stat %s: %s", identity_file, strerror(errno));

	memset(&ctx, 0, আকার(ctx));
	ctx.out = stdout;
	ctx.host = name;
	ctx.hash_hosts = hash_hosts;
	ctx.find_host = find_host;
	ctx.delete_host = delete_host;

	/*
	 * Find hosts goes to stdout, hash and deletions happen in-place
	 * A corner case is ssh-keygen -HF foo, which should go to stdout
	 */
	যদি (!find_host && (hash_hosts || delete_host)) {
		যদি (strlcpy(tmp, identity_file, আকার(tmp)) >= আকার(tmp) ||
		    strlcat(tmp, ".XXXXXXXXXX", আকার(tmp)) >= আকার(tmp) ||
		    strlcpy(old, identity_file, আকার(old)) >= আকার(old) ||
		    strlcat(old, ".old", আকার(old)) >= আকার(old))
			fatal("known_hosts path too long");
		umask(077);
		যদি ((fd = mkstemp(tmp)) == -1)
			fatal("mkstemp: %s", strerror(errno));
		যদি ((ctx.out = fdopen(fd, "w")) == ফাঁকা) {
			oerrno = errno;
			unlink(tmp);
			fatal("fdopen: %s", strerror(oerrno));
		}
		(শূন্য)fchmod(fd, sb.st_mode & 0644);
		inplace = 1;
	}
	/* XXX support identity_file == "-" for stdin */
	foreach_options = find_host ? HKF_WANT_MATCH : 0;
	foreach_options |= print_fingerprint ? HKF_WANT_PARSE_চাবি : 0;
	যদি ((r = hostkeys_foreach(identity_file, (find_host || !hash_hosts) ?
	    known_hosts_find_delete : known_hosts_hash, &ctx, name, ফাঁকা,
	    foreach_options, 0)) != 0) {
		যদি (inplace)
			unlink(tmp);
		fatal_fr(r, "hostkeys_foreach");
	}

	যদি (inplace)
		fclose(ctx.out);

	যদি (ctx.invalid) {
		error("%s is not a valid known_hosts file.", identity_file);
		যদি (inplace) {
			error("Not replacing existing known_hosts "
			    "file because of errors");
			unlink(tmp);
		}
		exit(1);
	} অন্যথা যদি (delete_host && !ctx.found_চাবি) {
		logit("Host %s not found in %s", name, identity_file);
		যদি (inplace)
			unlink(tmp);
	} অন্যথা যদি (inplace) {
		/* Backup existing file */
		যদি (unlink(old) == -1 && errno != ENOENT)
			fatal("unlink %.100s: %s", old, strerror(errno));
		যদি (link(identity_file, old) == -1)
			fatal("link %.100s to %.100s: %s", identity_file, old,
			    strerror(errno));
		/* Move new one into place */
		যদি (rename(tmp, identity_file) == -1) {
			error("rename\"%s\" to \"%s\": %s", tmp, identity_file,
			    strerror(errno));
			unlink(tmp);
			unlink(old);
			exit(1);
		}

		printf("%s updated.\n", identity_file);
		printf("Original contents retained as %s\n", old);
		যদি (ctx.has_unhashed) {
			logit("WARNING: %s contains unhashed entries", old);
			logit("Delete this file to ensure privacy "
			    "of hostnames");
		}
	}

	exit (find_host && !ctx.found_চাবি);
}

/*
 * Perform changing a passphrase.  The argument is the passwd structure
 * for the current user.
 */
স্থির শূন্য
do_change_passphrase(কাঠামো passwd *pw, অক্ষর * ধ্রুবক *opts, আকার_t nopts)
{
	অক্ষর *comment;
	অক্ষর *old_passphrase, *passphrase1, *passphrase2;
	কাঠামো stat st;
	কাঠামো sshkey *ব্যক্তিগত;
	পূর্ণসংখ্যা r;
	আকার_t i;

	যদি (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	যদি (stat(identity_file, &st) == -1)
		fatal("%s: %s", identity_file, strerror(errno));
	/* Try to load the file with empty passphrase. */
	r = sshkey_load_private(identity_file, "", &ব্যক্তিগত, &comment);
	যদি (r == SSH_ERR_চাবি_WRONG_PASSPHRASE) {
		যদি (identity_passphrase)
			old_passphrase = xstrdup(identity_passphrase);
		অন্যথা
			old_passphrase =
			    read_passphrase("Enter old passphrase: ",
			    RP_ALLOW_STDIN);
		r = sshkey_load_private(identity_file, old_passphrase,
		    &ব্যক্তিগত, &comment);
		freezero(old_passphrase, strlen(old_passphrase));
		যদি (r != 0)
			যাও badkey;
	} অন্যথা যদি (r != 0) {
 badkey:
		fatal_r(r, "Failed to load key %s", identity_file);
	}
	যদি (comment)
		mprintf("Key has comment '%s'\n", comment);

	/* All current -O options relate to FIDO keys only */
	যদি (nopts != 0 && !sshkey_is_sk(ব্যক্তিগত)) {
		fatal("FIDO-specific option requested for non-FIDO key %s",
		    identity_file);
	}
	যদি (sshkey_is_sk(ব্যক্তিগত)) {
		debug_f("%s: original FIDO key flags: "
		    "%stouch-required %sverify-required", identity_file,
		    (ব্যক্তিগত->sk_flags & SSH_SK_USER_PRESENCE_REQD) ? "": "no-",
		    (ব্যক্তিগত->sk_flags & SSH_SK_USER_VERIFICATION_REQD) ? "" : "no-");
	}
	জন্য (i = 0; i < nopts; i++) {
		যদি (strcasecmp(opts[i], "touch-required") == 0)
			ব্যক্তিগত->sk_flags |= SSH_SK_USER_PRESENCE_REQD;
		অন্যথা যদি (strcasecmp(opts[i], "no-touch-required") == 0)
			ব্যক্তিগত->sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
		অন্যথা যদি (strcasecmp(opts[i], "verify-required") == 0)
			ব্যক্তিগত->sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
		অন্যথা যদি (strcasecmp(opts[i], "no-verify-required") == 0)
			ব্যক্তিগত->sk_flags &= ~SSH_SK_USER_VERIFICATION_REQD;
		অন্যথা {
			fatal("Option \"%s\" is unsupported for "
			    "key passphrase change", opts[i]);
		}
	}
	যদি (sshkey_is_sk(ব্যক্তিগত) && nopts != 0) {
		debug_f("%s: updated FIDO key flags: "
		    "%stouch-required %sverify-required", identity_file,
		    (ব্যক্তিগত->sk_flags & SSH_SK_USER_PRESENCE_REQD) ? "": "no-",
		    (ব্যক্তিগত->sk_flags & SSH_SK_USER_VERIFICATION_REQD) ? "" : "no-");
	}

	/* Ask the new passphrase (twice). */
	যদি (identity_new_passphrase) {
		passphrase1 = xstrdup(identity_new_passphrase);
		passphrase2 = ফাঁকা;
	} অন্যথা {
		passphrase1 =
			read_passphrase("Enter new passphrase (empty for no "
			    "passphrase): ", RP_ALLOW_STDIN);
		passphrase2 = read_passphrase("Enter same passphrase again: ",
		    RP_ALLOW_STDIN);

		/* Verify that they are the same. */
		যদি (strcmp(passphrase1, passphrase2) != 0) {
			explicit_bzero(passphrase1, strlen(passphrase1));
			explicit_bzero(passphrase2, strlen(passphrase2));
			মুক্ত(passphrase1);
			মুক্ত(passphrase2);
			printf("Pass phrases do not match.  Try again.\n");
			exit(1);
		}
		/* Destroy the other copy. */
		freezero(passphrase2, strlen(passphrase2));
	}

	/* Save the file using the new passphrase. */
	যদি ((r = sshkey_save_private(ব্যক্তিগত, identity_file, passphrase1,
	    comment, private_চাবি_format, openssh_format_cipher, rounds)) != 0) {
		error_r(r, "Saving key \"%s\" failed", identity_file);
		freezero(passphrase1, strlen(passphrase1));
		sshkey_free(ব্যক্তিগত);
		মুক্ত(comment);
		exit(1);
	}
	/* Destroy the passphrase and the copy of the key in memory. */
	freezero(passphrase1, strlen(passphrase1));
	sshkey_free(ব্যক্তিগত);		 /* Destroys contents */
	মুক্ত(comment);

	printf("Your identification has been saved with the new passphrase.\n");
	exit(0);
}

/*
 * Print the SSHFP RR.
 */
স্থির পূর্ণসংখ্যা
do_print_resource_record(কাঠামো passwd *pw, অক্ষর *fname, অক্ষর *hname,
    পূর্ণসংখ্যা print_generic, অক্ষর * ধ্রুবক *opts, আকার_t nopts)
{
	কাঠামো sshkey *সর্বজনীন;
	অক্ষর *comment = ফাঁকা;
	ধ্রুবক অক্ষর *p;
	কাঠামো stat st;
	পূর্ণসংখ্যা r, hash = -1;
	আকার_t i;

	জন্য (i = 0; i < nopts; i++) {
		যদি ((p = strprefix(opts[i], "hashalg=", 1)) != ফাঁকা) {
			যদি ((hash = ssh_digest_alg_by_name(p)) == -1)
				fatal("Unsupported hash algorithm");
		} অন্যথা {
			error("Invalid option \"%s\"", opts[i]);
			ফেরত SSH_ERR_INVALID_ARGUMENT;
		}
	}
	যদি (fname == ফাঁকা)
		fatal_f("no filename");
	যদি (stat(fname, &st) == -1) {
		যদি (errno == ENOENT)
			ফেরত 0;
		fatal("%s: %s", fname, strerror(errno));
	}
	যদি ((r = sshkey_load_public(fname, &সর্বজনীন, &comment)) != 0)
		fatal_r(r, "Failed to read v2 public key from \"%s\"", fname);
	export_dns_rr(hname, সর্বজনীন, stdout, print_generic, hash);
	sshkey_free(সর্বজনীন);
	মুক্ত(comment);
	ফেরত 1;
}

/*
 * Change the comment of a private key file.
 */
স্থির শূন্য
do_change_comment(কাঠামো passwd *pw, ধ্রুবক অক্ষর *identity_comment)
{
	অক্ষর new_comment[চাবি_COMMENT_MAX], *comment, *passphrase;
	কাঠামো sshkey *ব্যক্তিগত;
	কাঠামো sshkey *সর্বজনীন;
	কাঠামো stat st;
	পূর্ণসংখ্যা r;

	যদি (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	যদি (stat(identity_file, &st) == -1)
		fatal("%s: %s", identity_file, strerror(errno));
	যদি ((r = sshkey_load_private(identity_file, "",
	    &ব্যক্তিগত, &comment)) == 0)
		passphrase = xstrdup("");
	অন্যথা যদি (r != SSH_ERR_চাবি_WRONG_PASSPHRASE)
		fatal_r(r, "Cannot load private key \"%s\"", identity_file);
	অন্যথা {
		যদি (identity_passphrase)
			passphrase = xstrdup(identity_passphrase);
		অন্যথা যদি (identity_new_passphrase)
			passphrase = xstrdup(identity_new_passphrase);
		অন্যথা
			passphrase = read_passphrase("Enter passphrase: ",
			    RP_ALLOW_STDIN);
		/* Try to load using the passphrase. */
		যদি ((r = sshkey_load_private(identity_file, passphrase,
		    &ব্যক্তিগত, &comment)) != 0) {
			freezero(passphrase, strlen(passphrase));
			fatal_r(r, "Cannot load private key \"%s\"",
			    identity_file);
		}
	}

	যদি (ব্যক্তিগত->type != চাবি_ED25519 &&
	    private_চাবি_format != SSHKEY_PRIVATE_OPENSSH) {
		error("Comments are only supported for keys stored in "
		    "the new format (-o).");
		explicit_bzero(passphrase, strlen(passphrase));
		sshkey_free(ব্যক্তিগত);
		exit(1);
	}
	যদি (comment)
		printf("Old comment: %s\n", comment);
	অন্যথা
		printf("No existing comment\n");

	যদি (identity_comment) {
		strlcpy(new_comment, identity_comment, আকার(new_comment));
	} অন্যথা {
		printf("New comment: ");
		fflush(stdout);
		যদি (!fgets(new_comment, আকার(new_comment), stdin)) {
			explicit_bzero(passphrase, strlen(passphrase));
			sshkey_free(ব্যক্তিগত);
			exit(1);
		}
		new_comment[strcspn(new_comment, "\n")] = '\0';
	}
	যদি (comment != ফাঁকা && strcmp(comment, new_comment) == 0) {
		printf("No change to comment\n");
		মুক্ত(passphrase);
		sshkey_free(ব্যক্তিগত);
		মুক্ত(comment);
		exit(0);
	}

	/* Save the file using the new passphrase. */
	যদি ((r = sshkey_save_private(ব্যক্তিগত, identity_file, passphrase,
	    new_comment, private_চাবি_format, openssh_format_cipher,
	    rounds)) != 0) {
		error_r(r, "Saving key \"%s\" failed", identity_file);
		freezero(passphrase, strlen(passphrase));
		sshkey_free(ব্যক্তিগত);
		মুক্ত(comment);
		exit(1);
	}
	freezero(passphrase, strlen(passphrase));
	যদি ((r = sshkey_from_private(ব্যক্তিগত, &সর্বজনীন)) != 0)
		fatal_fr(r, "sshkey_from_private");
	sshkey_free(ব্যক্তিগত);

	strlcat(identity_file, ".pub", আকার(identity_file));
	যদি ((r = sshkey_save_public(সর্বজনীন, identity_file, new_comment)) != 0)
		fatal_r(r, "Unable to save public key to %s", identity_file);
	sshkey_free(সর্বজনীন);
	মুক্ত(comment);

	যদি (strlen(new_comment) > 0)
		printf("Comment '%s' applied\n", new_comment);
	অন্যথা
		printf("Comment removed\n");

	exit(0);
}

স্থির শূন্য
cert_ext_add(ধ্রুবক অক্ষর *চাবি, ধ্রুবক অক্ষর *মান, পূর্ণসংখ্যা iscrit)
{
	cert_ext = xreallocarray(cert_ext, ncert_ext + 1, আকার(*cert_ext));
	cert_ext[ncert_ext].চাবি = xstrdup(চাবি);
	cert_ext[ncert_ext].val = মান == ফাঁকা ? ফাঁকা : xstrdup(মান);
	cert_ext[ncert_ext].crit = iscrit;
	ncert_ext++;
}

/* qsort(3) comparison function for certificate extensions */
স্থির পূর্ণসংখ্যা
cert_ext_cmp(ধ্রুবক শূন্য *_a, ধ্রুবক শূন্য *_b)
{
	ধ্রুবক কাঠামো cert_ext *a = (ধ্রুবক কাঠামো cert_ext *)_a;
	ধ্রুবক কাঠামো cert_ext *b = (ধ্রুবক কাঠামো cert_ext *)_b;
	পূর্ণসংখ্যা r;

	যদি (a->crit != b->crit)
		ফেরত (a->crit < b->crit) ? -1 : 1;
	যদি ((r = strcmp(a->চাবি, b->চাবি)) != 0)
		ফেরত r;
	যদি ((a->val == ফাঁকা) != (b->val == ফাঁকা))
		ফেরত (a->val == ফাঁকা) ? -1 : 1;
	যদি (a->val != ফাঁকা && (r = strcmp(a->val, b->val)) != 0)
		ফেরত r;
	ফেরত 0;
}

#define OPTIONS_CRITICAL	1
#define OPTIONS_EXTENSIONS	2
স্থির শূন্য
prepare_options_buf(কাঠামো sshbuf *c, পূর্ণসংখ্যা which)
{
	কাঠামো sshbuf *b;
	আকার_t i;
	পূর্ণসংখ্যা r;
	ধ্রুবক কাঠামো cert_ext *ext;

	যদি ((b = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");
	sshbuf_reset(c);
	জন্য (i = 0; i < ncert_ext; i++) {
		ext = &cert_ext[i];
		যদি ((ext->crit && (which & OPTIONS_EXTENSIONS)) ||
		    (!ext->crit && (which & OPTIONS_CRITICAL)))
			চালু;
		যদি (ext->val == ফাঁকা) {
			/* flag option */
			debug3_f("%s", ext->চাবি);
			যদি ((r = sshbuf_put_cstring(c, ext->চাবি)) != 0 ||
			    (r = sshbuf_put_string(c, ফাঁকা, 0)) != 0)
				fatal_fr(r, "prepare flag");
		} অন্যথা {
			/* key/value option */
			debug3_f("%s=%s", ext->চাবি, ext->val);
			sshbuf_reset(b);
			যদি ((r = sshbuf_put_cstring(c, ext->চাবি)) != 0 ||
			    (r = sshbuf_put_cstring(b, ext->val)) != 0 ||
			    (r = sshbuf_put_stringb(c, b)) != 0)
				fatal_fr(r, "prepare k/v");
		}
	}
	sshbuf_free(b);
}

স্থির শূন্য
finalise_cert_exts(শূন্য)
{
	/* critical options */
	যদি (certflags_command != ফাঁকা)
		cert_ext_add("force-command", certflags_command, 1);
	যদি (certflags_src_addr != ফাঁকা)
		cert_ext_add("source-address", certflags_src_addr, 1);
	যদি ((certflags_flags & CERTOPT_REQUIRE_VERIFY) != 0)
		cert_ext_add("verify-required", ফাঁকা, 1);
	/* extensions */
	যদি ((certflags_flags & CERTOPT_X_FWD) != 0)
		cert_ext_add("permit-X11-forwarding", ফাঁকা, 0);
	যদি ((certflags_flags & CERTOPT_AGENT_FWD) != 0)
		cert_ext_add("permit-agent-forwarding", ফাঁকা, 0);
	যদি ((certflags_flags & CERTOPT_PORT_FWD) != 0)
		cert_ext_add("permit-port-forwarding", ফাঁকা, 0);
	যদি ((certflags_flags & CERTOPT_PTY) != 0)
		cert_ext_add("permit-pty", ফাঁকা, 0);
	যদি ((certflags_flags & CERTOPT_USER_RC) != 0)
		cert_ext_add("permit-user-rc", ফাঁকা, 0);
	যদি ((certflags_flags & CERTOPT_NO_REQUIRE_USER_PRESENCE) != 0)
		cert_ext_add("no-touch-required", ফাঁকা, 0);
	/* order lexically by key */
	যদি (ncert_ext > 0)
		qsort(cert_ext, ncert_ext, আকার(*cert_ext), cert_ext_cmp);
}

স্থির কাঠামো sshkey *
load_pkcs11_চাবি(অক্ষর *path)
{
#ifdef ENABLE_PKCS11
	কাঠামো sshkey **চাবিগুলি = ফাঁকা, *সর্বজনীন, *ব্যক্তিগত = ফাঁকা;
	পূর্ণসংখ্যা r, i, nkeys;

	যদি ((r = sshkey_load_public(path, &সর্বজনীন, ফাঁকা)) != 0)
		fatal_r(r, "Couldn't load CA public key \"%s\"", path);

	nkeys = pkcs11_add_provider(pkcs11provider, identity_passphrase,
	    &চাবিগুলি, ফাঁকা);
	debug3_f("%d keys", nkeys);
	যদি (nkeys <= 0)
		fatal("cannot read public key from pkcs11");
	জন্য (i = 0; i < nkeys; i++) {
		যদি (sshkey_equal_public(সর্বজনীন, চাবিগুলি[i])) {
			ব্যক্তিগত = চাবিগুলি[i];
			চালু;
		}
		sshkey_free(চাবিগুলি[i]);
	}
	মুক্ত(চাবিগুলি);
	sshkey_free(সর্বজনীন);
	ফেরত ব্যক্তিগত;
#অন্যথা
	fatal("no pkcs11 support");
#endif /* ENABLE_PKCS11 */
}

/* Signer for sshkey_certify_custom that uses the agent */
স্থির পূর্ণসংখ্যা
agent_signer(কাঠামো sshkey *চাবি, u_char **sigp, আকার_t *lenp,
    ধ্রুবক u_char *তথ্য, আকার_t datalen,
    ধ্রুবক অক্ষর *alg, ধ্রুবক অক্ষর *provider, ধ্রুবক অক্ষর *pin,
    u_int compat, শূন্য *ctx)
{
	পূর্ণসংখ্যা *agent_fdp = (পূর্ণসংখ্যা *)ctx;

	ফেরত ssh_agent_sign(*agent_fdp, চাবি, sigp, lenp,
	    তথ্য, datalen, alg, compat);
}

স্থির শূন্য
do_ca_sign(কাঠামো passwd *pw, ধ্রুবক অক্ষর *ca_চাবি_path, পূর্ণসংখ্যা prefer_agent,
    unsigned long long cert_serial, পূর্ণসংখ্যা cert_serial_autoinc,
    পূর্ণসংখ্যা argc, অক্ষর **argv)
{
	পূর্ণসংখ্যা r, i, চাবি_in_agent = 0, agent_fd = -1;
	u_int n;
	কাঠামো sshkey *ca, *সর্বজনীন;
	অক্ষর valid[64], *otmp, *tmp, *cp, *out, *comment;
	অক্ষর *ca_fp = ফাঁকা, **plist = ফাঁকা, *pin = ফাঁকা;
	কাঠামো ssh_identitylist *agent_ids;
	আকার_t j;
	কাঠামো notifier_ctx *notifier = ফাঁকা;

#ifdef ENABLE_PKCS11
	pkcs11_init(1);
#endif
	tmp = tilde_expand_filename(ca_চাবি_path, pw->pw_uid);
	যদি (pkcs11provider != ফাঁকা) {
		/* If a PKCS#11 token was specified then try to use it */
		যদি ((ca = load_pkcs11_চাবি(tmp)) == ফাঁকা)
			fatal("No PKCS#11 key matching %s found", ca_চাবি_path);
	} অন্যথা যদি (prefer_agent) {
		/*
		 * Agent signature requested. Try to use agent after making
		 * sure the public key specified is actually present in the
		 * agent.
		 */
		যদি ((r = sshkey_load_public(tmp, &ca, ফাঁকা)) != 0)
			fatal_r(r, "Cannot load CA public key %s", tmp);
		যদি ((r = ssh_get_authentication_socket(&agent_fd)) != 0)
			fatal_r(r, "Cannot use public key for CA signature");
		যদি ((r = ssh_fetch_identitylist(agent_fd, &agent_ids)) != 0)
			fatal_r(r, "Retrieve agent key list");
		জন্য (j = 0; j < agent_ids->nkeys; j++) {
			যদি (sshkey_equal(ca, agent_ids->চাবিগুলি[j])) {
				চাবি_in_agent = 1;
				/* Replace the CA key with the agent one */
				sshkey_free(ca);
				ca = agent_ids->চাবিগুলি[j];
				agent_ids->চাবিগুলি[j] = ফাঁকা;
				বিরতি;
			}
		}
		যদি (!চাবি_in_agent)
			fatal("CA key %s not found in agent", tmp);
		ssh_free_identitylist(agent_ids);
	} অন্যথা {
		/* CA key is assumed to be a private key on the filesystem */
		ca = load_identity(tmp, ফাঁকা);
		যদি (sshkey_is_sk(ca) &&
		    (ca->sk_flags & SSH_SK_USER_VERIFICATION_REQD)) {
			যদি ((pin = read_passphrase("Enter PIN for CA key: ",
			    RP_ALLOW_STDIN)) == ফাঁকা)
				fatal_f("couldn't read PIN");
		}
	}
	মুক্ত(tmp);

	যদি (চাবি_type_name != ফাঁকা) {
		যদি (sshkey_type_from_shortname(চাবি_type_name) != ca->type) {
			fatal("CA key type %s doesn't match specified %s",
			    sshkey_ssh_name(ca), চাবি_type_name);
		}
	} অন্যথা যদি (ca->type == চাবি_RSA) {
		/* Default to a good signature algorithm */
		চাবি_type_name = "rsa-sha2-512";
	}
	ca_fp = sshkey_fingerprint(ca, fingerprint_hash, SSH_FP_DEFAULT);

	finalise_cert_exts();
	জন্য (i = 0; i < argc; i++) {
		/* Split list of principals */
		n = 0;
		যদি (cert_principals != ফাঁকা) {
			otmp = tmp = xstrdup(cert_principals);
			plist = ফাঁকা;
			জন্য (; (cp = strsep(&tmp, ",")) != ফাঁকা; n++) {
				plist = xreallocarray(plist, n + 1, আকার(*plist));
				যদি (*(plist[n] = xstrdup(cp)) == '\0')
					fatal("Empty principal name");
			}
			মুক্ত(otmp);
		}
		যদি (n > SSHKEY_CERT_MAX_PRINCIPALS)
			fatal("Too many certificate principals specified");

		tmp = tilde_expand_filename(argv[i], pw->pw_uid);
		যদি ((r = sshkey_load_public(tmp, &সর্বজনীন, &comment)) != 0)
			fatal_r(r, "load pubkey \"%s\"", tmp);
		যদি (sshkey_is_cert(সর্বজনীন))
			fatal_f("key \"%s\" type %s cannot be certified",
			    tmp, sshkey_type(সর্বজনীন));

		/* Prepare certificate to sign */
		যদি ((r = sshkey_to_certified(সর্বজনীন)) != 0)
			fatal_r(r, "Could not upgrade key %s to certificate", tmp);
		সর্বজনীন->cert->type = cert_চাবি_type;
		সর্বজনীন->cert->serial = (uint64_t)cert_serial;
		সর্বজনীন->cert->চাবি_id = xstrdup(cert_চাবি_id);
		সর্বজনীন->cert->nprincipals = n;
		সর্বজনীন->cert->principals = plist;
		সর্বজনীন->cert->valid_after = cert_valid_from;
		সর্বজনীন->cert->valid_before = cert_valid_to;
		prepare_options_buf(সর্বজনীন->cert->critical, OPTIONS_CRITICAL);
		prepare_options_buf(সর্বজনীন->cert->extensions,
		    OPTIONS_EXTENSIONS);
		যদি ((r = sshkey_from_private(ca,
		    &সর্বজনীন->cert->signature_চাবি)) != 0)
			fatal_r(r, "sshkey_from_private (ca key)");

		যদি (চাবি_in_agent) {
			যদি ((r = sshkey_certify_custom(সর্বজনীন, ca,
			    চাবি_type_name, sk_provider, ফাঁকা, agent_signer,
			    &agent_fd)) != 0)
				fatal_r(r, "Couldn't certify %s via agent", tmp);
		} অন্যথা {
			যদি (sshkey_is_sk(ca) &&
			    (ca->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
				notifier = notify_start(0,
				    "Confirm user presence for key %s %s",
				    sshkey_type(ca), ca_fp);
			}
			r = sshkey_certify(সর্বজনীন, ca, চাবি_type_name,
			    sk_provider, pin);
			notify_complete(notifier, "User presence confirmed");
			যদি (r != 0)
				fatal_r(r, "Couldn't certify key %s", tmp);
		}

		যদি ((cp = strrchr(tmp, '.')) != ফাঁকা && strcmp(cp, ".pub") == 0)
			*cp = '\0';
		xasprintf(&out, "%s-cert.pub", tmp);
		মুক্ত(tmp);

		যদি ((r = sshkey_save_public(সর্বজনীন, out, comment)) != 0) {
			fatal_r(r, "Unable to save public key to %s",
			    identity_file);
		}

		যদি (!quiet) {
			sshkey_format_cert_validity(সর্বজনীন->cert,
			    valid, আকার(valid));
			logit("Signed %s key %s: id \"%s\" serial %llu%s%s "
			    "valid %s", sshkey_cert_type(সর্বজনীন),
			    out, সর্বজনীন->cert->চাবি_id,
			    (unsigned long long)সর্বজনীন->cert->serial,
			    cert_principals != ফাঁকা ? " for " : "",
			    cert_principals != ফাঁকা ? cert_principals : "",
			    valid);
		}

		sshkey_free(সর্বজনীন);
		মুক্ত(out);
		মুক্ত(comment);
		যদি (cert_serial_autoinc)
			cert_serial++;
	}
	যদি (pin != ফাঁকা)
		freezero(pin, strlen(pin));
	sshkey_free(ca);
	মুক্ত(ca_fp);
#ifdef ENABLE_PKCS11
	pkcs11_terminate();
#endif
}

স্থির uint64_t
parse_relative_time(ধ্রুবক অক্ষর *s, time_t now)
{
	int64_t mul, secs;

	mul = *s == '-' ? -1 : 1;

	যদি ((secs = convtime(s + 1)) == -1)
		fatal("Invalid relative certificate time %s", s);
	যদি (mul == -1 && secs > now)
		fatal("Certificate time %s cannot be represented", s);
	ফেরত now + (uint64_t)(secs * mul);
}

স্থির শূন্য
parse_hex_u64(ধ্রুবক অক্ষর *s, uint64_t *up)
{
	অক্ষর *ep;
	unsigned long long ull;

	errno = 0;
	ull = strtoull(s, &ep, 16);
	যদি (*s == '\0' || *ep != '\0')
		fatal("Invalid certificate time: not a number");
	যদি (errno == ERANGE && ull == ULONG_MAX)
		fatal_fr(SSH_ERR_SYSTEM_ERROR, "Invalid certificate time");
	*up = (uint64_t)ull;
}

স্থির শূন্য
parse_cert_times(অক্ষর *timespec)
{
	অক্ষর *from, *to;
	time_t now = time(ফাঁকা);
	int64_t secs;

	/* +timespec relative to now */
	যদি (*timespec == '+' && strchr(timespec, ':') == ফাঁকা) {
		যদি ((secs = convtime(timespec + 1)) == -1)
			fatal("Invalid relative certificate life %s", timespec);
		cert_valid_to = now + secs;
		/*
		 * Backdate certificate one minute to avoid problems on hosts
		 * with poorly-synchronised clocks.
		 */
		cert_valid_from = ((now - 59)/ 60) * 60;
		ফেরত;
	}

	/*
	 * from:to, where
	 * from := [+-]timespec | YYYYMMDD | YYYYMMDDHHMMSS | 0x... | "always"
	 *   to := [+-]timespec | YYYYMMDD | YYYYMMDDHHMMSS | 0x... | "forever"
	 */
	from = xstrdup(timespec);
	to = strchr(from, ':');
	যদি (to == ফাঁকা || from == to || *(to + 1) == '\0')
		fatal("Invalid certificate life specification %s", timespec);
	*to++ = '\0';

	যদি (*from == '-' || *from == '+')
		cert_valid_from = parse_relative_time(from, now);
	অন্যথা যদি (strcmp(from, "always") == 0)
		cert_valid_from = 0;
	অন্যথা যদি (strncmp(from, "0x", 2) == 0)
		parse_hex_u64(from, &cert_valid_from);
	অন্যথা যদি (parse_absolute_time(from, &cert_valid_from) != 0)
		fatal("Invalid from time \"%s\"", from);

	যদি (*to == '-' || *to == '+')
		cert_valid_to = parse_relative_time(to, now);
	অন্যথা যদি (strcmp(to, "forever") == 0)
		cert_valid_to = ~(uint64_t)0;
	অন্যথা যদি (strncmp(to, "0x", 2) == 0)
		parse_hex_u64(to, &cert_valid_to);
	অন্যথা যদি (parse_absolute_time(to, &cert_valid_to) != 0)
		fatal("Invalid to time \"%s\"", to);

	যদি (cert_valid_to <= cert_valid_from)
		fatal("Empty certificate validity interval");
	মুক্ত(from);
}

স্থির শূন্য
add_cert_option(অক্ষর *opt)
{
	অক্ষর *val, *cp;
	ধ্রুবক অক্ষর *p;
	পূর্ণসংখ্যা iscrit = 0;

	যদি (strcasecmp(opt, "clear") == 0)
		certflags_flags = 0;
	অন্যথা যদি (strcasecmp(opt, "no-x11-forwarding") == 0)
		certflags_flags &= ~CERTOPT_X_FWD;
	অন্যথা যদি (strcasecmp(opt, "permit-x11-forwarding") == 0)
		certflags_flags |= CERTOPT_X_FWD;
	অন্যথা যদি (strcasecmp(opt, "no-agent-forwarding") == 0)
		certflags_flags &= ~CERTOPT_AGENT_FWD;
	অন্যথা যদি (strcasecmp(opt, "permit-agent-forwarding") == 0)
		certflags_flags |= CERTOPT_AGENT_FWD;
	অন্যথা যদি (strcasecmp(opt, "no-port-forwarding") == 0)
		certflags_flags &= ~CERTOPT_PORT_FWD;
	অন্যথা যদি (strcasecmp(opt, "permit-port-forwarding") == 0)
		certflags_flags |= CERTOPT_PORT_FWD;
	অন্যথা যদি (strcasecmp(opt, "no-pty") == 0)
		certflags_flags &= ~CERTOPT_PTY;
	অন্যথা যদি (strcasecmp(opt, "permit-pty") == 0)
		certflags_flags |= CERTOPT_PTY;
	অন্যথা যদি (strcasecmp(opt, "no-user-rc") == 0)
		certflags_flags &= ~CERTOPT_USER_RC;
	অন্যথা যদি (strcasecmp(opt, "permit-user-rc") == 0)
		certflags_flags |= CERTOPT_USER_RC;
	অন্যথা যদি (strcasecmp(opt, "touch-required") == 0)
		certflags_flags &= ~CERTOPT_NO_REQUIRE_USER_PRESENCE;
	অন্যথা যদি (strcasecmp(opt, "no-touch-required") == 0)
		certflags_flags |= CERTOPT_NO_REQUIRE_USER_PRESENCE;
	অন্যথা যদি (strcasecmp(opt, "no-verify-required") == 0)
		certflags_flags &= ~CERTOPT_REQUIRE_VERIFY;
	অন্যথা যদি (strcasecmp(opt, "verify-required") == 0)
		certflags_flags |= CERTOPT_REQUIRE_VERIFY;
	অন্যথা যদি ((p = strprefix(opt, "force-command=", 1)) != ফাঁকা) {
		যদি (*p == '\0')
			fatal("Empty force-command option");
		যদি (certflags_command != ফাঁকা)
			fatal("force-command already specified");
		certflags_command = xstrdup(p);
	} অন্যথা যদি ((p = strprefix(opt, "source-address=", 1)) != ফাঁকা) {
		যদি (*p == '\0')
			fatal("Empty source-address option");
		যদি (certflags_src_addr != ফাঁকা)
			fatal("source-address already specified");
		যদি (addr_match_cidr_list(ফাঁকা, p) != 0)
			fatal("Invalid source-address list");
		certflags_src_addr = xstrdup(p);
	} অন্যথা যদি (strprefix(opt, "extension:", 1) != ফাঁকা ||
		    (iscrit = (strprefix(opt, "critical:", 1) != ফাঁকা))) {
		val = xstrdup(strchr(opt, ':') + 1);
		যদি ((cp = strchr(val, '=')) != ফাঁকা)
			*cp++ = '\0';
		cert_ext_add(val, cp, iscrit);
		মুক্ত(val);
	} অন্যথা
		fatal("Unsupported certificate option \"%s\"", opt);
}

স্থির শূন্য
show_options(কাঠামো sshbuf *optbuf, পূর্ণসংখ্যা in_critical)
{
	অক্ষর *name, *arg, *hex;
	কাঠামো sshbuf *options, *option = ফাঁকা;
	পূর্ণসংখ্যা r;

	যদি ((options = sshbuf_fromb(optbuf)) == ফাঁকা)
		fatal_f("sshbuf_fromb failed");
	যখন (sshbuf_len(options) != 0) {
		sshbuf_free(option);
		option = ফাঁকা;
		যদি ((r = sshbuf_get_cstring(options, &name, ফাঁকা)) != 0 ||
		    (r = sshbuf_froms(options, &option)) != 0)
			fatal_fr(r, "parse option");
		printf("                %s", name);
		যদি (!in_critical &&
		    (strcmp(name, "permit-X11-forwarding") == 0 ||
		    strcmp(name, "permit-agent-forwarding") == 0 ||
		    strcmp(name, "permit-port-forwarding") == 0 ||
		    strcmp(name, "permit-pty") == 0 ||
		    strcmp(name, "permit-user-rc") == 0 ||
		    strcmp(name, "no-touch-required") == 0)) {
			printf("\n");
		} অন্যথা যদি (in_critical &&
		    (strcmp(name, "force-command") == 0 ||
		    strcmp(name, "source-address") == 0)) {
			যদি ((r = sshbuf_get_cstring(option, &arg, ফাঁকা)) != 0)
				fatal_fr(r, "parse critical");
			printf(" %s\n", arg);
			মুক্ত(arg);
		} অন্যথা যদি (in_critical &&
		    strcmp(name, "verify-required") == 0) {
			printf("\n");
		} অন্যথা যদি (sshbuf_len(option) > 0) {
			hex = sshbuf_dtob16(option);
			printf(" UNKNOWN OPTION: %s (len %zu)\n",
			    hex, sshbuf_len(option));
			sshbuf_reset(option);
			মুক্ত(hex);
		} অন্যথা
			printf(" UNKNOWN FLAG OPTION\n");
		মুক্ত(name);
		যদি (sshbuf_len(option) != 0)
			fatal("Option corrupt: extra data at end");
	}
	sshbuf_free(option);
	sshbuf_free(options);
}

স্থির শূন্য
print_cert(কাঠামো sshkey *চাবি)
{
	অক্ষর valid[64], *চাবি_fp, *ca_fp;
	u_int i;

	চাবি_fp = sshkey_fingerprint(চাবি, fingerprint_hash, SSH_FP_DEFAULT);
	ca_fp = sshkey_fingerprint(চাবি->cert->signature_চাবি,
	    fingerprint_hash, SSH_FP_DEFAULT);
	যদি (চাবি_fp == ফাঁকা || ca_fp == ফাঁকা)
		fatal_f("sshkey_fingerprint fail");
	sshkey_format_cert_validity(চাবি->cert, valid, আকার(valid));

	printf("        Type: %s %s certificate\n", sshkey_ssh_name(চাবি),
	    sshkey_cert_type(চাবি));
	printf("        Public key: %s %s\n", sshkey_type(চাবি), চাবি_fp);
	printf("        Signing CA: %s %s (using %s)\n",
	    sshkey_type(চাবি->cert->signature_চাবি), ca_fp,
	    চাবি->cert->signature_type);
	printf("        Key ID: \"%s\"\n", চাবি->cert->চাবি_id);
	printf("        Serial: %llu\n", (unsigned long long)চাবি->cert->serial);
	printf("        Valid: %s\n", valid);
	printf("        Principals: ");
	যদি (চাবি->cert->nprincipals == 0)
		printf("(none)\n");
	অন্যথা {
		জন্য (i = 0; i < চাবি->cert->nprincipals; i++)
			printf("\n                %s",
			    চাবি->cert->principals[i]);
		printf("\n");
	}
	printf("        Critical Options: ");
	যদি (sshbuf_len(চাবি->cert->critical) == 0)
		printf("(none)\n");
	অন্যথা {
		printf("\n");
		show_options(চাবি->cert->critical, 1);
	}
	printf("        Extensions: ");
	যদি (sshbuf_len(চাবি->cert->extensions) == 0)
		printf("(none)\n");
	অন্যথা {
		printf("\n");
		show_options(চাবি->cert->extensions, 0);
	}
	মুক্ত(চাবি_fp);
	মুক্ত(ca_fp);
}

স্থির শূন্য
do_show_cert(কাঠামো passwd *pw)
{
	কাঠামো sshkey *চাবি = ফাঁকা;
	কাঠামো stat st;
	পূর্ণসংখ্যা r, is_stdin = 0, ok = 0;
	FILE *f;
	অক্ষর *cp, *সারি = ফাঁকা;
	ধ্রুবক অক্ষর *path;
	আকার_t linesize = 0;
	u_long lnum = 0;

	যদি (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	যদি (strcmp(identity_file, "-") != 0 && stat(identity_file, &st) == -1)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));

	path = identity_file;
	যদি (strcmp(path, "-") == 0) {
		f = stdin;
		path = "(stdin)";
		is_stdin = 1;
	} অন্যথা যদি ((f = fopen(identity_file, "r")) == ফাঁকা)
		fatal("fopen %s: %s", identity_file, strerror(errno));

	যখন (getline(&সারি, &linesize, f) != -1) {
		lnum++;
		sshkey_free(চাবি);
		চাবি = ফাঁকা;
		/* Trim leading space and comments */
		cp = সারি + strspn(সারি, " \t");
		যদি (*cp == '#' || *cp == '\0')
			চালু;
		যদি ((চাবি = sshkey_new(চাবি_UNSPEC)) == ফাঁকা)
			fatal("sshkey_new");
		যদি ((r = sshkey_read(চাবি, &cp)) != 0) {
			error_r(r, "%s:%lu: invalid key", path, lnum);
			চালু;
		}
		যদি (!sshkey_is_cert(চাবি)) {
			error("%s:%lu is not a certificate", path, lnum);
			চালু;
		}
		ok = 1;
		যদি (!is_stdin && lnum == 1)
			printf("%s:\n", path);
		অন্যথা
			printf("%s:%lu:\n", path, lnum);
		print_cert(চাবি);
	}
	মুক্ত(সারি);
	sshkey_free(চাবি);
	fclose(f);
	exit(ok ? 0 : 1);
}

স্থির শূন্য
load_krl(ধ্রুবক অক্ষর *path, কাঠামো ssh_krl **krlp)
{
	কাঠামো sshbuf *krlbuf;
	পূর্ণসংখ্যা r;

	যদি ((r = sshbuf_load_file(path, &krlbuf)) != 0)
		fatal_r(r, "Unable to load KRL %s", path);
	/* XXX check sigs */
	যদি ((r = ssh_krl_from_blob(krlbuf, krlp)) != 0 ||
	    *krlp == ফাঁকা)
		fatal_r(r, "Invalid KRL file %s", path);
	sshbuf_free(krlbuf);
}

স্থির শূন্য
hash_to_blob(ধ্রুবক অক্ষর *cp, u_char **blobp, আকার_t *lenp,
    ধ্রুবক অক্ষর *file, u_long lnum)
{
	অক্ষর *tmp;
	আকার_t tlen;
	কাঠামো sshbuf *b;
	পূর্ণসংখ্যা r;

	যদি ((cp = strprefix(cp, "SHA256:", 0)) == ফাঁকা)
		fatal("%s:%lu: unsupported hash algorithm", file, lnum);

	/*
	 * OpenSSH base64 hashes omit trailing '='
	 * characters; put them back for decode.
	 */
	যদি ((tlen = strlen(cp)) >= SIZE_MAX - 5)
		fatal_f("hash too long: %zu bytes", tlen);
	tmp = xmalloc(tlen + 4 + 1);
	strlcpy(tmp, cp, tlen + 1);
	যখন ((tlen % 4) != 0) {
		tmp[tlen++] = '=';
		tmp[tlen] = '\0';
	}
	যদি ((b = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshbuf_b64tod(b, tmp)) != 0)
		fatal_r(r, "%s:%lu: decode hash failed", file, lnum);
	মুক্ত(tmp);
	*lenp = sshbuf_len(b);
	*blobp = xmalloc(*lenp);
	memcpy(*blobp, sshbuf_ptr(b), *lenp);
	sshbuf_free(b);
}

স্থির শূন্য
update_krl_from_file(কাঠামো passwd *pw, ধ্রুবক অক্ষর *file, পূর্ণসংখ্যা wild_ca,
    ধ্রুবক কাঠামো sshkey *ca, কাঠামো ssh_krl *krl)
{
	কাঠামো sshkey *চাবি = ফাঁকা;
	u_long lnum = 0;
	অক্ষর *path, *cp, *ep, *সারি = ফাঁকা;
	u_char *blob = ফাঁকা;
	আকার_t blen = 0, linesize = 0;
	unsigned long long serial, serial2;
	পূর্ণসংখ্যা i, was_explicit_চাবি, was_sha1, was_sha256, was_hash, r;
	FILE *krl_spec;

	path = tilde_expand_filename(file, pw->pw_uid);
	যদি (strcmp(path, "-") == 0) {
		krl_spec = stdin;
		মুক্ত(path);
		path = xstrdup("(standard input)");
	} অন্যথা যদি ((krl_spec = fopen(path, "r")) == ফাঁকা)
		fatal("fopen %s: %s", path, strerror(errno));

	যদি (!quiet)
		printf("Revoking from %s\n", path);
	যখন (getline(&সারি, &linesize, krl_spec) != -1) {
		যদি (linesize >= INT_MAX) {
			fatal_f("%s contains unparsable line, len=%zu",
			    path, linesize);
		}
		lnum++;
		was_explicit_চাবি = was_sha1 = was_sha256 = was_hash = 0;
		cp = সারি + strspn(সারি, " \t");
		/* Trim trailing space, comments and strip \n */
		জন্য (i = 0, r = -1; cp[i] != '\0'; i++) {
			যদি (cp[i] == '#' || cp[i] == '\n') {
				cp[i] = '\0';
				বিরতি;
			}
			যদি (cp[i] == ' ' || cp[i] == '\t') {
				/* Remember the start of a span of whitespace */
				যদি (r == -1)
					r = i;
			} অন্যথা
				r = -1;
		}
		যদি (r != -1)
			cp[r] = '\0';
		যদি (*cp == '\0')
			চালু;
		যদি (strncasecmp(cp, "serial:", 7) == 0) {
			যদি (ca == ফাঁকা && !wild_ca) {
				fatal("revoking certificates by serial number "
				    "requires specification of a CA key");
			}
			cp += 7;
			cp = cp + strspn(cp, " \t");
			errno = 0;
			serial = strtoull(cp, &ep, 0);
			যদি (*cp == '\0' || (*ep != '\0' && *ep != '-'))
				fatal("%s:%lu: invalid serial \"%s\"",
				    path, lnum, cp);
			যদি (errno == ERANGE && serial == ULLONG_MAX)
				fatal("%s:%lu: serial out of range",
				    path, lnum);
			serial2 = serial;
			যদি (*ep == '-') {
				cp = ep + 1;
				errno = 0;
				serial2 = strtoull(cp, &ep, 0);
				যদি (*cp == '\0' || *ep != '\0')
					fatal("%s:%lu: invalid serial \"%s\"",
					    path, lnum, cp);
				যদি (errno == ERANGE && serial2 == ULLONG_MAX)
					fatal("%s:%lu: serial out of range",
					    path, lnum);
				যদি (serial2 <= serial)
					fatal("%s:%lu: invalid serial range "
					    "%llu:%llu", path, lnum,
					    (unsigned long long)serial,
					    (unsigned long long)serial2);
			}
			যদি (ssh_krl_revoke_cert_by_serial_range(krl,
			    ca, serial, serial2) != 0) {
				fatal_f("revoke serial failed");
			}
		} অন্যথা যদি (strncasecmp(cp, "id:", 3) == 0) {
			যদি (ca == ফাঁকা && !wild_ca) {
				fatal("revoking certificates by key ID "
				    "requires specification of a CA key");
			}
			cp += 3;
			cp = cp + strspn(cp, " \t");
			যদি (ssh_krl_revoke_cert_by_চাবি_id(krl, ca, cp) != 0)
				fatal_f("revoke key ID failed");
		} অন্যথা যদি (strncasecmp(cp, "hash:", 5) == 0) {
			cp += 5;
			cp = cp + strspn(cp, " \t");
			hash_to_blob(cp, &blob, &blen, file, lnum);
			যদি ((r = ssh_krl_revoke_চাবি_sha256(krl,
			    blob, blen)) != 0)
				fatal_fr(r, "revoke key failed");
			মুক্ত(blob);
			blob = ফাঁকা;
			blen = 0;
		} অন্যথা {
			যদি (strncasecmp(cp, "key:", 4) == 0) {
				cp += 4;
				cp = cp + strspn(cp, " \t");
				was_explicit_চাবি = 1;
			} অন্যথা যদি (strncasecmp(cp, "sha1:", 5) == 0) {
				cp += 5;
				cp = cp + strspn(cp, " \t");
				was_sha1 = 1;
			} অন্যথা যদি (strncasecmp(cp, "sha256:", 7) == 0) {
				cp += 7;
				cp = cp + strspn(cp, " \t");
				was_sha256 = 1;
				/*
				 * Just try to process the line as a key.
				 * Parsing will fail if it isn't.
				 */
			}
			যদি ((চাবি = sshkey_new(চাবি_UNSPEC)) == ফাঁকা)
				fatal("sshkey_new");
			যদি ((r = sshkey_read(চাবি, &cp)) != 0)
				fatal_r(r, "%s:%lu: invalid key", path, lnum);
			যদি (was_explicit_চাবি)
				r = ssh_krl_revoke_চাবি_explicit(krl, চাবি);
			অন্যথা যদি (was_sha1) {
				যদি (sshkey_fingerprint_raw(চাবি,
				    SSH_DIGEST_SHA1, &blob, &blen) != 0) {
					fatal("%s:%lu: fingerprint failed",
					    file, lnum);
				}
				r = ssh_krl_revoke_চাবি_sha1(krl, blob, blen);
			} অন্যথা যদি (was_sha256) {
				যদি (sshkey_fingerprint_raw(চাবি,
				    SSH_DIGEST_SHA256, &blob, &blen) != 0) {
					fatal("%s:%lu: fingerprint failed",
					    file, lnum);
				}
				r = ssh_krl_revoke_চাবি_sha256(krl, blob, blen);
			} অন্যথা
				r = ssh_krl_revoke_চাবি(krl, চাবি);
			যদি (r != 0)
				fatal_fr(r, "revoke key failed");
			freezero(blob, blen);
			blob = ফাঁকা;
			blen = 0;
			sshkey_free(চাবি);
		}
	}
	যদি (strcmp(path, "-") != 0)
		fclose(krl_spec);
	মুক্ত(সারি);
	মুক্ত(path);
}

স্থির শূন্য
do_gen_krl(কাঠামো passwd *pw, পূর্ণসংখ্যা updating, ধ্রুবক অক্ষর *ca_চাবি_path,
    unsigned long long krl_version, ধ্রুবক অক্ষর *krl_comment,
    পূর্ণসংখ্যা argc, অক্ষর **argv)
{
	কাঠামো ssh_krl *krl;
	কাঠামো stat sb;
	কাঠামো sshkey *ca = ফাঁকা;
	পূর্ণসংখ্যা i, r, wild_ca = 0;
	অক্ষর *tmp;
	কাঠামো sshbuf *kbuf;

	যদি (*identity_file == '\0')
		fatal("KRL generation requires an output file");
	যদি (stat(identity_file, &sb) == -1) {
		যদি (errno != ENOENT)
			fatal("Cannot access KRL \"%s\": %s",
			    identity_file, strerror(errno));
		যদি (updating)
			fatal("KRL \"%s\" does not exist", identity_file);
	}
	যদি (ca_চাবি_path != ফাঁকা) {
		যদি (strcasecmp(ca_চাবি_path, "none") == 0)
			wild_ca = 1;
		অন্যথা {
			tmp = tilde_expand_filename(ca_চাবি_path, pw->pw_uid);
			যদি ((r = sshkey_load_public(tmp, &ca, ফাঁকা)) != 0)
				fatal_r(r, "Cannot load CA public key %s", tmp);
			মুক্ত(tmp);
		}
	}

	যদি (updating)
		load_krl(identity_file, &krl);
	অন্যথা যদি ((krl = ssh_krl_init()) == ফাঁকা)
		fatal("couldn't create KRL");

	যদি (krl_version != 0)
		ssh_krl_set_version(krl, krl_version);
	যদি (krl_comment != ফাঁকা)
		ssh_krl_set_comment(krl, krl_comment);

	জন্য (i = 0; i < argc; i++)
		update_krl_from_file(pw, argv[i], wild_ca, ca, krl);

	যদি ((kbuf = sshbuf_new()) == ফাঁকা)
		fatal("sshbuf_new failed");
	যদি (ssh_krl_to_blob(krl, kbuf) != 0)
		fatal("Couldn't generate KRL");
	যদি ((r = sshbuf_write_file(identity_file, kbuf)) != 0)
		fatal("write %s: %s", identity_file, strerror(errno));
	sshbuf_free(kbuf);
	ssh_krl_free(krl);
	sshkey_free(ca);
}

স্থির শূন্য
do_check_krl(কাঠামো passwd *pw, পূর্ণসংখ্যা print_krl, পূর্ণসংখ্যা argc, অক্ষর **argv)
{
	পূর্ণসংখ্যা i, r, ret = 0;
	অক্ষর *comment;
	কাঠামো ssh_krl *krl;
	কাঠামো sshkey *k;

	যদি (*identity_file == '\0')
		fatal("KRL checking requires an input file");
	load_krl(identity_file, &krl);
	যদি (print_krl)
		krl_dump(krl, stdout);
	জন্য (i = 0; i < argc; i++) {
		যদি ((r = sshkey_load_public(argv[i], &k, &comment)) != 0)
			fatal_r(r, "Cannot load public key %s", argv[i]);
		r = ssh_krl_check_চাবি(krl, k);
		printf("%s%s%s%s: %s\n", argv[i],
		    *comment ? " (" : "", comment, *comment ? ")" : "",
		    r == 0 ? "ok" : "REVOKED");
		যদি (r != 0)
			ret = 1;
		sshkey_free(k);
		মুক্ত(comment);
	}
	ssh_krl_free(krl);
	exit(ret);
}

স্থির কাঠামো sshkey *
load_sign_চাবি(ধ্রুবক অক্ষর *keypath, ধ্রুবক কাঠামো sshkey *pubkey)
{
	আকার_t i, slen, plen = strlen(keypath);
	অক্ষর *privpath = xstrdup(keypath);
	স্থির ধ্রুবক অক্ষর * ধ্রুবক suffixes[] = { "-cert.pub", ".pub", ফাঁকা };
	কাঠামো sshkey *ret = ফাঁকা, *privkey = ফাঁকা;
	পূর্ণসংখ্যা r, waspub = 0;
	কাঠামো stat st;

	/*
	 * If passed a public key filename, then try to locate the corresponding
	 * private key. This lets us specify certificates on the command-line
	 * and have ssh-keygen find the appropriate private key.
	 */
	জন্য (i = 0; suffixes[i]; i++) {
		slen = strlen(suffixes[i]);
		যদি (plen <= slen ||
		    strcmp(privpath + plen - slen, suffixes[i]) != 0)
			চালু;
		privpath[plen - slen] = '\0';
		debug_f("%s looks like a public key, using private key "
		    "path %s instead", keypath, privpath);
		waspub = 1;
	}
	যদি (waspub && stat(privpath, &st) != 0 && errno == ENOENT)
		fatal("No private key found for public key \"%s\"", keypath);
	যদি ((r = sshkey_load_private(privpath, "", &privkey, ফাঁকা)) != 0 &&
	    (r != SSH_ERR_চাবি_WRONG_PASSPHRASE)) {
		debug_fr(r, "load private key \"%s\"", privpath);
		fatal("No private key found for \"%s\"", privpath);
	} অন্যথা যদি (privkey == ফাঁকা)
		privkey = load_identity(privpath, ফাঁকা);

	যদি (!sshkey_equal_public(pubkey, privkey)) {
		error("Public key %s doesn't match private %s",
		    keypath, privpath);
		যাও done;
	}
	যদি (sshkey_is_cert(pubkey) && !sshkey_is_cert(privkey)) {
		/*
		 * Graft the certificate onto the private key to make
		 * it capable of signing.
		 */
		যদি ((r = sshkey_to_certified(privkey)) != 0) {
			error_fr(r, "sshkey_to_certified");
			যাও done;
		}
		যদি ((r = sshkey_cert_copy(pubkey, privkey)) != 0) {
			error_fr(r, "sshkey_cert_copy");
			যাও done;
		}
	}
	/* success */
	ret = privkey;
	privkey = ফাঁকা;
 done:
	sshkey_free(privkey);
	মুক্ত(privpath);
	ফেরত ret;
}

স্থির পূর্ণসংখ্যা
sign_one(কাঠামো sshkey *signkey, ধ্রুবক অক্ষর *filename, পূর্ণসংখ্যা fd,
    ধ্রুবক অক্ষর *sig_namespace, ধ্রুবক অক্ষর *hashalg, sshsig_signer *signer,
    শূন্য *signer_ctx)
{
	কাঠামো sshbuf *sigbuf = ফাঁকা, *abuf = ফাঁকা;
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR, wfd = -1, oerrno;
	অক্ষর *wfile = ফাঁকা, *asig = ফাঁকা, *fp = ফাঁকা;
	অক্ষর *pin = ফাঁকা, *prompt = ফাঁকা;

	যদি (!quiet) {
		যদি (fd == STDIN_FILENO)
			fprintf(stderr, "Signing data on standard input\n");
		অন্যথা
			fprintf(stderr, "Signing file %s\n", filename);
	}
	যদি (signer == ফাঁকা && sshkey_is_sk(signkey)) {
		যদি ((signkey->sk_flags & SSH_SK_USER_VERIFICATION_REQD)) {
			xasprintf(&prompt, "Enter PIN for %s key: ",
			    sshkey_type(signkey));
			যদি ((pin = read_passphrase(prompt,
			    RP_ALLOW_STDIN)) == ফাঁকা)
				fatal_f("couldn't read PIN");
		}
		যদি ((signkey->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
			যদি ((fp = sshkey_fingerprint(signkey, fingerprint_hash,
			    SSH_FP_DEFAULT)) == ফাঁকা)
				fatal_f("fingerprint failed");
			fprintf(stderr, "Confirm user presence for key %s %s\n",
			    sshkey_type(signkey), fp);
			মুক্ত(fp);
		}
	}
	যদি ((r = sshsig_sign_fd(signkey, hashalg, sk_provider, pin,
	    fd, sig_namespace, &sigbuf, signer, signer_ctx)) != 0) {
		error_r(r, "Signing %s failed", filename);
		যাও out;
	}
	যদি ((r = sshsig_armor(sigbuf, &abuf)) != 0) {
		error_fr(r, "sshsig_armor");
		যাও out;
	}
	যদি ((asig = sshbuf_dup_string(abuf)) == ফাঁকা) {
		error_f("buffer error");
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}

	যদি (fd == STDIN_FILENO) {
		fputs(asig, stdout);
		fflush(stdout);
	} অন্যথা {
		xasprintf(&wfile, "%s.sig", filename);
		যদি (confirm_overwrite(wfile)) {
			যদি ((wfd = open(wfile, O_WRONLY|O_CREAT|O_TRUNC,
			    0666)) == -1) {
				oerrno = errno;
				error("Cannot open %s: %s",
				    wfile, strerror(errno));
				errno = oerrno;
				r = SSH_ERR_SYSTEM_ERROR;
				যাও out;
			}
			যদি (atomicio(vwrite, wfd, asig,
			    strlen(asig)) != strlen(asig)) {
				oerrno = errno;
				error("Cannot write to %s: %s",
				    wfile, strerror(errno));
				errno = oerrno;
				r = SSH_ERR_SYSTEM_ERROR;
				যাও out;
			}
			যদি (!quiet) {
				fprintf(stderr, "Write signature to %s\n",
				    wfile);
			}
		}
	}
	/* success */
	r = 0;
 out:
	মুক্ত(wfile);
	মুক্ত(prompt);
	মুক্ত(asig);
	যদি (pin != ফাঁকা)
		freezero(pin, strlen(pin));
	sshbuf_free(abuf);
	sshbuf_free(sigbuf);
	যদি (wfd != -1)
		close(wfd);
	ফেরত r;
}

স্থির পূর্ণসংখ্যা
sig_process_opts(অক্ষর * ধ্রুবক *opts, আকার_t nopts, অক্ষর **hashalgp,
    uint64_t *verify_timep, পূর্ণসংখ্যা *print_pubkey)
{
	আকার_t i;
	time_t now;
	ধ্রুবক অক্ষর *p;

	যদি (verify_timep != ফাঁকা)
		*verify_timep = 0;
	যদি (print_pubkey != ফাঁকা)
		*print_pubkey = 0;
	যদি (hashalgp != ফাঁকা)
		*hashalgp = ফাঁকা;
	জন্য (i = 0; i < nopts; i++) {
		যদি (hashalgp != ফাঁকা &&
		    (p = strprefix(opts[i], "hashalg=", 1)) != ফাঁকা) {
			*hashalgp = xstrdup(p);
		} অন্যথা যদি (verify_timep &&
		    (p = strprefix(opts[i], "verify-time=", 1)) != ফাঁকা) {
			যদি (parse_absolute_time(p, verify_timep) != 0 ||
			    *verify_timep == 0) {
				error("Invalid \"verify-time\" option");
				ফেরত SSH_ERR_INVALID_ARGUMENT;
			}
		} অন্যথা যদি (print_pubkey &&
		    strcasecmp(opts[i], "print-pubkey") == 0) {
			*print_pubkey = 1;
		} অন্যথা {
			error("Invalid option \"%s\"", opts[i]);
			ফেরত SSH_ERR_INVALID_ARGUMENT;
		}
	}
	যদি (verify_timep && *verify_timep == 0) {
		যদি ((now = time(ফাঁকা)) < 0) {
			error("Time is before epoch");
			ফেরত SSH_ERR_INVALID_ARGUMENT;
		}
		*verify_timep = (uint64_t)now;
	}
	ফেরত 0;
}


স্থির পূর্ণসংখ্যা
sig_sign(ধ্রুবক অক্ষর *keypath, ধ্রুবক অক্ষর *sig_namespace, পূর্ণসংখ্যা require_agent,
    পূর্ণসংখ্যা argc, অক্ষর **argv, অক্ষর * ধ্রুবক *opts, আকার_t nopts)
{
	পূর্ণসংখ্যা i, fd = -1, r, ret = -1;
	পূর্ণসংখ্যা agent_fd = -1;
	কাঠামো sshkey *pubkey = ফাঁকা, *privkey = ফাঁকা, *signkey = ফাঁকা;
	sshsig_signer *signer = ফাঁকা;
	অক্ষর *hashalg = ফাঁকা;

	/* Check file arguments. */
	জন্য (i = 0; i < argc; i++) {
		যদি (strcmp(argv[i], "-") != 0)
			চালু;
		যদি (i > 0 || argc > 1)
			fatal("Cannot sign mix of paths and standard input");
	}

	যদি (sig_process_opts(opts, nopts, &hashalg, ফাঁকা, ফাঁকা) != 0)
		যাও done; /* error already logged */

	যদি ((r = sshkey_load_public(keypath, &pubkey, ফাঁকা)) != 0) {
		error_r(r, "Couldn't load public key %s", keypath);
		যাও done;
	}

	যদি ((r = ssh_get_authentication_socket(&agent_fd)) != 0) {
		যদি (require_agent)
			fatal("Couldn't get agent socket");
		debug_r(r, "Couldn't get agent socket");
	} অন্যথা {
		যদি ((r = ssh_agent_has_চাবি(agent_fd, pubkey)) == 0)
			signer = agent_signer;
		অন্যথা {
			যদি (require_agent)
				fatal("Couldn't find key in agent");
			debug_r(r, "Couldn't find key in agent");
		}
	}

	যদি (signer == ফাঁকা) {
		/* Not using agent - try to load private key */
		যদি ((privkey = load_sign_চাবি(keypath, pubkey)) == ফাঁকা)
			যাও done;
		signkey = privkey;
	} অন্যথা {
		/* Will use key in agent */
		signkey = pubkey;
	}

	যদি (argc == 0) {
		যদি ((r = sign_one(signkey, "(stdin)", STDIN_FILENO,
		    sig_namespace, hashalg, signer, &agent_fd)) != 0)
			যাও done;
	} অন্যথা {
		জন্য (i = 0; i < argc; i++) {
			যদি (strcmp(argv[i], "-") == 0)
				fd = STDIN_FILENO;
			অন্যথা যদি ((fd = open(argv[i], O_RDONLY)) == -1) {
				error("Cannot open %s for signing: %s",
				    argv[i], strerror(errno));
				যাও done;
			}
			যদি ((r = sign_one(signkey, argv[i], fd, sig_namespace,
			    hashalg, signer, &agent_fd)) != 0)
				যাও done;
			যদি (fd != STDIN_FILENO)
				close(fd);
			fd = -1;
		}
	}

	ret = 0;
done:
	যদি (fd != -1 && fd != STDIN_FILENO)
		close(fd);
	sshkey_free(pubkey);
	sshkey_free(privkey);
	মুক্ত(hashalg);
	ফেরত ret;
}

স্থির পূর্ণসংখ্যা
sig_verify(ধ্রুবক অক্ষর *signature, ধ্রুবক অক্ষর *sig_namespace,
    ধ্রুবক অক্ষর *principal, ধ্রুবক অক্ষর *allowed_চাবিগুলি, ধ্রুবক অক্ষর *revoked_চাবিগুলি,
    অক্ষর * ধ্রুবক *opts, আকার_t nopts)
{
	পূর্ণসংখ্যা r, ret = -1;
	পূর্ণসংখ্যা print_pubkey = 0;
	কাঠামো sshbuf *sigbuf = ফাঁকা, *abuf = ফাঁকা;
	কাঠামো sshkey *sign_চাবি = ফাঁকা;
	অক্ষর *fp = ফাঁকা;
	কাঠামো sshkey_sig_details *sig_details = ফাঁকা;
	uint64_t verify_time = 0;

	যদি (sig_process_opts(opts, nopts, ফাঁকা, &verify_time,
	    &print_pubkey) != 0)
		যাও done; /* error already logged */

	memset(&sig_details, 0, আকার(sig_details));
	যদি ((r = sshbuf_load_file(signature, &abuf)) != 0) {
		error_r(r, "Couldn't read signature file");
		যাও done;
	}

	যদি ((r = sshsig_dearmor(abuf, &sigbuf)) != 0) {
		error_fr(r, "sshsig_armor");
		যাও done;
	}
	যদি ((r = sshsig_verify_fd(sigbuf, STDIN_FILENO, sig_namespace,
	    &sign_চাবি, &sig_details)) != 0)
		যাও done; /* sshsig_verify() prints error */

	যদি ((fp = sshkey_fingerprint(sign_চাবি, fingerprint_hash,
	    SSH_FP_DEFAULT)) == ফাঁকা)
		fatal_f("sshkey_fingerprint failed");
	debug("Valid (unverified) signature from key %s", fp);
	যদি (sig_details != ফাঁকা) {
		debug2_f("signature details: counter = %u, flags = 0x%02x",
		    sig_details->sk_গণক, sig_details->sk_flags);
	}
	মুক্ত(fp);
	fp = ফাঁকা;

	যদি (revoked_চাবিগুলি != ফাঁকা) {
		যদি ((r = sshkey_check_revoked(sign_চাবি, revoked_চাবিগুলি)) != 0) {
			debug3_fr(r, "sshkey_check_revoked");
			যাও done;
		}
	}

	যদি (allowed_চাবিগুলি != ফাঁকা && (r = sshsig_check_allowed_চাবিগুলি(allowed_চাবিগুলি,
	    sign_চাবি, principal, sig_namespace, verify_time)) != 0) {
		debug3_fr(r, "sshsig_check_allowed_keys");
		যাও done;
	}
	/* success */
	ret = 0;
done:
	যদি (!quiet) {
		যদি (ret == 0) {
			যদি ((fp = sshkey_fingerprint(sign_চাবি, fingerprint_hash,
			    SSH_FP_DEFAULT)) == ফাঁকা)
				fatal_f("sshkey_fingerprint failed");
			যদি (principal == ফাঁকা) {
				printf("Good \"%s\" signature with %s key %s\n",
				    sig_namespace, sshkey_type(sign_চাবি), fp);

			} অন্যথা {
				printf("Good \"%s\" signature for %s with %s key %s\n",
				    sig_namespace, principal,
				    sshkey_type(sign_চাবি), fp);
			}
		} অন্যথা {
			printf("Could not verify signature.\n");
		}
	}
	/* Print the signature key if requested */
	যদি (ret == 0 && print_pubkey && sign_চাবি != ফাঁকা) {
		যদি ((r = sshkey_write(sign_চাবি, stdout)) == 0)
			fputc('\n', stdout);
		অন্যথা {
			error_r(r, "Could not print public key.\n");
			ret = -1;
		}
	}
	sshbuf_free(sigbuf);
	sshbuf_free(abuf);
	sshkey_free(sign_চাবি);
	sshkey_sig_details_free(sig_details);
	মুক্ত(fp);
	ফেরত ret;
}

স্থির পূর্ণসংখ্যা
sig_find_principals(ধ্রুবক অক্ষর *signature, ধ্রুবক অক্ষর *allowed_চাবিগুলি,
    অক্ষর * ধ্রুবক *opts, আকার_t nopts)
{
	পূর্ণসংখ্যা r, ret = -1;
	কাঠামো sshbuf *sigbuf = ফাঁকা, *abuf = ফাঁকা;
	কাঠামো sshkey *sign_চাবি = ফাঁকা;
	অক্ষর *principals = ফাঁকা, *cp, *tmp;
	uint64_t verify_time = 0;

	যদি (sig_process_opts(opts, nopts, ফাঁকা, &verify_time, ফাঁকা) != 0)
		যাও done; /* error already logged */

	যদি ((r = sshbuf_load_file(signature, &abuf)) != 0) {
		error_r(r, "Couldn't read signature file");
		যাও done;
	}
	যদি ((r = sshsig_dearmor(abuf, &sigbuf)) != 0) {
		error_fr(r, "sshsig_armor");
		যাও done;
	}
	যদি ((r = sshsig_get_pubkey(sigbuf, &sign_চাবি)) != 0) {
		error_fr(r, "sshsig_get_pubkey");
		যাও done;
	}
	যদি ((r = sshsig_find_principals(allowed_চাবিগুলি, sign_চাবি,
	    verify_time, &principals)) != 0) {
		যদি (r != SSH_ERR_চাবি_NOT_FOUND)
			error_fr(r, "sshsig_find_principal");
		যাও done;
	}
	ret = 0;
done:
	যদি (ret == 0 ) {
		/* Emit matching principals one per line */
		tmp = principals;
		যখন ((cp = strsep(&tmp, ",")) != ফাঁকা && *cp != '\0')
			puts(cp);
	} অন্যথা {
		fprintf(stderr, "No principal matched.\n");
	}
	sshbuf_free(sigbuf);
	sshbuf_free(abuf);
	sshkey_free(sign_চাবি);
	মুক্ত(principals);
	ফেরত ret;
}

স্থির পূর্ণসংখ্যা
sig_match_principals(ধ্রুবক অক্ষর *allowed_চাবিগুলি, অক্ষর *principal,
	অক্ষর * ধ্রুবক *opts, আকার_t nopts)
{
	পূর্ণসংখ্যা r;
	অক্ষর **principals = ফাঁকা;
	আকার_t i, nprincipals = 0;

	যদি ((r = sig_process_opts(opts, nopts, ফাঁকা, ফাঁকা, ফাঁকা)) != 0)
		ফেরত r; /* error already logged */

	যদি ((r = sshsig_match_principals(allowed_চাবিগুলি, principal,
	    &principals, &nprincipals)) != 0) {
		debug_f("match: %s", ssh_err(r));
		fprintf(stderr, "No principal matched.\n");
		ফেরত r;
	}
	জন্য (i = 0; i < nprincipals; i++) {
		printf("%s\n", principals[i]);
		মুক্ত(principals[i]);
	}
	মুক্ত(principals);

	ফেরত 0;
}

স্থির শূন্য
do_moduli_gen(ধ্রুবক অক্ষর *out_file, অক্ষর **opts, আকার_t nopts)
{
#ifdef WITH_OPENSSL
	/* Moduli generation/screening */
	BIGNUM *start = ফাঁকা;
	পূর্ণসংখ্যা moduli_bits = 0;
	FILE *out;
	আকার_t i;
	ধ্রুবক অক্ষর *errstr, *p;

	/* Parse options */
	জন্য (i = 0; i < nopts; i++) {
		যদি ((p = strprefix(opts[i], "start=", 0)) != ফাঁকা) {
			/* XXX - also compare length against bits */
			যদি (BN_hex2bn(&start, p) == 0)
				fatal("Invalid start point.");
		} অন্যথা যদি ((p = strprefix(opts[i], "bits=", 0)) != ফাঁকা) {
			moduli_bits = (পূর্ণসংখ্যা)strtonum(p, 1, INT_MAX, &errstr);
			যদি (errstr) {
				fatal("Invalid number: %s (%s)", p, errstr);
			}
		} অন্যথা {
			fatal("Option \"%s\" is unsupported for moduli "
			    "generation", opts[i]);
		}
	}

	যদি (strcmp(out_file, "-") == 0)
		out = stdout;
	অন্যথা যদি ((out = fopen(out_file, "w")) == ফাঁকা) {
		fatal("Couldn't open modulus candidate file \"%s\": %s",
		    out_file, strerror(errno));
	}
	setvbuf(out, ফাঁকা, _IOLBF, 0);

	যদি (moduli_bits == 0)
		moduli_bits = DEFAULT_BITS;
	যদি (gen_candidates(out, moduli_bits, start) != 0)
		fatal("modulus candidate generation failed");
#অন্যথা /* WITH_OPENSSL */
	fatal("Moduli generation is not supported");
#endif /* WITH_OPENSSL */
}

স্থির শূন্য
do_moduli_screen(ধ্রুবক অক্ষর *out_file, অক্ষর **opts, আকার_t nopts)
{
#ifdef WITH_OPENSSL
	/* Moduli generation/screening */
	অক্ষর *checkpoint = ফাঁকা;
	uint32_t generator_wanted = 0;
	unsigned long start_lineno = 0, সারিগুলি_to_process = 0;
	পূর্ণসংখ্যা মৌলিক_tests = 0;
	FILE *out, *in = stdin;
	আকার_t i;
	ধ্রুবক অক্ষর *errstr, *p;

	/* Parse options */
	জন্য (i = 0; i < nopts; i++) {
		যদি ((p = strprefix(opts[i], "lines=", 0)) != ফাঁকা) {
			সারিগুলি_to_process = strtoul(p, ফাঁকা, 10);
		} অন্যথা যদি ((p = strprefix(opts[i], "start-line=", 0)) != ফাঁকা) {
			start_lineno = strtoul(p, ফাঁকা, 10);
		} অন্যথা যদি ((p = strprefix(opts[i], "checkpoint=", 0)) != ফাঁকা) {
			মুক্ত(checkpoint);
			checkpoint = xstrdup(p);
		} অন্যথা যদি ((p = strprefix(opts[i], "generator=", 0)) != ফাঁকা) {
			generator_wanted = (uint32_t)strtonum(p, 1, UINT_MAX,
			    &errstr);
			যদি (errstr != ফাঁকা) {
				fatal("Generator invalid: %s (%s)", p, errstr);
			}
		} অন্যথা যদি ((p = strprefix(opts[i], "prime-tests=", 0)) != ফাঁকা) {
			মৌলিক_tests = (পূর্ণসংখ্যা)strtonum(p, 1, INT_MAX, &errstr);
			যদি (errstr) {
				fatal("Invalid number: %s (%s)", p, errstr);
			}
		} অন্যথা {
			fatal("Option \"%s\" is unsupported for moduli "
			    "screening", opts[i]);
		}
	}

	যদি (have_identity && strcmp(identity_file, "-") != 0) {
		যদি ((in = fopen(identity_file, "r")) == ফাঁকা) {
			fatal("Couldn't open modulus candidate "
			    "file \"%s\": %s", identity_file,
			    strerror(errno));
		}
	}

	যদি (strcmp(out_file, "-") == 0)
		out = stdout;
	অন্যথা যদি ((out = fopen(out_file, "a")) == ফাঁকা) {
		fatal("Couldn't open moduli file \"%s\": %s",
		    out_file, strerror(errno));
	}
	setvbuf(out, ফাঁকা, _IOLBF, 0);
	যদি (মৌলিক_test(in, out, মৌলিক_tests == 0 ? 100 : মৌলিক_tests,
	    generator_wanted, checkpoint,
	    start_lineno, সারিগুলি_to_process) != 0)
		fatal("modulus screening failed");
	যদি (in != stdin)
		(শূন্য)fclose(in);
	মুক্ত(checkpoint);
#অন্যথা /* WITH_OPENSSL */
	fatal("Moduli screening is not supported");
#endif /* WITH_OPENSSL */
}

/* Read and confirm a passphrase */
স্থির অক্ষর *
read_check_passphrase(ধ্রুবক অক্ষর *prompt1, ধ্রুবক অক্ষর *prompt2,
    ধ্রুবক অক্ষর *retry_prompt)
{
	অক্ষর *passphrase1, *passphrase2;

	জন্য (;;) {
		passphrase1 = read_passphrase(prompt1, RP_ALLOW_STDIN);
		passphrase2 = read_passphrase(prompt2, RP_ALLOW_STDIN);
		যদি (strcmp(passphrase1, passphrase2) == 0) {
			freezero(passphrase2, strlen(passphrase2));
			ফেরত passphrase1;
		}
		/* The passphrases do not match. Clear them and retry. */
		freezero(passphrase1, strlen(passphrase1));
		freezero(passphrase2, strlen(passphrase2));
		fputs(retry_prompt, stdout);
		fputc('\n', stdout);
		fflush(stdout);
	}
	/* NOTREACHED */
	ফেরত ফাঁকা;
}

স্থির অক্ষর *
private_চাবি_passphrase(ধ্রুবক অক্ষর *path)
{
	অক্ষর *prompt, *ret;

	যদি (identity_passphrase)
		ফেরত xstrdup(identity_passphrase);
	যদি (identity_new_passphrase)
		ফেরত xstrdup(identity_new_passphrase);

	xasprintf(&prompt, "Enter passphrase for \"%s\" "
	    "(empty for no passphrase): ", path);
	ret = read_check_passphrase(prompt,
	    "Enter same passphrase again: ",
	    "Passphrases do not match.  Try again.");
	মুক্ত(prompt);
	ফেরত ret;
}

স্থির অক্ষর *
sk_suffix(ধ্রুবক অক্ষর *application, ধ্রুবক uint8_t *user, আকার_t userlen)
{
	অক্ষর *ret, *cp;
	ধ্রুবক অক্ষর *p;
	আকার_t slen, i;

	/* Trim off URL-like preamble */
	যদি ((p = strprefix(application, "ssh://", 0)) != ফাঁকা)
		ret =  xstrdup(p);
	অন্যথা যদি ((p = strprefix(application, "ssh:", 0)) != ফাঁকা)
		ret =  xstrdup(p);
	অন্যথা
		ret = xstrdup(application);

	/* Count trailing zeros in user */
	জন্য (i = 0; i < userlen; i++) {
		যদি (user[userlen - i - 1] != 0)
			বিরতি;
	}
	যদি (i >= userlen)
		ফেরত ret; /* user-id was default all-zeros */

	/* Append user-id, escaping non-UTF-8 characters */
	slen = userlen - i;
	যদি (asmprintf(&cp, INT_MAX, ফাঁকা, "%.*s", (পূর্ণসংখ্যা)slen, user) == -1)
		fatal_f("asmprintf failed");
	/* Don't emit a user-id that contains path or control characters */
	যদি (strchr(cp, '/') != ফাঁকা || strstr(cp, "..") != ফাঁকা ||
	    strchr(cp, '\\') != ফাঁকা) {
		মুক্ত(cp);
		cp = tohex(user, slen);
	}
	xextendf(&ret, "_", "%s", cp);
	মুক্ত(cp);
	ফেরত ret;
}

স্থির পূর্ণসংখ্যা
do_download_sk(ধ্রুবক অক্ষর *skprovider, ধ্রুবক অক্ষর *device)
{
	কাঠামো sshsk_resident_চাবি **srks;
	আকার_t nsrks, i;
	পূর্ণসংখ্যা r, ret = -1;
	অক্ষর *fp, *pin = ফাঁকা, *pass = ফাঁকা, *path, *pubpath;
	ধ্রুবক অক্ষর *ext;
	কাঠামো sshkey *চাবি;

	যদি (skprovider == ফাঁকা)
		fatal("Cannot download keys without provider");

	pin = read_passphrase("Enter PIN for authenticator: ", RP_ALLOW_STDIN);
	যদি (!quiet) {
		printf("You may need to touch your authenticator "
		    "to authorize key download.\n");
	}
	যদি ((r = sshsk_load_resident(skprovider, device, pin, 0,
	    &srks, &nsrks)) != 0) {
		যদি (pin != ফাঁকা)
			freezero(pin, strlen(pin));
		error_r(r, "Unable to load resident keys");
		ফেরত -1;
	}
	যদি (nsrks == 0)
		logit("No keys to download");
	যদি (pin != ফাঁকা)
		freezero(pin, strlen(pin));

	জন্য (i = 0; i < nsrks; i++) {
		চাবি = srks[i]->চাবি;
		যদি (চাবি->type != চাবি_ECDSA_SK && চাবি->type != চাবি_ED25519_SK) {
			error("Unsupported key type %s (%d)",
			    sshkey_type(চাবি), চাবি->type);
			চালু;
		}
		যদি ((fp = sshkey_fingerprint(চাবি, fingerprint_hash,
		    SSH_FP_DEFAULT)) == ফাঁকা)
			fatal_f("sshkey_fingerprint failed");
		debug_f("key %zu: %s %s %s (flags 0x%02x)", i,
		    sshkey_type(চাবি), fp, চাবি->sk_application, চাবি->sk_flags);
		ext = sk_suffix(চাবি->sk_application,
		    srks[i]->user_id, srks[i]->user_id_len);
		xasprintf(&path, "id_%s_rk%s%s",
		    চাবি->type == চাবি_ECDSA_SK ? "ecdsa_sk" : "ed25519_sk",
		    *ext == '\0' ? "" : "_", ext);

		/* If the file already exists, ask the user to confirm. */
		যদি (!confirm_overwrite(path)) {
			মুক্ত(path);
			বিরতি;
		}

		/* Save the key with the application string as the comment */
		যদি (pass == ফাঁকা)
			pass = private_চাবি_passphrase(path);
		যদি ((r = sshkey_save_private(চাবি, path, pass,
		    চাবি->sk_application, private_চাবি_format,
		    openssh_format_cipher, rounds)) != 0) {
			error_r(r, "Saving key \"%s\" failed", path);
			মুক্ত(path);
			বিরতি;
		}
		যদি (!quiet) {
			printf("Saved %s key%s%s to %s\n", sshkey_type(চাবি),
			    *ext != '\0' ? " " : "",
			    *ext != '\0' ? চাবি->sk_application : "",
			    path);
		}

		/* Save public key too */
		xasprintf(&pubpath, "%s.pub", path);
		মুক্ত(path);
		যদি ((r = sshkey_save_public(চাবি, pubpath,
		    চাবি->sk_application)) != 0) {
			error_r(r, "Saving public key \"%s\" failed", pubpath);
			মুক্ত(pubpath);
			বিরতি;
		}
		মুক্ত(pubpath);
	}

	যদি (i >= nsrks)
		ret = 0; /* success */
	যদি (pass != ফাঁকা)
		freezero(pass, strlen(pass));
	sshsk_free_resident_চাবিগুলি(srks, nsrks);
	ফেরত ret;
}

স্থির শূন্য
save_attestation(কাঠামো sshbuf *attest, ধ্রুবক অক্ষর *path)
{
	mode_t omask;
	পূর্ণসংখ্যা r;

	যদি (path == ফাঁকা)
		ফেরত; /* nothing to do */
	যদি (attest == ফাঁকা || sshbuf_len(attest) == 0)
		fatal("Enrollment did not return attestation data");
	omask = umask(077);
	r = sshbuf_write_file(path, attest);
	umask(omask);
	যদি (r != 0)
		fatal_r(r, "Unable to write attestation data \"%s\"", path);
	যদি (!quiet)
		printf("Your FIDO attestation certificate has been saved in "
		    "%s\n", path);
}

স্থির পূর্ণসংখ্যা
confirm_sk_overwrite(ধ্রুবক অক্ষর *application, ধ্রুবক অক্ষর *user)
{
	অক্ষর yesno[3];

	printf("A resident key scoped to '%s' with user id '%s' already "
	    "exists.\n", application == ফাঁকা ? "ssh:" : application,
	    user == ফাঁকা ? "null" : user);
	printf("Overwrite key in token (y/n)? ");
	fflush(stdout);
	যদি (fgets(yesno, আকার(yesno), stdin) == ফাঁকা)
		ফেরত 0;
	যদি (yesno[0] != 'y' && yesno[0] != 'Y')
		ফেরত 0;
	ফেরত 1;
}

স্থির শূন্য
usage(শূন্য)
{
	fprintf(stderr,
	    "usage: ssh-keygen [-q] [-a rounds] [-b bits] [-C comment] [-f output_keyfile]\n"
	    "                  [-m format] [-N new_passphrase] [-O option]\n"
	    "                  [-t ecdsa|ecdsa-sk|ed25519|ed25519-sk|mldsa44-ed25519|rsa]\n"
	    "                  [-w provider] [-Z cipher]\n"
	    "       ssh-keygen -p [-a rounds] [-f keyfile] [-m format] [-N new_passphrase]\n"
	    "                   [-P old_passphrase] [-Z cipher]\n"
#ifdef WITH_OPENSSL
	    "       ssh-keygen -i [-f input_keyfile] [-m key_format]\n"
	    "       ssh-keygen -e [-f input_keyfile] [-m key_format]\n"
#endif
	    "       ssh-keygen -y [-f input_keyfile]\n"
	    "       ssh-keygen -c [-a rounds] [-C comment] [-f keyfile] [-P passphrase]\n"
	    "       ssh-keygen -l [-v] [-E fingerprint_hash] [-f input_keyfile]\n"
	    "       ssh-keygen -B [-f input_keyfile]\n");
#ifdef ENABLE_PKCS11
	fprintf(stderr,
	    "       ssh-keygen -D pkcs11\n");
#endif
	fprintf(stderr,
	    "       ssh-keygen -F hostname [-lv] [-f known_hosts_file]\n"
	    "       ssh-keygen -H [-f known_hosts_file]\n"
	    "       ssh-keygen -K [-a rounds] [-w provider]\n"
	    "       ssh-keygen -R hostname [-f known_hosts_file]\n"
	    "       ssh-keygen -r hostname [-g] [-f input_keyfile]\n"
#ifdef WITH_OPENSSL
	    "       ssh-keygen -M generate [-O option] output_file\n"
	    "       ssh-keygen -M screen [-f input_file] [-O option] output_file\n"
#endif
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
	exit(1);
}

/*
 * Main program for key management.
 */
পূর্ণসংখ্যা
প্রধান(পূর্ণসংখ্যা argc, অক্ষর **argv)
{
	অক্ষর comment[চাবি_COMMENT_MAX], *passphrase = ফাঁকা;
	অক্ষর *rr_hostname = ফাঁকা, *ep, *fp, *ra;
	কাঠামো sshkey *ব্যক্তিগত = ফাঁকা, *সর্বজনীন = ফাঁকা;
	কাঠামো passwd *pw;
	পূর্ণসংখ্যা ret = 0, r, opt, type;
	পূর্ণসংখ্যা change_passphrase = 0, change_comment = 0, show_cert = 0;
	পূর্ণসংখ্যা find_host = 0, delete_host = 0, hash_hosts = 0;
	পূর্ণসংখ্যা gen_all_hostkeys = 0, gen_krl = 0, update_krl = 0, check_krl = 0;
	পূর্ণসংখ্যা prefer_agent = 0, convert_to = 0, convert_from = 0;
	পূর্ণসংখ্যা print_public = 0, print_generic = 0, cert_serial_autoinc = 0;
	পূর্ণসংখ্যা do_gen_candidates = 0, do_screen_candidates = 0, download_sk = 0;
	unsigned long long cert_serial = 0;
	অক্ষর *identity_comment = ফাঁকা, *ca_চাবি_path = ফাঁকা, **opts = ফাঁকা;
	অক্ষর *sk_application = ফাঁকা, *sk_device = ফাঁকা, *sk_user = ফাঁকা;
	অক্ষর *sk_attestation_path = ফাঁকা;
	কাঠামো sshbuf *challenge = ফাঁকা, *attest = ফাঁকা;
	আকার_t i, nopts = 0;
	uint32_t bits = 0;
	uint8_t sk_flags = SSH_SK_USER_PRESENCE_REQD;
	ধ্রুবক অক্ষর *errstr, *p;
	পূর্ণসংখ্যা log_level = SYSLOG_LEVEL_INFO;
	অক্ষর *sign_op = ফাঁকা;

	বাহ্যিক পূর্ণসংখ্যা optind;
	বাহ্যিক অক্ষর *optarg;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	__progname = ssh_get_progname(argv[0]);

	seed_rng();

	log_init(argv[0], SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_USER, 1);

	msetlocale();

	/* we need this for the home * directory.  */
	pw = getpwuid(getuid());
	যদি (!pw)
		fatal("No user exists for uid %lu", (u_long)getuid());
	pw = pwcopy(pw);
	যদি (gethostname(hostname, আকার(hostname)) == -1)
		fatal("gethostname: %s", strerror(errno));

	sk_provider = getenv("SSH_SK_PROVIDER");

	/* Remaining characters: dGjJSTWx */
	যখন ((opt = getopt(argc, argv, "ABHKLQUXceghiklopquvy"
	    "C:D:E:F:I:M:N:O:P:R:V:Y:Z:"
	    "a:b:f:g:m:n:r:s:t:w:z:")) != -1) {
		নির্বাচন (opt) {
		ক্ষেত্র 'A':
			gen_all_hostkeys = 1;
			বিরতি;
		ক্ষেত্র 'b':
			bits = (uint32_t)strtonum(optarg, 1, UINT32_MAX,
			    &errstr);
			যদি (errstr)
				fatal("Bits has bad value %s (%s)",
					optarg, errstr);
			বিরতি;
		ক্ষেত্র 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			যদি (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			বিরতি;
		ক্ষেত্র 'F':
			find_host = 1;
			rr_hostname = optarg;
			বিরতি;
		ক্ষেত্র 'H':
			hash_hosts = 1;
			বিরতি;
		ক্ষেত্র 'I':
			cert_চাবি_id = optarg;
			বিরতি;
		ক্ষেত্র 'R':
			delete_host = 1;
			rr_hostname = optarg;
			বিরতি;
		ক্ষেত্র 'L':
			show_cert = 1;
			বিরতি;
		ক্ষেত্র 'l':
			print_fingerprint = 1;
			বিরতি;
		ক্ষেত্র 'B':
			print_bubblebabble = 1;
			বিরতি;
		ক্ষেত্র 'm':
			যদি (strcasecmp(optarg, "RFC4716") == 0 ||
			    strcasecmp(optarg, "ssh2") == 0) {
				convert_format = FMT_RFC4716;
				বিরতি;
			}
			যদি (strcasecmp(optarg, "PKCS8") == 0) {
				convert_format = FMT_PKCS8;
				private_চাবি_format = SSHKEY_PRIVATE_PKCS8;
				বিরতি;
			}
			যদি (strcasecmp(optarg, "PEM") == 0) {
				convert_format = FMT_PEM;
				private_চাবি_format = SSHKEY_PRIVATE_PEM;
				বিরতি;
			}
			যদি (strcasecmp(optarg, "hexdump") == 0) {
				convert_format = FMT_HEXDUMP;
				বিরতি;
			}
			fatal("Unsupported conversion format \"%s\"", optarg);
		ক্ষেত্র 'n':
			cert_principals = optarg;
			বিরতি;
		ক্ষেত্র 'o':
			/* no-op; new format is already the default */
			বিরতি;
		ক্ষেত্র 'p':
			change_passphrase = 1;
			বিরতি;
		ক্ষেত্র 'c':
			change_comment = 1;
			বিরতি;
		ক্ষেত্র 'f':
			যদি (strlcpy(identity_file, optarg,
			    আকার(identity_file)) >= আকার(identity_file))
				fatal("Identity filename too long");
			have_identity = 1;
			বিরতি;
		ক্ষেত্র 'g':
			print_generic = 1;
			বিরতি;
		ক্ষেত্র 'K':
			download_sk = 1;
			বিরতি;
		ক্ষেত্র 'P':
			identity_passphrase = optarg;
			বিরতি;
		ক্ষেত্র 'N':
			identity_new_passphrase = optarg;
			বিরতি;
		ক্ষেত্র 'Q':
			check_krl = 1;
			বিরতি;
		ক্ষেত্র 'O':
			opts = xrecallocarray(opts, nopts, nopts + 1,
			    আকার(*opts));
			opts[nopts++] = xstrdup(optarg);
			বিরতি;
		ক্ষেত্র 'Z':
			openssh_format_cipher = optarg;
			যদি (cipher_by_name(openssh_format_cipher) == ফাঁকা)
				fatal("Invalid OpenSSH-format cipher '%s'",
				    openssh_format_cipher);
			বিরতি;
		ক্ষেত্র 'C':
			identity_comment = optarg;
			বিরতি;
		ক্ষেত্র 'q':
			quiet = 1;
			বিরতি;
		ক্ষেত্র 'e':
			/* export key */
			convert_to = 1;
			বিরতি;
		ক্ষেত্র 'h':
			cert_চাবি_type = SSH2_CERT_TYPE_HOST;
			certflags_flags = 0;
			বিরতি;
		ক্ষেত্র 'k':
			gen_krl = 1;
			বিরতি;
		ক্ষেত্র 'i':
		ক্ষেত্র 'X':
			/* import key */
			convert_from = 1;
			বিরতি;
		ক্ষেত্র 'y':
			print_public = 1;
			বিরতি;
		ক্ষেত্র 's':
			ca_চাবি_path = optarg;
			বিরতি;
		ক্ষেত্র 't':
			চাবি_type_name = optarg;
			বিরতি;
		ক্ষেত্র 'D':
			pkcs11provider = optarg;
			বিরতি;
		ক্ষেত্র 'U':
			prefer_agent = 1;
			বিরতি;
		ক্ষেত্র 'u':
			update_krl = 1;
			বিরতি;
		ক্ষেত্র 'v':
			যদি (log_level == SYSLOG_LEVEL_INFO)
				log_level = SYSLOG_LEVEL_DEBUG1;
			অন্যথা {
				যদি (log_level >= SYSLOG_LEVEL_DEBUG1 &&
				    log_level < SYSLOG_LEVEL_DEBUG3)
					log_level++;
			}
			বিরতি;
		ক্ষেত্র 'r':
			rr_hostname = optarg;
			বিরতি;
		ক্ষেত্র 'a':
			rounds = (পূর্ণসংখ্যা)strtonum(optarg, 1, INT_MAX, &errstr);
			যদি (errstr)
				fatal("Invalid number: %s (%s)",
					optarg, errstr);
			বিরতি;
		ক্ষেত্র 'V':
			parse_cert_times(optarg);
			বিরতি;
		ক্ষেত্র 'Y':
			sign_op = optarg;
			বিরতি;
		ক্ষেত্র 'w':
			sk_provider = optarg;
			বিরতি;
		ক্ষেত্র 'z':
			errno = 0;
			যদি (*optarg == '+') {
				cert_serial_autoinc = 1;
				optarg++;
			}
			cert_serial = strtoull(optarg, &ep, 10);
			যদি (*optarg < '0' || *optarg > '9' || *ep != '\0' ||
			    (errno == ERANGE && cert_serial == ULLONG_MAX))
				fatal("Invalid serial number \"%s\"", optarg);
			বিরতি;
		ক্ষেত্র 'M':
			যদি (strcmp(optarg, "generate") == 0)
				do_gen_candidates = 1;
			অন্যথা যদি (strcmp(optarg, "screen") == 0)
				do_screen_candidates = 1;
			অন্যথা
				fatal("Unsupported moduli option %s", optarg);
			বিরতি;
		পূর্বনির্ধারিত:
			usage();
		}
	}

#ifdef ENABLE_SK_INTERNAL
	যদি (sk_provider == ফাঁকা)
		sk_provider = "internal";
#endif

	/* reinit */
	log_init(argv[0], log_level, SYSLOG_FACILITY_USER, 1);

	argv += optind;
	argc -= optind;

	যদি (sign_op != ফাঁকা) {
		যদি (strprefix(sign_op, "find-principals", 0) != ফাঁকা) {
			যদি (ca_চাবি_path == ফাঁকা) {
				error("Too few arguments for find-principals:"
				    "missing signature file");
				exit(1);
			}
			যদি (!have_identity) {
				error("Too few arguments for find-principals:"
				    "missing allowed keys file");
				exit(1);
			}
			ret = sig_find_principals(ca_চাবি_path, identity_file,
			    opts, nopts);
			যাও done;
		} অন্যথা যদি (strprefix(sign_op, "match-principals", 0) != ফাঁকা) {
			যদি (!have_identity) {
				error("Too few arguments for match-principals:"
				    "missing allowed keys file");
				exit(1);
			}
			যদি (cert_চাবি_id == ফাঁকা) {
				error("Too few arguments for match-principals: "
				    "missing principal ID");
				exit(1);
			}
			ret = sig_match_principals(identity_file, cert_চাবি_id,
			    opts, nopts);
			যাও done;
		} অন্যথা যদি (strprefix(sign_op, "sign", 0) != ফাঁকা) {
			/* NB. cert_principals is actually namespace, via -n */
			যদি (cert_principals == ফাঁকা ||
			    *cert_principals == '\0') {
				error("Too few arguments for sign: "
				    "missing namespace");
				exit(1);
			}
			যদি (!have_identity) {
				error("Too few arguments for sign: "
				    "missing key");
				exit(1);
			}
			ret = sig_sign(identity_file, cert_principals,
			    prefer_agent, argc, argv, opts, nopts);
			যাও done;
		} অন্যথা যদি (strprefix(sign_op, "check-novalidate", 0) != ফাঁকা) {
			/* NB. cert_principals is actually namespace, via -n */
			যদি (cert_principals == ফাঁকা ||
			    *cert_principals == '\0') {
				error("Too few arguments for check-novalidate: "
				    "missing namespace");
				exit(1);
			}
			যদি (ca_চাবি_path == ফাঁকা) {
				error("Too few arguments for check-novalidate: "
				    "missing signature file");
				exit(1);
			}
			ret = sig_verify(ca_চাবি_path, cert_principals,
			    ফাঁকা, ফাঁকা, ফাঁকা, opts, nopts);
			যাও done;
		} অন্যথা যদি (strprefix(sign_op, "verify", 0) != ফাঁকা) {
			/* NB. cert_principals is actually namespace, via -n */
			যদি (cert_principals == ফাঁকা ||
			    *cert_principals == '\0') {
				error("Too few arguments for verify: "
				    "missing namespace");
				exit(1);
			}
			যদি (ca_চাবি_path == ফাঁকা) {
				error("Too few arguments for verify: "
				    "missing signature file");
				exit(1);
			}
			যদি (!have_identity) {
				error("Too few arguments for sign: "
				    "missing allowed keys file");
				exit(1);
			}
			যদি (cert_চাবি_id == ফাঁকা) {
				error("Too few arguments for verify: "
				    "missing principal identity");
				exit(1);
			}
			ret = sig_verify(ca_চাবি_path, cert_principals,
			    cert_চাবি_id, identity_file, rr_hostname,
			    opts, nopts);
			যাও done;
		}
		error("Unsupported operation for -Y: \"%s\"", sign_op);
		usage();
		/* NOTREACHED */
	}

	যদি (ca_চাবি_path != ফাঁকা) {
		যদি (argc < 1 && !gen_krl) {
			error("Too few arguments.");
			usage();
		}
	} অন্যথা যদি (argc > 0 && !gen_krl && !check_krl &&
	    !do_gen_candidates && !do_screen_candidates) {
		error("Too many arguments.");
		usage();
	}
	যদি (change_passphrase && change_comment) {
		error("Can only have one of -p and -c.");
		usage();
	}
	যদি (print_fingerprint && (delete_host || hash_hosts)) {
		error("Cannot use -l with -H or -R.");
		usage();
	}
	যদি (gen_krl) {
		do_gen_krl(pw, update_krl, ca_চাবি_path,
		    cert_serial, identity_comment, argc, argv);
		যাও done;
	}
	যদি (check_krl) {
		do_check_krl(pw, print_fingerprint, argc, argv);
		যাও done;
	}
	যদি (ca_চাবি_path != ফাঁকা) {
		যদি (cert_চাবি_id == ফাঁকা)
			fatal("Must specify key id (-I) when certifying");
		যদি (cert_principals == ফাঁকা) {
			/*
			 * Ideally this would be a fatal(), but we need to
			 * be able to generate such certificates for testing
			 * even though they will be rejected.
			 */
			error("Warning: certificate will contain no "
			    "principals (-n)");
		}
		জন্য (i = 0; i < nopts; i++)
			add_cert_option(opts[i]);
		do_ca_sign(pw, ca_চাবি_path, prefer_agent,
		    cert_serial, cert_serial_autoinc, argc, argv);
		যাও done;
	}
	যদি (show_cert)
		do_show_cert(pw);
	যদি (delete_host || hash_hosts || find_host) {
		do_known_hosts(pw, rr_hostname, find_host,
		    delete_host, hash_hosts);
	}
	যদি (pkcs11provider != ফাঁকা)
		do_download(pw);
	যদি (download_sk) {
		জন্য (i = 0; i < nopts; i++) {
			যদি ((p = strprefix(opts[i], "device=", 1)) != ফাঁকা) {
				sk_device = xstrdup(p);
			} অন্যথা {
				fatal("Option \"%s\" is unsupported for "
				    "FIDO authenticator download", opts[i]);
			}
		}
		ret = do_download_sk(sk_provider, sk_device);
		যাও done;
	}
	যদি (print_fingerprint || print_bubblebabble)
		do_fingerprint(pw);
	যদি (change_passphrase)
		do_change_passphrase(pw, opts, nopts);
	যদি (change_comment)
		do_change_comment(pw, identity_comment);
#ifdef WITH_OPENSSL
	যদি (convert_to) {
		do_convert_to(pw);
		যাও done;
	}
	যদি (convert_from) {
		do_convert_from(pw);
		যাও done;
	}
#অন্যথা /* WITH_OPENSSL */
	যদি (convert_to || convert_from)
		fatal("key conversion disabled at compile time");
#endif /* WITH_OPENSSL */
	যদি (print_public)
		do_print_public(pw);
	যদি (rr_hostname != ফাঁকা) {
		unsigned পূর্ণসংখ্যা n = 0;

		যদি (have_identity) {
			n = do_print_resource_record(pw, identity_file,
			    rr_hostname, print_generic, opts, nopts);
			যদি (n == 0)
				fatal("%s: %s", identity_file, strerror(errno));
			exit(0);
		} অন্যথা {

			n += do_print_resource_record(pw,
			    PATH_HOST_RSA_চাবি_FILE, rr_hostname,
			    print_generic, opts, nopts);
			n += do_print_resource_record(pw,
			    PATH_HOST_ECDSA_চাবি_FILE, rr_hostname,
			    print_generic, opts, nopts);
			n += do_print_resource_record(pw,
			    PATH_HOST_ED25519_চাবি_FILE, rr_hostname,
			    print_generic, opts, nopts);
			যদি (n == 0)
				fatal("no keys found.");
			exit(0);
		}
	}

	যদি (do_gen_candidates || do_screen_candidates) {
		যদি (argc <= 0)
			fatal("No output file specified");
		অন্যথা যদি (argc > 1)
			fatal("Too many output files specified");
	}
	যদি (do_gen_candidates) {
		do_moduli_gen(argv[0], opts, nopts);
		যাও done;
	}
	যদি (do_screen_candidates) {
		do_moduli_screen(argv[0], opts, nopts);
		যাও done;
	}

	যদি (gen_all_hostkeys) {
		do_gen_all_hostkeys(pw);
		যাও done;
	}

	যদি (চাবি_type_name == ফাঁকা)
		চাবি_type_name = DEFAULT_চাবি_TYPE_NAME;

	type = sshkey_type_from_shortname(চাবি_type_name);
	type_bits_valid(type, চাবি_type_name, &bits);

	যদি (!quiet)
		printf("Generating public/private %s key pair.\n",
		    চাবি_type_name);
	নির্বাচন (type) {
	ক্ষেত্র চাবি_ECDSA_SK:
	ক্ষেত্র চাবি_ED25519_SK:
		জন্য (i = 0; i < nopts; i++) {
			যদি (strcasecmp(opts[i], "no-touch-required") == 0) {
				sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
			} অন্যথা যদি (strcasecmp(opts[i], "verify-required") == 0) {
				sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
			} অন্যথা যদি (strcasecmp(opts[i], "resident") == 0) {
				sk_flags |= SSH_SK_RESIDENT_চাবি;
			} অন্যথা যদি ((p = strprefix(opts[i], "device=", 1))
			    != ফাঁকা ) {
				sk_device = xstrdup(p);
			} অন্যথা যদি ((p = strprefix(opts[i], "user=", 1))
			    != ফাঁকা) {
				sk_user = xstrdup(p);
			} অন্যথা যদি ((p = strprefix(opts[i], "challenge=", 1))
			    != ফাঁকা) {
				যদি ((r = sshbuf_load_file(p,
				    &challenge)) != 0) {
					fatal_r(r, "Unable to load FIDO "
					    "enrollment challenge \"%s\"", p);
				}
			} অন্যথা যদি (strncasecmp(opts[i],
			    "write-attestation=", 18) == 0) {
				sk_attestation_path = opts[i] + 18;
			} অন্যথা যদি (strncasecmp(opts[i],
			    "application=", 12) == 0) {
				sk_application = xstrdup(opts[i] + 12);
				যদি (strncmp(sk_application, "ssh:", 4) != 0) {
					fatal("FIDO application string must "
					    "begin with \"ssh:\"");
				}
			} অন্যথা {
				fatal("Option \"%s\" is unsupported for "
				    "FIDO authenticator enrollment", opts[i]);
			}
		}
		যদি ((attest = sshbuf_new()) == ফাঁকা)
			fatal("sshbuf_new failed");
		r = 0;
		জন্য (i = 0 ;;) {
			যদি (!quiet) {
				printf("You may need to touch your "
				    "authenticator%s to authorize key "
				    "generation.\n",
				    r == 0 ? "" : " again");
			}
			fflush(stdout);
			r = sshsk_enroll(type, sk_provider, sk_device,
			    sk_application == ফাঁকা ? "ssh:" : sk_application,
			    sk_user, sk_flags, passphrase, challenge,
			    &ব্যক্তিগত, attest);
			যদি (r == 0)
				বিরতি;
			যদি (r == SSH_ERR_চাবি_BAD_PERMISSIONS &&
			    (sk_flags & SSH_SK_RESIDENT_চাবি) != 0 &&
			    (sk_flags & SSH_SK_FORCE_OPERATION) == 0 &&
			    confirm_sk_overwrite(sk_application, sk_user)) {
				sk_flags |= SSH_SK_FORCE_OPERATION;
				চালু;
			}
			যদি (r != SSH_ERR_চাবি_WRONG_PASSPHRASE)
				fatal_r(r, "Key enrollment failed");
			অন্যথা যদি (passphrase != ফাঁকা) {
				error("PIN incorrect");
				freezero(passphrase, strlen(passphrase));
				passphrase = ফাঁকা;
			}
			যদি (++i >= 3)
				fatal("Too many incorrect PINs");
			passphrase = read_passphrase("Enter PIN for "
			    "authenticator: ", RP_ALLOW_STDIN);
		}
		যদি (passphrase != ফাঁকা) {
			freezero(passphrase, strlen(passphrase));
			passphrase = ফাঁকা;
		}
		বিরতি;
	পূর্বনির্ধারিত:
		যদি ((r = sshkey_generate(type, bits, &ব্যক্তিগত)) != 0)
			fatal("sshkey_generate failed");
		বিরতি;
	}
	যদি ((r = sshkey_from_private(ব্যক্তিগত, &সর্বজনীন)) != 0)
		fatal_r(r, "sshkey_from_private");

	যদি (!have_identity)
		ask_filename(pw, "Enter file in which to save the key");

	/* Create ~/.ssh directory if it doesn't already exist. */
	hostfile_create_user_ssh_dir(identity_file, !quiet);

	/* If the file already exists, ask the user to confirm. */
	যদি (!confirm_overwrite(identity_file))
		exit(1);

	/* Determine the passphrase for the private key */
	passphrase = private_চাবি_passphrase(identity_file);
	যদি (identity_comment) {
		strlcpy(comment, identity_comment, আকার(comment));
	} অন্যথা {
		/* Create default comment field for the passphrase. */
		snprintf(comment, আকার comment, "%s@%s", pw->pw_name, hostname);
	}



	/* Save the key with the given passphrase and comment. */
	যদি ((r = sshkey_save_private(ব্যক্তিগত, identity_file, passphrase,
	    comment, private_চাবি_format, openssh_format_cipher, rounds)) != 0) {
		error_r(r, "Saving key \"%s\" failed", identity_file);
		freezero(passphrase, strlen(passphrase));
		exit(1);
	}
	freezero(passphrase, strlen(passphrase));
	sshkey_free(ব্যক্তিগত);

	যদি (!quiet) {
		printf("Your identification has been saved in %s\n",
		    identity_file);
	}

	strlcat(identity_file, ".pub", আকার(identity_file));
	যদি ((r = sshkey_save_public(সর্বজনীন, identity_file, comment)) != 0)
		fatal_r(r, "Unable to save public key to %s", identity_file);

	যদি (!quiet) {
		fp = sshkey_fingerprint(সর্বজনীন, fingerprint_hash,
		    SSH_FP_DEFAULT);
		ra = sshkey_fingerprint(সর্বজনীন, fingerprint_hash,
		    SSH_FP_RANDOMART);
		যদি (fp == ফাঁকা || ra == ফাঁকা)
			fatal("sshkey_fingerprint failed");
		printf("Your public key has been saved in %s\n",
		    identity_file);
		printf("The key fingerprint is:\n");
		printf("%s %s\n", fp, comment);
		printf("The key's randomart image is:\n");
		printf("%s\n", ra);
		মুক্ত(ra);
		মুক্ত(fp);
	}

	যদি (sk_attestation_path != ফাঁকা)
		save_attestation(attest, sk_attestation_path);

 done:
	sshbuf_free(attest);
	sshkey_free(সর্বজনীন);
	pwfree(pw);
	exit(ret);
}
