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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/socket.h>
#شامل <sys/stat.h>

#ifdef WITH_OPENSSL
#شامل "openbsd-compat/openssl-compat.h"
#شامل <openssl/bn.h>
#شامل <openssl/evp.h>
#شامل <openssl/pem.h>
#endif

#شامل <stdint.h>
#شامل <errno.h>
#شامل <fcntl.h>
#شامل <netdb.h>
#شامل <paths.h>
#شامل <pwd.h>
#شامل <stdarg.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <unistd.h>
#شامل <limits.h>
#شامل <locale.h>
#شامل <time.h>

#شامل "xmalloc.h"
#شامل "sshkey.h"
#شامل "authfile.h"
#شامل "sshbuf.h"
#شامل "pathnames.h"
#شامل "log.h"
#شامل "misc.h"
#شامل "match.h"
#شامل "hostfile.h"
#شامل "dns.h"
#شامل "ssh.h"
#شامل "ssh2.h"
#شامل "ssherr.h"
#شامل "atomicio.h"
#شامل "krl.h"
#شامل "digest.h"
#شامل "utf8.h"
#شامل "authfd.h"
#شامل "sshsig.h"
#شامل "ssh-sk.h"
#شامل "sk-api.h" /* XXX for SSH_SK_USER_PRESENCE_REQD; remove */
#شامل "cipher.h"

#ifdef ENABLE_PKCS11
#شامل "ssh-pkcs11.h"
#endif

#define DEFAULT_کلید_TYPE_NAME "ed25519"

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

#define کلید_COMMENT_MAX		(NI_MAXHOST + 1024)

ایستا صحیح quiet = 0;

/* Flag indicating that we just want to see the key fingerprint */
ایستا صحیح print_fingerprint = 0;
ایستا صحیح print_bubblebabble = 0;

/* Hash algorithm to use for fingerprints. */
ایستا صحیح fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* The identity file name, given on the command line or entered by the user. */
ایستا نویسه identity_file[PATH_MAX];
ایستا صحیح have_identity = 0;

/* This is set to the passphrase if given on the command line. */
ایستا نویسه *identity_passphrase = پوچ;

/* This is set to the new passphrase if given on the command line. */
ایستا نویسه *identity_new_passphrase = پوچ;

/* Key type when certifying */
ایستا u_int cert_کلید_type = SSH2_CERT_TYPE_USER;

/* "key ID" of signed key */
ایستا نویسه *cert_کلید_id = پوچ;

/* Comma-separated list of principal names for certifying keys */
ایستا نویسه *cert_principals = پوچ;

/* Validity period for certificates */
ایستا uint64_t cert_valid_from = 0;
ایستا uint64_t cert_valid_to = ~0ULL;

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
ایستا uint32_t certflags_flags = CERTOPT_DEFAULT;
ایستا نویسه *certflags_command = پوچ;
ایستا نویسه *certflags_src_addr = پوچ;

/* Arbitrary extensions specified by user */
ساختار cert_ext {
	نویسه *کلید;
	نویسه *val;
	صحیح crit;
};
ایستا ساختار cert_ext *cert_ext;
ایستا size_t ncert_ext;

/* Conversion to/from various formats */
شمارش {
	FMT_RFC4716,
	FMT_PKCS8,
	FMT_PEM,
	FMT_HEXDUMP
} convert_format = FMT_RFC4716;

ایستا نویسه *کلید_type_name = پوچ;

/* Load key from this PKCS#11 provider */
ایستا نویسه *pkcs11provider = پوچ;

/* FIDO/U2F provider to use */
ایستا نویسه *sk_provider = پوچ;

/* Format for writing private keys */
ایستا صحیح private_کلید_format = SSHKEY_PRIVATE_OPENSSH;

/* Cipher for new-format private keys */
ایستا نویسه *openssh_format_cipher = پوچ;

/* Number of KDF rounds to derive new format keys. */
ایستا صحیح rounds = 0;

/* argv0 */
بیرونی نویسه *__progname;

ایستا نویسه hostname[NI_MAXHOST];

#ifdef WITH_OPENSSL
/* moduli.c */
صحیح gen_candidates(FILE *, uint32_t, BIGNUM *);
صحیح اول_test(FILE *, FILE *, uint32_t, uint32_t, نویسه *, unsigned long,
    unsigned long);
#endif

ایستا تهی
type_bits_valid(صحیح type, ثابت نویسه *name, uint32_t *bitsp)
{
	اگر (type == کلید_UNSPEC)
		fatal("unknown key type %s", کلید_type_name);
	اگر (*bitsp == 0) {
#ifdef WITH_OPENSSL
		صحیح nid;

		انتخاب(type) {
		حالت کلید_ECDSA:
			اگر (name != پوچ &&
			    (nid = sshkey_ecdsa_nid_from_name(name)) > 0)
				*bitsp = sshkey_curve_nid_to_bits(nid);
			اگر (*bitsp == 0)
				*bitsp = DEFAULT_BITS_ECDSA;
			بشکن;
		حالت کلید_RSA:
			*bitsp = DEFAULT_BITS;
			بشکن;
		}
#endif
	}
#ifdef WITH_OPENSSL
	انتخاب (type) {
	حالت کلید_RSA:
		اگر (*bitsp < SSH_RSA_MINIMUM_MODULUS_SIZE)
			fatal("Invalid RSA key length: minimum is %d bits",
			    SSH_RSA_MINIMUM_MODULUS_SIZE);
		وگرنه اگر (*bitsp > OPENSSL_RSA_MAX_MODULUS_BITS)
			fatal("Invalid RSA key length: maximum is %d bits",
			    OPENSSL_RSA_MAX_MODULUS_BITS);
		بشکن;
	حالت کلید_ECDSA:
		اگر (sshkey_ecdsa_bits_to_nid(*bitsp) == -1)
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
ایستا صحیح
confirm_overwrite(ثابت نویسه *filename)
{
	نویسه yesno[3];
	ساختار stat st;

	اگر (stat(filename, &st) != 0)
		بازگشت 1;
	printf("%s already exists.\n", filename);
	printf("Overwrite (y/n)? ");
	fflush(stdout);
	اگر (fgets(yesno, اندازه(yesno), stdin) == پوچ)
		بازگشت 0;
	اگر (yesno[0] != 'y' && yesno[0] != 'Y')
		بازگشت 0;
	بازگشت 1;
}

ایستا تهی
ask_filename(ساختار passwd *pw, ثابت نویسه *prompt)
{
	نویسه buf[1024];
	نویسه *name = پوچ;

	اگر (کلید_type_name == پوچ)
		name = _PATH_SSH_CLIENT_ID_ED25519;
	وگرنه {
		انتخاب (sshkey_type_from_shortname(کلید_type_name)) {
		حالت کلید_ECDSA_CERT:
		حالت کلید_ECDSA:
			name = _PATH_SSH_CLIENT_ID_ECDSA;
			بشکن;
		حالت کلید_ECDSA_SK_CERT:
		حالت کلید_ECDSA_SK:
			name = _PATH_SSH_CLIENT_ID_ECDSA_SK;
			بشکن;
		حالت کلید_RSA_CERT:
		حالت کلید_RSA:
			name = _PATH_SSH_CLIENT_ID_RSA;
			بشکن;
		حالت کلید_ED25519:
		حالت کلید_ED25519_CERT:
			name = _PATH_SSH_CLIENT_ID_ED25519;
			بشکن;
		حالت کلید_ED25519_SK:
		حالت کلید_ED25519_SK_CERT:
			name = _PATH_SSH_CLIENT_ID_ED25519_SK;
			بشکن;
		حالت کلید_MLDSA44_ED25519:
		حالت کلید_MLDSA44_ED25519_CERT:
			name = _PATH_SSH_CLIENT_ID_MLDSA44_ED25519;
			بشکن;
		پیشفرض:
			fatal("bad key type");
		}
	}
	snprintf(identity_file, اندازه(identity_file),
	    "%s/%s", pw->pw_dir, name);
	printf("%s (%s): ", prompt, identity_file);
	fflush(stdout);
	اگر (fgets(buf, اندازه(buf), stdin) == پوچ)
		exit(1);
	buf[strcspn(buf, "\n")] = '\0';
	اگر (strcmp(buf, "") != 0)
		strlcpy(identity_file, buf, اندازه(identity_file));
	have_identity = 1;
}

ایستا ساختار sshkey *
load_identity(ثابت نویسه *filename, نویسه **commentp)
{
	نویسه *prompt, *pass;
	ساختار sshkey *prv;
	صحیح r;

	اگر (commentp != پوچ)
		*commentp = پوچ;
	اگر ((r = sshkey_load_private(filename, "", &prv, commentp)) == 0)
		بازگشت prv;
	اگر (r != SSH_ERR_کلید_WRONG_PASSPHRASE)
		fatal_r(r, "Load key \"%s\"", filename);
	اگر (identity_passphrase)
		pass = xstrdup(identity_passphrase);
	وگرنه {
		xasprintf(&prompt, "Enter passphrase for \"%s\": ", filename);
		pass = read_passphrase(prompt, RP_ALLOW_STDIN);
		آزاد(prompt);
	}
	r = sshkey_load_private(filename, pass, &prv, commentp);
	freezero(pass, strlen(pass));
	اگر (r != 0)
		fatal_r(r, "Load key \"%s\"", filename);
	بازگشت prv;
}

#define SSH_COM_PUBLIC_BEGIN		"---- BEGIN SSH2 PUBLIC KEY ----"
#define SSH_COM_PUBLIC_END		"---- END SSH2 PUBLIC KEY ----"
#define SSH_COM_PRIVATE_BEGIN		"---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----"
#define	SSH_COM_PRIVATE_کلید_MAGIC	0x3f6ff9eb

#ifdef WITH_OPENSSL
ایستا تهی
do_convert_to_ssh2(ساختار passwd *pw, ساختار sshkey *k)
{
	ساختار sshbuf *b;
	نویسه comment[61], *b64;
	صحیح r;

	اگر ((b = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshkey_putb(k, b)) != 0)
		fatal_fr(r, "put key");
	اگر ((b64 = sshbuf_dtob64_string(b, 1)) == پوچ)
		fatal_f("sshbuf_dtob64_string failed");

	/* Comment + surrounds must fit into 72 chars (RFC 4716 sec 3.3) */
	snprintf(comment, اندازه(comment),
	    "%u-bit %s, converted by %s@%s from OpenSSH",
	    sshkey_size(k), sshkey_type(k),
	    pw->pw_name, hostname);

	sshkey_free(k);
	sshbuf_free(b);

	fprintf(stdout, "%s\n", SSH_COM_PUBLIC_BEGIN);
	fprintf(stdout, "Comment: \"%s\"\n%s", comment, b64);
	fprintf(stdout, "%s\n", SSH_COM_PUBLIC_END);
	آزاد(b64);
}

ایستا تهی
do_convert_to_pkcs8(ساختار sshkey *k)
{
	انتخاب (sshkey_type_plain(k->type)) {
	حالت کلید_RSA:
		اگر (!PEM_write_RSA_PUBKEY(stdout,
		    EVP_PKEY_get0_RSA(k->pkey)))
			fatal("PEM_write_RSA_PUBKEY failed");
		بشکن;
	حالت کلید_ECDSA:
		اگر (!PEM_write_EC_PUBKEY(stdout,
		    EVP_PKEY_get0_EC_کلید(k->pkey)))
			fatal("PEM_write_EC_PUBKEY failed");
		بشکن;
	پیشفرض:
		fatal_f("unsupported key type %s", sshkey_type(k));
	}
}

ایستا تهی
do_convert_to_pem(ساختار sshkey *k)
{
	انتخاب (sshkey_type_plain(k->type)) {
	حالت کلید_RSA:
		اگر (!PEM_write_RSAPublic_کلید(stdout,
		    EVP_PKEY_get0_RSA(k->pkey)))
			fatal("PEM_write_RSAPublicKey failed");
		بشکن;
	حالت کلید_ECDSA:
		اگر (!PEM_write_EC_PUBKEY(stdout,
		    EVP_PKEY_get0_EC_کلید(k->pkey)))
			fatal("PEM_write_EC_PUBKEY failed");
		بشکن;
	پیشفرض:
		fatal_f("unsupported key type %s", sshkey_type(k));
	}
}

ایستا تهی
do_convert_to_hexdump(ساختار sshkey *k)
{
	ساختار sshbuf *b;
	صحیح r;

	اگر ((b = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	/* pubkey */
	اگر ((r = sshkey_putb(k, b)) != 0)
		fatal_fr(r, "serialise private");
	printf("Public %s key:\n", sshkey_type(k));
	sshbuf_dump(b, stdout);
	sshbuf_reset(b);
	اگر ((r = sshkey_private_serialize(k, b)) != 0) {
		debug_fr(r, "serialise private");
		برو out;
	}
	printf("\nPrivate %s key:\n", sshkey_type(k));
	sshbuf_dump(b, stdout);
 out:
	sshbuf_free(b);
}

ایستا تهی
do_convert_to(ساختار passwd *pw)
{
	ساختار sshkey *k = پوچ;
	ساختار stat st;
	صحیح r;

	اگر (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	اگر (stat(identity_file, &st) == -1)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));

	/* If we're trying to hexdump, then prefer the private key */
	اگر (convert_format == FMT_HEXDUMP) {
		اگر ((r = sshkey_load_private(identity_file,
		    پوچ, &k, پوچ)) != 0 &&
		    r == SSH_ERR_کلید_WRONG_PASSPHRASE)
			k = load_identity(identity_file, پوچ);
	}
	اگر (k == پوچ && (r = sshkey_load_public(identity_file, &k, پوچ)) != 0)
		k = load_identity(identity_file, پوچ);

	انتخاب (convert_format) {
	حالت FMT_RFC4716:
		do_convert_to_ssh2(pw, k);
		بشکن;
	حالت FMT_PKCS8:
		do_convert_to_pkcs8(k);
		بشکن;
	حالت FMT_PEM:
		do_convert_to_pem(k);
		بشکن;
	حالت FMT_HEXDUMP:
		do_convert_to_hexdump(k);
		بشکن;
	پیشفرض:
		fatal_f("unknown key format %d", convert_format);
	}
}

/*
 * This is almost exactly the bignum1 encoding, but with 32 bit for length
 * instead of 16.
 */
ایستا تهی
buffer_get_bignum_bits(ساختار sshbuf *b, BIGNUM *مقدار)
{
	u_int bytes, bignum_bits;
	صحیح r;

	اگر ((r = sshbuf_get_u32(b, &bignum_bits)) != 0)
		fatal_fr(r, "parse");
	bytes = (bignum_bits + 7) / 8;
	اگر (sshbuf_len(b) < bytes)
		fatal_f("input buffer too small: need %d have %zu",
		    bytes, sshbuf_len(b));
	اگر (BN_bin2bn(sshbuf_ptr(b), bytes, مقدار) == پوچ)
		fatal_f("BN_bin2bn failed");
	اگر ((r = sshbuf_consume(b, bytes)) != 0)
		fatal_fr(r, "consume");
}

ایستا ساختار sshkey *
do_convert_private_ssh2(ساختار sshbuf *b)
{
	ساختار sshkey *کلید = پوچ;
	نویسه *type, *cipher;
	ثابت نویسه *alg = پوچ;
	u_char e1, e2, e3, *sig = پوچ, data[] = "abcde12345";
	صحیح r, rlen, ktype;
	u_int magic, i1, i2, i3, i4;
	size_t slen;
	u_long e;
	BIGNUM *rsa_n = پوچ, *rsa_e = پوچ, *rsa_d = پوچ;
	BIGNUM *rsa_p = پوچ, *rsa_q = پوچ, *rsa_iqmp = پوچ;
	BIGNUM *rsa_dmp1 = پوچ, *rsa_dmq1 = پوچ;
	RSA *rsa = پوچ;

	اگر ((r = sshbuf_get_u32(b, &magic)) != 0)
		fatal_fr(r, "parse magic");

	اگر (magic != SSH_COM_PRIVATE_کلید_MAGIC) {
		error("bad magic 0x%x != 0x%x", magic,
		    SSH_COM_PRIVATE_کلید_MAGIC);
		بازگشت پوچ;
	}
	اگر ((r = sshbuf_get_u32(b, &i1)) != 0 ||
	    (r = sshbuf_get_cstring(b, &type, پوچ)) != 0 ||
	    (r = sshbuf_get_cstring(b, &cipher, پوچ)) != 0 ||
	    (r = sshbuf_get_u32(b, &i2)) != 0 ||
	    (r = sshbuf_get_u32(b, &i3)) != 0 ||
	    (r = sshbuf_get_u32(b, &i4)) != 0)
		fatal_fr(r, "parse");
	debug("ignore (%d %d %d %d)", i1, i2, i3, i4);
	اگر (strcmp(cipher, "none") != 0) {
		error("unsupported cipher %s", cipher);
		آزاد(cipher);
		آزاد(type);
		بازگشت پوچ;
	}
	آزاد(cipher);

	اگر (strstr(type, "rsa")) {
		ktype = کلید_RSA;
	} وگرنه {
		آزاد(type);
		بازگشت پوچ;
	}
	اگر ((کلید = sshkey_new(ktype)) == پوچ)
		fatal("sshkey_new failed");
	آزاد(type);

	انتخاب (کلید->type) {
	حالت کلید_RSA:
		اگر ((r = sshbuf_get_u8(b, &e1)) != 0 ||
		    (e1 < 30 && (r = sshbuf_get_u8(b, &e2)) != 0) ||
		    (e1 < 30 && (r = sshbuf_get_u8(b, &e3)) != 0))
			fatal_fr(r, "parse RSA");
		e = e1;
		debug("e %lx", e);
		اگر (e < 30) {
			e <<= 8;
			e += e2;
			debug("e %lx", e);
			e <<= 8;
			e += e3;
			debug("e %lx", e);
		}
		اگر ((rsa_e = BN_new()) == پوچ)
			fatal_f("BN_new");
		اگر (!BN_set_word(rsa_e, e)) {
			BN_clear_free(rsa_e);
			sshkey_free(کلید);
			بازگشت پوچ;
		}
		اگر ((rsa_n = BN_new()) == پوچ ||
		    (rsa_d = BN_new()) == پوچ ||
		    (rsa_p = BN_new()) == پوچ ||
		    (rsa_q = BN_new()) == پوچ ||
		    (rsa_iqmp = BN_new()) == پوچ)
			fatal_f("BN_new");
		buffer_get_bignum_bits(b, rsa_d);
		buffer_get_bignum_bits(b, rsa_n);
		buffer_get_bignum_bits(b, rsa_iqmp);
		buffer_get_bignum_bits(b, rsa_q);
		buffer_get_bignum_bits(b, rsa_p);
		اگر ((r = ssh_rsa_complete_crt_parameters(rsa_d, rsa_p, rsa_q,
		    rsa_iqmp, &rsa_dmp1, &rsa_dmq1)) != 0)
			fatal_fr(r, "generate RSA CRT parameters");
		EVP_PKEY_free(کلید->pkey);
		اگر ((کلید->pkey = EVP_PKEY_new()) == پوچ)
			fatal_f("EVP_PKEY_new failed");
		اگر ((rsa = RSA_new()) == پوچ)
			fatal_f("RSA_new failed");
		اگر (!RSA_set0_کلید(rsa, rsa_n, rsa_e, rsa_d))
			fatal_f("RSA_set0_key failed");
		rsa_n = rsa_e = rsa_d = پوچ; /* transferred */
		اگر (!RSA_set0_factors(rsa, rsa_p, rsa_q))
			fatal_f("RSA_set0_factors failed");
		rsa_p = rsa_q = پوچ; /* transferred */
		اگر (RSA_set0_crt_params(rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp) != 1)
			fatal_f("RSA_set0_crt_params failed");
		rsa_dmp1 = rsa_dmq1 = rsa_iqmp = پوچ;
		اگر (EVP_PKEY_set1_RSA(کلید->pkey, rsa) != 1)
			fatal_f("EVP_PKEY_set1_RSA failed");
		RSA_free(rsa);
		alg = "rsa-sha2-256";
		بشکن;
	}
	rlen = sshbuf_len(b);
	اگر (rlen != 0)
		error_f("remaining bytes in key blob %d", rlen);

	/* try the key */
	اگر ((r = sshkey_sign(کلید, &sig, &slen, data, اندازه(data),
	    alg, پوچ, پوچ, 0)) != 0)
		error_fr(r, "signing with converted key failed");
	وگرنه اگر ((r = sshkey_verify(کلید, sig, slen, data, اندازه(data),
	    alg, 0, پوچ)) != 0)
		error_fr(r, "verification with converted key failed");
	اگر (r != 0) {
		sshkey_free(کلید);
		آزاد(sig);
		بازگشت پوچ;
	}
	آزاد(sig);
	بازگشت کلید;
}

ایستا صحیح
get_سطر(FILE *fp, نویسه *سطر, size_t len)
{
	صحیح c;
	size_t pos = 0;

	سطر[0] = '\0';
	وقتی ((c = fgetc(fp)) != EOF) {
		اگر (pos >= len - 1)
			fatal("input line too long.");
		انتخاب (c) {
		حالت '\r':
			c = fgetc(fp);
			اگر (c != EOF && c != '\n' && ungetc(c, fp) == EOF)
				fatal("unget: %s", strerror(errno));
			بازگشت pos;
		حالت '\n':
			بازگشت pos;
		}
		سطر[pos++] = c;
		سطر[pos] = '\0';
	}
	/* We reached EOF */
	بازگشت -1;
}

ایستا تهی
do_convert_from_ssh2(ساختار passwd *pw, ساختار sshkey **k, صحیح *خصوصی)
{
	صحیح r, blen, escaped = 0;
	u_int len;
	نویسه سطر[1024];
	ساختار sshbuf *buf;
	نویسه encoded[8096];
	FILE *fp;

	اگر ((buf = sshbuf_new()) == پوچ)
		fatal("sshbuf_new failed");
	اگر ((fp = fopen(identity_file, "r")) == پوچ)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));
	encoded[0] = '\0';
	وقتی ((blen = get_سطر(fp, سطر, اندازه(سطر))) != -1) {
		اگر (blen > 0 && سطر[blen - 1] == '\\')
			escaped++;
		اگر (strncmp(سطر, "----", 4) == 0 ||
		    strstr(سطر, ": ") != پوچ) {
			اگر (strstr(سطر, SSH_COM_PRIVATE_BEGIN) != پوچ)
				*خصوصی = 1;
			اگر (strstr(سطر, " END ") != پوچ) {
				بشکن;
			}
			/* fprintf(stderr, "ignore: %s", line); */
			ادامه;
		}
		اگر (escaped) {
			escaped--;
			/* fprintf(stderr, "escaped: %s", line); */
			ادامه;
		}
		strlcat(encoded, سطر, اندازه(encoded));
	}
	len = strlen(encoded);
	اگر (((len % 4) == 3) &&
	    (encoded[len-1] == '=') &&
	    (encoded[len-2] == '=') &&
	    (encoded[len-3] == '='))
		encoded[len-3] = '\0';
	اگر ((r = sshbuf_b64tod(buf, encoded)) != 0)
		fatal_fr(r, "base64 decode");
	اگر (*خصوصی) {
		اگر ((*k = do_convert_private_ssh2(buf)) == پوچ)
			fatal_f("private key conversion failed");
	} وگرنه اگر ((r = sshkey_fromb(buf, k)) != 0)
		fatal_fr(r, "parse key");
	sshbuf_free(buf);
	fclose(fp);
}

ایستا تهی
do_convert_from_pkcs8(ساختار sshkey **k, صحیح *خصوصی)
{
	EVP_PKEY *pubkey;
	FILE *fp;

	اگر ((fp = fopen(identity_file, "r")) == پوچ)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));
	اگر ((pubkey = PEM_read_PUBKEY(fp, پوچ, پوچ, پوچ)) == پوچ) {
		fatal_f("%s is not a recognised public key format",
		    identity_file);
	}
	fclose(fp);
	انتخاب (EVP_PKEY_base_id(pubkey)) {
	حالت EVP_PKEY_RSA:
		اگر ((*k = sshkey_new(کلید_UNSPEC)) == پوچ)
			fatal("sshkey_new failed");
		(*k)->type = کلید_RSA;
		(*k)->pkey = pubkey;
		pubkey = پوچ;
		بشکن;
	حالت EVP_PKEY_EC:
		اگر ((*k = sshkey_new(کلید_UNSPEC)) == پوچ)
			fatal("sshkey_new failed");
		اگر (((*k)->ecdsa_nid = sshkey_ecdsa_fixup_group(pubkey)) == -1)
			fatal("sshkey_ecdsa_fixup_group failed");
		(*k)->type = کلید_ECDSA;
		(*k)->pkey = pubkey;
		pubkey = پوچ;
		بشکن;
	پیشفرض:
		fatal_f("unsupported pubkey type %d",
		    EVP_PKEY_base_id(pubkey));
	}
	EVP_PKEY_free(pubkey);
}

ایستا تهی
do_convert_from_pem(ساختار sshkey **k, صحیح *خصوصی)
{
	FILE *fp;
	RSA *rsa;

	اگر ((fp = fopen(identity_file, "r")) == پوچ)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));
	اگر ((rsa = PEM_read_RSAPublic_کلید(fp, پوچ, پوچ, پوچ)) != پوچ) {
		اگر ((*k = sshkey_new(کلید_UNSPEC)) == پوچ)
			fatal("sshkey_new failed");
		اگر (((*k)->pkey = EVP_PKEY_new()) == پوچ)
			fatal("EVP_PKEY_new failed");
		(*k)->type = کلید_RSA;
		اگر (EVP_PKEY_set1_RSA((*k)->pkey, rsa) != 1)
			fatal("EVP_PKEY_set1_RSA failed");
		RSA_free(rsa);
		fclose(fp);
		بازگشت;
	}
	fatal_f("unrecognised raw private key format");
}

ایستا تهی
do_convert_from(ساختار passwd *pw)
{
	ساختار sshkey *k = پوچ;
	صحیح r, خصوصی = 0, ok = 0;
	ساختار stat st;

	اگر (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	اگر (stat(identity_file, &st) == -1)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));

	انتخاب (convert_format) {
	حالت FMT_RFC4716:
		do_convert_from_ssh2(pw, &k, &خصوصی);
		بشکن;
	حالت FMT_PKCS8:
		do_convert_from_pkcs8(&k, &خصوصی);
		بشکن;
	حالت FMT_PEM:
		do_convert_from_pem(&k, &خصوصی);
		بشکن;
	پیشفرض:
		fatal_f("unknown key format %d", convert_format);
	}

	اگر (!خصوصی) {
		اگر ((r = sshkey_write(k, stdout)) == 0)
			ok = 1;
		اگر (ok)
			fprintf(stdout, "\n");
	} وگرنه {
		انتخاب (k->type) {
		حالت کلید_ECDSA:
			ok = PEM_write_ECPrivate_کلید(stdout,
			    EVP_PKEY_get0_EC_کلید(k->pkey), پوچ, پوچ, 0,
			    پوچ, پوچ);
			بشکن;
		حالت کلید_RSA:
			ok = PEM_write_RSAPrivate_کلید(stdout,
			    EVP_PKEY_get0_RSA(k->pkey), پوچ, پوچ, 0,
			    پوچ, پوچ);
			بشکن;
		پیشفرض:
			fatal_f("unsupported key type %s", sshkey_type(k));
		}
	}

	اگر (!ok)
		fatal("key write failed");
	sshkey_free(k);
}
#endif

ایستا تهی
do_print_public(ساختار passwd *pw)
{
	ساختار sshkey *prv;
	ساختار stat st;
	صحیح r;
	نویسه *comment = پوچ;

	اگر (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	اگر (stat(identity_file, &st) == -1)
		fatal("%s: %s", identity_file, strerror(errno));
	prv = load_identity(identity_file, &comment);
	اگر ((r = sshkey_write(prv, stdout)) != 0)
		fatal_fr(r, "write key");
	اگر (comment != پوچ && *comment != '\0')
		fprintf(stdout, " %s", comment);
	fprintf(stdout, "\n");
	اگر (sshkey_is_sk(prv)) {
		debug("sk_application: \"%s\", sk_flags 0x%02x",
			prv->sk_application, prv->sk_flags);
	}
	sshkey_free(prv);
	آزاد(comment);
	exit(0);
}

ایستا تهی
do_download(ساختار passwd *pw)
{
#ifdef ENABLE_PKCS11
	ساختار sshkey **کلیدها = پوچ;
	صحیح i, nkeys;
	شمارش sshkey_fp_rep rep;
	صحیح fptype;
	نویسه *fp, *ra, **comments = پوچ;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;

	pkcs11_init(1);
	nkeys = pkcs11_add_provider(pkcs11provider, پوچ, &کلیدها, &comments);
	اگر (nkeys <= 0)
		fatal("cannot read public key from pkcs11");
	برای (i = 0; i < nkeys; i++) {
		اگر (print_fingerprint) {
			fp = sshkey_fingerprint(کلیدها[i], fptype, rep);
			ra = sshkey_fingerprint(کلیدها[i], fingerprint_hash,
			    SSH_FP_RANDOMART);
			اگر (fp == پوچ || ra == پوچ)
				fatal_f("sshkey_fingerprint fail");
			printf("%u %s %s (PKCS11 key)\n", sshkey_size(کلیدها[i]),
			    fp, sshkey_type(کلیدها[i]));
			اگر (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
				printf("%s\n", ra);
			آزاد(ra);
			آزاد(fp);
		} وگرنه {
			(تهی) sshkey_write(کلیدها[i], stdout); /* XXX check */
			fprintf(stdout, "%s%s\n",
			    *(comments[i]) == '\0' ? "" : " ", comments[i]);
		}
		آزاد(comments[i]);
		sshkey_free(کلیدها[i]);
	}
	آزاد(comments);
	آزاد(کلیدها);
	pkcs11_terminate();
	exit(0);
#وگرنه
	fatal("no pkcs11 support");
#endif /* ENABLE_PKCS11 */
}

ایستا ساختار sshkey *
try_read_کلید(نویسه **cpp)
{
	ساختار sshkey *ret;
	صحیح r;

	اگر ((ret = sshkey_new(کلید_UNSPEC)) == پوچ)
		fatal("sshkey_new failed");
	اگر ((r = sshkey_read(ret, cpp)) == 0)
		بازگشت ret;
	/* Not a key */
	sshkey_free(ret);
	بازگشت پوچ;
}

ایستا تهی
fingerprint_one_کلید(ثابت ساختار sshkey *عمومی, ثابت نویسه *comment)
{
	نویسه *fp = پوچ, *ra = پوچ;
	شمارش sshkey_fp_rep rep;
	صحیح fptype;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;
	fp = sshkey_fingerprint(عمومی, fptype, rep);
	ra = sshkey_fingerprint(عمومی, fingerprint_hash, SSH_FP_RANDOMART);
	اگر (fp == پوچ || ra == پوچ)
		fatal_f("sshkey_fingerprint failed");
	mprintf("%u %s %s (%s)\n", sshkey_size(عمومی), fp,
	    comment ? comment : "no comment", sshkey_type(عمومی));
	اگر (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
		printf("%s\n", ra);
	آزاد(ra);
	آزاد(fp);
}

ایستا تهی
fingerprint_private(ثابت نویسه *path)
{
	ساختار stat st;
	نویسه *comment = پوچ;
	ساختار sshkey *privkey = پوچ, *pubkey = پوچ;
	صحیح r;

	اگر (stat(identity_file, &st) == -1)
		fatal("%s: %s", path, strerror(errno));
	اگر ((r = sshkey_load_public(path, &pubkey, &comment)) != 0)
		debug_r(r, "load public \"%s\"", path);
	اگر (pubkey == پوچ || comment == پوچ || *comment == '\0') {
		آزاد(comment);
		اگر ((r = sshkey_load_private(path, پوچ,
		    &privkey, &comment)) != 0)
			debug_r(r, "load private \"%s\"", path);
	}
	اگر (pubkey == پوچ && privkey == پوچ)
		fatal("%s is not a key file.", path);

	fingerprint_one_کلید(pubkey == پوچ ? privkey : pubkey, comment);
	sshkey_free(pubkey);
	sshkey_free(privkey);
	آزاد(comment);
}

ایستا تهی
do_fingerprint(ساختار passwd *pw)
{
	FILE *f;
	ساختار sshkey *عمومی = پوچ;
	نویسه *comment = پوچ, *cp, *ep, *سطر = پوچ;
	size_t linesize = 0;
	صحیح i, invalid = 1;
	ثابت نویسه *path;
	u_long lnum = 0;

	اگر (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	path = identity_file;

	اگر (strcmp(identity_file, "-") == 0) {
		f = stdin;
		path = "(stdin)";
	} وگرنه اگر ((f = fopen(path, "r")) == پوچ)
		fatal("%s: %s: %s", __progname, path, strerror(errno));

	وقتی (getline(&سطر, &linesize, f) != -1) {
		lnum++;
		cp = سطر;
		cp[strcspn(cp, "\r\n")] = '\0';
		/* Trim leading space and comments */
		cp = سطر + strspn(سطر, " \t");
		اگر (*cp == '#' || *cp == '\0')
			ادامه;

		/*
		 * Input may be plain keys, private keys, authorized_keys
		 * or known_hosts.
		 */

		/*
		 * Try private keys first. Assume a key is private if
		 * "SSH PRIVATE KEY" appears on the first line and we're
		 * not reading from stdin (XXX support private keys on stdin).
		 */
		اگر (lnum == 1 && strcmp(identity_file, "-") != 0 &&
		    strstr(cp, "PRIVATE KEY") != پوچ) {
			آزاد(سطر);
			fclose(f);
			fingerprint_private(path);
			exit(0);
		}

		/*
		 * If it's not a private key, then this must be prepared to
		 * accept a public key prefixed with a hostname or options.
		 * Try a bare key first, otherwise skip the leading stuff.
		 */
		comment = پوچ;
		اگر ((عمومی = try_read_کلید(&cp)) == پوچ) {
			i = strtol(cp, &ep, 10);
			اگر (i == 0 || ep == پوچ ||
			    (*ep != ' ' && *ep != '\t')) {
				صحیح quoted = 0;

				comment = cp;
				برای (; *cp && (quoted || (*cp != ' ' &&
				    *cp != '\t')); cp++) {
					اگر (*cp == '\\' && cp[1] == '"')
						cp++;	/* Skip both */
					وگرنه اگر (*cp == '"')
						quoted = !quoted;
				}
				اگر (!*cp)
					ادامه;
				*cp++ = '\0';
			}
		}
		/* Retry after parsing leading hostname/key options */
		اگر (عمومی == پوچ && (عمومی = try_read_کلید(&cp)) == پوچ) {
			debug("%s:%lu: not a public key", path, lnum);
			ادامه;
		}

		/* Find trailing comment, if any */
		برای (; *cp == ' ' || *cp == '\t'; cp++)
			;
		اگر (*cp != '\0' && *cp != '#')
			comment = cp;

		fingerprint_one_کلید(عمومی, comment);
		sshkey_free(عمومی);
		invalid = 0; /* One good key in the file is sufficient */
	}
	fclose(f);
	آزاد(سطر);

	اگر (invalid)
		fatal("%s is not a public key file.", path);
	exit(0);
}

ایستا تهی
do_gen_all_hostkeys(ساختار passwd *pw)
{
	ساختار {
		نویسه *کلید_type;
		نویسه *کلید_type_display;
		نویسه *path;
	} کلید_types[] = {
#ifdef WITH_OPENSSL
		{ "rsa", "RSA" ,PATH_HOST_RSA_کلید_FILE },
		{ "ecdsa", "ECDSA",PATH_HOST_ECDSA_کلید_FILE },
#endif /* WITH_OPENSSL */
		{ "ed25519", "ED25519",PATH_HOST_ED25519_کلید_FILE },
#ifdef USE_MLDSA
		{ "mldsa44-ed25519", "MLDSA44-ED25519",
		     PATH_HOST_MLDSA44_ED25519_کلید_FILE },
#endif
		{ پوچ, پوچ, پوچ }
	};

	uint32_t bits = 0;
	صحیح first = 0;
	ساختار stat st;
	ساختار sshkey *خصوصی, *عمومی;
	نویسه comment[کلید_COMMENT_MAX], *prv_tmp, *pub_tmp, *prv_file, *pub_file;
	صحیح i, type, fd, r;

	برای (i = 0; کلید_types[i].کلید_type; i++) {
		عمومی = خصوصی = پوچ;
		prv_tmp = pub_tmp = prv_file = pub_file = پوچ;

		xasprintf(&prv_file, "%s%s",
		    identity_file, کلید_types[i].path);

		/* Check whether private key exists and is not zero-length */
		اگر (stat(prv_file, &st) == 0) {
			اگر (st.st_size != 0)
				برو next;
		} وگرنه اگر (errno != ENOENT) {
			error("Could not stat %s: %s", کلید_types[i].path,
			    strerror(errno));
			برو failnext;
		}

		/*
		 * Private key doesn't exist or is invalid; proceed with
		 * key generation.
		 */
		xasprintf(&prv_tmp, "%s%s.XXXXXXXXXX",
		    identity_file, کلید_types[i].path);
		xasprintf(&pub_tmp, "%s%s.pub.XXXXXXXXXX",
		    identity_file, کلید_types[i].path);
		xasprintf(&pub_file, "%s%s.pub",
		    identity_file, کلید_types[i].path);

		اگر (first == 0) {
			first = 1;
			printf("%s: generating new host keys: ", __progname);
		}
		printf("%s ", کلید_types[i].کلید_type_display);
		fflush(stdout);
		type = sshkey_type_from_shortname(کلید_types[i].کلید_type);
		اگر ((fd = mkstemp(prv_tmp)) == -1) {
			error("Could not save your private key in %s: %s",
			    prv_tmp, strerror(errno));
			برو failnext;
		}
		(تهی)close(fd); /* just using mkstemp() to reserve a name */
		bits = 0;
		type_bits_valid(type, پوچ, &bits);
		اگر ((r = sshkey_generate(type, bits, &خصوصی)) != 0) {
			error_r(r, "sshkey_generate failed");
			برو failnext;
		}
		اگر ((r = sshkey_from_private(خصوصی, &عمومی)) != 0)
			fatal_fr(r, "sshkey_from_private");
		snprintf(comment, اندازه comment, "%s@%s", pw->pw_name,
		    hostname);
		اگر ((r = sshkey_save_private(خصوصی, prv_tmp, "",
		    comment, private_کلید_format, openssh_format_cipher,
		    rounds)) != 0) {
			error_r(r, "Saving key \"%s\" failed", prv_tmp);
			برو failnext;
		}
		اگر ((fd = mkstemp(pub_tmp)) == -1) {
			error("Could not save your public key in %s: %s",
			    pub_tmp, strerror(errno));
			برو failnext;
		}
		(تهی)fchmod(fd, 0644);
		(تهی)close(fd);
		اگر ((r = sshkey_save_public(عمومی, pub_tmp, comment)) != 0) {
			error_r(r, "Unable to save public key to %s",
			    identity_file);
			برو failnext;
		}

		/* Rename temporary files to their permanent locations. */
		اگر (rename(pub_tmp, pub_file) != 0) {
			error("Unable to move %s into position: %s",
			    pub_file, strerror(errno));
			برو failnext;
		}
		اگر (rename(prv_tmp, prv_file) != 0) {
			error("Unable to move %s into position: %s",
			    کلید_types[i].path, strerror(errno));
 failnext:
			first = 0;
			برو next;
		}
 next:
		sshkey_free(خصوصی);
		sshkey_free(عمومی);
		آزاد(prv_tmp);
		آزاد(pub_tmp);
		آزاد(prv_file);
		آزاد(pub_file);
	}
	اگر (first != 0)
		printf("\n");
}

ساختار known_hosts_ctx {
	ثابت نویسه *host;	/* Hostname searched for in find/delete case */
	FILE *out;		/* Output file, stdout for find_hosts case */
	صحیح has_unhashed;	/* When hashing, original had unhashed hosts */
	صحیح found_کلید;		/* For find/delete, host was found */
	صحیح invalid;		/* File contained invalid items; don't delete */
	صحیح hash_hosts;		/* Hash hostnames as we go */
	صحیح find_host;		/* Search for specific hostname */
	صحیح delete_host;	/* Delete host from known_hosts */
};

ایستا صحیح
known_hosts_hash(ساختار hostkey_foreach_سطر *l, تهی *_ctx)
{
	ساختار known_hosts_ctx *ctx = (ساختار known_hosts_ctx *)_ctx;
	نویسه *hashed, *cp, *hosts, *ohosts;
	صحیح has_wild = l->hosts && strcspn(l->hosts, "*?!") != strlen(l->hosts);
	صحیح was_hashed = l->hosts && l->hosts[0] == HASH_DELIM;

	انتخاب (l->status) {
	حالت HKF_STATUS_OK:
	حالت HKF_STATUS_MATCHED:
		/*
		 * Don't hash hosts already hashed, with wildcard
		 * characters or a CA/revocation marker.
		 */
		اگر (was_hashed || has_wild || l->marker != MRK_NONE) {
			fprintf(ctx->out, "%s\n", l->سطر);
			اگر (has_wild && !ctx->find_host) {
				logit("%s:%lu: ignoring host name "
				    "with wildcard: %.64s", l->path,
				    l->linenum, l->hosts);
			}
			بازگشت 0;
		}
		/*
		 * Split any comma-separated hostnames from the host list,
		 * hash and store separately.
		 */
		ohosts = hosts = xstrdup(l->hosts);
		وقتی ((cp = strsep(&hosts, ",")) != پوچ && *cp != '\0') {
			lowercase(cp);
			اگر ((hashed = host_hash(cp, پوچ, 0)) == پوچ)
				fatal("hash_host failed");
			fprintf(ctx->out, "%s %s\n", hashed, l->rawkey);
			آزاد(hashed);
			ctx->has_unhashed = 1;
		}
		آزاد(ohosts);
		بازگشت 0;
	حالت HKF_STATUS_INVALID:
		/* Retain invalid lines, but mark file as invalid. */
		ctx->invalid = 1;
		logit("%s:%lu: invalid line", l->path, l->linenum);
		/* FALLTHROUGH */
	پیشفرض:
		fprintf(ctx->out, "%s\n", l->سطر);
		بازگشت 0;
	}
	/* NOTREACHED */
	بازگشت -1;
}

ایستا صحیح
known_hosts_find_delete(ساختار hostkey_foreach_سطر *l, تهی *_ctx)
{
	ساختار known_hosts_ctx *ctx = (ساختار known_hosts_ctx *)_ctx;
	شمارش sshkey_fp_rep rep;
	صحیح fptype;
	نویسه *fp = پوچ, *ra = پوچ;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;

	اگر (l->status == HKF_STATUS_MATCHED) {
		اگر (ctx->delete_host) {
			اگر (l->marker != MRK_NONE) {
				/* Don't remove CA and revocation lines */
				fprintf(ctx->out, "%s\n", l->سطر);
			} وگرنه {
				/*
				 * Hostname matches and has no CA/revoke
				 * marker, delete it by *not* writing the
				 * line to ctx->out.
				 */
				ctx->found_کلید = 1;
				اگر (!quiet)
					printf("# Host %s found: line %lu\n",
					    ctx->host, l->linenum);
			}
			بازگشت 0;
		} وگرنه اگر (ctx->find_host) {
			ctx->found_کلید = 1;
			اگر (!quiet) {
				printf("# Host %s found: line %lu %s\n",
				    ctx->host,
				    l->linenum, l->marker == MRK_CA ? "CA" :
				    (l->marker == MRK_REVOKE ? "REVOKED" : ""));
			}
			اگر (ctx->hash_hosts)
				known_hosts_hash(l, ctx);
			وگرنه اگر (print_fingerprint) {
				fp = sshkey_fingerprint(l->کلید, fptype, rep);
				ra = sshkey_fingerprint(l->کلید,
				    fingerprint_hash, SSH_FP_RANDOMART);
				اگر (fp == پوچ || ra == پوچ)
					fatal_f("sshkey_fingerprint failed");
				mprintf("%s %s %s%s%s\n", ctx->host,
				    sshkey_type(l->کلید), fp,
				    l->comment[0] ? " " : "",
				    l->comment);
				اگر (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
					printf("%s\n", ra);
				آزاد(ra);
				آزاد(fp);
			} وگرنه
				fprintf(ctx->out, "%s\n", l->سطر);
			بازگشت 0;
		}
	} وگرنه اگر (ctx->delete_host) {
		/* Retain non-matching hosts when deleting */
		اگر (l->status == HKF_STATUS_INVALID) {
			ctx->invalid = 1;
			logit("%s:%lu: invalid line", l->path, l->linenum);
		}
		fprintf(ctx->out, "%s\n", l->سطر);
	}
	بازگشت 0;
}

ایستا تهی
do_known_hosts(ساختار passwd *pw, ثابت نویسه *name, صحیح find_host,
    صحیح delete_host, صحیح hash_hosts)
{
	نویسه *cp, tmp[PATH_MAX], old[PATH_MAX];
	صحیح r, fd, oerrno, inplace = 0;
	ساختار known_hosts_ctx ctx;
	u_int foreach_options;
	ساختار stat sb;

	اگر (!have_identity) {
		cp = tilde_expand_filename(_PATH_SSH_USER_HOSTFILE, pw->pw_uid);
		اگر (strlcpy(identity_file, cp, اندازه(identity_file)) >=
		    اندازه(identity_file))
			fatal("Specified known hosts path too long");
		آزاد(cp);
		have_identity = 1;
	}
	اگر (stat(identity_file, &sb) != 0)
		fatal("Cannot stat %s: %s", identity_file, strerror(errno));

	memset(&ctx, 0, اندازه(ctx));
	ctx.out = stdout;
	ctx.host = name;
	ctx.hash_hosts = hash_hosts;
	ctx.find_host = find_host;
	ctx.delete_host = delete_host;

	/*
	 * Find hosts goes to stdout, hash and deletions happen in-place
	 * A corner case is ssh-keygen -HF foo, which should go to stdout
	 */
	اگر (!find_host && (hash_hosts || delete_host)) {
		اگر (strlcpy(tmp, identity_file, اندازه(tmp)) >= اندازه(tmp) ||
		    strlcat(tmp, ".XXXXXXXXXX", اندازه(tmp)) >= اندازه(tmp) ||
		    strlcpy(old, identity_file, اندازه(old)) >= اندازه(old) ||
		    strlcat(old, ".old", اندازه(old)) >= اندازه(old))
			fatal("known_hosts path too long");
		umask(077);
		اگر ((fd = mkstemp(tmp)) == -1)
			fatal("mkstemp: %s", strerror(errno));
		اگر ((ctx.out = fdopen(fd, "w")) == پوچ) {
			oerrno = errno;
			unlink(tmp);
			fatal("fdopen: %s", strerror(oerrno));
		}
		(تهی)fchmod(fd, sb.st_mode & 0644);
		inplace = 1;
	}
	/* XXX support identity_file == "-" for stdin */
	foreach_options = find_host ? HKF_WANT_MATCH : 0;
	foreach_options |= print_fingerprint ? HKF_WANT_PARSE_کلید : 0;
	اگر ((r = hostkeys_foreach(identity_file, (find_host || !hash_hosts) ?
	    known_hosts_find_delete : known_hosts_hash, &ctx, name, پوچ,
	    foreach_options, 0)) != 0) {
		اگر (inplace)
			unlink(tmp);
		fatal_fr(r, "hostkeys_foreach");
	}

	اگر (inplace)
		fclose(ctx.out);

	اگر (ctx.invalid) {
		error("%s is not a valid known_hosts file.", identity_file);
		اگر (inplace) {
			error("Not replacing existing known_hosts "
			    "file because of errors");
			unlink(tmp);
		}
		exit(1);
	} وگرنه اگر (delete_host && !ctx.found_کلید) {
		logit("Host %s not found in %s", name, identity_file);
		اگر (inplace)
			unlink(tmp);
	} وگرنه اگر (inplace) {
		/* Backup existing file */
		اگر (unlink(old) == -1 && errno != ENOENT)
			fatal("unlink %.100s: %s", old, strerror(errno));
		اگر (link(identity_file, old) == -1)
			fatal("link %.100s to %.100s: %s", identity_file, old,
			    strerror(errno));
		/* Move new one into place */
		اگر (rename(tmp, identity_file) == -1) {
			error("rename\"%s\" to \"%s\": %s", tmp, identity_file,
			    strerror(errno));
			unlink(tmp);
			unlink(old);
			exit(1);
		}

		printf("%s updated.\n", identity_file);
		printf("Original contents retained as %s\n", old);
		اگر (ctx.has_unhashed) {
			logit("WARNING: %s contains unhashed entries", old);
			logit("Delete this file to ensure privacy "
			    "of hostnames");
		}
	}

	exit (find_host && !ctx.found_کلید);
}

/*
 * Perform changing a passphrase.  The argument is the passwd structure
 * for the current user.
 */
ایستا تهی
do_change_passphrase(ساختار passwd *pw, نویسه * ثابت *opts, size_t nopts)
{
	نویسه *comment;
	نویسه *old_passphrase, *passphrase1, *passphrase2;
	ساختار stat st;
	ساختار sshkey *خصوصی;
	صحیح r;
	size_t i;

	اگر (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	اگر (stat(identity_file, &st) == -1)
		fatal("%s: %s", identity_file, strerror(errno));
	/* Try to load the file with empty passphrase. */
	r = sshkey_load_private(identity_file, "", &خصوصی, &comment);
	اگر (r == SSH_ERR_کلید_WRONG_PASSPHRASE) {
		اگر (identity_passphrase)
			old_passphrase = xstrdup(identity_passphrase);
		وگرنه
			old_passphrase =
			    read_passphrase("Enter old passphrase: ",
			    RP_ALLOW_STDIN);
		r = sshkey_load_private(identity_file, old_passphrase,
		    &خصوصی, &comment);
		freezero(old_passphrase, strlen(old_passphrase));
		اگر (r != 0)
			برو badkey;
	} وگرنه اگر (r != 0) {
 badkey:
		fatal_r(r, "Failed to load key %s", identity_file);
	}
	اگر (comment)
		mprintf("Key has comment '%s'\n", comment);

	/* All current -O options relate to FIDO keys only */
	اگر (nopts != 0 && !sshkey_is_sk(خصوصی)) {
		fatal("FIDO-specific option requested for non-FIDO key %s",
		    identity_file);
	}
	اگر (sshkey_is_sk(خصوصی)) {
		debug_f("%s: original FIDO key flags: "
		    "%stouch-required %sverify-required", identity_file,
		    (خصوصی->sk_flags & SSH_SK_USER_PRESENCE_REQD) ? "": "no-",
		    (خصوصی->sk_flags & SSH_SK_USER_VERIFICATION_REQD) ? "" : "no-");
	}
	برای (i = 0; i < nopts; i++) {
		اگر (strcasecmp(opts[i], "touch-required") == 0)
			خصوصی->sk_flags |= SSH_SK_USER_PRESENCE_REQD;
		وگرنه اگر (strcasecmp(opts[i], "no-touch-required") == 0)
			خصوصی->sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
		وگرنه اگر (strcasecmp(opts[i], "verify-required") == 0)
			خصوصی->sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
		وگرنه اگر (strcasecmp(opts[i], "no-verify-required") == 0)
			خصوصی->sk_flags &= ~SSH_SK_USER_VERIFICATION_REQD;
		وگرنه {
			fatal("Option \"%s\" is unsupported for "
			    "key passphrase change", opts[i]);
		}
	}
	اگر (sshkey_is_sk(خصوصی) && nopts != 0) {
		debug_f("%s: updated FIDO key flags: "
		    "%stouch-required %sverify-required", identity_file,
		    (خصوصی->sk_flags & SSH_SK_USER_PRESENCE_REQD) ? "": "no-",
		    (خصوصی->sk_flags & SSH_SK_USER_VERIFICATION_REQD) ? "" : "no-");
	}

	/* Ask the new passphrase (twice). */
	اگر (identity_new_passphrase) {
		passphrase1 = xstrdup(identity_new_passphrase);
		passphrase2 = پوچ;
	} وگرنه {
		passphrase1 =
			read_passphrase("Enter new passphrase (empty for no "
			    "passphrase): ", RP_ALLOW_STDIN);
		passphrase2 = read_passphrase("Enter same passphrase again: ",
		    RP_ALLOW_STDIN);

		/* Verify that they are the same. */
		اگر (strcmp(passphrase1, passphrase2) != 0) {
			explicit_bzero(passphrase1, strlen(passphrase1));
			explicit_bzero(passphrase2, strlen(passphrase2));
			آزاد(passphrase1);
			آزاد(passphrase2);
			printf("Pass phrases do not match.  Try again.\n");
			exit(1);
		}
		/* Destroy the other copy. */
		freezero(passphrase2, strlen(passphrase2));
	}

	/* Save the file using the new passphrase. */
	اگر ((r = sshkey_save_private(خصوصی, identity_file, passphrase1,
	    comment, private_کلید_format, openssh_format_cipher, rounds)) != 0) {
		error_r(r, "Saving key \"%s\" failed", identity_file);
		freezero(passphrase1, strlen(passphrase1));
		sshkey_free(خصوصی);
		آزاد(comment);
		exit(1);
	}
	/* Destroy the passphrase and the copy of the key in memory. */
	freezero(passphrase1, strlen(passphrase1));
	sshkey_free(خصوصی);		 /* Destroys contents */
	آزاد(comment);

	printf("Your identification has been saved with the new passphrase.\n");
	exit(0);
}

/*
 * Print the SSHFP RR.
 */
ایستا صحیح
do_print_resource_record(ساختار passwd *pw, نویسه *fname, نویسه *hname,
    صحیح print_generic, نویسه * ثابت *opts, size_t nopts)
{
	ساختار sshkey *عمومی;
	نویسه *comment = پوچ;
	ثابت نویسه *p;
	ساختار stat st;
	صحیح r, hash = -1;
	size_t i;

	برای (i = 0; i < nopts; i++) {
		اگر ((p = strprefix(opts[i], "hashalg=", 1)) != پوچ) {
			اگر ((hash = ssh_digest_alg_by_name(p)) == -1)
				fatal("Unsupported hash algorithm");
		} وگرنه {
			error("Invalid option \"%s\"", opts[i]);
			بازگشت SSH_ERR_INVALID_ARGUMENT;
		}
	}
	اگر (fname == پوچ)
		fatal_f("no filename");
	اگر (stat(fname, &st) == -1) {
		اگر (errno == ENOENT)
			بازگشت 0;
		fatal("%s: %s", fname, strerror(errno));
	}
	اگر ((r = sshkey_load_public(fname, &عمومی, &comment)) != 0)
		fatal_r(r, "Failed to read v2 public key from \"%s\"", fname);
	export_dns_rr(hname, عمومی, stdout, print_generic, hash);
	sshkey_free(عمومی);
	آزاد(comment);
	بازگشت 1;
}

/*
 * Change the comment of a private key file.
 */
ایستا تهی
do_change_comment(ساختار passwd *pw, ثابت نویسه *identity_comment)
{
	نویسه new_comment[کلید_COMMENT_MAX], *comment, *passphrase;
	ساختار sshkey *خصوصی;
	ساختار sshkey *عمومی;
	ساختار stat st;
	صحیح r;

	اگر (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	اگر (stat(identity_file, &st) == -1)
		fatal("%s: %s", identity_file, strerror(errno));
	اگر ((r = sshkey_load_private(identity_file, "",
	    &خصوصی, &comment)) == 0)
		passphrase = xstrdup("");
	وگرنه اگر (r != SSH_ERR_کلید_WRONG_PASSPHRASE)
		fatal_r(r, "Cannot load private key \"%s\"", identity_file);
	وگرنه {
		اگر (identity_passphrase)
			passphrase = xstrdup(identity_passphrase);
		وگرنه اگر (identity_new_passphrase)
			passphrase = xstrdup(identity_new_passphrase);
		وگرنه
			passphrase = read_passphrase("Enter passphrase: ",
			    RP_ALLOW_STDIN);
		/* Try to load using the passphrase. */
		اگر ((r = sshkey_load_private(identity_file, passphrase,
		    &خصوصی, &comment)) != 0) {
			freezero(passphrase, strlen(passphrase));
			fatal_r(r, "Cannot load private key \"%s\"",
			    identity_file);
		}
	}

	اگر (خصوصی->type != کلید_ED25519 &&
	    private_کلید_format != SSHKEY_PRIVATE_OPENSSH) {
		error("Comments are only supported for keys stored in "
		    "the new format (-o).");
		explicit_bzero(passphrase, strlen(passphrase));
		sshkey_free(خصوصی);
		exit(1);
	}
	اگر (comment)
		printf("Old comment: %s\n", comment);
	وگرنه
		printf("No existing comment\n");

	اگر (identity_comment) {
		strlcpy(new_comment, identity_comment, اندازه(new_comment));
	} وگرنه {
		printf("New comment: ");
		fflush(stdout);
		اگر (!fgets(new_comment, اندازه(new_comment), stdin)) {
			explicit_bzero(passphrase, strlen(passphrase));
			sshkey_free(خصوصی);
			exit(1);
		}
		new_comment[strcspn(new_comment, "\n")] = '\0';
	}
	اگر (comment != پوچ && strcmp(comment, new_comment) == 0) {
		printf("No change to comment\n");
		آزاد(passphrase);
		sshkey_free(خصوصی);
		آزاد(comment);
		exit(0);
	}

	/* Save the file using the new passphrase. */
	اگر ((r = sshkey_save_private(خصوصی, identity_file, passphrase,
	    new_comment, private_کلید_format, openssh_format_cipher,
	    rounds)) != 0) {
		error_r(r, "Saving key \"%s\" failed", identity_file);
		freezero(passphrase, strlen(passphrase));
		sshkey_free(خصوصی);
		آزاد(comment);
		exit(1);
	}
	freezero(passphrase, strlen(passphrase));
	اگر ((r = sshkey_from_private(خصوصی, &عمومی)) != 0)
		fatal_fr(r, "sshkey_from_private");
	sshkey_free(خصوصی);

	strlcat(identity_file, ".pub", اندازه(identity_file));
	اگر ((r = sshkey_save_public(عمومی, identity_file, new_comment)) != 0)
		fatal_r(r, "Unable to save public key to %s", identity_file);
	sshkey_free(عمومی);
	آزاد(comment);

	اگر (strlen(new_comment) > 0)
		printf("Comment '%s' applied\n", new_comment);
	وگرنه
		printf("Comment removed\n");

	exit(0);
}

ایستا تهی
cert_ext_add(ثابت نویسه *کلید, ثابت نویسه *مقدار, صحیح iscrit)
{
	cert_ext = xreallocarray(cert_ext, ncert_ext + 1, اندازه(*cert_ext));
	cert_ext[ncert_ext].کلید = xstrdup(کلید);
	cert_ext[ncert_ext].val = مقدار == پوچ ? پوچ : xstrdup(مقدار);
	cert_ext[ncert_ext].crit = iscrit;
	ncert_ext++;
}

/* qsort(3) comparison function for certificate extensions */
ایستا صحیح
cert_ext_cmp(ثابت تهی *_a, ثابت تهی *_b)
{
	ثابت ساختار cert_ext *a = (ثابت ساختار cert_ext *)_a;
	ثابت ساختار cert_ext *b = (ثابت ساختار cert_ext *)_b;
	صحیح r;

	اگر (a->crit != b->crit)
		بازگشت (a->crit < b->crit) ? -1 : 1;
	اگر ((r = strcmp(a->کلید, b->کلید)) != 0)
		بازگشت r;
	اگر ((a->val == پوچ) != (b->val == پوچ))
		بازگشت (a->val == پوچ) ? -1 : 1;
	اگر (a->val != پوچ && (r = strcmp(a->val, b->val)) != 0)
		بازگشت r;
	بازگشت 0;
}

#define OPTIONS_CRITICAL	1
#define OPTIONS_EXTENSIONS	2
ایستا تهی
prepare_options_buf(ساختار sshbuf *c, صحیح which)
{
	ساختار sshbuf *b;
	size_t i;
	صحیح r;
	ثابت ساختار cert_ext *ext;

	اگر ((b = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	sshbuf_reset(c);
	برای (i = 0; i < ncert_ext; i++) {
		ext = &cert_ext[i];
		اگر ((ext->crit && (which & OPTIONS_EXTENSIONS)) ||
		    (!ext->crit && (which & OPTIONS_CRITICAL)))
			ادامه;
		اگر (ext->val == پوچ) {
			/* flag option */
			debug3_f("%s", ext->کلید);
			اگر ((r = sshbuf_put_cstring(c, ext->کلید)) != 0 ||
			    (r = sshbuf_put_string(c, پوچ, 0)) != 0)
				fatal_fr(r, "prepare flag");
		} وگرنه {
			/* key/value option */
			debug3_f("%s=%s", ext->کلید, ext->val);
			sshbuf_reset(b);
			اگر ((r = sshbuf_put_cstring(c, ext->کلید)) != 0 ||
			    (r = sshbuf_put_cstring(b, ext->val)) != 0 ||
			    (r = sshbuf_put_stringb(c, b)) != 0)
				fatal_fr(r, "prepare k/v");
		}
	}
	sshbuf_free(b);
}

ایستا تهی
finalise_cert_exts(تهی)
{
	/* critical options */
	اگر (certflags_command != پوچ)
		cert_ext_add("force-command", certflags_command, 1);
	اگر (certflags_src_addr != پوچ)
		cert_ext_add("source-address", certflags_src_addr, 1);
	اگر ((certflags_flags & CERTOPT_REQUIRE_VERIFY) != 0)
		cert_ext_add("verify-required", پوچ, 1);
	/* extensions */
	اگر ((certflags_flags & CERTOPT_X_FWD) != 0)
		cert_ext_add("permit-X11-forwarding", پوچ, 0);
	اگر ((certflags_flags & CERTOPT_AGENT_FWD) != 0)
		cert_ext_add("permit-agent-forwarding", پوچ, 0);
	اگر ((certflags_flags & CERTOPT_PORT_FWD) != 0)
		cert_ext_add("permit-port-forwarding", پوچ, 0);
	اگر ((certflags_flags & CERTOPT_PTY) != 0)
		cert_ext_add("permit-pty", پوچ, 0);
	اگر ((certflags_flags & CERTOPT_USER_RC) != 0)
		cert_ext_add("permit-user-rc", پوچ, 0);
	اگر ((certflags_flags & CERTOPT_NO_REQUIRE_USER_PRESENCE) != 0)
		cert_ext_add("no-touch-required", پوچ, 0);
	/* order lexically by key */
	اگر (ncert_ext > 0)
		qsort(cert_ext, ncert_ext, اندازه(*cert_ext), cert_ext_cmp);
}

ایستا ساختار sshkey *
load_pkcs11_کلید(نویسه *path)
{
#ifdef ENABLE_PKCS11
	ساختار sshkey **کلیدها = پوچ, *عمومی, *خصوصی = پوچ;
	صحیح r, i, nkeys;

	اگر ((r = sshkey_load_public(path, &عمومی, پوچ)) != 0)
		fatal_r(r, "Couldn't load CA public key \"%s\"", path);

	nkeys = pkcs11_add_provider(pkcs11provider, identity_passphrase,
	    &کلیدها, پوچ);
	debug3_f("%d keys", nkeys);
	اگر (nkeys <= 0)
		fatal("cannot read public key from pkcs11");
	برای (i = 0; i < nkeys; i++) {
		اگر (sshkey_equal_public(عمومی, کلیدها[i])) {
			خصوصی = کلیدها[i];
			ادامه;
		}
		sshkey_free(کلیدها[i]);
	}
	آزاد(کلیدها);
	sshkey_free(عمومی);
	بازگشت خصوصی;
#وگرنه
	fatal("no pkcs11 support");
#endif /* ENABLE_PKCS11 */
}

/* Signer for sshkey_certify_custom that uses the agent */
ایستا صحیح
agent_signer(ساختار sshkey *کلید, u_char **sigp, size_t *lenp,
    ثابت u_char *data, size_t datalen,
    ثابت نویسه *alg, ثابت نویسه *provider, ثابت نویسه *pin,
    u_int compat, تهی *ctx)
{
	صحیح *agent_fdp = (صحیح *)ctx;

	بازگشت ssh_agent_sign(*agent_fdp, کلید, sigp, lenp,
	    data, datalen, alg, compat);
}

ایستا تهی
do_ca_sign(ساختار passwd *pw, ثابت نویسه *ca_کلید_path, صحیح prefer_agent,
    unsigned long long cert_serial, صحیح cert_serial_autoinc,
    صحیح argc, نویسه **argv)
{
	صحیح r, i, کلید_in_agent = 0, agent_fd = -1;
	u_int n;
	ساختار sshkey *ca, *عمومی;
	نویسه valid[64], *otmp, *tmp, *cp, *out, *comment;
	نویسه *ca_fp = پوچ, **plist = پوچ, *pin = پوچ;
	ساختار ssh_identitylist *agent_ids;
	size_t j;
	ساختار notifier_ctx *notifier = پوچ;

#ifdef ENABLE_PKCS11
	pkcs11_init(1);
#endif
	tmp = tilde_expand_filename(ca_کلید_path, pw->pw_uid);
	اگر (pkcs11provider != پوچ) {
		/* If a PKCS#11 token was specified then try to use it */
		اگر ((ca = load_pkcs11_کلید(tmp)) == پوچ)
			fatal("No PKCS#11 key matching %s found", ca_کلید_path);
	} وگرنه اگر (prefer_agent) {
		/*
		 * Agent signature requested. Try to use agent after making
		 * sure the public key specified is actually present in the
		 * agent.
		 */
		اگر ((r = sshkey_load_public(tmp, &ca, پوچ)) != 0)
			fatal_r(r, "Cannot load CA public key %s", tmp);
		اگر ((r = ssh_get_authentication_socket(&agent_fd)) != 0)
			fatal_r(r, "Cannot use public key for CA signature");
		اگر ((r = ssh_fetch_identitylist(agent_fd, &agent_ids)) != 0)
			fatal_r(r, "Retrieve agent key list");
		برای (j = 0; j < agent_ids->nkeys; j++) {
			اگر (sshkey_equal(ca, agent_ids->کلیدها[j])) {
				کلید_in_agent = 1;
				/* Replace the CA key with the agent one */
				sshkey_free(ca);
				ca = agent_ids->کلیدها[j];
				agent_ids->کلیدها[j] = پوچ;
				بشکن;
			}
		}
		اگر (!کلید_in_agent)
			fatal("CA key %s not found in agent", tmp);
		ssh_free_identitylist(agent_ids);
	} وگرنه {
		/* CA key is assumed to be a private key on the filesystem */
		ca = load_identity(tmp, پوچ);
		اگر (sshkey_is_sk(ca) &&
		    (ca->sk_flags & SSH_SK_USER_VERIFICATION_REQD)) {
			اگر ((pin = read_passphrase("Enter PIN for CA key: ",
			    RP_ALLOW_STDIN)) == پوچ)
				fatal_f("couldn't read PIN");
		}
	}
	آزاد(tmp);

	اگر (کلید_type_name != پوچ) {
		اگر (sshkey_type_from_shortname(کلید_type_name) != ca->type) {
			fatal("CA key type %s doesn't match specified %s",
			    sshkey_ssh_name(ca), کلید_type_name);
		}
	} وگرنه اگر (ca->type == کلید_RSA) {
		/* Default to a good signature algorithm */
		کلید_type_name = "rsa-sha2-512";
	}
	ca_fp = sshkey_fingerprint(ca, fingerprint_hash, SSH_FP_DEFAULT);

	finalise_cert_exts();
	برای (i = 0; i < argc; i++) {
		/* Split list of principals */
		n = 0;
		اگر (cert_principals != پوچ) {
			otmp = tmp = xstrdup(cert_principals);
			plist = پوچ;
			برای (; (cp = strsep(&tmp, ",")) != پوچ; n++) {
				plist = xreallocarray(plist, n + 1, اندازه(*plist));
				اگر (*(plist[n] = xstrdup(cp)) == '\0')
					fatal("Empty principal name");
			}
			آزاد(otmp);
		}
		اگر (n > SSHKEY_CERT_MAX_PRINCIPALS)
			fatal("Too many certificate principals specified");

		tmp = tilde_expand_filename(argv[i], pw->pw_uid);
		اگر ((r = sshkey_load_public(tmp, &عمومی, &comment)) != 0)
			fatal_r(r, "load pubkey \"%s\"", tmp);
		اگر (sshkey_is_cert(عمومی))
			fatal_f("key \"%s\" type %s cannot be certified",
			    tmp, sshkey_type(عمومی));

		/* Prepare certificate to sign */
		اگر ((r = sshkey_to_certified(عمومی)) != 0)
			fatal_r(r, "Could not upgrade key %s to certificate", tmp);
		عمومی->cert->type = cert_کلید_type;
		عمومی->cert->serial = (uint64_t)cert_serial;
		عمومی->cert->کلید_id = xstrdup(cert_کلید_id);
		عمومی->cert->nprincipals = n;
		عمومی->cert->principals = plist;
		عمومی->cert->valid_after = cert_valid_from;
		عمومی->cert->valid_before = cert_valid_to;
		prepare_options_buf(عمومی->cert->critical, OPTIONS_CRITICAL);
		prepare_options_buf(عمومی->cert->extensions,
		    OPTIONS_EXTENSIONS);
		اگر ((r = sshkey_from_private(ca,
		    &عمومی->cert->signature_کلید)) != 0)
			fatal_r(r, "sshkey_from_private (ca key)");

		اگر (کلید_in_agent) {
			اگر ((r = sshkey_certify_custom(عمومی, ca,
			    کلید_type_name, sk_provider, پوچ, agent_signer,
			    &agent_fd)) != 0)
				fatal_r(r, "Couldn't certify %s via agent", tmp);
		} وگرنه {
			اگر (sshkey_is_sk(ca) &&
			    (ca->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
				notifier = notify_start(0,
				    "Confirm user presence for key %s %s",
				    sshkey_type(ca), ca_fp);
			}
			r = sshkey_certify(عمومی, ca, کلید_type_name,
			    sk_provider, pin);
			notify_complete(notifier, "User presence confirmed");
			اگر (r != 0)
				fatal_r(r, "Couldn't certify key %s", tmp);
		}

		اگر ((cp = strrchr(tmp, '.')) != پوچ && strcmp(cp, ".pub") == 0)
			*cp = '\0';
		xasprintf(&out, "%s-cert.pub", tmp);
		آزاد(tmp);

		اگر ((r = sshkey_save_public(عمومی, out, comment)) != 0) {
			fatal_r(r, "Unable to save public key to %s",
			    identity_file);
		}

		اگر (!quiet) {
			sshkey_format_cert_validity(عمومی->cert,
			    valid, اندازه(valid));
			logit("Signed %s key %s: id \"%s\" serial %llu%s%s "
			    "valid %s", sshkey_cert_type(عمومی),
			    out, عمومی->cert->کلید_id,
			    (unsigned long long)عمومی->cert->serial,
			    cert_principals != پوچ ? " for " : "",
			    cert_principals != پوچ ? cert_principals : "",
			    valid);
		}

		sshkey_free(عمومی);
		آزاد(out);
		آزاد(comment);
		اگر (cert_serial_autoinc)
			cert_serial++;
	}
	اگر (pin != پوچ)
		freezero(pin, strlen(pin));
	sshkey_free(ca);
	آزاد(ca_fp);
#ifdef ENABLE_PKCS11
	pkcs11_terminate();
#endif
}

ایستا uint64_t
parse_relative_time(ثابت نویسه *s, time_t now)
{
	int64_t mul, secs;

	mul = *s == '-' ? -1 : 1;

	اگر ((secs = convtime(s + 1)) == -1)
		fatal("Invalid relative certificate time %s", s);
	اگر (mul == -1 && secs > now)
		fatal("Certificate time %s cannot be represented", s);
	بازگشت now + (uint64_t)(secs * mul);
}

ایستا تهی
parse_hex_u64(ثابت نویسه *s, uint64_t *up)
{
	نویسه *ep;
	unsigned long long ull;

	errno = 0;
	ull = strtoull(s, &ep, 16);
	اگر (*s == '\0' || *ep != '\0')
		fatal("Invalid certificate time: not a number");
	اگر (errno == ERANGE && ull == ULONG_MAX)
		fatal_fr(SSH_ERR_SYSTEM_ERROR, "Invalid certificate time");
	*up = (uint64_t)ull;
}

ایستا تهی
parse_cert_times(نویسه *timespec)
{
	نویسه *from, *to;
	time_t now = time(پوچ);
	int64_t secs;

	/* +timespec relative to now */
	اگر (*timespec == '+' && strchr(timespec, ':') == پوچ) {
		اگر ((secs = convtime(timespec + 1)) == -1)
			fatal("Invalid relative certificate life %s", timespec);
		cert_valid_to = now + secs;
		/*
		 * Backdate certificate one minute to avoid problems on hosts
		 * with poorly-synchronised clocks.
		 */
		cert_valid_from = ((now - 59)/ 60) * 60;
		بازگشت;
	}

	/*
	 * from:to, where
	 * from := [+-]timespec | YYYYMMDD | YYYYMMDDHHMMSS | 0x... | "always"
	 *   to := [+-]timespec | YYYYMMDD | YYYYMMDDHHMMSS | 0x... | "forever"
	 */
	from = xstrdup(timespec);
	to = strchr(from, ':');
	اگر (to == پوچ || from == to || *(to + 1) == '\0')
		fatal("Invalid certificate life specification %s", timespec);
	*to++ = '\0';

	اگر (*from == '-' || *from == '+')
		cert_valid_from = parse_relative_time(from, now);
	وگرنه اگر (strcmp(from, "always") == 0)
		cert_valid_from = 0;
	وگرنه اگر (strncmp(from, "0x", 2) == 0)
		parse_hex_u64(from, &cert_valid_from);
	وگرنه اگر (parse_absolute_time(from, &cert_valid_from) != 0)
		fatal("Invalid from time \"%s\"", from);

	اگر (*to == '-' || *to == '+')
		cert_valid_to = parse_relative_time(to, now);
	وگرنه اگر (strcmp(to, "forever") == 0)
		cert_valid_to = ~(uint64_t)0;
	وگرنه اگر (strncmp(to, "0x", 2) == 0)
		parse_hex_u64(to, &cert_valid_to);
	وگرنه اگر (parse_absolute_time(to, &cert_valid_to) != 0)
		fatal("Invalid to time \"%s\"", to);

	اگر (cert_valid_to <= cert_valid_from)
		fatal("Empty certificate validity interval");
	آزاد(from);
}

ایستا تهی
add_cert_option(نویسه *opt)
{
	نویسه *val, *cp;
	ثابت نویسه *p;
	صحیح iscrit = 0;

	اگر (strcasecmp(opt, "clear") == 0)
		certflags_flags = 0;
	وگرنه اگر (strcasecmp(opt, "no-x11-forwarding") == 0)
		certflags_flags &= ~CERTOPT_X_FWD;
	وگرنه اگر (strcasecmp(opt, "permit-x11-forwarding") == 0)
		certflags_flags |= CERTOPT_X_FWD;
	وگرنه اگر (strcasecmp(opt, "no-agent-forwarding") == 0)
		certflags_flags &= ~CERTOPT_AGENT_FWD;
	وگرنه اگر (strcasecmp(opt, "permit-agent-forwarding") == 0)
		certflags_flags |= CERTOPT_AGENT_FWD;
	وگرنه اگر (strcasecmp(opt, "no-port-forwarding") == 0)
		certflags_flags &= ~CERTOPT_PORT_FWD;
	وگرنه اگر (strcasecmp(opt, "permit-port-forwarding") == 0)
		certflags_flags |= CERTOPT_PORT_FWD;
	وگرنه اگر (strcasecmp(opt, "no-pty") == 0)
		certflags_flags &= ~CERTOPT_PTY;
	وگرنه اگر (strcasecmp(opt, "permit-pty") == 0)
		certflags_flags |= CERTOPT_PTY;
	وگرنه اگر (strcasecmp(opt, "no-user-rc") == 0)
		certflags_flags &= ~CERTOPT_USER_RC;
	وگرنه اگر (strcasecmp(opt, "permit-user-rc") == 0)
		certflags_flags |= CERTOPT_USER_RC;
	وگرنه اگر (strcasecmp(opt, "touch-required") == 0)
		certflags_flags &= ~CERTOPT_NO_REQUIRE_USER_PRESENCE;
	وگرنه اگر (strcasecmp(opt, "no-touch-required") == 0)
		certflags_flags |= CERTOPT_NO_REQUIRE_USER_PRESENCE;
	وگرنه اگر (strcasecmp(opt, "no-verify-required") == 0)
		certflags_flags &= ~CERTOPT_REQUIRE_VERIFY;
	وگرنه اگر (strcasecmp(opt, "verify-required") == 0)
		certflags_flags |= CERTOPT_REQUIRE_VERIFY;
	وگرنه اگر ((p = strprefix(opt, "force-command=", 1)) != پوچ) {
		اگر (*p == '\0')
			fatal("Empty force-command option");
		اگر (certflags_command != پوچ)
			fatal("force-command already specified");
		certflags_command = xstrdup(p);
	} وگرنه اگر ((p = strprefix(opt, "source-address=", 1)) != پوچ) {
		اگر (*p == '\0')
			fatal("Empty source-address option");
		اگر (certflags_src_addr != پوچ)
			fatal("source-address already specified");
		اگر (addr_match_cidr_list(پوچ, p) != 0)
			fatal("Invalid source-address list");
		certflags_src_addr = xstrdup(p);
	} وگرنه اگر (strprefix(opt, "extension:", 1) != پوچ ||
		    (iscrit = (strprefix(opt, "critical:", 1) != پوچ))) {
		val = xstrdup(strchr(opt, ':') + 1);
		اگر ((cp = strchr(val, '=')) != پوچ)
			*cp++ = '\0';
		cert_ext_add(val, cp, iscrit);
		آزاد(val);
	} وگرنه
		fatal("Unsupported certificate option \"%s\"", opt);
}

ایستا تهی
show_options(ساختار sshbuf *optbuf, صحیح in_critical)
{
	نویسه *name, *arg, *hex;
	ساختار sshbuf *options, *option = پوچ;
	صحیح r;

	اگر ((options = sshbuf_fromb(optbuf)) == پوچ)
		fatal_f("sshbuf_fromb failed");
	وقتی (sshbuf_len(options) != 0) {
		sshbuf_free(option);
		option = پوچ;
		اگر ((r = sshbuf_get_cstring(options, &name, پوچ)) != 0 ||
		    (r = sshbuf_froms(options, &option)) != 0)
			fatal_fr(r, "parse option");
		printf("                %s", name);
		اگر (!in_critical &&
		    (strcmp(name, "permit-X11-forwarding") == 0 ||
		    strcmp(name, "permit-agent-forwarding") == 0 ||
		    strcmp(name, "permit-port-forwarding") == 0 ||
		    strcmp(name, "permit-pty") == 0 ||
		    strcmp(name, "permit-user-rc") == 0 ||
		    strcmp(name, "no-touch-required") == 0)) {
			printf("\n");
		} وگرنه اگر (in_critical &&
		    (strcmp(name, "force-command") == 0 ||
		    strcmp(name, "source-address") == 0)) {
			اگر ((r = sshbuf_get_cstring(option, &arg, پوچ)) != 0)
				fatal_fr(r, "parse critical");
			printf(" %s\n", arg);
			آزاد(arg);
		} وگرنه اگر (in_critical &&
		    strcmp(name, "verify-required") == 0) {
			printf("\n");
		} وگرنه اگر (sshbuf_len(option) > 0) {
			hex = sshbuf_dtob16(option);
			printf(" UNKNOWN OPTION: %s (len %zu)\n",
			    hex, sshbuf_len(option));
			sshbuf_reset(option);
			آزاد(hex);
		} وگرنه
			printf(" UNKNOWN FLAG OPTION\n");
		آزاد(name);
		اگر (sshbuf_len(option) != 0)
			fatal("Option corrupt: extra data at end");
	}
	sshbuf_free(option);
	sshbuf_free(options);
}

ایستا تهی
print_cert(ساختار sshkey *کلید)
{
	نویسه valid[64], *کلید_fp, *ca_fp;
	u_int i;

	کلید_fp = sshkey_fingerprint(کلید, fingerprint_hash, SSH_FP_DEFAULT);
	ca_fp = sshkey_fingerprint(کلید->cert->signature_کلید,
	    fingerprint_hash, SSH_FP_DEFAULT);
	اگر (کلید_fp == پوچ || ca_fp == پوچ)
		fatal_f("sshkey_fingerprint fail");
	sshkey_format_cert_validity(کلید->cert, valid, اندازه(valid));

	printf("        Type: %s %s certificate\n", sshkey_ssh_name(کلید),
	    sshkey_cert_type(کلید));
	printf("        Public key: %s %s\n", sshkey_type(کلید), کلید_fp);
	printf("        Signing CA: %s %s (using %s)\n",
	    sshkey_type(کلید->cert->signature_کلید), ca_fp,
	    کلید->cert->signature_type);
	printf("        Key ID: \"%s\"\n", کلید->cert->کلید_id);
	printf("        Serial: %llu\n", (unsigned long long)کلید->cert->serial);
	printf("        Valid: %s\n", valid);
	printf("        Principals: ");
	اگر (کلید->cert->nprincipals == 0)
		printf("(none)\n");
	وگرنه {
		برای (i = 0; i < کلید->cert->nprincipals; i++)
			printf("\n                %s",
			    کلید->cert->principals[i]);
		printf("\n");
	}
	printf("        Critical Options: ");
	اگر (sshbuf_len(کلید->cert->critical) == 0)
		printf("(none)\n");
	وگرنه {
		printf("\n");
		show_options(کلید->cert->critical, 1);
	}
	printf("        Extensions: ");
	اگر (sshbuf_len(کلید->cert->extensions) == 0)
		printf("(none)\n");
	وگرنه {
		printf("\n");
		show_options(کلید->cert->extensions, 0);
	}
	آزاد(کلید_fp);
	آزاد(ca_fp);
}

ایستا تهی
do_show_cert(ساختار passwd *pw)
{
	ساختار sshkey *کلید = پوچ;
	ساختار stat st;
	صحیح r, is_stdin = 0, ok = 0;
	FILE *f;
	نویسه *cp, *سطر = پوچ;
	ثابت نویسه *path;
	size_t linesize = 0;
	u_long lnum = 0;

	اگر (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	اگر (strcmp(identity_file, "-") != 0 && stat(identity_file, &st) == -1)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));

	path = identity_file;
	اگر (strcmp(path, "-") == 0) {
		f = stdin;
		path = "(stdin)";
		is_stdin = 1;
	} وگرنه اگر ((f = fopen(identity_file, "r")) == پوچ)
		fatal("fopen %s: %s", identity_file, strerror(errno));

	وقتی (getline(&سطر, &linesize, f) != -1) {
		lnum++;
		sshkey_free(کلید);
		کلید = پوچ;
		/* Trim leading space and comments */
		cp = سطر + strspn(سطر, " \t");
		اگر (*cp == '#' || *cp == '\0')
			ادامه;
		اگر ((کلید = sshkey_new(کلید_UNSPEC)) == پوچ)
			fatal("sshkey_new");
		اگر ((r = sshkey_read(کلید, &cp)) != 0) {
			error_r(r, "%s:%lu: invalid key", path, lnum);
			ادامه;
		}
		اگر (!sshkey_is_cert(کلید)) {
			error("%s:%lu is not a certificate", path, lnum);
			ادامه;
		}
		ok = 1;
		اگر (!is_stdin && lnum == 1)
			printf("%s:\n", path);
		وگرنه
			printf("%s:%lu:\n", path, lnum);
		print_cert(کلید);
	}
	آزاد(سطر);
	sshkey_free(کلید);
	fclose(f);
	exit(ok ? 0 : 1);
}

ایستا تهی
load_krl(ثابت نویسه *path, ساختار ssh_krl **krlp)
{
	ساختار sshbuf *krlbuf;
	صحیح r;

	اگر ((r = sshbuf_load_file(path, &krlbuf)) != 0)
		fatal_r(r, "Unable to load KRL %s", path);
	/* XXX check sigs */
	اگر ((r = ssh_krl_from_blob(krlbuf, krlp)) != 0 ||
	    *krlp == پوچ)
		fatal_r(r, "Invalid KRL file %s", path);
	sshbuf_free(krlbuf);
}

ایستا تهی
hash_to_blob(ثابت نویسه *cp, u_char **blobp, size_t *lenp,
    ثابت نویسه *file, u_long lnum)
{
	نویسه *tmp;
	size_t tlen;
	ساختار sshbuf *b;
	صحیح r;

	اگر ((cp = strprefix(cp, "SHA256:", 0)) == پوچ)
		fatal("%s:%lu: unsupported hash algorithm", file, lnum);

	/*
	 * OpenSSH base64 hashes omit trailing '='
	 * characters; put them back for decode.
	 */
	اگر ((tlen = strlen(cp)) >= SIZE_MAX - 5)
		fatal_f("hash too long: %zu bytes", tlen);
	tmp = xmalloc(tlen + 4 + 1);
	strlcpy(tmp, cp, tlen + 1);
	وقتی ((tlen % 4) != 0) {
		tmp[tlen++] = '=';
		tmp[tlen] = '\0';
	}
	اگر ((b = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_b64tod(b, tmp)) != 0)
		fatal_r(r, "%s:%lu: decode hash failed", file, lnum);
	آزاد(tmp);
	*lenp = sshbuf_len(b);
	*blobp = xmalloc(*lenp);
	memcpy(*blobp, sshbuf_ptr(b), *lenp);
	sshbuf_free(b);
}

ایستا تهی
update_krl_from_file(ساختار passwd *pw, ثابت نویسه *file, صحیح wild_ca,
    ثابت ساختار sshkey *ca, ساختار ssh_krl *krl)
{
	ساختار sshkey *کلید = پوچ;
	u_long lnum = 0;
	نویسه *path, *cp, *ep, *سطر = پوچ;
	u_char *blob = پوچ;
	size_t blen = 0, linesize = 0;
	unsigned long long serial, serial2;
	صحیح i, was_explicit_کلید, was_sha1, was_sha256, was_hash, r;
	FILE *krl_spec;

	path = tilde_expand_filename(file, pw->pw_uid);
	اگر (strcmp(path, "-") == 0) {
		krl_spec = stdin;
		آزاد(path);
		path = xstrdup("(standard input)");
	} وگرنه اگر ((krl_spec = fopen(path, "r")) == پوچ)
		fatal("fopen %s: %s", path, strerror(errno));

	اگر (!quiet)
		printf("Revoking from %s\n", path);
	وقتی (getline(&سطر, &linesize, krl_spec) != -1) {
		اگر (linesize >= INT_MAX) {
			fatal_f("%s contains unparsable line, len=%zu",
			    path, linesize);
		}
		lnum++;
		was_explicit_کلید = was_sha1 = was_sha256 = was_hash = 0;
		cp = سطر + strspn(سطر, " \t");
		/* Trim trailing space, comments and strip \n */
		برای (i = 0, r = -1; cp[i] != '\0'; i++) {
			اگر (cp[i] == '#' || cp[i] == '\n') {
				cp[i] = '\0';
				بشکن;
			}
			اگر (cp[i] == ' ' || cp[i] == '\t') {
				/* Remember the start of a span of whitespace */
				اگر (r == -1)
					r = i;
			} وگرنه
				r = -1;
		}
		اگر (r != -1)
			cp[r] = '\0';
		اگر (*cp == '\0')
			ادامه;
		اگر (strncasecmp(cp, "serial:", 7) == 0) {
			اگر (ca == پوچ && !wild_ca) {
				fatal("revoking certificates by serial number "
				    "requires specification of a CA key");
			}
			cp += 7;
			cp = cp + strspn(cp, " \t");
			errno = 0;
			serial = strtoull(cp, &ep, 0);
			اگر (*cp == '\0' || (*ep != '\0' && *ep != '-'))
				fatal("%s:%lu: invalid serial \"%s\"",
				    path, lnum, cp);
			اگر (errno == ERANGE && serial == ULLONG_MAX)
				fatal("%s:%lu: serial out of range",
				    path, lnum);
			serial2 = serial;
			اگر (*ep == '-') {
				cp = ep + 1;
				errno = 0;
				serial2 = strtoull(cp, &ep, 0);
				اگر (*cp == '\0' || *ep != '\0')
					fatal("%s:%lu: invalid serial \"%s\"",
					    path, lnum, cp);
				اگر (errno == ERANGE && serial2 == ULLONG_MAX)
					fatal("%s:%lu: serial out of range",
					    path, lnum);
				اگر (serial2 <= serial)
					fatal("%s:%lu: invalid serial range "
					    "%llu:%llu", path, lnum,
					    (unsigned long long)serial,
					    (unsigned long long)serial2);
			}
			اگر (ssh_krl_revoke_cert_by_serial_range(krl,
			    ca, serial, serial2) != 0) {
				fatal_f("revoke serial failed");
			}
		} وگرنه اگر (strncasecmp(cp, "id:", 3) == 0) {
			اگر (ca == پوچ && !wild_ca) {
				fatal("revoking certificates by key ID "
				    "requires specification of a CA key");
			}
			cp += 3;
			cp = cp + strspn(cp, " \t");
			اگر (ssh_krl_revoke_cert_by_کلید_id(krl, ca, cp) != 0)
				fatal_f("revoke key ID failed");
		} وگرنه اگر (strncasecmp(cp, "hash:", 5) == 0) {
			cp += 5;
			cp = cp + strspn(cp, " \t");
			hash_to_blob(cp, &blob, &blen, file, lnum);
			اگر ((r = ssh_krl_revoke_کلید_sha256(krl,
			    blob, blen)) != 0)
				fatal_fr(r, "revoke key failed");
			آزاد(blob);
			blob = پوچ;
			blen = 0;
		} وگرنه {
			اگر (strncasecmp(cp, "key:", 4) == 0) {
				cp += 4;
				cp = cp + strspn(cp, " \t");
				was_explicit_کلید = 1;
			} وگرنه اگر (strncasecmp(cp, "sha1:", 5) == 0) {
				cp += 5;
				cp = cp + strspn(cp, " \t");
				was_sha1 = 1;
			} وگرنه اگر (strncasecmp(cp, "sha256:", 7) == 0) {
				cp += 7;
				cp = cp + strspn(cp, " \t");
				was_sha256 = 1;
				/*
				 * Just try to process the line as a key.
				 * Parsing will fail if it isn't.
				 */
			}
			اگر ((کلید = sshkey_new(کلید_UNSPEC)) == پوچ)
				fatal("sshkey_new");
			اگر ((r = sshkey_read(کلید, &cp)) != 0)
				fatal_r(r, "%s:%lu: invalid key", path, lnum);
			اگر (was_explicit_کلید)
				r = ssh_krl_revoke_کلید_explicit(krl, کلید);
			وگرنه اگر (was_sha1) {
				اگر (sshkey_fingerprint_raw(کلید,
				    SSH_DIGEST_SHA1, &blob, &blen) != 0) {
					fatal("%s:%lu: fingerprint failed",
					    file, lnum);
				}
				r = ssh_krl_revoke_کلید_sha1(krl, blob, blen);
			} وگرنه اگر (was_sha256) {
				اگر (sshkey_fingerprint_raw(کلید,
				    SSH_DIGEST_SHA256, &blob, &blen) != 0) {
					fatal("%s:%lu: fingerprint failed",
					    file, lnum);
				}
				r = ssh_krl_revoke_کلید_sha256(krl, blob, blen);
			} وگرنه
				r = ssh_krl_revoke_کلید(krl, کلید);
			اگر (r != 0)
				fatal_fr(r, "revoke key failed");
			freezero(blob, blen);
			blob = پوچ;
			blen = 0;
			sshkey_free(کلید);
		}
	}
	اگر (strcmp(path, "-") != 0)
		fclose(krl_spec);
	آزاد(سطر);
	آزاد(path);
}

ایستا تهی
do_gen_krl(ساختار passwd *pw, صحیح updating, ثابت نویسه *ca_کلید_path,
    unsigned long long krl_version, ثابت نویسه *krl_comment,
    صحیح argc, نویسه **argv)
{
	ساختار ssh_krl *krl;
	ساختار stat sb;
	ساختار sshkey *ca = پوچ;
	صحیح i, r, wild_ca = 0;
	نویسه *tmp;
	ساختار sshbuf *kbuf;

	اگر (*identity_file == '\0')
		fatal("KRL generation requires an output file");
	اگر (stat(identity_file, &sb) == -1) {
		اگر (errno != ENOENT)
			fatal("Cannot access KRL \"%s\": %s",
			    identity_file, strerror(errno));
		اگر (updating)
			fatal("KRL \"%s\" does not exist", identity_file);
	}
	اگر (ca_کلید_path != پوچ) {
		اگر (strcasecmp(ca_کلید_path, "none") == 0)
			wild_ca = 1;
		وگرنه {
			tmp = tilde_expand_filename(ca_کلید_path, pw->pw_uid);
			اگر ((r = sshkey_load_public(tmp, &ca, پوچ)) != 0)
				fatal_r(r, "Cannot load CA public key %s", tmp);
			آزاد(tmp);
		}
	}

	اگر (updating)
		load_krl(identity_file, &krl);
	وگرنه اگر ((krl = ssh_krl_init()) == پوچ)
		fatal("couldn't create KRL");

	اگر (krl_version != 0)
		ssh_krl_set_version(krl, krl_version);
	اگر (krl_comment != پوچ)
		ssh_krl_set_comment(krl, krl_comment);

	برای (i = 0; i < argc; i++)
		update_krl_from_file(pw, argv[i], wild_ca, ca, krl);

	اگر ((kbuf = sshbuf_new()) == پوچ)
		fatal("sshbuf_new failed");
	اگر (ssh_krl_to_blob(krl, kbuf) != 0)
		fatal("Couldn't generate KRL");
	اگر ((r = sshbuf_write_file(identity_file, kbuf)) != 0)
		fatal("write %s: %s", identity_file, strerror(errno));
	sshbuf_free(kbuf);
	ssh_krl_free(krl);
	sshkey_free(ca);
}

ایستا تهی
do_check_krl(ساختار passwd *pw, صحیح print_krl, صحیح argc, نویسه **argv)
{
	صحیح i, r, ret = 0;
	نویسه *comment;
	ساختار ssh_krl *krl;
	ساختار sshkey *k;

	اگر (*identity_file == '\0')
		fatal("KRL checking requires an input file");
	load_krl(identity_file, &krl);
	اگر (print_krl)
		krl_dump(krl, stdout);
	برای (i = 0; i < argc; i++) {
		اگر ((r = sshkey_load_public(argv[i], &k, &comment)) != 0)
			fatal_r(r, "Cannot load public key %s", argv[i]);
		r = ssh_krl_check_کلید(krl, k);
		printf("%s%s%s%s: %s\n", argv[i],
		    *comment ? " (" : "", comment, *comment ? ")" : "",
		    r == 0 ? "ok" : "REVOKED");
		اگر (r != 0)
			ret = 1;
		sshkey_free(k);
		آزاد(comment);
	}
	ssh_krl_free(krl);
	exit(ret);
}

ایستا ساختار sshkey *
load_sign_کلید(ثابت نویسه *keypath, ثابت ساختار sshkey *pubkey)
{
	size_t i, slen, plen = strlen(keypath);
	نویسه *privpath = xstrdup(keypath);
	ایستا ثابت نویسه * ثابت suffixes[] = { "-cert.pub", ".pub", پوچ };
	ساختار sshkey *ret = پوچ, *privkey = پوچ;
	صحیح r, waspub = 0;
	ساختار stat st;

	/*
	 * If passed a public key filename, then try to locate the corresponding
	 * private key. This lets us specify certificates on the command-line
	 * and have ssh-keygen find the appropriate private key.
	 */
	برای (i = 0; suffixes[i]; i++) {
		slen = strlen(suffixes[i]);
		اگر (plen <= slen ||
		    strcmp(privpath + plen - slen, suffixes[i]) != 0)
			ادامه;
		privpath[plen - slen] = '\0';
		debug_f("%s looks like a public key, using private key "
		    "path %s instead", keypath, privpath);
		waspub = 1;
	}
	اگر (waspub && stat(privpath, &st) != 0 && errno == ENOENT)
		fatal("No private key found for public key \"%s\"", keypath);
	اگر ((r = sshkey_load_private(privpath, "", &privkey, پوچ)) != 0 &&
	    (r != SSH_ERR_کلید_WRONG_PASSPHRASE)) {
		debug_fr(r, "load private key \"%s\"", privpath);
		fatal("No private key found for \"%s\"", privpath);
	} وگرنه اگر (privkey == پوچ)
		privkey = load_identity(privpath, پوچ);

	اگر (!sshkey_equal_public(pubkey, privkey)) {
		error("Public key %s doesn't match private %s",
		    keypath, privpath);
		برو done;
	}
	اگر (sshkey_is_cert(pubkey) && !sshkey_is_cert(privkey)) {
		/*
		 * Graft the certificate onto the private key to make
		 * it capable of signing.
		 */
		اگر ((r = sshkey_to_certified(privkey)) != 0) {
			error_fr(r, "sshkey_to_certified");
			برو done;
		}
		اگر ((r = sshkey_cert_copy(pubkey, privkey)) != 0) {
			error_fr(r, "sshkey_cert_copy");
			برو done;
		}
	}
	/* success */
	ret = privkey;
	privkey = پوچ;
 done:
	sshkey_free(privkey);
	آزاد(privpath);
	بازگشت ret;
}

ایستا صحیح
sign_one(ساختار sshkey *signkey, ثابت نویسه *filename, صحیح fd,
    ثابت نویسه *sig_namespace, ثابت نویسه *hashalg, sshsig_signer *signer,
    تهی *signer_ctx)
{
	ساختار sshbuf *sigbuf = پوچ, *abuf = پوچ;
	صحیح r = SSH_ERR_INTERNAL_ERROR, wfd = -1, oerrno;
	نویسه *wfile = پوچ, *asig = پوچ, *fp = پوچ;
	نویسه *pin = پوچ, *prompt = پوچ;

	اگر (!quiet) {
		اگر (fd == STDIN_FILENO)
			fprintf(stderr, "Signing data on standard input\n");
		وگرنه
			fprintf(stderr, "Signing file %s\n", filename);
	}
	اگر (signer == پوچ && sshkey_is_sk(signkey)) {
		اگر ((signkey->sk_flags & SSH_SK_USER_VERIFICATION_REQD)) {
			xasprintf(&prompt, "Enter PIN for %s key: ",
			    sshkey_type(signkey));
			اگر ((pin = read_passphrase(prompt,
			    RP_ALLOW_STDIN)) == پوچ)
				fatal_f("couldn't read PIN");
		}
		اگر ((signkey->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
			اگر ((fp = sshkey_fingerprint(signkey, fingerprint_hash,
			    SSH_FP_DEFAULT)) == پوچ)
				fatal_f("fingerprint failed");
			fprintf(stderr, "Confirm user presence for key %s %s\n",
			    sshkey_type(signkey), fp);
			آزاد(fp);
		}
	}
	اگر ((r = sshsig_sign_fd(signkey, hashalg, sk_provider, pin,
	    fd, sig_namespace, &sigbuf, signer, signer_ctx)) != 0) {
		error_r(r, "Signing %s failed", filename);
		برو out;
	}
	اگر ((r = sshsig_armor(sigbuf, &abuf)) != 0) {
		error_fr(r, "sshsig_armor");
		برو out;
	}
	اگر ((asig = sshbuf_dup_string(abuf)) == پوچ) {
		error_f("buffer error");
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}

	اگر (fd == STDIN_FILENO) {
		fputs(asig, stdout);
		fflush(stdout);
	} وگرنه {
		xasprintf(&wfile, "%s.sig", filename);
		اگر (confirm_overwrite(wfile)) {
			اگر ((wfd = open(wfile, O_WRONLY|O_CREAT|O_TRUNC,
			    0666)) == -1) {
				oerrno = errno;
				error("Cannot open %s: %s",
				    wfile, strerror(errno));
				errno = oerrno;
				r = SSH_ERR_SYSTEM_ERROR;
				برو out;
			}
			اگر (atomicio(vwrite, wfd, asig,
			    strlen(asig)) != strlen(asig)) {
				oerrno = errno;
				error("Cannot write to %s: %s",
				    wfile, strerror(errno));
				errno = oerrno;
				r = SSH_ERR_SYSTEM_ERROR;
				برو out;
			}
			اگر (!quiet) {
				fprintf(stderr, "Write signature to %s\n",
				    wfile);
			}
		}
	}
	/* success */
	r = 0;
 out:
	آزاد(wfile);
	آزاد(prompt);
	آزاد(asig);
	اگر (pin != پوچ)
		freezero(pin, strlen(pin));
	sshbuf_free(abuf);
	sshbuf_free(sigbuf);
	اگر (wfd != -1)
		close(wfd);
	بازگشت r;
}

ایستا صحیح
sig_process_opts(نویسه * ثابت *opts, size_t nopts, نویسه **hashalgp,
    uint64_t *verify_timep, صحیح *print_pubkey)
{
	size_t i;
	time_t now;
	ثابت نویسه *p;

	اگر (verify_timep != پوچ)
		*verify_timep = 0;
	اگر (print_pubkey != پوچ)
		*print_pubkey = 0;
	اگر (hashalgp != پوچ)
		*hashalgp = پوچ;
	برای (i = 0; i < nopts; i++) {
		اگر (hashalgp != پوچ &&
		    (p = strprefix(opts[i], "hashalg=", 1)) != پوچ) {
			*hashalgp = xstrdup(p);
		} وگرنه اگر (verify_timep &&
		    (p = strprefix(opts[i], "verify-time=", 1)) != پوچ) {
			اگر (parse_absolute_time(p, verify_timep) != 0 ||
			    *verify_timep == 0) {
				error("Invalid \"verify-time\" option");
				بازگشت SSH_ERR_INVALID_ARGUMENT;
			}
		} وگرنه اگر (print_pubkey &&
		    strcasecmp(opts[i], "print-pubkey") == 0) {
			*print_pubkey = 1;
		} وگرنه {
			error("Invalid option \"%s\"", opts[i]);
			بازگشت SSH_ERR_INVALID_ARGUMENT;
		}
	}
	اگر (verify_timep && *verify_timep == 0) {
		اگر ((now = time(پوچ)) < 0) {
			error("Time is before epoch");
			بازگشت SSH_ERR_INVALID_ARGUMENT;
		}
		*verify_timep = (uint64_t)now;
	}
	بازگشت 0;
}


ایستا صحیح
sig_sign(ثابت نویسه *keypath, ثابت نویسه *sig_namespace, صحیح require_agent,
    صحیح argc, نویسه **argv, نویسه * ثابت *opts, size_t nopts)
{
	صحیح i, fd = -1, r, ret = -1;
	صحیح agent_fd = -1;
	ساختار sshkey *pubkey = پوچ, *privkey = پوچ, *signkey = پوچ;
	sshsig_signer *signer = پوچ;
	نویسه *hashalg = پوچ;

	/* Check file arguments. */
	برای (i = 0; i < argc; i++) {
		اگر (strcmp(argv[i], "-") != 0)
			ادامه;
		اگر (i > 0 || argc > 1)
			fatal("Cannot sign mix of paths and standard input");
	}

	اگر (sig_process_opts(opts, nopts, &hashalg, پوچ, پوچ) != 0)
		برو done; /* error already logged */

	اگر ((r = sshkey_load_public(keypath, &pubkey, پوچ)) != 0) {
		error_r(r, "Couldn't load public key %s", keypath);
		برو done;
	}

	اگر ((r = ssh_get_authentication_socket(&agent_fd)) != 0) {
		اگر (require_agent)
			fatal("Couldn't get agent socket");
		debug_r(r, "Couldn't get agent socket");
	} وگرنه {
		اگر ((r = ssh_agent_has_کلید(agent_fd, pubkey)) == 0)
			signer = agent_signer;
		وگرنه {
			اگر (require_agent)
				fatal("Couldn't find key in agent");
			debug_r(r, "Couldn't find key in agent");
		}
	}

	اگر (signer == پوچ) {
		/* Not using agent - try to load private key */
		اگر ((privkey = load_sign_کلید(keypath, pubkey)) == پوچ)
			برو done;
		signkey = privkey;
	} وگرنه {
		/* Will use key in agent */
		signkey = pubkey;
	}

	اگر (argc == 0) {
		اگر ((r = sign_one(signkey, "(stdin)", STDIN_FILENO,
		    sig_namespace, hashalg, signer, &agent_fd)) != 0)
			برو done;
	} وگرنه {
		برای (i = 0; i < argc; i++) {
			اگر (strcmp(argv[i], "-") == 0)
				fd = STDIN_FILENO;
			وگرنه اگر ((fd = open(argv[i], O_RDONLY)) == -1) {
				error("Cannot open %s for signing: %s",
				    argv[i], strerror(errno));
				برو done;
			}
			اگر ((r = sign_one(signkey, argv[i], fd, sig_namespace,
			    hashalg, signer, &agent_fd)) != 0)
				برو done;
			اگر (fd != STDIN_FILENO)
				close(fd);
			fd = -1;
		}
	}

	ret = 0;
done:
	اگر (fd != -1 && fd != STDIN_FILENO)
		close(fd);
	sshkey_free(pubkey);
	sshkey_free(privkey);
	آزاد(hashalg);
	بازگشت ret;
}

ایستا صحیح
sig_verify(ثابت نویسه *signature, ثابت نویسه *sig_namespace,
    ثابت نویسه *principal, ثابت نویسه *allowed_کلیدها, ثابت نویسه *revoked_کلیدها,
    نویسه * ثابت *opts, size_t nopts)
{
	صحیح r, ret = -1;
	صحیح print_pubkey = 0;
	ساختار sshbuf *sigbuf = پوچ, *abuf = پوچ;
	ساختار sshkey *sign_کلید = پوچ;
	نویسه *fp = پوچ;
	ساختار sshkey_sig_details *sig_details = پوچ;
	uint64_t verify_time = 0;

	اگر (sig_process_opts(opts, nopts, پوچ, &verify_time,
	    &print_pubkey) != 0)
		برو done; /* error already logged */

	memset(&sig_details, 0, اندازه(sig_details));
	اگر ((r = sshbuf_load_file(signature, &abuf)) != 0) {
		error_r(r, "Couldn't read signature file");
		برو done;
	}

	اگر ((r = sshsig_dearmor(abuf, &sigbuf)) != 0) {
		error_fr(r, "sshsig_armor");
		برو done;
	}
	اگر ((r = sshsig_verify_fd(sigbuf, STDIN_FILENO, sig_namespace,
	    &sign_کلید, &sig_details)) != 0)
		برو done; /* sshsig_verify() prints error */

	اگر ((fp = sshkey_fingerprint(sign_کلید, fingerprint_hash,
	    SSH_FP_DEFAULT)) == پوچ)
		fatal_f("sshkey_fingerprint failed");
	debug("Valid (unverified) signature from key %s", fp);
	اگر (sig_details != پوچ) {
		debug2_f("signature details: counter = %u, flags = 0x%02x",
		    sig_details->sk_counter, sig_details->sk_flags);
	}
	آزاد(fp);
	fp = پوچ;

	اگر (revoked_کلیدها != پوچ) {
		اگر ((r = sshkey_check_revoked(sign_کلید, revoked_کلیدها)) != 0) {
			debug3_fr(r, "sshkey_check_revoked");
			برو done;
		}
	}

	اگر (allowed_کلیدها != پوچ && (r = sshsig_check_allowed_کلیدها(allowed_کلیدها,
	    sign_کلید, principal, sig_namespace, verify_time)) != 0) {
		debug3_fr(r, "sshsig_check_allowed_keys");
		برو done;
	}
	/* success */
	ret = 0;
done:
	اگر (!quiet) {
		اگر (ret == 0) {
			اگر ((fp = sshkey_fingerprint(sign_کلید, fingerprint_hash,
			    SSH_FP_DEFAULT)) == پوچ)
				fatal_f("sshkey_fingerprint failed");
			اگر (principal == پوچ) {
				printf("Good \"%s\" signature with %s key %s\n",
				    sig_namespace, sshkey_type(sign_کلید), fp);

			} وگرنه {
				printf("Good \"%s\" signature for %s with %s key %s\n",
				    sig_namespace, principal,
				    sshkey_type(sign_کلید), fp);
			}
		} وگرنه {
			printf("Could not verify signature.\n");
		}
	}
	/* Print the signature key if requested */
	اگر (ret == 0 && print_pubkey && sign_کلید != پوچ) {
		اگر ((r = sshkey_write(sign_کلید, stdout)) == 0)
			fputc('\n', stdout);
		وگرنه {
			error_r(r, "Could not print public key.\n");
			ret = -1;
		}
	}
	sshbuf_free(sigbuf);
	sshbuf_free(abuf);
	sshkey_free(sign_کلید);
	sshkey_sig_details_free(sig_details);
	آزاد(fp);
	بازگشت ret;
}

ایستا صحیح
sig_find_principals(ثابت نویسه *signature, ثابت نویسه *allowed_کلیدها,
    نویسه * ثابت *opts, size_t nopts)
{
	صحیح r, ret = -1;
	ساختار sshbuf *sigbuf = پوچ, *abuf = پوچ;
	ساختار sshkey *sign_کلید = پوچ;
	نویسه *principals = پوچ, *cp, *tmp;
	uint64_t verify_time = 0;

	اگر (sig_process_opts(opts, nopts, پوچ, &verify_time, پوچ) != 0)
		برو done; /* error already logged */

	اگر ((r = sshbuf_load_file(signature, &abuf)) != 0) {
		error_r(r, "Couldn't read signature file");
		برو done;
	}
	اگر ((r = sshsig_dearmor(abuf, &sigbuf)) != 0) {
		error_fr(r, "sshsig_armor");
		برو done;
	}
	اگر ((r = sshsig_get_pubkey(sigbuf, &sign_کلید)) != 0) {
		error_fr(r, "sshsig_get_pubkey");
		برو done;
	}
	اگر ((r = sshsig_find_principals(allowed_کلیدها, sign_کلید,
	    verify_time, &principals)) != 0) {
		اگر (r != SSH_ERR_کلید_NOT_FOUND)
			error_fr(r, "sshsig_find_principal");
		برو done;
	}
	ret = 0;
done:
	اگر (ret == 0 ) {
		/* Emit matching principals one per line */
		tmp = principals;
		وقتی ((cp = strsep(&tmp, ",")) != پوچ && *cp != '\0')
			puts(cp);
	} وگرنه {
		fprintf(stderr, "No principal matched.\n");
	}
	sshbuf_free(sigbuf);
	sshbuf_free(abuf);
	sshkey_free(sign_کلید);
	آزاد(principals);
	بازگشت ret;
}

ایستا صحیح
sig_match_principals(ثابت نویسه *allowed_کلیدها, نویسه *principal,
	نویسه * ثابت *opts, size_t nopts)
{
	صحیح r;
	نویسه **principals = پوچ;
	size_t i, nprincipals = 0;

	اگر ((r = sig_process_opts(opts, nopts, پوچ, پوچ, پوچ)) != 0)
		بازگشت r; /* error already logged */

	اگر ((r = sshsig_match_principals(allowed_کلیدها, principal,
	    &principals, &nprincipals)) != 0) {
		debug_f("match: %s", ssh_err(r));
		fprintf(stderr, "No principal matched.\n");
		بازگشت r;
	}
	برای (i = 0; i < nprincipals; i++) {
		printf("%s\n", principals[i]);
		آزاد(principals[i]);
	}
	آزاد(principals);

	بازگشت 0;
}

ایستا تهی
do_moduli_gen(ثابت نویسه *out_file, نویسه **opts, size_t nopts)
{
#ifdef WITH_OPENSSL
	/* Moduli generation/screening */
	BIGNUM *start = پوچ;
	صحیح moduli_bits = 0;
	FILE *out;
	size_t i;
	ثابت نویسه *errstr, *p;

	/* Parse options */
	برای (i = 0; i < nopts; i++) {
		اگر ((p = strprefix(opts[i], "start=", 0)) != پوچ) {
			/* XXX - also compare length against bits */
			اگر (BN_hex2bn(&start, p) == 0)
				fatal("Invalid start point.");
		} وگرنه اگر ((p = strprefix(opts[i], "bits=", 0)) != پوچ) {
			moduli_bits = (صحیح)strtonum(p, 1, INT_MAX, &errstr);
			اگر (errstr) {
				fatal("Invalid number: %s (%s)", p, errstr);
			}
		} وگرنه {
			fatal("Option \"%s\" is unsupported for moduli "
			    "generation", opts[i]);
		}
	}

	اگر (strcmp(out_file, "-") == 0)
		out = stdout;
	وگرنه اگر ((out = fopen(out_file, "w")) == پوچ) {
		fatal("Couldn't open modulus candidate file \"%s\": %s",
		    out_file, strerror(errno));
	}
	setvbuf(out, پوچ, _IOLBF, 0);

	اگر (moduli_bits == 0)
		moduli_bits = DEFAULT_BITS;
	اگر (gen_candidates(out, moduli_bits, start) != 0)
		fatal("modulus candidate generation failed");
#وگرنه /* WITH_OPENSSL */
	fatal("Moduli generation is not supported");
#endif /* WITH_OPENSSL */
}

ایستا تهی
do_moduli_screen(ثابت نویسه *out_file, نویسه **opts, size_t nopts)
{
#ifdef WITH_OPENSSL
	/* Moduli generation/screening */
	نویسه *checkpoint = پوچ;
	uint32_t generator_wanted = 0;
	unsigned long start_lineno = 0, سطرها_to_process = 0;
	صحیح اول_tests = 0;
	FILE *out, *in = stdin;
	size_t i;
	ثابت نویسه *errstr, *p;

	/* Parse options */
	برای (i = 0; i < nopts; i++) {
		اگر ((p = strprefix(opts[i], "lines=", 0)) != پوچ) {
			سطرها_to_process = strtoul(p, پوچ, 10);
		} وگرنه اگر ((p = strprefix(opts[i], "start-line=", 0)) != پوچ) {
			start_lineno = strtoul(p, پوچ, 10);
		} وگرنه اگر ((p = strprefix(opts[i], "checkpoint=", 0)) != پوچ) {
			آزاد(checkpoint);
			checkpoint = xstrdup(p);
		} وگرنه اگر ((p = strprefix(opts[i], "generator=", 0)) != پوچ) {
			generator_wanted = (uint32_t)strtonum(p, 1, UINT_MAX,
			    &errstr);
			اگر (errstr != پوچ) {
				fatal("Generator invalid: %s (%s)", p, errstr);
			}
		} وگرنه اگر ((p = strprefix(opts[i], "prime-tests=", 0)) != پوچ) {
			اول_tests = (صحیح)strtonum(p, 1, INT_MAX, &errstr);
			اگر (errstr) {
				fatal("Invalid number: %s (%s)", p, errstr);
			}
		} وگرنه {
			fatal("Option \"%s\" is unsupported for moduli "
			    "screening", opts[i]);
		}
	}

	اگر (have_identity && strcmp(identity_file, "-") != 0) {
		اگر ((in = fopen(identity_file, "r")) == پوچ) {
			fatal("Couldn't open modulus candidate "
			    "file \"%s\": %s", identity_file,
			    strerror(errno));
		}
	}

	اگر (strcmp(out_file, "-") == 0)
		out = stdout;
	وگرنه اگر ((out = fopen(out_file, "a")) == پوچ) {
		fatal("Couldn't open moduli file \"%s\": %s",
		    out_file, strerror(errno));
	}
	setvbuf(out, پوچ, _IOLBF, 0);
	اگر (اول_test(in, out, اول_tests == 0 ? 100 : اول_tests,
	    generator_wanted, checkpoint,
	    start_lineno, سطرها_to_process) != 0)
		fatal("modulus screening failed");
	اگر (in != stdin)
		(تهی)fclose(in);
	آزاد(checkpoint);
#وگرنه /* WITH_OPENSSL */
	fatal("Moduli screening is not supported");
#endif /* WITH_OPENSSL */
}

/* Read and confirm a passphrase */
ایستا نویسه *
read_check_passphrase(ثابت نویسه *prompt1, ثابت نویسه *prompt2,
    ثابت نویسه *retry_prompt)
{
	نویسه *passphrase1, *passphrase2;

	برای (;;) {
		passphrase1 = read_passphrase(prompt1, RP_ALLOW_STDIN);
		passphrase2 = read_passphrase(prompt2, RP_ALLOW_STDIN);
		اگر (strcmp(passphrase1, passphrase2) == 0) {
			freezero(passphrase2, strlen(passphrase2));
			بازگشت passphrase1;
		}
		/* The passphrases do not match. Clear them and retry. */
		freezero(passphrase1, strlen(passphrase1));
		freezero(passphrase2, strlen(passphrase2));
		fputs(retry_prompt, stdout);
		fputc('\n', stdout);
		fflush(stdout);
	}
	/* NOTREACHED */
	بازگشت پوچ;
}

ایستا نویسه *
private_کلید_passphrase(ثابت نویسه *path)
{
	نویسه *prompt, *ret;

	اگر (identity_passphrase)
		بازگشت xstrdup(identity_passphrase);
	اگر (identity_new_passphrase)
		بازگشت xstrdup(identity_new_passphrase);

	xasprintf(&prompt, "Enter passphrase for \"%s\" "
	    "(empty for no passphrase): ", path);
	ret = read_check_passphrase(prompt,
	    "Enter same passphrase again: ",
	    "Passphrases do not match.  Try again.");
	آزاد(prompt);
	بازگشت ret;
}

ایستا نویسه *
sk_suffix(ثابت نویسه *application, ثابت uint8_t *user, size_t userlen)
{
	نویسه *ret, *cp;
	ثابت نویسه *p;
	size_t slen, i;

	/* Trim off URL-like preamble */
	اگر ((p = strprefix(application, "ssh://", 0)) != پوچ)
		ret =  xstrdup(p);
	وگرنه اگر ((p = strprefix(application, "ssh:", 0)) != پوچ)
		ret =  xstrdup(p);
	وگرنه
		ret = xstrdup(application);

	/* Count trailing zeros in user */
	برای (i = 0; i < userlen; i++) {
		اگر (user[userlen - i - 1] != 0)
			بشکن;
	}
	اگر (i >= userlen)
		بازگشت ret; /* user-id was default all-zeros */

	/* Append user-id, escaping non-UTF-8 characters */
	slen = userlen - i;
	اگر (asmprintf(&cp, INT_MAX, پوچ, "%.*s", (صحیح)slen, user) == -1)
		fatal_f("asmprintf failed");
	/* Don't emit a user-id that contains path or control characters */
	اگر (strchr(cp, '/') != پوچ || strstr(cp, "..") != پوچ ||
	    strchr(cp, '\\') != پوچ) {
		آزاد(cp);
		cp = tohex(user, slen);
	}
	xextendf(&ret, "_", "%s", cp);
	آزاد(cp);
	بازگشت ret;
}

ایستا صحیح
do_download_sk(ثابت نویسه *skprovider, ثابت نویسه *device)
{
	ساختار sshsk_resident_کلید **srks;
	size_t nsrks, i;
	صحیح r, ret = -1;
	نویسه *fp, *pin = پوچ, *pass = پوچ, *path, *pubpath;
	ثابت نویسه *ext;
	ساختار sshkey *کلید;

	اگر (skprovider == پوچ)
		fatal("Cannot download keys without provider");

	pin = read_passphrase("Enter PIN for authenticator: ", RP_ALLOW_STDIN);
	اگر (!quiet) {
		printf("You may need to touch your authenticator "
		    "to authorize key download.\n");
	}
	اگر ((r = sshsk_load_resident(skprovider, device, pin, 0,
	    &srks, &nsrks)) != 0) {
		اگر (pin != پوچ)
			freezero(pin, strlen(pin));
		error_r(r, "Unable to load resident keys");
		بازگشت -1;
	}
	اگر (nsrks == 0)
		logit("No keys to download");
	اگر (pin != پوچ)
		freezero(pin, strlen(pin));

	برای (i = 0; i < nsrks; i++) {
		کلید = srks[i]->کلید;
		اگر (کلید->type != کلید_ECDSA_SK && کلید->type != کلید_ED25519_SK) {
			error("Unsupported key type %s (%d)",
			    sshkey_type(کلید), کلید->type);
			ادامه;
		}
		اگر ((fp = sshkey_fingerprint(کلید, fingerprint_hash,
		    SSH_FP_DEFAULT)) == پوچ)
			fatal_f("sshkey_fingerprint failed");
		debug_f("key %zu: %s %s %s (flags 0x%02x)", i,
		    sshkey_type(کلید), fp, کلید->sk_application, کلید->sk_flags);
		ext = sk_suffix(کلید->sk_application,
		    srks[i]->user_id, srks[i]->user_id_len);
		xasprintf(&path, "id_%s_rk%s%s",
		    کلید->type == کلید_ECDSA_SK ? "ecdsa_sk" : "ed25519_sk",
		    *ext == '\0' ? "" : "_", ext);

		/* If the file already exists, ask the user to confirm. */
		اگر (!confirm_overwrite(path)) {
			آزاد(path);
			بشکن;
		}

		/* Save the key with the application string as the comment */
		اگر (pass == پوچ)
			pass = private_کلید_passphrase(path);
		اگر ((r = sshkey_save_private(کلید, path, pass,
		    کلید->sk_application, private_کلید_format,
		    openssh_format_cipher, rounds)) != 0) {
			error_r(r, "Saving key \"%s\" failed", path);
			آزاد(path);
			بشکن;
		}
		اگر (!quiet) {
			printf("Saved %s key%s%s to %s\n", sshkey_type(کلید),
			    *ext != '\0' ? " " : "",
			    *ext != '\0' ? کلید->sk_application : "",
			    path);
		}

		/* Save public key too */
		xasprintf(&pubpath, "%s.pub", path);
		آزاد(path);
		اگر ((r = sshkey_save_public(کلید, pubpath,
		    کلید->sk_application)) != 0) {
			error_r(r, "Saving public key \"%s\" failed", pubpath);
			آزاد(pubpath);
			بشکن;
		}
		آزاد(pubpath);
	}

	اگر (i >= nsrks)
		ret = 0; /* success */
	اگر (pass != پوچ)
		freezero(pass, strlen(pass));
	sshsk_free_resident_کلیدها(srks, nsrks);
	بازگشت ret;
}

ایستا تهی
save_attestation(ساختار sshbuf *attest, ثابت نویسه *path)
{
	mode_t omask;
	صحیح r;

	اگر (path == پوچ)
		بازگشت; /* nothing to do */
	اگر (attest == پوچ || sshbuf_len(attest) == 0)
		fatal("Enrollment did not return attestation data");
	omask = umask(077);
	r = sshbuf_write_file(path, attest);
	umask(omask);
	اگر (r != 0)
		fatal_r(r, "Unable to write attestation data \"%s\"", path);
	اگر (!quiet)
		printf("Your FIDO attestation certificate has been saved in "
		    "%s\n", path);
}

ایستا صحیح
confirm_sk_overwrite(ثابت نویسه *application, ثابت نویسه *user)
{
	نویسه yesno[3];

	printf("A resident key scoped to '%s' with user id '%s' already "
	    "exists.\n", application == پوچ ? "ssh:" : application,
	    user == پوچ ? "null" : user);
	printf("Overwrite key in token (y/n)? ");
	fflush(stdout);
	اگر (fgets(yesno, اندازه(yesno), stdin) == پوچ)
		بازگشت 0;
	اگر (yesno[0] != 'y' && yesno[0] != 'Y')
		بازگشت 0;
	بازگشت 1;
}

ایستا تهی
usage(تهی)
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
صحیح
اصلی(صحیح argc, نویسه **argv)
{
	نویسه comment[کلید_COMMENT_MAX], *passphrase = پوچ;
	نویسه *rr_hostname = پوچ, *ep, *fp, *ra;
	ساختار sshkey *خصوصی = پوچ, *عمومی = پوچ;
	ساختار passwd *pw;
	صحیح ret = 0, r, opt, type;
	صحیح change_passphrase = 0, change_comment = 0, show_cert = 0;
	صحیح find_host = 0, delete_host = 0, hash_hosts = 0;
	صحیح gen_all_hostkeys = 0, gen_krl = 0, update_krl = 0, check_krl = 0;
	صحیح prefer_agent = 0, convert_to = 0, convert_from = 0;
	صحیح print_public = 0, print_generic = 0, cert_serial_autoinc = 0;
	صحیح do_gen_candidates = 0, do_screen_candidates = 0, download_sk = 0;
	unsigned long long cert_serial = 0;
	نویسه *identity_comment = پوچ, *ca_کلید_path = پوچ, **opts = پوچ;
	نویسه *sk_application = پوچ, *sk_device = پوچ, *sk_user = پوچ;
	نویسه *sk_attestation_path = پوچ;
	ساختار sshbuf *challenge = پوچ, *attest = پوچ;
	size_t i, nopts = 0;
	uint32_t bits = 0;
	uint8_t sk_flags = SSH_SK_USER_PRESENCE_REQD;
	ثابت نویسه *errstr, *p;
	صحیح log_level = SYSLOG_LEVEL_INFO;
	نویسه *sign_op = پوچ;

	بیرونی صحیح optind;
	بیرونی نویسه *optarg;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	__progname = ssh_get_progname(argv[0]);

	seed_rng();

	log_init(argv[0], SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_USER, 1);

	msetlocale();

	/* we need this for the home * directory.  */
	pw = getpwuid(getuid());
	اگر (!pw)
		fatal("No user exists for uid %lu", (u_long)getuid());
	pw = pwcopy(pw);
	اگر (gethostname(hostname, اندازه(hostname)) == -1)
		fatal("gethostname: %s", strerror(errno));

	sk_provider = getenv("SSH_SK_PROVIDER");

	/* Remaining characters: dGjJSTWx */
	وقتی ((opt = getopt(argc, argv, "ABHKLQUXceghiklopquvy"
	    "C:D:E:F:I:M:N:O:P:R:V:Y:Z:"
	    "a:b:f:g:m:n:r:s:t:w:z:")) != -1) {
		انتخاب (opt) {
		حالت 'A':
			gen_all_hostkeys = 1;
			بشکن;
		حالت 'b':
			bits = (uint32_t)strtonum(optarg, 1, UINT32_MAX,
			    &errstr);
			اگر (errstr)
				fatal("Bits has bad value %s (%s)",
					optarg, errstr);
			بشکن;
		حالت 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			اگر (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			بشکن;
		حالت 'F':
			find_host = 1;
			rr_hostname = optarg;
			بشکن;
		حالت 'H':
			hash_hosts = 1;
			بشکن;
		حالت 'I':
			cert_کلید_id = optarg;
			بشکن;
		حالت 'R':
			delete_host = 1;
			rr_hostname = optarg;
			بشکن;
		حالت 'L':
			show_cert = 1;
			بشکن;
		حالت 'l':
			print_fingerprint = 1;
			بشکن;
		حالت 'B':
			print_bubblebabble = 1;
			بشکن;
		حالت 'm':
			اگر (strcasecmp(optarg, "RFC4716") == 0 ||
			    strcasecmp(optarg, "ssh2") == 0) {
				convert_format = FMT_RFC4716;
				بشکن;
			}
			اگر (strcasecmp(optarg, "PKCS8") == 0) {
				convert_format = FMT_PKCS8;
				private_کلید_format = SSHKEY_PRIVATE_PKCS8;
				بشکن;
			}
			اگر (strcasecmp(optarg, "PEM") == 0) {
				convert_format = FMT_PEM;
				private_کلید_format = SSHKEY_PRIVATE_PEM;
				بشکن;
			}
			اگر (strcasecmp(optarg, "hexdump") == 0) {
				convert_format = FMT_HEXDUMP;
				بشکن;
			}
			fatal("Unsupported conversion format \"%s\"", optarg);
		حالت 'n':
			cert_principals = optarg;
			بشکن;
		حالت 'o':
			/* no-op; new format is already the default */
			بشکن;
		حالت 'p':
			change_passphrase = 1;
			بشکن;
		حالت 'c':
			change_comment = 1;
			بشکن;
		حالت 'f':
			اگر (strlcpy(identity_file, optarg,
			    اندازه(identity_file)) >= اندازه(identity_file))
				fatal("Identity filename too long");
			have_identity = 1;
			بشکن;
		حالت 'g':
			print_generic = 1;
			بشکن;
		حالت 'K':
			download_sk = 1;
			بشکن;
		حالت 'P':
			identity_passphrase = optarg;
			بشکن;
		حالت 'N':
			identity_new_passphrase = optarg;
			بشکن;
		حالت 'Q':
			check_krl = 1;
			بشکن;
		حالت 'O':
			opts = xrecallocarray(opts, nopts, nopts + 1,
			    اندازه(*opts));
			opts[nopts++] = xstrdup(optarg);
			بشکن;
		حالت 'Z':
			openssh_format_cipher = optarg;
			اگر (cipher_by_name(openssh_format_cipher) == پوچ)
				fatal("Invalid OpenSSH-format cipher '%s'",
				    openssh_format_cipher);
			بشکن;
		حالت 'C':
			identity_comment = optarg;
			بشکن;
		حالت 'q':
			quiet = 1;
			بشکن;
		حالت 'e':
			/* export key */
			convert_to = 1;
			بشکن;
		حالت 'h':
			cert_کلید_type = SSH2_CERT_TYPE_HOST;
			certflags_flags = 0;
			بشکن;
		حالت 'k':
			gen_krl = 1;
			بشکن;
		حالت 'i':
		حالت 'X':
			/* import key */
			convert_from = 1;
			بشکن;
		حالت 'y':
			print_public = 1;
			بشکن;
		حالت 's':
			ca_کلید_path = optarg;
			بشکن;
		حالت 't':
			کلید_type_name = optarg;
			بشکن;
		حالت 'D':
			pkcs11provider = optarg;
			بشکن;
		حالت 'U':
			prefer_agent = 1;
			بشکن;
		حالت 'u':
			update_krl = 1;
			بشکن;
		حالت 'v':
			اگر (log_level == SYSLOG_LEVEL_INFO)
				log_level = SYSLOG_LEVEL_DEBUG1;
			وگرنه {
				اگر (log_level >= SYSLOG_LEVEL_DEBUG1 &&
				    log_level < SYSLOG_LEVEL_DEBUG3)
					log_level++;
			}
			بشکن;
		حالت 'r':
			rr_hostname = optarg;
			بشکن;
		حالت 'a':
			rounds = (صحیح)strtonum(optarg, 1, INT_MAX, &errstr);
			اگر (errstr)
				fatal("Invalid number: %s (%s)",
					optarg, errstr);
			بشکن;
		حالت 'V':
			parse_cert_times(optarg);
			بشکن;
		حالت 'Y':
			sign_op = optarg;
			بشکن;
		حالت 'w':
			sk_provider = optarg;
			بشکن;
		حالت 'z':
			errno = 0;
			اگر (*optarg == '+') {
				cert_serial_autoinc = 1;
				optarg++;
			}
			cert_serial = strtoull(optarg, &ep, 10);
			اگر (*optarg < '0' || *optarg > '9' || *ep != '\0' ||
			    (errno == ERANGE && cert_serial == ULLONG_MAX))
				fatal("Invalid serial number \"%s\"", optarg);
			بشکن;
		حالت 'M':
			اگر (strcmp(optarg, "generate") == 0)
				do_gen_candidates = 1;
			وگرنه اگر (strcmp(optarg, "screen") == 0)
				do_screen_candidates = 1;
			وگرنه
				fatal("Unsupported moduli option %s", optarg);
			بشکن;
		پیشفرض:
			usage();
		}
	}

#ifdef ENABLE_SK_INTERNAL
	اگر (sk_provider == پوچ)
		sk_provider = "internal";
#endif

	/* reinit */
	log_init(argv[0], log_level, SYSLOG_FACILITY_USER, 1);

	argv += optind;
	argc -= optind;

	اگر (sign_op != پوچ) {
		اگر (strprefix(sign_op, "find-principals", 0) != پوچ) {
			اگر (ca_کلید_path == پوچ) {
				error("Too few arguments for find-principals:"
				    "missing signature file");
				exit(1);
			}
			اگر (!have_identity) {
				error("Too few arguments for find-principals:"
				    "missing allowed keys file");
				exit(1);
			}
			ret = sig_find_principals(ca_کلید_path, identity_file,
			    opts, nopts);
			برو done;
		} وگرنه اگر (strprefix(sign_op, "match-principals", 0) != پوچ) {
			اگر (!have_identity) {
				error("Too few arguments for match-principals:"
				    "missing allowed keys file");
				exit(1);
			}
			اگر (cert_کلید_id == پوچ) {
				error("Too few arguments for match-principals: "
				    "missing principal ID");
				exit(1);
			}
			ret = sig_match_principals(identity_file, cert_کلید_id,
			    opts, nopts);
			برو done;
		} وگرنه اگر (strprefix(sign_op, "sign", 0) != پوچ) {
			/* NB. cert_principals is actually namespace, via -n */
			اگر (cert_principals == پوچ ||
			    *cert_principals == '\0') {
				error("Too few arguments for sign: "
				    "missing namespace");
				exit(1);
			}
			اگر (!have_identity) {
				error("Too few arguments for sign: "
				    "missing key");
				exit(1);
			}
			ret = sig_sign(identity_file, cert_principals,
			    prefer_agent, argc, argv, opts, nopts);
			برو done;
		} وگرنه اگر (strprefix(sign_op, "check-novalidate", 0) != پوچ) {
			/* NB. cert_principals is actually namespace, via -n */
			اگر (cert_principals == پوچ ||
			    *cert_principals == '\0') {
				error("Too few arguments for check-novalidate: "
				    "missing namespace");
				exit(1);
			}
			اگر (ca_کلید_path == پوچ) {
				error("Too few arguments for check-novalidate: "
				    "missing signature file");
				exit(1);
			}
			ret = sig_verify(ca_کلید_path, cert_principals,
			    پوچ, پوچ, پوچ, opts, nopts);
			برو done;
		} وگرنه اگر (strprefix(sign_op, "verify", 0) != پوچ) {
			/* NB. cert_principals is actually namespace, via -n */
			اگر (cert_principals == پوچ ||
			    *cert_principals == '\0') {
				error("Too few arguments for verify: "
				    "missing namespace");
				exit(1);
			}
			اگر (ca_کلید_path == پوچ) {
				error("Too few arguments for verify: "
				    "missing signature file");
				exit(1);
			}
			اگر (!have_identity) {
				error("Too few arguments for sign: "
				    "missing allowed keys file");
				exit(1);
			}
			اگر (cert_کلید_id == پوچ) {
				error("Too few arguments for verify: "
				    "missing principal identity");
				exit(1);
			}
			ret = sig_verify(ca_کلید_path, cert_principals,
			    cert_کلید_id, identity_file, rr_hostname,
			    opts, nopts);
			برو done;
		}
		error("Unsupported operation for -Y: \"%s\"", sign_op);
		usage();
		/* NOTREACHED */
	}

	اگر (ca_کلید_path != پوچ) {
		اگر (argc < 1 && !gen_krl) {
			error("Too few arguments.");
			usage();
		}
	} وگرنه اگر (argc > 0 && !gen_krl && !check_krl &&
	    !do_gen_candidates && !do_screen_candidates) {
		error("Too many arguments.");
		usage();
	}
	اگر (change_passphrase && change_comment) {
		error("Can only have one of -p and -c.");
		usage();
	}
	اگر (print_fingerprint && (delete_host || hash_hosts)) {
		error("Cannot use -l with -H or -R.");
		usage();
	}
	اگر (gen_krl) {
		do_gen_krl(pw, update_krl, ca_کلید_path,
		    cert_serial, identity_comment, argc, argv);
		برو done;
	}
	اگر (check_krl) {
		do_check_krl(pw, print_fingerprint, argc, argv);
		برو done;
	}
	اگر (ca_کلید_path != پوچ) {
		اگر (cert_کلید_id == پوچ)
			fatal("Must specify key id (-I) when certifying");
		اگر (cert_principals == پوچ) {
			/*
			 * Ideally this would be a fatal(), but we need to
			 * be able to generate such certificates for testing
			 * even though they will be rejected.
			 */
			error("Warning: certificate will contain no "
			    "principals (-n)");
		}
		برای (i = 0; i < nopts; i++)
			add_cert_option(opts[i]);
		do_ca_sign(pw, ca_کلید_path, prefer_agent,
		    cert_serial, cert_serial_autoinc, argc, argv);
		برو done;
	}
	اگر (show_cert)
		do_show_cert(pw);
	اگر (delete_host || hash_hosts || find_host) {
		do_known_hosts(pw, rr_hostname, find_host,
		    delete_host, hash_hosts);
	}
	اگر (pkcs11provider != پوچ)
		do_download(pw);
	اگر (download_sk) {
		برای (i = 0; i < nopts; i++) {
			اگر ((p = strprefix(opts[i], "device=", 1)) != پوچ) {
				sk_device = xstrdup(p);
			} وگرنه {
				fatal("Option \"%s\" is unsupported for "
				    "FIDO authenticator download", opts[i]);
			}
		}
		ret = do_download_sk(sk_provider, sk_device);
		برو done;
	}
	اگر (print_fingerprint || print_bubblebabble)
		do_fingerprint(pw);
	اگر (change_passphrase)
		do_change_passphrase(pw, opts, nopts);
	اگر (change_comment)
		do_change_comment(pw, identity_comment);
#ifdef WITH_OPENSSL
	اگر (convert_to) {
		do_convert_to(pw);
		برو done;
	}
	اگر (convert_from) {
		do_convert_from(pw);
		برو done;
	}
#وگرنه /* WITH_OPENSSL */
	اگر (convert_to || convert_from)
		fatal("key conversion disabled at compile time");
#endif /* WITH_OPENSSL */
	اگر (print_public)
		do_print_public(pw);
	اگر (rr_hostname != پوچ) {
		unsigned صحیح n = 0;

		اگر (have_identity) {
			n = do_print_resource_record(pw, identity_file,
			    rr_hostname, print_generic, opts, nopts);
			اگر (n == 0)
				fatal("%s: %s", identity_file, strerror(errno));
			exit(0);
		} وگرنه {

			n += do_print_resource_record(pw,
			    PATH_HOST_RSA_کلید_FILE, rr_hostname,
			    print_generic, opts, nopts);
			n += do_print_resource_record(pw,
			    PATH_HOST_ECDSA_کلید_FILE, rr_hostname,
			    print_generic, opts, nopts);
			n += do_print_resource_record(pw,
			    PATH_HOST_ED25519_کلید_FILE, rr_hostname,
			    print_generic, opts, nopts);
			اگر (n == 0)
				fatal("no keys found.");
			exit(0);
		}
	}

	اگر (do_gen_candidates || do_screen_candidates) {
		اگر (argc <= 0)
			fatal("No output file specified");
		وگرنه اگر (argc > 1)
			fatal("Too many output files specified");
	}
	اگر (do_gen_candidates) {
		do_moduli_gen(argv[0], opts, nopts);
		برو done;
	}
	اگر (do_screen_candidates) {
		do_moduli_screen(argv[0], opts, nopts);
		برو done;
	}

	اگر (gen_all_hostkeys) {
		do_gen_all_hostkeys(pw);
		برو done;
	}

	اگر (کلید_type_name == پوچ)
		کلید_type_name = DEFAULT_کلید_TYPE_NAME;

	type = sshkey_type_from_shortname(کلید_type_name);
	type_bits_valid(type, کلید_type_name, &bits);

	اگر (!quiet)
		printf("Generating public/private %s key pair.\n",
		    کلید_type_name);
	انتخاب (type) {
	حالت کلید_ECDSA_SK:
	حالت کلید_ED25519_SK:
		برای (i = 0; i < nopts; i++) {
			اگر (strcasecmp(opts[i], "no-touch-required") == 0) {
				sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
			} وگرنه اگر (strcasecmp(opts[i], "verify-required") == 0) {
				sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
			} وگرنه اگر (strcasecmp(opts[i], "resident") == 0) {
				sk_flags |= SSH_SK_RESIDENT_کلید;
			} وگرنه اگر ((p = strprefix(opts[i], "device=", 1))
			    != پوچ ) {
				sk_device = xstrdup(p);
			} وگرنه اگر ((p = strprefix(opts[i], "user=", 1))
			    != پوچ) {
				sk_user = xstrdup(p);
			} وگرنه اگر ((p = strprefix(opts[i], "challenge=", 1))
			    != پوچ) {
				اگر ((r = sshbuf_load_file(p,
				    &challenge)) != 0) {
					fatal_r(r, "Unable to load FIDO "
					    "enrollment challenge \"%s\"", p);
				}
			} وگرنه اگر (strncasecmp(opts[i],
			    "write-attestation=", 18) == 0) {
				sk_attestation_path = opts[i] + 18;
			} وگرنه اگر (strncasecmp(opts[i],
			    "application=", 12) == 0) {
				sk_application = xstrdup(opts[i] + 12);
				اگر (strncmp(sk_application, "ssh:", 4) != 0) {
					fatal("FIDO application string must "
					    "begin with \"ssh:\"");
				}
			} وگرنه {
				fatal("Option \"%s\" is unsupported for "
				    "FIDO authenticator enrollment", opts[i]);
			}
		}
		اگر ((attest = sshbuf_new()) == پوچ)
			fatal("sshbuf_new failed");
		r = 0;
		برای (i = 0 ;;) {
			اگر (!quiet) {
				printf("You may need to touch your "
				    "authenticator%s to authorize key "
				    "generation.\n",
				    r == 0 ? "" : " again");
			}
			fflush(stdout);
			r = sshsk_enroll(type, sk_provider, sk_device,
			    sk_application == پوچ ? "ssh:" : sk_application,
			    sk_user, sk_flags, passphrase, challenge,
			    &خصوصی, attest);
			اگر (r == 0)
				بشکن;
			اگر (r == SSH_ERR_کلید_BAD_PERMISSIONS &&
			    (sk_flags & SSH_SK_RESIDENT_کلید) != 0 &&
			    (sk_flags & SSH_SK_FORCE_OPERATION) == 0 &&
			    confirm_sk_overwrite(sk_application, sk_user)) {
				sk_flags |= SSH_SK_FORCE_OPERATION;
				ادامه;
			}
			اگر (r != SSH_ERR_کلید_WRONG_PASSPHRASE)
				fatal_r(r, "Key enrollment failed");
			وگرنه اگر (passphrase != پوچ) {
				error("PIN incorrect");
				freezero(passphrase, strlen(passphrase));
				passphrase = پوچ;
			}
			اگر (++i >= 3)
				fatal("Too many incorrect PINs");
			passphrase = read_passphrase("Enter PIN for "
			    "authenticator: ", RP_ALLOW_STDIN);
		}
		اگر (passphrase != پوچ) {
			freezero(passphrase, strlen(passphrase));
			passphrase = پوچ;
		}
		بشکن;
	پیشفرض:
		اگر ((r = sshkey_generate(type, bits, &خصوصی)) != 0)
			fatal("sshkey_generate failed");
		بشکن;
	}
	اگر ((r = sshkey_from_private(خصوصی, &عمومی)) != 0)
		fatal_r(r, "sshkey_from_private");

	اگر (!have_identity)
		ask_filename(pw, "Enter file in which to save the key");

	/* Create ~/.ssh directory if it doesn't already exist. */
	hostfile_create_user_ssh_dir(identity_file, !quiet);

	/* If the file already exists, ask the user to confirm. */
	اگر (!confirm_overwrite(identity_file))
		exit(1);

	/* Determine the passphrase for the private key */
	passphrase = private_کلید_passphrase(identity_file);
	اگر (identity_comment) {
		strlcpy(comment, identity_comment, اندازه(comment));
	} وگرنه {
		/* Create default comment field for the passphrase. */
		snprintf(comment, اندازه comment, "%s@%s", pw->pw_name, hostname);
	}



	/* Save the key with the given passphrase and comment. */
	اگر ((r = sshkey_save_private(خصوصی, identity_file, passphrase,
	    comment, private_کلید_format, openssh_format_cipher, rounds)) != 0) {
		error_r(r, "Saving key \"%s\" failed", identity_file);
		freezero(passphrase, strlen(passphrase));
		exit(1);
	}
	freezero(passphrase, strlen(passphrase));
	sshkey_free(خصوصی);

	اگر (!quiet) {
		printf("Your identification has been saved in %s\n",
		    identity_file);
	}

	strlcat(identity_file, ".pub", اندازه(identity_file));
	اگر ((r = sshkey_save_public(عمومی, identity_file, comment)) != 0)
		fatal_r(r, "Unable to save public key to %s", identity_file);

	اگر (!quiet) {
		fp = sshkey_fingerprint(عمومی, fingerprint_hash,
		    SSH_FP_DEFAULT);
		ra = sshkey_fingerprint(عمومی, fingerprint_hash,
		    SSH_FP_RANDOMART);
		اگر (fp == پوچ || ra == پوچ)
			fatal("sshkey_fingerprint failed");
		printf("Your public key has been saved in %s\n",
		    identity_file);
		printf("The key fingerprint is:\n");
		printf("%s %s\n", fp, comment);
		printf("The key's randomart image is:\n");
		printf("%s\n", ra);
		آزاد(ra);
		آزاد(fp);
	}

	اگر (sk_attestation_path != پوچ)
		save_attestation(attest, sk_attestation_path);

 done:
	sshbuf_free(attest);
	sshkey_free(عمومی);
	pwfree(pw);
	exit(ret);
}
