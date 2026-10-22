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

#اگر_تعریف_شدہ WITH_OPENSSL
#شامل "openbsd-compat/openssl-compat.h"
#شامل <openssl/bn.h>
#شامل <openssl/evp.h>
#شامل <openssl/pem.h>
#اگر_ختم

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

#اگر_تعریف_شدہ ENABLE_PKCS11
#شامل "ssh-pkcs11.h"
#اگر_ختم

#تعریف_کرو DEFAULT_کلید_TYPE_NAME "ed25519"

/*
 * Default number of bits in the RSA and ECDSA keys.  These value can be
 * overridden on the command line.
 *
 * These values provide security equivalent to at least 128 bits of security
 * according to NIST Special Publication 800-57: Recommendation for Key
 * Management Part 1 rev 4 section 5.6.1.
 */
#تعریف_کرو DEFAULT_بٹ		3072
#تعریف_کرو DEFAULT_بٹ_ECDSA	256

#تعریف_کرو کلید_COMMENT_MAX		(NI_MAXHOST + 1024)

ساکن صحیح quiet = 0;

/* Flag indicating that we just want to see the key fingerprint */
ساکن صحیح print_fingerprint = 0;
ساکن صحیح print_bubblebabble = 0;

/* Hash algorithm to use for fingerprints. */
ساکن صحیح fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* The identity file name, given on the command line or entered by the user. */
ساکن حرف شناختی_عنصر_file[PATH_MAX];
ساکن صحیح have_شناختی_عنصر = 0;

/* This is set to the passphrase if given on the command line. */
ساکن حرف *شناختی_عنصر_passphrase = تہی;

/* This is set to the new passphrase if given on the command line. */
ساکن حرف *شناختی_عنصر_new_passphrase = تہی;

/* Key type when certifying */
ساکن u_int cert_کلید_type = SSH2_CERT_TYPE_USER;

/* "key ID" of signed key */
ساکن حرف *cert_کلید_id = تہی;

/* Comma-separated list of principal names for certifying keys */
ساکن حرف *cert_principals = تہی;

/* Validity period for certificates */
ساکن uint64_t cert_valid_from = 0;
ساکن uint64_t cert_valid_مقصد = ~0ULL;

/* Certificate options */
#تعریف_کرو CERTOPT_X_FWD				(1)
#تعریف_کرو CERTOPT_AGENT_FWD			(1<<1)
#تعریف_کرو CERTOPT_پورٹ_FWD			(1<<2)
#تعریف_کرو CERTOPT_PTY				(1<<3)
#تعریف_کرو CERTOPT_USER_RC				(1<<4)
#تعریف_کرو CERTOPT_NO_REQUIRE_USER_PRESENCE	(1<<5)
#تعریف_کرو CERTOPT_REQUIRE_VERIFY			(1<<6)
#تعریف_کرو CERTOPT_DEFAULT	(CERTOPT_X_FWD|CERTOPT_AGENT_FWD| \
			 CERTOPT_پورٹ_FWD|CERTOPT_PTY|CERTOPT_USER_RC)
ساکن uint32_t certflags_flags = CERTOPT_DEFAULT;
ساکن حرف *certflags_command = تہی;
ساکن حرف *certflags_src_addr = تہی;

/* Arbitrary extensions specified by user */
ساخت cert_ext {
	حرف *کلید;
	حرف *val;
	صحیح crit;
};
ساکن ساخت cert_ext *cert_ext;
ساکن سائز_t ncert_ext;

/* Conversion to/from various formats */
شمار {
	FMT_RFC4716,
	FMT_PKCS8,
	FMT_PEM,
	FMT_HEXDUMP
} convert_format = FMT_RFC4716;

ساکن حرف *کلید_type_name = تہی;

/* Load key from this PKCS#11 provider */
ساکن حرف *pkcs11provider = تہی;

/* FIDO/U2F provider to use */
ساکن حرف *sk_provider = تہی;

/* Format for writing private keys */
ساکن صحیح نجی_کلید_format = SSHKEY_نجی_OPENSSH;

/* Cipher for new-format private keys */
ساکن حرف *openssh_format_cipher = تہی;

/* Number of KDF rounds to derive new format keys. */
ساکن صحیح دور = 0;

/* argv0 */
خارجی حرف *__progname;

ساکن حرف hostname[NI_MAXHOST];

#اگر_تعریف_شدہ WITH_OPENSSL
/* moduli.c */
صحیح gen_candidates(FILE *, uint32_t, BIGNUM *);
صحیح مفرد_test(FILE *, FILE *, uint32_t, uint32_t, حرف *, غیرعلامتی طویل,
    غیرعلامتی طویل);
#اگر_ختم

ساکن خالی
type_بٹ_valid(صحیح type, ثابت حرف *name, uint32_t *bitsp)
{
	اگر (type == کلید_UNSPEC)
		fatal("unknown key type %s", کلید_type_name);
	اگر (*bitsp == 0) {
#اگر_تعریف_شدہ WITH_OPENSSL
		صحیح nid;

		انتخاب(type) {
		حالت کلید_ECDSA:
			اگر (name != تہی &&
			    (nid = sshkey_ecdsa_nid_from_name(name)) > 0)
				*bitsp = sshkey_خم_nid_مقصد_بٹ(nid);
			اگر (*bitsp == 0)
				*bitsp = DEFAULT_بٹ_ECDSA;
			توڑو;
		حالت کلید_RSA:
			*bitsp = DEFAULT_بٹ;
			توڑو;
		}
#اگر_ختم
	}
#اگر_تعریف_شدہ WITH_OPENSSL
	انتخاب (type) {
	حالت کلید_RSA:
		اگر (*bitsp < SSH_RSA_MINIMUM_MODULUS_سائز)
			fatal("Invalid RSA key length: minimum is %d bits",
			    SSH_RSA_MINIMUM_MODULUS_سائز);
		ورنہ اگر (*bitsp > OPENSSL_RSA_MAX_MODULUS_بٹ)
			fatal("Invalid RSA key length: maximum is %d bits",
			    OPENSSL_RSA_MAX_MODULUS_بٹ);
		توڑو;
	حالت کلید_ECDSA:
		اگر (sshkey_ecdsa_بٹ_مقصد_nid(*bitsp) == -1)
			fatal("Invalid ECDSA key length: valid lengths are "
			    "256, 384 or 521 bits");
	}
#اگر_ختم
}

/*
 * Checks whether a file exists and, if so, asks the user whether they wish
 * to overwrite it.
 * Returns nonzero if the file does not already exist or if the user agrees to
 * overwrite, or zero otherwise.
 */
ساکن صحیح
confirm_overwrite(ثابت حرف *filename)
{
	حرف yesno[3];
	ساخت stat st;

	اگر (stat(filename, &st) != 0)
		واپس 1;
	لکھو("%s already exists.\n", filename);
	لکھو("Overwrite (y/n)? ");
	fflush(stdout);
	اگر (fgets(yesno, حجم(yesno), stdin) == تہی)
		واپس 0;
	اگر (yesno[0] != 'y' && yesno[0] != 'Y')
		واپس 0;
	واپس 1;
}

ساکن خالی
ask_filename(ساخت passwd *pw, ثابت حرف *prompt)
{
	حرف buf[1024];
	حرف *name = تہی;

	اگر (کلید_type_name == تہی)
		name = راستہ_SSH_CLIENT_ID_ED25519;
	ورنہ {
		انتخاب (sshkey_type_from_shortname(کلید_type_name)) {
		حالت کلید_ECDSA_CERT:
		حالت کلید_ECDSA:
			name = راستہ_SSH_CLIENT_ID_ECDSA;
			توڑو;
		حالت کلید_ECDSA_SK_CERT:
		حالت کلید_ECDSA_SK:
			name = راستہ_SSH_CLIENT_ID_ECDSA_SK;
			توڑو;
		حالت کلید_RSA_CERT:
		حالت کلید_RSA:
			name = راستہ_SSH_CLIENT_ID_RSA;
			توڑو;
		حالت کلید_ED25519:
		حالت کلید_ED25519_CERT:
			name = راستہ_SSH_CLIENT_ID_ED25519;
			توڑو;
		حالت کلید_ED25519_SK:
		حالت کلید_ED25519_SK_CERT:
			name = راستہ_SSH_CLIENT_ID_ED25519_SK;
			توڑو;
		حالت کلید_MLDSA44_ED25519:
		حالت کلید_MLDSA44_ED25519_CERT:
			name = راستہ_SSH_CLIENT_ID_MLDSA44_ED25519;
			توڑو;
		طےشدہ:
			fatal("bad key type");
		}
	}
	snprintf(شناختی_عنصر_file, حجم(شناختی_عنصر_file),
	    "%s/%s", pw->pw_dir, name);
	لکھو("%s (%s): ", prompt, شناختی_عنصر_file);
	fflush(stdout);
	اگر (fgets(buf, حجم(buf), stdin) == تہی)
		باہر_نکلو(1);
	buf[strcspn(buf, "\n")] = '\0';
	اگر (strcmp(buf, "") != 0)
		strlcpy(شناختی_عنصر_file, buf, حجم(شناختی_عنصر_file));
	have_شناختی_عنصر = 1;
}

ساکن ساخت sshkey *
بھرو_شناختی_عنصر(ثابت حرف *filename, حرف **commentp)
{
	حرف *prompt, *pass;
	ساخت sshkey *prv;
	صحیح r;

	اگر (commentp != تہی)
		*commentp = تہی;
	اگر ((r = sshkey_بھرو_نجی(filename, "", &prv, commentp)) == 0)
		واپس prv;
	اگر (r != SSH_ERR_کلید_WRONG_PASSPHRASE)
		fatal_r(r, "Load key \"%s\"", filename);
	اگر (شناختی_عنصر_passphrase)
		pass = xstrdup(شناختی_عنصر_passphrase);
	ورنہ {
		xasprintf(&prompt, "Enter passphrase for \"%s\": ", filename);
		pass = read_passphrase(prompt, RP_ALLOW_STDIN);
		آزاد(prompt);
	}
	r = sshkey_بھرو_نجی(filename, pass, &prv, commentp);
	freezero(pass, لڑی_لمبائی(pass));
	اگر (r != 0)
		fatal_r(r, "Load key \"%s\"", filename);
	واپس prv;
}

#تعریف_کرو SSH_COM_عوامی_BEGIN		"---- BEGIN SSH2 PUBLIC KEY ----"
#تعریف_کرو SSH_COM_عوامی_انتہا		"---- END SSH2 PUBLIC KEY ----"
#تعریف_کرو SSH_COM_نجی_BEGIN		"---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----"
#تعریف_کرو	SSH_COM_نجی_کلید_MAGIC	0x3f6ff9eb

#اگر_تعریف_شدہ WITH_OPENSSL
ساکن خالی
do_convert_مقصد_ssh2(ساخت passwd *pw, ساخت sshkey *k)
{
	ساخت sshbuf *b;
	حرف comment[61], *b64;
	صحیح r;

	اگر ((b = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshkey_putb(k, b)) != 0)
		fatal_fr(r, "put key");
	اگر ((b64 = sshbuf_dtob64_string(b, 1)) == تہی)
		fatal_f("sshbuf_dtob64_string failed");

	/* Comment + surrounds must fit into 72 chars (RFC 4716 sec 3.3) */
	snprintf(comment, حجم(comment),
	    "%u-bit %s, converted by %s@%s from OpenSSH",
	    sshkey_سائز(k), sshkey_type(k),
	    pw->pw_name, hostname);

	sshkey_free(k);
	sshbuf_free(b);

	fprintf(stdout, "%s\n", SSH_COM_عوامی_BEGIN);
	fprintf(stdout, "Comment: \"%s\"\n%s", comment, b64);
	fprintf(stdout, "%s\n", SSH_COM_عوامی_انتہا);
	آزاد(b64);
}

ساکن خالی
do_convert_مقصد_pkcs8(ساخت sshkey *k)
{
	انتخاب (sshkey_type_plain(k->type)) {
	حالت کلید_RSA:
		اگر (!PEM_write_RSA_PUBKEY(stdout,
		    EVP_PKEY_get0_RSA(k->pkey)))
			fatal("PEM_write_RSA_PUBKEY failed");
		توڑو;
	حالت کلید_ECDSA:
		اگر (!PEM_write_EC_PUBKEY(stdout,
		    EVP_PKEY_get0_EC_کلید(k->pkey)))
			fatal("PEM_write_EC_PUBKEY failed");
		توڑو;
	طےشدہ:
		fatal_f("unsupported key type %s", sshkey_type(k));
	}
}

ساکن خالی
do_convert_مقصد_pem(ساخت sshkey *k)
{
	انتخاب (sshkey_type_plain(k->type)) {
	حالت کلید_RSA:
		اگر (!PEM_write_RSAPublic_کلید(stdout,
		    EVP_PKEY_get0_RSA(k->pkey)))
			fatal("PEM_write_RSAPublicKey failed");
		توڑو;
	حالت کلید_ECDSA:
		اگر (!PEM_write_EC_PUBKEY(stdout,
		    EVP_PKEY_get0_EC_کلید(k->pkey)))
			fatal("PEM_write_EC_PUBKEY failed");
		توڑو;
	طےشدہ:
		fatal_f("unsupported key type %s", sshkey_type(k));
	}
}

ساکن خالی
do_convert_مقصد_hexdump(ساخت sshkey *k)
{
	ساخت sshbuf *b;
	صحیح r;

	اگر ((b = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	/* pubkey */
	اگر ((r = sshkey_putb(k, b)) != 0)
		fatal_fr(r, "serialise private");
	لکھو("Public %s key:\n", sshkey_type(k));
	sshbuf_dump(b, stdout);
	sshbuf_reset(b);
	اگر ((r = sshkey_نجی_serialize(k, b)) != 0) {
		debug_fr(r, "serialise private");
		جاؤ برآمد;
	}
	لکھو("\nPrivate %s key:\n", sshkey_type(k));
	sshbuf_dump(b, stdout);
 برآمد:
	sshbuf_free(b);
}

ساکن خالی
do_convert_مقصد(ساخت passwd *pw)
{
	ساخت sshkey *k = تہی;
	ساخت stat st;
	صحیح r;

	اگر (!have_شناختی_عنصر)
		ask_filename(pw, "Enter file in which the key is");
	اگر (stat(شناختی_عنصر_file, &st) == -1)
		fatal("%s: %s: %s", __progname, شناختی_عنصر_file, strerror(errno));

	/* If we're trying to hexdump, then prefer the private key */
	اگر (convert_format == FMT_HEXDUMP) {
		اگر ((r = sshkey_بھرو_نجی(شناختی_عنصر_file,
		    تہی, &k, تہی)) != 0 &&
		    r == SSH_ERR_کلید_WRONG_PASSPHRASE)
			k = بھرو_شناختی_عنصر(شناختی_عنصر_file, تہی);
	}
	اگر (k == تہی && (r = sshkey_بھرو_عوامی(شناختی_عنصر_file, &k, تہی)) != 0)
		k = بھرو_شناختی_عنصر(شناختی_عنصر_file, تہی);

	انتخاب (convert_format) {
	حالت FMT_RFC4716:
		do_convert_مقصد_ssh2(pw, k);
		توڑو;
	حالت FMT_PKCS8:
		do_convert_مقصد_pkcs8(k);
		توڑو;
	حالت FMT_PEM:
		do_convert_مقصد_pem(k);
		توڑو;
	حالت FMT_HEXDUMP:
		do_convert_مقصد_hexdump(k);
		توڑو;
	طےشدہ:
		fatal_f("unknown key format %d", convert_format);
	}
}

/*
 * This is almost exactly the bignum1 encoding, but with 32 bit for length
 * instead of 16.
 */
ساکن خالی
بفر_get_bignum_بٹ(ساخت sshbuf *b, BIGNUM *قدر)
{
	u_int بائٹیں, bignum_بٹ;
	صحیح r;

	اگر ((r = sshbuf_get_u32(b, &bignum_بٹ)) != 0)
		fatal_fr(r, "parse");
	بائٹیں = (bignum_بٹ + 7) / 8;
	اگر (sshbuf_len(b) < بائٹیں)
		fatal_f("input buffer too small: need %d have %zu",
		    بائٹیں, sshbuf_len(b));
	اگر (BN_bin2bn(sshbuf_ptr(b), بائٹیں, قدر) == تہی)
		fatal_f("BN_bin2bn failed");
	اگر ((r = sshbuf_consume(b, بائٹیں)) != 0)
		fatal_fr(r, "consume");
}

ساکن ساخت sshkey *
do_convert_نجی_ssh2(ساخت sshbuf *b)
{
	ساخت sshkey *کلید = تہی;
	حرف *type, *cipher;
	ثابت حرف *alg = تہی;
	u_char e1, e2, e3, *sig = تہی, ڈیٹا[] = "abcde12345";
	صحیح r, rlen, ktype;
	u_int magic, i1, i2, i3, i4;
	سائز_t slen;
	u_long e;
	BIGNUM *rsa_n = تہی, *rsa_e = تہی, *rsa_d = تہی;
	BIGNUM *rsa_p = تہی, *rsa_q = تہی, *rsa_iqmp = تہی;
	BIGNUM *rsa_dmp1 = تہی, *rsa_dmq1 = تہی;
	RSA *rsa = تہی;

	اگر ((r = sshbuf_get_u32(b, &magic)) != 0)
		fatal_fr(r, "parse magic");

	اگر (magic != SSH_COM_نجی_کلید_MAGIC) {
		error("bad magic 0x%x != 0x%x", magic,
		    SSH_COM_نجی_کلید_MAGIC);
		واپس تہی;
	}
	اگر ((r = sshbuf_get_u32(b, &i1)) != 0 ||
	    (r = sshbuf_get_cstring(b, &type, تہی)) != 0 ||
	    (r = sshbuf_get_cstring(b, &cipher, تہی)) != 0 ||
	    (r = sshbuf_get_u32(b, &i2)) != 0 ||
	    (r = sshbuf_get_u32(b, &i3)) != 0 ||
	    (r = sshbuf_get_u32(b, &i4)) != 0)
		fatal_fr(r, "parse");
	debug("ignore (%d %d %d %d)", i1, i2, i3, i4);
	اگر (strcmp(cipher, "none") != 0) {
		error("unsupported cipher %s", cipher);
		آزاد(cipher);
		آزاد(type);
		واپس تہی;
	}
	آزاد(cipher);

	اگر (لڑی_تلاش(type, "rsa")) {
		ktype = کلید_RSA;
	} ورنہ {
		آزاد(type);
		واپس تہی;
	}
	اگر ((کلید = sshkey_new(ktype)) == تہی)
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
		اگر ((rsa_e = BN_new()) == تہی)
			fatal_f("BN_new");
		اگر (!BN_سیٹ_لفظ(rsa_e, e)) {
			BN_clear_free(rsa_e);
			sshkey_free(کلید);
			واپس تہی;
		}
		اگر ((rsa_n = BN_new()) == تہی ||
		    (rsa_d = BN_new()) == تہی ||
		    (rsa_p = BN_new()) == تہی ||
		    (rsa_q = BN_new()) == تہی ||
		    (rsa_iqmp = BN_new()) == تہی)
			fatal_f("BN_new");
		بفر_get_bignum_بٹ(b, rsa_d);
		بفر_get_bignum_بٹ(b, rsa_n);
		بفر_get_bignum_بٹ(b, rsa_iqmp);
		بفر_get_bignum_بٹ(b, rsa_q);
		بفر_get_bignum_بٹ(b, rsa_p);
		اگر ((r = ssh_rsa_complete_crt_parameters(rsa_d, rsa_p, rsa_q,
		    rsa_iqmp, &rsa_dmp1, &rsa_dmq1)) != 0)
			fatal_fr(r, "generate RSA CRT parameters");
		EVP_PKEY_free(کلید->pkey);
		اگر ((کلید->pkey = EVP_PKEY_new()) == تہی)
			fatal_f("EVP_PKEY_new failed");
		اگر ((rsa = RSA_new()) == تہی)
			fatal_f("RSA_new failed");
		اگر (!RSA_set0_کلید(rsa, rsa_n, rsa_e, rsa_d))
			fatal_f("RSA_set0_key failed");
		rsa_n = rsa_e = rsa_d = تہی; /* transferred */
		اگر (!RSA_set0_factors(rsa, rsa_p, rsa_q))
			fatal_f("RSA_set0_factors failed");
		rsa_p = rsa_q = تہی; /* transferred */
		اگر (RSA_set0_crt_params(rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp) != 1)
			fatal_f("RSA_set0_crt_params failed");
		rsa_dmp1 = rsa_dmq1 = rsa_iqmp = تہی;
		اگر (EVP_PKEY_set1_RSA(کلید->pkey, rsa) != 1)
			fatal_f("EVP_PKEY_set1_RSA failed");
		RSA_free(rsa);
		alg = "rsa-sha2-256";
		توڑو;
	}
	rlen = sshbuf_len(b);
	اگر (rlen != 0)
		error_f("remaining bytes in key blob %d", rlen);

	/* try the key */
	اگر ((r = sshkey_sign(کلید, &sig, &slen, ڈیٹا, حجم(ڈیٹا),
	    alg, تہی, تہی, 0)) != 0)
		error_fr(r, "signing with converted key failed");
	ورنہ اگر ((r = sshkey_verify(کلید, sig, slen, ڈیٹا, حجم(ڈیٹا),
	    alg, 0, تہی)) != 0)
		error_fr(r, "verification with converted key failed");
	اگر (r != 0) {
		sshkey_free(کلید);
		آزاد(sig);
		واپس تہی;
	}
	آزاد(sig);
	واپس کلید;
}

ساکن صحیح
get_سطر(FILE *fp, حرف *سطر, سائز_t len)
{
	صحیح c;
	سائز_t pos = 0;

	سطر[0] = '\0';
	جب ((c = fgetc(fp)) != EOF) {
		اگر (pos >= len - 1)
			fatal("input line too long.");
		انتخاب (c) {
		حالت '\r':
			c = fgetc(fp);
			اگر (c != EOF && c != '\n' && ungetc(c, fp) == EOF)
				fatal("unget: %s", strerror(errno));
			واپس pos;
		حالت '\n':
			واپس pos;
		}
		سطر[pos++] = c;
		سطر[pos] = '\0';
	}
	/* We reached EOF */
	واپس -1;
}

ساکن خالی
do_convert_from_ssh2(ساخت passwd *pw, ساخت sshkey **k, صحیح *نجی)
{
	صحیح r, blen, escaped = 0;
	u_int len;
	حرف سطر[1024];
	ساخت sshbuf *buf;
	حرف encoded[8096];
	FILE *fp;

	اگر ((buf = sshbuf_new()) == تہی)
		fatal("sshbuf_new failed");
	اگر ((fp = fopen(شناختی_عنصر_file, "r")) == تہی)
		fatal("%s: %s: %s", __progname, شناختی_عنصر_file, strerror(errno));
	encoded[0] = '\0';
	جب ((blen = get_سطر(fp, سطر, حجم(سطر))) != -1) {
		اگر (blen > 0 && سطر[blen - 1] == '\\')
			escaped++;
		اگر (لڑی_موازنہ(سطر, "----", 4) == 0 ||
		    لڑی_تلاش(سطر, ": ") != تہی) {
			اگر (لڑی_تلاش(سطر, SSH_COM_نجی_BEGIN) != تہی)
				*نجی = 1;
			اگر (لڑی_تلاش(سطر, " END ") != تہی) {
				توڑو;
			}
			/* fprintf(stderr, "ignore: %s", line); */
			جاری;
		}
		اگر (escaped) {
			escaped--;
			/* fprintf(stderr, "escaped: %s", line); */
			جاری;
		}
		strlcat(encoded, سطر, حجم(encoded));
	}
	len = لڑی_لمبائی(encoded);
	اگر (((len % 4) == 3) &&
	    (encoded[len-1] == '=') &&
	    (encoded[len-2] == '=') &&
	    (encoded[len-3] == '='))
		encoded[len-3] = '\0';
	اگر ((r = sshbuf_b64tod(buf, encoded)) != 0)
		fatal_fr(r, "base64 decode");
	اگر (*نجی) {
		اگر ((*k = do_convert_نجی_ssh2(buf)) == تہی)
			fatal_f("private key conversion failed");
	} ورنہ اگر ((r = sshkey_fromb(buf, k)) != 0)
		fatal_fr(r, "parse key");
	sshbuf_free(buf);
	fclose(fp);
}

ساکن خالی
do_convert_from_pkcs8(ساخت sshkey **k, صحیح *نجی)
{
	EVP_PKEY *pubkey;
	FILE *fp;

	اگر ((fp = fopen(شناختی_عنصر_file, "r")) == تہی)
		fatal("%s: %s: %s", __progname, شناختی_عنصر_file, strerror(errno));
	اگر ((pubkey = PEM_read_PUBKEY(fp, تہی, تہی, تہی)) == تہی) {
		fatal_f("%s is not a recognised public key format",
		    شناختی_عنصر_file);
	}
	fclose(fp);
	انتخاب (EVP_PKEY_بنیاد_id(pubkey)) {
	حالت EVP_PKEY_RSA:
		اگر ((*k = sshkey_new(کلید_UNSPEC)) == تہی)
			fatal("sshkey_new failed");
		(*k)->type = کلید_RSA;
		(*k)->pkey = pubkey;
		pubkey = تہی;
		توڑو;
	حالت EVP_PKEY_EC:
		اگر ((*k = sshkey_new(کلید_UNSPEC)) == تہی)
			fatal("sshkey_new failed");
		اگر (((*k)->ecdsa_nid = sshkey_ecdsa_fixup_گروہ(pubkey)) == -1)
			fatal("sshkey_ecdsa_fixup_group failed");
		(*k)->type = کلید_ECDSA;
		(*k)->pkey = pubkey;
		pubkey = تہی;
		توڑو;
	طےشدہ:
		fatal_f("unsupported pubkey type %d",
		    EVP_PKEY_بنیاد_id(pubkey));
	}
	EVP_PKEY_free(pubkey);
}

ساکن خالی
do_convert_from_pem(ساخت sshkey **k, صحیح *نجی)
{
	FILE *fp;
	RSA *rsa;

	اگر ((fp = fopen(شناختی_عنصر_file, "r")) == تہی)
		fatal("%s: %s: %s", __progname, شناختی_عنصر_file, strerror(errno));
	اگر ((rsa = PEM_read_RSAPublic_کلید(fp, تہی, تہی, تہی)) != تہی) {
		اگر ((*k = sshkey_new(کلید_UNSPEC)) == تہی)
			fatal("sshkey_new failed");
		اگر (((*k)->pkey = EVP_PKEY_new()) == تہی)
			fatal("EVP_PKEY_new failed");
		(*k)->type = کلید_RSA;
		اگر (EVP_PKEY_set1_RSA((*k)->pkey, rsa) != 1)
			fatal("EVP_PKEY_set1_RSA failed");
		RSA_free(rsa);
		fclose(fp);
		واپس;
	}
	fatal_f("unrecognised raw private key format");
}

ساکن خالی
do_convert_from(ساخت passwd *pw)
{
	ساخت sshkey *k = تہی;
	صحیح r, نجی = 0, ok = 0;
	ساخت stat st;

	اگر (!have_شناختی_عنصر)
		ask_filename(pw, "Enter file in which the key is");
	اگر (stat(شناختی_عنصر_file, &st) == -1)
		fatal("%s: %s: %s", __progname, شناختی_عنصر_file, strerror(errno));

	انتخاب (convert_format) {
	حالت FMT_RFC4716:
		do_convert_from_ssh2(pw, &k, &نجی);
		توڑو;
	حالت FMT_PKCS8:
		do_convert_from_pkcs8(&k, &نجی);
		توڑو;
	حالت FMT_PEM:
		do_convert_from_pem(&k, &نجی);
		توڑو;
	طےشدہ:
		fatal_f("unknown key format %d", convert_format);
	}

	اگر (!نجی) {
		اگر ((r = sshkey_write(k, stdout)) == 0)
			ok = 1;
		اگر (ok)
			fprintf(stdout, "\n");
	} ورنہ {
		انتخاب (k->type) {
		حالت کلید_ECDSA:
			ok = PEM_write_ECPrivate_کلید(stdout,
			    EVP_PKEY_get0_EC_کلید(k->pkey), تہی, تہی, 0,
			    تہی, تہی);
			توڑو;
		حالت کلید_RSA:
			ok = PEM_write_RSAPrivate_کلید(stdout,
			    EVP_PKEY_get0_RSA(k->pkey), تہی, تہی, 0,
			    تہی, تہی);
			توڑو;
		طےشدہ:
			fatal_f("unsupported key type %s", sshkey_type(k));
		}
	}

	اگر (!ok)
		fatal("key write failed");
	sshkey_free(k);
}
#اگر_ختم

ساکن خالی
do_print_عوامی(ساخت passwd *pw)
{
	ساخت sshkey *prv;
	ساخت stat st;
	صحیح r;
	حرف *comment = تہی;

	اگر (!have_شناختی_عنصر)
		ask_filename(pw, "Enter file in which the key is");
	اگر (stat(شناختی_عنصر_file, &st) == -1)
		fatal("%s: %s", شناختی_عنصر_file, strerror(errno));
	prv = بھرو_شناختی_عنصر(شناختی_عنصر_file, &comment);
	اگر ((r = sshkey_write(prv, stdout)) != 0)
		fatal_fr(r, "write key");
	اگر (comment != تہی && *comment != '\0')
		fprintf(stdout, " %s", comment);
	fprintf(stdout, "\n");
	اگر (sshkey_is_sk(prv)) {
		debug("sk_application: \"%s\", sk_flags 0x%02x",
			prv->sk_application, prv->sk_flags);
	}
	sshkey_free(prv);
	آزاد(comment);
	باہر_نکلو(0);
}

ساکن خالی
do_download(ساخت passwd *pw)
{
#اگر_تعریف_شدہ ENABLE_PKCS11
	ساخت sshkey **کلیدیں = تہی;
	صحیح i, nkeys;
	شمار sshkey_fp_rep rep;
	صحیح fptype;
	حرف *fp, *ra, **comments = تہی;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;

	pkcs11_init(1);
	nkeys = pkcs11_جوڑو_provider(pkcs11provider, تہی, &کلیدیں, &comments);
	اگر (nkeys <= 0)
		fatal("cannot read public key from pkcs11");
	برائے (i = 0; i < nkeys; i++) {
		اگر (print_fingerprint) {
			fp = sshkey_fingerprint(کلیدیں[i], fptype, rep);
			ra = sshkey_fingerprint(کلیدیں[i], fingerprint_hash,
			    SSH_FP_RANDOMART);
			اگر (fp == تہی || ra == تہی)
				fatal_f("sshkey_fingerprint fail");
			لکھو("%u %s %s (PKCS11 key)\n", sshkey_سائز(کلیدیں[i]),
			    fp, sshkey_type(کلیدیں[i]));
			اگر (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
				لکھو("%s\n", ra);
			آزاد(ra);
			آزاد(fp);
		} ورنہ {
			(خالی) sshkey_write(کلیدیں[i], stdout); /* XXX check */
			fprintf(stdout, "%s%s\n",
			    *(comments[i]) == '\0' ? "" : " ", comments[i]);
		}
		آزاد(comments[i]);
		sshkey_free(کلیدیں[i]);
	}
	آزاد(comments);
	آزاد(کلیدیں);
	pkcs11_terminate();
	باہر_نکلو(0);
#ورنہ
	fatal("no pkcs11 support");
#اگر_ختم /* ENABLE_PKCS11 */
}

ساکن ساخت sshkey *
try_read_کلید(حرف **cpp)
{
	ساخت sshkey *ret;
	صحیح r;

	اگر ((ret = sshkey_new(کلید_UNSPEC)) == تہی)
		fatal("sshkey_new failed");
	اگر ((r = sshkey_read(ret, cpp)) == 0)
		واپس ret;
	/* Not a key */
	sshkey_free(ret);
	واپس تہی;
}

ساکن خالی
fingerprint_one_کلید(ثابت ساخت sshkey *عوامی, ثابت حرف *comment)
{
	حرف *fp = تہی, *ra = تہی;
	شمار sshkey_fp_rep rep;
	صحیح fptype;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;
	fp = sshkey_fingerprint(عوامی, fptype, rep);
	ra = sshkey_fingerprint(عوامی, fingerprint_hash, SSH_FP_RANDOMART);
	اگر (fp == تہی || ra == تہی)
		fatal_f("sshkey_fingerprint failed");
	mprintf("%u %s %s (%s)\n", sshkey_سائز(عوامی), fp,
	    comment ? comment : "no comment", sshkey_type(عوامی));
	اگر (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
		لکھو("%s\n", ra);
	آزاد(ra);
	آزاد(fp);
}

ساکن خالی
fingerprint_نجی(ثابت حرف *راستہ)
{
	ساخت stat st;
	حرف *comment = تہی;
	ساخت sshkey *privkey = تہی, *pubkey = تہی;
	صحیح r;

	اگر (stat(شناختی_عنصر_file, &st) == -1)
		fatal("%s: %s", راستہ, strerror(errno));
	اگر ((r = sshkey_بھرو_عوامی(راستہ, &pubkey, &comment)) != 0)
		debug_r(r, "load public \"%s\"", راستہ);
	اگر (pubkey == تہی || comment == تہی || *comment == '\0') {
		آزاد(comment);
		اگر ((r = sshkey_بھرو_نجی(راستہ, تہی,
		    &privkey, &comment)) != 0)
			debug_r(r, "load private \"%s\"", راستہ);
	}
	اگر (pubkey == تہی && privkey == تہی)
		fatal("%s is not a key file.", راستہ);

	fingerprint_one_کلید(pubkey == تہی ? privkey : pubkey, comment);
	sshkey_free(pubkey);
	sshkey_free(privkey);
	آزاد(comment);
}

ساکن خالی
do_fingerprint(ساخت passwd *pw)
{
	FILE *f;
	ساخت sshkey *عوامی = تہی;
	حرف *comment = تہی, *cp, *ep, *سطر = تہی;
	سائز_t linesize = 0;
	صحیح i, invalid = 1;
	ثابت حرف *راستہ;
	u_long lnum = 0;

	اگر (!have_شناختی_عنصر)
		ask_filename(pw, "Enter file in which the key is");
	راستہ = شناختی_عنصر_file;

	اگر (strcmp(شناختی_عنصر_file, "-") == 0) {
		f = stdin;
		راستہ = "(stdin)";
	} ورنہ اگر ((f = fopen(راستہ, "r")) == تہی)
		fatal("%s: %s: %s", __progname, راستہ, strerror(errno));

	جب (getline(&سطر, &linesize, f) != -1) {
		lnum++;
		cp = سطر;
		cp[strcspn(cp, "\r\n")] = '\0';
		/* Trim leading space and comments */
		cp = سطر + strspn(سطر, " \t");
		اگر (*cp == '#' || *cp == '\0')
			جاری;

		/*
		 * Input may be plain keys, private keys, authorized_keys
		 * or known_hosts.
		 */

		/*
		 * Try private keys first. Assume a key is private if
		 * "SSH PRIVATE KEY" appears on the first line and we're
		 * not reading from stdin (XXX support private keys on stdin).
		 */
		اگر (lnum == 1 && strcmp(شناختی_عنصر_file, "-") != 0 &&
		    لڑی_تلاش(cp, "PRIVATE KEY") != تہی) {
			آزاد(سطر);
			fclose(f);
			fingerprint_نجی(راستہ);
			باہر_نکلو(0);
		}

		/*
		 * If it's not a private key, then this must be prepared to
		 * accept a public key prefixed with a hostname or options.
		 * Try a bare key first, otherwise skip the leading stuff.
		 */
		comment = تہی;
		اگر ((عوامی = try_read_کلید(&cp)) == تہی) {
			i = strtol(cp, &ep, 10);
			اگر (i == 0 || ep == تہی ||
			    (*ep != ' ' && *ep != '\t')) {
				صحیح quoted = 0;

				comment = cp;
				برائے (; *cp && (quoted || (*cp != ' ' &&
				    *cp != '\t')); cp++) {
					اگر (*cp == '\\' && cp[1] == '"')
						cp++;	/* Skip both */
					ورنہ اگر (*cp == '"')
						quoted = !quoted;
				}
				اگر (!*cp)
					جاری;
				*cp++ = '\0';
			}
		}
		/* Retry after parsing leading hostname/key options */
		اگر (عوامی == تہی && (عوامی = try_read_کلید(&cp)) == تہی) {
			debug("%s:%lu: not a public key", راستہ, lnum);
			جاری;
		}

		/* Find trailing comment, if any */
		برائے (; *cp == ' ' || *cp == '\t'; cp++)
			;
		اگر (*cp != '\0' && *cp != '#')
			comment = cp;

		fingerprint_one_کلید(عوامی, comment);
		sshkey_free(عوامی);
		invalid = 0; /* One good key in the file is sufficient */
	}
	fclose(f);
	آزاد(سطر);

	اگر (invalid)
		fatal("%s is not a public key file.", راستہ);
	باہر_نکلو(0);
}

ساکن خالی
do_gen_all_hostkeys(ساخت passwd *pw)
{
	ساخت {
		حرف *کلید_type;
		حرف *کلید_type_display;
		حرف *راستہ;
	} کلید_types[] = {
#اگر_تعریف_شدہ WITH_OPENSSL
		{ "rsa", "RSA" ,راستہ_HOST_RSA_کلید_FILE },
		{ "ecdsa", "ECDSA",راستہ_HOST_ECDSA_کلید_FILE },
#اگر_ختم /* WITH_OPENSSL */
		{ "ed25519", "ED25519",راستہ_HOST_ED25519_کلید_FILE },
#اگر_تعریف_شدہ USE_MLDSA
		{ "mldsa44-ed25519", "MLDSA44-ED25519",
		     راستہ_HOST_MLDSA44_ED25519_کلید_FILE },
#اگر_ختم
		{ تہی, تہی, تہی }
	};

	uint32_t بٹ = 0;
	صحیح پہلا = 0;
	ساخت stat st;
	ساخت sshkey *نجی, *عوامی;
	حرف comment[کلید_COMMENT_MAX], *prv_tmp, *pub_tmp, *prv_file, *pub_file;
	صحیح i, type, fd, r;

	برائے (i = 0; کلید_types[i].کلید_type; i++) {
		عوامی = نجی = تہی;
		prv_tmp = pub_tmp = prv_file = pub_file = تہی;

		xasprintf(&prv_file, "%s%s",
		    شناختی_عنصر_file, کلید_types[i].راستہ);

		/* Check whether private key exists and is not zero-length */
		اگر (stat(prv_file, &st) == 0) {
			اگر (st.st_size != 0)
				جاؤ اگلا;
		} ورنہ اگر (errno != ENOENT) {
			error("Could not stat %s: %s", کلید_types[i].راستہ,
			    strerror(errno));
			جاؤ failnext;
		}

		/*
		 * Private key doesn't exist or is invalid; proceed with
		 * key generation.
		 */
		xasprintf(&prv_tmp, "%s%s.XXXXXXXXXX",
		    شناختی_عنصر_file, کلید_types[i].راستہ);
		xasprintf(&pub_tmp, "%s%s.pub.XXXXXXXXXX",
		    شناختی_عنصر_file, کلید_types[i].راستہ);
		xasprintf(&pub_file, "%s%s.pub",
		    شناختی_عنصر_file, کلید_types[i].راستہ);

		اگر (پہلا == 0) {
			پہلا = 1;
			لکھو("%s: generating new host keys: ", __progname);
		}
		لکھو("%s ", کلید_types[i].کلید_type_display);
		fflush(stdout);
		type = sshkey_type_from_shortname(کلید_types[i].کلید_type);
		اگر ((fd = mkstemp(prv_tmp)) == -1) {
			error("Could not save your private key in %s: %s",
			    prv_tmp, strerror(errno));
			جاؤ failnext;
		}
		(خالی)close(fd); /* just using mkstemp() to reserve a name */
		بٹ = 0;
		type_بٹ_valid(type, تہی, &بٹ);
		اگر ((r = sshkey_generate(type, بٹ, &نجی)) != 0) {
			error_r(r, "sshkey_generate failed");
			جاؤ failnext;
		}
		اگر ((r = sshkey_from_نجی(نجی, &عوامی)) != 0)
			fatal_fr(r, "sshkey_from_private");
		snprintf(comment, حجم comment, "%s@%s", pw->pw_name,
		    hostname);
		اگر ((r = sshkey_save_نجی(نجی, prv_tmp, "",
		    comment, نجی_کلید_format, openssh_format_cipher,
		    دور)) != 0) {
			error_r(r, "Saving key \"%s\" failed", prv_tmp);
			جاؤ failnext;
		}
		اگر ((fd = mkstemp(pub_tmp)) == -1) {
			error("Could not save your public key in %s: %s",
			    pub_tmp, strerror(errno));
			جاؤ failnext;
		}
		(خالی)fchmod(fd, 0644);
		(خالی)close(fd);
		اگر ((r = sshkey_save_عوامی(عوامی, pub_tmp, comment)) != 0) {
			error_r(r, "Unable to save public key to %s",
			    شناختی_عنصر_file);
			جاؤ failnext;
		}

		/* Rename temporary files to their permanent locations. */
		اگر (rename(pub_tmp, pub_file) != 0) {
			error("Unable to move %s into position: %s",
			    pub_file, strerror(errno));
			جاؤ failnext;
		}
		اگر (rename(prv_tmp, prv_file) != 0) {
			error("Unable to move %s into position: %s",
			    کلید_types[i].راستہ, strerror(errno));
 failnext:
			پہلا = 0;
			جاؤ اگلا;
		}
 اگلا:
		sshkey_free(نجی);
		sshkey_free(عوامی);
		آزاد(prv_tmp);
		آزاد(pub_tmp);
		آزاد(prv_file);
		آزاد(pub_file);
	}
	اگر (پہلا != 0)
		لکھو("\n");
}

ساخت معلوم_hosts_ctx {
	ثابت حرف *host;	/* Hostname searched for in find/delete case */
	FILE *برآمد;		/* Output file, stdout for find_hosts case */
	صحیح has_unhashed;	/* When hashing, original had unhashed hosts */
	صحیح ملا_کلید;		/* For find/delete, host was found */
	صحیح invalid;		/* File contained invalid items; don't delete */
	صحیح hash_hosts;		/* Hash hostnames as we go */
	صحیح ڈھونڈو_host;		/* Search for specific hostname */
	صحیح delete_host;	/* Delete host from known_hosts */
};

ساکن صحیح
معلوم_hosts_hash(ساخت hostkey_foreach_سطر *l, خالی *_ctx)
{
	ساخت معلوم_hosts_ctx *ctx = (ساخت معلوم_hosts_ctx *)_ctx;
	حرف *hashed, *cp, *hosts, *ohosts;
	صحیح has_wild = l->hosts && strcspn(l->hosts, "*?!") != لڑی_لمبائی(l->hosts);
	صحیح was_hashed = l->hosts && l->hosts[0] == HASH_DELIM;

	انتخاب (l->حالت_2) {
	حالت HKF_حالت_OK:
	حالت HKF_حالت_MATCHED:
		/*
		 * Don't hash hosts already hashed, with wildcard
		 * characters or a CA/revocation marker.
		 */
		اگر (was_hashed || has_wild || l->marker != MRK_NONE) {
			fprintf(ctx->برآمد, "%s\n", l->سطر);
			اگر (has_wild && !ctx->ڈھونڈو_host) {
				logit("%s:%lu: ignoring host name "
				    "with wildcard: %.64s", l->راستہ,
				    l->linenum, l->hosts);
			}
			واپس 0;
		}
		/*
		 * Split any comma-separated hostnames from the host list,
		 * hash and store separately.
		 */
		ohosts = hosts = xstrdup(l->hosts);
		جب ((cp = strsep(&hosts, ",")) != تہی && *cp != '\0') {
			lowercase(cp);
			اگر ((hashed = host_hash(cp, تہی, 0)) == تہی)
				fatal("hash_host failed");
			fprintf(ctx->برآمد, "%s %s\n", hashed, l->rawkey);
			آزاد(hashed);
			ctx->has_unhashed = 1;
		}
		آزاد(ohosts);
		واپس 0;
	حالت HKF_حالت_INVALID:
		/* Retain invalid lines, but mark file as invalid. */
		ctx->invalid = 1;
		logit("%s:%lu: invalid line", l->راستہ, l->linenum);
		/* FALLTHROUGH */
	طےشدہ:
		fprintf(ctx->برآمد, "%s\n", l->سطر);
		واپس 0;
	}
	/* NOTREACHED */
	واپس -1;
}

ساکن صحیح
معلوم_hosts_ڈھونڈو_delete(ساخت hostkey_foreach_سطر *l, خالی *_ctx)
{
	ساخت معلوم_hosts_ctx *ctx = (ساخت معلوم_hosts_ctx *)_ctx;
	شمار sshkey_fp_rep rep;
	صحیح fptype;
	حرف *fp = تہی, *ra = تہی;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;

	اگر (l->حالت_2 == HKF_حالت_MATCHED) {
		اگر (ctx->delete_host) {
			اگر (l->marker != MRK_NONE) {
				/* Don't remove CA and revocation lines */
				fprintf(ctx->برآمد, "%s\n", l->سطر);
			} ورنہ {
				/*
				 * Hostname matches and has no CA/revoke
				 * marker, delete it by *not* writing the
				 * line to ctx->out.
				 */
				ctx->ملا_کلید = 1;
				اگر (!quiet)
					لکھو("# Host %s found: line %lu\n",
					    ctx->host, l->linenum);
			}
			واپس 0;
		} ورنہ اگر (ctx->ڈھونڈو_host) {
			ctx->ملا_کلید = 1;
			اگر (!quiet) {
				لکھو("# Host %s found: line %lu %s\n",
				    ctx->host,
				    l->linenum, l->marker == MRK_CA ? "CA" :
				    (l->marker == MRK_REVOKE ? "REVOKED" : ""));
			}
			اگر (ctx->hash_hosts)
				معلوم_hosts_hash(l, ctx);
			ورنہ اگر (print_fingerprint) {
				fp = sshkey_fingerprint(l->کلید, fptype, rep);
				ra = sshkey_fingerprint(l->کلید,
				    fingerprint_hash, SSH_FP_RANDOMART);
				اگر (fp == تہی || ra == تہی)
					fatal_f("sshkey_fingerprint failed");
				mprintf("%s %s %s%s%s\n", ctx->host,
				    sshkey_type(l->کلید), fp,
				    l->comment[0] ? " " : "",
				    l->comment);
				اگر (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
					لکھو("%s\n", ra);
				آزاد(ra);
				آزاد(fp);
			} ورنہ
				fprintf(ctx->برآمد, "%s\n", l->سطر);
			واپس 0;
		}
	} ورنہ اگر (ctx->delete_host) {
		/* Retain non-matching hosts when deleting */
		اگر (l->حالت_2 == HKF_حالت_INVALID) {
			ctx->invalid = 1;
			logit("%s:%lu: invalid line", l->راستہ, l->linenum);
		}
		fprintf(ctx->برآمد, "%s\n", l->سطر);
	}
	واپس 0;
}

ساکن خالی
do_معلوم_hosts(ساخت passwd *pw, ثابت حرف *name, صحیح ڈھونڈو_host,
    صحیح delete_host, صحیح hash_hosts)
{
	حرف *cp, tmp[PATH_MAX], old[PATH_MAX];
	صحیح r, fd, oerrno, inplace = 0;
	ساخت معلوم_hosts_ctx ctx;
	u_int foreach_options;
	ساخت stat sb;

	اگر (!have_شناختی_عنصر) {
		cp = tilde_expand_filename(راستہ_SSH_USER_HOSTFILE, pw->pw_uid);
		اگر (strlcpy(شناختی_عنصر_file, cp, حجم(شناختی_عنصر_file)) >=
		    حجم(شناختی_عنصر_file))
			fatal("Specified known hosts path too long");
		آزاد(cp);
		have_شناختی_عنصر = 1;
	}
	اگر (stat(شناختی_عنصر_file, &sb) != 0)
		fatal("Cannot stat %s: %s", شناختی_عنصر_file, strerror(errno));

	memset(&ctx, 0, حجم(ctx));
	ctx.برآمد = stdout;
	ctx.host = name;
	ctx.hash_hosts = hash_hosts;
	ctx.ڈھونڈو_host = ڈھونڈو_host;
	ctx.delete_host = delete_host;

	/*
	 * Find hosts goes to stdout, hash and deletions happen in-place
	 * A corner case is ssh-keygen -HF foo, which should go to stdout
	 */
	اگر (!ڈھونڈو_host && (hash_hosts || delete_host)) {
		اگر (strlcpy(tmp, شناختی_عنصر_file, حجم(tmp)) >= حجم(tmp) ||
		    strlcat(tmp, ".XXXXXXXXXX", حجم(tmp)) >= حجم(tmp) ||
		    strlcpy(old, شناختی_عنصر_file, حجم(old)) >= حجم(old) ||
		    strlcat(old, ".old", حجم(old)) >= حجم(old))
			fatal("known_hosts path too long");
		umask(077);
		اگر ((fd = mkstemp(tmp)) == -1)
			fatal("mkstemp: %s", strerror(errno));
		اگر ((ctx.برآمد = fdopen(fd, "w")) == تہی) {
			oerrno = errno;
			unlink(tmp);
			fatal("fdopen: %s", strerror(oerrno));
		}
		(خالی)fchmod(fd, sb.st_mode & 0644);
		inplace = 1;
	}
	/* XXX support identity_file == "-" for stdin */
	foreach_options = ڈھونڈو_host ? HKF_WANT_مطابقت : 0;
	foreach_options |= print_fingerprint ? HKF_WANT_PARSE_کلید : 0;
	اگر ((r = hostkeys_foreach(شناختی_عنصر_file, (ڈھونڈو_host || !hash_hosts) ?
	    معلوم_hosts_ڈھونڈو_delete : معلوم_hosts_hash, &ctx, name, تہی,
	    foreach_options, 0)) != 0) {
		اگر (inplace)
			unlink(tmp);
		fatal_fr(r, "hostkeys_foreach");
	}

	اگر (inplace)
		fclose(ctx.برآمد);

	اگر (ctx.invalid) {
		error("%s is not a valid known_hosts file.", شناختی_عنصر_file);
		اگر (inplace) {
			error("Not replacing existing known_hosts "
			    "file because of errors");
			unlink(tmp);
		}
		باہر_نکلو(1);
	} ورنہ اگر (delete_host && !ctx.ملا_کلید) {
		logit("Host %s not found in %s", name, شناختی_عنصر_file);
		اگر (inplace)
			unlink(tmp);
	} ورنہ اگر (inplace) {
		/* Backup existing file */
		اگر (unlink(old) == -1 && errno != ENOENT)
			fatal("unlink %.100s: %s", old, strerror(errno));
		اگر (link(شناختی_عنصر_file, old) == -1)
			fatal("link %.100s to %.100s: %s", شناختی_عنصر_file, old,
			    strerror(errno));
		/* Move new one into place */
		اگر (rename(tmp, شناختی_عنصر_file) == -1) {
			error("rename\"%s\" to \"%s\": %s", tmp, شناختی_عنصر_file,
			    strerror(errno));
			unlink(tmp);
			unlink(old);
			باہر_نکلو(1);
		}

		لکھو("%s updated.\n", شناختی_عنصر_file);
		لکھو("Original contents retained as %s\n", old);
		اگر (ctx.has_unhashed) {
			logit("WARNING: %s contains unhashed entries", old);
			logit("Delete this file to ensure privacy "
			    "of hostnames");
		}
	}

	باہر_نکلو (ڈھونڈو_host && !ctx.ملا_کلید);
}

/*
 * Perform changing a passphrase.  The argument is the passwd structure
 * for the current user.
 */
ساکن خالی
do_change_passphrase(ساخت passwd *pw, حرف * ثابت *opts, سائز_t nopts)
{
	حرف *comment;
	حرف *old_passphrase, *passphrase1, *passphrase2;
	ساخت stat st;
	ساخت sshkey *نجی;
	صحیح r;
	سائز_t i;

	اگر (!have_شناختی_عنصر)
		ask_filename(pw, "Enter file in which the key is");
	اگر (stat(شناختی_عنصر_file, &st) == -1)
		fatal("%s: %s", شناختی_عنصر_file, strerror(errno));
	/* Try to load the file with empty passphrase. */
	r = sshkey_بھرو_نجی(شناختی_عنصر_file, "", &نجی, &comment);
	اگر (r == SSH_ERR_کلید_WRONG_PASSPHRASE) {
		اگر (شناختی_عنصر_passphrase)
			old_passphrase = xstrdup(شناختی_عنصر_passphrase);
		ورنہ
			old_passphrase =
			    read_passphrase("Enter old passphrase: ",
			    RP_ALLOW_STDIN);
		r = sshkey_بھرو_نجی(شناختی_عنصر_file, old_passphrase,
		    &نجی, &comment);
		freezero(old_passphrase, لڑی_لمبائی(old_passphrase));
		اگر (r != 0)
			جاؤ badkey;
	} ورنہ اگر (r != 0) {
 badkey:
		fatal_r(r, "Failed to load key %s", شناختی_عنصر_file);
	}
	اگر (comment)
		mprintf("Key has comment '%s'\n", comment);

	/* All current -O options relate to FIDO keys only */
	اگر (nopts != 0 && !sshkey_is_sk(نجی)) {
		fatal("FIDO-specific option requested for non-FIDO key %s",
		    شناختی_عنصر_file);
	}
	اگر (sshkey_is_sk(نجی)) {
		debug_f("%s: original FIDO key flags: "
		    "%stouch-required %sverify-required", شناختی_عنصر_file,
		    (نجی->sk_flags & SSH_SK_USER_PRESENCE_REQD) ? "": "no-",
		    (نجی->sk_flags & SSH_SK_USER_VERIFICATION_REQD) ? "" : "no-");
	}
	برائے (i = 0; i < nopts; i++) {
		اگر (strcasecmp(opts[i], "touch-required") == 0)
			نجی->sk_flags |= SSH_SK_USER_PRESENCE_REQD;
		ورنہ اگر (strcasecmp(opts[i], "no-touch-required") == 0)
			نجی->sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
		ورنہ اگر (strcasecmp(opts[i], "verify-required") == 0)
			نجی->sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
		ورنہ اگر (strcasecmp(opts[i], "no-verify-required") == 0)
			نجی->sk_flags &= ~SSH_SK_USER_VERIFICATION_REQD;
		ورنہ {
			fatal("Option \"%s\" is unsupported for "
			    "key passphrase change", opts[i]);
		}
	}
	اگر (sshkey_is_sk(نجی) && nopts != 0) {
		debug_f("%s: updated FIDO key flags: "
		    "%stouch-required %sverify-required", شناختی_عنصر_file,
		    (نجی->sk_flags & SSH_SK_USER_PRESENCE_REQD) ? "": "no-",
		    (نجی->sk_flags & SSH_SK_USER_VERIFICATION_REQD) ? "" : "no-");
	}

	/* Ask the new passphrase (twice). */
	اگر (شناختی_عنصر_new_passphrase) {
		passphrase1 = xstrdup(شناختی_عنصر_new_passphrase);
		passphrase2 = تہی;
	} ورنہ {
		passphrase1 =
			read_passphrase("Enter new passphrase (empty for no "
			    "passphrase): ", RP_ALLOW_STDIN);
		passphrase2 = read_passphrase("Enter same passphrase again: ",
		    RP_ALLOW_STDIN);

		/* Verify that they are the same. */
		اگر (strcmp(passphrase1, passphrase2) != 0) {
			explicit_bzero(passphrase1, لڑی_لمبائی(passphrase1));
			explicit_bzero(passphrase2, لڑی_لمبائی(passphrase2));
			آزاد(passphrase1);
			آزاد(passphrase2);
			لکھو("Pass phrases do not match.  Try again.\n");
			باہر_نکلو(1);
		}
		/* Destroy the other copy. */
		freezero(passphrase2, لڑی_لمبائی(passphrase2));
	}

	/* Save the file using the new passphrase. */
	اگر ((r = sshkey_save_نجی(نجی, شناختی_عنصر_file, passphrase1,
	    comment, نجی_کلید_format, openssh_format_cipher, دور)) != 0) {
		error_r(r, "Saving key \"%s\" failed", شناختی_عنصر_file);
		freezero(passphrase1, لڑی_لمبائی(passphrase1));
		sshkey_free(نجی);
		آزاد(comment);
		باہر_نکلو(1);
	}
	/* Destroy the passphrase and the copy of the key in memory. */
	freezero(passphrase1, لڑی_لمبائی(passphrase1));
	sshkey_free(نجی);		 /* Destroys contents */
	آزاد(comment);

	لکھو("Your identification has been saved with the new passphrase.\n");
	باہر_نکلو(0);
}

/*
 * Print the SSHFP RR.
 */
ساکن صحیح
do_print_resource_ریکارڈ(ساخت passwd *pw, حرف *fname, حرف *hname,
    صحیح print_generic, حرف * ثابت *opts, سائز_t nopts)
{
	ساخت sshkey *عوامی;
	حرف *comment = تہی;
	ثابت حرف *p;
	ساخت stat st;
	صحیح r, hash = -1;
	سائز_t i;

	برائے (i = 0; i < nopts; i++) {
		اگر ((p = strprefix(opts[i], "hashalg=", 1)) != تہی) {
			اگر ((hash = ssh_digest_alg_by_name(p)) == -1)
				fatal("Unsupported hash algorithm");
		} ورنہ {
			error("Invalid option \"%s\"", opts[i]);
			واپس SSH_ERR_INVALID_دلیل;
		}
	}
	اگر (fname == تہی)
		fatal_f("no filename");
	اگر (stat(fname, &st) == -1) {
		اگر (errno == ENOENT)
			واپس 0;
		fatal("%s: %s", fname, strerror(errno));
	}
	اگر ((r = sshkey_بھرو_عوامی(fname, &عوامی, &comment)) != 0)
		fatal_r(r, "Failed to read v2 public key from \"%s\"", fname);
	export_dns_rr(hname, عوامی, stdout, print_generic, hash);
	sshkey_free(عوامی);
	آزاد(comment);
	واپس 1;
}

/*
 * Change the comment of a private key file.
 */
ساکن خالی
do_change_comment(ساخت passwd *pw, ثابت حرف *شناختی_عنصر_comment)
{
	حرف new_comment[کلید_COMMENT_MAX], *comment, *passphrase;
	ساخت sshkey *نجی;
	ساخت sshkey *عوامی;
	ساخت stat st;
	صحیح r;

	اگر (!have_شناختی_عنصر)
		ask_filename(pw, "Enter file in which the key is");
	اگر (stat(شناختی_عنصر_file, &st) == -1)
		fatal("%s: %s", شناختی_عنصر_file, strerror(errno));
	اگر ((r = sshkey_بھرو_نجی(شناختی_عنصر_file, "",
	    &نجی, &comment)) == 0)
		passphrase = xstrdup("");
	ورنہ اگر (r != SSH_ERR_کلید_WRONG_PASSPHRASE)
		fatal_r(r, "Cannot load private key \"%s\"", شناختی_عنصر_file);
	ورنہ {
		اگر (شناختی_عنصر_passphrase)
			passphrase = xstrdup(شناختی_عنصر_passphrase);
		ورنہ اگر (شناختی_عنصر_new_passphrase)
			passphrase = xstrdup(شناختی_عنصر_new_passphrase);
		ورنہ
			passphrase = read_passphrase("Enter passphrase: ",
			    RP_ALLOW_STDIN);
		/* Try to load using the passphrase. */
		اگر ((r = sshkey_بھرو_نجی(شناختی_عنصر_file, passphrase,
		    &نجی, &comment)) != 0) {
			freezero(passphrase, لڑی_لمبائی(passphrase));
			fatal_r(r, "Cannot load private key \"%s\"",
			    شناختی_عنصر_file);
		}
	}

	اگر (نجی->type != کلید_ED25519 &&
	    نجی_کلید_format != SSHKEY_نجی_OPENSSH) {
		error("Comments are only supported for keys stored in "
		    "the new format (-o).");
		explicit_bzero(passphrase, لڑی_لمبائی(passphrase));
		sshkey_free(نجی);
		باہر_نکلو(1);
	}
	اگر (comment)
		لکھو("Old comment: %s\n", comment);
	ورنہ
		لکھو("No existing comment\n");

	اگر (شناختی_عنصر_comment) {
		strlcpy(new_comment, شناختی_عنصر_comment, حجم(new_comment));
	} ورنہ {
		لکھو("New comment: ");
		fflush(stdout);
		اگر (!fgets(new_comment, حجم(new_comment), stdin)) {
			explicit_bzero(passphrase, لڑی_لمبائی(passphrase));
			sshkey_free(نجی);
			باہر_نکلو(1);
		}
		new_comment[strcspn(new_comment, "\n")] = '\0';
	}
	اگر (comment != تہی && strcmp(comment, new_comment) == 0) {
		لکھو("No change to comment\n");
		آزاد(passphrase);
		sshkey_free(نجی);
		آزاد(comment);
		باہر_نکلو(0);
	}

	/* Save the file using the new passphrase. */
	اگر ((r = sshkey_save_نجی(نجی, شناختی_عنصر_file, passphrase,
	    new_comment, نجی_کلید_format, openssh_format_cipher,
	    دور)) != 0) {
		error_r(r, "Saving key \"%s\" failed", شناختی_عنصر_file);
		freezero(passphrase, لڑی_لمبائی(passphrase));
		sshkey_free(نجی);
		آزاد(comment);
		باہر_نکلو(1);
	}
	freezero(passphrase, لڑی_لمبائی(passphrase));
	اگر ((r = sshkey_from_نجی(نجی, &عوامی)) != 0)
		fatal_fr(r, "sshkey_from_private");
	sshkey_free(نجی);

	strlcat(شناختی_عنصر_file, ".pub", حجم(شناختی_عنصر_file));
	اگر ((r = sshkey_save_عوامی(عوامی, شناختی_عنصر_file, new_comment)) != 0)
		fatal_r(r, "Unable to save public key to %s", شناختی_عنصر_file);
	sshkey_free(عوامی);
	آزاد(comment);

	اگر (لڑی_لمبائی(new_comment) > 0)
		لکھو("Comment '%s' applied\n", new_comment);
	ورنہ
		لکھو("Comment removed\n");

	باہر_نکلو(0);
}

ساکن خالی
cert_ext_جوڑو(ثابت حرف *کلید, ثابت حرف *قدر, صحیح iscrit)
{
	cert_ext = xreallocarray(cert_ext, ncert_ext + 1, حجم(*cert_ext));
	cert_ext[ncert_ext].کلید = xstrdup(کلید);
	cert_ext[ncert_ext].val = قدر == تہی ? تہی : xstrdup(قدر);
	cert_ext[ncert_ext].crit = iscrit;
	ncert_ext++;
}

/* qsort(3) comparison function for certificate extensions */
ساکن صحیح
cert_ext_cmp(ثابت خالی *_a, ثابت خالی *_b)
{
	ثابت ساخت cert_ext *a = (ثابت ساخت cert_ext *)_a;
	ثابت ساخت cert_ext *b = (ثابت ساخت cert_ext *)_b;
	صحیح r;

	اگر (a->crit != b->crit)
		واپس (a->crit < b->crit) ? -1 : 1;
	اگر ((r = strcmp(a->کلید, b->کلید)) != 0)
		واپس r;
	اگر ((a->val == تہی) != (b->val == تہی))
		واپس (a->val == تہی) ? -1 : 1;
	اگر (a->val != تہی && (r = strcmp(a->val, b->val)) != 0)
		واپس r;
	واپس 0;
}

#تعریف_کرو OPTIONS_CRITICAL	1
#تعریف_کرو OPTIONS_EXTENSIONS	2
ساکن خالی
prepare_options_buf(ساخت sshbuf *c, صحیح which)
{
	ساخت sshbuf *b;
	سائز_t i;
	صحیح r;
	ثابت ساخت cert_ext *ext;

	اگر ((b = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	sshbuf_reset(c);
	برائے (i = 0; i < ncert_ext; i++) {
		ext = &cert_ext[i];
		اگر ((ext->crit && (which & OPTIONS_EXTENSIONS)) ||
		    (!ext->crit && (which & OPTIONS_CRITICAL)))
			جاری;
		اگر (ext->val == تہی) {
			/* flag option */
			debug3_f("%s", ext->کلید);
			اگر ((r = sshbuf_put_cstring(c, ext->کلید)) != 0 ||
			    (r = sshbuf_put_string(c, تہی, 0)) != 0)
				fatal_fr(r, "prepare flag");
		} ورنہ {
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

ساکن خالی
finalise_cert_exts(خالی)
{
	/* critical options */
	اگر (certflags_command != تہی)
		cert_ext_جوڑو("force-command", certflags_command, 1);
	اگر (certflags_src_addr != تہی)
		cert_ext_جوڑو("source-address", certflags_src_addr, 1);
	اگر ((certflags_flags & CERTOPT_REQUIRE_VERIFY) != 0)
		cert_ext_جوڑو("verify-required", تہی, 1);
	/* extensions */
	اگر ((certflags_flags & CERTOPT_X_FWD) != 0)
		cert_ext_جوڑو("permit-X11-forwarding", تہی, 0);
	اگر ((certflags_flags & CERTOPT_AGENT_FWD) != 0)
		cert_ext_جوڑو("permit-agent-forwarding", تہی, 0);
	اگر ((certflags_flags & CERTOPT_پورٹ_FWD) != 0)
		cert_ext_جوڑو("permit-port-forwarding", تہی, 0);
	اگر ((certflags_flags & CERTOPT_PTY) != 0)
		cert_ext_جوڑو("permit-pty", تہی, 0);
	اگر ((certflags_flags & CERTOPT_USER_RC) != 0)
		cert_ext_جوڑو("permit-user-rc", تہی, 0);
	اگر ((certflags_flags & CERTOPT_NO_REQUIRE_USER_PRESENCE) != 0)
		cert_ext_جوڑو("no-touch-required", تہی, 0);
	/* order lexically by key */
	اگر (ncert_ext > 0)
		qsort(cert_ext, ncert_ext, حجم(*cert_ext), cert_ext_cmp);
}

ساکن ساخت sshkey *
بھرو_pkcs11_کلید(حرف *راستہ)
{
#اگر_تعریف_شدہ ENABLE_PKCS11
	ساخت sshkey **کلیدیں = تہی, *عوامی, *نجی = تہی;
	صحیح r, i, nkeys;

	اگر ((r = sshkey_بھرو_عوامی(راستہ, &عوامی, تہی)) != 0)
		fatal_r(r, "Couldn't load CA public key \"%s\"", راستہ);

	nkeys = pkcs11_جوڑو_provider(pkcs11provider, شناختی_عنصر_passphrase,
	    &کلیدیں, تہی);
	debug3_f("%d keys", nkeys);
	اگر (nkeys <= 0)
		fatal("cannot read public key from pkcs11");
	برائے (i = 0; i < nkeys; i++) {
		اگر (sshkey_equal_عوامی(عوامی, کلیدیں[i])) {
			نجی = کلیدیں[i];
			جاری;
		}
		sshkey_free(کلیدیں[i]);
	}
	آزاد(کلیدیں);
	sshkey_free(عوامی);
	واپس نجی;
#ورنہ
	fatal("no pkcs11 support");
#اگر_ختم /* ENABLE_PKCS11 */
}

/* Signer for sshkey_certify_custom that uses the agent */
ساکن صحیح
agent_signer(ساخت sshkey *کلید, u_char **sigp, سائز_t *lenp,
    ثابت u_char *ڈیٹا, سائز_t datalen,
    ثابت حرف *alg, ثابت حرف *provider, ثابت حرف *pin,
    u_int compat, خالی *ctx)
{
	صحیح *agent_fdp = (صحیح *)ctx;

	واپس ssh_agent_sign(*agent_fdp, کلید, sigp, lenp,
	    ڈیٹا, datalen, alg, compat);
}

ساکن خالی
do_ca_sign(ساخت passwd *pw, ثابت حرف *ca_کلید_راستہ, صحیح prefer_agent,
    غیرعلامتی طویل طویل cert_serial, صحیح cert_serial_autoinc,
    صحیح argc, حرف **argv)
{
	صحیح r, i, کلید_اندر_agent = 0, agent_fd = -1;
	u_int n;
	ساخت sshkey *ca, *عوامی;
	حرف valid[64], *otmp, *tmp, *cp, *برآمد, *comment;
	حرف *ca_fp = تہی, **plist = تہی, *pin = تہی;
	ساخت ssh_identitylist *agent_ids;
	سائز_t j;
	ساخت notifier_ctx *notifier = تہی;

#اگر_تعریف_شدہ ENABLE_PKCS11
	pkcs11_init(1);
#اگر_ختم
	tmp = tilde_expand_filename(ca_کلید_راستہ, pw->pw_uid);
	اگر (pkcs11provider != تہی) {
		/* If a PKCS#11 token was specified then try to use it */
		اگر ((ca = بھرو_pkcs11_کلید(tmp)) == تہی)
			fatal("No PKCS#11 key matching %s found", ca_کلید_راستہ);
	} ورنہ اگر (prefer_agent) {
		/*
		 * Agent signature requested. Try to use agent after making
		 * sure the public key specified is actually present in the
		 * agent.
		 */
		اگر ((r = sshkey_بھرو_عوامی(tmp, &ca, تہی)) != 0)
			fatal_r(r, "Cannot load CA public key %s", tmp);
		اگر ((r = ssh_get_authentication_socket(&agent_fd)) != 0)
			fatal_r(r, "Cannot use public key for CA signature");
		اگر ((r = ssh_fetch_identitylist(agent_fd, &agent_ids)) != 0)
			fatal_r(r, "Retrieve agent key list");
		برائے (j = 0; j < agent_ids->nkeys; j++) {
			اگر (sshkey_equal(ca, agent_ids->کلیدیں[j])) {
				کلید_اندر_agent = 1;
				/* Replace the CA key with the agent one */
				sshkey_free(ca);
				ca = agent_ids->کلیدیں[j];
				agent_ids->کلیدیں[j] = تہی;
				توڑو;
			}
		}
		اگر (!کلید_اندر_agent)
			fatal("CA key %s not found in agent", tmp);
		ssh_free_identitylist(agent_ids);
	} ورنہ {
		/* CA key is assumed to be a private key on the filesystem */
		ca = بھرو_شناختی_عنصر(tmp, تہی);
		اگر (sshkey_is_sk(ca) &&
		    (ca->sk_flags & SSH_SK_USER_VERIFICATION_REQD)) {
			اگر ((pin = read_passphrase("Enter PIN for CA key: ",
			    RP_ALLOW_STDIN)) == تہی)
				fatal_f("couldn't read PIN");
		}
	}
	آزاد(tmp);

	اگر (کلید_type_name != تہی) {
		اگر (sshkey_type_from_shortname(کلید_type_name) != ca->type) {
			fatal("CA key type %s doesn't match specified %s",
			    sshkey_ssh_name(ca), کلید_type_name);
		}
	} ورنہ اگر (ca->type == کلید_RSA) {
		/* Default to a good signature algorithm */
		کلید_type_name = "rsa-sha2-512";
	}
	ca_fp = sshkey_fingerprint(ca, fingerprint_hash, SSH_FP_DEFAULT);

	finalise_cert_exts();
	برائے (i = 0; i < argc; i++) {
		/* Split list of principals */
		n = 0;
		اگر (cert_principals != تہی) {
			otmp = tmp = xstrdup(cert_principals);
			plist = تہی;
			برائے (; (cp = strsep(&tmp, ",")) != تہی; n++) {
				plist = xreallocarray(plist, n + 1, حجم(*plist));
				اگر (*(plist[n] = xstrdup(cp)) == '\0')
					fatal("Empty principal name");
			}
			آزاد(otmp);
		}
		اگر (n > SSHKEY_CERT_MAX_PRINCIPALS)
			fatal("Too many certificate principals specified");

		tmp = tilde_expand_filename(argv[i], pw->pw_uid);
		اگر ((r = sshkey_بھرو_عوامی(tmp, &عوامی, &comment)) != 0)
			fatal_r(r, "load pubkey \"%s\"", tmp);
		اگر (sshkey_is_cert(عوامی))
			fatal_f("key \"%s\" type %s cannot be certified",
			    tmp, sshkey_type(عوامی));

		/* Prepare certificate to sign */
		اگر ((r = sshkey_مقصد_certified(عوامی)) != 0)
			fatal_r(r, "Could not upgrade key %s to certificate", tmp);
		عوامی->cert->type = cert_کلید_type;
		عوامی->cert->serial = (uint64_t)cert_serial;
		عوامی->cert->کلید_id = xstrdup(cert_کلید_id);
		عوامی->cert->nprincipals = n;
		عوامی->cert->principals = plist;
		عوامی->cert->valid_after = cert_valid_from;
		عوامی->cert->valid_before = cert_valid_مقصد;
		prepare_options_buf(عوامی->cert->critical, OPTIONS_CRITICAL);
		prepare_options_buf(عوامی->cert->extensions,
		    OPTIONS_EXTENSIONS);
		اگر ((r = sshkey_from_نجی(ca,
		    &عوامی->cert->signature_کلید)) != 0)
			fatal_r(r, "sshkey_from_private (ca key)");

		اگر (کلید_اندر_agent) {
			اگر ((r = sshkey_certify_custom(عوامی, ca,
			    کلید_type_name, sk_provider, تہی, agent_signer,
			    &agent_fd)) != 0)
				fatal_r(r, "Couldn't certify %s via agent", tmp);
		} ورنہ {
			اگر (sshkey_is_sk(ca) &&
			    (ca->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
				notifier = notify_آغاز(0,
				    "Confirm user presence for key %s %s",
				    sshkey_type(ca), ca_fp);
			}
			r = sshkey_certify(عوامی, ca, کلید_type_name,
			    sk_provider, pin);
			notify_complete(notifier, "User presence confirmed");
			اگر (r != 0)
				fatal_r(r, "Couldn't certify key %s", tmp);
		}

		اگر ((cp = strrchr(tmp, '.')) != تہی && strcmp(cp, ".pub") == 0)
			*cp = '\0';
		xasprintf(&برآمد, "%s-cert.pub", tmp);
		آزاد(tmp);

		اگر ((r = sshkey_save_عوامی(عوامی, برآمد, comment)) != 0) {
			fatal_r(r, "Unable to save public key to %s",
			    شناختی_عنصر_file);
		}

		اگر (!quiet) {
			sshkey_format_cert_validity(عوامی->cert,
			    valid, حجم(valid));
			logit("Signed %s key %s: id \"%s\" serial %llu%s%s "
			    "valid %s", sshkey_cert_type(عوامی),
			    برآمد, عوامی->cert->کلید_id,
			    (غیرعلامتی طویل طویل)عوامی->cert->serial,
			    cert_principals != تہی ? " for " : "",
			    cert_principals != تہی ? cert_principals : "",
			    valid);
		}

		sshkey_free(عوامی);
		آزاد(برآمد);
		آزاد(comment);
		اگر (cert_serial_autoinc)
			cert_serial++;
	}
	اگر (pin != تہی)
		freezero(pin, لڑی_لمبائی(pin));
	sshkey_free(ca);
	آزاد(ca_fp);
#اگر_تعریف_شدہ ENABLE_PKCS11
	pkcs11_terminate();
#اگر_ختم
}

ساکن uint64_t
parse_relative_وقت(ثابت حرف *s, time_t now)
{
	int64_t mul, secs;

	mul = *s == '-' ? -1 : 1;

	اگر ((secs = convtime(s + 1)) == -1)
		fatal("Invalid relative certificate time %s", s);
	اگر (mul == -1 && secs > now)
		fatal("Certificate time %s cannot be represented", s);
	واپس now + (uint64_t)(secs * mul);
}

ساکن خالی
parse_hex_u64(ثابت حرف *s, uint64_t *اوپر)
{
	حرف *ep;
	غیرعلامتی طویل طویل ull;

	errno = 0;
	ull = strtoull(s, &ep, 16);
	اگر (*s == '\0' || *ep != '\0')
		fatal("Invalid certificate time: not a number");
	اگر (errno == ERANGE && ull == ULONG_MAX)
		fatal_fr(SSH_ERR_SYSTEM_ERROR, "Invalid certificate time");
	*اوپر = (uint64_t)ull;
}

ساکن خالی
parse_cert_times(حرف *timespec)
{
	حرف *from, *مقصد;
	time_t now = time(تہی);
	int64_t secs;

	/* +timespec relative to now */
	اگر (*timespec == '+' && strchr(timespec, ':') == تہی) {
		اگر ((secs = convtime(timespec + 1)) == -1)
			fatal("Invalid relative certificate life %s", timespec);
		cert_valid_مقصد = now + secs;
		/*
		 * Backdate certificate one minute to avoid problems on hosts
		 * with poorly-synchronised clocks.
		 */
		cert_valid_from = ((now - 59)/ 60) * 60;
		واپس;
	}

	/*
	 * from:to, where
	 * from := [+-]timespec | YYYYMMDD | YYYYMMDDHHMMSS | 0x... | "always"
	 *   to := [+-]timespec | YYYYMMDD | YYYYMMDDHHMMSS | 0x... | "forever"
	 */
	from = xstrdup(timespec);
	مقصد = strchr(from, ':');
	اگر (مقصد == تہی || from == مقصد || *(مقصد + 1) == '\0')
		fatal("Invalid certificate life specification %s", timespec);
	*مقصد++ = '\0';

	اگر (*from == '-' || *from == '+')
		cert_valid_from = parse_relative_وقت(from, now);
	ورنہ اگر (strcmp(from, "always") == 0)
		cert_valid_from = 0;
	ورنہ اگر (لڑی_موازنہ(from, "0x", 2) == 0)
		parse_hex_u64(from, &cert_valid_from);
	ورنہ اگر (parse_absolute_وقت(from, &cert_valid_from) != 0)
		fatal("Invalid from time \"%s\"", from);

	اگر (*مقصد == '-' || *مقصد == '+')
		cert_valid_مقصد = parse_relative_وقت(مقصد, now);
	ورنہ اگر (strcmp(مقصد, "forever") == 0)
		cert_valid_مقصد = ~(uint64_t)0;
	ورنہ اگر (لڑی_موازنہ(مقصد, "0x", 2) == 0)
		parse_hex_u64(مقصد, &cert_valid_مقصد);
	ورنہ اگر (parse_absolute_وقت(مقصد, &cert_valid_مقصد) != 0)
		fatal("Invalid to time \"%s\"", مقصد);

	اگر (cert_valid_مقصد <= cert_valid_from)
		fatal("Empty certificate validity interval");
	آزاد(from);
}

ساکن خالی
جوڑو_cert_option(حرف *opt)
{
	حرف *val, *cp;
	ثابت حرف *p;
	صحیح iscrit = 0;

	اگر (strcasecmp(opt, "clear") == 0)
		certflags_flags = 0;
	ورنہ اگر (strcasecmp(opt, "no-x11-forwarding") == 0)
		certflags_flags &= ~CERTOPT_X_FWD;
	ورنہ اگر (strcasecmp(opt, "permit-x11-forwarding") == 0)
		certflags_flags |= CERTOPT_X_FWD;
	ورنہ اگر (strcasecmp(opt, "no-agent-forwarding") == 0)
		certflags_flags &= ~CERTOPT_AGENT_FWD;
	ورنہ اگر (strcasecmp(opt, "permit-agent-forwarding") == 0)
		certflags_flags |= CERTOPT_AGENT_FWD;
	ورنہ اگر (strcasecmp(opt, "no-port-forwarding") == 0)
		certflags_flags &= ~CERTOPT_پورٹ_FWD;
	ورنہ اگر (strcasecmp(opt, "permit-port-forwarding") == 0)
		certflags_flags |= CERTOPT_پورٹ_FWD;
	ورنہ اگر (strcasecmp(opt, "no-pty") == 0)
		certflags_flags &= ~CERTOPT_PTY;
	ورنہ اگر (strcasecmp(opt, "permit-pty") == 0)
		certflags_flags |= CERTOPT_PTY;
	ورنہ اگر (strcasecmp(opt, "no-user-rc") == 0)
		certflags_flags &= ~CERTOPT_USER_RC;
	ورنہ اگر (strcasecmp(opt, "permit-user-rc") == 0)
		certflags_flags |= CERTOPT_USER_RC;
	ورنہ اگر (strcasecmp(opt, "touch-required") == 0)
		certflags_flags &= ~CERTOPT_NO_REQUIRE_USER_PRESENCE;
	ورنہ اگر (strcasecmp(opt, "no-touch-required") == 0)
		certflags_flags |= CERTOPT_NO_REQUIRE_USER_PRESENCE;
	ورنہ اگر (strcasecmp(opt, "no-verify-required") == 0)
		certflags_flags &= ~CERTOPT_REQUIRE_VERIFY;
	ورنہ اگر (strcasecmp(opt, "verify-required") == 0)
		certflags_flags |= CERTOPT_REQUIRE_VERIFY;
	ورنہ اگر ((p = strprefix(opt, "force-command=", 1)) != تہی) {
		اگر (*p == '\0')
			fatal("Empty force-command option");
		اگر (certflags_command != تہی)
			fatal("force-command already specified");
		certflags_command = xstrdup(p);
	} ورنہ اگر ((p = strprefix(opt, "source-address=", 1)) != تہی) {
		اگر (*p == '\0')
			fatal("Empty source-address option");
		اگر (certflags_src_addr != تہی)
			fatal("source-address already specified");
		اگر (addr_مطابقت_cidr_list(تہی, p) != 0)
			fatal("Invalid source-address list");
		certflags_src_addr = xstrdup(p);
	} ورنہ اگر (strprefix(opt, "extension:", 1) != تہی ||
		    (iscrit = (strprefix(opt, "critical:", 1) != تہی))) {
		val = xstrdup(strchr(opt, ':') + 1);
		اگر ((cp = strchr(val, '=')) != تہی)
			*cp++ = '\0';
		cert_ext_جوڑو(val, cp, iscrit);
		آزاد(val);
	} ورنہ
		fatal("Unsupported certificate option \"%s\"", opt);
}

ساکن خالی
show_options(ساخت sshbuf *optbuf, صحیح اندر_critical)
{
	حرف *name, *arg, *hex;
	ساخت sshbuf *options, *option = تہی;
	صحیح r;

	اگر ((options = sshbuf_fromb(optbuf)) == تہی)
		fatal_f("sshbuf_fromb failed");
	جب (sshbuf_len(options) != 0) {
		sshbuf_free(option);
		option = تہی;
		اگر ((r = sshbuf_get_cstring(options, &name, تہی)) != 0 ||
		    (r = sshbuf_froms(options, &option)) != 0)
			fatal_fr(r, "parse option");
		لکھو("                %s", name);
		اگر (!اندر_critical &&
		    (strcmp(name, "permit-X11-forwarding") == 0 ||
		    strcmp(name, "permit-agent-forwarding") == 0 ||
		    strcmp(name, "permit-port-forwarding") == 0 ||
		    strcmp(name, "permit-pty") == 0 ||
		    strcmp(name, "permit-user-rc") == 0 ||
		    strcmp(name, "no-touch-required") == 0)) {
			لکھو("\n");
		} ورنہ اگر (اندر_critical &&
		    (strcmp(name, "force-command") == 0 ||
		    strcmp(name, "source-address") == 0)) {
			اگر ((r = sshbuf_get_cstring(option, &arg, تہی)) != 0)
				fatal_fr(r, "parse critical");
			لکھو(" %s\n", arg);
			آزاد(arg);
		} ورنہ اگر (اندر_critical &&
		    strcmp(name, "verify-required") == 0) {
			لکھو("\n");
		} ورنہ اگر (sshbuf_len(option) > 0) {
			hex = sshbuf_dtob16(option);
			لکھو(" UNKNOWN OPTION: %s (len %zu)\n",
			    hex, sshbuf_len(option));
			sshbuf_reset(option);
			آزاد(hex);
		} ورنہ
			لکھو(" UNKNOWN FLAG OPTION\n");
		آزاد(name);
		اگر (sshbuf_len(option) != 0)
			fatal("Option corrupt: extra data at end");
	}
	sshbuf_free(option);
	sshbuf_free(options);
}

ساکن خالی
print_cert(ساخت sshkey *کلید)
{
	حرف valid[64], *کلید_fp, *ca_fp;
	u_int i;

	کلید_fp = sshkey_fingerprint(کلید, fingerprint_hash, SSH_FP_DEFAULT);
	ca_fp = sshkey_fingerprint(کلید->cert->signature_کلید,
	    fingerprint_hash, SSH_FP_DEFAULT);
	اگر (کلید_fp == تہی || ca_fp == تہی)
		fatal_f("sshkey_fingerprint fail");
	sshkey_format_cert_validity(کلید->cert, valid, حجم(valid));

	لکھو("        Type: %s %s certificate\n", sshkey_ssh_name(کلید),
	    sshkey_cert_type(کلید));
	لکھو("        Public key: %s %s\n", sshkey_type(کلید), کلید_fp);
	لکھو("        Signing CA: %s %s (using %s)\n",
	    sshkey_type(کلید->cert->signature_کلید), ca_fp,
	    کلید->cert->signature_type);
	لکھو("        Key ID: \"%s\"\n", کلید->cert->کلید_id);
	لکھو("        Serial: %llu\n", (غیرعلامتی طویل طویل)کلید->cert->serial);
	لکھو("        Valid: %s\n", valid);
	لکھو("        Principals: ");
	اگر (کلید->cert->nprincipals == 0)
		لکھو("(none)\n");
	ورنہ {
		برائے (i = 0; i < کلید->cert->nprincipals; i++)
			لکھو("\n                %s",
			    کلید->cert->principals[i]);
		لکھو("\n");
	}
	لکھو("        Critical Options: ");
	اگر (sshbuf_len(کلید->cert->critical) == 0)
		لکھو("(none)\n");
	ورنہ {
		لکھو("\n");
		show_options(کلید->cert->critical, 1);
	}
	لکھو("        Extensions: ");
	اگر (sshbuf_len(کلید->cert->extensions) == 0)
		لکھو("(none)\n");
	ورنہ {
		لکھو("\n");
		show_options(کلید->cert->extensions, 0);
	}
	آزاد(کلید_fp);
	آزاد(ca_fp);
}

ساکن خالی
do_show_cert(ساخت passwd *pw)
{
	ساخت sshkey *کلید = تہی;
	ساخت stat st;
	صحیح r, is_stdin = 0, ok = 0;
	FILE *f;
	حرف *cp, *سطر = تہی;
	ثابت حرف *راستہ;
	سائز_t linesize = 0;
	u_long lnum = 0;

	اگر (!have_شناختی_عنصر)
		ask_filename(pw, "Enter file in which the key is");
	اگر (strcmp(شناختی_عنصر_file, "-") != 0 && stat(شناختی_عنصر_file, &st) == -1)
		fatal("%s: %s: %s", __progname, شناختی_عنصر_file, strerror(errno));

	راستہ = شناختی_عنصر_file;
	اگر (strcmp(راستہ, "-") == 0) {
		f = stdin;
		راستہ = "(stdin)";
		is_stdin = 1;
	} ورنہ اگر ((f = fopen(شناختی_عنصر_file, "r")) == تہی)
		fatal("fopen %s: %s", شناختی_عنصر_file, strerror(errno));

	جب (getline(&سطر, &linesize, f) != -1) {
		lnum++;
		sshkey_free(کلید);
		کلید = تہی;
		/* Trim leading space and comments */
		cp = سطر + strspn(سطر, " \t");
		اگر (*cp == '#' || *cp == '\0')
			جاری;
		اگر ((کلید = sshkey_new(کلید_UNSPEC)) == تہی)
			fatal("sshkey_new");
		اگر ((r = sshkey_read(کلید, &cp)) != 0) {
			error_r(r, "%s:%lu: invalid key", راستہ, lnum);
			جاری;
		}
		اگر (!sshkey_is_cert(کلید)) {
			error("%s:%lu is not a certificate", راستہ, lnum);
			جاری;
		}
		ok = 1;
		اگر (!is_stdin && lnum == 1)
			لکھو("%s:\n", راستہ);
		ورنہ
			لکھو("%s:%lu:\n", راستہ, lnum);
		print_cert(کلید);
	}
	آزاد(سطر);
	sshkey_free(کلید);
	fclose(f);
	باہر_نکلو(ok ? 0 : 1);
}

ساکن خالی
بھرو_krl(ثابت حرف *راستہ, ساخت ssh_krl **krlp)
{
	ساخت sshbuf *krlbuf;
	صحیح r;

	اگر ((r = sshbuf_بھرو_file(راستہ, &krlbuf)) != 0)
		fatal_r(r, "Unable to load KRL %s", راستہ);
	/* XXX check sigs */
	اگر ((r = ssh_krl_from_blob(krlbuf, krlp)) != 0 ||
	    *krlp == تہی)
		fatal_r(r, "Invalid KRL file %s", راستہ);
	sshbuf_free(krlbuf);
}

ساکن خالی
hash_مقصد_blob(ثابت حرف *cp, u_char **blobp, سائز_t *lenp,
    ثابت حرف *file, u_long lnum)
{
	حرف *tmp;
	سائز_t tlen;
	ساخت sshbuf *b;
	صحیح r;

	اگر ((cp = strprefix(cp, "SHA256:", 0)) == تہی)
		fatal("%s:%lu: unsupported hash algorithm", file, lnum);

	/*
	 * OpenSSH base64 hashes omit trailing '='
	 * characters; put them back for decode.
	 */
	اگر ((tlen = لڑی_لمبائی(cp)) >= SIZE_MAX - 5)
		fatal_f("hash too long: %zu bytes", tlen);
	tmp = xmalloc(tlen + 4 + 1);
	strlcpy(tmp, cp, tlen + 1);
	جب ((tlen % 4) != 0) {
		tmp[tlen++] = '=';
		tmp[tlen] = '\0';
	}
	اگر ((b = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_b64tod(b, tmp)) != 0)
		fatal_r(r, "%s:%lu: decode hash failed", file, lnum);
	آزاد(tmp);
	*lenp = sshbuf_len(b);
	*blobp = xmalloc(*lenp);
	حافظہ_نقل(*blobp, sshbuf_ptr(b), *lenp);
	sshbuf_free(b);
}

ساکن خالی
update_krl_from_file(ساخت passwd *pw, ثابت حرف *file, صحیح wild_ca,
    ثابت ساخت sshkey *ca, ساخت ssh_krl *krl)
{
	ساخت sshkey *کلید = تہی;
	u_long lnum = 0;
	حرف *راستہ, *cp, *ep, *سطر = تہی;
	u_char *blob = تہی;
	سائز_t blen = 0, linesize = 0;
	غیرعلامتی طویل طویل serial, serial2;
	صحیح i, was_explicit_کلید, was_sha1, was_sha256, was_hash, r;
	FILE *krl_spec;

	راستہ = tilde_expand_filename(file, pw->pw_uid);
	اگر (strcmp(راستہ, "-") == 0) {
		krl_spec = stdin;
		آزاد(راستہ);
		راستہ = xstrdup("(standard input)");
	} ورنہ اگر ((krl_spec = fopen(راستہ, "r")) == تہی)
		fatal("fopen %s: %s", راستہ, strerror(errno));

	اگر (!quiet)
		لکھو("Revoking from %s\n", راستہ);
	جب (getline(&سطر, &linesize, krl_spec) != -1) {
		اگر (linesize >= زیادہ_سے_زیادہ_عدد) {
			fatal_f("%s contains unparsable line, len=%zu",
			    راستہ, linesize);
		}
		lnum++;
		was_explicit_کلید = was_sha1 = was_sha256 = was_hash = 0;
		cp = سطر + strspn(سطر, " \t");
		/* Trim trailing space, comments and strip \n */
		برائے (i = 0, r = -1; cp[i] != '\0'; i++) {
			اگر (cp[i] == '#' || cp[i] == '\n') {
				cp[i] = '\0';
				توڑو;
			}
			اگر (cp[i] == ' ' || cp[i] == '\t') {
				/* Remember the start of a span of whitespace */
				اگر (r == -1)
					r = i;
			} ورنہ
				r = -1;
		}
		اگر (r != -1)
			cp[r] = '\0';
		اگر (*cp == '\0')
			جاری;
		اگر (strncasecmp(cp, "serial:", 7) == 0) {
			اگر (ca == تہی && !wild_ca) {
				fatal("revoking certificates by serial number "
				    "requires specification of a CA key");
			}
			cp += 7;
			cp = cp + strspn(cp, " \t");
			errno = 0;
			serial = strtoull(cp, &ep, 0);
			اگر (*cp == '\0' || (*ep != '\0' && *ep != '-'))
				fatal("%s:%lu: invalid serial \"%s\"",
				    راستہ, lnum, cp);
			اگر (errno == ERANGE && serial == ULLONG_MAX)
				fatal("%s:%lu: serial out of range",
				    راستہ, lnum);
			serial2 = serial;
			اگر (*ep == '-') {
				cp = ep + 1;
				errno = 0;
				serial2 = strtoull(cp, &ep, 0);
				اگر (*cp == '\0' || *ep != '\0')
					fatal("%s:%lu: invalid serial \"%s\"",
					    راستہ, lnum, cp);
				اگر (errno == ERANGE && serial2 == ULLONG_MAX)
					fatal("%s:%lu: serial out of range",
					    راستہ, lnum);
				اگر (serial2 <= serial)
					fatal("%s:%lu: invalid serial range "
					    "%llu:%llu", راستہ, lnum,
					    (غیرعلامتی طویل طویل)serial,
					    (غیرعلامتی طویل طویل)serial2);
			}
			اگر (ssh_krl_revoke_cert_by_serial_range(krl,
			    ca, serial, serial2) != 0) {
				fatal_f("revoke serial failed");
			}
		} ورنہ اگر (strncasecmp(cp, "id:", 3) == 0) {
			اگر (ca == تہی && !wild_ca) {
				fatal("revoking certificates by key ID "
				    "requires specification of a CA key");
			}
			cp += 3;
			cp = cp + strspn(cp, " \t");
			اگر (ssh_krl_revoke_cert_by_کلید_id(krl, ca, cp) != 0)
				fatal_f("revoke key ID failed");
		} ورنہ اگر (strncasecmp(cp, "hash:", 5) == 0) {
			cp += 5;
			cp = cp + strspn(cp, " \t");
			hash_مقصد_blob(cp, &blob, &blen, file, lnum);
			اگر ((r = ssh_krl_revoke_کلید_sha256(krl,
			    blob, blen)) != 0)
				fatal_fr(r, "revoke key failed");
			آزاد(blob);
			blob = تہی;
			blen = 0;
		} ورنہ {
			اگر (strncasecmp(cp, "key:", 4) == 0) {
				cp += 4;
				cp = cp + strspn(cp, " \t");
				was_explicit_کلید = 1;
			} ورنہ اگر (strncasecmp(cp, "sha1:", 5) == 0) {
				cp += 5;
				cp = cp + strspn(cp, " \t");
				was_sha1 = 1;
			} ورنہ اگر (strncasecmp(cp, "sha256:", 7) == 0) {
				cp += 7;
				cp = cp + strspn(cp, " \t");
				was_sha256 = 1;
				/*
				 * Just try to process the line as a key.
				 * Parsing will fail if it isn't.
				 */
			}
			اگر ((کلید = sshkey_new(کلید_UNSPEC)) == تہی)
				fatal("sshkey_new");
			اگر ((r = sshkey_read(کلید, &cp)) != 0)
				fatal_r(r, "%s:%lu: invalid key", راستہ, lnum);
			اگر (was_explicit_کلید)
				r = ssh_krl_revoke_کلید_explicit(krl, کلید);
			ورنہ اگر (was_sha1) {
				اگر (sshkey_fingerprint_raw(کلید,
				    SSH_DIGEST_SHA1, &blob, &blen) != 0) {
					fatal("%s:%lu: fingerprint failed",
					    file, lnum);
				}
				r = ssh_krl_revoke_کلید_sha1(krl, blob, blen);
			} ورنہ اگر (was_sha256) {
				اگر (sshkey_fingerprint_raw(کلید,
				    SSH_DIGEST_SHA256, &blob, &blen) != 0) {
					fatal("%s:%lu: fingerprint failed",
					    file, lnum);
				}
				r = ssh_krl_revoke_کلید_sha256(krl, blob, blen);
			} ورنہ
				r = ssh_krl_revoke_کلید(krl, کلید);
			اگر (r != 0)
				fatal_fr(r, "revoke key failed");
			freezero(blob, blen);
			blob = تہی;
			blen = 0;
			sshkey_free(کلید);
		}
	}
	اگر (strcmp(راستہ, "-") != 0)
		fclose(krl_spec);
	آزاد(سطر);
	آزاد(راستہ);
}

ساکن خالی
do_gen_krl(ساخت passwd *pw, صحیح updating, ثابت حرف *ca_کلید_راستہ,
    غیرعلامتی طویل طویل krl_نسخہ, ثابت حرف *krl_comment,
    صحیح argc, حرف **argv)
{
	ساخت ssh_krl *krl;
	ساخت stat sb;
	ساخت sshkey *ca = تہی;
	صحیح i, r, wild_ca = 0;
	حرف *tmp;
	ساخت sshbuf *kbuf;

	اگر (*شناختی_عنصر_file == '\0')
		fatal("KRL generation requires an output file");
	اگر (stat(شناختی_عنصر_file, &sb) == -1) {
		اگر (errno != ENOENT)
			fatal("Cannot access KRL \"%s\": %s",
			    شناختی_عنصر_file, strerror(errno));
		اگر (updating)
			fatal("KRL \"%s\" does not exist", شناختی_عنصر_file);
	}
	اگر (ca_کلید_راستہ != تہی) {
		اگر (strcasecmp(ca_کلید_راستہ, "none") == 0)
			wild_ca = 1;
		ورنہ {
			tmp = tilde_expand_filename(ca_کلید_راستہ, pw->pw_uid);
			اگر ((r = sshkey_بھرو_عوامی(tmp, &ca, تہی)) != 0)
				fatal_r(r, "Cannot load CA public key %s", tmp);
			آزاد(tmp);
		}
	}

	اگر (updating)
		بھرو_krl(شناختی_عنصر_file, &krl);
	ورنہ اگر ((krl = ssh_krl_init()) == تہی)
		fatal("couldn't create KRL");

	اگر (krl_نسخہ != 0)
		ssh_krl_سیٹ_نسخہ(krl, krl_نسخہ);
	اگر (krl_comment != تہی)
		ssh_krl_سیٹ_comment(krl, krl_comment);

	برائے (i = 0; i < argc; i++)
		update_krl_from_file(pw, argv[i], wild_ca, ca, krl);

	اگر ((kbuf = sshbuf_new()) == تہی)
		fatal("sshbuf_new failed");
	اگر (ssh_krl_مقصد_blob(krl, kbuf) != 0)
		fatal("Couldn't generate KRL");
	اگر ((r = sshbuf_write_file(شناختی_عنصر_file, kbuf)) != 0)
		fatal("write %s: %s", شناختی_عنصر_file, strerror(errno));
	sshbuf_free(kbuf);
	ssh_krl_free(krl);
	sshkey_free(ca);
}

ساکن خالی
do_check_krl(ساخت passwd *pw, صحیح print_krl, صحیح argc, حرف **argv)
{
	صحیح i, r, ret = 0;
	حرف *comment;
	ساخت ssh_krl *krl;
	ساخت sshkey *k;

	اگر (*شناختی_عنصر_file == '\0')
		fatal("KRL checking requires an input file");
	بھرو_krl(شناختی_عنصر_file, &krl);
	اگر (print_krl)
		krl_dump(krl, stdout);
	برائے (i = 0; i < argc; i++) {
		اگر ((r = sshkey_بھرو_عوامی(argv[i], &k, &comment)) != 0)
			fatal_r(r, "Cannot load public key %s", argv[i]);
		r = ssh_krl_check_کلید(krl, k);
		لکھو("%s%s%s%s: %s\n", argv[i],
		    *comment ? " (" : "", comment, *comment ? ")" : "",
		    r == 0 ? "ok" : "REVOKED");
		اگر (r != 0)
			ret = 1;
		sshkey_free(k);
		آزاد(comment);
	}
	ssh_krl_free(krl);
	باہر_نکلو(ret);
}

ساکن ساخت sshkey *
بھرو_sign_کلید(ثابت حرف *keypath, ثابت ساخت sshkey *pubkey)
{
	سائز_t i, slen, plen = لڑی_لمبائی(keypath);
	حرف *privpath = xstrdup(keypath);
	ساکن ثابت حرف * ثابت suffixes[] = { "-cert.pub", ".pub", تہی };
	ساخت sshkey *ret = تہی, *privkey = تہی;
	صحیح r, waspub = 0;
	ساخت stat st;

	/*
	 * If passed a public key filename, then try to locate the corresponding
	 * private key. This lets us specify certificates on the command-line
	 * and have ssh-keygen find the appropriate private key.
	 */
	برائے (i = 0; suffixes[i]; i++) {
		slen = لڑی_لمبائی(suffixes[i]);
		اگر (plen <= slen ||
		    strcmp(privpath + plen - slen, suffixes[i]) != 0)
			جاری;
		privpath[plen - slen] = '\0';
		debug_f("%s looks like a public key, using private key "
		    "path %s instead", keypath, privpath);
		waspub = 1;
	}
	اگر (waspub && stat(privpath, &st) != 0 && errno == ENOENT)
		fatal("No private key found for public key \"%s\"", keypath);
	اگر ((r = sshkey_بھرو_نجی(privpath, "", &privkey, تہی)) != 0 &&
	    (r != SSH_ERR_کلید_WRONG_PASSPHRASE)) {
		debug_fr(r, "load private key \"%s\"", privpath);
		fatal("No private key found for \"%s\"", privpath);
	} ورنہ اگر (privkey == تہی)
		privkey = بھرو_شناختی_عنصر(privpath, تہی);

	اگر (!sshkey_equal_عوامی(pubkey, privkey)) {
		error("Public key %s doesn't match private %s",
		    keypath, privpath);
		جاؤ مکمل;
	}
	اگر (sshkey_is_cert(pubkey) && !sshkey_is_cert(privkey)) {
		/*
		 * Graft the certificate onto the private key to make
		 * it capable of signing.
		 */
		اگر ((r = sshkey_مقصد_certified(privkey)) != 0) {
			error_fr(r, "sshkey_to_certified");
			جاؤ مکمل;
		}
		اگر ((r = sshkey_cert_copy(pubkey, privkey)) != 0) {
			error_fr(r, "sshkey_cert_copy");
			جاؤ مکمل;
		}
	}
	/* success */
	ret = privkey;
	privkey = تہی;
 مکمل:
	sshkey_free(privkey);
	آزاد(privpath);
	واپس ret;
}

ساکن صحیح
sign_one(ساخت sshkey *signkey, ثابت حرف *filename, صحیح fd,
    ثابت حرف *sig_namespace, ثابت حرف *hashalg, sshsig_signer *signer,
    خالی *signer_ctx)
{
	ساخت sshbuf *sigbuf = تہی, *abuf = تہی;
	صحیح r = SSH_ERR_اندرونی_ERROR, wfd = -1, oerrno;
	حرف *wfile = تہی, *asig = تہی, *fp = تہی;
	حرف *pin = تہی, *prompt = تہی;

	اگر (!quiet) {
		اگر (fd == STDIN_FILENO)
			fprintf(stderr, "Signing data on standard input\n");
		ورنہ
			fprintf(stderr, "Signing file %s\n", filename);
	}
	اگر (signer == تہی && sshkey_is_sk(signkey)) {
		اگر ((signkey->sk_flags & SSH_SK_USER_VERIFICATION_REQD)) {
			xasprintf(&prompt, "Enter PIN for %s key: ",
			    sshkey_type(signkey));
			اگر ((pin = read_passphrase(prompt,
			    RP_ALLOW_STDIN)) == تہی)
				fatal_f("couldn't read PIN");
		}
		اگر ((signkey->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
			اگر ((fp = sshkey_fingerprint(signkey, fingerprint_hash,
			    SSH_FP_DEFAULT)) == تہی)
				fatal_f("fingerprint failed");
			fprintf(stderr, "Confirm user presence for key %s %s\n",
			    sshkey_type(signkey), fp);
			آزاد(fp);
		}
	}
	اگر ((r = sshsig_sign_fd(signkey, hashalg, sk_provider, pin,
	    fd, sig_namespace, &sigbuf, signer, signer_ctx)) != 0) {
		error_r(r, "Signing %s failed", filename);
		جاؤ برآمد;
	}
	اگر ((r = sshsig_armor(sigbuf, &abuf)) != 0) {
		error_fr(r, "sshsig_armor");
		جاؤ برآمد;
	}
	اگر ((asig = sshbuf_dup_string(abuf)) == تہی) {
		error_f("buffer error");
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}

	اگر (fd == STDIN_FILENO) {
		fputs(asig, stdout);
		fflush(stdout);
	} ورنہ {
		xasprintf(&wfile, "%s.sig", filename);
		اگر (confirm_overwrite(wfile)) {
			اگر ((wfd = open(wfile, O_WRONLY|O_CREAT|O_TRUNC,
			    0666)) == -1) {
				oerrno = errno;
				error("Cannot open %s: %s",
				    wfile, strerror(errno));
				errno = oerrno;
				r = SSH_ERR_SYSTEM_ERROR;
				جاؤ برآمد;
			}
			اگر (atomicio(vwrite, wfd, asig,
			    لڑی_لمبائی(asig)) != لڑی_لمبائی(asig)) {
				oerrno = errno;
				error("Cannot write to %s: %s",
				    wfile, strerror(errno));
				errno = oerrno;
				r = SSH_ERR_SYSTEM_ERROR;
				جاؤ برآمد;
			}
			اگر (!quiet) {
				fprintf(stderr, "Write signature to %s\n",
				    wfile);
			}
		}
	}
	/* success */
	r = 0;
 برآمد:
	آزاد(wfile);
	آزاد(prompt);
	آزاد(asig);
	اگر (pin != تہی)
		freezero(pin, لڑی_لمبائی(pin));
	sshbuf_free(abuf);
	sshbuf_free(sigbuf);
	اگر (wfd != -1)
		close(wfd);
	واپس r;
}

ساکن صحیح
sig_process_opts(حرف * ثابت *opts, سائز_t nopts, حرف **hashalgp,
    uint64_t *verify_timep, صحیح *print_pubkey)
{
	سائز_t i;
	time_t now;
	ثابت حرف *p;

	اگر (verify_timep != تہی)
		*verify_timep = 0;
	اگر (print_pubkey != تہی)
		*print_pubkey = 0;
	اگر (hashalgp != تہی)
		*hashalgp = تہی;
	برائے (i = 0; i < nopts; i++) {
		اگر (hashalgp != تہی &&
		    (p = strprefix(opts[i], "hashalg=", 1)) != تہی) {
			*hashalgp = xstrdup(p);
		} ورنہ اگر (verify_timep &&
		    (p = strprefix(opts[i], "verify-time=", 1)) != تہی) {
			اگر (parse_absolute_وقت(p, verify_timep) != 0 ||
			    *verify_timep == 0) {
				error("Invalid \"verify-time\" option");
				واپس SSH_ERR_INVALID_دلیل;
			}
		} ورنہ اگر (print_pubkey &&
		    strcasecmp(opts[i], "print-pubkey") == 0) {
			*print_pubkey = 1;
		} ورنہ {
			error("Invalid option \"%s\"", opts[i]);
			واپس SSH_ERR_INVALID_دلیل;
		}
	}
	اگر (verify_timep && *verify_timep == 0) {
		اگر ((now = time(تہی)) < 0) {
			error("Time is before epoch");
			واپس SSH_ERR_INVALID_دلیل;
		}
		*verify_timep = (uint64_t)now;
	}
	واپس 0;
}


ساکن صحیح
sig_sign(ثابت حرف *keypath, ثابت حرف *sig_namespace, صحیح require_agent,
    صحیح argc, حرف **argv, حرف * ثابت *opts, سائز_t nopts)
{
	صحیح i, fd = -1, r, ret = -1;
	صحیح agent_fd = -1;
	ساخت sshkey *pubkey = تہی, *privkey = تہی, *signkey = تہی;
	sshsig_signer *signer = تہی;
	حرف *hashalg = تہی;

	/* Check file arguments. */
	برائے (i = 0; i < argc; i++) {
		اگر (strcmp(argv[i], "-") != 0)
			جاری;
		اگر (i > 0 || argc > 1)
			fatal("Cannot sign mix of paths and standard input");
	}

	اگر (sig_process_opts(opts, nopts, &hashalg, تہی, تہی) != 0)
		جاؤ مکمل; /* error already logged */

	اگر ((r = sshkey_بھرو_عوامی(keypath, &pubkey, تہی)) != 0) {
		error_r(r, "Couldn't load public key %s", keypath);
		جاؤ مکمل;
	}

	اگر ((r = ssh_get_authentication_socket(&agent_fd)) != 0) {
		اگر (require_agent)
			fatal("Couldn't get agent socket");
		debug_r(r, "Couldn't get agent socket");
	} ورنہ {
		اگر ((r = ssh_agent_has_کلید(agent_fd, pubkey)) == 0)
			signer = agent_signer;
		ورنہ {
			اگر (require_agent)
				fatal("Couldn't find key in agent");
			debug_r(r, "Couldn't find key in agent");
		}
	}

	اگر (signer == تہی) {
		/* Not using agent - try to load private key */
		اگر ((privkey = بھرو_sign_کلید(keypath, pubkey)) == تہی)
			جاؤ مکمل;
		signkey = privkey;
	} ورنہ {
		/* Will use key in agent */
		signkey = pubkey;
	}

	اگر (argc == 0) {
		اگر ((r = sign_one(signkey, "(stdin)", STDIN_FILENO,
		    sig_namespace, hashalg, signer, &agent_fd)) != 0)
			جاؤ مکمل;
	} ورنہ {
		برائے (i = 0; i < argc; i++) {
			اگر (strcmp(argv[i], "-") == 0)
				fd = STDIN_FILENO;
			ورنہ اگر ((fd = open(argv[i], O_RDONLY)) == -1) {
				error("Cannot open %s for signing: %s",
				    argv[i], strerror(errno));
				جاؤ مکمل;
			}
			اگر ((r = sign_one(signkey, argv[i], fd, sig_namespace,
			    hashalg, signer, &agent_fd)) != 0)
				جاؤ مکمل;
			اگر (fd != STDIN_FILENO)
				close(fd);
			fd = -1;
		}
	}

	ret = 0;
مکمل:
	اگر (fd != -1 && fd != STDIN_FILENO)
		close(fd);
	sshkey_free(pubkey);
	sshkey_free(privkey);
	آزاد(hashalg);
	واپس ret;
}

ساکن صحیح
sig_verify(ثابت حرف *signature, ثابت حرف *sig_namespace,
    ثابت حرف *principal, ثابت حرف *allowed_کلیدیں, ثابت حرف *revoked_کلیدیں,
    حرف * ثابت *opts, سائز_t nopts)
{
	صحیح r, ret = -1;
	صحیح print_pubkey = 0;
	ساخت sshbuf *sigbuf = تہی, *abuf = تہی;
	ساخت sshkey *sign_کلید = تہی;
	حرف *fp = تہی;
	ساخت sshkey_sig_details *sig_details = تہی;
	uint64_t verify_وقت = 0;

	اگر (sig_process_opts(opts, nopts, تہی, &verify_وقت,
	    &print_pubkey) != 0)
		جاؤ مکمل; /* error already logged */

	memset(&sig_details, 0, حجم(sig_details));
	اگر ((r = sshbuf_بھرو_file(signature, &abuf)) != 0) {
		error_r(r, "Couldn't read signature file");
		جاؤ مکمل;
	}

	اگر ((r = sshsig_dearmor(abuf, &sigbuf)) != 0) {
		error_fr(r, "sshsig_armor");
		جاؤ مکمل;
	}
	اگر ((r = sshsig_verify_fd(sigbuf, STDIN_FILENO, sig_namespace,
	    &sign_کلید, &sig_details)) != 0)
		جاؤ مکمل; /* sshsig_verify() prints error */

	اگر ((fp = sshkey_fingerprint(sign_کلید, fingerprint_hash,
	    SSH_FP_DEFAULT)) == تہی)
		fatal_f("sshkey_fingerprint failed");
	debug("Valid (unverified) signature from key %s", fp);
	اگر (sig_details != تہی) {
		debug2_f("signature details: counter = %u, flags = 0x%02x",
		    sig_details->sk_شمار, sig_details->sk_flags);
	}
	آزاد(fp);
	fp = تہی;

	اگر (revoked_کلیدیں != تہی) {
		اگر ((r = sshkey_check_revoked(sign_کلید, revoked_کلیدیں)) != 0) {
			debug3_fr(r, "sshkey_check_revoked");
			جاؤ مکمل;
		}
	}

	اگر (allowed_کلیدیں != تہی && (r = sshsig_check_allowed_کلیدیں(allowed_کلیدیں,
	    sign_کلید, principal, sig_namespace, verify_وقت)) != 0) {
		debug3_fr(r, "sshsig_check_allowed_keys");
		جاؤ مکمل;
	}
	/* success */
	ret = 0;
مکمل:
	اگر (!quiet) {
		اگر (ret == 0) {
			اگر ((fp = sshkey_fingerprint(sign_کلید, fingerprint_hash,
			    SSH_FP_DEFAULT)) == تہی)
				fatal_f("sshkey_fingerprint failed");
			اگر (principal == تہی) {
				لکھو("Good \"%s\" signature with %s key %s\n",
				    sig_namespace, sshkey_type(sign_کلید), fp);

			} ورنہ {
				لکھو("Good \"%s\" signature for %s with %s key %s\n",
				    sig_namespace, principal,
				    sshkey_type(sign_کلید), fp);
			}
		} ورنہ {
			لکھو("Could not verify signature.\n");
		}
	}
	/* Print the signature key if requested */
	اگر (ret == 0 && print_pubkey && sign_کلید != تہی) {
		اگر ((r = sshkey_write(sign_کلید, stdout)) == 0)
			fputc('\n', stdout);
		ورنہ {
			error_r(r, "Could not print public key.\n");
			ret = -1;
		}
	}
	sshbuf_free(sigbuf);
	sshbuf_free(abuf);
	sshkey_free(sign_کلید);
	sshkey_sig_details_free(sig_details);
	آزاد(fp);
	واپس ret;
}

ساکن صحیح
sig_ڈھونڈو_principals(ثابت حرف *signature, ثابت حرف *allowed_کلیدیں,
    حرف * ثابت *opts, سائز_t nopts)
{
	صحیح r, ret = -1;
	ساخت sshbuf *sigbuf = تہی, *abuf = تہی;
	ساخت sshkey *sign_کلید = تہی;
	حرف *principals = تہی, *cp, *tmp;
	uint64_t verify_وقت = 0;

	اگر (sig_process_opts(opts, nopts, تہی, &verify_وقت, تہی) != 0)
		جاؤ مکمل; /* error already logged */

	اگر ((r = sshbuf_بھرو_file(signature, &abuf)) != 0) {
		error_r(r, "Couldn't read signature file");
		جاؤ مکمل;
	}
	اگر ((r = sshsig_dearmor(abuf, &sigbuf)) != 0) {
		error_fr(r, "sshsig_armor");
		جاؤ مکمل;
	}
	اگر ((r = sshsig_get_pubkey(sigbuf, &sign_کلید)) != 0) {
		error_fr(r, "sshsig_get_pubkey");
		جاؤ مکمل;
	}
	اگر ((r = sshsig_ڈھونڈو_principals(allowed_کلیدیں, sign_کلید,
	    verify_وقت, &principals)) != 0) {
		اگر (r != SSH_ERR_کلید_NOT_ملا)
			error_fr(r, "sshsig_find_principal");
		جاؤ مکمل;
	}
	ret = 0;
مکمل:
	اگر (ret == 0 ) {
		/* Emit matching principals one per line */
		tmp = principals;
		جب ((cp = strsep(&tmp, ",")) != تہی && *cp != '\0')
			puts(cp);
	} ورنہ {
		fprintf(stderr, "No principal matched.\n");
	}
	sshbuf_free(sigbuf);
	sshbuf_free(abuf);
	sshkey_free(sign_کلید);
	آزاد(principals);
	واپس ret;
}

ساکن صحیح
sig_مطابقت_principals(ثابت حرف *allowed_کلیدیں, حرف *principal,
	حرف * ثابت *opts, سائز_t nopts)
{
	صحیح r;
	حرف **principals = تہی;
	سائز_t i, nprincipals = 0;

	اگر ((r = sig_process_opts(opts, nopts, تہی, تہی, تہی)) != 0)
		واپس r; /* error already logged */

	اگر ((r = sshsig_مطابقت_principals(allowed_کلیدیں, principal,
	    &principals, &nprincipals)) != 0) {
		debug_f("match: %s", ssh_err(r));
		fprintf(stderr, "No principal matched.\n");
		واپس r;
	}
	برائے (i = 0; i < nprincipals; i++) {
		لکھو("%s\n", principals[i]);
		آزاد(principals[i]);
	}
	آزاد(principals);

	واپس 0;
}

ساکن خالی
do_moduli_gen(ثابت حرف *برآمد_file, حرف **opts, سائز_t nopts)
{
#اگر_تعریف_شدہ WITH_OPENSSL
	/* Moduli generation/screening */
	BIGNUM *آغاز = تہی;
	صحیح moduli_بٹ = 0;
	FILE *برآمد;
	سائز_t i;
	ثابت حرف *errstr, *p;

	/* Parse options */
	برائے (i = 0; i < nopts; i++) {
		اگر ((p = strprefix(opts[i], "start=", 0)) != تہی) {
			/* XXX - also compare length against bits */
			اگر (BN_hex2bn(&آغاز, p) == 0)
				fatal("Invalid start point.");
		} ورنہ اگر ((p = strprefix(opts[i], "bits=", 0)) != تہی) {
			moduli_بٹ = (صحیح)strtonum(p, 1, زیادہ_سے_زیادہ_عدد, &errstr);
			اگر (errstr) {
				fatal("Invalid number: %s (%s)", p, errstr);
			}
		} ورنہ {
			fatal("Option \"%s\" is unsupported for moduli "
			    "generation", opts[i]);
		}
	}

	اگر (strcmp(برآمد_file, "-") == 0)
		برآمد = stdout;
	ورنہ اگر ((برآمد = fopen(برآمد_file, "w")) == تہی) {
		fatal("Couldn't open modulus candidate file \"%s\": %s",
		    برآمد_file, strerror(errno));
	}
	setvbuf(برآمد, تہی, _IOLBF, 0);

	اگر (moduli_بٹ == 0)
		moduli_بٹ = DEFAULT_بٹ;
	اگر (gen_candidates(برآمد, moduli_بٹ, آغاز) != 0)
		fatal("modulus candidate generation failed");
#ورنہ /* WITH_OPENSSL */
	fatal("Moduli generation is not supported");
#اگر_ختم /* WITH_OPENSSL */
}

ساکن خالی
do_moduli_screen(ثابت حرف *برآمد_file, حرف **opts, سائز_t nopts)
{
#اگر_تعریف_شدہ WITH_OPENSSL
	/* Moduli generation/screening */
	حرف *checkpoint = تہی;
	uint32_t generator_wanted = 0;
	غیرعلامتی طویل آغاز_lineno = 0, سطریں_مقصد_process = 0;
	صحیح مفرد_tests = 0;
	FILE *برآمد, *اندر = stdin;
	سائز_t i;
	ثابت حرف *errstr, *p;

	/* Parse options */
	برائے (i = 0; i < nopts; i++) {
		اگر ((p = strprefix(opts[i], "lines=", 0)) != تہی) {
			سطریں_مقصد_process = strtoul(p, تہی, 10);
		} ورنہ اگر ((p = strprefix(opts[i], "start-line=", 0)) != تہی) {
			آغاز_lineno = strtoul(p, تہی, 10);
		} ورنہ اگر ((p = strprefix(opts[i], "checkpoint=", 0)) != تہی) {
			آزاد(checkpoint);
			checkpoint = xstrdup(p);
		} ورنہ اگر ((p = strprefix(opts[i], "generator=", 0)) != تہی) {
			generator_wanted = (uint32_t)strtonum(p, 1, UINT_MAX,
			    &errstr);
			اگر (errstr != تہی) {
				fatal("Generator invalid: %s (%s)", p, errstr);
			}
		} ورنہ اگر ((p = strprefix(opts[i], "prime-tests=", 0)) != تہی) {
			مفرد_tests = (صحیح)strtonum(p, 1, زیادہ_سے_زیادہ_عدد, &errstr);
			اگر (errstr) {
				fatal("Invalid number: %s (%s)", p, errstr);
			}
		} ورنہ {
			fatal("Option \"%s\" is unsupported for moduli "
			    "screening", opts[i]);
		}
	}

	اگر (have_شناختی_عنصر && strcmp(شناختی_عنصر_file, "-") != 0) {
		اگر ((اندر = fopen(شناختی_عنصر_file, "r")) == تہی) {
			fatal("Couldn't open modulus candidate "
			    "file \"%s\": %s", شناختی_عنصر_file,
			    strerror(errno));
		}
	}

	اگر (strcmp(برآمد_file, "-") == 0)
		برآمد = stdout;
	ورنہ اگر ((برآمد = fopen(برآمد_file, "a")) == تہی) {
		fatal("Couldn't open moduli file \"%s\": %s",
		    برآمد_file, strerror(errno));
	}
	setvbuf(برآمد, تہی, _IOLBF, 0);
	اگر (مفرد_test(اندر, برآمد, مفرد_tests == 0 ? 100 : مفرد_tests,
	    generator_wanted, checkpoint,
	    آغاز_lineno, سطریں_مقصد_process) != 0)
		fatal("modulus screening failed");
	اگر (اندر != stdin)
		(خالی)fclose(اندر);
	آزاد(checkpoint);
#ورنہ /* WITH_OPENSSL */
	fatal("Moduli screening is not supported");
#اگر_ختم /* WITH_OPENSSL */
}

/* Read and confirm a passphrase */
ساکن حرف *
read_check_passphrase(ثابت حرف *prompt1, ثابت حرف *prompt2,
    ثابت حرف *retry_prompt)
{
	حرف *passphrase1, *passphrase2;

	برائے (;;) {
		passphrase1 = read_passphrase(prompt1, RP_ALLOW_STDIN);
		passphrase2 = read_passphrase(prompt2, RP_ALLOW_STDIN);
		اگر (strcmp(passphrase1, passphrase2) == 0) {
			freezero(passphrase2, لڑی_لمبائی(passphrase2));
			واپس passphrase1;
		}
		/* The passphrases do not match. Clear them and retry. */
		freezero(passphrase1, لڑی_لمبائی(passphrase1));
		freezero(passphrase2, لڑی_لمبائی(passphrase2));
		fputs(retry_prompt, stdout);
		fputc('\n', stdout);
		fflush(stdout);
	}
	/* NOTREACHED */
	واپس تہی;
}

ساکن حرف *
نجی_کلید_passphrase(ثابت حرف *راستہ)
{
	حرف *prompt, *ret;

	اگر (شناختی_عنصر_passphrase)
		واپس xstrdup(شناختی_عنصر_passphrase);
	اگر (شناختی_عنصر_new_passphrase)
		واپس xstrdup(شناختی_عنصر_new_passphrase);

	xasprintf(&prompt, "Enter passphrase for \"%s\" "
	    "(empty for no passphrase): ", راستہ);
	ret = read_check_passphrase(prompt,
	    "Enter same passphrase again: ",
	    "Passphrases do not match.  Try again.");
	آزاد(prompt);
	واپس ret;
}

ساکن حرف *
sk_suffix(ثابت حرف *application, ثابت uint8_t *user, سائز_t userlen)
{
	حرف *ret, *cp;
	ثابت حرف *p;
	سائز_t slen, i;

	/* Trim off URL-like preamble */
	اگر ((p = strprefix(application, "ssh://", 0)) != تہی)
		ret =  xstrdup(p);
	ورنہ اگر ((p = strprefix(application, "ssh:", 0)) != تہی)
		ret =  xstrdup(p);
	ورنہ
		ret = xstrdup(application);

	/* Count trailing zeros in user */
	برائے (i = 0; i < userlen; i++) {
		اگر (user[userlen - i - 1] != 0)
			توڑو;
	}
	اگر (i >= userlen)
		واپس ret; /* user-id was default all-zeros */

	/* Append user-id, escaping non-UTF-8 characters */
	slen = userlen - i;
	اگر (asmprintf(&cp, زیادہ_سے_زیادہ_عدد, تہی, "%.*s", (صحیح)slen, user) == -1)
		fatal_f("asmprintf failed");
	/* Don't emit a user-id that contains path or control characters */
	اگر (strchr(cp, '/') != تہی || لڑی_تلاش(cp, "..") != تہی ||
	    strchr(cp, '\\') != تہی) {
		آزاد(cp);
		cp = tohex(user, slen);
	}
	xextendf(&ret, "_", "%s", cp);
	آزاد(cp);
	واپس ret;
}

ساکن صحیح
do_download_sk(ثابت حرف *skprovider, ثابت حرف *device)
{
	ساخت sshsk_resident_کلید **srks;
	سائز_t nsrks, i;
	صحیح r, ret = -1;
	حرف *fp, *pin = تہی, *pass = تہی, *راستہ, *pubpath;
	ثابت حرف *ext;
	ساخت sshkey *کلید;

	اگر (skprovider == تہی)
		fatal("Cannot download keys without provider");

	pin = read_passphrase("Enter PIN for authenticator: ", RP_ALLOW_STDIN);
	اگر (!quiet) {
		لکھو("You may need to touch your authenticator "
		    "to authorize key download.\n");
	}
	اگر ((r = sshsk_بھرو_resident(skprovider, device, pin, 0,
	    &srks, &nsrks)) != 0) {
		اگر (pin != تہی)
			freezero(pin, لڑی_لمبائی(pin));
		error_r(r, "Unable to load resident keys");
		واپس -1;
	}
	اگر (nsrks == 0)
		logit("No keys to download");
	اگر (pin != تہی)
		freezero(pin, لڑی_لمبائی(pin));

	برائے (i = 0; i < nsrks; i++) {
		کلید = srks[i]->کلید;
		اگر (کلید->type != کلید_ECDSA_SK && کلید->type != کلید_ED25519_SK) {
			error("Unsupported key type %s (%d)",
			    sshkey_type(کلید), کلید->type);
			جاری;
		}
		اگر ((fp = sshkey_fingerprint(کلید, fingerprint_hash,
		    SSH_FP_DEFAULT)) == تہی)
			fatal_f("sshkey_fingerprint failed");
		debug_f("key %zu: %s %s %s (flags 0x%02x)", i,
		    sshkey_type(کلید), fp, کلید->sk_application, کلید->sk_flags);
		ext = sk_suffix(کلید->sk_application,
		    srks[i]->user_id, srks[i]->user_id_len);
		xasprintf(&راستہ, "id_%s_rk%s%s",
		    کلید->type == کلید_ECDSA_SK ? "ecdsa_sk" : "ed25519_sk",
		    *ext == '\0' ? "" : "_", ext);

		/* If the file already exists, ask the user to confirm. */
		اگر (!confirm_overwrite(راستہ)) {
			آزاد(راستہ);
			توڑو;
		}

		/* Save the key with the application string as the comment */
		اگر (pass == تہی)
			pass = نجی_کلید_passphrase(راستہ);
		اگر ((r = sshkey_save_نجی(کلید, راستہ, pass,
		    کلید->sk_application, نجی_کلید_format,
		    openssh_format_cipher, دور)) != 0) {
			error_r(r, "Saving key \"%s\" failed", راستہ);
			آزاد(راستہ);
			توڑو;
		}
		اگر (!quiet) {
			لکھو("Saved %s key%s%s to %s\n", sshkey_type(کلید),
			    *ext != '\0' ? " " : "",
			    *ext != '\0' ? کلید->sk_application : "",
			    راستہ);
		}

		/* Save public key too */
		xasprintf(&pubpath, "%s.pub", راستہ);
		آزاد(راستہ);
		اگر ((r = sshkey_save_عوامی(کلید, pubpath,
		    کلید->sk_application)) != 0) {
			error_r(r, "Saving public key \"%s\" failed", pubpath);
			آزاد(pubpath);
			توڑو;
		}
		آزاد(pubpath);
	}

	اگر (i >= nsrks)
		ret = 0; /* success */
	اگر (pass != تہی)
		freezero(pass, لڑی_لمبائی(pass));
	sshsk_free_resident_کلیدیں(srks, nsrks);
	واپس ret;
}

ساکن خالی
save_attestation(ساخت sshbuf *attest, ثابت حرف *راستہ)
{
	منوال_t omask;
	صحیح r;

	اگر (راستہ == تہی)
		واپس; /* nothing to do */
	اگر (attest == تہی || sshbuf_len(attest) == 0)
		fatal("Enrollment did not return attestation data");
	omask = umask(077);
	r = sshbuf_write_file(راستہ, attest);
	umask(omask);
	اگر (r != 0)
		fatal_r(r, "Unable to write attestation data \"%s\"", راستہ);
	اگر (!quiet)
		لکھو("Your FIDO attestation certificate has been saved in "
		    "%s\n", راستہ);
}

ساکن صحیح
confirm_sk_overwrite(ثابت حرف *application, ثابت حرف *user)
{
	حرف yesno[3];

	لکھو("A resident key scoped to '%s' with user id '%s' already "
	    "exists.\n", application == تہی ? "ssh:" : application,
	    user == تہی ? "null" : user);
	لکھو("Overwrite key in token (y/n)? ");
	fflush(stdout);
	اگر (fgets(yesno, حجم(yesno), stdin) == تہی)
		واپس 0;
	اگر (yesno[0] != 'y' && yesno[0] != 'Y')
		واپس 0;
	واپس 1;
}

ساکن خالی
usage(خالی)
{
	fprintf(stderr,
	    "usage: ssh-keygen [-q] [-a rounds] [-b bits] [-C comment] [-f output_keyfile]\n"
	    "                  [-m format] [-N new_passphrase] [-O option]\n"
	    "                  [-t ecdsa|ecdsa-sk|ed25519|ed25519-sk|mldsa44-ed25519|rsa]\n"
	    "                  [-w provider] [-Z cipher]\n"
	    "       ssh-keygen -p [-a rounds] [-f keyfile] [-m format] [-N new_passphrase]\n"
	    "                   [-P old_passphrase] [-Z cipher]\n"
#اگر_تعریف_شدہ WITH_OPENSSL
	    "       ssh-keygen -i [-f input_keyfile] [-m key_format]\n"
	    "       ssh-keygen -e [-f input_keyfile] [-m key_format]\n"
#اگر_ختم
	    "       ssh-keygen -y [-f input_keyfile]\n"
	    "       ssh-keygen -c [-a rounds] [-C comment] [-f keyfile] [-P passphrase]\n"
	    "       ssh-keygen -l [-v] [-E fingerprint_hash] [-f input_keyfile]\n"
	    "       ssh-keygen -B [-f input_keyfile]\n");
#اگر_تعریف_شدہ ENABLE_PKCS11
	fprintf(stderr,
	    "       ssh-keygen -D pkcs11\n");
#اگر_ختم
	fprintf(stderr,
	    "       ssh-keygen -F hostname [-lv] [-f known_hosts_file]\n"
	    "       ssh-keygen -H [-f known_hosts_file]\n"
	    "       ssh-keygen -K [-a rounds] [-w provider]\n"
	    "       ssh-keygen -R hostname [-f known_hosts_file]\n"
	    "       ssh-keygen -r hostname [-g] [-f input_keyfile]\n"
#اگر_تعریف_شدہ WITH_OPENSSL
	    "       ssh-keygen -M generate [-O option] output_file\n"
	    "       ssh-keygen -M screen [-f input_file] [-O option] output_file\n"
#اگر_ختم
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
	باہر_نکلو(1);
}

/*
 * Main program for key management.
 */
صحیح
مین(صحیح argc, حرف **argv)
{
	حرف comment[کلید_COMMENT_MAX], *passphrase = تہی;
	حرف *rr_hostname = تہی, *ep, *fp, *ra;
	ساخت sshkey *نجی = تہی, *عوامی = تہی;
	ساخت passwd *pw;
	صحیح ret = 0, r, opt, type;
	صحیح change_passphrase = 0, change_comment = 0, show_cert = 0;
	صحیح ڈھونڈو_host = 0, delete_host = 0, hash_hosts = 0;
	صحیح gen_all_hostkeys = 0, gen_krl = 0, update_krl = 0, check_krl = 0;
	صحیح prefer_agent = 0, convert_مقصد = 0, convert_from = 0;
	صحیح print_عوامی = 0, print_generic = 0, cert_serial_autoinc = 0;
	صحیح do_gen_candidates = 0, do_screen_candidates = 0, download_sk = 0;
	غیرعلامتی طویل طویل cert_serial = 0;
	حرف *شناختی_عنصر_comment = تہی, *ca_کلید_راستہ = تہی, **opts = تہی;
	حرف *sk_application = تہی, *sk_device = تہی, *sk_user = تہی;
	حرف *sk_attestation_راستہ = تہی;
	ساخت sshbuf *challenge = تہی, *attest = تہی;
	سائز_t i, nopts = 0;
	uint32_t بٹ = 0;
	uint8_t sk_flags = SSH_SK_USER_PRESENCE_REQD;
	ثابت حرف *errstr, *p;
	صحیح log_level = SYSLOG_LEVEL_INFO;
	حرف *sign_op = تہی;

	خارجی صحیح optind;
	خارجی حرف *optarg;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	__progname = ssh_get_progname(argv[0]);

	بیج_rng();

	log_init(argv[0], SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_USER, 1);

	msetlocale();

	/* we need this for the home * directory.  */
	pw = getpwuid(getuid());
	اگر (!pw)
		fatal("No user exists for uid %lu", (u_long)getuid());
	pw = pwcopy(pw);
	اگر (gethostname(hostname, حجم(hostname)) == -1)
		fatal("gethostname: %s", strerror(errno));

	sk_provider = getenv("SSH_SK_PROVIDER");

	/* Remaining characters: dGjJSTWx */
	جب ((opt = getopt(argc, argv, "ABHKLQUXceghiklopquvy"
	    "C:D:E:F:I:M:N:O:P:R:V:Y:Z:"
	    "a:b:f:g:m:n:r:s:t:w:z:")) != -1) {
		انتخاب (opt) {
		حالت 'A':
			gen_all_hostkeys = 1;
			توڑو;
		حالت 'b':
			بٹ = (uint32_t)strtonum(optarg, 1, UINT32_MAX,
			    &errstr);
			اگر (errstr)
				fatal("Bits has bad value %s (%s)",
					optarg, errstr);
			توڑو;
		حالت 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			اگر (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			توڑو;
		حالت 'F':
			ڈھونڈو_host = 1;
			rr_hostname = optarg;
			توڑو;
		حالت 'H':
			hash_hosts = 1;
			توڑو;
		حالت 'I':
			cert_کلید_id = optarg;
			توڑو;
		حالت 'R':
			delete_host = 1;
			rr_hostname = optarg;
			توڑو;
		حالت 'L':
			show_cert = 1;
			توڑو;
		حالت 'l':
			print_fingerprint = 1;
			توڑو;
		حالت 'B':
			print_bubblebabble = 1;
			توڑو;
		حالت 'm':
			اگر (strcasecmp(optarg, "RFC4716") == 0 ||
			    strcasecmp(optarg, "ssh2") == 0) {
				convert_format = FMT_RFC4716;
				توڑو;
			}
			اگر (strcasecmp(optarg, "PKCS8") == 0) {
				convert_format = FMT_PKCS8;
				نجی_کلید_format = SSHKEY_نجی_PKCS8;
				توڑو;
			}
			اگر (strcasecmp(optarg, "PEM") == 0) {
				convert_format = FMT_PEM;
				نجی_کلید_format = SSHKEY_نجی_PEM;
				توڑو;
			}
			اگر (strcasecmp(optarg, "hexdump") == 0) {
				convert_format = FMT_HEXDUMP;
				توڑو;
			}
			fatal("Unsupported conversion format \"%s\"", optarg);
		حالت 'n':
			cert_principals = optarg;
			توڑو;
		حالت 'o':
			/* no-op; new format is already the default */
			توڑو;
		حالت 'p':
			change_passphrase = 1;
			توڑو;
		حالت 'c':
			change_comment = 1;
			توڑو;
		حالت 'f':
			اگر (strlcpy(شناختی_عنصر_file, optarg,
			    حجم(شناختی_عنصر_file)) >= حجم(شناختی_عنصر_file))
				fatal("Identity filename too long");
			have_شناختی_عنصر = 1;
			توڑو;
		حالت 'g':
			print_generic = 1;
			توڑو;
		حالت 'K':
			download_sk = 1;
			توڑو;
		حالت 'P':
			شناختی_عنصر_passphrase = optarg;
			توڑو;
		حالت 'N':
			شناختی_عنصر_new_passphrase = optarg;
			توڑو;
		حالت 'Q':
			check_krl = 1;
			توڑو;
		حالت 'O':
			opts = xrecallocarray(opts, nopts, nopts + 1,
			    حجم(*opts));
			opts[nopts++] = xstrdup(optarg);
			توڑو;
		حالت 'Z':
			openssh_format_cipher = optarg;
			اگر (cipher_by_name(openssh_format_cipher) == تہی)
				fatal("Invalid OpenSSH-format cipher '%s'",
				    openssh_format_cipher);
			توڑو;
		حالت 'C':
			شناختی_عنصر_comment = optarg;
			توڑو;
		حالت 'q':
			quiet = 1;
			توڑو;
		حالت 'e':
			/* export key */
			convert_مقصد = 1;
			توڑو;
		حالت 'h':
			cert_کلید_type = SSH2_CERT_TYPE_HOST;
			certflags_flags = 0;
			توڑو;
		حالت 'k':
			gen_krl = 1;
			توڑو;
		حالت 'i':
		حالت 'X':
			/* import key */
			convert_from = 1;
			توڑو;
		حالت 'y':
			print_عوامی = 1;
			توڑو;
		حالت 's':
			ca_کلید_راستہ = optarg;
			توڑو;
		حالت 't':
			کلید_type_name = optarg;
			توڑو;
		حالت 'D':
			pkcs11provider = optarg;
			توڑو;
		حالت 'U':
			prefer_agent = 1;
			توڑو;
		حالت 'u':
			update_krl = 1;
			توڑو;
		حالت 'v':
			اگر (log_level == SYSLOG_LEVEL_INFO)
				log_level = SYSLOG_LEVEL_DEBUG1;
			ورنہ {
				اگر (log_level >= SYSLOG_LEVEL_DEBUG1 &&
				    log_level < SYSLOG_LEVEL_DEBUG3)
					log_level++;
			}
			توڑو;
		حالت 'r':
			rr_hostname = optarg;
			توڑو;
		حالت 'a':
			دور = (صحیح)strtonum(optarg, 1, زیادہ_سے_زیادہ_عدد, &errstr);
			اگر (errstr)
				fatal("Invalid number: %s (%s)",
					optarg, errstr);
			توڑو;
		حالت 'V':
			parse_cert_times(optarg);
			توڑو;
		حالت 'Y':
			sign_op = optarg;
			توڑو;
		حالت 'w':
			sk_provider = optarg;
			توڑو;
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
			توڑو;
		حالت 'M':
			اگر (strcmp(optarg, "generate") == 0)
				do_gen_candidates = 1;
			ورنہ اگر (strcmp(optarg, "screen") == 0)
				do_screen_candidates = 1;
			ورنہ
				fatal("Unsupported moduli option %s", optarg);
			توڑو;
		طےشدہ:
			usage();
		}
	}

#اگر_تعریف_شدہ ENABLE_SK_اندرونی
	اگر (sk_provider == تہی)
		sk_provider = "internal";
#اگر_ختم

	/* reinit */
	log_init(argv[0], log_level, SYSLOG_FACILITY_USER, 1);

	argv += optind;
	argc -= optind;

	اگر (sign_op != تہی) {
		اگر (strprefix(sign_op, "find-principals", 0) != تہی) {
			اگر (ca_کلید_راستہ == تہی) {
				error("Too few arguments for find-principals:"
				    "missing signature file");
				باہر_نکلو(1);
			}
			اگر (!have_شناختی_عنصر) {
				error("Too few arguments for find-principals:"
				    "missing allowed keys file");
				باہر_نکلو(1);
			}
			ret = sig_ڈھونڈو_principals(ca_کلید_راستہ, شناختی_عنصر_file,
			    opts, nopts);
			جاؤ مکمل;
		} ورنہ اگر (strprefix(sign_op, "match-principals", 0) != تہی) {
			اگر (!have_شناختی_عنصر) {
				error("Too few arguments for match-principals:"
				    "missing allowed keys file");
				باہر_نکلو(1);
			}
			اگر (cert_کلید_id == تہی) {
				error("Too few arguments for match-principals: "
				    "missing principal ID");
				باہر_نکلو(1);
			}
			ret = sig_مطابقت_principals(شناختی_عنصر_file, cert_کلید_id,
			    opts, nopts);
			جاؤ مکمل;
		} ورنہ اگر (strprefix(sign_op, "sign", 0) != تہی) {
			/* NB. cert_principals is actually namespace, via -n */
			اگر (cert_principals == تہی ||
			    *cert_principals == '\0') {
				error("Too few arguments for sign: "
				    "missing namespace");
				باہر_نکلو(1);
			}
			اگر (!have_شناختی_عنصر) {
				error("Too few arguments for sign: "
				    "missing key");
				باہر_نکلو(1);
			}
			ret = sig_sign(شناختی_عنصر_file, cert_principals,
			    prefer_agent, argc, argv, opts, nopts);
			جاؤ مکمل;
		} ورنہ اگر (strprefix(sign_op, "check-novalidate", 0) != تہی) {
			/* NB. cert_principals is actually namespace, via -n */
			اگر (cert_principals == تہی ||
			    *cert_principals == '\0') {
				error("Too few arguments for check-novalidate: "
				    "missing namespace");
				باہر_نکلو(1);
			}
			اگر (ca_کلید_راستہ == تہی) {
				error("Too few arguments for check-novalidate: "
				    "missing signature file");
				باہر_نکلو(1);
			}
			ret = sig_verify(ca_کلید_راستہ, cert_principals,
			    تہی, تہی, تہی, opts, nopts);
			جاؤ مکمل;
		} ورنہ اگر (strprefix(sign_op, "verify", 0) != تہی) {
			/* NB. cert_principals is actually namespace, via -n */
			اگر (cert_principals == تہی ||
			    *cert_principals == '\0') {
				error("Too few arguments for verify: "
				    "missing namespace");
				باہر_نکلو(1);
			}
			اگر (ca_کلید_راستہ == تہی) {
				error("Too few arguments for verify: "
				    "missing signature file");
				باہر_نکلو(1);
			}
			اگر (!have_شناختی_عنصر) {
				error("Too few arguments for sign: "
				    "missing allowed keys file");
				باہر_نکلو(1);
			}
			اگر (cert_کلید_id == تہی) {
				error("Too few arguments for verify: "
				    "missing principal identity");
				باہر_نکلو(1);
			}
			ret = sig_verify(ca_کلید_راستہ, cert_principals,
			    cert_کلید_id, شناختی_عنصر_file, rr_hostname,
			    opts, nopts);
			جاؤ مکمل;
		}
		error("Unsupported operation for -Y: \"%s\"", sign_op);
		usage();
		/* NOTREACHED */
	}

	اگر (ca_کلید_راستہ != تہی) {
		اگر (argc < 1 && !gen_krl) {
			error("Too few arguments.");
			usage();
		}
	} ورنہ اگر (argc > 0 && !gen_krl && !check_krl &&
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
		do_gen_krl(pw, update_krl, ca_کلید_راستہ,
		    cert_serial, شناختی_عنصر_comment, argc, argv);
		جاؤ مکمل;
	}
	اگر (check_krl) {
		do_check_krl(pw, print_fingerprint, argc, argv);
		جاؤ مکمل;
	}
	اگر (ca_کلید_راستہ != تہی) {
		اگر (cert_کلید_id == تہی)
			fatal("Must specify key id (-I) when certifying");
		اگر (cert_principals == تہی) {
			/*
			 * Ideally this would be a fatal(), but we need to
			 * be able to generate such certificates for testing
			 * even though they will be rejected.
			 */
			error("Warning: certificate will contain no "
			    "principals (-n)");
		}
		برائے (i = 0; i < nopts; i++)
			جوڑو_cert_option(opts[i]);
		do_ca_sign(pw, ca_کلید_راستہ, prefer_agent,
		    cert_serial, cert_serial_autoinc, argc, argv);
		جاؤ مکمل;
	}
	اگر (show_cert)
		do_show_cert(pw);
	اگر (delete_host || hash_hosts || ڈھونڈو_host) {
		do_معلوم_hosts(pw, rr_hostname, ڈھونڈو_host,
		    delete_host, hash_hosts);
	}
	اگر (pkcs11provider != تہی)
		do_download(pw);
	اگر (download_sk) {
		برائے (i = 0; i < nopts; i++) {
			اگر ((p = strprefix(opts[i], "device=", 1)) != تہی) {
				sk_device = xstrdup(p);
			} ورنہ {
				fatal("Option \"%s\" is unsupported for "
				    "FIDO authenticator download", opts[i]);
			}
		}
		ret = do_download_sk(sk_provider, sk_device);
		جاؤ مکمل;
	}
	اگر (print_fingerprint || print_bubblebabble)
		do_fingerprint(pw);
	اگر (change_passphrase)
		do_change_passphrase(pw, opts, nopts);
	اگر (change_comment)
		do_change_comment(pw, شناختی_عنصر_comment);
#اگر_تعریف_شدہ WITH_OPENSSL
	اگر (convert_مقصد) {
		do_convert_مقصد(pw);
		جاؤ مکمل;
	}
	اگر (convert_from) {
		do_convert_from(pw);
		جاؤ مکمل;
	}
#ورنہ /* WITH_OPENSSL */
	اگر (convert_مقصد || convert_from)
		fatal("key conversion disabled at compile time");
#اگر_ختم /* WITH_OPENSSL */
	اگر (print_عوامی)
		do_print_عوامی(pw);
	اگر (rr_hostname != تہی) {
		غیرعلامتی صحیح n = 0;

		اگر (have_شناختی_عنصر) {
			n = do_print_resource_ریکارڈ(pw, شناختی_عنصر_file,
			    rr_hostname, print_generic, opts, nopts);
			اگر (n == 0)
				fatal("%s: %s", شناختی_عنصر_file, strerror(errno));
			باہر_نکلو(0);
		} ورنہ {

			n += do_print_resource_ریکارڈ(pw,
			    راستہ_HOST_RSA_کلید_FILE, rr_hostname,
			    print_generic, opts, nopts);
			n += do_print_resource_ریکارڈ(pw,
			    راستہ_HOST_ECDSA_کلید_FILE, rr_hostname,
			    print_generic, opts, nopts);
			n += do_print_resource_ریکارڈ(pw,
			    راستہ_HOST_ED25519_کلید_FILE, rr_hostname,
			    print_generic, opts, nopts);
			اگر (n == 0)
				fatal("no keys found.");
			باہر_نکلو(0);
		}
	}

	اگر (do_gen_candidates || do_screen_candidates) {
		اگر (argc <= 0)
			fatal("No output file specified");
		ورنہ اگر (argc > 1)
			fatal("Too many output files specified");
	}
	اگر (do_gen_candidates) {
		do_moduli_gen(argv[0], opts, nopts);
		جاؤ مکمل;
	}
	اگر (do_screen_candidates) {
		do_moduli_screen(argv[0], opts, nopts);
		جاؤ مکمل;
	}

	اگر (gen_all_hostkeys) {
		do_gen_all_hostkeys(pw);
		جاؤ مکمل;
	}

	اگر (کلید_type_name == تہی)
		کلید_type_name = DEFAULT_کلید_TYPE_NAME;

	type = sshkey_type_from_shortname(کلید_type_name);
	type_بٹ_valid(type, کلید_type_name, &بٹ);

	اگر (!quiet)
		لکھو("Generating public/private %s key pair.\n",
		    کلید_type_name);
	انتخاب (type) {
	حالت کلید_ECDSA_SK:
	حالت کلید_ED25519_SK:
		برائے (i = 0; i < nopts; i++) {
			اگر (strcasecmp(opts[i], "no-touch-required") == 0) {
				sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
			} ورنہ اگر (strcasecmp(opts[i], "verify-required") == 0) {
				sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
			} ورنہ اگر (strcasecmp(opts[i], "resident") == 0) {
				sk_flags |= SSH_SK_RESIDENT_کلید;
			} ورنہ اگر ((p = strprefix(opts[i], "device=", 1))
			    != تہی ) {
				sk_device = xstrdup(p);
			} ورنہ اگر ((p = strprefix(opts[i], "user=", 1))
			    != تہی) {
				sk_user = xstrdup(p);
			} ورنہ اگر ((p = strprefix(opts[i], "challenge=", 1))
			    != تہی) {
				اگر ((r = sshbuf_بھرو_file(p,
				    &challenge)) != 0) {
					fatal_r(r, "Unable to load FIDO "
					    "enrollment challenge \"%s\"", p);
				}
			} ورنہ اگر (strncasecmp(opts[i],
			    "write-attestation=", 18) == 0) {
				sk_attestation_راستہ = opts[i] + 18;
			} ورنہ اگر (strncasecmp(opts[i],
			    "application=", 12) == 0) {
				sk_application = xstrdup(opts[i] + 12);
				اگر (لڑی_موازنہ(sk_application, "ssh:", 4) != 0) {
					fatal("FIDO application string must "
					    "begin with \"ssh:\"");
				}
			} ورنہ {
				fatal("Option \"%s\" is unsupported for "
				    "FIDO authenticator enrollment", opts[i]);
			}
		}
		اگر ((attest = sshbuf_new()) == تہی)
			fatal("sshbuf_new failed");
		r = 0;
		برائے (i = 0 ;;) {
			اگر (!quiet) {
				لکھو("You may need to touch your "
				    "authenticator%s to authorize key "
				    "generation.\n",
				    r == 0 ? "" : " again");
			}
			fflush(stdout);
			r = sshsk_enroll(type, sk_provider, sk_device,
			    sk_application == تہی ? "ssh:" : sk_application,
			    sk_user, sk_flags, passphrase, challenge,
			    &نجی, attest);
			اگر (r == 0)
				توڑو;
			اگر (r == SSH_ERR_کلید_BAD_PERMISSIONS &&
			    (sk_flags & SSH_SK_RESIDENT_کلید) != 0 &&
			    (sk_flags & SSH_SK_FORCE_OPERATION) == 0 &&
			    confirm_sk_overwrite(sk_application, sk_user)) {
				sk_flags |= SSH_SK_FORCE_OPERATION;
				جاری;
			}
			اگر (r != SSH_ERR_کلید_WRONG_PASSPHRASE)
				fatal_r(r, "Key enrollment failed");
			ورنہ اگر (passphrase != تہی) {
				error("PIN incorrect");
				freezero(passphrase, لڑی_لمبائی(passphrase));
				passphrase = تہی;
			}
			اگر (++i >= 3)
				fatal("Too many incorrect PINs");
			passphrase = read_passphrase("Enter PIN for "
			    "authenticator: ", RP_ALLOW_STDIN);
		}
		اگر (passphrase != تہی) {
			freezero(passphrase, لڑی_لمبائی(passphrase));
			passphrase = تہی;
		}
		توڑو;
	طےشدہ:
		اگر ((r = sshkey_generate(type, بٹ, &نجی)) != 0)
			fatal("sshkey_generate failed");
		توڑو;
	}
	اگر ((r = sshkey_from_نجی(نجی, &عوامی)) != 0)
		fatal_r(r, "sshkey_from_private");

	اگر (!have_شناختی_عنصر)
		ask_filename(pw, "Enter file in which to save the key");

	/* Create ~/.ssh directory if it doesn't already exist. */
	hostfile_create_user_ssh_dir(شناختی_عنصر_file, !quiet);

	/* If the file already exists, ask the user to confirm. */
	اگر (!confirm_overwrite(شناختی_عنصر_file))
		باہر_نکلو(1);

	/* Determine the passphrase for the private key */
	passphrase = نجی_کلید_passphrase(شناختی_عنصر_file);
	اگر (شناختی_عنصر_comment) {
		strlcpy(comment, شناختی_عنصر_comment, حجم(comment));
	} ورنہ {
		/* Create default comment field for the passphrase. */
		snprintf(comment, حجم comment, "%s@%s", pw->pw_name, hostname);
	}



	/* Save the key with the given passphrase and comment. */
	اگر ((r = sshkey_save_نجی(نجی, شناختی_عنصر_file, passphrase,
	    comment, نجی_کلید_format, openssh_format_cipher, دور)) != 0) {
		error_r(r, "Saving key \"%s\" failed", شناختی_عنصر_file);
		freezero(passphrase, لڑی_لمبائی(passphrase));
		باہر_نکلو(1);
	}
	freezero(passphrase, لڑی_لمبائی(passphrase));
	sshkey_free(نجی);

	اگر (!quiet) {
		لکھو("Your identification has been saved in %s\n",
		    شناختی_عنصر_file);
	}

	strlcat(شناختی_عنصر_file, ".pub", حجم(شناختی_عنصر_file));
	اگر ((r = sshkey_save_عوامی(عوامی, شناختی_عنصر_file, comment)) != 0)
		fatal_r(r, "Unable to save public key to %s", شناختی_عنصر_file);

	اگر (!quiet) {
		fp = sshkey_fingerprint(عوامی, fingerprint_hash,
		    SSH_FP_DEFAULT);
		ra = sshkey_fingerprint(عوامی, fingerprint_hash,
		    SSH_FP_RANDOMART);
		اگر (fp == تہی || ra == تہی)
			fatal("sshkey_fingerprint failed");
		لکھو("Your public key has been saved in %s\n",
		    شناختی_عنصر_file);
		لکھو("The key fingerprint is:\n");
		لکھو("%s %s\n", fp, comment);
		لکھو("The key's randomart image is:\n");
		لکھو("%s\n", ra);
		آزاد(ra);
		آزاد(fp);
	}

	اگر (sk_attestation_راستہ != تہی)
		save_attestation(attest, sk_attestation_راستہ);

 مکمل:
	sshbuf_free(attest);
	sshkey_free(عوامی);
	pwfree(pw);
	باہر_نکلو(ret);
}
