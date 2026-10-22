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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/socket.h>
#ضمن <sys/stat.h>

#جے_تعریف_شدہ WITH_OPENSSL
#ضمن "openbsd-compat/openssl-compat.h"
#ضمن <openssl/bn.h>
#ضمن <openssl/evp.h>
#ضمن <openssl/pem.h>
#جے_انت

#ضمن <stdint.h>
#ضمن <errno.h>
#ضمن <fcntl.h>
#ضمن <netdb.h>
#ضمن <paths.h>
#ضمن <pwd.h>
#ضمن <stdarg.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <unistd.h>
#ضمن <limits.h>
#ضمن <locale.h>
#ضمن <time.h>

#ضمن "xmalloc.h"
#ضمن "sshkey.h"
#ضمن "authfile.h"
#ضمن "sshbuf.h"
#ضمن "pathnames.h"
#ضمن "log.h"
#ضمن "misc.h"
#ضمن "match.h"
#ضمن "hostfile.h"
#ضمن "dns.h"
#ضمن "ssh.h"
#ضمن "ssh2.h"
#ضمن "ssherr.h"
#ضمن "atomicio.h"
#ضمن "krl.h"
#ضمن "digest.h"
#ضمن "utf8.h"
#ضمن "authfd.h"
#ضمن "sshsig.h"
#ضمن "ssh-sk.h"
#ضمن "sk-api.h" /* XXX for SSH_SK_USER_PRESENCE_REQD; remove */
#ضمن "cipher.h"

#جے_تعریف_شدہ ENABLE_PKCS11
#ضمن "ssh-pkcs11.h"
#جے_انت

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

ساكن صحيح quiet = 0;

/* Flag indicating that we just want to see the key fingerprint */
ساكن صحيح print_fingerprint = 0;
ساكن صحيح print_bubblebabble = 0;

/* Hash algorithm to use for fingerprints. */
ساكن صحيح fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* The identity file name, given on the command line or entered by the user. */
ساكن حرف پچھان_تت_file[PATH_MAX];
ساكن صحيح have_پچھان_تت = 0;

/* This is set to the passphrase if given on the command line. */
ساكن حرف *پچھان_تت_passphrase = عدم;

/* This is set to the new passphrase if given on the command line. */
ساكن حرف *پچھان_تت_new_passphrase = عدم;

/* Key type when certifying */
ساكن u_int cert_کلید_type = SSH2_CERT_TYPE_USER;

/* "key ID" of signed key */
ساكن حرف *cert_کلید_id = عدم;

/* Comma-separated list of principal names for certifying keys */
ساكن حرف *cert_principals = عدم;

/* Validity period for certificates */
ساكن uint64_t cert_valid_from = 0;
ساكن uint64_t cert_valid_منزل = ~0ULL;

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
ساكن uint32_t certflags_flags = CERTOPT_DEFAULT;
ساكن حرف *certflags_command = عدم;
ساكن حرف *certflags_src_addr = عدم;

/* Arbitrary extensions specified by user */
بنية cert_ext {
	حرف *کلید;
	حرف *val;
	صحيح crit;
};
ساكن بنية cert_ext *cert_ext;
ساكن ناپ_t ncert_ext;

/* Conversion to/from various formats */
تعداد {
	FMT_RFC4716,
	FMT_PKCS8,
	FMT_PEM,
	FMT_HEXDUMP
} convert_format = FMT_RFC4716;

ساكن حرف *کلید_type_name = عدم;

/* Load key from this PKCS#11 provider */
ساكن حرف *pkcs11provider = عدم;

/* FIDO/U2F provider to use */
ساكن حرف *sk_provider = عدم;

/* Format for writing private keys */
ساكن صحيح نجی_کلید_format = SSHKEY_نجی_OPENSSH;

/* Cipher for new-format private keys */
ساكن حرف *openssh_format_cipher = عدم;

/* Number of KDF rounds to derive new format keys. */
ساكن صحيح گیڑ = 0;

/* argv0 */
خارجي حرف *__progname;

ساكن حرف hostname[NI_MAXHOST];

#جے_تعریف_شدہ WITH_OPENSSL
/* moduli.c */
صحيح gen_candidates(FILE *, uint32_t, BIGNUM *);
صحيح مفرد_test(FILE *, FILE *, uint32_t, uint32_t, حرف *, بنانشانی لما,
    بنانشانی لما);
#جے_انت

ساكن فراغ
type_بٹ_valid(صحيح type, ثابت حرف *name, uint32_t *bitsp)
{
	إذا (type == کلید_UNSPEC)
		fatal("unknown key type %s", کلید_type_name);
	إذا (*bitsp == 0) {
#جے_تعریف_شدہ WITH_OPENSSL
		صحيح nid;

		بدل(type) {
		حالة کلید_ECDSA:
			إذا (name != عدم &&
			    (nid = sshkey_ecdsa_nid_from_name(name)) > 0)
				*bitsp = sshkey_ونگ_nid_منزل_بٹ(nid);
			إذا (*bitsp == 0)
				*bitsp = DEFAULT_بٹ_ECDSA;
			اكسر;
		حالة کلید_RSA:
			*bitsp = DEFAULT_بٹ;
			اكسر;
		}
#جے_انت
	}
#جے_تعریف_شدہ WITH_OPENSSL
	بدل (type) {
	حالة کلید_RSA:
		إذا (*bitsp < SSH_RSA_MINIMUM_MODULUS_ناپ)
			fatal("Invalid RSA key length: minimum is %d bits",
			    SSH_RSA_MINIMUM_MODULUS_ناپ);
		وإلا إذا (*bitsp > OPENSSL_RSA_MAX_MODULUS_بٹ)
			fatal("Invalid RSA key length: maximum is %d bits",
			    OPENSSL_RSA_MAX_MODULUS_بٹ);
		اكسر;
	حالة کلید_ECDSA:
		إذا (sshkey_ecdsa_بٹ_منزل_nid(*bitsp) == -1)
			fatal("Invalid ECDSA key length: valid lengths are "
			    "256, 384 or 521 bits");
	}
#جے_انت
}

/*
 * Checks whether a file exists and, if so, asks the user whether they wish
 * to overwrite it.
 * Returns nonzero if the file does not already exist or if the user agrees to
 * overwrite, or zero otherwise.
 */
ساكن صحيح
confirm_overwrite(ثابت حرف *filename)
{
	حرف yesno[3];
	بنية stat st;

	إذا (stat(filename, &st) != 0)
		أرجع 1;
	لکھو("%s already exists.\n", filename);
	لکھو("Overwrite (y/n)? ");
	fflush(stdout);
	إذا (fgets(yesno, حجم(yesno), stdin) == عدم)
		أرجع 0;
	إذا (yesno[0] != 'y' && yesno[0] != 'Y')
		أرجع 0;
	أرجع 1;
}

ساكن فراغ
ask_filename(بنية passwd *pw, ثابت حرف *prompt)
{
	حرف buf[1024];
	حرف *name = عدم;

	إذا (کلید_type_name == عدم)
		name = رستہ_SSH_CLIENT_ID_ED25519;
	وإلا {
		بدل (sshkey_type_from_shortname(کلید_type_name)) {
		حالة کلید_ECDSA_CERT:
		حالة کلید_ECDSA:
			name = رستہ_SSH_CLIENT_ID_ECDSA;
			اكسر;
		حالة کلید_ECDSA_SK_CERT:
		حالة کلید_ECDSA_SK:
			name = رستہ_SSH_CLIENT_ID_ECDSA_SK;
			اكسر;
		حالة کلید_RSA_CERT:
		حالة کلید_RSA:
			name = رستہ_SSH_CLIENT_ID_RSA;
			اكسر;
		حالة کلید_ED25519:
		حالة کلید_ED25519_CERT:
			name = رستہ_SSH_CLIENT_ID_ED25519;
			اكسر;
		حالة کلید_ED25519_SK:
		حالة کلید_ED25519_SK_CERT:
			name = رستہ_SSH_CLIENT_ID_ED25519_SK;
			اكسر;
		حالة کلید_MLDSA44_ED25519:
		حالة کلید_MLDSA44_ED25519_CERT:
			name = رستہ_SSH_CLIENT_ID_MLDSA44_ED25519;
			اكسر;
		افتراضي:
			fatal("bad key type");
		}
	}
	snprintf(پچھان_تت_file, حجم(پچھان_تت_file),
	    "%s/%s", pw->pw_dir, name);
	لکھو("%s (%s): ", prompt, پچھان_تت_file);
	fflush(stdout);
	إذا (fgets(buf, حجم(buf), stdin) == عدم)
		باہر_نکلو(1);
	buf[strcspn(buf, "\n")] = '\0';
	إذا (strcmp(buf, "") != 0)
		strlcpy(پچھان_تت_file, buf, حجم(پچھان_تت_file));
	have_پچھان_تت = 1;
}

ساكن بنية sshkey *
لدو_پچھان_تت(ثابت حرف *filename, حرف **commentp)
{
	حرف *prompt, *pass;
	بنية sshkey *prv;
	صحيح r;

	إذا (commentp != عدم)
		*commentp = عدم;
	إذا ((r = sshkey_لدو_نجی(filename, "", &prv, commentp)) == 0)
		أرجع prv;
	إذا (r != SSH_ERR_کلید_WRONG_PASSPHRASE)
		fatal_r(r, "Load key \"%s\"", filename);
	إذا (پچھان_تت_passphrase)
		pass = xstrdup(پچھان_تت_passphrase);
	وإلا {
		xasprintf(&prompt, "Enter passphrase for \"%s\": ", filename);
		pass = read_passphrase(prompt, RP_ALLOW_STDIN);
		حرر(prompt);
	}
	r = sshkey_لدو_نجی(filename, pass, &prv, commentp);
	freezero(pass, لڑی_لمبائی(pass));
	إذا (r != 0)
		fatal_r(r, "Load key \"%s\"", filename);
	أرجع prv;
}

#تعریف_کرو SSH_COM_عوامی_BEGIN		"---- BEGIN SSH2 PUBLIC KEY ----"
#تعریف_کرو SSH_COM_عوامی_سرا		"---- END SSH2 PUBLIC KEY ----"
#تعریف_کرو SSH_COM_نجی_BEGIN		"---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----"
#تعریف_کرو	SSH_COM_نجی_کلید_MAGIC	0x3f6ff9eb

#جے_تعریف_شدہ WITH_OPENSSL
ساكن فراغ
do_convert_منزل_ssh2(بنية passwd *pw, بنية sshkey *k)
{
	بنية sshbuf *b;
	حرف comment[61], *b64;
	صحيح r;

	إذا ((b = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshkey_putb(k, b)) != 0)
		fatal_fr(r, "put key");
	إذا ((b64 = sshbuf_dtob64_string(b, 1)) == عدم)
		fatal_f("sshbuf_dtob64_string failed");

	/* Comment + surrounds must fit into 72 chars (RFC 4716 sec 3.3) */
	snprintf(comment, حجم(comment),
	    "%u-bit %s, converted by %s@%s from OpenSSH",
	    sshkey_ناپ(k), sshkey_type(k),
	    pw->pw_name, hostname);

	sshkey_free(k);
	sshbuf_free(b);

	fprintf(stdout, "%s\n", SSH_COM_عوامی_BEGIN);
	fprintf(stdout, "Comment: \"%s\"\n%s", comment, b64);
	fprintf(stdout, "%s\n", SSH_COM_عوامی_سرا);
	حرر(b64);
}

ساكن فراغ
do_convert_منزل_pkcs8(بنية sshkey *k)
{
	بدل (sshkey_type_plain(k->type)) {
	حالة کلید_RSA:
		إذا (!PEM_write_RSA_PUBKEY(stdout,
		    EVP_PKEY_get0_RSA(k->pkey)))
			fatal("PEM_write_RSA_PUBKEY failed");
		اكسر;
	حالة کلید_ECDSA:
		إذا (!PEM_write_EC_PUBKEY(stdout,
		    EVP_PKEY_get0_EC_کلید(k->pkey)))
			fatal("PEM_write_EC_PUBKEY failed");
		اكسر;
	افتراضي:
		fatal_f("unsupported key type %s", sshkey_type(k));
	}
}

ساكن فراغ
do_convert_منزل_pem(بنية sshkey *k)
{
	بدل (sshkey_type_plain(k->type)) {
	حالة کلید_RSA:
		إذا (!PEM_write_RSAPublic_کلید(stdout,
		    EVP_PKEY_get0_RSA(k->pkey)))
			fatal("PEM_write_RSAPublicKey failed");
		اكسر;
	حالة کلید_ECDSA:
		إذا (!PEM_write_EC_PUBKEY(stdout,
		    EVP_PKEY_get0_EC_کلید(k->pkey)))
			fatal("PEM_write_EC_PUBKEY failed");
		اكسر;
	افتراضي:
		fatal_f("unsupported key type %s", sshkey_type(k));
	}
}

ساكن فراغ
do_convert_منزل_hexdump(بنية sshkey *k)
{
	بنية sshbuf *b;
	صحيح r;

	إذا ((b = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	/* pubkey */
	إذا ((r = sshkey_putb(k, b)) != 0)
		fatal_fr(r, "serialise private");
	لکھو("Public %s key:\n", sshkey_type(k));
	sshbuf_dump(b, stdout);
	sshbuf_reset(b);
	إذا ((r = sshkey_نجی_serialize(k, b)) != 0) {
		debug_fr(r, "serialise private");
		اذهب باہرلا;
	}
	لکھو("\nPrivate %s key:\n", sshkey_type(k));
	sshbuf_dump(b, stdout);
 باہرلا:
	sshbuf_free(b);
}

ساكن فراغ
do_convert_منزل(بنية passwd *pw)
{
	بنية sshkey *k = عدم;
	بنية stat st;
	صحيح r;

	إذا (!have_پچھان_تت)
		ask_filename(pw, "Enter file in which the key is");
	إذا (stat(پچھان_تت_file, &st) == -1)
		fatal("%s: %s: %s", __progname, پچھان_تت_file, strerror(errno));

	/* If we're trying to hexdump, then prefer the private key */
	إذا (convert_format == FMT_HEXDUMP) {
		إذا ((r = sshkey_لدو_نجی(پچھان_تت_file,
		    عدم, &k, عدم)) != 0 &&
		    r == SSH_ERR_کلید_WRONG_PASSPHRASE)
			k = لدو_پچھان_تت(پچھان_تت_file, عدم);
	}
	إذا (k == عدم && (r = sshkey_لدو_عوامی(پچھان_تت_file, &k, عدم)) != 0)
		k = لدو_پچھان_تت(پچھان_تت_file, عدم);

	بدل (convert_format) {
	حالة FMT_RFC4716:
		do_convert_منزل_ssh2(pw, k);
		اكسر;
	حالة FMT_PKCS8:
		do_convert_منزل_pkcs8(k);
		اكسر;
	حالة FMT_PEM:
		do_convert_منزل_pem(k);
		اكسر;
	حالة FMT_HEXDUMP:
		do_convert_منزل_hexdump(k);
		اكسر;
	افتراضي:
		fatal_f("unknown key format %d", convert_format);
	}
}

/*
 * This is almost exactly the bignum1 encoding, but with 32 bit for length
 * instead of 16.
 */
ساكن فراغ
بفر_get_bignum_بٹ(بنية sshbuf *b, BIGNUM *قدر)
{
	u_int بائٹاں, bignum_بٹ;
	صحيح r;

	إذا ((r = sshbuf_get_u32(b, &bignum_بٹ)) != 0)
		fatal_fr(r, "parse");
	بائٹاں = (bignum_بٹ + 7) / 8;
	إذا (sshbuf_len(b) < بائٹاں)
		fatal_f("input buffer too small: need %d have %zu",
		    بائٹاں, sshbuf_len(b));
	إذا (BN_bin2bn(sshbuf_ptr(b), بائٹاں, قدر) == عدم)
		fatal_f("BN_bin2bn failed");
	إذا ((r = sshbuf_consume(b, بائٹاں)) != 0)
		fatal_fr(r, "consume");
}

ساكن بنية sshkey *
do_convert_نجی_ssh2(بنية sshbuf *b)
{
	بنية sshkey *کلید = عدم;
	حرف *type, *cipher;
	ثابت حرف *alg = عدم;
	u_char e1, e2, e3, *sig = عدم, انکڑے[] = "abcde12345";
	صحيح r, rlen, ktype;
	u_int magic, i1, i2, i3, i4;
	ناپ_t slen;
	u_long e;
	BIGNUM *rsa_n = عدم, *rsa_e = عدم, *rsa_d = عدم;
	BIGNUM *rsa_p = عدم, *rsa_q = عدم, *rsa_iqmp = عدم;
	BIGNUM *rsa_dmp1 = عدم, *rsa_dmq1 = عدم;
	RSA *rsa = عدم;

	إذا ((r = sshbuf_get_u32(b, &magic)) != 0)
		fatal_fr(r, "parse magic");

	إذا (magic != SSH_COM_نجی_کلید_MAGIC) {
		error("bad magic 0x%x != 0x%x", magic,
		    SSH_COM_نجی_کلید_MAGIC);
		أرجع عدم;
	}
	إذا ((r = sshbuf_get_u32(b, &i1)) != 0 ||
	    (r = sshbuf_get_cstring(b, &type, عدم)) != 0 ||
	    (r = sshbuf_get_cstring(b, &cipher, عدم)) != 0 ||
	    (r = sshbuf_get_u32(b, &i2)) != 0 ||
	    (r = sshbuf_get_u32(b, &i3)) != 0 ||
	    (r = sshbuf_get_u32(b, &i4)) != 0)
		fatal_fr(r, "parse");
	debug("ignore (%d %d %d %d)", i1, i2, i3, i4);
	إذا (strcmp(cipher, "none") != 0) {
		error("unsupported cipher %s", cipher);
		حرر(cipher);
		حرر(type);
		أرجع عدم;
	}
	حرر(cipher);

	إذا (لڑی_کھوج(type, "rsa")) {
		ktype = کلید_RSA;
	} وإلا {
		حرر(type);
		أرجع عدم;
	}
	إذا ((کلید = sshkey_new(ktype)) == عدم)
		fatal("sshkey_new failed");
	حرر(type);

	بدل (کلید->type) {
	حالة کلید_RSA:
		إذا ((r = sshbuf_get_u8(b, &e1)) != 0 ||
		    (e1 < 30 && (r = sshbuf_get_u8(b, &e2)) != 0) ||
		    (e1 < 30 && (r = sshbuf_get_u8(b, &e3)) != 0))
			fatal_fr(r, "parse RSA");
		e = e1;
		debug("e %lx", e);
		إذا (e < 30) {
			e <<= 8;
			e += e2;
			debug("e %lx", e);
			e <<= 8;
			e += e3;
			debug("e %lx", e);
		}
		إذا ((rsa_e = BN_new()) == عدم)
			fatal_f("BN_new");
		إذا (!BN_سیٹ_لفظ(rsa_e, e)) {
			BN_clear_free(rsa_e);
			sshkey_free(کلید);
			أرجع عدم;
		}
		إذا ((rsa_n = BN_new()) == عدم ||
		    (rsa_d = BN_new()) == عدم ||
		    (rsa_p = BN_new()) == عدم ||
		    (rsa_q = BN_new()) == عدم ||
		    (rsa_iqmp = BN_new()) == عدم)
			fatal_f("BN_new");
		بفر_get_bignum_بٹ(b, rsa_d);
		بفر_get_bignum_بٹ(b, rsa_n);
		بفر_get_bignum_بٹ(b, rsa_iqmp);
		بفر_get_bignum_بٹ(b, rsa_q);
		بفر_get_bignum_بٹ(b, rsa_p);
		إذا ((r = ssh_rsa_complete_crt_parameters(rsa_d, rsa_p, rsa_q,
		    rsa_iqmp, &rsa_dmp1, &rsa_dmq1)) != 0)
			fatal_fr(r, "generate RSA CRT parameters");
		EVP_PKEY_free(کلید->pkey);
		إذا ((کلید->pkey = EVP_PKEY_new()) == عدم)
			fatal_f("EVP_PKEY_new failed");
		إذا ((rsa = RSA_new()) == عدم)
			fatal_f("RSA_new failed");
		إذا (!RSA_set0_کلید(rsa, rsa_n, rsa_e, rsa_d))
			fatal_f("RSA_set0_key failed");
		rsa_n = rsa_e = rsa_d = عدم; /* transferred */
		إذا (!RSA_set0_factors(rsa, rsa_p, rsa_q))
			fatal_f("RSA_set0_factors failed");
		rsa_p = rsa_q = عدم; /* transferred */
		إذا (RSA_set0_crt_params(rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp) != 1)
			fatal_f("RSA_set0_crt_params failed");
		rsa_dmp1 = rsa_dmq1 = rsa_iqmp = عدم;
		إذا (EVP_PKEY_set1_RSA(کلید->pkey, rsa) != 1)
			fatal_f("EVP_PKEY_set1_RSA failed");
		RSA_free(rsa);
		alg = "rsa-sha2-256";
		اكسر;
	}
	rlen = sshbuf_len(b);
	إذا (rlen != 0)
		error_f("remaining bytes in key blob %d", rlen);

	/* try the key */
	إذا ((r = sshkey_sign(کلید, &sig, &slen, انکڑے, حجم(انکڑے),
	    alg, عدم, عدم, 0)) != 0)
		error_fr(r, "signing with converted key failed");
	وإلا إذا ((r = sshkey_verify(کلید, sig, slen, انکڑے, حجم(انکڑے),
	    alg, 0, عدم)) != 0)
		error_fr(r, "verification with converted key failed");
	إذا (r != 0) {
		sshkey_free(کلید);
		حرر(sig);
		أرجع عدم;
	}
	حرر(sig);
	أرجع کلید;
}

ساكن صحيح
get_سطر(FILE *fp, حرف *سطر, ناپ_t len)
{
	صحيح c;
	ناپ_t pos = 0;

	سطر[0] = '\0';
	طالما ((c = fgetc(fp)) != EOF) {
		إذا (pos >= len - 1)
			fatal("input line too long.");
		بدل (c) {
		حالة '\r':
			c = fgetc(fp);
			إذا (c != EOF && c != '\n' && ungetc(c, fp) == EOF)
				fatal("unget: %s", strerror(errno));
			أرجع pos;
		حالة '\n':
			أرجع pos;
		}
		سطر[pos++] = c;
		سطر[pos] = '\0';
	}
	/* We reached EOF */
	أرجع -1;
}

ساكن فراغ
do_convert_from_ssh2(بنية passwd *pw, بنية sshkey **k, صحيح *خاص)
{
	صحيح r, blen, escaped = 0;
	u_int len;
	حرف سطر[1024];
	بنية sshbuf *buf;
	حرف encoded[8096];
	FILE *fp;

	إذا ((buf = sshbuf_new()) == عدم)
		fatal("sshbuf_new failed");
	إذا ((fp = fopen(پچھان_تت_file, "r")) == عدم)
		fatal("%s: %s: %s", __progname, پچھان_تت_file, strerror(errno));
	encoded[0] = '\0';
	طالما ((blen = get_سطر(fp, سطر, حجم(سطر))) != -1) {
		إذا (blen > 0 && سطر[blen - 1] == '\\')
			escaped++;
		إذا (لڑی_مقابلہ(سطر, "----", 4) == 0 ||
		    لڑی_کھوج(سطر, ": ") != عدم) {
			إذا (لڑی_کھوج(سطر, SSH_COM_نجی_BEGIN) != عدم)
				*خاص = 1;
			إذا (لڑی_کھوج(سطر, " END ") != عدم) {
				اكسر;
			}
			/* fprintf(stderr, "ignore: %s", line); */
			استمر;
		}
		إذا (escaped) {
			escaped--;
			/* fprintf(stderr, "escaped: %s", line); */
			استمر;
		}
		strlcat(encoded, سطر, حجم(encoded));
	}
	len = لڑی_لمبائی(encoded);
	إذا (((len % 4) == 3) &&
	    (encoded[len-1] == '=') &&
	    (encoded[len-2] == '=') &&
	    (encoded[len-3] == '='))
		encoded[len-3] = '\0';
	إذا ((r = sshbuf_b64tod(buf, encoded)) != 0)
		fatal_fr(r, "base64 decode");
	إذا (*خاص) {
		إذا ((*k = do_convert_نجی_ssh2(buf)) == عدم)
			fatal_f("private key conversion failed");
	} وإلا إذا ((r = sshkey_fromb(buf, k)) != 0)
		fatal_fr(r, "parse key");
	sshbuf_free(buf);
	fclose(fp);
}

ساكن فراغ
do_convert_from_pkcs8(بنية sshkey **k, صحيح *خاص)
{
	EVP_PKEY *pubkey;
	FILE *fp;

	إذا ((fp = fopen(پچھان_تت_file, "r")) == عدم)
		fatal("%s: %s: %s", __progname, پچھان_تت_file, strerror(errno));
	إذا ((pubkey = PEM_read_PUBKEY(fp, عدم, عدم, عدم)) == عدم) {
		fatal_f("%s is not a recognised public key format",
		    پچھان_تت_file);
	}
	fclose(fp);
	بدل (EVP_PKEY_ادھار_id(pubkey)) {
	حالة EVP_PKEY_RSA:
		إذا ((*k = sshkey_new(کلید_UNSPEC)) == عدم)
			fatal("sshkey_new failed");
		(*k)->type = کلید_RSA;
		(*k)->pkey = pubkey;
		pubkey = عدم;
		اكسر;
	حالة EVP_PKEY_EC:
		إذا ((*k = sshkey_new(کلید_UNSPEC)) == عدم)
			fatal("sshkey_new failed");
		إذا (((*k)->ecdsa_nid = sshkey_ecdsa_fixup_گروہ(pubkey)) == -1)
			fatal("sshkey_ecdsa_fixup_group failed");
		(*k)->type = کلید_ECDSA;
		(*k)->pkey = pubkey;
		pubkey = عدم;
		اكسر;
	افتراضي:
		fatal_f("unsupported pubkey type %d",
		    EVP_PKEY_ادھار_id(pubkey));
	}
	EVP_PKEY_free(pubkey);
}

ساكن فراغ
do_convert_from_pem(بنية sshkey **k, صحيح *خاص)
{
	FILE *fp;
	RSA *rsa;

	إذا ((fp = fopen(پچھان_تت_file, "r")) == عدم)
		fatal("%s: %s: %s", __progname, پچھان_تت_file, strerror(errno));
	إذا ((rsa = PEM_read_RSAPublic_کلید(fp, عدم, عدم, عدم)) != عدم) {
		إذا ((*k = sshkey_new(کلید_UNSPEC)) == عدم)
			fatal("sshkey_new failed");
		إذا (((*k)->pkey = EVP_PKEY_new()) == عدم)
			fatal("EVP_PKEY_new failed");
		(*k)->type = کلید_RSA;
		إذا (EVP_PKEY_set1_RSA((*k)->pkey, rsa) != 1)
			fatal("EVP_PKEY_set1_RSA failed");
		RSA_free(rsa);
		fclose(fp);
		أرجع;
	}
	fatal_f("unrecognised raw private key format");
}

ساكن فراغ
do_convert_from(بنية passwd *pw)
{
	بنية sshkey *k = عدم;
	صحيح r, خاص = 0, ok = 0;
	بنية stat st;

	إذا (!have_پچھان_تت)
		ask_filename(pw, "Enter file in which the key is");
	إذا (stat(پچھان_تت_file, &st) == -1)
		fatal("%s: %s: %s", __progname, پچھان_تت_file, strerror(errno));

	بدل (convert_format) {
	حالة FMT_RFC4716:
		do_convert_from_ssh2(pw, &k, &خاص);
		اكسر;
	حالة FMT_PKCS8:
		do_convert_from_pkcs8(&k, &خاص);
		اكسر;
	حالة FMT_PEM:
		do_convert_from_pem(&k, &خاص);
		اكسر;
	افتراضي:
		fatal_f("unknown key format %d", convert_format);
	}

	إذا (!خاص) {
		إذا ((r = sshkey_write(k, stdout)) == 0)
			ok = 1;
		إذا (ok)
			fprintf(stdout, "\n");
	} وإلا {
		بدل (k->type) {
		حالة کلید_ECDSA:
			ok = PEM_write_ECPrivate_کلید(stdout,
			    EVP_PKEY_get0_EC_کلید(k->pkey), عدم, عدم, 0,
			    عدم, عدم);
			اكسر;
		حالة کلید_RSA:
			ok = PEM_write_RSAPrivate_کلید(stdout,
			    EVP_PKEY_get0_RSA(k->pkey), عدم, عدم, 0,
			    عدم, عدم);
			اكسر;
		افتراضي:
			fatal_f("unsupported key type %s", sshkey_type(k));
		}
	}

	إذا (!ok)
		fatal("key write failed");
	sshkey_free(k);
}
#جے_انت

ساكن فراغ
do_print_عوامی(بنية passwd *pw)
{
	بنية sshkey *prv;
	بنية stat st;
	صحيح r;
	حرف *comment = عدم;

	إذا (!have_پچھان_تت)
		ask_filename(pw, "Enter file in which the key is");
	إذا (stat(پچھان_تت_file, &st) == -1)
		fatal("%s: %s", پچھان_تت_file, strerror(errno));
	prv = لدو_پچھان_تت(پچھان_تت_file, &comment);
	إذا ((r = sshkey_write(prv, stdout)) != 0)
		fatal_fr(r, "write key");
	إذا (comment != عدم && *comment != '\0')
		fprintf(stdout, " %s", comment);
	fprintf(stdout, "\n");
	إذا (sshkey_is_sk(prv)) {
		debug("sk_application: \"%s\", sk_flags 0x%02x",
			prv->sk_application, prv->sk_flags);
	}
	sshkey_free(prv);
	حرر(comment);
	باہر_نکلو(0);
}

ساكن فراغ
do_download(بنية passwd *pw)
{
#جے_تعریف_شدہ ENABLE_PKCS11
	بنية sshkey **کلیدیں = عدم;
	صحيح i, nkeys;
	تعداد sshkey_fp_rep rep;
	صحيح fptype;
	حرف *fp, *ra, **comments = عدم;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;

	pkcs11_init(1);
	nkeys = pkcs11_جوڑو_provider(pkcs11provider, عدم, &کلیدیں, &comments);
	إذا (nkeys <= 0)
		fatal("cannot read public key from pkcs11");
	لكل (i = 0; i < nkeys; i++) {
		إذا (print_fingerprint) {
			fp = sshkey_fingerprint(کلیدیں[i], fptype, rep);
			ra = sshkey_fingerprint(کلیدیں[i], fingerprint_hash,
			    SSH_FP_RANDOMART);
			إذا (fp == عدم || ra == عدم)
				fatal_f("sshkey_fingerprint fail");
			لکھو("%u %s %s (PKCS11 key)\n", sshkey_ناپ(کلیدیں[i]),
			    fp, sshkey_type(کلیدیں[i]));
			إذا (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
				لکھو("%s\n", ra);
			حرر(ra);
			حرر(fp);
		} وإلا {
			(فراغ) sshkey_write(کلیدیں[i], stdout); /* XXX check */
			fprintf(stdout, "%s%s\n",
			    *(comments[i]) == '\0' ? "" : " ", comments[i]);
		}
		حرر(comments[i]);
		sshkey_free(کلیدیں[i]);
	}
	حرر(comments);
	حرر(کلیدیں);
	pkcs11_terminate();
	باہر_نکلو(0);
#وإلا
	fatal("no pkcs11 support");
#جے_انت /* ENABLE_PKCS11 */
}

ساكن بنية sshkey *
try_read_کلید(حرف **cpp)
{
	بنية sshkey *ret;
	صحيح r;

	إذا ((ret = sshkey_new(کلید_UNSPEC)) == عدم)
		fatal("sshkey_new failed");
	إذا ((r = sshkey_read(ret, cpp)) == 0)
		أرجع ret;
	/* Not a key */
	sshkey_free(ret);
	أرجع عدم;
}

ساكن فراغ
fingerprint_one_کلید(ثابت بنية sshkey *عام, ثابت حرف *comment)
{
	حرف *fp = عدم, *ra = عدم;
	تعداد sshkey_fp_rep rep;
	صحيح fptype;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;
	fp = sshkey_fingerprint(عام, fptype, rep);
	ra = sshkey_fingerprint(عام, fingerprint_hash, SSH_FP_RANDOMART);
	إذا (fp == عدم || ra == عدم)
		fatal_f("sshkey_fingerprint failed");
	mprintf("%u %s %s (%s)\n", sshkey_ناپ(عام), fp,
	    comment ? comment : "no comment", sshkey_type(عام));
	إذا (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
		لکھو("%s\n", ra);
	حرر(ra);
	حرر(fp);
}

ساكن فراغ
fingerprint_نجی(ثابت حرف *رستہ)
{
	بنية stat st;
	حرف *comment = عدم;
	بنية sshkey *privkey = عدم, *pubkey = عدم;
	صحيح r;

	إذا (stat(پچھان_تت_file, &st) == -1)
		fatal("%s: %s", رستہ, strerror(errno));
	إذا ((r = sshkey_لدو_عوامی(رستہ, &pubkey, &comment)) != 0)
		debug_r(r, "load public \"%s\"", رستہ);
	إذا (pubkey == عدم || comment == عدم || *comment == '\0') {
		حرر(comment);
		إذا ((r = sshkey_لدو_نجی(رستہ, عدم,
		    &privkey, &comment)) != 0)
			debug_r(r, "load private \"%s\"", رستہ);
	}
	إذا (pubkey == عدم && privkey == عدم)
		fatal("%s is not a key file.", رستہ);

	fingerprint_one_کلید(pubkey == عدم ? privkey : pubkey, comment);
	sshkey_free(pubkey);
	sshkey_free(privkey);
	حرر(comment);
}

ساكن فراغ
do_fingerprint(بنية passwd *pw)
{
	FILE *f;
	بنية sshkey *عام = عدم;
	حرف *comment = عدم, *cp, *ep, *سطر = عدم;
	ناپ_t linesize = 0;
	صحيح i, invalid = 1;
	ثابت حرف *رستہ;
	u_long lnum = 0;

	إذا (!have_پچھان_تت)
		ask_filename(pw, "Enter file in which the key is");
	رستہ = پچھان_تت_file;

	إذا (strcmp(پچھان_تت_file, "-") == 0) {
		f = stdin;
		رستہ = "(stdin)";
	} وإلا إذا ((f = fopen(رستہ, "r")) == عدم)
		fatal("%s: %s: %s", __progname, رستہ, strerror(errno));

	طالما (getline(&سطر, &linesize, f) != -1) {
		lnum++;
		cp = سطر;
		cp[strcspn(cp, "\r\n")] = '\0';
		/* Trim leading space and comments */
		cp = سطر + strspn(سطر, " \t");
		إذا (*cp == '#' || *cp == '\0')
			استمر;

		/*
		 * Input may be plain keys, private keys, authorized_keys
		 * or known_hosts.
		 */

		/*
		 * Try private keys first. Assume a key is private if
		 * "SSH PRIVATE KEY" appears on the first line and we're
		 * not reading from stdin (XXX support private keys on stdin).
		 */
		إذا (lnum == 1 && strcmp(پچھان_تت_file, "-") != 0 &&
		    لڑی_کھوج(cp, "PRIVATE KEY") != عدم) {
			حرر(سطر);
			fclose(f);
			fingerprint_نجی(رستہ);
			باہر_نکلو(0);
		}

		/*
		 * If it's not a private key, then this must be prepared to
		 * accept a public key prefixed with a hostname or options.
		 * Try a bare key first, otherwise skip the leading stuff.
		 */
		comment = عدم;
		إذا ((عام = try_read_کلید(&cp)) == عدم) {
			i = strtol(cp, &ep, 10);
			إذا (i == 0 || ep == عدم ||
			    (*ep != ' ' && *ep != '\t')) {
				صحيح quoted = 0;

				comment = cp;
				لكل (; *cp && (quoted || (*cp != ' ' &&
				    *cp != '\t')); cp++) {
					إذا (*cp == '\\' && cp[1] == '"')
						cp++;	/* Skip both */
					وإلا إذا (*cp == '"')
						quoted = !quoted;
				}
				إذا (!*cp)
					استمر;
				*cp++ = '\0';
			}
		}
		/* Retry after parsing leading hostname/key options */
		إذا (عام == عدم && (عام = try_read_کلید(&cp)) == عدم) {
			debug("%s:%lu: not a public key", رستہ, lnum);
			استمر;
		}

		/* Find trailing comment, if any */
		لكل (; *cp == ' ' || *cp == '\t'; cp++)
			;
		إذا (*cp != '\0' && *cp != '#')
			comment = cp;

		fingerprint_one_کلید(عام, comment);
		sshkey_free(عام);
		invalid = 0; /* One good key in the file is sufficient */
	}
	fclose(f);
	حرر(سطر);

	إذا (invalid)
		fatal("%s is not a public key file.", رستہ);
	باہر_نکلو(0);
}

ساكن فراغ
do_gen_all_hostkeys(بنية passwd *pw)
{
	بنية {
		حرف *کلید_type;
		حرف *کلید_type_display;
		حرف *رستہ;
	} کلید_types[] = {
#جے_تعریف_شدہ WITH_OPENSSL
		{ "rsa", "RSA" ,رستہ_HOST_RSA_کلید_FILE },
		{ "ecdsa", "ECDSA",رستہ_HOST_ECDSA_کلید_FILE },
#جے_انت /* WITH_OPENSSL */
		{ "ed25519", "ED25519",رستہ_HOST_ED25519_کلید_FILE },
#جے_تعریف_شدہ USE_MLDSA
		{ "mldsa44-ed25519", "MLDSA44-ED25519",
		     رستہ_HOST_MLDSA44_ED25519_کلید_FILE },
#جے_انت
		{ عدم, عدم, عدم }
	};

	uint32_t بٹ = 0;
	صحيح پہلا = 0;
	بنية stat st;
	بنية sshkey *خاص, *عام;
	حرف comment[کلید_COMMENT_MAX], *prv_tmp, *pub_tmp, *prv_file, *pub_file;
	صحيح i, type, fd, r;

	لكل (i = 0; کلید_types[i].کلید_type; i++) {
		عام = خاص = عدم;
		prv_tmp = pub_tmp = prv_file = pub_file = عدم;

		xasprintf(&prv_file, "%s%s",
		    پچھان_تت_file, کلید_types[i].رستہ);

		/* Check whether private key exists and is not zero-length */
		إذا (stat(prv_file, &st) == 0) {
			إذا (st.st_size != 0)
				اذهب اگلا;
		} وإلا إذا (errno != ENOENT) {
			error("Could not stat %s: %s", کلید_types[i].رستہ,
			    strerror(errno));
			اذهب failnext;
		}

		/*
		 * Private key doesn't exist or is invalid; proceed with
		 * key generation.
		 */
		xasprintf(&prv_tmp, "%s%s.XXXXXXXXXX",
		    پچھان_تت_file, کلید_types[i].رستہ);
		xasprintf(&pub_tmp, "%s%s.pub.XXXXXXXXXX",
		    پچھان_تت_file, کلید_types[i].رستہ);
		xasprintf(&pub_file, "%s%s.pub",
		    پچھان_تت_file, کلید_types[i].رستہ);

		إذا (پہلا == 0) {
			پہلا = 1;
			لکھو("%s: generating new host keys: ", __progname);
		}
		لکھو("%s ", کلید_types[i].کلید_type_display);
		fflush(stdout);
		type = sshkey_type_from_shortname(کلید_types[i].کلید_type);
		إذا ((fd = mkstemp(prv_tmp)) == -1) {
			error("Could not save your private key in %s: %s",
			    prv_tmp, strerror(errno));
			اذهب failnext;
		}
		(فراغ)close(fd); /* just using mkstemp() to reserve a name */
		بٹ = 0;
		type_بٹ_valid(type, عدم, &بٹ);
		إذا ((r = sshkey_generate(type, بٹ, &خاص)) != 0) {
			error_r(r, "sshkey_generate failed");
			اذهب failnext;
		}
		إذا ((r = sshkey_from_نجی(خاص, &عام)) != 0)
			fatal_fr(r, "sshkey_from_private");
		snprintf(comment, حجم comment, "%s@%s", pw->pw_name,
		    hostname);
		إذا ((r = sshkey_save_نجی(خاص, prv_tmp, "",
		    comment, نجی_کلید_format, openssh_format_cipher,
		    گیڑ)) != 0) {
			error_r(r, "Saving key \"%s\" failed", prv_tmp);
			اذهب failnext;
		}
		إذا ((fd = mkstemp(pub_tmp)) == -1) {
			error("Could not save your public key in %s: %s",
			    pub_tmp, strerror(errno));
			اذهب failnext;
		}
		(فراغ)fchmod(fd, 0644);
		(فراغ)close(fd);
		إذا ((r = sshkey_save_عوامی(عام, pub_tmp, comment)) != 0) {
			error_r(r, "Unable to save public key to %s",
			    پچھان_تت_file);
			اذهب failnext;
		}

		/* Rename temporary files to their permanent locations. */
		إذا (rename(pub_tmp, pub_file) != 0) {
			error("Unable to move %s into position: %s",
			    pub_file, strerror(errno));
			اذهب failnext;
		}
		إذا (rename(prv_tmp, prv_file) != 0) {
			error("Unable to move %s into position: %s",
			    کلید_types[i].رستہ, strerror(errno));
 failnext:
			پہلا = 0;
			اذهب اگلا;
		}
 اگلا:
		sshkey_free(خاص);
		sshkey_free(عام);
		حرر(prv_tmp);
		حرر(pub_tmp);
		حرر(prv_file);
		حرر(pub_file);
	}
	إذا (پہلا != 0)
		لکھو("\n");
}

بنية معلوم_hosts_ctx {
	ثابت حرف *host;	/* Hostname searched for in find/delete case */
	FILE *باہرلا;		/* Output file, stdout for find_hosts case */
	صحيح has_unhashed;	/* When hashing, original had unhashed hosts */
	صحيح لبھیا_کلید;		/* For find/delete, host was found */
	صحيح invalid;		/* File contained invalid items; don't delete */
	صحيح hash_hosts;		/* Hash hostnames as we go */
	صحيح لبھو_host;		/* Search for specific hostname */
	صحيح delete_host;	/* Delete host from known_hosts */
};

ساكن صحيح
معلوم_hosts_hash(بنية hostkey_foreach_سطر *l, فراغ *_ctx)
{
	بنية معلوم_hosts_ctx *ctx = (بنية معلوم_hosts_ctx *)_ctx;
	حرف *hashed, *cp, *hosts, *ohosts;
	صحيح has_wild = l->hosts && strcspn(l->hosts, "*?!") != لڑی_لمبائی(l->hosts);
	صحيح was_hashed = l->hosts && l->hosts[0] == HASH_DELIM;

	بدل (l->حالت) {
	حالة HKF_حالت_OK:
	حالة HKF_حالت_MATCHED:
		/*
		 * Don't hash hosts already hashed, with wildcard
		 * characters or a CA/revocation marker.
		 */
		إذا (was_hashed || has_wild || l->marker != MRK_NONE) {
			fprintf(ctx->باہرلا, "%s\n", l->سطر);
			إذا (has_wild && !ctx->لبھو_host) {
				logit("%s:%lu: ignoring host name "
				    "with wildcard: %.64s", l->رستہ,
				    l->linenum, l->hosts);
			}
			أرجع 0;
		}
		/*
		 * Split any comma-separated hostnames from the host list,
		 * hash and store separately.
		 */
		ohosts = hosts = xstrdup(l->hosts);
		طالما ((cp = strsep(&hosts, ",")) != عدم && *cp != '\0') {
			lowercase(cp);
			إذا ((hashed = host_hash(cp, عدم, 0)) == عدم)
				fatal("hash_host failed");
			fprintf(ctx->باہرلا, "%s %s\n", hashed, l->rawkey);
			حرر(hashed);
			ctx->has_unhashed = 1;
		}
		حرر(ohosts);
		أرجع 0;
	حالة HKF_حالت_INVALID:
		/* Retain invalid lines, but mark file as invalid. */
		ctx->invalid = 1;
		logit("%s:%lu: invalid line", l->رستہ, l->linenum);
		/* FALLTHROUGH */
	افتراضي:
		fprintf(ctx->باہرلا, "%s\n", l->سطر);
		أرجع 0;
	}
	/* NOTREACHED */
	أرجع -1;
}

ساكن صحيح
معلوم_hosts_لبھو_delete(بنية hostkey_foreach_سطر *l, فراغ *_ctx)
{
	بنية معلوم_hosts_ctx *ctx = (بنية معلوم_hosts_ctx *)_ctx;
	تعداد sshkey_fp_rep rep;
	صحيح fptype;
	حرف *fp = عدم, *ra = عدم;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;

	إذا (l->حالت == HKF_حالت_MATCHED) {
		إذا (ctx->delete_host) {
			إذا (l->marker != MRK_NONE) {
				/* Don't remove CA and revocation lines */
				fprintf(ctx->باہرلا, "%s\n", l->سطر);
			} وإلا {
				/*
				 * Hostname matches and has no CA/revoke
				 * marker, delete it by *not* writing the
				 * line to ctx->out.
				 */
				ctx->لبھیا_کلید = 1;
				إذا (!quiet)
					لکھو("# Host %s found: line %lu\n",
					    ctx->host, l->linenum);
			}
			أرجع 0;
		} وإلا إذا (ctx->لبھو_host) {
			ctx->لبھیا_کلید = 1;
			إذا (!quiet) {
				لکھو("# Host %s found: line %lu %s\n",
				    ctx->host,
				    l->linenum, l->marker == MRK_CA ? "CA" :
				    (l->marker == MRK_REVOKE ? "REVOKED" : ""));
			}
			إذا (ctx->hash_hosts)
				معلوم_hosts_hash(l, ctx);
			وإلا إذا (print_fingerprint) {
				fp = sshkey_fingerprint(l->کلید, fptype, rep);
				ra = sshkey_fingerprint(l->کلید,
				    fingerprint_hash, SSH_FP_RANDOMART);
				إذا (fp == عدم || ra == عدم)
					fatal_f("sshkey_fingerprint failed");
				mprintf("%s %s %s%s%s\n", ctx->host,
				    sshkey_type(l->کلید), fp,
				    l->comment[0] ? " " : "",
				    l->comment);
				إذا (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
					لکھو("%s\n", ra);
				حرر(ra);
				حرر(fp);
			} وإلا
				fprintf(ctx->باہرلا, "%s\n", l->سطر);
			أرجع 0;
		}
	} وإلا إذا (ctx->delete_host) {
		/* Retain non-matching hosts when deleting */
		إذا (l->حالت == HKF_حالت_INVALID) {
			ctx->invalid = 1;
			logit("%s:%lu: invalid line", l->رستہ, l->linenum);
		}
		fprintf(ctx->باہرلا, "%s\n", l->سطر);
	}
	أرجع 0;
}

ساكن فراغ
do_معلوم_hosts(بنية passwd *pw, ثابت حرف *name, صحيح لبھو_host,
    صحيح delete_host, صحيح hash_hosts)
{
	حرف *cp, tmp[PATH_MAX], old[PATH_MAX];
	صحيح r, fd, oerrno, inplace = 0;
	بنية معلوم_hosts_ctx ctx;
	u_int foreach_options;
	بنية stat sb;

	إذا (!have_پچھان_تت) {
		cp = tilde_expand_filename(رستہ_SSH_USER_HOSTFILE, pw->pw_uid);
		إذا (strlcpy(پچھان_تت_file, cp, حجم(پچھان_تت_file)) >=
		    حجم(پچھان_تت_file))
			fatal("Specified known hosts path too long");
		حرر(cp);
		have_پچھان_تت = 1;
	}
	إذا (stat(پچھان_تت_file, &sb) != 0)
		fatal("Cannot stat %s: %s", پچھان_تت_file, strerror(errno));

	memset(&ctx, 0, حجم(ctx));
	ctx.باہرلا = stdout;
	ctx.host = name;
	ctx.hash_hosts = hash_hosts;
	ctx.لبھو_host = لبھو_host;
	ctx.delete_host = delete_host;

	/*
	 * Find hosts goes to stdout, hash and deletions happen in-place
	 * A corner case is ssh-keygen -HF foo, which should go to stdout
	 */
	إذا (!لبھو_host && (hash_hosts || delete_host)) {
		إذا (strlcpy(tmp, پچھان_تت_file, حجم(tmp)) >= حجم(tmp) ||
		    strlcat(tmp, ".XXXXXXXXXX", حجم(tmp)) >= حجم(tmp) ||
		    strlcpy(old, پچھان_تت_file, حجم(old)) >= حجم(old) ||
		    strlcat(old, ".old", حجم(old)) >= حجم(old))
			fatal("known_hosts path too long");
		umask(077);
		إذا ((fd = mkstemp(tmp)) == -1)
			fatal("mkstemp: %s", strerror(errno));
		إذا ((ctx.باہرلا = fdopen(fd, "w")) == عدم) {
			oerrno = errno;
			unlink(tmp);
			fatal("fdopen: %s", strerror(oerrno));
		}
		(فراغ)fchmod(fd, sb.st_mode & 0644);
		inplace = 1;
	}
	/* XXX support identity_file == "-" for stdin */
	foreach_options = لبھو_host ? HKF_WANT_میل : 0;
	foreach_options |= print_fingerprint ? HKF_WANT_PARSE_کلید : 0;
	إذا ((r = hostkeys_foreach(پچھان_تت_file, (لبھو_host || !hash_hosts) ?
	    معلوم_hosts_لبھو_delete : معلوم_hosts_hash, &ctx, name, عدم,
	    foreach_options, 0)) != 0) {
		إذا (inplace)
			unlink(tmp);
		fatal_fr(r, "hostkeys_foreach");
	}

	إذا (inplace)
		fclose(ctx.باہرلا);

	إذا (ctx.invalid) {
		error("%s is not a valid known_hosts file.", پچھان_تت_file);
		إذا (inplace) {
			error("Not replacing existing known_hosts "
			    "file because of errors");
			unlink(tmp);
		}
		باہر_نکلو(1);
	} وإلا إذا (delete_host && !ctx.لبھیا_کلید) {
		logit("Host %s not found in %s", name, پچھان_تت_file);
		إذا (inplace)
			unlink(tmp);
	} وإلا إذا (inplace) {
		/* Backup existing file */
		إذا (unlink(old) == -1 && errno != ENOENT)
			fatal("unlink %.100s: %s", old, strerror(errno));
		إذا (link(پچھان_تت_file, old) == -1)
			fatal("link %.100s to %.100s: %s", پچھان_تت_file, old,
			    strerror(errno));
		/* Move new one into place */
		إذا (rename(tmp, پچھان_تت_file) == -1) {
			error("rename\"%s\" to \"%s\": %s", tmp, پچھان_تت_file,
			    strerror(errno));
			unlink(tmp);
			unlink(old);
			باہر_نکلو(1);
		}

		لکھو("%s updated.\n", پچھان_تت_file);
		لکھو("Original contents retained as %s\n", old);
		إذا (ctx.has_unhashed) {
			logit("WARNING: %s contains unhashed entries", old);
			logit("Delete this file to ensure privacy "
			    "of hostnames");
		}
	}

	باہر_نکلو (لبھو_host && !ctx.لبھیا_کلید);
}

/*
 * Perform changing a passphrase.  The argument is the passwd structure
 * for the current user.
 */
ساكن فراغ
do_change_passphrase(بنية passwd *pw, حرف * ثابت *opts, ناپ_t nopts)
{
	حرف *comment;
	حرف *old_passphrase, *passphrase1, *passphrase2;
	بنية stat st;
	بنية sshkey *خاص;
	صحيح r;
	ناپ_t i;

	إذا (!have_پچھان_تت)
		ask_filename(pw, "Enter file in which the key is");
	إذا (stat(پچھان_تت_file, &st) == -1)
		fatal("%s: %s", پچھان_تت_file, strerror(errno));
	/* Try to load the file with empty passphrase. */
	r = sshkey_لدو_نجی(پچھان_تت_file, "", &خاص, &comment);
	إذا (r == SSH_ERR_کلید_WRONG_PASSPHRASE) {
		إذا (پچھان_تت_passphrase)
			old_passphrase = xstrdup(پچھان_تت_passphrase);
		وإلا
			old_passphrase =
			    read_passphrase("Enter old passphrase: ",
			    RP_ALLOW_STDIN);
		r = sshkey_لدو_نجی(پچھان_تت_file, old_passphrase,
		    &خاص, &comment);
		freezero(old_passphrase, لڑی_لمبائی(old_passphrase));
		إذا (r != 0)
			اذهب badkey;
	} وإلا إذا (r != 0) {
 badkey:
		fatal_r(r, "Failed to load key %s", پچھان_تت_file);
	}
	إذا (comment)
		mprintf("Key has comment '%s'\n", comment);

	/* All current -O options relate to FIDO keys only */
	إذا (nopts != 0 && !sshkey_is_sk(خاص)) {
		fatal("FIDO-specific option requested for non-FIDO key %s",
		    پچھان_تت_file);
	}
	إذا (sshkey_is_sk(خاص)) {
		debug_f("%s: original FIDO key flags: "
		    "%stouch-required %sverify-required", پچھان_تت_file,
		    (خاص->sk_flags & SSH_SK_USER_PRESENCE_REQD) ? "": "no-",
		    (خاص->sk_flags & SSH_SK_USER_VERIFICATION_REQD) ? "" : "no-");
	}
	لكل (i = 0; i < nopts; i++) {
		إذا (strcasecmp(opts[i], "touch-required") == 0)
			خاص->sk_flags |= SSH_SK_USER_PRESENCE_REQD;
		وإلا إذا (strcasecmp(opts[i], "no-touch-required") == 0)
			خاص->sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
		وإلا إذا (strcasecmp(opts[i], "verify-required") == 0)
			خاص->sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
		وإلا إذا (strcasecmp(opts[i], "no-verify-required") == 0)
			خاص->sk_flags &= ~SSH_SK_USER_VERIFICATION_REQD;
		وإلا {
			fatal("Option \"%s\" is unsupported for "
			    "key passphrase change", opts[i]);
		}
	}
	إذا (sshkey_is_sk(خاص) && nopts != 0) {
		debug_f("%s: updated FIDO key flags: "
		    "%stouch-required %sverify-required", پچھان_تت_file,
		    (خاص->sk_flags & SSH_SK_USER_PRESENCE_REQD) ? "": "no-",
		    (خاص->sk_flags & SSH_SK_USER_VERIFICATION_REQD) ? "" : "no-");
	}

	/* Ask the new passphrase (twice). */
	إذا (پچھان_تت_new_passphrase) {
		passphrase1 = xstrdup(پچھان_تت_new_passphrase);
		passphrase2 = عدم;
	} وإلا {
		passphrase1 =
			read_passphrase("Enter new passphrase (empty for no "
			    "passphrase): ", RP_ALLOW_STDIN);
		passphrase2 = read_passphrase("Enter same passphrase again: ",
		    RP_ALLOW_STDIN);

		/* Verify that they are the same. */
		إذا (strcmp(passphrase1, passphrase2) != 0) {
			explicit_bzero(passphrase1, لڑی_لمبائی(passphrase1));
			explicit_bzero(passphrase2, لڑی_لمبائی(passphrase2));
			حرر(passphrase1);
			حرر(passphrase2);
			لکھو("Pass phrases do not match.  Try again.\n");
			باہر_نکلو(1);
		}
		/* Destroy the other copy. */
		freezero(passphrase2, لڑی_لمبائی(passphrase2));
	}

	/* Save the file using the new passphrase. */
	إذا ((r = sshkey_save_نجی(خاص, پچھان_تت_file, passphrase1,
	    comment, نجی_کلید_format, openssh_format_cipher, گیڑ)) != 0) {
		error_r(r, "Saving key \"%s\" failed", پچھان_تت_file);
		freezero(passphrase1, لڑی_لمبائی(passphrase1));
		sshkey_free(خاص);
		حرر(comment);
		باہر_نکلو(1);
	}
	/* Destroy the passphrase and the copy of the key in memory. */
	freezero(passphrase1, لڑی_لمبائی(passphrase1));
	sshkey_free(خاص);		 /* Destroys contents */
	حرر(comment);

	لکھو("Your identification has been saved with the new passphrase.\n");
	باہر_نکلو(0);
}

/*
 * Print the SSHFP RR.
 */
ساكن صحيح
do_print_resource_ریکارڈ(بنية passwd *pw, حرف *fname, حرف *hname,
    صحيح print_generic, حرف * ثابت *opts, ناپ_t nopts)
{
	بنية sshkey *عام;
	حرف *comment = عدم;
	ثابت حرف *p;
	بنية stat st;
	صحيح r, hash = -1;
	ناپ_t i;

	لكل (i = 0; i < nopts; i++) {
		إذا ((p = strprefix(opts[i], "hashalg=", 1)) != عدم) {
			إذا ((hash = ssh_digest_alg_by_name(p)) == -1)
				fatal("Unsupported hash algorithm");
		} وإلا {
			error("Invalid option \"%s\"", opts[i]);
			أرجع SSH_ERR_INVALID_دلیل;
		}
	}
	إذا (fname == عدم)
		fatal_f("no filename");
	إذا (stat(fname, &st) == -1) {
		إذا (errno == ENOENT)
			أرجع 0;
		fatal("%s: %s", fname, strerror(errno));
	}
	إذا ((r = sshkey_لدو_عوامی(fname, &عام, &comment)) != 0)
		fatal_r(r, "Failed to read v2 public key from \"%s\"", fname);
	export_dns_rr(hname, عام, stdout, print_generic, hash);
	sshkey_free(عام);
	حرر(comment);
	أرجع 1;
}

/*
 * Change the comment of a private key file.
 */
ساكن فراغ
do_change_comment(بنية passwd *pw, ثابت حرف *پچھان_تت_comment)
{
	حرف new_comment[کلید_COMMENT_MAX], *comment, *passphrase;
	بنية sshkey *خاص;
	بنية sshkey *عام;
	بنية stat st;
	صحيح r;

	إذا (!have_پچھان_تت)
		ask_filename(pw, "Enter file in which the key is");
	إذا (stat(پچھان_تت_file, &st) == -1)
		fatal("%s: %s", پچھان_تت_file, strerror(errno));
	إذا ((r = sshkey_لدو_نجی(پچھان_تت_file, "",
	    &خاص, &comment)) == 0)
		passphrase = xstrdup("");
	وإلا إذا (r != SSH_ERR_کلید_WRONG_PASSPHRASE)
		fatal_r(r, "Cannot load private key \"%s\"", پچھان_تت_file);
	وإلا {
		إذا (پچھان_تت_passphrase)
			passphrase = xstrdup(پچھان_تت_passphrase);
		وإلا إذا (پچھان_تت_new_passphrase)
			passphrase = xstrdup(پچھان_تت_new_passphrase);
		وإلا
			passphrase = read_passphrase("Enter passphrase: ",
			    RP_ALLOW_STDIN);
		/* Try to load using the passphrase. */
		إذا ((r = sshkey_لدو_نجی(پچھان_تت_file, passphrase,
		    &خاص, &comment)) != 0) {
			freezero(passphrase, لڑی_لمبائی(passphrase));
			fatal_r(r, "Cannot load private key \"%s\"",
			    پچھان_تت_file);
		}
	}

	إذا (خاص->type != کلید_ED25519 &&
	    نجی_کلید_format != SSHKEY_نجی_OPENSSH) {
		error("Comments are only supported for keys stored in "
		    "the new format (-o).");
		explicit_bzero(passphrase, لڑی_لمبائی(passphrase));
		sshkey_free(خاص);
		باہر_نکلو(1);
	}
	إذا (comment)
		لکھو("Old comment: %s\n", comment);
	وإلا
		لکھو("No existing comment\n");

	إذا (پچھان_تت_comment) {
		strlcpy(new_comment, پچھان_تت_comment, حجم(new_comment));
	} وإلا {
		لکھو("New comment: ");
		fflush(stdout);
		إذا (!fgets(new_comment, حجم(new_comment), stdin)) {
			explicit_bzero(passphrase, لڑی_لمبائی(passphrase));
			sshkey_free(خاص);
			باہر_نکلو(1);
		}
		new_comment[strcspn(new_comment, "\n")] = '\0';
	}
	إذا (comment != عدم && strcmp(comment, new_comment) == 0) {
		لکھو("No change to comment\n");
		حرر(passphrase);
		sshkey_free(خاص);
		حرر(comment);
		باہر_نکلو(0);
	}

	/* Save the file using the new passphrase. */
	إذا ((r = sshkey_save_نجی(خاص, پچھان_تت_file, passphrase,
	    new_comment, نجی_کلید_format, openssh_format_cipher,
	    گیڑ)) != 0) {
		error_r(r, "Saving key \"%s\" failed", پچھان_تت_file);
		freezero(passphrase, لڑی_لمبائی(passphrase));
		sshkey_free(خاص);
		حرر(comment);
		باہر_نکلو(1);
	}
	freezero(passphrase, لڑی_لمبائی(passphrase));
	إذا ((r = sshkey_from_نجی(خاص, &عام)) != 0)
		fatal_fr(r, "sshkey_from_private");
	sshkey_free(خاص);

	strlcat(پچھان_تت_file, ".pub", حجم(پچھان_تت_file));
	إذا ((r = sshkey_save_عوامی(عام, پچھان_تت_file, new_comment)) != 0)
		fatal_r(r, "Unable to save public key to %s", پچھان_تت_file);
	sshkey_free(عام);
	حرر(comment);

	إذا (لڑی_لمبائی(new_comment) > 0)
		لکھو("Comment '%s' applied\n", new_comment);
	وإلا
		لکھو("Comment removed\n");

	باہر_نکلو(0);
}

ساكن فراغ
cert_ext_جوڑو(ثابت حرف *کلید, ثابت حرف *قدر, صحيح iscrit)
{
	cert_ext = xreallocarray(cert_ext, ncert_ext + 1, حجم(*cert_ext));
	cert_ext[ncert_ext].کلید = xstrdup(کلید);
	cert_ext[ncert_ext].val = قدر == عدم ? عدم : xstrdup(قدر);
	cert_ext[ncert_ext].crit = iscrit;
	ncert_ext++;
}

/* qsort(3) comparison function for certificate extensions */
ساكن صحيح
cert_ext_cmp(ثابت فراغ *_a, ثابت فراغ *_b)
{
	ثابت بنية cert_ext *a = (ثابت بنية cert_ext *)_a;
	ثابت بنية cert_ext *b = (ثابت بنية cert_ext *)_b;
	صحيح r;

	إذا (a->crit != b->crit)
		أرجع (a->crit < b->crit) ? -1 : 1;
	إذا ((r = strcmp(a->کلید, b->کلید)) != 0)
		أرجع r;
	إذا ((a->val == عدم) != (b->val == عدم))
		أرجع (a->val == عدم) ? -1 : 1;
	إذا (a->val != عدم && (r = strcmp(a->val, b->val)) != 0)
		أرجع r;
	أرجع 0;
}

#تعریف_کرو OPTIONS_CRITICAL	1
#تعریف_کرو OPTIONS_EXTENSIONS	2
ساكن فراغ
prepare_options_buf(بنية sshbuf *c, صحيح which)
{
	بنية sshbuf *b;
	ناپ_t i;
	صحيح r;
	ثابت بنية cert_ext *ext;

	إذا ((b = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	sshbuf_reset(c);
	لكل (i = 0; i < ncert_ext; i++) {
		ext = &cert_ext[i];
		إذا ((ext->crit && (which & OPTIONS_EXTENSIONS)) ||
		    (!ext->crit && (which & OPTIONS_CRITICAL)))
			استمر;
		إذا (ext->val == عدم) {
			/* flag option */
			debug3_f("%s", ext->کلید);
			إذا ((r = sshbuf_put_cstring(c, ext->کلید)) != 0 ||
			    (r = sshbuf_put_string(c, عدم, 0)) != 0)
				fatal_fr(r, "prepare flag");
		} وإلا {
			/* key/value option */
			debug3_f("%s=%s", ext->کلید, ext->val);
			sshbuf_reset(b);
			إذا ((r = sshbuf_put_cstring(c, ext->کلید)) != 0 ||
			    (r = sshbuf_put_cstring(b, ext->val)) != 0 ||
			    (r = sshbuf_put_stringb(c, b)) != 0)
				fatal_fr(r, "prepare k/v");
		}
	}
	sshbuf_free(b);
}

ساكن فراغ
finalise_cert_exts(فراغ)
{
	/* critical options */
	إذا (certflags_command != عدم)
		cert_ext_جوڑو("force-command", certflags_command, 1);
	إذا (certflags_src_addr != عدم)
		cert_ext_جوڑو("source-address", certflags_src_addr, 1);
	إذا ((certflags_flags & CERTOPT_REQUIRE_VERIFY) != 0)
		cert_ext_جوڑو("verify-required", عدم, 1);
	/* extensions */
	إذا ((certflags_flags & CERTOPT_X_FWD) != 0)
		cert_ext_جوڑو("permit-X11-forwarding", عدم, 0);
	إذا ((certflags_flags & CERTOPT_AGENT_FWD) != 0)
		cert_ext_جوڑو("permit-agent-forwarding", عدم, 0);
	إذا ((certflags_flags & CERTOPT_پورٹ_FWD) != 0)
		cert_ext_جوڑو("permit-port-forwarding", عدم, 0);
	إذا ((certflags_flags & CERTOPT_PTY) != 0)
		cert_ext_جوڑو("permit-pty", عدم, 0);
	إذا ((certflags_flags & CERTOPT_USER_RC) != 0)
		cert_ext_جوڑو("permit-user-rc", عدم, 0);
	إذا ((certflags_flags & CERTOPT_NO_REQUIRE_USER_PRESENCE) != 0)
		cert_ext_جوڑو("no-touch-required", عدم, 0);
	/* order lexically by key */
	إذا (ncert_ext > 0)
		qsort(cert_ext, ncert_ext, حجم(*cert_ext), cert_ext_cmp);
}

ساكن بنية sshkey *
لدو_pkcs11_کلید(حرف *رستہ)
{
#جے_تعریف_شدہ ENABLE_PKCS11
	بنية sshkey **کلیدیں = عدم, *عام, *خاص = عدم;
	صحيح r, i, nkeys;

	إذا ((r = sshkey_لدو_عوامی(رستہ, &عام, عدم)) != 0)
		fatal_r(r, "Couldn't load CA public key \"%s\"", رستہ);

	nkeys = pkcs11_جوڑو_provider(pkcs11provider, پچھان_تت_passphrase,
	    &کلیدیں, عدم);
	debug3_f("%d keys", nkeys);
	إذا (nkeys <= 0)
		fatal("cannot read public key from pkcs11");
	لكل (i = 0; i < nkeys; i++) {
		إذا (sshkey_equal_عوامی(عام, کلیدیں[i])) {
			خاص = کلیدیں[i];
			استمر;
		}
		sshkey_free(کلیدیں[i]);
	}
	حرر(کلیدیں);
	sshkey_free(عام);
	أرجع خاص;
#وإلا
	fatal("no pkcs11 support");
#جے_انت /* ENABLE_PKCS11 */
}

/* Signer for sshkey_certify_custom that uses the agent */
ساكن صحيح
agent_signer(بنية sshkey *کلید, u_char **sigp, ناپ_t *lenp,
    ثابت u_char *انکڑے, ناپ_t datalen,
    ثابت حرف *alg, ثابت حرف *provider, ثابت حرف *pin,
    u_int compat, فراغ *ctx)
{
	صحيح *agent_fdp = (صحيح *)ctx;

	أرجع ssh_agent_sign(*agent_fdp, کلید, sigp, lenp,
	    انکڑے, datalen, alg, compat);
}

ساكن فراغ
do_ca_sign(بنية passwd *pw, ثابت حرف *ca_کلید_رستہ, صحيح prefer_agent,
    بنانشانی لما لما cert_serial, صحيح cert_serial_autoinc,
    صحيح argc, حرف **argv)
{
	صحيح r, i, کلید_وچ_agent = 0, agent_fd = -1;
	u_int n;
	بنية sshkey *ca, *عام;
	حرف valid[64], *otmp, *tmp, *cp, *باہرلا, *comment;
	حرف *ca_fp = عدم, **plist = عدم, *pin = عدم;
	بنية ssh_identitylist *agent_ids;
	ناپ_t j;
	بنية notifier_ctx *notifier = عدم;

#جے_تعریف_شدہ ENABLE_PKCS11
	pkcs11_init(1);
#جے_انت
	tmp = tilde_expand_filename(ca_کلید_رستہ, pw->pw_uid);
	إذا (pkcs11provider != عدم) {
		/* If a PKCS#11 token was specified then try to use it */
		إذا ((ca = لدو_pkcs11_کلید(tmp)) == عدم)
			fatal("No PKCS#11 key matching %s found", ca_کلید_رستہ);
	} وإلا إذا (prefer_agent) {
		/*
		 * Agent signature requested. Try to use agent after making
		 * sure the public key specified is actually present in the
		 * agent.
		 */
		إذا ((r = sshkey_لدو_عوامی(tmp, &ca, عدم)) != 0)
			fatal_r(r, "Cannot load CA public key %s", tmp);
		إذا ((r = ssh_get_authentication_socket(&agent_fd)) != 0)
			fatal_r(r, "Cannot use public key for CA signature");
		إذا ((r = ssh_fetch_identitylist(agent_fd, &agent_ids)) != 0)
			fatal_r(r, "Retrieve agent key list");
		لكل (j = 0; j < agent_ids->nkeys; j++) {
			إذا (sshkey_equal(ca, agent_ids->کلیدیں[j])) {
				کلید_وچ_agent = 1;
				/* Replace the CA key with the agent one */
				sshkey_free(ca);
				ca = agent_ids->کلیدیں[j];
				agent_ids->کلیدیں[j] = عدم;
				اكسر;
			}
		}
		إذا (!کلید_وچ_agent)
			fatal("CA key %s not found in agent", tmp);
		ssh_free_identitylist(agent_ids);
	} وإلا {
		/* CA key is assumed to be a private key on the filesystem */
		ca = لدو_پچھان_تت(tmp, عدم);
		إذا (sshkey_is_sk(ca) &&
		    (ca->sk_flags & SSH_SK_USER_VERIFICATION_REQD)) {
			إذا ((pin = read_passphrase("Enter PIN for CA key: ",
			    RP_ALLOW_STDIN)) == عدم)
				fatal_f("couldn't read PIN");
		}
	}
	حرر(tmp);

	إذا (کلید_type_name != عدم) {
		إذا (sshkey_type_from_shortname(کلید_type_name) != ca->type) {
			fatal("CA key type %s doesn't match specified %s",
			    sshkey_ssh_name(ca), کلید_type_name);
		}
	} وإلا إذا (ca->type == کلید_RSA) {
		/* Default to a good signature algorithm */
		کلید_type_name = "rsa-sha2-512";
	}
	ca_fp = sshkey_fingerprint(ca, fingerprint_hash, SSH_FP_DEFAULT);

	finalise_cert_exts();
	لكل (i = 0; i < argc; i++) {
		/* Split list of principals */
		n = 0;
		إذا (cert_principals != عدم) {
			otmp = tmp = xstrdup(cert_principals);
			plist = عدم;
			لكل (; (cp = strsep(&tmp, ",")) != عدم; n++) {
				plist = xreallocarray(plist, n + 1, حجم(*plist));
				إذا (*(plist[n] = xstrdup(cp)) == '\0')
					fatal("Empty principal name");
			}
			حرر(otmp);
		}
		إذا (n > SSHKEY_CERT_MAX_PRINCIPALS)
			fatal("Too many certificate principals specified");

		tmp = tilde_expand_filename(argv[i], pw->pw_uid);
		إذا ((r = sshkey_لدو_عوامی(tmp, &عام, &comment)) != 0)
			fatal_r(r, "load pubkey \"%s\"", tmp);
		إذا (sshkey_is_cert(عام))
			fatal_f("key \"%s\" type %s cannot be certified",
			    tmp, sshkey_type(عام));

		/* Prepare certificate to sign */
		إذا ((r = sshkey_منزل_certified(عام)) != 0)
			fatal_r(r, "Could not upgrade key %s to certificate", tmp);
		عام->cert->type = cert_کلید_type;
		عام->cert->serial = (uint64_t)cert_serial;
		عام->cert->کلید_id = xstrdup(cert_کلید_id);
		عام->cert->nprincipals = n;
		عام->cert->principals = plist;
		عام->cert->valid_after = cert_valid_from;
		عام->cert->valid_before = cert_valid_منزل;
		prepare_options_buf(عام->cert->critical, OPTIONS_CRITICAL);
		prepare_options_buf(عام->cert->extensions,
		    OPTIONS_EXTENSIONS);
		إذا ((r = sshkey_from_نجی(ca,
		    &عام->cert->signature_کلید)) != 0)
			fatal_r(r, "sshkey_from_private (ca key)");

		إذا (کلید_وچ_agent) {
			إذا ((r = sshkey_certify_custom(عام, ca,
			    کلید_type_name, sk_provider, عدم, agent_signer,
			    &agent_fd)) != 0)
				fatal_r(r, "Couldn't certify %s via agent", tmp);
		} وإلا {
			إذا (sshkey_is_sk(ca) &&
			    (ca->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
				notifier = notify_شروع(0,
				    "Confirm user presence for key %s %s",
				    sshkey_type(ca), ca_fp);
			}
			r = sshkey_certify(عام, ca, کلید_type_name,
			    sk_provider, pin);
			notify_complete(notifier, "User presence confirmed");
			إذا (r != 0)
				fatal_r(r, "Couldn't certify key %s", tmp);
		}

		إذا ((cp = strrchr(tmp, '.')) != عدم && strcmp(cp, ".pub") == 0)
			*cp = '\0';
		xasprintf(&باہرلا, "%s-cert.pub", tmp);
		حرر(tmp);

		إذا ((r = sshkey_save_عوامی(عام, باہرلا, comment)) != 0) {
			fatal_r(r, "Unable to save public key to %s",
			    پچھان_تت_file);
		}

		إذا (!quiet) {
			sshkey_format_cert_validity(عام->cert,
			    valid, حجم(valid));
			logit("Signed %s key %s: id \"%s\" serial %llu%s%s "
			    "valid %s", sshkey_cert_type(عام),
			    باہرلا, عام->cert->کلید_id,
			    (بنانشانی لما لما)عام->cert->serial,
			    cert_principals != عدم ? " for " : "",
			    cert_principals != عدم ? cert_principals : "",
			    valid);
		}

		sshkey_free(عام);
		حرر(باہرلا);
		حرر(comment);
		إذا (cert_serial_autoinc)
			cert_serial++;
	}
	إذا (pin != عدم)
		freezero(pin, لڑی_لمبائی(pin));
	sshkey_free(ca);
	حرر(ca_fp);
#جے_تعریف_شدہ ENABLE_PKCS11
	pkcs11_terminate();
#جے_انت
}

ساكن uint64_t
parse_relative_ویلا(ثابت حرف *s, time_t now)
{
	int64_t mul, secs;

	mul = *s == '-' ? -1 : 1;

	إذا ((secs = convtime(s + 1)) == -1)
		fatal("Invalid relative certificate time %s", s);
	إذا (mul == -1 && secs > now)
		fatal("Certificate time %s cannot be represented", s);
	أرجع now + (uint64_t)(secs * mul);
}

ساكن فراغ
parse_hex_u64(ثابت حرف *s, uint64_t *اتے)
{
	حرف *ep;
	بنانشانی لما لما ull;

	errno = 0;
	ull = strtoull(s, &ep, 16);
	إذا (*s == '\0' || *ep != '\0')
		fatal("Invalid certificate time: not a number");
	إذا (errno == ERANGE && ull == ULONG_MAX)
		fatal_fr(SSH_ERR_SYSTEM_ERROR, "Invalid certificate time");
	*اتے = (uint64_t)ull;
}

ساكن فراغ
parse_cert_times(حرف *timespec)
{
	حرف *from, *منزل;
	time_t now = time(عدم);
	int64_t secs;

	/* +timespec relative to now */
	إذا (*timespec == '+' && strchr(timespec, ':') == عدم) {
		إذا ((secs = convtime(timespec + 1)) == -1)
			fatal("Invalid relative certificate life %s", timespec);
		cert_valid_منزل = now + secs;
		/*
		 * Backdate certificate one minute to avoid problems on hosts
		 * with poorly-synchronised clocks.
		 */
		cert_valid_from = ((now - 59)/ 60) * 60;
		أرجع;
	}

	/*
	 * from:to, where
	 * from := [+-]timespec | YYYYMMDD | YYYYMMDDHHMMSS | 0x... | "always"
	 *   to := [+-]timespec | YYYYMMDD | YYYYMMDDHHMMSS | 0x... | "forever"
	 */
	from = xstrdup(timespec);
	منزل = strchr(from, ':');
	إذا (منزل == عدم || from == منزل || *(منزل + 1) == '\0')
		fatal("Invalid certificate life specification %s", timespec);
	*منزل++ = '\0';

	إذا (*from == '-' || *from == '+')
		cert_valid_from = parse_relative_ویلا(from, now);
	وإلا إذا (strcmp(from, "always") == 0)
		cert_valid_from = 0;
	وإلا إذا (لڑی_مقابلہ(from, "0x", 2) == 0)
		parse_hex_u64(from, &cert_valid_from);
	وإلا إذا (parse_absolute_ویلا(from, &cert_valid_from) != 0)
		fatal("Invalid from time \"%s\"", from);

	إذا (*منزل == '-' || *منزل == '+')
		cert_valid_منزل = parse_relative_ویلا(منزل, now);
	وإلا إذا (strcmp(منزل, "forever") == 0)
		cert_valid_منزل = ~(uint64_t)0;
	وإلا إذا (لڑی_مقابلہ(منزل, "0x", 2) == 0)
		parse_hex_u64(منزل, &cert_valid_منزل);
	وإلا إذا (parse_absolute_ویلا(منزل, &cert_valid_منزل) != 0)
		fatal("Invalid to time \"%s\"", منزل);

	إذا (cert_valid_منزل <= cert_valid_from)
		fatal("Empty certificate validity interval");
	حرر(from);
}

ساكن فراغ
جوڑو_cert_option(حرف *opt)
{
	حرف *val, *cp;
	ثابت حرف *p;
	صحيح iscrit = 0;

	إذا (strcasecmp(opt, "clear") == 0)
		certflags_flags = 0;
	وإلا إذا (strcasecmp(opt, "no-x11-forwarding") == 0)
		certflags_flags &= ~CERTOPT_X_FWD;
	وإلا إذا (strcasecmp(opt, "permit-x11-forwarding") == 0)
		certflags_flags |= CERTOPT_X_FWD;
	وإلا إذا (strcasecmp(opt, "no-agent-forwarding") == 0)
		certflags_flags &= ~CERTOPT_AGENT_FWD;
	وإلا إذا (strcasecmp(opt, "permit-agent-forwarding") == 0)
		certflags_flags |= CERTOPT_AGENT_FWD;
	وإلا إذا (strcasecmp(opt, "no-port-forwarding") == 0)
		certflags_flags &= ~CERTOPT_پورٹ_FWD;
	وإلا إذا (strcasecmp(opt, "permit-port-forwarding") == 0)
		certflags_flags |= CERTOPT_پورٹ_FWD;
	وإلا إذا (strcasecmp(opt, "no-pty") == 0)
		certflags_flags &= ~CERTOPT_PTY;
	وإلا إذا (strcasecmp(opt, "permit-pty") == 0)
		certflags_flags |= CERTOPT_PTY;
	وإلا إذا (strcasecmp(opt, "no-user-rc") == 0)
		certflags_flags &= ~CERTOPT_USER_RC;
	وإلا إذا (strcasecmp(opt, "permit-user-rc") == 0)
		certflags_flags |= CERTOPT_USER_RC;
	وإلا إذا (strcasecmp(opt, "touch-required") == 0)
		certflags_flags &= ~CERTOPT_NO_REQUIRE_USER_PRESENCE;
	وإلا إذا (strcasecmp(opt, "no-touch-required") == 0)
		certflags_flags |= CERTOPT_NO_REQUIRE_USER_PRESENCE;
	وإلا إذا (strcasecmp(opt, "no-verify-required") == 0)
		certflags_flags &= ~CERTOPT_REQUIRE_VERIFY;
	وإلا إذا (strcasecmp(opt, "verify-required") == 0)
		certflags_flags |= CERTOPT_REQUIRE_VERIFY;
	وإلا إذا ((p = strprefix(opt, "force-command=", 1)) != عدم) {
		إذا (*p == '\0')
			fatal("Empty force-command option");
		إذا (certflags_command != عدم)
			fatal("force-command already specified");
		certflags_command = xstrdup(p);
	} وإلا إذا ((p = strprefix(opt, "source-address=", 1)) != عدم) {
		إذا (*p == '\0')
			fatal("Empty source-address option");
		إذا (certflags_src_addr != عدم)
			fatal("source-address already specified");
		إذا (addr_میل_cidr_list(عدم, p) != 0)
			fatal("Invalid source-address list");
		certflags_src_addr = xstrdup(p);
	} وإلا إذا (strprefix(opt, "extension:", 1) != عدم ||
		    (iscrit = (strprefix(opt, "critical:", 1) != عدم))) {
		val = xstrdup(strchr(opt, ':') + 1);
		إذا ((cp = strchr(val, '=')) != عدم)
			*cp++ = '\0';
		cert_ext_جوڑو(val, cp, iscrit);
		حرر(val);
	} وإلا
		fatal("Unsupported certificate option \"%s\"", opt);
}

ساكن فراغ
show_options(بنية sshbuf *optbuf, صحيح وچ_critical)
{
	حرف *name, *arg, *hex;
	بنية sshbuf *options, *option = عدم;
	صحيح r;

	إذا ((options = sshbuf_fromb(optbuf)) == عدم)
		fatal_f("sshbuf_fromb failed");
	طالما (sshbuf_len(options) != 0) {
		sshbuf_free(option);
		option = عدم;
		إذا ((r = sshbuf_get_cstring(options, &name, عدم)) != 0 ||
		    (r = sshbuf_froms(options, &option)) != 0)
			fatal_fr(r, "parse option");
		لکھو("                %s", name);
		إذا (!وچ_critical &&
		    (strcmp(name, "permit-X11-forwarding") == 0 ||
		    strcmp(name, "permit-agent-forwarding") == 0 ||
		    strcmp(name, "permit-port-forwarding") == 0 ||
		    strcmp(name, "permit-pty") == 0 ||
		    strcmp(name, "permit-user-rc") == 0 ||
		    strcmp(name, "no-touch-required") == 0)) {
			لکھو("\n");
		} وإلا إذا (وچ_critical &&
		    (strcmp(name, "force-command") == 0 ||
		    strcmp(name, "source-address") == 0)) {
			إذا ((r = sshbuf_get_cstring(option, &arg, عدم)) != 0)
				fatal_fr(r, "parse critical");
			لکھو(" %s\n", arg);
			حرر(arg);
		} وإلا إذا (وچ_critical &&
		    strcmp(name, "verify-required") == 0) {
			لکھو("\n");
		} وإلا إذا (sshbuf_len(option) > 0) {
			hex = sshbuf_dtob16(option);
			لکھو(" UNKNOWN OPTION: %s (len %zu)\n",
			    hex, sshbuf_len(option));
			sshbuf_reset(option);
			حرر(hex);
		} وإلا
			لکھو(" UNKNOWN FLAG OPTION\n");
		حرر(name);
		إذا (sshbuf_len(option) != 0)
			fatal("Option corrupt: extra data at end");
	}
	sshbuf_free(option);
	sshbuf_free(options);
}

ساكن فراغ
print_cert(بنية sshkey *کلید)
{
	حرف valid[64], *کلید_fp, *ca_fp;
	u_int i;

	کلید_fp = sshkey_fingerprint(کلید, fingerprint_hash, SSH_FP_DEFAULT);
	ca_fp = sshkey_fingerprint(کلید->cert->signature_کلید,
	    fingerprint_hash, SSH_FP_DEFAULT);
	إذا (کلید_fp == عدم || ca_fp == عدم)
		fatal_f("sshkey_fingerprint fail");
	sshkey_format_cert_validity(کلید->cert, valid, حجم(valid));

	لکھو("        Type: %s %s certificate\n", sshkey_ssh_name(کلید),
	    sshkey_cert_type(کلید));
	لکھو("        Public key: %s %s\n", sshkey_type(کلید), کلید_fp);
	لکھو("        Signing CA: %s %s (using %s)\n",
	    sshkey_type(کلید->cert->signature_کلید), ca_fp,
	    کلید->cert->signature_type);
	لکھو("        Key ID: \"%s\"\n", کلید->cert->کلید_id);
	لکھو("        Serial: %llu\n", (بنانشانی لما لما)کلید->cert->serial);
	لکھو("        Valid: %s\n", valid);
	لکھو("        Principals: ");
	إذا (کلید->cert->nprincipals == 0)
		لکھو("(none)\n");
	وإلا {
		لكل (i = 0; i < کلید->cert->nprincipals; i++)
			لکھو("\n                %s",
			    کلید->cert->principals[i]);
		لکھو("\n");
	}
	لکھو("        Critical Options: ");
	إذا (sshbuf_len(کلید->cert->critical) == 0)
		لکھو("(none)\n");
	وإلا {
		لکھو("\n");
		show_options(کلید->cert->critical, 1);
	}
	لکھو("        Extensions: ");
	إذا (sshbuf_len(کلید->cert->extensions) == 0)
		لکھو("(none)\n");
	وإلا {
		لکھو("\n");
		show_options(کلید->cert->extensions, 0);
	}
	حرر(کلید_fp);
	حرر(ca_fp);
}

ساكن فراغ
do_show_cert(بنية passwd *pw)
{
	بنية sshkey *کلید = عدم;
	بنية stat st;
	صحيح r, is_stdin = 0, ok = 0;
	FILE *f;
	حرف *cp, *سطر = عدم;
	ثابت حرف *رستہ;
	ناپ_t linesize = 0;
	u_long lnum = 0;

	إذا (!have_پچھان_تت)
		ask_filename(pw, "Enter file in which the key is");
	إذا (strcmp(پچھان_تت_file, "-") != 0 && stat(پچھان_تت_file, &st) == -1)
		fatal("%s: %s: %s", __progname, پچھان_تت_file, strerror(errno));

	رستہ = پچھان_تت_file;
	إذا (strcmp(رستہ, "-") == 0) {
		f = stdin;
		رستہ = "(stdin)";
		is_stdin = 1;
	} وإلا إذا ((f = fopen(پچھان_تت_file, "r")) == عدم)
		fatal("fopen %s: %s", پچھان_تت_file, strerror(errno));

	طالما (getline(&سطر, &linesize, f) != -1) {
		lnum++;
		sshkey_free(کلید);
		کلید = عدم;
		/* Trim leading space and comments */
		cp = سطر + strspn(سطر, " \t");
		إذا (*cp == '#' || *cp == '\0')
			استمر;
		إذا ((کلید = sshkey_new(کلید_UNSPEC)) == عدم)
			fatal("sshkey_new");
		إذا ((r = sshkey_read(کلید, &cp)) != 0) {
			error_r(r, "%s:%lu: invalid key", رستہ, lnum);
			استمر;
		}
		إذا (!sshkey_is_cert(کلید)) {
			error("%s:%lu is not a certificate", رستہ, lnum);
			استمر;
		}
		ok = 1;
		إذا (!is_stdin && lnum == 1)
			لکھو("%s:\n", رستہ);
		وإلا
			لکھو("%s:%lu:\n", رستہ, lnum);
		print_cert(کلید);
	}
	حرر(سطر);
	sshkey_free(کلید);
	fclose(f);
	باہر_نکلو(ok ? 0 : 1);
}

ساكن فراغ
لدو_krl(ثابت حرف *رستہ, بنية ssh_krl **krlp)
{
	بنية sshbuf *krlbuf;
	صحيح r;

	إذا ((r = sshbuf_لدو_file(رستہ, &krlbuf)) != 0)
		fatal_r(r, "Unable to load KRL %s", رستہ);
	/* XXX check sigs */
	إذا ((r = ssh_krl_from_blob(krlbuf, krlp)) != 0 ||
	    *krlp == عدم)
		fatal_r(r, "Invalid KRL file %s", رستہ);
	sshbuf_free(krlbuf);
}

ساكن فراغ
hash_منزل_blob(ثابت حرف *cp, u_char **blobp, ناپ_t *lenp,
    ثابت حرف *file, u_long lnum)
{
	حرف *tmp;
	ناپ_t tlen;
	بنية sshbuf *b;
	صحيح r;

	إذا ((cp = strprefix(cp, "SHA256:", 0)) == عدم)
		fatal("%s:%lu: unsupported hash algorithm", file, lnum);

	/*
	 * OpenSSH base64 hashes omit trailing '='
	 * characters; put them back for decode.
	 */
	إذا ((tlen = لڑی_لمبائی(cp)) >= SIZE_MAX - 5)
		fatal_f("hash too long: %zu bytes", tlen);
	tmp = xmalloc(tlen + 4 + 1);
	strlcpy(tmp, cp, tlen + 1);
	طالما ((tlen % 4) != 0) {
		tmp[tlen++] = '=';
		tmp[tlen] = '\0';
	}
	إذا ((b = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshbuf_b64tod(b, tmp)) != 0)
		fatal_r(r, "%s:%lu: decode hash failed", file, lnum);
	حرر(tmp);
	*lenp = sshbuf_len(b);
	*blobp = xmalloc(*lenp);
	حافظہ_نقل(*blobp, sshbuf_ptr(b), *lenp);
	sshbuf_free(b);
}

ساكن فراغ
update_krl_from_file(بنية passwd *pw, ثابت حرف *file, صحيح wild_ca,
    ثابت بنية sshkey *ca, بنية ssh_krl *krl)
{
	بنية sshkey *کلید = عدم;
	u_long lnum = 0;
	حرف *رستہ, *cp, *ep, *سطر = عدم;
	u_char *blob = عدم;
	ناپ_t blen = 0, linesize = 0;
	بنانشانی لما لما serial, serial2;
	صحيح i, was_explicit_کلید, was_sha1, was_sha256, was_hash, r;
	FILE *krl_spec;

	رستہ = tilde_expand_filename(file, pw->pw_uid);
	إذا (strcmp(رستہ, "-") == 0) {
		krl_spec = stdin;
		حرر(رستہ);
		رستہ = xstrdup("(standard input)");
	} وإلا إذا ((krl_spec = fopen(رستہ, "r")) == عدم)
		fatal("fopen %s: %s", رستہ, strerror(errno));

	إذا (!quiet)
		لکھو("Revoking from %s\n", رستہ);
	طالما (getline(&سطر, &linesize, krl_spec) != -1) {
		إذا (linesize >= ودھ_توں_ودھ_عدد) {
			fatal_f("%s contains unparsable line, len=%zu",
			    رستہ, linesize);
		}
		lnum++;
		was_explicit_کلید = was_sha1 = was_sha256 = was_hash = 0;
		cp = سطر + strspn(سطر, " \t");
		/* Trim trailing space, comments and strip \n */
		لكل (i = 0, r = -1; cp[i] != '\0'; i++) {
			إذا (cp[i] == '#' || cp[i] == '\n') {
				cp[i] = '\0';
				اكسر;
			}
			إذا (cp[i] == ' ' || cp[i] == '\t') {
				/* Remember the start of a span of whitespace */
				إذا (r == -1)
					r = i;
			} وإلا
				r = -1;
		}
		إذا (r != -1)
			cp[r] = '\0';
		إذا (*cp == '\0')
			استمر;
		إذا (strncasecmp(cp, "serial:", 7) == 0) {
			إذا (ca == عدم && !wild_ca) {
				fatal("revoking certificates by serial number "
				    "requires specification of a CA key");
			}
			cp += 7;
			cp = cp + strspn(cp, " \t");
			errno = 0;
			serial = strtoull(cp, &ep, 0);
			إذا (*cp == '\0' || (*ep != '\0' && *ep != '-'))
				fatal("%s:%lu: invalid serial \"%s\"",
				    رستہ, lnum, cp);
			إذا (errno == ERANGE && serial == ULLONG_MAX)
				fatal("%s:%lu: serial out of range",
				    رستہ, lnum);
			serial2 = serial;
			إذا (*ep == '-') {
				cp = ep + 1;
				errno = 0;
				serial2 = strtoull(cp, &ep, 0);
				إذا (*cp == '\0' || *ep != '\0')
					fatal("%s:%lu: invalid serial \"%s\"",
					    رستہ, lnum, cp);
				إذا (errno == ERANGE && serial2 == ULLONG_MAX)
					fatal("%s:%lu: serial out of range",
					    رستہ, lnum);
				إذا (serial2 <= serial)
					fatal("%s:%lu: invalid serial range "
					    "%llu:%llu", رستہ, lnum,
					    (بنانشانی لما لما)serial,
					    (بنانشانی لما لما)serial2);
			}
			إذا (ssh_krl_revoke_cert_by_serial_range(krl,
			    ca, serial, serial2) != 0) {
				fatal_f("revoke serial failed");
			}
		} وإلا إذا (strncasecmp(cp, "id:", 3) == 0) {
			إذا (ca == عدم && !wild_ca) {
				fatal("revoking certificates by key ID "
				    "requires specification of a CA key");
			}
			cp += 3;
			cp = cp + strspn(cp, " \t");
			إذا (ssh_krl_revoke_cert_by_کلید_id(krl, ca, cp) != 0)
				fatal_f("revoke key ID failed");
		} وإلا إذا (strncasecmp(cp, "hash:", 5) == 0) {
			cp += 5;
			cp = cp + strspn(cp, " \t");
			hash_منزل_blob(cp, &blob, &blen, file, lnum);
			إذا ((r = ssh_krl_revoke_کلید_sha256(krl,
			    blob, blen)) != 0)
				fatal_fr(r, "revoke key failed");
			حرر(blob);
			blob = عدم;
			blen = 0;
		} وإلا {
			إذا (strncasecmp(cp, "key:", 4) == 0) {
				cp += 4;
				cp = cp + strspn(cp, " \t");
				was_explicit_کلید = 1;
			} وإلا إذا (strncasecmp(cp, "sha1:", 5) == 0) {
				cp += 5;
				cp = cp + strspn(cp, " \t");
				was_sha1 = 1;
			} وإلا إذا (strncasecmp(cp, "sha256:", 7) == 0) {
				cp += 7;
				cp = cp + strspn(cp, " \t");
				was_sha256 = 1;
				/*
				 * Just try to process the line as a key.
				 * Parsing will fail if it isn't.
				 */
			}
			إذا ((کلید = sshkey_new(کلید_UNSPEC)) == عدم)
				fatal("sshkey_new");
			إذا ((r = sshkey_read(کلید, &cp)) != 0)
				fatal_r(r, "%s:%lu: invalid key", رستہ, lnum);
			إذا (was_explicit_کلید)
				r = ssh_krl_revoke_کلید_explicit(krl, کلید);
			وإلا إذا (was_sha1) {
				إذا (sshkey_fingerprint_raw(کلید,
				    SSH_DIGEST_SHA1, &blob, &blen) != 0) {
					fatal("%s:%lu: fingerprint failed",
					    file, lnum);
				}
				r = ssh_krl_revoke_کلید_sha1(krl, blob, blen);
			} وإلا إذا (was_sha256) {
				إذا (sshkey_fingerprint_raw(کلید,
				    SSH_DIGEST_SHA256, &blob, &blen) != 0) {
					fatal("%s:%lu: fingerprint failed",
					    file, lnum);
				}
				r = ssh_krl_revoke_کلید_sha256(krl, blob, blen);
			} وإلا
				r = ssh_krl_revoke_کلید(krl, کلید);
			إذا (r != 0)
				fatal_fr(r, "revoke key failed");
			freezero(blob, blen);
			blob = عدم;
			blen = 0;
			sshkey_free(کلید);
		}
	}
	إذا (strcmp(رستہ, "-") != 0)
		fclose(krl_spec);
	حرر(سطر);
	حرر(رستہ);
}

ساكن فراغ
do_gen_krl(بنية passwd *pw, صحيح updating, ثابت حرف *ca_کلید_رستہ,
    بنانشانی لما لما krl_نسخہ, ثابت حرف *krl_comment,
    صحيح argc, حرف **argv)
{
	بنية ssh_krl *krl;
	بنية stat sb;
	بنية sshkey *ca = عدم;
	صحيح i, r, wild_ca = 0;
	حرف *tmp;
	بنية sshbuf *kbuf;

	إذا (*پچھان_تت_file == '\0')
		fatal("KRL generation requires an output file");
	إذا (stat(پچھان_تت_file, &sb) == -1) {
		إذا (errno != ENOENT)
			fatal("Cannot access KRL \"%s\": %s",
			    پچھان_تت_file, strerror(errno));
		إذا (updating)
			fatal("KRL \"%s\" does not exist", پچھان_تت_file);
	}
	إذا (ca_کلید_رستہ != عدم) {
		إذا (strcasecmp(ca_کلید_رستہ, "none") == 0)
			wild_ca = 1;
		وإلا {
			tmp = tilde_expand_filename(ca_کلید_رستہ, pw->pw_uid);
			إذا ((r = sshkey_لدو_عوامی(tmp, &ca, عدم)) != 0)
				fatal_r(r, "Cannot load CA public key %s", tmp);
			حرر(tmp);
		}
	}

	إذا (updating)
		لدو_krl(پچھان_تت_file, &krl);
	وإلا إذا ((krl = ssh_krl_init()) == عدم)
		fatal("couldn't create KRL");

	إذا (krl_نسخہ != 0)
		ssh_krl_سیٹ_نسخہ(krl, krl_نسخہ);
	إذا (krl_comment != عدم)
		ssh_krl_سیٹ_comment(krl, krl_comment);

	لكل (i = 0; i < argc; i++)
		update_krl_from_file(pw, argv[i], wild_ca, ca, krl);

	إذا ((kbuf = sshbuf_new()) == عدم)
		fatal("sshbuf_new failed");
	إذا (ssh_krl_منزل_blob(krl, kbuf) != 0)
		fatal("Couldn't generate KRL");
	إذا ((r = sshbuf_write_file(پچھان_تت_file, kbuf)) != 0)
		fatal("write %s: %s", پچھان_تت_file, strerror(errno));
	sshbuf_free(kbuf);
	ssh_krl_free(krl);
	sshkey_free(ca);
}

ساكن فراغ
do_check_krl(بنية passwd *pw, صحيح print_krl, صحيح argc, حرف **argv)
{
	صحيح i, r, ret = 0;
	حرف *comment;
	بنية ssh_krl *krl;
	بنية sshkey *k;

	إذا (*پچھان_تت_file == '\0')
		fatal("KRL checking requires an input file");
	لدو_krl(پچھان_تت_file, &krl);
	إذا (print_krl)
		krl_dump(krl, stdout);
	لكل (i = 0; i < argc; i++) {
		إذا ((r = sshkey_لدو_عوامی(argv[i], &k, &comment)) != 0)
			fatal_r(r, "Cannot load public key %s", argv[i]);
		r = ssh_krl_check_کلید(krl, k);
		لکھو("%s%s%s%s: %s\n", argv[i],
		    *comment ? " (" : "", comment, *comment ? ")" : "",
		    r == 0 ? "ok" : "REVOKED");
		إذا (r != 0)
			ret = 1;
		sshkey_free(k);
		حرر(comment);
	}
	ssh_krl_free(krl);
	باہر_نکلو(ret);
}

ساكن بنية sshkey *
لدو_sign_کلید(ثابت حرف *keypath, ثابت بنية sshkey *pubkey)
{
	ناپ_t i, slen, plen = لڑی_لمبائی(keypath);
	حرف *privpath = xstrdup(keypath);
	ساكن ثابت حرف * ثابت suffixes[] = { "-cert.pub", ".pub", عدم };
	بنية sshkey *ret = عدم, *privkey = عدم;
	صحيح r, waspub = 0;
	بنية stat st;

	/*
	 * If passed a public key filename, then try to locate the corresponding
	 * private key. This lets us specify certificates on the command-line
	 * and have ssh-keygen find the appropriate private key.
	 */
	لكل (i = 0; suffixes[i]; i++) {
		slen = لڑی_لمبائی(suffixes[i]);
		إذا (plen <= slen ||
		    strcmp(privpath + plen - slen, suffixes[i]) != 0)
			استمر;
		privpath[plen - slen] = '\0';
		debug_f("%s looks like a public key, using private key "
		    "path %s instead", keypath, privpath);
		waspub = 1;
	}
	إذا (waspub && stat(privpath, &st) != 0 && errno == ENOENT)
		fatal("No private key found for public key \"%s\"", keypath);
	إذا ((r = sshkey_لدو_نجی(privpath, "", &privkey, عدم)) != 0 &&
	    (r != SSH_ERR_کلید_WRONG_PASSPHRASE)) {
		debug_fr(r, "load private key \"%s\"", privpath);
		fatal("No private key found for \"%s\"", privpath);
	} وإلا إذا (privkey == عدم)
		privkey = لدو_پچھان_تت(privpath, عدم);

	إذا (!sshkey_equal_عوامی(pubkey, privkey)) {
		error("Public key %s doesn't match private %s",
		    keypath, privpath);
		اذهب پورا;
	}
	إذا (sshkey_is_cert(pubkey) && !sshkey_is_cert(privkey)) {
		/*
		 * Graft the certificate onto the private key to make
		 * it capable of signing.
		 */
		إذا ((r = sshkey_منزل_certified(privkey)) != 0) {
			error_fr(r, "sshkey_to_certified");
			اذهب پورا;
		}
		إذا ((r = sshkey_cert_copy(pubkey, privkey)) != 0) {
			error_fr(r, "sshkey_cert_copy");
			اذهب پورا;
		}
	}
	/* success */
	ret = privkey;
	privkey = عدم;
 پورا:
	sshkey_free(privkey);
	حرر(privpath);
	أرجع ret;
}

ساكن صحيح
sign_one(بنية sshkey *signkey, ثابت حرف *filename, صحيح fd,
    ثابت حرف *sig_namespace, ثابت حرف *hashalg, sshsig_signer *signer,
    فراغ *signer_ctx)
{
	بنية sshbuf *sigbuf = عدم, *abuf = عدم;
	صحيح r = SSH_ERR_اندرونی_ERROR, wfd = -1, oerrno;
	حرف *wfile = عدم, *asig = عدم, *fp = عدم;
	حرف *pin = عدم, *prompt = عدم;

	إذا (!quiet) {
		إذا (fd == STDIN_FILENO)
			fprintf(stderr, "Signing data on standard input\n");
		وإلا
			fprintf(stderr, "Signing file %s\n", filename);
	}
	إذا (signer == عدم && sshkey_is_sk(signkey)) {
		إذا ((signkey->sk_flags & SSH_SK_USER_VERIFICATION_REQD)) {
			xasprintf(&prompt, "Enter PIN for %s key: ",
			    sshkey_type(signkey));
			إذا ((pin = read_passphrase(prompt,
			    RP_ALLOW_STDIN)) == عدم)
				fatal_f("couldn't read PIN");
		}
		إذا ((signkey->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
			إذا ((fp = sshkey_fingerprint(signkey, fingerprint_hash,
			    SSH_FP_DEFAULT)) == عدم)
				fatal_f("fingerprint failed");
			fprintf(stderr, "Confirm user presence for key %s %s\n",
			    sshkey_type(signkey), fp);
			حرر(fp);
		}
	}
	إذا ((r = sshsig_sign_fd(signkey, hashalg, sk_provider, pin,
	    fd, sig_namespace, &sigbuf, signer, signer_ctx)) != 0) {
		error_r(r, "Signing %s failed", filename);
		اذهب باہرلا;
	}
	إذا ((r = sshsig_armor(sigbuf, &abuf)) != 0) {
		error_fr(r, "sshsig_armor");
		اذهب باہرلا;
	}
	إذا ((asig = sshbuf_dup_string(abuf)) == عدم) {
		error_f("buffer error");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب باہرلا;
	}

	إذا (fd == STDIN_FILENO) {
		fputs(asig, stdout);
		fflush(stdout);
	} وإلا {
		xasprintf(&wfile, "%s.sig", filename);
		إذا (confirm_overwrite(wfile)) {
			إذا ((wfd = open(wfile, O_WRONLY|O_CREAT|O_TRUNC,
			    0666)) == -1) {
				oerrno = errno;
				error("Cannot open %s: %s",
				    wfile, strerror(errno));
				errno = oerrno;
				r = SSH_ERR_SYSTEM_ERROR;
				اذهب باہرلا;
			}
			إذا (atomicio(vwrite, wfd, asig,
			    لڑی_لمبائی(asig)) != لڑی_لمبائی(asig)) {
				oerrno = errno;
				error("Cannot write to %s: %s",
				    wfile, strerror(errno));
				errno = oerrno;
				r = SSH_ERR_SYSTEM_ERROR;
				اذهب باہرلا;
			}
			إذا (!quiet) {
				fprintf(stderr, "Write signature to %s\n",
				    wfile);
			}
		}
	}
	/* success */
	r = 0;
 باہرلا:
	حرر(wfile);
	حرر(prompt);
	حرر(asig);
	إذا (pin != عدم)
		freezero(pin, لڑی_لمبائی(pin));
	sshbuf_free(abuf);
	sshbuf_free(sigbuf);
	إذا (wfd != -1)
		close(wfd);
	أرجع r;
}

ساكن صحيح
sig_process_opts(حرف * ثابت *opts, ناپ_t nopts, حرف **hashalgp,
    uint64_t *verify_timep, صحيح *print_pubkey)
{
	ناپ_t i;
	time_t now;
	ثابت حرف *p;

	إذا (verify_timep != عدم)
		*verify_timep = 0;
	إذا (print_pubkey != عدم)
		*print_pubkey = 0;
	إذا (hashalgp != عدم)
		*hashalgp = عدم;
	لكل (i = 0; i < nopts; i++) {
		إذا (hashalgp != عدم &&
		    (p = strprefix(opts[i], "hashalg=", 1)) != عدم) {
			*hashalgp = xstrdup(p);
		} وإلا إذا (verify_timep &&
		    (p = strprefix(opts[i], "verify-time=", 1)) != عدم) {
			إذا (parse_absolute_ویلا(p, verify_timep) != 0 ||
			    *verify_timep == 0) {
				error("Invalid \"verify-time\" option");
				أرجع SSH_ERR_INVALID_دلیل;
			}
		} وإلا إذا (print_pubkey &&
		    strcasecmp(opts[i], "print-pubkey") == 0) {
			*print_pubkey = 1;
		} وإلا {
			error("Invalid option \"%s\"", opts[i]);
			أرجع SSH_ERR_INVALID_دلیل;
		}
	}
	إذا (verify_timep && *verify_timep == 0) {
		إذا ((now = time(عدم)) < 0) {
			error("Time is before epoch");
			أرجع SSH_ERR_INVALID_دلیل;
		}
		*verify_timep = (uint64_t)now;
	}
	أرجع 0;
}


ساكن صحيح
sig_sign(ثابت حرف *keypath, ثابت حرف *sig_namespace, صحيح require_agent,
    صحيح argc, حرف **argv, حرف * ثابت *opts, ناپ_t nopts)
{
	صحيح i, fd = -1, r, ret = -1;
	صحيح agent_fd = -1;
	بنية sshkey *pubkey = عدم, *privkey = عدم, *signkey = عدم;
	sshsig_signer *signer = عدم;
	حرف *hashalg = عدم;

	/* Check file arguments. */
	لكل (i = 0; i < argc; i++) {
		إذا (strcmp(argv[i], "-") != 0)
			استمر;
		إذا (i > 0 || argc > 1)
			fatal("Cannot sign mix of paths and standard input");
	}

	إذا (sig_process_opts(opts, nopts, &hashalg, عدم, عدم) != 0)
		اذهب پورا; /* error already logged */

	إذا ((r = sshkey_لدو_عوامی(keypath, &pubkey, عدم)) != 0) {
		error_r(r, "Couldn't load public key %s", keypath);
		اذهب پورا;
	}

	إذا ((r = ssh_get_authentication_socket(&agent_fd)) != 0) {
		إذا (require_agent)
			fatal("Couldn't get agent socket");
		debug_r(r, "Couldn't get agent socket");
	} وإلا {
		إذا ((r = ssh_agent_has_کلید(agent_fd, pubkey)) == 0)
			signer = agent_signer;
		وإلا {
			إذا (require_agent)
				fatal("Couldn't find key in agent");
			debug_r(r, "Couldn't find key in agent");
		}
	}

	إذا (signer == عدم) {
		/* Not using agent - try to load private key */
		إذا ((privkey = لدو_sign_کلید(keypath, pubkey)) == عدم)
			اذهب پورا;
		signkey = privkey;
	} وإلا {
		/* Will use key in agent */
		signkey = pubkey;
	}

	إذا (argc == 0) {
		إذا ((r = sign_one(signkey, "(stdin)", STDIN_FILENO,
		    sig_namespace, hashalg, signer, &agent_fd)) != 0)
			اذهب پورا;
	} وإلا {
		لكل (i = 0; i < argc; i++) {
			إذا (strcmp(argv[i], "-") == 0)
				fd = STDIN_FILENO;
			وإلا إذا ((fd = open(argv[i], O_RDONLY)) == -1) {
				error("Cannot open %s for signing: %s",
				    argv[i], strerror(errno));
				اذهب پورا;
			}
			إذا ((r = sign_one(signkey, argv[i], fd, sig_namespace,
			    hashalg, signer, &agent_fd)) != 0)
				اذهب پورا;
			إذا (fd != STDIN_FILENO)
				close(fd);
			fd = -1;
		}
	}

	ret = 0;
پورا:
	إذا (fd != -1 && fd != STDIN_FILENO)
		close(fd);
	sshkey_free(pubkey);
	sshkey_free(privkey);
	حرر(hashalg);
	أرجع ret;
}

ساكن صحيح
sig_verify(ثابت حرف *signature, ثابت حرف *sig_namespace,
    ثابت حرف *principal, ثابت حرف *allowed_کلیدیں, ثابت حرف *revoked_کلیدیں,
    حرف * ثابت *opts, ناپ_t nopts)
{
	صحيح r, ret = -1;
	صحيح print_pubkey = 0;
	بنية sshbuf *sigbuf = عدم, *abuf = عدم;
	بنية sshkey *sign_کلید = عدم;
	حرف *fp = عدم;
	بنية sshkey_sig_details *sig_details = عدم;
	uint64_t verify_ویلا = 0;

	إذا (sig_process_opts(opts, nopts, عدم, &verify_ویلا,
	    &print_pubkey) != 0)
		اذهب پورا; /* error already logged */

	memset(&sig_details, 0, حجم(sig_details));
	إذا ((r = sshbuf_لدو_file(signature, &abuf)) != 0) {
		error_r(r, "Couldn't read signature file");
		اذهب پورا;
	}

	إذا ((r = sshsig_dearmor(abuf, &sigbuf)) != 0) {
		error_fr(r, "sshsig_armor");
		اذهب پورا;
	}
	إذا ((r = sshsig_verify_fd(sigbuf, STDIN_FILENO, sig_namespace,
	    &sign_کلید, &sig_details)) != 0)
		اذهب پورا; /* sshsig_verify() prints error */

	إذا ((fp = sshkey_fingerprint(sign_کلید, fingerprint_hash,
	    SSH_FP_DEFAULT)) == عدم)
		fatal_f("sshkey_fingerprint failed");
	debug("Valid (unverified) signature from key %s", fp);
	إذا (sig_details != عدم) {
		debug2_f("signature details: counter = %u, flags = 0x%02x",
		    sig_details->sk_counter, sig_details->sk_flags);
	}
	حرر(fp);
	fp = عدم;

	إذا (revoked_کلیدیں != عدم) {
		إذا ((r = sshkey_check_revoked(sign_کلید, revoked_کلیدیں)) != 0) {
			debug3_fr(r, "sshkey_check_revoked");
			اذهب پورا;
		}
	}

	إذا (allowed_کلیدیں != عدم && (r = sshsig_check_allowed_کلیدیں(allowed_کلیدیں,
	    sign_کلید, principal, sig_namespace, verify_ویلا)) != 0) {
		debug3_fr(r, "sshsig_check_allowed_keys");
		اذهب پورا;
	}
	/* success */
	ret = 0;
پورا:
	إذا (!quiet) {
		إذا (ret == 0) {
			إذا ((fp = sshkey_fingerprint(sign_کلید, fingerprint_hash,
			    SSH_FP_DEFAULT)) == عدم)
				fatal_f("sshkey_fingerprint failed");
			إذا (principal == عدم) {
				لکھو("Good \"%s\" signature with %s key %s\n",
				    sig_namespace, sshkey_type(sign_کلید), fp);

			} وإلا {
				لکھو("Good \"%s\" signature for %s with %s key %s\n",
				    sig_namespace, principal,
				    sshkey_type(sign_کلید), fp);
			}
		} وإلا {
			لکھو("Could not verify signature.\n");
		}
	}
	/* Print the signature key if requested */
	إذا (ret == 0 && print_pubkey && sign_کلید != عدم) {
		إذا ((r = sshkey_write(sign_کلید, stdout)) == 0)
			fputc('\n', stdout);
		وإلا {
			error_r(r, "Could not print public key.\n");
			ret = -1;
		}
	}
	sshbuf_free(sigbuf);
	sshbuf_free(abuf);
	sshkey_free(sign_کلید);
	sshkey_sig_details_free(sig_details);
	حرر(fp);
	أرجع ret;
}

ساكن صحيح
sig_لبھو_principals(ثابت حرف *signature, ثابت حرف *allowed_کلیدیں,
    حرف * ثابت *opts, ناپ_t nopts)
{
	صحيح r, ret = -1;
	بنية sshbuf *sigbuf = عدم, *abuf = عدم;
	بنية sshkey *sign_کلید = عدم;
	حرف *principals = عدم, *cp, *tmp;
	uint64_t verify_ویلا = 0;

	إذا (sig_process_opts(opts, nopts, عدم, &verify_ویلا, عدم) != 0)
		اذهب پورا; /* error already logged */

	إذا ((r = sshbuf_لدو_file(signature, &abuf)) != 0) {
		error_r(r, "Couldn't read signature file");
		اذهب پورا;
	}
	إذا ((r = sshsig_dearmor(abuf, &sigbuf)) != 0) {
		error_fr(r, "sshsig_armor");
		اذهب پورا;
	}
	إذا ((r = sshsig_get_pubkey(sigbuf, &sign_کلید)) != 0) {
		error_fr(r, "sshsig_get_pubkey");
		اذهب پورا;
	}
	إذا ((r = sshsig_لبھو_principals(allowed_کلیدیں, sign_کلید,
	    verify_ویلا, &principals)) != 0) {
		إذا (r != SSH_ERR_کلید_NOT_لبھیا)
			error_fr(r, "sshsig_find_principal");
		اذهب پورا;
	}
	ret = 0;
پورا:
	إذا (ret == 0 ) {
		/* Emit matching principals one per line */
		tmp = principals;
		طالما ((cp = strsep(&tmp, ",")) != عدم && *cp != '\0')
			puts(cp);
	} وإلا {
		fprintf(stderr, "No principal matched.\n");
	}
	sshbuf_free(sigbuf);
	sshbuf_free(abuf);
	sshkey_free(sign_کلید);
	حرر(principals);
	أرجع ret;
}

ساكن صحيح
sig_میل_principals(ثابت حرف *allowed_کلیدیں, حرف *principal,
	حرف * ثابت *opts, ناپ_t nopts)
{
	صحيح r;
	حرف **principals = عدم;
	ناپ_t i, nprincipals = 0;

	إذا ((r = sig_process_opts(opts, nopts, عدم, عدم, عدم)) != 0)
		أرجع r; /* error already logged */

	إذا ((r = sshsig_میل_principals(allowed_کلیدیں, principal,
	    &principals, &nprincipals)) != 0) {
		debug_f("match: %s", ssh_err(r));
		fprintf(stderr, "No principal matched.\n");
		أرجع r;
	}
	لكل (i = 0; i < nprincipals; i++) {
		لکھو("%s\n", principals[i]);
		حرر(principals[i]);
	}
	حرر(principals);

	أرجع 0;
}

ساكن فراغ
do_moduli_gen(ثابت حرف *باہرلا_file, حرف **opts, ناپ_t nopts)
{
#جے_تعریف_شدہ WITH_OPENSSL
	/* Moduli generation/screening */
	BIGNUM *شروع = عدم;
	صحيح moduli_بٹ = 0;
	FILE *باہرلا;
	ناپ_t i;
	ثابت حرف *errstr, *p;

	/* Parse options */
	لكل (i = 0; i < nopts; i++) {
		إذا ((p = strprefix(opts[i], "start=", 0)) != عدم) {
			/* XXX - also compare length against bits */
			إذا (BN_hex2bn(&شروع, p) == 0)
				fatal("Invalid start point.");
		} وإلا إذا ((p = strprefix(opts[i], "bits=", 0)) != عدم) {
			moduli_بٹ = (صحيح)strtonum(p, 1, ودھ_توں_ودھ_عدد, &errstr);
			إذا (errstr) {
				fatal("Invalid number: %s (%s)", p, errstr);
			}
		} وإلا {
			fatal("Option \"%s\" is unsupported for moduli "
			    "generation", opts[i]);
		}
	}

	إذا (strcmp(باہرلا_file, "-") == 0)
		باہرلا = stdout;
	وإلا إذا ((باہرلا = fopen(باہرلا_file, "w")) == عدم) {
		fatal("Couldn't open modulus candidate file \"%s\": %s",
		    باہرلا_file, strerror(errno));
	}
	setvbuf(باہرلا, عدم, _IOLBF, 0);

	إذا (moduli_بٹ == 0)
		moduli_بٹ = DEFAULT_بٹ;
	إذا (gen_candidates(باہرلا, moduli_بٹ, شروع) != 0)
		fatal("modulus candidate generation failed");
#وإلا /* WITH_OPENSSL */
	fatal("Moduli generation is not supported");
#جے_انت /* WITH_OPENSSL */
}

ساكن فراغ
do_moduli_screen(ثابت حرف *باہرلا_file, حرف **opts, ناپ_t nopts)
{
#جے_تعریف_شدہ WITH_OPENSSL
	/* Moduli generation/screening */
	حرف *checkpoint = عدم;
	uint32_t generator_wanted = 0;
	بنانشانی لما شروع_lineno = 0, سطریں_منزل_process = 0;
	صحيح مفرد_tests = 0;
	FILE *باہرلا, *وچ = stdin;
	ناپ_t i;
	ثابت حرف *errstr, *p;

	/* Parse options */
	لكل (i = 0; i < nopts; i++) {
		إذا ((p = strprefix(opts[i], "lines=", 0)) != عدم) {
			سطریں_منزل_process = strtoul(p, عدم, 10);
		} وإلا إذا ((p = strprefix(opts[i], "start-line=", 0)) != عدم) {
			شروع_lineno = strtoul(p, عدم, 10);
		} وإلا إذا ((p = strprefix(opts[i], "checkpoint=", 0)) != عدم) {
			حرر(checkpoint);
			checkpoint = xstrdup(p);
		} وإلا إذا ((p = strprefix(opts[i], "generator=", 0)) != عدم) {
			generator_wanted = (uint32_t)strtonum(p, 1, UINT_MAX,
			    &errstr);
			إذا (errstr != عدم) {
				fatal("Generator invalid: %s (%s)", p, errstr);
			}
		} وإلا إذا ((p = strprefix(opts[i], "prime-tests=", 0)) != عدم) {
			مفرد_tests = (صحيح)strtonum(p, 1, ودھ_توں_ودھ_عدد, &errstr);
			إذا (errstr) {
				fatal("Invalid number: %s (%s)", p, errstr);
			}
		} وإلا {
			fatal("Option \"%s\" is unsupported for moduli "
			    "screening", opts[i]);
		}
	}

	إذا (have_پچھان_تت && strcmp(پچھان_تت_file, "-") != 0) {
		إذا ((وچ = fopen(پچھان_تت_file, "r")) == عدم) {
			fatal("Couldn't open modulus candidate "
			    "file \"%s\": %s", پچھان_تت_file,
			    strerror(errno));
		}
	}

	إذا (strcmp(باہرلا_file, "-") == 0)
		باہرلا = stdout;
	وإلا إذا ((باہرلا = fopen(باہرلا_file, "a")) == عدم) {
		fatal("Couldn't open moduli file \"%s\": %s",
		    باہرلا_file, strerror(errno));
	}
	setvbuf(باہرلا, عدم, _IOLBF, 0);
	إذا (مفرد_test(وچ, باہرلا, مفرد_tests == 0 ? 100 : مفرد_tests,
	    generator_wanted, checkpoint,
	    شروع_lineno, سطریں_منزل_process) != 0)
		fatal("modulus screening failed");
	إذا (وچ != stdin)
		(فراغ)fclose(وچ);
	حرر(checkpoint);
#وإلا /* WITH_OPENSSL */
	fatal("Moduli screening is not supported");
#جے_انت /* WITH_OPENSSL */
}

/* Read and confirm a passphrase */
ساكن حرف *
read_check_passphrase(ثابت حرف *prompt1, ثابت حرف *prompt2,
    ثابت حرف *retry_prompt)
{
	حرف *passphrase1, *passphrase2;

	لكل (;;) {
		passphrase1 = read_passphrase(prompt1, RP_ALLOW_STDIN);
		passphrase2 = read_passphrase(prompt2, RP_ALLOW_STDIN);
		إذا (strcmp(passphrase1, passphrase2) == 0) {
			freezero(passphrase2, لڑی_لمبائی(passphrase2));
			أرجع passphrase1;
		}
		/* The passphrases do not match. Clear them and retry. */
		freezero(passphrase1, لڑی_لمبائی(passphrase1));
		freezero(passphrase2, لڑی_لمبائی(passphrase2));
		fputs(retry_prompt, stdout);
		fputc('\n', stdout);
		fflush(stdout);
	}
	/* NOTREACHED */
	أرجع عدم;
}

ساكن حرف *
نجی_کلید_passphrase(ثابت حرف *رستہ)
{
	حرف *prompt, *ret;

	إذا (پچھان_تت_passphrase)
		أرجع xstrdup(پچھان_تت_passphrase);
	إذا (پچھان_تت_new_passphrase)
		أرجع xstrdup(پچھان_تت_new_passphrase);

	xasprintf(&prompt, "Enter passphrase for \"%s\" "
	    "(empty for no passphrase): ", رستہ);
	ret = read_check_passphrase(prompt,
	    "Enter same passphrase again: ",
	    "Passphrases do not match.  Try again.");
	حرر(prompt);
	أرجع ret;
}

ساكن حرف *
sk_suffix(ثابت حرف *application, ثابت uint8_t *user, ناپ_t userlen)
{
	حرف *ret, *cp;
	ثابت حرف *p;
	ناپ_t slen, i;

	/* Trim off URL-like preamble */
	إذا ((p = strprefix(application, "ssh://", 0)) != عدم)
		ret =  xstrdup(p);
	وإلا إذا ((p = strprefix(application, "ssh:", 0)) != عدم)
		ret =  xstrdup(p);
	وإلا
		ret = xstrdup(application);

	/* Count trailing zeros in user */
	لكل (i = 0; i < userlen; i++) {
		إذا (user[userlen - i - 1] != 0)
			اكسر;
	}
	إذا (i >= userlen)
		أرجع ret; /* user-id was default all-zeros */

	/* Append user-id, escaping non-UTF-8 characters */
	slen = userlen - i;
	إذا (asmprintf(&cp, ودھ_توں_ودھ_عدد, عدم, "%.*s", (صحيح)slen, user) == -1)
		fatal_f("asmprintf failed");
	/* Don't emit a user-id that contains path or control characters */
	إذا (strchr(cp, '/') != عدم || لڑی_کھوج(cp, "..") != عدم ||
	    strchr(cp, '\\') != عدم) {
		حرر(cp);
		cp = tohex(user, slen);
	}
	xextendf(&ret, "_", "%s", cp);
	حرر(cp);
	أرجع ret;
}

ساكن صحيح
do_download_sk(ثابت حرف *skprovider, ثابت حرف *device)
{
	بنية sshsk_resident_کلید **srks;
	ناپ_t nsrks, i;
	صحيح r, ret = -1;
	حرف *fp, *pin = عدم, *pass = عدم, *رستہ, *pubpath;
	ثابت حرف *ext;
	بنية sshkey *کلید;

	إذا (skprovider == عدم)
		fatal("Cannot download keys without provider");

	pin = read_passphrase("Enter PIN for authenticator: ", RP_ALLOW_STDIN);
	إذا (!quiet) {
		لکھو("You may need to touch your authenticator "
		    "to authorize key download.\n");
	}
	إذا ((r = sshsk_لدو_resident(skprovider, device, pin, 0,
	    &srks, &nsrks)) != 0) {
		إذا (pin != عدم)
			freezero(pin, لڑی_لمبائی(pin));
		error_r(r, "Unable to load resident keys");
		أرجع -1;
	}
	إذا (nsrks == 0)
		logit("No keys to download");
	إذا (pin != عدم)
		freezero(pin, لڑی_لمبائی(pin));

	لكل (i = 0; i < nsrks; i++) {
		کلید = srks[i]->کلید;
		إذا (کلید->type != کلید_ECDSA_SK && کلید->type != کلید_ED25519_SK) {
			error("Unsupported key type %s (%d)",
			    sshkey_type(کلید), کلید->type);
			استمر;
		}
		إذا ((fp = sshkey_fingerprint(کلید, fingerprint_hash,
		    SSH_FP_DEFAULT)) == عدم)
			fatal_f("sshkey_fingerprint failed");
		debug_f("key %zu: %s %s %s (flags 0x%02x)", i,
		    sshkey_type(کلید), fp, کلید->sk_application, کلید->sk_flags);
		ext = sk_suffix(کلید->sk_application,
		    srks[i]->user_id, srks[i]->user_id_len);
		xasprintf(&رستہ, "id_%s_rk%s%s",
		    کلید->type == کلید_ECDSA_SK ? "ecdsa_sk" : "ed25519_sk",
		    *ext == '\0' ? "" : "_", ext);

		/* If the file already exists, ask the user to confirm. */
		إذا (!confirm_overwrite(رستہ)) {
			حرر(رستہ);
			اكسر;
		}

		/* Save the key with the application string as the comment */
		إذا (pass == عدم)
			pass = نجی_کلید_passphrase(رستہ);
		إذا ((r = sshkey_save_نجی(کلید, رستہ, pass,
		    کلید->sk_application, نجی_کلید_format,
		    openssh_format_cipher, گیڑ)) != 0) {
			error_r(r, "Saving key \"%s\" failed", رستہ);
			حرر(رستہ);
			اكسر;
		}
		إذا (!quiet) {
			لکھو("Saved %s key%s%s to %s\n", sshkey_type(کلید),
			    *ext != '\0' ? " " : "",
			    *ext != '\0' ? کلید->sk_application : "",
			    رستہ);
		}

		/* Save public key too */
		xasprintf(&pubpath, "%s.pub", رستہ);
		حرر(رستہ);
		إذا ((r = sshkey_save_عوامی(کلید, pubpath,
		    کلید->sk_application)) != 0) {
			error_r(r, "Saving public key \"%s\" failed", pubpath);
			حرر(pubpath);
			اكسر;
		}
		حرر(pubpath);
	}

	إذا (i >= nsrks)
		ret = 0; /* success */
	إذا (pass != عدم)
		freezero(pass, لڑی_لمبائی(pass));
	sshsk_free_resident_کلیدیں(srks, nsrks);
	أرجع ret;
}

ساكن فراغ
save_attestation(بنية sshbuf *attest, ثابت حرف *رستہ)
{
	منوال_t omask;
	صحيح r;

	إذا (رستہ == عدم)
		أرجع; /* nothing to do */
	إذا (attest == عدم || sshbuf_len(attest) == 0)
		fatal("Enrollment did not return attestation data");
	omask = umask(077);
	r = sshbuf_write_file(رستہ, attest);
	umask(omask);
	إذا (r != 0)
		fatal_r(r, "Unable to write attestation data \"%s\"", رستہ);
	إذا (!quiet)
		لکھو("Your FIDO attestation certificate has been saved in "
		    "%s\n", رستہ);
}

ساكن صحيح
confirm_sk_overwrite(ثابت حرف *application, ثابت حرف *user)
{
	حرف yesno[3];

	لکھو("A resident key scoped to '%s' with user id '%s' already "
	    "exists.\n", application == عدم ? "ssh:" : application,
	    user == عدم ? "null" : user);
	لکھو("Overwrite key in token (y/n)? ");
	fflush(stdout);
	إذا (fgets(yesno, حجم(yesno), stdin) == عدم)
		أرجع 0;
	إذا (yesno[0] != 'y' && yesno[0] != 'Y')
		أرجع 0;
	أرجع 1;
}

ساكن فراغ
usage(فراغ)
{
	fprintf(stderr,
	    "usage: ssh-keygen [-q] [-a rounds] [-b bits] [-C comment] [-f output_keyfile]\n"
	    "                  [-m format] [-N new_passphrase] [-O option]\n"
	    "                  [-t ecdsa|ecdsa-sk|ed25519|ed25519-sk|mldsa44-ed25519|rsa]\n"
	    "                  [-w provider] [-Z cipher]\n"
	    "       ssh-keygen -p [-a rounds] [-f keyfile] [-m format] [-N new_passphrase]\n"
	    "                   [-P old_passphrase] [-Z cipher]\n"
#جے_تعریف_شدہ WITH_OPENSSL
	    "       ssh-keygen -i [-f input_keyfile] [-m key_format]\n"
	    "       ssh-keygen -e [-f input_keyfile] [-m key_format]\n"
#جے_انت
	    "       ssh-keygen -y [-f input_keyfile]\n"
	    "       ssh-keygen -c [-a rounds] [-C comment] [-f keyfile] [-P passphrase]\n"
	    "       ssh-keygen -l [-v] [-E fingerprint_hash] [-f input_keyfile]\n"
	    "       ssh-keygen -B [-f input_keyfile]\n");
#جے_تعریف_شدہ ENABLE_PKCS11
	fprintf(stderr,
	    "       ssh-keygen -D pkcs11\n");
#جے_انت
	fprintf(stderr,
	    "       ssh-keygen -F hostname [-lv] [-f known_hosts_file]\n"
	    "       ssh-keygen -H [-f known_hosts_file]\n"
	    "       ssh-keygen -K [-a rounds] [-w provider]\n"
	    "       ssh-keygen -R hostname [-f known_hosts_file]\n"
	    "       ssh-keygen -r hostname [-g] [-f input_keyfile]\n"
#جے_تعریف_شدہ WITH_OPENSSL
	    "       ssh-keygen -M generate [-O option] output_file\n"
	    "       ssh-keygen -M screen [-f input_file] [-O option] output_file\n"
#جے_انت
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
صحيح
مکھ(صحيح argc, حرف **argv)
{
	حرف comment[کلید_COMMENT_MAX], *passphrase = عدم;
	حرف *rr_hostname = عدم, *ep, *fp, *ra;
	بنية sshkey *خاص = عدم, *عام = عدم;
	بنية passwd *pw;
	صحيح ret = 0, r, opt, type;
	صحيح change_passphrase = 0, change_comment = 0, show_cert = 0;
	صحيح لبھو_host = 0, delete_host = 0, hash_hosts = 0;
	صحيح gen_all_hostkeys = 0, gen_krl = 0, update_krl = 0, check_krl = 0;
	صحيح prefer_agent = 0, convert_منزل = 0, convert_from = 0;
	صحيح print_عوامی = 0, print_generic = 0, cert_serial_autoinc = 0;
	صحيح do_gen_candidates = 0, do_screen_candidates = 0, download_sk = 0;
	بنانشانی لما لما cert_serial = 0;
	حرف *پچھان_تت_comment = عدم, *ca_کلید_رستہ = عدم, **opts = عدم;
	حرف *sk_application = عدم, *sk_device = عدم, *sk_user = عدم;
	حرف *sk_attestation_رستہ = عدم;
	بنية sshbuf *challenge = عدم, *attest = عدم;
	ناپ_t i, nopts = 0;
	uint32_t بٹ = 0;
	uint8_t sk_flags = SSH_SK_USER_PRESENCE_REQD;
	ثابت حرف *errstr, *p;
	صحيح log_level = SYSLOG_LEVEL_INFO;
	حرف *sign_op = عدم;

	خارجي صحيح optind;
	خارجي حرف *optarg;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	__progname = ssh_get_progname(argv[0]);

	بیج_rng();

	log_init(argv[0], SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_USER, 1);

	msetlocale();

	/* we need this for the home * directory.  */
	pw = getpwuid(getuid());
	إذا (!pw)
		fatal("No user exists for uid %lu", (u_long)getuid());
	pw = pwcopy(pw);
	إذا (gethostname(hostname, حجم(hostname)) == -1)
		fatal("gethostname: %s", strerror(errno));

	sk_provider = getenv("SSH_SK_PROVIDER");

	/* Remaining characters: dGjJSTWx */
	طالما ((opt = getopt(argc, argv, "ABHKLQUXceghiklopquvy"
	    "C:D:E:F:I:M:N:O:P:R:V:Y:Z:"
	    "a:b:f:g:m:n:r:s:t:w:z:")) != -1) {
		بدل (opt) {
		حالة 'A':
			gen_all_hostkeys = 1;
			اكسر;
		حالة 'b':
			بٹ = (uint32_t)strtonum(optarg, 1, UINT32_MAX,
			    &errstr);
			إذا (errstr)
				fatal("Bits has bad value %s (%s)",
					optarg, errstr);
			اكسر;
		حالة 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			إذا (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			اكسر;
		حالة 'F':
			لبھو_host = 1;
			rr_hostname = optarg;
			اكسر;
		حالة 'H':
			hash_hosts = 1;
			اكسر;
		حالة 'I':
			cert_کلید_id = optarg;
			اكسر;
		حالة 'R':
			delete_host = 1;
			rr_hostname = optarg;
			اكسر;
		حالة 'L':
			show_cert = 1;
			اكسر;
		حالة 'l':
			print_fingerprint = 1;
			اكسر;
		حالة 'B':
			print_bubblebabble = 1;
			اكسر;
		حالة 'm':
			إذا (strcasecmp(optarg, "RFC4716") == 0 ||
			    strcasecmp(optarg, "ssh2") == 0) {
				convert_format = FMT_RFC4716;
				اكسر;
			}
			إذا (strcasecmp(optarg, "PKCS8") == 0) {
				convert_format = FMT_PKCS8;
				نجی_کلید_format = SSHKEY_نجی_PKCS8;
				اكسر;
			}
			إذا (strcasecmp(optarg, "PEM") == 0) {
				convert_format = FMT_PEM;
				نجی_کلید_format = SSHKEY_نجی_PEM;
				اكسر;
			}
			إذا (strcasecmp(optarg, "hexdump") == 0) {
				convert_format = FMT_HEXDUMP;
				اكسر;
			}
			fatal("Unsupported conversion format \"%s\"", optarg);
		حالة 'n':
			cert_principals = optarg;
			اكسر;
		حالة 'o':
			/* no-op; new format is already the default */
			اكسر;
		حالة 'p':
			change_passphrase = 1;
			اكسر;
		حالة 'c':
			change_comment = 1;
			اكسر;
		حالة 'f':
			إذا (strlcpy(پچھان_تت_file, optarg,
			    حجم(پچھان_تت_file)) >= حجم(پچھان_تت_file))
				fatal("Identity filename too long");
			have_پچھان_تت = 1;
			اكسر;
		حالة 'g':
			print_generic = 1;
			اكسر;
		حالة 'K':
			download_sk = 1;
			اكسر;
		حالة 'P':
			پچھان_تت_passphrase = optarg;
			اكسر;
		حالة 'N':
			پچھان_تت_new_passphrase = optarg;
			اكسر;
		حالة 'Q':
			check_krl = 1;
			اكسر;
		حالة 'O':
			opts = xrecallocarray(opts, nopts, nopts + 1,
			    حجم(*opts));
			opts[nopts++] = xstrdup(optarg);
			اكسر;
		حالة 'Z':
			openssh_format_cipher = optarg;
			إذا (cipher_by_name(openssh_format_cipher) == عدم)
				fatal("Invalid OpenSSH-format cipher '%s'",
				    openssh_format_cipher);
			اكسر;
		حالة 'C':
			پچھان_تت_comment = optarg;
			اكسر;
		حالة 'q':
			quiet = 1;
			اكسر;
		حالة 'e':
			/* export key */
			convert_منزل = 1;
			اكسر;
		حالة 'h':
			cert_کلید_type = SSH2_CERT_TYPE_HOST;
			certflags_flags = 0;
			اكسر;
		حالة 'k':
			gen_krl = 1;
			اكسر;
		حالة 'i':
		حالة 'X':
			/* import key */
			convert_from = 1;
			اكسر;
		حالة 'y':
			print_عوامی = 1;
			اكسر;
		حالة 's':
			ca_کلید_رستہ = optarg;
			اكسر;
		حالة 't':
			کلید_type_name = optarg;
			اكسر;
		حالة 'D':
			pkcs11provider = optarg;
			اكسر;
		حالة 'U':
			prefer_agent = 1;
			اكسر;
		حالة 'u':
			update_krl = 1;
			اكسر;
		حالة 'v':
			إذا (log_level == SYSLOG_LEVEL_INFO)
				log_level = SYSLOG_LEVEL_DEBUG1;
			وإلا {
				إذا (log_level >= SYSLOG_LEVEL_DEBUG1 &&
				    log_level < SYSLOG_LEVEL_DEBUG3)
					log_level++;
			}
			اكسر;
		حالة 'r':
			rr_hostname = optarg;
			اكسر;
		حالة 'a':
			گیڑ = (صحيح)strtonum(optarg, 1, ودھ_توں_ودھ_عدد, &errstr);
			إذا (errstr)
				fatal("Invalid number: %s (%s)",
					optarg, errstr);
			اكسر;
		حالة 'V':
			parse_cert_times(optarg);
			اكسر;
		حالة 'Y':
			sign_op = optarg;
			اكسر;
		حالة 'w':
			sk_provider = optarg;
			اكسر;
		حالة 'z':
			errno = 0;
			إذا (*optarg == '+') {
				cert_serial_autoinc = 1;
				optarg++;
			}
			cert_serial = strtoull(optarg, &ep, 10);
			إذا (*optarg < '0' || *optarg > '9' || *ep != '\0' ||
			    (errno == ERANGE && cert_serial == ULLONG_MAX))
				fatal("Invalid serial number \"%s\"", optarg);
			اكسر;
		حالة 'M':
			إذا (strcmp(optarg, "generate") == 0)
				do_gen_candidates = 1;
			وإلا إذا (strcmp(optarg, "screen") == 0)
				do_screen_candidates = 1;
			وإلا
				fatal("Unsupported moduli option %s", optarg);
			اكسر;
		افتراضي:
			usage();
		}
	}

#جے_تعریف_شدہ ENABLE_SK_اندرونی
	إذا (sk_provider == عدم)
		sk_provider = "internal";
#جے_انت

	/* reinit */
	log_init(argv[0], log_level, SYSLOG_FACILITY_USER, 1);

	argv += optind;
	argc -= optind;

	إذا (sign_op != عدم) {
		إذا (strprefix(sign_op, "find-principals", 0) != عدم) {
			إذا (ca_کلید_رستہ == عدم) {
				error("Too few arguments for find-principals:"
				    "missing signature file");
				باہر_نکلو(1);
			}
			إذا (!have_پچھان_تت) {
				error("Too few arguments for find-principals:"
				    "missing allowed keys file");
				باہر_نکلو(1);
			}
			ret = sig_لبھو_principals(ca_کلید_رستہ, پچھان_تت_file,
			    opts, nopts);
			اذهب پورا;
		} وإلا إذا (strprefix(sign_op, "match-principals", 0) != عدم) {
			إذا (!have_پچھان_تت) {
				error("Too few arguments for match-principals:"
				    "missing allowed keys file");
				باہر_نکلو(1);
			}
			إذا (cert_کلید_id == عدم) {
				error("Too few arguments for match-principals: "
				    "missing principal ID");
				باہر_نکلو(1);
			}
			ret = sig_میل_principals(پچھان_تت_file, cert_کلید_id,
			    opts, nopts);
			اذهب پورا;
		} وإلا إذا (strprefix(sign_op, "sign", 0) != عدم) {
			/* NB. cert_principals is actually namespace, via -n */
			إذا (cert_principals == عدم ||
			    *cert_principals == '\0') {
				error("Too few arguments for sign: "
				    "missing namespace");
				باہر_نکلو(1);
			}
			إذا (!have_پچھان_تت) {
				error("Too few arguments for sign: "
				    "missing key");
				باہر_نکلو(1);
			}
			ret = sig_sign(پچھان_تت_file, cert_principals,
			    prefer_agent, argc, argv, opts, nopts);
			اذهب پورا;
		} وإلا إذا (strprefix(sign_op, "check-novalidate", 0) != عدم) {
			/* NB. cert_principals is actually namespace, via -n */
			إذا (cert_principals == عدم ||
			    *cert_principals == '\0') {
				error("Too few arguments for check-novalidate: "
				    "missing namespace");
				باہر_نکلو(1);
			}
			إذا (ca_کلید_رستہ == عدم) {
				error("Too few arguments for check-novalidate: "
				    "missing signature file");
				باہر_نکلو(1);
			}
			ret = sig_verify(ca_کلید_رستہ, cert_principals,
			    عدم, عدم, عدم, opts, nopts);
			اذهب پورا;
		} وإلا إذا (strprefix(sign_op, "verify", 0) != عدم) {
			/* NB. cert_principals is actually namespace, via -n */
			إذا (cert_principals == عدم ||
			    *cert_principals == '\0') {
				error("Too few arguments for verify: "
				    "missing namespace");
				باہر_نکلو(1);
			}
			إذا (ca_کلید_رستہ == عدم) {
				error("Too few arguments for verify: "
				    "missing signature file");
				باہر_نکلو(1);
			}
			إذا (!have_پچھان_تت) {
				error("Too few arguments for sign: "
				    "missing allowed keys file");
				باہر_نکلو(1);
			}
			إذا (cert_کلید_id == عدم) {
				error("Too few arguments for verify: "
				    "missing principal identity");
				باہر_نکلو(1);
			}
			ret = sig_verify(ca_کلید_رستہ, cert_principals,
			    cert_کلید_id, پچھان_تت_file, rr_hostname,
			    opts, nopts);
			اذهب پورا;
		}
		error("Unsupported operation for -Y: \"%s\"", sign_op);
		usage();
		/* NOTREACHED */
	}

	إذا (ca_کلید_رستہ != عدم) {
		إذا (argc < 1 && !gen_krl) {
			error("Too few arguments.");
			usage();
		}
	} وإلا إذا (argc > 0 && !gen_krl && !check_krl &&
	    !do_gen_candidates && !do_screen_candidates) {
		error("Too many arguments.");
		usage();
	}
	إذا (change_passphrase && change_comment) {
		error("Can only have one of -p and -c.");
		usage();
	}
	إذا (print_fingerprint && (delete_host || hash_hosts)) {
		error("Cannot use -l with -H or -R.");
		usage();
	}
	إذا (gen_krl) {
		do_gen_krl(pw, update_krl, ca_کلید_رستہ,
		    cert_serial, پچھان_تت_comment, argc, argv);
		اذهب پورا;
	}
	إذا (check_krl) {
		do_check_krl(pw, print_fingerprint, argc, argv);
		اذهب پورا;
	}
	إذا (ca_کلید_رستہ != عدم) {
		إذا (cert_کلید_id == عدم)
			fatal("Must specify key id (-I) when certifying");
		إذا (cert_principals == عدم) {
			/*
			 * Ideally this would be a fatal(), but we need to
			 * be able to generate such certificates for testing
			 * even though they will be rejected.
			 */
			error("Warning: certificate will contain no "
			    "principals (-n)");
		}
		لكل (i = 0; i < nopts; i++)
			جوڑو_cert_option(opts[i]);
		do_ca_sign(pw, ca_کلید_رستہ, prefer_agent,
		    cert_serial, cert_serial_autoinc, argc, argv);
		اذهب پورا;
	}
	إذا (show_cert)
		do_show_cert(pw);
	إذا (delete_host || hash_hosts || لبھو_host) {
		do_معلوم_hosts(pw, rr_hostname, لبھو_host,
		    delete_host, hash_hosts);
	}
	إذا (pkcs11provider != عدم)
		do_download(pw);
	إذا (download_sk) {
		لكل (i = 0; i < nopts; i++) {
			إذا ((p = strprefix(opts[i], "device=", 1)) != عدم) {
				sk_device = xstrdup(p);
			} وإلا {
				fatal("Option \"%s\" is unsupported for "
				    "FIDO authenticator download", opts[i]);
			}
		}
		ret = do_download_sk(sk_provider, sk_device);
		اذهب پورا;
	}
	إذا (print_fingerprint || print_bubblebabble)
		do_fingerprint(pw);
	إذا (change_passphrase)
		do_change_passphrase(pw, opts, nopts);
	إذا (change_comment)
		do_change_comment(pw, پچھان_تت_comment);
#جے_تعریف_شدہ WITH_OPENSSL
	إذا (convert_منزل) {
		do_convert_منزل(pw);
		اذهب پورا;
	}
	إذا (convert_from) {
		do_convert_from(pw);
		اذهب پورا;
	}
#وإلا /* WITH_OPENSSL */
	إذا (convert_منزل || convert_from)
		fatal("key conversion disabled at compile time");
#جے_انت /* WITH_OPENSSL */
	إذا (print_عوامی)
		do_print_عوامی(pw);
	إذا (rr_hostname != عدم) {
		بنانشانی صحيح n = 0;

		إذا (have_پچھان_تت) {
			n = do_print_resource_ریکارڈ(pw, پچھان_تت_file,
			    rr_hostname, print_generic, opts, nopts);
			إذا (n == 0)
				fatal("%s: %s", پچھان_تت_file, strerror(errno));
			باہر_نکلو(0);
		} وإلا {

			n += do_print_resource_ریکارڈ(pw,
			    رستہ_HOST_RSA_کلید_FILE, rr_hostname,
			    print_generic, opts, nopts);
			n += do_print_resource_ریکارڈ(pw,
			    رستہ_HOST_ECDSA_کلید_FILE, rr_hostname,
			    print_generic, opts, nopts);
			n += do_print_resource_ریکارڈ(pw,
			    رستہ_HOST_ED25519_کلید_FILE, rr_hostname,
			    print_generic, opts, nopts);
			إذا (n == 0)
				fatal("no keys found.");
			باہر_نکلو(0);
		}
	}

	إذا (do_gen_candidates || do_screen_candidates) {
		إذا (argc <= 0)
			fatal("No output file specified");
		وإلا إذا (argc > 1)
			fatal("Too many output files specified");
	}
	إذا (do_gen_candidates) {
		do_moduli_gen(argv[0], opts, nopts);
		اذهب پورا;
	}
	إذا (do_screen_candidates) {
		do_moduli_screen(argv[0], opts, nopts);
		اذهب پورا;
	}

	إذا (gen_all_hostkeys) {
		do_gen_all_hostkeys(pw);
		اذهب پورا;
	}

	إذا (کلید_type_name == عدم)
		کلید_type_name = DEFAULT_کلید_TYPE_NAME;

	type = sshkey_type_from_shortname(کلید_type_name);
	type_بٹ_valid(type, کلید_type_name, &بٹ);

	إذا (!quiet)
		لکھو("Generating public/private %s key pair.\n",
		    کلید_type_name);
	بدل (type) {
	حالة کلید_ECDSA_SK:
	حالة کلید_ED25519_SK:
		لكل (i = 0; i < nopts; i++) {
			إذا (strcasecmp(opts[i], "no-touch-required") == 0) {
				sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
			} وإلا إذا (strcasecmp(opts[i], "verify-required") == 0) {
				sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
			} وإلا إذا (strcasecmp(opts[i], "resident") == 0) {
				sk_flags |= SSH_SK_RESIDENT_کلید;
			} وإلا إذا ((p = strprefix(opts[i], "device=", 1))
			    != عدم ) {
				sk_device = xstrdup(p);
			} وإلا إذا ((p = strprefix(opts[i], "user=", 1))
			    != عدم) {
				sk_user = xstrdup(p);
			} وإلا إذا ((p = strprefix(opts[i], "challenge=", 1))
			    != عدم) {
				إذا ((r = sshbuf_لدو_file(p,
				    &challenge)) != 0) {
					fatal_r(r, "Unable to load FIDO "
					    "enrollment challenge \"%s\"", p);
				}
			} وإلا إذا (strncasecmp(opts[i],
			    "write-attestation=", 18) == 0) {
				sk_attestation_رستہ = opts[i] + 18;
			} وإلا إذا (strncasecmp(opts[i],
			    "application=", 12) == 0) {
				sk_application = xstrdup(opts[i] + 12);
				إذا (لڑی_مقابلہ(sk_application, "ssh:", 4) != 0) {
					fatal("FIDO application string must "
					    "begin with \"ssh:\"");
				}
			} وإلا {
				fatal("Option \"%s\" is unsupported for "
				    "FIDO authenticator enrollment", opts[i]);
			}
		}
		إذا ((attest = sshbuf_new()) == عدم)
			fatal("sshbuf_new failed");
		r = 0;
		لكل (i = 0 ;;) {
			إذا (!quiet) {
				لکھو("You may need to touch your "
				    "authenticator%s to authorize key "
				    "generation.\n",
				    r == 0 ? "" : " again");
			}
			fflush(stdout);
			r = sshsk_enroll(type, sk_provider, sk_device,
			    sk_application == عدم ? "ssh:" : sk_application,
			    sk_user, sk_flags, passphrase, challenge,
			    &خاص, attest);
			إذا (r == 0)
				اكسر;
			إذا (r == SSH_ERR_کلید_BAD_PERMISSIONS &&
			    (sk_flags & SSH_SK_RESIDENT_کلید) != 0 &&
			    (sk_flags & SSH_SK_FORCE_OPERATION) == 0 &&
			    confirm_sk_overwrite(sk_application, sk_user)) {
				sk_flags |= SSH_SK_FORCE_OPERATION;
				استمر;
			}
			إذا (r != SSH_ERR_کلید_WRONG_PASSPHRASE)
				fatal_r(r, "Key enrollment failed");
			وإلا إذا (passphrase != عدم) {
				error("PIN incorrect");
				freezero(passphrase, لڑی_لمبائی(passphrase));
				passphrase = عدم;
			}
			إذا (++i >= 3)
				fatal("Too many incorrect PINs");
			passphrase = read_passphrase("Enter PIN for "
			    "authenticator: ", RP_ALLOW_STDIN);
		}
		إذا (passphrase != عدم) {
			freezero(passphrase, لڑی_لمبائی(passphrase));
			passphrase = عدم;
		}
		اكسر;
	افتراضي:
		إذا ((r = sshkey_generate(type, بٹ, &خاص)) != 0)
			fatal("sshkey_generate failed");
		اكسر;
	}
	إذا ((r = sshkey_from_نجی(خاص, &عام)) != 0)
		fatal_r(r, "sshkey_from_private");

	إذا (!have_پچھان_تت)
		ask_filename(pw, "Enter file in which to save the key");

	/* Create ~/.ssh directory if it doesn't already exist. */
	hostfile_create_user_ssh_dir(پچھان_تت_file, !quiet);

	/* If the file already exists, ask the user to confirm. */
	إذا (!confirm_overwrite(پچھان_تت_file))
		باہر_نکلو(1);

	/* Determine the passphrase for the private key */
	passphrase = نجی_کلید_passphrase(پچھان_تت_file);
	إذا (پچھان_تت_comment) {
		strlcpy(comment, پچھان_تت_comment, حجم(comment));
	} وإلا {
		/* Create default comment field for the passphrase. */
		snprintf(comment, حجم comment, "%s@%s", pw->pw_name, hostname);
	}



	/* Save the key with the given passphrase and comment. */
	إذا ((r = sshkey_save_نجی(خاص, پچھان_تت_file, passphrase,
	    comment, نجی_کلید_format, openssh_format_cipher, گیڑ)) != 0) {
		error_r(r, "Saving key \"%s\" failed", پچھان_تت_file);
		freezero(passphrase, لڑی_لمبائی(passphrase));
		باہر_نکلو(1);
	}
	freezero(passphrase, لڑی_لمبائی(passphrase));
	sshkey_free(خاص);

	إذا (!quiet) {
		لکھو("Your identification has been saved in %s\n",
		    پچھان_تت_file);
	}

	strlcat(پچھان_تت_file, ".pub", حجم(پچھان_تت_file));
	إذا ((r = sshkey_save_عوامی(عام, پچھان_تت_file, comment)) != 0)
		fatal_r(r, "Unable to save public key to %s", پچھان_تت_file);

	إذا (!quiet) {
		fp = sshkey_fingerprint(عام, fingerprint_hash,
		    SSH_FP_DEFAULT);
		ra = sshkey_fingerprint(عام, fingerprint_hash,
		    SSH_FP_RANDOMART);
		إذا (fp == عدم || ra == عدم)
			fatal("sshkey_fingerprint failed");
		لکھو("Your public key has been saved in %s\n",
		    پچھان_تت_file);
		لکھو("The key fingerprint is:\n");
		لکھو("%s %s\n", fp, comment);
		لکھو("The key's randomart image is:\n");
		لکھو("%s\n", ra);
		حرر(ra);
		حرر(fp);
	}

	إذا (sk_attestation_رستہ != عدم)
		save_attestation(attest, sk_attestation_رستہ);

 پورا:
	sshbuf_free(attest);
	sshkey_free(عام);
	pwfree(pw);
	باہر_نکلو(ret);
}
