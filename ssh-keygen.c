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

#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
#ضمن "openbsd-compat/openssl-compat.h"
#ضمن <openssl/bn.h>
#ضمن <openssl/evp.h>
#ضمن <openssl/pem.h>
#جيڪڏهن_پورو

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

#جيڪڏهن_وصف_ٿيل ENABLE_PKCS11
#ضمن "ssh-pkcs11.h"
#جيڪڏهن_پورو

#وصف_ڪريو DEFAULT_ڪنجي_TYPE_NAME "ed25519"

/*
 * Default number of bits in the RSA and ECDSA keys.  These value can be
 * overridden on the command line.
 *
 * These values provide security equivalent to at least 128 bits of security
 * according to NIST Special Publication 800-57: Recommendation for Key
 * Management Part 1 rev 4 section 5.6.1.
 */
#وصف_ڪريو DEFAULT_بٽ		3072
#وصف_ڪريو DEFAULT_بٽ_ECDSA	256

#وصف_ڪريو ڪنجي_COMMENT_MAX		(NI_MAXHOST + 1024)

ساكن صحيح quiet = 0;

/* Flag indicating that we just want to see the key fingerprint */
ساكن صحيح print_fingerprint = 0;
ساكن صحيح print_bubblebabble = 0;

/* Hash algorithm to use for fingerprints. */
ساكن صحيح fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* The identity file name, given on the command line or entered by the user. */
ساكن حرف سڃاڻپ_عنصر_file[PATH_MAX];
ساكن صحيح have_سڃاڻپ_عنصر = 0;

/* This is set to the passphrase if given on the command line. */
ساكن حرف *سڃاڻپ_عنصر_passphrase = عدم;

/* This is set to the new passphrase if given on the command line. */
ساكن حرف *سڃاڻپ_عنصر_new_passphrase = عدم;

/* Key type when certifying */
ساكن u_int cert_ڪنجي_type = SSH2_CERT_TYPE_USER;

/* "key ID" of signed key */
ساكن حرف *cert_ڪنجي_id = عدم;

/* Comma-separated list of principal names for certifying keys */
ساكن حرف *cert_principals = عدم;

/* Validity period for certificates */
ساكن uint64_t cert_valid_from = 0;
ساكن uint64_t cert_valid_منزل = ~0ULL;

/* Certificate options */
#وصف_ڪريو CERTOPT_X_FWD				(1)
#وصف_ڪريو CERTOPT_AGENT_FWD			(1<<1)
#وصف_ڪريو CERTOPT_پورٽ_FWD			(1<<2)
#وصف_ڪريو CERTOPT_PTY				(1<<3)
#وصف_ڪريو CERTOPT_USER_RC				(1<<4)
#وصف_ڪريو CERTOPT_NO_REQUIRE_USER_PRESENCE	(1<<5)
#وصف_ڪريو CERTOPT_REQUIRE_VERIFY			(1<<6)
#وصف_ڪريو CERTOPT_DEFAULT	(CERTOPT_X_FWD|CERTOPT_AGENT_FWD| \
			 CERTOPT_پورٽ_FWD|CERTOPT_PTY|CERTOPT_USER_RC)
ساكن uint32_t certflags_flags = CERTOPT_DEFAULT;
ساكن حرف *certflags_command = عدم;
ساكن حرف *certflags_src_addr = عدم;

/* Arbitrary extensions specified by user */
بنية cert_ext {
	حرف *ڪنجي;
	حرف *val;
	صحيح crit;
};
ساكن بنية cert_ext *cert_ext;
ساكن سائيز_t ncert_ext;

/* Conversion to/from various formats */
تعداد {
	FMT_RFC4716,
	FMT_PKCS8,
	FMT_PEM,
	FMT_HEXDUMP
} convert_format = FMT_RFC4716;

ساكن حرف *ڪنجي_type_name = عدم;

/* Load key from this PKCS#11 provider */
ساكن حرف *pkcs11provider = عدم;

/* FIDO/U2F provider to use */
ساكن حرف *sk_provider = عدم;

/* Format for writing private keys */
ساكن صحيح ذاتي_ڪنجي_format = SSHKEY_ذاتي_OPENSSH;

/* Cipher for new-format private keys */
ساكن حرف *openssh_format_cipher = عدم;

/* Number of KDF rounds to derive new format keys. */
ساكن صحيح ڦيرا = 0;

/* argv0 */
خارجي حرف *__progname;

ساكن حرف hostname[NI_MAXHOST];

#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
/* moduli.c */
صحيح gen_candidates(FILE *, uint32_t, BIGNUM *);
صحيح مفرد_test(FILE *, FILE *, uint32_t, uint32_t, حرف *, بنانشان ڊگهو,
    بنانشان ڊگهو);
#جيڪڏهن_پورو

ساكن فراغ
type_بٽ_valid(صحيح type, ثابت حرف *name, uint32_t *bitsp)
{
	إذا (type == ڪنجي_UNSPEC)
		fatal("unknown key type %s", ڪنجي_type_name);
	إذا (*bitsp == 0) {
#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
		صحيح nid;

		بدل(type) {
		حالة ڪنجي_ECDSA:
			إذا (name != عدم &&
			    (nid = sshkey_ecdsa_nid_from_name(name)) > 0)
				*bitsp = sshkey_وڪر_nid_منزل_بٽ(nid);
			إذا (*bitsp == 0)
				*bitsp = DEFAULT_بٽ_ECDSA;
			اكسر;
		حالة ڪنجي_RSA:
			*bitsp = DEFAULT_بٽ;
			اكسر;
		}
#جيڪڏهن_پورو
	}
#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
	بدل (type) {
	حالة ڪنجي_RSA:
		إذا (*bitsp < SSH_RSA_MINIMUM_MODULUS_سائيز)
			fatal("Invalid RSA key length: minimum is %d bits",
			    SSH_RSA_MINIMUM_MODULUS_سائيز);
		وإلا إذا (*bitsp > OPENSSL_RSA_MAX_MODULUS_بٽ)
			fatal("Invalid RSA key length: maximum is %d bits",
			    OPENSSL_RSA_MAX_MODULUS_بٽ);
		اكسر;
	حالة ڪنجي_ECDSA:
		إذا (sshkey_ecdsa_بٽ_منزل_nid(*bitsp) == -1)
			fatal("Invalid ECDSA key length: valid lengths are "
			    "256, 384 or 521 bits");
	}
#جيڪڏهن_پورو
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
	لکو("%s already exists.\n", filename);
	لکو("Overwrite (y/n)? ");
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

	إذا (ڪنجي_type_name == عدم)
		name = رستو_SSH_CLIENT_ID_ED25519;
	وإلا {
		بدل (sshkey_type_from_shortname(ڪنجي_type_name)) {
		حالة ڪنجي_ECDSA_CERT:
		حالة ڪنجي_ECDSA:
			name = رستو_SSH_CLIENT_ID_ECDSA;
			اكسر;
		حالة ڪنجي_ECDSA_SK_CERT:
		حالة ڪنجي_ECDSA_SK:
			name = رستو_SSH_CLIENT_ID_ECDSA_SK;
			اكسر;
		حالة ڪنجي_RSA_CERT:
		حالة ڪنجي_RSA:
			name = رستو_SSH_CLIENT_ID_RSA;
			اكسر;
		حالة ڪنجي_ED25519:
		حالة ڪنجي_ED25519_CERT:
			name = رستو_SSH_CLIENT_ID_ED25519;
			اكسر;
		حالة ڪنجي_ED25519_SK:
		حالة ڪنجي_ED25519_SK_CERT:
			name = رستو_SSH_CLIENT_ID_ED25519_SK;
			اكسر;
		حالة ڪنجي_MLDSA44_ED25519:
		حالة ڪنجي_MLDSA44_ED25519_CERT:
			name = رستو_SSH_CLIENT_ID_MLDSA44_ED25519;
			اكسر;
		افتراضي:
			fatal("bad key type");
		}
	}
	snprintf(سڃاڻپ_عنصر_file, حجم(سڃاڻپ_عنصر_file),
	    "%s/%s", pw->pw_dir, name);
	لکو("%s (%s): ", prompt, سڃاڻپ_عنصر_file);
	fflush(stdout);
	إذا (fgets(buf, حجم(buf), stdin) == عدم)
		ٻاهر_نڪرو(1);
	buf[strcspn(buf, "\n")] = '\0';
	إذا (strcmp(buf, "") != 0)
		strlcpy(سڃاڻپ_عنصر_file, buf, حجم(سڃاڻپ_عنصر_file));
	have_سڃاڻپ_عنصر = 1;
}

ساكن بنية sshkey *
ڀريو_سڃاڻپ_عنصر(ثابت حرف *filename, حرف **commentp)
{
	حرف *prompt, *pass;
	بنية sshkey *prv;
	صحيح r;

	إذا (commentp != عدم)
		*commentp = عدم;
	إذا ((r = sshkey_ڀريو_ذاتي(filename, "", &prv, commentp)) == 0)
		أرجع prv;
	إذا (r != SSH_ERR_ڪنجي_WRONG_PASSPHRASE)
		fatal_r(r, "Load key \"%s\"", filename);
	إذا (سڃاڻپ_عنصر_passphrase)
		pass = xstrdup(سڃاڻپ_عنصر_passphrase);
	وإلا {
		xasprintf(&prompt, "Enter passphrase for \"%s\": ", filename);
		pass = read_passphrase(prompt, RP_ALLOW_STDIN);
		حرر(prompt);
	}
	r = sshkey_ڀريو_ذاتي(filename, pass, &prv, commentp);
	freezero(pass, لڙي_ڊيگهه(pass));
	إذا (r != 0)
		fatal_r(r, "Load key \"%s\"", filename);
	أرجع prv;
}

#وصف_ڪريو SSH_COM_عوامي_BEGIN		"---- BEGIN SSH2 PUBLIC KEY ----"
#وصف_ڪريو SSH_COM_عوامي_پڇاڙي		"---- END SSH2 PUBLIC KEY ----"
#وصف_ڪريو SSH_COM_ذاتي_BEGIN		"---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----"
#وصف_ڪريو	SSH_COM_ذاتي_ڪنجي_MAGIC	0x3f6ff9eb

#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
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
	    sshkey_سائيز(k), sshkey_type(k),
	    pw->pw_name, hostname);

	sshkey_free(k);
	sshbuf_free(b);

	fprintf(stdout, "%s\n", SSH_COM_عوامي_BEGIN);
	fprintf(stdout, "Comment: \"%s\"\n%s", comment, b64);
	fprintf(stdout, "%s\n", SSH_COM_عوامي_پڇاڙي);
	حرر(b64);
}

ساكن فراغ
do_convert_منزل_pkcs8(بنية sshkey *k)
{
	بدل (sshkey_type_plain(k->type)) {
	حالة ڪنجي_RSA:
		إذا (!PEM_write_RSA_PUBKEY(stdout,
		    EVP_PKEY_get0_RSA(k->pkey)))
			fatal("PEM_write_RSA_PUBKEY failed");
		اكسر;
	حالة ڪنجي_ECDSA:
		إذا (!PEM_write_EC_PUBKEY(stdout,
		    EVP_PKEY_get0_EC_ڪنجي(k->pkey)))
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
	حالة ڪنجي_RSA:
		إذا (!PEM_write_RSAPublic_ڪنجي(stdout,
		    EVP_PKEY_get0_RSA(k->pkey)))
			fatal("PEM_write_RSAPublicKey failed");
		اكسر;
	حالة ڪنجي_ECDSA:
		إذا (!PEM_write_EC_PUBKEY(stdout,
		    EVP_PKEY_get0_EC_ڪنجي(k->pkey)))
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
	لکو("Public %s key:\n", sshkey_type(k));
	sshbuf_dump(b, stdout);
	sshbuf_reset(b);
	إذا ((r = sshkey_ذاتي_serialize(k, b)) != 0) {
		debug_fr(r, "serialise private");
		اذهب ٻاهريون;
	}
	لکو("\nPrivate %s key:\n", sshkey_type(k));
	sshbuf_dump(b, stdout);
 ٻاهريون:
	sshbuf_free(b);
}

ساكن فراغ
do_convert_منزل(بنية passwd *pw)
{
	بنية sshkey *k = عدم;
	بنية stat st;
	صحيح r;

	إذا (!have_سڃاڻپ_عنصر)
		ask_filename(pw, "Enter file in which the key is");
	إذا (stat(سڃاڻپ_عنصر_file, &st) == -1)
		fatal("%s: %s: %s", __progname, سڃاڻپ_عنصر_file, strerror(errno));

	/* If we're trying to hexdump, then prefer the private key */
	إذا (convert_format == FMT_HEXDUMP) {
		إذا ((r = sshkey_ڀريو_ذاتي(سڃاڻپ_عنصر_file,
		    عدم, &k, عدم)) != 0 &&
		    r == SSH_ERR_ڪنجي_WRONG_PASSPHRASE)
			k = ڀريو_سڃاڻپ_عنصر(سڃاڻپ_عنصر_file, عدم);
	}
	إذا (k == عدم && (r = sshkey_ڀريو_عوامي(سڃاڻپ_عنصر_file, &k, عدم)) != 0)
		k = ڀريو_سڃاڻپ_عنصر(سڃاڻپ_عنصر_file, عدم);

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
بفر_get_bignum_بٽ(بنية sshbuf *b, BIGNUM *قدر)
{
	u_int بائيٽون, bignum_بٽ;
	صحيح r;

	إذا ((r = sshbuf_get_u32(b, &bignum_بٽ)) != 0)
		fatal_fr(r, "parse");
	بائيٽون = (bignum_بٽ + 7) / 8;
	إذا (sshbuf_len(b) < بائيٽون)
		fatal_f("input buffer too small: need %d have %zu",
		    بائيٽون, sshbuf_len(b));
	إذا (BN_bin2bn(sshbuf_ptr(b), بائيٽون, قدر) == عدم)
		fatal_f("BN_bin2bn failed");
	إذا ((r = sshbuf_consume(b, بائيٽون)) != 0)
		fatal_fr(r, "consume");
}

ساكن بنية sshkey *
do_convert_ذاتي_ssh2(بنية sshbuf *b)
{
	بنية sshkey *ڪنجي = عدم;
	حرف *type, *cipher;
	ثابت حرف *alg = عدم;
	u_char e1, e2, e3, *sig = عدم, معلومات[] = "abcde12345";
	صحيح r, rlen, ktype;
	u_int magic, i1, i2, i3, i4;
	سائيز_t slen;
	u_long e;
	BIGNUM *rsa_n = عدم, *rsa_e = عدم, *rsa_d = عدم;
	BIGNUM *rsa_p = عدم, *rsa_q = عدم, *rsa_iqmp = عدم;
	BIGNUM *rsa_dmp1 = عدم, *rsa_dmq1 = عدم;
	RSA *rsa = عدم;

	إذا ((r = sshbuf_get_u32(b, &magic)) != 0)
		fatal_fr(r, "parse magic");

	إذا (magic != SSH_COM_ذاتي_ڪنجي_MAGIC) {
		error("bad magic 0x%x != 0x%x", magic,
		    SSH_COM_ذاتي_ڪنجي_MAGIC);
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

	إذا (لڙي_ڳولا(type, "rsa")) {
		ktype = ڪنجي_RSA;
	} وإلا {
		حرر(type);
		أرجع عدم;
	}
	إذا ((ڪنجي = sshkey_new(ktype)) == عدم)
		fatal("sshkey_new failed");
	حرر(type);

	بدل (ڪنجي->type) {
	حالة ڪنجي_RSA:
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
		إذا (!BN_سيٽ_لفظ(rsa_e, e)) {
			BN_clear_free(rsa_e);
			sshkey_free(ڪنجي);
			أرجع عدم;
		}
		إذا ((rsa_n = BN_new()) == عدم ||
		    (rsa_d = BN_new()) == عدم ||
		    (rsa_p = BN_new()) == عدم ||
		    (rsa_q = BN_new()) == عدم ||
		    (rsa_iqmp = BN_new()) == عدم)
			fatal_f("BN_new");
		بفر_get_bignum_بٽ(b, rsa_d);
		بفر_get_bignum_بٽ(b, rsa_n);
		بفر_get_bignum_بٽ(b, rsa_iqmp);
		بفر_get_bignum_بٽ(b, rsa_q);
		بفر_get_bignum_بٽ(b, rsa_p);
		إذا ((r = ssh_rsa_complete_crt_parameters(rsa_d, rsa_p, rsa_q,
		    rsa_iqmp, &rsa_dmp1, &rsa_dmq1)) != 0)
			fatal_fr(r, "generate RSA CRT parameters");
		EVP_PKEY_free(ڪنجي->pkey);
		إذا ((ڪنجي->pkey = EVP_PKEY_new()) == عدم)
			fatal_f("EVP_PKEY_new failed");
		إذا ((rsa = RSA_new()) == عدم)
			fatal_f("RSA_new failed");
		إذا (!RSA_set0_ڪنجي(rsa, rsa_n, rsa_e, rsa_d))
			fatal_f("RSA_set0_key failed");
		rsa_n = rsa_e = rsa_d = عدم; /* transferred */
		إذا (!RSA_set0_factors(rsa, rsa_p, rsa_q))
			fatal_f("RSA_set0_factors failed");
		rsa_p = rsa_q = عدم; /* transferred */
		إذا (RSA_set0_crt_params(rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp) != 1)
			fatal_f("RSA_set0_crt_params failed");
		rsa_dmp1 = rsa_dmq1 = rsa_iqmp = عدم;
		إذا (EVP_PKEY_set1_RSA(ڪنجي->pkey, rsa) != 1)
			fatal_f("EVP_PKEY_set1_RSA failed");
		RSA_free(rsa);
		alg = "rsa-sha2-256";
		اكسر;
	}
	rlen = sshbuf_len(b);
	إذا (rlen != 0)
		error_f("remaining bytes in key blob %d", rlen);

	/* try the key */
	إذا ((r = sshkey_sign(ڪنجي, &sig, &slen, معلومات, حجم(معلومات),
	    alg, عدم, عدم, 0)) != 0)
		error_fr(r, "signing with converted key failed");
	وإلا إذا ((r = sshkey_verify(ڪنجي, sig, slen, معلومات, حجم(معلومات),
	    alg, 0, عدم)) != 0)
		error_fr(r, "verification with converted key failed");
	إذا (r != 0) {
		sshkey_free(ڪنجي);
		حرر(sig);
		أرجع عدم;
	}
	حرر(sig);
	أرجع ڪنجي;
}

ساكن صحيح
get_سٽ(FILE *fp, حرف *سٽ, سائيز_t len)
{
	صحيح c;
	سائيز_t pos = 0;

	سٽ[0] = '\0';
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
		سٽ[pos++] = c;
		سٽ[pos] = '\0';
	}
	/* We reached EOF */
	أرجع -1;
}

ساكن فراغ
do_convert_from_ssh2(بنية passwd *pw, بنية sshkey **k, صحيح *خاص)
{
	صحيح r, blen, escaped = 0;
	u_int len;
	حرف سٽ[1024];
	بنية sshbuf *buf;
	حرف encoded[8096];
	FILE *fp;

	إذا ((buf = sshbuf_new()) == عدم)
		fatal("sshbuf_new failed");
	إذا ((fp = fopen(سڃاڻپ_عنصر_file, "r")) == عدم)
		fatal("%s: %s: %s", __progname, سڃاڻپ_عنصر_file, strerror(errno));
	encoded[0] = '\0';
	طالما ((blen = get_سٽ(fp, سٽ, حجم(سٽ))) != -1) {
		إذا (blen > 0 && سٽ[blen - 1] == '\\')
			escaped++;
		إذا (لڙي_ڀيٽ(سٽ, "----", 4) == 0 ||
		    لڙي_ڳولا(سٽ, ": ") != عدم) {
			إذا (لڙي_ڳولا(سٽ, SSH_COM_ذاتي_BEGIN) != عدم)
				*خاص = 1;
			إذا (لڙي_ڳولا(سٽ, " END ") != عدم) {
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
		strlcat(encoded, سٽ, حجم(encoded));
	}
	len = لڙي_ڊيگهه(encoded);
	إذا (((len % 4) == 3) &&
	    (encoded[len-1] == '=') &&
	    (encoded[len-2] == '=') &&
	    (encoded[len-3] == '='))
		encoded[len-3] = '\0';
	إذا ((r = sshbuf_b64tod(buf, encoded)) != 0)
		fatal_fr(r, "base64 decode");
	إذا (*خاص) {
		إذا ((*k = do_convert_ذاتي_ssh2(buf)) == عدم)
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

	إذا ((fp = fopen(سڃاڻپ_عنصر_file, "r")) == عدم)
		fatal("%s: %s: %s", __progname, سڃاڻپ_عنصر_file, strerror(errno));
	إذا ((pubkey = PEM_read_PUBKEY(fp, عدم, عدم, عدم)) == عدم) {
		fatal_f("%s is not a recognised public key format",
		    سڃاڻپ_عنصر_file);
	}
	fclose(fp);
	بدل (EVP_PKEY_بنياد_id(pubkey)) {
	حالة EVP_PKEY_RSA:
		إذا ((*k = sshkey_new(ڪنجي_UNSPEC)) == عدم)
			fatal("sshkey_new failed");
		(*k)->type = ڪنجي_RSA;
		(*k)->pkey = pubkey;
		pubkey = عدم;
		اكسر;
	حالة EVP_PKEY_EC:
		إذا ((*k = sshkey_new(ڪنجي_UNSPEC)) == عدم)
			fatal("sshkey_new failed");
		إذا (((*k)->ecdsa_nid = sshkey_ecdsa_fixup_گروهه(pubkey)) == -1)
			fatal("sshkey_ecdsa_fixup_group failed");
		(*k)->type = ڪنجي_ECDSA;
		(*k)->pkey = pubkey;
		pubkey = عدم;
		اكسر;
	افتراضي:
		fatal_f("unsupported pubkey type %d",
		    EVP_PKEY_بنياد_id(pubkey));
	}
	EVP_PKEY_free(pubkey);
}

ساكن فراغ
do_convert_from_pem(بنية sshkey **k, صحيح *خاص)
{
	FILE *fp;
	RSA *rsa;

	إذا ((fp = fopen(سڃاڻپ_عنصر_file, "r")) == عدم)
		fatal("%s: %s: %s", __progname, سڃاڻپ_عنصر_file, strerror(errno));
	إذا ((rsa = PEM_read_RSAPublic_ڪنجي(fp, عدم, عدم, عدم)) != عدم) {
		إذا ((*k = sshkey_new(ڪنجي_UNSPEC)) == عدم)
			fatal("sshkey_new failed");
		إذا (((*k)->pkey = EVP_PKEY_new()) == عدم)
			fatal("EVP_PKEY_new failed");
		(*k)->type = ڪنجي_RSA;
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

	إذا (!have_سڃاڻپ_عنصر)
		ask_filename(pw, "Enter file in which the key is");
	إذا (stat(سڃاڻپ_عنصر_file, &st) == -1)
		fatal("%s: %s: %s", __progname, سڃاڻپ_عنصر_file, strerror(errno));

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
		حالة ڪنجي_ECDSA:
			ok = PEM_write_ECPrivate_ڪنجي(stdout,
			    EVP_PKEY_get0_EC_ڪنجي(k->pkey), عدم, عدم, 0,
			    عدم, عدم);
			اكسر;
		حالة ڪنجي_RSA:
			ok = PEM_write_RSAPrivate_ڪنجي(stdout,
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
#جيڪڏهن_پورو

ساكن فراغ
do_print_عوامي(بنية passwd *pw)
{
	بنية sshkey *prv;
	بنية stat st;
	صحيح r;
	حرف *comment = عدم;

	إذا (!have_سڃاڻپ_عنصر)
		ask_filename(pw, "Enter file in which the key is");
	إذا (stat(سڃاڻپ_عنصر_file, &st) == -1)
		fatal("%s: %s", سڃاڻپ_عنصر_file, strerror(errno));
	prv = ڀريو_سڃاڻپ_عنصر(سڃاڻپ_عنصر_file, &comment);
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
	ٻاهر_نڪرو(0);
}

ساكن فراغ
do_download(بنية passwd *pw)
{
#جيڪڏهن_وصف_ٿيل ENABLE_PKCS11
	بنية sshkey **ڪنجيون = عدم;
	صحيح i, nkeys;
	تعداد sshkey_fp_rep rep;
	صحيح fptype;
	حرف *fp, *ra, **comments = عدم;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;

	pkcs11_init(1);
	nkeys = pkcs11_جوڙيو_provider(pkcs11provider, عدم, &ڪنجيون, &comments);
	إذا (nkeys <= 0)
		fatal("cannot read public key from pkcs11");
	لكل (i = 0; i < nkeys; i++) {
		إذا (print_fingerprint) {
			fp = sshkey_fingerprint(ڪنجيون[i], fptype, rep);
			ra = sshkey_fingerprint(ڪنجيون[i], fingerprint_hash,
			    SSH_FP_RANDOMART);
			إذا (fp == عدم || ra == عدم)
				fatal_f("sshkey_fingerprint fail");
			لکو("%u %s %s (PKCS11 key)\n", sshkey_سائيز(ڪنجيون[i]),
			    fp, sshkey_type(ڪنجيون[i]));
			إذا (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
				لکو("%s\n", ra);
			حرر(ra);
			حرر(fp);
		} وإلا {
			(فراغ) sshkey_write(ڪنجيون[i], stdout); /* XXX check */
			fprintf(stdout, "%s%s\n",
			    *(comments[i]) == '\0' ? "" : " ", comments[i]);
		}
		حرر(comments[i]);
		sshkey_free(ڪنجيون[i]);
	}
	حرر(comments);
	حرر(ڪنجيون);
	pkcs11_terminate();
	ٻاهر_نڪرو(0);
#وإلا
	fatal("no pkcs11 support");
#جيڪڏهن_پورو /* ENABLE_PKCS11 */
}

ساكن بنية sshkey *
try_read_ڪنجي(حرف **cpp)
{
	بنية sshkey *ret;
	صحيح r;

	إذا ((ret = sshkey_new(ڪنجي_UNSPEC)) == عدم)
		fatal("sshkey_new failed");
	إذا ((r = sshkey_read(ret, cpp)) == 0)
		أرجع ret;
	/* Not a key */
	sshkey_free(ret);
	أرجع عدم;
}

ساكن فراغ
fingerprint_one_ڪنجي(ثابت بنية sshkey *عام, ثابت حرف *comment)
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
	mprintf("%u %s %s (%s)\n", sshkey_سائيز(عام), fp,
	    comment ? comment : "no comment", sshkey_type(عام));
	إذا (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
		لکو("%s\n", ra);
	حرر(ra);
	حرر(fp);
}

ساكن فراغ
fingerprint_ذاتي(ثابت حرف *رستو)
{
	بنية stat st;
	حرف *comment = عدم;
	بنية sshkey *privkey = عدم, *pubkey = عدم;
	صحيح r;

	إذا (stat(سڃاڻپ_عنصر_file, &st) == -1)
		fatal("%s: %s", رستو, strerror(errno));
	إذا ((r = sshkey_ڀريو_عوامي(رستو, &pubkey, &comment)) != 0)
		debug_r(r, "load public \"%s\"", رستو);
	إذا (pubkey == عدم || comment == عدم || *comment == '\0') {
		حرر(comment);
		إذا ((r = sshkey_ڀريو_ذاتي(رستو, عدم,
		    &privkey, &comment)) != 0)
			debug_r(r, "load private \"%s\"", رستو);
	}
	إذا (pubkey == عدم && privkey == عدم)
		fatal("%s is not a key file.", رستو);

	fingerprint_one_ڪنجي(pubkey == عدم ? privkey : pubkey, comment);
	sshkey_free(pubkey);
	sshkey_free(privkey);
	حرر(comment);
}

ساكن فراغ
do_fingerprint(بنية passwd *pw)
{
	FILE *f;
	بنية sshkey *عام = عدم;
	حرف *comment = عدم, *cp, *ep, *سٽ = عدم;
	سائيز_t linesize = 0;
	صحيح i, invalid = 1;
	ثابت حرف *رستو;
	u_long lnum = 0;

	إذا (!have_سڃاڻپ_عنصر)
		ask_filename(pw, "Enter file in which the key is");
	رستو = سڃاڻپ_عنصر_file;

	إذا (strcmp(سڃاڻپ_عنصر_file, "-") == 0) {
		f = stdin;
		رستو = "(stdin)";
	} وإلا إذا ((f = fopen(رستو, "r")) == عدم)
		fatal("%s: %s: %s", __progname, رستو, strerror(errno));

	طالما (getline(&سٽ, &linesize, f) != -1) {
		lnum++;
		cp = سٽ;
		cp[strcspn(cp, "\r\n")] = '\0';
		/* Trim leading space and comments */
		cp = سٽ + strspn(سٽ, " \t");
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
		إذا (lnum == 1 && strcmp(سڃاڻپ_عنصر_file, "-") != 0 &&
		    لڙي_ڳولا(cp, "PRIVATE KEY") != عدم) {
			حرر(سٽ);
			fclose(f);
			fingerprint_ذاتي(رستو);
			ٻاهر_نڪرو(0);
		}

		/*
		 * If it's not a private key, then this must be prepared to
		 * accept a public key prefixed with a hostname or options.
		 * Try a bare key first, otherwise skip the leading stuff.
		 */
		comment = عدم;
		إذا ((عام = try_read_ڪنجي(&cp)) == عدم) {
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
		إذا (عام == عدم && (عام = try_read_ڪنجي(&cp)) == عدم) {
			debug("%s:%lu: not a public key", رستو, lnum);
			استمر;
		}

		/* Find trailing comment, if any */
		لكل (; *cp == ' ' || *cp == '\t'; cp++)
			;
		إذا (*cp != '\0' && *cp != '#')
			comment = cp;

		fingerprint_one_ڪنجي(عام, comment);
		sshkey_free(عام);
		invalid = 0; /* One good key in the file is sufficient */
	}
	fclose(f);
	حرر(سٽ);

	إذا (invalid)
		fatal("%s is not a public key file.", رستو);
	ٻاهر_نڪرو(0);
}

ساكن فراغ
do_gen_all_hostkeys(بنية passwd *pw)
{
	بنية {
		حرف *ڪنجي_type;
		حرف *ڪنجي_type_display;
		حرف *رستو;
	} ڪنجي_types[] = {
#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
		{ "rsa", "RSA" ,رستو_HOST_RSA_ڪنجي_FILE },
		{ "ecdsa", "ECDSA",رستو_HOST_ECDSA_ڪنجي_FILE },
#جيڪڏهن_پورو /* WITH_OPENSSL */
		{ "ed25519", "ED25519",رستو_HOST_ED25519_ڪنجي_FILE },
#جيڪڏهن_وصف_ٿيل USE_MLDSA
		{ "mldsa44-ed25519", "MLDSA44-ED25519",
		     رستو_HOST_MLDSA44_ED25519_ڪنجي_FILE },
#جيڪڏهن_پورو
		{ عدم, عدم, عدم }
	};

	uint32_t بٽ = 0;
	صحيح پهريون = 0;
	بنية stat st;
	بنية sshkey *خاص, *عام;
	حرف comment[ڪنجي_COMMENT_MAX], *prv_tmp, *pub_tmp, *prv_file, *pub_file;
	صحيح i, type, fd, r;

	لكل (i = 0; ڪنجي_types[i].ڪنجي_type; i++) {
		عام = خاص = عدم;
		prv_tmp = pub_tmp = prv_file = pub_file = عدم;

		xasprintf(&prv_file, "%s%s",
		    سڃاڻپ_عنصر_file, ڪنجي_types[i].رستو);

		/* Check whether private key exists and is not zero-length */
		إذا (stat(prv_file, &st) == 0) {
			إذا (st.st_size != 0)
				اذهب ايندڙ;
		} وإلا إذا (errno != ENOENT) {
			error("Could not stat %s: %s", ڪنجي_types[i].رستو,
			    strerror(errno));
			اذهب failnext;
		}

		/*
		 * Private key doesn't exist or is invalid; proceed with
		 * key generation.
		 */
		xasprintf(&prv_tmp, "%s%s.XXXXXXXXXX",
		    سڃاڻپ_عنصر_file, ڪنجي_types[i].رستو);
		xasprintf(&pub_tmp, "%s%s.pub.XXXXXXXXXX",
		    سڃاڻپ_عنصر_file, ڪنجي_types[i].رستو);
		xasprintf(&pub_file, "%s%s.pub",
		    سڃاڻپ_عنصر_file, ڪنجي_types[i].رستو);

		إذا (پهريون == 0) {
			پهريون = 1;
			لکو("%s: generating new host keys: ", __progname);
		}
		لکو("%s ", ڪنجي_types[i].ڪنجي_type_display);
		fflush(stdout);
		type = sshkey_type_from_shortname(ڪنجي_types[i].ڪنجي_type);
		إذا ((fd = mkstemp(prv_tmp)) == -1) {
			error("Could not save your private key in %s: %s",
			    prv_tmp, strerror(errno));
			اذهب failnext;
		}
		(فراغ)close(fd); /* just using mkstemp() to reserve a name */
		بٽ = 0;
		type_بٽ_valid(type, عدم, &بٽ);
		إذا ((r = sshkey_generate(type, بٽ, &خاص)) != 0) {
			error_r(r, "sshkey_generate failed");
			اذهب failnext;
		}
		إذا ((r = sshkey_from_ذاتي(خاص, &عام)) != 0)
			fatal_fr(r, "sshkey_from_private");
		snprintf(comment, حجم comment, "%s@%s", pw->pw_name,
		    hostname);
		إذا ((r = sshkey_save_ذاتي(خاص, prv_tmp, "",
		    comment, ذاتي_ڪنجي_format, openssh_format_cipher,
		    ڦيرا)) != 0) {
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
		إذا ((r = sshkey_save_عوامي(عام, pub_tmp, comment)) != 0) {
			error_r(r, "Unable to save public key to %s",
			    سڃاڻپ_عنصر_file);
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
			    ڪنجي_types[i].رستو, strerror(errno));
 failnext:
			پهريون = 0;
			اذهب ايندڙ;
		}
 ايندڙ:
		sshkey_free(خاص);
		sshkey_free(عام);
		حرر(prv_tmp);
		حرر(pub_tmp);
		حرر(prv_file);
		حرر(pub_file);
	}
	إذا (پهريون != 0)
		لکو("\n");
}

بنية معلوم_hosts_ctx {
	ثابت حرف *host;	/* Hostname searched for in find/delete case */
	FILE *ٻاهريون;		/* Output file, stdout for find_hosts case */
	صحيح has_unhashed;	/* When hashing, original had unhashed hosts */
	صحيح مليو_ڪنجي;		/* For find/delete, host was found */
	صحيح invalid;		/* File contained invalid items; don't delete */
	صحيح hash_hosts;		/* Hash hostnames as we go */
	صحيح ڳوليو_host;		/* Search for specific hostname */
	صحيح delete_host;	/* Delete host from known_hosts */
};

ساكن صحيح
معلوم_hosts_hash(بنية hostkey_foreach_سٽ *l, فراغ *_ctx)
{
	بنية معلوم_hosts_ctx *ctx = (بنية معلوم_hosts_ctx *)_ctx;
	حرف *hashed, *cp, *hosts, *ohosts;
	صحيح has_wild = l->hosts && strcspn(l->hosts, "*?!") != لڙي_ڊيگهه(l->hosts);
	صحيح was_hashed = l->hosts && l->hosts[0] == HASH_DELIM;

	بدل (l->حالت) {
	حالة HKF_حالت_OK:
	حالة HKF_حالت_MATCHED:
		/*
		 * Don't hash hosts already hashed, with wildcard
		 * characters or a CA/revocation marker.
		 */
		إذا (was_hashed || has_wild || l->marker != MRK_NONE) {
			fprintf(ctx->ٻاهريون, "%s\n", l->سٽ);
			إذا (has_wild && !ctx->ڳوليو_host) {
				logit("%s:%lu: ignoring host name "
				    "with wildcard: %.64s", l->رستو,
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
			fprintf(ctx->ٻاهريون, "%s %s\n", hashed, l->rawkey);
			حرر(hashed);
			ctx->has_unhashed = 1;
		}
		حرر(ohosts);
		أرجع 0;
	حالة HKF_حالت_INVALID:
		/* Retain invalid lines, but mark file as invalid. */
		ctx->invalid = 1;
		logit("%s:%lu: invalid line", l->رستو, l->linenum);
		/* FALLTHROUGH */
	افتراضي:
		fprintf(ctx->ٻاهريون, "%s\n", l->سٽ);
		أرجع 0;
	}
	/* NOTREACHED */
	أرجع -1;
}

ساكن صحيح
معلوم_hosts_ڳوليو_delete(بنية hostkey_foreach_سٽ *l, فراغ *_ctx)
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
				fprintf(ctx->ٻاهريون, "%s\n", l->سٽ);
			} وإلا {
				/*
				 * Hostname matches and has no CA/revoke
				 * marker, delete it by *not* writing the
				 * line to ctx->out.
				 */
				ctx->مليو_ڪنجي = 1;
				إذا (!quiet)
					لکو("# Host %s found: line %lu\n",
					    ctx->host, l->linenum);
			}
			أرجع 0;
		} وإلا إذا (ctx->ڳوليو_host) {
			ctx->مليو_ڪنجي = 1;
			إذا (!quiet) {
				لکو("# Host %s found: line %lu %s\n",
				    ctx->host,
				    l->linenum, l->marker == MRK_CA ? "CA" :
				    (l->marker == MRK_REVOKE ? "REVOKED" : ""));
			}
			إذا (ctx->hash_hosts)
				معلوم_hosts_hash(l, ctx);
			وإلا إذا (print_fingerprint) {
				fp = sshkey_fingerprint(l->ڪنجي, fptype, rep);
				ra = sshkey_fingerprint(l->ڪنجي,
				    fingerprint_hash, SSH_FP_RANDOMART);
				إذا (fp == عدم || ra == عدم)
					fatal_f("sshkey_fingerprint failed");
				mprintf("%s %s %s%s%s\n", ctx->host,
				    sshkey_type(l->ڪنجي), fp,
				    l->comment[0] ? " " : "",
				    l->comment);
				إذا (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
					لکو("%s\n", ra);
				حرر(ra);
				حرر(fp);
			} وإلا
				fprintf(ctx->ٻاهريون, "%s\n", l->سٽ);
			أرجع 0;
		}
	} وإلا إذا (ctx->delete_host) {
		/* Retain non-matching hosts when deleting */
		إذا (l->حالت == HKF_حالت_INVALID) {
			ctx->invalid = 1;
			logit("%s:%lu: invalid line", l->رستو, l->linenum);
		}
		fprintf(ctx->ٻاهريون, "%s\n", l->سٽ);
	}
	أرجع 0;
}

ساكن فراغ
do_معلوم_hosts(بنية passwd *pw, ثابت حرف *name, صحيح ڳوليو_host,
    صحيح delete_host, صحيح hash_hosts)
{
	حرف *cp, tmp[PATH_MAX], old[PATH_MAX];
	صحيح r, fd, oerrno, inplace = 0;
	بنية معلوم_hosts_ctx ctx;
	u_int foreach_options;
	بنية stat sb;

	إذا (!have_سڃاڻپ_عنصر) {
		cp = tilde_expand_filename(رستو_SSH_USER_HOSTFILE, pw->pw_uid);
		إذا (strlcpy(سڃاڻپ_عنصر_file, cp, حجم(سڃاڻپ_عنصر_file)) >=
		    حجم(سڃاڻپ_عنصر_file))
			fatal("Specified known hosts path too long");
		حرر(cp);
		have_سڃاڻپ_عنصر = 1;
	}
	إذا (stat(سڃاڻپ_عنصر_file, &sb) != 0)
		fatal("Cannot stat %s: %s", سڃاڻپ_عنصر_file, strerror(errno));

	memset(&ctx, 0, حجم(ctx));
	ctx.ٻاهريون = stdout;
	ctx.host = name;
	ctx.hash_hosts = hash_hosts;
	ctx.ڳوليو_host = ڳوليو_host;
	ctx.delete_host = delete_host;

	/*
	 * Find hosts goes to stdout, hash and deletions happen in-place
	 * A corner case is ssh-keygen -HF foo, which should go to stdout
	 */
	إذا (!ڳوليو_host && (hash_hosts || delete_host)) {
		إذا (strlcpy(tmp, سڃاڻپ_عنصر_file, حجم(tmp)) >= حجم(tmp) ||
		    strlcat(tmp, ".XXXXXXXXXX", حجم(tmp)) >= حجم(tmp) ||
		    strlcpy(old, سڃاڻپ_عنصر_file, حجم(old)) >= حجم(old) ||
		    strlcat(old, ".old", حجم(old)) >= حجم(old))
			fatal("known_hosts path too long");
		umask(077);
		إذا ((fd = mkstemp(tmp)) == -1)
			fatal("mkstemp: %s", strerror(errno));
		إذا ((ctx.ٻاهريون = fdopen(fd, "w")) == عدم) {
			oerrno = errno;
			unlink(tmp);
			fatal("fdopen: %s", strerror(oerrno));
		}
		(فراغ)fchmod(fd, sb.st_mode & 0644);
		inplace = 1;
	}
	/* XXX support identity_file == "-" for stdin */
	foreach_options = ڳوليو_host ? HKF_WANT_ميلاپ : 0;
	foreach_options |= print_fingerprint ? HKF_WANT_PARSE_ڪنجي : 0;
	إذا ((r = hostkeys_foreach(سڃاڻپ_عنصر_file, (ڳوليو_host || !hash_hosts) ?
	    معلوم_hosts_ڳوليو_delete : معلوم_hosts_hash, &ctx, name, عدم,
	    foreach_options, 0)) != 0) {
		إذا (inplace)
			unlink(tmp);
		fatal_fr(r, "hostkeys_foreach");
	}

	إذا (inplace)
		fclose(ctx.ٻاهريون);

	إذا (ctx.invalid) {
		error("%s is not a valid known_hosts file.", سڃاڻپ_عنصر_file);
		إذا (inplace) {
			error("Not replacing existing known_hosts "
			    "file because of errors");
			unlink(tmp);
		}
		ٻاهر_نڪرو(1);
	} وإلا إذا (delete_host && !ctx.مليو_ڪنجي) {
		logit("Host %s not found in %s", name, سڃاڻپ_عنصر_file);
		إذا (inplace)
			unlink(tmp);
	} وإلا إذا (inplace) {
		/* Backup existing file */
		إذا (unlink(old) == -1 && errno != ENOENT)
			fatal("unlink %.100s: %s", old, strerror(errno));
		إذا (link(سڃاڻپ_عنصر_file, old) == -1)
			fatal("link %.100s to %.100s: %s", سڃاڻپ_عنصر_file, old,
			    strerror(errno));
		/* Move new one into place */
		إذا (rename(tmp, سڃاڻپ_عنصر_file) == -1) {
			error("rename\"%s\" to \"%s\": %s", tmp, سڃاڻپ_عنصر_file,
			    strerror(errno));
			unlink(tmp);
			unlink(old);
			ٻاهر_نڪرو(1);
		}

		لکو("%s updated.\n", سڃاڻپ_عنصر_file);
		لکو("Original contents retained as %s\n", old);
		إذا (ctx.has_unhashed) {
			logit("WARNING: %s contains unhashed entries", old);
			logit("Delete this file to ensure privacy "
			    "of hostnames");
		}
	}

	ٻاهر_نڪرو (ڳوليو_host && !ctx.مليو_ڪنجي);
}

/*
 * Perform changing a passphrase.  The argument is the passwd structure
 * for the current user.
 */
ساكن فراغ
do_change_passphrase(بنية passwd *pw, حرف * ثابت *opts, سائيز_t nopts)
{
	حرف *comment;
	حرف *old_passphrase, *passphrase1, *passphrase2;
	بنية stat st;
	بنية sshkey *خاص;
	صحيح r;
	سائيز_t i;

	إذا (!have_سڃاڻپ_عنصر)
		ask_filename(pw, "Enter file in which the key is");
	إذا (stat(سڃاڻپ_عنصر_file, &st) == -1)
		fatal("%s: %s", سڃاڻپ_عنصر_file, strerror(errno));
	/* Try to load the file with empty passphrase. */
	r = sshkey_ڀريو_ذاتي(سڃاڻپ_عنصر_file, "", &خاص, &comment);
	إذا (r == SSH_ERR_ڪنجي_WRONG_PASSPHRASE) {
		إذا (سڃاڻپ_عنصر_passphrase)
			old_passphrase = xstrdup(سڃاڻپ_عنصر_passphrase);
		وإلا
			old_passphrase =
			    read_passphrase("Enter old passphrase: ",
			    RP_ALLOW_STDIN);
		r = sshkey_ڀريو_ذاتي(سڃاڻپ_عنصر_file, old_passphrase,
		    &خاص, &comment);
		freezero(old_passphrase, لڙي_ڊيگهه(old_passphrase));
		إذا (r != 0)
			اذهب badkey;
	} وإلا إذا (r != 0) {
 badkey:
		fatal_r(r, "Failed to load key %s", سڃاڻپ_عنصر_file);
	}
	إذا (comment)
		mprintf("Key has comment '%s'\n", comment);

	/* All current -O options relate to FIDO keys only */
	إذا (nopts != 0 && !sshkey_is_sk(خاص)) {
		fatal("FIDO-specific option requested for non-FIDO key %s",
		    سڃاڻپ_عنصر_file);
	}
	إذا (sshkey_is_sk(خاص)) {
		debug_f("%s: original FIDO key flags: "
		    "%stouch-required %sverify-required", سڃاڻپ_عنصر_file,
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
		    "%stouch-required %sverify-required", سڃاڻپ_عنصر_file,
		    (خاص->sk_flags & SSH_SK_USER_PRESENCE_REQD) ? "": "no-",
		    (خاص->sk_flags & SSH_SK_USER_VERIFICATION_REQD) ? "" : "no-");
	}

	/* Ask the new passphrase (twice). */
	إذا (سڃاڻپ_عنصر_new_passphrase) {
		passphrase1 = xstrdup(سڃاڻپ_عنصر_new_passphrase);
		passphrase2 = عدم;
	} وإلا {
		passphrase1 =
			read_passphrase("Enter new passphrase (empty for no "
			    "passphrase): ", RP_ALLOW_STDIN);
		passphrase2 = read_passphrase("Enter same passphrase again: ",
		    RP_ALLOW_STDIN);

		/* Verify that they are the same. */
		إذا (strcmp(passphrase1, passphrase2) != 0) {
			explicit_bzero(passphrase1, لڙي_ڊيگهه(passphrase1));
			explicit_bzero(passphrase2, لڙي_ڊيگهه(passphrase2));
			حرر(passphrase1);
			حرر(passphrase2);
			لکو("Pass phrases do not match.  Try again.\n");
			ٻاهر_نڪرو(1);
		}
		/* Destroy the other copy. */
		freezero(passphrase2, لڙي_ڊيگهه(passphrase2));
	}

	/* Save the file using the new passphrase. */
	إذا ((r = sshkey_save_ذاتي(خاص, سڃاڻپ_عنصر_file, passphrase1,
	    comment, ذاتي_ڪنجي_format, openssh_format_cipher, ڦيرا)) != 0) {
		error_r(r, "Saving key \"%s\" failed", سڃاڻپ_عنصر_file);
		freezero(passphrase1, لڙي_ڊيگهه(passphrase1));
		sshkey_free(خاص);
		حرر(comment);
		ٻاهر_نڪرو(1);
	}
	/* Destroy the passphrase and the copy of the key in memory. */
	freezero(passphrase1, لڙي_ڊيگهه(passphrase1));
	sshkey_free(خاص);		 /* Destroys contents */
	حرر(comment);

	لکو("Your identification has been saved with the new passphrase.\n");
	ٻاهر_نڪرو(0);
}

/*
 * Print the SSHFP RR.
 */
ساكن صحيح
do_print_resource_رڪارڊ(بنية passwd *pw, حرف *fname, حرف *hname,
    صحيح print_generic, حرف * ثابت *opts, سائيز_t nopts)
{
	بنية sshkey *عام;
	حرف *comment = عدم;
	ثابت حرف *p;
	بنية stat st;
	صحيح r, hash = -1;
	سائيز_t i;

	لكل (i = 0; i < nopts; i++) {
		إذا ((p = strprefix(opts[i], "hashalg=", 1)) != عدم) {
			إذا ((hash = ssh_digest_alg_by_name(p)) == -1)
				fatal("Unsupported hash algorithm");
		} وإلا {
			error("Invalid option \"%s\"", opts[i]);
			أرجع SSH_ERR_INVALID_دليل;
		}
	}
	إذا (fname == عدم)
		fatal_f("no filename");
	إذا (stat(fname, &st) == -1) {
		إذا (errno == ENOENT)
			أرجع 0;
		fatal("%s: %s", fname, strerror(errno));
	}
	إذا ((r = sshkey_ڀريو_عوامي(fname, &عام, &comment)) != 0)
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
do_change_comment(بنية passwd *pw, ثابت حرف *سڃاڻپ_عنصر_comment)
{
	حرف new_comment[ڪنجي_COMMENT_MAX], *comment, *passphrase;
	بنية sshkey *خاص;
	بنية sshkey *عام;
	بنية stat st;
	صحيح r;

	إذا (!have_سڃاڻپ_عنصر)
		ask_filename(pw, "Enter file in which the key is");
	إذا (stat(سڃاڻپ_عنصر_file, &st) == -1)
		fatal("%s: %s", سڃاڻپ_عنصر_file, strerror(errno));
	إذا ((r = sshkey_ڀريو_ذاتي(سڃاڻپ_عنصر_file, "",
	    &خاص, &comment)) == 0)
		passphrase = xstrdup("");
	وإلا إذا (r != SSH_ERR_ڪنجي_WRONG_PASSPHRASE)
		fatal_r(r, "Cannot load private key \"%s\"", سڃاڻپ_عنصر_file);
	وإلا {
		إذا (سڃاڻپ_عنصر_passphrase)
			passphrase = xstrdup(سڃاڻپ_عنصر_passphrase);
		وإلا إذا (سڃاڻپ_عنصر_new_passphrase)
			passphrase = xstrdup(سڃاڻپ_عنصر_new_passphrase);
		وإلا
			passphrase = read_passphrase("Enter passphrase: ",
			    RP_ALLOW_STDIN);
		/* Try to load using the passphrase. */
		إذا ((r = sshkey_ڀريو_ذاتي(سڃاڻپ_عنصر_file, passphrase,
		    &خاص, &comment)) != 0) {
			freezero(passphrase, لڙي_ڊيگهه(passphrase));
			fatal_r(r, "Cannot load private key \"%s\"",
			    سڃاڻپ_عنصر_file);
		}
	}

	إذا (خاص->type != ڪنجي_ED25519 &&
	    ذاتي_ڪنجي_format != SSHKEY_ذاتي_OPENSSH) {
		error("Comments are only supported for keys stored in "
		    "the new format (-o).");
		explicit_bzero(passphrase, لڙي_ڊيگهه(passphrase));
		sshkey_free(خاص);
		ٻاهر_نڪرو(1);
	}
	إذا (comment)
		لکو("Old comment: %s\n", comment);
	وإلا
		لکو("No existing comment\n");

	إذا (سڃاڻپ_عنصر_comment) {
		strlcpy(new_comment, سڃاڻپ_عنصر_comment, حجم(new_comment));
	} وإلا {
		لکو("New comment: ");
		fflush(stdout);
		إذا (!fgets(new_comment, حجم(new_comment), stdin)) {
			explicit_bzero(passphrase, لڙي_ڊيگهه(passphrase));
			sshkey_free(خاص);
			ٻاهر_نڪرو(1);
		}
		new_comment[strcspn(new_comment, "\n")] = '\0';
	}
	إذا (comment != عدم && strcmp(comment, new_comment) == 0) {
		لکو("No change to comment\n");
		حرر(passphrase);
		sshkey_free(خاص);
		حرر(comment);
		ٻاهر_نڪرو(0);
	}

	/* Save the file using the new passphrase. */
	إذا ((r = sshkey_save_ذاتي(خاص, سڃاڻپ_عنصر_file, passphrase,
	    new_comment, ذاتي_ڪنجي_format, openssh_format_cipher,
	    ڦيرا)) != 0) {
		error_r(r, "Saving key \"%s\" failed", سڃاڻپ_عنصر_file);
		freezero(passphrase, لڙي_ڊيگهه(passphrase));
		sshkey_free(خاص);
		حرر(comment);
		ٻاهر_نڪرو(1);
	}
	freezero(passphrase, لڙي_ڊيگهه(passphrase));
	إذا ((r = sshkey_from_ذاتي(خاص, &عام)) != 0)
		fatal_fr(r, "sshkey_from_private");
	sshkey_free(خاص);

	strlcat(سڃاڻپ_عنصر_file, ".pub", حجم(سڃاڻپ_عنصر_file));
	إذا ((r = sshkey_save_عوامي(عام, سڃاڻپ_عنصر_file, new_comment)) != 0)
		fatal_r(r, "Unable to save public key to %s", سڃاڻپ_عنصر_file);
	sshkey_free(عام);
	حرر(comment);

	إذا (لڙي_ڊيگهه(new_comment) > 0)
		لکو("Comment '%s' applied\n", new_comment);
	وإلا
		لکو("Comment removed\n");

	ٻاهر_نڪرو(0);
}

ساكن فراغ
cert_ext_جوڙيو(ثابت حرف *ڪنجي, ثابت حرف *قدر, صحيح iscrit)
{
	cert_ext = xreallocarray(cert_ext, ncert_ext + 1, حجم(*cert_ext));
	cert_ext[ncert_ext].ڪنجي = xstrdup(ڪنجي);
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
	إذا ((r = strcmp(a->ڪنجي, b->ڪنجي)) != 0)
		أرجع r;
	إذا ((a->val == عدم) != (b->val == عدم))
		أرجع (a->val == عدم) ? -1 : 1;
	إذا (a->val != عدم && (r = strcmp(a->val, b->val)) != 0)
		أرجع r;
	أرجع 0;
}

#وصف_ڪريو OPTIONS_CRITICAL	1
#وصف_ڪريو OPTIONS_EXTENSIONS	2
ساكن فراغ
prepare_options_buf(بنية sshbuf *c, صحيح which)
{
	بنية sshbuf *b;
	سائيز_t i;
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
			debug3_f("%s", ext->ڪنجي);
			إذا ((r = sshbuf_put_cstring(c, ext->ڪنجي)) != 0 ||
			    (r = sshbuf_put_string(c, عدم, 0)) != 0)
				fatal_fr(r, "prepare flag");
		} وإلا {
			/* key/value option */
			debug3_f("%s=%s", ext->ڪنجي, ext->val);
			sshbuf_reset(b);
			إذا ((r = sshbuf_put_cstring(c, ext->ڪنجي)) != 0 ||
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
		cert_ext_جوڙيو("force-command", certflags_command, 1);
	إذا (certflags_src_addr != عدم)
		cert_ext_جوڙيو("source-address", certflags_src_addr, 1);
	إذا ((certflags_flags & CERTOPT_REQUIRE_VERIFY) != 0)
		cert_ext_جوڙيو("verify-required", عدم, 1);
	/* extensions */
	إذا ((certflags_flags & CERTOPT_X_FWD) != 0)
		cert_ext_جوڙيو("permit-X11-forwarding", عدم, 0);
	إذا ((certflags_flags & CERTOPT_AGENT_FWD) != 0)
		cert_ext_جوڙيو("permit-agent-forwarding", عدم, 0);
	إذا ((certflags_flags & CERTOPT_پورٽ_FWD) != 0)
		cert_ext_جوڙيو("permit-port-forwarding", عدم, 0);
	إذا ((certflags_flags & CERTOPT_PTY) != 0)
		cert_ext_جوڙيو("permit-pty", عدم, 0);
	إذا ((certflags_flags & CERTOPT_USER_RC) != 0)
		cert_ext_جوڙيو("permit-user-rc", عدم, 0);
	إذا ((certflags_flags & CERTOPT_NO_REQUIRE_USER_PRESENCE) != 0)
		cert_ext_جوڙيو("no-touch-required", عدم, 0);
	/* order lexically by key */
	إذا (ncert_ext > 0)
		qsort(cert_ext, ncert_ext, حجم(*cert_ext), cert_ext_cmp);
}

ساكن بنية sshkey *
ڀريو_pkcs11_ڪنجي(حرف *رستو)
{
#جيڪڏهن_وصف_ٿيل ENABLE_PKCS11
	بنية sshkey **ڪنجيون = عدم, *عام, *خاص = عدم;
	صحيح r, i, nkeys;

	إذا ((r = sshkey_ڀريو_عوامي(رستو, &عام, عدم)) != 0)
		fatal_r(r, "Couldn't load CA public key \"%s\"", رستو);

	nkeys = pkcs11_جوڙيو_provider(pkcs11provider, سڃاڻپ_عنصر_passphrase,
	    &ڪنجيون, عدم);
	debug3_f("%d keys", nkeys);
	إذا (nkeys <= 0)
		fatal("cannot read public key from pkcs11");
	لكل (i = 0; i < nkeys; i++) {
		إذا (sshkey_equal_عوامي(عام, ڪنجيون[i])) {
			خاص = ڪنجيون[i];
			استمر;
		}
		sshkey_free(ڪنجيون[i]);
	}
	حرر(ڪنجيون);
	sshkey_free(عام);
	أرجع خاص;
#وإلا
	fatal("no pkcs11 support");
#جيڪڏهن_پورو /* ENABLE_PKCS11 */
}

/* Signer for sshkey_certify_custom that uses the agent */
ساكن صحيح
agent_signer(بنية sshkey *ڪنجي, u_char **sigp, سائيز_t *lenp,
    ثابت u_char *معلومات, سائيز_t datalen,
    ثابت حرف *alg, ثابت حرف *provider, ثابت حرف *pin,
    u_int compat, فراغ *ctx)
{
	صحيح *agent_fdp = (صحيح *)ctx;

	أرجع ssh_agent_sign(*agent_fdp, ڪنجي, sigp, lenp,
	    معلومات, datalen, alg, compat);
}

ساكن فراغ
do_ca_sign(بنية passwd *pw, ثابت حرف *ca_ڪنجي_رستو, صحيح prefer_agent,
    بنانشان ڊگهو ڊگهو cert_serial, صحيح cert_serial_autoinc,
    صحيح argc, حرف **argv)
{
	صحيح r, i, ڪنجي_اندريون_agent = 0, agent_fd = -1;
	u_int n;
	بنية sshkey *ca, *عام;
	حرف valid[64], *otmp, *tmp, *cp, *ٻاهريون, *comment;
	حرف *ca_fp = عدم, **plist = عدم, *pin = عدم;
	بنية ssh_identitylist *agent_ids;
	سائيز_t j;
	بنية notifier_ctx *notifier = عدم;

#جيڪڏهن_وصف_ٿيل ENABLE_PKCS11
	pkcs11_init(1);
#جيڪڏهن_پورو
	tmp = tilde_expand_filename(ca_ڪنجي_رستو, pw->pw_uid);
	إذا (pkcs11provider != عدم) {
		/* If a PKCS#11 token was specified then try to use it */
		إذا ((ca = ڀريو_pkcs11_ڪنجي(tmp)) == عدم)
			fatal("No PKCS#11 key matching %s found", ca_ڪنجي_رستو);
	} وإلا إذا (prefer_agent) {
		/*
		 * Agent signature requested. Try to use agent after making
		 * sure the public key specified is actually present in the
		 * agent.
		 */
		إذا ((r = sshkey_ڀريو_عوامي(tmp, &ca, عدم)) != 0)
			fatal_r(r, "Cannot load CA public key %s", tmp);
		إذا ((r = ssh_get_authentication_socket(&agent_fd)) != 0)
			fatal_r(r, "Cannot use public key for CA signature");
		إذا ((r = ssh_fetch_identitylist(agent_fd, &agent_ids)) != 0)
			fatal_r(r, "Retrieve agent key list");
		لكل (j = 0; j < agent_ids->nkeys; j++) {
			إذا (sshkey_equal(ca, agent_ids->ڪنجيون[j])) {
				ڪنجي_اندريون_agent = 1;
				/* Replace the CA key with the agent one */
				sshkey_free(ca);
				ca = agent_ids->ڪنجيون[j];
				agent_ids->ڪنجيون[j] = عدم;
				اكسر;
			}
		}
		إذا (!ڪنجي_اندريون_agent)
			fatal("CA key %s not found in agent", tmp);
		ssh_free_identitylist(agent_ids);
	} وإلا {
		/* CA key is assumed to be a private key on the filesystem */
		ca = ڀريو_سڃاڻپ_عنصر(tmp, عدم);
		إذا (sshkey_is_sk(ca) &&
		    (ca->sk_flags & SSH_SK_USER_VERIFICATION_REQD)) {
			إذا ((pin = read_passphrase("Enter PIN for CA key: ",
			    RP_ALLOW_STDIN)) == عدم)
				fatal_f("couldn't read PIN");
		}
	}
	حرر(tmp);

	إذا (ڪنجي_type_name != عدم) {
		إذا (sshkey_type_from_shortname(ڪنجي_type_name) != ca->type) {
			fatal("CA key type %s doesn't match specified %s",
			    sshkey_ssh_name(ca), ڪنجي_type_name);
		}
	} وإلا إذا (ca->type == ڪنجي_RSA) {
		/* Default to a good signature algorithm */
		ڪنجي_type_name = "rsa-sha2-512";
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
		إذا ((r = sshkey_ڀريو_عوامي(tmp, &عام, &comment)) != 0)
			fatal_r(r, "load pubkey \"%s\"", tmp);
		إذا (sshkey_is_cert(عام))
			fatal_f("key \"%s\" type %s cannot be certified",
			    tmp, sshkey_type(عام));

		/* Prepare certificate to sign */
		إذا ((r = sshkey_منزل_certified(عام)) != 0)
			fatal_r(r, "Could not upgrade key %s to certificate", tmp);
		عام->cert->type = cert_ڪنجي_type;
		عام->cert->serial = (uint64_t)cert_serial;
		عام->cert->ڪنجي_id = xstrdup(cert_ڪنجي_id);
		عام->cert->nprincipals = n;
		عام->cert->principals = plist;
		عام->cert->valid_after = cert_valid_from;
		عام->cert->valid_before = cert_valid_منزل;
		prepare_options_buf(عام->cert->critical, OPTIONS_CRITICAL);
		prepare_options_buf(عام->cert->extensions,
		    OPTIONS_EXTENSIONS);
		إذا ((r = sshkey_from_ذاتي(ca,
		    &عام->cert->signature_ڪنجي)) != 0)
			fatal_r(r, "sshkey_from_private (ca key)");

		إذا (ڪنجي_اندريون_agent) {
			إذا ((r = sshkey_certify_custom(عام, ca,
			    ڪنجي_type_name, sk_provider, عدم, agent_signer,
			    &agent_fd)) != 0)
				fatal_r(r, "Couldn't certify %s via agent", tmp);
		} وإلا {
			إذا (sshkey_is_sk(ca) &&
			    (ca->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
				notifier = notify_شروعات(0,
				    "Confirm user presence for key %s %s",
				    sshkey_type(ca), ca_fp);
			}
			r = sshkey_certify(عام, ca, ڪنجي_type_name,
			    sk_provider, pin);
			notify_complete(notifier, "User presence confirmed");
			إذا (r != 0)
				fatal_r(r, "Couldn't certify key %s", tmp);
		}

		إذا ((cp = strrchr(tmp, '.')) != عدم && strcmp(cp, ".pub") == 0)
			*cp = '\0';
		xasprintf(&ٻاهريون, "%s-cert.pub", tmp);
		حرر(tmp);

		إذا ((r = sshkey_save_عوامي(عام, ٻاهريون, comment)) != 0) {
			fatal_r(r, "Unable to save public key to %s",
			    سڃاڻپ_عنصر_file);
		}

		إذا (!quiet) {
			sshkey_format_cert_validity(عام->cert,
			    valid, حجم(valid));
			logit("Signed %s key %s: id \"%s\" serial %llu%s%s "
			    "valid %s", sshkey_cert_type(عام),
			    ٻاهريون, عام->cert->ڪنجي_id,
			    (بنانشان ڊگهو ڊگهو)عام->cert->serial,
			    cert_principals != عدم ? " for " : "",
			    cert_principals != عدم ? cert_principals : "",
			    valid);
		}

		sshkey_free(عام);
		حرر(ٻاهريون);
		حرر(comment);
		إذا (cert_serial_autoinc)
			cert_serial++;
	}
	إذا (pin != عدم)
		freezero(pin, لڙي_ڊيگهه(pin));
	sshkey_free(ca);
	حرر(ca_fp);
#جيڪڏهن_وصف_ٿيل ENABLE_PKCS11
	pkcs11_terminate();
#جيڪڏهن_پورو
}

ساكن uint64_t
parse_relative_وقت(ثابت حرف *s, time_t now)
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
parse_hex_u64(ثابت حرف *s, uint64_t *مٿي)
{
	حرف *ep;
	بنانشان ڊگهو ڊگهو ull;

	errno = 0;
	ull = strtoull(s, &ep, 16);
	إذا (*s == '\0' || *ep != '\0')
		fatal("Invalid certificate time: not a number");
	إذا (errno == ERANGE && ull == ULONG_MAX)
		fatal_fr(SSH_ERR_SYSTEM_ERROR, "Invalid certificate time");
	*مٿي = (uint64_t)ull;
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
		cert_valid_from = parse_relative_وقت(from, now);
	وإلا إذا (strcmp(from, "always") == 0)
		cert_valid_from = 0;
	وإلا إذا (لڙي_ڀيٽ(from, "0x", 2) == 0)
		parse_hex_u64(from, &cert_valid_from);
	وإلا إذا (parse_absolute_وقت(from, &cert_valid_from) != 0)
		fatal("Invalid from time \"%s\"", from);

	إذا (*منزل == '-' || *منزل == '+')
		cert_valid_منزل = parse_relative_وقت(منزل, now);
	وإلا إذا (strcmp(منزل, "forever") == 0)
		cert_valid_منزل = ~(uint64_t)0;
	وإلا إذا (لڙي_ڀيٽ(منزل, "0x", 2) == 0)
		parse_hex_u64(منزل, &cert_valid_منزل);
	وإلا إذا (parse_absolute_وقت(منزل, &cert_valid_منزل) != 0)
		fatal("Invalid to time \"%s\"", منزل);

	إذا (cert_valid_منزل <= cert_valid_from)
		fatal("Empty certificate validity interval");
	حرر(from);
}

ساكن فراغ
جوڙيو_cert_option(حرف *opt)
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
		certflags_flags &= ~CERTOPT_پورٽ_FWD;
	وإلا إذا (strcasecmp(opt, "permit-port-forwarding") == 0)
		certflags_flags |= CERTOPT_پورٽ_FWD;
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
		إذا (addr_ميلاپ_cidr_list(عدم, p) != 0)
			fatal("Invalid source-address list");
		certflags_src_addr = xstrdup(p);
	} وإلا إذا (strprefix(opt, "extension:", 1) != عدم ||
		    (iscrit = (strprefix(opt, "critical:", 1) != عدم))) {
		val = xstrdup(strchr(opt, ':') + 1);
		إذا ((cp = strchr(val, '=')) != عدم)
			*cp++ = '\0';
		cert_ext_جوڙيو(val, cp, iscrit);
		حرر(val);
	} وإلا
		fatal("Unsupported certificate option \"%s\"", opt);
}

ساكن فراغ
show_options(بنية sshbuf *optbuf, صحيح اندريون_critical)
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
		لکو("                %s", name);
		إذا (!اندريون_critical &&
		    (strcmp(name, "permit-X11-forwarding") == 0 ||
		    strcmp(name, "permit-agent-forwarding") == 0 ||
		    strcmp(name, "permit-port-forwarding") == 0 ||
		    strcmp(name, "permit-pty") == 0 ||
		    strcmp(name, "permit-user-rc") == 0 ||
		    strcmp(name, "no-touch-required") == 0)) {
			لکو("\n");
		} وإلا إذا (اندريون_critical &&
		    (strcmp(name, "force-command") == 0 ||
		    strcmp(name, "source-address") == 0)) {
			إذا ((r = sshbuf_get_cstring(option, &arg, عدم)) != 0)
				fatal_fr(r, "parse critical");
			لکو(" %s\n", arg);
			حرر(arg);
		} وإلا إذا (اندريون_critical &&
		    strcmp(name, "verify-required") == 0) {
			لکو("\n");
		} وإلا إذا (sshbuf_len(option) > 0) {
			hex = sshbuf_dtob16(option);
			لکو(" UNKNOWN OPTION: %s (len %zu)\n",
			    hex, sshbuf_len(option));
			sshbuf_reset(option);
			حرر(hex);
		} وإلا
			لکو(" UNKNOWN FLAG OPTION\n");
		حرر(name);
		إذا (sshbuf_len(option) != 0)
			fatal("Option corrupt: extra data at end");
	}
	sshbuf_free(option);
	sshbuf_free(options);
}

ساكن فراغ
print_cert(بنية sshkey *ڪنجي)
{
	حرف valid[64], *ڪنجي_fp, *ca_fp;
	u_int i;

	ڪنجي_fp = sshkey_fingerprint(ڪنجي, fingerprint_hash, SSH_FP_DEFAULT);
	ca_fp = sshkey_fingerprint(ڪنجي->cert->signature_ڪنجي,
	    fingerprint_hash, SSH_FP_DEFAULT);
	إذا (ڪنجي_fp == عدم || ca_fp == عدم)
		fatal_f("sshkey_fingerprint fail");
	sshkey_format_cert_validity(ڪنجي->cert, valid, حجم(valid));

	لکو("        Type: %s %s certificate\n", sshkey_ssh_name(ڪنجي),
	    sshkey_cert_type(ڪنجي));
	لکو("        Public key: %s %s\n", sshkey_type(ڪنجي), ڪنجي_fp);
	لکو("        Signing CA: %s %s (using %s)\n",
	    sshkey_type(ڪنجي->cert->signature_ڪنجي), ca_fp,
	    ڪنجي->cert->signature_type);
	لکو("        Key ID: \"%s\"\n", ڪنجي->cert->ڪنجي_id);
	لکو("        Serial: %llu\n", (بنانشان ڊگهو ڊگهو)ڪنجي->cert->serial);
	لکو("        Valid: %s\n", valid);
	لکو("        Principals: ");
	إذا (ڪنجي->cert->nprincipals == 0)
		لکو("(none)\n");
	وإلا {
		لكل (i = 0; i < ڪنجي->cert->nprincipals; i++)
			لکو("\n                %s",
			    ڪنجي->cert->principals[i]);
		لکو("\n");
	}
	لکو("        Critical Options: ");
	إذا (sshbuf_len(ڪنجي->cert->critical) == 0)
		لکو("(none)\n");
	وإلا {
		لکو("\n");
		show_options(ڪنجي->cert->critical, 1);
	}
	لکو("        Extensions: ");
	إذا (sshbuf_len(ڪنجي->cert->extensions) == 0)
		لکو("(none)\n");
	وإلا {
		لکو("\n");
		show_options(ڪنجي->cert->extensions, 0);
	}
	حرر(ڪنجي_fp);
	حرر(ca_fp);
}

ساكن فراغ
do_show_cert(بنية passwd *pw)
{
	بنية sshkey *ڪنجي = عدم;
	بنية stat st;
	صحيح r, is_stdin = 0, ok = 0;
	FILE *f;
	حرف *cp, *سٽ = عدم;
	ثابت حرف *رستو;
	سائيز_t linesize = 0;
	u_long lnum = 0;

	إذا (!have_سڃاڻپ_عنصر)
		ask_filename(pw, "Enter file in which the key is");
	إذا (strcmp(سڃاڻپ_عنصر_file, "-") != 0 && stat(سڃاڻپ_عنصر_file, &st) == -1)
		fatal("%s: %s: %s", __progname, سڃاڻپ_عنصر_file, strerror(errno));

	رستو = سڃاڻپ_عنصر_file;
	إذا (strcmp(رستو, "-") == 0) {
		f = stdin;
		رستو = "(stdin)";
		is_stdin = 1;
	} وإلا إذا ((f = fopen(سڃاڻپ_عنصر_file, "r")) == عدم)
		fatal("fopen %s: %s", سڃاڻپ_عنصر_file, strerror(errno));

	طالما (getline(&سٽ, &linesize, f) != -1) {
		lnum++;
		sshkey_free(ڪنجي);
		ڪنجي = عدم;
		/* Trim leading space and comments */
		cp = سٽ + strspn(سٽ, " \t");
		إذا (*cp == '#' || *cp == '\0')
			استمر;
		إذا ((ڪنجي = sshkey_new(ڪنجي_UNSPEC)) == عدم)
			fatal("sshkey_new");
		إذا ((r = sshkey_read(ڪنجي, &cp)) != 0) {
			error_r(r, "%s:%lu: invalid key", رستو, lnum);
			استمر;
		}
		إذا (!sshkey_is_cert(ڪنجي)) {
			error("%s:%lu is not a certificate", رستو, lnum);
			استمر;
		}
		ok = 1;
		إذا (!is_stdin && lnum == 1)
			لکو("%s:\n", رستو);
		وإلا
			لکو("%s:%lu:\n", رستو, lnum);
		print_cert(ڪنجي);
	}
	حرر(سٽ);
	sshkey_free(ڪنجي);
	fclose(f);
	ٻاهر_نڪرو(ok ? 0 : 1);
}

ساكن فراغ
ڀريو_krl(ثابت حرف *رستو, بنية ssh_krl **krlp)
{
	بنية sshbuf *krlbuf;
	صحيح r;

	إذا ((r = sshbuf_ڀريو_file(رستو, &krlbuf)) != 0)
		fatal_r(r, "Unable to load KRL %s", رستو);
	/* XXX check sigs */
	إذا ((r = ssh_krl_from_blob(krlbuf, krlp)) != 0 ||
	    *krlp == عدم)
		fatal_r(r, "Invalid KRL file %s", رستو);
	sshbuf_free(krlbuf);
}

ساكن فراغ
hash_منزل_blob(ثابت حرف *cp, u_char **blobp, سائيز_t *lenp,
    ثابت حرف *file, u_long lnum)
{
	حرف *tmp;
	سائيز_t tlen;
	بنية sshbuf *b;
	صحيح r;

	إذا ((cp = strprefix(cp, "SHA256:", 0)) == عدم)
		fatal("%s:%lu: unsupported hash algorithm", file, lnum);

	/*
	 * OpenSSH base64 hashes omit trailing '='
	 * characters; put them back for decode.
	 */
	إذا ((tlen = لڙي_ڊيگهه(cp)) >= SIZE_MAX - 5)
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
	يادگيري_نقل(*blobp, sshbuf_ptr(b), *lenp);
	sshbuf_free(b);
}

ساكن فراغ
update_krl_from_file(بنية passwd *pw, ثابت حرف *file, صحيح wild_ca,
    ثابت بنية sshkey *ca, بنية ssh_krl *krl)
{
	بنية sshkey *ڪنجي = عدم;
	u_long lnum = 0;
	حرف *رستو, *cp, *ep, *سٽ = عدم;
	u_char *blob = عدم;
	سائيز_t blen = 0, linesize = 0;
	بنانشان ڊگهو ڊگهو serial, serial2;
	صحيح i, was_explicit_ڪنجي, was_sha1, was_sha256, was_hash, r;
	FILE *krl_spec;

	رستو = tilde_expand_filename(file, pw->pw_uid);
	إذا (strcmp(رستو, "-") == 0) {
		krl_spec = stdin;
		حرر(رستو);
		رستو = xstrdup("(standard input)");
	} وإلا إذا ((krl_spec = fopen(رستو, "r")) == عدم)
		fatal("fopen %s: %s", رستو, strerror(errno));

	إذا (!quiet)
		لکو("Revoking from %s\n", رستو);
	طالما (getline(&سٽ, &linesize, krl_spec) != -1) {
		إذا (linesize >= وڌ_کان_وڌ_عدد) {
			fatal_f("%s contains unparsable line, len=%zu",
			    رستو, linesize);
		}
		lnum++;
		was_explicit_ڪنجي = was_sha1 = was_sha256 = was_hash = 0;
		cp = سٽ + strspn(سٽ, " \t");
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
				    رستو, lnum, cp);
			إذا (errno == ERANGE && serial == ULLONG_MAX)
				fatal("%s:%lu: serial out of range",
				    رستو, lnum);
			serial2 = serial;
			إذا (*ep == '-') {
				cp = ep + 1;
				errno = 0;
				serial2 = strtoull(cp, &ep, 0);
				إذا (*cp == '\0' || *ep != '\0')
					fatal("%s:%lu: invalid serial \"%s\"",
					    رستو, lnum, cp);
				إذا (errno == ERANGE && serial2 == ULLONG_MAX)
					fatal("%s:%lu: serial out of range",
					    رستو, lnum);
				إذا (serial2 <= serial)
					fatal("%s:%lu: invalid serial range "
					    "%llu:%llu", رستو, lnum,
					    (بنانشان ڊگهو ڊگهو)serial,
					    (بنانشان ڊگهو ڊگهو)serial2);
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
			إذا (ssh_krl_revoke_cert_by_ڪنجي_id(krl, ca, cp) != 0)
				fatal_f("revoke key ID failed");
		} وإلا إذا (strncasecmp(cp, "hash:", 5) == 0) {
			cp += 5;
			cp = cp + strspn(cp, " \t");
			hash_منزل_blob(cp, &blob, &blen, file, lnum);
			إذا ((r = ssh_krl_revoke_ڪنجي_sha256(krl,
			    blob, blen)) != 0)
				fatal_fr(r, "revoke key failed");
			حرر(blob);
			blob = عدم;
			blen = 0;
		} وإلا {
			إذا (strncasecmp(cp, "key:", 4) == 0) {
				cp += 4;
				cp = cp + strspn(cp, " \t");
				was_explicit_ڪنجي = 1;
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
			إذا ((ڪنجي = sshkey_new(ڪنجي_UNSPEC)) == عدم)
				fatal("sshkey_new");
			إذا ((r = sshkey_read(ڪنجي, &cp)) != 0)
				fatal_r(r, "%s:%lu: invalid key", رستو, lnum);
			إذا (was_explicit_ڪنجي)
				r = ssh_krl_revoke_ڪنجي_explicit(krl, ڪنجي);
			وإلا إذا (was_sha1) {
				إذا (sshkey_fingerprint_raw(ڪنجي,
				    SSH_DIGEST_SHA1, &blob, &blen) != 0) {
					fatal("%s:%lu: fingerprint failed",
					    file, lnum);
				}
				r = ssh_krl_revoke_ڪنجي_sha1(krl, blob, blen);
			} وإلا إذا (was_sha256) {
				إذا (sshkey_fingerprint_raw(ڪنجي,
				    SSH_DIGEST_SHA256, &blob, &blen) != 0) {
					fatal("%s:%lu: fingerprint failed",
					    file, lnum);
				}
				r = ssh_krl_revoke_ڪنجي_sha256(krl, blob, blen);
			} وإلا
				r = ssh_krl_revoke_ڪنجي(krl, ڪنجي);
			إذا (r != 0)
				fatal_fr(r, "revoke key failed");
			freezero(blob, blen);
			blob = عدم;
			blen = 0;
			sshkey_free(ڪنجي);
		}
	}
	إذا (strcmp(رستو, "-") != 0)
		fclose(krl_spec);
	حرر(سٽ);
	حرر(رستو);
}

ساكن فراغ
do_gen_krl(بنية passwd *pw, صحيح updating, ثابت حرف *ca_ڪنجي_رستو,
    بنانشان ڊگهو ڊگهو krl_نسخو, ثابت حرف *krl_comment,
    صحيح argc, حرف **argv)
{
	بنية ssh_krl *krl;
	بنية stat sb;
	بنية sshkey *ca = عدم;
	صحيح i, r, wild_ca = 0;
	حرف *tmp;
	بنية sshbuf *kbuf;

	إذا (*سڃاڻپ_عنصر_file == '\0')
		fatal("KRL generation requires an output file");
	إذا (stat(سڃاڻپ_عنصر_file, &sb) == -1) {
		إذا (errno != ENOENT)
			fatal("Cannot access KRL \"%s\": %s",
			    سڃاڻپ_عنصر_file, strerror(errno));
		إذا (updating)
			fatal("KRL \"%s\" does not exist", سڃاڻپ_عنصر_file);
	}
	إذا (ca_ڪنجي_رستو != عدم) {
		إذا (strcasecmp(ca_ڪنجي_رستو, "none") == 0)
			wild_ca = 1;
		وإلا {
			tmp = tilde_expand_filename(ca_ڪنجي_رستو, pw->pw_uid);
			إذا ((r = sshkey_ڀريو_عوامي(tmp, &ca, عدم)) != 0)
				fatal_r(r, "Cannot load CA public key %s", tmp);
			حرر(tmp);
		}
	}

	إذا (updating)
		ڀريو_krl(سڃاڻپ_عنصر_file, &krl);
	وإلا إذا ((krl = ssh_krl_init()) == عدم)
		fatal("couldn't create KRL");

	إذا (krl_نسخو != 0)
		ssh_krl_سيٽ_نسخو(krl, krl_نسخو);
	إذا (krl_comment != عدم)
		ssh_krl_سيٽ_comment(krl, krl_comment);

	لكل (i = 0; i < argc; i++)
		update_krl_from_file(pw, argv[i], wild_ca, ca, krl);

	إذا ((kbuf = sshbuf_new()) == عدم)
		fatal("sshbuf_new failed");
	إذا (ssh_krl_منزل_blob(krl, kbuf) != 0)
		fatal("Couldn't generate KRL");
	إذا ((r = sshbuf_write_file(سڃاڻپ_عنصر_file, kbuf)) != 0)
		fatal("write %s: %s", سڃاڻپ_عنصر_file, strerror(errno));
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

	إذا (*سڃاڻپ_عنصر_file == '\0')
		fatal("KRL checking requires an input file");
	ڀريو_krl(سڃاڻپ_عنصر_file, &krl);
	إذا (print_krl)
		krl_dump(krl, stdout);
	لكل (i = 0; i < argc; i++) {
		إذا ((r = sshkey_ڀريو_عوامي(argv[i], &k, &comment)) != 0)
			fatal_r(r, "Cannot load public key %s", argv[i]);
		r = ssh_krl_check_ڪنجي(krl, k);
		لکو("%s%s%s%s: %s\n", argv[i],
		    *comment ? " (" : "", comment, *comment ? ")" : "",
		    r == 0 ? "ok" : "REVOKED");
		إذا (r != 0)
			ret = 1;
		sshkey_free(k);
		حرر(comment);
	}
	ssh_krl_free(krl);
	ٻاهر_نڪرو(ret);
}

ساكن بنية sshkey *
ڀريو_sign_ڪنجي(ثابت حرف *keypath, ثابت بنية sshkey *pubkey)
{
	سائيز_t i, slen, plen = لڙي_ڊيگهه(keypath);
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
		slen = لڙي_ڊيگهه(suffixes[i]);
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
	إذا ((r = sshkey_ڀريو_ذاتي(privpath, "", &privkey, عدم)) != 0 &&
	    (r != SSH_ERR_ڪنجي_WRONG_PASSPHRASE)) {
		debug_fr(r, "load private key \"%s\"", privpath);
		fatal("No private key found for \"%s\"", privpath);
	} وإلا إذا (privkey == عدم)
		privkey = ڀريو_سڃاڻپ_عنصر(privpath, عدم);

	إذا (!sshkey_equal_عوامي(pubkey, privkey)) {
		error("Public key %s doesn't match private %s",
		    keypath, privpath);
		اذهب پورو;
	}
	إذا (sshkey_is_cert(pubkey) && !sshkey_is_cert(privkey)) {
		/*
		 * Graft the certificate onto the private key to make
		 * it capable of signing.
		 */
		إذا ((r = sshkey_منزل_certified(privkey)) != 0) {
			error_fr(r, "sshkey_to_certified");
			اذهب پورو;
		}
		إذا ((r = sshkey_cert_copy(pubkey, privkey)) != 0) {
			error_fr(r, "sshkey_cert_copy");
			اذهب پورو;
		}
	}
	/* success */
	ret = privkey;
	privkey = عدم;
 پورو:
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
	صحيح r = SSH_ERR_اندروني_ERROR, wfd = -1, oerrno;
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
		اذهب ٻاهريون;
	}
	إذا ((r = sshsig_armor(sigbuf, &abuf)) != 0) {
		error_fr(r, "sshsig_armor");
		اذهب ٻاهريون;
	}
	إذا ((asig = sshbuf_dup_string(abuf)) == عدم) {
		error_f("buffer error");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب ٻاهريون;
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
				اذهب ٻاهريون;
			}
			إذا (atomicio(vwrite, wfd, asig,
			    لڙي_ڊيگهه(asig)) != لڙي_ڊيگهه(asig)) {
				oerrno = errno;
				error("Cannot write to %s: %s",
				    wfile, strerror(errno));
				errno = oerrno;
				r = SSH_ERR_SYSTEM_ERROR;
				اذهب ٻاهريون;
			}
			إذا (!quiet) {
				fprintf(stderr, "Write signature to %s\n",
				    wfile);
			}
		}
	}
	/* success */
	r = 0;
 ٻاهريون:
	حرر(wfile);
	حرر(prompt);
	حرر(asig);
	إذا (pin != عدم)
		freezero(pin, لڙي_ڊيگهه(pin));
	sshbuf_free(abuf);
	sshbuf_free(sigbuf);
	إذا (wfd != -1)
		close(wfd);
	أرجع r;
}

ساكن صحيح
sig_process_opts(حرف * ثابت *opts, سائيز_t nopts, حرف **hashalgp,
    uint64_t *verify_timep, صحيح *print_pubkey)
{
	سائيز_t i;
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
			إذا (parse_absolute_وقت(p, verify_timep) != 0 ||
			    *verify_timep == 0) {
				error("Invalid \"verify-time\" option");
				أرجع SSH_ERR_INVALID_دليل;
			}
		} وإلا إذا (print_pubkey &&
		    strcasecmp(opts[i], "print-pubkey") == 0) {
			*print_pubkey = 1;
		} وإلا {
			error("Invalid option \"%s\"", opts[i]);
			أرجع SSH_ERR_INVALID_دليل;
		}
	}
	إذا (verify_timep && *verify_timep == 0) {
		إذا ((now = time(عدم)) < 0) {
			error("Time is before epoch");
			أرجع SSH_ERR_INVALID_دليل;
		}
		*verify_timep = (uint64_t)now;
	}
	أرجع 0;
}


ساكن صحيح
sig_sign(ثابت حرف *keypath, ثابت حرف *sig_namespace, صحيح require_agent,
    صحيح argc, حرف **argv, حرف * ثابت *opts, سائيز_t nopts)
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
		اذهب پورو; /* error already logged */

	إذا ((r = sshkey_ڀريو_عوامي(keypath, &pubkey, عدم)) != 0) {
		error_r(r, "Couldn't load public key %s", keypath);
		اذهب پورو;
	}

	إذا ((r = ssh_get_authentication_socket(&agent_fd)) != 0) {
		إذا (require_agent)
			fatal("Couldn't get agent socket");
		debug_r(r, "Couldn't get agent socket");
	} وإلا {
		إذا ((r = ssh_agent_has_ڪنجي(agent_fd, pubkey)) == 0)
			signer = agent_signer;
		وإلا {
			إذا (require_agent)
				fatal("Couldn't find key in agent");
			debug_r(r, "Couldn't find key in agent");
		}
	}

	إذا (signer == عدم) {
		/* Not using agent - try to load private key */
		إذا ((privkey = ڀريو_sign_ڪنجي(keypath, pubkey)) == عدم)
			اذهب پورو;
		signkey = privkey;
	} وإلا {
		/* Will use key in agent */
		signkey = pubkey;
	}

	إذا (argc == 0) {
		إذا ((r = sign_one(signkey, "(stdin)", STDIN_FILENO,
		    sig_namespace, hashalg, signer, &agent_fd)) != 0)
			اذهب پورو;
	} وإلا {
		لكل (i = 0; i < argc; i++) {
			إذا (strcmp(argv[i], "-") == 0)
				fd = STDIN_FILENO;
			وإلا إذا ((fd = open(argv[i], O_RDONLY)) == -1) {
				error("Cannot open %s for signing: %s",
				    argv[i], strerror(errno));
				اذهب پورو;
			}
			إذا ((r = sign_one(signkey, argv[i], fd, sig_namespace,
			    hashalg, signer, &agent_fd)) != 0)
				اذهب پورو;
			إذا (fd != STDIN_FILENO)
				close(fd);
			fd = -1;
		}
	}

	ret = 0;
پورو:
	إذا (fd != -1 && fd != STDIN_FILENO)
		close(fd);
	sshkey_free(pubkey);
	sshkey_free(privkey);
	حرر(hashalg);
	أرجع ret;
}

ساكن صحيح
sig_verify(ثابت حرف *signature, ثابت حرف *sig_namespace,
    ثابت حرف *principal, ثابت حرف *allowed_ڪنجيون, ثابت حرف *revoked_ڪنجيون,
    حرف * ثابت *opts, سائيز_t nopts)
{
	صحيح r, ret = -1;
	صحيح print_pubkey = 0;
	بنية sshbuf *sigbuf = عدم, *abuf = عدم;
	بنية sshkey *sign_ڪنجي = عدم;
	حرف *fp = عدم;
	بنية sshkey_sig_details *sig_details = عدم;
	uint64_t verify_وقت = 0;

	إذا (sig_process_opts(opts, nopts, عدم, &verify_وقت,
	    &print_pubkey) != 0)
		اذهب پورو; /* error already logged */

	memset(&sig_details, 0, حجم(sig_details));
	إذا ((r = sshbuf_ڀريو_file(signature, &abuf)) != 0) {
		error_r(r, "Couldn't read signature file");
		اذهب پورو;
	}

	إذا ((r = sshsig_dearmor(abuf, &sigbuf)) != 0) {
		error_fr(r, "sshsig_armor");
		اذهب پورو;
	}
	إذا ((r = sshsig_verify_fd(sigbuf, STDIN_FILENO, sig_namespace,
	    &sign_ڪنجي, &sig_details)) != 0)
		اذهب پورو; /* sshsig_verify() prints error */

	إذا ((fp = sshkey_fingerprint(sign_ڪنجي, fingerprint_hash,
	    SSH_FP_DEFAULT)) == عدم)
		fatal_f("sshkey_fingerprint failed");
	debug("Valid (unverified) signature from key %s", fp);
	إذا (sig_details != عدم) {
		debug2_f("signature details: counter = %u, flags = 0x%02x",
		    sig_details->sk_counter, sig_details->sk_flags);
	}
	حرر(fp);
	fp = عدم;

	إذا (revoked_ڪنجيون != عدم) {
		إذا ((r = sshkey_check_revoked(sign_ڪنجي, revoked_ڪنجيون)) != 0) {
			debug3_fr(r, "sshkey_check_revoked");
			اذهب پورو;
		}
	}

	إذا (allowed_ڪنجيون != عدم && (r = sshsig_check_allowed_ڪنجيون(allowed_ڪنجيون,
	    sign_ڪنجي, principal, sig_namespace, verify_وقت)) != 0) {
		debug3_fr(r, "sshsig_check_allowed_keys");
		اذهب پورو;
	}
	/* success */
	ret = 0;
پورو:
	إذا (!quiet) {
		إذا (ret == 0) {
			إذا ((fp = sshkey_fingerprint(sign_ڪنجي, fingerprint_hash,
			    SSH_FP_DEFAULT)) == عدم)
				fatal_f("sshkey_fingerprint failed");
			إذا (principal == عدم) {
				لکو("Good \"%s\" signature with %s key %s\n",
				    sig_namespace, sshkey_type(sign_ڪنجي), fp);

			} وإلا {
				لکو("Good \"%s\" signature for %s with %s key %s\n",
				    sig_namespace, principal,
				    sshkey_type(sign_ڪنجي), fp);
			}
		} وإلا {
			لکو("Could not verify signature.\n");
		}
	}
	/* Print the signature key if requested */
	إذا (ret == 0 && print_pubkey && sign_ڪنجي != عدم) {
		إذا ((r = sshkey_write(sign_ڪنجي, stdout)) == 0)
			fputc('\n', stdout);
		وإلا {
			error_r(r, "Could not print public key.\n");
			ret = -1;
		}
	}
	sshbuf_free(sigbuf);
	sshbuf_free(abuf);
	sshkey_free(sign_ڪنجي);
	sshkey_sig_details_free(sig_details);
	حرر(fp);
	أرجع ret;
}

ساكن صحيح
sig_ڳوليو_principals(ثابت حرف *signature, ثابت حرف *allowed_ڪنجيون,
    حرف * ثابت *opts, سائيز_t nopts)
{
	صحيح r, ret = -1;
	بنية sshbuf *sigbuf = عدم, *abuf = عدم;
	بنية sshkey *sign_ڪنجي = عدم;
	حرف *principals = عدم, *cp, *tmp;
	uint64_t verify_وقت = 0;

	إذا (sig_process_opts(opts, nopts, عدم, &verify_وقت, عدم) != 0)
		اذهب پورو; /* error already logged */

	إذا ((r = sshbuf_ڀريو_file(signature, &abuf)) != 0) {
		error_r(r, "Couldn't read signature file");
		اذهب پورو;
	}
	إذا ((r = sshsig_dearmor(abuf, &sigbuf)) != 0) {
		error_fr(r, "sshsig_armor");
		اذهب پورو;
	}
	إذا ((r = sshsig_get_pubkey(sigbuf, &sign_ڪنجي)) != 0) {
		error_fr(r, "sshsig_get_pubkey");
		اذهب پورو;
	}
	إذا ((r = sshsig_ڳوليو_principals(allowed_ڪنجيون, sign_ڪنجي,
	    verify_وقت, &principals)) != 0) {
		إذا (r != SSH_ERR_ڪنجي_NOT_مليو)
			error_fr(r, "sshsig_find_principal");
		اذهب پورو;
	}
	ret = 0;
پورو:
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
	sshkey_free(sign_ڪنجي);
	حرر(principals);
	أرجع ret;
}

ساكن صحيح
sig_ميلاپ_principals(ثابت حرف *allowed_ڪنجيون, حرف *principal,
	حرف * ثابت *opts, سائيز_t nopts)
{
	صحيح r;
	حرف **principals = عدم;
	سائيز_t i, nprincipals = 0;

	إذا ((r = sig_process_opts(opts, nopts, عدم, عدم, عدم)) != 0)
		أرجع r; /* error already logged */

	إذا ((r = sshsig_ميلاپ_principals(allowed_ڪنجيون, principal,
	    &principals, &nprincipals)) != 0) {
		debug_f("match: %s", ssh_err(r));
		fprintf(stderr, "No principal matched.\n");
		أرجع r;
	}
	لكل (i = 0; i < nprincipals; i++) {
		لکو("%s\n", principals[i]);
		حرر(principals[i]);
	}
	حرر(principals);

	أرجع 0;
}

ساكن فراغ
do_moduli_gen(ثابت حرف *ٻاهريون_file, حرف **opts, سائيز_t nopts)
{
#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
	/* Moduli generation/screening */
	BIGNUM *شروعات = عدم;
	صحيح moduli_بٽ = 0;
	FILE *ٻاهريون;
	سائيز_t i;
	ثابت حرف *errstr, *p;

	/* Parse options */
	لكل (i = 0; i < nopts; i++) {
		إذا ((p = strprefix(opts[i], "start=", 0)) != عدم) {
			/* XXX - also compare length against bits */
			إذا (BN_hex2bn(&شروعات, p) == 0)
				fatal("Invalid start point.");
		} وإلا إذا ((p = strprefix(opts[i], "bits=", 0)) != عدم) {
			moduli_بٽ = (صحيح)strtonum(p, 1, وڌ_کان_وڌ_عدد, &errstr);
			إذا (errstr) {
				fatal("Invalid number: %s (%s)", p, errstr);
			}
		} وإلا {
			fatal("Option \"%s\" is unsupported for moduli "
			    "generation", opts[i]);
		}
	}

	إذا (strcmp(ٻاهريون_file, "-") == 0)
		ٻاهريون = stdout;
	وإلا إذا ((ٻاهريون = fopen(ٻاهريون_file, "w")) == عدم) {
		fatal("Couldn't open modulus candidate file \"%s\": %s",
		    ٻاهريون_file, strerror(errno));
	}
	setvbuf(ٻاهريون, عدم, _IOLBF, 0);

	إذا (moduli_بٽ == 0)
		moduli_بٽ = DEFAULT_بٽ;
	إذا (gen_candidates(ٻاهريون, moduli_بٽ, شروعات) != 0)
		fatal("modulus candidate generation failed");
#وإلا /* WITH_OPENSSL */
	fatal("Moduli generation is not supported");
#جيڪڏهن_پورو /* WITH_OPENSSL */
}

ساكن فراغ
do_moduli_screen(ثابت حرف *ٻاهريون_file, حرف **opts, سائيز_t nopts)
{
#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
	/* Moduli generation/screening */
	حرف *checkpoint = عدم;
	uint32_t generator_wanted = 0;
	بنانشان ڊگهو شروعات_lineno = 0, سٽون_منزل_process = 0;
	صحيح مفرد_tests = 0;
	FILE *ٻاهريون, *اندريون = stdin;
	سائيز_t i;
	ثابت حرف *errstr, *p;

	/* Parse options */
	لكل (i = 0; i < nopts; i++) {
		إذا ((p = strprefix(opts[i], "lines=", 0)) != عدم) {
			سٽون_منزل_process = strtoul(p, عدم, 10);
		} وإلا إذا ((p = strprefix(opts[i], "start-line=", 0)) != عدم) {
			شروعات_lineno = strtoul(p, عدم, 10);
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
			مفرد_tests = (صحيح)strtonum(p, 1, وڌ_کان_وڌ_عدد, &errstr);
			إذا (errstr) {
				fatal("Invalid number: %s (%s)", p, errstr);
			}
		} وإلا {
			fatal("Option \"%s\" is unsupported for moduli "
			    "screening", opts[i]);
		}
	}

	إذا (have_سڃاڻپ_عنصر && strcmp(سڃاڻپ_عنصر_file, "-") != 0) {
		إذا ((اندريون = fopen(سڃاڻپ_عنصر_file, "r")) == عدم) {
			fatal("Couldn't open modulus candidate "
			    "file \"%s\": %s", سڃاڻپ_عنصر_file,
			    strerror(errno));
		}
	}

	إذا (strcmp(ٻاهريون_file, "-") == 0)
		ٻاهريون = stdout;
	وإلا إذا ((ٻاهريون = fopen(ٻاهريون_file, "a")) == عدم) {
		fatal("Couldn't open moduli file \"%s\": %s",
		    ٻاهريون_file, strerror(errno));
	}
	setvbuf(ٻاهريون, عدم, _IOLBF, 0);
	إذا (مفرد_test(اندريون, ٻاهريون, مفرد_tests == 0 ? 100 : مفرد_tests,
	    generator_wanted, checkpoint,
	    شروعات_lineno, سٽون_منزل_process) != 0)
		fatal("modulus screening failed");
	إذا (اندريون != stdin)
		(فراغ)fclose(اندريون);
	حرر(checkpoint);
#وإلا /* WITH_OPENSSL */
	fatal("Moduli screening is not supported");
#جيڪڏهن_پورو /* WITH_OPENSSL */
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
			freezero(passphrase2, لڙي_ڊيگهه(passphrase2));
			أرجع passphrase1;
		}
		/* The passphrases do not match. Clear them and retry. */
		freezero(passphrase1, لڙي_ڊيگهه(passphrase1));
		freezero(passphrase2, لڙي_ڊيگهه(passphrase2));
		fputs(retry_prompt, stdout);
		fputc('\n', stdout);
		fflush(stdout);
	}
	/* NOTREACHED */
	أرجع عدم;
}

ساكن حرف *
ذاتي_ڪنجي_passphrase(ثابت حرف *رستو)
{
	حرف *prompt, *ret;

	إذا (سڃاڻپ_عنصر_passphrase)
		أرجع xstrdup(سڃاڻپ_عنصر_passphrase);
	إذا (سڃاڻپ_عنصر_new_passphrase)
		أرجع xstrdup(سڃاڻپ_عنصر_new_passphrase);

	xasprintf(&prompt, "Enter passphrase for \"%s\" "
	    "(empty for no passphrase): ", رستو);
	ret = read_check_passphrase(prompt,
	    "Enter same passphrase again: ",
	    "Passphrases do not match.  Try again.");
	حرر(prompt);
	أرجع ret;
}

ساكن حرف *
sk_suffix(ثابت حرف *application, ثابت uint8_t *user, سائيز_t userlen)
{
	حرف *ret, *cp;
	ثابت حرف *p;
	سائيز_t slen, i;

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
	إذا (asmprintf(&cp, وڌ_کان_وڌ_عدد, عدم, "%.*s", (صحيح)slen, user) == -1)
		fatal_f("asmprintf failed");
	/* Don't emit a user-id that contains path or control characters */
	إذا (strchr(cp, '/') != عدم || لڙي_ڳولا(cp, "..") != عدم ||
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
	بنية sshsk_resident_ڪنجي **srks;
	سائيز_t nsrks, i;
	صحيح r, ret = -1;
	حرف *fp, *pin = عدم, *pass = عدم, *رستو, *pubpath;
	ثابت حرف *ext;
	بنية sshkey *ڪنجي;

	إذا (skprovider == عدم)
		fatal("Cannot download keys without provider");

	pin = read_passphrase("Enter PIN for authenticator: ", RP_ALLOW_STDIN);
	إذا (!quiet) {
		لکو("You may need to touch your authenticator "
		    "to authorize key download.\n");
	}
	إذا ((r = sshsk_ڀريو_resident(skprovider, device, pin, 0,
	    &srks, &nsrks)) != 0) {
		إذا (pin != عدم)
			freezero(pin, لڙي_ڊيگهه(pin));
		error_r(r, "Unable to load resident keys");
		أرجع -1;
	}
	إذا (nsrks == 0)
		logit("No keys to download");
	إذا (pin != عدم)
		freezero(pin, لڙي_ڊيگهه(pin));

	لكل (i = 0; i < nsrks; i++) {
		ڪنجي = srks[i]->ڪنجي;
		إذا (ڪنجي->type != ڪنجي_ECDSA_SK && ڪنجي->type != ڪنجي_ED25519_SK) {
			error("Unsupported key type %s (%d)",
			    sshkey_type(ڪنجي), ڪنجي->type);
			استمر;
		}
		إذا ((fp = sshkey_fingerprint(ڪنجي, fingerprint_hash,
		    SSH_FP_DEFAULT)) == عدم)
			fatal_f("sshkey_fingerprint failed");
		debug_f("key %zu: %s %s %s (flags 0x%02x)", i,
		    sshkey_type(ڪنجي), fp, ڪنجي->sk_application, ڪنجي->sk_flags);
		ext = sk_suffix(ڪنجي->sk_application,
		    srks[i]->user_id, srks[i]->user_id_len);
		xasprintf(&رستو, "id_%s_rk%s%s",
		    ڪنجي->type == ڪنجي_ECDSA_SK ? "ecdsa_sk" : "ed25519_sk",
		    *ext == '\0' ? "" : "_", ext);

		/* If the file already exists, ask the user to confirm. */
		إذا (!confirm_overwrite(رستو)) {
			حرر(رستو);
			اكسر;
		}

		/* Save the key with the application string as the comment */
		إذا (pass == عدم)
			pass = ذاتي_ڪنجي_passphrase(رستو);
		إذا ((r = sshkey_save_ذاتي(ڪنجي, رستو, pass,
		    ڪنجي->sk_application, ذاتي_ڪنجي_format,
		    openssh_format_cipher, ڦيرا)) != 0) {
			error_r(r, "Saving key \"%s\" failed", رستو);
			حرر(رستو);
			اكسر;
		}
		إذا (!quiet) {
			لکو("Saved %s key%s%s to %s\n", sshkey_type(ڪنجي),
			    *ext != '\0' ? " " : "",
			    *ext != '\0' ? ڪنجي->sk_application : "",
			    رستو);
		}

		/* Save public key too */
		xasprintf(&pubpath, "%s.pub", رستو);
		حرر(رستو);
		إذا ((r = sshkey_save_عوامي(ڪنجي, pubpath,
		    ڪنجي->sk_application)) != 0) {
			error_r(r, "Saving public key \"%s\" failed", pubpath);
			حرر(pubpath);
			اكسر;
		}
		حرر(pubpath);
	}

	إذا (i >= nsrks)
		ret = 0; /* success */
	إذا (pass != عدم)
		freezero(pass, لڙي_ڊيگهه(pass));
	sshsk_free_resident_ڪنجيون(srks, nsrks);
	أرجع ret;
}

ساكن فراغ
save_attestation(بنية sshbuf *attest, ثابت حرف *رستو)
{
	گهڻائي_t omask;
	صحيح r;

	إذا (رستو == عدم)
		أرجع; /* nothing to do */
	إذا (attest == عدم || sshbuf_len(attest) == 0)
		fatal("Enrollment did not return attestation data");
	omask = umask(077);
	r = sshbuf_write_file(رستو, attest);
	umask(omask);
	إذا (r != 0)
		fatal_r(r, "Unable to write attestation data \"%s\"", رستو);
	إذا (!quiet)
		لکو("Your FIDO attestation certificate has been saved in "
		    "%s\n", رستو);
}

ساكن صحيح
confirm_sk_overwrite(ثابت حرف *application, ثابت حرف *user)
{
	حرف yesno[3];

	لکو("A resident key scoped to '%s' with user id '%s' already "
	    "exists.\n", application == عدم ? "ssh:" : application,
	    user == عدم ? "null" : user);
	لکو("Overwrite key in token (y/n)? ");
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
#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
	    "       ssh-keygen -i [-f input_keyfile] [-m key_format]\n"
	    "       ssh-keygen -e [-f input_keyfile] [-m key_format]\n"
#جيڪڏهن_پورو
	    "       ssh-keygen -y [-f input_keyfile]\n"
	    "       ssh-keygen -c [-a rounds] [-C comment] [-f keyfile] [-P passphrase]\n"
	    "       ssh-keygen -l [-v] [-E fingerprint_hash] [-f input_keyfile]\n"
	    "       ssh-keygen -B [-f input_keyfile]\n");
#جيڪڏهن_وصف_ٿيل ENABLE_PKCS11
	fprintf(stderr,
	    "       ssh-keygen -D pkcs11\n");
#جيڪڏهن_پورو
	fprintf(stderr,
	    "       ssh-keygen -F hostname [-lv] [-f known_hosts_file]\n"
	    "       ssh-keygen -H [-f known_hosts_file]\n"
	    "       ssh-keygen -K [-a rounds] [-w provider]\n"
	    "       ssh-keygen -R hostname [-f known_hosts_file]\n"
	    "       ssh-keygen -r hostname [-g] [-f input_keyfile]\n"
#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
	    "       ssh-keygen -M generate [-O option] output_file\n"
	    "       ssh-keygen -M screen [-f input_file] [-O option] output_file\n"
#جيڪڏهن_پورو
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
	ٻاهر_نڪرو(1);
}

/*
 * Main program for key management.
 */
صحيح
مکيه(صحيح argc, حرف **argv)
{
	حرف comment[ڪنجي_COMMENT_MAX], *passphrase = عدم;
	حرف *rr_hostname = عدم, *ep, *fp, *ra;
	بنية sshkey *خاص = عدم, *عام = عدم;
	بنية passwd *pw;
	صحيح ret = 0, r, opt, type;
	صحيح change_passphrase = 0, change_comment = 0, show_cert = 0;
	صحيح ڳوليو_host = 0, delete_host = 0, hash_hosts = 0;
	صحيح gen_all_hostkeys = 0, gen_krl = 0, update_krl = 0, check_krl = 0;
	صحيح prefer_agent = 0, convert_منزل = 0, convert_from = 0;
	صحيح print_عوامي = 0, print_generic = 0, cert_serial_autoinc = 0;
	صحيح do_gen_candidates = 0, do_screen_candidates = 0, download_sk = 0;
	بنانشان ڊگهو ڊگهو cert_serial = 0;
	حرف *سڃاڻپ_عنصر_comment = عدم, *ca_ڪنجي_رستو = عدم, **opts = عدم;
	حرف *sk_application = عدم, *sk_device = عدم, *sk_user = عدم;
	حرف *sk_attestation_رستو = عدم;
	بنية sshbuf *challenge = عدم, *attest = عدم;
	سائيز_t i, nopts = 0;
	uint32_t بٽ = 0;
	uint8_t sk_flags = SSH_SK_USER_PRESENCE_REQD;
	ثابت حرف *errstr, *p;
	صحيح log_level = SYSLOG_LEVEL_INFO;
	حرف *sign_op = عدم;

	خارجي صحيح optind;
	خارجي حرف *optarg;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	__progname = ssh_get_progname(argv[0]);

	ٻج_rng();

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
			بٽ = (uint32_t)strtonum(optarg, 1, UINT32_MAX,
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
			ڳوليو_host = 1;
			rr_hostname = optarg;
			اكسر;
		حالة 'H':
			hash_hosts = 1;
			اكسر;
		حالة 'I':
			cert_ڪنجي_id = optarg;
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
				ذاتي_ڪنجي_format = SSHKEY_ذاتي_PKCS8;
				اكسر;
			}
			إذا (strcasecmp(optarg, "PEM") == 0) {
				convert_format = FMT_PEM;
				ذاتي_ڪنجي_format = SSHKEY_ذاتي_PEM;
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
			إذا (strlcpy(سڃاڻپ_عنصر_file, optarg,
			    حجم(سڃاڻپ_عنصر_file)) >= حجم(سڃاڻپ_عنصر_file))
				fatal("Identity filename too long");
			have_سڃاڻپ_عنصر = 1;
			اكسر;
		حالة 'g':
			print_generic = 1;
			اكسر;
		حالة 'K':
			download_sk = 1;
			اكسر;
		حالة 'P':
			سڃاڻپ_عنصر_passphrase = optarg;
			اكسر;
		حالة 'N':
			سڃاڻپ_عنصر_new_passphrase = optarg;
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
			سڃاڻپ_عنصر_comment = optarg;
			اكسر;
		حالة 'q':
			quiet = 1;
			اكسر;
		حالة 'e':
			/* export key */
			convert_منزل = 1;
			اكسر;
		حالة 'h':
			cert_ڪنجي_type = SSH2_CERT_TYPE_HOST;
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
			print_عوامي = 1;
			اكسر;
		حالة 's':
			ca_ڪنجي_رستو = optarg;
			اكسر;
		حالة 't':
			ڪنجي_type_name = optarg;
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
			ڦيرا = (صحيح)strtonum(optarg, 1, وڌ_کان_وڌ_عدد, &errstr);
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

#جيڪڏهن_وصف_ٿيل ENABLE_SK_اندروني
	إذا (sk_provider == عدم)
		sk_provider = "internal";
#جيڪڏهن_پورو

	/* reinit */
	log_init(argv[0], log_level, SYSLOG_FACILITY_USER, 1);

	argv += optind;
	argc -= optind;

	إذا (sign_op != عدم) {
		إذا (strprefix(sign_op, "find-principals", 0) != عدم) {
			إذا (ca_ڪنجي_رستو == عدم) {
				error("Too few arguments for find-principals:"
				    "missing signature file");
				ٻاهر_نڪرو(1);
			}
			إذا (!have_سڃاڻپ_عنصر) {
				error("Too few arguments for find-principals:"
				    "missing allowed keys file");
				ٻاهر_نڪرو(1);
			}
			ret = sig_ڳوليو_principals(ca_ڪنجي_رستو, سڃاڻپ_عنصر_file,
			    opts, nopts);
			اذهب پورو;
		} وإلا إذا (strprefix(sign_op, "match-principals", 0) != عدم) {
			إذا (!have_سڃاڻپ_عنصر) {
				error("Too few arguments for match-principals:"
				    "missing allowed keys file");
				ٻاهر_نڪرو(1);
			}
			إذا (cert_ڪنجي_id == عدم) {
				error("Too few arguments for match-principals: "
				    "missing principal ID");
				ٻاهر_نڪرو(1);
			}
			ret = sig_ميلاپ_principals(سڃاڻپ_عنصر_file, cert_ڪنجي_id,
			    opts, nopts);
			اذهب پورو;
		} وإلا إذا (strprefix(sign_op, "sign", 0) != عدم) {
			/* NB. cert_principals is actually namespace, via -n */
			إذا (cert_principals == عدم ||
			    *cert_principals == '\0') {
				error("Too few arguments for sign: "
				    "missing namespace");
				ٻاهر_نڪرو(1);
			}
			إذا (!have_سڃاڻپ_عنصر) {
				error("Too few arguments for sign: "
				    "missing key");
				ٻاهر_نڪرو(1);
			}
			ret = sig_sign(سڃاڻپ_عنصر_file, cert_principals,
			    prefer_agent, argc, argv, opts, nopts);
			اذهب پورو;
		} وإلا إذا (strprefix(sign_op, "check-novalidate", 0) != عدم) {
			/* NB. cert_principals is actually namespace, via -n */
			إذا (cert_principals == عدم ||
			    *cert_principals == '\0') {
				error("Too few arguments for check-novalidate: "
				    "missing namespace");
				ٻاهر_نڪرو(1);
			}
			إذا (ca_ڪنجي_رستو == عدم) {
				error("Too few arguments for check-novalidate: "
				    "missing signature file");
				ٻاهر_نڪرو(1);
			}
			ret = sig_verify(ca_ڪنجي_رستو, cert_principals,
			    عدم, عدم, عدم, opts, nopts);
			اذهب پورو;
		} وإلا إذا (strprefix(sign_op, "verify", 0) != عدم) {
			/* NB. cert_principals is actually namespace, via -n */
			إذا (cert_principals == عدم ||
			    *cert_principals == '\0') {
				error("Too few arguments for verify: "
				    "missing namespace");
				ٻاهر_نڪرو(1);
			}
			إذا (ca_ڪنجي_رستو == عدم) {
				error("Too few arguments for verify: "
				    "missing signature file");
				ٻاهر_نڪرو(1);
			}
			إذا (!have_سڃاڻپ_عنصر) {
				error("Too few arguments for sign: "
				    "missing allowed keys file");
				ٻاهر_نڪرو(1);
			}
			إذا (cert_ڪنجي_id == عدم) {
				error("Too few arguments for verify: "
				    "missing principal identity");
				ٻاهر_نڪرو(1);
			}
			ret = sig_verify(ca_ڪنجي_رستو, cert_principals,
			    cert_ڪنجي_id, سڃاڻپ_عنصر_file, rr_hostname,
			    opts, nopts);
			اذهب پورو;
		}
		error("Unsupported operation for -Y: \"%s\"", sign_op);
		usage();
		/* NOTREACHED */
	}

	إذا (ca_ڪنجي_رستو != عدم) {
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
		do_gen_krl(pw, update_krl, ca_ڪنجي_رستو,
		    cert_serial, سڃاڻپ_عنصر_comment, argc, argv);
		اذهب پورو;
	}
	إذا (check_krl) {
		do_check_krl(pw, print_fingerprint, argc, argv);
		اذهب پورو;
	}
	إذا (ca_ڪنجي_رستو != عدم) {
		إذا (cert_ڪنجي_id == عدم)
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
			جوڙيو_cert_option(opts[i]);
		do_ca_sign(pw, ca_ڪنجي_رستو, prefer_agent,
		    cert_serial, cert_serial_autoinc, argc, argv);
		اذهب پورو;
	}
	إذا (show_cert)
		do_show_cert(pw);
	إذا (delete_host || hash_hosts || ڳوليو_host) {
		do_معلوم_hosts(pw, rr_hostname, ڳوليو_host,
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
		اذهب پورو;
	}
	إذا (print_fingerprint || print_bubblebabble)
		do_fingerprint(pw);
	إذا (change_passphrase)
		do_change_passphrase(pw, opts, nopts);
	إذا (change_comment)
		do_change_comment(pw, سڃاڻپ_عنصر_comment);
#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
	إذا (convert_منزل) {
		do_convert_منزل(pw);
		اذهب پورو;
	}
	إذا (convert_from) {
		do_convert_from(pw);
		اذهب پورو;
	}
#وإلا /* WITH_OPENSSL */
	إذا (convert_منزل || convert_from)
		fatal("key conversion disabled at compile time");
#جيڪڏهن_پورو /* WITH_OPENSSL */
	إذا (print_عوامي)
		do_print_عوامي(pw);
	إذا (rr_hostname != عدم) {
		بنانشان صحيح n = 0;

		إذا (have_سڃاڻپ_عنصر) {
			n = do_print_resource_رڪارڊ(pw, سڃاڻپ_عنصر_file,
			    rr_hostname, print_generic, opts, nopts);
			إذا (n == 0)
				fatal("%s: %s", سڃاڻپ_عنصر_file, strerror(errno));
			ٻاهر_نڪرو(0);
		} وإلا {

			n += do_print_resource_رڪارڊ(pw,
			    رستو_HOST_RSA_ڪنجي_FILE, rr_hostname,
			    print_generic, opts, nopts);
			n += do_print_resource_رڪارڊ(pw,
			    رستو_HOST_ECDSA_ڪنجي_FILE, rr_hostname,
			    print_generic, opts, nopts);
			n += do_print_resource_رڪارڊ(pw,
			    رستو_HOST_ED25519_ڪنجي_FILE, rr_hostname,
			    print_generic, opts, nopts);
			إذا (n == 0)
				fatal("no keys found.");
			ٻاهر_نڪرو(0);
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
		اذهب پورو;
	}
	إذا (do_screen_candidates) {
		do_moduli_screen(argv[0], opts, nopts);
		اذهب پورو;
	}

	إذا (gen_all_hostkeys) {
		do_gen_all_hostkeys(pw);
		اذهب پورو;
	}

	إذا (ڪنجي_type_name == عدم)
		ڪنجي_type_name = DEFAULT_ڪنجي_TYPE_NAME;

	type = sshkey_type_from_shortname(ڪنجي_type_name);
	type_بٽ_valid(type, ڪنجي_type_name, &بٽ);

	إذا (!quiet)
		لکو("Generating public/private %s key pair.\n",
		    ڪنجي_type_name);
	بدل (type) {
	حالة ڪنجي_ECDSA_SK:
	حالة ڪنجي_ED25519_SK:
		لكل (i = 0; i < nopts; i++) {
			إذا (strcasecmp(opts[i], "no-touch-required") == 0) {
				sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
			} وإلا إذا (strcasecmp(opts[i], "verify-required") == 0) {
				sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
			} وإلا إذا (strcasecmp(opts[i], "resident") == 0) {
				sk_flags |= SSH_SK_RESIDENT_ڪنجي;
			} وإلا إذا ((p = strprefix(opts[i], "device=", 1))
			    != عدم ) {
				sk_device = xstrdup(p);
			} وإلا إذا ((p = strprefix(opts[i], "user=", 1))
			    != عدم) {
				sk_user = xstrdup(p);
			} وإلا إذا ((p = strprefix(opts[i], "challenge=", 1))
			    != عدم) {
				إذا ((r = sshbuf_ڀريو_file(p,
				    &challenge)) != 0) {
					fatal_r(r, "Unable to load FIDO "
					    "enrollment challenge \"%s\"", p);
				}
			} وإلا إذا (strncasecmp(opts[i],
			    "write-attestation=", 18) == 0) {
				sk_attestation_رستو = opts[i] + 18;
			} وإلا إذا (strncasecmp(opts[i],
			    "application=", 12) == 0) {
				sk_application = xstrdup(opts[i] + 12);
				إذا (لڙي_ڀيٽ(sk_application, "ssh:", 4) != 0) {
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
				لکو("You may need to touch your "
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
			إذا (r == SSH_ERR_ڪنجي_BAD_PERMISSIONS &&
			    (sk_flags & SSH_SK_RESIDENT_ڪنجي) != 0 &&
			    (sk_flags & SSH_SK_FORCE_OPERATION) == 0 &&
			    confirm_sk_overwrite(sk_application, sk_user)) {
				sk_flags |= SSH_SK_FORCE_OPERATION;
				استمر;
			}
			إذا (r != SSH_ERR_ڪنجي_WRONG_PASSPHRASE)
				fatal_r(r, "Key enrollment failed");
			وإلا إذا (passphrase != عدم) {
				error("PIN incorrect");
				freezero(passphrase, لڙي_ڊيگهه(passphrase));
				passphrase = عدم;
			}
			إذا (++i >= 3)
				fatal("Too many incorrect PINs");
			passphrase = read_passphrase("Enter PIN for "
			    "authenticator: ", RP_ALLOW_STDIN);
		}
		إذا (passphrase != عدم) {
			freezero(passphrase, لڙي_ڊيگهه(passphrase));
			passphrase = عدم;
		}
		اكسر;
	افتراضي:
		إذا ((r = sshkey_generate(type, بٽ, &خاص)) != 0)
			fatal("sshkey_generate failed");
		اكسر;
	}
	إذا ((r = sshkey_from_ذاتي(خاص, &عام)) != 0)
		fatal_r(r, "sshkey_from_private");

	إذا (!have_سڃاڻپ_عنصر)
		ask_filename(pw, "Enter file in which to save the key");

	/* Create ~/.ssh directory if it doesn't already exist. */
	hostfile_create_user_ssh_dir(سڃاڻپ_عنصر_file, !quiet);

	/* If the file already exists, ask the user to confirm. */
	إذا (!confirm_overwrite(سڃاڻپ_عنصر_file))
		ٻاهر_نڪرو(1);

	/* Determine the passphrase for the private key */
	passphrase = ذاتي_ڪنجي_passphrase(سڃاڻپ_عنصر_file);
	إذا (سڃاڻپ_عنصر_comment) {
		strlcpy(comment, سڃاڻپ_عنصر_comment, حجم(comment));
	} وإلا {
		/* Create default comment field for the passphrase. */
		snprintf(comment, حجم comment, "%s@%s", pw->pw_name, hostname);
	}



	/* Save the key with the given passphrase and comment. */
	إذا ((r = sshkey_save_ذاتي(خاص, سڃاڻپ_عنصر_file, passphrase,
	    comment, ذاتي_ڪنجي_format, openssh_format_cipher, ڦيرا)) != 0) {
		error_r(r, "Saving key \"%s\" failed", سڃاڻپ_عنصر_file);
		freezero(passphrase, لڙي_ڊيگهه(passphrase));
		ٻاهر_نڪرو(1);
	}
	freezero(passphrase, لڙي_ڊيگهه(passphrase));
	sshkey_free(خاص);

	إذا (!quiet) {
		لکو("Your identification has been saved in %s\n",
		    سڃاڻپ_عنصر_file);
	}

	strlcat(سڃاڻپ_عنصر_file, ".pub", حجم(سڃاڻپ_عنصر_file));
	إذا ((r = sshkey_save_عوامي(عام, سڃاڻپ_عنصر_file, comment)) != 0)
		fatal_r(r, "Unable to save public key to %s", سڃاڻپ_عنصر_file);

	إذا (!quiet) {
		fp = sshkey_fingerprint(عام, fingerprint_hash,
		    SSH_FP_DEFAULT);
		ra = sshkey_fingerprint(عام, fingerprint_hash,
		    SSH_FP_RANDOMART);
		إذا (fp == عدم || ra == عدم)
			fatal("sshkey_fingerprint failed");
		لکو("Your public key has been saved in %s\n",
		    سڃاڻپ_عنصر_file);
		لکو("The key fingerprint is:\n");
		لکو("%s %s\n", fp, comment);
		لکو("The key's randomart image is:\n");
		لکو("%s\n", ra);
		حرر(ra);
		حرر(fp);
	}

	إذا (sk_attestation_رستو != عدم)
		save_attestation(attest, sk_attestation_رستو);

 پورو:
	sshbuf_free(attest);
	sshkey_free(عام);
	pwfree(pw);
	ٻاهر_نڪرو(ret);
}
