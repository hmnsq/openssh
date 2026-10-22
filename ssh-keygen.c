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

#که_تعریف_شوی WITH_OPENSSL
#ضمن "openbsd-compat/openssl-compat.h"
#ضمن <openssl/bn.h>
#ضمن <openssl/evp.h>
#ضمن <openssl/pem.h>
#د_که_پای

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

#که_تعریف_شوی ENABLE_PKCS11
#ضمن "ssh-pkcs11.h"
#د_که_پای

#تعریف_کړه DEFAULT_کلی_TYPE_NAME "ed25519"

/*
 * Default number of bits in the RSA and ECDSA keys.  These value can be
 * overridden on the command line.
 *
 * These values provide security equivalent to at least 128 bits of security
 * according to NIST Special Publication 800-57: Recommendation for Key
 * Management Part 1 rev 4 section 5.6.1.
 */
#تعریف_کړه DEFAULT_بټونه		3072
#تعریف_کړه DEFAULT_بټونه_ECDSA	256

#تعریف_کړه کلی_COMMENT_MAX		(NI_MAXHOST + 1024)

ساكن صحيح quiet = 0;

/* Flag indicating that we just want to see the key fingerprint */
ساكن صحيح print_fingerprint = 0;
ساكن صحيح print_bubblebabble = 0;

/* Hash algorithm to use for fingerprints. */
ساكن صحيح fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* The identity file name, given on the command line or entered by the user. */
ساكن حرف بې_اغېزه_عنصر_file[PATH_MAX];
ساكن صحيح have_بې_اغېزه_عنصر = 0;

/* This is set to the passphrase if given on the command line. */
ساكن حرف *بې_اغېزه_عنصر_passphrase = عدم;

/* This is set to the new passphrase if given on the command line. */
ساكن حرف *بې_اغېزه_عنصر_new_passphrase = عدم;

/* Key type when certifying */
ساكن u_int cert_کلی_type = SSH2_CERT_TYPE_USER;

/* "key ID" of signed key */
ساكن حرف *cert_کلی_id = عدم;

/* Comma-separated list of principal names for certifying keys */
ساكن حرف *cert_principals = عدم;

/* Validity period for certificates */
ساكن uint64_t cert_valid_from = 0;
ساكن uint64_t cert_valid_منزل = ~0ULL;

/* Certificate options */
#تعریف_کړه CERTOPT_X_FWD				(1)
#تعریف_کړه CERTOPT_AGENT_FWD			(1<<1)
#تعریف_کړه CERTOPT_پورټ_FWD			(1<<2)
#تعریف_کړه CERTOPT_PTY				(1<<3)
#تعریف_کړه CERTOPT_USER_RC				(1<<4)
#تعریف_کړه CERTOPT_NO_REQUIRE_USER_PRESENCE	(1<<5)
#تعریف_کړه CERTOPT_REQUIRE_VERIFY			(1<<6)
#تعریف_کړه CERTOPT_DEFAULT	(CERTOPT_X_FWD|CERTOPT_AGENT_FWD| \
			 CERTOPT_پورټ_FWD|CERTOPT_PTY|CERTOPT_USER_RC)
ساكن uint32_t certflags_flags = CERTOPT_DEFAULT;
ساكن حرف *certflags_command = عدم;
ساكن حرف *certflags_src_addr = عدم;

/* Arbitrary extensions specified by user */
بنية cert_ext {
	حرف *کلی;
	حرف *val;
	صحيح crit;
};
ساكن بنية cert_ext *cert_ext;
ساكن اندازه_t ncert_ext;

/* Conversion to/from various formats */
تعداد {
	FMT_RFC4716,
	FMT_PKCS8,
	FMT_PEM,
	FMT_HEXDUMP
} convert_format = FMT_RFC4716;

ساكن حرف *کلی_type_name = عدم;

/* Load key from this PKCS#11 provider */
ساكن حرف *pkcs11provider = عدم;

/* FIDO/U2F provider to use */
ساكن حرف *sk_provider = عدم;

/* Format for writing private keys */
ساكن صحيح شخصي_کلی_format = SSHKEY_شخصي_OPENSSH;

/* Cipher for new-format private keys */
ساكن حرف *openssh_format_cipher = عدم;

/* Number of KDF rounds to derive new format keys. */
ساكن صحيح پړاوونه = 0;

/* argv0 */
خارجي حرف *__progname;

ساكن حرف hostname[NI_MAXHOST];

#که_تعریف_شوی WITH_OPENSSL
/* moduli.c */
صحيح gen_candidates(FILE *, uint32_t, BIGNUM *);
صحيح اولي_test(FILE *, FILE *, uint32_t, uint32_t, حرف *, بینښه اوږد,
    بینښه اوږد);
#د_که_پای

ساكن فراغ
type_بټونه_valid(صحيح type, ثابت حرف *name, uint32_t *bitsp)
{
	إذا (type == کلی_UNSPEC)
		fatal("unknown key type %s", کلی_type_name);
	إذا (*bitsp == 0) {
#که_تعریف_شوی WITH_OPENSSL
		صحيح nid;

		بدل(type) {
		حالة کلی_ECDSA:
			إذا (name != عدم &&
			    (nid = sshkey_ecdsa_nid_from_name(name)) > 0)
				*bitsp = sshkey_منحني_nid_منزل_بټونه(nid);
			إذا (*bitsp == 0)
				*bitsp = DEFAULT_بټونه_ECDSA;
			اكسر;
		حالة کلی_RSA:
			*bitsp = DEFAULT_بټونه;
			اكسر;
		}
#د_که_پای
	}
#که_تعریف_شوی WITH_OPENSSL
	بدل (type) {
	حالة کلی_RSA:
		إذا (*bitsp < SSH_RSA_MINIMUM_MODULUS_اندازه)
			fatal("Invalid RSA key length: minimum is %d bits",
			    SSH_RSA_MINIMUM_MODULUS_اندازه);
		وإلا إذا (*bitsp > OPENSSL_RSA_MAX_MODULUS_بټونه)
			fatal("Invalid RSA key length: maximum is %d bits",
			    OPENSSL_RSA_MAX_MODULUS_بټونه);
		اكسر;
	حالة کلی_ECDSA:
		إذا (sshkey_ecdsa_بټونه_منزل_nid(*bitsp) == -1)
			fatal("Invalid ECDSA key length: valid lengths are "
			    "256, 384 or 521 bits");
	}
#د_که_پای
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
	چاپ_کړه("%s already exists.\n", filename);
	چاپ_کړه("Overwrite (y/n)? ");
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

	إذا (کلی_type_name == عدم)
		name = لار_SSH_CLIENT_ID_ED25519;
	وإلا {
		بدل (sshkey_type_from_shortname(کلی_type_name)) {
		حالة کلی_ECDSA_CERT:
		حالة کلی_ECDSA:
			name = لار_SSH_CLIENT_ID_ECDSA;
			اكسر;
		حالة کلی_ECDSA_SK_CERT:
		حالة کلی_ECDSA_SK:
			name = لار_SSH_CLIENT_ID_ECDSA_SK;
			اكسر;
		حالة کلی_RSA_CERT:
		حالة کلی_RSA:
			name = لار_SSH_CLIENT_ID_RSA;
			اكسر;
		حالة کلی_ED25519:
		حالة کلی_ED25519_CERT:
			name = لار_SSH_CLIENT_ID_ED25519;
			اكسر;
		حالة کلی_ED25519_SK:
		حالة کلی_ED25519_SK_CERT:
			name = لار_SSH_CLIENT_ID_ED25519_SK;
			اكسر;
		حالة کلی_MLDSA44_ED25519:
		حالة کلی_MLDSA44_ED25519_CERT:
			name = لار_SSH_CLIENT_ID_MLDSA44_ED25519;
			اكسر;
		افتراضي:
			fatal("bad key type");
		}
	}
	snprintf(بې_اغېزه_عنصر_file, حجم(بې_اغېزه_عنصر_file),
	    "%s/%s", pw->pw_dir, name);
	چاپ_کړه("%s (%s): ", prompt, بې_اغېزه_عنصر_file);
	fflush(stdout);
	إذا (fgets(buf, حجم(buf), stdin) == عدم)
		وتل(1);
	buf[strcspn(buf, "\n")] = '\0';
	إذا (strcmp(buf, "") != 0)
		strlcpy(بې_اغېزه_عنصر_file, buf, حجم(بې_اغېزه_عنصر_file));
	have_بې_اغېزه_عنصر = 1;
}

ساكن بنية sshkey *
بارول_بې_اغېزه_عنصر(ثابت حرف *filename, حرف **commentp)
{
	حرف *prompt, *pass;
	بنية sshkey *prv;
	صحيح r;

	إذا (commentp != عدم)
		*commentp = عدم;
	إذا ((r = sshkey_بارول_شخصي(filename, "", &prv, commentp)) == 0)
		أرجع prv;
	إذا (r != SSH_ERR_کلی_WRONG_PASSPHRASE)
		fatal_r(r, "Load key \"%s\"", filename);
	إذا (بې_اغېزه_عنصر_passphrase)
		pass = xstrdup(بې_اغېزه_عنصر_passphrase);
	وإلا {
		xasprintf(&prompt, "Enter passphrase for \"%s\": ", filename);
		pass = read_passphrase(prompt, RP_ALLOW_STDIN);
		حرر(prompt);
	}
	r = sshkey_بارول_شخصي(filename, pass, &prv, commentp);
	freezero(pass, مزي_اوږدوالی(pass));
	إذا (r != 0)
		fatal_r(r, "Load key \"%s\"", filename);
	أرجع prv;
}

#تعریف_کړه SSH_COM_عامه_BEGIN		"---- BEGIN SSH2 PUBLIC KEY ----"
#تعریف_کړه SSH_COM_عامه_پای_ټکی		"---- END SSH2 PUBLIC KEY ----"
#تعریف_کړه SSH_COM_شخصي_BEGIN		"---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----"
#تعریف_کړه	SSH_COM_شخصي_کلی_MAGIC	0x3f6ff9eb

#که_تعریف_شوی WITH_OPENSSL
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
	    sshkey_اندازه(k), sshkey_type(k),
	    pw->pw_name, hostname);

	sshkey_free(k);
	sshbuf_free(b);

	fprintf(stdout, "%s\n", SSH_COM_عامه_BEGIN);
	fprintf(stdout, "Comment: \"%s\"\n%s", comment, b64);
	fprintf(stdout, "%s\n", SSH_COM_عامه_پای_ټکی);
	حرر(b64);
}

ساكن فراغ
do_convert_منزل_pkcs8(بنية sshkey *k)
{
	بدل (sshkey_type_plain(k->type)) {
	حالة کلی_RSA:
		إذا (!PEM_write_RSA_PUBKEY(stdout,
		    EVP_PKEY_get0_RSA(k->pkey)))
			fatal("PEM_write_RSA_PUBKEY failed");
		اكسر;
	حالة کلی_ECDSA:
		إذا (!PEM_write_EC_PUBKEY(stdout,
		    EVP_PKEY_get0_EC_کلی(k->pkey)))
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
	حالة کلی_RSA:
		إذا (!PEM_write_RSAPublic_کلی(stdout,
		    EVP_PKEY_get0_RSA(k->pkey)))
			fatal("PEM_write_RSAPublicKey failed");
		اكسر;
	حالة کلی_ECDSA:
		إذا (!PEM_write_EC_PUBKEY(stdout,
		    EVP_PKEY_get0_EC_کلی(k->pkey)))
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
	چاپ_کړه("Public %s key:\n", sshkey_type(k));
	sshbuf_dump(b, stdout);
	sshbuf_reset(b);
	إذا ((r = sshkey_شخصي_serialize(k, b)) != 0) {
		debug_fr(r, "serialise private");
		اذهب بهر;
	}
	چاپ_کړه("\nPrivate %s key:\n", sshkey_type(k));
	sshbuf_dump(b, stdout);
 بهر:
	sshbuf_free(b);
}

ساكن فراغ
do_convert_منزل(بنية passwd *pw)
{
	بنية sshkey *k = عدم;
	بنية stat st;
	صحيح r;

	إذا (!have_بې_اغېزه_عنصر)
		ask_filename(pw, "Enter file in which the key is");
	إذا (stat(بې_اغېزه_عنصر_file, &st) == -1)
		fatal("%s: %s: %s", __progname, بې_اغېزه_عنصر_file, strerror(errno));

	/* If we're trying to hexdump, then prefer the private key */
	إذا (convert_format == FMT_HEXDUMP) {
		إذا ((r = sshkey_بارول_شخصي(بې_اغېزه_عنصر_file,
		    عدم, &k, عدم)) != 0 &&
		    r == SSH_ERR_کلی_WRONG_PASSPHRASE)
			k = بارول_بې_اغېزه_عنصر(بې_اغېزه_عنصر_file, عدم);
	}
	إذا (k == عدم && (r = sshkey_بارول_عامه(بې_اغېزه_عنصر_file, &k, عدم)) != 0)
		k = بارول_بې_اغېزه_عنصر(بې_اغېزه_عنصر_file, عدم);

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
بفر_get_bignum_بټونه(بنية sshbuf *b, BIGNUM *ارزښت)
{
	u_int بایټونه, bignum_بټونه;
	صحيح r;

	إذا ((r = sshbuf_get_u32(b, &bignum_بټونه)) != 0)
		fatal_fr(r, "parse");
	بایټونه = (bignum_بټونه + 7) / 8;
	إذا (sshbuf_len(b) < بایټونه)
		fatal_f("input buffer too small: need %d have %zu",
		    بایټونه, sshbuf_len(b));
	إذا (BN_bin2bn(sshbuf_ptr(b), بایټونه, ارزښت) == عدم)
		fatal_f("BN_bin2bn failed");
	إذا ((r = sshbuf_consume(b, بایټونه)) != 0)
		fatal_fr(r, "consume");
}

ساكن بنية sshkey *
do_convert_شخصي_ssh2(بنية sshbuf *b)
{
	بنية sshkey *کلی = عدم;
	حرف *type, *cipher;
	ثابت حرف *alg = عدم;
	u_char e1, e2, e3, *sig = عدم, معلومات[] = "abcde12345";
	صحيح r, rlen, ktype;
	u_int magic, i1, i2, i3, i4;
	اندازه_t slen;
	u_long e;
	BIGNUM *rsa_n = عدم, *rsa_e = عدم, *rsa_d = عدم;
	BIGNUM *rsa_p = عدم, *rsa_q = عدم, *rsa_iqmp = عدم;
	BIGNUM *rsa_dmp1 = عدم, *rsa_dmq1 = عدم;
	RSA *rsa = عدم;

	إذا ((r = sshbuf_get_u32(b, &magic)) != 0)
		fatal_fr(r, "parse magic");

	إذا (magic != SSH_COM_شخصي_کلی_MAGIC) {
		error("bad magic 0x%x != 0x%x", magic,
		    SSH_COM_شخصي_کلی_MAGIC);
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

	إذا (مزي_پلټنه(type, "rsa")) {
		ktype = کلی_RSA;
	} وإلا {
		حرر(type);
		أرجع عدم;
	}
	إذا ((کلی = sshkey_new(ktype)) == عدم)
		fatal("sshkey_new failed");
	حرر(type);

	بدل (کلی->type) {
	حالة کلی_RSA:
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
		إذا (!BN_سېټ_کلمه(rsa_e, e)) {
			BN_clear_free(rsa_e);
			sshkey_free(کلی);
			أرجع عدم;
		}
		إذا ((rsa_n = BN_new()) == عدم ||
		    (rsa_d = BN_new()) == عدم ||
		    (rsa_p = BN_new()) == عدم ||
		    (rsa_q = BN_new()) == عدم ||
		    (rsa_iqmp = BN_new()) == عدم)
			fatal_f("BN_new");
		بفر_get_bignum_بټونه(b, rsa_d);
		بفر_get_bignum_بټونه(b, rsa_n);
		بفر_get_bignum_بټونه(b, rsa_iqmp);
		بفر_get_bignum_بټونه(b, rsa_q);
		بفر_get_bignum_بټونه(b, rsa_p);
		إذا ((r = ssh_rsa_complete_crt_parameters(rsa_d, rsa_p, rsa_q,
		    rsa_iqmp, &rsa_dmp1, &rsa_dmq1)) != 0)
			fatal_fr(r, "generate RSA CRT parameters");
		EVP_PKEY_free(کلی->pkey);
		إذا ((کلی->pkey = EVP_PKEY_new()) == عدم)
			fatal_f("EVP_PKEY_new failed");
		إذا ((rsa = RSA_new()) == عدم)
			fatal_f("RSA_new failed");
		إذا (!RSA_set0_کلی(rsa, rsa_n, rsa_e, rsa_d))
			fatal_f("RSA_set0_key failed");
		rsa_n = rsa_e = rsa_d = عدم; /* transferred */
		إذا (!RSA_set0_factors(rsa, rsa_p, rsa_q))
			fatal_f("RSA_set0_factors failed");
		rsa_p = rsa_q = عدم; /* transferred */
		إذا (RSA_set0_crt_params(rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp) != 1)
			fatal_f("RSA_set0_crt_params failed");
		rsa_dmp1 = rsa_dmq1 = rsa_iqmp = عدم;
		إذا (EVP_PKEY_set1_RSA(کلی->pkey, rsa) != 1)
			fatal_f("EVP_PKEY_set1_RSA failed");
		RSA_free(rsa);
		alg = "rsa-sha2-256";
		اكسر;
	}
	rlen = sshbuf_len(b);
	إذا (rlen != 0)
		error_f("remaining bytes in key blob %d", rlen);

	/* try the key */
	إذا ((r = sshkey_sign(کلی, &sig, &slen, معلومات, حجم(معلومات),
	    alg, عدم, عدم, 0)) != 0)
		error_fr(r, "signing with converted key failed");
	وإلا إذا ((r = sshkey_verify(کلی, sig, slen, معلومات, حجم(معلومات),
	    alg, 0, عدم)) != 0)
		error_fr(r, "verification with converted key failed");
	إذا (r != 0) {
		sshkey_free(کلی);
		حرر(sig);
		أرجع عدم;
	}
	حرر(sig);
	أرجع کلی;
}

ساكن صحيح
get_کرښه(FILE *fp, حرف *کرښه, اندازه_t len)
{
	صحيح c;
	اندازه_t pos = 0;

	کرښه[0] = '\0';
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
		کرښه[pos++] = c;
		کرښه[pos] = '\0';
	}
	/* We reached EOF */
	أرجع -1;
}

ساكن فراغ
do_convert_from_ssh2(بنية passwd *pw, بنية sshkey **k, صحيح *خاص)
{
	صحيح r, blen, escaped = 0;
	u_int len;
	حرف کرښه[1024];
	بنية sshbuf *buf;
	حرف encoded[8096];
	FILE *fp;

	إذا ((buf = sshbuf_new()) == عدم)
		fatal("sshbuf_new failed");
	إذا ((fp = fopen(بې_اغېزه_عنصر_file, "r")) == عدم)
		fatal("%s: %s: %s", __progname, بې_اغېزه_عنصر_file, strerror(errno));
	encoded[0] = '\0';
	طالما ((blen = get_کرښه(fp, کرښه, حجم(کرښه))) != -1) {
		إذا (blen > 0 && کرښه[blen - 1] == '\\')
			escaped++;
		إذا (مزي_پرتله(کرښه, "----", 4) == 0 ||
		    مزي_پلټنه(کرښه, ": ") != عدم) {
			إذا (مزي_پلټنه(کرښه, SSH_COM_شخصي_BEGIN) != عدم)
				*خاص = 1;
			إذا (مزي_پلټنه(کرښه, " END ") != عدم) {
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
		strlcat(encoded, کرښه, حجم(encoded));
	}
	len = مزي_اوږدوالی(encoded);
	إذا (((len % 4) == 3) &&
	    (encoded[len-1] == '=') &&
	    (encoded[len-2] == '=') &&
	    (encoded[len-3] == '='))
		encoded[len-3] = '\0';
	إذا ((r = sshbuf_b64tod(buf, encoded)) != 0)
		fatal_fr(r, "base64 decode");
	إذا (*خاص) {
		إذا ((*k = do_convert_شخصي_ssh2(buf)) == عدم)
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

	إذا ((fp = fopen(بې_اغېزه_عنصر_file, "r")) == عدم)
		fatal("%s: %s: %s", __progname, بې_اغېزه_عنصر_file, strerror(errno));
	إذا ((pubkey = PEM_read_PUBKEY(fp, عدم, عدم, عدم)) == عدم) {
		fatal_f("%s is not a recognised public key format",
		    بې_اغېزه_عنصر_file);
	}
	fclose(fp);
	بدل (EVP_PKEY_بنسټ_id(pubkey)) {
	حالة EVP_PKEY_RSA:
		إذا ((*k = sshkey_new(کلی_UNSPEC)) == عدم)
			fatal("sshkey_new failed");
		(*k)->type = کلی_RSA;
		(*k)->pkey = pubkey;
		pubkey = عدم;
		اكسر;
	حالة EVP_PKEY_EC:
		إذا ((*k = sshkey_new(کلی_UNSPEC)) == عدم)
			fatal("sshkey_new failed");
		إذا (((*k)->ecdsa_nid = sshkey_ecdsa_fixup_ډله(pubkey)) == -1)
			fatal("sshkey_ecdsa_fixup_group failed");
		(*k)->type = کلی_ECDSA;
		(*k)->pkey = pubkey;
		pubkey = عدم;
		اكسر;
	افتراضي:
		fatal_f("unsupported pubkey type %d",
		    EVP_PKEY_بنسټ_id(pubkey));
	}
	EVP_PKEY_free(pubkey);
}

ساكن فراغ
do_convert_from_pem(بنية sshkey **k, صحيح *خاص)
{
	FILE *fp;
	RSA *rsa;

	إذا ((fp = fopen(بې_اغېزه_عنصر_file, "r")) == عدم)
		fatal("%s: %s: %s", __progname, بې_اغېزه_عنصر_file, strerror(errno));
	إذا ((rsa = PEM_read_RSAPublic_کلی(fp, عدم, عدم, عدم)) != عدم) {
		إذا ((*k = sshkey_new(کلی_UNSPEC)) == عدم)
			fatal("sshkey_new failed");
		إذا (((*k)->pkey = EVP_PKEY_new()) == عدم)
			fatal("EVP_PKEY_new failed");
		(*k)->type = کلی_RSA;
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

	إذا (!have_بې_اغېزه_عنصر)
		ask_filename(pw, "Enter file in which the key is");
	إذا (stat(بې_اغېزه_عنصر_file, &st) == -1)
		fatal("%s: %s: %s", __progname, بې_اغېزه_عنصر_file, strerror(errno));

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
		حالة کلی_ECDSA:
			ok = PEM_write_ECPrivate_کلی(stdout,
			    EVP_PKEY_get0_EC_کلی(k->pkey), عدم, عدم, 0,
			    عدم, عدم);
			اكسر;
		حالة کلی_RSA:
			ok = PEM_write_RSAPrivate_کلی(stdout,
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
#د_که_پای

ساكن فراغ
do_print_عامه(بنية passwd *pw)
{
	بنية sshkey *prv;
	بنية stat st;
	صحيح r;
	حرف *comment = عدم;

	إذا (!have_بې_اغېزه_عنصر)
		ask_filename(pw, "Enter file in which the key is");
	إذا (stat(بې_اغېزه_عنصر_file, &st) == -1)
		fatal("%s: %s", بې_اغېزه_عنصر_file, strerror(errno));
	prv = بارول_بې_اغېزه_عنصر(بې_اغېزه_عنصر_file, &comment);
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
	وتل(0);
}

ساكن فراغ
do_download(بنية passwd *pw)
{
#که_تعریف_شوی ENABLE_PKCS11
	بنية sshkey **کلیګانې = عدم;
	صحيح i, nkeys;
	تعداد sshkey_fp_rep rep;
	صحيح fptype;
	حرف *fp, *ra, **comments = عدم;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;

	pkcs11_init(1);
	nkeys = pkcs11_جمع_کړه_provider(pkcs11provider, عدم, &کلیګانې, &comments);
	إذا (nkeys <= 0)
		fatal("cannot read public key from pkcs11");
	لكل (i = 0; i < nkeys; i++) {
		إذا (print_fingerprint) {
			fp = sshkey_fingerprint(کلیګانې[i], fptype, rep);
			ra = sshkey_fingerprint(کلیګانې[i], fingerprint_hash,
			    SSH_FP_RANDOMART);
			إذا (fp == عدم || ra == عدم)
				fatal_f("sshkey_fingerprint fail");
			چاپ_کړه("%u %s %s (PKCS11 key)\n", sshkey_اندازه(کلیګانې[i]),
			    fp, sshkey_type(کلیګانې[i]));
			إذا (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
				چاپ_کړه("%s\n", ra);
			حرر(ra);
			حرر(fp);
		} وإلا {
			(فراغ) sshkey_write(کلیګانې[i], stdout); /* XXX check */
			fprintf(stdout, "%s%s\n",
			    *(comments[i]) == '\0' ? "" : " ", comments[i]);
		}
		حرر(comments[i]);
		sshkey_free(کلیګانې[i]);
	}
	حرر(comments);
	حرر(کلیګانې);
	pkcs11_terminate();
	وتل(0);
#وإلا
	fatal("no pkcs11 support");
#د_که_پای /* ENABLE_PKCS11 */
}

ساكن بنية sshkey *
try_read_کلی(حرف **cpp)
{
	بنية sshkey *ret;
	صحيح r;

	إذا ((ret = sshkey_new(کلی_UNSPEC)) == عدم)
		fatal("sshkey_new failed");
	إذا ((r = sshkey_read(ret, cpp)) == 0)
		أرجع ret;
	/* Not a key */
	sshkey_free(ret);
	أرجع عدم;
}

ساكن فراغ
fingerprint_one_کلی(ثابت بنية sshkey *عام, ثابت حرف *comment)
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
	mprintf("%u %s %s (%s)\n", sshkey_اندازه(عام), fp,
	    comment ? comment : "no comment", sshkey_type(عام));
	إذا (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
		چاپ_کړه("%s\n", ra);
	حرر(ra);
	حرر(fp);
}

ساكن فراغ
fingerprint_شخصي(ثابت حرف *لار)
{
	بنية stat st;
	حرف *comment = عدم;
	بنية sshkey *privkey = عدم, *pubkey = عدم;
	صحيح r;

	إذا (stat(بې_اغېزه_عنصر_file, &st) == -1)
		fatal("%s: %s", لار, strerror(errno));
	إذا ((r = sshkey_بارول_عامه(لار, &pubkey, &comment)) != 0)
		debug_r(r, "load public \"%s\"", لار);
	إذا (pubkey == عدم || comment == عدم || *comment == '\0') {
		حرر(comment);
		إذا ((r = sshkey_بارول_شخصي(لار, عدم,
		    &privkey, &comment)) != 0)
			debug_r(r, "load private \"%s\"", لار);
	}
	إذا (pubkey == عدم && privkey == عدم)
		fatal("%s is not a key file.", لار);

	fingerprint_one_کلی(pubkey == عدم ? privkey : pubkey, comment);
	sshkey_free(pubkey);
	sshkey_free(privkey);
	حرر(comment);
}

ساكن فراغ
do_fingerprint(بنية passwd *pw)
{
	FILE *f;
	بنية sshkey *عام = عدم;
	حرف *comment = عدم, *cp, *ep, *کرښه = عدم;
	اندازه_t linesize = 0;
	صحيح i, invalid = 1;
	ثابت حرف *لار;
	u_long lnum = 0;

	إذا (!have_بې_اغېزه_عنصر)
		ask_filename(pw, "Enter file in which the key is");
	لار = بې_اغېزه_عنصر_file;

	إذا (strcmp(بې_اغېزه_عنصر_file, "-") == 0) {
		f = stdin;
		لار = "(stdin)";
	} وإلا إذا ((f = fopen(لار, "r")) == عدم)
		fatal("%s: %s: %s", __progname, لار, strerror(errno));

	طالما (getline(&کرښه, &linesize, f) != -1) {
		lnum++;
		cp = کرښه;
		cp[strcspn(cp, "\r\n")] = '\0';
		/* Trim leading space and comments */
		cp = کرښه + strspn(کرښه, " \t");
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
		إذا (lnum == 1 && strcmp(بې_اغېزه_عنصر_file, "-") != 0 &&
		    مزي_پلټنه(cp, "PRIVATE KEY") != عدم) {
			حرر(کرښه);
			fclose(f);
			fingerprint_شخصي(لار);
			وتل(0);
		}

		/*
		 * If it's not a private key, then this must be prepared to
		 * accept a public key prefixed with a hostname or options.
		 * Try a bare key first, otherwise skip the leading stuff.
		 */
		comment = عدم;
		إذا ((عام = try_read_کلی(&cp)) == عدم) {
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
		إذا (عام == عدم && (عام = try_read_کلی(&cp)) == عدم) {
			debug("%s:%lu: not a public key", لار, lnum);
			استمر;
		}

		/* Find trailing comment, if any */
		لكل (; *cp == ' ' || *cp == '\t'; cp++)
			;
		إذا (*cp != '\0' && *cp != '#')
			comment = cp;

		fingerprint_one_کلی(عام, comment);
		sshkey_free(عام);
		invalid = 0; /* One good key in the file is sufficient */
	}
	fclose(f);
	حرر(کرښه);

	إذا (invalid)
		fatal("%s is not a public key file.", لار);
	وتل(0);
}

ساكن فراغ
do_gen_all_hostkeys(بنية passwd *pw)
{
	بنية {
		حرف *کلی_type;
		حرف *کلی_type_display;
		حرف *لار;
	} کلی_types[] = {
#که_تعریف_شوی WITH_OPENSSL
		{ "rsa", "RSA" ,لار_HOST_RSA_کلی_FILE },
		{ "ecdsa", "ECDSA",لار_HOST_ECDSA_کلی_FILE },
#د_که_پای /* WITH_OPENSSL */
		{ "ed25519", "ED25519",لار_HOST_ED25519_کلی_FILE },
#که_تعریف_شوی USE_MLDSA
		{ "mldsa44-ed25519", "MLDSA44-ED25519",
		     لار_HOST_MLDSA44_ED25519_کلی_FILE },
#د_که_پای
		{ عدم, عدم, عدم }
	};

	uint32_t بټونه = 0;
	صحيح لومړی = 0;
	بنية stat st;
	بنية sshkey *خاص, *عام;
	حرف comment[کلی_COMMENT_MAX], *prv_tmp, *pub_tmp, *prv_file, *pub_file;
	صحيح i, type, fd, r;

	لكل (i = 0; کلی_types[i].کلی_type; i++) {
		عام = خاص = عدم;
		prv_tmp = pub_tmp = prv_file = pub_file = عدم;

		xasprintf(&prv_file, "%s%s",
		    بې_اغېزه_عنصر_file, کلی_types[i].لار);

		/* Check whether private key exists and is not zero-length */
		إذا (stat(prv_file, &st) == 0) {
			إذا (st.st_size != 0)
				اذهب بل;
		} وإلا إذا (errno != ENOENT) {
			error("Could not stat %s: %s", کلی_types[i].لار,
			    strerror(errno));
			اذهب failnext;
		}

		/*
		 * Private key doesn't exist or is invalid; proceed with
		 * key generation.
		 */
		xasprintf(&prv_tmp, "%s%s.XXXXXXXXXX",
		    بې_اغېزه_عنصر_file, کلی_types[i].لار);
		xasprintf(&pub_tmp, "%s%s.pub.XXXXXXXXXX",
		    بې_اغېزه_عنصر_file, کلی_types[i].لار);
		xasprintf(&pub_file, "%s%s.pub",
		    بې_اغېزه_عنصر_file, کلی_types[i].لار);

		إذا (لومړی == 0) {
			لومړی = 1;
			چاپ_کړه("%s: generating new host keys: ", __progname);
		}
		چاپ_کړه("%s ", کلی_types[i].کلی_type_display);
		fflush(stdout);
		type = sshkey_type_from_shortname(کلی_types[i].کلی_type);
		إذا ((fd = mkstemp(prv_tmp)) == -1) {
			error("Could not save your private key in %s: %s",
			    prv_tmp, strerror(errno));
			اذهب failnext;
		}
		(فراغ)close(fd); /* just using mkstemp() to reserve a name */
		بټونه = 0;
		type_بټونه_valid(type, عدم, &بټونه);
		إذا ((r = sshkey_generate(type, بټونه, &خاص)) != 0) {
			error_r(r, "sshkey_generate failed");
			اذهب failnext;
		}
		إذا ((r = sshkey_from_شخصي(خاص, &عام)) != 0)
			fatal_fr(r, "sshkey_from_private");
		snprintf(comment, حجم comment, "%s@%s", pw->pw_name,
		    hostname);
		إذا ((r = sshkey_save_شخصي(خاص, prv_tmp, "",
		    comment, شخصي_کلی_format, openssh_format_cipher,
		    پړاوونه)) != 0) {
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
		إذا ((r = sshkey_save_عامه(عام, pub_tmp, comment)) != 0) {
			error_r(r, "Unable to save public key to %s",
			    بې_اغېزه_عنصر_file);
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
			    کلی_types[i].لار, strerror(errno));
 failnext:
			لومړی = 0;
			اذهب بل;
		}
 بل:
		sshkey_free(خاص);
		sshkey_free(عام);
		حرر(prv_tmp);
		حرر(pub_tmp);
		حرر(prv_file);
		حرر(pub_file);
	}
	إذا (لومړی != 0)
		چاپ_کړه("\n");
}

بنية معلوم_hosts_ctx {
	ثابت حرف *host;	/* Hostname searched for in find/delete case */
	FILE *بهر;		/* Output file, stdout for find_hosts case */
	صحيح has_unhashed;	/* When hashing, original had unhashed hosts */
	صحيح وموندل_کلی;		/* For find/delete, host was found */
	صحيح invalid;		/* File contained invalid items; don't delete */
	صحيح hash_hosts;		/* Hash hostnames as we go */
	صحيح پیدا_کړه_host;		/* Search for specific hostname */
	صحيح delete_host;	/* Delete host from known_hosts */
};

ساكن صحيح
معلوم_hosts_hash(بنية hostkey_foreach_کرښه *l, فراغ *_ctx)
{
	بنية معلوم_hosts_ctx *ctx = (بنية معلوم_hosts_ctx *)_ctx;
	حرف *hashed, *cp, *hosts, *ohosts;
	صحيح has_wild = l->hosts && strcspn(l->hosts, "*?!") != مزي_اوږدوالی(l->hosts);
	صحيح was_hashed = l->hosts && l->hosts[0] == HASH_DELIM;

	بدل (l->حالت) {
	حالة HKF_حالت_OK:
	حالة HKF_حالت_MATCHED:
		/*
		 * Don't hash hosts already hashed, with wildcard
		 * characters or a CA/revocation marker.
		 */
		إذا (was_hashed || has_wild || l->marker != MRK_NONE) {
			fprintf(ctx->بهر, "%s\n", l->کرښه);
			إذا (has_wild && !ctx->پیدا_کړه_host) {
				logit("%s:%lu: ignoring host name "
				    "with wildcard: %.64s", l->لار,
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
			fprintf(ctx->بهر, "%s %s\n", hashed, l->rawkey);
			حرر(hashed);
			ctx->has_unhashed = 1;
		}
		حرر(ohosts);
		أرجع 0;
	حالة HKF_حالت_INVALID:
		/* Retain invalid lines, but mark file as invalid. */
		ctx->invalid = 1;
		logit("%s:%lu: invalid line", l->لار, l->linenum);
		/* FALLTHROUGH */
	افتراضي:
		fprintf(ctx->بهر, "%s\n", l->کرښه);
		أرجع 0;
	}
	/* NOTREACHED */
	أرجع -1;
}

ساكن صحيح
معلوم_hosts_پیدا_کړه_delete(بنية hostkey_foreach_کرښه *l, فراغ *_ctx)
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
				fprintf(ctx->بهر, "%s\n", l->کرښه);
			} وإلا {
				/*
				 * Hostname matches and has no CA/revoke
				 * marker, delete it by *not* writing the
				 * line to ctx->out.
				 */
				ctx->وموندل_کلی = 1;
				إذا (!quiet)
					چاپ_کړه("# Host %s found: line %lu\n",
					    ctx->host, l->linenum);
			}
			أرجع 0;
		} وإلا إذا (ctx->پیدا_کړه_host) {
			ctx->وموندل_کلی = 1;
			إذا (!quiet) {
				چاپ_کړه("# Host %s found: line %lu %s\n",
				    ctx->host,
				    l->linenum, l->marker == MRK_CA ? "CA" :
				    (l->marker == MRK_REVOKE ? "REVOKED" : ""));
			}
			إذا (ctx->hash_hosts)
				معلوم_hosts_hash(l, ctx);
			وإلا إذا (print_fingerprint) {
				fp = sshkey_fingerprint(l->کلی, fptype, rep);
				ra = sshkey_fingerprint(l->کلی,
				    fingerprint_hash, SSH_FP_RANDOMART);
				إذا (fp == عدم || ra == عدم)
					fatal_f("sshkey_fingerprint failed");
				mprintf("%s %s %s%s%s\n", ctx->host,
				    sshkey_type(l->کلی), fp,
				    l->comment[0] ? " " : "",
				    l->comment);
				إذا (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
					چاپ_کړه("%s\n", ra);
				حرر(ra);
				حرر(fp);
			} وإلا
				fprintf(ctx->بهر, "%s\n", l->کرښه);
			أرجع 0;
		}
	} وإلا إذا (ctx->delete_host) {
		/* Retain non-matching hosts when deleting */
		إذا (l->حالت == HKF_حالت_INVALID) {
			ctx->invalid = 1;
			logit("%s:%lu: invalid line", l->لار, l->linenum);
		}
		fprintf(ctx->بهر, "%s\n", l->کرښه);
	}
	أرجع 0;
}

ساكن فراغ
do_معلوم_hosts(بنية passwd *pw, ثابت حرف *name, صحيح پیدا_کړه_host,
    صحيح delete_host, صحيح hash_hosts)
{
	حرف *cp, tmp[PATH_MAX], old[PATH_MAX];
	صحيح r, fd, oerrno, inplace = 0;
	بنية معلوم_hosts_ctx ctx;
	u_int foreach_options;
	بنية stat sb;

	إذا (!have_بې_اغېزه_عنصر) {
		cp = tilde_expand_filename(لار_SSH_USER_HOSTFILE, pw->pw_uid);
		إذا (strlcpy(بې_اغېزه_عنصر_file, cp, حجم(بې_اغېزه_عنصر_file)) >=
		    حجم(بې_اغېزه_عنصر_file))
			fatal("Specified known hosts path too long");
		حرر(cp);
		have_بې_اغېزه_عنصر = 1;
	}
	إذا (stat(بې_اغېزه_عنصر_file, &sb) != 0)
		fatal("Cannot stat %s: %s", بې_اغېزه_عنصر_file, strerror(errno));

	memset(&ctx, 0, حجم(ctx));
	ctx.بهر = stdout;
	ctx.host = name;
	ctx.hash_hosts = hash_hosts;
	ctx.پیدا_کړه_host = پیدا_کړه_host;
	ctx.delete_host = delete_host;

	/*
	 * Find hosts goes to stdout, hash and deletions happen in-place
	 * A corner case is ssh-keygen -HF foo, which should go to stdout
	 */
	إذا (!پیدا_کړه_host && (hash_hosts || delete_host)) {
		إذا (strlcpy(tmp, بې_اغېزه_عنصر_file, حجم(tmp)) >= حجم(tmp) ||
		    strlcat(tmp, ".XXXXXXXXXX", حجم(tmp)) >= حجم(tmp) ||
		    strlcpy(old, بې_اغېزه_عنصر_file, حجم(old)) >= حجم(old) ||
		    strlcat(old, ".old", حجم(old)) >= حجم(old))
			fatal("known_hosts path too long");
		umask(077);
		إذا ((fd = mkstemp(tmp)) == -1)
			fatal("mkstemp: %s", strerror(errno));
		إذا ((ctx.بهر = fdopen(fd, "w")) == عدم) {
			oerrno = errno;
			unlink(tmp);
			fatal("fdopen: %s", strerror(oerrno));
		}
		(فراغ)fchmod(fd, sb.st_mode & 0644);
		inplace = 1;
	}
	/* XXX support identity_file == "-" for stdin */
	foreach_options = پیدا_کړه_host ? HKF_WANT_سمون : 0;
	foreach_options |= print_fingerprint ? HKF_WANT_PARSE_کلی : 0;
	إذا ((r = hostkeys_foreach(بې_اغېزه_عنصر_file, (پیدا_کړه_host || !hash_hosts) ?
	    معلوم_hosts_پیدا_کړه_delete : معلوم_hosts_hash, &ctx, name, عدم,
	    foreach_options, 0)) != 0) {
		إذا (inplace)
			unlink(tmp);
		fatal_fr(r, "hostkeys_foreach");
	}

	إذا (inplace)
		fclose(ctx.بهر);

	إذا (ctx.invalid) {
		error("%s is not a valid known_hosts file.", بې_اغېزه_عنصر_file);
		إذا (inplace) {
			error("Not replacing existing known_hosts "
			    "file because of errors");
			unlink(tmp);
		}
		وتل(1);
	} وإلا إذا (delete_host && !ctx.وموندل_کلی) {
		logit("Host %s not found in %s", name, بې_اغېزه_عنصر_file);
		إذا (inplace)
			unlink(tmp);
	} وإلا إذا (inplace) {
		/* Backup existing file */
		إذا (unlink(old) == -1 && errno != ENOENT)
			fatal("unlink %.100s: %s", old, strerror(errno));
		إذا (link(بې_اغېزه_عنصر_file, old) == -1)
			fatal("link %.100s to %.100s: %s", بې_اغېزه_عنصر_file, old,
			    strerror(errno));
		/* Move new one into place */
		إذا (rename(tmp, بې_اغېزه_عنصر_file) == -1) {
			error("rename\"%s\" to \"%s\": %s", tmp, بې_اغېزه_عنصر_file,
			    strerror(errno));
			unlink(tmp);
			unlink(old);
			وتل(1);
		}

		چاپ_کړه("%s updated.\n", بې_اغېزه_عنصر_file);
		چاپ_کړه("Original contents retained as %s\n", old);
		إذا (ctx.has_unhashed) {
			logit("WARNING: %s contains unhashed entries", old);
			logit("Delete this file to ensure privacy "
			    "of hostnames");
		}
	}

	وتل (پیدا_کړه_host && !ctx.وموندل_کلی);
}

/*
 * Perform changing a passphrase.  The argument is the passwd structure
 * for the current user.
 */
ساكن فراغ
do_change_passphrase(بنية passwd *pw, حرف * ثابت *opts, اندازه_t nopts)
{
	حرف *comment;
	حرف *old_passphrase, *passphrase1, *passphrase2;
	بنية stat st;
	بنية sshkey *خاص;
	صحيح r;
	اندازه_t i;

	إذا (!have_بې_اغېزه_عنصر)
		ask_filename(pw, "Enter file in which the key is");
	إذا (stat(بې_اغېزه_عنصر_file, &st) == -1)
		fatal("%s: %s", بې_اغېزه_عنصر_file, strerror(errno));
	/* Try to load the file with empty passphrase. */
	r = sshkey_بارول_شخصي(بې_اغېزه_عنصر_file, "", &خاص, &comment);
	إذا (r == SSH_ERR_کلی_WRONG_PASSPHRASE) {
		إذا (بې_اغېزه_عنصر_passphrase)
			old_passphrase = xstrdup(بې_اغېزه_عنصر_passphrase);
		وإلا
			old_passphrase =
			    read_passphrase("Enter old passphrase: ",
			    RP_ALLOW_STDIN);
		r = sshkey_بارول_شخصي(بې_اغېزه_عنصر_file, old_passphrase,
		    &خاص, &comment);
		freezero(old_passphrase, مزي_اوږدوالی(old_passphrase));
		إذا (r != 0)
			اذهب badkey;
	} وإلا إذا (r != 0) {
 badkey:
		fatal_r(r, "Failed to load key %s", بې_اغېزه_عنصر_file);
	}
	إذا (comment)
		mprintf("Key has comment '%s'\n", comment);

	/* All current -O options relate to FIDO keys only */
	إذا (nopts != 0 && !sshkey_is_sk(خاص)) {
		fatal("FIDO-specific option requested for non-FIDO key %s",
		    بې_اغېزه_عنصر_file);
	}
	إذا (sshkey_is_sk(خاص)) {
		debug_f("%s: original FIDO key flags: "
		    "%stouch-required %sverify-required", بې_اغېزه_عنصر_file,
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
		    "%stouch-required %sverify-required", بې_اغېزه_عنصر_file,
		    (خاص->sk_flags & SSH_SK_USER_PRESENCE_REQD) ? "": "no-",
		    (خاص->sk_flags & SSH_SK_USER_VERIFICATION_REQD) ? "" : "no-");
	}

	/* Ask the new passphrase (twice). */
	إذا (بې_اغېزه_عنصر_new_passphrase) {
		passphrase1 = xstrdup(بې_اغېزه_عنصر_new_passphrase);
		passphrase2 = عدم;
	} وإلا {
		passphrase1 =
			read_passphrase("Enter new passphrase (empty for no "
			    "passphrase): ", RP_ALLOW_STDIN);
		passphrase2 = read_passphrase("Enter same passphrase again: ",
		    RP_ALLOW_STDIN);

		/* Verify that they are the same. */
		إذا (strcmp(passphrase1, passphrase2) != 0) {
			explicit_bzero(passphrase1, مزي_اوږدوالی(passphrase1));
			explicit_bzero(passphrase2, مزي_اوږدوالی(passphrase2));
			حرر(passphrase1);
			حرر(passphrase2);
			چاپ_کړه("Pass phrases do not match.  Try again.\n");
			وتل(1);
		}
		/* Destroy the other copy. */
		freezero(passphrase2, مزي_اوږدوالی(passphrase2));
	}

	/* Save the file using the new passphrase. */
	إذا ((r = sshkey_save_شخصي(خاص, بې_اغېزه_عنصر_file, passphrase1,
	    comment, شخصي_کلی_format, openssh_format_cipher, پړاوونه)) != 0) {
		error_r(r, "Saving key \"%s\" failed", بې_اغېزه_عنصر_file);
		freezero(passphrase1, مزي_اوږدوالی(passphrase1));
		sshkey_free(خاص);
		حرر(comment);
		وتل(1);
	}
	/* Destroy the passphrase and the copy of the key in memory. */
	freezero(passphrase1, مزي_اوږدوالی(passphrase1));
	sshkey_free(خاص);		 /* Destroys contents */
	حرر(comment);

	چاپ_کړه("Your identification has been saved with the new passphrase.\n");
	وتل(0);
}

/*
 * Print the SSHFP RR.
 */
ساكن صحيح
do_print_resource_ریکارډ(بنية passwd *pw, حرف *fname, حرف *hname,
    صحيح print_generic, حرف * ثابت *opts, اندازه_t nopts)
{
	بنية sshkey *عام;
	حرف *comment = عدم;
	ثابت حرف *p;
	بنية stat st;
	صحيح r, hash = -1;
	اندازه_t i;

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
	إذا ((r = sshkey_بارول_عامه(fname, &عام, &comment)) != 0)
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
do_change_comment(بنية passwd *pw, ثابت حرف *بې_اغېزه_عنصر_comment)
{
	حرف new_comment[کلی_COMMENT_MAX], *comment, *passphrase;
	بنية sshkey *خاص;
	بنية sshkey *عام;
	بنية stat st;
	صحيح r;

	إذا (!have_بې_اغېزه_عنصر)
		ask_filename(pw, "Enter file in which the key is");
	إذا (stat(بې_اغېزه_عنصر_file, &st) == -1)
		fatal("%s: %s", بې_اغېزه_عنصر_file, strerror(errno));
	إذا ((r = sshkey_بارول_شخصي(بې_اغېزه_عنصر_file, "",
	    &خاص, &comment)) == 0)
		passphrase = xstrdup("");
	وإلا إذا (r != SSH_ERR_کلی_WRONG_PASSPHRASE)
		fatal_r(r, "Cannot load private key \"%s\"", بې_اغېزه_عنصر_file);
	وإلا {
		إذا (بې_اغېزه_عنصر_passphrase)
			passphrase = xstrdup(بې_اغېزه_عنصر_passphrase);
		وإلا إذا (بې_اغېزه_عنصر_new_passphrase)
			passphrase = xstrdup(بې_اغېزه_عنصر_new_passphrase);
		وإلا
			passphrase = read_passphrase("Enter passphrase: ",
			    RP_ALLOW_STDIN);
		/* Try to load using the passphrase. */
		إذا ((r = sshkey_بارول_شخصي(بې_اغېزه_عنصر_file, passphrase,
		    &خاص, &comment)) != 0) {
			freezero(passphrase, مزي_اوږدوالی(passphrase));
			fatal_r(r, "Cannot load private key \"%s\"",
			    بې_اغېزه_عنصر_file);
		}
	}

	إذا (خاص->type != کلی_ED25519 &&
	    شخصي_کلی_format != SSHKEY_شخصي_OPENSSH) {
		error("Comments are only supported for keys stored in "
		    "the new format (-o).");
		explicit_bzero(passphrase, مزي_اوږدوالی(passphrase));
		sshkey_free(خاص);
		وتل(1);
	}
	إذا (comment)
		چاپ_کړه("Old comment: %s\n", comment);
	وإلا
		چاپ_کړه("No existing comment\n");

	إذا (بې_اغېزه_عنصر_comment) {
		strlcpy(new_comment, بې_اغېزه_عنصر_comment, حجم(new_comment));
	} وإلا {
		چاپ_کړه("New comment: ");
		fflush(stdout);
		إذا (!fgets(new_comment, حجم(new_comment), stdin)) {
			explicit_bzero(passphrase, مزي_اوږدوالی(passphrase));
			sshkey_free(خاص);
			وتل(1);
		}
		new_comment[strcspn(new_comment, "\n")] = '\0';
	}
	إذا (comment != عدم && strcmp(comment, new_comment) == 0) {
		چاپ_کړه("No change to comment\n");
		حرر(passphrase);
		sshkey_free(خاص);
		حرر(comment);
		وتل(0);
	}

	/* Save the file using the new passphrase. */
	إذا ((r = sshkey_save_شخصي(خاص, بې_اغېزه_عنصر_file, passphrase,
	    new_comment, شخصي_کلی_format, openssh_format_cipher,
	    پړاوونه)) != 0) {
		error_r(r, "Saving key \"%s\" failed", بې_اغېزه_عنصر_file);
		freezero(passphrase, مزي_اوږدوالی(passphrase));
		sshkey_free(خاص);
		حرر(comment);
		وتل(1);
	}
	freezero(passphrase, مزي_اوږدوالی(passphrase));
	إذا ((r = sshkey_from_شخصي(خاص, &عام)) != 0)
		fatal_fr(r, "sshkey_from_private");
	sshkey_free(خاص);

	strlcat(بې_اغېزه_عنصر_file, ".pub", حجم(بې_اغېزه_عنصر_file));
	إذا ((r = sshkey_save_عامه(عام, بې_اغېزه_عنصر_file, new_comment)) != 0)
		fatal_r(r, "Unable to save public key to %s", بې_اغېزه_عنصر_file);
	sshkey_free(عام);
	حرر(comment);

	إذا (مزي_اوږدوالی(new_comment) > 0)
		چاپ_کړه("Comment '%s' applied\n", new_comment);
	وإلا
		چاپ_کړه("Comment removed\n");

	وتل(0);
}

ساكن فراغ
cert_ext_جمع_کړه(ثابت حرف *کلی, ثابت حرف *ارزښت, صحيح iscrit)
{
	cert_ext = xreallocarray(cert_ext, ncert_ext + 1, حجم(*cert_ext));
	cert_ext[ncert_ext].کلی = xstrdup(کلی);
	cert_ext[ncert_ext].val = ارزښت == عدم ? عدم : xstrdup(ارزښت);
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
	إذا ((r = strcmp(a->کلی, b->کلی)) != 0)
		أرجع r;
	إذا ((a->val == عدم) != (b->val == عدم))
		أرجع (a->val == عدم) ? -1 : 1;
	إذا (a->val != عدم && (r = strcmp(a->val, b->val)) != 0)
		أرجع r;
	أرجع 0;
}

#تعریف_کړه OPTIONS_CRITICAL	1
#تعریف_کړه OPTIONS_EXTENSIONS	2
ساكن فراغ
prepare_options_buf(بنية sshbuf *c, صحيح which)
{
	بنية sshbuf *b;
	اندازه_t i;
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
			debug3_f("%s", ext->کلی);
			إذا ((r = sshbuf_put_cstring(c, ext->کلی)) != 0 ||
			    (r = sshbuf_put_string(c, عدم, 0)) != 0)
				fatal_fr(r, "prepare flag");
		} وإلا {
			/* key/value option */
			debug3_f("%s=%s", ext->کلی, ext->val);
			sshbuf_reset(b);
			إذا ((r = sshbuf_put_cstring(c, ext->کلی)) != 0 ||
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
		cert_ext_جمع_کړه("force-command", certflags_command, 1);
	إذا (certflags_src_addr != عدم)
		cert_ext_جمع_کړه("source-address", certflags_src_addr, 1);
	إذا ((certflags_flags & CERTOPT_REQUIRE_VERIFY) != 0)
		cert_ext_جمع_کړه("verify-required", عدم, 1);
	/* extensions */
	إذا ((certflags_flags & CERTOPT_X_FWD) != 0)
		cert_ext_جمع_کړه("permit-X11-forwarding", عدم, 0);
	إذا ((certflags_flags & CERTOPT_AGENT_FWD) != 0)
		cert_ext_جمع_کړه("permit-agent-forwarding", عدم, 0);
	إذا ((certflags_flags & CERTOPT_پورټ_FWD) != 0)
		cert_ext_جمع_کړه("permit-port-forwarding", عدم, 0);
	إذا ((certflags_flags & CERTOPT_PTY) != 0)
		cert_ext_جمع_کړه("permit-pty", عدم, 0);
	إذا ((certflags_flags & CERTOPT_USER_RC) != 0)
		cert_ext_جمع_کړه("permit-user-rc", عدم, 0);
	إذا ((certflags_flags & CERTOPT_NO_REQUIRE_USER_PRESENCE) != 0)
		cert_ext_جمع_کړه("no-touch-required", عدم, 0);
	/* order lexically by key */
	إذا (ncert_ext > 0)
		qsort(cert_ext, ncert_ext, حجم(*cert_ext), cert_ext_cmp);
}

ساكن بنية sshkey *
بارول_pkcs11_کلی(حرف *لار)
{
#که_تعریف_شوی ENABLE_PKCS11
	بنية sshkey **کلیګانې = عدم, *عام, *خاص = عدم;
	صحيح r, i, nkeys;

	إذا ((r = sshkey_بارول_عامه(لار, &عام, عدم)) != 0)
		fatal_r(r, "Couldn't load CA public key \"%s\"", لار);

	nkeys = pkcs11_جمع_کړه_provider(pkcs11provider, بې_اغېزه_عنصر_passphrase,
	    &کلیګانې, عدم);
	debug3_f("%d keys", nkeys);
	إذا (nkeys <= 0)
		fatal("cannot read public key from pkcs11");
	لكل (i = 0; i < nkeys; i++) {
		إذا (sshkey_equal_عامه(عام, کلیګانې[i])) {
			خاص = کلیګانې[i];
			استمر;
		}
		sshkey_free(کلیګانې[i]);
	}
	حرر(کلیګانې);
	sshkey_free(عام);
	أرجع خاص;
#وإلا
	fatal("no pkcs11 support");
#د_که_پای /* ENABLE_PKCS11 */
}

/* Signer for sshkey_certify_custom that uses the agent */
ساكن صحيح
agent_signer(بنية sshkey *کلی, u_char **sigp, اندازه_t *lenp,
    ثابت u_char *معلومات, اندازه_t datalen,
    ثابت حرف *alg, ثابت حرف *provider, ثابت حرف *pin,
    u_int compat, فراغ *ctx)
{
	صحيح *agent_fdp = (صحيح *)ctx;

	أرجع ssh_agent_sign(*agent_fdp, کلی, sigp, lenp,
	    معلومات, datalen, alg, compat);
}

ساكن فراغ
do_ca_sign(بنية passwd *pw, ثابت حرف *ca_کلی_لار, صحيح prefer_agent,
    بینښه اوږد اوږد cert_serial, صحيح cert_serial_autoinc,
    صحيح argc, حرف **argv)
{
	صحيح r, i, کلی_دننه_agent = 0, agent_fd = -1;
	u_int n;
	بنية sshkey *ca, *عام;
	حرف valid[64], *otmp, *tmp, *cp, *بهر, *comment;
	حرف *ca_fp = عدم, **plist = عدم, *pin = عدم;
	بنية ssh_identitylist *agent_ids;
	اندازه_t j;
	بنية notifier_ctx *notifier = عدم;

#که_تعریف_شوی ENABLE_PKCS11
	pkcs11_init(1);
#د_که_پای
	tmp = tilde_expand_filename(ca_کلی_لار, pw->pw_uid);
	إذا (pkcs11provider != عدم) {
		/* If a PKCS#11 token was specified then try to use it */
		إذا ((ca = بارول_pkcs11_کلی(tmp)) == عدم)
			fatal("No PKCS#11 key matching %s found", ca_کلی_لار);
	} وإلا إذا (prefer_agent) {
		/*
		 * Agent signature requested. Try to use agent after making
		 * sure the public key specified is actually present in the
		 * agent.
		 */
		إذا ((r = sshkey_بارول_عامه(tmp, &ca, عدم)) != 0)
			fatal_r(r, "Cannot load CA public key %s", tmp);
		إذا ((r = ssh_get_authentication_socket(&agent_fd)) != 0)
			fatal_r(r, "Cannot use public key for CA signature");
		إذا ((r = ssh_fetch_identitylist(agent_fd, &agent_ids)) != 0)
			fatal_r(r, "Retrieve agent key list");
		لكل (j = 0; j < agent_ids->nkeys; j++) {
			إذا (sshkey_equal(ca, agent_ids->کلیګانې[j])) {
				کلی_دننه_agent = 1;
				/* Replace the CA key with the agent one */
				sshkey_free(ca);
				ca = agent_ids->کلیګانې[j];
				agent_ids->کلیګانې[j] = عدم;
				اكسر;
			}
		}
		إذا (!کلی_دننه_agent)
			fatal("CA key %s not found in agent", tmp);
		ssh_free_identitylist(agent_ids);
	} وإلا {
		/* CA key is assumed to be a private key on the filesystem */
		ca = بارول_بې_اغېزه_عنصر(tmp, عدم);
		إذا (sshkey_is_sk(ca) &&
		    (ca->sk_flags & SSH_SK_USER_VERIFICATION_REQD)) {
			إذا ((pin = read_passphrase("Enter PIN for CA key: ",
			    RP_ALLOW_STDIN)) == عدم)
				fatal_f("couldn't read PIN");
		}
	}
	حرر(tmp);

	إذا (کلی_type_name != عدم) {
		إذا (sshkey_type_from_shortname(کلی_type_name) != ca->type) {
			fatal("CA key type %s doesn't match specified %s",
			    sshkey_ssh_name(ca), کلی_type_name);
		}
	} وإلا إذا (ca->type == کلی_RSA) {
		/* Default to a good signature algorithm */
		کلی_type_name = "rsa-sha2-512";
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
		إذا ((r = sshkey_بارول_عامه(tmp, &عام, &comment)) != 0)
			fatal_r(r, "load pubkey \"%s\"", tmp);
		إذا (sshkey_is_cert(عام))
			fatal_f("key \"%s\" type %s cannot be certified",
			    tmp, sshkey_type(عام));

		/* Prepare certificate to sign */
		إذا ((r = sshkey_منزل_certified(عام)) != 0)
			fatal_r(r, "Could not upgrade key %s to certificate", tmp);
		عام->cert->type = cert_کلی_type;
		عام->cert->serial = (uint64_t)cert_serial;
		عام->cert->کلی_id = xstrdup(cert_کلی_id);
		عام->cert->nprincipals = n;
		عام->cert->principals = plist;
		عام->cert->valid_after = cert_valid_from;
		عام->cert->valid_before = cert_valid_منزل;
		prepare_options_buf(عام->cert->critical, OPTIONS_CRITICAL);
		prepare_options_buf(عام->cert->extensions,
		    OPTIONS_EXTENSIONS);
		إذا ((r = sshkey_from_شخصي(ca,
		    &عام->cert->signature_کلی)) != 0)
			fatal_r(r, "sshkey_from_private (ca key)");

		إذا (کلی_دننه_agent) {
			إذا ((r = sshkey_certify_custom(عام, ca,
			    کلی_type_name, sk_provider, عدم, agent_signer,
			    &agent_fd)) != 0)
				fatal_r(r, "Couldn't certify %s via agent", tmp);
		} وإلا {
			إذا (sshkey_is_sk(ca) &&
			    (ca->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
				notifier = notify_پیل(0,
				    "Confirm user presence for key %s %s",
				    sshkey_type(ca), ca_fp);
			}
			r = sshkey_certify(عام, ca, کلی_type_name,
			    sk_provider, pin);
			notify_complete(notifier, "User presence confirmed");
			إذا (r != 0)
				fatal_r(r, "Couldn't certify key %s", tmp);
		}

		إذا ((cp = strrchr(tmp, '.')) != عدم && strcmp(cp, ".pub") == 0)
			*cp = '\0';
		xasprintf(&بهر, "%s-cert.pub", tmp);
		حرر(tmp);

		إذا ((r = sshkey_save_عامه(عام, بهر, comment)) != 0) {
			fatal_r(r, "Unable to save public key to %s",
			    بې_اغېزه_عنصر_file);
		}

		إذا (!quiet) {
			sshkey_format_cert_validity(عام->cert,
			    valid, حجم(valid));
			logit("Signed %s key %s: id \"%s\" serial %llu%s%s "
			    "valid %s", sshkey_cert_type(عام),
			    بهر, عام->cert->کلی_id,
			    (بینښه اوږد اوږد)عام->cert->serial,
			    cert_principals != عدم ? " for " : "",
			    cert_principals != عدم ? cert_principals : "",
			    valid);
		}

		sshkey_free(عام);
		حرر(بهر);
		حرر(comment);
		إذا (cert_serial_autoinc)
			cert_serial++;
	}
	إذا (pin != عدم)
		freezero(pin, مزي_اوږدوالی(pin));
	sshkey_free(ca);
	حرر(ca_fp);
#که_تعریف_شوی ENABLE_PKCS11
	pkcs11_terminate();
#د_که_پای
}

ساكن uint64_t
parse_relative_وخت(ثابت حرف *s, time_t now)
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
parse_hex_u64(ثابت حرف *s, uint64_t *پورته)
{
	حرف *ep;
	بینښه اوږد اوږد ull;

	errno = 0;
	ull = strtoull(s, &ep, 16);
	إذا (*s == '\0' || *ep != '\0')
		fatal("Invalid certificate time: not a number");
	إذا (errno == ERANGE && ull == ULONG_MAX)
		fatal_fr(SSH_ERR_SYSTEM_ERROR, "Invalid certificate time");
	*پورته = (uint64_t)ull;
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
		cert_valid_from = parse_relative_وخت(from, now);
	وإلا إذا (strcmp(from, "always") == 0)
		cert_valid_from = 0;
	وإلا إذا (مزي_پرتله(from, "0x", 2) == 0)
		parse_hex_u64(from, &cert_valid_from);
	وإلا إذا (parse_absolute_وخت(from, &cert_valid_from) != 0)
		fatal("Invalid from time \"%s\"", from);

	إذا (*منزل == '-' || *منزل == '+')
		cert_valid_منزل = parse_relative_وخت(منزل, now);
	وإلا إذا (strcmp(منزل, "forever") == 0)
		cert_valid_منزل = ~(uint64_t)0;
	وإلا إذا (مزي_پرتله(منزل, "0x", 2) == 0)
		parse_hex_u64(منزل, &cert_valid_منزل);
	وإلا إذا (parse_absolute_وخت(منزل, &cert_valid_منزل) != 0)
		fatal("Invalid to time \"%s\"", منزل);

	إذا (cert_valid_منزل <= cert_valid_from)
		fatal("Empty certificate validity interval");
	حرر(from);
}

ساكن فراغ
جمع_کړه_cert_option(حرف *opt)
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
		certflags_flags &= ~CERTOPT_پورټ_FWD;
	وإلا إذا (strcasecmp(opt, "permit-port-forwarding") == 0)
		certflags_flags |= CERTOPT_پورټ_FWD;
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
		إذا (addr_سمون_cidr_list(عدم, p) != 0)
			fatal("Invalid source-address list");
		certflags_src_addr = xstrdup(p);
	} وإلا إذا (strprefix(opt, "extension:", 1) != عدم ||
		    (iscrit = (strprefix(opt, "critical:", 1) != عدم))) {
		val = xstrdup(strchr(opt, ':') + 1);
		إذا ((cp = strchr(val, '=')) != عدم)
			*cp++ = '\0';
		cert_ext_جمع_کړه(val, cp, iscrit);
		حرر(val);
	} وإلا
		fatal("Unsupported certificate option \"%s\"", opt);
}

ساكن فراغ
show_options(بنية sshbuf *optbuf, صحيح دننه_critical)
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
		چاپ_کړه("                %s", name);
		إذا (!دننه_critical &&
		    (strcmp(name, "permit-X11-forwarding") == 0 ||
		    strcmp(name, "permit-agent-forwarding") == 0 ||
		    strcmp(name, "permit-port-forwarding") == 0 ||
		    strcmp(name, "permit-pty") == 0 ||
		    strcmp(name, "permit-user-rc") == 0 ||
		    strcmp(name, "no-touch-required") == 0)) {
			چاپ_کړه("\n");
		} وإلا إذا (دننه_critical &&
		    (strcmp(name, "force-command") == 0 ||
		    strcmp(name, "source-address") == 0)) {
			إذا ((r = sshbuf_get_cstring(option, &arg, عدم)) != 0)
				fatal_fr(r, "parse critical");
			چاپ_کړه(" %s\n", arg);
			حرر(arg);
		} وإلا إذا (دننه_critical &&
		    strcmp(name, "verify-required") == 0) {
			چاپ_کړه("\n");
		} وإلا إذا (sshbuf_len(option) > 0) {
			hex = sshbuf_dtob16(option);
			چاپ_کړه(" UNKNOWN OPTION: %s (len %zu)\n",
			    hex, sshbuf_len(option));
			sshbuf_reset(option);
			حرر(hex);
		} وإلا
			چاپ_کړه(" UNKNOWN FLAG OPTION\n");
		حرر(name);
		إذا (sshbuf_len(option) != 0)
			fatal("Option corrupt: extra data at end");
	}
	sshbuf_free(option);
	sshbuf_free(options);
}

ساكن فراغ
print_cert(بنية sshkey *کلی)
{
	حرف valid[64], *کلی_fp, *ca_fp;
	u_int i;

	کلی_fp = sshkey_fingerprint(کلی, fingerprint_hash, SSH_FP_DEFAULT);
	ca_fp = sshkey_fingerprint(کلی->cert->signature_کلی,
	    fingerprint_hash, SSH_FP_DEFAULT);
	إذا (کلی_fp == عدم || ca_fp == عدم)
		fatal_f("sshkey_fingerprint fail");
	sshkey_format_cert_validity(کلی->cert, valid, حجم(valid));

	چاپ_کړه("        Type: %s %s certificate\n", sshkey_ssh_name(کلی),
	    sshkey_cert_type(کلی));
	چاپ_کړه("        Public key: %s %s\n", sshkey_type(کلی), کلی_fp);
	چاپ_کړه("        Signing CA: %s %s (using %s)\n",
	    sshkey_type(کلی->cert->signature_کلی), ca_fp,
	    کلی->cert->signature_type);
	چاپ_کړه("        Key ID: \"%s\"\n", کلی->cert->کلی_id);
	چاپ_کړه("        Serial: %llu\n", (بینښه اوږد اوږد)کلی->cert->serial);
	چاپ_کړه("        Valid: %s\n", valid);
	چاپ_کړه("        Principals: ");
	إذا (کلی->cert->nprincipals == 0)
		چاپ_کړه("(none)\n");
	وإلا {
		لكل (i = 0; i < کلی->cert->nprincipals; i++)
			چاپ_کړه("\n                %s",
			    کلی->cert->principals[i]);
		چاپ_کړه("\n");
	}
	چاپ_کړه("        Critical Options: ");
	إذا (sshbuf_len(کلی->cert->critical) == 0)
		چاپ_کړه("(none)\n");
	وإلا {
		چاپ_کړه("\n");
		show_options(کلی->cert->critical, 1);
	}
	چاپ_کړه("        Extensions: ");
	إذا (sshbuf_len(کلی->cert->extensions) == 0)
		چاپ_کړه("(none)\n");
	وإلا {
		چاپ_کړه("\n");
		show_options(کلی->cert->extensions, 0);
	}
	حرر(کلی_fp);
	حرر(ca_fp);
}

ساكن فراغ
do_show_cert(بنية passwd *pw)
{
	بنية sshkey *کلی = عدم;
	بنية stat st;
	صحيح r, is_stdin = 0, ok = 0;
	FILE *f;
	حرف *cp, *کرښه = عدم;
	ثابت حرف *لار;
	اندازه_t linesize = 0;
	u_long lnum = 0;

	إذا (!have_بې_اغېزه_عنصر)
		ask_filename(pw, "Enter file in which the key is");
	إذا (strcmp(بې_اغېزه_عنصر_file, "-") != 0 && stat(بې_اغېزه_عنصر_file, &st) == -1)
		fatal("%s: %s: %s", __progname, بې_اغېزه_عنصر_file, strerror(errno));

	لار = بې_اغېزه_عنصر_file;
	إذا (strcmp(لار, "-") == 0) {
		f = stdin;
		لار = "(stdin)";
		is_stdin = 1;
	} وإلا إذا ((f = fopen(بې_اغېزه_عنصر_file, "r")) == عدم)
		fatal("fopen %s: %s", بې_اغېزه_عنصر_file, strerror(errno));

	طالما (getline(&کرښه, &linesize, f) != -1) {
		lnum++;
		sshkey_free(کلی);
		کلی = عدم;
		/* Trim leading space and comments */
		cp = کرښه + strspn(کرښه, " \t");
		إذا (*cp == '#' || *cp == '\0')
			استمر;
		إذا ((کلی = sshkey_new(کلی_UNSPEC)) == عدم)
			fatal("sshkey_new");
		إذا ((r = sshkey_read(کلی, &cp)) != 0) {
			error_r(r, "%s:%lu: invalid key", لار, lnum);
			استمر;
		}
		إذا (!sshkey_is_cert(کلی)) {
			error("%s:%lu is not a certificate", لار, lnum);
			استمر;
		}
		ok = 1;
		إذا (!is_stdin && lnum == 1)
			چاپ_کړه("%s:\n", لار);
		وإلا
			چاپ_کړه("%s:%lu:\n", لار, lnum);
		print_cert(کلی);
	}
	حرر(کرښه);
	sshkey_free(کلی);
	fclose(f);
	وتل(ok ? 0 : 1);
}

ساكن فراغ
بارول_krl(ثابت حرف *لار, بنية ssh_krl **krlp)
{
	بنية sshbuf *krlbuf;
	صحيح r;

	إذا ((r = sshbuf_بارول_file(لار, &krlbuf)) != 0)
		fatal_r(r, "Unable to load KRL %s", لار);
	/* XXX check sigs */
	إذا ((r = ssh_krl_from_blob(krlbuf, krlp)) != 0 ||
	    *krlp == عدم)
		fatal_r(r, "Invalid KRL file %s", لار);
	sshbuf_free(krlbuf);
}

ساكن فراغ
hash_منزل_blob(ثابت حرف *cp, u_char **blobp, اندازه_t *lenp,
    ثابت حرف *file, u_long lnum)
{
	حرف *tmp;
	اندازه_t tlen;
	بنية sshbuf *b;
	صحيح r;

	إذا ((cp = strprefix(cp, "SHA256:", 0)) == عدم)
		fatal("%s:%lu: unsupported hash algorithm", file, lnum);

	/*
	 * OpenSSH base64 hashes omit trailing '='
	 * characters; put them back for decode.
	 */
	إذا ((tlen = مزي_اوږدوالی(cp)) >= SIZE_MAX - 5)
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
	حافظه_نقل(*blobp, sshbuf_ptr(b), *lenp);
	sshbuf_free(b);
}

ساكن فراغ
update_krl_from_file(بنية passwd *pw, ثابت حرف *file, صحيح wild_ca,
    ثابت بنية sshkey *ca, بنية ssh_krl *krl)
{
	بنية sshkey *کلی = عدم;
	u_long lnum = 0;
	حرف *لار, *cp, *ep, *کرښه = عدم;
	u_char *blob = عدم;
	اندازه_t blen = 0, linesize = 0;
	بینښه اوږد اوږد serial, serial2;
	صحيح i, was_explicit_کلی, was_sha1, was_sha256, was_hash, r;
	FILE *krl_spec;

	لار = tilde_expand_filename(file, pw->pw_uid);
	إذا (strcmp(لار, "-") == 0) {
		krl_spec = stdin;
		حرر(لار);
		لار = xstrdup("(standard input)");
	} وإلا إذا ((krl_spec = fopen(لار, "r")) == عدم)
		fatal("fopen %s: %s", لار, strerror(errno));

	إذا (!quiet)
		چاپ_کړه("Revoking from %s\n", لار);
	طالما (getline(&کرښه, &linesize, krl_spec) != -1) {
		إذا (linesize >= لوی_عدد) {
			fatal_f("%s contains unparsable line, len=%zu",
			    لار, linesize);
		}
		lnum++;
		was_explicit_کلی = was_sha1 = was_sha256 = was_hash = 0;
		cp = کرښه + strspn(کرښه, " \t");
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
				    لار, lnum, cp);
			إذا (errno == ERANGE && serial == ULLONG_MAX)
				fatal("%s:%lu: serial out of range",
				    لار, lnum);
			serial2 = serial;
			إذا (*ep == '-') {
				cp = ep + 1;
				errno = 0;
				serial2 = strtoull(cp, &ep, 0);
				إذا (*cp == '\0' || *ep != '\0')
					fatal("%s:%lu: invalid serial \"%s\"",
					    لار, lnum, cp);
				إذا (errno == ERANGE && serial2 == ULLONG_MAX)
					fatal("%s:%lu: serial out of range",
					    لار, lnum);
				إذا (serial2 <= serial)
					fatal("%s:%lu: invalid serial range "
					    "%llu:%llu", لار, lnum,
					    (بینښه اوږد اوږد)serial,
					    (بینښه اوږد اوږد)serial2);
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
			إذا (ssh_krl_revoke_cert_by_کلی_id(krl, ca, cp) != 0)
				fatal_f("revoke key ID failed");
		} وإلا إذا (strncasecmp(cp, "hash:", 5) == 0) {
			cp += 5;
			cp = cp + strspn(cp, " \t");
			hash_منزل_blob(cp, &blob, &blen, file, lnum);
			إذا ((r = ssh_krl_revoke_کلی_sha256(krl,
			    blob, blen)) != 0)
				fatal_fr(r, "revoke key failed");
			حرر(blob);
			blob = عدم;
			blen = 0;
		} وإلا {
			إذا (strncasecmp(cp, "key:", 4) == 0) {
				cp += 4;
				cp = cp + strspn(cp, " \t");
				was_explicit_کلی = 1;
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
			إذا ((کلی = sshkey_new(کلی_UNSPEC)) == عدم)
				fatal("sshkey_new");
			إذا ((r = sshkey_read(کلی, &cp)) != 0)
				fatal_r(r, "%s:%lu: invalid key", لار, lnum);
			إذا (was_explicit_کلی)
				r = ssh_krl_revoke_کلی_explicit(krl, کلی);
			وإلا إذا (was_sha1) {
				إذا (sshkey_fingerprint_raw(کلی,
				    SSH_DIGEST_SHA1, &blob, &blen) != 0) {
					fatal("%s:%lu: fingerprint failed",
					    file, lnum);
				}
				r = ssh_krl_revoke_کلی_sha1(krl, blob, blen);
			} وإلا إذا (was_sha256) {
				إذا (sshkey_fingerprint_raw(کلی,
				    SSH_DIGEST_SHA256, &blob, &blen) != 0) {
					fatal("%s:%lu: fingerprint failed",
					    file, lnum);
				}
				r = ssh_krl_revoke_کلی_sha256(krl, blob, blen);
			} وإلا
				r = ssh_krl_revoke_کلی(krl, کلی);
			إذا (r != 0)
				fatal_fr(r, "revoke key failed");
			freezero(blob, blen);
			blob = عدم;
			blen = 0;
			sshkey_free(کلی);
		}
	}
	إذا (strcmp(لار, "-") != 0)
		fclose(krl_spec);
	حرر(کرښه);
	حرر(لار);
}

ساكن فراغ
do_gen_krl(بنية passwd *pw, صحيح updating, ثابت حرف *ca_کلی_لار,
    بینښه اوږد اوږد krl_نسخه, ثابت حرف *krl_comment,
    صحيح argc, حرف **argv)
{
	بنية ssh_krl *krl;
	بنية stat sb;
	بنية sshkey *ca = عدم;
	صحيح i, r, wild_ca = 0;
	حرف *tmp;
	بنية sshbuf *kbuf;

	إذا (*بې_اغېزه_عنصر_file == '\0')
		fatal("KRL generation requires an output file");
	إذا (stat(بې_اغېزه_عنصر_file, &sb) == -1) {
		إذا (errno != ENOENT)
			fatal("Cannot access KRL \"%s\": %s",
			    بې_اغېزه_عنصر_file, strerror(errno));
		إذا (updating)
			fatal("KRL \"%s\" does not exist", بې_اغېزه_عنصر_file);
	}
	إذا (ca_کلی_لار != عدم) {
		إذا (strcasecmp(ca_کلی_لار, "none") == 0)
			wild_ca = 1;
		وإلا {
			tmp = tilde_expand_filename(ca_کلی_لار, pw->pw_uid);
			إذا ((r = sshkey_بارول_عامه(tmp, &ca, عدم)) != 0)
				fatal_r(r, "Cannot load CA public key %s", tmp);
			حرر(tmp);
		}
	}

	إذا (updating)
		بارول_krl(بې_اغېزه_عنصر_file, &krl);
	وإلا إذا ((krl = ssh_krl_init()) == عدم)
		fatal("couldn't create KRL");

	إذا (krl_نسخه != 0)
		ssh_krl_سېټ_نسخه(krl, krl_نسخه);
	إذا (krl_comment != عدم)
		ssh_krl_سېټ_comment(krl, krl_comment);

	لكل (i = 0; i < argc; i++)
		update_krl_from_file(pw, argv[i], wild_ca, ca, krl);

	إذا ((kbuf = sshbuf_new()) == عدم)
		fatal("sshbuf_new failed");
	إذا (ssh_krl_منزل_blob(krl, kbuf) != 0)
		fatal("Couldn't generate KRL");
	إذا ((r = sshbuf_write_file(بې_اغېزه_عنصر_file, kbuf)) != 0)
		fatal("write %s: %s", بې_اغېزه_عنصر_file, strerror(errno));
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

	إذا (*بې_اغېزه_عنصر_file == '\0')
		fatal("KRL checking requires an input file");
	بارول_krl(بې_اغېزه_عنصر_file, &krl);
	إذا (print_krl)
		krl_dump(krl, stdout);
	لكل (i = 0; i < argc; i++) {
		إذا ((r = sshkey_بارول_عامه(argv[i], &k, &comment)) != 0)
			fatal_r(r, "Cannot load public key %s", argv[i]);
		r = ssh_krl_check_کلی(krl, k);
		چاپ_کړه("%s%s%s%s: %s\n", argv[i],
		    *comment ? " (" : "", comment, *comment ? ")" : "",
		    r == 0 ? "ok" : "REVOKED");
		إذا (r != 0)
			ret = 1;
		sshkey_free(k);
		حرر(comment);
	}
	ssh_krl_free(krl);
	وتل(ret);
}

ساكن بنية sshkey *
بارول_sign_کلی(ثابت حرف *keypath, ثابت بنية sshkey *pubkey)
{
	اندازه_t i, slen, plen = مزي_اوږدوالی(keypath);
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
		slen = مزي_اوږدوالی(suffixes[i]);
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
	إذا ((r = sshkey_بارول_شخصي(privpath, "", &privkey, عدم)) != 0 &&
	    (r != SSH_ERR_کلی_WRONG_PASSPHRASE)) {
		debug_fr(r, "load private key \"%s\"", privpath);
		fatal("No private key found for \"%s\"", privpath);
	} وإلا إذا (privkey == عدم)
		privkey = بارول_بې_اغېزه_عنصر(privpath, عدم);

	إذا (!sshkey_equal_عامه(pubkey, privkey)) {
		error("Public key %s doesn't match private %s",
		    keypath, privpath);
		اذهب بشپړ;
	}
	إذا (sshkey_is_cert(pubkey) && !sshkey_is_cert(privkey)) {
		/*
		 * Graft the certificate onto the private key to make
		 * it capable of signing.
		 */
		إذا ((r = sshkey_منزل_certified(privkey)) != 0) {
			error_fr(r, "sshkey_to_certified");
			اذهب بشپړ;
		}
		إذا ((r = sshkey_cert_copy(pubkey, privkey)) != 0) {
			error_fr(r, "sshkey_cert_copy");
			اذهب بشپړ;
		}
	}
	/* success */
	ret = privkey;
	privkey = عدم;
 بشپړ:
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
	صحيح r = SSH_ERR_دننی_ERROR, wfd = -1, oerrno;
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
		اذهب بهر;
	}
	إذا ((r = sshsig_armor(sigbuf, &abuf)) != 0) {
		error_fr(r, "sshsig_armor");
		اذهب بهر;
	}
	إذا ((asig = sshbuf_dup_string(abuf)) == عدم) {
		error_f("buffer error");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
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
				اذهب بهر;
			}
			إذا (atomicio(vwrite, wfd, asig,
			    مزي_اوږدوالی(asig)) != مزي_اوږدوالی(asig)) {
				oerrno = errno;
				error("Cannot write to %s: %s",
				    wfile, strerror(errno));
				errno = oerrno;
				r = SSH_ERR_SYSTEM_ERROR;
				اذهب بهر;
			}
			إذا (!quiet) {
				fprintf(stderr, "Write signature to %s\n",
				    wfile);
			}
		}
	}
	/* success */
	r = 0;
 بهر:
	حرر(wfile);
	حرر(prompt);
	حرر(asig);
	إذا (pin != عدم)
		freezero(pin, مزي_اوږدوالی(pin));
	sshbuf_free(abuf);
	sshbuf_free(sigbuf);
	إذا (wfd != -1)
		close(wfd);
	أرجع r;
}

ساكن صحيح
sig_process_opts(حرف * ثابت *opts, اندازه_t nopts, حرف **hashalgp,
    uint64_t *verify_timep, صحيح *print_pubkey)
{
	اندازه_t i;
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
			إذا (parse_absolute_وخت(p, verify_timep) != 0 ||
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
    صحيح argc, حرف **argv, حرف * ثابت *opts, اندازه_t nopts)
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
		اذهب بشپړ; /* error already logged */

	إذا ((r = sshkey_بارول_عامه(keypath, &pubkey, عدم)) != 0) {
		error_r(r, "Couldn't load public key %s", keypath);
		اذهب بشپړ;
	}

	إذا ((r = ssh_get_authentication_socket(&agent_fd)) != 0) {
		إذا (require_agent)
			fatal("Couldn't get agent socket");
		debug_r(r, "Couldn't get agent socket");
	} وإلا {
		إذا ((r = ssh_agent_has_کلی(agent_fd, pubkey)) == 0)
			signer = agent_signer;
		وإلا {
			إذا (require_agent)
				fatal("Couldn't find key in agent");
			debug_r(r, "Couldn't find key in agent");
		}
	}

	إذا (signer == عدم) {
		/* Not using agent - try to load private key */
		إذا ((privkey = بارول_sign_کلی(keypath, pubkey)) == عدم)
			اذهب بشپړ;
		signkey = privkey;
	} وإلا {
		/* Will use key in agent */
		signkey = pubkey;
	}

	إذا (argc == 0) {
		إذا ((r = sign_one(signkey, "(stdin)", STDIN_FILENO,
		    sig_namespace, hashalg, signer, &agent_fd)) != 0)
			اذهب بشپړ;
	} وإلا {
		لكل (i = 0; i < argc; i++) {
			إذا (strcmp(argv[i], "-") == 0)
				fd = STDIN_FILENO;
			وإلا إذا ((fd = open(argv[i], O_RDONLY)) == -1) {
				error("Cannot open %s for signing: %s",
				    argv[i], strerror(errno));
				اذهب بشپړ;
			}
			إذا ((r = sign_one(signkey, argv[i], fd, sig_namespace,
			    hashalg, signer, &agent_fd)) != 0)
				اذهب بشپړ;
			إذا (fd != STDIN_FILENO)
				close(fd);
			fd = -1;
		}
	}

	ret = 0;
بشپړ:
	إذا (fd != -1 && fd != STDIN_FILENO)
		close(fd);
	sshkey_free(pubkey);
	sshkey_free(privkey);
	حرر(hashalg);
	أرجع ret;
}

ساكن صحيح
sig_verify(ثابت حرف *signature, ثابت حرف *sig_namespace,
    ثابت حرف *principal, ثابت حرف *allowed_کلیګانې, ثابت حرف *revoked_کلیګانې,
    حرف * ثابت *opts, اندازه_t nopts)
{
	صحيح r, ret = -1;
	صحيح print_pubkey = 0;
	بنية sshbuf *sigbuf = عدم, *abuf = عدم;
	بنية sshkey *sign_کلی = عدم;
	حرف *fp = عدم;
	بنية sshkey_sig_details *sig_details = عدم;
	uint64_t verify_وخت = 0;

	إذا (sig_process_opts(opts, nopts, عدم, &verify_وخت,
	    &print_pubkey) != 0)
		اذهب بشپړ; /* error already logged */

	memset(&sig_details, 0, حجم(sig_details));
	إذا ((r = sshbuf_بارول_file(signature, &abuf)) != 0) {
		error_r(r, "Couldn't read signature file");
		اذهب بشپړ;
	}

	إذا ((r = sshsig_dearmor(abuf, &sigbuf)) != 0) {
		error_fr(r, "sshsig_armor");
		اذهب بشپړ;
	}
	إذا ((r = sshsig_verify_fd(sigbuf, STDIN_FILENO, sig_namespace,
	    &sign_کلی, &sig_details)) != 0)
		اذهب بشپړ; /* sshsig_verify() prints error */

	إذا ((fp = sshkey_fingerprint(sign_کلی, fingerprint_hash,
	    SSH_FP_DEFAULT)) == عدم)
		fatal_f("sshkey_fingerprint failed");
	debug("Valid (unverified) signature from key %s", fp);
	إذا (sig_details != عدم) {
		debug2_f("signature details: counter = %u, flags = 0x%02x",
		    sig_details->sk_counter, sig_details->sk_flags);
	}
	حرر(fp);
	fp = عدم;

	إذا (revoked_کلیګانې != عدم) {
		إذا ((r = sshkey_check_revoked(sign_کلی, revoked_کلیګانې)) != 0) {
			debug3_fr(r, "sshkey_check_revoked");
			اذهب بشپړ;
		}
	}

	إذا (allowed_کلیګانې != عدم && (r = sshsig_check_allowed_کلیګانې(allowed_کلیګانې,
	    sign_کلی, principal, sig_namespace, verify_وخت)) != 0) {
		debug3_fr(r, "sshsig_check_allowed_keys");
		اذهب بشپړ;
	}
	/* success */
	ret = 0;
بشپړ:
	إذا (!quiet) {
		إذا (ret == 0) {
			إذا ((fp = sshkey_fingerprint(sign_کلی, fingerprint_hash,
			    SSH_FP_DEFAULT)) == عدم)
				fatal_f("sshkey_fingerprint failed");
			إذا (principal == عدم) {
				چاپ_کړه("Good \"%s\" signature with %s key %s\n",
				    sig_namespace, sshkey_type(sign_کلی), fp);

			} وإلا {
				چاپ_کړه("Good \"%s\" signature for %s with %s key %s\n",
				    sig_namespace, principal,
				    sshkey_type(sign_کلی), fp);
			}
		} وإلا {
			چاپ_کړه("Could not verify signature.\n");
		}
	}
	/* Print the signature key if requested */
	إذا (ret == 0 && print_pubkey && sign_کلی != عدم) {
		إذا ((r = sshkey_write(sign_کلی, stdout)) == 0)
			fputc('\n', stdout);
		وإلا {
			error_r(r, "Could not print public key.\n");
			ret = -1;
		}
	}
	sshbuf_free(sigbuf);
	sshbuf_free(abuf);
	sshkey_free(sign_کلی);
	sshkey_sig_details_free(sig_details);
	حرر(fp);
	أرجع ret;
}

ساكن صحيح
sig_پیدا_کړه_principals(ثابت حرف *signature, ثابت حرف *allowed_کلیګانې,
    حرف * ثابت *opts, اندازه_t nopts)
{
	صحيح r, ret = -1;
	بنية sshbuf *sigbuf = عدم, *abuf = عدم;
	بنية sshkey *sign_کلی = عدم;
	حرف *principals = عدم, *cp, *tmp;
	uint64_t verify_وخت = 0;

	إذا (sig_process_opts(opts, nopts, عدم, &verify_وخت, عدم) != 0)
		اذهب بشپړ; /* error already logged */

	إذا ((r = sshbuf_بارول_file(signature, &abuf)) != 0) {
		error_r(r, "Couldn't read signature file");
		اذهب بشپړ;
	}
	إذا ((r = sshsig_dearmor(abuf, &sigbuf)) != 0) {
		error_fr(r, "sshsig_armor");
		اذهب بشپړ;
	}
	إذا ((r = sshsig_get_pubkey(sigbuf, &sign_کلی)) != 0) {
		error_fr(r, "sshsig_get_pubkey");
		اذهب بشپړ;
	}
	إذا ((r = sshsig_پیدا_کړه_principals(allowed_کلیګانې, sign_کلی,
	    verify_وخت, &principals)) != 0) {
		إذا (r != SSH_ERR_کلی_NOT_وموندل)
			error_fr(r, "sshsig_find_principal");
		اذهب بشپړ;
	}
	ret = 0;
بشپړ:
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
	sshkey_free(sign_کلی);
	حرر(principals);
	أرجع ret;
}

ساكن صحيح
sig_سمون_principals(ثابت حرف *allowed_کلیګانې, حرف *principal,
	حرف * ثابت *opts, اندازه_t nopts)
{
	صحيح r;
	حرف **principals = عدم;
	اندازه_t i, nprincipals = 0;

	إذا ((r = sig_process_opts(opts, nopts, عدم, عدم, عدم)) != 0)
		أرجع r; /* error already logged */

	إذا ((r = sshsig_سمون_principals(allowed_کلیګانې, principal,
	    &principals, &nprincipals)) != 0) {
		debug_f("match: %s", ssh_err(r));
		fprintf(stderr, "No principal matched.\n");
		أرجع r;
	}
	لكل (i = 0; i < nprincipals; i++) {
		چاپ_کړه("%s\n", principals[i]);
		حرر(principals[i]);
	}
	حرر(principals);

	أرجع 0;
}

ساكن فراغ
do_moduli_gen(ثابت حرف *بهر_file, حرف **opts, اندازه_t nopts)
{
#که_تعریف_شوی WITH_OPENSSL
	/* Moduli generation/screening */
	BIGNUM *پیل = عدم;
	صحيح moduli_بټونه = 0;
	FILE *بهر;
	اندازه_t i;
	ثابت حرف *errstr, *p;

	/* Parse options */
	لكل (i = 0; i < nopts; i++) {
		إذا ((p = strprefix(opts[i], "start=", 0)) != عدم) {
			/* XXX - also compare length against bits */
			إذا (BN_hex2bn(&پیل, p) == 0)
				fatal("Invalid start point.");
		} وإلا إذا ((p = strprefix(opts[i], "bits=", 0)) != عدم) {
			moduli_بټونه = (صحيح)strtonum(p, 1, لوی_عدد, &errstr);
			إذا (errstr) {
				fatal("Invalid number: %s (%s)", p, errstr);
			}
		} وإلا {
			fatal("Option \"%s\" is unsupported for moduli "
			    "generation", opts[i]);
		}
	}

	إذا (strcmp(بهر_file, "-") == 0)
		بهر = stdout;
	وإلا إذا ((بهر = fopen(بهر_file, "w")) == عدم) {
		fatal("Couldn't open modulus candidate file \"%s\": %s",
		    بهر_file, strerror(errno));
	}
	setvbuf(بهر, عدم, _IOLBF, 0);

	إذا (moduli_بټونه == 0)
		moduli_بټونه = DEFAULT_بټونه;
	إذا (gen_candidates(بهر, moduli_بټونه, پیل) != 0)
		fatal("modulus candidate generation failed");
#وإلا /* WITH_OPENSSL */
	fatal("Moduli generation is not supported");
#د_که_پای /* WITH_OPENSSL */
}

ساكن فراغ
do_moduli_screen(ثابت حرف *بهر_file, حرف **opts, اندازه_t nopts)
{
#که_تعریف_شوی WITH_OPENSSL
	/* Moduli generation/screening */
	حرف *checkpoint = عدم;
	uint32_t generator_wanted = 0;
	بینښه اوږد پیل_lineno = 0, کرښې_منزل_process = 0;
	صحيح اولي_tests = 0;
	FILE *بهر, *دننه = stdin;
	اندازه_t i;
	ثابت حرف *errstr, *p;

	/* Parse options */
	لكل (i = 0; i < nopts; i++) {
		إذا ((p = strprefix(opts[i], "lines=", 0)) != عدم) {
			کرښې_منزل_process = strtoul(p, عدم, 10);
		} وإلا إذا ((p = strprefix(opts[i], "start-line=", 0)) != عدم) {
			پیل_lineno = strtoul(p, عدم, 10);
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
			اولي_tests = (صحيح)strtonum(p, 1, لوی_عدد, &errstr);
			إذا (errstr) {
				fatal("Invalid number: %s (%s)", p, errstr);
			}
		} وإلا {
			fatal("Option \"%s\" is unsupported for moduli "
			    "screening", opts[i]);
		}
	}

	إذا (have_بې_اغېزه_عنصر && strcmp(بې_اغېزه_عنصر_file, "-") != 0) {
		إذا ((دننه = fopen(بې_اغېزه_عنصر_file, "r")) == عدم) {
			fatal("Couldn't open modulus candidate "
			    "file \"%s\": %s", بې_اغېزه_عنصر_file,
			    strerror(errno));
		}
	}

	إذا (strcmp(بهر_file, "-") == 0)
		بهر = stdout;
	وإلا إذا ((بهر = fopen(بهر_file, "a")) == عدم) {
		fatal("Couldn't open moduli file \"%s\": %s",
		    بهر_file, strerror(errno));
	}
	setvbuf(بهر, عدم, _IOLBF, 0);
	إذا (اولي_test(دننه, بهر, اولي_tests == 0 ? 100 : اولي_tests,
	    generator_wanted, checkpoint,
	    پیل_lineno, کرښې_منزل_process) != 0)
		fatal("modulus screening failed");
	إذا (دننه != stdin)
		(فراغ)fclose(دننه);
	حرر(checkpoint);
#وإلا /* WITH_OPENSSL */
	fatal("Moduli screening is not supported");
#د_که_پای /* WITH_OPENSSL */
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
			freezero(passphrase2, مزي_اوږدوالی(passphrase2));
			أرجع passphrase1;
		}
		/* The passphrases do not match. Clear them and retry. */
		freezero(passphrase1, مزي_اوږدوالی(passphrase1));
		freezero(passphrase2, مزي_اوږدوالی(passphrase2));
		fputs(retry_prompt, stdout);
		fputc('\n', stdout);
		fflush(stdout);
	}
	/* NOTREACHED */
	أرجع عدم;
}

ساكن حرف *
شخصي_کلی_passphrase(ثابت حرف *لار)
{
	حرف *prompt, *ret;

	إذا (بې_اغېزه_عنصر_passphrase)
		أرجع xstrdup(بې_اغېزه_عنصر_passphrase);
	إذا (بې_اغېزه_عنصر_new_passphrase)
		أرجع xstrdup(بې_اغېزه_عنصر_new_passphrase);

	xasprintf(&prompt, "Enter passphrase for \"%s\" "
	    "(empty for no passphrase): ", لار);
	ret = read_check_passphrase(prompt,
	    "Enter same passphrase again: ",
	    "Passphrases do not match.  Try again.");
	حرر(prompt);
	أرجع ret;
}

ساكن حرف *
sk_suffix(ثابت حرف *application, ثابت uint8_t *user, اندازه_t userlen)
{
	حرف *ret, *cp;
	ثابت حرف *p;
	اندازه_t slen, i;

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
	إذا (asmprintf(&cp, لوی_عدد, عدم, "%.*s", (صحيح)slen, user) == -1)
		fatal_f("asmprintf failed");
	/* Don't emit a user-id that contains path or control characters */
	إذا (strchr(cp, '/') != عدم || مزي_پلټنه(cp, "..") != عدم ||
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
	بنية sshsk_resident_کلی **srks;
	اندازه_t nsrks, i;
	صحيح r, ret = -1;
	حرف *fp, *pin = عدم, *pass = عدم, *لار, *pubpath;
	ثابت حرف *ext;
	بنية sshkey *کلی;

	إذا (skprovider == عدم)
		fatal("Cannot download keys without provider");

	pin = read_passphrase("Enter PIN for authenticator: ", RP_ALLOW_STDIN);
	إذا (!quiet) {
		چاپ_کړه("You may need to touch your authenticator "
		    "to authorize key download.\n");
	}
	إذا ((r = sshsk_بارول_resident(skprovider, device, pin, 0,
	    &srks, &nsrks)) != 0) {
		إذا (pin != عدم)
			freezero(pin, مزي_اوږدوالی(pin));
		error_r(r, "Unable to load resident keys");
		أرجع -1;
	}
	إذا (nsrks == 0)
		logit("No keys to download");
	إذا (pin != عدم)
		freezero(pin, مزي_اوږدوالی(pin));

	لكل (i = 0; i < nsrks; i++) {
		کلی = srks[i]->کلی;
		إذا (کلی->type != کلی_ECDSA_SK && کلی->type != کلی_ED25519_SK) {
			error("Unsupported key type %s (%d)",
			    sshkey_type(کلی), کلی->type);
			استمر;
		}
		إذا ((fp = sshkey_fingerprint(کلی, fingerprint_hash,
		    SSH_FP_DEFAULT)) == عدم)
			fatal_f("sshkey_fingerprint failed");
		debug_f("key %zu: %s %s %s (flags 0x%02x)", i,
		    sshkey_type(کلی), fp, کلی->sk_application, کلی->sk_flags);
		ext = sk_suffix(کلی->sk_application,
		    srks[i]->user_id, srks[i]->user_id_len);
		xasprintf(&لار, "id_%s_rk%s%s",
		    کلی->type == کلی_ECDSA_SK ? "ecdsa_sk" : "ed25519_sk",
		    *ext == '\0' ? "" : "_", ext);

		/* If the file already exists, ask the user to confirm. */
		إذا (!confirm_overwrite(لار)) {
			حرر(لار);
			اكسر;
		}

		/* Save the key with the application string as the comment */
		إذا (pass == عدم)
			pass = شخصي_کلی_passphrase(لار);
		إذا ((r = sshkey_save_شخصي(کلی, لار, pass,
		    کلی->sk_application, شخصي_کلی_format,
		    openssh_format_cipher, پړاوونه)) != 0) {
			error_r(r, "Saving key \"%s\" failed", لار);
			حرر(لار);
			اكسر;
		}
		إذا (!quiet) {
			چاپ_کړه("Saved %s key%s%s to %s\n", sshkey_type(کلی),
			    *ext != '\0' ? " " : "",
			    *ext != '\0' ? کلی->sk_application : "",
			    لار);
		}

		/* Save public key too */
		xasprintf(&pubpath, "%s.pub", لار);
		حرر(لار);
		إذا ((r = sshkey_save_عامه(کلی, pubpath,
		    کلی->sk_application)) != 0) {
			error_r(r, "Saving public key \"%s\" failed", pubpath);
			حرر(pubpath);
			اكسر;
		}
		حرر(pubpath);
	}

	إذا (i >= nsrks)
		ret = 0; /* success */
	إذا (pass != عدم)
		freezero(pass, مزي_اوږدوالی(pass));
	sshsk_free_resident_کلیګانې(srks, nsrks);
	أرجع ret;
}

ساكن فراغ
save_attestation(بنية sshbuf *attest, ثابت حرف *لار)
{
	ډېرپېښ_t omask;
	صحيح r;

	إذا (لار == عدم)
		أرجع; /* nothing to do */
	إذا (attest == عدم || sshbuf_len(attest) == 0)
		fatal("Enrollment did not return attestation data");
	omask = umask(077);
	r = sshbuf_write_file(لار, attest);
	umask(omask);
	إذا (r != 0)
		fatal_r(r, "Unable to write attestation data \"%s\"", لار);
	إذا (!quiet)
		چاپ_کړه("Your FIDO attestation certificate has been saved in "
		    "%s\n", لار);
}

ساكن صحيح
confirm_sk_overwrite(ثابت حرف *application, ثابت حرف *user)
{
	حرف yesno[3];

	چاپ_کړه("A resident key scoped to '%s' with user id '%s' already "
	    "exists.\n", application == عدم ? "ssh:" : application,
	    user == عدم ? "null" : user);
	چاپ_کړه("Overwrite key in token (y/n)? ");
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
#که_تعریف_شوی WITH_OPENSSL
	    "       ssh-keygen -i [-f input_keyfile] [-m key_format]\n"
	    "       ssh-keygen -e [-f input_keyfile] [-m key_format]\n"
#د_که_پای
	    "       ssh-keygen -y [-f input_keyfile]\n"
	    "       ssh-keygen -c [-a rounds] [-C comment] [-f keyfile] [-P passphrase]\n"
	    "       ssh-keygen -l [-v] [-E fingerprint_hash] [-f input_keyfile]\n"
	    "       ssh-keygen -B [-f input_keyfile]\n");
#که_تعریف_شوی ENABLE_PKCS11
	fprintf(stderr,
	    "       ssh-keygen -D pkcs11\n");
#د_که_پای
	fprintf(stderr,
	    "       ssh-keygen -F hostname [-lv] [-f known_hosts_file]\n"
	    "       ssh-keygen -H [-f known_hosts_file]\n"
	    "       ssh-keygen -K [-a rounds] [-w provider]\n"
	    "       ssh-keygen -R hostname [-f known_hosts_file]\n"
	    "       ssh-keygen -r hostname [-g] [-f input_keyfile]\n"
#که_تعریف_شوی WITH_OPENSSL
	    "       ssh-keygen -M generate [-O option] output_file\n"
	    "       ssh-keygen -M screen [-f input_file] [-O option] output_file\n"
#د_که_پای
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
	وتل(1);
}

/*
 * Main program for key management.
 */
صحيح
اصلي(صحيح argc, حرف **argv)
{
	حرف comment[کلی_COMMENT_MAX], *passphrase = عدم;
	حرف *rr_hostname = عدم, *ep, *fp, *ra;
	بنية sshkey *خاص = عدم, *عام = عدم;
	بنية passwd *pw;
	صحيح ret = 0, r, opt, type;
	صحيح change_passphrase = 0, change_comment = 0, show_cert = 0;
	صحيح پیدا_کړه_host = 0, delete_host = 0, hash_hosts = 0;
	صحيح gen_all_hostkeys = 0, gen_krl = 0, update_krl = 0, check_krl = 0;
	صحيح prefer_agent = 0, convert_منزل = 0, convert_from = 0;
	صحيح print_عامه = 0, print_generic = 0, cert_serial_autoinc = 0;
	صحيح do_gen_candidates = 0, do_screen_candidates = 0, download_sk = 0;
	بینښه اوږد اوږد cert_serial = 0;
	حرف *بې_اغېزه_عنصر_comment = عدم, *ca_کلی_لار = عدم, **opts = عدم;
	حرف *sk_application = عدم, *sk_device = عدم, *sk_user = عدم;
	حرف *sk_attestation_لار = عدم;
	بنية sshbuf *challenge = عدم, *attest = عدم;
	اندازه_t i, nopts = 0;
	uint32_t بټونه = 0;
	uint8_t sk_flags = SSH_SK_USER_PRESENCE_REQD;
	ثابت حرف *errstr, *p;
	صحيح log_level = SYSLOG_LEVEL_INFO;
	حرف *sign_op = عدم;

	خارجي صحيح optind;
	خارجي حرف *optarg;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	__progname = ssh_get_progname(argv[0]);

	تخم_rng();

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
			بټونه = (uint32_t)strtonum(optarg, 1, UINT32_MAX,
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
			پیدا_کړه_host = 1;
			rr_hostname = optarg;
			اكسر;
		حالة 'H':
			hash_hosts = 1;
			اكسر;
		حالة 'I':
			cert_کلی_id = optarg;
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
				شخصي_کلی_format = SSHKEY_شخصي_PKCS8;
				اكسر;
			}
			إذا (strcasecmp(optarg, "PEM") == 0) {
				convert_format = FMT_PEM;
				شخصي_کلی_format = SSHKEY_شخصي_PEM;
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
			إذا (strlcpy(بې_اغېزه_عنصر_file, optarg,
			    حجم(بې_اغېزه_عنصر_file)) >= حجم(بې_اغېزه_عنصر_file))
				fatal("Identity filename too long");
			have_بې_اغېزه_عنصر = 1;
			اكسر;
		حالة 'g':
			print_generic = 1;
			اكسر;
		حالة 'K':
			download_sk = 1;
			اكسر;
		حالة 'P':
			بې_اغېزه_عنصر_passphrase = optarg;
			اكسر;
		حالة 'N':
			بې_اغېزه_عنصر_new_passphrase = optarg;
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
			بې_اغېزه_عنصر_comment = optarg;
			اكسر;
		حالة 'q':
			quiet = 1;
			اكسر;
		حالة 'e':
			/* export key */
			convert_منزل = 1;
			اكسر;
		حالة 'h':
			cert_کلی_type = SSH2_CERT_TYPE_HOST;
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
			print_عامه = 1;
			اكسر;
		حالة 's':
			ca_کلی_لار = optarg;
			اكسر;
		حالة 't':
			کلی_type_name = optarg;
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
			پړاوونه = (صحيح)strtonum(optarg, 1, لوی_عدد, &errstr);
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

#که_تعریف_شوی ENABLE_SK_دننی
	إذا (sk_provider == عدم)
		sk_provider = "internal";
#د_که_پای

	/* reinit */
	log_init(argv[0], log_level, SYSLOG_FACILITY_USER, 1);

	argv += optind;
	argc -= optind;

	إذا (sign_op != عدم) {
		إذا (strprefix(sign_op, "find-principals", 0) != عدم) {
			إذا (ca_کلی_لار == عدم) {
				error("Too few arguments for find-principals:"
				    "missing signature file");
				وتل(1);
			}
			إذا (!have_بې_اغېزه_عنصر) {
				error("Too few arguments for find-principals:"
				    "missing allowed keys file");
				وتل(1);
			}
			ret = sig_پیدا_کړه_principals(ca_کلی_لار, بې_اغېزه_عنصر_file,
			    opts, nopts);
			اذهب بشپړ;
		} وإلا إذا (strprefix(sign_op, "match-principals", 0) != عدم) {
			إذا (!have_بې_اغېزه_عنصر) {
				error("Too few arguments for match-principals:"
				    "missing allowed keys file");
				وتل(1);
			}
			إذا (cert_کلی_id == عدم) {
				error("Too few arguments for match-principals: "
				    "missing principal ID");
				وتل(1);
			}
			ret = sig_سمون_principals(بې_اغېزه_عنصر_file, cert_کلی_id,
			    opts, nopts);
			اذهب بشپړ;
		} وإلا إذا (strprefix(sign_op, "sign", 0) != عدم) {
			/* NB. cert_principals is actually namespace, via -n */
			إذا (cert_principals == عدم ||
			    *cert_principals == '\0') {
				error("Too few arguments for sign: "
				    "missing namespace");
				وتل(1);
			}
			إذا (!have_بې_اغېزه_عنصر) {
				error("Too few arguments for sign: "
				    "missing key");
				وتل(1);
			}
			ret = sig_sign(بې_اغېزه_عنصر_file, cert_principals,
			    prefer_agent, argc, argv, opts, nopts);
			اذهب بشپړ;
		} وإلا إذا (strprefix(sign_op, "check-novalidate", 0) != عدم) {
			/* NB. cert_principals is actually namespace, via -n */
			إذا (cert_principals == عدم ||
			    *cert_principals == '\0') {
				error("Too few arguments for check-novalidate: "
				    "missing namespace");
				وتل(1);
			}
			إذا (ca_کلی_لار == عدم) {
				error("Too few arguments for check-novalidate: "
				    "missing signature file");
				وتل(1);
			}
			ret = sig_verify(ca_کلی_لار, cert_principals,
			    عدم, عدم, عدم, opts, nopts);
			اذهب بشپړ;
		} وإلا إذا (strprefix(sign_op, "verify", 0) != عدم) {
			/* NB. cert_principals is actually namespace, via -n */
			إذا (cert_principals == عدم ||
			    *cert_principals == '\0') {
				error("Too few arguments for verify: "
				    "missing namespace");
				وتل(1);
			}
			إذا (ca_کلی_لار == عدم) {
				error("Too few arguments for verify: "
				    "missing signature file");
				وتل(1);
			}
			إذا (!have_بې_اغېزه_عنصر) {
				error("Too few arguments for sign: "
				    "missing allowed keys file");
				وتل(1);
			}
			إذا (cert_کلی_id == عدم) {
				error("Too few arguments for verify: "
				    "missing principal identity");
				وتل(1);
			}
			ret = sig_verify(ca_کلی_لار, cert_principals,
			    cert_کلی_id, بې_اغېزه_عنصر_file, rr_hostname,
			    opts, nopts);
			اذهب بشپړ;
		}
		error("Unsupported operation for -Y: \"%s\"", sign_op);
		usage();
		/* NOTREACHED */
	}

	إذا (ca_کلی_لار != عدم) {
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
		do_gen_krl(pw, update_krl, ca_کلی_لار,
		    cert_serial, بې_اغېزه_عنصر_comment, argc, argv);
		اذهب بشپړ;
	}
	إذا (check_krl) {
		do_check_krl(pw, print_fingerprint, argc, argv);
		اذهب بشپړ;
	}
	إذا (ca_کلی_لار != عدم) {
		إذا (cert_کلی_id == عدم)
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
			جمع_کړه_cert_option(opts[i]);
		do_ca_sign(pw, ca_کلی_لار, prefer_agent,
		    cert_serial, cert_serial_autoinc, argc, argv);
		اذهب بشپړ;
	}
	إذا (show_cert)
		do_show_cert(pw);
	إذا (delete_host || hash_hosts || پیدا_کړه_host) {
		do_معلوم_hosts(pw, rr_hostname, پیدا_کړه_host,
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
		اذهب بشپړ;
	}
	إذا (print_fingerprint || print_bubblebabble)
		do_fingerprint(pw);
	إذا (change_passphrase)
		do_change_passphrase(pw, opts, nopts);
	إذا (change_comment)
		do_change_comment(pw, بې_اغېزه_عنصر_comment);
#که_تعریف_شوی WITH_OPENSSL
	إذا (convert_منزل) {
		do_convert_منزل(pw);
		اذهب بشپړ;
	}
	إذا (convert_from) {
		do_convert_from(pw);
		اذهب بشپړ;
	}
#وإلا /* WITH_OPENSSL */
	إذا (convert_منزل || convert_from)
		fatal("key conversion disabled at compile time");
#د_که_پای /* WITH_OPENSSL */
	إذا (print_عامه)
		do_print_عامه(pw);
	إذا (rr_hostname != عدم) {
		بینښه صحيح n = 0;

		إذا (have_بې_اغېزه_عنصر) {
			n = do_print_resource_ریکارډ(pw, بې_اغېزه_عنصر_file,
			    rr_hostname, print_generic, opts, nopts);
			إذا (n == 0)
				fatal("%s: %s", بې_اغېزه_عنصر_file, strerror(errno));
			وتل(0);
		} وإلا {

			n += do_print_resource_ریکارډ(pw,
			    لار_HOST_RSA_کلی_FILE, rr_hostname,
			    print_generic, opts, nopts);
			n += do_print_resource_ریکارډ(pw,
			    لار_HOST_ECDSA_کلی_FILE, rr_hostname,
			    print_generic, opts, nopts);
			n += do_print_resource_ریکارډ(pw,
			    لار_HOST_ED25519_کلی_FILE, rr_hostname,
			    print_generic, opts, nopts);
			إذا (n == 0)
				fatal("no keys found.");
			وتل(0);
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
		اذهب بشپړ;
	}
	إذا (do_screen_candidates) {
		do_moduli_screen(argv[0], opts, nopts);
		اذهب بشپړ;
	}

	إذا (gen_all_hostkeys) {
		do_gen_all_hostkeys(pw);
		اذهب بشپړ;
	}

	إذا (کلی_type_name == عدم)
		کلی_type_name = DEFAULT_کلی_TYPE_NAME;

	type = sshkey_type_from_shortname(کلی_type_name);
	type_بټونه_valid(type, کلی_type_name, &بټونه);

	إذا (!quiet)
		چاپ_کړه("Generating public/private %s key pair.\n",
		    کلی_type_name);
	بدل (type) {
	حالة کلی_ECDSA_SK:
	حالة کلی_ED25519_SK:
		لكل (i = 0; i < nopts; i++) {
			إذا (strcasecmp(opts[i], "no-touch-required") == 0) {
				sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
			} وإلا إذا (strcasecmp(opts[i], "verify-required") == 0) {
				sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
			} وإلا إذا (strcasecmp(opts[i], "resident") == 0) {
				sk_flags |= SSH_SK_RESIDENT_کلی;
			} وإلا إذا ((p = strprefix(opts[i], "device=", 1))
			    != عدم ) {
				sk_device = xstrdup(p);
			} وإلا إذا ((p = strprefix(opts[i], "user=", 1))
			    != عدم) {
				sk_user = xstrdup(p);
			} وإلا إذا ((p = strprefix(opts[i], "challenge=", 1))
			    != عدم) {
				إذا ((r = sshbuf_بارول_file(p,
				    &challenge)) != 0) {
					fatal_r(r, "Unable to load FIDO "
					    "enrollment challenge \"%s\"", p);
				}
			} وإلا إذا (strncasecmp(opts[i],
			    "write-attestation=", 18) == 0) {
				sk_attestation_لار = opts[i] + 18;
			} وإلا إذا (strncasecmp(opts[i],
			    "application=", 12) == 0) {
				sk_application = xstrdup(opts[i] + 12);
				إذا (مزي_پرتله(sk_application, "ssh:", 4) != 0) {
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
				چاپ_کړه("You may need to touch your "
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
			إذا (r == SSH_ERR_کلی_BAD_PERMISSIONS &&
			    (sk_flags & SSH_SK_RESIDENT_کلی) != 0 &&
			    (sk_flags & SSH_SK_FORCE_OPERATION) == 0 &&
			    confirm_sk_overwrite(sk_application, sk_user)) {
				sk_flags |= SSH_SK_FORCE_OPERATION;
				استمر;
			}
			إذا (r != SSH_ERR_کلی_WRONG_PASSPHRASE)
				fatal_r(r, "Key enrollment failed");
			وإلا إذا (passphrase != عدم) {
				error("PIN incorrect");
				freezero(passphrase, مزي_اوږدوالی(passphrase));
				passphrase = عدم;
			}
			إذا (++i >= 3)
				fatal("Too many incorrect PINs");
			passphrase = read_passphrase("Enter PIN for "
			    "authenticator: ", RP_ALLOW_STDIN);
		}
		إذا (passphrase != عدم) {
			freezero(passphrase, مزي_اوږدوالی(passphrase));
			passphrase = عدم;
		}
		اكسر;
	افتراضي:
		إذا ((r = sshkey_generate(type, بټونه, &خاص)) != 0)
			fatal("sshkey_generate failed");
		اكسر;
	}
	إذا ((r = sshkey_from_شخصي(خاص, &عام)) != 0)
		fatal_r(r, "sshkey_from_private");

	إذا (!have_بې_اغېزه_عنصر)
		ask_filename(pw, "Enter file in which to save the key");

	/* Create ~/.ssh directory if it doesn't already exist. */
	hostfile_create_user_ssh_dir(بې_اغېزه_عنصر_file, !quiet);

	/* If the file already exists, ask the user to confirm. */
	إذا (!confirm_overwrite(بې_اغېزه_عنصر_file))
		وتل(1);

	/* Determine the passphrase for the private key */
	passphrase = شخصي_کلی_passphrase(بې_اغېزه_عنصر_file);
	إذا (بې_اغېزه_عنصر_comment) {
		strlcpy(comment, بې_اغېزه_عنصر_comment, حجم(comment));
	} وإلا {
		/* Create default comment field for the passphrase. */
		snprintf(comment, حجم comment, "%s@%s", pw->pw_name, hostname);
	}



	/* Save the key with the given passphrase and comment. */
	إذا ((r = sshkey_save_شخصي(خاص, بې_اغېزه_عنصر_file, passphrase,
	    comment, شخصي_کلی_format, openssh_format_cipher, پړاوونه)) != 0) {
		error_r(r, "Saving key \"%s\" failed", بې_اغېزه_عنصر_file);
		freezero(passphrase, مزي_اوږدوالی(passphrase));
		وتل(1);
	}
	freezero(passphrase, مزي_اوږدوالی(passphrase));
	sshkey_free(خاص);

	إذا (!quiet) {
		چاپ_کړه("Your identification has been saved in %s\n",
		    بې_اغېزه_عنصر_file);
	}

	strlcat(بې_اغېزه_عنصر_file, ".pub", حجم(بې_اغېزه_عنصر_file));
	إذا ((r = sshkey_save_عامه(عام, بې_اغېزه_عنصر_file, comment)) != 0)
		fatal_r(r, "Unable to save public key to %s", بې_اغېزه_عنصر_file);

	إذا (!quiet) {
		fp = sshkey_fingerprint(عام, fingerprint_hash,
		    SSH_FP_DEFAULT);
		ra = sshkey_fingerprint(عام, fingerprint_hash,
		    SSH_FP_RANDOMART);
		إذا (fp == عدم || ra == عدم)
			fatal("sshkey_fingerprint failed");
		چاپ_کړه("Your public key has been saved in %s\n",
		    بې_اغېزه_عنصر_file);
		چاپ_کړه("The key fingerprint is:\n");
		چاپ_کړه("%s %s\n", fp, comment);
		چاپ_کړه("The key's randomart image is:\n");
		چاپ_کړه("%s\n", ra);
		حرر(ra);
		حرر(fp);
	}

	إذا (sk_attestation_لار != عدم)
		save_attestation(attest, sk_attestation_لار);

 بشپړ:
	sshbuf_free(attest);
	sshkey_free(عام);
	pwfree(pw);
	وتل(ret);
}
