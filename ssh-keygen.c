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

#ifdef WITH_OPENSSL
#ضمن "openbsd-compat/openssl-compat.h"
#ضمن <openssl/bn.h>
#ضمن <openssl/evp.h>
#ضمن <openssl/pem.h>
#endif

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

#ifdef ENABLE_PKCS11
#ضمن "ssh-pkcs11.h"
#endif

#define DEFAULT_KEY_TYPE_NAME "ed25519"

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

#define KEY_COMMENT_MAX		(NI_MAXHOST + 1024)

ساكن صحيح quiet = 0;

/* Flag indicating that we just want to see the key fingerprint */
ساكن صحيح print_fingerprint = 0;
ساكن صحيح print_bubblebabble = 0;

/* Hash algorithm to use for fingerprints. */
ساكن صحيح fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* The identity file name, given on the command line or entered by the user. */
ساكن حرف identity_file[PATH_MAX];
ساكن صحيح have_identity = 0;

/* This is set to the passphrase if given on the command line. */
ساكن حرف *identity_passphrase = عدم;

/* This is set to the new passphrase if given on the command line. */
ساكن حرف *identity_new_passphrase = عدم;

/* Key type when certifying */
ساكن u_int cert_key_type = SSH2_CERT_TYPE_USER;

/* "key ID" of signed key */
ساكن حرف *cert_key_id = عدم;

/* Comma-separated list of principal names for certifying keys */
ساكن حرف *cert_principals = عدم;

/* Validity period for certificates */
ساكن uint64_t cert_valid_from = 0;
ساكن uint64_t cert_valid_to = ~0ULL;

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
ساكن uint32_t certflags_flags = CERTOPT_DEFAULT;
ساكن حرف *certflags_command = عدم;
ساكن حرف *certflags_src_addr = عدم;

/* Arbitrary extensions specified by user */
بنية cert_ext {
	حرف *key;
	حرف *val;
	صحيح crit;
};
ساكن بنية cert_ext *cert_ext;
ساكن size_t ncert_ext;

/* Conversion to/from various formats */
تعداد {
	FMT_RFC4716,
	FMT_PKCS8,
	FMT_PEM,
	FMT_HEXDUMP
} convert_format = FMT_RFC4716;

ساكن حرف *key_type_name = عدم;

/* Load key from this PKCS#11 provider */
ساكن حرف *pkcs11provider = عدم;

/* FIDO/U2F provider to use */
ساكن حرف *sk_provider = عدم;

/* Format for writing private keys */
ساكن صحيح private_key_format = SSHKEY_PRIVATE_OPENSSH;

/* Cipher for new-format private keys */
ساكن حرف *openssh_format_cipher = عدم;

/* Number of KDF rounds to derive new format keys. */
ساكن صحيح rounds = 0;

/* argv0 */
خارجي حرف *__progname;

ساكن حرف hostname[NI_MAXHOST];

#ifdef WITH_OPENSSL
/* moduli.c */
صحيح gen_candidates(FILE *, uint32_t, BIGNUM *);
صحيح prime_test(FILE *, FILE *, uint32_t, uint32_t, حرف *, unsigned long,
    unsigned long);
#endif

ساكن فراغ
type_bits_valid(صحيح type, ثابت حرف *name, uint32_t *bitsp)
{
	אם (type == KEY_UNSPEC)
		fatal("unknown key type %s", key_type_name);
	אם (*bitsp == 0) {
#ifdef WITH_OPENSSL
		صحيح nid;

		بدل(type) {
		حالة KEY_ECDSA:
			אם (name != عدم &&
			    (nid = sshkey_ecdsa_nid_from_name(name)) > 0)
				*bitsp = sshkey_curve_nid_to_bits(nid);
			אם (*bitsp == 0)
				*bitsp = DEFAULT_BITS_ECDSA;
			اكسر;
		حالة KEY_RSA:
			*bitsp = DEFAULT_BITS;
			اكسر;
		}
#endif
	}
#ifdef WITH_OPENSSL
	بدل (type) {
	حالة KEY_RSA:
		אם (*bitsp < SSH_RSA_MINIMUM_MODULUS_SIZE)
			fatal("Invalid RSA key length: minimum is %d bits",
			    SSH_RSA_MINIMUM_MODULUS_SIZE);
		אחרת אם (*bitsp > OPENSSL_RSA_MAX_MODULUS_BITS)
			fatal("Invalid RSA key length: maximum is %d bits",
			    OPENSSL_RSA_MAX_MODULUS_BITS);
		اكسر;
	حالة KEY_ECDSA:
		אם (sshkey_ecdsa_bits_to_nid(*bitsp) == -1)
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
ساكن صحيح
confirm_overwrite(ثابت حرف *filename)
{
	حرف yesno[3];
	بنية stat st;

	אם (stat(filename, &st) != 0)
		החזר 1;
	printf("%s already exists.\n", filename);
	printf("Overwrite (y/n)? ");
	fflush(stdout);
	אם (fgets(yesno, حجم(yesno), stdin) == عدم)
		החזר 0;
	אם (yesno[0] != 'y' && yesno[0] != 'Y')
		החזר 0;
	החזר 1;
}

ساكن فراغ
ask_filename(بنية passwd *pw, ثابت حرف *prompt)
{
	حرف buf[1024];
	حرف *name = عدم;

	אם (key_type_name == عدم)
		name = _PATH_SSH_CLIENT_ID_ED25519;
	אחרת {
		بدل (sshkey_type_from_shortname(key_type_name)) {
		حالة KEY_ECDSA_CERT:
		حالة KEY_ECDSA:
			name = _PATH_SSH_CLIENT_ID_ECDSA;
			اكسر;
		حالة KEY_ECDSA_SK_CERT:
		حالة KEY_ECDSA_SK:
			name = _PATH_SSH_CLIENT_ID_ECDSA_SK;
			اكسر;
		حالة KEY_RSA_CERT:
		حالة KEY_RSA:
			name = _PATH_SSH_CLIENT_ID_RSA;
			اكسر;
		حالة KEY_ED25519:
		حالة KEY_ED25519_CERT:
			name = _PATH_SSH_CLIENT_ID_ED25519;
			اكسر;
		حالة KEY_ED25519_SK:
		حالة KEY_ED25519_SK_CERT:
			name = _PATH_SSH_CLIENT_ID_ED25519_SK;
			اكسر;
		حالة KEY_MLDSA44_ED25519:
		حالة KEY_MLDSA44_ED25519_CERT:
			name = _PATH_SSH_CLIENT_ID_MLDSA44_ED25519;
			اكسر;
		افتراضي:
			fatal("bad key type");
		}
	}
	snprintf(identity_file, حجم(identity_file),
	    "%s/%s", pw->pw_dir, name);
	printf("%s (%s): ", prompt, identity_file);
	fflush(stdout);
	אם (fgets(buf, حجم(buf), stdin) == عدم)
		exit(1);
	buf[strcspn(buf, "\n")] = '\0';
	אם (strcmp(buf, "") != 0)
		strlcpy(identity_file, buf, حجم(identity_file));
	have_identity = 1;
}

ساكن بنية sshkey *
load_identity(ثابت حرف *filename, حرف **commentp)
{
	حرف *prompt, *pass;
	بنية sshkey *prv;
	صحيح r;

	אם (commentp != عدم)
		*commentp = عدم;
	אם ((r = sshkey_load_private(filename, "", &prv, commentp)) == 0)
		החזר prv;
	אם (r != SSH_ERR_KEY_WRONG_PASSPHRASE)
		fatal_r(r, "Load key \"%s\"", filename);
	אם (identity_passphrase)
		pass = xstrdup(identity_passphrase);
	אחרת {
		xasprintf(&prompt, "Enter passphrase for \"%s\": ", filename);
		pass = read_passphrase(prompt, RP_ALLOW_STDIN);
		حرر(prompt);
	}
	r = sshkey_load_private(filename, pass, &prv, commentp);
	freezero(pass, strlen(pass));
	אם (r != 0)
		fatal_r(r, "Load key \"%s\"", filename);
	החזר prv;
}

#define SSH_COM_PUBLIC_BEGIN		"---- BEGIN SSH2 PUBLIC KEY ----"
#define SSH_COM_PUBLIC_END		"---- END SSH2 PUBLIC KEY ----"
#define SSH_COM_PRIVATE_BEGIN		"---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----"
#define	SSH_COM_PRIVATE_KEY_MAGIC	0x3f6ff9eb

#ifdef WITH_OPENSSL
ساكن فراغ
do_convert_to_ssh2(بنية passwd *pw, بنية sshkey *k)
{
	بنية sshbuf *b;
	حرف comment[61], *b64;
	صحيح r;

	אם ((b = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	אם ((r = sshkey_putb(k, b)) != 0)
		fatal_fr(r, "put key");
	אם ((b64 = sshbuf_dtob64_string(b, 1)) == عدم)
		fatal_f("sshbuf_dtob64_string failed");

	/* Comment + surrounds must fit into 72 chars (RFC 4716 sec 3.3) */
	snprintf(comment, حجم(comment),
	    "%u-bit %s, converted by %s@%s from OpenSSH",
	    sshkey_size(k), sshkey_type(k),
	    pw->pw_name, hostname);

	sshkey_free(k);
	sshbuf_free(b);

	fprintf(stdout, "%s\n", SSH_COM_PUBLIC_BEGIN);
	fprintf(stdout, "Comment: \"%s\"\n%s", comment, b64);
	fprintf(stdout, "%s\n", SSH_COM_PUBLIC_END);
	حرر(b64);
}

ساكن فراغ
do_convert_to_pkcs8(بنية sshkey *k)
{
	بدل (sshkey_type_plain(k->type)) {
	حالة KEY_RSA:
		אם (!PEM_write_RSA_PUBKEY(stdout,
		    EVP_PKEY_get0_RSA(k->pkey)))
			fatal("PEM_write_RSA_PUBKEY failed");
		اكسر;
	حالة KEY_ECDSA:
		אם (!PEM_write_EC_PUBKEY(stdout,
		    EVP_PKEY_get0_EC_KEY(k->pkey)))
			fatal("PEM_write_EC_PUBKEY failed");
		اكسر;
	افتراضي:
		fatal_f("unsupported key type %s", sshkey_type(k));
	}
}

ساكن فراغ
do_convert_to_pem(بنية sshkey *k)
{
	بدل (sshkey_type_plain(k->type)) {
	حالة KEY_RSA:
		אם (!PEM_write_RSAPublicKey(stdout,
		    EVP_PKEY_get0_RSA(k->pkey)))
			fatal("PEM_write_RSAPublicKey failed");
		اكسر;
	حالة KEY_ECDSA:
		אם (!PEM_write_EC_PUBKEY(stdout,
		    EVP_PKEY_get0_EC_KEY(k->pkey)))
			fatal("PEM_write_EC_PUBKEY failed");
		اكسر;
	افتراضي:
		fatal_f("unsupported key type %s", sshkey_type(k));
	}
}

ساكن فراغ
do_convert_to_hexdump(بنية sshkey *k)
{
	بنية sshbuf *b;
	صحيح r;

	אם ((b = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	/* pubkey */
	אם ((r = sshkey_putb(k, b)) != 0)
		fatal_fr(r, "serialise private");
	printf("Public %s key:\n", sshkey_type(k));
	sshbuf_dump(b, stdout);
	sshbuf_reset(b);
	אם ((r = sshkey_private_serialize(k, b)) != 0) {
		debug_fr(r, "serialise private");
		اذهب out;
	}
	printf("\nPrivate %s key:\n", sshkey_type(k));
	sshbuf_dump(b, stdout);
 out:
	sshbuf_free(b);
}

ساكن فراغ
do_convert_to(بنية passwd *pw)
{
	بنية sshkey *k = عدم;
	بنية stat st;
	صحيح r;

	אם (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	אם (stat(identity_file, &st) == -1)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));

	/* If we're trying to hexdump, then prefer the private key */
	אם (convert_format == FMT_HEXDUMP) {
		אם ((r = sshkey_load_private(identity_file,
		    عدم, &k, عدم)) != 0 &&
		    r == SSH_ERR_KEY_WRONG_PASSPHRASE)
			k = load_identity(identity_file, عدم);
	}
	אם (k == عدم && (r = sshkey_load_public(identity_file, &k, عدم)) != 0)
		k = load_identity(identity_file, عدم);

	بدل (convert_format) {
	حالة FMT_RFC4716:
		do_convert_to_ssh2(pw, k);
		اكسر;
	حالة FMT_PKCS8:
		do_convert_to_pkcs8(k);
		اكسر;
	حالة FMT_PEM:
		do_convert_to_pem(k);
		اكسر;
	حالة FMT_HEXDUMP:
		do_convert_to_hexdump(k);
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
buffer_get_bignum_bits(بنية sshbuf *b, BIGNUM *value)
{
	u_int bytes, bignum_bits;
	صحيح r;

	אם ((r = sshbuf_get_u32(b, &bignum_bits)) != 0)
		fatal_fr(r, "parse");
	bytes = (bignum_bits + 7) / 8;
	אם (sshbuf_len(b) < bytes)
		fatal_f("input buffer too small: need %d have %zu",
		    bytes, sshbuf_len(b));
	אם (BN_bin2bn(sshbuf_ptr(b), bytes, value) == عدم)
		fatal_f("BN_bin2bn failed");
	אם ((r = sshbuf_consume(b, bytes)) != 0)
		fatal_fr(r, "consume");
}

ساكن بنية sshkey *
do_convert_private_ssh2(بنية sshbuf *b)
{
	بنية sshkey *key = عدم;
	حرف *type, *cipher;
	ثابت حرف *alg = عدم;
	u_char e1, e2, e3, *sig = عدم, data[] = "abcde12345";
	صحيح r, rlen, ktype;
	u_int magic, i1, i2, i3, i4;
	size_t slen;
	u_long e;
	BIGNUM *rsa_n = عدم, *rsa_e = عدم, *rsa_d = عدم;
	BIGNUM *rsa_p = عدم, *rsa_q = عدم, *rsa_iqmp = عدم;
	BIGNUM *rsa_dmp1 = عدم, *rsa_dmq1 = عدم;
	RSA *rsa = عدم;

	אם ((r = sshbuf_get_u32(b, &magic)) != 0)
		fatal_fr(r, "parse magic");

	אם (magic != SSH_COM_PRIVATE_KEY_MAGIC) {
		error("bad magic 0x%x != 0x%x", magic,
		    SSH_COM_PRIVATE_KEY_MAGIC);
		החזר عدم;
	}
	אם ((r = sshbuf_get_u32(b, &i1)) != 0 ||
	    (r = sshbuf_get_cstring(b, &type, عدم)) != 0 ||
	    (r = sshbuf_get_cstring(b, &cipher, عدم)) != 0 ||
	    (r = sshbuf_get_u32(b, &i2)) != 0 ||
	    (r = sshbuf_get_u32(b, &i3)) != 0 ||
	    (r = sshbuf_get_u32(b, &i4)) != 0)
		fatal_fr(r, "parse");
	debug("ignore (%d %d %d %d)", i1, i2, i3, i4);
	אם (strcmp(cipher, "none") != 0) {
		error("unsupported cipher %s", cipher);
		حرر(cipher);
		حرر(type);
		החזר عدم;
	}
	حرر(cipher);

	אם (strstr(type, "rsa")) {
		ktype = KEY_RSA;
	} אחרת {
		حرر(type);
		החזר عدم;
	}
	אם ((key = sshkey_new(ktype)) == عدم)
		fatal("sshkey_new failed");
	حرر(type);

	بدل (key->type) {
	حالة KEY_RSA:
		אם ((r = sshbuf_get_u8(b, &e1)) != 0 ||
		    (e1 < 30 && (r = sshbuf_get_u8(b, &e2)) != 0) ||
		    (e1 < 30 && (r = sshbuf_get_u8(b, &e3)) != 0))
			fatal_fr(r, "parse RSA");
		e = e1;
		debug("e %lx", e);
		אם (e < 30) {
			e <<= 8;
			e += e2;
			debug("e %lx", e);
			e <<= 8;
			e += e3;
			debug("e %lx", e);
		}
		אם ((rsa_e = BN_new()) == عدم)
			fatal_f("BN_new");
		אם (!BN_set_word(rsa_e, e)) {
			BN_clear_free(rsa_e);
			sshkey_free(key);
			החזר عدم;
		}
		אם ((rsa_n = BN_new()) == عدم ||
		    (rsa_d = BN_new()) == عدم ||
		    (rsa_p = BN_new()) == عدم ||
		    (rsa_q = BN_new()) == عدم ||
		    (rsa_iqmp = BN_new()) == عدم)
			fatal_f("BN_new");
		buffer_get_bignum_bits(b, rsa_d);
		buffer_get_bignum_bits(b, rsa_n);
		buffer_get_bignum_bits(b, rsa_iqmp);
		buffer_get_bignum_bits(b, rsa_q);
		buffer_get_bignum_bits(b, rsa_p);
		אם ((r = ssh_rsa_complete_crt_parameters(rsa_d, rsa_p, rsa_q,
		    rsa_iqmp, &rsa_dmp1, &rsa_dmq1)) != 0)
			fatal_fr(r, "generate RSA CRT parameters");
		EVP_PKEY_free(key->pkey);
		אם ((key->pkey = EVP_PKEY_new()) == عدم)
			fatal_f("EVP_PKEY_new failed");
		אם ((rsa = RSA_new()) == عدم)
			fatal_f("RSA_new failed");
		אם (!RSA_set0_key(rsa, rsa_n, rsa_e, rsa_d))
			fatal_f("RSA_set0_key failed");
		rsa_n = rsa_e = rsa_d = عدم; /* transferred */
		אם (!RSA_set0_factors(rsa, rsa_p, rsa_q))
			fatal_f("RSA_set0_factors failed");
		rsa_p = rsa_q = عدم; /* transferred */
		אם (RSA_set0_crt_params(rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp) != 1)
			fatal_f("RSA_set0_crt_params failed");
		rsa_dmp1 = rsa_dmq1 = rsa_iqmp = عدم;
		אם (EVP_PKEY_set1_RSA(key->pkey, rsa) != 1)
			fatal_f("EVP_PKEY_set1_RSA failed");
		RSA_free(rsa);
		alg = "rsa-sha2-256";
		اكسر;
	}
	rlen = sshbuf_len(b);
	אם (rlen != 0)
		error_f("remaining bytes in key blob %d", rlen);

	/* try the key */
	אם ((r = sshkey_sign(key, &sig, &slen, data, حجم(data),
	    alg, عدم, عدم, 0)) != 0)
		error_fr(r, "signing with converted key failed");
	אחרת אם ((r = sshkey_verify(key, sig, slen, data, حجم(data),
	    alg, 0, عدم)) != 0)
		error_fr(r, "verification with converted key failed");
	אם (r != 0) {
		sshkey_free(key);
		حرر(sig);
		החזר عدم;
	}
	حرر(sig);
	החזר key;
}

ساكن صحيح
get_line(FILE *fp, حرف *line, size_t len)
{
	صحيح c;
	size_t pos = 0;

	line[0] = '\0';
	כלעוד ((c = fgetc(fp)) != EOF) {
		אם (pos >= len - 1)
			fatal("input line too long.");
		بدل (c) {
		حالة '\r':
			c = fgetc(fp);
			אם (c != EOF && c != '\n' && ungetc(c, fp) == EOF)
				fatal("unget: %s", strerror(errno));
			החזר pos;
		حالة '\n':
			החזר pos;
		}
		line[pos++] = c;
		line[pos] = '\0';
	}
	/* We reached EOF */
	החזר -1;
}

ساكن فراغ
do_convert_from_ssh2(بنية passwd *pw, بنية sshkey **k, صحيح *خاص)
{
	صحيح r, blen, escaped = 0;
	u_int len;
	حرف line[1024];
	بنية sshbuf *buf;
	حرف encoded[8096];
	FILE *fp;

	אם ((buf = sshbuf_new()) == عدم)
		fatal("sshbuf_new failed");
	אם ((fp = fopen(identity_file, "r")) == عدم)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));
	encoded[0] = '\0';
	כלעוד ((blen = get_line(fp, line, حجم(line))) != -1) {
		אם (blen > 0 && line[blen - 1] == '\\')
			escaped++;
		אם (strncmp(line, "----", 4) == 0 ||
		    strstr(line, ": ") != عدم) {
			אם (strstr(line, SSH_COM_PRIVATE_BEGIN) != عدم)
				*خاص = 1;
			אם (strstr(line, " END ") != عدم) {
				اكسر;
			}
			/* fprintf(stderr, "ignore: %s", line); */
			استمر;
		}
		אם (escaped) {
			escaped--;
			/* fprintf(stderr, "escaped: %s", line); */
			استمر;
		}
		strlcat(encoded, line, حجم(encoded));
	}
	len = strlen(encoded);
	אם (((len % 4) == 3) &&
	    (encoded[len-1] == '=') &&
	    (encoded[len-2] == '=') &&
	    (encoded[len-3] == '='))
		encoded[len-3] = '\0';
	אם ((r = sshbuf_b64tod(buf, encoded)) != 0)
		fatal_fr(r, "base64 decode");
	אם (*خاص) {
		אם ((*k = do_convert_private_ssh2(buf)) == عدم)
			fatal_f("private key conversion failed");
	} אחרת אם ((r = sshkey_fromb(buf, k)) != 0)
		fatal_fr(r, "parse key");
	sshbuf_free(buf);
	fclose(fp);
}

ساكن فراغ
do_convert_from_pkcs8(بنية sshkey **k, صحيح *خاص)
{
	EVP_PKEY *pubkey;
	FILE *fp;

	אם ((fp = fopen(identity_file, "r")) == عدم)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));
	אם ((pubkey = PEM_read_PUBKEY(fp, عدم, عدم, عدم)) == عدم) {
		fatal_f("%s is not a recognised public key format",
		    identity_file);
	}
	fclose(fp);
	بدل (EVP_PKEY_base_id(pubkey)) {
	حالة EVP_PKEY_RSA:
		אם ((*k = sshkey_new(KEY_UNSPEC)) == عدم)
			fatal("sshkey_new failed");
		(*k)->type = KEY_RSA;
		(*k)->pkey = pubkey;
		pubkey = عدم;
		اكسر;
	حالة EVP_PKEY_EC:
		אם ((*k = sshkey_new(KEY_UNSPEC)) == عدم)
			fatal("sshkey_new failed");
		אם (((*k)->ecdsa_nid = sshkey_ecdsa_fixup_group(pubkey)) == -1)
			fatal("sshkey_ecdsa_fixup_group failed");
		(*k)->type = KEY_ECDSA;
		(*k)->pkey = pubkey;
		pubkey = عدم;
		اكسر;
	افتراضي:
		fatal_f("unsupported pubkey type %d",
		    EVP_PKEY_base_id(pubkey));
	}
	EVP_PKEY_free(pubkey);
}

ساكن فراغ
do_convert_from_pem(بنية sshkey **k, صحيح *خاص)
{
	FILE *fp;
	RSA *rsa;

	אם ((fp = fopen(identity_file, "r")) == عدم)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));
	אם ((rsa = PEM_read_RSAPublicKey(fp, عدم, عدم, عدم)) != عدم) {
		אם ((*k = sshkey_new(KEY_UNSPEC)) == عدم)
			fatal("sshkey_new failed");
		אם (((*k)->pkey = EVP_PKEY_new()) == عدم)
			fatal("EVP_PKEY_new failed");
		(*k)->type = KEY_RSA;
		אם (EVP_PKEY_set1_RSA((*k)->pkey, rsa) != 1)
			fatal("EVP_PKEY_set1_RSA failed");
		RSA_free(rsa);
		fclose(fp);
		החזר;
	}
	fatal_f("unrecognised raw private key format");
}

ساكن فراغ
do_convert_from(بنية passwd *pw)
{
	بنية sshkey *k = عدم;
	صحيح r, خاص = 0, ok = 0;
	بنية stat st;

	אם (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	אם (stat(identity_file, &st) == -1)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));

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

	אם (!خاص) {
		אם ((r = sshkey_write(k, stdout)) == 0)
			ok = 1;
		אם (ok)
			fprintf(stdout, "\n");
	} אחרת {
		بدل (k->type) {
		حالة KEY_ECDSA:
			ok = PEM_write_ECPrivateKey(stdout,
			    EVP_PKEY_get0_EC_KEY(k->pkey), عدم, عدم, 0,
			    عدم, عدم);
			اكسر;
		حالة KEY_RSA:
			ok = PEM_write_RSAPrivateKey(stdout,
			    EVP_PKEY_get0_RSA(k->pkey), عدم, عدم, 0,
			    عدم, عدم);
			اكسر;
		افتراضي:
			fatal_f("unsupported key type %s", sshkey_type(k));
		}
	}

	אם (!ok)
		fatal("key write failed");
	sshkey_free(k);
}
#endif

ساكن فراغ
do_print_public(بنية passwd *pw)
{
	بنية sshkey *prv;
	بنية stat st;
	صحيح r;
	حرف *comment = عدم;

	אם (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	אם (stat(identity_file, &st) == -1)
		fatal("%s: %s", identity_file, strerror(errno));
	prv = load_identity(identity_file, &comment);
	אם ((r = sshkey_write(prv, stdout)) != 0)
		fatal_fr(r, "write key");
	אם (comment != عدم && *comment != '\0')
		fprintf(stdout, " %s", comment);
	fprintf(stdout, "\n");
	אם (sshkey_is_sk(prv)) {
		debug("sk_application: \"%s\", sk_flags 0x%02x",
			prv->sk_application, prv->sk_flags);
	}
	sshkey_free(prv);
	حرر(comment);
	exit(0);
}

ساكن فراغ
do_download(بنية passwd *pw)
{
#ifdef ENABLE_PKCS11
	بنية sshkey **keys = عدم;
	صحيح i, nkeys;
	تعداد sshkey_fp_rep rep;
	صحيح fptype;
	حرف *fp, *ra, **comments = عدم;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;

	pkcs11_init(1);
	nkeys = pkcs11_add_provider(pkcs11provider, عدم, &keys, &comments);
	אם (nkeys <= 0)
		fatal("cannot read public key from pkcs11");
	עבור (i = 0; i < nkeys; i++) {
		אם (print_fingerprint) {
			fp = sshkey_fingerprint(keys[i], fptype, rep);
			ra = sshkey_fingerprint(keys[i], fingerprint_hash,
			    SSH_FP_RANDOMART);
			אם (fp == عدم || ra == عدم)
				fatal_f("sshkey_fingerprint fail");
			printf("%u %s %s (PKCS11 key)\n", sshkey_size(keys[i]),
			    fp, sshkey_type(keys[i]));
			אם (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
				printf("%s\n", ra);
			حرر(ra);
			حرر(fp);
		} אחרת {
			(فراغ) sshkey_write(keys[i], stdout); /* XXX check */
			fprintf(stdout, "%s%s\n",
			    *(comments[i]) == '\0' ? "" : " ", comments[i]);
		}
		حرر(comments[i]);
		sshkey_free(keys[i]);
	}
	حرر(comments);
	حرر(keys);
	pkcs11_terminate();
	exit(0);
#אחרת
	fatal("no pkcs11 support");
#endif /* ENABLE_PKCS11 */
}

ساكن بنية sshkey *
try_read_key(حرف **cpp)
{
	بنية sshkey *ret;
	صحيح r;

	אם ((ret = sshkey_new(KEY_UNSPEC)) == عدم)
		fatal("sshkey_new failed");
	אם ((r = sshkey_read(ret, cpp)) == 0)
		החזר ret;
	/* Not a key */
	sshkey_free(ret);
	החזר عدم;
}

ساكن فراغ
fingerprint_one_key(ثابت بنية sshkey *عام, ثابت حرف *comment)
{
	حرف *fp = عدم, *ra = عدم;
	تعداد sshkey_fp_rep rep;
	صحيح fptype;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;
	fp = sshkey_fingerprint(عام, fptype, rep);
	ra = sshkey_fingerprint(عام, fingerprint_hash, SSH_FP_RANDOMART);
	אם (fp == عدم || ra == عدم)
		fatal_f("sshkey_fingerprint failed");
	mprintf("%u %s %s (%s)\n", sshkey_size(عام), fp,
	    comment ? comment : "no comment", sshkey_type(عام));
	אם (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
		printf("%s\n", ra);
	حرر(ra);
	حرر(fp);
}

ساكن فراغ
fingerprint_private(ثابت حرف *path)
{
	بنية stat st;
	حرف *comment = عدم;
	بنية sshkey *privkey = عدم, *pubkey = عدم;
	صحيح r;

	אם (stat(identity_file, &st) == -1)
		fatal("%s: %s", path, strerror(errno));
	אם ((r = sshkey_load_public(path, &pubkey, &comment)) != 0)
		debug_r(r, "load public \"%s\"", path);
	אם (pubkey == عدم || comment == عدم || *comment == '\0') {
		حرر(comment);
		אם ((r = sshkey_load_private(path, عدم,
		    &privkey, &comment)) != 0)
			debug_r(r, "load private \"%s\"", path);
	}
	אם (pubkey == عدم && privkey == عدم)
		fatal("%s is not a key file.", path);

	fingerprint_one_key(pubkey == عدم ? privkey : pubkey, comment);
	sshkey_free(pubkey);
	sshkey_free(privkey);
	حرر(comment);
}

ساكن فراغ
do_fingerprint(بنية passwd *pw)
{
	FILE *f;
	بنية sshkey *عام = عدم;
	حرف *comment = عدم, *cp, *ep, *line = عدم;
	size_t linesize = 0;
	صحيح i, invalid = 1;
	ثابت حرف *path;
	u_long lnum = 0;

	אם (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	path = identity_file;

	אם (strcmp(identity_file, "-") == 0) {
		f = stdin;
		path = "(stdin)";
	} אחרת אם ((f = fopen(path, "r")) == عدم)
		fatal("%s: %s: %s", __progname, path, strerror(errno));

	כלעוד (getline(&line, &linesize, f) != -1) {
		lnum++;
		cp = line;
		cp[strcspn(cp, "\r\n")] = '\0';
		/* Trim leading space and comments */
		cp = line + strspn(line, " \t");
		אם (*cp == '#' || *cp == '\0')
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
		אם (lnum == 1 && strcmp(identity_file, "-") != 0 &&
		    strstr(cp, "PRIVATE KEY") != عدم) {
			حرر(line);
			fclose(f);
			fingerprint_private(path);
			exit(0);
		}

		/*
		 * If it's not a private key, then this must be prepared to
		 * accept a public key prefixed with a hostname or options.
		 * Try a bare key first, otherwise skip the leading stuff.
		 */
		comment = عدم;
		אם ((عام = try_read_key(&cp)) == عدم) {
			i = strtol(cp, &ep, 10);
			אם (i == 0 || ep == عدم ||
			    (*ep != ' ' && *ep != '\t')) {
				صحيح quoted = 0;

				comment = cp;
				עבור (; *cp && (quoted || (*cp != ' ' &&
				    *cp != '\t')); cp++) {
					אם (*cp == '\\' && cp[1] == '"')
						cp++;	/* Skip both */
					אחרת אם (*cp == '"')
						quoted = !quoted;
				}
				אם (!*cp)
					استمر;
				*cp++ = '\0';
			}
		}
		/* Retry after parsing leading hostname/key options */
		אם (عام == عدم && (عام = try_read_key(&cp)) == عدم) {
			debug("%s:%lu: not a public key", path, lnum);
			استمر;
		}

		/* Find trailing comment, if any */
		עבור (; *cp == ' ' || *cp == '\t'; cp++)
			;
		אם (*cp != '\0' && *cp != '#')
			comment = cp;

		fingerprint_one_key(عام, comment);
		sshkey_free(عام);
		invalid = 0; /* One good key in the file is sufficient */
	}
	fclose(f);
	حرر(line);

	אם (invalid)
		fatal("%s is not a public key file.", path);
	exit(0);
}

ساكن فراغ
do_gen_all_hostkeys(بنية passwd *pw)
{
	بنية {
		حرف *key_type;
		حرف *key_type_display;
		حرف *path;
	} key_types[] = {
#ifdef WITH_OPENSSL
		{ "rsa", "RSA" ,_PATH_HOST_RSA_KEY_FILE },
		{ "ecdsa", "ECDSA",_PATH_HOST_ECDSA_KEY_FILE },
#endif /* WITH_OPENSSL */
		{ "ed25519", "ED25519",_PATH_HOST_ED25519_KEY_FILE },
#ifdef USE_MLDSA
		{ "mldsa44-ed25519", "MLDSA44-ED25519",
		     _PATH_HOST_MLDSA44_ED25519_KEY_FILE },
#endif
		{ عدم, عدم, عدم }
	};

	uint32_t bits = 0;
	صحيح first = 0;
	بنية stat st;
	بنية sshkey *خاص, *عام;
	حرف comment[KEY_COMMENT_MAX], *prv_tmp, *pub_tmp, *prv_file, *pub_file;
	صحيح i, type, fd, r;

	עבור (i = 0; key_types[i].key_type; i++) {
		عام = خاص = عدم;
		prv_tmp = pub_tmp = prv_file = pub_file = عدم;

		xasprintf(&prv_file, "%s%s",
		    identity_file, key_types[i].path);

		/* Check whether private key exists and is not zero-length */
		אם (stat(prv_file, &st) == 0) {
			אם (st.st_size != 0)
				اذهب next;
		} אחרת אם (errno != ENOENT) {
			error("Could not stat %s: %s", key_types[i].path,
			    strerror(errno));
			اذهب failnext;
		}

		/*
		 * Private key doesn't exist or is invalid; proceed with
		 * key generation.
		 */
		xasprintf(&prv_tmp, "%s%s.XXXXXXXXXX",
		    identity_file, key_types[i].path);
		xasprintf(&pub_tmp, "%s%s.pub.XXXXXXXXXX",
		    identity_file, key_types[i].path);
		xasprintf(&pub_file, "%s%s.pub",
		    identity_file, key_types[i].path);

		אם (first == 0) {
			first = 1;
			printf("%s: generating new host keys: ", __progname);
		}
		printf("%s ", key_types[i].key_type_display);
		fflush(stdout);
		type = sshkey_type_from_shortname(key_types[i].key_type);
		אם ((fd = mkstemp(prv_tmp)) == -1) {
			error("Could not save your private key in %s: %s",
			    prv_tmp, strerror(errno));
			اذهب failnext;
		}
		(فراغ)close(fd); /* just using mkstemp() to reserve a name */
		bits = 0;
		type_bits_valid(type, عدم, &bits);
		אם ((r = sshkey_generate(type, bits, &خاص)) != 0) {
			error_r(r, "sshkey_generate failed");
			اذهب failnext;
		}
		אם ((r = sshkey_from_private(خاص, &عام)) != 0)
			fatal_fr(r, "sshkey_from_private");
		snprintf(comment, حجم comment, "%s@%s", pw->pw_name,
		    hostname);
		אם ((r = sshkey_save_private(خاص, prv_tmp, "",
		    comment, private_key_format, openssh_format_cipher,
		    rounds)) != 0) {
			error_r(r, "Saving key \"%s\" failed", prv_tmp);
			اذهب failnext;
		}
		אם ((fd = mkstemp(pub_tmp)) == -1) {
			error("Could not save your public key in %s: %s",
			    pub_tmp, strerror(errno));
			اذهب failnext;
		}
		(فراغ)fchmod(fd, 0644);
		(فراغ)close(fd);
		אם ((r = sshkey_save_public(عام, pub_tmp, comment)) != 0) {
			error_r(r, "Unable to save public key to %s",
			    identity_file);
			اذهب failnext;
		}

		/* Rename temporary files to their permanent locations. */
		אם (rename(pub_tmp, pub_file) != 0) {
			error("Unable to move %s into position: %s",
			    pub_file, strerror(errno));
			اذهب failnext;
		}
		אם (rename(prv_tmp, prv_file) != 0) {
			error("Unable to move %s into position: %s",
			    key_types[i].path, strerror(errno));
 failnext:
			first = 0;
			اذهب next;
		}
 next:
		sshkey_free(خاص);
		sshkey_free(عام);
		حرر(prv_tmp);
		حرر(pub_tmp);
		حرر(prv_file);
		حرر(pub_file);
	}
	אם (first != 0)
		printf("\n");
}

بنية known_hosts_ctx {
	ثابت حرف *host;	/* Hostname searched for in find/delete case */
	FILE *out;		/* Output file, stdout for find_hosts case */
	صحيح has_unhashed;	/* When hashing, original had unhashed hosts */
	صحيح found_key;		/* For find/delete, host was found */
	صحيح invalid;		/* File contained invalid items; don't delete */
	صحيح hash_hosts;		/* Hash hostnames as we go */
	صحيح find_host;		/* Search for specific hostname */
	صحيح delete_host;	/* Delete host from known_hosts */
};

ساكن صحيح
known_hosts_hash(بنية hostkey_foreach_line *l, فراغ *_ctx)
{
	بنية known_hosts_ctx *ctx = (بنية known_hosts_ctx *)_ctx;
	حرف *hashed, *cp, *hosts, *ohosts;
	صحيح has_wild = l->hosts && strcspn(l->hosts, "*?!") != strlen(l->hosts);
	صحيح was_hashed = l->hosts && l->hosts[0] == HASH_DELIM;

	بدل (l->status) {
	حالة HKF_STATUS_OK:
	حالة HKF_STATUS_MATCHED:
		/*
		 * Don't hash hosts already hashed, with wildcard
		 * characters or a CA/revocation marker.
		 */
		אם (was_hashed || has_wild || l->marker != MRK_NONE) {
			fprintf(ctx->out, "%s\n", l->line);
			אם (has_wild && !ctx->find_host) {
				logit("%s:%lu: ignoring host name "
				    "with wildcard: %.64s", l->path,
				    l->linenum, l->hosts);
			}
			החזר 0;
		}
		/*
		 * Split any comma-separated hostnames from the host list,
		 * hash and store separately.
		 */
		ohosts = hosts = xstrdup(l->hosts);
		כלעוד ((cp = strsep(&hosts, ",")) != عدم && *cp != '\0') {
			lowercase(cp);
			אם ((hashed = host_hash(cp, عدم, 0)) == عدم)
				fatal("hash_host failed");
			fprintf(ctx->out, "%s %s\n", hashed, l->rawkey);
			حرر(hashed);
			ctx->has_unhashed = 1;
		}
		حرر(ohosts);
		החזר 0;
	حالة HKF_STATUS_INVALID:
		/* Retain invalid lines, but mark file as invalid. */
		ctx->invalid = 1;
		logit("%s:%lu: invalid line", l->path, l->linenum);
		/* FALLTHROUGH */
	افتراضي:
		fprintf(ctx->out, "%s\n", l->line);
		החזר 0;
	}
	/* NOTREACHED */
	החזר -1;
}

ساكن صحيح
known_hosts_find_delete(بنية hostkey_foreach_line *l, فراغ *_ctx)
{
	بنية known_hosts_ctx *ctx = (بنية known_hosts_ctx *)_ctx;
	تعداد sshkey_fp_rep rep;
	صحيح fptype;
	حرف *fp = عدم, *ra = عدم;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;

	אם (l->status == HKF_STATUS_MATCHED) {
		אם (ctx->delete_host) {
			אם (l->marker != MRK_NONE) {
				/* Don't remove CA and revocation lines */
				fprintf(ctx->out, "%s\n", l->line);
			} אחרת {
				/*
				 * Hostname matches and has no CA/revoke
				 * marker, delete it by *not* writing the
				 * line to ctx->out.
				 */
				ctx->found_key = 1;
				אם (!quiet)
					printf("# Host %s found: line %lu\n",
					    ctx->host, l->linenum);
			}
			החזר 0;
		} אחרת אם (ctx->find_host) {
			ctx->found_key = 1;
			אם (!quiet) {
				printf("# Host %s found: line %lu %s\n",
				    ctx->host,
				    l->linenum, l->marker == MRK_CA ? "CA" :
				    (l->marker == MRK_REVOKE ? "REVOKED" : ""));
			}
			אם (ctx->hash_hosts)
				known_hosts_hash(l, ctx);
			אחרת אם (print_fingerprint) {
				fp = sshkey_fingerprint(l->key, fptype, rep);
				ra = sshkey_fingerprint(l->key,
				    fingerprint_hash, SSH_FP_RANDOMART);
				אם (fp == عدم || ra == عدم)
					fatal_f("sshkey_fingerprint failed");
				mprintf("%s %s %s%s%s\n", ctx->host,
				    sshkey_type(l->key), fp,
				    l->comment[0] ? " " : "",
				    l->comment);
				אם (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
					printf("%s\n", ra);
				حرر(ra);
				حرر(fp);
			} אחרת
				fprintf(ctx->out, "%s\n", l->line);
			החזר 0;
		}
	} אחרת אם (ctx->delete_host) {
		/* Retain non-matching hosts when deleting */
		אם (l->status == HKF_STATUS_INVALID) {
			ctx->invalid = 1;
			logit("%s:%lu: invalid line", l->path, l->linenum);
		}
		fprintf(ctx->out, "%s\n", l->line);
	}
	החזר 0;
}

ساكن فراغ
do_known_hosts(بنية passwd *pw, ثابت حرف *name, صحيح find_host,
    صحيح delete_host, صحيح hash_hosts)
{
	حرف *cp, tmp[PATH_MAX], old[PATH_MAX];
	صحيح r, fd, oerrno, inplace = 0;
	بنية known_hosts_ctx ctx;
	u_int foreach_options;
	بنية stat sb;

	אם (!have_identity) {
		cp = tilde_expand_filename(_PATH_SSH_USER_HOSTFILE, pw->pw_uid);
		אם (strlcpy(identity_file, cp, حجم(identity_file)) >=
		    حجم(identity_file))
			fatal("Specified known hosts path too long");
		حرر(cp);
		have_identity = 1;
	}
	אם (stat(identity_file, &sb) != 0)
		fatal("Cannot stat %s: %s", identity_file, strerror(errno));

	memset(&ctx, 0, حجم(ctx));
	ctx.out = stdout;
	ctx.host = name;
	ctx.hash_hosts = hash_hosts;
	ctx.find_host = find_host;
	ctx.delete_host = delete_host;

	/*
	 * Find hosts goes to stdout, hash and deletions happen in-place
	 * A corner case is ssh-keygen -HF foo, which should go to stdout
	 */
	אם (!find_host && (hash_hosts || delete_host)) {
		אם (strlcpy(tmp, identity_file, حجم(tmp)) >= حجم(tmp) ||
		    strlcat(tmp, ".XXXXXXXXXX", حجم(tmp)) >= حجم(tmp) ||
		    strlcpy(old, identity_file, حجم(old)) >= حجم(old) ||
		    strlcat(old, ".old", حجم(old)) >= حجم(old))
			fatal("known_hosts path too long");
		umask(077);
		אם ((fd = mkstemp(tmp)) == -1)
			fatal("mkstemp: %s", strerror(errno));
		אם ((ctx.out = fdopen(fd, "w")) == عدم) {
			oerrno = errno;
			unlink(tmp);
			fatal("fdopen: %s", strerror(oerrno));
		}
		(فراغ)fchmod(fd, sb.st_mode & 0644);
		inplace = 1;
	}
	/* XXX support identity_file == "-" for stdin */
	foreach_options = find_host ? HKF_WANT_MATCH : 0;
	foreach_options |= print_fingerprint ? HKF_WANT_PARSE_KEY : 0;
	אם ((r = hostkeys_foreach(identity_file, (find_host || !hash_hosts) ?
	    known_hosts_find_delete : known_hosts_hash, &ctx, name, عدم,
	    foreach_options, 0)) != 0) {
		אם (inplace)
			unlink(tmp);
		fatal_fr(r, "hostkeys_foreach");
	}

	אם (inplace)
		fclose(ctx.out);

	אם (ctx.invalid) {
		error("%s is not a valid known_hosts file.", identity_file);
		אם (inplace) {
			error("Not replacing existing known_hosts "
			    "file because of errors");
			unlink(tmp);
		}
		exit(1);
	} אחרת אם (delete_host && !ctx.found_key) {
		logit("Host %s not found in %s", name, identity_file);
		אם (inplace)
			unlink(tmp);
	} אחרת אם (inplace) {
		/* Backup existing file */
		אם (unlink(old) == -1 && errno != ENOENT)
			fatal("unlink %.100s: %s", old, strerror(errno));
		אם (link(identity_file, old) == -1)
			fatal("link %.100s to %.100s: %s", identity_file, old,
			    strerror(errno));
		/* Move new one into place */
		אם (rename(tmp, identity_file) == -1) {
			error("rename\"%s\" to \"%s\": %s", tmp, identity_file,
			    strerror(errno));
			unlink(tmp);
			unlink(old);
			exit(1);
		}

		printf("%s updated.\n", identity_file);
		printf("Original contents retained as %s\n", old);
		אם (ctx.has_unhashed) {
			logit("WARNING: %s contains unhashed entries", old);
			logit("Delete this file to ensure privacy "
			    "of hostnames");
		}
	}

	exit (find_host && !ctx.found_key);
}

/*
 * Perform changing a passphrase.  The argument is the passwd structure
 * for the current user.
 */
ساكن فراغ
do_change_passphrase(بنية passwd *pw, حرف * ثابت *opts, size_t nopts)
{
	حرف *comment;
	حرف *old_passphrase, *passphrase1, *passphrase2;
	بنية stat st;
	بنية sshkey *خاص;
	صحيح r;
	size_t i;

	אם (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	אם (stat(identity_file, &st) == -1)
		fatal("%s: %s", identity_file, strerror(errno));
	/* Try to load the file with empty passphrase. */
	r = sshkey_load_private(identity_file, "", &خاص, &comment);
	אם (r == SSH_ERR_KEY_WRONG_PASSPHRASE) {
		אם (identity_passphrase)
			old_passphrase = xstrdup(identity_passphrase);
		אחרת
			old_passphrase =
			    read_passphrase("Enter old passphrase: ",
			    RP_ALLOW_STDIN);
		r = sshkey_load_private(identity_file, old_passphrase,
		    &خاص, &comment);
		freezero(old_passphrase, strlen(old_passphrase));
		אם (r != 0)
			اذهب badkey;
	} אחרת אם (r != 0) {
 badkey:
		fatal_r(r, "Failed to load key %s", identity_file);
	}
	אם (comment)
		mprintf("Key has comment '%s'\n", comment);

	/* All current -O options relate to FIDO keys only */
	אם (nopts != 0 && !sshkey_is_sk(خاص)) {
		fatal("FIDO-specific option requested for non-FIDO key %s",
		    identity_file);
	}
	אם (sshkey_is_sk(خاص)) {
		debug_f("%s: original FIDO key flags: "
		    "%stouch-required %sverify-required", identity_file,
		    (خاص->sk_flags & SSH_SK_USER_PRESENCE_REQD) ? "": "no-",
		    (خاص->sk_flags & SSH_SK_USER_VERIFICATION_REQD) ? "" : "no-");
	}
	עבור (i = 0; i < nopts; i++) {
		אם (strcasecmp(opts[i], "touch-required") == 0)
			خاص->sk_flags |= SSH_SK_USER_PRESENCE_REQD;
		אחרת אם (strcasecmp(opts[i], "no-touch-required") == 0)
			خاص->sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
		אחרת אם (strcasecmp(opts[i], "verify-required") == 0)
			خاص->sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
		אחרת אם (strcasecmp(opts[i], "no-verify-required") == 0)
			خاص->sk_flags &= ~SSH_SK_USER_VERIFICATION_REQD;
		אחרת {
			fatal("Option \"%s\" is unsupported for "
			    "key passphrase change", opts[i]);
		}
	}
	אם (sshkey_is_sk(خاص) && nopts != 0) {
		debug_f("%s: updated FIDO key flags: "
		    "%stouch-required %sverify-required", identity_file,
		    (خاص->sk_flags & SSH_SK_USER_PRESENCE_REQD) ? "": "no-",
		    (خاص->sk_flags & SSH_SK_USER_VERIFICATION_REQD) ? "" : "no-");
	}

	/* Ask the new passphrase (twice). */
	אם (identity_new_passphrase) {
		passphrase1 = xstrdup(identity_new_passphrase);
		passphrase2 = عدم;
	} אחרת {
		passphrase1 =
			read_passphrase("Enter new passphrase (empty for no "
			    "passphrase): ", RP_ALLOW_STDIN);
		passphrase2 = read_passphrase("Enter same passphrase again: ",
		    RP_ALLOW_STDIN);

		/* Verify that they are the same. */
		אם (strcmp(passphrase1, passphrase2) != 0) {
			explicit_bzero(passphrase1, strlen(passphrase1));
			explicit_bzero(passphrase2, strlen(passphrase2));
			حرر(passphrase1);
			حرر(passphrase2);
			printf("Pass phrases do not match.  Try again.\n");
			exit(1);
		}
		/* Destroy the other copy. */
		freezero(passphrase2, strlen(passphrase2));
	}

	/* Save the file using the new passphrase. */
	אם ((r = sshkey_save_private(خاص, identity_file, passphrase1,
	    comment, private_key_format, openssh_format_cipher, rounds)) != 0) {
		error_r(r, "Saving key \"%s\" failed", identity_file);
		freezero(passphrase1, strlen(passphrase1));
		sshkey_free(خاص);
		حرر(comment);
		exit(1);
	}
	/* Destroy the passphrase and the copy of the key in memory. */
	freezero(passphrase1, strlen(passphrase1));
	sshkey_free(خاص);		 /* Destroys contents */
	حرر(comment);

	printf("Your identification has been saved with the new passphrase.\n");
	exit(0);
}

/*
 * Print the SSHFP RR.
 */
ساكن صحيح
do_print_resource_record(بنية passwd *pw, حرف *fname, حرف *hname,
    صحيح print_generic, حرف * ثابت *opts, size_t nopts)
{
	بنية sshkey *عام;
	حرف *comment = عدم;
	ثابت حرف *p;
	بنية stat st;
	صحيح r, hash = -1;
	size_t i;

	עבור (i = 0; i < nopts; i++) {
		אם ((p = strprefix(opts[i], "hashalg=", 1)) != عدم) {
			אם ((hash = ssh_digest_alg_by_name(p)) == -1)
				fatal("Unsupported hash algorithm");
		} אחרת {
			error("Invalid option \"%s\"", opts[i]);
			החזר SSH_ERR_INVALID_ARGUMENT;
		}
	}
	אם (fname == عدم)
		fatal_f("no filename");
	אם (stat(fname, &st) == -1) {
		אם (errno == ENOENT)
			החזר 0;
		fatal("%s: %s", fname, strerror(errno));
	}
	אם ((r = sshkey_load_public(fname, &عام, &comment)) != 0)
		fatal_r(r, "Failed to read v2 public key from \"%s\"", fname);
	export_dns_rr(hname, عام, stdout, print_generic, hash);
	sshkey_free(عام);
	حرر(comment);
	החזר 1;
}

/*
 * Change the comment of a private key file.
 */
ساكن فراغ
do_change_comment(بنية passwd *pw, ثابت حرف *identity_comment)
{
	حرف new_comment[KEY_COMMENT_MAX], *comment, *passphrase;
	بنية sshkey *خاص;
	بنية sshkey *عام;
	بنية stat st;
	صحيح r;

	אם (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	אם (stat(identity_file, &st) == -1)
		fatal("%s: %s", identity_file, strerror(errno));
	אם ((r = sshkey_load_private(identity_file, "",
	    &خاص, &comment)) == 0)
		passphrase = xstrdup("");
	אחרת אם (r != SSH_ERR_KEY_WRONG_PASSPHRASE)
		fatal_r(r, "Cannot load private key \"%s\"", identity_file);
	אחרת {
		אם (identity_passphrase)
			passphrase = xstrdup(identity_passphrase);
		אחרת אם (identity_new_passphrase)
			passphrase = xstrdup(identity_new_passphrase);
		אחרת
			passphrase = read_passphrase("Enter passphrase: ",
			    RP_ALLOW_STDIN);
		/* Try to load using the passphrase. */
		אם ((r = sshkey_load_private(identity_file, passphrase,
		    &خاص, &comment)) != 0) {
			freezero(passphrase, strlen(passphrase));
			fatal_r(r, "Cannot load private key \"%s\"",
			    identity_file);
		}
	}

	אם (خاص->type != KEY_ED25519 &&
	    private_key_format != SSHKEY_PRIVATE_OPENSSH) {
		error("Comments are only supported for keys stored in "
		    "the new format (-o).");
		explicit_bzero(passphrase, strlen(passphrase));
		sshkey_free(خاص);
		exit(1);
	}
	אם (comment)
		printf("Old comment: %s\n", comment);
	אחרת
		printf("No existing comment\n");

	אם (identity_comment) {
		strlcpy(new_comment, identity_comment, حجم(new_comment));
	} אחרת {
		printf("New comment: ");
		fflush(stdout);
		אם (!fgets(new_comment, حجم(new_comment), stdin)) {
			explicit_bzero(passphrase, strlen(passphrase));
			sshkey_free(خاص);
			exit(1);
		}
		new_comment[strcspn(new_comment, "\n")] = '\0';
	}
	אם (comment != عدم && strcmp(comment, new_comment) == 0) {
		printf("No change to comment\n");
		حرر(passphrase);
		sshkey_free(خاص);
		حرر(comment);
		exit(0);
	}

	/* Save the file using the new passphrase. */
	אם ((r = sshkey_save_private(خاص, identity_file, passphrase,
	    new_comment, private_key_format, openssh_format_cipher,
	    rounds)) != 0) {
		error_r(r, "Saving key \"%s\" failed", identity_file);
		freezero(passphrase, strlen(passphrase));
		sshkey_free(خاص);
		حرر(comment);
		exit(1);
	}
	freezero(passphrase, strlen(passphrase));
	אם ((r = sshkey_from_private(خاص, &عام)) != 0)
		fatal_fr(r, "sshkey_from_private");
	sshkey_free(خاص);

	strlcat(identity_file, ".pub", حجم(identity_file));
	אם ((r = sshkey_save_public(عام, identity_file, new_comment)) != 0)
		fatal_r(r, "Unable to save public key to %s", identity_file);
	sshkey_free(عام);
	حرر(comment);

	אם (strlen(new_comment) > 0)
		printf("Comment '%s' applied\n", new_comment);
	אחרת
		printf("Comment removed\n");

	exit(0);
}

ساكن فراغ
cert_ext_add(ثابت حرف *key, ثابت حرف *value, صحيح iscrit)
{
	cert_ext = xreallocarray(cert_ext, ncert_ext + 1, حجم(*cert_ext));
	cert_ext[ncert_ext].key = xstrdup(key);
	cert_ext[ncert_ext].val = value == عدم ? عدم : xstrdup(value);
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

	אם (a->crit != b->crit)
		החזר (a->crit < b->crit) ? -1 : 1;
	אם ((r = strcmp(a->key, b->key)) != 0)
		החזר r;
	אם ((a->val == عدم) != (b->val == عدم))
		החזר (a->val == عدم) ? -1 : 1;
	אם (a->val != عدم && (r = strcmp(a->val, b->val)) != 0)
		החזר r;
	החזר 0;
}

#define OPTIONS_CRITICAL	1
#define OPTIONS_EXTENSIONS	2
ساكن فراغ
prepare_options_buf(بنية sshbuf *c, صحيح which)
{
	بنية sshbuf *b;
	size_t i;
	صحيح r;
	ثابت بنية cert_ext *ext;

	אם ((b = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	sshbuf_reset(c);
	עבור (i = 0; i < ncert_ext; i++) {
		ext = &cert_ext[i];
		אם ((ext->crit && (which & OPTIONS_EXTENSIONS)) ||
		    (!ext->crit && (which & OPTIONS_CRITICAL)))
			استمر;
		אם (ext->val == عدم) {
			/* flag option */
			debug3_f("%s", ext->key);
			אם ((r = sshbuf_put_cstring(c, ext->key)) != 0 ||
			    (r = sshbuf_put_string(c, عدم, 0)) != 0)
				fatal_fr(r, "prepare flag");
		} אחרת {
			/* key/value option */
			debug3_f("%s=%s", ext->key, ext->val);
			sshbuf_reset(b);
			אם ((r = sshbuf_put_cstring(c, ext->key)) != 0 ||
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
	אם (certflags_command != عدم)
		cert_ext_add("force-command", certflags_command, 1);
	אם (certflags_src_addr != عدم)
		cert_ext_add("source-address", certflags_src_addr, 1);
	אם ((certflags_flags & CERTOPT_REQUIRE_VERIFY) != 0)
		cert_ext_add("verify-required", عدم, 1);
	/* extensions */
	אם ((certflags_flags & CERTOPT_X_FWD) != 0)
		cert_ext_add("permit-X11-forwarding", عدم, 0);
	אם ((certflags_flags & CERTOPT_AGENT_FWD) != 0)
		cert_ext_add("permit-agent-forwarding", عدم, 0);
	אם ((certflags_flags & CERTOPT_PORT_FWD) != 0)
		cert_ext_add("permit-port-forwarding", عدم, 0);
	אם ((certflags_flags & CERTOPT_PTY) != 0)
		cert_ext_add("permit-pty", عدم, 0);
	אם ((certflags_flags & CERTOPT_USER_RC) != 0)
		cert_ext_add("permit-user-rc", عدم, 0);
	אם ((certflags_flags & CERTOPT_NO_REQUIRE_USER_PRESENCE) != 0)
		cert_ext_add("no-touch-required", عدم, 0);
	/* order lexically by key */
	אם (ncert_ext > 0)
		qsort(cert_ext, ncert_ext, حجم(*cert_ext), cert_ext_cmp);
}

ساكن بنية sshkey *
load_pkcs11_key(حرف *path)
{
#ifdef ENABLE_PKCS11
	بنية sshkey **keys = عدم, *عام, *خاص = عدم;
	صحيح r, i, nkeys;

	אם ((r = sshkey_load_public(path, &عام, عدم)) != 0)
		fatal_r(r, "Couldn't load CA public key \"%s\"", path);

	nkeys = pkcs11_add_provider(pkcs11provider, identity_passphrase,
	    &keys, عدم);
	debug3_f("%d keys", nkeys);
	אם (nkeys <= 0)
		fatal("cannot read public key from pkcs11");
	עבור (i = 0; i < nkeys; i++) {
		אם (sshkey_equal_public(عام, keys[i])) {
			خاص = keys[i];
			استمر;
		}
		sshkey_free(keys[i]);
	}
	حرر(keys);
	sshkey_free(عام);
	החזר خاص;
#אחרת
	fatal("no pkcs11 support");
#endif /* ENABLE_PKCS11 */
}

/* Signer for sshkey_certify_custom that uses the agent */
ساكن صحيح
agent_signer(بنية sshkey *key, u_char **sigp, size_t *lenp,
    ثابت u_char *data, size_t datalen,
    ثابت حرف *alg, ثابت حرف *provider, ثابت حرف *pin,
    u_int compat, فراغ *ctx)
{
	صحيح *agent_fdp = (صحيح *)ctx;

	החזר ssh_agent_sign(*agent_fdp, key, sigp, lenp,
	    data, datalen, alg, compat);
}

ساكن فراغ
do_ca_sign(بنية passwd *pw, ثابت حرف *ca_key_path, صحيح prefer_agent,
    unsigned long long cert_serial, صحيح cert_serial_autoinc,
    صحيح argc, حرف **argv)
{
	صحيح r, i, key_in_agent = 0, agent_fd = -1;
	u_int n;
	بنية sshkey *ca, *عام;
	حرف valid[64], *otmp, *tmp, *cp, *out, *comment;
	حرف *ca_fp = عدم, **plist = عدم, *pin = عدم;
	بنية ssh_identitylist *agent_ids;
	size_t j;
	بنية notifier_ctx *notifier = عدم;

#ifdef ENABLE_PKCS11
	pkcs11_init(1);
#endif
	tmp = tilde_expand_filename(ca_key_path, pw->pw_uid);
	אם (pkcs11provider != عدم) {
		/* If a PKCS#11 token was specified then try to use it */
		אם ((ca = load_pkcs11_key(tmp)) == عدم)
			fatal("No PKCS#11 key matching %s found", ca_key_path);
	} אחרת אם (prefer_agent) {
		/*
		 * Agent signature requested. Try to use agent after making
		 * sure the public key specified is actually present in the
		 * agent.
		 */
		אם ((r = sshkey_load_public(tmp, &ca, عدم)) != 0)
			fatal_r(r, "Cannot load CA public key %s", tmp);
		אם ((r = ssh_get_authentication_socket(&agent_fd)) != 0)
			fatal_r(r, "Cannot use public key for CA signature");
		אם ((r = ssh_fetch_identitylist(agent_fd, &agent_ids)) != 0)
			fatal_r(r, "Retrieve agent key list");
		עבור (j = 0; j < agent_ids->nkeys; j++) {
			אם (sshkey_equal(ca, agent_ids->keys[j])) {
				key_in_agent = 1;
				/* Replace the CA key with the agent one */
				sshkey_free(ca);
				ca = agent_ids->keys[j];
				agent_ids->keys[j] = عدم;
				اكسر;
			}
		}
		אם (!key_in_agent)
			fatal("CA key %s not found in agent", tmp);
		ssh_free_identitylist(agent_ids);
	} אחרת {
		/* CA key is assumed to be a private key on the filesystem */
		ca = load_identity(tmp, عدم);
		אם (sshkey_is_sk(ca) &&
		    (ca->sk_flags & SSH_SK_USER_VERIFICATION_REQD)) {
			אם ((pin = read_passphrase("Enter PIN for CA key: ",
			    RP_ALLOW_STDIN)) == عدم)
				fatal_f("couldn't read PIN");
		}
	}
	حرر(tmp);

	אם (key_type_name != عدم) {
		אם (sshkey_type_from_shortname(key_type_name) != ca->type) {
			fatal("CA key type %s doesn't match specified %s",
			    sshkey_ssh_name(ca), key_type_name);
		}
	} אחרת אם (ca->type == KEY_RSA) {
		/* Default to a good signature algorithm */
		key_type_name = "rsa-sha2-512";
	}
	ca_fp = sshkey_fingerprint(ca, fingerprint_hash, SSH_FP_DEFAULT);

	finalise_cert_exts();
	עבור (i = 0; i < argc; i++) {
		/* Split list of principals */
		n = 0;
		אם (cert_principals != عدم) {
			otmp = tmp = xstrdup(cert_principals);
			plist = عدم;
			עבור (; (cp = strsep(&tmp, ",")) != عدم; n++) {
				plist = xreallocarray(plist, n + 1, حجم(*plist));
				אם (*(plist[n] = xstrdup(cp)) == '\0')
					fatal("Empty principal name");
			}
			حرر(otmp);
		}
		אם (n > SSHKEY_CERT_MAX_PRINCIPALS)
			fatal("Too many certificate principals specified");

		tmp = tilde_expand_filename(argv[i], pw->pw_uid);
		אם ((r = sshkey_load_public(tmp, &عام, &comment)) != 0)
			fatal_r(r, "load pubkey \"%s\"", tmp);
		אם (sshkey_is_cert(عام))
			fatal_f("key \"%s\" type %s cannot be certified",
			    tmp, sshkey_type(عام));

		/* Prepare certificate to sign */
		אם ((r = sshkey_to_certified(عام)) != 0)
			fatal_r(r, "Could not upgrade key %s to certificate", tmp);
		عام->cert->type = cert_key_type;
		عام->cert->serial = (uint64_t)cert_serial;
		عام->cert->key_id = xstrdup(cert_key_id);
		عام->cert->nprincipals = n;
		عام->cert->principals = plist;
		عام->cert->valid_after = cert_valid_from;
		عام->cert->valid_before = cert_valid_to;
		prepare_options_buf(عام->cert->critical, OPTIONS_CRITICAL);
		prepare_options_buf(عام->cert->extensions,
		    OPTIONS_EXTENSIONS);
		אם ((r = sshkey_from_private(ca,
		    &عام->cert->signature_key)) != 0)
			fatal_r(r, "sshkey_from_private (ca key)");

		אם (key_in_agent) {
			אם ((r = sshkey_certify_custom(عام, ca,
			    key_type_name, sk_provider, عدم, agent_signer,
			    &agent_fd)) != 0)
				fatal_r(r, "Couldn't certify %s via agent", tmp);
		} אחרת {
			אם (sshkey_is_sk(ca) &&
			    (ca->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
				notifier = notify_start(0,
				    "Confirm user presence for key %s %s",
				    sshkey_type(ca), ca_fp);
			}
			r = sshkey_certify(عام, ca, key_type_name,
			    sk_provider, pin);
			notify_complete(notifier, "User presence confirmed");
			אם (r != 0)
				fatal_r(r, "Couldn't certify key %s", tmp);
		}

		אם ((cp = strrchr(tmp, '.')) != عدم && strcmp(cp, ".pub") == 0)
			*cp = '\0';
		xasprintf(&out, "%s-cert.pub", tmp);
		حرر(tmp);

		אם ((r = sshkey_save_public(عام, out, comment)) != 0) {
			fatal_r(r, "Unable to save public key to %s",
			    identity_file);
		}

		אם (!quiet) {
			sshkey_format_cert_validity(عام->cert,
			    valid, حجم(valid));
			logit("Signed %s key %s: id \"%s\" serial %llu%s%s "
			    "valid %s", sshkey_cert_type(عام),
			    out, عام->cert->key_id,
			    (unsigned long long)عام->cert->serial,
			    cert_principals != عدم ? " for " : "",
			    cert_principals != عدم ? cert_principals : "",
			    valid);
		}

		sshkey_free(عام);
		حرر(out);
		حرر(comment);
		אם (cert_serial_autoinc)
			cert_serial++;
	}
	אם (pin != عدم)
		freezero(pin, strlen(pin));
	sshkey_free(ca);
	حرر(ca_fp);
#ifdef ENABLE_PKCS11
	pkcs11_terminate();
#endif
}

ساكن uint64_t
parse_relative_time(ثابت حرف *s, time_t now)
{
	int64_t mul, secs;

	mul = *s == '-' ? -1 : 1;

	אם ((secs = convtime(s + 1)) == -1)
		fatal("Invalid relative certificate time %s", s);
	אם (mul == -1 && secs > now)
		fatal("Certificate time %s cannot be represented", s);
	החזר now + (uint64_t)(secs * mul);
}

ساكن فراغ
parse_hex_u64(ثابت حرف *s, uint64_t *up)
{
	حرف *ep;
	unsigned long long ull;

	errno = 0;
	ull = strtoull(s, &ep, 16);
	אם (*s == '\0' || *ep != '\0')
		fatal("Invalid certificate time: not a number");
	אם (errno == ERANGE && ull == ULONG_MAX)
		fatal_fr(SSH_ERR_SYSTEM_ERROR, "Invalid certificate time");
	*up = (uint64_t)ull;
}

ساكن فراغ
parse_cert_times(حرف *timespec)
{
	حرف *from, *to;
	time_t now = time(عدم);
	int64_t secs;

	/* +timespec relative to now */
	אם (*timespec == '+' && strchr(timespec, ':') == عدم) {
		אם ((secs = convtime(timespec + 1)) == -1)
			fatal("Invalid relative certificate life %s", timespec);
		cert_valid_to = now + secs;
		/*
		 * Backdate certificate one minute to avoid problems on hosts
		 * with poorly-synchronised clocks.
		 */
		cert_valid_from = ((now - 59)/ 60) * 60;
		החזר;
	}

	/*
	 * from:to, where
	 * from := [+-]timespec | YYYYMMDD | YYYYMMDDHHMMSS | 0x... | "always"
	 *   to := [+-]timespec | YYYYMMDD | YYYYMMDDHHMMSS | 0x... | "forever"
	 */
	from = xstrdup(timespec);
	to = strchr(from, ':');
	אם (to == عدم || from == to || *(to + 1) == '\0')
		fatal("Invalid certificate life specification %s", timespec);
	*to++ = '\0';

	אם (*from == '-' || *from == '+')
		cert_valid_from = parse_relative_time(from, now);
	אחרת אם (strcmp(from, "always") == 0)
		cert_valid_from = 0;
	אחרת אם (strncmp(from, "0x", 2) == 0)
		parse_hex_u64(from, &cert_valid_from);
	אחרת אם (parse_absolute_time(from, &cert_valid_from) != 0)
		fatal("Invalid from time \"%s\"", from);

	אם (*to == '-' || *to == '+')
		cert_valid_to = parse_relative_time(to, now);
	אחרת אם (strcmp(to, "forever") == 0)
		cert_valid_to = ~(uint64_t)0;
	אחרת אם (strncmp(to, "0x", 2) == 0)
		parse_hex_u64(to, &cert_valid_to);
	אחרת אם (parse_absolute_time(to, &cert_valid_to) != 0)
		fatal("Invalid to time \"%s\"", to);

	אם (cert_valid_to <= cert_valid_from)
		fatal("Empty certificate validity interval");
	حرر(from);
}

ساكن فراغ
add_cert_option(حرف *opt)
{
	حرف *val, *cp;
	ثابت حرف *p;
	صحيح iscrit = 0;

	אם (strcasecmp(opt, "clear") == 0)
		certflags_flags = 0;
	אחרת אם (strcasecmp(opt, "no-x11-forwarding") == 0)
		certflags_flags &= ~CERTOPT_X_FWD;
	אחרת אם (strcasecmp(opt, "permit-x11-forwarding") == 0)
		certflags_flags |= CERTOPT_X_FWD;
	אחרת אם (strcasecmp(opt, "no-agent-forwarding") == 0)
		certflags_flags &= ~CERTOPT_AGENT_FWD;
	אחרת אם (strcasecmp(opt, "permit-agent-forwarding") == 0)
		certflags_flags |= CERTOPT_AGENT_FWD;
	אחרת אם (strcasecmp(opt, "no-port-forwarding") == 0)
		certflags_flags &= ~CERTOPT_PORT_FWD;
	אחרת אם (strcasecmp(opt, "permit-port-forwarding") == 0)
		certflags_flags |= CERTOPT_PORT_FWD;
	אחרת אם (strcasecmp(opt, "no-pty") == 0)
		certflags_flags &= ~CERTOPT_PTY;
	אחרת אם (strcasecmp(opt, "permit-pty") == 0)
		certflags_flags |= CERTOPT_PTY;
	אחרת אם (strcasecmp(opt, "no-user-rc") == 0)
		certflags_flags &= ~CERTOPT_USER_RC;
	אחרת אם (strcasecmp(opt, "permit-user-rc") == 0)
		certflags_flags |= CERTOPT_USER_RC;
	אחרת אם (strcasecmp(opt, "touch-required") == 0)
		certflags_flags &= ~CERTOPT_NO_REQUIRE_USER_PRESENCE;
	אחרת אם (strcasecmp(opt, "no-touch-required") == 0)
		certflags_flags |= CERTOPT_NO_REQUIRE_USER_PRESENCE;
	אחרת אם (strcasecmp(opt, "no-verify-required") == 0)
		certflags_flags &= ~CERTOPT_REQUIRE_VERIFY;
	אחרת אם (strcasecmp(opt, "verify-required") == 0)
		certflags_flags |= CERTOPT_REQUIRE_VERIFY;
	אחרת אם ((p = strprefix(opt, "force-command=", 1)) != عدم) {
		אם (*p == '\0')
			fatal("Empty force-command option");
		אם (certflags_command != عدم)
			fatal("force-command already specified");
		certflags_command = xstrdup(p);
	} אחרת אם ((p = strprefix(opt, "source-address=", 1)) != عدم) {
		אם (*p == '\0')
			fatal("Empty source-address option");
		אם (certflags_src_addr != عدم)
			fatal("source-address already specified");
		אם (addr_match_cidr_list(عدم, p) != 0)
			fatal("Invalid source-address list");
		certflags_src_addr = xstrdup(p);
	} אחרת אם (strprefix(opt, "extension:", 1) != عدم ||
		    (iscrit = (strprefix(opt, "critical:", 1) != عدم))) {
		val = xstrdup(strchr(opt, ':') + 1);
		אם ((cp = strchr(val, '=')) != عدم)
			*cp++ = '\0';
		cert_ext_add(val, cp, iscrit);
		حرر(val);
	} אחרת
		fatal("Unsupported certificate option \"%s\"", opt);
}

ساكن فراغ
show_options(بنية sshbuf *optbuf, صحيح in_critical)
{
	حرف *name, *arg, *hex;
	بنية sshbuf *options, *option = عدم;
	صحيح r;

	אם ((options = sshbuf_fromb(optbuf)) == عدم)
		fatal_f("sshbuf_fromb failed");
	כלעוד (sshbuf_len(options) != 0) {
		sshbuf_free(option);
		option = عدم;
		אם ((r = sshbuf_get_cstring(options, &name, عدم)) != 0 ||
		    (r = sshbuf_froms(options, &option)) != 0)
			fatal_fr(r, "parse option");
		printf("                %s", name);
		אם (!in_critical &&
		    (strcmp(name, "permit-X11-forwarding") == 0 ||
		    strcmp(name, "permit-agent-forwarding") == 0 ||
		    strcmp(name, "permit-port-forwarding") == 0 ||
		    strcmp(name, "permit-pty") == 0 ||
		    strcmp(name, "permit-user-rc") == 0 ||
		    strcmp(name, "no-touch-required") == 0)) {
			printf("\n");
		} אחרת אם (in_critical &&
		    (strcmp(name, "force-command") == 0 ||
		    strcmp(name, "source-address") == 0)) {
			אם ((r = sshbuf_get_cstring(option, &arg, عدم)) != 0)
				fatal_fr(r, "parse critical");
			printf(" %s\n", arg);
			حرر(arg);
		} אחרת אם (in_critical &&
		    strcmp(name, "verify-required") == 0) {
			printf("\n");
		} אחרת אם (sshbuf_len(option) > 0) {
			hex = sshbuf_dtob16(option);
			printf(" UNKNOWN OPTION: %s (len %zu)\n",
			    hex, sshbuf_len(option));
			sshbuf_reset(option);
			حرر(hex);
		} אחרת
			printf(" UNKNOWN FLAG OPTION\n");
		حرر(name);
		אם (sshbuf_len(option) != 0)
			fatal("Option corrupt: extra data at end");
	}
	sshbuf_free(option);
	sshbuf_free(options);
}

ساكن فراغ
print_cert(بنية sshkey *key)
{
	حرف valid[64], *key_fp, *ca_fp;
	u_int i;

	key_fp = sshkey_fingerprint(key, fingerprint_hash, SSH_FP_DEFAULT);
	ca_fp = sshkey_fingerprint(key->cert->signature_key,
	    fingerprint_hash, SSH_FP_DEFAULT);
	אם (key_fp == عدم || ca_fp == عدم)
		fatal_f("sshkey_fingerprint fail");
	sshkey_format_cert_validity(key->cert, valid, حجم(valid));

	printf("        Type: %s %s certificate\n", sshkey_ssh_name(key),
	    sshkey_cert_type(key));
	printf("        Public key: %s %s\n", sshkey_type(key), key_fp);
	printf("        Signing CA: %s %s (using %s)\n",
	    sshkey_type(key->cert->signature_key), ca_fp,
	    key->cert->signature_type);
	printf("        Key ID: \"%s\"\n", key->cert->key_id);
	printf("        Serial: %llu\n", (unsigned long long)key->cert->serial);
	printf("        Valid: %s\n", valid);
	printf("        Principals: ");
	אם (key->cert->nprincipals == 0)
		printf("(none)\n");
	אחרת {
		עבור (i = 0; i < key->cert->nprincipals; i++)
			printf("\n                %s",
			    key->cert->principals[i]);
		printf("\n");
	}
	printf("        Critical Options: ");
	אם (sshbuf_len(key->cert->critical) == 0)
		printf("(none)\n");
	אחרת {
		printf("\n");
		show_options(key->cert->critical, 1);
	}
	printf("        Extensions: ");
	אם (sshbuf_len(key->cert->extensions) == 0)
		printf("(none)\n");
	אחרת {
		printf("\n");
		show_options(key->cert->extensions, 0);
	}
	حرر(key_fp);
	حرر(ca_fp);
}

ساكن فراغ
do_show_cert(بنية passwd *pw)
{
	بنية sshkey *key = عدم;
	بنية stat st;
	صحيح r, is_stdin = 0, ok = 0;
	FILE *f;
	حرف *cp, *line = عدم;
	ثابت حرف *path;
	size_t linesize = 0;
	u_long lnum = 0;

	אם (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	אם (strcmp(identity_file, "-") != 0 && stat(identity_file, &st) == -1)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));

	path = identity_file;
	אם (strcmp(path, "-") == 0) {
		f = stdin;
		path = "(stdin)";
		is_stdin = 1;
	} אחרת אם ((f = fopen(identity_file, "r")) == عدم)
		fatal("fopen %s: %s", identity_file, strerror(errno));

	כלעוד (getline(&line, &linesize, f) != -1) {
		lnum++;
		sshkey_free(key);
		key = عدم;
		/* Trim leading space and comments */
		cp = line + strspn(line, " \t");
		אם (*cp == '#' || *cp == '\0')
			استمر;
		אם ((key = sshkey_new(KEY_UNSPEC)) == عدم)
			fatal("sshkey_new");
		אם ((r = sshkey_read(key, &cp)) != 0) {
			error_r(r, "%s:%lu: invalid key", path, lnum);
			استمر;
		}
		אם (!sshkey_is_cert(key)) {
			error("%s:%lu is not a certificate", path, lnum);
			استمر;
		}
		ok = 1;
		אם (!is_stdin && lnum == 1)
			printf("%s:\n", path);
		אחרת
			printf("%s:%lu:\n", path, lnum);
		print_cert(key);
	}
	حرر(line);
	sshkey_free(key);
	fclose(f);
	exit(ok ? 0 : 1);
}

ساكن فراغ
load_krl(ثابت حرف *path, بنية ssh_krl **krlp)
{
	بنية sshbuf *krlbuf;
	صحيح r;

	אם ((r = sshbuf_load_file(path, &krlbuf)) != 0)
		fatal_r(r, "Unable to load KRL %s", path);
	/* XXX check sigs */
	אם ((r = ssh_krl_from_blob(krlbuf, krlp)) != 0 ||
	    *krlp == عدم)
		fatal_r(r, "Invalid KRL file %s", path);
	sshbuf_free(krlbuf);
}

ساكن فراغ
hash_to_blob(ثابت حرف *cp, u_char **blobp, size_t *lenp,
    ثابت حرف *file, u_long lnum)
{
	حرف *tmp;
	size_t tlen;
	بنية sshbuf *b;
	صحيح r;

	אם ((cp = strprefix(cp, "SHA256:", 0)) == عدم)
		fatal("%s:%lu: unsupported hash algorithm", file, lnum);

	/*
	 * OpenSSH base64 hashes omit trailing '='
	 * characters; put them back for decode.
	 */
	אם ((tlen = strlen(cp)) >= SIZE_MAX - 5)
		fatal_f("hash too long: %zu bytes", tlen);
	tmp = xmalloc(tlen + 4 + 1);
	strlcpy(tmp, cp, tlen + 1);
	כלעוד ((tlen % 4) != 0) {
		tmp[tlen++] = '=';
		tmp[tlen] = '\0';
	}
	אם ((b = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	אם ((r = sshbuf_b64tod(b, tmp)) != 0)
		fatal_r(r, "%s:%lu: decode hash failed", file, lnum);
	حرر(tmp);
	*lenp = sshbuf_len(b);
	*blobp = xmalloc(*lenp);
	memcpy(*blobp, sshbuf_ptr(b), *lenp);
	sshbuf_free(b);
}

ساكن فراغ
update_krl_from_file(بنية passwd *pw, ثابت حرف *file, صحيح wild_ca,
    ثابت بنية sshkey *ca, بنية ssh_krl *krl)
{
	بنية sshkey *key = عدم;
	u_long lnum = 0;
	حرف *path, *cp, *ep, *line = عدم;
	u_char *blob = عدم;
	size_t blen = 0, linesize = 0;
	unsigned long long serial, serial2;
	صحيح i, was_explicit_key, was_sha1, was_sha256, was_hash, r;
	FILE *krl_spec;

	path = tilde_expand_filename(file, pw->pw_uid);
	אם (strcmp(path, "-") == 0) {
		krl_spec = stdin;
		حرر(path);
		path = xstrdup("(standard input)");
	} אחרת אם ((krl_spec = fopen(path, "r")) == عدم)
		fatal("fopen %s: %s", path, strerror(errno));

	אם (!quiet)
		printf("Revoking from %s\n", path);
	כלעוד (getline(&line, &linesize, krl_spec) != -1) {
		אם (linesize >= INT_MAX) {
			fatal_f("%s contains unparsable line, len=%zu",
			    path, linesize);
		}
		lnum++;
		was_explicit_key = was_sha1 = was_sha256 = was_hash = 0;
		cp = line + strspn(line, " \t");
		/* Trim trailing space, comments and strip \n */
		עבור (i = 0, r = -1; cp[i] != '\0'; i++) {
			אם (cp[i] == '#' || cp[i] == '\n') {
				cp[i] = '\0';
				اكسر;
			}
			אם (cp[i] == ' ' || cp[i] == '\t') {
				/* Remember the start of a span of whitespace */
				אם (r == -1)
					r = i;
			} אחרת
				r = -1;
		}
		אם (r != -1)
			cp[r] = '\0';
		אם (*cp == '\0')
			استمر;
		אם (strncasecmp(cp, "serial:", 7) == 0) {
			אם (ca == عدم && !wild_ca) {
				fatal("revoking certificates by serial number "
				    "requires specification of a CA key");
			}
			cp += 7;
			cp = cp + strspn(cp, " \t");
			errno = 0;
			serial = strtoull(cp, &ep, 0);
			אם (*cp == '\0' || (*ep != '\0' && *ep != '-'))
				fatal("%s:%lu: invalid serial \"%s\"",
				    path, lnum, cp);
			אם (errno == ERANGE && serial == ULLONG_MAX)
				fatal("%s:%lu: serial out of range",
				    path, lnum);
			serial2 = serial;
			אם (*ep == '-') {
				cp = ep + 1;
				errno = 0;
				serial2 = strtoull(cp, &ep, 0);
				אם (*cp == '\0' || *ep != '\0')
					fatal("%s:%lu: invalid serial \"%s\"",
					    path, lnum, cp);
				אם (errno == ERANGE && serial2 == ULLONG_MAX)
					fatal("%s:%lu: serial out of range",
					    path, lnum);
				אם (serial2 <= serial)
					fatal("%s:%lu: invalid serial range "
					    "%llu:%llu", path, lnum,
					    (unsigned long long)serial,
					    (unsigned long long)serial2);
			}
			אם (ssh_krl_revoke_cert_by_serial_range(krl,
			    ca, serial, serial2) != 0) {
				fatal_f("revoke serial failed");
			}
		} אחרת אם (strncasecmp(cp, "id:", 3) == 0) {
			אם (ca == عدم && !wild_ca) {
				fatal("revoking certificates by key ID "
				    "requires specification of a CA key");
			}
			cp += 3;
			cp = cp + strspn(cp, " \t");
			אם (ssh_krl_revoke_cert_by_key_id(krl, ca, cp) != 0)
				fatal_f("revoke key ID failed");
		} אחרת אם (strncasecmp(cp, "hash:", 5) == 0) {
			cp += 5;
			cp = cp + strspn(cp, " \t");
			hash_to_blob(cp, &blob, &blen, file, lnum);
			אם ((r = ssh_krl_revoke_key_sha256(krl,
			    blob, blen)) != 0)
				fatal_fr(r, "revoke key failed");
			حرر(blob);
			blob = عدم;
			blen = 0;
		} אחרת {
			אם (strncasecmp(cp, "key:", 4) == 0) {
				cp += 4;
				cp = cp + strspn(cp, " \t");
				was_explicit_key = 1;
			} אחרת אם (strncasecmp(cp, "sha1:", 5) == 0) {
				cp += 5;
				cp = cp + strspn(cp, " \t");
				was_sha1 = 1;
			} אחרת אם (strncasecmp(cp, "sha256:", 7) == 0) {
				cp += 7;
				cp = cp + strspn(cp, " \t");
				was_sha256 = 1;
				/*
				 * Just try to process the line as a key.
				 * Parsing will fail if it isn't.
				 */
			}
			אם ((key = sshkey_new(KEY_UNSPEC)) == عدم)
				fatal("sshkey_new");
			אם ((r = sshkey_read(key, &cp)) != 0)
				fatal_r(r, "%s:%lu: invalid key", path, lnum);
			אם (was_explicit_key)
				r = ssh_krl_revoke_key_explicit(krl, key);
			אחרת אם (was_sha1) {
				אם (sshkey_fingerprint_raw(key,
				    SSH_DIGEST_SHA1, &blob, &blen) != 0) {
					fatal("%s:%lu: fingerprint failed",
					    file, lnum);
				}
				r = ssh_krl_revoke_key_sha1(krl, blob, blen);
			} אחרת אם (was_sha256) {
				אם (sshkey_fingerprint_raw(key,
				    SSH_DIGEST_SHA256, &blob, &blen) != 0) {
					fatal("%s:%lu: fingerprint failed",
					    file, lnum);
				}
				r = ssh_krl_revoke_key_sha256(krl, blob, blen);
			} אחרת
				r = ssh_krl_revoke_key(krl, key);
			אם (r != 0)
				fatal_fr(r, "revoke key failed");
			freezero(blob, blen);
			blob = عدم;
			blen = 0;
			sshkey_free(key);
		}
	}
	אם (strcmp(path, "-") != 0)
		fclose(krl_spec);
	حرر(line);
	حرر(path);
}

ساكن فراغ
do_gen_krl(بنية passwd *pw, صحيح updating, ثابت حرف *ca_key_path,
    unsigned long long krl_version, ثابت حرف *krl_comment,
    صحيح argc, حرف **argv)
{
	بنية ssh_krl *krl;
	بنية stat sb;
	بنية sshkey *ca = عدم;
	صحيح i, r, wild_ca = 0;
	حرف *tmp;
	بنية sshbuf *kbuf;

	אם (*identity_file == '\0')
		fatal("KRL generation requires an output file");
	אם (stat(identity_file, &sb) == -1) {
		אם (errno != ENOENT)
			fatal("Cannot access KRL \"%s\": %s",
			    identity_file, strerror(errno));
		אם (updating)
			fatal("KRL \"%s\" does not exist", identity_file);
	}
	אם (ca_key_path != عدم) {
		אם (strcasecmp(ca_key_path, "none") == 0)
			wild_ca = 1;
		אחרת {
			tmp = tilde_expand_filename(ca_key_path, pw->pw_uid);
			אם ((r = sshkey_load_public(tmp, &ca, عدم)) != 0)
				fatal_r(r, "Cannot load CA public key %s", tmp);
			حرر(tmp);
		}
	}

	אם (updating)
		load_krl(identity_file, &krl);
	אחרת אם ((krl = ssh_krl_init()) == عدم)
		fatal("couldn't create KRL");

	אם (krl_version != 0)
		ssh_krl_set_version(krl, krl_version);
	אם (krl_comment != عدم)
		ssh_krl_set_comment(krl, krl_comment);

	עבור (i = 0; i < argc; i++)
		update_krl_from_file(pw, argv[i], wild_ca, ca, krl);

	אם ((kbuf = sshbuf_new()) == عدم)
		fatal("sshbuf_new failed");
	אם (ssh_krl_to_blob(krl, kbuf) != 0)
		fatal("Couldn't generate KRL");
	אם ((r = sshbuf_write_file(identity_file, kbuf)) != 0)
		fatal("write %s: %s", identity_file, strerror(errno));
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

	אם (*identity_file == '\0')
		fatal("KRL checking requires an input file");
	load_krl(identity_file, &krl);
	אם (print_krl)
		krl_dump(krl, stdout);
	עבור (i = 0; i < argc; i++) {
		אם ((r = sshkey_load_public(argv[i], &k, &comment)) != 0)
			fatal_r(r, "Cannot load public key %s", argv[i]);
		r = ssh_krl_check_key(krl, k);
		printf("%s%s%s%s: %s\n", argv[i],
		    *comment ? " (" : "", comment, *comment ? ")" : "",
		    r == 0 ? "ok" : "REVOKED");
		אם (r != 0)
			ret = 1;
		sshkey_free(k);
		حرر(comment);
	}
	ssh_krl_free(krl);
	exit(ret);
}

ساكن بنية sshkey *
load_sign_key(ثابت حرف *keypath, ثابت بنية sshkey *pubkey)
{
	size_t i, slen, plen = strlen(keypath);
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
	עבור (i = 0; suffixes[i]; i++) {
		slen = strlen(suffixes[i]);
		אם (plen <= slen ||
		    strcmp(privpath + plen - slen, suffixes[i]) != 0)
			استمر;
		privpath[plen - slen] = '\0';
		debug_f("%s looks like a public key, using private key "
		    "path %s instead", keypath, privpath);
		waspub = 1;
	}
	אם (waspub && stat(privpath, &st) != 0 && errno == ENOENT)
		fatal("No private key found for public key \"%s\"", keypath);
	אם ((r = sshkey_load_private(privpath, "", &privkey, عدم)) != 0 &&
	    (r != SSH_ERR_KEY_WRONG_PASSPHRASE)) {
		debug_fr(r, "load private key \"%s\"", privpath);
		fatal("No private key found for \"%s\"", privpath);
	} אחרת אם (privkey == عدم)
		privkey = load_identity(privpath, عدم);

	אם (!sshkey_equal_public(pubkey, privkey)) {
		error("Public key %s doesn't match private %s",
		    keypath, privpath);
		اذهب done;
	}
	אם (sshkey_is_cert(pubkey) && !sshkey_is_cert(privkey)) {
		/*
		 * Graft the certificate onto the private key to make
		 * it capable of signing.
		 */
		אם ((r = sshkey_to_certified(privkey)) != 0) {
			error_fr(r, "sshkey_to_certified");
			اذهب done;
		}
		אם ((r = sshkey_cert_copy(pubkey, privkey)) != 0) {
			error_fr(r, "sshkey_cert_copy");
			اذهب done;
		}
	}
	/* success */
	ret = privkey;
	privkey = عدم;
 done:
	sshkey_free(privkey);
	حرر(privpath);
	החזר ret;
}

ساكن صحيح
sign_one(بنية sshkey *signkey, ثابت حرف *filename, صحيح fd,
    ثابت حرف *sig_namespace, ثابت حرف *hashalg, sshsig_signer *signer,
    فراغ *signer_ctx)
{
	بنية sshbuf *sigbuf = عدم, *abuf = عدم;
	صحيح r = SSH_ERR_INTERNAL_ERROR, wfd = -1, oerrno;
	حرف *wfile = عدم, *asig = عدم, *fp = عدم;
	حرف *pin = عدم, *prompt = عدم;

	אם (!quiet) {
		אם (fd == STDIN_FILENO)
			fprintf(stderr, "Signing data on standard input\n");
		אחרת
			fprintf(stderr, "Signing file %s\n", filename);
	}
	אם (signer == عدم && sshkey_is_sk(signkey)) {
		אם ((signkey->sk_flags & SSH_SK_USER_VERIFICATION_REQD)) {
			xasprintf(&prompt, "Enter PIN for %s key: ",
			    sshkey_type(signkey));
			אם ((pin = read_passphrase(prompt,
			    RP_ALLOW_STDIN)) == عدم)
				fatal_f("couldn't read PIN");
		}
		אם ((signkey->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
			אם ((fp = sshkey_fingerprint(signkey, fingerprint_hash,
			    SSH_FP_DEFAULT)) == عدم)
				fatal_f("fingerprint failed");
			fprintf(stderr, "Confirm user presence for key %s %s\n",
			    sshkey_type(signkey), fp);
			حرر(fp);
		}
	}
	אם ((r = sshsig_sign_fd(signkey, hashalg, sk_provider, pin,
	    fd, sig_namespace, &sigbuf, signer, signer_ctx)) != 0) {
		error_r(r, "Signing %s failed", filename);
		اذهب out;
	}
	אם ((r = sshsig_armor(sigbuf, &abuf)) != 0) {
		error_fr(r, "sshsig_armor");
		اذهب out;
	}
	אם ((asig = sshbuf_dup_string(abuf)) == عدم) {
		error_f("buffer error");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}

	אם (fd == STDIN_FILENO) {
		fputs(asig, stdout);
		fflush(stdout);
	} אחרת {
		xasprintf(&wfile, "%s.sig", filename);
		אם (confirm_overwrite(wfile)) {
			אם ((wfd = open(wfile, O_WRONLY|O_CREAT|O_TRUNC,
			    0666)) == -1) {
				oerrno = errno;
				error("Cannot open %s: %s",
				    wfile, strerror(errno));
				errno = oerrno;
				r = SSH_ERR_SYSTEM_ERROR;
				اذهب out;
			}
			אם (atomicio(vwrite, wfd, asig,
			    strlen(asig)) != strlen(asig)) {
				oerrno = errno;
				error("Cannot write to %s: %s",
				    wfile, strerror(errno));
				errno = oerrno;
				r = SSH_ERR_SYSTEM_ERROR;
				اذهب out;
			}
			אם (!quiet) {
				fprintf(stderr, "Write signature to %s\n",
				    wfile);
			}
		}
	}
	/* success */
	r = 0;
 out:
	حرر(wfile);
	حرر(prompt);
	حرر(asig);
	אם (pin != عدم)
		freezero(pin, strlen(pin));
	sshbuf_free(abuf);
	sshbuf_free(sigbuf);
	אם (wfd != -1)
		close(wfd);
	החזר r;
}

ساكن صحيح
sig_process_opts(حرف * ثابت *opts, size_t nopts, حرف **hashalgp,
    uint64_t *verify_timep, صحيح *print_pubkey)
{
	size_t i;
	time_t now;
	ثابت حرف *p;

	אם (verify_timep != عدم)
		*verify_timep = 0;
	אם (print_pubkey != عدم)
		*print_pubkey = 0;
	אם (hashalgp != عدم)
		*hashalgp = عدم;
	עבור (i = 0; i < nopts; i++) {
		אם (hashalgp != عدم &&
		    (p = strprefix(opts[i], "hashalg=", 1)) != عدم) {
			*hashalgp = xstrdup(p);
		} אחרת אם (verify_timep &&
		    (p = strprefix(opts[i], "verify-time=", 1)) != عدم) {
			אם (parse_absolute_time(p, verify_timep) != 0 ||
			    *verify_timep == 0) {
				error("Invalid \"verify-time\" option");
				החזר SSH_ERR_INVALID_ARGUMENT;
			}
		} אחרת אם (print_pubkey &&
		    strcasecmp(opts[i], "print-pubkey") == 0) {
			*print_pubkey = 1;
		} אחרת {
			error("Invalid option \"%s\"", opts[i]);
			החזר SSH_ERR_INVALID_ARGUMENT;
		}
	}
	אם (verify_timep && *verify_timep == 0) {
		אם ((now = time(عدم)) < 0) {
			error("Time is before epoch");
			החזר SSH_ERR_INVALID_ARGUMENT;
		}
		*verify_timep = (uint64_t)now;
	}
	החזר 0;
}


ساكن صحيح
sig_sign(ثابت حرف *keypath, ثابت حرف *sig_namespace, صحيح require_agent,
    صحيح argc, حرف **argv, حرف * ثابت *opts, size_t nopts)
{
	صحيح i, fd = -1, r, ret = -1;
	صحيح agent_fd = -1;
	بنية sshkey *pubkey = عدم, *privkey = عدم, *signkey = عدم;
	sshsig_signer *signer = عدم;
	حرف *hashalg = عدم;

	/* Check file arguments. */
	עבור (i = 0; i < argc; i++) {
		אם (strcmp(argv[i], "-") != 0)
			استمر;
		אם (i > 0 || argc > 1)
			fatal("Cannot sign mix of paths and standard input");
	}

	אם (sig_process_opts(opts, nopts, &hashalg, عدم, عدم) != 0)
		اذهب done; /* error already logged */

	אם ((r = sshkey_load_public(keypath, &pubkey, عدم)) != 0) {
		error_r(r, "Couldn't load public key %s", keypath);
		اذهب done;
	}

	אם ((r = ssh_get_authentication_socket(&agent_fd)) != 0) {
		אם (require_agent)
			fatal("Couldn't get agent socket");
		debug_r(r, "Couldn't get agent socket");
	} אחרת {
		אם ((r = ssh_agent_has_key(agent_fd, pubkey)) == 0)
			signer = agent_signer;
		אחרת {
			אם (require_agent)
				fatal("Couldn't find key in agent");
			debug_r(r, "Couldn't find key in agent");
		}
	}

	אם (signer == عدم) {
		/* Not using agent - try to load private key */
		אם ((privkey = load_sign_key(keypath, pubkey)) == عدم)
			اذهب done;
		signkey = privkey;
	} אחרת {
		/* Will use key in agent */
		signkey = pubkey;
	}

	אם (argc == 0) {
		אם ((r = sign_one(signkey, "(stdin)", STDIN_FILENO,
		    sig_namespace, hashalg, signer, &agent_fd)) != 0)
			اذهب done;
	} אחרת {
		עבור (i = 0; i < argc; i++) {
			אם (strcmp(argv[i], "-") == 0)
				fd = STDIN_FILENO;
			אחרת אם ((fd = open(argv[i], O_RDONLY)) == -1) {
				error("Cannot open %s for signing: %s",
				    argv[i], strerror(errno));
				اذهب done;
			}
			אם ((r = sign_one(signkey, argv[i], fd, sig_namespace,
			    hashalg, signer, &agent_fd)) != 0)
				اذهب done;
			אם (fd != STDIN_FILENO)
				close(fd);
			fd = -1;
		}
	}

	ret = 0;
done:
	אם (fd != -1 && fd != STDIN_FILENO)
		close(fd);
	sshkey_free(pubkey);
	sshkey_free(privkey);
	حرر(hashalg);
	החזר ret;
}

ساكن صحيح
sig_verify(ثابت حرف *signature, ثابت حرف *sig_namespace,
    ثابت حرف *principal, ثابت حرف *allowed_keys, ثابت حرف *revoked_keys,
    حرف * ثابت *opts, size_t nopts)
{
	صحيح r, ret = -1;
	صحيح print_pubkey = 0;
	بنية sshbuf *sigbuf = عدم, *abuf = عدم;
	بنية sshkey *sign_key = عدم;
	حرف *fp = عدم;
	بنية sshkey_sig_details *sig_details = عدم;
	uint64_t verify_time = 0;

	אם (sig_process_opts(opts, nopts, عدم, &verify_time,
	    &print_pubkey) != 0)
		اذهب done; /* error already logged */

	memset(&sig_details, 0, حجم(sig_details));
	אם ((r = sshbuf_load_file(signature, &abuf)) != 0) {
		error_r(r, "Couldn't read signature file");
		اذهب done;
	}

	אם ((r = sshsig_dearmor(abuf, &sigbuf)) != 0) {
		error_fr(r, "sshsig_armor");
		اذهب done;
	}
	אם ((r = sshsig_verify_fd(sigbuf, STDIN_FILENO, sig_namespace,
	    &sign_key, &sig_details)) != 0)
		اذهب done; /* sshsig_verify() prints error */

	אם ((fp = sshkey_fingerprint(sign_key, fingerprint_hash,
	    SSH_FP_DEFAULT)) == عدم)
		fatal_f("sshkey_fingerprint failed");
	debug("Valid (unverified) signature from key %s", fp);
	אם (sig_details != عدم) {
		debug2_f("signature details: counter = %u, flags = 0x%02x",
		    sig_details->sk_counter, sig_details->sk_flags);
	}
	حرر(fp);
	fp = عدم;

	אם (revoked_keys != عدم) {
		אם ((r = sshkey_check_revoked(sign_key, revoked_keys)) != 0) {
			debug3_fr(r, "sshkey_check_revoked");
			اذهب done;
		}
	}

	אם (allowed_keys != عدم && (r = sshsig_check_allowed_keys(allowed_keys,
	    sign_key, principal, sig_namespace, verify_time)) != 0) {
		debug3_fr(r, "sshsig_check_allowed_keys");
		اذهب done;
	}
	/* success */
	ret = 0;
done:
	אם (!quiet) {
		אם (ret == 0) {
			אם ((fp = sshkey_fingerprint(sign_key, fingerprint_hash,
			    SSH_FP_DEFAULT)) == عدم)
				fatal_f("sshkey_fingerprint failed");
			אם (principal == عدم) {
				printf("Good \"%s\" signature with %s key %s\n",
				    sig_namespace, sshkey_type(sign_key), fp);

			} אחרת {
				printf("Good \"%s\" signature for %s with %s key %s\n",
				    sig_namespace, principal,
				    sshkey_type(sign_key), fp);
			}
		} אחרת {
			printf("Could not verify signature.\n");
		}
	}
	/* Print the signature key if requested */
	אם (ret == 0 && print_pubkey && sign_key != عدم) {
		אם ((r = sshkey_write(sign_key, stdout)) == 0)
			fputc('\n', stdout);
		אחרת {
			error_r(r, "Could not print public key.\n");
			ret = -1;
		}
	}
	sshbuf_free(sigbuf);
	sshbuf_free(abuf);
	sshkey_free(sign_key);
	sshkey_sig_details_free(sig_details);
	حرر(fp);
	החזר ret;
}

ساكن صحيح
sig_find_principals(ثابت حرف *signature, ثابت حرف *allowed_keys,
    حرف * ثابت *opts, size_t nopts)
{
	صحيح r, ret = -1;
	بنية sshbuf *sigbuf = عدم, *abuf = عدم;
	بنية sshkey *sign_key = عدم;
	حرف *principals = عدم, *cp, *tmp;
	uint64_t verify_time = 0;

	אם (sig_process_opts(opts, nopts, عدم, &verify_time, عدم) != 0)
		اذهب done; /* error already logged */

	אם ((r = sshbuf_load_file(signature, &abuf)) != 0) {
		error_r(r, "Couldn't read signature file");
		اذهب done;
	}
	אם ((r = sshsig_dearmor(abuf, &sigbuf)) != 0) {
		error_fr(r, "sshsig_armor");
		اذهب done;
	}
	אם ((r = sshsig_get_pubkey(sigbuf, &sign_key)) != 0) {
		error_fr(r, "sshsig_get_pubkey");
		اذهب done;
	}
	אם ((r = sshsig_find_principals(allowed_keys, sign_key,
	    verify_time, &principals)) != 0) {
		אם (r != SSH_ERR_KEY_NOT_FOUND)
			error_fr(r, "sshsig_find_principal");
		اذهب done;
	}
	ret = 0;
done:
	אם (ret == 0 ) {
		/* Emit matching principals one per line */
		tmp = principals;
		כלעוד ((cp = strsep(&tmp, ",")) != عدم && *cp != '\0')
			puts(cp);
	} אחרת {
		fprintf(stderr, "No principal matched.\n");
	}
	sshbuf_free(sigbuf);
	sshbuf_free(abuf);
	sshkey_free(sign_key);
	حرر(principals);
	החזר ret;
}

ساكن صحيح
sig_match_principals(ثابت حرف *allowed_keys, حرف *principal,
	حرف * ثابت *opts, size_t nopts)
{
	صحيح r;
	حرف **principals = عدم;
	size_t i, nprincipals = 0;

	אם ((r = sig_process_opts(opts, nopts, عدم, عدم, عدم)) != 0)
		החזר r; /* error already logged */

	אם ((r = sshsig_match_principals(allowed_keys, principal,
	    &principals, &nprincipals)) != 0) {
		debug_f("match: %s", ssh_err(r));
		fprintf(stderr, "No principal matched.\n");
		החזר r;
	}
	עבור (i = 0; i < nprincipals; i++) {
		printf("%s\n", principals[i]);
		حرر(principals[i]);
	}
	حرر(principals);

	החזר 0;
}

ساكن فراغ
do_moduli_gen(ثابت حرف *out_file, حرف **opts, size_t nopts)
{
#ifdef WITH_OPENSSL
	/* Moduli generation/screening */
	BIGNUM *start = عدم;
	صحيح moduli_bits = 0;
	FILE *out;
	size_t i;
	ثابت حرف *errstr, *p;

	/* Parse options */
	עבור (i = 0; i < nopts; i++) {
		אם ((p = strprefix(opts[i], "start=", 0)) != عدم) {
			/* XXX - also compare length against bits */
			אם (BN_hex2bn(&start, p) == 0)
				fatal("Invalid start point.");
		} אחרת אם ((p = strprefix(opts[i], "bits=", 0)) != عدم) {
			moduli_bits = (صحيح)strtonum(p, 1, INT_MAX, &errstr);
			אם (errstr) {
				fatal("Invalid number: %s (%s)", p, errstr);
			}
		} אחרת {
			fatal("Option \"%s\" is unsupported for moduli "
			    "generation", opts[i]);
		}
	}

	אם (strcmp(out_file, "-") == 0)
		out = stdout;
	אחרת אם ((out = fopen(out_file, "w")) == عدم) {
		fatal("Couldn't open modulus candidate file \"%s\": %s",
		    out_file, strerror(errno));
	}
	setvbuf(out, عدم, _IOLBF, 0);

	אם (moduli_bits == 0)
		moduli_bits = DEFAULT_BITS;
	אם (gen_candidates(out, moduli_bits, start) != 0)
		fatal("modulus candidate generation failed");
#אחרת /* WITH_OPENSSL */
	fatal("Moduli generation is not supported");
#endif /* WITH_OPENSSL */
}

ساكن فراغ
do_moduli_screen(ثابت حرف *out_file, حرف **opts, size_t nopts)
{
#ifdef WITH_OPENSSL
	/* Moduli generation/screening */
	حرف *checkpoint = عدم;
	uint32_t generator_wanted = 0;
	unsigned long start_lineno = 0, lines_to_process = 0;
	صحيح prime_tests = 0;
	FILE *out, *in = stdin;
	size_t i;
	ثابت حرف *errstr, *p;

	/* Parse options */
	עבור (i = 0; i < nopts; i++) {
		אם ((p = strprefix(opts[i], "lines=", 0)) != عدم) {
			lines_to_process = strtoul(p, عدم, 10);
		} אחרת אם ((p = strprefix(opts[i], "start-line=", 0)) != عدم) {
			start_lineno = strtoul(p, عدم, 10);
		} אחרת אם ((p = strprefix(opts[i], "checkpoint=", 0)) != عدم) {
			حرر(checkpoint);
			checkpoint = xstrdup(p);
		} אחרת אם ((p = strprefix(opts[i], "generator=", 0)) != عدم) {
			generator_wanted = (uint32_t)strtonum(p, 1, UINT_MAX,
			    &errstr);
			אם (errstr != عدم) {
				fatal("Generator invalid: %s (%s)", p, errstr);
			}
		} אחרת אם ((p = strprefix(opts[i], "prime-tests=", 0)) != عدم) {
			prime_tests = (صحيح)strtonum(p, 1, INT_MAX, &errstr);
			אם (errstr) {
				fatal("Invalid number: %s (%s)", p, errstr);
			}
		} אחרת {
			fatal("Option \"%s\" is unsupported for moduli "
			    "screening", opts[i]);
		}
	}

	אם (have_identity && strcmp(identity_file, "-") != 0) {
		אם ((in = fopen(identity_file, "r")) == عدم) {
			fatal("Couldn't open modulus candidate "
			    "file \"%s\": %s", identity_file,
			    strerror(errno));
		}
	}

	אם (strcmp(out_file, "-") == 0)
		out = stdout;
	אחרת אם ((out = fopen(out_file, "a")) == عدم) {
		fatal("Couldn't open moduli file \"%s\": %s",
		    out_file, strerror(errno));
	}
	setvbuf(out, عدم, _IOLBF, 0);
	אם (prime_test(in, out, prime_tests == 0 ? 100 : prime_tests,
	    generator_wanted, checkpoint,
	    start_lineno, lines_to_process) != 0)
		fatal("modulus screening failed");
	אם (in != stdin)
		(فراغ)fclose(in);
	حرر(checkpoint);
#אחרת /* WITH_OPENSSL */
	fatal("Moduli screening is not supported");
#endif /* WITH_OPENSSL */
}

/* Read and confirm a passphrase */
ساكن حرف *
read_check_passphrase(ثابت حرف *prompt1, ثابت حرف *prompt2,
    ثابت حرف *retry_prompt)
{
	حرف *passphrase1, *passphrase2;

	עבור (;;) {
		passphrase1 = read_passphrase(prompt1, RP_ALLOW_STDIN);
		passphrase2 = read_passphrase(prompt2, RP_ALLOW_STDIN);
		אם (strcmp(passphrase1, passphrase2) == 0) {
			freezero(passphrase2, strlen(passphrase2));
			החזר passphrase1;
		}
		/* The passphrases do not match. Clear them and retry. */
		freezero(passphrase1, strlen(passphrase1));
		freezero(passphrase2, strlen(passphrase2));
		fputs(retry_prompt, stdout);
		fputc('\n', stdout);
		fflush(stdout);
	}
	/* NOTREACHED */
	החזר عدم;
}

ساكن حرف *
private_key_passphrase(ثابت حرف *path)
{
	حرف *prompt, *ret;

	אם (identity_passphrase)
		החזר xstrdup(identity_passphrase);
	אם (identity_new_passphrase)
		החזר xstrdup(identity_new_passphrase);

	xasprintf(&prompt, "Enter passphrase for \"%s\" "
	    "(empty for no passphrase): ", path);
	ret = read_check_passphrase(prompt,
	    "Enter same passphrase again: ",
	    "Passphrases do not match.  Try again.");
	حرر(prompt);
	החזר ret;
}

ساكن حرف *
sk_suffix(ثابت حرف *application, ثابت uint8_t *user, size_t userlen)
{
	حرف *ret, *cp;
	ثابت حرف *p;
	size_t slen, i;

	/* Trim off URL-like preamble */
	אם ((p = strprefix(application, "ssh://", 0)) != عدم)
		ret =  xstrdup(p);
	אחרת אם ((p = strprefix(application, "ssh:", 0)) != عدم)
		ret =  xstrdup(p);
	אחרת
		ret = xstrdup(application);

	/* Count trailing zeros in user */
	עבור (i = 0; i < userlen; i++) {
		אם (user[userlen - i - 1] != 0)
			اكسر;
	}
	אם (i >= userlen)
		החזר ret; /* user-id was default all-zeros */

	/* Append user-id, escaping non-UTF-8 characters */
	slen = userlen - i;
	אם (asmprintf(&cp, INT_MAX, عدم, "%.*s", (صحيح)slen, user) == -1)
		fatal_f("asmprintf failed");
	/* Don't emit a user-id that contains path or control characters */
	אם (strchr(cp, '/') != عدم || strstr(cp, "..") != عدم ||
	    strchr(cp, '\\') != عدم) {
		حرر(cp);
		cp = tohex(user, slen);
	}
	xextendf(&ret, "_", "%s", cp);
	حرر(cp);
	החזר ret;
}

ساكن صحيح
do_download_sk(ثابت حرف *skprovider, ثابت حرف *device)
{
	بنية sshsk_resident_key **srks;
	size_t nsrks, i;
	صحيح r, ret = -1;
	حرف *fp, *pin = عدم, *pass = عدم, *path, *pubpath;
	ثابت حرف *ext;
	بنية sshkey *key;

	אם (skprovider == عدم)
		fatal("Cannot download keys without provider");

	pin = read_passphrase("Enter PIN for authenticator: ", RP_ALLOW_STDIN);
	אם (!quiet) {
		printf("You may need to touch your authenticator "
		    "to authorize key download.\n");
	}
	אם ((r = sshsk_load_resident(skprovider, device, pin, 0,
	    &srks, &nsrks)) != 0) {
		אם (pin != عدم)
			freezero(pin, strlen(pin));
		error_r(r, "Unable to load resident keys");
		החזר -1;
	}
	אם (nsrks == 0)
		logit("No keys to download");
	אם (pin != عدم)
		freezero(pin, strlen(pin));

	עבור (i = 0; i < nsrks; i++) {
		key = srks[i]->key;
		אם (key->type != KEY_ECDSA_SK && key->type != KEY_ED25519_SK) {
			error("Unsupported key type %s (%d)",
			    sshkey_type(key), key->type);
			استمر;
		}
		אם ((fp = sshkey_fingerprint(key, fingerprint_hash,
		    SSH_FP_DEFAULT)) == عدم)
			fatal_f("sshkey_fingerprint failed");
		debug_f("key %zu: %s %s %s (flags 0x%02x)", i,
		    sshkey_type(key), fp, key->sk_application, key->sk_flags);
		ext = sk_suffix(key->sk_application,
		    srks[i]->user_id, srks[i]->user_id_len);
		xasprintf(&path, "id_%s_rk%s%s",
		    key->type == KEY_ECDSA_SK ? "ecdsa_sk" : "ed25519_sk",
		    *ext == '\0' ? "" : "_", ext);

		/* If the file already exists, ask the user to confirm. */
		אם (!confirm_overwrite(path)) {
			حرر(path);
			اكسر;
		}

		/* Save the key with the application string as the comment */
		אם (pass == عدم)
			pass = private_key_passphrase(path);
		אם ((r = sshkey_save_private(key, path, pass,
		    key->sk_application, private_key_format,
		    openssh_format_cipher, rounds)) != 0) {
			error_r(r, "Saving key \"%s\" failed", path);
			حرر(path);
			اكسر;
		}
		אם (!quiet) {
			printf("Saved %s key%s%s to %s\n", sshkey_type(key),
			    *ext != '\0' ? " " : "",
			    *ext != '\0' ? key->sk_application : "",
			    path);
		}

		/* Save public key too */
		xasprintf(&pubpath, "%s.pub", path);
		حرر(path);
		אם ((r = sshkey_save_public(key, pubpath,
		    key->sk_application)) != 0) {
			error_r(r, "Saving public key \"%s\" failed", pubpath);
			حرر(pubpath);
			اكسر;
		}
		حرر(pubpath);
	}

	אם (i >= nsrks)
		ret = 0; /* success */
	אם (pass != عدم)
		freezero(pass, strlen(pass));
	sshsk_free_resident_keys(srks, nsrks);
	החזר ret;
}

ساكن فراغ
save_attestation(بنية sshbuf *attest, ثابت حرف *path)
{
	mode_t omask;
	صحيح r;

	אם (path == عدم)
		החזר; /* nothing to do */
	אם (attest == عدم || sshbuf_len(attest) == 0)
		fatal("Enrollment did not return attestation data");
	omask = umask(077);
	r = sshbuf_write_file(path, attest);
	umask(omask);
	אם (r != 0)
		fatal_r(r, "Unable to write attestation data \"%s\"", path);
	אם (!quiet)
		printf("Your FIDO attestation certificate has been saved in "
		    "%s\n", path);
}

ساكن صحيح
confirm_sk_overwrite(ثابت حرف *application, ثابت حرف *user)
{
	حرف yesno[3];

	printf("A resident key scoped to '%s' with user id '%s' already "
	    "exists.\n", application == عدم ? "ssh:" : application,
	    user == عدم ? "null" : user);
	printf("Overwrite key in token (y/n)? ");
	fflush(stdout);
	אם (fgets(yesno, حجم(yesno), stdin) == عدم)
		החזר 0;
	אם (yesno[0] != 'y' && yesno[0] != 'Y')
		החזר 0;
	החזר 1;
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
صحيح
main(صحيح argc, حرف **argv)
{
	حرف comment[KEY_COMMENT_MAX], *passphrase = عدم;
	حرف *rr_hostname = عدم, *ep, *fp, *ra;
	بنية sshkey *خاص = عدم, *عام = عدم;
	بنية passwd *pw;
	صحيح ret = 0, r, opt, type;
	صحيح change_passphrase = 0, change_comment = 0, show_cert = 0;
	صحيح find_host = 0, delete_host = 0, hash_hosts = 0;
	صحيح gen_all_hostkeys = 0, gen_krl = 0, update_krl = 0, check_krl = 0;
	صحيح prefer_agent = 0, convert_to = 0, convert_from = 0;
	صحيح print_public = 0, print_generic = 0, cert_serial_autoinc = 0;
	صحيح do_gen_candidates = 0, do_screen_candidates = 0, download_sk = 0;
	unsigned long long cert_serial = 0;
	حرف *identity_comment = عدم, *ca_key_path = عدم, **opts = عدم;
	حرف *sk_application = عدم, *sk_device = عدم, *sk_user = عدم;
	حرف *sk_attestation_path = عدم;
	بنية sshbuf *challenge = عدم, *attest = عدم;
	size_t i, nopts = 0;
	uint32_t bits = 0;
	uint8_t sk_flags = SSH_SK_USER_PRESENCE_REQD;
	ثابت حرف *errstr, *p;
	صحيح log_level = SYSLOG_LEVEL_INFO;
	حرف *sign_op = عدم;

	خارجي صحيح optind;
	خارجي حرف *optarg;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	__progname = ssh_get_progname(argv[0]);

	seed_rng();

	log_init(argv[0], SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_USER, 1);

	msetlocale();

	/* we need this for the home * directory.  */
	pw = getpwuid(getuid());
	אם (!pw)
		fatal("No user exists for uid %lu", (u_long)getuid());
	pw = pwcopy(pw);
	אם (gethostname(hostname, حجم(hostname)) == -1)
		fatal("gethostname: %s", strerror(errno));

	sk_provider = getenv("SSH_SK_PROVIDER");

	/* Remaining characters: dGjJSTWx */
	כלעוד ((opt = getopt(argc, argv, "ABHKLQUXceghiklopquvy"
	    "C:D:E:F:I:M:N:O:P:R:V:Y:Z:"
	    "a:b:f:g:m:n:r:s:t:w:z:")) != -1) {
		بدل (opt) {
		حالة 'A':
			gen_all_hostkeys = 1;
			اكسر;
		حالة 'b':
			bits = (uint32_t)strtonum(optarg, 1, UINT32_MAX,
			    &errstr);
			אם (errstr)
				fatal("Bits has bad value %s (%s)",
					optarg, errstr);
			اكسر;
		حالة 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			אם (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			اكسر;
		حالة 'F':
			find_host = 1;
			rr_hostname = optarg;
			اكسر;
		حالة 'H':
			hash_hosts = 1;
			اكسر;
		حالة 'I':
			cert_key_id = optarg;
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
			אם (strcasecmp(optarg, "RFC4716") == 0 ||
			    strcasecmp(optarg, "ssh2") == 0) {
				convert_format = FMT_RFC4716;
				اكسر;
			}
			אם (strcasecmp(optarg, "PKCS8") == 0) {
				convert_format = FMT_PKCS8;
				private_key_format = SSHKEY_PRIVATE_PKCS8;
				اكسر;
			}
			אם (strcasecmp(optarg, "PEM") == 0) {
				convert_format = FMT_PEM;
				private_key_format = SSHKEY_PRIVATE_PEM;
				اكسر;
			}
			אם (strcasecmp(optarg, "hexdump") == 0) {
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
			אם (strlcpy(identity_file, optarg,
			    حجم(identity_file)) >= حجم(identity_file))
				fatal("Identity filename too long");
			have_identity = 1;
			اكسر;
		حالة 'g':
			print_generic = 1;
			اكسر;
		حالة 'K':
			download_sk = 1;
			اكسر;
		حالة 'P':
			identity_passphrase = optarg;
			اكسر;
		حالة 'N':
			identity_new_passphrase = optarg;
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
			אם (cipher_by_name(openssh_format_cipher) == عدم)
				fatal("Invalid OpenSSH-format cipher '%s'",
				    openssh_format_cipher);
			اكسر;
		حالة 'C':
			identity_comment = optarg;
			اكسر;
		حالة 'q':
			quiet = 1;
			اكسر;
		حالة 'e':
			/* export key */
			convert_to = 1;
			اكسر;
		حالة 'h':
			cert_key_type = SSH2_CERT_TYPE_HOST;
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
			print_public = 1;
			اكسر;
		حالة 's':
			ca_key_path = optarg;
			اكسر;
		حالة 't':
			key_type_name = optarg;
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
			אם (log_level == SYSLOG_LEVEL_INFO)
				log_level = SYSLOG_LEVEL_DEBUG1;
			אחרת {
				אם (log_level >= SYSLOG_LEVEL_DEBUG1 &&
				    log_level < SYSLOG_LEVEL_DEBUG3)
					log_level++;
			}
			اكسر;
		حالة 'r':
			rr_hostname = optarg;
			اكسر;
		حالة 'a':
			rounds = (صحيح)strtonum(optarg, 1, INT_MAX, &errstr);
			אם (errstr)
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
			אם (*optarg == '+') {
				cert_serial_autoinc = 1;
				optarg++;
			}
			cert_serial = strtoull(optarg, &ep, 10);
			אם (*optarg < '0' || *optarg > '9' || *ep != '\0' ||
			    (errno == ERANGE && cert_serial == ULLONG_MAX))
				fatal("Invalid serial number \"%s\"", optarg);
			اكسر;
		حالة 'M':
			אם (strcmp(optarg, "generate") == 0)
				do_gen_candidates = 1;
			אחרת אם (strcmp(optarg, "screen") == 0)
				do_screen_candidates = 1;
			אחרת
				fatal("Unsupported moduli option %s", optarg);
			اكسر;
		افتراضي:
			usage();
		}
	}

#ifdef ENABLE_SK_INTERNAL
	אם (sk_provider == عدم)
		sk_provider = "internal";
#endif

	/* reinit */
	log_init(argv[0], log_level, SYSLOG_FACILITY_USER, 1);

	argv += optind;
	argc -= optind;

	אם (sign_op != عدم) {
		אם (strprefix(sign_op, "find-principals", 0) != عدم) {
			אם (ca_key_path == عدم) {
				error("Too few arguments for find-principals:"
				    "missing signature file");
				exit(1);
			}
			אם (!have_identity) {
				error("Too few arguments for find-principals:"
				    "missing allowed keys file");
				exit(1);
			}
			ret = sig_find_principals(ca_key_path, identity_file,
			    opts, nopts);
			اذهب done;
		} אחרת אם (strprefix(sign_op, "match-principals", 0) != عدم) {
			אם (!have_identity) {
				error("Too few arguments for match-principals:"
				    "missing allowed keys file");
				exit(1);
			}
			אם (cert_key_id == عدم) {
				error("Too few arguments for match-principals: "
				    "missing principal ID");
				exit(1);
			}
			ret = sig_match_principals(identity_file, cert_key_id,
			    opts, nopts);
			اذهب done;
		} אחרת אם (strprefix(sign_op, "sign", 0) != عدم) {
			/* NB. cert_principals is actually namespace, via -n */
			אם (cert_principals == عدم ||
			    *cert_principals == '\0') {
				error("Too few arguments for sign: "
				    "missing namespace");
				exit(1);
			}
			אם (!have_identity) {
				error("Too few arguments for sign: "
				    "missing key");
				exit(1);
			}
			ret = sig_sign(identity_file, cert_principals,
			    prefer_agent, argc, argv, opts, nopts);
			اذهب done;
		} אחרת אם (strprefix(sign_op, "check-novalidate", 0) != عدم) {
			/* NB. cert_principals is actually namespace, via -n */
			אם (cert_principals == عدم ||
			    *cert_principals == '\0') {
				error("Too few arguments for check-novalidate: "
				    "missing namespace");
				exit(1);
			}
			אם (ca_key_path == عدم) {
				error("Too few arguments for check-novalidate: "
				    "missing signature file");
				exit(1);
			}
			ret = sig_verify(ca_key_path, cert_principals,
			    عدم, عدم, عدم, opts, nopts);
			اذهب done;
		} אחרת אם (strprefix(sign_op, "verify", 0) != عدم) {
			/* NB. cert_principals is actually namespace, via -n */
			אם (cert_principals == عدم ||
			    *cert_principals == '\0') {
				error("Too few arguments for verify: "
				    "missing namespace");
				exit(1);
			}
			אם (ca_key_path == عدم) {
				error("Too few arguments for verify: "
				    "missing signature file");
				exit(1);
			}
			אם (!have_identity) {
				error("Too few arguments for sign: "
				    "missing allowed keys file");
				exit(1);
			}
			אם (cert_key_id == عدم) {
				error("Too few arguments for verify: "
				    "missing principal identity");
				exit(1);
			}
			ret = sig_verify(ca_key_path, cert_principals,
			    cert_key_id, identity_file, rr_hostname,
			    opts, nopts);
			اذهب done;
		}
		error("Unsupported operation for -Y: \"%s\"", sign_op);
		usage();
		/* NOTREACHED */
	}

	אם (ca_key_path != عدم) {
		אם (argc < 1 && !gen_krl) {
			error("Too few arguments.");
			usage();
		}
	} אחרת אם (argc > 0 && !gen_krl && !check_krl &&
	    !do_gen_candidates && !do_screen_candidates) {
		error("Too many arguments.");
		usage();
	}
	אם (change_passphrase && change_comment) {
		error("Can only have one of -p and -c.");
		usage();
	}
	אם (print_fingerprint && (delete_host || hash_hosts)) {
		error("Cannot use -l with -H or -R.");
		usage();
	}
	אם (gen_krl) {
		do_gen_krl(pw, update_krl, ca_key_path,
		    cert_serial, identity_comment, argc, argv);
		اذهب done;
	}
	אם (check_krl) {
		do_check_krl(pw, print_fingerprint, argc, argv);
		اذهب done;
	}
	אם (ca_key_path != عدم) {
		אם (cert_key_id == عدم)
			fatal("Must specify key id (-I) when certifying");
		אם (cert_principals == عدم) {
			/*
			 * Ideally this would be a fatal(), but we need to
			 * be able to generate such certificates for testing
			 * even though they will be rejected.
			 */
			error("Warning: certificate will contain no "
			    "principals (-n)");
		}
		עבור (i = 0; i < nopts; i++)
			add_cert_option(opts[i]);
		do_ca_sign(pw, ca_key_path, prefer_agent,
		    cert_serial, cert_serial_autoinc, argc, argv);
		اذهب done;
	}
	אם (show_cert)
		do_show_cert(pw);
	אם (delete_host || hash_hosts || find_host) {
		do_known_hosts(pw, rr_hostname, find_host,
		    delete_host, hash_hosts);
	}
	אם (pkcs11provider != عدم)
		do_download(pw);
	אם (download_sk) {
		עבור (i = 0; i < nopts; i++) {
			אם ((p = strprefix(opts[i], "device=", 1)) != عدم) {
				sk_device = xstrdup(p);
			} אחרת {
				fatal("Option \"%s\" is unsupported for "
				    "FIDO authenticator download", opts[i]);
			}
		}
		ret = do_download_sk(sk_provider, sk_device);
		اذهب done;
	}
	אם (print_fingerprint || print_bubblebabble)
		do_fingerprint(pw);
	אם (change_passphrase)
		do_change_passphrase(pw, opts, nopts);
	אם (change_comment)
		do_change_comment(pw, identity_comment);
#ifdef WITH_OPENSSL
	אם (convert_to) {
		do_convert_to(pw);
		اذهب done;
	}
	אם (convert_from) {
		do_convert_from(pw);
		اذهب done;
	}
#אחרת /* WITH_OPENSSL */
	אם (convert_to || convert_from)
		fatal("key conversion disabled at compile time");
#endif /* WITH_OPENSSL */
	אם (print_public)
		do_print_public(pw);
	אם (rr_hostname != عدم) {
		unsigned صحيح n = 0;

		אם (have_identity) {
			n = do_print_resource_record(pw, identity_file,
			    rr_hostname, print_generic, opts, nopts);
			אם (n == 0)
				fatal("%s: %s", identity_file, strerror(errno));
			exit(0);
		} אחרת {

			n += do_print_resource_record(pw,
			    _PATH_HOST_RSA_KEY_FILE, rr_hostname,
			    print_generic, opts, nopts);
			n += do_print_resource_record(pw,
			    _PATH_HOST_ECDSA_KEY_FILE, rr_hostname,
			    print_generic, opts, nopts);
			n += do_print_resource_record(pw,
			    _PATH_HOST_ED25519_KEY_FILE, rr_hostname,
			    print_generic, opts, nopts);
			אם (n == 0)
				fatal("no keys found.");
			exit(0);
		}
	}

	אם (do_gen_candidates || do_screen_candidates) {
		אם (argc <= 0)
			fatal("No output file specified");
		אחרת אם (argc > 1)
			fatal("Too many output files specified");
	}
	אם (do_gen_candidates) {
		do_moduli_gen(argv[0], opts, nopts);
		اذهب done;
	}
	אם (do_screen_candidates) {
		do_moduli_screen(argv[0], opts, nopts);
		اذهب done;
	}

	אם (gen_all_hostkeys) {
		do_gen_all_hostkeys(pw);
		اذهب done;
	}

	אם (key_type_name == عدم)
		key_type_name = DEFAULT_KEY_TYPE_NAME;

	type = sshkey_type_from_shortname(key_type_name);
	type_bits_valid(type, key_type_name, &bits);

	אם (!quiet)
		printf("Generating public/private %s key pair.\n",
		    key_type_name);
	بدل (type) {
	حالة KEY_ECDSA_SK:
	حالة KEY_ED25519_SK:
		עבור (i = 0; i < nopts; i++) {
			אם (strcasecmp(opts[i], "no-touch-required") == 0) {
				sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
			} אחרת אם (strcasecmp(opts[i], "verify-required") == 0) {
				sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
			} אחרת אם (strcasecmp(opts[i], "resident") == 0) {
				sk_flags |= SSH_SK_RESIDENT_KEY;
			} אחרת אם ((p = strprefix(opts[i], "device=", 1))
			    != عدم ) {
				sk_device = xstrdup(p);
			} אחרת אם ((p = strprefix(opts[i], "user=", 1))
			    != عدم) {
				sk_user = xstrdup(p);
			} אחרת אם ((p = strprefix(opts[i], "challenge=", 1))
			    != عدم) {
				אם ((r = sshbuf_load_file(p,
				    &challenge)) != 0) {
					fatal_r(r, "Unable to load FIDO "
					    "enrollment challenge \"%s\"", p);
				}
			} אחרת אם (strncasecmp(opts[i],
			    "write-attestation=", 18) == 0) {
				sk_attestation_path = opts[i] + 18;
			} אחרת אם (strncasecmp(opts[i],
			    "application=", 12) == 0) {
				sk_application = xstrdup(opts[i] + 12);
				אם (strncmp(sk_application, "ssh:", 4) != 0) {
					fatal("FIDO application string must "
					    "begin with \"ssh:\"");
				}
			} אחרת {
				fatal("Option \"%s\" is unsupported for "
				    "FIDO authenticator enrollment", opts[i]);
			}
		}
		אם ((attest = sshbuf_new()) == عدم)
			fatal("sshbuf_new failed");
		r = 0;
		עבור (i = 0 ;;) {
			אם (!quiet) {
				printf("You may need to touch your "
				    "authenticator%s to authorize key "
				    "generation.\n",
				    r == 0 ? "" : " again");
			}
			fflush(stdout);
			r = sshsk_enroll(type, sk_provider, sk_device,
			    sk_application == عدم ? "ssh:" : sk_application,
			    sk_user, sk_flags, passphrase, challenge,
			    &خاص, attest);
			אם (r == 0)
				اكسر;
			אם (r == SSH_ERR_KEY_BAD_PERMISSIONS &&
			    (sk_flags & SSH_SK_RESIDENT_KEY) != 0 &&
			    (sk_flags & SSH_SK_FORCE_OPERATION) == 0 &&
			    confirm_sk_overwrite(sk_application, sk_user)) {
				sk_flags |= SSH_SK_FORCE_OPERATION;
				استمر;
			}
			אם (r != SSH_ERR_KEY_WRONG_PASSPHRASE)
				fatal_r(r, "Key enrollment failed");
			אחרת אם (passphrase != عدم) {
				error("PIN incorrect");
				freezero(passphrase, strlen(passphrase));
				passphrase = عدم;
			}
			אם (++i >= 3)
				fatal("Too many incorrect PINs");
			passphrase = read_passphrase("Enter PIN for "
			    "authenticator: ", RP_ALLOW_STDIN);
		}
		אם (passphrase != عدم) {
			freezero(passphrase, strlen(passphrase));
			passphrase = عدم;
		}
		اكسر;
	افتراضي:
		אם ((r = sshkey_generate(type, bits, &خاص)) != 0)
			fatal("sshkey_generate failed");
		اكسر;
	}
	אם ((r = sshkey_from_private(خاص, &عام)) != 0)
		fatal_r(r, "sshkey_from_private");

	אם (!have_identity)
		ask_filename(pw, "Enter file in which to save the key");

	/* Create ~/.ssh directory if it doesn't already exist. */
	hostfile_create_user_ssh_dir(identity_file, !quiet);

	/* If the file already exists, ask the user to confirm. */
	אם (!confirm_overwrite(identity_file))
		exit(1);

	/* Determine the passphrase for the private key */
	passphrase = private_key_passphrase(identity_file);
	אם (identity_comment) {
		strlcpy(comment, identity_comment, حجم(comment));
	} אחרת {
		/* Create default comment field for the passphrase. */
		snprintf(comment, حجم comment, "%s@%s", pw->pw_name, hostname);
	}



	/* Save the key with the given passphrase and comment. */
	אם ((r = sshkey_save_private(خاص, identity_file, passphrase,
	    comment, private_key_format, openssh_format_cipher, rounds)) != 0) {
		error_r(r, "Saving key \"%s\" failed", identity_file);
		freezero(passphrase, strlen(passphrase));
		exit(1);
	}
	freezero(passphrase, strlen(passphrase));
	sshkey_free(خاص);

	אם (!quiet) {
		printf("Your identification has been saved in %s\n",
		    identity_file);
	}

	strlcat(identity_file, ".pub", حجم(identity_file));
	אם ((r = sshkey_save_public(عام, identity_file, comment)) != 0)
		fatal_r(r, "Unable to save public key to %s", identity_file);

	אם (!quiet) {
		fp = sshkey_fingerprint(عام, fingerprint_hash,
		    SSH_FP_DEFAULT);
		ra = sshkey_fingerprint(عام, fingerprint_hash,
		    SSH_FP_RANDOMART);
		אם (fp == عدم || ra == عدم)
			fatal("sshkey_fingerprint failed");
		printf("Your public key has been saved in %s\n",
		    identity_file);
		printf("The key fingerprint is:\n");
		printf("%s %s\n", fp, comment);
		printf("The key's randomart image is:\n");
		printf("%s\n", ra);
		حرر(ra);
		حرر(fp);
	}

	אם (sk_attestation_path != عدم)
		save_attestation(attest, sk_attestation_path);

 done:
	sshbuf_free(attest);
	sshkey_free(عام);
	pwfree(pw);
	exit(ret);
}
