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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/socket.h>
#அந்தர்பாவ <sys/stat.h>

#ifdef WITH_OPENSSL
#அந்தர்பாவ "openbsd-compat/openssl-compat.h"
#அந்தர்பாவ <openssl/bn.h>
#அந்தர்பாவ <openssl/evp.h>
#அந்தர்பாவ <openssl/pem.h>
#endif

#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <fcntl.h>
#அந்தர்பாவ <netdb.h>
#அந்தர்பாவ <paths.h>
#அந்தர்பாவ <pwd.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <limits.h>
#அந்தர்பாவ <locale.h>
#அந்தர்பாவ <time.h>

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "authfile.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "pathnames.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "match.h"
#அந்தர்பாவ "hostfile.h"
#அந்தர்பாவ "dns.h"
#அந்தர்பாவ "ssh.h"
#அந்தர்பாவ "ssh2.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "atomicio.h"
#அந்தர்பாவ "krl.h"
#அந்தர்பாவ "digest.h"
#அந்தர்பாவ "utf8.h"
#அந்தர்பாவ "authfd.h"
#அந்தர்பாவ "sshsig.h"
#அந்தர்பாவ "ssh-sk.h"
#அந்தர்பாவ "sk-api.h" /* XXX for SSH_SK_USER_PRESENCE_REQD; remove */
#அந்தர்பாவ "cipher.h"

#ifdef ENABLE_PKCS11
#அந்தர்பாவ "ssh-pkcs11.h"
#endif

#define DEFAULT_சாவி_TYPE_NAME "ed25519"

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

#define சாவி_COMMENT_MAX		(NI_MAXHOST + 1024)

நிலையான முழு quiet = 0;

/* Flag indicating that we just want to see the key fingerprint */
நிலையான முழு print_fingerprint = 0;
நிலையான முழு print_bubblebabble = 0;

/* Hash algorithm to use for fingerprints. */
நிலையான முழு fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* The identity file name, given on the command line or entered by the user. */
நிலையான எழுத்து identity_file[PATH_MAX];
நிலையான முழு have_identity = 0;

/* This is set to the passphrase if given on the command line. */
நிலையான எழுத்து *identity_passphrase = வெற்று;

/* This is set to the new passphrase if given on the command line. */
நிலையான எழுத்து *identity_new_passphrase = வெற்று;

/* Key type when certifying */
நிலையான u_int cert_சாவி_type = SSH2_CERT_TYPE_USER;

/* "key ID" of signed key */
நிலையான எழுத்து *cert_சாவி_id = வெற்று;

/* Comma-separated list of principal names for certifying keys */
நிலையான எழுத்து *cert_principals = வெற்று;

/* Validity period for certificates */
நிலையான uint64_t cert_valid_from = 0;
நிலையான uint64_t cert_valid_to = ~0ULL;

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
நிலையான uint32_t certflags_flags = CERTOPT_DEFAULT;
நிலையான எழுத்து *certflags_command = வெற்று;
நிலையான எழுத்து *certflags_src_addr = வெற்று;

/* Arbitrary extensions specified by user */
கட்டமைப்பு cert_ext {
	எழுத்து *சாவி;
	எழுத்து *val;
	முழு crit;
};
நிலையான கட்டமைப்பு cert_ext *cert_ext;
நிலையான size_t ncert_ext;

/* Conversion to/from various formats */
எண்ணிக்கை {
	FMT_RFC4716,
	FMT_PKCS8,
	FMT_PEM,
	FMT_HEXDUMP
} convert_format = FMT_RFC4716;

நிலையான எழுத்து *சாவி_type_name = வெற்று;

/* Load key from this PKCS#11 provider */
நிலையான எழுத்து *pkcs11provider = வெற்று;

/* FIDO/U2F provider to use */
நிலையான எழுத்து *sk_provider = வெற்று;

/* Format for writing private keys */
நிலையான முழு private_சாவி_format = SSHKEY_PRIVATE_OPENSSH;

/* Cipher for new-format private keys */
நிலையான எழுத்து *openssh_format_cipher = வெற்று;

/* Number of KDF rounds to derive new format keys. */
நிலையான முழு rounds = 0;

/* argv0 */
வெளி எழுத்து *__progname;

நிலையான எழுத்து hostname[NI_MAXHOST];

#ifdef WITH_OPENSSL
/* moduli.c */
முழு gen_candidates(FILE *, uint32_t, BIGNUM *);
முழு பகாஎண்_test(FILE *, FILE *, uint32_t, uint32_t, எழுத்து *, unsigned long,
    unsigned long);
#endif

நிலையான வெறுமை
type_bits_valid(முழு type, மாறிலி எழுத்து *name, uint32_t *bitsp)
{
	எனில் (type == சாவி_UNSPEC)
		fatal("unknown key type %s", சாவி_type_name);
	எனில் (*bitsp == 0) {
#ifdef WITH_OPENSSL
		முழு nid;

		தேர்வு(type) {
		நிலை சாவி_ECDSA:
			எனில் (name != வெற்று &&
			    (nid = sshkey_ecdsa_nid_from_name(name)) > 0)
				*bitsp = sshkey_curve_nid_to_bits(nid);
			எனில் (*bitsp == 0)
				*bitsp = DEFAULT_BITS_ECDSA;
			நிறுத்து;
		நிலை சாவி_RSA:
			*bitsp = DEFAULT_BITS;
			நிறுத்து;
		}
#endif
	}
#ifdef WITH_OPENSSL
	தேர்வு (type) {
	நிலை சாவி_RSA:
		எனில் (*bitsp < SSH_RSA_MINIMUM_MODULUS_SIZE)
			fatal("Invalid RSA key length: minimum is %d bits",
			    SSH_RSA_MINIMUM_MODULUS_SIZE);
		இல்லையெனில் எனில் (*bitsp > OPENSSL_RSA_MAX_MODULUS_BITS)
			fatal("Invalid RSA key length: maximum is %d bits",
			    OPENSSL_RSA_MAX_MODULUS_BITS);
		நிறுத்து;
	நிலை சாவி_ECDSA:
		எனில் (sshkey_ecdsa_bits_to_nid(*bitsp) == -1)
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
நிலையான முழு
confirm_overwrite(மாறிலி எழுத்து *filename)
{
	எழுத்து yesno[3];
	கட்டமைப்பு stat st;

	எனில் (stat(filename, &st) != 0)
		திரும்பு 1;
	printf("%s already exists.\n", filename);
	printf("Overwrite (y/n)? ");
	fflush(stdout);
	எனில் (fgets(yesno, அளவு(yesno), stdin) == வெற்று)
		திரும்பு 0;
	எனில் (yesno[0] != 'y' && yesno[0] != 'Y')
		திரும்பு 0;
	திரும்பு 1;
}

நிலையான வெறுமை
ask_filename(கட்டமைப்பு passwd *pw, மாறிலி எழுத்து *prompt)
{
	எழுத்து buf[1024];
	எழுத்து *name = வெற்று;

	எனில் (சாவி_type_name == வெற்று)
		name = _PATH_SSH_CLIENT_ID_ED25519;
	இல்லையெனில் {
		தேர்வு (sshkey_type_from_shortname(சாவி_type_name)) {
		நிலை சாவி_ECDSA_CERT:
		நிலை சாவி_ECDSA:
			name = _PATH_SSH_CLIENT_ID_ECDSA;
			நிறுத்து;
		நிலை சாவி_ECDSA_SK_CERT:
		நிலை சாவி_ECDSA_SK:
			name = _PATH_SSH_CLIENT_ID_ECDSA_SK;
			நிறுத்து;
		நிலை சாவி_RSA_CERT:
		நிலை சாவி_RSA:
			name = _PATH_SSH_CLIENT_ID_RSA;
			நிறுத்து;
		நிலை சாவி_ED25519:
		நிலை சாவி_ED25519_CERT:
			name = _PATH_SSH_CLIENT_ID_ED25519;
			நிறுத்து;
		நிலை சாவி_ED25519_SK:
		நிலை சாவி_ED25519_SK_CERT:
			name = _PATH_SSH_CLIENT_ID_ED25519_SK;
			நிறுத்து;
		நிலை சாவி_MLDSA44_ED25519:
		நிலை சாவி_MLDSA44_ED25519_CERT:
			name = _PATH_SSH_CLIENT_ID_MLDSA44_ED25519;
			நிறுத்து;
		இயல்பு:
			fatal("bad key type");
		}
	}
	snprintf(identity_file, அளவு(identity_file),
	    "%s/%s", pw->pw_dir, name);
	printf("%s (%s): ", prompt, identity_file);
	fflush(stdout);
	எனில் (fgets(buf, அளவு(buf), stdin) == வெற்று)
		exit(1);
	buf[strcspn(buf, "\n")] = '\0';
	எனில் (strcmp(buf, "") != 0)
		strlcpy(identity_file, buf, அளவு(identity_file));
	have_identity = 1;
}

நிலையான கட்டமைப்பு sshkey *
load_identity(மாறிலி எழுத்து *filename, எழுத்து **commentp)
{
	எழுத்து *prompt, *pass;
	கட்டமைப்பு sshkey *prv;
	முழு r;

	எனில் (commentp != வெற்று)
		*commentp = வெற்று;
	எனில் ((r = sshkey_load_private(filename, "", &prv, commentp)) == 0)
		திரும்பு prv;
	எனில் (r != SSH_ERR_சாவி_WRONG_PASSPHRASE)
		fatal_r(r, "Load key \"%s\"", filename);
	எனில் (identity_passphrase)
		pass = xstrdup(identity_passphrase);
	இல்லையெனில் {
		xasprintf(&prompt, "Enter passphrase for \"%s\": ", filename);
		pass = read_passphrase(prompt, RP_ALLOW_STDIN);
		விடுவி(prompt);
	}
	r = sshkey_load_private(filename, pass, &prv, commentp);
	freezero(pass, strlen(pass));
	எனில் (r != 0)
		fatal_r(r, "Load key \"%s\"", filename);
	திரும்பு prv;
}

#define SSH_COM_PUBLIC_BEGIN		"---- BEGIN SSH2 PUBLIC KEY ----"
#define SSH_COM_PUBLIC_END		"---- END SSH2 PUBLIC KEY ----"
#define SSH_COM_PRIVATE_BEGIN		"---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----"
#define	SSH_COM_PRIVATE_சாவி_MAGIC	0x3f6ff9eb

#ifdef WITH_OPENSSL
நிலையான வெறுமை
do_convert_to_ssh2(கட்டமைப்பு passwd *pw, கட்டமைப்பு sshkey *k)
{
	கட்டமைப்பு sshbuf *b;
	எழுத்து comment[61], *b64;
	முழு r;

	எனில் ((b = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = sshkey_putb(k, b)) != 0)
		fatal_fr(r, "put key");
	எனில் ((b64 = sshbuf_dtob64_string(b, 1)) == வெற்று)
		fatal_f("sshbuf_dtob64_string failed");

	/* Comment + surrounds must fit into 72 chars (RFC 4716 sec 3.3) */
	snprintf(comment, அளவு(comment),
	    "%u-bit %s, converted by %s@%s from OpenSSH",
	    sshkey_size(k), sshkey_type(k),
	    pw->pw_name, hostname);

	sshkey_free(k);
	sshbuf_free(b);

	fprintf(stdout, "%s\n", SSH_COM_PUBLIC_BEGIN);
	fprintf(stdout, "Comment: \"%s\"\n%s", comment, b64);
	fprintf(stdout, "%s\n", SSH_COM_PUBLIC_END);
	விடுவி(b64);
}

நிலையான வெறுமை
do_convert_to_pkcs8(கட்டமைப்பு sshkey *k)
{
	தேர்வு (sshkey_type_plain(k->type)) {
	நிலை சாவி_RSA:
		எனில் (!PEM_write_RSA_PUBKEY(stdout,
		    EVP_PKEY_get0_RSA(k->pkey)))
			fatal("PEM_write_RSA_PUBKEY failed");
		நிறுத்து;
	நிலை சாவி_ECDSA:
		எனில் (!PEM_write_EC_PUBKEY(stdout,
		    EVP_PKEY_get0_EC_சாவி(k->pkey)))
			fatal("PEM_write_EC_PUBKEY failed");
		நிறுத்து;
	இயல்பு:
		fatal_f("unsupported key type %s", sshkey_type(k));
	}
}

நிலையான வெறுமை
do_convert_to_pem(கட்டமைப்பு sshkey *k)
{
	தேர்வு (sshkey_type_plain(k->type)) {
	நிலை சாவி_RSA:
		எனில் (!PEM_write_RSAPublic_சாவி(stdout,
		    EVP_PKEY_get0_RSA(k->pkey)))
			fatal("PEM_write_RSAPublicKey failed");
		நிறுத்து;
	நிலை சாவி_ECDSA:
		எனில் (!PEM_write_EC_PUBKEY(stdout,
		    EVP_PKEY_get0_EC_சாவி(k->pkey)))
			fatal("PEM_write_EC_PUBKEY failed");
		நிறுத்து;
	இயல்பு:
		fatal_f("unsupported key type %s", sshkey_type(k));
	}
}

நிலையான வெறுமை
do_convert_to_hexdump(கட்டமைப்பு sshkey *k)
{
	கட்டமைப்பு sshbuf *b;
	முழு r;

	எனில் ((b = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	/* pubkey */
	எனில் ((r = sshkey_putb(k, b)) != 0)
		fatal_fr(r, "serialise private");
	printf("Public %s key:\n", sshkey_type(k));
	sshbuf_dump(b, stdout);
	sshbuf_reset(b);
	எனில் ((r = sshkey_private_serialize(k, b)) != 0) {
		debug_fr(r, "serialise private");
		செல் out;
	}
	printf("\nPrivate %s key:\n", sshkey_type(k));
	sshbuf_dump(b, stdout);
 out:
	sshbuf_free(b);
}

நிலையான வெறுமை
do_convert_to(கட்டமைப்பு passwd *pw)
{
	கட்டமைப்பு sshkey *k = வெற்று;
	கட்டமைப்பு stat st;
	முழு r;

	எனில் (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	எனில் (stat(identity_file, &st) == -1)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));

	/* If we're trying to hexdump, then prefer the private key */
	எனில் (convert_format == FMT_HEXDUMP) {
		எனில் ((r = sshkey_load_private(identity_file,
		    வெற்று, &k, வெற்று)) != 0 &&
		    r == SSH_ERR_சாவி_WRONG_PASSPHRASE)
			k = load_identity(identity_file, வெற்று);
	}
	எனில் (k == வெற்று && (r = sshkey_load_public(identity_file, &k, வெற்று)) != 0)
		k = load_identity(identity_file, வெற்று);

	தேர்வு (convert_format) {
	நிலை FMT_RFC4716:
		do_convert_to_ssh2(pw, k);
		நிறுத்து;
	நிலை FMT_PKCS8:
		do_convert_to_pkcs8(k);
		நிறுத்து;
	நிலை FMT_PEM:
		do_convert_to_pem(k);
		நிறுத்து;
	நிலை FMT_HEXDUMP:
		do_convert_to_hexdump(k);
		நிறுத்து;
	இயல்பு:
		fatal_f("unknown key format %d", convert_format);
	}
}

/*
 * This is almost exactly the bignum1 encoding, but with 32 bit for length
 * instead of 16.
 */
நிலையான வெறுமை
buffer_get_bignum_bits(கட்டமைப்பு sshbuf *b, BIGNUM *மதிப்பு)
{
	u_int bytes, bignum_bits;
	முழு r;

	எனில் ((r = sshbuf_get_u32(b, &bignum_bits)) != 0)
		fatal_fr(r, "parse");
	bytes = (bignum_bits + 7) / 8;
	எனில் (sshbuf_len(b) < bytes)
		fatal_f("input buffer too small: need %d have %zu",
		    bytes, sshbuf_len(b));
	எனில் (BN_bin2bn(sshbuf_ptr(b), bytes, மதிப்பு) == வெற்று)
		fatal_f("BN_bin2bn failed");
	எனில் ((r = sshbuf_consume(b, bytes)) != 0)
		fatal_fr(r, "consume");
}

நிலையான கட்டமைப்பு sshkey *
do_convert_private_ssh2(கட்டமைப்பு sshbuf *b)
{
	கட்டமைப்பு sshkey *சாவி = வெற்று;
	எழுத்து *type, *cipher;
	மாறிலி எழுத்து *alg = வெற்று;
	u_char e1, e2, e3, *sig = வெற்று, data[] = "abcde12345";
	முழு r, rlen, ktype;
	u_int magic, i1, i2, i3, i4;
	size_t slen;
	u_long e;
	BIGNUM *rsa_n = வெற்று, *rsa_e = வெற்று, *rsa_d = வெற்று;
	BIGNUM *rsa_p = வெற்று, *rsa_q = வெற்று, *rsa_iqmp = வெற்று;
	BIGNUM *rsa_dmp1 = வெற்று, *rsa_dmq1 = வெற்று;
	RSA *rsa = வெற்று;

	எனில் ((r = sshbuf_get_u32(b, &magic)) != 0)
		fatal_fr(r, "parse magic");

	எனில் (magic != SSH_COM_PRIVATE_சாவி_MAGIC) {
		error("bad magic 0x%x != 0x%x", magic,
		    SSH_COM_PRIVATE_சாவி_MAGIC);
		திரும்பு வெற்று;
	}
	எனில் ((r = sshbuf_get_u32(b, &i1)) != 0 ||
	    (r = sshbuf_get_cstring(b, &type, வெற்று)) != 0 ||
	    (r = sshbuf_get_cstring(b, &cipher, வெற்று)) != 0 ||
	    (r = sshbuf_get_u32(b, &i2)) != 0 ||
	    (r = sshbuf_get_u32(b, &i3)) != 0 ||
	    (r = sshbuf_get_u32(b, &i4)) != 0)
		fatal_fr(r, "parse");
	debug("ignore (%d %d %d %d)", i1, i2, i3, i4);
	எனில் (strcmp(cipher, "none") != 0) {
		error("unsupported cipher %s", cipher);
		விடுவி(cipher);
		விடுவி(type);
		திரும்பு வெற்று;
	}
	விடுவி(cipher);

	எனில் (strstr(type, "rsa")) {
		ktype = சாவி_RSA;
	} இல்லையெனில் {
		விடுவி(type);
		திரும்பு வெற்று;
	}
	எனில் ((சாவி = sshkey_new(ktype)) == வெற்று)
		fatal("sshkey_new failed");
	விடுவி(type);

	தேர்வு (சாவி->type) {
	நிலை சாவி_RSA:
		எனில் ((r = sshbuf_get_u8(b, &e1)) != 0 ||
		    (e1 < 30 && (r = sshbuf_get_u8(b, &e2)) != 0) ||
		    (e1 < 30 && (r = sshbuf_get_u8(b, &e3)) != 0))
			fatal_fr(r, "parse RSA");
		e = e1;
		debug("e %lx", e);
		எனில் (e < 30) {
			e <<= 8;
			e += e2;
			debug("e %lx", e);
			e <<= 8;
			e += e3;
			debug("e %lx", e);
		}
		எனில் ((rsa_e = BN_new()) == வெற்று)
			fatal_f("BN_new");
		எனில் (!BN_set_word(rsa_e, e)) {
			BN_clear_free(rsa_e);
			sshkey_free(சாவி);
			திரும்பு வெற்று;
		}
		எனில் ((rsa_n = BN_new()) == வெற்று ||
		    (rsa_d = BN_new()) == வெற்று ||
		    (rsa_p = BN_new()) == வெற்று ||
		    (rsa_q = BN_new()) == வெற்று ||
		    (rsa_iqmp = BN_new()) == வெற்று)
			fatal_f("BN_new");
		buffer_get_bignum_bits(b, rsa_d);
		buffer_get_bignum_bits(b, rsa_n);
		buffer_get_bignum_bits(b, rsa_iqmp);
		buffer_get_bignum_bits(b, rsa_q);
		buffer_get_bignum_bits(b, rsa_p);
		எனில் ((r = ssh_rsa_complete_crt_parameters(rsa_d, rsa_p, rsa_q,
		    rsa_iqmp, &rsa_dmp1, &rsa_dmq1)) != 0)
			fatal_fr(r, "generate RSA CRT parameters");
		EVP_PKEY_free(சாவி->pkey);
		எனில் ((சாவி->pkey = EVP_PKEY_new()) == வெற்று)
			fatal_f("EVP_PKEY_new failed");
		எனில் ((rsa = RSA_new()) == வெற்று)
			fatal_f("RSA_new failed");
		எனில் (!RSA_set0_சாவி(rsa, rsa_n, rsa_e, rsa_d))
			fatal_f("RSA_set0_key failed");
		rsa_n = rsa_e = rsa_d = வெற்று; /* transferred */
		எனில் (!RSA_set0_factors(rsa, rsa_p, rsa_q))
			fatal_f("RSA_set0_factors failed");
		rsa_p = rsa_q = வெற்று; /* transferred */
		எனில் (RSA_set0_crt_params(rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp) != 1)
			fatal_f("RSA_set0_crt_params failed");
		rsa_dmp1 = rsa_dmq1 = rsa_iqmp = வெற்று;
		எனில் (EVP_PKEY_set1_RSA(சாவி->pkey, rsa) != 1)
			fatal_f("EVP_PKEY_set1_RSA failed");
		RSA_free(rsa);
		alg = "rsa-sha2-256";
		நிறுத்து;
	}
	rlen = sshbuf_len(b);
	எனில் (rlen != 0)
		error_f("remaining bytes in key blob %d", rlen);

	/* try the key */
	எனில் ((r = sshkey_sign(சாவி, &sig, &slen, data, அளவு(data),
	    alg, வெற்று, வெற்று, 0)) != 0)
		error_fr(r, "signing with converted key failed");
	இல்லையெனில் எனில் ((r = sshkey_verify(சாவி, sig, slen, data, அளவு(data),
	    alg, 0, வெற்று)) != 0)
		error_fr(r, "verification with converted key failed");
	எனில் (r != 0) {
		sshkey_free(சாவி);
		விடுவி(sig);
		திரும்பு வெற்று;
	}
	விடுவி(sig);
	திரும்பு சாவி;
}

நிலையான முழு
get_வரி(FILE *fp, எழுத்து *வரி, size_t len)
{
	முழு c;
	size_t pos = 0;

	வரி[0] = '\0';
	போது ((c = fgetc(fp)) != EOF) {
		எனில் (pos >= len - 1)
			fatal("input line too long.");
		தேர்வு (c) {
		நிலை '\r':
			c = fgetc(fp);
			எனில் (c != EOF && c != '\n' && ungetc(c, fp) == EOF)
				fatal("unget: %s", strerror(errno));
			திரும்பு pos;
		நிலை '\n':
			திரும்பு pos;
		}
		வரி[pos++] = c;
		வரி[pos] = '\0';
	}
	/* We reached EOF */
	திரும்பு -1;
}

நிலையான வெறுமை
do_convert_from_ssh2(கட்டமைப்பு passwd *pw, கட்டமைப்பு sshkey **k, முழு *தனிப்பட்ட)
{
	முழு r, blen, escaped = 0;
	u_int len;
	எழுத்து வரி[1024];
	கட்டமைப்பு sshbuf *buf;
	எழுத்து encoded[8096];
	FILE *fp;

	எனில் ((buf = sshbuf_new()) == வெற்று)
		fatal("sshbuf_new failed");
	எனில் ((fp = fopen(identity_file, "r")) == வெற்று)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));
	encoded[0] = '\0';
	போது ((blen = get_வரி(fp, வரி, அளவு(வரி))) != -1) {
		எனில் (blen > 0 && வரி[blen - 1] == '\\')
			escaped++;
		எனில் (strncmp(வரி, "----", 4) == 0 ||
		    strstr(வரி, ": ") != வெற்று) {
			எனில் (strstr(வரி, SSH_COM_PRIVATE_BEGIN) != வெற்று)
				*தனிப்பட்ட = 1;
			எனில் (strstr(வரி, " END ") != வெற்று) {
				நிறுத்து;
			}
			/* fprintf(stderr, "ignore: %s", line); */
			தொடர்;
		}
		எனில் (escaped) {
			escaped--;
			/* fprintf(stderr, "escaped: %s", line); */
			தொடர்;
		}
		strlcat(encoded, வரி, அளவு(encoded));
	}
	len = strlen(encoded);
	எனில் (((len % 4) == 3) &&
	    (encoded[len-1] == '=') &&
	    (encoded[len-2] == '=') &&
	    (encoded[len-3] == '='))
		encoded[len-3] = '\0';
	எனில் ((r = sshbuf_b64tod(buf, encoded)) != 0)
		fatal_fr(r, "base64 decode");
	எனில் (*தனிப்பட்ட) {
		எனில் ((*k = do_convert_private_ssh2(buf)) == வெற்று)
			fatal_f("private key conversion failed");
	} இல்லையெனில் எனில் ((r = sshkey_fromb(buf, k)) != 0)
		fatal_fr(r, "parse key");
	sshbuf_free(buf);
	fclose(fp);
}

நிலையான வெறுமை
do_convert_from_pkcs8(கட்டமைப்பு sshkey **k, முழு *தனிப்பட்ட)
{
	EVP_PKEY *pubkey;
	FILE *fp;

	எனில் ((fp = fopen(identity_file, "r")) == வெற்று)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));
	எனில் ((pubkey = PEM_read_PUBKEY(fp, வெற்று, வெற்று, வெற்று)) == வெற்று) {
		fatal_f("%s is not a recognised public key format",
		    identity_file);
	}
	fclose(fp);
	தேர்வு (EVP_PKEY_base_id(pubkey)) {
	நிலை EVP_PKEY_RSA:
		எனில் ((*k = sshkey_new(சாவி_UNSPEC)) == வெற்று)
			fatal("sshkey_new failed");
		(*k)->type = சாவி_RSA;
		(*k)->pkey = pubkey;
		pubkey = வெற்று;
		நிறுத்து;
	நிலை EVP_PKEY_EC:
		எனில் ((*k = sshkey_new(சாவி_UNSPEC)) == வெற்று)
			fatal("sshkey_new failed");
		எனில் (((*k)->ecdsa_nid = sshkey_ecdsa_fixup_group(pubkey)) == -1)
			fatal("sshkey_ecdsa_fixup_group failed");
		(*k)->type = சாவி_ECDSA;
		(*k)->pkey = pubkey;
		pubkey = வெற்று;
		நிறுத்து;
	இயல்பு:
		fatal_f("unsupported pubkey type %d",
		    EVP_PKEY_base_id(pubkey));
	}
	EVP_PKEY_free(pubkey);
}

நிலையான வெறுமை
do_convert_from_pem(கட்டமைப்பு sshkey **k, முழு *தனிப்பட்ட)
{
	FILE *fp;
	RSA *rsa;

	எனில் ((fp = fopen(identity_file, "r")) == வெற்று)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));
	எனில் ((rsa = PEM_read_RSAPublic_சாவி(fp, வெற்று, வெற்று, வெற்று)) != வெற்று) {
		எனில் ((*k = sshkey_new(சாவி_UNSPEC)) == வெற்று)
			fatal("sshkey_new failed");
		எனில் (((*k)->pkey = EVP_PKEY_new()) == வெற்று)
			fatal("EVP_PKEY_new failed");
		(*k)->type = சாவி_RSA;
		எனில் (EVP_PKEY_set1_RSA((*k)->pkey, rsa) != 1)
			fatal("EVP_PKEY_set1_RSA failed");
		RSA_free(rsa);
		fclose(fp);
		திரும்பு;
	}
	fatal_f("unrecognised raw private key format");
}

நிலையான வெறுமை
do_convert_from(கட்டமைப்பு passwd *pw)
{
	கட்டமைப்பு sshkey *k = வெற்று;
	முழு r, தனிப்பட்ட = 0, ok = 0;
	கட்டமைப்பு stat st;

	எனில் (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	எனில் (stat(identity_file, &st) == -1)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));

	தேர்வு (convert_format) {
	நிலை FMT_RFC4716:
		do_convert_from_ssh2(pw, &k, &தனிப்பட்ட);
		நிறுத்து;
	நிலை FMT_PKCS8:
		do_convert_from_pkcs8(&k, &தனிப்பட்ட);
		நிறுத்து;
	நிலை FMT_PEM:
		do_convert_from_pem(&k, &தனிப்பட்ட);
		நிறுத்து;
	இயல்பு:
		fatal_f("unknown key format %d", convert_format);
	}

	எனில் (!தனிப்பட்ட) {
		எனில் ((r = sshkey_write(k, stdout)) == 0)
			ok = 1;
		எனில் (ok)
			fprintf(stdout, "\n");
	} இல்லையெனில் {
		தேர்வு (k->type) {
		நிலை சாவி_ECDSA:
			ok = PEM_write_ECPrivate_சாவி(stdout,
			    EVP_PKEY_get0_EC_சாவி(k->pkey), வெற்று, வெற்று, 0,
			    வெற்று, வெற்று);
			நிறுத்து;
		நிலை சாவி_RSA:
			ok = PEM_write_RSAPrivate_சாவி(stdout,
			    EVP_PKEY_get0_RSA(k->pkey), வெற்று, வெற்று, 0,
			    வெற்று, வெற்று);
			நிறுத்து;
		இயல்பு:
			fatal_f("unsupported key type %s", sshkey_type(k));
		}
	}

	எனில் (!ok)
		fatal("key write failed");
	sshkey_free(k);
}
#endif

நிலையான வெறுமை
do_print_public(கட்டமைப்பு passwd *pw)
{
	கட்டமைப்பு sshkey *prv;
	கட்டமைப்பு stat st;
	முழு r;
	எழுத்து *comment = வெற்று;

	எனில் (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	எனில் (stat(identity_file, &st) == -1)
		fatal("%s: %s", identity_file, strerror(errno));
	prv = load_identity(identity_file, &comment);
	எனில் ((r = sshkey_write(prv, stdout)) != 0)
		fatal_fr(r, "write key");
	எனில் (comment != வெற்று && *comment != '\0')
		fprintf(stdout, " %s", comment);
	fprintf(stdout, "\n");
	எனில் (sshkey_is_sk(prv)) {
		debug("sk_application: \"%s\", sk_flags 0x%02x",
			prv->sk_application, prv->sk_flags);
	}
	sshkey_free(prv);
	விடுவி(comment);
	exit(0);
}

நிலையான வெறுமை
do_download(கட்டமைப்பு passwd *pw)
{
#ifdef ENABLE_PKCS11
	கட்டமைப்பு sshkey **சாவிகள் = வெற்று;
	முழு i, nkeys;
	எண்ணிக்கை sshkey_fp_rep rep;
	முழு fptype;
	எழுத்து *fp, *ra, **comments = வெற்று;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;

	pkcs11_init(1);
	nkeys = pkcs11_add_provider(pkcs11provider, வெற்று, &சாவிகள், &comments);
	எனில் (nkeys <= 0)
		fatal("cannot read public key from pkcs11");
	க்கு (i = 0; i < nkeys; i++) {
		எனில் (print_fingerprint) {
			fp = sshkey_fingerprint(சாவிகள்[i], fptype, rep);
			ra = sshkey_fingerprint(சாவிகள்[i], fingerprint_hash,
			    SSH_FP_RANDOMART);
			எனில் (fp == வெற்று || ra == வெற்று)
				fatal_f("sshkey_fingerprint fail");
			printf("%u %s %s (PKCS11 key)\n", sshkey_size(சாவிகள்[i]),
			    fp, sshkey_type(சாவிகள்[i]));
			எனில் (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
				printf("%s\n", ra);
			விடுவி(ra);
			விடுவி(fp);
		} இல்லையெனில் {
			(வெறுமை) sshkey_write(சாவிகள்[i], stdout); /* XXX check */
			fprintf(stdout, "%s%s\n",
			    *(comments[i]) == '\0' ? "" : " ", comments[i]);
		}
		விடுவி(comments[i]);
		sshkey_free(சாவிகள்[i]);
	}
	விடுவி(comments);
	விடுவி(சாவிகள்);
	pkcs11_terminate();
	exit(0);
#இல்லையெனில்
	fatal("no pkcs11 support");
#endif /* ENABLE_PKCS11 */
}

நிலையான கட்டமைப்பு sshkey *
try_read_சாவி(எழுத்து **cpp)
{
	கட்டமைப்பு sshkey *ret;
	முழு r;

	எனில் ((ret = sshkey_new(சாவி_UNSPEC)) == வெற்று)
		fatal("sshkey_new failed");
	எனில் ((r = sshkey_read(ret, cpp)) == 0)
		திரும்பு ret;
	/* Not a key */
	sshkey_free(ret);
	திரும்பு வெற்று;
}

நிலையான வெறுமை
fingerprint_one_சாவி(மாறிலி கட்டமைப்பு sshkey *பொது, மாறிலி எழுத்து *comment)
{
	எழுத்து *fp = வெற்று, *ra = வெற்று;
	எண்ணிக்கை sshkey_fp_rep rep;
	முழு fptype;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;
	fp = sshkey_fingerprint(பொது, fptype, rep);
	ra = sshkey_fingerprint(பொது, fingerprint_hash, SSH_FP_RANDOMART);
	எனில் (fp == வெற்று || ra == வெற்று)
		fatal_f("sshkey_fingerprint failed");
	mprintf("%u %s %s (%s)\n", sshkey_size(பொது), fp,
	    comment ? comment : "no comment", sshkey_type(பொது));
	எனில் (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
		printf("%s\n", ra);
	விடுவி(ra);
	விடுவி(fp);
}

நிலையான வெறுமை
fingerprint_private(மாறிலி எழுத்து *path)
{
	கட்டமைப்பு stat st;
	எழுத்து *comment = வெற்று;
	கட்டமைப்பு sshkey *privkey = வெற்று, *pubkey = வெற்று;
	முழு r;

	எனில் (stat(identity_file, &st) == -1)
		fatal("%s: %s", path, strerror(errno));
	எனில் ((r = sshkey_load_public(path, &pubkey, &comment)) != 0)
		debug_r(r, "load public \"%s\"", path);
	எனில் (pubkey == வெற்று || comment == வெற்று || *comment == '\0') {
		விடுவி(comment);
		எனில் ((r = sshkey_load_private(path, வெற்று,
		    &privkey, &comment)) != 0)
			debug_r(r, "load private \"%s\"", path);
	}
	எனில் (pubkey == வெற்று && privkey == வெற்று)
		fatal("%s is not a key file.", path);

	fingerprint_one_சாவி(pubkey == வெற்று ? privkey : pubkey, comment);
	sshkey_free(pubkey);
	sshkey_free(privkey);
	விடுவி(comment);
}

நிலையான வெறுமை
do_fingerprint(கட்டமைப்பு passwd *pw)
{
	FILE *f;
	கட்டமைப்பு sshkey *பொது = வெற்று;
	எழுத்து *comment = வெற்று, *cp, *ep, *வரி = வெற்று;
	size_t linesize = 0;
	முழு i, invalid = 1;
	மாறிலி எழுத்து *path;
	u_long lnum = 0;

	எனில் (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	path = identity_file;

	எனில் (strcmp(identity_file, "-") == 0) {
		f = stdin;
		path = "(stdin)";
	} இல்லையெனில் எனில் ((f = fopen(path, "r")) == வெற்று)
		fatal("%s: %s: %s", __progname, path, strerror(errno));

	போது (getline(&வரி, &linesize, f) != -1) {
		lnum++;
		cp = வரி;
		cp[strcspn(cp, "\r\n")] = '\0';
		/* Trim leading space and comments */
		cp = வரி + strspn(வரி, " \t");
		எனில் (*cp == '#' || *cp == '\0')
			தொடர்;

		/*
		 * Input may be plain keys, private keys, authorized_keys
		 * or known_hosts.
		 */

		/*
		 * Try private keys first. Assume a key is private if
		 * "SSH PRIVATE KEY" appears on the first line and we're
		 * not reading from stdin (XXX support private keys on stdin).
		 */
		எனில் (lnum == 1 && strcmp(identity_file, "-") != 0 &&
		    strstr(cp, "PRIVATE KEY") != வெற்று) {
			விடுவி(வரி);
			fclose(f);
			fingerprint_private(path);
			exit(0);
		}

		/*
		 * If it's not a private key, then this must be prepared to
		 * accept a public key prefixed with a hostname or options.
		 * Try a bare key first, otherwise skip the leading stuff.
		 */
		comment = வெற்று;
		எனில் ((பொது = try_read_சாவி(&cp)) == வெற்று) {
			i = strtol(cp, &ep, 10);
			எனில் (i == 0 || ep == வெற்று ||
			    (*ep != ' ' && *ep != '\t')) {
				முழு quoted = 0;

				comment = cp;
				க்கு (; *cp && (quoted || (*cp != ' ' &&
				    *cp != '\t')); cp++) {
					எனில் (*cp == '\\' && cp[1] == '"')
						cp++;	/* Skip both */
					இல்லையெனில் எனில் (*cp == '"')
						quoted = !quoted;
				}
				எனில் (!*cp)
					தொடர்;
				*cp++ = '\0';
			}
		}
		/* Retry after parsing leading hostname/key options */
		எனில் (பொது == வெற்று && (பொது = try_read_சாவி(&cp)) == வெற்று) {
			debug("%s:%lu: not a public key", path, lnum);
			தொடர்;
		}

		/* Find trailing comment, if any */
		க்கு (; *cp == ' ' || *cp == '\t'; cp++)
			;
		எனில் (*cp != '\0' && *cp != '#')
			comment = cp;

		fingerprint_one_சாவி(பொது, comment);
		sshkey_free(பொது);
		invalid = 0; /* One good key in the file is sufficient */
	}
	fclose(f);
	விடுவி(வரி);

	எனில் (invalid)
		fatal("%s is not a public key file.", path);
	exit(0);
}

நிலையான வெறுமை
do_gen_all_hostkeys(கட்டமைப்பு passwd *pw)
{
	கட்டமைப்பு {
		எழுத்து *சாவி_type;
		எழுத்து *சாவி_type_display;
		எழுத்து *path;
	} சாவி_types[] = {
#ifdef WITH_OPENSSL
		{ "rsa", "RSA" ,PATH_HOST_RSA_சாவி_FILE },
		{ "ecdsa", "ECDSA",PATH_HOST_ECDSA_சாவி_FILE },
#endif /* WITH_OPENSSL */
		{ "ed25519", "ED25519",PATH_HOST_ED25519_சாவி_FILE },
#ifdef USE_MLDSA
		{ "mldsa44-ed25519", "MLDSA44-ED25519",
		     PATH_HOST_MLDSA44_ED25519_சாவி_FILE },
#endif
		{ வெற்று, வெற்று, வெற்று }
	};

	uint32_t bits = 0;
	முழு first = 0;
	கட்டமைப்பு stat st;
	கட்டமைப்பு sshkey *தனிப்பட்ட, *பொது;
	எழுத்து comment[சாவி_COMMENT_MAX], *prv_tmp, *pub_tmp, *prv_file, *pub_file;
	முழு i, type, fd, r;

	க்கு (i = 0; சாவி_types[i].சாவி_type; i++) {
		பொது = தனிப்பட்ட = வெற்று;
		prv_tmp = pub_tmp = prv_file = pub_file = வெற்று;

		xasprintf(&prv_file, "%s%s",
		    identity_file, சாவி_types[i].path);

		/* Check whether private key exists and is not zero-length */
		எனில் (stat(prv_file, &st) == 0) {
			எனில் (st.st_size != 0)
				செல் next;
		} இல்லையெனில் எனில் (errno != ENOENT) {
			error("Could not stat %s: %s", சாவி_types[i].path,
			    strerror(errno));
			செல் failnext;
		}

		/*
		 * Private key doesn't exist or is invalid; proceed with
		 * key generation.
		 */
		xasprintf(&prv_tmp, "%s%s.XXXXXXXXXX",
		    identity_file, சாவி_types[i].path);
		xasprintf(&pub_tmp, "%s%s.pub.XXXXXXXXXX",
		    identity_file, சாவி_types[i].path);
		xasprintf(&pub_file, "%s%s.pub",
		    identity_file, சாவி_types[i].path);

		எனில் (first == 0) {
			first = 1;
			printf("%s: generating new host keys: ", __progname);
		}
		printf("%s ", சாவி_types[i].சாவி_type_display);
		fflush(stdout);
		type = sshkey_type_from_shortname(சாவி_types[i].சாவி_type);
		எனில் ((fd = mkstemp(prv_tmp)) == -1) {
			error("Could not save your private key in %s: %s",
			    prv_tmp, strerror(errno));
			செல் failnext;
		}
		(வெறுமை)close(fd); /* just using mkstemp() to reserve a name */
		bits = 0;
		type_bits_valid(type, வெற்று, &bits);
		எனில் ((r = sshkey_generate(type, bits, &தனிப்பட்ட)) != 0) {
			error_r(r, "sshkey_generate failed");
			செல் failnext;
		}
		எனில் ((r = sshkey_from_private(தனிப்பட்ட, &பொது)) != 0)
			fatal_fr(r, "sshkey_from_private");
		snprintf(comment, அளவு comment, "%s@%s", pw->pw_name,
		    hostname);
		எனில் ((r = sshkey_save_private(தனிப்பட்ட, prv_tmp, "",
		    comment, private_சாவி_format, openssh_format_cipher,
		    rounds)) != 0) {
			error_r(r, "Saving key \"%s\" failed", prv_tmp);
			செல் failnext;
		}
		எனில் ((fd = mkstemp(pub_tmp)) == -1) {
			error("Could not save your public key in %s: %s",
			    pub_tmp, strerror(errno));
			செல் failnext;
		}
		(வெறுமை)fchmod(fd, 0644);
		(வெறுமை)close(fd);
		எனில் ((r = sshkey_save_public(பொது, pub_tmp, comment)) != 0) {
			error_r(r, "Unable to save public key to %s",
			    identity_file);
			செல் failnext;
		}

		/* Rename temporary files to their permanent locations. */
		எனில் (rename(pub_tmp, pub_file) != 0) {
			error("Unable to move %s into position: %s",
			    pub_file, strerror(errno));
			செல் failnext;
		}
		எனில் (rename(prv_tmp, prv_file) != 0) {
			error("Unable to move %s into position: %s",
			    சாவி_types[i].path, strerror(errno));
 failnext:
			first = 0;
			செல் next;
		}
 next:
		sshkey_free(தனிப்பட்ட);
		sshkey_free(பொது);
		விடுவி(prv_tmp);
		விடுவி(pub_tmp);
		விடுவி(prv_file);
		விடுவி(pub_file);
	}
	எனில் (first != 0)
		printf("\n");
}

கட்டமைப்பு known_hosts_ctx {
	மாறிலி எழுத்து *host;	/* Hostname searched for in find/delete case */
	FILE *out;		/* Output file, stdout for find_hosts case */
	முழு has_unhashed;	/* When hashing, original had unhashed hosts */
	முழு found_சாவி;		/* For find/delete, host was found */
	முழு invalid;		/* File contained invalid items; don't delete */
	முழு hash_hosts;		/* Hash hostnames as we go */
	முழு find_host;		/* Search for specific hostname */
	முழு delete_host;	/* Delete host from known_hosts */
};

நிலையான முழு
known_hosts_hash(கட்டமைப்பு hostkey_foreach_வரி *l, வெறுமை *_ctx)
{
	கட்டமைப்பு known_hosts_ctx *ctx = (கட்டமைப்பு known_hosts_ctx *)_ctx;
	எழுத்து *hashed, *cp, *hosts, *ohosts;
	முழு has_wild = l->hosts && strcspn(l->hosts, "*?!") != strlen(l->hosts);
	முழு was_hashed = l->hosts && l->hosts[0] == HASH_DELIM;

	தேர்வு (l->status) {
	நிலை HKF_STATUS_OK:
	நிலை HKF_STATUS_MATCHED:
		/*
		 * Don't hash hosts already hashed, with wildcard
		 * characters or a CA/revocation marker.
		 */
		எனில் (was_hashed || has_wild || l->marker != MRK_NONE) {
			fprintf(ctx->out, "%s\n", l->வரி);
			எனில் (has_wild && !ctx->find_host) {
				logit("%s:%lu: ignoring host name "
				    "with wildcard: %.64s", l->path,
				    l->linenum, l->hosts);
			}
			திரும்பு 0;
		}
		/*
		 * Split any comma-separated hostnames from the host list,
		 * hash and store separately.
		 */
		ohosts = hosts = xstrdup(l->hosts);
		போது ((cp = strsep(&hosts, ",")) != வெற்று && *cp != '\0') {
			lowercase(cp);
			எனில் ((hashed = host_hash(cp, வெற்று, 0)) == வெற்று)
				fatal("hash_host failed");
			fprintf(ctx->out, "%s %s\n", hashed, l->rawkey);
			விடுவி(hashed);
			ctx->has_unhashed = 1;
		}
		விடுவி(ohosts);
		திரும்பு 0;
	நிலை HKF_STATUS_INVALID:
		/* Retain invalid lines, but mark file as invalid. */
		ctx->invalid = 1;
		logit("%s:%lu: invalid line", l->path, l->linenum);
		/* FALLTHROUGH */
	இயல்பு:
		fprintf(ctx->out, "%s\n", l->வரி);
		திரும்பு 0;
	}
	/* NOTREACHED */
	திரும்பு -1;
}

நிலையான முழு
known_hosts_find_delete(கட்டமைப்பு hostkey_foreach_வரி *l, வெறுமை *_ctx)
{
	கட்டமைப்பு known_hosts_ctx *ctx = (கட்டமைப்பு known_hosts_ctx *)_ctx;
	எண்ணிக்கை sshkey_fp_rep rep;
	முழு fptype;
	எழுத்து *fp = வெற்று, *ra = வெற்று;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;

	எனில் (l->status == HKF_STATUS_MATCHED) {
		எனில் (ctx->delete_host) {
			எனில் (l->marker != MRK_NONE) {
				/* Don't remove CA and revocation lines */
				fprintf(ctx->out, "%s\n", l->வரி);
			} இல்லையெனில் {
				/*
				 * Hostname matches and has no CA/revoke
				 * marker, delete it by *not* writing the
				 * line to ctx->out.
				 */
				ctx->found_சாவி = 1;
				எனில் (!quiet)
					printf("# Host %s found: line %lu\n",
					    ctx->host, l->linenum);
			}
			திரும்பு 0;
		} இல்லையெனில் எனில் (ctx->find_host) {
			ctx->found_சாவி = 1;
			எனில் (!quiet) {
				printf("# Host %s found: line %lu %s\n",
				    ctx->host,
				    l->linenum, l->marker == MRK_CA ? "CA" :
				    (l->marker == MRK_REVOKE ? "REVOKED" : ""));
			}
			எனில் (ctx->hash_hosts)
				known_hosts_hash(l, ctx);
			இல்லையெனில் எனில் (print_fingerprint) {
				fp = sshkey_fingerprint(l->சாவி, fptype, rep);
				ra = sshkey_fingerprint(l->சாவி,
				    fingerprint_hash, SSH_FP_RANDOMART);
				எனில் (fp == வெற்று || ra == வெற்று)
					fatal_f("sshkey_fingerprint failed");
				mprintf("%s %s %s%s%s\n", ctx->host,
				    sshkey_type(l->சாவி), fp,
				    l->comment[0] ? " " : "",
				    l->comment);
				எனில் (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
					printf("%s\n", ra);
				விடுவி(ra);
				விடுவி(fp);
			} இல்லையெனில்
				fprintf(ctx->out, "%s\n", l->வரி);
			திரும்பு 0;
		}
	} இல்லையெனில் எனில் (ctx->delete_host) {
		/* Retain non-matching hosts when deleting */
		எனில் (l->status == HKF_STATUS_INVALID) {
			ctx->invalid = 1;
			logit("%s:%lu: invalid line", l->path, l->linenum);
		}
		fprintf(ctx->out, "%s\n", l->வரி);
	}
	திரும்பு 0;
}

நிலையான வெறுமை
do_known_hosts(கட்டமைப்பு passwd *pw, மாறிலி எழுத்து *name, முழு find_host,
    முழு delete_host, முழு hash_hosts)
{
	எழுத்து *cp, tmp[PATH_MAX], old[PATH_MAX];
	முழு r, fd, oerrno, inplace = 0;
	கட்டமைப்பு known_hosts_ctx ctx;
	u_int foreach_options;
	கட்டமைப்பு stat sb;

	எனில் (!have_identity) {
		cp = tilde_expand_filename(_PATH_SSH_USER_HOSTFILE, pw->pw_uid);
		எனில் (strlcpy(identity_file, cp, அளவு(identity_file)) >=
		    அளவு(identity_file))
			fatal("Specified known hosts path too long");
		விடுவி(cp);
		have_identity = 1;
	}
	எனில் (stat(identity_file, &sb) != 0)
		fatal("Cannot stat %s: %s", identity_file, strerror(errno));

	memset(&ctx, 0, அளவு(ctx));
	ctx.out = stdout;
	ctx.host = name;
	ctx.hash_hosts = hash_hosts;
	ctx.find_host = find_host;
	ctx.delete_host = delete_host;

	/*
	 * Find hosts goes to stdout, hash and deletions happen in-place
	 * A corner case is ssh-keygen -HF foo, which should go to stdout
	 */
	எனில் (!find_host && (hash_hosts || delete_host)) {
		எனில் (strlcpy(tmp, identity_file, அளவு(tmp)) >= அளவு(tmp) ||
		    strlcat(tmp, ".XXXXXXXXXX", அளவு(tmp)) >= அளவு(tmp) ||
		    strlcpy(old, identity_file, அளவு(old)) >= அளவு(old) ||
		    strlcat(old, ".old", அளவு(old)) >= அளவு(old))
			fatal("known_hosts path too long");
		umask(077);
		எனில் ((fd = mkstemp(tmp)) == -1)
			fatal("mkstemp: %s", strerror(errno));
		எனில் ((ctx.out = fdopen(fd, "w")) == வெற்று) {
			oerrno = errno;
			unlink(tmp);
			fatal("fdopen: %s", strerror(oerrno));
		}
		(வெறுமை)fchmod(fd, sb.st_mode & 0644);
		inplace = 1;
	}
	/* XXX support identity_file == "-" for stdin */
	foreach_options = find_host ? HKF_WANT_MATCH : 0;
	foreach_options |= print_fingerprint ? HKF_WANT_PARSE_சாவி : 0;
	எனில் ((r = hostkeys_foreach(identity_file, (find_host || !hash_hosts) ?
	    known_hosts_find_delete : known_hosts_hash, &ctx, name, வெற்று,
	    foreach_options, 0)) != 0) {
		எனில் (inplace)
			unlink(tmp);
		fatal_fr(r, "hostkeys_foreach");
	}

	எனில் (inplace)
		fclose(ctx.out);

	எனில் (ctx.invalid) {
		error("%s is not a valid known_hosts file.", identity_file);
		எனில் (inplace) {
			error("Not replacing existing known_hosts "
			    "file because of errors");
			unlink(tmp);
		}
		exit(1);
	} இல்லையெனில் எனில் (delete_host && !ctx.found_சாவி) {
		logit("Host %s not found in %s", name, identity_file);
		எனில் (inplace)
			unlink(tmp);
	} இல்லையெனில் எனில் (inplace) {
		/* Backup existing file */
		எனில் (unlink(old) == -1 && errno != ENOENT)
			fatal("unlink %.100s: %s", old, strerror(errno));
		எனில் (link(identity_file, old) == -1)
			fatal("link %.100s to %.100s: %s", identity_file, old,
			    strerror(errno));
		/* Move new one into place */
		எனில் (rename(tmp, identity_file) == -1) {
			error("rename\"%s\" to \"%s\": %s", tmp, identity_file,
			    strerror(errno));
			unlink(tmp);
			unlink(old);
			exit(1);
		}

		printf("%s updated.\n", identity_file);
		printf("Original contents retained as %s\n", old);
		எனில் (ctx.has_unhashed) {
			logit("WARNING: %s contains unhashed entries", old);
			logit("Delete this file to ensure privacy "
			    "of hostnames");
		}
	}

	exit (find_host && !ctx.found_சாவி);
}

/*
 * Perform changing a passphrase.  The argument is the passwd structure
 * for the current user.
 */
நிலையான வெறுமை
do_change_passphrase(கட்டமைப்பு passwd *pw, எழுத்து * மாறிலி *opts, size_t nopts)
{
	எழுத்து *comment;
	எழுத்து *old_passphrase, *passphrase1, *passphrase2;
	கட்டமைப்பு stat st;
	கட்டமைப்பு sshkey *தனிப்பட்ட;
	முழு r;
	size_t i;

	எனில் (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	எனில் (stat(identity_file, &st) == -1)
		fatal("%s: %s", identity_file, strerror(errno));
	/* Try to load the file with empty passphrase. */
	r = sshkey_load_private(identity_file, "", &தனிப்பட்ட, &comment);
	எனில் (r == SSH_ERR_சாவி_WRONG_PASSPHRASE) {
		எனில் (identity_passphrase)
			old_passphrase = xstrdup(identity_passphrase);
		இல்லையெனில்
			old_passphrase =
			    read_passphrase("Enter old passphrase: ",
			    RP_ALLOW_STDIN);
		r = sshkey_load_private(identity_file, old_passphrase,
		    &தனிப்பட்ட, &comment);
		freezero(old_passphrase, strlen(old_passphrase));
		எனில் (r != 0)
			செல் badkey;
	} இல்லையெனில் எனில் (r != 0) {
 badkey:
		fatal_r(r, "Failed to load key %s", identity_file);
	}
	எனில் (comment)
		mprintf("Key has comment '%s'\n", comment);

	/* All current -O options relate to FIDO keys only */
	எனில் (nopts != 0 && !sshkey_is_sk(தனிப்பட்ட)) {
		fatal("FIDO-specific option requested for non-FIDO key %s",
		    identity_file);
	}
	எனில் (sshkey_is_sk(தனிப்பட்ட)) {
		debug_f("%s: original FIDO key flags: "
		    "%stouch-required %sverify-required", identity_file,
		    (தனிப்பட்ட->sk_flags & SSH_SK_USER_PRESENCE_REQD) ? "": "no-",
		    (தனிப்பட்ட->sk_flags & SSH_SK_USER_VERIFICATION_REQD) ? "" : "no-");
	}
	க்கு (i = 0; i < nopts; i++) {
		எனில் (strcasecmp(opts[i], "touch-required") == 0)
			தனிப்பட்ட->sk_flags |= SSH_SK_USER_PRESENCE_REQD;
		இல்லையெனில் எனில் (strcasecmp(opts[i], "no-touch-required") == 0)
			தனிப்பட்ட->sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
		இல்லையெனில் எனில் (strcasecmp(opts[i], "verify-required") == 0)
			தனிப்பட்ட->sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
		இல்லையெனில் எனில் (strcasecmp(opts[i], "no-verify-required") == 0)
			தனிப்பட்ட->sk_flags &= ~SSH_SK_USER_VERIFICATION_REQD;
		இல்லையெனில் {
			fatal("Option \"%s\" is unsupported for "
			    "key passphrase change", opts[i]);
		}
	}
	எனில் (sshkey_is_sk(தனிப்பட்ட) && nopts != 0) {
		debug_f("%s: updated FIDO key flags: "
		    "%stouch-required %sverify-required", identity_file,
		    (தனிப்பட்ட->sk_flags & SSH_SK_USER_PRESENCE_REQD) ? "": "no-",
		    (தனிப்பட்ட->sk_flags & SSH_SK_USER_VERIFICATION_REQD) ? "" : "no-");
	}

	/* Ask the new passphrase (twice). */
	எனில் (identity_new_passphrase) {
		passphrase1 = xstrdup(identity_new_passphrase);
		passphrase2 = வெற்று;
	} இல்லையெனில் {
		passphrase1 =
			read_passphrase("Enter new passphrase (empty for no "
			    "passphrase): ", RP_ALLOW_STDIN);
		passphrase2 = read_passphrase("Enter same passphrase again: ",
		    RP_ALLOW_STDIN);

		/* Verify that they are the same. */
		எனில் (strcmp(passphrase1, passphrase2) != 0) {
			explicit_bzero(passphrase1, strlen(passphrase1));
			explicit_bzero(passphrase2, strlen(passphrase2));
			விடுவி(passphrase1);
			விடுவி(passphrase2);
			printf("Pass phrases do not match.  Try again.\n");
			exit(1);
		}
		/* Destroy the other copy. */
		freezero(passphrase2, strlen(passphrase2));
	}

	/* Save the file using the new passphrase. */
	எனில் ((r = sshkey_save_private(தனிப்பட்ட, identity_file, passphrase1,
	    comment, private_சாவி_format, openssh_format_cipher, rounds)) != 0) {
		error_r(r, "Saving key \"%s\" failed", identity_file);
		freezero(passphrase1, strlen(passphrase1));
		sshkey_free(தனிப்பட்ட);
		விடுவி(comment);
		exit(1);
	}
	/* Destroy the passphrase and the copy of the key in memory. */
	freezero(passphrase1, strlen(passphrase1));
	sshkey_free(தனிப்பட்ட);		 /* Destroys contents */
	விடுவி(comment);

	printf("Your identification has been saved with the new passphrase.\n");
	exit(0);
}

/*
 * Print the SSHFP RR.
 */
நிலையான முழு
do_print_resource_record(கட்டமைப்பு passwd *pw, எழுத்து *fname, எழுத்து *hname,
    முழு print_generic, எழுத்து * மாறிலி *opts, size_t nopts)
{
	கட்டமைப்பு sshkey *பொது;
	எழுத்து *comment = வெற்று;
	மாறிலி எழுத்து *p;
	கட்டமைப்பு stat st;
	முழு r, hash = -1;
	size_t i;

	க்கு (i = 0; i < nopts; i++) {
		எனில் ((p = strprefix(opts[i], "hashalg=", 1)) != வெற்று) {
			எனில் ((hash = ssh_digest_alg_by_name(p)) == -1)
				fatal("Unsupported hash algorithm");
		} இல்லையெனில் {
			error("Invalid option \"%s\"", opts[i]);
			திரும்பு SSH_ERR_INVALID_ARGUMENT;
		}
	}
	எனில் (fname == வெற்று)
		fatal_f("no filename");
	எனில் (stat(fname, &st) == -1) {
		எனில் (errno == ENOENT)
			திரும்பு 0;
		fatal("%s: %s", fname, strerror(errno));
	}
	எனில் ((r = sshkey_load_public(fname, &பொது, &comment)) != 0)
		fatal_r(r, "Failed to read v2 public key from \"%s\"", fname);
	export_dns_rr(hname, பொது, stdout, print_generic, hash);
	sshkey_free(பொது);
	விடுவி(comment);
	திரும்பு 1;
}

/*
 * Change the comment of a private key file.
 */
நிலையான வெறுமை
do_change_comment(கட்டமைப்பு passwd *pw, மாறிலி எழுத்து *identity_comment)
{
	எழுத்து new_comment[சாவி_COMMENT_MAX], *comment, *passphrase;
	கட்டமைப்பு sshkey *தனிப்பட்ட;
	கட்டமைப்பு sshkey *பொது;
	கட்டமைப்பு stat st;
	முழு r;

	எனில் (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	எனில் (stat(identity_file, &st) == -1)
		fatal("%s: %s", identity_file, strerror(errno));
	எனில் ((r = sshkey_load_private(identity_file, "",
	    &தனிப்பட்ட, &comment)) == 0)
		passphrase = xstrdup("");
	இல்லையெனில் எனில் (r != SSH_ERR_சாவி_WRONG_PASSPHRASE)
		fatal_r(r, "Cannot load private key \"%s\"", identity_file);
	இல்லையெனில் {
		எனில் (identity_passphrase)
			passphrase = xstrdup(identity_passphrase);
		இல்லையெனில் எனில் (identity_new_passphrase)
			passphrase = xstrdup(identity_new_passphrase);
		இல்லையெனில்
			passphrase = read_passphrase("Enter passphrase: ",
			    RP_ALLOW_STDIN);
		/* Try to load using the passphrase. */
		எனில் ((r = sshkey_load_private(identity_file, passphrase,
		    &தனிப்பட்ட, &comment)) != 0) {
			freezero(passphrase, strlen(passphrase));
			fatal_r(r, "Cannot load private key \"%s\"",
			    identity_file);
		}
	}

	எனில் (தனிப்பட்ட->type != சாவி_ED25519 &&
	    private_சாவி_format != SSHKEY_PRIVATE_OPENSSH) {
		error("Comments are only supported for keys stored in "
		    "the new format (-o).");
		explicit_bzero(passphrase, strlen(passphrase));
		sshkey_free(தனிப்பட்ட);
		exit(1);
	}
	எனில் (comment)
		printf("Old comment: %s\n", comment);
	இல்லையெனில்
		printf("No existing comment\n");

	எனில் (identity_comment) {
		strlcpy(new_comment, identity_comment, அளவு(new_comment));
	} இல்லையெனில் {
		printf("New comment: ");
		fflush(stdout);
		எனில் (!fgets(new_comment, அளவு(new_comment), stdin)) {
			explicit_bzero(passphrase, strlen(passphrase));
			sshkey_free(தனிப்பட்ட);
			exit(1);
		}
		new_comment[strcspn(new_comment, "\n")] = '\0';
	}
	எனில் (comment != வெற்று && strcmp(comment, new_comment) == 0) {
		printf("No change to comment\n");
		விடுவி(passphrase);
		sshkey_free(தனிப்பட்ட);
		விடுவி(comment);
		exit(0);
	}

	/* Save the file using the new passphrase. */
	எனில் ((r = sshkey_save_private(தனிப்பட்ட, identity_file, passphrase,
	    new_comment, private_சாவி_format, openssh_format_cipher,
	    rounds)) != 0) {
		error_r(r, "Saving key \"%s\" failed", identity_file);
		freezero(passphrase, strlen(passphrase));
		sshkey_free(தனிப்பட்ட);
		விடுவி(comment);
		exit(1);
	}
	freezero(passphrase, strlen(passphrase));
	எனில் ((r = sshkey_from_private(தனிப்பட்ட, &பொது)) != 0)
		fatal_fr(r, "sshkey_from_private");
	sshkey_free(தனிப்பட்ட);

	strlcat(identity_file, ".pub", அளவு(identity_file));
	எனில் ((r = sshkey_save_public(பொது, identity_file, new_comment)) != 0)
		fatal_r(r, "Unable to save public key to %s", identity_file);
	sshkey_free(பொது);
	விடுவி(comment);

	எனில் (strlen(new_comment) > 0)
		printf("Comment '%s' applied\n", new_comment);
	இல்லையெனில்
		printf("Comment removed\n");

	exit(0);
}

நிலையான வெறுமை
cert_ext_add(மாறிலி எழுத்து *சாவி, மாறிலி எழுத்து *மதிப்பு, முழு iscrit)
{
	cert_ext = xreallocarray(cert_ext, ncert_ext + 1, அளவு(*cert_ext));
	cert_ext[ncert_ext].சாவி = xstrdup(சாவி);
	cert_ext[ncert_ext].val = மதிப்பு == வெற்று ? வெற்று : xstrdup(மதிப்பு);
	cert_ext[ncert_ext].crit = iscrit;
	ncert_ext++;
}

/* qsort(3) comparison function for certificate extensions */
நிலையான முழு
cert_ext_cmp(மாறிலி வெறுமை *_a, மாறிலி வெறுமை *_b)
{
	மாறிலி கட்டமைப்பு cert_ext *a = (மாறிலி கட்டமைப்பு cert_ext *)_a;
	மாறிலி கட்டமைப்பு cert_ext *b = (மாறிலி கட்டமைப்பு cert_ext *)_b;
	முழு r;

	எனில் (a->crit != b->crit)
		திரும்பு (a->crit < b->crit) ? -1 : 1;
	எனில் ((r = strcmp(a->சாவி, b->சாவி)) != 0)
		திரும்பு r;
	எனில் ((a->val == வெற்று) != (b->val == வெற்று))
		திரும்பு (a->val == வெற்று) ? -1 : 1;
	எனில் (a->val != வெற்று && (r = strcmp(a->val, b->val)) != 0)
		திரும்பு r;
	திரும்பு 0;
}

#define OPTIONS_CRITICAL	1
#define OPTIONS_EXTENSIONS	2
நிலையான வெறுமை
prepare_options_buf(கட்டமைப்பு sshbuf *c, முழு which)
{
	கட்டமைப்பு sshbuf *b;
	size_t i;
	முழு r;
	மாறிலி கட்டமைப்பு cert_ext *ext;

	எனில் ((b = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	sshbuf_reset(c);
	க்கு (i = 0; i < ncert_ext; i++) {
		ext = &cert_ext[i];
		எனில் ((ext->crit && (which & OPTIONS_EXTENSIONS)) ||
		    (!ext->crit && (which & OPTIONS_CRITICAL)))
			தொடர்;
		எனில் (ext->val == வெற்று) {
			/* flag option */
			debug3_f("%s", ext->சாவி);
			எனில் ((r = sshbuf_put_cstring(c, ext->சாவி)) != 0 ||
			    (r = sshbuf_put_string(c, வெற்று, 0)) != 0)
				fatal_fr(r, "prepare flag");
		} இல்லையெனில் {
			/* key/value option */
			debug3_f("%s=%s", ext->சாவி, ext->val);
			sshbuf_reset(b);
			எனில் ((r = sshbuf_put_cstring(c, ext->சாவி)) != 0 ||
			    (r = sshbuf_put_cstring(b, ext->val)) != 0 ||
			    (r = sshbuf_put_stringb(c, b)) != 0)
				fatal_fr(r, "prepare k/v");
		}
	}
	sshbuf_free(b);
}

நிலையான வெறுமை
finalise_cert_exts(வெறுமை)
{
	/* critical options */
	எனில் (certflags_command != வெற்று)
		cert_ext_add("force-command", certflags_command, 1);
	எனில் (certflags_src_addr != வெற்று)
		cert_ext_add("source-address", certflags_src_addr, 1);
	எனில் ((certflags_flags & CERTOPT_REQUIRE_VERIFY) != 0)
		cert_ext_add("verify-required", வெற்று, 1);
	/* extensions */
	எனில் ((certflags_flags & CERTOPT_X_FWD) != 0)
		cert_ext_add("permit-X11-forwarding", வெற்று, 0);
	எனில் ((certflags_flags & CERTOPT_AGENT_FWD) != 0)
		cert_ext_add("permit-agent-forwarding", வெற்று, 0);
	எனில் ((certflags_flags & CERTOPT_PORT_FWD) != 0)
		cert_ext_add("permit-port-forwarding", வெற்று, 0);
	எனில் ((certflags_flags & CERTOPT_PTY) != 0)
		cert_ext_add("permit-pty", வெற்று, 0);
	எனில் ((certflags_flags & CERTOPT_USER_RC) != 0)
		cert_ext_add("permit-user-rc", வெற்று, 0);
	எனில் ((certflags_flags & CERTOPT_NO_REQUIRE_USER_PRESENCE) != 0)
		cert_ext_add("no-touch-required", வெற்று, 0);
	/* order lexically by key */
	எனில் (ncert_ext > 0)
		qsort(cert_ext, ncert_ext, அளவு(*cert_ext), cert_ext_cmp);
}

நிலையான கட்டமைப்பு sshkey *
load_pkcs11_சாவி(எழுத்து *path)
{
#ifdef ENABLE_PKCS11
	கட்டமைப்பு sshkey **சாவிகள் = வெற்று, *பொது, *தனிப்பட்ட = வெற்று;
	முழு r, i, nkeys;

	எனில் ((r = sshkey_load_public(path, &பொது, வெற்று)) != 0)
		fatal_r(r, "Couldn't load CA public key \"%s\"", path);

	nkeys = pkcs11_add_provider(pkcs11provider, identity_passphrase,
	    &சாவிகள், வெற்று);
	debug3_f("%d keys", nkeys);
	எனில் (nkeys <= 0)
		fatal("cannot read public key from pkcs11");
	க்கு (i = 0; i < nkeys; i++) {
		எனில் (sshkey_equal_public(பொது, சாவிகள்[i])) {
			தனிப்பட்ட = சாவிகள்[i];
			தொடர்;
		}
		sshkey_free(சாவிகள்[i]);
	}
	விடுவி(சாவிகள்);
	sshkey_free(பொது);
	திரும்பு தனிப்பட்ட;
#இல்லையெனில்
	fatal("no pkcs11 support");
#endif /* ENABLE_PKCS11 */
}

/* Signer for sshkey_certify_custom that uses the agent */
நிலையான முழு
agent_signer(கட்டமைப்பு sshkey *சாவி, u_char **sigp, size_t *lenp,
    மாறிலி u_char *data, size_t datalen,
    மாறிலி எழுத்து *alg, மாறிலி எழுத்து *provider, மாறிலி எழுத்து *pin,
    u_int compat, வெறுமை *ctx)
{
	முழு *agent_fdp = (முழு *)ctx;

	திரும்பு ssh_agent_sign(*agent_fdp, சாவி, sigp, lenp,
	    data, datalen, alg, compat);
}

நிலையான வெறுமை
do_ca_sign(கட்டமைப்பு passwd *pw, மாறிலி எழுத்து *ca_சாவி_path, முழு prefer_agent,
    unsigned long long cert_serial, முழு cert_serial_autoinc,
    முழு argc, எழுத்து **argv)
{
	முழு r, i, சாவி_in_agent = 0, agent_fd = -1;
	u_int n;
	கட்டமைப்பு sshkey *ca, *பொது;
	எழுத்து valid[64], *otmp, *tmp, *cp, *out, *comment;
	எழுத்து *ca_fp = வெற்று, **plist = வெற்று, *pin = வெற்று;
	கட்டமைப்பு ssh_identitylist *agent_ids;
	size_t j;
	கட்டமைப்பு notifier_ctx *notifier = வெற்று;

#ifdef ENABLE_PKCS11
	pkcs11_init(1);
#endif
	tmp = tilde_expand_filename(ca_சாவி_path, pw->pw_uid);
	எனில் (pkcs11provider != வெற்று) {
		/* If a PKCS#11 token was specified then try to use it */
		எனில் ((ca = load_pkcs11_சாவி(tmp)) == வெற்று)
			fatal("No PKCS#11 key matching %s found", ca_சாவி_path);
	} இல்லையெனில் எனில் (prefer_agent) {
		/*
		 * Agent signature requested. Try to use agent after making
		 * sure the public key specified is actually present in the
		 * agent.
		 */
		எனில் ((r = sshkey_load_public(tmp, &ca, வெற்று)) != 0)
			fatal_r(r, "Cannot load CA public key %s", tmp);
		எனில் ((r = ssh_get_authentication_socket(&agent_fd)) != 0)
			fatal_r(r, "Cannot use public key for CA signature");
		எனில் ((r = ssh_fetch_identitylist(agent_fd, &agent_ids)) != 0)
			fatal_r(r, "Retrieve agent key list");
		க்கு (j = 0; j < agent_ids->nkeys; j++) {
			எனில் (sshkey_equal(ca, agent_ids->சாவிகள்[j])) {
				சாவி_in_agent = 1;
				/* Replace the CA key with the agent one */
				sshkey_free(ca);
				ca = agent_ids->சாவிகள்[j];
				agent_ids->சாவிகள்[j] = வெற்று;
				நிறுத்து;
			}
		}
		எனில் (!சாவி_in_agent)
			fatal("CA key %s not found in agent", tmp);
		ssh_free_identitylist(agent_ids);
	} இல்லையெனில் {
		/* CA key is assumed to be a private key on the filesystem */
		ca = load_identity(tmp, வெற்று);
		எனில் (sshkey_is_sk(ca) &&
		    (ca->sk_flags & SSH_SK_USER_VERIFICATION_REQD)) {
			எனில் ((pin = read_passphrase("Enter PIN for CA key: ",
			    RP_ALLOW_STDIN)) == வெற்று)
				fatal_f("couldn't read PIN");
		}
	}
	விடுவி(tmp);

	எனில் (சாவி_type_name != வெற்று) {
		எனில் (sshkey_type_from_shortname(சாவி_type_name) != ca->type) {
			fatal("CA key type %s doesn't match specified %s",
			    sshkey_ssh_name(ca), சாவி_type_name);
		}
	} இல்லையெனில் எனில் (ca->type == சாவி_RSA) {
		/* Default to a good signature algorithm */
		சாவி_type_name = "rsa-sha2-512";
	}
	ca_fp = sshkey_fingerprint(ca, fingerprint_hash, SSH_FP_DEFAULT);

	finalise_cert_exts();
	க்கு (i = 0; i < argc; i++) {
		/* Split list of principals */
		n = 0;
		எனில் (cert_principals != வெற்று) {
			otmp = tmp = xstrdup(cert_principals);
			plist = வெற்று;
			க்கு (; (cp = strsep(&tmp, ",")) != வெற்று; n++) {
				plist = xreallocarray(plist, n + 1, அளவு(*plist));
				எனில் (*(plist[n] = xstrdup(cp)) == '\0')
					fatal("Empty principal name");
			}
			விடுவி(otmp);
		}
		எனில் (n > SSHKEY_CERT_MAX_PRINCIPALS)
			fatal("Too many certificate principals specified");

		tmp = tilde_expand_filename(argv[i], pw->pw_uid);
		எனில் ((r = sshkey_load_public(tmp, &பொது, &comment)) != 0)
			fatal_r(r, "load pubkey \"%s\"", tmp);
		எனில் (sshkey_is_cert(பொது))
			fatal_f("key \"%s\" type %s cannot be certified",
			    tmp, sshkey_type(பொது));

		/* Prepare certificate to sign */
		எனில் ((r = sshkey_to_certified(பொது)) != 0)
			fatal_r(r, "Could not upgrade key %s to certificate", tmp);
		பொது->cert->type = cert_சாவி_type;
		பொது->cert->serial = (uint64_t)cert_serial;
		பொது->cert->சாவி_id = xstrdup(cert_சாவி_id);
		பொது->cert->nprincipals = n;
		பொது->cert->principals = plist;
		பொது->cert->valid_after = cert_valid_from;
		பொது->cert->valid_before = cert_valid_to;
		prepare_options_buf(பொது->cert->critical, OPTIONS_CRITICAL);
		prepare_options_buf(பொது->cert->extensions,
		    OPTIONS_EXTENSIONS);
		எனில் ((r = sshkey_from_private(ca,
		    &பொது->cert->signature_சாவி)) != 0)
			fatal_r(r, "sshkey_from_private (ca key)");

		எனில் (சாவி_in_agent) {
			எனில் ((r = sshkey_certify_custom(பொது, ca,
			    சாவி_type_name, sk_provider, வெற்று, agent_signer,
			    &agent_fd)) != 0)
				fatal_r(r, "Couldn't certify %s via agent", tmp);
		} இல்லையெனில் {
			எனில் (sshkey_is_sk(ca) &&
			    (ca->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
				notifier = notify_start(0,
				    "Confirm user presence for key %s %s",
				    sshkey_type(ca), ca_fp);
			}
			r = sshkey_certify(பொது, ca, சாவி_type_name,
			    sk_provider, pin);
			notify_complete(notifier, "User presence confirmed");
			எனில் (r != 0)
				fatal_r(r, "Couldn't certify key %s", tmp);
		}

		எனில் ((cp = strrchr(tmp, '.')) != வெற்று && strcmp(cp, ".pub") == 0)
			*cp = '\0';
		xasprintf(&out, "%s-cert.pub", tmp);
		விடுவி(tmp);

		எனில் ((r = sshkey_save_public(பொது, out, comment)) != 0) {
			fatal_r(r, "Unable to save public key to %s",
			    identity_file);
		}

		எனில் (!quiet) {
			sshkey_format_cert_validity(பொது->cert,
			    valid, அளவு(valid));
			logit("Signed %s key %s: id \"%s\" serial %llu%s%s "
			    "valid %s", sshkey_cert_type(பொது),
			    out, பொது->cert->சாவி_id,
			    (unsigned long long)பொது->cert->serial,
			    cert_principals != வெற்று ? " for " : "",
			    cert_principals != வெற்று ? cert_principals : "",
			    valid);
		}

		sshkey_free(பொது);
		விடுவி(out);
		விடுவி(comment);
		எனில் (cert_serial_autoinc)
			cert_serial++;
	}
	எனில் (pin != வெற்று)
		freezero(pin, strlen(pin));
	sshkey_free(ca);
	விடுவி(ca_fp);
#ifdef ENABLE_PKCS11
	pkcs11_terminate();
#endif
}

நிலையான uint64_t
parse_relative_time(மாறிலி எழுத்து *s, time_t now)
{
	int64_t mul, secs;

	mul = *s == '-' ? -1 : 1;

	எனில் ((secs = convtime(s + 1)) == -1)
		fatal("Invalid relative certificate time %s", s);
	எனில் (mul == -1 && secs > now)
		fatal("Certificate time %s cannot be represented", s);
	திரும்பு now + (uint64_t)(secs * mul);
}

நிலையான வெறுமை
parse_hex_u64(மாறிலி எழுத்து *s, uint64_t *up)
{
	எழுத்து *ep;
	unsigned long long ull;

	errno = 0;
	ull = strtoull(s, &ep, 16);
	எனில் (*s == '\0' || *ep != '\0')
		fatal("Invalid certificate time: not a number");
	எனில் (errno == ERANGE && ull == ULONG_MAX)
		fatal_fr(SSH_ERR_SYSTEM_ERROR, "Invalid certificate time");
	*up = (uint64_t)ull;
}

நிலையான வெறுமை
parse_cert_times(எழுத்து *timespec)
{
	எழுத்து *from, *to;
	time_t now = time(வெற்று);
	int64_t secs;

	/* +timespec relative to now */
	எனில் (*timespec == '+' && strchr(timespec, ':') == வெற்று) {
		எனில் ((secs = convtime(timespec + 1)) == -1)
			fatal("Invalid relative certificate life %s", timespec);
		cert_valid_to = now + secs;
		/*
		 * Backdate certificate one minute to avoid problems on hosts
		 * with poorly-synchronised clocks.
		 */
		cert_valid_from = ((now - 59)/ 60) * 60;
		திரும்பு;
	}

	/*
	 * from:to, where
	 * from := [+-]timespec | YYYYMMDD | YYYYMMDDHHMMSS | 0x... | "always"
	 *   to := [+-]timespec | YYYYMMDD | YYYYMMDDHHMMSS | 0x... | "forever"
	 */
	from = xstrdup(timespec);
	to = strchr(from, ':');
	எனில் (to == வெற்று || from == to || *(to + 1) == '\0')
		fatal("Invalid certificate life specification %s", timespec);
	*to++ = '\0';

	எனில் (*from == '-' || *from == '+')
		cert_valid_from = parse_relative_time(from, now);
	இல்லையெனில் எனில் (strcmp(from, "always") == 0)
		cert_valid_from = 0;
	இல்லையெனில் எனில் (strncmp(from, "0x", 2) == 0)
		parse_hex_u64(from, &cert_valid_from);
	இல்லையெனில் எனில் (parse_absolute_time(from, &cert_valid_from) != 0)
		fatal("Invalid from time \"%s\"", from);

	எனில் (*to == '-' || *to == '+')
		cert_valid_to = parse_relative_time(to, now);
	இல்லையெனில் எனில் (strcmp(to, "forever") == 0)
		cert_valid_to = ~(uint64_t)0;
	இல்லையெனில் எனில் (strncmp(to, "0x", 2) == 0)
		parse_hex_u64(to, &cert_valid_to);
	இல்லையெனில் எனில் (parse_absolute_time(to, &cert_valid_to) != 0)
		fatal("Invalid to time \"%s\"", to);

	எனில் (cert_valid_to <= cert_valid_from)
		fatal("Empty certificate validity interval");
	விடுவி(from);
}

நிலையான வெறுமை
add_cert_option(எழுத்து *opt)
{
	எழுத்து *val, *cp;
	மாறிலி எழுத்து *p;
	முழு iscrit = 0;

	எனில் (strcasecmp(opt, "clear") == 0)
		certflags_flags = 0;
	இல்லையெனில் எனில் (strcasecmp(opt, "no-x11-forwarding") == 0)
		certflags_flags &= ~CERTOPT_X_FWD;
	இல்லையெனில் எனில் (strcasecmp(opt, "permit-x11-forwarding") == 0)
		certflags_flags |= CERTOPT_X_FWD;
	இல்லையெனில் எனில் (strcasecmp(opt, "no-agent-forwarding") == 0)
		certflags_flags &= ~CERTOPT_AGENT_FWD;
	இல்லையெனில் எனில் (strcasecmp(opt, "permit-agent-forwarding") == 0)
		certflags_flags |= CERTOPT_AGENT_FWD;
	இல்லையெனில் எனில் (strcasecmp(opt, "no-port-forwarding") == 0)
		certflags_flags &= ~CERTOPT_PORT_FWD;
	இல்லையெனில் எனில் (strcasecmp(opt, "permit-port-forwarding") == 0)
		certflags_flags |= CERTOPT_PORT_FWD;
	இல்லையெனில் எனில் (strcasecmp(opt, "no-pty") == 0)
		certflags_flags &= ~CERTOPT_PTY;
	இல்லையெனில் எனில் (strcasecmp(opt, "permit-pty") == 0)
		certflags_flags |= CERTOPT_PTY;
	இல்லையெனில் எனில் (strcasecmp(opt, "no-user-rc") == 0)
		certflags_flags &= ~CERTOPT_USER_RC;
	இல்லையெனில் எனில் (strcasecmp(opt, "permit-user-rc") == 0)
		certflags_flags |= CERTOPT_USER_RC;
	இல்லையெனில் எனில் (strcasecmp(opt, "touch-required") == 0)
		certflags_flags &= ~CERTOPT_NO_REQUIRE_USER_PRESENCE;
	இல்லையெனில் எனில் (strcasecmp(opt, "no-touch-required") == 0)
		certflags_flags |= CERTOPT_NO_REQUIRE_USER_PRESENCE;
	இல்லையெனில் எனில் (strcasecmp(opt, "no-verify-required") == 0)
		certflags_flags &= ~CERTOPT_REQUIRE_VERIFY;
	இல்லையெனில் எனில் (strcasecmp(opt, "verify-required") == 0)
		certflags_flags |= CERTOPT_REQUIRE_VERIFY;
	இல்லையெனில் எனில் ((p = strprefix(opt, "force-command=", 1)) != வெற்று) {
		எனில் (*p == '\0')
			fatal("Empty force-command option");
		எனில் (certflags_command != வெற்று)
			fatal("force-command already specified");
		certflags_command = xstrdup(p);
	} இல்லையெனில் எனில் ((p = strprefix(opt, "source-address=", 1)) != வெற்று) {
		எனில் (*p == '\0')
			fatal("Empty source-address option");
		எனில் (certflags_src_addr != வெற்று)
			fatal("source-address already specified");
		எனில் (addr_match_cidr_list(வெற்று, p) != 0)
			fatal("Invalid source-address list");
		certflags_src_addr = xstrdup(p);
	} இல்லையெனில் எனில் (strprefix(opt, "extension:", 1) != வெற்று ||
		    (iscrit = (strprefix(opt, "critical:", 1) != வெற்று))) {
		val = xstrdup(strchr(opt, ':') + 1);
		எனில் ((cp = strchr(val, '=')) != வெற்று)
			*cp++ = '\0';
		cert_ext_add(val, cp, iscrit);
		விடுவி(val);
	} இல்லையெனில்
		fatal("Unsupported certificate option \"%s\"", opt);
}

நிலையான வெறுமை
show_options(கட்டமைப்பு sshbuf *optbuf, முழு in_critical)
{
	எழுத்து *name, *arg, *hex;
	கட்டமைப்பு sshbuf *options, *option = வெற்று;
	முழு r;

	எனில் ((options = sshbuf_fromb(optbuf)) == வெற்று)
		fatal_f("sshbuf_fromb failed");
	போது (sshbuf_len(options) != 0) {
		sshbuf_free(option);
		option = வெற்று;
		எனில் ((r = sshbuf_get_cstring(options, &name, வெற்று)) != 0 ||
		    (r = sshbuf_froms(options, &option)) != 0)
			fatal_fr(r, "parse option");
		printf("                %s", name);
		எனில் (!in_critical &&
		    (strcmp(name, "permit-X11-forwarding") == 0 ||
		    strcmp(name, "permit-agent-forwarding") == 0 ||
		    strcmp(name, "permit-port-forwarding") == 0 ||
		    strcmp(name, "permit-pty") == 0 ||
		    strcmp(name, "permit-user-rc") == 0 ||
		    strcmp(name, "no-touch-required") == 0)) {
			printf("\n");
		} இல்லையெனில் எனில் (in_critical &&
		    (strcmp(name, "force-command") == 0 ||
		    strcmp(name, "source-address") == 0)) {
			எனில் ((r = sshbuf_get_cstring(option, &arg, வெற்று)) != 0)
				fatal_fr(r, "parse critical");
			printf(" %s\n", arg);
			விடுவி(arg);
		} இல்லையெனில் எனில் (in_critical &&
		    strcmp(name, "verify-required") == 0) {
			printf("\n");
		} இல்லையெனில் எனில் (sshbuf_len(option) > 0) {
			hex = sshbuf_dtob16(option);
			printf(" UNKNOWN OPTION: %s (len %zu)\n",
			    hex, sshbuf_len(option));
			sshbuf_reset(option);
			விடுவி(hex);
		} இல்லையெனில்
			printf(" UNKNOWN FLAG OPTION\n");
		விடுவி(name);
		எனில் (sshbuf_len(option) != 0)
			fatal("Option corrupt: extra data at end");
	}
	sshbuf_free(option);
	sshbuf_free(options);
}

நிலையான வெறுமை
print_cert(கட்டமைப்பு sshkey *சாவி)
{
	எழுத்து valid[64], *சாவி_fp, *ca_fp;
	u_int i;

	சாவி_fp = sshkey_fingerprint(சாவி, fingerprint_hash, SSH_FP_DEFAULT);
	ca_fp = sshkey_fingerprint(சாவி->cert->signature_சாவி,
	    fingerprint_hash, SSH_FP_DEFAULT);
	எனில் (சாவி_fp == வெற்று || ca_fp == வெற்று)
		fatal_f("sshkey_fingerprint fail");
	sshkey_format_cert_validity(சாவி->cert, valid, அளவு(valid));

	printf("        Type: %s %s certificate\n", sshkey_ssh_name(சாவி),
	    sshkey_cert_type(சாவி));
	printf("        Public key: %s %s\n", sshkey_type(சாவி), சாவி_fp);
	printf("        Signing CA: %s %s (using %s)\n",
	    sshkey_type(சாவி->cert->signature_சாவி), ca_fp,
	    சாவி->cert->signature_type);
	printf("        Key ID: \"%s\"\n", சாவி->cert->சாவி_id);
	printf("        Serial: %llu\n", (unsigned long long)சாவி->cert->serial);
	printf("        Valid: %s\n", valid);
	printf("        Principals: ");
	எனில் (சாவி->cert->nprincipals == 0)
		printf("(none)\n");
	இல்லையெனில் {
		க்கு (i = 0; i < சாவி->cert->nprincipals; i++)
			printf("\n                %s",
			    சாவி->cert->principals[i]);
		printf("\n");
	}
	printf("        Critical Options: ");
	எனில் (sshbuf_len(சாவி->cert->critical) == 0)
		printf("(none)\n");
	இல்லையெனில் {
		printf("\n");
		show_options(சாவி->cert->critical, 1);
	}
	printf("        Extensions: ");
	எனில் (sshbuf_len(சாவி->cert->extensions) == 0)
		printf("(none)\n");
	இல்லையெனில் {
		printf("\n");
		show_options(சாவி->cert->extensions, 0);
	}
	விடுவி(சாவி_fp);
	விடுவி(ca_fp);
}

நிலையான வெறுமை
do_show_cert(கட்டமைப்பு passwd *pw)
{
	கட்டமைப்பு sshkey *சாவி = வெற்று;
	கட்டமைப்பு stat st;
	முழு r, is_stdin = 0, ok = 0;
	FILE *f;
	எழுத்து *cp, *வரி = வெற்று;
	மாறிலி எழுத்து *path;
	size_t linesize = 0;
	u_long lnum = 0;

	எனில் (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	எனில் (strcmp(identity_file, "-") != 0 && stat(identity_file, &st) == -1)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));

	path = identity_file;
	எனில் (strcmp(path, "-") == 0) {
		f = stdin;
		path = "(stdin)";
		is_stdin = 1;
	} இல்லையெனில் எனில் ((f = fopen(identity_file, "r")) == வெற்று)
		fatal("fopen %s: %s", identity_file, strerror(errno));

	போது (getline(&வரி, &linesize, f) != -1) {
		lnum++;
		sshkey_free(சாவி);
		சாவி = வெற்று;
		/* Trim leading space and comments */
		cp = வரி + strspn(வரி, " \t");
		எனில் (*cp == '#' || *cp == '\0')
			தொடர்;
		எனில் ((சாவி = sshkey_new(சாவி_UNSPEC)) == வெற்று)
			fatal("sshkey_new");
		எனில் ((r = sshkey_read(சாவி, &cp)) != 0) {
			error_r(r, "%s:%lu: invalid key", path, lnum);
			தொடர்;
		}
		எனில் (!sshkey_is_cert(சாவி)) {
			error("%s:%lu is not a certificate", path, lnum);
			தொடர்;
		}
		ok = 1;
		எனில் (!is_stdin && lnum == 1)
			printf("%s:\n", path);
		இல்லையெனில்
			printf("%s:%lu:\n", path, lnum);
		print_cert(சாவி);
	}
	விடுவி(வரி);
	sshkey_free(சாவி);
	fclose(f);
	exit(ok ? 0 : 1);
}

நிலையான வெறுமை
load_krl(மாறிலி எழுத்து *path, கட்டமைப்பு ssh_krl **krlp)
{
	கட்டமைப்பு sshbuf *krlbuf;
	முழு r;

	எனில் ((r = sshbuf_load_file(path, &krlbuf)) != 0)
		fatal_r(r, "Unable to load KRL %s", path);
	/* XXX check sigs */
	எனில் ((r = ssh_krl_from_blob(krlbuf, krlp)) != 0 ||
	    *krlp == வெற்று)
		fatal_r(r, "Invalid KRL file %s", path);
	sshbuf_free(krlbuf);
}

நிலையான வெறுமை
hash_to_blob(மாறிலி எழுத்து *cp, u_char **blobp, size_t *lenp,
    மாறிலி எழுத்து *file, u_long lnum)
{
	எழுத்து *tmp;
	size_t tlen;
	கட்டமைப்பு sshbuf *b;
	முழு r;

	எனில் ((cp = strprefix(cp, "SHA256:", 0)) == வெற்று)
		fatal("%s:%lu: unsupported hash algorithm", file, lnum);

	/*
	 * OpenSSH base64 hashes omit trailing '='
	 * characters; put them back for decode.
	 */
	எனில் ((tlen = strlen(cp)) >= SIZE_MAX - 5)
		fatal_f("hash too long: %zu bytes", tlen);
	tmp = xmalloc(tlen + 4 + 1);
	strlcpy(tmp, cp, tlen + 1);
	போது ((tlen % 4) != 0) {
		tmp[tlen++] = '=';
		tmp[tlen] = '\0';
	}
	எனில் ((b = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = sshbuf_b64tod(b, tmp)) != 0)
		fatal_r(r, "%s:%lu: decode hash failed", file, lnum);
	விடுவி(tmp);
	*lenp = sshbuf_len(b);
	*blobp = xmalloc(*lenp);
	memcpy(*blobp, sshbuf_ptr(b), *lenp);
	sshbuf_free(b);
}

நிலையான வெறுமை
update_krl_from_file(கட்டமைப்பு passwd *pw, மாறிலி எழுத்து *file, முழு wild_ca,
    மாறிலி கட்டமைப்பு sshkey *ca, கட்டமைப்பு ssh_krl *krl)
{
	கட்டமைப்பு sshkey *சாவி = வெற்று;
	u_long lnum = 0;
	எழுத்து *path, *cp, *ep, *வரி = வெற்று;
	u_char *blob = வெற்று;
	size_t blen = 0, linesize = 0;
	unsigned long long serial, serial2;
	முழு i, was_explicit_சாவி, was_sha1, was_sha256, was_hash, r;
	FILE *krl_spec;

	path = tilde_expand_filename(file, pw->pw_uid);
	எனில் (strcmp(path, "-") == 0) {
		krl_spec = stdin;
		விடுவி(path);
		path = xstrdup("(standard input)");
	} இல்லையெனில் எனில் ((krl_spec = fopen(path, "r")) == வெற்று)
		fatal("fopen %s: %s", path, strerror(errno));

	எனில் (!quiet)
		printf("Revoking from %s\n", path);
	போது (getline(&வரி, &linesize, krl_spec) != -1) {
		எனில் (linesize >= INT_MAX) {
			fatal_f("%s contains unparsable line, len=%zu",
			    path, linesize);
		}
		lnum++;
		was_explicit_சாவி = was_sha1 = was_sha256 = was_hash = 0;
		cp = வரி + strspn(வரி, " \t");
		/* Trim trailing space, comments and strip \n */
		க்கு (i = 0, r = -1; cp[i] != '\0'; i++) {
			எனில் (cp[i] == '#' || cp[i] == '\n') {
				cp[i] = '\0';
				நிறுத்து;
			}
			எனில் (cp[i] == ' ' || cp[i] == '\t') {
				/* Remember the start of a span of whitespace */
				எனில் (r == -1)
					r = i;
			} இல்லையெனில்
				r = -1;
		}
		எனில் (r != -1)
			cp[r] = '\0';
		எனில் (*cp == '\0')
			தொடர்;
		எனில் (strncasecmp(cp, "serial:", 7) == 0) {
			எனில் (ca == வெற்று && !wild_ca) {
				fatal("revoking certificates by serial number "
				    "requires specification of a CA key");
			}
			cp += 7;
			cp = cp + strspn(cp, " \t");
			errno = 0;
			serial = strtoull(cp, &ep, 0);
			எனில் (*cp == '\0' || (*ep != '\0' && *ep != '-'))
				fatal("%s:%lu: invalid serial \"%s\"",
				    path, lnum, cp);
			எனில் (errno == ERANGE && serial == ULLONG_MAX)
				fatal("%s:%lu: serial out of range",
				    path, lnum);
			serial2 = serial;
			எனில் (*ep == '-') {
				cp = ep + 1;
				errno = 0;
				serial2 = strtoull(cp, &ep, 0);
				எனில் (*cp == '\0' || *ep != '\0')
					fatal("%s:%lu: invalid serial \"%s\"",
					    path, lnum, cp);
				எனில் (errno == ERANGE && serial2 == ULLONG_MAX)
					fatal("%s:%lu: serial out of range",
					    path, lnum);
				எனில் (serial2 <= serial)
					fatal("%s:%lu: invalid serial range "
					    "%llu:%llu", path, lnum,
					    (unsigned long long)serial,
					    (unsigned long long)serial2);
			}
			எனில் (ssh_krl_revoke_cert_by_serial_range(krl,
			    ca, serial, serial2) != 0) {
				fatal_f("revoke serial failed");
			}
		} இல்லையெனில் எனில் (strncasecmp(cp, "id:", 3) == 0) {
			எனில் (ca == வெற்று && !wild_ca) {
				fatal("revoking certificates by key ID "
				    "requires specification of a CA key");
			}
			cp += 3;
			cp = cp + strspn(cp, " \t");
			எனில் (ssh_krl_revoke_cert_by_சாவி_id(krl, ca, cp) != 0)
				fatal_f("revoke key ID failed");
		} இல்லையெனில் எனில் (strncasecmp(cp, "hash:", 5) == 0) {
			cp += 5;
			cp = cp + strspn(cp, " \t");
			hash_to_blob(cp, &blob, &blen, file, lnum);
			எனில் ((r = ssh_krl_revoke_சாவி_sha256(krl,
			    blob, blen)) != 0)
				fatal_fr(r, "revoke key failed");
			விடுவி(blob);
			blob = வெற்று;
			blen = 0;
		} இல்லையெனில் {
			எனில் (strncasecmp(cp, "key:", 4) == 0) {
				cp += 4;
				cp = cp + strspn(cp, " \t");
				was_explicit_சாவி = 1;
			} இல்லையெனில் எனில் (strncasecmp(cp, "sha1:", 5) == 0) {
				cp += 5;
				cp = cp + strspn(cp, " \t");
				was_sha1 = 1;
			} இல்லையெனில் எனில் (strncasecmp(cp, "sha256:", 7) == 0) {
				cp += 7;
				cp = cp + strspn(cp, " \t");
				was_sha256 = 1;
				/*
				 * Just try to process the line as a key.
				 * Parsing will fail if it isn't.
				 */
			}
			எனில் ((சாவி = sshkey_new(சாவி_UNSPEC)) == வெற்று)
				fatal("sshkey_new");
			எனில் ((r = sshkey_read(சாவி, &cp)) != 0)
				fatal_r(r, "%s:%lu: invalid key", path, lnum);
			எனில் (was_explicit_சாவி)
				r = ssh_krl_revoke_சாவி_explicit(krl, சாவி);
			இல்லையெனில் எனில் (was_sha1) {
				எனில் (sshkey_fingerprint_raw(சாவி,
				    SSH_DIGEST_SHA1, &blob, &blen) != 0) {
					fatal("%s:%lu: fingerprint failed",
					    file, lnum);
				}
				r = ssh_krl_revoke_சாவி_sha1(krl, blob, blen);
			} இல்லையெனில் எனில் (was_sha256) {
				எனில் (sshkey_fingerprint_raw(சாவி,
				    SSH_DIGEST_SHA256, &blob, &blen) != 0) {
					fatal("%s:%lu: fingerprint failed",
					    file, lnum);
				}
				r = ssh_krl_revoke_சாவி_sha256(krl, blob, blen);
			} இல்லையெனில்
				r = ssh_krl_revoke_சாவி(krl, சாவி);
			எனில் (r != 0)
				fatal_fr(r, "revoke key failed");
			freezero(blob, blen);
			blob = வெற்று;
			blen = 0;
			sshkey_free(சாவி);
		}
	}
	எனில் (strcmp(path, "-") != 0)
		fclose(krl_spec);
	விடுவி(வரி);
	விடுவி(path);
}

நிலையான வெறுமை
do_gen_krl(கட்டமைப்பு passwd *pw, முழு updating, மாறிலி எழுத்து *ca_சாவி_path,
    unsigned long long krl_version, மாறிலி எழுத்து *krl_comment,
    முழு argc, எழுத்து **argv)
{
	கட்டமைப்பு ssh_krl *krl;
	கட்டமைப்பு stat sb;
	கட்டமைப்பு sshkey *ca = வெற்று;
	முழு i, r, wild_ca = 0;
	எழுத்து *tmp;
	கட்டமைப்பு sshbuf *kbuf;

	எனில் (*identity_file == '\0')
		fatal("KRL generation requires an output file");
	எனில் (stat(identity_file, &sb) == -1) {
		எனில் (errno != ENOENT)
			fatal("Cannot access KRL \"%s\": %s",
			    identity_file, strerror(errno));
		எனில் (updating)
			fatal("KRL \"%s\" does not exist", identity_file);
	}
	எனில் (ca_சாவி_path != வெற்று) {
		எனில் (strcasecmp(ca_சாவி_path, "none") == 0)
			wild_ca = 1;
		இல்லையெனில் {
			tmp = tilde_expand_filename(ca_சாவி_path, pw->pw_uid);
			எனில் ((r = sshkey_load_public(tmp, &ca, வெற்று)) != 0)
				fatal_r(r, "Cannot load CA public key %s", tmp);
			விடுவி(tmp);
		}
	}

	எனில் (updating)
		load_krl(identity_file, &krl);
	இல்லையெனில் எனில் ((krl = ssh_krl_init()) == வெற்று)
		fatal("couldn't create KRL");

	எனில் (krl_version != 0)
		ssh_krl_set_version(krl, krl_version);
	எனில் (krl_comment != வெற்று)
		ssh_krl_set_comment(krl, krl_comment);

	க்கு (i = 0; i < argc; i++)
		update_krl_from_file(pw, argv[i], wild_ca, ca, krl);

	எனில் ((kbuf = sshbuf_new()) == வெற்று)
		fatal("sshbuf_new failed");
	எனில் (ssh_krl_to_blob(krl, kbuf) != 0)
		fatal("Couldn't generate KRL");
	எனில் ((r = sshbuf_write_file(identity_file, kbuf)) != 0)
		fatal("write %s: %s", identity_file, strerror(errno));
	sshbuf_free(kbuf);
	ssh_krl_free(krl);
	sshkey_free(ca);
}

நிலையான வெறுமை
do_check_krl(கட்டமைப்பு passwd *pw, முழு print_krl, முழு argc, எழுத்து **argv)
{
	முழு i, r, ret = 0;
	எழுத்து *comment;
	கட்டமைப்பு ssh_krl *krl;
	கட்டமைப்பு sshkey *k;

	எனில் (*identity_file == '\0')
		fatal("KRL checking requires an input file");
	load_krl(identity_file, &krl);
	எனில் (print_krl)
		krl_dump(krl, stdout);
	க்கு (i = 0; i < argc; i++) {
		எனில் ((r = sshkey_load_public(argv[i], &k, &comment)) != 0)
			fatal_r(r, "Cannot load public key %s", argv[i]);
		r = ssh_krl_check_சாவி(krl, k);
		printf("%s%s%s%s: %s\n", argv[i],
		    *comment ? " (" : "", comment, *comment ? ")" : "",
		    r == 0 ? "ok" : "REVOKED");
		எனில் (r != 0)
			ret = 1;
		sshkey_free(k);
		விடுவி(comment);
	}
	ssh_krl_free(krl);
	exit(ret);
}

நிலையான கட்டமைப்பு sshkey *
load_sign_சாவி(மாறிலி எழுத்து *keypath, மாறிலி கட்டமைப்பு sshkey *pubkey)
{
	size_t i, slen, plen = strlen(keypath);
	எழுத்து *privpath = xstrdup(keypath);
	நிலையான மாறிலி எழுத்து * மாறிலி suffixes[] = { "-cert.pub", ".pub", வெற்று };
	கட்டமைப்பு sshkey *ret = வெற்று, *privkey = வெற்று;
	முழு r, waspub = 0;
	கட்டமைப்பு stat st;

	/*
	 * If passed a public key filename, then try to locate the corresponding
	 * private key. This lets us specify certificates on the command-line
	 * and have ssh-keygen find the appropriate private key.
	 */
	க்கு (i = 0; suffixes[i]; i++) {
		slen = strlen(suffixes[i]);
		எனில் (plen <= slen ||
		    strcmp(privpath + plen - slen, suffixes[i]) != 0)
			தொடர்;
		privpath[plen - slen] = '\0';
		debug_f("%s looks like a public key, using private key "
		    "path %s instead", keypath, privpath);
		waspub = 1;
	}
	எனில் (waspub && stat(privpath, &st) != 0 && errno == ENOENT)
		fatal("No private key found for public key \"%s\"", keypath);
	எனில் ((r = sshkey_load_private(privpath, "", &privkey, வெற்று)) != 0 &&
	    (r != SSH_ERR_சாவி_WRONG_PASSPHRASE)) {
		debug_fr(r, "load private key \"%s\"", privpath);
		fatal("No private key found for \"%s\"", privpath);
	} இல்லையெனில் எனில் (privkey == வெற்று)
		privkey = load_identity(privpath, வெற்று);

	எனில் (!sshkey_equal_public(pubkey, privkey)) {
		error("Public key %s doesn't match private %s",
		    keypath, privpath);
		செல் done;
	}
	எனில் (sshkey_is_cert(pubkey) && !sshkey_is_cert(privkey)) {
		/*
		 * Graft the certificate onto the private key to make
		 * it capable of signing.
		 */
		எனில் ((r = sshkey_to_certified(privkey)) != 0) {
			error_fr(r, "sshkey_to_certified");
			செல் done;
		}
		எனில் ((r = sshkey_cert_copy(pubkey, privkey)) != 0) {
			error_fr(r, "sshkey_cert_copy");
			செல் done;
		}
	}
	/* success */
	ret = privkey;
	privkey = வெற்று;
 done:
	sshkey_free(privkey);
	விடுவி(privpath);
	திரும்பு ret;
}

நிலையான முழு
sign_one(கட்டமைப்பு sshkey *signkey, மாறிலி எழுத்து *filename, முழு fd,
    மாறிலி எழுத்து *sig_namespace, மாறிலி எழுத்து *hashalg, sshsig_signer *signer,
    வெறுமை *signer_ctx)
{
	கட்டமைப்பு sshbuf *sigbuf = வெற்று, *abuf = வெற்று;
	முழு r = SSH_ERR_INTERNAL_ERROR, wfd = -1, oerrno;
	எழுத்து *wfile = வெற்று, *asig = வெற்று, *fp = வெற்று;
	எழுத்து *pin = வெற்று, *prompt = வெற்று;

	எனில் (!quiet) {
		எனில் (fd == STDIN_FILENO)
			fprintf(stderr, "Signing data on standard input\n");
		இல்லையெனில்
			fprintf(stderr, "Signing file %s\n", filename);
	}
	எனில் (signer == வெற்று && sshkey_is_sk(signkey)) {
		எனில் ((signkey->sk_flags & SSH_SK_USER_VERIFICATION_REQD)) {
			xasprintf(&prompt, "Enter PIN for %s key: ",
			    sshkey_type(signkey));
			எனில் ((pin = read_passphrase(prompt,
			    RP_ALLOW_STDIN)) == வெற்று)
				fatal_f("couldn't read PIN");
		}
		எனில் ((signkey->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
			எனில் ((fp = sshkey_fingerprint(signkey, fingerprint_hash,
			    SSH_FP_DEFAULT)) == வெற்று)
				fatal_f("fingerprint failed");
			fprintf(stderr, "Confirm user presence for key %s %s\n",
			    sshkey_type(signkey), fp);
			விடுவி(fp);
		}
	}
	எனில் ((r = sshsig_sign_fd(signkey, hashalg, sk_provider, pin,
	    fd, sig_namespace, &sigbuf, signer, signer_ctx)) != 0) {
		error_r(r, "Signing %s failed", filename);
		செல் out;
	}
	எனில் ((r = sshsig_armor(sigbuf, &abuf)) != 0) {
		error_fr(r, "sshsig_armor");
		செல் out;
	}
	எனில் ((asig = sshbuf_dup_string(abuf)) == வெற்று) {
		error_f("buffer error");
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}

	எனில் (fd == STDIN_FILENO) {
		fputs(asig, stdout);
		fflush(stdout);
	} இல்லையெனில் {
		xasprintf(&wfile, "%s.sig", filename);
		எனில் (confirm_overwrite(wfile)) {
			எனில் ((wfd = open(wfile, O_WRONLY|O_CREAT|O_TRUNC,
			    0666)) == -1) {
				oerrno = errno;
				error("Cannot open %s: %s",
				    wfile, strerror(errno));
				errno = oerrno;
				r = SSH_ERR_SYSTEM_ERROR;
				செல் out;
			}
			எனில் (atomicio(vwrite, wfd, asig,
			    strlen(asig)) != strlen(asig)) {
				oerrno = errno;
				error("Cannot write to %s: %s",
				    wfile, strerror(errno));
				errno = oerrno;
				r = SSH_ERR_SYSTEM_ERROR;
				செல் out;
			}
			எனில் (!quiet) {
				fprintf(stderr, "Write signature to %s\n",
				    wfile);
			}
		}
	}
	/* success */
	r = 0;
 out:
	விடுவி(wfile);
	விடுவி(prompt);
	விடுவி(asig);
	எனில் (pin != வெற்று)
		freezero(pin, strlen(pin));
	sshbuf_free(abuf);
	sshbuf_free(sigbuf);
	எனில் (wfd != -1)
		close(wfd);
	திரும்பு r;
}

நிலையான முழு
sig_process_opts(எழுத்து * மாறிலி *opts, size_t nopts, எழுத்து **hashalgp,
    uint64_t *verify_timep, முழு *print_pubkey)
{
	size_t i;
	time_t now;
	மாறிலி எழுத்து *p;

	எனில் (verify_timep != வெற்று)
		*verify_timep = 0;
	எனில் (print_pubkey != வெற்று)
		*print_pubkey = 0;
	எனில் (hashalgp != வெற்று)
		*hashalgp = வெற்று;
	க்கு (i = 0; i < nopts; i++) {
		எனில் (hashalgp != வெற்று &&
		    (p = strprefix(opts[i], "hashalg=", 1)) != வெற்று) {
			*hashalgp = xstrdup(p);
		} இல்லையெனில் எனில் (verify_timep &&
		    (p = strprefix(opts[i], "verify-time=", 1)) != வெற்று) {
			எனில் (parse_absolute_time(p, verify_timep) != 0 ||
			    *verify_timep == 0) {
				error("Invalid \"verify-time\" option");
				திரும்பு SSH_ERR_INVALID_ARGUMENT;
			}
		} இல்லையெனில் எனில் (print_pubkey &&
		    strcasecmp(opts[i], "print-pubkey") == 0) {
			*print_pubkey = 1;
		} இல்லையெனில் {
			error("Invalid option \"%s\"", opts[i]);
			திரும்பு SSH_ERR_INVALID_ARGUMENT;
		}
	}
	எனில் (verify_timep && *verify_timep == 0) {
		எனில் ((now = time(வெற்று)) < 0) {
			error("Time is before epoch");
			திரும்பு SSH_ERR_INVALID_ARGUMENT;
		}
		*verify_timep = (uint64_t)now;
	}
	திரும்பு 0;
}


நிலையான முழு
sig_sign(மாறிலி எழுத்து *keypath, மாறிலி எழுத்து *sig_namespace, முழு require_agent,
    முழு argc, எழுத்து **argv, எழுத்து * மாறிலி *opts, size_t nopts)
{
	முழு i, fd = -1, r, ret = -1;
	முழு agent_fd = -1;
	கட்டமைப்பு sshkey *pubkey = வெற்று, *privkey = வெற்று, *signkey = வெற்று;
	sshsig_signer *signer = வெற்று;
	எழுத்து *hashalg = வெற்று;

	/* Check file arguments. */
	க்கு (i = 0; i < argc; i++) {
		எனில் (strcmp(argv[i], "-") != 0)
			தொடர்;
		எனில் (i > 0 || argc > 1)
			fatal("Cannot sign mix of paths and standard input");
	}

	எனில் (sig_process_opts(opts, nopts, &hashalg, வெற்று, வெற்று) != 0)
		செல் done; /* error already logged */

	எனில் ((r = sshkey_load_public(keypath, &pubkey, வெற்று)) != 0) {
		error_r(r, "Couldn't load public key %s", keypath);
		செல் done;
	}

	எனில் ((r = ssh_get_authentication_socket(&agent_fd)) != 0) {
		எனில் (require_agent)
			fatal("Couldn't get agent socket");
		debug_r(r, "Couldn't get agent socket");
	} இல்லையெனில் {
		எனில் ((r = ssh_agent_has_சாவி(agent_fd, pubkey)) == 0)
			signer = agent_signer;
		இல்லையெனில் {
			எனில் (require_agent)
				fatal("Couldn't find key in agent");
			debug_r(r, "Couldn't find key in agent");
		}
	}

	எனில் (signer == வெற்று) {
		/* Not using agent - try to load private key */
		எனில் ((privkey = load_sign_சாவி(keypath, pubkey)) == வெற்று)
			செல் done;
		signkey = privkey;
	} இல்லையெனில் {
		/* Will use key in agent */
		signkey = pubkey;
	}

	எனில் (argc == 0) {
		எனில் ((r = sign_one(signkey, "(stdin)", STDIN_FILENO,
		    sig_namespace, hashalg, signer, &agent_fd)) != 0)
			செல் done;
	} இல்லையெனில் {
		க்கு (i = 0; i < argc; i++) {
			எனில் (strcmp(argv[i], "-") == 0)
				fd = STDIN_FILENO;
			இல்லையெனில் எனில் ((fd = open(argv[i], O_RDONLY)) == -1) {
				error("Cannot open %s for signing: %s",
				    argv[i], strerror(errno));
				செல் done;
			}
			எனில் ((r = sign_one(signkey, argv[i], fd, sig_namespace,
			    hashalg, signer, &agent_fd)) != 0)
				செல் done;
			எனில் (fd != STDIN_FILENO)
				close(fd);
			fd = -1;
		}
	}

	ret = 0;
done:
	எனில் (fd != -1 && fd != STDIN_FILENO)
		close(fd);
	sshkey_free(pubkey);
	sshkey_free(privkey);
	விடுவி(hashalg);
	திரும்பு ret;
}

நிலையான முழு
sig_verify(மாறிலி எழுத்து *signature, மாறிலி எழுத்து *sig_namespace,
    மாறிலி எழுத்து *principal, மாறிலி எழுத்து *allowed_சாவிகள், மாறிலி எழுத்து *revoked_சாவிகள்,
    எழுத்து * மாறிலி *opts, size_t nopts)
{
	முழு r, ret = -1;
	முழு print_pubkey = 0;
	கட்டமைப்பு sshbuf *sigbuf = வெற்று, *abuf = வெற்று;
	கட்டமைப்பு sshkey *sign_சாவி = வெற்று;
	எழுத்து *fp = வெற்று;
	கட்டமைப்பு sshkey_sig_details *sig_details = வெற்று;
	uint64_t verify_time = 0;

	எனில் (sig_process_opts(opts, nopts, வெற்று, &verify_time,
	    &print_pubkey) != 0)
		செல் done; /* error already logged */

	memset(&sig_details, 0, அளவு(sig_details));
	எனில் ((r = sshbuf_load_file(signature, &abuf)) != 0) {
		error_r(r, "Couldn't read signature file");
		செல் done;
	}

	எனில் ((r = sshsig_dearmor(abuf, &sigbuf)) != 0) {
		error_fr(r, "sshsig_armor");
		செல் done;
	}
	எனில் ((r = sshsig_verify_fd(sigbuf, STDIN_FILENO, sig_namespace,
	    &sign_சாவி, &sig_details)) != 0)
		செல் done; /* sshsig_verify() prints error */

	எனில் ((fp = sshkey_fingerprint(sign_சாவி, fingerprint_hash,
	    SSH_FP_DEFAULT)) == வெற்று)
		fatal_f("sshkey_fingerprint failed");
	debug("Valid (unverified) signature from key %s", fp);
	எனில் (sig_details != வெற்று) {
		debug2_f("signature details: counter = %u, flags = 0x%02x",
		    sig_details->sk_counter, sig_details->sk_flags);
	}
	விடுவி(fp);
	fp = வெற்று;

	எனில் (revoked_சாவிகள் != வெற்று) {
		எனில் ((r = sshkey_check_revoked(sign_சாவி, revoked_சாவிகள்)) != 0) {
			debug3_fr(r, "sshkey_check_revoked");
			செல் done;
		}
	}

	எனில் (allowed_சாவிகள் != வெற்று && (r = sshsig_check_allowed_சாவிகள்(allowed_சாவிகள்,
	    sign_சாவி, principal, sig_namespace, verify_time)) != 0) {
		debug3_fr(r, "sshsig_check_allowed_keys");
		செல் done;
	}
	/* success */
	ret = 0;
done:
	எனில் (!quiet) {
		எனில் (ret == 0) {
			எனில் ((fp = sshkey_fingerprint(sign_சாவி, fingerprint_hash,
			    SSH_FP_DEFAULT)) == வெற்று)
				fatal_f("sshkey_fingerprint failed");
			எனில் (principal == வெற்று) {
				printf("Good \"%s\" signature with %s key %s\n",
				    sig_namespace, sshkey_type(sign_சாவி), fp);

			} இல்லையெனில் {
				printf("Good \"%s\" signature for %s with %s key %s\n",
				    sig_namespace, principal,
				    sshkey_type(sign_சாவி), fp);
			}
		} இல்லையெனில் {
			printf("Could not verify signature.\n");
		}
	}
	/* Print the signature key if requested */
	எனில் (ret == 0 && print_pubkey && sign_சாவி != வெற்று) {
		எனில் ((r = sshkey_write(sign_சாவி, stdout)) == 0)
			fputc('\n', stdout);
		இல்லையெனில் {
			error_r(r, "Could not print public key.\n");
			ret = -1;
		}
	}
	sshbuf_free(sigbuf);
	sshbuf_free(abuf);
	sshkey_free(sign_சாவி);
	sshkey_sig_details_free(sig_details);
	விடுவி(fp);
	திரும்பு ret;
}

நிலையான முழு
sig_find_principals(மாறிலி எழுத்து *signature, மாறிலி எழுத்து *allowed_சாவிகள்,
    எழுத்து * மாறிலி *opts, size_t nopts)
{
	முழு r, ret = -1;
	கட்டமைப்பு sshbuf *sigbuf = வெற்று, *abuf = வெற்று;
	கட்டமைப்பு sshkey *sign_சாவி = வெற்று;
	எழுத்து *principals = வெற்று, *cp, *tmp;
	uint64_t verify_time = 0;

	எனில் (sig_process_opts(opts, nopts, வெற்று, &verify_time, வெற்று) != 0)
		செல் done; /* error already logged */

	எனில் ((r = sshbuf_load_file(signature, &abuf)) != 0) {
		error_r(r, "Couldn't read signature file");
		செல் done;
	}
	எனில் ((r = sshsig_dearmor(abuf, &sigbuf)) != 0) {
		error_fr(r, "sshsig_armor");
		செல் done;
	}
	எனில் ((r = sshsig_get_pubkey(sigbuf, &sign_சாவி)) != 0) {
		error_fr(r, "sshsig_get_pubkey");
		செல் done;
	}
	எனில் ((r = sshsig_find_principals(allowed_சாவிகள், sign_சாவி,
	    verify_time, &principals)) != 0) {
		எனில் (r != SSH_ERR_சாவி_NOT_FOUND)
			error_fr(r, "sshsig_find_principal");
		செல் done;
	}
	ret = 0;
done:
	எனில் (ret == 0 ) {
		/* Emit matching principals one per line */
		tmp = principals;
		போது ((cp = strsep(&tmp, ",")) != வெற்று && *cp != '\0')
			puts(cp);
	} இல்லையெனில் {
		fprintf(stderr, "No principal matched.\n");
	}
	sshbuf_free(sigbuf);
	sshbuf_free(abuf);
	sshkey_free(sign_சாவி);
	விடுவி(principals);
	திரும்பு ret;
}

நிலையான முழு
sig_match_principals(மாறிலி எழுத்து *allowed_சாவிகள், எழுத்து *principal,
	எழுத்து * மாறிலி *opts, size_t nopts)
{
	முழு r;
	எழுத்து **principals = வெற்று;
	size_t i, nprincipals = 0;

	எனில் ((r = sig_process_opts(opts, nopts, வெற்று, வெற்று, வெற்று)) != 0)
		திரும்பு r; /* error already logged */

	எனில் ((r = sshsig_match_principals(allowed_சாவிகள், principal,
	    &principals, &nprincipals)) != 0) {
		debug_f("match: %s", ssh_err(r));
		fprintf(stderr, "No principal matched.\n");
		திரும்பு r;
	}
	க்கு (i = 0; i < nprincipals; i++) {
		printf("%s\n", principals[i]);
		விடுவி(principals[i]);
	}
	விடுவி(principals);

	திரும்பு 0;
}

நிலையான வெறுமை
do_moduli_gen(மாறிலி எழுத்து *out_file, எழுத்து **opts, size_t nopts)
{
#ifdef WITH_OPENSSL
	/* Moduli generation/screening */
	BIGNUM *start = வெற்று;
	முழு moduli_bits = 0;
	FILE *out;
	size_t i;
	மாறிலி எழுத்து *errstr, *p;

	/* Parse options */
	க்கு (i = 0; i < nopts; i++) {
		எனில் ((p = strprefix(opts[i], "start=", 0)) != வெற்று) {
			/* XXX - also compare length against bits */
			எனில் (BN_hex2bn(&start, p) == 0)
				fatal("Invalid start point.");
		} இல்லையெனில் எனில் ((p = strprefix(opts[i], "bits=", 0)) != வெற்று) {
			moduli_bits = (முழு)strtonum(p, 1, INT_MAX, &errstr);
			எனில் (errstr) {
				fatal("Invalid number: %s (%s)", p, errstr);
			}
		} இல்லையெனில் {
			fatal("Option \"%s\" is unsupported for moduli "
			    "generation", opts[i]);
		}
	}

	எனில் (strcmp(out_file, "-") == 0)
		out = stdout;
	இல்லையெனில் எனில் ((out = fopen(out_file, "w")) == வெற்று) {
		fatal("Couldn't open modulus candidate file \"%s\": %s",
		    out_file, strerror(errno));
	}
	setvbuf(out, வெற்று, _IOLBF, 0);

	எனில் (moduli_bits == 0)
		moduli_bits = DEFAULT_BITS;
	எனில் (gen_candidates(out, moduli_bits, start) != 0)
		fatal("modulus candidate generation failed");
#இல்லையெனில் /* WITH_OPENSSL */
	fatal("Moduli generation is not supported");
#endif /* WITH_OPENSSL */
}

நிலையான வெறுமை
do_moduli_screen(மாறிலி எழுத்து *out_file, எழுத்து **opts, size_t nopts)
{
#ifdef WITH_OPENSSL
	/* Moduli generation/screening */
	எழுத்து *checkpoint = வெற்று;
	uint32_t generator_wanted = 0;
	unsigned long start_lineno = 0, வரிகள்_to_process = 0;
	முழு பகாஎண்_tests = 0;
	FILE *out, *in = stdin;
	size_t i;
	மாறிலி எழுத்து *errstr, *p;

	/* Parse options */
	க்கு (i = 0; i < nopts; i++) {
		எனில் ((p = strprefix(opts[i], "lines=", 0)) != வெற்று) {
			வரிகள்_to_process = strtoul(p, வெற்று, 10);
		} இல்லையெனில் எனில் ((p = strprefix(opts[i], "start-line=", 0)) != வெற்று) {
			start_lineno = strtoul(p, வெற்று, 10);
		} இல்லையெனில் எனில் ((p = strprefix(opts[i], "checkpoint=", 0)) != வெற்று) {
			விடுவி(checkpoint);
			checkpoint = xstrdup(p);
		} இல்லையெனில் எனில் ((p = strprefix(opts[i], "generator=", 0)) != வெற்று) {
			generator_wanted = (uint32_t)strtonum(p, 1, UINT_MAX,
			    &errstr);
			எனில் (errstr != வெற்று) {
				fatal("Generator invalid: %s (%s)", p, errstr);
			}
		} இல்லையெனில் எனில் ((p = strprefix(opts[i], "prime-tests=", 0)) != வெற்று) {
			பகாஎண்_tests = (முழு)strtonum(p, 1, INT_MAX, &errstr);
			எனில் (errstr) {
				fatal("Invalid number: %s (%s)", p, errstr);
			}
		} இல்லையெனில் {
			fatal("Option \"%s\" is unsupported for moduli "
			    "screening", opts[i]);
		}
	}

	எனில் (have_identity && strcmp(identity_file, "-") != 0) {
		எனில் ((in = fopen(identity_file, "r")) == வெற்று) {
			fatal("Couldn't open modulus candidate "
			    "file \"%s\": %s", identity_file,
			    strerror(errno));
		}
	}

	எனில் (strcmp(out_file, "-") == 0)
		out = stdout;
	இல்லையெனில் எனில் ((out = fopen(out_file, "a")) == வெற்று) {
		fatal("Couldn't open moduli file \"%s\": %s",
		    out_file, strerror(errno));
	}
	setvbuf(out, வெற்று, _IOLBF, 0);
	எனில் (பகாஎண்_test(in, out, பகாஎண்_tests == 0 ? 100 : பகாஎண்_tests,
	    generator_wanted, checkpoint,
	    start_lineno, வரிகள்_to_process) != 0)
		fatal("modulus screening failed");
	எனில் (in != stdin)
		(வெறுமை)fclose(in);
	விடுவி(checkpoint);
#இல்லையெனில் /* WITH_OPENSSL */
	fatal("Moduli screening is not supported");
#endif /* WITH_OPENSSL */
}

/* Read and confirm a passphrase */
நிலையான எழுத்து *
read_check_passphrase(மாறிலி எழுத்து *prompt1, மாறிலி எழுத்து *prompt2,
    மாறிலி எழுத்து *retry_prompt)
{
	எழுத்து *passphrase1, *passphrase2;

	க்கு (;;) {
		passphrase1 = read_passphrase(prompt1, RP_ALLOW_STDIN);
		passphrase2 = read_passphrase(prompt2, RP_ALLOW_STDIN);
		எனில் (strcmp(passphrase1, passphrase2) == 0) {
			freezero(passphrase2, strlen(passphrase2));
			திரும்பு passphrase1;
		}
		/* The passphrases do not match. Clear them and retry. */
		freezero(passphrase1, strlen(passphrase1));
		freezero(passphrase2, strlen(passphrase2));
		fputs(retry_prompt, stdout);
		fputc('\n', stdout);
		fflush(stdout);
	}
	/* NOTREACHED */
	திரும்பு வெற்று;
}

நிலையான எழுத்து *
private_சாவி_passphrase(மாறிலி எழுத்து *path)
{
	எழுத்து *prompt, *ret;

	எனில் (identity_passphrase)
		திரும்பு xstrdup(identity_passphrase);
	எனில் (identity_new_passphrase)
		திரும்பு xstrdup(identity_new_passphrase);

	xasprintf(&prompt, "Enter passphrase for \"%s\" "
	    "(empty for no passphrase): ", path);
	ret = read_check_passphrase(prompt,
	    "Enter same passphrase again: ",
	    "Passphrases do not match.  Try again.");
	விடுவி(prompt);
	திரும்பு ret;
}

நிலையான எழுத்து *
sk_suffix(மாறிலி எழுத்து *application, மாறிலி uint8_t *user, size_t userlen)
{
	எழுத்து *ret, *cp;
	மாறிலி எழுத்து *p;
	size_t slen, i;

	/* Trim off URL-like preamble */
	எனில் ((p = strprefix(application, "ssh://", 0)) != வெற்று)
		ret =  xstrdup(p);
	இல்லையெனில் எனில் ((p = strprefix(application, "ssh:", 0)) != வெற்று)
		ret =  xstrdup(p);
	இல்லையெனில்
		ret = xstrdup(application);

	/* Count trailing zeros in user */
	க்கு (i = 0; i < userlen; i++) {
		எனில் (user[userlen - i - 1] != 0)
			நிறுத்து;
	}
	எனில் (i >= userlen)
		திரும்பு ret; /* user-id was default all-zeros */

	/* Append user-id, escaping non-UTF-8 characters */
	slen = userlen - i;
	எனில் (asmprintf(&cp, INT_MAX, வெற்று, "%.*s", (முழு)slen, user) == -1)
		fatal_f("asmprintf failed");
	/* Don't emit a user-id that contains path or control characters */
	எனில் (strchr(cp, '/') != வெற்று || strstr(cp, "..") != வெற்று ||
	    strchr(cp, '\\') != வெற்று) {
		விடுவி(cp);
		cp = tohex(user, slen);
	}
	xextendf(&ret, "_", "%s", cp);
	விடுவி(cp);
	திரும்பு ret;
}

நிலையான முழு
do_download_sk(மாறிலி எழுத்து *skprovider, மாறிலி எழுத்து *device)
{
	கட்டமைப்பு sshsk_resident_சாவி **srks;
	size_t nsrks, i;
	முழு r, ret = -1;
	எழுத்து *fp, *pin = வெற்று, *pass = வெற்று, *path, *pubpath;
	மாறிலி எழுத்து *ext;
	கட்டமைப்பு sshkey *சாவி;

	எனில் (skprovider == வெற்று)
		fatal("Cannot download keys without provider");

	pin = read_passphrase("Enter PIN for authenticator: ", RP_ALLOW_STDIN);
	எனில் (!quiet) {
		printf("You may need to touch your authenticator "
		    "to authorize key download.\n");
	}
	எனில் ((r = sshsk_load_resident(skprovider, device, pin, 0,
	    &srks, &nsrks)) != 0) {
		எனில் (pin != வெற்று)
			freezero(pin, strlen(pin));
		error_r(r, "Unable to load resident keys");
		திரும்பு -1;
	}
	எனில் (nsrks == 0)
		logit("No keys to download");
	எனில் (pin != வெற்று)
		freezero(pin, strlen(pin));

	க்கு (i = 0; i < nsrks; i++) {
		சாவி = srks[i]->சாவி;
		எனில் (சாவி->type != சாவி_ECDSA_SK && சாவி->type != சாவி_ED25519_SK) {
			error("Unsupported key type %s (%d)",
			    sshkey_type(சாவி), சாவி->type);
			தொடர்;
		}
		எனில் ((fp = sshkey_fingerprint(சாவி, fingerprint_hash,
		    SSH_FP_DEFAULT)) == வெற்று)
			fatal_f("sshkey_fingerprint failed");
		debug_f("key %zu: %s %s %s (flags 0x%02x)", i,
		    sshkey_type(சாவி), fp, சாவி->sk_application, சாவி->sk_flags);
		ext = sk_suffix(சாவி->sk_application,
		    srks[i]->user_id, srks[i]->user_id_len);
		xasprintf(&path, "id_%s_rk%s%s",
		    சாவி->type == சாவி_ECDSA_SK ? "ecdsa_sk" : "ed25519_sk",
		    *ext == '\0' ? "" : "_", ext);

		/* If the file already exists, ask the user to confirm. */
		எனில் (!confirm_overwrite(path)) {
			விடுவி(path);
			நிறுத்து;
		}

		/* Save the key with the application string as the comment */
		எனில் (pass == வெற்று)
			pass = private_சாவி_passphrase(path);
		எனில் ((r = sshkey_save_private(சாவி, path, pass,
		    சாவி->sk_application, private_சாவி_format,
		    openssh_format_cipher, rounds)) != 0) {
			error_r(r, "Saving key \"%s\" failed", path);
			விடுவி(path);
			நிறுத்து;
		}
		எனில் (!quiet) {
			printf("Saved %s key%s%s to %s\n", sshkey_type(சாவி),
			    *ext != '\0' ? " " : "",
			    *ext != '\0' ? சாவி->sk_application : "",
			    path);
		}

		/* Save public key too */
		xasprintf(&pubpath, "%s.pub", path);
		விடுவி(path);
		எனில் ((r = sshkey_save_public(சாவி, pubpath,
		    சாவி->sk_application)) != 0) {
			error_r(r, "Saving public key \"%s\" failed", pubpath);
			விடுவி(pubpath);
			நிறுத்து;
		}
		விடுவி(pubpath);
	}

	எனில் (i >= nsrks)
		ret = 0; /* success */
	எனில் (pass != வெற்று)
		freezero(pass, strlen(pass));
	sshsk_free_resident_சாவிகள்(srks, nsrks);
	திரும்பு ret;
}

நிலையான வெறுமை
save_attestation(கட்டமைப்பு sshbuf *attest, மாறிலி எழுத்து *path)
{
	mode_t omask;
	முழு r;

	எனில் (path == வெற்று)
		திரும்பு; /* nothing to do */
	எனில் (attest == வெற்று || sshbuf_len(attest) == 0)
		fatal("Enrollment did not return attestation data");
	omask = umask(077);
	r = sshbuf_write_file(path, attest);
	umask(omask);
	எனில் (r != 0)
		fatal_r(r, "Unable to write attestation data \"%s\"", path);
	எனில் (!quiet)
		printf("Your FIDO attestation certificate has been saved in "
		    "%s\n", path);
}

நிலையான முழு
confirm_sk_overwrite(மாறிலி எழுத்து *application, மாறிலி எழுத்து *user)
{
	எழுத்து yesno[3];

	printf("A resident key scoped to '%s' with user id '%s' already "
	    "exists.\n", application == வெற்று ? "ssh:" : application,
	    user == வெற்று ? "null" : user);
	printf("Overwrite key in token (y/n)? ");
	fflush(stdout);
	எனில் (fgets(yesno, அளவு(yesno), stdin) == வெற்று)
		திரும்பு 0;
	எனில் (yesno[0] != 'y' && yesno[0] != 'Y')
		திரும்பு 0;
	திரும்பு 1;
}

நிலையான வெறுமை
usage(வெறுமை)
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
முழு
முதன்மை(முழு argc, எழுத்து **argv)
{
	எழுத்து comment[சாவி_COMMENT_MAX], *passphrase = வெற்று;
	எழுத்து *rr_hostname = வெற்று, *ep, *fp, *ra;
	கட்டமைப்பு sshkey *தனிப்பட்ட = வெற்று, *பொது = வெற்று;
	கட்டமைப்பு passwd *pw;
	முழு ret = 0, r, opt, type;
	முழு change_passphrase = 0, change_comment = 0, show_cert = 0;
	முழு find_host = 0, delete_host = 0, hash_hosts = 0;
	முழு gen_all_hostkeys = 0, gen_krl = 0, update_krl = 0, check_krl = 0;
	முழு prefer_agent = 0, convert_to = 0, convert_from = 0;
	முழு print_public = 0, print_generic = 0, cert_serial_autoinc = 0;
	முழு do_gen_candidates = 0, do_screen_candidates = 0, download_sk = 0;
	unsigned long long cert_serial = 0;
	எழுத்து *identity_comment = வெற்று, *ca_சாவி_path = வெற்று, **opts = வெற்று;
	எழுத்து *sk_application = வெற்று, *sk_device = வெற்று, *sk_user = வெற்று;
	எழுத்து *sk_attestation_path = வெற்று;
	கட்டமைப்பு sshbuf *challenge = வெற்று, *attest = வெற்று;
	size_t i, nopts = 0;
	uint32_t bits = 0;
	uint8_t sk_flags = SSH_SK_USER_PRESENCE_REQD;
	மாறிலி எழுத்து *errstr, *p;
	முழு log_level = SYSLOG_LEVEL_INFO;
	எழுத்து *sign_op = வெற்று;

	வெளி முழு optind;
	வெளி எழுத்து *optarg;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	__progname = ssh_get_progname(argv[0]);

	seed_rng();

	log_init(argv[0], SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_USER, 1);

	msetlocale();

	/* we need this for the home * directory.  */
	pw = getpwuid(getuid());
	எனில் (!pw)
		fatal("No user exists for uid %lu", (u_long)getuid());
	pw = pwcopy(pw);
	எனில் (gethostname(hostname, அளவு(hostname)) == -1)
		fatal("gethostname: %s", strerror(errno));

	sk_provider = getenv("SSH_SK_PROVIDER");

	/* Remaining characters: dGjJSTWx */
	போது ((opt = getopt(argc, argv, "ABHKLQUXceghiklopquvy"
	    "C:D:E:F:I:M:N:O:P:R:V:Y:Z:"
	    "a:b:f:g:m:n:r:s:t:w:z:")) != -1) {
		தேர்வு (opt) {
		நிலை 'A':
			gen_all_hostkeys = 1;
			நிறுத்து;
		நிலை 'b':
			bits = (uint32_t)strtonum(optarg, 1, UINT32_MAX,
			    &errstr);
			எனில் (errstr)
				fatal("Bits has bad value %s (%s)",
					optarg, errstr);
			நிறுத்து;
		நிலை 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			எனில் (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			நிறுத்து;
		நிலை 'F':
			find_host = 1;
			rr_hostname = optarg;
			நிறுத்து;
		நிலை 'H':
			hash_hosts = 1;
			நிறுத்து;
		நிலை 'I':
			cert_சாவி_id = optarg;
			நிறுத்து;
		நிலை 'R':
			delete_host = 1;
			rr_hostname = optarg;
			நிறுத்து;
		நிலை 'L':
			show_cert = 1;
			நிறுத்து;
		நிலை 'l':
			print_fingerprint = 1;
			நிறுத்து;
		நிலை 'B':
			print_bubblebabble = 1;
			நிறுத்து;
		நிலை 'm':
			எனில் (strcasecmp(optarg, "RFC4716") == 0 ||
			    strcasecmp(optarg, "ssh2") == 0) {
				convert_format = FMT_RFC4716;
				நிறுத்து;
			}
			எனில் (strcasecmp(optarg, "PKCS8") == 0) {
				convert_format = FMT_PKCS8;
				private_சாவி_format = SSHKEY_PRIVATE_PKCS8;
				நிறுத்து;
			}
			எனில் (strcasecmp(optarg, "PEM") == 0) {
				convert_format = FMT_PEM;
				private_சாவி_format = SSHKEY_PRIVATE_PEM;
				நிறுத்து;
			}
			எனில் (strcasecmp(optarg, "hexdump") == 0) {
				convert_format = FMT_HEXDUMP;
				நிறுத்து;
			}
			fatal("Unsupported conversion format \"%s\"", optarg);
		நிலை 'n':
			cert_principals = optarg;
			நிறுத்து;
		நிலை 'o':
			/* no-op; new format is already the default */
			நிறுத்து;
		நிலை 'p':
			change_passphrase = 1;
			நிறுத்து;
		நிலை 'c':
			change_comment = 1;
			நிறுத்து;
		நிலை 'f':
			எனில் (strlcpy(identity_file, optarg,
			    அளவு(identity_file)) >= அளவு(identity_file))
				fatal("Identity filename too long");
			have_identity = 1;
			நிறுத்து;
		நிலை 'g':
			print_generic = 1;
			நிறுத்து;
		நிலை 'K':
			download_sk = 1;
			நிறுத்து;
		நிலை 'P':
			identity_passphrase = optarg;
			நிறுத்து;
		நிலை 'N':
			identity_new_passphrase = optarg;
			நிறுத்து;
		நிலை 'Q':
			check_krl = 1;
			நிறுத்து;
		நிலை 'O':
			opts = xrecallocarray(opts, nopts, nopts + 1,
			    அளவு(*opts));
			opts[nopts++] = xstrdup(optarg);
			நிறுத்து;
		நிலை 'Z':
			openssh_format_cipher = optarg;
			எனில் (cipher_by_name(openssh_format_cipher) == வெற்று)
				fatal("Invalid OpenSSH-format cipher '%s'",
				    openssh_format_cipher);
			நிறுத்து;
		நிலை 'C':
			identity_comment = optarg;
			நிறுத்து;
		நிலை 'q':
			quiet = 1;
			நிறுத்து;
		நிலை 'e':
			/* export key */
			convert_to = 1;
			நிறுத்து;
		நிலை 'h':
			cert_சாவி_type = SSH2_CERT_TYPE_HOST;
			certflags_flags = 0;
			நிறுத்து;
		நிலை 'k':
			gen_krl = 1;
			நிறுத்து;
		நிலை 'i':
		நிலை 'X':
			/* import key */
			convert_from = 1;
			நிறுத்து;
		நிலை 'y':
			print_public = 1;
			நிறுத்து;
		நிலை 's':
			ca_சாவி_path = optarg;
			நிறுத்து;
		நிலை 't':
			சாவி_type_name = optarg;
			நிறுத்து;
		நிலை 'D':
			pkcs11provider = optarg;
			நிறுத்து;
		நிலை 'U':
			prefer_agent = 1;
			நிறுத்து;
		நிலை 'u':
			update_krl = 1;
			நிறுத்து;
		நிலை 'v':
			எனில் (log_level == SYSLOG_LEVEL_INFO)
				log_level = SYSLOG_LEVEL_DEBUG1;
			இல்லையெனில் {
				எனில் (log_level >= SYSLOG_LEVEL_DEBUG1 &&
				    log_level < SYSLOG_LEVEL_DEBUG3)
					log_level++;
			}
			நிறுத்து;
		நிலை 'r':
			rr_hostname = optarg;
			நிறுத்து;
		நிலை 'a':
			rounds = (முழு)strtonum(optarg, 1, INT_MAX, &errstr);
			எனில் (errstr)
				fatal("Invalid number: %s (%s)",
					optarg, errstr);
			நிறுத்து;
		நிலை 'V':
			parse_cert_times(optarg);
			நிறுத்து;
		நிலை 'Y':
			sign_op = optarg;
			நிறுத்து;
		நிலை 'w':
			sk_provider = optarg;
			நிறுத்து;
		நிலை 'z':
			errno = 0;
			எனில் (*optarg == '+') {
				cert_serial_autoinc = 1;
				optarg++;
			}
			cert_serial = strtoull(optarg, &ep, 10);
			எனில் (*optarg < '0' || *optarg > '9' || *ep != '\0' ||
			    (errno == ERANGE && cert_serial == ULLONG_MAX))
				fatal("Invalid serial number \"%s\"", optarg);
			நிறுத்து;
		நிலை 'M':
			எனில் (strcmp(optarg, "generate") == 0)
				do_gen_candidates = 1;
			இல்லையெனில் எனில் (strcmp(optarg, "screen") == 0)
				do_screen_candidates = 1;
			இல்லையெனில்
				fatal("Unsupported moduli option %s", optarg);
			நிறுத்து;
		இயல்பு:
			usage();
		}
	}

#ifdef ENABLE_SK_INTERNAL
	எனில் (sk_provider == வெற்று)
		sk_provider = "internal";
#endif

	/* reinit */
	log_init(argv[0], log_level, SYSLOG_FACILITY_USER, 1);

	argv += optind;
	argc -= optind;

	எனில் (sign_op != வெற்று) {
		எனில் (strprefix(sign_op, "find-principals", 0) != வெற்று) {
			எனில் (ca_சாவி_path == வெற்று) {
				error("Too few arguments for find-principals:"
				    "missing signature file");
				exit(1);
			}
			எனில் (!have_identity) {
				error("Too few arguments for find-principals:"
				    "missing allowed keys file");
				exit(1);
			}
			ret = sig_find_principals(ca_சாவி_path, identity_file,
			    opts, nopts);
			செல் done;
		} இல்லையெனில் எனில் (strprefix(sign_op, "match-principals", 0) != வெற்று) {
			எனில் (!have_identity) {
				error("Too few arguments for match-principals:"
				    "missing allowed keys file");
				exit(1);
			}
			எனில் (cert_சாவி_id == வெற்று) {
				error("Too few arguments for match-principals: "
				    "missing principal ID");
				exit(1);
			}
			ret = sig_match_principals(identity_file, cert_சாவி_id,
			    opts, nopts);
			செல் done;
		} இல்லையெனில் எனில் (strprefix(sign_op, "sign", 0) != வெற்று) {
			/* NB. cert_principals is actually namespace, via -n */
			எனில் (cert_principals == வெற்று ||
			    *cert_principals == '\0') {
				error("Too few arguments for sign: "
				    "missing namespace");
				exit(1);
			}
			எனில் (!have_identity) {
				error("Too few arguments for sign: "
				    "missing key");
				exit(1);
			}
			ret = sig_sign(identity_file, cert_principals,
			    prefer_agent, argc, argv, opts, nopts);
			செல் done;
		} இல்லையெனில் எனில் (strprefix(sign_op, "check-novalidate", 0) != வெற்று) {
			/* NB. cert_principals is actually namespace, via -n */
			எனில் (cert_principals == வெற்று ||
			    *cert_principals == '\0') {
				error("Too few arguments for check-novalidate: "
				    "missing namespace");
				exit(1);
			}
			எனில் (ca_சாவி_path == வெற்று) {
				error("Too few arguments for check-novalidate: "
				    "missing signature file");
				exit(1);
			}
			ret = sig_verify(ca_சாவி_path, cert_principals,
			    வெற்று, வெற்று, வெற்று, opts, nopts);
			செல் done;
		} இல்லையெனில் எனில் (strprefix(sign_op, "verify", 0) != வெற்று) {
			/* NB. cert_principals is actually namespace, via -n */
			எனில் (cert_principals == வெற்று ||
			    *cert_principals == '\0') {
				error("Too few arguments for verify: "
				    "missing namespace");
				exit(1);
			}
			எனில் (ca_சாவி_path == வெற்று) {
				error("Too few arguments for verify: "
				    "missing signature file");
				exit(1);
			}
			எனில் (!have_identity) {
				error("Too few arguments for sign: "
				    "missing allowed keys file");
				exit(1);
			}
			எனில் (cert_சாவி_id == வெற்று) {
				error("Too few arguments for verify: "
				    "missing principal identity");
				exit(1);
			}
			ret = sig_verify(ca_சாவி_path, cert_principals,
			    cert_சாவி_id, identity_file, rr_hostname,
			    opts, nopts);
			செல் done;
		}
		error("Unsupported operation for -Y: \"%s\"", sign_op);
		usage();
		/* NOTREACHED */
	}

	எனில் (ca_சாவி_path != வெற்று) {
		எனில் (argc < 1 && !gen_krl) {
			error("Too few arguments.");
			usage();
		}
	} இல்லையெனில் எனில் (argc > 0 && !gen_krl && !check_krl &&
	    !do_gen_candidates && !do_screen_candidates) {
		error("Too many arguments.");
		usage();
	}
	எனில் (change_passphrase && change_comment) {
		error("Can only have one of -p and -c.");
		usage();
	}
	எனில் (print_fingerprint && (delete_host || hash_hosts)) {
		error("Cannot use -l with -H or -R.");
		usage();
	}
	எனில் (gen_krl) {
		do_gen_krl(pw, update_krl, ca_சாவி_path,
		    cert_serial, identity_comment, argc, argv);
		செல் done;
	}
	எனில் (check_krl) {
		do_check_krl(pw, print_fingerprint, argc, argv);
		செல் done;
	}
	எனில் (ca_சாவி_path != வெற்று) {
		எனில் (cert_சாவி_id == வெற்று)
			fatal("Must specify key id (-I) when certifying");
		எனில் (cert_principals == வெற்று) {
			/*
			 * Ideally this would be a fatal(), but we need to
			 * be able to generate such certificates for testing
			 * even though they will be rejected.
			 */
			error("Warning: certificate will contain no "
			    "principals (-n)");
		}
		க்கு (i = 0; i < nopts; i++)
			add_cert_option(opts[i]);
		do_ca_sign(pw, ca_சாவி_path, prefer_agent,
		    cert_serial, cert_serial_autoinc, argc, argv);
		செல் done;
	}
	எனில் (show_cert)
		do_show_cert(pw);
	எனில் (delete_host || hash_hosts || find_host) {
		do_known_hosts(pw, rr_hostname, find_host,
		    delete_host, hash_hosts);
	}
	எனில் (pkcs11provider != வெற்று)
		do_download(pw);
	எனில் (download_sk) {
		க்கு (i = 0; i < nopts; i++) {
			எனில் ((p = strprefix(opts[i], "device=", 1)) != வெற்று) {
				sk_device = xstrdup(p);
			} இல்லையெனில் {
				fatal("Option \"%s\" is unsupported for "
				    "FIDO authenticator download", opts[i]);
			}
		}
		ret = do_download_sk(sk_provider, sk_device);
		செல் done;
	}
	எனில் (print_fingerprint || print_bubblebabble)
		do_fingerprint(pw);
	எனில் (change_passphrase)
		do_change_passphrase(pw, opts, nopts);
	எனில் (change_comment)
		do_change_comment(pw, identity_comment);
#ifdef WITH_OPENSSL
	எனில் (convert_to) {
		do_convert_to(pw);
		செல் done;
	}
	எனில் (convert_from) {
		do_convert_from(pw);
		செல் done;
	}
#இல்லையெனில் /* WITH_OPENSSL */
	எனில் (convert_to || convert_from)
		fatal("key conversion disabled at compile time");
#endif /* WITH_OPENSSL */
	எனில் (print_public)
		do_print_public(pw);
	எனில் (rr_hostname != வெற்று) {
		unsigned முழு n = 0;

		எனில் (have_identity) {
			n = do_print_resource_record(pw, identity_file,
			    rr_hostname, print_generic, opts, nopts);
			எனில் (n == 0)
				fatal("%s: %s", identity_file, strerror(errno));
			exit(0);
		} இல்லையெனில் {

			n += do_print_resource_record(pw,
			    PATH_HOST_RSA_சாவி_FILE, rr_hostname,
			    print_generic, opts, nopts);
			n += do_print_resource_record(pw,
			    PATH_HOST_ECDSA_சாவி_FILE, rr_hostname,
			    print_generic, opts, nopts);
			n += do_print_resource_record(pw,
			    PATH_HOST_ED25519_சாவி_FILE, rr_hostname,
			    print_generic, opts, nopts);
			எனில் (n == 0)
				fatal("no keys found.");
			exit(0);
		}
	}

	எனில் (do_gen_candidates || do_screen_candidates) {
		எனில் (argc <= 0)
			fatal("No output file specified");
		இல்லையெனில் எனில் (argc > 1)
			fatal("Too many output files specified");
	}
	எனில் (do_gen_candidates) {
		do_moduli_gen(argv[0], opts, nopts);
		செல் done;
	}
	எனில் (do_screen_candidates) {
		do_moduli_screen(argv[0], opts, nopts);
		செல் done;
	}

	எனில் (gen_all_hostkeys) {
		do_gen_all_hostkeys(pw);
		செல் done;
	}

	எனில் (சாவி_type_name == வெற்று)
		சாவி_type_name = DEFAULT_சாவி_TYPE_NAME;

	type = sshkey_type_from_shortname(சாவி_type_name);
	type_bits_valid(type, சாவி_type_name, &bits);

	எனில் (!quiet)
		printf("Generating public/private %s key pair.\n",
		    சாவி_type_name);
	தேர்வு (type) {
	நிலை சாவி_ECDSA_SK:
	நிலை சாவி_ED25519_SK:
		க்கு (i = 0; i < nopts; i++) {
			எனில் (strcasecmp(opts[i], "no-touch-required") == 0) {
				sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
			} இல்லையெனில் எனில் (strcasecmp(opts[i], "verify-required") == 0) {
				sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
			} இல்லையெனில் எனில் (strcasecmp(opts[i], "resident") == 0) {
				sk_flags |= SSH_SK_RESIDENT_சாவி;
			} இல்லையெனில் எனில் ((p = strprefix(opts[i], "device=", 1))
			    != வெற்று ) {
				sk_device = xstrdup(p);
			} இல்லையெனில் எனில் ((p = strprefix(opts[i], "user=", 1))
			    != வெற்று) {
				sk_user = xstrdup(p);
			} இல்லையெனில் எனில் ((p = strprefix(opts[i], "challenge=", 1))
			    != வெற்று) {
				எனில் ((r = sshbuf_load_file(p,
				    &challenge)) != 0) {
					fatal_r(r, "Unable to load FIDO "
					    "enrollment challenge \"%s\"", p);
				}
			} இல்லையெனில் எனில் (strncasecmp(opts[i],
			    "write-attestation=", 18) == 0) {
				sk_attestation_path = opts[i] + 18;
			} இல்லையெனில் எனில் (strncasecmp(opts[i],
			    "application=", 12) == 0) {
				sk_application = xstrdup(opts[i] + 12);
				எனில் (strncmp(sk_application, "ssh:", 4) != 0) {
					fatal("FIDO application string must "
					    "begin with \"ssh:\"");
				}
			} இல்லையெனில் {
				fatal("Option \"%s\" is unsupported for "
				    "FIDO authenticator enrollment", opts[i]);
			}
		}
		எனில் ((attest = sshbuf_new()) == வெற்று)
			fatal("sshbuf_new failed");
		r = 0;
		க்கு (i = 0 ;;) {
			எனில் (!quiet) {
				printf("You may need to touch your "
				    "authenticator%s to authorize key "
				    "generation.\n",
				    r == 0 ? "" : " again");
			}
			fflush(stdout);
			r = sshsk_enroll(type, sk_provider, sk_device,
			    sk_application == வெற்று ? "ssh:" : sk_application,
			    sk_user, sk_flags, passphrase, challenge,
			    &தனிப்பட்ட, attest);
			எனில் (r == 0)
				நிறுத்து;
			எனில் (r == SSH_ERR_சாவி_BAD_PERMISSIONS &&
			    (sk_flags & SSH_SK_RESIDENT_சாவி) != 0 &&
			    (sk_flags & SSH_SK_FORCE_OPERATION) == 0 &&
			    confirm_sk_overwrite(sk_application, sk_user)) {
				sk_flags |= SSH_SK_FORCE_OPERATION;
				தொடர்;
			}
			எனில் (r != SSH_ERR_சாவி_WRONG_PASSPHRASE)
				fatal_r(r, "Key enrollment failed");
			இல்லையெனில் எனில் (passphrase != வெற்று) {
				error("PIN incorrect");
				freezero(passphrase, strlen(passphrase));
				passphrase = வெற்று;
			}
			எனில் (++i >= 3)
				fatal("Too many incorrect PINs");
			passphrase = read_passphrase("Enter PIN for "
			    "authenticator: ", RP_ALLOW_STDIN);
		}
		எனில் (passphrase != வெற்று) {
			freezero(passphrase, strlen(passphrase));
			passphrase = வெற்று;
		}
		நிறுத்து;
	இயல்பு:
		எனில் ((r = sshkey_generate(type, bits, &தனிப்பட்ட)) != 0)
			fatal("sshkey_generate failed");
		நிறுத்து;
	}
	எனில் ((r = sshkey_from_private(தனிப்பட்ட, &பொது)) != 0)
		fatal_r(r, "sshkey_from_private");

	எனில் (!have_identity)
		ask_filename(pw, "Enter file in which to save the key");

	/* Create ~/.ssh directory if it doesn't already exist. */
	hostfile_create_user_ssh_dir(identity_file, !quiet);

	/* If the file already exists, ask the user to confirm. */
	எனில் (!confirm_overwrite(identity_file))
		exit(1);

	/* Determine the passphrase for the private key */
	passphrase = private_சாவி_passphrase(identity_file);
	எனில் (identity_comment) {
		strlcpy(comment, identity_comment, அளவு(comment));
	} இல்லையெனில் {
		/* Create default comment field for the passphrase. */
		snprintf(comment, அளவு comment, "%s@%s", pw->pw_name, hostname);
	}



	/* Save the key with the given passphrase and comment. */
	எனில் ((r = sshkey_save_private(தனிப்பட்ட, identity_file, passphrase,
	    comment, private_சாவி_format, openssh_format_cipher, rounds)) != 0) {
		error_r(r, "Saving key \"%s\" failed", identity_file);
		freezero(passphrase, strlen(passphrase));
		exit(1);
	}
	freezero(passphrase, strlen(passphrase));
	sshkey_free(தனிப்பட்ட);

	எனில் (!quiet) {
		printf("Your identification has been saved in %s\n",
		    identity_file);
	}

	strlcat(identity_file, ".pub", அளவு(identity_file));
	எனில் ((r = sshkey_save_public(பொது, identity_file, comment)) != 0)
		fatal_r(r, "Unable to save public key to %s", identity_file);

	எனில் (!quiet) {
		fp = sshkey_fingerprint(பொது, fingerprint_hash,
		    SSH_FP_DEFAULT);
		ra = sshkey_fingerprint(பொது, fingerprint_hash,
		    SSH_FP_RANDOMART);
		எனில் (fp == வெற்று || ra == வெற்று)
			fatal("sshkey_fingerprint failed");
		printf("Your public key has been saved in %s\n",
		    identity_file);
		printf("The key fingerprint is:\n");
		printf("%s %s\n", fp, comment);
		printf("The key's randomart image is:\n");
		printf("%s\n", ra);
		விடுவி(ra);
		விடுவி(fp);
	}

	எனில் (sk_attestation_path != வெற்று)
		save_attestation(attest, sk_attestation_path);

 done:
	sshbuf_free(attest);
	sshkey_free(பொது);
	pwfree(pw);
	exit(ret);
}
