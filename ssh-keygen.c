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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/socket.h>
#അന്തര്ഭാവ <sys/stat.h>

#ifdef WITH_OPENSSL
#അന്തര്ഭാവ "openbsd-compat/openssl-compat.h"
#അന്തര്ഭാവ <openssl/bn.h>
#അന്തര്ഭാവ <openssl/evp.h>
#അന്തര്ഭാവ <openssl/pem.h>
#endif

#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <fcntl.h>
#അന്തര്ഭാവ <netdb.h>
#അന്തര്ഭാവ <paths.h>
#അന്തര്ഭാവ <pwd.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <limits.h>
#അന്തര്ഭാവ <locale.h>
#അന്തര്ഭാവ <time.h>

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "authfile.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "pathnames.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "match.h"
#അന്തര്ഭാവ "hostfile.h"
#അന്തര്ഭാവ "dns.h"
#അന്തര്ഭാവ "ssh.h"
#അന്തര്ഭാവ "ssh2.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "atomicio.h"
#അന്തര്ഭാവ "krl.h"
#അന്തര്ഭാവ "digest.h"
#അന്തര്ഭാവ "utf8.h"
#അന്തര്ഭാവ "authfd.h"
#അന്തര്ഭാവ "sshsig.h"
#അന്തര്ഭാവ "ssh-sk.h"
#അന്തര്ഭാവ "sk-api.h" /* XXX for SSH_SK_USER_PRESENCE_REQD; remove */
#അന്തര്ഭാവ "cipher.h"

#ifdef ENABLE_PKCS11
#അന്തര്ഭാവ "ssh-pkcs11.h"
#endif

#define DEFAULT_താക്കോൽ_TYPE_NAME "ed25519"

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

#define താക്കോൽ_COMMENT_MAX		(NI_MAXHOST + 1024)

സ്ഥിതം പൂർണ്ണസംഖ്യ quiet = 0;

/* Flag indicating that we just want to see the key fingerprint */
സ്ഥിതം പൂർണ്ണസംഖ്യ print_fingerprint = 0;
സ്ഥിതം പൂർണ്ണസംഖ്യ print_bubblebabble = 0;

/* Hash algorithm to use for fingerprints. */
സ്ഥിതം പൂർണ്ണസംഖ്യ fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* The identity file name, given on the command line or entered by the user. */
സ്ഥിതം അക്ഷരം identity_file[PATH_MAX];
സ്ഥിതം പൂർണ്ണസംഖ്യ have_identity = 0;

/* This is set to the passphrase if given on the command line. */
സ്ഥിതം അക്ഷരം *identity_passphrase = ശൂന്യ;

/* This is set to the new passphrase if given on the command line. */
സ്ഥിതം അക്ഷരം *identity_new_passphrase = ശൂന്യ;

/* Key type when certifying */
സ്ഥിതം u_int cert_താക്കോൽ_type = SSH2_CERT_TYPE_USER;

/* "key ID" of signed key */
സ്ഥിതം അക്ഷരം *cert_താക്കോൽ_id = ശൂന്യ;

/* Comma-separated list of principal names for certifying keys */
സ്ഥിതം അക്ഷരം *cert_principals = ശൂന്യ;

/* Validity period for certificates */
സ്ഥിതം uint64_t cert_valid_from = 0;
സ്ഥിതം uint64_t cert_valid_to = ~0ULL;

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
സ്ഥിതം uint32_t certflags_flags = CERTOPT_DEFAULT;
സ്ഥിതം അക്ഷരം *certflags_command = ശൂന്യ;
സ്ഥിതം അക്ഷരം *certflags_src_addr = ശൂന്യ;

/* Arbitrary extensions specified by user */
ഘടന cert_ext {
	അക്ഷരം *താക്കോൽ;
	അക്ഷരം *val;
	പൂർണ്ണസംഖ്യ crit;
};
സ്ഥിതം ഘടന cert_ext *cert_ext;
സ്ഥിതം size_t ncert_ext;

/* Conversion to/from various formats */
എണ്ണൽ {
	FMT_RFC4716,
	FMT_PKCS8,
	FMT_PEM,
	FMT_HEXDUMP
} convert_format = FMT_RFC4716;

സ്ഥിതം അക്ഷരം *താക്കോൽ_type_name = ശൂന്യ;

/* Load key from this PKCS#11 provider */
സ്ഥിതം അക്ഷരം *pkcs11provider = ശൂന്യ;

/* FIDO/U2F provider to use */
സ്ഥിതം അക്ഷരം *sk_provider = ശൂന്യ;

/* Format for writing private keys */
സ്ഥിതം പൂർണ്ണസംഖ്യ private_താക്കോൽ_format = SSHKEY_PRIVATE_OPENSSH;

/* Cipher for new-format private keys */
സ്ഥിതം അക്ഷരം *openssh_format_cipher = ശൂന്യ;

/* Number of KDF rounds to derive new format keys. */
സ്ഥിതം പൂർണ്ണസംഖ്യ rounds = 0;

/* argv0 */
ബാഹ്യ അക്ഷരം *__progname;

സ്ഥിതം അക്ഷരം hostname[NI_MAXHOST];

#ifdef WITH_OPENSSL
/* moduli.c */
പൂർണ്ണസംഖ്യ gen_candidates(FILE *, uint32_t, BIGNUM *);
പൂർണ്ണസംഖ്യ അഭാജ്യം_test(FILE *, FILE *, uint32_t, uint32_t, അക്ഷരം *, unsigned long,
    unsigned long);
#endif

സ്ഥിതം ശൂന്യം
type_bits_valid(പൂർണ്ണസംഖ്യ type, സ്ഥിരം അക്ഷരം *name, uint32_t *bitsp)
{
	എങ്കിൽ (type == താക്കോൽ_UNSPEC)
		fatal("unknown key type %s", താക്കോൽ_type_name);
	എങ്കിൽ (*bitsp == 0) {
#ifdef WITH_OPENSSL
		പൂർണ്ണസംഖ്യ nid;

		തിരഞ്ഞെടുപ്പ്(type) {
		അവസ്ഥ താക്കോൽ_ECDSA:
			എങ്കിൽ (name != ശൂന്യ &&
			    (nid = sshkey_ecdsa_nid_from_name(name)) > 0)
				*bitsp = sshkey_curve_nid_to_bits(nid);
			എങ്കിൽ (*bitsp == 0)
				*bitsp = DEFAULT_BITS_ECDSA;
			നിർത്തുക;
		അവസ്ഥ താക്കോൽ_RSA:
			*bitsp = DEFAULT_BITS;
			നിർത്തുക;
		}
#endif
	}
#ifdef WITH_OPENSSL
	തിരഞ്ഞെടുപ്പ് (type) {
	അവസ്ഥ താക്കോൽ_RSA:
		എങ്കിൽ (*bitsp < SSH_RSA_MINIMUM_MODULUS_SIZE)
			fatal("Invalid RSA key length: minimum is %d bits",
			    SSH_RSA_MINIMUM_MODULUS_SIZE);
		അല്ലെങ്കിൽ എങ്കിൽ (*bitsp > OPENSSL_RSA_MAX_MODULUS_BITS)
			fatal("Invalid RSA key length: maximum is %d bits",
			    OPENSSL_RSA_MAX_MODULUS_BITS);
		നിർത്തുക;
	അവസ്ഥ താക്കോൽ_ECDSA:
		എങ്കിൽ (sshkey_ecdsa_bits_to_nid(*bitsp) == -1)
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
സ്ഥിതം പൂർണ്ണസംഖ്യ
confirm_overwrite(സ്ഥിരം അക്ഷരം *filename)
{
	അക്ഷരം yesno[3];
	ഘടന stat st;

	എങ്കിൽ (stat(filename, &st) != 0)
		തിരികെ 1;
	printf("%s already exists.\n", filename);
	printf("Overwrite (y/n)? ");
	fflush(stdout);
	എങ്കിൽ (fgets(yesno, വലുപ്പം(yesno), stdin) == ശൂന്യ)
		തിരികെ 0;
	എങ്കിൽ (yesno[0] != 'y' && yesno[0] != 'Y')
		തിരികെ 0;
	തിരികെ 1;
}

സ്ഥിതം ശൂന്യം
ask_filename(ഘടന passwd *pw, സ്ഥിരം അക്ഷരം *prompt)
{
	അക്ഷരം buf[1024];
	അക്ഷരം *name = ശൂന്യ;

	എങ്കിൽ (താക്കോൽ_type_name == ശൂന്യ)
		name = _PATH_SSH_CLIENT_ID_ED25519;
	അല്ലെങ്കിൽ {
		തിരഞ്ഞെടുപ്പ് (sshkey_type_from_shortname(താക്കോൽ_type_name)) {
		അവസ്ഥ താക്കോൽ_ECDSA_CERT:
		അവസ്ഥ താക്കോൽ_ECDSA:
			name = _PATH_SSH_CLIENT_ID_ECDSA;
			നിർത്തുക;
		അവസ്ഥ താക്കോൽ_ECDSA_SK_CERT:
		അവസ്ഥ താക്കോൽ_ECDSA_SK:
			name = _PATH_SSH_CLIENT_ID_ECDSA_SK;
			നിർത്തുക;
		അവസ്ഥ താക്കോൽ_RSA_CERT:
		അവസ്ഥ താക്കോൽ_RSA:
			name = _PATH_SSH_CLIENT_ID_RSA;
			നിർത്തുക;
		അവസ്ഥ താക്കോൽ_ED25519:
		അവസ്ഥ താക്കോൽ_ED25519_CERT:
			name = _PATH_SSH_CLIENT_ID_ED25519;
			നിർത്തുക;
		അവസ്ഥ താക്കോൽ_ED25519_SK:
		അവസ്ഥ താക്കോൽ_ED25519_SK_CERT:
			name = _PATH_SSH_CLIENT_ID_ED25519_SK;
			നിർത്തുക;
		അവസ്ഥ താക്കോൽ_MLDSA44_ED25519:
		അവസ്ഥ താക്കോൽ_MLDSA44_ED25519_CERT:
			name = _PATH_SSH_CLIENT_ID_MLDSA44_ED25519;
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			fatal("bad key type");
		}
	}
	snprintf(identity_file, വലുപ്പം(identity_file),
	    "%s/%s", pw->pw_dir, name);
	printf("%s (%s): ", prompt, identity_file);
	fflush(stdout);
	എങ്കിൽ (fgets(buf, വലുപ്പം(buf), stdin) == ശൂന്യ)
		exit(1);
	buf[strcspn(buf, "\n")] = '\0';
	എങ്കിൽ (strcmp(buf, "") != 0)
		strlcpy(identity_file, buf, വലുപ്പം(identity_file));
	have_identity = 1;
}

സ്ഥിതം ഘടന sshkey *
load_identity(സ്ഥിരം അക്ഷരം *filename, അക്ഷരം **commentp)
{
	അക്ഷരം *prompt, *pass;
	ഘടന sshkey *prv;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (commentp != ശൂന്യ)
		*commentp = ശൂന്യ;
	എങ്കിൽ ((r = sshkey_load_private(filename, "", &prv, commentp)) == 0)
		തിരികെ prv;
	എങ്കിൽ (r != SSH_ERR_താക്കോൽ_WRONG_PASSPHRASE)
		fatal_r(r, "Load key \"%s\"", filename);
	എങ്കിൽ (identity_passphrase)
		pass = xstrdup(identity_passphrase);
	അല്ലെങ്കിൽ {
		xasprintf(&prompt, "Enter passphrase for \"%s\": ", filename);
		pass = read_passphrase(prompt, RP_ALLOW_STDIN);
		സ്വതന്ത്രം(prompt);
	}
	r = sshkey_load_private(filename, pass, &prv, commentp);
	freezero(pass, strlen(pass));
	എങ്കിൽ (r != 0)
		fatal_r(r, "Load key \"%s\"", filename);
	തിരികെ prv;
}

#define SSH_COM_PUBLIC_BEGIN		"---- BEGIN SSH2 PUBLIC KEY ----"
#define SSH_COM_PUBLIC_END		"---- END SSH2 PUBLIC KEY ----"
#define SSH_COM_PRIVATE_BEGIN		"---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----"
#define	SSH_COM_PRIVATE_താക്കോൽ_MAGIC	0x3f6ff9eb

#ifdef WITH_OPENSSL
സ്ഥിതം ശൂന്യം
do_convert_to_ssh2(ഘടന passwd *pw, ഘടന sshkey *k)
{
	ഘടന sshbuf *b;
	അക്ഷരം comment[61], *b64;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((b = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = sshkey_putb(k, b)) != 0)
		fatal_fr(r, "put key");
	എങ്കിൽ ((b64 = sshbuf_dtob64_string(b, 1)) == ശൂന്യ)
		fatal_f("sshbuf_dtob64_string failed");

	/* Comment + surrounds must fit into 72 chars (RFC 4716 sec 3.3) */
	snprintf(comment, വലുപ്പം(comment),
	    "%u-bit %s, converted by %s@%s from OpenSSH",
	    sshkey_size(k), sshkey_type(k),
	    pw->pw_name, hostname);

	sshkey_free(k);
	sshbuf_free(b);

	fprintf(stdout, "%s\n", SSH_COM_PUBLIC_BEGIN);
	fprintf(stdout, "Comment: \"%s\"\n%s", comment, b64);
	fprintf(stdout, "%s\n", SSH_COM_PUBLIC_END);
	സ്വതന്ത്രം(b64);
}

സ്ഥിതം ശൂന്യം
do_convert_to_pkcs8(ഘടന sshkey *k)
{
	തിരഞ്ഞെടുപ്പ് (sshkey_type_plain(k->type)) {
	അവസ്ഥ താക്കോൽ_RSA:
		എങ്കിൽ (!PEM_write_RSA_PUBKEY(stdout,
		    EVP_PKEY_get0_RSA(k->pkey)))
			fatal("PEM_write_RSA_PUBKEY failed");
		നിർത്തുക;
	അവസ്ഥ താക്കോൽ_ECDSA:
		എങ്കിൽ (!PEM_write_EC_PUBKEY(stdout,
		    EVP_PKEY_get0_EC_താക്കോൽ(k->pkey)))
			fatal("PEM_write_EC_PUBKEY failed");
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		fatal_f("unsupported key type %s", sshkey_type(k));
	}
}

സ്ഥിതം ശൂന്യം
do_convert_to_pem(ഘടന sshkey *k)
{
	തിരഞ്ഞെടുപ്പ് (sshkey_type_plain(k->type)) {
	അവസ്ഥ താക്കോൽ_RSA:
		എങ്കിൽ (!PEM_write_RSAPublic_താക്കോൽ(stdout,
		    EVP_PKEY_get0_RSA(k->pkey)))
			fatal("PEM_write_RSAPublicKey failed");
		നിർത്തുക;
	അവസ്ഥ താക്കോൽ_ECDSA:
		എങ്കിൽ (!PEM_write_EC_PUBKEY(stdout,
		    EVP_PKEY_get0_EC_താക്കോൽ(k->pkey)))
			fatal("PEM_write_EC_PUBKEY failed");
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		fatal_f("unsupported key type %s", sshkey_type(k));
	}
}

സ്ഥിതം ശൂന്യം
do_convert_to_hexdump(ഘടന sshkey *k)
{
	ഘടന sshbuf *b;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((b = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	/* pubkey */
	എങ്കിൽ ((r = sshkey_putb(k, b)) != 0)
		fatal_fr(r, "serialise private");
	printf("Public %s key:\n", sshkey_type(k));
	sshbuf_dump(b, stdout);
	sshbuf_reset(b);
	എങ്കിൽ ((r = sshkey_private_serialize(k, b)) != 0) {
		debug_fr(r, "serialise private");
		പോകുക out;
	}
	printf("\nPrivate %s key:\n", sshkey_type(k));
	sshbuf_dump(b, stdout);
 out:
	sshbuf_free(b);
}

സ്ഥിതം ശൂന്യം
do_convert_to(ഘടന passwd *pw)
{
	ഘടന sshkey *k = ശൂന്യ;
	ഘടന stat st;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	എങ്കിൽ (stat(identity_file, &st) == -1)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));

	/* If we're trying to hexdump, then prefer the private key */
	എങ്കിൽ (convert_format == FMT_HEXDUMP) {
		എങ്കിൽ ((r = sshkey_load_private(identity_file,
		    ശൂന്യ, &k, ശൂന്യ)) != 0 &&
		    r == SSH_ERR_താക്കോൽ_WRONG_PASSPHRASE)
			k = load_identity(identity_file, ശൂന്യ);
	}
	എങ്കിൽ (k == ശൂന്യ && (r = sshkey_load_public(identity_file, &k, ശൂന്യ)) != 0)
		k = load_identity(identity_file, ശൂന്യ);

	തിരഞ്ഞെടുപ്പ് (convert_format) {
	അവസ്ഥ FMT_RFC4716:
		do_convert_to_ssh2(pw, k);
		നിർത്തുക;
	അവസ്ഥ FMT_PKCS8:
		do_convert_to_pkcs8(k);
		നിർത്തുക;
	അവസ്ഥ FMT_PEM:
		do_convert_to_pem(k);
		നിർത്തുക;
	അവസ്ഥ FMT_HEXDUMP:
		do_convert_to_hexdump(k);
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		fatal_f("unknown key format %d", convert_format);
	}
}

/*
 * This is almost exactly the bignum1 encoding, but with 32 bit for length
 * instead of 16.
 */
സ്ഥിതം ശൂന്യം
buffer_get_bignum_bits(ഘടന sshbuf *b, BIGNUM *മൂല്യം)
{
	u_int bytes, bignum_bits;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshbuf_get_u32(b, &bignum_bits)) != 0)
		fatal_fr(r, "parse");
	bytes = (bignum_bits + 7) / 8;
	എങ്കിൽ (sshbuf_len(b) < bytes)
		fatal_f("input buffer too small: need %d have %zu",
		    bytes, sshbuf_len(b));
	എങ്കിൽ (BN_bin2bn(sshbuf_ptr(b), bytes, മൂല്യം) == ശൂന്യ)
		fatal_f("BN_bin2bn failed");
	എങ്കിൽ ((r = sshbuf_consume(b, bytes)) != 0)
		fatal_fr(r, "consume");
}

സ്ഥിതം ഘടന sshkey *
do_convert_private_ssh2(ഘടന sshbuf *b)
{
	ഘടന sshkey *താക്കോൽ = ശൂന്യ;
	അക്ഷരം *type, *cipher;
	സ്ഥിരം അക്ഷരം *alg = ശൂന്യ;
	u_char e1, e2, e3, *sig = ശൂന്യ, data[] = "abcde12345";
	പൂർണ്ണസംഖ്യ r, rlen, ktype;
	u_int magic, i1, i2, i3, i4;
	size_t slen;
	u_long e;
	BIGNUM *rsa_n = ശൂന്യ, *rsa_e = ശൂന്യ, *rsa_d = ശൂന്യ;
	BIGNUM *rsa_p = ശൂന്യ, *rsa_q = ശൂന്യ, *rsa_iqmp = ശൂന്യ;
	BIGNUM *rsa_dmp1 = ശൂന്യ, *rsa_dmq1 = ശൂന്യ;
	RSA *rsa = ശൂന്യ;

	എങ്കിൽ ((r = sshbuf_get_u32(b, &magic)) != 0)
		fatal_fr(r, "parse magic");

	എങ്കിൽ (magic != SSH_COM_PRIVATE_താക്കോൽ_MAGIC) {
		error("bad magic 0x%x != 0x%x", magic,
		    SSH_COM_PRIVATE_താക്കോൽ_MAGIC);
		തിരികെ ശൂന്യ;
	}
	എങ്കിൽ ((r = sshbuf_get_u32(b, &i1)) != 0 ||
	    (r = sshbuf_get_cstring(b, &type, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_cstring(b, &cipher, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_u32(b, &i2)) != 0 ||
	    (r = sshbuf_get_u32(b, &i3)) != 0 ||
	    (r = sshbuf_get_u32(b, &i4)) != 0)
		fatal_fr(r, "parse");
	debug("ignore (%d %d %d %d)", i1, i2, i3, i4);
	എങ്കിൽ (strcmp(cipher, "none") != 0) {
		error("unsupported cipher %s", cipher);
		സ്വതന്ത്രം(cipher);
		സ്വതന്ത്രം(type);
		തിരികെ ശൂന്യ;
	}
	സ്വതന്ത്രം(cipher);

	എങ്കിൽ (strstr(type, "rsa")) {
		ktype = താക്കോൽ_RSA;
	} അല്ലെങ്കിൽ {
		സ്വതന്ത്രം(type);
		തിരികെ ശൂന്യ;
	}
	എങ്കിൽ ((താക്കോൽ = sshkey_new(ktype)) == ശൂന്യ)
		fatal("sshkey_new failed");
	സ്വതന്ത്രം(type);

	തിരഞ്ഞെടുപ്പ് (താക്കോൽ->type) {
	അവസ്ഥ താക്കോൽ_RSA:
		എങ്കിൽ ((r = sshbuf_get_u8(b, &e1)) != 0 ||
		    (e1 < 30 && (r = sshbuf_get_u8(b, &e2)) != 0) ||
		    (e1 < 30 && (r = sshbuf_get_u8(b, &e3)) != 0))
			fatal_fr(r, "parse RSA");
		e = e1;
		debug("e %lx", e);
		എങ്കിൽ (e < 30) {
			e <<= 8;
			e += e2;
			debug("e %lx", e);
			e <<= 8;
			e += e3;
			debug("e %lx", e);
		}
		എങ്കിൽ ((rsa_e = BN_new()) == ശൂന്യ)
			fatal_f("BN_new");
		എങ്കിൽ (!BN_set_word(rsa_e, e)) {
			BN_clear_free(rsa_e);
			sshkey_free(താക്കോൽ);
			തിരികെ ശൂന്യ;
		}
		എങ്കിൽ ((rsa_n = BN_new()) == ശൂന്യ ||
		    (rsa_d = BN_new()) == ശൂന്യ ||
		    (rsa_p = BN_new()) == ശൂന്യ ||
		    (rsa_q = BN_new()) == ശൂന്യ ||
		    (rsa_iqmp = BN_new()) == ശൂന്യ)
			fatal_f("BN_new");
		buffer_get_bignum_bits(b, rsa_d);
		buffer_get_bignum_bits(b, rsa_n);
		buffer_get_bignum_bits(b, rsa_iqmp);
		buffer_get_bignum_bits(b, rsa_q);
		buffer_get_bignum_bits(b, rsa_p);
		എങ്കിൽ ((r = ssh_rsa_complete_crt_parameters(rsa_d, rsa_p, rsa_q,
		    rsa_iqmp, &rsa_dmp1, &rsa_dmq1)) != 0)
			fatal_fr(r, "generate RSA CRT parameters");
		EVP_PKEY_free(താക്കോൽ->pkey);
		എങ്കിൽ ((താക്കോൽ->pkey = EVP_PKEY_new()) == ശൂന്യ)
			fatal_f("EVP_PKEY_new failed");
		എങ്കിൽ ((rsa = RSA_new()) == ശൂന്യ)
			fatal_f("RSA_new failed");
		എങ്കിൽ (!RSA_set0_താക്കോൽ(rsa, rsa_n, rsa_e, rsa_d))
			fatal_f("RSA_set0_key failed");
		rsa_n = rsa_e = rsa_d = ശൂന്യ; /* transferred */
		എങ്കിൽ (!RSA_set0_factors(rsa, rsa_p, rsa_q))
			fatal_f("RSA_set0_factors failed");
		rsa_p = rsa_q = ശൂന്യ; /* transferred */
		എങ്കിൽ (RSA_set0_crt_params(rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp) != 1)
			fatal_f("RSA_set0_crt_params failed");
		rsa_dmp1 = rsa_dmq1 = rsa_iqmp = ശൂന്യ;
		എങ്കിൽ (EVP_PKEY_set1_RSA(താക്കോൽ->pkey, rsa) != 1)
			fatal_f("EVP_PKEY_set1_RSA failed");
		RSA_free(rsa);
		alg = "rsa-sha2-256";
		നിർത്തുക;
	}
	rlen = sshbuf_len(b);
	എങ്കിൽ (rlen != 0)
		error_f("remaining bytes in key blob %d", rlen);

	/* try the key */
	എങ്കിൽ ((r = sshkey_sign(താക്കോൽ, &sig, &slen, data, വലുപ്പം(data),
	    alg, ശൂന്യ, ശൂന്യ, 0)) != 0)
		error_fr(r, "signing with converted key failed");
	അല്ലെങ്കിൽ എങ്കിൽ ((r = sshkey_verify(താക്കോൽ, sig, slen, data, വലുപ്പം(data),
	    alg, 0, ശൂന്യ)) != 0)
		error_fr(r, "verification with converted key failed");
	എങ്കിൽ (r != 0) {
		sshkey_free(താക്കോൽ);
		സ്വതന്ത്രം(sig);
		തിരികെ ശൂന്യ;
	}
	സ്വതന്ത്രം(sig);
	തിരികെ താക്കോൽ;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
get_വരി(FILE *fp, അക്ഷരം *വരി, size_t len)
{
	പൂർണ്ണസംഖ്യ c;
	size_t pos = 0;

	വരി[0] = '\0';
	ആകുമ്പോൾ ((c = fgetc(fp)) != EOF) {
		എങ്കിൽ (pos >= len - 1)
			fatal("input line too long.");
		തിരഞ്ഞെടുപ്പ് (c) {
		അവസ്ഥ '\r':
			c = fgetc(fp);
			എങ്കിൽ (c != EOF && c != '\n' && ungetc(c, fp) == EOF)
				fatal("unget: %s", strerror(errno));
			തിരികെ pos;
		അവസ്ഥ '\n':
			തിരികെ pos;
		}
		വരി[pos++] = c;
		വരി[pos] = '\0';
	}
	/* We reached EOF */
	തിരികെ -1;
}

സ്ഥിതം ശൂന്യം
do_convert_from_ssh2(ഘടന passwd *pw, ഘടന sshkey **k, പൂർണ്ണസംഖ്യ *സ്വകാര്യ)
{
	പൂർണ്ണസംഖ്യ r, blen, escaped = 0;
	u_int len;
	അക്ഷരം വരി[1024];
	ഘടന sshbuf *buf;
	അക്ഷരം encoded[8096];
	FILE *fp;

	എങ്കിൽ ((buf = sshbuf_new()) == ശൂന്യ)
		fatal("sshbuf_new failed");
	എങ്കിൽ ((fp = fopen(identity_file, "r")) == ശൂന്യ)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));
	encoded[0] = '\0';
	ആകുമ്പോൾ ((blen = get_വരി(fp, വരി, വലുപ്പം(വരി))) != -1) {
		എങ്കിൽ (blen > 0 && വരി[blen - 1] == '\\')
			escaped++;
		എങ്കിൽ (strncmp(വരി, "----", 4) == 0 ||
		    strstr(വരി, ": ") != ശൂന്യ) {
			എങ്കിൽ (strstr(വരി, SSH_COM_PRIVATE_BEGIN) != ശൂന്യ)
				*സ്വകാര്യ = 1;
			എങ്കിൽ (strstr(വരി, " END ") != ശൂന്യ) {
				നിർത്തുക;
			}
			/* fprintf(stderr, "ignore: %s", line); */
			തുടരുക;
		}
		എങ്കിൽ (escaped) {
			escaped--;
			/* fprintf(stderr, "escaped: %s", line); */
			തുടരുക;
		}
		strlcat(encoded, വരി, വലുപ്പം(encoded));
	}
	len = strlen(encoded);
	എങ്കിൽ (((len % 4) == 3) &&
	    (encoded[len-1] == '=') &&
	    (encoded[len-2] == '=') &&
	    (encoded[len-3] == '='))
		encoded[len-3] = '\0';
	എങ്കിൽ ((r = sshbuf_b64tod(buf, encoded)) != 0)
		fatal_fr(r, "base64 decode");
	എങ്കിൽ (*സ്വകാര്യ) {
		എങ്കിൽ ((*k = do_convert_private_ssh2(buf)) == ശൂന്യ)
			fatal_f("private key conversion failed");
	} അല്ലെങ്കിൽ എങ്കിൽ ((r = sshkey_fromb(buf, k)) != 0)
		fatal_fr(r, "parse key");
	sshbuf_free(buf);
	fclose(fp);
}

സ്ഥിതം ശൂന്യം
do_convert_from_pkcs8(ഘടന sshkey **k, പൂർണ്ണസംഖ്യ *സ്വകാര്യ)
{
	EVP_PKEY *pubkey;
	FILE *fp;

	എങ്കിൽ ((fp = fopen(identity_file, "r")) == ശൂന്യ)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));
	എങ്കിൽ ((pubkey = PEM_read_PUBKEY(fp, ശൂന്യ, ശൂന്യ, ശൂന്യ)) == ശൂന്യ) {
		fatal_f("%s is not a recognised public key format",
		    identity_file);
	}
	fclose(fp);
	തിരഞ്ഞെടുപ്പ് (EVP_PKEY_base_id(pubkey)) {
	അവസ്ഥ EVP_PKEY_RSA:
		എങ്കിൽ ((*k = sshkey_new(താക്കോൽ_UNSPEC)) == ശൂന്യ)
			fatal("sshkey_new failed");
		(*k)->type = താക്കോൽ_RSA;
		(*k)->pkey = pubkey;
		pubkey = ശൂന്യ;
		നിർത്തുക;
	അവസ്ഥ EVP_PKEY_EC:
		എങ്കിൽ ((*k = sshkey_new(താക്കോൽ_UNSPEC)) == ശൂന്യ)
			fatal("sshkey_new failed");
		എങ്കിൽ (((*k)->ecdsa_nid = sshkey_ecdsa_fixup_group(pubkey)) == -1)
			fatal("sshkey_ecdsa_fixup_group failed");
		(*k)->type = താക്കോൽ_ECDSA;
		(*k)->pkey = pubkey;
		pubkey = ശൂന്യ;
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		fatal_f("unsupported pubkey type %d",
		    EVP_PKEY_base_id(pubkey));
	}
	EVP_PKEY_free(pubkey);
}

സ്ഥിതം ശൂന്യം
do_convert_from_pem(ഘടന sshkey **k, പൂർണ്ണസംഖ്യ *സ്വകാര്യ)
{
	FILE *fp;
	RSA *rsa;

	എങ്കിൽ ((fp = fopen(identity_file, "r")) == ശൂന്യ)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));
	എങ്കിൽ ((rsa = PEM_read_RSAPublic_താക്കോൽ(fp, ശൂന്യ, ശൂന്യ, ശൂന്യ)) != ശൂന്യ) {
		എങ്കിൽ ((*k = sshkey_new(താക്കോൽ_UNSPEC)) == ശൂന്യ)
			fatal("sshkey_new failed");
		എങ്കിൽ (((*k)->pkey = EVP_PKEY_new()) == ശൂന്യ)
			fatal("EVP_PKEY_new failed");
		(*k)->type = താക്കോൽ_RSA;
		എങ്കിൽ (EVP_PKEY_set1_RSA((*k)->pkey, rsa) != 1)
			fatal("EVP_PKEY_set1_RSA failed");
		RSA_free(rsa);
		fclose(fp);
		തിരികെ;
	}
	fatal_f("unrecognised raw private key format");
}

സ്ഥിതം ശൂന്യം
do_convert_from(ഘടന passwd *pw)
{
	ഘടന sshkey *k = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r, സ്വകാര്യ = 0, ok = 0;
	ഘടന stat st;

	എങ്കിൽ (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	എങ്കിൽ (stat(identity_file, &st) == -1)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));

	തിരഞ്ഞെടുപ്പ് (convert_format) {
	അവസ്ഥ FMT_RFC4716:
		do_convert_from_ssh2(pw, &k, &സ്വകാര്യ);
		നിർത്തുക;
	അവസ്ഥ FMT_PKCS8:
		do_convert_from_pkcs8(&k, &സ്വകാര്യ);
		നിർത്തുക;
	അവസ്ഥ FMT_PEM:
		do_convert_from_pem(&k, &സ്വകാര്യ);
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		fatal_f("unknown key format %d", convert_format);
	}

	എങ്കിൽ (!സ്വകാര്യ) {
		എങ്കിൽ ((r = sshkey_write(k, stdout)) == 0)
			ok = 1;
		എങ്കിൽ (ok)
			fprintf(stdout, "\n");
	} അല്ലെങ്കിൽ {
		തിരഞ്ഞെടുപ്പ് (k->type) {
		അവസ്ഥ താക്കോൽ_ECDSA:
			ok = PEM_write_ECPrivate_താക്കോൽ(stdout,
			    EVP_PKEY_get0_EC_താക്കോൽ(k->pkey), ശൂന്യ, ശൂന്യ, 0,
			    ശൂന്യ, ശൂന്യ);
			നിർത്തുക;
		അവസ്ഥ താക്കോൽ_RSA:
			ok = PEM_write_RSAPrivate_താക്കോൽ(stdout,
			    EVP_PKEY_get0_RSA(k->pkey), ശൂന്യ, ശൂന്യ, 0,
			    ശൂന്യ, ശൂന്യ);
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			fatal_f("unsupported key type %s", sshkey_type(k));
		}
	}

	എങ്കിൽ (!ok)
		fatal("key write failed");
	sshkey_free(k);
}
#endif

സ്ഥിതം ശൂന്യം
do_print_public(ഘടന passwd *pw)
{
	ഘടന sshkey *prv;
	ഘടന stat st;
	പൂർണ്ണസംഖ്യ r;
	അക്ഷരം *comment = ശൂന്യ;

	എങ്കിൽ (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	എങ്കിൽ (stat(identity_file, &st) == -1)
		fatal("%s: %s", identity_file, strerror(errno));
	prv = load_identity(identity_file, &comment);
	എങ്കിൽ ((r = sshkey_write(prv, stdout)) != 0)
		fatal_fr(r, "write key");
	എങ്കിൽ (comment != ശൂന്യ && *comment != '\0')
		fprintf(stdout, " %s", comment);
	fprintf(stdout, "\n");
	എങ്കിൽ (sshkey_is_sk(prv)) {
		debug("sk_application: \"%s\", sk_flags 0x%02x",
			prv->sk_application, prv->sk_flags);
	}
	sshkey_free(prv);
	സ്വതന്ത്രം(comment);
	exit(0);
}

സ്ഥിതം ശൂന്യം
do_download(ഘടന passwd *pw)
{
#ifdef ENABLE_PKCS11
	ഘടന sshkey **താക്കോലുകൾ = ശൂന്യ;
	പൂർണ്ണസംഖ്യ i, nkeys;
	എണ്ണൽ sshkey_fp_rep rep;
	പൂർണ്ണസംഖ്യ fptype;
	അക്ഷരം *fp, *ra, **comments = ശൂന്യ;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;

	pkcs11_init(1);
	nkeys = pkcs11_add_provider(pkcs11provider, ശൂന്യ, &താക്കോലുകൾ, &comments);
	എങ്കിൽ (nkeys <= 0)
		fatal("cannot read public key from pkcs11");
	വേണ്ടി (i = 0; i < nkeys; i++) {
		എങ്കിൽ (print_fingerprint) {
			fp = sshkey_fingerprint(താക്കോലുകൾ[i], fptype, rep);
			ra = sshkey_fingerprint(താക്കോലുകൾ[i], fingerprint_hash,
			    SSH_FP_RANDOMART);
			എങ്കിൽ (fp == ശൂന്യ || ra == ശൂന്യ)
				fatal_f("sshkey_fingerprint fail");
			printf("%u %s %s (PKCS11 key)\n", sshkey_size(താക്കോലുകൾ[i]),
			    fp, sshkey_type(താക്കോലുകൾ[i]));
			എങ്കിൽ (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
				printf("%s\n", ra);
			സ്വതന്ത്രം(ra);
			സ്വതന്ത്രം(fp);
		} അല്ലെങ്കിൽ {
			(ശൂന്യം) sshkey_write(താക്കോലുകൾ[i], stdout); /* XXX check */
			fprintf(stdout, "%s%s\n",
			    *(comments[i]) == '\0' ? "" : " ", comments[i]);
		}
		സ്വതന്ത്രം(comments[i]);
		sshkey_free(താക്കോലുകൾ[i]);
	}
	സ്വതന്ത്രം(comments);
	സ്വതന്ത്രം(താക്കോലുകൾ);
	pkcs11_terminate();
	exit(0);
#അല്ലെങ്കിൽ
	fatal("no pkcs11 support");
#endif /* ENABLE_PKCS11 */
}

സ്ഥിതം ഘടന sshkey *
try_read_താക്കോൽ(അക്ഷരം **cpp)
{
	ഘടന sshkey *ret;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((ret = sshkey_new(താക്കോൽ_UNSPEC)) == ശൂന്യ)
		fatal("sshkey_new failed");
	എങ്കിൽ ((r = sshkey_read(ret, cpp)) == 0)
		തിരികെ ret;
	/* Not a key */
	sshkey_free(ret);
	തിരികെ ശൂന്യ;
}

സ്ഥിതം ശൂന്യം
fingerprint_one_താക്കോൽ(സ്ഥിരം ഘടന sshkey *പൊതു, സ്ഥിരം അക്ഷരം *comment)
{
	അക്ഷരം *fp = ശൂന്യ, *ra = ശൂന്യ;
	എണ്ണൽ sshkey_fp_rep rep;
	പൂർണ്ണസംഖ്യ fptype;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;
	fp = sshkey_fingerprint(പൊതു, fptype, rep);
	ra = sshkey_fingerprint(പൊതു, fingerprint_hash, SSH_FP_RANDOMART);
	എങ്കിൽ (fp == ശൂന്യ || ra == ശൂന്യ)
		fatal_f("sshkey_fingerprint failed");
	mprintf("%u %s %s (%s)\n", sshkey_size(പൊതു), fp,
	    comment ? comment : "no comment", sshkey_type(പൊതു));
	എങ്കിൽ (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
		printf("%s\n", ra);
	സ്വതന്ത്രം(ra);
	സ്വതന്ത്രം(fp);
}

സ്ഥിതം ശൂന്യം
fingerprint_private(സ്ഥിരം അക്ഷരം *path)
{
	ഘടന stat st;
	അക്ഷരം *comment = ശൂന്യ;
	ഘടന sshkey *privkey = ശൂന്യ, *pubkey = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (stat(identity_file, &st) == -1)
		fatal("%s: %s", path, strerror(errno));
	എങ്കിൽ ((r = sshkey_load_public(path, &pubkey, &comment)) != 0)
		debug_r(r, "load public \"%s\"", path);
	എങ്കിൽ (pubkey == ശൂന്യ || comment == ശൂന്യ || *comment == '\0') {
		സ്വതന്ത്രം(comment);
		എങ്കിൽ ((r = sshkey_load_private(path, ശൂന്യ,
		    &privkey, &comment)) != 0)
			debug_r(r, "load private \"%s\"", path);
	}
	എങ്കിൽ (pubkey == ശൂന്യ && privkey == ശൂന്യ)
		fatal("%s is not a key file.", path);

	fingerprint_one_താക്കോൽ(pubkey == ശൂന്യ ? privkey : pubkey, comment);
	sshkey_free(pubkey);
	sshkey_free(privkey);
	സ്വതന്ത്രം(comment);
}

സ്ഥിതം ശൂന്യം
do_fingerprint(ഘടന passwd *pw)
{
	FILE *f;
	ഘടന sshkey *പൊതു = ശൂന്യ;
	അക്ഷരം *comment = ശൂന്യ, *cp, *ep, *വരി = ശൂന്യ;
	size_t linesize = 0;
	പൂർണ്ണസംഖ്യ i, invalid = 1;
	സ്ഥിരം അക്ഷരം *path;
	u_long lnum = 0;

	എങ്കിൽ (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	path = identity_file;

	എങ്കിൽ (strcmp(identity_file, "-") == 0) {
		f = stdin;
		path = "(stdin)";
	} അല്ലെങ്കിൽ എങ്കിൽ ((f = fopen(path, "r")) == ശൂന്യ)
		fatal("%s: %s: %s", __progname, path, strerror(errno));

	ആകുമ്പോൾ (getline(&വരി, &linesize, f) != -1) {
		lnum++;
		cp = വരി;
		cp[strcspn(cp, "\r\n")] = '\0';
		/* Trim leading space and comments */
		cp = വരി + strspn(വരി, " \t");
		എങ്കിൽ (*cp == '#' || *cp == '\0')
			തുടരുക;

		/*
		 * Input may be plain keys, private keys, authorized_keys
		 * or known_hosts.
		 */

		/*
		 * Try private keys first. Assume a key is private if
		 * "SSH PRIVATE KEY" appears on the first line and we're
		 * not reading from stdin (XXX support private keys on stdin).
		 */
		എങ്കിൽ (lnum == 1 && strcmp(identity_file, "-") != 0 &&
		    strstr(cp, "PRIVATE KEY") != ശൂന്യ) {
			സ്വതന്ത്രം(വരി);
			fclose(f);
			fingerprint_private(path);
			exit(0);
		}

		/*
		 * If it's not a private key, then this must be prepared to
		 * accept a public key prefixed with a hostname or options.
		 * Try a bare key first, otherwise skip the leading stuff.
		 */
		comment = ശൂന്യ;
		എങ്കിൽ ((പൊതു = try_read_താക്കോൽ(&cp)) == ശൂന്യ) {
			i = strtol(cp, &ep, 10);
			എങ്കിൽ (i == 0 || ep == ശൂന്യ ||
			    (*ep != ' ' && *ep != '\t')) {
				പൂർണ്ണസംഖ്യ quoted = 0;

				comment = cp;
				വേണ്ടി (; *cp && (quoted || (*cp != ' ' &&
				    *cp != '\t')); cp++) {
					എങ്കിൽ (*cp == '\\' && cp[1] == '"')
						cp++;	/* Skip both */
					അല്ലെങ്കിൽ എങ്കിൽ (*cp == '"')
						quoted = !quoted;
				}
				എങ്കിൽ (!*cp)
					തുടരുക;
				*cp++ = '\0';
			}
		}
		/* Retry after parsing leading hostname/key options */
		എങ്കിൽ (പൊതു == ശൂന്യ && (പൊതു = try_read_താക്കോൽ(&cp)) == ശൂന്യ) {
			debug("%s:%lu: not a public key", path, lnum);
			തുടരുക;
		}

		/* Find trailing comment, if any */
		വേണ്ടി (; *cp == ' ' || *cp == '\t'; cp++)
			;
		എങ്കിൽ (*cp != '\0' && *cp != '#')
			comment = cp;

		fingerprint_one_താക്കോൽ(പൊതു, comment);
		sshkey_free(പൊതു);
		invalid = 0; /* One good key in the file is sufficient */
	}
	fclose(f);
	സ്വതന്ത്രം(വരി);

	എങ്കിൽ (invalid)
		fatal("%s is not a public key file.", path);
	exit(0);
}

സ്ഥിതം ശൂന്യം
do_gen_all_hostkeys(ഘടന passwd *pw)
{
	ഘടന {
		അക്ഷരം *താക്കോൽ_type;
		അക്ഷരം *താക്കോൽ_type_display;
		അക്ഷരം *path;
	} താക്കോൽ_types[] = {
#ifdef WITH_OPENSSL
		{ "rsa", "RSA" ,PATH_HOST_RSA_താക്കോൽ_FILE },
		{ "ecdsa", "ECDSA",PATH_HOST_ECDSA_താക്കോൽ_FILE },
#endif /* WITH_OPENSSL */
		{ "ed25519", "ED25519",PATH_HOST_ED25519_താക്കോൽ_FILE },
#ifdef USE_MLDSA
		{ "mldsa44-ed25519", "MLDSA44-ED25519",
		     PATH_HOST_MLDSA44_ED25519_താക്കോൽ_FILE },
#endif
		{ ശൂന്യ, ശൂന്യ, ശൂന്യ }
	};

	uint32_t bits = 0;
	പൂർണ്ണസംഖ്യ first = 0;
	ഘടന stat st;
	ഘടന sshkey *സ്വകാര്യ, *പൊതു;
	അക്ഷരം comment[താക്കോൽ_COMMENT_MAX], *prv_tmp, *pub_tmp, *prv_file, *pub_file;
	പൂർണ്ണസംഖ്യ i, type, fd, r;

	വേണ്ടി (i = 0; താക്കോൽ_types[i].താക്കോൽ_type; i++) {
		പൊതു = സ്വകാര്യ = ശൂന്യ;
		prv_tmp = pub_tmp = prv_file = pub_file = ശൂന്യ;

		xasprintf(&prv_file, "%s%s",
		    identity_file, താക്കോൽ_types[i].path);

		/* Check whether private key exists and is not zero-length */
		എങ്കിൽ (stat(prv_file, &st) == 0) {
			എങ്കിൽ (st.st_size != 0)
				പോകുക next;
		} അല്ലെങ്കിൽ എങ്കിൽ (errno != ENOENT) {
			error("Could not stat %s: %s", താക്കോൽ_types[i].path,
			    strerror(errno));
			പോകുക failnext;
		}

		/*
		 * Private key doesn't exist or is invalid; proceed with
		 * key generation.
		 */
		xasprintf(&prv_tmp, "%s%s.XXXXXXXXXX",
		    identity_file, താക്കോൽ_types[i].path);
		xasprintf(&pub_tmp, "%s%s.pub.XXXXXXXXXX",
		    identity_file, താക്കോൽ_types[i].path);
		xasprintf(&pub_file, "%s%s.pub",
		    identity_file, താക്കോൽ_types[i].path);

		എങ്കിൽ (first == 0) {
			first = 1;
			printf("%s: generating new host keys: ", __progname);
		}
		printf("%s ", താക്കോൽ_types[i].താക്കോൽ_type_display);
		fflush(stdout);
		type = sshkey_type_from_shortname(താക്കോൽ_types[i].താക്കോൽ_type);
		എങ്കിൽ ((fd = mkstemp(prv_tmp)) == -1) {
			error("Could not save your private key in %s: %s",
			    prv_tmp, strerror(errno));
			പോകുക failnext;
		}
		(ശൂന്യം)close(fd); /* just using mkstemp() to reserve a name */
		bits = 0;
		type_bits_valid(type, ശൂന്യ, &bits);
		എങ്കിൽ ((r = sshkey_generate(type, bits, &സ്വകാര്യ)) != 0) {
			error_r(r, "sshkey_generate failed");
			പോകുക failnext;
		}
		എങ്കിൽ ((r = sshkey_from_private(സ്വകാര്യ, &പൊതു)) != 0)
			fatal_fr(r, "sshkey_from_private");
		snprintf(comment, വലുപ്പം comment, "%s@%s", pw->pw_name,
		    hostname);
		എങ്കിൽ ((r = sshkey_save_private(സ്വകാര്യ, prv_tmp, "",
		    comment, private_താക്കോൽ_format, openssh_format_cipher,
		    rounds)) != 0) {
			error_r(r, "Saving key \"%s\" failed", prv_tmp);
			പോകുക failnext;
		}
		എങ്കിൽ ((fd = mkstemp(pub_tmp)) == -1) {
			error("Could not save your public key in %s: %s",
			    pub_tmp, strerror(errno));
			പോകുക failnext;
		}
		(ശൂന്യം)fchmod(fd, 0644);
		(ശൂന്യം)close(fd);
		എങ്കിൽ ((r = sshkey_save_public(പൊതു, pub_tmp, comment)) != 0) {
			error_r(r, "Unable to save public key to %s",
			    identity_file);
			പോകുക failnext;
		}

		/* Rename temporary files to their permanent locations. */
		എങ്കിൽ (rename(pub_tmp, pub_file) != 0) {
			error("Unable to move %s into position: %s",
			    pub_file, strerror(errno));
			പോകുക failnext;
		}
		എങ്കിൽ (rename(prv_tmp, prv_file) != 0) {
			error("Unable to move %s into position: %s",
			    താക്കോൽ_types[i].path, strerror(errno));
 failnext:
			first = 0;
			പോകുക next;
		}
 next:
		sshkey_free(സ്വകാര്യ);
		sshkey_free(പൊതു);
		സ്വതന്ത്രം(prv_tmp);
		സ്വതന്ത്രം(pub_tmp);
		സ്വതന്ത്രം(prv_file);
		സ്വതന്ത്രം(pub_file);
	}
	എങ്കിൽ (first != 0)
		printf("\n");
}

ഘടന known_hosts_ctx {
	സ്ഥിരം അക്ഷരം *host;	/* Hostname searched for in find/delete case */
	FILE *out;		/* Output file, stdout for find_hosts case */
	പൂർണ്ണസംഖ്യ has_unhashed;	/* When hashing, original had unhashed hosts */
	പൂർണ്ണസംഖ്യ found_താക്കോൽ;		/* For find/delete, host was found */
	പൂർണ്ണസംഖ്യ invalid;		/* File contained invalid items; don't delete */
	പൂർണ്ണസംഖ്യ hash_hosts;		/* Hash hostnames as we go */
	പൂർണ്ണസംഖ്യ find_host;		/* Search for specific hostname */
	പൂർണ്ണസംഖ്യ delete_host;	/* Delete host from known_hosts */
};

സ്ഥിതം പൂർണ്ണസംഖ്യ
known_hosts_hash(ഘടന hostkey_foreach_വരി *l, ശൂന്യം *_ctx)
{
	ഘടന known_hosts_ctx *ctx = (ഘടന known_hosts_ctx *)_ctx;
	അക്ഷരം *hashed, *cp, *hosts, *ohosts;
	പൂർണ്ണസംഖ്യ has_wild = l->hosts && strcspn(l->hosts, "*?!") != strlen(l->hosts);
	പൂർണ്ണസംഖ്യ was_hashed = l->hosts && l->hosts[0] == HASH_DELIM;

	തിരഞ്ഞെടുപ്പ് (l->status) {
	അവസ്ഥ HKF_STATUS_OK:
	അവസ്ഥ HKF_STATUS_MATCHED:
		/*
		 * Don't hash hosts already hashed, with wildcard
		 * characters or a CA/revocation marker.
		 */
		എങ്കിൽ (was_hashed || has_wild || l->marker != MRK_NONE) {
			fprintf(ctx->out, "%s\n", l->വരി);
			എങ്കിൽ (has_wild && !ctx->find_host) {
				logit("%s:%lu: ignoring host name "
				    "with wildcard: %.64s", l->path,
				    l->linenum, l->hosts);
			}
			തിരികെ 0;
		}
		/*
		 * Split any comma-separated hostnames from the host list,
		 * hash and store separately.
		 */
		ohosts = hosts = xstrdup(l->hosts);
		ആകുമ്പോൾ ((cp = strsep(&hosts, ",")) != ശൂന്യ && *cp != '\0') {
			lowercase(cp);
			എങ്കിൽ ((hashed = host_hash(cp, ശൂന്യ, 0)) == ശൂന്യ)
				fatal("hash_host failed");
			fprintf(ctx->out, "%s %s\n", hashed, l->rawkey);
			സ്വതന്ത്രം(hashed);
			ctx->has_unhashed = 1;
		}
		സ്വതന്ത്രം(ohosts);
		തിരികെ 0;
	അവസ്ഥ HKF_STATUS_INVALID:
		/* Retain invalid lines, but mark file as invalid. */
		ctx->invalid = 1;
		logit("%s:%lu: invalid line", l->path, l->linenum);
		/* FALLTHROUGH */
	സ്ഥിരസ്ഥിതി:
		fprintf(ctx->out, "%s\n", l->വരി);
		തിരികെ 0;
	}
	/* NOTREACHED */
	തിരികെ -1;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
known_hosts_find_delete(ഘടന hostkey_foreach_വരി *l, ശൂന്യം *_ctx)
{
	ഘടന known_hosts_ctx *ctx = (ഘടന known_hosts_ctx *)_ctx;
	എണ്ണൽ sshkey_fp_rep rep;
	പൂർണ്ണസംഖ്യ fptype;
	അക്ഷരം *fp = ശൂന്യ, *ra = ശൂന്യ;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;

	എങ്കിൽ (l->status == HKF_STATUS_MATCHED) {
		എങ്കിൽ (ctx->delete_host) {
			എങ്കിൽ (l->marker != MRK_NONE) {
				/* Don't remove CA and revocation lines */
				fprintf(ctx->out, "%s\n", l->വരി);
			} അല്ലെങ്കിൽ {
				/*
				 * Hostname matches and has no CA/revoke
				 * marker, delete it by *not* writing the
				 * line to ctx->out.
				 */
				ctx->found_താക്കോൽ = 1;
				എങ്കിൽ (!quiet)
					printf("# Host %s found: line %lu\n",
					    ctx->host, l->linenum);
			}
			തിരികെ 0;
		} അല്ലെങ്കിൽ എങ്കിൽ (ctx->find_host) {
			ctx->found_താക്കോൽ = 1;
			എങ്കിൽ (!quiet) {
				printf("# Host %s found: line %lu %s\n",
				    ctx->host,
				    l->linenum, l->marker == MRK_CA ? "CA" :
				    (l->marker == MRK_REVOKE ? "REVOKED" : ""));
			}
			എങ്കിൽ (ctx->hash_hosts)
				known_hosts_hash(l, ctx);
			അല്ലെങ്കിൽ എങ്കിൽ (print_fingerprint) {
				fp = sshkey_fingerprint(l->താക്കോൽ, fptype, rep);
				ra = sshkey_fingerprint(l->താക്കോൽ,
				    fingerprint_hash, SSH_FP_RANDOMART);
				എങ്കിൽ (fp == ശൂന്യ || ra == ശൂന്യ)
					fatal_f("sshkey_fingerprint failed");
				mprintf("%s %s %s%s%s\n", ctx->host,
				    sshkey_type(l->താക്കോൽ), fp,
				    l->comment[0] ? " " : "",
				    l->comment);
				എങ്കിൽ (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
					printf("%s\n", ra);
				സ്വതന്ത്രം(ra);
				സ്വതന്ത്രം(fp);
			} അല്ലെങ്കിൽ
				fprintf(ctx->out, "%s\n", l->വരി);
			തിരികെ 0;
		}
	} അല്ലെങ്കിൽ എങ്കിൽ (ctx->delete_host) {
		/* Retain non-matching hosts when deleting */
		എങ്കിൽ (l->status == HKF_STATUS_INVALID) {
			ctx->invalid = 1;
			logit("%s:%lu: invalid line", l->path, l->linenum);
		}
		fprintf(ctx->out, "%s\n", l->വരി);
	}
	തിരികെ 0;
}

സ്ഥിതം ശൂന്യം
do_known_hosts(ഘടന passwd *pw, സ്ഥിരം അക്ഷരം *name, പൂർണ്ണസംഖ്യ find_host,
    പൂർണ്ണസംഖ്യ delete_host, പൂർണ്ണസംഖ്യ hash_hosts)
{
	അക്ഷരം *cp, tmp[PATH_MAX], old[PATH_MAX];
	പൂർണ്ണസംഖ്യ r, fd, oerrno, inplace = 0;
	ഘടന known_hosts_ctx ctx;
	u_int foreach_options;
	ഘടന stat sb;

	എങ്കിൽ (!have_identity) {
		cp = tilde_expand_filename(_PATH_SSH_USER_HOSTFILE, pw->pw_uid);
		എങ്കിൽ (strlcpy(identity_file, cp, വലുപ്പം(identity_file)) >=
		    വലുപ്പം(identity_file))
			fatal("Specified known hosts path too long");
		സ്വതന്ത്രം(cp);
		have_identity = 1;
	}
	എങ്കിൽ (stat(identity_file, &sb) != 0)
		fatal("Cannot stat %s: %s", identity_file, strerror(errno));

	memset(&ctx, 0, വലുപ്പം(ctx));
	ctx.out = stdout;
	ctx.host = name;
	ctx.hash_hosts = hash_hosts;
	ctx.find_host = find_host;
	ctx.delete_host = delete_host;

	/*
	 * Find hosts goes to stdout, hash and deletions happen in-place
	 * A corner case is ssh-keygen -HF foo, which should go to stdout
	 */
	എങ്കിൽ (!find_host && (hash_hosts || delete_host)) {
		എങ്കിൽ (strlcpy(tmp, identity_file, വലുപ്പം(tmp)) >= വലുപ്പം(tmp) ||
		    strlcat(tmp, ".XXXXXXXXXX", വലുപ്പം(tmp)) >= വലുപ്പം(tmp) ||
		    strlcpy(old, identity_file, വലുപ്പം(old)) >= വലുപ്പം(old) ||
		    strlcat(old, ".old", വലുപ്പം(old)) >= വലുപ്പം(old))
			fatal("known_hosts path too long");
		umask(077);
		എങ്കിൽ ((fd = mkstemp(tmp)) == -1)
			fatal("mkstemp: %s", strerror(errno));
		എങ്കിൽ ((ctx.out = fdopen(fd, "w")) == ശൂന്യ) {
			oerrno = errno;
			unlink(tmp);
			fatal("fdopen: %s", strerror(oerrno));
		}
		(ശൂന്യം)fchmod(fd, sb.st_mode & 0644);
		inplace = 1;
	}
	/* XXX support identity_file == "-" for stdin */
	foreach_options = find_host ? HKF_WANT_MATCH : 0;
	foreach_options |= print_fingerprint ? HKF_WANT_PARSE_താക്കോൽ : 0;
	എങ്കിൽ ((r = hostkeys_foreach(identity_file, (find_host || !hash_hosts) ?
	    known_hosts_find_delete : known_hosts_hash, &ctx, name, ശൂന്യ,
	    foreach_options, 0)) != 0) {
		എങ്കിൽ (inplace)
			unlink(tmp);
		fatal_fr(r, "hostkeys_foreach");
	}

	എങ്കിൽ (inplace)
		fclose(ctx.out);

	എങ്കിൽ (ctx.invalid) {
		error("%s is not a valid known_hosts file.", identity_file);
		എങ്കിൽ (inplace) {
			error("Not replacing existing known_hosts "
			    "file because of errors");
			unlink(tmp);
		}
		exit(1);
	} അല്ലെങ്കിൽ എങ്കിൽ (delete_host && !ctx.found_താക്കോൽ) {
		logit("Host %s not found in %s", name, identity_file);
		എങ്കിൽ (inplace)
			unlink(tmp);
	} അല്ലെങ്കിൽ എങ്കിൽ (inplace) {
		/* Backup existing file */
		എങ്കിൽ (unlink(old) == -1 && errno != ENOENT)
			fatal("unlink %.100s: %s", old, strerror(errno));
		എങ്കിൽ (link(identity_file, old) == -1)
			fatal("link %.100s to %.100s: %s", identity_file, old,
			    strerror(errno));
		/* Move new one into place */
		എങ്കിൽ (rename(tmp, identity_file) == -1) {
			error("rename\"%s\" to \"%s\": %s", tmp, identity_file,
			    strerror(errno));
			unlink(tmp);
			unlink(old);
			exit(1);
		}

		printf("%s updated.\n", identity_file);
		printf("Original contents retained as %s\n", old);
		എങ്കിൽ (ctx.has_unhashed) {
			logit("WARNING: %s contains unhashed entries", old);
			logit("Delete this file to ensure privacy "
			    "of hostnames");
		}
	}

	exit (find_host && !ctx.found_താക്കോൽ);
}

/*
 * Perform changing a passphrase.  The argument is the passwd structure
 * for the current user.
 */
സ്ഥിതം ശൂന്യം
do_change_passphrase(ഘടന passwd *pw, അക്ഷരം * സ്ഥിരം *opts, size_t nopts)
{
	അക്ഷരം *comment;
	അക്ഷരം *old_passphrase, *passphrase1, *passphrase2;
	ഘടന stat st;
	ഘടന sshkey *സ്വകാര്യ;
	പൂർണ്ണസംഖ്യ r;
	size_t i;

	എങ്കിൽ (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	എങ്കിൽ (stat(identity_file, &st) == -1)
		fatal("%s: %s", identity_file, strerror(errno));
	/* Try to load the file with empty passphrase. */
	r = sshkey_load_private(identity_file, "", &സ്വകാര്യ, &comment);
	എങ്കിൽ (r == SSH_ERR_താക്കോൽ_WRONG_PASSPHRASE) {
		എങ്കിൽ (identity_passphrase)
			old_passphrase = xstrdup(identity_passphrase);
		അല്ലെങ്കിൽ
			old_passphrase =
			    read_passphrase("Enter old passphrase: ",
			    RP_ALLOW_STDIN);
		r = sshkey_load_private(identity_file, old_passphrase,
		    &സ്വകാര്യ, &comment);
		freezero(old_passphrase, strlen(old_passphrase));
		എങ്കിൽ (r != 0)
			പോകുക badkey;
	} അല്ലെങ്കിൽ എങ്കിൽ (r != 0) {
 badkey:
		fatal_r(r, "Failed to load key %s", identity_file);
	}
	എങ്കിൽ (comment)
		mprintf("Key has comment '%s'\n", comment);

	/* All current -O options relate to FIDO keys only */
	എങ്കിൽ (nopts != 0 && !sshkey_is_sk(സ്വകാര്യ)) {
		fatal("FIDO-specific option requested for non-FIDO key %s",
		    identity_file);
	}
	എങ്കിൽ (sshkey_is_sk(സ്വകാര്യ)) {
		debug_f("%s: original FIDO key flags: "
		    "%stouch-required %sverify-required", identity_file,
		    (സ്വകാര്യ->sk_flags & SSH_SK_USER_PRESENCE_REQD) ? "": "no-",
		    (സ്വകാര്യ->sk_flags & SSH_SK_USER_VERIFICATION_REQD) ? "" : "no-");
	}
	വേണ്ടി (i = 0; i < nopts; i++) {
		എങ്കിൽ (strcasecmp(opts[i], "touch-required") == 0)
			സ്വകാര്യ->sk_flags |= SSH_SK_USER_PRESENCE_REQD;
		അല്ലെങ്കിൽ എങ്കിൽ (strcasecmp(opts[i], "no-touch-required") == 0)
			സ്വകാര്യ->sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
		അല്ലെങ്കിൽ എങ്കിൽ (strcasecmp(opts[i], "verify-required") == 0)
			സ്വകാര്യ->sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
		അല്ലെങ്കിൽ എങ്കിൽ (strcasecmp(opts[i], "no-verify-required") == 0)
			സ്വകാര്യ->sk_flags &= ~SSH_SK_USER_VERIFICATION_REQD;
		അല്ലെങ്കിൽ {
			fatal("Option \"%s\" is unsupported for "
			    "key passphrase change", opts[i]);
		}
	}
	എങ്കിൽ (sshkey_is_sk(സ്വകാര്യ) && nopts != 0) {
		debug_f("%s: updated FIDO key flags: "
		    "%stouch-required %sverify-required", identity_file,
		    (സ്വകാര്യ->sk_flags & SSH_SK_USER_PRESENCE_REQD) ? "": "no-",
		    (സ്വകാര്യ->sk_flags & SSH_SK_USER_VERIFICATION_REQD) ? "" : "no-");
	}

	/* Ask the new passphrase (twice). */
	എങ്കിൽ (identity_new_passphrase) {
		passphrase1 = xstrdup(identity_new_passphrase);
		passphrase2 = ശൂന്യ;
	} അല്ലെങ്കിൽ {
		passphrase1 =
			read_passphrase("Enter new passphrase (empty for no "
			    "passphrase): ", RP_ALLOW_STDIN);
		passphrase2 = read_passphrase("Enter same passphrase again: ",
		    RP_ALLOW_STDIN);

		/* Verify that they are the same. */
		എങ്കിൽ (strcmp(passphrase1, passphrase2) != 0) {
			explicit_bzero(passphrase1, strlen(passphrase1));
			explicit_bzero(passphrase2, strlen(passphrase2));
			സ്വതന്ത്രം(passphrase1);
			സ്വതന്ത്രം(passphrase2);
			printf("Pass phrases do not match.  Try again.\n");
			exit(1);
		}
		/* Destroy the other copy. */
		freezero(passphrase2, strlen(passphrase2));
	}

	/* Save the file using the new passphrase. */
	എങ്കിൽ ((r = sshkey_save_private(സ്വകാര്യ, identity_file, passphrase1,
	    comment, private_താക്കോൽ_format, openssh_format_cipher, rounds)) != 0) {
		error_r(r, "Saving key \"%s\" failed", identity_file);
		freezero(passphrase1, strlen(passphrase1));
		sshkey_free(സ്വകാര്യ);
		സ്വതന്ത്രം(comment);
		exit(1);
	}
	/* Destroy the passphrase and the copy of the key in memory. */
	freezero(passphrase1, strlen(passphrase1));
	sshkey_free(സ്വകാര്യ);		 /* Destroys contents */
	സ്വതന്ത്രം(comment);

	printf("Your identification has been saved with the new passphrase.\n");
	exit(0);
}

/*
 * Print the SSHFP RR.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
do_print_resource_record(ഘടന passwd *pw, അക്ഷരം *fname, അക്ഷരം *hname,
    പൂർണ്ണസംഖ്യ print_generic, അക്ഷരം * സ്ഥിരം *opts, size_t nopts)
{
	ഘടന sshkey *പൊതു;
	അക്ഷരം *comment = ശൂന്യ;
	സ്ഥിരം അക്ഷരം *p;
	ഘടന stat st;
	പൂർണ്ണസംഖ്യ r, hash = -1;
	size_t i;

	വേണ്ടി (i = 0; i < nopts; i++) {
		എങ്കിൽ ((p = strprefix(opts[i], "hashalg=", 1)) != ശൂന്യ) {
			എങ്കിൽ ((hash = ssh_digest_alg_by_name(p)) == -1)
				fatal("Unsupported hash algorithm");
		} അല്ലെങ്കിൽ {
			error("Invalid option \"%s\"", opts[i]);
			തിരികെ SSH_ERR_INVALID_ARGUMENT;
		}
	}
	എങ്കിൽ (fname == ശൂന്യ)
		fatal_f("no filename");
	എങ്കിൽ (stat(fname, &st) == -1) {
		എങ്കിൽ (errno == ENOENT)
			തിരികെ 0;
		fatal("%s: %s", fname, strerror(errno));
	}
	എങ്കിൽ ((r = sshkey_load_public(fname, &പൊതു, &comment)) != 0)
		fatal_r(r, "Failed to read v2 public key from \"%s\"", fname);
	export_dns_rr(hname, പൊതു, stdout, print_generic, hash);
	sshkey_free(പൊതു);
	സ്വതന്ത്രം(comment);
	തിരികെ 1;
}

/*
 * Change the comment of a private key file.
 */
സ്ഥിതം ശൂന്യം
do_change_comment(ഘടന passwd *pw, സ്ഥിരം അക്ഷരം *identity_comment)
{
	അക്ഷരം new_comment[താക്കോൽ_COMMENT_MAX], *comment, *passphrase;
	ഘടന sshkey *സ്വകാര്യ;
	ഘടന sshkey *പൊതു;
	ഘടന stat st;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	എങ്കിൽ (stat(identity_file, &st) == -1)
		fatal("%s: %s", identity_file, strerror(errno));
	എങ്കിൽ ((r = sshkey_load_private(identity_file, "",
	    &സ്വകാര്യ, &comment)) == 0)
		passphrase = xstrdup("");
	അല്ലെങ്കിൽ എങ്കിൽ (r != SSH_ERR_താക്കോൽ_WRONG_PASSPHRASE)
		fatal_r(r, "Cannot load private key \"%s\"", identity_file);
	അല്ലെങ്കിൽ {
		എങ്കിൽ (identity_passphrase)
			passphrase = xstrdup(identity_passphrase);
		അല്ലെങ്കിൽ എങ്കിൽ (identity_new_passphrase)
			passphrase = xstrdup(identity_new_passphrase);
		അല്ലെങ്കിൽ
			passphrase = read_passphrase("Enter passphrase: ",
			    RP_ALLOW_STDIN);
		/* Try to load using the passphrase. */
		എങ്കിൽ ((r = sshkey_load_private(identity_file, passphrase,
		    &സ്വകാര്യ, &comment)) != 0) {
			freezero(passphrase, strlen(passphrase));
			fatal_r(r, "Cannot load private key \"%s\"",
			    identity_file);
		}
	}

	എങ്കിൽ (സ്വകാര്യ->type != താക്കോൽ_ED25519 &&
	    private_താക്കോൽ_format != SSHKEY_PRIVATE_OPENSSH) {
		error("Comments are only supported for keys stored in "
		    "the new format (-o).");
		explicit_bzero(passphrase, strlen(passphrase));
		sshkey_free(സ്വകാര്യ);
		exit(1);
	}
	എങ്കിൽ (comment)
		printf("Old comment: %s\n", comment);
	അല്ലെങ്കിൽ
		printf("No existing comment\n");

	എങ്കിൽ (identity_comment) {
		strlcpy(new_comment, identity_comment, വലുപ്പം(new_comment));
	} അല്ലെങ്കിൽ {
		printf("New comment: ");
		fflush(stdout);
		എങ്കിൽ (!fgets(new_comment, വലുപ്പം(new_comment), stdin)) {
			explicit_bzero(passphrase, strlen(passphrase));
			sshkey_free(സ്വകാര്യ);
			exit(1);
		}
		new_comment[strcspn(new_comment, "\n")] = '\0';
	}
	എങ്കിൽ (comment != ശൂന്യ && strcmp(comment, new_comment) == 0) {
		printf("No change to comment\n");
		സ്വതന്ത്രം(passphrase);
		sshkey_free(സ്വകാര്യ);
		സ്വതന്ത്രം(comment);
		exit(0);
	}

	/* Save the file using the new passphrase. */
	എങ്കിൽ ((r = sshkey_save_private(സ്വകാര്യ, identity_file, passphrase,
	    new_comment, private_താക്കോൽ_format, openssh_format_cipher,
	    rounds)) != 0) {
		error_r(r, "Saving key \"%s\" failed", identity_file);
		freezero(passphrase, strlen(passphrase));
		sshkey_free(സ്വകാര്യ);
		സ്വതന്ത്രം(comment);
		exit(1);
	}
	freezero(passphrase, strlen(passphrase));
	എങ്കിൽ ((r = sshkey_from_private(സ്വകാര്യ, &പൊതു)) != 0)
		fatal_fr(r, "sshkey_from_private");
	sshkey_free(സ്വകാര്യ);

	strlcat(identity_file, ".pub", വലുപ്പം(identity_file));
	എങ്കിൽ ((r = sshkey_save_public(പൊതു, identity_file, new_comment)) != 0)
		fatal_r(r, "Unable to save public key to %s", identity_file);
	sshkey_free(പൊതു);
	സ്വതന്ത്രം(comment);

	എങ്കിൽ (strlen(new_comment) > 0)
		printf("Comment '%s' applied\n", new_comment);
	അല്ലെങ്കിൽ
		printf("Comment removed\n");

	exit(0);
}

സ്ഥിതം ശൂന്യം
cert_ext_add(സ്ഥിരം അക്ഷരം *താക്കോൽ, സ്ഥിരം അക്ഷരം *മൂല്യം, പൂർണ്ണസംഖ്യ iscrit)
{
	cert_ext = xreallocarray(cert_ext, ncert_ext + 1, വലുപ്പം(*cert_ext));
	cert_ext[ncert_ext].താക്കോൽ = xstrdup(താക്കോൽ);
	cert_ext[ncert_ext].val = മൂല്യം == ശൂന്യ ? ശൂന്യ : xstrdup(മൂല്യം);
	cert_ext[ncert_ext].crit = iscrit;
	ncert_ext++;
}

/* qsort(3) comparison function for certificate extensions */
സ്ഥിതം പൂർണ്ണസംഖ്യ
cert_ext_cmp(സ്ഥിരം ശൂന്യം *_a, സ്ഥിരം ശൂന്യം *_b)
{
	സ്ഥിരം ഘടന cert_ext *a = (സ്ഥിരം ഘടന cert_ext *)_a;
	സ്ഥിരം ഘടന cert_ext *b = (സ്ഥിരം ഘടന cert_ext *)_b;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (a->crit != b->crit)
		തിരികെ (a->crit < b->crit) ? -1 : 1;
	എങ്കിൽ ((r = strcmp(a->താക്കോൽ, b->താക്കോൽ)) != 0)
		തിരികെ r;
	എങ്കിൽ ((a->val == ശൂന്യ) != (b->val == ശൂന്യ))
		തിരികെ (a->val == ശൂന്യ) ? -1 : 1;
	എങ്കിൽ (a->val != ശൂന്യ && (r = strcmp(a->val, b->val)) != 0)
		തിരികെ r;
	തിരികെ 0;
}

#define OPTIONS_CRITICAL	1
#define OPTIONS_EXTENSIONS	2
സ്ഥിതം ശൂന്യം
prepare_options_buf(ഘടന sshbuf *c, പൂർണ്ണസംഖ്യ which)
{
	ഘടന sshbuf *b;
	size_t i;
	പൂർണ്ണസംഖ്യ r;
	സ്ഥിരം ഘടന cert_ext *ext;

	എങ്കിൽ ((b = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	sshbuf_reset(c);
	വേണ്ടി (i = 0; i < ncert_ext; i++) {
		ext = &cert_ext[i];
		എങ്കിൽ ((ext->crit && (which & OPTIONS_EXTENSIONS)) ||
		    (!ext->crit && (which & OPTIONS_CRITICAL)))
			തുടരുക;
		എങ്കിൽ (ext->val == ശൂന്യ) {
			/* flag option */
			debug3_f("%s", ext->താക്കോൽ);
			എങ്കിൽ ((r = sshbuf_put_cstring(c, ext->താക്കോൽ)) != 0 ||
			    (r = sshbuf_put_string(c, ശൂന്യ, 0)) != 0)
				fatal_fr(r, "prepare flag");
		} അല്ലെങ്കിൽ {
			/* key/value option */
			debug3_f("%s=%s", ext->താക്കോൽ, ext->val);
			sshbuf_reset(b);
			എങ്കിൽ ((r = sshbuf_put_cstring(c, ext->താക്കോൽ)) != 0 ||
			    (r = sshbuf_put_cstring(b, ext->val)) != 0 ||
			    (r = sshbuf_put_stringb(c, b)) != 0)
				fatal_fr(r, "prepare k/v");
		}
	}
	sshbuf_free(b);
}

സ്ഥിതം ശൂന്യം
finalise_cert_exts(ശൂന്യം)
{
	/* critical options */
	എങ്കിൽ (certflags_command != ശൂന്യ)
		cert_ext_add("force-command", certflags_command, 1);
	എങ്കിൽ (certflags_src_addr != ശൂന്യ)
		cert_ext_add("source-address", certflags_src_addr, 1);
	എങ്കിൽ ((certflags_flags & CERTOPT_REQUIRE_VERIFY) != 0)
		cert_ext_add("verify-required", ശൂന്യ, 1);
	/* extensions */
	എങ്കിൽ ((certflags_flags & CERTOPT_X_FWD) != 0)
		cert_ext_add("permit-X11-forwarding", ശൂന്യ, 0);
	എങ്കിൽ ((certflags_flags & CERTOPT_AGENT_FWD) != 0)
		cert_ext_add("permit-agent-forwarding", ശൂന്യ, 0);
	എങ്കിൽ ((certflags_flags & CERTOPT_PORT_FWD) != 0)
		cert_ext_add("permit-port-forwarding", ശൂന്യ, 0);
	എങ്കിൽ ((certflags_flags & CERTOPT_PTY) != 0)
		cert_ext_add("permit-pty", ശൂന്യ, 0);
	എങ്കിൽ ((certflags_flags & CERTOPT_USER_RC) != 0)
		cert_ext_add("permit-user-rc", ശൂന്യ, 0);
	എങ്കിൽ ((certflags_flags & CERTOPT_NO_REQUIRE_USER_PRESENCE) != 0)
		cert_ext_add("no-touch-required", ശൂന്യ, 0);
	/* order lexically by key */
	എങ്കിൽ (ncert_ext > 0)
		qsort(cert_ext, ncert_ext, വലുപ്പം(*cert_ext), cert_ext_cmp);
}

സ്ഥിതം ഘടന sshkey *
load_pkcs11_താക്കോൽ(അക്ഷരം *path)
{
#ifdef ENABLE_PKCS11
	ഘടന sshkey **താക്കോലുകൾ = ശൂന്യ, *പൊതു, *സ്വകാര്യ = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r, i, nkeys;

	എങ്കിൽ ((r = sshkey_load_public(path, &പൊതു, ശൂന്യ)) != 0)
		fatal_r(r, "Couldn't load CA public key \"%s\"", path);

	nkeys = pkcs11_add_provider(pkcs11provider, identity_passphrase,
	    &താക്കോലുകൾ, ശൂന്യ);
	debug3_f("%d keys", nkeys);
	എങ്കിൽ (nkeys <= 0)
		fatal("cannot read public key from pkcs11");
	വേണ്ടി (i = 0; i < nkeys; i++) {
		എങ്കിൽ (sshkey_equal_public(പൊതു, താക്കോലുകൾ[i])) {
			സ്വകാര്യ = താക്കോലുകൾ[i];
			തുടരുക;
		}
		sshkey_free(താക്കോലുകൾ[i]);
	}
	സ്വതന്ത്രം(താക്കോലുകൾ);
	sshkey_free(പൊതു);
	തിരികെ സ്വകാര്യ;
#അല്ലെങ്കിൽ
	fatal("no pkcs11 support");
#endif /* ENABLE_PKCS11 */
}

/* Signer for sshkey_certify_custom that uses the agent */
സ്ഥിതം പൂർണ്ണസംഖ്യ
agent_signer(ഘടന sshkey *താക്കോൽ, u_char **sigp, size_t *lenp,
    സ്ഥിരം u_char *data, size_t datalen,
    സ്ഥിരം അക്ഷരം *alg, സ്ഥിരം അക്ഷരം *provider, സ്ഥിരം അക്ഷരം *pin,
    u_int compat, ശൂന്യം *ctx)
{
	പൂർണ്ണസംഖ്യ *agent_fdp = (പൂർണ്ണസംഖ്യ *)ctx;

	തിരികെ ssh_agent_sign(*agent_fdp, താക്കോൽ, sigp, lenp,
	    data, datalen, alg, compat);
}

സ്ഥിതം ശൂന്യം
do_ca_sign(ഘടന passwd *pw, സ്ഥിരം അക്ഷരം *ca_താക്കോൽ_path, പൂർണ്ണസംഖ്യ prefer_agent,
    unsigned long long cert_serial, പൂർണ്ണസംഖ്യ cert_serial_autoinc,
    പൂർണ്ണസംഖ്യ argc, അക്ഷരം **argv)
{
	പൂർണ്ണസംഖ്യ r, i, താക്കോൽ_in_agent = 0, agent_fd = -1;
	u_int n;
	ഘടന sshkey *ca, *പൊതു;
	അക്ഷരം valid[64], *otmp, *tmp, *cp, *out, *comment;
	അക്ഷരം *ca_fp = ശൂന്യ, **plist = ശൂന്യ, *pin = ശൂന്യ;
	ഘടന ssh_identitylist *agent_ids;
	size_t j;
	ഘടന notifier_ctx *notifier = ശൂന്യ;

#ifdef ENABLE_PKCS11
	pkcs11_init(1);
#endif
	tmp = tilde_expand_filename(ca_താക്കോൽ_path, pw->pw_uid);
	എങ്കിൽ (pkcs11provider != ശൂന്യ) {
		/* If a PKCS#11 token was specified then try to use it */
		എങ്കിൽ ((ca = load_pkcs11_താക്കോൽ(tmp)) == ശൂന്യ)
			fatal("No PKCS#11 key matching %s found", ca_താക്കോൽ_path);
	} അല്ലെങ്കിൽ എങ്കിൽ (prefer_agent) {
		/*
		 * Agent signature requested. Try to use agent after making
		 * sure the public key specified is actually present in the
		 * agent.
		 */
		എങ്കിൽ ((r = sshkey_load_public(tmp, &ca, ശൂന്യ)) != 0)
			fatal_r(r, "Cannot load CA public key %s", tmp);
		എങ്കിൽ ((r = ssh_get_authentication_socket(&agent_fd)) != 0)
			fatal_r(r, "Cannot use public key for CA signature");
		എങ്കിൽ ((r = ssh_fetch_identitylist(agent_fd, &agent_ids)) != 0)
			fatal_r(r, "Retrieve agent key list");
		വേണ്ടി (j = 0; j < agent_ids->nkeys; j++) {
			എങ്കിൽ (sshkey_equal(ca, agent_ids->താക്കോലുകൾ[j])) {
				താക്കോൽ_in_agent = 1;
				/* Replace the CA key with the agent one */
				sshkey_free(ca);
				ca = agent_ids->താക്കോലുകൾ[j];
				agent_ids->താക്കോലുകൾ[j] = ശൂന്യ;
				നിർത്തുക;
			}
		}
		എങ്കിൽ (!താക്കോൽ_in_agent)
			fatal("CA key %s not found in agent", tmp);
		ssh_free_identitylist(agent_ids);
	} അല്ലെങ്കിൽ {
		/* CA key is assumed to be a private key on the filesystem */
		ca = load_identity(tmp, ശൂന്യ);
		എങ്കിൽ (sshkey_is_sk(ca) &&
		    (ca->sk_flags & SSH_SK_USER_VERIFICATION_REQD)) {
			എങ്കിൽ ((pin = read_passphrase("Enter PIN for CA key: ",
			    RP_ALLOW_STDIN)) == ശൂന്യ)
				fatal_f("couldn't read PIN");
		}
	}
	സ്വതന്ത്രം(tmp);

	എങ്കിൽ (താക്കോൽ_type_name != ശൂന്യ) {
		എങ്കിൽ (sshkey_type_from_shortname(താക്കോൽ_type_name) != ca->type) {
			fatal("CA key type %s doesn't match specified %s",
			    sshkey_ssh_name(ca), താക്കോൽ_type_name);
		}
	} അല്ലെങ്കിൽ എങ്കിൽ (ca->type == താക്കോൽ_RSA) {
		/* Default to a good signature algorithm */
		താക്കോൽ_type_name = "rsa-sha2-512";
	}
	ca_fp = sshkey_fingerprint(ca, fingerprint_hash, SSH_FP_DEFAULT);

	finalise_cert_exts();
	വേണ്ടി (i = 0; i < argc; i++) {
		/* Split list of principals */
		n = 0;
		എങ്കിൽ (cert_principals != ശൂന്യ) {
			otmp = tmp = xstrdup(cert_principals);
			plist = ശൂന്യ;
			വേണ്ടി (; (cp = strsep(&tmp, ",")) != ശൂന്യ; n++) {
				plist = xreallocarray(plist, n + 1, വലുപ്പം(*plist));
				എങ്കിൽ (*(plist[n] = xstrdup(cp)) == '\0')
					fatal("Empty principal name");
			}
			സ്വതന്ത്രം(otmp);
		}
		എങ്കിൽ (n > SSHKEY_CERT_MAX_PRINCIPALS)
			fatal("Too many certificate principals specified");

		tmp = tilde_expand_filename(argv[i], pw->pw_uid);
		എങ്കിൽ ((r = sshkey_load_public(tmp, &പൊതു, &comment)) != 0)
			fatal_r(r, "load pubkey \"%s\"", tmp);
		എങ്കിൽ (sshkey_is_cert(പൊതു))
			fatal_f("key \"%s\" type %s cannot be certified",
			    tmp, sshkey_type(പൊതു));

		/* Prepare certificate to sign */
		എങ്കിൽ ((r = sshkey_to_certified(പൊതു)) != 0)
			fatal_r(r, "Could not upgrade key %s to certificate", tmp);
		പൊതു->cert->type = cert_താക്കോൽ_type;
		പൊതു->cert->serial = (uint64_t)cert_serial;
		പൊതു->cert->താക്കോൽ_id = xstrdup(cert_താക്കോൽ_id);
		പൊതു->cert->nprincipals = n;
		പൊതു->cert->principals = plist;
		പൊതു->cert->valid_after = cert_valid_from;
		പൊതു->cert->valid_before = cert_valid_to;
		prepare_options_buf(പൊതു->cert->critical, OPTIONS_CRITICAL);
		prepare_options_buf(പൊതു->cert->extensions,
		    OPTIONS_EXTENSIONS);
		എങ്കിൽ ((r = sshkey_from_private(ca,
		    &പൊതു->cert->signature_താക്കോൽ)) != 0)
			fatal_r(r, "sshkey_from_private (ca key)");

		എങ്കിൽ (താക്കോൽ_in_agent) {
			എങ്കിൽ ((r = sshkey_certify_custom(പൊതു, ca,
			    താക്കോൽ_type_name, sk_provider, ശൂന്യ, agent_signer,
			    &agent_fd)) != 0)
				fatal_r(r, "Couldn't certify %s via agent", tmp);
		} അല്ലെങ്കിൽ {
			എങ്കിൽ (sshkey_is_sk(ca) &&
			    (ca->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
				notifier = notify_start(0,
				    "Confirm user presence for key %s %s",
				    sshkey_type(ca), ca_fp);
			}
			r = sshkey_certify(പൊതു, ca, താക്കോൽ_type_name,
			    sk_provider, pin);
			notify_complete(notifier, "User presence confirmed");
			എങ്കിൽ (r != 0)
				fatal_r(r, "Couldn't certify key %s", tmp);
		}

		എങ്കിൽ ((cp = strrchr(tmp, '.')) != ശൂന്യ && strcmp(cp, ".pub") == 0)
			*cp = '\0';
		xasprintf(&out, "%s-cert.pub", tmp);
		സ്വതന്ത്രം(tmp);

		എങ്കിൽ ((r = sshkey_save_public(പൊതു, out, comment)) != 0) {
			fatal_r(r, "Unable to save public key to %s",
			    identity_file);
		}

		എങ്കിൽ (!quiet) {
			sshkey_format_cert_validity(പൊതു->cert,
			    valid, വലുപ്പം(valid));
			logit("Signed %s key %s: id \"%s\" serial %llu%s%s "
			    "valid %s", sshkey_cert_type(പൊതു),
			    out, പൊതു->cert->താക്കോൽ_id,
			    (unsigned long long)പൊതു->cert->serial,
			    cert_principals != ശൂന്യ ? " for " : "",
			    cert_principals != ശൂന്യ ? cert_principals : "",
			    valid);
		}

		sshkey_free(പൊതു);
		സ്വതന്ത്രം(out);
		സ്വതന്ത്രം(comment);
		എങ്കിൽ (cert_serial_autoinc)
			cert_serial++;
	}
	എങ്കിൽ (pin != ശൂന്യ)
		freezero(pin, strlen(pin));
	sshkey_free(ca);
	സ്വതന്ത്രം(ca_fp);
#ifdef ENABLE_PKCS11
	pkcs11_terminate();
#endif
}

സ്ഥിതം uint64_t
parse_relative_time(സ്ഥിരം അക്ഷരം *s, time_t now)
{
	int64_t mul, secs;

	mul = *s == '-' ? -1 : 1;

	എങ്കിൽ ((secs = convtime(s + 1)) == -1)
		fatal("Invalid relative certificate time %s", s);
	എങ്കിൽ (mul == -1 && secs > now)
		fatal("Certificate time %s cannot be represented", s);
	തിരികെ now + (uint64_t)(secs * mul);
}

സ്ഥിതം ശൂന്യം
parse_hex_u64(സ്ഥിരം അക്ഷരം *s, uint64_t *up)
{
	അക്ഷരം *ep;
	unsigned long long ull;

	errno = 0;
	ull = strtoull(s, &ep, 16);
	എങ്കിൽ (*s == '\0' || *ep != '\0')
		fatal("Invalid certificate time: not a number");
	എങ്കിൽ (errno == ERANGE && ull == ULONG_MAX)
		fatal_fr(SSH_ERR_SYSTEM_ERROR, "Invalid certificate time");
	*up = (uint64_t)ull;
}

സ്ഥിതം ശൂന്യം
parse_cert_times(അക്ഷരം *timespec)
{
	അക്ഷരം *from, *to;
	time_t now = time(ശൂന്യ);
	int64_t secs;

	/* +timespec relative to now */
	എങ്കിൽ (*timespec == '+' && strchr(timespec, ':') == ശൂന്യ) {
		എങ്കിൽ ((secs = convtime(timespec + 1)) == -1)
			fatal("Invalid relative certificate life %s", timespec);
		cert_valid_to = now + secs;
		/*
		 * Backdate certificate one minute to avoid problems on hosts
		 * with poorly-synchronised clocks.
		 */
		cert_valid_from = ((now - 59)/ 60) * 60;
		തിരികെ;
	}

	/*
	 * from:to, where
	 * from := [+-]timespec | YYYYMMDD | YYYYMMDDHHMMSS | 0x... | "always"
	 *   to := [+-]timespec | YYYYMMDD | YYYYMMDDHHMMSS | 0x... | "forever"
	 */
	from = xstrdup(timespec);
	to = strchr(from, ':');
	എങ്കിൽ (to == ശൂന്യ || from == to || *(to + 1) == '\0')
		fatal("Invalid certificate life specification %s", timespec);
	*to++ = '\0';

	എങ്കിൽ (*from == '-' || *from == '+')
		cert_valid_from = parse_relative_time(from, now);
	അല്ലെങ്കിൽ എങ്കിൽ (strcmp(from, "always") == 0)
		cert_valid_from = 0;
	അല്ലെങ്കിൽ എങ്കിൽ (strncmp(from, "0x", 2) == 0)
		parse_hex_u64(from, &cert_valid_from);
	അല്ലെങ്കിൽ എങ്കിൽ (parse_absolute_time(from, &cert_valid_from) != 0)
		fatal("Invalid from time \"%s\"", from);

	എങ്കിൽ (*to == '-' || *to == '+')
		cert_valid_to = parse_relative_time(to, now);
	അല്ലെങ്കിൽ എങ്കിൽ (strcmp(to, "forever") == 0)
		cert_valid_to = ~(uint64_t)0;
	അല്ലെങ്കിൽ എങ്കിൽ (strncmp(to, "0x", 2) == 0)
		parse_hex_u64(to, &cert_valid_to);
	അല്ലെങ്കിൽ എങ്കിൽ (parse_absolute_time(to, &cert_valid_to) != 0)
		fatal("Invalid to time \"%s\"", to);

	എങ്കിൽ (cert_valid_to <= cert_valid_from)
		fatal("Empty certificate validity interval");
	സ്വതന്ത്രം(from);
}

സ്ഥിതം ശൂന്യം
add_cert_option(അക്ഷരം *opt)
{
	അക്ഷരം *val, *cp;
	സ്ഥിരം അക്ഷരം *p;
	പൂർണ്ണസംഖ്യ iscrit = 0;

	എങ്കിൽ (strcasecmp(opt, "clear") == 0)
		certflags_flags = 0;
	അല്ലെങ്കിൽ എങ്കിൽ (strcasecmp(opt, "no-x11-forwarding") == 0)
		certflags_flags &= ~CERTOPT_X_FWD;
	അല്ലെങ്കിൽ എങ്കിൽ (strcasecmp(opt, "permit-x11-forwarding") == 0)
		certflags_flags |= CERTOPT_X_FWD;
	അല്ലെങ്കിൽ എങ്കിൽ (strcasecmp(opt, "no-agent-forwarding") == 0)
		certflags_flags &= ~CERTOPT_AGENT_FWD;
	അല്ലെങ്കിൽ എങ്കിൽ (strcasecmp(opt, "permit-agent-forwarding") == 0)
		certflags_flags |= CERTOPT_AGENT_FWD;
	അല്ലെങ്കിൽ എങ്കിൽ (strcasecmp(opt, "no-port-forwarding") == 0)
		certflags_flags &= ~CERTOPT_PORT_FWD;
	അല്ലെങ്കിൽ എങ്കിൽ (strcasecmp(opt, "permit-port-forwarding") == 0)
		certflags_flags |= CERTOPT_PORT_FWD;
	അല്ലെങ്കിൽ എങ്കിൽ (strcasecmp(opt, "no-pty") == 0)
		certflags_flags &= ~CERTOPT_PTY;
	അല്ലെങ്കിൽ എങ്കിൽ (strcasecmp(opt, "permit-pty") == 0)
		certflags_flags |= CERTOPT_PTY;
	അല്ലെങ്കിൽ എങ്കിൽ (strcasecmp(opt, "no-user-rc") == 0)
		certflags_flags &= ~CERTOPT_USER_RC;
	അല്ലെങ്കിൽ എങ്കിൽ (strcasecmp(opt, "permit-user-rc") == 0)
		certflags_flags |= CERTOPT_USER_RC;
	അല്ലെങ്കിൽ എങ്കിൽ (strcasecmp(opt, "touch-required") == 0)
		certflags_flags &= ~CERTOPT_NO_REQUIRE_USER_PRESENCE;
	അല്ലെങ്കിൽ എങ്കിൽ (strcasecmp(opt, "no-touch-required") == 0)
		certflags_flags |= CERTOPT_NO_REQUIRE_USER_PRESENCE;
	അല്ലെങ്കിൽ എങ്കിൽ (strcasecmp(opt, "no-verify-required") == 0)
		certflags_flags &= ~CERTOPT_REQUIRE_VERIFY;
	അല്ലെങ്കിൽ എങ്കിൽ (strcasecmp(opt, "verify-required") == 0)
		certflags_flags |= CERTOPT_REQUIRE_VERIFY;
	അല്ലെങ്കിൽ എങ്കിൽ ((p = strprefix(opt, "force-command=", 1)) != ശൂന്യ) {
		എങ്കിൽ (*p == '\0')
			fatal("Empty force-command option");
		എങ്കിൽ (certflags_command != ശൂന്യ)
			fatal("force-command already specified");
		certflags_command = xstrdup(p);
	} അല്ലെങ്കിൽ എങ്കിൽ ((p = strprefix(opt, "source-address=", 1)) != ശൂന്യ) {
		എങ്കിൽ (*p == '\0')
			fatal("Empty source-address option");
		എങ്കിൽ (certflags_src_addr != ശൂന്യ)
			fatal("source-address already specified");
		എങ്കിൽ (addr_match_cidr_list(ശൂന്യ, p) != 0)
			fatal("Invalid source-address list");
		certflags_src_addr = xstrdup(p);
	} അല്ലെങ്കിൽ എങ്കിൽ (strprefix(opt, "extension:", 1) != ശൂന്യ ||
		    (iscrit = (strprefix(opt, "critical:", 1) != ശൂന്യ))) {
		val = xstrdup(strchr(opt, ':') + 1);
		എങ്കിൽ ((cp = strchr(val, '=')) != ശൂന്യ)
			*cp++ = '\0';
		cert_ext_add(val, cp, iscrit);
		സ്വതന്ത്രം(val);
	} അല്ലെങ്കിൽ
		fatal("Unsupported certificate option \"%s\"", opt);
}

സ്ഥിതം ശൂന്യം
show_options(ഘടന sshbuf *optbuf, പൂർണ്ണസംഖ്യ in_critical)
{
	അക്ഷരം *name, *arg, *hex;
	ഘടന sshbuf *options, *option = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((options = sshbuf_fromb(optbuf)) == ശൂന്യ)
		fatal_f("sshbuf_fromb failed");
	ആകുമ്പോൾ (sshbuf_len(options) != 0) {
		sshbuf_free(option);
		option = ശൂന്യ;
		എങ്കിൽ ((r = sshbuf_get_cstring(options, &name, ശൂന്യ)) != 0 ||
		    (r = sshbuf_froms(options, &option)) != 0)
			fatal_fr(r, "parse option");
		printf("                %s", name);
		എങ്കിൽ (!in_critical &&
		    (strcmp(name, "permit-X11-forwarding") == 0 ||
		    strcmp(name, "permit-agent-forwarding") == 0 ||
		    strcmp(name, "permit-port-forwarding") == 0 ||
		    strcmp(name, "permit-pty") == 0 ||
		    strcmp(name, "permit-user-rc") == 0 ||
		    strcmp(name, "no-touch-required") == 0)) {
			printf("\n");
		} അല്ലെങ്കിൽ എങ്കിൽ (in_critical &&
		    (strcmp(name, "force-command") == 0 ||
		    strcmp(name, "source-address") == 0)) {
			എങ്കിൽ ((r = sshbuf_get_cstring(option, &arg, ശൂന്യ)) != 0)
				fatal_fr(r, "parse critical");
			printf(" %s\n", arg);
			സ്വതന്ത്രം(arg);
		} അല്ലെങ്കിൽ എങ്കിൽ (in_critical &&
		    strcmp(name, "verify-required") == 0) {
			printf("\n");
		} അല്ലെങ്കിൽ എങ്കിൽ (sshbuf_len(option) > 0) {
			hex = sshbuf_dtob16(option);
			printf(" UNKNOWN OPTION: %s (len %zu)\n",
			    hex, sshbuf_len(option));
			sshbuf_reset(option);
			സ്വതന്ത്രം(hex);
		} അല്ലെങ്കിൽ
			printf(" UNKNOWN FLAG OPTION\n");
		സ്വതന്ത്രം(name);
		എങ്കിൽ (sshbuf_len(option) != 0)
			fatal("Option corrupt: extra data at end");
	}
	sshbuf_free(option);
	sshbuf_free(options);
}

സ്ഥിതം ശൂന്യം
print_cert(ഘടന sshkey *താക്കോൽ)
{
	അക്ഷരം valid[64], *താക്കോൽ_fp, *ca_fp;
	u_int i;

	താക്കോൽ_fp = sshkey_fingerprint(താക്കോൽ, fingerprint_hash, SSH_FP_DEFAULT);
	ca_fp = sshkey_fingerprint(താക്കോൽ->cert->signature_താക്കോൽ,
	    fingerprint_hash, SSH_FP_DEFAULT);
	എങ്കിൽ (താക്കോൽ_fp == ശൂന്യ || ca_fp == ശൂന്യ)
		fatal_f("sshkey_fingerprint fail");
	sshkey_format_cert_validity(താക്കോൽ->cert, valid, വലുപ്പം(valid));

	printf("        Type: %s %s certificate\n", sshkey_ssh_name(താക്കോൽ),
	    sshkey_cert_type(താക്കോൽ));
	printf("        Public key: %s %s\n", sshkey_type(താക്കോൽ), താക്കോൽ_fp);
	printf("        Signing CA: %s %s (using %s)\n",
	    sshkey_type(താക്കോൽ->cert->signature_താക്കോൽ), ca_fp,
	    താക്കോൽ->cert->signature_type);
	printf("        Key ID: \"%s\"\n", താക്കോൽ->cert->താക്കോൽ_id);
	printf("        Serial: %llu\n", (unsigned long long)താക്കോൽ->cert->serial);
	printf("        Valid: %s\n", valid);
	printf("        Principals: ");
	എങ്കിൽ (താക്കോൽ->cert->nprincipals == 0)
		printf("(none)\n");
	അല്ലെങ്കിൽ {
		വേണ്ടി (i = 0; i < താക്കോൽ->cert->nprincipals; i++)
			printf("\n                %s",
			    താക്കോൽ->cert->principals[i]);
		printf("\n");
	}
	printf("        Critical Options: ");
	എങ്കിൽ (sshbuf_len(താക്കോൽ->cert->critical) == 0)
		printf("(none)\n");
	അല്ലെങ്കിൽ {
		printf("\n");
		show_options(താക്കോൽ->cert->critical, 1);
	}
	printf("        Extensions: ");
	എങ്കിൽ (sshbuf_len(താക്കോൽ->cert->extensions) == 0)
		printf("(none)\n");
	അല്ലെങ്കിൽ {
		printf("\n");
		show_options(താക്കോൽ->cert->extensions, 0);
	}
	സ്വതന്ത്രം(താക്കോൽ_fp);
	സ്വതന്ത്രം(ca_fp);
}

സ്ഥിതം ശൂന്യം
do_show_cert(ഘടന passwd *pw)
{
	ഘടന sshkey *താക്കോൽ = ശൂന്യ;
	ഘടന stat st;
	പൂർണ്ണസംഖ്യ r, is_stdin = 0, ok = 0;
	FILE *f;
	അക്ഷരം *cp, *വരി = ശൂന്യ;
	സ്ഥിരം അക്ഷരം *path;
	size_t linesize = 0;
	u_long lnum = 0;

	എങ്കിൽ (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	എങ്കിൽ (strcmp(identity_file, "-") != 0 && stat(identity_file, &st) == -1)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));

	path = identity_file;
	എങ്കിൽ (strcmp(path, "-") == 0) {
		f = stdin;
		path = "(stdin)";
		is_stdin = 1;
	} അല്ലെങ്കിൽ എങ്കിൽ ((f = fopen(identity_file, "r")) == ശൂന്യ)
		fatal("fopen %s: %s", identity_file, strerror(errno));

	ആകുമ്പോൾ (getline(&വരി, &linesize, f) != -1) {
		lnum++;
		sshkey_free(താക്കോൽ);
		താക്കോൽ = ശൂന്യ;
		/* Trim leading space and comments */
		cp = വരി + strspn(വരി, " \t");
		എങ്കിൽ (*cp == '#' || *cp == '\0')
			തുടരുക;
		എങ്കിൽ ((താക്കോൽ = sshkey_new(താക്കോൽ_UNSPEC)) == ശൂന്യ)
			fatal("sshkey_new");
		എങ്കിൽ ((r = sshkey_read(താക്കോൽ, &cp)) != 0) {
			error_r(r, "%s:%lu: invalid key", path, lnum);
			തുടരുക;
		}
		എങ്കിൽ (!sshkey_is_cert(താക്കോൽ)) {
			error("%s:%lu is not a certificate", path, lnum);
			തുടരുക;
		}
		ok = 1;
		എങ്കിൽ (!is_stdin && lnum == 1)
			printf("%s:\n", path);
		അല്ലെങ്കിൽ
			printf("%s:%lu:\n", path, lnum);
		print_cert(താക്കോൽ);
	}
	സ്വതന്ത്രം(വരി);
	sshkey_free(താക്കോൽ);
	fclose(f);
	exit(ok ? 0 : 1);
}

സ്ഥിതം ശൂന്യം
load_krl(സ്ഥിരം അക്ഷരം *path, ഘടന ssh_krl **krlp)
{
	ഘടന sshbuf *krlbuf;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshbuf_load_file(path, &krlbuf)) != 0)
		fatal_r(r, "Unable to load KRL %s", path);
	/* XXX check sigs */
	എങ്കിൽ ((r = ssh_krl_from_blob(krlbuf, krlp)) != 0 ||
	    *krlp == ശൂന്യ)
		fatal_r(r, "Invalid KRL file %s", path);
	sshbuf_free(krlbuf);
}

സ്ഥിതം ശൂന്യം
hash_to_blob(സ്ഥിരം അക്ഷരം *cp, u_char **blobp, size_t *lenp,
    സ്ഥിരം അക്ഷരം *file, u_long lnum)
{
	അക്ഷരം *tmp;
	size_t tlen;
	ഘടന sshbuf *b;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((cp = strprefix(cp, "SHA256:", 0)) == ശൂന്യ)
		fatal("%s:%lu: unsupported hash algorithm", file, lnum);

	/*
	 * OpenSSH base64 hashes omit trailing '='
	 * characters; put them back for decode.
	 */
	എങ്കിൽ ((tlen = strlen(cp)) >= SIZE_MAX - 5)
		fatal_f("hash too long: %zu bytes", tlen);
	tmp = xmalloc(tlen + 4 + 1);
	strlcpy(tmp, cp, tlen + 1);
	ആകുമ്പോൾ ((tlen % 4) != 0) {
		tmp[tlen++] = '=';
		tmp[tlen] = '\0';
	}
	എങ്കിൽ ((b = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = sshbuf_b64tod(b, tmp)) != 0)
		fatal_r(r, "%s:%lu: decode hash failed", file, lnum);
	സ്വതന്ത്രം(tmp);
	*lenp = sshbuf_len(b);
	*blobp = xmalloc(*lenp);
	memcpy(*blobp, sshbuf_ptr(b), *lenp);
	sshbuf_free(b);
}

സ്ഥിതം ശൂന്യം
update_krl_from_file(ഘടന passwd *pw, സ്ഥിരം അക്ഷരം *file, പൂർണ്ണസംഖ്യ wild_ca,
    സ്ഥിരം ഘടന sshkey *ca, ഘടന ssh_krl *krl)
{
	ഘടന sshkey *താക്കോൽ = ശൂന്യ;
	u_long lnum = 0;
	അക്ഷരം *path, *cp, *ep, *വരി = ശൂന്യ;
	u_char *blob = ശൂന്യ;
	size_t blen = 0, linesize = 0;
	unsigned long long serial, serial2;
	പൂർണ്ണസംഖ്യ i, was_explicit_താക്കോൽ, was_sha1, was_sha256, was_hash, r;
	FILE *krl_spec;

	path = tilde_expand_filename(file, pw->pw_uid);
	എങ്കിൽ (strcmp(path, "-") == 0) {
		krl_spec = stdin;
		സ്വതന്ത്രം(path);
		path = xstrdup("(standard input)");
	} അല്ലെങ്കിൽ എങ്കിൽ ((krl_spec = fopen(path, "r")) == ശൂന്യ)
		fatal("fopen %s: %s", path, strerror(errno));

	എങ്കിൽ (!quiet)
		printf("Revoking from %s\n", path);
	ആകുമ്പോൾ (getline(&വരി, &linesize, krl_spec) != -1) {
		എങ്കിൽ (linesize >= INT_MAX) {
			fatal_f("%s contains unparsable line, len=%zu",
			    path, linesize);
		}
		lnum++;
		was_explicit_താക്കോൽ = was_sha1 = was_sha256 = was_hash = 0;
		cp = വരി + strspn(വരി, " \t");
		/* Trim trailing space, comments and strip \n */
		വേണ്ടി (i = 0, r = -1; cp[i] != '\0'; i++) {
			എങ്കിൽ (cp[i] == '#' || cp[i] == '\n') {
				cp[i] = '\0';
				നിർത്തുക;
			}
			എങ്കിൽ (cp[i] == ' ' || cp[i] == '\t') {
				/* Remember the start of a span of whitespace */
				എങ്കിൽ (r == -1)
					r = i;
			} അല്ലെങ്കിൽ
				r = -1;
		}
		എങ്കിൽ (r != -1)
			cp[r] = '\0';
		എങ്കിൽ (*cp == '\0')
			തുടരുക;
		എങ്കിൽ (strncasecmp(cp, "serial:", 7) == 0) {
			എങ്കിൽ (ca == ശൂന്യ && !wild_ca) {
				fatal("revoking certificates by serial number "
				    "requires specification of a CA key");
			}
			cp += 7;
			cp = cp + strspn(cp, " \t");
			errno = 0;
			serial = strtoull(cp, &ep, 0);
			എങ്കിൽ (*cp == '\0' || (*ep != '\0' && *ep != '-'))
				fatal("%s:%lu: invalid serial \"%s\"",
				    path, lnum, cp);
			എങ്കിൽ (errno == ERANGE && serial == ULLONG_MAX)
				fatal("%s:%lu: serial out of range",
				    path, lnum);
			serial2 = serial;
			എങ്കിൽ (*ep == '-') {
				cp = ep + 1;
				errno = 0;
				serial2 = strtoull(cp, &ep, 0);
				എങ്കിൽ (*cp == '\0' || *ep != '\0')
					fatal("%s:%lu: invalid serial \"%s\"",
					    path, lnum, cp);
				എങ്കിൽ (errno == ERANGE && serial2 == ULLONG_MAX)
					fatal("%s:%lu: serial out of range",
					    path, lnum);
				എങ്കിൽ (serial2 <= serial)
					fatal("%s:%lu: invalid serial range "
					    "%llu:%llu", path, lnum,
					    (unsigned long long)serial,
					    (unsigned long long)serial2);
			}
			എങ്കിൽ (ssh_krl_revoke_cert_by_serial_range(krl,
			    ca, serial, serial2) != 0) {
				fatal_f("revoke serial failed");
			}
		} അല്ലെങ്കിൽ എങ്കിൽ (strncasecmp(cp, "id:", 3) == 0) {
			എങ്കിൽ (ca == ശൂന്യ && !wild_ca) {
				fatal("revoking certificates by key ID "
				    "requires specification of a CA key");
			}
			cp += 3;
			cp = cp + strspn(cp, " \t");
			എങ്കിൽ (ssh_krl_revoke_cert_by_താക്കോൽ_id(krl, ca, cp) != 0)
				fatal_f("revoke key ID failed");
		} അല്ലെങ്കിൽ എങ്കിൽ (strncasecmp(cp, "hash:", 5) == 0) {
			cp += 5;
			cp = cp + strspn(cp, " \t");
			hash_to_blob(cp, &blob, &blen, file, lnum);
			എങ്കിൽ ((r = ssh_krl_revoke_താക്കോൽ_sha256(krl,
			    blob, blen)) != 0)
				fatal_fr(r, "revoke key failed");
			സ്വതന്ത്രം(blob);
			blob = ശൂന്യ;
			blen = 0;
		} അല്ലെങ്കിൽ {
			എങ്കിൽ (strncasecmp(cp, "key:", 4) == 0) {
				cp += 4;
				cp = cp + strspn(cp, " \t");
				was_explicit_താക്കോൽ = 1;
			} അല്ലെങ്കിൽ എങ്കിൽ (strncasecmp(cp, "sha1:", 5) == 0) {
				cp += 5;
				cp = cp + strspn(cp, " \t");
				was_sha1 = 1;
			} അല്ലെങ്കിൽ എങ്കിൽ (strncasecmp(cp, "sha256:", 7) == 0) {
				cp += 7;
				cp = cp + strspn(cp, " \t");
				was_sha256 = 1;
				/*
				 * Just try to process the line as a key.
				 * Parsing will fail if it isn't.
				 */
			}
			എങ്കിൽ ((താക്കോൽ = sshkey_new(താക്കോൽ_UNSPEC)) == ശൂന്യ)
				fatal("sshkey_new");
			എങ്കിൽ ((r = sshkey_read(താക്കോൽ, &cp)) != 0)
				fatal_r(r, "%s:%lu: invalid key", path, lnum);
			എങ്കിൽ (was_explicit_താക്കോൽ)
				r = ssh_krl_revoke_താക്കോൽ_explicit(krl, താക്കോൽ);
			അല്ലെങ്കിൽ എങ്കിൽ (was_sha1) {
				എങ്കിൽ (sshkey_fingerprint_raw(താക്കോൽ,
				    SSH_DIGEST_SHA1, &blob, &blen) != 0) {
					fatal("%s:%lu: fingerprint failed",
					    file, lnum);
				}
				r = ssh_krl_revoke_താക്കോൽ_sha1(krl, blob, blen);
			} അല്ലെങ്കിൽ എങ്കിൽ (was_sha256) {
				എങ്കിൽ (sshkey_fingerprint_raw(താക്കോൽ,
				    SSH_DIGEST_SHA256, &blob, &blen) != 0) {
					fatal("%s:%lu: fingerprint failed",
					    file, lnum);
				}
				r = ssh_krl_revoke_താക്കോൽ_sha256(krl, blob, blen);
			} അല്ലെങ്കിൽ
				r = ssh_krl_revoke_താക്കോൽ(krl, താക്കോൽ);
			എങ്കിൽ (r != 0)
				fatal_fr(r, "revoke key failed");
			freezero(blob, blen);
			blob = ശൂന്യ;
			blen = 0;
			sshkey_free(താക്കോൽ);
		}
	}
	എങ്കിൽ (strcmp(path, "-") != 0)
		fclose(krl_spec);
	സ്വതന്ത്രം(വരി);
	സ്വതന്ത്രം(path);
}

സ്ഥിതം ശൂന്യം
do_gen_krl(ഘടന passwd *pw, പൂർണ്ണസംഖ്യ updating, സ്ഥിരം അക്ഷരം *ca_താക്കോൽ_path,
    unsigned long long krl_version, സ്ഥിരം അക്ഷരം *krl_comment,
    പൂർണ്ണസംഖ്യ argc, അക്ഷരം **argv)
{
	ഘടന ssh_krl *krl;
	ഘടന stat sb;
	ഘടന sshkey *ca = ശൂന്യ;
	പൂർണ്ണസംഖ്യ i, r, wild_ca = 0;
	അക്ഷരം *tmp;
	ഘടന sshbuf *kbuf;

	എങ്കിൽ (*identity_file == '\0')
		fatal("KRL generation requires an output file");
	എങ്കിൽ (stat(identity_file, &sb) == -1) {
		എങ്കിൽ (errno != ENOENT)
			fatal("Cannot access KRL \"%s\": %s",
			    identity_file, strerror(errno));
		എങ്കിൽ (updating)
			fatal("KRL \"%s\" does not exist", identity_file);
	}
	എങ്കിൽ (ca_താക്കോൽ_path != ശൂന്യ) {
		എങ്കിൽ (strcasecmp(ca_താക്കോൽ_path, "none") == 0)
			wild_ca = 1;
		അല്ലെങ്കിൽ {
			tmp = tilde_expand_filename(ca_താക്കോൽ_path, pw->pw_uid);
			എങ്കിൽ ((r = sshkey_load_public(tmp, &ca, ശൂന്യ)) != 0)
				fatal_r(r, "Cannot load CA public key %s", tmp);
			സ്വതന്ത്രം(tmp);
		}
	}

	എങ്കിൽ (updating)
		load_krl(identity_file, &krl);
	അല്ലെങ്കിൽ എങ്കിൽ ((krl = ssh_krl_init()) == ശൂന്യ)
		fatal("couldn't create KRL");

	എങ്കിൽ (krl_version != 0)
		ssh_krl_set_version(krl, krl_version);
	എങ്കിൽ (krl_comment != ശൂന്യ)
		ssh_krl_set_comment(krl, krl_comment);

	വേണ്ടി (i = 0; i < argc; i++)
		update_krl_from_file(pw, argv[i], wild_ca, ca, krl);

	എങ്കിൽ ((kbuf = sshbuf_new()) == ശൂന്യ)
		fatal("sshbuf_new failed");
	എങ്കിൽ (ssh_krl_to_blob(krl, kbuf) != 0)
		fatal("Couldn't generate KRL");
	എങ്കിൽ ((r = sshbuf_write_file(identity_file, kbuf)) != 0)
		fatal("write %s: %s", identity_file, strerror(errno));
	sshbuf_free(kbuf);
	ssh_krl_free(krl);
	sshkey_free(ca);
}

സ്ഥിതം ശൂന്യം
do_check_krl(ഘടന passwd *pw, പൂർണ്ണസംഖ്യ print_krl, പൂർണ്ണസംഖ്യ argc, അക്ഷരം **argv)
{
	പൂർണ്ണസംഖ്യ i, r, ret = 0;
	അക്ഷരം *comment;
	ഘടന ssh_krl *krl;
	ഘടന sshkey *k;

	എങ്കിൽ (*identity_file == '\0')
		fatal("KRL checking requires an input file");
	load_krl(identity_file, &krl);
	എങ്കിൽ (print_krl)
		krl_dump(krl, stdout);
	വേണ്ടി (i = 0; i < argc; i++) {
		എങ്കിൽ ((r = sshkey_load_public(argv[i], &k, &comment)) != 0)
			fatal_r(r, "Cannot load public key %s", argv[i]);
		r = ssh_krl_check_താക്കോൽ(krl, k);
		printf("%s%s%s%s: %s\n", argv[i],
		    *comment ? " (" : "", comment, *comment ? ")" : "",
		    r == 0 ? "ok" : "REVOKED");
		എങ്കിൽ (r != 0)
			ret = 1;
		sshkey_free(k);
		സ്വതന്ത്രം(comment);
	}
	ssh_krl_free(krl);
	exit(ret);
}

സ്ഥിതം ഘടന sshkey *
load_sign_താക്കോൽ(സ്ഥിരം അക്ഷരം *keypath, സ്ഥിരം ഘടന sshkey *pubkey)
{
	size_t i, slen, plen = strlen(keypath);
	അക്ഷരം *privpath = xstrdup(keypath);
	സ്ഥിതം സ്ഥിരം അക്ഷരം * സ്ഥിരം suffixes[] = { "-cert.pub", ".pub", ശൂന്യ };
	ഘടന sshkey *ret = ശൂന്യ, *privkey = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r, waspub = 0;
	ഘടന stat st;

	/*
	 * If passed a public key filename, then try to locate the corresponding
	 * private key. This lets us specify certificates on the command-line
	 * and have ssh-keygen find the appropriate private key.
	 */
	വേണ്ടി (i = 0; suffixes[i]; i++) {
		slen = strlen(suffixes[i]);
		എങ്കിൽ (plen <= slen ||
		    strcmp(privpath + plen - slen, suffixes[i]) != 0)
			തുടരുക;
		privpath[plen - slen] = '\0';
		debug_f("%s looks like a public key, using private key "
		    "path %s instead", keypath, privpath);
		waspub = 1;
	}
	എങ്കിൽ (waspub && stat(privpath, &st) != 0 && errno == ENOENT)
		fatal("No private key found for public key \"%s\"", keypath);
	എങ്കിൽ ((r = sshkey_load_private(privpath, "", &privkey, ശൂന്യ)) != 0 &&
	    (r != SSH_ERR_താക്കോൽ_WRONG_PASSPHRASE)) {
		debug_fr(r, "load private key \"%s\"", privpath);
		fatal("No private key found for \"%s\"", privpath);
	} അല്ലെങ്കിൽ എങ്കിൽ (privkey == ശൂന്യ)
		privkey = load_identity(privpath, ശൂന്യ);

	എങ്കിൽ (!sshkey_equal_public(pubkey, privkey)) {
		error("Public key %s doesn't match private %s",
		    keypath, privpath);
		പോകുക done;
	}
	എങ്കിൽ (sshkey_is_cert(pubkey) && !sshkey_is_cert(privkey)) {
		/*
		 * Graft the certificate onto the private key to make
		 * it capable of signing.
		 */
		എങ്കിൽ ((r = sshkey_to_certified(privkey)) != 0) {
			error_fr(r, "sshkey_to_certified");
			പോകുക done;
		}
		എങ്കിൽ ((r = sshkey_cert_copy(pubkey, privkey)) != 0) {
			error_fr(r, "sshkey_cert_copy");
			പോകുക done;
		}
	}
	/* success */
	ret = privkey;
	privkey = ശൂന്യ;
 done:
	sshkey_free(privkey);
	സ്വതന്ത്രം(privpath);
	തിരികെ ret;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
sign_one(ഘടന sshkey *signkey, സ്ഥിരം അക്ഷരം *filename, പൂർണ്ണസംഖ്യ fd,
    സ്ഥിരം അക്ഷരം *sig_namespace, സ്ഥിരം അക്ഷരം *hashalg, sshsig_signer *signer,
    ശൂന്യം *signer_ctx)
{
	ഘടന sshbuf *sigbuf = ശൂന്യ, *abuf = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR, wfd = -1, oerrno;
	അക്ഷരം *wfile = ശൂന്യ, *asig = ശൂന്യ, *fp = ശൂന്യ;
	അക്ഷരം *pin = ശൂന്യ, *prompt = ശൂന്യ;

	എങ്കിൽ (!quiet) {
		എങ്കിൽ (fd == STDIN_FILENO)
			fprintf(stderr, "Signing data on standard input\n");
		അല്ലെങ്കിൽ
			fprintf(stderr, "Signing file %s\n", filename);
	}
	എങ്കിൽ (signer == ശൂന്യ && sshkey_is_sk(signkey)) {
		എങ്കിൽ ((signkey->sk_flags & SSH_SK_USER_VERIFICATION_REQD)) {
			xasprintf(&prompt, "Enter PIN for %s key: ",
			    sshkey_type(signkey));
			എങ്കിൽ ((pin = read_passphrase(prompt,
			    RP_ALLOW_STDIN)) == ശൂന്യ)
				fatal_f("couldn't read PIN");
		}
		എങ്കിൽ ((signkey->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
			എങ്കിൽ ((fp = sshkey_fingerprint(signkey, fingerprint_hash,
			    SSH_FP_DEFAULT)) == ശൂന്യ)
				fatal_f("fingerprint failed");
			fprintf(stderr, "Confirm user presence for key %s %s\n",
			    sshkey_type(signkey), fp);
			സ്വതന്ത്രം(fp);
		}
	}
	എങ്കിൽ ((r = sshsig_sign_fd(signkey, hashalg, sk_provider, pin,
	    fd, sig_namespace, &sigbuf, signer, signer_ctx)) != 0) {
		error_r(r, "Signing %s failed", filename);
		പോകുക out;
	}
	എങ്കിൽ ((r = sshsig_armor(sigbuf, &abuf)) != 0) {
		error_fr(r, "sshsig_armor");
		പോകുക out;
	}
	എങ്കിൽ ((asig = sshbuf_dup_string(abuf)) == ശൂന്യ) {
		error_f("buffer error");
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}

	എങ്കിൽ (fd == STDIN_FILENO) {
		fputs(asig, stdout);
		fflush(stdout);
	} അല്ലെങ്കിൽ {
		xasprintf(&wfile, "%s.sig", filename);
		എങ്കിൽ (confirm_overwrite(wfile)) {
			എങ്കിൽ ((wfd = open(wfile, O_WRONLY|O_CREAT|O_TRUNC,
			    0666)) == -1) {
				oerrno = errno;
				error("Cannot open %s: %s",
				    wfile, strerror(errno));
				errno = oerrno;
				r = SSH_ERR_SYSTEM_ERROR;
				പോകുക out;
			}
			എങ്കിൽ (atomicio(vwrite, wfd, asig,
			    strlen(asig)) != strlen(asig)) {
				oerrno = errno;
				error("Cannot write to %s: %s",
				    wfile, strerror(errno));
				errno = oerrno;
				r = SSH_ERR_SYSTEM_ERROR;
				പോകുക out;
			}
			എങ്കിൽ (!quiet) {
				fprintf(stderr, "Write signature to %s\n",
				    wfile);
			}
		}
	}
	/* success */
	r = 0;
 out:
	സ്വതന്ത്രം(wfile);
	സ്വതന്ത്രം(prompt);
	സ്വതന്ത്രം(asig);
	എങ്കിൽ (pin != ശൂന്യ)
		freezero(pin, strlen(pin));
	sshbuf_free(abuf);
	sshbuf_free(sigbuf);
	എങ്കിൽ (wfd != -1)
		close(wfd);
	തിരികെ r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
sig_process_opts(അക്ഷരം * സ്ഥിരം *opts, size_t nopts, അക്ഷരം **hashalgp,
    uint64_t *verify_timep, പൂർണ്ണസംഖ്യ *print_pubkey)
{
	size_t i;
	time_t now;
	സ്ഥിരം അക്ഷരം *p;

	എങ്കിൽ (verify_timep != ശൂന്യ)
		*verify_timep = 0;
	എങ്കിൽ (print_pubkey != ശൂന്യ)
		*print_pubkey = 0;
	എങ്കിൽ (hashalgp != ശൂന്യ)
		*hashalgp = ശൂന്യ;
	വേണ്ടി (i = 0; i < nopts; i++) {
		എങ്കിൽ (hashalgp != ശൂന്യ &&
		    (p = strprefix(opts[i], "hashalg=", 1)) != ശൂന്യ) {
			*hashalgp = xstrdup(p);
		} അല്ലെങ്കിൽ എങ്കിൽ (verify_timep &&
		    (p = strprefix(opts[i], "verify-time=", 1)) != ശൂന്യ) {
			എങ്കിൽ (parse_absolute_time(p, verify_timep) != 0 ||
			    *verify_timep == 0) {
				error("Invalid \"verify-time\" option");
				തിരികെ SSH_ERR_INVALID_ARGUMENT;
			}
		} അല്ലെങ്കിൽ എങ്കിൽ (print_pubkey &&
		    strcasecmp(opts[i], "print-pubkey") == 0) {
			*print_pubkey = 1;
		} അല്ലെങ്കിൽ {
			error("Invalid option \"%s\"", opts[i]);
			തിരികെ SSH_ERR_INVALID_ARGUMENT;
		}
	}
	എങ്കിൽ (verify_timep && *verify_timep == 0) {
		എങ്കിൽ ((now = time(ശൂന്യ)) < 0) {
			error("Time is before epoch");
			തിരികെ SSH_ERR_INVALID_ARGUMENT;
		}
		*verify_timep = (uint64_t)now;
	}
	തിരികെ 0;
}


സ്ഥിതം പൂർണ്ണസംഖ്യ
sig_sign(സ്ഥിരം അക്ഷരം *keypath, സ്ഥിരം അക്ഷരം *sig_namespace, പൂർണ്ണസംഖ്യ require_agent,
    പൂർണ്ണസംഖ്യ argc, അക്ഷരം **argv, അക്ഷരം * സ്ഥിരം *opts, size_t nopts)
{
	പൂർണ്ണസംഖ്യ i, fd = -1, r, ret = -1;
	പൂർണ്ണസംഖ്യ agent_fd = -1;
	ഘടന sshkey *pubkey = ശൂന്യ, *privkey = ശൂന്യ, *signkey = ശൂന്യ;
	sshsig_signer *signer = ശൂന്യ;
	അക്ഷരം *hashalg = ശൂന്യ;

	/* Check file arguments. */
	വേണ്ടി (i = 0; i < argc; i++) {
		എങ്കിൽ (strcmp(argv[i], "-") != 0)
			തുടരുക;
		എങ്കിൽ (i > 0 || argc > 1)
			fatal("Cannot sign mix of paths and standard input");
	}

	എങ്കിൽ (sig_process_opts(opts, nopts, &hashalg, ശൂന്യ, ശൂന്യ) != 0)
		പോകുക done; /* error already logged */

	എങ്കിൽ ((r = sshkey_load_public(keypath, &pubkey, ശൂന്യ)) != 0) {
		error_r(r, "Couldn't load public key %s", keypath);
		പോകുക done;
	}

	എങ്കിൽ ((r = ssh_get_authentication_socket(&agent_fd)) != 0) {
		എങ്കിൽ (require_agent)
			fatal("Couldn't get agent socket");
		debug_r(r, "Couldn't get agent socket");
	} അല്ലെങ്കിൽ {
		എങ്കിൽ ((r = ssh_agent_has_താക്കോൽ(agent_fd, pubkey)) == 0)
			signer = agent_signer;
		അല്ലെങ്കിൽ {
			എങ്കിൽ (require_agent)
				fatal("Couldn't find key in agent");
			debug_r(r, "Couldn't find key in agent");
		}
	}

	എങ്കിൽ (signer == ശൂന്യ) {
		/* Not using agent - try to load private key */
		എങ്കിൽ ((privkey = load_sign_താക്കോൽ(keypath, pubkey)) == ശൂന്യ)
			പോകുക done;
		signkey = privkey;
	} അല്ലെങ്കിൽ {
		/* Will use key in agent */
		signkey = pubkey;
	}

	എങ്കിൽ (argc == 0) {
		എങ്കിൽ ((r = sign_one(signkey, "(stdin)", STDIN_FILENO,
		    sig_namespace, hashalg, signer, &agent_fd)) != 0)
			പോകുക done;
	} അല്ലെങ്കിൽ {
		വേണ്ടി (i = 0; i < argc; i++) {
			എങ്കിൽ (strcmp(argv[i], "-") == 0)
				fd = STDIN_FILENO;
			അല്ലെങ്കിൽ എങ്കിൽ ((fd = open(argv[i], O_RDONLY)) == -1) {
				error("Cannot open %s for signing: %s",
				    argv[i], strerror(errno));
				പോകുക done;
			}
			എങ്കിൽ ((r = sign_one(signkey, argv[i], fd, sig_namespace,
			    hashalg, signer, &agent_fd)) != 0)
				പോകുക done;
			എങ്കിൽ (fd != STDIN_FILENO)
				close(fd);
			fd = -1;
		}
	}

	ret = 0;
done:
	എങ്കിൽ (fd != -1 && fd != STDIN_FILENO)
		close(fd);
	sshkey_free(pubkey);
	sshkey_free(privkey);
	സ്വതന്ത്രം(hashalg);
	തിരികെ ret;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
sig_verify(സ്ഥിരം അക്ഷരം *signature, സ്ഥിരം അക്ഷരം *sig_namespace,
    സ്ഥിരം അക്ഷരം *principal, സ്ഥിരം അക്ഷരം *allowed_താക്കോലുകൾ, സ്ഥിരം അക്ഷരം *revoked_താക്കോലുകൾ,
    അക്ഷരം * സ്ഥിരം *opts, size_t nopts)
{
	പൂർണ്ണസംഖ്യ r, ret = -1;
	പൂർണ്ണസംഖ്യ print_pubkey = 0;
	ഘടന sshbuf *sigbuf = ശൂന്യ, *abuf = ശൂന്യ;
	ഘടന sshkey *sign_താക്കോൽ = ശൂന്യ;
	അക്ഷരം *fp = ശൂന്യ;
	ഘടന sshkey_sig_details *sig_details = ശൂന്യ;
	uint64_t verify_time = 0;

	എങ്കിൽ (sig_process_opts(opts, nopts, ശൂന്യ, &verify_time,
	    &print_pubkey) != 0)
		പോകുക done; /* error already logged */

	memset(&sig_details, 0, വലുപ്പം(sig_details));
	എങ്കിൽ ((r = sshbuf_load_file(signature, &abuf)) != 0) {
		error_r(r, "Couldn't read signature file");
		പോകുക done;
	}

	എങ്കിൽ ((r = sshsig_dearmor(abuf, &sigbuf)) != 0) {
		error_fr(r, "sshsig_armor");
		പോകുക done;
	}
	എങ്കിൽ ((r = sshsig_verify_fd(sigbuf, STDIN_FILENO, sig_namespace,
	    &sign_താക്കോൽ, &sig_details)) != 0)
		പോകുക done; /* sshsig_verify() prints error */

	എങ്കിൽ ((fp = sshkey_fingerprint(sign_താക്കോൽ, fingerprint_hash,
	    SSH_FP_DEFAULT)) == ശൂന്യ)
		fatal_f("sshkey_fingerprint failed");
	debug("Valid (unverified) signature from key %s", fp);
	എങ്കിൽ (sig_details != ശൂന്യ) {
		debug2_f("signature details: counter = %u, flags = 0x%02x",
		    sig_details->sk_counter, sig_details->sk_flags);
	}
	സ്വതന്ത്രം(fp);
	fp = ശൂന്യ;

	എങ്കിൽ (revoked_താക്കോലുകൾ != ശൂന്യ) {
		എങ്കിൽ ((r = sshkey_check_revoked(sign_താക്കോൽ, revoked_താക്കോലുകൾ)) != 0) {
			debug3_fr(r, "sshkey_check_revoked");
			പോകുക done;
		}
	}

	എങ്കിൽ (allowed_താക്കോലുകൾ != ശൂന്യ && (r = sshsig_check_allowed_താക്കോലുകൾ(allowed_താക്കോലുകൾ,
	    sign_താക്കോൽ, principal, sig_namespace, verify_time)) != 0) {
		debug3_fr(r, "sshsig_check_allowed_keys");
		പോകുക done;
	}
	/* success */
	ret = 0;
done:
	എങ്കിൽ (!quiet) {
		എങ്കിൽ (ret == 0) {
			എങ്കിൽ ((fp = sshkey_fingerprint(sign_താക്കോൽ, fingerprint_hash,
			    SSH_FP_DEFAULT)) == ശൂന്യ)
				fatal_f("sshkey_fingerprint failed");
			എങ്കിൽ (principal == ശൂന്യ) {
				printf("Good \"%s\" signature with %s key %s\n",
				    sig_namespace, sshkey_type(sign_താക്കോൽ), fp);

			} അല്ലെങ്കിൽ {
				printf("Good \"%s\" signature for %s with %s key %s\n",
				    sig_namespace, principal,
				    sshkey_type(sign_താക്കോൽ), fp);
			}
		} അല്ലെങ്കിൽ {
			printf("Could not verify signature.\n");
		}
	}
	/* Print the signature key if requested */
	എങ്കിൽ (ret == 0 && print_pubkey && sign_താക്കോൽ != ശൂന്യ) {
		എങ്കിൽ ((r = sshkey_write(sign_താക്കോൽ, stdout)) == 0)
			fputc('\n', stdout);
		അല്ലെങ്കിൽ {
			error_r(r, "Could not print public key.\n");
			ret = -1;
		}
	}
	sshbuf_free(sigbuf);
	sshbuf_free(abuf);
	sshkey_free(sign_താക്കോൽ);
	sshkey_sig_details_free(sig_details);
	സ്വതന്ത്രം(fp);
	തിരികെ ret;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
sig_find_principals(സ്ഥിരം അക്ഷരം *signature, സ്ഥിരം അക്ഷരം *allowed_താക്കോലുകൾ,
    അക്ഷരം * സ്ഥിരം *opts, size_t nopts)
{
	പൂർണ്ണസംഖ്യ r, ret = -1;
	ഘടന sshbuf *sigbuf = ശൂന്യ, *abuf = ശൂന്യ;
	ഘടന sshkey *sign_താക്കോൽ = ശൂന്യ;
	അക്ഷരം *principals = ശൂന്യ, *cp, *tmp;
	uint64_t verify_time = 0;

	എങ്കിൽ (sig_process_opts(opts, nopts, ശൂന്യ, &verify_time, ശൂന്യ) != 0)
		പോകുക done; /* error already logged */

	എങ്കിൽ ((r = sshbuf_load_file(signature, &abuf)) != 0) {
		error_r(r, "Couldn't read signature file");
		പോകുക done;
	}
	എങ്കിൽ ((r = sshsig_dearmor(abuf, &sigbuf)) != 0) {
		error_fr(r, "sshsig_armor");
		പോകുക done;
	}
	എങ്കിൽ ((r = sshsig_get_pubkey(sigbuf, &sign_താക്കോൽ)) != 0) {
		error_fr(r, "sshsig_get_pubkey");
		പോകുക done;
	}
	എങ്കിൽ ((r = sshsig_find_principals(allowed_താക്കോലുകൾ, sign_താക്കോൽ,
	    verify_time, &principals)) != 0) {
		എങ്കിൽ (r != SSH_ERR_താക്കോൽ_NOT_FOUND)
			error_fr(r, "sshsig_find_principal");
		പോകുക done;
	}
	ret = 0;
done:
	എങ്കിൽ (ret == 0 ) {
		/* Emit matching principals one per line */
		tmp = principals;
		ആകുമ്പോൾ ((cp = strsep(&tmp, ",")) != ശൂന്യ && *cp != '\0')
			puts(cp);
	} അല്ലെങ്കിൽ {
		fprintf(stderr, "No principal matched.\n");
	}
	sshbuf_free(sigbuf);
	sshbuf_free(abuf);
	sshkey_free(sign_താക്കോൽ);
	സ്വതന്ത്രം(principals);
	തിരികെ ret;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
sig_match_principals(സ്ഥിരം അക്ഷരം *allowed_താക്കോലുകൾ, അക്ഷരം *principal,
	അക്ഷരം * സ്ഥിരം *opts, size_t nopts)
{
	പൂർണ്ണസംഖ്യ r;
	അക്ഷരം **principals = ശൂന്യ;
	size_t i, nprincipals = 0;

	എങ്കിൽ ((r = sig_process_opts(opts, nopts, ശൂന്യ, ശൂന്യ, ശൂന്യ)) != 0)
		തിരികെ r; /* error already logged */

	എങ്കിൽ ((r = sshsig_match_principals(allowed_താക്കോലുകൾ, principal,
	    &principals, &nprincipals)) != 0) {
		debug_f("match: %s", ssh_err(r));
		fprintf(stderr, "No principal matched.\n");
		തിരികെ r;
	}
	വേണ്ടി (i = 0; i < nprincipals; i++) {
		printf("%s\n", principals[i]);
		സ്വതന്ത്രം(principals[i]);
	}
	സ്വതന്ത്രം(principals);

	തിരികെ 0;
}

സ്ഥിതം ശൂന്യം
do_moduli_gen(സ്ഥിരം അക്ഷരം *out_file, അക്ഷരം **opts, size_t nopts)
{
#ifdef WITH_OPENSSL
	/* Moduli generation/screening */
	BIGNUM *start = ശൂന്യ;
	പൂർണ്ണസംഖ്യ moduli_bits = 0;
	FILE *out;
	size_t i;
	സ്ഥിരം അക്ഷരം *errstr, *p;

	/* Parse options */
	വേണ്ടി (i = 0; i < nopts; i++) {
		എങ്കിൽ ((p = strprefix(opts[i], "start=", 0)) != ശൂന്യ) {
			/* XXX - also compare length against bits */
			എങ്കിൽ (BN_hex2bn(&start, p) == 0)
				fatal("Invalid start point.");
		} അല്ലെങ്കിൽ എങ്കിൽ ((p = strprefix(opts[i], "bits=", 0)) != ശൂന്യ) {
			moduli_bits = (പൂർണ്ണസംഖ്യ)strtonum(p, 1, INT_MAX, &errstr);
			എങ്കിൽ (errstr) {
				fatal("Invalid number: %s (%s)", p, errstr);
			}
		} അല്ലെങ്കിൽ {
			fatal("Option \"%s\" is unsupported for moduli "
			    "generation", opts[i]);
		}
	}

	എങ്കിൽ (strcmp(out_file, "-") == 0)
		out = stdout;
	അല്ലെങ്കിൽ എങ്കിൽ ((out = fopen(out_file, "w")) == ശൂന്യ) {
		fatal("Couldn't open modulus candidate file \"%s\": %s",
		    out_file, strerror(errno));
	}
	setvbuf(out, ശൂന്യ, _IOLBF, 0);

	എങ്കിൽ (moduli_bits == 0)
		moduli_bits = DEFAULT_BITS;
	എങ്കിൽ (gen_candidates(out, moduli_bits, start) != 0)
		fatal("modulus candidate generation failed");
#അല്ലെങ്കിൽ /* WITH_OPENSSL */
	fatal("Moduli generation is not supported");
#endif /* WITH_OPENSSL */
}

സ്ഥിതം ശൂന്യം
do_moduli_screen(സ്ഥിരം അക്ഷരം *out_file, അക്ഷരം **opts, size_t nopts)
{
#ifdef WITH_OPENSSL
	/* Moduli generation/screening */
	അക്ഷരം *checkpoint = ശൂന്യ;
	uint32_t generator_wanted = 0;
	unsigned long start_lineno = 0, വരികൾ_to_process = 0;
	പൂർണ്ണസംഖ്യ അഭാജ്യം_tests = 0;
	FILE *out, *in = stdin;
	size_t i;
	സ്ഥിരം അക്ഷരം *errstr, *p;

	/* Parse options */
	വേണ്ടി (i = 0; i < nopts; i++) {
		എങ്കിൽ ((p = strprefix(opts[i], "lines=", 0)) != ശൂന്യ) {
			വരികൾ_to_process = strtoul(p, ശൂന്യ, 10);
		} അല്ലെങ്കിൽ എങ്കിൽ ((p = strprefix(opts[i], "start-line=", 0)) != ശൂന്യ) {
			start_lineno = strtoul(p, ശൂന്യ, 10);
		} അല്ലെങ്കിൽ എങ്കിൽ ((p = strprefix(opts[i], "checkpoint=", 0)) != ശൂന്യ) {
			സ്വതന്ത്രം(checkpoint);
			checkpoint = xstrdup(p);
		} അല്ലെങ്കിൽ എങ്കിൽ ((p = strprefix(opts[i], "generator=", 0)) != ശൂന്യ) {
			generator_wanted = (uint32_t)strtonum(p, 1, UINT_MAX,
			    &errstr);
			എങ്കിൽ (errstr != ശൂന്യ) {
				fatal("Generator invalid: %s (%s)", p, errstr);
			}
		} അല്ലെങ്കിൽ എങ്കിൽ ((p = strprefix(opts[i], "prime-tests=", 0)) != ശൂന്യ) {
			അഭാജ്യം_tests = (പൂർണ്ണസംഖ്യ)strtonum(p, 1, INT_MAX, &errstr);
			എങ്കിൽ (errstr) {
				fatal("Invalid number: %s (%s)", p, errstr);
			}
		} അല്ലെങ്കിൽ {
			fatal("Option \"%s\" is unsupported for moduli "
			    "screening", opts[i]);
		}
	}

	എങ്കിൽ (have_identity && strcmp(identity_file, "-") != 0) {
		എങ്കിൽ ((in = fopen(identity_file, "r")) == ശൂന്യ) {
			fatal("Couldn't open modulus candidate "
			    "file \"%s\": %s", identity_file,
			    strerror(errno));
		}
	}

	എങ്കിൽ (strcmp(out_file, "-") == 0)
		out = stdout;
	അല്ലെങ്കിൽ എങ്കിൽ ((out = fopen(out_file, "a")) == ശൂന്യ) {
		fatal("Couldn't open moduli file \"%s\": %s",
		    out_file, strerror(errno));
	}
	setvbuf(out, ശൂന്യ, _IOLBF, 0);
	എങ്കിൽ (അഭാജ്യം_test(in, out, അഭാജ്യം_tests == 0 ? 100 : അഭാജ്യം_tests,
	    generator_wanted, checkpoint,
	    start_lineno, വരികൾ_to_process) != 0)
		fatal("modulus screening failed");
	എങ്കിൽ (in != stdin)
		(ശൂന്യം)fclose(in);
	സ്വതന്ത്രം(checkpoint);
#അല്ലെങ്കിൽ /* WITH_OPENSSL */
	fatal("Moduli screening is not supported");
#endif /* WITH_OPENSSL */
}

/* Read and confirm a passphrase */
സ്ഥിതം അക്ഷരം *
read_check_passphrase(സ്ഥിരം അക്ഷരം *prompt1, സ്ഥിരം അക്ഷരം *prompt2,
    സ്ഥിരം അക്ഷരം *retry_prompt)
{
	അക്ഷരം *passphrase1, *passphrase2;

	വേണ്ടി (;;) {
		passphrase1 = read_passphrase(prompt1, RP_ALLOW_STDIN);
		passphrase2 = read_passphrase(prompt2, RP_ALLOW_STDIN);
		എങ്കിൽ (strcmp(passphrase1, passphrase2) == 0) {
			freezero(passphrase2, strlen(passphrase2));
			തിരികെ passphrase1;
		}
		/* The passphrases do not match. Clear them and retry. */
		freezero(passphrase1, strlen(passphrase1));
		freezero(passphrase2, strlen(passphrase2));
		fputs(retry_prompt, stdout);
		fputc('\n', stdout);
		fflush(stdout);
	}
	/* NOTREACHED */
	തിരികെ ശൂന്യ;
}

സ്ഥിതം അക്ഷരം *
private_താക്കോൽ_passphrase(സ്ഥിരം അക്ഷരം *path)
{
	അക്ഷരം *prompt, *ret;

	എങ്കിൽ (identity_passphrase)
		തിരികെ xstrdup(identity_passphrase);
	എങ്കിൽ (identity_new_passphrase)
		തിരികെ xstrdup(identity_new_passphrase);

	xasprintf(&prompt, "Enter passphrase for \"%s\" "
	    "(empty for no passphrase): ", path);
	ret = read_check_passphrase(prompt,
	    "Enter same passphrase again: ",
	    "Passphrases do not match.  Try again.");
	സ്വതന്ത്രം(prompt);
	തിരികെ ret;
}

സ്ഥിതം അക്ഷരം *
sk_suffix(സ്ഥിരം അക്ഷരം *application, സ്ഥിരം uint8_t *user, size_t userlen)
{
	അക്ഷരം *ret, *cp;
	സ്ഥിരം അക്ഷരം *p;
	size_t slen, i;

	/* Trim off URL-like preamble */
	എങ്കിൽ ((p = strprefix(application, "ssh://", 0)) != ശൂന്യ)
		ret =  xstrdup(p);
	അല്ലെങ്കിൽ എങ്കിൽ ((p = strprefix(application, "ssh:", 0)) != ശൂന്യ)
		ret =  xstrdup(p);
	അല്ലെങ്കിൽ
		ret = xstrdup(application);

	/* Count trailing zeros in user */
	വേണ്ടി (i = 0; i < userlen; i++) {
		എങ്കിൽ (user[userlen - i - 1] != 0)
			നിർത്തുക;
	}
	എങ്കിൽ (i >= userlen)
		തിരികെ ret; /* user-id was default all-zeros */

	/* Append user-id, escaping non-UTF-8 characters */
	slen = userlen - i;
	എങ്കിൽ (asmprintf(&cp, INT_MAX, ശൂന്യ, "%.*s", (പൂർണ്ണസംഖ്യ)slen, user) == -1)
		fatal_f("asmprintf failed");
	/* Don't emit a user-id that contains path or control characters */
	എങ്കിൽ (strchr(cp, '/') != ശൂന്യ || strstr(cp, "..") != ശൂന്യ ||
	    strchr(cp, '\\') != ശൂന്യ) {
		സ്വതന്ത്രം(cp);
		cp = tohex(user, slen);
	}
	xextendf(&ret, "_", "%s", cp);
	സ്വതന്ത്രം(cp);
	തിരികെ ret;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
do_download_sk(സ്ഥിരം അക്ഷരം *skprovider, സ്ഥിരം അക്ഷരം *device)
{
	ഘടന sshsk_resident_താക്കോൽ **srks;
	size_t nsrks, i;
	പൂർണ്ണസംഖ്യ r, ret = -1;
	അക്ഷരം *fp, *pin = ശൂന്യ, *pass = ശൂന്യ, *path, *pubpath;
	സ്ഥിരം അക്ഷരം *ext;
	ഘടന sshkey *താക്കോൽ;

	എങ്കിൽ (skprovider == ശൂന്യ)
		fatal("Cannot download keys without provider");

	pin = read_passphrase("Enter PIN for authenticator: ", RP_ALLOW_STDIN);
	എങ്കിൽ (!quiet) {
		printf("You may need to touch your authenticator "
		    "to authorize key download.\n");
	}
	എങ്കിൽ ((r = sshsk_load_resident(skprovider, device, pin, 0,
	    &srks, &nsrks)) != 0) {
		എങ്കിൽ (pin != ശൂന്യ)
			freezero(pin, strlen(pin));
		error_r(r, "Unable to load resident keys");
		തിരികെ -1;
	}
	എങ്കിൽ (nsrks == 0)
		logit("No keys to download");
	എങ്കിൽ (pin != ശൂന്യ)
		freezero(pin, strlen(pin));

	വേണ്ടി (i = 0; i < nsrks; i++) {
		താക്കോൽ = srks[i]->താക്കോൽ;
		എങ്കിൽ (താക്കോൽ->type != താക്കോൽ_ECDSA_SK && താക്കോൽ->type != താക്കോൽ_ED25519_SK) {
			error("Unsupported key type %s (%d)",
			    sshkey_type(താക്കോൽ), താക്കോൽ->type);
			തുടരുക;
		}
		എങ്കിൽ ((fp = sshkey_fingerprint(താക്കോൽ, fingerprint_hash,
		    SSH_FP_DEFAULT)) == ശൂന്യ)
			fatal_f("sshkey_fingerprint failed");
		debug_f("key %zu: %s %s %s (flags 0x%02x)", i,
		    sshkey_type(താക്കോൽ), fp, താക്കോൽ->sk_application, താക്കോൽ->sk_flags);
		ext = sk_suffix(താക്കോൽ->sk_application,
		    srks[i]->user_id, srks[i]->user_id_len);
		xasprintf(&path, "id_%s_rk%s%s",
		    താക്കോൽ->type == താക്കോൽ_ECDSA_SK ? "ecdsa_sk" : "ed25519_sk",
		    *ext == '\0' ? "" : "_", ext);

		/* If the file already exists, ask the user to confirm. */
		എങ്കിൽ (!confirm_overwrite(path)) {
			സ്വതന്ത്രം(path);
			നിർത്തുക;
		}

		/* Save the key with the application string as the comment */
		എങ്കിൽ (pass == ശൂന്യ)
			pass = private_താക്കോൽ_passphrase(path);
		എങ്കിൽ ((r = sshkey_save_private(താക്കോൽ, path, pass,
		    താക്കോൽ->sk_application, private_താക്കോൽ_format,
		    openssh_format_cipher, rounds)) != 0) {
			error_r(r, "Saving key \"%s\" failed", path);
			സ്വതന്ത്രം(path);
			നിർത്തുക;
		}
		എങ്കിൽ (!quiet) {
			printf("Saved %s key%s%s to %s\n", sshkey_type(താക്കോൽ),
			    *ext != '\0' ? " " : "",
			    *ext != '\0' ? താക്കോൽ->sk_application : "",
			    path);
		}

		/* Save public key too */
		xasprintf(&pubpath, "%s.pub", path);
		സ്വതന്ത്രം(path);
		എങ്കിൽ ((r = sshkey_save_public(താക്കോൽ, pubpath,
		    താക്കോൽ->sk_application)) != 0) {
			error_r(r, "Saving public key \"%s\" failed", pubpath);
			സ്വതന്ത്രം(pubpath);
			നിർത്തുക;
		}
		സ്വതന്ത്രം(pubpath);
	}

	എങ്കിൽ (i >= nsrks)
		ret = 0; /* success */
	എങ്കിൽ (pass != ശൂന്യ)
		freezero(pass, strlen(pass));
	sshsk_free_resident_താക്കോലുകൾ(srks, nsrks);
	തിരികെ ret;
}

സ്ഥിതം ശൂന്യം
save_attestation(ഘടന sshbuf *attest, സ്ഥിരം അക്ഷരം *path)
{
	mode_t omask;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (path == ശൂന്യ)
		തിരികെ; /* nothing to do */
	എങ്കിൽ (attest == ശൂന്യ || sshbuf_len(attest) == 0)
		fatal("Enrollment did not return attestation data");
	omask = umask(077);
	r = sshbuf_write_file(path, attest);
	umask(omask);
	എങ്കിൽ (r != 0)
		fatal_r(r, "Unable to write attestation data \"%s\"", path);
	എങ്കിൽ (!quiet)
		printf("Your FIDO attestation certificate has been saved in "
		    "%s\n", path);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
confirm_sk_overwrite(സ്ഥിരം അക്ഷരം *application, സ്ഥിരം അക്ഷരം *user)
{
	അക്ഷരം yesno[3];

	printf("A resident key scoped to '%s' with user id '%s' already "
	    "exists.\n", application == ശൂന്യ ? "ssh:" : application,
	    user == ശൂന്യ ? "null" : user);
	printf("Overwrite key in token (y/n)? ");
	fflush(stdout);
	എങ്കിൽ (fgets(yesno, വലുപ്പം(yesno), stdin) == ശൂന്യ)
		തിരികെ 0;
	എങ്കിൽ (yesno[0] != 'y' && yesno[0] != 'Y')
		തിരികെ 0;
	തിരികെ 1;
}

സ്ഥിതം ശൂന്യം
usage(ശൂന്യം)
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
പൂർണ്ണസംഖ്യ
പ്രധാന(പൂർണ്ണസംഖ്യ argc, അക്ഷരം **argv)
{
	അക്ഷരം comment[താക്കോൽ_COMMENT_MAX], *passphrase = ശൂന്യ;
	അക്ഷരം *rr_hostname = ശൂന്യ, *ep, *fp, *ra;
	ഘടന sshkey *സ്വകാര്യ = ശൂന്യ, *പൊതു = ശൂന്യ;
	ഘടന passwd *pw;
	പൂർണ്ണസംഖ്യ ret = 0, r, opt, type;
	പൂർണ്ണസംഖ്യ change_passphrase = 0, change_comment = 0, show_cert = 0;
	പൂർണ്ണസംഖ്യ find_host = 0, delete_host = 0, hash_hosts = 0;
	പൂർണ്ണസംഖ്യ gen_all_hostkeys = 0, gen_krl = 0, update_krl = 0, check_krl = 0;
	പൂർണ്ണസംഖ്യ prefer_agent = 0, convert_to = 0, convert_from = 0;
	പൂർണ്ണസംഖ്യ print_public = 0, print_generic = 0, cert_serial_autoinc = 0;
	പൂർണ്ണസംഖ്യ do_gen_candidates = 0, do_screen_candidates = 0, download_sk = 0;
	unsigned long long cert_serial = 0;
	അക്ഷരം *identity_comment = ശൂന്യ, *ca_താക്കോൽ_path = ശൂന്യ, **opts = ശൂന്യ;
	അക്ഷരം *sk_application = ശൂന്യ, *sk_device = ശൂന്യ, *sk_user = ശൂന്യ;
	അക്ഷരം *sk_attestation_path = ശൂന്യ;
	ഘടന sshbuf *challenge = ശൂന്യ, *attest = ശൂന്യ;
	size_t i, nopts = 0;
	uint32_t bits = 0;
	uint8_t sk_flags = SSH_SK_USER_PRESENCE_REQD;
	സ്ഥിരം അക്ഷരം *errstr, *p;
	പൂർണ്ണസംഖ്യ log_level = SYSLOG_LEVEL_INFO;
	അക്ഷരം *sign_op = ശൂന്യ;

	ബാഹ്യ പൂർണ്ണസംഖ്യ optind;
	ബാഹ്യ അക്ഷരം *optarg;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	__progname = ssh_get_progname(argv[0]);

	seed_rng();

	log_init(argv[0], SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_USER, 1);

	msetlocale();

	/* we need this for the home * directory.  */
	pw = getpwuid(getuid());
	എങ്കിൽ (!pw)
		fatal("No user exists for uid %lu", (u_long)getuid());
	pw = pwcopy(pw);
	എങ്കിൽ (gethostname(hostname, വലുപ്പം(hostname)) == -1)
		fatal("gethostname: %s", strerror(errno));

	sk_provider = getenv("SSH_SK_PROVIDER");

	/* Remaining characters: dGjJSTWx */
	ആകുമ്പോൾ ((opt = getopt(argc, argv, "ABHKLQUXceghiklopquvy"
	    "C:D:E:F:I:M:N:O:P:R:V:Y:Z:"
	    "a:b:f:g:m:n:r:s:t:w:z:")) != -1) {
		തിരഞ്ഞെടുപ്പ് (opt) {
		അവസ്ഥ 'A':
			gen_all_hostkeys = 1;
			നിർത്തുക;
		അവസ്ഥ 'b':
			bits = (uint32_t)strtonum(optarg, 1, UINT32_MAX,
			    &errstr);
			എങ്കിൽ (errstr)
				fatal("Bits has bad value %s (%s)",
					optarg, errstr);
			നിർത്തുക;
		അവസ്ഥ 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			എങ്കിൽ (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			നിർത്തുക;
		അവസ്ഥ 'F':
			find_host = 1;
			rr_hostname = optarg;
			നിർത്തുക;
		അവസ്ഥ 'H':
			hash_hosts = 1;
			നിർത്തുക;
		അവസ്ഥ 'I':
			cert_താക്കോൽ_id = optarg;
			നിർത്തുക;
		അവസ്ഥ 'R':
			delete_host = 1;
			rr_hostname = optarg;
			നിർത്തുക;
		അവസ്ഥ 'L':
			show_cert = 1;
			നിർത്തുക;
		അവസ്ഥ 'l':
			print_fingerprint = 1;
			നിർത്തുക;
		അവസ്ഥ 'B':
			print_bubblebabble = 1;
			നിർത്തുക;
		അവസ്ഥ 'm':
			എങ്കിൽ (strcasecmp(optarg, "RFC4716") == 0 ||
			    strcasecmp(optarg, "ssh2") == 0) {
				convert_format = FMT_RFC4716;
				നിർത്തുക;
			}
			എങ്കിൽ (strcasecmp(optarg, "PKCS8") == 0) {
				convert_format = FMT_PKCS8;
				private_താക്കോൽ_format = SSHKEY_PRIVATE_PKCS8;
				നിർത്തുക;
			}
			എങ്കിൽ (strcasecmp(optarg, "PEM") == 0) {
				convert_format = FMT_PEM;
				private_താക്കോൽ_format = SSHKEY_PRIVATE_PEM;
				നിർത്തുക;
			}
			എങ്കിൽ (strcasecmp(optarg, "hexdump") == 0) {
				convert_format = FMT_HEXDUMP;
				നിർത്തുക;
			}
			fatal("Unsupported conversion format \"%s\"", optarg);
		അവസ്ഥ 'n':
			cert_principals = optarg;
			നിർത്തുക;
		അവസ്ഥ 'o':
			/* no-op; new format is already the default */
			നിർത്തുക;
		അവസ്ഥ 'p':
			change_passphrase = 1;
			നിർത്തുക;
		അവസ്ഥ 'c':
			change_comment = 1;
			നിർത്തുക;
		അവസ്ഥ 'f':
			എങ്കിൽ (strlcpy(identity_file, optarg,
			    വലുപ്പം(identity_file)) >= വലുപ്പം(identity_file))
				fatal("Identity filename too long");
			have_identity = 1;
			നിർത്തുക;
		അവസ്ഥ 'g':
			print_generic = 1;
			നിർത്തുക;
		അവസ്ഥ 'K':
			download_sk = 1;
			നിർത്തുക;
		അവസ്ഥ 'P':
			identity_passphrase = optarg;
			നിർത്തുക;
		അവസ്ഥ 'N':
			identity_new_passphrase = optarg;
			നിർത്തുക;
		അവസ്ഥ 'Q':
			check_krl = 1;
			നിർത്തുക;
		അവസ്ഥ 'O':
			opts = xrecallocarray(opts, nopts, nopts + 1,
			    വലുപ്പം(*opts));
			opts[nopts++] = xstrdup(optarg);
			നിർത്തുക;
		അവസ്ഥ 'Z':
			openssh_format_cipher = optarg;
			എങ്കിൽ (cipher_by_name(openssh_format_cipher) == ശൂന്യ)
				fatal("Invalid OpenSSH-format cipher '%s'",
				    openssh_format_cipher);
			നിർത്തുക;
		അവസ്ഥ 'C':
			identity_comment = optarg;
			നിർത്തുക;
		അവസ്ഥ 'q':
			quiet = 1;
			നിർത്തുക;
		അവസ്ഥ 'e':
			/* export key */
			convert_to = 1;
			നിർത്തുക;
		അവസ്ഥ 'h':
			cert_താക്കോൽ_type = SSH2_CERT_TYPE_HOST;
			certflags_flags = 0;
			നിർത്തുക;
		അവസ്ഥ 'k':
			gen_krl = 1;
			നിർത്തുക;
		അവസ്ഥ 'i':
		അവസ്ഥ 'X':
			/* import key */
			convert_from = 1;
			നിർത്തുക;
		അവസ്ഥ 'y':
			print_public = 1;
			നിർത്തുക;
		അവസ്ഥ 's':
			ca_താക്കോൽ_path = optarg;
			നിർത്തുക;
		അവസ്ഥ 't':
			താക്കോൽ_type_name = optarg;
			നിർത്തുക;
		അവസ്ഥ 'D':
			pkcs11provider = optarg;
			നിർത്തുക;
		അവസ്ഥ 'U':
			prefer_agent = 1;
			നിർത്തുക;
		അവസ്ഥ 'u':
			update_krl = 1;
			നിർത്തുക;
		അവസ്ഥ 'v':
			എങ്കിൽ (log_level == SYSLOG_LEVEL_INFO)
				log_level = SYSLOG_LEVEL_DEBUG1;
			അല്ലെങ്കിൽ {
				എങ്കിൽ (log_level >= SYSLOG_LEVEL_DEBUG1 &&
				    log_level < SYSLOG_LEVEL_DEBUG3)
					log_level++;
			}
			നിർത്തുക;
		അവസ്ഥ 'r':
			rr_hostname = optarg;
			നിർത്തുക;
		അവസ്ഥ 'a':
			rounds = (പൂർണ്ണസംഖ്യ)strtonum(optarg, 1, INT_MAX, &errstr);
			എങ്കിൽ (errstr)
				fatal("Invalid number: %s (%s)",
					optarg, errstr);
			നിർത്തുക;
		അവസ്ഥ 'V':
			parse_cert_times(optarg);
			നിർത്തുക;
		അവസ്ഥ 'Y':
			sign_op = optarg;
			നിർത്തുക;
		അവസ്ഥ 'w':
			sk_provider = optarg;
			നിർത്തുക;
		അവസ്ഥ 'z':
			errno = 0;
			എങ്കിൽ (*optarg == '+') {
				cert_serial_autoinc = 1;
				optarg++;
			}
			cert_serial = strtoull(optarg, &ep, 10);
			എങ്കിൽ (*optarg < '0' || *optarg > '9' || *ep != '\0' ||
			    (errno == ERANGE && cert_serial == ULLONG_MAX))
				fatal("Invalid serial number \"%s\"", optarg);
			നിർത്തുക;
		അവസ്ഥ 'M':
			എങ്കിൽ (strcmp(optarg, "generate") == 0)
				do_gen_candidates = 1;
			അല്ലെങ്കിൽ എങ്കിൽ (strcmp(optarg, "screen") == 0)
				do_screen_candidates = 1;
			അല്ലെങ്കിൽ
				fatal("Unsupported moduli option %s", optarg);
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			usage();
		}
	}

#ifdef ENABLE_SK_INTERNAL
	എങ്കിൽ (sk_provider == ശൂന്യ)
		sk_provider = "internal";
#endif

	/* reinit */
	log_init(argv[0], log_level, SYSLOG_FACILITY_USER, 1);

	argv += optind;
	argc -= optind;

	എങ്കിൽ (sign_op != ശൂന്യ) {
		എങ്കിൽ (strprefix(sign_op, "find-principals", 0) != ശൂന്യ) {
			എങ്കിൽ (ca_താക്കോൽ_path == ശൂന്യ) {
				error("Too few arguments for find-principals:"
				    "missing signature file");
				exit(1);
			}
			എങ്കിൽ (!have_identity) {
				error("Too few arguments for find-principals:"
				    "missing allowed keys file");
				exit(1);
			}
			ret = sig_find_principals(ca_താക്കോൽ_path, identity_file,
			    opts, nopts);
			പോകുക done;
		} അല്ലെങ്കിൽ എങ്കിൽ (strprefix(sign_op, "match-principals", 0) != ശൂന്യ) {
			എങ്കിൽ (!have_identity) {
				error("Too few arguments for match-principals:"
				    "missing allowed keys file");
				exit(1);
			}
			എങ്കിൽ (cert_താക്കോൽ_id == ശൂന്യ) {
				error("Too few arguments for match-principals: "
				    "missing principal ID");
				exit(1);
			}
			ret = sig_match_principals(identity_file, cert_താക്കോൽ_id,
			    opts, nopts);
			പോകുക done;
		} അല്ലെങ്കിൽ എങ്കിൽ (strprefix(sign_op, "sign", 0) != ശൂന്യ) {
			/* NB. cert_principals is actually namespace, via -n */
			എങ്കിൽ (cert_principals == ശൂന്യ ||
			    *cert_principals == '\0') {
				error("Too few arguments for sign: "
				    "missing namespace");
				exit(1);
			}
			എങ്കിൽ (!have_identity) {
				error("Too few arguments for sign: "
				    "missing key");
				exit(1);
			}
			ret = sig_sign(identity_file, cert_principals,
			    prefer_agent, argc, argv, opts, nopts);
			പോകുക done;
		} അല്ലെങ്കിൽ എങ്കിൽ (strprefix(sign_op, "check-novalidate", 0) != ശൂന്യ) {
			/* NB. cert_principals is actually namespace, via -n */
			എങ്കിൽ (cert_principals == ശൂന്യ ||
			    *cert_principals == '\0') {
				error("Too few arguments for check-novalidate: "
				    "missing namespace");
				exit(1);
			}
			എങ്കിൽ (ca_താക്കോൽ_path == ശൂന്യ) {
				error("Too few arguments for check-novalidate: "
				    "missing signature file");
				exit(1);
			}
			ret = sig_verify(ca_താക്കോൽ_path, cert_principals,
			    ശൂന്യ, ശൂന്യ, ശൂന്യ, opts, nopts);
			പോകുക done;
		} അല്ലെങ്കിൽ എങ്കിൽ (strprefix(sign_op, "verify", 0) != ശൂന്യ) {
			/* NB. cert_principals is actually namespace, via -n */
			എങ്കിൽ (cert_principals == ശൂന്യ ||
			    *cert_principals == '\0') {
				error("Too few arguments for verify: "
				    "missing namespace");
				exit(1);
			}
			എങ്കിൽ (ca_താക്കോൽ_path == ശൂന്യ) {
				error("Too few arguments for verify: "
				    "missing signature file");
				exit(1);
			}
			എങ്കിൽ (!have_identity) {
				error("Too few arguments for sign: "
				    "missing allowed keys file");
				exit(1);
			}
			എങ്കിൽ (cert_താക്കോൽ_id == ശൂന്യ) {
				error("Too few arguments for verify: "
				    "missing principal identity");
				exit(1);
			}
			ret = sig_verify(ca_താക്കോൽ_path, cert_principals,
			    cert_താക്കോൽ_id, identity_file, rr_hostname,
			    opts, nopts);
			പോകുക done;
		}
		error("Unsupported operation for -Y: \"%s\"", sign_op);
		usage();
		/* NOTREACHED */
	}

	എങ്കിൽ (ca_താക്കോൽ_path != ശൂന്യ) {
		എങ്കിൽ (argc < 1 && !gen_krl) {
			error("Too few arguments.");
			usage();
		}
	} അല്ലെങ്കിൽ എങ്കിൽ (argc > 0 && !gen_krl && !check_krl &&
	    !do_gen_candidates && !do_screen_candidates) {
		error("Too many arguments.");
		usage();
	}
	എങ്കിൽ (change_passphrase && change_comment) {
		error("Can only have one of -p and -c.");
		usage();
	}
	എങ്കിൽ (print_fingerprint && (delete_host || hash_hosts)) {
		error("Cannot use -l with -H or -R.");
		usage();
	}
	എങ്കിൽ (gen_krl) {
		do_gen_krl(pw, update_krl, ca_താക്കോൽ_path,
		    cert_serial, identity_comment, argc, argv);
		പോകുക done;
	}
	എങ്കിൽ (check_krl) {
		do_check_krl(pw, print_fingerprint, argc, argv);
		പോകുക done;
	}
	എങ്കിൽ (ca_താക്കോൽ_path != ശൂന്യ) {
		എങ്കിൽ (cert_താക്കോൽ_id == ശൂന്യ)
			fatal("Must specify key id (-I) when certifying");
		എങ്കിൽ (cert_principals == ശൂന്യ) {
			/*
			 * Ideally this would be a fatal(), but we need to
			 * be able to generate such certificates for testing
			 * even though they will be rejected.
			 */
			error("Warning: certificate will contain no "
			    "principals (-n)");
		}
		വേണ്ടി (i = 0; i < nopts; i++)
			add_cert_option(opts[i]);
		do_ca_sign(pw, ca_താക്കോൽ_path, prefer_agent,
		    cert_serial, cert_serial_autoinc, argc, argv);
		പോകുക done;
	}
	എങ്കിൽ (show_cert)
		do_show_cert(pw);
	എങ്കിൽ (delete_host || hash_hosts || find_host) {
		do_known_hosts(pw, rr_hostname, find_host,
		    delete_host, hash_hosts);
	}
	എങ്കിൽ (pkcs11provider != ശൂന്യ)
		do_download(pw);
	എങ്കിൽ (download_sk) {
		വേണ്ടി (i = 0; i < nopts; i++) {
			എങ്കിൽ ((p = strprefix(opts[i], "device=", 1)) != ശൂന്യ) {
				sk_device = xstrdup(p);
			} അല്ലെങ്കിൽ {
				fatal("Option \"%s\" is unsupported for "
				    "FIDO authenticator download", opts[i]);
			}
		}
		ret = do_download_sk(sk_provider, sk_device);
		പോകുക done;
	}
	എങ്കിൽ (print_fingerprint || print_bubblebabble)
		do_fingerprint(pw);
	എങ്കിൽ (change_passphrase)
		do_change_passphrase(pw, opts, nopts);
	എങ്കിൽ (change_comment)
		do_change_comment(pw, identity_comment);
#ifdef WITH_OPENSSL
	എങ്കിൽ (convert_to) {
		do_convert_to(pw);
		പോകുക done;
	}
	എങ്കിൽ (convert_from) {
		do_convert_from(pw);
		പോകുക done;
	}
#അല്ലെങ്കിൽ /* WITH_OPENSSL */
	എങ്കിൽ (convert_to || convert_from)
		fatal("key conversion disabled at compile time");
#endif /* WITH_OPENSSL */
	എങ്കിൽ (print_public)
		do_print_public(pw);
	എങ്കിൽ (rr_hostname != ശൂന്യ) {
		unsigned പൂർണ്ണസംഖ്യ n = 0;

		എങ്കിൽ (have_identity) {
			n = do_print_resource_record(pw, identity_file,
			    rr_hostname, print_generic, opts, nopts);
			എങ്കിൽ (n == 0)
				fatal("%s: %s", identity_file, strerror(errno));
			exit(0);
		} അല്ലെങ്കിൽ {

			n += do_print_resource_record(pw,
			    PATH_HOST_RSA_താക്കോൽ_FILE, rr_hostname,
			    print_generic, opts, nopts);
			n += do_print_resource_record(pw,
			    PATH_HOST_ECDSA_താക്കോൽ_FILE, rr_hostname,
			    print_generic, opts, nopts);
			n += do_print_resource_record(pw,
			    PATH_HOST_ED25519_താക്കോൽ_FILE, rr_hostname,
			    print_generic, opts, nopts);
			എങ്കിൽ (n == 0)
				fatal("no keys found.");
			exit(0);
		}
	}

	എങ്കിൽ (do_gen_candidates || do_screen_candidates) {
		എങ്കിൽ (argc <= 0)
			fatal("No output file specified");
		അല്ലെങ്കിൽ എങ്കിൽ (argc > 1)
			fatal("Too many output files specified");
	}
	എങ്കിൽ (do_gen_candidates) {
		do_moduli_gen(argv[0], opts, nopts);
		പോകുക done;
	}
	എങ്കിൽ (do_screen_candidates) {
		do_moduli_screen(argv[0], opts, nopts);
		പോകുക done;
	}

	എങ്കിൽ (gen_all_hostkeys) {
		do_gen_all_hostkeys(pw);
		പോകുക done;
	}

	എങ്കിൽ (താക്കോൽ_type_name == ശൂന്യ)
		താക്കോൽ_type_name = DEFAULT_താക്കോൽ_TYPE_NAME;

	type = sshkey_type_from_shortname(താക്കോൽ_type_name);
	type_bits_valid(type, താക്കോൽ_type_name, &bits);

	എങ്കിൽ (!quiet)
		printf("Generating public/private %s key pair.\n",
		    താക്കോൽ_type_name);
	തിരഞ്ഞെടുപ്പ് (type) {
	അവസ്ഥ താക്കോൽ_ECDSA_SK:
	അവസ്ഥ താക്കോൽ_ED25519_SK:
		വേണ്ടി (i = 0; i < nopts; i++) {
			എങ്കിൽ (strcasecmp(opts[i], "no-touch-required") == 0) {
				sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
			} അല്ലെങ്കിൽ എങ്കിൽ (strcasecmp(opts[i], "verify-required") == 0) {
				sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
			} അല്ലെങ്കിൽ എങ്കിൽ (strcasecmp(opts[i], "resident") == 0) {
				sk_flags |= SSH_SK_RESIDENT_താക്കോൽ;
			} അല്ലെങ്കിൽ എങ്കിൽ ((p = strprefix(opts[i], "device=", 1))
			    != ശൂന്യ ) {
				sk_device = xstrdup(p);
			} അല്ലെങ്കിൽ എങ്കിൽ ((p = strprefix(opts[i], "user=", 1))
			    != ശൂന്യ) {
				sk_user = xstrdup(p);
			} അല്ലെങ്കിൽ എങ്കിൽ ((p = strprefix(opts[i], "challenge=", 1))
			    != ശൂന്യ) {
				എങ്കിൽ ((r = sshbuf_load_file(p,
				    &challenge)) != 0) {
					fatal_r(r, "Unable to load FIDO "
					    "enrollment challenge \"%s\"", p);
				}
			} അല്ലെങ്കിൽ എങ്കിൽ (strncasecmp(opts[i],
			    "write-attestation=", 18) == 0) {
				sk_attestation_path = opts[i] + 18;
			} അല്ലെങ്കിൽ എങ്കിൽ (strncasecmp(opts[i],
			    "application=", 12) == 0) {
				sk_application = xstrdup(opts[i] + 12);
				എങ്കിൽ (strncmp(sk_application, "ssh:", 4) != 0) {
					fatal("FIDO application string must "
					    "begin with \"ssh:\"");
				}
			} അല്ലെങ്കിൽ {
				fatal("Option \"%s\" is unsupported for "
				    "FIDO authenticator enrollment", opts[i]);
			}
		}
		എങ്കിൽ ((attest = sshbuf_new()) == ശൂന്യ)
			fatal("sshbuf_new failed");
		r = 0;
		വേണ്ടി (i = 0 ;;) {
			എങ്കിൽ (!quiet) {
				printf("You may need to touch your "
				    "authenticator%s to authorize key "
				    "generation.\n",
				    r == 0 ? "" : " again");
			}
			fflush(stdout);
			r = sshsk_enroll(type, sk_provider, sk_device,
			    sk_application == ശൂന്യ ? "ssh:" : sk_application,
			    sk_user, sk_flags, passphrase, challenge,
			    &സ്വകാര്യ, attest);
			എങ്കിൽ (r == 0)
				നിർത്തുക;
			എങ്കിൽ (r == SSH_ERR_താക്കോൽ_BAD_PERMISSIONS &&
			    (sk_flags & SSH_SK_RESIDENT_താക്കോൽ) != 0 &&
			    (sk_flags & SSH_SK_FORCE_OPERATION) == 0 &&
			    confirm_sk_overwrite(sk_application, sk_user)) {
				sk_flags |= SSH_SK_FORCE_OPERATION;
				തുടരുക;
			}
			എങ്കിൽ (r != SSH_ERR_താക്കോൽ_WRONG_PASSPHRASE)
				fatal_r(r, "Key enrollment failed");
			അല്ലെങ്കിൽ എങ്കിൽ (passphrase != ശൂന്യ) {
				error("PIN incorrect");
				freezero(passphrase, strlen(passphrase));
				passphrase = ശൂന്യ;
			}
			എങ്കിൽ (++i >= 3)
				fatal("Too many incorrect PINs");
			passphrase = read_passphrase("Enter PIN for "
			    "authenticator: ", RP_ALLOW_STDIN);
		}
		എങ്കിൽ (passphrase != ശൂന്യ) {
			freezero(passphrase, strlen(passphrase));
			passphrase = ശൂന്യ;
		}
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		എങ്കിൽ ((r = sshkey_generate(type, bits, &സ്വകാര്യ)) != 0)
			fatal("sshkey_generate failed");
		നിർത്തുക;
	}
	എങ്കിൽ ((r = sshkey_from_private(സ്വകാര്യ, &പൊതു)) != 0)
		fatal_r(r, "sshkey_from_private");

	എങ്കിൽ (!have_identity)
		ask_filename(pw, "Enter file in which to save the key");

	/* Create ~/.ssh directory if it doesn't already exist. */
	hostfile_create_user_ssh_dir(identity_file, !quiet);

	/* If the file already exists, ask the user to confirm. */
	എങ്കിൽ (!confirm_overwrite(identity_file))
		exit(1);

	/* Determine the passphrase for the private key */
	passphrase = private_താക്കോൽ_passphrase(identity_file);
	എങ്കിൽ (identity_comment) {
		strlcpy(comment, identity_comment, വലുപ്പം(comment));
	} അല്ലെങ്കിൽ {
		/* Create default comment field for the passphrase. */
		snprintf(comment, വലുപ്പം comment, "%s@%s", pw->pw_name, hostname);
	}



	/* Save the key with the given passphrase and comment. */
	എങ്കിൽ ((r = sshkey_save_private(സ്വകാര്യ, identity_file, passphrase,
	    comment, private_താക്കോൽ_format, openssh_format_cipher, rounds)) != 0) {
		error_r(r, "Saving key \"%s\" failed", identity_file);
		freezero(passphrase, strlen(passphrase));
		exit(1);
	}
	freezero(passphrase, strlen(passphrase));
	sshkey_free(സ്വകാര്യ);

	എങ്കിൽ (!quiet) {
		printf("Your identification has been saved in %s\n",
		    identity_file);
	}

	strlcat(identity_file, ".pub", വലുപ്പം(identity_file));
	എങ്കിൽ ((r = sshkey_save_public(പൊതു, identity_file, comment)) != 0)
		fatal_r(r, "Unable to save public key to %s", identity_file);

	എങ്കിൽ (!quiet) {
		fp = sshkey_fingerprint(പൊതു, fingerprint_hash,
		    SSH_FP_DEFAULT);
		ra = sshkey_fingerprint(പൊതു, fingerprint_hash,
		    SSH_FP_RANDOMART);
		എങ്കിൽ (fp == ശൂന്യ || ra == ശൂന്യ)
			fatal("sshkey_fingerprint failed");
		printf("Your public key has been saved in %s\n",
		    identity_file);
		printf("The key fingerprint is:\n");
		printf("%s %s\n", fp, comment);
		printf("The key's randomart image is:\n");
		printf("%s\n", ra);
		സ്വതന്ത്രം(ra);
		സ്വതന്ത്രം(fp);
	}

	എങ്കിൽ (sk_attestation_path != ശൂന്യ)
		save_attestation(attest, sk_attestation_path);

 done:
	sshbuf_free(attest);
	sshkey_free(പൊതു);
	pwfree(pw);
	exit(ret);
}
