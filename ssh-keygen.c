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

#include "includes.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>

#ifdef WITH_OPENSSL
#include "openbsd-compat/openssl-compat.h"
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#endif

#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <paths.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <locale.h>
#include <time.h>

#include "xmalloc.h"
#include "sshkey.h"
#include "authfile.h"
#include "sshbuf.h"
#include "pathnames.h"
#include "log.h"
#include "misc.h"
#include "match.h"
#include "hostfile.h"
#include "dns.h"
#include "ssh.h"
#include "ssh2.h"
#include "ssherr.h"
#include "atomicio.h"
#include "krl.h"
#include "digest.h"
#include "utf8.h"
#include "authfd.h"
#include "sshsig.h"
#include "ssh-sk.h"
#include "sk-api.h" /* XXX for SSH_SK_USER_PRESENCE_REQD; remove */
#include "cipher.h"

#ifdef ENABLE_PKCS11
#include "ssh-pkcs11.h"
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

static ціле quiet = 0;

/* Flag indicating that we just want to see the key fingerprint */
static ціле print_fingerprint = 0;
static ціле print_bubblebabble = 0;

/* Hash algorithm to use for fingerprints. */
static ціле fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* The identity file name, given on the command line or entered by the user. */
static char identity_file[PATH_MAX];
static ціле have_identity = 0;

/* This is set to the passphrase if given on the command line. */
static char *identity_passphrase = NULL;

/* This is set to the new passphrase if given on the command line. */
static char *identity_new_passphrase = NULL;

/* Key type when certifying */
static u_int cert_key_type = SSH2_CERT_TYPE_USER;

/* "key ID" of signed key */
static char *cert_key_id = NULL;

/* Comma-separated list of principal names for certifying keys */
static char *cert_principals = NULL;

/* Validity period for certificates */
static uint64_t cert_valid_from = 0;
static uint64_t cert_valid_to = ~0ULL;

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
static uint32_t certflags_flags = CERTOPT_DEFAULT;
static char *certflags_command = NULL;
static char *certflags_src_addr = NULL;

/* Arbitrary extensions specified by user */
struct cert_ext {
	char *key;
	char *val;
	ціле crit;
};
static struct cert_ext *cert_ext;
static size_t ncert_ext;

/* Conversion to/from various formats */
enum {
	FMT_RFC4716,
	FMT_PKCS8,
	FMT_PEM,
	FMT_HEXDUMP
} convert_format = FMT_RFC4716;

static char *key_type_name = NULL;

/* Load key from this PKCS#11 provider */
static char *pkcs11provider = NULL;

/* FIDO/U2F provider to use */
static char *sk_provider = NULL;

/* Format for writing private keys */
static ціле private_key_format = SSHKEY_PRIVATE_OPENSSH;

/* Cipher for new-format private keys */
static char *openssh_format_cipher = NULL;

/* Number of KDF rounds to derive new format keys. */
static ціле rounds = 0;

/* argv0 */
extern char *__progname;

static char hostname[NI_MAXHOST];

#ifdef WITH_OPENSSL
/* moduli.c */
ціле gen_candidates(FILE *, uint32_t, BIGNUM *);
ціле prime_test(FILE *, FILE *, uint32_t, uint32_t, char *, unsigned long,
    unsigned long);
#endif

static void
type_bits_valid(ціле type, const char *name, uint32_t *bitsp)
{
	якщо (type == KEY_UNSPEC)
		fatal("unknown key type %s", key_type_name);
	якщо (*bitsp == 0) {
#ifdef WITH_OPENSSL
		ціле nid;

		switch(type) {
		case KEY_ECDSA:
			якщо (name != NULL &&
			    (nid = sshkey_ecdsa_nid_from_name(name)) > 0)
				*bitsp = sshkey_curve_nid_to_bits(nid);
			якщо (*bitsp == 0)
				*bitsp = DEFAULT_BITS_ECDSA;
			break;
		case KEY_RSA:
			*bitsp = DEFAULT_BITS;
			break;
		}
#endif
	}
#ifdef WITH_OPENSSL
	switch (type) {
	case KEY_RSA:
		якщо (*bitsp < SSH_RSA_MINIMUM_MODULUS_SIZE)
			fatal("Invalid RSA key length: minimum is %d bits",
			    SSH_RSA_MINIMUM_MODULUS_SIZE);
		інакше якщо (*bitsp > OPENSSL_RSA_MAX_MODULUS_BITS)
			fatal("Invalid RSA key length: maximum is %d bits",
			    OPENSSL_RSA_MAX_MODULUS_BITS);
		break;
	case KEY_ECDSA:
		якщо (sshkey_ecdsa_bits_to_nid(*bitsp) == -1)
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
static ціле
confirm_overwrite(const char *filename)
{
	char yesno[3];
	struct stat st;

	якщо (stat(filename, &st) != 0)
		повернути 1;
	printf("%s already exists.\n", filename);
	printf("Overwrite (y/n)? ");
	fflush(stdout);
	якщо (fgets(yesno, sizeof(yesno), stdin) == NULL)
		повернути 0;
	якщо (yesno[0] != 'y' && yesno[0] != 'Y')
		повернути 0;
	повернути 1;
}

static void
ask_filename(struct passwd *pw, const char *prompt)
{
	char buf[1024];
	char *name = NULL;

	якщо (key_type_name == NULL)
		name = _PATH_SSH_CLIENT_ID_ED25519;
	інакше {
		switch (sshkey_type_from_shortname(key_type_name)) {
		case KEY_ECDSA_CERT:
		case KEY_ECDSA:
			name = _PATH_SSH_CLIENT_ID_ECDSA;
			break;
		case KEY_ECDSA_SK_CERT:
		case KEY_ECDSA_SK:
			name = _PATH_SSH_CLIENT_ID_ECDSA_SK;
			break;
		case KEY_RSA_CERT:
		case KEY_RSA:
			name = _PATH_SSH_CLIENT_ID_RSA;
			break;
		case KEY_ED25519:
		case KEY_ED25519_CERT:
			name = _PATH_SSH_CLIENT_ID_ED25519;
			break;
		case KEY_ED25519_SK:
		case KEY_ED25519_SK_CERT:
			name = _PATH_SSH_CLIENT_ID_ED25519_SK;
			break;
		case KEY_MLDSA44_ED25519:
		case KEY_MLDSA44_ED25519_CERT:
			name = _PATH_SSH_CLIENT_ID_MLDSA44_ED25519;
			break;
		default:
			fatal("bad key type");
		}
	}
	snprintf(identity_file, sizeof(identity_file),
	    "%s/%s", pw->pw_dir, name);
	printf("%s (%s): ", prompt, identity_file);
	fflush(stdout);
	якщо (fgets(buf, sizeof(buf), stdin) == NULL)
		exit(1);
	buf[strcspn(buf, "\n")] = '\0';
	якщо (strcmp(buf, "") != 0)
		strlcpy(identity_file, buf, sizeof(identity_file));
	have_identity = 1;
}

static struct sshkey *
load_identity(const char *filename, char **commentp)
{
	char *prompt, *pass;
	struct sshkey *prv;
	ціле r;

	якщо (commentp != NULL)
		*commentp = NULL;
	якщо ((r = sshkey_load_private(filename, "", &prv, commentp)) == 0)
		повернути prv;
	якщо (r != SSH_ERR_KEY_WRONG_PASSPHRASE)
		fatal_r(r, "Load key \"%s\"", filename);
	якщо (identity_passphrase)
		pass = xstrdup(identity_passphrase);
	інакше {
		xasprintf(&prompt, "Enter passphrase for \"%s\": ", filename);
		pass = read_passphrase(prompt, RP_ALLOW_STDIN);
		free(prompt);
	}
	r = sshkey_load_private(filename, pass, &prv, commentp);
	freezero(pass, strlen(pass));
	якщо (r != 0)
		fatal_r(r, "Load key \"%s\"", filename);
	повернути prv;
}

#define SSH_COM_PUBLIC_BEGIN		"---- BEGIN SSH2 PUBLIC KEY ----"
#define SSH_COM_PUBLIC_END		"---- END SSH2 PUBLIC KEY ----"
#define SSH_COM_PRIVATE_BEGIN		"---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----"
#define	SSH_COM_PRIVATE_KEY_MAGIC	0x3f6ff9eb

#ifdef WITH_OPENSSL
static void
do_convert_to_ssh2(struct passwd *pw, struct sshkey *k)
{
	struct sshbuf *b;
	char comment[61], *b64;
	ціле r;

	якщо ((b = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	якщо ((r = sshkey_putb(k, b)) != 0)
		fatal_fr(r, "put key");
	якщо ((b64 = sshbuf_dtob64_string(b, 1)) == NULL)
		fatal_f("sshbuf_dtob64_string failed");

	/* Comment + surrounds must fit into 72 chars (RFC 4716 sec 3.3) */
	snprintf(comment, sizeof(comment),
	    "%u-bit %s, converted by %s@%s from OpenSSH",
	    sshkey_size(k), sshkey_type(k),
	    pw->pw_name, hostname);

	sshkey_free(k);
	sshbuf_free(b);

	fprintf(stdout, "%s\n", SSH_COM_PUBLIC_BEGIN);
	fprintf(stdout, "Comment: \"%s\"\n%s", comment, b64);
	fprintf(stdout, "%s\n", SSH_COM_PUBLIC_END);
	free(b64);
}

static void
do_convert_to_pkcs8(struct sshkey *k)
{
	switch (sshkey_type_plain(k->type)) {
	case KEY_RSA:
		якщо (!PEM_write_RSA_PUBKEY(stdout,
		    EVP_PKEY_get0_RSA(k->pkey)))
			fatal("PEM_write_RSA_PUBKEY failed");
		break;
	case KEY_ECDSA:
		якщо (!PEM_write_EC_PUBKEY(stdout,
		    EVP_PKEY_get0_EC_KEY(k->pkey)))
			fatal("PEM_write_EC_PUBKEY failed");
		break;
	default:
		fatal_f("unsupported key type %s", sshkey_type(k));
	}
}

static void
do_convert_to_pem(struct sshkey *k)
{
	switch (sshkey_type_plain(k->type)) {
	case KEY_RSA:
		якщо (!PEM_write_RSAPublicKey(stdout,
		    EVP_PKEY_get0_RSA(k->pkey)))
			fatal("PEM_write_RSAPublicKey failed");
		break;
	case KEY_ECDSA:
		якщо (!PEM_write_EC_PUBKEY(stdout,
		    EVP_PKEY_get0_EC_KEY(k->pkey)))
			fatal("PEM_write_EC_PUBKEY failed");
		break;
	default:
		fatal_f("unsupported key type %s", sshkey_type(k));
	}
}

static void
do_convert_to_hexdump(struct sshkey *k)
{
	struct sshbuf *b;
	ціле r;

	якщо ((b = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	/* pubkey */
	якщо ((r = sshkey_putb(k, b)) != 0)
		fatal_fr(r, "serialise private");
	printf("Public %s key:\n", sshkey_type(k));
	sshbuf_dump(b, stdout);
	sshbuf_reset(b);
	якщо ((r = sshkey_private_serialize(k, b)) != 0) {
		debug_fr(r, "serialise private");
		goto out;
	}
	printf("\nPrivate %s key:\n", sshkey_type(k));
	sshbuf_dump(b, stdout);
 out:
	sshbuf_free(b);
}

static void
do_convert_to(struct passwd *pw)
{
	struct sshkey *k = NULL;
	struct stat st;
	ціле r;

	якщо (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	якщо (stat(identity_file, &st) == -1)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));

	/* If we're trying to hexdump, then prefer the private key */
	якщо (convert_format == FMT_HEXDUMP) {
		якщо ((r = sshkey_load_private(identity_file,
		    NULL, &k, NULL)) != 0 &&
		    r == SSH_ERR_KEY_WRONG_PASSPHRASE)
			k = load_identity(identity_file, NULL);
	}
	якщо (k == NULL && (r = sshkey_load_public(identity_file, &k, NULL)) != 0)
		k = load_identity(identity_file, NULL);

	switch (convert_format) {
	case FMT_RFC4716:
		do_convert_to_ssh2(pw, k);
		break;
	case FMT_PKCS8:
		do_convert_to_pkcs8(k);
		break;
	case FMT_PEM:
		do_convert_to_pem(k);
		break;
	case FMT_HEXDUMP:
		do_convert_to_hexdump(k);
		break;
	default:
		fatal_f("unknown key format %d", convert_format);
	}
}

/*
 * This is almost exactly the bignum1 encoding, but with 32 bit for length
 * instead of 16.
 */
static void
buffer_get_bignum_bits(struct sshbuf *b, BIGNUM *value)
{
	u_int bytes, bignum_bits;
	ціле r;

	якщо ((r = sshbuf_get_u32(b, &bignum_bits)) != 0)
		fatal_fr(r, "parse");
	bytes = (bignum_bits + 7) / 8;
	якщо (sshbuf_len(b) < bytes)
		fatal_f("input buffer too small: need %d have %zu",
		    bytes, sshbuf_len(b));
	якщо (BN_bin2bn(sshbuf_ptr(b), bytes, value) == NULL)
		fatal_f("BN_bin2bn failed");
	якщо ((r = sshbuf_consume(b, bytes)) != 0)
		fatal_fr(r, "consume");
}

static struct sshkey *
do_convert_private_ssh2(struct sshbuf *b)
{
	struct sshkey *key = NULL;
	char *type, *cipher;
	const char *alg = NULL;
	u_char e1, e2, e3, *sig = NULL, data[] = "abcde12345";
	ціле r, rlen, ktype;
	u_int magic, i1, i2, i3, i4;
	size_t slen;
	u_long e;
	BIGNUM *rsa_n = NULL, *rsa_e = NULL, *rsa_d = NULL;
	BIGNUM *rsa_p = NULL, *rsa_q = NULL, *rsa_iqmp = NULL;
	BIGNUM *rsa_dmp1 = NULL, *rsa_dmq1 = NULL;
	RSA *rsa = NULL;

	якщо ((r = sshbuf_get_u32(b, &magic)) != 0)
		fatal_fr(r, "parse magic");

	якщо (magic != SSH_COM_PRIVATE_KEY_MAGIC) {
		error("bad magic 0x%x != 0x%x", magic,
		    SSH_COM_PRIVATE_KEY_MAGIC);
		повернути NULL;
	}
	якщо ((r = sshbuf_get_u32(b, &i1)) != 0 ||
	    (r = sshbuf_get_cstring(b, &type, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(b, &cipher, NULL)) != 0 ||
	    (r = sshbuf_get_u32(b, &i2)) != 0 ||
	    (r = sshbuf_get_u32(b, &i3)) != 0 ||
	    (r = sshbuf_get_u32(b, &i4)) != 0)
		fatal_fr(r, "parse");
	debug("ignore (%d %d %d %d)", i1, i2, i3, i4);
	якщо (strcmp(cipher, "none") != 0) {
		error("unsupported cipher %s", cipher);
		free(cipher);
		free(type);
		повернути NULL;
	}
	free(cipher);

	якщо (strstr(type, "rsa")) {
		ktype = KEY_RSA;
	} інакше {
		free(type);
		повернути NULL;
	}
	якщо ((key = sshkey_new(ktype)) == NULL)
		fatal("sshkey_new failed");
	free(type);

	switch (key->type) {
	case KEY_RSA:
		якщо ((r = sshbuf_get_u8(b, &e1)) != 0 ||
		    (e1 < 30 && (r = sshbuf_get_u8(b, &e2)) != 0) ||
		    (e1 < 30 && (r = sshbuf_get_u8(b, &e3)) != 0))
			fatal_fr(r, "parse RSA");
		e = e1;
		debug("e %lx", e);
		якщо (e < 30) {
			e <<= 8;
			e += e2;
			debug("e %lx", e);
			e <<= 8;
			e += e3;
			debug("e %lx", e);
		}
		якщо ((rsa_e = BN_new()) == NULL)
			fatal_f("BN_new");
		якщо (!BN_set_word(rsa_e, e)) {
			BN_clear_free(rsa_e);
			sshkey_free(key);
			повернути NULL;
		}
		якщо ((rsa_n = BN_new()) == NULL ||
		    (rsa_d = BN_new()) == NULL ||
		    (rsa_p = BN_new()) == NULL ||
		    (rsa_q = BN_new()) == NULL ||
		    (rsa_iqmp = BN_new()) == NULL)
			fatal_f("BN_new");
		buffer_get_bignum_bits(b, rsa_d);
		buffer_get_bignum_bits(b, rsa_n);
		buffer_get_bignum_bits(b, rsa_iqmp);
		buffer_get_bignum_bits(b, rsa_q);
		buffer_get_bignum_bits(b, rsa_p);
		якщо ((r = ssh_rsa_complete_crt_parameters(rsa_d, rsa_p, rsa_q,
		    rsa_iqmp, &rsa_dmp1, &rsa_dmq1)) != 0)
			fatal_fr(r, "generate RSA CRT parameters");
		EVP_PKEY_free(key->pkey);
		якщо ((key->pkey = EVP_PKEY_new()) == NULL)
			fatal_f("EVP_PKEY_new failed");
		якщо ((rsa = RSA_new()) == NULL)
			fatal_f("RSA_new failed");
		якщо (!RSA_set0_key(rsa, rsa_n, rsa_e, rsa_d))
			fatal_f("RSA_set0_key failed");
		rsa_n = rsa_e = rsa_d = NULL; /* transferred */
		якщо (!RSA_set0_factors(rsa, rsa_p, rsa_q))
			fatal_f("RSA_set0_factors failed");
		rsa_p = rsa_q = NULL; /* transferred */
		якщо (RSA_set0_crt_params(rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp) != 1)
			fatal_f("RSA_set0_crt_params failed");
		rsa_dmp1 = rsa_dmq1 = rsa_iqmp = NULL;
		якщо (EVP_PKEY_set1_RSA(key->pkey, rsa) != 1)
			fatal_f("EVP_PKEY_set1_RSA failed");
		RSA_free(rsa);
		alg = "rsa-sha2-256";
		break;
	}
	rlen = sshbuf_len(b);
	якщо (rlen != 0)
		error_f("remaining bytes in key blob %d", rlen);

	/* try the key */
	якщо ((r = sshkey_sign(key, &sig, &slen, data, sizeof(data),
	    alg, NULL, NULL, 0)) != 0)
		error_fr(r, "signing with converted key failed");
	інакше якщо ((r = sshkey_verify(key, sig, slen, data, sizeof(data),
	    alg, 0, NULL)) != 0)
		error_fr(r, "verification with converted key failed");
	якщо (r != 0) {
		sshkey_free(key);
		free(sig);
		повернути NULL;
	}
	free(sig);
	повернути key;
}

static ціле
get_line(FILE *fp, char *line, size_t len)
{
	ціле c;
	size_t pos = 0;

	line[0] = '\0';
	поки ((c = fgetc(fp)) != EOF) {
		якщо (pos >= len - 1)
			fatal("input line too long.");
		switch (c) {
		case '\r':
			c = fgetc(fp);
			якщо (c != EOF && c != '\n' && ungetc(c, fp) == EOF)
				fatal("unget: %s", strerror(errno));
			повернути pos;
		case '\n':
			повернути pos;
		}
		line[pos++] = c;
		line[pos] = '\0';
	}
	/* We reached EOF */
	повернути -1;
}

static void
do_convert_from_ssh2(struct passwd *pw, struct sshkey **k, ціле *private)
{
	ціле r, blen, escaped = 0;
	u_int len;
	char line[1024];
	struct sshbuf *buf;
	char encoded[8096];
	FILE *fp;

	якщо ((buf = sshbuf_new()) == NULL)
		fatal("sshbuf_new failed");
	якщо ((fp = fopen(identity_file, "r")) == NULL)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));
	encoded[0] = '\0';
	поки ((blen = get_line(fp, line, sizeof(line))) != -1) {
		якщо (blen > 0 && line[blen - 1] == '\\')
			escaped++;
		якщо (strncmp(line, "----", 4) == 0 ||
		    strstr(line, ": ") != NULL) {
			якщо (strstr(line, SSH_COM_PRIVATE_BEGIN) != NULL)
				*private = 1;
			якщо (strstr(line, " END ") != NULL) {
				break;
			}
			/* fprintf(stderr, "ignore: %s", line); */
			continue;
		}
		якщо (escaped) {
			escaped--;
			/* fprintf(stderr, "escaped: %s", line); */
			continue;
		}
		strlcat(encoded, line, sizeof(encoded));
	}
	len = strlen(encoded);
	якщо (((len % 4) == 3) &&
	    (encoded[len-1] == '=') &&
	    (encoded[len-2] == '=') &&
	    (encoded[len-3] == '='))
		encoded[len-3] = '\0';
	якщо ((r = sshbuf_b64tod(buf, encoded)) != 0)
		fatal_fr(r, "base64 decode");
	якщо (*private) {
		якщо ((*k = do_convert_private_ssh2(buf)) == NULL)
			fatal_f("private key conversion failed");
	} інакше якщо ((r = sshkey_fromb(buf, k)) != 0)
		fatal_fr(r, "parse key");
	sshbuf_free(buf);
	fclose(fp);
}

static void
do_convert_from_pkcs8(struct sshkey **k, ціле *private)
{
	EVP_PKEY *pubkey;
	FILE *fp;

	якщо ((fp = fopen(identity_file, "r")) == NULL)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));
	якщо ((pubkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL)) == NULL) {
		fatal_f("%s is not a recognised public key format",
		    identity_file);
	}
	fclose(fp);
	switch (EVP_PKEY_base_id(pubkey)) {
	case EVP_PKEY_RSA:
		якщо ((*k = sshkey_new(KEY_UNSPEC)) == NULL)
			fatal("sshkey_new failed");
		(*k)->type = KEY_RSA;
		(*k)->pkey = pubkey;
		pubkey = NULL;
		break;
	case EVP_PKEY_EC:
		якщо ((*k = sshkey_new(KEY_UNSPEC)) == NULL)
			fatal("sshkey_new failed");
		якщо (((*k)->ecdsa_nid = sshkey_ecdsa_fixup_group(pubkey)) == -1)
			fatal("sshkey_ecdsa_fixup_group failed");
		(*k)->type = KEY_ECDSA;
		(*k)->pkey = pubkey;
		pubkey = NULL;
		break;
	default:
		fatal_f("unsupported pubkey type %d",
		    EVP_PKEY_base_id(pubkey));
	}
	EVP_PKEY_free(pubkey);
}

static void
do_convert_from_pem(struct sshkey **k, ціле *private)
{
	FILE *fp;
	RSA *rsa;

	якщо ((fp = fopen(identity_file, "r")) == NULL)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));
	якщо ((rsa = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL)) != NULL) {
		якщо ((*k = sshkey_new(KEY_UNSPEC)) == NULL)
			fatal("sshkey_new failed");
		якщо (((*k)->pkey = EVP_PKEY_new()) == NULL)
			fatal("EVP_PKEY_new failed");
		(*k)->type = KEY_RSA;
		якщо (EVP_PKEY_set1_RSA((*k)->pkey, rsa) != 1)
			fatal("EVP_PKEY_set1_RSA failed");
		RSA_free(rsa);
		fclose(fp);
		повернути;
	}
	fatal_f("unrecognised raw private key format");
}

static void
do_convert_from(struct passwd *pw)
{
	struct sshkey *k = NULL;
	ціле r, private = 0, ok = 0;
	struct stat st;

	якщо (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	якщо (stat(identity_file, &st) == -1)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));

	switch (convert_format) {
	case FMT_RFC4716:
		do_convert_from_ssh2(pw, &k, &private);
		break;
	case FMT_PKCS8:
		do_convert_from_pkcs8(&k, &private);
		break;
	case FMT_PEM:
		do_convert_from_pem(&k, &private);
		break;
	default:
		fatal_f("unknown key format %d", convert_format);
	}

	якщо (!private) {
		якщо ((r = sshkey_write(k, stdout)) == 0)
			ok = 1;
		якщо (ok)
			fprintf(stdout, "\n");
	} інакше {
		switch (k->type) {
		case KEY_ECDSA:
			ok = PEM_write_ECPrivateKey(stdout,
			    EVP_PKEY_get0_EC_KEY(k->pkey), NULL, NULL, 0,
			    NULL, NULL);
			break;
		case KEY_RSA:
			ok = PEM_write_RSAPrivateKey(stdout,
			    EVP_PKEY_get0_RSA(k->pkey), NULL, NULL, 0,
			    NULL, NULL);
			break;
		default:
			fatal_f("unsupported key type %s", sshkey_type(k));
		}
	}

	якщо (!ok)
		fatal("key write failed");
	sshkey_free(k);
}
#endif

static void
do_print_public(struct passwd *pw)
{
	struct sshkey *prv;
	struct stat st;
	ціле r;
	char *comment = NULL;

	якщо (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	якщо (stat(identity_file, &st) == -1)
		fatal("%s: %s", identity_file, strerror(errno));
	prv = load_identity(identity_file, &comment);
	якщо ((r = sshkey_write(prv, stdout)) != 0)
		fatal_fr(r, "write key");
	якщо (comment != NULL && *comment != '\0')
		fprintf(stdout, " %s", comment);
	fprintf(stdout, "\n");
	якщо (sshkey_is_sk(prv)) {
		debug("sk_application: \"%s\", sk_flags 0x%02x",
			prv->sk_application, prv->sk_flags);
	}
	sshkey_free(prv);
	free(comment);
	exit(0);
}

static void
do_download(struct passwd *pw)
{
#ifdef ENABLE_PKCS11
	struct sshkey **keys = NULL;
	ціле i, nkeys;
	enum sshkey_fp_rep rep;
	ціле fptype;
	char *fp, *ra, **comments = NULL;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;

	pkcs11_init(1);
	nkeys = pkcs11_add_provider(pkcs11provider, NULL, &keys, &comments);
	якщо (nkeys <= 0)
		fatal("cannot read public key from pkcs11");
	для (i = 0; i < nkeys; i++) {
		якщо (print_fingerprint) {
			fp = sshkey_fingerprint(keys[i], fptype, rep);
			ra = sshkey_fingerprint(keys[i], fingerprint_hash,
			    SSH_FP_RANDOMART);
			якщо (fp == NULL || ra == NULL)
				fatal_f("sshkey_fingerprint fail");
			printf("%u %s %s (PKCS11 key)\n", sshkey_size(keys[i]),
			    fp, sshkey_type(keys[i]));
			якщо (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
				printf("%s\n", ra);
			free(ra);
			free(fp);
		} інакше {
			(void) sshkey_write(keys[i], stdout); /* XXX check */
			fprintf(stdout, "%s%s\n",
			    *(comments[i]) == '\0' ? "" : " ", comments[i]);
		}
		free(comments[i]);
		sshkey_free(keys[i]);
	}
	free(comments);
	free(keys);
	pkcs11_terminate();
	exit(0);
#інакше
	fatal("no pkcs11 support");
#endif /* ENABLE_PKCS11 */
}

static struct sshkey *
try_read_key(char **cpp)
{
	struct sshkey *ret;
	ціле r;

	якщо ((ret = sshkey_new(KEY_UNSPEC)) == NULL)
		fatal("sshkey_new failed");
	якщо ((r = sshkey_read(ret, cpp)) == 0)
		повернути ret;
	/* Not a key */
	sshkey_free(ret);
	повернути NULL;
}

static void
fingerprint_one_key(const struct sshkey *public, const char *comment)
{
	char *fp = NULL, *ra = NULL;
	enum sshkey_fp_rep rep;
	ціле fptype;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;
	fp = sshkey_fingerprint(public, fptype, rep);
	ra = sshkey_fingerprint(public, fingerprint_hash, SSH_FP_RANDOMART);
	якщо (fp == NULL || ra == NULL)
		fatal_f("sshkey_fingerprint failed");
	mprintf("%u %s %s (%s)\n", sshkey_size(public), fp,
	    comment ? comment : "no comment", sshkey_type(public));
	якщо (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
		printf("%s\n", ra);
	free(ra);
	free(fp);
}

static void
fingerprint_private(const char *path)
{
	struct stat st;
	char *comment = NULL;
	struct sshkey *privkey = NULL, *pubkey = NULL;
	ціле r;

	якщо (stat(identity_file, &st) == -1)
		fatal("%s: %s", path, strerror(errno));
	якщо ((r = sshkey_load_public(path, &pubkey, &comment)) != 0)
		debug_r(r, "load public \"%s\"", path);
	якщо (pubkey == NULL || comment == NULL || *comment == '\0') {
		free(comment);
		якщо ((r = sshkey_load_private(path, NULL,
		    &privkey, &comment)) != 0)
			debug_r(r, "load private \"%s\"", path);
	}
	якщо (pubkey == NULL && privkey == NULL)
		fatal("%s is not a key file.", path);

	fingerprint_one_key(pubkey == NULL ? privkey : pubkey, comment);
	sshkey_free(pubkey);
	sshkey_free(privkey);
	free(comment);
}

static void
do_fingerprint(struct passwd *pw)
{
	FILE *f;
	struct sshkey *public = NULL;
	char *comment = NULL, *cp, *ep, *line = NULL;
	size_t linesize = 0;
	ціле i, invalid = 1;
	const char *path;
	u_long lnum = 0;

	якщо (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	path = identity_file;

	якщо (strcmp(identity_file, "-") == 0) {
		f = stdin;
		path = "(stdin)";
	} інакше якщо ((f = fopen(path, "r")) == NULL)
		fatal("%s: %s: %s", __progname, path, strerror(errno));

	поки (getline(&line, &linesize, f) != -1) {
		lnum++;
		cp = line;
		cp[strcspn(cp, "\r\n")] = '\0';
		/* Trim leading space and comments */
		cp = line + strspn(line, " \t");
		якщо (*cp == '#' || *cp == '\0')
			continue;

		/*
		 * Input may be plain keys, private keys, authorized_keys
		 * or known_hosts.
		 */

		/*
		 * Try private keys first. Assume a key is private if
		 * "SSH PRIVATE KEY" appears on the first line and we're
		 * not reading from stdin (XXX support private keys on stdin).
		 */
		якщо (lnum == 1 && strcmp(identity_file, "-") != 0 &&
		    strstr(cp, "PRIVATE KEY") != NULL) {
			free(line);
			fclose(f);
			fingerprint_private(path);
			exit(0);
		}

		/*
		 * If it's not a private key, then this must be prepared to
		 * accept a public key prefixed with a hostname or options.
		 * Try a bare key first, otherwise skip the leading stuff.
		 */
		comment = NULL;
		якщо ((public = try_read_key(&cp)) == NULL) {
			i = strtol(cp, &ep, 10);
			якщо (i == 0 || ep == NULL ||
			    (*ep != ' ' && *ep != '\t')) {
				ціле quoted = 0;

				comment = cp;
				для (; *cp && (quoted || (*cp != ' ' &&
				    *cp != '\t')); cp++) {
					якщо (*cp == '\\' && cp[1] == '"')
						cp++;	/* Skip both */
					інакше якщо (*cp == '"')
						quoted = !quoted;
				}
				якщо (!*cp)
					continue;
				*cp++ = '\0';
			}
		}
		/* Retry after parsing leading hostname/key options */
		якщо (public == NULL && (public = try_read_key(&cp)) == NULL) {
			debug("%s:%lu: not a public key", path, lnum);
			continue;
		}

		/* Find trailing comment, if any */
		для (; *cp == ' ' || *cp == '\t'; cp++)
			;
		якщо (*cp != '\0' && *cp != '#')
			comment = cp;

		fingerprint_one_key(public, comment);
		sshkey_free(public);
		invalid = 0; /* One good key in the file is sufficient */
	}
	fclose(f);
	free(line);

	якщо (invalid)
		fatal("%s is not a public key file.", path);
	exit(0);
}

static void
do_gen_all_hostkeys(struct passwd *pw)
{
	struct {
		char *key_type;
		char *key_type_display;
		char *path;
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
		{ NULL, NULL, NULL }
	};

	uint32_t bits = 0;
	ціле first = 0;
	struct stat st;
	struct sshkey *private, *public;
	char comment[KEY_COMMENT_MAX], *prv_tmp, *pub_tmp, *prv_file, *pub_file;
	ціле i, type, fd, r;

	для (i = 0; key_types[i].key_type; i++) {
		public = private = NULL;
		prv_tmp = pub_tmp = prv_file = pub_file = NULL;

		xasprintf(&prv_file, "%s%s",
		    identity_file, key_types[i].path);

		/* Check whether private key exists and is not zero-length */
		якщо (stat(prv_file, &st) == 0) {
			якщо (st.st_size != 0)
				goto next;
		} інакше якщо (errno != ENOENT) {
			error("Could not stat %s: %s", key_types[i].path,
			    strerror(errno));
			goto failnext;
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

		якщо (first == 0) {
			first = 1;
			printf("%s: generating new host keys: ", __progname);
		}
		printf("%s ", key_types[i].key_type_display);
		fflush(stdout);
		type = sshkey_type_from_shortname(key_types[i].key_type);
		якщо ((fd = mkstemp(prv_tmp)) == -1) {
			error("Could not save your private key in %s: %s",
			    prv_tmp, strerror(errno));
			goto failnext;
		}
		(void)close(fd); /* just using mkstemp() to reserve a name */
		bits = 0;
		type_bits_valid(type, NULL, &bits);
		якщо ((r = sshkey_generate(type, bits, &private)) != 0) {
			error_r(r, "sshkey_generate failed");
			goto failnext;
		}
		якщо ((r = sshkey_from_private(private, &public)) != 0)
			fatal_fr(r, "sshkey_from_private");
		snprintf(comment, sizeof comment, "%s@%s", pw->pw_name,
		    hostname);
		якщо ((r = sshkey_save_private(private, prv_tmp, "",
		    comment, private_key_format, openssh_format_cipher,
		    rounds)) != 0) {
			error_r(r, "Saving key \"%s\" failed", prv_tmp);
			goto failnext;
		}
		якщо ((fd = mkstemp(pub_tmp)) == -1) {
			error("Could not save your public key in %s: %s",
			    pub_tmp, strerror(errno));
			goto failnext;
		}
		(void)fchmod(fd, 0644);
		(void)close(fd);
		якщо ((r = sshkey_save_public(public, pub_tmp, comment)) != 0) {
			error_r(r, "Unable to save public key to %s",
			    identity_file);
			goto failnext;
		}

		/* Rename temporary files to their permanent locations. */
		якщо (rename(pub_tmp, pub_file) != 0) {
			error("Unable to move %s into position: %s",
			    pub_file, strerror(errno));
			goto failnext;
		}
		якщо (rename(prv_tmp, prv_file) != 0) {
			error("Unable to move %s into position: %s",
			    key_types[i].path, strerror(errno));
 failnext:
			first = 0;
			goto next;
		}
 next:
		sshkey_free(private);
		sshkey_free(public);
		free(prv_tmp);
		free(pub_tmp);
		free(prv_file);
		free(pub_file);
	}
	якщо (first != 0)
		printf("\n");
}

struct known_hosts_ctx {
	const char *host;	/* Hostname searched for in find/delete case */
	FILE *out;		/* Output file, stdout for find_hosts case */
	ціле has_unhashed;	/* When hashing, original had unhashed hosts */
	ціле found_key;		/* For find/delete, host was found */
	ціле invalid;		/* File contained invalid items; don't delete */
	ціле hash_hosts;		/* Hash hostnames as we go */
	ціле find_host;		/* Search for specific hostname */
	ціле delete_host;	/* Delete host from known_hosts */
};

static ціле
known_hosts_hash(struct hostkey_foreach_line *l, void *_ctx)
{
	struct known_hosts_ctx *ctx = (struct known_hosts_ctx *)_ctx;
	char *hashed, *cp, *hosts, *ohosts;
	ціле has_wild = l->hosts && strcspn(l->hosts, "*?!") != strlen(l->hosts);
	ціле was_hashed = l->hosts && l->hosts[0] == HASH_DELIM;

	switch (l->status) {
	case HKF_STATUS_OK:
	case HKF_STATUS_MATCHED:
		/*
		 * Don't hash hosts already hashed, with wildcard
		 * characters or a CA/revocation marker.
		 */
		якщо (was_hashed || has_wild || l->marker != MRK_NONE) {
			fprintf(ctx->out, "%s\n", l->line);
			якщо (has_wild && !ctx->find_host) {
				logit("%s:%lu: ignoring host name "
				    "with wildcard: %.64s", l->path,
				    l->linenum, l->hosts);
			}
			повернути 0;
		}
		/*
		 * Split any comma-separated hostnames from the host list,
		 * hash and store separately.
		 */
		ohosts = hosts = xstrdup(l->hosts);
		поки ((cp = strsep(&hosts, ",")) != NULL && *cp != '\0') {
			lowercase(cp);
			якщо ((hashed = host_hash(cp, NULL, 0)) == NULL)
				fatal("hash_host failed");
			fprintf(ctx->out, "%s %s\n", hashed, l->rawkey);
			free(hashed);
			ctx->has_unhashed = 1;
		}
		free(ohosts);
		повернути 0;
	case HKF_STATUS_INVALID:
		/* Retain invalid lines, but mark file as invalid. */
		ctx->invalid = 1;
		logit("%s:%lu: invalid line", l->path, l->linenum);
		/* FALLTHROUGH */
	default:
		fprintf(ctx->out, "%s\n", l->line);
		повернути 0;
	}
	/* NOTREACHED */
	повернути -1;
}

static ціле
known_hosts_find_delete(struct hostkey_foreach_line *l, void *_ctx)
{
	struct known_hosts_ctx *ctx = (struct known_hosts_ctx *)_ctx;
	enum sshkey_fp_rep rep;
	ціле fptype;
	char *fp = NULL, *ra = NULL;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;

	якщо (l->status == HKF_STATUS_MATCHED) {
		якщо (ctx->delete_host) {
			якщо (l->marker != MRK_NONE) {
				/* Don't remove CA and revocation lines */
				fprintf(ctx->out, "%s\n", l->line);
			} інакше {
				/*
				 * Hostname matches and has no CA/revoke
				 * marker, delete it by *not* writing the
				 * line to ctx->out.
				 */
				ctx->found_key = 1;
				якщо (!quiet)
					printf("# Host %s found: line %lu\n",
					    ctx->host, l->linenum);
			}
			повернути 0;
		} інакше якщо (ctx->find_host) {
			ctx->found_key = 1;
			якщо (!quiet) {
				printf("# Host %s found: line %lu %s\n",
				    ctx->host,
				    l->linenum, l->marker == MRK_CA ? "CA" :
				    (l->marker == MRK_REVOKE ? "REVOKED" : ""));
			}
			якщо (ctx->hash_hosts)
				known_hosts_hash(l, ctx);
			інакше якщо (print_fingerprint) {
				fp = sshkey_fingerprint(l->key, fptype, rep);
				ra = sshkey_fingerprint(l->key,
				    fingerprint_hash, SSH_FP_RANDOMART);
				якщо (fp == NULL || ra == NULL)
					fatal_f("sshkey_fingerprint failed");
				mprintf("%s %s %s%s%s\n", ctx->host,
				    sshkey_type(l->key), fp,
				    l->comment[0] ? " " : "",
				    l->comment);
				якщо (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
					printf("%s\n", ra);
				free(ra);
				free(fp);
			} інакше
				fprintf(ctx->out, "%s\n", l->line);
			повернути 0;
		}
	} інакше якщо (ctx->delete_host) {
		/* Retain non-matching hosts when deleting */
		якщо (l->status == HKF_STATUS_INVALID) {
			ctx->invalid = 1;
			logit("%s:%lu: invalid line", l->path, l->linenum);
		}
		fprintf(ctx->out, "%s\n", l->line);
	}
	повернути 0;
}

static void
do_known_hosts(struct passwd *pw, const char *name, ціле find_host,
    ціле delete_host, ціле hash_hosts)
{
	char *cp, tmp[PATH_MAX], old[PATH_MAX];
	ціле r, fd, oerrno, inplace = 0;
	struct known_hosts_ctx ctx;
	u_int foreach_options;
	struct stat sb;

	якщо (!have_identity) {
		cp = tilde_expand_filename(_PATH_SSH_USER_HOSTFILE, pw->pw_uid);
		якщо (strlcpy(identity_file, cp, sizeof(identity_file)) >=
		    sizeof(identity_file))
			fatal("Specified known hosts path too long");
		free(cp);
		have_identity = 1;
	}
	якщо (stat(identity_file, &sb) != 0)
		fatal("Cannot stat %s: %s", identity_file, strerror(errno));

	memset(&ctx, 0, sizeof(ctx));
	ctx.out = stdout;
	ctx.host = name;
	ctx.hash_hosts = hash_hosts;
	ctx.find_host = find_host;
	ctx.delete_host = delete_host;

	/*
	 * Find hosts goes to stdout, hash and deletions happen in-place
	 * A corner case is ssh-keygen -HF foo, which should go to stdout
	 */
	якщо (!find_host && (hash_hosts || delete_host)) {
		якщо (strlcpy(tmp, identity_file, sizeof(tmp)) >= sizeof(tmp) ||
		    strlcat(tmp, ".XXXXXXXXXX", sizeof(tmp)) >= sizeof(tmp) ||
		    strlcpy(old, identity_file, sizeof(old)) >= sizeof(old) ||
		    strlcat(old, ".old", sizeof(old)) >= sizeof(old))
			fatal("known_hosts path too long");
		umask(077);
		якщо ((fd = mkstemp(tmp)) == -1)
			fatal("mkstemp: %s", strerror(errno));
		якщо ((ctx.out = fdopen(fd, "w")) == NULL) {
			oerrno = errno;
			unlink(tmp);
			fatal("fdopen: %s", strerror(oerrno));
		}
		(void)fchmod(fd, sb.st_mode & 0644);
		inplace = 1;
	}
	/* XXX support identity_file == "-" for stdin */
	foreach_options = find_host ? HKF_WANT_MATCH : 0;
	foreach_options |= print_fingerprint ? HKF_WANT_PARSE_KEY : 0;
	якщо ((r = hostkeys_foreach(identity_file, (find_host || !hash_hosts) ?
	    known_hosts_find_delete : known_hosts_hash, &ctx, name, NULL,
	    foreach_options, 0)) != 0) {
		якщо (inplace)
			unlink(tmp);
		fatal_fr(r, "hostkeys_foreach");
	}

	якщо (inplace)
		fclose(ctx.out);

	якщо (ctx.invalid) {
		error("%s is not a valid known_hosts file.", identity_file);
		якщо (inplace) {
			error("Not replacing existing known_hosts "
			    "file because of errors");
			unlink(tmp);
		}
		exit(1);
	} інакше якщо (delete_host && !ctx.found_key) {
		logit("Host %s not found in %s", name, identity_file);
		якщо (inplace)
			unlink(tmp);
	} інакше якщо (inplace) {
		/* Backup existing file */
		якщо (unlink(old) == -1 && errno != ENOENT)
			fatal("unlink %.100s: %s", old, strerror(errno));
		якщо (link(identity_file, old) == -1)
			fatal("link %.100s to %.100s: %s", identity_file, old,
			    strerror(errno));
		/* Move new one into place */
		якщо (rename(tmp, identity_file) == -1) {
			error("rename\"%s\" to \"%s\": %s", tmp, identity_file,
			    strerror(errno));
			unlink(tmp);
			unlink(old);
			exit(1);
		}

		printf("%s updated.\n", identity_file);
		printf("Original contents retained as %s\n", old);
		якщо (ctx.has_unhashed) {
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
static void
do_change_passphrase(struct passwd *pw, char * const *opts, size_t nopts)
{
	char *comment;
	char *old_passphrase, *passphrase1, *passphrase2;
	struct stat st;
	struct sshkey *private;
	ціле r;
	size_t i;

	якщо (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	якщо (stat(identity_file, &st) == -1)
		fatal("%s: %s", identity_file, strerror(errno));
	/* Try to load the file with empty passphrase. */
	r = sshkey_load_private(identity_file, "", &private, &comment);
	якщо (r == SSH_ERR_KEY_WRONG_PASSPHRASE) {
		якщо (identity_passphrase)
			old_passphrase = xstrdup(identity_passphrase);
		інакше
			old_passphrase =
			    read_passphrase("Enter old passphrase: ",
			    RP_ALLOW_STDIN);
		r = sshkey_load_private(identity_file, old_passphrase,
		    &private, &comment);
		freezero(old_passphrase, strlen(old_passphrase));
		якщо (r != 0)
			goto badkey;
	} інакше якщо (r != 0) {
 badkey:
		fatal_r(r, "Failed to load key %s", identity_file);
	}
	якщо (comment)
		mprintf("Key has comment '%s'\n", comment);

	/* All current -O options relate to FIDO keys only */
	якщо (nopts != 0 && !sshkey_is_sk(private)) {
		fatal("FIDO-specific option requested for non-FIDO key %s",
		    identity_file);
	}
	якщо (sshkey_is_sk(private)) {
		debug_f("%s: original FIDO key flags: "
		    "%stouch-required %sverify-required", identity_file,
		    (private->sk_flags & SSH_SK_USER_PRESENCE_REQD) ? "": "no-",
		    (private->sk_flags & SSH_SK_USER_VERIFICATION_REQD) ? "" : "no-");
	}
	для (i = 0; i < nopts; i++) {
		якщо (strcasecmp(opts[i], "touch-required") == 0)
			private->sk_flags |= SSH_SK_USER_PRESENCE_REQD;
		інакше якщо (strcasecmp(opts[i], "no-touch-required") == 0)
			private->sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
		інакше якщо (strcasecmp(opts[i], "verify-required") == 0)
			private->sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
		інакше якщо (strcasecmp(opts[i], "no-verify-required") == 0)
			private->sk_flags &= ~SSH_SK_USER_VERIFICATION_REQD;
		інакше {
			fatal("Option \"%s\" is unsupported for "
			    "key passphrase change", opts[i]);
		}
	}
	якщо (sshkey_is_sk(private) && nopts != 0) {
		debug_f("%s: updated FIDO key flags: "
		    "%stouch-required %sverify-required", identity_file,
		    (private->sk_flags & SSH_SK_USER_PRESENCE_REQD) ? "": "no-",
		    (private->sk_flags & SSH_SK_USER_VERIFICATION_REQD) ? "" : "no-");
	}

	/* Ask the new passphrase (twice). */
	якщо (identity_new_passphrase) {
		passphrase1 = xstrdup(identity_new_passphrase);
		passphrase2 = NULL;
	} інакше {
		passphrase1 =
			read_passphrase("Enter new passphrase (empty for no "
			    "passphrase): ", RP_ALLOW_STDIN);
		passphrase2 = read_passphrase("Enter same passphrase again: ",
		    RP_ALLOW_STDIN);

		/* Verify that they are the same. */
		якщо (strcmp(passphrase1, passphrase2) != 0) {
			explicit_bzero(passphrase1, strlen(passphrase1));
			explicit_bzero(passphrase2, strlen(passphrase2));
			free(passphrase1);
			free(passphrase2);
			printf("Pass phrases do not match.  Try again.\n");
			exit(1);
		}
		/* Destroy the other copy. */
		freezero(passphrase2, strlen(passphrase2));
	}

	/* Save the file using the new passphrase. */
	якщо ((r = sshkey_save_private(private, identity_file, passphrase1,
	    comment, private_key_format, openssh_format_cipher, rounds)) != 0) {
		error_r(r, "Saving key \"%s\" failed", identity_file);
		freezero(passphrase1, strlen(passphrase1));
		sshkey_free(private);
		free(comment);
		exit(1);
	}
	/* Destroy the passphrase and the copy of the key in memory. */
	freezero(passphrase1, strlen(passphrase1));
	sshkey_free(private);		 /* Destroys contents */
	free(comment);

	printf("Your identification has been saved with the new passphrase.\n");
	exit(0);
}

/*
 * Print the SSHFP RR.
 */
static ціле
do_print_resource_record(struct passwd *pw, char *fname, char *hname,
    ціле print_generic, char * const *opts, size_t nopts)
{
	struct sshkey *public;
	char *comment = NULL;
	const char *p;
	struct stat st;
	ціле r, hash = -1;
	size_t i;

	для (i = 0; i < nopts; i++) {
		якщо ((p = strprefix(opts[i], "hashalg=", 1)) != NULL) {
			якщо ((hash = ssh_digest_alg_by_name(p)) == -1)
				fatal("Unsupported hash algorithm");
		} інакше {
			error("Invalid option \"%s\"", opts[i]);
			повернути SSH_ERR_INVALID_ARGUMENT;
		}
	}
	якщо (fname == NULL)
		fatal_f("no filename");
	якщо (stat(fname, &st) == -1) {
		якщо (errno == ENOENT)
			повернути 0;
		fatal("%s: %s", fname, strerror(errno));
	}
	якщо ((r = sshkey_load_public(fname, &public, &comment)) != 0)
		fatal_r(r, "Failed to read v2 public key from \"%s\"", fname);
	export_dns_rr(hname, public, stdout, print_generic, hash);
	sshkey_free(public);
	free(comment);
	повернути 1;
}

/*
 * Change the comment of a private key file.
 */
static void
do_change_comment(struct passwd *pw, const char *identity_comment)
{
	char new_comment[KEY_COMMENT_MAX], *comment, *passphrase;
	struct sshkey *private;
	struct sshkey *public;
	struct stat st;
	ціле r;

	якщо (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	якщо (stat(identity_file, &st) == -1)
		fatal("%s: %s", identity_file, strerror(errno));
	якщо ((r = sshkey_load_private(identity_file, "",
	    &private, &comment)) == 0)
		passphrase = xstrdup("");
	інакше якщо (r != SSH_ERR_KEY_WRONG_PASSPHRASE)
		fatal_r(r, "Cannot load private key \"%s\"", identity_file);
	інакше {
		якщо (identity_passphrase)
			passphrase = xstrdup(identity_passphrase);
		інакше якщо (identity_new_passphrase)
			passphrase = xstrdup(identity_new_passphrase);
		інакше
			passphrase = read_passphrase("Enter passphrase: ",
			    RP_ALLOW_STDIN);
		/* Try to load using the passphrase. */
		якщо ((r = sshkey_load_private(identity_file, passphrase,
		    &private, &comment)) != 0) {
			freezero(passphrase, strlen(passphrase));
			fatal_r(r, "Cannot load private key \"%s\"",
			    identity_file);
		}
	}

	якщо (private->type != KEY_ED25519 &&
	    private_key_format != SSHKEY_PRIVATE_OPENSSH) {
		error("Comments are only supported for keys stored in "
		    "the new format (-o).");
		explicit_bzero(passphrase, strlen(passphrase));
		sshkey_free(private);
		exit(1);
	}
	якщо (comment)
		printf("Old comment: %s\n", comment);
	інакше
		printf("No existing comment\n");

	якщо (identity_comment) {
		strlcpy(new_comment, identity_comment, sizeof(new_comment));
	} інакше {
		printf("New comment: ");
		fflush(stdout);
		якщо (!fgets(new_comment, sizeof(new_comment), stdin)) {
			explicit_bzero(passphrase, strlen(passphrase));
			sshkey_free(private);
			exit(1);
		}
		new_comment[strcspn(new_comment, "\n")] = '\0';
	}
	якщо (comment != NULL && strcmp(comment, new_comment) == 0) {
		printf("No change to comment\n");
		free(passphrase);
		sshkey_free(private);
		free(comment);
		exit(0);
	}

	/* Save the file using the new passphrase. */
	якщо ((r = sshkey_save_private(private, identity_file, passphrase,
	    new_comment, private_key_format, openssh_format_cipher,
	    rounds)) != 0) {
		error_r(r, "Saving key \"%s\" failed", identity_file);
		freezero(passphrase, strlen(passphrase));
		sshkey_free(private);
		free(comment);
		exit(1);
	}
	freezero(passphrase, strlen(passphrase));
	якщо ((r = sshkey_from_private(private, &public)) != 0)
		fatal_fr(r, "sshkey_from_private");
	sshkey_free(private);

	strlcat(identity_file, ".pub", sizeof(identity_file));
	якщо ((r = sshkey_save_public(public, identity_file, new_comment)) != 0)
		fatal_r(r, "Unable to save public key to %s", identity_file);
	sshkey_free(public);
	free(comment);

	якщо (strlen(new_comment) > 0)
		printf("Comment '%s' applied\n", new_comment);
	інакше
		printf("Comment removed\n");

	exit(0);
}

static void
cert_ext_add(const char *key, const char *value, ціле iscrit)
{
	cert_ext = xreallocarray(cert_ext, ncert_ext + 1, sizeof(*cert_ext));
	cert_ext[ncert_ext].key = xstrdup(key);
	cert_ext[ncert_ext].val = value == NULL ? NULL : xstrdup(value);
	cert_ext[ncert_ext].crit = iscrit;
	ncert_ext++;
}

/* qsort(3) comparison function for certificate extensions */
static ціле
cert_ext_cmp(const void *_a, const void *_b)
{
	const struct cert_ext *a = (const struct cert_ext *)_a;
	const struct cert_ext *b = (const struct cert_ext *)_b;
	ціле r;

	якщо (a->crit != b->crit)
		повернути (a->crit < b->crit) ? -1 : 1;
	якщо ((r = strcmp(a->key, b->key)) != 0)
		повернути r;
	якщо ((a->val == NULL) != (b->val == NULL))
		повернути (a->val == NULL) ? -1 : 1;
	якщо (a->val != NULL && (r = strcmp(a->val, b->val)) != 0)
		повернути r;
	повернути 0;
}

#define OPTIONS_CRITICAL	1
#define OPTIONS_EXTENSIONS	2
static void
prepare_options_buf(struct sshbuf *c, ціле which)
{
	struct sshbuf *b;
	size_t i;
	ціле r;
	const struct cert_ext *ext;

	якщо ((b = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	sshbuf_reset(c);
	для (i = 0; i < ncert_ext; i++) {
		ext = &cert_ext[i];
		якщо ((ext->crit && (which & OPTIONS_EXTENSIONS)) ||
		    (!ext->crit && (which & OPTIONS_CRITICAL)))
			continue;
		якщо (ext->val == NULL) {
			/* flag option */
			debug3_f("%s", ext->key);
			якщо ((r = sshbuf_put_cstring(c, ext->key)) != 0 ||
			    (r = sshbuf_put_string(c, NULL, 0)) != 0)
				fatal_fr(r, "prepare flag");
		} інакше {
			/* key/value option */
			debug3_f("%s=%s", ext->key, ext->val);
			sshbuf_reset(b);
			якщо ((r = sshbuf_put_cstring(c, ext->key)) != 0 ||
			    (r = sshbuf_put_cstring(b, ext->val)) != 0 ||
			    (r = sshbuf_put_stringb(c, b)) != 0)
				fatal_fr(r, "prepare k/v");
		}
	}
	sshbuf_free(b);
}

static void
finalise_cert_exts(void)
{
	/* critical options */
	якщо (certflags_command != NULL)
		cert_ext_add("force-command", certflags_command, 1);
	якщо (certflags_src_addr != NULL)
		cert_ext_add("source-address", certflags_src_addr, 1);
	якщо ((certflags_flags & CERTOPT_REQUIRE_VERIFY) != 0)
		cert_ext_add("verify-required", NULL, 1);
	/* extensions */
	якщо ((certflags_flags & CERTOPT_X_FWD) != 0)
		cert_ext_add("permit-X11-forwarding", NULL, 0);
	якщо ((certflags_flags & CERTOPT_AGENT_FWD) != 0)
		cert_ext_add("permit-agent-forwarding", NULL, 0);
	якщо ((certflags_flags & CERTOPT_PORT_FWD) != 0)
		cert_ext_add("permit-port-forwarding", NULL, 0);
	якщо ((certflags_flags & CERTOPT_PTY) != 0)
		cert_ext_add("permit-pty", NULL, 0);
	якщо ((certflags_flags & CERTOPT_USER_RC) != 0)
		cert_ext_add("permit-user-rc", NULL, 0);
	якщо ((certflags_flags & CERTOPT_NO_REQUIRE_USER_PRESENCE) != 0)
		cert_ext_add("no-touch-required", NULL, 0);
	/* order lexically by key */
	якщо (ncert_ext > 0)
		qsort(cert_ext, ncert_ext, sizeof(*cert_ext), cert_ext_cmp);
}

static struct sshkey *
load_pkcs11_key(char *path)
{
#ifdef ENABLE_PKCS11
	struct sshkey **keys = NULL, *public, *private = NULL;
	ціле r, i, nkeys;

	якщо ((r = sshkey_load_public(path, &public, NULL)) != 0)
		fatal_r(r, "Couldn't load CA public key \"%s\"", path);

	nkeys = pkcs11_add_provider(pkcs11provider, identity_passphrase,
	    &keys, NULL);
	debug3_f("%d keys", nkeys);
	якщо (nkeys <= 0)
		fatal("cannot read public key from pkcs11");
	для (i = 0; i < nkeys; i++) {
		якщо (sshkey_equal_public(public, keys[i])) {
			private = keys[i];
			continue;
		}
		sshkey_free(keys[i]);
	}
	free(keys);
	sshkey_free(public);
	повернути private;
#інакше
	fatal("no pkcs11 support");
#endif /* ENABLE_PKCS11 */
}

/* Signer for sshkey_certify_custom that uses the agent */
static ціле
agent_signer(struct sshkey *key, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen,
    const char *alg, const char *provider, const char *pin,
    u_int compat, void *ctx)
{
	ціле *agent_fdp = (ціле *)ctx;

	повернути ssh_agent_sign(*agent_fdp, key, sigp, lenp,
	    data, datalen, alg, compat);
}

static void
do_ca_sign(struct passwd *pw, const char *ca_key_path, ціле prefer_agent,
    unsigned long long cert_serial, ціле cert_serial_autoinc,
    ціле argc, char **argv)
{
	ціле r, i, key_in_agent = 0, agent_fd = -1;
	u_int n;
	struct sshkey *ca, *public;
	char valid[64], *otmp, *tmp, *cp, *out, *comment;
	char *ca_fp = NULL, **plist = NULL, *pin = NULL;
	struct ssh_identitylist *agent_ids;
	size_t j;
	struct notifier_ctx *notifier = NULL;

#ifdef ENABLE_PKCS11
	pkcs11_init(1);
#endif
	tmp = tilde_expand_filename(ca_key_path, pw->pw_uid);
	якщо (pkcs11provider != NULL) {
		/* If a PKCS#11 token was specified then try to use it */
		якщо ((ca = load_pkcs11_key(tmp)) == NULL)
			fatal("No PKCS#11 key matching %s found", ca_key_path);
	} інакше якщо (prefer_agent) {
		/*
		 * Agent signature requested. Try to use agent after making
		 * sure the public key specified is actually present in the
		 * agent.
		 */
		якщо ((r = sshkey_load_public(tmp, &ca, NULL)) != 0)
			fatal_r(r, "Cannot load CA public key %s", tmp);
		якщо ((r = ssh_get_authentication_socket(&agent_fd)) != 0)
			fatal_r(r, "Cannot use public key for CA signature");
		якщо ((r = ssh_fetch_identitylist(agent_fd, &agent_ids)) != 0)
			fatal_r(r, "Retrieve agent key list");
		для (j = 0; j < agent_ids->nkeys; j++) {
			якщо (sshkey_equal(ca, agent_ids->keys[j])) {
				key_in_agent = 1;
				/* Replace the CA key with the agent one */
				sshkey_free(ca);
				ca = agent_ids->keys[j];
				agent_ids->keys[j] = NULL;
				break;
			}
		}
		якщо (!key_in_agent)
			fatal("CA key %s not found in agent", tmp);
		ssh_free_identitylist(agent_ids);
	} інакше {
		/* CA key is assumed to be a private key on the filesystem */
		ca = load_identity(tmp, NULL);
		якщо (sshkey_is_sk(ca) &&
		    (ca->sk_flags & SSH_SK_USER_VERIFICATION_REQD)) {
			якщо ((pin = read_passphrase("Enter PIN for CA key: ",
			    RP_ALLOW_STDIN)) == NULL)
				fatal_f("couldn't read PIN");
		}
	}
	free(tmp);

	якщо (key_type_name != NULL) {
		якщо (sshkey_type_from_shortname(key_type_name) != ca->type) {
			fatal("CA key type %s doesn't match specified %s",
			    sshkey_ssh_name(ca), key_type_name);
		}
	} інакше якщо (ca->type == KEY_RSA) {
		/* Default to a good signature algorithm */
		key_type_name = "rsa-sha2-512";
	}
	ca_fp = sshkey_fingerprint(ca, fingerprint_hash, SSH_FP_DEFAULT);

	finalise_cert_exts();
	для (i = 0; i < argc; i++) {
		/* Split list of principals */
		n = 0;
		якщо (cert_principals != NULL) {
			otmp = tmp = xstrdup(cert_principals);
			plist = NULL;
			для (; (cp = strsep(&tmp, ",")) != NULL; n++) {
				plist = xreallocarray(plist, n + 1, sizeof(*plist));
				якщо (*(plist[n] = xstrdup(cp)) == '\0')
					fatal("Empty principal name");
			}
			free(otmp);
		}
		якщо (n > SSHKEY_CERT_MAX_PRINCIPALS)
			fatal("Too many certificate principals specified");

		tmp = tilde_expand_filename(argv[i], pw->pw_uid);
		якщо ((r = sshkey_load_public(tmp, &public, &comment)) != 0)
			fatal_r(r, "load pubkey \"%s\"", tmp);
		якщо (sshkey_is_cert(public))
			fatal_f("key \"%s\" type %s cannot be certified",
			    tmp, sshkey_type(public));

		/* Prepare certificate to sign */
		якщо ((r = sshkey_to_certified(public)) != 0)
			fatal_r(r, "Could not upgrade key %s to certificate", tmp);
		public->cert->type = cert_key_type;
		public->cert->serial = (uint64_t)cert_serial;
		public->cert->key_id = xstrdup(cert_key_id);
		public->cert->nprincipals = n;
		public->cert->principals = plist;
		public->cert->valid_after = cert_valid_from;
		public->cert->valid_before = cert_valid_to;
		prepare_options_buf(public->cert->critical, OPTIONS_CRITICAL);
		prepare_options_buf(public->cert->extensions,
		    OPTIONS_EXTENSIONS);
		якщо ((r = sshkey_from_private(ca,
		    &public->cert->signature_key)) != 0)
			fatal_r(r, "sshkey_from_private (ca key)");

		якщо (key_in_agent) {
			якщо ((r = sshkey_certify_custom(public, ca,
			    key_type_name, sk_provider, NULL, agent_signer,
			    &agent_fd)) != 0)
				fatal_r(r, "Couldn't certify %s via agent", tmp);
		} інакше {
			якщо (sshkey_is_sk(ca) &&
			    (ca->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
				notifier = notify_start(0,
				    "Confirm user presence for key %s %s",
				    sshkey_type(ca), ca_fp);
			}
			r = sshkey_certify(public, ca, key_type_name,
			    sk_provider, pin);
			notify_complete(notifier, "User presence confirmed");
			якщо (r != 0)
				fatal_r(r, "Couldn't certify key %s", tmp);
		}

		якщо ((cp = strrchr(tmp, '.')) != NULL && strcmp(cp, ".pub") == 0)
			*cp = '\0';
		xasprintf(&out, "%s-cert.pub", tmp);
		free(tmp);

		якщо ((r = sshkey_save_public(public, out, comment)) != 0) {
			fatal_r(r, "Unable to save public key to %s",
			    identity_file);
		}

		якщо (!quiet) {
			sshkey_format_cert_validity(public->cert,
			    valid, sizeof(valid));
			logit("Signed %s key %s: id \"%s\" serial %llu%s%s "
			    "valid %s", sshkey_cert_type(public),
			    out, public->cert->key_id,
			    (unsigned long long)public->cert->serial,
			    cert_principals != NULL ? " for " : "",
			    cert_principals != NULL ? cert_principals : "",
			    valid);
		}

		sshkey_free(public);
		free(out);
		free(comment);
		якщо (cert_serial_autoinc)
			cert_serial++;
	}
	якщо (pin != NULL)
		freezero(pin, strlen(pin));
	sshkey_free(ca);
	free(ca_fp);
#ifdef ENABLE_PKCS11
	pkcs11_terminate();
#endif
}

static uint64_t
parse_relative_time(const char *s, time_t now)
{
	int64_t mul, secs;

	mul = *s == '-' ? -1 : 1;

	якщо ((secs = convtime(s + 1)) == -1)
		fatal("Invalid relative certificate time %s", s);
	якщо (mul == -1 && secs > now)
		fatal("Certificate time %s cannot be represented", s);
	повернути now + (uint64_t)(secs * mul);
}

static void
parse_hex_u64(const char *s, uint64_t *up)
{
	char *ep;
	unsigned long long ull;

	errno = 0;
	ull = strtoull(s, &ep, 16);
	якщо (*s == '\0' || *ep != '\0')
		fatal("Invalid certificate time: not a number");
	якщо (errno == ERANGE && ull == ULONG_MAX)
		fatal_fr(SSH_ERR_SYSTEM_ERROR, "Invalid certificate time");
	*up = (uint64_t)ull;
}

static void
parse_cert_times(char *timespec)
{
	char *from, *to;
	time_t now = time(NULL);
	int64_t secs;

	/* +timespec relative to now */
	якщо (*timespec == '+' && strchr(timespec, ':') == NULL) {
		якщо ((secs = convtime(timespec + 1)) == -1)
			fatal("Invalid relative certificate life %s", timespec);
		cert_valid_to = now + secs;
		/*
		 * Backdate certificate one minute to avoid problems on hosts
		 * with poorly-synchronised clocks.
		 */
		cert_valid_from = ((now - 59)/ 60) * 60;
		повернути;
	}

	/*
	 * from:to, where
	 * from := [+-]timespec | YYYYMMDD | YYYYMMDDHHMMSS | 0x... | "always"
	 *   to := [+-]timespec | YYYYMMDD | YYYYMMDDHHMMSS | 0x... | "forever"
	 */
	from = xstrdup(timespec);
	to = strchr(from, ':');
	якщо (to == NULL || from == to || *(to + 1) == '\0')
		fatal("Invalid certificate life specification %s", timespec);
	*to++ = '\0';

	якщо (*from == '-' || *from == '+')
		cert_valid_from = parse_relative_time(from, now);
	інакше якщо (strcmp(from, "always") == 0)
		cert_valid_from = 0;
	інакше якщо (strncmp(from, "0x", 2) == 0)
		parse_hex_u64(from, &cert_valid_from);
	інакше якщо (parse_absolute_time(from, &cert_valid_from) != 0)
		fatal("Invalid from time \"%s\"", from);

	якщо (*to == '-' || *to == '+')
		cert_valid_to = parse_relative_time(to, now);
	інакше якщо (strcmp(to, "forever") == 0)
		cert_valid_to = ~(uint64_t)0;
	інакше якщо (strncmp(to, "0x", 2) == 0)
		parse_hex_u64(to, &cert_valid_to);
	інакше якщо (parse_absolute_time(to, &cert_valid_to) != 0)
		fatal("Invalid to time \"%s\"", to);

	якщо (cert_valid_to <= cert_valid_from)
		fatal("Empty certificate validity interval");
	free(from);
}

static void
add_cert_option(char *opt)
{
	char *val, *cp;
	const char *p;
	ціле iscrit = 0;

	якщо (strcasecmp(opt, "clear") == 0)
		certflags_flags = 0;
	інакше якщо (strcasecmp(opt, "no-x11-forwarding") == 0)
		certflags_flags &= ~CERTOPT_X_FWD;
	інакше якщо (strcasecmp(opt, "permit-x11-forwarding") == 0)
		certflags_flags |= CERTOPT_X_FWD;
	інакше якщо (strcasecmp(opt, "no-agent-forwarding") == 0)
		certflags_flags &= ~CERTOPT_AGENT_FWD;
	інакше якщо (strcasecmp(opt, "permit-agent-forwarding") == 0)
		certflags_flags |= CERTOPT_AGENT_FWD;
	інакше якщо (strcasecmp(opt, "no-port-forwarding") == 0)
		certflags_flags &= ~CERTOPT_PORT_FWD;
	інакше якщо (strcasecmp(opt, "permit-port-forwarding") == 0)
		certflags_flags |= CERTOPT_PORT_FWD;
	інакше якщо (strcasecmp(opt, "no-pty") == 0)
		certflags_flags &= ~CERTOPT_PTY;
	інакше якщо (strcasecmp(opt, "permit-pty") == 0)
		certflags_flags |= CERTOPT_PTY;
	інакше якщо (strcasecmp(opt, "no-user-rc") == 0)
		certflags_flags &= ~CERTOPT_USER_RC;
	інакше якщо (strcasecmp(opt, "permit-user-rc") == 0)
		certflags_flags |= CERTOPT_USER_RC;
	інакше якщо (strcasecmp(opt, "touch-required") == 0)
		certflags_flags &= ~CERTOPT_NO_REQUIRE_USER_PRESENCE;
	інакше якщо (strcasecmp(opt, "no-touch-required") == 0)
		certflags_flags |= CERTOPT_NO_REQUIRE_USER_PRESENCE;
	інакше якщо (strcasecmp(opt, "no-verify-required") == 0)
		certflags_flags &= ~CERTOPT_REQUIRE_VERIFY;
	інакше якщо (strcasecmp(opt, "verify-required") == 0)
		certflags_flags |= CERTOPT_REQUIRE_VERIFY;
	інакше якщо ((p = strprefix(opt, "force-command=", 1)) != NULL) {
		якщо (*p == '\0')
			fatal("Empty force-command option");
		якщо (certflags_command != NULL)
			fatal("force-command already specified");
		certflags_command = xstrdup(p);
	} інакше якщо ((p = strprefix(opt, "source-address=", 1)) != NULL) {
		якщо (*p == '\0')
			fatal("Empty source-address option");
		якщо (certflags_src_addr != NULL)
			fatal("source-address already specified");
		якщо (addr_match_cidr_list(NULL, p) != 0)
			fatal("Invalid source-address list");
		certflags_src_addr = xstrdup(p);
	} інакше якщо (strprefix(opt, "extension:", 1) != NULL ||
		    (iscrit = (strprefix(opt, "critical:", 1) != NULL))) {
		val = xstrdup(strchr(opt, ':') + 1);
		якщо ((cp = strchr(val, '=')) != NULL)
			*cp++ = '\0';
		cert_ext_add(val, cp, iscrit);
		free(val);
	} інакше
		fatal("Unsupported certificate option \"%s\"", opt);
}

static void
show_options(struct sshbuf *optbuf, ціле in_critical)
{
	char *name, *arg, *hex;
	struct sshbuf *options, *option = NULL;
	ціле r;

	якщо ((options = sshbuf_fromb(optbuf)) == NULL)
		fatal_f("sshbuf_fromb failed");
	поки (sshbuf_len(options) != 0) {
		sshbuf_free(option);
		option = NULL;
		якщо ((r = sshbuf_get_cstring(options, &name, NULL)) != 0 ||
		    (r = sshbuf_froms(options, &option)) != 0)
			fatal_fr(r, "parse option");
		printf("                %s", name);
		якщо (!in_critical &&
		    (strcmp(name, "permit-X11-forwarding") == 0 ||
		    strcmp(name, "permit-agent-forwarding") == 0 ||
		    strcmp(name, "permit-port-forwarding") == 0 ||
		    strcmp(name, "permit-pty") == 0 ||
		    strcmp(name, "permit-user-rc") == 0 ||
		    strcmp(name, "no-touch-required") == 0)) {
			printf("\n");
		} інакше якщо (in_critical &&
		    (strcmp(name, "force-command") == 0 ||
		    strcmp(name, "source-address") == 0)) {
			якщо ((r = sshbuf_get_cstring(option, &arg, NULL)) != 0)
				fatal_fr(r, "parse critical");
			printf(" %s\n", arg);
			free(arg);
		} інакше якщо (in_critical &&
		    strcmp(name, "verify-required") == 0) {
			printf("\n");
		} інакше якщо (sshbuf_len(option) > 0) {
			hex = sshbuf_dtob16(option);
			printf(" UNKNOWN OPTION: %s (len %zu)\n",
			    hex, sshbuf_len(option));
			sshbuf_reset(option);
			free(hex);
		} інакше
			printf(" UNKNOWN FLAG OPTION\n");
		free(name);
		якщо (sshbuf_len(option) != 0)
			fatal("Option corrupt: extra data at end");
	}
	sshbuf_free(option);
	sshbuf_free(options);
}

static void
print_cert(struct sshkey *key)
{
	char valid[64], *key_fp, *ca_fp;
	u_int i;

	key_fp = sshkey_fingerprint(key, fingerprint_hash, SSH_FP_DEFAULT);
	ca_fp = sshkey_fingerprint(key->cert->signature_key,
	    fingerprint_hash, SSH_FP_DEFAULT);
	якщо (key_fp == NULL || ca_fp == NULL)
		fatal_f("sshkey_fingerprint fail");
	sshkey_format_cert_validity(key->cert, valid, sizeof(valid));

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
	якщо (key->cert->nprincipals == 0)
		printf("(none)\n");
	інакше {
		для (i = 0; i < key->cert->nprincipals; i++)
			printf("\n                %s",
			    key->cert->principals[i]);
		printf("\n");
	}
	printf("        Critical Options: ");
	якщо (sshbuf_len(key->cert->critical) == 0)
		printf("(none)\n");
	інакше {
		printf("\n");
		show_options(key->cert->critical, 1);
	}
	printf("        Extensions: ");
	якщо (sshbuf_len(key->cert->extensions) == 0)
		printf("(none)\n");
	інакше {
		printf("\n");
		show_options(key->cert->extensions, 0);
	}
	free(key_fp);
	free(ca_fp);
}

static void
do_show_cert(struct passwd *pw)
{
	struct sshkey *key = NULL;
	struct stat st;
	ціле r, is_stdin = 0, ok = 0;
	FILE *f;
	char *cp, *line = NULL;
	const char *path;
	size_t linesize = 0;
	u_long lnum = 0;

	якщо (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	якщо (strcmp(identity_file, "-") != 0 && stat(identity_file, &st) == -1)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));

	path = identity_file;
	якщо (strcmp(path, "-") == 0) {
		f = stdin;
		path = "(stdin)";
		is_stdin = 1;
	} інакше якщо ((f = fopen(identity_file, "r")) == NULL)
		fatal("fopen %s: %s", identity_file, strerror(errno));

	поки (getline(&line, &linesize, f) != -1) {
		lnum++;
		sshkey_free(key);
		key = NULL;
		/* Trim leading space and comments */
		cp = line + strspn(line, " \t");
		якщо (*cp == '#' || *cp == '\0')
			continue;
		якщо ((key = sshkey_new(KEY_UNSPEC)) == NULL)
			fatal("sshkey_new");
		якщо ((r = sshkey_read(key, &cp)) != 0) {
			error_r(r, "%s:%lu: invalid key", path, lnum);
			continue;
		}
		якщо (!sshkey_is_cert(key)) {
			error("%s:%lu is not a certificate", path, lnum);
			continue;
		}
		ok = 1;
		якщо (!is_stdin && lnum == 1)
			printf("%s:\n", path);
		інакше
			printf("%s:%lu:\n", path, lnum);
		print_cert(key);
	}
	free(line);
	sshkey_free(key);
	fclose(f);
	exit(ok ? 0 : 1);
}

static void
load_krl(const char *path, struct ssh_krl **krlp)
{
	struct sshbuf *krlbuf;
	ціле r;

	якщо ((r = sshbuf_load_file(path, &krlbuf)) != 0)
		fatal_r(r, "Unable to load KRL %s", path);
	/* XXX check sigs */
	якщо ((r = ssh_krl_from_blob(krlbuf, krlp)) != 0 ||
	    *krlp == NULL)
		fatal_r(r, "Invalid KRL file %s", path);
	sshbuf_free(krlbuf);
}

static void
hash_to_blob(const char *cp, u_char **blobp, size_t *lenp,
    const char *file, u_long lnum)
{
	char *tmp;
	size_t tlen;
	struct sshbuf *b;
	ціле r;

	якщо ((cp = strprefix(cp, "SHA256:", 0)) == NULL)
		fatal("%s:%lu: unsupported hash algorithm", file, lnum);

	/*
	 * OpenSSH base64 hashes omit trailing '='
	 * characters; put them back for decode.
	 */
	якщо ((tlen = strlen(cp)) >= SIZE_MAX - 5)
		fatal_f("hash too long: %zu bytes", tlen);
	tmp = xmalloc(tlen + 4 + 1);
	strlcpy(tmp, cp, tlen + 1);
	поки ((tlen % 4) != 0) {
		tmp[tlen++] = '=';
		tmp[tlen] = '\0';
	}
	якщо ((b = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	якщо ((r = sshbuf_b64tod(b, tmp)) != 0)
		fatal_r(r, "%s:%lu: decode hash failed", file, lnum);
	free(tmp);
	*lenp = sshbuf_len(b);
	*blobp = xmalloc(*lenp);
	memcpy(*blobp, sshbuf_ptr(b), *lenp);
	sshbuf_free(b);
}

static void
update_krl_from_file(struct passwd *pw, const char *file, ціле wild_ca,
    const struct sshkey *ca, struct ssh_krl *krl)
{
	struct sshkey *key = NULL;
	u_long lnum = 0;
	char *path, *cp, *ep, *line = NULL;
	u_char *blob = NULL;
	size_t blen = 0, linesize = 0;
	unsigned long long serial, serial2;
	ціле i, was_explicit_key, was_sha1, was_sha256, was_hash, r;
	FILE *krl_spec;

	path = tilde_expand_filename(file, pw->pw_uid);
	якщо (strcmp(path, "-") == 0) {
		krl_spec = stdin;
		free(path);
		path = xstrdup("(standard input)");
	} інакше якщо ((krl_spec = fopen(path, "r")) == NULL)
		fatal("fopen %s: %s", path, strerror(errno));

	якщо (!quiet)
		printf("Revoking from %s\n", path);
	поки (getline(&line, &linesize, krl_spec) != -1) {
		якщо (linesize >= INT_MAX) {
			fatal_f("%s contains unparsable line, len=%zu",
			    path, linesize);
		}
		lnum++;
		was_explicit_key = was_sha1 = was_sha256 = was_hash = 0;
		cp = line + strspn(line, " \t");
		/* Trim trailing space, comments and strip \n */
		для (i = 0, r = -1; cp[i] != '\0'; i++) {
			якщо (cp[i] == '#' || cp[i] == '\n') {
				cp[i] = '\0';
				break;
			}
			якщо (cp[i] == ' ' || cp[i] == '\t') {
				/* Remember the start of a span of whitespace */
				якщо (r == -1)
					r = i;
			} інакше
				r = -1;
		}
		якщо (r != -1)
			cp[r] = '\0';
		якщо (*cp == '\0')
			continue;
		якщо (strncasecmp(cp, "serial:", 7) == 0) {
			якщо (ca == NULL && !wild_ca) {
				fatal("revoking certificates by serial number "
				    "requires specification of a CA key");
			}
			cp += 7;
			cp = cp + strspn(cp, " \t");
			errno = 0;
			serial = strtoull(cp, &ep, 0);
			якщо (*cp == '\0' || (*ep != '\0' && *ep != '-'))
				fatal("%s:%lu: invalid serial \"%s\"",
				    path, lnum, cp);
			якщо (errno == ERANGE && serial == ULLONG_MAX)
				fatal("%s:%lu: serial out of range",
				    path, lnum);
			serial2 = serial;
			якщо (*ep == '-') {
				cp = ep + 1;
				errno = 0;
				serial2 = strtoull(cp, &ep, 0);
				якщо (*cp == '\0' || *ep != '\0')
					fatal("%s:%lu: invalid serial \"%s\"",
					    path, lnum, cp);
				якщо (errno == ERANGE && serial2 == ULLONG_MAX)
					fatal("%s:%lu: serial out of range",
					    path, lnum);
				якщо (serial2 <= serial)
					fatal("%s:%lu: invalid serial range "
					    "%llu:%llu", path, lnum,
					    (unsigned long long)serial,
					    (unsigned long long)serial2);
			}
			якщо (ssh_krl_revoke_cert_by_serial_range(krl,
			    ca, serial, serial2) != 0) {
				fatal_f("revoke serial failed");
			}
		} інакше якщо (strncasecmp(cp, "id:", 3) == 0) {
			якщо (ca == NULL && !wild_ca) {
				fatal("revoking certificates by key ID "
				    "requires specification of a CA key");
			}
			cp += 3;
			cp = cp + strspn(cp, " \t");
			якщо (ssh_krl_revoke_cert_by_key_id(krl, ca, cp) != 0)
				fatal_f("revoke key ID failed");
		} інакше якщо (strncasecmp(cp, "hash:", 5) == 0) {
			cp += 5;
			cp = cp + strspn(cp, " \t");
			hash_to_blob(cp, &blob, &blen, file, lnum);
			якщо ((r = ssh_krl_revoke_key_sha256(krl,
			    blob, blen)) != 0)
				fatal_fr(r, "revoke key failed");
			free(blob);
			blob = NULL;
			blen = 0;
		} інакше {
			якщо (strncasecmp(cp, "key:", 4) == 0) {
				cp += 4;
				cp = cp + strspn(cp, " \t");
				was_explicit_key = 1;
			} інакше якщо (strncasecmp(cp, "sha1:", 5) == 0) {
				cp += 5;
				cp = cp + strspn(cp, " \t");
				was_sha1 = 1;
			} інакше якщо (strncasecmp(cp, "sha256:", 7) == 0) {
				cp += 7;
				cp = cp + strspn(cp, " \t");
				was_sha256 = 1;
				/*
				 * Just try to process the line as a key.
				 * Parsing will fail if it isn't.
				 */
			}
			якщо ((key = sshkey_new(KEY_UNSPEC)) == NULL)
				fatal("sshkey_new");
			якщо ((r = sshkey_read(key, &cp)) != 0)
				fatal_r(r, "%s:%lu: invalid key", path, lnum);
			якщо (was_explicit_key)
				r = ssh_krl_revoke_key_explicit(krl, key);
			інакше якщо (was_sha1) {
				якщо (sshkey_fingerprint_raw(key,
				    SSH_DIGEST_SHA1, &blob, &blen) != 0) {
					fatal("%s:%lu: fingerprint failed",
					    file, lnum);
				}
				r = ssh_krl_revoke_key_sha1(krl, blob, blen);
			} інакше якщо (was_sha256) {
				якщо (sshkey_fingerprint_raw(key,
				    SSH_DIGEST_SHA256, &blob, &blen) != 0) {
					fatal("%s:%lu: fingerprint failed",
					    file, lnum);
				}
				r = ssh_krl_revoke_key_sha256(krl, blob, blen);
			} інакше
				r = ssh_krl_revoke_key(krl, key);
			якщо (r != 0)
				fatal_fr(r, "revoke key failed");
			freezero(blob, blen);
			blob = NULL;
			blen = 0;
			sshkey_free(key);
		}
	}
	якщо (strcmp(path, "-") != 0)
		fclose(krl_spec);
	free(line);
	free(path);
}

static void
do_gen_krl(struct passwd *pw, ціле updating, const char *ca_key_path,
    unsigned long long krl_version, const char *krl_comment,
    ціле argc, char **argv)
{
	struct ssh_krl *krl;
	struct stat sb;
	struct sshkey *ca = NULL;
	ціле i, r, wild_ca = 0;
	char *tmp;
	struct sshbuf *kbuf;

	якщо (*identity_file == '\0')
		fatal("KRL generation requires an output file");
	якщо (stat(identity_file, &sb) == -1) {
		якщо (errno != ENOENT)
			fatal("Cannot access KRL \"%s\": %s",
			    identity_file, strerror(errno));
		якщо (updating)
			fatal("KRL \"%s\" does not exist", identity_file);
	}
	якщо (ca_key_path != NULL) {
		якщо (strcasecmp(ca_key_path, "none") == 0)
			wild_ca = 1;
		інакше {
			tmp = tilde_expand_filename(ca_key_path, pw->pw_uid);
			якщо ((r = sshkey_load_public(tmp, &ca, NULL)) != 0)
				fatal_r(r, "Cannot load CA public key %s", tmp);
			free(tmp);
		}
	}

	якщо (updating)
		load_krl(identity_file, &krl);
	інакше якщо ((krl = ssh_krl_init()) == NULL)
		fatal("couldn't create KRL");

	якщо (krl_version != 0)
		ssh_krl_set_version(krl, krl_version);
	якщо (krl_comment != NULL)
		ssh_krl_set_comment(krl, krl_comment);

	для (i = 0; i < argc; i++)
		update_krl_from_file(pw, argv[i], wild_ca, ca, krl);

	якщо ((kbuf = sshbuf_new()) == NULL)
		fatal("sshbuf_new failed");
	якщо (ssh_krl_to_blob(krl, kbuf) != 0)
		fatal("Couldn't generate KRL");
	якщо ((r = sshbuf_write_file(identity_file, kbuf)) != 0)
		fatal("write %s: %s", identity_file, strerror(errno));
	sshbuf_free(kbuf);
	ssh_krl_free(krl);
	sshkey_free(ca);
}

static void
do_check_krl(struct passwd *pw, ціле print_krl, ціле argc, char **argv)
{
	ціле i, r, ret = 0;
	char *comment;
	struct ssh_krl *krl;
	struct sshkey *k;

	якщо (*identity_file == '\0')
		fatal("KRL checking requires an input file");
	load_krl(identity_file, &krl);
	якщо (print_krl)
		krl_dump(krl, stdout);
	для (i = 0; i < argc; i++) {
		якщо ((r = sshkey_load_public(argv[i], &k, &comment)) != 0)
			fatal_r(r, "Cannot load public key %s", argv[i]);
		r = ssh_krl_check_key(krl, k);
		printf("%s%s%s%s: %s\n", argv[i],
		    *comment ? " (" : "", comment, *comment ? ")" : "",
		    r == 0 ? "ok" : "REVOKED");
		якщо (r != 0)
			ret = 1;
		sshkey_free(k);
		free(comment);
	}
	ssh_krl_free(krl);
	exit(ret);
}

static struct sshkey *
load_sign_key(const char *keypath, const struct sshkey *pubkey)
{
	size_t i, slen, plen = strlen(keypath);
	char *privpath = xstrdup(keypath);
	static const char * const suffixes[] = { "-cert.pub", ".pub", NULL };
	struct sshkey *ret = NULL, *privkey = NULL;
	ціле r, waspub = 0;
	struct stat st;

	/*
	 * If passed a public key filename, then try to locate the corresponding
	 * private key. This lets us specify certificates on the command-line
	 * and have ssh-keygen find the appropriate private key.
	 */
	для (i = 0; suffixes[i]; i++) {
		slen = strlen(suffixes[i]);
		якщо (plen <= slen ||
		    strcmp(privpath + plen - slen, suffixes[i]) != 0)
			continue;
		privpath[plen - slen] = '\0';
		debug_f("%s looks like a public key, using private key "
		    "path %s instead", keypath, privpath);
		waspub = 1;
	}
	якщо (waspub && stat(privpath, &st) != 0 && errno == ENOENT)
		fatal("No private key found for public key \"%s\"", keypath);
	якщо ((r = sshkey_load_private(privpath, "", &privkey, NULL)) != 0 &&
	    (r != SSH_ERR_KEY_WRONG_PASSPHRASE)) {
		debug_fr(r, "load private key \"%s\"", privpath);
		fatal("No private key found for \"%s\"", privpath);
	} інакше якщо (privkey == NULL)
		privkey = load_identity(privpath, NULL);

	якщо (!sshkey_equal_public(pubkey, privkey)) {
		error("Public key %s doesn't match private %s",
		    keypath, privpath);
		goto done;
	}
	якщо (sshkey_is_cert(pubkey) && !sshkey_is_cert(privkey)) {
		/*
		 * Graft the certificate onto the private key to make
		 * it capable of signing.
		 */
		якщо ((r = sshkey_to_certified(privkey)) != 0) {
			error_fr(r, "sshkey_to_certified");
			goto done;
		}
		якщо ((r = sshkey_cert_copy(pubkey, privkey)) != 0) {
			error_fr(r, "sshkey_cert_copy");
			goto done;
		}
	}
	/* success */
	ret = privkey;
	privkey = NULL;
 done:
	sshkey_free(privkey);
	free(privpath);
	повернути ret;
}

static ціле
sign_one(struct sshkey *signkey, const char *filename, ціле fd,
    const char *sig_namespace, const char *hashalg, sshsig_signer *signer,
    void *signer_ctx)
{
	struct sshbuf *sigbuf = NULL, *abuf = NULL;
	ціле r = SSH_ERR_INTERNAL_ERROR, wfd = -1, oerrno;
	char *wfile = NULL, *asig = NULL, *fp = NULL;
	char *pin = NULL, *prompt = NULL;

	якщо (!quiet) {
		якщо (fd == STDIN_FILENO)
			fprintf(stderr, "Signing data on standard input\n");
		інакше
			fprintf(stderr, "Signing file %s\n", filename);
	}
	якщо (signer == NULL && sshkey_is_sk(signkey)) {
		якщо ((signkey->sk_flags & SSH_SK_USER_VERIFICATION_REQD)) {
			xasprintf(&prompt, "Enter PIN for %s key: ",
			    sshkey_type(signkey));
			якщо ((pin = read_passphrase(prompt,
			    RP_ALLOW_STDIN)) == NULL)
				fatal_f("couldn't read PIN");
		}
		якщо ((signkey->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
			якщо ((fp = sshkey_fingerprint(signkey, fingerprint_hash,
			    SSH_FP_DEFAULT)) == NULL)
				fatal_f("fingerprint failed");
			fprintf(stderr, "Confirm user presence for key %s %s\n",
			    sshkey_type(signkey), fp);
			free(fp);
		}
	}
	якщо ((r = sshsig_sign_fd(signkey, hashalg, sk_provider, pin,
	    fd, sig_namespace, &sigbuf, signer, signer_ctx)) != 0) {
		error_r(r, "Signing %s failed", filename);
		goto out;
	}
	якщо ((r = sshsig_armor(sigbuf, &abuf)) != 0) {
		error_fr(r, "sshsig_armor");
		goto out;
	}
	якщо ((asig = sshbuf_dup_string(abuf)) == NULL) {
		error_f("buffer error");
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	якщо (fd == STDIN_FILENO) {
		fputs(asig, stdout);
		fflush(stdout);
	} інакше {
		xasprintf(&wfile, "%s.sig", filename);
		якщо (confirm_overwrite(wfile)) {
			якщо ((wfd = open(wfile, O_WRONLY|O_CREAT|O_TRUNC,
			    0666)) == -1) {
				oerrno = errno;
				error("Cannot open %s: %s",
				    wfile, strerror(errno));
				errno = oerrno;
				r = SSH_ERR_SYSTEM_ERROR;
				goto out;
			}
			якщо (atomicio(vwrite, wfd, asig,
			    strlen(asig)) != strlen(asig)) {
				oerrno = errno;
				error("Cannot write to %s: %s",
				    wfile, strerror(errno));
				errno = oerrno;
				r = SSH_ERR_SYSTEM_ERROR;
				goto out;
			}
			якщо (!quiet) {
				fprintf(stderr, "Write signature to %s\n",
				    wfile);
			}
		}
	}
	/* success */
	r = 0;
 out:
	free(wfile);
	free(prompt);
	free(asig);
	якщо (pin != NULL)
		freezero(pin, strlen(pin));
	sshbuf_free(abuf);
	sshbuf_free(sigbuf);
	якщо (wfd != -1)
		close(wfd);
	повернути r;
}

static ціле
sig_process_opts(char * const *opts, size_t nopts, char **hashalgp,
    uint64_t *verify_timep, ціле *print_pubkey)
{
	size_t i;
	time_t now;
	const char *p;

	якщо (verify_timep != NULL)
		*verify_timep = 0;
	якщо (print_pubkey != NULL)
		*print_pubkey = 0;
	якщо (hashalgp != NULL)
		*hashalgp = NULL;
	для (i = 0; i < nopts; i++) {
		якщо (hashalgp != NULL &&
		    (p = strprefix(opts[i], "hashalg=", 1)) != NULL) {
			*hashalgp = xstrdup(p);
		} інакше якщо (verify_timep &&
		    (p = strprefix(opts[i], "verify-time=", 1)) != NULL) {
			якщо (parse_absolute_time(p, verify_timep) != 0 ||
			    *verify_timep == 0) {
				error("Invalid \"verify-time\" option");
				повернути SSH_ERR_INVALID_ARGUMENT;
			}
		} інакше якщо (print_pubkey &&
		    strcasecmp(opts[i], "print-pubkey") == 0) {
			*print_pubkey = 1;
		} інакше {
			error("Invalid option \"%s\"", opts[i]);
			повернути SSH_ERR_INVALID_ARGUMENT;
		}
	}
	якщо (verify_timep && *verify_timep == 0) {
		якщо ((now = time(NULL)) < 0) {
			error("Time is before epoch");
			повернути SSH_ERR_INVALID_ARGUMENT;
		}
		*verify_timep = (uint64_t)now;
	}
	повернути 0;
}


static ціле
sig_sign(const char *keypath, const char *sig_namespace, ціле require_agent,
    ціле argc, char **argv, char * const *opts, size_t nopts)
{
	ціле i, fd = -1, r, ret = -1;
	ціле agent_fd = -1;
	struct sshkey *pubkey = NULL, *privkey = NULL, *signkey = NULL;
	sshsig_signer *signer = NULL;
	char *hashalg = NULL;

	/* Check file arguments. */
	для (i = 0; i < argc; i++) {
		якщо (strcmp(argv[i], "-") != 0)
			continue;
		якщо (i > 0 || argc > 1)
			fatal("Cannot sign mix of paths and standard input");
	}

	якщо (sig_process_opts(opts, nopts, &hashalg, NULL, NULL) != 0)
		goto done; /* error already logged */

	якщо ((r = sshkey_load_public(keypath, &pubkey, NULL)) != 0) {
		error_r(r, "Couldn't load public key %s", keypath);
		goto done;
	}

	якщо ((r = ssh_get_authentication_socket(&agent_fd)) != 0) {
		якщо (require_agent)
			fatal("Couldn't get agent socket");
		debug_r(r, "Couldn't get agent socket");
	} інакше {
		якщо ((r = ssh_agent_has_key(agent_fd, pubkey)) == 0)
			signer = agent_signer;
		інакше {
			якщо (require_agent)
				fatal("Couldn't find key in agent");
			debug_r(r, "Couldn't find key in agent");
		}
	}

	якщо (signer == NULL) {
		/* Not using agent - try to load private key */
		якщо ((privkey = load_sign_key(keypath, pubkey)) == NULL)
			goto done;
		signkey = privkey;
	} інакше {
		/* Will use key in agent */
		signkey = pubkey;
	}

	якщо (argc == 0) {
		якщо ((r = sign_one(signkey, "(stdin)", STDIN_FILENO,
		    sig_namespace, hashalg, signer, &agent_fd)) != 0)
			goto done;
	} інакше {
		для (i = 0; i < argc; i++) {
			якщо (strcmp(argv[i], "-") == 0)
				fd = STDIN_FILENO;
			інакше якщо ((fd = open(argv[i], O_RDONLY)) == -1) {
				error("Cannot open %s for signing: %s",
				    argv[i], strerror(errno));
				goto done;
			}
			якщо ((r = sign_one(signkey, argv[i], fd, sig_namespace,
			    hashalg, signer, &agent_fd)) != 0)
				goto done;
			якщо (fd != STDIN_FILENO)
				close(fd);
			fd = -1;
		}
	}

	ret = 0;
done:
	якщо (fd != -1 && fd != STDIN_FILENO)
		close(fd);
	sshkey_free(pubkey);
	sshkey_free(privkey);
	free(hashalg);
	повернути ret;
}

static ціле
sig_verify(const char *signature, const char *sig_namespace,
    const char *principal, const char *allowed_keys, const char *revoked_keys,
    char * const *opts, size_t nopts)
{
	ціле r, ret = -1;
	ціле print_pubkey = 0;
	struct sshbuf *sigbuf = NULL, *abuf = NULL;
	struct sshkey *sign_key = NULL;
	char *fp = NULL;
	struct sshkey_sig_details *sig_details = NULL;
	uint64_t verify_time = 0;

	якщо (sig_process_opts(opts, nopts, NULL, &verify_time,
	    &print_pubkey) != 0)
		goto done; /* error already logged */

	memset(&sig_details, 0, sizeof(sig_details));
	якщо ((r = sshbuf_load_file(signature, &abuf)) != 0) {
		error_r(r, "Couldn't read signature file");
		goto done;
	}

	якщо ((r = sshsig_dearmor(abuf, &sigbuf)) != 0) {
		error_fr(r, "sshsig_armor");
		goto done;
	}
	якщо ((r = sshsig_verify_fd(sigbuf, STDIN_FILENO, sig_namespace,
	    &sign_key, &sig_details)) != 0)
		goto done; /* sshsig_verify() prints error */

	якщо ((fp = sshkey_fingerprint(sign_key, fingerprint_hash,
	    SSH_FP_DEFAULT)) == NULL)
		fatal_f("sshkey_fingerprint failed");
	debug("Valid (unverified) signature from key %s", fp);
	якщо (sig_details != NULL) {
		debug2_f("signature details: counter = %u, flags = 0x%02x",
		    sig_details->sk_counter, sig_details->sk_flags);
	}
	free(fp);
	fp = NULL;

	якщо (revoked_keys != NULL) {
		якщо ((r = sshkey_check_revoked(sign_key, revoked_keys)) != 0) {
			debug3_fr(r, "sshkey_check_revoked");
			goto done;
		}
	}

	якщо (allowed_keys != NULL && (r = sshsig_check_allowed_keys(allowed_keys,
	    sign_key, principal, sig_namespace, verify_time)) != 0) {
		debug3_fr(r, "sshsig_check_allowed_keys");
		goto done;
	}
	/* success */
	ret = 0;
done:
	якщо (!quiet) {
		якщо (ret == 0) {
			якщо ((fp = sshkey_fingerprint(sign_key, fingerprint_hash,
			    SSH_FP_DEFAULT)) == NULL)
				fatal_f("sshkey_fingerprint failed");
			якщо (principal == NULL) {
				printf("Good \"%s\" signature with %s key %s\n",
				    sig_namespace, sshkey_type(sign_key), fp);

			} інакше {
				printf("Good \"%s\" signature for %s with %s key %s\n",
				    sig_namespace, principal,
				    sshkey_type(sign_key), fp);
			}
		} інакше {
			printf("Could not verify signature.\n");
		}
	}
	/* Print the signature key if requested */
	якщо (ret == 0 && print_pubkey && sign_key != NULL) {
		якщо ((r = sshkey_write(sign_key, stdout)) == 0)
			fputc('\n', stdout);
		інакше {
			error_r(r, "Could not print public key.\n");
			ret = -1;
		}
	}
	sshbuf_free(sigbuf);
	sshbuf_free(abuf);
	sshkey_free(sign_key);
	sshkey_sig_details_free(sig_details);
	free(fp);
	повернути ret;
}

static ціле
sig_find_principals(const char *signature, const char *allowed_keys,
    char * const *opts, size_t nopts)
{
	ціле r, ret = -1;
	struct sshbuf *sigbuf = NULL, *abuf = NULL;
	struct sshkey *sign_key = NULL;
	char *principals = NULL, *cp, *tmp;
	uint64_t verify_time = 0;

	якщо (sig_process_opts(opts, nopts, NULL, &verify_time, NULL) != 0)
		goto done; /* error already logged */

	якщо ((r = sshbuf_load_file(signature, &abuf)) != 0) {
		error_r(r, "Couldn't read signature file");
		goto done;
	}
	якщо ((r = sshsig_dearmor(abuf, &sigbuf)) != 0) {
		error_fr(r, "sshsig_armor");
		goto done;
	}
	якщо ((r = sshsig_get_pubkey(sigbuf, &sign_key)) != 0) {
		error_fr(r, "sshsig_get_pubkey");
		goto done;
	}
	якщо ((r = sshsig_find_principals(allowed_keys, sign_key,
	    verify_time, &principals)) != 0) {
		якщо (r != SSH_ERR_KEY_NOT_FOUND)
			error_fr(r, "sshsig_find_principal");
		goto done;
	}
	ret = 0;
done:
	якщо (ret == 0 ) {
		/* Emit matching principals one per line */
		tmp = principals;
		поки ((cp = strsep(&tmp, ",")) != NULL && *cp != '\0')
			puts(cp);
	} інакше {
		fprintf(stderr, "No principal matched.\n");
	}
	sshbuf_free(sigbuf);
	sshbuf_free(abuf);
	sshkey_free(sign_key);
	free(principals);
	повернути ret;
}

static ціле
sig_match_principals(const char *allowed_keys, char *principal,
	char * const *opts, size_t nopts)
{
	ціле r;
	char **principals = NULL;
	size_t i, nprincipals = 0;

	якщо ((r = sig_process_opts(opts, nopts, NULL, NULL, NULL)) != 0)
		повернути r; /* error already logged */

	якщо ((r = sshsig_match_principals(allowed_keys, principal,
	    &principals, &nprincipals)) != 0) {
		debug_f("match: %s", ssh_err(r));
		fprintf(stderr, "No principal matched.\n");
		повернути r;
	}
	для (i = 0; i < nprincipals; i++) {
		printf("%s\n", principals[i]);
		free(principals[i]);
	}
	free(principals);

	повернути 0;
}

static void
do_moduli_gen(const char *out_file, char **opts, size_t nopts)
{
#ifdef WITH_OPENSSL
	/* Moduli generation/screening */
	BIGNUM *start = NULL;
	ціле moduli_bits = 0;
	FILE *out;
	size_t i;
	const char *errstr, *p;

	/* Parse options */
	для (i = 0; i < nopts; i++) {
		якщо ((p = strprefix(opts[i], "start=", 0)) != NULL) {
			/* XXX - also compare length against bits */
			якщо (BN_hex2bn(&start, p) == 0)
				fatal("Invalid start point.");
		} інакше якщо ((p = strprefix(opts[i], "bits=", 0)) != NULL) {
			moduli_bits = (ціле)strtonum(p, 1, INT_MAX, &errstr);
			якщо (errstr) {
				fatal("Invalid number: %s (%s)", p, errstr);
			}
		} інакше {
			fatal("Option \"%s\" is unsupported for moduli "
			    "generation", opts[i]);
		}
	}

	якщо (strcmp(out_file, "-") == 0)
		out = stdout;
	інакше якщо ((out = fopen(out_file, "w")) == NULL) {
		fatal("Couldn't open modulus candidate file \"%s\": %s",
		    out_file, strerror(errno));
	}
	setvbuf(out, NULL, _IOLBF, 0);

	якщо (moduli_bits == 0)
		moduli_bits = DEFAULT_BITS;
	якщо (gen_candidates(out, moduli_bits, start) != 0)
		fatal("modulus candidate generation failed");
#інакше /* WITH_OPENSSL */
	fatal("Moduli generation is not supported");
#endif /* WITH_OPENSSL */
}

static void
do_moduli_screen(const char *out_file, char **opts, size_t nopts)
{
#ifdef WITH_OPENSSL
	/* Moduli generation/screening */
	char *checkpoint = NULL;
	uint32_t generator_wanted = 0;
	unsigned long start_lineno = 0, lines_to_process = 0;
	ціле prime_tests = 0;
	FILE *out, *in = stdin;
	size_t i;
	const char *errstr, *p;

	/* Parse options */
	для (i = 0; i < nopts; i++) {
		якщо ((p = strprefix(opts[i], "lines=", 0)) != NULL) {
			lines_to_process = strtoul(p, NULL, 10);
		} інакше якщо ((p = strprefix(opts[i], "start-line=", 0)) != NULL) {
			start_lineno = strtoul(p, NULL, 10);
		} інакше якщо ((p = strprefix(opts[i], "checkpoint=", 0)) != NULL) {
			free(checkpoint);
			checkpoint = xstrdup(p);
		} інакше якщо ((p = strprefix(opts[i], "generator=", 0)) != NULL) {
			generator_wanted = (uint32_t)strtonum(p, 1, UINT_MAX,
			    &errstr);
			якщо (errstr != NULL) {
				fatal("Generator invalid: %s (%s)", p, errstr);
			}
		} інакше якщо ((p = strprefix(opts[i], "prime-tests=", 0)) != NULL) {
			prime_tests = (ціле)strtonum(p, 1, INT_MAX, &errstr);
			якщо (errstr) {
				fatal("Invalid number: %s (%s)", p, errstr);
			}
		} інакше {
			fatal("Option \"%s\" is unsupported for moduli "
			    "screening", opts[i]);
		}
	}

	якщо (have_identity && strcmp(identity_file, "-") != 0) {
		якщо ((in = fopen(identity_file, "r")) == NULL) {
			fatal("Couldn't open modulus candidate "
			    "file \"%s\": %s", identity_file,
			    strerror(errno));
		}
	}

	якщо (strcmp(out_file, "-") == 0)
		out = stdout;
	інакше якщо ((out = fopen(out_file, "a")) == NULL) {
		fatal("Couldn't open moduli file \"%s\": %s",
		    out_file, strerror(errno));
	}
	setvbuf(out, NULL, _IOLBF, 0);
	якщо (prime_test(in, out, prime_tests == 0 ? 100 : prime_tests,
	    generator_wanted, checkpoint,
	    start_lineno, lines_to_process) != 0)
		fatal("modulus screening failed");
	якщо (in != stdin)
		(void)fclose(in);
	free(checkpoint);
#інакше /* WITH_OPENSSL */
	fatal("Moduli screening is not supported");
#endif /* WITH_OPENSSL */
}

/* Read and confirm a passphrase */
static char *
read_check_passphrase(const char *prompt1, const char *prompt2,
    const char *retry_prompt)
{
	char *passphrase1, *passphrase2;

	для (;;) {
		passphrase1 = read_passphrase(prompt1, RP_ALLOW_STDIN);
		passphrase2 = read_passphrase(prompt2, RP_ALLOW_STDIN);
		якщо (strcmp(passphrase1, passphrase2) == 0) {
			freezero(passphrase2, strlen(passphrase2));
			повернути passphrase1;
		}
		/* The passphrases do not match. Clear them and retry. */
		freezero(passphrase1, strlen(passphrase1));
		freezero(passphrase2, strlen(passphrase2));
		fputs(retry_prompt, stdout);
		fputc('\n', stdout);
		fflush(stdout);
	}
	/* NOTREACHED */
	повернути NULL;
}

static char *
private_key_passphrase(const char *path)
{
	char *prompt, *ret;

	якщо (identity_passphrase)
		повернути xstrdup(identity_passphrase);
	якщо (identity_new_passphrase)
		повернути xstrdup(identity_new_passphrase);

	xasprintf(&prompt, "Enter passphrase for \"%s\" "
	    "(empty for no passphrase): ", path);
	ret = read_check_passphrase(prompt,
	    "Enter same passphrase again: ",
	    "Passphrases do not match.  Try again.");
	free(prompt);
	повернути ret;
}

static char *
sk_suffix(const char *application, const uint8_t *user, size_t userlen)
{
	char *ret, *cp;
	const char *p;
	size_t slen, i;

	/* Trim off URL-like preamble */
	якщо ((p = strprefix(application, "ssh://", 0)) != NULL)
		ret =  xstrdup(p);
	інакше якщо ((p = strprefix(application, "ssh:", 0)) != NULL)
		ret =  xstrdup(p);
	інакше
		ret = xstrdup(application);

	/* Count trailing zeros in user */
	для (i = 0; i < userlen; i++) {
		якщо (user[userlen - i - 1] != 0)
			break;
	}
	якщо (i >= userlen)
		повернути ret; /* user-id was default all-zeros */

	/* Append user-id, escaping non-UTF-8 characters */
	slen = userlen - i;
	якщо (asmprintf(&cp, INT_MAX, NULL, "%.*s", (ціле)slen, user) == -1)
		fatal_f("asmprintf failed");
	/* Don't emit a user-id that contains path or control characters */
	якщо (strchr(cp, '/') != NULL || strstr(cp, "..") != NULL ||
	    strchr(cp, '\\') != NULL) {
		free(cp);
		cp = tohex(user, slen);
	}
	xextendf(&ret, "_", "%s", cp);
	free(cp);
	повернути ret;
}

static ціле
do_download_sk(const char *skprovider, const char *device)
{
	struct sshsk_resident_key **srks;
	size_t nsrks, i;
	ціле r, ret = -1;
	char *fp, *pin = NULL, *pass = NULL, *path, *pubpath;
	const char *ext;
	struct sshkey *key;

	якщо (skprovider == NULL)
		fatal("Cannot download keys without provider");

	pin = read_passphrase("Enter PIN for authenticator: ", RP_ALLOW_STDIN);
	якщо (!quiet) {
		printf("You may need to touch your authenticator "
		    "to authorize key download.\n");
	}
	якщо ((r = sshsk_load_resident(skprovider, device, pin, 0,
	    &srks, &nsrks)) != 0) {
		якщо (pin != NULL)
			freezero(pin, strlen(pin));
		error_r(r, "Unable to load resident keys");
		повернути -1;
	}
	якщо (nsrks == 0)
		logit("No keys to download");
	якщо (pin != NULL)
		freezero(pin, strlen(pin));

	для (i = 0; i < nsrks; i++) {
		key = srks[i]->key;
		якщо (key->type != KEY_ECDSA_SK && key->type != KEY_ED25519_SK) {
			error("Unsupported key type %s (%d)",
			    sshkey_type(key), key->type);
			continue;
		}
		якщо ((fp = sshkey_fingerprint(key, fingerprint_hash,
		    SSH_FP_DEFAULT)) == NULL)
			fatal_f("sshkey_fingerprint failed");
		debug_f("key %zu: %s %s %s (flags 0x%02x)", i,
		    sshkey_type(key), fp, key->sk_application, key->sk_flags);
		ext = sk_suffix(key->sk_application,
		    srks[i]->user_id, srks[i]->user_id_len);
		xasprintf(&path, "id_%s_rk%s%s",
		    key->type == KEY_ECDSA_SK ? "ecdsa_sk" : "ed25519_sk",
		    *ext == '\0' ? "" : "_", ext);

		/* If the file already exists, ask the user to confirm. */
		якщо (!confirm_overwrite(path)) {
			free(path);
			break;
		}

		/* Save the key with the application string as the comment */
		якщо (pass == NULL)
			pass = private_key_passphrase(path);
		якщо ((r = sshkey_save_private(key, path, pass,
		    key->sk_application, private_key_format,
		    openssh_format_cipher, rounds)) != 0) {
			error_r(r, "Saving key \"%s\" failed", path);
			free(path);
			break;
		}
		якщо (!quiet) {
			printf("Saved %s key%s%s to %s\n", sshkey_type(key),
			    *ext != '\0' ? " " : "",
			    *ext != '\0' ? key->sk_application : "",
			    path);
		}

		/* Save public key too */
		xasprintf(&pubpath, "%s.pub", path);
		free(path);
		якщо ((r = sshkey_save_public(key, pubpath,
		    key->sk_application)) != 0) {
			error_r(r, "Saving public key \"%s\" failed", pubpath);
			free(pubpath);
			break;
		}
		free(pubpath);
	}

	якщо (i >= nsrks)
		ret = 0; /* success */
	якщо (pass != NULL)
		freezero(pass, strlen(pass));
	sshsk_free_resident_keys(srks, nsrks);
	повернути ret;
}

static void
save_attestation(struct sshbuf *attest, const char *path)
{
	mode_t omask;
	ціле r;

	якщо (path == NULL)
		повернути; /* nothing to do */
	якщо (attest == NULL || sshbuf_len(attest) == 0)
		fatal("Enrollment did not return attestation data");
	omask = umask(077);
	r = sshbuf_write_file(path, attest);
	umask(omask);
	якщо (r != 0)
		fatal_r(r, "Unable to write attestation data \"%s\"", path);
	якщо (!quiet)
		printf("Your FIDO attestation certificate has been saved in "
		    "%s\n", path);
}

static ціле
confirm_sk_overwrite(const char *application, const char *user)
{
	char yesno[3];

	printf("A resident key scoped to '%s' with user id '%s' already "
	    "exists.\n", application == NULL ? "ssh:" : application,
	    user == NULL ? "null" : user);
	printf("Overwrite key in token (y/n)? ");
	fflush(stdout);
	якщо (fgets(yesno, sizeof(yesno), stdin) == NULL)
		повернути 0;
	якщо (yesno[0] != 'y' && yesno[0] != 'Y')
		повернути 0;
	повернути 1;
}

static void
usage(void)
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
ціле
main(ціле argc, char **argv)
{
	char comment[KEY_COMMENT_MAX], *passphrase = NULL;
	char *rr_hostname = NULL, *ep, *fp, *ra;
	struct sshkey *private = NULL, *public = NULL;
	struct passwd *pw;
	ціле ret = 0, r, opt, type;
	ціле change_passphrase = 0, change_comment = 0, show_cert = 0;
	ціле find_host = 0, delete_host = 0, hash_hosts = 0;
	ціле gen_all_hostkeys = 0, gen_krl = 0, update_krl = 0, check_krl = 0;
	ціле prefer_agent = 0, convert_to = 0, convert_from = 0;
	ціле print_public = 0, print_generic = 0, cert_serial_autoinc = 0;
	ціле do_gen_candidates = 0, do_screen_candidates = 0, download_sk = 0;
	unsigned long long cert_serial = 0;
	char *identity_comment = NULL, *ca_key_path = NULL, **opts = NULL;
	char *sk_application = NULL, *sk_device = NULL, *sk_user = NULL;
	char *sk_attestation_path = NULL;
	struct sshbuf *challenge = NULL, *attest = NULL;
	size_t i, nopts = 0;
	uint32_t bits = 0;
	uint8_t sk_flags = SSH_SK_USER_PRESENCE_REQD;
	const char *errstr, *p;
	ціле log_level = SYSLOG_LEVEL_INFO;
	char *sign_op = NULL;

	extern ціле optind;
	extern char *optarg;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	__progname = ssh_get_progname(argv[0]);

	seed_rng();

	log_init(argv[0], SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_USER, 1);

	msetlocale();

	/* we need this for the home * directory.  */
	pw = getpwuid(getuid());
	якщо (!pw)
		fatal("No user exists for uid %lu", (u_long)getuid());
	pw = pwcopy(pw);
	якщо (gethostname(hostname, sizeof(hostname)) == -1)
		fatal("gethostname: %s", strerror(errno));

	sk_provider = getenv("SSH_SK_PROVIDER");

	/* Remaining characters: dGjJSTWx */
	поки ((opt = getopt(argc, argv, "ABHKLQUXceghiklopquvy"
	    "C:D:E:F:I:M:N:O:P:R:V:Y:Z:"
	    "a:b:f:g:m:n:r:s:t:w:z:")) != -1) {
		switch (opt) {
		case 'A':
			gen_all_hostkeys = 1;
			break;
		case 'b':
			bits = (uint32_t)strtonum(optarg, 1, UINT32_MAX,
			    &errstr);
			якщо (errstr)
				fatal("Bits has bad value %s (%s)",
					optarg, errstr);
			break;
		case 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			якщо (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			break;
		case 'F':
			find_host = 1;
			rr_hostname = optarg;
			break;
		case 'H':
			hash_hosts = 1;
			break;
		case 'I':
			cert_key_id = optarg;
			break;
		case 'R':
			delete_host = 1;
			rr_hostname = optarg;
			break;
		case 'L':
			show_cert = 1;
			break;
		case 'l':
			print_fingerprint = 1;
			break;
		case 'B':
			print_bubblebabble = 1;
			break;
		case 'm':
			якщо (strcasecmp(optarg, "RFC4716") == 0 ||
			    strcasecmp(optarg, "ssh2") == 0) {
				convert_format = FMT_RFC4716;
				break;
			}
			якщо (strcasecmp(optarg, "PKCS8") == 0) {
				convert_format = FMT_PKCS8;
				private_key_format = SSHKEY_PRIVATE_PKCS8;
				break;
			}
			якщо (strcasecmp(optarg, "PEM") == 0) {
				convert_format = FMT_PEM;
				private_key_format = SSHKEY_PRIVATE_PEM;
				break;
			}
			якщо (strcasecmp(optarg, "hexdump") == 0) {
				convert_format = FMT_HEXDUMP;
				break;
			}
			fatal("Unsupported conversion format \"%s\"", optarg);
		case 'n':
			cert_principals = optarg;
			break;
		case 'o':
			/* no-op; new format is already the default */
			break;
		case 'p':
			change_passphrase = 1;
			break;
		case 'c':
			change_comment = 1;
			break;
		case 'f':
			якщо (strlcpy(identity_file, optarg,
			    sizeof(identity_file)) >= sizeof(identity_file))
				fatal("Identity filename too long");
			have_identity = 1;
			break;
		case 'g':
			print_generic = 1;
			break;
		case 'K':
			download_sk = 1;
			break;
		case 'P':
			identity_passphrase = optarg;
			break;
		case 'N':
			identity_new_passphrase = optarg;
			break;
		case 'Q':
			check_krl = 1;
			break;
		case 'O':
			opts = xrecallocarray(opts, nopts, nopts + 1,
			    sizeof(*opts));
			opts[nopts++] = xstrdup(optarg);
			break;
		case 'Z':
			openssh_format_cipher = optarg;
			якщо (cipher_by_name(openssh_format_cipher) == NULL)
				fatal("Invalid OpenSSH-format cipher '%s'",
				    openssh_format_cipher);
			break;
		case 'C':
			identity_comment = optarg;
			break;
		case 'q':
			quiet = 1;
			break;
		case 'e':
			/* export key */
			convert_to = 1;
			break;
		case 'h':
			cert_key_type = SSH2_CERT_TYPE_HOST;
			certflags_flags = 0;
			break;
		case 'k':
			gen_krl = 1;
			break;
		case 'i':
		case 'X':
			/* import key */
			convert_from = 1;
			break;
		case 'y':
			print_public = 1;
			break;
		case 's':
			ca_key_path = optarg;
			break;
		case 't':
			key_type_name = optarg;
			break;
		case 'D':
			pkcs11provider = optarg;
			break;
		case 'U':
			prefer_agent = 1;
			break;
		case 'u':
			update_krl = 1;
			break;
		case 'v':
			якщо (log_level == SYSLOG_LEVEL_INFO)
				log_level = SYSLOG_LEVEL_DEBUG1;
			інакше {
				якщо (log_level >= SYSLOG_LEVEL_DEBUG1 &&
				    log_level < SYSLOG_LEVEL_DEBUG3)
					log_level++;
			}
			break;
		case 'r':
			rr_hostname = optarg;
			break;
		case 'a':
			rounds = (ціле)strtonum(optarg, 1, INT_MAX, &errstr);
			якщо (errstr)
				fatal("Invalid number: %s (%s)",
					optarg, errstr);
			break;
		case 'V':
			parse_cert_times(optarg);
			break;
		case 'Y':
			sign_op = optarg;
			break;
		case 'w':
			sk_provider = optarg;
			break;
		case 'z':
			errno = 0;
			якщо (*optarg == '+') {
				cert_serial_autoinc = 1;
				optarg++;
			}
			cert_serial = strtoull(optarg, &ep, 10);
			якщо (*optarg < '0' || *optarg > '9' || *ep != '\0' ||
			    (errno == ERANGE && cert_serial == ULLONG_MAX))
				fatal("Invalid serial number \"%s\"", optarg);
			break;
		case 'M':
			якщо (strcmp(optarg, "generate") == 0)
				do_gen_candidates = 1;
			інакше якщо (strcmp(optarg, "screen") == 0)
				do_screen_candidates = 1;
			інакше
				fatal("Unsupported moduli option %s", optarg);
			break;
		default:
			usage();
		}
	}

#ifdef ENABLE_SK_INTERNAL
	якщо (sk_provider == NULL)
		sk_provider = "internal";
#endif

	/* reinit */
	log_init(argv[0], log_level, SYSLOG_FACILITY_USER, 1);

	argv += optind;
	argc -= optind;

	якщо (sign_op != NULL) {
		якщо (strprefix(sign_op, "find-principals", 0) != NULL) {
			якщо (ca_key_path == NULL) {
				error("Too few arguments for find-principals:"
				    "missing signature file");
				exit(1);
			}
			якщо (!have_identity) {
				error("Too few arguments for find-principals:"
				    "missing allowed keys file");
				exit(1);
			}
			ret = sig_find_principals(ca_key_path, identity_file,
			    opts, nopts);
			goto done;
		} інакше якщо (strprefix(sign_op, "match-principals", 0) != NULL) {
			якщо (!have_identity) {
				error("Too few arguments for match-principals:"
				    "missing allowed keys file");
				exit(1);
			}
			якщо (cert_key_id == NULL) {
				error("Too few arguments for match-principals: "
				    "missing principal ID");
				exit(1);
			}
			ret = sig_match_principals(identity_file, cert_key_id,
			    opts, nopts);
			goto done;
		} інакше якщо (strprefix(sign_op, "sign", 0) != NULL) {
			/* NB. cert_principals is actually namespace, via -n */
			якщо (cert_principals == NULL ||
			    *cert_principals == '\0') {
				error("Too few arguments for sign: "
				    "missing namespace");
				exit(1);
			}
			якщо (!have_identity) {
				error("Too few arguments for sign: "
				    "missing key");
				exit(1);
			}
			ret = sig_sign(identity_file, cert_principals,
			    prefer_agent, argc, argv, opts, nopts);
			goto done;
		} інакше якщо (strprefix(sign_op, "check-novalidate", 0) != NULL) {
			/* NB. cert_principals is actually namespace, via -n */
			якщо (cert_principals == NULL ||
			    *cert_principals == '\0') {
				error("Too few arguments for check-novalidate: "
				    "missing namespace");
				exit(1);
			}
			якщо (ca_key_path == NULL) {
				error("Too few arguments for check-novalidate: "
				    "missing signature file");
				exit(1);
			}
			ret = sig_verify(ca_key_path, cert_principals,
			    NULL, NULL, NULL, opts, nopts);
			goto done;
		} інакше якщо (strprefix(sign_op, "verify", 0) != NULL) {
			/* NB. cert_principals is actually namespace, via -n */
			якщо (cert_principals == NULL ||
			    *cert_principals == '\0') {
				error("Too few arguments for verify: "
				    "missing namespace");
				exit(1);
			}
			якщо (ca_key_path == NULL) {
				error("Too few arguments for verify: "
				    "missing signature file");
				exit(1);
			}
			якщо (!have_identity) {
				error("Too few arguments for sign: "
				    "missing allowed keys file");
				exit(1);
			}
			якщо (cert_key_id == NULL) {
				error("Too few arguments for verify: "
				    "missing principal identity");
				exit(1);
			}
			ret = sig_verify(ca_key_path, cert_principals,
			    cert_key_id, identity_file, rr_hostname,
			    opts, nopts);
			goto done;
		}
		error("Unsupported operation for -Y: \"%s\"", sign_op);
		usage();
		/* NOTREACHED */
	}

	якщо (ca_key_path != NULL) {
		якщо (argc < 1 && !gen_krl) {
			error("Too few arguments.");
			usage();
		}
	} інакше якщо (argc > 0 && !gen_krl && !check_krl &&
	    !do_gen_candidates && !do_screen_candidates) {
		error("Too many arguments.");
		usage();
	}
	якщо (change_passphrase && change_comment) {
		error("Can only have one of -p and -c.");
		usage();
	}
	якщо (print_fingerprint && (delete_host || hash_hosts)) {
		error("Cannot use -l with -H or -R.");
		usage();
	}
	якщо (gen_krl) {
		do_gen_krl(pw, update_krl, ca_key_path,
		    cert_serial, identity_comment, argc, argv);
		goto done;
	}
	якщо (check_krl) {
		do_check_krl(pw, print_fingerprint, argc, argv);
		goto done;
	}
	якщо (ca_key_path != NULL) {
		якщо (cert_key_id == NULL)
			fatal("Must specify key id (-I) when certifying");
		якщо (cert_principals == NULL) {
			/*
			 * Ideally this would be a fatal(), but we need to
			 * be able to generate such certificates for testing
			 * even though they will be rejected.
			 */
			error("Warning: certificate will contain no "
			    "principals (-n)");
		}
		для (i = 0; i < nopts; i++)
			add_cert_option(opts[i]);
		do_ca_sign(pw, ca_key_path, prefer_agent,
		    cert_serial, cert_serial_autoinc, argc, argv);
		goto done;
	}
	якщо (show_cert)
		do_show_cert(pw);
	якщо (delete_host || hash_hosts || find_host) {
		do_known_hosts(pw, rr_hostname, find_host,
		    delete_host, hash_hosts);
	}
	якщо (pkcs11provider != NULL)
		do_download(pw);
	якщо (download_sk) {
		для (i = 0; i < nopts; i++) {
			якщо ((p = strprefix(opts[i], "device=", 1)) != NULL) {
				sk_device = xstrdup(p);
			} інакше {
				fatal("Option \"%s\" is unsupported for "
				    "FIDO authenticator download", opts[i]);
			}
		}
		ret = do_download_sk(sk_provider, sk_device);
		goto done;
	}
	якщо (print_fingerprint || print_bubblebabble)
		do_fingerprint(pw);
	якщо (change_passphrase)
		do_change_passphrase(pw, opts, nopts);
	якщо (change_comment)
		do_change_comment(pw, identity_comment);
#ifdef WITH_OPENSSL
	якщо (convert_to) {
		do_convert_to(pw);
		goto done;
	}
	якщо (convert_from) {
		do_convert_from(pw);
		goto done;
	}
#інакше /* WITH_OPENSSL */
	якщо (convert_to || convert_from)
		fatal("key conversion disabled at compile time");
#endif /* WITH_OPENSSL */
	якщо (print_public)
		do_print_public(pw);
	якщо (rr_hostname != NULL) {
		unsigned ціле n = 0;

		якщо (have_identity) {
			n = do_print_resource_record(pw, identity_file,
			    rr_hostname, print_generic, opts, nopts);
			якщо (n == 0)
				fatal("%s: %s", identity_file, strerror(errno));
			exit(0);
		} інакше {

			n += do_print_resource_record(pw,
			    _PATH_HOST_RSA_KEY_FILE, rr_hostname,
			    print_generic, opts, nopts);
			n += do_print_resource_record(pw,
			    _PATH_HOST_ECDSA_KEY_FILE, rr_hostname,
			    print_generic, opts, nopts);
			n += do_print_resource_record(pw,
			    _PATH_HOST_ED25519_KEY_FILE, rr_hostname,
			    print_generic, opts, nopts);
			якщо (n == 0)
				fatal("no keys found.");
			exit(0);
		}
	}

	якщо (do_gen_candidates || do_screen_candidates) {
		якщо (argc <= 0)
			fatal("No output file specified");
		інакше якщо (argc > 1)
			fatal("Too many output files specified");
	}
	якщо (do_gen_candidates) {
		do_moduli_gen(argv[0], opts, nopts);
		goto done;
	}
	якщо (do_screen_candidates) {
		do_moduli_screen(argv[0], opts, nopts);
		goto done;
	}

	якщо (gen_all_hostkeys) {
		do_gen_all_hostkeys(pw);
		goto done;
	}

	якщо (key_type_name == NULL)
		key_type_name = DEFAULT_KEY_TYPE_NAME;

	type = sshkey_type_from_shortname(key_type_name);
	type_bits_valid(type, key_type_name, &bits);

	якщо (!quiet)
		printf("Generating public/private %s key pair.\n",
		    key_type_name);
	switch (type) {
	case KEY_ECDSA_SK:
	case KEY_ED25519_SK:
		для (i = 0; i < nopts; i++) {
			якщо (strcasecmp(opts[i], "no-touch-required") == 0) {
				sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
			} інакше якщо (strcasecmp(opts[i], "verify-required") == 0) {
				sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
			} інакше якщо (strcasecmp(opts[i], "resident") == 0) {
				sk_flags |= SSH_SK_RESIDENT_KEY;
			} інакше якщо ((p = strprefix(opts[i], "device=", 1))
			    != NULL ) {
				sk_device = xstrdup(p);
			} інакше якщо ((p = strprefix(opts[i], "user=", 1))
			    != NULL) {
				sk_user = xstrdup(p);
			} інакше якщо ((p = strprefix(opts[i], "challenge=", 1))
			    != NULL) {
				якщо ((r = sshbuf_load_file(p,
				    &challenge)) != 0) {
					fatal_r(r, "Unable to load FIDO "
					    "enrollment challenge \"%s\"", p);
				}
			} інакше якщо (strncasecmp(opts[i],
			    "write-attestation=", 18) == 0) {
				sk_attestation_path = opts[i] + 18;
			} інакше якщо (strncasecmp(opts[i],
			    "application=", 12) == 0) {
				sk_application = xstrdup(opts[i] + 12);
				якщо (strncmp(sk_application, "ssh:", 4) != 0) {
					fatal("FIDO application string must "
					    "begin with \"ssh:\"");
				}
			} інакше {
				fatal("Option \"%s\" is unsupported for "
				    "FIDO authenticator enrollment", opts[i]);
			}
		}
		якщо ((attest = sshbuf_new()) == NULL)
			fatal("sshbuf_new failed");
		r = 0;
		для (i = 0 ;;) {
			якщо (!quiet) {
				printf("You may need to touch your "
				    "authenticator%s to authorize key "
				    "generation.\n",
				    r == 0 ? "" : " again");
			}
			fflush(stdout);
			r = sshsk_enroll(type, sk_provider, sk_device,
			    sk_application == NULL ? "ssh:" : sk_application,
			    sk_user, sk_flags, passphrase, challenge,
			    &private, attest);
			якщо (r == 0)
				break;
			якщо (r == SSH_ERR_KEY_BAD_PERMISSIONS &&
			    (sk_flags & SSH_SK_RESIDENT_KEY) != 0 &&
			    (sk_flags & SSH_SK_FORCE_OPERATION) == 0 &&
			    confirm_sk_overwrite(sk_application, sk_user)) {
				sk_flags |= SSH_SK_FORCE_OPERATION;
				continue;
			}
			якщо (r != SSH_ERR_KEY_WRONG_PASSPHRASE)
				fatal_r(r, "Key enrollment failed");
			інакше якщо (passphrase != NULL) {
				error("PIN incorrect");
				freezero(passphrase, strlen(passphrase));
				passphrase = NULL;
			}
			якщо (++i >= 3)
				fatal("Too many incorrect PINs");
			passphrase = read_passphrase("Enter PIN for "
			    "authenticator: ", RP_ALLOW_STDIN);
		}
		якщо (passphrase != NULL) {
			freezero(passphrase, strlen(passphrase));
			passphrase = NULL;
		}
		break;
	default:
		якщо ((r = sshkey_generate(type, bits, &private)) != 0)
			fatal("sshkey_generate failed");
		break;
	}
	якщо ((r = sshkey_from_private(private, &public)) != 0)
		fatal_r(r, "sshkey_from_private");

	якщо (!have_identity)
		ask_filename(pw, "Enter file in which to save the key");

	/* Create ~/.ssh directory if it doesn't already exist. */
	hostfile_create_user_ssh_dir(identity_file, !quiet);

	/* If the file already exists, ask the user to confirm. */
	якщо (!confirm_overwrite(identity_file))
		exit(1);

	/* Determine the passphrase for the private key */
	passphrase = private_key_passphrase(identity_file);
	якщо (identity_comment) {
		strlcpy(comment, identity_comment, sizeof(comment));
	} інакше {
		/* Create default comment field for the passphrase. */
		snprintf(comment, sizeof comment, "%s@%s", pw->pw_name, hostname);
	}



	/* Save the key with the given passphrase and comment. */
	якщо ((r = sshkey_save_private(private, identity_file, passphrase,
	    comment, private_key_format, openssh_format_cipher, rounds)) != 0) {
		error_r(r, "Saving key \"%s\" failed", identity_file);
		freezero(passphrase, strlen(passphrase));
		exit(1);
	}
	freezero(passphrase, strlen(passphrase));
	sshkey_free(private);

	якщо (!quiet) {
		printf("Your identification has been saved in %s\n",
		    identity_file);
	}

	strlcat(identity_file, ".pub", sizeof(identity_file));
	якщо ((r = sshkey_save_public(public, identity_file, comment)) != 0)
		fatal_r(r, "Unable to save public key to %s", identity_file);

	якщо (!quiet) {
		fp = sshkey_fingerprint(public, fingerprint_hash,
		    SSH_FP_DEFAULT);
		ra = sshkey_fingerprint(public, fingerprint_hash,
		    SSH_FP_RANDOMART);
		якщо (fp == NULL || ra == NULL)
			fatal("sshkey_fingerprint failed");
		printf("Your public key has been saved in %s\n",
		    identity_file);
		printf("The key fingerprint is:\n");
		printf("%s %s\n", fp, comment);
		printf("The key's randomart image is:\n");
		printf("%s\n", ra);
		free(ra);
		free(fp);
	}

	якщо (sk_attestation_path != NULL)
		save_attestation(attest, sk_attestation_path);

 done:
	sshbuf_free(attest);
	sshkey_free(public);
	pwfree(pw);
	exit(ret);
}
