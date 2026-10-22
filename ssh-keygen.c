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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/socket.h>
#ଅନ୍ତର୍ଭାଵ <sys/stat.h>

#ifdef WITH_OPENSSL
#ଅନ୍ତର୍ଭାଵ "openbsd-compat/openssl-compat.h"
#ଅନ୍ତର୍ଭାଵ <openssl/bn.h>
#ଅନ୍ତର୍ଭାଵ <openssl/evp.h>
#ଅନ୍ତର୍ଭାଵ <openssl/pem.h>
#endif

#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <fcntl.h>
#ଅନ୍ତର୍ଭାଵ <netdb.h>
#ଅନ୍ତର୍ଭାଵ <paths.h>
#ଅନ୍ତର୍ଭାଵ <pwd.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>
#ଅନ୍ତର୍ଭାଵ <locale.h>
#ଅନ୍ତର୍ଭାଵ <time.h>

#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "authfile.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "pathnames.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "match.h"
#ଅନ୍ତର୍ଭାଵ "hostfile.h"
#ଅନ୍ତର୍ଭାଵ "dns.h"
#ଅନ୍ତର୍ଭାଵ "ssh.h"
#ଅନ୍ତର୍ଭାଵ "ssh2.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "atomicio.h"
#ଅନ୍ତର୍ଭାଵ "krl.h"
#ଅନ୍ତର୍ଭାଵ "digest.h"
#ଅନ୍ତର୍ଭାଵ "utf8.h"
#ଅନ୍ତର୍ଭାଵ "authfd.h"
#ଅନ୍ତର୍ଭାଵ "sshsig.h"
#ଅନ୍ତର୍ଭାଵ "ssh-sk.h"
#ଅନ୍ତର୍ଭାଵ "sk-api.h" /* XXX for SSH_SK_USER_PRESENCE_REQD; remove */
#ଅନ୍ତର୍ଭାଵ "cipher.h"

#ifdef ENABLE_PKCS11
#ଅନ୍ତର୍ଭାଵ "ssh-pkcs11.h"
#endif

#define DEFAULT_ଚାବି_TYPE_NAME "ed25519"

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

#define ଚାବି_COMMENT_MAX		(NI_MAXHOST + 1024)

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା quiet = 0;

/* Flag indicating that we just want to see the key fingerprint */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା print_fingerprint = 0;
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା print_bubblebabble = 0;

/* Hash algorithm to use for fingerprints. */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* The identity file name, given on the command line or entered by the user. */
ସ୍ଥିର ଅକ୍ଷର identity_file[PATH_MAX];
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା have_identity = 0;

/* This is set to the passphrase if given on the command line. */
ସ୍ଥିର ଅକ୍ଷର *identity_passphrase = ଖାଲି;

/* This is set to the new passphrase if given on the command line. */
ସ୍ଥିର ଅକ୍ଷର *identity_new_passphrase = ଖାଲି;

/* Key type when certifying */
ସ୍ଥିର u_int cert_ଚାବି_type = SSH2_CERT_TYPE_USER;

/* "key ID" of signed key */
ସ୍ଥିର ଅକ୍ଷର *cert_ଚାବି_id = ଖାଲି;

/* Comma-separated list of principal names for certifying keys */
ସ୍ଥିର ଅକ୍ଷର *cert_principals = ଖାଲି;

/* Validity period for certificates */
ସ୍ଥିର uint64_t cert_valid_from = 0;
ସ୍ଥିର uint64_t cert_valid_to = ~0ULL;

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
ସ୍ଥିର uint32_t certflags_flags = CERTOPT_DEFAULT;
ସ୍ଥିର ଅକ୍ଷର *certflags_command = ଖାଲି;
ସ୍ଥିର ଅକ୍ଷର *certflags_src_addr = ଖାଲି;

/* Arbitrary extensions specified by user */
ସଂରଚନା cert_ext {
	ଅକ୍ଷର *ଚାବି;
	ଅକ୍ଷର *val;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା crit;
};
ସ୍ଥିର ସଂରଚନା cert_ext *cert_ext;
ସ୍ଥିର size_t ncert_ext;

/* Conversion to/from various formats */
ଗଣନା {
	FMT_RFC4716,
	FMT_PKCS8,
	FMT_PEM,
	FMT_HEXDUMP
} convert_format = FMT_RFC4716;

ସ୍ଥିର ଅକ୍ଷର *ଚାବି_type_name = ଖାଲି;

/* Load key from this PKCS#11 provider */
ସ୍ଥିର ଅକ୍ଷର *pkcs11provider = ଖାଲି;

/* FIDO/U2F provider to use */
ସ୍ଥିର ଅକ୍ଷର *sk_provider = ଖାଲି;

/* Format for writing private keys */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା private_ଚାବି_format = SSHKEY_PRIVATE_OPENSSH;

/* Cipher for new-format private keys */
ସ୍ଥିର ଅକ୍ଷର *openssh_format_cipher = ଖାଲି;

/* Number of KDF rounds to derive new format keys. */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା rounds = 0;

/* argv0 */
ବାହ୍ୟ ଅକ୍ଷର *__progname;

ସ୍ଥିର ଅକ୍ଷର hostname[NI_MAXHOST];

#ifdef WITH_OPENSSL
/* moduli.c */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା gen_candidates(FILE *, uint32_t, BIGNUM *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା ମୌଳିକ_test(FILE *, FILE *, uint32_t, uint32_t, ଅକ୍ଷର *, unsigned long,
    unsigned long);
#endif

ସ୍ଥିର ଶୂନ୍ୟ
type_bits_valid(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, ଅଚଳ ଅକ୍ଷର *name, uint32_t *bitsp)
{
	ଯଦି (type == ଚାବି_UNSPEC)
		fatal("unknown key type %s", ଚାବି_type_name);
	ଯଦି (*bitsp == 0) {
#ifdef WITH_OPENSSL
		ପୂର୍ଣ୍ଣସଂଖ୍ୟା nid;

		ବାଛ(type) {
		ସ୍ଥିତି ଚାବି_ECDSA:
			ଯଦି (name != ଖାଲି &&
			    (nid = sshkey_ecdsa_nid_from_name(name)) > 0)
				*bitsp = sshkey_curve_nid_to_bits(nid);
			ଯଦି (*bitsp == 0)
				*bitsp = DEFAULT_BITS_ECDSA;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି ଚାବି_RSA:
			*bitsp = DEFAULT_BITS;
			ଭାଙ୍ଗ;
		}
#endif
	}
#ifdef WITH_OPENSSL
	ବାଛ (type) {
	ସ୍ଥିତି ଚାବି_RSA:
		ଯଦି (*bitsp < SSH_RSA_MINIMUM_MODULUS_SIZE)
			fatal("Invalid RSA key length: minimum is %d bits",
			    SSH_RSA_MINIMUM_MODULUS_SIZE);
		ଅନ୍ୟଥା ଯଦି (*bitsp > OPENSSL_RSA_MAX_MODULUS_BITS)
			fatal("Invalid RSA key length: maximum is %d bits",
			    OPENSSL_RSA_MAX_MODULUS_BITS);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି ଚାବି_ECDSA:
		ଯଦି (sshkey_ecdsa_bits_to_nid(*bitsp) == -1)
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
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
confirm_overwrite(ଅଚଳ ଅକ୍ଷର *filename)
{
	ଅକ୍ଷର yesno[3];
	ସଂରଚନା stat st;

	ଯଦି (stat(filename, &st) != 0)
		ଫେରନ୍ତୁ 1;
	printf("%s already exists.\n", filename);
	printf("Overwrite (y/n)? ");
	fflush(stdout);
	ଯଦି (fgets(yesno, ଆକାର(yesno), stdin) == ଖାଲି)
		ଫେରନ୍ତୁ 0;
	ଯଦି (yesno[0] != 'y' && yesno[0] != 'Y')
		ଫେରନ୍ତୁ 0;
	ଫେରନ୍ତୁ 1;
}

ସ୍ଥିର ଶୂନ୍ୟ
ask_filename(ସଂରଚନା passwd *pw, ଅଚଳ ଅକ୍ଷର *prompt)
{
	ଅକ୍ଷର buf[1024];
	ଅକ୍ଷର *name = ଖାଲି;

	ଯଦି (ଚାବି_type_name == ଖାଲି)
		name = _PATH_SSH_CLIENT_ID_ED25519;
	ଅନ୍ୟଥା {
		ବାଛ (sshkey_type_from_shortname(ଚାବି_type_name)) {
		ସ୍ଥିତି ଚାବି_ECDSA_CERT:
		ସ୍ଥିତି ଚାବି_ECDSA:
			name = _PATH_SSH_CLIENT_ID_ECDSA;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି ଚାବି_ECDSA_SK_CERT:
		ସ୍ଥିତି ଚାବି_ECDSA_SK:
			name = _PATH_SSH_CLIENT_ID_ECDSA_SK;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି ଚାବି_RSA_CERT:
		ସ୍ଥିତି ଚାବି_RSA:
			name = _PATH_SSH_CLIENT_ID_RSA;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି ଚାବି_ED25519:
		ସ୍ଥିତି ଚାବି_ED25519_CERT:
			name = _PATH_SSH_CLIENT_ID_ED25519;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି ଚାବି_ED25519_SK:
		ସ୍ଥିତି ଚାବି_ED25519_SK_CERT:
			name = _PATH_SSH_CLIENT_ID_ED25519_SK;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି ଚାବି_MLDSA44_ED25519:
		ସ୍ଥିତି ଚାବି_MLDSA44_ED25519_CERT:
			name = _PATH_SSH_CLIENT_ID_MLDSA44_ED25519;
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			fatal("bad key type");
		}
	}
	snprintf(identity_file, ଆକାର(identity_file),
	    "%s/%s", pw->pw_dir, name);
	printf("%s (%s): ", prompt, identity_file);
	fflush(stdout);
	ଯଦି (fgets(buf, ଆକାର(buf), stdin) == ଖାଲି)
		exit(1);
	buf[strcspn(buf, "\n")] = '\0';
	ଯଦି (strcmp(buf, "") != 0)
		strlcpy(identity_file, buf, ଆକାର(identity_file));
	have_identity = 1;
}

ସ୍ଥିର ସଂରଚନା sshkey *
load_identity(ଅଚଳ ଅକ୍ଷର *filename, ଅକ୍ଷର **commentp)
{
	ଅକ୍ଷର *prompt, *pass;
	ସଂରଚନା sshkey *prv;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (commentp != ଖାଲି)
		*commentp = ଖାଲି;
	ଯଦି ((r = sshkey_load_private(filename, "", &prv, commentp)) == 0)
		ଫେରନ୍ତୁ prv;
	ଯଦି (r != SSH_ERR_ଚାବି_WRONG_PASSPHRASE)
		fatal_r(r, "Load key \"%s\"", filename);
	ଯଦି (identity_passphrase)
		pass = xstrdup(identity_passphrase);
	ଅନ୍ୟଥା {
		xasprintf(&prompt, "Enter passphrase for \"%s\": ", filename);
		pass = read_passphrase(prompt, RP_ALLOW_STDIN);
		ମୁକ୍ତ(prompt);
	}
	r = sshkey_load_private(filename, pass, &prv, commentp);
	freezero(pass, strlen(pass));
	ଯଦି (r != 0)
		fatal_r(r, "Load key \"%s\"", filename);
	ଫେରନ୍ତୁ prv;
}

#define SSH_COM_PUBLIC_BEGIN		"---- BEGIN SSH2 PUBLIC KEY ----"
#define SSH_COM_PUBLIC_END		"---- END SSH2 PUBLIC KEY ----"
#define SSH_COM_PRIVATE_BEGIN		"---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----"
#define	SSH_COM_PRIVATE_ଚାବି_MAGIC	0x3f6ff9eb

#ifdef WITH_OPENSSL
ସ୍ଥିର ଶୂନ୍ୟ
do_convert_to_ssh2(ସଂରଚନା passwd *pw, ସଂରଚନା sshkey *k)
{
	ସଂରଚନା sshbuf *b;
	ଅକ୍ଷର comment[61], *b64;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((b = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = sshkey_putb(k, b)) != 0)
		fatal_fr(r, "put key");
	ଯଦି ((b64 = sshbuf_dtob64_string(b, 1)) == ଖାଲି)
		fatal_f("sshbuf_dtob64_string failed");

	/* Comment + surrounds must fit into 72 chars (RFC 4716 sec 3.3) */
	snprintf(comment, ଆକାର(comment),
	    "%u-bit %s, converted by %s@%s from OpenSSH",
	    sshkey_size(k), sshkey_type(k),
	    pw->pw_name, hostname);

	sshkey_free(k);
	sshbuf_free(b);

	fprintf(stdout, "%s\n", SSH_COM_PUBLIC_BEGIN);
	fprintf(stdout, "Comment: \"%s\"\n%s", comment, b64);
	fprintf(stdout, "%s\n", SSH_COM_PUBLIC_END);
	ମୁକ୍ତ(b64);
}

ସ୍ଥିର ଶୂନ୍ୟ
do_convert_to_pkcs8(ସଂରଚନା sshkey *k)
{
	ବାଛ (sshkey_type_plain(k->type)) {
	ସ୍ଥିତି ଚାବି_RSA:
		ଯଦି (!PEM_write_RSA_PUBKEY(stdout,
		    EVP_PKEY_get0_RSA(k->pkey)))
			fatal("PEM_write_RSA_PUBKEY failed");
		ଭାଙ୍ଗ;
	ସ୍ଥିତି ଚାବି_ECDSA:
		ଯଦି (!PEM_write_EC_PUBKEY(stdout,
		    EVP_PKEY_get0_EC_ଚାବି(k->pkey)))
			fatal("PEM_write_EC_PUBKEY failed");
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		fatal_f("unsupported key type %s", sshkey_type(k));
	}
}

ସ୍ଥିର ଶୂନ୍ୟ
do_convert_to_pem(ସଂରଚନା sshkey *k)
{
	ବାଛ (sshkey_type_plain(k->type)) {
	ସ୍ଥିତି ଚାବି_RSA:
		ଯଦି (!PEM_write_RSAPublic_ଚାବି(stdout,
		    EVP_PKEY_get0_RSA(k->pkey)))
			fatal("PEM_write_RSAPublicKey failed");
		ଭାଙ୍ଗ;
	ସ୍ଥିତି ଚାବି_ECDSA:
		ଯଦି (!PEM_write_EC_PUBKEY(stdout,
		    EVP_PKEY_get0_EC_ଚାବି(k->pkey)))
			fatal("PEM_write_EC_PUBKEY failed");
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		fatal_f("unsupported key type %s", sshkey_type(k));
	}
}

ସ୍ଥିର ଶୂନ୍ୟ
do_convert_to_hexdump(ସଂରଚନା sshkey *k)
{
	ସଂରଚନା sshbuf *b;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((b = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	/* pubkey */
	ଯଦି ((r = sshkey_putb(k, b)) != 0)
		fatal_fr(r, "serialise private");
	printf("Public %s key:\n", sshkey_type(k));
	sshbuf_dump(b, stdout);
	sshbuf_reset(b);
	ଯଦି ((r = sshkey_private_serialize(k, b)) != 0) {
		debug_fr(r, "serialise private");
		ଯାଅ out;
	}
	printf("\nPrivate %s key:\n", sshkey_type(k));
	sshbuf_dump(b, stdout);
 out:
	sshbuf_free(b);
}

ସ୍ଥିର ଶୂନ୍ୟ
do_convert_to(ସଂରଚନା passwd *pw)
{
	ସଂରଚନା sshkey *k = ଖାଲି;
	ସଂରଚନା stat st;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	ଯଦି (stat(identity_file, &st) == -1)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));

	/* If we're trying to hexdump, then prefer the private key */
	ଯଦି (convert_format == FMT_HEXDUMP) {
		ଯଦି ((r = sshkey_load_private(identity_file,
		    ଖାଲି, &k, ଖାଲି)) != 0 &&
		    r == SSH_ERR_ଚାବି_WRONG_PASSPHRASE)
			k = load_identity(identity_file, ଖାଲି);
	}
	ଯଦି (k == ଖାଲି && (r = sshkey_load_public(identity_file, &k, ଖାଲି)) != 0)
		k = load_identity(identity_file, ଖାଲି);

	ବାଛ (convert_format) {
	ସ୍ଥିତି FMT_RFC4716:
		do_convert_to_ssh2(pw, k);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି FMT_PKCS8:
		do_convert_to_pkcs8(k);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି FMT_PEM:
		do_convert_to_pem(k);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି FMT_HEXDUMP:
		do_convert_to_hexdump(k);
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		fatal_f("unknown key format %d", convert_format);
	}
}

/*
 * This is almost exactly the bignum1 encoding, but with 32 bit for length
 * instead of 16.
 */
ସ୍ଥିର ଶୂନ୍ୟ
buffer_get_bignum_bits(ସଂରଚନା sshbuf *b, BIGNUM *ମୂଲ୍ୟ)
{
	u_int bytes, bignum_bits;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshbuf_get_u32(b, &bignum_bits)) != 0)
		fatal_fr(r, "parse");
	bytes = (bignum_bits + 7) / 8;
	ଯଦି (sshbuf_len(b) < bytes)
		fatal_f("input buffer too small: need %d have %zu",
		    bytes, sshbuf_len(b));
	ଯଦି (BN_bin2bn(sshbuf_ptr(b), bytes, ମୂଲ୍ୟ) == ଖାଲି)
		fatal_f("BN_bin2bn failed");
	ଯଦି ((r = sshbuf_consume(b, bytes)) != 0)
		fatal_fr(r, "consume");
}

ସ୍ଥିର ସଂରଚନା sshkey *
do_convert_private_ssh2(ସଂରଚନା sshbuf *b)
{
	ସଂରଚନା sshkey *ଚାବି = ଖାଲି;
	ଅକ୍ଷର *type, *cipher;
	ଅଚଳ ଅକ୍ଷର *alg = ଖାଲି;
	u_char e1, e2, e3, *sig = ଖାଲି, data[] = "abcde12345";
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, rlen, ktype;
	u_int magic, i1, i2, i3, i4;
	size_t slen;
	u_long e;
	BIGNUM *rsa_n = ଖାଲି, *rsa_e = ଖାଲି, *rsa_d = ଖାଲି;
	BIGNUM *rsa_p = ଖାଲି, *rsa_q = ଖାଲି, *rsa_iqmp = ଖାଲି;
	BIGNUM *rsa_dmp1 = ଖାଲି, *rsa_dmq1 = ଖାଲି;
	RSA *rsa = ଖାଲି;

	ଯଦି ((r = sshbuf_get_u32(b, &magic)) != 0)
		fatal_fr(r, "parse magic");

	ଯଦି (magic != SSH_COM_PRIVATE_ଚାବି_MAGIC) {
		error("bad magic 0x%x != 0x%x", magic,
		    SSH_COM_PRIVATE_ଚାବି_MAGIC);
		ଫେରନ୍ତୁ ଖାଲି;
	}
	ଯଦି ((r = sshbuf_get_u32(b, &i1)) != 0 ||
	    (r = sshbuf_get_cstring(b, &type, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_cstring(b, &cipher, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_u32(b, &i2)) != 0 ||
	    (r = sshbuf_get_u32(b, &i3)) != 0 ||
	    (r = sshbuf_get_u32(b, &i4)) != 0)
		fatal_fr(r, "parse");
	debug("ignore (%d %d %d %d)", i1, i2, i3, i4);
	ଯଦି (strcmp(cipher, "none") != 0) {
		error("unsupported cipher %s", cipher);
		ମୁକ୍ତ(cipher);
		ମୁକ୍ତ(type);
		ଫେରନ୍ତୁ ଖାଲି;
	}
	ମୁକ୍ତ(cipher);

	ଯଦି (strstr(type, "rsa")) {
		ktype = ଚାବି_RSA;
	} ଅନ୍ୟଥା {
		ମୁକ୍ତ(type);
		ଫେରନ୍ତୁ ଖାଲି;
	}
	ଯଦି ((ଚାବି = sshkey_new(ktype)) == ଖାଲି)
		fatal("sshkey_new failed");
	ମୁକ୍ତ(type);

	ବାଛ (ଚାବି->type) {
	ସ୍ଥିତି ଚାବି_RSA:
		ଯଦି ((r = sshbuf_get_u8(b, &e1)) != 0 ||
		    (e1 < 30 && (r = sshbuf_get_u8(b, &e2)) != 0) ||
		    (e1 < 30 && (r = sshbuf_get_u8(b, &e3)) != 0))
			fatal_fr(r, "parse RSA");
		e = e1;
		debug("e %lx", e);
		ଯଦି (e < 30) {
			e <<= 8;
			e += e2;
			debug("e %lx", e);
			e <<= 8;
			e += e3;
			debug("e %lx", e);
		}
		ଯଦି ((rsa_e = BN_new()) == ଖାଲି)
			fatal_f("BN_new");
		ଯଦି (!BN_set_word(rsa_e, e)) {
			BN_clear_free(rsa_e);
			sshkey_free(ଚାବି);
			ଫେରନ୍ତୁ ଖାଲି;
		}
		ଯଦି ((rsa_n = BN_new()) == ଖାଲି ||
		    (rsa_d = BN_new()) == ଖାଲି ||
		    (rsa_p = BN_new()) == ଖାଲି ||
		    (rsa_q = BN_new()) == ଖାଲି ||
		    (rsa_iqmp = BN_new()) == ଖାଲି)
			fatal_f("BN_new");
		buffer_get_bignum_bits(b, rsa_d);
		buffer_get_bignum_bits(b, rsa_n);
		buffer_get_bignum_bits(b, rsa_iqmp);
		buffer_get_bignum_bits(b, rsa_q);
		buffer_get_bignum_bits(b, rsa_p);
		ଯଦି ((r = ssh_rsa_complete_crt_parameters(rsa_d, rsa_p, rsa_q,
		    rsa_iqmp, &rsa_dmp1, &rsa_dmq1)) != 0)
			fatal_fr(r, "generate RSA CRT parameters");
		EVP_PKEY_free(ଚାବି->pkey);
		ଯଦି ((ଚାବି->pkey = EVP_PKEY_new()) == ଖାଲି)
			fatal_f("EVP_PKEY_new failed");
		ଯଦି ((rsa = RSA_new()) == ଖାଲି)
			fatal_f("RSA_new failed");
		ଯଦି (!RSA_set0_ଚାବି(rsa, rsa_n, rsa_e, rsa_d))
			fatal_f("RSA_set0_key failed");
		rsa_n = rsa_e = rsa_d = ଖାଲି; /* transferred */
		ଯଦି (!RSA_set0_factors(rsa, rsa_p, rsa_q))
			fatal_f("RSA_set0_factors failed");
		rsa_p = rsa_q = ଖାଲି; /* transferred */
		ଯଦି (RSA_set0_crt_params(rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp) != 1)
			fatal_f("RSA_set0_crt_params failed");
		rsa_dmp1 = rsa_dmq1 = rsa_iqmp = ଖାଲି;
		ଯଦି (EVP_PKEY_set1_RSA(ଚାବି->pkey, rsa) != 1)
			fatal_f("EVP_PKEY_set1_RSA failed");
		RSA_free(rsa);
		alg = "rsa-sha2-256";
		ଭାଙ୍ଗ;
	}
	rlen = sshbuf_len(b);
	ଯଦି (rlen != 0)
		error_f("remaining bytes in key blob %d", rlen);

	/* try the key */
	ଯଦି ((r = sshkey_sign(ଚାବି, &sig, &slen, data, ଆକାର(data),
	    alg, ଖାଲି, ଖାଲି, 0)) != 0)
		error_fr(r, "signing with converted key failed");
	ଅନ୍ୟଥା ଯଦି ((r = sshkey_verify(ଚାବି, sig, slen, data, ଆକାର(data),
	    alg, 0, ଖାଲି)) != 0)
		error_fr(r, "verification with converted key failed");
	ଯଦି (r != 0) {
		sshkey_free(ଚାବି);
		ମୁକ୍ତ(sig);
		ଫେରନ୍ତୁ ଖାଲି;
	}
	ମୁକ୍ତ(sig);
	ଫେରନ୍ତୁ ଚାବି;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
get_ଧାଡ଼ି(FILE *fp, ଅକ୍ଷର *ଧାଡ଼ି, size_t len)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା c;
	size_t pos = 0;

	ଧାଡ଼ି[0] = '\0';
	ଯେତେବେଳେ ((c = fgetc(fp)) != EOF) {
		ଯଦି (pos >= len - 1)
			fatal("input line too long.");
		ବାଛ (c) {
		ସ୍ଥିତି '\r':
			c = fgetc(fp);
			ଯଦି (c != EOF && c != '\n' && ungetc(c, fp) == EOF)
				fatal("unget: %s", strerror(errno));
			ଫେରନ୍ତୁ pos;
		ସ୍ଥିତି '\n':
			ଫେରନ୍ତୁ pos;
		}
		ଧାଡ଼ି[pos++] = c;
		ଧାଡ଼ି[pos] = '\0';
	}
	/* We reached EOF */
	ଫେରନ୍ତୁ -1;
}

ସ୍ଥିର ଶୂନ୍ୟ
do_convert_from_ssh2(ସଂରଚନା passwd *pw, ସଂରଚନା sshkey **k, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *ବ୍ୟକ୍ତିଗତ)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, blen, escaped = 0;
	u_int len;
	ଅକ୍ଷର ଧାଡ଼ି[1024];
	ସଂରଚନା sshbuf *buf;
	ଅକ୍ଷର encoded[8096];
	FILE *fp;

	ଯଦି ((buf = sshbuf_new()) == ଖାଲି)
		fatal("sshbuf_new failed");
	ଯଦି ((fp = fopen(identity_file, "r")) == ଖାଲି)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));
	encoded[0] = '\0';
	ଯେତେବେଳେ ((blen = get_ଧାଡ଼ି(fp, ଧାଡ଼ି, ଆକାର(ଧାଡ଼ି))) != -1) {
		ଯଦି (blen > 0 && ଧାଡ଼ି[blen - 1] == '\\')
			escaped++;
		ଯଦି (strncmp(ଧାଡ଼ି, "----", 4) == 0 ||
		    strstr(ଧାଡ଼ି, ": ") != ଖାଲି) {
			ଯଦି (strstr(ଧାଡ଼ି, SSH_COM_PRIVATE_BEGIN) != ଖାଲି)
				*ବ୍ୟକ୍ତିଗତ = 1;
			ଯଦି (strstr(ଧାଡ଼ି, " END ") != ଖାଲି) {
				ଭାଙ୍ଗ;
			}
			/* fprintf(stderr, "ignore: %s", line); */
			ଜାରି;
		}
		ଯଦି (escaped) {
			escaped--;
			/* fprintf(stderr, "escaped: %s", line); */
			ଜାରି;
		}
		strlcat(encoded, ଧାଡ଼ି, ଆକାର(encoded));
	}
	len = strlen(encoded);
	ଯଦି (((len % 4) == 3) &&
	    (encoded[len-1] == '=') &&
	    (encoded[len-2] == '=') &&
	    (encoded[len-3] == '='))
		encoded[len-3] = '\0';
	ଯଦି ((r = sshbuf_b64tod(buf, encoded)) != 0)
		fatal_fr(r, "base64 decode");
	ଯଦି (*ବ୍ୟକ୍ତିଗତ) {
		ଯଦି ((*k = do_convert_private_ssh2(buf)) == ଖାଲି)
			fatal_f("private key conversion failed");
	} ଅନ୍ୟଥା ଯଦି ((r = sshkey_fromb(buf, k)) != 0)
		fatal_fr(r, "parse key");
	sshbuf_free(buf);
	fclose(fp);
}

ସ୍ଥିର ଶୂନ୍ୟ
do_convert_from_pkcs8(ସଂରଚନା sshkey **k, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *ବ୍ୟକ୍ତିଗତ)
{
	EVP_PKEY *pubkey;
	FILE *fp;

	ଯଦି ((fp = fopen(identity_file, "r")) == ଖାଲି)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));
	ଯଦି ((pubkey = PEM_read_PUBKEY(fp, ଖାଲି, ଖାଲି, ଖାଲି)) == ଖାଲି) {
		fatal_f("%s is not a recognised public key format",
		    identity_file);
	}
	fclose(fp);
	ବାଛ (EVP_PKEY_base_id(pubkey)) {
	ସ୍ଥିତି EVP_PKEY_RSA:
		ଯଦି ((*k = sshkey_new(ଚାବି_UNSPEC)) == ଖାଲି)
			fatal("sshkey_new failed");
		(*k)->type = ଚାବି_RSA;
		(*k)->pkey = pubkey;
		pubkey = ଖାଲି;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି EVP_PKEY_EC:
		ଯଦି ((*k = sshkey_new(ଚାବି_UNSPEC)) == ଖାଲି)
			fatal("sshkey_new failed");
		ଯଦି (((*k)->ecdsa_nid = sshkey_ecdsa_fixup_group(pubkey)) == -1)
			fatal("sshkey_ecdsa_fixup_group failed");
		(*k)->type = ଚାବି_ECDSA;
		(*k)->pkey = pubkey;
		pubkey = ଖାଲି;
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		fatal_f("unsupported pubkey type %d",
		    EVP_PKEY_base_id(pubkey));
	}
	EVP_PKEY_free(pubkey);
}

ସ୍ଥିର ଶୂନ୍ୟ
do_convert_from_pem(ସଂରଚନା sshkey **k, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *ବ୍ୟକ୍ତିଗତ)
{
	FILE *fp;
	RSA *rsa;

	ଯଦି ((fp = fopen(identity_file, "r")) == ଖାଲି)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));
	ଯଦି ((rsa = PEM_read_RSAPublic_ଚାବି(fp, ଖାଲି, ଖାଲି, ଖାଲି)) != ଖାଲି) {
		ଯଦି ((*k = sshkey_new(ଚାବି_UNSPEC)) == ଖାଲି)
			fatal("sshkey_new failed");
		ଯଦି (((*k)->pkey = EVP_PKEY_new()) == ଖାଲି)
			fatal("EVP_PKEY_new failed");
		(*k)->type = ଚାବି_RSA;
		ଯଦି (EVP_PKEY_set1_RSA((*k)->pkey, rsa) != 1)
			fatal("EVP_PKEY_set1_RSA failed");
		RSA_free(rsa);
		fclose(fp);
		ଫେରନ୍ତୁ;
	}
	fatal_f("unrecognised raw private key format");
}

ସ୍ଥିର ଶୂନ୍ୟ
do_convert_from(ସଂରଚନା passwd *pw)
{
	ସଂରଚନା sshkey *k = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, ବ୍ୟକ୍ତିଗତ = 0, ok = 0;
	ସଂରଚନା stat st;

	ଯଦି (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	ଯଦି (stat(identity_file, &st) == -1)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));

	ବାଛ (convert_format) {
	ସ୍ଥିତି FMT_RFC4716:
		do_convert_from_ssh2(pw, &k, &ବ୍ୟକ୍ତିଗତ);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି FMT_PKCS8:
		do_convert_from_pkcs8(&k, &ବ୍ୟକ୍ତିଗତ);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି FMT_PEM:
		do_convert_from_pem(&k, &ବ୍ୟକ୍ତିଗତ);
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		fatal_f("unknown key format %d", convert_format);
	}

	ଯଦି (!ବ୍ୟକ୍ତିଗତ) {
		ଯଦି ((r = sshkey_write(k, stdout)) == 0)
			ok = 1;
		ଯଦି (ok)
			fprintf(stdout, "\n");
	} ଅନ୍ୟଥା {
		ବାଛ (k->type) {
		ସ୍ଥିତି ଚାବି_ECDSA:
			ok = PEM_write_ECPrivate_ଚାବି(stdout,
			    EVP_PKEY_get0_EC_ଚାବି(k->pkey), ଖାଲି, ଖାଲି, 0,
			    ଖାଲି, ଖାଲି);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି ଚାବି_RSA:
			ok = PEM_write_RSAPrivate_ଚାବି(stdout,
			    EVP_PKEY_get0_RSA(k->pkey), ଖାଲି, ଖାଲି, 0,
			    ଖାଲି, ଖାଲି);
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			fatal_f("unsupported key type %s", sshkey_type(k));
		}
	}

	ଯଦି (!ok)
		fatal("key write failed");
	sshkey_free(k);
}
#endif

ସ୍ଥିର ଶୂନ୍ୟ
do_print_public(ସଂରଚନା passwd *pw)
{
	ସଂରଚନା sshkey *prv;
	ସଂରଚନା stat st;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ଅକ୍ଷର *comment = ଖାଲି;

	ଯଦି (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	ଯଦି (stat(identity_file, &st) == -1)
		fatal("%s: %s", identity_file, strerror(errno));
	prv = load_identity(identity_file, &comment);
	ଯଦି ((r = sshkey_write(prv, stdout)) != 0)
		fatal_fr(r, "write key");
	ଯଦି (comment != ଖାଲି && *comment != '\0')
		fprintf(stdout, " %s", comment);
	fprintf(stdout, "\n");
	ଯଦି (sshkey_is_sk(prv)) {
		debug("sk_application: \"%s\", sk_flags 0x%02x",
			prv->sk_application, prv->sk_flags);
	}
	sshkey_free(prv);
	ମୁକ୍ତ(comment);
	exit(0);
}

ସ୍ଥିର ଶୂନ୍ୟ
do_download(ସଂରଚନା passwd *pw)
{
#ifdef ENABLE_PKCS11
	ସଂରଚନା sshkey **ଚାବିଗୁଡ଼ିକ = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, nkeys;
	ଗଣନା sshkey_fp_rep rep;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା fptype;
	ଅକ୍ଷର *fp, *ra, **comments = ଖାଲି;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;

	pkcs11_init(1);
	nkeys = pkcs11_add_provider(pkcs11provider, ଖାଲି, &ଚାବିଗୁଡ଼ିକ, &comments);
	ଯଦି (nkeys <= 0)
		fatal("cannot read public key from pkcs11");
	ପାଇଁ (i = 0; i < nkeys; i++) {
		ଯଦି (print_fingerprint) {
			fp = sshkey_fingerprint(ଚାବିଗୁଡ଼ିକ[i], fptype, rep);
			ra = sshkey_fingerprint(ଚାବିଗୁଡ଼ିକ[i], fingerprint_hash,
			    SSH_FP_RANDOMART);
			ଯଦି (fp == ଖାଲି || ra == ଖାଲି)
				fatal_f("sshkey_fingerprint fail");
			printf("%u %s %s (PKCS11 key)\n", sshkey_size(ଚାବିଗୁଡ଼ିକ[i]),
			    fp, sshkey_type(ଚାବିଗୁଡ଼ିକ[i]));
			ଯଦି (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
				printf("%s\n", ra);
			ମୁକ୍ତ(ra);
			ମୁକ୍ତ(fp);
		} ଅନ୍ୟଥା {
			(ଶୂନ୍ୟ) sshkey_write(ଚାବିଗୁଡ଼ିକ[i], stdout); /* XXX check */
			fprintf(stdout, "%s%s\n",
			    *(comments[i]) == '\0' ? "" : " ", comments[i]);
		}
		ମୁକ୍ତ(comments[i]);
		sshkey_free(ଚାବିଗୁଡ଼ିକ[i]);
	}
	ମୁକ୍ତ(comments);
	ମୁକ୍ତ(ଚାବିଗୁଡ଼ିକ);
	pkcs11_terminate();
	exit(0);
#ଅନ୍ୟଥା
	fatal("no pkcs11 support");
#endif /* ENABLE_PKCS11 */
}

ସ୍ଥିର ସଂରଚନା sshkey *
try_read_ଚାବି(ଅକ୍ଷର **cpp)
{
	ସଂରଚନା sshkey *ret;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((ret = sshkey_new(ଚାବି_UNSPEC)) == ଖାଲି)
		fatal("sshkey_new failed");
	ଯଦି ((r = sshkey_read(ret, cpp)) == 0)
		ଫେରନ୍ତୁ ret;
	/* Not a key */
	sshkey_free(ret);
	ଫେରନ୍ତୁ ଖାଲି;
}

ସ୍ଥିର ଶୂନ୍ୟ
fingerprint_one_ଚାବି(ଅଚଳ ସଂରଚନା sshkey *ସର୍ବସାଧାରଣ, ଅଚଳ ଅକ୍ଷର *comment)
{
	ଅକ୍ଷର *fp = ଖାଲି, *ra = ଖାଲି;
	ଗଣନା sshkey_fp_rep rep;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା fptype;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;
	fp = sshkey_fingerprint(ସର୍ବସାଧାରଣ, fptype, rep);
	ra = sshkey_fingerprint(ସର୍ବସାଧାରଣ, fingerprint_hash, SSH_FP_RANDOMART);
	ଯଦି (fp == ଖାଲି || ra == ଖାଲି)
		fatal_f("sshkey_fingerprint failed");
	mprintf("%u %s %s (%s)\n", sshkey_size(ସର୍ବସାଧାରଣ), fp,
	    comment ? comment : "no comment", sshkey_type(ସର୍ବସାଧାରଣ));
	ଯଦି (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
		printf("%s\n", ra);
	ମୁକ୍ତ(ra);
	ମୁକ୍ତ(fp);
}

ସ୍ଥିର ଶୂନ୍ୟ
fingerprint_private(ଅଚଳ ଅକ୍ଷର *path)
{
	ସଂରଚନା stat st;
	ଅକ୍ଷର *comment = ଖାଲି;
	ସଂରଚନା sshkey *privkey = ଖାଲି, *pubkey = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (stat(identity_file, &st) == -1)
		fatal("%s: %s", path, strerror(errno));
	ଯଦି ((r = sshkey_load_public(path, &pubkey, &comment)) != 0)
		debug_r(r, "load public \"%s\"", path);
	ଯଦି (pubkey == ଖାଲି || comment == ଖାଲି || *comment == '\0') {
		ମୁକ୍ତ(comment);
		ଯଦି ((r = sshkey_load_private(path, ଖାଲି,
		    &privkey, &comment)) != 0)
			debug_r(r, "load private \"%s\"", path);
	}
	ଯଦି (pubkey == ଖାଲି && privkey == ଖାଲି)
		fatal("%s is not a key file.", path);

	fingerprint_one_ଚାବି(pubkey == ଖାଲି ? privkey : pubkey, comment);
	sshkey_free(pubkey);
	sshkey_free(privkey);
	ମୁକ୍ତ(comment);
}

ସ୍ଥିର ଶୂନ୍ୟ
do_fingerprint(ସଂରଚନା passwd *pw)
{
	FILE *f;
	ସଂରଚନା sshkey *ସର୍ବସାଧାରଣ = ଖାଲି;
	ଅକ୍ଷର *comment = ଖାଲି, *cp, *ep, *ଧାଡ଼ି = ଖାଲି;
	size_t linesize = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, invalid = 1;
	ଅଚଳ ଅକ୍ଷର *path;
	u_long lnum = 0;

	ଯଦି (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	path = identity_file;

	ଯଦି (strcmp(identity_file, "-") == 0) {
		f = stdin;
		path = "(stdin)";
	} ଅନ୍ୟଥା ଯଦି ((f = fopen(path, "r")) == ଖାଲି)
		fatal("%s: %s: %s", __progname, path, strerror(errno));

	ଯେତେବେଳେ (getline(&ଧାଡ଼ି, &linesize, f) != -1) {
		lnum++;
		cp = ଧାଡ଼ି;
		cp[strcspn(cp, "\r\n")] = '\0';
		/* Trim leading space and comments */
		cp = ଧାଡ଼ି + strspn(ଧାଡ଼ି, " \t");
		ଯଦି (*cp == '#' || *cp == '\0')
			ଜାରି;

		/*
		 * Input may be plain keys, private keys, authorized_keys
		 * or known_hosts.
		 */

		/*
		 * Try private keys first. Assume a key is private if
		 * "SSH PRIVATE KEY" appears on the first line and we're
		 * not reading from stdin (XXX support private keys on stdin).
		 */
		ଯଦି (lnum == 1 && strcmp(identity_file, "-") != 0 &&
		    strstr(cp, "PRIVATE KEY") != ଖାଲି) {
			ମୁକ୍ତ(ଧାଡ଼ି);
			fclose(f);
			fingerprint_private(path);
			exit(0);
		}

		/*
		 * If it's not a private key, then this must be prepared to
		 * accept a public key prefixed with a hostname or options.
		 * Try a bare key first, otherwise skip the leading stuff.
		 */
		comment = ଖାଲି;
		ଯଦି ((ସର୍ବସାଧାରଣ = try_read_ଚାବି(&cp)) == ଖାଲି) {
			i = strtol(cp, &ep, 10);
			ଯଦି (i == 0 || ep == ଖାଲି ||
			    (*ep != ' ' && *ep != '\t')) {
				ପୂର୍ଣ୍ଣସଂଖ୍ୟା quoted = 0;

				comment = cp;
				ପାଇଁ (; *cp && (quoted || (*cp != ' ' &&
				    *cp != '\t')); cp++) {
					ଯଦି (*cp == '\\' && cp[1] == '"')
						cp++;	/* Skip both */
					ଅନ୍ୟଥା ଯଦି (*cp == '"')
						quoted = !quoted;
				}
				ଯଦି (!*cp)
					ଜାରି;
				*cp++ = '\0';
			}
		}
		/* Retry after parsing leading hostname/key options */
		ଯଦି (ସର୍ବସାଧାରଣ == ଖାଲି && (ସର୍ବସାଧାରଣ = try_read_ଚାବି(&cp)) == ଖାଲି) {
			debug("%s:%lu: not a public key", path, lnum);
			ଜାରି;
		}

		/* Find trailing comment, if any */
		ପାଇଁ (; *cp == ' ' || *cp == '\t'; cp++)
			;
		ଯଦି (*cp != '\0' && *cp != '#')
			comment = cp;

		fingerprint_one_ଚାବି(ସର୍ବସାଧାରଣ, comment);
		sshkey_free(ସର୍ବସାଧାରଣ);
		invalid = 0; /* One good key in the file is sufficient */
	}
	fclose(f);
	ମୁକ୍ତ(ଧାଡ଼ି);

	ଯଦି (invalid)
		fatal("%s is not a public key file.", path);
	exit(0);
}

ସ୍ଥିର ଶୂନ୍ୟ
do_gen_all_hostkeys(ସଂରଚନା passwd *pw)
{
	ସଂରଚନା {
		ଅକ୍ଷର *ଚାବି_type;
		ଅକ୍ଷର *ଚାବି_type_display;
		ଅକ୍ଷର *path;
	} ଚାବି_types[] = {
#ifdef WITH_OPENSSL
		{ "rsa", "RSA" ,PATH_HOST_RSA_ଚାବି_FILE },
		{ "ecdsa", "ECDSA",PATH_HOST_ECDSA_ଚାବି_FILE },
#endif /* WITH_OPENSSL */
		{ "ed25519", "ED25519",PATH_HOST_ED25519_ଚାବି_FILE },
#ifdef USE_MLDSA
		{ "mldsa44-ed25519", "MLDSA44-ED25519",
		     PATH_HOST_MLDSA44_ED25519_ଚାବି_FILE },
#endif
		{ ଖାଲି, ଖାଲି, ଖାଲି }
	};

	uint32_t bits = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା first = 0;
	ସଂରଚନା stat st;
	ସଂରଚନା sshkey *ବ୍ୟକ୍ତିଗତ, *ସର୍ବସାଧାରଣ;
	ଅକ୍ଷର comment[ଚାବି_COMMENT_MAX], *prv_tmp, *pub_tmp, *prv_file, *pub_file;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, type, fd, r;

	ପାଇଁ (i = 0; ଚାବି_types[i].ଚାବି_type; i++) {
		ସର୍ବସାଧାରଣ = ବ୍ୟକ୍ତିଗତ = ଖାଲି;
		prv_tmp = pub_tmp = prv_file = pub_file = ଖାଲି;

		xasprintf(&prv_file, "%s%s",
		    identity_file, ଚାବି_types[i].path);

		/* Check whether private key exists and is not zero-length */
		ଯଦି (stat(prv_file, &st) == 0) {
			ଯଦି (st.st_size != 0)
				ଯାଅ next;
		} ଅନ୍ୟଥା ଯଦି (errno != ENOENT) {
			error("Could not stat %s: %s", ଚାବି_types[i].path,
			    strerror(errno));
			ଯାଅ failnext;
		}

		/*
		 * Private key doesn't exist or is invalid; proceed with
		 * key generation.
		 */
		xasprintf(&prv_tmp, "%s%s.XXXXXXXXXX",
		    identity_file, ଚାବି_types[i].path);
		xasprintf(&pub_tmp, "%s%s.pub.XXXXXXXXXX",
		    identity_file, ଚାବି_types[i].path);
		xasprintf(&pub_file, "%s%s.pub",
		    identity_file, ଚାବି_types[i].path);

		ଯଦି (first == 0) {
			first = 1;
			printf("%s: generating new host keys: ", __progname);
		}
		printf("%s ", ଚାବି_types[i].ଚାବି_type_display);
		fflush(stdout);
		type = sshkey_type_from_shortname(ଚାବି_types[i].ଚାବି_type);
		ଯଦି ((fd = mkstemp(prv_tmp)) == -1) {
			error("Could not save your private key in %s: %s",
			    prv_tmp, strerror(errno));
			ଯାଅ failnext;
		}
		(ଶୂନ୍ୟ)close(fd); /* just using mkstemp() to reserve a name */
		bits = 0;
		type_bits_valid(type, ଖାଲି, &bits);
		ଯଦି ((r = sshkey_generate(type, bits, &ବ୍ୟକ୍ତିଗତ)) != 0) {
			error_r(r, "sshkey_generate failed");
			ଯାଅ failnext;
		}
		ଯଦି ((r = sshkey_from_private(ବ୍ୟକ୍ତିଗତ, &ସର୍ବସାଧାରଣ)) != 0)
			fatal_fr(r, "sshkey_from_private");
		snprintf(comment, ଆକାର comment, "%s@%s", pw->pw_name,
		    hostname);
		ଯଦି ((r = sshkey_save_private(ବ୍ୟକ୍ତିଗତ, prv_tmp, "",
		    comment, private_ଚାବି_format, openssh_format_cipher,
		    rounds)) != 0) {
			error_r(r, "Saving key \"%s\" failed", prv_tmp);
			ଯାଅ failnext;
		}
		ଯଦି ((fd = mkstemp(pub_tmp)) == -1) {
			error("Could not save your public key in %s: %s",
			    pub_tmp, strerror(errno));
			ଯାଅ failnext;
		}
		(ଶୂନ୍ୟ)fchmod(fd, 0644);
		(ଶୂନ୍ୟ)close(fd);
		ଯଦି ((r = sshkey_save_public(ସର୍ବସାଧାରଣ, pub_tmp, comment)) != 0) {
			error_r(r, "Unable to save public key to %s",
			    identity_file);
			ଯାଅ failnext;
		}

		/* Rename temporary files to their permanent locations. */
		ଯଦି (rename(pub_tmp, pub_file) != 0) {
			error("Unable to move %s into position: %s",
			    pub_file, strerror(errno));
			ଯାଅ failnext;
		}
		ଯଦି (rename(prv_tmp, prv_file) != 0) {
			error("Unable to move %s into position: %s",
			    ଚାବି_types[i].path, strerror(errno));
 failnext:
			first = 0;
			ଯାଅ next;
		}
 next:
		sshkey_free(ବ୍ୟକ୍ତିଗତ);
		sshkey_free(ସର୍ବସାଧାରଣ);
		ମୁକ୍ତ(prv_tmp);
		ମୁକ୍ତ(pub_tmp);
		ମୁକ୍ତ(prv_file);
		ମୁକ୍ତ(pub_file);
	}
	ଯଦି (first != 0)
		printf("\n");
}

ସଂରଚନା known_hosts_ctx {
	ଅଚଳ ଅକ୍ଷର *host;	/* Hostname searched for in find/delete case */
	FILE *out;		/* Output file, stdout for find_hosts case */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା has_unhashed;	/* When hashing, original had unhashed hosts */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା found_ଚାବି;		/* For find/delete, host was found */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା invalid;		/* File contained invalid items; don't delete */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା hash_hosts;		/* Hash hostnames as we go */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା find_host;		/* Search for specific hostname */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା delete_host;	/* Delete host from known_hosts */
};

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
known_hosts_hash(ସଂରଚନା hostkey_foreach_ଧାଡ଼ି *l, ଶୂନ୍ୟ *_ctx)
{
	ସଂରଚନା known_hosts_ctx *ctx = (ସଂରଚନା known_hosts_ctx *)_ctx;
	ଅକ୍ଷର *hashed, *cp, *hosts, *ohosts;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା has_wild = l->hosts && strcspn(l->hosts, "*?!") != strlen(l->hosts);
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା was_hashed = l->hosts && l->hosts[0] == HASH_DELIM;

	ବାଛ (l->status) {
	ସ୍ଥିତି HKF_STATUS_OK:
	ସ୍ଥିତି HKF_STATUS_MATCHED:
		/*
		 * Don't hash hosts already hashed, with wildcard
		 * characters or a CA/revocation marker.
		 */
		ଯଦି (was_hashed || has_wild || l->marker != MRK_NONE) {
			fprintf(ctx->out, "%s\n", l->ଧାଡ଼ି);
			ଯଦି (has_wild && !ctx->find_host) {
				logit("%s:%lu: ignoring host name "
				    "with wildcard: %.64s", l->path,
				    l->linenum, l->hosts);
			}
			ଫେରନ୍ତୁ 0;
		}
		/*
		 * Split any comma-separated hostnames from the host list,
		 * hash and store separately.
		 */
		ohosts = hosts = xstrdup(l->hosts);
		ଯେତେବେଳେ ((cp = strsep(&hosts, ",")) != ଖାଲି && *cp != '\0') {
			lowercase(cp);
			ଯଦି ((hashed = host_hash(cp, ଖାଲି, 0)) == ଖାଲି)
				fatal("hash_host failed");
			fprintf(ctx->out, "%s %s\n", hashed, l->rawkey);
			ମୁକ୍ତ(hashed);
			ctx->has_unhashed = 1;
		}
		ମୁକ୍ତ(ohosts);
		ଫେରନ୍ତୁ 0;
	ସ୍ଥିତି HKF_STATUS_INVALID:
		/* Retain invalid lines, but mark file as invalid. */
		ctx->invalid = 1;
		logit("%s:%lu: invalid line", l->path, l->linenum);
		/* FALLTHROUGH */
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		fprintf(ctx->out, "%s\n", l->ଧାଡ଼ି);
		ଫେରନ୍ତୁ 0;
	}
	/* NOTREACHED */
	ଫେରନ୍ତୁ -1;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
known_hosts_find_delete(ସଂରଚନା hostkey_foreach_ଧାଡ଼ି *l, ଶୂନ୍ୟ *_ctx)
{
	ସଂରଚନା known_hosts_ctx *ctx = (ସଂରଚନା known_hosts_ctx *)_ctx;
	ଗଣନା sshkey_fp_rep rep;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା fptype;
	ଅକ୍ଷର *fp = ଖାଲି, *ra = ଖାଲି;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;

	ଯଦି (l->status == HKF_STATUS_MATCHED) {
		ଯଦି (ctx->delete_host) {
			ଯଦି (l->marker != MRK_NONE) {
				/* Don't remove CA and revocation lines */
				fprintf(ctx->out, "%s\n", l->ଧାଡ଼ି);
			} ଅନ୍ୟଥା {
				/*
				 * Hostname matches and has no CA/revoke
				 * marker, delete it by *not* writing the
				 * line to ctx->out.
				 */
				ctx->found_ଚାବି = 1;
				ଯଦି (!quiet)
					printf("# Host %s found: line %lu\n",
					    ctx->host, l->linenum);
			}
			ଫେରନ୍ତୁ 0;
		} ଅନ୍ୟଥା ଯଦି (ctx->find_host) {
			ctx->found_ଚାବି = 1;
			ଯଦି (!quiet) {
				printf("# Host %s found: line %lu %s\n",
				    ctx->host,
				    l->linenum, l->marker == MRK_CA ? "CA" :
				    (l->marker == MRK_REVOKE ? "REVOKED" : ""));
			}
			ଯଦି (ctx->hash_hosts)
				known_hosts_hash(l, ctx);
			ଅନ୍ୟଥା ଯଦି (print_fingerprint) {
				fp = sshkey_fingerprint(l->ଚାବି, fptype, rep);
				ra = sshkey_fingerprint(l->ଚାବି,
				    fingerprint_hash, SSH_FP_RANDOMART);
				ଯଦି (fp == ଖାଲି || ra == ଖାଲି)
					fatal_f("sshkey_fingerprint failed");
				mprintf("%s %s %s%s%s\n", ctx->host,
				    sshkey_type(l->ଚାବି), fp,
				    l->comment[0] ? " " : "",
				    l->comment);
				ଯଦି (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
					printf("%s\n", ra);
				ମୁକ୍ତ(ra);
				ମୁକ୍ତ(fp);
			} ଅନ୍ୟଥା
				fprintf(ctx->out, "%s\n", l->ଧାଡ଼ି);
			ଫେରନ୍ତୁ 0;
		}
	} ଅନ୍ୟଥା ଯଦି (ctx->delete_host) {
		/* Retain non-matching hosts when deleting */
		ଯଦି (l->status == HKF_STATUS_INVALID) {
			ctx->invalid = 1;
			logit("%s:%lu: invalid line", l->path, l->linenum);
		}
		fprintf(ctx->out, "%s\n", l->ଧାଡ଼ି);
	}
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ଶୂନ୍ୟ
do_known_hosts(ସଂରଚନା passwd *pw, ଅଚଳ ଅକ୍ଷର *name, ପୂର୍ଣ୍ଣସଂଖ୍ୟା find_host,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା delete_host, ପୂର୍ଣ୍ଣସଂଖ୍ୟା hash_hosts)
{
	ଅକ୍ଷର *cp, tmp[PATH_MAX], old[PATH_MAX];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, fd, oerrno, inplace = 0;
	ସଂରଚନା known_hosts_ctx ctx;
	u_int foreach_options;
	ସଂରଚନା stat sb;

	ଯଦି (!have_identity) {
		cp = tilde_expand_filename(_PATH_SSH_USER_HOSTFILE, pw->pw_uid);
		ଯଦି (strlcpy(identity_file, cp, ଆକାର(identity_file)) >=
		    ଆକାର(identity_file))
			fatal("Specified known hosts path too long");
		ମୁକ୍ତ(cp);
		have_identity = 1;
	}
	ଯଦି (stat(identity_file, &sb) != 0)
		fatal("Cannot stat %s: %s", identity_file, strerror(errno));

	memset(&ctx, 0, ଆକାର(ctx));
	ctx.out = stdout;
	ctx.host = name;
	ctx.hash_hosts = hash_hosts;
	ctx.find_host = find_host;
	ctx.delete_host = delete_host;

	/*
	 * Find hosts goes to stdout, hash and deletions happen in-place
	 * A corner case is ssh-keygen -HF foo, which should go to stdout
	 */
	ଯଦି (!find_host && (hash_hosts || delete_host)) {
		ଯଦି (strlcpy(tmp, identity_file, ଆକାର(tmp)) >= ଆକାର(tmp) ||
		    strlcat(tmp, ".XXXXXXXXXX", ଆକାର(tmp)) >= ଆକାର(tmp) ||
		    strlcpy(old, identity_file, ଆକାର(old)) >= ଆକାର(old) ||
		    strlcat(old, ".old", ଆକାର(old)) >= ଆକାର(old))
			fatal("known_hosts path too long");
		umask(077);
		ଯଦି ((fd = mkstemp(tmp)) == -1)
			fatal("mkstemp: %s", strerror(errno));
		ଯଦି ((ctx.out = fdopen(fd, "w")) == ଖାଲି) {
			oerrno = errno;
			unlink(tmp);
			fatal("fdopen: %s", strerror(oerrno));
		}
		(ଶୂନ୍ୟ)fchmod(fd, sb.st_mode & 0644);
		inplace = 1;
	}
	/* XXX support identity_file == "-" for stdin */
	foreach_options = find_host ? HKF_WANT_MATCH : 0;
	foreach_options |= print_fingerprint ? HKF_WANT_PARSE_ଚାବି : 0;
	ଯଦି ((r = hostkeys_foreach(identity_file, (find_host || !hash_hosts) ?
	    known_hosts_find_delete : known_hosts_hash, &ctx, name, ଖାଲି,
	    foreach_options, 0)) != 0) {
		ଯଦି (inplace)
			unlink(tmp);
		fatal_fr(r, "hostkeys_foreach");
	}

	ଯଦି (inplace)
		fclose(ctx.out);

	ଯଦି (ctx.invalid) {
		error("%s is not a valid known_hosts file.", identity_file);
		ଯଦି (inplace) {
			error("Not replacing existing known_hosts "
			    "file because of errors");
			unlink(tmp);
		}
		exit(1);
	} ଅନ୍ୟଥା ଯଦି (delete_host && !ctx.found_ଚାବି) {
		logit("Host %s not found in %s", name, identity_file);
		ଯଦି (inplace)
			unlink(tmp);
	} ଅନ୍ୟଥା ଯଦି (inplace) {
		/* Backup existing file */
		ଯଦି (unlink(old) == -1 && errno != ENOENT)
			fatal("unlink %.100s: %s", old, strerror(errno));
		ଯଦି (link(identity_file, old) == -1)
			fatal("link %.100s to %.100s: %s", identity_file, old,
			    strerror(errno));
		/* Move new one into place */
		ଯଦି (rename(tmp, identity_file) == -1) {
			error("rename\"%s\" to \"%s\": %s", tmp, identity_file,
			    strerror(errno));
			unlink(tmp);
			unlink(old);
			exit(1);
		}

		printf("%s updated.\n", identity_file);
		printf("Original contents retained as %s\n", old);
		ଯଦି (ctx.has_unhashed) {
			logit("WARNING: %s contains unhashed entries", old);
			logit("Delete this file to ensure privacy "
			    "of hostnames");
		}
	}

	exit (find_host && !ctx.found_ଚାବି);
}

/*
 * Perform changing a passphrase.  The argument is the passwd structure
 * for the current user.
 */
ସ୍ଥିର ଶୂନ୍ୟ
do_change_passphrase(ସଂରଚନା passwd *pw, ଅକ୍ଷର * ଅଚଳ *opts, size_t nopts)
{
	ଅକ୍ଷର *comment;
	ଅକ୍ଷର *old_passphrase, *passphrase1, *passphrase2;
	ସଂରଚନା stat st;
	ସଂରଚନା sshkey *ବ୍ୟକ୍ତିଗତ;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	size_t i;

	ଯଦି (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	ଯଦି (stat(identity_file, &st) == -1)
		fatal("%s: %s", identity_file, strerror(errno));
	/* Try to load the file with empty passphrase. */
	r = sshkey_load_private(identity_file, "", &ବ୍ୟକ୍ତିଗତ, &comment);
	ଯଦି (r == SSH_ERR_ଚାବି_WRONG_PASSPHRASE) {
		ଯଦି (identity_passphrase)
			old_passphrase = xstrdup(identity_passphrase);
		ଅନ୍ୟଥା
			old_passphrase =
			    read_passphrase("Enter old passphrase: ",
			    RP_ALLOW_STDIN);
		r = sshkey_load_private(identity_file, old_passphrase,
		    &ବ୍ୟକ୍ତିଗତ, &comment);
		freezero(old_passphrase, strlen(old_passphrase));
		ଯଦି (r != 0)
			ଯାଅ badkey;
	} ଅନ୍ୟଥା ଯଦି (r != 0) {
 badkey:
		fatal_r(r, "Failed to load key %s", identity_file);
	}
	ଯଦି (comment)
		mprintf("Key has comment '%s'\n", comment);

	/* All current -O options relate to FIDO keys only */
	ଯଦି (nopts != 0 && !sshkey_is_sk(ବ୍ୟକ୍ତିଗତ)) {
		fatal("FIDO-specific option requested for non-FIDO key %s",
		    identity_file);
	}
	ଯଦି (sshkey_is_sk(ବ୍ୟକ୍ତିଗତ)) {
		debug_f("%s: original FIDO key flags: "
		    "%stouch-required %sverify-required", identity_file,
		    (ବ୍ୟକ୍ତିଗତ->sk_flags & SSH_SK_USER_PRESENCE_REQD) ? "": "no-",
		    (ବ୍ୟକ୍ତିଗତ->sk_flags & SSH_SK_USER_VERIFICATION_REQD) ? "" : "no-");
	}
	ପାଇଁ (i = 0; i < nopts; i++) {
		ଯଦି (strcasecmp(opts[i], "touch-required") == 0)
			ବ୍ୟକ୍ତିଗତ->sk_flags |= SSH_SK_USER_PRESENCE_REQD;
		ଅନ୍ୟଥା ଯଦି (strcasecmp(opts[i], "no-touch-required") == 0)
			ବ୍ୟକ୍ତିଗତ->sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
		ଅନ୍ୟଥା ଯଦି (strcasecmp(opts[i], "verify-required") == 0)
			ବ୍ୟକ୍ତିଗତ->sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
		ଅନ୍ୟଥା ଯଦି (strcasecmp(opts[i], "no-verify-required") == 0)
			ବ୍ୟକ୍ତିଗତ->sk_flags &= ~SSH_SK_USER_VERIFICATION_REQD;
		ଅନ୍ୟଥା {
			fatal("Option \"%s\" is unsupported for "
			    "key passphrase change", opts[i]);
		}
	}
	ଯଦି (sshkey_is_sk(ବ୍ୟକ୍ତିଗତ) && nopts != 0) {
		debug_f("%s: updated FIDO key flags: "
		    "%stouch-required %sverify-required", identity_file,
		    (ବ୍ୟକ୍ତିଗତ->sk_flags & SSH_SK_USER_PRESENCE_REQD) ? "": "no-",
		    (ବ୍ୟକ୍ତିଗତ->sk_flags & SSH_SK_USER_VERIFICATION_REQD) ? "" : "no-");
	}

	/* Ask the new passphrase (twice). */
	ଯଦି (identity_new_passphrase) {
		passphrase1 = xstrdup(identity_new_passphrase);
		passphrase2 = ଖାଲି;
	} ଅନ୍ୟଥା {
		passphrase1 =
			read_passphrase("Enter new passphrase (empty for no "
			    "passphrase): ", RP_ALLOW_STDIN);
		passphrase2 = read_passphrase("Enter same passphrase again: ",
		    RP_ALLOW_STDIN);

		/* Verify that they are the same. */
		ଯଦି (strcmp(passphrase1, passphrase2) != 0) {
			explicit_bzero(passphrase1, strlen(passphrase1));
			explicit_bzero(passphrase2, strlen(passphrase2));
			ମୁକ୍ତ(passphrase1);
			ମୁକ୍ତ(passphrase2);
			printf("Pass phrases do not match.  Try again.\n");
			exit(1);
		}
		/* Destroy the other copy. */
		freezero(passphrase2, strlen(passphrase2));
	}

	/* Save the file using the new passphrase. */
	ଯଦି ((r = sshkey_save_private(ବ୍ୟକ୍ତିଗତ, identity_file, passphrase1,
	    comment, private_ଚାବି_format, openssh_format_cipher, rounds)) != 0) {
		error_r(r, "Saving key \"%s\" failed", identity_file);
		freezero(passphrase1, strlen(passphrase1));
		sshkey_free(ବ୍ୟକ୍ତିଗତ);
		ମୁକ୍ତ(comment);
		exit(1);
	}
	/* Destroy the passphrase and the copy of the key in memory. */
	freezero(passphrase1, strlen(passphrase1));
	sshkey_free(ବ୍ୟକ୍ତିଗତ);		 /* Destroys contents */
	ମୁକ୍ତ(comment);

	printf("Your identification has been saved with the new passphrase.\n");
	exit(0);
}

/*
 * Print the SSHFP RR.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
do_print_resource_record(ସଂରଚନା passwd *pw, ଅକ୍ଷର *fname, ଅକ୍ଷର *hname,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା print_generic, ଅକ୍ଷର * ଅଚଳ *opts, size_t nopts)
{
	ସଂରଚନା sshkey *ସର୍ବସାଧାରଣ;
	ଅକ୍ଷର *comment = ଖାଲି;
	ଅଚଳ ଅକ୍ଷର *p;
	ସଂରଚନା stat st;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, hash = -1;
	size_t i;

	ପାଇଁ (i = 0; i < nopts; i++) {
		ଯଦି ((p = strprefix(opts[i], "hashalg=", 1)) != ଖାଲି) {
			ଯଦି ((hash = ssh_digest_alg_by_name(p)) == -1)
				fatal("Unsupported hash algorithm");
		} ଅନ୍ୟଥା {
			error("Invalid option \"%s\"", opts[i]);
			ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
		}
	}
	ଯଦି (fname == ଖାଲି)
		fatal_f("no filename");
	ଯଦି (stat(fname, &st) == -1) {
		ଯଦି (errno == ENOENT)
			ଫେରନ୍ତୁ 0;
		fatal("%s: %s", fname, strerror(errno));
	}
	ଯଦି ((r = sshkey_load_public(fname, &ସର୍ବସାଧାରଣ, &comment)) != 0)
		fatal_r(r, "Failed to read v2 public key from \"%s\"", fname);
	export_dns_rr(hname, ସର୍ବସାଧାରଣ, stdout, print_generic, hash);
	sshkey_free(ସର୍ବସାଧାରଣ);
	ମୁକ୍ତ(comment);
	ଫେରନ୍ତୁ 1;
}

/*
 * Change the comment of a private key file.
 */
ସ୍ଥିର ଶୂନ୍ୟ
do_change_comment(ସଂରଚନା passwd *pw, ଅଚଳ ଅକ୍ଷର *identity_comment)
{
	ଅକ୍ଷର new_comment[ଚାବି_COMMENT_MAX], *comment, *passphrase;
	ସଂରଚନା sshkey *ବ୍ୟକ୍ତିଗତ;
	ସଂରଚନା sshkey *ସର୍ବସାଧାରଣ;
	ସଂରଚନା stat st;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	ଯଦି (stat(identity_file, &st) == -1)
		fatal("%s: %s", identity_file, strerror(errno));
	ଯଦି ((r = sshkey_load_private(identity_file, "",
	    &ବ୍ୟକ୍ତିଗତ, &comment)) == 0)
		passphrase = xstrdup("");
	ଅନ୍ୟଥା ଯଦି (r != SSH_ERR_ଚାବି_WRONG_PASSPHRASE)
		fatal_r(r, "Cannot load private key \"%s\"", identity_file);
	ଅନ୍ୟଥା {
		ଯଦି (identity_passphrase)
			passphrase = xstrdup(identity_passphrase);
		ଅନ୍ୟଥା ଯଦି (identity_new_passphrase)
			passphrase = xstrdup(identity_new_passphrase);
		ଅନ୍ୟଥା
			passphrase = read_passphrase("Enter passphrase: ",
			    RP_ALLOW_STDIN);
		/* Try to load using the passphrase. */
		ଯଦି ((r = sshkey_load_private(identity_file, passphrase,
		    &ବ୍ୟକ୍ତିଗତ, &comment)) != 0) {
			freezero(passphrase, strlen(passphrase));
			fatal_r(r, "Cannot load private key \"%s\"",
			    identity_file);
		}
	}

	ଯଦି (ବ୍ୟକ୍ତିଗତ->type != ଚାବି_ED25519 &&
	    private_ଚାବି_format != SSHKEY_PRIVATE_OPENSSH) {
		error("Comments are only supported for keys stored in "
		    "the new format (-o).");
		explicit_bzero(passphrase, strlen(passphrase));
		sshkey_free(ବ୍ୟକ୍ତିଗତ);
		exit(1);
	}
	ଯଦି (comment)
		printf("Old comment: %s\n", comment);
	ଅନ୍ୟଥା
		printf("No existing comment\n");

	ଯଦି (identity_comment) {
		strlcpy(new_comment, identity_comment, ଆକାର(new_comment));
	} ଅନ୍ୟଥା {
		printf("New comment: ");
		fflush(stdout);
		ଯଦି (!fgets(new_comment, ଆକାର(new_comment), stdin)) {
			explicit_bzero(passphrase, strlen(passphrase));
			sshkey_free(ବ୍ୟକ୍ତିଗତ);
			exit(1);
		}
		new_comment[strcspn(new_comment, "\n")] = '\0';
	}
	ଯଦି (comment != ଖାଲି && strcmp(comment, new_comment) == 0) {
		printf("No change to comment\n");
		ମୁକ୍ତ(passphrase);
		sshkey_free(ବ୍ୟକ୍ତିଗତ);
		ମୁକ୍ତ(comment);
		exit(0);
	}

	/* Save the file using the new passphrase. */
	ଯଦି ((r = sshkey_save_private(ବ୍ୟକ୍ତିଗତ, identity_file, passphrase,
	    new_comment, private_ଚାବି_format, openssh_format_cipher,
	    rounds)) != 0) {
		error_r(r, "Saving key \"%s\" failed", identity_file);
		freezero(passphrase, strlen(passphrase));
		sshkey_free(ବ୍ୟକ୍ତିଗତ);
		ମୁକ୍ତ(comment);
		exit(1);
	}
	freezero(passphrase, strlen(passphrase));
	ଯଦି ((r = sshkey_from_private(ବ୍ୟକ୍ତିଗତ, &ସର୍ବସାଧାରଣ)) != 0)
		fatal_fr(r, "sshkey_from_private");
	sshkey_free(ବ୍ୟକ୍ତିଗତ);

	strlcat(identity_file, ".pub", ଆକାର(identity_file));
	ଯଦି ((r = sshkey_save_public(ସର୍ବସାଧାରଣ, identity_file, new_comment)) != 0)
		fatal_r(r, "Unable to save public key to %s", identity_file);
	sshkey_free(ସର୍ବସାଧାରଣ);
	ମୁକ୍ତ(comment);

	ଯଦି (strlen(new_comment) > 0)
		printf("Comment '%s' applied\n", new_comment);
	ଅନ୍ୟଥା
		printf("Comment removed\n");

	exit(0);
}

ସ୍ଥିର ଶୂନ୍ୟ
cert_ext_add(ଅଚଳ ଅକ୍ଷର *ଚାବି, ଅଚଳ ଅକ୍ଷର *ମୂଲ୍ୟ, ପୂର୍ଣ୍ଣସଂଖ୍ୟା iscrit)
{
	cert_ext = xreallocarray(cert_ext, ncert_ext + 1, ଆକାର(*cert_ext));
	cert_ext[ncert_ext].ଚାବି = xstrdup(ଚାବି);
	cert_ext[ncert_ext].val = ମୂଲ୍ୟ == ଖାଲି ? ଖାଲି : xstrdup(ମୂଲ୍ୟ);
	cert_ext[ncert_ext].crit = iscrit;
	ncert_ext++;
}

/* qsort(3) comparison function for certificate extensions */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
cert_ext_cmp(ଅଚଳ ଶୂନ୍ୟ *_a, ଅଚଳ ଶୂନ୍ୟ *_b)
{
	ଅଚଳ ସଂରଚନା cert_ext *a = (ଅଚଳ ସଂରଚନା cert_ext *)_a;
	ଅଚଳ ସଂରଚନା cert_ext *b = (ଅଚଳ ସଂରଚନା cert_ext *)_b;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (a->crit != b->crit)
		ଫେରନ୍ତୁ (a->crit < b->crit) ? -1 : 1;
	ଯଦି ((r = strcmp(a->ଚାବି, b->ଚାବି)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି ((a->val == ଖାଲି) != (b->val == ଖାଲି))
		ଫେରନ୍ତୁ (a->val == ଖାଲି) ? -1 : 1;
	ଯଦି (a->val != ଖାଲି && (r = strcmp(a->val, b->val)) != 0)
		ଫେରନ୍ତୁ r;
	ଫେରନ୍ତୁ 0;
}

#define OPTIONS_CRITICAL	1
#define OPTIONS_EXTENSIONS	2
ସ୍ଥିର ଶୂନ୍ୟ
prepare_options_buf(ସଂରଚନା sshbuf *c, ପୂର୍ଣ୍ଣସଂଖ୍ୟା which)
{
	ସଂରଚନା sshbuf *b;
	size_t i;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ଅଚଳ ସଂରଚନା cert_ext *ext;

	ଯଦି ((b = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	sshbuf_reset(c);
	ପାଇଁ (i = 0; i < ncert_ext; i++) {
		ext = &cert_ext[i];
		ଯଦି ((ext->crit && (which & OPTIONS_EXTENSIONS)) ||
		    (!ext->crit && (which & OPTIONS_CRITICAL)))
			ଜାରି;
		ଯଦି (ext->val == ଖାଲି) {
			/* flag option */
			debug3_f("%s", ext->ଚାବି);
			ଯଦି ((r = sshbuf_put_cstring(c, ext->ଚାବି)) != 0 ||
			    (r = sshbuf_put_string(c, ଖାଲି, 0)) != 0)
				fatal_fr(r, "prepare flag");
		} ଅନ୍ୟଥା {
			/* key/value option */
			debug3_f("%s=%s", ext->ଚାବି, ext->val);
			sshbuf_reset(b);
			ଯଦି ((r = sshbuf_put_cstring(c, ext->ଚାବି)) != 0 ||
			    (r = sshbuf_put_cstring(b, ext->val)) != 0 ||
			    (r = sshbuf_put_stringb(c, b)) != 0)
				fatal_fr(r, "prepare k/v");
		}
	}
	sshbuf_free(b);
}

ସ୍ଥିର ଶୂନ୍ୟ
finalise_cert_exts(ଶୂନ୍ୟ)
{
	/* critical options */
	ଯଦି (certflags_command != ଖାଲି)
		cert_ext_add("force-command", certflags_command, 1);
	ଯଦି (certflags_src_addr != ଖାଲି)
		cert_ext_add("source-address", certflags_src_addr, 1);
	ଯଦି ((certflags_flags & CERTOPT_REQUIRE_VERIFY) != 0)
		cert_ext_add("verify-required", ଖାଲି, 1);
	/* extensions */
	ଯଦି ((certflags_flags & CERTOPT_X_FWD) != 0)
		cert_ext_add("permit-X11-forwarding", ଖାଲି, 0);
	ଯଦି ((certflags_flags & CERTOPT_AGENT_FWD) != 0)
		cert_ext_add("permit-agent-forwarding", ଖାଲି, 0);
	ଯଦି ((certflags_flags & CERTOPT_PORT_FWD) != 0)
		cert_ext_add("permit-port-forwarding", ଖାଲି, 0);
	ଯଦି ((certflags_flags & CERTOPT_PTY) != 0)
		cert_ext_add("permit-pty", ଖାଲି, 0);
	ଯଦି ((certflags_flags & CERTOPT_USER_RC) != 0)
		cert_ext_add("permit-user-rc", ଖାଲି, 0);
	ଯଦି ((certflags_flags & CERTOPT_NO_REQUIRE_USER_PRESENCE) != 0)
		cert_ext_add("no-touch-required", ଖାଲି, 0);
	/* order lexically by key */
	ଯଦି (ncert_ext > 0)
		qsort(cert_ext, ncert_ext, ଆକାର(*cert_ext), cert_ext_cmp);
}

ସ୍ଥିର ସଂରଚନା sshkey *
load_pkcs11_ଚାବି(ଅକ୍ଷର *path)
{
#ifdef ENABLE_PKCS11
	ସଂରଚନା sshkey **ଚାବିଗୁଡ଼ିକ = ଖାଲି, *ସର୍ବସାଧାରଣ, *ବ୍ୟକ୍ତିଗତ = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, i, nkeys;

	ଯଦି ((r = sshkey_load_public(path, &ସର୍ବସାଧାରଣ, ଖାଲି)) != 0)
		fatal_r(r, "Couldn't load CA public key \"%s\"", path);

	nkeys = pkcs11_add_provider(pkcs11provider, identity_passphrase,
	    &ଚାବିଗୁଡ଼ିକ, ଖାଲି);
	debug3_f("%d keys", nkeys);
	ଯଦି (nkeys <= 0)
		fatal("cannot read public key from pkcs11");
	ପାଇଁ (i = 0; i < nkeys; i++) {
		ଯଦି (sshkey_equal_public(ସର୍ବସାଧାରଣ, ଚାବିଗୁଡ଼ିକ[i])) {
			ବ୍ୟକ୍ତିଗତ = ଚାବିଗୁଡ଼ିକ[i];
			ଜାରି;
		}
		sshkey_free(ଚାବିଗୁଡ଼ିକ[i]);
	}
	ମୁକ୍ତ(ଚାବିଗୁଡ଼ିକ);
	sshkey_free(ସର୍ବସାଧାରଣ);
	ଫେରନ୍ତୁ ବ୍ୟକ୍ତିଗତ;
#ଅନ୍ୟଥା
	fatal("no pkcs11 support");
#endif /* ENABLE_PKCS11 */
}

/* Signer for sshkey_certify_custom that uses the agent */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
agent_signer(ସଂରଚନା sshkey *ଚାବି, u_char **sigp, size_t *lenp,
    ଅଚଳ u_char *data, size_t datalen,
    ଅଚଳ ଅକ୍ଷର *alg, ଅଚଳ ଅକ୍ଷର *provider, ଅଚଳ ଅକ୍ଷର *pin,
    u_int compat, ଶୂନ୍ୟ *ctx)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା *agent_fdp = (ପୂର୍ଣ୍ଣସଂଖ୍ୟା *)ctx;

	ଫେରନ୍ତୁ ssh_agent_sign(*agent_fdp, ଚାବି, sigp, lenp,
	    data, datalen, alg, compat);
}

ସ୍ଥିର ଶୂନ୍ୟ
do_ca_sign(ସଂରଚନା passwd *pw, ଅଚଳ ଅକ୍ଷର *ca_ଚାବି_path, ପୂର୍ଣ୍ଣସଂଖ୍ୟା prefer_agent,
    unsigned long long cert_serial, ପୂର୍ଣ୍ଣସଂଖ୍ୟା cert_serial_autoinc,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା argc, ଅକ୍ଷର **argv)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, i, ଚାବି_in_agent = 0, agent_fd = -1;
	u_int n;
	ସଂରଚନା sshkey *ca, *ସର୍ବସାଧାରଣ;
	ଅକ୍ଷର valid[64], *otmp, *tmp, *cp, *out, *comment;
	ଅକ୍ଷର *ca_fp = ଖାଲି, **plist = ଖାଲି, *pin = ଖାଲି;
	ସଂରଚନା ssh_identitylist *agent_ids;
	size_t j;
	ସଂରଚନା notifier_ctx *notifier = ଖାଲି;

#ifdef ENABLE_PKCS11
	pkcs11_init(1);
#endif
	tmp = tilde_expand_filename(ca_ଚାବି_path, pw->pw_uid);
	ଯଦି (pkcs11provider != ଖାଲି) {
		/* If a PKCS#11 token was specified then try to use it */
		ଯଦି ((ca = load_pkcs11_ଚାବି(tmp)) == ଖାଲି)
			fatal("No PKCS#11 key matching %s found", ca_ଚାବି_path);
	} ଅନ୍ୟଥା ଯଦି (prefer_agent) {
		/*
		 * Agent signature requested. Try to use agent after making
		 * sure the public key specified is actually present in the
		 * agent.
		 */
		ଯଦି ((r = sshkey_load_public(tmp, &ca, ଖାଲି)) != 0)
			fatal_r(r, "Cannot load CA public key %s", tmp);
		ଯଦି ((r = ssh_get_authentication_socket(&agent_fd)) != 0)
			fatal_r(r, "Cannot use public key for CA signature");
		ଯଦି ((r = ssh_fetch_identitylist(agent_fd, &agent_ids)) != 0)
			fatal_r(r, "Retrieve agent key list");
		ପାଇଁ (j = 0; j < agent_ids->nkeys; j++) {
			ଯଦି (sshkey_equal(ca, agent_ids->ଚାବିଗୁଡ଼ିକ[j])) {
				ଚାବି_in_agent = 1;
				/* Replace the CA key with the agent one */
				sshkey_free(ca);
				ca = agent_ids->ଚାବିଗୁଡ଼ିକ[j];
				agent_ids->ଚାବିଗୁଡ଼ିକ[j] = ଖାଲି;
				ଭାଙ୍ଗ;
			}
		}
		ଯଦି (!ଚାବି_in_agent)
			fatal("CA key %s not found in agent", tmp);
		ssh_free_identitylist(agent_ids);
	} ଅନ୍ୟଥା {
		/* CA key is assumed to be a private key on the filesystem */
		ca = load_identity(tmp, ଖାଲି);
		ଯଦି (sshkey_is_sk(ca) &&
		    (ca->sk_flags & SSH_SK_USER_VERIFICATION_REQD)) {
			ଯଦି ((pin = read_passphrase("Enter PIN for CA key: ",
			    RP_ALLOW_STDIN)) == ଖାଲି)
				fatal_f("couldn't read PIN");
		}
	}
	ମୁକ୍ତ(tmp);

	ଯଦି (ଚାବି_type_name != ଖାଲି) {
		ଯଦି (sshkey_type_from_shortname(ଚାବି_type_name) != ca->type) {
			fatal("CA key type %s doesn't match specified %s",
			    sshkey_ssh_name(ca), ଚାବି_type_name);
		}
	} ଅନ୍ୟଥା ଯଦି (ca->type == ଚାବି_RSA) {
		/* Default to a good signature algorithm */
		ଚାବି_type_name = "rsa-sha2-512";
	}
	ca_fp = sshkey_fingerprint(ca, fingerprint_hash, SSH_FP_DEFAULT);

	finalise_cert_exts();
	ପାଇଁ (i = 0; i < argc; i++) {
		/* Split list of principals */
		n = 0;
		ଯଦି (cert_principals != ଖାଲି) {
			otmp = tmp = xstrdup(cert_principals);
			plist = ଖାଲି;
			ପାଇଁ (; (cp = strsep(&tmp, ",")) != ଖାଲି; n++) {
				plist = xreallocarray(plist, n + 1, ଆକାର(*plist));
				ଯଦି (*(plist[n] = xstrdup(cp)) == '\0')
					fatal("Empty principal name");
			}
			ମୁକ୍ତ(otmp);
		}
		ଯଦି (n > SSHKEY_CERT_MAX_PRINCIPALS)
			fatal("Too many certificate principals specified");

		tmp = tilde_expand_filename(argv[i], pw->pw_uid);
		ଯଦି ((r = sshkey_load_public(tmp, &ସର୍ବସାଧାରଣ, &comment)) != 0)
			fatal_r(r, "load pubkey \"%s\"", tmp);
		ଯଦି (sshkey_is_cert(ସର୍ବସାଧାରଣ))
			fatal_f("key \"%s\" type %s cannot be certified",
			    tmp, sshkey_type(ସର୍ବସାଧାରଣ));

		/* Prepare certificate to sign */
		ଯଦି ((r = sshkey_to_certified(ସର୍ବସାଧାରଣ)) != 0)
			fatal_r(r, "Could not upgrade key %s to certificate", tmp);
		ସର୍ବସାଧାରଣ->cert->type = cert_ଚାବି_type;
		ସର୍ବସାଧାରଣ->cert->serial = (uint64_t)cert_serial;
		ସର୍ବସାଧାରଣ->cert->ଚାବି_id = xstrdup(cert_ଚାବି_id);
		ସର୍ବସାଧାରଣ->cert->nprincipals = n;
		ସର୍ବସାଧାରଣ->cert->principals = plist;
		ସର୍ବସାଧାରଣ->cert->valid_after = cert_valid_from;
		ସର୍ବସାଧାରଣ->cert->valid_before = cert_valid_to;
		prepare_options_buf(ସର୍ବସାଧାରଣ->cert->critical, OPTIONS_CRITICAL);
		prepare_options_buf(ସର୍ବସାଧାରଣ->cert->extensions,
		    OPTIONS_EXTENSIONS);
		ଯଦି ((r = sshkey_from_private(ca,
		    &ସର୍ବସାଧାରଣ->cert->signature_ଚାବି)) != 0)
			fatal_r(r, "sshkey_from_private (ca key)");

		ଯଦି (ଚାବି_in_agent) {
			ଯଦି ((r = sshkey_certify_custom(ସର୍ବସାଧାରଣ, ca,
			    ଚାବି_type_name, sk_provider, ଖାଲି, agent_signer,
			    &agent_fd)) != 0)
				fatal_r(r, "Couldn't certify %s via agent", tmp);
		} ଅନ୍ୟଥା {
			ଯଦି (sshkey_is_sk(ca) &&
			    (ca->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
				notifier = notify_start(0,
				    "Confirm user presence for key %s %s",
				    sshkey_type(ca), ca_fp);
			}
			r = sshkey_certify(ସର୍ବସାଧାରଣ, ca, ଚାବି_type_name,
			    sk_provider, pin);
			notify_complete(notifier, "User presence confirmed");
			ଯଦି (r != 0)
				fatal_r(r, "Couldn't certify key %s", tmp);
		}

		ଯଦି ((cp = strrchr(tmp, '.')) != ଖାଲି && strcmp(cp, ".pub") == 0)
			*cp = '\0';
		xasprintf(&out, "%s-cert.pub", tmp);
		ମୁକ୍ତ(tmp);

		ଯଦି ((r = sshkey_save_public(ସର୍ବସାଧାରଣ, out, comment)) != 0) {
			fatal_r(r, "Unable to save public key to %s",
			    identity_file);
		}

		ଯଦି (!quiet) {
			sshkey_format_cert_validity(ସର୍ବସାଧାରଣ->cert,
			    valid, ଆକାର(valid));
			logit("Signed %s key %s: id \"%s\" serial %llu%s%s "
			    "valid %s", sshkey_cert_type(ସର୍ବସାଧାରଣ),
			    out, ସର୍ବସାଧାରଣ->cert->ଚାବି_id,
			    (unsigned long long)ସର୍ବସାଧାରଣ->cert->serial,
			    cert_principals != ଖାଲି ? " for " : "",
			    cert_principals != ଖାଲି ? cert_principals : "",
			    valid);
		}

		sshkey_free(ସର୍ବସାଧାରଣ);
		ମୁକ୍ତ(out);
		ମୁକ୍ତ(comment);
		ଯଦି (cert_serial_autoinc)
			cert_serial++;
	}
	ଯଦି (pin != ଖାଲି)
		freezero(pin, strlen(pin));
	sshkey_free(ca);
	ମୁକ୍ତ(ca_fp);
#ifdef ENABLE_PKCS11
	pkcs11_terminate();
#endif
}

ସ୍ଥିର uint64_t
parse_relative_time(ଅଚଳ ଅକ୍ଷର *s, time_t now)
{
	int64_t mul, secs;

	mul = *s == '-' ? -1 : 1;

	ଯଦି ((secs = convtime(s + 1)) == -1)
		fatal("Invalid relative certificate time %s", s);
	ଯଦି (mul == -1 && secs > now)
		fatal("Certificate time %s cannot be represented", s);
	ଫେରନ୍ତୁ now + (uint64_t)(secs * mul);
}

ସ୍ଥିର ଶୂନ୍ୟ
parse_hex_u64(ଅଚଳ ଅକ୍ଷର *s, uint64_t *up)
{
	ଅକ୍ଷର *ep;
	unsigned long long ull;

	errno = 0;
	ull = strtoull(s, &ep, 16);
	ଯଦି (*s == '\0' || *ep != '\0')
		fatal("Invalid certificate time: not a number");
	ଯଦି (errno == ERANGE && ull == ULONG_MAX)
		fatal_fr(SSH_ERR_SYSTEM_ERROR, "Invalid certificate time");
	*up = (uint64_t)ull;
}

ସ୍ଥିର ଶୂନ୍ୟ
parse_cert_times(ଅକ୍ଷର *timespec)
{
	ଅକ୍ଷର *from, *to;
	time_t now = time(ଖାଲି);
	int64_t secs;

	/* +timespec relative to now */
	ଯଦି (*timespec == '+' && strchr(timespec, ':') == ଖାଲି) {
		ଯଦି ((secs = convtime(timespec + 1)) == -1)
			fatal("Invalid relative certificate life %s", timespec);
		cert_valid_to = now + secs;
		/*
		 * Backdate certificate one minute to avoid problems on hosts
		 * with poorly-synchronised clocks.
		 */
		cert_valid_from = ((now - 59)/ 60) * 60;
		ଫେରନ୍ତୁ;
	}

	/*
	 * from:to, where
	 * from := [+-]timespec | YYYYMMDD | YYYYMMDDHHMMSS | 0x... | "always"
	 *   to := [+-]timespec | YYYYMMDD | YYYYMMDDHHMMSS | 0x... | "forever"
	 */
	from = xstrdup(timespec);
	to = strchr(from, ':');
	ଯଦି (to == ଖାଲି || from == to || *(to + 1) == '\0')
		fatal("Invalid certificate life specification %s", timespec);
	*to++ = '\0';

	ଯଦି (*from == '-' || *from == '+')
		cert_valid_from = parse_relative_time(from, now);
	ଅନ୍ୟଥା ଯଦି (strcmp(from, "always") == 0)
		cert_valid_from = 0;
	ଅନ୍ୟଥା ଯଦି (strncmp(from, "0x", 2) == 0)
		parse_hex_u64(from, &cert_valid_from);
	ଅନ୍ୟଥା ଯଦି (parse_absolute_time(from, &cert_valid_from) != 0)
		fatal("Invalid from time \"%s\"", from);

	ଯଦି (*to == '-' || *to == '+')
		cert_valid_to = parse_relative_time(to, now);
	ଅନ୍ୟଥା ଯଦି (strcmp(to, "forever") == 0)
		cert_valid_to = ~(uint64_t)0;
	ଅନ୍ୟଥା ଯଦି (strncmp(to, "0x", 2) == 0)
		parse_hex_u64(to, &cert_valid_to);
	ଅନ୍ୟଥା ଯଦି (parse_absolute_time(to, &cert_valid_to) != 0)
		fatal("Invalid to time \"%s\"", to);

	ଯଦି (cert_valid_to <= cert_valid_from)
		fatal("Empty certificate validity interval");
	ମୁକ୍ତ(from);
}

ସ୍ଥିର ଶୂନ୍ୟ
add_cert_option(ଅକ୍ଷର *opt)
{
	ଅକ୍ଷର *val, *cp;
	ଅଚଳ ଅକ୍ଷର *p;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା iscrit = 0;

	ଯଦି (strcasecmp(opt, "clear") == 0)
		certflags_flags = 0;
	ଅନ୍ୟଥା ଯଦି (strcasecmp(opt, "no-x11-forwarding") == 0)
		certflags_flags &= ~CERTOPT_X_FWD;
	ଅନ୍ୟଥା ଯଦି (strcasecmp(opt, "permit-x11-forwarding") == 0)
		certflags_flags |= CERTOPT_X_FWD;
	ଅନ୍ୟଥା ଯଦି (strcasecmp(opt, "no-agent-forwarding") == 0)
		certflags_flags &= ~CERTOPT_AGENT_FWD;
	ଅନ୍ୟଥା ଯଦି (strcasecmp(opt, "permit-agent-forwarding") == 0)
		certflags_flags |= CERTOPT_AGENT_FWD;
	ଅନ୍ୟଥା ଯଦି (strcasecmp(opt, "no-port-forwarding") == 0)
		certflags_flags &= ~CERTOPT_PORT_FWD;
	ଅନ୍ୟଥା ଯଦି (strcasecmp(opt, "permit-port-forwarding") == 0)
		certflags_flags |= CERTOPT_PORT_FWD;
	ଅନ୍ୟଥା ଯଦି (strcasecmp(opt, "no-pty") == 0)
		certflags_flags &= ~CERTOPT_PTY;
	ଅନ୍ୟଥା ଯଦି (strcasecmp(opt, "permit-pty") == 0)
		certflags_flags |= CERTOPT_PTY;
	ଅନ୍ୟଥା ଯଦି (strcasecmp(opt, "no-user-rc") == 0)
		certflags_flags &= ~CERTOPT_USER_RC;
	ଅନ୍ୟଥା ଯଦି (strcasecmp(opt, "permit-user-rc") == 0)
		certflags_flags |= CERTOPT_USER_RC;
	ଅନ୍ୟଥା ଯଦି (strcasecmp(opt, "touch-required") == 0)
		certflags_flags &= ~CERTOPT_NO_REQUIRE_USER_PRESENCE;
	ଅନ୍ୟଥା ଯଦି (strcasecmp(opt, "no-touch-required") == 0)
		certflags_flags |= CERTOPT_NO_REQUIRE_USER_PRESENCE;
	ଅନ୍ୟଥା ଯଦି (strcasecmp(opt, "no-verify-required") == 0)
		certflags_flags &= ~CERTOPT_REQUIRE_VERIFY;
	ଅନ୍ୟଥା ଯଦି (strcasecmp(opt, "verify-required") == 0)
		certflags_flags |= CERTOPT_REQUIRE_VERIFY;
	ଅନ୍ୟଥା ଯଦି ((p = strprefix(opt, "force-command=", 1)) != ଖାଲି) {
		ଯଦି (*p == '\0')
			fatal("Empty force-command option");
		ଯଦି (certflags_command != ଖାଲି)
			fatal("force-command already specified");
		certflags_command = xstrdup(p);
	} ଅନ୍ୟଥା ଯଦି ((p = strprefix(opt, "source-address=", 1)) != ଖାଲି) {
		ଯଦି (*p == '\0')
			fatal("Empty source-address option");
		ଯଦି (certflags_src_addr != ଖାଲି)
			fatal("source-address already specified");
		ଯଦି (addr_match_cidr_list(ଖାଲି, p) != 0)
			fatal("Invalid source-address list");
		certflags_src_addr = xstrdup(p);
	} ଅନ୍ୟଥା ଯଦି (strprefix(opt, "extension:", 1) != ଖାଲି ||
		    (iscrit = (strprefix(opt, "critical:", 1) != ଖାଲି))) {
		val = xstrdup(strchr(opt, ':') + 1);
		ଯଦି ((cp = strchr(val, '=')) != ଖାଲି)
			*cp++ = '\0';
		cert_ext_add(val, cp, iscrit);
		ମୁକ୍ତ(val);
	} ଅନ୍ୟଥା
		fatal("Unsupported certificate option \"%s\"", opt);
}

ସ୍ଥିର ଶୂନ୍ୟ
show_options(ସଂରଚନା sshbuf *optbuf, ପୂର୍ଣ୍ଣସଂଖ୍ୟା in_critical)
{
	ଅକ୍ଷର *name, *arg, *hex;
	ସଂରଚନା sshbuf *options, *option = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((options = sshbuf_fromb(optbuf)) == ଖାଲି)
		fatal_f("sshbuf_fromb failed");
	ଯେତେବେଳେ (sshbuf_len(options) != 0) {
		sshbuf_free(option);
		option = ଖାଲି;
		ଯଦି ((r = sshbuf_get_cstring(options, &name, ଖାଲି)) != 0 ||
		    (r = sshbuf_froms(options, &option)) != 0)
			fatal_fr(r, "parse option");
		printf("                %s", name);
		ଯଦି (!in_critical &&
		    (strcmp(name, "permit-X11-forwarding") == 0 ||
		    strcmp(name, "permit-agent-forwarding") == 0 ||
		    strcmp(name, "permit-port-forwarding") == 0 ||
		    strcmp(name, "permit-pty") == 0 ||
		    strcmp(name, "permit-user-rc") == 0 ||
		    strcmp(name, "no-touch-required") == 0)) {
			printf("\n");
		} ଅନ୍ୟଥା ଯଦି (in_critical &&
		    (strcmp(name, "force-command") == 0 ||
		    strcmp(name, "source-address") == 0)) {
			ଯଦି ((r = sshbuf_get_cstring(option, &arg, ଖାଲି)) != 0)
				fatal_fr(r, "parse critical");
			printf(" %s\n", arg);
			ମୁକ୍ତ(arg);
		} ଅନ୍ୟଥା ଯଦି (in_critical &&
		    strcmp(name, "verify-required") == 0) {
			printf("\n");
		} ଅନ୍ୟଥା ଯଦି (sshbuf_len(option) > 0) {
			hex = sshbuf_dtob16(option);
			printf(" UNKNOWN OPTION: %s (len %zu)\n",
			    hex, sshbuf_len(option));
			sshbuf_reset(option);
			ମୁକ୍ତ(hex);
		} ଅନ୍ୟଥା
			printf(" UNKNOWN FLAG OPTION\n");
		ମୁକ୍ତ(name);
		ଯଦି (sshbuf_len(option) != 0)
			fatal("Option corrupt: extra data at end");
	}
	sshbuf_free(option);
	sshbuf_free(options);
}

ସ୍ଥିର ଶୂନ୍ୟ
print_cert(ସଂରଚନା sshkey *ଚାବି)
{
	ଅକ୍ଷର valid[64], *ଚାବି_fp, *ca_fp;
	u_int i;

	ଚାବି_fp = sshkey_fingerprint(ଚାବି, fingerprint_hash, SSH_FP_DEFAULT);
	ca_fp = sshkey_fingerprint(ଚାବି->cert->signature_ଚାବି,
	    fingerprint_hash, SSH_FP_DEFAULT);
	ଯଦି (ଚାବି_fp == ଖାଲି || ca_fp == ଖାଲି)
		fatal_f("sshkey_fingerprint fail");
	sshkey_format_cert_validity(ଚାବି->cert, valid, ଆକାର(valid));

	printf("        Type: %s %s certificate\n", sshkey_ssh_name(ଚାବି),
	    sshkey_cert_type(ଚାବି));
	printf("        Public key: %s %s\n", sshkey_type(ଚାବି), ଚାବି_fp);
	printf("        Signing CA: %s %s (using %s)\n",
	    sshkey_type(ଚାବି->cert->signature_ଚାବି), ca_fp,
	    ଚାବି->cert->signature_type);
	printf("        Key ID: \"%s\"\n", ଚାବି->cert->ଚାବି_id);
	printf("        Serial: %llu\n", (unsigned long long)ଚାବି->cert->serial);
	printf("        Valid: %s\n", valid);
	printf("        Principals: ");
	ଯଦି (ଚାବି->cert->nprincipals == 0)
		printf("(none)\n");
	ଅନ୍ୟଥା {
		ପାଇଁ (i = 0; i < ଚାବି->cert->nprincipals; i++)
			printf("\n                %s",
			    ଚାବି->cert->principals[i]);
		printf("\n");
	}
	printf("        Critical Options: ");
	ଯଦି (sshbuf_len(ଚାବି->cert->critical) == 0)
		printf("(none)\n");
	ଅନ୍ୟଥା {
		printf("\n");
		show_options(ଚାବି->cert->critical, 1);
	}
	printf("        Extensions: ");
	ଯଦି (sshbuf_len(ଚାବି->cert->extensions) == 0)
		printf("(none)\n");
	ଅନ୍ୟଥା {
		printf("\n");
		show_options(ଚାବି->cert->extensions, 0);
	}
	ମୁକ୍ତ(ଚାବି_fp);
	ମୁକ୍ତ(ca_fp);
}

ସ୍ଥିର ଶୂନ୍ୟ
do_show_cert(ସଂରଚନା passwd *pw)
{
	ସଂରଚନା sshkey *ଚାବି = ଖାଲି;
	ସଂରଚନା stat st;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, is_stdin = 0, ok = 0;
	FILE *f;
	ଅକ୍ଷର *cp, *ଧାଡ଼ି = ଖାଲି;
	ଅଚଳ ଅକ୍ଷର *path;
	size_t linesize = 0;
	u_long lnum = 0;

	ଯଦି (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	ଯଦି (strcmp(identity_file, "-") != 0 && stat(identity_file, &st) == -1)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));

	path = identity_file;
	ଯଦି (strcmp(path, "-") == 0) {
		f = stdin;
		path = "(stdin)";
		is_stdin = 1;
	} ଅନ୍ୟଥା ଯଦି ((f = fopen(identity_file, "r")) == ଖାଲି)
		fatal("fopen %s: %s", identity_file, strerror(errno));

	ଯେତେବେଳେ (getline(&ଧାଡ଼ି, &linesize, f) != -1) {
		lnum++;
		sshkey_free(ଚାବି);
		ଚାବି = ଖାଲି;
		/* Trim leading space and comments */
		cp = ଧାଡ଼ି + strspn(ଧାଡ଼ି, " \t");
		ଯଦି (*cp == '#' || *cp == '\0')
			ଜାରି;
		ଯଦି ((ଚାବି = sshkey_new(ଚାବି_UNSPEC)) == ଖାଲି)
			fatal("sshkey_new");
		ଯଦି ((r = sshkey_read(ଚାବି, &cp)) != 0) {
			error_r(r, "%s:%lu: invalid key", path, lnum);
			ଜାରି;
		}
		ଯଦି (!sshkey_is_cert(ଚାବି)) {
			error("%s:%lu is not a certificate", path, lnum);
			ଜାରି;
		}
		ok = 1;
		ଯଦି (!is_stdin && lnum == 1)
			printf("%s:\n", path);
		ଅନ୍ୟଥା
			printf("%s:%lu:\n", path, lnum);
		print_cert(ଚାବି);
	}
	ମୁକ୍ତ(ଧାଡ଼ି);
	sshkey_free(ଚାବି);
	fclose(f);
	exit(ok ? 0 : 1);
}

ସ୍ଥିର ଶୂନ୍ୟ
load_krl(ଅଚଳ ଅକ୍ଷର *path, ସଂରଚନା ssh_krl **krlp)
{
	ସଂରଚନା sshbuf *krlbuf;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshbuf_load_file(path, &krlbuf)) != 0)
		fatal_r(r, "Unable to load KRL %s", path);
	/* XXX check sigs */
	ଯଦି ((r = ssh_krl_from_blob(krlbuf, krlp)) != 0 ||
	    *krlp == ଖାଲି)
		fatal_r(r, "Invalid KRL file %s", path);
	sshbuf_free(krlbuf);
}

ସ୍ଥିର ଶୂନ୍ୟ
hash_to_blob(ଅଚଳ ଅକ୍ଷର *cp, u_char **blobp, size_t *lenp,
    ଅଚଳ ଅକ୍ଷର *file, u_long lnum)
{
	ଅକ୍ଷର *tmp;
	size_t tlen;
	ସଂରଚନା sshbuf *b;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((cp = strprefix(cp, "SHA256:", 0)) == ଖାଲି)
		fatal("%s:%lu: unsupported hash algorithm", file, lnum);

	/*
	 * OpenSSH base64 hashes omit trailing '='
	 * characters; put them back for decode.
	 */
	ଯଦି ((tlen = strlen(cp)) >= SIZE_MAX - 5)
		fatal_f("hash too long: %zu bytes", tlen);
	tmp = xmalloc(tlen + 4 + 1);
	strlcpy(tmp, cp, tlen + 1);
	ଯେତେବେଳେ ((tlen % 4) != 0) {
		tmp[tlen++] = '=';
		tmp[tlen] = '\0';
	}
	ଯଦି ((b = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = sshbuf_b64tod(b, tmp)) != 0)
		fatal_r(r, "%s:%lu: decode hash failed", file, lnum);
	ମୁକ୍ତ(tmp);
	*lenp = sshbuf_len(b);
	*blobp = xmalloc(*lenp);
	memcpy(*blobp, sshbuf_ptr(b), *lenp);
	sshbuf_free(b);
}

ସ୍ଥିର ଶୂନ୍ୟ
update_krl_from_file(ସଂରଚନା passwd *pw, ଅଚଳ ଅକ୍ଷର *file, ପୂର୍ଣ୍ଣସଂଖ୍ୟା wild_ca,
    ଅଚଳ ସଂରଚନା sshkey *ca, ସଂରଚନା ssh_krl *krl)
{
	ସଂରଚନା sshkey *ଚାବି = ଖାଲି;
	u_long lnum = 0;
	ଅକ୍ଷର *path, *cp, *ep, *ଧାଡ଼ି = ଖାଲି;
	u_char *blob = ଖାଲି;
	size_t blen = 0, linesize = 0;
	unsigned long long serial, serial2;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, was_explicit_ଚାବି, was_sha1, was_sha256, was_hash, r;
	FILE *krl_spec;

	path = tilde_expand_filename(file, pw->pw_uid);
	ଯଦି (strcmp(path, "-") == 0) {
		krl_spec = stdin;
		ମୁକ୍ତ(path);
		path = xstrdup("(standard input)");
	} ଅନ୍ୟଥା ଯଦି ((krl_spec = fopen(path, "r")) == ଖାଲି)
		fatal("fopen %s: %s", path, strerror(errno));

	ଯଦି (!quiet)
		printf("Revoking from %s\n", path);
	ଯେତେବେଳେ (getline(&ଧାଡ଼ି, &linesize, krl_spec) != -1) {
		ଯଦି (linesize >= INT_MAX) {
			fatal_f("%s contains unparsable line, len=%zu",
			    path, linesize);
		}
		lnum++;
		was_explicit_ଚାବି = was_sha1 = was_sha256 = was_hash = 0;
		cp = ଧାଡ଼ି + strspn(ଧାଡ଼ି, " \t");
		/* Trim trailing space, comments and strip \n */
		ପାଇଁ (i = 0, r = -1; cp[i] != '\0'; i++) {
			ଯଦି (cp[i] == '#' || cp[i] == '\n') {
				cp[i] = '\0';
				ଭାଙ୍ଗ;
			}
			ଯଦି (cp[i] == ' ' || cp[i] == '\t') {
				/* Remember the start of a span of whitespace */
				ଯଦି (r == -1)
					r = i;
			} ଅନ୍ୟଥା
				r = -1;
		}
		ଯଦି (r != -1)
			cp[r] = '\0';
		ଯଦି (*cp == '\0')
			ଜାରି;
		ଯଦି (strncasecmp(cp, "serial:", 7) == 0) {
			ଯଦି (ca == ଖାଲି && !wild_ca) {
				fatal("revoking certificates by serial number "
				    "requires specification of a CA key");
			}
			cp += 7;
			cp = cp + strspn(cp, " \t");
			errno = 0;
			serial = strtoull(cp, &ep, 0);
			ଯଦି (*cp == '\0' || (*ep != '\0' && *ep != '-'))
				fatal("%s:%lu: invalid serial \"%s\"",
				    path, lnum, cp);
			ଯଦି (errno == ERANGE && serial == ULLONG_MAX)
				fatal("%s:%lu: serial out of range",
				    path, lnum);
			serial2 = serial;
			ଯଦି (*ep == '-') {
				cp = ep + 1;
				errno = 0;
				serial2 = strtoull(cp, &ep, 0);
				ଯଦି (*cp == '\0' || *ep != '\0')
					fatal("%s:%lu: invalid serial \"%s\"",
					    path, lnum, cp);
				ଯଦି (errno == ERANGE && serial2 == ULLONG_MAX)
					fatal("%s:%lu: serial out of range",
					    path, lnum);
				ଯଦି (serial2 <= serial)
					fatal("%s:%lu: invalid serial range "
					    "%llu:%llu", path, lnum,
					    (unsigned long long)serial,
					    (unsigned long long)serial2);
			}
			ଯଦି (ssh_krl_revoke_cert_by_serial_range(krl,
			    ca, serial, serial2) != 0) {
				fatal_f("revoke serial failed");
			}
		} ଅନ୍ୟଥା ଯଦି (strncasecmp(cp, "id:", 3) == 0) {
			ଯଦି (ca == ଖାଲି && !wild_ca) {
				fatal("revoking certificates by key ID "
				    "requires specification of a CA key");
			}
			cp += 3;
			cp = cp + strspn(cp, " \t");
			ଯଦି (ssh_krl_revoke_cert_by_ଚାବି_id(krl, ca, cp) != 0)
				fatal_f("revoke key ID failed");
		} ଅନ୍ୟଥା ଯଦି (strncasecmp(cp, "hash:", 5) == 0) {
			cp += 5;
			cp = cp + strspn(cp, " \t");
			hash_to_blob(cp, &blob, &blen, file, lnum);
			ଯଦି ((r = ssh_krl_revoke_ଚାବି_sha256(krl,
			    blob, blen)) != 0)
				fatal_fr(r, "revoke key failed");
			ମୁକ୍ତ(blob);
			blob = ଖାଲି;
			blen = 0;
		} ଅନ୍ୟଥା {
			ଯଦି (strncasecmp(cp, "key:", 4) == 0) {
				cp += 4;
				cp = cp + strspn(cp, " \t");
				was_explicit_ଚାବି = 1;
			} ଅନ୍ୟଥା ଯଦି (strncasecmp(cp, "sha1:", 5) == 0) {
				cp += 5;
				cp = cp + strspn(cp, " \t");
				was_sha1 = 1;
			} ଅନ୍ୟଥା ଯଦି (strncasecmp(cp, "sha256:", 7) == 0) {
				cp += 7;
				cp = cp + strspn(cp, " \t");
				was_sha256 = 1;
				/*
				 * Just try to process the line as a key.
				 * Parsing will fail if it isn't.
				 */
			}
			ଯଦି ((ଚାବି = sshkey_new(ଚାବି_UNSPEC)) == ଖାଲି)
				fatal("sshkey_new");
			ଯଦି ((r = sshkey_read(ଚାବି, &cp)) != 0)
				fatal_r(r, "%s:%lu: invalid key", path, lnum);
			ଯଦି (was_explicit_ଚାବି)
				r = ssh_krl_revoke_ଚାବି_explicit(krl, ଚାବି);
			ଅନ୍ୟଥା ଯଦି (was_sha1) {
				ଯଦି (sshkey_fingerprint_raw(ଚାବି,
				    SSH_DIGEST_SHA1, &blob, &blen) != 0) {
					fatal("%s:%lu: fingerprint failed",
					    file, lnum);
				}
				r = ssh_krl_revoke_ଚାବି_sha1(krl, blob, blen);
			} ଅନ୍ୟଥା ଯଦି (was_sha256) {
				ଯଦି (sshkey_fingerprint_raw(ଚାବି,
				    SSH_DIGEST_SHA256, &blob, &blen) != 0) {
					fatal("%s:%lu: fingerprint failed",
					    file, lnum);
				}
				r = ssh_krl_revoke_ଚାବି_sha256(krl, blob, blen);
			} ଅନ୍ୟଥା
				r = ssh_krl_revoke_ଚାବି(krl, ଚାବି);
			ଯଦି (r != 0)
				fatal_fr(r, "revoke key failed");
			freezero(blob, blen);
			blob = ଖାଲି;
			blen = 0;
			sshkey_free(ଚାବି);
		}
	}
	ଯଦି (strcmp(path, "-") != 0)
		fclose(krl_spec);
	ମୁକ୍ତ(ଧାଡ଼ି);
	ମୁକ୍ତ(path);
}

ସ୍ଥିର ଶୂନ୍ୟ
do_gen_krl(ସଂରଚନା passwd *pw, ପୂର୍ଣ୍ଣସଂଖ୍ୟା updating, ଅଚଳ ଅକ୍ଷର *ca_ଚାବି_path,
    unsigned long long krl_version, ଅଚଳ ଅକ୍ଷର *krl_comment,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା argc, ଅକ୍ଷର **argv)
{
	ସଂରଚନା ssh_krl *krl;
	ସଂରଚନା stat sb;
	ସଂରଚନା sshkey *ca = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, r, wild_ca = 0;
	ଅକ୍ଷର *tmp;
	ସଂରଚନା sshbuf *kbuf;

	ଯଦି (*identity_file == '\0')
		fatal("KRL generation requires an output file");
	ଯଦି (stat(identity_file, &sb) == -1) {
		ଯଦି (errno != ENOENT)
			fatal("Cannot access KRL \"%s\": %s",
			    identity_file, strerror(errno));
		ଯଦି (updating)
			fatal("KRL \"%s\" does not exist", identity_file);
	}
	ଯଦି (ca_ଚାବି_path != ଖାଲି) {
		ଯଦି (strcasecmp(ca_ଚାବି_path, "none") == 0)
			wild_ca = 1;
		ଅନ୍ୟଥା {
			tmp = tilde_expand_filename(ca_ଚାବି_path, pw->pw_uid);
			ଯଦି ((r = sshkey_load_public(tmp, &ca, ଖାଲି)) != 0)
				fatal_r(r, "Cannot load CA public key %s", tmp);
			ମୁକ୍ତ(tmp);
		}
	}

	ଯଦି (updating)
		load_krl(identity_file, &krl);
	ଅନ୍ୟଥା ଯଦି ((krl = ssh_krl_init()) == ଖାଲି)
		fatal("couldn't create KRL");

	ଯଦି (krl_version != 0)
		ssh_krl_set_version(krl, krl_version);
	ଯଦି (krl_comment != ଖାଲି)
		ssh_krl_set_comment(krl, krl_comment);

	ପାଇଁ (i = 0; i < argc; i++)
		update_krl_from_file(pw, argv[i], wild_ca, ca, krl);

	ଯଦି ((kbuf = sshbuf_new()) == ଖାଲି)
		fatal("sshbuf_new failed");
	ଯଦି (ssh_krl_to_blob(krl, kbuf) != 0)
		fatal("Couldn't generate KRL");
	ଯଦି ((r = sshbuf_write_file(identity_file, kbuf)) != 0)
		fatal("write %s: %s", identity_file, strerror(errno));
	sshbuf_free(kbuf);
	ssh_krl_free(krl);
	sshkey_free(ca);
}

ସ୍ଥିର ଶୂନ୍ୟ
do_check_krl(ସଂରଚନା passwd *pw, ପୂର୍ଣ୍ଣସଂଖ୍ୟା print_krl, ପୂର୍ଣ୍ଣସଂଖ୍ୟା argc, ଅକ୍ଷର **argv)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, r, ret = 0;
	ଅକ୍ଷର *comment;
	ସଂରଚନା ssh_krl *krl;
	ସଂରଚନା sshkey *k;

	ଯଦି (*identity_file == '\0')
		fatal("KRL checking requires an input file");
	load_krl(identity_file, &krl);
	ଯଦି (print_krl)
		krl_dump(krl, stdout);
	ପାଇଁ (i = 0; i < argc; i++) {
		ଯଦି ((r = sshkey_load_public(argv[i], &k, &comment)) != 0)
			fatal_r(r, "Cannot load public key %s", argv[i]);
		r = ssh_krl_check_ଚାବି(krl, k);
		printf("%s%s%s%s: %s\n", argv[i],
		    *comment ? " (" : "", comment, *comment ? ")" : "",
		    r == 0 ? "ok" : "REVOKED");
		ଯଦି (r != 0)
			ret = 1;
		sshkey_free(k);
		ମୁକ୍ତ(comment);
	}
	ssh_krl_free(krl);
	exit(ret);
}

ସ୍ଥିର ସଂରଚନା sshkey *
load_sign_ଚାବି(ଅଚଳ ଅକ୍ଷର *keypath, ଅଚଳ ସଂରଚନା sshkey *pubkey)
{
	size_t i, slen, plen = strlen(keypath);
	ଅକ୍ଷର *privpath = xstrdup(keypath);
	ସ୍ଥିର ଅଚଳ ଅକ୍ଷର * ଅଚଳ suffixes[] = { "-cert.pub", ".pub", ଖାଲି };
	ସଂରଚନା sshkey *ret = ଖାଲି, *privkey = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, waspub = 0;
	ସଂରଚନା stat st;

	/*
	 * If passed a public key filename, then try to locate the corresponding
	 * private key. This lets us specify certificates on the command-line
	 * and have ssh-keygen find the appropriate private key.
	 */
	ପାଇଁ (i = 0; suffixes[i]; i++) {
		slen = strlen(suffixes[i]);
		ଯଦି (plen <= slen ||
		    strcmp(privpath + plen - slen, suffixes[i]) != 0)
			ଜାରି;
		privpath[plen - slen] = '\0';
		debug_f("%s looks like a public key, using private key "
		    "path %s instead", keypath, privpath);
		waspub = 1;
	}
	ଯଦି (waspub && stat(privpath, &st) != 0 && errno == ENOENT)
		fatal("No private key found for public key \"%s\"", keypath);
	ଯଦି ((r = sshkey_load_private(privpath, "", &privkey, ଖାଲି)) != 0 &&
	    (r != SSH_ERR_ଚାବି_WRONG_PASSPHRASE)) {
		debug_fr(r, "load private key \"%s\"", privpath);
		fatal("No private key found for \"%s\"", privpath);
	} ଅନ୍ୟଥା ଯଦି (privkey == ଖାଲି)
		privkey = load_identity(privpath, ଖାଲି);

	ଯଦି (!sshkey_equal_public(pubkey, privkey)) {
		error("Public key %s doesn't match private %s",
		    keypath, privpath);
		ଯାଅ done;
	}
	ଯଦି (sshkey_is_cert(pubkey) && !sshkey_is_cert(privkey)) {
		/*
		 * Graft the certificate onto the private key to make
		 * it capable of signing.
		 */
		ଯଦି ((r = sshkey_to_certified(privkey)) != 0) {
			error_fr(r, "sshkey_to_certified");
			ଯାଅ done;
		}
		ଯଦି ((r = sshkey_cert_copy(pubkey, privkey)) != 0) {
			error_fr(r, "sshkey_cert_copy");
			ଯାଅ done;
		}
	}
	/* success */
	ret = privkey;
	privkey = ଖାଲି;
 done:
	sshkey_free(privkey);
	ମୁକ୍ତ(privpath);
	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sign_one(ସଂରଚନା sshkey *signkey, ଅଚଳ ଅକ୍ଷର *filename, ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd,
    ଅଚଳ ଅକ୍ଷର *sig_namespace, ଅଚଳ ଅକ୍ଷର *hashalg, sshsig_signer *signer,
    ଶୂନ୍ୟ *signer_ctx)
{
	ସଂରଚନା sshbuf *sigbuf = ଖାଲି, *abuf = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR, wfd = -1, oerrno;
	ଅକ୍ଷର *wfile = ଖାଲି, *asig = ଖାଲି, *fp = ଖାଲି;
	ଅକ୍ଷର *pin = ଖାଲି, *prompt = ଖାଲି;

	ଯଦି (!quiet) {
		ଯଦି (fd == STDIN_FILENO)
			fprintf(stderr, "Signing data on standard input\n");
		ଅନ୍ୟଥା
			fprintf(stderr, "Signing file %s\n", filename);
	}
	ଯଦି (signer == ଖାଲି && sshkey_is_sk(signkey)) {
		ଯଦି ((signkey->sk_flags & SSH_SK_USER_VERIFICATION_REQD)) {
			xasprintf(&prompt, "Enter PIN for %s key: ",
			    sshkey_type(signkey));
			ଯଦି ((pin = read_passphrase(prompt,
			    RP_ALLOW_STDIN)) == ଖାଲି)
				fatal_f("couldn't read PIN");
		}
		ଯଦି ((signkey->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
			ଯଦି ((fp = sshkey_fingerprint(signkey, fingerprint_hash,
			    SSH_FP_DEFAULT)) == ଖାଲି)
				fatal_f("fingerprint failed");
			fprintf(stderr, "Confirm user presence for key %s %s\n",
			    sshkey_type(signkey), fp);
			ମୁକ୍ତ(fp);
		}
	}
	ଯଦି ((r = sshsig_sign_fd(signkey, hashalg, sk_provider, pin,
	    fd, sig_namespace, &sigbuf, signer, signer_ctx)) != 0) {
		error_r(r, "Signing %s failed", filename);
		ଯାଅ out;
	}
	ଯଦି ((r = sshsig_armor(sigbuf, &abuf)) != 0) {
		error_fr(r, "sshsig_armor");
		ଯାଅ out;
	}
	ଯଦି ((asig = sshbuf_dup_string(abuf)) == ଖାଲି) {
		error_f("buffer error");
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}

	ଯଦି (fd == STDIN_FILENO) {
		fputs(asig, stdout);
		fflush(stdout);
	} ଅନ୍ୟଥା {
		xasprintf(&wfile, "%s.sig", filename);
		ଯଦି (confirm_overwrite(wfile)) {
			ଯଦି ((wfd = open(wfile, O_WRONLY|O_CREAT|O_TRUNC,
			    0666)) == -1) {
				oerrno = errno;
				error("Cannot open %s: %s",
				    wfile, strerror(errno));
				errno = oerrno;
				r = SSH_ERR_SYSTEM_ERROR;
				ଯାଅ out;
			}
			ଯଦି (atomicio(vwrite, wfd, asig,
			    strlen(asig)) != strlen(asig)) {
				oerrno = errno;
				error("Cannot write to %s: %s",
				    wfile, strerror(errno));
				errno = oerrno;
				r = SSH_ERR_SYSTEM_ERROR;
				ଯାଅ out;
			}
			ଯଦି (!quiet) {
				fprintf(stderr, "Write signature to %s\n",
				    wfile);
			}
		}
	}
	/* success */
	r = 0;
 out:
	ମୁକ୍ତ(wfile);
	ମୁକ୍ତ(prompt);
	ମୁକ୍ତ(asig);
	ଯଦି (pin != ଖାଲି)
		freezero(pin, strlen(pin));
	sshbuf_free(abuf);
	sshbuf_free(sigbuf);
	ଯଦି (wfd != -1)
		close(wfd);
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sig_process_opts(ଅକ୍ଷର * ଅଚଳ *opts, size_t nopts, ଅକ୍ଷର **hashalgp,
    uint64_t *verify_timep, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *print_pubkey)
{
	size_t i;
	time_t now;
	ଅଚଳ ଅକ୍ଷର *p;

	ଯଦି (verify_timep != ଖାଲି)
		*verify_timep = 0;
	ଯଦି (print_pubkey != ଖାଲି)
		*print_pubkey = 0;
	ଯଦି (hashalgp != ଖାଲି)
		*hashalgp = ଖାଲି;
	ପାଇଁ (i = 0; i < nopts; i++) {
		ଯଦି (hashalgp != ଖାଲି &&
		    (p = strprefix(opts[i], "hashalg=", 1)) != ଖାଲି) {
			*hashalgp = xstrdup(p);
		} ଅନ୍ୟଥା ଯଦି (verify_timep &&
		    (p = strprefix(opts[i], "verify-time=", 1)) != ଖାଲି) {
			ଯଦି (parse_absolute_time(p, verify_timep) != 0 ||
			    *verify_timep == 0) {
				error("Invalid \"verify-time\" option");
				ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
			}
		} ଅନ୍ୟଥା ଯଦି (print_pubkey &&
		    strcasecmp(opts[i], "print-pubkey") == 0) {
			*print_pubkey = 1;
		} ଅନ୍ୟଥା {
			error("Invalid option \"%s\"", opts[i]);
			ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
		}
	}
	ଯଦି (verify_timep && *verify_timep == 0) {
		ଯଦି ((now = time(ଖାଲି)) < 0) {
			error("Time is before epoch");
			ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
		}
		*verify_timep = (uint64_t)now;
	}
	ଫେରନ୍ତୁ 0;
}


ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sig_sign(ଅଚଳ ଅକ୍ଷର *keypath, ଅଚଳ ଅକ୍ଷର *sig_namespace, ପୂର୍ଣ୍ଣସଂଖ୍ୟା require_agent,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା argc, ଅକ୍ଷର **argv, ଅକ୍ଷର * ଅଚଳ *opts, size_t nopts)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, fd = -1, r, ret = -1;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା agent_fd = -1;
	ସଂରଚନା sshkey *pubkey = ଖାଲି, *privkey = ଖାଲି, *signkey = ଖାଲି;
	sshsig_signer *signer = ଖାଲି;
	ଅକ୍ଷର *hashalg = ଖାଲି;

	/* Check file arguments. */
	ପାଇଁ (i = 0; i < argc; i++) {
		ଯଦି (strcmp(argv[i], "-") != 0)
			ଜାରି;
		ଯଦି (i > 0 || argc > 1)
			fatal("Cannot sign mix of paths and standard input");
	}

	ଯଦି (sig_process_opts(opts, nopts, &hashalg, ଖାଲି, ଖାଲି) != 0)
		ଯାଅ done; /* error already logged */

	ଯଦି ((r = sshkey_load_public(keypath, &pubkey, ଖାଲି)) != 0) {
		error_r(r, "Couldn't load public key %s", keypath);
		ଯାଅ done;
	}

	ଯଦି ((r = ssh_get_authentication_socket(&agent_fd)) != 0) {
		ଯଦି (require_agent)
			fatal("Couldn't get agent socket");
		debug_r(r, "Couldn't get agent socket");
	} ଅନ୍ୟଥା {
		ଯଦି ((r = ssh_agent_has_ଚାବି(agent_fd, pubkey)) == 0)
			signer = agent_signer;
		ଅନ୍ୟଥା {
			ଯଦି (require_agent)
				fatal("Couldn't find key in agent");
			debug_r(r, "Couldn't find key in agent");
		}
	}

	ଯଦି (signer == ଖାଲି) {
		/* Not using agent - try to load private key */
		ଯଦି ((privkey = load_sign_ଚାବି(keypath, pubkey)) == ଖାଲି)
			ଯାଅ done;
		signkey = privkey;
	} ଅନ୍ୟଥା {
		/* Will use key in agent */
		signkey = pubkey;
	}

	ଯଦି (argc == 0) {
		ଯଦି ((r = sign_one(signkey, "(stdin)", STDIN_FILENO,
		    sig_namespace, hashalg, signer, &agent_fd)) != 0)
			ଯାଅ done;
	} ଅନ୍ୟଥା {
		ପାଇଁ (i = 0; i < argc; i++) {
			ଯଦି (strcmp(argv[i], "-") == 0)
				fd = STDIN_FILENO;
			ଅନ୍ୟଥା ଯଦି ((fd = open(argv[i], O_RDONLY)) == -1) {
				error("Cannot open %s for signing: %s",
				    argv[i], strerror(errno));
				ଯାଅ done;
			}
			ଯଦି ((r = sign_one(signkey, argv[i], fd, sig_namespace,
			    hashalg, signer, &agent_fd)) != 0)
				ଯାଅ done;
			ଯଦି (fd != STDIN_FILENO)
				close(fd);
			fd = -1;
		}
	}

	ret = 0;
done:
	ଯଦି (fd != -1 && fd != STDIN_FILENO)
		close(fd);
	sshkey_free(pubkey);
	sshkey_free(privkey);
	ମୁକ୍ତ(hashalg);
	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sig_verify(ଅଚଳ ଅକ୍ଷର *signature, ଅଚଳ ଅକ୍ଷର *sig_namespace,
    ଅଚଳ ଅକ୍ଷର *principal, ଅଚଳ ଅକ୍ଷର *allowed_ଚାବିଗୁଡ଼ିକ, ଅଚଳ ଅକ୍ଷର *revoked_ଚାବିଗୁଡ଼ିକ,
    ଅକ୍ଷର * ଅଚଳ *opts, size_t nopts)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, ret = -1;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା print_pubkey = 0;
	ସଂରଚନା sshbuf *sigbuf = ଖାଲି, *abuf = ଖାଲି;
	ସଂରଚନା sshkey *sign_ଚାବି = ଖାଲି;
	ଅକ୍ଷର *fp = ଖାଲି;
	ସଂରଚନା sshkey_sig_details *sig_details = ଖାଲି;
	uint64_t verify_time = 0;

	ଯଦି (sig_process_opts(opts, nopts, ଖାଲି, &verify_time,
	    &print_pubkey) != 0)
		ଯାଅ done; /* error already logged */

	memset(&sig_details, 0, ଆକାର(sig_details));
	ଯଦି ((r = sshbuf_load_file(signature, &abuf)) != 0) {
		error_r(r, "Couldn't read signature file");
		ଯାଅ done;
	}

	ଯଦି ((r = sshsig_dearmor(abuf, &sigbuf)) != 0) {
		error_fr(r, "sshsig_armor");
		ଯାଅ done;
	}
	ଯଦି ((r = sshsig_verify_fd(sigbuf, STDIN_FILENO, sig_namespace,
	    &sign_ଚାବି, &sig_details)) != 0)
		ଯାଅ done; /* sshsig_verify() prints error */

	ଯଦି ((fp = sshkey_fingerprint(sign_ଚାବି, fingerprint_hash,
	    SSH_FP_DEFAULT)) == ଖାଲି)
		fatal_f("sshkey_fingerprint failed");
	debug("Valid (unverified) signature from key %s", fp);
	ଯଦି (sig_details != ଖାଲି) {
		debug2_f("signature details: counter = %u, flags = 0x%02x",
		    sig_details->sk_counter, sig_details->sk_flags);
	}
	ମୁକ୍ତ(fp);
	fp = ଖାଲି;

	ଯଦି (revoked_ଚାବିଗୁଡ଼ିକ != ଖାଲି) {
		ଯଦି ((r = sshkey_check_revoked(sign_ଚାବି, revoked_ଚାବିଗୁଡ଼ିକ)) != 0) {
			debug3_fr(r, "sshkey_check_revoked");
			ଯାଅ done;
		}
	}

	ଯଦି (allowed_ଚାବିଗୁଡ଼ିକ != ଖାଲି && (r = sshsig_check_allowed_ଚାବିଗୁଡ଼ିକ(allowed_ଚାବିଗୁଡ଼ିକ,
	    sign_ଚାବି, principal, sig_namespace, verify_time)) != 0) {
		debug3_fr(r, "sshsig_check_allowed_keys");
		ଯାଅ done;
	}
	/* success */
	ret = 0;
done:
	ଯଦି (!quiet) {
		ଯଦି (ret == 0) {
			ଯଦି ((fp = sshkey_fingerprint(sign_ଚାବି, fingerprint_hash,
			    SSH_FP_DEFAULT)) == ଖାଲି)
				fatal_f("sshkey_fingerprint failed");
			ଯଦି (principal == ଖାଲି) {
				printf("Good \"%s\" signature with %s key %s\n",
				    sig_namespace, sshkey_type(sign_ଚାବି), fp);

			} ଅନ୍ୟଥା {
				printf("Good \"%s\" signature for %s with %s key %s\n",
				    sig_namespace, principal,
				    sshkey_type(sign_ଚାବି), fp);
			}
		} ଅନ୍ୟଥା {
			printf("Could not verify signature.\n");
		}
	}
	/* Print the signature key if requested */
	ଯଦି (ret == 0 && print_pubkey && sign_ଚାବି != ଖାଲି) {
		ଯଦି ((r = sshkey_write(sign_ଚାବି, stdout)) == 0)
			fputc('\n', stdout);
		ଅନ୍ୟଥା {
			error_r(r, "Could not print public key.\n");
			ret = -1;
		}
	}
	sshbuf_free(sigbuf);
	sshbuf_free(abuf);
	sshkey_free(sign_ଚାବି);
	sshkey_sig_details_free(sig_details);
	ମୁକ୍ତ(fp);
	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sig_find_principals(ଅଚଳ ଅକ୍ଷର *signature, ଅଚଳ ଅକ୍ଷର *allowed_ଚାବିଗୁଡ଼ିକ,
    ଅକ୍ଷର * ଅଚଳ *opts, size_t nopts)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, ret = -1;
	ସଂରଚନା sshbuf *sigbuf = ଖାଲି, *abuf = ଖାଲି;
	ସଂରଚନା sshkey *sign_ଚାବି = ଖାଲି;
	ଅକ୍ଷର *principals = ଖାଲି, *cp, *tmp;
	uint64_t verify_time = 0;

	ଯଦି (sig_process_opts(opts, nopts, ଖାଲି, &verify_time, ଖାଲି) != 0)
		ଯାଅ done; /* error already logged */

	ଯଦି ((r = sshbuf_load_file(signature, &abuf)) != 0) {
		error_r(r, "Couldn't read signature file");
		ଯାଅ done;
	}
	ଯଦି ((r = sshsig_dearmor(abuf, &sigbuf)) != 0) {
		error_fr(r, "sshsig_armor");
		ଯାଅ done;
	}
	ଯଦି ((r = sshsig_get_pubkey(sigbuf, &sign_ଚାବି)) != 0) {
		error_fr(r, "sshsig_get_pubkey");
		ଯାଅ done;
	}
	ଯଦି ((r = sshsig_find_principals(allowed_ଚାବିଗୁଡ଼ିକ, sign_ଚାବି,
	    verify_time, &principals)) != 0) {
		ଯଦି (r != SSH_ERR_ଚାବି_NOT_FOUND)
			error_fr(r, "sshsig_find_principal");
		ଯାଅ done;
	}
	ret = 0;
done:
	ଯଦି (ret == 0 ) {
		/* Emit matching principals one per line */
		tmp = principals;
		ଯେତେବେଳେ ((cp = strsep(&tmp, ",")) != ଖାଲି && *cp != '\0')
			puts(cp);
	} ଅନ୍ୟଥା {
		fprintf(stderr, "No principal matched.\n");
	}
	sshbuf_free(sigbuf);
	sshbuf_free(abuf);
	sshkey_free(sign_ଚାବି);
	ମୁକ୍ତ(principals);
	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sig_match_principals(ଅଚଳ ଅକ୍ଷର *allowed_ଚାବିଗୁଡ଼ିକ, ଅକ୍ଷର *principal,
	ଅକ୍ଷର * ଅଚଳ *opts, size_t nopts)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ଅକ୍ଷର **principals = ଖାଲି;
	size_t i, nprincipals = 0;

	ଯଦି ((r = sig_process_opts(opts, nopts, ଖାଲି, ଖାଲି, ଖାଲି)) != 0)
		ଫେରନ୍ତୁ r; /* error already logged */

	ଯଦି ((r = sshsig_match_principals(allowed_ଚାବିଗୁଡ଼ିକ, principal,
	    &principals, &nprincipals)) != 0) {
		debug_f("match: %s", ssh_err(r));
		fprintf(stderr, "No principal matched.\n");
		ଫେରନ୍ତୁ r;
	}
	ପାଇଁ (i = 0; i < nprincipals; i++) {
		printf("%s\n", principals[i]);
		ମୁକ୍ତ(principals[i]);
	}
	ମୁକ୍ତ(principals);

	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ଶୂନ୍ୟ
do_moduli_gen(ଅଚଳ ଅକ୍ଷର *out_file, ଅକ୍ଷର **opts, size_t nopts)
{
#ifdef WITH_OPENSSL
	/* Moduli generation/screening */
	BIGNUM *start = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା moduli_bits = 0;
	FILE *out;
	size_t i;
	ଅଚଳ ଅକ୍ଷର *errstr, *p;

	/* Parse options */
	ପାଇଁ (i = 0; i < nopts; i++) {
		ଯଦି ((p = strprefix(opts[i], "start=", 0)) != ଖାଲି) {
			/* XXX - also compare length against bits */
			ଯଦି (BN_hex2bn(&start, p) == 0)
				fatal("Invalid start point.");
		} ଅନ୍ୟଥା ଯଦି ((p = strprefix(opts[i], "bits=", 0)) != ଖାଲି) {
			moduli_bits = (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)strtonum(p, 1, INT_MAX, &errstr);
			ଯଦି (errstr) {
				fatal("Invalid number: %s (%s)", p, errstr);
			}
		} ଅନ୍ୟଥା {
			fatal("Option \"%s\" is unsupported for moduli "
			    "generation", opts[i]);
		}
	}

	ଯଦି (strcmp(out_file, "-") == 0)
		out = stdout;
	ଅନ୍ୟଥା ଯଦି ((out = fopen(out_file, "w")) == ଖାଲି) {
		fatal("Couldn't open modulus candidate file \"%s\": %s",
		    out_file, strerror(errno));
	}
	setvbuf(out, ଖାଲି, _IOLBF, 0);

	ଯଦି (moduli_bits == 0)
		moduli_bits = DEFAULT_BITS;
	ଯଦି (gen_candidates(out, moduli_bits, start) != 0)
		fatal("modulus candidate generation failed");
#ଅନ୍ୟଥା /* WITH_OPENSSL */
	fatal("Moduli generation is not supported");
#endif /* WITH_OPENSSL */
}

ସ୍ଥିର ଶୂନ୍ୟ
do_moduli_screen(ଅଚଳ ଅକ୍ଷର *out_file, ଅକ୍ଷର **opts, size_t nopts)
{
#ifdef WITH_OPENSSL
	/* Moduli generation/screening */
	ଅକ୍ଷର *checkpoint = ଖାଲି;
	uint32_t generator_wanted = 0;
	unsigned long start_lineno = 0, ଧାଡ଼ିଗୁଡ଼ିକ_to_process = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ମୌଳିକ_tests = 0;
	FILE *out, *in = stdin;
	size_t i;
	ଅଚଳ ଅକ୍ଷର *errstr, *p;

	/* Parse options */
	ପାଇଁ (i = 0; i < nopts; i++) {
		ଯଦି ((p = strprefix(opts[i], "lines=", 0)) != ଖାଲି) {
			ଧାଡ଼ିଗୁଡ଼ିକ_to_process = strtoul(p, ଖାଲି, 10);
		} ଅନ୍ୟଥା ଯଦି ((p = strprefix(opts[i], "start-line=", 0)) != ଖାଲି) {
			start_lineno = strtoul(p, ଖାଲି, 10);
		} ଅନ୍ୟଥା ଯଦି ((p = strprefix(opts[i], "checkpoint=", 0)) != ଖାଲି) {
			ମୁକ୍ତ(checkpoint);
			checkpoint = xstrdup(p);
		} ଅନ୍ୟଥା ଯଦି ((p = strprefix(opts[i], "generator=", 0)) != ଖାଲି) {
			generator_wanted = (uint32_t)strtonum(p, 1, UINT_MAX,
			    &errstr);
			ଯଦି (errstr != ଖାଲି) {
				fatal("Generator invalid: %s (%s)", p, errstr);
			}
		} ଅନ୍ୟଥା ଯଦି ((p = strprefix(opts[i], "prime-tests=", 0)) != ଖାଲି) {
			ମୌଳିକ_tests = (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)strtonum(p, 1, INT_MAX, &errstr);
			ଯଦି (errstr) {
				fatal("Invalid number: %s (%s)", p, errstr);
			}
		} ଅନ୍ୟଥା {
			fatal("Option \"%s\" is unsupported for moduli "
			    "screening", opts[i]);
		}
	}

	ଯଦି (have_identity && strcmp(identity_file, "-") != 0) {
		ଯଦି ((in = fopen(identity_file, "r")) == ଖାଲି) {
			fatal("Couldn't open modulus candidate "
			    "file \"%s\": %s", identity_file,
			    strerror(errno));
		}
	}

	ଯଦି (strcmp(out_file, "-") == 0)
		out = stdout;
	ଅନ୍ୟଥା ଯଦି ((out = fopen(out_file, "a")) == ଖାଲି) {
		fatal("Couldn't open moduli file \"%s\": %s",
		    out_file, strerror(errno));
	}
	setvbuf(out, ଖାଲି, _IOLBF, 0);
	ଯଦି (ମୌଳିକ_test(in, out, ମୌଳିକ_tests == 0 ? 100 : ମୌଳିକ_tests,
	    generator_wanted, checkpoint,
	    start_lineno, ଧାଡ଼ିଗୁଡ଼ିକ_to_process) != 0)
		fatal("modulus screening failed");
	ଯଦି (in != stdin)
		(ଶୂନ୍ୟ)fclose(in);
	ମୁକ୍ତ(checkpoint);
#ଅନ୍ୟଥା /* WITH_OPENSSL */
	fatal("Moduli screening is not supported");
#endif /* WITH_OPENSSL */
}

/* Read and confirm a passphrase */
ସ୍ଥିର ଅକ୍ଷର *
read_check_passphrase(ଅଚଳ ଅକ୍ଷର *prompt1, ଅଚଳ ଅକ୍ଷର *prompt2,
    ଅଚଳ ଅକ୍ଷର *retry_prompt)
{
	ଅକ୍ଷର *passphrase1, *passphrase2;

	ପାଇଁ (;;) {
		passphrase1 = read_passphrase(prompt1, RP_ALLOW_STDIN);
		passphrase2 = read_passphrase(prompt2, RP_ALLOW_STDIN);
		ଯଦି (strcmp(passphrase1, passphrase2) == 0) {
			freezero(passphrase2, strlen(passphrase2));
			ଫେରନ୍ତୁ passphrase1;
		}
		/* The passphrases do not match. Clear them and retry. */
		freezero(passphrase1, strlen(passphrase1));
		freezero(passphrase2, strlen(passphrase2));
		fputs(retry_prompt, stdout);
		fputc('\n', stdout);
		fflush(stdout);
	}
	/* NOTREACHED */
	ଫେରନ୍ତୁ ଖାଲି;
}

ସ୍ଥିର ଅକ୍ଷର *
private_ଚାବି_passphrase(ଅଚଳ ଅକ୍ଷର *path)
{
	ଅକ୍ଷର *prompt, *ret;

	ଯଦି (identity_passphrase)
		ଫେରନ୍ତୁ xstrdup(identity_passphrase);
	ଯଦି (identity_new_passphrase)
		ଫେରନ୍ତୁ xstrdup(identity_new_passphrase);

	xasprintf(&prompt, "Enter passphrase for \"%s\" "
	    "(empty for no passphrase): ", path);
	ret = read_check_passphrase(prompt,
	    "Enter same passphrase again: ",
	    "Passphrases do not match.  Try again.");
	ମୁକ୍ତ(prompt);
	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ଅକ୍ଷର *
sk_suffix(ଅଚଳ ଅକ୍ଷର *application, ଅଚଳ uint8_t *user, size_t userlen)
{
	ଅକ୍ଷର *ret, *cp;
	ଅଚଳ ଅକ୍ଷର *p;
	size_t slen, i;

	/* Trim off URL-like preamble */
	ଯଦି ((p = strprefix(application, "ssh://", 0)) != ଖାଲି)
		ret =  xstrdup(p);
	ଅନ୍ୟଥା ଯଦି ((p = strprefix(application, "ssh:", 0)) != ଖାଲି)
		ret =  xstrdup(p);
	ଅନ୍ୟଥା
		ret = xstrdup(application);

	/* Count trailing zeros in user */
	ପାଇଁ (i = 0; i < userlen; i++) {
		ଯଦି (user[userlen - i - 1] != 0)
			ଭାଙ୍ଗ;
	}
	ଯଦି (i >= userlen)
		ଫେରନ୍ତୁ ret; /* user-id was default all-zeros */

	/* Append user-id, escaping non-UTF-8 characters */
	slen = userlen - i;
	ଯଦି (asmprintf(&cp, INT_MAX, ଖାଲି, "%.*s", (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)slen, user) == -1)
		fatal_f("asmprintf failed");
	/* Don't emit a user-id that contains path or control characters */
	ଯଦି (strchr(cp, '/') != ଖାଲି || strstr(cp, "..") != ଖାଲି ||
	    strchr(cp, '\\') != ଖାଲି) {
		ମୁକ୍ତ(cp);
		cp = tohex(user, slen);
	}
	xextendf(&ret, "_", "%s", cp);
	ମୁକ୍ତ(cp);
	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
do_download_sk(ଅଚଳ ଅକ୍ଷର *skprovider, ଅଚଳ ଅକ୍ଷର *device)
{
	ସଂରଚନା sshsk_resident_ଚାବି **srks;
	size_t nsrks, i;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, ret = -1;
	ଅକ୍ଷର *fp, *pin = ଖାଲି, *pass = ଖାଲି, *path, *pubpath;
	ଅଚଳ ଅକ୍ଷର *ext;
	ସଂରଚନା sshkey *ଚାବି;

	ଯଦି (skprovider == ଖାଲି)
		fatal("Cannot download keys without provider");

	pin = read_passphrase("Enter PIN for authenticator: ", RP_ALLOW_STDIN);
	ଯଦି (!quiet) {
		printf("You may need to touch your authenticator "
		    "to authorize key download.\n");
	}
	ଯଦି ((r = sshsk_load_resident(skprovider, device, pin, 0,
	    &srks, &nsrks)) != 0) {
		ଯଦି (pin != ଖାଲି)
			freezero(pin, strlen(pin));
		error_r(r, "Unable to load resident keys");
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି (nsrks == 0)
		logit("No keys to download");
	ଯଦି (pin != ଖାଲି)
		freezero(pin, strlen(pin));

	ପାଇଁ (i = 0; i < nsrks; i++) {
		ଚାବି = srks[i]->ଚାବି;
		ଯଦି (ଚାବି->type != ଚାବି_ECDSA_SK && ଚାବି->type != ଚାବି_ED25519_SK) {
			error("Unsupported key type %s (%d)",
			    sshkey_type(ଚାବି), ଚାବି->type);
			ଜାରି;
		}
		ଯଦି ((fp = sshkey_fingerprint(ଚାବି, fingerprint_hash,
		    SSH_FP_DEFAULT)) == ଖାଲି)
			fatal_f("sshkey_fingerprint failed");
		debug_f("key %zu: %s %s %s (flags 0x%02x)", i,
		    sshkey_type(ଚାବି), fp, ଚାବି->sk_application, ଚାବି->sk_flags);
		ext = sk_suffix(ଚାବି->sk_application,
		    srks[i]->user_id, srks[i]->user_id_len);
		xasprintf(&path, "id_%s_rk%s%s",
		    ଚାବି->type == ଚାବି_ECDSA_SK ? "ecdsa_sk" : "ed25519_sk",
		    *ext == '\0' ? "" : "_", ext);

		/* If the file already exists, ask the user to confirm. */
		ଯଦି (!confirm_overwrite(path)) {
			ମୁକ୍ତ(path);
			ଭାଙ୍ଗ;
		}

		/* Save the key with the application string as the comment */
		ଯଦି (pass == ଖାଲି)
			pass = private_ଚାବି_passphrase(path);
		ଯଦି ((r = sshkey_save_private(ଚାବି, path, pass,
		    ଚାବି->sk_application, private_ଚାବି_format,
		    openssh_format_cipher, rounds)) != 0) {
			error_r(r, "Saving key \"%s\" failed", path);
			ମୁକ୍ତ(path);
			ଭାଙ୍ଗ;
		}
		ଯଦି (!quiet) {
			printf("Saved %s key%s%s to %s\n", sshkey_type(ଚାବି),
			    *ext != '\0' ? " " : "",
			    *ext != '\0' ? ଚାବି->sk_application : "",
			    path);
		}

		/* Save public key too */
		xasprintf(&pubpath, "%s.pub", path);
		ମୁକ୍ତ(path);
		ଯଦି ((r = sshkey_save_public(ଚାବି, pubpath,
		    ଚାବି->sk_application)) != 0) {
			error_r(r, "Saving public key \"%s\" failed", pubpath);
			ମୁକ୍ତ(pubpath);
			ଭାଙ୍ଗ;
		}
		ମୁକ୍ତ(pubpath);
	}

	ଯଦି (i >= nsrks)
		ret = 0; /* success */
	ଯଦି (pass != ଖାଲି)
		freezero(pass, strlen(pass));
	sshsk_free_resident_ଚାବିଗୁଡ଼ିକ(srks, nsrks);
	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ଶୂନ୍ୟ
save_attestation(ସଂରଚନା sshbuf *attest, ଅଚଳ ଅକ୍ଷର *path)
{
	mode_t omask;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (path == ଖାଲି)
		ଫେରନ୍ତୁ; /* nothing to do */
	ଯଦି (attest == ଖାଲି || sshbuf_len(attest) == 0)
		fatal("Enrollment did not return attestation data");
	omask = umask(077);
	r = sshbuf_write_file(path, attest);
	umask(omask);
	ଯଦି (r != 0)
		fatal_r(r, "Unable to write attestation data \"%s\"", path);
	ଯଦି (!quiet)
		printf("Your FIDO attestation certificate has been saved in "
		    "%s\n", path);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
confirm_sk_overwrite(ଅଚଳ ଅକ୍ଷର *application, ଅଚଳ ଅକ୍ଷର *user)
{
	ଅକ୍ଷର yesno[3];

	printf("A resident key scoped to '%s' with user id '%s' already "
	    "exists.\n", application == ଖାଲି ? "ssh:" : application,
	    user == ଖାଲି ? "null" : user);
	printf("Overwrite key in token (y/n)? ");
	fflush(stdout);
	ଯଦି (fgets(yesno, ଆକାର(yesno), stdin) == ଖାଲି)
		ଫେରନ୍ତୁ 0;
	ଯଦି (yesno[0] != 'y' && yesno[0] != 'Y')
		ଫେରନ୍ତୁ 0;
	ଫେରନ୍ତୁ 1;
}

ସ୍ଥିର ଶୂନ୍ୟ
usage(ଶୂନ୍ୟ)
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
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ମୁଖ୍ୟ(ପୂର୍ଣ୍ଣସଂଖ୍ୟା argc, ଅକ୍ଷର **argv)
{
	ଅକ୍ଷର comment[ଚାବି_COMMENT_MAX], *passphrase = ଖାଲି;
	ଅକ୍ଷର *rr_hostname = ଖାଲି, *ep, *fp, *ra;
	ସଂରଚନା sshkey *ବ୍ୟକ୍ତିଗତ = ଖାଲି, *ସର୍ବସାଧାରଣ = ଖାଲି;
	ସଂରଚନା passwd *pw;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = 0, r, opt, type;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା change_passphrase = 0, change_comment = 0, show_cert = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା find_host = 0, delete_host = 0, hash_hosts = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା gen_all_hostkeys = 0, gen_krl = 0, update_krl = 0, check_krl = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା prefer_agent = 0, convert_to = 0, convert_from = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା print_public = 0, print_generic = 0, cert_serial_autoinc = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା do_gen_candidates = 0, do_screen_candidates = 0, download_sk = 0;
	unsigned long long cert_serial = 0;
	ଅକ୍ଷର *identity_comment = ଖାଲି, *ca_ଚାବି_path = ଖାଲି, **opts = ଖାଲି;
	ଅକ୍ଷର *sk_application = ଖାଲି, *sk_device = ଖାଲି, *sk_user = ଖାଲି;
	ଅକ୍ଷର *sk_attestation_path = ଖାଲି;
	ସଂରଚନା sshbuf *challenge = ଖାଲି, *attest = ଖାଲି;
	size_t i, nopts = 0;
	uint32_t bits = 0;
	uint8_t sk_flags = SSH_SK_USER_PRESENCE_REQD;
	ଅଚଳ ଅକ୍ଷର *errstr, *p;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା log_level = SYSLOG_LEVEL_INFO;
	ଅକ୍ଷର *sign_op = ଖାଲି;

	ବାହ୍ୟ ପୂର୍ଣ୍ଣସଂଖ୍ୟା optind;
	ବାହ୍ୟ ଅକ୍ଷର *optarg;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	__progname = ssh_get_progname(argv[0]);

	seed_rng();

	log_init(argv[0], SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_USER, 1);

	msetlocale();

	/* we need this for the home * directory.  */
	pw = getpwuid(getuid());
	ଯଦି (!pw)
		fatal("No user exists for uid %lu", (u_long)getuid());
	pw = pwcopy(pw);
	ଯଦି (gethostname(hostname, ଆକାର(hostname)) == -1)
		fatal("gethostname: %s", strerror(errno));

	sk_provider = getenv("SSH_SK_PROVIDER");

	/* Remaining characters: dGjJSTWx */
	ଯେତେବେଳେ ((opt = getopt(argc, argv, "ABHKLQUXceghiklopquvy"
	    "C:D:E:F:I:M:N:O:P:R:V:Y:Z:"
	    "a:b:f:g:m:n:r:s:t:w:z:")) != -1) {
		ବାଛ (opt) {
		ସ୍ଥିତି 'A':
			gen_all_hostkeys = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'b':
			bits = (uint32_t)strtonum(optarg, 1, UINT32_MAX,
			    &errstr);
			ଯଦି (errstr)
				fatal("Bits has bad value %s (%s)",
					optarg, errstr);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			ଯଦି (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'F':
			find_host = 1;
			rr_hostname = optarg;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'H':
			hash_hosts = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'I':
			cert_ଚାବି_id = optarg;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'R':
			delete_host = 1;
			rr_hostname = optarg;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'L':
			show_cert = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'l':
			print_fingerprint = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'B':
			print_bubblebabble = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'm':
			ଯଦି (strcasecmp(optarg, "RFC4716") == 0 ||
			    strcasecmp(optarg, "ssh2") == 0) {
				convert_format = FMT_RFC4716;
				ଭାଙ୍ଗ;
			}
			ଯଦି (strcasecmp(optarg, "PKCS8") == 0) {
				convert_format = FMT_PKCS8;
				private_ଚାବି_format = SSHKEY_PRIVATE_PKCS8;
				ଭାଙ୍ଗ;
			}
			ଯଦି (strcasecmp(optarg, "PEM") == 0) {
				convert_format = FMT_PEM;
				private_ଚାବି_format = SSHKEY_PRIVATE_PEM;
				ଭାଙ୍ଗ;
			}
			ଯଦି (strcasecmp(optarg, "hexdump") == 0) {
				convert_format = FMT_HEXDUMP;
				ଭାଙ୍ଗ;
			}
			fatal("Unsupported conversion format \"%s\"", optarg);
		ସ୍ଥିତି 'n':
			cert_principals = optarg;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'o':
			/* no-op; new format is already the default */
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'p':
			change_passphrase = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'c':
			change_comment = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'f':
			ଯଦି (strlcpy(identity_file, optarg,
			    ଆକାର(identity_file)) >= ଆକାର(identity_file))
				fatal("Identity filename too long");
			have_identity = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'g':
			print_generic = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'K':
			download_sk = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'P':
			identity_passphrase = optarg;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'N':
			identity_new_passphrase = optarg;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'Q':
			check_krl = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'O':
			opts = xrecallocarray(opts, nopts, nopts + 1,
			    ଆକାର(*opts));
			opts[nopts++] = xstrdup(optarg);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'Z':
			openssh_format_cipher = optarg;
			ଯଦି (cipher_by_name(openssh_format_cipher) == ଖାଲି)
				fatal("Invalid OpenSSH-format cipher '%s'",
				    openssh_format_cipher);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'C':
			identity_comment = optarg;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'q':
			quiet = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'e':
			/* export key */
			convert_to = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'h':
			cert_ଚାବି_type = SSH2_CERT_TYPE_HOST;
			certflags_flags = 0;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'k':
			gen_krl = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'i':
		ସ୍ଥିତି 'X':
			/* import key */
			convert_from = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'y':
			print_public = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 's':
			ca_ଚାବି_path = optarg;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 't':
			ଚାବି_type_name = optarg;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'D':
			pkcs11provider = optarg;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'U':
			prefer_agent = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'u':
			update_krl = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'v':
			ଯଦି (log_level == SYSLOG_LEVEL_INFO)
				log_level = SYSLOG_LEVEL_DEBUG1;
			ଅନ୍ୟଥା {
				ଯଦି (log_level >= SYSLOG_LEVEL_DEBUG1 &&
				    log_level < SYSLOG_LEVEL_DEBUG3)
					log_level++;
			}
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'r':
			rr_hostname = optarg;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'a':
			rounds = (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)strtonum(optarg, 1, INT_MAX, &errstr);
			ଯଦି (errstr)
				fatal("Invalid number: %s (%s)",
					optarg, errstr);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'V':
			parse_cert_times(optarg);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'Y':
			sign_op = optarg;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'w':
			sk_provider = optarg;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'z':
			errno = 0;
			ଯଦି (*optarg == '+') {
				cert_serial_autoinc = 1;
				optarg++;
			}
			cert_serial = strtoull(optarg, &ep, 10);
			ଯଦି (*optarg < '0' || *optarg > '9' || *ep != '\0' ||
			    (errno == ERANGE && cert_serial == ULLONG_MAX))
				fatal("Invalid serial number \"%s\"", optarg);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'M':
			ଯଦି (strcmp(optarg, "generate") == 0)
				do_gen_candidates = 1;
			ଅନ୍ୟଥା ଯଦି (strcmp(optarg, "screen") == 0)
				do_screen_candidates = 1;
			ଅନ୍ୟଥା
				fatal("Unsupported moduli option %s", optarg);
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			usage();
		}
	}

#ifdef ENABLE_SK_INTERNAL
	ଯଦି (sk_provider == ଖାଲି)
		sk_provider = "internal";
#endif

	/* reinit */
	log_init(argv[0], log_level, SYSLOG_FACILITY_USER, 1);

	argv += optind;
	argc -= optind;

	ଯଦି (sign_op != ଖାଲି) {
		ଯଦି (strprefix(sign_op, "find-principals", 0) != ଖାଲି) {
			ଯଦି (ca_ଚାବି_path == ଖାଲି) {
				error("Too few arguments for find-principals:"
				    "missing signature file");
				exit(1);
			}
			ଯଦି (!have_identity) {
				error("Too few arguments for find-principals:"
				    "missing allowed keys file");
				exit(1);
			}
			ret = sig_find_principals(ca_ଚାବି_path, identity_file,
			    opts, nopts);
			ଯାଅ done;
		} ଅନ୍ୟଥା ଯଦି (strprefix(sign_op, "match-principals", 0) != ଖାଲି) {
			ଯଦି (!have_identity) {
				error("Too few arguments for match-principals:"
				    "missing allowed keys file");
				exit(1);
			}
			ଯଦି (cert_ଚାବି_id == ଖାଲି) {
				error("Too few arguments for match-principals: "
				    "missing principal ID");
				exit(1);
			}
			ret = sig_match_principals(identity_file, cert_ଚାବି_id,
			    opts, nopts);
			ଯାଅ done;
		} ଅନ୍ୟଥା ଯଦି (strprefix(sign_op, "sign", 0) != ଖାଲି) {
			/* NB. cert_principals is actually namespace, via -n */
			ଯଦି (cert_principals == ଖାଲି ||
			    *cert_principals == '\0') {
				error("Too few arguments for sign: "
				    "missing namespace");
				exit(1);
			}
			ଯଦି (!have_identity) {
				error("Too few arguments for sign: "
				    "missing key");
				exit(1);
			}
			ret = sig_sign(identity_file, cert_principals,
			    prefer_agent, argc, argv, opts, nopts);
			ଯାଅ done;
		} ଅନ୍ୟଥା ଯଦି (strprefix(sign_op, "check-novalidate", 0) != ଖାଲି) {
			/* NB. cert_principals is actually namespace, via -n */
			ଯଦି (cert_principals == ଖାଲି ||
			    *cert_principals == '\0') {
				error("Too few arguments for check-novalidate: "
				    "missing namespace");
				exit(1);
			}
			ଯଦି (ca_ଚାବି_path == ଖାଲି) {
				error("Too few arguments for check-novalidate: "
				    "missing signature file");
				exit(1);
			}
			ret = sig_verify(ca_ଚାବି_path, cert_principals,
			    ଖାଲି, ଖାଲି, ଖାଲି, opts, nopts);
			ଯାଅ done;
		} ଅନ୍ୟଥା ଯଦି (strprefix(sign_op, "verify", 0) != ଖାଲି) {
			/* NB. cert_principals is actually namespace, via -n */
			ଯଦି (cert_principals == ଖାଲି ||
			    *cert_principals == '\0') {
				error("Too few arguments for verify: "
				    "missing namespace");
				exit(1);
			}
			ଯଦି (ca_ଚାବି_path == ଖାଲି) {
				error("Too few arguments for verify: "
				    "missing signature file");
				exit(1);
			}
			ଯଦି (!have_identity) {
				error("Too few arguments for sign: "
				    "missing allowed keys file");
				exit(1);
			}
			ଯଦି (cert_ଚାବି_id == ଖାଲି) {
				error("Too few arguments for verify: "
				    "missing principal identity");
				exit(1);
			}
			ret = sig_verify(ca_ଚାବି_path, cert_principals,
			    cert_ଚାବି_id, identity_file, rr_hostname,
			    opts, nopts);
			ଯାଅ done;
		}
		error("Unsupported operation for -Y: \"%s\"", sign_op);
		usage();
		/* NOTREACHED */
	}

	ଯଦି (ca_ଚାବି_path != ଖାଲି) {
		ଯଦି (argc < 1 && !gen_krl) {
			error("Too few arguments.");
			usage();
		}
	} ଅନ୍ୟଥା ଯଦି (argc > 0 && !gen_krl && !check_krl &&
	    !do_gen_candidates && !do_screen_candidates) {
		error("Too many arguments.");
		usage();
	}
	ଯଦି (change_passphrase && change_comment) {
		error("Can only have one of -p and -c.");
		usage();
	}
	ଯଦି (print_fingerprint && (delete_host || hash_hosts)) {
		error("Cannot use -l with -H or -R.");
		usage();
	}
	ଯଦି (gen_krl) {
		do_gen_krl(pw, update_krl, ca_ଚାବି_path,
		    cert_serial, identity_comment, argc, argv);
		ଯାଅ done;
	}
	ଯଦି (check_krl) {
		do_check_krl(pw, print_fingerprint, argc, argv);
		ଯାଅ done;
	}
	ଯଦି (ca_ଚାବି_path != ଖାଲି) {
		ଯଦି (cert_ଚାବି_id == ଖାଲି)
			fatal("Must specify key id (-I) when certifying");
		ଯଦି (cert_principals == ଖାଲି) {
			/*
			 * Ideally this would be a fatal(), but we need to
			 * be able to generate such certificates for testing
			 * even though they will be rejected.
			 */
			error("Warning: certificate will contain no "
			    "principals (-n)");
		}
		ପାଇଁ (i = 0; i < nopts; i++)
			add_cert_option(opts[i]);
		do_ca_sign(pw, ca_ଚାବି_path, prefer_agent,
		    cert_serial, cert_serial_autoinc, argc, argv);
		ଯାଅ done;
	}
	ଯଦି (show_cert)
		do_show_cert(pw);
	ଯଦି (delete_host || hash_hosts || find_host) {
		do_known_hosts(pw, rr_hostname, find_host,
		    delete_host, hash_hosts);
	}
	ଯଦି (pkcs11provider != ଖାଲି)
		do_download(pw);
	ଯଦି (download_sk) {
		ପାଇଁ (i = 0; i < nopts; i++) {
			ଯଦି ((p = strprefix(opts[i], "device=", 1)) != ଖାଲି) {
				sk_device = xstrdup(p);
			} ଅନ୍ୟଥା {
				fatal("Option \"%s\" is unsupported for "
				    "FIDO authenticator download", opts[i]);
			}
		}
		ret = do_download_sk(sk_provider, sk_device);
		ଯାଅ done;
	}
	ଯଦି (print_fingerprint || print_bubblebabble)
		do_fingerprint(pw);
	ଯଦି (change_passphrase)
		do_change_passphrase(pw, opts, nopts);
	ଯଦି (change_comment)
		do_change_comment(pw, identity_comment);
#ifdef WITH_OPENSSL
	ଯଦି (convert_to) {
		do_convert_to(pw);
		ଯାଅ done;
	}
	ଯଦି (convert_from) {
		do_convert_from(pw);
		ଯାଅ done;
	}
#ଅନ୍ୟଥା /* WITH_OPENSSL */
	ଯଦି (convert_to || convert_from)
		fatal("key conversion disabled at compile time");
#endif /* WITH_OPENSSL */
	ଯଦି (print_public)
		do_print_public(pw);
	ଯଦି (rr_hostname != ଖାଲି) {
		unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା n = 0;

		ଯଦି (have_identity) {
			n = do_print_resource_record(pw, identity_file,
			    rr_hostname, print_generic, opts, nopts);
			ଯଦି (n == 0)
				fatal("%s: %s", identity_file, strerror(errno));
			exit(0);
		} ଅନ୍ୟଥା {

			n += do_print_resource_record(pw,
			    PATH_HOST_RSA_ଚାବି_FILE, rr_hostname,
			    print_generic, opts, nopts);
			n += do_print_resource_record(pw,
			    PATH_HOST_ECDSA_ଚାବି_FILE, rr_hostname,
			    print_generic, opts, nopts);
			n += do_print_resource_record(pw,
			    PATH_HOST_ED25519_ଚାବି_FILE, rr_hostname,
			    print_generic, opts, nopts);
			ଯଦି (n == 0)
				fatal("no keys found.");
			exit(0);
		}
	}

	ଯଦି (do_gen_candidates || do_screen_candidates) {
		ଯଦି (argc <= 0)
			fatal("No output file specified");
		ଅନ୍ୟଥା ଯଦି (argc > 1)
			fatal("Too many output files specified");
	}
	ଯଦି (do_gen_candidates) {
		do_moduli_gen(argv[0], opts, nopts);
		ଯାଅ done;
	}
	ଯଦି (do_screen_candidates) {
		do_moduli_screen(argv[0], opts, nopts);
		ଯାଅ done;
	}

	ଯଦି (gen_all_hostkeys) {
		do_gen_all_hostkeys(pw);
		ଯାଅ done;
	}

	ଯଦି (ଚାବି_type_name == ଖାଲି)
		ଚାବି_type_name = DEFAULT_ଚାବି_TYPE_NAME;

	type = sshkey_type_from_shortname(ଚାବି_type_name);
	type_bits_valid(type, ଚାବି_type_name, &bits);

	ଯଦି (!quiet)
		printf("Generating public/private %s key pair.\n",
		    ଚାବି_type_name);
	ବାଛ (type) {
	ସ୍ଥିତି ଚାବି_ECDSA_SK:
	ସ୍ଥିତି ଚାବି_ED25519_SK:
		ପାଇଁ (i = 0; i < nopts; i++) {
			ଯଦି (strcasecmp(opts[i], "no-touch-required") == 0) {
				sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
			} ଅନ୍ୟଥା ଯଦି (strcasecmp(opts[i], "verify-required") == 0) {
				sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
			} ଅନ୍ୟଥା ଯଦି (strcasecmp(opts[i], "resident") == 0) {
				sk_flags |= SSH_SK_RESIDENT_ଚାବି;
			} ଅନ୍ୟଥା ଯଦି ((p = strprefix(opts[i], "device=", 1))
			    != ଖାଲି ) {
				sk_device = xstrdup(p);
			} ଅନ୍ୟଥା ଯଦି ((p = strprefix(opts[i], "user=", 1))
			    != ଖାଲି) {
				sk_user = xstrdup(p);
			} ଅନ୍ୟଥା ଯଦି ((p = strprefix(opts[i], "challenge=", 1))
			    != ଖାଲି) {
				ଯଦି ((r = sshbuf_load_file(p,
				    &challenge)) != 0) {
					fatal_r(r, "Unable to load FIDO "
					    "enrollment challenge \"%s\"", p);
				}
			} ଅନ୍ୟଥା ଯଦି (strncasecmp(opts[i],
			    "write-attestation=", 18) == 0) {
				sk_attestation_path = opts[i] + 18;
			} ଅନ୍ୟଥା ଯଦି (strncasecmp(opts[i],
			    "application=", 12) == 0) {
				sk_application = xstrdup(opts[i] + 12);
				ଯଦି (strncmp(sk_application, "ssh:", 4) != 0) {
					fatal("FIDO application string must "
					    "begin with \"ssh:\"");
				}
			} ଅନ୍ୟଥା {
				fatal("Option \"%s\" is unsupported for "
				    "FIDO authenticator enrollment", opts[i]);
			}
		}
		ଯଦି ((attest = sshbuf_new()) == ଖାଲି)
			fatal("sshbuf_new failed");
		r = 0;
		ପାଇଁ (i = 0 ;;) {
			ଯଦି (!quiet) {
				printf("You may need to touch your "
				    "authenticator%s to authorize key "
				    "generation.\n",
				    r == 0 ? "" : " again");
			}
			fflush(stdout);
			r = sshsk_enroll(type, sk_provider, sk_device,
			    sk_application == ଖାଲି ? "ssh:" : sk_application,
			    sk_user, sk_flags, passphrase, challenge,
			    &ବ୍ୟକ୍ତିଗତ, attest);
			ଯଦି (r == 0)
				ଭାଙ୍ଗ;
			ଯଦି (r == SSH_ERR_ଚାବି_BAD_PERMISSIONS &&
			    (sk_flags & SSH_SK_RESIDENT_ଚାବି) != 0 &&
			    (sk_flags & SSH_SK_FORCE_OPERATION) == 0 &&
			    confirm_sk_overwrite(sk_application, sk_user)) {
				sk_flags |= SSH_SK_FORCE_OPERATION;
				ଜାରି;
			}
			ଯଦି (r != SSH_ERR_ଚାବି_WRONG_PASSPHRASE)
				fatal_r(r, "Key enrollment failed");
			ଅନ୍ୟଥା ଯଦି (passphrase != ଖାଲି) {
				error("PIN incorrect");
				freezero(passphrase, strlen(passphrase));
				passphrase = ଖାଲି;
			}
			ଯଦି (++i >= 3)
				fatal("Too many incorrect PINs");
			passphrase = read_passphrase("Enter PIN for "
			    "authenticator: ", RP_ALLOW_STDIN);
		}
		ଯଦି (passphrase != ଖାଲି) {
			freezero(passphrase, strlen(passphrase));
			passphrase = ଖାଲି;
		}
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଯଦି ((r = sshkey_generate(type, bits, &ବ୍ୟକ୍ତିଗତ)) != 0)
			fatal("sshkey_generate failed");
		ଭାଙ୍ଗ;
	}
	ଯଦି ((r = sshkey_from_private(ବ୍ୟକ୍ତିଗତ, &ସର୍ବସାଧାରଣ)) != 0)
		fatal_r(r, "sshkey_from_private");

	ଯଦି (!have_identity)
		ask_filename(pw, "Enter file in which to save the key");

	/* Create ~/.ssh directory if it doesn't already exist. */
	hostfile_create_user_ssh_dir(identity_file, !quiet);

	/* If the file already exists, ask the user to confirm. */
	ଯଦି (!confirm_overwrite(identity_file))
		exit(1);

	/* Determine the passphrase for the private key */
	passphrase = private_ଚାବି_passphrase(identity_file);
	ଯଦି (identity_comment) {
		strlcpy(comment, identity_comment, ଆକାର(comment));
	} ଅନ୍ୟଥା {
		/* Create default comment field for the passphrase. */
		snprintf(comment, ଆକାର comment, "%s@%s", pw->pw_name, hostname);
	}



	/* Save the key with the given passphrase and comment. */
	ଯଦି ((r = sshkey_save_private(ବ୍ୟକ୍ତିଗତ, identity_file, passphrase,
	    comment, private_ଚାବି_format, openssh_format_cipher, rounds)) != 0) {
		error_r(r, "Saving key \"%s\" failed", identity_file);
		freezero(passphrase, strlen(passphrase));
		exit(1);
	}
	freezero(passphrase, strlen(passphrase));
	sshkey_free(ବ୍ୟକ୍ତିଗତ);

	ଯଦି (!quiet) {
		printf("Your identification has been saved in %s\n",
		    identity_file);
	}

	strlcat(identity_file, ".pub", ଆକାର(identity_file));
	ଯଦି ((r = sshkey_save_public(ସର୍ବସାଧାରଣ, identity_file, comment)) != 0)
		fatal_r(r, "Unable to save public key to %s", identity_file);

	ଯଦି (!quiet) {
		fp = sshkey_fingerprint(ସର୍ବସାଧାରଣ, fingerprint_hash,
		    SSH_FP_DEFAULT);
		ra = sshkey_fingerprint(ସର୍ବସାଧାରଣ, fingerprint_hash,
		    SSH_FP_RANDOMART);
		ଯଦି (fp == ଖାଲି || ra == ଖାଲି)
			fatal("sshkey_fingerprint failed");
		printf("Your public key has been saved in %s\n",
		    identity_file);
		printf("The key fingerprint is:\n");
		printf("%s %s\n", fp, comment);
		printf("The key's randomart image is:\n");
		printf("%s\n", ra);
		ମୁକ୍ତ(ra);
		ମୁକ୍ତ(fp);
	}

	ଯଦି (sk_attestation_path != ଖାଲି)
		save_attestation(attest, sk_attestation_path);

 done:
	sshbuf_free(attest);
	sshkey_free(ସର୍ବସାଧାରଣ);
	pwfree(pw);
	exit(ret);
}
