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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/socket.h>
#અન્તર્ભાવ <sys/stat.h>

#ifdef WITH_OPENSSL
#અન્તર્ભાવ "openbsd-compat/openssl-compat.h"
#અન્તર્ભાવ <openssl/bn.h>
#અન્તર્ભાવ <openssl/evp.h>
#અન્તર્ભાવ <openssl/pem.h>
#endif

#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <fcntl.h>
#અન્તર્ભાવ <netdb.h>
#અન્તર્ભાવ <paths.h>
#અન્તર્ભાવ <pwd.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <limits.h>
#અન્તર્ભાવ <locale.h>
#અન્તર્ભાવ <time.h>

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "authfile.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "pathnames.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "match.h"
#અન્તર્ભાવ "hostfile.h"
#અન્તર્ભાવ "dns.h"
#અન્તર્ભાવ "ssh.h"
#અન્તર્ભાવ "ssh2.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "atomicio.h"
#અન્તર્ભાવ "krl.h"
#અન્તર્ભાવ "digest.h"
#અન્તર્ભાવ "utf8.h"
#અન્તર્ભાવ "authfd.h"
#અન્તર્ભાવ "sshsig.h"
#અન્તર્ભાવ "ssh-sk.h"
#અન્તર્ભાવ "sk-api.h" /* XXX for SSH_SK_USER_PRESENCE_REQD; remove */
#અન્તર્ભાવ "cipher.h"

#ifdef ENABLE_PKCS11
#અન્તર્ભાવ "ssh-pkcs11.h"
#endif

#define DEFAULT_ચાવી_TYPE_NAME "ed25519"

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

#define ચાવી_COMMENT_MAX		(NI_MAXHOST + 1024)

સ્થિર પૂર્ણાંક quiet = 0;

/* Flag indicating that we just want to see the key fingerprint */
સ્થિર પૂર્ણાંક print_fingerprint = 0;
સ્થિર પૂર્ણાંક print_bubblebabble = 0;

/* Hash algorithm to use for fingerprints. */
સ્થિર પૂર્ણાંક fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* The identity file name, given on the command line or entered by the user. */
સ્થિર અક્ષર identity_file[PATH_MAX];
સ્થિર પૂર્ણાંક have_identity = 0;

/* This is set to the passphrase if given on the command line. */
સ્થિર અક્ષર *identity_passphrase = ખાલી;

/* This is set to the new passphrase if given on the command line. */
સ્થિર અક્ષર *identity_new_passphrase = ખાલી;

/* Key type when certifying */
સ્થિર u_int cert_ચાવી_type = SSH2_CERT_TYPE_USER;

/* "key ID" of signed key */
સ્થિર અક્ષર *cert_ચાવી_id = ખાલી;

/* Comma-separated list of principal names for certifying keys */
સ્થિર અક્ષર *cert_principals = ખાલી;

/* Validity period for certificates */
સ્થિર uint64_t cert_valid_from = 0;
સ્થિર uint64_t cert_valid_to = ~0ULL;

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
સ્થિર uint32_t certflags_flags = CERTOPT_DEFAULT;
સ્થિર અક્ષર *certflags_command = ખાલી;
સ્થિર અક્ષર *certflags_src_addr = ખાલી;

/* Arbitrary extensions specified by user */
સંરચના cert_ext {
	અક્ષર *ચાવી;
	અક્ષર *val;
	પૂર્ણાંક crit;
};
સ્થિર સંરચના cert_ext *cert_ext;
સ્થિર size_t ncert_ext;

/* Conversion to/from various formats */
ગણના {
	FMT_RFC4716,
	FMT_PKCS8,
	FMT_PEM,
	FMT_HEXDUMP
} convert_format = FMT_RFC4716;

સ્થિર અક્ષર *ચાવી_type_name = ખાલી;

/* Load key from this PKCS#11 provider */
સ્થિર અક્ષર *pkcs11provider = ખાલી;

/* FIDO/U2F provider to use */
સ્થિર અક્ષર *sk_provider = ખાલી;

/* Format for writing private keys */
સ્થિર પૂર્ણાંક private_ચાવી_format = SSHKEY_PRIVATE_OPENSSH;

/* Cipher for new-format private keys */
સ્થિર અક્ષર *openssh_format_cipher = ખાલી;

/* Number of KDF rounds to derive new format keys. */
સ્થિર પૂર્ણાંક rounds = 0;

/* argv0 */
બાહ્ય અક્ષર *__progname;

સ્થિર અક્ષર hostname[NI_MAXHOST];

#ifdef WITH_OPENSSL
/* moduli.c */
પૂર્ણાંક gen_candidates(FILE *, uint32_t, BIGNUM *);
પૂર્ણાંક અવિભાજ્ય_test(FILE *, FILE *, uint32_t, uint32_t, અક્ષર *, unsigned long,
    unsigned long);
#endif

સ્થિર શૂન્ય
type_bits_valid(પૂર્ણાંક type, અચલ અક્ષર *name, uint32_t *bitsp)
{
	જો (type == ચાવી_UNSPEC)
		fatal("unknown key type %s", ચાવી_type_name);
	જો (*bitsp == 0) {
#ifdef WITH_OPENSSL
		પૂર્ણાંક nid;

		પસંદગી(type) {
		સ્થિતિ ચાવી_ECDSA:
			જો (name != ખાલી &&
			    (nid = sshkey_ecdsa_nid_from_name(name)) > 0)
				*bitsp = sshkey_curve_nid_to_bits(nid);
			જો (*bitsp == 0)
				*bitsp = DEFAULT_BITS_ECDSA;
			તોડો;
		સ્થિતિ ચાવી_RSA:
			*bitsp = DEFAULT_BITS;
			તોડો;
		}
#endif
	}
#ifdef WITH_OPENSSL
	પસંદગી (type) {
	સ્થિતિ ચાવી_RSA:
		જો (*bitsp < SSH_RSA_MINIMUM_MODULUS_SIZE)
			fatal("Invalid RSA key length: minimum is %d bits",
			    SSH_RSA_MINIMUM_MODULUS_SIZE);
		નહીંતર જો (*bitsp > OPENSSL_RSA_MAX_MODULUS_BITS)
			fatal("Invalid RSA key length: maximum is %d bits",
			    OPENSSL_RSA_MAX_MODULUS_BITS);
		તોડો;
	સ્થિતિ ચાવી_ECDSA:
		જો (sshkey_ecdsa_bits_to_nid(*bitsp) == -1)
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
સ્થિર પૂર્ણાંક
confirm_overwrite(અચલ અક્ષર *filename)
{
	અક્ષર yesno[3];
	સંરચના stat st;

	જો (stat(filename, &st) != 0)
		પાછા 1;
	printf("%s already exists.\n", filename);
	printf("Overwrite (y/n)? ");
	fflush(stdout);
	જો (fgets(yesno, કદ(yesno), stdin) == ખાલી)
		પાછા 0;
	જો (yesno[0] != 'y' && yesno[0] != 'Y')
		પાછા 0;
	પાછા 1;
}

સ્થિર શૂન્ય
ask_filename(સંરચના passwd *pw, અચલ અક્ષર *prompt)
{
	અક્ષર buf[1024];
	અક્ષર *name = ખાલી;

	જો (ચાવી_type_name == ખાલી)
		name = _PATH_SSH_CLIENT_ID_ED25519;
	નહીંતર {
		પસંદગી (sshkey_type_from_shortname(ચાવી_type_name)) {
		સ્થિતિ ચાવી_ECDSA_CERT:
		સ્થિતિ ચાવી_ECDSA:
			name = _PATH_SSH_CLIENT_ID_ECDSA;
			તોડો;
		સ્થિતિ ચાવી_ECDSA_SK_CERT:
		સ્થિતિ ચાવી_ECDSA_SK:
			name = _PATH_SSH_CLIENT_ID_ECDSA_SK;
			તોડો;
		સ્થિતિ ચાવી_RSA_CERT:
		સ્થિતિ ચાવી_RSA:
			name = _PATH_SSH_CLIENT_ID_RSA;
			તોડો;
		સ્થિતિ ચાવી_ED25519:
		સ્થિતિ ચાવી_ED25519_CERT:
			name = _PATH_SSH_CLIENT_ID_ED25519;
			તોડો;
		સ્થિતિ ચાવી_ED25519_SK:
		સ્થિતિ ચાવી_ED25519_SK_CERT:
			name = _PATH_SSH_CLIENT_ID_ED25519_SK;
			તોડો;
		સ્થિતિ ચાવી_MLDSA44_ED25519:
		સ્થિતિ ચાવી_MLDSA44_ED25519_CERT:
			name = _PATH_SSH_CLIENT_ID_MLDSA44_ED25519;
			તોડો;
		મૂળભૂત:
			fatal("bad key type");
		}
	}
	snprintf(identity_file, કદ(identity_file),
	    "%s/%s", pw->pw_dir, name);
	printf("%s (%s): ", prompt, identity_file);
	fflush(stdout);
	જો (fgets(buf, કદ(buf), stdin) == ખાલી)
		exit(1);
	buf[strcspn(buf, "\n")] = '\0';
	જો (strcmp(buf, "") != 0)
		strlcpy(identity_file, buf, કદ(identity_file));
	have_identity = 1;
}

સ્થિર સંરચના sshkey *
load_identity(અચલ અક્ષર *filename, અક્ષર **commentp)
{
	અક્ષર *prompt, *pass;
	સંરચના sshkey *prv;
	પૂર્ણાંક r;

	જો (commentp != ખાલી)
		*commentp = ખાલી;
	જો ((r = sshkey_load_private(filename, "", &prv, commentp)) == 0)
		પાછા prv;
	જો (r != SSH_ERR_ચાવી_WRONG_PASSPHRASE)
		fatal_r(r, "Load key \"%s\"", filename);
	જો (identity_passphrase)
		pass = xstrdup(identity_passphrase);
	નહીંતર {
		xasprintf(&prompt, "Enter passphrase for \"%s\": ", filename);
		pass = read_passphrase(prompt, RP_ALLOW_STDIN);
		મુક્ત(prompt);
	}
	r = sshkey_load_private(filename, pass, &prv, commentp);
	freezero(pass, strlen(pass));
	જો (r != 0)
		fatal_r(r, "Load key \"%s\"", filename);
	પાછા prv;
}

#define SSH_COM_PUBLIC_BEGIN		"---- BEGIN SSH2 PUBLIC KEY ----"
#define SSH_COM_PUBLIC_END		"---- END SSH2 PUBLIC KEY ----"
#define SSH_COM_PRIVATE_BEGIN		"---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----"
#define	SSH_COM_PRIVATE_ચાવી_MAGIC	0x3f6ff9eb

#ifdef WITH_OPENSSL
સ્થિર શૂન્ય
do_convert_to_ssh2(સંરચના passwd *pw, સંરચના sshkey *k)
{
	સંરચના sshbuf *b;
	અક્ષર comment[61], *b64;
	પૂર્ણાંક r;

	જો ((b = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = sshkey_putb(k, b)) != 0)
		fatal_fr(r, "put key");
	જો ((b64 = sshbuf_dtob64_string(b, 1)) == ખાલી)
		fatal_f("sshbuf_dtob64_string failed");

	/* Comment + surrounds must fit into 72 chars (RFC 4716 sec 3.3) */
	snprintf(comment, કદ(comment),
	    "%u-bit %s, converted by %s@%s from OpenSSH",
	    sshkey_size(k), sshkey_type(k),
	    pw->pw_name, hostname);

	sshkey_free(k);
	sshbuf_free(b);

	fprintf(stdout, "%s\n", SSH_COM_PUBLIC_BEGIN);
	fprintf(stdout, "Comment: \"%s\"\n%s", comment, b64);
	fprintf(stdout, "%s\n", SSH_COM_PUBLIC_END);
	મુક્ત(b64);
}

સ્થિર શૂન્ય
do_convert_to_pkcs8(સંરચના sshkey *k)
{
	પસંદગી (sshkey_type_plain(k->type)) {
	સ્થિતિ ચાવી_RSA:
		જો (!PEM_write_RSA_PUBKEY(stdout,
		    EVP_PKEY_get0_RSA(k->pkey)))
			fatal("PEM_write_RSA_PUBKEY failed");
		તોડો;
	સ્થિતિ ચાવી_ECDSA:
		જો (!PEM_write_EC_PUBKEY(stdout,
		    EVP_PKEY_get0_EC_ચાવી(k->pkey)))
			fatal("PEM_write_EC_PUBKEY failed");
		તોડો;
	મૂળભૂત:
		fatal_f("unsupported key type %s", sshkey_type(k));
	}
}

સ્થિર શૂન્ય
do_convert_to_pem(સંરચના sshkey *k)
{
	પસંદગી (sshkey_type_plain(k->type)) {
	સ્થિતિ ચાવી_RSA:
		જો (!PEM_write_RSAPublic_ચાવી(stdout,
		    EVP_PKEY_get0_RSA(k->pkey)))
			fatal("PEM_write_RSAPublicKey failed");
		તોડો;
	સ્થિતિ ચાવી_ECDSA:
		જો (!PEM_write_EC_PUBKEY(stdout,
		    EVP_PKEY_get0_EC_ચાવી(k->pkey)))
			fatal("PEM_write_EC_PUBKEY failed");
		તોડો;
	મૂળભૂત:
		fatal_f("unsupported key type %s", sshkey_type(k));
	}
}

સ્થિર શૂન્ય
do_convert_to_hexdump(સંરચના sshkey *k)
{
	સંરચના sshbuf *b;
	પૂર્ણાંક r;

	જો ((b = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	/* pubkey */
	જો ((r = sshkey_putb(k, b)) != 0)
		fatal_fr(r, "serialise private");
	printf("Public %s key:\n", sshkey_type(k));
	sshbuf_dump(b, stdout);
	sshbuf_reset(b);
	જો ((r = sshkey_private_serialize(k, b)) != 0) {
		debug_fr(r, "serialise private");
		જાઓ out;
	}
	printf("\nPrivate %s key:\n", sshkey_type(k));
	sshbuf_dump(b, stdout);
 out:
	sshbuf_free(b);
}

સ્થિર શૂન્ય
do_convert_to(સંરચના passwd *pw)
{
	સંરચના sshkey *k = ખાલી;
	સંરચના stat st;
	પૂર્ણાંક r;

	જો (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	જો (stat(identity_file, &st) == -1)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));

	/* If we're trying to hexdump, then prefer the private key */
	જો (convert_format == FMT_HEXDUMP) {
		જો ((r = sshkey_load_private(identity_file,
		    ખાલી, &k, ખાલી)) != 0 &&
		    r == SSH_ERR_ચાવી_WRONG_PASSPHRASE)
			k = load_identity(identity_file, ખાલી);
	}
	જો (k == ખાલી && (r = sshkey_load_public(identity_file, &k, ખાલી)) != 0)
		k = load_identity(identity_file, ખાલી);

	પસંદગી (convert_format) {
	સ્થિતિ FMT_RFC4716:
		do_convert_to_ssh2(pw, k);
		તોડો;
	સ્થિતિ FMT_PKCS8:
		do_convert_to_pkcs8(k);
		તોડો;
	સ્થિતિ FMT_PEM:
		do_convert_to_pem(k);
		તોડો;
	સ્થિતિ FMT_HEXDUMP:
		do_convert_to_hexdump(k);
		તોડો;
	મૂળભૂત:
		fatal_f("unknown key format %d", convert_format);
	}
}

/*
 * This is almost exactly the bignum1 encoding, but with 32 bit for length
 * instead of 16.
 */
સ્થિર શૂન્ય
buffer_get_bignum_bits(સંરચના sshbuf *b, BIGNUM *કિંમત)
{
	u_int bytes, bignum_bits;
	પૂર્ણાંક r;

	જો ((r = sshbuf_get_u32(b, &bignum_bits)) != 0)
		fatal_fr(r, "parse");
	bytes = (bignum_bits + 7) / 8;
	જો (sshbuf_len(b) < bytes)
		fatal_f("input buffer too small: need %d have %zu",
		    bytes, sshbuf_len(b));
	જો (BN_bin2bn(sshbuf_ptr(b), bytes, કિંમત) == ખાલી)
		fatal_f("BN_bin2bn failed");
	જો ((r = sshbuf_consume(b, bytes)) != 0)
		fatal_fr(r, "consume");
}

સ્થિર સંરચના sshkey *
do_convert_private_ssh2(સંરચના sshbuf *b)
{
	સંરચના sshkey *ચાવી = ખાલી;
	અક્ષર *type, *cipher;
	અચલ અક્ષર *alg = ખાલી;
	u_char e1, e2, e3, *sig = ખાલી, data[] = "abcde12345";
	પૂર્ણાંક r, rlen, ktype;
	u_int magic, i1, i2, i3, i4;
	size_t slen;
	u_long e;
	BIGNUM *rsa_n = ખાલી, *rsa_e = ખાલી, *rsa_d = ખાલી;
	BIGNUM *rsa_p = ખાલી, *rsa_q = ખાલી, *rsa_iqmp = ખાલી;
	BIGNUM *rsa_dmp1 = ખાલી, *rsa_dmq1 = ખાલી;
	RSA *rsa = ખાલી;

	જો ((r = sshbuf_get_u32(b, &magic)) != 0)
		fatal_fr(r, "parse magic");

	જો (magic != SSH_COM_PRIVATE_ચાવી_MAGIC) {
		error("bad magic 0x%x != 0x%x", magic,
		    SSH_COM_PRIVATE_ચાવી_MAGIC);
		પાછા ખાલી;
	}
	જો ((r = sshbuf_get_u32(b, &i1)) != 0 ||
	    (r = sshbuf_get_cstring(b, &type, ખાલી)) != 0 ||
	    (r = sshbuf_get_cstring(b, &cipher, ખાલી)) != 0 ||
	    (r = sshbuf_get_u32(b, &i2)) != 0 ||
	    (r = sshbuf_get_u32(b, &i3)) != 0 ||
	    (r = sshbuf_get_u32(b, &i4)) != 0)
		fatal_fr(r, "parse");
	debug("ignore (%d %d %d %d)", i1, i2, i3, i4);
	જો (strcmp(cipher, "none") != 0) {
		error("unsupported cipher %s", cipher);
		મુક્ત(cipher);
		મુક્ત(type);
		પાછા ખાલી;
	}
	મુક્ત(cipher);

	જો (strstr(type, "rsa")) {
		ktype = ચાવી_RSA;
	} નહીંતર {
		મુક્ત(type);
		પાછા ખાલી;
	}
	જો ((ચાવી = sshkey_new(ktype)) == ખાલી)
		fatal("sshkey_new failed");
	મુક્ત(type);

	પસંદગી (ચાવી->type) {
	સ્થિતિ ચાવી_RSA:
		જો ((r = sshbuf_get_u8(b, &e1)) != 0 ||
		    (e1 < 30 && (r = sshbuf_get_u8(b, &e2)) != 0) ||
		    (e1 < 30 && (r = sshbuf_get_u8(b, &e3)) != 0))
			fatal_fr(r, "parse RSA");
		e = e1;
		debug("e %lx", e);
		જો (e < 30) {
			e <<= 8;
			e += e2;
			debug("e %lx", e);
			e <<= 8;
			e += e3;
			debug("e %lx", e);
		}
		જો ((rsa_e = BN_new()) == ખાલી)
			fatal_f("BN_new");
		જો (!BN_set_word(rsa_e, e)) {
			BN_clear_free(rsa_e);
			sshkey_free(ચાવી);
			પાછા ખાલી;
		}
		જો ((rsa_n = BN_new()) == ખાલી ||
		    (rsa_d = BN_new()) == ખાલી ||
		    (rsa_p = BN_new()) == ખાલી ||
		    (rsa_q = BN_new()) == ખાલી ||
		    (rsa_iqmp = BN_new()) == ખાલી)
			fatal_f("BN_new");
		buffer_get_bignum_bits(b, rsa_d);
		buffer_get_bignum_bits(b, rsa_n);
		buffer_get_bignum_bits(b, rsa_iqmp);
		buffer_get_bignum_bits(b, rsa_q);
		buffer_get_bignum_bits(b, rsa_p);
		જો ((r = ssh_rsa_complete_crt_parameters(rsa_d, rsa_p, rsa_q,
		    rsa_iqmp, &rsa_dmp1, &rsa_dmq1)) != 0)
			fatal_fr(r, "generate RSA CRT parameters");
		EVP_PKEY_free(ચાવી->pkey);
		જો ((ચાવી->pkey = EVP_PKEY_new()) == ખાલી)
			fatal_f("EVP_PKEY_new failed");
		જો ((rsa = RSA_new()) == ખાલી)
			fatal_f("RSA_new failed");
		જો (!RSA_set0_ચાવી(rsa, rsa_n, rsa_e, rsa_d))
			fatal_f("RSA_set0_key failed");
		rsa_n = rsa_e = rsa_d = ખાલી; /* transferred */
		જો (!RSA_set0_factors(rsa, rsa_p, rsa_q))
			fatal_f("RSA_set0_factors failed");
		rsa_p = rsa_q = ખાલી; /* transferred */
		જો (RSA_set0_crt_params(rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp) != 1)
			fatal_f("RSA_set0_crt_params failed");
		rsa_dmp1 = rsa_dmq1 = rsa_iqmp = ખાલી;
		જો (EVP_PKEY_set1_RSA(ચાવી->pkey, rsa) != 1)
			fatal_f("EVP_PKEY_set1_RSA failed");
		RSA_free(rsa);
		alg = "rsa-sha2-256";
		તોડો;
	}
	rlen = sshbuf_len(b);
	જો (rlen != 0)
		error_f("remaining bytes in key blob %d", rlen);

	/* try the key */
	જો ((r = sshkey_sign(ચાવી, &sig, &slen, data, કદ(data),
	    alg, ખાલી, ખાલી, 0)) != 0)
		error_fr(r, "signing with converted key failed");
	નહીંતર જો ((r = sshkey_verify(ચાવી, sig, slen, data, કદ(data),
	    alg, 0, ખાલી)) != 0)
		error_fr(r, "verification with converted key failed");
	જો (r != 0) {
		sshkey_free(ચાવી);
		મુક્ત(sig);
		પાછા ખાલી;
	}
	મુક્ત(sig);
	પાછા ચાવી;
}

સ્થિર પૂર્ણાંક
get_લીટી(FILE *fp, અક્ષર *લીટી, size_t len)
{
	પૂર્ણાંક c;
	size_t pos = 0;

	લીટી[0] = '\0';
	જ્યારે ((c = fgetc(fp)) != EOF) {
		જો (pos >= len - 1)
			fatal("input line too long.");
		પસંદગી (c) {
		સ્થિતિ '\r':
			c = fgetc(fp);
			જો (c != EOF && c != '\n' && ungetc(c, fp) == EOF)
				fatal("unget: %s", strerror(errno));
			પાછા pos;
		સ્થિતિ '\n':
			પાછા pos;
		}
		લીટી[pos++] = c;
		લીટી[pos] = '\0';
	}
	/* We reached EOF */
	પાછા -1;
}

સ્થિર શૂન્ય
do_convert_from_ssh2(સંરચના passwd *pw, સંરચના sshkey **k, પૂર્ણાંક *ખાનગી)
{
	પૂર્ણાંક r, blen, escaped = 0;
	u_int len;
	અક્ષર લીટી[1024];
	સંરચના sshbuf *buf;
	અક્ષર encoded[8096];
	FILE *fp;

	જો ((buf = sshbuf_new()) == ખાલી)
		fatal("sshbuf_new failed");
	જો ((fp = fopen(identity_file, "r")) == ખાલી)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));
	encoded[0] = '\0';
	જ્યારે ((blen = get_લીટી(fp, લીટી, કદ(લીટી))) != -1) {
		જો (blen > 0 && લીટી[blen - 1] == '\\')
			escaped++;
		જો (strncmp(લીટી, "----", 4) == 0 ||
		    strstr(લીટી, ": ") != ખાલી) {
			જો (strstr(લીટી, SSH_COM_PRIVATE_BEGIN) != ખાલી)
				*ખાનગી = 1;
			જો (strstr(લીટી, " END ") != ખાલી) {
				તોડો;
			}
			/* fprintf(stderr, "ignore: %s", line); */
			ચાલુ;
		}
		જો (escaped) {
			escaped--;
			/* fprintf(stderr, "escaped: %s", line); */
			ચાલુ;
		}
		strlcat(encoded, લીટી, કદ(encoded));
	}
	len = strlen(encoded);
	જો (((len % 4) == 3) &&
	    (encoded[len-1] == '=') &&
	    (encoded[len-2] == '=') &&
	    (encoded[len-3] == '='))
		encoded[len-3] = '\0';
	જો ((r = sshbuf_b64tod(buf, encoded)) != 0)
		fatal_fr(r, "base64 decode");
	જો (*ખાનગી) {
		જો ((*k = do_convert_private_ssh2(buf)) == ખાલી)
			fatal_f("private key conversion failed");
	} નહીંતર જો ((r = sshkey_fromb(buf, k)) != 0)
		fatal_fr(r, "parse key");
	sshbuf_free(buf);
	fclose(fp);
}

સ્થિર શૂન્ય
do_convert_from_pkcs8(સંરચના sshkey **k, પૂર્ણાંક *ખાનગી)
{
	EVP_PKEY *pubkey;
	FILE *fp;

	જો ((fp = fopen(identity_file, "r")) == ખાલી)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));
	જો ((pubkey = PEM_read_PUBKEY(fp, ખાલી, ખાલી, ખાલી)) == ખાલી) {
		fatal_f("%s is not a recognised public key format",
		    identity_file);
	}
	fclose(fp);
	પસંદગી (EVP_PKEY_base_id(pubkey)) {
	સ્થિતિ EVP_PKEY_RSA:
		જો ((*k = sshkey_new(ચાવી_UNSPEC)) == ખાલી)
			fatal("sshkey_new failed");
		(*k)->type = ચાવી_RSA;
		(*k)->pkey = pubkey;
		pubkey = ખાલી;
		તોડો;
	સ્થિતિ EVP_PKEY_EC:
		જો ((*k = sshkey_new(ચાવી_UNSPEC)) == ખાલી)
			fatal("sshkey_new failed");
		જો (((*k)->ecdsa_nid = sshkey_ecdsa_fixup_group(pubkey)) == -1)
			fatal("sshkey_ecdsa_fixup_group failed");
		(*k)->type = ચાવી_ECDSA;
		(*k)->pkey = pubkey;
		pubkey = ખાલી;
		તોડો;
	મૂળભૂત:
		fatal_f("unsupported pubkey type %d",
		    EVP_PKEY_base_id(pubkey));
	}
	EVP_PKEY_free(pubkey);
}

સ્થિર શૂન્ય
do_convert_from_pem(સંરચના sshkey **k, પૂર્ણાંક *ખાનગી)
{
	FILE *fp;
	RSA *rsa;

	જો ((fp = fopen(identity_file, "r")) == ખાલી)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));
	જો ((rsa = PEM_read_RSAPublic_ચાવી(fp, ખાલી, ખાલી, ખાલી)) != ખાલી) {
		જો ((*k = sshkey_new(ચાવી_UNSPEC)) == ખાલી)
			fatal("sshkey_new failed");
		જો (((*k)->pkey = EVP_PKEY_new()) == ખાલી)
			fatal("EVP_PKEY_new failed");
		(*k)->type = ચાવી_RSA;
		જો (EVP_PKEY_set1_RSA((*k)->pkey, rsa) != 1)
			fatal("EVP_PKEY_set1_RSA failed");
		RSA_free(rsa);
		fclose(fp);
		પાછા;
	}
	fatal_f("unrecognised raw private key format");
}

સ્થિર શૂન્ય
do_convert_from(સંરચના passwd *pw)
{
	સંરચના sshkey *k = ખાલી;
	પૂર્ણાંક r, ખાનગી = 0, ok = 0;
	સંરચના stat st;

	જો (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	જો (stat(identity_file, &st) == -1)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));

	પસંદગી (convert_format) {
	સ્થિતિ FMT_RFC4716:
		do_convert_from_ssh2(pw, &k, &ખાનગી);
		તોડો;
	સ્થિતિ FMT_PKCS8:
		do_convert_from_pkcs8(&k, &ખાનગી);
		તોડો;
	સ્થિતિ FMT_PEM:
		do_convert_from_pem(&k, &ખાનગી);
		તોડો;
	મૂળભૂત:
		fatal_f("unknown key format %d", convert_format);
	}

	જો (!ખાનગી) {
		જો ((r = sshkey_write(k, stdout)) == 0)
			ok = 1;
		જો (ok)
			fprintf(stdout, "\n");
	} નહીંતર {
		પસંદગી (k->type) {
		સ્થિતિ ચાવી_ECDSA:
			ok = PEM_write_ECPrivate_ચાવી(stdout,
			    EVP_PKEY_get0_EC_ચાવી(k->pkey), ખાલી, ખાલી, 0,
			    ખાલી, ખાલી);
			તોડો;
		સ્થિતિ ચાવી_RSA:
			ok = PEM_write_RSAPrivate_ચાવી(stdout,
			    EVP_PKEY_get0_RSA(k->pkey), ખાલી, ખાલી, 0,
			    ખાલી, ખાલી);
			તોડો;
		મૂળભૂત:
			fatal_f("unsupported key type %s", sshkey_type(k));
		}
	}

	જો (!ok)
		fatal("key write failed");
	sshkey_free(k);
}
#endif

સ્થિર શૂન્ય
do_print_public(સંરચના passwd *pw)
{
	સંરચના sshkey *prv;
	સંરચના stat st;
	પૂર્ણાંક r;
	અક્ષર *comment = ખાલી;

	જો (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	જો (stat(identity_file, &st) == -1)
		fatal("%s: %s", identity_file, strerror(errno));
	prv = load_identity(identity_file, &comment);
	જો ((r = sshkey_write(prv, stdout)) != 0)
		fatal_fr(r, "write key");
	જો (comment != ખાલી && *comment != '\0')
		fprintf(stdout, " %s", comment);
	fprintf(stdout, "\n");
	જો (sshkey_is_sk(prv)) {
		debug("sk_application: \"%s\", sk_flags 0x%02x",
			prv->sk_application, prv->sk_flags);
	}
	sshkey_free(prv);
	મુક્ત(comment);
	exit(0);
}

સ્થિર શૂન્ય
do_download(સંરચના passwd *pw)
{
#ifdef ENABLE_PKCS11
	સંરચના sshkey **ચાવીઓ = ખાલી;
	પૂર્ણાંક i, nkeys;
	ગણના sshkey_fp_rep rep;
	પૂર્ણાંક fptype;
	અક્ષર *fp, *ra, **comments = ખાલી;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;

	pkcs11_init(1);
	nkeys = pkcs11_add_provider(pkcs11provider, ખાલી, &ચાવીઓ, &comments);
	જો (nkeys <= 0)
		fatal("cannot read public key from pkcs11");
	માટે (i = 0; i < nkeys; i++) {
		જો (print_fingerprint) {
			fp = sshkey_fingerprint(ચાવીઓ[i], fptype, rep);
			ra = sshkey_fingerprint(ચાવીઓ[i], fingerprint_hash,
			    SSH_FP_RANDOMART);
			જો (fp == ખાલી || ra == ખાલી)
				fatal_f("sshkey_fingerprint fail");
			printf("%u %s %s (PKCS11 key)\n", sshkey_size(ચાવીઓ[i]),
			    fp, sshkey_type(ચાવીઓ[i]));
			જો (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
				printf("%s\n", ra);
			મુક્ત(ra);
			મુક્ત(fp);
		} નહીંતર {
			(શૂન્ય) sshkey_write(ચાવીઓ[i], stdout); /* XXX check */
			fprintf(stdout, "%s%s\n",
			    *(comments[i]) == '\0' ? "" : " ", comments[i]);
		}
		મુક્ત(comments[i]);
		sshkey_free(ચાવીઓ[i]);
	}
	મુક્ત(comments);
	મુક્ત(ચાવીઓ);
	pkcs11_terminate();
	exit(0);
#નહીંતર
	fatal("no pkcs11 support");
#endif /* ENABLE_PKCS11 */
}

સ્થિર સંરચના sshkey *
try_read_ચાવી(અક્ષર **cpp)
{
	સંરચના sshkey *ret;
	પૂર્ણાંક r;

	જો ((ret = sshkey_new(ચાવી_UNSPEC)) == ખાલી)
		fatal("sshkey_new failed");
	જો ((r = sshkey_read(ret, cpp)) == 0)
		પાછા ret;
	/* Not a key */
	sshkey_free(ret);
	પાછા ખાલી;
}

સ્થિર શૂન્ય
fingerprint_one_ચાવી(અચલ સંરચના sshkey *જાહેર, અચલ અક્ષર *comment)
{
	અક્ષર *fp = ખાલી, *ra = ખાલી;
	ગણના sshkey_fp_rep rep;
	પૂર્ણાંક fptype;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;
	fp = sshkey_fingerprint(જાહેર, fptype, rep);
	ra = sshkey_fingerprint(જાહેર, fingerprint_hash, SSH_FP_RANDOMART);
	જો (fp == ખાલી || ra == ખાલી)
		fatal_f("sshkey_fingerprint failed");
	mprintf("%u %s %s (%s)\n", sshkey_size(જાહેર), fp,
	    comment ? comment : "no comment", sshkey_type(જાહેર));
	જો (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
		printf("%s\n", ra);
	મુક્ત(ra);
	મુક્ત(fp);
}

સ્થિર શૂન્ય
fingerprint_private(અચલ અક્ષર *path)
{
	સંરચના stat st;
	અક્ષર *comment = ખાલી;
	સંરચના sshkey *privkey = ખાલી, *pubkey = ખાલી;
	પૂર્ણાંક r;

	જો (stat(identity_file, &st) == -1)
		fatal("%s: %s", path, strerror(errno));
	જો ((r = sshkey_load_public(path, &pubkey, &comment)) != 0)
		debug_r(r, "load public \"%s\"", path);
	જો (pubkey == ખાલી || comment == ખાલી || *comment == '\0') {
		મુક્ત(comment);
		જો ((r = sshkey_load_private(path, ખાલી,
		    &privkey, &comment)) != 0)
			debug_r(r, "load private \"%s\"", path);
	}
	જો (pubkey == ખાલી && privkey == ખાલી)
		fatal("%s is not a key file.", path);

	fingerprint_one_ચાવી(pubkey == ખાલી ? privkey : pubkey, comment);
	sshkey_free(pubkey);
	sshkey_free(privkey);
	મુક્ત(comment);
}

સ્થિર શૂન્ય
do_fingerprint(સંરચના passwd *pw)
{
	FILE *f;
	સંરચના sshkey *જાહેર = ખાલી;
	અક્ષર *comment = ખાલી, *cp, *ep, *લીટી = ખાલી;
	size_t linesize = 0;
	પૂર્ણાંક i, invalid = 1;
	અચલ અક્ષર *path;
	u_long lnum = 0;

	જો (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	path = identity_file;

	જો (strcmp(identity_file, "-") == 0) {
		f = stdin;
		path = "(stdin)";
	} નહીંતર જો ((f = fopen(path, "r")) == ખાલી)
		fatal("%s: %s: %s", __progname, path, strerror(errno));

	જ્યારે (getline(&લીટી, &linesize, f) != -1) {
		lnum++;
		cp = લીટી;
		cp[strcspn(cp, "\r\n")] = '\0';
		/* Trim leading space and comments */
		cp = લીટી + strspn(લીટી, " \t");
		જો (*cp == '#' || *cp == '\0')
			ચાલુ;

		/*
		 * Input may be plain keys, private keys, authorized_keys
		 * or known_hosts.
		 */

		/*
		 * Try private keys first. Assume a key is private if
		 * "SSH PRIVATE KEY" appears on the first line and we're
		 * not reading from stdin (XXX support private keys on stdin).
		 */
		જો (lnum == 1 && strcmp(identity_file, "-") != 0 &&
		    strstr(cp, "PRIVATE KEY") != ખાલી) {
			મુક્ત(લીટી);
			fclose(f);
			fingerprint_private(path);
			exit(0);
		}

		/*
		 * If it's not a private key, then this must be prepared to
		 * accept a public key prefixed with a hostname or options.
		 * Try a bare key first, otherwise skip the leading stuff.
		 */
		comment = ખાલી;
		જો ((જાહેર = try_read_ચાવી(&cp)) == ખાલી) {
			i = strtol(cp, &ep, 10);
			જો (i == 0 || ep == ખાલી ||
			    (*ep != ' ' && *ep != '\t')) {
				પૂર્ણાંક quoted = 0;

				comment = cp;
				માટે (; *cp && (quoted || (*cp != ' ' &&
				    *cp != '\t')); cp++) {
					જો (*cp == '\\' && cp[1] == '"')
						cp++;	/* Skip both */
					નહીંતર જો (*cp == '"')
						quoted = !quoted;
				}
				જો (!*cp)
					ચાલુ;
				*cp++ = '\0';
			}
		}
		/* Retry after parsing leading hostname/key options */
		જો (જાહેર == ખાલી && (જાહેર = try_read_ચાવી(&cp)) == ખાલી) {
			debug("%s:%lu: not a public key", path, lnum);
			ચાલુ;
		}

		/* Find trailing comment, if any */
		માટે (; *cp == ' ' || *cp == '\t'; cp++)
			;
		જો (*cp != '\0' && *cp != '#')
			comment = cp;

		fingerprint_one_ચાવી(જાહેર, comment);
		sshkey_free(જાહેર);
		invalid = 0; /* One good key in the file is sufficient */
	}
	fclose(f);
	મુક્ત(લીટી);

	જો (invalid)
		fatal("%s is not a public key file.", path);
	exit(0);
}

સ્થિર શૂન્ય
do_gen_all_hostkeys(સંરચના passwd *pw)
{
	સંરચના {
		અક્ષર *ચાવી_type;
		અક્ષર *ચાવી_type_display;
		અક્ષર *path;
	} ચાવી_types[] = {
#ifdef WITH_OPENSSL
		{ "rsa", "RSA" ,PATH_HOST_RSA_ચાવી_FILE },
		{ "ecdsa", "ECDSA",PATH_HOST_ECDSA_ચાવી_FILE },
#endif /* WITH_OPENSSL */
		{ "ed25519", "ED25519",PATH_HOST_ED25519_ચાવી_FILE },
#ifdef USE_MLDSA
		{ "mldsa44-ed25519", "MLDSA44-ED25519",
		     PATH_HOST_MLDSA44_ED25519_ચાવી_FILE },
#endif
		{ ખાલી, ખાલી, ખાલી }
	};

	uint32_t bits = 0;
	પૂર્ણાંક first = 0;
	સંરચના stat st;
	સંરચના sshkey *ખાનગી, *જાહેર;
	અક્ષર comment[ચાવી_COMMENT_MAX], *prv_tmp, *pub_tmp, *prv_file, *pub_file;
	પૂર્ણાંક i, type, fd, r;

	માટે (i = 0; ચાવી_types[i].ચાવી_type; i++) {
		જાહેર = ખાનગી = ખાલી;
		prv_tmp = pub_tmp = prv_file = pub_file = ખાલી;

		xasprintf(&prv_file, "%s%s",
		    identity_file, ચાવી_types[i].path);

		/* Check whether private key exists and is not zero-length */
		જો (stat(prv_file, &st) == 0) {
			જો (st.st_size != 0)
				જાઓ next;
		} નહીંતર જો (errno != ENOENT) {
			error("Could not stat %s: %s", ચાવી_types[i].path,
			    strerror(errno));
			જાઓ failnext;
		}

		/*
		 * Private key doesn't exist or is invalid; proceed with
		 * key generation.
		 */
		xasprintf(&prv_tmp, "%s%s.XXXXXXXXXX",
		    identity_file, ચાવી_types[i].path);
		xasprintf(&pub_tmp, "%s%s.pub.XXXXXXXXXX",
		    identity_file, ચાવી_types[i].path);
		xasprintf(&pub_file, "%s%s.pub",
		    identity_file, ચાવી_types[i].path);

		જો (first == 0) {
			first = 1;
			printf("%s: generating new host keys: ", __progname);
		}
		printf("%s ", ચાવી_types[i].ચાવી_type_display);
		fflush(stdout);
		type = sshkey_type_from_shortname(ચાવી_types[i].ચાવી_type);
		જો ((fd = mkstemp(prv_tmp)) == -1) {
			error("Could not save your private key in %s: %s",
			    prv_tmp, strerror(errno));
			જાઓ failnext;
		}
		(શૂન્ય)close(fd); /* just using mkstemp() to reserve a name */
		bits = 0;
		type_bits_valid(type, ખાલી, &bits);
		જો ((r = sshkey_generate(type, bits, &ખાનગી)) != 0) {
			error_r(r, "sshkey_generate failed");
			જાઓ failnext;
		}
		જો ((r = sshkey_from_private(ખાનગી, &જાહેર)) != 0)
			fatal_fr(r, "sshkey_from_private");
		snprintf(comment, કદ comment, "%s@%s", pw->pw_name,
		    hostname);
		જો ((r = sshkey_save_private(ખાનગી, prv_tmp, "",
		    comment, private_ચાવી_format, openssh_format_cipher,
		    rounds)) != 0) {
			error_r(r, "Saving key \"%s\" failed", prv_tmp);
			જાઓ failnext;
		}
		જો ((fd = mkstemp(pub_tmp)) == -1) {
			error("Could not save your public key in %s: %s",
			    pub_tmp, strerror(errno));
			જાઓ failnext;
		}
		(શૂન્ય)fchmod(fd, 0644);
		(શૂન્ય)close(fd);
		જો ((r = sshkey_save_public(જાહેર, pub_tmp, comment)) != 0) {
			error_r(r, "Unable to save public key to %s",
			    identity_file);
			જાઓ failnext;
		}

		/* Rename temporary files to their permanent locations. */
		જો (rename(pub_tmp, pub_file) != 0) {
			error("Unable to move %s into position: %s",
			    pub_file, strerror(errno));
			જાઓ failnext;
		}
		જો (rename(prv_tmp, prv_file) != 0) {
			error("Unable to move %s into position: %s",
			    ચાવી_types[i].path, strerror(errno));
 failnext:
			first = 0;
			જાઓ next;
		}
 next:
		sshkey_free(ખાનગી);
		sshkey_free(જાહેર);
		મુક્ત(prv_tmp);
		મુક્ત(pub_tmp);
		મુક્ત(prv_file);
		મુક્ત(pub_file);
	}
	જો (first != 0)
		printf("\n");
}

સંરચના known_hosts_ctx {
	અચલ અક્ષર *host;	/* Hostname searched for in find/delete case */
	FILE *out;		/* Output file, stdout for find_hosts case */
	પૂર્ણાંક has_unhashed;	/* When hashing, original had unhashed hosts */
	પૂર્ણાંક found_ચાવી;		/* For find/delete, host was found */
	પૂર્ણાંક invalid;		/* File contained invalid items; don't delete */
	પૂર્ણાંક hash_hosts;		/* Hash hostnames as we go */
	પૂર્ણાંક find_host;		/* Search for specific hostname */
	પૂર્ણાંક delete_host;	/* Delete host from known_hosts */
};

સ્થિર પૂર્ણાંક
known_hosts_hash(સંરચના hostkey_foreach_લીટી *l, શૂન્ય *_ctx)
{
	સંરચના known_hosts_ctx *ctx = (સંરચના known_hosts_ctx *)_ctx;
	અક્ષર *hashed, *cp, *hosts, *ohosts;
	પૂર્ણાંક has_wild = l->hosts && strcspn(l->hosts, "*?!") != strlen(l->hosts);
	પૂર્ણાંક was_hashed = l->hosts && l->hosts[0] == HASH_DELIM;

	પસંદગી (l->status) {
	સ્થિતિ HKF_STATUS_OK:
	સ્થિતિ HKF_STATUS_MATCHED:
		/*
		 * Don't hash hosts already hashed, with wildcard
		 * characters or a CA/revocation marker.
		 */
		જો (was_hashed || has_wild || l->marker != MRK_NONE) {
			fprintf(ctx->out, "%s\n", l->લીટી);
			જો (has_wild && !ctx->find_host) {
				logit("%s:%lu: ignoring host name "
				    "with wildcard: %.64s", l->path,
				    l->linenum, l->hosts);
			}
			પાછા 0;
		}
		/*
		 * Split any comma-separated hostnames from the host list,
		 * hash and store separately.
		 */
		ohosts = hosts = xstrdup(l->hosts);
		જ્યારે ((cp = strsep(&hosts, ",")) != ખાલી && *cp != '\0') {
			lowercase(cp);
			જો ((hashed = host_hash(cp, ખાલી, 0)) == ખાલી)
				fatal("hash_host failed");
			fprintf(ctx->out, "%s %s\n", hashed, l->rawkey);
			મુક્ત(hashed);
			ctx->has_unhashed = 1;
		}
		મુક્ત(ohosts);
		પાછા 0;
	સ્થિતિ HKF_STATUS_INVALID:
		/* Retain invalid lines, but mark file as invalid. */
		ctx->invalid = 1;
		logit("%s:%lu: invalid line", l->path, l->linenum);
		/* FALLTHROUGH */
	મૂળભૂત:
		fprintf(ctx->out, "%s\n", l->લીટી);
		પાછા 0;
	}
	/* NOTREACHED */
	પાછા -1;
}

સ્થિર પૂર્ણાંક
known_hosts_find_delete(સંરચના hostkey_foreach_લીટી *l, શૂન્ય *_ctx)
{
	સંરચના known_hosts_ctx *ctx = (સંરચના known_hosts_ctx *)_ctx;
	ગણના sshkey_fp_rep rep;
	પૂર્ણાંક fptype;
	અક્ષર *fp = ખાલી, *ra = ખાલી;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;

	જો (l->status == HKF_STATUS_MATCHED) {
		જો (ctx->delete_host) {
			જો (l->marker != MRK_NONE) {
				/* Don't remove CA and revocation lines */
				fprintf(ctx->out, "%s\n", l->લીટી);
			} નહીંતર {
				/*
				 * Hostname matches and has no CA/revoke
				 * marker, delete it by *not* writing the
				 * line to ctx->out.
				 */
				ctx->found_ચાવી = 1;
				જો (!quiet)
					printf("# Host %s found: line %lu\n",
					    ctx->host, l->linenum);
			}
			પાછા 0;
		} નહીંતર જો (ctx->find_host) {
			ctx->found_ચાવી = 1;
			જો (!quiet) {
				printf("# Host %s found: line %lu %s\n",
				    ctx->host,
				    l->linenum, l->marker == MRK_CA ? "CA" :
				    (l->marker == MRK_REVOKE ? "REVOKED" : ""));
			}
			જો (ctx->hash_hosts)
				known_hosts_hash(l, ctx);
			નહીંતર જો (print_fingerprint) {
				fp = sshkey_fingerprint(l->ચાવી, fptype, rep);
				ra = sshkey_fingerprint(l->ચાવી,
				    fingerprint_hash, SSH_FP_RANDOMART);
				જો (fp == ખાલી || ra == ખાલી)
					fatal_f("sshkey_fingerprint failed");
				mprintf("%s %s %s%s%s\n", ctx->host,
				    sshkey_type(l->ચાવી), fp,
				    l->comment[0] ? " " : "",
				    l->comment);
				જો (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
					printf("%s\n", ra);
				મુક્ત(ra);
				મુક્ત(fp);
			} નહીંતર
				fprintf(ctx->out, "%s\n", l->લીટી);
			પાછા 0;
		}
	} નહીંતર જો (ctx->delete_host) {
		/* Retain non-matching hosts when deleting */
		જો (l->status == HKF_STATUS_INVALID) {
			ctx->invalid = 1;
			logit("%s:%lu: invalid line", l->path, l->linenum);
		}
		fprintf(ctx->out, "%s\n", l->લીટી);
	}
	પાછા 0;
}

સ્થિર શૂન્ય
do_known_hosts(સંરચના passwd *pw, અચલ અક્ષર *name, પૂર્ણાંક find_host,
    પૂર્ણાંક delete_host, પૂર્ણાંક hash_hosts)
{
	અક્ષર *cp, tmp[PATH_MAX], old[PATH_MAX];
	પૂર્ણાંક r, fd, oerrno, inplace = 0;
	સંરચના known_hosts_ctx ctx;
	u_int foreach_options;
	સંરચના stat sb;

	જો (!have_identity) {
		cp = tilde_expand_filename(_PATH_SSH_USER_HOSTFILE, pw->pw_uid);
		જો (strlcpy(identity_file, cp, કદ(identity_file)) >=
		    કદ(identity_file))
			fatal("Specified known hosts path too long");
		મુક્ત(cp);
		have_identity = 1;
	}
	જો (stat(identity_file, &sb) != 0)
		fatal("Cannot stat %s: %s", identity_file, strerror(errno));

	memset(&ctx, 0, કદ(ctx));
	ctx.out = stdout;
	ctx.host = name;
	ctx.hash_hosts = hash_hosts;
	ctx.find_host = find_host;
	ctx.delete_host = delete_host;

	/*
	 * Find hosts goes to stdout, hash and deletions happen in-place
	 * A corner case is ssh-keygen -HF foo, which should go to stdout
	 */
	જો (!find_host && (hash_hosts || delete_host)) {
		જો (strlcpy(tmp, identity_file, કદ(tmp)) >= કદ(tmp) ||
		    strlcat(tmp, ".XXXXXXXXXX", કદ(tmp)) >= કદ(tmp) ||
		    strlcpy(old, identity_file, કદ(old)) >= કદ(old) ||
		    strlcat(old, ".old", કદ(old)) >= કદ(old))
			fatal("known_hosts path too long");
		umask(077);
		જો ((fd = mkstemp(tmp)) == -1)
			fatal("mkstemp: %s", strerror(errno));
		જો ((ctx.out = fdopen(fd, "w")) == ખાલી) {
			oerrno = errno;
			unlink(tmp);
			fatal("fdopen: %s", strerror(oerrno));
		}
		(શૂન્ય)fchmod(fd, sb.st_mode & 0644);
		inplace = 1;
	}
	/* XXX support identity_file == "-" for stdin */
	foreach_options = find_host ? HKF_WANT_MATCH : 0;
	foreach_options |= print_fingerprint ? HKF_WANT_PARSE_ચાવી : 0;
	જો ((r = hostkeys_foreach(identity_file, (find_host || !hash_hosts) ?
	    known_hosts_find_delete : known_hosts_hash, &ctx, name, ખાલી,
	    foreach_options, 0)) != 0) {
		જો (inplace)
			unlink(tmp);
		fatal_fr(r, "hostkeys_foreach");
	}

	જો (inplace)
		fclose(ctx.out);

	જો (ctx.invalid) {
		error("%s is not a valid known_hosts file.", identity_file);
		જો (inplace) {
			error("Not replacing existing known_hosts "
			    "file because of errors");
			unlink(tmp);
		}
		exit(1);
	} નહીંતર જો (delete_host && !ctx.found_ચાવી) {
		logit("Host %s not found in %s", name, identity_file);
		જો (inplace)
			unlink(tmp);
	} નહીંતર જો (inplace) {
		/* Backup existing file */
		જો (unlink(old) == -1 && errno != ENOENT)
			fatal("unlink %.100s: %s", old, strerror(errno));
		જો (link(identity_file, old) == -1)
			fatal("link %.100s to %.100s: %s", identity_file, old,
			    strerror(errno));
		/* Move new one into place */
		જો (rename(tmp, identity_file) == -1) {
			error("rename\"%s\" to \"%s\": %s", tmp, identity_file,
			    strerror(errno));
			unlink(tmp);
			unlink(old);
			exit(1);
		}

		printf("%s updated.\n", identity_file);
		printf("Original contents retained as %s\n", old);
		જો (ctx.has_unhashed) {
			logit("WARNING: %s contains unhashed entries", old);
			logit("Delete this file to ensure privacy "
			    "of hostnames");
		}
	}

	exit (find_host && !ctx.found_ચાવી);
}

/*
 * Perform changing a passphrase.  The argument is the passwd structure
 * for the current user.
 */
સ્થિર શૂન્ય
do_change_passphrase(સંરચના passwd *pw, અક્ષર * અચલ *opts, size_t nopts)
{
	અક્ષર *comment;
	અક્ષર *old_passphrase, *passphrase1, *passphrase2;
	સંરચના stat st;
	સંરચના sshkey *ખાનગી;
	પૂર્ણાંક r;
	size_t i;

	જો (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	જો (stat(identity_file, &st) == -1)
		fatal("%s: %s", identity_file, strerror(errno));
	/* Try to load the file with empty passphrase. */
	r = sshkey_load_private(identity_file, "", &ખાનગી, &comment);
	જો (r == SSH_ERR_ચાવી_WRONG_PASSPHRASE) {
		જો (identity_passphrase)
			old_passphrase = xstrdup(identity_passphrase);
		નહીંતર
			old_passphrase =
			    read_passphrase("Enter old passphrase: ",
			    RP_ALLOW_STDIN);
		r = sshkey_load_private(identity_file, old_passphrase,
		    &ખાનગી, &comment);
		freezero(old_passphrase, strlen(old_passphrase));
		જો (r != 0)
			જાઓ badkey;
	} નહીંતર જો (r != 0) {
 badkey:
		fatal_r(r, "Failed to load key %s", identity_file);
	}
	જો (comment)
		mprintf("Key has comment '%s'\n", comment);

	/* All current -O options relate to FIDO keys only */
	જો (nopts != 0 && !sshkey_is_sk(ખાનગી)) {
		fatal("FIDO-specific option requested for non-FIDO key %s",
		    identity_file);
	}
	જો (sshkey_is_sk(ખાનગી)) {
		debug_f("%s: original FIDO key flags: "
		    "%stouch-required %sverify-required", identity_file,
		    (ખાનગી->sk_flags & SSH_SK_USER_PRESENCE_REQD) ? "": "no-",
		    (ખાનગી->sk_flags & SSH_SK_USER_VERIFICATION_REQD) ? "" : "no-");
	}
	માટે (i = 0; i < nopts; i++) {
		જો (strcasecmp(opts[i], "touch-required") == 0)
			ખાનગી->sk_flags |= SSH_SK_USER_PRESENCE_REQD;
		નહીંતર જો (strcasecmp(opts[i], "no-touch-required") == 0)
			ખાનગી->sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
		નહીંતર જો (strcasecmp(opts[i], "verify-required") == 0)
			ખાનગી->sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
		નહીંતર જો (strcasecmp(opts[i], "no-verify-required") == 0)
			ખાનગી->sk_flags &= ~SSH_SK_USER_VERIFICATION_REQD;
		નહીંતર {
			fatal("Option \"%s\" is unsupported for "
			    "key passphrase change", opts[i]);
		}
	}
	જો (sshkey_is_sk(ખાનગી) && nopts != 0) {
		debug_f("%s: updated FIDO key flags: "
		    "%stouch-required %sverify-required", identity_file,
		    (ખાનગી->sk_flags & SSH_SK_USER_PRESENCE_REQD) ? "": "no-",
		    (ખાનગી->sk_flags & SSH_SK_USER_VERIFICATION_REQD) ? "" : "no-");
	}

	/* Ask the new passphrase (twice). */
	જો (identity_new_passphrase) {
		passphrase1 = xstrdup(identity_new_passphrase);
		passphrase2 = ખાલી;
	} નહીંતર {
		passphrase1 =
			read_passphrase("Enter new passphrase (empty for no "
			    "passphrase): ", RP_ALLOW_STDIN);
		passphrase2 = read_passphrase("Enter same passphrase again: ",
		    RP_ALLOW_STDIN);

		/* Verify that they are the same. */
		જો (strcmp(passphrase1, passphrase2) != 0) {
			explicit_bzero(passphrase1, strlen(passphrase1));
			explicit_bzero(passphrase2, strlen(passphrase2));
			મુક્ત(passphrase1);
			મુક્ત(passphrase2);
			printf("Pass phrases do not match.  Try again.\n");
			exit(1);
		}
		/* Destroy the other copy. */
		freezero(passphrase2, strlen(passphrase2));
	}

	/* Save the file using the new passphrase. */
	જો ((r = sshkey_save_private(ખાનગી, identity_file, passphrase1,
	    comment, private_ચાવી_format, openssh_format_cipher, rounds)) != 0) {
		error_r(r, "Saving key \"%s\" failed", identity_file);
		freezero(passphrase1, strlen(passphrase1));
		sshkey_free(ખાનગી);
		મુક્ત(comment);
		exit(1);
	}
	/* Destroy the passphrase and the copy of the key in memory. */
	freezero(passphrase1, strlen(passphrase1));
	sshkey_free(ખાનગી);		 /* Destroys contents */
	મુક્ત(comment);

	printf("Your identification has been saved with the new passphrase.\n");
	exit(0);
}

/*
 * Print the SSHFP RR.
 */
સ્થિર પૂર્ણાંક
do_print_resource_record(સંરચના passwd *pw, અક્ષર *fname, અક્ષર *hname,
    પૂર્ણાંક print_generic, અક્ષર * અચલ *opts, size_t nopts)
{
	સંરચના sshkey *જાહેર;
	અક્ષર *comment = ખાલી;
	અચલ અક્ષર *p;
	સંરચના stat st;
	પૂર્ણાંક r, hash = -1;
	size_t i;

	માટે (i = 0; i < nopts; i++) {
		જો ((p = strprefix(opts[i], "hashalg=", 1)) != ખાલી) {
			જો ((hash = ssh_digest_alg_by_name(p)) == -1)
				fatal("Unsupported hash algorithm");
		} નહીંતર {
			error("Invalid option \"%s\"", opts[i]);
			પાછા SSH_ERR_INVALID_ARGUMENT;
		}
	}
	જો (fname == ખાલી)
		fatal_f("no filename");
	જો (stat(fname, &st) == -1) {
		જો (errno == ENOENT)
			પાછા 0;
		fatal("%s: %s", fname, strerror(errno));
	}
	જો ((r = sshkey_load_public(fname, &જાહેર, &comment)) != 0)
		fatal_r(r, "Failed to read v2 public key from \"%s\"", fname);
	export_dns_rr(hname, જાહેર, stdout, print_generic, hash);
	sshkey_free(જાહેર);
	મુક્ત(comment);
	પાછા 1;
}

/*
 * Change the comment of a private key file.
 */
સ્થિર શૂન્ય
do_change_comment(સંરચના passwd *pw, અચલ અક્ષર *identity_comment)
{
	અક્ષર new_comment[ચાવી_COMMENT_MAX], *comment, *passphrase;
	સંરચના sshkey *ખાનગી;
	સંરચના sshkey *જાહેર;
	સંરચના stat st;
	પૂર્ણાંક r;

	જો (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	જો (stat(identity_file, &st) == -1)
		fatal("%s: %s", identity_file, strerror(errno));
	જો ((r = sshkey_load_private(identity_file, "",
	    &ખાનગી, &comment)) == 0)
		passphrase = xstrdup("");
	નહીંતર જો (r != SSH_ERR_ચાવી_WRONG_PASSPHRASE)
		fatal_r(r, "Cannot load private key \"%s\"", identity_file);
	નહીંતર {
		જો (identity_passphrase)
			passphrase = xstrdup(identity_passphrase);
		નહીંતર જો (identity_new_passphrase)
			passphrase = xstrdup(identity_new_passphrase);
		નહીંતર
			passphrase = read_passphrase("Enter passphrase: ",
			    RP_ALLOW_STDIN);
		/* Try to load using the passphrase. */
		જો ((r = sshkey_load_private(identity_file, passphrase,
		    &ખાનગી, &comment)) != 0) {
			freezero(passphrase, strlen(passphrase));
			fatal_r(r, "Cannot load private key \"%s\"",
			    identity_file);
		}
	}

	જો (ખાનગી->type != ચાવી_ED25519 &&
	    private_ચાવી_format != SSHKEY_PRIVATE_OPENSSH) {
		error("Comments are only supported for keys stored in "
		    "the new format (-o).");
		explicit_bzero(passphrase, strlen(passphrase));
		sshkey_free(ખાનગી);
		exit(1);
	}
	જો (comment)
		printf("Old comment: %s\n", comment);
	નહીંતર
		printf("No existing comment\n");

	જો (identity_comment) {
		strlcpy(new_comment, identity_comment, કદ(new_comment));
	} નહીંતર {
		printf("New comment: ");
		fflush(stdout);
		જો (!fgets(new_comment, કદ(new_comment), stdin)) {
			explicit_bzero(passphrase, strlen(passphrase));
			sshkey_free(ખાનગી);
			exit(1);
		}
		new_comment[strcspn(new_comment, "\n")] = '\0';
	}
	જો (comment != ખાલી && strcmp(comment, new_comment) == 0) {
		printf("No change to comment\n");
		મુક્ત(passphrase);
		sshkey_free(ખાનગી);
		મુક્ત(comment);
		exit(0);
	}

	/* Save the file using the new passphrase. */
	જો ((r = sshkey_save_private(ખાનગી, identity_file, passphrase,
	    new_comment, private_ચાવી_format, openssh_format_cipher,
	    rounds)) != 0) {
		error_r(r, "Saving key \"%s\" failed", identity_file);
		freezero(passphrase, strlen(passphrase));
		sshkey_free(ખાનગી);
		મુક્ત(comment);
		exit(1);
	}
	freezero(passphrase, strlen(passphrase));
	જો ((r = sshkey_from_private(ખાનગી, &જાહેર)) != 0)
		fatal_fr(r, "sshkey_from_private");
	sshkey_free(ખાનગી);

	strlcat(identity_file, ".pub", કદ(identity_file));
	જો ((r = sshkey_save_public(જાહેર, identity_file, new_comment)) != 0)
		fatal_r(r, "Unable to save public key to %s", identity_file);
	sshkey_free(જાહેર);
	મુક્ત(comment);

	જો (strlen(new_comment) > 0)
		printf("Comment '%s' applied\n", new_comment);
	નહીંતર
		printf("Comment removed\n");

	exit(0);
}

સ્થિર શૂન્ય
cert_ext_add(અચલ અક્ષર *ચાવી, અચલ અક્ષર *કિંમત, પૂર્ણાંક iscrit)
{
	cert_ext = xreallocarray(cert_ext, ncert_ext + 1, કદ(*cert_ext));
	cert_ext[ncert_ext].ચાવી = xstrdup(ચાવી);
	cert_ext[ncert_ext].val = કિંમત == ખાલી ? ખાલી : xstrdup(કિંમત);
	cert_ext[ncert_ext].crit = iscrit;
	ncert_ext++;
}

/* qsort(3) comparison function for certificate extensions */
સ્થિર પૂર્ણાંક
cert_ext_cmp(અચલ શૂન્ય *_a, અચલ શૂન્ય *_b)
{
	અચલ સંરચના cert_ext *a = (અચલ સંરચના cert_ext *)_a;
	અચલ સંરચના cert_ext *b = (અચલ સંરચના cert_ext *)_b;
	પૂર્ણાંક r;

	જો (a->crit != b->crit)
		પાછા (a->crit < b->crit) ? -1 : 1;
	જો ((r = strcmp(a->ચાવી, b->ચાવી)) != 0)
		પાછા r;
	જો ((a->val == ખાલી) != (b->val == ખાલી))
		પાછા (a->val == ખાલી) ? -1 : 1;
	જો (a->val != ખાલી && (r = strcmp(a->val, b->val)) != 0)
		પાછા r;
	પાછા 0;
}

#define OPTIONS_CRITICAL	1
#define OPTIONS_EXTENSIONS	2
સ્થિર શૂન્ય
prepare_options_buf(સંરચના sshbuf *c, પૂર્ણાંક which)
{
	સંરચના sshbuf *b;
	size_t i;
	પૂર્ણાંક r;
	અચલ સંરચના cert_ext *ext;

	જો ((b = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	sshbuf_reset(c);
	માટે (i = 0; i < ncert_ext; i++) {
		ext = &cert_ext[i];
		જો ((ext->crit && (which & OPTIONS_EXTENSIONS)) ||
		    (!ext->crit && (which & OPTIONS_CRITICAL)))
			ચાલુ;
		જો (ext->val == ખાલી) {
			/* flag option */
			debug3_f("%s", ext->ચાવી);
			જો ((r = sshbuf_put_cstring(c, ext->ચાવી)) != 0 ||
			    (r = sshbuf_put_string(c, ખાલી, 0)) != 0)
				fatal_fr(r, "prepare flag");
		} નહીંતર {
			/* key/value option */
			debug3_f("%s=%s", ext->ચાવી, ext->val);
			sshbuf_reset(b);
			જો ((r = sshbuf_put_cstring(c, ext->ચાવી)) != 0 ||
			    (r = sshbuf_put_cstring(b, ext->val)) != 0 ||
			    (r = sshbuf_put_stringb(c, b)) != 0)
				fatal_fr(r, "prepare k/v");
		}
	}
	sshbuf_free(b);
}

સ્થિર શૂન્ય
finalise_cert_exts(શૂન્ય)
{
	/* critical options */
	જો (certflags_command != ખાલી)
		cert_ext_add("force-command", certflags_command, 1);
	જો (certflags_src_addr != ખાલી)
		cert_ext_add("source-address", certflags_src_addr, 1);
	જો ((certflags_flags & CERTOPT_REQUIRE_VERIFY) != 0)
		cert_ext_add("verify-required", ખાલી, 1);
	/* extensions */
	જો ((certflags_flags & CERTOPT_X_FWD) != 0)
		cert_ext_add("permit-X11-forwarding", ખાલી, 0);
	જો ((certflags_flags & CERTOPT_AGENT_FWD) != 0)
		cert_ext_add("permit-agent-forwarding", ખાલી, 0);
	જો ((certflags_flags & CERTOPT_PORT_FWD) != 0)
		cert_ext_add("permit-port-forwarding", ખાલી, 0);
	જો ((certflags_flags & CERTOPT_PTY) != 0)
		cert_ext_add("permit-pty", ખાલી, 0);
	જો ((certflags_flags & CERTOPT_USER_RC) != 0)
		cert_ext_add("permit-user-rc", ખાલી, 0);
	જો ((certflags_flags & CERTOPT_NO_REQUIRE_USER_PRESENCE) != 0)
		cert_ext_add("no-touch-required", ખાલી, 0);
	/* order lexically by key */
	જો (ncert_ext > 0)
		qsort(cert_ext, ncert_ext, કદ(*cert_ext), cert_ext_cmp);
}

સ્થિર સંરચના sshkey *
load_pkcs11_ચાવી(અક્ષર *path)
{
#ifdef ENABLE_PKCS11
	સંરચના sshkey **ચાવીઓ = ખાલી, *જાહેર, *ખાનગી = ખાલી;
	પૂર્ણાંક r, i, nkeys;

	જો ((r = sshkey_load_public(path, &જાહેર, ખાલી)) != 0)
		fatal_r(r, "Couldn't load CA public key \"%s\"", path);

	nkeys = pkcs11_add_provider(pkcs11provider, identity_passphrase,
	    &ચાવીઓ, ખાલી);
	debug3_f("%d keys", nkeys);
	જો (nkeys <= 0)
		fatal("cannot read public key from pkcs11");
	માટે (i = 0; i < nkeys; i++) {
		જો (sshkey_equal_public(જાહેર, ચાવીઓ[i])) {
			ખાનગી = ચાવીઓ[i];
			ચાલુ;
		}
		sshkey_free(ચાવીઓ[i]);
	}
	મુક્ત(ચાવીઓ);
	sshkey_free(જાહેર);
	પાછા ખાનગી;
#નહીંતર
	fatal("no pkcs11 support");
#endif /* ENABLE_PKCS11 */
}

/* Signer for sshkey_certify_custom that uses the agent */
સ્થિર પૂર્ણાંક
agent_signer(સંરચના sshkey *ચાવી, u_char **sigp, size_t *lenp,
    અચલ u_char *data, size_t datalen,
    અચલ અક્ષર *alg, અચલ અક્ષર *provider, અચલ અક્ષર *pin,
    u_int compat, શૂન્ય *ctx)
{
	પૂર્ણાંક *agent_fdp = (પૂર્ણાંક *)ctx;

	પાછા ssh_agent_sign(*agent_fdp, ચાવી, sigp, lenp,
	    data, datalen, alg, compat);
}

સ્થિર શૂન્ય
do_ca_sign(સંરચના passwd *pw, અચલ અક્ષર *ca_ચાવી_path, પૂર્ણાંક prefer_agent,
    unsigned long long cert_serial, પૂર્ણાંક cert_serial_autoinc,
    પૂર્ણાંક argc, અક્ષર **argv)
{
	પૂર્ણાંક r, i, ચાવી_in_agent = 0, agent_fd = -1;
	u_int n;
	સંરચના sshkey *ca, *જાહેર;
	અક્ષર valid[64], *otmp, *tmp, *cp, *out, *comment;
	અક્ષર *ca_fp = ખાલી, **plist = ખાલી, *pin = ખાલી;
	સંરચના ssh_identitylist *agent_ids;
	size_t j;
	સંરચના notifier_ctx *notifier = ખાલી;

#ifdef ENABLE_PKCS11
	pkcs11_init(1);
#endif
	tmp = tilde_expand_filename(ca_ચાવી_path, pw->pw_uid);
	જો (pkcs11provider != ખાલી) {
		/* If a PKCS#11 token was specified then try to use it */
		જો ((ca = load_pkcs11_ચાવી(tmp)) == ખાલી)
			fatal("No PKCS#11 key matching %s found", ca_ચાવી_path);
	} નહીંતર જો (prefer_agent) {
		/*
		 * Agent signature requested. Try to use agent after making
		 * sure the public key specified is actually present in the
		 * agent.
		 */
		જો ((r = sshkey_load_public(tmp, &ca, ખાલી)) != 0)
			fatal_r(r, "Cannot load CA public key %s", tmp);
		જો ((r = ssh_get_authentication_socket(&agent_fd)) != 0)
			fatal_r(r, "Cannot use public key for CA signature");
		જો ((r = ssh_fetch_identitylist(agent_fd, &agent_ids)) != 0)
			fatal_r(r, "Retrieve agent key list");
		માટે (j = 0; j < agent_ids->nkeys; j++) {
			જો (sshkey_equal(ca, agent_ids->ચાવીઓ[j])) {
				ચાવી_in_agent = 1;
				/* Replace the CA key with the agent one */
				sshkey_free(ca);
				ca = agent_ids->ચાવીઓ[j];
				agent_ids->ચાવીઓ[j] = ખાલી;
				તોડો;
			}
		}
		જો (!ચાવી_in_agent)
			fatal("CA key %s not found in agent", tmp);
		ssh_free_identitylist(agent_ids);
	} નહીંતર {
		/* CA key is assumed to be a private key on the filesystem */
		ca = load_identity(tmp, ખાલી);
		જો (sshkey_is_sk(ca) &&
		    (ca->sk_flags & SSH_SK_USER_VERIFICATION_REQD)) {
			જો ((pin = read_passphrase("Enter PIN for CA key: ",
			    RP_ALLOW_STDIN)) == ખાલી)
				fatal_f("couldn't read PIN");
		}
	}
	મુક્ત(tmp);

	જો (ચાવી_type_name != ખાલી) {
		જો (sshkey_type_from_shortname(ચાવી_type_name) != ca->type) {
			fatal("CA key type %s doesn't match specified %s",
			    sshkey_ssh_name(ca), ચાવી_type_name);
		}
	} નહીંતર જો (ca->type == ચાવી_RSA) {
		/* Default to a good signature algorithm */
		ચાવી_type_name = "rsa-sha2-512";
	}
	ca_fp = sshkey_fingerprint(ca, fingerprint_hash, SSH_FP_DEFAULT);

	finalise_cert_exts();
	માટે (i = 0; i < argc; i++) {
		/* Split list of principals */
		n = 0;
		જો (cert_principals != ખાલી) {
			otmp = tmp = xstrdup(cert_principals);
			plist = ખાલી;
			માટે (; (cp = strsep(&tmp, ",")) != ખાલી; n++) {
				plist = xreallocarray(plist, n + 1, કદ(*plist));
				જો (*(plist[n] = xstrdup(cp)) == '\0')
					fatal("Empty principal name");
			}
			મુક્ત(otmp);
		}
		જો (n > SSHKEY_CERT_MAX_PRINCIPALS)
			fatal("Too many certificate principals specified");

		tmp = tilde_expand_filename(argv[i], pw->pw_uid);
		જો ((r = sshkey_load_public(tmp, &જાહેર, &comment)) != 0)
			fatal_r(r, "load pubkey \"%s\"", tmp);
		જો (sshkey_is_cert(જાહેર))
			fatal_f("key \"%s\" type %s cannot be certified",
			    tmp, sshkey_type(જાહેર));

		/* Prepare certificate to sign */
		જો ((r = sshkey_to_certified(જાહેર)) != 0)
			fatal_r(r, "Could not upgrade key %s to certificate", tmp);
		જાહેર->cert->type = cert_ચાવી_type;
		જાહેર->cert->serial = (uint64_t)cert_serial;
		જાહેર->cert->ચાવી_id = xstrdup(cert_ચાવી_id);
		જાહેર->cert->nprincipals = n;
		જાહેર->cert->principals = plist;
		જાહેર->cert->valid_after = cert_valid_from;
		જાહેર->cert->valid_before = cert_valid_to;
		prepare_options_buf(જાહેર->cert->critical, OPTIONS_CRITICAL);
		prepare_options_buf(જાહેર->cert->extensions,
		    OPTIONS_EXTENSIONS);
		જો ((r = sshkey_from_private(ca,
		    &જાહેર->cert->signature_ચાવી)) != 0)
			fatal_r(r, "sshkey_from_private (ca key)");

		જો (ચાવી_in_agent) {
			જો ((r = sshkey_certify_custom(જાહેર, ca,
			    ચાવી_type_name, sk_provider, ખાલી, agent_signer,
			    &agent_fd)) != 0)
				fatal_r(r, "Couldn't certify %s via agent", tmp);
		} નહીંતર {
			જો (sshkey_is_sk(ca) &&
			    (ca->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
				notifier = notify_start(0,
				    "Confirm user presence for key %s %s",
				    sshkey_type(ca), ca_fp);
			}
			r = sshkey_certify(જાહેર, ca, ચાવી_type_name,
			    sk_provider, pin);
			notify_complete(notifier, "User presence confirmed");
			જો (r != 0)
				fatal_r(r, "Couldn't certify key %s", tmp);
		}

		જો ((cp = strrchr(tmp, '.')) != ખાલી && strcmp(cp, ".pub") == 0)
			*cp = '\0';
		xasprintf(&out, "%s-cert.pub", tmp);
		મુક્ત(tmp);

		જો ((r = sshkey_save_public(જાહેર, out, comment)) != 0) {
			fatal_r(r, "Unable to save public key to %s",
			    identity_file);
		}

		જો (!quiet) {
			sshkey_format_cert_validity(જાહેર->cert,
			    valid, કદ(valid));
			logit("Signed %s key %s: id \"%s\" serial %llu%s%s "
			    "valid %s", sshkey_cert_type(જાહેર),
			    out, જાહેર->cert->ચાવી_id,
			    (unsigned long long)જાહેર->cert->serial,
			    cert_principals != ખાલી ? " for " : "",
			    cert_principals != ખાલી ? cert_principals : "",
			    valid);
		}

		sshkey_free(જાહેર);
		મુક્ત(out);
		મુક્ત(comment);
		જો (cert_serial_autoinc)
			cert_serial++;
	}
	જો (pin != ખાલી)
		freezero(pin, strlen(pin));
	sshkey_free(ca);
	મુક્ત(ca_fp);
#ifdef ENABLE_PKCS11
	pkcs11_terminate();
#endif
}

સ્થિર uint64_t
parse_relative_time(અચલ અક્ષર *s, time_t now)
{
	int64_t mul, secs;

	mul = *s == '-' ? -1 : 1;

	જો ((secs = convtime(s + 1)) == -1)
		fatal("Invalid relative certificate time %s", s);
	જો (mul == -1 && secs > now)
		fatal("Certificate time %s cannot be represented", s);
	પાછા now + (uint64_t)(secs * mul);
}

સ્થિર શૂન્ય
parse_hex_u64(અચલ અક્ષર *s, uint64_t *up)
{
	અક્ષર *ep;
	unsigned long long ull;

	errno = 0;
	ull = strtoull(s, &ep, 16);
	જો (*s == '\0' || *ep != '\0')
		fatal("Invalid certificate time: not a number");
	જો (errno == ERANGE && ull == ULONG_MAX)
		fatal_fr(SSH_ERR_SYSTEM_ERROR, "Invalid certificate time");
	*up = (uint64_t)ull;
}

સ્થિર શૂન્ય
parse_cert_times(અક્ષર *timespec)
{
	અક્ષર *from, *to;
	time_t now = time(ખાલી);
	int64_t secs;

	/* +timespec relative to now */
	જો (*timespec == '+' && strchr(timespec, ':') == ખાલી) {
		જો ((secs = convtime(timespec + 1)) == -1)
			fatal("Invalid relative certificate life %s", timespec);
		cert_valid_to = now + secs;
		/*
		 * Backdate certificate one minute to avoid problems on hosts
		 * with poorly-synchronised clocks.
		 */
		cert_valid_from = ((now - 59)/ 60) * 60;
		પાછા;
	}

	/*
	 * from:to, where
	 * from := [+-]timespec | YYYYMMDD | YYYYMMDDHHMMSS | 0x... | "always"
	 *   to := [+-]timespec | YYYYMMDD | YYYYMMDDHHMMSS | 0x... | "forever"
	 */
	from = xstrdup(timespec);
	to = strchr(from, ':');
	જો (to == ખાલી || from == to || *(to + 1) == '\0')
		fatal("Invalid certificate life specification %s", timespec);
	*to++ = '\0';

	જો (*from == '-' || *from == '+')
		cert_valid_from = parse_relative_time(from, now);
	નહીંતર જો (strcmp(from, "always") == 0)
		cert_valid_from = 0;
	નહીંતર જો (strncmp(from, "0x", 2) == 0)
		parse_hex_u64(from, &cert_valid_from);
	નહીંતર જો (parse_absolute_time(from, &cert_valid_from) != 0)
		fatal("Invalid from time \"%s\"", from);

	જો (*to == '-' || *to == '+')
		cert_valid_to = parse_relative_time(to, now);
	નહીંતર જો (strcmp(to, "forever") == 0)
		cert_valid_to = ~(uint64_t)0;
	નહીંતર જો (strncmp(to, "0x", 2) == 0)
		parse_hex_u64(to, &cert_valid_to);
	નહીંતર જો (parse_absolute_time(to, &cert_valid_to) != 0)
		fatal("Invalid to time \"%s\"", to);

	જો (cert_valid_to <= cert_valid_from)
		fatal("Empty certificate validity interval");
	મુક્ત(from);
}

સ્થિર શૂન્ય
add_cert_option(અક્ષર *opt)
{
	અક્ષર *val, *cp;
	અચલ અક્ષર *p;
	પૂર્ણાંક iscrit = 0;

	જો (strcasecmp(opt, "clear") == 0)
		certflags_flags = 0;
	નહીંતર જો (strcasecmp(opt, "no-x11-forwarding") == 0)
		certflags_flags &= ~CERTOPT_X_FWD;
	નહીંતર જો (strcasecmp(opt, "permit-x11-forwarding") == 0)
		certflags_flags |= CERTOPT_X_FWD;
	નહીંતર જો (strcasecmp(opt, "no-agent-forwarding") == 0)
		certflags_flags &= ~CERTOPT_AGENT_FWD;
	નહીંતર જો (strcasecmp(opt, "permit-agent-forwarding") == 0)
		certflags_flags |= CERTOPT_AGENT_FWD;
	નહીંતર જો (strcasecmp(opt, "no-port-forwarding") == 0)
		certflags_flags &= ~CERTOPT_PORT_FWD;
	નહીંતર જો (strcasecmp(opt, "permit-port-forwarding") == 0)
		certflags_flags |= CERTOPT_PORT_FWD;
	નહીંતર જો (strcasecmp(opt, "no-pty") == 0)
		certflags_flags &= ~CERTOPT_PTY;
	નહીંતર જો (strcasecmp(opt, "permit-pty") == 0)
		certflags_flags |= CERTOPT_PTY;
	નહીંતર જો (strcasecmp(opt, "no-user-rc") == 0)
		certflags_flags &= ~CERTOPT_USER_RC;
	નહીંતર જો (strcasecmp(opt, "permit-user-rc") == 0)
		certflags_flags |= CERTOPT_USER_RC;
	નહીંતર જો (strcasecmp(opt, "touch-required") == 0)
		certflags_flags &= ~CERTOPT_NO_REQUIRE_USER_PRESENCE;
	નહીંતર જો (strcasecmp(opt, "no-touch-required") == 0)
		certflags_flags |= CERTOPT_NO_REQUIRE_USER_PRESENCE;
	નહીંતર જો (strcasecmp(opt, "no-verify-required") == 0)
		certflags_flags &= ~CERTOPT_REQUIRE_VERIFY;
	નહીંતર જો (strcasecmp(opt, "verify-required") == 0)
		certflags_flags |= CERTOPT_REQUIRE_VERIFY;
	નહીંતર જો ((p = strprefix(opt, "force-command=", 1)) != ખાલી) {
		જો (*p == '\0')
			fatal("Empty force-command option");
		જો (certflags_command != ખાલી)
			fatal("force-command already specified");
		certflags_command = xstrdup(p);
	} નહીંતર જો ((p = strprefix(opt, "source-address=", 1)) != ખાલી) {
		જો (*p == '\0')
			fatal("Empty source-address option");
		જો (certflags_src_addr != ખાલી)
			fatal("source-address already specified");
		જો (addr_match_cidr_list(ખાલી, p) != 0)
			fatal("Invalid source-address list");
		certflags_src_addr = xstrdup(p);
	} નહીંતર જો (strprefix(opt, "extension:", 1) != ખાલી ||
		    (iscrit = (strprefix(opt, "critical:", 1) != ખાલી))) {
		val = xstrdup(strchr(opt, ':') + 1);
		જો ((cp = strchr(val, '=')) != ખાલી)
			*cp++ = '\0';
		cert_ext_add(val, cp, iscrit);
		મુક્ત(val);
	} નહીંતર
		fatal("Unsupported certificate option \"%s\"", opt);
}

સ્થિર શૂન્ય
show_options(સંરચના sshbuf *optbuf, પૂર્ણાંક in_critical)
{
	અક્ષર *name, *arg, *hex;
	સંરચના sshbuf *options, *option = ખાલી;
	પૂર્ણાંક r;

	જો ((options = sshbuf_fromb(optbuf)) == ખાલી)
		fatal_f("sshbuf_fromb failed");
	જ્યારે (sshbuf_len(options) != 0) {
		sshbuf_free(option);
		option = ખાલી;
		જો ((r = sshbuf_get_cstring(options, &name, ખાલી)) != 0 ||
		    (r = sshbuf_froms(options, &option)) != 0)
			fatal_fr(r, "parse option");
		printf("                %s", name);
		જો (!in_critical &&
		    (strcmp(name, "permit-X11-forwarding") == 0 ||
		    strcmp(name, "permit-agent-forwarding") == 0 ||
		    strcmp(name, "permit-port-forwarding") == 0 ||
		    strcmp(name, "permit-pty") == 0 ||
		    strcmp(name, "permit-user-rc") == 0 ||
		    strcmp(name, "no-touch-required") == 0)) {
			printf("\n");
		} નહીંતર જો (in_critical &&
		    (strcmp(name, "force-command") == 0 ||
		    strcmp(name, "source-address") == 0)) {
			જો ((r = sshbuf_get_cstring(option, &arg, ખાલી)) != 0)
				fatal_fr(r, "parse critical");
			printf(" %s\n", arg);
			મુક્ત(arg);
		} નહીંતર જો (in_critical &&
		    strcmp(name, "verify-required") == 0) {
			printf("\n");
		} નહીંતર જો (sshbuf_len(option) > 0) {
			hex = sshbuf_dtob16(option);
			printf(" UNKNOWN OPTION: %s (len %zu)\n",
			    hex, sshbuf_len(option));
			sshbuf_reset(option);
			મુક્ત(hex);
		} નહીંતર
			printf(" UNKNOWN FLAG OPTION\n");
		મુક્ત(name);
		જો (sshbuf_len(option) != 0)
			fatal("Option corrupt: extra data at end");
	}
	sshbuf_free(option);
	sshbuf_free(options);
}

સ્થિર શૂન્ય
print_cert(સંરચના sshkey *ચાવી)
{
	અક્ષર valid[64], *ચાવી_fp, *ca_fp;
	u_int i;

	ચાવી_fp = sshkey_fingerprint(ચાવી, fingerprint_hash, SSH_FP_DEFAULT);
	ca_fp = sshkey_fingerprint(ચાવી->cert->signature_ચાવી,
	    fingerprint_hash, SSH_FP_DEFAULT);
	જો (ચાવી_fp == ખાલી || ca_fp == ખાલી)
		fatal_f("sshkey_fingerprint fail");
	sshkey_format_cert_validity(ચાવી->cert, valid, કદ(valid));

	printf("        Type: %s %s certificate\n", sshkey_ssh_name(ચાવી),
	    sshkey_cert_type(ચાવી));
	printf("        Public key: %s %s\n", sshkey_type(ચાવી), ચાવી_fp);
	printf("        Signing CA: %s %s (using %s)\n",
	    sshkey_type(ચાવી->cert->signature_ચાવી), ca_fp,
	    ચાવી->cert->signature_type);
	printf("        Key ID: \"%s\"\n", ચાવી->cert->ચાવી_id);
	printf("        Serial: %llu\n", (unsigned long long)ચાવી->cert->serial);
	printf("        Valid: %s\n", valid);
	printf("        Principals: ");
	જો (ચાવી->cert->nprincipals == 0)
		printf("(none)\n");
	નહીંતર {
		માટે (i = 0; i < ચાવી->cert->nprincipals; i++)
			printf("\n                %s",
			    ચાવી->cert->principals[i]);
		printf("\n");
	}
	printf("        Critical Options: ");
	જો (sshbuf_len(ચાવી->cert->critical) == 0)
		printf("(none)\n");
	નહીંતર {
		printf("\n");
		show_options(ચાવી->cert->critical, 1);
	}
	printf("        Extensions: ");
	જો (sshbuf_len(ચાવી->cert->extensions) == 0)
		printf("(none)\n");
	નહીંતર {
		printf("\n");
		show_options(ચાવી->cert->extensions, 0);
	}
	મુક્ત(ચાવી_fp);
	મુક્ત(ca_fp);
}

સ્થિર શૂન્ય
do_show_cert(સંરચના passwd *pw)
{
	સંરચના sshkey *ચાવી = ખાલી;
	સંરચના stat st;
	પૂર્ણાંક r, is_stdin = 0, ok = 0;
	FILE *f;
	અક્ષર *cp, *લીટી = ખાલી;
	અચલ અક્ષર *path;
	size_t linesize = 0;
	u_long lnum = 0;

	જો (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	જો (strcmp(identity_file, "-") != 0 && stat(identity_file, &st) == -1)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));

	path = identity_file;
	જો (strcmp(path, "-") == 0) {
		f = stdin;
		path = "(stdin)";
		is_stdin = 1;
	} નહીંતર જો ((f = fopen(identity_file, "r")) == ખાલી)
		fatal("fopen %s: %s", identity_file, strerror(errno));

	જ્યારે (getline(&લીટી, &linesize, f) != -1) {
		lnum++;
		sshkey_free(ચાવી);
		ચાવી = ખાલી;
		/* Trim leading space and comments */
		cp = લીટી + strspn(લીટી, " \t");
		જો (*cp == '#' || *cp == '\0')
			ચાલુ;
		જો ((ચાવી = sshkey_new(ચાવી_UNSPEC)) == ખાલી)
			fatal("sshkey_new");
		જો ((r = sshkey_read(ચાવી, &cp)) != 0) {
			error_r(r, "%s:%lu: invalid key", path, lnum);
			ચાલુ;
		}
		જો (!sshkey_is_cert(ચાવી)) {
			error("%s:%lu is not a certificate", path, lnum);
			ચાલુ;
		}
		ok = 1;
		જો (!is_stdin && lnum == 1)
			printf("%s:\n", path);
		નહીંતર
			printf("%s:%lu:\n", path, lnum);
		print_cert(ચાવી);
	}
	મુક્ત(લીટી);
	sshkey_free(ચાવી);
	fclose(f);
	exit(ok ? 0 : 1);
}

સ્થિર શૂન્ય
load_krl(અચલ અક્ષર *path, સંરચના ssh_krl **krlp)
{
	સંરચના sshbuf *krlbuf;
	પૂર્ણાંક r;

	જો ((r = sshbuf_load_file(path, &krlbuf)) != 0)
		fatal_r(r, "Unable to load KRL %s", path);
	/* XXX check sigs */
	જો ((r = ssh_krl_from_blob(krlbuf, krlp)) != 0 ||
	    *krlp == ખાલી)
		fatal_r(r, "Invalid KRL file %s", path);
	sshbuf_free(krlbuf);
}

સ્થિર શૂન્ય
hash_to_blob(અચલ અક્ષર *cp, u_char **blobp, size_t *lenp,
    અચલ અક્ષર *file, u_long lnum)
{
	અક્ષર *tmp;
	size_t tlen;
	સંરચના sshbuf *b;
	પૂર્ણાંક r;

	જો ((cp = strprefix(cp, "SHA256:", 0)) == ખાલી)
		fatal("%s:%lu: unsupported hash algorithm", file, lnum);

	/*
	 * OpenSSH base64 hashes omit trailing '='
	 * characters; put them back for decode.
	 */
	જો ((tlen = strlen(cp)) >= SIZE_MAX - 5)
		fatal_f("hash too long: %zu bytes", tlen);
	tmp = xmalloc(tlen + 4 + 1);
	strlcpy(tmp, cp, tlen + 1);
	જ્યારે ((tlen % 4) != 0) {
		tmp[tlen++] = '=';
		tmp[tlen] = '\0';
	}
	જો ((b = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = sshbuf_b64tod(b, tmp)) != 0)
		fatal_r(r, "%s:%lu: decode hash failed", file, lnum);
	મુક્ત(tmp);
	*lenp = sshbuf_len(b);
	*blobp = xmalloc(*lenp);
	memcpy(*blobp, sshbuf_ptr(b), *lenp);
	sshbuf_free(b);
}

સ્થિર શૂન્ય
update_krl_from_file(સંરચના passwd *pw, અચલ અક્ષર *file, પૂર્ણાંક wild_ca,
    અચલ સંરચના sshkey *ca, સંરચના ssh_krl *krl)
{
	સંરચના sshkey *ચાવી = ખાલી;
	u_long lnum = 0;
	અક્ષર *path, *cp, *ep, *લીટી = ખાલી;
	u_char *blob = ખાલી;
	size_t blen = 0, linesize = 0;
	unsigned long long serial, serial2;
	પૂર્ણાંક i, was_explicit_ચાવી, was_sha1, was_sha256, was_hash, r;
	FILE *krl_spec;

	path = tilde_expand_filename(file, pw->pw_uid);
	જો (strcmp(path, "-") == 0) {
		krl_spec = stdin;
		મુક્ત(path);
		path = xstrdup("(standard input)");
	} નહીંતર જો ((krl_spec = fopen(path, "r")) == ખાલી)
		fatal("fopen %s: %s", path, strerror(errno));

	જો (!quiet)
		printf("Revoking from %s\n", path);
	જ્યારે (getline(&લીટી, &linesize, krl_spec) != -1) {
		જો (linesize >= INT_MAX) {
			fatal_f("%s contains unparsable line, len=%zu",
			    path, linesize);
		}
		lnum++;
		was_explicit_ચાવી = was_sha1 = was_sha256 = was_hash = 0;
		cp = લીટી + strspn(લીટી, " \t");
		/* Trim trailing space, comments and strip \n */
		માટે (i = 0, r = -1; cp[i] != '\0'; i++) {
			જો (cp[i] == '#' || cp[i] == '\n') {
				cp[i] = '\0';
				તોડો;
			}
			જો (cp[i] == ' ' || cp[i] == '\t') {
				/* Remember the start of a span of whitespace */
				જો (r == -1)
					r = i;
			} નહીંતર
				r = -1;
		}
		જો (r != -1)
			cp[r] = '\0';
		જો (*cp == '\0')
			ચાલુ;
		જો (strncasecmp(cp, "serial:", 7) == 0) {
			જો (ca == ખાલી && !wild_ca) {
				fatal("revoking certificates by serial number "
				    "requires specification of a CA key");
			}
			cp += 7;
			cp = cp + strspn(cp, " \t");
			errno = 0;
			serial = strtoull(cp, &ep, 0);
			જો (*cp == '\0' || (*ep != '\0' && *ep != '-'))
				fatal("%s:%lu: invalid serial \"%s\"",
				    path, lnum, cp);
			જો (errno == ERANGE && serial == ULLONG_MAX)
				fatal("%s:%lu: serial out of range",
				    path, lnum);
			serial2 = serial;
			જો (*ep == '-') {
				cp = ep + 1;
				errno = 0;
				serial2 = strtoull(cp, &ep, 0);
				જો (*cp == '\0' || *ep != '\0')
					fatal("%s:%lu: invalid serial \"%s\"",
					    path, lnum, cp);
				જો (errno == ERANGE && serial2 == ULLONG_MAX)
					fatal("%s:%lu: serial out of range",
					    path, lnum);
				જો (serial2 <= serial)
					fatal("%s:%lu: invalid serial range "
					    "%llu:%llu", path, lnum,
					    (unsigned long long)serial,
					    (unsigned long long)serial2);
			}
			જો (ssh_krl_revoke_cert_by_serial_range(krl,
			    ca, serial, serial2) != 0) {
				fatal_f("revoke serial failed");
			}
		} નહીંતર જો (strncasecmp(cp, "id:", 3) == 0) {
			જો (ca == ખાલી && !wild_ca) {
				fatal("revoking certificates by key ID "
				    "requires specification of a CA key");
			}
			cp += 3;
			cp = cp + strspn(cp, " \t");
			જો (ssh_krl_revoke_cert_by_ચાવી_id(krl, ca, cp) != 0)
				fatal_f("revoke key ID failed");
		} નહીંતર જો (strncasecmp(cp, "hash:", 5) == 0) {
			cp += 5;
			cp = cp + strspn(cp, " \t");
			hash_to_blob(cp, &blob, &blen, file, lnum);
			જો ((r = ssh_krl_revoke_ચાવી_sha256(krl,
			    blob, blen)) != 0)
				fatal_fr(r, "revoke key failed");
			મુક્ત(blob);
			blob = ખાલી;
			blen = 0;
		} નહીંતર {
			જો (strncasecmp(cp, "key:", 4) == 0) {
				cp += 4;
				cp = cp + strspn(cp, " \t");
				was_explicit_ચાવી = 1;
			} નહીંતર જો (strncasecmp(cp, "sha1:", 5) == 0) {
				cp += 5;
				cp = cp + strspn(cp, " \t");
				was_sha1 = 1;
			} નહીંતર જો (strncasecmp(cp, "sha256:", 7) == 0) {
				cp += 7;
				cp = cp + strspn(cp, " \t");
				was_sha256 = 1;
				/*
				 * Just try to process the line as a key.
				 * Parsing will fail if it isn't.
				 */
			}
			જો ((ચાવી = sshkey_new(ચાવી_UNSPEC)) == ખાલી)
				fatal("sshkey_new");
			જો ((r = sshkey_read(ચાવી, &cp)) != 0)
				fatal_r(r, "%s:%lu: invalid key", path, lnum);
			જો (was_explicit_ચાવી)
				r = ssh_krl_revoke_ચાવી_explicit(krl, ચાવી);
			નહીંતર જો (was_sha1) {
				જો (sshkey_fingerprint_raw(ચાવી,
				    SSH_DIGEST_SHA1, &blob, &blen) != 0) {
					fatal("%s:%lu: fingerprint failed",
					    file, lnum);
				}
				r = ssh_krl_revoke_ચાવી_sha1(krl, blob, blen);
			} નહીંતર જો (was_sha256) {
				જો (sshkey_fingerprint_raw(ચાવી,
				    SSH_DIGEST_SHA256, &blob, &blen) != 0) {
					fatal("%s:%lu: fingerprint failed",
					    file, lnum);
				}
				r = ssh_krl_revoke_ચાવી_sha256(krl, blob, blen);
			} નહીંતર
				r = ssh_krl_revoke_ચાવી(krl, ચાવી);
			જો (r != 0)
				fatal_fr(r, "revoke key failed");
			freezero(blob, blen);
			blob = ખાલી;
			blen = 0;
			sshkey_free(ચાવી);
		}
	}
	જો (strcmp(path, "-") != 0)
		fclose(krl_spec);
	મુક્ત(લીટી);
	મુક્ત(path);
}

સ્થિર શૂન્ય
do_gen_krl(સંરચના passwd *pw, પૂર્ણાંક updating, અચલ અક્ષર *ca_ચાવી_path,
    unsigned long long krl_version, અચલ અક્ષર *krl_comment,
    પૂર્ણાંક argc, અક્ષર **argv)
{
	સંરચના ssh_krl *krl;
	સંરચના stat sb;
	સંરચના sshkey *ca = ખાલી;
	પૂર્ણાંક i, r, wild_ca = 0;
	અક્ષર *tmp;
	સંરચના sshbuf *kbuf;

	જો (*identity_file == '\0')
		fatal("KRL generation requires an output file");
	જો (stat(identity_file, &sb) == -1) {
		જો (errno != ENOENT)
			fatal("Cannot access KRL \"%s\": %s",
			    identity_file, strerror(errno));
		જો (updating)
			fatal("KRL \"%s\" does not exist", identity_file);
	}
	જો (ca_ચાવી_path != ખાલી) {
		જો (strcasecmp(ca_ચાવી_path, "none") == 0)
			wild_ca = 1;
		નહીંતર {
			tmp = tilde_expand_filename(ca_ચાવી_path, pw->pw_uid);
			જો ((r = sshkey_load_public(tmp, &ca, ખાલી)) != 0)
				fatal_r(r, "Cannot load CA public key %s", tmp);
			મુક્ત(tmp);
		}
	}

	જો (updating)
		load_krl(identity_file, &krl);
	નહીંતર જો ((krl = ssh_krl_init()) == ખાલી)
		fatal("couldn't create KRL");

	જો (krl_version != 0)
		ssh_krl_set_version(krl, krl_version);
	જો (krl_comment != ખાલી)
		ssh_krl_set_comment(krl, krl_comment);

	માટે (i = 0; i < argc; i++)
		update_krl_from_file(pw, argv[i], wild_ca, ca, krl);

	જો ((kbuf = sshbuf_new()) == ખાલી)
		fatal("sshbuf_new failed");
	જો (ssh_krl_to_blob(krl, kbuf) != 0)
		fatal("Couldn't generate KRL");
	જો ((r = sshbuf_write_file(identity_file, kbuf)) != 0)
		fatal("write %s: %s", identity_file, strerror(errno));
	sshbuf_free(kbuf);
	ssh_krl_free(krl);
	sshkey_free(ca);
}

સ્થિર શૂન્ય
do_check_krl(સંરચના passwd *pw, પૂર્ણાંક print_krl, પૂર્ણાંક argc, અક્ષર **argv)
{
	પૂર્ણાંક i, r, ret = 0;
	અક્ષર *comment;
	સંરચના ssh_krl *krl;
	સંરચના sshkey *k;

	જો (*identity_file == '\0')
		fatal("KRL checking requires an input file");
	load_krl(identity_file, &krl);
	જો (print_krl)
		krl_dump(krl, stdout);
	માટે (i = 0; i < argc; i++) {
		જો ((r = sshkey_load_public(argv[i], &k, &comment)) != 0)
			fatal_r(r, "Cannot load public key %s", argv[i]);
		r = ssh_krl_check_ચાવી(krl, k);
		printf("%s%s%s%s: %s\n", argv[i],
		    *comment ? " (" : "", comment, *comment ? ")" : "",
		    r == 0 ? "ok" : "REVOKED");
		જો (r != 0)
			ret = 1;
		sshkey_free(k);
		મુક્ત(comment);
	}
	ssh_krl_free(krl);
	exit(ret);
}

સ્થિર સંરચના sshkey *
load_sign_ચાવી(અચલ અક્ષર *keypath, અચલ સંરચના sshkey *pubkey)
{
	size_t i, slen, plen = strlen(keypath);
	અક્ષર *privpath = xstrdup(keypath);
	સ્થિર અચલ અક્ષર * અચલ suffixes[] = { "-cert.pub", ".pub", ખાલી };
	સંરચના sshkey *ret = ખાલી, *privkey = ખાલી;
	પૂર્ણાંક r, waspub = 0;
	સંરચના stat st;

	/*
	 * If passed a public key filename, then try to locate the corresponding
	 * private key. This lets us specify certificates on the command-line
	 * and have ssh-keygen find the appropriate private key.
	 */
	માટે (i = 0; suffixes[i]; i++) {
		slen = strlen(suffixes[i]);
		જો (plen <= slen ||
		    strcmp(privpath + plen - slen, suffixes[i]) != 0)
			ચાલુ;
		privpath[plen - slen] = '\0';
		debug_f("%s looks like a public key, using private key "
		    "path %s instead", keypath, privpath);
		waspub = 1;
	}
	જો (waspub && stat(privpath, &st) != 0 && errno == ENOENT)
		fatal("No private key found for public key \"%s\"", keypath);
	જો ((r = sshkey_load_private(privpath, "", &privkey, ખાલી)) != 0 &&
	    (r != SSH_ERR_ચાવી_WRONG_PASSPHRASE)) {
		debug_fr(r, "load private key \"%s\"", privpath);
		fatal("No private key found for \"%s\"", privpath);
	} નહીંતર જો (privkey == ખાલી)
		privkey = load_identity(privpath, ખાલી);

	જો (!sshkey_equal_public(pubkey, privkey)) {
		error("Public key %s doesn't match private %s",
		    keypath, privpath);
		જાઓ done;
	}
	જો (sshkey_is_cert(pubkey) && !sshkey_is_cert(privkey)) {
		/*
		 * Graft the certificate onto the private key to make
		 * it capable of signing.
		 */
		જો ((r = sshkey_to_certified(privkey)) != 0) {
			error_fr(r, "sshkey_to_certified");
			જાઓ done;
		}
		જો ((r = sshkey_cert_copy(pubkey, privkey)) != 0) {
			error_fr(r, "sshkey_cert_copy");
			જાઓ done;
		}
	}
	/* success */
	ret = privkey;
	privkey = ખાલી;
 done:
	sshkey_free(privkey);
	મુક્ત(privpath);
	પાછા ret;
}

સ્થિર પૂર્ણાંક
sign_one(સંરચના sshkey *signkey, અચલ અક્ષર *filename, પૂર્ણાંક fd,
    અચલ અક્ષર *sig_namespace, અચલ અક્ષર *hashalg, sshsig_signer *signer,
    શૂન્ય *signer_ctx)
{
	સંરચના sshbuf *sigbuf = ખાલી, *abuf = ખાલી;
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR, wfd = -1, oerrno;
	અક્ષર *wfile = ખાલી, *asig = ખાલી, *fp = ખાલી;
	અક્ષર *pin = ખાલી, *prompt = ખાલી;

	જો (!quiet) {
		જો (fd == STDIN_FILENO)
			fprintf(stderr, "Signing data on standard input\n");
		નહીંતર
			fprintf(stderr, "Signing file %s\n", filename);
	}
	જો (signer == ખાલી && sshkey_is_sk(signkey)) {
		જો ((signkey->sk_flags & SSH_SK_USER_VERIFICATION_REQD)) {
			xasprintf(&prompt, "Enter PIN for %s key: ",
			    sshkey_type(signkey));
			જો ((pin = read_passphrase(prompt,
			    RP_ALLOW_STDIN)) == ખાલી)
				fatal_f("couldn't read PIN");
		}
		જો ((signkey->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
			જો ((fp = sshkey_fingerprint(signkey, fingerprint_hash,
			    SSH_FP_DEFAULT)) == ખાલી)
				fatal_f("fingerprint failed");
			fprintf(stderr, "Confirm user presence for key %s %s\n",
			    sshkey_type(signkey), fp);
			મુક્ત(fp);
		}
	}
	જો ((r = sshsig_sign_fd(signkey, hashalg, sk_provider, pin,
	    fd, sig_namespace, &sigbuf, signer, signer_ctx)) != 0) {
		error_r(r, "Signing %s failed", filename);
		જાઓ out;
	}
	જો ((r = sshsig_armor(sigbuf, &abuf)) != 0) {
		error_fr(r, "sshsig_armor");
		જાઓ out;
	}
	જો ((asig = sshbuf_dup_string(abuf)) == ખાલી) {
		error_f("buffer error");
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}

	જો (fd == STDIN_FILENO) {
		fputs(asig, stdout);
		fflush(stdout);
	} નહીંતર {
		xasprintf(&wfile, "%s.sig", filename);
		જો (confirm_overwrite(wfile)) {
			જો ((wfd = open(wfile, O_WRONLY|O_CREAT|O_TRUNC,
			    0666)) == -1) {
				oerrno = errno;
				error("Cannot open %s: %s",
				    wfile, strerror(errno));
				errno = oerrno;
				r = SSH_ERR_SYSTEM_ERROR;
				જાઓ out;
			}
			જો (atomicio(vwrite, wfd, asig,
			    strlen(asig)) != strlen(asig)) {
				oerrno = errno;
				error("Cannot write to %s: %s",
				    wfile, strerror(errno));
				errno = oerrno;
				r = SSH_ERR_SYSTEM_ERROR;
				જાઓ out;
			}
			જો (!quiet) {
				fprintf(stderr, "Write signature to %s\n",
				    wfile);
			}
		}
	}
	/* success */
	r = 0;
 out:
	મુક્ત(wfile);
	મુક્ત(prompt);
	મુક્ત(asig);
	જો (pin != ખાલી)
		freezero(pin, strlen(pin));
	sshbuf_free(abuf);
	sshbuf_free(sigbuf);
	જો (wfd != -1)
		close(wfd);
	પાછા r;
}

સ્થિર પૂર્ણાંક
sig_process_opts(અક્ષર * અચલ *opts, size_t nopts, અક્ષર **hashalgp,
    uint64_t *verify_timep, પૂર્ણાંક *print_pubkey)
{
	size_t i;
	time_t now;
	અચલ અક્ષર *p;

	જો (verify_timep != ખાલી)
		*verify_timep = 0;
	જો (print_pubkey != ખાલી)
		*print_pubkey = 0;
	જો (hashalgp != ખાલી)
		*hashalgp = ખાલી;
	માટે (i = 0; i < nopts; i++) {
		જો (hashalgp != ખાલી &&
		    (p = strprefix(opts[i], "hashalg=", 1)) != ખાલી) {
			*hashalgp = xstrdup(p);
		} નહીંતર જો (verify_timep &&
		    (p = strprefix(opts[i], "verify-time=", 1)) != ખાલી) {
			જો (parse_absolute_time(p, verify_timep) != 0 ||
			    *verify_timep == 0) {
				error("Invalid \"verify-time\" option");
				પાછા SSH_ERR_INVALID_ARGUMENT;
			}
		} નહીંતર જો (print_pubkey &&
		    strcasecmp(opts[i], "print-pubkey") == 0) {
			*print_pubkey = 1;
		} નહીંતર {
			error("Invalid option \"%s\"", opts[i]);
			પાછા SSH_ERR_INVALID_ARGUMENT;
		}
	}
	જો (verify_timep && *verify_timep == 0) {
		જો ((now = time(ખાલી)) < 0) {
			error("Time is before epoch");
			પાછા SSH_ERR_INVALID_ARGUMENT;
		}
		*verify_timep = (uint64_t)now;
	}
	પાછા 0;
}


સ્થિર પૂર્ણાંક
sig_sign(અચલ અક્ષર *keypath, અચલ અક્ષર *sig_namespace, પૂર્ણાંક require_agent,
    પૂર્ણાંક argc, અક્ષર **argv, અક્ષર * અચલ *opts, size_t nopts)
{
	પૂર્ણાંક i, fd = -1, r, ret = -1;
	પૂર્ણાંક agent_fd = -1;
	સંરચના sshkey *pubkey = ખાલી, *privkey = ખાલી, *signkey = ખાલી;
	sshsig_signer *signer = ખાલી;
	અક્ષર *hashalg = ખાલી;

	/* Check file arguments. */
	માટે (i = 0; i < argc; i++) {
		જો (strcmp(argv[i], "-") != 0)
			ચાલુ;
		જો (i > 0 || argc > 1)
			fatal("Cannot sign mix of paths and standard input");
	}

	જો (sig_process_opts(opts, nopts, &hashalg, ખાલી, ખાલી) != 0)
		જાઓ done; /* error already logged */

	જો ((r = sshkey_load_public(keypath, &pubkey, ખાલી)) != 0) {
		error_r(r, "Couldn't load public key %s", keypath);
		જાઓ done;
	}

	જો ((r = ssh_get_authentication_socket(&agent_fd)) != 0) {
		જો (require_agent)
			fatal("Couldn't get agent socket");
		debug_r(r, "Couldn't get agent socket");
	} નહીંતર {
		જો ((r = ssh_agent_has_ચાવી(agent_fd, pubkey)) == 0)
			signer = agent_signer;
		નહીંતર {
			જો (require_agent)
				fatal("Couldn't find key in agent");
			debug_r(r, "Couldn't find key in agent");
		}
	}

	જો (signer == ખાલી) {
		/* Not using agent - try to load private key */
		જો ((privkey = load_sign_ચાવી(keypath, pubkey)) == ખાલી)
			જાઓ done;
		signkey = privkey;
	} નહીંતર {
		/* Will use key in agent */
		signkey = pubkey;
	}

	જો (argc == 0) {
		જો ((r = sign_one(signkey, "(stdin)", STDIN_FILENO,
		    sig_namespace, hashalg, signer, &agent_fd)) != 0)
			જાઓ done;
	} નહીંતર {
		માટે (i = 0; i < argc; i++) {
			જો (strcmp(argv[i], "-") == 0)
				fd = STDIN_FILENO;
			નહીંતર જો ((fd = open(argv[i], O_RDONLY)) == -1) {
				error("Cannot open %s for signing: %s",
				    argv[i], strerror(errno));
				જાઓ done;
			}
			જો ((r = sign_one(signkey, argv[i], fd, sig_namespace,
			    hashalg, signer, &agent_fd)) != 0)
				જાઓ done;
			જો (fd != STDIN_FILENO)
				close(fd);
			fd = -1;
		}
	}

	ret = 0;
done:
	જો (fd != -1 && fd != STDIN_FILENO)
		close(fd);
	sshkey_free(pubkey);
	sshkey_free(privkey);
	મુક્ત(hashalg);
	પાછા ret;
}

સ્થિર પૂર્ણાંક
sig_verify(અચલ અક્ષર *signature, અચલ અક્ષર *sig_namespace,
    અચલ અક્ષર *principal, અચલ અક્ષર *allowed_ચાવીઓ, અચલ અક્ષર *revoked_ચાવીઓ,
    અક્ષર * અચલ *opts, size_t nopts)
{
	પૂર્ણાંક r, ret = -1;
	પૂર્ણાંક print_pubkey = 0;
	સંરચના sshbuf *sigbuf = ખાલી, *abuf = ખાલી;
	સંરચના sshkey *sign_ચાવી = ખાલી;
	અક્ષર *fp = ખાલી;
	સંરચના sshkey_sig_details *sig_details = ખાલી;
	uint64_t verify_time = 0;

	જો (sig_process_opts(opts, nopts, ખાલી, &verify_time,
	    &print_pubkey) != 0)
		જાઓ done; /* error already logged */

	memset(&sig_details, 0, કદ(sig_details));
	જો ((r = sshbuf_load_file(signature, &abuf)) != 0) {
		error_r(r, "Couldn't read signature file");
		જાઓ done;
	}

	જો ((r = sshsig_dearmor(abuf, &sigbuf)) != 0) {
		error_fr(r, "sshsig_armor");
		જાઓ done;
	}
	જો ((r = sshsig_verify_fd(sigbuf, STDIN_FILENO, sig_namespace,
	    &sign_ચાવી, &sig_details)) != 0)
		જાઓ done; /* sshsig_verify() prints error */

	જો ((fp = sshkey_fingerprint(sign_ચાવી, fingerprint_hash,
	    SSH_FP_DEFAULT)) == ખાલી)
		fatal_f("sshkey_fingerprint failed");
	debug("Valid (unverified) signature from key %s", fp);
	જો (sig_details != ખાલી) {
		debug2_f("signature details: counter = %u, flags = 0x%02x",
		    sig_details->sk_counter, sig_details->sk_flags);
	}
	મુક્ત(fp);
	fp = ખાલી;

	જો (revoked_ચાવીઓ != ખાલી) {
		જો ((r = sshkey_check_revoked(sign_ચાવી, revoked_ચાવીઓ)) != 0) {
			debug3_fr(r, "sshkey_check_revoked");
			જાઓ done;
		}
	}

	જો (allowed_ચાવીઓ != ખાલી && (r = sshsig_check_allowed_ચાવીઓ(allowed_ચાવીઓ,
	    sign_ચાવી, principal, sig_namespace, verify_time)) != 0) {
		debug3_fr(r, "sshsig_check_allowed_keys");
		જાઓ done;
	}
	/* success */
	ret = 0;
done:
	જો (!quiet) {
		જો (ret == 0) {
			જો ((fp = sshkey_fingerprint(sign_ચાવી, fingerprint_hash,
			    SSH_FP_DEFAULT)) == ખાલી)
				fatal_f("sshkey_fingerprint failed");
			જો (principal == ખાલી) {
				printf("Good \"%s\" signature with %s key %s\n",
				    sig_namespace, sshkey_type(sign_ચાવી), fp);

			} નહીંતર {
				printf("Good \"%s\" signature for %s with %s key %s\n",
				    sig_namespace, principal,
				    sshkey_type(sign_ચાવી), fp);
			}
		} નહીંતર {
			printf("Could not verify signature.\n");
		}
	}
	/* Print the signature key if requested */
	જો (ret == 0 && print_pubkey && sign_ચાવી != ખાલી) {
		જો ((r = sshkey_write(sign_ચાવી, stdout)) == 0)
			fputc('\n', stdout);
		નહીંતર {
			error_r(r, "Could not print public key.\n");
			ret = -1;
		}
	}
	sshbuf_free(sigbuf);
	sshbuf_free(abuf);
	sshkey_free(sign_ચાવી);
	sshkey_sig_details_free(sig_details);
	મુક્ત(fp);
	પાછા ret;
}

સ્થિર પૂર્ણાંક
sig_find_principals(અચલ અક્ષર *signature, અચલ અક્ષર *allowed_ચાવીઓ,
    અક્ષર * અચલ *opts, size_t nopts)
{
	પૂર્ણાંક r, ret = -1;
	સંરચના sshbuf *sigbuf = ખાલી, *abuf = ખાલી;
	સંરચના sshkey *sign_ચાવી = ખાલી;
	અક્ષર *principals = ખાલી, *cp, *tmp;
	uint64_t verify_time = 0;

	જો (sig_process_opts(opts, nopts, ખાલી, &verify_time, ખાલી) != 0)
		જાઓ done; /* error already logged */

	જો ((r = sshbuf_load_file(signature, &abuf)) != 0) {
		error_r(r, "Couldn't read signature file");
		જાઓ done;
	}
	જો ((r = sshsig_dearmor(abuf, &sigbuf)) != 0) {
		error_fr(r, "sshsig_armor");
		જાઓ done;
	}
	જો ((r = sshsig_get_pubkey(sigbuf, &sign_ચાવી)) != 0) {
		error_fr(r, "sshsig_get_pubkey");
		જાઓ done;
	}
	જો ((r = sshsig_find_principals(allowed_ચાવીઓ, sign_ચાવી,
	    verify_time, &principals)) != 0) {
		જો (r != SSH_ERR_ચાવી_NOT_FOUND)
			error_fr(r, "sshsig_find_principal");
		જાઓ done;
	}
	ret = 0;
done:
	જો (ret == 0 ) {
		/* Emit matching principals one per line */
		tmp = principals;
		જ્યારે ((cp = strsep(&tmp, ",")) != ખાલી && *cp != '\0')
			puts(cp);
	} નહીંતર {
		fprintf(stderr, "No principal matched.\n");
	}
	sshbuf_free(sigbuf);
	sshbuf_free(abuf);
	sshkey_free(sign_ચાવી);
	મુક્ત(principals);
	પાછા ret;
}

સ્થિર પૂર્ણાંક
sig_match_principals(અચલ અક્ષર *allowed_ચાવીઓ, અક્ષર *principal,
	અક્ષર * અચલ *opts, size_t nopts)
{
	પૂર્ણાંક r;
	અક્ષર **principals = ખાલી;
	size_t i, nprincipals = 0;

	જો ((r = sig_process_opts(opts, nopts, ખાલી, ખાલી, ખાલી)) != 0)
		પાછા r; /* error already logged */

	જો ((r = sshsig_match_principals(allowed_ચાવીઓ, principal,
	    &principals, &nprincipals)) != 0) {
		debug_f("match: %s", ssh_err(r));
		fprintf(stderr, "No principal matched.\n");
		પાછા r;
	}
	માટે (i = 0; i < nprincipals; i++) {
		printf("%s\n", principals[i]);
		મુક્ત(principals[i]);
	}
	મુક્ત(principals);

	પાછા 0;
}

સ્થિર શૂન્ય
do_moduli_gen(અચલ અક્ષર *out_file, અક્ષર **opts, size_t nopts)
{
#ifdef WITH_OPENSSL
	/* Moduli generation/screening */
	BIGNUM *start = ખાલી;
	પૂર્ણાંક moduli_bits = 0;
	FILE *out;
	size_t i;
	અચલ અક્ષર *errstr, *p;

	/* Parse options */
	માટે (i = 0; i < nopts; i++) {
		જો ((p = strprefix(opts[i], "start=", 0)) != ખાલી) {
			/* XXX - also compare length against bits */
			જો (BN_hex2bn(&start, p) == 0)
				fatal("Invalid start point.");
		} નહીંતર જો ((p = strprefix(opts[i], "bits=", 0)) != ખાલી) {
			moduli_bits = (પૂર્ણાંક)strtonum(p, 1, INT_MAX, &errstr);
			જો (errstr) {
				fatal("Invalid number: %s (%s)", p, errstr);
			}
		} નહીંતર {
			fatal("Option \"%s\" is unsupported for moduli "
			    "generation", opts[i]);
		}
	}

	જો (strcmp(out_file, "-") == 0)
		out = stdout;
	નહીંતર જો ((out = fopen(out_file, "w")) == ખાલી) {
		fatal("Couldn't open modulus candidate file \"%s\": %s",
		    out_file, strerror(errno));
	}
	setvbuf(out, ખાલી, _IOLBF, 0);

	જો (moduli_bits == 0)
		moduli_bits = DEFAULT_BITS;
	જો (gen_candidates(out, moduli_bits, start) != 0)
		fatal("modulus candidate generation failed");
#નહીંતર /* WITH_OPENSSL */
	fatal("Moduli generation is not supported");
#endif /* WITH_OPENSSL */
}

સ્થિર શૂન્ય
do_moduli_screen(અચલ અક્ષર *out_file, અક્ષર **opts, size_t nopts)
{
#ifdef WITH_OPENSSL
	/* Moduli generation/screening */
	અક્ષર *checkpoint = ખાલી;
	uint32_t generator_wanted = 0;
	unsigned long start_lineno = 0, લીટીઓ_to_process = 0;
	પૂર્ણાંક અવિભાજ્ય_tests = 0;
	FILE *out, *in = stdin;
	size_t i;
	અચલ અક્ષર *errstr, *p;

	/* Parse options */
	માટે (i = 0; i < nopts; i++) {
		જો ((p = strprefix(opts[i], "lines=", 0)) != ખાલી) {
			લીટીઓ_to_process = strtoul(p, ખાલી, 10);
		} નહીંતર જો ((p = strprefix(opts[i], "start-line=", 0)) != ખાલી) {
			start_lineno = strtoul(p, ખાલી, 10);
		} નહીંતર જો ((p = strprefix(opts[i], "checkpoint=", 0)) != ખાલી) {
			મુક્ત(checkpoint);
			checkpoint = xstrdup(p);
		} નહીંતર જો ((p = strprefix(opts[i], "generator=", 0)) != ખાલી) {
			generator_wanted = (uint32_t)strtonum(p, 1, UINT_MAX,
			    &errstr);
			જો (errstr != ખાલી) {
				fatal("Generator invalid: %s (%s)", p, errstr);
			}
		} નહીંતર જો ((p = strprefix(opts[i], "prime-tests=", 0)) != ખાલી) {
			અવિભાજ્ય_tests = (પૂર્ણાંક)strtonum(p, 1, INT_MAX, &errstr);
			જો (errstr) {
				fatal("Invalid number: %s (%s)", p, errstr);
			}
		} નહીંતર {
			fatal("Option \"%s\" is unsupported for moduli "
			    "screening", opts[i]);
		}
	}

	જો (have_identity && strcmp(identity_file, "-") != 0) {
		જો ((in = fopen(identity_file, "r")) == ખાલી) {
			fatal("Couldn't open modulus candidate "
			    "file \"%s\": %s", identity_file,
			    strerror(errno));
		}
	}

	જો (strcmp(out_file, "-") == 0)
		out = stdout;
	નહીંતર જો ((out = fopen(out_file, "a")) == ખાલી) {
		fatal("Couldn't open moduli file \"%s\": %s",
		    out_file, strerror(errno));
	}
	setvbuf(out, ખાલી, _IOLBF, 0);
	જો (અવિભાજ્ય_test(in, out, અવિભાજ્ય_tests == 0 ? 100 : અવિભાજ્ય_tests,
	    generator_wanted, checkpoint,
	    start_lineno, લીટીઓ_to_process) != 0)
		fatal("modulus screening failed");
	જો (in != stdin)
		(શૂન્ય)fclose(in);
	મુક્ત(checkpoint);
#નહીંતર /* WITH_OPENSSL */
	fatal("Moduli screening is not supported");
#endif /* WITH_OPENSSL */
}

/* Read and confirm a passphrase */
સ્થિર અક્ષર *
read_check_passphrase(અચલ અક્ષર *prompt1, અચલ અક્ષર *prompt2,
    અચલ અક્ષર *retry_prompt)
{
	અક્ષર *passphrase1, *passphrase2;

	માટે (;;) {
		passphrase1 = read_passphrase(prompt1, RP_ALLOW_STDIN);
		passphrase2 = read_passphrase(prompt2, RP_ALLOW_STDIN);
		જો (strcmp(passphrase1, passphrase2) == 0) {
			freezero(passphrase2, strlen(passphrase2));
			પાછા passphrase1;
		}
		/* The passphrases do not match. Clear them and retry. */
		freezero(passphrase1, strlen(passphrase1));
		freezero(passphrase2, strlen(passphrase2));
		fputs(retry_prompt, stdout);
		fputc('\n', stdout);
		fflush(stdout);
	}
	/* NOTREACHED */
	પાછા ખાલી;
}

સ્થિર અક્ષર *
private_ચાવી_passphrase(અચલ અક્ષર *path)
{
	અક્ષર *prompt, *ret;

	જો (identity_passphrase)
		પાછા xstrdup(identity_passphrase);
	જો (identity_new_passphrase)
		પાછા xstrdup(identity_new_passphrase);

	xasprintf(&prompt, "Enter passphrase for \"%s\" "
	    "(empty for no passphrase): ", path);
	ret = read_check_passphrase(prompt,
	    "Enter same passphrase again: ",
	    "Passphrases do not match.  Try again.");
	મુક્ત(prompt);
	પાછા ret;
}

સ્થિર અક્ષર *
sk_suffix(અચલ અક્ષર *application, અચલ uint8_t *user, size_t userlen)
{
	અક્ષર *ret, *cp;
	અચલ અક્ષર *p;
	size_t slen, i;

	/* Trim off URL-like preamble */
	જો ((p = strprefix(application, "ssh://", 0)) != ખાલી)
		ret =  xstrdup(p);
	નહીંતર જો ((p = strprefix(application, "ssh:", 0)) != ખાલી)
		ret =  xstrdup(p);
	નહીંતર
		ret = xstrdup(application);

	/* Count trailing zeros in user */
	માટે (i = 0; i < userlen; i++) {
		જો (user[userlen - i - 1] != 0)
			તોડો;
	}
	જો (i >= userlen)
		પાછા ret; /* user-id was default all-zeros */

	/* Append user-id, escaping non-UTF-8 characters */
	slen = userlen - i;
	જો (asmprintf(&cp, INT_MAX, ખાલી, "%.*s", (પૂર્ણાંક)slen, user) == -1)
		fatal_f("asmprintf failed");
	/* Don't emit a user-id that contains path or control characters */
	જો (strchr(cp, '/') != ખાલી || strstr(cp, "..") != ખાલી ||
	    strchr(cp, '\\') != ખાલી) {
		મુક્ત(cp);
		cp = tohex(user, slen);
	}
	xextendf(&ret, "_", "%s", cp);
	મુક્ત(cp);
	પાછા ret;
}

સ્થિર પૂર્ણાંક
do_download_sk(અચલ અક્ષર *skprovider, અચલ અક્ષર *device)
{
	સંરચના sshsk_resident_ચાવી **srks;
	size_t nsrks, i;
	પૂર્ણાંક r, ret = -1;
	અક્ષર *fp, *pin = ખાલી, *pass = ખાલી, *path, *pubpath;
	અચલ અક્ષર *ext;
	સંરચના sshkey *ચાવી;

	જો (skprovider == ખાલી)
		fatal("Cannot download keys without provider");

	pin = read_passphrase("Enter PIN for authenticator: ", RP_ALLOW_STDIN);
	જો (!quiet) {
		printf("You may need to touch your authenticator "
		    "to authorize key download.\n");
	}
	જો ((r = sshsk_load_resident(skprovider, device, pin, 0,
	    &srks, &nsrks)) != 0) {
		જો (pin != ખાલી)
			freezero(pin, strlen(pin));
		error_r(r, "Unable to load resident keys");
		પાછા -1;
	}
	જો (nsrks == 0)
		logit("No keys to download");
	જો (pin != ખાલી)
		freezero(pin, strlen(pin));

	માટે (i = 0; i < nsrks; i++) {
		ચાવી = srks[i]->ચાવી;
		જો (ચાવી->type != ચાવી_ECDSA_SK && ચાવી->type != ચાવી_ED25519_SK) {
			error("Unsupported key type %s (%d)",
			    sshkey_type(ચાવી), ચાવી->type);
			ચાલુ;
		}
		જો ((fp = sshkey_fingerprint(ચાવી, fingerprint_hash,
		    SSH_FP_DEFAULT)) == ખાલી)
			fatal_f("sshkey_fingerprint failed");
		debug_f("key %zu: %s %s %s (flags 0x%02x)", i,
		    sshkey_type(ચાવી), fp, ચાવી->sk_application, ચાવી->sk_flags);
		ext = sk_suffix(ચાવી->sk_application,
		    srks[i]->user_id, srks[i]->user_id_len);
		xasprintf(&path, "id_%s_rk%s%s",
		    ચાવી->type == ચાવી_ECDSA_SK ? "ecdsa_sk" : "ed25519_sk",
		    *ext == '\0' ? "" : "_", ext);

		/* If the file already exists, ask the user to confirm. */
		જો (!confirm_overwrite(path)) {
			મુક્ત(path);
			તોડો;
		}

		/* Save the key with the application string as the comment */
		જો (pass == ખાલી)
			pass = private_ચાવી_passphrase(path);
		જો ((r = sshkey_save_private(ચાવી, path, pass,
		    ચાવી->sk_application, private_ચાવી_format,
		    openssh_format_cipher, rounds)) != 0) {
			error_r(r, "Saving key \"%s\" failed", path);
			મુક્ત(path);
			તોડો;
		}
		જો (!quiet) {
			printf("Saved %s key%s%s to %s\n", sshkey_type(ચાવી),
			    *ext != '\0' ? " " : "",
			    *ext != '\0' ? ચાવી->sk_application : "",
			    path);
		}

		/* Save public key too */
		xasprintf(&pubpath, "%s.pub", path);
		મુક્ત(path);
		જો ((r = sshkey_save_public(ચાવી, pubpath,
		    ચાવી->sk_application)) != 0) {
			error_r(r, "Saving public key \"%s\" failed", pubpath);
			મુક્ત(pubpath);
			તોડો;
		}
		મુક્ત(pubpath);
	}

	જો (i >= nsrks)
		ret = 0; /* success */
	જો (pass != ખાલી)
		freezero(pass, strlen(pass));
	sshsk_free_resident_ચાવીઓ(srks, nsrks);
	પાછા ret;
}

સ્થિર શૂન્ય
save_attestation(સંરચના sshbuf *attest, અચલ અક્ષર *path)
{
	mode_t omask;
	પૂર્ણાંક r;

	જો (path == ખાલી)
		પાછા; /* nothing to do */
	જો (attest == ખાલી || sshbuf_len(attest) == 0)
		fatal("Enrollment did not return attestation data");
	omask = umask(077);
	r = sshbuf_write_file(path, attest);
	umask(omask);
	જો (r != 0)
		fatal_r(r, "Unable to write attestation data \"%s\"", path);
	જો (!quiet)
		printf("Your FIDO attestation certificate has been saved in "
		    "%s\n", path);
}

સ્થિર પૂર્ણાંક
confirm_sk_overwrite(અચલ અક્ષર *application, અચલ અક્ષર *user)
{
	અક્ષર yesno[3];

	printf("A resident key scoped to '%s' with user id '%s' already "
	    "exists.\n", application == ખાલી ? "ssh:" : application,
	    user == ખાલી ? "null" : user);
	printf("Overwrite key in token (y/n)? ");
	fflush(stdout);
	જો (fgets(yesno, કદ(yesno), stdin) == ખાલી)
		પાછા 0;
	જો (yesno[0] != 'y' && yesno[0] != 'Y')
		પાછા 0;
	પાછા 1;
}

સ્થિર શૂન્ય
usage(શૂન્ય)
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
પૂર્ણાંક
મુખ્ય(પૂર્ણાંક argc, અક્ષર **argv)
{
	અક્ષર comment[ચાવી_COMMENT_MAX], *passphrase = ખાલી;
	અક્ષર *rr_hostname = ખાલી, *ep, *fp, *ra;
	સંરચના sshkey *ખાનગી = ખાલી, *જાહેર = ખાલી;
	સંરચના passwd *pw;
	પૂર્ણાંક ret = 0, r, opt, type;
	પૂર્ણાંક change_passphrase = 0, change_comment = 0, show_cert = 0;
	પૂર્ણાંક find_host = 0, delete_host = 0, hash_hosts = 0;
	પૂર્ણાંક gen_all_hostkeys = 0, gen_krl = 0, update_krl = 0, check_krl = 0;
	પૂર્ણાંક prefer_agent = 0, convert_to = 0, convert_from = 0;
	પૂર્ણાંક print_public = 0, print_generic = 0, cert_serial_autoinc = 0;
	પૂર્ણાંક do_gen_candidates = 0, do_screen_candidates = 0, download_sk = 0;
	unsigned long long cert_serial = 0;
	અક્ષર *identity_comment = ખાલી, *ca_ચાવી_path = ખાલી, **opts = ખાલી;
	અક્ષર *sk_application = ખાલી, *sk_device = ખાલી, *sk_user = ખાલી;
	અક્ષર *sk_attestation_path = ખાલી;
	સંરચના sshbuf *challenge = ખાલી, *attest = ખાલી;
	size_t i, nopts = 0;
	uint32_t bits = 0;
	uint8_t sk_flags = SSH_SK_USER_PRESENCE_REQD;
	અચલ અક્ષર *errstr, *p;
	પૂર્ણાંક log_level = SYSLOG_LEVEL_INFO;
	અક્ષર *sign_op = ખાલી;

	બાહ્ય પૂર્ણાંક optind;
	બાહ્ય અક્ષર *optarg;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	__progname = ssh_get_progname(argv[0]);

	seed_rng();

	log_init(argv[0], SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_USER, 1);

	msetlocale();

	/* we need this for the home * directory.  */
	pw = getpwuid(getuid());
	જો (!pw)
		fatal("No user exists for uid %lu", (u_long)getuid());
	pw = pwcopy(pw);
	જો (gethostname(hostname, કદ(hostname)) == -1)
		fatal("gethostname: %s", strerror(errno));

	sk_provider = getenv("SSH_SK_PROVIDER");

	/* Remaining characters: dGjJSTWx */
	જ્યારે ((opt = getopt(argc, argv, "ABHKLQUXceghiklopquvy"
	    "C:D:E:F:I:M:N:O:P:R:V:Y:Z:"
	    "a:b:f:g:m:n:r:s:t:w:z:")) != -1) {
		પસંદગી (opt) {
		સ્થિતિ 'A':
			gen_all_hostkeys = 1;
			તોડો;
		સ્થિતિ 'b':
			bits = (uint32_t)strtonum(optarg, 1, UINT32_MAX,
			    &errstr);
			જો (errstr)
				fatal("Bits has bad value %s (%s)",
					optarg, errstr);
			તોડો;
		સ્થિતિ 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			જો (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			તોડો;
		સ્થિતિ 'F':
			find_host = 1;
			rr_hostname = optarg;
			તોડો;
		સ્થિતિ 'H':
			hash_hosts = 1;
			તોડો;
		સ્થિતિ 'I':
			cert_ચાવી_id = optarg;
			તોડો;
		સ્થિતિ 'R':
			delete_host = 1;
			rr_hostname = optarg;
			તોડો;
		સ્થિતિ 'L':
			show_cert = 1;
			તોડો;
		સ્થિતિ 'l':
			print_fingerprint = 1;
			તોડો;
		સ્થિતિ 'B':
			print_bubblebabble = 1;
			તોડો;
		સ્થિતિ 'm':
			જો (strcasecmp(optarg, "RFC4716") == 0 ||
			    strcasecmp(optarg, "ssh2") == 0) {
				convert_format = FMT_RFC4716;
				તોડો;
			}
			જો (strcasecmp(optarg, "PKCS8") == 0) {
				convert_format = FMT_PKCS8;
				private_ચાવી_format = SSHKEY_PRIVATE_PKCS8;
				તોડો;
			}
			જો (strcasecmp(optarg, "PEM") == 0) {
				convert_format = FMT_PEM;
				private_ચાવી_format = SSHKEY_PRIVATE_PEM;
				તોડો;
			}
			જો (strcasecmp(optarg, "hexdump") == 0) {
				convert_format = FMT_HEXDUMP;
				તોડો;
			}
			fatal("Unsupported conversion format \"%s\"", optarg);
		સ્થિતિ 'n':
			cert_principals = optarg;
			તોડો;
		સ્થિતિ 'o':
			/* no-op; new format is already the default */
			તોડો;
		સ્થિતિ 'p':
			change_passphrase = 1;
			તોડો;
		સ્થિતિ 'c':
			change_comment = 1;
			તોડો;
		સ્થિતિ 'f':
			જો (strlcpy(identity_file, optarg,
			    કદ(identity_file)) >= કદ(identity_file))
				fatal("Identity filename too long");
			have_identity = 1;
			તોડો;
		સ્થિતિ 'g':
			print_generic = 1;
			તોડો;
		સ્થિતિ 'K':
			download_sk = 1;
			તોડો;
		સ્થિતિ 'P':
			identity_passphrase = optarg;
			તોડો;
		સ્થિતિ 'N':
			identity_new_passphrase = optarg;
			તોડો;
		સ્થિતિ 'Q':
			check_krl = 1;
			તોડો;
		સ્થિતિ 'O':
			opts = xrecallocarray(opts, nopts, nopts + 1,
			    કદ(*opts));
			opts[nopts++] = xstrdup(optarg);
			તોડો;
		સ્થિતિ 'Z':
			openssh_format_cipher = optarg;
			જો (cipher_by_name(openssh_format_cipher) == ખાલી)
				fatal("Invalid OpenSSH-format cipher '%s'",
				    openssh_format_cipher);
			તોડો;
		સ્થિતિ 'C':
			identity_comment = optarg;
			તોડો;
		સ્થિતિ 'q':
			quiet = 1;
			તોડો;
		સ્થિતિ 'e':
			/* export key */
			convert_to = 1;
			તોડો;
		સ્થિતિ 'h':
			cert_ચાવી_type = SSH2_CERT_TYPE_HOST;
			certflags_flags = 0;
			તોડો;
		સ્થિતિ 'k':
			gen_krl = 1;
			તોડો;
		સ્થિતિ 'i':
		સ્થિતિ 'X':
			/* import key */
			convert_from = 1;
			તોડો;
		સ્થિતિ 'y':
			print_public = 1;
			તોડો;
		સ્થિતિ 's':
			ca_ચાવી_path = optarg;
			તોડો;
		સ્થિતિ 't':
			ચાવી_type_name = optarg;
			તોડો;
		સ્થિતિ 'D':
			pkcs11provider = optarg;
			તોડો;
		સ્થિતિ 'U':
			prefer_agent = 1;
			તોડો;
		સ્થિતિ 'u':
			update_krl = 1;
			તોડો;
		સ્થિતિ 'v':
			જો (log_level == SYSLOG_LEVEL_INFO)
				log_level = SYSLOG_LEVEL_DEBUG1;
			નહીંતર {
				જો (log_level >= SYSLOG_LEVEL_DEBUG1 &&
				    log_level < SYSLOG_LEVEL_DEBUG3)
					log_level++;
			}
			તોડો;
		સ્થિતિ 'r':
			rr_hostname = optarg;
			તોડો;
		સ્થિતિ 'a':
			rounds = (પૂર્ણાંક)strtonum(optarg, 1, INT_MAX, &errstr);
			જો (errstr)
				fatal("Invalid number: %s (%s)",
					optarg, errstr);
			તોડો;
		સ્થિતિ 'V':
			parse_cert_times(optarg);
			તોડો;
		સ્થિતિ 'Y':
			sign_op = optarg;
			તોડો;
		સ્થિતિ 'w':
			sk_provider = optarg;
			તોડો;
		સ્થિતિ 'z':
			errno = 0;
			જો (*optarg == '+') {
				cert_serial_autoinc = 1;
				optarg++;
			}
			cert_serial = strtoull(optarg, &ep, 10);
			જો (*optarg < '0' || *optarg > '9' || *ep != '\0' ||
			    (errno == ERANGE && cert_serial == ULLONG_MAX))
				fatal("Invalid serial number \"%s\"", optarg);
			તોડો;
		સ્થિતિ 'M':
			જો (strcmp(optarg, "generate") == 0)
				do_gen_candidates = 1;
			નહીંતર જો (strcmp(optarg, "screen") == 0)
				do_screen_candidates = 1;
			નહીંતર
				fatal("Unsupported moduli option %s", optarg);
			તોડો;
		મૂળભૂત:
			usage();
		}
	}

#ifdef ENABLE_SK_INTERNAL
	જો (sk_provider == ખાલી)
		sk_provider = "internal";
#endif

	/* reinit */
	log_init(argv[0], log_level, SYSLOG_FACILITY_USER, 1);

	argv += optind;
	argc -= optind;

	જો (sign_op != ખાલી) {
		જો (strprefix(sign_op, "find-principals", 0) != ખાલી) {
			જો (ca_ચાવી_path == ખાલી) {
				error("Too few arguments for find-principals:"
				    "missing signature file");
				exit(1);
			}
			જો (!have_identity) {
				error("Too few arguments for find-principals:"
				    "missing allowed keys file");
				exit(1);
			}
			ret = sig_find_principals(ca_ચાવી_path, identity_file,
			    opts, nopts);
			જાઓ done;
		} નહીંતર જો (strprefix(sign_op, "match-principals", 0) != ખાલી) {
			જો (!have_identity) {
				error("Too few arguments for match-principals:"
				    "missing allowed keys file");
				exit(1);
			}
			જો (cert_ચાવી_id == ખાલી) {
				error("Too few arguments for match-principals: "
				    "missing principal ID");
				exit(1);
			}
			ret = sig_match_principals(identity_file, cert_ચાવી_id,
			    opts, nopts);
			જાઓ done;
		} નહીંતર જો (strprefix(sign_op, "sign", 0) != ખાલી) {
			/* NB. cert_principals is actually namespace, via -n */
			જો (cert_principals == ખાલી ||
			    *cert_principals == '\0') {
				error("Too few arguments for sign: "
				    "missing namespace");
				exit(1);
			}
			જો (!have_identity) {
				error("Too few arguments for sign: "
				    "missing key");
				exit(1);
			}
			ret = sig_sign(identity_file, cert_principals,
			    prefer_agent, argc, argv, opts, nopts);
			જાઓ done;
		} નહીંતર જો (strprefix(sign_op, "check-novalidate", 0) != ખાલી) {
			/* NB. cert_principals is actually namespace, via -n */
			જો (cert_principals == ખાલી ||
			    *cert_principals == '\0') {
				error("Too few arguments for check-novalidate: "
				    "missing namespace");
				exit(1);
			}
			જો (ca_ચાવી_path == ખાલી) {
				error("Too few arguments for check-novalidate: "
				    "missing signature file");
				exit(1);
			}
			ret = sig_verify(ca_ચાવી_path, cert_principals,
			    ખાલી, ખાલી, ખાલી, opts, nopts);
			જાઓ done;
		} નહીંતર જો (strprefix(sign_op, "verify", 0) != ખાલી) {
			/* NB. cert_principals is actually namespace, via -n */
			જો (cert_principals == ખાલી ||
			    *cert_principals == '\0') {
				error("Too few arguments for verify: "
				    "missing namespace");
				exit(1);
			}
			જો (ca_ચાવી_path == ખાલી) {
				error("Too few arguments for verify: "
				    "missing signature file");
				exit(1);
			}
			જો (!have_identity) {
				error("Too few arguments for sign: "
				    "missing allowed keys file");
				exit(1);
			}
			જો (cert_ચાવી_id == ખાલી) {
				error("Too few arguments for verify: "
				    "missing principal identity");
				exit(1);
			}
			ret = sig_verify(ca_ચાવી_path, cert_principals,
			    cert_ચાવી_id, identity_file, rr_hostname,
			    opts, nopts);
			જાઓ done;
		}
		error("Unsupported operation for -Y: \"%s\"", sign_op);
		usage();
		/* NOTREACHED */
	}

	જો (ca_ચાવી_path != ખાલી) {
		જો (argc < 1 && !gen_krl) {
			error("Too few arguments.");
			usage();
		}
	} નહીંતર જો (argc > 0 && !gen_krl && !check_krl &&
	    !do_gen_candidates && !do_screen_candidates) {
		error("Too many arguments.");
		usage();
	}
	જો (change_passphrase && change_comment) {
		error("Can only have one of -p and -c.");
		usage();
	}
	જો (print_fingerprint && (delete_host || hash_hosts)) {
		error("Cannot use -l with -H or -R.");
		usage();
	}
	જો (gen_krl) {
		do_gen_krl(pw, update_krl, ca_ચાવી_path,
		    cert_serial, identity_comment, argc, argv);
		જાઓ done;
	}
	જો (check_krl) {
		do_check_krl(pw, print_fingerprint, argc, argv);
		જાઓ done;
	}
	જો (ca_ચાવી_path != ખાલી) {
		જો (cert_ચાવી_id == ખાલી)
			fatal("Must specify key id (-I) when certifying");
		જો (cert_principals == ખાલી) {
			/*
			 * Ideally this would be a fatal(), but we need to
			 * be able to generate such certificates for testing
			 * even though they will be rejected.
			 */
			error("Warning: certificate will contain no "
			    "principals (-n)");
		}
		માટે (i = 0; i < nopts; i++)
			add_cert_option(opts[i]);
		do_ca_sign(pw, ca_ચાવી_path, prefer_agent,
		    cert_serial, cert_serial_autoinc, argc, argv);
		જાઓ done;
	}
	જો (show_cert)
		do_show_cert(pw);
	જો (delete_host || hash_hosts || find_host) {
		do_known_hosts(pw, rr_hostname, find_host,
		    delete_host, hash_hosts);
	}
	જો (pkcs11provider != ખાલી)
		do_download(pw);
	જો (download_sk) {
		માટે (i = 0; i < nopts; i++) {
			જો ((p = strprefix(opts[i], "device=", 1)) != ખાલી) {
				sk_device = xstrdup(p);
			} નહીંતર {
				fatal("Option \"%s\" is unsupported for "
				    "FIDO authenticator download", opts[i]);
			}
		}
		ret = do_download_sk(sk_provider, sk_device);
		જાઓ done;
	}
	જો (print_fingerprint || print_bubblebabble)
		do_fingerprint(pw);
	જો (change_passphrase)
		do_change_passphrase(pw, opts, nopts);
	જો (change_comment)
		do_change_comment(pw, identity_comment);
#ifdef WITH_OPENSSL
	જો (convert_to) {
		do_convert_to(pw);
		જાઓ done;
	}
	જો (convert_from) {
		do_convert_from(pw);
		જાઓ done;
	}
#નહીંતર /* WITH_OPENSSL */
	જો (convert_to || convert_from)
		fatal("key conversion disabled at compile time");
#endif /* WITH_OPENSSL */
	જો (print_public)
		do_print_public(pw);
	જો (rr_hostname != ખાલી) {
		unsigned પૂર્ણાંક n = 0;

		જો (have_identity) {
			n = do_print_resource_record(pw, identity_file,
			    rr_hostname, print_generic, opts, nopts);
			જો (n == 0)
				fatal("%s: %s", identity_file, strerror(errno));
			exit(0);
		} નહીંતર {

			n += do_print_resource_record(pw,
			    PATH_HOST_RSA_ચાવી_FILE, rr_hostname,
			    print_generic, opts, nopts);
			n += do_print_resource_record(pw,
			    PATH_HOST_ECDSA_ચાવી_FILE, rr_hostname,
			    print_generic, opts, nopts);
			n += do_print_resource_record(pw,
			    PATH_HOST_ED25519_ચાવી_FILE, rr_hostname,
			    print_generic, opts, nopts);
			જો (n == 0)
				fatal("no keys found.");
			exit(0);
		}
	}

	જો (do_gen_candidates || do_screen_candidates) {
		જો (argc <= 0)
			fatal("No output file specified");
		નહીંતર જો (argc > 1)
			fatal("Too many output files specified");
	}
	જો (do_gen_candidates) {
		do_moduli_gen(argv[0], opts, nopts);
		જાઓ done;
	}
	જો (do_screen_candidates) {
		do_moduli_screen(argv[0], opts, nopts);
		જાઓ done;
	}

	જો (gen_all_hostkeys) {
		do_gen_all_hostkeys(pw);
		જાઓ done;
	}

	જો (ચાવી_type_name == ખાલી)
		ચાવી_type_name = DEFAULT_ચાવી_TYPE_NAME;

	type = sshkey_type_from_shortname(ચાવી_type_name);
	type_bits_valid(type, ચાવી_type_name, &bits);

	જો (!quiet)
		printf("Generating public/private %s key pair.\n",
		    ચાવી_type_name);
	પસંદગી (type) {
	સ્થિતિ ચાવી_ECDSA_SK:
	સ્થિતિ ચાવી_ED25519_SK:
		માટે (i = 0; i < nopts; i++) {
			જો (strcasecmp(opts[i], "no-touch-required") == 0) {
				sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
			} નહીંતર જો (strcasecmp(opts[i], "verify-required") == 0) {
				sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
			} નહીંતર જો (strcasecmp(opts[i], "resident") == 0) {
				sk_flags |= SSH_SK_RESIDENT_ચાવી;
			} નહીંતર જો ((p = strprefix(opts[i], "device=", 1))
			    != ખાલી ) {
				sk_device = xstrdup(p);
			} નહીંતર જો ((p = strprefix(opts[i], "user=", 1))
			    != ખાલી) {
				sk_user = xstrdup(p);
			} નહીંતર જો ((p = strprefix(opts[i], "challenge=", 1))
			    != ખાલી) {
				જો ((r = sshbuf_load_file(p,
				    &challenge)) != 0) {
					fatal_r(r, "Unable to load FIDO "
					    "enrollment challenge \"%s\"", p);
				}
			} નહીંતર જો (strncasecmp(opts[i],
			    "write-attestation=", 18) == 0) {
				sk_attestation_path = opts[i] + 18;
			} નહીંતર જો (strncasecmp(opts[i],
			    "application=", 12) == 0) {
				sk_application = xstrdup(opts[i] + 12);
				જો (strncmp(sk_application, "ssh:", 4) != 0) {
					fatal("FIDO application string must "
					    "begin with \"ssh:\"");
				}
			} નહીંતર {
				fatal("Option \"%s\" is unsupported for "
				    "FIDO authenticator enrollment", opts[i]);
			}
		}
		જો ((attest = sshbuf_new()) == ખાલી)
			fatal("sshbuf_new failed");
		r = 0;
		માટે (i = 0 ;;) {
			જો (!quiet) {
				printf("You may need to touch your "
				    "authenticator%s to authorize key "
				    "generation.\n",
				    r == 0 ? "" : " again");
			}
			fflush(stdout);
			r = sshsk_enroll(type, sk_provider, sk_device,
			    sk_application == ખાલી ? "ssh:" : sk_application,
			    sk_user, sk_flags, passphrase, challenge,
			    &ખાનગી, attest);
			જો (r == 0)
				તોડો;
			જો (r == SSH_ERR_ચાવી_BAD_PERMISSIONS &&
			    (sk_flags & SSH_SK_RESIDENT_ચાવી) != 0 &&
			    (sk_flags & SSH_SK_FORCE_OPERATION) == 0 &&
			    confirm_sk_overwrite(sk_application, sk_user)) {
				sk_flags |= SSH_SK_FORCE_OPERATION;
				ચાલુ;
			}
			જો (r != SSH_ERR_ચાવી_WRONG_PASSPHRASE)
				fatal_r(r, "Key enrollment failed");
			નહીંતર જો (passphrase != ખાલી) {
				error("PIN incorrect");
				freezero(passphrase, strlen(passphrase));
				passphrase = ખાલી;
			}
			જો (++i >= 3)
				fatal("Too many incorrect PINs");
			passphrase = read_passphrase("Enter PIN for "
			    "authenticator: ", RP_ALLOW_STDIN);
		}
		જો (passphrase != ખાલી) {
			freezero(passphrase, strlen(passphrase));
			passphrase = ખાલી;
		}
		તોડો;
	મૂળભૂત:
		જો ((r = sshkey_generate(type, bits, &ખાનગી)) != 0)
			fatal("sshkey_generate failed");
		તોડો;
	}
	જો ((r = sshkey_from_private(ખાનગી, &જાહેર)) != 0)
		fatal_r(r, "sshkey_from_private");

	જો (!have_identity)
		ask_filename(pw, "Enter file in which to save the key");

	/* Create ~/.ssh directory if it doesn't already exist. */
	hostfile_create_user_ssh_dir(identity_file, !quiet);

	/* If the file already exists, ask the user to confirm. */
	જો (!confirm_overwrite(identity_file))
		exit(1);

	/* Determine the passphrase for the private key */
	passphrase = private_ચાવી_passphrase(identity_file);
	જો (identity_comment) {
		strlcpy(comment, identity_comment, કદ(comment));
	} નહીંતર {
		/* Create default comment field for the passphrase. */
		snprintf(comment, કદ comment, "%s@%s", pw->pw_name, hostname);
	}



	/* Save the key with the given passphrase and comment. */
	જો ((r = sshkey_save_private(ખાનગી, identity_file, passphrase,
	    comment, private_ચાવી_format, openssh_format_cipher, rounds)) != 0) {
		error_r(r, "Saving key \"%s\" failed", identity_file);
		freezero(passphrase, strlen(passphrase));
		exit(1);
	}
	freezero(passphrase, strlen(passphrase));
	sshkey_free(ખાનગી);

	જો (!quiet) {
		printf("Your identification has been saved in %s\n",
		    identity_file);
	}

	strlcat(identity_file, ".pub", કદ(identity_file));
	જો ((r = sshkey_save_public(જાહેર, identity_file, comment)) != 0)
		fatal_r(r, "Unable to save public key to %s", identity_file);

	જો (!quiet) {
		fp = sshkey_fingerprint(જાહેર, fingerprint_hash,
		    SSH_FP_DEFAULT);
		ra = sshkey_fingerprint(જાહેર, fingerprint_hash,
		    SSH_FP_RANDOMART);
		જો (fp == ખાલી || ra == ખાલી)
			fatal("sshkey_fingerprint failed");
		printf("Your public key has been saved in %s\n",
		    identity_file);
		printf("The key fingerprint is:\n");
		printf("%s %s\n", fp, comment);
		printf("The key's randomart image is:\n");
		printf("%s\n", ra);
		મુક્ત(ra);
		મુક્ત(fp);
	}

	જો (sk_attestation_path != ખાલી)
		save_attestation(attest, sk_attestation_path);

 done:
	sshbuf_free(attest);
	sshkey_free(જાહેર);
	pwfree(pw);
	exit(ret);
}
