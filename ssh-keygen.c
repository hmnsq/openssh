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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>

#ifdef WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ "openbsd-compat/openssl-compat.h"
#ಅನ್ತರ್ಭಾವ <openssl/bn.h>
#ಅನ್ತರ್ಭಾವ <openssl/evp.h>
#ಅನ್ತರ್ಭಾವ <openssl/pem.h>
#endif

#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <netdb.h>
#ಅನ್ತರ್ಭಾವ <paths.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <locale.h>
#ಅನ್ತರ್ಭಾವ <time.h>

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "authfile.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "pathnames.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "match.h"
#ಅನ್ತರ್ಭಾವ "hostfile.h"
#ಅನ್ತರ್ಭಾವ "dns.h"
#ಅನ್ತರ್ಭಾವ "ssh.h"
#ಅನ್ತರ್ಭಾವ "ssh2.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "atomicio.h"
#ಅನ್ತರ್ಭಾವ "krl.h"
#ಅನ್ತರ್ಭಾವ "digest.h"
#ಅನ್ತರ್ಭಾವ "utf8.h"
#ಅನ್ತರ್ಭಾವ "authfd.h"
#ಅನ್ತರ್ಭಾವ "sshsig.h"
#ಅನ್ತರ್ಭಾವ "ssh-sk.h"
#ಅನ್ತರ್ಭಾವ "sk-api.h" /* XXX for SSH_SK_USER_PRESENCE_REQD; remove */
#ಅನ್ತರ್ಭಾವ "cipher.h"

#ifdef ENABLE_PKCS11
#ಅನ್ತರ್ಭಾವ "ssh-pkcs11.h"
#endif

#define DEFAULT_ಕೀಲಿ_TYPE_NAME "ed25519"

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

#define ಕೀಲಿ_COMMENT_MAX		(NI_MAXHOST + 1024)

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ quiet = 0;

/* Flag indicating that we just want to see the key fingerprint */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ print_fingerprint = 0;
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ print_bubblebabble = 0;

/* Hash algorithm to use for fingerprints. */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* The identity file name, given on the command line or entered by the user. */
ಸ್ಥಿರ ವರ್ಣ identity_file[PATH_MAX];
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ have_identity = 0;

/* This is set to the passphrase if given on the command line. */
ಸ್ಥಿರ ವರ್ಣ *identity_passphrase = ರಿಕ್ತ;

/* This is set to the new passphrase if given on the command line. */
ಸ್ಥಿರ ವರ್ಣ *identity_new_passphrase = ರಿಕ್ತ;

/* Key type when certifying */
ಸ್ಥಿರ u_int cert_ಕೀಲಿ_type = SSH2_CERT_TYPE_USER;

/* "key ID" of signed key */
ಸ್ಥಿರ ವರ್ಣ *cert_ಕೀಲಿ_id = ರಿಕ್ತ;

/* Comma-separated list of principal names for certifying keys */
ಸ್ಥಿರ ವರ್ಣ *cert_principals = ರಿಕ್ತ;

/* Validity period for certificates */
ಸ್ಥಿರ uint64_t cert_valid_from = 0;
ಸ್ಥಿರ uint64_t cert_valid_to = ~0ULL;

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
ಸ್ಥಿರ uint32_t certflags_flags = CERTOPT_DEFAULT;
ಸ್ಥಿರ ವರ್ಣ *certflags_command = ರಿಕ್ತ;
ಸ್ಥಿರ ವರ್ಣ *certflags_src_addr = ರಿಕ್ತ;

/* Arbitrary extensions specified by user */
ಸಂರಚನಾ cert_ext {
	ವರ್ಣ *ಕೀಲಿ;
	ವರ್ಣ *val;
	ಪೂರ್ಣಾಙ್ಕ crit;
};
ಸ್ಥಿರ ಸಂರಚನಾ cert_ext *cert_ext;
ಸ್ಥಿರ size_t ncert_ext;

/* Conversion to/from various formats */
ಗಣನಾ {
	FMT_RFC4716,
	FMT_PKCS8,
	FMT_PEM,
	FMT_HEXDUMP
} convert_format = FMT_RFC4716;

ಸ್ಥಿರ ವರ್ಣ *ಕೀಲಿ_type_name = ರಿಕ್ತ;

/* Load key from this PKCS#11 provider */
ಸ್ಥಿರ ವರ್ಣ *pkcs11provider = ರಿಕ್ತ;

/* FIDO/U2F provider to use */
ಸ್ಥಿರ ವರ್ಣ *sk_provider = ರಿಕ್ತ;

/* Format for writing private keys */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ private_ಕೀಲಿ_format = SSHKEY_PRIVATE_OPENSSH;

/* Cipher for new-format private keys */
ಸ್ಥಿರ ವರ್ಣ *openssh_format_cipher = ರಿಕ್ತ;

/* Number of KDF rounds to derive new format keys. */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ rounds = 0;

/* argv0 */
ಬಾಹ್ಯ ವರ್ಣ *__progname;

ಸ್ಥಿರ ವರ್ಣ hostname[NI_MAXHOST];

#ifdef WITH_OPENSSL
/* moduli.c */
ಪೂರ್ಣಾಙ್ಕ gen_candidates(FILE *, uint32_t, BIGNUM *);
ಪೂರ್ಣಾಙ್ಕ ಅವಿಭಾಜ್ಯ_test(FILE *, FILE *, uint32_t, uint32_t, ವರ್ಣ *, unsigned long,
    unsigned long);
#endif

ಸ್ಥಿರ ಶೂನ್ಯ
type_bits_valid(ಪೂರ್ಣಾಙ್ಕ type, ಧ್ರುವ ವರ್ಣ *name, uint32_t *bitsp)
{
	ಯದಿ (type == ಕೀಲಿ_UNSPEC)
		fatal("unknown key type %s", ಕೀಲಿ_type_name);
	ಯದಿ (*bitsp == 0) {
#ifdef WITH_OPENSSL
		ಪೂರ್ಣಾಙ್ಕ nid;

		ವಿಕಲ್ಪ(type) {
		ಪಕ್ಷ ಕೀಲಿ_ECDSA:
			ಯದಿ (name != ರಿಕ್ತ &&
			    (nid = sshkey_ecdsa_nid_from_name(name)) > 0)
				*bitsp = sshkey_curve_nid_to_bits(nid);
			ಯದಿ (*bitsp == 0)
				*bitsp = DEFAULT_BITS_ECDSA;
			ಭಙ್ಗ;
		ಪಕ್ಷ ಕೀಲಿ_RSA:
			*bitsp = DEFAULT_BITS;
			ಭಙ್ಗ;
		}
#endif
	}
#ifdef WITH_OPENSSL
	ವಿಕಲ್ಪ (type) {
	ಪಕ್ಷ ಕೀಲಿ_RSA:
		ಯದಿ (*bitsp < SSH_RSA_MINIMUM_MODULUS_SIZE)
			fatal("Invalid RSA key length: minimum is %d bits",
			    SSH_RSA_MINIMUM_MODULUS_SIZE);
		ಅನ್ಯಥಾ ಯದಿ (*bitsp > OPENSSL_RSA_MAX_MODULUS_BITS)
			fatal("Invalid RSA key length: maximum is %d bits",
			    OPENSSL_RSA_MAX_MODULUS_BITS);
		ಭಙ್ಗ;
	ಪಕ್ಷ ಕೀಲಿ_ECDSA:
		ಯದಿ (sshkey_ecdsa_bits_to_nid(*bitsp) == -1)
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
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
confirm_overwrite(ಧ್ರುವ ವರ್ಣ *filename)
{
	ವರ್ಣ yesno[3];
	ಸಂರಚನಾ stat st;

	ಯದಿ (stat(filename, &st) != 0)
		ಪ್ರತ್ಯಾಗಮ 1;
	printf("%s already exists.\n", filename);
	printf("Overwrite (y/n)? ");
	fflush(stdout);
	ಯದಿ (fgets(yesno, ಪರಿಮಾಣ(yesno), stdin) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (yesno[0] != 'y' && yesno[0] != 'Y')
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತ್ಯಾಗಮ 1;
}

ಸ್ಥಿರ ಶೂನ್ಯ
ask_filename(ಸಂರಚನಾ passwd *pw, ಧ್ರುವ ವರ್ಣ *prompt)
{
	ವರ್ಣ buf[1024];
	ವರ್ಣ *name = ರಿಕ್ತ;

	ಯದಿ (ಕೀಲಿ_type_name == ರಿಕ್ತ)
		name = _PATH_SSH_CLIENT_ID_ED25519;
	ಅನ್ಯಥಾ {
		ವಿಕಲ್ಪ (sshkey_type_from_shortname(ಕೀಲಿ_type_name)) {
		ಪಕ್ಷ ಕೀಲಿ_ECDSA_CERT:
		ಪಕ್ಷ ಕೀಲಿ_ECDSA:
			name = _PATH_SSH_CLIENT_ID_ECDSA;
			ಭಙ್ಗ;
		ಪಕ್ಷ ಕೀಲಿ_ECDSA_SK_CERT:
		ಪಕ್ಷ ಕೀಲಿ_ECDSA_SK:
			name = _PATH_SSH_CLIENT_ID_ECDSA_SK;
			ಭಙ್ಗ;
		ಪಕ್ಷ ಕೀಲಿ_RSA_CERT:
		ಪಕ್ಷ ಕೀಲಿ_RSA:
			name = _PATH_SSH_CLIENT_ID_RSA;
			ಭಙ್ಗ;
		ಪಕ್ಷ ಕೀಲಿ_ED25519:
		ಪಕ್ಷ ಕೀಲಿ_ED25519_CERT:
			name = _PATH_SSH_CLIENT_ID_ED25519;
			ಭಙ್ಗ;
		ಪಕ್ಷ ಕೀಲಿ_ED25519_SK:
		ಪಕ್ಷ ಕೀಲಿ_ED25519_SK_CERT:
			name = _PATH_SSH_CLIENT_ID_ED25519_SK;
			ಭಙ್ಗ;
		ಪಕ್ಷ ಕೀಲಿ_MLDSA44_ED25519:
		ಪಕ್ಷ ಕೀಲಿ_MLDSA44_ED25519_CERT:
			name = _PATH_SSH_CLIENT_ID_MLDSA44_ED25519;
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			fatal("bad key type");
		}
	}
	snprintf(identity_file, ಪರಿಮಾಣ(identity_file),
	    "%s/%s", pw->pw_dir, name);
	printf("%s (%s): ", prompt, identity_file);
	fflush(stdout);
	ಯದಿ (fgets(buf, ಪರಿಮಾಣ(buf), stdin) == ರಿಕ್ತ)
		exit(1);
	buf[strcspn(buf, "\n")] = '\0';
	ಯದಿ (strcmp(buf, "") != 0)
		strlcpy(identity_file, buf, ಪರಿಮಾಣ(identity_file));
	have_identity = 1;
}

ಸ್ಥಿರ ಸಂರಚನಾ sshkey *
load_identity(ಧ್ರುವ ವರ್ಣ *filename, ವರ್ಣ **commentp)
{
	ವರ್ಣ *prompt, *pass;
	ಸಂರಚನಾ sshkey *prv;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (commentp != ರಿಕ್ತ)
		*commentp = ರಿಕ್ತ;
	ಯದಿ ((r = sshkey_load_private(filename, "", &prv, commentp)) == 0)
		ಪ್ರತ್ಯಾಗಮ prv;
	ಯದಿ (r != SSH_ERR_ಕೀಲಿ_WRONG_PASSPHRASE)
		fatal_r(r, "Load key \"%s\"", filename);
	ಯದಿ (identity_passphrase)
		pass = xstrdup(identity_passphrase);
	ಅನ್ಯಥಾ {
		xasprintf(&prompt, "Enter passphrase for \"%s\": ", filename);
		pass = read_passphrase(prompt, RP_ALLOW_STDIN);
		ಮುಕ್ತ(prompt);
	}
	r = sshkey_load_private(filename, pass, &prv, commentp);
	freezero(pass, strlen(pass));
	ಯದಿ (r != 0)
		fatal_r(r, "Load key \"%s\"", filename);
	ಪ್ರತ್ಯಾಗಮ prv;
}

#define SSH_COM_PUBLIC_BEGIN		"---- BEGIN SSH2 PUBLIC KEY ----"
#define SSH_COM_PUBLIC_END		"---- END SSH2 PUBLIC KEY ----"
#define SSH_COM_PRIVATE_BEGIN		"---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----"
#define	SSH_COM_PRIVATE_ಕೀಲಿ_MAGIC	0x3f6ff9eb

#ifdef WITH_OPENSSL
ಸ್ಥಿರ ಶೂನ್ಯ
do_convert_to_ssh2(ಸಂರಚನಾ passwd *pw, ಸಂರಚನಾ sshkey *k)
{
	ಸಂರಚನಾ sshbuf *b;
	ವರ್ಣ comment[61], *b64;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((b = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = sshkey_putb(k, b)) != 0)
		fatal_fr(r, "put key");
	ಯದಿ ((b64 = sshbuf_dtob64_string(b, 1)) == ರಿಕ್ತ)
		fatal_f("sshbuf_dtob64_string failed");

	/* Comment + surrounds must fit into 72 chars (RFC 4716 sec 3.3) */
	snprintf(comment, ಪರಿಮಾಣ(comment),
	    "%u-bit %s, converted by %s@%s from OpenSSH",
	    sshkey_size(k), sshkey_type(k),
	    pw->pw_name, hostname);

	sshkey_free(k);
	sshbuf_free(b);

	fprintf(stdout, "%s\n", SSH_COM_PUBLIC_BEGIN);
	fprintf(stdout, "Comment: \"%s\"\n%s", comment, b64);
	fprintf(stdout, "%s\n", SSH_COM_PUBLIC_END);
	ಮುಕ್ತ(b64);
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_convert_to_pkcs8(ಸಂರಚನಾ sshkey *k)
{
	ವಿಕಲ್ಪ (sshkey_type_plain(k->type)) {
	ಪಕ್ಷ ಕೀಲಿ_RSA:
		ಯದಿ (!PEM_write_RSA_PUBKEY(stdout,
		    EVP_PKEY_get0_RSA(k->pkey)))
			fatal("PEM_write_RSA_PUBKEY failed");
		ಭಙ್ಗ;
	ಪಕ್ಷ ಕೀಲಿ_ECDSA:
		ಯದಿ (!PEM_write_EC_PUBKEY(stdout,
		    EVP_PKEY_get0_EC_ಕೀಲಿ(k->pkey)))
			fatal("PEM_write_EC_PUBKEY failed");
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		fatal_f("unsupported key type %s", sshkey_type(k));
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_convert_to_pem(ಸಂರಚನಾ sshkey *k)
{
	ವಿಕಲ್ಪ (sshkey_type_plain(k->type)) {
	ಪಕ್ಷ ಕೀಲಿ_RSA:
		ಯದಿ (!PEM_write_RSAPublic_ಕೀಲಿ(stdout,
		    EVP_PKEY_get0_RSA(k->pkey)))
			fatal("PEM_write_RSAPublicKey failed");
		ಭಙ್ಗ;
	ಪಕ್ಷ ಕೀಲಿ_ECDSA:
		ಯದಿ (!PEM_write_EC_PUBKEY(stdout,
		    EVP_PKEY_get0_EC_ಕೀಲಿ(k->pkey)))
			fatal("PEM_write_EC_PUBKEY failed");
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		fatal_f("unsupported key type %s", sshkey_type(k));
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_convert_to_hexdump(ಸಂರಚನಾ sshkey *k)
{
	ಸಂರಚನಾ sshbuf *b;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((b = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	/* pubkey */
	ಯದಿ ((r = sshkey_putb(k, b)) != 0)
		fatal_fr(r, "serialise private");
	printf("Public %s key:\n", sshkey_type(k));
	sshbuf_dump(b, stdout);
	sshbuf_reset(b);
	ಯದಿ ((r = sshkey_private_serialize(k, b)) != 0) {
		debug_fr(r, "serialise private");
		ಗಚ್ಛ out;
	}
	printf("\nPrivate %s key:\n", sshkey_type(k));
	sshbuf_dump(b, stdout);
 out:
	sshbuf_free(b);
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_convert_to(ಸಂರಚನಾ passwd *pw)
{
	ಸಂರಚನಾ sshkey *k = ರಿಕ್ತ;
	ಸಂರಚನಾ stat st;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	ಯದಿ (stat(identity_file, &st) == -1)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));

	/* If we're trying to hexdump, then prefer the private key */
	ಯದಿ (convert_format == FMT_HEXDUMP) {
		ಯದಿ ((r = sshkey_load_private(identity_file,
		    ರಿಕ್ತ, &k, ರಿಕ್ತ)) != 0 &&
		    r == SSH_ERR_ಕೀಲಿ_WRONG_PASSPHRASE)
			k = load_identity(identity_file, ರಿಕ್ತ);
	}
	ಯದಿ (k == ರಿಕ್ತ && (r = sshkey_load_public(identity_file, &k, ರಿಕ್ತ)) != 0)
		k = load_identity(identity_file, ರಿಕ್ತ);

	ವಿಕಲ್ಪ (convert_format) {
	ಪಕ್ಷ FMT_RFC4716:
		do_convert_to_ssh2(pw, k);
		ಭಙ್ಗ;
	ಪಕ್ಷ FMT_PKCS8:
		do_convert_to_pkcs8(k);
		ಭಙ್ಗ;
	ಪಕ್ಷ FMT_PEM:
		do_convert_to_pem(k);
		ಭಙ್ಗ;
	ಪಕ್ಷ FMT_HEXDUMP:
		do_convert_to_hexdump(k);
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		fatal_f("unknown key format %d", convert_format);
	}
}

/*
 * This is almost exactly the bignum1 encoding, but with 32 bit for length
 * instead of 16.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
buffer_get_bignum_bits(ಸಂರಚನಾ sshbuf *b, BIGNUM *ಮೌಲ್ಯ)
{
	u_int bytes, bignum_bits;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshbuf_get_u32(b, &bignum_bits)) != 0)
		fatal_fr(r, "parse");
	bytes = (bignum_bits + 7) / 8;
	ಯದಿ (sshbuf_len(b) < bytes)
		fatal_f("input buffer too small: need %d have %zu",
		    bytes, sshbuf_len(b));
	ಯದಿ (BN_bin2bn(sshbuf_ptr(b), bytes, ಮೌಲ್ಯ) == ರಿಕ್ತ)
		fatal_f("BN_bin2bn failed");
	ಯದಿ ((r = sshbuf_consume(b, bytes)) != 0)
		fatal_fr(r, "consume");
}

ಸ್ಥಿರ ಸಂರಚನಾ sshkey *
do_convert_private_ssh2(ಸಂರಚನಾ sshbuf *b)
{
	ಸಂರಚನಾ sshkey *ಕೀಲಿ = ರಿಕ್ತ;
	ವರ್ಣ *type, *cipher;
	ಧ್ರುವ ವರ್ಣ *alg = ರಿಕ್ತ;
	u_char e1, e2, e3, *sig = ರಿಕ್ತ, data[] = "abcde12345";
	ಪೂರ್ಣಾಙ್ಕ r, rlen, ktype;
	u_int magic, i1, i2, i3, i4;
	size_t slen;
	u_long e;
	BIGNUM *rsa_n = ರಿಕ್ತ, *rsa_e = ರಿಕ್ತ, *rsa_d = ರಿಕ್ತ;
	BIGNUM *rsa_p = ರಿಕ್ತ, *rsa_q = ರಿಕ್ತ, *rsa_iqmp = ರಿಕ್ತ;
	BIGNUM *rsa_dmp1 = ರಿಕ್ತ, *rsa_dmq1 = ರಿಕ್ತ;
	RSA *rsa = ರಿಕ್ತ;

	ಯದಿ ((r = sshbuf_get_u32(b, &magic)) != 0)
		fatal_fr(r, "parse magic");

	ಯದಿ (magic != SSH_COM_PRIVATE_ಕೀಲಿ_MAGIC) {
		error("bad magic 0x%x != 0x%x", magic,
		    SSH_COM_PRIVATE_ಕೀಲಿ_MAGIC);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	ಯದಿ ((r = sshbuf_get_u32(b, &i1)) != 0 ||
	    (r = sshbuf_get_cstring(b, &type, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_cstring(b, &cipher, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_u32(b, &i2)) != 0 ||
	    (r = sshbuf_get_u32(b, &i3)) != 0 ||
	    (r = sshbuf_get_u32(b, &i4)) != 0)
		fatal_fr(r, "parse");
	debug("ignore (%d %d %d %d)", i1, i2, i3, i4);
	ಯದಿ (strcmp(cipher, "none") != 0) {
		error("unsupported cipher %s", cipher);
		ಮುಕ್ತ(cipher);
		ಮುಕ್ತ(type);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	ಮುಕ್ತ(cipher);

	ಯದಿ (strstr(type, "rsa")) {
		ktype = ಕೀಲಿ_RSA;
	} ಅನ್ಯಥಾ {
		ಮುಕ್ತ(type);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	ಯದಿ ((ಕೀಲಿ = sshkey_new(ktype)) == ರಿಕ್ತ)
		fatal("sshkey_new failed");
	ಮುಕ್ತ(type);

	ವಿಕಲ್ಪ (ಕೀಲಿ->type) {
	ಪಕ್ಷ ಕೀಲಿ_RSA:
		ಯದಿ ((r = sshbuf_get_u8(b, &e1)) != 0 ||
		    (e1 < 30 && (r = sshbuf_get_u8(b, &e2)) != 0) ||
		    (e1 < 30 && (r = sshbuf_get_u8(b, &e3)) != 0))
			fatal_fr(r, "parse RSA");
		e = e1;
		debug("e %lx", e);
		ಯದಿ (e < 30) {
			e <<= 8;
			e += e2;
			debug("e %lx", e);
			e <<= 8;
			e += e3;
			debug("e %lx", e);
		}
		ಯದಿ ((rsa_e = BN_new()) == ರಿಕ್ತ)
			fatal_f("BN_new");
		ಯದಿ (!BN_set_word(rsa_e, e)) {
			BN_clear_free(rsa_e);
			sshkey_free(ಕೀಲಿ);
			ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
		}
		ಯದಿ ((rsa_n = BN_new()) == ರಿಕ್ತ ||
		    (rsa_d = BN_new()) == ರಿಕ್ತ ||
		    (rsa_p = BN_new()) == ರಿಕ್ತ ||
		    (rsa_q = BN_new()) == ರಿಕ್ತ ||
		    (rsa_iqmp = BN_new()) == ರಿಕ್ತ)
			fatal_f("BN_new");
		buffer_get_bignum_bits(b, rsa_d);
		buffer_get_bignum_bits(b, rsa_n);
		buffer_get_bignum_bits(b, rsa_iqmp);
		buffer_get_bignum_bits(b, rsa_q);
		buffer_get_bignum_bits(b, rsa_p);
		ಯದಿ ((r = ssh_rsa_complete_crt_parameters(rsa_d, rsa_p, rsa_q,
		    rsa_iqmp, &rsa_dmp1, &rsa_dmq1)) != 0)
			fatal_fr(r, "generate RSA CRT parameters");
		EVP_PKEY_free(ಕೀಲಿ->pkey);
		ಯದಿ ((ಕೀಲಿ->pkey = EVP_PKEY_new()) == ರಿಕ್ತ)
			fatal_f("EVP_PKEY_new failed");
		ಯದಿ ((rsa = RSA_new()) == ರಿಕ್ತ)
			fatal_f("RSA_new failed");
		ಯದಿ (!RSA_set0_ಕೀಲಿ(rsa, rsa_n, rsa_e, rsa_d))
			fatal_f("RSA_set0_key failed");
		rsa_n = rsa_e = rsa_d = ರಿಕ್ತ; /* transferred */
		ಯದಿ (!RSA_set0_factors(rsa, rsa_p, rsa_q))
			fatal_f("RSA_set0_factors failed");
		rsa_p = rsa_q = ರಿಕ್ತ; /* transferred */
		ಯದಿ (RSA_set0_crt_params(rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp) != 1)
			fatal_f("RSA_set0_crt_params failed");
		rsa_dmp1 = rsa_dmq1 = rsa_iqmp = ರಿಕ್ತ;
		ಯದಿ (EVP_PKEY_set1_RSA(ಕೀಲಿ->pkey, rsa) != 1)
			fatal_f("EVP_PKEY_set1_RSA failed");
		RSA_free(rsa);
		alg = "rsa-sha2-256";
		ಭಙ್ಗ;
	}
	rlen = sshbuf_len(b);
	ಯದಿ (rlen != 0)
		error_f("remaining bytes in key blob %d", rlen);

	/* try the key */
	ಯದಿ ((r = sshkey_sign(ಕೀಲಿ, &sig, &slen, data, ಪರಿಮಾಣ(data),
	    alg, ರಿಕ್ತ, ರಿಕ್ತ, 0)) != 0)
		error_fr(r, "signing with converted key failed");
	ಅನ್ಯಥಾ ಯದಿ ((r = sshkey_verify(ಕೀಲಿ, sig, slen, data, ಪರಿಮಾಣ(data),
	    alg, 0, ರಿಕ್ತ)) != 0)
		error_fr(r, "verification with converted key failed");
	ಯದಿ (r != 0) {
		sshkey_free(ಕೀಲಿ);
		ಮುಕ್ತ(sig);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	ಮುಕ್ತ(sig);
	ಪ್ರತ್ಯಾಗಮ ಕೀಲಿ;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
get_ಸಾಲು(FILE *fp, ವರ್ಣ *ಸಾಲು, size_t len)
{
	ಪೂರ್ಣಾಙ್ಕ c;
	size_t pos = 0;

	ಸಾಲು[0] = '\0';
	ಯಾವತ್ ((c = fgetc(fp)) != EOF) {
		ಯದಿ (pos >= len - 1)
			fatal("input line too long.");
		ವಿಕಲ್ಪ (c) {
		ಪಕ್ಷ '\r':
			c = fgetc(fp);
			ಯದಿ (c != EOF && c != '\n' && ungetc(c, fp) == EOF)
				fatal("unget: %s", strerror(errno));
			ಪ್ರತ್ಯಾಗಮ pos;
		ಪಕ್ಷ '\n':
			ಪ್ರತ್ಯಾಗಮ pos;
		}
		ಸಾಲು[pos++] = c;
		ಸಾಲು[pos] = '\0';
	}
	/* We reached EOF */
	ಪ್ರತ್ಯಾಗಮ -1;
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_convert_from_ssh2(ಸಂರಚನಾ passwd *pw, ಸಂರಚನಾ sshkey **k, ಪೂರ್ಣಾಙ್ಕ *ಗುಪ್ತ)
{
	ಪೂರ್ಣಾಙ್ಕ r, blen, escaped = 0;
	u_int len;
	ವರ್ಣ ಸಾಲು[1024];
	ಸಂರಚನಾ sshbuf *buf;
	ವರ್ಣ encoded[8096];
	FILE *fp;

	ಯದಿ ((buf = sshbuf_new()) == ರಿಕ್ತ)
		fatal("sshbuf_new failed");
	ಯದಿ ((fp = fopen(identity_file, "r")) == ರಿಕ್ತ)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));
	encoded[0] = '\0';
	ಯಾವತ್ ((blen = get_ಸಾಲು(fp, ಸಾಲು, ಪರಿಮಾಣ(ಸಾಲು))) != -1) {
		ಯದಿ (blen > 0 && ಸಾಲು[blen - 1] == '\\')
			escaped++;
		ಯದಿ (strncmp(ಸಾಲು, "----", 4) == 0 ||
		    strstr(ಸಾಲು, ": ") != ರಿಕ್ತ) {
			ಯದಿ (strstr(ಸಾಲು, SSH_COM_PRIVATE_BEGIN) != ರಿಕ್ತ)
				*ಗುಪ್ತ = 1;
			ಯದಿ (strstr(ಸಾಲು, " END ") != ರಿಕ್ತ) {
				ಭಙ್ಗ;
			}
			/* fprintf(stderr, "ignore: %s", line); */
			ಅನುವರ್ತ;
		}
		ಯದಿ (escaped) {
			escaped--;
			/* fprintf(stderr, "escaped: %s", line); */
			ಅನುವರ್ತ;
		}
		strlcat(encoded, ಸಾಲು, ಪರಿಮಾಣ(encoded));
	}
	len = strlen(encoded);
	ಯದಿ (((len % 4) == 3) &&
	    (encoded[len-1] == '=') &&
	    (encoded[len-2] == '=') &&
	    (encoded[len-3] == '='))
		encoded[len-3] = '\0';
	ಯದಿ ((r = sshbuf_b64tod(buf, encoded)) != 0)
		fatal_fr(r, "base64 decode");
	ಯದಿ (*ಗುಪ್ತ) {
		ಯದಿ ((*k = do_convert_private_ssh2(buf)) == ರಿಕ್ತ)
			fatal_f("private key conversion failed");
	} ಅನ್ಯಥಾ ಯದಿ ((r = sshkey_fromb(buf, k)) != 0)
		fatal_fr(r, "parse key");
	sshbuf_free(buf);
	fclose(fp);
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_convert_from_pkcs8(ಸಂರಚನಾ sshkey **k, ಪೂರ್ಣಾಙ್ಕ *ಗುಪ್ತ)
{
	EVP_PKEY *pubkey;
	FILE *fp;

	ಯದಿ ((fp = fopen(identity_file, "r")) == ರಿಕ್ತ)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));
	ಯದಿ ((pubkey = PEM_read_PUBKEY(fp, ರಿಕ್ತ, ರಿಕ್ತ, ರಿಕ್ತ)) == ರಿಕ್ತ) {
		fatal_f("%s is not a recognised public key format",
		    identity_file);
	}
	fclose(fp);
	ವಿಕಲ್ಪ (EVP_PKEY_base_id(pubkey)) {
	ಪಕ್ಷ EVP_PKEY_RSA:
		ಯದಿ ((*k = sshkey_new(ಕೀಲಿ_UNSPEC)) == ರಿಕ್ತ)
			fatal("sshkey_new failed");
		(*k)->type = ಕೀಲಿ_RSA;
		(*k)->pkey = pubkey;
		pubkey = ರಿಕ್ತ;
		ಭಙ್ಗ;
	ಪಕ್ಷ EVP_PKEY_EC:
		ಯದಿ ((*k = sshkey_new(ಕೀಲಿ_UNSPEC)) == ರಿಕ್ತ)
			fatal("sshkey_new failed");
		ಯದಿ (((*k)->ecdsa_nid = sshkey_ecdsa_fixup_group(pubkey)) == -1)
			fatal("sshkey_ecdsa_fixup_group failed");
		(*k)->type = ಕೀಲಿ_ECDSA;
		(*k)->pkey = pubkey;
		pubkey = ರಿಕ್ತ;
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		fatal_f("unsupported pubkey type %d",
		    EVP_PKEY_base_id(pubkey));
	}
	EVP_PKEY_free(pubkey);
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_convert_from_pem(ಸಂರಚನಾ sshkey **k, ಪೂರ್ಣಾಙ್ಕ *ಗುಪ್ತ)
{
	FILE *fp;
	RSA *rsa;

	ಯದಿ ((fp = fopen(identity_file, "r")) == ರಿಕ್ತ)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));
	ಯದಿ ((rsa = PEM_read_RSAPublic_ಕೀಲಿ(fp, ರಿಕ್ತ, ರಿಕ್ತ, ರಿಕ್ತ)) != ರಿಕ್ತ) {
		ಯದಿ ((*k = sshkey_new(ಕೀಲಿ_UNSPEC)) == ರಿಕ್ತ)
			fatal("sshkey_new failed");
		ಯದಿ (((*k)->pkey = EVP_PKEY_new()) == ರಿಕ್ತ)
			fatal("EVP_PKEY_new failed");
		(*k)->type = ಕೀಲಿ_RSA;
		ಯದಿ (EVP_PKEY_set1_RSA((*k)->pkey, rsa) != 1)
			fatal("EVP_PKEY_set1_RSA failed");
		RSA_free(rsa);
		fclose(fp);
		ಪ್ರತ್ಯಾಗಮ;
	}
	fatal_f("unrecognised raw private key format");
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_convert_from(ಸಂರಚನಾ passwd *pw)
{
	ಸಂರಚನಾ sshkey *k = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r, ಗುಪ್ತ = 0, ok = 0;
	ಸಂರಚನಾ stat st;

	ಯದಿ (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	ಯದಿ (stat(identity_file, &st) == -1)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));

	ವಿಕಲ್ಪ (convert_format) {
	ಪಕ್ಷ FMT_RFC4716:
		do_convert_from_ssh2(pw, &k, &ಗುಪ್ತ);
		ಭಙ್ಗ;
	ಪಕ್ಷ FMT_PKCS8:
		do_convert_from_pkcs8(&k, &ಗುಪ್ತ);
		ಭಙ್ಗ;
	ಪಕ್ಷ FMT_PEM:
		do_convert_from_pem(&k, &ಗುಪ್ತ);
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		fatal_f("unknown key format %d", convert_format);
	}

	ಯದಿ (!ಗುಪ್ತ) {
		ಯದಿ ((r = sshkey_write(k, stdout)) == 0)
			ok = 1;
		ಯದಿ (ok)
			fprintf(stdout, "\n");
	} ಅನ್ಯಥಾ {
		ವಿಕಲ್ಪ (k->type) {
		ಪಕ್ಷ ಕೀಲಿ_ECDSA:
			ok = PEM_write_ECPrivate_ಕೀಲಿ(stdout,
			    EVP_PKEY_get0_EC_ಕೀಲಿ(k->pkey), ರಿಕ್ತ, ರಿಕ್ತ, 0,
			    ರಿಕ್ತ, ರಿಕ್ತ);
			ಭಙ್ಗ;
		ಪಕ್ಷ ಕೀಲಿ_RSA:
			ok = PEM_write_RSAPrivate_ಕೀಲಿ(stdout,
			    EVP_PKEY_get0_RSA(k->pkey), ರಿಕ್ತ, ರಿಕ್ತ, 0,
			    ರಿಕ್ತ, ರಿಕ್ತ);
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			fatal_f("unsupported key type %s", sshkey_type(k));
		}
	}

	ಯದಿ (!ok)
		fatal("key write failed");
	sshkey_free(k);
}
#endif

ಸ್ಥಿರ ಶೂನ್ಯ
do_print_public(ಸಂರಚನಾ passwd *pw)
{
	ಸಂರಚನಾ sshkey *prv;
	ಸಂರಚನಾ stat st;
	ಪೂರ್ಣಾಙ್ಕ r;
	ವರ್ಣ *comment = ರಿಕ್ತ;

	ಯದಿ (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	ಯದಿ (stat(identity_file, &st) == -1)
		fatal("%s: %s", identity_file, strerror(errno));
	prv = load_identity(identity_file, &comment);
	ಯದಿ ((r = sshkey_write(prv, stdout)) != 0)
		fatal_fr(r, "write key");
	ಯದಿ (comment != ರಿಕ್ತ && *comment != '\0')
		fprintf(stdout, " %s", comment);
	fprintf(stdout, "\n");
	ಯದಿ (sshkey_is_sk(prv)) {
		debug("sk_application: \"%s\", sk_flags 0x%02x",
			prv->sk_application, prv->sk_flags);
	}
	sshkey_free(prv);
	ಮುಕ್ತ(comment);
	exit(0);
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_download(ಸಂರಚನಾ passwd *pw)
{
#ifdef ENABLE_PKCS11
	ಸಂರಚನಾ sshkey **ಕೀಲಿಗಳು = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ i, nkeys;
	ಗಣನಾ sshkey_fp_rep rep;
	ಪೂರ್ಣಾಙ್ಕ fptype;
	ವರ್ಣ *fp, *ra, **comments = ರಿಕ್ತ;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;

	pkcs11_init(1);
	nkeys = pkcs11_add_provider(pkcs11provider, ರಿಕ್ತ, &ಕೀಲಿಗಳು, &comments);
	ಯದಿ (nkeys <= 0)
		fatal("cannot read public key from pkcs11");
	ಪ್ರತಿ (i = 0; i < nkeys; i++) {
		ಯದಿ (print_fingerprint) {
			fp = sshkey_fingerprint(ಕೀಲಿಗಳು[i], fptype, rep);
			ra = sshkey_fingerprint(ಕೀಲಿಗಳು[i], fingerprint_hash,
			    SSH_FP_RANDOMART);
			ಯದಿ (fp == ರಿಕ್ತ || ra == ರಿಕ್ತ)
				fatal_f("sshkey_fingerprint fail");
			printf("%u %s %s (PKCS11 key)\n", sshkey_size(ಕೀಲಿಗಳು[i]),
			    fp, sshkey_type(ಕೀಲಿಗಳು[i]));
			ಯದಿ (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
				printf("%s\n", ra);
			ಮುಕ್ತ(ra);
			ಮುಕ್ತ(fp);
		} ಅನ್ಯಥಾ {
			(ಶೂನ್ಯ) sshkey_write(ಕೀಲಿಗಳು[i], stdout); /* XXX check */
			fprintf(stdout, "%s%s\n",
			    *(comments[i]) == '\0' ? "" : " ", comments[i]);
		}
		ಮುಕ್ತ(comments[i]);
		sshkey_free(ಕೀಲಿಗಳು[i]);
	}
	ಮುಕ್ತ(comments);
	ಮುಕ್ತ(ಕೀಲಿಗಳು);
	pkcs11_terminate();
	exit(0);
#ಅನ್ಯಥಾ
	fatal("no pkcs11 support");
#endif /* ENABLE_PKCS11 */
}

ಸ್ಥಿರ ಸಂರಚನಾ sshkey *
try_read_ಕೀಲಿ(ವರ್ಣ **cpp)
{
	ಸಂರಚನಾ sshkey *ret;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((ret = sshkey_new(ಕೀಲಿ_UNSPEC)) == ರಿಕ್ತ)
		fatal("sshkey_new failed");
	ಯದಿ ((r = sshkey_read(ret, cpp)) == 0)
		ಪ್ರತ್ಯಾಗಮ ret;
	/* Not a key */
	sshkey_free(ret);
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}

ಸ್ಥಿರ ಶೂನ್ಯ
fingerprint_one_ಕೀಲಿ(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಸಾರ್ವಜನಿಕ, ಧ್ರುವ ವರ್ಣ *comment)
{
	ವರ್ಣ *fp = ರಿಕ್ತ, *ra = ರಿಕ್ತ;
	ಗಣನಾ sshkey_fp_rep rep;
	ಪೂರ್ಣಾಙ್ಕ fptype;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;
	fp = sshkey_fingerprint(ಸಾರ್ವಜನಿಕ, fptype, rep);
	ra = sshkey_fingerprint(ಸಾರ್ವಜನಿಕ, fingerprint_hash, SSH_FP_RANDOMART);
	ಯದಿ (fp == ರಿಕ್ತ || ra == ರಿಕ್ತ)
		fatal_f("sshkey_fingerprint failed");
	mprintf("%u %s %s (%s)\n", sshkey_size(ಸಾರ್ವಜನಿಕ), fp,
	    comment ? comment : "no comment", sshkey_type(ಸಾರ್ವಜನಿಕ));
	ಯದಿ (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
		printf("%s\n", ra);
	ಮುಕ್ತ(ra);
	ಮುಕ್ತ(fp);
}

ಸ್ಥಿರ ಶೂನ್ಯ
fingerprint_private(ಧ್ರುವ ವರ್ಣ *path)
{
	ಸಂರಚನಾ stat st;
	ವರ್ಣ *comment = ರಿಕ್ತ;
	ಸಂರಚನಾ sshkey *privkey = ರಿಕ್ತ, *pubkey = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (stat(identity_file, &st) == -1)
		fatal("%s: %s", path, strerror(errno));
	ಯದಿ ((r = sshkey_load_public(path, &pubkey, &comment)) != 0)
		debug_r(r, "load public \"%s\"", path);
	ಯದಿ (pubkey == ರಿಕ್ತ || comment == ರಿಕ್ತ || *comment == '\0') {
		ಮುಕ್ತ(comment);
		ಯದಿ ((r = sshkey_load_private(path, ರಿಕ್ತ,
		    &privkey, &comment)) != 0)
			debug_r(r, "load private \"%s\"", path);
	}
	ಯದಿ (pubkey == ರಿಕ್ತ && privkey == ರಿಕ್ತ)
		fatal("%s is not a key file.", path);

	fingerprint_one_ಕೀಲಿ(pubkey == ರಿಕ್ತ ? privkey : pubkey, comment);
	sshkey_free(pubkey);
	sshkey_free(privkey);
	ಮುಕ್ತ(comment);
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_fingerprint(ಸಂರಚನಾ passwd *pw)
{
	FILE *f;
	ಸಂರಚನಾ sshkey *ಸಾರ್ವಜನಿಕ = ರಿಕ್ತ;
	ವರ್ಣ *comment = ರಿಕ್ತ, *cp, *ep, *ಸಾಲು = ರಿಕ್ತ;
	size_t linesize = 0;
	ಪೂರ್ಣಾಙ್ಕ i, invalid = 1;
	ಧ್ರುವ ವರ್ಣ *path;
	u_long lnum = 0;

	ಯದಿ (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	path = identity_file;

	ಯದಿ (strcmp(identity_file, "-") == 0) {
		f = stdin;
		path = "(stdin)";
	} ಅನ್ಯಥಾ ಯದಿ ((f = fopen(path, "r")) == ರಿಕ್ತ)
		fatal("%s: %s: %s", __progname, path, strerror(errno));

	ಯಾವತ್ (getline(&ಸಾಲು, &linesize, f) != -1) {
		lnum++;
		cp = ಸಾಲು;
		cp[strcspn(cp, "\r\n")] = '\0';
		/* Trim leading space and comments */
		cp = ಸಾಲು + strspn(ಸಾಲು, " \t");
		ಯದಿ (*cp == '#' || *cp == '\0')
			ಅನುವರ್ತ;

		/*
		 * Input may be plain keys, private keys, authorized_keys
		 * or known_hosts.
		 */

		/*
		 * Try private keys first. Assume a key is private if
		 * "SSH PRIVATE KEY" appears on the first line and we're
		 * not reading from stdin (XXX support private keys on stdin).
		 */
		ಯದಿ (lnum == 1 && strcmp(identity_file, "-") != 0 &&
		    strstr(cp, "PRIVATE KEY") != ರಿಕ್ತ) {
			ಮುಕ್ತ(ಸಾಲು);
			fclose(f);
			fingerprint_private(path);
			exit(0);
		}

		/*
		 * If it's not a private key, then this must be prepared to
		 * accept a public key prefixed with a hostname or options.
		 * Try a bare key first, otherwise skip the leading stuff.
		 */
		comment = ರಿಕ್ತ;
		ಯದಿ ((ಸಾರ್ವಜನಿಕ = try_read_ಕೀಲಿ(&cp)) == ರಿಕ್ತ) {
			i = strtol(cp, &ep, 10);
			ಯದಿ (i == 0 || ep == ರಿಕ್ತ ||
			    (*ep != ' ' && *ep != '\t')) {
				ಪೂರ್ಣಾಙ್ಕ quoted = 0;

				comment = cp;
				ಪ್ರತಿ (; *cp && (quoted || (*cp != ' ' &&
				    *cp != '\t')); cp++) {
					ಯದಿ (*cp == '\\' && cp[1] == '"')
						cp++;	/* Skip both */
					ಅನ್ಯಥಾ ಯದಿ (*cp == '"')
						quoted = !quoted;
				}
				ಯದಿ (!*cp)
					ಅನುವರ್ತ;
				*cp++ = '\0';
			}
		}
		/* Retry after parsing leading hostname/key options */
		ಯದಿ (ಸಾರ್ವಜನಿಕ == ರಿಕ್ತ && (ಸಾರ್ವಜನಿಕ = try_read_ಕೀಲಿ(&cp)) == ರಿಕ್ತ) {
			debug("%s:%lu: not a public key", path, lnum);
			ಅನುವರ್ತ;
		}

		/* Find trailing comment, if any */
		ಪ್ರತಿ (; *cp == ' ' || *cp == '\t'; cp++)
			;
		ಯದಿ (*cp != '\0' && *cp != '#')
			comment = cp;

		fingerprint_one_ಕೀಲಿ(ಸಾರ್ವಜನಿಕ, comment);
		sshkey_free(ಸಾರ್ವಜನಿಕ);
		invalid = 0; /* One good key in the file is sufficient */
	}
	fclose(f);
	ಮುಕ್ತ(ಸಾಲು);

	ಯದಿ (invalid)
		fatal("%s is not a public key file.", path);
	exit(0);
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_gen_all_hostkeys(ಸಂರಚನಾ passwd *pw)
{
	ಸಂರಚನಾ {
		ವರ್ಣ *ಕೀಲಿ_type;
		ವರ್ಣ *ಕೀಲಿ_type_display;
		ವರ್ಣ *path;
	} ಕೀಲಿ_types[] = {
#ifdef WITH_OPENSSL
		{ "rsa", "RSA" ,PATH_HOST_RSA_ಕೀಲಿ_FILE },
		{ "ecdsa", "ECDSA",PATH_HOST_ECDSA_ಕೀಲಿ_FILE },
#endif /* WITH_OPENSSL */
		{ "ed25519", "ED25519",PATH_HOST_ED25519_ಕೀಲಿ_FILE },
#ifdef USE_MLDSA
		{ "mldsa44-ed25519", "MLDSA44-ED25519",
		     PATH_HOST_MLDSA44_ED25519_ಕೀಲಿ_FILE },
#endif
		{ ರಿಕ್ತ, ರಿಕ್ತ, ರಿಕ್ತ }
	};

	uint32_t bits = 0;
	ಪೂರ್ಣಾಙ್ಕ first = 0;
	ಸಂರಚನಾ stat st;
	ಸಂರಚನಾ sshkey *ಗುಪ್ತ, *ಸಾರ್ವಜನಿಕ;
	ವರ್ಣ comment[ಕೀಲಿ_COMMENT_MAX], *prv_tmp, *pub_tmp, *prv_file, *pub_file;
	ಪೂರ್ಣಾಙ್ಕ i, type, fd, r;

	ಪ್ರತಿ (i = 0; ಕೀಲಿ_types[i].ಕೀಲಿ_type; i++) {
		ಸಾರ್ವಜನಿಕ = ಗುಪ್ತ = ರಿಕ್ತ;
		prv_tmp = pub_tmp = prv_file = pub_file = ರಿಕ್ತ;

		xasprintf(&prv_file, "%s%s",
		    identity_file, ಕೀಲಿ_types[i].path);

		/* Check whether private key exists and is not zero-length */
		ಯದಿ (stat(prv_file, &st) == 0) {
			ಯದಿ (st.st_size != 0)
				ಗಚ್ಛ next;
		} ಅನ್ಯಥಾ ಯದಿ (errno != ENOENT) {
			error("Could not stat %s: %s", ಕೀಲಿ_types[i].path,
			    strerror(errno));
			ಗಚ್ಛ failnext;
		}

		/*
		 * Private key doesn't exist or is invalid; proceed with
		 * key generation.
		 */
		xasprintf(&prv_tmp, "%s%s.XXXXXXXXXX",
		    identity_file, ಕೀಲಿ_types[i].path);
		xasprintf(&pub_tmp, "%s%s.pub.XXXXXXXXXX",
		    identity_file, ಕೀಲಿ_types[i].path);
		xasprintf(&pub_file, "%s%s.pub",
		    identity_file, ಕೀಲಿ_types[i].path);

		ಯದಿ (first == 0) {
			first = 1;
			printf("%s: generating new host keys: ", __progname);
		}
		printf("%s ", ಕೀಲಿ_types[i].ಕೀಲಿ_type_display);
		fflush(stdout);
		type = sshkey_type_from_shortname(ಕೀಲಿ_types[i].ಕೀಲಿ_type);
		ಯದಿ ((fd = mkstemp(prv_tmp)) == -1) {
			error("Could not save your private key in %s: %s",
			    prv_tmp, strerror(errno));
			ಗಚ್ಛ failnext;
		}
		(ಶೂನ್ಯ)close(fd); /* just using mkstemp() to reserve a name */
		bits = 0;
		type_bits_valid(type, ರಿಕ್ತ, &bits);
		ಯದಿ ((r = sshkey_generate(type, bits, &ಗುಪ್ತ)) != 0) {
			error_r(r, "sshkey_generate failed");
			ಗಚ್ಛ failnext;
		}
		ಯದಿ ((r = sshkey_from_private(ಗುಪ್ತ, &ಸಾರ್ವಜನಿಕ)) != 0)
			fatal_fr(r, "sshkey_from_private");
		snprintf(comment, ಪರಿಮಾಣ comment, "%s@%s", pw->pw_name,
		    hostname);
		ಯದಿ ((r = sshkey_save_private(ಗುಪ್ತ, prv_tmp, "",
		    comment, private_ಕೀಲಿ_format, openssh_format_cipher,
		    rounds)) != 0) {
			error_r(r, "Saving key \"%s\" failed", prv_tmp);
			ಗಚ್ಛ failnext;
		}
		ಯದಿ ((fd = mkstemp(pub_tmp)) == -1) {
			error("Could not save your public key in %s: %s",
			    pub_tmp, strerror(errno));
			ಗಚ್ಛ failnext;
		}
		(ಶೂನ್ಯ)fchmod(fd, 0644);
		(ಶೂನ್ಯ)close(fd);
		ಯದಿ ((r = sshkey_save_public(ಸಾರ್ವಜನಿಕ, pub_tmp, comment)) != 0) {
			error_r(r, "Unable to save public key to %s",
			    identity_file);
			ಗಚ್ಛ failnext;
		}

		/* Rename temporary files to their permanent locations. */
		ಯದಿ (rename(pub_tmp, pub_file) != 0) {
			error("Unable to move %s into position: %s",
			    pub_file, strerror(errno));
			ಗಚ್ಛ failnext;
		}
		ಯದಿ (rename(prv_tmp, prv_file) != 0) {
			error("Unable to move %s into position: %s",
			    ಕೀಲಿ_types[i].path, strerror(errno));
 failnext:
			first = 0;
			ಗಚ್ಛ next;
		}
 next:
		sshkey_free(ಗುಪ್ತ);
		sshkey_free(ಸಾರ್ವಜನಿಕ);
		ಮುಕ್ತ(prv_tmp);
		ಮುಕ್ತ(pub_tmp);
		ಮುಕ್ತ(prv_file);
		ಮುಕ್ತ(pub_file);
	}
	ಯದಿ (first != 0)
		printf("\n");
}

ಸಂರಚನಾ known_hosts_ctx {
	ಧ್ರುವ ವರ್ಣ *host;	/* Hostname searched for in find/delete case */
	FILE *out;		/* Output file, stdout for find_hosts case */
	ಪೂರ್ಣಾಙ್ಕ has_unhashed;	/* When hashing, original had unhashed hosts */
	ಪೂರ್ಣಾಙ್ಕ found_ಕೀಲಿ;		/* For find/delete, host was found */
	ಪೂರ್ಣಾಙ್ಕ invalid;		/* File contained invalid items; don't delete */
	ಪೂರ್ಣಾಙ್ಕ hash_hosts;		/* Hash hostnames as we go */
	ಪೂರ್ಣಾಙ್ಕ find_host;		/* Search for specific hostname */
	ಪೂರ್ಣಾಙ್ಕ delete_host;	/* Delete host from known_hosts */
};

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
known_hosts_hash(ಸಂರಚನಾ hostkey_foreach_ಸಾಲು *l, ಶೂನ್ಯ *_ctx)
{
	ಸಂರಚನಾ known_hosts_ctx *ctx = (ಸಂರಚನಾ known_hosts_ctx *)_ctx;
	ವರ್ಣ *hashed, *cp, *hosts, *ohosts;
	ಪೂರ್ಣಾಙ್ಕ has_wild = l->hosts && strcspn(l->hosts, "*?!") != strlen(l->hosts);
	ಪೂರ್ಣಾಙ್ಕ was_hashed = l->hosts && l->hosts[0] == HASH_DELIM;

	ವಿಕಲ್ಪ (l->status) {
	ಪಕ್ಷ HKF_STATUS_OK:
	ಪಕ್ಷ HKF_STATUS_MATCHED:
		/*
		 * Don't hash hosts already hashed, with wildcard
		 * characters or a CA/revocation marker.
		 */
		ಯದಿ (was_hashed || has_wild || l->marker != MRK_NONE) {
			fprintf(ctx->out, "%s\n", l->ಸಾಲು);
			ಯದಿ (has_wild && !ctx->find_host) {
				logit("%s:%lu: ignoring host name "
				    "with wildcard: %.64s", l->path,
				    l->linenum, l->hosts);
			}
			ಪ್ರತ್ಯಾಗಮ 0;
		}
		/*
		 * Split any comma-separated hostnames from the host list,
		 * hash and store separately.
		 */
		ohosts = hosts = xstrdup(l->hosts);
		ಯಾವತ್ ((cp = strsep(&hosts, ",")) != ರಿಕ್ತ && *cp != '\0') {
			lowercase(cp);
			ಯದಿ ((hashed = host_hash(cp, ರಿಕ್ತ, 0)) == ರಿಕ್ತ)
				fatal("hash_host failed");
			fprintf(ctx->out, "%s %s\n", hashed, l->rawkey);
			ಮುಕ್ತ(hashed);
			ctx->has_unhashed = 1;
		}
		ಮುಕ್ತ(ohosts);
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪಕ್ಷ HKF_STATUS_INVALID:
		/* Retain invalid lines, but mark file as invalid. */
		ctx->invalid = 1;
		logit("%s:%lu: invalid line", l->path, l->linenum);
		/* FALLTHROUGH */
	ಸ್ವಭಾವ:
		fprintf(ctx->out, "%s\n", l->ಸಾಲು);
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	/* NOTREACHED */
	ಪ್ರತ್ಯಾಗಮ -1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
known_hosts_find_delete(ಸಂರಚನಾ hostkey_foreach_ಸಾಲು *l, ಶೂನ್ಯ *_ctx)
{
	ಸಂರಚನಾ known_hosts_ctx *ctx = (ಸಂರಚನಾ known_hosts_ctx *)_ctx;
	ಗಣನಾ sshkey_fp_rep rep;
	ಪೂರ್ಣಾಙ್ಕ fptype;
	ವರ್ಣ *fp = ರಿಕ್ತ, *ra = ರಿಕ್ತ;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;

	ಯದಿ (l->status == HKF_STATUS_MATCHED) {
		ಯದಿ (ctx->delete_host) {
			ಯದಿ (l->marker != MRK_NONE) {
				/* Don't remove CA and revocation lines */
				fprintf(ctx->out, "%s\n", l->ಸಾಲು);
			} ಅನ್ಯಥಾ {
				/*
				 * Hostname matches and has no CA/revoke
				 * marker, delete it by *not* writing the
				 * line to ctx->out.
				 */
				ctx->found_ಕೀಲಿ = 1;
				ಯದಿ (!quiet)
					printf("# Host %s found: line %lu\n",
					    ctx->host, l->linenum);
			}
			ಪ್ರತ್ಯಾಗಮ 0;
		} ಅನ್ಯಥಾ ಯದಿ (ctx->find_host) {
			ctx->found_ಕೀಲಿ = 1;
			ಯದಿ (!quiet) {
				printf("# Host %s found: line %lu %s\n",
				    ctx->host,
				    l->linenum, l->marker == MRK_CA ? "CA" :
				    (l->marker == MRK_REVOKE ? "REVOKED" : ""));
			}
			ಯದಿ (ctx->hash_hosts)
				known_hosts_hash(l, ctx);
			ಅನ್ಯಥಾ ಯದಿ (print_fingerprint) {
				fp = sshkey_fingerprint(l->ಕೀಲಿ, fptype, rep);
				ra = sshkey_fingerprint(l->ಕೀಲಿ,
				    fingerprint_hash, SSH_FP_RANDOMART);
				ಯದಿ (fp == ರಿಕ್ತ || ra == ರಿಕ್ತ)
					fatal_f("sshkey_fingerprint failed");
				mprintf("%s %s %s%s%s\n", ctx->host,
				    sshkey_type(l->ಕೀಲಿ), fp,
				    l->comment[0] ? " " : "",
				    l->comment);
				ಯದಿ (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
					printf("%s\n", ra);
				ಮುಕ್ತ(ra);
				ಮುಕ್ತ(fp);
			} ಅನ್ಯಥಾ
				fprintf(ctx->out, "%s\n", l->ಸಾಲು);
			ಪ್ರತ್ಯಾಗಮ 0;
		}
	} ಅನ್ಯಥಾ ಯದಿ (ctx->delete_host) {
		/* Retain non-matching hosts when deleting */
		ಯದಿ (l->status == HKF_STATUS_INVALID) {
			ctx->invalid = 1;
			logit("%s:%lu: invalid line", l->path, l->linenum);
		}
		fprintf(ctx->out, "%s\n", l->ಸಾಲು);
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_known_hosts(ಸಂರಚನಾ passwd *pw, ಧ್ರುವ ವರ್ಣ *name, ಪೂರ್ಣಾಙ್ಕ find_host,
    ಪೂರ್ಣಾಙ್ಕ delete_host, ಪೂರ್ಣಾಙ್ಕ hash_hosts)
{
	ವರ್ಣ *cp, tmp[PATH_MAX], old[PATH_MAX];
	ಪೂರ್ಣಾಙ್ಕ r, fd, oerrno, inplace = 0;
	ಸಂರಚನಾ known_hosts_ctx ctx;
	u_int foreach_options;
	ಸಂರಚನಾ stat sb;

	ಯದಿ (!have_identity) {
		cp = tilde_expand_filename(_PATH_SSH_USER_HOSTFILE, pw->pw_uid);
		ಯದಿ (strlcpy(identity_file, cp, ಪರಿಮಾಣ(identity_file)) >=
		    ಪರಿಮಾಣ(identity_file))
			fatal("Specified known hosts path too long");
		ಮುಕ್ತ(cp);
		have_identity = 1;
	}
	ಯದಿ (stat(identity_file, &sb) != 0)
		fatal("Cannot stat %s: %s", identity_file, strerror(errno));

	memset(&ctx, 0, ಪರಿಮಾಣ(ctx));
	ctx.out = stdout;
	ctx.host = name;
	ctx.hash_hosts = hash_hosts;
	ctx.find_host = find_host;
	ctx.delete_host = delete_host;

	/*
	 * Find hosts goes to stdout, hash and deletions happen in-place
	 * A corner case is ssh-keygen -HF foo, which should go to stdout
	 */
	ಯದಿ (!find_host && (hash_hosts || delete_host)) {
		ಯದಿ (strlcpy(tmp, identity_file, ಪರಿಮಾಣ(tmp)) >= ಪರಿಮಾಣ(tmp) ||
		    strlcat(tmp, ".XXXXXXXXXX", ಪರಿಮಾಣ(tmp)) >= ಪರಿಮಾಣ(tmp) ||
		    strlcpy(old, identity_file, ಪರಿಮಾಣ(old)) >= ಪರಿಮಾಣ(old) ||
		    strlcat(old, ".old", ಪರಿಮಾಣ(old)) >= ಪರಿಮಾಣ(old))
			fatal("known_hosts path too long");
		umask(077);
		ಯದಿ ((fd = mkstemp(tmp)) == -1)
			fatal("mkstemp: %s", strerror(errno));
		ಯದಿ ((ctx.out = fdopen(fd, "w")) == ರಿಕ್ತ) {
			oerrno = errno;
			unlink(tmp);
			fatal("fdopen: %s", strerror(oerrno));
		}
		(ಶೂನ್ಯ)fchmod(fd, sb.st_mode & 0644);
		inplace = 1;
	}
	/* XXX support identity_file == "-" for stdin */
	foreach_options = find_host ? HKF_WANT_MATCH : 0;
	foreach_options |= print_fingerprint ? HKF_WANT_PARSE_ಕೀಲಿ : 0;
	ಯದಿ ((r = hostkeys_foreach(identity_file, (find_host || !hash_hosts) ?
	    known_hosts_find_delete : known_hosts_hash, &ctx, name, ರಿಕ್ತ,
	    foreach_options, 0)) != 0) {
		ಯದಿ (inplace)
			unlink(tmp);
		fatal_fr(r, "hostkeys_foreach");
	}

	ಯದಿ (inplace)
		fclose(ctx.out);

	ಯದಿ (ctx.invalid) {
		error("%s is not a valid known_hosts file.", identity_file);
		ಯದಿ (inplace) {
			error("Not replacing existing known_hosts "
			    "file because of errors");
			unlink(tmp);
		}
		exit(1);
	} ಅನ್ಯಥಾ ಯದಿ (delete_host && !ctx.found_ಕೀಲಿ) {
		logit("Host %s not found in %s", name, identity_file);
		ಯದಿ (inplace)
			unlink(tmp);
	} ಅನ್ಯಥಾ ಯದಿ (inplace) {
		/* Backup existing file */
		ಯದಿ (unlink(old) == -1 && errno != ENOENT)
			fatal("unlink %.100s: %s", old, strerror(errno));
		ಯದಿ (link(identity_file, old) == -1)
			fatal("link %.100s to %.100s: %s", identity_file, old,
			    strerror(errno));
		/* Move new one into place */
		ಯದಿ (rename(tmp, identity_file) == -1) {
			error("rename\"%s\" to \"%s\": %s", tmp, identity_file,
			    strerror(errno));
			unlink(tmp);
			unlink(old);
			exit(1);
		}

		printf("%s updated.\n", identity_file);
		printf("Original contents retained as %s\n", old);
		ಯದಿ (ctx.has_unhashed) {
			logit("WARNING: %s contains unhashed entries", old);
			logit("Delete this file to ensure privacy "
			    "of hostnames");
		}
	}

	exit (find_host && !ctx.found_ಕೀಲಿ);
}

/*
 * Perform changing a passphrase.  The argument is the passwd structure
 * for the current user.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
do_change_passphrase(ಸಂರಚನಾ passwd *pw, ವರ್ಣ * ಧ್ರುವ *opts, size_t nopts)
{
	ವರ್ಣ *comment;
	ವರ್ಣ *old_passphrase, *passphrase1, *passphrase2;
	ಸಂರಚನಾ stat st;
	ಸಂರಚನಾ sshkey *ಗುಪ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r;
	size_t i;

	ಯದಿ (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	ಯದಿ (stat(identity_file, &st) == -1)
		fatal("%s: %s", identity_file, strerror(errno));
	/* Try to load the file with empty passphrase. */
	r = sshkey_load_private(identity_file, "", &ಗುಪ್ತ, &comment);
	ಯದಿ (r == SSH_ERR_ಕೀಲಿ_WRONG_PASSPHRASE) {
		ಯದಿ (identity_passphrase)
			old_passphrase = xstrdup(identity_passphrase);
		ಅನ್ಯಥಾ
			old_passphrase =
			    read_passphrase("Enter old passphrase: ",
			    RP_ALLOW_STDIN);
		r = sshkey_load_private(identity_file, old_passphrase,
		    &ಗುಪ್ತ, &comment);
		freezero(old_passphrase, strlen(old_passphrase));
		ಯದಿ (r != 0)
			ಗಚ್ಛ badkey;
	} ಅನ್ಯಥಾ ಯದಿ (r != 0) {
 badkey:
		fatal_r(r, "Failed to load key %s", identity_file);
	}
	ಯದಿ (comment)
		mprintf("Key has comment '%s'\n", comment);

	/* All current -O options relate to FIDO keys only */
	ಯದಿ (nopts != 0 && !sshkey_is_sk(ಗುಪ್ತ)) {
		fatal("FIDO-specific option requested for non-FIDO key %s",
		    identity_file);
	}
	ಯದಿ (sshkey_is_sk(ಗುಪ್ತ)) {
		debug_f("%s: original FIDO key flags: "
		    "%stouch-required %sverify-required", identity_file,
		    (ಗುಪ್ತ->sk_flags & SSH_SK_USER_PRESENCE_REQD) ? "": "no-",
		    (ಗುಪ್ತ->sk_flags & SSH_SK_USER_VERIFICATION_REQD) ? "" : "no-");
	}
	ಪ್ರತಿ (i = 0; i < nopts; i++) {
		ಯದಿ (strcasecmp(opts[i], "touch-required") == 0)
			ಗುಪ್ತ->sk_flags |= SSH_SK_USER_PRESENCE_REQD;
		ಅನ್ಯಥಾ ಯದಿ (strcasecmp(opts[i], "no-touch-required") == 0)
			ಗುಪ್ತ->sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
		ಅನ್ಯಥಾ ಯದಿ (strcasecmp(opts[i], "verify-required") == 0)
			ಗುಪ್ತ->sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
		ಅನ್ಯಥಾ ಯದಿ (strcasecmp(opts[i], "no-verify-required") == 0)
			ಗುಪ್ತ->sk_flags &= ~SSH_SK_USER_VERIFICATION_REQD;
		ಅನ್ಯಥಾ {
			fatal("Option \"%s\" is unsupported for "
			    "key passphrase change", opts[i]);
		}
	}
	ಯದಿ (sshkey_is_sk(ಗುಪ್ತ) && nopts != 0) {
		debug_f("%s: updated FIDO key flags: "
		    "%stouch-required %sverify-required", identity_file,
		    (ಗುಪ್ತ->sk_flags & SSH_SK_USER_PRESENCE_REQD) ? "": "no-",
		    (ಗುಪ್ತ->sk_flags & SSH_SK_USER_VERIFICATION_REQD) ? "" : "no-");
	}

	/* Ask the new passphrase (twice). */
	ಯದಿ (identity_new_passphrase) {
		passphrase1 = xstrdup(identity_new_passphrase);
		passphrase2 = ರಿಕ್ತ;
	} ಅನ್ಯಥಾ {
		passphrase1 =
			read_passphrase("Enter new passphrase (empty for no "
			    "passphrase): ", RP_ALLOW_STDIN);
		passphrase2 = read_passphrase("Enter same passphrase again: ",
		    RP_ALLOW_STDIN);

		/* Verify that they are the same. */
		ಯದಿ (strcmp(passphrase1, passphrase2) != 0) {
			explicit_bzero(passphrase1, strlen(passphrase1));
			explicit_bzero(passphrase2, strlen(passphrase2));
			ಮುಕ್ತ(passphrase1);
			ಮುಕ್ತ(passphrase2);
			printf("Pass phrases do not match.  Try again.\n");
			exit(1);
		}
		/* Destroy the other copy. */
		freezero(passphrase2, strlen(passphrase2));
	}

	/* Save the file using the new passphrase. */
	ಯದಿ ((r = sshkey_save_private(ಗುಪ್ತ, identity_file, passphrase1,
	    comment, private_ಕೀಲಿ_format, openssh_format_cipher, rounds)) != 0) {
		error_r(r, "Saving key \"%s\" failed", identity_file);
		freezero(passphrase1, strlen(passphrase1));
		sshkey_free(ಗುಪ್ತ);
		ಮುಕ್ತ(comment);
		exit(1);
	}
	/* Destroy the passphrase and the copy of the key in memory. */
	freezero(passphrase1, strlen(passphrase1));
	sshkey_free(ಗುಪ್ತ);		 /* Destroys contents */
	ಮುಕ್ತ(comment);

	printf("Your identification has been saved with the new passphrase.\n");
	exit(0);
}

/*
 * Print the SSHFP RR.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
do_print_resource_record(ಸಂರಚನಾ passwd *pw, ವರ್ಣ *fname, ವರ್ಣ *hname,
    ಪೂರ್ಣಾಙ್ಕ print_generic, ವರ್ಣ * ಧ್ರುವ *opts, size_t nopts)
{
	ಸಂರಚನಾ sshkey *ಸಾರ್ವಜನಿಕ;
	ವರ್ಣ *comment = ರಿಕ್ತ;
	ಧ್ರುವ ವರ್ಣ *p;
	ಸಂರಚನಾ stat st;
	ಪೂರ್ಣಾಙ್ಕ r, hash = -1;
	size_t i;

	ಪ್ರತಿ (i = 0; i < nopts; i++) {
		ಯದಿ ((p = strprefix(opts[i], "hashalg=", 1)) != ರಿಕ್ತ) {
			ಯದಿ ((hash = ssh_digest_alg_by_name(p)) == -1)
				fatal("Unsupported hash algorithm");
		} ಅನ್ಯಥಾ {
			error("Invalid option \"%s\"", opts[i]);
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
		}
	}
	ಯದಿ (fname == ರಿಕ್ತ)
		fatal_f("no filename");
	ಯದಿ (stat(fname, &st) == -1) {
		ಯದಿ (errno == ENOENT)
			ಪ್ರತ್ಯಾಗಮ 0;
		fatal("%s: %s", fname, strerror(errno));
	}
	ಯದಿ ((r = sshkey_load_public(fname, &ಸಾರ್ವಜನಿಕ, &comment)) != 0)
		fatal_r(r, "Failed to read v2 public key from \"%s\"", fname);
	export_dns_rr(hname, ಸಾರ್ವಜನಿಕ, stdout, print_generic, hash);
	sshkey_free(ಸಾರ್ವಜನಿಕ);
	ಮುಕ್ತ(comment);
	ಪ್ರತ್ಯಾಗಮ 1;
}

/*
 * Change the comment of a private key file.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
do_change_comment(ಸಂರಚನಾ passwd *pw, ಧ್ರುವ ವರ್ಣ *identity_comment)
{
	ವರ್ಣ new_comment[ಕೀಲಿ_COMMENT_MAX], *comment, *passphrase;
	ಸಂರಚನಾ sshkey *ಗುಪ್ತ;
	ಸಂರಚನಾ sshkey *ಸಾರ್ವಜನಿಕ;
	ಸಂರಚನಾ stat st;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	ಯದಿ (stat(identity_file, &st) == -1)
		fatal("%s: %s", identity_file, strerror(errno));
	ಯದಿ ((r = sshkey_load_private(identity_file, "",
	    &ಗುಪ್ತ, &comment)) == 0)
		passphrase = xstrdup("");
	ಅನ್ಯಥಾ ಯದಿ (r != SSH_ERR_ಕೀಲಿ_WRONG_PASSPHRASE)
		fatal_r(r, "Cannot load private key \"%s\"", identity_file);
	ಅನ್ಯಥಾ {
		ಯದಿ (identity_passphrase)
			passphrase = xstrdup(identity_passphrase);
		ಅನ್ಯಥಾ ಯದಿ (identity_new_passphrase)
			passphrase = xstrdup(identity_new_passphrase);
		ಅನ್ಯಥಾ
			passphrase = read_passphrase("Enter passphrase: ",
			    RP_ALLOW_STDIN);
		/* Try to load using the passphrase. */
		ಯದಿ ((r = sshkey_load_private(identity_file, passphrase,
		    &ಗುಪ್ತ, &comment)) != 0) {
			freezero(passphrase, strlen(passphrase));
			fatal_r(r, "Cannot load private key \"%s\"",
			    identity_file);
		}
	}

	ಯದಿ (ಗುಪ್ತ->type != ಕೀಲಿ_ED25519 &&
	    private_ಕೀಲಿ_format != SSHKEY_PRIVATE_OPENSSH) {
		error("Comments are only supported for keys stored in "
		    "the new format (-o).");
		explicit_bzero(passphrase, strlen(passphrase));
		sshkey_free(ಗುಪ್ತ);
		exit(1);
	}
	ಯದಿ (comment)
		printf("Old comment: %s\n", comment);
	ಅನ್ಯಥಾ
		printf("No existing comment\n");

	ಯದಿ (identity_comment) {
		strlcpy(new_comment, identity_comment, ಪರಿಮಾಣ(new_comment));
	} ಅನ್ಯಥಾ {
		printf("New comment: ");
		fflush(stdout);
		ಯದಿ (!fgets(new_comment, ಪರಿಮಾಣ(new_comment), stdin)) {
			explicit_bzero(passphrase, strlen(passphrase));
			sshkey_free(ಗುಪ್ತ);
			exit(1);
		}
		new_comment[strcspn(new_comment, "\n")] = '\0';
	}
	ಯದಿ (comment != ರಿಕ್ತ && strcmp(comment, new_comment) == 0) {
		printf("No change to comment\n");
		ಮುಕ್ತ(passphrase);
		sshkey_free(ಗುಪ್ತ);
		ಮುಕ್ತ(comment);
		exit(0);
	}

	/* Save the file using the new passphrase. */
	ಯದಿ ((r = sshkey_save_private(ಗುಪ್ತ, identity_file, passphrase,
	    new_comment, private_ಕೀಲಿ_format, openssh_format_cipher,
	    rounds)) != 0) {
		error_r(r, "Saving key \"%s\" failed", identity_file);
		freezero(passphrase, strlen(passphrase));
		sshkey_free(ಗುಪ್ತ);
		ಮುಕ್ತ(comment);
		exit(1);
	}
	freezero(passphrase, strlen(passphrase));
	ಯದಿ ((r = sshkey_from_private(ಗುಪ್ತ, &ಸಾರ್ವಜನಿಕ)) != 0)
		fatal_fr(r, "sshkey_from_private");
	sshkey_free(ಗುಪ್ತ);

	strlcat(identity_file, ".pub", ಪರಿಮಾಣ(identity_file));
	ಯದಿ ((r = sshkey_save_public(ಸಾರ್ವಜನಿಕ, identity_file, new_comment)) != 0)
		fatal_r(r, "Unable to save public key to %s", identity_file);
	sshkey_free(ಸಾರ್ವಜನಿಕ);
	ಮುಕ್ತ(comment);

	ಯದಿ (strlen(new_comment) > 0)
		printf("Comment '%s' applied\n", new_comment);
	ಅನ್ಯಥಾ
		printf("Comment removed\n");

	exit(0);
}

ಸ್ಥಿರ ಶೂನ್ಯ
cert_ext_add(ಧ್ರುವ ವರ್ಣ *ಕೀಲಿ, ಧ್ರುವ ವರ್ಣ *ಮೌಲ್ಯ, ಪೂರ್ಣಾಙ್ಕ iscrit)
{
	cert_ext = xreallocarray(cert_ext, ncert_ext + 1, ಪರಿಮಾಣ(*cert_ext));
	cert_ext[ncert_ext].ಕೀಲಿ = xstrdup(ಕೀಲಿ);
	cert_ext[ncert_ext].val = ಮೌಲ್ಯ == ರಿಕ್ತ ? ರಿಕ್ತ : xstrdup(ಮೌಲ್ಯ);
	cert_ext[ncert_ext].crit = iscrit;
	ncert_ext++;
}

/* qsort(3) comparison function for certificate extensions */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
cert_ext_cmp(ಧ್ರುವ ಶೂನ್ಯ *_a, ಧ್ರುವ ಶೂನ್ಯ *_b)
{
	ಧ್ರುವ ಸಂರಚನಾ cert_ext *a = (ಧ್ರುವ ಸಂರಚನಾ cert_ext *)_a;
	ಧ್ರುವ ಸಂರಚನಾ cert_ext *b = (ಧ್ರುವ ಸಂರಚನಾ cert_ext *)_b;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (a->crit != b->crit)
		ಪ್ರತ್ಯಾಗಮ (a->crit < b->crit) ? -1 : 1;
	ಯದಿ ((r = strcmp(a->ಕೀಲಿ, b->ಕೀಲಿ)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ ((a->val == ರಿಕ್ತ) != (b->val == ರಿಕ್ತ))
		ಪ್ರತ್ಯಾಗಮ (a->val == ರಿಕ್ತ) ? -1 : 1;
	ಯದಿ (a->val != ರಿಕ್ತ && (r = strcmp(a->val, b->val)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಪ್ರತ್ಯಾಗಮ 0;
}

#define OPTIONS_CRITICAL	1
#define OPTIONS_EXTENSIONS	2
ಸ್ಥಿರ ಶೂನ್ಯ
prepare_options_buf(ಸಂರಚನಾ sshbuf *c, ಪೂರ್ಣಾಙ್ಕ which)
{
	ಸಂರಚನಾ sshbuf *b;
	size_t i;
	ಪೂರ್ಣಾಙ್ಕ r;
	ಧ್ರುವ ಸಂರಚನಾ cert_ext *ext;

	ಯದಿ ((b = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	sshbuf_reset(c);
	ಪ್ರತಿ (i = 0; i < ncert_ext; i++) {
		ext = &cert_ext[i];
		ಯದಿ ((ext->crit && (which & OPTIONS_EXTENSIONS)) ||
		    (!ext->crit && (which & OPTIONS_CRITICAL)))
			ಅನುವರ್ತ;
		ಯದಿ (ext->val == ರಿಕ್ತ) {
			/* flag option */
			debug3_f("%s", ext->ಕೀಲಿ);
			ಯದಿ ((r = sshbuf_put_cstring(c, ext->ಕೀಲಿ)) != 0 ||
			    (r = sshbuf_put_string(c, ರಿಕ್ತ, 0)) != 0)
				fatal_fr(r, "prepare flag");
		} ಅನ್ಯಥಾ {
			/* key/value option */
			debug3_f("%s=%s", ext->ಕೀಲಿ, ext->val);
			sshbuf_reset(b);
			ಯದಿ ((r = sshbuf_put_cstring(c, ext->ಕೀಲಿ)) != 0 ||
			    (r = sshbuf_put_cstring(b, ext->val)) != 0 ||
			    (r = sshbuf_put_stringb(c, b)) != 0)
				fatal_fr(r, "prepare k/v");
		}
	}
	sshbuf_free(b);
}

ಸ್ಥಿರ ಶೂನ್ಯ
finalise_cert_exts(ಶೂನ್ಯ)
{
	/* critical options */
	ಯದಿ (certflags_command != ರಿಕ್ತ)
		cert_ext_add("force-command", certflags_command, 1);
	ಯದಿ (certflags_src_addr != ರಿಕ್ತ)
		cert_ext_add("source-address", certflags_src_addr, 1);
	ಯದಿ ((certflags_flags & CERTOPT_REQUIRE_VERIFY) != 0)
		cert_ext_add("verify-required", ರಿಕ್ತ, 1);
	/* extensions */
	ಯದಿ ((certflags_flags & CERTOPT_X_FWD) != 0)
		cert_ext_add("permit-X11-forwarding", ರಿಕ್ತ, 0);
	ಯದಿ ((certflags_flags & CERTOPT_AGENT_FWD) != 0)
		cert_ext_add("permit-agent-forwarding", ರಿಕ್ತ, 0);
	ಯದಿ ((certflags_flags & CERTOPT_PORT_FWD) != 0)
		cert_ext_add("permit-port-forwarding", ರಿಕ್ತ, 0);
	ಯದಿ ((certflags_flags & CERTOPT_PTY) != 0)
		cert_ext_add("permit-pty", ರಿಕ್ತ, 0);
	ಯದಿ ((certflags_flags & CERTOPT_USER_RC) != 0)
		cert_ext_add("permit-user-rc", ರಿಕ್ತ, 0);
	ಯದಿ ((certflags_flags & CERTOPT_NO_REQUIRE_USER_PRESENCE) != 0)
		cert_ext_add("no-touch-required", ರಿಕ್ತ, 0);
	/* order lexically by key */
	ಯದಿ (ncert_ext > 0)
		qsort(cert_ext, ncert_ext, ಪರಿಮಾಣ(*cert_ext), cert_ext_cmp);
}

ಸ್ಥಿರ ಸಂರಚನಾ sshkey *
load_pkcs11_ಕೀಲಿ(ವರ್ಣ *path)
{
#ifdef ENABLE_PKCS11
	ಸಂರಚನಾ sshkey **ಕೀಲಿಗಳು = ರಿಕ್ತ, *ಸಾರ್ವಜನಿಕ, *ಗುಪ್ತ = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r, i, nkeys;

	ಯದಿ ((r = sshkey_load_public(path, &ಸಾರ್ವಜನಿಕ, ರಿಕ್ತ)) != 0)
		fatal_r(r, "Couldn't load CA public key \"%s\"", path);

	nkeys = pkcs11_add_provider(pkcs11provider, identity_passphrase,
	    &ಕೀಲಿಗಳು, ರಿಕ್ತ);
	debug3_f("%d keys", nkeys);
	ಯದಿ (nkeys <= 0)
		fatal("cannot read public key from pkcs11");
	ಪ್ರತಿ (i = 0; i < nkeys; i++) {
		ಯದಿ (sshkey_equal_public(ಸಾರ್ವಜನಿಕ, ಕೀಲಿಗಳು[i])) {
			ಗುಪ್ತ = ಕೀಲಿಗಳು[i];
			ಅನುವರ್ತ;
		}
		sshkey_free(ಕೀಲಿಗಳು[i]);
	}
	ಮುಕ್ತ(ಕೀಲಿಗಳು);
	sshkey_free(ಸಾರ್ವಜನಿಕ);
	ಪ್ರತ್ಯಾಗಮ ಗುಪ್ತ;
#ಅನ್ಯಥಾ
	fatal("no pkcs11 support");
#endif /* ENABLE_PKCS11 */
}

/* Signer for sshkey_certify_custom that uses the agent */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
agent_signer(ಸಂರಚನಾ sshkey *ಕೀಲಿ, u_char **sigp, size_t *lenp,
    ಧ್ರುವ u_char *data, size_t datalen,
    ಧ್ರುವ ವರ್ಣ *alg, ಧ್ರುವ ವರ್ಣ *provider, ಧ್ರುವ ವರ್ಣ *pin,
    u_int compat, ಶೂನ್ಯ *ctx)
{
	ಪೂರ್ಣಾಙ್ಕ *agent_fdp = (ಪೂರ್ಣಾಙ್ಕ *)ctx;

	ಪ್ರತ್ಯಾಗಮ ssh_agent_sign(*agent_fdp, ಕೀಲಿ, sigp, lenp,
	    data, datalen, alg, compat);
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_ca_sign(ಸಂರಚನಾ passwd *pw, ಧ್ರುವ ವರ್ಣ *ca_ಕೀಲಿ_path, ಪೂರ್ಣಾಙ್ಕ prefer_agent,
    unsigned long long cert_serial, ಪೂರ್ಣಾಙ್ಕ cert_serial_autoinc,
    ಪೂರ್ಣಾಙ್ಕ argc, ವರ್ಣ **argv)
{
	ಪೂರ್ಣಾಙ್ಕ r, i, ಕೀಲಿ_in_agent = 0, agent_fd = -1;
	u_int n;
	ಸಂರಚನಾ sshkey *ca, *ಸಾರ್ವಜನಿಕ;
	ವರ್ಣ valid[64], *otmp, *tmp, *cp, *out, *comment;
	ವರ್ಣ *ca_fp = ರಿಕ್ತ, **plist = ರಿಕ್ತ, *pin = ರಿಕ್ತ;
	ಸಂರಚನಾ ssh_identitylist *agent_ids;
	size_t j;
	ಸಂರಚನಾ notifier_ctx *notifier = ರಿಕ್ತ;

#ifdef ENABLE_PKCS11
	pkcs11_init(1);
#endif
	tmp = tilde_expand_filename(ca_ಕೀಲಿ_path, pw->pw_uid);
	ಯದಿ (pkcs11provider != ರಿಕ್ತ) {
		/* If a PKCS#11 token was specified then try to use it */
		ಯದಿ ((ca = load_pkcs11_ಕೀಲಿ(tmp)) == ರಿಕ್ತ)
			fatal("No PKCS#11 key matching %s found", ca_ಕೀಲಿ_path);
	} ಅನ್ಯಥಾ ಯದಿ (prefer_agent) {
		/*
		 * Agent signature requested. Try to use agent after making
		 * sure the public key specified is actually present in the
		 * agent.
		 */
		ಯದಿ ((r = sshkey_load_public(tmp, &ca, ರಿಕ್ತ)) != 0)
			fatal_r(r, "Cannot load CA public key %s", tmp);
		ಯದಿ ((r = ssh_get_authentication_socket(&agent_fd)) != 0)
			fatal_r(r, "Cannot use public key for CA signature");
		ಯದಿ ((r = ssh_fetch_identitylist(agent_fd, &agent_ids)) != 0)
			fatal_r(r, "Retrieve agent key list");
		ಪ್ರತಿ (j = 0; j < agent_ids->nkeys; j++) {
			ಯದಿ (sshkey_equal(ca, agent_ids->ಕೀಲಿಗಳು[j])) {
				ಕೀಲಿ_in_agent = 1;
				/* Replace the CA key with the agent one */
				sshkey_free(ca);
				ca = agent_ids->ಕೀಲಿಗಳು[j];
				agent_ids->ಕೀಲಿಗಳು[j] = ರಿಕ್ತ;
				ಭಙ್ಗ;
			}
		}
		ಯದಿ (!ಕೀಲಿ_in_agent)
			fatal("CA key %s not found in agent", tmp);
		ssh_free_identitylist(agent_ids);
	} ಅನ್ಯಥಾ {
		/* CA key is assumed to be a private key on the filesystem */
		ca = load_identity(tmp, ರಿಕ್ತ);
		ಯದಿ (sshkey_is_sk(ca) &&
		    (ca->sk_flags & SSH_SK_USER_VERIFICATION_REQD)) {
			ಯದಿ ((pin = read_passphrase("Enter PIN for CA key: ",
			    RP_ALLOW_STDIN)) == ರಿಕ್ತ)
				fatal_f("couldn't read PIN");
		}
	}
	ಮುಕ್ತ(tmp);

	ಯದಿ (ಕೀಲಿ_type_name != ರಿಕ್ತ) {
		ಯದಿ (sshkey_type_from_shortname(ಕೀಲಿ_type_name) != ca->type) {
			fatal("CA key type %s doesn't match specified %s",
			    sshkey_ssh_name(ca), ಕೀಲಿ_type_name);
		}
	} ಅನ್ಯಥಾ ಯದಿ (ca->type == ಕೀಲಿ_RSA) {
		/* Default to a good signature algorithm */
		ಕೀಲಿ_type_name = "rsa-sha2-512";
	}
	ca_fp = sshkey_fingerprint(ca, fingerprint_hash, SSH_FP_DEFAULT);

	finalise_cert_exts();
	ಪ್ರತಿ (i = 0; i < argc; i++) {
		/* Split list of principals */
		n = 0;
		ಯದಿ (cert_principals != ರಿಕ್ತ) {
			otmp = tmp = xstrdup(cert_principals);
			plist = ರಿಕ್ತ;
			ಪ್ರತಿ (; (cp = strsep(&tmp, ",")) != ರಿಕ್ತ; n++) {
				plist = xreallocarray(plist, n + 1, ಪರಿಮಾಣ(*plist));
				ಯದಿ (*(plist[n] = xstrdup(cp)) == '\0')
					fatal("Empty principal name");
			}
			ಮುಕ್ತ(otmp);
		}
		ಯದಿ (n > SSHKEY_CERT_MAX_PRINCIPALS)
			fatal("Too many certificate principals specified");

		tmp = tilde_expand_filename(argv[i], pw->pw_uid);
		ಯದಿ ((r = sshkey_load_public(tmp, &ಸಾರ್ವಜನಿಕ, &comment)) != 0)
			fatal_r(r, "load pubkey \"%s\"", tmp);
		ಯದಿ (sshkey_is_cert(ಸಾರ್ವಜನಿಕ))
			fatal_f("key \"%s\" type %s cannot be certified",
			    tmp, sshkey_type(ಸಾರ್ವಜನಿಕ));

		/* Prepare certificate to sign */
		ಯದಿ ((r = sshkey_to_certified(ಸಾರ್ವಜನಿಕ)) != 0)
			fatal_r(r, "Could not upgrade key %s to certificate", tmp);
		ಸಾರ್ವಜನಿಕ->cert->type = cert_ಕೀಲಿ_type;
		ಸಾರ್ವಜನಿಕ->cert->serial = (uint64_t)cert_serial;
		ಸಾರ್ವಜನಿಕ->cert->ಕೀಲಿ_id = xstrdup(cert_ಕೀಲಿ_id);
		ಸಾರ್ವಜನಿಕ->cert->nprincipals = n;
		ಸಾರ್ವಜನಿಕ->cert->principals = plist;
		ಸಾರ್ವಜನಿಕ->cert->valid_after = cert_valid_from;
		ಸಾರ್ವಜನಿಕ->cert->valid_before = cert_valid_to;
		prepare_options_buf(ಸಾರ್ವಜನಿಕ->cert->critical, OPTIONS_CRITICAL);
		prepare_options_buf(ಸಾರ್ವಜನಿಕ->cert->extensions,
		    OPTIONS_EXTENSIONS);
		ಯದಿ ((r = sshkey_from_private(ca,
		    &ಸಾರ್ವಜನಿಕ->cert->signature_ಕೀಲಿ)) != 0)
			fatal_r(r, "sshkey_from_private (ca key)");

		ಯದಿ (ಕೀಲಿ_in_agent) {
			ಯದಿ ((r = sshkey_certify_custom(ಸಾರ್ವಜನಿಕ, ca,
			    ಕೀಲಿ_type_name, sk_provider, ರಿಕ್ತ, agent_signer,
			    &agent_fd)) != 0)
				fatal_r(r, "Couldn't certify %s via agent", tmp);
		} ಅನ್ಯಥಾ {
			ಯದಿ (sshkey_is_sk(ca) &&
			    (ca->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
				notifier = notify_start(0,
				    "Confirm user presence for key %s %s",
				    sshkey_type(ca), ca_fp);
			}
			r = sshkey_certify(ಸಾರ್ವಜನಿಕ, ca, ಕೀಲಿ_type_name,
			    sk_provider, pin);
			notify_complete(notifier, "User presence confirmed");
			ಯದಿ (r != 0)
				fatal_r(r, "Couldn't certify key %s", tmp);
		}

		ಯದಿ ((cp = strrchr(tmp, '.')) != ರಿಕ್ತ && strcmp(cp, ".pub") == 0)
			*cp = '\0';
		xasprintf(&out, "%s-cert.pub", tmp);
		ಮುಕ್ತ(tmp);

		ಯದಿ ((r = sshkey_save_public(ಸಾರ್ವಜನಿಕ, out, comment)) != 0) {
			fatal_r(r, "Unable to save public key to %s",
			    identity_file);
		}

		ಯದಿ (!quiet) {
			sshkey_format_cert_validity(ಸಾರ್ವಜನಿಕ->cert,
			    valid, ಪರಿಮಾಣ(valid));
			logit("Signed %s key %s: id \"%s\" serial %llu%s%s "
			    "valid %s", sshkey_cert_type(ಸಾರ್ವಜನಿಕ),
			    out, ಸಾರ್ವಜನಿಕ->cert->ಕೀಲಿ_id,
			    (unsigned long long)ಸಾರ್ವಜನಿಕ->cert->serial,
			    cert_principals != ರಿಕ್ತ ? " for " : "",
			    cert_principals != ರಿಕ್ತ ? cert_principals : "",
			    valid);
		}

		sshkey_free(ಸಾರ್ವಜನಿಕ);
		ಮುಕ್ತ(out);
		ಮುಕ್ತ(comment);
		ಯದಿ (cert_serial_autoinc)
			cert_serial++;
	}
	ಯದಿ (pin != ರಿಕ್ತ)
		freezero(pin, strlen(pin));
	sshkey_free(ca);
	ಮುಕ್ತ(ca_fp);
#ifdef ENABLE_PKCS11
	pkcs11_terminate();
#endif
}

ಸ್ಥಿರ uint64_t
parse_relative_time(ಧ್ರುವ ವರ್ಣ *s, time_t now)
{
	int64_t mul, secs;

	mul = *s == '-' ? -1 : 1;

	ಯದಿ ((secs = convtime(s + 1)) == -1)
		fatal("Invalid relative certificate time %s", s);
	ಯದಿ (mul == -1 && secs > now)
		fatal("Certificate time %s cannot be represented", s);
	ಪ್ರತ್ಯಾಗಮ now + (uint64_t)(secs * mul);
}

ಸ್ಥಿರ ಶೂನ್ಯ
parse_hex_u64(ಧ್ರುವ ವರ್ಣ *s, uint64_t *up)
{
	ವರ್ಣ *ep;
	unsigned long long ull;

	errno = 0;
	ull = strtoull(s, &ep, 16);
	ಯದಿ (*s == '\0' || *ep != '\0')
		fatal("Invalid certificate time: not a number");
	ಯದಿ (errno == ERANGE && ull == ULONG_MAX)
		fatal_fr(SSH_ERR_SYSTEM_ERROR, "Invalid certificate time");
	*up = (uint64_t)ull;
}

ಸ್ಥಿರ ಶೂನ್ಯ
parse_cert_times(ವರ್ಣ *timespec)
{
	ವರ್ಣ *from, *to;
	time_t now = time(ರಿಕ್ತ);
	int64_t secs;

	/* +timespec relative to now */
	ಯದಿ (*timespec == '+' && strchr(timespec, ':') == ರಿಕ್ತ) {
		ಯದಿ ((secs = convtime(timespec + 1)) == -1)
			fatal("Invalid relative certificate life %s", timespec);
		cert_valid_to = now + secs;
		/*
		 * Backdate certificate one minute to avoid problems on hosts
		 * with poorly-synchronised clocks.
		 */
		cert_valid_from = ((now - 59)/ 60) * 60;
		ಪ್ರತ್ಯಾಗಮ;
	}

	/*
	 * from:to, where
	 * from := [+-]timespec | YYYYMMDD | YYYYMMDDHHMMSS | 0x... | "always"
	 *   to := [+-]timespec | YYYYMMDD | YYYYMMDDHHMMSS | 0x... | "forever"
	 */
	from = xstrdup(timespec);
	to = strchr(from, ':');
	ಯದಿ (to == ರಿಕ್ತ || from == to || *(to + 1) == '\0')
		fatal("Invalid certificate life specification %s", timespec);
	*to++ = '\0';

	ಯದಿ (*from == '-' || *from == '+')
		cert_valid_from = parse_relative_time(from, now);
	ಅನ್ಯಥಾ ಯದಿ (strcmp(from, "always") == 0)
		cert_valid_from = 0;
	ಅನ್ಯಥಾ ಯದಿ (strncmp(from, "0x", 2) == 0)
		parse_hex_u64(from, &cert_valid_from);
	ಅನ್ಯಥಾ ಯದಿ (parse_absolute_time(from, &cert_valid_from) != 0)
		fatal("Invalid from time \"%s\"", from);

	ಯದಿ (*to == '-' || *to == '+')
		cert_valid_to = parse_relative_time(to, now);
	ಅನ್ಯಥಾ ಯದಿ (strcmp(to, "forever") == 0)
		cert_valid_to = ~(uint64_t)0;
	ಅನ್ಯಥಾ ಯದಿ (strncmp(to, "0x", 2) == 0)
		parse_hex_u64(to, &cert_valid_to);
	ಅನ್ಯಥಾ ಯದಿ (parse_absolute_time(to, &cert_valid_to) != 0)
		fatal("Invalid to time \"%s\"", to);

	ಯದಿ (cert_valid_to <= cert_valid_from)
		fatal("Empty certificate validity interval");
	ಮುಕ್ತ(from);
}

ಸ್ಥಿರ ಶೂನ್ಯ
add_cert_option(ವರ್ಣ *opt)
{
	ವರ್ಣ *val, *cp;
	ಧ್ರುವ ವರ್ಣ *p;
	ಪೂರ್ಣಾಙ್ಕ iscrit = 0;

	ಯದಿ (strcasecmp(opt, "clear") == 0)
		certflags_flags = 0;
	ಅನ್ಯಥಾ ಯದಿ (strcasecmp(opt, "no-x11-forwarding") == 0)
		certflags_flags &= ~CERTOPT_X_FWD;
	ಅನ್ಯಥಾ ಯದಿ (strcasecmp(opt, "permit-x11-forwarding") == 0)
		certflags_flags |= CERTOPT_X_FWD;
	ಅನ್ಯಥಾ ಯದಿ (strcasecmp(opt, "no-agent-forwarding") == 0)
		certflags_flags &= ~CERTOPT_AGENT_FWD;
	ಅನ್ಯಥಾ ಯದಿ (strcasecmp(opt, "permit-agent-forwarding") == 0)
		certflags_flags |= CERTOPT_AGENT_FWD;
	ಅನ್ಯಥಾ ಯದಿ (strcasecmp(opt, "no-port-forwarding") == 0)
		certflags_flags &= ~CERTOPT_PORT_FWD;
	ಅನ್ಯಥಾ ಯದಿ (strcasecmp(opt, "permit-port-forwarding") == 0)
		certflags_flags |= CERTOPT_PORT_FWD;
	ಅನ್ಯಥಾ ಯದಿ (strcasecmp(opt, "no-pty") == 0)
		certflags_flags &= ~CERTOPT_PTY;
	ಅನ್ಯಥಾ ಯದಿ (strcasecmp(opt, "permit-pty") == 0)
		certflags_flags |= CERTOPT_PTY;
	ಅನ್ಯಥಾ ಯದಿ (strcasecmp(opt, "no-user-rc") == 0)
		certflags_flags &= ~CERTOPT_USER_RC;
	ಅನ್ಯಥಾ ಯದಿ (strcasecmp(opt, "permit-user-rc") == 0)
		certflags_flags |= CERTOPT_USER_RC;
	ಅನ್ಯಥಾ ಯದಿ (strcasecmp(opt, "touch-required") == 0)
		certflags_flags &= ~CERTOPT_NO_REQUIRE_USER_PRESENCE;
	ಅನ್ಯಥಾ ಯದಿ (strcasecmp(opt, "no-touch-required") == 0)
		certflags_flags |= CERTOPT_NO_REQUIRE_USER_PRESENCE;
	ಅನ್ಯಥಾ ಯದಿ (strcasecmp(opt, "no-verify-required") == 0)
		certflags_flags &= ~CERTOPT_REQUIRE_VERIFY;
	ಅನ್ಯಥಾ ಯದಿ (strcasecmp(opt, "verify-required") == 0)
		certflags_flags |= CERTOPT_REQUIRE_VERIFY;
	ಅನ್ಯಥಾ ಯದಿ ((p = strprefix(opt, "force-command=", 1)) != ರಿಕ್ತ) {
		ಯದಿ (*p == '\0')
			fatal("Empty force-command option");
		ಯದಿ (certflags_command != ರಿಕ್ತ)
			fatal("force-command already specified");
		certflags_command = xstrdup(p);
	} ಅನ್ಯಥಾ ಯದಿ ((p = strprefix(opt, "source-address=", 1)) != ರಿಕ್ತ) {
		ಯದಿ (*p == '\0')
			fatal("Empty source-address option");
		ಯದಿ (certflags_src_addr != ರಿಕ್ತ)
			fatal("source-address already specified");
		ಯದಿ (addr_match_cidr_list(ರಿಕ್ತ, p) != 0)
			fatal("Invalid source-address list");
		certflags_src_addr = xstrdup(p);
	} ಅನ್ಯಥಾ ಯದಿ (strprefix(opt, "extension:", 1) != ರಿಕ್ತ ||
		    (iscrit = (strprefix(opt, "critical:", 1) != ರಿಕ್ತ))) {
		val = xstrdup(strchr(opt, ':') + 1);
		ಯದಿ ((cp = strchr(val, '=')) != ರಿಕ್ತ)
			*cp++ = '\0';
		cert_ext_add(val, cp, iscrit);
		ಮುಕ್ತ(val);
	} ಅನ್ಯಥಾ
		fatal("Unsupported certificate option \"%s\"", opt);
}

ಸ್ಥಿರ ಶೂನ್ಯ
show_options(ಸಂರಚನಾ sshbuf *optbuf, ಪೂರ್ಣಾಙ್ಕ in_critical)
{
	ವರ್ಣ *name, *arg, *hex;
	ಸಂರಚನಾ sshbuf *options, *option = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((options = sshbuf_fromb(optbuf)) == ರಿಕ್ತ)
		fatal_f("sshbuf_fromb failed");
	ಯಾವತ್ (sshbuf_len(options) != 0) {
		sshbuf_free(option);
		option = ರಿಕ್ತ;
		ಯದಿ ((r = sshbuf_get_cstring(options, &name, ರಿಕ್ತ)) != 0 ||
		    (r = sshbuf_froms(options, &option)) != 0)
			fatal_fr(r, "parse option");
		printf("                %s", name);
		ಯದಿ (!in_critical &&
		    (strcmp(name, "permit-X11-forwarding") == 0 ||
		    strcmp(name, "permit-agent-forwarding") == 0 ||
		    strcmp(name, "permit-port-forwarding") == 0 ||
		    strcmp(name, "permit-pty") == 0 ||
		    strcmp(name, "permit-user-rc") == 0 ||
		    strcmp(name, "no-touch-required") == 0)) {
			printf("\n");
		} ಅನ್ಯಥಾ ಯದಿ (in_critical &&
		    (strcmp(name, "force-command") == 0 ||
		    strcmp(name, "source-address") == 0)) {
			ಯದಿ ((r = sshbuf_get_cstring(option, &arg, ರಿಕ್ತ)) != 0)
				fatal_fr(r, "parse critical");
			printf(" %s\n", arg);
			ಮುಕ್ತ(arg);
		} ಅನ್ಯಥಾ ಯದಿ (in_critical &&
		    strcmp(name, "verify-required") == 0) {
			printf("\n");
		} ಅನ್ಯಥಾ ಯದಿ (sshbuf_len(option) > 0) {
			hex = sshbuf_dtob16(option);
			printf(" UNKNOWN OPTION: %s (len %zu)\n",
			    hex, sshbuf_len(option));
			sshbuf_reset(option);
			ಮುಕ್ತ(hex);
		} ಅನ್ಯಥಾ
			printf(" UNKNOWN FLAG OPTION\n");
		ಮುಕ್ತ(name);
		ಯದಿ (sshbuf_len(option) != 0)
			fatal("Option corrupt: extra data at end");
	}
	sshbuf_free(option);
	sshbuf_free(options);
}

ಸ್ಥಿರ ಶೂನ್ಯ
print_cert(ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
	ವರ್ಣ valid[64], *ಕೀಲಿ_fp, *ca_fp;
	u_int i;

	ಕೀಲಿ_fp = sshkey_fingerprint(ಕೀಲಿ, fingerprint_hash, SSH_FP_DEFAULT);
	ca_fp = sshkey_fingerprint(ಕೀಲಿ->cert->signature_ಕೀಲಿ,
	    fingerprint_hash, SSH_FP_DEFAULT);
	ಯದಿ (ಕೀಲಿ_fp == ರಿಕ್ತ || ca_fp == ರಿಕ್ತ)
		fatal_f("sshkey_fingerprint fail");
	sshkey_format_cert_validity(ಕೀಲಿ->cert, valid, ಪರಿಮಾಣ(valid));

	printf("        Type: %s %s certificate\n", sshkey_ssh_name(ಕೀಲಿ),
	    sshkey_cert_type(ಕೀಲಿ));
	printf("        Public key: %s %s\n", sshkey_type(ಕೀಲಿ), ಕೀಲಿ_fp);
	printf("        Signing CA: %s %s (using %s)\n",
	    sshkey_type(ಕೀಲಿ->cert->signature_ಕೀಲಿ), ca_fp,
	    ಕೀಲಿ->cert->signature_type);
	printf("        Key ID: \"%s\"\n", ಕೀಲಿ->cert->ಕೀಲಿ_id);
	printf("        Serial: %llu\n", (unsigned long long)ಕೀಲಿ->cert->serial);
	printf("        Valid: %s\n", valid);
	printf("        Principals: ");
	ಯದಿ (ಕೀಲಿ->cert->nprincipals == 0)
		printf("(none)\n");
	ಅನ್ಯಥಾ {
		ಪ್ರತಿ (i = 0; i < ಕೀಲಿ->cert->nprincipals; i++)
			printf("\n                %s",
			    ಕೀಲಿ->cert->principals[i]);
		printf("\n");
	}
	printf("        Critical Options: ");
	ಯದಿ (sshbuf_len(ಕೀಲಿ->cert->critical) == 0)
		printf("(none)\n");
	ಅನ್ಯಥಾ {
		printf("\n");
		show_options(ಕೀಲಿ->cert->critical, 1);
	}
	printf("        Extensions: ");
	ಯದಿ (sshbuf_len(ಕೀಲಿ->cert->extensions) == 0)
		printf("(none)\n");
	ಅನ್ಯಥಾ {
		printf("\n");
		show_options(ಕೀಲಿ->cert->extensions, 0);
	}
	ಮುಕ್ತ(ಕೀಲಿ_fp);
	ಮುಕ್ತ(ca_fp);
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_show_cert(ಸಂರಚನಾ passwd *pw)
{
	ಸಂರಚನಾ sshkey *ಕೀಲಿ = ರಿಕ್ತ;
	ಸಂರಚನಾ stat st;
	ಪೂರ್ಣಾಙ್ಕ r, is_stdin = 0, ok = 0;
	FILE *f;
	ವರ್ಣ *cp, *ಸಾಲು = ರಿಕ್ತ;
	ಧ್ರುವ ವರ್ಣ *path;
	size_t linesize = 0;
	u_long lnum = 0;

	ಯದಿ (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	ಯದಿ (strcmp(identity_file, "-") != 0 && stat(identity_file, &st) == -1)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));

	path = identity_file;
	ಯದಿ (strcmp(path, "-") == 0) {
		f = stdin;
		path = "(stdin)";
		is_stdin = 1;
	} ಅನ್ಯಥಾ ಯದಿ ((f = fopen(identity_file, "r")) == ರಿಕ್ತ)
		fatal("fopen %s: %s", identity_file, strerror(errno));

	ಯಾವತ್ (getline(&ಸಾಲು, &linesize, f) != -1) {
		lnum++;
		sshkey_free(ಕೀಲಿ);
		ಕೀಲಿ = ರಿಕ್ತ;
		/* Trim leading space and comments */
		cp = ಸಾಲು + strspn(ಸಾಲು, " \t");
		ಯದಿ (*cp == '#' || *cp == '\0')
			ಅನುವರ್ತ;
		ಯದಿ ((ಕೀಲಿ = sshkey_new(ಕೀಲಿ_UNSPEC)) == ರಿಕ್ತ)
			fatal("sshkey_new");
		ಯದಿ ((r = sshkey_read(ಕೀಲಿ, &cp)) != 0) {
			error_r(r, "%s:%lu: invalid key", path, lnum);
			ಅನುವರ್ತ;
		}
		ಯದಿ (!sshkey_is_cert(ಕೀಲಿ)) {
			error("%s:%lu is not a certificate", path, lnum);
			ಅನುವರ್ತ;
		}
		ok = 1;
		ಯದಿ (!is_stdin && lnum == 1)
			printf("%s:\n", path);
		ಅನ್ಯಥಾ
			printf("%s:%lu:\n", path, lnum);
		print_cert(ಕೀಲಿ);
	}
	ಮುಕ್ತ(ಸಾಲು);
	sshkey_free(ಕೀಲಿ);
	fclose(f);
	exit(ok ? 0 : 1);
}

ಸ್ಥಿರ ಶೂನ್ಯ
load_krl(ಧ್ರುವ ವರ್ಣ *path, ಸಂರಚನಾ ssh_krl **krlp)
{
	ಸಂರಚನಾ sshbuf *krlbuf;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshbuf_load_file(path, &krlbuf)) != 0)
		fatal_r(r, "Unable to load KRL %s", path);
	/* XXX check sigs */
	ಯದಿ ((r = ssh_krl_from_blob(krlbuf, krlp)) != 0 ||
	    *krlp == ರಿಕ್ತ)
		fatal_r(r, "Invalid KRL file %s", path);
	sshbuf_free(krlbuf);
}

ಸ್ಥಿರ ಶೂನ್ಯ
hash_to_blob(ಧ್ರುವ ವರ್ಣ *cp, u_char **blobp, size_t *lenp,
    ಧ್ರುವ ವರ್ಣ *file, u_long lnum)
{
	ವರ್ಣ *tmp;
	size_t tlen;
	ಸಂರಚನಾ sshbuf *b;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((cp = strprefix(cp, "SHA256:", 0)) == ರಿಕ್ತ)
		fatal("%s:%lu: unsupported hash algorithm", file, lnum);

	/*
	 * OpenSSH base64 hashes omit trailing '='
	 * characters; put them back for decode.
	 */
	ಯದಿ ((tlen = strlen(cp)) >= SIZE_MAX - 5)
		fatal_f("hash too long: %zu bytes", tlen);
	tmp = xmalloc(tlen + 4 + 1);
	strlcpy(tmp, cp, tlen + 1);
	ಯಾವತ್ ((tlen % 4) != 0) {
		tmp[tlen++] = '=';
		tmp[tlen] = '\0';
	}
	ಯದಿ ((b = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = sshbuf_b64tod(b, tmp)) != 0)
		fatal_r(r, "%s:%lu: decode hash failed", file, lnum);
	ಮುಕ್ತ(tmp);
	*lenp = sshbuf_len(b);
	*blobp = xmalloc(*lenp);
	memcpy(*blobp, sshbuf_ptr(b), *lenp);
	sshbuf_free(b);
}

ಸ್ಥಿರ ಶೂನ್ಯ
update_krl_from_file(ಸಂರಚನಾ passwd *pw, ಧ್ರುವ ವರ್ಣ *file, ಪೂರ್ಣಾಙ್ಕ wild_ca,
    ಧ್ರುವ ಸಂರಚನಾ sshkey *ca, ಸಂರಚನಾ ssh_krl *krl)
{
	ಸಂರಚನಾ sshkey *ಕೀಲಿ = ರಿಕ್ತ;
	u_long lnum = 0;
	ವರ್ಣ *path, *cp, *ep, *ಸಾಲು = ರಿಕ್ತ;
	u_char *blob = ರಿಕ್ತ;
	size_t blen = 0, linesize = 0;
	unsigned long long serial, serial2;
	ಪೂರ್ಣಾಙ್ಕ i, was_explicit_ಕೀಲಿ, was_sha1, was_sha256, was_hash, r;
	FILE *krl_spec;

	path = tilde_expand_filename(file, pw->pw_uid);
	ಯದಿ (strcmp(path, "-") == 0) {
		krl_spec = stdin;
		ಮುಕ್ತ(path);
		path = xstrdup("(standard input)");
	} ಅನ್ಯಥಾ ಯದಿ ((krl_spec = fopen(path, "r")) == ರಿಕ್ತ)
		fatal("fopen %s: %s", path, strerror(errno));

	ಯದಿ (!quiet)
		printf("Revoking from %s\n", path);
	ಯಾವತ್ (getline(&ಸಾಲು, &linesize, krl_spec) != -1) {
		ಯದಿ (linesize >= INT_MAX) {
			fatal_f("%s contains unparsable line, len=%zu",
			    path, linesize);
		}
		lnum++;
		was_explicit_ಕೀಲಿ = was_sha1 = was_sha256 = was_hash = 0;
		cp = ಸಾಲು + strspn(ಸಾಲು, " \t");
		/* Trim trailing space, comments and strip \n */
		ಪ್ರತಿ (i = 0, r = -1; cp[i] != '\0'; i++) {
			ಯದಿ (cp[i] == '#' || cp[i] == '\n') {
				cp[i] = '\0';
				ಭಙ್ಗ;
			}
			ಯದಿ (cp[i] == ' ' || cp[i] == '\t') {
				/* Remember the start of a span of whitespace */
				ಯದಿ (r == -1)
					r = i;
			} ಅನ್ಯಥಾ
				r = -1;
		}
		ಯದಿ (r != -1)
			cp[r] = '\0';
		ಯದಿ (*cp == '\0')
			ಅನುವರ್ತ;
		ಯದಿ (strncasecmp(cp, "serial:", 7) == 0) {
			ಯದಿ (ca == ರಿಕ್ತ && !wild_ca) {
				fatal("revoking certificates by serial number "
				    "requires specification of a CA key");
			}
			cp += 7;
			cp = cp + strspn(cp, " \t");
			errno = 0;
			serial = strtoull(cp, &ep, 0);
			ಯದಿ (*cp == '\0' || (*ep != '\0' && *ep != '-'))
				fatal("%s:%lu: invalid serial \"%s\"",
				    path, lnum, cp);
			ಯದಿ (errno == ERANGE && serial == ULLONG_MAX)
				fatal("%s:%lu: serial out of range",
				    path, lnum);
			serial2 = serial;
			ಯದಿ (*ep == '-') {
				cp = ep + 1;
				errno = 0;
				serial2 = strtoull(cp, &ep, 0);
				ಯದಿ (*cp == '\0' || *ep != '\0')
					fatal("%s:%lu: invalid serial \"%s\"",
					    path, lnum, cp);
				ಯದಿ (errno == ERANGE && serial2 == ULLONG_MAX)
					fatal("%s:%lu: serial out of range",
					    path, lnum);
				ಯದಿ (serial2 <= serial)
					fatal("%s:%lu: invalid serial range "
					    "%llu:%llu", path, lnum,
					    (unsigned long long)serial,
					    (unsigned long long)serial2);
			}
			ಯದಿ (ssh_krl_revoke_cert_by_serial_range(krl,
			    ca, serial, serial2) != 0) {
				fatal_f("revoke serial failed");
			}
		} ಅನ್ಯಥಾ ಯದಿ (strncasecmp(cp, "id:", 3) == 0) {
			ಯದಿ (ca == ರಿಕ್ತ && !wild_ca) {
				fatal("revoking certificates by key ID "
				    "requires specification of a CA key");
			}
			cp += 3;
			cp = cp + strspn(cp, " \t");
			ಯದಿ (ssh_krl_revoke_cert_by_ಕೀಲಿ_id(krl, ca, cp) != 0)
				fatal_f("revoke key ID failed");
		} ಅನ್ಯಥಾ ಯದಿ (strncasecmp(cp, "hash:", 5) == 0) {
			cp += 5;
			cp = cp + strspn(cp, " \t");
			hash_to_blob(cp, &blob, &blen, file, lnum);
			ಯದಿ ((r = ssh_krl_revoke_ಕೀಲಿ_sha256(krl,
			    blob, blen)) != 0)
				fatal_fr(r, "revoke key failed");
			ಮುಕ್ತ(blob);
			blob = ರಿಕ್ತ;
			blen = 0;
		} ಅನ್ಯಥಾ {
			ಯದಿ (strncasecmp(cp, "key:", 4) == 0) {
				cp += 4;
				cp = cp + strspn(cp, " \t");
				was_explicit_ಕೀಲಿ = 1;
			} ಅನ್ಯಥಾ ಯದಿ (strncasecmp(cp, "sha1:", 5) == 0) {
				cp += 5;
				cp = cp + strspn(cp, " \t");
				was_sha1 = 1;
			} ಅನ್ಯಥಾ ಯದಿ (strncasecmp(cp, "sha256:", 7) == 0) {
				cp += 7;
				cp = cp + strspn(cp, " \t");
				was_sha256 = 1;
				/*
				 * Just try to process the line as a key.
				 * Parsing will fail if it isn't.
				 */
			}
			ಯದಿ ((ಕೀಲಿ = sshkey_new(ಕೀಲಿ_UNSPEC)) == ರಿಕ್ತ)
				fatal("sshkey_new");
			ಯದಿ ((r = sshkey_read(ಕೀಲಿ, &cp)) != 0)
				fatal_r(r, "%s:%lu: invalid key", path, lnum);
			ಯದಿ (was_explicit_ಕೀಲಿ)
				r = ssh_krl_revoke_ಕೀಲಿ_explicit(krl, ಕೀಲಿ);
			ಅನ್ಯಥಾ ಯದಿ (was_sha1) {
				ಯದಿ (sshkey_fingerprint_raw(ಕೀಲಿ,
				    SSH_DIGEST_SHA1, &blob, &blen) != 0) {
					fatal("%s:%lu: fingerprint failed",
					    file, lnum);
				}
				r = ssh_krl_revoke_ಕೀಲಿ_sha1(krl, blob, blen);
			} ಅನ್ಯಥಾ ಯದಿ (was_sha256) {
				ಯದಿ (sshkey_fingerprint_raw(ಕೀಲಿ,
				    SSH_DIGEST_SHA256, &blob, &blen) != 0) {
					fatal("%s:%lu: fingerprint failed",
					    file, lnum);
				}
				r = ssh_krl_revoke_ಕೀಲಿ_sha256(krl, blob, blen);
			} ಅನ್ಯಥಾ
				r = ssh_krl_revoke_ಕೀಲಿ(krl, ಕೀಲಿ);
			ಯದಿ (r != 0)
				fatal_fr(r, "revoke key failed");
			freezero(blob, blen);
			blob = ರಿಕ್ತ;
			blen = 0;
			sshkey_free(ಕೀಲಿ);
		}
	}
	ಯದಿ (strcmp(path, "-") != 0)
		fclose(krl_spec);
	ಮುಕ್ತ(ಸಾಲು);
	ಮುಕ್ತ(path);
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_gen_krl(ಸಂರಚನಾ passwd *pw, ಪೂರ್ಣಾಙ್ಕ updating, ಧ್ರುವ ವರ್ಣ *ca_ಕೀಲಿ_path,
    unsigned long long krl_version, ಧ್ರುವ ವರ್ಣ *krl_comment,
    ಪೂರ್ಣಾಙ್ಕ argc, ವರ್ಣ **argv)
{
	ಸಂರಚನಾ ssh_krl *krl;
	ಸಂರಚನಾ stat sb;
	ಸಂರಚನಾ sshkey *ca = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ i, r, wild_ca = 0;
	ವರ್ಣ *tmp;
	ಸಂರಚನಾ sshbuf *kbuf;

	ಯದಿ (*identity_file == '\0')
		fatal("KRL generation requires an output file");
	ಯದಿ (stat(identity_file, &sb) == -1) {
		ಯದಿ (errno != ENOENT)
			fatal("Cannot access KRL \"%s\": %s",
			    identity_file, strerror(errno));
		ಯದಿ (updating)
			fatal("KRL \"%s\" does not exist", identity_file);
	}
	ಯದಿ (ca_ಕೀಲಿ_path != ರಿಕ್ತ) {
		ಯದಿ (strcasecmp(ca_ಕೀಲಿ_path, "none") == 0)
			wild_ca = 1;
		ಅನ್ಯಥಾ {
			tmp = tilde_expand_filename(ca_ಕೀಲಿ_path, pw->pw_uid);
			ಯದಿ ((r = sshkey_load_public(tmp, &ca, ರಿಕ್ತ)) != 0)
				fatal_r(r, "Cannot load CA public key %s", tmp);
			ಮುಕ್ತ(tmp);
		}
	}

	ಯದಿ (updating)
		load_krl(identity_file, &krl);
	ಅನ್ಯಥಾ ಯದಿ ((krl = ssh_krl_init()) == ರಿಕ್ತ)
		fatal("couldn't create KRL");

	ಯದಿ (krl_version != 0)
		ssh_krl_set_version(krl, krl_version);
	ಯದಿ (krl_comment != ರಿಕ್ತ)
		ssh_krl_set_comment(krl, krl_comment);

	ಪ್ರತಿ (i = 0; i < argc; i++)
		update_krl_from_file(pw, argv[i], wild_ca, ca, krl);

	ಯದಿ ((kbuf = sshbuf_new()) == ರಿಕ್ತ)
		fatal("sshbuf_new failed");
	ಯದಿ (ssh_krl_to_blob(krl, kbuf) != 0)
		fatal("Couldn't generate KRL");
	ಯದಿ ((r = sshbuf_write_file(identity_file, kbuf)) != 0)
		fatal("write %s: %s", identity_file, strerror(errno));
	sshbuf_free(kbuf);
	ssh_krl_free(krl);
	sshkey_free(ca);
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_check_krl(ಸಂರಚನಾ passwd *pw, ಪೂರ್ಣಾಙ್ಕ print_krl, ಪೂರ್ಣಾಙ್ಕ argc, ವರ್ಣ **argv)
{
	ಪೂರ್ಣಾಙ್ಕ i, r, ret = 0;
	ವರ್ಣ *comment;
	ಸಂರಚನಾ ssh_krl *krl;
	ಸಂರಚನಾ sshkey *k;

	ಯದಿ (*identity_file == '\0')
		fatal("KRL checking requires an input file");
	load_krl(identity_file, &krl);
	ಯದಿ (print_krl)
		krl_dump(krl, stdout);
	ಪ್ರತಿ (i = 0; i < argc; i++) {
		ಯದಿ ((r = sshkey_load_public(argv[i], &k, &comment)) != 0)
			fatal_r(r, "Cannot load public key %s", argv[i]);
		r = ssh_krl_check_ಕೀಲಿ(krl, k);
		printf("%s%s%s%s: %s\n", argv[i],
		    *comment ? " (" : "", comment, *comment ? ")" : "",
		    r == 0 ? "ok" : "REVOKED");
		ಯದಿ (r != 0)
			ret = 1;
		sshkey_free(k);
		ಮುಕ್ತ(comment);
	}
	ssh_krl_free(krl);
	exit(ret);
}

ಸ್ಥಿರ ಸಂರಚನಾ sshkey *
load_sign_ಕೀಲಿ(ಧ್ರುವ ವರ್ಣ *keypath, ಧ್ರುವ ಸಂರಚನಾ sshkey *pubkey)
{
	size_t i, slen, plen = strlen(keypath);
	ವರ್ಣ *privpath = xstrdup(keypath);
	ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ * ಧ್ರುವ suffixes[] = { "-cert.pub", ".pub", ರಿಕ್ತ };
	ಸಂರಚನಾ sshkey *ret = ರಿಕ್ತ, *privkey = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r, waspub = 0;
	ಸಂರಚನಾ stat st;

	/*
	 * If passed a public key filename, then try to locate the corresponding
	 * private key. This lets us specify certificates on the command-line
	 * and have ssh-keygen find the appropriate private key.
	 */
	ಪ್ರತಿ (i = 0; suffixes[i]; i++) {
		slen = strlen(suffixes[i]);
		ಯದಿ (plen <= slen ||
		    strcmp(privpath + plen - slen, suffixes[i]) != 0)
			ಅನುವರ್ತ;
		privpath[plen - slen] = '\0';
		debug_f("%s looks like a public key, using private key "
		    "path %s instead", keypath, privpath);
		waspub = 1;
	}
	ಯದಿ (waspub && stat(privpath, &st) != 0 && errno == ENOENT)
		fatal("No private key found for public key \"%s\"", keypath);
	ಯದಿ ((r = sshkey_load_private(privpath, "", &privkey, ರಿಕ್ತ)) != 0 &&
	    (r != SSH_ERR_ಕೀಲಿ_WRONG_PASSPHRASE)) {
		debug_fr(r, "load private key \"%s\"", privpath);
		fatal("No private key found for \"%s\"", privpath);
	} ಅನ್ಯಥಾ ಯದಿ (privkey == ರಿಕ್ತ)
		privkey = load_identity(privpath, ರಿಕ್ತ);

	ಯದಿ (!sshkey_equal_public(pubkey, privkey)) {
		error("Public key %s doesn't match private %s",
		    keypath, privpath);
		ಗಚ್ಛ done;
	}
	ಯದಿ (sshkey_is_cert(pubkey) && !sshkey_is_cert(privkey)) {
		/*
		 * Graft the certificate onto the private key to make
		 * it capable of signing.
		 */
		ಯದಿ ((r = sshkey_to_certified(privkey)) != 0) {
			error_fr(r, "sshkey_to_certified");
			ಗಚ್ಛ done;
		}
		ಯದಿ ((r = sshkey_cert_copy(pubkey, privkey)) != 0) {
			error_fr(r, "sshkey_cert_copy");
			ಗಚ್ಛ done;
		}
	}
	/* success */
	ret = privkey;
	privkey = ರಿಕ್ತ;
 done:
	sshkey_free(privkey);
	ಮುಕ್ತ(privpath);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sign_one(ಸಂರಚನಾ sshkey *signkey, ಧ್ರುವ ವರ್ಣ *filename, ಪೂರ್ಣಾಙ್ಕ fd,
    ಧ್ರುವ ವರ್ಣ *sig_namespace, ಧ್ರುವ ವರ್ಣ *hashalg, sshsig_signer *signer,
    ಶೂನ್ಯ *signer_ctx)
{
	ಸಂರಚನಾ sshbuf *sigbuf = ರಿಕ್ತ, *abuf = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR, wfd = -1, oerrno;
	ವರ್ಣ *wfile = ರಿಕ್ತ, *asig = ರಿಕ್ತ, *fp = ರಿಕ್ತ;
	ವರ್ಣ *pin = ರಿಕ್ತ, *prompt = ರಿಕ್ತ;

	ಯದಿ (!quiet) {
		ಯದಿ (fd == STDIN_FILENO)
			fprintf(stderr, "Signing data on standard input\n");
		ಅನ್ಯಥಾ
			fprintf(stderr, "Signing file %s\n", filename);
	}
	ಯದಿ (signer == ರಿಕ್ತ && sshkey_is_sk(signkey)) {
		ಯದಿ ((signkey->sk_flags & SSH_SK_USER_VERIFICATION_REQD)) {
			xasprintf(&prompt, "Enter PIN for %s key: ",
			    sshkey_type(signkey));
			ಯದಿ ((pin = read_passphrase(prompt,
			    RP_ALLOW_STDIN)) == ರಿಕ್ತ)
				fatal_f("couldn't read PIN");
		}
		ಯದಿ ((signkey->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
			ಯದಿ ((fp = sshkey_fingerprint(signkey, fingerprint_hash,
			    SSH_FP_DEFAULT)) == ರಿಕ್ತ)
				fatal_f("fingerprint failed");
			fprintf(stderr, "Confirm user presence for key %s %s\n",
			    sshkey_type(signkey), fp);
			ಮುಕ್ತ(fp);
		}
	}
	ಯದಿ ((r = sshsig_sign_fd(signkey, hashalg, sk_provider, pin,
	    fd, sig_namespace, &sigbuf, signer, signer_ctx)) != 0) {
		error_r(r, "Signing %s failed", filename);
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshsig_armor(sigbuf, &abuf)) != 0) {
		error_fr(r, "sshsig_armor");
		ಗಚ್ಛ out;
	}
	ಯದಿ ((asig = sshbuf_dup_string(abuf)) == ರಿಕ್ತ) {
		error_f("buffer error");
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}

	ಯದಿ (fd == STDIN_FILENO) {
		fputs(asig, stdout);
		fflush(stdout);
	} ಅನ್ಯಥಾ {
		xasprintf(&wfile, "%s.sig", filename);
		ಯದಿ (confirm_overwrite(wfile)) {
			ಯದಿ ((wfd = open(wfile, O_WRONLY|O_CREAT|O_TRUNC,
			    0666)) == -1) {
				oerrno = errno;
				error("Cannot open %s: %s",
				    wfile, strerror(errno));
				errno = oerrno;
				r = SSH_ERR_SYSTEM_ERROR;
				ಗಚ್ಛ out;
			}
			ಯದಿ (atomicio(vwrite, wfd, asig,
			    strlen(asig)) != strlen(asig)) {
				oerrno = errno;
				error("Cannot write to %s: %s",
				    wfile, strerror(errno));
				errno = oerrno;
				r = SSH_ERR_SYSTEM_ERROR;
				ಗಚ್ಛ out;
			}
			ಯದಿ (!quiet) {
				fprintf(stderr, "Write signature to %s\n",
				    wfile);
			}
		}
	}
	/* success */
	r = 0;
 out:
	ಮುಕ್ತ(wfile);
	ಮುಕ್ತ(prompt);
	ಮುಕ್ತ(asig);
	ಯದಿ (pin != ರಿಕ್ತ)
		freezero(pin, strlen(pin));
	sshbuf_free(abuf);
	sshbuf_free(sigbuf);
	ಯದಿ (wfd != -1)
		close(wfd);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sig_process_opts(ವರ್ಣ * ಧ್ರುವ *opts, size_t nopts, ವರ್ಣ **hashalgp,
    uint64_t *verify_timep, ಪೂರ್ಣಾಙ್ಕ *print_pubkey)
{
	size_t i;
	time_t now;
	ಧ್ರುವ ವರ್ಣ *p;

	ಯದಿ (verify_timep != ರಿಕ್ತ)
		*verify_timep = 0;
	ಯದಿ (print_pubkey != ರಿಕ್ತ)
		*print_pubkey = 0;
	ಯದಿ (hashalgp != ರಿಕ್ತ)
		*hashalgp = ರಿಕ್ತ;
	ಪ್ರತಿ (i = 0; i < nopts; i++) {
		ಯದಿ (hashalgp != ರಿಕ್ತ &&
		    (p = strprefix(opts[i], "hashalg=", 1)) != ರಿಕ್ತ) {
			*hashalgp = xstrdup(p);
		} ಅನ್ಯಥಾ ಯದಿ (verify_timep &&
		    (p = strprefix(opts[i], "verify-time=", 1)) != ರಿಕ್ತ) {
			ಯದಿ (parse_absolute_time(p, verify_timep) != 0 ||
			    *verify_timep == 0) {
				error("Invalid \"verify-time\" option");
				ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
			}
		} ಅನ್ಯಥಾ ಯದಿ (print_pubkey &&
		    strcasecmp(opts[i], "print-pubkey") == 0) {
			*print_pubkey = 1;
		} ಅನ್ಯಥಾ {
			error("Invalid option \"%s\"", opts[i]);
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
		}
	}
	ಯದಿ (verify_timep && *verify_timep == 0) {
		ಯದಿ ((now = time(ರಿಕ್ತ)) < 0) {
			error("Time is before epoch");
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
		}
		*verify_timep = (uint64_t)now;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}


ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sig_sign(ಧ್ರುವ ವರ್ಣ *keypath, ಧ್ರುವ ವರ್ಣ *sig_namespace, ಪೂರ್ಣಾಙ್ಕ require_agent,
    ಪೂರ್ಣಾಙ್ಕ argc, ವರ್ಣ **argv, ವರ್ಣ * ಧ್ರುವ *opts, size_t nopts)
{
	ಪೂರ್ಣಾಙ್ಕ i, fd = -1, r, ret = -1;
	ಪೂರ್ಣಾಙ್ಕ agent_fd = -1;
	ಸಂರಚನಾ sshkey *pubkey = ರಿಕ್ತ, *privkey = ರಿಕ್ತ, *signkey = ರಿಕ್ತ;
	sshsig_signer *signer = ರಿಕ್ತ;
	ವರ್ಣ *hashalg = ರಿಕ್ತ;

	/* Check file arguments. */
	ಪ್ರತಿ (i = 0; i < argc; i++) {
		ಯದಿ (strcmp(argv[i], "-") != 0)
			ಅನುವರ್ತ;
		ಯದಿ (i > 0 || argc > 1)
			fatal("Cannot sign mix of paths and standard input");
	}

	ಯದಿ (sig_process_opts(opts, nopts, &hashalg, ರಿಕ್ತ, ರಿಕ್ತ) != 0)
		ಗಚ್ಛ done; /* error already logged */

	ಯದಿ ((r = sshkey_load_public(keypath, &pubkey, ರಿಕ್ತ)) != 0) {
		error_r(r, "Couldn't load public key %s", keypath);
		ಗಚ್ಛ done;
	}

	ಯದಿ ((r = ssh_get_authentication_socket(&agent_fd)) != 0) {
		ಯದಿ (require_agent)
			fatal("Couldn't get agent socket");
		debug_r(r, "Couldn't get agent socket");
	} ಅನ್ಯಥಾ {
		ಯದಿ ((r = ssh_agent_has_ಕೀಲಿ(agent_fd, pubkey)) == 0)
			signer = agent_signer;
		ಅನ್ಯಥಾ {
			ಯದಿ (require_agent)
				fatal("Couldn't find key in agent");
			debug_r(r, "Couldn't find key in agent");
		}
	}

	ಯದಿ (signer == ರಿಕ್ತ) {
		/* Not using agent - try to load private key */
		ಯದಿ ((privkey = load_sign_ಕೀಲಿ(keypath, pubkey)) == ರಿಕ್ತ)
			ಗಚ್ಛ done;
		signkey = privkey;
	} ಅನ್ಯಥಾ {
		/* Will use key in agent */
		signkey = pubkey;
	}

	ಯದಿ (argc == 0) {
		ಯದಿ ((r = sign_one(signkey, "(stdin)", STDIN_FILENO,
		    sig_namespace, hashalg, signer, &agent_fd)) != 0)
			ಗಚ್ಛ done;
	} ಅನ್ಯಥಾ {
		ಪ್ರತಿ (i = 0; i < argc; i++) {
			ಯದಿ (strcmp(argv[i], "-") == 0)
				fd = STDIN_FILENO;
			ಅನ್ಯಥಾ ಯದಿ ((fd = open(argv[i], O_RDONLY)) == -1) {
				error("Cannot open %s for signing: %s",
				    argv[i], strerror(errno));
				ಗಚ್ಛ done;
			}
			ಯದಿ ((r = sign_one(signkey, argv[i], fd, sig_namespace,
			    hashalg, signer, &agent_fd)) != 0)
				ಗಚ್ಛ done;
			ಯದಿ (fd != STDIN_FILENO)
				close(fd);
			fd = -1;
		}
	}

	ret = 0;
done:
	ಯದಿ (fd != -1 && fd != STDIN_FILENO)
		close(fd);
	sshkey_free(pubkey);
	sshkey_free(privkey);
	ಮುಕ್ತ(hashalg);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sig_verify(ಧ್ರುವ ವರ್ಣ *signature, ಧ್ರುವ ವರ್ಣ *sig_namespace,
    ಧ್ರುವ ವರ್ಣ *principal, ಧ್ರುವ ವರ್ಣ *allowed_ಕೀಲಿಗಳು, ಧ್ರುವ ವರ್ಣ *revoked_ಕೀಲಿಗಳು,
    ವರ್ಣ * ಧ್ರುವ *opts, size_t nopts)
{
	ಪೂರ್ಣಾಙ್ಕ r, ret = -1;
	ಪೂರ್ಣಾಙ್ಕ print_pubkey = 0;
	ಸಂರಚನಾ sshbuf *sigbuf = ರಿಕ್ತ, *abuf = ರಿಕ್ತ;
	ಸಂರಚನಾ sshkey *sign_ಕೀಲಿ = ರಿಕ್ತ;
	ವರ್ಣ *fp = ರಿಕ್ತ;
	ಸಂರಚನಾ sshkey_sig_details *sig_details = ರಿಕ್ತ;
	uint64_t verify_time = 0;

	ಯದಿ (sig_process_opts(opts, nopts, ರಿಕ್ತ, &verify_time,
	    &print_pubkey) != 0)
		ಗಚ್ಛ done; /* error already logged */

	memset(&sig_details, 0, ಪರಿಮಾಣ(sig_details));
	ಯದಿ ((r = sshbuf_load_file(signature, &abuf)) != 0) {
		error_r(r, "Couldn't read signature file");
		ಗಚ್ಛ done;
	}

	ಯದಿ ((r = sshsig_dearmor(abuf, &sigbuf)) != 0) {
		error_fr(r, "sshsig_armor");
		ಗಚ್ಛ done;
	}
	ಯದಿ ((r = sshsig_verify_fd(sigbuf, STDIN_FILENO, sig_namespace,
	    &sign_ಕೀಲಿ, &sig_details)) != 0)
		ಗಚ್ಛ done; /* sshsig_verify() prints error */

	ಯದಿ ((fp = sshkey_fingerprint(sign_ಕೀಲಿ, fingerprint_hash,
	    SSH_FP_DEFAULT)) == ರಿಕ್ತ)
		fatal_f("sshkey_fingerprint failed");
	debug("Valid (unverified) signature from key %s", fp);
	ಯದಿ (sig_details != ರಿಕ್ತ) {
		debug2_f("signature details: counter = %u, flags = 0x%02x",
		    sig_details->sk_counter, sig_details->sk_flags);
	}
	ಮುಕ್ತ(fp);
	fp = ರಿಕ್ತ;

	ಯದಿ (revoked_ಕೀಲಿಗಳು != ರಿಕ್ತ) {
		ಯದಿ ((r = sshkey_check_revoked(sign_ಕೀಲಿ, revoked_ಕೀಲಿಗಳು)) != 0) {
			debug3_fr(r, "sshkey_check_revoked");
			ಗಚ್ಛ done;
		}
	}

	ಯದಿ (allowed_ಕೀಲಿಗಳು != ರಿಕ್ತ && (r = sshsig_check_allowed_ಕೀಲಿಗಳು(allowed_ಕೀಲಿಗಳು,
	    sign_ಕೀಲಿ, principal, sig_namespace, verify_time)) != 0) {
		debug3_fr(r, "sshsig_check_allowed_keys");
		ಗಚ್ಛ done;
	}
	/* success */
	ret = 0;
done:
	ಯದಿ (!quiet) {
		ಯದಿ (ret == 0) {
			ಯದಿ ((fp = sshkey_fingerprint(sign_ಕೀಲಿ, fingerprint_hash,
			    SSH_FP_DEFAULT)) == ರಿಕ್ತ)
				fatal_f("sshkey_fingerprint failed");
			ಯದಿ (principal == ರಿಕ್ತ) {
				printf("Good \"%s\" signature with %s key %s\n",
				    sig_namespace, sshkey_type(sign_ಕೀಲಿ), fp);

			} ಅನ್ಯಥಾ {
				printf("Good \"%s\" signature for %s with %s key %s\n",
				    sig_namespace, principal,
				    sshkey_type(sign_ಕೀಲಿ), fp);
			}
		} ಅನ್ಯಥಾ {
			printf("Could not verify signature.\n");
		}
	}
	/* Print the signature key if requested */
	ಯದಿ (ret == 0 && print_pubkey && sign_ಕೀಲಿ != ರಿಕ್ತ) {
		ಯದಿ ((r = sshkey_write(sign_ಕೀಲಿ, stdout)) == 0)
			fputc('\n', stdout);
		ಅನ್ಯಥಾ {
			error_r(r, "Could not print public key.\n");
			ret = -1;
		}
	}
	sshbuf_free(sigbuf);
	sshbuf_free(abuf);
	sshkey_free(sign_ಕೀಲಿ);
	sshkey_sig_details_free(sig_details);
	ಮುಕ್ತ(fp);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sig_find_principals(ಧ್ರುವ ವರ್ಣ *signature, ಧ್ರುವ ವರ್ಣ *allowed_ಕೀಲಿಗಳು,
    ವರ್ಣ * ಧ್ರುವ *opts, size_t nopts)
{
	ಪೂರ್ಣಾಙ್ಕ r, ret = -1;
	ಸಂರಚನಾ sshbuf *sigbuf = ರಿಕ್ತ, *abuf = ರಿಕ್ತ;
	ಸಂರಚನಾ sshkey *sign_ಕೀಲಿ = ರಿಕ್ತ;
	ವರ್ಣ *principals = ರಿಕ್ತ, *cp, *tmp;
	uint64_t verify_time = 0;

	ಯದಿ (sig_process_opts(opts, nopts, ರಿಕ್ತ, &verify_time, ರಿಕ್ತ) != 0)
		ಗಚ್ಛ done; /* error already logged */

	ಯದಿ ((r = sshbuf_load_file(signature, &abuf)) != 0) {
		error_r(r, "Couldn't read signature file");
		ಗಚ್ಛ done;
	}
	ಯದಿ ((r = sshsig_dearmor(abuf, &sigbuf)) != 0) {
		error_fr(r, "sshsig_armor");
		ಗಚ್ಛ done;
	}
	ಯದಿ ((r = sshsig_get_pubkey(sigbuf, &sign_ಕೀಲಿ)) != 0) {
		error_fr(r, "sshsig_get_pubkey");
		ಗಚ್ಛ done;
	}
	ಯದಿ ((r = sshsig_find_principals(allowed_ಕೀಲಿಗಳು, sign_ಕೀಲಿ,
	    verify_time, &principals)) != 0) {
		ಯದಿ (r != SSH_ERR_ಕೀಲಿ_NOT_FOUND)
			error_fr(r, "sshsig_find_principal");
		ಗಚ್ಛ done;
	}
	ret = 0;
done:
	ಯದಿ (ret == 0 ) {
		/* Emit matching principals one per line */
		tmp = principals;
		ಯಾವತ್ ((cp = strsep(&tmp, ",")) != ರಿಕ್ತ && *cp != '\0')
			puts(cp);
	} ಅನ್ಯಥಾ {
		fprintf(stderr, "No principal matched.\n");
	}
	sshbuf_free(sigbuf);
	sshbuf_free(abuf);
	sshkey_free(sign_ಕೀಲಿ);
	ಮುಕ್ತ(principals);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sig_match_principals(ಧ್ರುವ ವರ್ಣ *allowed_ಕೀಲಿಗಳು, ವರ್ಣ *principal,
	ವರ್ಣ * ಧ್ರುವ *opts, size_t nopts)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	ವರ್ಣ **principals = ರಿಕ್ತ;
	size_t i, nprincipals = 0;

	ಯದಿ ((r = sig_process_opts(opts, nopts, ರಿಕ್ತ, ರಿಕ್ತ, ರಿಕ್ತ)) != 0)
		ಪ್ರತ್ಯಾಗಮ r; /* error already logged */

	ಯದಿ ((r = sshsig_match_principals(allowed_ಕೀಲಿಗಳು, principal,
	    &principals, &nprincipals)) != 0) {
		debug_f("match: %s", ssh_err(r));
		fprintf(stderr, "No principal matched.\n");
		ಪ್ರತ್ಯಾಗಮ r;
	}
	ಪ್ರತಿ (i = 0; i < nprincipals; i++) {
		printf("%s\n", principals[i]);
		ಮುಕ್ತ(principals[i]);
	}
	ಮುಕ್ತ(principals);

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_moduli_gen(ಧ್ರುವ ವರ್ಣ *out_file, ವರ್ಣ **opts, size_t nopts)
{
#ifdef WITH_OPENSSL
	/* Moduli generation/screening */
	BIGNUM *start = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ moduli_bits = 0;
	FILE *out;
	size_t i;
	ಧ್ರುವ ವರ್ಣ *errstr, *p;

	/* Parse options */
	ಪ್ರತಿ (i = 0; i < nopts; i++) {
		ಯದಿ ((p = strprefix(opts[i], "start=", 0)) != ರಿಕ್ತ) {
			/* XXX - also compare length against bits */
			ಯದಿ (BN_hex2bn(&start, p) == 0)
				fatal("Invalid start point.");
		} ಅನ್ಯಥಾ ಯದಿ ((p = strprefix(opts[i], "bits=", 0)) != ರಿಕ್ತ) {
			moduli_bits = (ಪೂರ್ಣಾಙ್ಕ)strtonum(p, 1, INT_MAX, &errstr);
			ಯದಿ (errstr) {
				fatal("Invalid number: %s (%s)", p, errstr);
			}
		} ಅನ್ಯಥಾ {
			fatal("Option \"%s\" is unsupported for moduli "
			    "generation", opts[i]);
		}
	}

	ಯದಿ (strcmp(out_file, "-") == 0)
		out = stdout;
	ಅನ್ಯಥಾ ಯದಿ ((out = fopen(out_file, "w")) == ರಿಕ್ತ) {
		fatal("Couldn't open modulus candidate file \"%s\": %s",
		    out_file, strerror(errno));
	}
	setvbuf(out, ರಿಕ್ತ, _IOLBF, 0);

	ಯದಿ (moduli_bits == 0)
		moduli_bits = DEFAULT_BITS;
	ಯದಿ (gen_candidates(out, moduli_bits, start) != 0)
		fatal("modulus candidate generation failed");
#ಅನ್ಯಥಾ /* WITH_OPENSSL */
	fatal("Moduli generation is not supported");
#endif /* WITH_OPENSSL */
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_moduli_screen(ಧ್ರುವ ವರ್ಣ *out_file, ವರ್ಣ **opts, size_t nopts)
{
#ifdef WITH_OPENSSL
	/* Moduli generation/screening */
	ವರ್ಣ *checkpoint = ರಿಕ್ತ;
	uint32_t generator_wanted = 0;
	unsigned long start_lineno = 0, ಸಾಲುಗಳು_to_process = 0;
	ಪೂರ್ಣಾಙ್ಕ ಅವಿಭಾಜ್ಯ_tests = 0;
	FILE *out, *in = stdin;
	size_t i;
	ಧ್ರುವ ವರ್ಣ *errstr, *p;

	/* Parse options */
	ಪ್ರತಿ (i = 0; i < nopts; i++) {
		ಯದಿ ((p = strprefix(opts[i], "lines=", 0)) != ರಿಕ್ತ) {
			ಸಾಲುಗಳು_to_process = strtoul(p, ರಿಕ್ತ, 10);
		} ಅನ್ಯಥಾ ಯದಿ ((p = strprefix(opts[i], "start-line=", 0)) != ರಿಕ್ತ) {
			start_lineno = strtoul(p, ರಿಕ್ತ, 10);
		} ಅನ್ಯಥಾ ಯದಿ ((p = strprefix(opts[i], "checkpoint=", 0)) != ರಿಕ್ತ) {
			ಮುಕ್ತ(checkpoint);
			checkpoint = xstrdup(p);
		} ಅನ್ಯಥಾ ಯದಿ ((p = strprefix(opts[i], "generator=", 0)) != ರಿಕ್ತ) {
			generator_wanted = (uint32_t)strtonum(p, 1, UINT_MAX,
			    &errstr);
			ಯದಿ (errstr != ರಿಕ್ತ) {
				fatal("Generator invalid: %s (%s)", p, errstr);
			}
		} ಅನ್ಯಥಾ ಯದಿ ((p = strprefix(opts[i], "prime-tests=", 0)) != ರಿಕ್ತ) {
			ಅವಿಭಾಜ್ಯ_tests = (ಪೂರ್ಣಾಙ್ಕ)strtonum(p, 1, INT_MAX, &errstr);
			ಯದಿ (errstr) {
				fatal("Invalid number: %s (%s)", p, errstr);
			}
		} ಅನ್ಯಥಾ {
			fatal("Option \"%s\" is unsupported for moduli "
			    "screening", opts[i]);
		}
	}

	ಯದಿ (have_identity && strcmp(identity_file, "-") != 0) {
		ಯದಿ ((in = fopen(identity_file, "r")) == ರಿಕ್ತ) {
			fatal("Couldn't open modulus candidate "
			    "file \"%s\": %s", identity_file,
			    strerror(errno));
		}
	}

	ಯದಿ (strcmp(out_file, "-") == 0)
		out = stdout;
	ಅನ್ಯಥಾ ಯದಿ ((out = fopen(out_file, "a")) == ರಿಕ್ತ) {
		fatal("Couldn't open moduli file \"%s\": %s",
		    out_file, strerror(errno));
	}
	setvbuf(out, ರಿಕ್ತ, _IOLBF, 0);
	ಯದಿ (ಅವಿಭಾಜ್ಯ_test(in, out, ಅವಿಭಾಜ್ಯ_tests == 0 ? 100 : ಅವಿಭಾಜ್ಯ_tests,
	    generator_wanted, checkpoint,
	    start_lineno, ಸಾಲುಗಳು_to_process) != 0)
		fatal("modulus screening failed");
	ಯದಿ (in != stdin)
		(ಶೂನ್ಯ)fclose(in);
	ಮುಕ್ತ(checkpoint);
#ಅನ್ಯಥಾ /* WITH_OPENSSL */
	fatal("Moduli screening is not supported");
#endif /* WITH_OPENSSL */
}

/* Read and confirm a passphrase */
ಸ್ಥಿರ ವರ್ಣ *
read_check_passphrase(ಧ್ರುವ ವರ್ಣ *prompt1, ಧ್ರುವ ವರ್ಣ *prompt2,
    ಧ್ರುವ ವರ್ಣ *retry_prompt)
{
	ವರ್ಣ *passphrase1, *passphrase2;

	ಪ್ರತಿ (;;) {
		passphrase1 = read_passphrase(prompt1, RP_ALLOW_STDIN);
		passphrase2 = read_passphrase(prompt2, RP_ALLOW_STDIN);
		ಯದಿ (strcmp(passphrase1, passphrase2) == 0) {
			freezero(passphrase2, strlen(passphrase2));
			ಪ್ರತ್ಯಾಗಮ passphrase1;
		}
		/* The passphrases do not match. Clear them and retry. */
		freezero(passphrase1, strlen(passphrase1));
		freezero(passphrase2, strlen(passphrase2));
		fputs(retry_prompt, stdout);
		fputc('\n', stdout);
		fflush(stdout);
	}
	/* NOTREACHED */
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}

ಸ್ಥಿರ ವರ್ಣ *
private_ಕೀಲಿ_passphrase(ಧ್ರುವ ವರ್ಣ *path)
{
	ವರ್ಣ *prompt, *ret;

	ಯದಿ (identity_passphrase)
		ಪ್ರತ್ಯಾಗಮ xstrdup(identity_passphrase);
	ಯದಿ (identity_new_passphrase)
		ಪ್ರತ್ಯಾಗಮ xstrdup(identity_new_passphrase);

	xasprintf(&prompt, "Enter passphrase for \"%s\" "
	    "(empty for no passphrase): ", path);
	ret = read_check_passphrase(prompt,
	    "Enter same passphrase again: ",
	    "Passphrases do not match.  Try again.");
	ಮುಕ್ತ(prompt);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ವರ್ಣ *
sk_suffix(ಧ್ರುವ ವರ್ಣ *application, ಧ್ರುವ uint8_t *user, size_t userlen)
{
	ವರ್ಣ *ret, *cp;
	ಧ್ರುವ ವರ್ಣ *p;
	size_t slen, i;

	/* Trim off URL-like preamble */
	ಯದಿ ((p = strprefix(application, "ssh://", 0)) != ರಿಕ್ತ)
		ret =  xstrdup(p);
	ಅನ್ಯಥಾ ಯದಿ ((p = strprefix(application, "ssh:", 0)) != ರಿಕ್ತ)
		ret =  xstrdup(p);
	ಅನ್ಯಥಾ
		ret = xstrdup(application);

	/* Count trailing zeros in user */
	ಪ್ರತಿ (i = 0; i < userlen; i++) {
		ಯದಿ (user[userlen - i - 1] != 0)
			ಭಙ್ಗ;
	}
	ಯದಿ (i >= userlen)
		ಪ್ರತ್ಯಾಗಮ ret; /* user-id was default all-zeros */

	/* Append user-id, escaping non-UTF-8 characters */
	slen = userlen - i;
	ಯದಿ (asmprintf(&cp, INT_MAX, ರಿಕ್ತ, "%.*s", (ಪೂರ್ಣಾಙ್ಕ)slen, user) == -1)
		fatal_f("asmprintf failed");
	/* Don't emit a user-id that contains path or control characters */
	ಯದಿ (strchr(cp, '/') != ರಿಕ್ತ || strstr(cp, "..") != ರಿಕ್ತ ||
	    strchr(cp, '\\') != ರಿಕ್ತ) {
		ಮುಕ್ತ(cp);
		cp = tohex(user, slen);
	}
	xextendf(&ret, "_", "%s", cp);
	ಮುಕ್ತ(cp);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
do_download_sk(ಧ್ರುವ ವರ್ಣ *skprovider, ಧ್ರುವ ವರ್ಣ *device)
{
	ಸಂರಚನಾ sshsk_resident_ಕೀಲಿ **srks;
	size_t nsrks, i;
	ಪೂರ್ಣಾಙ್ಕ r, ret = -1;
	ವರ್ಣ *fp, *pin = ರಿಕ್ತ, *pass = ರಿಕ್ತ, *path, *pubpath;
	ಧ್ರುವ ವರ್ಣ *ext;
	ಸಂರಚನಾ sshkey *ಕೀಲಿ;

	ಯದಿ (skprovider == ರಿಕ್ತ)
		fatal("Cannot download keys without provider");

	pin = read_passphrase("Enter PIN for authenticator: ", RP_ALLOW_STDIN);
	ಯದಿ (!quiet) {
		printf("You may need to touch your authenticator "
		    "to authorize key download.\n");
	}
	ಯದಿ ((r = sshsk_load_resident(skprovider, device, pin, 0,
	    &srks, &nsrks)) != 0) {
		ಯದಿ (pin != ರಿಕ್ತ)
			freezero(pin, strlen(pin));
		error_r(r, "Unable to load resident keys");
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯದಿ (nsrks == 0)
		logit("No keys to download");
	ಯದಿ (pin != ರಿಕ್ತ)
		freezero(pin, strlen(pin));

	ಪ್ರತಿ (i = 0; i < nsrks; i++) {
		ಕೀಲಿ = srks[i]->ಕೀಲಿ;
		ಯದಿ (ಕೀಲಿ->type != ಕೀಲಿ_ECDSA_SK && ಕೀಲಿ->type != ಕೀಲಿ_ED25519_SK) {
			error("Unsupported key type %s (%d)",
			    sshkey_type(ಕೀಲಿ), ಕೀಲಿ->type);
			ಅನುವರ್ತ;
		}
		ಯದಿ ((fp = sshkey_fingerprint(ಕೀಲಿ, fingerprint_hash,
		    SSH_FP_DEFAULT)) == ರಿಕ್ತ)
			fatal_f("sshkey_fingerprint failed");
		debug_f("key %zu: %s %s %s (flags 0x%02x)", i,
		    sshkey_type(ಕೀಲಿ), fp, ಕೀಲಿ->sk_application, ಕೀಲಿ->sk_flags);
		ext = sk_suffix(ಕೀಲಿ->sk_application,
		    srks[i]->user_id, srks[i]->user_id_len);
		xasprintf(&path, "id_%s_rk%s%s",
		    ಕೀಲಿ->type == ಕೀಲಿ_ECDSA_SK ? "ecdsa_sk" : "ed25519_sk",
		    *ext == '\0' ? "" : "_", ext);

		/* If the file already exists, ask the user to confirm. */
		ಯದಿ (!confirm_overwrite(path)) {
			ಮುಕ್ತ(path);
			ಭಙ್ಗ;
		}

		/* Save the key with the application string as the comment */
		ಯದಿ (pass == ರಿಕ್ತ)
			pass = private_ಕೀಲಿ_passphrase(path);
		ಯದಿ ((r = sshkey_save_private(ಕೀಲಿ, path, pass,
		    ಕೀಲಿ->sk_application, private_ಕೀಲಿ_format,
		    openssh_format_cipher, rounds)) != 0) {
			error_r(r, "Saving key \"%s\" failed", path);
			ಮುಕ್ತ(path);
			ಭಙ್ಗ;
		}
		ಯದಿ (!quiet) {
			printf("Saved %s key%s%s to %s\n", sshkey_type(ಕೀಲಿ),
			    *ext != '\0' ? " " : "",
			    *ext != '\0' ? ಕೀಲಿ->sk_application : "",
			    path);
		}

		/* Save public key too */
		xasprintf(&pubpath, "%s.pub", path);
		ಮುಕ್ತ(path);
		ಯದಿ ((r = sshkey_save_public(ಕೀಲಿ, pubpath,
		    ಕೀಲಿ->sk_application)) != 0) {
			error_r(r, "Saving public key \"%s\" failed", pubpath);
			ಮುಕ್ತ(pubpath);
			ಭಙ್ಗ;
		}
		ಮುಕ್ತ(pubpath);
	}

	ಯದಿ (i >= nsrks)
		ret = 0; /* success */
	ಯದಿ (pass != ರಿಕ್ತ)
		freezero(pass, strlen(pass));
	sshsk_free_resident_ಕೀಲಿಗಳು(srks, nsrks);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಶೂನ್ಯ
save_attestation(ಸಂರಚನಾ sshbuf *attest, ಧ್ರುವ ವರ್ಣ *path)
{
	mode_t omask;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (path == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ; /* nothing to do */
	ಯದಿ (attest == ರಿಕ್ತ || sshbuf_len(attest) == 0)
		fatal("Enrollment did not return attestation data");
	omask = umask(077);
	r = sshbuf_write_file(path, attest);
	umask(omask);
	ಯದಿ (r != 0)
		fatal_r(r, "Unable to write attestation data \"%s\"", path);
	ಯದಿ (!quiet)
		printf("Your FIDO attestation certificate has been saved in "
		    "%s\n", path);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
confirm_sk_overwrite(ಧ್ರುವ ವರ್ಣ *application, ಧ್ರುವ ವರ್ಣ *user)
{
	ವರ್ಣ yesno[3];

	printf("A resident key scoped to '%s' with user id '%s' already "
	    "exists.\n", application == ರಿಕ್ತ ? "ssh:" : application,
	    user == ರಿಕ್ತ ? "null" : user);
	printf("Overwrite key in token (y/n)? ");
	fflush(stdout);
	ಯದಿ (fgets(yesno, ಪರಿಮಾಣ(yesno), stdin) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (yesno[0] != 'y' && yesno[0] != 'Y')
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತ್ಯಾಗಮ 1;
}

ಸ್ಥಿರ ಶೂನ್ಯ
usage(ಶೂನ್ಯ)
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
ಪೂರ್ಣಾಙ್ಕ
main(ಪೂರ್ಣಾಙ್ಕ argc, ವರ್ಣ **argv)
{
	ವರ್ಣ comment[ಕೀಲಿ_COMMENT_MAX], *passphrase = ರಿಕ್ತ;
	ವರ್ಣ *rr_hostname = ರಿಕ್ತ, *ep, *fp, *ra;
	ಸಂರಚನಾ sshkey *ಗುಪ್ತ = ರಿಕ್ತ, *ಸಾರ್ವಜನಿಕ = ರಿಕ್ತ;
	ಸಂರಚನಾ passwd *pw;
	ಪೂರ್ಣಾಙ್ಕ ret = 0, r, opt, type;
	ಪೂರ್ಣಾಙ್ಕ change_passphrase = 0, change_comment = 0, show_cert = 0;
	ಪೂರ್ಣಾಙ್ಕ find_host = 0, delete_host = 0, hash_hosts = 0;
	ಪೂರ್ಣಾಙ್ಕ gen_all_hostkeys = 0, gen_krl = 0, update_krl = 0, check_krl = 0;
	ಪೂರ್ಣಾಙ್ಕ prefer_agent = 0, convert_to = 0, convert_from = 0;
	ಪೂರ್ಣಾಙ್ಕ print_public = 0, print_generic = 0, cert_serial_autoinc = 0;
	ಪೂರ್ಣಾಙ್ಕ do_gen_candidates = 0, do_screen_candidates = 0, download_sk = 0;
	unsigned long long cert_serial = 0;
	ವರ್ಣ *identity_comment = ರಿಕ್ತ, *ca_ಕೀಲಿ_path = ರಿಕ್ತ, **opts = ರಿಕ್ತ;
	ವರ್ಣ *sk_application = ರಿಕ್ತ, *sk_device = ರಿಕ್ತ, *sk_user = ರಿಕ್ತ;
	ವರ್ಣ *sk_attestation_path = ರಿಕ್ತ;
	ಸಂರಚನಾ sshbuf *challenge = ರಿಕ್ತ, *attest = ರಿಕ್ತ;
	size_t i, nopts = 0;
	uint32_t bits = 0;
	uint8_t sk_flags = SSH_SK_USER_PRESENCE_REQD;
	ಧ್ರುವ ವರ್ಣ *errstr, *p;
	ಪೂರ್ಣಾಙ್ಕ log_level = SYSLOG_LEVEL_INFO;
	ವರ್ಣ *sign_op = ರಿಕ್ತ;

	ಬಾಹ್ಯ ಪೂರ್ಣಾಙ್ಕ optind;
	ಬಾಹ್ಯ ವರ್ಣ *optarg;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	__progname = ssh_get_progname(argv[0]);

	seed_rng();

	log_init(argv[0], SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_USER, 1);

	msetlocale();

	/* we need this for the home * directory.  */
	pw = getpwuid(getuid());
	ಯದಿ (!pw)
		fatal("No user exists for uid %lu", (u_long)getuid());
	pw = pwcopy(pw);
	ಯದಿ (gethostname(hostname, ಪರಿಮಾಣ(hostname)) == -1)
		fatal("gethostname: %s", strerror(errno));

	sk_provider = getenv("SSH_SK_PROVIDER");

	/* Remaining characters: dGjJSTWx */
	ಯಾವತ್ ((opt = getopt(argc, argv, "ABHKLQUXceghiklopquvy"
	    "C:D:E:F:I:M:N:O:P:R:V:Y:Z:"
	    "a:b:f:g:m:n:r:s:t:w:z:")) != -1) {
		ವಿಕಲ್ಪ (opt) {
		ಪಕ್ಷ 'A':
			gen_all_hostkeys = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'b':
			bits = (uint32_t)strtonum(optarg, 1, UINT32_MAX,
			    &errstr);
			ಯದಿ (errstr)
				fatal("Bits has bad value %s (%s)",
					optarg, errstr);
			ಭಙ್ಗ;
		ಪಕ್ಷ 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			ಯದಿ (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			ಭಙ್ಗ;
		ಪಕ್ಷ 'F':
			find_host = 1;
			rr_hostname = optarg;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'H':
			hash_hosts = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'I':
			cert_ಕೀಲಿ_id = optarg;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'R':
			delete_host = 1;
			rr_hostname = optarg;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'L':
			show_cert = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'l':
			print_fingerprint = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'B':
			print_bubblebabble = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'm':
			ಯದಿ (strcasecmp(optarg, "RFC4716") == 0 ||
			    strcasecmp(optarg, "ssh2") == 0) {
				convert_format = FMT_RFC4716;
				ಭಙ್ಗ;
			}
			ಯದಿ (strcasecmp(optarg, "PKCS8") == 0) {
				convert_format = FMT_PKCS8;
				private_ಕೀಲಿ_format = SSHKEY_PRIVATE_PKCS8;
				ಭಙ್ಗ;
			}
			ಯದಿ (strcasecmp(optarg, "PEM") == 0) {
				convert_format = FMT_PEM;
				private_ಕೀಲಿ_format = SSHKEY_PRIVATE_PEM;
				ಭಙ್ಗ;
			}
			ಯದಿ (strcasecmp(optarg, "hexdump") == 0) {
				convert_format = FMT_HEXDUMP;
				ಭಙ್ಗ;
			}
			fatal("Unsupported conversion format \"%s\"", optarg);
		ಪಕ್ಷ 'n':
			cert_principals = optarg;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'o':
			/* no-op; new format is already the default */
			ಭಙ್ಗ;
		ಪಕ್ಷ 'p':
			change_passphrase = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'c':
			change_comment = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'f':
			ಯದಿ (strlcpy(identity_file, optarg,
			    ಪರಿಮಾಣ(identity_file)) >= ಪರಿಮಾಣ(identity_file))
				fatal("Identity filename too long");
			have_identity = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'g':
			print_generic = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'K':
			download_sk = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'P':
			identity_passphrase = optarg;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'N':
			identity_new_passphrase = optarg;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'Q':
			check_krl = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'O':
			opts = xrecallocarray(opts, nopts, nopts + 1,
			    ಪರಿಮಾಣ(*opts));
			opts[nopts++] = xstrdup(optarg);
			ಭಙ್ಗ;
		ಪಕ್ಷ 'Z':
			openssh_format_cipher = optarg;
			ಯದಿ (cipher_by_name(openssh_format_cipher) == ರಿಕ್ತ)
				fatal("Invalid OpenSSH-format cipher '%s'",
				    openssh_format_cipher);
			ಭಙ್ಗ;
		ಪಕ್ಷ 'C':
			identity_comment = optarg;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'q':
			quiet = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'e':
			/* export key */
			convert_to = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'h':
			cert_ಕೀಲಿ_type = SSH2_CERT_TYPE_HOST;
			certflags_flags = 0;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'k':
			gen_krl = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'i':
		ಪಕ್ಷ 'X':
			/* import key */
			convert_from = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'y':
			print_public = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 's':
			ca_ಕೀಲಿ_path = optarg;
			ಭಙ್ಗ;
		ಪಕ್ಷ 't':
			ಕೀಲಿ_type_name = optarg;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'D':
			pkcs11provider = optarg;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'U':
			prefer_agent = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'u':
			update_krl = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'v':
			ಯದಿ (log_level == SYSLOG_LEVEL_INFO)
				log_level = SYSLOG_LEVEL_DEBUG1;
			ಅನ್ಯಥಾ {
				ಯದಿ (log_level >= SYSLOG_LEVEL_DEBUG1 &&
				    log_level < SYSLOG_LEVEL_DEBUG3)
					log_level++;
			}
			ಭಙ್ಗ;
		ಪಕ್ಷ 'r':
			rr_hostname = optarg;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'a':
			rounds = (ಪೂರ್ಣಾಙ್ಕ)strtonum(optarg, 1, INT_MAX, &errstr);
			ಯದಿ (errstr)
				fatal("Invalid number: %s (%s)",
					optarg, errstr);
			ಭಙ್ಗ;
		ಪಕ್ಷ 'V':
			parse_cert_times(optarg);
			ಭಙ್ಗ;
		ಪಕ್ಷ 'Y':
			sign_op = optarg;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'w':
			sk_provider = optarg;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'z':
			errno = 0;
			ಯದಿ (*optarg == '+') {
				cert_serial_autoinc = 1;
				optarg++;
			}
			cert_serial = strtoull(optarg, &ep, 10);
			ಯದಿ (*optarg < '0' || *optarg > '9' || *ep != '\0' ||
			    (errno == ERANGE && cert_serial == ULLONG_MAX))
				fatal("Invalid serial number \"%s\"", optarg);
			ಭಙ್ಗ;
		ಪಕ್ಷ 'M':
			ಯದಿ (strcmp(optarg, "generate") == 0)
				do_gen_candidates = 1;
			ಅನ್ಯಥಾ ಯದಿ (strcmp(optarg, "screen") == 0)
				do_screen_candidates = 1;
			ಅನ್ಯಥಾ
				fatal("Unsupported moduli option %s", optarg);
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			usage();
		}
	}

#ifdef ENABLE_SK_INTERNAL
	ಯದಿ (sk_provider == ರಿಕ್ತ)
		sk_provider = "internal";
#endif

	/* reinit */
	log_init(argv[0], log_level, SYSLOG_FACILITY_USER, 1);

	argv += optind;
	argc -= optind;

	ಯದಿ (sign_op != ರಿಕ್ತ) {
		ಯದಿ (strprefix(sign_op, "find-principals", 0) != ರಿಕ್ತ) {
			ಯದಿ (ca_ಕೀಲಿ_path == ರಿಕ್ತ) {
				error("Too few arguments for find-principals:"
				    "missing signature file");
				exit(1);
			}
			ಯದಿ (!have_identity) {
				error("Too few arguments for find-principals:"
				    "missing allowed keys file");
				exit(1);
			}
			ret = sig_find_principals(ca_ಕೀಲಿ_path, identity_file,
			    opts, nopts);
			ಗಚ್ಛ done;
		} ಅನ್ಯಥಾ ಯದಿ (strprefix(sign_op, "match-principals", 0) != ರಿಕ್ತ) {
			ಯದಿ (!have_identity) {
				error("Too few arguments for match-principals:"
				    "missing allowed keys file");
				exit(1);
			}
			ಯದಿ (cert_ಕೀಲಿ_id == ರಿಕ್ತ) {
				error("Too few arguments for match-principals: "
				    "missing principal ID");
				exit(1);
			}
			ret = sig_match_principals(identity_file, cert_ಕೀಲಿ_id,
			    opts, nopts);
			ಗಚ್ಛ done;
		} ಅನ್ಯಥಾ ಯದಿ (strprefix(sign_op, "sign", 0) != ರಿಕ್ತ) {
			/* NB. cert_principals is actually namespace, via -n */
			ಯದಿ (cert_principals == ರಿಕ್ತ ||
			    *cert_principals == '\0') {
				error("Too few arguments for sign: "
				    "missing namespace");
				exit(1);
			}
			ಯದಿ (!have_identity) {
				error("Too few arguments for sign: "
				    "missing key");
				exit(1);
			}
			ret = sig_sign(identity_file, cert_principals,
			    prefer_agent, argc, argv, opts, nopts);
			ಗಚ್ಛ done;
		} ಅನ್ಯಥಾ ಯದಿ (strprefix(sign_op, "check-novalidate", 0) != ರಿಕ್ತ) {
			/* NB. cert_principals is actually namespace, via -n */
			ಯದಿ (cert_principals == ರಿಕ್ತ ||
			    *cert_principals == '\0') {
				error("Too few arguments for check-novalidate: "
				    "missing namespace");
				exit(1);
			}
			ಯದಿ (ca_ಕೀಲಿ_path == ರಿಕ್ತ) {
				error("Too few arguments for check-novalidate: "
				    "missing signature file");
				exit(1);
			}
			ret = sig_verify(ca_ಕೀಲಿ_path, cert_principals,
			    ರಿಕ್ತ, ರಿಕ್ತ, ರಿಕ್ತ, opts, nopts);
			ಗಚ್ಛ done;
		} ಅನ್ಯಥಾ ಯದಿ (strprefix(sign_op, "verify", 0) != ರಿಕ್ತ) {
			/* NB. cert_principals is actually namespace, via -n */
			ಯದಿ (cert_principals == ರಿಕ್ತ ||
			    *cert_principals == '\0') {
				error("Too few arguments for verify: "
				    "missing namespace");
				exit(1);
			}
			ಯದಿ (ca_ಕೀಲಿ_path == ರಿಕ್ತ) {
				error("Too few arguments for verify: "
				    "missing signature file");
				exit(1);
			}
			ಯದಿ (!have_identity) {
				error("Too few arguments for sign: "
				    "missing allowed keys file");
				exit(1);
			}
			ಯದಿ (cert_ಕೀಲಿ_id == ರಿಕ್ತ) {
				error("Too few arguments for verify: "
				    "missing principal identity");
				exit(1);
			}
			ret = sig_verify(ca_ಕೀಲಿ_path, cert_principals,
			    cert_ಕೀಲಿ_id, identity_file, rr_hostname,
			    opts, nopts);
			ಗಚ್ಛ done;
		}
		error("Unsupported operation for -Y: \"%s\"", sign_op);
		usage();
		/* NOTREACHED */
	}

	ಯದಿ (ca_ಕೀಲಿ_path != ರಿಕ್ತ) {
		ಯದಿ (argc < 1 && !gen_krl) {
			error("Too few arguments.");
			usage();
		}
	} ಅನ್ಯಥಾ ಯದಿ (argc > 0 && !gen_krl && !check_krl &&
	    !do_gen_candidates && !do_screen_candidates) {
		error("Too many arguments.");
		usage();
	}
	ಯದಿ (change_passphrase && change_comment) {
		error("Can only have one of -p and -c.");
		usage();
	}
	ಯದಿ (print_fingerprint && (delete_host || hash_hosts)) {
		error("Cannot use -l with -H or -R.");
		usage();
	}
	ಯದಿ (gen_krl) {
		do_gen_krl(pw, update_krl, ca_ಕೀಲಿ_path,
		    cert_serial, identity_comment, argc, argv);
		ಗಚ್ಛ done;
	}
	ಯದಿ (check_krl) {
		do_check_krl(pw, print_fingerprint, argc, argv);
		ಗಚ್ಛ done;
	}
	ಯದಿ (ca_ಕೀಲಿ_path != ರಿಕ್ತ) {
		ಯದಿ (cert_ಕೀಲಿ_id == ರಿಕ್ತ)
			fatal("Must specify key id (-I) when certifying");
		ಯದಿ (cert_principals == ರಿಕ್ತ) {
			/*
			 * Ideally this would be a fatal(), but we need to
			 * be able to generate such certificates for testing
			 * even though they will be rejected.
			 */
			error("Warning: certificate will contain no "
			    "principals (-n)");
		}
		ಪ್ರತಿ (i = 0; i < nopts; i++)
			add_cert_option(opts[i]);
		do_ca_sign(pw, ca_ಕೀಲಿ_path, prefer_agent,
		    cert_serial, cert_serial_autoinc, argc, argv);
		ಗಚ್ಛ done;
	}
	ಯದಿ (show_cert)
		do_show_cert(pw);
	ಯದಿ (delete_host || hash_hosts || find_host) {
		do_known_hosts(pw, rr_hostname, find_host,
		    delete_host, hash_hosts);
	}
	ಯದಿ (pkcs11provider != ರಿಕ್ತ)
		do_download(pw);
	ಯದಿ (download_sk) {
		ಪ್ರತಿ (i = 0; i < nopts; i++) {
			ಯದಿ ((p = strprefix(opts[i], "device=", 1)) != ರಿಕ್ತ) {
				sk_device = xstrdup(p);
			} ಅನ್ಯಥಾ {
				fatal("Option \"%s\" is unsupported for "
				    "FIDO authenticator download", opts[i]);
			}
		}
		ret = do_download_sk(sk_provider, sk_device);
		ಗಚ್ಛ done;
	}
	ಯದಿ (print_fingerprint || print_bubblebabble)
		do_fingerprint(pw);
	ಯದಿ (change_passphrase)
		do_change_passphrase(pw, opts, nopts);
	ಯದಿ (change_comment)
		do_change_comment(pw, identity_comment);
#ifdef WITH_OPENSSL
	ಯದಿ (convert_to) {
		do_convert_to(pw);
		ಗಚ್ಛ done;
	}
	ಯದಿ (convert_from) {
		do_convert_from(pw);
		ಗಚ್ಛ done;
	}
#ಅನ್ಯಥಾ /* WITH_OPENSSL */
	ಯದಿ (convert_to || convert_from)
		fatal("key conversion disabled at compile time");
#endif /* WITH_OPENSSL */
	ಯದಿ (print_public)
		do_print_public(pw);
	ಯದಿ (rr_hostname != ರಿಕ್ತ) {
		unsigned ಪೂರ್ಣಾಙ್ಕ n = 0;

		ಯದಿ (have_identity) {
			n = do_print_resource_record(pw, identity_file,
			    rr_hostname, print_generic, opts, nopts);
			ಯದಿ (n == 0)
				fatal("%s: %s", identity_file, strerror(errno));
			exit(0);
		} ಅನ್ಯಥಾ {

			n += do_print_resource_record(pw,
			    PATH_HOST_RSA_ಕೀಲಿ_FILE, rr_hostname,
			    print_generic, opts, nopts);
			n += do_print_resource_record(pw,
			    PATH_HOST_ECDSA_ಕೀಲಿ_FILE, rr_hostname,
			    print_generic, opts, nopts);
			n += do_print_resource_record(pw,
			    PATH_HOST_ED25519_ಕೀಲಿ_FILE, rr_hostname,
			    print_generic, opts, nopts);
			ಯದಿ (n == 0)
				fatal("no keys found.");
			exit(0);
		}
	}

	ಯದಿ (do_gen_candidates || do_screen_candidates) {
		ಯದಿ (argc <= 0)
			fatal("No output file specified");
		ಅನ್ಯಥಾ ಯದಿ (argc > 1)
			fatal("Too many output files specified");
	}
	ಯದಿ (do_gen_candidates) {
		do_moduli_gen(argv[0], opts, nopts);
		ಗಚ್ಛ done;
	}
	ಯದಿ (do_screen_candidates) {
		do_moduli_screen(argv[0], opts, nopts);
		ಗಚ್ಛ done;
	}

	ಯದಿ (gen_all_hostkeys) {
		do_gen_all_hostkeys(pw);
		ಗಚ್ಛ done;
	}

	ಯದಿ (ಕೀಲಿ_type_name == ರಿಕ್ತ)
		ಕೀಲಿ_type_name = DEFAULT_ಕೀಲಿ_TYPE_NAME;

	type = sshkey_type_from_shortname(ಕೀಲಿ_type_name);
	type_bits_valid(type, ಕೀಲಿ_type_name, &bits);

	ಯದಿ (!quiet)
		printf("Generating public/private %s key pair.\n",
		    ಕೀಲಿ_type_name);
	ವಿಕಲ್ಪ (type) {
	ಪಕ್ಷ ಕೀಲಿ_ECDSA_SK:
	ಪಕ್ಷ ಕೀಲಿ_ED25519_SK:
		ಪ್ರತಿ (i = 0; i < nopts; i++) {
			ಯದಿ (strcasecmp(opts[i], "no-touch-required") == 0) {
				sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
			} ಅನ್ಯಥಾ ಯದಿ (strcasecmp(opts[i], "verify-required") == 0) {
				sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
			} ಅನ್ಯಥಾ ಯದಿ (strcasecmp(opts[i], "resident") == 0) {
				sk_flags |= SSH_SK_RESIDENT_ಕೀಲಿ;
			} ಅನ್ಯಥಾ ಯದಿ ((p = strprefix(opts[i], "device=", 1))
			    != ರಿಕ್ತ ) {
				sk_device = xstrdup(p);
			} ಅನ್ಯಥಾ ಯದಿ ((p = strprefix(opts[i], "user=", 1))
			    != ರಿಕ್ತ) {
				sk_user = xstrdup(p);
			} ಅನ್ಯಥಾ ಯದಿ ((p = strprefix(opts[i], "challenge=", 1))
			    != ರಿಕ್ತ) {
				ಯದಿ ((r = sshbuf_load_file(p,
				    &challenge)) != 0) {
					fatal_r(r, "Unable to load FIDO "
					    "enrollment challenge \"%s\"", p);
				}
			} ಅನ್ಯಥಾ ಯದಿ (strncasecmp(opts[i],
			    "write-attestation=", 18) == 0) {
				sk_attestation_path = opts[i] + 18;
			} ಅನ್ಯಥಾ ಯದಿ (strncasecmp(opts[i],
			    "application=", 12) == 0) {
				sk_application = xstrdup(opts[i] + 12);
				ಯದಿ (strncmp(sk_application, "ssh:", 4) != 0) {
					fatal("FIDO application string must "
					    "begin with \"ssh:\"");
				}
			} ಅನ್ಯಥಾ {
				fatal("Option \"%s\" is unsupported for "
				    "FIDO authenticator enrollment", opts[i]);
			}
		}
		ಯದಿ ((attest = sshbuf_new()) == ರಿಕ್ತ)
			fatal("sshbuf_new failed");
		r = 0;
		ಪ್ರತಿ (i = 0 ;;) {
			ಯದಿ (!quiet) {
				printf("You may need to touch your "
				    "authenticator%s to authorize key "
				    "generation.\n",
				    r == 0 ? "" : " again");
			}
			fflush(stdout);
			r = sshsk_enroll(type, sk_provider, sk_device,
			    sk_application == ರಿಕ್ತ ? "ssh:" : sk_application,
			    sk_user, sk_flags, passphrase, challenge,
			    &ಗುಪ್ತ, attest);
			ಯದಿ (r == 0)
				ಭಙ್ಗ;
			ಯದಿ (r == SSH_ERR_ಕೀಲಿ_BAD_PERMISSIONS &&
			    (sk_flags & SSH_SK_RESIDENT_ಕೀಲಿ) != 0 &&
			    (sk_flags & SSH_SK_FORCE_OPERATION) == 0 &&
			    confirm_sk_overwrite(sk_application, sk_user)) {
				sk_flags |= SSH_SK_FORCE_OPERATION;
				ಅನುವರ್ತ;
			}
			ಯದಿ (r != SSH_ERR_ಕೀಲಿ_WRONG_PASSPHRASE)
				fatal_r(r, "Key enrollment failed");
			ಅನ್ಯಥಾ ಯದಿ (passphrase != ರಿಕ್ತ) {
				error("PIN incorrect");
				freezero(passphrase, strlen(passphrase));
				passphrase = ರಿಕ್ತ;
			}
			ಯದಿ (++i >= 3)
				fatal("Too many incorrect PINs");
			passphrase = read_passphrase("Enter PIN for "
			    "authenticator: ", RP_ALLOW_STDIN);
		}
		ಯದಿ (passphrase != ರಿಕ್ತ) {
			freezero(passphrase, strlen(passphrase));
			passphrase = ರಿಕ್ತ;
		}
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		ಯದಿ ((r = sshkey_generate(type, bits, &ಗುಪ್ತ)) != 0)
			fatal("sshkey_generate failed");
		ಭಙ್ಗ;
	}
	ಯದಿ ((r = sshkey_from_private(ಗುಪ್ತ, &ಸಾರ್ವಜನಿಕ)) != 0)
		fatal_r(r, "sshkey_from_private");

	ಯದಿ (!have_identity)
		ask_filename(pw, "Enter file in which to save the key");

	/* Create ~/.ssh directory if it doesn't already exist. */
	hostfile_create_user_ssh_dir(identity_file, !quiet);

	/* If the file already exists, ask the user to confirm. */
	ಯದಿ (!confirm_overwrite(identity_file))
		exit(1);

	/* Determine the passphrase for the private key */
	passphrase = private_ಕೀಲಿ_passphrase(identity_file);
	ಯದಿ (identity_comment) {
		strlcpy(comment, identity_comment, ಪರಿಮಾಣ(comment));
	} ಅನ್ಯಥಾ {
		/* Create default comment field for the passphrase. */
		snprintf(comment, ಪರಿಮಾಣ comment, "%s@%s", pw->pw_name, hostname);
	}



	/* Save the key with the given passphrase and comment. */
	ಯದಿ ((r = sshkey_save_private(ಗುಪ್ತ, identity_file, passphrase,
	    comment, private_ಕೀಲಿ_format, openssh_format_cipher, rounds)) != 0) {
		error_r(r, "Saving key \"%s\" failed", identity_file);
		freezero(passphrase, strlen(passphrase));
		exit(1);
	}
	freezero(passphrase, strlen(passphrase));
	sshkey_free(ಗುಪ್ತ);

	ಯದಿ (!quiet) {
		printf("Your identification has been saved in %s\n",
		    identity_file);
	}

	strlcat(identity_file, ".pub", ಪರಿಮಾಣ(identity_file));
	ಯದಿ ((r = sshkey_save_public(ಸಾರ್ವಜನಿಕ, identity_file, comment)) != 0)
		fatal_r(r, "Unable to save public key to %s", identity_file);

	ಯದಿ (!quiet) {
		fp = sshkey_fingerprint(ಸಾರ್ವಜನಿಕ, fingerprint_hash,
		    SSH_FP_DEFAULT);
		ra = sshkey_fingerprint(ಸಾರ್ವಜನಿಕ, fingerprint_hash,
		    SSH_FP_RANDOMART);
		ಯದಿ (fp == ರಿಕ್ತ || ra == ರಿಕ್ತ)
			fatal("sshkey_fingerprint failed");
		printf("Your public key has been saved in %s\n",
		    identity_file);
		printf("The key fingerprint is:\n");
		printf("%s %s\n", fp, comment);
		printf("The key's randomart image is:\n");
		printf("%s\n", ra);
		ಮುಕ್ತ(ra);
		ಮುಕ್ತ(fp);
	}

	ಯದಿ (sk_attestation_path != ರಿಕ್ತ)
		save_attestation(attest, sk_attestation_path);

 done:
	sshbuf_free(attest);
	sshkey_free(ಸಾರ್ವಜನಿಕ);
	pwfree(pw);
	exit(ret);
}
