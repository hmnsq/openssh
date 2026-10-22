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

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ "openbsd-compat/openssl-compat.h"
#ಅನ್ತರ್ಭಾವ <openssl/bn.h>
#ಅನ್ತರ್ಭಾವ <openssl/evp.h>
#ಅನ್ತರ್ಭಾವ <openssl/pem.h>
#ಆದರೆ_ಅಂತ್ಯ

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

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ ENABLE_PKCS11
#ಅನ್ತರ್ಭಾವ "ssh-pkcs11.h"
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿಸು DEFAULT_ಕೀಲಿ_TYPE_NAME "ed25519"

/*
 * Default number of bits in the RSA and ECDSA keys.  These value can be
 * overridden on the command line.
 *
 * These values provide security equivalent to at least 128 bits of security
 * according to NIST Special Publication 800-57: Recommendation for Key
 * Management Part 1 rev 4 section 5.6.1.
 */
#ವ್ಯಾಖ್ಯಾನಿಸು DEFAULT_ಬಿಟ್ಟುಗಳು		3072
#ವ್ಯಾಖ್ಯಾನಿಸು DEFAULT_ಬಿಟ್ಟುಗಳು_ECDSA	256

#ವ್ಯಾಖ್ಯಾನಿಸು ಕೀಲಿ_COMMENT_MAX		(NI_MAXHOST + 1024)

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ quiet = 0;

/* Flag indicating that we just want to see the key fingerprint */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ print_fingerprint = 0;
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ print_bubblebabble = 0;

/* Hash algorithm to use for fingerprints. */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* The identity file name, given on the command line or entered by the user. */
ಸ್ಥಿರ ಅಕ್ಷರ ತಟಸ್ಥ_file[PATH_MAX];
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ have_ತಟಸ್ಥ = 0;

/* This is set to the passphrase if given on the command line. */
ಸ್ಥಿರ ಅಕ್ಷರ *ತಟಸ್ಥ_passphrase = ಖಾಲಿ;

/* This is set to the new passphrase if given on the command line. */
ಸ್ಥಿರ ಅಕ್ಷರ *ತಟಸ್ಥ_new_passphrase = ಖಾಲಿ;

/* Key type when certifying */
ಸ್ಥಿರ u_int cert_ಕೀಲಿ_type = SSH2_CERT_TYPE_USER;

/* "key ID" of signed key */
ಸ್ಥಿರ ಅಕ್ಷರ *cert_ಕೀಲಿ_id = ಖಾಲಿ;

/* Comma-separated list of principal names for certifying keys */
ಸ್ಥಿರ ಅಕ್ಷರ *cert_principals = ಖಾಲಿ;

/* Validity period for certificates */
ಸ್ಥಿರ uint64_t cert_valid_from = 0;
ಸ್ಥಿರ uint64_t cert_valid_ಗಮ್ಯ = ~0ULL;

/* Certificate options */
#ವ್ಯಾಖ್ಯಾನಿಸು CERTOPT_X_FWD				(1)
#ವ್ಯಾಖ್ಯಾನಿಸು CERTOPT_AGENT_FWD			(1<<1)
#ವ್ಯಾಖ್ಯಾನಿಸು CERTOPT_ಪೋರ್ಟ್_FWD			(1<<2)
#ವ್ಯಾಖ್ಯಾನಿಸು CERTOPT_PTY				(1<<3)
#ವ್ಯಾಖ್ಯಾನಿಸು CERTOPT_USER_RC				(1<<4)
#ವ್ಯಾಖ್ಯಾನಿಸು CERTOPT_NO_REQUIRE_USER_PRESENCE	(1<<5)
#ವ್ಯಾಖ್ಯಾನಿಸು CERTOPT_REQUIRE_VERIFY			(1<<6)
#ವ್ಯಾಖ್ಯಾನಿಸು CERTOPT_DEFAULT	(CERTOPT_X_FWD|CERTOPT_AGENT_FWD| \
			 CERTOPT_ಪೋರ್ಟ್_FWD|CERTOPT_PTY|CERTOPT_USER_RC)
ಸ್ಥಿರ uint32_t certflags_flags = CERTOPT_DEFAULT;
ಸ್ಥಿರ ಅಕ್ಷರ *certflags_command = ಖಾಲಿ;
ಸ್ಥಿರ ಅಕ್ಷರ *certflags_src_addr = ಖಾಲಿ;

/* Arbitrary extensions specified by user */
ರಚನೆ cert_ext {
	ಅಕ್ಷರ *ಕೀಲಿ;
	ಅಕ್ಷರ *val;
	ಪೂರ್ಣಾಂಕ crit;
};
ಸ್ಥಿರ ರಚನೆ cert_ext *cert_ext;
ಸ್ಥಿರ ಗಾತ್ರ_t ncert_ext;

/* Conversion to/from various formats */
ಎಣಿಕೆ {
	FMT_RFC4716,
	FMT_PKCS8,
	FMT_PEM,
	FMT_HEXDUMP
} convert_format = FMT_RFC4716;

ಸ್ಥಿರ ಅಕ್ಷರ *ಕೀಲಿ_type_name = ಖಾಲಿ;

/* Load key from this PKCS#11 provider */
ಸ್ಥಿರ ಅಕ್ಷರ *pkcs11provider = ಖಾಲಿ;

/* FIDO/U2F provider to use */
ಸ್ಥಿರ ಅಕ್ಷರ *sk_provider = ಖಾಲಿ;

/* Format for writing private keys */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ಖಾಸಗಿ_ಕೀಲಿ_format = SSHKEY_ಖಾಸಗಿ_OPENSSH;

/* Cipher for new-format private keys */
ಸ್ಥಿರ ಅಕ್ಷರ *openssh_format_cipher = ಖಾಲಿ;

/* Number of KDF rounds to derive new format keys. */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ಸುತ್ತುಗಳು = 0;

/* argv0 */
ಬಾಹ್ಯ ಅಕ್ಷರ *__progname;

ಸ್ಥಿರ ಅಕ್ಷರ hostname[NI_MAXHOST];

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
/* moduli.c */
ಪೂರ್ಣಾಂಕ gen_candidates(FILE *, uint32_t, BIGNUM *);
ಪೂರ್ಣಾಂಕ ಅವಿಭಾಜ್ಯ_test(FILE *, FILE *, uint32_t, uint32_t, ಅಕ್ಷರ *, ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ,
    ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ);
#ಆದರೆ_ಅಂತ್ಯ

ಸ್ಥಿರ ಶೂನ್ಯ
type_ಬಿಟ್ಟುಗಳು_valid(ಪೂರ್ಣಾಂಕ type, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name, uint32_t *bitsp)
{
	ಆದರೆ (type == ಕೀಲಿ_UNSPEC)
		fatal("unknown key type %s", ಕೀಲಿ_type_name);
	ಆದರೆ (*bitsp == 0) {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
		ಪೂರ್ಣಾಂಕ nid;

		ಆಯ್ಕೆ(type) {
		ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA:
			ಆದರೆ (name != ಖಾಲಿ &&
			    (nid = sshkey_ecdsa_nid_from_name(name)) > 0)
				*bitsp = sshkey_ವಕ್ರ_nid_ಗಮ್ಯ_ಬಿಟ್ಟುಗಳು(nid);
			ಆದರೆ (*bitsp == 0)
				*bitsp = DEFAULT_ಬಿಟ್ಟುಗಳು_ECDSA;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ ಕೀಲಿ_RSA:
			*bitsp = DEFAULT_ಬಿಟ್ಟುಗಳು;
			ನಿಲ್ಲಿಸು;
		}
#ಆದರೆ_ಅಂತ್ಯ
	}
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	ಆಯ್ಕೆ (type) {
	ಸ್ಥಿತಿ ಕೀಲಿ_RSA:
		ಆದರೆ (*bitsp < SSH_RSA_MINIMUM_MODULUS_ಗಾತ್ರ)
			fatal("Invalid RSA key length: minimum is %d bits",
			    SSH_RSA_MINIMUM_MODULUS_ಗಾತ್ರ);
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (*bitsp > OPENSSL_RSA_MAX_MODULUS_ಬಿಟ್ಟುಗಳು)
			fatal("Invalid RSA key length: maximum is %d bits",
			    OPENSSL_RSA_MAX_MODULUS_ಬಿಟ್ಟುಗಳು);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA:
		ಆದರೆ (sshkey_ecdsa_ಬಿಟ್ಟುಗಳು_ಗಮ್ಯ_nid(*bitsp) == -1)
			fatal("Invalid ECDSA key length: valid lengths are "
			    "256, 384 or 521 bits");
	}
#ಆದರೆ_ಅಂತ್ಯ
}

/*
 * Checks whether a file exists and, if so, asks the user whether they wish
 * to overwrite it.
 * Returns nonzero if the file does not already exist or if the user agrees to
 * overwrite, or zero otherwise.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
confirm_overwrite(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename)
{
	ಅಕ್ಷರ yesno[3];
	ರಚನೆ stat st;

	ಆದರೆ (stat(filename, &st) != 0)
		ಹಿಂತಿರುಗಿ 1;
	ಬರೆ("%s already exists.\n", filename);
	ಬರೆ("Overwrite (y/n)? ");
	fflush(stdout);
	ಆದರೆ (fgets(yesno, ಗಾತ್ರ(yesno), stdin) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (yesno[0] != 'y' && yesno[0] != 'Y')
		ಹಿಂತಿರುಗಿ 0;
	ಹಿಂತಿರುಗಿ 1;
}

ಸ್ಥಿರ ಶೂನ್ಯ
ask_filename(ರಚನೆ passwd *pw, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *prompt)
{
	ಅಕ್ಷರ buf[1024];
	ಅಕ್ಷರ *name = ಖಾಲಿ;

	ಆದರೆ (ಕೀಲಿ_type_name == ಖಾಲಿ)
		name = ಮಾರ್ಗ_SSH_CLIENT_ID_ED25519;
	ಇಲ್ಲದಿದ್ದರೆ {
		ಆಯ್ಕೆ (sshkey_type_from_shortname(ಕೀಲಿ_type_name)) {
		ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA_CERT:
		ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA:
			name = ಮಾರ್ಗ_SSH_CLIENT_ID_ECDSA;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA_SK_CERT:
		ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA_SK:
			name = ಮಾರ್ಗ_SSH_CLIENT_ID_ECDSA_SK;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ ಕೀಲಿ_RSA_CERT:
		ಸ್ಥಿತಿ ಕೀಲಿ_RSA:
			name = ಮಾರ್ಗ_SSH_CLIENT_ID_RSA;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ ಕೀಲಿ_ED25519:
		ಸ್ಥಿತಿ ಕೀಲಿ_ED25519_CERT:
			name = ಮಾರ್ಗ_SSH_CLIENT_ID_ED25519;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ ಕೀಲಿ_ED25519_SK:
		ಸ್ಥಿತಿ ಕೀಲಿ_ED25519_SK_CERT:
			name = ಮಾರ್ಗ_SSH_CLIENT_ID_ED25519_SK;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ ಕೀಲಿ_MLDSA44_ED25519:
		ಸ್ಥಿತಿ ಕೀಲಿ_MLDSA44_ED25519_CERT:
			name = ಮಾರ್ಗ_SSH_CLIENT_ID_MLDSA44_ED25519;
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			fatal("bad key type");
		}
	}
	snprintf(ತಟಸ್ಥ_file, ಗಾತ್ರ(ತಟಸ್ಥ_file),
	    "%s/%s", pw->pw_dir, name);
	ಬರೆ("%s (%s): ", prompt, ತಟಸ್ಥ_file);
	fflush(stdout);
	ಆದರೆ (fgets(buf, ಗಾತ್ರ(buf), stdin) == ಖಾಲಿ)
		ನಿರ್ಗಮಿಸು(1);
	buf[strcspn(buf, "\n")] = '\0';
	ಆದರೆ (strcmp(buf, "") != 0)
		strlcpy(ತಟಸ್ಥ_file, buf, ಗಾತ್ರ(ತಟಸ್ಥ_file));
	have_ತಟಸ್ಥ = 1;
}

ಸ್ಥಿರ ರಚನೆ sshkey *
ತುಂಬು_ತಟಸ್ಥ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename, ಅಕ್ಷರ **commentp)
{
	ಅಕ್ಷರ *prompt, *pass;
	ರಚನೆ sshkey *prv;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (commentp != ಖಾಲಿ)
		*commentp = ಖಾಲಿ;
	ಆದರೆ ((r = sshkey_ತುಂಬು_ಖಾಸಗಿ(filename, "", &prv, commentp)) == 0)
		ಹಿಂತಿರುಗಿ prv;
	ಆದರೆ (r != SSH_ERR_ಕೀಲಿ_WRONG_PASSPHRASE)
		fatal_r(r, "Load key \"%s\"", filename);
	ಆದರೆ (ತಟಸ್ಥ_passphrase)
		pass = xstrdup(ತಟಸ್ಥ_passphrase);
	ಇಲ್ಲದಿದ್ದರೆ {
		xasprintf(&prompt, "Enter passphrase for \"%s\": ", filename);
		pass = read_passphrase(prompt, RP_ALLOW_STDIN);
		ಬಿಡುಗಡೆ(prompt);
	}
	r = sshkey_ತುಂಬು_ಖಾಸಗಿ(filename, pass, &prv, commentp);
	freezero(pass, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(pass));
	ಆದರೆ (r != 0)
		fatal_r(r, "Load key \"%s\"", filename);
	ಹಿಂತಿರುಗಿ prv;
}

#ವ್ಯಾಖ್ಯಾನಿಸು SSH_COM_ಬಹಿರಂಗ_BEGIN		"---- BEGIN SSH2 PUBLIC KEY ----"
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_COM_ಬಹಿರಂಗ_ಕೊನೆ		"---- END SSH2 PUBLIC KEY ----"
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_COM_ಖಾಸಗಿ_BEGIN		"---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----"
#ವ್ಯಾಖ್ಯಾನಿಸು	SSH_COM_ಖಾಸಗಿ_ಕೀಲಿ_MAGIC	0x3f6ff9eb

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
ಸ್ಥಿರ ಶೂನ್ಯ
do_convert_ಗಮ್ಯ_ssh2(ರಚನೆ passwd *pw, ರಚನೆ sshkey *k)
{
	ರಚನೆ sshbuf *b;
	ಅಕ್ಷರ comment[61], *b64;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((b = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = sshkey_putb(k, b)) != 0)
		fatal_fr(r, "put key");
	ಆದರೆ ((b64 = sshbuf_dtob64_string(b, 1)) == ಖಾಲಿ)
		fatal_f("sshbuf_dtob64_string failed");

	/* Comment + surrounds must fit into 72 chars (RFC 4716 sec 3.3) */
	snprintf(comment, ಗಾತ್ರ(comment),
	    "%u-bit %s, converted by %s@%s from OpenSSH",
	    sshkey_ಗಾತ್ರ(k), sshkey_type(k),
	    pw->pw_name, hostname);

	sshkey_free(k);
	sshbuf_free(b);

	fprintf(stdout, "%s\n", SSH_COM_ಬಹಿರಂಗ_BEGIN);
	fprintf(stdout, "Comment: \"%s\"\n%s", comment, b64);
	fprintf(stdout, "%s\n", SSH_COM_ಬಹಿರಂಗ_ಕೊನೆ);
	ಬಿಡುಗಡೆ(b64);
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_convert_ಗಮ್ಯ_pkcs8(ರಚನೆ sshkey *k)
{
	ಆಯ್ಕೆ (sshkey_type_plain(k->type)) {
	ಸ್ಥಿತಿ ಕೀಲಿ_RSA:
		ಆದರೆ (!PEM_write_RSA_PUBKEY(stdout,
		    EVP_PKEY_get0_RSA(k->pkey)))
			fatal("PEM_write_RSA_PUBKEY failed");
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA:
		ಆದರೆ (!PEM_write_EC_PUBKEY(stdout,
		    EVP_PKEY_get0_EC_ಕೀಲಿ(k->pkey)))
			fatal("PEM_write_EC_PUBKEY failed");
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		fatal_f("unsupported key type %s", sshkey_type(k));
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_convert_ಗಮ್ಯ_pem(ರಚನೆ sshkey *k)
{
	ಆಯ್ಕೆ (sshkey_type_plain(k->type)) {
	ಸ್ಥಿತಿ ಕೀಲಿ_RSA:
		ಆದರೆ (!PEM_write_RSAPublic_ಕೀಲಿ(stdout,
		    EVP_PKEY_get0_RSA(k->pkey)))
			fatal("PEM_write_RSAPublicKey failed");
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA:
		ಆದರೆ (!PEM_write_EC_PUBKEY(stdout,
		    EVP_PKEY_get0_EC_ಕೀಲಿ(k->pkey)))
			fatal("PEM_write_EC_PUBKEY failed");
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		fatal_f("unsupported key type %s", sshkey_type(k));
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_convert_ಗಮ್ಯ_hexdump(ರಚನೆ sshkey *k)
{
	ರಚನೆ sshbuf *b;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((b = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	/* pubkey */
	ಆದರೆ ((r = sshkey_putb(k, b)) != 0)
		fatal_fr(r, "serialise private");
	ಬರೆ("Public %s key:\n", sshkey_type(k));
	sshbuf_dump(b, stdout);
	sshbuf_reset(b);
	ಆದರೆ ((r = sshkey_ಖಾಸಗಿ_serialize(k, b)) != 0) {
		debug_fr(r, "serialise private");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಬರೆ("\nPrivate %s key:\n", sshkey_type(k));
	sshbuf_dump(b, stdout);
 ಹೊರಹೋಗು:
	sshbuf_free(b);
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_convert_ಗಮ್ಯ(ರಚನೆ passwd *pw)
{
	ರಚನೆ sshkey *k = ಖಾಲಿ;
	ರಚನೆ stat st;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (!have_ತಟಸ್ಥ)
		ask_filename(pw, "Enter file in which the key is");
	ಆದರೆ (stat(ತಟಸ್ಥ_file, &st) == -1)
		fatal("%s: %s: %s", __progname, ತಟಸ್ಥ_file, strerror(errno));

	/* If we're trying to hexdump, then prefer the private key */
	ಆದರೆ (convert_format == FMT_HEXDUMP) {
		ಆದರೆ ((r = sshkey_ತುಂಬು_ಖಾಸಗಿ(ತಟಸ್ಥ_file,
		    ಖಾಲಿ, &k, ಖಾಲಿ)) != 0 &&
		    r == SSH_ERR_ಕೀಲಿ_WRONG_PASSPHRASE)
			k = ತುಂಬು_ತಟಸ್ಥ(ತಟಸ್ಥ_file, ಖಾಲಿ);
	}
	ಆದರೆ (k == ಖಾಲಿ && (r = sshkey_ತುಂಬು_ಬಹಿರಂಗ(ತಟಸ್ಥ_file, &k, ಖಾಲಿ)) != 0)
		k = ತುಂಬು_ತಟಸ್ಥ(ತಟಸ್ಥ_file, ಖಾಲಿ);

	ಆಯ್ಕೆ (convert_format) {
	ಸ್ಥಿತಿ FMT_RFC4716:
		do_convert_ಗಮ್ಯ_ssh2(pw, k);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ FMT_PKCS8:
		do_convert_ಗಮ್ಯ_pkcs8(k);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ FMT_PEM:
		do_convert_ಗಮ್ಯ_pem(k);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ FMT_HEXDUMP:
		do_convert_ಗಮ್ಯ_hexdump(k);
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		fatal_f("unknown key format %d", convert_format);
	}
}

/*
 * This is almost exactly the bignum1 encoding, but with 32 bit for length
 * instead of 16.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
ಬಫರ್_get_bignum_ಬಿಟ್ಟುಗಳು(ರಚನೆ sshbuf *b, BIGNUM *ಮೌಲ್ಯ)
{
	u_int ಬೈಟುಗಳು, bignum_ಬಿಟ್ಟುಗಳು;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshbuf_get_u32(b, &bignum_ಬಿಟ್ಟುಗಳು)) != 0)
		fatal_fr(r, "parse");
	ಬೈಟುಗಳು = (bignum_ಬಿಟ್ಟುಗಳು + 7) / 8;
	ಆದರೆ (sshbuf_len(b) < ಬೈಟುಗಳು)
		fatal_f("input buffer too small: need %d have %zu",
		    ಬೈಟುಗಳು, sshbuf_len(b));
	ಆದರೆ (BN_bin2bn(sshbuf_ptr(b), ಬೈಟುಗಳು, ಮೌಲ್ಯ) == ಖಾಲಿ)
		fatal_f("BN_bin2bn failed");
	ಆದರೆ ((r = sshbuf_consume(b, ಬೈಟುಗಳು)) != 0)
		fatal_fr(r, "consume");
}

ಸ್ಥಿರ ರಚನೆ sshkey *
do_convert_ಖಾಸಗಿ_ssh2(ರಚನೆ sshbuf *b)
{
	ರಚನೆ sshkey *ಕೀಲಿ = ಖಾಲಿ;
	ಅಕ್ಷರ *type, *cipher;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *alg = ಖಾಲಿ;
	u_char e1, e2, e3, *sig = ಖಾಲಿ, ದತ್ತಾಂಶ[] = "abcde12345";
	ಪೂರ್ಣಾಂಕ r, rlen, ktype;
	u_int magic, i1, i2, i3, i4;
	ಗಾತ್ರ_t slen;
	u_long e;
	BIGNUM *rsa_n = ಖಾಲಿ, *rsa_e = ಖಾಲಿ, *rsa_d = ಖಾಲಿ;
	BIGNUM *rsa_p = ಖಾಲಿ, *rsa_q = ಖಾಲಿ, *rsa_iqmp = ಖಾಲಿ;
	BIGNUM *rsa_dmp1 = ಖಾಲಿ, *rsa_dmq1 = ಖಾಲಿ;
	RSA *rsa = ಖಾಲಿ;

	ಆದರೆ ((r = sshbuf_get_u32(b, &magic)) != 0)
		fatal_fr(r, "parse magic");

	ಆದರೆ (magic != SSH_COM_ಖಾಸಗಿ_ಕೀಲಿ_MAGIC) {
		error("bad magic 0x%x != 0x%x", magic,
		    SSH_COM_ಖಾಸಗಿ_ಕೀಲಿ_MAGIC);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಆದರೆ ((r = sshbuf_get_u32(b, &i1)) != 0 ||
	    (r = sshbuf_get_cstring(b, &type, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_cstring(b, &cipher, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_u32(b, &i2)) != 0 ||
	    (r = sshbuf_get_u32(b, &i3)) != 0 ||
	    (r = sshbuf_get_u32(b, &i4)) != 0)
		fatal_fr(r, "parse");
	debug("ignore (%d %d %d %d)", i1, i2, i3, i4);
	ಆದರೆ (strcmp(cipher, "none") != 0) {
		error("unsupported cipher %s", cipher);
		ಬಿಡುಗಡೆ(cipher);
		ಬಿಡುಗಡೆ(type);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಬಿಡುಗಡೆ(cipher);

	ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹುಡುಕು(type, "rsa")) {
		ktype = ಕೀಲಿ_RSA;
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಬಿಡುಗಡೆ(type);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಆದರೆ ((ಕೀಲಿ = sshkey_new(ktype)) == ಖಾಲಿ)
		fatal("sshkey_new failed");
	ಬಿಡುಗಡೆ(type);

	ಆಯ್ಕೆ (ಕೀಲಿ->type) {
	ಸ್ಥಿತಿ ಕೀಲಿ_RSA:
		ಆದರೆ ((r = sshbuf_get_u8(b, &e1)) != 0 ||
		    (e1 < 30 && (r = sshbuf_get_u8(b, &e2)) != 0) ||
		    (e1 < 30 && (r = sshbuf_get_u8(b, &e3)) != 0))
			fatal_fr(r, "parse RSA");
		e = e1;
		debug("e %lx", e);
		ಆದರೆ (e < 30) {
			e <<= 8;
			e += e2;
			debug("e %lx", e);
			e <<= 8;
			e += e3;
			debug("e %lx", e);
		}
		ಆದರೆ ((rsa_e = BN_new()) == ಖಾಲಿ)
			fatal_f("BN_new");
		ಆದರೆ (!BN_ಗಣ_ಶಬ್ದ(rsa_e, e)) {
			BN_clear_free(rsa_e);
			sshkey_free(ಕೀಲಿ);
			ಹಿಂತಿರುಗಿ ಖಾಲಿ;
		}
		ಆದರೆ ((rsa_n = BN_new()) == ಖಾಲಿ ||
		    (rsa_d = BN_new()) == ಖಾಲಿ ||
		    (rsa_p = BN_new()) == ಖಾಲಿ ||
		    (rsa_q = BN_new()) == ಖಾಲಿ ||
		    (rsa_iqmp = BN_new()) == ಖಾಲಿ)
			fatal_f("BN_new");
		ಬಫರ್_get_bignum_ಬಿಟ್ಟುಗಳು(b, rsa_d);
		ಬಫರ್_get_bignum_ಬಿಟ್ಟುಗಳು(b, rsa_n);
		ಬಫರ್_get_bignum_ಬಿಟ್ಟುಗಳು(b, rsa_iqmp);
		ಬಫರ್_get_bignum_ಬಿಟ್ಟುಗಳು(b, rsa_q);
		ಬಫರ್_get_bignum_ಬಿಟ್ಟುಗಳು(b, rsa_p);
		ಆದರೆ ((r = ssh_rsa_complete_crt_parameters(rsa_d, rsa_p, rsa_q,
		    rsa_iqmp, &rsa_dmp1, &rsa_dmq1)) != 0)
			fatal_fr(r, "generate RSA CRT parameters");
		EVP_PKEY_free(ಕೀಲಿ->pkey);
		ಆದರೆ ((ಕೀಲಿ->pkey = EVP_PKEY_new()) == ಖಾಲಿ)
			fatal_f("EVP_PKEY_new failed");
		ಆದರೆ ((rsa = RSA_new()) == ಖಾಲಿ)
			fatal_f("RSA_new failed");
		ಆದರೆ (!RSA_set0_ಕೀಲಿ(rsa, rsa_n, rsa_e, rsa_d))
			fatal_f("RSA_set0_key failed");
		rsa_n = rsa_e = rsa_d = ಖಾಲಿ; /* transferred */
		ಆದರೆ (!RSA_set0_factors(rsa, rsa_p, rsa_q))
			fatal_f("RSA_set0_factors failed");
		rsa_p = rsa_q = ಖಾಲಿ; /* transferred */
		ಆದರೆ (RSA_set0_crt_params(rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp) != 1)
			fatal_f("RSA_set0_crt_params failed");
		rsa_dmp1 = rsa_dmq1 = rsa_iqmp = ಖಾಲಿ;
		ಆದರೆ (EVP_PKEY_set1_RSA(ಕೀಲಿ->pkey, rsa) != 1)
			fatal_f("EVP_PKEY_set1_RSA failed");
		RSA_free(rsa);
		alg = "rsa-sha2-256";
		ನಿಲ್ಲಿಸು;
	}
	rlen = sshbuf_len(b);
	ಆದರೆ (rlen != 0)
		error_f("remaining bytes in key blob %d", rlen);

	/* try the key */
	ಆದರೆ ((r = sshkey_sign(ಕೀಲಿ, &sig, &slen, ದತ್ತಾಂಶ, ಗಾತ್ರ(ದತ್ತಾಂಶ),
	    alg, ಖಾಲಿ, ಖಾಲಿ, 0)) != 0)
		error_fr(r, "signing with converted key failed");
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((r = sshkey_verify(ಕೀಲಿ, sig, slen, ದತ್ತಾಂಶ, ಗಾತ್ರ(ದತ್ತಾಂಶ),
	    alg, 0, ಖಾಲಿ)) != 0)
		error_fr(r, "verification with converted key failed");
	ಆದರೆ (r != 0) {
		sshkey_free(ಕೀಲಿ);
		ಬಿಡುಗಡೆ(sig);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಬಿಡುಗಡೆ(sig);
	ಹಿಂತಿರುಗಿ ಕೀಲಿ;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
get_ಸಾಲು(FILE *fp, ಅಕ್ಷರ *ಸಾಲು, ಗಾತ್ರ_t len)
{
	ಪೂರ್ಣಾಂಕ c;
	ಗಾತ್ರ_t pos = 0;

	ಸಾಲು[0] = '\0';
	ಆಗ ((c = fgetc(fp)) != EOF) {
		ಆದರೆ (pos >= len - 1)
			fatal("input line too long.");
		ಆಯ್ಕೆ (c) {
		ಸ್ಥಿತಿ '\r':
			c = fgetc(fp);
			ಆದರೆ (c != EOF && c != '\n' && ungetc(c, fp) == EOF)
				fatal("unget: %s", strerror(errno));
			ಹಿಂತಿರುಗಿ pos;
		ಸ್ಥಿತಿ '\n':
			ಹಿಂತಿರುಗಿ pos;
		}
		ಸಾಲು[pos++] = c;
		ಸಾಲು[pos] = '\0';
	}
	/* We reached EOF */
	ಹಿಂತಿರುಗಿ -1;
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_convert_from_ssh2(ರಚನೆ passwd *pw, ರಚನೆ sshkey **k, ಪೂರ್ಣಾಂಕ *ಖಾಸಗಿ)
{
	ಪೂರ್ಣಾಂಕ r, blen, escaped = 0;
	u_int len;
	ಅಕ್ಷರ ಸಾಲು[1024];
	ರಚನೆ sshbuf *buf;
	ಅಕ್ಷರ encoded[8096];
	FILE *fp;

	ಆದರೆ ((buf = sshbuf_new()) == ಖಾಲಿ)
		fatal("sshbuf_new failed");
	ಆದರೆ ((fp = fopen(ತಟಸ್ಥ_file, "r")) == ಖಾಲಿ)
		fatal("%s: %s: %s", __progname, ತಟಸ್ಥ_file, strerror(errno));
	encoded[0] = '\0';
	ಆಗ ((blen = get_ಸಾಲು(fp, ಸಾಲು, ಗಾತ್ರ(ಸಾಲು))) != -1) {
		ಆದರೆ (blen > 0 && ಸಾಲು[blen - 1] == '\\')
			escaped++;
		ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(ಸಾಲು, "----", 4) == 0 ||
		    ಅಕ್ಷರಸರಣಿ_ಹುಡುಕು(ಸಾಲು, ": ") != ಖಾಲಿ) {
			ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹುಡುಕು(ಸಾಲು, SSH_COM_ಖಾಸಗಿ_BEGIN) != ಖಾಲಿ)
				*ಖಾಸಗಿ = 1;
			ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹುಡುಕು(ಸಾಲು, " END ") != ಖಾಲಿ) {
				ನಿಲ್ಲಿಸು;
			}
			/* fprintf(stderr, "ignore: %s", line); */
			ಮುಂದುವರಿ;
		}
		ಆದರೆ (escaped) {
			escaped--;
			/* fprintf(stderr, "escaped: %s", line); */
			ಮುಂದುವರಿ;
		}
		strlcat(encoded, ಸಾಲು, ಗಾತ್ರ(encoded));
	}
	len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(encoded);
	ಆದರೆ (((len % 4) == 3) &&
	    (encoded[len-1] == '=') &&
	    (encoded[len-2] == '=') &&
	    (encoded[len-3] == '='))
		encoded[len-3] = '\0';
	ಆದರೆ ((r = sshbuf_b64tod(buf, encoded)) != 0)
		fatal_fr(r, "base64 decode");
	ಆದರೆ (*ಖಾಸಗಿ) {
		ಆದರೆ ((*k = do_convert_ಖಾಸಗಿ_ssh2(buf)) == ಖಾಲಿ)
			fatal_f("private key conversion failed");
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((r = sshkey_fromb(buf, k)) != 0)
		fatal_fr(r, "parse key");
	sshbuf_free(buf);
	fclose(fp);
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_convert_from_pkcs8(ರಚನೆ sshkey **k, ಪೂರ್ಣಾಂಕ *ಖಾಸಗಿ)
{
	EVP_PKEY *pubkey;
	FILE *fp;

	ಆದರೆ ((fp = fopen(ತಟಸ್ಥ_file, "r")) == ಖಾಲಿ)
		fatal("%s: %s: %s", __progname, ತಟಸ್ಥ_file, strerror(errno));
	ಆದರೆ ((pubkey = PEM_read_PUBKEY(fp, ಖಾಲಿ, ಖಾಲಿ, ಖಾಲಿ)) == ಖಾಲಿ) {
		fatal_f("%s is not a recognised public key format",
		    ತಟಸ್ಥ_file);
	}
	fclose(fp);
	ಆಯ್ಕೆ (EVP_PKEY_ತಳ_id(pubkey)) {
	ಸ್ಥಿತಿ EVP_PKEY_RSA:
		ಆದರೆ ((*k = sshkey_new(ಕೀಲಿ_UNSPEC)) == ಖಾಲಿ)
			fatal("sshkey_new failed");
		(*k)->type = ಕೀಲಿ_RSA;
		(*k)->pkey = pubkey;
		pubkey = ಖಾಲಿ;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ EVP_PKEY_EC:
		ಆದರೆ ((*k = sshkey_new(ಕೀಲಿ_UNSPEC)) == ಖಾಲಿ)
			fatal("sshkey_new failed");
		ಆದರೆ (((*k)->ecdsa_nid = sshkey_ecdsa_fixup_ಗುಂಪು(pubkey)) == -1)
			fatal("sshkey_ecdsa_fixup_group failed");
		(*k)->type = ಕೀಲಿ_ECDSA;
		(*k)->pkey = pubkey;
		pubkey = ಖಾಲಿ;
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		fatal_f("unsupported pubkey type %d",
		    EVP_PKEY_ತಳ_id(pubkey));
	}
	EVP_PKEY_free(pubkey);
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_convert_from_pem(ರಚನೆ sshkey **k, ಪೂರ್ಣಾಂಕ *ಖಾಸಗಿ)
{
	FILE *fp;
	RSA *rsa;

	ಆದರೆ ((fp = fopen(ತಟಸ್ಥ_file, "r")) == ಖಾಲಿ)
		fatal("%s: %s: %s", __progname, ತಟಸ್ಥ_file, strerror(errno));
	ಆದರೆ ((rsa = PEM_read_RSAPublic_ಕೀಲಿ(fp, ಖಾಲಿ, ಖಾಲಿ, ಖಾಲಿ)) != ಖಾಲಿ) {
		ಆದರೆ ((*k = sshkey_new(ಕೀಲಿ_UNSPEC)) == ಖಾಲಿ)
			fatal("sshkey_new failed");
		ಆದರೆ (((*k)->pkey = EVP_PKEY_new()) == ಖಾಲಿ)
			fatal("EVP_PKEY_new failed");
		(*k)->type = ಕೀಲಿ_RSA;
		ಆದರೆ (EVP_PKEY_set1_RSA((*k)->pkey, rsa) != 1)
			fatal("EVP_PKEY_set1_RSA failed");
		RSA_free(rsa);
		fclose(fp);
		ಹಿಂತಿರುಗಿ;
	}
	fatal_f("unrecognised raw private key format");
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_convert_from(ರಚನೆ passwd *pw)
{
	ರಚನೆ sshkey *k = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r, ಖಾಸಗಿ = 0, ok = 0;
	ರಚನೆ stat st;

	ಆದರೆ (!have_ತಟಸ್ಥ)
		ask_filename(pw, "Enter file in which the key is");
	ಆದರೆ (stat(ತಟಸ್ಥ_file, &st) == -1)
		fatal("%s: %s: %s", __progname, ತಟಸ್ಥ_file, strerror(errno));

	ಆಯ್ಕೆ (convert_format) {
	ಸ್ಥಿತಿ FMT_RFC4716:
		do_convert_from_ssh2(pw, &k, &ಖಾಸಗಿ);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ FMT_PKCS8:
		do_convert_from_pkcs8(&k, &ಖಾಸಗಿ);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ FMT_PEM:
		do_convert_from_pem(&k, &ಖಾಸಗಿ);
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		fatal_f("unknown key format %d", convert_format);
	}

	ಆದರೆ (!ಖಾಸಗಿ) {
		ಆದರೆ ((r = sshkey_write(k, stdout)) == 0)
			ok = 1;
		ಆದರೆ (ok)
			fprintf(stdout, "\n");
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆಯ್ಕೆ (k->type) {
		ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA:
			ok = PEM_write_ECPrivate_ಕೀಲಿ(stdout,
			    EVP_PKEY_get0_EC_ಕೀಲಿ(k->pkey), ಖಾಲಿ, ಖಾಲಿ, 0,
			    ಖಾಲಿ, ಖಾಲಿ);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ ಕೀಲಿ_RSA:
			ok = PEM_write_RSAPrivate_ಕೀಲಿ(stdout,
			    EVP_PKEY_get0_RSA(k->pkey), ಖಾಲಿ, ಖಾಲಿ, 0,
			    ಖಾಲಿ, ಖಾಲಿ);
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			fatal_f("unsupported key type %s", sshkey_type(k));
		}
	}

	ಆದರೆ (!ok)
		fatal("key write failed");
	sshkey_free(k);
}
#ಆದರೆ_ಅಂತ್ಯ

ಸ್ಥಿರ ಶೂನ್ಯ
do_print_ಬಹಿರಂಗ(ರಚನೆ passwd *pw)
{
	ರಚನೆ sshkey *prv;
	ರಚನೆ stat st;
	ಪೂರ್ಣಾಂಕ r;
	ಅಕ್ಷರ *comment = ಖಾಲಿ;

	ಆದರೆ (!have_ತಟಸ್ಥ)
		ask_filename(pw, "Enter file in which the key is");
	ಆದರೆ (stat(ತಟಸ್ಥ_file, &st) == -1)
		fatal("%s: %s", ತಟಸ್ಥ_file, strerror(errno));
	prv = ತುಂಬು_ತಟಸ್ಥ(ತಟಸ್ಥ_file, &comment);
	ಆದರೆ ((r = sshkey_write(prv, stdout)) != 0)
		fatal_fr(r, "write key");
	ಆದರೆ (comment != ಖಾಲಿ && *comment != '\0')
		fprintf(stdout, " %s", comment);
	fprintf(stdout, "\n");
	ಆದರೆ (sshkey_is_sk(prv)) {
		debug("sk_application: \"%s\", sk_flags 0x%02x",
			prv->sk_application, prv->sk_flags);
	}
	sshkey_free(prv);
	ಬಿಡುಗಡೆ(comment);
	ನಿರ್ಗಮಿಸು(0);
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_download(ರಚನೆ passwd *pw)
{
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ ENABLE_PKCS11
	ರಚನೆ sshkey **ಕೀಲಿಗಳು = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ i, nkeys;
	ಎಣಿಕೆ sshkey_fp_rep rep;
	ಪೂರ್ಣಾಂಕ fptype;
	ಅಕ್ಷರ *fp, *ra, **comments = ಖಾಲಿ;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;

	pkcs11_init(1);
	nkeys = pkcs11_ಕೂಡಿಸು_provider(pkcs11provider, ಖಾಲಿ, &ಕೀಲಿಗಳು, &comments);
	ಆದರೆ (nkeys <= 0)
		fatal("cannot read public key from pkcs11");
	ಗಾಗಿ (i = 0; i < nkeys; i++) {
		ಆದರೆ (print_fingerprint) {
			fp = sshkey_fingerprint(ಕೀಲಿಗಳು[i], fptype, rep);
			ra = sshkey_fingerprint(ಕೀಲಿಗಳು[i], fingerprint_hash,
			    SSH_FP_RANDOMART);
			ಆದರೆ (fp == ಖಾಲಿ || ra == ಖಾಲಿ)
				fatal_f("sshkey_fingerprint fail");
			ಬರೆ("%u %s %s (PKCS11 key)\n", sshkey_ಗಾತ್ರ(ಕೀಲಿಗಳು[i]),
			    fp, sshkey_type(ಕೀಲಿಗಳು[i]));
			ಆದರೆ (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
				ಬರೆ("%s\n", ra);
			ಬಿಡುಗಡೆ(ra);
			ಬಿಡುಗಡೆ(fp);
		} ಇಲ್ಲದಿದ್ದರೆ {
			(ಶೂನ್ಯ) sshkey_write(ಕೀಲಿಗಳು[i], stdout); /* XXX check */
			fprintf(stdout, "%s%s\n",
			    *(comments[i]) == '\0' ? "" : " ", comments[i]);
		}
		ಬಿಡುಗಡೆ(comments[i]);
		sshkey_free(ಕೀಲಿಗಳು[i]);
	}
	ಬಿಡುಗಡೆ(comments);
	ಬಿಡುಗಡೆ(ಕೀಲಿಗಳು);
	pkcs11_terminate();
	ನಿರ್ಗಮಿಸು(0);
#ಇಲ್ಲದಿದ್ದರೆ
	fatal("no pkcs11 support");
#ಆದರೆ_ಅಂತ್ಯ /* ENABLE_PKCS11 */
}

ಸ್ಥಿರ ರಚನೆ sshkey *
try_read_ಕೀಲಿ(ಅಕ್ಷರ **cpp)
{
	ರಚನೆ sshkey *ret;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((ret = sshkey_new(ಕೀಲಿ_UNSPEC)) == ಖಾಲಿ)
		fatal("sshkey_new failed");
	ಆದರೆ ((r = sshkey_read(ret, cpp)) == 0)
		ಹಿಂತಿರುಗಿ ret;
	/* Not a key */
	sshkey_free(ret);
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

ಸ್ಥಿರ ಶೂನ್ಯ
fingerprint_one_ಕೀಲಿ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಸಾರ್ವಜನಿಕ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *comment)
{
	ಅಕ್ಷರ *fp = ಖಾಲಿ, *ra = ಖಾಲಿ;
	ಎಣಿಕೆ sshkey_fp_rep rep;
	ಪೂರ್ಣಾಂಕ fptype;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;
	fp = sshkey_fingerprint(ಸಾರ್ವಜನಿಕ, fptype, rep);
	ra = sshkey_fingerprint(ಸಾರ್ವಜನಿಕ, fingerprint_hash, SSH_FP_RANDOMART);
	ಆದರೆ (fp == ಖಾಲಿ || ra == ಖಾಲಿ)
		fatal_f("sshkey_fingerprint failed");
	mprintf("%u %s %s (%s)\n", sshkey_ಗಾತ್ರ(ಸಾರ್ವಜನಿಕ), fp,
	    comment ? comment : "no comment", sshkey_type(ಸಾರ್ವಜನಿಕ));
	ಆದರೆ (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
		ಬರೆ("%s\n", ra);
	ಬಿಡುಗಡೆ(ra);
	ಬಿಡುಗಡೆ(fp);
}

ಸ್ಥಿರ ಶೂನ್ಯ
fingerprint_ಖಾಸಗಿ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ)
{
	ರಚನೆ stat st;
	ಅಕ್ಷರ *comment = ಖಾಲಿ;
	ರಚನೆ sshkey *privkey = ಖಾಲಿ, *pubkey = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (stat(ತಟಸ್ಥ_file, &st) == -1)
		fatal("%s: %s", ಮಾರ್ಗ, strerror(errno));
	ಆದರೆ ((r = sshkey_ತುಂಬು_ಬಹಿರಂಗ(ಮಾರ್ಗ, &pubkey, &comment)) != 0)
		debug_r(r, "load public \"%s\"", ಮಾರ್ಗ);
	ಆದರೆ (pubkey == ಖಾಲಿ || comment == ಖಾಲಿ || *comment == '\0') {
		ಬಿಡುಗಡೆ(comment);
		ಆದರೆ ((r = sshkey_ತುಂಬು_ಖಾಸಗಿ(ಮಾರ್ಗ, ಖಾಲಿ,
		    &privkey, &comment)) != 0)
			debug_r(r, "load private \"%s\"", ಮಾರ್ಗ);
	}
	ಆದರೆ (pubkey == ಖಾಲಿ && privkey == ಖಾಲಿ)
		fatal("%s is not a key file.", ಮಾರ್ಗ);

	fingerprint_one_ಕೀಲಿ(pubkey == ಖಾಲಿ ? privkey : pubkey, comment);
	sshkey_free(pubkey);
	sshkey_free(privkey);
	ಬಿಡುಗಡೆ(comment);
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_fingerprint(ರಚನೆ passwd *pw)
{
	FILE *f;
	ರಚನೆ sshkey *ಸಾರ್ವಜನಿಕ = ಖಾಲಿ;
	ಅಕ್ಷರ *comment = ಖಾಲಿ, *cp, *ep, *ಸಾಲು = ಖಾಲಿ;
	ಗಾತ್ರ_t linesize = 0;
	ಪೂರ್ಣಾಂಕ i, invalid = 1;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ;
	u_long lnum = 0;

	ಆದರೆ (!have_ತಟಸ್ಥ)
		ask_filename(pw, "Enter file in which the key is");
	ಮಾರ್ಗ = ತಟಸ್ಥ_file;

	ಆದರೆ (strcmp(ತಟಸ್ಥ_file, "-") == 0) {
		f = stdin;
		ಮಾರ್ಗ = "(stdin)";
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((f = fopen(ಮಾರ್ಗ, "r")) == ಖಾಲಿ)
		fatal("%s: %s: %s", __progname, ಮಾರ್ಗ, strerror(errno));

	ಆಗ (getline(&ಸಾಲು, &linesize, f) != -1) {
		lnum++;
		cp = ಸಾಲು;
		cp[strcspn(cp, "\r\n")] = '\0';
		/* Trim leading space and comments */
		cp = ಸಾಲು + strspn(ಸಾಲು, " \t");
		ಆದರೆ (*cp == '#' || *cp == '\0')
			ಮುಂದುವರಿ;

		/*
		 * Input may be plain keys, private keys, authorized_keys
		 * or known_hosts.
		 */

		/*
		 * Try private keys first. Assume a key is private if
		 * "SSH PRIVATE KEY" appears on the first line and we're
		 * not reading from stdin (XXX support private keys on stdin).
		 */
		ಆದರೆ (lnum == 1 && strcmp(ತಟಸ್ಥ_file, "-") != 0 &&
		    ಅಕ್ಷರಸರಣಿ_ಹುಡುಕು(cp, "PRIVATE KEY") != ಖಾಲಿ) {
			ಬಿಡುಗಡೆ(ಸಾಲು);
			fclose(f);
			fingerprint_ಖಾಸಗಿ(ಮಾರ್ಗ);
			ನಿರ್ಗಮಿಸು(0);
		}

		/*
		 * If it's not a private key, then this must be prepared to
		 * accept a public key prefixed with a hostname or options.
		 * Try a bare key first, otherwise skip the leading stuff.
		 */
		comment = ಖಾಲಿ;
		ಆದರೆ ((ಸಾರ್ವಜನಿಕ = try_read_ಕೀಲಿ(&cp)) == ಖಾಲಿ) {
			i = strtol(cp, &ep, 10);
			ಆದರೆ (i == 0 || ep == ಖಾಲಿ ||
			    (*ep != ' ' && *ep != '\t')) {
				ಪೂರ್ಣಾಂಕ quoted = 0;

				comment = cp;
				ಗಾಗಿ (; *cp && (quoted || (*cp != ' ' &&
				    *cp != '\t')); cp++) {
					ಆದರೆ (*cp == '\\' && cp[1] == '"')
						cp++;	/* Skip both */
					ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (*cp == '"')
						quoted = !quoted;
				}
				ಆದರೆ (!*cp)
					ಮುಂದುವರಿ;
				*cp++ = '\0';
			}
		}
		/* Retry after parsing leading hostname/key options */
		ಆದರೆ (ಸಾರ್ವಜನಿಕ == ಖಾಲಿ && (ಸಾರ್ವಜನಿಕ = try_read_ಕೀಲಿ(&cp)) == ಖಾಲಿ) {
			debug("%s:%lu: not a public key", ಮಾರ್ಗ, lnum);
			ಮುಂದುವರಿ;
		}

		/* Find trailing comment, if any */
		ಗಾಗಿ (; *cp == ' ' || *cp == '\t'; cp++)
			;
		ಆದರೆ (*cp != '\0' && *cp != '#')
			comment = cp;

		fingerprint_one_ಕೀಲಿ(ಸಾರ್ವಜನಿಕ, comment);
		sshkey_free(ಸಾರ್ವಜನಿಕ);
		invalid = 0; /* One good key in the file is sufficient */
	}
	fclose(f);
	ಬಿಡುಗಡೆ(ಸಾಲು);

	ಆದರೆ (invalid)
		fatal("%s is not a public key file.", ಮಾರ್ಗ);
	ನಿರ್ಗಮಿಸು(0);
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_gen_all_hostkeys(ರಚನೆ passwd *pw)
{
	ರಚನೆ {
		ಅಕ್ಷರ *ಕೀಲಿ_type;
		ಅಕ್ಷರ *ಕೀಲಿ_type_display;
		ಅಕ್ಷರ *ಮಾರ್ಗ;
	} ಕೀಲಿ_types[] = {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
		{ "rsa", "RSA" ,ಮಾರ್ಗ_HOST_RSA_ಕೀಲಿ_FILE },
		{ "ecdsa", "ECDSA",ಮಾರ್ಗ_HOST_ECDSA_ಕೀಲಿ_FILE },
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
		{ "ed25519", "ED25519",ಮಾರ್ಗ_HOST_ED25519_ಕೀಲಿ_FILE },
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_MLDSA
		{ "mldsa44-ed25519", "MLDSA44-ED25519",
		     ಮಾರ್ಗ_HOST_MLDSA44_ED25519_ಕೀಲಿ_FILE },
#ಆದರೆ_ಅಂತ್ಯ
		{ ಖಾಲಿ, ಖಾಲಿ, ಖಾಲಿ }
	};

	uint32_t ಬಿಟ್ಟುಗಳು = 0;
	ಪೂರ್ಣಾಂಕ ಮೊದಲ = 0;
	ರಚನೆ stat st;
	ರಚನೆ sshkey *ಖಾಸಗಿ, *ಸಾರ್ವಜನಿಕ;
	ಅಕ್ಷರ comment[ಕೀಲಿ_COMMENT_MAX], *prv_tmp, *pub_tmp, *prv_file, *pub_file;
	ಪೂರ್ಣಾಂಕ i, type, fd, r;

	ಗಾಗಿ (i = 0; ಕೀಲಿ_types[i].ಕೀಲಿ_type; i++) {
		ಸಾರ್ವಜನಿಕ = ಖಾಸಗಿ = ಖಾಲಿ;
		prv_tmp = pub_tmp = prv_file = pub_file = ಖಾಲಿ;

		xasprintf(&prv_file, "%s%s",
		    ತಟಸ್ಥ_file, ಕೀಲಿ_types[i].ಮಾರ್ಗ);

		/* Check whether private key exists and is not zero-length */
		ಆದರೆ (stat(prv_file, &st) == 0) {
			ಆದರೆ (st.st_size != 0)
				ಹೋಗು ಮುಂದಿನ;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (errno != ENOENT) {
			error("Could not stat %s: %s", ಕೀಲಿ_types[i].ಮಾರ್ಗ,
			    strerror(errno));
			ಹೋಗು failnext;
		}

		/*
		 * Private key doesn't exist or is invalid; proceed with
		 * key generation.
		 */
		xasprintf(&prv_tmp, "%s%s.XXXXXXXXXX",
		    ತಟಸ್ಥ_file, ಕೀಲಿ_types[i].ಮಾರ್ಗ);
		xasprintf(&pub_tmp, "%s%s.pub.XXXXXXXXXX",
		    ತಟಸ್ಥ_file, ಕೀಲಿ_types[i].ಮಾರ್ಗ);
		xasprintf(&pub_file, "%s%s.pub",
		    ತಟಸ್ಥ_file, ಕೀಲಿ_types[i].ಮಾರ್ಗ);

		ಆದರೆ (ಮೊದಲ == 0) {
			ಮೊದಲ = 1;
			ಬರೆ("%s: generating new host keys: ", __progname);
		}
		ಬರೆ("%s ", ಕೀಲಿ_types[i].ಕೀಲಿ_type_display);
		fflush(stdout);
		type = sshkey_type_from_shortname(ಕೀಲಿ_types[i].ಕೀಲಿ_type);
		ಆದರೆ ((fd = mkstemp(prv_tmp)) == -1) {
			error("Could not save your private key in %s: %s",
			    prv_tmp, strerror(errno));
			ಹೋಗು failnext;
		}
		(ಶೂನ್ಯ)close(fd); /* just using mkstemp() to reserve a name */
		ಬಿಟ್ಟುಗಳು = 0;
		type_ಬಿಟ್ಟುಗಳು_valid(type, ಖಾಲಿ, &ಬಿಟ್ಟುಗಳು);
		ಆದರೆ ((r = sshkey_generate(type, ಬಿಟ್ಟುಗಳು, &ಖಾಸಗಿ)) != 0) {
			error_r(r, "sshkey_generate failed");
			ಹೋಗು failnext;
		}
		ಆದರೆ ((r = sshkey_from_ಖಾಸಗಿ(ಖಾಸಗಿ, &ಸಾರ್ವಜನಿಕ)) != 0)
			fatal_fr(r, "sshkey_from_private");
		snprintf(comment, ಗಾತ್ರ comment, "%s@%s", pw->pw_name,
		    hostname);
		ಆದರೆ ((r = sshkey_save_ಖಾಸಗಿ(ಖಾಸಗಿ, prv_tmp, "",
		    comment, ಖಾಸಗಿ_ಕೀಲಿ_format, openssh_format_cipher,
		    ಸುತ್ತುಗಳು)) != 0) {
			error_r(r, "Saving key \"%s\" failed", prv_tmp);
			ಹೋಗು failnext;
		}
		ಆದರೆ ((fd = mkstemp(pub_tmp)) == -1) {
			error("Could not save your public key in %s: %s",
			    pub_tmp, strerror(errno));
			ಹೋಗು failnext;
		}
		(ಶೂನ್ಯ)fchmod(fd, 0644);
		(ಶೂನ್ಯ)close(fd);
		ಆದರೆ ((r = sshkey_save_ಬಹಿರಂಗ(ಸಾರ್ವಜನಿಕ, pub_tmp, comment)) != 0) {
			error_r(r, "Unable to save public key to %s",
			    ತಟಸ್ಥ_file);
			ಹೋಗು failnext;
		}

		/* Rename temporary files to their permanent locations. */
		ಆದರೆ (rename(pub_tmp, pub_file) != 0) {
			error("Unable to move %s into position: %s",
			    pub_file, strerror(errno));
			ಹೋಗು failnext;
		}
		ಆದರೆ (rename(prv_tmp, prv_file) != 0) {
			error("Unable to move %s into position: %s",
			    ಕೀಲಿ_types[i].ಮಾರ್ಗ, strerror(errno));
 failnext:
			ಮೊದಲ = 0;
			ಹೋಗು ಮುಂದಿನ;
		}
 ಮುಂದಿನ:
		sshkey_free(ಖಾಸಗಿ);
		sshkey_free(ಸಾರ್ವಜನಿಕ);
		ಬಿಡುಗಡೆ(prv_tmp);
		ಬಿಡುಗಡೆ(pub_tmp);
		ಬಿಡುಗಡೆ(prv_file);
		ಬಿಡುಗಡೆ(pub_file);
	}
	ಆದರೆ (ಮೊದಲ != 0)
		ಬರೆ("\n");
}

ರಚನೆ ತಿಳಿದ_hosts_ctx {
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host;	/* Hostname searched for in find/delete case */
	FILE *ಹೊರಹೋಗು;		/* Output file, stdout for find_hosts case */
	ಪೂರ್ಣಾಂಕ has_unhashed;	/* When hashing, original had unhashed hosts */
	ಪೂರ್ಣಾಂಕ ಸಿಕ್ಕಿತು_ಕೀಲಿ;		/* For find/delete, host was found */
	ಪೂರ್ಣಾಂಕ invalid;		/* File contained invalid items; don't delete */
	ಪೂರ್ಣಾಂಕ hash_hosts;		/* Hash hostnames as we go */
	ಪೂರ್ಣಾಂಕ ಕಂಡುಹಿಡಿ_host;		/* Search for specific hostname */
	ಪೂರ್ಣಾಂಕ delete_host;	/* Delete host from known_hosts */
};

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ತಿಳಿದ_hosts_hash(ರಚನೆ hostkey_foreach_ಸಾಲು *l, ಶೂನ್ಯ *_ctx)
{
	ರಚನೆ ತಿಳಿದ_hosts_ctx *ctx = (ರಚನೆ ತಿಳಿದ_hosts_ctx *)_ctx;
	ಅಕ್ಷರ *hashed, *cp, *hosts, *ohosts;
	ಪೂರ್ಣಾಂಕ has_wild = l->hosts && strcspn(l->hosts, "*?!") != ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(l->hosts);
	ಪೂರ್ಣಾಂಕ was_hashed = l->hosts && l->hosts[0] == HASH_DELIM;

	ಆಯ್ಕೆ (l->ಸ್ಥಿತಿ_2) {
	ಸ್ಥಿತಿ HKF_ಸ್ಥಿತಿ_OK:
	ಸ್ಥಿತಿ HKF_ಸ್ಥಿತಿ_MATCHED:
		/*
		 * Don't hash hosts already hashed, with wildcard
		 * characters or a CA/revocation marker.
		 */
		ಆದರೆ (was_hashed || has_wild || l->marker != MRK_NONE) {
			fprintf(ctx->ಹೊರಹೋಗು, "%s\n", l->ಸಾಲು);
			ಆದರೆ (has_wild && !ctx->ಕಂಡುಹಿಡಿ_host) {
				logit("%s:%lu: ignoring host name "
				    "with wildcard: %.64s", l->ಮಾರ್ಗ,
				    l->linenum, l->hosts);
			}
			ಹಿಂತಿರುಗಿ 0;
		}
		/*
		 * Split any comma-separated hostnames from the host list,
		 * hash and store separately.
		 */
		ohosts = hosts = xstrdup(l->hosts);
		ಆಗ ((cp = strsep(&hosts, ",")) != ಖಾಲಿ && *cp != '\0') {
			lowercase(cp);
			ಆದರೆ ((hashed = host_hash(cp, ಖಾಲಿ, 0)) == ಖಾಲಿ)
				fatal("hash_host failed");
			fprintf(ctx->ಹೊರಹೋಗು, "%s %s\n", hashed, l->rawkey);
			ಬಿಡುಗಡೆ(hashed);
			ctx->has_unhashed = 1;
		}
		ಬಿಡುಗಡೆ(ohosts);
		ಹಿಂತಿರುಗಿ 0;
	ಸ್ಥಿತಿ HKF_ಸ್ಥಿತಿ_INVALID:
		/* Retain invalid lines, but mark file as invalid. */
		ctx->invalid = 1;
		logit("%s:%lu: invalid line", l->ಮಾರ್ಗ, l->linenum);
		/* FALLTHROUGH */
	ಪೂರ್ವನಿಯೋಜಿತ:
		fprintf(ctx->ಹೊರಹೋಗು, "%s\n", l->ಸಾಲು);
		ಹಿಂತಿರುಗಿ 0;
	}
	/* NOTREACHED */
	ಹಿಂತಿರುಗಿ -1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ತಿಳಿದ_hosts_ಕಂಡುಹಿಡಿ_delete(ರಚನೆ hostkey_foreach_ಸಾಲು *l, ಶೂನ್ಯ *_ctx)
{
	ರಚನೆ ತಿಳಿದ_hosts_ctx *ctx = (ರಚನೆ ತಿಳಿದ_hosts_ctx *)_ctx;
	ಎಣಿಕೆ sshkey_fp_rep rep;
	ಪೂರ್ಣಾಂಕ fptype;
	ಅಕ್ಷರ *fp = ಖಾಲಿ, *ra = ಖಾಲಿ;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;

	ಆದರೆ (l->ಸ್ಥಿತಿ_2 == HKF_ಸ್ಥಿತಿ_MATCHED) {
		ಆದರೆ (ctx->delete_host) {
			ಆದರೆ (l->marker != MRK_NONE) {
				/* Don't remove CA and revocation lines */
				fprintf(ctx->ಹೊರಹೋಗು, "%s\n", l->ಸಾಲು);
			} ಇಲ್ಲದಿದ್ದರೆ {
				/*
				 * Hostname matches and has no CA/revoke
				 * marker, delete it by *not* writing the
				 * line to ctx->out.
				 */
				ctx->ಸಿಕ್ಕಿತು_ಕೀಲಿ = 1;
				ಆದರೆ (!quiet)
					ಬರೆ("# Host %s found: line %lu\n",
					    ctx->host, l->linenum);
			}
			ಹಿಂತಿರುಗಿ 0;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ctx->ಕಂಡುಹಿಡಿ_host) {
			ctx->ಸಿಕ್ಕಿತು_ಕೀಲಿ = 1;
			ಆದರೆ (!quiet) {
				ಬರೆ("# Host %s found: line %lu %s\n",
				    ctx->host,
				    l->linenum, l->marker == MRK_CA ? "CA" :
				    (l->marker == MRK_REVOKE ? "REVOKED" : ""));
			}
			ಆದರೆ (ctx->hash_hosts)
				ತಿಳಿದ_hosts_hash(l, ctx);
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (print_fingerprint) {
				fp = sshkey_fingerprint(l->ಕೀಲಿ, fptype, rep);
				ra = sshkey_fingerprint(l->ಕೀಲಿ,
				    fingerprint_hash, SSH_FP_RANDOMART);
				ಆದರೆ (fp == ಖಾಲಿ || ra == ಖಾಲಿ)
					fatal_f("sshkey_fingerprint failed");
				mprintf("%s %s %s%s%s\n", ctx->host,
				    sshkey_type(l->ಕೀಲಿ), fp,
				    l->comment[0] ? " " : "",
				    l->comment);
				ಆದರೆ (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
					ಬರೆ("%s\n", ra);
				ಬಿಡುಗಡೆ(ra);
				ಬಿಡುಗಡೆ(fp);
			} ಇಲ್ಲದಿದ್ದರೆ
				fprintf(ctx->ಹೊರಹೋಗು, "%s\n", l->ಸಾಲು);
			ಹಿಂತಿರುಗಿ 0;
		}
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ctx->delete_host) {
		/* Retain non-matching hosts when deleting */
		ಆದರೆ (l->ಸ್ಥಿತಿ_2 == HKF_ಸ್ಥಿತಿ_INVALID) {
			ctx->invalid = 1;
			logit("%s:%lu: invalid line", l->ಮಾರ್ಗ, l->linenum);
		}
		fprintf(ctx->ಹೊರಹೋಗು, "%s\n", l->ಸಾಲು);
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_ತಿಳಿದ_hosts(ರಚನೆ passwd *pw, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name, ಪೂರ್ಣಾಂಕ ಕಂಡುಹಿಡಿ_host,
    ಪೂರ್ಣಾಂಕ delete_host, ಪೂರ್ಣಾಂಕ hash_hosts)
{
	ಅಕ್ಷರ *cp, tmp[PATH_MAX], old[PATH_MAX];
	ಪೂರ್ಣಾಂಕ r, fd, oerrno, inplace = 0;
	ರಚನೆ ತಿಳಿದ_hosts_ctx ctx;
	u_int foreach_options;
	ರಚನೆ stat sb;

	ಆದರೆ (!have_ತಟಸ್ಥ) {
		cp = tilde_expand_filename(ಮಾರ್ಗ_SSH_USER_HOSTFILE, pw->pw_uid);
		ಆದರೆ (strlcpy(ತಟಸ್ಥ_file, cp, ಗಾತ್ರ(ತಟಸ್ಥ_file)) >=
		    ಗಾತ್ರ(ತಟಸ್ಥ_file))
			fatal("Specified known hosts path too long");
		ಬಿಡುಗಡೆ(cp);
		have_ತಟಸ್ಥ = 1;
	}
	ಆದರೆ (stat(ತಟಸ್ಥ_file, &sb) != 0)
		fatal("Cannot stat %s: %s", ತಟಸ್ಥ_file, strerror(errno));

	memset(&ctx, 0, ಗಾತ್ರ(ctx));
	ctx.ಹೊರಹೋಗು = stdout;
	ctx.host = name;
	ctx.hash_hosts = hash_hosts;
	ctx.ಕಂಡುಹಿಡಿ_host = ಕಂಡುಹಿಡಿ_host;
	ctx.delete_host = delete_host;

	/*
	 * Find hosts goes to stdout, hash and deletions happen in-place
	 * A corner case is ssh-keygen -HF foo, which should go to stdout
	 */
	ಆದರೆ (!ಕಂಡುಹಿಡಿ_host && (hash_hosts || delete_host)) {
		ಆದರೆ (strlcpy(tmp, ತಟಸ್ಥ_file, ಗಾತ್ರ(tmp)) >= ಗಾತ್ರ(tmp) ||
		    strlcat(tmp, ".XXXXXXXXXX", ಗಾತ್ರ(tmp)) >= ಗಾತ್ರ(tmp) ||
		    strlcpy(old, ತಟಸ್ಥ_file, ಗಾತ್ರ(old)) >= ಗಾತ್ರ(old) ||
		    strlcat(old, ".old", ಗಾತ್ರ(old)) >= ಗಾತ್ರ(old))
			fatal("known_hosts path too long");
		umask(077);
		ಆದರೆ ((fd = mkstemp(tmp)) == -1)
			fatal("mkstemp: %s", strerror(errno));
		ಆದರೆ ((ctx.ಹೊರಹೋಗು = fdopen(fd, "w")) == ಖಾಲಿ) {
			oerrno = errno;
			unlink(tmp);
			fatal("fdopen: %s", strerror(oerrno));
		}
		(ಶೂನ್ಯ)fchmod(fd, sb.st_mode & 0644);
		inplace = 1;
	}
	/* XXX support identity_file == "-" for stdin */
	foreach_options = ಕಂಡುಹಿಡಿ_host ? HKF_WANT_ಹೊಂದಿಕೆ : 0;
	foreach_options |= print_fingerprint ? HKF_WANT_PARSE_ಕೀಲಿ : 0;
	ಆದರೆ ((r = hostkeys_foreach(ತಟಸ್ಥ_file, (ಕಂಡುಹಿಡಿ_host || !hash_hosts) ?
	    ತಿಳಿದ_hosts_ಕಂಡುಹಿಡಿ_delete : ತಿಳಿದ_hosts_hash, &ctx, name, ಖಾಲಿ,
	    foreach_options, 0)) != 0) {
		ಆದರೆ (inplace)
			unlink(tmp);
		fatal_fr(r, "hostkeys_foreach");
	}

	ಆದರೆ (inplace)
		fclose(ctx.ಹೊರಹೋಗು);

	ಆದರೆ (ctx.invalid) {
		error("%s is not a valid known_hosts file.", ತಟಸ್ಥ_file);
		ಆದರೆ (inplace) {
			error("Not replacing existing known_hosts "
			    "file because of errors");
			unlink(tmp);
		}
		ನಿರ್ಗಮಿಸು(1);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (delete_host && !ctx.ಸಿಕ್ಕಿತು_ಕೀಲಿ) {
		logit("Host %s not found in %s", name, ತಟಸ್ಥ_file);
		ಆದರೆ (inplace)
			unlink(tmp);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (inplace) {
		/* Backup existing file */
		ಆದರೆ (unlink(old) == -1 && errno != ENOENT)
			fatal("unlink %.100s: %s", old, strerror(errno));
		ಆದರೆ (link(ತಟಸ್ಥ_file, old) == -1)
			fatal("link %.100s to %.100s: %s", ತಟಸ್ಥ_file, old,
			    strerror(errno));
		/* Move new one into place */
		ಆದರೆ (rename(tmp, ತಟಸ್ಥ_file) == -1) {
			error("rename\"%s\" to \"%s\": %s", tmp, ತಟಸ್ಥ_file,
			    strerror(errno));
			unlink(tmp);
			unlink(old);
			ನಿರ್ಗಮಿಸು(1);
		}

		ಬರೆ("%s updated.\n", ತಟಸ್ಥ_file);
		ಬರೆ("Original contents retained as %s\n", old);
		ಆದರೆ (ctx.has_unhashed) {
			logit("WARNING: %s contains unhashed entries", old);
			logit("Delete this file to ensure privacy "
			    "of hostnames");
		}
	}

	ನಿರ್ಗಮಿಸು (ಕಂಡುಹಿಡಿ_host && !ctx.ಸಿಕ್ಕಿತು_ಕೀಲಿ);
}

/*
 * Perform changing a passphrase.  The argument is the passwd structure
 * for the current user.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
do_change_passphrase(ರಚನೆ passwd *pw, ಅಕ್ಷರ * ಸ್ಥಿರಾಂಕ *opts, ಗಾತ್ರ_t nopts)
{
	ಅಕ್ಷರ *comment;
	ಅಕ್ಷರ *old_passphrase, *passphrase1, *passphrase2;
	ರಚನೆ stat st;
	ರಚನೆ sshkey *ಖಾಸಗಿ;
	ಪೂರ್ಣಾಂಕ r;
	ಗಾತ್ರ_t i;

	ಆದರೆ (!have_ತಟಸ್ಥ)
		ask_filename(pw, "Enter file in which the key is");
	ಆದರೆ (stat(ತಟಸ್ಥ_file, &st) == -1)
		fatal("%s: %s", ತಟಸ್ಥ_file, strerror(errno));
	/* Try to load the file with empty passphrase. */
	r = sshkey_ತುಂಬು_ಖಾಸಗಿ(ತಟಸ್ಥ_file, "", &ಖಾಸಗಿ, &comment);
	ಆದರೆ (r == SSH_ERR_ಕೀಲಿ_WRONG_PASSPHRASE) {
		ಆದರೆ (ತಟಸ್ಥ_passphrase)
			old_passphrase = xstrdup(ತಟಸ್ಥ_passphrase);
		ಇಲ್ಲದಿದ್ದರೆ
			old_passphrase =
			    read_passphrase("Enter old passphrase: ",
			    RP_ALLOW_STDIN);
		r = sshkey_ತುಂಬು_ಖಾಸಗಿ(ತಟಸ್ಥ_file, old_passphrase,
		    &ಖಾಸಗಿ, &comment);
		freezero(old_passphrase, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(old_passphrase));
		ಆದರೆ (r != 0)
			ಹೋಗು badkey;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (r != 0) {
 badkey:
		fatal_r(r, "Failed to load key %s", ತಟಸ್ಥ_file);
	}
	ಆದರೆ (comment)
		mprintf("Key has comment '%s'\n", comment);

	/* All current -O options relate to FIDO keys only */
	ಆದರೆ (nopts != 0 && !sshkey_is_sk(ಖಾಸಗಿ)) {
		fatal("FIDO-specific option requested for non-FIDO key %s",
		    ತಟಸ್ಥ_file);
	}
	ಆದರೆ (sshkey_is_sk(ಖಾಸಗಿ)) {
		debug_f("%s: original FIDO key flags: "
		    "%stouch-required %sverify-required", ತಟಸ್ಥ_file,
		    (ಖಾಸಗಿ->sk_flags & SSH_SK_USER_PRESENCE_REQD) ? "": "no-",
		    (ಖಾಸಗಿ->sk_flags & SSH_SK_USER_VERIFICATION_REQD) ? "" : "no-");
	}
	ಗಾಗಿ (i = 0; i < nopts; i++) {
		ಆದರೆ (strcasecmp(opts[i], "touch-required") == 0)
			ಖಾಸಗಿ->sk_flags |= SSH_SK_USER_PRESENCE_REQD;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcasecmp(opts[i], "no-touch-required") == 0)
			ಖಾಸಗಿ->sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcasecmp(opts[i], "verify-required") == 0)
			ಖಾಸಗಿ->sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcasecmp(opts[i], "no-verify-required") == 0)
			ಖಾಸಗಿ->sk_flags &= ~SSH_SK_USER_VERIFICATION_REQD;
		ಇಲ್ಲದಿದ್ದರೆ {
			fatal("Option \"%s\" is unsupported for "
			    "key passphrase change", opts[i]);
		}
	}
	ಆದರೆ (sshkey_is_sk(ಖಾಸಗಿ) && nopts != 0) {
		debug_f("%s: updated FIDO key flags: "
		    "%stouch-required %sverify-required", ತಟಸ್ಥ_file,
		    (ಖಾಸಗಿ->sk_flags & SSH_SK_USER_PRESENCE_REQD) ? "": "no-",
		    (ಖಾಸಗಿ->sk_flags & SSH_SK_USER_VERIFICATION_REQD) ? "" : "no-");
	}

	/* Ask the new passphrase (twice). */
	ಆದರೆ (ತಟಸ್ಥ_new_passphrase) {
		passphrase1 = xstrdup(ತಟಸ್ಥ_new_passphrase);
		passphrase2 = ಖಾಲಿ;
	} ಇಲ್ಲದಿದ್ದರೆ {
		passphrase1 =
			read_passphrase("Enter new passphrase (empty for no "
			    "passphrase): ", RP_ALLOW_STDIN);
		passphrase2 = read_passphrase("Enter same passphrase again: ",
		    RP_ALLOW_STDIN);

		/* Verify that they are the same. */
		ಆದರೆ (strcmp(passphrase1, passphrase2) != 0) {
			explicit_bzero(passphrase1, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(passphrase1));
			explicit_bzero(passphrase2, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(passphrase2));
			ಬಿಡುಗಡೆ(passphrase1);
			ಬಿಡುಗಡೆ(passphrase2);
			ಬರೆ("Pass phrases do not match.  Try again.\n");
			ನಿರ್ಗಮಿಸು(1);
		}
		/* Destroy the other copy. */
		freezero(passphrase2, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(passphrase2));
	}

	/* Save the file using the new passphrase. */
	ಆದರೆ ((r = sshkey_save_ಖಾಸಗಿ(ಖಾಸಗಿ, ತಟಸ್ಥ_file, passphrase1,
	    comment, ಖಾಸಗಿ_ಕೀಲಿ_format, openssh_format_cipher, ಸುತ್ತುಗಳು)) != 0) {
		error_r(r, "Saving key \"%s\" failed", ತಟಸ್ಥ_file);
		freezero(passphrase1, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(passphrase1));
		sshkey_free(ಖಾಸಗಿ);
		ಬಿಡುಗಡೆ(comment);
		ನಿರ್ಗಮಿಸು(1);
	}
	/* Destroy the passphrase and the copy of the key in memory. */
	freezero(passphrase1, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(passphrase1));
	sshkey_free(ಖಾಸಗಿ);		 /* Destroys contents */
	ಬಿಡುಗಡೆ(comment);

	ಬರೆ("Your identification has been saved with the new passphrase.\n");
	ನಿರ್ಗಮಿಸು(0);
}

/*
 * Print the SSHFP RR.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
do_print_resource_ದಾಖಲೆ(ರಚನೆ passwd *pw, ಅಕ್ಷರ *fname, ಅಕ್ಷರ *hname,
    ಪೂರ್ಣಾಂಕ print_generic, ಅಕ್ಷರ * ಸ್ಥಿರಾಂಕ *opts, ಗಾತ್ರ_t nopts)
{
	ರಚನೆ sshkey *ಸಾರ್ವಜನಿಕ;
	ಅಕ್ಷರ *comment = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *p;
	ರಚನೆ stat st;
	ಪೂರ್ಣಾಂಕ r, hash = -1;
	ಗಾತ್ರ_t i;

	ಗಾಗಿ (i = 0; i < nopts; i++) {
		ಆದರೆ ((p = strprefix(opts[i], "hashalg=", 1)) != ಖಾಲಿ) {
			ಆದರೆ ((hash = ssh_digest_alg_by_name(p)) == -1)
				fatal("Unsupported hash algorithm");
		} ಇಲ್ಲದಿದ್ದರೆ {
			error("Invalid option \"%s\"", opts[i]);
			ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
		}
	}
	ಆದರೆ (fname == ಖಾಲಿ)
		fatal_f("no filename");
	ಆದರೆ (stat(fname, &st) == -1) {
		ಆದರೆ (errno == ENOENT)
			ಹಿಂತಿರುಗಿ 0;
		fatal("%s: %s", fname, strerror(errno));
	}
	ಆದರೆ ((r = sshkey_ತುಂಬು_ಬಹಿರಂಗ(fname, &ಸಾರ್ವಜನಿಕ, &comment)) != 0)
		fatal_r(r, "Failed to read v2 public key from \"%s\"", fname);
	export_dns_rr(hname, ಸಾರ್ವಜನಿಕ, stdout, print_generic, hash);
	sshkey_free(ಸಾರ್ವಜನಿಕ);
	ಬಿಡುಗಡೆ(comment);
	ಹಿಂತಿರುಗಿ 1;
}

/*
 * Change the comment of a private key file.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
do_change_comment(ರಚನೆ passwd *pw, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ತಟಸ್ಥ_comment)
{
	ಅಕ್ಷರ new_comment[ಕೀಲಿ_COMMENT_MAX], *comment, *passphrase;
	ರಚನೆ sshkey *ಖಾಸಗಿ;
	ರಚನೆ sshkey *ಸಾರ್ವಜನಿಕ;
	ರಚನೆ stat st;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (!have_ತಟಸ್ಥ)
		ask_filename(pw, "Enter file in which the key is");
	ಆದರೆ (stat(ತಟಸ್ಥ_file, &st) == -1)
		fatal("%s: %s", ತಟಸ್ಥ_file, strerror(errno));
	ಆದರೆ ((r = sshkey_ತುಂಬು_ಖಾಸಗಿ(ತಟಸ್ಥ_file, "",
	    &ಖಾಸಗಿ, &comment)) == 0)
		passphrase = xstrdup("");
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (r != SSH_ERR_ಕೀಲಿ_WRONG_PASSPHRASE)
		fatal_r(r, "Cannot load private key \"%s\"", ತಟಸ್ಥ_file);
	ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ (ತಟಸ್ಥ_passphrase)
			passphrase = xstrdup(ತಟಸ್ಥ_passphrase);
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ತಟಸ್ಥ_new_passphrase)
			passphrase = xstrdup(ತಟಸ್ಥ_new_passphrase);
		ಇಲ್ಲದಿದ್ದರೆ
			passphrase = read_passphrase("Enter passphrase: ",
			    RP_ALLOW_STDIN);
		/* Try to load using the passphrase. */
		ಆದರೆ ((r = sshkey_ತುಂಬು_ಖಾಸಗಿ(ತಟಸ್ಥ_file, passphrase,
		    &ಖಾಸಗಿ, &comment)) != 0) {
			freezero(passphrase, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(passphrase));
			fatal_r(r, "Cannot load private key \"%s\"",
			    ತಟಸ್ಥ_file);
		}
	}

	ಆದರೆ (ಖಾಸಗಿ->type != ಕೀಲಿ_ED25519 &&
	    ಖಾಸಗಿ_ಕೀಲಿ_format != SSHKEY_ಖಾಸಗಿ_OPENSSH) {
		error("Comments are only supported for keys stored in "
		    "the new format (-o).");
		explicit_bzero(passphrase, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(passphrase));
		sshkey_free(ಖಾಸಗಿ);
		ನಿರ್ಗಮಿಸು(1);
	}
	ಆದರೆ (comment)
		ಬರೆ("Old comment: %s\n", comment);
	ಇಲ್ಲದಿದ್ದರೆ
		ಬರೆ("No existing comment\n");

	ಆದರೆ (ತಟಸ್ಥ_comment) {
		strlcpy(new_comment, ತಟಸ್ಥ_comment, ಗಾತ್ರ(new_comment));
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಬರೆ("New comment: ");
		fflush(stdout);
		ಆದರೆ (!fgets(new_comment, ಗಾತ್ರ(new_comment), stdin)) {
			explicit_bzero(passphrase, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(passphrase));
			sshkey_free(ಖಾಸಗಿ);
			ನಿರ್ಗಮಿಸು(1);
		}
		new_comment[strcspn(new_comment, "\n")] = '\0';
	}
	ಆದರೆ (comment != ಖಾಲಿ && strcmp(comment, new_comment) == 0) {
		ಬರೆ("No change to comment\n");
		ಬಿಡುಗಡೆ(passphrase);
		sshkey_free(ಖಾಸಗಿ);
		ಬಿಡುಗಡೆ(comment);
		ನಿರ್ಗಮಿಸು(0);
	}

	/* Save the file using the new passphrase. */
	ಆದರೆ ((r = sshkey_save_ಖಾಸಗಿ(ಖಾಸಗಿ, ತಟಸ್ಥ_file, passphrase,
	    new_comment, ಖಾಸಗಿ_ಕೀಲಿ_format, openssh_format_cipher,
	    ಸುತ್ತುಗಳು)) != 0) {
		error_r(r, "Saving key \"%s\" failed", ತಟಸ್ಥ_file);
		freezero(passphrase, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(passphrase));
		sshkey_free(ಖಾಸಗಿ);
		ಬಿಡುಗಡೆ(comment);
		ನಿರ್ಗಮಿಸು(1);
	}
	freezero(passphrase, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(passphrase));
	ಆದರೆ ((r = sshkey_from_ಖಾಸಗಿ(ಖಾಸಗಿ, &ಸಾರ್ವಜನಿಕ)) != 0)
		fatal_fr(r, "sshkey_from_private");
	sshkey_free(ಖಾಸಗಿ);

	strlcat(ತಟಸ್ಥ_file, ".pub", ಗಾತ್ರ(ತಟಸ್ಥ_file));
	ಆದರೆ ((r = sshkey_save_ಬಹಿರಂಗ(ಸಾರ್ವಜನಿಕ, ತಟಸ್ಥ_file, new_comment)) != 0)
		fatal_r(r, "Unable to save public key to %s", ತಟಸ್ಥ_file);
	sshkey_free(ಸಾರ್ವಜನಿಕ);
	ಬಿಡುಗಡೆ(comment);

	ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(new_comment) > 0)
		ಬರೆ("Comment '%s' applied\n", new_comment);
	ಇಲ್ಲದಿದ್ದರೆ
		ಬರೆ("Comment removed\n");

	ನಿರ್ಗಮಿಸು(0);
}

ಸ್ಥಿರ ಶೂನ್ಯ
cert_ext_ಕೂಡಿಸು(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಕೀಲಿ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮೌಲ್ಯ, ಪೂರ್ಣಾಂಕ iscrit)
{
	cert_ext = xreallocarray(cert_ext, ncert_ext + 1, ಗಾತ್ರ(*cert_ext));
	cert_ext[ncert_ext].ಕೀಲಿ = xstrdup(ಕೀಲಿ);
	cert_ext[ncert_ext].val = ಮೌಲ್ಯ == ಖಾಲಿ ? ಖಾಲಿ : xstrdup(ಮೌಲ್ಯ);
	cert_ext[ncert_ext].crit = iscrit;
	ncert_ext++;
}

/* qsort(3) comparison function for certificate extensions */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
cert_ext_cmp(ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *_a, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *_b)
{
	ಸ್ಥಿರಾಂಕ ರಚನೆ cert_ext *a = (ಸ್ಥಿರಾಂಕ ರಚನೆ cert_ext *)_a;
	ಸ್ಥಿರಾಂಕ ರಚನೆ cert_ext *b = (ಸ್ಥಿರಾಂಕ ರಚನೆ cert_ext *)_b;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (a->crit != b->crit)
		ಹಿಂತಿರುಗಿ (a->crit < b->crit) ? -1 : 1;
	ಆದರೆ ((r = strcmp(a->ಕೀಲಿ, b->ಕೀಲಿ)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ ((a->val == ಖಾಲಿ) != (b->val == ಖಾಲಿ))
		ಹಿಂತಿರುಗಿ (a->val == ಖಾಲಿ) ? -1 : 1;
	ಆದರೆ (a->val != ಖಾಲಿ && (r = strcmp(a->val, b->val)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಹಿಂತಿರುಗಿ 0;
}

#ವ್ಯಾಖ್ಯಾನಿಸು OPTIONS_CRITICAL	1
#ವ್ಯಾಖ್ಯಾನಿಸು OPTIONS_EXTENSIONS	2
ಸ್ಥಿರ ಶೂನ್ಯ
prepare_options_buf(ರಚನೆ sshbuf *c, ಪೂರ್ಣಾಂಕ which)
{
	ರಚನೆ sshbuf *b;
	ಗಾತ್ರ_t i;
	ಪೂರ್ಣಾಂಕ r;
	ಸ್ಥಿರಾಂಕ ರಚನೆ cert_ext *ext;

	ಆದರೆ ((b = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	sshbuf_reset(c);
	ಗಾಗಿ (i = 0; i < ncert_ext; i++) {
		ext = &cert_ext[i];
		ಆದರೆ ((ext->crit && (which & OPTIONS_EXTENSIONS)) ||
		    (!ext->crit && (which & OPTIONS_CRITICAL)))
			ಮುಂದುವರಿ;
		ಆದರೆ (ext->val == ಖಾಲಿ) {
			/* flag option */
			debug3_f("%s", ext->ಕೀಲಿ);
			ಆದರೆ ((r = sshbuf_put_cstring(c, ext->ಕೀಲಿ)) != 0 ||
			    (r = sshbuf_put_string(c, ಖಾಲಿ, 0)) != 0)
				fatal_fr(r, "prepare flag");
		} ಇಲ್ಲದಿದ್ದರೆ {
			/* key/value option */
			debug3_f("%s=%s", ext->ಕೀಲಿ, ext->val);
			sshbuf_reset(b);
			ಆದರೆ ((r = sshbuf_put_cstring(c, ext->ಕೀಲಿ)) != 0 ||
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
	ಆದರೆ (certflags_command != ಖಾಲಿ)
		cert_ext_ಕೂಡಿಸು("force-command", certflags_command, 1);
	ಆದರೆ (certflags_src_addr != ಖಾಲಿ)
		cert_ext_ಕೂಡಿಸು("source-address", certflags_src_addr, 1);
	ಆದರೆ ((certflags_flags & CERTOPT_REQUIRE_VERIFY) != 0)
		cert_ext_ಕೂಡಿಸು("verify-required", ಖಾಲಿ, 1);
	/* extensions */
	ಆದರೆ ((certflags_flags & CERTOPT_X_FWD) != 0)
		cert_ext_ಕೂಡಿಸು("permit-X11-forwarding", ಖಾಲಿ, 0);
	ಆದರೆ ((certflags_flags & CERTOPT_AGENT_FWD) != 0)
		cert_ext_ಕೂಡಿಸು("permit-agent-forwarding", ಖಾಲಿ, 0);
	ಆದರೆ ((certflags_flags & CERTOPT_ಪೋರ್ಟ್_FWD) != 0)
		cert_ext_ಕೂಡಿಸು("permit-port-forwarding", ಖಾಲಿ, 0);
	ಆದರೆ ((certflags_flags & CERTOPT_PTY) != 0)
		cert_ext_ಕೂಡಿಸು("permit-pty", ಖಾಲಿ, 0);
	ಆದರೆ ((certflags_flags & CERTOPT_USER_RC) != 0)
		cert_ext_ಕೂಡಿಸು("permit-user-rc", ಖಾಲಿ, 0);
	ಆದರೆ ((certflags_flags & CERTOPT_NO_REQUIRE_USER_PRESENCE) != 0)
		cert_ext_ಕೂಡಿಸು("no-touch-required", ಖಾಲಿ, 0);
	/* order lexically by key */
	ಆದರೆ (ncert_ext > 0)
		qsort(cert_ext, ncert_ext, ಗಾತ್ರ(*cert_ext), cert_ext_cmp);
}

ಸ್ಥಿರ ರಚನೆ sshkey *
ತುಂಬು_pkcs11_ಕೀಲಿ(ಅಕ್ಷರ *ಮಾರ್ಗ)
{
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ ENABLE_PKCS11
	ರಚನೆ sshkey **ಕೀಲಿಗಳು = ಖಾಲಿ, *ಸಾರ್ವಜನಿಕ, *ಖಾಸಗಿ = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r, i, nkeys;

	ಆದರೆ ((r = sshkey_ತುಂಬು_ಬಹಿರಂಗ(ಮಾರ್ಗ, &ಸಾರ್ವಜನಿಕ, ಖಾಲಿ)) != 0)
		fatal_r(r, "Couldn't load CA public key \"%s\"", ಮಾರ್ಗ);

	nkeys = pkcs11_ಕೂಡಿಸು_provider(pkcs11provider, ತಟಸ್ಥ_passphrase,
	    &ಕೀಲಿಗಳು, ಖಾಲಿ);
	debug3_f("%d keys", nkeys);
	ಆದರೆ (nkeys <= 0)
		fatal("cannot read public key from pkcs11");
	ಗಾಗಿ (i = 0; i < nkeys; i++) {
		ಆದರೆ (sshkey_equal_ಬಹಿರಂಗ(ಸಾರ್ವಜನಿಕ, ಕೀಲಿಗಳು[i])) {
			ಖಾಸಗಿ = ಕೀಲಿಗಳು[i];
			ಮುಂದುವರಿ;
		}
		sshkey_free(ಕೀಲಿಗಳು[i]);
	}
	ಬಿಡುಗಡೆ(ಕೀಲಿಗಳು);
	sshkey_free(ಸಾರ್ವಜನಿಕ);
	ಹಿಂತಿರುಗಿ ಖಾಸಗಿ;
#ಇಲ್ಲದಿದ್ದರೆ
	fatal("no pkcs11 support");
#ಆದರೆ_ಅಂತ್ಯ /* ENABLE_PKCS11 */
}

/* Signer for sshkey_certify_custom that uses the agent */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
agent_signer(ರಚನೆ sshkey *ಕೀಲಿ, u_char **sigp, ಗಾತ್ರ_t *lenp,
    ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ, ಗಾತ್ರ_t datalen,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *alg, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *provider, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pin,
    u_int compat, ಶೂನ್ಯ *ctx)
{
	ಪೂರ್ಣಾಂಕ *agent_fdp = (ಪೂರ್ಣಾಂಕ *)ctx;

	ಹಿಂತಿರುಗಿ ssh_agent_sign(*agent_fdp, ಕೀಲಿ, sigp, lenp,
	    ದತ್ತಾಂಶ, datalen, alg, compat);
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_ca_sign(ರಚನೆ passwd *pw, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ca_ಕೀಲಿ_ಮಾರ್ಗ, ಪೂರ್ಣಾಂಕ prefer_agent,
    ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ cert_serial, ಪೂರ್ಣಾಂಕ cert_serial_autoinc,
    ಪೂರ್ಣಾಂಕ argc, ಅಕ್ಷರ **argv)
{
	ಪೂರ್ಣಾಂಕ r, i, ಕೀಲಿ_ಒಳ_agent = 0, agent_fd = -1;
	u_int n;
	ರಚನೆ sshkey *ca, *ಸಾರ್ವಜನಿಕ;
	ಅಕ್ಷರ valid[64], *otmp, *tmp, *cp, *ಹೊರಹೋಗು, *comment;
	ಅಕ್ಷರ *ca_fp = ಖಾಲಿ, **plist = ಖಾಲಿ, *pin = ಖಾಲಿ;
	ರಚನೆ ssh_identitylist *agent_ids;
	ಗಾತ್ರ_t j;
	ರಚನೆ notifier_ctx *notifier = ಖಾಲಿ;

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ ENABLE_PKCS11
	pkcs11_init(1);
#ಆದರೆ_ಅಂತ್ಯ
	tmp = tilde_expand_filename(ca_ಕೀಲಿ_ಮಾರ್ಗ, pw->pw_uid);
	ಆದರೆ (pkcs11provider != ಖಾಲಿ) {
		/* If a PKCS#11 token was specified then try to use it */
		ಆದರೆ ((ca = ತುಂಬು_pkcs11_ಕೀಲಿ(tmp)) == ಖಾಲಿ)
			fatal("No PKCS#11 key matching %s found", ca_ಕೀಲಿ_ಮಾರ್ಗ);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (prefer_agent) {
		/*
		 * Agent signature requested. Try to use agent after making
		 * sure the public key specified is actually present in the
		 * agent.
		 */
		ಆದರೆ ((r = sshkey_ತುಂಬು_ಬಹಿರಂಗ(tmp, &ca, ಖಾಲಿ)) != 0)
			fatal_r(r, "Cannot load CA public key %s", tmp);
		ಆದರೆ ((r = ssh_get_authentication_socket(&agent_fd)) != 0)
			fatal_r(r, "Cannot use public key for CA signature");
		ಆದರೆ ((r = ssh_fetch_identitylist(agent_fd, &agent_ids)) != 0)
			fatal_r(r, "Retrieve agent key list");
		ಗಾಗಿ (j = 0; j < agent_ids->nkeys; j++) {
			ಆದರೆ (sshkey_equal(ca, agent_ids->ಕೀಲಿಗಳು[j])) {
				ಕೀಲಿ_ಒಳ_agent = 1;
				/* Replace the CA key with the agent one */
				sshkey_free(ca);
				ca = agent_ids->ಕೀಲಿಗಳು[j];
				agent_ids->ಕೀಲಿಗಳು[j] = ಖಾಲಿ;
				ನಿಲ್ಲಿಸು;
			}
		}
		ಆದರೆ (!ಕೀಲಿ_ಒಳ_agent)
			fatal("CA key %s not found in agent", tmp);
		ssh_free_identitylist(agent_ids);
	} ಇಲ್ಲದಿದ್ದರೆ {
		/* CA key is assumed to be a private key on the filesystem */
		ca = ತುಂಬು_ತಟಸ್ಥ(tmp, ಖಾಲಿ);
		ಆದರೆ (sshkey_is_sk(ca) &&
		    (ca->sk_flags & SSH_SK_USER_VERIFICATION_REQD)) {
			ಆದರೆ ((pin = read_passphrase("Enter PIN for CA key: ",
			    RP_ALLOW_STDIN)) == ಖಾಲಿ)
				fatal_f("couldn't read PIN");
		}
	}
	ಬಿಡುಗಡೆ(tmp);

	ಆದರೆ (ಕೀಲಿ_type_name != ಖಾಲಿ) {
		ಆದರೆ (sshkey_type_from_shortname(ಕೀಲಿ_type_name) != ca->type) {
			fatal("CA key type %s doesn't match specified %s",
			    sshkey_ssh_name(ca), ಕೀಲಿ_type_name);
		}
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ca->type == ಕೀಲಿ_RSA) {
		/* Default to a good signature algorithm */
		ಕೀಲಿ_type_name = "rsa-sha2-512";
	}
	ca_fp = sshkey_fingerprint(ca, fingerprint_hash, SSH_FP_DEFAULT);

	finalise_cert_exts();
	ಗಾಗಿ (i = 0; i < argc; i++) {
		/* Split list of principals */
		n = 0;
		ಆದರೆ (cert_principals != ಖಾಲಿ) {
			otmp = tmp = xstrdup(cert_principals);
			plist = ಖಾಲಿ;
			ಗಾಗಿ (; (cp = strsep(&tmp, ",")) != ಖಾಲಿ; n++) {
				plist = xreallocarray(plist, n + 1, ಗಾತ್ರ(*plist));
				ಆದರೆ (*(plist[n] = xstrdup(cp)) == '\0')
					fatal("Empty principal name");
			}
			ಬಿಡುಗಡೆ(otmp);
		}
		ಆದರೆ (n > SSHKEY_CERT_MAX_PRINCIPALS)
			fatal("Too many certificate principals specified");

		tmp = tilde_expand_filename(argv[i], pw->pw_uid);
		ಆದರೆ ((r = sshkey_ತುಂಬು_ಬಹಿರಂಗ(tmp, &ಸಾರ್ವಜನಿಕ, &comment)) != 0)
			fatal_r(r, "load pubkey \"%s\"", tmp);
		ಆದರೆ (sshkey_is_cert(ಸಾರ್ವಜನಿಕ))
			fatal_f("key \"%s\" type %s cannot be certified",
			    tmp, sshkey_type(ಸಾರ್ವಜನಿಕ));

		/* Prepare certificate to sign */
		ಆದರೆ ((r = sshkey_ಗಮ್ಯ_certified(ಸಾರ್ವಜನಿಕ)) != 0)
			fatal_r(r, "Could not upgrade key %s to certificate", tmp);
		ಸಾರ್ವಜನಿಕ->cert->type = cert_ಕೀಲಿ_type;
		ಸಾರ್ವಜನಿಕ->cert->serial = (uint64_t)cert_serial;
		ಸಾರ್ವಜನಿಕ->cert->ಕೀಲಿ_id = xstrdup(cert_ಕೀಲಿ_id);
		ಸಾರ್ವಜನಿಕ->cert->nprincipals = n;
		ಸಾರ್ವಜನಿಕ->cert->principals = plist;
		ಸಾರ್ವಜನಿಕ->cert->valid_after = cert_valid_from;
		ಸಾರ್ವಜನಿಕ->cert->valid_before = cert_valid_ಗಮ್ಯ;
		prepare_options_buf(ಸಾರ್ವಜನಿಕ->cert->critical, OPTIONS_CRITICAL);
		prepare_options_buf(ಸಾರ್ವಜನಿಕ->cert->extensions,
		    OPTIONS_EXTENSIONS);
		ಆದರೆ ((r = sshkey_from_ಖಾಸಗಿ(ca,
		    &ಸಾರ್ವಜನಿಕ->cert->signature_ಕೀಲಿ)) != 0)
			fatal_r(r, "sshkey_from_private (ca key)");

		ಆದರೆ (ಕೀಲಿ_ಒಳ_agent) {
			ಆದರೆ ((r = sshkey_certify_custom(ಸಾರ್ವಜನಿಕ, ca,
			    ಕೀಲಿ_type_name, sk_provider, ಖಾಲಿ, agent_signer,
			    &agent_fd)) != 0)
				fatal_r(r, "Couldn't certify %s via agent", tmp);
		} ಇಲ್ಲದಿದ್ದರೆ {
			ಆದರೆ (sshkey_is_sk(ca) &&
			    (ca->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
				notifier = notify_ಆರಂಭ(0,
				    "Confirm user presence for key %s %s",
				    sshkey_type(ca), ca_fp);
			}
			r = sshkey_certify(ಸಾರ್ವಜನಿಕ, ca, ಕೀಲಿ_type_name,
			    sk_provider, pin);
			notify_complete(notifier, "User presence confirmed");
			ಆದರೆ (r != 0)
				fatal_r(r, "Couldn't certify key %s", tmp);
		}

		ಆದರೆ ((cp = strrchr(tmp, '.')) != ಖಾಲಿ && strcmp(cp, ".pub") == 0)
			*cp = '\0';
		xasprintf(&ಹೊರಹೋಗು, "%s-cert.pub", tmp);
		ಬಿಡುಗಡೆ(tmp);

		ಆದರೆ ((r = sshkey_save_ಬಹಿರಂಗ(ಸಾರ್ವಜನಿಕ, ಹೊರಹೋಗು, comment)) != 0) {
			fatal_r(r, "Unable to save public key to %s",
			    ತಟಸ್ಥ_file);
		}

		ಆದರೆ (!quiet) {
			sshkey_format_cert_validity(ಸಾರ್ವಜನಿಕ->cert,
			    valid, ಗಾತ್ರ(valid));
			logit("Signed %s key %s: id \"%s\" serial %llu%s%s "
			    "valid %s", sshkey_cert_type(ಸಾರ್ವಜನಿಕ),
			    ಹೊರಹೋಗು, ಸಾರ್ವಜನಿಕ->cert->ಕೀಲಿ_id,
			    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ಸಾರ್ವಜನಿಕ->cert->serial,
			    cert_principals != ಖಾಲಿ ? " for " : "",
			    cert_principals != ಖಾಲಿ ? cert_principals : "",
			    valid);
		}

		sshkey_free(ಸಾರ್ವಜನಿಕ);
		ಬಿಡುಗಡೆ(ಹೊರಹೋಗು);
		ಬಿಡುಗಡೆ(comment);
		ಆದರೆ (cert_serial_autoinc)
			cert_serial++;
	}
	ಆದರೆ (pin != ಖಾಲಿ)
		freezero(pin, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(pin));
	sshkey_free(ca);
	ಬಿಡುಗಡೆ(ca_fp);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ ENABLE_PKCS11
	pkcs11_terminate();
#ಆದರೆ_ಅಂತ್ಯ
}

ಸ್ಥಿರ uint64_t
parse_relative_ಸಮಯ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s, time_t now)
{
	int64_t mul, secs;

	mul = *s == '-' ? -1 : 1;

	ಆದರೆ ((secs = convtime(s + 1)) == -1)
		fatal("Invalid relative certificate time %s", s);
	ಆದರೆ (mul == -1 && secs > now)
		fatal("Certificate time %s cannot be represented", s);
	ಹಿಂತಿರುಗಿ now + (uint64_t)(secs * mul);
}

ಸ್ಥಿರ ಶೂನ್ಯ
parse_hex_u64(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s, uint64_t *ಮೇಲೆ)
{
	ಅಕ್ಷರ *ep;
	ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ ull;

	errno = 0;
	ull = strtoull(s, &ep, 16);
	ಆದರೆ (*s == '\0' || *ep != '\0')
		fatal("Invalid certificate time: not a number");
	ಆದರೆ (errno == ERANGE && ull == ULONG_MAX)
		fatal_fr(SSH_ERR_SYSTEM_ERROR, "Invalid certificate time");
	*ಮೇಲೆ = (uint64_t)ull;
}

ಸ್ಥಿರ ಶೂನ್ಯ
parse_cert_times(ಅಕ್ಷರ *timespec)
{
	ಅಕ್ಷರ *from, *ಗಮ್ಯ;
	time_t now = time(ಖಾಲಿ);
	int64_t secs;

	/* +timespec relative to now */
	ಆದರೆ (*timespec == '+' && strchr(timespec, ':') == ಖಾಲಿ) {
		ಆದರೆ ((secs = convtime(timespec + 1)) == -1)
			fatal("Invalid relative certificate life %s", timespec);
		cert_valid_ಗಮ್ಯ = now + secs;
		/*
		 * Backdate certificate one minute to avoid problems on hosts
		 * with poorly-synchronised clocks.
		 */
		cert_valid_from = ((now - 59)/ 60) * 60;
		ಹಿಂತಿರುಗಿ;
	}

	/*
	 * from:to, where
	 * from := [+-]timespec | YYYYMMDD | YYYYMMDDHHMMSS | 0x... | "always"
	 *   to := [+-]timespec | YYYYMMDD | YYYYMMDDHHMMSS | 0x... | "forever"
	 */
	from = xstrdup(timespec);
	ಗಮ್ಯ = strchr(from, ':');
	ಆದರೆ (ಗಮ್ಯ == ಖಾಲಿ || from == ಗಮ್ಯ || *(ಗಮ್ಯ + 1) == '\0')
		fatal("Invalid certificate life specification %s", timespec);
	*ಗಮ್ಯ++ = '\0';

	ಆದರೆ (*from == '-' || *from == '+')
		cert_valid_from = parse_relative_ಸಮಯ(from, now);
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(from, "always") == 0)
		cert_valid_from = 0;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(from, "0x", 2) == 0)
		parse_hex_u64(from, &cert_valid_from);
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (parse_absolute_ಸಮಯ(from, &cert_valid_from) != 0)
		fatal("Invalid from time \"%s\"", from);

	ಆದರೆ (*ಗಮ್ಯ == '-' || *ಗಮ್ಯ == '+')
		cert_valid_ಗಮ್ಯ = parse_relative_ಸಮಯ(ಗಮ್ಯ, now);
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(ಗಮ್ಯ, "forever") == 0)
		cert_valid_ಗಮ್ಯ = ~(uint64_t)0;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(ಗಮ್ಯ, "0x", 2) == 0)
		parse_hex_u64(ಗಮ್ಯ, &cert_valid_ಗಮ್ಯ);
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (parse_absolute_ಸಮಯ(ಗಮ್ಯ, &cert_valid_ಗಮ್ಯ) != 0)
		fatal("Invalid to time \"%s\"", ಗಮ್ಯ);

	ಆದರೆ (cert_valid_ಗಮ್ಯ <= cert_valid_from)
		fatal("Empty certificate validity interval");
	ಬಿಡುಗಡೆ(from);
}

ಸ್ಥಿರ ಶೂನ್ಯ
ಕೂಡಿಸು_cert_option(ಅಕ್ಷರ *opt)
{
	ಅಕ್ಷರ *val, *cp;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *p;
	ಪೂರ್ಣಾಂಕ iscrit = 0;

	ಆದರೆ (strcasecmp(opt, "clear") == 0)
		certflags_flags = 0;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcasecmp(opt, "no-x11-forwarding") == 0)
		certflags_flags &= ~CERTOPT_X_FWD;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcasecmp(opt, "permit-x11-forwarding") == 0)
		certflags_flags |= CERTOPT_X_FWD;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcasecmp(opt, "no-agent-forwarding") == 0)
		certflags_flags &= ~CERTOPT_AGENT_FWD;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcasecmp(opt, "permit-agent-forwarding") == 0)
		certflags_flags |= CERTOPT_AGENT_FWD;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcasecmp(opt, "no-port-forwarding") == 0)
		certflags_flags &= ~CERTOPT_ಪೋರ್ಟ್_FWD;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcasecmp(opt, "permit-port-forwarding") == 0)
		certflags_flags |= CERTOPT_ಪೋರ್ಟ್_FWD;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcasecmp(opt, "no-pty") == 0)
		certflags_flags &= ~CERTOPT_PTY;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcasecmp(opt, "permit-pty") == 0)
		certflags_flags |= CERTOPT_PTY;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcasecmp(opt, "no-user-rc") == 0)
		certflags_flags &= ~CERTOPT_USER_RC;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcasecmp(opt, "permit-user-rc") == 0)
		certflags_flags |= CERTOPT_USER_RC;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcasecmp(opt, "touch-required") == 0)
		certflags_flags &= ~CERTOPT_NO_REQUIRE_USER_PRESENCE;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcasecmp(opt, "no-touch-required") == 0)
		certflags_flags |= CERTOPT_NO_REQUIRE_USER_PRESENCE;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcasecmp(opt, "no-verify-required") == 0)
		certflags_flags &= ~CERTOPT_REQUIRE_VERIFY;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcasecmp(opt, "verify-required") == 0)
		certflags_flags |= CERTOPT_REQUIRE_VERIFY;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((p = strprefix(opt, "force-command=", 1)) != ಖಾಲಿ) {
		ಆದರೆ (*p == '\0')
			fatal("Empty force-command option");
		ಆದರೆ (certflags_command != ಖಾಲಿ)
			fatal("force-command already specified");
		certflags_command = xstrdup(p);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((p = strprefix(opt, "source-address=", 1)) != ಖಾಲಿ) {
		ಆದರೆ (*p == '\0')
			fatal("Empty source-address option");
		ಆದರೆ (certflags_src_addr != ಖಾಲಿ)
			fatal("source-address already specified");
		ಆದರೆ (addr_ಹೊಂದಿಕೆ_cidr_list(ಖಾಲಿ, p) != 0)
			fatal("Invalid source-address list");
		certflags_src_addr = xstrdup(p);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strprefix(opt, "extension:", 1) != ಖಾಲಿ ||
		    (iscrit = (strprefix(opt, "critical:", 1) != ಖಾಲಿ))) {
		val = xstrdup(strchr(opt, ':') + 1);
		ಆದರೆ ((cp = strchr(val, '=')) != ಖಾಲಿ)
			*cp++ = '\0';
		cert_ext_ಕೂಡಿಸು(val, cp, iscrit);
		ಬಿಡುಗಡೆ(val);
	} ಇಲ್ಲದಿದ್ದರೆ
		fatal("Unsupported certificate option \"%s\"", opt);
}

ಸ್ಥಿರ ಶೂನ್ಯ
show_options(ರಚನೆ sshbuf *optbuf, ಪೂರ್ಣಾಂಕ ಒಳ_critical)
{
	ಅಕ್ಷರ *name, *arg, *hex;
	ರಚನೆ sshbuf *options, *option = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((options = sshbuf_fromb(optbuf)) == ಖಾಲಿ)
		fatal_f("sshbuf_fromb failed");
	ಆಗ (sshbuf_len(options) != 0) {
		sshbuf_free(option);
		option = ಖಾಲಿ;
		ಆದರೆ ((r = sshbuf_get_cstring(options, &name, ಖಾಲಿ)) != 0 ||
		    (r = sshbuf_froms(options, &option)) != 0)
			fatal_fr(r, "parse option");
		ಬರೆ("                %s", name);
		ಆದರೆ (!ಒಳ_critical &&
		    (strcmp(name, "permit-X11-forwarding") == 0 ||
		    strcmp(name, "permit-agent-forwarding") == 0 ||
		    strcmp(name, "permit-port-forwarding") == 0 ||
		    strcmp(name, "permit-pty") == 0 ||
		    strcmp(name, "permit-user-rc") == 0 ||
		    strcmp(name, "no-touch-required") == 0)) {
			ಬರೆ("\n");
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ಒಳ_critical &&
		    (strcmp(name, "force-command") == 0 ||
		    strcmp(name, "source-address") == 0)) {
			ಆದರೆ ((r = sshbuf_get_cstring(option, &arg, ಖಾಲಿ)) != 0)
				fatal_fr(r, "parse critical");
			ಬರೆ(" %s\n", arg);
			ಬಿಡುಗಡೆ(arg);
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ಒಳ_critical &&
		    strcmp(name, "verify-required") == 0) {
			ಬರೆ("\n");
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (sshbuf_len(option) > 0) {
			hex = sshbuf_dtob16(option);
			ಬರೆ(" UNKNOWN OPTION: %s (len %zu)\n",
			    hex, sshbuf_len(option));
			sshbuf_reset(option);
			ಬಿಡುಗಡೆ(hex);
		} ಇಲ್ಲದಿದ್ದರೆ
			ಬರೆ(" UNKNOWN FLAG OPTION\n");
		ಬಿಡುಗಡೆ(name);
		ಆದರೆ (sshbuf_len(option) != 0)
			fatal("Option corrupt: extra data at end");
	}
	sshbuf_free(option);
	sshbuf_free(options);
}

ಸ್ಥಿರ ಶೂನ್ಯ
print_cert(ರಚನೆ sshkey *ಕೀಲಿ)
{
	ಅಕ್ಷರ valid[64], *ಕೀಲಿ_fp, *ca_fp;
	u_int i;

	ಕೀಲಿ_fp = sshkey_fingerprint(ಕೀಲಿ, fingerprint_hash, SSH_FP_DEFAULT);
	ca_fp = sshkey_fingerprint(ಕೀಲಿ->cert->signature_ಕೀಲಿ,
	    fingerprint_hash, SSH_FP_DEFAULT);
	ಆದರೆ (ಕೀಲಿ_fp == ಖಾಲಿ || ca_fp == ಖಾಲಿ)
		fatal_f("sshkey_fingerprint fail");
	sshkey_format_cert_validity(ಕೀಲಿ->cert, valid, ಗಾತ್ರ(valid));

	ಬರೆ("        Type: %s %s certificate\n", sshkey_ssh_name(ಕೀಲಿ),
	    sshkey_cert_type(ಕೀಲಿ));
	ಬರೆ("        Public key: %s %s\n", sshkey_type(ಕೀಲಿ), ಕೀಲಿ_fp);
	ಬರೆ("        Signing CA: %s %s (using %s)\n",
	    sshkey_type(ಕೀಲಿ->cert->signature_ಕೀಲಿ), ca_fp,
	    ಕೀಲಿ->cert->signature_type);
	ಬರೆ("        Key ID: \"%s\"\n", ಕೀಲಿ->cert->ಕೀಲಿ_id);
	ಬರೆ("        Serial: %llu\n", (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ಕೀಲಿ->cert->serial);
	ಬರೆ("        Valid: %s\n", valid);
	ಬರೆ("        Principals: ");
	ಆದರೆ (ಕೀಲಿ->cert->nprincipals == 0)
		ಬರೆ("(none)\n");
	ಇಲ್ಲದಿದ್ದರೆ {
		ಗಾಗಿ (i = 0; i < ಕೀಲಿ->cert->nprincipals; i++)
			ಬರೆ("\n                %s",
			    ಕೀಲಿ->cert->principals[i]);
		ಬರೆ("\n");
	}
	ಬರೆ("        Critical Options: ");
	ಆದರೆ (sshbuf_len(ಕೀಲಿ->cert->critical) == 0)
		ಬರೆ("(none)\n");
	ಇಲ್ಲದಿದ್ದರೆ {
		ಬರೆ("\n");
		show_options(ಕೀಲಿ->cert->critical, 1);
	}
	ಬರೆ("        Extensions: ");
	ಆದರೆ (sshbuf_len(ಕೀಲಿ->cert->extensions) == 0)
		ಬರೆ("(none)\n");
	ಇಲ್ಲದಿದ್ದರೆ {
		ಬರೆ("\n");
		show_options(ಕೀಲಿ->cert->extensions, 0);
	}
	ಬಿಡುಗಡೆ(ಕೀಲಿ_fp);
	ಬಿಡುಗಡೆ(ca_fp);
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_show_cert(ರಚನೆ passwd *pw)
{
	ರಚನೆ sshkey *ಕೀಲಿ = ಖಾಲಿ;
	ರಚನೆ stat st;
	ಪೂರ್ಣಾಂಕ r, is_stdin = 0, ok = 0;
	FILE *f;
	ಅಕ್ಷರ *cp, *ಸಾಲು = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ;
	ಗಾತ್ರ_t linesize = 0;
	u_long lnum = 0;

	ಆದರೆ (!have_ತಟಸ್ಥ)
		ask_filename(pw, "Enter file in which the key is");
	ಆದರೆ (strcmp(ತಟಸ್ಥ_file, "-") != 0 && stat(ತಟಸ್ಥ_file, &st) == -1)
		fatal("%s: %s: %s", __progname, ತಟಸ್ಥ_file, strerror(errno));

	ಮಾರ್ಗ = ತಟಸ್ಥ_file;
	ಆದರೆ (strcmp(ಮಾರ್ಗ, "-") == 0) {
		f = stdin;
		ಮಾರ್ಗ = "(stdin)";
		is_stdin = 1;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((f = fopen(ತಟಸ್ಥ_file, "r")) == ಖಾಲಿ)
		fatal("fopen %s: %s", ತಟಸ್ಥ_file, strerror(errno));

	ಆಗ (getline(&ಸಾಲು, &linesize, f) != -1) {
		lnum++;
		sshkey_free(ಕೀಲಿ);
		ಕೀಲಿ = ಖಾಲಿ;
		/* Trim leading space and comments */
		cp = ಸಾಲು + strspn(ಸಾಲು, " \t");
		ಆದರೆ (*cp == '#' || *cp == '\0')
			ಮುಂದುವರಿ;
		ಆದರೆ ((ಕೀಲಿ = sshkey_new(ಕೀಲಿ_UNSPEC)) == ಖಾಲಿ)
			fatal("sshkey_new");
		ಆದರೆ ((r = sshkey_read(ಕೀಲಿ, &cp)) != 0) {
			error_r(r, "%s:%lu: invalid key", ಮಾರ್ಗ, lnum);
			ಮುಂದುವರಿ;
		}
		ಆದರೆ (!sshkey_is_cert(ಕೀಲಿ)) {
			error("%s:%lu is not a certificate", ಮಾರ್ಗ, lnum);
			ಮುಂದುವರಿ;
		}
		ok = 1;
		ಆದರೆ (!is_stdin && lnum == 1)
			ಬರೆ("%s:\n", ಮಾರ್ಗ);
		ಇಲ್ಲದಿದ್ದರೆ
			ಬರೆ("%s:%lu:\n", ಮಾರ್ಗ, lnum);
		print_cert(ಕೀಲಿ);
	}
	ಬಿಡುಗಡೆ(ಸಾಲು);
	sshkey_free(ಕೀಲಿ);
	fclose(f);
	ನಿರ್ಗಮಿಸು(ok ? 0 : 1);
}

ಸ್ಥಿರ ಶೂನ್ಯ
ತುಂಬು_krl(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, ರಚನೆ ssh_krl **krlp)
{
	ರಚನೆ sshbuf *krlbuf;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshbuf_ತುಂಬು_file(ಮಾರ್ಗ, &krlbuf)) != 0)
		fatal_r(r, "Unable to load KRL %s", ಮಾರ್ಗ);
	/* XXX check sigs */
	ಆದರೆ ((r = ssh_krl_from_blob(krlbuf, krlp)) != 0 ||
	    *krlp == ಖಾಲಿ)
		fatal_r(r, "Invalid KRL file %s", ಮಾರ್ಗ);
	sshbuf_free(krlbuf);
}

ಸ್ಥಿರ ಶೂನ್ಯ
hash_ಗಮ್ಯ_blob(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *cp, u_char **blobp, ಗಾತ್ರ_t *lenp,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, u_long lnum)
{
	ಅಕ್ಷರ *tmp;
	ಗಾತ್ರ_t tlen;
	ರಚನೆ sshbuf *b;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((cp = strprefix(cp, "SHA256:", 0)) == ಖಾಲಿ)
		fatal("%s:%lu: unsupported hash algorithm", file, lnum);

	/*
	 * OpenSSH base64 hashes omit trailing '='
	 * characters; put them back for decode.
	 */
	ಆದರೆ ((tlen = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(cp)) >= SIZE_MAX - 5)
		fatal_f("hash too long: %zu bytes", tlen);
	tmp = xmalloc(tlen + 4 + 1);
	strlcpy(tmp, cp, tlen + 1);
	ಆಗ ((tlen % 4) != 0) {
		tmp[tlen++] = '=';
		tmp[tlen] = '\0';
	}
	ಆದರೆ ((b = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = sshbuf_b64tod(b, tmp)) != 0)
		fatal_r(r, "%s:%lu: decode hash failed", file, lnum);
	ಬಿಡುಗಡೆ(tmp);
	*lenp = sshbuf_len(b);
	*blobp = xmalloc(*lenp);
	ಸ್ಮರಣೆ_ನಕಲು(*blobp, sshbuf_ptr(b), *lenp);
	sshbuf_free(b);
}

ಸ್ಥಿರ ಶೂನ್ಯ
update_krl_from_file(ರಚನೆ passwd *pw, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಪೂರ್ಣಾಂಕ wild_ca,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ca, ರಚನೆ ssh_krl *krl)
{
	ರಚನೆ sshkey *ಕೀಲಿ = ಖಾಲಿ;
	u_long lnum = 0;
	ಅಕ್ಷರ *ಮಾರ್ಗ, *cp, *ep, *ಸಾಲು = ಖಾಲಿ;
	u_char *blob = ಖಾಲಿ;
	ಗಾತ್ರ_t blen = 0, linesize = 0;
	ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ serial, serial2;
	ಪೂರ್ಣಾಂಕ i, was_explicit_ಕೀಲಿ, was_sha1, was_sha256, was_hash, r;
	FILE *krl_spec;

	ಮಾರ್ಗ = tilde_expand_filename(file, pw->pw_uid);
	ಆದರೆ (strcmp(ಮಾರ್ಗ, "-") == 0) {
		krl_spec = stdin;
		ಬಿಡುಗಡೆ(ಮಾರ್ಗ);
		ಮಾರ್ಗ = xstrdup("(standard input)");
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((krl_spec = fopen(ಮಾರ್ಗ, "r")) == ಖಾಲಿ)
		fatal("fopen %s: %s", ಮಾರ್ಗ, strerror(errno));

	ಆದರೆ (!quiet)
		ಬರೆ("Revoking from %s\n", ಮಾರ್ಗ);
	ಆಗ (getline(&ಸಾಲು, &linesize, krl_spec) != -1) {
		ಆದರೆ (linesize >= ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ) {
			fatal_f("%s contains unparsable line, len=%zu",
			    ಮಾರ್ಗ, linesize);
		}
		lnum++;
		was_explicit_ಕೀಲಿ = was_sha1 = was_sha256 = was_hash = 0;
		cp = ಸಾಲು + strspn(ಸಾಲು, " \t");
		/* Trim trailing space, comments and strip \n */
		ಗಾಗಿ (i = 0, r = -1; cp[i] != '\0'; i++) {
			ಆದರೆ (cp[i] == '#' || cp[i] == '\n') {
				cp[i] = '\0';
				ನಿಲ್ಲಿಸು;
			}
			ಆದರೆ (cp[i] == ' ' || cp[i] == '\t') {
				/* Remember the start of a span of whitespace */
				ಆದರೆ (r == -1)
					r = i;
			} ಇಲ್ಲದಿದ್ದರೆ
				r = -1;
		}
		ಆದರೆ (r != -1)
			cp[r] = '\0';
		ಆದರೆ (*cp == '\0')
			ಮುಂದುವರಿ;
		ಆದರೆ (strncasecmp(cp, "serial:", 7) == 0) {
			ಆದರೆ (ca == ಖಾಲಿ && !wild_ca) {
				fatal("revoking certificates by serial number "
				    "requires specification of a CA key");
			}
			cp += 7;
			cp = cp + strspn(cp, " \t");
			errno = 0;
			serial = strtoull(cp, &ep, 0);
			ಆದರೆ (*cp == '\0' || (*ep != '\0' && *ep != '-'))
				fatal("%s:%lu: invalid serial \"%s\"",
				    ಮಾರ್ಗ, lnum, cp);
			ಆದರೆ (errno == ERANGE && serial == ULLONG_MAX)
				fatal("%s:%lu: serial out of range",
				    ಮಾರ್ಗ, lnum);
			serial2 = serial;
			ಆದರೆ (*ep == '-') {
				cp = ep + 1;
				errno = 0;
				serial2 = strtoull(cp, &ep, 0);
				ಆದರೆ (*cp == '\0' || *ep != '\0')
					fatal("%s:%lu: invalid serial \"%s\"",
					    ಮಾರ್ಗ, lnum, cp);
				ಆದರೆ (errno == ERANGE && serial2 == ULLONG_MAX)
					fatal("%s:%lu: serial out of range",
					    ಮಾರ್ಗ, lnum);
				ಆದರೆ (serial2 <= serial)
					fatal("%s:%lu: invalid serial range "
					    "%llu:%llu", ಮಾರ್ಗ, lnum,
					    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)serial,
					    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)serial2);
			}
			ಆದರೆ (ssh_krl_revoke_cert_by_serial_range(krl,
			    ca, serial, serial2) != 0) {
				fatal_f("revoke serial failed");
			}
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strncasecmp(cp, "id:", 3) == 0) {
			ಆದರೆ (ca == ಖಾಲಿ && !wild_ca) {
				fatal("revoking certificates by key ID "
				    "requires specification of a CA key");
			}
			cp += 3;
			cp = cp + strspn(cp, " \t");
			ಆದರೆ (ssh_krl_revoke_cert_by_ಕೀಲಿ_id(krl, ca, cp) != 0)
				fatal_f("revoke key ID failed");
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strncasecmp(cp, "hash:", 5) == 0) {
			cp += 5;
			cp = cp + strspn(cp, " \t");
			hash_ಗಮ್ಯ_blob(cp, &blob, &blen, file, lnum);
			ಆದರೆ ((r = ssh_krl_revoke_ಕೀಲಿ_sha256(krl,
			    blob, blen)) != 0)
				fatal_fr(r, "revoke key failed");
			ಬಿಡುಗಡೆ(blob);
			blob = ಖಾಲಿ;
			blen = 0;
		} ಇಲ್ಲದಿದ್ದರೆ {
			ಆದರೆ (strncasecmp(cp, "key:", 4) == 0) {
				cp += 4;
				cp = cp + strspn(cp, " \t");
				was_explicit_ಕೀಲಿ = 1;
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strncasecmp(cp, "sha1:", 5) == 0) {
				cp += 5;
				cp = cp + strspn(cp, " \t");
				was_sha1 = 1;
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strncasecmp(cp, "sha256:", 7) == 0) {
				cp += 7;
				cp = cp + strspn(cp, " \t");
				was_sha256 = 1;
				/*
				 * Just try to process the line as a key.
				 * Parsing will fail if it isn't.
				 */
			}
			ಆದರೆ ((ಕೀಲಿ = sshkey_new(ಕೀಲಿ_UNSPEC)) == ಖಾಲಿ)
				fatal("sshkey_new");
			ಆದರೆ ((r = sshkey_read(ಕೀಲಿ, &cp)) != 0)
				fatal_r(r, "%s:%lu: invalid key", ಮಾರ್ಗ, lnum);
			ಆದರೆ (was_explicit_ಕೀಲಿ)
				r = ssh_krl_revoke_ಕೀಲಿ_explicit(krl, ಕೀಲಿ);
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (was_sha1) {
				ಆದರೆ (sshkey_fingerprint_raw(ಕೀಲಿ,
				    SSH_DIGEST_SHA1, &blob, &blen) != 0) {
					fatal("%s:%lu: fingerprint failed",
					    file, lnum);
				}
				r = ssh_krl_revoke_ಕೀಲಿ_sha1(krl, blob, blen);
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (was_sha256) {
				ಆದರೆ (sshkey_fingerprint_raw(ಕೀಲಿ,
				    SSH_DIGEST_SHA256, &blob, &blen) != 0) {
					fatal("%s:%lu: fingerprint failed",
					    file, lnum);
				}
				r = ssh_krl_revoke_ಕೀಲಿ_sha256(krl, blob, blen);
			} ಇಲ್ಲದಿದ್ದರೆ
				r = ssh_krl_revoke_ಕೀಲಿ(krl, ಕೀಲಿ);
			ಆದರೆ (r != 0)
				fatal_fr(r, "revoke key failed");
			freezero(blob, blen);
			blob = ಖಾಲಿ;
			blen = 0;
			sshkey_free(ಕೀಲಿ);
		}
	}
	ಆದರೆ (strcmp(ಮಾರ್ಗ, "-") != 0)
		fclose(krl_spec);
	ಬಿಡುಗಡೆ(ಸಾಲು);
	ಬಿಡುಗಡೆ(ಮಾರ್ಗ);
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_gen_krl(ರಚನೆ passwd *pw, ಪೂರ್ಣಾಂಕ updating, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ca_ಕೀಲಿ_ಮಾರ್ಗ,
    ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ krl_ಆವೃತ್ತಿ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *krl_comment,
    ಪೂರ್ಣಾಂಕ argc, ಅಕ್ಷರ **argv)
{
	ರಚನೆ ssh_krl *krl;
	ರಚನೆ stat sb;
	ರಚನೆ sshkey *ca = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ i, r, wild_ca = 0;
	ಅಕ್ಷರ *tmp;
	ರಚನೆ sshbuf *kbuf;

	ಆದರೆ (*ತಟಸ್ಥ_file == '\0')
		fatal("KRL generation requires an output file");
	ಆದರೆ (stat(ತಟಸ್ಥ_file, &sb) == -1) {
		ಆದರೆ (errno != ENOENT)
			fatal("Cannot access KRL \"%s\": %s",
			    ತಟಸ್ಥ_file, strerror(errno));
		ಆದರೆ (updating)
			fatal("KRL \"%s\" does not exist", ತಟಸ್ಥ_file);
	}
	ಆದರೆ (ca_ಕೀಲಿ_ಮಾರ್ಗ != ಖಾಲಿ) {
		ಆದರೆ (strcasecmp(ca_ಕೀಲಿ_ಮಾರ್ಗ, "none") == 0)
			wild_ca = 1;
		ಇಲ್ಲದಿದ್ದರೆ {
			tmp = tilde_expand_filename(ca_ಕೀಲಿ_ಮಾರ್ಗ, pw->pw_uid);
			ಆದರೆ ((r = sshkey_ತುಂಬು_ಬಹಿರಂಗ(tmp, &ca, ಖಾಲಿ)) != 0)
				fatal_r(r, "Cannot load CA public key %s", tmp);
			ಬಿಡುಗಡೆ(tmp);
		}
	}

	ಆದರೆ (updating)
		ತುಂಬು_krl(ತಟಸ್ಥ_file, &krl);
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((krl = ssh_krl_init()) == ಖಾಲಿ)
		fatal("couldn't create KRL");

	ಆದರೆ (krl_ಆವೃತ್ತಿ != 0)
		ssh_krl_ಗಣ_ಆವೃತ್ತಿ(krl, krl_ಆವೃತ್ತಿ);
	ಆದರೆ (krl_comment != ಖಾಲಿ)
		ssh_krl_ಗಣ_comment(krl, krl_comment);

	ಗಾಗಿ (i = 0; i < argc; i++)
		update_krl_from_file(pw, argv[i], wild_ca, ca, krl);

	ಆದರೆ ((kbuf = sshbuf_new()) == ಖಾಲಿ)
		fatal("sshbuf_new failed");
	ಆದರೆ (ssh_krl_ಗಮ್ಯ_blob(krl, kbuf) != 0)
		fatal("Couldn't generate KRL");
	ಆದರೆ ((r = sshbuf_write_file(ತಟಸ್ಥ_file, kbuf)) != 0)
		fatal("write %s: %s", ತಟಸ್ಥ_file, strerror(errno));
	sshbuf_free(kbuf);
	ssh_krl_free(krl);
	sshkey_free(ca);
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_check_krl(ರಚನೆ passwd *pw, ಪೂರ್ಣಾಂಕ print_krl, ಪೂರ್ಣಾಂಕ argc, ಅಕ್ಷರ **argv)
{
	ಪೂರ್ಣಾಂಕ i, r, ret = 0;
	ಅಕ್ಷರ *comment;
	ರಚನೆ ssh_krl *krl;
	ರಚನೆ sshkey *k;

	ಆದರೆ (*ತಟಸ್ಥ_file == '\0')
		fatal("KRL checking requires an input file");
	ತುಂಬು_krl(ತಟಸ್ಥ_file, &krl);
	ಆದರೆ (print_krl)
		krl_dump(krl, stdout);
	ಗಾಗಿ (i = 0; i < argc; i++) {
		ಆದರೆ ((r = sshkey_ತುಂಬು_ಬಹಿರಂಗ(argv[i], &k, &comment)) != 0)
			fatal_r(r, "Cannot load public key %s", argv[i]);
		r = ssh_krl_check_ಕೀಲಿ(krl, k);
		ಬರೆ("%s%s%s%s: %s\n", argv[i],
		    *comment ? " (" : "", comment, *comment ? ")" : "",
		    r == 0 ? "ok" : "REVOKED");
		ಆದರೆ (r != 0)
			ret = 1;
		sshkey_free(k);
		ಬಿಡುಗಡೆ(comment);
	}
	ssh_krl_free(krl);
	ನಿರ್ಗಮಿಸು(ret);
}

ಸ್ಥಿರ ರಚನೆ sshkey *
ತುಂಬು_sign_ಕೀಲಿ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *keypath, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *pubkey)
{
	ಗಾತ್ರ_t i, slen, plen = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(keypath);
	ಅಕ್ಷರ *privpath = xstrdup(keypath);
	ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ * ಸ್ಥಿರಾಂಕ suffixes[] = { "-cert.pub", ".pub", ಖಾಲಿ };
	ರಚನೆ sshkey *ret = ಖಾಲಿ, *privkey = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r, waspub = 0;
	ರಚನೆ stat st;

	/*
	 * If passed a public key filename, then try to locate the corresponding
	 * private key. This lets us specify certificates on the command-line
	 * and have ssh-keygen find the appropriate private key.
	 */
	ಗಾಗಿ (i = 0; suffixes[i]; i++) {
		slen = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(suffixes[i]);
		ಆದರೆ (plen <= slen ||
		    strcmp(privpath + plen - slen, suffixes[i]) != 0)
			ಮುಂದುವರಿ;
		privpath[plen - slen] = '\0';
		debug_f("%s looks like a public key, using private key "
		    "path %s instead", keypath, privpath);
		waspub = 1;
	}
	ಆದರೆ (waspub && stat(privpath, &st) != 0 && errno == ENOENT)
		fatal("No private key found for public key \"%s\"", keypath);
	ಆದರೆ ((r = sshkey_ತುಂಬು_ಖಾಸಗಿ(privpath, "", &privkey, ಖಾಲಿ)) != 0 &&
	    (r != SSH_ERR_ಕೀಲಿ_WRONG_PASSPHRASE)) {
		debug_fr(r, "load private key \"%s\"", privpath);
		fatal("No private key found for \"%s\"", privpath);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (privkey == ಖಾಲಿ)
		privkey = ತುಂಬು_ತಟಸ್ಥ(privpath, ಖಾಲಿ);

	ಆದರೆ (!sshkey_equal_ಬಹಿರಂಗ(pubkey, privkey)) {
		error("Public key %s doesn't match private %s",
		    keypath, privpath);
		ಹೋಗು ಮುಗಿದ;
	}
	ಆದರೆ (sshkey_is_cert(pubkey) && !sshkey_is_cert(privkey)) {
		/*
		 * Graft the certificate onto the private key to make
		 * it capable of signing.
		 */
		ಆದರೆ ((r = sshkey_ಗಮ್ಯ_certified(privkey)) != 0) {
			error_fr(r, "sshkey_to_certified");
			ಹೋಗು ಮುಗಿದ;
		}
		ಆದರೆ ((r = sshkey_cert_copy(pubkey, privkey)) != 0) {
			error_fr(r, "sshkey_cert_copy");
			ಹೋಗು ಮುಗಿದ;
		}
	}
	/* success */
	ret = privkey;
	privkey = ಖಾಲಿ;
 ಮುಗಿದ:
	sshkey_free(privkey);
	ಬಿಡುಗಡೆ(privpath);
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sign_one(ರಚನೆ sshkey *signkey, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename, ಪೂರ್ಣಾಂಕ fd,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sig_namespace, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *hashalg, sshsig_signer *signer,
    ಶೂನ್ಯ *signer_ctx)
{
	ರಚನೆ sshbuf *sigbuf = ಖಾಲಿ, *abuf = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR, wfd = -1, oerrno;
	ಅಕ್ಷರ *wfile = ಖಾಲಿ, *asig = ಖಾಲಿ, *fp = ಖಾಲಿ;
	ಅಕ್ಷರ *pin = ಖಾಲಿ, *prompt = ಖಾಲಿ;

	ಆದರೆ (!quiet) {
		ಆದರೆ (fd == STDIN_FILENO)
			fprintf(stderr, "Signing data on standard input\n");
		ಇಲ್ಲದಿದ್ದರೆ
			fprintf(stderr, "Signing file %s\n", filename);
	}
	ಆದರೆ (signer == ಖಾಲಿ && sshkey_is_sk(signkey)) {
		ಆದರೆ ((signkey->sk_flags & SSH_SK_USER_VERIFICATION_REQD)) {
			xasprintf(&prompt, "Enter PIN for %s key: ",
			    sshkey_type(signkey));
			ಆದರೆ ((pin = read_passphrase(prompt,
			    RP_ALLOW_STDIN)) == ಖಾಲಿ)
				fatal_f("couldn't read PIN");
		}
		ಆದರೆ ((signkey->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
			ಆದರೆ ((fp = sshkey_fingerprint(signkey, fingerprint_hash,
			    SSH_FP_DEFAULT)) == ಖಾಲಿ)
				fatal_f("fingerprint failed");
			fprintf(stderr, "Confirm user presence for key %s %s\n",
			    sshkey_type(signkey), fp);
			ಬಿಡುಗಡೆ(fp);
		}
	}
	ಆದರೆ ((r = sshsig_sign_fd(signkey, hashalg, sk_provider, pin,
	    fd, sig_namespace, &sigbuf, signer, signer_ctx)) != 0) {
		error_r(r, "Signing %s failed", filename);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshsig_armor(sigbuf, &abuf)) != 0) {
		error_fr(r, "sshsig_armor");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((asig = sshbuf_dup_string(abuf)) == ಖಾಲಿ) {
		error_f("buffer error");
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ (fd == STDIN_FILENO) {
		fputs(asig, stdout);
		fflush(stdout);
	} ಇಲ್ಲದಿದ್ದರೆ {
		xasprintf(&wfile, "%s.sig", filename);
		ಆದರೆ (confirm_overwrite(wfile)) {
			ಆದರೆ ((wfd = open(wfile, O_WRONLY|O_CREAT|O_TRUNC,
			    0666)) == -1) {
				oerrno = errno;
				error("Cannot open %s: %s",
				    wfile, strerror(errno));
				errno = oerrno;
				r = SSH_ERR_SYSTEM_ERROR;
				ಹೋಗು ಹೊರಹೋಗು;
			}
			ಆದರೆ (atomicio(vwrite, wfd, asig,
			    ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(asig)) != ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(asig)) {
				oerrno = errno;
				error("Cannot write to %s: %s",
				    wfile, strerror(errno));
				errno = oerrno;
				r = SSH_ERR_SYSTEM_ERROR;
				ಹೋಗು ಹೊರಹೋಗು;
			}
			ಆದರೆ (!quiet) {
				fprintf(stderr, "Write signature to %s\n",
				    wfile);
			}
		}
	}
	/* success */
	r = 0;
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(wfile);
	ಬಿಡುಗಡೆ(prompt);
	ಬಿಡುಗಡೆ(asig);
	ಆದರೆ (pin != ಖಾಲಿ)
		freezero(pin, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(pin));
	sshbuf_free(abuf);
	sshbuf_free(sigbuf);
	ಆದರೆ (wfd != -1)
		close(wfd);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sig_process_opts(ಅಕ್ಷರ * ಸ್ಥಿರಾಂಕ *opts, ಗಾತ್ರ_t nopts, ಅಕ್ಷರ **hashalgp,
    uint64_t *verify_timep, ಪೂರ್ಣಾಂಕ *print_pubkey)
{
	ಗಾತ್ರ_t i;
	time_t now;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *p;

	ಆದರೆ (verify_timep != ಖಾಲಿ)
		*verify_timep = 0;
	ಆದರೆ (print_pubkey != ಖಾಲಿ)
		*print_pubkey = 0;
	ಆದರೆ (hashalgp != ಖಾಲಿ)
		*hashalgp = ಖಾಲಿ;
	ಗಾಗಿ (i = 0; i < nopts; i++) {
		ಆದರೆ (hashalgp != ಖಾಲಿ &&
		    (p = strprefix(opts[i], "hashalg=", 1)) != ಖಾಲಿ) {
			*hashalgp = xstrdup(p);
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (verify_timep &&
		    (p = strprefix(opts[i], "verify-time=", 1)) != ಖಾಲಿ) {
			ಆದರೆ (parse_absolute_ಸಮಯ(p, verify_timep) != 0 ||
			    *verify_timep == 0) {
				error("Invalid \"verify-time\" option");
				ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
			}
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (print_pubkey &&
		    strcasecmp(opts[i], "print-pubkey") == 0) {
			*print_pubkey = 1;
		} ಇಲ್ಲದಿದ್ದರೆ {
			error("Invalid option \"%s\"", opts[i]);
			ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
		}
	}
	ಆದರೆ (verify_timep && *verify_timep == 0) {
		ಆದರೆ ((now = time(ಖಾಲಿ)) < 0) {
			error("Time is before epoch");
			ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
		}
		*verify_timep = (uint64_t)now;
	}
	ಹಿಂತಿರುಗಿ 0;
}


ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sig_sign(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *keypath, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sig_namespace, ಪೂರ್ಣಾಂಕ require_agent,
    ಪೂರ್ಣಾಂಕ argc, ಅಕ್ಷರ **argv, ಅಕ್ಷರ * ಸ್ಥಿರಾಂಕ *opts, ಗಾತ್ರ_t nopts)
{
	ಪೂರ್ಣಾಂಕ i, fd = -1, r, ret = -1;
	ಪೂರ್ಣಾಂಕ agent_fd = -1;
	ರಚನೆ sshkey *pubkey = ಖಾಲಿ, *privkey = ಖಾಲಿ, *signkey = ಖಾಲಿ;
	sshsig_signer *signer = ಖಾಲಿ;
	ಅಕ್ಷರ *hashalg = ಖಾಲಿ;

	/* Check file arguments. */
	ಗಾಗಿ (i = 0; i < argc; i++) {
		ಆದರೆ (strcmp(argv[i], "-") != 0)
			ಮುಂದುವರಿ;
		ಆದರೆ (i > 0 || argc > 1)
			fatal("Cannot sign mix of paths and standard input");
	}

	ಆದರೆ (sig_process_opts(opts, nopts, &hashalg, ಖಾಲಿ, ಖಾಲಿ) != 0)
		ಹೋಗು ಮುಗಿದ; /* error already logged */

	ಆದರೆ ((r = sshkey_ತುಂಬು_ಬಹಿರಂಗ(keypath, &pubkey, ಖಾಲಿ)) != 0) {
		error_r(r, "Couldn't load public key %s", keypath);
		ಹೋಗು ಮುಗಿದ;
	}

	ಆದರೆ ((r = ssh_get_authentication_socket(&agent_fd)) != 0) {
		ಆದರೆ (require_agent)
			fatal("Couldn't get agent socket");
		debug_r(r, "Couldn't get agent socket");
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ ((r = ssh_agent_has_ಕೀಲಿ(agent_fd, pubkey)) == 0)
			signer = agent_signer;
		ಇಲ್ಲದಿದ್ದರೆ {
			ಆದರೆ (require_agent)
				fatal("Couldn't find key in agent");
			debug_r(r, "Couldn't find key in agent");
		}
	}

	ಆದರೆ (signer == ಖಾಲಿ) {
		/* Not using agent - try to load private key */
		ಆದರೆ ((privkey = ತುಂಬು_sign_ಕೀಲಿ(keypath, pubkey)) == ಖಾಲಿ)
			ಹೋಗು ಮುಗಿದ;
		signkey = privkey;
	} ಇಲ್ಲದಿದ್ದರೆ {
		/* Will use key in agent */
		signkey = pubkey;
	}

	ಆದರೆ (argc == 0) {
		ಆದರೆ ((r = sign_one(signkey, "(stdin)", STDIN_FILENO,
		    sig_namespace, hashalg, signer, &agent_fd)) != 0)
			ಹೋಗು ಮುಗಿದ;
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಗಾಗಿ (i = 0; i < argc; i++) {
			ಆದರೆ (strcmp(argv[i], "-") == 0)
				fd = STDIN_FILENO;
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((fd = open(argv[i], O_RDONLY)) == -1) {
				error("Cannot open %s for signing: %s",
				    argv[i], strerror(errno));
				ಹೋಗು ಮುಗಿದ;
			}
			ಆದರೆ ((r = sign_one(signkey, argv[i], fd, sig_namespace,
			    hashalg, signer, &agent_fd)) != 0)
				ಹೋಗು ಮುಗಿದ;
			ಆದರೆ (fd != STDIN_FILENO)
				close(fd);
			fd = -1;
		}
	}

	ret = 0;
ಮುಗಿದ:
	ಆದರೆ (fd != -1 && fd != STDIN_FILENO)
		close(fd);
	sshkey_free(pubkey);
	sshkey_free(privkey);
	ಬಿಡುಗಡೆ(hashalg);
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sig_verify(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *signature, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sig_namespace,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *principal, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *allowed_ಕೀಲಿಗಳು, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *revoked_ಕೀಲಿಗಳು,
    ಅಕ್ಷರ * ಸ್ಥಿರಾಂಕ *opts, ಗಾತ್ರ_t nopts)
{
	ಪೂರ್ಣಾಂಕ r, ret = -1;
	ಪೂರ್ಣಾಂಕ print_pubkey = 0;
	ರಚನೆ sshbuf *sigbuf = ಖಾಲಿ, *abuf = ಖಾಲಿ;
	ರಚನೆ sshkey *sign_ಕೀಲಿ = ಖಾಲಿ;
	ಅಕ್ಷರ *fp = ಖಾಲಿ;
	ರಚನೆ sshkey_sig_details *sig_details = ಖಾಲಿ;
	uint64_t verify_ಸಮಯ = 0;

	ಆದರೆ (sig_process_opts(opts, nopts, ಖಾಲಿ, &verify_ಸಮಯ,
	    &print_pubkey) != 0)
		ಹೋಗು ಮುಗಿದ; /* error already logged */

	memset(&sig_details, 0, ಗಾತ್ರ(sig_details));
	ಆದರೆ ((r = sshbuf_ತುಂಬು_file(signature, &abuf)) != 0) {
		error_r(r, "Couldn't read signature file");
		ಹೋಗು ಮುಗಿದ;
	}

	ಆದರೆ ((r = sshsig_dearmor(abuf, &sigbuf)) != 0) {
		error_fr(r, "sshsig_armor");
		ಹೋಗು ಮುಗಿದ;
	}
	ಆದರೆ ((r = sshsig_verify_fd(sigbuf, STDIN_FILENO, sig_namespace,
	    &sign_ಕೀಲಿ, &sig_details)) != 0)
		ಹೋಗು ಮುಗಿದ; /* sshsig_verify() prints error */

	ಆದರೆ ((fp = sshkey_fingerprint(sign_ಕೀಲಿ, fingerprint_hash,
	    SSH_FP_DEFAULT)) == ಖಾಲಿ)
		fatal_f("sshkey_fingerprint failed");
	debug("Valid (unverified) signature from key %s", fp);
	ಆದರೆ (sig_details != ಖಾಲಿ) {
		debug2_f("signature details: counter = %u, flags = 0x%02x",
		    sig_details->sk_counter, sig_details->sk_flags);
	}
	ಬಿಡುಗಡೆ(fp);
	fp = ಖಾಲಿ;

	ಆದರೆ (revoked_ಕೀಲಿಗಳು != ಖಾಲಿ) {
		ಆದರೆ ((r = sshkey_check_revoked(sign_ಕೀಲಿ, revoked_ಕೀಲಿಗಳು)) != 0) {
			debug3_fr(r, "sshkey_check_revoked");
			ಹೋಗು ಮುಗಿದ;
		}
	}

	ಆದರೆ (allowed_ಕೀಲಿಗಳು != ಖಾಲಿ && (r = sshsig_check_allowed_ಕೀಲಿಗಳು(allowed_ಕೀಲಿಗಳು,
	    sign_ಕೀಲಿ, principal, sig_namespace, verify_ಸಮಯ)) != 0) {
		debug3_fr(r, "sshsig_check_allowed_keys");
		ಹೋಗು ಮುಗಿದ;
	}
	/* success */
	ret = 0;
ಮುಗಿದ:
	ಆದರೆ (!quiet) {
		ಆದರೆ (ret == 0) {
			ಆದರೆ ((fp = sshkey_fingerprint(sign_ಕೀಲಿ, fingerprint_hash,
			    SSH_FP_DEFAULT)) == ಖಾಲಿ)
				fatal_f("sshkey_fingerprint failed");
			ಆದರೆ (principal == ಖಾಲಿ) {
				ಬರೆ("Good \"%s\" signature with %s key %s\n",
				    sig_namespace, sshkey_type(sign_ಕೀಲಿ), fp);

			} ಇಲ್ಲದಿದ್ದರೆ {
				ಬರೆ("Good \"%s\" signature for %s with %s key %s\n",
				    sig_namespace, principal,
				    sshkey_type(sign_ಕೀಲಿ), fp);
			}
		} ಇಲ್ಲದಿದ್ದರೆ {
			ಬರೆ("Could not verify signature.\n");
		}
	}
	/* Print the signature key if requested */
	ಆದರೆ (ret == 0 && print_pubkey && sign_ಕೀಲಿ != ಖಾಲಿ) {
		ಆದರೆ ((r = sshkey_write(sign_ಕೀಲಿ, stdout)) == 0)
			fputc('\n', stdout);
		ಇಲ್ಲದಿದ್ದರೆ {
			error_r(r, "Could not print public key.\n");
			ret = -1;
		}
	}
	sshbuf_free(sigbuf);
	sshbuf_free(abuf);
	sshkey_free(sign_ಕೀಲಿ);
	sshkey_sig_details_free(sig_details);
	ಬಿಡುಗಡೆ(fp);
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sig_ಕಂಡುಹಿಡಿ_principals(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *signature, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *allowed_ಕೀಲಿಗಳು,
    ಅಕ್ಷರ * ಸ್ಥಿರಾಂಕ *opts, ಗಾತ್ರ_t nopts)
{
	ಪೂರ್ಣಾಂಕ r, ret = -1;
	ರಚನೆ sshbuf *sigbuf = ಖಾಲಿ, *abuf = ಖಾಲಿ;
	ರಚನೆ sshkey *sign_ಕೀಲಿ = ಖಾಲಿ;
	ಅಕ್ಷರ *principals = ಖಾಲಿ, *cp, *tmp;
	uint64_t verify_ಸಮಯ = 0;

	ಆದರೆ (sig_process_opts(opts, nopts, ಖಾಲಿ, &verify_ಸಮಯ, ಖಾಲಿ) != 0)
		ಹೋಗು ಮುಗಿದ; /* error already logged */

	ಆದರೆ ((r = sshbuf_ತುಂಬು_file(signature, &abuf)) != 0) {
		error_r(r, "Couldn't read signature file");
		ಹೋಗು ಮುಗಿದ;
	}
	ಆದರೆ ((r = sshsig_dearmor(abuf, &sigbuf)) != 0) {
		error_fr(r, "sshsig_armor");
		ಹೋಗು ಮುಗಿದ;
	}
	ಆದರೆ ((r = sshsig_get_pubkey(sigbuf, &sign_ಕೀಲಿ)) != 0) {
		error_fr(r, "sshsig_get_pubkey");
		ಹೋಗು ಮುಗಿದ;
	}
	ಆದರೆ ((r = sshsig_ಕಂಡುಹಿಡಿ_principals(allowed_ಕೀಲಿಗಳು, sign_ಕೀಲಿ,
	    verify_ಸಮಯ, &principals)) != 0) {
		ಆದರೆ (r != SSH_ERR_ಕೀಲಿ_NOT_ಸಿಕ್ಕಿತು)
			error_fr(r, "sshsig_find_principal");
		ಹೋಗು ಮುಗಿದ;
	}
	ret = 0;
ಮುಗಿದ:
	ಆದರೆ (ret == 0 ) {
		/* Emit matching principals one per line */
		tmp = principals;
		ಆಗ ((cp = strsep(&tmp, ",")) != ಖಾಲಿ && *cp != '\0')
			puts(cp);
	} ಇಲ್ಲದಿದ್ದರೆ {
		fprintf(stderr, "No principal matched.\n");
	}
	sshbuf_free(sigbuf);
	sshbuf_free(abuf);
	sshkey_free(sign_ಕೀಲಿ);
	ಬಿಡುಗಡೆ(principals);
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sig_ಹೊಂದಿಕೆ_principals(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *allowed_ಕೀಲಿಗಳು, ಅಕ್ಷರ *principal,
	ಅಕ್ಷರ * ಸ್ಥಿರಾಂಕ *opts, ಗಾತ್ರ_t nopts)
{
	ಪೂರ್ಣಾಂಕ r;
	ಅಕ್ಷರ **principals = ಖಾಲಿ;
	ಗಾತ್ರ_t i, nprincipals = 0;

	ಆದರೆ ((r = sig_process_opts(opts, nopts, ಖಾಲಿ, ಖಾಲಿ, ಖಾಲಿ)) != 0)
		ಹಿಂತಿರುಗಿ r; /* error already logged */

	ಆದರೆ ((r = sshsig_ಹೊಂದಿಕೆ_principals(allowed_ಕೀಲಿಗಳು, principal,
	    &principals, &nprincipals)) != 0) {
		debug_f("match: %s", ssh_err(r));
		fprintf(stderr, "No principal matched.\n");
		ಹಿಂತಿರುಗಿ r;
	}
	ಗಾಗಿ (i = 0; i < nprincipals; i++) {
		ಬರೆ("%s\n", principals[i]);
		ಬಿಡುಗಡೆ(principals[i]);
	}
	ಬಿಡುಗಡೆ(principals);

	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_moduli_gen(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಹೊರಹೋಗು_file, ಅಕ್ಷರ **opts, ಗಾತ್ರ_t nopts)
{
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	/* Moduli generation/screening */
	BIGNUM *ಆರಂಭ = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ moduli_ಬಿಟ್ಟುಗಳು = 0;
	FILE *ಹೊರಹೋಗು;
	ಗಾತ್ರ_t i;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *errstr, *p;

	/* Parse options */
	ಗಾಗಿ (i = 0; i < nopts; i++) {
		ಆದರೆ ((p = strprefix(opts[i], "start=", 0)) != ಖಾಲಿ) {
			/* XXX - also compare length against bits */
			ಆದರೆ (BN_hex2bn(&ಆರಂಭ, p) == 0)
				fatal("Invalid start point.");
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((p = strprefix(opts[i], "bits=", 0)) != ಖಾಲಿ) {
			moduli_ಬಿಟ್ಟುಗಳು = (ಪೂರ್ಣಾಂಕ)strtonum(p, 1, ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ, &errstr);
			ಆದರೆ (errstr) {
				fatal("Invalid number: %s (%s)", p, errstr);
			}
		} ಇಲ್ಲದಿದ್ದರೆ {
			fatal("Option \"%s\" is unsupported for moduli "
			    "generation", opts[i]);
		}
	}

	ಆದರೆ (strcmp(ಹೊರಹೋಗು_file, "-") == 0)
		ಹೊರಹೋಗು = stdout;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((ಹೊರಹೋಗು = fopen(ಹೊರಹೋಗು_file, "w")) == ಖಾಲಿ) {
		fatal("Couldn't open modulus candidate file \"%s\": %s",
		    ಹೊರಹೋಗು_file, strerror(errno));
	}
	setvbuf(ಹೊರಹೋಗು, ಖಾಲಿ, _IOLBF, 0);

	ಆದರೆ (moduli_ಬಿಟ್ಟುಗಳು == 0)
		moduli_ಬಿಟ್ಟುಗಳು = DEFAULT_ಬಿಟ್ಟುಗಳು;
	ಆದರೆ (gen_candidates(ಹೊರಹೋಗು, moduli_ಬಿಟ್ಟುಗಳು, ಆರಂಭ) != 0)
		fatal("modulus candidate generation failed");
#ಇಲ್ಲದಿದ್ದರೆ /* WITH_OPENSSL */
	fatal("Moduli generation is not supported");
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_moduli_screen(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಹೊರಹೋಗು_file, ಅಕ್ಷರ **opts, ಗಾತ್ರ_t nopts)
{
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	/* Moduli generation/screening */
	ಅಕ್ಷರ *checkpoint = ಖಾಲಿ;
	uint32_t generator_wanted = 0;
	ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ಆರಂಭ_lineno = 0, ಸಾಲುಗಳು_ಗಮ್ಯ_process = 0;
	ಪೂರ್ಣಾಂಕ ಅವಿಭಾಜ್ಯ_tests = 0;
	FILE *ಹೊರಹೋಗು, *ಒಳ = stdin;
	ಗಾತ್ರ_t i;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *errstr, *p;

	/* Parse options */
	ಗಾಗಿ (i = 0; i < nopts; i++) {
		ಆದರೆ ((p = strprefix(opts[i], "lines=", 0)) != ಖಾಲಿ) {
			ಸಾಲುಗಳು_ಗಮ್ಯ_process = strtoul(p, ಖಾಲಿ, 10);
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((p = strprefix(opts[i], "start-line=", 0)) != ಖಾಲಿ) {
			ಆರಂಭ_lineno = strtoul(p, ಖಾಲಿ, 10);
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((p = strprefix(opts[i], "checkpoint=", 0)) != ಖಾಲಿ) {
			ಬಿಡುಗಡೆ(checkpoint);
			checkpoint = xstrdup(p);
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((p = strprefix(opts[i], "generator=", 0)) != ಖಾಲಿ) {
			generator_wanted = (uint32_t)strtonum(p, 1, UINT_MAX,
			    &errstr);
			ಆದರೆ (errstr != ಖಾಲಿ) {
				fatal("Generator invalid: %s (%s)", p, errstr);
			}
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((p = strprefix(opts[i], "prime-tests=", 0)) != ಖಾಲಿ) {
			ಅವಿಭಾಜ್ಯ_tests = (ಪೂರ್ಣಾಂಕ)strtonum(p, 1, ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ, &errstr);
			ಆದರೆ (errstr) {
				fatal("Invalid number: %s (%s)", p, errstr);
			}
		} ಇಲ್ಲದಿದ್ದರೆ {
			fatal("Option \"%s\" is unsupported for moduli "
			    "screening", opts[i]);
		}
	}

	ಆದರೆ (have_ತಟಸ್ಥ && strcmp(ತಟಸ್ಥ_file, "-") != 0) {
		ಆದರೆ ((ಒಳ = fopen(ತಟಸ್ಥ_file, "r")) == ಖಾಲಿ) {
			fatal("Couldn't open modulus candidate "
			    "file \"%s\": %s", ತಟಸ್ಥ_file,
			    strerror(errno));
		}
	}

	ಆದರೆ (strcmp(ಹೊರಹೋಗು_file, "-") == 0)
		ಹೊರಹೋಗು = stdout;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((ಹೊರಹೋಗು = fopen(ಹೊರಹೋಗು_file, "a")) == ಖಾಲಿ) {
		fatal("Couldn't open moduli file \"%s\": %s",
		    ಹೊರಹೋಗು_file, strerror(errno));
	}
	setvbuf(ಹೊರಹೋಗು, ಖಾಲಿ, _IOLBF, 0);
	ಆದರೆ (ಅವಿಭಾಜ್ಯ_test(ಒಳ, ಹೊರಹೋಗು, ಅವಿಭಾಜ್ಯ_tests == 0 ? 100 : ಅವಿಭಾಜ್ಯ_tests,
	    generator_wanted, checkpoint,
	    ಆರಂಭ_lineno, ಸಾಲುಗಳು_ಗಮ್ಯ_process) != 0)
		fatal("modulus screening failed");
	ಆದರೆ (ಒಳ != stdin)
		(ಶೂನ್ಯ)fclose(ಒಳ);
	ಬಿಡುಗಡೆ(checkpoint);
#ಇಲ್ಲದಿದ್ದರೆ /* WITH_OPENSSL */
	fatal("Moduli screening is not supported");
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
}

/* Read and confirm a passphrase */
ಸ್ಥಿರ ಅಕ್ಷರ *
read_check_passphrase(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *prompt1, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *prompt2,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *retry_prompt)
{
	ಅಕ್ಷರ *passphrase1, *passphrase2;

	ಗಾಗಿ (;;) {
		passphrase1 = read_passphrase(prompt1, RP_ALLOW_STDIN);
		passphrase2 = read_passphrase(prompt2, RP_ALLOW_STDIN);
		ಆದರೆ (strcmp(passphrase1, passphrase2) == 0) {
			freezero(passphrase2, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(passphrase2));
			ಹಿಂತಿರುಗಿ passphrase1;
		}
		/* The passphrases do not match. Clear them and retry. */
		freezero(passphrase1, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(passphrase1));
		freezero(passphrase2, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(passphrase2));
		fputs(retry_prompt, stdout);
		fputc('\n', stdout);
		fflush(stdout);
	}
	/* NOTREACHED */
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

ಸ್ಥಿರ ಅಕ್ಷರ *
ಖಾಸಗಿ_ಕೀಲಿ_passphrase(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ)
{
	ಅಕ್ಷರ *prompt, *ret;

	ಆದರೆ (ತಟಸ್ಥ_passphrase)
		ಹಿಂತಿರುಗಿ xstrdup(ತಟಸ್ಥ_passphrase);
	ಆದರೆ (ತಟಸ್ಥ_new_passphrase)
		ಹಿಂತಿರುಗಿ xstrdup(ತಟಸ್ಥ_new_passphrase);

	xasprintf(&prompt, "Enter passphrase for \"%s\" "
	    "(empty for no passphrase): ", ಮಾರ್ಗ);
	ret = read_check_passphrase(prompt,
	    "Enter same passphrase again: ",
	    "Passphrases do not match.  Try again.");
	ಬಿಡುಗಡೆ(prompt);
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಅಕ್ಷರ *
sk_suffix(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *application, ಸ್ಥಿರಾಂಕ uint8_t *user, ಗಾತ್ರ_t userlen)
{
	ಅಕ್ಷರ *ret, *cp;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *p;
	ಗಾತ್ರ_t slen, i;

	/* Trim off URL-like preamble */
	ಆದರೆ ((p = strprefix(application, "ssh://", 0)) != ಖಾಲಿ)
		ret =  xstrdup(p);
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((p = strprefix(application, "ssh:", 0)) != ಖಾಲಿ)
		ret =  xstrdup(p);
	ಇಲ್ಲದಿದ್ದರೆ
		ret = xstrdup(application);

	/* Count trailing zeros in user */
	ಗಾಗಿ (i = 0; i < userlen; i++) {
		ಆದರೆ (user[userlen - i - 1] != 0)
			ನಿಲ್ಲಿಸು;
	}
	ಆದರೆ (i >= userlen)
		ಹಿಂತಿರುಗಿ ret; /* user-id was default all-zeros */

	/* Append user-id, escaping non-UTF-8 characters */
	slen = userlen - i;
	ಆದರೆ (asmprintf(&cp, ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ, ಖಾಲಿ, "%.*s", (ಪೂರ್ಣಾಂಕ)slen, user) == -1)
		fatal_f("asmprintf failed");
	/* Don't emit a user-id that contains path or control characters */
	ಆದರೆ (strchr(cp, '/') != ಖಾಲಿ || ಅಕ್ಷರಸರಣಿ_ಹುಡುಕು(cp, "..") != ಖಾಲಿ ||
	    strchr(cp, '\\') != ಖಾಲಿ) {
		ಬಿಡುಗಡೆ(cp);
		cp = tohex(user, slen);
	}
	xextendf(&ret, "_", "%s", cp);
	ಬಿಡುಗಡೆ(cp);
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
do_download_sk(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *skprovider, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *device)
{
	ರಚನೆ sshsk_resident_ಕೀಲಿ **srks;
	ಗಾತ್ರ_t nsrks, i;
	ಪೂರ್ಣಾಂಕ r, ret = -1;
	ಅಕ್ಷರ *fp, *pin = ಖಾಲಿ, *pass = ಖಾಲಿ, *ಮಾರ್ಗ, *pubpath;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ext;
	ರಚನೆ sshkey *ಕೀಲಿ;

	ಆದರೆ (skprovider == ಖಾಲಿ)
		fatal("Cannot download keys without provider");

	pin = read_passphrase("Enter PIN for authenticator: ", RP_ALLOW_STDIN);
	ಆದರೆ (!quiet) {
		ಬರೆ("You may need to touch your authenticator "
		    "to authorize key download.\n");
	}
	ಆದರೆ ((r = sshsk_ತುಂಬು_resident(skprovider, device, pin, 0,
	    &srks, &nsrks)) != 0) {
		ಆದರೆ (pin != ಖಾಲಿ)
			freezero(pin, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(pin));
		error_r(r, "Unable to load resident keys");
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ (nsrks == 0)
		logit("No keys to download");
	ಆದರೆ (pin != ಖಾಲಿ)
		freezero(pin, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(pin));

	ಗಾಗಿ (i = 0; i < nsrks; i++) {
		ಕೀಲಿ = srks[i]->ಕೀಲಿ;
		ಆದರೆ (ಕೀಲಿ->type != ಕೀಲಿ_ECDSA_SK && ಕೀಲಿ->type != ಕೀಲಿ_ED25519_SK) {
			error("Unsupported key type %s (%d)",
			    sshkey_type(ಕೀಲಿ), ಕೀಲಿ->type);
			ಮುಂದುವರಿ;
		}
		ಆದರೆ ((fp = sshkey_fingerprint(ಕೀಲಿ, fingerprint_hash,
		    SSH_FP_DEFAULT)) == ಖಾಲಿ)
			fatal_f("sshkey_fingerprint failed");
		debug_f("key %zu: %s %s %s (flags 0x%02x)", i,
		    sshkey_type(ಕೀಲಿ), fp, ಕೀಲಿ->sk_application, ಕೀಲಿ->sk_flags);
		ext = sk_suffix(ಕೀಲಿ->sk_application,
		    srks[i]->user_id, srks[i]->user_id_len);
		xasprintf(&ಮಾರ್ಗ, "id_%s_rk%s%s",
		    ಕೀಲಿ->type == ಕೀಲಿ_ECDSA_SK ? "ecdsa_sk" : "ed25519_sk",
		    *ext == '\0' ? "" : "_", ext);

		/* If the file already exists, ask the user to confirm. */
		ಆದರೆ (!confirm_overwrite(ಮಾರ್ಗ)) {
			ಬಿಡುಗಡೆ(ಮಾರ್ಗ);
			ನಿಲ್ಲಿಸು;
		}

		/* Save the key with the application string as the comment */
		ಆದರೆ (pass == ಖಾಲಿ)
			pass = ಖಾಸಗಿ_ಕೀಲಿ_passphrase(ಮಾರ್ಗ);
		ಆದರೆ ((r = sshkey_save_ಖಾಸಗಿ(ಕೀಲಿ, ಮಾರ್ಗ, pass,
		    ಕೀಲಿ->sk_application, ಖಾಸಗಿ_ಕೀಲಿ_format,
		    openssh_format_cipher, ಸುತ್ತುಗಳು)) != 0) {
			error_r(r, "Saving key \"%s\" failed", ಮಾರ್ಗ);
			ಬಿಡುಗಡೆ(ಮಾರ್ಗ);
			ನಿಲ್ಲಿಸು;
		}
		ಆದರೆ (!quiet) {
			ಬರೆ("Saved %s key%s%s to %s\n", sshkey_type(ಕೀಲಿ),
			    *ext != '\0' ? " " : "",
			    *ext != '\0' ? ಕೀಲಿ->sk_application : "",
			    ಮಾರ್ಗ);
		}

		/* Save public key too */
		xasprintf(&pubpath, "%s.pub", ಮಾರ್ಗ);
		ಬಿಡುಗಡೆ(ಮಾರ್ಗ);
		ಆದರೆ ((r = sshkey_save_ಬಹಿರಂಗ(ಕೀಲಿ, pubpath,
		    ಕೀಲಿ->sk_application)) != 0) {
			error_r(r, "Saving public key \"%s\" failed", pubpath);
			ಬಿಡುಗಡೆ(pubpath);
			ನಿಲ್ಲಿಸು;
		}
		ಬಿಡುಗಡೆ(pubpath);
	}

	ಆದರೆ (i >= nsrks)
		ret = 0; /* success */
	ಆದರೆ (pass != ಖಾಲಿ)
		freezero(pass, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(pass));
	sshsk_free_resident_ಕೀಲಿಗಳು(srks, nsrks);
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಶೂನ್ಯ
save_attestation(ರಚನೆ sshbuf *attest, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ)
{
	ಬಹುಲಕ_t omask;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (ಮಾರ್ಗ == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ; /* nothing to do */
	ಆದರೆ (attest == ಖಾಲಿ || sshbuf_len(attest) == 0)
		fatal("Enrollment did not return attestation data");
	omask = umask(077);
	r = sshbuf_write_file(ಮಾರ್ಗ, attest);
	umask(omask);
	ಆದರೆ (r != 0)
		fatal_r(r, "Unable to write attestation data \"%s\"", ಮಾರ್ಗ);
	ಆದರೆ (!quiet)
		ಬರೆ("Your FIDO attestation certificate has been saved in "
		    "%s\n", ಮಾರ್ಗ);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
confirm_sk_overwrite(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *application, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *user)
{
	ಅಕ್ಷರ yesno[3];

	ಬರೆ("A resident key scoped to '%s' with user id '%s' already "
	    "exists.\n", application == ಖಾಲಿ ? "ssh:" : application,
	    user == ಖಾಲಿ ? "null" : user);
	ಬರೆ("Overwrite key in token (y/n)? ");
	fflush(stdout);
	ಆದರೆ (fgets(yesno, ಗಾತ್ರ(yesno), stdin) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (yesno[0] != 'y' && yesno[0] != 'Y')
		ಹಿಂತಿರುಗಿ 0;
	ಹಿಂತಿರುಗಿ 1;
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
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	    "       ssh-keygen -i [-f input_keyfile] [-m key_format]\n"
	    "       ssh-keygen -e [-f input_keyfile] [-m key_format]\n"
#ಆದರೆ_ಅಂತ್ಯ
	    "       ssh-keygen -y [-f input_keyfile]\n"
	    "       ssh-keygen -c [-a rounds] [-C comment] [-f keyfile] [-P passphrase]\n"
	    "       ssh-keygen -l [-v] [-E fingerprint_hash] [-f input_keyfile]\n"
	    "       ssh-keygen -B [-f input_keyfile]\n");
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ ENABLE_PKCS11
	fprintf(stderr,
	    "       ssh-keygen -D pkcs11\n");
#ಆದರೆ_ಅಂತ್ಯ
	fprintf(stderr,
	    "       ssh-keygen -F hostname [-lv] [-f known_hosts_file]\n"
	    "       ssh-keygen -H [-f known_hosts_file]\n"
	    "       ssh-keygen -K [-a rounds] [-w provider]\n"
	    "       ssh-keygen -R hostname [-f known_hosts_file]\n"
	    "       ssh-keygen -r hostname [-g] [-f input_keyfile]\n"
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	    "       ssh-keygen -M generate [-O option] output_file\n"
	    "       ssh-keygen -M screen [-f input_file] [-O option] output_file\n"
#ಆದರೆ_ಅಂತ್ಯ
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
	ನಿರ್ಗಮಿಸು(1);
}

/*
 * Main program for key management.
 */
ಪೂರ್ಣಾಂಕ
ಮುಖ್ಯ(ಪೂರ್ಣಾಂಕ argc, ಅಕ್ಷರ **argv)
{
	ಅಕ್ಷರ comment[ಕೀಲಿ_COMMENT_MAX], *passphrase = ಖಾಲಿ;
	ಅಕ್ಷರ *rr_hostname = ಖಾಲಿ, *ep, *fp, *ra;
	ರಚನೆ sshkey *ಖಾಸಗಿ = ಖಾಲಿ, *ಸಾರ್ವಜನಿಕ = ಖಾಲಿ;
	ರಚನೆ passwd *pw;
	ಪೂರ್ಣಾಂಕ ret = 0, r, opt, type;
	ಪೂರ್ಣಾಂಕ change_passphrase = 0, change_comment = 0, show_cert = 0;
	ಪೂರ್ಣಾಂಕ ಕಂಡುಹಿಡಿ_host = 0, delete_host = 0, hash_hosts = 0;
	ಪೂರ್ಣಾಂಕ gen_all_hostkeys = 0, gen_krl = 0, update_krl = 0, check_krl = 0;
	ಪೂರ್ಣಾಂಕ prefer_agent = 0, convert_ಗಮ್ಯ = 0, convert_from = 0;
	ಪೂರ್ಣಾಂಕ print_ಬಹಿರಂಗ = 0, print_generic = 0, cert_serial_autoinc = 0;
	ಪೂರ್ಣಾಂಕ do_gen_candidates = 0, do_screen_candidates = 0, download_sk = 0;
	ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ cert_serial = 0;
	ಅಕ್ಷರ *ತಟಸ್ಥ_comment = ಖಾಲಿ, *ca_ಕೀಲಿ_ಮಾರ್ಗ = ಖಾಲಿ, **opts = ಖಾಲಿ;
	ಅಕ್ಷರ *sk_application = ಖಾಲಿ, *sk_device = ಖಾಲಿ, *sk_user = ಖಾಲಿ;
	ಅಕ್ಷರ *sk_attestation_ಮಾರ್ಗ = ಖಾಲಿ;
	ರಚನೆ sshbuf *challenge = ಖಾಲಿ, *attest = ಖಾಲಿ;
	ಗಾತ್ರ_t i, nopts = 0;
	uint32_t ಬಿಟ್ಟುಗಳು = 0;
	uint8_t sk_flags = SSH_SK_USER_PRESENCE_REQD;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *errstr, *p;
	ಪೂರ್ಣಾಂಕ log_level = SYSLOG_LEVEL_INFO;
	ಅಕ್ಷರ *sign_op = ಖಾಲಿ;

	ಬಾಹ್ಯ ಪೂರ್ಣಾಂಕ optind;
	ಬಾಹ್ಯ ಅಕ್ಷರ *optarg;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	__progname = ssh_get_progname(argv[0]);

	ಬೀಜ_rng();

	log_init(argv[0], SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_USER, 1);

	msetlocale();

	/* we need this for the home * directory.  */
	pw = getpwuid(getuid());
	ಆದರೆ (!pw)
		fatal("No user exists for uid %lu", (u_long)getuid());
	pw = pwcopy(pw);
	ಆದರೆ (gethostname(hostname, ಗಾತ್ರ(hostname)) == -1)
		fatal("gethostname: %s", strerror(errno));

	sk_provider = getenv("SSH_SK_PROVIDER");

	/* Remaining characters: dGjJSTWx */
	ಆಗ ((opt = getopt(argc, argv, "ABHKLQUXceghiklopquvy"
	    "C:D:E:F:I:M:N:O:P:R:V:Y:Z:"
	    "a:b:f:g:m:n:r:s:t:w:z:")) != -1) {
		ಆಯ್ಕೆ (opt) {
		ಸ್ಥಿತಿ 'A':
			gen_all_hostkeys = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'b':
			ಬಿಟ್ಟುಗಳು = (uint32_t)strtonum(optarg, 1, UINT32_MAX,
			    &errstr);
			ಆದರೆ (errstr)
				fatal("Bits has bad value %s (%s)",
					optarg, errstr);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			ಆದರೆ (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'F':
			ಕಂಡುಹಿಡಿ_host = 1;
			rr_hostname = optarg;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'H':
			hash_hosts = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'I':
			cert_ಕೀಲಿ_id = optarg;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'R':
			delete_host = 1;
			rr_hostname = optarg;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'L':
			show_cert = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'l':
			print_fingerprint = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'B':
			print_bubblebabble = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'm':
			ಆದರೆ (strcasecmp(optarg, "RFC4716") == 0 ||
			    strcasecmp(optarg, "ssh2") == 0) {
				convert_format = FMT_RFC4716;
				ನಿಲ್ಲಿಸು;
			}
			ಆದರೆ (strcasecmp(optarg, "PKCS8") == 0) {
				convert_format = FMT_PKCS8;
				ಖಾಸಗಿ_ಕೀಲಿ_format = SSHKEY_ಖಾಸಗಿ_PKCS8;
				ನಿಲ್ಲಿಸು;
			}
			ಆದರೆ (strcasecmp(optarg, "PEM") == 0) {
				convert_format = FMT_PEM;
				ಖಾಸಗಿ_ಕೀಲಿ_format = SSHKEY_ಖಾಸಗಿ_PEM;
				ನಿಲ್ಲಿಸು;
			}
			ಆದರೆ (strcasecmp(optarg, "hexdump") == 0) {
				convert_format = FMT_HEXDUMP;
				ನಿಲ್ಲಿಸು;
			}
			fatal("Unsupported conversion format \"%s\"", optarg);
		ಸ್ಥಿತಿ 'n':
			cert_principals = optarg;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'o':
			/* no-op; new format is already the default */
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'p':
			change_passphrase = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'c':
			change_comment = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'f':
			ಆದರೆ (strlcpy(ತಟಸ್ಥ_file, optarg,
			    ಗಾತ್ರ(ತಟಸ್ಥ_file)) >= ಗಾತ್ರ(ತಟಸ್ಥ_file))
				fatal("Identity filename too long");
			have_ತಟಸ್ಥ = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'g':
			print_generic = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'K':
			download_sk = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'P':
			ತಟಸ್ಥ_passphrase = optarg;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'N':
			ತಟಸ್ಥ_new_passphrase = optarg;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'Q':
			check_krl = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'O':
			opts = xrecallocarray(opts, nopts, nopts + 1,
			    ಗಾತ್ರ(*opts));
			opts[nopts++] = xstrdup(optarg);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'Z':
			openssh_format_cipher = optarg;
			ಆದರೆ (cipher_by_name(openssh_format_cipher) == ಖಾಲಿ)
				fatal("Invalid OpenSSH-format cipher '%s'",
				    openssh_format_cipher);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'C':
			ತಟಸ್ಥ_comment = optarg;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'q':
			quiet = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'e':
			/* export key */
			convert_ಗಮ್ಯ = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'h':
			cert_ಕೀಲಿ_type = SSH2_CERT_TYPE_HOST;
			certflags_flags = 0;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'k':
			gen_krl = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'i':
		ಸ್ಥಿತಿ 'X':
			/* import key */
			convert_from = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'y':
			print_ಬಹಿರಂಗ = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 's':
			ca_ಕೀಲಿ_ಮಾರ್ಗ = optarg;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 't':
			ಕೀಲಿ_type_name = optarg;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'D':
			pkcs11provider = optarg;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'U':
			prefer_agent = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'u':
			update_krl = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'v':
			ಆದರೆ (log_level == SYSLOG_LEVEL_INFO)
				log_level = SYSLOG_LEVEL_DEBUG1;
			ಇಲ್ಲದಿದ್ದರೆ {
				ಆದರೆ (log_level >= SYSLOG_LEVEL_DEBUG1 &&
				    log_level < SYSLOG_LEVEL_DEBUG3)
					log_level++;
			}
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'r':
			rr_hostname = optarg;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'a':
			ಸುತ್ತುಗಳು = (ಪೂರ್ಣಾಂಕ)strtonum(optarg, 1, ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ, &errstr);
			ಆದರೆ (errstr)
				fatal("Invalid number: %s (%s)",
					optarg, errstr);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'V':
			parse_cert_times(optarg);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'Y':
			sign_op = optarg;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'w':
			sk_provider = optarg;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'z':
			errno = 0;
			ಆದರೆ (*optarg == '+') {
				cert_serial_autoinc = 1;
				optarg++;
			}
			cert_serial = strtoull(optarg, &ep, 10);
			ಆದರೆ (*optarg < '0' || *optarg > '9' || *ep != '\0' ||
			    (errno == ERANGE && cert_serial == ULLONG_MAX))
				fatal("Invalid serial number \"%s\"", optarg);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'M':
			ಆದರೆ (strcmp(optarg, "generate") == 0)
				do_gen_candidates = 1;
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(optarg, "screen") == 0)
				do_screen_candidates = 1;
			ಇಲ್ಲದಿದ್ದರೆ
				fatal("Unsupported moduli option %s", optarg);
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			usage();
		}
	}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ ENABLE_SK_ಆಂತರಿಕ
	ಆದರೆ (sk_provider == ಖಾಲಿ)
		sk_provider = "internal";
#ಆದರೆ_ಅಂತ್ಯ

	/* reinit */
	log_init(argv[0], log_level, SYSLOG_FACILITY_USER, 1);

	argv += optind;
	argc -= optind;

	ಆದರೆ (sign_op != ಖಾಲಿ) {
		ಆದರೆ (strprefix(sign_op, "find-principals", 0) != ಖಾಲಿ) {
			ಆದರೆ (ca_ಕೀಲಿ_ಮಾರ್ಗ == ಖಾಲಿ) {
				error("Too few arguments for find-principals:"
				    "missing signature file");
				ನಿರ್ಗಮಿಸು(1);
			}
			ಆದರೆ (!have_ತಟಸ್ಥ) {
				error("Too few arguments for find-principals:"
				    "missing allowed keys file");
				ನಿರ್ಗಮಿಸು(1);
			}
			ret = sig_ಕಂಡುಹಿಡಿ_principals(ca_ಕೀಲಿ_ಮಾರ್ಗ, ತಟಸ್ಥ_file,
			    opts, nopts);
			ಹೋಗು ಮುಗಿದ;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strprefix(sign_op, "match-principals", 0) != ಖಾಲಿ) {
			ಆದರೆ (!have_ತಟಸ್ಥ) {
				error("Too few arguments for match-principals:"
				    "missing allowed keys file");
				ನಿರ್ಗಮಿಸು(1);
			}
			ಆದರೆ (cert_ಕೀಲಿ_id == ಖಾಲಿ) {
				error("Too few arguments for match-principals: "
				    "missing principal ID");
				ನಿರ್ಗಮಿಸು(1);
			}
			ret = sig_ಹೊಂದಿಕೆ_principals(ತಟಸ್ಥ_file, cert_ಕೀಲಿ_id,
			    opts, nopts);
			ಹೋಗು ಮುಗಿದ;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strprefix(sign_op, "sign", 0) != ಖಾಲಿ) {
			/* NB. cert_principals is actually namespace, via -n */
			ಆದರೆ (cert_principals == ಖಾಲಿ ||
			    *cert_principals == '\0') {
				error("Too few arguments for sign: "
				    "missing namespace");
				ನಿರ್ಗಮಿಸು(1);
			}
			ಆದರೆ (!have_ತಟಸ್ಥ) {
				error("Too few arguments for sign: "
				    "missing key");
				ನಿರ್ಗಮಿಸು(1);
			}
			ret = sig_sign(ತಟಸ್ಥ_file, cert_principals,
			    prefer_agent, argc, argv, opts, nopts);
			ಹೋಗು ಮುಗಿದ;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strprefix(sign_op, "check-novalidate", 0) != ಖಾಲಿ) {
			/* NB. cert_principals is actually namespace, via -n */
			ಆದರೆ (cert_principals == ಖಾಲಿ ||
			    *cert_principals == '\0') {
				error("Too few arguments for check-novalidate: "
				    "missing namespace");
				ನಿರ್ಗಮಿಸು(1);
			}
			ಆದರೆ (ca_ಕೀಲಿ_ಮಾರ್ಗ == ಖಾಲಿ) {
				error("Too few arguments for check-novalidate: "
				    "missing signature file");
				ನಿರ್ಗಮಿಸು(1);
			}
			ret = sig_verify(ca_ಕೀಲಿ_ಮಾರ್ಗ, cert_principals,
			    ಖಾಲಿ, ಖಾಲಿ, ಖಾಲಿ, opts, nopts);
			ಹೋಗು ಮುಗಿದ;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strprefix(sign_op, "verify", 0) != ಖಾಲಿ) {
			/* NB. cert_principals is actually namespace, via -n */
			ಆದರೆ (cert_principals == ಖಾಲಿ ||
			    *cert_principals == '\0') {
				error("Too few arguments for verify: "
				    "missing namespace");
				ನಿರ್ಗಮಿಸು(1);
			}
			ಆದರೆ (ca_ಕೀಲಿ_ಮಾರ್ಗ == ಖಾಲಿ) {
				error("Too few arguments for verify: "
				    "missing signature file");
				ನಿರ್ಗಮಿಸು(1);
			}
			ಆದರೆ (!have_ತಟಸ್ಥ) {
				error("Too few arguments for sign: "
				    "missing allowed keys file");
				ನಿರ್ಗಮಿಸು(1);
			}
			ಆದರೆ (cert_ಕೀಲಿ_id == ಖಾಲಿ) {
				error("Too few arguments for verify: "
				    "missing principal identity");
				ನಿರ್ಗಮಿಸು(1);
			}
			ret = sig_verify(ca_ಕೀಲಿ_ಮಾರ್ಗ, cert_principals,
			    cert_ಕೀಲಿ_id, ತಟಸ್ಥ_file, rr_hostname,
			    opts, nopts);
			ಹೋಗು ಮುಗಿದ;
		}
		error("Unsupported operation for -Y: \"%s\"", sign_op);
		usage();
		/* NOTREACHED */
	}

	ಆದರೆ (ca_ಕೀಲಿ_ಮಾರ್ಗ != ಖಾಲಿ) {
		ಆದರೆ (argc < 1 && !gen_krl) {
			error("Too few arguments.");
			usage();
		}
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (argc > 0 && !gen_krl && !check_krl &&
	    !do_gen_candidates && !do_screen_candidates) {
		error("Too many arguments.");
		usage();
	}
	ಆದರೆ (change_passphrase && change_comment) {
		error("Can only have one of -p and -c.");
		usage();
	}
	ಆದರೆ (print_fingerprint && (delete_host || hash_hosts)) {
		error("Cannot use -l with -H or -R.");
		usage();
	}
	ಆದರೆ (gen_krl) {
		do_gen_krl(pw, update_krl, ca_ಕೀಲಿ_ಮಾರ್ಗ,
		    cert_serial, ತಟಸ್ಥ_comment, argc, argv);
		ಹೋಗು ಮುಗಿದ;
	}
	ಆದರೆ (check_krl) {
		do_check_krl(pw, print_fingerprint, argc, argv);
		ಹೋಗು ಮುಗಿದ;
	}
	ಆದರೆ (ca_ಕೀಲಿ_ಮಾರ್ಗ != ಖಾಲಿ) {
		ಆದರೆ (cert_ಕೀಲಿ_id == ಖಾಲಿ)
			fatal("Must specify key id (-I) when certifying");
		ಆದರೆ (cert_principals == ಖಾಲಿ) {
			/*
			 * Ideally this would be a fatal(), but we need to
			 * be able to generate such certificates for testing
			 * even though they will be rejected.
			 */
			error("Warning: certificate will contain no "
			    "principals (-n)");
		}
		ಗಾಗಿ (i = 0; i < nopts; i++)
			ಕೂಡಿಸು_cert_option(opts[i]);
		do_ca_sign(pw, ca_ಕೀಲಿ_ಮಾರ್ಗ, prefer_agent,
		    cert_serial, cert_serial_autoinc, argc, argv);
		ಹೋಗು ಮುಗಿದ;
	}
	ಆದರೆ (show_cert)
		do_show_cert(pw);
	ಆದರೆ (delete_host || hash_hosts || ಕಂಡುಹಿಡಿ_host) {
		do_ತಿಳಿದ_hosts(pw, rr_hostname, ಕಂಡುಹಿಡಿ_host,
		    delete_host, hash_hosts);
	}
	ಆದರೆ (pkcs11provider != ಖಾಲಿ)
		do_download(pw);
	ಆದರೆ (download_sk) {
		ಗಾಗಿ (i = 0; i < nopts; i++) {
			ಆದರೆ ((p = strprefix(opts[i], "device=", 1)) != ಖಾಲಿ) {
				sk_device = xstrdup(p);
			} ಇಲ್ಲದಿದ್ದರೆ {
				fatal("Option \"%s\" is unsupported for "
				    "FIDO authenticator download", opts[i]);
			}
		}
		ret = do_download_sk(sk_provider, sk_device);
		ಹೋಗು ಮುಗಿದ;
	}
	ಆದರೆ (print_fingerprint || print_bubblebabble)
		do_fingerprint(pw);
	ಆದರೆ (change_passphrase)
		do_change_passphrase(pw, opts, nopts);
	ಆದರೆ (change_comment)
		do_change_comment(pw, ತಟಸ್ಥ_comment);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	ಆದರೆ (convert_ಗಮ್ಯ) {
		do_convert_ಗಮ್ಯ(pw);
		ಹೋಗು ಮುಗಿದ;
	}
	ಆದರೆ (convert_from) {
		do_convert_from(pw);
		ಹೋಗು ಮುಗಿದ;
	}
#ಇಲ್ಲದಿದ್ದರೆ /* WITH_OPENSSL */
	ಆದರೆ (convert_ಗಮ್ಯ || convert_from)
		fatal("key conversion disabled at compile time");
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
	ಆದರೆ (print_ಬಹಿರಂಗ)
		do_print_ಬಹಿರಂಗ(pw);
	ಆದರೆ (rr_hostname != ಖಾಲಿ) {
		ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ n = 0;

		ಆದರೆ (have_ತಟಸ್ಥ) {
			n = do_print_resource_ದಾಖಲೆ(pw, ತಟಸ್ಥ_file,
			    rr_hostname, print_generic, opts, nopts);
			ಆದರೆ (n == 0)
				fatal("%s: %s", ತಟಸ್ಥ_file, strerror(errno));
			ನಿರ್ಗಮಿಸು(0);
		} ಇಲ್ಲದಿದ್ದರೆ {

			n += do_print_resource_ದಾಖಲೆ(pw,
			    ಮಾರ್ಗ_HOST_RSA_ಕೀಲಿ_FILE, rr_hostname,
			    print_generic, opts, nopts);
			n += do_print_resource_ದಾಖಲೆ(pw,
			    ಮಾರ್ಗ_HOST_ECDSA_ಕೀಲಿ_FILE, rr_hostname,
			    print_generic, opts, nopts);
			n += do_print_resource_ದಾಖಲೆ(pw,
			    ಮಾರ್ಗ_HOST_ED25519_ಕೀಲಿ_FILE, rr_hostname,
			    print_generic, opts, nopts);
			ಆದರೆ (n == 0)
				fatal("no keys found.");
			ನಿರ್ಗಮಿಸು(0);
		}
	}

	ಆದರೆ (do_gen_candidates || do_screen_candidates) {
		ಆದರೆ (argc <= 0)
			fatal("No output file specified");
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (argc > 1)
			fatal("Too many output files specified");
	}
	ಆದರೆ (do_gen_candidates) {
		do_moduli_gen(argv[0], opts, nopts);
		ಹೋಗು ಮುಗಿದ;
	}
	ಆದರೆ (do_screen_candidates) {
		do_moduli_screen(argv[0], opts, nopts);
		ಹೋಗು ಮುಗಿದ;
	}

	ಆದರೆ (gen_all_hostkeys) {
		do_gen_all_hostkeys(pw);
		ಹೋಗು ಮುಗಿದ;
	}

	ಆದರೆ (ಕೀಲಿ_type_name == ಖಾಲಿ)
		ಕೀಲಿ_type_name = DEFAULT_ಕೀಲಿ_TYPE_NAME;

	type = sshkey_type_from_shortname(ಕೀಲಿ_type_name);
	type_ಬಿಟ್ಟುಗಳು_valid(type, ಕೀಲಿ_type_name, &ಬಿಟ್ಟುಗಳು);

	ಆದರೆ (!quiet)
		ಬರೆ("Generating public/private %s key pair.\n",
		    ಕೀಲಿ_type_name);
	ಆಯ್ಕೆ (type) {
	ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA_SK:
	ಸ್ಥಿತಿ ಕೀಲಿ_ED25519_SK:
		ಗಾಗಿ (i = 0; i < nopts; i++) {
			ಆದರೆ (strcasecmp(opts[i], "no-touch-required") == 0) {
				sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcasecmp(opts[i], "verify-required") == 0) {
				sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcasecmp(opts[i], "resident") == 0) {
				sk_flags |= SSH_SK_RESIDENT_ಕೀಲಿ;
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((p = strprefix(opts[i], "device=", 1))
			    != ಖಾಲಿ ) {
				sk_device = xstrdup(p);
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((p = strprefix(opts[i], "user=", 1))
			    != ಖಾಲಿ) {
				sk_user = xstrdup(p);
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((p = strprefix(opts[i], "challenge=", 1))
			    != ಖಾಲಿ) {
				ಆದರೆ ((r = sshbuf_ತುಂಬು_file(p,
				    &challenge)) != 0) {
					fatal_r(r, "Unable to load FIDO "
					    "enrollment challenge \"%s\"", p);
				}
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strncasecmp(opts[i],
			    "write-attestation=", 18) == 0) {
				sk_attestation_ಮಾರ್ಗ = opts[i] + 18;
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strncasecmp(opts[i],
			    "application=", 12) == 0) {
				sk_application = xstrdup(opts[i] + 12);
				ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(sk_application, "ssh:", 4) != 0) {
					fatal("FIDO application string must "
					    "begin with \"ssh:\"");
				}
			} ಇಲ್ಲದಿದ್ದರೆ {
				fatal("Option \"%s\" is unsupported for "
				    "FIDO authenticator enrollment", opts[i]);
			}
		}
		ಆದರೆ ((attest = sshbuf_new()) == ಖಾಲಿ)
			fatal("sshbuf_new failed");
		r = 0;
		ಗಾಗಿ (i = 0 ;;) {
			ಆದರೆ (!quiet) {
				ಬರೆ("You may need to touch your "
				    "authenticator%s to authorize key "
				    "generation.\n",
				    r == 0 ? "" : " again");
			}
			fflush(stdout);
			r = sshsk_enroll(type, sk_provider, sk_device,
			    sk_application == ಖಾಲಿ ? "ssh:" : sk_application,
			    sk_user, sk_flags, passphrase, challenge,
			    &ಖಾಸಗಿ, attest);
			ಆದರೆ (r == 0)
				ನಿಲ್ಲಿಸು;
			ಆದರೆ (r == SSH_ERR_ಕೀಲಿ_BAD_PERMISSIONS &&
			    (sk_flags & SSH_SK_RESIDENT_ಕೀಲಿ) != 0 &&
			    (sk_flags & SSH_SK_FORCE_OPERATION) == 0 &&
			    confirm_sk_overwrite(sk_application, sk_user)) {
				sk_flags |= SSH_SK_FORCE_OPERATION;
				ಮುಂದುವರಿ;
			}
			ಆದರೆ (r != SSH_ERR_ಕೀಲಿ_WRONG_PASSPHRASE)
				fatal_r(r, "Key enrollment failed");
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (passphrase != ಖಾಲಿ) {
				error("PIN incorrect");
				freezero(passphrase, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(passphrase));
				passphrase = ಖಾಲಿ;
			}
			ಆದರೆ (++i >= 3)
				fatal("Too many incorrect PINs");
			passphrase = read_passphrase("Enter PIN for "
			    "authenticator: ", RP_ALLOW_STDIN);
		}
		ಆದರೆ (passphrase != ಖಾಲಿ) {
			freezero(passphrase, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(passphrase));
			passphrase = ಖಾಲಿ;
		}
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಆದರೆ ((r = sshkey_generate(type, ಬಿಟ್ಟುಗಳು, &ಖಾಸಗಿ)) != 0)
			fatal("sshkey_generate failed");
		ನಿಲ್ಲಿಸು;
	}
	ಆದರೆ ((r = sshkey_from_ಖಾಸಗಿ(ಖಾಸಗಿ, &ಸಾರ್ವಜನಿಕ)) != 0)
		fatal_r(r, "sshkey_from_private");

	ಆದರೆ (!have_ತಟಸ್ಥ)
		ask_filename(pw, "Enter file in which to save the key");

	/* Create ~/.ssh directory if it doesn't already exist. */
	hostfile_create_user_ssh_dir(ತಟಸ್ಥ_file, !quiet);

	/* If the file already exists, ask the user to confirm. */
	ಆದರೆ (!confirm_overwrite(ತಟಸ್ಥ_file))
		ನಿರ್ಗಮಿಸು(1);

	/* Determine the passphrase for the private key */
	passphrase = ಖಾಸಗಿ_ಕೀಲಿ_passphrase(ತಟಸ್ಥ_file);
	ಆದರೆ (ತಟಸ್ಥ_comment) {
		strlcpy(comment, ತಟಸ್ಥ_comment, ಗಾತ್ರ(comment));
	} ಇಲ್ಲದಿದ್ದರೆ {
		/* Create default comment field for the passphrase. */
		snprintf(comment, ಗಾತ್ರ comment, "%s@%s", pw->pw_name, hostname);
	}



	/* Save the key with the given passphrase and comment. */
	ಆದರೆ ((r = sshkey_save_ಖಾಸಗಿ(ಖಾಸಗಿ, ತಟಸ್ಥ_file, passphrase,
	    comment, ಖಾಸಗಿ_ಕೀಲಿ_format, openssh_format_cipher, ಸುತ್ತುಗಳು)) != 0) {
		error_r(r, "Saving key \"%s\" failed", ತಟಸ್ಥ_file);
		freezero(passphrase, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(passphrase));
		ನಿರ್ಗಮಿಸು(1);
	}
	freezero(passphrase, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(passphrase));
	sshkey_free(ಖಾಸಗಿ);

	ಆದರೆ (!quiet) {
		ಬರೆ("Your identification has been saved in %s\n",
		    ತಟಸ್ಥ_file);
	}

	strlcat(ತಟಸ್ಥ_file, ".pub", ಗಾತ್ರ(ತಟಸ್ಥ_file));
	ಆದರೆ ((r = sshkey_save_ಬಹಿರಂಗ(ಸಾರ್ವಜನಿಕ, ತಟಸ್ಥ_file, comment)) != 0)
		fatal_r(r, "Unable to save public key to %s", ತಟಸ್ಥ_file);

	ಆದರೆ (!quiet) {
		fp = sshkey_fingerprint(ಸಾರ್ವಜನಿಕ, fingerprint_hash,
		    SSH_FP_DEFAULT);
		ra = sshkey_fingerprint(ಸಾರ್ವಜನಿಕ, fingerprint_hash,
		    SSH_FP_RANDOMART);
		ಆದರೆ (fp == ಖಾಲಿ || ra == ಖಾಲಿ)
			fatal("sshkey_fingerprint failed");
		ಬರೆ("Your public key has been saved in %s\n",
		    ತಟಸ್ಥ_file);
		ಬರೆ("The key fingerprint is:\n");
		ಬರೆ("%s %s\n", fp, comment);
		ಬರೆ("The key's randomart image is:\n");
		ಬರೆ("%s\n", ra);
		ಬಿಡುಗಡೆ(ra);
		ಬಿಡುಗಡೆ(fp);
	}

	ಆದರೆ (sk_attestation_ಮಾರ್ಗ != ಖಾಲಿ)
		save_attestation(attest, sk_attestation_ಮಾರ್ಗ);

 ಮುಗಿದ:
	sshbuf_free(attest);
	sshkey_free(ಸಾರ್ವಜನಿಕ);
	pwfree(pw);
	ನಿರ್ಗಮಿಸು(ret);
}
