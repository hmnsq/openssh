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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/stat.h>

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
#ਅਨ੍ਤਰ੍ਭਾਵ "openbsd-compat/openssl-compat.h"
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/bn.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/evp.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/pem.h>
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <netdb.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <paths.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <pwd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <locale.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <time.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "authfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "pathnames.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "match.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "hostfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "dns.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh2.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "atomicio.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "krl.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "digest.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "utf8.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "authfd.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshsig.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh-sk.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sk-api.h" /* XXX for SSH_SK_USER_PRESENCE_REQD; remove */
#ਅਨ੍ਤਰ੍ਭਾਵ "cipher.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ ENABLE_PKCS11
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh-pkcs11.h"
#ਜੇ_ਅੰਤ

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DEFAULT_ਕੁੰਜੀ_TYPE_NAME "ed25519"

/*
 * Default number of bits in the RSA and ECDSA keys.  These value can be
 * overridden on the command line.
 *
 * These values provide security equivalent to at least 128 bits of security
 * according to NIST Special Publication 800-57: Recommendation for Key
 * Management Part 1 rev 4 section 5.6.1.
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DEFAULT_ਬਿੱਟ		3072
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DEFAULT_ਬਿੱਟ_ECDSA	256

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਕੁੰਜੀ_COMMENT_MAX		(NI_MAXHOST + 1024)

ਸਥਿਰ ਪੂਰਨ quiet = 0;

/* Flag indicating that we just want to see the key fingerprint */
ਸਥਿਰ ਪੂਰਨ print_fingerprint = 0;
ਸਥਿਰ ਪੂਰਨ print_bubblebabble = 0;

/* Hash algorithm to use for fingerprints. */
ਸਥਿਰ ਪੂਰਨ fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* The identity file name, given on the command line or entered by the user. */
ਸਥਿਰ ਅੱਖਰ ਪਛਾਣ_ਤੱਤ_file[PATH_MAX];
ਸਥਿਰ ਪੂਰਨ have_ਪਛਾਣ_ਤੱਤ = 0;

/* This is set to the passphrase if given on the command line. */
ਸਥਿਰ ਅੱਖਰ *ਪਛਾਣ_ਤੱਤ_passphrase = ਨਿਰਾ;

/* This is set to the new passphrase if given on the command line. */
ਸਥਿਰ ਅੱਖਰ *ਪਛਾਣ_ਤੱਤ_new_passphrase = ਨਿਰਾ;

/* Key type when certifying */
ਸਥਿਰ u_int cert_ਕੁੰਜੀ_type = SSH2_CERT_TYPE_USER;

/* "key ID" of signed key */
ਸਥਿਰ ਅੱਖਰ *cert_ਕੁੰਜੀ_id = ਨਿਰਾ;

/* Comma-separated list of principal names for certifying keys */
ਸਥਿਰ ਅੱਖਰ *cert_principals = ਨਿਰਾ;

/* Validity period for certificates */
ਸਥਿਰ uint64_t cert_valid_from = 0;
ਸਥਿਰ uint64_t cert_valid_ਮੰਜ਼ਿਲ = ~0ULL;

/* Certificate options */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CERTOPT_X_FWD				(1)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CERTOPT_AGENT_FWD			(1<<1)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CERTOPT_ਪੋਰਟ_FWD			(1<<2)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CERTOPT_PTY				(1<<3)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CERTOPT_USER_RC				(1<<4)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CERTOPT_NO_REQUIRE_USER_PRESENCE	(1<<5)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CERTOPT_REQUIRE_VERIFY			(1<<6)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CERTOPT_DEFAULT	(CERTOPT_X_FWD|CERTOPT_AGENT_FWD| \
			 CERTOPT_ਪੋਰਟ_FWD|CERTOPT_PTY|CERTOPT_USER_RC)
ਸਥਿਰ uint32_t certflags_flags = CERTOPT_DEFAULT;
ਸਥਿਰ ਅੱਖਰ *certflags_command = ਨਿਰਾ;
ਸਥਿਰ ਅੱਖਰ *certflags_src_addr = ਨਿਰਾ;

/* Arbitrary extensions specified by user */
ਬਣਤਰ cert_ext {
	ਅੱਖਰ *ਕੁੰਜੀ;
	ਅੱਖਰ *val;
	ਪੂਰਨ crit;
};
ਸਥਿਰ ਬਣਤਰ cert_ext *cert_ext;
ਸਥਿਰ ਮਾਪ_t ncert_ext;

/* Conversion to/from various formats */
ਗਿਣਤੀ {
	FMT_RFC4716,
	FMT_PKCS8,
	FMT_PEM,
	FMT_HEXDUMP
} convert_format = FMT_RFC4716;

ਸਥਿਰ ਅੱਖਰ *ਕੁੰਜੀ_type_name = ਨਿਰਾ;

/* Load key from this PKCS#11 provider */
ਸਥਿਰ ਅੱਖਰ *pkcs11provider = ਨਿਰਾ;

/* FIDO/U2F provider to use */
ਸਥਿਰ ਅੱਖਰ *sk_provider = ਨਿਰਾ;

/* Format for writing private keys */
ਸਥਿਰ ਪੂਰਨ ਨਿੱਜੀ_ਕੁੰਜੀ_format = SSHKEY_ਨਿੱਜੀ_OPENSSH;

/* Cipher for new-format private keys */
ਸਥਿਰ ਅੱਖਰ *openssh_format_cipher = ਨਿਰਾ;

/* Number of KDF rounds to derive new format keys. */
ਸਥਿਰ ਪੂਰਨ ਗੇੜ = 0;

/* argv0 */
ਬਾਹਰੀ ਅੱਖਰ *__progname;

ਸਥਿਰ ਅੱਖਰ hostname[NI_MAXHOST];

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
/* moduli.c */
ਪੂਰਨ gen_candidates(FILE *, uint32_t, BIGNUM *);
ਪੂਰਨ ਅਭਾਜ_test(FILE *, FILE *, uint32_t, uint32_t, ਅੱਖਰ *, ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ,
    ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ);
#ਜੇ_ਅੰਤ

ਸਥਿਰ ਖਾਲੀ
type_ਬਿੱਟ_valid(ਪੂਰਨ type, ਅਚਲ ਅੱਖਰ *name, uint32_t *bitsp)
{
	ਜੇ (type == ਕੁੰਜੀ_UNSPEC)
		fatal("unknown key type %s", ਕੁੰਜੀ_type_name);
	ਜੇ (*bitsp == 0) {
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
		ਪੂਰਨ nid;

		ਚੋਣ(type) {
		ਹਾਲਤ ਕੁੰਜੀ_ECDSA:
			ਜੇ (name != ਨਿਰਾ &&
			    (nid = sshkey_ecdsa_nid_from_name(name)) > 0)
				*bitsp = sshkey_ਵਕਰ_nid_ਮੰਜ਼ਿਲ_ਬਿੱਟ(nid);
			ਜੇ (*bitsp == 0)
				*bitsp = DEFAULT_ਬਿੱਟ_ECDSA;
			ਰੋਕੋ;
		ਹਾਲਤ ਕੁੰਜੀ_RSA:
			*bitsp = DEFAULT_ਬਿੱਟ;
			ਰੋਕੋ;
		}
#ਜੇ_ਅੰਤ
	}
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	ਚੋਣ (type) {
	ਹਾਲਤ ਕੁੰਜੀ_RSA:
		ਜੇ (*bitsp < SSH_RSA_MINIMUM_MODULUS_ਮਾਪ)
			fatal("Invalid RSA key length: minimum is %d bits",
			    SSH_RSA_MINIMUM_MODULUS_ਮਾਪ);
		ਨਹੀਂਤਾਂ ਜੇ (*bitsp > OPENSSL_RSA_MAX_MODULUS_ਬਿੱਟ)
			fatal("Invalid RSA key length: maximum is %d bits",
			    OPENSSL_RSA_MAX_MODULUS_ਬਿੱਟ);
		ਰੋਕੋ;
	ਹਾਲਤ ਕੁੰਜੀ_ECDSA:
		ਜੇ (sshkey_ecdsa_ਬਿੱਟ_ਮੰਜ਼ਿਲ_nid(*bitsp) == -1)
			fatal("Invalid ECDSA key length: valid lengths are "
			    "256, 384 or 521 bits");
	}
#ਜੇ_ਅੰਤ
}

/*
 * Checks whether a file exists and, if so, asks the user whether they wish
 * to overwrite it.
 * Returns nonzero if the file does not already exist or if the user agrees to
 * overwrite, or zero otherwise.
 */
ਸਥਿਰ ਪੂਰਨ
confirm_overwrite(ਅਚਲ ਅੱਖਰ *filename)
{
	ਅੱਖਰ yesno[3];
	ਬਣਤਰ stat st;

	ਜੇ (stat(filename, &st) != 0)
		ਵਾਪਸ 1;
	ਲਿਖੋ("%s already exists.\n", filename);
	ਲਿਖੋ("Overwrite (y/n)? ");
	fflush(stdout);
	ਜੇ (fgets(yesno, ਆਕਾਰ(yesno), stdin) == ਨਿਰਾ)
		ਵਾਪਸ 0;
	ਜੇ (yesno[0] != 'y' && yesno[0] != 'Y')
		ਵਾਪਸ 0;
	ਵਾਪਸ 1;
}

ਸਥਿਰ ਖਾਲੀ
ask_filename(ਬਣਤਰ passwd *pw, ਅਚਲ ਅੱਖਰ *prompt)
{
	ਅੱਖਰ buf[1024];
	ਅੱਖਰ *name = ਨਿਰਾ;

	ਜੇ (ਕੁੰਜੀ_type_name == ਨਿਰਾ)
		name = ਰਸਤਾ_SSH_CLIENT_ID_ED25519;
	ਨਹੀਂਤਾਂ {
		ਚੋਣ (sshkey_type_from_shortname(ਕੁੰਜੀ_type_name)) {
		ਹਾਲਤ ਕੁੰਜੀ_ECDSA_CERT:
		ਹਾਲਤ ਕੁੰਜੀ_ECDSA:
			name = ਰਸਤਾ_SSH_CLIENT_ID_ECDSA;
			ਰੋਕੋ;
		ਹਾਲਤ ਕੁੰਜੀ_ECDSA_SK_CERT:
		ਹਾਲਤ ਕੁੰਜੀ_ECDSA_SK:
			name = ਰਸਤਾ_SSH_CLIENT_ID_ECDSA_SK;
			ਰੋਕੋ;
		ਹਾਲਤ ਕੁੰਜੀ_RSA_CERT:
		ਹਾਲਤ ਕੁੰਜੀ_RSA:
			name = ਰਸਤਾ_SSH_CLIENT_ID_RSA;
			ਰੋਕੋ;
		ਹਾਲਤ ਕੁੰਜੀ_ED25519:
		ਹਾਲਤ ਕੁੰਜੀ_ED25519_CERT:
			name = ਰਸਤਾ_SSH_CLIENT_ID_ED25519;
			ਰੋਕੋ;
		ਹਾਲਤ ਕੁੰਜੀ_ED25519_SK:
		ਹਾਲਤ ਕੁੰਜੀ_ED25519_SK_CERT:
			name = ਰਸਤਾ_SSH_CLIENT_ID_ED25519_SK;
			ਰੋਕੋ;
		ਹਾਲਤ ਕੁੰਜੀ_MLDSA44_ED25519:
		ਹਾਲਤ ਕੁੰਜੀ_MLDSA44_ED25519_CERT:
			name = ਰਸਤਾ_SSH_CLIENT_ID_MLDSA44_ED25519;
			ਰੋਕੋ;
		ਮੂਲ:
			fatal("bad key type");
		}
	}
	snprintf(ਪਛਾਣ_ਤੱਤ_file, ਆਕਾਰ(ਪਛਾਣ_ਤੱਤ_file),
	    "%s/%s", pw->pw_dir, name);
	ਲਿਖੋ("%s (%s): ", prompt, ਪਛਾਣ_ਤੱਤ_file);
	fflush(stdout);
	ਜੇ (fgets(buf, ਆਕਾਰ(buf), stdin) == ਨਿਰਾ)
		ਬਾਹਰ_ਨਿਕਲੋ(1);
	buf[strcspn(buf, "\n")] = '\0';
	ਜੇ (strcmp(buf, "") != 0)
		strlcpy(ਪਛਾਣ_ਤੱਤ_file, buf, ਆਕਾਰ(ਪਛਾਣ_ਤੱਤ_file));
	have_ਪਛਾਣ_ਤੱਤ = 1;
}

ਸਥਿਰ ਬਣਤਰ sshkey *
ਲੱਦੋ_ਪਛਾਣ_ਤੱਤ(ਅਚਲ ਅੱਖਰ *filename, ਅੱਖਰ **commentp)
{
	ਅੱਖਰ *prompt, *pass;
	ਬਣਤਰ sshkey *prv;
	ਪੂਰਨ r;

	ਜੇ (commentp != ਨਿਰਾ)
		*commentp = ਨਿਰਾ;
	ਜੇ ((r = sshkey_ਲੱਦੋ_ਨਿੱਜੀ(filename, "", &prv, commentp)) == 0)
		ਵਾਪਸ prv;
	ਜੇ (r != SSH_ERR_ਕੁੰਜੀ_WRONG_PASSPHRASE)
		fatal_r(r, "Load key \"%s\"", filename);
	ਜੇ (ਪਛਾਣ_ਤੱਤ_passphrase)
		pass = xstrdup(ਪਛਾਣ_ਤੱਤ_passphrase);
	ਨਹੀਂਤਾਂ {
		xasprintf(&prompt, "Enter passphrase for \"%s\": ", filename);
		pass = read_passphrase(prompt, RP_ALLOW_STDIN);
		ਮੁਕਤ(prompt);
	}
	r = sshkey_ਲੱਦੋ_ਨਿੱਜੀ(filename, pass, &prv, commentp);
	freezero(pass, ਲੜੀ_ਲੰਬਾਈ(pass));
	ਜੇ (r != 0)
		fatal_r(r, "Load key \"%s\"", filename);
	ਵਾਪਸ prv;
}

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_COM_ਜਨਤਕ_BEGIN		"---- BEGIN SSH2 PUBLIC KEY ----"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_COM_ਜਨਤਕ_ਸਿਰਾ		"---- END SSH2 PUBLIC KEY ----"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_COM_ਨਿੱਜੀ_BEGIN		"---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	SSH_COM_ਨਿੱਜੀ_ਕੁੰਜੀ_MAGIC	0x3f6ff9eb

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
ਸਥਿਰ ਖਾਲੀ
do_convert_ਮੰਜ਼ਿਲ_ssh2(ਬਣਤਰ passwd *pw, ਬਣਤਰ sshkey *k)
{
	ਬਣਤਰ sshbuf *b;
	ਅੱਖਰ comment[61], *b64;
	ਪੂਰਨ r;

	ਜੇ ((b = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = sshkey_putb(k, b)) != 0)
		fatal_fr(r, "put key");
	ਜੇ ((b64 = sshbuf_dtob64_string(b, 1)) == ਨਿਰਾ)
		fatal_f("sshbuf_dtob64_string failed");

	/* Comment + surrounds must fit into 72 chars (RFC 4716 sec 3.3) */
	snprintf(comment, ਆਕਾਰ(comment),
	    "%u-bit %s, converted by %s@%s from OpenSSH",
	    sshkey_ਮਾਪ(k), sshkey_type(k),
	    pw->pw_name, hostname);

	sshkey_free(k);
	sshbuf_free(b);

	fprintf(stdout, "%s\n", SSH_COM_ਜਨਤਕ_BEGIN);
	fprintf(stdout, "Comment: \"%s\"\n%s", comment, b64);
	fprintf(stdout, "%s\n", SSH_COM_ਜਨਤਕ_ਸਿਰਾ);
	ਮੁਕਤ(b64);
}

ਸਥਿਰ ਖਾਲੀ
do_convert_ਮੰਜ਼ਿਲ_pkcs8(ਬਣਤਰ sshkey *k)
{
	ਚੋਣ (sshkey_type_plain(k->type)) {
	ਹਾਲਤ ਕੁੰਜੀ_RSA:
		ਜੇ (!PEM_write_RSA_PUBKEY(stdout,
		    EVP_PKEY_get0_RSA(k->pkey)))
			fatal("PEM_write_RSA_PUBKEY failed");
		ਰੋਕੋ;
	ਹਾਲਤ ਕੁੰਜੀ_ECDSA:
		ਜੇ (!PEM_write_EC_PUBKEY(stdout,
		    EVP_PKEY_get0_EC_ਕੁੰਜੀ(k->pkey)))
			fatal("PEM_write_EC_PUBKEY failed");
		ਰੋਕੋ;
	ਮੂਲ:
		fatal_f("unsupported key type %s", sshkey_type(k));
	}
}

ਸਥਿਰ ਖਾਲੀ
do_convert_ਮੰਜ਼ਿਲ_pem(ਬਣਤਰ sshkey *k)
{
	ਚੋਣ (sshkey_type_plain(k->type)) {
	ਹਾਲਤ ਕੁੰਜੀ_RSA:
		ਜੇ (!PEM_write_RSAPublic_ਕੁੰਜੀ(stdout,
		    EVP_PKEY_get0_RSA(k->pkey)))
			fatal("PEM_write_RSAPublicKey failed");
		ਰੋਕੋ;
	ਹਾਲਤ ਕੁੰਜੀ_ECDSA:
		ਜੇ (!PEM_write_EC_PUBKEY(stdout,
		    EVP_PKEY_get0_EC_ਕੁੰਜੀ(k->pkey)))
			fatal("PEM_write_EC_PUBKEY failed");
		ਰੋਕੋ;
	ਮੂਲ:
		fatal_f("unsupported key type %s", sshkey_type(k));
	}
}

ਸਥਿਰ ਖਾਲੀ
do_convert_ਮੰਜ਼ਿਲ_hexdump(ਬਣਤਰ sshkey *k)
{
	ਬਣਤਰ sshbuf *b;
	ਪੂਰਨ r;

	ਜੇ ((b = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	/* pubkey */
	ਜੇ ((r = sshkey_putb(k, b)) != 0)
		fatal_fr(r, "serialise private");
	ਲਿਖੋ("Public %s key:\n", sshkey_type(k));
	sshbuf_dump(b, stdout);
	sshbuf_reset(b);
	ਜੇ ((r = sshkey_ਨਿੱਜੀ_serialize(k, b)) != 0) {
		debug_fr(r, "serialise private");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਲਿਖੋ("\nPrivate %s key:\n", sshkey_type(k));
	sshbuf_dump(b, stdout);
 ਬਾਹਰਲਾ:
	sshbuf_free(b);
}

ਸਥਿਰ ਖਾਲੀ
do_convert_ਮੰਜ਼ਿਲ(ਬਣਤਰ passwd *pw)
{
	ਬਣਤਰ sshkey *k = ਨਿਰਾ;
	ਬਣਤਰ stat st;
	ਪੂਰਨ r;

	ਜੇ (!have_ਪਛਾਣ_ਤੱਤ)
		ask_filename(pw, "Enter file in which the key is");
	ਜੇ (stat(ਪਛਾਣ_ਤੱਤ_file, &st) == -1)
		fatal("%s: %s: %s", __progname, ਪਛਾਣ_ਤੱਤ_file, strerror(errno));

	/* If we're trying to hexdump, then prefer the private key */
	ਜੇ (convert_format == FMT_HEXDUMP) {
		ਜੇ ((r = sshkey_ਲੱਦੋ_ਨਿੱਜੀ(ਪਛਾਣ_ਤੱਤ_file,
		    ਨਿਰਾ, &k, ਨਿਰਾ)) != 0 &&
		    r == SSH_ERR_ਕੁੰਜੀ_WRONG_PASSPHRASE)
			k = ਲੱਦੋ_ਪਛਾਣ_ਤੱਤ(ਪਛਾਣ_ਤੱਤ_file, ਨਿਰਾ);
	}
	ਜੇ (k == ਨਿਰਾ && (r = sshkey_ਲੱਦੋ_ਜਨਤਕ(ਪਛਾਣ_ਤੱਤ_file, &k, ਨਿਰਾ)) != 0)
		k = ਲੱਦੋ_ਪਛਾਣ_ਤੱਤ(ਪਛਾਣ_ਤੱਤ_file, ਨਿਰਾ);

	ਚੋਣ (convert_format) {
	ਹਾਲਤ FMT_RFC4716:
		do_convert_ਮੰਜ਼ਿਲ_ssh2(pw, k);
		ਰੋਕੋ;
	ਹਾਲਤ FMT_PKCS8:
		do_convert_ਮੰਜ਼ਿਲ_pkcs8(k);
		ਰੋਕੋ;
	ਹਾਲਤ FMT_PEM:
		do_convert_ਮੰਜ਼ਿਲ_pem(k);
		ਰੋਕੋ;
	ਹਾਲਤ FMT_HEXDUMP:
		do_convert_ਮੰਜ਼ਿਲ_hexdump(k);
		ਰੋਕੋ;
	ਮੂਲ:
		fatal_f("unknown key format %d", convert_format);
	}
}

/*
 * This is almost exactly the bignum1 encoding, but with 32 bit for length
 * instead of 16.
 */
ਸਥਿਰ ਖਾਲੀ
ਬਫਰ_get_bignum_ਬਿੱਟ(ਬਣਤਰ sshbuf *b, BIGNUM *ਮੁੱਲ)
{
	u_int ਬਾਈਟਾਂ, bignum_ਬਿੱਟ;
	ਪੂਰਨ r;

	ਜੇ ((r = sshbuf_get_u32(b, &bignum_ਬਿੱਟ)) != 0)
		fatal_fr(r, "parse");
	ਬਾਈਟਾਂ = (bignum_ਬਿੱਟ + 7) / 8;
	ਜੇ (sshbuf_len(b) < ਬਾਈਟਾਂ)
		fatal_f("input buffer too small: need %d have %zu",
		    ਬਾਈਟਾਂ, sshbuf_len(b));
	ਜੇ (BN_bin2bn(sshbuf_ptr(b), ਬਾਈਟਾਂ, ਮੁੱਲ) == ਨਿਰਾ)
		fatal_f("BN_bin2bn failed");
	ਜੇ ((r = sshbuf_consume(b, ਬਾਈਟਾਂ)) != 0)
		fatal_fr(r, "consume");
}

ਸਥਿਰ ਬਣਤਰ sshkey *
do_convert_ਨਿੱਜੀ_ssh2(ਬਣਤਰ sshbuf *b)
{
	ਬਣਤਰ sshkey *ਕੁੰਜੀ = ਨਿਰਾ;
	ਅੱਖਰ *type, *cipher;
	ਅਚਲ ਅੱਖਰ *alg = ਨਿਰਾ;
	u_char e1, e2, e3, *sig = ਨਿਰਾ, ਅੰਕੜੇ[] = "abcde12345";
	ਪੂਰਨ r, rlen, ktype;
	u_int magic, i1, i2, i3, i4;
	ਮਾਪ_t slen;
	u_long e;
	BIGNUM *rsa_n = ਨਿਰਾ, *rsa_e = ਨਿਰਾ, *rsa_d = ਨਿਰਾ;
	BIGNUM *rsa_p = ਨਿਰਾ, *rsa_q = ਨਿਰਾ, *rsa_iqmp = ਨਿਰਾ;
	BIGNUM *rsa_dmp1 = ਨਿਰਾ, *rsa_dmq1 = ਨਿਰਾ;
	RSA *rsa = ਨਿਰਾ;

	ਜੇ ((r = sshbuf_get_u32(b, &magic)) != 0)
		fatal_fr(r, "parse magic");

	ਜੇ (magic != SSH_COM_ਨਿੱਜੀ_ਕੁੰਜੀ_MAGIC) {
		error("bad magic 0x%x != 0x%x", magic,
		    SSH_COM_ਨਿੱਜੀ_ਕੁੰਜੀ_MAGIC);
		ਵਾਪਸ ਨਿਰਾ;
	}
	ਜੇ ((r = sshbuf_get_u32(b, &i1)) != 0 ||
	    (r = sshbuf_get_cstring(b, &type, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_cstring(b, &cipher, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_u32(b, &i2)) != 0 ||
	    (r = sshbuf_get_u32(b, &i3)) != 0 ||
	    (r = sshbuf_get_u32(b, &i4)) != 0)
		fatal_fr(r, "parse");
	debug("ignore (%d %d %d %d)", i1, i2, i3, i4);
	ਜੇ (strcmp(cipher, "none") != 0) {
		error("unsupported cipher %s", cipher);
		ਮੁਕਤ(cipher);
		ਮੁਕਤ(type);
		ਵਾਪਸ ਨਿਰਾ;
	}
	ਮੁਕਤ(cipher);

	ਜੇ (ਲੜੀ_ਖੋਜ(type, "rsa")) {
		ktype = ਕੁੰਜੀ_RSA;
	} ਨਹੀਂਤਾਂ {
		ਮੁਕਤ(type);
		ਵਾਪਸ ਨਿਰਾ;
	}
	ਜੇ ((ਕੁੰਜੀ = sshkey_new(ktype)) == ਨਿਰਾ)
		fatal("sshkey_new failed");
	ਮੁਕਤ(type);

	ਚੋਣ (ਕੁੰਜੀ->type) {
	ਹਾਲਤ ਕੁੰਜੀ_RSA:
		ਜੇ ((r = sshbuf_get_u8(b, &e1)) != 0 ||
		    (e1 < 30 && (r = sshbuf_get_u8(b, &e2)) != 0) ||
		    (e1 < 30 && (r = sshbuf_get_u8(b, &e3)) != 0))
			fatal_fr(r, "parse RSA");
		e = e1;
		debug("e %lx", e);
		ਜੇ (e < 30) {
			e <<= 8;
			e += e2;
			debug("e %lx", e);
			e <<= 8;
			e += e3;
			debug("e %lx", e);
		}
		ਜੇ ((rsa_e = BN_new()) == ਨਿਰਾ)
			fatal_f("BN_new");
		ਜੇ (!BN_ਸੈੱਟ_ਸ਼ਬਦ(rsa_e, e)) {
			BN_clear_free(rsa_e);
			sshkey_free(ਕੁੰਜੀ);
			ਵਾਪਸ ਨਿਰਾ;
		}
		ਜੇ ((rsa_n = BN_new()) == ਨਿਰਾ ||
		    (rsa_d = BN_new()) == ਨਿਰਾ ||
		    (rsa_p = BN_new()) == ਨਿਰਾ ||
		    (rsa_q = BN_new()) == ਨਿਰਾ ||
		    (rsa_iqmp = BN_new()) == ਨਿਰਾ)
			fatal_f("BN_new");
		ਬਫਰ_get_bignum_ਬਿੱਟ(b, rsa_d);
		ਬਫਰ_get_bignum_ਬਿੱਟ(b, rsa_n);
		ਬਫਰ_get_bignum_ਬਿੱਟ(b, rsa_iqmp);
		ਬਫਰ_get_bignum_ਬਿੱਟ(b, rsa_q);
		ਬਫਰ_get_bignum_ਬਿੱਟ(b, rsa_p);
		ਜੇ ((r = ssh_rsa_complete_crt_parameters(rsa_d, rsa_p, rsa_q,
		    rsa_iqmp, &rsa_dmp1, &rsa_dmq1)) != 0)
			fatal_fr(r, "generate RSA CRT parameters");
		EVP_PKEY_free(ਕੁੰਜੀ->pkey);
		ਜੇ ((ਕੁੰਜੀ->pkey = EVP_PKEY_new()) == ਨਿਰਾ)
			fatal_f("EVP_PKEY_new failed");
		ਜੇ ((rsa = RSA_new()) == ਨਿਰਾ)
			fatal_f("RSA_new failed");
		ਜੇ (!RSA_set0_ਕੁੰਜੀ(rsa, rsa_n, rsa_e, rsa_d))
			fatal_f("RSA_set0_key failed");
		rsa_n = rsa_e = rsa_d = ਨਿਰਾ; /* transferred */
		ਜੇ (!RSA_set0_factors(rsa, rsa_p, rsa_q))
			fatal_f("RSA_set0_factors failed");
		rsa_p = rsa_q = ਨਿਰਾ; /* transferred */
		ਜੇ (RSA_set0_crt_params(rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp) != 1)
			fatal_f("RSA_set0_crt_params failed");
		rsa_dmp1 = rsa_dmq1 = rsa_iqmp = ਨਿਰਾ;
		ਜੇ (EVP_PKEY_set1_RSA(ਕੁੰਜੀ->pkey, rsa) != 1)
			fatal_f("EVP_PKEY_set1_RSA failed");
		RSA_free(rsa);
		alg = "rsa-sha2-256";
		ਰੋਕੋ;
	}
	rlen = sshbuf_len(b);
	ਜੇ (rlen != 0)
		error_f("remaining bytes in key blob %d", rlen);

	/* try the key */
	ਜੇ ((r = sshkey_sign(ਕੁੰਜੀ, &sig, &slen, ਅੰਕੜੇ, ਆਕਾਰ(ਅੰਕੜੇ),
	    alg, ਨਿਰਾ, ਨਿਰਾ, 0)) != 0)
		error_fr(r, "signing with converted key failed");
	ਨਹੀਂਤਾਂ ਜੇ ((r = sshkey_verify(ਕੁੰਜੀ, sig, slen, ਅੰਕੜੇ, ਆਕਾਰ(ਅੰਕੜੇ),
	    alg, 0, ਨਿਰਾ)) != 0)
		error_fr(r, "verification with converted key failed");
	ਜੇ (r != 0) {
		sshkey_free(ਕੁੰਜੀ);
		ਮੁਕਤ(sig);
		ਵਾਪਸ ਨਿਰਾ;
	}
	ਮੁਕਤ(sig);
	ਵਾਪਸ ਕੁੰਜੀ;
}

ਸਥਿਰ ਪੂਰਨ
get_ਸਤਰ(FILE *fp, ਅੱਖਰ *ਸਤਰ, ਮਾਪ_t len)
{
	ਪੂਰਨ c;
	ਮਾਪ_t pos = 0;

	ਸਤਰ[0] = '\0';
	ਜਦੋਂ ((c = fgetc(fp)) != EOF) {
		ਜੇ (pos >= len - 1)
			fatal("input line too long.");
		ਚੋਣ (c) {
		ਹਾਲਤ '\r':
			c = fgetc(fp);
			ਜੇ (c != EOF && c != '\n' && ungetc(c, fp) == EOF)
				fatal("unget: %s", strerror(errno));
			ਵਾਪਸ pos;
		ਹਾਲਤ '\n':
			ਵਾਪਸ pos;
		}
		ਸਤਰ[pos++] = c;
		ਸਤਰ[pos] = '\0';
	}
	/* We reached EOF */
	ਵਾਪਸ -1;
}

ਸਥਿਰ ਖਾਲੀ
do_convert_from_ssh2(ਬਣਤਰ passwd *pw, ਬਣਤਰ sshkey **k, ਪੂਰਨ *ਨਿਜੀ)
{
	ਪੂਰਨ r, blen, escaped = 0;
	u_int len;
	ਅੱਖਰ ਸਤਰ[1024];
	ਬਣਤਰ sshbuf *buf;
	ਅੱਖਰ encoded[8096];
	FILE *fp;

	ਜੇ ((buf = sshbuf_new()) == ਨਿਰਾ)
		fatal("sshbuf_new failed");
	ਜੇ ((fp = fopen(ਪਛਾਣ_ਤੱਤ_file, "r")) == ਨਿਰਾ)
		fatal("%s: %s: %s", __progname, ਪਛਾਣ_ਤੱਤ_file, strerror(errno));
	encoded[0] = '\0';
	ਜਦੋਂ ((blen = get_ਸਤਰ(fp, ਸਤਰ, ਆਕਾਰ(ਸਤਰ))) != -1) {
		ਜੇ (blen > 0 && ਸਤਰ[blen - 1] == '\\')
			escaped++;
		ਜੇ (ਲੜੀ_ਤੁਲਨਾ(ਸਤਰ, "----", 4) == 0 ||
		    ਲੜੀ_ਖੋਜ(ਸਤਰ, ": ") != ਨਿਰਾ) {
			ਜੇ (ਲੜੀ_ਖੋਜ(ਸਤਰ, SSH_COM_ਨਿੱਜੀ_BEGIN) != ਨਿਰਾ)
				*ਨਿਜੀ = 1;
			ਜੇ (ਲੜੀ_ਖੋਜ(ਸਤਰ, " END ") != ਨਿਰਾ) {
				ਰੋਕੋ;
			}
			/* fprintf(stderr, "ignore: %s", line); */
			ਜਾਰੀ;
		}
		ਜੇ (escaped) {
			escaped--;
			/* fprintf(stderr, "escaped: %s", line); */
			ਜਾਰੀ;
		}
		strlcat(encoded, ਸਤਰ, ਆਕਾਰ(encoded));
	}
	len = ਲੜੀ_ਲੰਬਾਈ(encoded);
	ਜੇ (((len % 4) == 3) &&
	    (encoded[len-1] == '=') &&
	    (encoded[len-2] == '=') &&
	    (encoded[len-3] == '='))
		encoded[len-3] = '\0';
	ਜੇ ((r = sshbuf_b64tod(buf, encoded)) != 0)
		fatal_fr(r, "base64 decode");
	ਜੇ (*ਨਿਜੀ) {
		ਜੇ ((*k = do_convert_ਨਿੱਜੀ_ssh2(buf)) == ਨਿਰਾ)
			fatal_f("private key conversion failed");
	} ਨਹੀਂਤਾਂ ਜੇ ((r = sshkey_fromb(buf, k)) != 0)
		fatal_fr(r, "parse key");
	sshbuf_free(buf);
	fclose(fp);
}

ਸਥਿਰ ਖਾਲੀ
do_convert_from_pkcs8(ਬਣਤਰ sshkey **k, ਪੂਰਨ *ਨਿਜੀ)
{
	EVP_PKEY *pubkey;
	FILE *fp;

	ਜੇ ((fp = fopen(ਪਛਾਣ_ਤੱਤ_file, "r")) == ਨਿਰਾ)
		fatal("%s: %s: %s", __progname, ਪਛਾਣ_ਤੱਤ_file, strerror(errno));
	ਜੇ ((pubkey = PEM_read_PUBKEY(fp, ਨਿਰਾ, ਨਿਰਾ, ਨਿਰਾ)) == ਨਿਰਾ) {
		fatal_f("%s is not a recognised public key format",
		    ਪਛਾਣ_ਤੱਤ_file);
	}
	fclose(fp);
	ਚੋਣ (EVP_PKEY_ਅਧਾਰ_id(pubkey)) {
	ਹਾਲਤ EVP_PKEY_RSA:
		ਜੇ ((*k = sshkey_new(ਕੁੰਜੀ_UNSPEC)) == ਨਿਰਾ)
			fatal("sshkey_new failed");
		(*k)->type = ਕੁੰਜੀ_RSA;
		(*k)->pkey = pubkey;
		pubkey = ਨਿਰਾ;
		ਰੋਕੋ;
	ਹਾਲਤ EVP_PKEY_EC:
		ਜੇ ((*k = sshkey_new(ਕੁੰਜੀ_UNSPEC)) == ਨਿਰਾ)
			fatal("sshkey_new failed");
		ਜੇ (((*k)->ecdsa_nid = sshkey_ecdsa_fixup_ਸਮੂਹ(pubkey)) == -1)
			fatal("sshkey_ecdsa_fixup_group failed");
		(*k)->type = ਕੁੰਜੀ_ECDSA;
		(*k)->pkey = pubkey;
		pubkey = ਨਿਰਾ;
		ਰੋਕੋ;
	ਮੂਲ:
		fatal_f("unsupported pubkey type %d",
		    EVP_PKEY_ਅਧਾਰ_id(pubkey));
	}
	EVP_PKEY_free(pubkey);
}

ਸਥਿਰ ਖਾਲੀ
do_convert_from_pem(ਬਣਤਰ sshkey **k, ਪੂਰਨ *ਨਿਜੀ)
{
	FILE *fp;
	RSA *rsa;

	ਜੇ ((fp = fopen(ਪਛਾਣ_ਤੱਤ_file, "r")) == ਨਿਰਾ)
		fatal("%s: %s: %s", __progname, ਪਛਾਣ_ਤੱਤ_file, strerror(errno));
	ਜੇ ((rsa = PEM_read_RSAPublic_ਕੁੰਜੀ(fp, ਨਿਰਾ, ਨਿਰਾ, ਨਿਰਾ)) != ਨਿਰਾ) {
		ਜੇ ((*k = sshkey_new(ਕੁੰਜੀ_UNSPEC)) == ਨਿਰਾ)
			fatal("sshkey_new failed");
		ਜੇ (((*k)->pkey = EVP_PKEY_new()) == ਨਿਰਾ)
			fatal("EVP_PKEY_new failed");
		(*k)->type = ਕੁੰਜੀ_RSA;
		ਜੇ (EVP_PKEY_set1_RSA((*k)->pkey, rsa) != 1)
			fatal("EVP_PKEY_set1_RSA failed");
		RSA_free(rsa);
		fclose(fp);
		ਵਾਪਸ;
	}
	fatal_f("unrecognised raw private key format");
}

ਸਥਿਰ ਖਾਲੀ
do_convert_from(ਬਣਤਰ passwd *pw)
{
	ਬਣਤਰ sshkey *k = ਨਿਰਾ;
	ਪੂਰਨ r, ਨਿਜੀ = 0, ok = 0;
	ਬਣਤਰ stat st;

	ਜੇ (!have_ਪਛਾਣ_ਤੱਤ)
		ask_filename(pw, "Enter file in which the key is");
	ਜੇ (stat(ਪਛਾਣ_ਤੱਤ_file, &st) == -1)
		fatal("%s: %s: %s", __progname, ਪਛਾਣ_ਤੱਤ_file, strerror(errno));

	ਚੋਣ (convert_format) {
	ਹਾਲਤ FMT_RFC4716:
		do_convert_from_ssh2(pw, &k, &ਨਿਜੀ);
		ਰੋਕੋ;
	ਹਾਲਤ FMT_PKCS8:
		do_convert_from_pkcs8(&k, &ਨਿਜੀ);
		ਰੋਕੋ;
	ਹਾਲਤ FMT_PEM:
		do_convert_from_pem(&k, &ਨਿਜੀ);
		ਰੋਕੋ;
	ਮੂਲ:
		fatal_f("unknown key format %d", convert_format);
	}

	ਜੇ (!ਨਿਜੀ) {
		ਜੇ ((r = sshkey_write(k, stdout)) == 0)
			ok = 1;
		ਜੇ (ok)
			fprintf(stdout, "\n");
	} ਨਹੀਂਤਾਂ {
		ਚੋਣ (k->type) {
		ਹਾਲਤ ਕੁੰਜੀ_ECDSA:
			ok = PEM_write_ECPrivate_ਕੁੰਜੀ(stdout,
			    EVP_PKEY_get0_EC_ਕੁੰਜੀ(k->pkey), ਨਿਰਾ, ਨਿਰਾ, 0,
			    ਨਿਰਾ, ਨਿਰਾ);
			ਰੋਕੋ;
		ਹਾਲਤ ਕੁੰਜੀ_RSA:
			ok = PEM_write_RSAPrivate_ਕੁੰਜੀ(stdout,
			    EVP_PKEY_get0_RSA(k->pkey), ਨਿਰਾ, ਨਿਰਾ, 0,
			    ਨਿਰਾ, ਨਿਰਾ);
			ਰੋਕੋ;
		ਮੂਲ:
			fatal_f("unsupported key type %s", sshkey_type(k));
		}
	}

	ਜੇ (!ok)
		fatal("key write failed");
	sshkey_free(k);
}
#ਜੇ_ਅੰਤ

ਸਥਿਰ ਖਾਲੀ
do_print_ਜਨਤਕ(ਬਣਤਰ passwd *pw)
{
	ਬਣਤਰ sshkey *prv;
	ਬਣਤਰ stat st;
	ਪੂਰਨ r;
	ਅੱਖਰ *comment = ਨਿਰਾ;

	ਜੇ (!have_ਪਛਾਣ_ਤੱਤ)
		ask_filename(pw, "Enter file in which the key is");
	ਜੇ (stat(ਪਛਾਣ_ਤੱਤ_file, &st) == -1)
		fatal("%s: %s", ਪਛਾਣ_ਤੱਤ_file, strerror(errno));
	prv = ਲੱਦੋ_ਪਛਾਣ_ਤੱਤ(ਪਛਾਣ_ਤੱਤ_file, &comment);
	ਜੇ ((r = sshkey_write(prv, stdout)) != 0)
		fatal_fr(r, "write key");
	ਜੇ (comment != ਨਿਰਾ && *comment != '\0')
		fprintf(stdout, " %s", comment);
	fprintf(stdout, "\n");
	ਜੇ (sshkey_is_sk(prv)) {
		debug("sk_application: \"%s\", sk_flags 0x%02x",
			prv->sk_application, prv->sk_flags);
	}
	sshkey_free(prv);
	ਮੁਕਤ(comment);
	ਬਾਹਰ_ਨਿਕਲੋ(0);
}

ਸਥਿਰ ਖਾਲੀ
do_download(ਬਣਤਰ passwd *pw)
{
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ ENABLE_PKCS11
	ਬਣਤਰ sshkey **ਕੁੰਜੀਆਂ = ਨਿਰਾ;
	ਪੂਰਨ i, nkeys;
	ਗਿਣਤੀ sshkey_fp_rep rep;
	ਪੂਰਨ fptype;
	ਅੱਖਰ *fp, *ra, **comments = ਨਿਰਾ;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;

	pkcs11_init(1);
	nkeys = pkcs11_ਜੋੜੋ_provider(pkcs11provider, ਨਿਰਾ, &ਕੁੰਜੀਆਂ, &comments);
	ਜੇ (nkeys <= 0)
		fatal("cannot read public key from pkcs11");
	ਲਈ (i = 0; i < nkeys; i++) {
		ਜੇ (print_fingerprint) {
			fp = sshkey_fingerprint(ਕੁੰਜੀਆਂ[i], fptype, rep);
			ra = sshkey_fingerprint(ਕੁੰਜੀਆਂ[i], fingerprint_hash,
			    SSH_FP_RANDOMART);
			ਜੇ (fp == ਨਿਰਾ || ra == ਨਿਰਾ)
				fatal_f("sshkey_fingerprint fail");
			ਲਿਖੋ("%u %s %s (PKCS11 key)\n", sshkey_ਮਾਪ(ਕੁੰਜੀਆਂ[i]),
			    fp, sshkey_type(ਕੁੰਜੀਆਂ[i]));
			ਜੇ (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
				ਲਿਖੋ("%s\n", ra);
			ਮੁਕਤ(ra);
			ਮੁਕਤ(fp);
		} ਨਹੀਂਤਾਂ {
			(ਖਾਲੀ) sshkey_write(ਕੁੰਜੀਆਂ[i], stdout); /* XXX check */
			fprintf(stdout, "%s%s\n",
			    *(comments[i]) == '\0' ? "" : " ", comments[i]);
		}
		ਮੁਕਤ(comments[i]);
		sshkey_free(ਕੁੰਜੀਆਂ[i]);
	}
	ਮੁਕਤ(comments);
	ਮੁਕਤ(ਕੁੰਜੀਆਂ);
	pkcs11_terminate();
	ਬਾਹਰ_ਨਿਕਲੋ(0);
#ਨਹੀਂਤਾਂ
	fatal("no pkcs11 support");
#ਜੇ_ਅੰਤ /* ENABLE_PKCS11 */
}

ਸਥਿਰ ਬਣਤਰ sshkey *
try_read_ਕੁੰਜੀ(ਅੱਖਰ **cpp)
{
	ਬਣਤਰ sshkey *ret;
	ਪੂਰਨ r;

	ਜੇ ((ret = sshkey_new(ਕੁੰਜੀ_UNSPEC)) == ਨਿਰਾ)
		fatal("sshkey_new failed");
	ਜੇ ((r = sshkey_read(ret, cpp)) == 0)
		ਵਾਪਸ ret;
	/* Not a key */
	sshkey_free(ret);
	ਵਾਪਸ ਨਿਰਾ;
}

ਸਥਿਰ ਖਾਲੀ
fingerprint_one_ਕੁੰਜੀ(ਅਚਲ ਬਣਤਰ sshkey *ਜਨਤਕ, ਅਚਲ ਅੱਖਰ *comment)
{
	ਅੱਖਰ *fp = ਨਿਰਾ, *ra = ਨਿਰਾ;
	ਗਿਣਤੀ sshkey_fp_rep rep;
	ਪੂਰਨ fptype;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;
	fp = sshkey_fingerprint(ਜਨਤਕ, fptype, rep);
	ra = sshkey_fingerprint(ਜਨਤਕ, fingerprint_hash, SSH_FP_RANDOMART);
	ਜੇ (fp == ਨਿਰਾ || ra == ਨਿਰਾ)
		fatal_f("sshkey_fingerprint failed");
	mprintf("%u %s %s (%s)\n", sshkey_ਮਾਪ(ਜਨਤਕ), fp,
	    comment ? comment : "no comment", sshkey_type(ਜਨਤਕ));
	ਜੇ (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
		ਲਿਖੋ("%s\n", ra);
	ਮੁਕਤ(ra);
	ਮੁਕਤ(fp);
}

ਸਥਿਰ ਖਾਲੀ
fingerprint_ਨਿੱਜੀ(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ)
{
	ਬਣਤਰ stat st;
	ਅੱਖਰ *comment = ਨਿਰਾ;
	ਬਣਤਰ sshkey *privkey = ਨਿਰਾ, *pubkey = ਨਿਰਾ;
	ਪੂਰਨ r;

	ਜੇ (stat(ਪਛਾਣ_ਤੱਤ_file, &st) == -1)
		fatal("%s: %s", ਰਸਤਾ, strerror(errno));
	ਜੇ ((r = sshkey_ਲੱਦੋ_ਜਨਤਕ(ਰਸਤਾ, &pubkey, &comment)) != 0)
		debug_r(r, "load public \"%s\"", ਰਸਤਾ);
	ਜੇ (pubkey == ਨਿਰਾ || comment == ਨਿਰਾ || *comment == '\0') {
		ਮੁਕਤ(comment);
		ਜੇ ((r = sshkey_ਲੱਦੋ_ਨਿੱਜੀ(ਰਸਤਾ, ਨਿਰਾ,
		    &privkey, &comment)) != 0)
			debug_r(r, "load private \"%s\"", ਰਸਤਾ);
	}
	ਜੇ (pubkey == ਨਿਰਾ && privkey == ਨਿਰਾ)
		fatal("%s is not a key file.", ਰਸਤਾ);

	fingerprint_one_ਕੁੰਜੀ(pubkey == ਨਿਰਾ ? privkey : pubkey, comment);
	sshkey_free(pubkey);
	sshkey_free(privkey);
	ਮੁਕਤ(comment);
}

ਸਥਿਰ ਖਾਲੀ
do_fingerprint(ਬਣਤਰ passwd *pw)
{
	FILE *f;
	ਬਣਤਰ sshkey *ਜਨਤਕ = ਨਿਰਾ;
	ਅੱਖਰ *comment = ਨਿਰਾ, *cp, *ep, *ਸਤਰ = ਨਿਰਾ;
	ਮਾਪ_t linesize = 0;
	ਪੂਰਨ i, invalid = 1;
	ਅਚਲ ਅੱਖਰ *ਰਸਤਾ;
	u_long lnum = 0;

	ਜੇ (!have_ਪਛਾਣ_ਤੱਤ)
		ask_filename(pw, "Enter file in which the key is");
	ਰਸਤਾ = ਪਛਾਣ_ਤੱਤ_file;

	ਜੇ (strcmp(ਪਛਾਣ_ਤੱਤ_file, "-") == 0) {
		f = stdin;
		ਰਸਤਾ = "(stdin)";
	} ਨਹੀਂਤਾਂ ਜੇ ((f = fopen(ਰਸਤਾ, "r")) == ਨਿਰਾ)
		fatal("%s: %s: %s", __progname, ਰਸਤਾ, strerror(errno));

	ਜਦੋਂ (getline(&ਸਤਰ, &linesize, f) != -1) {
		lnum++;
		cp = ਸਤਰ;
		cp[strcspn(cp, "\r\n")] = '\0';
		/* Trim leading space and comments */
		cp = ਸਤਰ + strspn(ਸਤਰ, " \t");
		ਜੇ (*cp == '#' || *cp == '\0')
			ਜਾਰੀ;

		/*
		 * Input may be plain keys, private keys, authorized_keys
		 * or known_hosts.
		 */

		/*
		 * Try private keys first. Assume a key is private if
		 * "SSH PRIVATE KEY" appears on the first line and we're
		 * not reading from stdin (XXX support private keys on stdin).
		 */
		ਜੇ (lnum == 1 && strcmp(ਪਛਾਣ_ਤੱਤ_file, "-") != 0 &&
		    ਲੜੀ_ਖੋਜ(cp, "PRIVATE KEY") != ਨਿਰਾ) {
			ਮੁਕਤ(ਸਤਰ);
			fclose(f);
			fingerprint_ਨਿੱਜੀ(ਰਸਤਾ);
			ਬਾਹਰ_ਨਿਕਲੋ(0);
		}

		/*
		 * If it's not a private key, then this must be prepared to
		 * accept a public key prefixed with a hostname or options.
		 * Try a bare key first, otherwise skip the leading stuff.
		 */
		comment = ਨਿਰਾ;
		ਜੇ ((ਜਨਤਕ = try_read_ਕੁੰਜੀ(&cp)) == ਨਿਰਾ) {
			i = strtol(cp, &ep, 10);
			ਜੇ (i == 0 || ep == ਨਿਰਾ ||
			    (*ep != ' ' && *ep != '\t')) {
				ਪੂਰਨ quoted = 0;

				comment = cp;
				ਲਈ (; *cp && (quoted || (*cp != ' ' &&
				    *cp != '\t')); cp++) {
					ਜੇ (*cp == '\\' && cp[1] == '"')
						cp++;	/* Skip both */
					ਨਹੀਂਤਾਂ ਜੇ (*cp == '"')
						quoted = !quoted;
				}
				ਜੇ (!*cp)
					ਜਾਰੀ;
				*cp++ = '\0';
			}
		}
		/* Retry after parsing leading hostname/key options */
		ਜੇ (ਜਨਤਕ == ਨਿਰਾ && (ਜਨਤਕ = try_read_ਕੁੰਜੀ(&cp)) == ਨਿਰਾ) {
			debug("%s:%lu: not a public key", ਰਸਤਾ, lnum);
			ਜਾਰੀ;
		}

		/* Find trailing comment, if any */
		ਲਈ (; *cp == ' ' || *cp == '\t'; cp++)
			;
		ਜੇ (*cp != '\0' && *cp != '#')
			comment = cp;

		fingerprint_one_ਕੁੰਜੀ(ਜਨਤਕ, comment);
		sshkey_free(ਜਨਤਕ);
		invalid = 0; /* One good key in the file is sufficient */
	}
	fclose(f);
	ਮੁਕਤ(ਸਤਰ);

	ਜੇ (invalid)
		fatal("%s is not a public key file.", ਰਸਤਾ);
	ਬਾਹਰ_ਨਿਕਲੋ(0);
}

ਸਥਿਰ ਖਾਲੀ
do_gen_all_hostkeys(ਬਣਤਰ passwd *pw)
{
	ਬਣਤਰ {
		ਅੱਖਰ *ਕੁੰਜੀ_type;
		ਅੱਖਰ *ਕੁੰਜੀ_type_display;
		ਅੱਖਰ *ਰਸਤਾ;
	} ਕੁੰਜੀ_types[] = {
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
		{ "rsa", "RSA" ,ਰਸਤਾ_HOST_RSA_ਕੁੰਜੀ_FILE },
		{ "ecdsa", "ECDSA",ਰਸਤਾ_HOST_ECDSA_ਕੁੰਜੀ_FILE },
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
		{ "ed25519", "ED25519",ਰਸਤਾ_HOST_ED25519_ਕੁੰਜੀ_FILE },
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_MLDSA
		{ "mldsa44-ed25519", "MLDSA44-ED25519",
		     ਰਸਤਾ_HOST_MLDSA44_ED25519_ਕੁੰਜੀ_FILE },
#ਜੇ_ਅੰਤ
		{ ਨਿਰਾ, ਨਿਰਾ, ਨਿਰਾ }
	};

	uint32_t ਬਿੱਟ = 0;
	ਪੂਰਨ ਪਹਿਲਾ = 0;
	ਬਣਤਰ stat st;
	ਬਣਤਰ sshkey *ਨਿਜੀ, *ਜਨਤਕ;
	ਅੱਖਰ comment[ਕੁੰਜੀ_COMMENT_MAX], *prv_tmp, *pub_tmp, *prv_file, *pub_file;
	ਪੂਰਨ i, type, fd, r;

	ਲਈ (i = 0; ਕੁੰਜੀ_types[i].ਕੁੰਜੀ_type; i++) {
		ਜਨਤਕ = ਨਿਜੀ = ਨਿਰਾ;
		prv_tmp = pub_tmp = prv_file = pub_file = ਨਿਰਾ;

		xasprintf(&prv_file, "%s%s",
		    ਪਛਾਣ_ਤੱਤ_file, ਕੁੰਜੀ_types[i].ਰਸਤਾ);

		/* Check whether private key exists and is not zero-length */
		ਜੇ (stat(prv_file, &st) == 0) {
			ਜੇ (st.st_size != 0)
				ਜਾਓ ਅਗਲਾ;
		} ਨਹੀਂਤਾਂ ਜੇ (errno != ENOENT) {
			error("Could not stat %s: %s", ਕੁੰਜੀ_types[i].ਰਸਤਾ,
			    strerror(errno));
			ਜਾਓ failnext;
		}

		/*
		 * Private key doesn't exist or is invalid; proceed with
		 * key generation.
		 */
		xasprintf(&prv_tmp, "%s%s.XXXXXXXXXX",
		    ਪਛਾਣ_ਤੱਤ_file, ਕੁੰਜੀ_types[i].ਰਸਤਾ);
		xasprintf(&pub_tmp, "%s%s.pub.XXXXXXXXXX",
		    ਪਛਾਣ_ਤੱਤ_file, ਕੁੰਜੀ_types[i].ਰਸਤਾ);
		xasprintf(&pub_file, "%s%s.pub",
		    ਪਛਾਣ_ਤੱਤ_file, ਕੁੰਜੀ_types[i].ਰਸਤਾ);

		ਜੇ (ਪਹਿਲਾ == 0) {
			ਪਹਿਲਾ = 1;
			ਲਿਖੋ("%s: generating new host keys: ", __progname);
		}
		ਲਿਖੋ("%s ", ਕੁੰਜੀ_types[i].ਕੁੰਜੀ_type_display);
		fflush(stdout);
		type = sshkey_type_from_shortname(ਕੁੰਜੀ_types[i].ਕੁੰਜੀ_type);
		ਜੇ ((fd = mkstemp(prv_tmp)) == -1) {
			error("Could not save your private key in %s: %s",
			    prv_tmp, strerror(errno));
			ਜਾਓ failnext;
		}
		(ਖਾਲੀ)close(fd); /* just using mkstemp() to reserve a name */
		ਬਿੱਟ = 0;
		type_ਬਿੱਟ_valid(type, ਨਿਰਾ, &ਬਿੱਟ);
		ਜੇ ((r = sshkey_generate(type, ਬਿੱਟ, &ਨਿਜੀ)) != 0) {
			error_r(r, "sshkey_generate failed");
			ਜਾਓ failnext;
		}
		ਜੇ ((r = sshkey_from_ਨਿੱਜੀ(ਨਿਜੀ, &ਜਨਤਕ)) != 0)
			fatal_fr(r, "sshkey_from_private");
		snprintf(comment, ਆਕਾਰ comment, "%s@%s", pw->pw_name,
		    hostname);
		ਜੇ ((r = sshkey_save_ਨਿੱਜੀ(ਨਿਜੀ, prv_tmp, "",
		    comment, ਨਿੱਜੀ_ਕੁੰਜੀ_format, openssh_format_cipher,
		    ਗੇੜ)) != 0) {
			error_r(r, "Saving key \"%s\" failed", prv_tmp);
			ਜਾਓ failnext;
		}
		ਜੇ ((fd = mkstemp(pub_tmp)) == -1) {
			error("Could not save your public key in %s: %s",
			    pub_tmp, strerror(errno));
			ਜਾਓ failnext;
		}
		(ਖਾਲੀ)fchmod(fd, 0644);
		(ਖਾਲੀ)close(fd);
		ਜੇ ((r = sshkey_save_ਜਨਤਕ(ਜਨਤਕ, pub_tmp, comment)) != 0) {
			error_r(r, "Unable to save public key to %s",
			    ਪਛਾਣ_ਤੱਤ_file);
			ਜਾਓ failnext;
		}

		/* Rename temporary files to their permanent locations. */
		ਜੇ (rename(pub_tmp, pub_file) != 0) {
			error("Unable to move %s into position: %s",
			    pub_file, strerror(errno));
			ਜਾਓ failnext;
		}
		ਜੇ (rename(prv_tmp, prv_file) != 0) {
			error("Unable to move %s into position: %s",
			    ਕੁੰਜੀ_types[i].ਰਸਤਾ, strerror(errno));
 failnext:
			ਪਹਿਲਾ = 0;
			ਜਾਓ ਅਗਲਾ;
		}
 ਅਗਲਾ:
		sshkey_free(ਨਿਜੀ);
		sshkey_free(ਜਨਤਕ);
		ਮੁਕਤ(prv_tmp);
		ਮੁਕਤ(pub_tmp);
		ਮੁਕਤ(prv_file);
		ਮੁਕਤ(pub_file);
	}
	ਜੇ (ਪਹਿਲਾ != 0)
		ਲਿਖੋ("\n");
}

ਬਣਤਰ ਗਿਆਤ_hosts_ctx {
	ਅਚਲ ਅੱਖਰ *host;	/* Hostname searched for in find/delete case */
	FILE *ਬਾਹਰਲਾ;		/* Output file, stdout for find_hosts case */
	ਪੂਰਨ has_unhashed;	/* When hashing, original had unhashed hosts */
	ਪੂਰਨ ਮਿਲਿਆ_ਕੁੰਜੀ;		/* For find/delete, host was found */
	ਪੂਰਨ invalid;		/* File contained invalid items; don't delete */
	ਪੂਰਨ hash_hosts;		/* Hash hostnames as we go */
	ਪੂਰਨ ਲੱਭੋ_host;		/* Search for specific hostname */
	ਪੂਰਨ delete_host;	/* Delete host from known_hosts */
};

ਸਥਿਰ ਪੂਰਨ
ਗਿਆਤ_hosts_hash(ਬਣਤਰ hostkey_foreach_ਸਤਰ *l, ਖਾਲੀ *_ctx)
{
	ਬਣਤਰ ਗਿਆਤ_hosts_ctx *ctx = (ਬਣਤਰ ਗਿਆਤ_hosts_ctx *)_ctx;
	ਅੱਖਰ *hashed, *cp, *hosts, *ohosts;
	ਪੂਰਨ has_wild = l->hosts && strcspn(l->hosts, "*?!") != ਲੜੀ_ਲੰਬਾਈ(l->hosts);
	ਪੂਰਨ was_hashed = l->hosts && l->hosts[0] == HASH_DELIM;

	ਚੋਣ (l->ਸਥਿਤੀ) {
	ਹਾਲਤ HKF_ਸਥਿਤੀ_OK:
	ਹਾਲਤ HKF_ਸਥਿਤੀ_MATCHED:
		/*
		 * Don't hash hosts already hashed, with wildcard
		 * characters or a CA/revocation marker.
		 */
		ਜੇ (was_hashed || has_wild || l->marker != MRK_NONE) {
			fprintf(ctx->ਬਾਹਰਲਾ, "%s\n", l->ਸਤਰ);
			ਜੇ (has_wild && !ctx->ਲੱਭੋ_host) {
				logit("%s:%lu: ignoring host name "
				    "with wildcard: %.64s", l->ਰਸਤਾ,
				    l->linenum, l->hosts);
			}
			ਵਾਪਸ 0;
		}
		/*
		 * Split any comma-separated hostnames from the host list,
		 * hash and store separately.
		 */
		ohosts = hosts = xstrdup(l->hosts);
		ਜਦੋਂ ((cp = strsep(&hosts, ",")) != ਨਿਰਾ && *cp != '\0') {
			lowercase(cp);
			ਜੇ ((hashed = host_hash(cp, ਨਿਰਾ, 0)) == ਨਿਰਾ)
				fatal("hash_host failed");
			fprintf(ctx->ਬਾਹਰਲਾ, "%s %s\n", hashed, l->rawkey);
			ਮੁਕਤ(hashed);
			ctx->has_unhashed = 1;
		}
		ਮੁਕਤ(ohosts);
		ਵਾਪਸ 0;
	ਹਾਲਤ HKF_ਸਥਿਤੀ_INVALID:
		/* Retain invalid lines, but mark file as invalid. */
		ctx->invalid = 1;
		logit("%s:%lu: invalid line", l->ਰਸਤਾ, l->linenum);
		/* FALLTHROUGH */
	ਮੂਲ:
		fprintf(ctx->ਬਾਹਰਲਾ, "%s\n", l->ਸਤਰ);
		ਵਾਪਸ 0;
	}
	/* NOTREACHED */
	ਵਾਪਸ -1;
}

ਸਥਿਰ ਪੂਰਨ
ਗਿਆਤ_hosts_ਲੱਭੋ_delete(ਬਣਤਰ hostkey_foreach_ਸਤਰ *l, ਖਾਲੀ *_ctx)
{
	ਬਣਤਰ ਗਿਆਤ_hosts_ctx *ctx = (ਬਣਤਰ ਗਿਆਤ_hosts_ctx *)_ctx;
	ਗਿਣਤੀ sshkey_fp_rep rep;
	ਪੂਰਨ fptype;
	ਅੱਖਰ *fp = ਨਿਰਾ, *ra = ਨਿਰਾ;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;

	ਜੇ (l->ਸਥਿਤੀ == HKF_ਸਥਿਤੀ_MATCHED) {
		ਜੇ (ctx->delete_host) {
			ਜੇ (l->marker != MRK_NONE) {
				/* Don't remove CA and revocation lines */
				fprintf(ctx->ਬਾਹਰਲਾ, "%s\n", l->ਸਤਰ);
			} ਨਹੀਂਤਾਂ {
				/*
				 * Hostname matches and has no CA/revoke
				 * marker, delete it by *not* writing the
				 * line to ctx->out.
				 */
				ctx->ਮਿਲਿਆ_ਕੁੰਜੀ = 1;
				ਜੇ (!quiet)
					ਲਿਖੋ("# Host %s found: line %lu\n",
					    ctx->host, l->linenum);
			}
			ਵਾਪਸ 0;
		} ਨਹੀਂਤਾਂ ਜੇ (ctx->ਲੱਭੋ_host) {
			ctx->ਮਿਲਿਆ_ਕੁੰਜੀ = 1;
			ਜੇ (!quiet) {
				ਲਿਖੋ("# Host %s found: line %lu %s\n",
				    ctx->host,
				    l->linenum, l->marker == MRK_CA ? "CA" :
				    (l->marker == MRK_REVOKE ? "REVOKED" : ""));
			}
			ਜੇ (ctx->hash_hosts)
				ਗਿਆਤ_hosts_hash(l, ctx);
			ਨਹੀਂਤਾਂ ਜੇ (print_fingerprint) {
				fp = sshkey_fingerprint(l->ਕੁੰਜੀ, fptype, rep);
				ra = sshkey_fingerprint(l->ਕੁੰਜੀ,
				    fingerprint_hash, SSH_FP_RANDOMART);
				ਜੇ (fp == ਨਿਰਾ || ra == ਨਿਰਾ)
					fatal_f("sshkey_fingerprint failed");
				mprintf("%s %s %s%s%s\n", ctx->host,
				    sshkey_type(l->ਕੁੰਜੀ), fp,
				    l->comment[0] ? " " : "",
				    l->comment);
				ਜੇ (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
					ਲਿਖੋ("%s\n", ra);
				ਮੁਕਤ(ra);
				ਮੁਕਤ(fp);
			} ਨਹੀਂਤਾਂ
				fprintf(ctx->ਬਾਹਰਲਾ, "%s\n", l->ਸਤਰ);
			ਵਾਪਸ 0;
		}
	} ਨਹੀਂਤਾਂ ਜੇ (ctx->delete_host) {
		/* Retain non-matching hosts when deleting */
		ਜੇ (l->ਸਥਿਤੀ == HKF_ਸਥਿਤੀ_INVALID) {
			ctx->invalid = 1;
			logit("%s:%lu: invalid line", l->ਰਸਤਾ, l->linenum);
		}
		fprintf(ctx->ਬਾਹਰਲਾ, "%s\n", l->ਸਤਰ);
	}
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਖਾਲੀ
do_ਗਿਆਤ_hosts(ਬਣਤਰ passwd *pw, ਅਚਲ ਅੱਖਰ *name, ਪੂਰਨ ਲੱਭੋ_host,
    ਪੂਰਨ delete_host, ਪੂਰਨ hash_hosts)
{
	ਅੱਖਰ *cp, tmp[PATH_MAX], old[PATH_MAX];
	ਪੂਰਨ r, fd, oerrno, inplace = 0;
	ਬਣਤਰ ਗਿਆਤ_hosts_ctx ctx;
	u_int foreach_options;
	ਬਣਤਰ stat sb;

	ਜੇ (!have_ਪਛਾਣ_ਤੱਤ) {
		cp = tilde_expand_filename(ਰਸਤਾ_SSH_USER_HOSTFILE, pw->pw_uid);
		ਜੇ (strlcpy(ਪਛਾਣ_ਤੱਤ_file, cp, ਆਕਾਰ(ਪਛਾਣ_ਤੱਤ_file)) >=
		    ਆਕਾਰ(ਪਛਾਣ_ਤੱਤ_file))
			fatal("Specified known hosts path too long");
		ਮੁਕਤ(cp);
		have_ਪਛਾਣ_ਤੱਤ = 1;
	}
	ਜੇ (stat(ਪਛਾਣ_ਤੱਤ_file, &sb) != 0)
		fatal("Cannot stat %s: %s", ਪਛਾਣ_ਤੱਤ_file, strerror(errno));

	memset(&ctx, 0, ਆਕਾਰ(ctx));
	ctx.ਬਾਹਰਲਾ = stdout;
	ctx.host = name;
	ctx.hash_hosts = hash_hosts;
	ctx.ਲੱਭੋ_host = ਲੱਭੋ_host;
	ctx.delete_host = delete_host;

	/*
	 * Find hosts goes to stdout, hash and deletions happen in-place
	 * A corner case is ssh-keygen -HF foo, which should go to stdout
	 */
	ਜੇ (!ਲੱਭੋ_host && (hash_hosts || delete_host)) {
		ਜੇ (strlcpy(tmp, ਪਛਾਣ_ਤੱਤ_file, ਆਕਾਰ(tmp)) >= ਆਕਾਰ(tmp) ||
		    strlcat(tmp, ".XXXXXXXXXX", ਆਕਾਰ(tmp)) >= ਆਕਾਰ(tmp) ||
		    strlcpy(old, ਪਛਾਣ_ਤੱਤ_file, ਆਕਾਰ(old)) >= ਆਕਾਰ(old) ||
		    strlcat(old, ".old", ਆਕਾਰ(old)) >= ਆਕਾਰ(old))
			fatal("known_hosts path too long");
		umask(077);
		ਜੇ ((fd = mkstemp(tmp)) == -1)
			fatal("mkstemp: %s", strerror(errno));
		ਜੇ ((ctx.ਬਾਹਰਲਾ = fdopen(fd, "w")) == ਨਿਰਾ) {
			oerrno = errno;
			unlink(tmp);
			fatal("fdopen: %s", strerror(oerrno));
		}
		(ਖਾਲੀ)fchmod(fd, sb.st_mode & 0644);
		inplace = 1;
	}
	/* XXX support identity_file == "-" for stdin */
	foreach_options = ਲੱਭੋ_host ? HKF_WANT_ਮੇਲ : 0;
	foreach_options |= print_fingerprint ? HKF_WANT_PARSE_ਕੁੰਜੀ : 0;
	ਜੇ ((r = hostkeys_foreach(ਪਛਾਣ_ਤੱਤ_file, (ਲੱਭੋ_host || !hash_hosts) ?
	    ਗਿਆਤ_hosts_ਲੱਭੋ_delete : ਗਿਆਤ_hosts_hash, &ctx, name, ਨਿਰਾ,
	    foreach_options, 0)) != 0) {
		ਜੇ (inplace)
			unlink(tmp);
		fatal_fr(r, "hostkeys_foreach");
	}

	ਜੇ (inplace)
		fclose(ctx.ਬਾਹਰਲਾ);

	ਜੇ (ctx.invalid) {
		error("%s is not a valid known_hosts file.", ਪਛਾਣ_ਤੱਤ_file);
		ਜੇ (inplace) {
			error("Not replacing existing known_hosts "
			    "file because of errors");
			unlink(tmp);
		}
		ਬਾਹਰ_ਨਿਕਲੋ(1);
	} ਨਹੀਂਤਾਂ ਜੇ (delete_host && !ctx.ਮਿਲਿਆ_ਕੁੰਜੀ) {
		logit("Host %s not found in %s", name, ਪਛਾਣ_ਤੱਤ_file);
		ਜੇ (inplace)
			unlink(tmp);
	} ਨਹੀਂਤਾਂ ਜੇ (inplace) {
		/* Backup existing file */
		ਜੇ (unlink(old) == -1 && errno != ENOENT)
			fatal("unlink %.100s: %s", old, strerror(errno));
		ਜੇ (link(ਪਛਾਣ_ਤੱਤ_file, old) == -1)
			fatal("link %.100s to %.100s: %s", ਪਛਾਣ_ਤੱਤ_file, old,
			    strerror(errno));
		/* Move new one into place */
		ਜੇ (rename(tmp, ਪਛਾਣ_ਤੱਤ_file) == -1) {
			error("rename\"%s\" to \"%s\": %s", tmp, ਪਛਾਣ_ਤੱਤ_file,
			    strerror(errno));
			unlink(tmp);
			unlink(old);
			ਬਾਹਰ_ਨਿਕਲੋ(1);
		}

		ਲਿਖੋ("%s updated.\n", ਪਛਾਣ_ਤੱਤ_file);
		ਲਿਖੋ("Original contents retained as %s\n", old);
		ਜੇ (ctx.has_unhashed) {
			logit("WARNING: %s contains unhashed entries", old);
			logit("Delete this file to ensure privacy "
			    "of hostnames");
		}
	}

	ਬਾਹਰ_ਨਿਕਲੋ (ਲੱਭੋ_host && !ctx.ਮਿਲਿਆ_ਕੁੰਜੀ);
}

/*
 * Perform changing a passphrase.  The argument is the passwd structure
 * for the current user.
 */
ਸਥਿਰ ਖਾਲੀ
do_change_passphrase(ਬਣਤਰ passwd *pw, ਅੱਖਰ * ਅਚਲ *opts, ਮਾਪ_t nopts)
{
	ਅੱਖਰ *comment;
	ਅੱਖਰ *old_passphrase, *passphrase1, *passphrase2;
	ਬਣਤਰ stat st;
	ਬਣਤਰ sshkey *ਨਿਜੀ;
	ਪੂਰਨ r;
	ਮਾਪ_t i;

	ਜੇ (!have_ਪਛਾਣ_ਤੱਤ)
		ask_filename(pw, "Enter file in which the key is");
	ਜੇ (stat(ਪਛਾਣ_ਤੱਤ_file, &st) == -1)
		fatal("%s: %s", ਪਛਾਣ_ਤੱਤ_file, strerror(errno));
	/* Try to load the file with empty passphrase. */
	r = sshkey_ਲੱਦੋ_ਨਿੱਜੀ(ਪਛਾਣ_ਤੱਤ_file, "", &ਨਿਜੀ, &comment);
	ਜੇ (r == SSH_ERR_ਕੁੰਜੀ_WRONG_PASSPHRASE) {
		ਜੇ (ਪਛਾਣ_ਤੱਤ_passphrase)
			old_passphrase = xstrdup(ਪਛਾਣ_ਤੱਤ_passphrase);
		ਨਹੀਂਤਾਂ
			old_passphrase =
			    read_passphrase("Enter old passphrase: ",
			    RP_ALLOW_STDIN);
		r = sshkey_ਲੱਦੋ_ਨਿੱਜੀ(ਪਛਾਣ_ਤੱਤ_file, old_passphrase,
		    &ਨਿਜੀ, &comment);
		freezero(old_passphrase, ਲੜੀ_ਲੰਬਾਈ(old_passphrase));
		ਜੇ (r != 0)
			ਜਾਓ badkey;
	} ਨਹੀਂਤਾਂ ਜੇ (r != 0) {
 badkey:
		fatal_r(r, "Failed to load key %s", ਪਛਾਣ_ਤੱਤ_file);
	}
	ਜੇ (comment)
		mprintf("Key has comment '%s'\n", comment);

	/* All current -O options relate to FIDO keys only */
	ਜੇ (nopts != 0 && !sshkey_is_sk(ਨਿਜੀ)) {
		fatal("FIDO-specific option requested for non-FIDO key %s",
		    ਪਛਾਣ_ਤੱਤ_file);
	}
	ਜੇ (sshkey_is_sk(ਨਿਜੀ)) {
		debug_f("%s: original FIDO key flags: "
		    "%stouch-required %sverify-required", ਪਛਾਣ_ਤੱਤ_file,
		    (ਨਿਜੀ->sk_flags & SSH_SK_USER_PRESENCE_REQD) ? "": "no-",
		    (ਨਿਜੀ->sk_flags & SSH_SK_USER_VERIFICATION_REQD) ? "" : "no-");
	}
	ਲਈ (i = 0; i < nopts; i++) {
		ਜੇ (strcasecmp(opts[i], "touch-required") == 0)
			ਨਿਜੀ->sk_flags |= SSH_SK_USER_PRESENCE_REQD;
		ਨਹੀਂਤਾਂ ਜੇ (strcasecmp(opts[i], "no-touch-required") == 0)
			ਨਿਜੀ->sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
		ਨਹੀਂਤਾਂ ਜੇ (strcasecmp(opts[i], "verify-required") == 0)
			ਨਿਜੀ->sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
		ਨਹੀਂਤਾਂ ਜੇ (strcasecmp(opts[i], "no-verify-required") == 0)
			ਨਿਜੀ->sk_flags &= ~SSH_SK_USER_VERIFICATION_REQD;
		ਨਹੀਂਤਾਂ {
			fatal("Option \"%s\" is unsupported for "
			    "key passphrase change", opts[i]);
		}
	}
	ਜੇ (sshkey_is_sk(ਨਿਜੀ) && nopts != 0) {
		debug_f("%s: updated FIDO key flags: "
		    "%stouch-required %sverify-required", ਪਛਾਣ_ਤੱਤ_file,
		    (ਨਿਜੀ->sk_flags & SSH_SK_USER_PRESENCE_REQD) ? "": "no-",
		    (ਨਿਜੀ->sk_flags & SSH_SK_USER_VERIFICATION_REQD) ? "" : "no-");
	}

	/* Ask the new passphrase (twice). */
	ਜੇ (ਪਛਾਣ_ਤੱਤ_new_passphrase) {
		passphrase1 = xstrdup(ਪਛਾਣ_ਤੱਤ_new_passphrase);
		passphrase2 = ਨਿਰਾ;
	} ਨਹੀਂਤਾਂ {
		passphrase1 =
			read_passphrase("Enter new passphrase (empty for no "
			    "passphrase): ", RP_ALLOW_STDIN);
		passphrase2 = read_passphrase("Enter same passphrase again: ",
		    RP_ALLOW_STDIN);

		/* Verify that they are the same. */
		ਜੇ (strcmp(passphrase1, passphrase2) != 0) {
			explicit_bzero(passphrase1, ਲੜੀ_ਲੰਬਾਈ(passphrase1));
			explicit_bzero(passphrase2, ਲੜੀ_ਲੰਬਾਈ(passphrase2));
			ਮੁਕਤ(passphrase1);
			ਮੁਕਤ(passphrase2);
			ਲਿਖੋ("Pass phrases do not match.  Try again.\n");
			ਬਾਹਰ_ਨਿਕਲੋ(1);
		}
		/* Destroy the other copy. */
		freezero(passphrase2, ਲੜੀ_ਲੰਬਾਈ(passphrase2));
	}

	/* Save the file using the new passphrase. */
	ਜੇ ((r = sshkey_save_ਨਿੱਜੀ(ਨਿਜੀ, ਪਛਾਣ_ਤੱਤ_file, passphrase1,
	    comment, ਨਿੱਜੀ_ਕੁੰਜੀ_format, openssh_format_cipher, ਗੇੜ)) != 0) {
		error_r(r, "Saving key \"%s\" failed", ਪਛਾਣ_ਤੱਤ_file);
		freezero(passphrase1, ਲੜੀ_ਲੰਬਾਈ(passphrase1));
		sshkey_free(ਨਿਜੀ);
		ਮੁਕਤ(comment);
		ਬਾਹਰ_ਨਿਕਲੋ(1);
	}
	/* Destroy the passphrase and the copy of the key in memory. */
	freezero(passphrase1, ਲੜੀ_ਲੰਬਾਈ(passphrase1));
	sshkey_free(ਨਿਜੀ);		 /* Destroys contents */
	ਮੁਕਤ(comment);

	ਲਿਖੋ("Your identification has been saved with the new passphrase.\n");
	ਬਾਹਰ_ਨਿਕਲੋ(0);
}

/*
 * Print the SSHFP RR.
 */
ਸਥਿਰ ਪੂਰਨ
do_print_resource_ਰਿਕਾਰਡ(ਬਣਤਰ passwd *pw, ਅੱਖਰ *fname, ਅੱਖਰ *hname,
    ਪੂਰਨ print_generic, ਅੱਖਰ * ਅਚਲ *opts, ਮਾਪ_t nopts)
{
	ਬਣਤਰ sshkey *ਜਨਤਕ;
	ਅੱਖਰ *comment = ਨਿਰਾ;
	ਅਚਲ ਅੱਖਰ *p;
	ਬਣਤਰ stat st;
	ਪੂਰਨ r, hash = -1;
	ਮਾਪ_t i;

	ਲਈ (i = 0; i < nopts; i++) {
		ਜੇ ((p = strprefix(opts[i], "hashalg=", 1)) != ਨਿਰਾ) {
			ਜੇ ((hash = ssh_digest_alg_by_name(p)) == -1)
				fatal("Unsupported hash algorithm");
		} ਨਹੀਂਤਾਂ {
			error("Invalid option \"%s\"", opts[i]);
			ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
		}
	}
	ਜੇ (fname == ਨਿਰਾ)
		fatal_f("no filename");
	ਜੇ (stat(fname, &st) == -1) {
		ਜੇ (errno == ENOENT)
			ਵਾਪਸ 0;
		fatal("%s: %s", fname, strerror(errno));
	}
	ਜੇ ((r = sshkey_ਲੱਦੋ_ਜਨਤਕ(fname, &ਜਨਤਕ, &comment)) != 0)
		fatal_r(r, "Failed to read v2 public key from \"%s\"", fname);
	export_dns_rr(hname, ਜਨਤਕ, stdout, print_generic, hash);
	sshkey_free(ਜਨਤਕ);
	ਮੁਕਤ(comment);
	ਵਾਪਸ 1;
}

/*
 * Change the comment of a private key file.
 */
ਸਥਿਰ ਖਾਲੀ
do_change_comment(ਬਣਤਰ passwd *pw, ਅਚਲ ਅੱਖਰ *ਪਛਾਣ_ਤੱਤ_comment)
{
	ਅੱਖਰ new_comment[ਕੁੰਜੀ_COMMENT_MAX], *comment, *passphrase;
	ਬਣਤਰ sshkey *ਨਿਜੀ;
	ਬਣਤਰ sshkey *ਜਨਤਕ;
	ਬਣਤਰ stat st;
	ਪੂਰਨ r;

	ਜੇ (!have_ਪਛਾਣ_ਤੱਤ)
		ask_filename(pw, "Enter file in which the key is");
	ਜੇ (stat(ਪਛਾਣ_ਤੱਤ_file, &st) == -1)
		fatal("%s: %s", ਪਛਾਣ_ਤੱਤ_file, strerror(errno));
	ਜੇ ((r = sshkey_ਲੱਦੋ_ਨਿੱਜੀ(ਪਛਾਣ_ਤੱਤ_file, "",
	    &ਨਿਜੀ, &comment)) == 0)
		passphrase = xstrdup("");
	ਨਹੀਂਤਾਂ ਜੇ (r != SSH_ERR_ਕੁੰਜੀ_WRONG_PASSPHRASE)
		fatal_r(r, "Cannot load private key \"%s\"", ਪਛਾਣ_ਤੱਤ_file);
	ਨਹੀਂਤਾਂ {
		ਜੇ (ਪਛਾਣ_ਤੱਤ_passphrase)
			passphrase = xstrdup(ਪਛਾਣ_ਤੱਤ_passphrase);
		ਨਹੀਂਤਾਂ ਜੇ (ਪਛਾਣ_ਤੱਤ_new_passphrase)
			passphrase = xstrdup(ਪਛਾਣ_ਤੱਤ_new_passphrase);
		ਨਹੀਂਤਾਂ
			passphrase = read_passphrase("Enter passphrase: ",
			    RP_ALLOW_STDIN);
		/* Try to load using the passphrase. */
		ਜੇ ((r = sshkey_ਲੱਦੋ_ਨਿੱਜੀ(ਪਛਾਣ_ਤੱਤ_file, passphrase,
		    &ਨਿਜੀ, &comment)) != 0) {
			freezero(passphrase, ਲੜੀ_ਲੰਬਾਈ(passphrase));
			fatal_r(r, "Cannot load private key \"%s\"",
			    ਪਛਾਣ_ਤੱਤ_file);
		}
	}

	ਜੇ (ਨਿਜੀ->type != ਕੁੰਜੀ_ED25519 &&
	    ਨਿੱਜੀ_ਕੁੰਜੀ_format != SSHKEY_ਨਿੱਜੀ_OPENSSH) {
		error("Comments are only supported for keys stored in "
		    "the new format (-o).");
		explicit_bzero(passphrase, ਲੜੀ_ਲੰਬਾਈ(passphrase));
		sshkey_free(ਨਿਜੀ);
		ਬਾਹਰ_ਨਿਕਲੋ(1);
	}
	ਜੇ (comment)
		ਲਿਖੋ("Old comment: %s\n", comment);
	ਨਹੀਂਤਾਂ
		ਲਿਖੋ("No existing comment\n");

	ਜੇ (ਪਛਾਣ_ਤੱਤ_comment) {
		strlcpy(new_comment, ਪਛਾਣ_ਤੱਤ_comment, ਆਕਾਰ(new_comment));
	} ਨਹੀਂਤਾਂ {
		ਲਿਖੋ("New comment: ");
		fflush(stdout);
		ਜੇ (!fgets(new_comment, ਆਕਾਰ(new_comment), stdin)) {
			explicit_bzero(passphrase, ਲੜੀ_ਲੰਬਾਈ(passphrase));
			sshkey_free(ਨਿਜੀ);
			ਬਾਹਰ_ਨਿਕਲੋ(1);
		}
		new_comment[strcspn(new_comment, "\n")] = '\0';
	}
	ਜੇ (comment != ਨਿਰਾ && strcmp(comment, new_comment) == 0) {
		ਲਿਖੋ("No change to comment\n");
		ਮੁਕਤ(passphrase);
		sshkey_free(ਨਿਜੀ);
		ਮੁਕਤ(comment);
		ਬਾਹਰ_ਨਿਕਲੋ(0);
	}

	/* Save the file using the new passphrase. */
	ਜੇ ((r = sshkey_save_ਨਿੱਜੀ(ਨਿਜੀ, ਪਛਾਣ_ਤੱਤ_file, passphrase,
	    new_comment, ਨਿੱਜੀ_ਕੁੰਜੀ_format, openssh_format_cipher,
	    ਗੇੜ)) != 0) {
		error_r(r, "Saving key \"%s\" failed", ਪਛਾਣ_ਤੱਤ_file);
		freezero(passphrase, ਲੜੀ_ਲੰਬਾਈ(passphrase));
		sshkey_free(ਨਿਜੀ);
		ਮੁਕਤ(comment);
		ਬਾਹਰ_ਨਿਕਲੋ(1);
	}
	freezero(passphrase, ਲੜੀ_ਲੰਬਾਈ(passphrase));
	ਜੇ ((r = sshkey_from_ਨਿੱਜੀ(ਨਿਜੀ, &ਜਨਤਕ)) != 0)
		fatal_fr(r, "sshkey_from_private");
	sshkey_free(ਨਿਜੀ);

	strlcat(ਪਛਾਣ_ਤੱਤ_file, ".pub", ਆਕਾਰ(ਪਛਾਣ_ਤੱਤ_file));
	ਜੇ ((r = sshkey_save_ਜਨਤਕ(ਜਨਤਕ, ਪਛਾਣ_ਤੱਤ_file, new_comment)) != 0)
		fatal_r(r, "Unable to save public key to %s", ਪਛਾਣ_ਤੱਤ_file);
	sshkey_free(ਜਨਤਕ);
	ਮੁਕਤ(comment);

	ਜੇ (ਲੜੀ_ਲੰਬਾਈ(new_comment) > 0)
		ਲਿਖੋ("Comment '%s' applied\n", new_comment);
	ਨਹੀਂਤਾਂ
		ਲਿਖੋ("Comment removed\n");

	ਬਾਹਰ_ਨਿਕਲੋ(0);
}

ਸਥਿਰ ਖਾਲੀ
cert_ext_ਜੋੜੋ(ਅਚਲ ਅੱਖਰ *ਕੁੰਜੀ, ਅਚਲ ਅੱਖਰ *ਮੁੱਲ, ਪੂਰਨ iscrit)
{
	cert_ext = xreallocarray(cert_ext, ncert_ext + 1, ਆਕਾਰ(*cert_ext));
	cert_ext[ncert_ext].ਕੁੰਜੀ = xstrdup(ਕੁੰਜੀ);
	cert_ext[ncert_ext].val = ਮੁੱਲ == ਨਿਰਾ ? ਨਿਰਾ : xstrdup(ਮੁੱਲ);
	cert_ext[ncert_ext].crit = iscrit;
	ncert_ext++;
}

/* qsort(3) comparison function for certificate extensions */
ਸਥਿਰ ਪੂਰਨ
cert_ext_cmp(ਅਚਲ ਖਾਲੀ *_a, ਅਚਲ ਖਾਲੀ *_b)
{
	ਅਚਲ ਬਣਤਰ cert_ext *a = (ਅਚਲ ਬਣਤਰ cert_ext *)_a;
	ਅਚਲ ਬਣਤਰ cert_ext *b = (ਅਚਲ ਬਣਤਰ cert_ext *)_b;
	ਪੂਰਨ r;

	ਜੇ (a->crit != b->crit)
		ਵਾਪਸ (a->crit < b->crit) ? -1 : 1;
	ਜੇ ((r = strcmp(a->ਕੁੰਜੀ, b->ਕੁੰਜੀ)) != 0)
		ਵਾਪਸ r;
	ਜੇ ((a->val == ਨਿਰਾ) != (b->val == ਨਿਰਾ))
		ਵਾਪਸ (a->val == ਨਿਰਾ) ? -1 : 1;
	ਜੇ (a->val != ਨਿਰਾ && (r = strcmp(a->val, b->val)) != 0)
		ਵਾਪਸ r;
	ਵਾਪਸ 0;
}

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ OPTIONS_CRITICAL	1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ OPTIONS_EXTENSIONS	2
ਸਥਿਰ ਖਾਲੀ
prepare_options_buf(ਬਣਤਰ sshbuf *c, ਪੂਰਨ which)
{
	ਬਣਤਰ sshbuf *b;
	ਮਾਪ_t i;
	ਪੂਰਨ r;
	ਅਚਲ ਬਣਤਰ cert_ext *ext;

	ਜੇ ((b = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	sshbuf_reset(c);
	ਲਈ (i = 0; i < ncert_ext; i++) {
		ext = &cert_ext[i];
		ਜੇ ((ext->crit && (which & OPTIONS_EXTENSIONS)) ||
		    (!ext->crit && (which & OPTIONS_CRITICAL)))
			ਜਾਰੀ;
		ਜੇ (ext->val == ਨਿਰਾ) {
			/* flag option */
			debug3_f("%s", ext->ਕੁੰਜੀ);
			ਜੇ ((r = sshbuf_put_cstring(c, ext->ਕੁੰਜੀ)) != 0 ||
			    (r = sshbuf_put_string(c, ਨਿਰਾ, 0)) != 0)
				fatal_fr(r, "prepare flag");
		} ਨਹੀਂਤਾਂ {
			/* key/value option */
			debug3_f("%s=%s", ext->ਕੁੰਜੀ, ext->val);
			sshbuf_reset(b);
			ਜੇ ((r = sshbuf_put_cstring(c, ext->ਕੁੰਜੀ)) != 0 ||
			    (r = sshbuf_put_cstring(b, ext->val)) != 0 ||
			    (r = sshbuf_put_stringb(c, b)) != 0)
				fatal_fr(r, "prepare k/v");
		}
	}
	sshbuf_free(b);
}

ਸਥਿਰ ਖਾਲੀ
finalise_cert_exts(ਖਾਲੀ)
{
	/* critical options */
	ਜੇ (certflags_command != ਨਿਰਾ)
		cert_ext_ਜੋੜੋ("force-command", certflags_command, 1);
	ਜੇ (certflags_src_addr != ਨਿਰਾ)
		cert_ext_ਜੋੜੋ("source-address", certflags_src_addr, 1);
	ਜੇ ((certflags_flags & CERTOPT_REQUIRE_VERIFY) != 0)
		cert_ext_ਜੋੜੋ("verify-required", ਨਿਰਾ, 1);
	/* extensions */
	ਜੇ ((certflags_flags & CERTOPT_X_FWD) != 0)
		cert_ext_ਜੋੜੋ("permit-X11-forwarding", ਨਿਰਾ, 0);
	ਜੇ ((certflags_flags & CERTOPT_AGENT_FWD) != 0)
		cert_ext_ਜੋੜੋ("permit-agent-forwarding", ਨਿਰਾ, 0);
	ਜੇ ((certflags_flags & CERTOPT_ਪੋਰਟ_FWD) != 0)
		cert_ext_ਜੋੜੋ("permit-port-forwarding", ਨਿਰਾ, 0);
	ਜੇ ((certflags_flags & CERTOPT_PTY) != 0)
		cert_ext_ਜੋੜੋ("permit-pty", ਨਿਰਾ, 0);
	ਜੇ ((certflags_flags & CERTOPT_USER_RC) != 0)
		cert_ext_ਜੋੜੋ("permit-user-rc", ਨਿਰਾ, 0);
	ਜੇ ((certflags_flags & CERTOPT_NO_REQUIRE_USER_PRESENCE) != 0)
		cert_ext_ਜੋੜੋ("no-touch-required", ਨਿਰਾ, 0);
	/* order lexically by key */
	ਜੇ (ncert_ext > 0)
		qsort(cert_ext, ncert_ext, ਆਕਾਰ(*cert_ext), cert_ext_cmp);
}

ਸਥਿਰ ਬਣਤਰ sshkey *
ਲੱਦੋ_pkcs11_ਕੁੰਜੀ(ਅੱਖਰ *ਰਸਤਾ)
{
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ ENABLE_PKCS11
	ਬਣਤਰ sshkey **ਕੁੰਜੀਆਂ = ਨਿਰਾ, *ਜਨਤਕ, *ਨਿਜੀ = ਨਿਰਾ;
	ਪੂਰਨ r, i, nkeys;

	ਜੇ ((r = sshkey_ਲੱਦੋ_ਜਨਤਕ(ਰਸਤਾ, &ਜਨਤਕ, ਨਿਰਾ)) != 0)
		fatal_r(r, "Couldn't load CA public key \"%s\"", ਰਸਤਾ);

	nkeys = pkcs11_ਜੋੜੋ_provider(pkcs11provider, ਪਛਾਣ_ਤੱਤ_passphrase,
	    &ਕੁੰਜੀਆਂ, ਨਿਰਾ);
	debug3_f("%d keys", nkeys);
	ਜੇ (nkeys <= 0)
		fatal("cannot read public key from pkcs11");
	ਲਈ (i = 0; i < nkeys; i++) {
		ਜੇ (sshkey_equal_ਜਨਤਕ(ਜਨਤਕ, ਕੁੰਜੀਆਂ[i])) {
			ਨਿਜੀ = ਕੁੰਜੀਆਂ[i];
			ਜਾਰੀ;
		}
		sshkey_free(ਕੁੰਜੀਆਂ[i]);
	}
	ਮੁਕਤ(ਕੁੰਜੀਆਂ);
	sshkey_free(ਜਨਤਕ);
	ਵਾਪਸ ਨਿਜੀ;
#ਨਹੀਂਤਾਂ
	fatal("no pkcs11 support");
#ਜੇ_ਅੰਤ /* ENABLE_PKCS11 */
}

/* Signer for sshkey_certify_custom that uses the agent */
ਸਥਿਰ ਪੂਰਨ
agent_signer(ਬਣਤਰ sshkey *ਕੁੰਜੀ, u_char **sigp, ਮਾਪ_t *lenp,
    ਅਚਲ u_char *ਅੰਕੜੇ, ਮਾਪ_t datalen,
    ਅਚਲ ਅੱਖਰ *alg, ਅਚਲ ਅੱਖਰ *provider, ਅਚਲ ਅੱਖਰ *pin,
    u_int compat, ਖਾਲੀ *ctx)
{
	ਪੂਰਨ *agent_fdp = (ਪੂਰਨ *)ctx;

	ਵਾਪਸ ssh_agent_sign(*agent_fdp, ਕੁੰਜੀ, sigp, lenp,
	    ਅੰਕੜੇ, datalen, alg, compat);
}

ਸਥਿਰ ਖਾਲੀ
do_ca_sign(ਬਣਤਰ passwd *pw, ਅਚਲ ਅੱਖਰ *ca_ਕੁੰਜੀ_ਰਸਤਾ, ਪੂਰਨ prefer_agent,
    ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ cert_serial, ਪੂਰਨ cert_serial_autoinc,
    ਪੂਰਨ argc, ਅੱਖਰ **argv)
{
	ਪੂਰਨ r, i, ਕੁੰਜੀ_ਵਿੱਚ_agent = 0, agent_fd = -1;
	u_int n;
	ਬਣਤਰ sshkey *ca, *ਜਨਤਕ;
	ਅੱਖਰ valid[64], *otmp, *tmp, *cp, *ਬਾਹਰਲਾ, *comment;
	ਅੱਖਰ *ca_fp = ਨਿਰਾ, **plist = ਨਿਰਾ, *pin = ਨਿਰਾ;
	ਬਣਤਰ ssh_identitylist *agent_ids;
	ਮਾਪ_t j;
	ਬਣਤਰ notifier_ctx *notifier = ਨਿਰਾ;

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ ENABLE_PKCS11
	pkcs11_init(1);
#ਜੇ_ਅੰਤ
	tmp = tilde_expand_filename(ca_ਕੁੰਜੀ_ਰਸਤਾ, pw->pw_uid);
	ਜੇ (pkcs11provider != ਨਿਰਾ) {
		/* If a PKCS#11 token was specified then try to use it */
		ਜੇ ((ca = ਲੱਦੋ_pkcs11_ਕੁੰਜੀ(tmp)) == ਨਿਰਾ)
			fatal("No PKCS#11 key matching %s found", ca_ਕੁੰਜੀ_ਰਸਤਾ);
	} ਨਹੀਂਤਾਂ ਜੇ (prefer_agent) {
		/*
		 * Agent signature requested. Try to use agent after making
		 * sure the public key specified is actually present in the
		 * agent.
		 */
		ਜੇ ((r = sshkey_ਲੱਦੋ_ਜਨਤਕ(tmp, &ca, ਨਿਰਾ)) != 0)
			fatal_r(r, "Cannot load CA public key %s", tmp);
		ਜੇ ((r = ssh_get_authentication_socket(&agent_fd)) != 0)
			fatal_r(r, "Cannot use public key for CA signature");
		ਜੇ ((r = ssh_fetch_identitylist(agent_fd, &agent_ids)) != 0)
			fatal_r(r, "Retrieve agent key list");
		ਲਈ (j = 0; j < agent_ids->nkeys; j++) {
			ਜੇ (sshkey_equal(ca, agent_ids->ਕੁੰਜੀਆਂ[j])) {
				ਕੁੰਜੀ_ਵਿੱਚ_agent = 1;
				/* Replace the CA key with the agent one */
				sshkey_free(ca);
				ca = agent_ids->ਕੁੰਜੀਆਂ[j];
				agent_ids->ਕੁੰਜੀਆਂ[j] = ਨਿਰਾ;
				ਰੋਕੋ;
			}
		}
		ਜੇ (!ਕੁੰਜੀ_ਵਿੱਚ_agent)
			fatal("CA key %s not found in agent", tmp);
		ssh_free_identitylist(agent_ids);
	} ਨਹੀਂਤਾਂ {
		/* CA key is assumed to be a private key on the filesystem */
		ca = ਲੱਦੋ_ਪਛਾਣ_ਤੱਤ(tmp, ਨਿਰਾ);
		ਜੇ (sshkey_is_sk(ca) &&
		    (ca->sk_flags & SSH_SK_USER_VERIFICATION_REQD)) {
			ਜੇ ((pin = read_passphrase("Enter PIN for CA key: ",
			    RP_ALLOW_STDIN)) == ਨਿਰਾ)
				fatal_f("couldn't read PIN");
		}
	}
	ਮੁਕਤ(tmp);

	ਜੇ (ਕੁੰਜੀ_type_name != ਨਿਰਾ) {
		ਜੇ (sshkey_type_from_shortname(ਕੁੰਜੀ_type_name) != ca->type) {
			fatal("CA key type %s doesn't match specified %s",
			    sshkey_ssh_name(ca), ਕੁੰਜੀ_type_name);
		}
	} ਨਹੀਂਤਾਂ ਜੇ (ca->type == ਕੁੰਜੀ_RSA) {
		/* Default to a good signature algorithm */
		ਕੁੰਜੀ_type_name = "rsa-sha2-512";
	}
	ca_fp = sshkey_fingerprint(ca, fingerprint_hash, SSH_FP_DEFAULT);

	finalise_cert_exts();
	ਲਈ (i = 0; i < argc; i++) {
		/* Split list of principals */
		n = 0;
		ਜੇ (cert_principals != ਨਿਰਾ) {
			otmp = tmp = xstrdup(cert_principals);
			plist = ਨਿਰਾ;
			ਲਈ (; (cp = strsep(&tmp, ",")) != ਨਿਰਾ; n++) {
				plist = xreallocarray(plist, n + 1, ਆਕਾਰ(*plist));
				ਜੇ (*(plist[n] = xstrdup(cp)) == '\0')
					fatal("Empty principal name");
			}
			ਮੁਕਤ(otmp);
		}
		ਜੇ (n > SSHKEY_CERT_MAX_PRINCIPALS)
			fatal("Too many certificate principals specified");

		tmp = tilde_expand_filename(argv[i], pw->pw_uid);
		ਜੇ ((r = sshkey_ਲੱਦੋ_ਜਨਤਕ(tmp, &ਜਨਤਕ, &comment)) != 0)
			fatal_r(r, "load pubkey \"%s\"", tmp);
		ਜੇ (sshkey_is_cert(ਜਨਤਕ))
			fatal_f("key \"%s\" type %s cannot be certified",
			    tmp, sshkey_type(ਜਨਤਕ));

		/* Prepare certificate to sign */
		ਜੇ ((r = sshkey_ਮੰਜ਼ਿਲ_certified(ਜਨਤਕ)) != 0)
			fatal_r(r, "Could not upgrade key %s to certificate", tmp);
		ਜਨਤਕ->cert->type = cert_ਕੁੰਜੀ_type;
		ਜਨਤਕ->cert->serial = (uint64_t)cert_serial;
		ਜਨਤਕ->cert->ਕੁੰਜੀ_id = xstrdup(cert_ਕੁੰਜੀ_id);
		ਜਨਤਕ->cert->nprincipals = n;
		ਜਨਤਕ->cert->principals = plist;
		ਜਨਤਕ->cert->valid_after = cert_valid_from;
		ਜਨਤਕ->cert->valid_before = cert_valid_ਮੰਜ਼ਿਲ;
		prepare_options_buf(ਜਨਤਕ->cert->critical, OPTIONS_CRITICAL);
		prepare_options_buf(ਜਨਤਕ->cert->extensions,
		    OPTIONS_EXTENSIONS);
		ਜੇ ((r = sshkey_from_ਨਿੱਜੀ(ca,
		    &ਜਨਤਕ->cert->signature_ਕੁੰਜੀ)) != 0)
			fatal_r(r, "sshkey_from_private (ca key)");

		ਜੇ (ਕੁੰਜੀ_ਵਿੱਚ_agent) {
			ਜੇ ((r = sshkey_certify_custom(ਜਨਤਕ, ca,
			    ਕੁੰਜੀ_type_name, sk_provider, ਨਿਰਾ, agent_signer,
			    &agent_fd)) != 0)
				fatal_r(r, "Couldn't certify %s via agent", tmp);
		} ਨਹੀਂਤਾਂ {
			ਜੇ (sshkey_is_sk(ca) &&
			    (ca->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
				notifier = notify_ਸ਼ੁਰੂ(0,
				    "Confirm user presence for key %s %s",
				    sshkey_type(ca), ca_fp);
			}
			r = sshkey_certify(ਜਨਤਕ, ca, ਕੁੰਜੀ_type_name,
			    sk_provider, pin);
			notify_complete(notifier, "User presence confirmed");
			ਜੇ (r != 0)
				fatal_r(r, "Couldn't certify key %s", tmp);
		}

		ਜੇ ((cp = strrchr(tmp, '.')) != ਨਿਰਾ && strcmp(cp, ".pub") == 0)
			*cp = '\0';
		xasprintf(&ਬਾਹਰਲਾ, "%s-cert.pub", tmp);
		ਮੁਕਤ(tmp);

		ਜੇ ((r = sshkey_save_ਜਨਤਕ(ਜਨਤਕ, ਬਾਹਰਲਾ, comment)) != 0) {
			fatal_r(r, "Unable to save public key to %s",
			    ਪਛਾਣ_ਤੱਤ_file);
		}

		ਜੇ (!quiet) {
			sshkey_format_cert_validity(ਜਨਤਕ->cert,
			    valid, ਆਕਾਰ(valid));
			logit("Signed %s key %s: id \"%s\" serial %llu%s%s "
			    "valid %s", sshkey_cert_type(ਜਨਤਕ),
			    ਬਾਹਰਲਾ, ਜਨਤਕ->cert->ਕੁੰਜੀ_id,
			    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)ਜਨਤਕ->cert->serial,
			    cert_principals != ਨਿਰਾ ? " for " : "",
			    cert_principals != ਨਿਰਾ ? cert_principals : "",
			    valid);
		}

		sshkey_free(ਜਨਤਕ);
		ਮੁਕਤ(ਬਾਹਰਲਾ);
		ਮੁਕਤ(comment);
		ਜੇ (cert_serial_autoinc)
			cert_serial++;
	}
	ਜੇ (pin != ਨਿਰਾ)
		freezero(pin, ਲੜੀ_ਲੰਬਾਈ(pin));
	sshkey_free(ca);
	ਮੁਕਤ(ca_fp);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ ENABLE_PKCS11
	pkcs11_terminate();
#ਜੇ_ਅੰਤ
}

ਸਥਿਰ uint64_t
parse_relative_ਸਮਾਂ(ਅਚਲ ਅੱਖਰ *s, time_t now)
{
	int64_t mul, secs;

	mul = *s == '-' ? -1 : 1;

	ਜੇ ((secs = convtime(s + 1)) == -1)
		fatal("Invalid relative certificate time %s", s);
	ਜੇ (mul == -1 && secs > now)
		fatal("Certificate time %s cannot be represented", s);
	ਵਾਪਸ now + (uint64_t)(secs * mul);
}

ਸਥਿਰ ਖਾਲੀ
parse_hex_u64(ਅਚਲ ਅੱਖਰ *s, uint64_t *ਉੱਪਰ)
{
	ਅੱਖਰ *ep;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ ull;

	errno = 0;
	ull = strtoull(s, &ep, 16);
	ਜੇ (*s == '\0' || *ep != '\0')
		fatal("Invalid certificate time: not a number");
	ਜੇ (errno == ERANGE && ull == ULONG_MAX)
		fatal_fr(SSH_ERR_SYSTEM_ERROR, "Invalid certificate time");
	*ਉੱਪਰ = (uint64_t)ull;
}

ਸਥਿਰ ਖਾਲੀ
parse_cert_times(ਅੱਖਰ *timespec)
{
	ਅੱਖਰ *from, *ਮੰਜ਼ਿਲ;
	time_t now = time(ਨਿਰਾ);
	int64_t secs;

	/* +timespec relative to now */
	ਜੇ (*timespec == '+' && strchr(timespec, ':') == ਨਿਰਾ) {
		ਜੇ ((secs = convtime(timespec + 1)) == -1)
			fatal("Invalid relative certificate life %s", timespec);
		cert_valid_ਮੰਜ਼ਿਲ = now + secs;
		/*
		 * Backdate certificate one minute to avoid problems on hosts
		 * with poorly-synchronised clocks.
		 */
		cert_valid_from = ((now - 59)/ 60) * 60;
		ਵਾਪਸ;
	}

	/*
	 * from:to, where
	 * from := [+-]timespec | YYYYMMDD | YYYYMMDDHHMMSS | 0x... | "always"
	 *   to := [+-]timespec | YYYYMMDD | YYYYMMDDHHMMSS | 0x... | "forever"
	 */
	from = xstrdup(timespec);
	ਮੰਜ਼ਿਲ = strchr(from, ':');
	ਜੇ (ਮੰਜ਼ਿਲ == ਨਿਰਾ || from == ਮੰਜ਼ਿਲ || *(ਮੰਜ਼ਿਲ + 1) == '\0')
		fatal("Invalid certificate life specification %s", timespec);
	*ਮੰਜ਼ਿਲ++ = '\0';

	ਜੇ (*from == '-' || *from == '+')
		cert_valid_from = parse_relative_ਸਮਾਂ(from, now);
	ਨਹੀਂਤਾਂ ਜੇ (strcmp(from, "always") == 0)
		cert_valid_from = 0;
	ਨਹੀਂਤਾਂ ਜੇ (ਲੜੀ_ਤੁਲਨਾ(from, "0x", 2) == 0)
		parse_hex_u64(from, &cert_valid_from);
	ਨਹੀਂਤਾਂ ਜੇ (parse_absolute_ਸਮਾਂ(from, &cert_valid_from) != 0)
		fatal("Invalid from time \"%s\"", from);

	ਜੇ (*ਮੰਜ਼ਿਲ == '-' || *ਮੰਜ਼ਿਲ == '+')
		cert_valid_ਮੰਜ਼ਿਲ = parse_relative_ਸਮਾਂ(ਮੰਜ਼ਿਲ, now);
	ਨਹੀਂਤਾਂ ਜੇ (strcmp(ਮੰਜ਼ਿਲ, "forever") == 0)
		cert_valid_ਮੰਜ਼ਿਲ = ~(uint64_t)0;
	ਨਹੀਂਤਾਂ ਜੇ (ਲੜੀ_ਤੁਲਨਾ(ਮੰਜ਼ਿਲ, "0x", 2) == 0)
		parse_hex_u64(ਮੰਜ਼ਿਲ, &cert_valid_ਮੰਜ਼ਿਲ);
	ਨਹੀਂਤਾਂ ਜੇ (parse_absolute_ਸਮਾਂ(ਮੰਜ਼ਿਲ, &cert_valid_ਮੰਜ਼ਿਲ) != 0)
		fatal("Invalid to time \"%s\"", ਮੰਜ਼ਿਲ);

	ਜੇ (cert_valid_ਮੰਜ਼ਿਲ <= cert_valid_from)
		fatal("Empty certificate validity interval");
	ਮੁਕਤ(from);
}

ਸਥਿਰ ਖਾਲੀ
ਜੋੜੋ_cert_option(ਅੱਖਰ *opt)
{
	ਅੱਖਰ *val, *cp;
	ਅਚਲ ਅੱਖਰ *p;
	ਪੂਰਨ iscrit = 0;

	ਜੇ (strcasecmp(opt, "clear") == 0)
		certflags_flags = 0;
	ਨਹੀਂਤਾਂ ਜੇ (strcasecmp(opt, "no-x11-forwarding") == 0)
		certflags_flags &= ~CERTOPT_X_FWD;
	ਨਹੀਂਤਾਂ ਜੇ (strcasecmp(opt, "permit-x11-forwarding") == 0)
		certflags_flags |= CERTOPT_X_FWD;
	ਨਹੀਂਤਾਂ ਜੇ (strcasecmp(opt, "no-agent-forwarding") == 0)
		certflags_flags &= ~CERTOPT_AGENT_FWD;
	ਨਹੀਂਤਾਂ ਜੇ (strcasecmp(opt, "permit-agent-forwarding") == 0)
		certflags_flags |= CERTOPT_AGENT_FWD;
	ਨਹੀਂਤਾਂ ਜੇ (strcasecmp(opt, "no-port-forwarding") == 0)
		certflags_flags &= ~CERTOPT_ਪੋਰਟ_FWD;
	ਨਹੀਂਤਾਂ ਜੇ (strcasecmp(opt, "permit-port-forwarding") == 0)
		certflags_flags |= CERTOPT_ਪੋਰਟ_FWD;
	ਨਹੀਂਤਾਂ ਜੇ (strcasecmp(opt, "no-pty") == 0)
		certflags_flags &= ~CERTOPT_PTY;
	ਨਹੀਂਤਾਂ ਜੇ (strcasecmp(opt, "permit-pty") == 0)
		certflags_flags |= CERTOPT_PTY;
	ਨਹੀਂਤਾਂ ਜੇ (strcasecmp(opt, "no-user-rc") == 0)
		certflags_flags &= ~CERTOPT_USER_RC;
	ਨਹੀਂਤਾਂ ਜੇ (strcasecmp(opt, "permit-user-rc") == 0)
		certflags_flags |= CERTOPT_USER_RC;
	ਨਹੀਂਤਾਂ ਜੇ (strcasecmp(opt, "touch-required") == 0)
		certflags_flags &= ~CERTOPT_NO_REQUIRE_USER_PRESENCE;
	ਨਹੀਂਤਾਂ ਜੇ (strcasecmp(opt, "no-touch-required") == 0)
		certflags_flags |= CERTOPT_NO_REQUIRE_USER_PRESENCE;
	ਨਹੀਂਤਾਂ ਜੇ (strcasecmp(opt, "no-verify-required") == 0)
		certflags_flags &= ~CERTOPT_REQUIRE_VERIFY;
	ਨਹੀਂਤਾਂ ਜੇ (strcasecmp(opt, "verify-required") == 0)
		certflags_flags |= CERTOPT_REQUIRE_VERIFY;
	ਨਹੀਂਤਾਂ ਜੇ ((p = strprefix(opt, "force-command=", 1)) != ਨਿਰਾ) {
		ਜੇ (*p == '\0')
			fatal("Empty force-command option");
		ਜੇ (certflags_command != ਨਿਰਾ)
			fatal("force-command already specified");
		certflags_command = xstrdup(p);
	} ਨਹੀਂਤਾਂ ਜੇ ((p = strprefix(opt, "source-address=", 1)) != ਨਿਰਾ) {
		ਜੇ (*p == '\0')
			fatal("Empty source-address option");
		ਜੇ (certflags_src_addr != ਨਿਰਾ)
			fatal("source-address already specified");
		ਜੇ (addr_ਮੇਲ_cidr_list(ਨਿਰਾ, p) != 0)
			fatal("Invalid source-address list");
		certflags_src_addr = xstrdup(p);
	} ਨਹੀਂਤਾਂ ਜੇ (strprefix(opt, "extension:", 1) != ਨਿਰਾ ||
		    (iscrit = (strprefix(opt, "critical:", 1) != ਨਿਰਾ))) {
		val = xstrdup(strchr(opt, ':') + 1);
		ਜੇ ((cp = strchr(val, '=')) != ਨਿਰਾ)
			*cp++ = '\0';
		cert_ext_ਜੋੜੋ(val, cp, iscrit);
		ਮੁਕਤ(val);
	} ਨਹੀਂਤਾਂ
		fatal("Unsupported certificate option \"%s\"", opt);
}

ਸਥਿਰ ਖਾਲੀ
show_options(ਬਣਤਰ sshbuf *optbuf, ਪੂਰਨ ਵਿੱਚ_critical)
{
	ਅੱਖਰ *name, *arg, *hex;
	ਬਣਤਰ sshbuf *options, *option = ਨਿਰਾ;
	ਪੂਰਨ r;

	ਜੇ ((options = sshbuf_fromb(optbuf)) == ਨਿਰਾ)
		fatal_f("sshbuf_fromb failed");
	ਜਦੋਂ (sshbuf_len(options) != 0) {
		sshbuf_free(option);
		option = ਨਿਰਾ;
		ਜੇ ((r = sshbuf_get_cstring(options, &name, ਨਿਰਾ)) != 0 ||
		    (r = sshbuf_froms(options, &option)) != 0)
			fatal_fr(r, "parse option");
		ਲਿਖੋ("                %s", name);
		ਜੇ (!ਵਿੱਚ_critical &&
		    (strcmp(name, "permit-X11-forwarding") == 0 ||
		    strcmp(name, "permit-agent-forwarding") == 0 ||
		    strcmp(name, "permit-port-forwarding") == 0 ||
		    strcmp(name, "permit-pty") == 0 ||
		    strcmp(name, "permit-user-rc") == 0 ||
		    strcmp(name, "no-touch-required") == 0)) {
			ਲਿਖੋ("\n");
		} ਨਹੀਂਤਾਂ ਜੇ (ਵਿੱਚ_critical &&
		    (strcmp(name, "force-command") == 0 ||
		    strcmp(name, "source-address") == 0)) {
			ਜੇ ((r = sshbuf_get_cstring(option, &arg, ਨਿਰਾ)) != 0)
				fatal_fr(r, "parse critical");
			ਲਿਖੋ(" %s\n", arg);
			ਮੁਕਤ(arg);
		} ਨਹੀਂਤਾਂ ਜੇ (ਵਿੱਚ_critical &&
		    strcmp(name, "verify-required") == 0) {
			ਲਿਖੋ("\n");
		} ਨਹੀਂਤਾਂ ਜੇ (sshbuf_len(option) > 0) {
			hex = sshbuf_dtob16(option);
			ਲਿਖੋ(" UNKNOWN OPTION: %s (len %zu)\n",
			    hex, sshbuf_len(option));
			sshbuf_reset(option);
			ਮੁਕਤ(hex);
		} ਨਹੀਂਤਾਂ
			ਲਿਖੋ(" UNKNOWN FLAG OPTION\n");
		ਮੁਕਤ(name);
		ਜੇ (sshbuf_len(option) != 0)
			fatal("Option corrupt: extra data at end");
	}
	sshbuf_free(option);
	sshbuf_free(options);
}

ਸਥਿਰ ਖਾਲੀ
print_cert(ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	ਅੱਖਰ valid[64], *ਕੁੰਜੀ_fp, *ca_fp;
	u_int i;

	ਕੁੰਜੀ_fp = sshkey_fingerprint(ਕੁੰਜੀ, fingerprint_hash, SSH_FP_DEFAULT);
	ca_fp = sshkey_fingerprint(ਕੁੰਜੀ->cert->signature_ਕੁੰਜੀ,
	    fingerprint_hash, SSH_FP_DEFAULT);
	ਜੇ (ਕੁੰਜੀ_fp == ਨਿਰਾ || ca_fp == ਨਿਰਾ)
		fatal_f("sshkey_fingerprint fail");
	sshkey_format_cert_validity(ਕੁੰਜੀ->cert, valid, ਆਕਾਰ(valid));

	ਲਿਖੋ("        Type: %s %s certificate\n", sshkey_ssh_name(ਕੁੰਜੀ),
	    sshkey_cert_type(ਕੁੰਜੀ));
	ਲਿਖੋ("        Public key: %s %s\n", sshkey_type(ਕੁੰਜੀ), ਕੁੰਜੀ_fp);
	ਲਿਖੋ("        Signing CA: %s %s (using %s)\n",
	    sshkey_type(ਕੁੰਜੀ->cert->signature_ਕੁੰਜੀ), ca_fp,
	    ਕੁੰਜੀ->cert->signature_type);
	ਲਿਖੋ("        Key ID: \"%s\"\n", ਕੁੰਜੀ->cert->ਕੁੰਜੀ_id);
	ਲਿਖੋ("        Serial: %llu\n", (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)ਕੁੰਜੀ->cert->serial);
	ਲਿਖੋ("        Valid: %s\n", valid);
	ਲਿਖੋ("        Principals: ");
	ਜੇ (ਕੁੰਜੀ->cert->nprincipals == 0)
		ਲਿਖੋ("(none)\n");
	ਨਹੀਂਤਾਂ {
		ਲਈ (i = 0; i < ਕੁੰਜੀ->cert->nprincipals; i++)
			ਲਿਖੋ("\n                %s",
			    ਕੁੰਜੀ->cert->principals[i]);
		ਲਿਖੋ("\n");
	}
	ਲਿਖੋ("        Critical Options: ");
	ਜੇ (sshbuf_len(ਕੁੰਜੀ->cert->critical) == 0)
		ਲਿਖੋ("(none)\n");
	ਨਹੀਂਤਾਂ {
		ਲਿਖੋ("\n");
		show_options(ਕੁੰਜੀ->cert->critical, 1);
	}
	ਲਿਖੋ("        Extensions: ");
	ਜੇ (sshbuf_len(ਕੁੰਜੀ->cert->extensions) == 0)
		ਲਿਖੋ("(none)\n");
	ਨਹੀਂਤਾਂ {
		ਲਿਖੋ("\n");
		show_options(ਕੁੰਜੀ->cert->extensions, 0);
	}
	ਮੁਕਤ(ਕੁੰਜੀ_fp);
	ਮੁਕਤ(ca_fp);
}

ਸਥਿਰ ਖਾਲੀ
do_show_cert(ਬਣਤਰ passwd *pw)
{
	ਬਣਤਰ sshkey *ਕੁੰਜੀ = ਨਿਰਾ;
	ਬਣਤਰ stat st;
	ਪੂਰਨ r, is_stdin = 0, ok = 0;
	FILE *f;
	ਅੱਖਰ *cp, *ਸਤਰ = ਨਿਰਾ;
	ਅਚਲ ਅੱਖਰ *ਰਸਤਾ;
	ਮਾਪ_t linesize = 0;
	u_long lnum = 0;

	ਜੇ (!have_ਪਛਾਣ_ਤੱਤ)
		ask_filename(pw, "Enter file in which the key is");
	ਜੇ (strcmp(ਪਛਾਣ_ਤੱਤ_file, "-") != 0 && stat(ਪਛਾਣ_ਤੱਤ_file, &st) == -1)
		fatal("%s: %s: %s", __progname, ਪਛਾਣ_ਤੱਤ_file, strerror(errno));

	ਰਸਤਾ = ਪਛਾਣ_ਤੱਤ_file;
	ਜੇ (strcmp(ਰਸਤਾ, "-") == 0) {
		f = stdin;
		ਰਸਤਾ = "(stdin)";
		is_stdin = 1;
	} ਨਹੀਂਤਾਂ ਜੇ ((f = fopen(ਪਛਾਣ_ਤੱਤ_file, "r")) == ਨਿਰਾ)
		fatal("fopen %s: %s", ਪਛਾਣ_ਤੱਤ_file, strerror(errno));

	ਜਦੋਂ (getline(&ਸਤਰ, &linesize, f) != -1) {
		lnum++;
		sshkey_free(ਕੁੰਜੀ);
		ਕੁੰਜੀ = ਨਿਰਾ;
		/* Trim leading space and comments */
		cp = ਸਤਰ + strspn(ਸਤਰ, " \t");
		ਜੇ (*cp == '#' || *cp == '\0')
			ਜਾਰੀ;
		ਜੇ ((ਕੁੰਜੀ = sshkey_new(ਕੁੰਜੀ_UNSPEC)) == ਨਿਰਾ)
			fatal("sshkey_new");
		ਜੇ ((r = sshkey_read(ਕੁੰਜੀ, &cp)) != 0) {
			error_r(r, "%s:%lu: invalid key", ਰਸਤਾ, lnum);
			ਜਾਰੀ;
		}
		ਜੇ (!sshkey_is_cert(ਕੁੰਜੀ)) {
			error("%s:%lu is not a certificate", ਰਸਤਾ, lnum);
			ਜਾਰੀ;
		}
		ok = 1;
		ਜੇ (!is_stdin && lnum == 1)
			ਲਿਖੋ("%s:\n", ਰਸਤਾ);
		ਨਹੀਂਤਾਂ
			ਲਿਖੋ("%s:%lu:\n", ਰਸਤਾ, lnum);
		print_cert(ਕੁੰਜੀ);
	}
	ਮੁਕਤ(ਸਤਰ);
	sshkey_free(ਕੁੰਜੀ);
	fclose(f);
	ਬਾਹਰ_ਨਿਕਲੋ(ok ? 0 : 1);
}

ਸਥਿਰ ਖਾਲੀ
ਲੱਦੋ_krl(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, ਬਣਤਰ ssh_krl **krlp)
{
	ਬਣਤਰ sshbuf *krlbuf;
	ਪੂਰਨ r;

	ਜੇ ((r = sshbuf_ਲੱਦੋ_file(ਰਸਤਾ, &krlbuf)) != 0)
		fatal_r(r, "Unable to load KRL %s", ਰਸਤਾ);
	/* XXX check sigs */
	ਜੇ ((r = ssh_krl_from_blob(krlbuf, krlp)) != 0 ||
	    *krlp == ਨਿਰਾ)
		fatal_r(r, "Invalid KRL file %s", ਰਸਤਾ);
	sshbuf_free(krlbuf);
}

ਸਥਿਰ ਖਾਲੀ
hash_ਮੰਜ਼ਿਲ_blob(ਅਚਲ ਅੱਖਰ *cp, u_char **blobp, ਮਾਪ_t *lenp,
    ਅਚਲ ਅੱਖਰ *file, u_long lnum)
{
	ਅੱਖਰ *tmp;
	ਮਾਪ_t tlen;
	ਬਣਤਰ sshbuf *b;
	ਪੂਰਨ r;

	ਜੇ ((cp = strprefix(cp, "SHA256:", 0)) == ਨਿਰਾ)
		fatal("%s:%lu: unsupported hash algorithm", file, lnum);

	/*
	 * OpenSSH base64 hashes omit trailing '='
	 * characters; put them back for decode.
	 */
	ਜੇ ((tlen = ਲੜੀ_ਲੰਬਾਈ(cp)) >= SIZE_MAX - 5)
		fatal_f("hash too long: %zu bytes", tlen);
	tmp = xmalloc(tlen + 4 + 1);
	strlcpy(tmp, cp, tlen + 1);
	ਜਦੋਂ ((tlen % 4) != 0) {
		tmp[tlen++] = '=';
		tmp[tlen] = '\0';
	}
	ਜੇ ((b = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = sshbuf_b64tod(b, tmp)) != 0)
		fatal_r(r, "%s:%lu: decode hash failed", file, lnum);
	ਮੁਕਤ(tmp);
	*lenp = sshbuf_len(b);
	*blobp = xmalloc(*lenp);
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(*blobp, sshbuf_ptr(b), *lenp);
	sshbuf_free(b);
}

ਸਥਿਰ ਖਾਲੀ
update_krl_from_file(ਬਣਤਰ passwd *pw, ਅਚਲ ਅੱਖਰ *file, ਪੂਰਨ wild_ca,
    ਅਚਲ ਬਣਤਰ sshkey *ca, ਬਣਤਰ ssh_krl *krl)
{
	ਬਣਤਰ sshkey *ਕੁੰਜੀ = ਨਿਰਾ;
	u_long lnum = 0;
	ਅੱਖਰ *ਰਸਤਾ, *cp, *ep, *ਸਤਰ = ਨਿਰਾ;
	u_char *blob = ਨਿਰਾ;
	ਮਾਪ_t blen = 0, linesize = 0;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ serial, serial2;
	ਪੂਰਨ i, was_explicit_ਕੁੰਜੀ, was_sha1, was_sha256, was_hash, r;
	FILE *krl_spec;

	ਰਸਤਾ = tilde_expand_filename(file, pw->pw_uid);
	ਜੇ (strcmp(ਰਸਤਾ, "-") == 0) {
		krl_spec = stdin;
		ਮੁਕਤ(ਰਸਤਾ);
		ਰਸਤਾ = xstrdup("(standard input)");
	} ਨਹੀਂਤਾਂ ਜੇ ((krl_spec = fopen(ਰਸਤਾ, "r")) == ਨਿਰਾ)
		fatal("fopen %s: %s", ਰਸਤਾ, strerror(errno));

	ਜੇ (!quiet)
		ਲਿਖੋ("Revoking from %s\n", ਰਸਤਾ);
	ਜਦੋਂ (getline(&ਸਤਰ, &linesize, krl_spec) != -1) {
		ਜੇ (linesize >= ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ) {
			fatal_f("%s contains unparsable line, len=%zu",
			    ਰਸਤਾ, linesize);
		}
		lnum++;
		was_explicit_ਕੁੰਜੀ = was_sha1 = was_sha256 = was_hash = 0;
		cp = ਸਤਰ + strspn(ਸਤਰ, " \t");
		/* Trim trailing space, comments and strip \n */
		ਲਈ (i = 0, r = -1; cp[i] != '\0'; i++) {
			ਜੇ (cp[i] == '#' || cp[i] == '\n') {
				cp[i] = '\0';
				ਰੋਕੋ;
			}
			ਜੇ (cp[i] == ' ' || cp[i] == '\t') {
				/* Remember the start of a span of whitespace */
				ਜੇ (r == -1)
					r = i;
			} ਨਹੀਂਤਾਂ
				r = -1;
		}
		ਜੇ (r != -1)
			cp[r] = '\0';
		ਜੇ (*cp == '\0')
			ਜਾਰੀ;
		ਜੇ (strncasecmp(cp, "serial:", 7) == 0) {
			ਜੇ (ca == ਨਿਰਾ && !wild_ca) {
				fatal("revoking certificates by serial number "
				    "requires specification of a CA key");
			}
			cp += 7;
			cp = cp + strspn(cp, " \t");
			errno = 0;
			serial = strtoull(cp, &ep, 0);
			ਜੇ (*cp == '\0' || (*ep != '\0' && *ep != '-'))
				fatal("%s:%lu: invalid serial \"%s\"",
				    ਰਸਤਾ, lnum, cp);
			ਜੇ (errno == ERANGE && serial == ULLONG_MAX)
				fatal("%s:%lu: serial out of range",
				    ਰਸਤਾ, lnum);
			serial2 = serial;
			ਜੇ (*ep == '-') {
				cp = ep + 1;
				errno = 0;
				serial2 = strtoull(cp, &ep, 0);
				ਜੇ (*cp == '\0' || *ep != '\0')
					fatal("%s:%lu: invalid serial \"%s\"",
					    ਰਸਤਾ, lnum, cp);
				ਜੇ (errno == ERANGE && serial2 == ULLONG_MAX)
					fatal("%s:%lu: serial out of range",
					    ਰਸਤਾ, lnum);
				ਜੇ (serial2 <= serial)
					fatal("%s:%lu: invalid serial range "
					    "%llu:%llu", ਰਸਤਾ, lnum,
					    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)serial,
					    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)serial2);
			}
			ਜੇ (ssh_krl_revoke_cert_by_serial_range(krl,
			    ca, serial, serial2) != 0) {
				fatal_f("revoke serial failed");
			}
		} ਨਹੀਂਤਾਂ ਜੇ (strncasecmp(cp, "id:", 3) == 0) {
			ਜੇ (ca == ਨਿਰਾ && !wild_ca) {
				fatal("revoking certificates by key ID "
				    "requires specification of a CA key");
			}
			cp += 3;
			cp = cp + strspn(cp, " \t");
			ਜੇ (ssh_krl_revoke_cert_by_ਕੁੰਜੀ_id(krl, ca, cp) != 0)
				fatal_f("revoke key ID failed");
		} ਨਹੀਂਤਾਂ ਜੇ (strncasecmp(cp, "hash:", 5) == 0) {
			cp += 5;
			cp = cp + strspn(cp, " \t");
			hash_ਮੰਜ਼ਿਲ_blob(cp, &blob, &blen, file, lnum);
			ਜੇ ((r = ssh_krl_revoke_ਕੁੰਜੀ_sha256(krl,
			    blob, blen)) != 0)
				fatal_fr(r, "revoke key failed");
			ਮੁਕਤ(blob);
			blob = ਨਿਰਾ;
			blen = 0;
		} ਨਹੀਂਤਾਂ {
			ਜੇ (strncasecmp(cp, "key:", 4) == 0) {
				cp += 4;
				cp = cp + strspn(cp, " \t");
				was_explicit_ਕੁੰਜੀ = 1;
			} ਨਹੀਂਤਾਂ ਜੇ (strncasecmp(cp, "sha1:", 5) == 0) {
				cp += 5;
				cp = cp + strspn(cp, " \t");
				was_sha1 = 1;
			} ਨਹੀਂਤਾਂ ਜੇ (strncasecmp(cp, "sha256:", 7) == 0) {
				cp += 7;
				cp = cp + strspn(cp, " \t");
				was_sha256 = 1;
				/*
				 * Just try to process the line as a key.
				 * Parsing will fail if it isn't.
				 */
			}
			ਜੇ ((ਕੁੰਜੀ = sshkey_new(ਕੁੰਜੀ_UNSPEC)) == ਨਿਰਾ)
				fatal("sshkey_new");
			ਜੇ ((r = sshkey_read(ਕੁੰਜੀ, &cp)) != 0)
				fatal_r(r, "%s:%lu: invalid key", ਰਸਤਾ, lnum);
			ਜੇ (was_explicit_ਕੁੰਜੀ)
				r = ssh_krl_revoke_ਕੁੰਜੀ_explicit(krl, ਕੁੰਜੀ);
			ਨਹੀਂਤਾਂ ਜੇ (was_sha1) {
				ਜੇ (sshkey_fingerprint_raw(ਕੁੰਜੀ,
				    SSH_DIGEST_SHA1, &blob, &blen) != 0) {
					fatal("%s:%lu: fingerprint failed",
					    file, lnum);
				}
				r = ssh_krl_revoke_ਕੁੰਜੀ_sha1(krl, blob, blen);
			} ਨਹੀਂਤਾਂ ਜੇ (was_sha256) {
				ਜੇ (sshkey_fingerprint_raw(ਕੁੰਜੀ,
				    SSH_DIGEST_SHA256, &blob, &blen) != 0) {
					fatal("%s:%lu: fingerprint failed",
					    file, lnum);
				}
				r = ssh_krl_revoke_ਕੁੰਜੀ_sha256(krl, blob, blen);
			} ਨਹੀਂਤਾਂ
				r = ssh_krl_revoke_ਕੁੰਜੀ(krl, ਕੁੰਜੀ);
			ਜੇ (r != 0)
				fatal_fr(r, "revoke key failed");
			freezero(blob, blen);
			blob = ਨਿਰਾ;
			blen = 0;
			sshkey_free(ਕੁੰਜੀ);
		}
	}
	ਜੇ (strcmp(ਰਸਤਾ, "-") != 0)
		fclose(krl_spec);
	ਮੁਕਤ(ਸਤਰ);
	ਮੁਕਤ(ਰਸਤਾ);
}

ਸਥਿਰ ਖਾਲੀ
do_gen_krl(ਬਣਤਰ passwd *pw, ਪੂਰਨ updating, ਅਚਲ ਅੱਖਰ *ca_ਕੁੰਜੀ_ਰਸਤਾ,
    ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ krl_ਸੰਸਕਰਣ, ਅਚਲ ਅੱਖਰ *krl_comment,
    ਪੂਰਨ argc, ਅੱਖਰ **argv)
{
	ਬਣਤਰ ssh_krl *krl;
	ਬਣਤਰ stat sb;
	ਬਣਤਰ sshkey *ca = ਨਿਰਾ;
	ਪੂਰਨ i, r, wild_ca = 0;
	ਅੱਖਰ *tmp;
	ਬਣਤਰ sshbuf *kbuf;

	ਜੇ (*ਪਛਾਣ_ਤੱਤ_file == '\0')
		fatal("KRL generation requires an output file");
	ਜੇ (stat(ਪਛਾਣ_ਤੱਤ_file, &sb) == -1) {
		ਜੇ (errno != ENOENT)
			fatal("Cannot access KRL \"%s\": %s",
			    ਪਛਾਣ_ਤੱਤ_file, strerror(errno));
		ਜੇ (updating)
			fatal("KRL \"%s\" does not exist", ਪਛਾਣ_ਤੱਤ_file);
	}
	ਜੇ (ca_ਕੁੰਜੀ_ਰਸਤਾ != ਨਿਰਾ) {
		ਜੇ (strcasecmp(ca_ਕੁੰਜੀ_ਰਸਤਾ, "none") == 0)
			wild_ca = 1;
		ਨਹੀਂਤਾਂ {
			tmp = tilde_expand_filename(ca_ਕੁੰਜੀ_ਰਸਤਾ, pw->pw_uid);
			ਜੇ ((r = sshkey_ਲੱਦੋ_ਜਨਤਕ(tmp, &ca, ਨਿਰਾ)) != 0)
				fatal_r(r, "Cannot load CA public key %s", tmp);
			ਮੁਕਤ(tmp);
		}
	}

	ਜੇ (updating)
		ਲੱਦੋ_krl(ਪਛਾਣ_ਤੱਤ_file, &krl);
	ਨਹੀਂਤਾਂ ਜੇ ((krl = ssh_krl_init()) == ਨਿਰਾ)
		fatal("couldn't create KRL");

	ਜੇ (krl_ਸੰਸਕਰਣ != 0)
		ssh_krl_ਸੈੱਟ_ਸੰਸਕਰਣ(krl, krl_ਸੰਸਕਰਣ);
	ਜੇ (krl_comment != ਨਿਰਾ)
		ssh_krl_ਸੈੱਟ_comment(krl, krl_comment);

	ਲਈ (i = 0; i < argc; i++)
		update_krl_from_file(pw, argv[i], wild_ca, ca, krl);

	ਜੇ ((kbuf = sshbuf_new()) == ਨਿਰਾ)
		fatal("sshbuf_new failed");
	ਜੇ (ssh_krl_ਮੰਜ਼ਿਲ_blob(krl, kbuf) != 0)
		fatal("Couldn't generate KRL");
	ਜੇ ((r = sshbuf_write_file(ਪਛਾਣ_ਤੱਤ_file, kbuf)) != 0)
		fatal("write %s: %s", ਪਛਾਣ_ਤੱਤ_file, strerror(errno));
	sshbuf_free(kbuf);
	ssh_krl_free(krl);
	sshkey_free(ca);
}

ਸਥਿਰ ਖਾਲੀ
do_check_krl(ਬਣਤਰ passwd *pw, ਪੂਰਨ print_krl, ਪੂਰਨ argc, ਅੱਖਰ **argv)
{
	ਪੂਰਨ i, r, ret = 0;
	ਅੱਖਰ *comment;
	ਬਣਤਰ ssh_krl *krl;
	ਬਣਤਰ sshkey *k;

	ਜੇ (*ਪਛਾਣ_ਤੱਤ_file == '\0')
		fatal("KRL checking requires an input file");
	ਲੱਦੋ_krl(ਪਛਾਣ_ਤੱਤ_file, &krl);
	ਜੇ (print_krl)
		krl_dump(krl, stdout);
	ਲਈ (i = 0; i < argc; i++) {
		ਜੇ ((r = sshkey_ਲੱਦੋ_ਜਨਤਕ(argv[i], &k, &comment)) != 0)
			fatal_r(r, "Cannot load public key %s", argv[i]);
		r = ssh_krl_check_ਕੁੰਜੀ(krl, k);
		ਲਿਖੋ("%s%s%s%s: %s\n", argv[i],
		    *comment ? " (" : "", comment, *comment ? ")" : "",
		    r == 0 ? "ok" : "REVOKED");
		ਜੇ (r != 0)
			ret = 1;
		sshkey_free(k);
		ਮੁਕਤ(comment);
	}
	ssh_krl_free(krl);
	ਬਾਹਰ_ਨਿਕਲੋ(ret);
}

ਸਥਿਰ ਬਣਤਰ sshkey *
ਲੱਦੋ_sign_ਕੁੰਜੀ(ਅਚਲ ਅੱਖਰ *keypath, ਅਚਲ ਬਣਤਰ sshkey *pubkey)
{
	ਮਾਪ_t i, slen, plen = ਲੜੀ_ਲੰਬਾਈ(keypath);
	ਅੱਖਰ *privpath = xstrdup(keypath);
	ਸਥਿਰ ਅਚਲ ਅੱਖਰ * ਅਚਲ suffixes[] = { "-cert.pub", ".pub", ਨਿਰਾ };
	ਬਣਤਰ sshkey *ret = ਨਿਰਾ, *privkey = ਨਿਰਾ;
	ਪੂਰਨ r, waspub = 0;
	ਬਣਤਰ stat st;

	/*
	 * If passed a public key filename, then try to locate the corresponding
	 * private key. This lets us specify certificates on the command-line
	 * and have ssh-keygen find the appropriate private key.
	 */
	ਲਈ (i = 0; suffixes[i]; i++) {
		slen = ਲੜੀ_ਲੰਬਾਈ(suffixes[i]);
		ਜੇ (plen <= slen ||
		    strcmp(privpath + plen - slen, suffixes[i]) != 0)
			ਜਾਰੀ;
		privpath[plen - slen] = '\0';
		debug_f("%s looks like a public key, using private key "
		    "path %s instead", keypath, privpath);
		waspub = 1;
	}
	ਜੇ (waspub && stat(privpath, &st) != 0 && errno == ENOENT)
		fatal("No private key found for public key \"%s\"", keypath);
	ਜੇ ((r = sshkey_ਲੱਦੋ_ਨਿੱਜੀ(privpath, "", &privkey, ਨਿਰਾ)) != 0 &&
	    (r != SSH_ERR_ਕੁੰਜੀ_WRONG_PASSPHRASE)) {
		debug_fr(r, "load private key \"%s\"", privpath);
		fatal("No private key found for \"%s\"", privpath);
	} ਨਹੀਂਤਾਂ ਜੇ (privkey == ਨਿਰਾ)
		privkey = ਲੱਦੋ_ਪਛਾਣ_ਤੱਤ(privpath, ਨਿਰਾ);

	ਜੇ (!sshkey_equal_ਜਨਤਕ(pubkey, privkey)) {
		error("Public key %s doesn't match private %s",
		    keypath, privpath);
		ਜਾਓ ਪੂਰਾ;
	}
	ਜੇ (sshkey_is_cert(pubkey) && !sshkey_is_cert(privkey)) {
		/*
		 * Graft the certificate onto the private key to make
		 * it capable of signing.
		 */
		ਜੇ ((r = sshkey_ਮੰਜ਼ਿਲ_certified(privkey)) != 0) {
			error_fr(r, "sshkey_to_certified");
			ਜਾਓ ਪੂਰਾ;
		}
		ਜੇ ((r = sshkey_cert_copy(pubkey, privkey)) != 0) {
			error_fr(r, "sshkey_cert_copy");
			ਜਾਓ ਪੂਰਾ;
		}
	}
	/* success */
	ret = privkey;
	privkey = ਨਿਰਾ;
 ਪੂਰਾ:
	sshkey_free(privkey);
	ਮੁਕਤ(privpath);
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਪੂਰਨ
sign_one(ਬਣਤਰ sshkey *signkey, ਅਚਲ ਅੱਖਰ *filename, ਪੂਰਨ fd,
    ਅਚਲ ਅੱਖਰ *sig_namespace, ਅਚਲ ਅੱਖਰ *hashalg, sshsig_signer *signer,
    ਖਾਲੀ *signer_ctx)
{
	ਬਣਤਰ sshbuf *sigbuf = ਨਿਰਾ, *abuf = ਨਿਰਾ;
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR, wfd = -1, oerrno;
	ਅੱਖਰ *wfile = ਨਿਰਾ, *asig = ਨਿਰਾ, *fp = ਨਿਰਾ;
	ਅੱਖਰ *pin = ਨਿਰਾ, *prompt = ਨਿਰਾ;

	ਜੇ (!quiet) {
		ਜੇ (fd == STDIN_FILENO)
			fprintf(stderr, "Signing data on standard input\n");
		ਨਹੀਂਤਾਂ
			fprintf(stderr, "Signing file %s\n", filename);
	}
	ਜੇ (signer == ਨਿਰਾ && sshkey_is_sk(signkey)) {
		ਜੇ ((signkey->sk_flags & SSH_SK_USER_VERIFICATION_REQD)) {
			xasprintf(&prompt, "Enter PIN for %s key: ",
			    sshkey_type(signkey));
			ਜੇ ((pin = read_passphrase(prompt,
			    RP_ALLOW_STDIN)) == ਨਿਰਾ)
				fatal_f("couldn't read PIN");
		}
		ਜੇ ((signkey->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
			ਜੇ ((fp = sshkey_fingerprint(signkey, fingerprint_hash,
			    SSH_FP_DEFAULT)) == ਨਿਰਾ)
				fatal_f("fingerprint failed");
			fprintf(stderr, "Confirm user presence for key %s %s\n",
			    sshkey_type(signkey), fp);
			ਮੁਕਤ(fp);
		}
	}
	ਜੇ ((r = sshsig_sign_fd(signkey, hashalg, sk_provider, pin,
	    fd, sig_namespace, &sigbuf, signer, signer_ctx)) != 0) {
		error_r(r, "Signing %s failed", filename);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshsig_armor(sigbuf, &abuf)) != 0) {
		error_fr(r, "sshsig_armor");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((asig = sshbuf_dup_string(abuf)) == ਨਿਰਾ) {
		error_f("buffer error");
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ (fd == STDIN_FILENO) {
		fputs(asig, stdout);
		fflush(stdout);
	} ਨਹੀਂਤਾਂ {
		xasprintf(&wfile, "%s.sig", filename);
		ਜੇ (confirm_overwrite(wfile)) {
			ਜੇ ((wfd = open(wfile, O_WRONLY|O_CREAT|O_TRUNC,
			    0666)) == -1) {
				oerrno = errno;
				error("Cannot open %s: %s",
				    wfile, strerror(errno));
				errno = oerrno;
				r = SSH_ERR_SYSTEM_ERROR;
				ਜਾਓ ਬਾਹਰਲਾ;
			}
			ਜੇ (atomicio(vwrite, wfd, asig,
			    ਲੜੀ_ਲੰਬਾਈ(asig)) != ਲੜੀ_ਲੰਬਾਈ(asig)) {
				oerrno = errno;
				error("Cannot write to %s: %s",
				    wfile, strerror(errno));
				errno = oerrno;
				r = SSH_ERR_SYSTEM_ERROR;
				ਜਾਓ ਬਾਹਰਲਾ;
			}
			ਜੇ (!quiet) {
				fprintf(stderr, "Write signature to %s\n",
				    wfile);
			}
		}
	}
	/* success */
	r = 0;
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(wfile);
	ਮੁਕਤ(prompt);
	ਮੁਕਤ(asig);
	ਜੇ (pin != ਨਿਰਾ)
		freezero(pin, ਲੜੀ_ਲੰਬਾਈ(pin));
	sshbuf_free(abuf);
	sshbuf_free(sigbuf);
	ਜੇ (wfd != -1)
		close(wfd);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਪੂਰਨ
sig_process_opts(ਅੱਖਰ * ਅਚਲ *opts, ਮਾਪ_t nopts, ਅੱਖਰ **hashalgp,
    uint64_t *verify_timep, ਪੂਰਨ *print_pubkey)
{
	ਮਾਪ_t i;
	time_t now;
	ਅਚਲ ਅੱਖਰ *p;

	ਜੇ (verify_timep != ਨਿਰਾ)
		*verify_timep = 0;
	ਜੇ (print_pubkey != ਨਿਰਾ)
		*print_pubkey = 0;
	ਜੇ (hashalgp != ਨਿਰਾ)
		*hashalgp = ਨਿਰਾ;
	ਲਈ (i = 0; i < nopts; i++) {
		ਜੇ (hashalgp != ਨਿਰਾ &&
		    (p = strprefix(opts[i], "hashalg=", 1)) != ਨਿਰਾ) {
			*hashalgp = xstrdup(p);
		} ਨਹੀਂਤਾਂ ਜੇ (verify_timep &&
		    (p = strprefix(opts[i], "verify-time=", 1)) != ਨਿਰਾ) {
			ਜੇ (parse_absolute_ਸਮਾਂ(p, verify_timep) != 0 ||
			    *verify_timep == 0) {
				error("Invalid \"verify-time\" option");
				ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
			}
		} ਨਹੀਂਤਾਂ ਜੇ (print_pubkey &&
		    strcasecmp(opts[i], "print-pubkey") == 0) {
			*print_pubkey = 1;
		} ਨਹੀਂਤਾਂ {
			error("Invalid option \"%s\"", opts[i]);
			ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
		}
	}
	ਜੇ (verify_timep && *verify_timep == 0) {
		ਜੇ ((now = time(ਨਿਰਾ)) < 0) {
			error("Time is before epoch");
			ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
		}
		*verify_timep = (uint64_t)now;
	}
	ਵਾਪਸ 0;
}


ਸਥਿਰ ਪੂਰਨ
sig_sign(ਅਚਲ ਅੱਖਰ *keypath, ਅਚਲ ਅੱਖਰ *sig_namespace, ਪੂਰਨ require_agent,
    ਪੂਰਨ argc, ਅੱਖਰ **argv, ਅੱਖਰ * ਅਚਲ *opts, ਮਾਪ_t nopts)
{
	ਪੂਰਨ i, fd = -1, r, ret = -1;
	ਪੂਰਨ agent_fd = -1;
	ਬਣਤਰ sshkey *pubkey = ਨਿਰਾ, *privkey = ਨਿਰਾ, *signkey = ਨਿਰਾ;
	sshsig_signer *signer = ਨਿਰਾ;
	ਅੱਖਰ *hashalg = ਨਿਰਾ;

	/* Check file arguments. */
	ਲਈ (i = 0; i < argc; i++) {
		ਜੇ (strcmp(argv[i], "-") != 0)
			ਜਾਰੀ;
		ਜੇ (i > 0 || argc > 1)
			fatal("Cannot sign mix of paths and standard input");
	}

	ਜੇ (sig_process_opts(opts, nopts, &hashalg, ਨਿਰਾ, ਨਿਰਾ) != 0)
		ਜਾਓ ਪੂਰਾ; /* error already logged */

	ਜੇ ((r = sshkey_ਲੱਦੋ_ਜਨਤਕ(keypath, &pubkey, ਨਿਰਾ)) != 0) {
		error_r(r, "Couldn't load public key %s", keypath);
		ਜਾਓ ਪੂਰਾ;
	}

	ਜੇ ((r = ssh_get_authentication_socket(&agent_fd)) != 0) {
		ਜੇ (require_agent)
			fatal("Couldn't get agent socket");
		debug_r(r, "Couldn't get agent socket");
	} ਨਹੀਂਤਾਂ {
		ਜੇ ((r = ssh_agent_has_ਕੁੰਜੀ(agent_fd, pubkey)) == 0)
			signer = agent_signer;
		ਨਹੀਂਤਾਂ {
			ਜੇ (require_agent)
				fatal("Couldn't find key in agent");
			debug_r(r, "Couldn't find key in agent");
		}
	}

	ਜੇ (signer == ਨਿਰਾ) {
		/* Not using agent - try to load private key */
		ਜੇ ((privkey = ਲੱਦੋ_sign_ਕੁੰਜੀ(keypath, pubkey)) == ਨਿਰਾ)
			ਜਾਓ ਪੂਰਾ;
		signkey = privkey;
	} ਨਹੀਂਤਾਂ {
		/* Will use key in agent */
		signkey = pubkey;
	}

	ਜੇ (argc == 0) {
		ਜੇ ((r = sign_one(signkey, "(stdin)", STDIN_FILENO,
		    sig_namespace, hashalg, signer, &agent_fd)) != 0)
			ਜਾਓ ਪੂਰਾ;
	} ਨਹੀਂਤਾਂ {
		ਲਈ (i = 0; i < argc; i++) {
			ਜੇ (strcmp(argv[i], "-") == 0)
				fd = STDIN_FILENO;
			ਨਹੀਂਤਾਂ ਜੇ ((fd = open(argv[i], O_RDONLY)) == -1) {
				error("Cannot open %s for signing: %s",
				    argv[i], strerror(errno));
				ਜਾਓ ਪੂਰਾ;
			}
			ਜੇ ((r = sign_one(signkey, argv[i], fd, sig_namespace,
			    hashalg, signer, &agent_fd)) != 0)
				ਜਾਓ ਪੂਰਾ;
			ਜੇ (fd != STDIN_FILENO)
				close(fd);
			fd = -1;
		}
	}

	ret = 0;
ਪੂਰਾ:
	ਜੇ (fd != -1 && fd != STDIN_FILENO)
		close(fd);
	sshkey_free(pubkey);
	sshkey_free(privkey);
	ਮੁਕਤ(hashalg);
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਪੂਰਨ
sig_verify(ਅਚਲ ਅੱਖਰ *signature, ਅਚਲ ਅੱਖਰ *sig_namespace,
    ਅਚਲ ਅੱਖਰ *principal, ਅਚਲ ਅੱਖਰ *allowed_ਕੁੰਜੀਆਂ, ਅਚਲ ਅੱਖਰ *revoked_ਕੁੰਜੀਆਂ,
    ਅੱਖਰ * ਅਚਲ *opts, ਮਾਪ_t nopts)
{
	ਪੂਰਨ r, ret = -1;
	ਪੂਰਨ print_pubkey = 0;
	ਬਣਤਰ sshbuf *sigbuf = ਨਿਰਾ, *abuf = ਨਿਰਾ;
	ਬਣਤਰ sshkey *sign_ਕੁੰਜੀ = ਨਿਰਾ;
	ਅੱਖਰ *fp = ਨਿਰਾ;
	ਬਣਤਰ sshkey_sig_details *sig_details = ਨਿਰਾ;
	uint64_t verify_ਸਮਾਂ = 0;

	ਜੇ (sig_process_opts(opts, nopts, ਨਿਰਾ, &verify_ਸਮਾਂ,
	    &print_pubkey) != 0)
		ਜਾਓ ਪੂਰਾ; /* error already logged */

	memset(&sig_details, 0, ਆਕਾਰ(sig_details));
	ਜੇ ((r = sshbuf_ਲੱਦੋ_file(signature, &abuf)) != 0) {
		error_r(r, "Couldn't read signature file");
		ਜਾਓ ਪੂਰਾ;
	}

	ਜੇ ((r = sshsig_dearmor(abuf, &sigbuf)) != 0) {
		error_fr(r, "sshsig_armor");
		ਜਾਓ ਪੂਰਾ;
	}
	ਜੇ ((r = sshsig_verify_fd(sigbuf, STDIN_FILENO, sig_namespace,
	    &sign_ਕੁੰਜੀ, &sig_details)) != 0)
		ਜਾਓ ਪੂਰਾ; /* sshsig_verify() prints error */

	ਜੇ ((fp = sshkey_fingerprint(sign_ਕੁੰਜੀ, fingerprint_hash,
	    SSH_FP_DEFAULT)) == ਨਿਰਾ)
		fatal_f("sshkey_fingerprint failed");
	debug("Valid (unverified) signature from key %s", fp);
	ਜੇ (sig_details != ਨਿਰਾ) {
		debug2_f("signature details: counter = %u, flags = 0x%02x",
		    sig_details->sk_counter, sig_details->sk_flags);
	}
	ਮੁਕਤ(fp);
	fp = ਨਿਰਾ;

	ਜੇ (revoked_ਕੁੰਜੀਆਂ != ਨਿਰਾ) {
		ਜੇ ((r = sshkey_check_revoked(sign_ਕੁੰਜੀ, revoked_ਕੁੰਜੀਆਂ)) != 0) {
			debug3_fr(r, "sshkey_check_revoked");
			ਜਾਓ ਪੂਰਾ;
		}
	}

	ਜੇ (allowed_ਕੁੰਜੀਆਂ != ਨਿਰਾ && (r = sshsig_check_allowed_ਕੁੰਜੀਆਂ(allowed_ਕੁੰਜੀਆਂ,
	    sign_ਕੁੰਜੀ, principal, sig_namespace, verify_ਸਮਾਂ)) != 0) {
		debug3_fr(r, "sshsig_check_allowed_keys");
		ਜਾਓ ਪੂਰਾ;
	}
	/* success */
	ret = 0;
ਪੂਰਾ:
	ਜੇ (!quiet) {
		ਜੇ (ret == 0) {
			ਜੇ ((fp = sshkey_fingerprint(sign_ਕੁੰਜੀ, fingerprint_hash,
			    SSH_FP_DEFAULT)) == ਨਿਰਾ)
				fatal_f("sshkey_fingerprint failed");
			ਜੇ (principal == ਨਿਰਾ) {
				ਲਿਖੋ("Good \"%s\" signature with %s key %s\n",
				    sig_namespace, sshkey_type(sign_ਕੁੰਜੀ), fp);

			} ਨਹੀਂਤਾਂ {
				ਲਿਖੋ("Good \"%s\" signature for %s with %s key %s\n",
				    sig_namespace, principal,
				    sshkey_type(sign_ਕੁੰਜੀ), fp);
			}
		} ਨਹੀਂਤਾਂ {
			ਲਿਖੋ("Could not verify signature.\n");
		}
	}
	/* Print the signature key if requested */
	ਜੇ (ret == 0 && print_pubkey && sign_ਕੁੰਜੀ != ਨਿਰਾ) {
		ਜੇ ((r = sshkey_write(sign_ਕੁੰਜੀ, stdout)) == 0)
			fputc('\n', stdout);
		ਨਹੀਂਤਾਂ {
			error_r(r, "Could not print public key.\n");
			ret = -1;
		}
	}
	sshbuf_free(sigbuf);
	sshbuf_free(abuf);
	sshkey_free(sign_ਕੁੰਜੀ);
	sshkey_sig_details_free(sig_details);
	ਮੁਕਤ(fp);
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਪੂਰਨ
sig_ਲੱਭੋ_principals(ਅਚਲ ਅੱਖਰ *signature, ਅਚਲ ਅੱਖਰ *allowed_ਕੁੰਜੀਆਂ,
    ਅੱਖਰ * ਅਚਲ *opts, ਮਾਪ_t nopts)
{
	ਪੂਰਨ r, ret = -1;
	ਬਣਤਰ sshbuf *sigbuf = ਨਿਰਾ, *abuf = ਨਿਰਾ;
	ਬਣਤਰ sshkey *sign_ਕੁੰਜੀ = ਨਿਰਾ;
	ਅੱਖਰ *principals = ਨਿਰਾ, *cp, *tmp;
	uint64_t verify_ਸਮਾਂ = 0;

	ਜੇ (sig_process_opts(opts, nopts, ਨਿਰਾ, &verify_ਸਮਾਂ, ਨਿਰਾ) != 0)
		ਜਾਓ ਪੂਰਾ; /* error already logged */

	ਜੇ ((r = sshbuf_ਲੱਦੋ_file(signature, &abuf)) != 0) {
		error_r(r, "Couldn't read signature file");
		ਜਾਓ ਪੂਰਾ;
	}
	ਜੇ ((r = sshsig_dearmor(abuf, &sigbuf)) != 0) {
		error_fr(r, "sshsig_armor");
		ਜਾਓ ਪੂਰਾ;
	}
	ਜੇ ((r = sshsig_get_pubkey(sigbuf, &sign_ਕੁੰਜੀ)) != 0) {
		error_fr(r, "sshsig_get_pubkey");
		ਜਾਓ ਪੂਰਾ;
	}
	ਜੇ ((r = sshsig_ਲੱਭੋ_principals(allowed_ਕੁੰਜੀਆਂ, sign_ਕੁੰਜੀ,
	    verify_ਸਮਾਂ, &principals)) != 0) {
		ਜੇ (r != SSH_ERR_ਕੁੰਜੀ_NOT_ਮਿਲਿਆ)
			error_fr(r, "sshsig_find_principal");
		ਜਾਓ ਪੂਰਾ;
	}
	ret = 0;
ਪੂਰਾ:
	ਜੇ (ret == 0 ) {
		/* Emit matching principals one per line */
		tmp = principals;
		ਜਦੋਂ ((cp = strsep(&tmp, ",")) != ਨਿਰਾ && *cp != '\0')
			puts(cp);
	} ਨਹੀਂਤਾਂ {
		fprintf(stderr, "No principal matched.\n");
	}
	sshbuf_free(sigbuf);
	sshbuf_free(abuf);
	sshkey_free(sign_ਕੁੰਜੀ);
	ਮੁਕਤ(principals);
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਪੂਰਨ
sig_ਮੇਲ_principals(ਅਚਲ ਅੱਖਰ *allowed_ਕੁੰਜੀਆਂ, ਅੱਖਰ *principal,
	ਅੱਖਰ * ਅਚਲ *opts, ਮਾਪ_t nopts)
{
	ਪੂਰਨ r;
	ਅੱਖਰ **principals = ਨਿਰਾ;
	ਮਾਪ_t i, nprincipals = 0;

	ਜੇ ((r = sig_process_opts(opts, nopts, ਨਿਰਾ, ਨਿਰਾ, ਨਿਰਾ)) != 0)
		ਵਾਪਸ r; /* error already logged */

	ਜੇ ((r = sshsig_ਮੇਲ_principals(allowed_ਕੁੰਜੀਆਂ, principal,
	    &principals, &nprincipals)) != 0) {
		debug_f("match: %s", ssh_err(r));
		fprintf(stderr, "No principal matched.\n");
		ਵਾਪਸ r;
	}
	ਲਈ (i = 0; i < nprincipals; i++) {
		ਲਿਖੋ("%s\n", principals[i]);
		ਮੁਕਤ(principals[i]);
	}
	ਮੁਕਤ(principals);

	ਵਾਪਸ 0;
}

ਸਥਿਰ ਖਾਲੀ
do_moduli_gen(ਅਚਲ ਅੱਖਰ *ਬਾਹਰਲਾ_file, ਅੱਖਰ **opts, ਮਾਪ_t nopts)
{
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	/* Moduli generation/screening */
	BIGNUM *ਸ਼ੁਰੂ = ਨਿਰਾ;
	ਪੂਰਨ moduli_ਬਿੱਟ = 0;
	FILE *ਬਾਹਰਲਾ;
	ਮਾਪ_t i;
	ਅਚਲ ਅੱਖਰ *errstr, *p;

	/* Parse options */
	ਲਈ (i = 0; i < nopts; i++) {
		ਜੇ ((p = strprefix(opts[i], "start=", 0)) != ਨਿਰਾ) {
			/* XXX - also compare length against bits */
			ਜੇ (BN_hex2bn(&ਸ਼ੁਰੂ, p) == 0)
				fatal("Invalid start point.");
		} ਨਹੀਂਤਾਂ ਜੇ ((p = strprefix(opts[i], "bits=", 0)) != ਨਿਰਾ) {
			moduli_ਬਿੱਟ = (ਪੂਰਨ)strtonum(p, 1, ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ, &errstr);
			ਜੇ (errstr) {
				fatal("Invalid number: %s (%s)", p, errstr);
			}
		} ਨਹੀਂਤਾਂ {
			fatal("Option \"%s\" is unsupported for moduli "
			    "generation", opts[i]);
		}
	}

	ਜੇ (strcmp(ਬਾਹਰਲਾ_file, "-") == 0)
		ਬਾਹਰਲਾ = stdout;
	ਨਹੀਂਤਾਂ ਜੇ ((ਬਾਹਰਲਾ = fopen(ਬਾਹਰਲਾ_file, "w")) == ਨਿਰਾ) {
		fatal("Couldn't open modulus candidate file \"%s\": %s",
		    ਬਾਹਰਲਾ_file, strerror(errno));
	}
	setvbuf(ਬਾਹਰਲਾ, ਨਿਰਾ, _IOLBF, 0);

	ਜੇ (moduli_ਬਿੱਟ == 0)
		moduli_ਬਿੱਟ = DEFAULT_ਬਿੱਟ;
	ਜੇ (gen_candidates(ਬਾਹਰਲਾ, moduli_ਬਿੱਟ, ਸ਼ੁਰੂ) != 0)
		fatal("modulus candidate generation failed");
#ਨਹੀਂਤਾਂ /* WITH_OPENSSL */
	fatal("Moduli generation is not supported");
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
}

ਸਥਿਰ ਖਾਲੀ
do_moduli_screen(ਅਚਲ ਅੱਖਰ *ਬਾਹਰਲਾ_file, ਅੱਖਰ **opts, ਮਾਪ_t nopts)
{
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	/* Moduli generation/screening */
	ਅੱਖਰ *checkpoint = ਨਿਰਾ;
	uint32_t generator_wanted = 0;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਸ਼ੁਰੂ_lineno = 0, ਸਤਰਾਂ_ਮੰਜ਼ਿਲ_process = 0;
	ਪੂਰਨ ਅਭਾਜ_tests = 0;
	FILE *ਬਾਹਰਲਾ, *ਵਿੱਚ = stdin;
	ਮਾਪ_t i;
	ਅਚਲ ਅੱਖਰ *errstr, *p;

	/* Parse options */
	ਲਈ (i = 0; i < nopts; i++) {
		ਜੇ ((p = strprefix(opts[i], "lines=", 0)) != ਨਿਰਾ) {
			ਸਤਰਾਂ_ਮੰਜ਼ਿਲ_process = strtoul(p, ਨਿਰਾ, 10);
		} ਨਹੀਂਤਾਂ ਜੇ ((p = strprefix(opts[i], "start-line=", 0)) != ਨਿਰਾ) {
			ਸ਼ੁਰੂ_lineno = strtoul(p, ਨਿਰਾ, 10);
		} ਨਹੀਂਤਾਂ ਜੇ ((p = strprefix(opts[i], "checkpoint=", 0)) != ਨਿਰਾ) {
			ਮੁਕਤ(checkpoint);
			checkpoint = xstrdup(p);
		} ਨਹੀਂਤਾਂ ਜੇ ((p = strprefix(opts[i], "generator=", 0)) != ਨਿਰਾ) {
			generator_wanted = (uint32_t)strtonum(p, 1, UINT_MAX,
			    &errstr);
			ਜੇ (errstr != ਨਿਰਾ) {
				fatal("Generator invalid: %s (%s)", p, errstr);
			}
		} ਨਹੀਂਤਾਂ ਜੇ ((p = strprefix(opts[i], "prime-tests=", 0)) != ਨਿਰਾ) {
			ਅਭਾਜ_tests = (ਪੂਰਨ)strtonum(p, 1, ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ, &errstr);
			ਜੇ (errstr) {
				fatal("Invalid number: %s (%s)", p, errstr);
			}
		} ਨਹੀਂਤਾਂ {
			fatal("Option \"%s\" is unsupported for moduli "
			    "screening", opts[i]);
		}
	}

	ਜੇ (have_ਪਛਾਣ_ਤੱਤ && strcmp(ਪਛਾਣ_ਤੱਤ_file, "-") != 0) {
		ਜੇ ((ਵਿੱਚ = fopen(ਪਛਾਣ_ਤੱਤ_file, "r")) == ਨਿਰਾ) {
			fatal("Couldn't open modulus candidate "
			    "file \"%s\": %s", ਪਛਾਣ_ਤੱਤ_file,
			    strerror(errno));
		}
	}

	ਜੇ (strcmp(ਬਾਹਰਲਾ_file, "-") == 0)
		ਬਾਹਰਲਾ = stdout;
	ਨਹੀਂਤਾਂ ਜੇ ((ਬਾਹਰਲਾ = fopen(ਬਾਹਰਲਾ_file, "a")) == ਨਿਰਾ) {
		fatal("Couldn't open moduli file \"%s\": %s",
		    ਬਾਹਰਲਾ_file, strerror(errno));
	}
	setvbuf(ਬਾਹਰਲਾ, ਨਿਰਾ, _IOLBF, 0);
	ਜੇ (ਅਭਾਜ_test(ਵਿੱਚ, ਬਾਹਰਲਾ, ਅਭਾਜ_tests == 0 ? 100 : ਅਭਾਜ_tests,
	    generator_wanted, checkpoint,
	    ਸ਼ੁਰੂ_lineno, ਸਤਰਾਂ_ਮੰਜ਼ਿਲ_process) != 0)
		fatal("modulus screening failed");
	ਜੇ (ਵਿੱਚ != stdin)
		(ਖਾਲੀ)fclose(ਵਿੱਚ);
	ਮੁਕਤ(checkpoint);
#ਨਹੀਂਤਾਂ /* WITH_OPENSSL */
	fatal("Moduli screening is not supported");
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
}

/* Read and confirm a passphrase */
ਸਥਿਰ ਅੱਖਰ *
read_check_passphrase(ਅਚਲ ਅੱਖਰ *prompt1, ਅਚਲ ਅੱਖਰ *prompt2,
    ਅਚਲ ਅੱਖਰ *retry_prompt)
{
	ਅੱਖਰ *passphrase1, *passphrase2;

	ਲਈ (;;) {
		passphrase1 = read_passphrase(prompt1, RP_ALLOW_STDIN);
		passphrase2 = read_passphrase(prompt2, RP_ALLOW_STDIN);
		ਜੇ (strcmp(passphrase1, passphrase2) == 0) {
			freezero(passphrase2, ਲੜੀ_ਲੰਬਾਈ(passphrase2));
			ਵਾਪਸ passphrase1;
		}
		/* The passphrases do not match. Clear them and retry. */
		freezero(passphrase1, ਲੜੀ_ਲੰਬਾਈ(passphrase1));
		freezero(passphrase2, ਲੜੀ_ਲੰਬਾਈ(passphrase2));
		fputs(retry_prompt, stdout);
		fputc('\n', stdout);
		fflush(stdout);
	}
	/* NOTREACHED */
	ਵਾਪਸ ਨਿਰਾ;
}

ਸਥਿਰ ਅੱਖਰ *
ਨਿੱਜੀ_ਕੁੰਜੀ_passphrase(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ)
{
	ਅੱਖਰ *prompt, *ret;

	ਜੇ (ਪਛਾਣ_ਤੱਤ_passphrase)
		ਵਾਪਸ xstrdup(ਪਛਾਣ_ਤੱਤ_passphrase);
	ਜੇ (ਪਛਾਣ_ਤੱਤ_new_passphrase)
		ਵਾਪਸ xstrdup(ਪਛਾਣ_ਤੱਤ_new_passphrase);

	xasprintf(&prompt, "Enter passphrase for \"%s\" "
	    "(empty for no passphrase): ", ਰਸਤਾ);
	ret = read_check_passphrase(prompt,
	    "Enter same passphrase again: ",
	    "Passphrases do not match.  Try again.");
	ਮੁਕਤ(prompt);
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਅੱਖਰ *
sk_suffix(ਅਚਲ ਅੱਖਰ *application, ਅਚਲ uint8_t *user, ਮਾਪ_t userlen)
{
	ਅੱਖਰ *ret, *cp;
	ਅਚਲ ਅੱਖਰ *p;
	ਮਾਪ_t slen, i;

	/* Trim off URL-like preamble */
	ਜੇ ((p = strprefix(application, "ssh://", 0)) != ਨਿਰਾ)
		ret =  xstrdup(p);
	ਨਹੀਂਤਾਂ ਜੇ ((p = strprefix(application, "ssh:", 0)) != ਨਿਰਾ)
		ret =  xstrdup(p);
	ਨਹੀਂਤਾਂ
		ret = xstrdup(application);

	/* Count trailing zeros in user */
	ਲਈ (i = 0; i < userlen; i++) {
		ਜੇ (user[userlen - i - 1] != 0)
			ਰੋਕੋ;
	}
	ਜੇ (i >= userlen)
		ਵਾਪਸ ret; /* user-id was default all-zeros */

	/* Append user-id, escaping non-UTF-8 characters */
	slen = userlen - i;
	ਜੇ (asmprintf(&cp, ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ, ਨਿਰਾ, "%.*s", (ਪੂਰਨ)slen, user) == -1)
		fatal_f("asmprintf failed");
	/* Don't emit a user-id that contains path or control characters */
	ਜੇ (strchr(cp, '/') != ਨਿਰਾ || ਲੜੀ_ਖੋਜ(cp, "..") != ਨਿਰਾ ||
	    strchr(cp, '\\') != ਨਿਰਾ) {
		ਮੁਕਤ(cp);
		cp = tohex(user, slen);
	}
	xextendf(&ret, "_", "%s", cp);
	ਮੁਕਤ(cp);
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਪੂਰਨ
do_download_sk(ਅਚਲ ਅੱਖਰ *skprovider, ਅਚਲ ਅੱਖਰ *device)
{
	ਬਣਤਰ sshsk_resident_ਕੁੰਜੀ **srks;
	ਮਾਪ_t nsrks, i;
	ਪੂਰਨ r, ret = -1;
	ਅੱਖਰ *fp, *pin = ਨਿਰਾ, *pass = ਨਿਰਾ, *ਰਸਤਾ, *pubpath;
	ਅਚਲ ਅੱਖਰ *ext;
	ਬਣਤਰ sshkey *ਕੁੰਜੀ;

	ਜੇ (skprovider == ਨਿਰਾ)
		fatal("Cannot download keys without provider");

	pin = read_passphrase("Enter PIN for authenticator: ", RP_ALLOW_STDIN);
	ਜੇ (!quiet) {
		ਲਿਖੋ("You may need to touch your authenticator "
		    "to authorize key download.\n");
	}
	ਜੇ ((r = sshsk_ਲੱਦੋ_resident(skprovider, device, pin, 0,
	    &srks, &nsrks)) != 0) {
		ਜੇ (pin != ਨਿਰਾ)
			freezero(pin, ਲੜੀ_ਲੰਬਾਈ(pin));
		error_r(r, "Unable to load resident keys");
		ਵਾਪਸ -1;
	}
	ਜੇ (nsrks == 0)
		logit("No keys to download");
	ਜੇ (pin != ਨਿਰਾ)
		freezero(pin, ਲੜੀ_ਲੰਬਾਈ(pin));

	ਲਈ (i = 0; i < nsrks; i++) {
		ਕੁੰਜੀ = srks[i]->ਕੁੰਜੀ;
		ਜੇ (ਕੁੰਜੀ->type != ਕੁੰਜੀ_ECDSA_SK && ਕੁੰਜੀ->type != ਕੁੰਜੀ_ED25519_SK) {
			error("Unsupported key type %s (%d)",
			    sshkey_type(ਕੁੰਜੀ), ਕੁੰਜੀ->type);
			ਜਾਰੀ;
		}
		ਜੇ ((fp = sshkey_fingerprint(ਕੁੰਜੀ, fingerprint_hash,
		    SSH_FP_DEFAULT)) == ਨਿਰਾ)
			fatal_f("sshkey_fingerprint failed");
		debug_f("key %zu: %s %s %s (flags 0x%02x)", i,
		    sshkey_type(ਕੁੰਜੀ), fp, ਕੁੰਜੀ->sk_application, ਕੁੰਜੀ->sk_flags);
		ext = sk_suffix(ਕੁੰਜੀ->sk_application,
		    srks[i]->user_id, srks[i]->user_id_len);
		xasprintf(&ਰਸਤਾ, "id_%s_rk%s%s",
		    ਕੁੰਜੀ->type == ਕੁੰਜੀ_ECDSA_SK ? "ecdsa_sk" : "ed25519_sk",
		    *ext == '\0' ? "" : "_", ext);

		/* If the file already exists, ask the user to confirm. */
		ਜੇ (!confirm_overwrite(ਰਸਤਾ)) {
			ਮੁਕਤ(ਰਸਤਾ);
			ਰੋਕੋ;
		}

		/* Save the key with the application string as the comment */
		ਜੇ (pass == ਨਿਰਾ)
			pass = ਨਿੱਜੀ_ਕੁੰਜੀ_passphrase(ਰਸਤਾ);
		ਜੇ ((r = sshkey_save_ਨਿੱਜੀ(ਕੁੰਜੀ, ਰਸਤਾ, pass,
		    ਕੁੰਜੀ->sk_application, ਨਿੱਜੀ_ਕੁੰਜੀ_format,
		    openssh_format_cipher, ਗੇੜ)) != 0) {
			error_r(r, "Saving key \"%s\" failed", ਰਸਤਾ);
			ਮੁਕਤ(ਰਸਤਾ);
			ਰੋਕੋ;
		}
		ਜੇ (!quiet) {
			ਲਿਖੋ("Saved %s key%s%s to %s\n", sshkey_type(ਕੁੰਜੀ),
			    *ext != '\0' ? " " : "",
			    *ext != '\0' ? ਕੁੰਜੀ->sk_application : "",
			    ਰਸਤਾ);
		}

		/* Save public key too */
		xasprintf(&pubpath, "%s.pub", ਰਸਤਾ);
		ਮੁਕਤ(ਰਸਤਾ);
		ਜੇ ((r = sshkey_save_ਜਨਤਕ(ਕੁੰਜੀ, pubpath,
		    ਕੁੰਜੀ->sk_application)) != 0) {
			error_r(r, "Saving public key \"%s\" failed", pubpath);
			ਮੁਕਤ(pubpath);
			ਰੋਕੋ;
		}
		ਮੁਕਤ(pubpath);
	}

	ਜੇ (i >= nsrks)
		ret = 0; /* success */
	ਜੇ (pass != ਨਿਰਾ)
		freezero(pass, ਲੜੀ_ਲੰਬਾਈ(pass));
	sshsk_free_resident_ਕੁੰਜੀਆਂ(srks, nsrks);
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਖਾਲੀ
save_attestation(ਬਣਤਰ sshbuf *attest, ਅਚਲ ਅੱਖਰ *ਰਸਤਾ)
{
	ਬਹੁਲਕ_t omask;
	ਪੂਰਨ r;

	ਜੇ (ਰਸਤਾ == ਨਿਰਾ)
		ਵਾਪਸ; /* nothing to do */
	ਜੇ (attest == ਨਿਰਾ || sshbuf_len(attest) == 0)
		fatal("Enrollment did not return attestation data");
	omask = umask(077);
	r = sshbuf_write_file(ਰਸਤਾ, attest);
	umask(omask);
	ਜੇ (r != 0)
		fatal_r(r, "Unable to write attestation data \"%s\"", ਰਸਤਾ);
	ਜੇ (!quiet)
		ਲਿਖੋ("Your FIDO attestation certificate has been saved in "
		    "%s\n", ਰਸਤਾ);
}

ਸਥਿਰ ਪੂਰਨ
confirm_sk_overwrite(ਅਚਲ ਅੱਖਰ *application, ਅਚਲ ਅੱਖਰ *user)
{
	ਅੱਖਰ yesno[3];

	ਲਿਖੋ("A resident key scoped to '%s' with user id '%s' already "
	    "exists.\n", application == ਨਿਰਾ ? "ssh:" : application,
	    user == ਨਿਰਾ ? "null" : user);
	ਲਿਖੋ("Overwrite key in token (y/n)? ");
	fflush(stdout);
	ਜੇ (fgets(yesno, ਆਕਾਰ(yesno), stdin) == ਨਿਰਾ)
		ਵਾਪਸ 0;
	ਜੇ (yesno[0] != 'y' && yesno[0] != 'Y')
		ਵਾਪਸ 0;
	ਵਾਪਸ 1;
}

ਸਥਿਰ ਖਾਲੀ
usage(ਖਾਲੀ)
{
	fprintf(stderr,
	    "usage: ssh-keygen [-q] [-a rounds] [-b bits] [-C comment] [-f output_keyfile]\n"
	    "                  [-m format] [-N new_passphrase] [-O option]\n"
	    "                  [-t ecdsa|ecdsa-sk|ed25519|ed25519-sk|mldsa44-ed25519|rsa]\n"
	    "                  [-w provider] [-Z cipher]\n"
	    "       ssh-keygen -p [-a rounds] [-f keyfile] [-m format] [-N new_passphrase]\n"
	    "                   [-P old_passphrase] [-Z cipher]\n"
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	    "       ssh-keygen -i [-f input_keyfile] [-m key_format]\n"
	    "       ssh-keygen -e [-f input_keyfile] [-m key_format]\n"
#ਜੇ_ਅੰਤ
	    "       ssh-keygen -y [-f input_keyfile]\n"
	    "       ssh-keygen -c [-a rounds] [-C comment] [-f keyfile] [-P passphrase]\n"
	    "       ssh-keygen -l [-v] [-E fingerprint_hash] [-f input_keyfile]\n"
	    "       ssh-keygen -B [-f input_keyfile]\n");
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ ENABLE_PKCS11
	fprintf(stderr,
	    "       ssh-keygen -D pkcs11\n");
#ਜੇ_ਅੰਤ
	fprintf(stderr,
	    "       ssh-keygen -F hostname [-lv] [-f known_hosts_file]\n"
	    "       ssh-keygen -H [-f known_hosts_file]\n"
	    "       ssh-keygen -K [-a rounds] [-w provider]\n"
	    "       ssh-keygen -R hostname [-f known_hosts_file]\n"
	    "       ssh-keygen -r hostname [-g] [-f input_keyfile]\n"
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	    "       ssh-keygen -M generate [-O option] output_file\n"
	    "       ssh-keygen -M screen [-f input_file] [-O option] output_file\n"
#ਜੇ_ਅੰਤ
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
	ਬਾਹਰ_ਨਿਕਲੋ(1);
}

/*
 * Main program for key management.
 */
ਪੂਰਨ
ਮੁੱਖ(ਪੂਰਨ argc, ਅੱਖਰ **argv)
{
	ਅੱਖਰ comment[ਕੁੰਜੀ_COMMENT_MAX], *passphrase = ਨਿਰਾ;
	ਅੱਖਰ *rr_hostname = ਨਿਰਾ, *ep, *fp, *ra;
	ਬਣਤਰ sshkey *ਨਿਜੀ = ਨਿਰਾ, *ਜਨਤਕ = ਨਿਰਾ;
	ਬਣਤਰ passwd *pw;
	ਪੂਰਨ ret = 0, r, opt, type;
	ਪੂਰਨ change_passphrase = 0, change_comment = 0, show_cert = 0;
	ਪੂਰਨ ਲੱਭੋ_host = 0, delete_host = 0, hash_hosts = 0;
	ਪੂਰਨ gen_all_hostkeys = 0, gen_krl = 0, update_krl = 0, check_krl = 0;
	ਪੂਰਨ prefer_agent = 0, convert_ਮੰਜ਼ਿਲ = 0, convert_from = 0;
	ਪੂਰਨ print_ਜਨਤਕ = 0, print_generic = 0, cert_serial_autoinc = 0;
	ਪੂਰਨ do_gen_candidates = 0, do_screen_candidates = 0, download_sk = 0;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ cert_serial = 0;
	ਅੱਖਰ *ਪਛਾਣ_ਤੱਤ_comment = ਨਿਰਾ, *ca_ਕੁੰਜੀ_ਰਸਤਾ = ਨਿਰਾ, **opts = ਨਿਰਾ;
	ਅੱਖਰ *sk_application = ਨਿਰਾ, *sk_device = ਨਿਰਾ, *sk_user = ਨਿਰਾ;
	ਅੱਖਰ *sk_attestation_ਰਸਤਾ = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *challenge = ਨਿਰਾ, *attest = ਨਿਰਾ;
	ਮਾਪ_t i, nopts = 0;
	uint32_t ਬਿੱਟ = 0;
	uint8_t sk_flags = SSH_SK_USER_PRESENCE_REQD;
	ਅਚਲ ਅੱਖਰ *errstr, *p;
	ਪੂਰਨ log_level = SYSLOG_LEVEL_INFO;
	ਅੱਖਰ *sign_op = ਨਿਰਾ;

	ਬਾਹਰੀ ਪੂਰਨ optind;
	ਬਾਹਰੀ ਅੱਖਰ *optarg;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	__progname = ssh_get_progname(argv[0]);

	ਬੀਜ_rng();

	log_init(argv[0], SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_USER, 1);

	msetlocale();

	/* we need this for the home * directory.  */
	pw = getpwuid(getuid());
	ਜੇ (!pw)
		fatal("No user exists for uid %lu", (u_long)getuid());
	pw = pwcopy(pw);
	ਜੇ (gethostname(hostname, ਆਕਾਰ(hostname)) == -1)
		fatal("gethostname: %s", strerror(errno));

	sk_provider = getenv("SSH_SK_PROVIDER");

	/* Remaining characters: dGjJSTWx */
	ਜਦੋਂ ((opt = getopt(argc, argv, "ABHKLQUXceghiklopquvy"
	    "C:D:E:F:I:M:N:O:P:R:V:Y:Z:"
	    "a:b:f:g:m:n:r:s:t:w:z:")) != -1) {
		ਚੋਣ (opt) {
		ਹਾਲਤ 'A':
			gen_all_hostkeys = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'b':
			ਬਿੱਟ = (uint32_t)strtonum(optarg, 1, UINT32_MAX,
			    &errstr);
			ਜੇ (errstr)
				fatal("Bits has bad value %s (%s)",
					optarg, errstr);
			ਰੋਕੋ;
		ਹਾਲਤ 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			ਜੇ (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			ਰੋਕੋ;
		ਹਾਲਤ 'F':
			ਲੱਭੋ_host = 1;
			rr_hostname = optarg;
			ਰੋਕੋ;
		ਹਾਲਤ 'H':
			hash_hosts = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'I':
			cert_ਕੁੰਜੀ_id = optarg;
			ਰੋਕੋ;
		ਹਾਲਤ 'R':
			delete_host = 1;
			rr_hostname = optarg;
			ਰੋਕੋ;
		ਹਾਲਤ 'L':
			show_cert = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'l':
			print_fingerprint = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'B':
			print_bubblebabble = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'm':
			ਜੇ (strcasecmp(optarg, "RFC4716") == 0 ||
			    strcasecmp(optarg, "ssh2") == 0) {
				convert_format = FMT_RFC4716;
				ਰੋਕੋ;
			}
			ਜੇ (strcasecmp(optarg, "PKCS8") == 0) {
				convert_format = FMT_PKCS8;
				ਨਿੱਜੀ_ਕੁੰਜੀ_format = SSHKEY_ਨਿੱਜੀ_PKCS8;
				ਰੋਕੋ;
			}
			ਜੇ (strcasecmp(optarg, "PEM") == 0) {
				convert_format = FMT_PEM;
				ਨਿੱਜੀ_ਕੁੰਜੀ_format = SSHKEY_ਨਿੱਜੀ_PEM;
				ਰੋਕੋ;
			}
			ਜੇ (strcasecmp(optarg, "hexdump") == 0) {
				convert_format = FMT_HEXDUMP;
				ਰੋਕੋ;
			}
			fatal("Unsupported conversion format \"%s\"", optarg);
		ਹਾਲਤ 'n':
			cert_principals = optarg;
			ਰੋਕੋ;
		ਹਾਲਤ 'o':
			/* no-op; new format is already the default */
			ਰੋਕੋ;
		ਹਾਲਤ 'p':
			change_passphrase = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'c':
			change_comment = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'f':
			ਜੇ (strlcpy(ਪਛਾਣ_ਤੱਤ_file, optarg,
			    ਆਕਾਰ(ਪਛਾਣ_ਤੱਤ_file)) >= ਆਕਾਰ(ਪਛਾਣ_ਤੱਤ_file))
				fatal("Identity filename too long");
			have_ਪਛਾਣ_ਤੱਤ = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'g':
			print_generic = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'K':
			download_sk = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'P':
			ਪਛਾਣ_ਤੱਤ_passphrase = optarg;
			ਰੋਕੋ;
		ਹਾਲਤ 'N':
			ਪਛਾਣ_ਤੱਤ_new_passphrase = optarg;
			ਰੋਕੋ;
		ਹਾਲਤ 'Q':
			check_krl = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'O':
			opts = xrecallocarray(opts, nopts, nopts + 1,
			    ਆਕਾਰ(*opts));
			opts[nopts++] = xstrdup(optarg);
			ਰੋਕੋ;
		ਹਾਲਤ 'Z':
			openssh_format_cipher = optarg;
			ਜੇ (cipher_by_name(openssh_format_cipher) == ਨਿਰਾ)
				fatal("Invalid OpenSSH-format cipher '%s'",
				    openssh_format_cipher);
			ਰੋਕੋ;
		ਹਾਲਤ 'C':
			ਪਛਾਣ_ਤੱਤ_comment = optarg;
			ਰੋਕੋ;
		ਹਾਲਤ 'q':
			quiet = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'e':
			/* export key */
			convert_ਮੰਜ਼ਿਲ = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'h':
			cert_ਕੁੰਜੀ_type = SSH2_CERT_TYPE_HOST;
			certflags_flags = 0;
			ਰੋਕੋ;
		ਹਾਲਤ 'k':
			gen_krl = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'i':
		ਹਾਲਤ 'X':
			/* import key */
			convert_from = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'y':
			print_ਜਨਤਕ = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 's':
			ca_ਕੁੰਜੀ_ਰਸਤਾ = optarg;
			ਰੋਕੋ;
		ਹਾਲਤ 't':
			ਕੁੰਜੀ_type_name = optarg;
			ਰੋਕੋ;
		ਹਾਲਤ 'D':
			pkcs11provider = optarg;
			ਰੋਕੋ;
		ਹਾਲਤ 'U':
			prefer_agent = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'u':
			update_krl = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'v':
			ਜੇ (log_level == SYSLOG_LEVEL_INFO)
				log_level = SYSLOG_LEVEL_DEBUG1;
			ਨਹੀਂਤਾਂ {
				ਜੇ (log_level >= SYSLOG_LEVEL_DEBUG1 &&
				    log_level < SYSLOG_LEVEL_DEBUG3)
					log_level++;
			}
			ਰੋਕੋ;
		ਹਾਲਤ 'r':
			rr_hostname = optarg;
			ਰੋਕੋ;
		ਹਾਲਤ 'a':
			ਗੇੜ = (ਪੂਰਨ)strtonum(optarg, 1, ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ, &errstr);
			ਜੇ (errstr)
				fatal("Invalid number: %s (%s)",
					optarg, errstr);
			ਰੋਕੋ;
		ਹਾਲਤ 'V':
			parse_cert_times(optarg);
			ਰੋਕੋ;
		ਹਾਲਤ 'Y':
			sign_op = optarg;
			ਰੋਕੋ;
		ਹਾਲਤ 'w':
			sk_provider = optarg;
			ਰੋਕੋ;
		ਹਾਲਤ 'z':
			errno = 0;
			ਜੇ (*optarg == '+') {
				cert_serial_autoinc = 1;
				optarg++;
			}
			cert_serial = strtoull(optarg, &ep, 10);
			ਜੇ (*optarg < '0' || *optarg > '9' || *ep != '\0' ||
			    (errno == ERANGE && cert_serial == ULLONG_MAX))
				fatal("Invalid serial number \"%s\"", optarg);
			ਰੋਕੋ;
		ਹਾਲਤ 'M':
			ਜੇ (strcmp(optarg, "generate") == 0)
				do_gen_candidates = 1;
			ਨਹੀਂਤਾਂ ਜੇ (strcmp(optarg, "screen") == 0)
				do_screen_candidates = 1;
			ਨਹੀਂਤਾਂ
				fatal("Unsupported moduli option %s", optarg);
			ਰੋਕੋ;
		ਮੂਲ:
			usage();
		}
	}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ ENABLE_SK_ਅੰਦਰੂਨੀ
	ਜੇ (sk_provider == ਨਿਰਾ)
		sk_provider = "internal";
#ਜੇ_ਅੰਤ

	/* reinit */
	log_init(argv[0], log_level, SYSLOG_FACILITY_USER, 1);

	argv += optind;
	argc -= optind;

	ਜੇ (sign_op != ਨਿਰਾ) {
		ਜੇ (strprefix(sign_op, "find-principals", 0) != ਨਿਰਾ) {
			ਜੇ (ca_ਕੁੰਜੀ_ਰਸਤਾ == ਨਿਰਾ) {
				error("Too few arguments for find-principals:"
				    "missing signature file");
				ਬਾਹਰ_ਨਿਕਲੋ(1);
			}
			ਜੇ (!have_ਪਛਾਣ_ਤੱਤ) {
				error("Too few arguments for find-principals:"
				    "missing allowed keys file");
				ਬਾਹਰ_ਨਿਕਲੋ(1);
			}
			ret = sig_ਲੱਭੋ_principals(ca_ਕੁੰਜੀ_ਰਸਤਾ, ਪਛਾਣ_ਤੱਤ_file,
			    opts, nopts);
			ਜਾਓ ਪੂਰਾ;
		} ਨਹੀਂਤਾਂ ਜੇ (strprefix(sign_op, "match-principals", 0) != ਨਿਰਾ) {
			ਜੇ (!have_ਪਛਾਣ_ਤੱਤ) {
				error("Too few arguments for match-principals:"
				    "missing allowed keys file");
				ਬਾਹਰ_ਨਿਕਲੋ(1);
			}
			ਜੇ (cert_ਕੁੰਜੀ_id == ਨਿਰਾ) {
				error("Too few arguments for match-principals: "
				    "missing principal ID");
				ਬਾਹਰ_ਨਿਕਲੋ(1);
			}
			ret = sig_ਮੇਲ_principals(ਪਛਾਣ_ਤੱਤ_file, cert_ਕੁੰਜੀ_id,
			    opts, nopts);
			ਜਾਓ ਪੂਰਾ;
		} ਨਹੀਂਤਾਂ ਜੇ (strprefix(sign_op, "sign", 0) != ਨਿਰਾ) {
			/* NB. cert_principals is actually namespace, via -n */
			ਜੇ (cert_principals == ਨਿਰਾ ||
			    *cert_principals == '\0') {
				error("Too few arguments for sign: "
				    "missing namespace");
				ਬਾਹਰ_ਨਿਕਲੋ(1);
			}
			ਜੇ (!have_ਪਛਾਣ_ਤੱਤ) {
				error("Too few arguments for sign: "
				    "missing key");
				ਬਾਹਰ_ਨਿਕਲੋ(1);
			}
			ret = sig_sign(ਪਛਾਣ_ਤੱਤ_file, cert_principals,
			    prefer_agent, argc, argv, opts, nopts);
			ਜਾਓ ਪੂਰਾ;
		} ਨਹੀਂਤਾਂ ਜੇ (strprefix(sign_op, "check-novalidate", 0) != ਨਿਰਾ) {
			/* NB. cert_principals is actually namespace, via -n */
			ਜੇ (cert_principals == ਨਿਰਾ ||
			    *cert_principals == '\0') {
				error("Too few arguments for check-novalidate: "
				    "missing namespace");
				ਬਾਹਰ_ਨਿਕਲੋ(1);
			}
			ਜੇ (ca_ਕੁੰਜੀ_ਰਸਤਾ == ਨਿਰਾ) {
				error("Too few arguments for check-novalidate: "
				    "missing signature file");
				ਬਾਹਰ_ਨਿਕਲੋ(1);
			}
			ret = sig_verify(ca_ਕੁੰਜੀ_ਰਸਤਾ, cert_principals,
			    ਨਿਰਾ, ਨਿਰਾ, ਨਿਰਾ, opts, nopts);
			ਜਾਓ ਪੂਰਾ;
		} ਨਹੀਂਤਾਂ ਜੇ (strprefix(sign_op, "verify", 0) != ਨਿਰਾ) {
			/* NB. cert_principals is actually namespace, via -n */
			ਜੇ (cert_principals == ਨਿਰਾ ||
			    *cert_principals == '\0') {
				error("Too few arguments for verify: "
				    "missing namespace");
				ਬਾਹਰ_ਨਿਕਲੋ(1);
			}
			ਜੇ (ca_ਕੁੰਜੀ_ਰਸਤਾ == ਨਿਰਾ) {
				error("Too few arguments for verify: "
				    "missing signature file");
				ਬਾਹਰ_ਨਿਕਲੋ(1);
			}
			ਜੇ (!have_ਪਛਾਣ_ਤੱਤ) {
				error("Too few arguments for sign: "
				    "missing allowed keys file");
				ਬਾਹਰ_ਨਿਕਲੋ(1);
			}
			ਜੇ (cert_ਕੁੰਜੀ_id == ਨਿਰਾ) {
				error("Too few arguments for verify: "
				    "missing principal identity");
				ਬਾਹਰ_ਨਿਕਲੋ(1);
			}
			ret = sig_verify(ca_ਕੁੰਜੀ_ਰਸਤਾ, cert_principals,
			    cert_ਕੁੰਜੀ_id, ਪਛਾਣ_ਤੱਤ_file, rr_hostname,
			    opts, nopts);
			ਜਾਓ ਪੂਰਾ;
		}
		error("Unsupported operation for -Y: \"%s\"", sign_op);
		usage();
		/* NOTREACHED */
	}

	ਜੇ (ca_ਕੁੰਜੀ_ਰਸਤਾ != ਨਿਰਾ) {
		ਜੇ (argc < 1 && !gen_krl) {
			error("Too few arguments.");
			usage();
		}
	} ਨਹੀਂਤਾਂ ਜੇ (argc > 0 && !gen_krl && !check_krl &&
	    !do_gen_candidates && !do_screen_candidates) {
		error("Too many arguments.");
		usage();
	}
	ਜੇ (change_passphrase && change_comment) {
		error("Can only have one of -p and -c.");
		usage();
	}
	ਜੇ (print_fingerprint && (delete_host || hash_hosts)) {
		error("Cannot use -l with -H or -R.");
		usage();
	}
	ਜੇ (gen_krl) {
		do_gen_krl(pw, update_krl, ca_ਕੁੰਜੀ_ਰਸਤਾ,
		    cert_serial, ਪਛਾਣ_ਤੱਤ_comment, argc, argv);
		ਜਾਓ ਪੂਰਾ;
	}
	ਜੇ (check_krl) {
		do_check_krl(pw, print_fingerprint, argc, argv);
		ਜਾਓ ਪੂਰਾ;
	}
	ਜੇ (ca_ਕੁੰਜੀ_ਰਸਤਾ != ਨਿਰਾ) {
		ਜੇ (cert_ਕੁੰਜੀ_id == ਨਿਰਾ)
			fatal("Must specify key id (-I) when certifying");
		ਜੇ (cert_principals == ਨਿਰਾ) {
			/*
			 * Ideally this would be a fatal(), but we need to
			 * be able to generate such certificates for testing
			 * even though they will be rejected.
			 */
			error("Warning: certificate will contain no "
			    "principals (-n)");
		}
		ਲਈ (i = 0; i < nopts; i++)
			ਜੋੜੋ_cert_option(opts[i]);
		do_ca_sign(pw, ca_ਕੁੰਜੀ_ਰਸਤਾ, prefer_agent,
		    cert_serial, cert_serial_autoinc, argc, argv);
		ਜਾਓ ਪੂਰਾ;
	}
	ਜੇ (show_cert)
		do_show_cert(pw);
	ਜੇ (delete_host || hash_hosts || ਲੱਭੋ_host) {
		do_ਗਿਆਤ_hosts(pw, rr_hostname, ਲੱਭੋ_host,
		    delete_host, hash_hosts);
	}
	ਜੇ (pkcs11provider != ਨਿਰਾ)
		do_download(pw);
	ਜੇ (download_sk) {
		ਲਈ (i = 0; i < nopts; i++) {
			ਜੇ ((p = strprefix(opts[i], "device=", 1)) != ਨਿਰਾ) {
				sk_device = xstrdup(p);
			} ਨਹੀਂਤਾਂ {
				fatal("Option \"%s\" is unsupported for "
				    "FIDO authenticator download", opts[i]);
			}
		}
		ret = do_download_sk(sk_provider, sk_device);
		ਜਾਓ ਪੂਰਾ;
	}
	ਜੇ (print_fingerprint || print_bubblebabble)
		do_fingerprint(pw);
	ਜੇ (change_passphrase)
		do_change_passphrase(pw, opts, nopts);
	ਜੇ (change_comment)
		do_change_comment(pw, ਪਛਾਣ_ਤੱਤ_comment);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	ਜੇ (convert_ਮੰਜ਼ਿਲ) {
		do_convert_ਮੰਜ਼ਿਲ(pw);
		ਜਾਓ ਪੂਰਾ;
	}
	ਜੇ (convert_from) {
		do_convert_from(pw);
		ਜਾਓ ਪੂਰਾ;
	}
#ਨਹੀਂਤਾਂ /* WITH_OPENSSL */
	ਜੇ (convert_ਮੰਜ਼ਿਲ || convert_from)
		fatal("key conversion disabled at compile time");
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
	ਜੇ (print_ਜਨਤਕ)
		do_print_ਜਨਤਕ(pw);
	ਜੇ (rr_hostname != ਨਿਰਾ) {
		ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ n = 0;

		ਜੇ (have_ਪਛਾਣ_ਤੱਤ) {
			n = do_print_resource_ਰਿਕਾਰਡ(pw, ਪਛਾਣ_ਤੱਤ_file,
			    rr_hostname, print_generic, opts, nopts);
			ਜੇ (n == 0)
				fatal("%s: %s", ਪਛਾਣ_ਤੱਤ_file, strerror(errno));
			ਬਾਹਰ_ਨਿਕਲੋ(0);
		} ਨਹੀਂਤਾਂ {

			n += do_print_resource_ਰਿਕਾਰਡ(pw,
			    ਰਸਤਾ_HOST_RSA_ਕੁੰਜੀ_FILE, rr_hostname,
			    print_generic, opts, nopts);
			n += do_print_resource_ਰਿਕਾਰਡ(pw,
			    ਰਸਤਾ_HOST_ECDSA_ਕੁੰਜੀ_FILE, rr_hostname,
			    print_generic, opts, nopts);
			n += do_print_resource_ਰਿਕਾਰਡ(pw,
			    ਰਸਤਾ_HOST_ED25519_ਕੁੰਜੀ_FILE, rr_hostname,
			    print_generic, opts, nopts);
			ਜੇ (n == 0)
				fatal("no keys found.");
			ਬਾਹਰ_ਨਿਕਲੋ(0);
		}
	}

	ਜੇ (do_gen_candidates || do_screen_candidates) {
		ਜੇ (argc <= 0)
			fatal("No output file specified");
		ਨਹੀਂਤਾਂ ਜੇ (argc > 1)
			fatal("Too many output files specified");
	}
	ਜੇ (do_gen_candidates) {
		do_moduli_gen(argv[0], opts, nopts);
		ਜਾਓ ਪੂਰਾ;
	}
	ਜੇ (do_screen_candidates) {
		do_moduli_screen(argv[0], opts, nopts);
		ਜਾਓ ਪੂਰਾ;
	}

	ਜੇ (gen_all_hostkeys) {
		do_gen_all_hostkeys(pw);
		ਜਾਓ ਪੂਰਾ;
	}

	ਜੇ (ਕੁੰਜੀ_type_name == ਨਿਰਾ)
		ਕੁੰਜੀ_type_name = DEFAULT_ਕੁੰਜੀ_TYPE_NAME;

	type = sshkey_type_from_shortname(ਕੁੰਜੀ_type_name);
	type_ਬਿੱਟ_valid(type, ਕੁੰਜੀ_type_name, &ਬਿੱਟ);

	ਜੇ (!quiet)
		ਲਿਖੋ("Generating public/private %s key pair.\n",
		    ਕੁੰਜੀ_type_name);
	ਚੋਣ (type) {
	ਹਾਲਤ ਕੁੰਜੀ_ECDSA_SK:
	ਹਾਲਤ ਕੁੰਜੀ_ED25519_SK:
		ਲਈ (i = 0; i < nopts; i++) {
			ਜੇ (strcasecmp(opts[i], "no-touch-required") == 0) {
				sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
			} ਨਹੀਂਤਾਂ ਜੇ (strcasecmp(opts[i], "verify-required") == 0) {
				sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
			} ਨਹੀਂਤਾਂ ਜੇ (strcasecmp(opts[i], "resident") == 0) {
				sk_flags |= SSH_SK_RESIDENT_ਕੁੰਜੀ;
			} ਨਹੀਂਤਾਂ ਜੇ ((p = strprefix(opts[i], "device=", 1))
			    != ਨਿਰਾ ) {
				sk_device = xstrdup(p);
			} ਨਹੀਂਤਾਂ ਜੇ ((p = strprefix(opts[i], "user=", 1))
			    != ਨਿਰਾ) {
				sk_user = xstrdup(p);
			} ਨਹੀਂਤਾਂ ਜੇ ((p = strprefix(opts[i], "challenge=", 1))
			    != ਨਿਰਾ) {
				ਜੇ ((r = sshbuf_ਲੱਦੋ_file(p,
				    &challenge)) != 0) {
					fatal_r(r, "Unable to load FIDO "
					    "enrollment challenge \"%s\"", p);
				}
			} ਨਹੀਂਤਾਂ ਜੇ (strncasecmp(opts[i],
			    "write-attestation=", 18) == 0) {
				sk_attestation_ਰਸਤਾ = opts[i] + 18;
			} ਨਹੀਂਤਾਂ ਜੇ (strncasecmp(opts[i],
			    "application=", 12) == 0) {
				sk_application = xstrdup(opts[i] + 12);
				ਜੇ (ਲੜੀ_ਤੁਲਨਾ(sk_application, "ssh:", 4) != 0) {
					fatal("FIDO application string must "
					    "begin with \"ssh:\"");
				}
			} ਨਹੀਂਤਾਂ {
				fatal("Option \"%s\" is unsupported for "
				    "FIDO authenticator enrollment", opts[i]);
			}
		}
		ਜੇ ((attest = sshbuf_new()) == ਨਿਰਾ)
			fatal("sshbuf_new failed");
		r = 0;
		ਲਈ (i = 0 ;;) {
			ਜੇ (!quiet) {
				ਲਿਖੋ("You may need to touch your "
				    "authenticator%s to authorize key "
				    "generation.\n",
				    r == 0 ? "" : " again");
			}
			fflush(stdout);
			r = sshsk_enroll(type, sk_provider, sk_device,
			    sk_application == ਨਿਰਾ ? "ssh:" : sk_application,
			    sk_user, sk_flags, passphrase, challenge,
			    &ਨਿਜੀ, attest);
			ਜੇ (r == 0)
				ਰੋਕੋ;
			ਜੇ (r == SSH_ERR_ਕੁੰਜੀ_BAD_PERMISSIONS &&
			    (sk_flags & SSH_SK_RESIDENT_ਕੁੰਜੀ) != 0 &&
			    (sk_flags & SSH_SK_FORCE_OPERATION) == 0 &&
			    confirm_sk_overwrite(sk_application, sk_user)) {
				sk_flags |= SSH_SK_FORCE_OPERATION;
				ਜਾਰੀ;
			}
			ਜੇ (r != SSH_ERR_ਕੁੰਜੀ_WRONG_PASSPHRASE)
				fatal_r(r, "Key enrollment failed");
			ਨਹੀਂਤਾਂ ਜੇ (passphrase != ਨਿਰਾ) {
				error("PIN incorrect");
				freezero(passphrase, ਲੜੀ_ਲੰਬਾਈ(passphrase));
				passphrase = ਨਿਰਾ;
			}
			ਜੇ (++i >= 3)
				fatal("Too many incorrect PINs");
			passphrase = read_passphrase("Enter PIN for "
			    "authenticator: ", RP_ALLOW_STDIN);
		}
		ਜੇ (passphrase != ਨਿਰਾ) {
			freezero(passphrase, ਲੜੀ_ਲੰਬਾਈ(passphrase));
			passphrase = ਨਿਰਾ;
		}
		ਰੋਕੋ;
	ਮੂਲ:
		ਜੇ ((r = sshkey_generate(type, ਬਿੱਟ, &ਨਿਜੀ)) != 0)
			fatal("sshkey_generate failed");
		ਰੋਕੋ;
	}
	ਜੇ ((r = sshkey_from_ਨਿੱਜੀ(ਨਿਜੀ, &ਜਨਤਕ)) != 0)
		fatal_r(r, "sshkey_from_private");

	ਜੇ (!have_ਪਛਾਣ_ਤੱਤ)
		ask_filename(pw, "Enter file in which to save the key");

	/* Create ~/.ssh directory if it doesn't already exist. */
	hostfile_create_user_ssh_dir(ਪਛਾਣ_ਤੱਤ_file, !quiet);

	/* If the file already exists, ask the user to confirm. */
	ਜੇ (!confirm_overwrite(ਪਛਾਣ_ਤੱਤ_file))
		ਬਾਹਰ_ਨਿਕਲੋ(1);

	/* Determine the passphrase for the private key */
	passphrase = ਨਿੱਜੀ_ਕੁੰਜੀ_passphrase(ਪਛਾਣ_ਤੱਤ_file);
	ਜੇ (ਪਛਾਣ_ਤੱਤ_comment) {
		strlcpy(comment, ਪਛਾਣ_ਤੱਤ_comment, ਆਕਾਰ(comment));
	} ਨਹੀਂਤਾਂ {
		/* Create default comment field for the passphrase. */
		snprintf(comment, ਆਕਾਰ comment, "%s@%s", pw->pw_name, hostname);
	}



	/* Save the key with the given passphrase and comment. */
	ਜੇ ((r = sshkey_save_ਨਿੱਜੀ(ਨਿਜੀ, ਪਛਾਣ_ਤੱਤ_file, passphrase,
	    comment, ਨਿੱਜੀ_ਕੁੰਜੀ_format, openssh_format_cipher, ਗੇੜ)) != 0) {
		error_r(r, "Saving key \"%s\" failed", ਪਛਾਣ_ਤੱਤ_file);
		freezero(passphrase, ਲੜੀ_ਲੰਬਾਈ(passphrase));
		ਬਾਹਰ_ਨਿਕਲੋ(1);
	}
	freezero(passphrase, ਲੜੀ_ਲੰਬਾਈ(passphrase));
	sshkey_free(ਨਿਜੀ);

	ਜੇ (!quiet) {
		ਲਿਖੋ("Your identification has been saved in %s\n",
		    ਪਛਾਣ_ਤੱਤ_file);
	}

	strlcat(ਪਛਾਣ_ਤੱਤ_file, ".pub", ਆਕਾਰ(ਪਛਾਣ_ਤੱਤ_file));
	ਜੇ ((r = sshkey_save_ਜਨਤਕ(ਜਨਤਕ, ਪਛਾਣ_ਤੱਤ_file, comment)) != 0)
		fatal_r(r, "Unable to save public key to %s", ਪਛਾਣ_ਤੱਤ_file);

	ਜੇ (!quiet) {
		fp = sshkey_fingerprint(ਜਨਤਕ, fingerprint_hash,
		    SSH_FP_DEFAULT);
		ra = sshkey_fingerprint(ਜਨਤਕ, fingerprint_hash,
		    SSH_FP_RANDOMART);
		ਜੇ (fp == ਨਿਰਾ || ra == ਨਿਰਾ)
			fatal("sshkey_fingerprint failed");
		ਲਿਖੋ("Your public key has been saved in %s\n",
		    ਪਛਾਣ_ਤੱਤ_file);
		ਲਿਖੋ("The key fingerprint is:\n");
		ਲਿਖੋ("%s %s\n", fp, comment);
		ਲਿਖੋ("The key's randomart image is:\n");
		ਲਿਖੋ("%s\n", ra);
		ਮੁਕਤ(ra);
		ਮੁਕਤ(fp);
	}

	ਜੇ (sk_attestation_ਰਸਤਾ != ਨਿਰਾ)
		save_attestation(attest, sk_attestation_ਰਸਤਾ);

 ਪੂਰਾ:
	sshbuf_free(attest);
	sshkey_free(ਜਨਤਕ);
	pwfree(pw);
	ਬਾਹਰ_ਨਿਕਲੋ(ret);
}
