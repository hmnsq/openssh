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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <sys/stat.h>

#ifdef WITH_OPENSSL
#अन्तर्भाव "openbsd-compat/openssl-compat.h"
#अन्तर्भाव <openssl/bn.h>
#अन्तर्भाव <openssl/evp.h>
#अन्तर्भाव <openssl/pem.h>
#endif

#अन्तर्भाव <stdint.h>
#अन्तर्भाव <errno.h>
#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <netdb.h>
#अन्तर्भाव <paths.h>
#अन्तर्भाव <pwd.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <limits.h>
#अन्तर्भाव <locale.h>
#अन्तर्भाव <time.h>

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "authfile.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "pathnames.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "match.h"
#अन्तर्भाव "hostfile.h"
#अन्तर्भाव "dns.h"
#अन्तर्भाव "ssh.h"
#अन्तर्भाव "ssh2.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "atomicio.h"
#अन्तर्भाव "krl.h"
#अन्तर्भाव "digest.h"
#अन्तर्भाव "utf8.h"
#अन्तर्भाव "authfd.h"
#अन्तर्भाव "sshsig.h"
#अन्तर्भाव "ssh-sk.h"
#अन्तर्भाव "sk-api.h" /* XXX for SSH_SK_USER_PRESENCE_REQD; remove */
#अन्तर्भाव "cipher.h"

#ifdef ENABLE_PKCS11
#अन्तर्भाव "ssh-pkcs11.h"
#endif

#define DEFAULT_साँचो_TYPE_NAME "ed25519"

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

#define साँचो_COMMENT_MAX		(NI_MAXHOST + 1024)

स्थिर पूर्णाङ्क quiet = 0;

/* Flag indicating that we just want to see the key fingerprint */
स्थिर पूर्णाङ्क print_fingerprint = 0;
स्थिर पूर्णाङ्क print_bubblebabble = 0;

/* Hash algorithm to use for fingerprints. */
स्थिर पूर्णाङ्क fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* The identity file name, given on the command line or entered by the user. */
स्थिर वर्ण identity_file[PATH_MAX];
स्थिर पूर्णाङ्क have_identity = 0;

/* This is set to the passphrase if given on the command line. */
स्थिर वर्ण *identity_passphrase = रिक्त;

/* This is set to the new passphrase if given on the command line. */
स्थिर वर्ण *identity_new_passphrase = रिक्त;

/* Key type when certifying */
स्थिर u_int cert_साँचो_type = SSH2_CERT_TYPE_USER;

/* "key ID" of signed key */
स्थिर वर्ण *cert_साँचो_id = रिक्त;

/* Comma-separated list of principal names for certifying keys */
स्थिर वर्ण *cert_principals = रिक्त;

/* Validity period for certificates */
स्थिर uint64_t cert_valid_from = 0;
स्थिर uint64_t cert_valid_to = ~0ULL;

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
स्थिर uint32_t certflags_flags = CERTOPT_DEFAULT;
स्थिर वर्ण *certflags_command = रिक्त;
स्थिर वर्ण *certflags_src_addr = रिक्त;

/* Arbitrary extensions specified by user */
संरचना cert_ext {
	वर्ण *साँचो;
	वर्ण *val;
	पूर्णाङ्क crit;
};
स्थिर संरचना cert_ext *cert_ext;
स्थिर माप_प्रकार ncert_ext;

/* Conversion to/from various formats */
गणना {
	FMT_RFC4716,
	FMT_PKCS8,
	FMT_PEM,
	FMT_HEXDUMP
} convert_format = FMT_RFC4716;

स्थिर वर्ण *साँचो_type_name = रिक्त;

/* Load key from this PKCS#11 provider */
स्थिर वर्ण *pkcs11provider = रिक्त;

/* FIDO/U2F provider to use */
स्थिर वर्ण *sk_provider = रिक्त;

/* Format for writing private keys */
स्थिर पूर्णाङ्क private_साँचो_format = SSHKEY_PRIVATE_OPENSSH;

/* Cipher for new-format private keys */
स्थिर वर्ण *openssh_format_cipher = रिक्त;

/* Number of KDF rounds to derive new format keys. */
स्थिर पूर्णाङ्क rounds = 0;

/* argv0 */
बाह्य वर्ण *__progname;

स्थिर वर्ण hostname[NI_MAXHOST];

#ifdef WITH_OPENSSL
/* moduli.c */
पूर्णाङ्क gen_candidates(खाता *, uint32_t, BIGNUM *);
पूर्णाङ्क अविभाज्य_test(खाता *, खाता *, uint32_t, uint32_t, वर्ण *, अचिन्हित दीर्घ,
    अचिन्हित दीर्घ);
#endif

स्थिर शून्य
type_bits_valid(पूर्णाङ्क type, अचर वर्ण *name, uint32_t *bitsp)
{
	यदि (type == साँचो_UNSPEC)
		fatal("unknown key type %s", साँचो_type_name);
	यदि (*bitsp == 0) {
#ifdef WITH_OPENSSL
		पूर्णाङ्क nid;

		विकल्प(type) {
		पक्ष साँचो_ECDSA:
			यदि (name != रिक्त &&
			    (nid = sshkey_ecdsa_nid_from_name(name)) > 0)
				*bitsp = sshkey_curve_nid_to_bits(nid);
			यदि (*bitsp == 0)
				*bitsp = DEFAULT_BITS_ECDSA;
			रोक;
		पक्ष साँचो_RSA:
			*bitsp = DEFAULT_BITS;
			रोक;
		}
#endif
	}
#ifdef WITH_OPENSSL
	विकल्प (type) {
	पक्ष साँचो_RSA:
		यदि (*bitsp < SSH_RSA_MINIMUM_MODULUS_SIZE)
			fatal("Invalid RSA key length: minimum is %d bits",
			    SSH_RSA_MINIMUM_MODULUS_SIZE);
		अन्यथा यदि (*bitsp > OPENSSL_RSA_MAX_MODULUS_BITS)
			fatal("Invalid RSA key length: maximum is %d bits",
			    OPENSSL_RSA_MAX_MODULUS_BITS);
		रोक;
	पक्ष साँचो_ECDSA:
		यदि (sshkey_ecdsa_bits_to_nid(*bitsp) == -1)
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
स्थिर पूर्णाङ्क
confirm_overwrite(अचर वर्ण *filename)
{
	वर्ण yesno[3];
	संरचना stat st;

	यदि (stat(filename, &st) != 0)
		फर्काऊ 1;
	म_लिखो("%s already exists.\n", filename);
	म_लिखो("Overwrite (y/n)? ");
	ख_साफ(मानक_निकास);
	यदि (ख_माला_लो(yesno, परिमाण(yesno), मानक_निवेश) == रिक्त)
		फर्काऊ 0;
	यदि (yesno[0] != 'y' && yesno[0] != 'Y')
		फर्काऊ 0;
	फर्काऊ 1;
}

स्थिर शून्य
ask_filename(संरचना passwd *pw, अचर वर्ण *prompt)
{
	वर्ण buf[1024];
	वर्ण *name = रिक्त;

	यदि (साँचो_type_name == रिक्त)
		name = _PATH_SSH_CLIENT_ID_ED25519;
	अन्यथा {
		विकल्प (sshkey_type_from_shortname(साँचो_type_name)) {
		पक्ष साँचो_ECDSA_CERT:
		पक्ष साँचो_ECDSA:
			name = _PATH_SSH_CLIENT_ID_ECDSA;
			रोक;
		पक्ष साँचो_ECDSA_SK_CERT:
		पक्ष साँचो_ECDSA_SK:
			name = _PATH_SSH_CLIENT_ID_ECDSA_SK;
			रोक;
		पक्ष साँचो_RSA_CERT:
		पक्ष साँचो_RSA:
			name = _PATH_SSH_CLIENT_ID_RSA;
			रोक;
		पक्ष साँचो_ED25519:
		पक्ष साँचो_ED25519_CERT:
			name = _PATH_SSH_CLIENT_ID_ED25519;
			रोक;
		पक्ष साँचो_ED25519_SK:
		पक्ष साँचो_ED25519_SK_CERT:
			name = _PATH_SSH_CLIENT_ID_ED25519_SK;
			रोक;
		पक्ष साँचो_MLDSA44_ED25519:
		पक्ष साँचो_MLDSA44_ED25519_CERT:
			name = _PATH_SSH_CLIENT_ID_MLDSA44_ED25519;
			रोक;
		स्वभाव:
			fatal("bad key type");
		}
	}
	snprintf(identity_file, परिमाण(identity_file),
	    "%s/%s", pw->pw_dir, name);
	म_लिखो("%s (%s): ", prompt, identity_file);
	ख_साफ(मानक_निकास);
	यदि (ख_माला_लो(buf, परिमाण(buf), मानक_निवेश) == रिक्त)
		निकास(1);
	buf[म_खोज(buf, "\n")] = '\0';
	यदि (म_भेद(buf, "") != 0)
		strlcpy(identity_file, buf, परिमाण(identity_file));
	have_identity = 1;
}

स्थिर संरचना sshkey *
load_identity(अचर वर्ण *filename, वर्ण **commentp)
{
	वर्ण *prompt, *pass;
	संरचना sshkey *prv;
	पूर्णाङ्क r;

	यदि (commentp != रिक्त)
		*commentp = रिक्त;
	यदि ((r = sshkey_load_private(filename, "", &prv, commentp)) == 0)
		फर्काऊ prv;
	यदि (r != SSH_ERR_साँचो_WRONG_PASSPHRASE)
		fatal_r(r, "Load key \"%s\"", filename);
	यदि (identity_passphrase)
		pass = xstrdup(identity_passphrase);
	अन्यथा {
		xasprintf(&prompt, "Enter passphrase for \"%s\": ", filename);
		pass = read_passphrase(prompt, RP_ALLOW_STDIN);
		मुक्त(prompt);
	}
	r = sshkey_load_private(filename, pass, &prv, commentp);
	freezero(pass, म_माप(pass));
	यदि (r != 0)
		fatal_r(r, "Load key \"%s\"", filename);
	फर्काऊ prv;
}

#define SSH_COM_PUBLIC_BEGIN		"---- BEGIN SSH2 PUBLIC KEY ----"
#define SSH_COM_PUBLIC_END		"---- END SSH2 PUBLIC KEY ----"
#define SSH_COM_PRIVATE_BEGIN		"---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----"
#define	SSH_COM_PRIVATE_साँचो_MAGIC	0x3f6ff9eb

#ifdef WITH_OPENSSL
स्थिर शून्य
do_convert_to_ssh2(संरचना passwd *pw, संरचना sshkey *k)
{
	संरचना sshbuf *b;
	वर्ण comment[61], *b64;
	पूर्णाङ्क r;

	यदि ((b = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshkey_putb(k, b)) != 0)
		fatal_fr(r, "put key");
	यदि ((b64 = sshbuf_dtob64_string(b, 1)) == रिक्त)
		fatal_f("sshbuf_dtob64_string failed");

	/* Comment + surrounds must fit into 72 chars (RFC 4716 sec 3.3) */
	snprintf(comment, परिमाण(comment),
	    "%u-bit %s, converted by %s@%s from OpenSSH",
	    sshkey_size(k), sshkey_type(k),
	    pw->pw_name, hostname);

	sshkey_free(k);
	sshbuf_free(b);

	ख_लिखो(मानक_निकास, "%s\n", SSH_COM_PUBLIC_BEGIN);
	ख_लिखो(मानक_निकास, "Comment: \"%s\"\n%s", comment, b64);
	ख_लिखो(मानक_निकास, "%s\n", SSH_COM_PUBLIC_END);
	मुक्त(b64);
}

स्थिर शून्य
do_convert_to_pkcs8(संरचना sshkey *k)
{
	विकल्प (sshkey_type_plain(k->type)) {
	पक्ष साँचो_RSA:
		यदि (!PEM_write_RSA_PUBKEY(मानक_निकास,
		    EVP_PKEY_get0_RSA(k->pkey)))
			fatal("PEM_write_RSA_PUBKEY failed");
		रोक;
	पक्ष साँचो_ECDSA:
		यदि (!PEM_write_EC_PUBKEY(मानक_निकास,
		    EVP_PKEY_get0_EC_साँचो(k->pkey)))
			fatal("PEM_write_EC_PUBKEY failed");
		रोक;
	स्वभाव:
		fatal_f("unsupported key type %s", sshkey_type(k));
	}
}

स्थिर शून्य
do_convert_to_pem(संरचना sshkey *k)
{
	विकल्प (sshkey_type_plain(k->type)) {
	पक्ष साँचो_RSA:
		यदि (!PEM_write_RSAPublic_साँचो(मानक_निकास,
		    EVP_PKEY_get0_RSA(k->pkey)))
			fatal("PEM_write_RSAPublicKey failed");
		रोक;
	पक्ष साँचो_ECDSA:
		यदि (!PEM_write_EC_PUBKEY(मानक_निकास,
		    EVP_PKEY_get0_EC_साँचो(k->pkey)))
			fatal("PEM_write_EC_PUBKEY failed");
		रोक;
	स्वभाव:
		fatal_f("unsupported key type %s", sshkey_type(k));
	}
}

स्थिर शून्य
do_convert_to_hexdump(संरचना sshkey *k)
{
	संरचना sshbuf *b;
	पूर्णाङ्क r;

	यदि ((b = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	/* pubkey */
	यदि ((r = sshkey_putb(k, b)) != 0)
		fatal_fr(r, "serialise private");
	म_लिखो("Public %s key:\n", sshkey_type(k));
	sshbuf_dump(b, मानक_निकास);
	sshbuf_reset(b);
	यदि ((r = sshkey_private_serialize(k, b)) != 0) {
		debug_fr(r, "serialise private");
		गच्छ out;
	}
	म_लिखो("\nPrivate %s key:\n", sshkey_type(k));
	sshbuf_dump(b, मानक_निकास);
 out:
	sshbuf_free(b);
}

स्थिर शून्य
do_convert_to(संरचना passwd *pw)
{
	संरचना sshkey *k = रिक्त;
	संरचना stat st;
	पूर्णाङ्क r;

	यदि (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	यदि (stat(identity_file, &st) == -1)
		fatal("%s: %s: %s", __progname, identity_file, म_त्रुटि(त्रुटि_सं));

	/* If we're trying to hexdump, then prefer the private key */
	यदि (convert_format == FMT_HEXDUMP) {
		यदि ((r = sshkey_load_private(identity_file,
		    रिक्त, &k, रिक्त)) != 0 &&
		    r == SSH_ERR_साँचो_WRONG_PASSPHRASE)
			k = load_identity(identity_file, रिक्त);
	}
	यदि (k == रिक्त && (r = sshkey_load_public(identity_file, &k, रिक्त)) != 0)
		k = load_identity(identity_file, रिक्त);

	विकल्प (convert_format) {
	पक्ष FMT_RFC4716:
		do_convert_to_ssh2(pw, k);
		रोक;
	पक्ष FMT_PKCS8:
		do_convert_to_pkcs8(k);
		रोक;
	पक्ष FMT_PEM:
		do_convert_to_pem(k);
		रोक;
	पक्ष FMT_HEXDUMP:
		do_convert_to_hexdump(k);
		रोक;
	स्वभाव:
		fatal_f("unknown key format %d", convert_format);
	}
}

/*
 * This is almost exactly the bignum1 encoding, but with 32 bit for length
 * instead of 16.
 */
स्थिर शून्य
buffer_get_bignum_bits(संरचना sshbuf *b, BIGNUM *मान)
{
	u_int bytes, bignum_bits;
	पूर्णाङ्क r;

	यदि ((r = sshbuf_get_u32(b, &bignum_bits)) != 0)
		fatal_fr(r, "parse");
	bytes = (bignum_bits + 7) / 8;
	यदि (sshbuf_len(b) < bytes)
		fatal_f("input buffer too small: need %d have %zu",
		    bytes, sshbuf_len(b));
	यदि (BN_bin2bn(sshbuf_ptr(b), bytes, मान) == रिक्त)
		fatal_f("BN_bin2bn failed");
	यदि ((r = sshbuf_consume(b, bytes)) != 0)
		fatal_fr(r, "consume");
}

स्थिर संरचना sshkey *
do_convert_private_ssh2(संरचना sshbuf *b)
{
	संरचना sshkey *साँचो = रिक्त;
	वर्ण *type, *cipher;
	अचर वर्ण *alg = रिक्त;
	u_char e1, e2, e3, *sig = रिक्त, data[] = "abcde12345";
	पूर्णाङ्क r, rlen, ktype;
	u_int magic, i1, i2, i3, i4;
	माप_प्रकार slen;
	u_long e;
	BIGNUM *rsa_n = रिक्त, *rsa_e = रिक्त, *rsa_d = रिक्त;
	BIGNUM *rsa_p = रिक्त, *rsa_q = रिक्त, *rsa_iqmp = रिक्त;
	BIGNUM *rsa_dmp1 = रिक्त, *rsa_dmq1 = रिक्त;
	RSA *rsa = रिक्त;

	यदि ((r = sshbuf_get_u32(b, &magic)) != 0)
		fatal_fr(r, "parse magic");

	यदि (magic != SSH_COM_PRIVATE_साँचो_MAGIC) {
		error("bad magic 0x%x != 0x%x", magic,
		    SSH_COM_PRIVATE_साँचो_MAGIC);
		फर्काऊ रिक्त;
	}
	यदि ((r = sshbuf_get_u32(b, &i1)) != 0 ||
	    (r = sshbuf_get_cstring(b, &type, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(b, &cipher, रिक्त)) != 0 ||
	    (r = sshbuf_get_u32(b, &i2)) != 0 ||
	    (r = sshbuf_get_u32(b, &i3)) != 0 ||
	    (r = sshbuf_get_u32(b, &i4)) != 0)
		fatal_fr(r, "parse");
	debug("ignore (%d %d %d %d)", i1, i2, i3, i4);
	यदि (म_भेद(cipher, "none") != 0) {
		error("unsupported cipher %s", cipher);
		मुक्त(cipher);
		मुक्त(type);
		फर्काऊ रिक्त;
	}
	मुक्त(cipher);

	यदि (म_माला(type, "rsa")) {
		ktype = साँचो_RSA;
	} अन्यथा {
		मुक्त(type);
		फर्काऊ रिक्त;
	}
	यदि ((साँचो = sshkey_new(ktype)) == रिक्त)
		fatal("sshkey_new failed");
	मुक्त(type);

	विकल्प (साँचो->type) {
	पक्ष साँचो_RSA:
		यदि ((r = sshbuf_get_u8(b, &e1)) != 0 ||
		    (e1 < 30 && (r = sshbuf_get_u8(b, &e2)) != 0) ||
		    (e1 < 30 && (r = sshbuf_get_u8(b, &e3)) != 0))
			fatal_fr(r, "parse RSA");
		e = e1;
		debug("e %lx", e);
		यदि (e < 30) {
			e <<= 8;
			e += e2;
			debug("e %lx", e);
			e <<= 8;
			e += e3;
			debug("e %lx", e);
		}
		यदि ((rsa_e = BN_new()) == रिक्त)
			fatal_f("BN_new");
		यदि (!BN_set_word(rsa_e, e)) {
			BN_clear_free(rsa_e);
			sshkey_free(साँचो);
			फर्काऊ रिक्त;
		}
		यदि ((rsa_n = BN_new()) == रिक्त ||
		    (rsa_d = BN_new()) == रिक्त ||
		    (rsa_p = BN_new()) == रिक्त ||
		    (rsa_q = BN_new()) == रिक्त ||
		    (rsa_iqmp = BN_new()) == रिक्त)
			fatal_f("BN_new");
		buffer_get_bignum_bits(b, rsa_d);
		buffer_get_bignum_bits(b, rsa_n);
		buffer_get_bignum_bits(b, rsa_iqmp);
		buffer_get_bignum_bits(b, rsa_q);
		buffer_get_bignum_bits(b, rsa_p);
		यदि ((r = ssh_rsa_complete_crt_parameters(rsa_d, rsa_p, rsa_q,
		    rsa_iqmp, &rsa_dmp1, &rsa_dmq1)) != 0)
			fatal_fr(r, "generate RSA CRT parameters");
		EVP_PKEY_free(साँचो->pkey);
		यदि ((साँचो->pkey = EVP_PKEY_new()) == रिक्त)
			fatal_f("EVP_PKEY_new failed");
		यदि ((rsa = RSA_new()) == रिक्त)
			fatal_f("RSA_new failed");
		यदि (!RSA_set0_साँचो(rsa, rsa_n, rsa_e, rsa_d))
			fatal_f("RSA_set0_key failed");
		rsa_n = rsa_e = rsa_d = रिक्त; /* transferred */
		यदि (!RSA_set0_factors(rsa, rsa_p, rsa_q))
			fatal_f("RSA_set0_factors failed");
		rsa_p = rsa_q = रिक्त; /* transferred */
		यदि (RSA_set0_crt_params(rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp) != 1)
			fatal_f("RSA_set0_crt_params failed");
		rsa_dmp1 = rsa_dmq1 = rsa_iqmp = रिक्त;
		यदि (EVP_PKEY_set1_RSA(साँचो->pkey, rsa) != 1)
			fatal_f("EVP_PKEY_set1_RSA failed");
		RSA_free(rsa);
		alg = "rsa-sha2-256";
		रोक;
	}
	rlen = sshbuf_len(b);
	यदि (rlen != 0)
		error_f("remaining bytes in key blob %d", rlen);

	/* try the key */
	यदि ((r = sshkey_sign(साँचो, &sig, &slen, data, परिमाण(data),
	    alg, रिक्त, रिक्त, 0)) != 0)
		error_fr(r, "signing with converted key failed");
	अन्यथा यदि ((r = sshkey_verify(साँचो, sig, slen, data, परिमाण(data),
	    alg, 0, रिक्त)) != 0)
		error_fr(r, "verification with converted key failed");
	यदि (r != 0) {
		sshkey_free(साँचो);
		मुक्त(sig);
		फर्काऊ रिक्त;
	}
	मुक्त(sig);
	फर्काऊ साँचो;
}

स्थिर पूर्णाङ्क
get_पङ्क्ति(खाता *fp, वर्ण *पङ्क्ति, माप_प्रकार len)
{
	पूर्णाङ्क c;
	माप_प्रकार pos = 0;

	पङ्क्ति[0] = '\0';
	जबसम्म ((c = ख_अक्षर_लो(fp)) != खातापूर्ण) {
		यदि (pos >= len - 1)
			fatal("input line too long.");
		विकल्प (c) {
		पक्ष '\r':
			c = ख_अक्षर_लो(fp);
			यदि (c != खातापूर्ण && c != '\n' && अक्षर_वापस(c, fp) == खातापूर्ण)
				fatal("unget: %s", म_त्रुटि(त्रुटि_सं));
			फर्काऊ pos;
		पक्ष '\n':
			फर्काऊ pos;
		}
		पङ्क्ति[pos++] = c;
		पङ्क्ति[pos] = '\0';
	}
	/* We reached EOF */
	फर्काऊ -1;
}

स्थिर शून्य
do_convert_from_ssh2(संरचना passwd *pw, संरचना sshkey **k, पूर्णाङ्क *गुप्त)
{
	पूर्णाङ्क r, blen, escaped = 0;
	u_int len;
	वर्ण पङ्क्ति[1024];
	संरचना sshbuf *buf;
	वर्ण encoded[8096];
	खाता *fp;

	यदि ((buf = sshbuf_new()) == रिक्त)
		fatal("sshbuf_new failed");
	यदि ((fp = ख_खोलो(identity_file, "r")) == रिक्त)
		fatal("%s: %s: %s", __progname, identity_file, म_त्रुटि(त्रुटि_सं));
	encoded[0] = '\0';
	जबसम्म ((blen = get_पङ्क्ति(fp, पङ्क्ति, परिमाण(पङ्क्ति))) != -1) {
		यदि (blen > 0 && पङ्क्ति[blen - 1] == '\\')
			escaped++;
		यदि (म_भेदन(पङ्क्ति, "----", 4) == 0 ||
		    म_माला(पङ्क्ति, ": ") != रिक्त) {
			यदि (म_माला(पङ्क्ति, SSH_COM_PRIVATE_BEGIN) != रिक्त)
				*गुप्त = 1;
			यदि (म_माला(पङ्क्ति, " END ") != रिक्त) {
				रोक;
			}
			/* fprintf(stderr, "ignore: %s", line); */
			जारी;
		}
		यदि (escaped) {
			escaped--;
			/* fprintf(stderr, "escaped: %s", line); */
			जारी;
		}
		strlcat(encoded, पङ्क्ति, परिमाण(encoded));
	}
	len = म_माप(encoded);
	यदि (((len % 4) == 3) &&
	    (encoded[len-1] == '=') &&
	    (encoded[len-2] == '=') &&
	    (encoded[len-3] == '='))
		encoded[len-3] = '\0';
	यदि ((r = sshbuf_b64tod(buf, encoded)) != 0)
		fatal_fr(r, "base64 decode");
	यदि (*गुप्त) {
		यदि ((*k = do_convert_private_ssh2(buf)) == रिक्त)
			fatal_f("private key conversion failed");
	} अन्यथा यदि ((r = sshkey_fromb(buf, k)) != 0)
		fatal_fr(r, "parse key");
	sshbuf_free(buf);
	ख_बंद(fp);
}

स्थिर शून्य
do_convert_from_pkcs8(संरचना sshkey **k, पूर्णाङ्क *गुप्त)
{
	EVP_PKEY *pubkey;
	खाता *fp;

	यदि ((fp = ख_खोलो(identity_file, "r")) == रिक्त)
		fatal("%s: %s: %s", __progname, identity_file, म_त्रुटि(त्रुटि_सं));
	यदि ((pubkey = PEM_read_PUBKEY(fp, रिक्त, रिक्त, रिक्त)) == रिक्त) {
		fatal_f("%s is not a recognised public key format",
		    identity_file);
	}
	ख_बंद(fp);
	विकल्प (EVP_PKEY_base_id(pubkey)) {
	पक्ष EVP_PKEY_RSA:
		यदि ((*k = sshkey_new(साँचो_UNSPEC)) == रिक्त)
			fatal("sshkey_new failed");
		(*k)->type = साँचो_RSA;
		(*k)->pkey = pubkey;
		pubkey = रिक्त;
		रोक;
	पक्ष EVP_PKEY_EC:
		यदि ((*k = sshkey_new(साँचो_UNSPEC)) == रिक्त)
			fatal("sshkey_new failed");
		यदि (((*k)->ecdsa_nid = sshkey_ecdsa_fixup_group(pubkey)) == -1)
			fatal("sshkey_ecdsa_fixup_group failed");
		(*k)->type = साँचो_ECDSA;
		(*k)->pkey = pubkey;
		pubkey = रिक्त;
		रोक;
	स्वभाव:
		fatal_f("unsupported pubkey type %d",
		    EVP_PKEY_base_id(pubkey));
	}
	EVP_PKEY_free(pubkey);
}

स्थिर शून्य
do_convert_from_pem(संरचना sshkey **k, पूर्णाङ्क *गुप्त)
{
	खाता *fp;
	RSA *rsa;

	यदि ((fp = ख_खोलो(identity_file, "r")) == रिक्त)
		fatal("%s: %s: %s", __progname, identity_file, म_त्रुटि(त्रुटि_सं));
	यदि ((rsa = PEM_read_RSAPublic_साँचो(fp, रिक्त, रिक्त, रिक्त)) != रिक्त) {
		यदि ((*k = sshkey_new(साँचो_UNSPEC)) == रिक्त)
			fatal("sshkey_new failed");
		यदि (((*k)->pkey = EVP_PKEY_new()) == रिक्त)
			fatal("EVP_PKEY_new failed");
		(*k)->type = साँचो_RSA;
		यदि (EVP_PKEY_set1_RSA((*k)->pkey, rsa) != 1)
			fatal("EVP_PKEY_set1_RSA failed");
		RSA_free(rsa);
		ख_बंद(fp);
		फर्काऊ;
	}
	fatal_f("unrecognised raw private key format");
}

स्थिर शून्य
do_convert_from(संरचना passwd *pw)
{
	संरचना sshkey *k = रिक्त;
	पूर्णाङ्क r, गुप्त = 0, ok = 0;
	संरचना stat st;

	यदि (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	यदि (stat(identity_file, &st) == -1)
		fatal("%s: %s: %s", __progname, identity_file, म_त्रुटि(त्रुटि_सं));

	विकल्प (convert_format) {
	पक्ष FMT_RFC4716:
		do_convert_from_ssh2(pw, &k, &गुप्त);
		रोक;
	पक्ष FMT_PKCS8:
		do_convert_from_pkcs8(&k, &गुप्त);
		रोक;
	पक्ष FMT_PEM:
		do_convert_from_pem(&k, &गुप्त);
		रोक;
	स्वभाव:
		fatal_f("unknown key format %d", convert_format);
	}

	यदि (!गुप्त) {
		यदि ((r = sshkey_write(k, मानक_निकास)) == 0)
			ok = 1;
		यदि (ok)
			ख_लिखो(मानक_निकास, "\n");
	} अन्यथा {
		विकल्प (k->type) {
		पक्ष साँचो_ECDSA:
			ok = PEM_write_ECPrivate_साँचो(मानक_निकास,
			    EVP_PKEY_get0_EC_साँचो(k->pkey), रिक्त, रिक्त, 0,
			    रिक्त, रिक्त);
			रोक;
		पक्ष साँचो_RSA:
			ok = PEM_write_RSAPrivate_साँचो(मानक_निकास,
			    EVP_PKEY_get0_RSA(k->pkey), रिक्त, रिक्त, 0,
			    रिक्त, रिक्त);
			रोक;
		स्वभाव:
			fatal_f("unsupported key type %s", sshkey_type(k));
		}
	}

	यदि (!ok)
		fatal("key write failed");
	sshkey_free(k);
}
#endif

स्थिर शून्य
do_print_public(संरचना passwd *pw)
{
	संरचना sshkey *prv;
	संरचना stat st;
	पूर्णाङ्क r;
	वर्ण *comment = रिक्त;

	यदि (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	यदि (stat(identity_file, &st) == -1)
		fatal("%s: %s", identity_file, म_त्रुटि(त्रुटि_सं));
	prv = load_identity(identity_file, &comment);
	यदि ((r = sshkey_write(prv, मानक_निकास)) != 0)
		fatal_fr(r, "write key");
	यदि (comment != रिक्त && *comment != '\0')
		ख_लिखो(मानक_निकास, " %s", comment);
	ख_लिखो(मानक_निकास, "\n");
	यदि (sshkey_is_sk(prv)) {
		debug("sk_application: \"%s\", sk_flags 0x%02x",
			prv->sk_application, prv->sk_flags);
	}
	sshkey_free(prv);
	मुक्त(comment);
	निकास(0);
}

स्थिर शून्य
do_download(संरचना passwd *pw)
{
#ifdef ENABLE_PKCS11
	संरचना sshkey **साँचोहरू = रिक्त;
	पूर्णाङ्क i, nkeys;
	गणना sshkey_fp_rep rep;
	पूर्णाङ्क fptype;
	वर्ण *fp, *ra, **comments = रिक्त;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;

	pkcs11_init(1);
	nkeys = pkcs11_add_provider(pkcs11provider, रिक्त, &साँचोहरू, &comments);
	यदि (nkeys <= 0)
		fatal("cannot read public key from pkcs11");
	लागि (i = 0; i < nkeys; i++) {
		यदि (print_fingerprint) {
			fp = sshkey_fingerprint(साँचोहरू[i], fptype, rep);
			ra = sshkey_fingerprint(साँचोहरू[i], fingerprint_hash,
			    SSH_FP_RANDOMART);
			यदि (fp == रिक्त || ra == रिक्त)
				fatal_f("sshkey_fingerprint fail");
			म_लिखो("%u %s %s (PKCS11 key)\n", sshkey_size(साँचोहरू[i]),
			    fp, sshkey_type(साँचोहरू[i]));
			यदि (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
				म_लिखो("%s\n", ra);
			मुक्त(ra);
			मुक्त(fp);
		} अन्यथा {
			(शून्य) sshkey_write(साँचोहरू[i], मानक_निकास); /* XXX check */
			ख_लिखो(मानक_निकास, "%s%s\n",
			    *(comments[i]) == '\0' ? "" : " ", comments[i]);
		}
		मुक्त(comments[i]);
		sshkey_free(साँचोहरू[i]);
	}
	मुक्त(comments);
	मुक्त(साँचोहरू);
	pkcs11_terminate();
	निकास(0);
#अन्यथा
	fatal("no pkcs11 support");
#endif /* ENABLE_PKCS11 */
}

स्थिर संरचना sshkey *
try_read_साँचो(वर्ण **cpp)
{
	संरचना sshkey *ret;
	पूर्णाङ्क r;

	यदि ((ret = sshkey_new(साँचो_UNSPEC)) == रिक्त)
		fatal("sshkey_new failed");
	यदि ((r = sshkey_read(ret, cpp)) == 0)
		फर्काऊ ret;
	/* Not a key */
	sshkey_free(ret);
	फर्काऊ रिक्त;
}

स्थिर शून्य
fingerprint_one_साँचो(अचर संरचना sshkey *सार्वजनिक, अचर वर्ण *comment)
{
	वर्ण *fp = रिक्त, *ra = रिक्त;
	गणना sshkey_fp_rep rep;
	पूर्णाङ्क fptype;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;
	fp = sshkey_fingerprint(सार्वजनिक, fptype, rep);
	ra = sshkey_fingerprint(सार्वजनिक, fingerprint_hash, SSH_FP_RANDOMART);
	यदि (fp == रिक्त || ra == रिक्त)
		fatal_f("sshkey_fingerprint failed");
	mprintf("%u %s %s (%s)\n", sshkey_size(सार्वजनिक), fp,
	    comment ? comment : "no comment", sshkey_type(सार्वजनिक));
	यदि (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
		म_लिखो("%s\n", ra);
	मुक्त(ra);
	मुक्त(fp);
}

स्थिर शून्य
fingerprint_private(अचर वर्ण *path)
{
	संरचना stat st;
	वर्ण *comment = रिक्त;
	संरचना sshkey *privkey = रिक्त, *pubkey = रिक्त;
	पूर्णाङ्क r;

	यदि (stat(identity_file, &st) == -1)
		fatal("%s: %s", path, म_त्रुटि(त्रुटि_सं));
	यदि ((r = sshkey_load_public(path, &pubkey, &comment)) != 0)
		debug_r(r, "load public \"%s\"", path);
	यदि (pubkey == रिक्त || comment == रिक्त || *comment == '\0') {
		मुक्त(comment);
		यदि ((r = sshkey_load_private(path, रिक्त,
		    &privkey, &comment)) != 0)
			debug_r(r, "load private \"%s\"", path);
	}
	यदि (pubkey == रिक्त && privkey == रिक्त)
		fatal("%s is not a key file.", path);

	fingerprint_one_साँचो(pubkey == रिक्त ? privkey : pubkey, comment);
	sshkey_free(pubkey);
	sshkey_free(privkey);
	मुक्त(comment);
}

स्थिर शून्य
do_fingerprint(संरचना passwd *pw)
{
	खाता *f;
	संरचना sshkey *सार्वजनिक = रिक्त;
	वर्ण *comment = रिक्त, *cp, *ep, *पङ्क्ति = रिक्त;
	माप_प्रकार linesize = 0;
	पूर्णाङ्क i, invalid = 1;
	अचर वर्ण *path;
	u_long lnum = 0;

	यदि (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	path = identity_file;

	यदि (म_भेद(identity_file, "-") == 0) {
		f = मानक_निवेश;
		path = "(stdin)";
	} अन्यथा यदि ((f = ख_खोलो(path, "r")) == रिक्त)
		fatal("%s: %s: %s", __progname, path, म_त्रुटि(त्रुटि_सं));

	जबसम्म (getline(&पङ्क्ति, &linesize, f) != -1) {
		lnum++;
		cp = पङ्क्ति;
		cp[म_खोज(cp, "\r\n")] = '\0';
		/* Trim leading space and comments */
		cp = पङ्क्ति + म_अखोज(पङ्क्ति, " \t");
		यदि (*cp == '#' || *cp == '\0')
			जारी;

		/*
		 * Input may be plain keys, private keys, authorized_keys
		 * or known_hosts.
		 */

		/*
		 * Try private keys first. Assume a key is private if
		 * "SSH PRIVATE KEY" appears on the first line and we're
		 * not reading from stdin (XXX support private keys on stdin).
		 */
		यदि (lnum == 1 && म_भेद(identity_file, "-") != 0 &&
		    म_माला(cp, "PRIVATE KEY") != रिक्त) {
			मुक्त(पङ्क्ति);
			ख_बंद(f);
			fingerprint_private(path);
			निकास(0);
		}

		/*
		 * If it's not a private key, then this must be prepared to
		 * accept a public key prefixed with a hostname or options.
		 * Try a bare key first, otherwise skip the leading stuff.
		 */
		comment = रिक्त;
		यदि ((सार्वजनिक = try_read_साँचो(&cp)) == रिक्त) {
			i = म_से_दीर्घ(cp, &ep, 10);
			यदि (i == 0 || ep == रिक्त ||
			    (*ep != ' ' && *ep != '\t')) {
				पूर्णाङ्क quoted = 0;

				comment = cp;
				लागि (; *cp && (quoted || (*cp != ' ' &&
				    *cp != '\t')); cp++) {
					यदि (*cp == '\\' && cp[1] == '"')
						cp++;	/* Skip both */
					अन्यथा यदि (*cp == '"')
						quoted = !quoted;
				}
				यदि (!*cp)
					जारी;
				*cp++ = '\0';
			}
		}
		/* Retry after parsing leading hostname/key options */
		यदि (सार्वजनिक == रिक्त && (सार्वजनिक = try_read_साँचो(&cp)) == रिक्त) {
			debug("%s:%lu: not a public key", path, lnum);
			जारी;
		}

		/* Find trailing comment, if any */
		लागि (; *cp == ' ' || *cp == '\t'; cp++)
			;
		यदि (*cp != '\0' && *cp != '#')
			comment = cp;

		fingerprint_one_साँचो(सार्वजनिक, comment);
		sshkey_free(सार्वजनिक);
		invalid = 0; /* One good key in the file is sufficient */
	}
	ख_बंद(f);
	मुक्त(पङ्क्ति);

	यदि (invalid)
		fatal("%s is not a public key file.", path);
	निकास(0);
}

स्थिर शून्य
do_gen_all_hostkeys(संरचना passwd *pw)
{
	संरचना {
		वर्ण *साँचो_type;
		वर्ण *साँचो_type_display;
		वर्ण *path;
	} साँचो_types[] = {
#ifdef WITH_OPENSSL
		{ "rsa", "RSA" ,PATH_HOST_RSA_साँचो_FILE },
		{ "ecdsa", "ECDSA",PATH_HOST_ECDSA_साँचो_FILE },
#endif /* WITH_OPENSSL */
		{ "ed25519", "ED25519",PATH_HOST_ED25519_साँचो_FILE },
#ifdef USE_MLDSA
		{ "mldsa44-ed25519", "MLDSA44-ED25519",
		     PATH_HOST_MLDSA44_ED25519_साँचो_FILE },
#endif
		{ रिक्त, रिक्त, रिक्त }
	};

	uint32_t bits = 0;
	पूर्णाङ्क first = 0;
	संरचना stat st;
	संरचना sshkey *गुप्त, *सार्वजनिक;
	वर्ण comment[साँचो_COMMENT_MAX], *prv_tmp, *pub_tmp, *prv_file, *pub_file;
	पूर्णाङ्क i, type, fd, r;

	लागि (i = 0; साँचो_types[i].साँचो_type; i++) {
		सार्वजनिक = गुप्त = रिक्त;
		prv_tmp = pub_tmp = prv_file = pub_file = रिक्त;

		xasprintf(&prv_file, "%s%s",
		    identity_file, साँचो_types[i].path);

		/* Check whether private key exists and is not zero-length */
		यदि (stat(prv_file, &st) == 0) {
			यदि (st.st_size != 0)
				गच्छ next;
		} अन्यथा यदि (त्रुटि_सं != ENOENT) {
			error("Could not stat %s: %s", साँचो_types[i].path,
			    म_त्रुटि(त्रुटि_सं));
			गच्छ failnext;
		}

		/*
		 * Private key doesn't exist or is invalid; proceed with
		 * key generation.
		 */
		xasprintf(&prv_tmp, "%s%s.XXXXXXXXXX",
		    identity_file, साँचो_types[i].path);
		xasprintf(&pub_tmp, "%s%s.pub.XXXXXXXXXX",
		    identity_file, साँचो_types[i].path);
		xasprintf(&pub_file, "%s%s.pub",
		    identity_file, साँचो_types[i].path);

		यदि (first == 0) {
			first = 1;
			म_लिखो("%s: generating new host keys: ", __progname);
		}
		म_लिखो("%s ", साँचो_types[i].साँचो_type_display);
		ख_साफ(मानक_निकास);
		type = sshkey_type_from_shortname(साँचो_types[i].साँचो_type);
		यदि ((fd = mkstemp(prv_tmp)) == -1) {
			error("Could not save your private key in %s: %s",
			    prv_tmp, म_त्रुटि(त्रुटि_सं));
			गच्छ failnext;
		}
		(शून्य)बंद(fd); /* just using mkstemp() to reserve a name */
		bits = 0;
		type_bits_valid(type, रिक्त, &bits);
		यदि ((r = sshkey_generate(type, bits, &गुप्त)) != 0) {
			error_r(r, "sshkey_generate failed");
			गच्छ failnext;
		}
		यदि ((r = sshkey_from_private(गुप्त, &सार्वजनिक)) != 0)
			fatal_fr(r, "sshkey_from_private");
		snprintf(comment, परिमाण comment, "%s@%s", pw->pw_name,
		    hostname);
		यदि ((r = sshkey_save_private(गुप्त, prv_tmp, "",
		    comment, private_साँचो_format, openssh_format_cipher,
		    rounds)) != 0) {
			error_r(r, "Saving key \"%s\" failed", prv_tmp);
			गच्छ failnext;
		}
		यदि ((fd = mkstemp(pub_tmp)) == -1) {
			error("Could not save your public key in %s: %s",
			    pub_tmp, म_त्रुटि(त्रुटि_सं));
			गच्छ failnext;
		}
		(शून्य)fchmod(fd, 0644);
		(शून्य)बंद(fd);
		यदि ((r = sshkey_save_public(सार्वजनिक, pub_tmp, comment)) != 0) {
			error_r(r, "Unable to save public key to %s",
			    identity_file);
			गच्छ failnext;
		}

		/* Rename temporary files to their permanent locations. */
		यदि (नाम(pub_tmp, pub_file) != 0) {
			error("Unable to move %s into position: %s",
			    pub_file, म_त्रुटि(त्रुटि_सं));
			गच्छ failnext;
		}
		यदि (नाम(prv_tmp, prv_file) != 0) {
			error("Unable to move %s into position: %s",
			    साँचो_types[i].path, म_त्रुटि(त्रुटि_सं));
 failnext:
			first = 0;
			गच्छ next;
		}
 next:
		sshkey_free(गुप्त);
		sshkey_free(सार्वजनिक);
		मुक्त(prv_tmp);
		मुक्त(pub_tmp);
		मुक्त(prv_file);
		मुक्त(pub_file);
	}
	यदि (first != 0)
		म_लिखो("\n");
}

संरचना known_hosts_ctx {
	अचर वर्ण *host;	/* Hostname searched for in find/delete case */
	खाता *out;		/* Output file, stdout for find_hosts case */
	पूर्णाङ्क has_unhashed;	/* When hashing, original had unhashed hosts */
	पूर्णाङ्क found_साँचो;		/* For find/delete, host was found */
	पूर्णाङ्क invalid;		/* File contained invalid items; don't delete */
	पूर्णाङ्क hash_hosts;		/* Hash hostnames as we go */
	पूर्णाङ्क find_host;		/* Search for specific hostname */
	पूर्णाङ्क delete_host;	/* Delete host from known_hosts */
};

स्थिर पूर्णाङ्क
known_hosts_hash(संरचना hostkey_foreach_पङ्क्ति *l, शून्य *_ctx)
{
	संरचना known_hosts_ctx *ctx = (संरचना known_hosts_ctx *)_ctx;
	वर्ण *hashed, *cp, *hosts, *ohosts;
	पूर्णाङ्क has_wild = l->hosts && म_खोज(l->hosts, "*?!") != म_माप(l->hosts);
	पूर्णाङ्क was_hashed = l->hosts && l->hosts[0] == HASH_DELIM;

	विकल्प (l->status) {
	पक्ष HKF_STATUS_OK:
	पक्ष HKF_STATUS_MATCHED:
		/*
		 * Don't hash hosts already hashed, with wildcard
		 * characters or a CA/revocation marker.
		 */
		यदि (was_hashed || has_wild || l->marker != MRK_NONE) {
			ख_लिखो(ctx->out, "%s\n", l->पङ्क्ति);
			यदि (has_wild && !ctx->find_host) {
				logit("%s:%lu: ignoring host name "
				    "with wildcard: %.64s", l->path,
				    l->linenum, l->hosts);
			}
			फर्काऊ 0;
		}
		/*
		 * Split any comma-separated hostnames from the host list,
		 * hash and store separately.
		 */
		ohosts = hosts = xstrdup(l->hosts);
		जबसम्म ((cp = strsep(&hosts, ",")) != रिक्त && *cp != '\0') {
			lowercase(cp);
			यदि ((hashed = host_hash(cp, रिक्त, 0)) == रिक्त)
				fatal("hash_host failed");
			ख_लिखो(ctx->out, "%s %s\n", hashed, l->rawkey);
			मुक्त(hashed);
			ctx->has_unhashed = 1;
		}
		मुक्त(ohosts);
		फर्काऊ 0;
	पक्ष HKF_STATUS_INVALID:
		/* Retain invalid lines, but mark file as invalid. */
		ctx->invalid = 1;
		logit("%s:%lu: invalid line", l->path, l->linenum);
		/* FALLTHROUGH */
	स्वभाव:
		ख_लिखो(ctx->out, "%s\n", l->पङ्क्ति);
		फर्काऊ 0;
	}
	/* NOTREACHED */
	फर्काऊ -1;
}

स्थिर पूर्णाङ्क
known_hosts_find_delete(संरचना hostkey_foreach_पङ्क्ति *l, शून्य *_ctx)
{
	संरचना known_hosts_ctx *ctx = (संरचना known_hosts_ctx *)_ctx;
	गणना sshkey_fp_rep rep;
	पूर्णाङ्क fptype;
	वर्ण *fp = रिक्त, *ra = रिक्त;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;

	यदि (l->status == HKF_STATUS_MATCHED) {
		यदि (ctx->delete_host) {
			यदि (l->marker != MRK_NONE) {
				/* Don't remove CA and revocation lines */
				ख_लिखो(ctx->out, "%s\n", l->पङ्क्ति);
			} अन्यथा {
				/*
				 * Hostname matches and has no CA/revoke
				 * marker, delete it by *not* writing the
				 * line to ctx->out.
				 */
				ctx->found_साँचो = 1;
				यदि (!quiet)
					म_लिखो("# Host %s found: line %lu\n",
					    ctx->host, l->linenum);
			}
			फर्काऊ 0;
		} अन्यथा यदि (ctx->find_host) {
			ctx->found_साँचो = 1;
			यदि (!quiet) {
				म_लिखो("# Host %s found: line %lu %s\n",
				    ctx->host,
				    l->linenum, l->marker == MRK_CA ? "CA" :
				    (l->marker == MRK_REVOKE ? "REVOKED" : ""));
			}
			यदि (ctx->hash_hosts)
				known_hosts_hash(l, ctx);
			अन्यथा यदि (print_fingerprint) {
				fp = sshkey_fingerprint(l->साँचो, fptype, rep);
				ra = sshkey_fingerprint(l->साँचो,
				    fingerprint_hash, SSH_FP_RANDOMART);
				यदि (fp == रिक्त || ra == रिक्त)
					fatal_f("sshkey_fingerprint failed");
				mprintf("%s %s %s%s%s\n", ctx->host,
				    sshkey_type(l->साँचो), fp,
				    l->comment[0] ? " " : "",
				    l->comment);
				यदि (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
					म_लिखो("%s\n", ra);
				मुक्त(ra);
				मुक्त(fp);
			} अन्यथा
				ख_लिखो(ctx->out, "%s\n", l->पङ्क्ति);
			फर्काऊ 0;
		}
	} अन्यथा यदि (ctx->delete_host) {
		/* Retain non-matching hosts when deleting */
		यदि (l->status == HKF_STATUS_INVALID) {
			ctx->invalid = 1;
			logit("%s:%lu: invalid line", l->path, l->linenum);
		}
		ख_लिखो(ctx->out, "%s\n", l->पङ्क्ति);
	}
	फर्काऊ 0;
}

स्थिर शून्य
do_known_hosts(संरचना passwd *pw, अचर वर्ण *name, पूर्णाङ्क find_host,
    पूर्णाङ्क delete_host, पूर्णाङ्क hash_hosts)
{
	वर्ण *cp, tmp[PATH_MAX], old[PATH_MAX];
	पूर्णाङ्क r, fd, oerrno, inplace = 0;
	संरचना known_hosts_ctx ctx;
	u_int foreach_options;
	संरचना stat sb;

	यदि (!have_identity) {
		cp = tilde_expand_filename(_PATH_SSH_USER_HOSTFILE, pw->pw_uid);
		यदि (strlcpy(identity_file, cp, परिमाण(identity_file)) >=
		    परिमाण(identity_file))
			fatal("Specified known hosts path too long");
		मुक्त(cp);
		have_identity = 1;
	}
	यदि (stat(identity_file, &sb) != 0)
		fatal("Cannot stat %s: %s", identity_file, म_त्रुटि(त्रुटि_सं));

	स_रखो(&ctx, 0, परिमाण(ctx));
	ctx.out = मानक_निकास;
	ctx.host = name;
	ctx.hash_hosts = hash_hosts;
	ctx.find_host = find_host;
	ctx.delete_host = delete_host;

	/*
	 * Find hosts goes to stdout, hash and deletions happen in-place
	 * A corner case is ssh-keygen -HF foo, which should go to stdout
	 */
	यदि (!find_host && (hash_hosts || delete_host)) {
		यदि (strlcpy(tmp, identity_file, परिमाण(tmp)) >= परिमाण(tmp) ||
		    strlcat(tmp, ".XXXXXXXXXX", परिमाण(tmp)) >= परिमाण(tmp) ||
		    strlcpy(old, identity_file, परिमाण(old)) >= परिमाण(old) ||
		    strlcat(old, ".old", परिमाण(old)) >= परिमाण(old))
			fatal("known_hosts path too long");
		umask(077);
		यदि ((fd = mkstemp(tmp)) == -1)
			fatal("mkstemp: %s", म_त्रुटि(त्रुटि_सं));
		यदि ((ctx.out = fdopen(fd, "w")) == रिक्त) {
			oerrno = त्रुटि_सं;
			unlink(tmp);
			fatal("fdopen: %s", म_त्रुटि(oerrno));
		}
		(शून्य)fchmod(fd, sb.st_mode & 0644);
		inplace = 1;
	}
	/* XXX support identity_file == "-" for stdin */
	foreach_options = find_host ? HKF_WANT_MATCH : 0;
	foreach_options |= print_fingerprint ? HKF_WANT_PARSE_साँचो : 0;
	यदि ((r = hostkeys_foreach(identity_file, (find_host || !hash_hosts) ?
	    known_hosts_find_delete : known_hosts_hash, &ctx, name, रिक्त,
	    foreach_options, 0)) != 0) {
		यदि (inplace)
			unlink(tmp);
		fatal_fr(r, "hostkeys_foreach");
	}

	यदि (inplace)
		ख_बंद(ctx.out);

	यदि (ctx.invalid) {
		error("%s is not a valid known_hosts file.", identity_file);
		यदि (inplace) {
			error("Not replacing existing known_hosts "
			    "file because of errors");
			unlink(tmp);
		}
		निकास(1);
	} अन्यथा यदि (delete_host && !ctx.found_साँचो) {
		logit("Host %s not found in %s", name, identity_file);
		यदि (inplace)
			unlink(tmp);
	} अन्यथा यदि (inplace) {
		/* Backup existing file */
		यदि (unlink(old) == -1 && त्रुटि_सं != ENOENT)
			fatal("unlink %.100s: %s", old, म_त्रुटि(त्रुटि_सं));
		यदि (link(identity_file, old) == -1)
			fatal("link %.100s to %.100s: %s", identity_file, old,
			    म_त्रुटि(त्रुटि_सं));
		/* Move new one into place */
		यदि (नाम(tmp, identity_file) == -1) {
			error("rename\"%s\" to \"%s\": %s", tmp, identity_file,
			    म_त्रुटि(त्रुटि_सं));
			unlink(tmp);
			unlink(old);
			निकास(1);
		}

		म_लिखो("%s updated.\n", identity_file);
		म_लिखो("Original contents retained as %s\n", old);
		यदि (ctx.has_unhashed) {
			logit("WARNING: %s contains unhashed entries", old);
			logit("Delete this file to ensure privacy "
			    "of hostnames");
		}
	}

	निकास (find_host && !ctx.found_साँचो);
}

/*
 * Perform changing a passphrase.  The argument is the passwd structure
 * for the current user.
 */
स्थिर शून्य
do_change_passphrase(संरचना passwd *pw, वर्ण * अचर *opts, माप_प्रकार nopts)
{
	वर्ण *comment;
	वर्ण *old_passphrase, *passphrase1, *passphrase2;
	संरचना stat st;
	संरचना sshkey *गुप्त;
	पूर्णाङ्क r;
	माप_प्रकार i;

	यदि (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	यदि (stat(identity_file, &st) == -1)
		fatal("%s: %s", identity_file, म_त्रुटि(त्रुटि_सं));
	/* Try to load the file with empty passphrase. */
	r = sshkey_load_private(identity_file, "", &गुप्त, &comment);
	यदि (r == SSH_ERR_साँचो_WRONG_PASSPHRASE) {
		यदि (identity_passphrase)
			old_passphrase = xstrdup(identity_passphrase);
		अन्यथा
			old_passphrase =
			    read_passphrase("Enter old passphrase: ",
			    RP_ALLOW_STDIN);
		r = sshkey_load_private(identity_file, old_passphrase,
		    &गुप्त, &comment);
		freezero(old_passphrase, म_माप(old_passphrase));
		यदि (r != 0)
			गच्छ badkey;
	} अन्यथा यदि (r != 0) {
 badkey:
		fatal_r(r, "Failed to load key %s", identity_file);
	}
	यदि (comment)
		mprintf("Key has comment '%s'\n", comment);

	/* All current -O options relate to FIDO keys only */
	यदि (nopts != 0 && !sshkey_is_sk(गुप्त)) {
		fatal("FIDO-specific option requested for non-FIDO key %s",
		    identity_file);
	}
	यदि (sshkey_is_sk(गुप्त)) {
		debug_f("%s: original FIDO key flags: "
		    "%stouch-required %sverify-required", identity_file,
		    (गुप्त->sk_flags & SSH_SK_USER_PRESENCE_REQD) ? "": "no-",
		    (गुप्त->sk_flags & SSH_SK_USER_VERIFICATION_REQD) ? "" : "no-");
	}
	लागि (i = 0; i < nopts; i++) {
		यदि (strcasecmp(opts[i], "touch-required") == 0)
			गुप्त->sk_flags |= SSH_SK_USER_PRESENCE_REQD;
		अन्यथा यदि (strcasecmp(opts[i], "no-touch-required") == 0)
			गुप्त->sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
		अन्यथा यदि (strcasecmp(opts[i], "verify-required") == 0)
			गुप्त->sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
		अन्यथा यदि (strcasecmp(opts[i], "no-verify-required") == 0)
			गुप्त->sk_flags &= ~SSH_SK_USER_VERIFICATION_REQD;
		अन्यथा {
			fatal("Option \"%s\" is unsupported for "
			    "key passphrase change", opts[i]);
		}
	}
	यदि (sshkey_is_sk(गुप्त) && nopts != 0) {
		debug_f("%s: updated FIDO key flags: "
		    "%stouch-required %sverify-required", identity_file,
		    (गुप्त->sk_flags & SSH_SK_USER_PRESENCE_REQD) ? "": "no-",
		    (गुप्त->sk_flags & SSH_SK_USER_VERIFICATION_REQD) ? "" : "no-");
	}

	/* Ask the new passphrase (twice). */
	यदि (identity_new_passphrase) {
		passphrase1 = xstrdup(identity_new_passphrase);
		passphrase2 = रिक्त;
	} अन्यथा {
		passphrase1 =
			read_passphrase("Enter new passphrase (empty for no "
			    "passphrase): ", RP_ALLOW_STDIN);
		passphrase2 = read_passphrase("Enter same passphrase again: ",
		    RP_ALLOW_STDIN);

		/* Verify that they are the same. */
		यदि (म_भेद(passphrase1, passphrase2) != 0) {
			explicit_bzero(passphrase1, म_माप(passphrase1));
			explicit_bzero(passphrase2, म_माप(passphrase2));
			मुक्त(passphrase1);
			मुक्त(passphrase2);
			म_लिखो("Pass phrases do not match.  Try again.\n");
			निकास(1);
		}
		/* Destroy the other copy. */
		freezero(passphrase2, म_माप(passphrase2));
	}

	/* Save the file using the new passphrase. */
	यदि ((r = sshkey_save_private(गुप्त, identity_file, passphrase1,
	    comment, private_साँचो_format, openssh_format_cipher, rounds)) != 0) {
		error_r(r, "Saving key \"%s\" failed", identity_file);
		freezero(passphrase1, म_माप(passphrase1));
		sshkey_free(गुप्त);
		मुक्त(comment);
		निकास(1);
	}
	/* Destroy the passphrase and the copy of the key in memory. */
	freezero(passphrase1, म_माप(passphrase1));
	sshkey_free(गुप्त);		 /* Destroys contents */
	मुक्त(comment);

	म_लिखो("Your identification has been saved with the new passphrase.\n");
	निकास(0);
}

/*
 * Print the SSHFP RR.
 */
स्थिर पूर्णाङ्क
do_print_resource_record(संरचना passwd *pw, वर्ण *fname, वर्ण *hname,
    पूर्णाङ्क print_generic, वर्ण * अचर *opts, माप_प्रकार nopts)
{
	संरचना sshkey *सार्वजनिक;
	वर्ण *comment = रिक्त;
	अचर वर्ण *p;
	संरचना stat st;
	पूर्णाङ्क r, hash = -1;
	माप_प्रकार i;

	लागि (i = 0; i < nopts; i++) {
		यदि ((p = strprefix(opts[i], "hashalg=", 1)) != रिक्त) {
			यदि ((hash = ssh_digest_alg_by_name(p)) == -1)
				fatal("Unsupported hash algorithm");
		} अन्यथा {
			error("Invalid option \"%s\"", opts[i]);
			फर्काऊ SSH_ERR_INVALID_ARGUMENT;
		}
	}
	यदि (fname == रिक्त)
		fatal_f("no filename");
	यदि (stat(fname, &st) == -1) {
		यदि (त्रुटि_सं == ENOENT)
			फर्काऊ 0;
		fatal("%s: %s", fname, म_त्रुटि(त्रुटि_सं));
	}
	यदि ((r = sshkey_load_public(fname, &सार्वजनिक, &comment)) != 0)
		fatal_r(r, "Failed to read v2 public key from \"%s\"", fname);
	export_dns_rr(hname, सार्वजनिक, मानक_निकास, print_generic, hash);
	sshkey_free(सार्वजनिक);
	मुक्त(comment);
	फर्काऊ 1;
}

/*
 * Change the comment of a private key file.
 */
स्थिर शून्य
do_change_comment(संरचना passwd *pw, अचर वर्ण *identity_comment)
{
	वर्ण new_comment[साँचो_COMMENT_MAX], *comment, *passphrase;
	संरचना sshkey *गुप्त;
	संरचना sshkey *सार्वजनिक;
	संरचना stat st;
	पूर्णाङ्क r;

	यदि (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	यदि (stat(identity_file, &st) == -1)
		fatal("%s: %s", identity_file, म_त्रुटि(त्रुटि_सं));
	यदि ((r = sshkey_load_private(identity_file, "",
	    &गुप्त, &comment)) == 0)
		passphrase = xstrdup("");
	अन्यथा यदि (r != SSH_ERR_साँचो_WRONG_PASSPHRASE)
		fatal_r(r, "Cannot load private key \"%s\"", identity_file);
	अन्यथा {
		यदि (identity_passphrase)
			passphrase = xstrdup(identity_passphrase);
		अन्यथा यदि (identity_new_passphrase)
			passphrase = xstrdup(identity_new_passphrase);
		अन्यथा
			passphrase = read_passphrase("Enter passphrase: ",
			    RP_ALLOW_STDIN);
		/* Try to load using the passphrase. */
		यदि ((r = sshkey_load_private(identity_file, passphrase,
		    &गुप्त, &comment)) != 0) {
			freezero(passphrase, म_माप(passphrase));
			fatal_r(r, "Cannot load private key \"%s\"",
			    identity_file);
		}
	}

	यदि (गुप्त->type != साँचो_ED25519 &&
	    private_साँचो_format != SSHKEY_PRIVATE_OPENSSH) {
		error("Comments are only supported for keys stored in "
		    "the new format (-o).");
		explicit_bzero(passphrase, म_माप(passphrase));
		sshkey_free(गुप्त);
		निकास(1);
	}
	यदि (comment)
		म_लिखो("Old comment: %s\n", comment);
	अन्यथा
		म_लिखो("No existing comment\n");

	यदि (identity_comment) {
		strlcpy(new_comment, identity_comment, परिमाण(new_comment));
	} अन्यथा {
		म_लिखो("New comment: ");
		ख_साफ(मानक_निकास);
		यदि (!ख_माला_लो(new_comment, परिमाण(new_comment), मानक_निवेश)) {
			explicit_bzero(passphrase, म_माप(passphrase));
			sshkey_free(गुप्त);
			निकास(1);
		}
		new_comment[म_खोज(new_comment, "\n")] = '\0';
	}
	यदि (comment != रिक्त && म_भेद(comment, new_comment) == 0) {
		म_लिखो("No change to comment\n");
		मुक्त(passphrase);
		sshkey_free(गुप्त);
		मुक्त(comment);
		निकास(0);
	}

	/* Save the file using the new passphrase. */
	यदि ((r = sshkey_save_private(गुप्त, identity_file, passphrase,
	    new_comment, private_साँचो_format, openssh_format_cipher,
	    rounds)) != 0) {
		error_r(r, "Saving key \"%s\" failed", identity_file);
		freezero(passphrase, म_माप(passphrase));
		sshkey_free(गुप्त);
		मुक्त(comment);
		निकास(1);
	}
	freezero(passphrase, म_माप(passphrase));
	यदि ((r = sshkey_from_private(गुप्त, &सार्वजनिक)) != 0)
		fatal_fr(r, "sshkey_from_private");
	sshkey_free(गुप्त);

	strlcat(identity_file, ".pub", परिमाण(identity_file));
	यदि ((r = sshkey_save_public(सार्वजनिक, identity_file, new_comment)) != 0)
		fatal_r(r, "Unable to save public key to %s", identity_file);
	sshkey_free(सार्वजनिक);
	मुक्त(comment);

	यदि (म_माप(new_comment) > 0)
		म_लिखो("Comment '%s' applied\n", new_comment);
	अन्यथा
		म_लिखो("Comment removed\n");

	निकास(0);
}

स्थिर शून्य
cert_ext_add(अचर वर्ण *साँचो, अचर वर्ण *मान, पूर्णाङ्क iscrit)
{
	cert_ext = xreallocarray(cert_ext, ncert_ext + 1, परिमाण(*cert_ext));
	cert_ext[ncert_ext].साँचो = xstrdup(साँचो);
	cert_ext[ncert_ext].val = मान == रिक्त ? रिक्त : xstrdup(मान);
	cert_ext[ncert_ext].crit = iscrit;
	ncert_ext++;
}

/* qsort(3) comparison function for certificate extensions */
स्थिर पूर्णाङ्क
cert_ext_cmp(अचर शून्य *_a, अचर शून्य *_b)
{
	अचर संरचना cert_ext *a = (अचर संरचना cert_ext *)_a;
	अचर संरचना cert_ext *b = (अचर संरचना cert_ext *)_b;
	पूर्णाङ्क r;

	यदि (a->crit != b->crit)
		फर्काऊ (a->crit < b->crit) ? -1 : 1;
	यदि ((r = म_भेद(a->साँचो, b->साँचो)) != 0)
		फर्काऊ r;
	यदि ((a->val == रिक्त) != (b->val == रिक्त))
		फर्काऊ (a->val == रिक्त) ? -1 : 1;
	यदि (a->val != रिक्त && (r = म_भेद(a->val, b->val)) != 0)
		फर्काऊ r;
	फर्काऊ 0;
}

#define OPTIONS_CRITICAL	1
#define OPTIONS_EXTENSIONS	2
स्थिर शून्य
prepare_options_buf(संरचना sshbuf *c, पूर्णाङ्क which)
{
	संरचना sshbuf *b;
	माप_प्रकार i;
	पूर्णाङ्क r;
	अचर संरचना cert_ext *ext;

	यदि ((b = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	sshbuf_reset(c);
	लागि (i = 0; i < ncert_ext; i++) {
		ext = &cert_ext[i];
		यदि ((ext->crit && (which & OPTIONS_EXTENSIONS)) ||
		    (!ext->crit && (which & OPTIONS_CRITICAL)))
			जारी;
		यदि (ext->val == रिक्त) {
			/* flag option */
			debug3_f("%s", ext->साँचो);
			यदि ((r = sshbuf_put_cstring(c, ext->साँचो)) != 0 ||
			    (r = sshbuf_put_string(c, रिक्त, 0)) != 0)
				fatal_fr(r, "prepare flag");
		} अन्यथा {
			/* key/value option */
			debug3_f("%s=%s", ext->साँचो, ext->val);
			sshbuf_reset(b);
			यदि ((r = sshbuf_put_cstring(c, ext->साँचो)) != 0 ||
			    (r = sshbuf_put_cstring(b, ext->val)) != 0 ||
			    (r = sshbuf_put_stringb(c, b)) != 0)
				fatal_fr(r, "prepare k/v");
		}
	}
	sshbuf_free(b);
}

स्थिर शून्य
finalise_cert_exts(शून्य)
{
	/* critical options */
	यदि (certflags_command != रिक्त)
		cert_ext_add("force-command", certflags_command, 1);
	यदि (certflags_src_addr != रिक्त)
		cert_ext_add("source-address", certflags_src_addr, 1);
	यदि ((certflags_flags & CERTOPT_REQUIRE_VERIFY) != 0)
		cert_ext_add("verify-required", रिक्त, 1);
	/* extensions */
	यदि ((certflags_flags & CERTOPT_X_FWD) != 0)
		cert_ext_add("permit-X11-forwarding", रिक्त, 0);
	यदि ((certflags_flags & CERTOPT_AGENT_FWD) != 0)
		cert_ext_add("permit-agent-forwarding", रिक्त, 0);
	यदि ((certflags_flags & CERTOPT_PORT_FWD) != 0)
		cert_ext_add("permit-port-forwarding", रिक्त, 0);
	यदि ((certflags_flags & CERTOPT_PTY) != 0)
		cert_ext_add("permit-pty", रिक्त, 0);
	यदि ((certflags_flags & CERTOPT_USER_RC) != 0)
		cert_ext_add("permit-user-rc", रिक्त, 0);
	यदि ((certflags_flags & CERTOPT_NO_REQUIRE_USER_PRESENCE) != 0)
		cert_ext_add("no-touch-required", रिक्त, 0);
	/* order lexically by key */
	यदि (ncert_ext > 0)
		क्विक(cert_ext, ncert_ext, परिमाण(*cert_ext), cert_ext_cmp);
}

स्थिर संरचना sshkey *
load_pkcs11_साँचो(वर्ण *path)
{
#ifdef ENABLE_PKCS11
	संरचना sshkey **साँचोहरू = रिक्त, *सार्वजनिक, *गुप्त = रिक्त;
	पूर्णाङ्क r, i, nkeys;

	यदि ((r = sshkey_load_public(path, &सार्वजनिक, रिक्त)) != 0)
		fatal_r(r, "Couldn't load CA public key \"%s\"", path);

	nkeys = pkcs11_add_provider(pkcs11provider, identity_passphrase,
	    &साँचोहरू, रिक्त);
	debug3_f("%d keys", nkeys);
	यदि (nkeys <= 0)
		fatal("cannot read public key from pkcs11");
	लागि (i = 0; i < nkeys; i++) {
		यदि (sshkey_equal_public(सार्वजनिक, साँचोहरू[i])) {
			गुप्त = साँचोहरू[i];
			जारी;
		}
		sshkey_free(साँचोहरू[i]);
	}
	मुक्त(साँचोहरू);
	sshkey_free(सार्वजनिक);
	फर्काऊ गुप्त;
#अन्यथा
	fatal("no pkcs11 support");
#endif /* ENABLE_PKCS11 */
}

/* Signer for sshkey_certify_custom that uses the agent */
स्थिर पूर्णाङ्क
agent_signer(संरचना sshkey *साँचो, u_char **sigp, माप_प्रकार *lenp,
    अचर u_char *data, माप_प्रकार datalen,
    अचर वर्ण *alg, अचर वर्ण *provider, अचर वर्ण *pin,
    u_int compat, शून्य *ctx)
{
	पूर्णाङ्क *agent_fdp = (पूर्णाङ्क *)ctx;

	फर्काऊ ssh_agent_sign(*agent_fdp, साँचो, sigp, lenp,
	    data, datalen, alg, compat);
}

स्थिर शून्य
do_ca_sign(संरचना passwd *pw, अचर वर्ण *ca_साँचो_path, पूर्णाङ्क prefer_agent,
    अचिन्हित दीर्घ दीर्घ cert_serial, पूर्णाङ्क cert_serial_autoinc,
    पूर्णाङ्क argc, वर्ण **argv)
{
	पूर्णाङ्क r, i, साँचो_in_agent = 0, agent_fd = -1;
	u_int n;
	संरचना sshkey *ca, *सार्वजनिक;
	वर्ण valid[64], *otmp, *tmp, *cp, *out, *comment;
	वर्ण *ca_fp = रिक्त, **plist = रिक्त, *pin = रिक्त;
	संरचना ssh_identitylist *agent_ids;
	माप_प्रकार j;
	संरचना notifier_ctx *notifier = रिक्त;

#ifdef ENABLE_PKCS11
	pkcs11_init(1);
#endif
	tmp = tilde_expand_filename(ca_साँचो_path, pw->pw_uid);
	यदि (pkcs11provider != रिक्त) {
		/* If a PKCS#11 token was specified then try to use it */
		यदि ((ca = load_pkcs11_साँचो(tmp)) == रिक्त)
			fatal("No PKCS#11 key matching %s found", ca_साँचो_path);
	} अन्यथा यदि (prefer_agent) {
		/*
		 * Agent signature requested. Try to use agent after making
		 * sure the public key specified is actually present in the
		 * agent.
		 */
		यदि ((r = sshkey_load_public(tmp, &ca, रिक्त)) != 0)
			fatal_r(r, "Cannot load CA public key %s", tmp);
		यदि ((r = ssh_get_authentication_socket(&agent_fd)) != 0)
			fatal_r(r, "Cannot use public key for CA signature");
		यदि ((r = ssh_fetch_identitylist(agent_fd, &agent_ids)) != 0)
			fatal_r(r, "Retrieve agent key list");
		लागि (j = 0; j < agent_ids->nkeys; j++) {
			यदि (sshkey_equal(ca, agent_ids->साँचोहरू[j])) {
				साँचो_in_agent = 1;
				/* Replace the CA key with the agent one */
				sshkey_free(ca);
				ca = agent_ids->साँचोहरू[j];
				agent_ids->साँचोहरू[j] = रिक्त;
				रोक;
			}
		}
		यदि (!साँचो_in_agent)
			fatal("CA key %s not found in agent", tmp);
		ssh_free_identitylist(agent_ids);
	} अन्यथा {
		/* CA key is assumed to be a private key on the filesystem */
		ca = load_identity(tmp, रिक्त);
		यदि (sshkey_is_sk(ca) &&
		    (ca->sk_flags & SSH_SK_USER_VERIFICATION_REQD)) {
			यदि ((pin = read_passphrase("Enter PIN for CA key: ",
			    RP_ALLOW_STDIN)) == रिक्त)
				fatal_f("couldn't read PIN");
		}
	}
	मुक्त(tmp);

	यदि (साँचो_type_name != रिक्त) {
		यदि (sshkey_type_from_shortname(साँचो_type_name) != ca->type) {
			fatal("CA key type %s doesn't match specified %s",
			    sshkey_ssh_name(ca), साँचो_type_name);
		}
	} अन्यथा यदि (ca->type == साँचो_RSA) {
		/* Default to a good signature algorithm */
		साँचो_type_name = "rsa-sha2-512";
	}
	ca_fp = sshkey_fingerprint(ca, fingerprint_hash, SSH_FP_DEFAULT);

	finalise_cert_exts();
	लागि (i = 0; i < argc; i++) {
		/* Split list of principals */
		n = 0;
		यदि (cert_principals != रिक्त) {
			otmp = tmp = xstrdup(cert_principals);
			plist = रिक्त;
			लागि (; (cp = strsep(&tmp, ",")) != रिक्त; n++) {
				plist = xreallocarray(plist, n + 1, परिमाण(*plist));
				यदि (*(plist[n] = xstrdup(cp)) == '\0')
					fatal("Empty principal name");
			}
			मुक्त(otmp);
		}
		यदि (n > SSHKEY_CERT_MAX_PRINCIPALS)
			fatal("Too many certificate principals specified");

		tmp = tilde_expand_filename(argv[i], pw->pw_uid);
		यदि ((r = sshkey_load_public(tmp, &सार्वजनिक, &comment)) != 0)
			fatal_r(r, "load pubkey \"%s\"", tmp);
		यदि (sshkey_is_cert(सार्वजनिक))
			fatal_f("key \"%s\" type %s cannot be certified",
			    tmp, sshkey_type(सार्वजनिक));

		/* Prepare certificate to sign */
		यदि ((r = sshkey_to_certified(सार्वजनिक)) != 0)
			fatal_r(r, "Could not upgrade key %s to certificate", tmp);
		सार्वजनिक->cert->type = cert_साँचो_type;
		सार्वजनिक->cert->serial = (uint64_t)cert_serial;
		सार्वजनिक->cert->साँचो_id = xstrdup(cert_साँचो_id);
		सार्वजनिक->cert->nprincipals = n;
		सार्वजनिक->cert->principals = plist;
		सार्वजनिक->cert->valid_after = cert_valid_from;
		सार्वजनिक->cert->valid_before = cert_valid_to;
		prepare_options_buf(सार्वजनिक->cert->critical, OPTIONS_CRITICAL);
		prepare_options_buf(सार्वजनिक->cert->extensions,
		    OPTIONS_EXTENSIONS);
		यदि ((r = sshkey_from_private(ca,
		    &सार्वजनिक->cert->signature_साँचो)) != 0)
			fatal_r(r, "sshkey_from_private (ca key)");

		यदि (साँचो_in_agent) {
			यदि ((r = sshkey_certify_custom(सार्वजनिक, ca,
			    साँचो_type_name, sk_provider, रिक्त, agent_signer,
			    &agent_fd)) != 0)
				fatal_r(r, "Couldn't certify %s via agent", tmp);
		} अन्यथा {
			यदि (sshkey_is_sk(ca) &&
			    (ca->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
				notifier = notify_start(0,
				    "Confirm user presence for key %s %s",
				    sshkey_type(ca), ca_fp);
			}
			r = sshkey_certify(सार्वजनिक, ca, साँचो_type_name,
			    sk_provider, pin);
			notify_complete(notifier, "User presence confirmed");
			यदि (r != 0)
				fatal_r(r, "Couldn't certify key %s", tmp);
		}

		यदि ((cp = म_खोजप(tmp, '.')) != रिक्त && म_भेद(cp, ".pub") == 0)
			*cp = '\0';
		xasprintf(&out, "%s-cert.pub", tmp);
		मुक्त(tmp);

		यदि ((r = sshkey_save_public(सार्वजनिक, out, comment)) != 0) {
			fatal_r(r, "Unable to save public key to %s",
			    identity_file);
		}

		यदि (!quiet) {
			sshkey_format_cert_validity(सार्वजनिक->cert,
			    valid, परिमाण(valid));
			logit("Signed %s key %s: id \"%s\" serial %llu%s%s "
			    "valid %s", sshkey_cert_type(सार्वजनिक),
			    out, सार्वजनिक->cert->साँचो_id,
			    (अचिन्हित दीर्घ दीर्घ)सार्वजनिक->cert->serial,
			    cert_principals != रिक्त ? " for " : "",
			    cert_principals != रिक्त ? cert_principals : "",
			    valid);
		}

		sshkey_free(सार्वजनिक);
		मुक्त(out);
		मुक्त(comment);
		यदि (cert_serial_autoinc)
			cert_serial++;
	}
	यदि (pin != रिक्त)
		freezero(pin, म_माप(pin));
	sshkey_free(ca);
	मुक्त(ca_fp);
#ifdef ENABLE_PKCS11
	pkcs11_terminate();
#endif
}

स्थिर uint64_t
parse_relative_time(अचर वर्ण *s, समय_प्रकार now)
{
	int64_t mul, secs;

	mul = *s == '-' ? -1 : 1;

	यदि ((secs = convtime(s + 1)) == -1)
		fatal("Invalid relative certificate time %s", s);
	यदि (mul == -1 && secs > now)
		fatal("Certificate time %s cannot be represented", s);
	फर्काऊ now + (uint64_t)(secs * mul);
}

स्थिर शून्य
parse_hex_u64(अचर वर्ण *s, uint64_t *up)
{
	वर्ण *ep;
	अचिन्हित दीर्घ दीर्घ ull;

	त्रुटि_सं = 0;
	ull = strtoull(s, &ep, 16);
	यदि (*s == '\0' || *ep != '\0')
		fatal("Invalid certificate time: not a number");
	यदि (त्रुटि_सं == दुस्फल && ull == अच_दीर्घ_उच्च)
		fatal_fr(SSH_ERR_SYSTEM_ERROR, "Invalid certificate time");
	*up = (uint64_t)ull;
}

स्थिर शून्य
parse_cert_times(वर्ण *timespec)
{
	वर्ण *from, *to;
	समय_प्रकार now = समय(रिक्त);
	int64_t secs;

	/* +timespec relative to now */
	यदि (*timespec == '+' && म_अक्षर(timespec, ':') == रिक्त) {
		यदि ((secs = convtime(timespec + 1)) == -1)
			fatal("Invalid relative certificate life %s", timespec);
		cert_valid_to = now + secs;
		/*
		 * Backdate certificate one minute to avoid problems on hosts
		 * with poorly-synchronised clocks.
		 */
		cert_valid_from = ((now - 59)/ 60) * 60;
		फर्काऊ;
	}

	/*
	 * from:to, where
	 * from := [+-]timespec | YYYYMMDD | YYYYMMDDHHMMSS | 0x... | "always"
	 *   to := [+-]timespec | YYYYMMDD | YYYYMMDDHHMMSS | 0x... | "forever"
	 */
	from = xstrdup(timespec);
	to = म_अक्षर(from, ':');
	यदि (to == रिक्त || from == to || *(to + 1) == '\0')
		fatal("Invalid certificate life specification %s", timespec);
	*to++ = '\0';

	यदि (*from == '-' || *from == '+')
		cert_valid_from = parse_relative_time(from, now);
	अन्यथा यदि (म_भेद(from, "always") == 0)
		cert_valid_from = 0;
	अन्यथा यदि (म_भेदन(from, "0x", 2) == 0)
		parse_hex_u64(from, &cert_valid_from);
	अन्यथा यदि (parse_absolute_time(from, &cert_valid_from) != 0)
		fatal("Invalid from time \"%s\"", from);

	यदि (*to == '-' || *to == '+')
		cert_valid_to = parse_relative_time(to, now);
	अन्यथा यदि (म_भेद(to, "forever") == 0)
		cert_valid_to = ~(uint64_t)0;
	अन्यथा यदि (म_भेदन(to, "0x", 2) == 0)
		parse_hex_u64(to, &cert_valid_to);
	अन्यथा यदि (parse_absolute_time(to, &cert_valid_to) != 0)
		fatal("Invalid to time \"%s\"", to);

	यदि (cert_valid_to <= cert_valid_from)
		fatal("Empty certificate validity interval");
	मुक्त(from);
}

स्थिर शून्य
add_cert_option(वर्ण *opt)
{
	वर्ण *val, *cp;
	अचर वर्ण *p;
	पूर्णाङ्क iscrit = 0;

	यदि (strcasecmp(opt, "clear") == 0)
		certflags_flags = 0;
	अन्यथा यदि (strcasecmp(opt, "no-x11-forwarding") == 0)
		certflags_flags &= ~CERTOPT_X_FWD;
	अन्यथा यदि (strcasecmp(opt, "permit-x11-forwarding") == 0)
		certflags_flags |= CERTOPT_X_FWD;
	अन्यथा यदि (strcasecmp(opt, "no-agent-forwarding") == 0)
		certflags_flags &= ~CERTOPT_AGENT_FWD;
	अन्यथा यदि (strcasecmp(opt, "permit-agent-forwarding") == 0)
		certflags_flags |= CERTOPT_AGENT_FWD;
	अन्यथा यदि (strcasecmp(opt, "no-port-forwarding") == 0)
		certflags_flags &= ~CERTOPT_PORT_FWD;
	अन्यथा यदि (strcasecmp(opt, "permit-port-forwarding") == 0)
		certflags_flags |= CERTOPT_PORT_FWD;
	अन्यथा यदि (strcasecmp(opt, "no-pty") == 0)
		certflags_flags &= ~CERTOPT_PTY;
	अन्यथा यदि (strcasecmp(opt, "permit-pty") == 0)
		certflags_flags |= CERTOPT_PTY;
	अन्यथा यदि (strcasecmp(opt, "no-user-rc") == 0)
		certflags_flags &= ~CERTOPT_USER_RC;
	अन्यथा यदि (strcasecmp(opt, "permit-user-rc") == 0)
		certflags_flags |= CERTOPT_USER_RC;
	अन्यथा यदि (strcasecmp(opt, "touch-required") == 0)
		certflags_flags &= ~CERTOPT_NO_REQUIRE_USER_PRESENCE;
	अन्यथा यदि (strcasecmp(opt, "no-touch-required") == 0)
		certflags_flags |= CERTOPT_NO_REQUIRE_USER_PRESENCE;
	अन्यथा यदि (strcasecmp(opt, "no-verify-required") == 0)
		certflags_flags &= ~CERTOPT_REQUIRE_VERIFY;
	अन्यथा यदि (strcasecmp(opt, "verify-required") == 0)
		certflags_flags |= CERTOPT_REQUIRE_VERIFY;
	अन्यथा यदि ((p = strprefix(opt, "force-command=", 1)) != रिक्त) {
		यदि (*p == '\0')
			fatal("Empty force-command option");
		यदि (certflags_command != रिक्त)
			fatal("force-command already specified");
		certflags_command = xstrdup(p);
	} अन्यथा यदि ((p = strprefix(opt, "source-address=", 1)) != रिक्त) {
		यदि (*p == '\0')
			fatal("Empty source-address option");
		यदि (certflags_src_addr != रिक्त)
			fatal("source-address already specified");
		यदि (addr_match_cidr_list(रिक्त, p) != 0)
			fatal("Invalid source-address list");
		certflags_src_addr = xstrdup(p);
	} अन्यथा यदि (strprefix(opt, "extension:", 1) != रिक्त ||
		    (iscrit = (strprefix(opt, "critical:", 1) != रिक्त))) {
		val = xstrdup(म_अक्षर(opt, ':') + 1);
		यदि ((cp = म_अक्षर(val, '=')) != रिक्त)
			*cp++ = '\0';
		cert_ext_add(val, cp, iscrit);
		मुक्त(val);
	} अन्यथा
		fatal("Unsupported certificate option \"%s\"", opt);
}

स्थिर शून्य
show_options(संरचना sshbuf *optbuf, पूर्णाङ्क in_critical)
{
	वर्ण *name, *arg, *hex;
	संरचना sshbuf *options, *option = रिक्त;
	पूर्णाङ्क r;

	यदि ((options = sshbuf_fromb(optbuf)) == रिक्त)
		fatal_f("sshbuf_fromb failed");
	जबसम्म (sshbuf_len(options) != 0) {
		sshbuf_free(option);
		option = रिक्त;
		यदि ((r = sshbuf_get_cstring(options, &name, रिक्त)) != 0 ||
		    (r = sshbuf_froms(options, &option)) != 0)
			fatal_fr(r, "parse option");
		म_लिखो("                %s", name);
		यदि (!in_critical &&
		    (म_भेद(name, "permit-X11-forwarding") == 0 ||
		    म_भेद(name, "permit-agent-forwarding") == 0 ||
		    म_भेद(name, "permit-port-forwarding") == 0 ||
		    म_भेद(name, "permit-pty") == 0 ||
		    म_भेद(name, "permit-user-rc") == 0 ||
		    म_भेद(name, "no-touch-required") == 0)) {
			म_लिखो("\n");
		} अन्यथा यदि (in_critical &&
		    (म_भेद(name, "force-command") == 0 ||
		    म_भेद(name, "source-address") == 0)) {
			यदि ((r = sshbuf_get_cstring(option, &arg, रिक्त)) != 0)
				fatal_fr(r, "parse critical");
			म_लिखो(" %s\n", arg);
			मुक्त(arg);
		} अन्यथा यदि (in_critical &&
		    म_भेद(name, "verify-required") == 0) {
			म_लिखो("\n");
		} अन्यथा यदि (sshbuf_len(option) > 0) {
			hex = sshbuf_dtob16(option);
			म_लिखो(" UNKNOWN OPTION: %s (len %zu)\n",
			    hex, sshbuf_len(option));
			sshbuf_reset(option);
			मुक्त(hex);
		} अन्यथा
			म_लिखो(" UNKNOWN FLAG OPTION\n");
		मुक्त(name);
		यदि (sshbuf_len(option) != 0)
			fatal("Option corrupt: extra data at end");
	}
	sshbuf_free(option);
	sshbuf_free(options);
}

स्थिर शून्य
print_cert(संरचना sshkey *साँचो)
{
	वर्ण valid[64], *साँचो_fp, *ca_fp;
	u_int i;

	साँचो_fp = sshkey_fingerprint(साँचो, fingerprint_hash, SSH_FP_DEFAULT);
	ca_fp = sshkey_fingerprint(साँचो->cert->signature_साँचो,
	    fingerprint_hash, SSH_FP_DEFAULT);
	यदि (साँचो_fp == रिक्त || ca_fp == रिक्त)
		fatal_f("sshkey_fingerprint fail");
	sshkey_format_cert_validity(साँचो->cert, valid, परिमाण(valid));

	म_लिखो("        Type: %s %s certificate\n", sshkey_ssh_name(साँचो),
	    sshkey_cert_type(साँचो));
	म_लिखो("        Public key: %s %s\n", sshkey_type(साँचो), साँचो_fp);
	म_लिखो("        Signing CA: %s %s (using %s)\n",
	    sshkey_type(साँचो->cert->signature_साँचो), ca_fp,
	    साँचो->cert->signature_type);
	म_लिखो("        Key ID: \"%s\"\n", साँचो->cert->साँचो_id);
	म_लिखो("        Serial: %llu\n", (अचिन्हित दीर्घ दीर्घ)साँचो->cert->serial);
	म_लिखो("        Valid: %s\n", valid);
	म_लिखो("        Principals: ");
	यदि (साँचो->cert->nprincipals == 0)
		म_लिखो("(none)\n");
	अन्यथा {
		लागि (i = 0; i < साँचो->cert->nprincipals; i++)
			म_लिखो("\n                %s",
			    साँचो->cert->principals[i]);
		म_लिखो("\n");
	}
	म_लिखो("        Critical Options: ");
	यदि (sshbuf_len(साँचो->cert->critical) == 0)
		म_लिखो("(none)\n");
	अन्यथा {
		म_लिखो("\n");
		show_options(साँचो->cert->critical, 1);
	}
	म_लिखो("        Extensions: ");
	यदि (sshbuf_len(साँचो->cert->extensions) == 0)
		म_लिखो("(none)\n");
	अन्यथा {
		म_लिखो("\n");
		show_options(साँचो->cert->extensions, 0);
	}
	मुक्त(साँचो_fp);
	मुक्त(ca_fp);
}

स्थिर शून्य
do_show_cert(संरचना passwd *pw)
{
	संरचना sshkey *साँचो = रिक्त;
	संरचना stat st;
	पूर्णाङ्क r, is_stdin = 0, ok = 0;
	खाता *f;
	वर्ण *cp, *पङ्क्ति = रिक्त;
	अचर वर्ण *path;
	माप_प्रकार linesize = 0;
	u_long lnum = 0;

	यदि (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	यदि (म_भेद(identity_file, "-") != 0 && stat(identity_file, &st) == -1)
		fatal("%s: %s: %s", __progname, identity_file, म_त्रुटि(त्रुटि_सं));

	path = identity_file;
	यदि (म_भेद(path, "-") == 0) {
		f = मानक_निवेश;
		path = "(stdin)";
		is_stdin = 1;
	} अन्यथा यदि ((f = ख_खोलो(identity_file, "r")) == रिक्त)
		fatal("fopen %s: %s", identity_file, म_त्रुटि(त्रुटि_सं));

	जबसम्म (getline(&पङ्क्ति, &linesize, f) != -1) {
		lnum++;
		sshkey_free(साँचो);
		साँचो = रिक्त;
		/* Trim leading space and comments */
		cp = पङ्क्ति + म_अखोज(पङ्क्ति, " \t");
		यदि (*cp == '#' || *cp == '\0')
			जारी;
		यदि ((साँचो = sshkey_new(साँचो_UNSPEC)) == रिक्त)
			fatal("sshkey_new");
		यदि ((r = sshkey_read(साँचो, &cp)) != 0) {
			error_r(r, "%s:%lu: invalid key", path, lnum);
			जारी;
		}
		यदि (!sshkey_is_cert(साँचो)) {
			error("%s:%lu is not a certificate", path, lnum);
			जारी;
		}
		ok = 1;
		यदि (!is_stdin && lnum == 1)
			म_लिखो("%s:\n", path);
		अन्यथा
			म_लिखो("%s:%lu:\n", path, lnum);
		print_cert(साँचो);
	}
	मुक्त(पङ्क्ति);
	sshkey_free(साँचो);
	ख_बंद(f);
	निकास(ok ? 0 : 1);
}

स्थिर शून्य
load_krl(अचर वर्ण *path, संरचना ssh_krl **krlp)
{
	संरचना sshbuf *krlbuf;
	पूर्णाङ्क r;

	यदि ((r = sshbuf_load_file(path, &krlbuf)) != 0)
		fatal_r(r, "Unable to load KRL %s", path);
	/* XXX check sigs */
	यदि ((r = ssh_krl_from_blob(krlbuf, krlp)) != 0 ||
	    *krlp == रिक्त)
		fatal_r(r, "Invalid KRL file %s", path);
	sshbuf_free(krlbuf);
}

स्थिर शून्य
hash_to_blob(अचर वर्ण *cp, u_char **blobp, माप_प्रकार *lenp,
    अचर वर्ण *file, u_long lnum)
{
	वर्ण *tmp;
	माप_प्रकार tlen;
	संरचना sshbuf *b;
	पूर्णाङ्क r;

	यदि ((cp = strprefix(cp, "SHA256:", 0)) == रिक्त)
		fatal("%s:%lu: unsupported hash algorithm", file, lnum);

	/*
	 * OpenSSH base64 hashes omit trailing '='
	 * characters; put them back for decode.
	 */
	यदि ((tlen = म_माप(cp)) >= SIZE_MAX - 5)
		fatal_f("hash too long: %zu bytes", tlen);
	tmp = xmalloc(tlen + 4 + 1);
	strlcpy(tmp, cp, tlen + 1);
	जबसम्म ((tlen % 4) != 0) {
		tmp[tlen++] = '=';
		tmp[tlen] = '\0';
	}
	यदि ((b = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshbuf_b64tod(b, tmp)) != 0)
		fatal_r(r, "%s:%lu: decode hash failed", file, lnum);
	मुक्त(tmp);
	*lenp = sshbuf_len(b);
	*blobp = xmalloc(*lenp);
	स_नकल(*blobp, sshbuf_ptr(b), *lenp);
	sshbuf_free(b);
}

स्थिर शून्य
update_krl_from_file(संरचना passwd *pw, अचर वर्ण *file, पूर्णाङ्क wild_ca,
    अचर संरचना sshkey *ca, संरचना ssh_krl *krl)
{
	संरचना sshkey *साँचो = रिक्त;
	u_long lnum = 0;
	वर्ण *path, *cp, *ep, *पङ्क्ति = रिक्त;
	u_char *blob = रिक्त;
	माप_प्रकार blen = 0, linesize = 0;
	अचिन्हित दीर्घ दीर्घ serial, serial2;
	पूर्णाङ्क i, was_explicit_साँचो, was_sha1, was_sha256, was_hash, r;
	खाता *krl_spec;

	path = tilde_expand_filename(file, pw->pw_uid);
	यदि (म_भेद(path, "-") == 0) {
		krl_spec = मानक_निवेश;
		मुक्त(path);
		path = xstrdup("(standard input)");
	} अन्यथा यदि ((krl_spec = ख_खोलो(path, "r")) == रिक्त)
		fatal("fopen %s: %s", path, म_त्रुटि(त्रुटि_सं));

	यदि (!quiet)
		म_लिखो("Revoking from %s\n", path);
	जबसम्म (getline(&पङ्क्ति, &linesize, krl_spec) != -1) {
		यदि (linesize >= पूर्णांक_उच्च) {
			fatal_f("%s contains unparsable line, len=%zu",
			    path, linesize);
		}
		lnum++;
		was_explicit_साँचो = was_sha1 = was_sha256 = was_hash = 0;
		cp = पङ्क्ति + म_अखोज(पङ्क्ति, " \t");
		/* Trim trailing space, comments and strip \n */
		लागि (i = 0, r = -1; cp[i] != '\0'; i++) {
			यदि (cp[i] == '#' || cp[i] == '\n') {
				cp[i] = '\0';
				रोक;
			}
			यदि (cp[i] == ' ' || cp[i] == '\t') {
				/* Remember the start of a span of whitespace */
				यदि (r == -1)
					r = i;
			} अन्यथा
				r = -1;
		}
		यदि (r != -1)
			cp[r] = '\0';
		यदि (*cp == '\0')
			जारी;
		यदि (strncasecmp(cp, "serial:", 7) == 0) {
			यदि (ca == रिक्त && !wild_ca) {
				fatal("revoking certificates by serial number "
				    "requires specification of a CA key");
			}
			cp += 7;
			cp = cp + म_अखोज(cp, " \t");
			त्रुटि_सं = 0;
			serial = strtoull(cp, &ep, 0);
			यदि (*cp == '\0' || (*ep != '\0' && *ep != '-'))
				fatal("%s:%lu: invalid serial \"%s\"",
				    path, lnum, cp);
			यदि (त्रुटि_सं == दुस्फल && serial == ULLONG_MAX)
				fatal("%s:%lu: serial out of range",
				    path, lnum);
			serial2 = serial;
			यदि (*ep == '-') {
				cp = ep + 1;
				त्रुटि_सं = 0;
				serial2 = strtoull(cp, &ep, 0);
				यदि (*cp == '\0' || *ep != '\0')
					fatal("%s:%lu: invalid serial \"%s\"",
					    path, lnum, cp);
				यदि (त्रुटि_सं == दुस्फल && serial2 == ULLONG_MAX)
					fatal("%s:%lu: serial out of range",
					    path, lnum);
				यदि (serial2 <= serial)
					fatal("%s:%lu: invalid serial range "
					    "%llu:%llu", path, lnum,
					    (अचिन्हित दीर्घ दीर्घ)serial,
					    (अचिन्हित दीर्घ दीर्घ)serial2);
			}
			यदि (ssh_krl_revoke_cert_by_serial_range(krl,
			    ca, serial, serial2) != 0) {
				fatal_f("revoke serial failed");
			}
		} अन्यथा यदि (strncasecmp(cp, "id:", 3) == 0) {
			यदि (ca == रिक्त && !wild_ca) {
				fatal("revoking certificates by key ID "
				    "requires specification of a CA key");
			}
			cp += 3;
			cp = cp + म_अखोज(cp, " \t");
			यदि (ssh_krl_revoke_cert_by_साँचो_id(krl, ca, cp) != 0)
				fatal_f("revoke key ID failed");
		} अन्यथा यदि (strncasecmp(cp, "hash:", 5) == 0) {
			cp += 5;
			cp = cp + म_अखोज(cp, " \t");
			hash_to_blob(cp, &blob, &blen, file, lnum);
			यदि ((r = ssh_krl_revoke_साँचो_sha256(krl,
			    blob, blen)) != 0)
				fatal_fr(r, "revoke key failed");
			मुक्त(blob);
			blob = रिक्त;
			blen = 0;
		} अन्यथा {
			यदि (strncasecmp(cp, "key:", 4) == 0) {
				cp += 4;
				cp = cp + म_अखोज(cp, " \t");
				was_explicit_साँचो = 1;
			} अन्यथा यदि (strncasecmp(cp, "sha1:", 5) == 0) {
				cp += 5;
				cp = cp + म_अखोज(cp, " \t");
				was_sha1 = 1;
			} अन्यथा यदि (strncasecmp(cp, "sha256:", 7) == 0) {
				cp += 7;
				cp = cp + म_अखोज(cp, " \t");
				was_sha256 = 1;
				/*
				 * Just try to process the line as a key.
				 * Parsing will fail if it isn't.
				 */
			}
			यदि ((साँचो = sshkey_new(साँचो_UNSPEC)) == रिक्त)
				fatal("sshkey_new");
			यदि ((r = sshkey_read(साँचो, &cp)) != 0)
				fatal_r(r, "%s:%lu: invalid key", path, lnum);
			यदि (was_explicit_साँचो)
				r = ssh_krl_revoke_साँचो_explicit(krl, साँचो);
			अन्यथा यदि (was_sha1) {
				यदि (sshkey_fingerprint_raw(साँचो,
				    SSH_DIGEST_SHA1, &blob, &blen) != 0) {
					fatal("%s:%lu: fingerprint failed",
					    file, lnum);
				}
				r = ssh_krl_revoke_साँचो_sha1(krl, blob, blen);
			} अन्यथा यदि (was_sha256) {
				यदि (sshkey_fingerprint_raw(साँचो,
				    SSH_DIGEST_SHA256, &blob, &blen) != 0) {
					fatal("%s:%lu: fingerprint failed",
					    file, lnum);
				}
				r = ssh_krl_revoke_साँचो_sha256(krl, blob, blen);
			} अन्यथा
				r = ssh_krl_revoke_साँचो(krl, साँचो);
			यदि (r != 0)
				fatal_fr(r, "revoke key failed");
			freezero(blob, blen);
			blob = रिक्त;
			blen = 0;
			sshkey_free(साँचो);
		}
	}
	यदि (म_भेद(path, "-") != 0)
		ख_बंद(krl_spec);
	मुक्त(पङ्क्ति);
	मुक्त(path);
}

स्थिर शून्य
do_gen_krl(संरचना passwd *pw, पूर्णाङ्क updating, अचर वर्ण *ca_साँचो_path,
    अचिन्हित दीर्घ दीर्घ krl_version, अचर वर्ण *krl_comment,
    पूर्णाङ्क argc, वर्ण **argv)
{
	संरचना ssh_krl *krl;
	संरचना stat sb;
	संरचना sshkey *ca = रिक्त;
	पूर्णाङ्क i, r, wild_ca = 0;
	वर्ण *tmp;
	संरचना sshbuf *kbuf;

	यदि (*identity_file == '\0')
		fatal("KRL generation requires an output file");
	यदि (stat(identity_file, &sb) == -1) {
		यदि (त्रुटि_सं != ENOENT)
			fatal("Cannot access KRL \"%s\": %s",
			    identity_file, म_त्रुटि(त्रुटि_सं));
		यदि (updating)
			fatal("KRL \"%s\" does not exist", identity_file);
	}
	यदि (ca_साँचो_path != रिक्त) {
		यदि (strcasecmp(ca_साँचो_path, "none") == 0)
			wild_ca = 1;
		अन्यथा {
			tmp = tilde_expand_filename(ca_साँचो_path, pw->pw_uid);
			यदि ((r = sshkey_load_public(tmp, &ca, रिक्त)) != 0)
				fatal_r(r, "Cannot load CA public key %s", tmp);
			मुक्त(tmp);
		}
	}

	यदि (updating)
		load_krl(identity_file, &krl);
	अन्यथा यदि ((krl = ssh_krl_init()) == रिक्त)
		fatal("couldn't create KRL");

	यदि (krl_version != 0)
		ssh_krl_set_version(krl, krl_version);
	यदि (krl_comment != रिक्त)
		ssh_krl_set_comment(krl, krl_comment);

	लागि (i = 0; i < argc; i++)
		update_krl_from_file(pw, argv[i], wild_ca, ca, krl);

	यदि ((kbuf = sshbuf_new()) == रिक्त)
		fatal("sshbuf_new failed");
	यदि (ssh_krl_to_blob(krl, kbuf) != 0)
		fatal("Couldn't generate KRL");
	यदि ((r = sshbuf_write_file(identity_file, kbuf)) != 0)
		fatal("write %s: %s", identity_file, म_त्रुटि(त्रुटि_सं));
	sshbuf_free(kbuf);
	ssh_krl_free(krl);
	sshkey_free(ca);
}

स्थिर शून्य
do_check_krl(संरचना passwd *pw, पूर्णाङ्क print_krl, पूर्णाङ्क argc, वर्ण **argv)
{
	पूर्णाङ्क i, r, ret = 0;
	वर्ण *comment;
	संरचना ssh_krl *krl;
	संरचना sshkey *k;

	यदि (*identity_file == '\0')
		fatal("KRL checking requires an input file");
	load_krl(identity_file, &krl);
	यदि (print_krl)
		krl_dump(krl, मानक_निकास);
	लागि (i = 0; i < argc; i++) {
		यदि ((r = sshkey_load_public(argv[i], &k, &comment)) != 0)
			fatal_r(r, "Cannot load public key %s", argv[i]);
		r = ssh_krl_check_साँचो(krl, k);
		म_लिखो("%s%s%s%s: %s\n", argv[i],
		    *comment ? " (" : "", comment, *comment ? ")" : "",
		    r == 0 ? "ok" : "REVOKED");
		यदि (r != 0)
			ret = 1;
		sshkey_free(k);
		मुक्त(comment);
	}
	ssh_krl_free(krl);
	निकास(ret);
}

स्थिर संरचना sshkey *
load_sign_साँचो(अचर वर्ण *keypath, अचर संरचना sshkey *pubkey)
{
	माप_प्रकार i, slen, plen = म_माप(keypath);
	वर्ण *privpath = xstrdup(keypath);
	स्थिर अचर वर्ण * अचर suffixes[] = { "-cert.pub", ".pub", रिक्त };
	संरचना sshkey *ret = रिक्त, *privkey = रिक्त;
	पूर्णाङ्क r, waspub = 0;
	संरचना stat st;

	/*
	 * If passed a public key filename, then try to locate the corresponding
	 * private key. This lets us specify certificates on the command-line
	 * and have ssh-keygen find the appropriate private key.
	 */
	लागि (i = 0; suffixes[i]; i++) {
		slen = म_माप(suffixes[i]);
		यदि (plen <= slen ||
		    म_भेद(privpath + plen - slen, suffixes[i]) != 0)
			जारी;
		privpath[plen - slen] = '\0';
		debug_f("%s looks like a public key, using private key "
		    "path %s instead", keypath, privpath);
		waspub = 1;
	}
	यदि (waspub && stat(privpath, &st) != 0 && त्रुटि_सं == ENOENT)
		fatal("No private key found for public key \"%s\"", keypath);
	यदि ((r = sshkey_load_private(privpath, "", &privkey, रिक्त)) != 0 &&
	    (r != SSH_ERR_साँचो_WRONG_PASSPHRASE)) {
		debug_fr(r, "load private key \"%s\"", privpath);
		fatal("No private key found for \"%s\"", privpath);
	} अन्यथा यदि (privkey == रिक्त)
		privkey = load_identity(privpath, रिक्त);

	यदि (!sshkey_equal_public(pubkey, privkey)) {
		error("Public key %s doesn't match private %s",
		    keypath, privpath);
		गच्छ done;
	}
	यदि (sshkey_is_cert(pubkey) && !sshkey_is_cert(privkey)) {
		/*
		 * Graft the certificate onto the private key to make
		 * it capable of signing.
		 */
		यदि ((r = sshkey_to_certified(privkey)) != 0) {
			error_fr(r, "sshkey_to_certified");
			गच्छ done;
		}
		यदि ((r = sshkey_cert_copy(pubkey, privkey)) != 0) {
			error_fr(r, "sshkey_cert_copy");
			गच्छ done;
		}
	}
	/* success */
	ret = privkey;
	privkey = रिक्त;
 done:
	sshkey_free(privkey);
	मुक्त(privpath);
	फर्काऊ ret;
}

स्थिर पूर्णाङ्क
sign_one(संरचना sshkey *signkey, अचर वर्ण *filename, पूर्णाङ्क fd,
    अचर वर्ण *sig_namespace, अचर वर्ण *hashalg, sshsig_signer *signer,
    शून्य *signer_ctx)
{
	संरचना sshbuf *sigbuf = रिक्त, *abuf = रिक्त;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR, wfd = -1, oerrno;
	वर्ण *wfile = रिक्त, *asig = रिक्त, *fp = रिक्त;
	वर्ण *pin = रिक्त, *prompt = रिक्त;

	यदि (!quiet) {
		यदि (fd == STDIN_FILENO)
			ख_लिखो(मानक_त्रुटि, "Signing data on standard input\n");
		अन्यथा
			ख_लिखो(मानक_त्रुटि, "Signing file %s\n", filename);
	}
	यदि (signer == रिक्त && sshkey_is_sk(signkey)) {
		यदि ((signkey->sk_flags & SSH_SK_USER_VERIFICATION_REQD)) {
			xasprintf(&prompt, "Enter PIN for %s key: ",
			    sshkey_type(signkey));
			यदि ((pin = read_passphrase(prompt,
			    RP_ALLOW_STDIN)) == रिक्त)
				fatal_f("couldn't read PIN");
		}
		यदि ((signkey->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
			यदि ((fp = sshkey_fingerprint(signkey, fingerprint_hash,
			    SSH_FP_DEFAULT)) == रिक्त)
				fatal_f("fingerprint failed");
			ख_लिखो(मानक_त्रुटि, "Confirm user presence for key %s %s\n",
			    sshkey_type(signkey), fp);
			मुक्त(fp);
		}
	}
	यदि ((r = sshsig_sign_fd(signkey, hashalg, sk_provider, pin,
	    fd, sig_namespace, &sigbuf, signer, signer_ctx)) != 0) {
		error_r(r, "Signing %s failed", filename);
		गच्छ out;
	}
	यदि ((r = sshsig_armor(sigbuf, &abuf)) != 0) {
		error_fr(r, "sshsig_armor");
		गच्छ out;
	}
	यदि ((asig = sshbuf_dup_string(abuf)) == रिक्त) {
		error_f("buffer error");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}

	यदि (fd == STDIN_FILENO) {
		ख_माला_दो(asig, मानक_निकास);
		ख_साफ(मानक_निकास);
	} अन्यथा {
		xasprintf(&wfile, "%s.sig", filename);
		यदि (confirm_overwrite(wfile)) {
			यदि ((wfd = खोलो(wfile, O_WRONLY|O_CREAT|O_TRUNC,
			    0666)) == -1) {
				oerrno = त्रुटि_सं;
				error("Cannot open %s: %s",
				    wfile, म_त्रुटि(त्रुटि_सं));
				त्रुटि_सं = oerrno;
				r = SSH_ERR_SYSTEM_ERROR;
				गच्छ out;
			}
			यदि (atomicio(vwrite, wfd, asig,
			    म_माप(asig)) != म_माप(asig)) {
				oerrno = त्रुटि_सं;
				error("Cannot write to %s: %s",
				    wfile, म_त्रुटि(त्रुटि_सं));
				त्रुटि_सं = oerrno;
				r = SSH_ERR_SYSTEM_ERROR;
				गच्छ out;
			}
			यदि (!quiet) {
				ख_लिखो(मानक_त्रुटि, "Write signature to %s\n",
				    wfile);
			}
		}
	}
	/* success */
	r = 0;
 out:
	मुक्त(wfile);
	मुक्त(prompt);
	मुक्त(asig);
	यदि (pin != रिक्त)
		freezero(pin, म_माप(pin));
	sshbuf_free(abuf);
	sshbuf_free(sigbuf);
	यदि (wfd != -1)
		बंद(wfd);
	फर्काऊ r;
}

स्थिर पूर्णाङ्क
sig_process_opts(वर्ण * अचर *opts, माप_प्रकार nopts, वर्ण **hashalgp,
    uint64_t *verify_timep, पूर्णाङ्क *print_pubkey)
{
	माप_प्रकार i;
	समय_प्रकार now;
	अचर वर्ण *p;

	यदि (verify_timep != रिक्त)
		*verify_timep = 0;
	यदि (print_pubkey != रिक्त)
		*print_pubkey = 0;
	यदि (hashalgp != रिक्त)
		*hashalgp = रिक्त;
	लागि (i = 0; i < nopts; i++) {
		यदि (hashalgp != रिक्त &&
		    (p = strprefix(opts[i], "hashalg=", 1)) != रिक्त) {
			*hashalgp = xstrdup(p);
		} अन्यथा यदि (verify_timep &&
		    (p = strprefix(opts[i], "verify-time=", 1)) != रिक्त) {
			यदि (parse_absolute_time(p, verify_timep) != 0 ||
			    *verify_timep == 0) {
				error("Invalid \"verify-time\" option");
				फर्काऊ SSH_ERR_INVALID_ARGUMENT;
			}
		} अन्यथा यदि (print_pubkey &&
		    strcasecmp(opts[i], "print-pubkey") == 0) {
			*print_pubkey = 1;
		} अन्यथा {
			error("Invalid option \"%s\"", opts[i]);
			फर्काऊ SSH_ERR_INVALID_ARGUMENT;
		}
	}
	यदि (verify_timep && *verify_timep == 0) {
		यदि ((now = समय(रिक्त)) < 0) {
			error("Time is before epoch");
			फर्काऊ SSH_ERR_INVALID_ARGUMENT;
		}
		*verify_timep = (uint64_t)now;
	}
	फर्काऊ 0;
}


स्थिर पूर्णाङ्क
sig_sign(अचर वर्ण *keypath, अचर वर्ण *sig_namespace, पूर्णाङ्क require_agent,
    पूर्णाङ्क argc, वर्ण **argv, वर्ण * अचर *opts, माप_प्रकार nopts)
{
	पूर्णाङ्क i, fd = -1, r, ret = -1;
	पूर्णाङ्क agent_fd = -1;
	संरचना sshkey *pubkey = रिक्त, *privkey = रिक्त, *signkey = रिक्त;
	sshsig_signer *signer = रिक्त;
	वर्ण *hashalg = रिक्त;

	/* Check file arguments. */
	लागि (i = 0; i < argc; i++) {
		यदि (म_भेद(argv[i], "-") != 0)
			जारी;
		यदि (i > 0 || argc > 1)
			fatal("Cannot sign mix of paths and standard input");
	}

	यदि (sig_process_opts(opts, nopts, &hashalg, रिक्त, रिक्त) != 0)
		गच्छ done; /* error already logged */

	यदि ((r = sshkey_load_public(keypath, &pubkey, रिक्त)) != 0) {
		error_r(r, "Couldn't load public key %s", keypath);
		गच्छ done;
	}

	यदि ((r = ssh_get_authentication_socket(&agent_fd)) != 0) {
		यदि (require_agent)
			fatal("Couldn't get agent socket");
		debug_r(r, "Couldn't get agent socket");
	} अन्यथा {
		यदि ((r = ssh_agent_has_साँचो(agent_fd, pubkey)) == 0)
			signer = agent_signer;
		अन्यथा {
			यदि (require_agent)
				fatal("Couldn't find key in agent");
			debug_r(r, "Couldn't find key in agent");
		}
	}

	यदि (signer == रिक्त) {
		/* Not using agent - try to load private key */
		यदि ((privkey = load_sign_साँचो(keypath, pubkey)) == रिक्त)
			गच्छ done;
		signkey = privkey;
	} अन्यथा {
		/* Will use key in agent */
		signkey = pubkey;
	}

	यदि (argc == 0) {
		यदि ((r = sign_one(signkey, "(stdin)", STDIN_FILENO,
		    sig_namespace, hashalg, signer, &agent_fd)) != 0)
			गच्छ done;
	} अन्यथा {
		लागि (i = 0; i < argc; i++) {
			यदि (म_भेद(argv[i], "-") == 0)
				fd = STDIN_FILENO;
			अन्यथा यदि ((fd = खोलो(argv[i], O_RDONLY)) == -1) {
				error("Cannot open %s for signing: %s",
				    argv[i], म_त्रुटि(त्रुटि_सं));
				गच्छ done;
			}
			यदि ((r = sign_one(signkey, argv[i], fd, sig_namespace,
			    hashalg, signer, &agent_fd)) != 0)
				गच्छ done;
			यदि (fd != STDIN_FILENO)
				बंद(fd);
			fd = -1;
		}
	}

	ret = 0;
done:
	यदि (fd != -1 && fd != STDIN_FILENO)
		बंद(fd);
	sshkey_free(pubkey);
	sshkey_free(privkey);
	मुक्त(hashalg);
	फर्काऊ ret;
}

स्थिर पूर्णाङ्क
sig_verify(अचर वर्ण *signature, अचर वर्ण *sig_namespace,
    अचर वर्ण *principal, अचर वर्ण *allowed_साँचोहरू, अचर वर्ण *revoked_साँचोहरू,
    वर्ण * अचर *opts, माप_प्रकार nopts)
{
	पूर्णाङ्क r, ret = -1;
	पूर्णाङ्क print_pubkey = 0;
	संरचना sshbuf *sigbuf = रिक्त, *abuf = रिक्त;
	संरचना sshkey *sign_साँचो = रिक्त;
	वर्ण *fp = रिक्त;
	संरचना sshkey_sig_details *sig_details = रिक्त;
	uint64_t verify_time = 0;

	यदि (sig_process_opts(opts, nopts, रिक्त, &verify_time,
	    &print_pubkey) != 0)
		गच्छ done; /* error already logged */

	स_रखो(&sig_details, 0, परिमाण(sig_details));
	यदि ((r = sshbuf_load_file(signature, &abuf)) != 0) {
		error_r(r, "Couldn't read signature file");
		गच्छ done;
	}

	यदि ((r = sshsig_dearmor(abuf, &sigbuf)) != 0) {
		error_fr(r, "sshsig_armor");
		गच्छ done;
	}
	यदि ((r = sshsig_verify_fd(sigbuf, STDIN_FILENO, sig_namespace,
	    &sign_साँचो, &sig_details)) != 0)
		गच्छ done; /* sshsig_verify() prints error */

	यदि ((fp = sshkey_fingerprint(sign_साँचो, fingerprint_hash,
	    SSH_FP_DEFAULT)) == रिक्त)
		fatal_f("sshkey_fingerprint failed");
	debug("Valid (unverified) signature from key %s", fp);
	यदि (sig_details != रिक्त) {
		debug2_f("signature details: counter = %u, flags = 0x%02x",
		    sig_details->sk_counter, sig_details->sk_flags);
	}
	मुक्त(fp);
	fp = रिक्त;

	यदि (revoked_साँचोहरू != रिक्त) {
		यदि ((r = sshkey_check_revoked(sign_साँचो, revoked_साँचोहरू)) != 0) {
			debug3_fr(r, "sshkey_check_revoked");
			गच्छ done;
		}
	}

	यदि (allowed_साँचोहरू != रिक्त && (r = sshsig_check_allowed_साँचोहरू(allowed_साँचोहरू,
	    sign_साँचो, principal, sig_namespace, verify_time)) != 0) {
		debug3_fr(r, "sshsig_check_allowed_keys");
		गच्छ done;
	}
	/* success */
	ret = 0;
done:
	यदि (!quiet) {
		यदि (ret == 0) {
			यदि ((fp = sshkey_fingerprint(sign_साँचो, fingerprint_hash,
			    SSH_FP_DEFAULT)) == रिक्त)
				fatal_f("sshkey_fingerprint failed");
			यदि (principal == रिक्त) {
				म_लिखो("Good \"%s\" signature with %s key %s\n",
				    sig_namespace, sshkey_type(sign_साँचो), fp);

			} अन्यथा {
				म_लिखो("Good \"%s\" signature for %s with %s key %s\n",
				    sig_namespace, principal,
				    sshkey_type(sign_साँचो), fp);
			}
		} अन्यथा {
			म_लिखो("Could not verify signature.\n");
		}
	}
	/* Print the signature key if requested */
	यदि (ret == 0 && print_pubkey && sign_साँचो != रिक्त) {
		यदि ((r = sshkey_write(sign_साँचो, मानक_निकास)) == 0)
			ख_अक्षर_दो('\n', मानक_निकास);
		अन्यथा {
			error_r(r, "Could not print public key.\n");
			ret = -1;
		}
	}
	sshbuf_free(sigbuf);
	sshbuf_free(abuf);
	sshkey_free(sign_साँचो);
	sshkey_sig_details_free(sig_details);
	मुक्त(fp);
	फर्काऊ ret;
}

स्थिर पूर्णाङ्क
sig_find_principals(अचर वर्ण *signature, अचर वर्ण *allowed_साँचोहरू,
    वर्ण * अचर *opts, माप_प्रकार nopts)
{
	पूर्णाङ्क r, ret = -1;
	संरचना sshbuf *sigbuf = रिक्त, *abuf = रिक्त;
	संरचना sshkey *sign_साँचो = रिक्त;
	वर्ण *principals = रिक्त, *cp, *tmp;
	uint64_t verify_time = 0;

	यदि (sig_process_opts(opts, nopts, रिक्त, &verify_time, रिक्त) != 0)
		गच्छ done; /* error already logged */

	यदि ((r = sshbuf_load_file(signature, &abuf)) != 0) {
		error_r(r, "Couldn't read signature file");
		गच्छ done;
	}
	यदि ((r = sshsig_dearmor(abuf, &sigbuf)) != 0) {
		error_fr(r, "sshsig_armor");
		गच्छ done;
	}
	यदि ((r = sshsig_get_pubkey(sigbuf, &sign_साँचो)) != 0) {
		error_fr(r, "sshsig_get_pubkey");
		गच्छ done;
	}
	यदि ((r = sshsig_find_principals(allowed_साँचोहरू, sign_साँचो,
	    verify_time, &principals)) != 0) {
		यदि (r != SSH_ERR_साँचो_NOT_FOUND)
			error_fr(r, "sshsig_find_principal");
		गच्छ done;
	}
	ret = 0;
done:
	यदि (ret == 0 ) {
		/* Emit matching principals one per line */
		tmp = principals;
		जबसम्म ((cp = strsep(&tmp, ",")) != रिक्त && *cp != '\0')
			माला_दो(cp);
	} अन्यथा {
		ख_लिखो(मानक_त्रुटि, "No principal matched.\n");
	}
	sshbuf_free(sigbuf);
	sshbuf_free(abuf);
	sshkey_free(sign_साँचो);
	मुक्त(principals);
	फर्काऊ ret;
}

स्थिर पूर्णाङ्क
sig_match_principals(अचर वर्ण *allowed_साँचोहरू, वर्ण *principal,
	वर्ण * अचर *opts, माप_प्रकार nopts)
{
	पूर्णाङ्क r;
	वर्ण **principals = रिक्त;
	माप_प्रकार i, nprincipals = 0;

	यदि ((r = sig_process_opts(opts, nopts, रिक्त, रिक्त, रिक्त)) != 0)
		फर्काऊ r; /* error already logged */

	यदि ((r = sshsig_match_principals(allowed_साँचोहरू, principal,
	    &principals, &nprincipals)) != 0) {
		debug_f("match: %s", ssh_err(r));
		ख_लिखो(मानक_त्रुटि, "No principal matched.\n");
		फर्काऊ r;
	}
	लागि (i = 0; i < nprincipals; i++) {
		म_लिखो("%s\n", principals[i]);
		मुक्त(principals[i]);
	}
	मुक्त(principals);

	फर्काऊ 0;
}

स्थिर शून्य
do_moduli_gen(अचर वर्ण *out_file, वर्ण **opts, माप_प्रकार nopts)
{
#ifdef WITH_OPENSSL
	/* Moduli generation/screening */
	BIGNUM *start = रिक्त;
	पूर्णाङ्क moduli_bits = 0;
	खाता *out;
	माप_प्रकार i;
	अचर वर्ण *errstr, *p;

	/* Parse options */
	लागि (i = 0; i < nopts; i++) {
		यदि ((p = strprefix(opts[i], "start=", 0)) != रिक्त) {
			/* XXX - also compare length against bits */
			यदि (BN_hex2bn(&start, p) == 0)
				fatal("Invalid start point.");
		} अन्यथा यदि ((p = strprefix(opts[i], "bits=", 0)) != रिक्त) {
			moduli_bits = (पूर्णाङ्क)strtonum(p, 1, पूर्णांक_उच्च, &errstr);
			यदि (errstr) {
				fatal("Invalid number: %s (%s)", p, errstr);
			}
		} अन्यथा {
			fatal("Option \"%s\" is unsupported for moduli "
			    "generation", opts[i]);
		}
	}

	यदि (म_भेद(out_file, "-") == 0)
		out = मानक_निकास;
	अन्यथा यदि ((out = ख_खोलो(out_file, "w")) == रिक्त) {
		fatal("Couldn't open modulus candidate file \"%s\": %s",
		    out_file, म_त्रुटि(त्रुटि_सं));
	}
	रखो_भबफ(out, रिक्त, _IOLBF, 0);

	यदि (moduli_bits == 0)
		moduli_bits = DEFAULT_BITS;
	यदि (gen_candidates(out, moduli_bits, start) != 0)
		fatal("modulus candidate generation failed");
#अन्यथा /* WITH_OPENSSL */
	fatal("Moduli generation is not supported");
#endif /* WITH_OPENSSL */
}

स्थिर शून्य
do_moduli_screen(अचर वर्ण *out_file, वर्ण **opts, माप_प्रकार nopts)
{
#ifdef WITH_OPENSSL
	/* Moduli generation/screening */
	वर्ण *checkpoint = रिक्त;
	uint32_t generator_wanted = 0;
	अचिन्हित दीर्घ start_lineno = 0, पङ्क्तिहरू_to_process = 0;
	पूर्णाङ्क अविभाज्य_tests = 0;
	खाता *out, *in = मानक_निवेश;
	माप_प्रकार i;
	अचर वर्ण *errstr, *p;

	/* Parse options */
	लागि (i = 0; i < nopts; i++) {
		यदि ((p = strprefix(opts[i], "lines=", 0)) != रिक्त) {
			पङ्क्तिहरू_to_process = म_से_अदीर्घ(p, रिक्त, 10);
		} अन्यथा यदि ((p = strprefix(opts[i], "start-line=", 0)) != रिक्त) {
			start_lineno = म_से_अदीर्घ(p, रिक्त, 10);
		} अन्यथा यदि ((p = strprefix(opts[i], "checkpoint=", 0)) != रिक्त) {
			मुक्त(checkpoint);
			checkpoint = xstrdup(p);
		} अन्यथा यदि ((p = strprefix(opts[i], "generator=", 0)) != रिक्त) {
			generator_wanted = (uint32_t)strtonum(p, 1, अच_पूर्णांक_उच्च,
			    &errstr);
			यदि (errstr != रिक्त) {
				fatal("Generator invalid: %s (%s)", p, errstr);
			}
		} अन्यथा यदि ((p = strprefix(opts[i], "prime-tests=", 0)) != रिक्त) {
			अविभाज्य_tests = (पूर्णाङ्क)strtonum(p, 1, पूर्णांक_उच्च, &errstr);
			यदि (errstr) {
				fatal("Invalid number: %s (%s)", p, errstr);
			}
		} अन्यथा {
			fatal("Option \"%s\" is unsupported for moduli "
			    "screening", opts[i]);
		}
	}

	यदि (have_identity && म_भेद(identity_file, "-") != 0) {
		यदि ((in = ख_खोलो(identity_file, "r")) == रिक्त) {
			fatal("Couldn't open modulus candidate "
			    "file \"%s\": %s", identity_file,
			    म_त्रुटि(त्रुटि_सं));
		}
	}

	यदि (म_भेद(out_file, "-") == 0)
		out = मानक_निकास;
	अन्यथा यदि ((out = ख_खोलो(out_file, "a")) == रिक्त) {
		fatal("Couldn't open moduli file \"%s\": %s",
		    out_file, म_त्रुटि(त्रुटि_सं));
	}
	रखो_भबफ(out, रिक्त, _IOLBF, 0);
	यदि (अविभाज्य_test(in, out, अविभाज्य_tests == 0 ? 100 : अविभाज्य_tests,
	    generator_wanted, checkpoint,
	    start_lineno, पङ्क्तिहरू_to_process) != 0)
		fatal("modulus screening failed");
	यदि (in != मानक_निवेश)
		(शून्य)ख_बंद(in);
	मुक्त(checkpoint);
#अन्यथा /* WITH_OPENSSL */
	fatal("Moduli screening is not supported");
#endif /* WITH_OPENSSL */
}

/* Read and confirm a passphrase */
स्थिर वर्ण *
read_check_passphrase(अचर वर्ण *prompt1, अचर वर्ण *prompt2,
    अचर वर्ण *retry_prompt)
{
	वर्ण *passphrase1, *passphrase2;

	लागि (;;) {
		passphrase1 = read_passphrase(prompt1, RP_ALLOW_STDIN);
		passphrase2 = read_passphrase(prompt2, RP_ALLOW_STDIN);
		यदि (म_भेद(passphrase1, passphrase2) == 0) {
			freezero(passphrase2, म_माप(passphrase2));
			फर्काऊ passphrase1;
		}
		/* The passphrases do not match. Clear them and retry. */
		freezero(passphrase1, म_माप(passphrase1));
		freezero(passphrase2, म_माप(passphrase2));
		ख_माला_दो(retry_prompt, मानक_निकास);
		ख_अक्षर_दो('\n', मानक_निकास);
		ख_साफ(मानक_निकास);
	}
	/* NOTREACHED */
	फर्काऊ रिक्त;
}

स्थिर वर्ण *
private_साँचो_passphrase(अचर वर्ण *path)
{
	वर्ण *prompt, *ret;

	यदि (identity_passphrase)
		फर्काऊ xstrdup(identity_passphrase);
	यदि (identity_new_passphrase)
		फर्काऊ xstrdup(identity_new_passphrase);

	xasprintf(&prompt, "Enter passphrase for \"%s\" "
	    "(empty for no passphrase): ", path);
	ret = read_check_passphrase(prompt,
	    "Enter same passphrase again: ",
	    "Passphrases do not match.  Try again.");
	मुक्त(prompt);
	फर्काऊ ret;
}

स्थिर वर्ण *
sk_suffix(अचर वर्ण *application, अचर uint8_t *user, माप_प्रकार userlen)
{
	वर्ण *ret, *cp;
	अचर वर्ण *p;
	माप_प्रकार slen, i;

	/* Trim off URL-like preamble */
	यदि ((p = strprefix(application, "ssh://", 0)) != रिक्त)
		ret =  xstrdup(p);
	अन्यथा यदि ((p = strprefix(application, "ssh:", 0)) != रिक्त)
		ret =  xstrdup(p);
	अन्यथा
		ret = xstrdup(application);

	/* Count trailing zeros in user */
	लागि (i = 0; i < userlen; i++) {
		यदि (user[userlen - i - 1] != 0)
			रोक;
	}
	यदि (i >= userlen)
		फर्काऊ ret; /* user-id was default all-zeros */

	/* Append user-id, escaping non-UTF-8 characters */
	slen = userlen - i;
	यदि (asmprintf(&cp, पूर्णांक_उच्च, रिक्त, "%.*s", (पूर्णाङ्क)slen, user) == -1)
		fatal_f("asmprintf failed");
	/* Don't emit a user-id that contains path or control characters */
	यदि (म_अक्षर(cp, '/') != रिक्त || म_माला(cp, "..") != रिक्त ||
	    म_अक्षर(cp, '\\') != रिक्त) {
		मुक्त(cp);
		cp = tohex(user, slen);
	}
	xextendf(&ret, "_", "%s", cp);
	मुक्त(cp);
	फर्काऊ ret;
}

स्थिर पूर्णाङ्क
do_download_sk(अचर वर्ण *skprovider, अचर वर्ण *device)
{
	संरचना sshsk_resident_साँचो **srks;
	माप_प्रकार nsrks, i;
	पूर्णाङ्क r, ret = -1;
	वर्ण *fp, *pin = रिक्त, *pass = रिक्त, *path, *pubpath;
	अचर वर्ण *ext;
	संरचना sshkey *साँचो;

	यदि (skprovider == रिक्त)
		fatal("Cannot download keys without provider");

	pin = read_passphrase("Enter PIN for authenticator: ", RP_ALLOW_STDIN);
	यदि (!quiet) {
		म_लिखो("You may need to touch your authenticator "
		    "to authorize key download.\n");
	}
	यदि ((r = sshsk_load_resident(skprovider, device, pin, 0,
	    &srks, &nsrks)) != 0) {
		यदि (pin != रिक्त)
			freezero(pin, म_माप(pin));
		error_r(r, "Unable to load resident keys");
		फर्काऊ -1;
	}
	यदि (nsrks == 0)
		logit("No keys to download");
	यदि (pin != रिक्त)
		freezero(pin, म_माप(pin));

	लागि (i = 0; i < nsrks; i++) {
		साँचो = srks[i]->साँचो;
		यदि (साँचो->type != साँचो_ECDSA_SK && साँचो->type != साँचो_ED25519_SK) {
			error("Unsupported key type %s (%d)",
			    sshkey_type(साँचो), साँचो->type);
			जारी;
		}
		यदि ((fp = sshkey_fingerprint(साँचो, fingerprint_hash,
		    SSH_FP_DEFAULT)) == रिक्त)
			fatal_f("sshkey_fingerprint failed");
		debug_f("key %zu: %s %s %s (flags 0x%02x)", i,
		    sshkey_type(साँचो), fp, साँचो->sk_application, साँचो->sk_flags);
		ext = sk_suffix(साँचो->sk_application,
		    srks[i]->user_id, srks[i]->user_id_len);
		xasprintf(&path, "id_%s_rk%s%s",
		    साँचो->type == साँचो_ECDSA_SK ? "ecdsa_sk" : "ed25519_sk",
		    *ext == '\0' ? "" : "_", ext);

		/* If the file already exists, ask the user to confirm. */
		यदि (!confirm_overwrite(path)) {
			मुक्त(path);
			रोक;
		}

		/* Save the key with the application string as the comment */
		यदि (pass == रिक्त)
			pass = private_साँचो_passphrase(path);
		यदि ((r = sshkey_save_private(साँचो, path, pass,
		    साँचो->sk_application, private_साँचो_format,
		    openssh_format_cipher, rounds)) != 0) {
			error_r(r, "Saving key \"%s\" failed", path);
			मुक्त(path);
			रोक;
		}
		यदि (!quiet) {
			म_लिखो("Saved %s key%s%s to %s\n", sshkey_type(साँचो),
			    *ext != '\0' ? " " : "",
			    *ext != '\0' ? साँचो->sk_application : "",
			    path);
		}

		/* Save public key too */
		xasprintf(&pubpath, "%s.pub", path);
		मुक्त(path);
		यदि ((r = sshkey_save_public(साँचो, pubpath,
		    साँचो->sk_application)) != 0) {
			error_r(r, "Saving public key \"%s\" failed", pubpath);
			मुक्त(pubpath);
			रोक;
		}
		मुक्त(pubpath);
	}

	यदि (i >= nsrks)
		ret = 0; /* success */
	यदि (pass != रिक्त)
		freezero(pass, म_माप(pass));
	sshsk_free_resident_साँचोहरू(srks, nsrks);
	फर्काऊ ret;
}

स्थिर शून्य
save_attestation(संरचना sshbuf *attest, अचर वर्ण *path)
{
	mode_t omask;
	पूर्णाङ्क r;

	यदि (path == रिक्त)
		फर्काऊ; /* nothing to do */
	यदि (attest == रिक्त || sshbuf_len(attest) == 0)
		fatal("Enrollment did not return attestation data");
	omask = umask(077);
	r = sshbuf_write_file(path, attest);
	umask(omask);
	यदि (r != 0)
		fatal_r(r, "Unable to write attestation data \"%s\"", path);
	यदि (!quiet)
		म_लिखो("Your FIDO attestation certificate has been saved in "
		    "%s\n", path);
}

स्थिर पूर्णाङ्क
confirm_sk_overwrite(अचर वर्ण *application, अचर वर्ण *user)
{
	वर्ण yesno[3];

	म_लिखो("A resident key scoped to '%s' with user id '%s' already "
	    "exists.\n", application == रिक्त ? "ssh:" : application,
	    user == रिक्त ? "null" : user);
	म_लिखो("Overwrite key in token (y/n)? ");
	ख_साफ(मानक_निकास);
	यदि (ख_माला_लो(yesno, परिमाण(yesno), मानक_निवेश) == रिक्त)
		फर्काऊ 0;
	यदि (yesno[0] != 'y' && yesno[0] != 'Y')
		फर्काऊ 0;
	फर्काऊ 1;
}

स्थिर शून्य
usage(शून्य)
{
	ख_लिखो(मानक_त्रुटि,
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
	ख_लिखो(मानक_त्रुटि,
	    "       ssh-keygen -D pkcs11\n");
#endif
	ख_लिखो(मानक_त्रुटि,
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
	निकास(1);
}

/*
 * Main program for key management.
 */
पूर्णाङ्क
main(पूर्णाङ्क argc, वर्ण **argv)
{
	वर्ण comment[साँचो_COMMENT_MAX], *passphrase = रिक्त;
	वर्ण *rr_hostname = रिक्त, *ep, *fp, *ra;
	संरचना sshkey *गुप्त = रिक्त, *सार्वजनिक = रिक्त;
	संरचना passwd *pw;
	पूर्णाङ्क ret = 0, r, opt, type;
	पूर्णाङ्क change_passphrase = 0, change_comment = 0, show_cert = 0;
	पूर्णाङ्क find_host = 0, delete_host = 0, hash_hosts = 0;
	पूर्णाङ्क gen_all_hostkeys = 0, gen_krl = 0, update_krl = 0, check_krl = 0;
	पूर्णाङ्क prefer_agent = 0, convert_to = 0, convert_from = 0;
	पूर्णाङ्क print_public = 0, print_generic = 0, cert_serial_autoinc = 0;
	पूर्णाङ्क do_gen_candidates = 0, do_screen_candidates = 0, download_sk = 0;
	अचिन्हित दीर्घ दीर्घ cert_serial = 0;
	वर्ण *identity_comment = रिक्त, *ca_साँचो_path = रिक्त, **opts = रिक्त;
	वर्ण *sk_application = रिक्त, *sk_device = रिक्त, *sk_user = रिक्त;
	वर्ण *sk_attestation_path = रिक्त;
	संरचना sshbuf *challenge = रिक्त, *attest = रिक्त;
	माप_प्रकार i, nopts = 0;
	uint32_t bits = 0;
	uint8_t sk_flags = SSH_SK_USER_PRESENCE_REQD;
	अचर वर्ण *errstr, *p;
	पूर्णाङ्क log_level = SYSLOG_LEVEL_INFO;
	वर्ण *sign_op = रिक्त;

	बाह्य पूर्णाङ्क optind;
	बाह्य वर्ण *optarg;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	__progname = ssh_get_progname(argv[0]);

	seed_rng();

	log_init(argv[0], SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_USER, 1);

	msetlocale();

	/* we need this for the home * directory.  */
	pw = getpwuid(getuid());
	यदि (!pw)
		fatal("No user exists for uid %lu", (u_long)getuid());
	pw = pwcopy(pw);
	यदि (gethostname(hostname, परिमाण(hostname)) == -1)
		fatal("gethostname: %s", म_त्रुटि(त्रुटि_सं));

	sk_provider = दो_पर्या("SSH_SK_PROVIDER");

	/* Remaining characters: dGjJSTWx */
	जबसम्म ((opt = getopt(argc, argv, "ABHKLQUXceghiklopquvy"
	    "C:D:E:F:I:M:N:O:P:R:V:Y:Z:"
	    "a:b:f:g:m:n:r:s:t:w:z:")) != -1) {
		विकल्प (opt) {
		पक्ष 'A':
			gen_all_hostkeys = 1;
			रोक;
		पक्ष 'b':
			bits = (uint32_t)strtonum(optarg, 1, UINT32_MAX,
			    &errstr);
			यदि (errstr)
				fatal("Bits has bad value %s (%s)",
					optarg, errstr);
			रोक;
		पक्ष 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			यदि (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			रोक;
		पक्ष 'F':
			find_host = 1;
			rr_hostname = optarg;
			रोक;
		पक्ष 'H':
			hash_hosts = 1;
			रोक;
		पक्ष 'I':
			cert_साँचो_id = optarg;
			रोक;
		पक्ष 'R':
			delete_host = 1;
			rr_hostname = optarg;
			रोक;
		पक्ष 'L':
			show_cert = 1;
			रोक;
		पक्ष 'l':
			print_fingerprint = 1;
			रोक;
		पक्ष 'B':
			print_bubblebabble = 1;
			रोक;
		पक्ष 'm':
			यदि (strcasecmp(optarg, "RFC4716") == 0 ||
			    strcasecmp(optarg, "ssh2") == 0) {
				convert_format = FMT_RFC4716;
				रोक;
			}
			यदि (strcasecmp(optarg, "PKCS8") == 0) {
				convert_format = FMT_PKCS8;
				private_साँचो_format = SSHKEY_PRIVATE_PKCS8;
				रोक;
			}
			यदि (strcasecmp(optarg, "PEM") == 0) {
				convert_format = FMT_PEM;
				private_साँचो_format = SSHKEY_PRIVATE_PEM;
				रोक;
			}
			यदि (strcasecmp(optarg, "hexdump") == 0) {
				convert_format = FMT_HEXDUMP;
				रोक;
			}
			fatal("Unsupported conversion format \"%s\"", optarg);
		पक्ष 'n':
			cert_principals = optarg;
			रोक;
		पक्ष 'o':
			/* no-op; new format is already the default */
			रोक;
		पक्ष 'p':
			change_passphrase = 1;
			रोक;
		पक्ष 'c':
			change_comment = 1;
			रोक;
		पक्ष 'f':
			यदि (strlcpy(identity_file, optarg,
			    परिमाण(identity_file)) >= परिमाण(identity_file))
				fatal("Identity filename too long");
			have_identity = 1;
			रोक;
		पक्ष 'g':
			print_generic = 1;
			रोक;
		पक्ष 'K':
			download_sk = 1;
			रोक;
		पक्ष 'P':
			identity_passphrase = optarg;
			रोक;
		पक्ष 'N':
			identity_new_passphrase = optarg;
			रोक;
		पक्ष 'Q':
			check_krl = 1;
			रोक;
		पक्ष 'O':
			opts = xrecallocarray(opts, nopts, nopts + 1,
			    परिमाण(*opts));
			opts[nopts++] = xstrdup(optarg);
			रोक;
		पक्ष 'Z':
			openssh_format_cipher = optarg;
			यदि (cipher_by_name(openssh_format_cipher) == रिक्त)
				fatal("Invalid OpenSSH-format cipher '%s'",
				    openssh_format_cipher);
			रोक;
		पक्ष 'C':
			identity_comment = optarg;
			रोक;
		पक्ष 'q':
			quiet = 1;
			रोक;
		पक्ष 'e':
			/* export key */
			convert_to = 1;
			रोक;
		पक्ष 'h':
			cert_साँचो_type = SSH2_CERT_TYPE_HOST;
			certflags_flags = 0;
			रोक;
		पक्ष 'k':
			gen_krl = 1;
			रोक;
		पक्ष 'i':
		पक्ष 'X':
			/* import key */
			convert_from = 1;
			रोक;
		पक्ष 'y':
			print_public = 1;
			रोक;
		पक्ष 's':
			ca_साँचो_path = optarg;
			रोक;
		पक्ष 't':
			साँचो_type_name = optarg;
			रोक;
		पक्ष 'D':
			pkcs11provider = optarg;
			रोक;
		पक्ष 'U':
			prefer_agent = 1;
			रोक;
		पक्ष 'u':
			update_krl = 1;
			रोक;
		पक्ष 'v':
			यदि (log_level == SYSLOG_LEVEL_INFO)
				log_level = SYSLOG_LEVEL_DEBUG1;
			अन्यथा {
				यदि (log_level >= SYSLOG_LEVEL_DEBUG1 &&
				    log_level < SYSLOG_LEVEL_DEBUG3)
					log_level++;
			}
			रोक;
		पक्ष 'r':
			rr_hostname = optarg;
			रोक;
		पक्ष 'a':
			rounds = (पूर्णाङ्क)strtonum(optarg, 1, पूर्णांक_उच्च, &errstr);
			यदि (errstr)
				fatal("Invalid number: %s (%s)",
					optarg, errstr);
			रोक;
		पक्ष 'V':
			parse_cert_times(optarg);
			रोक;
		पक्ष 'Y':
			sign_op = optarg;
			रोक;
		पक्ष 'w':
			sk_provider = optarg;
			रोक;
		पक्ष 'z':
			त्रुटि_सं = 0;
			यदि (*optarg == '+') {
				cert_serial_autoinc = 1;
				optarg++;
			}
			cert_serial = strtoull(optarg, &ep, 10);
			यदि (*optarg < '0' || *optarg > '9' || *ep != '\0' ||
			    (त्रुटि_सं == दुस्फल && cert_serial == ULLONG_MAX))
				fatal("Invalid serial number \"%s\"", optarg);
			रोक;
		पक्ष 'M':
			यदि (म_भेद(optarg, "generate") == 0)
				do_gen_candidates = 1;
			अन्यथा यदि (म_भेद(optarg, "screen") == 0)
				do_screen_candidates = 1;
			अन्यथा
				fatal("Unsupported moduli option %s", optarg);
			रोक;
		स्वभाव:
			usage();
		}
	}

#ifdef ENABLE_SK_INTERNAL
	यदि (sk_provider == रिक्त)
		sk_provider = "internal";
#endif

	/* reinit */
	log_init(argv[0], log_level, SYSLOG_FACILITY_USER, 1);

	argv += optind;
	argc -= optind;

	यदि (sign_op != रिक्त) {
		यदि (strprefix(sign_op, "find-principals", 0) != रिक्त) {
			यदि (ca_साँचो_path == रिक्त) {
				error("Too few arguments for find-principals:"
				    "missing signature file");
				निकास(1);
			}
			यदि (!have_identity) {
				error("Too few arguments for find-principals:"
				    "missing allowed keys file");
				निकास(1);
			}
			ret = sig_find_principals(ca_साँचो_path, identity_file,
			    opts, nopts);
			गच्छ done;
		} अन्यथा यदि (strprefix(sign_op, "match-principals", 0) != रिक्त) {
			यदि (!have_identity) {
				error("Too few arguments for match-principals:"
				    "missing allowed keys file");
				निकास(1);
			}
			यदि (cert_साँचो_id == रिक्त) {
				error("Too few arguments for match-principals: "
				    "missing principal ID");
				निकास(1);
			}
			ret = sig_match_principals(identity_file, cert_साँचो_id,
			    opts, nopts);
			गच्छ done;
		} अन्यथा यदि (strprefix(sign_op, "sign", 0) != रिक्त) {
			/* NB. cert_principals is actually namespace, via -n */
			यदि (cert_principals == रिक्त ||
			    *cert_principals == '\0') {
				error("Too few arguments for sign: "
				    "missing namespace");
				निकास(1);
			}
			यदि (!have_identity) {
				error("Too few arguments for sign: "
				    "missing key");
				निकास(1);
			}
			ret = sig_sign(identity_file, cert_principals,
			    prefer_agent, argc, argv, opts, nopts);
			गच्छ done;
		} अन्यथा यदि (strprefix(sign_op, "check-novalidate", 0) != रिक्त) {
			/* NB. cert_principals is actually namespace, via -n */
			यदि (cert_principals == रिक्त ||
			    *cert_principals == '\0') {
				error("Too few arguments for check-novalidate: "
				    "missing namespace");
				निकास(1);
			}
			यदि (ca_साँचो_path == रिक्त) {
				error("Too few arguments for check-novalidate: "
				    "missing signature file");
				निकास(1);
			}
			ret = sig_verify(ca_साँचो_path, cert_principals,
			    रिक्त, रिक्त, रिक्त, opts, nopts);
			गच्छ done;
		} अन्यथा यदि (strprefix(sign_op, "verify", 0) != रिक्त) {
			/* NB. cert_principals is actually namespace, via -n */
			यदि (cert_principals == रिक्त ||
			    *cert_principals == '\0') {
				error("Too few arguments for verify: "
				    "missing namespace");
				निकास(1);
			}
			यदि (ca_साँचो_path == रिक्त) {
				error("Too few arguments for verify: "
				    "missing signature file");
				निकास(1);
			}
			यदि (!have_identity) {
				error("Too few arguments for sign: "
				    "missing allowed keys file");
				निकास(1);
			}
			यदि (cert_साँचो_id == रिक्त) {
				error("Too few arguments for verify: "
				    "missing principal identity");
				निकास(1);
			}
			ret = sig_verify(ca_साँचो_path, cert_principals,
			    cert_साँचो_id, identity_file, rr_hostname,
			    opts, nopts);
			गच्छ done;
		}
		error("Unsupported operation for -Y: \"%s\"", sign_op);
		usage();
		/* NOTREACHED */
	}

	यदि (ca_साँचो_path != रिक्त) {
		यदि (argc < 1 && !gen_krl) {
			error("Too few arguments.");
			usage();
		}
	} अन्यथा यदि (argc > 0 && !gen_krl && !check_krl &&
	    !do_gen_candidates && !do_screen_candidates) {
		error("Too many arguments.");
		usage();
	}
	यदि (change_passphrase && change_comment) {
		error("Can only have one of -p and -c.");
		usage();
	}
	यदि (print_fingerprint && (delete_host || hash_hosts)) {
		error("Cannot use -l with -H or -R.");
		usage();
	}
	यदि (gen_krl) {
		do_gen_krl(pw, update_krl, ca_साँचो_path,
		    cert_serial, identity_comment, argc, argv);
		गच्छ done;
	}
	यदि (check_krl) {
		do_check_krl(pw, print_fingerprint, argc, argv);
		गच्छ done;
	}
	यदि (ca_साँचो_path != रिक्त) {
		यदि (cert_साँचो_id == रिक्त)
			fatal("Must specify key id (-I) when certifying");
		यदि (cert_principals == रिक्त) {
			/*
			 * Ideally this would be a fatal(), but we need to
			 * be able to generate such certificates for testing
			 * even though they will be rejected.
			 */
			error("Warning: certificate will contain no "
			    "principals (-n)");
		}
		लागि (i = 0; i < nopts; i++)
			add_cert_option(opts[i]);
		do_ca_sign(pw, ca_साँचो_path, prefer_agent,
		    cert_serial, cert_serial_autoinc, argc, argv);
		गच्छ done;
	}
	यदि (show_cert)
		do_show_cert(pw);
	यदि (delete_host || hash_hosts || find_host) {
		do_known_hosts(pw, rr_hostname, find_host,
		    delete_host, hash_hosts);
	}
	यदि (pkcs11provider != रिक्त)
		do_download(pw);
	यदि (download_sk) {
		लागि (i = 0; i < nopts; i++) {
			यदि ((p = strprefix(opts[i], "device=", 1)) != रिक्त) {
				sk_device = xstrdup(p);
			} अन्यथा {
				fatal("Option \"%s\" is unsupported for "
				    "FIDO authenticator download", opts[i]);
			}
		}
		ret = do_download_sk(sk_provider, sk_device);
		गच्छ done;
	}
	यदि (print_fingerprint || print_bubblebabble)
		do_fingerprint(pw);
	यदि (change_passphrase)
		do_change_passphrase(pw, opts, nopts);
	यदि (change_comment)
		do_change_comment(pw, identity_comment);
#ifdef WITH_OPENSSL
	यदि (convert_to) {
		do_convert_to(pw);
		गच्छ done;
	}
	यदि (convert_from) {
		do_convert_from(pw);
		गच्छ done;
	}
#अन्यथा /* WITH_OPENSSL */
	यदि (convert_to || convert_from)
		fatal("key conversion disabled at compile time");
#endif /* WITH_OPENSSL */
	यदि (print_public)
		do_print_public(pw);
	यदि (rr_hostname != रिक्त) {
		अचिन्हित पूर्णाङ्क n = 0;

		यदि (have_identity) {
			n = do_print_resource_record(pw, identity_file,
			    rr_hostname, print_generic, opts, nopts);
			यदि (n == 0)
				fatal("%s: %s", identity_file, म_त्रुटि(त्रुटि_सं));
			निकास(0);
		} अन्यथा {

			n += do_print_resource_record(pw,
			    PATH_HOST_RSA_साँचो_FILE, rr_hostname,
			    print_generic, opts, nopts);
			n += do_print_resource_record(pw,
			    PATH_HOST_ECDSA_साँचो_FILE, rr_hostname,
			    print_generic, opts, nopts);
			n += do_print_resource_record(pw,
			    PATH_HOST_ED25519_साँचो_FILE, rr_hostname,
			    print_generic, opts, nopts);
			यदि (n == 0)
				fatal("no keys found.");
			निकास(0);
		}
	}

	यदि (do_gen_candidates || do_screen_candidates) {
		यदि (argc <= 0)
			fatal("No output file specified");
		अन्यथा यदि (argc > 1)
			fatal("Too many output files specified");
	}
	यदि (do_gen_candidates) {
		do_moduli_gen(argv[0], opts, nopts);
		गच्छ done;
	}
	यदि (do_screen_candidates) {
		do_moduli_screen(argv[0], opts, nopts);
		गच्छ done;
	}

	यदि (gen_all_hostkeys) {
		do_gen_all_hostkeys(pw);
		गच्छ done;
	}

	यदि (साँचो_type_name == रिक्त)
		साँचो_type_name = DEFAULT_साँचो_TYPE_NAME;

	type = sshkey_type_from_shortname(साँचो_type_name);
	type_bits_valid(type, साँचो_type_name, &bits);

	यदि (!quiet)
		म_लिखो("Generating public/private %s key pair.\n",
		    साँचो_type_name);
	विकल्प (type) {
	पक्ष साँचो_ECDSA_SK:
	पक्ष साँचो_ED25519_SK:
		लागि (i = 0; i < nopts; i++) {
			यदि (strcasecmp(opts[i], "no-touch-required") == 0) {
				sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
			} अन्यथा यदि (strcasecmp(opts[i], "verify-required") == 0) {
				sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
			} अन्यथा यदि (strcasecmp(opts[i], "resident") == 0) {
				sk_flags |= SSH_SK_RESIDENT_साँचो;
			} अन्यथा यदि ((p = strprefix(opts[i], "device=", 1))
			    != रिक्त ) {
				sk_device = xstrdup(p);
			} अन्यथा यदि ((p = strprefix(opts[i], "user=", 1))
			    != रिक्त) {
				sk_user = xstrdup(p);
			} अन्यथा यदि ((p = strprefix(opts[i], "challenge=", 1))
			    != रिक्त) {
				यदि ((r = sshbuf_load_file(p,
				    &challenge)) != 0) {
					fatal_r(r, "Unable to load FIDO "
					    "enrollment challenge \"%s\"", p);
				}
			} अन्यथा यदि (strncasecmp(opts[i],
			    "write-attestation=", 18) == 0) {
				sk_attestation_path = opts[i] + 18;
			} अन्यथा यदि (strncasecmp(opts[i],
			    "application=", 12) == 0) {
				sk_application = xstrdup(opts[i] + 12);
				यदि (म_भेदन(sk_application, "ssh:", 4) != 0) {
					fatal("FIDO application string must "
					    "begin with \"ssh:\"");
				}
			} अन्यथा {
				fatal("Option \"%s\" is unsupported for "
				    "FIDO authenticator enrollment", opts[i]);
			}
		}
		यदि ((attest = sshbuf_new()) == रिक्त)
			fatal("sshbuf_new failed");
		r = 0;
		लागि (i = 0 ;;) {
			यदि (!quiet) {
				म_लिखो("You may need to touch your "
				    "authenticator%s to authorize key "
				    "generation.\n",
				    r == 0 ? "" : " again");
			}
			ख_साफ(मानक_निकास);
			r = sshsk_enroll(type, sk_provider, sk_device,
			    sk_application == रिक्त ? "ssh:" : sk_application,
			    sk_user, sk_flags, passphrase, challenge,
			    &गुप्त, attest);
			यदि (r == 0)
				रोक;
			यदि (r == SSH_ERR_साँचो_BAD_PERMISSIONS &&
			    (sk_flags & SSH_SK_RESIDENT_साँचो) != 0 &&
			    (sk_flags & SSH_SK_FORCE_OPERATION) == 0 &&
			    confirm_sk_overwrite(sk_application, sk_user)) {
				sk_flags |= SSH_SK_FORCE_OPERATION;
				जारी;
			}
			यदि (r != SSH_ERR_साँचो_WRONG_PASSPHRASE)
				fatal_r(r, "Key enrollment failed");
			अन्यथा यदि (passphrase != रिक्त) {
				error("PIN incorrect");
				freezero(passphrase, म_माप(passphrase));
				passphrase = रिक्त;
			}
			यदि (++i >= 3)
				fatal("Too many incorrect PINs");
			passphrase = read_passphrase("Enter PIN for "
			    "authenticator: ", RP_ALLOW_STDIN);
		}
		यदि (passphrase != रिक्त) {
			freezero(passphrase, म_माप(passphrase));
			passphrase = रिक्त;
		}
		रोक;
	स्वभाव:
		यदि ((r = sshkey_generate(type, bits, &गुप्त)) != 0)
			fatal("sshkey_generate failed");
		रोक;
	}
	यदि ((r = sshkey_from_private(गुप्त, &सार्वजनिक)) != 0)
		fatal_r(r, "sshkey_from_private");

	यदि (!have_identity)
		ask_filename(pw, "Enter file in which to save the key");

	/* Create ~/.ssh directory if it doesn't already exist. */
	hostfile_create_user_ssh_dir(identity_file, !quiet);

	/* If the file already exists, ask the user to confirm. */
	यदि (!confirm_overwrite(identity_file))
		निकास(1);

	/* Determine the passphrase for the private key */
	passphrase = private_साँचो_passphrase(identity_file);
	यदि (identity_comment) {
		strlcpy(comment, identity_comment, परिमाण(comment));
	} अन्यथा {
		/* Create default comment field for the passphrase. */
		snprintf(comment, परिमाण comment, "%s@%s", pw->pw_name, hostname);
	}



	/* Save the key with the given passphrase and comment. */
	यदि ((r = sshkey_save_private(गुप्त, identity_file, passphrase,
	    comment, private_साँचो_format, openssh_format_cipher, rounds)) != 0) {
		error_r(r, "Saving key \"%s\" failed", identity_file);
		freezero(passphrase, म_माप(passphrase));
		निकास(1);
	}
	freezero(passphrase, म_माप(passphrase));
	sshkey_free(गुप्त);

	यदि (!quiet) {
		म_लिखो("Your identification has been saved in %s\n",
		    identity_file);
	}

	strlcat(identity_file, ".pub", परिमाण(identity_file));
	यदि ((r = sshkey_save_public(सार्वजनिक, identity_file, comment)) != 0)
		fatal_r(r, "Unable to save public key to %s", identity_file);

	यदि (!quiet) {
		fp = sshkey_fingerprint(सार्वजनिक, fingerprint_hash,
		    SSH_FP_DEFAULT);
		ra = sshkey_fingerprint(सार्वजनिक, fingerprint_hash,
		    SSH_FP_RANDOMART);
		यदि (fp == रिक्त || ra == रिक्त)
			fatal("sshkey_fingerprint failed");
		म_लिखो("Your public key has been saved in %s\n",
		    identity_file);
		म_लिखो("The key fingerprint is:\n");
		म_लिखो("%s %s\n", fp, comment);
		म_लिखो("The key's randomart image is:\n");
		म_लिखो("%s\n", ra);
		मुक्त(ra);
		मुक्त(fp);
	}

	यदि (sk_attestation_path != रिक्त)
		save_attestation(attest, sk_attestation_path);

 done:
	sshbuf_free(attest);
	sshkey_free(सार्वजनिक);
	pwfree(pw);
	निकास(ret);
}
