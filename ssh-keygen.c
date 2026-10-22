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

#define DEFAULT_किल्ली_TYPE_NAME "ed25519"

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

#define किल्ली_COMMENT_MAX		(NI_MAXHOST + 1024)

स्थिर पूर्णांक quiet = 0;

/* Flag indicating that we just want to see the key fingerprint */
स्थिर पूर्णांक print_fingerprint = 0;
स्थिर पूर्णांक print_bubblebabble = 0;

/* Hash algorithm to use for fingerprints. */
स्थिर पूर्णांक fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* The identity file name, given on the command line or entered by the user. */
स्थिर अक्षर identity_file[PATH_MAX];
स्थिर पूर्णांक have_identity = 0;

/* This is set to the passphrase if given on the command line. */
स्थिर अक्षर *identity_passphrase = रिक्त;

/* This is set to the new passphrase if given on the command line. */
स्थिर अक्षर *identity_new_passphrase = रिक्त;

/* Key type when certifying */
स्थिर u_int cert_किल्ली_type = SSH2_CERT_TYPE_USER;

/* "key ID" of signed key */
स्थिर अक्षर *cert_किल्ली_id = रिक्त;

/* Comma-separated list of principal names for certifying keys */
स्थिर अक्षर *cert_principals = रिक्त;

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
स्थिर अक्षर *certflags_command = रिक्त;
स्थिर अक्षर *certflags_src_addr = रिक्त;

/* Arbitrary extensions specified by user */
संरचना cert_ext {
	अक्षर *किल्ली;
	अक्षर *val;
	पूर्णांक crit;
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

स्थिर अक्षर *किल्ली_type_name = रिक्त;

/* Load key from this PKCS#11 provider */
स्थिर अक्षर *pkcs11provider = रिक्त;

/* FIDO/U2F provider to use */
स्थिर अक्षर *sk_provider = रिक्त;

/* Format for writing private keys */
स्थिर पूर्णांक private_किल्ली_format = SSHKEY_PRIVATE_OPENSSH;

/* Cipher for new-format private keys */
स्थिर अक्षर *openssh_format_cipher = रिक्त;

/* Number of KDF rounds to derive new format keys. */
स्थिर पूर्णांक rounds = 0;

/* argv0 */
बाह्य अक्षर *__progname;

स्थिर अक्षर hostname[NI_MAXHOST];

#ifdef WITH_OPENSSL
/* moduli.c */
पूर्णांक gen_candidates(खाता *, uint32_t, BIGNUM *);
पूर्णांक मूळसंख्या_test(खाता *, खाता *, uint32_t, uint32_t, अक्षर *, अचिन्हित दीर्घ,
    अचिन्हित दीर्घ);
#endif

स्थिर शून्य
type_bits_valid(पूर्णांक type, स्थिरांक अक्षर *name, uint32_t *bitsp)
{
	जर (type == किल्ली_UNSPEC)
		fatal("unknown key type %s", किल्ली_type_name);
	जर (*bitsp == 0) {
#ifdef WITH_OPENSSL
		पूर्णांक nid;

		निवड(type) {
		स्थिती किल्ली_ECDSA:
			जर (name != रिक्त &&
			    (nid = sshkey_ecdsa_nid_from_name(name)) > 0)
				*bitsp = sshkey_curve_nid_to_bits(nid);
			जर (*bitsp == 0)
				*bitsp = DEFAULT_BITS_ECDSA;
			थांबा;
		स्थिती किल्ली_RSA:
			*bitsp = DEFAULT_BITS;
			थांबा;
		}
#endif
	}
#ifdef WITH_OPENSSL
	निवड (type) {
	स्थिती किल्ली_RSA:
		जर (*bitsp < SSH_RSA_MINIMUM_MODULUS_SIZE)
			fatal("Invalid RSA key length: minimum is %d bits",
			    SSH_RSA_MINIMUM_MODULUS_SIZE);
		अन्यथा जर (*bitsp > OPENSSL_RSA_MAX_MODULUS_BITS)
			fatal("Invalid RSA key length: maximum is %d bits",
			    OPENSSL_RSA_MAX_MODULUS_BITS);
		थांबा;
	स्थिती किल्ली_ECDSA:
		जर (sshkey_ecdsa_bits_to_nid(*bitsp) == -1)
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
स्थिर पूर्णांक
confirm_overwrite(स्थिरांक अक्षर *filename)
{
	अक्षर yesno[3];
	संरचना stat st;

	जर (stat(filename, &st) != 0)
		परत 1;
	म_लिखो("%s already exists.\n", filename);
	म_लिखो("Overwrite (y/n)? ");
	ख_साफ(मानक_निकास);
	जर (ख_माला_लो(yesno, आकार(yesno), मानक_निवेश) == रिक्त)
		परत 0;
	जर (yesno[0] != 'y' && yesno[0] != 'Y')
		परत 0;
	परत 1;
}

स्थिर शून्य
ask_filename(संरचना passwd *pw, स्थिरांक अक्षर *prompt)
{
	अक्षर buf[1024];
	अक्षर *name = रिक्त;

	जर (किल्ली_type_name == रिक्त)
		name = _PATH_SSH_CLIENT_ID_ED25519;
	अन्यथा {
		निवड (sshkey_type_from_shortname(किल्ली_type_name)) {
		स्थिती किल्ली_ECDSA_CERT:
		स्थिती किल्ली_ECDSA:
			name = _PATH_SSH_CLIENT_ID_ECDSA;
			थांबा;
		स्थिती किल्ली_ECDSA_SK_CERT:
		स्थिती किल्ली_ECDSA_SK:
			name = _PATH_SSH_CLIENT_ID_ECDSA_SK;
			थांबा;
		स्थिती किल्ली_RSA_CERT:
		स्थिती किल्ली_RSA:
			name = _PATH_SSH_CLIENT_ID_RSA;
			थांबा;
		स्थिती किल्ली_ED25519:
		स्थिती किल्ली_ED25519_CERT:
			name = _PATH_SSH_CLIENT_ID_ED25519;
			थांबा;
		स्थिती किल्ली_ED25519_SK:
		स्थिती किल्ली_ED25519_SK_CERT:
			name = _PATH_SSH_CLIENT_ID_ED25519_SK;
			थांबा;
		स्थिती किल्ली_MLDSA44_ED25519:
		स्थिती किल्ली_MLDSA44_ED25519_CERT:
			name = _PATH_SSH_CLIENT_ID_MLDSA44_ED25519;
			थांबा;
		पूर्वनिर्धारित:
			fatal("bad key type");
		}
	}
	snprintf(identity_file, आकार(identity_file),
	    "%s/%s", pw->pw_dir, name);
	म_लिखो("%s (%s): ", prompt, identity_file);
	ख_साफ(मानक_निकास);
	जर (ख_माला_लो(buf, आकार(buf), मानक_निवेश) == रिक्त)
		निकास(1);
	buf[म_खोज(buf, "\n")] = '\0';
	जर (म_भेद(buf, "") != 0)
		strlcpy(identity_file, buf, आकार(identity_file));
	have_identity = 1;
}

स्थिर संरचना sshkey *
load_identity(स्थिरांक अक्षर *filename, अक्षर **commentp)
{
	अक्षर *prompt, *pass;
	संरचना sshkey *prv;
	पूर्णांक r;

	जर (commentp != रिक्त)
		*commentp = रिक्त;
	जर ((r = sshkey_load_private(filename, "", &prv, commentp)) == 0)
		परत prv;
	जर (r != SSH_ERR_किल्ली_WRONG_PASSPHRASE)
		fatal_r(r, "Load key \"%s\"", filename);
	जर (identity_passphrase)
		pass = xstrdup(identity_passphrase);
	अन्यथा {
		xasprintf(&prompt, "Enter passphrase for \"%s\": ", filename);
		pass = read_passphrase(prompt, RP_ALLOW_STDIN);
		मुक्त(prompt);
	}
	r = sshkey_load_private(filename, pass, &prv, commentp);
	freezero(pass, म_माप(pass));
	जर (r != 0)
		fatal_r(r, "Load key \"%s\"", filename);
	परत prv;
}

#define SSH_COM_PUBLIC_BEGIN		"---- BEGIN SSH2 PUBLIC KEY ----"
#define SSH_COM_PUBLIC_END		"---- END SSH2 PUBLIC KEY ----"
#define SSH_COM_PRIVATE_BEGIN		"---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----"
#define	SSH_COM_PRIVATE_किल्ली_MAGIC	0x3f6ff9eb

#ifdef WITH_OPENSSL
स्थिर शून्य
do_convert_to_ssh2(संरचना passwd *pw, संरचना sshkey *k)
{
	संरचना sshbuf *b;
	अक्षर comment[61], *b64;
	पूर्णांक r;

	जर ((b = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	जर ((r = sshkey_putb(k, b)) != 0)
		fatal_fr(r, "put key");
	जर ((b64 = sshbuf_dtob64_string(b, 1)) == रिक्त)
		fatal_f("sshbuf_dtob64_string failed");

	/* Comment + surrounds must fit into 72 chars (RFC 4716 sec 3.3) */
	snprintf(comment, आकार(comment),
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
	निवड (sshkey_type_plain(k->type)) {
	स्थिती किल्ली_RSA:
		जर (!PEM_write_RSA_PUBKEY(मानक_निकास,
		    EVP_PKEY_get0_RSA(k->pkey)))
			fatal("PEM_write_RSA_PUBKEY failed");
		थांबा;
	स्थिती किल्ली_ECDSA:
		जर (!PEM_write_EC_PUBKEY(मानक_निकास,
		    EVP_PKEY_get0_EC_किल्ली(k->pkey)))
			fatal("PEM_write_EC_PUBKEY failed");
		थांबा;
	पूर्वनिर्धारित:
		fatal_f("unsupported key type %s", sshkey_type(k));
	}
}

स्थिर शून्य
do_convert_to_pem(संरचना sshkey *k)
{
	निवड (sshkey_type_plain(k->type)) {
	स्थिती किल्ली_RSA:
		जर (!PEM_write_RSAPublic_किल्ली(मानक_निकास,
		    EVP_PKEY_get0_RSA(k->pkey)))
			fatal("PEM_write_RSAPublicKey failed");
		थांबा;
	स्थिती किल्ली_ECDSA:
		जर (!PEM_write_EC_PUBKEY(मानक_निकास,
		    EVP_PKEY_get0_EC_किल्ली(k->pkey)))
			fatal("PEM_write_EC_PUBKEY failed");
		थांबा;
	पूर्वनिर्धारित:
		fatal_f("unsupported key type %s", sshkey_type(k));
	}
}

स्थिर शून्य
do_convert_to_hexdump(संरचना sshkey *k)
{
	संरचना sshbuf *b;
	पूर्णांक r;

	जर ((b = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	/* pubkey */
	जर ((r = sshkey_putb(k, b)) != 0)
		fatal_fr(r, "serialise private");
	म_लिखो("Public %s key:\n", sshkey_type(k));
	sshbuf_dump(b, मानक_निकास);
	sshbuf_reset(b);
	जर ((r = sshkey_private_serialize(k, b)) != 0) {
		debug_fr(r, "serialise private");
		जा out;
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
	पूर्णांक r;

	जर (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	जर (stat(identity_file, &st) == -1)
		fatal("%s: %s: %s", __progname, identity_file, म_त्रुटि(त्रुटि_सं));

	/* If we're trying to hexdump, then prefer the private key */
	जर (convert_format == FMT_HEXDUMP) {
		जर ((r = sshkey_load_private(identity_file,
		    रिक्त, &k, रिक्त)) != 0 &&
		    r == SSH_ERR_किल्ली_WRONG_PASSPHRASE)
			k = load_identity(identity_file, रिक्त);
	}
	जर (k == रिक्त && (r = sshkey_load_public(identity_file, &k, रिक्त)) != 0)
		k = load_identity(identity_file, रिक्त);

	निवड (convert_format) {
	स्थिती FMT_RFC4716:
		do_convert_to_ssh2(pw, k);
		थांबा;
	स्थिती FMT_PKCS8:
		do_convert_to_pkcs8(k);
		थांबा;
	स्थिती FMT_PEM:
		do_convert_to_pem(k);
		थांबा;
	स्थिती FMT_HEXDUMP:
		do_convert_to_hexdump(k);
		थांबा;
	पूर्वनिर्धारित:
		fatal_f("unknown key format %d", convert_format);
	}
}

/*
 * This is almost exactly the bignum1 encoding, but with 32 bit for length
 * instead of 16.
 */
स्थिर शून्य
buffer_get_bignum_bits(संरचना sshbuf *b, BIGNUM *मूल्य)
{
	u_int bytes, bignum_bits;
	पूर्णांक r;

	जर ((r = sshbuf_get_u32(b, &bignum_bits)) != 0)
		fatal_fr(r, "parse");
	bytes = (bignum_bits + 7) / 8;
	जर (sshbuf_len(b) < bytes)
		fatal_f("input buffer too small: need %d have %zu",
		    bytes, sshbuf_len(b));
	जर (BN_bin2bn(sshbuf_ptr(b), bytes, मूल्य) == रिक्त)
		fatal_f("BN_bin2bn failed");
	जर ((r = sshbuf_consume(b, bytes)) != 0)
		fatal_fr(r, "consume");
}

स्थिर संरचना sshkey *
do_convert_private_ssh2(संरचना sshbuf *b)
{
	संरचना sshkey *किल्ली = रिक्त;
	अक्षर *type, *cipher;
	स्थिरांक अक्षर *alg = रिक्त;
	u_char e1, e2, e3, *sig = रिक्त, data[] = "abcde12345";
	पूर्णांक r, rlen, ktype;
	u_int magic, i1, i2, i3, i4;
	माप_प्रकार slen;
	u_long e;
	BIGNUM *rsa_n = रिक्त, *rsa_e = रिक्त, *rsa_d = रिक्त;
	BIGNUM *rsa_p = रिक्त, *rsa_q = रिक्त, *rsa_iqmp = रिक्त;
	BIGNUM *rsa_dmp1 = रिक्त, *rsa_dmq1 = रिक्त;
	RSA *rsa = रिक्त;

	जर ((r = sshbuf_get_u32(b, &magic)) != 0)
		fatal_fr(r, "parse magic");

	जर (magic != SSH_COM_PRIVATE_किल्ली_MAGIC) {
		error("bad magic 0x%x != 0x%x", magic,
		    SSH_COM_PRIVATE_किल्ली_MAGIC);
		परत रिक्त;
	}
	जर ((r = sshbuf_get_u32(b, &i1)) != 0 ||
	    (r = sshbuf_get_cstring(b, &type, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(b, &cipher, रिक्त)) != 0 ||
	    (r = sshbuf_get_u32(b, &i2)) != 0 ||
	    (r = sshbuf_get_u32(b, &i3)) != 0 ||
	    (r = sshbuf_get_u32(b, &i4)) != 0)
		fatal_fr(r, "parse");
	debug("ignore (%d %d %d %d)", i1, i2, i3, i4);
	जर (म_भेद(cipher, "none") != 0) {
		error("unsupported cipher %s", cipher);
		मुक्त(cipher);
		मुक्त(type);
		परत रिक्त;
	}
	मुक्त(cipher);

	जर (म_माला(type, "rsa")) {
		ktype = किल्ली_RSA;
	} अन्यथा {
		मुक्त(type);
		परत रिक्त;
	}
	जर ((किल्ली = sshkey_new(ktype)) == रिक्त)
		fatal("sshkey_new failed");
	मुक्त(type);

	निवड (किल्ली->type) {
	स्थिती किल्ली_RSA:
		जर ((r = sshbuf_get_u8(b, &e1)) != 0 ||
		    (e1 < 30 && (r = sshbuf_get_u8(b, &e2)) != 0) ||
		    (e1 < 30 && (r = sshbuf_get_u8(b, &e3)) != 0))
			fatal_fr(r, "parse RSA");
		e = e1;
		debug("e %lx", e);
		जर (e < 30) {
			e <<= 8;
			e += e2;
			debug("e %lx", e);
			e <<= 8;
			e += e3;
			debug("e %lx", e);
		}
		जर ((rsa_e = BN_new()) == रिक्त)
			fatal_f("BN_new");
		जर (!BN_set_word(rsa_e, e)) {
			BN_clear_free(rsa_e);
			sshkey_free(किल्ली);
			परत रिक्त;
		}
		जर ((rsa_n = BN_new()) == रिक्त ||
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
		जर ((r = ssh_rsa_complete_crt_parameters(rsa_d, rsa_p, rsa_q,
		    rsa_iqmp, &rsa_dmp1, &rsa_dmq1)) != 0)
			fatal_fr(r, "generate RSA CRT parameters");
		EVP_PKEY_free(किल्ली->pkey);
		जर ((किल्ली->pkey = EVP_PKEY_new()) == रिक्त)
			fatal_f("EVP_PKEY_new failed");
		जर ((rsa = RSA_new()) == रिक्त)
			fatal_f("RSA_new failed");
		जर (!RSA_set0_किल्ली(rsa, rsa_n, rsa_e, rsa_d))
			fatal_f("RSA_set0_key failed");
		rsa_n = rsa_e = rsa_d = रिक्त; /* transferred */
		जर (!RSA_set0_factors(rsa, rsa_p, rsa_q))
			fatal_f("RSA_set0_factors failed");
		rsa_p = rsa_q = रिक्त; /* transferred */
		जर (RSA_set0_crt_params(rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp) != 1)
			fatal_f("RSA_set0_crt_params failed");
		rsa_dmp1 = rsa_dmq1 = rsa_iqmp = रिक्त;
		जर (EVP_PKEY_set1_RSA(किल्ली->pkey, rsa) != 1)
			fatal_f("EVP_PKEY_set1_RSA failed");
		RSA_free(rsa);
		alg = "rsa-sha2-256";
		थांबा;
	}
	rlen = sshbuf_len(b);
	जर (rlen != 0)
		error_f("remaining bytes in key blob %d", rlen);

	/* try the key */
	जर ((r = sshkey_sign(किल्ली, &sig, &slen, data, आकार(data),
	    alg, रिक्त, रिक्त, 0)) != 0)
		error_fr(r, "signing with converted key failed");
	अन्यथा जर ((r = sshkey_verify(किल्ली, sig, slen, data, आकार(data),
	    alg, 0, रिक्त)) != 0)
		error_fr(r, "verification with converted key failed");
	जर (r != 0) {
		sshkey_free(किल्ली);
		मुक्त(sig);
		परत रिक्त;
	}
	मुक्त(sig);
	परत किल्ली;
}

स्थिर पूर्णांक
get_ओळ(खाता *fp, अक्षर *ओळ, माप_प्रकार len)
{
	पूर्णांक c;
	माप_प्रकार pos = 0;

	ओळ[0] = '\0';
	पर्यंत ((c = ख_अक्षर_लो(fp)) != खातापूर्ण) {
		जर (pos >= len - 1)
			fatal("input line too long.");
		निवड (c) {
		स्थिती '\r':
			c = ख_अक्षर_लो(fp);
			जर (c != खातापूर्ण && c != '\n' && अक्षर_वापस(c, fp) == खातापूर्ण)
				fatal("unget: %s", म_त्रुटि(त्रुटि_सं));
			परत pos;
		स्थिती '\n':
			परत pos;
		}
		ओळ[pos++] = c;
		ओळ[pos] = '\0';
	}
	/* We reached EOF */
	परत -1;
}

स्थिर शून्य
do_convert_from_ssh2(संरचना passwd *pw, संरचना sshkey **k, पूर्णांक *खाजगी)
{
	पूर्णांक r, blen, escaped = 0;
	u_int len;
	अक्षर ओळ[1024];
	संरचना sshbuf *buf;
	अक्षर encoded[8096];
	खाता *fp;

	जर ((buf = sshbuf_new()) == रिक्त)
		fatal("sshbuf_new failed");
	जर ((fp = ख_खोलो(identity_file, "r")) == रिक्त)
		fatal("%s: %s: %s", __progname, identity_file, म_त्रुटि(त्रुटि_सं));
	encoded[0] = '\0';
	पर्यंत ((blen = get_ओळ(fp, ओळ, आकार(ओळ))) != -1) {
		जर (blen > 0 && ओळ[blen - 1] == '\\')
			escaped++;
		जर (म_भेदन(ओळ, "----", 4) == 0 ||
		    म_माला(ओळ, ": ") != रिक्त) {
			जर (म_माला(ओळ, SSH_COM_PRIVATE_BEGIN) != रिक्त)
				*खाजगी = 1;
			जर (म_माला(ओळ, " END ") != रिक्त) {
				थांबा;
			}
			/* fprintf(stderr, "ignore: %s", line); */
			सुरूठेवा;
		}
		जर (escaped) {
			escaped--;
			/* fprintf(stderr, "escaped: %s", line); */
			सुरूठेवा;
		}
		strlcat(encoded, ओळ, आकार(encoded));
	}
	len = म_माप(encoded);
	जर (((len % 4) == 3) &&
	    (encoded[len-1] == '=') &&
	    (encoded[len-2] == '=') &&
	    (encoded[len-3] == '='))
		encoded[len-3] = '\0';
	जर ((r = sshbuf_b64tod(buf, encoded)) != 0)
		fatal_fr(r, "base64 decode");
	जर (*खाजगी) {
		जर ((*k = do_convert_private_ssh2(buf)) == रिक्त)
			fatal_f("private key conversion failed");
	} अन्यथा जर ((r = sshkey_fromb(buf, k)) != 0)
		fatal_fr(r, "parse key");
	sshbuf_free(buf);
	ख_बंद(fp);
}

स्थिर शून्य
do_convert_from_pkcs8(संरचना sshkey **k, पूर्णांक *खाजगी)
{
	EVP_PKEY *pubkey;
	खाता *fp;

	जर ((fp = ख_खोलो(identity_file, "r")) == रिक्त)
		fatal("%s: %s: %s", __progname, identity_file, म_त्रुटि(त्रुटि_सं));
	जर ((pubkey = PEM_read_PUBKEY(fp, रिक्त, रिक्त, रिक्त)) == रिक्त) {
		fatal_f("%s is not a recognised public key format",
		    identity_file);
	}
	ख_बंद(fp);
	निवड (EVP_PKEY_base_id(pubkey)) {
	स्थिती EVP_PKEY_RSA:
		जर ((*k = sshkey_new(किल्ली_UNSPEC)) == रिक्त)
			fatal("sshkey_new failed");
		(*k)->type = किल्ली_RSA;
		(*k)->pkey = pubkey;
		pubkey = रिक्त;
		थांबा;
	स्थिती EVP_PKEY_EC:
		जर ((*k = sshkey_new(किल्ली_UNSPEC)) == रिक्त)
			fatal("sshkey_new failed");
		जर (((*k)->ecdsa_nid = sshkey_ecdsa_fixup_group(pubkey)) == -1)
			fatal("sshkey_ecdsa_fixup_group failed");
		(*k)->type = किल्ली_ECDSA;
		(*k)->pkey = pubkey;
		pubkey = रिक्त;
		थांबा;
	पूर्वनिर्धारित:
		fatal_f("unsupported pubkey type %d",
		    EVP_PKEY_base_id(pubkey));
	}
	EVP_PKEY_free(pubkey);
}

स्थिर शून्य
do_convert_from_pem(संरचना sshkey **k, पूर्णांक *खाजगी)
{
	खाता *fp;
	RSA *rsa;

	जर ((fp = ख_खोलो(identity_file, "r")) == रिक्त)
		fatal("%s: %s: %s", __progname, identity_file, म_त्रुटि(त्रुटि_सं));
	जर ((rsa = PEM_read_RSAPublic_किल्ली(fp, रिक्त, रिक्त, रिक्त)) != रिक्त) {
		जर ((*k = sshkey_new(किल्ली_UNSPEC)) == रिक्त)
			fatal("sshkey_new failed");
		जर (((*k)->pkey = EVP_PKEY_new()) == रिक्त)
			fatal("EVP_PKEY_new failed");
		(*k)->type = किल्ली_RSA;
		जर (EVP_PKEY_set1_RSA((*k)->pkey, rsa) != 1)
			fatal("EVP_PKEY_set1_RSA failed");
		RSA_free(rsa);
		ख_बंद(fp);
		परत;
	}
	fatal_f("unrecognised raw private key format");
}

स्थिर शून्य
do_convert_from(संरचना passwd *pw)
{
	संरचना sshkey *k = रिक्त;
	पूर्णांक r, खाजगी = 0, ok = 0;
	संरचना stat st;

	जर (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	जर (stat(identity_file, &st) == -1)
		fatal("%s: %s: %s", __progname, identity_file, म_त्रुटि(त्रुटि_सं));

	निवड (convert_format) {
	स्थिती FMT_RFC4716:
		do_convert_from_ssh2(pw, &k, &खाजगी);
		थांबा;
	स्थिती FMT_PKCS8:
		do_convert_from_pkcs8(&k, &खाजगी);
		थांबा;
	स्थिती FMT_PEM:
		do_convert_from_pem(&k, &खाजगी);
		थांबा;
	पूर्वनिर्धारित:
		fatal_f("unknown key format %d", convert_format);
	}

	जर (!खाजगी) {
		जर ((r = sshkey_write(k, मानक_निकास)) == 0)
			ok = 1;
		जर (ok)
			ख_लिखो(मानक_निकास, "\n");
	} अन्यथा {
		निवड (k->type) {
		स्थिती किल्ली_ECDSA:
			ok = PEM_write_ECPrivate_किल्ली(मानक_निकास,
			    EVP_PKEY_get0_EC_किल्ली(k->pkey), रिक्त, रिक्त, 0,
			    रिक्त, रिक्त);
			थांबा;
		स्थिती किल्ली_RSA:
			ok = PEM_write_RSAPrivate_किल्ली(मानक_निकास,
			    EVP_PKEY_get0_RSA(k->pkey), रिक्त, रिक्त, 0,
			    रिक्त, रिक्त);
			थांबा;
		पूर्वनिर्धारित:
			fatal_f("unsupported key type %s", sshkey_type(k));
		}
	}

	जर (!ok)
		fatal("key write failed");
	sshkey_free(k);
}
#endif

स्थिर शून्य
do_print_public(संरचना passwd *pw)
{
	संरचना sshkey *prv;
	संरचना stat st;
	पूर्णांक r;
	अक्षर *comment = रिक्त;

	जर (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	जर (stat(identity_file, &st) == -1)
		fatal("%s: %s", identity_file, म_त्रुटि(त्रुटि_सं));
	prv = load_identity(identity_file, &comment);
	जर ((r = sshkey_write(prv, मानक_निकास)) != 0)
		fatal_fr(r, "write key");
	जर (comment != रिक्त && *comment != '\0')
		ख_लिखो(मानक_निकास, " %s", comment);
	ख_लिखो(मानक_निकास, "\n");
	जर (sshkey_is_sk(prv)) {
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
	संरचना sshkey **किल्ल्या = रिक्त;
	पूर्णांक i, nkeys;
	गणना sshkey_fp_rep rep;
	पूर्णांक fptype;
	अक्षर *fp, *ra, **comments = रिक्त;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;

	pkcs11_init(1);
	nkeys = pkcs11_add_provider(pkcs11provider, रिक्त, &किल्ल्या, &comments);
	जर (nkeys <= 0)
		fatal("cannot read public key from pkcs11");
	साठी (i = 0; i < nkeys; i++) {
		जर (print_fingerprint) {
			fp = sshkey_fingerprint(किल्ल्या[i], fptype, rep);
			ra = sshkey_fingerprint(किल्ल्या[i], fingerprint_hash,
			    SSH_FP_RANDOMART);
			जर (fp == रिक्त || ra == रिक्त)
				fatal_f("sshkey_fingerprint fail");
			म_लिखो("%u %s %s (PKCS11 key)\n", sshkey_size(किल्ल्या[i]),
			    fp, sshkey_type(किल्ल्या[i]));
			जर (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
				म_लिखो("%s\n", ra);
			मुक्त(ra);
			मुक्त(fp);
		} अन्यथा {
			(शून्य) sshkey_write(किल्ल्या[i], मानक_निकास); /* XXX check */
			ख_लिखो(मानक_निकास, "%s%s\n",
			    *(comments[i]) == '\0' ? "" : " ", comments[i]);
		}
		मुक्त(comments[i]);
		sshkey_free(किल्ल्या[i]);
	}
	मुक्त(comments);
	मुक्त(किल्ल्या);
	pkcs11_terminate();
	निकास(0);
#अन्यथा
	fatal("no pkcs11 support");
#endif /* ENABLE_PKCS11 */
}

स्थिर संरचना sshkey *
try_read_किल्ली(अक्षर **cpp)
{
	संरचना sshkey *ret;
	पूर्णांक r;

	जर ((ret = sshkey_new(किल्ली_UNSPEC)) == रिक्त)
		fatal("sshkey_new failed");
	जर ((r = sshkey_read(ret, cpp)) == 0)
		परत ret;
	/* Not a key */
	sshkey_free(ret);
	परत रिक्त;
}

स्थिर शून्य
fingerprint_one_किल्ली(स्थिरांक संरचना sshkey *सार्वजनिक, स्थिरांक अक्षर *comment)
{
	अक्षर *fp = रिक्त, *ra = रिक्त;
	गणना sshkey_fp_rep rep;
	पूर्णांक fptype;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;
	fp = sshkey_fingerprint(सार्वजनिक, fptype, rep);
	ra = sshkey_fingerprint(सार्वजनिक, fingerprint_hash, SSH_FP_RANDOMART);
	जर (fp == रिक्त || ra == रिक्त)
		fatal_f("sshkey_fingerprint failed");
	mprintf("%u %s %s (%s)\n", sshkey_size(सार्वजनिक), fp,
	    comment ? comment : "no comment", sshkey_type(सार्वजनिक));
	जर (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
		म_लिखो("%s\n", ra);
	मुक्त(ra);
	मुक्त(fp);
}

स्थिर शून्य
fingerprint_private(स्थिरांक अक्षर *path)
{
	संरचना stat st;
	अक्षर *comment = रिक्त;
	संरचना sshkey *privkey = रिक्त, *pubkey = रिक्त;
	पूर्णांक r;

	जर (stat(identity_file, &st) == -1)
		fatal("%s: %s", path, म_त्रुटि(त्रुटि_सं));
	जर ((r = sshkey_load_public(path, &pubkey, &comment)) != 0)
		debug_r(r, "load public \"%s\"", path);
	जर (pubkey == रिक्त || comment == रिक्त || *comment == '\0') {
		मुक्त(comment);
		जर ((r = sshkey_load_private(path, रिक्त,
		    &privkey, &comment)) != 0)
			debug_r(r, "load private \"%s\"", path);
	}
	जर (pubkey == रिक्त && privkey == रिक्त)
		fatal("%s is not a key file.", path);

	fingerprint_one_किल्ली(pubkey == रिक्त ? privkey : pubkey, comment);
	sshkey_free(pubkey);
	sshkey_free(privkey);
	मुक्त(comment);
}

स्थिर शून्य
do_fingerprint(संरचना passwd *pw)
{
	खाता *f;
	संरचना sshkey *सार्वजनिक = रिक्त;
	अक्षर *comment = रिक्त, *cp, *ep, *ओळ = रिक्त;
	माप_प्रकार linesize = 0;
	पूर्णांक i, invalid = 1;
	स्थिरांक अक्षर *path;
	u_long lnum = 0;

	जर (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	path = identity_file;

	जर (म_भेद(identity_file, "-") == 0) {
		f = मानक_निवेश;
		path = "(stdin)";
	} अन्यथा जर ((f = ख_खोलो(path, "r")) == रिक्त)
		fatal("%s: %s: %s", __progname, path, म_त्रुटि(त्रुटि_सं));

	पर्यंत (getline(&ओळ, &linesize, f) != -1) {
		lnum++;
		cp = ओळ;
		cp[म_खोज(cp, "\r\n")] = '\0';
		/* Trim leading space and comments */
		cp = ओळ + म_अखोज(ओळ, " \t");
		जर (*cp == '#' || *cp == '\0')
			सुरूठेवा;

		/*
		 * Input may be plain keys, private keys, authorized_keys
		 * or known_hosts.
		 */

		/*
		 * Try private keys first. Assume a key is private if
		 * "SSH PRIVATE KEY" appears on the first line and we're
		 * not reading from stdin (XXX support private keys on stdin).
		 */
		जर (lnum == 1 && म_भेद(identity_file, "-") != 0 &&
		    म_माला(cp, "PRIVATE KEY") != रिक्त) {
			मुक्त(ओळ);
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
		जर ((सार्वजनिक = try_read_किल्ली(&cp)) == रिक्त) {
			i = म_से_दीर्घ(cp, &ep, 10);
			जर (i == 0 || ep == रिक्त ||
			    (*ep != ' ' && *ep != '\t')) {
				पूर्णांक quoted = 0;

				comment = cp;
				साठी (; *cp && (quoted || (*cp != ' ' &&
				    *cp != '\t')); cp++) {
					जर (*cp == '\\' && cp[1] == '"')
						cp++;	/* Skip both */
					अन्यथा जर (*cp == '"')
						quoted = !quoted;
				}
				जर (!*cp)
					सुरूठेवा;
				*cp++ = '\0';
			}
		}
		/* Retry after parsing leading hostname/key options */
		जर (सार्वजनिक == रिक्त && (सार्वजनिक = try_read_किल्ली(&cp)) == रिक्त) {
			debug("%s:%lu: not a public key", path, lnum);
			सुरूठेवा;
		}

		/* Find trailing comment, if any */
		साठी (; *cp == ' ' || *cp == '\t'; cp++)
			;
		जर (*cp != '\0' && *cp != '#')
			comment = cp;

		fingerprint_one_किल्ली(सार्वजनिक, comment);
		sshkey_free(सार्वजनिक);
		invalid = 0; /* One good key in the file is sufficient */
	}
	ख_बंद(f);
	मुक्त(ओळ);

	जर (invalid)
		fatal("%s is not a public key file.", path);
	निकास(0);
}

स्थिर शून्य
do_gen_all_hostkeys(संरचना passwd *pw)
{
	संरचना {
		अक्षर *किल्ली_type;
		अक्षर *किल्ली_type_display;
		अक्षर *path;
	} किल्ली_types[] = {
#ifdef WITH_OPENSSL
		{ "rsa", "RSA" ,PATH_HOST_RSA_किल्ली_FILE },
		{ "ecdsa", "ECDSA",PATH_HOST_ECDSA_किल्ली_FILE },
#endif /* WITH_OPENSSL */
		{ "ed25519", "ED25519",PATH_HOST_ED25519_किल्ली_FILE },
#ifdef USE_MLDSA
		{ "mldsa44-ed25519", "MLDSA44-ED25519",
		     PATH_HOST_MLDSA44_ED25519_किल्ली_FILE },
#endif
		{ रिक्त, रिक्त, रिक्त }
	};

	uint32_t bits = 0;
	पूर्णांक first = 0;
	संरचना stat st;
	संरचना sshkey *खाजगी, *सार्वजनिक;
	अक्षर comment[किल्ली_COMMENT_MAX], *prv_tmp, *pub_tmp, *prv_file, *pub_file;
	पूर्णांक i, type, fd, r;

	साठी (i = 0; किल्ली_types[i].किल्ली_type; i++) {
		सार्वजनिक = खाजगी = रिक्त;
		prv_tmp = pub_tmp = prv_file = pub_file = रिक्त;

		xasprintf(&prv_file, "%s%s",
		    identity_file, किल्ली_types[i].path);

		/* Check whether private key exists and is not zero-length */
		जर (stat(prv_file, &st) == 0) {
			जर (st.st_size != 0)
				जा next;
		} अन्यथा जर (त्रुटि_सं != ENOENT) {
			error("Could not stat %s: %s", किल्ली_types[i].path,
			    म_त्रुटि(त्रुटि_सं));
			जा failnext;
		}

		/*
		 * Private key doesn't exist or is invalid; proceed with
		 * key generation.
		 */
		xasprintf(&prv_tmp, "%s%s.XXXXXXXXXX",
		    identity_file, किल्ली_types[i].path);
		xasprintf(&pub_tmp, "%s%s.pub.XXXXXXXXXX",
		    identity_file, किल्ली_types[i].path);
		xasprintf(&pub_file, "%s%s.pub",
		    identity_file, किल्ली_types[i].path);

		जर (first == 0) {
			first = 1;
			म_लिखो("%s: generating new host keys: ", __progname);
		}
		म_लिखो("%s ", किल्ली_types[i].किल्ली_type_display);
		ख_साफ(मानक_निकास);
		type = sshkey_type_from_shortname(किल्ली_types[i].किल्ली_type);
		जर ((fd = mkstemp(prv_tmp)) == -1) {
			error("Could not save your private key in %s: %s",
			    prv_tmp, म_त्रुटि(त्रुटि_सं));
			जा failnext;
		}
		(शून्य)बंद(fd); /* just using mkstemp() to reserve a name */
		bits = 0;
		type_bits_valid(type, रिक्त, &bits);
		जर ((r = sshkey_generate(type, bits, &खाजगी)) != 0) {
			error_r(r, "sshkey_generate failed");
			जा failnext;
		}
		जर ((r = sshkey_from_private(खाजगी, &सार्वजनिक)) != 0)
			fatal_fr(r, "sshkey_from_private");
		snprintf(comment, आकार comment, "%s@%s", pw->pw_name,
		    hostname);
		जर ((r = sshkey_save_private(खाजगी, prv_tmp, "",
		    comment, private_किल्ली_format, openssh_format_cipher,
		    rounds)) != 0) {
			error_r(r, "Saving key \"%s\" failed", prv_tmp);
			जा failnext;
		}
		जर ((fd = mkstemp(pub_tmp)) == -1) {
			error("Could not save your public key in %s: %s",
			    pub_tmp, म_त्रुटि(त्रुटि_सं));
			जा failnext;
		}
		(शून्य)fchmod(fd, 0644);
		(शून्य)बंद(fd);
		जर ((r = sshkey_save_public(सार्वजनिक, pub_tmp, comment)) != 0) {
			error_r(r, "Unable to save public key to %s",
			    identity_file);
			जा failnext;
		}

		/* Rename temporary files to their permanent locations. */
		जर (नाम(pub_tmp, pub_file) != 0) {
			error("Unable to move %s into position: %s",
			    pub_file, म_त्रुटि(त्रुटि_सं));
			जा failnext;
		}
		जर (नाम(prv_tmp, prv_file) != 0) {
			error("Unable to move %s into position: %s",
			    किल्ली_types[i].path, म_त्रुटि(त्रुटि_सं));
 failnext:
			first = 0;
			जा next;
		}
 next:
		sshkey_free(खाजगी);
		sshkey_free(सार्वजनिक);
		मुक्त(prv_tmp);
		मुक्त(pub_tmp);
		मुक्त(prv_file);
		मुक्त(pub_file);
	}
	जर (first != 0)
		म_लिखो("\n");
}

संरचना known_hosts_ctx {
	स्थिरांक अक्षर *host;	/* Hostname searched for in find/delete case */
	खाता *out;		/* Output file, stdout for find_hosts case */
	पूर्णांक has_unhashed;	/* When hashing, original had unhashed hosts */
	पूर्णांक found_किल्ली;		/* For find/delete, host was found */
	पूर्णांक invalid;		/* File contained invalid items; don't delete */
	पूर्णांक hash_hosts;		/* Hash hostnames as we go */
	पूर्णांक find_host;		/* Search for specific hostname */
	पूर्णांक delete_host;	/* Delete host from known_hosts */
};

स्थिर पूर्णांक
known_hosts_hash(संरचना hostkey_foreach_ओळ *l, शून्य *_ctx)
{
	संरचना known_hosts_ctx *ctx = (संरचना known_hosts_ctx *)_ctx;
	अक्षर *hashed, *cp, *hosts, *ohosts;
	पूर्णांक has_wild = l->hosts && म_खोज(l->hosts, "*?!") != म_माप(l->hosts);
	पूर्णांक was_hashed = l->hosts && l->hosts[0] == HASH_DELIM;

	निवड (l->status) {
	स्थिती HKF_STATUS_OK:
	स्थिती HKF_STATUS_MATCHED:
		/*
		 * Don't hash hosts already hashed, with wildcard
		 * characters or a CA/revocation marker.
		 */
		जर (was_hashed || has_wild || l->marker != MRK_NONE) {
			ख_लिखो(ctx->out, "%s\n", l->ओळ);
			जर (has_wild && !ctx->find_host) {
				logit("%s:%lu: ignoring host name "
				    "with wildcard: %.64s", l->path,
				    l->linenum, l->hosts);
			}
			परत 0;
		}
		/*
		 * Split any comma-separated hostnames from the host list,
		 * hash and store separately.
		 */
		ohosts = hosts = xstrdup(l->hosts);
		पर्यंत ((cp = strsep(&hosts, ",")) != रिक्त && *cp != '\0') {
			lowercase(cp);
			जर ((hashed = host_hash(cp, रिक्त, 0)) == रिक्त)
				fatal("hash_host failed");
			ख_लिखो(ctx->out, "%s %s\n", hashed, l->rawkey);
			मुक्त(hashed);
			ctx->has_unhashed = 1;
		}
		मुक्त(ohosts);
		परत 0;
	स्थिती HKF_STATUS_INVALID:
		/* Retain invalid lines, but mark file as invalid. */
		ctx->invalid = 1;
		logit("%s:%lu: invalid line", l->path, l->linenum);
		/* FALLTHROUGH */
	पूर्वनिर्धारित:
		ख_लिखो(ctx->out, "%s\n", l->ओळ);
		परत 0;
	}
	/* NOTREACHED */
	परत -1;
}

स्थिर पूर्णांक
known_hosts_find_delete(संरचना hostkey_foreach_ओळ *l, शून्य *_ctx)
{
	संरचना known_hosts_ctx *ctx = (संरचना known_hosts_ctx *)_ctx;
	गणना sshkey_fp_rep rep;
	पूर्णांक fptype;
	अक्षर *fp = रिक्त, *ra = रिक्त;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;

	जर (l->status == HKF_STATUS_MATCHED) {
		जर (ctx->delete_host) {
			जर (l->marker != MRK_NONE) {
				/* Don't remove CA and revocation lines */
				ख_लिखो(ctx->out, "%s\n", l->ओळ);
			} अन्यथा {
				/*
				 * Hostname matches and has no CA/revoke
				 * marker, delete it by *not* writing the
				 * line to ctx->out.
				 */
				ctx->found_किल्ली = 1;
				जर (!quiet)
					म_लिखो("# Host %s found: line %lu\n",
					    ctx->host, l->linenum);
			}
			परत 0;
		} अन्यथा जर (ctx->find_host) {
			ctx->found_किल्ली = 1;
			जर (!quiet) {
				म_लिखो("# Host %s found: line %lu %s\n",
				    ctx->host,
				    l->linenum, l->marker == MRK_CA ? "CA" :
				    (l->marker == MRK_REVOKE ? "REVOKED" : ""));
			}
			जर (ctx->hash_hosts)
				known_hosts_hash(l, ctx);
			अन्यथा जर (print_fingerprint) {
				fp = sshkey_fingerprint(l->किल्ली, fptype, rep);
				ra = sshkey_fingerprint(l->किल्ली,
				    fingerprint_hash, SSH_FP_RANDOMART);
				जर (fp == रिक्त || ra == रिक्त)
					fatal_f("sshkey_fingerprint failed");
				mprintf("%s %s %s%s%s\n", ctx->host,
				    sshkey_type(l->किल्ली), fp,
				    l->comment[0] ? " " : "",
				    l->comment);
				जर (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
					म_लिखो("%s\n", ra);
				मुक्त(ra);
				मुक्त(fp);
			} अन्यथा
				ख_लिखो(ctx->out, "%s\n", l->ओळ);
			परत 0;
		}
	} अन्यथा जर (ctx->delete_host) {
		/* Retain non-matching hosts when deleting */
		जर (l->status == HKF_STATUS_INVALID) {
			ctx->invalid = 1;
			logit("%s:%lu: invalid line", l->path, l->linenum);
		}
		ख_लिखो(ctx->out, "%s\n", l->ओळ);
	}
	परत 0;
}

स्थिर शून्य
do_known_hosts(संरचना passwd *pw, स्थिरांक अक्षर *name, पूर्णांक find_host,
    पूर्णांक delete_host, पूर्णांक hash_hosts)
{
	अक्षर *cp, tmp[PATH_MAX], old[PATH_MAX];
	पूर्णांक r, fd, oerrno, inplace = 0;
	संरचना known_hosts_ctx ctx;
	u_int foreach_options;
	संरचना stat sb;

	जर (!have_identity) {
		cp = tilde_expand_filename(_PATH_SSH_USER_HOSTFILE, pw->pw_uid);
		जर (strlcpy(identity_file, cp, आकार(identity_file)) >=
		    आकार(identity_file))
			fatal("Specified known hosts path too long");
		मुक्त(cp);
		have_identity = 1;
	}
	जर (stat(identity_file, &sb) != 0)
		fatal("Cannot stat %s: %s", identity_file, म_त्रुटि(त्रुटि_सं));

	स_रखो(&ctx, 0, आकार(ctx));
	ctx.out = मानक_निकास;
	ctx.host = name;
	ctx.hash_hosts = hash_hosts;
	ctx.find_host = find_host;
	ctx.delete_host = delete_host;

	/*
	 * Find hosts goes to stdout, hash and deletions happen in-place
	 * A corner case is ssh-keygen -HF foo, which should go to stdout
	 */
	जर (!find_host && (hash_hosts || delete_host)) {
		जर (strlcpy(tmp, identity_file, आकार(tmp)) >= आकार(tmp) ||
		    strlcat(tmp, ".XXXXXXXXXX", आकार(tmp)) >= आकार(tmp) ||
		    strlcpy(old, identity_file, आकार(old)) >= आकार(old) ||
		    strlcat(old, ".old", आकार(old)) >= आकार(old))
			fatal("known_hosts path too long");
		umask(077);
		जर ((fd = mkstemp(tmp)) == -1)
			fatal("mkstemp: %s", म_त्रुटि(त्रुटि_सं));
		जर ((ctx.out = fdopen(fd, "w")) == रिक्त) {
			oerrno = त्रुटि_सं;
			unlink(tmp);
			fatal("fdopen: %s", म_त्रुटि(oerrno));
		}
		(शून्य)fchmod(fd, sb.st_mode & 0644);
		inplace = 1;
	}
	/* XXX support identity_file == "-" for stdin */
	foreach_options = find_host ? HKF_WANT_MATCH : 0;
	foreach_options |= print_fingerprint ? HKF_WANT_PARSE_किल्ली : 0;
	जर ((r = hostkeys_foreach(identity_file, (find_host || !hash_hosts) ?
	    known_hosts_find_delete : known_hosts_hash, &ctx, name, रिक्त,
	    foreach_options, 0)) != 0) {
		जर (inplace)
			unlink(tmp);
		fatal_fr(r, "hostkeys_foreach");
	}

	जर (inplace)
		ख_बंद(ctx.out);

	जर (ctx.invalid) {
		error("%s is not a valid known_hosts file.", identity_file);
		जर (inplace) {
			error("Not replacing existing known_hosts "
			    "file because of errors");
			unlink(tmp);
		}
		निकास(1);
	} अन्यथा जर (delete_host && !ctx.found_किल्ली) {
		logit("Host %s not found in %s", name, identity_file);
		जर (inplace)
			unlink(tmp);
	} अन्यथा जर (inplace) {
		/* Backup existing file */
		जर (unlink(old) == -1 && त्रुटि_सं != ENOENT)
			fatal("unlink %.100s: %s", old, म_त्रुटि(त्रुटि_सं));
		जर (link(identity_file, old) == -1)
			fatal("link %.100s to %.100s: %s", identity_file, old,
			    म_त्रुटि(त्रुटि_सं));
		/* Move new one into place */
		जर (नाम(tmp, identity_file) == -1) {
			error("rename\"%s\" to \"%s\": %s", tmp, identity_file,
			    म_त्रुटि(त्रुटि_सं));
			unlink(tmp);
			unlink(old);
			निकास(1);
		}

		म_लिखो("%s updated.\n", identity_file);
		म_लिखो("Original contents retained as %s\n", old);
		जर (ctx.has_unhashed) {
			logit("WARNING: %s contains unhashed entries", old);
			logit("Delete this file to ensure privacy "
			    "of hostnames");
		}
	}

	निकास (find_host && !ctx.found_किल्ली);
}

/*
 * Perform changing a passphrase.  The argument is the passwd structure
 * for the current user.
 */
स्थिर शून्य
do_change_passphrase(संरचना passwd *pw, अक्षर * स्थिरांक *opts, माप_प्रकार nopts)
{
	अक्षर *comment;
	अक्षर *old_passphrase, *passphrase1, *passphrase2;
	संरचना stat st;
	संरचना sshkey *खाजगी;
	पूर्णांक r;
	माप_प्रकार i;

	जर (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	जर (stat(identity_file, &st) == -1)
		fatal("%s: %s", identity_file, म_त्रुटि(त्रुटि_सं));
	/* Try to load the file with empty passphrase. */
	r = sshkey_load_private(identity_file, "", &खाजगी, &comment);
	जर (r == SSH_ERR_किल्ली_WRONG_PASSPHRASE) {
		जर (identity_passphrase)
			old_passphrase = xstrdup(identity_passphrase);
		अन्यथा
			old_passphrase =
			    read_passphrase("Enter old passphrase: ",
			    RP_ALLOW_STDIN);
		r = sshkey_load_private(identity_file, old_passphrase,
		    &खाजगी, &comment);
		freezero(old_passphrase, म_माप(old_passphrase));
		जर (r != 0)
			जा badkey;
	} अन्यथा जर (r != 0) {
 badkey:
		fatal_r(r, "Failed to load key %s", identity_file);
	}
	जर (comment)
		mprintf("Key has comment '%s'\n", comment);

	/* All current -O options relate to FIDO keys only */
	जर (nopts != 0 && !sshkey_is_sk(खाजगी)) {
		fatal("FIDO-specific option requested for non-FIDO key %s",
		    identity_file);
	}
	जर (sshkey_is_sk(खाजगी)) {
		debug_f("%s: original FIDO key flags: "
		    "%stouch-required %sverify-required", identity_file,
		    (खाजगी->sk_flags & SSH_SK_USER_PRESENCE_REQD) ? "": "no-",
		    (खाजगी->sk_flags & SSH_SK_USER_VERIFICATION_REQD) ? "" : "no-");
	}
	साठी (i = 0; i < nopts; i++) {
		जर (strcasecmp(opts[i], "touch-required") == 0)
			खाजगी->sk_flags |= SSH_SK_USER_PRESENCE_REQD;
		अन्यथा जर (strcasecmp(opts[i], "no-touch-required") == 0)
			खाजगी->sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
		अन्यथा जर (strcasecmp(opts[i], "verify-required") == 0)
			खाजगी->sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
		अन्यथा जर (strcasecmp(opts[i], "no-verify-required") == 0)
			खाजगी->sk_flags &= ~SSH_SK_USER_VERIFICATION_REQD;
		अन्यथा {
			fatal("Option \"%s\" is unsupported for "
			    "key passphrase change", opts[i]);
		}
	}
	जर (sshkey_is_sk(खाजगी) && nopts != 0) {
		debug_f("%s: updated FIDO key flags: "
		    "%stouch-required %sverify-required", identity_file,
		    (खाजगी->sk_flags & SSH_SK_USER_PRESENCE_REQD) ? "": "no-",
		    (खाजगी->sk_flags & SSH_SK_USER_VERIFICATION_REQD) ? "" : "no-");
	}

	/* Ask the new passphrase (twice). */
	जर (identity_new_passphrase) {
		passphrase1 = xstrdup(identity_new_passphrase);
		passphrase2 = रिक्त;
	} अन्यथा {
		passphrase1 =
			read_passphrase("Enter new passphrase (empty for no "
			    "passphrase): ", RP_ALLOW_STDIN);
		passphrase2 = read_passphrase("Enter same passphrase again: ",
		    RP_ALLOW_STDIN);

		/* Verify that they are the same. */
		जर (म_भेद(passphrase1, passphrase2) != 0) {
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
	जर ((r = sshkey_save_private(खाजगी, identity_file, passphrase1,
	    comment, private_किल्ली_format, openssh_format_cipher, rounds)) != 0) {
		error_r(r, "Saving key \"%s\" failed", identity_file);
		freezero(passphrase1, म_माप(passphrase1));
		sshkey_free(खाजगी);
		मुक्त(comment);
		निकास(1);
	}
	/* Destroy the passphrase and the copy of the key in memory. */
	freezero(passphrase1, म_माप(passphrase1));
	sshkey_free(खाजगी);		 /* Destroys contents */
	मुक्त(comment);

	म_लिखो("Your identification has been saved with the new passphrase.\n");
	निकास(0);
}

/*
 * Print the SSHFP RR.
 */
स्थिर पूर्णांक
do_print_resource_record(संरचना passwd *pw, अक्षर *fname, अक्षर *hname,
    पूर्णांक print_generic, अक्षर * स्थिरांक *opts, माप_प्रकार nopts)
{
	संरचना sshkey *सार्वजनिक;
	अक्षर *comment = रिक्त;
	स्थिरांक अक्षर *p;
	संरचना stat st;
	पूर्णांक r, hash = -1;
	माप_प्रकार i;

	साठी (i = 0; i < nopts; i++) {
		जर ((p = strprefix(opts[i], "hashalg=", 1)) != रिक्त) {
			जर ((hash = ssh_digest_alg_by_name(p)) == -1)
				fatal("Unsupported hash algorithm");
		} अन्यथा {
			error("Invalid option \"%s\"", opts[i]);
			परत SSH_ERR_INVALID_ARGUMENT;
		}
	}
	जर (fname == रिक्त)
		fatal_f("no filename");
	जर (stat(fname, &st) == -1) {
		जर (त्रुटि_सं == ENOENT)
			परत 0;
		fatal("%s: %s", fname, म_त्रुटि(त्रुटि_सं));
	}
	जर ((r = sshkey_load_public(fname, &सार्वजनिक, &comment)) != 0)
		fatal_r(r, "Failed to read v2 public key from \"%s\"", fname);
	export_dns_rr(hname, सार्वजनिक, मानक_निकास, print_generic, hash);
	sshkey_free(सार्वजनिक);
	मुक्त(comment);
	परत 1;
}

/*
 * Change the comment of a private key file.
 */
स्थिर शून्य
do_change_comment(संरचना passwd *pw, स्थिरांक अक्षर *identity_comment)
{
	अक्षर new_comment[किल्ली_COMMENT_MAX], *comment, *passphrase;
	संरचना sshkey *खाजगी;
	संरचना sshkey *सार्वजनिक;
	संरचना stat st;
	पूर्णांक r;

	जर (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	जर (stat(identity_file, &st) == -1)
		fatal("%s: %s", identity_file, म_त्रुटि(त्रुटि_सं));
	जर ((r = sshkey_load_private(identity_file, "",
	    &खाजगी, &comment)) == 0)
		passphrase = xstrdup("");
	अन्यथा जर (r != SSH_ERR_किल्ली_WRONG_PASSPHRASE)
		fatal_r(r, "Cannot load private key \"%s\"", identity_file);
	अन्यथा {
		जर (identity_passphrase)
			passphrase = xstrdup(identity_passphrase);
		अन्यथा जर (identity_new_passphrase)
			passphrase = xstrdup(identity_new_passphrase);
		अन्यथा
			passphrase = read_passphrase("Enter passphrase: ",
			    RP_ALLOW_STDIN);
		/* Try to load using the passphrase. */
		जर ((r = sshkey_load_private(identity_file, passphrase,
		    &खाजगी, &comment)) != 0) {
			freezero(passphrase, म_माप(passphrase));
			fatal_r(r, "Cannot load private key \"%s\"",
			    identity_file);
		}
	}

	जर (खाजगी->type != किल्ली_ED25519 &&
	    private_किल्ली_format != SSHKEY_PRIVATE_OPENSSH) {
		error("Comments are only supported for keys stored in "
		    "the new format (-o).");
		explicit_bzero(passphrase, म_माप(passphrase));
		sshkey_free(खाजगी);
		निकास(1);
	}
	जर (comment)
		म_लिखो("Old comment: %s\n", comment);
	अन्यथा
		म_लिखो("No existing comment\n");

	जर (identity_comment) {
		strlcpy(new_comment, identity_comment, आकार(new_comment));
	} अन्यथा {
		म_लिखो("New comment: ");
		ख_साफ(मानक_निकास);
		जर (!ख_माला_लो(new_comment, आकार(new_comment), मानक_निवेश)) {
			explicit_bzero(passphrase, म_माप(passphrase));
			sshkey_free(खाजगी);
			निकास(1);
		}
		new_comment[म_खोज(new_comment, "\n")] = '\0';
	}
	जर (comment != रिक्त && म_भेद(comment, new_comment) == 0) {
		म_लिखो("No change to comment\n");
		मुक्त(passphrase);
		sshkey_free(खाजगी);
		मुक्त(comment);
		निकास(0);
	}

	/* Save the file using the new passphrase. */
	जर ((r = sshkey_save_private(खाजगी, identity_file, passphrase,
	    new_comment, private_किल्ली_format, openssh_format_cipher,
	    rounds)) != 0) {
		error_r(r, "Saving key \"%s\" failed", identity_file);
		freezero(passphrase, म_माप(passphrase));
		sshkey_free(खाजगी);
		मुक्त(comment);
		निकास(1);
	}
	freezero(passphrase, म_माप(passphrase));
	जर ((r = sshkey_from_private(खाजगी, &सार्वजनिक)) != 0)
		fatal_fr(r, "sshkey_from_private");
	sshkey_free(खाजगी);

	strlcat(identity_file, ".pub", आकार(identity_file));
	जर ((r = sshkey_save_public(सार्वजनिक, identity_file, new_comment)) != 0)
		fatal_r(r, "Unable to save public key to %s", identity_file);
	sshkey_free(सार्वजनिक);
	मुक्त(comment);

	जर (म_माप(new_comment) > 0)
		म_लिखो("Comment '%s' applied\n", new_comment);
	अन्यथा
		म_लिखो("Comment removed\n");

	निकास(0);
}

स्थिर शून्य
cert_ext_add(स्थिरांक अक्षर *किल्ली, स्थिरांक अक्षर *मूल्य, पूर्णांक iscrit)
{
	cert_ext = xreallocarray(cert_ext, ncert_ext + 1, आकार(*cert_ext));
	cert_ext[ncert_ext].किल्ली = xstrdup(किल्ली);
	cert_ext[ncert_ext].val = मूल्य == रिक्त ? रिक्त : xstrdup(मूल्य);
	cert_ext[ncert_ext].crit = iscrit;
	ncert_ext++;
}

/* qsort(3) comparison function for certificate extensions */
स्थिर पूर्णांक
cert_ext_cmp(स्थिरांक शून्य *_a, स्थिरांक शून्य *_b)
{
	स्थिरांक संरचना cert_ext *a = (स्थिरांक संरचना cert_ext *)_a;
	स्थिरांक संरचना cert_ext *b = (स्थिरांक संरचना cert_ext *)_b;
	पूर्णांक r;

	जर (a->crit != b->crit)
		परत (a->crit < b->crit) ? -1 : 1;
	जर ((r = म_भेद(a->किल्ली, b->किल्ली)) != 0)
		परत r;
	जर ((a->val == रिक्त) != (b->val == रिक्त))
		परत (a->val == रिक्त) ? -1 : 1;
	जर (a->val != रिक्त && (r = म_भेद(a->val, b->val)) != 0)
		परत r;
	परत 0;
}

#define OPTIONS_CRITICAL	1
#define OPTIONS_EXTENSIONS	2
स्थिर शून्य
prepare_options_buf(संरचना sshbuf *c, पूर्णांक which)
{
	संरचना sshbuf *b;
	माप_प्रकार i;
	पूर्णांक r;
	स्थिरांक संरचना cert_ext *ext;

	जर ((b = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	sshbuf_reset(c);
	साठी (i = 0; i < ncert_ext; i++) {
		ext = &cert_ext[i];
		जर ((ext->crit && (which & OPTIONS_EXTENSIONS)) ||
		    (!ext->crit && (which & OPTIONS_CRITICAL)))
			सुरूठेवा;
		जर (ext->val == रिक्त) {
			/* flag option */
			debug3_f("%s", ext->किल्ली);
			जर ((r = sshbuf_put_cstring(c, ext->किल्ली)) != 0 ||
			    (r = sshbuf_put_string(c, रिक्त, 0)) != 0)
				fatal_fr(r, "prepare flag");
		} अन्यथा {
			/* key/value option */
			debug3_f("%s=%s", ext->किल्ली, ext->val);
			sshbuf_reset(b);
			जर ((r = sshbuf_put_cstring(c, ext->किल्ली)) != 0 ||
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
	जर (certflags_command != रिक्त)
		cert_ext_add("force-command", certflags_command, 1);
	जर (certflags_src_addr != रिक्त)
		cert_ext_add("source-address", certflags_src_addr, 1);
	जर ((certflags_flags & CERTOPT_REQUIRE_VERIFY) != 0)
		cert_ext_add("verify-required", रिक्त, 1);
	/* extensions */
	जर ((certflags_flags & CERTOPT_X_FWD) != 0)
		cert_ext_add("permit-X11-forwarding", रिक्त, 0);
	जर ((certflags_flags & CERTOPT_AGENT_FWD) != 0)
		cert_ext_add("permit-agent-forwarding", रिक्त, 0);
	जर ((certflags_flags & CERTOPT_PORT_FWD) != 0)
		cert_ext_add("permit-port-forwarding", रिक्त, 0);
	जर ((certflags_flags & CERTOPT_PTY) != 0)
		cert_ext_add("permit-pty", रिक्त, 0);
	जर ((certflags_flags & CERTOPT_USER_RC) != 0)
		cert_ext_add("permit-user-rc", रिक्त, 0);
	जर ((certflags_flags & CERTOPT_NO_REQUIRE_USER_PRESENCE) != 0)
		cert_ext_add("no-touch-required", रिक्त, 0);
	/* order lexically by key */
	जर (ncert_ext > 0)
		क्विक(cert_ext, ncert_ext, आकार(*cert_ext), cert_ext_cmp);
}

स्थिर संरचना sshkey *
load_pkcs11_किल्ली(अक्षर *path)
{
#ifdef ENABLE_PKCS11
	संरचना sshkey **किल्ल्या = रिक्त, *सार्वजनिक, *खाजगी = रिक्त;
	पूर्णांक r, i, nkeys;

	जर ((r = sshkey_load_public(path, &सार्वजनिक, रिक्त)) != 0)
		fatal_r(r, "Couldn't load CA public key \"%s\"", path);

	nkeys = pkcs11_add_provider(pkcs11provider, identity_passphrase,
	    &किल्ल्या, रिक्त);
	debug3_f("%d keys", nkeys);
	जर (nkeys <= 0)
		fatal("cannot read public key from pkcs11");
	साठी (i = 0; i < nkeys; i++) {
		जर (sshkey_equal_public(सार्वजनिक, किल्ल्या[i])) {
			खाजगी = किल्ल्या[i];
			सुरूठेवा;
		}
		sshkey_free(किल्ल्या[i]);
	}
	मुक्त(किल्ल्या);
	sshkey_free(सार्वजनिक);
	परत खाजगी;
#अन्यथा
	fatal("no pkcs11 support");
#endif /* ENABLE_PKCS11 */
}

/* Signer for sshkey_certify_custom that uses the agent */
स्थिर पूर्णांक
agent_signer(संरचना sshkey *किल्ली, u_char **sigp, माप_प्रकार *lenp,
    स्थिरांक u_char *data, माप_प्रकार datalen,
    स्थिरांक अक्षर *alg, स्थिरांक अक्षर *provider, स्थिरांक अक्षर *pin,
    u_int compat, शून्य *ctx)
{
	पूर्णांक *agent_fdp = (पूर्णांक *)ctx;

	परत ssh_agent_sign(*agent_fdp, किल्ली, sigp, lenp,
	    data, datalen, alg, compat);
}

स्थिर शून्य
do_ca_sign(संरचना passwd *pw, स्थिरांक अक्षर *ca_किल्ली_path, पूर्णांक prefer_agent,
    अचिन्हित दीर्घ दीर्घ cert_serial, पूर्णांक cert_serial_autoinc,
    पूर्णांक argc, अक्षर **argv)
{
	पूर्णांक r, i, किल्ली_in_agent = 0, agent_fd = -1;
	u_int n;
	संरचना sshkey *ca, *सार्वजनिक;
	अक्षर valid[64], *otmp, *tmp, *cp, *out, *comment;
	अक्षर *ca_fp = रिक्त, **plist = रिक्त, *pin = रिक्त;
	संरचना ssh_identitylist *agent_ids;
	माप_प्रकार j;
	संरचना notifier_ctx *notifier = रिक्त;

#ifdef ENABLE_PKCS11
	pkcs11_init(1);
#endif
	tmp = tilde_expand_filename(ca_किल्ली_path, pw->pw_uid);
	जर (pkcs11provider != रिक्त) {
		/* If a PKCS#11 token was specified then try to use it */
		जर ((ca = load_pkcs11_किल्ली(tmp)) == रिक्त)
			fatal("No PKCS#11 key matching %s found", ca_किल्ली_path);
	} अन्यथा जर (prefer_agent) {
		/*
		 * Agent signature requested. Try to use agent after making
		 * sure the public key specified is actually present in the
		 * agent.
		 */
		जर ((r = sshkey_load_public(tmp, &ca, रिक्त)) != 0)
			fatal_r(r, "Cannot load CA public key %s", tmp);
		जर ((r = ssh_get_authentication_socket(&agent_fd)) != 0)
			fatal_r(r, "Cannot use public key for CA signature");
		जर ((r = ssh_fetch_identitylist(agent_fd, &agent_ids)) != 0)
			fatal_r(r, "Retrieve agent key list");
		साठी (j = 0; j < agent_ids->nkeys; j++) {
			जर (sshkey_equal(ca, agent_ids->किल्ल्या[j])) {
				किल्ली_in_agent = 1;
				/* Replace the CA key with the agent one */
				sshkey_free(ca);
				ca = agent_ids->किल्ल्या[j];
				agent_ids->किल्ल्या[j] = रिक्त;
				थांबा;
			}
		}
		जर (!किल्ली_in_agent)
			fatal("CA key %s not found in agent", tmp);
		ssh_free_identitylist(agent_ids);
	} अन्यथा {
		/* CA key is assumed to be a private key on the filesystem */
		ca = load_identity(tmp, रिक्त);
		जर (sshkey_is_sk(ca) &&
		    (ca->sk_flags & SSH_SK_USER_VERIFICATION_REQD)) {
			जर ((pin = read_passphrase("Enter PIN for CA key: ",
			    RP_ALLOW_STDIN)) == रिक्त)
				fatal_f("couldn't read PIN");
		}
	}
	मुक्त(tmp);

	जर (किल्ली_type_name != रिक्त) {
		जर (sshkey_type_from_shortname(किल्ली_type_name) != ca->type) {
			fatal("CA key type %s doesn't match specified %s",
			    sshkey_ssh_name(ca), किल्ली_type_name);
		}
	} अन्यथा जर (ca->type == किल्ली_RSA) {
		/* Default to a good signature algorithm */
		किल्ली_type_name = "rsa-sha2-512";
	}
	ca_fp = sshkey_fingerprint(ca, fingerprint_hash, SSH_FP_DEFAULT);

	finalise_cert_exts();
	साठी (i = 0; i < argc; i++) {
		/* Split list of principals */
		n = 0;
		जर (cert_principals != रिक्त) {
			otmp = tmp = xstrdup(cert_principals);
			plist = रिक्त;
			साठी (; (cp = strsep(&tmp, ",")) != रिक्त; n++) {
				plist = xreallocarray(plist, n + 1, आकार(*plist));
				जर (*(plist[n] = xstrdup(cp)) == '\0')
					fatal("Empty principal name");
			}
			मुक्त(otmp);
		}
		जर (n > SSHKEY_CERT_MAX_PRINCIPALS)
			fatal("Too many certificate principals specified");

		tmp = tilde_expand_filename(argv[i], pw->pw_uid);
		जर ((r = sshkey_load_public(tmp, &सार्वजनिक, &comment)) != 0)
			fatal_r(r, "load pubkey \"%s\"", tmp);
		जर (sshkey_is_cert(सार्वजनिक))
			fatal_f("key \"%s\" type %s cannot be certified",
			    tmp, sshkey_type(सार्वजनिक));

		/* Prepare certificate to sign */
		जर ((r = sshkey_to_certified(सार्वजनिक)) != 0)
			fatal_r(r, "Could not upgrade key %s to certificate", tmp);
		सार्वजनिक->cert->type = cert_किल्ली_type;
		सार्वजनिक->cert->serial = (uint64_t)cert_serial;
		सार्वजनिक->cert->किल्ली_id = xstrdup(cert_किल्ली_id);
		सार्वजनिक->cert->nprincipals = n;
		सार्वजनिक->cert->principals = plist;
		सार्वजनिक->cert->valid_after = cert_valid_from;
		सार्वजनिक->cert->valid_before = cert_valid_to;
		prepare_options_buf(सार्वजनिक->cert->critical, OPTIONS_CRITICAL);
		prepare_options_buf(सार्वजनिक->cert->extensions,
		    OPTIONS_EXTENSIONS);
		जर ((r = sshkey_from_private(ca,
		    &सार्वजनिक->cert->signature_किल्ली)) != 0)
			fatal_r(r, "sshkey_from_private (ca key)");

		जर (किल्ली_in_agent) {
			जर ((r = sshkey_certify_custom(सार्वजनिक, ca,
			    किल्ली_type_name, sk_provider, रिक्त, agent_signer,
			    &agent_fd)) != 0)
				fatal_r(r, "Couldn't certify %s via agent", tmp);
		} अन्यथा {
			जर (sshkey_is_sk(ca) &&
			    (ca->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
				notifier = notify_start(0,
				    "Confirm user presence for key %s %s",
				    sshkey_type(ca), ca_fp);
			}
			r = sshkey_certify(सार्वजनिक, ca, किल्ली_type_name,
			    sk_provider, pin);
			notify_complete(notifier, "User presence confirmed");
			जर (r != 0)
				fatal_r(r, "Couldn't certify key %s", tmp);
		}

		जर ((cp = म_खोजप(tmp, '.')) != रिक्त && म_भेद(cp, ".pub") == 0)
			*cp = '\0';
		xasprintf(&out, "%s-cert.pub", tmp);
		मुक्त(tmp);

		जर ((r = sshkey_save_public(सार्वजनिक, out, comment)) != 0) {
			fatal_r(r, "Unable to save public key to %s",
			    identity_file);
		}

		जर (!quiet) {
			sshkey_format_cert_validity(सार्वजनिक->cert,
			    valid, आकार(valid));
			logit("Signed %s key %s: id \"%s\" serial %llu%s%s "
			    "valid %s", sshkey_cert_type(सार्वजनिक),
			    out, सार्वजनिक->cert->किल्ली_id,
			    (अचिन्हित दीर्घ दीर्घ)सार्वजनिक->cert->serial,
			    cert_principals != रिक्त ? " for " : "",
			    cert_principals != रिक्त ? cert_principals : "",
			    valid);
		}

		sshkey_free(सार्वजनिक);
		मुक्त(out);
		मुक्त(comment);
		जर (cert_serial_autoinc)
			cert_serial++;
	}
	जर (pin != रिक्त)
		freezero(pin, म_माप(pin));
	sshkey_free(ca);
	मुक्त(ca_fp);
#ifdef ENABLE_PKCS11
	pkcs11_terminate();
#endif
}

स्थिर uint64_t
parse_relative_time(स्थिरांक अक्षर *s, समय_प्रकार now)
{
	int64_t mul, secs;

	mul = *s == '-' ? -1 : 1;

	जर ((secs = convtime(s + 1)) == -1)
		fatal("Invalid relative certificate time %s", s);
	जर (mul == -1 && secs > now)
		fatal("Certificate time %s cannot be represented", s);
	परत now + (uint64_t)(secs * mul);
}

स्थिर शून्य
parse_hex_u64(स्थिरांक अक्षर *s, uint64_t *up)
{
	अक्षर *ep;
	अचिन्हित दीर्घ दीर्घ ull;

	त्रुटि_सं = 0;
	ull = strtoull(s, &ep, 16);
	जर (*s == '\0' || *ep != '\0')
		fatal("Invalid certificate time: not a number");
	जर (त्रुटि_सं == दुस्फल && ull == अच_दीर्घ_उच्च)
		fatal_fr(SSH_ERR_SYSTEM_ERROR, "Invalid certificate time");
	*up = (uint64_t)ull;
}

स्थिर शून्य
parse_cert_times(अक्षर *timespec)
{
	अक्षर *from, *to;
	समय_प्रकार now = समय(रिक्त);
	int64_t secs;

	/* +timespec relative to now */
	जर (*timespec == '+' && म_अक्षर(timespec, ':') == रिक्त) {
		जर ((secs = convtime(timespec + 1)) == -1)
			fatal("Invalid relative certificate life %s", timespec);
		cert_valid_to = now + secs;
		/*
		 * Backdate certificate one minute to avoid problems on hosts
		 * with poorly-synchronised clocks.
		 */
		cert_valid_from = ((now - 59)/ 60) * 60;
		परत;
	}

	/*
	 * from:to, where
	 * from := [+-]timespec | YYYYMMDD | YYYYMMDDHHMMSS | 0x... | "always"
	 *   to := [+-]timespec | YYYYMMDD | YYYYMMDDHHMMSS | 0x... | "forever"
	 */
	from = xstrdup(timespec);
	to = म_अक्षर(from, ':');
	जर (to == रिक्त || from == to || *(to + 1) == '\0')
		fatal("Invalid certificate life specification %s", timespec);
	*to++ = '\0';

	जर (*from == '-' || *from == '+')
		cert_valid_from = parse_relative_time(from, now);
	अन्यथा जर (म_भेद(from, "always") == 0)
		cert_valid_from = 0;
	अन्यथा जर (म_भेदन(from, "0x", 2) == 0)
		parse_hex_u64(from, &cert_valid_from);
	अन्यथा जर (parse_absolute_time(from, &cert_valid_from) != 0)
		fatal("Invalid from time \"%s\"", from);

	जर (*to == '-' || *to == '+')
		cert_valid_to = parse_relative_time(to, now);
	अन्यथा जर (म_भेद(to, "forever") == 0)
		cert_valid_to = ~(uint64_t)0;
	अन्यथा जर (म_भेदन(to, "0x", 2) == 0)
		parse_hex_u64(to, &cert_valid_to);
	अन्यथा जर (parse_absolute_time(to, &cert_valid_to) != 0)
		fatal("Invalid to time \"%s\"", to);

	जर (cert_valid_to <= cert_valid_from)
		fatal("Empty certificate validity interval");
	मुक्त(from);
}

स्थिर शून्य
add_cert_option(अक्षर *opt)
{
	अक्षर *val, *cp;
	स्थिरांक अक्षर *p;
	पूर्णांक iscrit = 0;

	जर (strcasecmp(opt, "clear") == 0)
		certflags_flags = 0;
	अन्यथा जर (strcasecmp(opt, "no-x11-forwarding") == 0)
		certflags_flags &= ~CERTOPT_X_FWD;
	अन्यथा जर (strcasecmp(opt, "permit-x11-forwarding") == 0)
		certflags_flags |= CERTOPT_X_FWD;
	अन्यथा जर (strcasecmp(opt, "no-agent-forwarding") == 0)
		certflags_flags &= ~CERTOPT_AGENT_FWD;
	अन्यथा जर (strcasecmp(opt, "permit-agent-forwarding") == 0)
		certflags_flags |= CERTOPT_AGENT_FWD;
	अन्यथा जर (strcasecmp(opt, "no-port-forwarding") == 0)
		certflags_flags &= ~CERTOPT_PORT_FWD;
	अन्यथा जर (strcasecmp(opt, "permit-port-forwarding") == 0)
		certflags_flags |= CERTOPT_PORT_FWD;
	अन्यथा जर (strcasecmp(opt, "no-pty") == 0)
		certflags_flags &= ~CERTOPT_PTY;
	अन्यथा जर (strcasecmp(opt, "permit-pty") == 0)
		certflags_flags |= CERTOPT_PTY;
	अन्यथा जर (strcasecmp(opt, "no-user-rc") == 0)
		certflags_flags &= ~CERTOPT_USER_RC;
	अन्यथा जर (strcasecmp(opt, "permit-user-rc") == 0)
		certflags_flags |= CERTOPT_USER_RC;
	अन्यथा जर (strcasecmp(opt, "touch-required") == 0)
		certflags_flags &= ~CERTOPT_NO_REQUIRE_USER_PRESENCE;
	अन्यथा जर (strcasecmp(opt, "no-touch-required") == 0)
		certflags_flags |= CERTOPT_NO_REQUIRE_USER_PRESENCE;
	अन्यथा जर (strcasecmp(opt, "no-verify-required") == 0)
		certflags_flags &= ~CERTOPT_REQUIRE_VERIFY;
	अन्यथा जर (strcasecmp(opt, "verify-required") == 0)
		certflags_flags |= CERTOPT_REQUIRE_VERIFY;
	अन्यथा जर ((p = strprefix(opt, "force-command=", 1)) != रिक्त) {
		जर (*p == '\0')
			fatal("Empty force-command option");
		जर (certflags_command != रिक्त)
			fatal("force-command already specified");
		certflags_command = xstrdup(p);
	} अन्यथा जर ((p = strprefix(opt, "source-address=", 1)) != रिक्त) {
		जर (*p == '\0')
			fatal("Empty source-address option");
		जर (certflags_src_addr != रिक्त)
			fatal("source-address already specified");
		जर (addr_match_cidr_list(रिक्त, p) != 0)
			fatal("Invalid source-address list");
		certflags_src_addr = xstrdup(p);
	} अन्यथा जर (strprefix(opt, "extension:", 1) != रिक्त ||
		    (iscrit = (strprefix(opt, "critical:", 1) != रिक्त))) {
		val = xstrdup(म_अक्षर(opt, ':') + 1);
		जर ((cp = म_अक्षर(val, '=')) != रिक्त)
			*cp++ = '\0';
		cert_ext_add(val, cp, iscrit);
		मुक्त(val);
	} अन्यथा
		fatal("Unsupported certificate option \"%s\"", opt);
}

स्थिर शून्य
show_options(संरचना sshbuf *optbuf, पूर्णांक in_critical)
{
	अक्षर *name, *arg, *hex;
	संरचना sshbuf *options, *option = रिक्त;
	पूर्णांक r;

	जर ((options = sshbuf_fromb(optbuf)) == रिक्त)
		fatal_f("sshbuf_fromb failed");
	पर्यंत (sshbuf_len(options) != 0) {
		sshbuf_free(option);
		option = रिक्त;
		जर ((r = sshbuf_get_cstring(options, &name, रिक्त)) != 0 ||
		    (r = sshbuf_froms(options, &option)) != 0)
			fatal_fr(r, "parse option");
		म_लिखो("                %s", name);
		जर (!in_critical &&
		    (म_भेद(name, "permit-X11-forwarding") == 0 ||
		    म_भेद(name, "permit-agent-forwarding") == 0 ||
		    म_भेद(name, "permit-port-forwarding") == 0 ||
		    म_भेद(name, "permit-pty") == 0 ||
		    म_भेद(name, "permit-user-rc") == 0 ||
		    म_भेद(name, "no-touch-required") == 0)) {
			म_लिखो("\n");
		} अन्यथा जर (in_critical &&
		    (म_भेद(name, "force-command") == 0 ||
		    म_भेद(name, "source-address") == 0)) {
			जर ((r = sshbuf_get_cstring(option, &arg, रिक्त)) != 0)
				fatal_fr(r, "parse critical");
			म_लिखो(" %s\n", arg);
			मुक्त(arg);
		} अन्यथा जर (in_critical &&
		    म_भेद(name, "verify-required") == 0) {
			म_लिखो("\n");
		} अन्यथा जर (sshbuf_len(option) > 0) {
			hex = sshbuf_dtob16(option);
			म_लिखो(" UNKNOWN OPTION: %s (len %zu)\n",
			    hex, sshbuf_len(option));
			sshbuf_reset(option);
			मुक्त(hex);
		} अन्यथा
			म_लिखो(" UNKNOWN FLAG OPTION\n");
		मुक्त(name);
		जर (sshbuf_len(option) != 0)
			fatal("Option corrupt: extra data at end");
	}
	sshbuf_free(option);
	sshbuf_free(options);
}

स्थिर शून्य
print_cert(संरचना sshkey *किल्ली)
{
	अक्षर valid[64], *किल्ली_fp, *ca_fp;
	u_int i;

	किल्ली_fp = sshkey_fingerprint(किल्ली, fingerprint_hash, SSH_FP_DEFAULT);
	ca_fp = sshkey_fingerprint(किल्ली->cert->signature_किल्ली,
	    fingerprint_hash, SSH_FP_DEFAULT);
	जर (किल्ली_fp == रिक्त || ca_fp == रिक्त)
		fatal_f("sshkey_fingerprint fail");
	sshkey_format_cert_validity(किल्ली->cert, valid, आकार(valid));

	म_लिखो("        Type: %s %s certificate\n", sshkey_ssh_name(किल्ली),
	    sshkey_cert_type(किल्ली));
	म_लिखो("        Public key: %s %s\n", sshkey_type(किल्ली), किल्ली_fp);
	म_लिखो("        Signing CA: %s %s (using %s)\n",
	    sshkey_type(किल्ली->cert->signature_किल्ली), ca_fp,
	    किल्ली->cert->signature_type);
	म_लिखो("        Key ID: \"%s\"\n", किल्ली->cert->किल्ली_id);
	म_लिखो("        Serial: %llu\n", (अचिन्हित दीर्घ दीर्घ)किल्ली->cert->serial);
	म_लिखो("        Valid: %s\n", valid);
	म_लिखो("        Principals: ");
	जर (किल्ली->cert->nprincipals == 0)
		म_लिखो("(none)\n");
	अन्यथा {
		साठी (i = 0; i < किल्ली->cert->nprincipals; i++)
			म_लिखो("\n                %s",
			    किल्ली->cert->principals[i]);
		म_लिखो("\n");
	}
	म_लिखो("        Critical Options: ");
	जर (sshbuf_len(किल्ली->cert->critical) == 0)
		म_लिखो("(none)\n");
	अन्यथा {
		म_लिखो("\n");
		show_options(किल्ली->cert->critical, 1);
	}
	म_लिखो("        Extensions: ");
	जर (sshbuf_len(किल्ली->cert->extensions) == 0)
		म_लिखो("(none)\n");
	अन्यथा {
		म_लिखो("\n");
		show_options(किल्ली->cert->extensions, 0);
	}
	मुक्त(किल्ली_fp);
	मुक्त(ca_fp);
}

स्थिर शून्य
do_show_cert(संरचना passwd *pw)
{
	संरचना sshkey *किल्ली = रिक्त;
	संरचना stat st;
	पूर्णांक r, is_stdin = 0, ok = 0;
	खाता *f;
	अक्षर *cp, *ओळ = रिक्त;
	स्थिरांक अक्षर *path;
	माप_प्रकार linesize = 0;
	u_long lnum = 0;

	जर (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	जर (म_भेद(identity_file, "-") != 0 && stat(identity_file, &st) == -1)
		fatal("%s: %s: %s", __progname, identity_file, म_त्रुटि(त्रुटि_सं));

	path = identity_file;
	जर (म_भेद(path, "-") == 0) {
		f = मानक_निवेश;
		path = "(stdin)";
		is_stdin = 1;
	} अन्यथा जर ((f = ख_खोलो(identity_file, "r")) == रिक्त)
		fatal("fopen %s: %s", identity_file, म_त्रुटि(त्रुटि_सं));

	पर्यंत (getline(&ओळ, &linesize, f) != -1) {
		lnum++;
		sshkey_free(किल्ली);
		किल्ली = रिक्त;
		/* Trim leading space and comments */
		cp = ओळ + म_अखोज(ओळ, " \t");
		जर (*cp == '#' || *cp == '\0')
			सुरूठेवा;
		जर ((किल्ली = sshkey_new(किल्ली_UNSPEC)) == रिक्त)
			fatal("sshkey_new");
		जर ((r = sshkey_read(किल्ली, &cp)) != 0) {
			error_r(r, "%s:%lu: invalid key", path, lnum);
			सुरूठेवा;
		}
		जर (!sshkey_is_cert(किल्ली)) {
			error("%s:%lu is not a certificate", path, lnum);
			सुरूठेवा;
		}
		ok = 1;
		जर (!is_stdin && lnum == 1)
			म_लिखो("%s:\n", path);
		अन्यथा
			म_लिखो("%s:%lu:\n", path, lnum);
		print_cert(किल्ली);
	}
	मुक्त(ओळ);
	sshkey_free(किल्ली);
	ख_बंद(f);
	निकास(ok ? 0 : 1);
}

स्थिर शून्य
load_krl(स्थिरांक अक्षर *path, संरचना ssh_krl **krlp)
{
	संरचना sshbuf *krlbuf;
	पूर्णांक r;

	जर ((r = sshbuf_load_file(path, &krlbuf)) != 0)
		fatal_r(r, "Unable to load KRL %s", path);
	/* XXX check sigs */
	जर ((r = ssh_krl_from_blob(krlbuf, krlp)) != 0 ||
	    *krlp == रिक्त)
		fatal_r(r, "Invalid KRL file %s", path);
	sshbuf_free(krlbuf);
}

स्थिर शून्य
hash_to_blob(स्थिरांक अक्षर *cp, u_char **blobp, माप_प्रकार *lenp,
    स्थिरांक अक्षर *file, u_long lnum)
{
	अक्षर *tmp;
	माप_प्रकार tlen;
	संरचना sshbuf *b;
	पूर्णांक r;

	जर ((cp = strprefix(cp, "SHA256:", 0)) == रिक्त)
		fatal("%s:%lu: unsupported hash algorithm", file, lnum);

	/*
	 * OpenSSH base64 hashes omit trailing '='
	 * characters; put them back for decode.
	 */
	जर ((tlen = म_माप(cp)) >= SIZE_MAX - 5)
		fatal_f("hash too long: %zu bytes", tlen);
	tmp = xmalloc(tlen + 4 + 1);
	strlcpy(tmp, cp, tlen + 1);
	पर्यंत ((tlen % 4) != 0) {
		tmp[tlen++] = '=';
		tmp[tlen] = '\0';
	}
	जर ((b = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	जर ((r = sshbuf_b64tod(b, tmp)) != 0)
		fatal_r(r, "%s:%lu: decode hash failed", file, lnum);
	मुक्त(tmp);
	*lenp = sshbuf_len(b);
	*blobp = xmalloc(*lenp);
	स_नकल(*blobp, sshbuf_ptr(b), *lenp);
	sshbuf_free(b);
}

स्थिर शून्य
update_krl_from_file(संरचना passwd *pw, स्थिरांक अक्षर *file, पूर्णांक wild_ca,
    स्थिरांक संरचना sshkey *ca, संरचना ssh_krl *krl)
{
	संरचना sshkey *किल्ली = रिक्त;
	u_long lnum = 0;
	अक्षर *path, *cp, *ep, *ओळ = रिक्त;
	u_char *blob = रिक्त;
	माप_प्रकार blen = 0, linesize = 0;
	अचिन्हित दीर्घ दीर्घ serial, serial2;
	पूर्णांक i, was_explicit_किल्ली, was_sha1, was_sha256, was_hash, r;
	खाता *krl_spec;

	path = tilde_expand_filename(file, pw->pw_uid);
	जर (म_भेद(path, "-") == 0) {
		krl_spec = मानक_निवेश;
		मुक्त(path);
		path = xstrdup("(standard input)");
	} अन्यथा जर ((krl_spec = ख_खोलो(path, "r")) == रिक्त)
		fatal("fopen %s: %s", path, म_त्रुटि(त्रुटि_सं));

	जर (!quiet)
		म_लिखो("Revoking from %s\n", path);
	पर्यंत (getline(&ओळ, &linesize, krl_spec) != -1) {
		जर (linesize >= पूर्णांक_उच्च) {
			fatal_f("%s contains unparsable line, len=%zu",
			    path, linesize);
		}
		lnum++;
		was_explicit_किल्ली = was_sha1 = was_sha256 = was_hash = 0;
		cp = ओळ + म_अखोज(ओळ, " \t");
		/* Trim trailing space, comments and strip \n */
		साठी (i = 0, r = -1; cp[i] != '\0'; i++) {
			जर (cp[i] == '#' || cp[i] == '\n') {
				cp[i] = '\0';
				थांबा;
			}
			जर (cp[i] == ' ' || cp[i] == '\t') {
				/* Remember the start of a span of whitespace */
				जर (r == -1)
					r = i;
			} अन्यथा
				r = -1;
		}
		जर (r != -1)
			cp[r] = '\0';
		जर (*cp == '\0')
			सुरूठेवा;
		जर (strncasecmp(cp, "serial:", 7) == 0) {
			जर (ca == रिक्त && !wild_ca) {
				fatal("revoking certificates by serial number "
				    "requires specification of a CA key");
			}
			cp += 7;
			cp = cp + म_अखोज(cp, " \t");
			त्रुटि_सं = 0;
			serial = strtoull(cp, &ep, 0);
			जर (*cp == '\0' || (*ep != '\0' && *ep != '-'))
				fatal("%s:%lu: invalid serial \"%s\"",
				    path, lnum, cp);
			जर (त्रुटि_सं == दुस्फल && serial == ULLONG_MAX)
				fatal("%s:%lu: serial out of range",
				    path, lnum);
			serial2 = serial;
			जर (*ep == '-') {
				cp = ep + 1;
				त्रुटि_सं = 0;
				serial2 = strtoull(cp, &ep, 0);
				जर (*cp == '\0' || *ep != '\0')
					fatal("%s:%lu: invalid serial \"%s\"",
					    path, lnum, cp);
				जर (त्रुटि_सं == दुस्फल && serial2 == ULLONG_MAX)
					fatal("%s:%lu: serial out of range",
					    path, lnum);
				जर (serial2 <= serial)
					fatal("%s:%lu: invalid serial range "
					    "%llu:%llu", path, lnum,
					    (अचिन्हित दीर्घ दीर्घ)serial,
					    (अचिन्हित दीर्घ दीर्घ)serial2);
			}
			जर (ssh_krl_revoke_cert_by_serial_range(krl,
			    ca, serial, serial2) != 0) {
				fatal_f("revoke serial failed");
			}
		} अन्यथा जर (strncasecmp(cp, "id:", 3) == 0) {
			जर (ca == रिक्त && !wild_ca) {
				fatal("revoking certificates by key ID "
				    "requires specification of a CA key");
			}
			cp += 3;
			cp = cp + म_अखोज(cp, " \t");
			जर (ssh_krl_revoke_cert_by_किल्ली_id(krl, ca, cp) != 0)
				fatal_f("revoke key ID failed");
		} अन्यथा जर (strncasecmp(cp, "hash:", 5) == 0) {
			cp += 5;
			cp = cp + म_अखोज(cp, " \t");
			hash_to_blob(cp, &blob, &blen, file, lnum);
			जर ((r = ssh_krl_revoke_किल्ली_sha256(krl,
			    blob, blen)) != 0)
				fatal_fr(r, "revoke key failed");
			मुक्त(blob);
			blob = रिक्त;
			blen = 0;
		} अन्यथा {
			जर (strncasecmp(cp, "key:", 4) == 0) {
				cp += 4;
				cp = cp + म_अखोज(cp, " \t");
				was_explicit_किल्ली = 1;
			} अन्यथा जर (strncasecmp(cp, "sha1:", 5) == 0) {
				cp += 5;
				cp = cp + म_अखोज(cp, " \t");
				was_sha1 = 1;
			} अन्यथा जर (strncasecmp(cp, "sha256:", 7) == 0) {
				cp += 7;
				cp = cp + म_अखोज(cp, " \t");
				was_sha256 = 1;
				/*
				 * Just try to process the line as a key.
				 * Parsing will fail if it isn't.
				 */
			}
			जर ((किल्ली = sshkey_new(किल्ली_UNSPEC)) == रिक्त)
				fatal("sshkey_new");
			जर ((r = sshkey_read(किल्ली, &cp)) != 0)
				fatal_r(r, "%s:%lu: invalid key", path, lnum);
			जर (was_explicit_किल्ली)
				r = ssh_krl_revoke_किल्ली_explicit(krl, किल्ली);
			अन्यथा जर (was_sha1) {
				जर (sshkey_fingerprint_raw(किल्ली,
				    SSH_DIGEST_SHA1, &blob, &blen) != 0) {
					fatal("%s:%lu: fingerprint failed",
					    file, lnum);
				}
				r = ssh_krl_revoke_किल्ली_sha1(krl, blob, blen);
			} अन्यथा जर (was_sha256) {
				जर (sshkey_fingerprint_raw(किल्ली,
				    SSH_DIGEST_SHA256, &blob, &blen) != 0) {
					fatal("%s:%lu: fingerprint failed",
					    file, lnum);
				}
				r = ssh_krl_revoke_किल्ली_sha256(krl, blob, blen);
			} अन्यथा
				r = ssh_krl_revoke_किल्ली(krl, किल्ली);
			जर (r != 0)
				fatal_fr(r, "revoke key failed");
			freezero(blob, blen);
			blob = रिक्त;
			blen = 0;
			sshkey_free(किल्ली);
		}
	}
	जर (म_भेद(path, "-") != 0)
		ख_बंद(krl_spec);
	मुक्त(ओळ);
	मुक्त(path);
}

स्थिर शून्य
do_gen_krl(संरचना passwd *pw, पूर्णांक updating, स्थिरांक अक्षर *ca_किल्ली_path,
    अचिन्हित दीर्घ दीर्घ krl_version, स्थिरांक अक्षर *krl_comment,
    पूर्णांक argc, अक्षर **argv)
{
	संरचना ssh_krl *krl;
	संरचना stat sb;
	संरचना sshkey *ca = रिक्त;
	पूर्णांक i, r, wild_ca = 0;
	अक्षर *tmp;
	संरचना sshbuf *kbuf;

	जर (*identity_file == '\0')
		fatal("KRL generation requires an output file");
	जर (stat(identity_file, &sb) == -1) {
		जर (त्रुटि_सं != ENOENT)
			fatal("Cannot access KRL \"%s\": %s",
			    identity_file, म_त्रुटि(त्रुटि_सं));
		जर (updating)
			fatal("KRL \"%s\" does not exist", identity_file);
	}
	जर (ca_किल्ली_path != रिक्त) {
		जर (strcasecmp(ca_किल्ली_path, "none") == 0)
			wild_ca = 1;
		अन्यथा {
			tmp = tilde_expand_filename(ca_किल्ली_path, pw->pw_uid);
			जर ((r = sshkey_load_public(tmp, &ca, रिक्त)) != 0)
				fatal_r(r, "Cannot load CA public key %s", tmp);
			मुक्त(tmp);
		}
	}

	जर (updating)
		load_krl(identity_file, &krl);
	अन्यथा जर ((krl = ssh_krl_init()) == रिक्त)
		fatal("couldn't create KRL");

	जर (krl_version != 0)
		ssh_krl_set_version(krl, krl_version);
	जर (krl_comment != रिक्त)
		ssh_krl_set_comment(krl, krl_comment);

	साठी (i = 0; i < argc; i++)
		update_krl_from_file(pw, argv[i], wild_ca, ca, krl);

	जर ((kbuf = sshbuf_new()) == रिक्त)
		fatal("sshbuf_new failed");
	जर (ssh_krl_to_blob(krl, kbuf) != 0)
		fatal("Couldn't generate KRL");
	जर ((r = sshbuf_write_file(identity_file, kbuf)) != 0)
		fatal("write %s: %s", identity_file, म_त्रुटि(त्रुटि_सं));
	sshbuf_free(kbuf);
	ssh_krl_free(krl);
	sshkey_free(ca);
}

स्थिर शून्य
do_check_krl(संरचना passwd *pw, पूर्णांक print_krl, पूर्णांक argc, अक्षर **argv)
{
	पूर्णांक i, r, ret = 0;
	अक्षर *comment;
	संरचना ssh_krl *krl;
	संरचना sshkey *k;

	जर (*identity_file == '\0')
		fatal("KRL checking requires an input file");
	load_krl(identity_file, &krl);
	जर (print_krl)
		krl_dump(krl, मानक_निकास);
	साठी (i = 0; i < argc; i++) {
		जर ((r = sshkey_load_public(argv[i], &k, &comment)) != 0)
			fatal_r(r, "Cannot load public key %s", argv[i]);
		r = ssh_krl_check_किल्ली(krl, k);
		म_लिखो("%s%s%s%s: %s\n", argv[i],
		    *comment ? " (" : "", comment, *comment ? ")" : "",
		    r == 0 ? "ok" : "REVOKED");
		जर (r != 0)
			ret = 1;
		sshkey_free(k);
		मुक्त(comment);
	}
	ssh_krl_free(krl);
	निकास(ret);
}

स्थिर संरचना sshkey *
load_sign_किल्ली(स्थिरांक अक्षर *keypath, स्थिरांक संरचना sshkey *pubkey)
{
	माप_प्रकार i, slen, plen = म_माप(keypath);
	अक्षर *privpath = xstrdup(keypath);
	स्थिर स्थिरांक अक्षर * स्थिरांक suffixes[] = { "-cert.pub", ".pub", रिक्त };
	संरचना sshkey *ret = रिक्त, *privkey = रिक्त;
	पूर्णांक r, waspub = 0;
	संरचना stat st;

	/*
	 * If passed a public key filename, then try to locate the corresponding
	 * private key. This lets us specify certificates on the command-line
	 * and have ssh-keygen find the appropriate private key.
	 */
	साठी (i = 0; suffixes[i]; i++) {
		slen = म_माप(suffixes[i]);
		जर (plen <= slen ||
		    म_भेद(privpath + plen - slen, suffixes[i]) != 0)
			सुरूठेवा;
		privpath[plen - slen] = '\0';
		debug_f("%s looks like a public key, using private key "
		    "path %s instead", keypath, privpath);
		waspub = 1;
	}
	जर (waspub && stat(privpath, &st) != 0 && त्रुटि_सं == ENOENT)
		fatal("No private key found for public key \"%s\"", keypath);
	जर ((r = sshkey_load_private(privpath, "", &privkey, रिक्त)) != 0 &&
	    (r != SSH_ERR_किल्ली_WRONG_PASSPHRASE)) {
		debug_fr(r, "load private key \"%s\"", privpath);
		fatal("No private key found for \"%s\"", privpath);
	} अन्यथा जर (privkey == रिक्त)
		privkey = load_identity(privpath, रिक्त);

	जर (!sshkey_equal_public(pubkey, privkey)) {
		error("Public key %s doesn't match private %s",
		    keypath, privpath);
		जा done;
	}
	जर (sshkey_is_cert(pubkey) && !sshkey_is_cert(privkey)) {
		/*
		 * Graft the certificate onto the private key to make
		 * it capable of signing.
		 */
		जर ((r = sshkey_to_certified(privkey)) != 0) {
			error_fr(r, "sshkey_to_certified");
			जा done;
		}
		जर ((r = sshkey_cert_copy(pubkey, privkey)) != 0) {
			error_fr(r, "sshkey_cert_copy");
			जा done;
		}
	}
	/* success */
	ret = privkey;
	privkey = रिक्त;
 done:
	sshkey_free(privkey);
	मुक्त(privpath);
	परत ret;
}

स्थिर पूर्णांक
sign_one(संरचना sshkey *signkey, स्थिरांक अक्षर *filename, पूर्णांक fd,
    स्थिरांक अक्षर *sig_namespace, स्थिरांक अक्षर *hashalg, sshsig_signer *signer,
    शून्य *signer_ctx)
{
	संरचना sshbuf *sigbuf = रिक्त, *abuf = रिक्त;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR, wfd = -1, oerrno;
	अक्षर *wfile = रिक्त, *asig = रिक्त, *fp = रिक्त;
	अक्षर *pin = रिक्त, *prompt = रिक्त;

	जर (!quiet) {
		जर (fd == STDIN_FILENO)
			ख_लिखो(मानक_त्रुटि, "Signing data on standard input\n");
		अन्यथा
			ख_लिखो(मानक_त्रुटि, "Signing file %s\n", filename);
	}
	जर (signer == रिक्त && sshkey_is_sk(signkey)) {
		जर ((signkey->sk_flags & SSH_SK_USER_VERIFICATION_REQD)) {
			xasprintf(&prompt, "Enter PIN for %s key: ",
			    sshkey_type(signkey));
			जर ((pin = read_passphrase(prompt,
			    RP_ALLOW_STDIN)) == रिक्त)
				fatal_f("couldn't read PIN");
		}
		जर ((signkey->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
			जर ((fp = sshkey_fingerprint(signkey, fingerprint_hash,
			    SSH_FP_DEFAULT)) == रिक्त)
				fatal_f("fingerprint failed");
			ख_लिखो(मानक_त्रुटि, "Confirm user presence for key %s %s\n",
			    sshkey_type(signkey), fp);
			मुक्त(fp);
		}
	}
	जर ((r = sshsig_sign_fd(signkey, hashalg, sk_provider, pin,
	    fd, sig_namespace, &sigbuf, signer, signer_ctx)) != 0) {
		error_r(r, "Signing %s failed", filename);
		जा out;
	}
	जर ((r = sshsig_armor(sigbuf, &abuf)) != 0) {
		error_fr(r, "sshsig_armor");
		जा out;
	}
	जर ((asig = sshbuf_dup_string(abuf)) == रिक्त) {
		error_f("buffer error");
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}

	जर (fd == STDIN_FILENO) {
		ख_माला_दो(asig, मानक_निकास);
		ख_साफ(मानक_निकास);
	} अन्यथा {
		xasprintf(&wfile, "%s.sig", filename);
		जर (confirm_overwrite(wfile)) {
			जर ((wfd = खोलो(wfile, O_WRONLY|O_CREAT|O_TRUNC,
			    0666)) == -1) {
				oerrno = त्रुटि_सं;
				error("Cannot open %s: %s",
				    wfile, म_त्रुटि(त्रुटि_सं));
				त्रुटि_सं = oerrno;
				r = SSH_ERR_SYSTEM_ERROR;
				जा out;
			}
			जर (atomicio(vwrite, wfd, asig,
			    म_माप(asig)) != म_माप(asig)) {
				oerrno = त्रुटि_सं;
				error("Cannot write to %s: %s",
				    wfile, म_त्रुटि(त्रुटि_सं));
				त्रुटि_सं = oerrno;
				r = SSH_ERR_SYSTEM_ERROR;
				जा out;
			}
			जर (!quiet) {
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
	जर (pin != रिक्त)
		freezero(pin, म_माप(pin));
	sshbuf_free(abuf);
	sshbuf_free(sigbuf);
	जर (wfd != -1)
		बंद(wfd);
	परत r;
}

स्थिर पूर्णांक
sig_process_opts(अक्षर * स्थिरांक *opts, माप_प्रकार nopts, अक्षर **hashalgp,
    uint64_t *verify_timep, पूर्णांक *print_pubkey)
{
	माप_प्रकार i;
	समय_प्रकार now;
	स्थिरांक अक्षर *p;

	जर (verify_timep != रिक्त)
		*verify_timep = 0;
	जर (print_pubkey != रिक्त)
		*print_pubkey = 0;
	जर (hashalgp != रिक्त)
		*hashalgp = रिक्त;
	साठी (i = 0; i < nopts; i++) {
		जर (hashalgp != रिक्त &&
		    (p = strprefix(opts[i], "hashalg=", 1)) != रिक्त) {
			*hashalgp = xstrdup(p);
		} अन्यथा जर (verify_timep &&
		    (p = strprefix(opts[i], "verify-time=", 1)) != रिक्त) {
			जर (parse_absolute_time(p, verify_timep) != 0 ||
			    *verify_timep == 0) {
				error("Invalid \"verify-time\" option");
				परत SSH_ERR_INVALID_ARGUMENT;
			}
		} अन्यथा जर (print_pubkey &&
		    strcasecmp(opts[i], "print-pubkey") == 0) {
			*print_pubkey = 1;
		} अन्यथा {
			error("Invalid option \"%s\"", opts[i]);
			परत SSH_ERR_INVALID_ARGUMENT;
		}
	}
	जर (verify_timep && *verify_timep == 0) {
		जर ((now = समय(रिक्त)) < 0) {
			error("Time is before epoch");
			परत SSH_ERR_INVALID_ARGUMENT;
		}
		*verify_timep = (uint64_t)now;
	}
	परत 0;
}


स्थिर पूर्णांक
sig_sign(स्थिरांक अक्षर *keypath, स्थिरांक अक्षर *sig_namespace, पूर्णांक require_agent,
    पूर्णांक argc, अक्षर **argv, अक्षर * स्थिरांक *opts, माप_प्रकार nopts)
{
	पूर्णांक i, fd = -1, r, ret = -1;
	पूर्णांक agent_fd = -1;
	संरचना sshkey *pubkey = रिक्त, *privkey = रिक्त, *signkey = रिक्त;
	sshsig_signer *signer = रिक्त;
	अक्षर *hashalg = रिक्त;

	/* Check file arguments. */
	साठी (i = 0; i < argc; i++) {
		जर (म_भेद(argv[i], "-") != 0)
			सुरूठेवा;
		जर (i > 0 || argc > 1)
			fatal("Cannot sign mix of paths and standard input");
	}

	जर (sig_process_opts(opts, nopts, &hashalg, रिक्त, रिक्त) != 0)
		जा done; /* error already logged */

	जर ((r = sshkey_load_public(keypath, &pubkey, रिक्त)) != 0) {
		error_r(r, "Couldn't load public key %s", keypath);
		जा done;
	}

	जर ((r = ssh_get_authentication_socket(&agent_fd)) != 0) {
		जर (require_agent)
			fatal("Couldn't get agent socket");
		debug_r(r, "Couldn't get agent socket");
	} अन्यथा {
		जर ((r = ssh_agent_has_किल्ली(agent_fd, pubkey)) == 0)
			signer = agent_signer;
		अन्यथा {
			जर (require_agent)
				fatal("Couldn't find key in agent");
			debug_r(r, "Couldn't find key in agent");
		}
	}

	जर (signer == रिक्त) {
		/* Not using agent - try to load private key */
		जर ((privkey = load_sign_किल्ली(keypath, pubkey)) == रिक्त)
			जा done;
		signkey = privkey;
	} अन्यथा {
		/* Will use key in agent */
		signkey = pubkey;
	}

	जर (argc == 0) {
		जर ((r = sign_one(signkey, "(stdin)", STDIN_FILENO,
		    sig_namespace, hashalg, signer, &agent_fd)) != 0)
			जा done;
	} अन्यथा {
		साठी (i = 0; i < argc; i++) {
			जर (म_भेद(argv[i], "-") == 0)
				fd = STDIN_FILENO;
			अन्यथा जर ((fd = खोलो(argv[i], O_RDONLY)) == -1) {
				error("Cannot open %s for signing: %s",
				    argv[i], म_त्रुटि(त्रुटि_सं));
				जा done;
			}
			जर ((r = sign_one(signkey, argv[i], fd, sig_namespace,
			    hashalg, signer, &agent_fd)) != 0)
				जा done;
			जर (fd != STDIN_FILENO)
				बंद(fd);
			fd = -1;
		}
	}

	ret = 0;
done:
	जर (fd != -1 && fd != STDIN_FILENO)
		बंद(fd);
	sshkey_free(pubkey);
	sshkey_free(privkey);
	मुक्त(hashalg);
	परत ret;
}

स्थिर पूर्णांक
sig_verify(स्थिरांक अक्षर *signature, स्थिरांक अक्षर *sig_namespace,
    स्थिरांक अक्षर *principal, स्थिरांक अक्षर *allowed_किल्ल्या, स्थिरांक अक्षर *revoked_किल्ल्या,
    अक्षर * स्थिरांक *opts, माप_प्रकार nopts)
{
	पूर्णांक r, ret = -1;
	पूर्णांक print_pubkey = 0;
	संरचना sshbuf *sigbuf = रिक्त, *abuf = रिक्त;
	संरचना sshkey *sign_किल्ली = रिक्त;
	अक्षर *fp = रिक्त;
	संरचना sshkey_sig_details *sig_details = रिक्त;
	uint64_t verify_time = 0;

	जर (sig_process_opts(opts, nopts, रिक्त, &verify_time,
	    &print_pubkey) != 0)
		जा done; /* error already logged */

	स_रखो(&sig_details, 0, आकार(sig_details));
	जर ((r = sshbuf_load_file(signature, &abuf)) != 0) {
		error_r(r, "Couldn't read signature file");
		जा done;
	}

	जर ((r = sshsig_dearmor(abuf, &sigbuf)) != 0) {
		error_fr(r, "sshsig_armor");
		जा done;
	}
	जर ((r = sshsig_verify_fd(sigbuf, STDIN_FILENO, sig_namespace,
	    &sign_किल्ली, &sig_details)) != 0)
		जा done; /* sshsig_verify() prints error */

	जर ((fp = sshkey_fingerprint(sign_किल्ली, fingerprint_hash,
	    SSH_FP_DEFAULT)) == रिक्त)
		fatal_f("sshkey_fingerprint failed");
	debug("Valid (unverified) signature from key %s", fp);
	जर (sig_details != रिक्त) {
		debug2_f("signature details: counter = %u, flags = 0x%02x",
		    sig_details->sk_counter, sig_details->sk_flags);
	}
	मुक्त(fp);
	fp = रिक्त;

	जर (revoked_किल्ल्या != रिक्त) {
		जर ((r = sshkey_check_revoked(sign_किल्ली, revoked_किल्ल्या)) != 0) {
			debug3_fr(r, "sshkey_check_revoked");
			जा done;
		}
	}

	जर (allowed_किल्ल्या != रिक्त && (r = sshsig_check_allowed_किल्ल्या(allowed_किल्ल्या,
	    sign_किल्ली, principal, sig_namespace, verify_time)) != 0) {
		debug3_fr(r, "sshsig_check_allowed_keys");
		जा done;
	}
	/* success */
	ret = 0;
done:
	जर (!quiet) {
		जर (ret == 0) {
			जर ((fp = sshkey_fingerprint(sign_किल्ली, fingerprint_hash,
			    SSH_FP_DEFAULT)) == रिक्त)
				fatal_f("sshkey_fingerprint failed");
			जर (principal == रिक्त) {
				म_लिखो("Good \"%s\" signature with %s key %s\n",
				    sig_namespace, sshkey_type(sign_किल्ली), fp);

			} अन्यथा {
				म_लिखो("Good \"%s\" signature for %s with %s key %s\n",
				    sig_namespace, principal,
				    sshkey_type(sign_किल्ली), fp);
			}
		} अन्यथा {
			म_लिखो("Could not verify signature.\n");
		}
	}
	/* Print the signature key if requested */
	जर (ret == 0 && print_pubkey && sign_किल्ली != रिक्त) {
		जर ((r = sshkey_write(sign_किल्ली, मानक_निकास)) == 0)
			ख_अक्षर_दो('\n', मानक_निकास);
		अन्यथा {
			error_r(r, "Could not print public key.\n");
			ret = -1;
		}
	}
	sshbuf_free(sigbuf);
	sshbuf_free(abuf);
	sshkey_free(sign_किल्ली);
	sshkey_sig_details_free(sig_details);
	मुक्त(fp);
	परत ret;
}

स्थिर पूर्णांक
sig_find_principals(स्थिरांक अक्षर *signature, स्थिरांक अक्षर *allowed_किल्ल्या,
    अक्षर * स्थिरांक *opts, माप_प्रकार nopts)
{
	पूर्णांक r, ret = -1;
	संरचना sshbuf *sigbuf = रिक्त, *abuf = रिक्त;
	संरचना sshkey *sign_किल्ली = रिक्त;
	अक्षर *principals = रिक्त, *cp, *tmp;
	uint64_t verify_time = 0;

	जर (sig_process_opts(opts, nopts, रिक्त, &verify_time, रिक्त) != 0)
		जा done; /* error already logged */

	जर ((r = sshbuf_load_file(signature, &abuf)) != 0) {
		error_r(r, "Couldn't read signature file");
		जा done;
	}
	जर ((r = sshsig_dearmor(abuf, &sigbuf)) != 0) {
		error_fr(r, "sshsig_armor");
		जा done;
	}
	जर ((r = sshsig_get_pubkey(sigbuf, &sign_किल्ली)) != 0) {
		error_fr(r, "sshsig_get_pubkey");
		जा done;
	}
	जर ((r = sshsig_find_principals(allowed_किल्ल्या, sign_किल्ली,
	    verify_time, &principals)) != 0) {
		जर (r != SSH_ERR_किल्ली_NOT_FOUND)
			error_fr(r, "sshsig_find_principal");
		जा done;
	}
	ret = 0;
done:
	जर (ret == 0 ) {
		/* Emit matching principals one per line */
		tmp = principals;
		पर्यंत ((cp = strsep(&tmp, ",")) != रिक्त && *cp != '\0')
			माला_दो(cp);
	} अन्यथा {
		ख_लिखो(मानक_त्रुटि, "No principal matched.\n");
	}
	sshbuf_free(sigbuf);
	sshbuf_free(abuf);
	sshkey_free(sign_किल्ली);
	मुक्त(principals);
	परत ret;
}

स्थिर पूर्णांक
sig_match_principals(स्थिरांक अक्षर *allowed_किल्ल्या, अक्षर *principal,
	अक्षर * स्थिरांक *opts, माप_प्रकार nopts)
{
	पूर्णांक r;
	अक्षर **principals = रिक्त;
	माप_प्रकार i, nprincipals = 0;

	जर ((r = sig_process_opts(opts, nopts, रिक्त, रिक्त, रिक्त)) != 0)
		परत r; /* error already logged */

	जर ((r = sshsig_match_principals(allowed_किल्ल्या, principal,
	    &principals, &nprincipals)) != 0) {
		debug_f("match: %s", ssh_err(r));
		ख_लिखो(मानक_त्रुटि, "No principal matched.\n");
		परत r;
	}
	साठी (i = 0; i < nprincipals; i++) {
		म_लिखो("%s\n", principals[i]);
		मुक्त(principals[i]);
	}
	मुक्त(principals);

	परत 0;
}

स्थिर शून्य
do_moduli_gen(स्थिरांक अक्षर *out_file, अक्षर **opts, माप_प्रकार nopts)
{
#ifdef WITH_OPENSSL
	/* Moduli generation/screening */
	BIGNUM *start = रिक्त;
	पूर्णांक moduli_bits = 0;
	खाता *out;
	माप_प्रकार i;
	स्थिरांक अक्षर *errstr, *p;

	/* Parse options */
	साठी (i = 0; i < nopts; i++) {
		जर ((p = strprefix(opts[i], "start=", 0)) != रिक्त) {
			/* XXX - also compare length against bits */
			जर (BN_hex2bn(&start, p) == 0)
				fatal("Invalid start point.");
		} अन्यथा जर ((p = strprefix(opts[i], "bits=", 0)) != रिक्त) {
			moduli_bits = (पूर्णांक)strtonum(p, 1, पूर्णांक_उच्च, &errstr);
			जर (errstr) {
				fatal("Invalid number: %s (%s)", p, errstr);
			}
		} अन्यथा {
			fatal("Option \"%s\" is unsupported for moduli "
			    "generation", opts[i]);
		}
	}

	जर (म_भेद(out_file, "-") == 0)
		out = मानक_निकास;
	अन्यथा जर ((out = ख_खोलो(out_file, "w")) == रिक्त) {
		fatal("Couldn't open modulus candidate file \"%s\": %s",
		    out_file, म_त्रुटि(त्रुटि_सं));
	}
	रखो_भबफ(out, रिक्त, _IOLBF, 0);

	जर (moduli_bits == 0)
		moduli_bits = DEFAULT_BITS;
	जर (gen_candidates(out, moduli_bits, start) != 0)
		fatal("modulus candidate generation failed");
#अन्यथा /* WITH_OPENSSL */
	fatal("Moduli generation is not supported");
#endif /* WITH_OPENSSL */
}

स्थिर शून्य
do_moduli_screen(स्थिरांक अक्षर *out_file, अक्षर **opts, माप_प्रकार nopts)
{
#ifdef WITH_OPENSSL
	/* Moduli generation/screening */
	अक्षर *checkpoint = रिक्त;
	uint32_t generator_wanted = 0;
	अचिन्हित दीर्घ start_lineno = 0, ओळी_to_process = 0;
	पूर्णांक मूळसंख्या_tests = 0;
	खाता *out, *in = मानक_निवेश;
	माप_प्रकार i;
	स्थिरांक अक्षर *errstr, *p;

	/* Parse options */
	साठी (i = 0; i < nopts; i++) {
		जर ((p = strprefix(opts[i], "lines=", 0)) != रिक्त) {
			ओळी_to_process = म_से_अदीर्घ(p, रिक्त, 10);
		} अन्यथा जर ((p = strprefix(opts[i], "start-line=", 0)) != रिक्त) {
			start_lineno = म_से_अदीर्घ(p, रिक्त, 10);
		} अन्यथा जर ((p = strprefix(opts[i], "checkpoint=", 0)) != रिक्त) {
			मुक्त(checkpoint);
			checkpoint = xstrdup(p);
		} अन्यथा जर ((p = strprefix(opts[i], "generator=", 0)) != रिक्त) {
			generator_wanted = (uint32_t)strtonum(p, 1, अच_पूर्णांक_उच्च,
			    &errstr);
			जर (errstr != रिक्त) {
				fatal("Generator invalid: %s (%s)", p, errstr);
			}
		} अन्यथा जर ((p = strprefix(opts[i], "prime-tests=", 0)) != रिक्त) {
			मूळसंख्या_tests = (पूर्णांक)strtonum(p, 1, पूर्णांक_उच्च, &errstr);
			जर (errstr) {
				fatal("Invalid number: %s (%s)", p, errstr);
			}
		} अन्यथा {
			fatal("Option \"%s\" is unsupported for moduli "
			    "screening", opts[i]);
		}
	}

	जर (have_identity && म_भेद(identity_file, "-") != 0) {
		जर ((in = ख_खोलो(identity_file, "r")) == रिक्त) {
			fatal("Couldn't open modulus candidate "
			    "file \"%s\": %s", identity_file,
			    म_त्रुटि(त्रुटि_सं));
		}
	}

	जर (म_भेद(out_file, "-") == 0)
		out = मानक_निकास;
	अन्यथा जर ((out = ख_खोलो(out_file, "a")) == रिक्त) {
		fatal("Couldn't open moduli file \"%s\": %s",
		    out_file, म_त्रुटि(त्रुटि_सं));
	}
	रखो_भबफ(out, रिक्त, _IOLBF, 0);
	जर (मूळसंख्या_test(in, out, मूळसंख्या_tests == 0 ? 100 : मूळसंख्या_tests,
	    generator_wanted, checkpoint,
	    start_lineno, ओळी_to_process) != 0)
		fatal("modulus screening failed");
	जर (in != मानक_निवेश)
		(शून्य)ख_बंद(in);
	मुक्त(checkpoint);
#अन्यथा /* WITH_OPENSSL */
	fatal("Moduli screening is not supported");
#endif /* WITH_OPENSSL */
}

/* Read and confirm a passphrase */
स्थिर अक्षर *
read_check_passphrase(स्थिरांक अक्षर *prompt1, स्थिरांक अक्षर *prompt2,
    स्थिरांक अक्षर *retry_prompt)
{
	अक्षर *passphrase1, *passphrase2;

	साठी (;;) {
		passphrase1 = read_passphrase(prompt1, RP_ALLOW_STDIN);
		passphrase2 = read_passphrase(prompt2, RP_ALLOW_STDIN);
		जर (म_भेद(passphrase1, passphrase2) == 0) {
			freezero(passphrase2, म_माप(passphrase2));
			परत passphrase1;
		}
		/* The passphrases do not match. Clear them and retry. */
		freezero(passphrase1, म_माप(passphrase1));
		freezero(passphrase2, म_माप(passphrase2));
		ख_माला_दो(retry_prompt, मानक_निकास);
		ख_अक्षर_दो('\n', मानक_निकास);
		ख_साफ(मानक_निकास);
	}
	/* NOTREACHED */
	परत रिक्त;
}

स्थिर अक्षर *
private_किल्ली_passphrase(स्थिरांक अक्षर *path)
{
	अक्षर *prompt, *ret;

	जर (identity_passphrase)
		परत xstrdup(identity_passphrase);
	जर (identity_new_passphrase)
		परत xstrdup(identity_new_passphrase);

	xasprintf(&prompt, "Enter passphrase for \"%s\" "
	    "(empty for no passphrase): ", path);
	ret = read_check_passphrase(prompt,
	    "Enter same passphrase again: ",
	    "Passphrases do not match.  Try again.");
	मुक्त(prompt);
	परत ret;
}

स्थिर अक्षर *
sk_suffix(स्थिरांक अक्षर *application, स्थिरांक uint8_t *user, माप_प्रकार userlen)
{
	अक्षर *ret, *cp;
	स्थिरांक अक्षर *p;
	माप_प्रकार slen, i;

	/* Trim off URL-like preamble */
	जर ((p = strprefix(application, "ssh://", 0)) != रिक्त)
		ret =  xstrdup(p);
	अन्यथा जर ((p = strprefix(application, "ssh:", 0)) != रिक्त)
		ret =  xstrdup(p);
	अन्यथा
		ret = xstrdup(application);

	/* Count trailing zeros in user */
	साठी (i = 0; i < userlen; i++) {
		जर (user[userlen - i - 1] != 0)
			थांबा;
	}
	जर (i >= userlen)
		परत ret; /* user-id was default all-zeros */

	/* Append user-id, escaping non-UTF-8 characters */
	slen = userlen - i;
	जर (asmprintf(&cp, पूर्णांक_उच्च, रिक्त, "%.*s", (पूर्णांक)slen, user) == -1)
		fatal_f("asmprintf failed");
	/* Don't emit a user-id that contains path or control characters */
	जर (म_अक्षर(cp, '/') != रिक्त || म_माला(cp, "..") != रिक्त ||
	    म_अक्षर(cp, '\\') != रिक्त) {
		मुक्त(cp);
		cp = tohex(user, slen);
	}
	xextendf(&ret, "_", "%s", cp);
	मुक्त(cp);
	परत ret;
}

स्थिर पूर्णांक
do_download_sk(स्थिरांक अक्षर *skprovider, स्थिरांक अक्षर *device)
{
	संरचना sshsk_resident_किल्ली **srks;
	माप_प्रकार nsrks, i;
	पूर्णांक r, ret = -1;
	अक्षर *fp, *pin = रिक्त, *pass = रिक्त, *path, *pubpath;
	स्थिरांक अक्षर *ext;
	संरचना sshkey *किल्ली;

	जर (skprovider == रिक्त)
		fatal("Cannot download keys without provider");

	pin = read_passphrase("Enter PIN for authenticator: ", RP_ALLOW_STDIN);
	जर (!quiet) {
		म_लिखो("You may need to touch your authenticator "
		    "to authorize key download.\n");
	}
	जर ((r = sshsk_load_resident(skprovider, device, pin, 0,
	    &srks, &nsrks)) != 0) {
		जर (pin != रिक्त)
			freezero(pin, म_माप(pin));
		error_r(r, "Unable to load resident keys");
		परत -1;
	}
	जर (nsrks == 0)
		logit("No keys to download");
	जर (pin != रिक्त)
		freezero(pin, म_माप(pin));

	साठी (i = 0; i < nsrks; i++) {
		किल्ली = srks[i]->किल्ली;
		जर (किल्ली->type != किल्ली_ECDSA_SK && किल्ली->type != किल्ली_ED25519_SK) {
			error("Unsupported key type %s (%d)",
			    sshkey_type(किल्ली), किल्ली->type);
			सुरूठेवा;
		}
		जर ((fp = sshkey_fingerprint(किल्ली, fingerprint_hash,
		    SSH_FP_DEFAULT)) == रिक्त)
			fatal_f("sshkey_fingerprint failed");
		debug_f("key %zu: %s %s %s (flags 0x%02x)", i,
		    sshkey_type(किल्ली), fp, किल्ली->sk_application, किल्ली->sk_flags);
		ext = sk_suffix(किल्ली->sk_application,
		    srks[i]->user_id, srks[i]->user_id_len);
		xasprintf(&path, "id_%s_rk%s%s",
		    किल्ली->type == किल्ली_ECDSA_SK ? "ecdsa_sk" : "ed25519_sk",
		    *ext == '\0' ? "" : "_", ext);

		/* If the file already exists, ask the user to confirm. */
		जर (!confirm_overwrite(path)) {
			मुक्त(path);
			थांबा;
		}

		/* Save the key with the application string as the comment */
		जर (pass == रिक्त)
			pass = private_किल्ली_passphrase(path);
		जर ((r = sshkey_save_private(किल्ली, path, pass,
		    किल्ली->sk_application, private_किल्ली_format,
		    openssh_format_cipher, rounds)) != 0) {
			error_r(r, "Saving key \"%s\" failed", path);
			मुक्त(path);
			थांबा;
		}
		जर (!quiet) {
			म_लिखो("Saved %s key%s%s to %s\n", sshkey_type(किल्ली),
			    *ext != '\0' ? " " : "",
			    *ext != '\0' ? किल्ली->sk_application : "",
			    path);
		}

		/* Save public key too */
		xasprintf(&pubpath, "%s.pub", path);
		मुक्त(path);
		जर ((r = sshkey_save_public(किल्ली, pubpath,
		    किल्ली->sk_application)) != 0) {
			error_r(r, "Saving public key \"%s\" failed", pubpath);
			मुक्त(pubpath);
			थांबा;
		}
		मुक्त(pubpath);
	}

	जर (i >= nsrks)
		ret = 0; /* success */
	जर (pass != रिक्त)
		freezero(pass, म_माप(pass));
	sshsk_free_resident_किल्ल्या(srks, nsrks);
	परत ret;
}

स्थिर शून्य
save_attestation(संरचना sshbuf *attest, स्थिरांक अक्षर *path)
{
	mode_t omask;
	पूर्णांक r;

	जर (path == रिक्त)
		परत; /* nothing to do */
	जर (attest == रिक्त || sshbuf_len(attest) == 0)
		fatal("Enrollment did not return attestation data");
	omask = umask(077);
	r = sshbuf_write_file(path, attest);
	umask(omask);
	जर (r != 0)
		fatal_r(r, "Unable to write attestation data \"%s\"", path);
	जर (!quiet)
		म_लिखो("Your FIDO attestation certificate has been saved in "
		    "%s\n", path);
}

स्थिर पूर्णांक
confirm_sk_overwrite(स्थिरांक अक्षर *application, स्थिरांक अक्षर *user)
{
	अक्षर yesno[3];

	म_लिखो("A resident key scoped to '%s' with user id '%s' already "
	    "exists.\n", application == रिक्त ? "ssh:" : application,
	    user == रिक्त ? "null" : user);
	म_लिखो("Overwrite key in token (y/n)? ");
	ख_साफ(मानक_निकास);
	जर (ख_माला_लो(yesno, आकार(yesno), मानक_निवेश) == रिक्त)
		परत 0;
	जर (yesno[0] != 'y' && yesno[0] != 'Y')
		परत 0;
	परत 1;
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
पूर्णांक
main(पूर्णांक argc, अक्षर **argv)
{
	अक्षर comment[किल्ली_COMMENT_MAX], *passphrase = रिक्त;
	अक्षर *rr_hostname = रिक्त, *ep, *fp, *ra;
	संरचना sshkey *खाजगी = रिक्त, *सार्वजनिक = रिक्त;
	संरचना passwd *pw;
	पूर्णांक ret = 0, r, opt, type;
	पूर्णांक change_passphrase = 0, change_comment = 0, show_cert = 0;
	पूर्णांक find_host = 0, delete_host = 0, hash_hosts = 0;
	पूर्णांक gen_all_hostkeys = 0, gen_krl = 0, update_krl = 0, check_krl = 0;
	पूर्णांक prefer_agent = 0, convert_to = 0, convert_from = 0;
	पूर्णांक print_public = 0, print_generic = 0, cert_serial_autoinc = 0;
	पूर्णांक do_gen_candidates = 0, do_screen_candidates = 0, download_sk = 0;
	अचिन्हित दीर्घ दीर्घ cert_serial = 0;
	अक्षर *identity_comment = रिक्त, *ca_किल्ली_path = रिक्त, **opts = रिक्त;
	अक्षर *sk_application = रिक्त, *sk_device = रिक्त, *sk_user = रिक्त;
	अक्षर *sk_attestation_path = रिक्त;
	संरचना sshbuf *challenge = रिक्त, *attest = रिक्त;
	माप_प्रकार i, nopts = 0;
	uint32_t bits = 0;
	uint8_t sk_flags = SSH_SK_USER_PRESENCE_REQD;
	स्थिरांक अक्षर *errstr, *p;
	पूर्णांक log_level = SYSLOG_LEVEL_INFO;
	अक्षर *sign_op = रिक्त;

	बाह्य पूर्णांक optind;
	बाह्य अक्षर *optarg;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	__progname = ssh_get_progname(argv[0]);

	seed_rng();

	log_init(argv[0], SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_USER, 1);

	msetlocale();

	/* we need this for the home * directory.  */
	pw = getpwuid(getuid());
	जर (!pw)
		fatal("No user exists for uid %lu", (u_long)getuid());
	pw = pwcopy(pw);
	जर (gethostname(hostname, आकार(hostname)) == -1)
		fatal("gethostname: %s", म_त्रुटि(त्रुटि_सं));

	sk_provider = दो_पर्या("SSH_SK_PROVIDER");

	/* Remaining characters: dGjJSTWx */
	पर्यंत ((opt = getopt(argc, argv, "ABHKLQUXceghiklopquvy"
	    "C:D:E:F:I:M:N:O:P:R:V:Y:Z:"
	    "a:b:f:g:m:n:r:s:t:w:z:")) != -1) {
		निवड (opt) {
		स्थिती 'A':
			gen_all_hostkeys = 1;
			थांबा;
		स्थिती 'b':
			bits = (uint32_t)strtonum(optarg, 1, UINT32_MAX,
			    &errstr);
			जर (errstr)
				fatal("Bits has bad value %s (%s)",
					optarg, errstr);
			थांबा;
		स्थिती 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			जर (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			थांबा;
		स्थिती 'F':
			find_host = 1;
			rr_hostname = optarg;
			थांबा;
		स्थिती 'H':
			hash_hosts = 1;
			थांबा;
		स्थिती 'I':
			cert_किल्ली_id = optarg;
			थांबा;
		स्थिती 'R':
			delete_host = 1;
			rr_hostname = optarg;
			थांबा;
		स्थिती 'L':
			show_cert = 1;
			थांबा;
		स्थिती 'l':
			print_fingerprint = 1;
			थांबा;
		स्थिती 'B':
			print_bubblebabble = 1;
			थांबा;
		स्थिती 'm':
			जर (strcasecmp(optarg, "RFC4716") == 0 ||
			    strcasecmp(optarg, "ssh2") == 0) {
				convert_format = FMT_RFC4716;
				थांबा;
			}
			जर (strcasecmp(optarg, "PKCS8") == 0) {
				convert_format = FMT_PKCS8;
				private_किल्ली_format = SSHKEY_PRIVATE_PKCS8;
				थांबा;
			}
			जर (strcasecmp(optarg, "PEM") == 0) {
				convert_format = FMT_PEM;
				private_किल्ली_format = SSHKEY_PRIVATE_PEM;
				थांबा;
			}
			जर (strcasecmp(optarg, "hexdump") == 0) {
				convert_format = FMT_HEXDUMP;
				थांबा;
			}
			fatal("Unsupported conversion format \"%s\"", optarg);
		स्थिती 'n':
			cert_principals = optarg;
			थांबा;
		स्थिती 'o':
			/* no-op; new format is already the default */
			थांबा;
		स्थिती 'p':
			change_passphrase = 1;
			थांबा;
		स्थिती 'c':
			change_comment = 1;
			थांबा;
		स्थिती 'f':
			जर (strlcpy(identity_file, optarg,
			    आकार(identity_file)) >= आकार(identity_file))
				fatal("Identity filename too long");
			have_identity = 1;
			थांबा;
		स्थिती 'g':
			print_generic = 1;
			थांबा;
		स्थिती 'K':
			download_sk = 1;
			थांबा;
		स्थिती 'P':
			identity_passphrase = optarg;
			थांबा;
		स्थिती 'N':
			identity_new_passphrase = optarg;
			थांबा;
		स्थिती 'Q':
			check_krl = 1;
			थांबा;
		स्थिती 'O':
			opts = xrecallocarray(opts, nopts, nopts + 1,
			    आकार(*opts));
			opts[nopts++] = xstrdup(optarg);
			थांबा;
		स्थिती 'Z':
			openssh_format_cipher = optarg;
			जर (cipher_by_name(openssh_format_cipher) == रिक्त)
				fatal("Invalid OpenSSH-format cipher '%s'",
				    openssh_format_cipher);
			थांबा;
		स्थिती 'C':
			identity_comment = optarg;
			थांबा;
		स्थिती 'q':
			quiet = 1;
			थांबा;
		स्थिती 'e':
			/* export key */
			convert_to = 1;
			थांबा;
		स्थिती 'h':
			cert_किल्ली_type = SSH2_CERT_TYPE_HOST;
			certflags_flags = 0;
			थांबा;
		स्थिती 'k':
			gen_krl = 1;
			थांबा;
		स्थिती 'i':
		स्थिती 'X':
			/* import key */
			convert_from = 1;
			थांबा;
		स्थिती 'y':
			print_public = 1;
			थांबा;
		स्थिती 's':
			ca_किल्ली_path = optarg;
			थांबा;
		स्थिती 't':
			किल्ली_type_name = optarg;
			थांबा;
		स्थिती 'D':
			pkcs11provider = optarg;
			थांबा;
		स्थिती 'U':
			prefer_agent = 1;
			थांबा;
		स्थिती 'u':
			update_krl = 1;
			थांबा;
		स्थिती 'v':
			जर (log_level == SYSLOG_LEVEL_INFO)
				log_level = SYSLOG_LEVEL_DEBUG1;
			अन्यथा {
				जर (log_level >= SYSLOG_LEVEL_DEBUG1 &&
				    log_level < SYSLOG_LEVEL_DEBUG3)
					log_level++;
			}
			थांबा;
		स्थिती 'r':
			rr_hostname = optarg;
			थांबा;
		स्थिती 'a':
			rounds = (पूर्णांक)strtonum(optarg, 1, पूर्णांक_उच्च, &errstr);
			जर (errstr)
				fatal("Invalid number: %s (%s)",
					optarg, errstr);
			थांबा;
		स्थिती 'V':
			parse_cert_times(optarg);
			थांबा;
		स्थिती 'Y':
			sign_op = optarg;
			थांबा;
		स्थिती 'w':
			sk_provider = optarg;
			थांबा;
		स्थिती 'z':
			त्रुटि_सं = 0;
			जर (*optarg == '+') {
				cert_serial_autoinc = 1;
				optarg++;
			}
			cert_serial = strtoull(optarg, &ep, 10);
			जर (*optarg < '0' || *optarg > '9' || *ep != '\0' ||
			    (त्रुटि_सं == दुस्फल && cert_serial == ULLONG_MAX))
				fatal("Invalid serial number \"%s\"", optarg);
			थांबा;
		स्थिती 'M':
			जर (म_भेद(optarg, "generate") == 0)
				do_gen_candidates = 1;
			अन्यथा जर (म_भेद(optarg, "screen") == 0)
				do_screen_candidates = 1;
			अन्यथा
				fatal("Unsupported moduli option %s", optarg);
			थांबा;
		पूर्वनिर्धारित:
			usage();
		}
	}

#ifdef ENABLE_SK_INTERNAL
	जर (sk_provider == रिक्त)
		sk_provider = "internal";
#endif

	/* reinit */
	log_init(argv[0], log_level, SYSLOG_FACILITY_USER, 1);

	argv += optind;
	argc -= optind;

	जर (sign_op != रिक्त) {
		जर (strprefix(sign_op, "find-principals", 0) != रिक्त) {
			जर (ca_किल्ली_path == रिक्त) {
				error("Too few arguments for find-principals:"
				    "missing signature file");
				निकास(1);
			}
			जर (!have_identity) {
				error("Too few arguments for find-principals:"
				    "missing allowed keys file");
				निकास(1);
			}
			ret = sig_find_principals(ca_किल्ली_path, identity_file,
			    opts, nopts);
			जा done;
		} अन्यथा जर (strprefix(sign_op, "match-principals", 0) != रिक्त) {
			जर (!have_identity) {
				error("Too few arguments for match-principals:"
				    "missing allowed keys file");
				निकास(1);
			}
			जर (cert_किल्ली_id == रिक्त) {
				error("Too few arguments for match-principals: "
				    "missing principal ID");
				निकास(1);
			}
			ret = sig_match_principals(identity_file, cert_किल्ली_id,
			    opts, nopts);
			जा done;
		} अन्यथा जर (strprefix(sign_op, "sign", 0) != रिक्त) {
			/* NB. cert_principals is actually namespace, via -n */
			जर (cert_principals == रिक्त ||
			    *cert_principals == '\0') {
				error("Too few arguments for sign: "
				    "missing namespace");
				निकास(1);
			}
			जर (!have_identity) {
				error("Too few arguments for sign: "
				    "missing key");
				निकास(1);
			}
			ret = sig_sign(identity_file, cert_principals,
			    prefer_agent, argc, argv, opts, nopts);
			जा done;
		} अन्यथा जर (strprefix(sign_op, "check-novalidate", 0) != रिक्त) {
			/* NB. cert_principals is actually namespace, via -n */
			जर (cert_principals == रिक्त ||
			    *cert_principals == '\0') {
				error("Too few arguments for check-novalidate: "
				    "missing namespace");
				निकास(1);
			}
			जर (ca_किल्ली_path == रिक्त) {
				error("Too few arguments for check-novalidate: "
				    "missing signature file");
				निकास(1);
			}
			ret = sig_verify(ca_किल्ली_path, cert_principals,
			    रिक्त, रिक्त, रिक्त, opts, nopts);
			जा done;
		} अन्यथा जर (strprefix(sign_op, "verify", 0) != रिक्त) {
			/* NB. cert_principals is actually namespace, via -n */
			जर (cert_principals == रिक्त ||
			    *cert_principals == '\0') {
				error("Too few arguments for verify: "
				    "missing namespace");
				निकास(1);
			}
			जर (ca_किल्ली_path == रिक्त) {
				error("Too few arguments for verify: "
				    "missing signature file");
				निकास(1);
			}
			जर (!have_identity) {
				error("Too few arguments for sign: "
				    "missing allowed keys file");
				निकास(1);
			}
			जर (cert_किल्ली_id == रिक्त) {
				error("Too few arguments for verify: "
				    "missing principal identity");
				निकास(1);
			}
			ret = sig_verify(ca_किल्ली_path, cert_principals,
			    cert_किल्ली_id, identity_file, rr_hostname,
			    opts, nopts);
			जा done;
		}
		error("Unsupported operation for -Y: \"%s\"", sign_op);
		usage();
		/* NOTREACHED */
	}

	जर (ca_किल्ली_path != रिक्त) {
		जर (argc < 1 && !gen_krl) {
			error("Too few arguments.");
			usage();
		}
	} अन्यथा जर (argc > 0 && !gen_krl && !check_krl &&
	    !do_gen_candidates && !do_screen_candidates) {
		error("Too many arguments.");
		usage();
	}
	जर (change_passphrase && change_comment) {
		error("Can only have one of -p and -c.");
		usage();
	}
	जर (print_fingerprint && (delete_host || hash_hosts)) {
		error("Cannot use -l with -H or -R.");
		usage();
	}
	जर (gen_krl) {
		do_gen_krl(pw, update_krl, ca_किल्ली_path,
		    cert_serial, identity_comment, argc, argv);
		जा done;
	}
	जर (check_krl) {
		do_check_krl(pw, print_fingerprint, argc, argv);
		जा done;
	}
	जर (ca_किल्ली_path != रिक्त) {
		जर (cert_किल्ली_id == रिक्त)
			fatal("Must specify key id (-I) when certifying");
		जर (cert_principals == रिक्त) {
			/*
			 * Ideally this would be a fatal(), but we need to
			 * be able to generate such certificates for testing
			 * even though they will be rejected.
			 */
			error("Warning: certificate will contain no "
			    "principals (-n)");
		}
		साठी (i = 0; i < nopts; i++)
			add_cert_option(opts[i]);
		do_ca_sign(pw, ca_किल्ली_path, prefer_agent,
		    cert_serial, cert_serial_autoinc, argc, argv);
		जा done;
	}
	जर (show_cert)
		do_show_cert(pw);
	जर (delete_host || hash_hosts || find_host) {
		do_known_hosts(pw, rr_hostname, find_host,
		    delete_host, hash_hosts);
	}
	जर (pkcs11provider != रिक्त)
		do_download(pw);
	जर (download_sk) {
		साठी (i = 0; i < nopts; i++) {
			जर ((p = strprefix(opts[i], "device=", 1)) != रिक्त) {
				sk_device = xstrdup(p);
			} अन्यथा {
				fatal("Option \"%s\" is unsupported for "
				    "FIDO authenticator download", opts[i]);
			}
		}
		ret = do_download_sk(sk_provider, sk_device);
		जा done;
	}
	जर (print_fingerprint || print_bubblebabble)
		do_fingerprint(pw);
	जर (change_passphrase)
		do_change_passphrase(pw, opts, nopts);
	जर (change_comment)
		do_change_comment(pw, identity_comment);
#ifdef WITH_OPENSSL
	जर (convert_to) {
		do_convert_to(pw);
		जा done;
	}
	जर (convert_from) {
		do_convert_from(pw);
		जा done;
	}
#अन्यथा /* WITH_OPENSSL */
	जर (convert_to || convert_from)
		fatal("key conversion disabled at compile time");
#endif /* WITH_OPENSSL */
	जर (print_public)
		do_print_public(pw);
	जर (rr_hostname != रिक्त) {
		अचिन्हित पूर्णांक n = 0;

		जर (have_identity) {
			n = do_print_resource_record(pw, identity_file,
			    rr_hostname, print_generic, opts, nopts);
			जर (n == 0)
				fatal("%s: %s", identity_file, म_त्रुटि(त्रुटि_सं));
			निकास(0);
		} अन्यथा {

			n += do_print_resource_record(pw,
			    PATH_HOST_RSA_किल्ली_FILE, rr_hostname,
			    print_generic, opts, nopts);
			n += do_print_resource_record(pw,
			    PATH_HOST_ECDSA_किल्ली_FILE, rr_hostname,
			    print_generic, opts, nopts);
			n += do_print_resource_record(pw,
			    PATH_HOST_ED25519_किल्ली_FILE, rr_hostname,
			    print_generic, opts, nopts);
			जर (n == 0)
				fatal("no keys found.");
			निकास(0);
		}
	}

	जर (do_gen_candidates || do_screen_candidates) {
		जर (argc <= 0)
			fatal("No output file specified");
		अन्यथा जर (argc > 1)
			fatal("Too many output files specified");
	}
	जर (do_gen_candidates) {
		do_moduli_gen(argv[0], opts, nopts);
		जा done;
	}
	जर (do_screen_candidates) {
		do_moduli_screen(argv[0], opts, nopts);
		जा done;
	}

	जर (gen_all_hostkeys) {
		do_gen_all_hostkeys(pw);
		जा done;
	}

	जर (किल्ली_type_name == रिक्त)
		किल्ली_type_name = DEFAULT_किल्ली_TYPE_NAME;

	type = sshkey_type_from_shortname(किल्ली_type_name);
	type_bits_valid(type, किल्ली_type_name, &bits);

	जर (!quiet)
		म_लिखो("Generating public/private %s key pair.\n",
		    किल्ली_type_name);
	निवड (type) {
	स्थिती किल्ली_ECDSA_SK:
	स्थिती किल्ली_ED25519_SK:
		साठी (i = 0; i < nopts; i++) {
			जर (strcasecmp(opts[i], "no-touch-required") == 0) {
				sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
			} अन्यथा जर (strcasecmp(opts[i], "verify-required") == 0) {
				sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
			} अन्यथा जर (strcasecmp(opts[i], "resident") == 0) {
				sk_flags |= SSH_SK_RESIDENT_किल्ली;
			} अन्यथा जर ((p = strprefix(opts[i], "device=", 1))
			    != रिक्त ) {
				sk_device = xstrdup(p);
			} अन्यथा जर ((p = strprefix(opts[i], "user=", 1))
			    != रिक्त) {
				sk_user = xstrdup(p);
			} अन्यथा जर ((p = strprefix(opts[i], "challenge=", 1))
			    != रिक्त) {
				जर ((r = sshbuf_load_file(p,
				    &challenge)) != 0) {
					fatal_r(r, "Unable to load FIDO "
					    "enrollment challenge \"%s\"", p);
				}
			} अन्यथा जर (strncasecmp(opts[i],
			    "write-attestation=", 18) == 0) {
				sk_attestation_path = opts[i] + 18;
			} अन्यथा जर (strncasecmp(opts[i],
			    "application=", 12) == 0) {
				sk_application = xstrdup(opts[i] + 12);
				जर (म_भेदन(sk_application, "ssh:", 4) != 0) {
					fatal("FIDO application string must "
					    "begin with \"ssh:\"");
				}
			} अन्यथा {
				fatal("Option \"%s\" is unsupported for "
				    "FIDO authenticator enrollment", opts[i]);
			}
		}
		जर ((attest = sshbuf_new()) == रिक्त)
			fatal("sshbuf_new failed");
		r = 0;
		साठी (i = 0 ;;) {
			जर (!quiet) {
				म_लिखो("You may need to touch your "
				    "authenticator%s to authorize key "
				    "generation.\n",
				    r == 0 ? "" : " again");
			}
			ख_साफ(मानक_निकास);
			r = sshsk_enroll(type, sk_provider, sk_device,
			    sk_application == रिक्त ? "ssh:" : sk_application,
			    sk_user, sk_flags, passphrase, challenge,
			    &खाजगी, attest);
			जर (r == 0)
				थांबा;
			जर (r == SSH_ERR_किल्ली_BAD_PERMISSIONS &&
			    (sk_flags & SSH_SK_RESIDENT_किल्ली) != 0 &&
			    (sk_flags & SSH_SK_FORCE_OPERATION) == 0 &&
			    confirm_sk_overwrite(sk_application, sk_user)) {
				sk_flags |= SSH_SK_FORCE_OPERATION;
				सुरूठेवा;
			}
			जर (r != SSH_ERR_किल्ली_WRONG_PASSPHRASE)
				fatal_r(r, "Key enrollment failed");
			अन्यथा जर (passphrase != रिक्त) {
				error("PIN incorrect");
				freezero(passphrase, म_माप(passphrase));
				passphrase = रिक्त;
			}
			जर (++i >= 3)
				fatal("Too many incorrect PINs");
			passphrase = read_passphrase("Enter PIN for "
			    "authenticator: ", RP_ALLOW_STDIN);
		}
		जर (passphrase != रिक्त) {
			freezero(passphrase, म_माप(passphrase));
			passphrase = रिक्त;
		}
		थांबा;
	पूर्वनिर्धारित:
		जर ((r = sshkey_generate(type, bits, &खाजगी)) != 0)
			fatal("sshkey_generate failed");
		थांबा;
	}
	जर ((r = sshkey_from_private(खाजगी, &सार्वजनिक)) != 0)
		fatal_r(r, "sshkey_from_private");

	जर (!have_identity)
		ask_filename(pw, "Enter file in which to save the key");

	/* Create ~/.ssh directory if it doesn't already exist. */
	hostfile_create_user_ssh_dir(identity_file, !quiet);

	/* If the file already exists, ask the user to confirm. */
	जर (!confirm_overwrite(identity_file))
		निकास(1);

	/* Determine the passphrase for the private key */
	passphrase = private_किल्ली_passphrase(identity_file);
	जर (identity_comment) {
		strlcpy(comment, identity_comment, आकार(comment));
	} अन्यथा {
		/* Create default comment field for the passphrase. */
		snprintf(comment, आकार comment, "%s@%s", pw->pw_name, hostname);
	}



	/* Save the key with the given passphrase and comment. */
	जर ((r = sshkey_save_private(खाजगी, identity_file, passphrase,
	    comment, private_किल्ली_format, openssh_format_cipher, rounds)) != 0) {
		error_r(r, "Saving key \"%s\" failed", identity_file);
		freezero(passphrase, म_माप(passphrase));
		निकास(1);
	}
	freezero(passphrase, म_माप(passphrase));
	sshkey_free(खाजगी);

	जर (!quiet) {
		म_लिखो("Your identification has been saved in %s\n",
		    identity_file);
	}

	strlcat(identity_file, ".pub", आकार(identity_file));
	जर ((r = sshkey_save_public(सार्वजनिक, identity_file, comment)) != 0)
		fatal_r(r, "Unable to save public key to %s", identity_file);

	जर (!quiet) {
		fp = sshkey_fingerprint(सार्वजनिक, fingerprint_hash,
		    SSH_FP_DEFAULT);
		ra = sshkey_fingerprint(सार्वजनिक, fingerprint_hash,
		    SSH_FP_RANDOMART);
		जर (fp == रिक्त || ra == रिक्त)
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

	जर (sk_attestation_path != रिक्त)
		save_attestation(attest, sk_attestation_path);

 done:
	sshbuf_free(attest);
	sshkey_free(सार्वजनिक);
	pwfree(pw);
	निकास(ret);
}
