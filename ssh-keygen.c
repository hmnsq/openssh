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

#यदि_परिभाषितम् WITH_OPENSSL
#अन्तर्भाव "openbsd-compat/openssl-compat.h"
#अन्तर्भाव <openssl/bn.h>
#अन्तर्भाव <openssl/evp.h>
#अन्तर्भाव <openssl/pem.h>
#यदि_अन्तः

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

#यदि_परिभाषितम् ENABLE_PKCS11
#अन्तर्भाव "ssh-pkcs11.h"
#यदि_अन्तः

#परिभाषय DEFAULT_कुञ्चिका_TYPE_NAME "ed25519"

/*
 * Default number of bits in the RSA and ECDSA keys.  These value can be
 * overridden on the command line.
 *
 * These values provide security equivalent to at least 128 bits of security
 * according to NIST Special Publication 800-57: Recommendation for Key
 * Management Part 1 rev 4 section 5.6.1.
 */
#परिभाषय DEFAULT_द्वयङ्काः		3072
#परिभाषय DEFAULT_द्वयङ्काः_ECDSA	256

#परिभाषय कुञ्चिका_COMMENT_MAX		(NI_MAXHOST + 1024)

स्थिर पूर्णाङ्क quiet = 0;

/* Flag indicating that we just want to see the key fingerprint */
स्थिर पूर्णाङ्क print_fingerprint = 0;
स्थिर पूर्णाङ्क print_bubblebabble = 0;

/* Hash algorithm to use for fingerprints. */
स्थिर पूर्णाङ्क fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* The identity file name, given on the command line or entered by the user. */
स्थिर वर्ण तटस्थः_file[PATH_MAX];
स्थिर पूर्णाङ्क have_तटस्थः = 0;

/* This is set to the passphrase if given on the command line. */
स्थिर वर्ण *तटस्थः_passphrase = रिक्त;

/* This is set to the new passphrase if given on the command line. */
स्थिर वर्ण *तटस्थः_new_passphrase = रिक्त;

/* Key type when certifying */
स्थिर u_int cert_कुञ्चिका_type = SSH2_CERT_TYPE_USER;

/* "key ID" of signed key */
स्थिर वर्ण *cert_कुञ्चिका_id = रिक्त;

/* Comma-separated list of principal names for certifying keys */
स्थिर वर्ण *cert_principals = रिक्त;

/* Validity period for certificates */
स्थिर uint64_t cert_valid_from = 0;
स्थिर uint64_t cert_valid_गन्तव्यम् = ~0ULL;

/* Certificate options */
#परिभाषय CERTOPT_X_FWD				(1)
#परिभाषय CERTOPT_AGENT_FWD			(1<<1)
#परिभाषय CERTOPT_पत्तनम्_FWD			(1<<2)
#परिभाषय CERTOPT_PTY				(1<<3)
#परिभाषय CERTOPT_USER_RC				(1<<4)
#परिभाषय CERTOPT_NO_REQUIRE_USER_PRESENCE	(1<<5)
#परिभाषय CERTOPT_REQUIRE_VERIFY			(1<<6)
#परिभाषय CERTOPT_DEFAULT	(CERTOPT_X_FWD|CERTOPT_AGENT_FWD| \
			 CERTOPT_पत्तनम्_FWD|CERTOPT_PTY|CERTOPT_USER_RC)
स्थिर uint32_t certflags_flags = CERTOPT_DEFAULT;
स्थिर वर्ण *certflags_command = रिक्त;
स्थिर वर्ण *certflags_src_addr = रिक्त;

/* Arbitrary extensions specified by user */
संरचना cert_ext {
	वर्ण *कुञ्चिका;
	वर्ण *val;
	पूर्णाङ्क crit;
};
स्थिर संरचना cert_ext *cert_ext;
स्थिर आकार_t ncert_ext;

/* Conversion to/from various formats */
गणना {
	FMT_RFC4716,
	FMT_PKCS8,
	FMT_PEM,
	FMT_HEXDUMP
} convert_format = FMT_RFC4716;

स्थिर वर्ण *कुञ्चिका_type_name = रिक्त;

/* Load key from this PKCS#11 provider */
स्थिर वर्ण *pkcs11provider = रिक्त;

/* FIDO/U2F provider to use */
स्थिर वर्ण *sk_provider = रिक्त;

/* Format for writing private keys */
स्थिर पूर्णाङ्क वैयक्तिकम्_कुञ्चिका_format = SSHKEY_वैयक्तिकम्_OPENSSH;

/* Cipher for new-format private keys */
स्थिर वर्ण *openssh_format_cipher = रिक्त;

/* Number of KDF rounds to derive new format keys. */
स्थिर पूर्णाङ्क आवर्तनानि = 0;

/* argv0 */
बाह्य वर्ण *__progname;

स्थिर वर्ण hostname[NI_MAXHOST];

#यदि_परिभाषितम् WITH_OPENSSL
/* moduli.c */
पूर्णाङ्क gen_candidates(FILE *, uint32_t, BIGNUM *);
पूर्णाङ्क अविभाज्यः_test(FILE *, FILE *, uint32_t, uint32_t, वर्ण *, अचिह्नित दीर्घ,
    अचिह्नित दीर्घ);
#यदि_अन्तः

स्थिर शून्य
type_द्वयङ्काः_valid(पूर्णाङ्क type, ध्रुव वर्ण *name, uint32_t *bitsp)
{
	यदि (type == कुञ्चिका_UNSPEC)
		fatal("unknown key type %s", कुञ्चिका_type_name);
	यदि (*bitsp == 0) {
#यदि_परिभाषितम् WITH_OPENSSL
		पूर्णाङ्क nid;

		विकल्प(type) {
		पक्ष कुञ्चिका_ECDSA:
			यदि (name != रिक्त &&
			    (nid = sshkey_ecdsa_nid_from_name(name)) > 0)
				*bitsp = sshkey_वक्रम्_nid_गन्तव्यम्_द्वयङ्काः(nid);
			यदि (*bitsp == 0)
				*bitsp = DEFAULT_द्वयङ्काः_ECDSA;
			भङ्ग;
		पक्ष कुञ्चिका_RSA:
			*bitsp = DEFAULT_द्वयङ्काः;
			भङ्ग;
		}
#यदि_अन्तः
	}
#यदि_परिभाषितम् WITH_OPENSSL
	विकल्प (type) {
	पक्ष कुञ्चिका_RSA:
		यदि (*bitsp < SSH_RSA_MINIMUM_MODULUS_आकार)
			fatal("Invalid RSA key length: minimum is %d bits",
			    SSH_RSA_MINIMUM_MODULUS_आकार);
		अन्यथा यदि (*bitsp > OPENSSL_RSA_MAX_MODULUS_द्वयङ्काः)
			fatal("Invalid RSA key length: maximum is %d bits",
			    OPENSSL_RSA_MAX_MODULUS_द्वयङ्काः);
		भङ्ग;
	पक्ष कुञ्चिका_ECDSA:
		यदि (sshkey_ecdsa_द्वयङ्काः_गन्तव्यम्_nid(*bitsp) == -1)
			fatal("Invalid ECDSA key length: valid lengths are "
			    "256, 384 or 521 bits");
	}
#यदि_अन्तः
}

/*
 * Checks whether a file exists and, if so, asks the user whether they wish
 * to overwrite it.
 * Returns nonzero if the file does not already exist or if the user agrees to
 * overwrite, or zero otherwise.
 */
स्थिर पूर्णाङ्क
confirm_overwrite(ध्रुव वर्ण *filename)
{
	वर्ण yesno[3];
	संरचना stat st;

	यदि (stat(filename, &st) != 0)
		प्रत्यागम 1;
	प्रारूप_लिख("%s already exists.\n", filename);
	प्रारूप_लिख("Overwrite (y/n)? ");
	fflush(stdout);
	यदि (fgets(yesno, परिमाण(yesno), stdin) == रिक्त)
		प्रत्यागम 0;
	यदि (yesno[0] != 'y' && yesno[0] != 'Y')
		प्रत्यागम 0;
	प्रत्यागम 1;
}

स्थिर शून्य
ask_filename(संरचना passwd *pw, ध्रुव वर्ण *prompt)
{
	वर्ण buf[1024];
	वर्ण *name = रिक्त;

	यदि (कुञ्चिका_type_name == रिक्त)
		name = मार्गः_SSH_CLIENT_ID_ED25519;
	अन्यथा {
		विकल्प (sshkey_type_from_shortname(कुञ्चिका_type_name)) {
		पक्ष कुञ्चिका_ECDSA_CERT:
		पक्ष कुञ्चिका_ECDSA:
			name = मार्गः_SSH_CLIENT_ID_ECDSA;
			भङ्ग;
		पक्ष कुञ्चिका_ECDSA_SK_CERT:
		पक्ष कुञ्चिका_ECDSA_SK:
			name = मार्गः_SSH_CLIENT_ID_ECDSA_SK;
			भङ्ग;
		पक्ष कुञ्चिका_RSA_CERT:
		पक्ष कुञ्चिका_RSA:
			name = मार्गः_SSH_CLIENT_ID_RSA;
			भङ्ग;
		पक्ष कुञ्चिका_ED25519:
		पक्ष कुञ्चिका_ED25519_CERT:
			name = मार्गः_SSH_CLIENT_ID_ED25519;
			भङ्ग;
		पक्ष कुञ्चिका_ED25519_SK:
		पक्ष कुञ्चिका_ED25519_SK_CERT:
			name = मार्गः_SSH_CLIENT_ID_ED25519_SK;
			भङ्ग;
		पक्ष कुञ्चिका_MLDSA44_ED25519:
		पक्ष कुञ्चिका_MLDSA44_ED25519_CERT:
			name = मार्गः_SSH_CLIENT_ID_MLDSA44_ED25519;
			भङ्ग;
		स्वभाव:
			fatal("bad key type");
		}
	}
	snprintf(तटस्थः_file, परिमाण(तटस्थः_file),
	    "%s/%s", pw->pw_dir, name);
	प्रारूप_लिख("%s (%s): ", prompt, तटस्थः_file);
	fflush(stdout);
	यदि (fgets(buf, परिमाण(buf), stdin) == रिक्त)
		निर्गच्छ(1);
	buf[strcspn(buf, "\n")] = '\0';
	यदि (वाक्यं_तुलय(buf, "") != 0)
		strlcpy(तटस्थः_file, buf, परिमाण(तटस्थः_file));
	have_तटस्थः = 1;
}

स्थिर संरचना sshkey *
आरोपय_तटस्थः(ध्रुव वर्ण *filename, वर्ण **commentp)
{
	वर्ण *prompt, *pass;
	संरचना sshkey *prv;
	पूर्णाङ्क r;

	यदि (commentp != रिक्त)
		*commentp = रिक्त;
	यदि ((r = sshkey_आरोपय_वैयक्तिकम्(filename, "", &prv, commentp)) == 0)
		प्रत्यागम prv;
	यदि (r != SSH_ERR_कुञ्चिका_WRONG_PASSPHRASE)
		fatal_r(r, "Load key \"%s\"", filename);
	यदि (तटस्थः_passphrase)
		pass = xstrdup(तटस्थः_passphrase);
	अन्यथा {
		xasprintf(&prompt, "Enter passphrase for \"%s\": ", filename);
		pass = read_passphrase(prompt, RP_ALLOW_STDIN);
		मुक्त(prompt);
	}
	r = sshkey_आरोपय_वैयक्तिकम्(filename, pass, &prv, commentp);
	freezero(pass, वाक्यदैर्घ्यम्(pass));
	यदि (r != 0)
		fatal_r(r, "Load key \"%s\"", filename);
	प्रत्यागम prv;
}

#परिभाषय SSH_COM_लौकिकम्_BEGIN		"---- BEGIN SSH2 PUBLIC KEY ----"
#परिभाषय SSH_COM_लौकिकम्_अन्तः		"---- END SSH2 PUBLIC KEY ----"
#परिभाषय SSH_COM_वैयक्तिकम्_BEGIN		"---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----"
#परिभाषय	SSH_COM_वैयक्तिकम्_कुञ्चिका_MAGIC	0x3f6ff9eb

#यदि_परिभाषितम् WITH_OPENSSL
स्थिर शून्य
do_convert_गन्तव्यम्_ssh2(संरचना passwd *pw, संरचना sshkey *k)
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
	    sshkey_आकार(k), sshkey_type(k),
	    pw->pw_name, hostname);

	sshkey_free(k);
	sshbuf_free(b);

	fprintf(stdout, "%s\n", SSH_COM_लौकिकम्_BEGIN);
	fprintf(stdout, "Comment: \"%s\"\n%s", comment, b64);
	fprintf(stdout, "%s\n", SSH_COM_लौकिकम्_अन्तः);
	मुक्त(b64);
}

स्थिर शून्य
do_convert_गन्तव्यम्_pkcs8(संरचना sshkey *k)
{
	विकल्प (sshkey_type_plain(k->type)) {
	पक्ष कुञ्चिका_RSA:
		यदि (!PEM_write_RSA_PUBKEY(stdout,
		    EVP_PKEY_get0_RSA(k->pkey)))
			fatal("PEM_write_RSA_PUBKEY failed");
		भङ्ग;
	पक्ष कुञ्चिका_ECDSA:
		यदि (!PEM_write_EC_PUBKEY(stdout,
		    EVP_PKEY_get0_EC_कुञ्चिका(k->pkey)))
			fatal("PEM_write_EC_PUBKEY failed");
		भङ्ग;
	स्वभाव:
		fatal_f("unsupported key type %s", sshkey_type(k));
	}
}

स्थिर शून्य
do_convert_गन्तव्यम्_pem(संरचना sshkey *k)
{
	विकल्प (sshkey_type_plain(k->type)) {
	पक्ष कुञ्चिका_RSA:
		यदि (!PEM_write_RSAPublic_कुञ्चिका(stdout,
		    EVP_PKEY_get0_RSA(k->pkey)))
			fatal("PEM_write_RSAPublicKey failed");
		भङ्ग;
	पक्ष कुञ्चिका_ECDSA:
		यदि (!PEM_write_EC_PUBKEY(stdout,
		    EVP_PKEY_get0_EC_कुञ्चिका(k->pkey)))
			fatal("PEM_write_EC_PUBKEY failed");
		भङ्ग;
	स्वभाव:
		fatal_f("unsupported key type %s", sshkey_type(k));
	}
}

स्थिर शून्य
do_convert_गन्तव्यम्_hexdump(संरचना sshkey *k)
{
	संरचना sshbuf *b;
	पूर्णाङ्क r;

	यदि ((b = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	/* pubkey */
	यदि ((r = sshkey_putb(k, b)) != 0)
		fatal_fr(r, "serialise private");
	प्रारूप_लिख("Public %s key:\n", sshkey_type(k));
	sshbuf_dump(b, stdout);
	sshbuf_reset(b);
	यदि ((r = sshkey_वैयक्तिकम्_serialize(k, b)) != 0) {
		debug_fr(r, "serialise private");
		गच्छ बहिर्गमनम्;
	}
	प्रारूप_लिख("\nPrivate %s key:\n", sshkey_type(k));
	sshbuf_dump(b, stdout);
 बहिर्गमनम्:
	sshbuf_free(b);
}

स्थिर शून्य
do_convert_गन्तव्यम्(संरचना passwd *pw)
{
	संरचना sshkey *k = रिक्त;
	संरचना stat st;
	पूर्णाङ्क r;

	यदि (!have_तटस्थः)
		ask_filename(pw, "Enter file in which the key is");
	यदि (stat(तटस्थः_file, &st) == -1)
		fatal("%s: %s: %s", __progname, तटस्थः_file, strerror(errno));

	/* If we're trying to hexdump, then prefer the private key */
	यदि (convert_format == FMT_HEXDUMP) {
		यदि ((r = sshkey_आरोपय_वैयक्तिकम्(तटस्थः_file,
		    रिक्त, &k, रिक्त)) != 0 &&
		    r == SSH_ERR_कुञ्चिका_WRONG_PASSPHRASE)
			k = आरोपय_तटस्थः(तटस्थः_file, रिक्त);
	}
	यदि (k == रिक्त && (r = sshkey_आरोपय_लौकिकम्(तटस्थः_file, &k, रिक्त)) != 0)
		k = आरोपय_तटस्थः(तटस्थः_file, रिक्त);

	विकल्प (convert_format) {
	पक्ष FMT_RFC4716:
		do_convert_गन्तव्यम्_ssh2(pw, k);
		भङ्ग;
	पक्ष FMT_PKCS8:
		do_convert_गन्तव्यम्_pkcs8(k);
		भङ्ग;
	पक्ष FMT_PEM:
		do_convert_गन्तव्यम्_pem(k);
		भङ्ग;
	पक्ष FMT_HEXDUMP:
		do_convert_गन्तव्यम्_hexdump(k);
		भङ्ग;
	स्वभाव:
		fatal_f("unknown key format %d", convert_format);
	}
}

/*
 * This is almost exactly the bignum1 encoding, but with 32 bit for length
 * instead of 16.
 */
स्थिर शून्य
बफर_get_bignum_द्वयङ्काः(संरचना sshbuf *b, BIGNUM *मानम्)
{
	u_int अष्टकानि, bignum_द्वयङ्काः;
	पूर्णाङ्क r;

	यदि ((r = sshbuf_get_u32(b, &bignum_द्वयङ्काः)) != 0)
		fatal_fr(r, "parse");
	अष्टकानि = (bignum_द्वयङ्काः + 7) / 8;
	यदि (sshbuf_len(b) < अष्टकानि)
		fatal_f("input buffer too small: need %d have %zu",
		    अष्टकानि, sshbuf_len(b));
	यदि (BN_bin2bn(sshbuf_ptr(b), अष्टकानि, मानम्) == रिक्त)
		fatal_f("BN_bin2bn failed");
	यदि ((r = sshbuf_consume(b, अष्टकानि)) != 0)
		fatal_fr(r, "consume");
}

स्थिर संरचना sshkey *
do_convert_वैयक्तिकम्_ssh2(संरचना sshbuf *b)
{
	संरचना sshkey *कुञ्चिका = रिक्त;
	वर्ण *type, *cipher;
	ध्रुव वर्ण *alg = रिक्त;
	u_char e1, e2, e3, *sig = रिक्त, दत्त[] = "abcde12345";
	पूर्णाङ्क r, rlen, ktype;
	u_int magic, i1, i2, i3, i4;
	आकार_t slen;
	u_long e;
	BIGNUM *rsa_n = रिक्त, *rsa_e = रिक्त, *rsa_d = रिक्त;
	BIGNUM *rsa_p = रिक्त, *rsa_q = रिक्त, *rsa_iqmp = रिक्त;
	BIGNUM *rsa_dmp1 = रिक्त, *rsa_dmq1 = रिक्त;
	RSA *rsa = रिक्त;

	यदि ((r = sshbuf_get_u32(b, &magic)) != 0)
		fatal_fr(r, "parse magic");

	यदि (magic != SSH_COM_वैयक्तिकम्_कुञ्चिका_MAGIC) {
		error("bad magic 0x%x != 0x%x", magic,
		    SSH_COM_वैयक्तिकम्_कुञ्चिका_MAGIC);
		प्रत्यागम रिक्त;
	}
	यदि ((r = sshbuf_get_u32(b, &i1)) != 0 ||
	    (r = sshbuf_get_cstring(b, &type, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(b, &cipher, रिक्त)) != 0 ||
	    (r = sshbuf_get_u32(b, &i2)) != 0 ||
	    (r = sshbuf_get_u32(b, &i3)) != 0 ||
	    (r = sshbuf_get_u32(b, &i4)) != 0)
		fatal_fr(r, "parse");
	debug("ignore (%d %d %d %d)", i1, i2, i3, i4);
	यदि (वाक्यं_तुलय(cipher, "none") != 0) {
		error("unsupported cipher %s", cipher);
		मुक्त(cipher);
		मुक्त(type);
		प्रत्यागम रिक्त;
	}
	मुक्त(cipher);

	यदि (वाक्ये_अन्विष(type, "rsa")) {
		ktype = कुञ्चिका_RSA;
	} अन्यथा {
		मुक्त(type);
		प्रत्यागम रिक्त;
	}
	यदि ((कुञ्चिका = sshkey_new(ktype)) == रिक्त)
		fatal("sshkey_new failed");
	मुक्त(type);

	विकल्प (कुञ्चिका->type) {
	पक्ष कुञ्चिका_RSA:
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
		यदि (!BN_समुच्चयः_word(rsa_e, e)) {
			BN_clear_free(rsa_e);
			sshkey_free(कुञ्चिका);
			प्रत्यागम रिक्त;
		}
		यदि ((rsa_n = BN_new()) == रिक्त ||
		    (rsa_d = BN_new()) == रिक्त ||
		    (rsa_p = BN_new()) == रिक्त ||
		    (rsa_q = BN_new()) == रिक्त ||
		    (rsa_iqmp = BN_new()) == रिक्त)
			fatal_f("BN_new");
		बफर_get_bignum_द्वयङ्काः(b, rsa_d);
		बफर_get_bignum_द्वयङ्काः(b, rsa_n);
		बफर_get_bignum_द्वयङ्काः(b, rsa_iqmp);
		बफर_get_bignum_द्वयङ्काः(b, rsa_q);
		बफर_get_bignum_द्वयङ्काः(b, rsa_p);
		यदि ((r = ssh_rsa_complete_crt_parameters(rsa_d, rsa_p, rsa_q,
		    rsa_iqmp, &rsa_dmp1, &rsa_dmq1)) != 0)
			fatal_fr(r, "generate RSA CRT parameters");
		EVP_PKEY_free(कुञ्चिका->pkey);
		यदि ((कुञ्चिका->pkey = EVP_PKEY_new()) == रिक्त)
			fatal_f("EVP_PKEY_new failed");
		यदि ((rsa = RSA_new()) == रिक्त)
			fatal_f("RSA_new failed");
		यदि (!RSA_set0_कुञ्चिका(rsa, rsa_n, rsa_e, rsa_d))
			fatal_f("RSA_set0_key failed");
		rsa_n = rsa_e = rsa_d = रिक्त; /* transferred */
		यदि (!RSA_set0_factors(rsa, rsa_p, rsa_q))
			fatal_f("RSA_set0_factors failed");
		rsa_p = rsa_q = रिक्त; /* transferred */
		यदि (RSA_set0_crt_params(rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp) != 1)
			fatal_f("RSA_set0_crt_params failed");
		rsa_dmp1 = rsa_dmq1 = rsa_iqmp = रिक्त;
		यदि (EVP_PKEY_set1_RSA(कुञ्चिका->pkey, rsa) != 1)
			fatal_f("EVP_PKEY_set1_RSA failed");
		RSA_free(rsa);
		alg = "rsa-sha2-256";
		भङ्ग;
	}
	rlen = sshbuf_len(b);
	यदि (rlen != 0)
		error_f("remaining bytes in key blob %d", rlen);

	/* try the key */
	यदि ((r = sshkey_sign(कुञ्चिका, &sig, &slen, दत्त, परिमाण(दत्त),
	    alg, रिक्त, रिक्त, 0)) != 0)
		error_fr(r, "signing with converted key failed");
	अन्यथा यदि ((r = sshkey_verify(कुञ्चिका, sig, slen, दत्त, परिमाण(दत्त),
	    alg, 0, रिक्त)) != 0)
		error_fr(r, "verification with converted key failed");
	यदि (r != 0) {
		sshkey_free(कुञ्चिका);
		मुक्त(sig);
		प्रत्यागम रिक्त;
	}
	मुक्त(sig);
	प्रत्यागम कुञ्चिका;
}

स्थिर पूर्णाङ्क
get_पङ्क्तिः(FILE *fp, वर्ण *पङ्क्तिः, आकार_t len)
{
	पूर्णाङ्क c;
	आकार_t pos = 0;

	पङ्क्तिः[0] = '\0';
	यावत् ((c = fgetc(fp)) != EOF) {
		यदि (pos >= len - 1)
			fatal("input line too long.");
		विकल्प (c) {
		पक्ष '\r':
			c = fgetc(fp);
			यदि (c != EOF && c != '\n' && ungetc(c, fp) == EOF)
				fatal("unget: %s", strerror(errno));
			प्रत्यागम pos;
		पक्ष '\n':
			प्रत्यागम pos;
		}
		पङ्क्तिः[pos++] = c;
		पङ्क्तिः[pos] = '\0';
	}
	/* We reached EOF */
	प्रत्यागम -1;
}

स्थिर शून्य
do_convert_from_ssh2(संरचना passwd *pw, संरचना sshkey **k, पूर्णाङ्क *गुप्त)
{
	पूर्णाङ्क r, blen, escaped = 0;
	u_int len;
	वर्ण पङ्क्तिः[1024];
	संरचना sshbuf *buf;
	वर्ण encoded[8096];
	FILE *fp;

	यदि ((buf = sshbuf_new()) == रिक्त)
		fatal("sshbuf_new failed");
	यदि ((fp = fopen(तटस्थः_file, "r")) == रिक्त)
		fatal("%s: %s: %s", __progname, तटस्थः_file, strerror(errno));
	encoded[0] = '\0';
	यावत् ((blen = get_पङ्क्तिः(fp, पङ्क्तिः, परिमाण(पङ्क्तिः))) != -1) {
		यदि (blen > 0 && पङ्क्तिः[blen - 1] == '\\')
			escaped++;
		यदि (वाक्ये_तुलय(पङ्क्तिः, "----", 4) == 0 ||
		    वाक्ये_अन्विष(पङ्क्तिः, ": ") != रिक्त) {
			यदि (वाक्ये_अन्विष(पङ्क्तिः, SSH_COM_वैयक्तिकम्_BEGIN) != रिक्त)
				*गुप्त = 1;
			यदि (वाक्ये_अन्विष(पङ्क्तिः, " END ") != रिक्त) {
				भङ्ग;
			}
			/* fprintf(stderr, "ignore: %s", line); */
			अनुवर्त;
		}
		यदि (escaped) {
			escaped--;
			/* fprintf(stderr, "escaped: %s", line); */
			अनुवर्त;
		}
		strlcat(encoded, पङ्क्तिः, परिमाण(encoded));
	}
	len = वाक्यदैर्घ्यम्(encoded);
	यदि (((len % 4) == 3) &&
	    (encoded[len-1] == '=') &&
	    (encoded[len-2] == '=') &&
	    (encoded[len-3] == '='))
		encoded[len-3] = '\0';
	यदि ((r = sshbuf_b64tod(buf, encoded)) != 0)
		fatal_fr(r, "base64 decode");
	यदि (*गुप्त) {
		यदि ((*k = do_convert_वैयक्तिकम्_ssh2(buf)) == रिक्त)
			fatal_f("private key conversion failed");
	} अन्यथा यदि ((r = sshkey_fromb(buf, k)) != 0)
		fatal_fr(r, "parse key");
	sshbuf_free(buf);
	fclose(fp);
}

स्थिर शून्य
do_convert_from_pkcs8(संरचना sshkey **k, पूर्णाङ्क *गुप्त)
{
	EVP_PKEY *pubkey;
	FILE *fp;

	यदि ((fp = fopen(तटस्थः_file, "r")) == रिक्त)
		fatal("%s: %s: %s", __progname, तटस्थः_file, strerror(errno));
	यदि ((pubkey = PEM_read_PUBKEY(fp, रिक्त, रिक्त, रिक्त)) == रिक्त) {
		fatal_f("%s is not a recognised public key format",
		    तटस्थः_file);
	}
	fclose(fp);
	विकल्प (EVP_PKEY_आधारः_id(pubkey)) {
	पक्ष EVP_PKEY_RSA:
		यदि ((*k = sshkey_new(कुञ्चिका_UNSPEC)) == रिक्त)
			fatal("sshkey_new failed");
		(*k)->type = कुञ्चिका_RSA;
		(*k)->pkey = pubkey;
		pubkey = रिक्त;
		भङ्ग;
	पक्ष EVP_PKEY_EC:
		यदि ((*k = sshkey_new(कुञ्चिका_UNSPEC)) == रिक्त)
			fatal("sshkey_new failed");
		यदि (((*k)->ecdsa_nid = sshkey_ecdsa_fixup_गणः(pubkey)) == -1)
			fatal("sshkey_ecdsa_fixup_group failed");
		(*k)->type = कुञ्चिका_ECDSA;
		(*k)->pkey = pubkey;
		pubkey = रिक्त;
		भङ्ग;
	स्वभाव:
		fatal_f("unsupported pubkey type %d",
		    EVP_PKEY_आधारः_id(pubkey));
	}
	EVP_PKEY_free(pubkey);
}

स्थिर शून्य
do_convert_from_pem(संरचना sshkey **k, पूर्णाङ्क *गुप्त)
{
	FILE *fp;
	RSA *rsa;

	यदि ((fp = fopen(तटस्थः_file, "r")) == रिक्त)
		fatal("%s: %s: %s", __progname, तटस्थः_file, strerror(errno));
	यदि ((rsa = PEM_read_RSAPublic_कुञ्चिका(fp, रिक्त, रिक्त, रिक्त)) != रिक्त) {
		यदि ((*k = sshkey_new(कुञ्चिका_UNSPEC)) == रिक्त)
			fatal("sshkey_new failed");
		यदि (((*k)->pkey = EVP_PKEY_new()) == रिक्त)
			fatal("EVP_PKEY_new failed");
		(*k)->type = कुञ्चिका_RSA;
		यदि (EVP_PKEY_set1_RSA((*k)->pkey, rsa) != 1)
			fatal("EVP_PKEY_set1_RSA failed");
		RSA_free(rsa);
		fclose(fp);
		प्रत्यागम;
	}
	fatal_f("unrecognised raw private key format");
}

स्थिर शून्य
do_convert_from(संरचना passwd *pw)
{
	संरचना sshkey *k = रिक्त;
	पूर्णाङ्क r, गुप्त = 0, ok = 0;
	संरचना stat st;

	यदि (!have_तटस्थः)
		ask_filename(pw, "Enter file in which the key is");
	यदि (stat(तटस्थः_file, &st) == -1)
		fatal("%s: %s: %s", __progname, तटस्थः_file, strerror(errno));

	विकल्प (convert_format) {
	पक्ष FMT_RFC4716:
		do_convert_from_ssh2(pw, &k, &गुप्त);
		भङ्ग;
	पक्ष FMT_PKCS8:
		do_convert_from_pkcs8(&k, &गुप्त);
		भङ्ग;
	पक्ष FMT_PEM:
		do_convert_from_pem(&k, &गुप्त);
		भङ्ग;
	स्वभाव:
		fatal_f("unknown key format %d", convert_format);
	}

	यदि (!गुप्त) {
		यदि ((r = sshkey_write(k, stdout)) == 0)
			ok = 1;
		यदि (ok)
			fprintf(stdout, "\n");
	} अन्यथा {
		विकल्प (k->type) {
		पक्ष कुञ्चिका_ECDSA:
			ok = PEM_write_ECPrivate_कुञ्चिका(stdout,
			    EVP_PKEY_get0_EC_कुञ्चिका(k->pkey), रिक्त, रिक्त, 0,
			    रिक्त, रिक्त);
			भङ्ग;
		पक्ष कुञ्चिका_RSA:
			ok = PEM_write_RSAPrivate_कुञ्चिका(stdout,
			    EVP_PKEY_get0_RSA(k->pkey), रिक्त, रिक्त, 0,
			    रिक्त, रिक्त);
			भङ्ग;
		स्वभाव:
			fatal_f("unsupported key type %s", sshkey_type(k));
		}
	}

	यदि (!ok)
		fatal("key write failed");
	sshkey_free(k);
}
#यदि_अन्तः

स्थिर शून्य
do_print_लौकिकम्(संरचना passwd *pw)
{
	संरचना sshkey *prv;
	संरचना stat st;
	पूर्णाङ्क r;
	वर्ण *comment = रिक्त;

	यदि (!have_तटस्थः)
		ask_filename(pw, "Enter file in which the key is");
	यदि (stat(तटस्थः_file, &st) == -1)
		fatal("%s: %s", तटस्थः_file, strerror(errno));
	prv = आरोपय_तटस्थः(तटस्थः_file, &comment);
	यदि ((r = sshkey_write(prv, stdout)) != 0)
		fatal_fr(r, "write key");
	यदि (comment != रिक्त && *comment != '\0')
		fprintf(stdout, " %s", comment);
	fprintf(stdout, "\n");
	यदि (sshkey_is_sk(prv)) {
		debug("sk_application: \"%s\", sk_flags 0x%02x",
			prv->sk_application, prv->sk_flags);
	}
	sshkey_free(prv);
	मुक्त(comment);
	निर्गच्छ(0);
}

स्थिर शून्य
do_download(संरचना passwd *pw)
{
#यदि_परिभाषितम् ENABLE_PKCS11
	संरचना sshkey **कुञ्चिकाः = रिक्त;
	पूर्णाङ्क i, nkeys;
	गणना sshkey_fp_rep rep;
	पूर्णाङ्क fptype;
	वर्ण *fp, *ra, **comments = रिक्त;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;

	pkcs11_init(1);
	nkeys = pkcs11_सङ्कलय_provider(pkcs11provider, रिक्त, &कुञ्चिकाः, &comments);
	यदि (nkeys <= 0)
		fatal("cannot read public key from pkcs11");
	प्रति (i = 0; i < nkeys; i++) {
		यदि (print_fingerprint) {
			fp = sshkey_fingerprint(कुञ्चिकाः[i], fptype, rep);
			ra = sshkey_fingerprint(कुञ्चिकाः[i], fingerprint_hash,
			    SSH_FP_RANDOMART);
			यदि (fp == रिक्त || ra == रिक्त)
				fatal_f("sshkey_fingerprint fail");
			प्रारूप_लिख("%u %s %s (PKCS11 key)\n", sshkey_आकार(कुञ्चिकाः[i]),
			    fp, sshkey_type(कुञ्चिकाः[i]));
			यदि (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
				प्रारूप_लिख("%s\n", ra);
			मुक्त(ra);
			मुक्त(fp);
		} अन्यथा {
			(शून्य) sshkey_write(कुञ्चिकाः[i], stdout); /* XXX check */
			fprintf(stdout, "%s%s\n",
			    *(comments[i]) == '\0' ? "" : " ", comments[i]);
		}
		मुक्त(comments[i]);
		sshkey_free(कुञ्चिकाः[i]);
	}
	मुक्त(comments);
	मुक्त(कुञ्चिकाः);
	pkcs11_terminate();
	निर्गच्छ(0);
#अन्यथा
	fatal("no pkcs11 support");
#यदि_अन्तः /* ENABLE_PKCS11 */
}

स्थिर संरचना sshkey *
try_read_कुञ्चिका(वर्ण **cpp)
{
	संरचना sshkey *ret;
	पूर्णाङ्क r;

	यदि ((ret = sshkey_new(कुञ्चिका_UNSPEC)) == रिक्त)
		fatal("sshkey_new failed");
	यदि ((r = sshkey_read(ret, cpp)) == 0)
		प्रत्यागम ret;
	/* Not a key */
	sshkey_free(ret);
	प्रत्यागम रिक्त;
}

स्थिर शून्य
fingerprint_one_कुञ्चिका(ध्रुव संरचना sshkey *सार्वजनिक, ध्रुव वर्ण *comment)
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
	mprintf("%u %s %s (%s)\n", sshkey_आकार(सार्वजनिक), fp,
	    comment ? comment : "no comment", sshkey_type(सार्वजनिक));
	यदि (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
		प्रारूप_लिख("%s\n", ra);
	मुक्त(ra);
	मुक्त(fp);
}

स्थिर शून्य
fingerprint_वैयक्तिकम्(ध्रुव वर्ण *मार्गः)
{
	संरचना stat st;
	वर्ण *comment = रिक्त;
	संरचना sshkey *privkey = रिक्त, *pubkey = रिक्त;
	पूर्णाङ्क r;

	यदि (stat(तटस्थः_file, &st) == -1)
		fatal("%s: %s", मार्गः, strerror(errno));
	यदि ((r = sshkey_आरोपय_लौकिकम्(मार्गः, &pubkey, &comment)) != 0)
		debug_r(r, "load public \"%s\"", मार्गः);
	यदि (pubkey == रिक्त || comment == रिक्त || *comment == '\0') {
		मुक्त(comment);
		यदि ((r = sshkey_आरोपय_वैयक्तिकम्(मार्गः, रिक्त,
		    &privkey, &comment)) != 0)
			debug_r(r, "load private \"%s\"", मार्गः);
	}
	यदि (pubkey == रिक्त && privkey == रिक्त)
		fatal("%s is not a key file.", मार्गः);

	fingerprint_one_कुञ्चिका(pubkey == रिक्त ? privkey : pubkey, comment);
	sshkey_free(pubkey);
	sshkey_free(privkey);
	मुक्त(comment);
}

स्थिर शून्य
do_fingerprint(संरचना passwd *pw)
{
	FILE *f;
	संरचना sshkey *सार्वजनिक = रिक्त;
	वर्ण *comment = रिक्त, *cp, *ep, *पङ्क्तिः = रिक्त;
	आकार_t linesize = 0;
	पूर्णाङ्क i, invalid = 1;
	ध्रुव वर्ण *मार्गः;
	u_long lnum = 0;

	यदि (!have_तटस्थः)
		ask_filename(pw, "Enter file in which the key is");
	मार्गः = तटस्थः_file;

	यदि (वाक्यं_तुलय(तटस्थः_file, "-") == 0) {
		f = stdin;
		मार्गः = "(stdin)";
	} अन्यथा यदि ((f = fopen(मार्गः, "r")) == रिक्त)
		fatal("%s: %s: %s", __progname, मार्गः, strerror(errno));

	यावत् (getline(&पङ्क्तिः, &linesize, f) != -1) {
		lnum++;
		cp = पङ्क्तिः;
		cp[strcspn(cp, "\r\n")] = '\0';
		/* Trim leading space and comments */
		cp = पङ्क्तिः + strspn(पङ्क्तिः, " \t");
		यदि (*cp == '#' || *cp == '\0')
			अनुवर्त;

		/*
		 * Input may be plain keys, private keys, authorized_keys
		 * or known_hosts.
		 */

		/*
		 * Try private keys first. Assume a key is private if
		 * "SSH PRIVATE KEY" appears on the first line and we're
		 * not reading from stdin (XXX support private keys on stdin).
		 */
		यदि (lnum == 1 && वाक्यं_तुलय(तटस्थः_file, "-") != 0 &&
		    वाक्ये_अन्विष(cp, "PRIVATE KEY") != रिक्त) {
			मुक्त(पङ्क्तिः);
			fclose(f);
			fingerprint_वैयक्तिकम्(मार्गः);
			निर्गच्छ(0);
		}

		/*
		 * If it's not a private key, then this must be prepared to
		 * accept a public key prefixed with a hostname or options.
		 * Try a bare key first, otherwise skip the leading stuff.
		 */
		comment = रिक्त;
		यदि ((सार्वजनिक = try_read_कुञ्चिका(&cp)) == रिक्त) {
			i = strtol(cp, &ep, 10);
			यदि (i == 0 || ep == रिक्त ||
			    (*ep != ' ' && *ep != '\t')) {
				पूर्णाङ्क quoted = 0;

				comment = cp;
				प्रति (; *cp && (quoted || (*cp != ' ' &&
				    *cp != '\t')); cp++) {
					यदि (*cp == '\\' && cp[1] == '"')
						cp++;	/* Skip both */
					अन्यथा यदि (*cp == '"')
						quoted = !quoted;
				}
				यदि (!*cp)
					अनुवर्त;
				*cp++ = '\0';
			}
		}
		/* Retry after parsing leading hostname/key options */
		यदि (सार्वजनिक == रिक्त && (सार्वजनिक = try_read_कुञ्चिका(&cp)) == रिक्त) {
			debug("%s:%lu: not a public key", मार्गः, lnum);
			अनुवर्त;
		}

		/* Find trailing comment, if any */
		प्रति (; *cp == ' ' || *cp == '\t'; cp++)
			;
		यदि (*cp != '\0' && *cp != '#')
			comment = cp;

		fingerprint_one_कुञ्चिका(सार्वजनिक, comment);
		sshkey_free(सार्वजनिक);
		invalid = 0; /* One good key in the file is sufficient */
	}
	fclose(f);
	मुक्त(पङ्क्तिः);

	यदि (invalid)
		fatal("%s is not a public key file.", मार्गः);
	निर्गच्छ(0);
}

स्थिर शून्य
do_gen_all_hostkeys(संरचना passwd *pw)
{
	संरचना {
		वर्ण *कुञ्चिका_type;
		वर्ण *कुञ्चिका_type_display;
		वर्ण *मार्गः;
	} कुञ्चिका_types[] = {
#यदि_परिभाषितम् WITH_OPENSSL
		{ "rsa", "RSA" ,मार्गः_HOST_RSA_कुञ्चिका_FILE },
		{ "ecdsa", "ECDSA",मार्गः_HOST_ECDSA_कुञ्चिका_FILE },
#यदि_अन्तः /* WITH_OPENSSL */
		{ "ed25519", "ED25519",मार्गः_HOST_ED25519_कुञ्चिका_FILE },
#यदि_परिभाषितम् USE_MLDSA
		{ "mldsa44-ed25519", "MLDSA44-ED25519",
		     मार्गः_HOST_MLDSA44_ED25519_कुञ्चिका_FILE },
#यदि_अन्तः
		{ रिक्त, रिक्त, रिक्त }
	};

	uint32_t द्वयङ्काः = 0;
	पूर्णाङ्क first = 0;
	संरचना stat st;
	संरचना sshkey *गुप्त, *सार्वजनिक;
	वर्ण comment[कुञ्चिका_COMMENT_MAX], *prv_tmp, *pub_tmp, *prv_file, *pub_file;
	पूर्णाङ्क i, type, fd, r;

	प्रति (i = 0; कुञ्चिका_types[i].कुञ्चिका_type; i++) {
		सार्वजनिक = गुप्त = रिक्त;
		prv_tmp = pub_tmp = prv_file = pub_file = रिक्त;

		xasprintf(&prv_file, "%s%s",
		    तटस्थः_file, कुञ्चिका_types[i].मार्गः);

		/* Check whether private key exists and is not zero-length */
		यदि (stat(prv_file, &st) == 0) {
			यदि (st.st_size != 0)
				गच्छ अग्र;
		} अन्यथा यदि (errno != ENOENT) {
			error("Could not stat %s: %s", कुञ्चिका_types[i].मार्गः,
			    strerror(errno));
			गच्छ failnext;
		}

		/*
		 * Private key doesn't exist or is invalid; proceed with
		 * key generation.
		 */
		xasprintf(&prv_tmp, "%s%s.XXXXXXXXXX",
		    तटस्थः_file, कुञ्चिका_types[i].मार्गः);
		xasprintf(&pub_tmp, "%s%s.pub.XXXXXXXXXX",
		    तटस्थः_file, कुञ्चिका_types[i].मार्गः);
		xasprintf(&pub_file, "%s%s.pub",
		    तटस्थः_file, कुञ्चिका_types[i].मार्गः);

		यदि (first == 0) {
			first = 1;
			प्रारूप_लिख("%s: generating new host keys: ", __progname);
		}
		प्रारूप_लिख("%s ", कुञ्चिका_types[i].कुञ्चिका_type_display);
		fflush(stdout);
		type = sshkey_type_from_shortname(कुञ्चिका_types[i].कुञ्चिका_type);
		यदि ((fd = mkstemp(prv_tmp)) == -1) {
			error("Could not save your private key in %s: %s",
			    prv_tmp, strerror(errno));
			गच्छ failnext;
		}
		(शून्य)close(fd); /* just using mkstemp() to reserve a name */
		द्वयङ्काः = 0;
		type_द्वयङ्काः_valid(type, रिक्त, &द्वयङ्काः);
		यदि ((r = sshkey_generate(type, द्वयङ्काः, &गुप्त)) != 0) {
			error_r(r, "sshkey_generate failed");
			गच्छ failnext;
		}
		यदि ((r = sshkey_from_वैयक्तिकम्(गुप्त, &सार्वजनिक)) != 0)
			fatal_fr(r, "sshkey_from_private");
		snprintf(comment, परिमाण comment, "%s@%s", pw->pw_name,
		    hostname);
		यदि ((r = sshkey_save_वैयक्तिकम्(गुप्त, prv_tmp, "",
		    comment, वैयक्तिकम्_कुञ्चिका_format, openssh_format_cipher,
		    आवर्तनानि)) != 0) {
			error_r(r, "Saving key \"%s\" failed", prv_tmp);
			गच्छ failnext;
		}
		यदि ((fd = mkstemp(pub_tmp)) == -1) {
			error("Could not save your public key in %s: %s",
			    pub_tmp, strerror(errno));
			गच्छ failnext;
		}
		(शून्य)fchmod(fd, 0644);
		(शून्य)close(fd);
		यदि ((r = sshkey_save_लौकिकम्(सार्वजनिक, pub_tmp, comment)) != 0) {
			error_r(r, "Unable to save public key to %s",
			    तटस्थः_file);
			गच्छ failnext;
		}

		/* Rename temporary files to their permanent locations. */
		यदि (rename(pub_tmp, pub_file) != 0) {
			error("Unable to move %s into position: %s",
			    pub_file, strerror(errno));
			गच्छ failnext;
		}
		यदि (rename(prv_tmp, prv_file) != 0) {
			error("Unable to move %s into position: %s",
			    कुञ्चिका_types[i].मार्गः, strerror(errno));
 failnext:
			first = 0;
			गच्छ अग्र;
		}
 अग्र:
		sshkey_free(गुप्त);
		sshkey_free(सार्वजनिक);
		मुक्त(prv_tmp);
		मुक्त(pub_tmp);
		मुक्त(prv_file);
		मुक्त(pub_file);
	}
	यदि (first != 0)
		प्रारूप_लिख("\n");
}

संरचना ज्ञातम्_hosts_ctx {
	ध्रुव वर्ण *host;	/* Hostname searched for in find/delete case */
	FILE *बहिर्गमनम्;		/* Output file, stdout for find_hosts case */
	पूर्णाङ्क has_unhashed;	/* When hashing, original had unhashed hosts */
	पूर्णाङ्क प्राप्तम्_कुञ्चिका;		/* For find/delete, host was found */
	पूर्णाङ्क invalid;		/* File contained invalid items; don't delete */
	पूर्णाङ्क hash_hosts;		/* Hash hostnames as we go */
	पूर्णाङ्क find_host;		/* Search for specific hostname */
	पूर्णाङ्क delete_host;	/* Delete host from known_hosts */
};

स्थिर पूर्णाङ्क
ज्ञातम्_hosts_hash(संरचना hostkey_foreach_पङ्क्तिः *l, शून्य *_ctx)
{
	संरचना ज्ञातम्_hosts_ctx *ctx = (संरचना ज्ञातम्_hosts_ctx *)_ctx;
	वर्ण *hashed, *cp, *hosts, *ohosts;
	पूर्णाङ्क has_wild = l->hosts && strcspn(l->hosts, "*?!") != वाक्यदैर्घ्यम्(l->hosts);
	पूर्णाङ्क was_hashed = l->hosts && l->hosts[0] == HASH_DELIM;

	विकल्प (l->स्थितिः) {
	पक्ष HKF_स्थितिः_OK:
	पक्ष HKF_स्थितिः_MATCHED:
		/*
		 * Don't hash hosts already hashed, with wildcard
		 * characters or a CA/revocation marker.
		 */
		यदि (was_hashed || has_wild || l->marker != MRK_NONE) {
			fprintf(ctx->बहिर्गमनम्, "%s\n", l->पङ्क्तिः);
			यदि (has_wild && !ctx->find_host) {
				logit("%s:%lu: ignoring host name "
				    "with wildcard: %.64s", l->मार्गः,
				    l->linenum, l->hosts);
			}
			प्रत्यागम 0;
		}
		/*
		 * Split any comma-separated hostnames from the host list,
		 * hash and store separately.
		 */
		ohosts = hosts = xstrdup(l->hosts);
		यावत् ((cp = strsep(&hosts, ",")) != रिक्त && *cp != '\0') {
			lowercase(cp);
			यदि ((hashed = host_hash(cp, रिक्त, 0)) == रिक्त)
				fatal("hash_host failed");
			fprintf(ctx->बहिर्गमनम्, "%s %s\n", hashed, l->rawkey);
			मुक्त(hashed);
			ctx->has_unhashed = 1;
		}
		मुक्त(ohosts);
		प्रत्यागम 0;
	पक्ष HKF_स्थितिः_INVALID:
		/* Retain invalid lines, but mark file as invalid. */
		ctx->invalid = 1;
		logit("%s:%lu: invalid line", l->मार्गः, l->linenum);
		/* FALLTHROUGH */
	स्वभाव:
		fprintf(ctx->बहिर्गमनम्, "%s\n", l->पङ्क्तिः);
		प्रत्यागम 0;
	}
	/* NOTREACHED */
	प्रत्यागम -1;
}

स्थिर पूर्णाङ्क
ज्ञातम्_hosts_find_delete(संरचना hostkey_foreach_पङ्क्तिः *l, शून्य *_ctx)
{
	संरचना ज्ञातम्_hosts_ctx *ctx = (संरचना ज्ञातम्_hosts_ctx *)_ctx;
	गणना sshkey_fp_rep rep;
	पूर्णाङ्क fptype;
	वर्ण *fp = रिक्त, *ra = रिक्त;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;

	यदि (l->स्थितिः == HKF_स्थितिः_MATCHED) {
		यदि (ctx->delete_host) {
			यदि (l->marker != MRK_NONE) {
				/* Don't remove CA and revocation lines */
				fprintf(ctx->बहिर्गमनम्, "%s\n", l->पङ्क्तिः);
			} अन्यथा {
				/*
				 * Hostname matches and has no CA/revoke
				 * marker, delete it by *not* writing the
				 * line to ctx->out.
				 */
				ctx->प्राप्तम्_कुञ्चिका = 1;
				यदि (!quiet)
					प्रारूप_लिख("# Host %s found: line %lu\n",
					    ctx->host, l->linenum);
			}
			प्रत्यागम 0;
		} अन्यथा यदि (ctx->find_host) {
			ctx->प्राप्तम्_कुञ्चिका = 1;
			यदि (!quiet) {
				प्रारूप_लिख("# Host %s found: line %lu %s\n",
				    ctx->host,
				    l->linenum, l->marker == MRK_CA ? "CA" :
				    (l->marker == MRK_REVOKE ? "REVOKED" : ""));
			}
			यदि (ctx->hash_hosts)
				ज्ञातम्_hosts_hash(l, ctx);
			अन्यथा यदि (print_fingerprint) {
				fp = sshkey_fingerprint(l->कुञ्चिका, fptype, rep);
				ra = sshkey_fingerprint(l->कुञ्चिका,
				    fingerprint_hash, SSH_FP_RANDOMART);
				यदि (fp == रिक्त || ra == रिक्त)
					fatal_f("sshkey_fingerprint failed");
				mprintf("%s %s %s%s%s\n", ctx->host,
				    sshkey_type(l->कुञ्चिका), fp,
				    l->comment[0] ? " " : "",
				    l->comment);
				यदि (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
					प्रारूप_लिख("%s\n", ra);
				मुक्त(ra);
				मुक्त(fp);
			} अन्यथा
				fprintf(ctx->बहिर्गमनम्, "%s\n", l->पङ्क्तिः);
			प्रत्यागम 0;
		}
	} अन्यथा यदि (ctx->delete_host) {
		/* Retain non-matching hosts when deleting */
		यदि (l->स्थितिः == HKF_स्थितिः_INVALID) {
			ctx->invalid = 1;
			logit("%s:%lu: invalid line", l->मार्गः, l->linenum);
		}
		fprintf(ctx->बहिर्गमनम्, "%s\n", l->पङ्क्तिः);
	}
	प्रत्यागम 0;
}

स्थिर शून्य
do_ज्ञातम्_hosts(संरचना passwd *pw, ध्रुव वर्ण *name, पूर्णाङ्क find_host,
    पूर्णाङ्क delete_host, पूर्णाङ्क hash_hosts)
{
	वर्ण *cp, tmp[PATH_MAX], old[PATH_MAX];
	पूर्णाङ्क r, fd, oerrno, inplace = 0;
	संरचना ज्ञातम्_hosts_ctx ctx;
	u_int foreach_options;
	संरचना stat sb;

	यदि (!have_तटस्थः) {
		cp = tilde_expand_filename(मार्गः_SSH_USER_HOSTFILE, pw->pw_uid);
		यदि (strlcpy(तटस्थः_file, cp, परिमाण(तटस्थः_file)) >=
		    परिमाण(तटस्थः_file))
			fatal("Specified known hosts path too long");
		मुक्त(cp);
		have_तटस्थः = 1;
	}
	यदि (stat(तटस्थः_file, &sb) != 0)
		fatal("Cannot stat %s: %s", तटस्थः_file, strerror(errno));

	स्मृतिं_पूरय(&ctx, 0, परिमाण(ctx));
	ctx.बहिर्गमनम् = stdout;
	ctx.host = name;
	ctx.hash_hosts = hash_hosts;
	ctx.find_host = find_host;
	ctx.delete_host = delete_host;

	/*
	 * Find hosts goes to stdout, hash and deletions happen in-place
	 * A corner case is ssh-keygen -HF foo, which should go to stdout
	 */
	यदि (!find_host && (hash_hosts || delete_host)) {
		यदि (strlcpy(tmp, तटस्थः_file, परिमाण(tmp)) >= परिमाण(tmp) ||
		    strlcat(tmp, ".XXXXXXXXXX", परिमाण(tmp)) >= परिमाण(tmp) ||
		    strlcpy(old, तटस्थः_file, परिमाण(old)) >= परिमाण(old) ||
		    strlcat(old, ".old", परिमाण(old)) >= परिमाण(old))
			fatal("known_hosts path too long");
		umask(077);
		यदि ((fd = mkstemp(tmp)) == -1)
			fatal("mkstemp: %s", strerror(errno));
		यदि ((ctx.बहिर्गमनम् = fdopen(fd, "w")) == रिक्त) {
			oerrno = errno;
			unlink(tmp);
			fatal("fdopen: %s", strerror(oerrno));
		}
		(शून्य)fchmod(fd, sb.st_mode & 0644);
		inplace = 1;
	}
	/* XXX support identity_file == "-" for stdin */
	foreach_options = find_host ? HKF_WANT_मेलनम् : 0;
	foreach_options |= print_fingerprint ? HKF_WANT_PARSE_कुञ्चिका : 0;
	यदि ((r = hostkeys_foreach(तटस्थः_file, (find_host || !hash_hosts) ?
	    ज्ञातम्_hosts_find_delete : ज्ञातम्_hosts_hash, &ctx, name, रिक्त,
	    foreach_options, 0)) != 0) {
		यदि (inplace)
			unlink(tmp);
		fatal_fr(r, "hostkeys_foreach");
	}

	यदि (inplace)
		fclose(ctx.बहिर्गमनम्);

	यदि (ctx.invalid) {
		error("%s is not a valid known_hosts file.", तटस्थः_file);
		यदि (inplace) {
			error("Not replacing existing known_hosts "
			    "file because of errors");
			unlink(tmp);
		}
		निर्गच्छ(1);
	} अन्यथा यदि (delete_host && !ctx.प्राप्तम्_कुञ्चिका) {
		logit("Host %s not found in %s", name, तटस्थः_file);
		यदि (inplace)
			unlink(tmp);
	} अन्यथा यदि (inplace) {
		/* Backup existing file */
		यदि (unlink(old) == -1 && errno != ENOENT)
			fatal("unlink %.100s: %s", old, strerror(errno));
		यदि (link(तटस्थः_file, old) == -1)
			fatal("link %.100s to %.100s: %s", तटस्थः_file, old,
			    strerror(errno));
		/* Move new one into place */
		यदि (rename(tmp, तटस्थः_file) == -1) {
			error("rename\"%s\" to \"%s\": %s", tmp, तटस्थः_file,
			    strerror(errno));
			unlink(tmp);
			unlink(old);
			निर्गच्छ(1);
		}

		प्रारूप_लिख("%s updated.\n", तटस्थः_file);
		प्रारूप_लिख("Original contents retained as %s\n", old);
		यदि (ctx.has_unhashed) {
			logit("WARNING: %s contains unhashed entries", old);
			logit("Delete this file to ensure privacy "
			    "of hostnames");
		}
	}

	निर्गच्छ (find_host && !ctx.प्राप्तम्_कुञ्चिका);
}

/*
 * Perform changing a passphrase.  The argument is the passwd structure
 * for the current user.
 */
स्थिर शून्य
do_change_passphrase(संरचना passwd *pw, वर्ण * ध्रुव *opts, आकार_t nopts)
{
	वर्ण *comment;
	वर्ण *old_passphrase, *passphrase1, *passphrase2;
	संरचना stat st;
	संरचना sshkey *गुप्त;
	पूर्णाङ्क r;
	आकार_t i;

	यदि (!have_तटस्थः)
		ask_filename(pw, "Enter file in which the key is");
	यदि (stat(तटस्थः_file, &st) == -1)
		fatal("%s: %s", तटस्थः_file, strerror(errno));
	/* Try to load the file with empty passphrase. */
	r = sshkey_आरोपय_वैयक्तिकम्(तटस्थः_file, "", &गुप्त, &comment);
	यदि (r == SSH_ERR_कुञ्चिका_WRONG_PASSPHRASE) {
		यदि (तटस्थः_passphrase)
			old_passphrase = xstrdup(तटस्थः_passphrase);
		अन्यथा
			old_passphrase =
			    read_passphrase("Enter old passphrase: ",
			    RP_ALLOW_STDIN);
		r = sshkey_आरोपय_वैयक्तिकम्(तटस्थः_file, old_passphrase,
		    &गुप्त, &comment);
		freezero(old_passphrase, वाक्यदैर्घ्यम्(old_passphrase));
		यदि (r != 0)
			गच्छ badkey;
	} अन्यथा यदि (r != 0) {
 badkey:
		fatal_r(r, "Failed to load key %s", तटस्थः_file);
	}
	यदि (comment)
		mprintf("Key has comment '%s'\n", comment);

	/* All current -O options relate to FIDO keys only */
	यदि (nopts != 0 && !sshkey_is_sk(गुप्त)) {
		fatal("FIDO-specific option requested for non-FIDO key %s",
		    तटस्थः_file);
	}
	यदि (sshkey_is_sk(गुप्त)) {
		debug_f("%s: original FIDO key flags: "
		    "%stouch-required %sverify-required", तटस्थः_file,
		    (गुप्त->sk_flags & SSH_SK_USER_PRESENCE_REQD) ? "": "no-",
		    (गुप्त->sk_flags & SSH_SK_USER_VERIFICATION_REQD) ? "" : "no-");
	}
	प्रति (i = 0; i < nopts; i++) {
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
		    "%stouch-required %sverify-required", तटस्थः_file,
		    (गुप्त->sk_flags & SSH_SK_USER_PRESENCE_REQD) ? "": "no-",
		    (गुप्त->sk_flags & SSH_SK_USER_VERIFICATION_REQD) ? "" : "no-");
	}

	/* Ask the new passphrase (twice). */
	यदि (तटस्थः_new_passphrase) {
		passphrase1 = xstrdup(तटस्थः_new_passphrase);
		passphrase2 = रिक्त;
	} अन्यथा {
		passphrase1 =
			read_passphrase("Enter new passphrase (empty for no "
			    "passphrase): ", RP_ALLOW_STDIN);
		passphrase2 = read_passphrase("Enter same passphrase again: ",
		    RP_ALLOW_STDIN);

		/* Verify that they are the same. */
		यदि (वाक्यं_तुलय(passphrase1, passphrase2) != 0) {
			explicit_bzero(passphrase1, वाक्यदैर्घ्यम्(passphrase1));
			explicit_bzero(passphrase2, वाक्यदैर्घ्यम्(passphrase2));
			मुक्त(passphrase1);
			मुक्त(passphrase2);
			प्रारूप_लिख("Pass phrases do not match.  Try again.\n");
			निर्गच्छ(1);
		}
		/* Destroy the other copy. */
		freezero(passphrase2, वाक्यदैर्घ्यम्(passphrase2));
	}

	/* Save the file using the new passphrase. */
	यदि ((r = sshkey_save_वैयक्तिकम्(गुप्त, तटस्थः_file, passphrase1,
	    comment, वैयक्तिकम्_कुञ्चिका_format, openssh_format_cipher, आवर्तनानि)) != 0) {
		error_r(r, "Saving key \"%s\" failed", तटस्थः_file);
		freezero(passphrase1, वाक्यदैर्घ्यम्(passphrase1));
		sshkey_free(गुप्त);
		मुक्त(comment);
		निर्गच्छ(1);
	}
	/* Destroy the passphrase and the copy of the key in memory. */
	freezero(passphrase1, वाक्यदैर्घ्यम्(passphrase1));
	sshkey_free(गुप्त);		 /* Destroys contents */
	मुक्त(comment);

	प्रारूप_लिख("Your identification has been saved with the new passphrase.\n");
	निर्गच्छ(0);
}

/*
 * Print the SSHFP RR.
 */
स्थिर पूर्णाङ्क
do_print_resource_लेखः(संरचना passwd *pw, वर्ण *fname, वर्ण *hname,
    पूर्णाङ्क print_generic, वर्ण * ध्रुव *opts, आकार_t nopts)
{
	संरचना sshkey *सार्वजनिक;
	वर्ण *comment = रिक्त;
	ध्रुव वर्ण *p;
	संरचना stat st;
	पूर्णाङ्क r, hash = -1;
	आकार_t i;

	प्रति (i = 0; i < nopts; i++) {
		यदि ((p = strprefix(opts[i], "hashalg=", 1)) != रिक्त) {
			यदि ((hash = ssh_digest_alg_by_name(p)) == -1)
				fatal("Unsupported hash algorithm");
		} अन्यथा {
			error("Invalid option \"%s\"", opts[i]);
			प्रत्यागम SSH_ERR_INVALID_तर्कः;
		}
	}
	यदि (fname == रिक्त)
		fatal_f("no filename");
	यदि (stat(fname, &st) == -1) {
		यदि (errno == ENOENT)
			प्रत्यागम 0;
		fatal("%s: %s", fname, strerror(errno));
	}
	यदि ((r = sshkey_आरोपय_लौकिकम्(fname, &सार्वजनिक, &comment)) != 0)
		fatal_r(r, "Failed to read v2 public key from \"%s\"", fname);
	export_dns_rr(hname, सार्वजनिक, stdout, print_generic, hash);
	sshkey_free(सार्वजनिक);
	मुक्त(comment);
	प्रत्यागम 1;
}

/*
 * Change the comment of a private key file.
 */
स्थिर शून्य
do_change_comment(संरचना passwd *pw, ध्रुव वर्ण *तटस्थः_comment)
{
	वर्ण new_comment[कुञ्चिका_COMMENT_MAX], *comment, *passphrase;
	संरचना sshkey *गुप्त;
	संरचना sshkey *सार्वजनिक;
	संरचना stat st;
	पूर्णाङ्क r;

	यदि (!have_तटस्थः)
		ask_filename(pw, "Enter file in which the key is");
	यदि (stat(तटस्थः_file, &st) == -1)
		fatal("%s: %s", तटस्थः_file, strerror(errno));
	यदि ((r = sshkey_आरोपय_वैयक्तिकम्(तटस्थः_file, "",
	    &गुप्त, &comment)) == 0)
		passphrase = xstrdup("");
	अन्यथा यदि (r != SSH_ERR_कुञ्चिका_WRONG_PASSPHRASE)
		fatal_r(r, "Cannot load private key \"%s\"", तटस्थः_file);
	अन्यथा {
		यदि (तटस्थः_passphrase)
			passphrase = xstrdup(तटस्थः_passphrase);
		अन्यथा यदि (तटस्थः_new_passphrase)
			passphrase = xstrdup(तटस्थः_new_passphrase);
		अन्यथा
			passphrase = read_passphrase("Enter passphrase: ",
			    RP_ALLOW_STDIN);
		/* Try to load using the passphrase. */
		यदि ((r = sshkey_आरोपय_वैयक्तिकम्(तटस्थः_file, passphrase,
		    &गुप्त, &comment)) != 0) {
			freezero(passphrase, वाक्यदैर्घ्यम्(passphrase));
			fatal_r(r, "Cannot load private key \"%s\"",
			    तटस्थः_file);
		}
	}

	यदि (गुप्त->type != कुञ्चिका_ED25519 &&
	    वैयक्तिकम्_कुञ्चिका_format != SSHKEY_वैयक्तिकम्_OPENSSH) {
		error("Comments are only supported for keys stored in "
		    "the new format (-o).");
		explicit_bzero(passphrase, वाक्यदैर्घ्यम्(passphrase));
		sshkey_free(गुप्त);
		निर्गच्छ(1);
	}
	यदि (comment)
		प्रारूप_लिख("Old comment: %s\n", comment);
	अन्यथा
		प्रारूप_लिख("No existing comment\n");

	यदि (तटस्थः_comment) {
		strlcpy(new_comment, तटस्थः_comment, परिमाण(new_comment));
	} अन्यथा {
		प्रारूप_लिख("New comment: ");
		fflush(stdout);
		यदि (!fgets(new_comment, परिमाण(new_comment), stdin)) {
			explicit_bzero(passphrase, वाक्यदैर्घ्यम्(passphrase));
			sshkey_free(गुप्त);
			निर्गच्छ(1);
		}
		new_comment[strcspn(new_comment, "\n")] = '\0';
	}
	यदि (comment != रिक्त && वाक्यं_तुलय(comment, new_comment) == 0) {
		प्रारूप_लिख("No change to comment\n");
		मुक्त(passphrase);
		sshkey_free(गुप्त);
		मुक्त(comment);
		निर्गच्छ(0);
	}

	/* Save the file using the new passphrase. */
	यदि ((r = sshkey_save_वैयक्तिकम्(गुप्त, तटस्थः_file, passphrase,
	    new_comment, वैयक्तिकम्_कुञ्चिका_format, openssh_format_cipher,
	    आवर्तनानि)) != 0) {
		error_r(r, "Saving key \"%s\" failed", तटस्थः_file);
		freezero(passphrase, वाक्यदैर्घ्यम्(passphrase));
		sshkey_free(गुप्त);
		मुक्त(comment);
		निर्गच्छ(1);
	}
	freezero(passphrase, वाक्यदैर्घ्यम्(passphrase));
	यदि ((r = sshkey_from_वैयक्तिकम्(गुप्त, &सार्वजनिक)) != 0)
		fatal_fr(r, "sshkey_from_private");
	sshkey_free(गुप्त);

	strlcat(तटस्थः_file, ".pub", परिमाण(तटस्थः_file));
	यदि ((r = sshkey_save_लौकिकम्(सार्वजनिक, तटस्थः_file, new_comment)) != 0)
		fatal_r(r, "Unable to save public key to %s", तटस्थः_file);
	sshkey_free(सार्वजनिक);
	मुक्त(comment);

	यदि (वाक्यदैर्घ्यम्(new_comment) > 0)
		प्रारूप_लिख("Comment '%s' applied\n", new_comment);
	अन्यथा
		प्रारूप_लिख("Comment removed\n");

	निर्गच्छ(0);
}

स्थिर शून्य
cert_ext_सङ्कलय(ध्रुव वर्ण *कुञ्चिका, ध्रुव वर्ण *मानम्, पूर्णाङ्क iscrit)
{
	cert_ext = xreallocarray(cert_ext, ncert_ext + 1, परिमाण(*cert_ext));
	cert_ext[ncert_ext].कुञ्चिका = xstrdup(कुञ्चिका);
	cert_ext[ncert_ext].val = मानम् == रिक्त ? रिक्त : xstrdup(मानम्);
	cert_ext[ncert_ext].crit = iscrit;
	ncert_ext++;
}

/* qsort(3) comparison function for certificate extensions */
स्थिर पूर्णाङ्क
cert_ext_cmp(ध्रुव शून्य *_a, ध्रुव शून्य *_b)
{
	ध्रुव संरचना cert_ext *a = (ध्रुव संरचना cert_ext *)_a;
	ध्रुव संरचना cert_ext *b = (ध्रुव संरचना cert_ext *)_b;
	पूर्णाङ्क r;

	यदि (a->crit != b->crit)
		प्रत्यागम (a->crit < b->crit) ? -1 : 1;
	यदि ((r = वाक्यं_तुलय(a->कुञ्चिका, b->कुञ्चिका)) != 0)
		प्रत्यागम r;
	यदि ((a->val == रिक्त) != (b->val == रिक्त))
		प्रत्यागम (a->val == रिक्त) ? -1 : 1;
	यदि (a->val != रिक्त && (r = वाक्यं_तुलय(a->val, b->val)) != 0)
		प्रत्यागम r;
	प्रत्यागम 0;
}

#परिभाषय OPTIONS_CRITICAL	1
#परिभाषय OPTIONS_EXTENSIONS	2
स्थिर शून्य
prepare_options_buf(संरचना sshbuf *c, पूर्णाङ्क which)
{
	संरचना sshbuf *b;
	आकार_t i;
	पूर्णाङ्क r;
	ध्रुव संरचना cert_ext *ext;

	यदि ((b = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	sshbuf_reset(c);
	प्रति (i = 0; i < ncert_ext; i++) {
		ext = &cert_ext[i];
		यदि ((ext->crit && (which & OPTIONS_EXTENSIONS)) ||
		    (!ext->crit && (which & OPTIONS_CRITICAL)))
			अनुवर्त;
		यदि (ext->val == रिक्त) {
			/* flag option */
			debug3_f("%s", ext->कुञ्चिका);
			यदि ((r = sshbuf_put_cstring(c, ext->कुञ्चिका)) != 0 ||
			    (r = sshbuf_put_string(c, रिक्त, 0)) != 0)
				fatal_fr(r, "prepare flag");
		} अन्यथा {
			/* key/value option */
			debug3_f("%s=%s", ext->कुञ्चिका, ext->val);
			sshbuf_reset(b);
			यदि ((r = sshbuf_put_cstring(c, ext->कुञ्चिका)) != 0 ||
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
		cert_ext_सङ्कलय("force-command", certflags_command, 1);
	यदि (certflags_src_addr != रिक्त)
		cert_ext_सङ्कलय("source-address", certflags_src_addr, 1);
	यदि ((certflags_flags & CERTOPT_REQUIRE_VERIFY) != 0)
		cert_ext_सङ्कलय("verify-required", रिक्त, 1);
	/* extensions */
	यदि ((certflags_flags & CERTOPT_X_FWD) != 0)
		cert_ext_सङ्कलय("permit-X11-forwarding", रिक्त, 0);
	यदि ((certflags_flags & CERTOPT_AGENT_FWD) != 0)
		cert_ext_सङ्कलय("permit-agent-forwarding", रिक्त, 0);
	यदि ((certflags_flags & CERTOPT_पत्तनम्_FWD) != 0)
		cert_ext_सङ्कलय("permit-port-forwarding", रिक्त, 0);
	यदि ((certflags_flags & CERTOPT_PTY) != 0)
		cert_ext_सङ्कलय("permit-pty", रिक्त, 0);
	यदि ((certflags_flags & CERTOPT_USER_RC) != 0)
		cert_ext_सङ्कलय("permit-user-rc", रिक्त, 0);
	यदि ((certflags_flags & CERTOPT_NO_REQUIRE_USER_PRESENCE) != 0)
		cert_ext_सङ्कलय("no-touch-required", रिक्त, 0);
	/* order lexically by key */
	यदि (ncert_ext > 0)
		शीघ्रं_क्रमय(cert_ext, ncert_ext, परिमाण(*cert_ext), cert_ext_cmp);
}

स्थिर संरचना sshkey *
आरोपय_pkcs11_कुञ्चिका(वर्ण *मार्गः)
{
#यदि_परिभाषितम् ENABLE_PKCS11
	संरचना sshkey **कुञ्चिकाः = रिक्त, *सार्वजनिक, *गुप्त = रिक्त;
	पूर्णाङ्क r, i, nkeys;

	यदि ((r = sshkey_आरोपय_लौकिकम्(मार्गः, &सार्वजनिक, रिक्त)) != 0)
		fatal_r(r, "Couldn't load CA public key \"%s\"", मार्गः);

	nkeys = pkcs11_सङ्कलय_provider(pkcs11provider, तटस्थः_passphrase,
	    &कुञ्चिकाः, रिक्त);
	debug3_f("%d keys", nkeys);
	यदि (nkeys <= 0)
		fatal("cannot read public key from pkcs11");
	प्रति (i = 0; i < nkeys; i++) {
		यदि (sshkey_equal_लौकिकम्(सार्वजनिक, कुञ्चिकाः[i])) {
			गुप्त = कुञ्चिकाः[i];
			अनुवर्त;
		}
		sshkey_free(कुञ्चिकाः[i]);
	}
	मुक्त(कुञ्चिकाः);
	sshkey_free(सार्वजनिक);
	प्रत्यागम गुप्त;
#अन्यथा
	fatal("no pkcs11 support");
#यदि_अन्तः /* ENABLE_PKCS11 */
}

/* Signer for sshkey_certify_custom that uses the agent */
स्थिर पूर्णाङ्क
agent_signer(संरचना sshkey *कुञ्चिका, u_char **sigp, आकार_t *lenp,
    ध्रुव u_char *दत्त, आकार_t datalen,
    ध्रुव वर्ण *alg, ध्रुव वर्ण *provider, ध्रुव वर्ण *pin,
    u_int compat, शून्य *ctx)
{
	पूर्णाङ्क *agent_fdp = (पूर्णाङ्क *)ctx;

	प्रत्यागम ssh_agent_sign(*agent_fdp, कुञ्चिका, sigp, lenp,
	    दत्त, datalen, alg, compat);
}

स्थिर शून्य
do_ca_sign(संरचना passwd *pw, ध्रुव वर्ण *ca_कुञ्चिका_मार्गः, पूर्णाङ्क prefer_agent,
    अचिह्नित दीर्घ दीर्घ cert_serial, पूर्णाङ्क cert_serial_autoinc,
    पूर्णाङ्क argc, वर्ण **argv)
{
	पूर्णाङ्क r, i, कुञ्चिका_अन्तर्_agent = 0, agent_fd = -1;
	u_int n;
	संरचना sshkey *ca, *सार्वजनिक;
	वर्ण valid[64], *otmp, *tmp, *cp, *बहिर्गमनम्, *comment;
	वर्ण *ca_fp = रिक्त, **plist = रिक्त, *pin = रिक्त;
	संरचना ssh_identitylist *agent_ids;
	आकार_t j;
	संरचना notifier_ctx *notifier = रिक्त;

#यदि_परिभाषितम् ENABLE_PKCS11
	pkcs11_init(1);
#यदि_अन्तः
	tmp = tilde_expand_filename(ca_कुञ्चिका_मार्गः, pw->pw_uid);
	यदि (pkcs11provider != रिक्त) {
		/* If a PKCS#11 token was specified then try to use it */
		यदि ((ca = आरोपय_pkcs11_कुञ्चिका(tmp)) == रिक्त)
			fatal("No PKCS#11 key matching %s found", ca_कुञ्चिका_मार्गः);
	} अन्यथा यदि (prefer_agent) {
		/*
		 * Agent signature requested. Try to use agent after making
		 * sure the public key specified is actually present in the
		 * agent.
		 */
		यदि ((r = sshkey_आरोपय_लौकिकम्(tmp, &ca, रिक्त)) != 0)
			fatal_r(r, "Cannot load CA public key %s", tmp);
		यदि ((r = ssh_get_authentication_socket(&agent_fd)) != 0)
			fatal_r(r, "Cannot use public key for CA signature");
		यदि ((r = ssh_fetch_identitylist(agent_fd, &agent_ids)) != 0)
			fatal_r(r, "Retrieve agent key list");
		प्रति (j = 0; j < agent_ids->nkeys; j++) {
			यदि (sshkey_equal(ca, agent_ids->कुञ्चिकाः[j])) {
				कुञ्चिका_अन्तर्_agent = 1;
				/* Replace the CA key with the agent one */
				sshkey_free(ca);
				ca = agent_ids->कुञ्चिकाः[j];
				agent_ids->कुञ्चिकाः[j] = रिक्त;
				भङ्ग;
			}
		}
		यदि (!कुञ्चिका_अन्तर्_agent)
			fatal("CA key %s not found in agent", tmp);
		ssh_free_identitylist(agent_ids);
	} अन्यथा {
		/* CA key is assumed to be a private key on the filesystem */
		ca = आरोपय_तटस्थः(tmp, रिक्त);
		यदि (sshkey_is_sk(ca) &&
		    (ca->sk_flags & SSH_SK_USER_VERIFICATION_REQD)) {
			यदि ((pin = read_passphrase("Enter PIN for CA key: ",
			    RP_ALLOW_STDIN)) == रिक्त)
				fatal_f("couldn't read PIN");
		}
	}
	मुक्त(tmp);

	यदि (कुञ्चिका_type_name != रिक्त) {
		यदि (sshkey_type_from_shortname(कुञ्चिका_type_name) != ca->type) {
			fatal("CA key type %s doesn't match specified %s",
			    sshkey_ssh_name(ca), कुञ्चिका_type_name);
		}
	} अन्यथा यदि (ca->type == कुञ्चिका_RSA) {
		/* Default to a good signature algorithm */
		कुञ्चिका_type_name = "rsa-sha2-512";
	}
	ca_fp = sshkey_fingerprint(ca, fingerprint_hash, SSH_FP_DEFAULT);

	finalise_cert_exts();
	प्रति (i = 0; i < argc; i++) {
		/* Split list of principals */
		n = 0;
		यदि (cert_principals != रिक्त) {
			otmp = tmp = xstrdup(cert_principals);
			plist = रिक्त;
			प्रति (; (cp = strsep(&tmp, ",")) != रिक्त; n++) {
				plist = xreallocarray(plist, n + 1, परिमाण(*plist));
				यदि (*(plist[n] = xstrdup(cp)) == '\0')
					fatal("Empty principal name");
			}
			मुक्त(otmp);
		}
		यदि (n > SSHKEY_CERT_MAX_PRINCIPALS)
			fatal("Too many certificate principals specified");

		tmp = tilde_expand_filename(argv[i], pw->pw_uid);
		यदि ((r = sshkey_आरोपय_लौकिकम्(tmp, &सार्वजनिक, &comment)) != 0)
			fatal_r(r, "load pubkey \"%s\"", tmp);
		यदि (sshkey_is_cert(सार्वजनिक))
			fatal_f("key \"%s\" type %s cannot be certified",
			    tmp, sshkey_type(सार्वजनिक));

		/* Prepare certificate to sign */
		यदि ((r = sshkey_गन्तव्यम्_certified(सार्वजनिक)) != 0)
			fatal_r(r, "Could not upgrade key %s to certificate", tmp);
		सार्वजनिक->cert->type = cert_कुञ्चिका_type;
		सार्वजनिक->cert->serial = (uint64_t)cert_serial;
		सार्वजनिक->cert->कुञ्चिका_id = xstrdup(cert_कुञ्चिका_id);
		सार्वजनिक->cert->nprincipals = n;
		सार्वजनिक->cert->principals = plist;
		सार्वजनिक->cert->valid_after = cert_valid_from;
		सार्वजनिक->cert->valid_before = cert_valid_गन्तव्यम्;
		prepare_options_buf(सार्वजनिक->cert->critical, OPTIONS_CRITICAL);
		prepare_options_buf(सार्वजनिक->cert->extensions,
		    OPTIONS_EXTENSIONS);
		यदि ((r = sshkey_from_वैयक्तिकम्(ca,
		    &सार्वजनिक->cert->signature_कुञ्चिका)) != 0)
			fatal_r(r, "sshkey_from_private (ca key)");

		यदि (कुञ्चिका_अन्तर्_agent) {
			यदि ((r = sshkey_certify_custom(सार्वजनिक, ca,
			    कुञ्चिका_type_name, sk_provider, रिक्त, agent_signer,
			    &agent_fd)) != 0)
				fatal_r(r, "Couldn't certify %s via agent", tmp);
		} अन्यथा {
			यदि (sshkey_is_sk(ca) &&
			    (ca->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
				notifier = notify_start(0,
				    "Confirm user presence for key %s %s",
				    sshkey_type(ca), ca_fp);
			}
			r = sshkey_certify(सार्वजनिक, ca, कुञ्चिका_type_name,
			    sk_provider, pin);
			notify_complete(notifier, "User presence confirmed");
			यदि (r != 0)
				fatal_r(r, "Couldn't certify key %s", tmp);
		}

		यदि ((cp = strrchr(tmp, '.')) != रिक्त && वाक्यं_तुलय(cp, ".pub") == 0)
			*cp = '\0';
		xasprintf(&बहिर्गमनम्, "%s-cert.pub", tmp);
		मुक्त(tmp);

		यदि ((r = sshkey_save_लौकिकम्(सार्वजनिक, बहिर्गमनम्, comment)) != 0) {
			fatal_r(r, "Unable to save public key to %s",
			    तटस्थः_file);
		}

		यदि (!quiet) {
			sshkey_format_cert_validity(सार्वजनिक->cert,
			    valid, परिमाण(valid));
			logit("Signed %s key %s: id \"%s\" serial %llu%s%s "
			    "valid %s", sshkey_cert_type(सार्वजनिक),
			    बहिर्गमनम्, सार्वजनिक->cert->कुञ्चिका_id,
			    (अचिह्नित दीर्घ दीर्घ)सार्वजनिक->cert->serial,
			    cert_principals != रिक्त ? " for " : "",
			    cert_principals != रिक्त ? cert_principals : "",
			    valid);
		}

		sshkey_free(सार्वजनिक);
		मुक्त(बहिर्गमनम्);
		मुक्त(comment);
		यदि (cert_serial_autoinc)
			cert_serial++;
	}
	यदि (pin != रिक्त)
		freezero(pin, वाक्यदैर्घ्यम्(pin));
	sshkey_free(ca);
	मुक्त(ca_fp);
#यदि_परिभाषितम् ENABLE_PKCS11
	pkcs11_terminate();
#यदि_अन्तः
}

स्थिर uint64_t
parse_relative_time(ध्रुव वर्ण *s, time_t now)
{
	int64_t mul, secs;

	mul = *s == '-' ? -1 : 1;

	यदि ((secs = convtime(s + 1)) == -1)
		fatal("Invalid relative certificate time %s", s);
	यदि (mul == -1 && secs > now)
		fatal("Certificate time %s cannot be represented", s);
	प्रत्यागम now + (uint64_t)(secs * mul);
}

स्थिर शून्य
parse_hex_u64(ध्रुव वर्ण *s, uint64_t *ऊर्ध्वम्)
{
	वर्ण *ep;
	अचिह्नित दीर्घ दीर्घ ull;

	errno = 0;
	ull = strtoull(s, &ep, 16);
	यदि (*s == '\0' || *ep != '\0')
		fatal("Invalid certificate time: not a number");
	यदि (errno == ERANGE && ull == ULONG_MAX)
		fatal_fr(SSH_ERR_SYSTEM_ERROR, "Invalid certificate time");
	*ऊर्ध्वम् = (uint64_t)ull;
}

स्थिर शून्य
parse_cert_times(वर्ण *timespec)
{
	वर्ण *from, *गन्तव्यम्;
	time_t now = time(रिक्त);
	int64_t secs;

	/* +timespec relative to now */
	यदि (*timespec == '+' && strchr(timespec, ':') == रिक्त) {
		यदि ((secs = convtime(timespec + 1)) == -1)
			fatal("Invalid relative certificate life %s", timespec);
		cert_valid_गन्तव्यम् = now + secs;
		/*
		 * Backdate certificate one minute to avoid problems on hosts
		 * with poorly-synchronised clocks.
		 */
		cert_valid_from = ((now - 59)/ 60) * 60;
		प्रत्यागम;
	}

	/*
	 * from:to, where
	 * from := [+-]timespec | YYYYMMDD | YYYYMMDDHHMMSS | 0x... | "always"
	 *   to := [+-]timespec | YYYYMMDD | YYYYMMDDHHMMSS | 0x... | "forever"
	 */
	from = xstrdup(timespec);
	गन्तव्यम् = strchr(from, ':');
	यदि (गन्तव्यम् == रिक्त || from == गन्तव्यम् || *(गन्तव्यम् + 1) == '\0')
		fatal("Invalid certificate life specification %s", timespec);
	*गन्तव्यम्++ = '\0';

	यदि (*from == '-' || *from == '+')
		cert_valid_from = parse_relative_time(from, now);
	अन्यथा यदि (वाक्यं_तुलय(from, "always") == 0)
		cert_valid_from = 0;
	अन्यथा यदि (वाक्ये_तुलय(from, "0x", 2) == 0)
		parse_hex_u64(from, &cert_valid_from);
	अन्यथा यदि (parse_absolute_time(from, &cert_valid_from) != 0)
		fatal("Invalid from time \"%s\"", from);

	यदि (*गन्तव्यम् == '-' || *गन्तव्यम् == '+')
		cert_valid_गन्तव्यम् = parse_relative_time(गन्तव्यम्, now);
	अन्यथा यदि (वाक्यं_तुलय(गन्तव्यम्, "forever") == 0)
		cert_valid_गन्तव्यम् = ~(uint64_t)0;
	अन्यथा यदि (वाक्ये_तुलय(गन्तव्यम्, "0x", 2) == 0)
		parse_hex_u64(गन्तव्यम्, &cert_valid_गन्तव्यम्);
	अन्यथा यदि (parse_absolute_time(गन्तव्यम्, &cert_valid_गन्तव्यम्) != 0)
		fatal("Invalid to time \"%s\"", गन्तव्यम्);

	यदि (cert_valid_गन्तव्यम् <= cert_valid_from)
		fatal("Empty certificate validity interval");
	मुक्त(from);
}

स्थिर शून्य
सङ्कलय_cert_option(वर्ण *opt)
{
	वर्ण *val, *cp;
	ध्रुव वर्ण *p;
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
		certflags_flags &= ~CERTOPT_पत्तनम्_FWD;
	अन्यथा यदि (strcasecmp(opt, "permit-port-forwarding") == 0)
		certflags_flags |= CERTOPT_पत्तनम्_FWD;
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
		यदि (addr_मेलनम्_cidr_list(रिक्त, p) != 0)
			fatal("Invalid source-address list");
		certflags_src_addr = xstrdup(p);
	} अन्यथा यदि (strprefix(opt, "extension:", 1) != रिक्त ||
		    (iscrit = (strprefix(opt, "critical:", 1) != रिक्त))) {
		val = xstrdup(strchr(opt, ':') + 1);
		यदि ((cp = strchr(val, '=')) != रिक्त)
			*cp++ = '\0';
		cert_ext_सङ्कलय(val, cp, iscrit);
		मुक्त(val);
	} अन्यथा
		fatal("Unsupported certificate option \"%s\"", opt);
}

स्थिर शून्य
show_options(संरचना sshbuf *optbuf, पूर्णाङ्क अन्तर्_critical)
{
	वर्ण *name, *arg, *hex;
	संरचना sshbuf *options, *option = रिक्त;
	पूर्णाङ्क r;

	यदि ((options = sshbuf_fromb(optbuf)) == रिक्त)
		fatal_f("sshbuf_fromb failed");
	यावत् (sshbuf_len(options) != 0) {
		sshbuf_free(option);
		option = रिक्त;
		यदि ((r = sshbuf_get_cstring(options, &name, रिक्त)) != 0 ||
		    (r = sshbuf_froms(options, &option)) != 0)
			fatal_fr(r, "parse option");
		प्रारूप_लिख("                %s", name);
		यदि (!अन्तर्_critical &&
		    (वाक्यं_तुलय(name, "permit-X11-forwarding") == 0 ||
		    वाक्यं_तुलय(name, "permit-agent-forwarding") == 0 ||
		    वाक्यं_तुलय(name, "permit-port-forwarding") == 0 ||
		    वाक्यं_तुलय(name, "permit-pty") == 0 ||
		    वाक्यं_तुलय(name, "permit-user-rc") == 0 ||
		    वाक्यं_तुलय(name, "no-touch-required") == 0)) {
			प्रारूप_लिख("\n");
		} अन्यथा यदि (अन्तर्_critical &&
		    (वाक्यं_तुलय(name, "force-command") == 0 ||
		    वाक्यं_तुलय(name, "source-address") == 0)) {
			यदि ((r = sshbuf_get_cstring(option, &arg, रिक्त)) != 0)
				fatal_fr(r, "parse critical");
			प्रारूप_लिख(" %s\n", arg);
			मुक्त(arg);
		} अन्यथा यदि (अन्तर्_critical &&
		    वाक्यं_तुलय(name, "verify-required") == 0) {
			प्रारूप_लिख("\n");
		} अन्यथा यदि (sshbuf_len(option) > 0) {
			hex = sshbuf_dtob16(option);
			प्रारूप_लिख(" UNKNOWN OPTION: %s (len %zu)\n",
			    hex, sshbuf_len(option));
			sshbuf_reset(option);
			मुक्त(hex);
		} अन्यथा
			प्रारूप_लिख(" UNKNOWN FLAG OPTION\n");
		मुक्त(name);
		यदि (sshbuf_len(option) != 0)
			fatal("Option corrupt: extra data at end");
	}
	sshbuf_free(option);
	sshbuf_free(options);
}

स्थिर शून्य
print_cert(संरचना sshkey *कुञ्चिका)
{
	वर्ण valid[64], *कुञ्चिका_fp, *ca_fp;
	u_int i;

	कुञ्चिका_fp = sshkey_fingerprint(कुञ्चिका, fingerprint_hash, SSH_FP_DEFAULT);
	ca_fp = sshkey_fingerprint(कुञ्चिका->cert->signature_कुञ्चिका,
	    fingerprint_hash, SSH_FP_DEFAULT);
	यदि (कुञ्चिका_fp == रिक्त || ca_fp == रिक्त)
		fatal_f("sshkey_fingerprint fail");
	sshkey_format_cert_validity(कुञ्चिका->cert, valid, परिमाण(valid));

	प्रारूप_लिख("        Type: %s %s certificate\n", sshkey_ssh_name(कुञ्चिका),
	    sshkey_cert_type(कुञ्चिका));
	प्रारूप_लिख("        Public key: %s %s\n", sshkey_type(कुञ्चिका), कुञ्चिका_fp);
	प्रारूप_लिख("        Signing CA: %s %s (using %s)\n",
	    sshkey_type(कुञ्चिका->cert->signature_कुञ्चिका), ca_fp,
	    कुञ्चिका->cert->signature_type);
	प्रारूप_लिख("        Key ID: \"%s\"\n", कुञ्चिका->cert->कुञ्चिका_id);
	प्रारूप_लिख("        Serial: %llu\n", (अचिह्नित दीर्घ दीर्घ)कुञ्चिका->cert->serial);
	प्रारूप_लिख("        Valid: %s\n", valid);
	प्रारूप_लिख("        Principals: ");
	यदि (कुञ्चिका->cert->nprincipals == 0)
		प्रारूप_लिख("(none)\n");
	अन्यथा {
		प्रति (i = 0; i < कुञ्चिका->cert->nprincipals; i++)
			प्रारूप_लिख("\n                %s",
			    कुञ्चिका->cert->principals[i]);
		प्रारूप_लिख("\n");
	}
	प्रारूप_लिख("        Critical Options: ");
	यदि (sshbuf_len(कुञ्चिका->cert->critical) == 0)
		प्रारूप_लिख("(none)\n");
	अन्यथा {
		प्रारूप_लिख("\n");
		show_options(कुञ्चिका->cert->critical, 1);
	}
	प्रारूप_लिख("        Extensions: ");
	यदि (sshbuf_len(कुञ्चिका->cert->extensions) == 0)
		प्रारूप_लिख("(none)\n");
	अन्यथा {
		प्रारूप_लिख("\n");
		show_options(कुञ्चिका->cert->extensions, 0);
	}
	मुक्त(कुञ्चिका_fp);
	मुक्त(ca_fp);
}

स्थिर शून्य
do_show_cert(संरचना passwd *pw)
{
	संरचना sshkey *कुञ्चिका = रिक्त;
	संरचना stat st;
	पूर्णाङ्क r, is_stdin = 0, ok = 0;
	FILE *f;
	वर्ण *cp, *पङ्क्तिः = रिक्त;
	ध्रुव वर्ण *मार्गः;
	आकार_t linesize = 0;
	u_long lnum = 0;

	यदि (!have_तटस्थः)
		ask_filename(pw, "Enter file in which the key is");
	यदि (वाक्यं_तुलय(तटस्थः_file, "-") != 0 && stat(तटस्थः_file, &st) == -1)
		fatal("%s: %s: %s", __progname, तटस्थः_file, strerror(errno));

	मार्गः = तटस्थः_file;
	यदि (वाक्यं_तुलय(मार्गः, "-") == 0) {
		f = stdin;
		मार्गः = "(stdin)";
		is_stdin = 1;
	} अन्यथा यदि ((f = fopen(तटस्थः_file, "r")) == रिक्त)
		fatal("fopen %s: %s", तटस्थः_file, strerror(errno));

	यावत् (getline(&पङ्क्तिः, &linesize, f) != -1) {
		lnum++;
		sshkey_free(कुञ्चिका);
		कुञ्चिका = रिक्त;
		/* Trim leading space and comments */
		cp = पङ्क्तिः + strspn(पङ्क्तिः, " \t");
		यदि (*cp == '#' || *cp == '\0')
			अनुवर्त;
		यदि ((कुञ्चिका = sshkey_new(कुञ्चिका_UNSPEC)) == रिक्त)
			fatal("sshkey_new");
		यदि ((r = sshkey_read(कुञ्चिका, &cp)) != 0) {
			error_r(r, "%s:%lu: invalid key", मार्गः, lnum);
			अनुवर्त;
		}
		यदि (!sshkey_is_cert(कुञ्चिका)) {
			error("%s:%lu is not a certificate", मार्गः, lnum);
			अनुवर्त;
		}
		ok = 1;
		यदि (!is_stdin && lnum == 1)
			प्रारूप_लिख("%s:\n", मार्गः);
		अन्यथा
			प्रारूप_लिख("%s:%lu:\n", मार्गः, lnum);
		print_cert(कुञ्चिका);
	}
	मुक्त(पङ्क्तिः);
	sshkey_free(कुञ्चिका);
	fclose(f);
	निर्गच्छ(ok ? 0 : 1);
}

स्थिर शून्य
आरोपय_krl(ध्रुव वर्ण *मार्गः, संरचना ssh_krl **krlp)
{
	संरचना sshbuf *krlbuf;
	पूर्णाङ्क r;

	यदि ((r = sshbuf_आरोपय_file(मार्गः, &krlbuf)) != 0)
		fatal_r(r, "Unable to load KRL %s", मार्गः);
	/* XXX check sigs */
	यदि ((r = ssh_krl_from_blob(krlbuf, krlp)) != 0 ||
	    *krlp == रिक्त)
		fatal_r(r, "Invalid KRL file %s", मार्गः);
	sshbuf_free(krlbuf);
}

स्थिर शून्य
hash_गन्तव्यम्_blob(ध्रुव वर्ण *cp, u_char **blobp, आकार_t *lenp,
    ध्रुव वर्ण *file, u_long lnum)
{
	वर्ण *tmp;
	आकार_t tlen;
	संरचना sshbuf *b;
	पूर्णाङ्क r;

	यदि ((cp = strprefix(cp, "SHA256:", 0)) == रिक्त)
		fatal("%s:%lu: unsupported hash algorithm", file, lnum);

	/*
	 * OpenSSH base64 hashes omit trailing '='
	 * characters; put them back for decode.
	 */
	यदि ((tlen = वाक्यदैर्घ्यम्(cp)) >= SIZE_MAX - 5)
		fatal_f("hash too long: %zu bytes", tlen);
	tmp = xmalloc(tlen + 4 + 1);
	strlcpy(tmp, cp, tlen + 1);
	यावत् ((tlen % 4) != 0) {
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
	स्मृतिं_प्रतिलिख(*blobp, sshbuf_ptr(b), *lenp);
	sshbuf_free(b);
}

स्थिर शून्य
update_krl_from_file(संरचना passwd *pw, ध्रुव वर्ण *file, पूर्णाङ्क wild_ca,
    ध्रुव संरचना sshkey *ca, संरचना ssh_krl *krl)
{
	संरचना sshkey *कुञ्चिका = रिक्त;
	u_long lnum = 0;
	वर्ण *मार्गः, *cp, *ep, *पङ्क्तिः = रिक्त;
	u_char *blob = रिक्त;
	आकार_t blen = 0, linesize = 0;
	अचिह्नित दीर्घ दीर्घ serial, serial2;
	पूर्णाङ्क i, was_explicit_कुञ्चिका, was_sha1, was_sha256, was_hash, r;
	FILE *krl_spec;

	मार्गः = tilde_expand_filename(file, pw->pw_uid);
	यदि (वाक्यं_तुलय(मार्गः, "-") == 0) {
		krl_spec = stdin;
		मुक्त(मार्गः);
		मार्गः = xstrdup("(standard input)");
	} अन्यथा यदि ((krl_spec = fopen(मार्गः, "r")) == रिक्त)
		fatal("fopen %s: %s", मार्गः, strerror(errno));

	यदि (!quiet)
		प्रारूप_लिख("Revoking from %s\n", मार्गः);
	यावत् (getline(&पङ्क्तिः, &linesize, krl_spec) != -1) {
		यदि (linesize >= अधिकतम_पूर्णाङ्कः) {
			fatal_f("%s contains unparsable line, len=%zu",
			    मार्गः, linesize);
		}
		lnum++;
		was_explicit_कुञ्चिका = was_sha1 = was_sha256 = was_hash = 0;
		cp = पङ्क्तिः + strspn(पङ्क्तिः, " \t");
		/* Trim trailing space, comments and strip \n */
		प्रति (i = 0, r = -1; cp[i] != '\0'; i++) {
			यदि (cp[i] == '#' || cp[i] == '\n') {
				cp[i] = '\0';
				भङ्ग;
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
			अनुवर्त;
		यदि (strncasecmp(cp, "serial:", 7) == 0) {
			यदि (ca == रिक्त && !wild_ca) {
				fatal("revoking certificates by serial number "
				    "requires specification of a CA key");
			}
			cp += 7;
			cp = cp + strspn(cp, " \t");
			errno = 0;
			serial = strtoull(cp, &ep, 0);
			यदि (*cp == '\0' || (*ep != '\0' && *ep != '-'))
				fatal("%s:%lu: invalid serial \"%s\"",
				    मार्गः, lnum, cp);
			यदि (errno == ERANGE && serial == ULLONG_MAX)
				fatal("%s:%lu: serial out of range",
				    मार्गः, lnum);
			serial2 = serial;
			यदि (*ep == '-') {
				cp = ep + 1;
				errno = 0;
				serial2 = strtoull(cp, &ep, 0);
				यदि (*cp == '\0' || *ep != '\0')
					fatal("%s:%lu: invalid serial \"%s\"",
					    मार्गः, lnum, cp);
				यदि (errno == ERANGE && serial2 == ULLONG_MAX)
					fatal("%s:%lu: serial out of range",
					    मार्गः, lnum);
				यदि (serial2 <= serial)
					fatal("%s:%lu: invalid serial range "
					    "%llu:%llu", मार्गः, lnum,
					    (अचिह्नित दीर्घ दीर्घ)serial,
					    (अचिह्नित दीर्घ दीर्घ)serial2);
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
			cp = cp + strspn(cp, " \t");
			यदि (ssh_krl_revoke_cert_by_कुञ्चिका_id(krl, ca, cp) != 0)
				fatal_f("revoke key ID failed");
		} अन्यथा यदि (strncasecmp(cp, "hash:", 5) == 0) {
			cp += 5;
			cp = cp + strspn(cp, " \t");
			hash_गन्तव्यम्_blob(cp, &blob, &blen, file, lnum);
			यदि ((r = ssh_krl_revoke_कुञ्चिका_sha256(krl,
			    blob, blen)) != 0)
				fatal_fr(r, "revoke key failed");
			मुक्त(blob);
			blob = रिक्त;
			blen = 0;
		} अन्यथा {
			यदि (strncasecmp(cp, "key:", 4) == 0) {
				cp += 4;
				cp = cp + strspn(cp, " \t");
				was_explicit_कुञ्चिका = 1;
			} अन्यथा यदि (strncasecmp(cp, "sha1:", 5) == 0) {
				cp += 5;
				cp = cp + strspn(cp, " \t");
				was_sha1 = 1;
			} अन्यथा यदि (strncasecmp(cp, "sha256:", 7) == 0) {
				cp += 7;
				cp = cp + strspn(cp, " \t");
				was_sha256 = 1;
				/*
				 * Just try to process the line as a key.
				 * Parsing will fail if it isn't.
				 */
			}
			यदि ((कुञ्चिका = sshkey_new(कुञ्चिका_UNSPEC)) == रिक्त)
				fatal("sshkey_new");
			यदि ((r = sshkey_read(कुञ्चिका, &cp)) != 0)
				fatal_r(r, "%s:%lu: invalid key", मार्गः, lnum);
			यदि (was_explicit_कुञ्चिका)
				r = ssh_krl_revoke_कुञ्चिका_explicit(krl, कुञ्चिका);
			अन्यथा यदि (was_sha1) {
				यदि (sshkey_fingerprint_raw(कुञ्चिका,
				    SSH_DIGEST_SHA1, &blob, &blen) != 0) {
					fatal("%s:%lu: fingerprint failed",
					    file, lnum);
				}
				r = ssh_krl_revoke_कुञ्चिका_sha1(krl, blob, blen);
			} अन्यथा यदि (was_sha256) {
				यदि (sshkey_fingerprint_raw(कुञ्चिका,
				    SSH_DIGEST_SHA256, &blob, &blen) != 0) {
					fatal("%s:%lu: fingerprint failed",
					    file, lnum);
				}
				r = ssh_krl_revoke_कुञ्चिका_sha256(krl, blob, blen);
			} अन्यथा
				r = ssh_krl_revoke_कुञ्चिका(krl, कुञ्चिका);
			यदि (r != 0)
				fatal_fr(r, "revoke key failed");
			freezero(blob, blen);
			blob = रिक्त;
			blen = 0;
			sshkey_free(कुञ्चिका);
		}
	}
	यदि (वाक्यं_तुलय(मार्गः, "-") != 0)
		fclose(krl_spec);
	मुक्त(पङ्क्तिः);
	मुक्त(मार्गः);
}

स्थिर शून्य
do_gen_krl(संरचना passwd *pw, पूर्णाङ्क updating, ध्रुव वर्ण *ca_कुञ्चिका_मार्गः,
    अचिह्नित दीर्घ दीर्घ krl_संस्करणम्, ध्रुव वर्ण *krl_comment,
    पूर्णाङ्क argc, वर्ण **argv)
{
	संरचना ssh_krl *krl;
	संरचना stat sb;
	संरचना sshkey *ca = रिक्त;
	पूर्णाङ्क i, r, wild_ca = 0;
	वर्ण *tmp;
	संरचना sshbuf *kbuf;

	यदि (*तटस्थः_file == '\0')
		fatal("KRL generation requires an output file");
	यदि (stat(तटस्थः_file, &sb) == -1) {
		यदि (errno != ENOENT)
			fatal("Cannot access KRL \"%s\": %s",
			    तटस्थः_file, strerror(errno));
		यदि (updating)
			fatal("KRL \"%s\" does not exist", तटस्थः_file);
	}
	यदि (ca_कुञ्चिका_मार्गः != रिक्त) {
		यदि (strcasecmp(ca_कुञ्चिका_मार्गः, "none") == 0)
			wild_ca = 1;
		अन्यथा {
			tmp = tilde_expand_filename(ca_कुञ्चिका_मार्गः, pw->pw_uid);
			यदि ((r = sshkey_आरोपय_लौकिकम्(tmp, &ca, रिक्त)) != 0)
				fatal_r(r, "Cannot load CA public key %s", tmp);
			मुक्त(tmp);
		}
	}

	यदि (updating)
		आरोपय_krl(तटस्थः_file, &krl);
	अन्यथा यदि ((krl = ssh_krl_init()) == रिक्त)
		fatal("couldn't create KRL");

	यदि (krl_संस्करणम् != 0)
		ssh_krl_समुच्चयः_संस्करणम्(krl, krl_संस्करणम्);
	यदि (krl_comment != रिक्त)
		ssh_krl_समुच्चयः_comment(krl, krl_comment);

	प्रति (i = 0; i < argc; i++)
		update_krl_from_file(pw, argv[i], wild_ca, ca, krl);

	यदि ((kbuf = sshbuf_new()) == रिक्त)
		fatal("sshbuf_new failed");
	यदि (ssh_krl_गन्तव्यम्_blob(krl, kbuf) != 0)
		fatal("Couldn't generate KRL");
	यदि ((r = sshbuf_write_file(तटस्थः_file, kbuf)) != 0)
		fatal("write %s: %s", तटस्थः_file, strerror(errno));
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

	यदि (*तटस्थः_file == '\0')
		fatal("KRL checking requires an input file");
	आरोपय_krl(तटस्थः_file, &krl);
	यदि (print_krl)
		krl_dump(krl, stdout);
	प्रति (i = 0; i < argc; i++) {
		यदि ((r = sshkey_आरोपय_लौकिकम्(argv[i], &k, &comment)) != 0)
			fatal_r(r, "Cannot load public key %s", argv[i]);
		r = ssh_krl_check_कुञ्चिका(krl, k);
		प्रारूप_लिख("%s%s%s%s: %s\n", argv[i],
		    *comment ? " (" : "", comment, *comment ? ")" : "",
		    r == 0 ? "ok" : "REVOKED");
		यदि (r != 0)
			ret = 1;
		sshkey_free(k);
		मुक्त(comment);
	}
	ssh_krl_free(krl);
	निर्गच्छ(ret);
}

स्थिर संरचना sshkey *
आरोपय_sign_कुञ्चिका(ध्रुव वर्ण *keypath, ध्रुव संरचना sshkey *pubkey)
{
	आकार_t i, slen, plen = वाक्यदैर्घ्यम्(keypath);
	वर्ण *privpath = xstrdup(keypath);
	स्थिर ध्रुव वर्ण * ध्रुव suffixes[] = { "-cert.pub", ".pub", रिक्त };
	संरचना sshkey *ret = रिक्त, *privkey = रिक्त;
	पूर्णाङ्क r, waspub = 0;
	संरचना stat st;

	/*
	 * If passed a public key filename, then try to locate the corresponding
	 * private key. This lets us specify certificates on the command-line
	 * and have ssh-keygen find the appropriate private key.
	 */
	प्रति (i = 0; suffixes[i]; i++) {
		slen = वाक्यदैर्घ्यम्(suffixes[i]);
		यदि (plen <= slen ||
		    वाक्यं_तुलय(privpath + plen - slen, suffixes[i]) != 0)
			अनुवर्त;
		privpath[plen - slen] = '\0';
		debug_f("%s looks like a public key, using private key "
		    "path %s instead", keypath, privpath);
		waspub = 1;
	}
	यदि (waspub && stat(privpath, &st) != 0 && errno == ENOENT)
		fatal("No private key found for public key \"%s\"", keypath);
	यदि ((r = sshkey_आरोपय_वैयक्तिकम्(privpath, "", &privkey, रिक्त)) != 0 &&
	    (r != SSH_ERR_कुञ्चिका_WRONG_PASSPHRASE)) {
		debug_fr(r, "load private key \"%s\"", privpath);
		fatal("No private key found for \"%s\"", privpath);
	} अन्यथा यदि (privkey == रिक्त)
		privkey = आरोपय_तटस्थः(privpath, रिक्त);

	यदि (!sshkey_equal_लौकिकम्(pubkey, privkey)) {
		error("Public key %s doesn't match private %s",
		    keypath, privpath);
		गच्छ समाप्तम्;
	}
	यदि (sshkey_is_cert(pubkey) && !sshkey_is_cert(privkey)) {
		/*
		 * Graft the certificate onto the private key to make
		 * it capable of signing.
		 */
		यदि ((r = sshkey_गन्तव्यम्_certified(privkey)) != 0) {
			error_fr(r, "sshkey_to_certified");
			गच्छ समाप्तम्;
		}
		यदि ((r = sshkey_cert_copy(pubkey, privkey)) != 0) {
			error_fr(r, "sshkey_cert_copy");
			गच्छ समाप्तम्;
		}
	}
	/* success */
	ret = privkey;
	privkey = रिक्त;
 समाप्तम्:
	sshkey_free(privkey);
	मुक्त(privpath);
	प्रत्यागम ret;
}

स्थिर पूर्णाङ्क
sign_one(संरचना sshkey *signkey, ध्रुव वर्ण *filename, पूर्णाङ्क fd,
    ध्रुव वर्ण *sig_namespace, ध्रुव वर्ण *hashalg, sshsig_signer *signer,
    शून्य *signer_ctx)
{
	संरचना sshbuf *sigbuf = रिक्त, *abuf = रिक्त;
	पूर्णाङ्क r = SSH_ERR_आन्तरिकम्_ERROR, wfd = -1, oerrno;
	वर्ण *wfile = रिक्त, *asig = रिक्त, *fp = रिक्त;
	वर्ण *pin = रिक्त, *prompt = रिक्त;

	यदि (!quiet) {
		यदि (fd == STDIN_FILENO)
			fprintf(stderr, "Signing data on standard input\n");
		अन्यथा
			fprintf(stderr, "Signing file %s\n", filename);
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
			fprintf(stderr, "Confirm user presence for key %s %s\n",
			    sshkey_type(signkey), fp);
			मुक्त(fp);
		}
	}
	यदि ((r = sshsig_sign_fd(signkey, hashalg, sk_provider, pin,
	    fd, sig_namespace, &sigbuf, signer, signer_ctx)) != 0) {
		error_r(r, "Signing %s failed", filename);
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = sshsig_armor(sigbuf, &abuf)) != 0) {
		error_fr(r, "sshsig_armor");
		गच्छ बहिर्गमनम्;
	}
	यदि ((asig = sshbuf_dup_string(abuf)) == रिक्त) {
		error_f("buffer error");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}

	यदि (fd == STDIN_FILENO) {
		fputs(asig, stdout);
		fflush(stdout);
	} अन्यथा {
		xasprintf(&wfile, "%s.sig", filename);
		यदि (confirm_overwrite(wfile)) {
			यदि ((wfd = उद्घाटय(wfile, O_WRONLY|O_CREAT|O_TRUNC,
			    0666)) == -1) {
				oerrno = errno;
				error("Cannot open %s: %s",
				    wfile, strerror(errno));
				errno = oerrno;
				r = SSH_ERR_SYSTEM_ERROR;
				गच्छ बहिर्गमनम्;
			}
			यदि (atomicio(vwrite, wfd, asig,
			    वाक्यदैर्घ्यम्(asig)) != वाक्यदैर्घ्यम्(asig)) {
				oerrno = errno;
				error("Cannot write to %s: %s",
				    wfile, strerror(errno));
				errno = oerrno;
				r = SSH_ERR_SYSTEM_ERROR;
				गच्छ बहिर्गमनम्;
			}
			यदि (!quiet) {
				fprintf(stderr, "Write signature to %s\n",
				    wfile);
			}
		}
	}
	/* success */
	r = 0;
 बहिर्गमनम्:
	मुक्त(wfile);
	मुक्त(prompt);
	मुक्त(asig);
	यदि (pin != रिक्त)
		freezero(pin, वाक्यदैर्घ्यम्(pin));
	sshbuf_free(abuf);
	sshbuf_free(sigbuf);
	यदि (wfd != -1)
		close(wfd);
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
sig_process_opts(वर्ण * ध्रुव *opts, आकार_t nopts, वर्ण **hashalgp,
    uint64_t *verify_timep, पूर्णाङ्क *print_pubkey)
{
	आकार_t i;
	time_t now;
	ध्रुव वर्ण *p;

	यदि (verify_timep != रिक्त)
		*verify_timep = 0;
	यदि (print_pubkey != रिक्त)
		*print_pubkey = 0;
	यदि (hashalgp != रिक्त)
		*hashalgp = रिक्त;
	प्रति (i = 0; i < nopts; i++) {
		यदि (hashalgp != रिक्त &&
		    (p = strprefix(opts[i], "hashalg=", 1)) != रिक्त) {
			*hashalgp = xstrdup(p);
		} अन्यथा यदि (verify_timep &&
		    (p = strprefix(opts[i], "verify-time=", 1)) != रिक्त) {
			यदि (parse_absolute_time(p, verify_timep) != 0 ||
			    *verify_timep == 0) {
				error("Invalid \"verify-time\" option");
				प्रत्यागम SSH_ERR_INVALID_तर्कः;
			}
		} अन्यथा यदि (print_pubkey &&
		    strcasecmp(opts[i], "print-pubkey") == 0) {
			*print_pubkey = 1;
		} अन्यथा {
			error("Invalid option \"%s\"", opts[i]);
			प्रत्यागम SSH_ERR_INVALID_तर्कः;
		}
	}
	यदि (verify_timep && *verify_timep == 0) {
		यदि ((now = time(रिक्त)) < 0) {
			error("Time is before epoch");
			प्रत्यागम SSH_ERR_INVALID_तर्कः;
		}
		*verify_timep = (uint64_t)now;
	}
	प्रत्यागम 0;
}


स्थिर पूर्णाङ्क
sig_sign(ध्रुव वर्ण *keypath, ध्रुव वर्ण *sig_namespace, पूर्णाङ्क require_agent,
    पूर्णाङ्क argc, वर्ण **argv, वर्ण * ध्रुव *opts, आकार_t nopts)
{
	पूर्णाङ्क i, fd = -1, r, ret = -1;
	पूर्णाङ्क agent_fd = -1;
	संरचना sshkey *pubkey = रिक्त, *privkey = रिक्त, *signkey = रिक्त;
	sshsig_signer *signer = रिक्त;
	वर्ण *hashalg = रिक्त;

	/* Check file arguments. */
	प्रति (i = 0; i < argc; i++) {
		यदि (वाक्यं_तुलय(argv[i], "-") != 0)
			अनुवर्त;
		यदि (i > 0 || argc > 1)
			fatal("Cannot sign mix of paths and standard input");
	}

	यदि (sig_process_opts(opts, nopts, &hashalg, रिक्त, रिक्त) != 0)
		गच्छ समाप्तम्; /* error already logged */

	यदि ((r = sshkey_आरोपय_लौकिकम्(keypath, &pubkey, रिक्त)) != 0) {
		error_r(r, "Couldn't load public key %s", keypath);
		गच्छ समाप्तम्;
	}

	यदि ((r = ssh_get_authentication_socket(&agent_fd)) != 0) {
		यदि (require_agent)
			fatal("Couldn't get agent socket");
		debug_r(r, "Couldn't get agent socket");
	} अन्यथा {
		यदि ((r = ssh_agent_has_कुञ्चिका(agent_fd, pubkey)) == 0)
			signer = agent_signer;
		अन्यथा {
			यदि (require_agent)
				fatal("Couldn't find key in agent");
			debug_r(r, "Couldn't find key in agent");
		}
	}

	यदि (signer == रिक्त) {
		/* Not using agent - try to load private key */
		यदि ((privkey = आरोपय_sign_कुञ्चिका(keypath, pubkey)) == रिक्त)
			गच्छ समाप्तम्;
		signkey = privkey;
	} अन्यथा {
		/* Will use key in agent */
		signkey = pubkey;
	}

	यदि (argc == 0) {
		यदि ((r = sign_one(signkey, "(stdin)", STDIN_FILENO,
		    sig_namespace, hashalg, signer, &agent_fd)) != 0)
			गच्छ समाप्तम्;
	} अन्यथा {
		प्रति (i = 0; i < argc; i++) {
			यदि (वाक्यं_तुलय(argv[i], "-") == 0)
				fd = STDIN_FILENO;
			अन्यथा यदि ((fd = उद्घाटय(argv[i], O_RDONLY)) == -1) {
				error("Cannot open %s for signing: %s",
				    argv[i], strerror(errno));
				गच्छ समाप्तम्;
			}
			यदि ((r = sign_one(signkey, argv[i], fd, sig_namespace,
			    hashalg, signer, &agent_fd)) != 0)
				गच्छ समाप्तम्;
			यदि (fd != STDIN_FILENO)
				close(fd);
			fd = -1;
		}
	}

	ret = 0;
समाप्तम्:
	यदि (fd != -1 && fd != STDIN_FILENO)
		close(fd);
	sshkey_free(pubkey);
	sshkey_free(privkey);
	मुक्त(hashalg);
	प्रत्यागम ret;
}

स्थिर पूर्णाङ्क
sig_verify(ध्रुव वर्ण *signature, ध्रुव वर्ण *sig_namespace,
    ध्रुव वर्ण *principal, ध्रुव वर्ण *allowed_कुञ्चिकाः, ध्रुव वर्ण *revoked_कुञ्चिकाः,
    वर्ण * ध्रुव *opts, आकार_t nopts)
{
	पूर्णाङ्क r, ret = -1;
	पूर्णाङ्क print_pubkey = 0;
	संरचना sshbuf *sigbuf = रिक्त, *abuf = रिक्त;
	संरचना sshkey *sign_कुञ्चिका = रिक्त;
	वर्ण *fp = रिक्त;
	संरचना sshkey_sig_details *sig_details = रिक्त;
	uint64_t verify_time = 0;

	यदि (sig_process_opts(opts, nopts, रिक्त, &verify_time,
	    &print_pubkey) != 0)
		गच्छ समाप्तम्; /* error already logged */

	स्मृतिं_पूरय(&sig_details, 0, परिमाण(sig_details));
	यदि ((r = sshbuf_आरोपय_file(signature, &abuf)) != 0) {
		error_r(r, "Couldn't read signature file");
		गच्छ समाप्तम्;
	}

	यदि ((r = sshsig_dearmor(abuf, &sigbuf)) != 0) {
		error_fr(r, "sshsig_armor");
		गच्छ समाप्तम्;
	}
	यदि ((r = sshsig_verify_fd(sigbuf, STDIN_FILENO, sig_namespace,
	    &sign_कुञ्चिका, &sig_details)) != 0)
		गच्छ समाप्तम्; /* sshsig_verify() prints error */

	यदि ((fp = sshkey_fingerprint(sign_कुञ्चिका, fingerprint_hash,
	    SSH_FP_DEFAULT)) == रिक्त)
		fatal_f("sshkey_fingerprint failed");
	debug("Valid (unverified) signature from key %s", fp);
	यदि (sig_details != रिक्त) {
		debug2_f("signature details: counter = %u, flags = 0x%02x",
		    sig_details->sk_गणक, sig_details->sk_flags);
	}
	मुक्त(fp);
	fp = रिक्त;

	यदि (revoked_कुञ्चिकाः != रिक्त) {
		यदि ((r = sshkey_check_revoked(sign_कुञ्चिका, revoked_कुञ्चिकाः)) != 0) {
			debug3_fr(r, "sshkey_check_revoked");
			गच्छ समाप्तम्;
		}
	}

	यदि (allowed_कुञ्चिकाः != रिक्त && (r = sshsig_check_allowed_कुञ्चिकाः(allowed_कुञ्चिकाः,
	    sign_कुञ्चिका, principal, sig_namespace, verify_time)) != 0) {
		debug3_fr(r, "sshsig_check_allowed_keys");
		गच्छ समाप्तम्;
	}
	/* success */
	ret = 0;
समाप्तम्:
	यदि (!quiet) {
		यदि (ret == 0) {
			यदि ((fp = sshkey_fingerprint(sign_कुञ्चिका, fingerprint_hash,
			    SSH_FP_DEFAULT)) == रिक्त)
				fatal_f("sshkey_fingerprint failed");
			यदि (principal == रिक्त) {
				प्रारूप_लिख("Good \"%s\" signature with %s key %s\n",
				    sig_namespace, sshkey_type(sign_कुञ्चिका), fp);

			} अन्यथा {
				प्रारूप_लिख("Good \"%s\" signature for %s with %s key %s\n",
				    sig_namespace, principal,
				    sshkey_type(sign_कुञ्चिका), fp);
			}
		} अन्यथा {
			प्रारूप_लिख("Could not verify signature.\n");
		}
	}
	/* Print the signature key if requested */
	यदि (ret == 0 && print_pubkey && sign_कुञ्चिका != रिक्त) {
		यदि ((r = sshkey_write(sign_कुञ्चिका, stdout)) == 0)
			fputc('\n', stdout);
		अन्यथा {
			error_r(r, "Could not print public key.\n");
			ret = -1;
		}
	}
	sshbuf_free(sigbuf);
	sshbuf_free(abuf);
	sshkey_free(sign_कुञ्चिका);
	sshkey_sig_details_free(sig_details);
	मुक्त(fp);
	प्रत्यागम ret;
}

स्थिर पूर्णाङ्क
sig_find_principals(ध्रुव वर्ण *signature, ध्रुव वर्ण *allowed_कुञ्चिकाः,
    वर्ण * ध्रुव *opts, आकार_t nopts)
{
	पूर्णाङ्क r, ret = -1;
	संरचना sshbuf *sigbuf = रिक्त, *abuf = रिक्त;
	संरचना sshkey *sign_कुञ्चिका = रिक्त;
	वर्ण *principals = रिक्त, *cp, *tmp;
	uint64_t verify_time = 0;

	यदि (sig_process_opts(opts, nopts, रिक्त, &verify_time, रिक्त) != 0)
		गच्छ समाप्तम्; /* error already logged */

	यदि ((r = sshbuf_आरोपय_file(signature, &abuf)) != 0) {
		error_r(r, "Couldn't read signature file");
		गच्छ समाप्तम्;
	}
	यदि ((r = sshsig_dearmor(abuf, &sigbuf)) != 0) {
		error_fr(r, "sshsig_armor");
		गच्छ समाप्तम्;
	}
	यदि ((r = sshsig_get_pubkey(sigbuf, &sign_कुञ्चिका)) != 0) {
		error_fr(r, "sshsig_get_pubkey");
		गच्छ समाप्तम्;
	}
	यदि ((r = sshsig_find_principals(allowed_कुञ्चिकाः, sign_कुञ्चिका,
	    verify_time, &principals)) != 0) {
		यदि (r != SSH_ERR_कुञ्चिका_NOT_प्राप्तम्)
			error_fr(r, "sshsig_find_principal");
		गच्छ समाप्तम्;
	}
	ret = 0;
समाप्तम्:
	यदि (ret == 0 ) {
		/* Emit matching principals one per line */
		tmp = principals;
		यावत् ((cp = strsep(&tmp, ",")) != रिक्त && *cp != '\0')
			पङ्क्तिं_लिख(cp);
	} अन्यथा {
		fprintf(stderr, "No principal matched.\n");
	}
	sshbuf_free(sigbuf);
	sshbuf_free(abuf);
	sshkey_free(sign_कुञ्चिका);
	मुक्त(principals);
	प्रत्यागम ret;
}

स्थिर पूर्णाङ्क
sig_मेलनम्_principals(ध्रुव वर्ण *allowed_कुञ्चिकाः, वर्ण *principal,
	वर्ण * ध्रुव *opts, आकार_t nopts)
{
	पूर्णाङ्क r;
	वर्ण **principals = रिक्त;
	आकार_t i, nprincipals = 0;

	यदि ((r = sig_process_opts(opts, nopts, रिक्त, रिक्त, रिक्त)) != 0)
		प्रत्यागम r; /* error already logged */

	यदि ((r = sshsig_मेलनम्_principals(allowed_कुञ्चिकाः, principal,
	    &principals, &nprincipals)) != 0) {
		debug_f("match: %s", ssh_err(r));
		fprintf(stderr, "No principal matched.\n");
		प्रत्यागम r;
	}
	प्रति (i = 0; i < nprincipals; i++) {
		प्रारूप_लिख("%s\n", principals[i]);
		मुक्त(principals[i]);
	}
	मुक्त(principals);

	प्रत्यागम 0;
}

स्थिर शून्य
do_moduli_gen(ध्रुव वर्ण *बहिर्गमनम्_file, वर्ण **opts, आकार_t nopts)
{
#यदि_परिभाषितम् WITH_OPENSSL
	/* Moduli generation/screening */
	BIGNUM *start = रिक्त;
	पूर्णाङ्क moduli_द्वयङ्काः = 0;
	FILE *बहिर्गमनम्;
	आकार_t i;
	ध्रुव वर्ण *errstr, *p;

	/* Parse options */
	प्रति (i = 0; i < nopts; i++) {
		यदि ((p = strprefix(opts[i], "start=", 0)) != रिक्त) {
			/* XXX - also compare length against bits */
			यदि (BN_hex2bn(&start, p) == 0)
				fatal("Invalid start point.");
		} अन्यथा यदि ((p = strprefix(opts[i], "bits=", 0)) != रिक्त) {
			moduli_द्वयङ्काः = (पूर्णाङ्क)strtonum(p, 1, अधिकतम_पूर्णाङ्कः, &errstr);
			यदि (errstr) {
				fatal("Invalid number: %s (%s)", p, errstr);
			}
		} अन्यथा {
			fatal("Option \"%s\" is unsupported for moduli "
			    "generation", opts[i]);
		}
	}

	यदि (वाक्यं_तुलय(बहिर्गमनम्_file, "-") == 0)
		बहिर्गमनम् = stdout;
	अन्यथा यदि ((बहिर्गमनम् = fopen(बहिर्गमनम्_file, "w")) == रिक्त) {
		fatal("Couldn't open modulus candidate file \"%s\": %s",
		    बहिर्गमनम्_file, strerror(errno));
	}
	setvbuf(बहिर्गमनम्, रिक्त, _IOLBF, 0);

	यदि (moduli_द्वयङ्काः == 0)
		moduli_द्वयङ्काः = DEFAULT_द्वयङ्काः;
	यदि (gen_candidates(बहिर्गमनम्, moduli_द्वयङ्काः, start) != 0)
		fatal("modulus candidate generation failed");
#अन्यथा /* WITH_OPENSSL */
	fatal("Moduli generation is not supported");
#यदि_अन्तः /* WITH_OPENSSL */
}

स्थिर शून्य
do_moduli_screen(ध्रुव वर्ण *बहिर्गमनम्_file, वर्ण **opts, आकार_t nopts)
{
#यदि_परिभाषितम् WITH_OPENSSL
	/* Moduli generation/screening */
	वर्ण *checkpoint = रिक्त;
	uint32_t generator_wanted = 0;
	अचिह्नित दीर्घ start_lineno = 0, पङ्क्तयः_गन्तव्यम्_process = 0;
	पूर्णाङ्क अविभाज्यः_tests = 0;
	FILE *बहिर्गमनम्, *अन्तर् = stdin;
	आकार_t i;
	ध्रुव वर्ण *errstr, *p;

	/* Parse options */
	प्रति (i = 0; i < nopts; i++) {
		यदि ((p = strprefix(opts[i], "lines=", 0)) != रिक्त) {
			पङ्क्तयः_गन्तव्यम्_process = strtoul(p, रिक्त, 10);
		} अन्यथा यदि ((p = strprefix(opts[i], "start-line=", 0)) != रिक्त) {
			start_lineno = strtoul(p, रिक्त, 10);
		} अन्यथा यदि ((p = strprefix(opts[i], "checkpoint=", 0)) != रिक्त) {
			मुक्त(checkpoint);
			checkpoint = xstrdup(p);
		} अन्यथा यदि ((p = strprefix(opts[i], "generator=", 0)) != रिक्त) {
			generator_wanted = (uint32_t)strtonum(p, 1, UINT_MAX,
			    &errstr);
			यदि (errstr != रिक्त) {
				fatal("Generator invalid: %s (%s)", p, errstr);
			}
		} अन्यथा यदि ((p = strprefix(opts[i], "prime-tests=", 0)) != रिक्त) {
			अविभाज्यः_tests = (पूर्णाङ्क)strtonum(p, 1, अधिकतम_पूर्णाङ्कः, &errstr);
			यदि (errstr) {
				fatal("Invalid number: %s (%s)", p, errstr);
			}
		} अन्यथा {
			fatal("Option \"%s\" is unsupported for moduli "
			    "screening", opts[i]);
		}
	}

	यदि (have_तटस्थः && वाक्यं_तुलय(तटस्थः_file, "-") != 0) {
		यदि ((अन्तर् = fopen(तटस्थः_file, "r")) == रिक्त) {
			fatal("Couldn't open modulus candidate "
			    "file \"%s\": %s", तटस्थः_file,
			    strerror(errno));
		}
	}

	यदि (वाक्यं_तुलय(बहिर्गमनम्_file, "-") == 0)
		बहिर्गमनम् = stdout;
	अन्यथा यदि ((बहिर्गमनम् = fopen(बहिर्गमनम्_file, "a")) == रिक्त) {
		fatal("Couldn't open moduli file \"%s\": %s",
		    बहिर्गमनम्_file, strerror(errno));
	}
	setvbuf(बहिर्गमनम्, रिक्त, _IOLBF, 0);
	यदि (अविभाज्यः_test(अन्तर्, बहिर्गमनम्, अविभाज्यः_tests == 0 ? 100 : अविभाज्यः_tests,
	    generator_wanted, checkpoint,
	    start_lineno, पङ्क्तयः_गन्तव्यम्_process) != 0)
		fatal("modulus screening failed");
	यदि (अन्तर् != stdin)
		(शून्य)fclose(अन्तर्);
	मुक्त(checkpoint);
#अन्यथा /* WITH_OPENSSL */
	fatal("Moduli screening is not supported");
#यदि_अन्तः /* WITH_OPENSSL */
}

/* Read and confirm a passphrase */
स्थिर वर्ण *
read_check_passphrase(ध्रुव वर्ण *prompt1, ध्रुव वर्ण *prompt2,
    ध्रुव वर्ण *retry_prompt)
{
	वर्ण *passphrase1, *passphrase2;

	प्रति (;;) {
		passphrase1 = read_passphrase(prompt1, RP_ALLOW_STDIN);
		passphrase2 = read_passphrase(prompt2, RP_ALLOW_STDIN);
		यदि (वाक्यं_तुलय(passphrase1, passphrase2) == 0) {
			freezero(passphrase2, वाक्यदैर्घ्यम्(passphrase2));
			प्रत्यागम passphrase1;
		}
		/* The passphrases do not match. Clear them and retry. */
		freezero(passphrase1, वाक्यदैर्घ्यम्(passphrase1));
		freezero(passphrase2, वाक्यदैर्घ्यम्(passphrase2));
		fputs(retry_prompt, stdout);
		fputc('\n', stdout);
		fflush(stdout);
	}
	/* NOTREACHED */
	प्रत्यागम रिक्त;
}

स्थिर वर्ण *
वैयक्तिकम्_कुञ्चिका_passphrase(ध्रुव वर्ण *मार्गः)
{
	वर्ण *prompt, *ret;

	यदि (तटस्थः_passphrase)
		प्रत्यागम xstrdup(तटस्थः_passphrase);
	यदि (तटस्थः_new_passphrase)
		प्रत्यागम xstrdup(तटस्थः_new_passphrase);

	xasprintf(&prompt, "Enter passphrase for \"%s\" "
	    "(empty for no passphrase): ", मार्गः);
	ret = read_check_passphrase(prompt,
	    "Enter same passphrase again: ",
	    "Passphrases do not match.  Try again.");
	मुक्त(prompt);
	प्रत्यागम ret;
}

स्थिर वर्ण *
sk_suffix(ध्रुव वर्ण *application, ध्रुव uint8_t *user, आकार_t userlen)
{
	वर्ण *ret, *cp;
	ध्रुव वर्ण *p;
	आकार_t slen, i;

	/* Trim off URL-like preamble */
	यदि ((p = strprefix(application, "ssh://", 0)) != रिक्त)
		ret =  xstrdup(p);
	अन्यथा यदि ((p = strprefix(application, "ssh:", 0)) != रिक्त)
		ret =  xstrdup(p);
	अन्यथा
		ret = xstrdup(application);

	/* Count trailing zeros in user */
	प्रति (i = 0; i < userlen; i++) {
		यदि (user[userlen - i - 1] != 0)
			भङ्ग;
	}
	यदि (i >= userlen)
		प्रत्यागम ret; /* user-id was default all-zeros */

	/* Append user-id, escaping non-UTF-8 characters */
	slen = userlen - i;
	यदि (asmprintf(&cp, अधिकतम_पूर्णाङ्कः, रिक्त, "%.*s", (पूर्णाङ्क)slen, user) == -1)
		fatal_f("asmprintf failed");
	/* Don't emit a user-id that contains path or control characters */
	यदि (strchr(cp, '/') != रिक्त || वाक्ये_अन्विष(cp, "..") != रिक्त ||
	    strchr(cp, '\\') != रिक्त) {
		मुक्त(cp);
		cp = tohex(user, slen);
	}
	xextendf(&ret, "_", "%s", cp);
	मुक्त(cp);
	प्रत्यागम ret;
}

स्थिर पूर्णाङ्क
do_download_sk(ध्रुव वर्ण *skprovider, ध्रुव वर्ण *device)
{
	संरचना sshsk_resident_कुञ्चिका **srks;
	आकार_t nsrks, i;
	पूर्णाङ्क r, ret = -1;
	वर्ण *fp, *pin = रिक्त, *pass = रिक्त, *मार्गः, *pubpath;
	ध्रुव वर्ण *ext;
	संरचना sshkey *कुञ्चिका;

	यदि (skprovider == रिक्त)
		fatal("Cannot download keys without provider");

	pin = read_passphrase("Enter PIN for authenticator: ", RP_ALLOW_STDIN);
	यदि (!quiet) {
		प्रारूप_लिख("You may need to touch your authenticator "
		    "to authorize key download.\n");
	}
	यदि ((r = sshsk_आरोपय_resident(skprovider, device, pin, 0,
	    &srks, &nsrks)) != 0) {
		यदि (pin != रिक्त)
			freezero(pin, वाक्यदैर्घ्यम्(pin));
		error_r(r, "Unable to load resident keys");
		प्रत्यागम -1;
	}
	यदि (nsrks == 0)
		logit("No keys to download");
	यदि (pin != रिक्त)
		freezero(pin, वाक्यदैर्घ्यम्(pin));

	प्रति (i = 0; i < nsrks; i++) {
		कुञ्चिका = srks[i]->कुञ्चिका;
		यदि (कुञ्चिका->type != कुञ्चिका_ECDSA_SK && कुञ्चिका->type != कुञ्चिका_ED25519_SK) {
			error("Unsupported key type %s (%d)",
			    sshkey_type(कुञ्चिका), कुञ्चिका->type);
			अनुवर्त;
		}
		यदि ((fp = sshkey_fingerprint(कुञ्चिका, fingerprint_hash,
		    SSH_FP_DEFAULT)) == रिक्त)
			fatal_f("sshkey_fingerprint failed");
		debug_f("key %zu: %s %s %s (flags 0x%02x)", i,
		    sshkey_type(कुञ्चिका), fp, कुञ्चिका->sk_application, कुञ्चिका->sk_flags);
		ext = sk_suffix(कुञ्चिका->sk_application,
		    srks[i]->user_id, srks[i]->user_id_len);
		xasprintf(&मार्गः, "id_%s_rk%s%s",
		    कुञ्चिका->type == कुञ्चिका_ECDSA_SK ? "ecdsa_sk" : "ed25519_sk",
		    *ext == '\0' ? "" : "_", ext);

		/* If the file already exists, ask the user to confirm. */
		यदि (!confirm_overwrite(मार्गः)) {
			मुक्त(मार्गः);
			भङ्ग;
		}

		/* Save the key with the application string as the comment */
		यदि (pass == रिक्त)
			pass = वैयक्तिकम्_कुञ्चिका_passphrase(मार्गः);
		यदि ((r = sshkey_save_वैयक्तिकम्(कुञ्चिका, मार्गः, pass,
		    कुञ्चिका->sk_application, वैयक्तिकम्_कुञ्चिका_format,
		    openssh_format_cipher, आवर्तनानि)) != 0) {
			error_r(r, "Saving key \"%s\" failed", मार्गः);
			मुक्त(मार्गः);
			भङ्ग;
		}
		यदि (!quiet) {
			प्रारूप_लिख("Saved %s key%s%s to %s\n", sshkey_type(कुञ्चिका),
			    *ext != '\0' ? " " : "",
			    *ext != '\0' ? कुञ्चिका->sk_application : "",
			    मार्गः);
		}

		/* Save public key too */
		xasprintf(&pubpath, "%s.pub", मार्गः);
		मुक्त(मार्गः);
		यदि ((r = sshkey_save_लौकिकम्(कुञ्चिका, pubpath,
		    कुञ्चिका->sk_application)) != 0) {
			error_r(r, "Saving public key \"%s\" failed", pubpath);
			मुक्त(pubpath);
			भङ्ग;
		}
		मुक्त(pubpath);
	}

	यदि (i >= nsrks)
		ret = 0; /* success */
	यदि (pass != रिक्त)
		freezero(pass, वाक्यदैर्घ्यम्(pass));
	sshsk_free_resident_कुञ्चिकाः(srks, nsrks);
	प्रत्यागम ret;
}

स्थिर शून्य
save_attestation(संरचना sshbuf *attest, ध्रुव वर्ण *मार्गः)
{
	बहुलकम्_t omask;
	पूर्णाङ्क r;

	यदि (मार्गः == रिक्त)
		प्रत्यागम; /* nothing to do */
	यदि (attest == रिक्त || sshbuf_len(attest) == 0)
		fatal("Enrollment did not return attestation data");
	omask = umask(077);
	r = sshbuf_write_file(मार्गः, attest);
	umask(omask);
	यदि (r != 0)
		fatal_r(r, "Unable to write attestation data \"%s\"", मार्गः);
	यदि (!quiet)
		प्रारूप_लिख("Your FIDO attestation certificate has been saved in "
		    "%s\n", मार्गः);
}

स्थिर पूर्णाङ्क
confirm_sk_overwrite(ध्रुव वर्ण *application, ध्रुव वर्ण *user)
{
	वर्ण yesno[3];

	प्रारूप_लिख("A resident key scoped to '%s' with user id '%s' already "
	    "exists.\n", application == रिक्त ? "ssh:" : application,
	    user == रिक्त ? "null" : user);
	प्रारूप_लिख("Overwrite key in token (y/n)? ");
	fflush(stdout);
	यदि (fgets(yesno, परिमाण(yesno), stdin) == रिक्त)
		प्रत्यागम 0;
	यदि (yesno[0] != 'y' && yesno[0] != 'Y')
		प्रत्यागम 0;
	प्रत्यागम 1;
}

स्थिर शून्य
usage(शून्य)
{
	fprintf(stderr,
	    "usage: ssh-keygen [-q] [-a rounds] [-b bits] [-C comment] [-f output_keyfile]\n"
	    "                  [-m format] [-N new_passphrase] [-O option]\n"
	    "                  [-t ecdsa|ecdsa-sk|ed25519|ed25519-sk|mldsa44-ed25519|rsa]\n"
	    "                  [-w provider] [-Z cipher]\n"
	    "       ssh-keygen -p [-a rounds] [-f keyfile] [-m format] [-N new_passphrase]\n"
	    "                   [-P old_passphrase] [-Z cipher]\n"
#यदि_परिभाषितम् WITH_OPENSSL
	    "       ssh-keygen -i [-f input_keyfile] [-m key_format]\n"
	    "       ssh-keygen -e [-f input_keyfile] [-m key_format]\n"
#यदि_अन्तः
	    "       ssh-keygen -y [-f input_keyfile]\n"
	    "       ssh-keygen -c [-a rounds] [-C comment] [-f keyfile] [-P passphrase]\n"
	    "       ssh-keygen -l [-v] [-E fingerprint_hash] [-f input_keyfile]\n"
	    "       ssh-keygen -B [-f input_keyfile]\n");
#यदि_परिभाषितम् ENABLE_PKCS11
	fprintf(stderr,
	    "       ssh-keygen -D pkcs11\n");
#यदि_अन्तः
	fprintf(stderr,
	    "       ssh-keygen -F hostname [-lv] [-f known_hosts_file]\n"
	    "       ssh-keygen -H [-f known_hosts_file]\n"
	    "       ssh-keygen -K [-a rounds] [-w provider]\n"
	    "       ssh-keygen -R hostname [-f known_hosts_file]\n"
	    "       ssh-keygen -r hostname [-g] [-f input_keyfile]\n"
#यदि_परिभाषितम् WITH_OPENSSL
	    "       ssh-keygen -M generate [-O option] output_file\n"
	    "       ssh-keygen -M screen [-f input_file] [-O option] output_file\n"
#यदि_अन्तः
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
	निर्गच्छ(1);
}

/*
 * Main program for key management.
 */
पूर्णाङ्क
मुख्यम्(पूर्णाङ्क argc, वर्ण **argv)
{
	वर्ण comment[कुञ्चिका_COMMENT_MAX], *passphrase = रिक्त;
	वर्ण *rr_hostname = रिक्त, *ep, *fp, *ra;
	संरचना sshkey *गुप्त = रिक्त, *सार्वजनिक = रिक्त;
	संरचना passwd *pw;
	पूर्णाङ्क ret = 0, r, opt, type;
	पूर्णाङ्क change_passphrase = 0, change_comment = 0, show_cert = 0;
	पूर्णाङ्क find_host = 0, delete_host = 0, hash_hosts = 0;
	पूर्णाङ्क gen_all_hostkeys = 0, gen_krl = 0, update_krl = 0, check_krl = 0;
	पूर्णाङ्क prefer_agent = 0, convert_गन्तव्यम् = 0, convert_from = 0;
	पूर्णाङ्क print_लौकिकम् = 0, print_generic = 0, cert_serial_autoinc = 0;
	पूर्णाङ्क do_gen_candidates = 0, do_screen_candidates = 0, download_sk = 0;
	अचिह्नित दीर्घ दीर्घ cert_serial = 0;
	वर्ण *तटस्थः_comment = रिक्त, *ca_कुञ्चिका_मार्गः = रिक्त, **opts = रिक्त;
	वर्ण *sk_application = रिक्त, *sk_device = रिक्त, *sk_user = रिक्त;
	वर्ण *sk_attestation_मार्गः = रिक्त;
	संरचना sshbuf *challenge = रिक्त, *attest = रिक्त;
	आकार_t i, nopts = 0;
	uint32_t द्वयङ्काः = 0;
	uint8_t sk_flags = SSH_SK_USER_PRESENCE_REQD;
	ध्रुव वर्ण *errstr, *p;
	पूर्णाङ्क log_level = SYSLOG_LEVEL_INFO;
	वर्ण *sign_op = रिक्त;

	बाह्य पूर्णाङ्क optind;
	बाह्य वर्ण *optarg;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	__progname = ssh_get_progname(argv[0]);

	बीजम्_rng();

	log_init(argv[0], SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_USER, 1);

	msetlocale();

	/* we need this for the home * directory.  */
	pw = getpwuid(getuid());
	यदि (!pw)
		fatal("No user exists for uid %lu", (u_long)getuid());
	pw = pwcopy(pw);
	यदि (gethostname(hostname, परिमाण(hostname)) == -1)
		fatal("gethostname: %s", strerror(errno));

	sk_provider = getenv("SSH_SK_PROVIDER");

	/* Remaining characters: dGjJSTWx */
	यावत् ((opt = getopt(argc, argv, "ABHKLQUXceghiklopquvy"
	    "C:D:E:F:I:M:N:O:P:R:V:Y:Z:"
	    "a:b:f:g:m:n:r:s:t:w:z:")) != -1) {
		विकल्प (opt) {
		पक्ष 'A':
			gen_all_hostkeys = 1;
			भङ्ग;
		पक्ष 'b':
			द्वयङ्काः = (uint32_t)strtonum(optarg, 1, UINT32_MAX,
			    &errstr);
			यदि (errstr)
				fatal("Bits has bad value %s (%s)",
					optarg, errstr);
			भङ्ग;
		पक्ष 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			यदि (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			भङ्ग;
		पक्ष 'F':
			find_host = 1;
			rr_hostname = optarg;
			भङ्ग;
		पक्ष 'H':
			hash_hosts = 1;
			भङ्ग;
		पक्ष 'I':
			cert_कुञ्चिका_id = optarg;
			भङ्ग;
		पक्ष 'R':
			delete_host = 1;
			rr_hostname = optarg;
			भङ्ग;
		पक्ष 'L':
			show_cert = 1;
			भङ्ग;
		पक्ष 'l':
			print_fingerprint = 1;
			भङ्ग;
		पक्ष 'B':
			print_bubblebabble = 1;
			भङ्ग;
		पक्ष 'm':
			यदि (strcasecmp(optarg, "RFC4716") == 0 ||
			    strcasecmp(optarg, "ssh2") == 0) {
				convert_format = FMT_RFC4716;
				भङ्ग;
			}
			यदि (strcasecmp(optarg, "PKCS8") == 0) {
				convert_format = FMT_PKCS8;
				वैयक्तिकम्_कुञ्चिका_format = SSHKEY_वैयक्तिकम्_PKCS8;
				भङ्ग;
			}
			यदि (strcasecmp(optarg, "PEM") == 0) {
				convert_format = FMT_PEM;
				वैयक्तिकम्_कुञ्चिका_format = SSHKEY_वैयक्तिकम्_PEM;
				भङ्ग;
			}
			यदि (strcasecmp(optarg, "hexdump") == 0) {
				convert_format = FMT_HEXDUMP;
				भङ्ग;
			}
			fatal("Unsupported conversion format \"%s\"", optarg);
		पक्ष 'n':
			cert_principals = optarg;
			भङ्ग;
		पक्ष 'o':
			/* no-op; new format is already the default */
			भङ्ग;
		पक्ष 'p':
			change_passphrase = 1;
			भङ्ग;
		पक्ष 'c':
			change_comment = 1;
			भङ्ग;
		पक्ष 'f':
			यदि (strlcpy(तटस्थः_file, optarg,
			    परिमाण(तटस्थः_file)) >= परिमाण(तटस्थः_file))
				fatal("Identity filename too long");
			have_तटस्थः = 1;
			भङ्ग;
		पक्ष 'g':
			print_generic = 1;
			भङ्ग;
		पक्ष 'K':
			download_sk = 1;
			भङ्ग;
		पक्ष 'P':
			तटस्थः_passphrase = optarg;
			भङ्ग;
		पक्ष 'N':
			तटस्थः_new_passphrase = optarg;
			भङ्ग;
		पक्ष 'Q':
			check_krl = 1;
			भङ्ग;
		पक्ष 'O':
			opts = xrecallocarray(opts, nopts, nopts + 1,
			    परिमाण(*opts));
			opts[nopts++] = xstrdup(optarg);
			भङ्ग;
		पक्ष 'Z':
			openssh_format_cipher = optarg;
			यदि (cipher_by_name(openssh_format_cipher) == रिक्त)
				fatal("Invalid OpenSSH-format cipher '%s'",
				    openssh_format_cipher);
			भङ्ग;
		पक्ष 'C':
			तटस्थः_comment = optarg;
			भङ्ग;
		पक्ष 'q':
			quiet = 1;
			भङ्ग;
		पक्ष 'e':
			/* export key */
			convert_गन्तव्यम् = 1;
			भङ्ग;
		पक्ष 'h':
			cert_कुञ्चिका_type = SSH2_CERT_TYPE_HOST;
			certflags_flags = 0;
			भङ्ग;
		पक्ष 'k':
			gen_krl = 1;
			भङ्ग;
		पक्ष 'i':
		पक्ष 'X':
			/* import key */
			convert_from = 1;
			भङ्ग;
		पक्ष 'y':
			print_लौकिकम् = 1;
			भङ्ग;
		पक्ष 's':
			ca_कुञ्चिका_मार्गः = optarg;
			भङ्ग;
		पक्ष 't':
			कुञ्चिका_type_name = optarg;
			भङ्ग;
		पक्ष 'D':
			pkcs11provider = optarg;
			भङ्ग;
		पक्ष 'U':
			prefer_agent = 1;
			भङ्ग;
		पक्ष 'u':
			update_krl = 1;
			भङ्ग;
		पक्ष 'v':
			यदि (log_level == SYSLOG_LEVEL_INFO)
				log_level = SYSLOG_LEVEL_DEBUG1;
			अन्यथा {
				यदि (log_level >= SYSLOG_LEVEL_DEBUG1 &&
				    log_level < SYSLOG_LEVEL_DEBUG3)
					log_level++;
			}
			भङ्ग;
		पक्ष 'r':
			rr_hostname = optarg;
			भङ्ग;
		पक्ष 'a':
			आवर्तनानि = (पूर्णाङ्क)strtonum(optarg, 1, अधिकतम_पूर्णाङ्कः, &errstr);
			यदि (errstr)
				fatal("Invalid number: %s (%s)",
					optarg, errstr);
			भङ्ग;
		पक्ष 'V':
			parse_cert_times(optarg);
			भङ्ग;
		पक्ष 'Y':
			sign_op = optarg;
			भङ्ग;
		पक्ष 'w':
			sk_provider = optarg;
			भङ्ग;
		पक्ष 'z':
			errno = 0;
			यदि (*optarg == '+') {
				cert_serial_autoinc = 1;
				optarg++;
			}
			cert_serial = strtoull(optarg, &ep, 10);
			यदि (*optarg < '0' || *optarg > '9' || *ep != '\0' ||
			    (errno == ERANGE && cert_serial == ULLONG_MAX))
				fatal("Invalid serial number \"%s\"", optarg);
			भङ्ग;
		पक्ष 'M':
			यदि (वाक्यं_तुलय(optarg, "generate") == 0)
				do_gen_candidates = 1;
			अन्यथा यदि (वाक्यं_तुलय(optarg, "screen") == 0)
				do_screen_candidates = 1;
			अन्यथा
				fatal("Unsupported moduli option %s", optarg);
			भङ्ग;
		स्वभाव:
			usage();
		}
	}

#यदि_परिभाषितम् ENABLE_SK_आन्तरिकम्
	यदि (sk_provider == रिक्त)
		sk_provider = "internal";
#यदि_अन्तः

	/* reinit */
	log_init(argv[0], log_level, SYSLOG_FACILITY_USER, 1);

	argv += optind;
	argc -= optind;

	यदि (sign_op != रिक्त) {
		यदि (strprefix(sign_op, "find-principals", 0) != रिक्त) {
			यदि (ca_कुञ्चिका_मार्गः == रिक्त) {
				error("Too few arguments for find-principals:"
				    "missing signature file");
				निर्गच्छ(1);
			}
			यदि (!have_तटस्थः) {
				error("Too few arguments for find-principals:"
				    "missing allowed keys file");
				निर्गच्छ(1);
			}
			ret = sig_find_principals(ca_कुञ्चिका_मार्गः, तटस्थः_file,
			    opts, nopts);
			गच्छ समाप्तम्;
		} अन्यथा यदि (strprefix(sign_op, "match-principals", 0) != रिक्त) {
			यदि (!have_तटस्थः) {
				error("Too few arguments for match-principals:"
				    "missing allowed keys file");
				निर्गच्छ(1);
			}
			यदि (cert_कुञ्चिका_id == रिक्त) {
				error("Too few arguments for match-principals: "
				    "missing principal ID");
				निर्गच्छ(1);
			}
			ret = sig_मेलनम्_principals(तटस्थः_file, cert_कुञ्चिका_id,
			    opts, nopts);
			गच्छ समाप्तम्;
		} अन्यथा यदि (strprefix(sign_op, "sign", 0) != रिक्त) {
			/* NB. cert_principals is actually namespace, via -n */
			यदि (cert_principals == रिक्त ||
			    *cert_principals == '\0') {
				error("Too few arguments for sign: "
				    "missing namespace");
				निर्गच्छ(1);
			}
			यदि (!have_तटस्थः) {
				error("Too few arguments for sign: "
				    "missing key");
				निर्गच्छ(1);
			}
			ret = sig_sign(तटस्थः_file, cert_principals,
			    prefer_agent, argc, argv, opts, nopts);
			गच्छ समाप्तम्;
		} अन्यथा यदि (strprefix(sign_op, "check-novalidate", 0) != रिक्त) {
			/* NB. cert_principals is actually namespace, via -n */
			यदि (cert_principals == रिक्त ||
			    *cert_principals == '\0') {
				error("Too few arguments for check-novalidate: "
				    "missing namespace");
				निर्गच्छ(1);
			}
			यदि (ca_कुञ्चिका_मार्गः == रिक्त) {
				error("Too few arguments for check-novalidate: "
				    "missing signature file");
				निर्गच्छ(1);
			}
			ret = sig_verify(ca_कुञ्चिका_मार्गः, cert_principals,
			    रिक्त, रिक्त, रिक्त, opts, nopts);
			गच्छ समाप्तम्;
		} अन्यथा यदि (strprefix(sign_op, "verify", 0) != रिक्त) {
			/* NB. cert_principals is actually namespace, via -n */
			यदि (cert_principals == रिक्त ||
			    *cert_principals == '\0') {
				error("Too few arguments for verify: "
				    "missing namespace");
				निर्गच्छ(1);
			}
			यदि (ca_कुञ्चिका_मार्गः == रिक्त) {
				error("Too few arguments for verify: "
				    "missing signature file");
				निर्गच्छ(1);
			}
			यदि (!have_तटस्थः) {
				error("Too few arguments for sign: "
				    "missing allowed keys file");
				निर्गच्छ(1);
			}
			यदि (cert_कुञ्चिका_id == रिक्त) {
				error("Too few arguments for verify: "
				    "missing principal identity");
				निर्गच्छ(1);
			}
			ret = sig_verify(ca_कुञ्चिका_मार्गः, cert_principals,
			    cert_कुञ्चिका_id, तटस्थः_file, rr_hostname,
			    opts, nopts);
			गच्छ समाप्तम्;
		}
		error("Unsupported operation for -Y: \"%s\"", sign_op);
		usage();
		/* NOTREACHED */
	}

	यदि (ca_कुञ्चिका_मार्गः != रिक्त) {
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
		do_gen_krl(pw, update_krl, ca_कुञ्चिका_मार्गः,
		    cert_serial, तटस्थः_comment, argc, argv);
		गच्छ समाप्तम्;
	}
	यदि (check_krl) {
		do_check_krl(pw, print_fingerprint, argc, argv);
		गच्छ समाप्तम्;
	}
	यदि (ca_कुञ्चिका_मार्गः != रिक्त) {
		यदि (cert_कुञ्चिका_id == रिक्त)
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
		प्रति (i = 0; i < nopts; i++)
			सङ्कलय_cert_option(opts[i]);
		do_ca_sign(pw, ca_कुञ्चिका_मार्गः, prefer_agent,
		    cert_serial, cert_serial_autoinc, argc, argv);
		गच्छ समाप्तम्;
	}
	यदि (show_cert)
		do_show_cert(pw);
	यदि (delete_host || hash_hosts || find_host) {
		do_ज्ञातम्_hosts(pw, rr_hostname, find_host,
		    delete_host, hash_hosts);
	}
	यदि (pkcs11provider != रिक्त)
		do_download(pw);
	यदि (download_sk) {
		प्रति (i = 0; i < nopts; i++) {
			यदि ((p = strprefix(opts[i], "device=", 1)) != रिक्त) {
				sk_device = xstrdup(p);
			} अन्यथा {
				fatal("Option \"%s\" is unsupported for "
				    "FIDO authenticator download", opts[i]);
			}
		}
		ret = do_download_sk(sk_provider, sk_device);
		गच्छ समाप्तम्;
	}
	यदि (print_fingerprint || print_bubblebabble)
		do_fingerprint(pw);
	यदि (change_passphrase)
		do_change_passphrase(pw, opts, nopts);
	यदि (change_comment)
		do_change_comment(pw, तटस्थः_comment);
#यदि_परिभाषितम् WITH_OPENSSL
	यदि (convert_गन्तव्यम्) {
		do_convert_गन्तव्यम्(pw);
		गच्छ समाप्तम्;
	}
	यदि (convert_from) {
		do_convert_from(pw);
		गच्छ समाप्तम्;
	}
#अन्यथा /* WITH_OPENSSL */
	यदि (convert_गन्तव्यम् || convert_from)
		fatal("key conversion disabled at compile time");
#यदि_अन्तः /* WITH_OPENSSL */
	यदि (print_लौकिकम्)
		do_print_लौकिकम्(pw);
	यदि (rr_hostname != रिक्त) {
		अचिह्नित पूर्णाङ्क n = 0;

		यदि (have_तटस्थः) {
			n = do_print_resource_लेखः(pw, तटस्थः_file,
			    rr_hostname, print_generic, opts, nopts);
			यदि (n == 0)
				fatal("%s: %s", तटस्थः_file, strerror(errno));
			निर्गच्छ(0);
		} अन्यथा {

			n += do_print_resource_लेखः(pw,
			    मार्गः_HOST_RSA_कुञ्चिका_FILE, rr_hostname,
			    print_generic, opts, nopts);
			n += do_print_resource_लेखः(pw,
			    मार्गः_HOST_ECDSA_कुञ्चिका_FILE, rr_hostname,
			    print_generic, opts, nopts);
			n += do_print_resource_लेखः(pw,
			    मार्गः_HOST_ED25519_कुञ्चिका_FILE, rr_hostname,
			    print_generic, opts, nopts);
			यदि (n == 0)
				fatal("no keys found.");
			निर्गच्छ(0);
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
		गच्छ समाप्तम्;
	}
	यदि (do_screen_candidates) {
		do_moduli_screen(argv[0], opts, nopts);
		गच्छ समाप्तम्;
	}

	यदि (gen_all_hostkeys) {
		do_gen_all_hostkeys(pw);
		गच्छ समाप्तम्;
	}

	यदि (कुञ्चिका_type_name == रिक्त)
		कुञ्चिका_type_name = DEFAULT_कुञ्चिका_TYPE_NAME;

	type = sshkey_type_from_shortname(कुञ्चिका_type_name);
	type_द्वयङ्काः_valid(type, कुञ्चिका_type_name, &द्वयङ्काः);

	यदि (!quiet)
		प्रारूप_लिख("Generating public/private %s key pair.\n",
		    कुञ्चिका_type_name);
	विकल्प (type) {
	पक्ष कुञ्चिका_ECDSA_SK:
	पक्ष कुञ्चिका_ED25519_SK:
		प्रति (i = 0; i < nopts; i++) {
			यदि (strcasecmp(opts[i], "no-touch-required") == 0) {
				sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
			} अन्यथा यदि (strcasecmp(opts[i], "verify-required") == 0) {
				sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
			} अन्यथा यदि (strcasecmp(opts[i], "resident") == 0) {
				sk_flags |= SSH_SK_RESIDENT_कुञ्चिका;
			} अन्यथा यदि ((p = strprefix(opts[i], "device=", 1))
			    != रिक्त ) {
				sk_device = xstrdup(p);
			} अन्यथा यदि ((p = strprefix(opts[i], "user=", 1))
			    != रिक्त) {
				sk_user = xstrdup(p);
			} अन्यथा यदि ((p = strprefix(opts[i], "challenge=", 1))
			    != रिक्त) {
				यदि ((r = sshbuf_आरोपय_file(p,
				    &challenge)) != 0) {
					fatal_r(r, "Unable to load FIDO "
					    "enrollment challenge \"%s\"", p);
				}
			} अन्यथा यदि (strncasecmp(opts[i],
			    "write-attestation=", 18) == 0) {
				sk_attestation_मार्गः = opts[i] + 18;
			} अन्यथा यदि (strncasecmp(opts[i],
			    "application=", 12) == 0) {
				sk_application = xstrdup(opts[i] + 12);
				यदि (वाक्ये_तुलय(sk_application, "ssh:", 4) != 0) {
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
		प्रति (i = 0 ;;) {
			यदि (!quiet) {
				प्रारूप_लिख("You may need to touch your "
				    "authenticator%s to authorize key "
				    "generation.\n",
				    r == 0 ? "" : " again");
			}
			fflush(stdout);
			r = sshsk_enroll(type, sk_provider, sk_device,
			    sk_application == रिक्त ? "ssh:" : sk_application,
			    sk_user, sk_flags, passphrase, challenge,
			    &गुप्त, attest);
			यदि (r == 0)
				भङ्ग;
			यदि (r == SSH_ERR_कुञ्चिका_BAD_PERMISSIONS &&
			    (sk_flags & SSH_SK_RESIDENT_कुञ्चिका) != 0 &&
			    (sk_flags & SSH_SK_FORCE_OPERATION) == 0 &&
			    confirm_sk_overwrite(sk_application, sk_user)) {
				sk_flags |= SSH_SK_FORCE_OPERATION;
				अनुवर्त;
			}
			यदि (r != SSH_ERR_कुञ्चिका_WRONG_PASSPHRASE)
				fatal_r(r, "Key enrollment failed");
			अन्यथा यदि (passphrase != रिक्त) {
				error("PIN incorrect");
				freezero(passphrase, वाक्यदैर्घ्यम्(passphrase));
				passphrase = रिक्त;
			}
			यदि (++i >= 3)
				fatal("Too many incorrect PINs");
			passphrase = read_passphrase("Enter PIN for "
			    "authenticator: ", RP_ALLOW_STDIN);
		}
		यदि (passphrase != रिक्त) {
			freezero(passphrase, वाक्यदैर्घ्यम्(passphrase));
			passphrase = रिक्त;
		}
		भङ्ग;
	स्वभाव:
		यदि ((r = sshkey_generate(type, द्वयङ्काः, &गुप्त)) != 0)
			fatal("sshkey_generate failed");
		भङ्ग;
	}
	यदि ((r = sshkey_from_वैयक्तिकम्(गुप्त, &सार्वजनिक)) != 0)
		fatal_r(r, "sshkey_from_private");

	यदि (!have_तटस्थः)
		ask_filename(pw, "Enter file in which to save the key");

	/* Create ~/.ssh directory if it doesn't already exist. */
	hostfile_create_user_ssh_dir(तटस्थः_file, !quiet);

	/* If the file already exists, ask the user to confirm. */
	यदि (!confirm_overwrite(तटस्थः_file))
		निर्गच्छ(1);

	/* Determine the passphrase for the private key */
	passphrase = वैयक्तिकम्_कुञ्चिका_passphrase(तटस्थः_file);
	यदि (तटस्थः_comment) {
		strlcpy(comment, तटस्थः_comment, परिमाण(comment));
	} अन्यथा {
		/* Create default comment field for the passphrase. */
		snprintf(comment, परिमाण comment, "%s@%s", pw->pw_name, hostname);
	}



	/* Save the key with the given passphrase and comment. */
	यदि ((r = sshkey_save_वैयक्तिकम्(गुप्त, तटस्थः_file, passphrase,
	    comment, वैयक्तिकम्_कुञ्चिका_format, openssh_format_cipher, आवर्तनानि)) != 0) {
		error_r(r, "Saving key \"%s\" failed", तटस्थः_file);
		freezero(passphrase, वाक्यदैर्घ्यम्(passphrase));
		निर्गच्छ(1);
	}
	freezero(passphrase, वाक्यदैर्घ्यम्(passphrase));
	sshkey_free(गुप्त);

	यदि (!quiet) {
		प्रारूप_लिख("Your identification has been saved in %s\n",
		    तटस्थः_file);
	}

	strlcat(तटस्थः_file, ".pub", परिमाण(तटस्थः_file));
	यदि ((r = sshkey_save_लौकिकम्(सार्वजनिक, तटस्थः_file, comment)) != 0)
		fatal_r(r, "Unable to save public key to %s", तटस्थः_file);

	यदि (!quiet) {
		fp = sshkey_fingerprint(सार्वजनिक, fingerprint_hash,
		    SSH_FP_DEFAULT);
		ra = sshkey_fingerprint(सार्वजनिक, fingerprint_hash,
		    SSH_FP_RANDOMART);
		यदि (fp == रिक्त || ra == रिक्त)
			fatal("sshkey_fingerprint failed");
		प्रारूप_लिख("Your public key has been saved in %s\n",
		    तटस्थः_file);
		प्रारूप_लिख("The key fingerprint is:\n");
		प्रारूप_लिख("%s %s\n", fp, comment);
		प्रारूप_लिख("The key's randomart image is:\n");
		प्रारूप_लिख("%s\n", ra);
		मुक्त(ra);
		मुक्त(fp);
	}

	यदि (sk_attestation_मार्गः != रिक्त)
		save_attestation(attest, sk_attestation_मार्गः);

 समाप्तम्:
	sshbuf_free(attest);
	sshkey_free(सार्वजनिक);
	pwfree(pw);
	निर्गच्छ(ret);
}
