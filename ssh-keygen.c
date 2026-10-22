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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/socket.h>
#समावेश <sys/stat.h>

#अगर_घोषित WITH_OPENSSL
#समावेश "openbsd-compat/openssl-compat.h"
#समावेश <openssl/bn.h>
#समावेश <openssl/evp.h>
#समावेश <openssl/pem.h>
#पूर्ण_अगर

#समावेश <stdint.h>
#समावेश <errno.h>
#समावेश <fcntl.h>
#समावेश <netdb.h>
#समावेश <paths.h>
#समावेश <pwd.h>
#समावेश <stdarg.h>
#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <unistd.h>
#समावेश <limits.h>
#समावेश <locale.h>
#समावेश <time.h>

#समावेश "xmalloc.h"
#समावेश "sshkey.h"
#समावेश "authfile.h"
#समावेश "sshbuf.h"
#समावेश "pathnames.h"
#समावेश "log.h"
#समावेश "misc.h"
#समावेश "match.h"
#समावेश "hostfile.h"
#समावेश "dns.h"
#समावेश "ssh.h"
#समावेश "ssh2.h"
#समावेश "ssherr.h"
#समावेश "atomicio.h"
#समावेश "krl.h"
#समावेश "digest.h"
#समावेश "utf8.h"
#समावेश "authfd.h"
#समावेश "sshsig.h"
#समावेश "ssh-sk.h"
#समावेश "sk-api.h" /* XXX for SSH_SK_USER_PRESENCE_REQD; remove */
#समावेश "cipher.h"

#अगर_घोषित ENABLE_PKCS11
#समावेश "ssh-pkcs11.h"
#पूर्ण_अगर

#घोषणा DEFAULT_कुंजी_TYPE_NAME "ed25519"

/*
 * Default number of bits in the RSA and ECDSA keys.  These value can be
 * overridden on the command line.
 *
 * These values provide security equivalent to at least 128 bits of security
 * according to NIST Special Publication 800-57: Recommendation for Key
 * Management Part 1 rev 4 section 5.6.1.
 */
#घोषणा DEFAULT_BITS		3072
#घोषणा DEFAULT_BITS_ECDSA	256

#घोषणा कुंजी_COMMENT_MAX		(NI_MAXHOST + 1024)

अटल पूर्णांक quiet = 0;

/* Flag indicating that we just want to see the key fingerprint */
अटल पूर्णांक print_fingerprint = 0;
अटल पूर्णांक print_bubblebabble = 0;

/* Hash algorithm to use for fingerprints. */
अटल पूर्णांक fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* The identity file name, given on the command line or entered by the user. */
अटल अक्षर identity_file[PATH_MAX];
अटल पूर्णांक have_identity = 0;

/* This is set to the passphrase if given on the command line. */
अटल अक्षर *identity_passphrase = शून्य;

/* This is set to the new passphrase if given on the command line. */
अटल अक्षर *identity_new_passphrase = शून्य;

/* Key type when certifying */
अटल u_int cert_कुंजी_type = SSH2_CERT_TYPE_USER;

/* "key ID" of signed key */
अटल अक्षर *cert_कुंजी_id = शून्य;

/* Comma-separated list of principal names for certifying keys */
अटल अक्षर *cert_principals = शून्य;

/* Validity period for certificates */
अटल uint64_t cert_valid_from = 0;
अटल uint64_t cert_valid_to = ~0ULL;

/* Certificate options */
#घोषणा CERTOPT_X_FWD				(1)
#घोषणा CERTOPT_AGENT_FWD			(1<<1)
#घोषणा CERTOPT_PORT_FWD			(1<<2)
#घोषणा CERTOPT_PTY				(1<<3)
#घोषणा CERTOPT_USER_RC				(1<<4)
#घोषणा CERTOPT_NO_REQUIRE_USER_PRESENCE	(1<<5)
#घोषणा CERTOPT_REQUIRE_VERIFY			(1<<6)
#घोषणा CERTOPT_DEFAULT	(CERTOPT_X_FWD|CERTOPT_AGENT_FWD| \
			 CERTOPT_PORT_FWD|CERTOPT_PTY|CERTOPT_USER_RC)
अटल uint32_t certflags_flags = CERTOPT_DEFAULT;
अटल अक्षर *certflags_command = शून्य;
अटल अक्षर *certflags_src_addr = शून्य;

/* Arbitrary extensions specified by user */
काष्ठा cert_ext {
	अक्षर *कुंजी;
	अक्षर *val;
	पूर्णांक crit;
};
अटल काष्ठा cert_ext *cert_ext;
अटल माप_प्रकार ncert_ext;

/* Conversion to/from various formats */
क्रमागत {
	FMT_RFC4716,
	FMT_PKCS8,
	FMT_PEM,
	FMT_HEXDUMP
} convert_format = FMT_RFC4716;

अटल अक्षर *कुंजी_type_name = शून्य;

/* Load key from this PKCS#11 provider */
अटल अक्षर *pkcs11provider = शून्य;

/* FIDO/U2F provider to use */
अटल अक्षर *sk_provider = शून्य;

/* Format for writing private keys */
अटल पूर्णांक private_कुंजी_format = SSHKEY_PRIVATE_OPENSSH;

/* Cipher for new-format private keys */
अटल अक्षर *openssh_format_cipher = शून्य;

/* Number of KDF rounds to derive new format keys. */
अटल पूर्णांक rounds = 0;

/* argv0 */
बाह्य अक्षर *__progname;

अटल अक्षर hostname[NI_MAXHOST];

#अगर_घोषित WITH_OPENSSL
/* moduli.c */
पूर्णांक gen_candidates(खाता *, uint32_t, BIGNUM *);
पूर्णांक अभाज्य_test(खाता *, खाता *, uint32_t, uint32_t, अक्षर *, अचिन्हित दीर्घ,
    अचिन्हित दीर्घ);
#पूर्ण_अगर

अटल व्योम
type_bits_valid(पूर्णांक type, स्थिर अक्षर *name, uint32_t *bitsp)
{
	अगर (type == कुंजी_UNSPEC)
		fatal("unknown key type %s", कुंजी_type_name);
	अगर (*bitsp == 0) {
#अगर_घोषित WITH_OPENSSL
		पूर्णांक nid;

		चयन(type) {
		हाल कुंजी_ECDSA:
			अगर (name != शून्य &&
			    (nid = sshkey_ecdsa_nid_from_name(name)) > 0)
				*bitsp = sshkey_curve_nid_to_bits(nid);
			अगर (*bitsp == 0)
				*bitsp = DEFAULT_BITS_ECDSA;
			अवरोध;
		हाल कुंजी_RSA:
			*bitsp = DEFAULT_BITS;
			अवरोध;
		}
#पूर्ण_अगर
	}
#अगर_घोषित WITH_OPENSSL
	चयन (type) {
	हाल कुंजी_RSA:
		अगर (*bitsp < SSH_RSA_MINIMUM_MODULUS_आकार)
			fatal("Invalid RSA key length: minimum is %d bits",
			    SSH_RSA_MINIMUM_MODULUS_आकार);
		अन्यथा अगर (*bitsp > OPENSSL_RSA_MAX_MODULUS_BITS)
			fatal("Invalid RSA key length: maximum is %d bits",
			    OPENSSL_RSA_MAX_MODULUS_BITS);
		अवरोध;
	हाल कुंजी_ECDSA:
		अगर (sshkey_ecdsa_bits_to_nid(*bitsp) == -1)
			fatal("Invalid ECDSA key length: valid lengths are "
			    "256, 384 or 521 bits");
	}
#पूर्ण_अगर
}

/*
 * Checks whether a file exists and, if so, asks the user whether they wish
 * to overwrite it.
 * Returns nonzero if the file does not already exist or if the user agrees to
 * overwrite, or zero otherwise.
 */
अटल पूर्णांक
confirm_overwrite(स्थिर अक्षर *filename)
{
	अक्षर yesno[3];
	काष्ठा stat st;

	अगर (stat(filename, &st) != 0)
		वापस 1;
	म_लिखो("%s already exists.\n", filename);
	म_लिखो("Overwrite (y/n)? ");
	ख_साफ(मानक_निकास);
	अगर (ख_माला_लो(yesno, माप(yesno), मानक_निवेश) == शून्य)
		वापस 0;
	अगर (yesno[0] != 'y' && yesno[0] != 'Y')
		वापस 0;
	वापस 1;
}

अटल व्योम
ask_filename(काष्ठा passwd *pw, स्थिर अक्षर *prompt)
{
	अक्षर buf[1024];
	अक्षर *name = शून्य;

	अगर (कुंजी_type_name == शून्य)
		name = _PATH_SSH_CLIENT_ID_ED25519;
	अन्यथा {
		चयन (sshkey_type_from_shortname(कुंजी_type_name)) {
		हाल कुंजी_ECDSA_CERT:
		हाल कुंजी_ECDSA:
			name = _PATH_SSH_CLIENT_ID_ECDSA;
			अवरोध;
		हाल कुंजी_ECDSA_SK_CERT:
		हाल कुंजी_ECDSA_SK:
			name = _PATH_SSH_CLIENT_ID_ECDSA_SK;
			अवरोध;
		हाल कुंजी_RSA_CERT:
		हाल कुंजी_RSA:
			name = _PATH_SSH_CLIENT_ID_RSA;
			अवरोध;
		हाल कुंजी_ED25519:
		हाल कुंजी_ED25519_CERT:
			name = _PATH_SSH_CLIENT_ID_ED25519;
			अवरोध;
		हाल कुंजी_ED25519_SK:
		हाल कुंजी_ED25519_SK_CERT:
			name = _PATH_SSH_CLIENT_ID_ED25519_SK;
			अवरोध;
		हाल कुंजी_MLDSA44_ED25519:
		हाल कुंजी_MLDSA44_ED25519_CERT:
			name = _PATH_SSH_CLIENT_ID_MLDSA44_ED25519;
			अवरोध;
		शेष:
			fatal("bad key type");
		}
	}
	snprintf(identity_file, माप(identity_file),
	    "%s/%s", pw->pw_dir, name);
	म_लिखो("%s (%s): ", prompt, identity_file);
	ख_साफ(मानक_निकास);
	अगर (ख_माला_लो(buf, माप(buf), मानक_निवेश) == शून्य)
		निकास(1);
	buf[म_खोज(buf, "\n")] = '\0';
	अगर (म_भेद(buf, "") != 0)
		strlcpy(identity_file, buf, माप(identity_file));
	have_identity = 1;
}

अटल काष्ठा sshkey *
load_identity(स्थिर अक्षर *filename, अक्षर **commentp)
{
	अक्षर *prompt, *pass;
	काष्ठा sshkey *prv;
	पूर्णांक r;

	अगर (commentp != शून्य)
		*commentp = शून्य;
	अगर ((r = sshkey_load_private(filename, "", &prv, commentp)) == 0)
		वापस prv;
	अगर (r != SSH_ERR_कुंजी_WRONG_PASSPHRASE)
		fatal_r(r, "Load key \"%s\"", filename);
	अगर (identity_passphrase)
		pass = xstrdup(identity_passphrase);
	अन्यथा {
		xasprintf(&prompt, "Enter passphrase for \"%s\": ", filename);
		pass = read_passphrase(prompt, RP_ALLOW_STDIN);
		मुक्त(prompt);
	}
	r = sshkey_load_private(filename, pass, &prv, commentp);
	freezero(pass, म_माप(pass));
	अगर (r != 0)
		fatal_r(r, "Load key \"%s\"", filename);
	वापस prv;
}

#घोषणा SSH_COM_PUBLIC_BEGIN		"---- BEGIN SSH2 PUBLIC KEY ----"
#घोषणा SSH_COM_PUBLIC_END		"---- END SSH2 PUBLIC KEY ----"
#घोषणा SSH_COM_PRIVATE_BEGIN		"---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----"
#घोषणा	SSH_COM_PRIVATE_कुंजी_MAGIC	0x3f6ff9eb

#अगर_घोषित WITH_OPENSSL
अटल व्योम
do_convert_to_ssh2(काष्ठा passwd *pw, काष्ठा sshkey *k)
{
	काष्ठा sshbuf *b;
	अक्षर comment[61], *b64;
	पूर्णांक r;

	अगर ((b = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = sshkey_putb(k, b)) != 0)
		fatal_fr(r, "put key");
	अगर ((b64 = sshbuf_dtob64_string(b, 1)) == शून्य)
		fatal_f("sshbuf_dtob64_string failed");

	/* Comment + surrounds must fit into 72 chars (RFC 4716 sec 3.3) */
	snprintf(comment, माप(comment),
	    "%u-bit %s, converted by %s@%s from OpenSSH",
	    sshkey_आकार(k), sshkey_type(k),
	    pw->pw_name, hostname);

	sshkey_free(k);
	sshbuf_free(b);

	ख_लिखो(मानक_निकास, "%s\n", SSH_COM_PUBLIC_BEGIN);
	ख_लिखो(मानक_निकास, "Comment: \"%s\"\n%s", comment, b64);
	ख_लिखो(मानक_निकास, "%s\n", SSH_COM_PUBLIC_END);
	मुक्त(b64);
}

अटल व्योम
do_convert_to_pkcs8(काष्ठा sshkey *k)
{
	चयन (sshkey_type_plain(k->type)) {
	हाल कुंजी_RSA:
		अगर (!PEM_write_RSA_PUBKEY(मानक_निकास,
		    EVP_PKEY_get0_RSA(k->pkey)))
			fatal("PEM_write_RSA_PUBKEY failed");
		अवरोध;
	हाल कुंजी_ECDSA:
		अगर (!PEM_write_EC_PUBKEY(मानक_निकास,
		    EVP_PKEY_get0_EC_कुंजी(k->pkey)))
			fatal("PEM_write_EC_PUBKEY failed");
		अवरोध;
	शेष:
		fatal_f("unsupported key type %s", sshkey_type(k));
	}
}

अटल व्योम
do_convert_to_pem(काष्ठा sshkey *k)
{
	चयन (sshkey_type_plain(k->type)) {
	हाल कुंजी_RSA:
		अगर (!PEM_write_RSAPublic_कुंजी(मानक_निकास,
		    EVP_PKEY_get0_RSA(k->pkey)))
			fatal("PEM_write_RSAPublicKey failed");
		अवरोध;
	हाल कुंजी_ECDSA:
		अगर (!PEM_write_EC_PUBKEY(मानक_निकास,
		    EVP_PKEY_get0_EC_कुंजी(k->pkey)))
			fatal("PEM_write_EC_PUBKEY failed");
		अवरोध;
	शेष:
		fatal_f("unsupported key type %s", sshkey_type(k));
	}
}

अटल व्योम
do_convert_to_hexdump(काष्ठा sshkey *k)
{
	काष्ठा sshbuf *b;
	पूर्णांक r;

	अगर ((b = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	/* pubkey */
	अगर ((r = sshkey_putb(k, b)) != 0)
		fatal_fr(r, "serialise private");
	म_लिखो("Public %s key:\n", sshkey_type(k));
	sshbuf_dump(b, मानक_निकास);
	sshbuf_reset(b);
	अगर ((r = sshkey_private_serialize(k, b)) != 0) {
		debug_fr(r, "serialise private");
		जाओ out;
	}
	म_लिखो("\nPrivate %s key:\n", sshkey_type(k));
	sshbuf_dump(b, मानक_निकास);
 out:
	sshbuf_free(b);
}

अटल व्योम
do_convert_to(काष्ठा passwd *pw)
{
	काष्ठा sshkey *k = शून्य;
	काष्ठा stat st;
	पूर्णांक r;

	अगर (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	अगर (stat(identity_file, &st) == -1)
		fatal("%s: %s: %s", __progname, identity_file, म_त्रुटि(त्रुटि_सं));

	/* If we're trying to hexdump, then prefer the private key */
	अगर (convert_format == FMT_HEXDUMP) {
		अगर ((r = sshkey_load_private(identity_file,
		    शून्य, &k, शून्य)) != 0 &&
		    r == SSH_ERR_कुंजी_WRONG_PASSPHRASE)
			k = load_identity(identity_file, शून्य);
	}
	अगर (k == शून्य && (r = sshkey_load_public(identity_file, &k, शून्य)) != 0)
		k = load_identity(identity_file, शून्य);

	चयन (convert_format) {
	हाल FMT_RFC4716:
		do_convert_to_ssh2(pw, k);
		अवरोध;
	हाल FMT_PKCS8:
		do_convert_to_pkcs8(k);
		अवरोध;
	हाल FMT_PEM:
		do_convert_to_pem(k);
		अवरोध;
	हाल FMT_HEXDUMP:
		do_convert_to_hexdump(k);
		अवरोध;
	शेष:
		fatal_f("unknown key format %d", convert_format);
	}
}

/*
 * This is almost exactly the bignum1 encoding, but with 32 bit for length
 * instead of 16.
 */
अटल व्योम
बफर_get_bignum_bits(काष्ठा sshbuf *b, BIGNUM *मूल्य)
{
	u_int bytes, bignum_bits;
	पूर्णांक r;

	अगर ((r = sshbuf_get_u32(b, &bignum_bits)) != 0)
		fatal_fr(r, "parse");
	bytes = (bignum_bits + 7) / 8;
	अगर (sshbuf_len(b) < bytes)
		fatal_f("input buffer too small: need %d have %zu",
		    bytes, sshbuf_len(b));
	अगर (BN_bin2bn(sshbuf_ptr(b), bytes, मूल्य) == शून्य)
		fatal_f("BN_bin2bn failed");
	अगर ((r = sshbuf_consume(b, bytes)) != 0)
		fatal_fr(r, "consume");
}

अटल काष्ठा sshkey *
do_convert_private_ssh2(काष्ठा sshbuf *b)
{
	काष्ठा sshkey *कुंजी = शून्य;
	अक्षर *type, *cipher;
	स्थिर अक्षर *alg = शून्य;
	u_char e1, e2, e3, *sig = शून्य, तथ्य[] = "abcde12345";
	पूर्णांक r, rlen, ktype;
	u_int magic, i1, i2, i3, i4;
	माप_प्रकार slen;
	u_long e;
	BIGNUM *rsa_n = शून्य, *rsa_e = शून्य, *rsa_d = शून्य;
	BIGNUM *rsa_p = शून्य, *rsa_q = शून्य, *rsa_iqmp = शून्य;
	BIGNUM *rsa_dmp1 = शून्य, *rsa_dmq1 = शून्य;
	RSA *rsa = शून्य;

	अगर ((r = sshbuf_get_u32(b, &magic)) != 0)
		fatal_fr(r, "parse magic");

	अगर (magic != SSH_COM_PRIVATE_कुंजी_MAGIC) {
		error("bad magic 0x%x != 0x%x", magic,
		    SSH_COM_PRIVATE_कुंजी_MAGIC);
		वापस शून्य;
	}
	अगर ((r = sshbuf_get_u32(b, &i1)) != 0 ||
	    (r = sshbuf_get_cstring(b, &type, शून्य)) != 0 ||
	    (r = sshbuf_get_cstring(b, &cipher, शून्य)) != 0 ||
	    (r = sshbuf_get_u32(b, &i2)) != 0 ||
	    (r = sshbuf_get_u32(b, &i3)) != 0 ||
	    (r = sshbuf_get_u32(b, &i4)) != 0)
		fatal_fr(r, "parse");
	debug("ignore (%d %d %d %d)", i1, i2, i3, i4);
	अगर (म_भेद(cipher, "none") != 0) {
		error("unsupported cipher %s", cipher);
		मुक्त(cipher);
		मुक्त(type);
		वापस शून्य;
	}
	मुक्त(cipher);

	अगर (म_माला(type, "rsa")) {
		ktype = कुंजी_RSA;
	} अन्यथा {
		मुक्त(type);
		वापस शून्य;
	}
	अगर ((कुंजी = sshkey_new(ktype)) == शून्य)
		fatal("sshkey_new failed");
	मुक्त(type);

	चयन (कुंजी->type) {
	हाल कुंजी_RSA:
		अगर ((r = sshbuf_get_u8(b, &e1)) != 0 ||
		    (e1 < 30 && (r = sshbuf_get_u8(b, &e2)) != 0) ||
		    (e1 < 30 && (r = sshbuf_get_u8(b, &e3)) != 0))
			fatal_fr(r, "parse RSA");
		e = e1;
		debug("e %lx", e);
		अगर (e < 30) {
			e <<= 8;
			e += e2;
			debug("e %lx", e);
			e <<= 8;
			e += e3;
			debug("e %lx", e);
		}
		अगर ((rsa_e = BN_new()) == शून्य)
			fatal_f("BN_new");
		अगर (!BN_set_word(rsa_e, e)) {
			BN_clear_free(rsa_e);
			sshkey_free(कुंजी);
			वापस शून्य;
		}
		अगर ((rsa_n = BN_new()) == शून्य ||
		    (rsa_d = BN_new()) == शून्य ||
		    (rsa_p = BN_new()) == शून्य ||
		    (rsa_q = BN_new()) == शून्य ||
		    (rsa_iqmp = BN_new()) == शून्य)
			fatal_f("BN_new");
		बफर_get_bignum_bits(b, rsa_d);
		बफर_get_bignum_bits(b, rsa_n);
		बफर_get_bignum_bits(b, rsa_iqmp);
		बफर_get_bignum_bits(b, rsa_q);
		बफर_get_bignum_bits(b, rsa_p);
		अगर ((r = ssh_rsa_complete_crt_parameters(rsa_d, rsa_p, rsa_q,
		    rsa_iqmp, &rsa_dmp1, &rsa_dmq1)) != 0)
			fatal_fr(r, "generate RSA CRT parameters");
		EVP_PKEY_free(कुंजी->pkey);
		अगर ((कुंजी->pkey = EVP_PKEY_new()) == शून्य)
			fatal_f("EVP_PKEY_new failed");
		अगर ((rsa = RSA_new()) == शून्य)
			fatal_f("RSA_new failed");
		अगर (!RSA_set0_कुंजी(rsa, rsa_n, rsa_e, rsa_d))
			fatal_f("RSA_set0_key failed");
		rsa_n = rsa_e = rsa_d = शून्य; /* transferred */
		अगर (!RSA_set0_factors(rsa, rsa_p, rsa_q))
			fatal_f("RSA_set0_factors failed");
		rsa_p = rsa_q = शून्य; /* transferred */
		अगर (RSA_set0_crt_params(rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp) != 1)
			fatal_f("RSA_set0_crt_params failed");
		rsa_dmp1 = rsa_dmq1 = rsa_iqmp = शून्य;
		अगर (EVP_PKEY_set1_RSA(कुंजी->pkey, rsa) != 1)
			fatal_f("EVP_PKEY_set1_RSA failed");
		RSA_free(rsa);
		alg = "rsa-sha2-256";
		अवरोध;
	}
	rlen = sshbuf_len(b);
	अगर (rlen != 0)
		error_f("remaining bytes in key blob %d", rlen);

	/* try the key */
	अगर ((r = sshkey_sign(कुंजी, &sig, &slen, तथ्य, माप(तथ्य),
	    alg, शून्य, शून्य, 0)) != 0)
		error_fr(r, "signing with converted key failed");
	अन्यथा अगर ((r = sshkey_verify(कुंजी, sig, slen, तथ्य, माप(तथ्य),
	    alg, 0, शून्य)) != 0)
		error_fr(r, "verification with converted key failed");
	अगर (r != 0) {
		sshkey_free(कुंजी);
		मुक्त(sig);
		वापस शून्य;
	}
	मुक्त(sig);
	वापस कुंजी;
}

अटल पूर्णांक
get_पंक्ति(खाता *fp, अक्षर *पंक्ति, माप_प्रकार len)
{
	पूर्णांक c;
	माप_प्रकार pos = 0;

	पंक्ति[0] = '\0';
	जबतक ((c = ख_अक्षर_लो(fp)) != खातापूर्ण) {
		अगर (pos >= len - 1)
			fatal("input line too long.");
		चयन (c) {
		हाल '\r':
			c = ख_अक्षर_लो(fp);
			अगर (c != खातापूर्ण && c != '\n' && अक्षर_वापस(c, fp) == खातापूर्ण)
				fatal("unget: %s", म_त्रुटि(त्रुटि_सं));
			वापस pos;
		हाल '\n':
			वापस pos;
		}
		पंक्ति[pos++] = c;
		पंक्ति[pos] = '\0';
	}
	/* We reached EOF */
	वापस -1;
}

अटल व्योम
do_convert_from_ssh2(काष्ठा passwd *pw, काष्ठा sshkey **k, पूर्णांक *निजी)
{
	पूर्णांक r, blen, escaped = 0;
	u_int len;
	अक्षर पंक्ति[1024];
	काष्ठा sshbuf *buf;
	अक्षर encoded[8096];
	खाता *fp;

	अगर ((buf = sshbuf_new()) == शून्य)
		fatal("sshbuf_new failed");
	अगर ((fp = ख_खोलो(identity_file, "r")) == शून्य)
		fatal("%s: %s: %s", __progname, identity_file, म_त्रुटि(त्रुटि_सं));
	encoded[0] = '\0';
	जबतक ((blen = get_पंक्ति(fp, पंक्ति, माप(पंक्ति))) != -1) {
		अगर (blen > 0 && पंक्ति[blen - 1] == '\\')
			escaped++;
		अगर (म_भेदन(पंक्ति, "----", 4) == 0 ||
		    म_माला(पंक्ति, ": ") != शून्य) {
			अगर (म_माला(पंक्ति, SSH_COM_PRIVATE_BEGIN) != शून्य)
				*निजी = 1;
			अगर (म_माला(पंक्ति, " END ") != शून्य) {
				अवरोध;
			}
			/* fprintf(stderr, "ignore: %s", line); */
			जारी;
		}
		अगर (escaped) {
			escaped--;
			/* fprintf(stderr, "escaped: %s", line); */
			जारी;
		}
		strlcat(encoded, पंक्ति, माप(encoded));
	}
	len = म_माप(encoded);
	अगर (((len % 4) == 3) &&
	    (encoded[len-1] == '=') &&
	    (encoded[len-2] == '=') &&
	    (encoded[len-3] == '='))
		encoded[len-3] = '\0';
	अगर ((r = sshbuf_b64tod(buf, encoded)) != 0)
		fatal_fr(r, "base64 decode");
	अगर (*निजी) {
		अगर ((*k = do_convert_private_ssh2(buf)) == शून्य)
			fatal_f("private key conversion failed");
	} अन्यथा अगर ((r = sshkey_fromb(buf, k)) != 0)
		fatal_fr(r, "parse key");
	sshbuf_free(buf);
	ख_बंद(fp);
}

अटल व्योम
do_convert_from_pkcs8(काष्ठा sshkey **k, पूर्णांक *निजी)
{
	EVP_PKEY *pubkey;
	खाता *fp;

	अगर ((fp = ख_खोलो(identity_file, "r")) == शून्य)
		fatal("%s: %s: %s", __progname, identity_file, म_त्रुटि(त्रुटि_सं));
	अगर ((pubkey = PEM_read_PUBKEY(fp, शून्य, शून्य, शून्य)) == शून्य) {
		fatal_f("%s is not a recognised public key format",
		    identity_file);
	}
	ख_बंद(fp);
	चयन (EVP_PKEY_base_id(pubkey)) {
	हाल EVP_PKEY_RSA:
		अगर ((*k = sshkey_new(कुंजी_UNSPEC)) == शून्य)
			fatal("sshkey_new failed");
		(*k)->type = कुंजी_RSA;
		(*k)->pkey = pubkey;
		pubkey = शून्य;
		अवरोध;
	हाल EVP_PKEY_EC:
		अगर ((*k = sshkey_new(कुंजी_UNSPEC)) == शून्य)
			fatal("sshkey_new failed");
		अगर (((*k)->ecdsa_nid = sshkey_ecdsa_fixup_group(pubkey)) == -1)
			fatal("sshkey_ecdsa_fixup_group failed");
		(*k)->type = कुंजी_ECDSA;
		(*k)->pkey = pubkey;
		pubkey = शून्य;
		अवरोध;
	शेष:
		fatal_f("unsupported pubkey type %d",
		    EVP_PKEY_base_id(pubkey));
	}
	EVP_PKEY_free(pubkey);
}

अटल व्योम
do_convert_from_pem(काष्ठा sshkey **k, पूर्णांक *निजी)
{
	खाता *fp;
	RSA *rsa;

	अगर ((fp = ख_खोलो(identity_file, "r")) == शून्य)
		fatal("%s: %s: %s", __progname, identity_file, म_त्रुटि(त्रुटि_सं));
	अगर ((rsa = PEM_read_RSAPublic_कुंजी(fp, शून्य, शून्य, शून्य)) != शून्य) {
		अगर ((*k = sshkey_new(कुंजी_UNSPEC)) == शून्य)
			fatal("sshkey_new failed");
		अगर (((*k)->pkey = EVP_PKEY_new()) == शून्य)
			fatal("EVP_PKEY_new failed");
		(*k)->type = कुंजी_RSA;
		अगर (EVP_PKEY_set1_RSA((*k)->pkey, rsa) != 1)
			fatal("EVP_PKEY_set1_RSA failed");
		RSA_free(rsa);
		ख_बंद(fp);
		वापस;
	}
	fatal_f("unrecognised raw private key format");
}

अटल व्योम
do_convert_from(काष्ठा passwd *pw)
{
	काष्ठा sshkey *k = शून्य;
	पूर्णांक r, निजी = 0, ok = 0;
	काष्ठा stat st;

	अगर (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	अगर (stat(identity_file, &st) == -1)
		fatal("%s: %s: %s", __progname, identity_file, म_त्रुटि(त्रुटि_सं));

	चयन (convert_format) {
	हाल FMT_RFC4716:
		do_convert_from_ssh2(pw, &k, &निजी);
		अवरोध;
	हाल FMT_PKCS8:
		do_convert_from_pkcs8(&k, &निजी);
		अवरोध;
	हाल FMT_PEM:
		do_convert_from_pem(&k, &निजी);
		अवरोध;
	शेष:
		fatal_f("unknown key format %d", convert_format);
	}

	अगर (!निजी) {
		अगर ((r = sshkey_write(k, मानक_निकास)) == 0)
			ok = 1;
		अगर (ok)
			ख_लिखो(मानक_निकास, "\n");
	} अन्यथा {
		चयन (k->type) {
		हाल कुंजी_ECDSA:
			ok = PEM_write_ECPrivate_कुंजी(मानक_निकास,
			    EVP_PKEY_get0_EC_कुंजी(k->pkey), शून्य, शून्य, 0,
			    शून्य, शून्य);
			अवरोध;
		हाल कुंजी_RSA:
			ok = PEM_write_RSAPrivate_कुंजी(मानक_निकास,
			    EVP_PKEY_get0_RSA(k->pkey), शून्य, शून्य, 0,
			    शून्य, शून्य);
			अवरोध;
		शेष:
			fatal_f("unsupported key type %s", sshkey_type(k));
		}
	}

	अगर (!ok)
		fatal("key write failed");
	sshkey_free(k);
}
#पूर्ण_अगर

अटल व्योम
do_print_public(काष्ठा passwd *pw)
{
	काष्ठा sshkey *prv;
	काष्ठा stat st;
	पूर्णांक r;
	अक्षर *comment = शून्य;

	अगर (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	अगर (stat(identity_file, &st) == -1)
		fatal("%s: %s", identity_file, म_त्रुटि(त्रुटि_सं));
	prv = load_identity(identity_file, &comment);
	अगर ((r = sshkey_write(prv, मानक_निकास)) != 0)
		fatal_fr(r, "write key");
	अगर (comment != शून्य && *comment != '\0')
		ख_लिखो(मानक_निकास, " %s", comment);
	ख_लिखो(मानक_निकास, "\n");
	अगर (sshkey_is_sk(prv)) {
		debug("sk_application: \"%s\", sk_flags 0x%02x",
			prv->sk_application, prv->sk_flags);
	}
	sshkey_free(prv);
	मुक्त(comment);
	निकास(0);
}

अटल व्योम
do_download(काष्ठा passwd *pw)
{
#अगर_घोषित ENABLE_PKCS11
	काष्ठा sshkey **कुंजियाँ = शून्य;
	पूर्णांक i, nkeys;
	क्रमागत sshkey_fp_rep rep;
	पूर्णांक fptype;
	अक्षर *fp, *ra, **comments = शून्य;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;

	pkcs11_init(1);
	nkeys = pkcs11_add_provider(pkcs11provider, शून्य, &कुंजियाँ, &comments);
	अगर (nkeys <= 0)
		fatal("cannot read public key from pkcs11");
	क्रम (i = 0; i < nkeys; i++) {
		अगर (print_fingerprint) {
			fp = sshkey_fingerprint(कुंजियाँ[i], fptype, rep);
			ra = sshkey_fingerprint(कुंजियाँ[i], fingerprint_hash,
			    SSH_FP_RANDOMART);
			अगर (fp == शून्य || ra == शून्य)
				fatal_f("sshkey_fingerprint fail");
			म_लिखो("%u %s %s (PKCS11 key)\n", sshkey_आकार(कुंजियाँ[i]),
			    fp, sshkey_type(कुंजियाँ[i]));
			अगर (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
				म_लिखो("%s\n", ra);
			मुक्त(ra);
			मुक्त(fp);
		} अन्यथा {
			(व्योम) sshkey_write(कुंजियाँ[i], मानक_निकास); /* XXX check */
			ख_लिखो(मानक_निकास, "%s%s\n",
			    *(comments[i]) == '\0' ? "" : " ", comments[i]);
		}
		मुक्त(comments[i]);
		sshkey_free(कुंजियाँ[i]);
	}
	मुक्त(comments);
	मुक्त(कुंजियाँ);
	pkcs11_terminate();
	निकास(0);
#अन्यथा
	fatal("no pkcs11 support");
#पूर्ण_अगर /* ENABLE_PKCS11 */
}

अटल काष्ठा sshkey *
try_read_कुंजी(अक्षर **cpp)
{
	काष्ठा sshkey *ret;
	पूर्णांक r;

	अगर ((ret = sshkey_new(कुंजी_UNSPEC)) == शून्य)
		fatal("sshkey_new failed");
	अगर ((r = sshkey_read(ret, cpp)) == 0)
		वापस ret;
	/* Not a key */
	sshkey_free(ret);
	वापस शून्य;
}

अटल व्योम
fingerprint_one_कुंजी(स्थिर काष्ठा sshkey *खुला, स्थिर अक्षर *comment)
{
	अक्षर *fp = शून्य, *ra = शून्य;
	क्रमागत sshkey_fp_rep rep;
	पूर्णांक fptype;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;
	fp = sshkey_fingerprint(खुला, fptype, rep);
	ra = sshkey_fingerprint(खुला, fingerprint_hash, SSH_FP_RANDOMART);
	अगर (fp == शून्य || ra == शून्य)
		fatal_f("sshkey_fingerprint failed");
	mprintf("%u %s %s (%s)\n", sshkey_आकार(खुला), fp,
	    comment ? comment : "no comment", sshkey_type(खुला));
	अगर (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
		म_लिखो("%s\n", ra);
	मुक्त(ra);
	मुक्त(fp);
}

अटल व्योम
fingerprint_private(स्थिर अक्षर *path)
{
	काष्ठा stat st;
	अक्षर *comment = शून्य;
	काष्ठा sshkey *privkey = शून्य, *pubkey = शून्य;
	पूर्णांक r;

	अगर (stat(identity_file, &st) == -1)
		fatal("%s: %s", path, म_त्रुटि(त्रुटि_सं));
	अगर ((r = sshkey_load_public(path, &pubkey, &comment)) != 0)
		debug_r(r, "load public \"%s\"", path);
	अगर (pubkey == शून्य || comment == शून्य || *comment == '\0') {
		मुक्त(comment);
		अगर ((r = sshkey_load_private(path, शून्य,
		    &privkey, &comment)) != 0)
			debug_r(r, "load private \"%s\"", path);
	}
	अगर (pubkey == शून्य && privkey == शून्य)
		fatal("%s is not a key file.", path);

	fingerprint_one_कुंजी(pubkey == शून्य ? privkey : pubkey, comment);
	sshkey_free(pubkey);
	sshkey_free(privkey);
	मुक्त(comment);
}

अटल व्योम
do_fingerprint(काष्ठा passwd *pw)
{
	खाता *f;
	काष्ठा sshkey *खुला = शून्य;
	अक्षर *comment = शून्य, *cp, *ep, *पंक्ति = शून्य;
	माप_प्रकार linesize = 0;
	पूर्णांक i, invalid = 1;
	स्थिर अक्षर *path;
	u_long lnum = 0;

	अगर (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	path = identity_file;

	अगर (म_भेद(identity_file, "-") == 0) {
		f = मानक_निवेश;
		path = "(stdin)";
	} अन्यथा अगर ((f = ख_खोलो(path, "r")) == शून्य)
		fatal("%s: %s: %s", __progname, path, म_त्रुटि(त्रुटि_सं));

	जबतक (getline(&पंक्ति, &linesize, f) != -1) {
		lnum++;
		cp = पंक्ति;
		cp[म_खोज(cp, "\r\n")] = '\0';
		/* Trim leading space and comments */
		cp = पंक्ति + म_अखोज(पंक्ति, " \t");
		अगर (*cp == '#' || *cp == '\0')
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
		अगर (lnum == 1 && म_भेद(identity_file, "-") != 0 &&
		    म_माला(cp, "PRIVATE KEY") != शून्य) {
			मुक्त(पंक्ति);
			ख_बंद(f);
			fingerprint_private(path);
			निकास(0);
		}

		/*
		 * If it's not a private key, then this must be prepared to
		 * accept a public key prefixed with a hostname or options.
		 * Try a bare key first, otherwise skip the leading stuff.
		 */
		comment = शून्य;
		अगर ((खुला = try_read_कुंजी(&cp)) == शून्य) {
			i = म_से_दीर्घ(cp, &ep, 10);
			अगर (i == 0 || ep == शून्य ||
			    (*ep != ' ' && *ep != '\t')) {
				पूर्णांक quoted = 0;

				comment = cp;
				क्रम (; *cp && (quoted || (*cp != ' ' &&
				    *cp != '\t')); cp++) {
					अगर (*cp == '\\' && cp[1] == '"')
						cp++;	/* Skip both */
					अन्यथा अगर (*cp == '"')
						quoted = !quoted;
				}
				अगर (!*cp)
					जारी;
				*cp++ = '\0';
			}
		}
		/* Retry after parsing leading hostname/key options */
		अगर (खुला == शून्य && (खुला = try_read_कुंजी(&cp)) == शून्य) {
			debug("%s:%lu: not a public key", path, lnum);
			जारी;
		}

		/* Find trailing comment, if any */
		क्रम (; *cp == ' ' || *cp == '\t'; cp++)
			;
		अगर (*cp != '\0' && *cp != '#')
			comment = cp;

		fingerprint_one_कुंजी(खुला, comment);
		sshkey_free(खुला);
		invalid = 0; /* One good key in the file is sufficient */
	}
	ख_बंद(f);
	मुक्त(पंक्ति);

	अगर (invalid)
		fatal("%s is not a public key file.", path);
	निकास(0);
}

अटल व्योम
do_gen_all_hostkeys(काष्ठा passwd *pw)
{
	काष्ठा {
		अक्षर *कुंजी_type;
		अक्षर *कुंजी_type_display;
		अक्षर *path;
	} कुंजी_types[] = {
#अगर_घोषित WITH_OPENSSL
		{ "rsa", "RSA" ,PATH_HOST_RSA_कुंजी_FILE },
		{ "ecdsa", "ECDSA",PATH_HOST_ECDSA_कुंजी_FILE },
#पूर्ण_अगर /* WITH_OPENSSL */
		{ "ed25519", "ED25519",PATH_HOST_ED25519_कुंजी_FILE },
#अगर_घोषित USE_MLDSA
		{ "mldsa44-ed25519", "MLDSA44-ED25519",
		     PATH_HOST_MLDSA44_ED25519_कुंजी_FILE },
#पूर्ण_अगर
		{ शून्य, शून्य, शून्य }
	};

	uint32_t bits = 0;
	पूर्णांक first = 0;
	काष्ठा stat st;
	काष्ठा sshkey *निजी, *खुला;
	अक्षर comment[कुंजी_COMMENT_MAX], *prv_tmp, *pub_tmp, *prv_file, *pub_file;
	पूर्णांक i, type, fd, r;

	क्रम (i = 0; कुंजी_types[i].कुंजी_type; i++) {
		खुला = निजी = शून्य;
		prv_tmp = pub_tmp = prv_file = pub_file = शून्य;

		xasprintf(&prv_file, "%s%s",
		    identity_file, कुंजी_types[i].path);

		/* Check whether private key exists and is not zero-length */
		अगर (stat(prv_file, &st) == 0) {
			अगर (st.st_size != 0)
				जाओ अग्र;
		} अन्यथा अगर (त्रुटि_सं != ENOENT) {
			error("Could not stat %s: %s", कुंजी_types[i].path,
			    म_त्रुटि(त्रुटि_सं));
			जाओ failnext;
		}

		/*
		 * Private key doesn't exist or is invalid; proceed with
		 * key generation.
		 */
		xasprintf(&prv_tmp, "%s%s.XXXXXXXXXX",
		    identity_file, कुंजी_types[i].path);
		xasprintf(&pub_tmp, "%s%s.pub.XXXXXXXXXX",
		    identity_file, कुंजी_types[i].path);
		xasprintf(&pub_file, "%s%s.pub",
		    identity_file, कुंजी_types[i].path);

		अगर (first == 0) {
			first = 1;
			म_लिखो("%s: generating new host keys: ", __progname);
		}
		म_लिखो("%s ", कुंजी_types[i].कुंजी_type_display);
		ख_साफ(मानक_निकास);
		type = sshkey_type_from_shortname(कुंजी_types[i].कुंजी_type);
		अगर ((fd = mkstemp(prv_tmp)) == -1) {
			error("Could not save your private key in %s: %s",
			    prv_tmp, म_त्रुटि(त्रुटि_सं));
			जाओ failnext;
		}
		(व्योम)बंद(fd); /* just using mkstemp() to reserve a name */
		bits = 0;
		type_bits_valid(type, शून्य, &bits);
		अगर ((r = sshkey_generate(type, bits, &निजी)) != 0) {
			error_r(r, "sshkey_generate failed");
			जाओ failnext;
		}
		अगर ((r = sshkey_from_private(निजी, &खुला)) != 0)
			fatal_fr(r, "sshkey_from_private");
		snprintf(comment, माप comment, "%s@%s", pw->pw_name,
		    hostname);
		अगर ((r = sshkey_save_private(निजी, prv_tmp, "",
		    comment, private_कुंजी_format, openssh_format_cipher,
		    rounds)) != 0) {
			error_r(r, "Saving key \"%s\" failed", prv_tmp);
			जाओ failnext;
		}
		अगर ((fd = mkstemp(pub_tmp)) == -1) {
			error("Could not save your public key in %s: %s",
			    pub_tmp, म_त्रुटि(त्रुटि_सं));
			जाओ failnext;
		}
		(व्योम)fchmod(fd, 0644);
		(व्योम)बंद(fd);
		अगर ((r = sshkey_save_public(खुला, pub_tmp, comment)) != 0) {
			error_r(r, "Unable to save public key to %s",
			    identity_file);
			जाओ failnext;
		}

		/* Rename temporary files to their permanent locations. */
		अगर (नाम(pub_tmp, pub_file) != 0) {
			error("Unable to move %s into position: %s",
			    pub_file, म_त्रुटि(त्रुटि_सं));
			जाओ failnext;
		}
		अगर (नाम(prv_tmp, prv_file) != 0) {
			error("Unable to move %s into position: %s",
			    कुंजी_types[i].path, म_त्रुटि(त्रुटि_सं));
 failnext:
			first = 0;
			जाओ अग्र;
		}
 अग्र:
		sshkey_free(निजी);
		sshkey_free(खुला);
		मुक्त(prv_tmp);
		मुक्त(pub_tmp);
		मुक्त(prv_file);
		मुक्त(pub_file);
	}
	अगर (first != 0)
		म_लिखो("\n");
}

काष्ठा known_hosts_ctx {
	स्थिर अक्षर *host;	/* Hostname searched for in find/delete case */
	खाता *out;		/* Output file, stdout for find_hosts case */
	पूर्णांक has_unhashed;	/* When hashing, original had unhashed hosts */
	पूर्णांक found_कुंजी;		/* For find/delete, host was found */
	पूर्णांक invalid;		/* File contained invalid items; don't delete */
	पूर्णांक hash_hosts;		/* Hash hostnames as we go */
	पूर्णांक find_host;		/* Search for specific hostname */
	पूर्णांक delete_host;	/* Delete host from known_hosts */
};

अटल पूर्णांक
known_hosts_hash(काष्ठा hostkey_foreach_पंक्ति *l, व्योम *_ctx)
{
	काष्ठा known_hosts_ctx *ctx = (काष्ठा known_hosts_ctx *)_ctx;
	अक्षर *hashed, *cp, *hosts, *ohosts;
	पूर्णांक has_wild = l->hosts && म_खोज(l->hosts, "*?!") != म_माप(l->hosts);
	पूर्णांक was_hashed = l->hosts && l->hosts[0] == HASH_DELIM;

	चयन (l->status) {
	हाल HKF_STATUS_OK:
	हाल HKF_STATUS_MATCHED:
		/*
		 * Don't hash hosts already hashed, with wildcard
		 * characters or a CA/revocation marker.
		 */
		अगर (was_hashed || has_wild || l->marker != MRK_NONE) {
			ख_लिखो(ctx->out, "%s\n", l->पंक्ति);
			अगर (has_wild && !ctx->find_host) {
				logit("%s:%lu: ignoring host name "
				    "with wildcard: %.64s", l->path,
				    l->linenum, l->hosts);
			}
			वापस 0;
		}
		/*
		 * Split any comma-separated hostnames from the host list,
		 * hash and store separately.
		 */
		ohosts = hosts = xstrdup(l->hosts);
		जबतक ((cp = strsep(&hosts, ",")) != शून्य && *cp != '\0') {
			lowercase(cp);
			अगर ((hashed = host_hash(cp, शून्य, 0)) == शून्य)
				fatal("hash_host failed");
			ख_लिखो(ctx->out, "%s %s\n", hashed, l->rawkey);
			मुक्त(hashed);
			ctx->has_unhashed = 1;
		}
		मुक्त(ohosts);
		वापस 0;
	हाल HKF_STATUS_INVALID:
		/* Retain invalid lines, but mark file as invalid. */
		ctx->invalid = 1;
		logit("%s:%lu: invalid line", l->path, l->linenum);
		/* FALLTHROUGH */
	शेष:
		ख_लिखो(ctx->out, "%s\n", l->पंक्ति);
		वापस 0;
	}
	/* NOTREACHED */
	वापस -1;
}

अटल पूर्णांक
known_hosts_find_delete(काष्ठा hostkey_foreach_पंक्ति *l, व्योम *_ctx)
{
	काष्ठा known_hosts_ctx *ctx = (काष्ठा known_hosts_ctx *)_ctx;
	क्रमागत sshkey_fp_rep rep;
	पूर्णांक fptype;
	अक्षर *fp = शून्य, *ra = शून्य;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;

	अगर (l->status == HKF_STATUS_MATCHED) {
		अगर (ctx->delete_host) {
			अगर (l->marker != MRK_NONE) {
				/* Don't remove CA and revocation lines */
				ख_लिखो(ctx->out, "%s\n", l->पंक्ति);
			} अन्यथा {
				/*
				 * Hostname matches and has no CA/revoke
				 * marker, delete it by *not* writing the
				 * line to ctx->out.
				 */
				ctx->found_कुंजी = 1;
				अगर (!quiet)
					म_लिखो("# Host %s found: line %lu\n",
					    ctx->host, l->linenum);
			}
			वापस 0;
		} अन्यथा अगर (ctx->find_host) {
			ctx->found_कुंजी = 1;
			अगर (!quiet) {
				म_लिखो("# Host %s found: line %lu %s\n",
				    ctx->host,
				    l->linenum, l->marker == MRK_CA ? "CA" :
				    (l->marker == MRK_REVOKE ? "REVOKED" : ""));
			}
			अगर (ctx->hash_hosts)
				known_hosts_hash(l, ctx);
			अन्यथा अगर (print_fingerprint) {
				fp = sshkey_fingerprint(l->कुंजी, fptype, rep);
				ra = sshkey_fingerprint(l->कुंजी,
				    fingerprint_hash, SSH_FP_RANDOMART);
				अगर (fp == शून्य || ra == शून्य)
					fatal_f("sshkey_fingerprint failed");
				mprintf("%s %s %s%s%s\n", ctx->host,
				    sshkey_type(l->कुंजी), fp,
				    l->comment[0] ? " " : "",
				    l->comment);
				अगर (log_level_get() >= SYSLOG_LEVEL_VERBOSE)
					म_लिखो("%s\n", ra);
				मुक्त(ra);
				मुक्त(fp);
			} अन्यथा
				ख_लिखो(ctx->out, "%s\n", l->पंक्ति);
			वापस 0;
		}
	} अन्यथा अगर (ctx->delete_host) {
		/* Retain non-matching hosts when deleting */
		अगर (l->status == HKF_STATUS_INVALID) {
			ctx->invalid = 1;
			logit("%s:%lu: invalid line", l->path, l->linenum);
		}
		ख_लिखो(ctx->out, "%s\n", l->पंक्ति);
	}
	वापस 0;
}

अटल व्योम
do_known_hosts(काष्ठा passwd *pw, स्थिर अक्षर *name, पूर्णांक find_host,
    पूर्णांक delete_host, पूर्णांक hash_hosts)
{
	अक्षर *cp, tmp[PATH_MAX], old[PATH_MAX];
	पूर्णांक r, fd, oerrno, inplace = 0;
	काष्ठा known_hosts_ctx ctx;
	u_int foreach_options;
	काष्ठा stat sb;

	अगर (!have_identity) {
		cp = tilde_expand_filename(_PATH_SSH_USER_HOSTFILE, pw->pw_uid);
		अगर (strlcpy(identity_file, cp, माप(identity_file)) >=
		    माप(identity_file))
			fatal("Specified known hosts path too long");
		मुक्त(cp);
		have_identity = 1;
	}
	अगर (stat(identity_file, &sb) != 0)
		fatal("Cannot stat %s: %s", identity_file, म_त्रुटि(त्रुटि_सं));

	स_रखो(&ctx, 0, माप(ctx));
	ctx.out = मानक_निकास;
	ctx.host = name;
	ctx.hash_hosts = hash_hosts;
	ctx.find_host = find_host;
	ctx.delete_host = delete_host;

	/*
	 * Find hosts goes to stdout, hash and deletions happen in-place
	 * A corner case is ssh-keygen -HF foo, which should go to stdout
	 */
	अगर (!find_host && (hash_hosts || delete_host)) {
		अगर (strlcpy(tmp, identity_file, माप(tmp)) >= माप(tmp) ||
		    strlcat(tmp, ".XXXXXXXXXX", माप(tmp)) >= माप(tmp) ||
		    strlcpy(old, identity_file, माप(old)) >= माप(old) ||
		    strlcat(old, ".old", माप(old)) >= माप(old))
			fatal("known_hosts path too long");
		umask(077);
		अगर ((fd = mkstemp(tmp)) == -1)
			fatal("mkstemp: %s", म_त्रुटि(त्रुटि_सं));
		अगर ((ctx.out = fdopen(fd, "w")) == शून्य) {
			oerrno = त्रुटि_सं;
			unlink(tmp);
			fatal("fdopen: %s", म_त्रुटि(oerrno));
		}
		(व्योम)fchmod(fd, sb.st_mode & 0644);
		inplace = 1;
	}
	/* XXX support identity_file == "-" for stdin */
	foreach_options = find_host ? HKF_WANT_MATCH : 0;
	foreach_options |= print_fingerprint ? HKF_WANT_PARSE_कुंजी : 0;
	अगर ((r = hostkeys_foreach(identity_file, (find_host || !hash_hosts) ?
	    known_hosts_find_delete : known_hosts_hash, &ctx, name, शून्य,
	    foreach_options, 0)) != 0) {
		अगर (inplace)
			unlink(tmp);
		fatal_fr(r, "hostkeys_foreach");
	}

	अगर (inplace)
		ख_बंद(ctx.out);

	अगर (ctx.invalid) {
		error("%s is not a valid known_hosts file.", identity_file);
		अगर (inplace) {
			error("Not replacing existing known_hosts "
			    "file because of errors");
			unlink(tmp);
		}
		निकास(1);
	} अन्यथा अगर (delete_host && !ctx.found_कुंजी) {
		logit("Host %s not found in %s", name, identity_file);
		अगर (inplace)
			unlink(tmp);
	} अन्यथा अगर (inplace) {
		/* Backup existing file */
		अगर (unlink(old) == -1 && त्रुटि_सं != ENOENT)
			fatal("unlink %.100s: %s", old, म_त्रुटि(त्रुटि_सं));
		अगर (link(identity_file, old) == -1)
			fatal("link %.100s to %.100s: %s", identity_file, old,
			    म_त्रुटि(त्रुटि_सं));
		/* Move new one into place */
		अगर (नाम(tmp, identity_file) == -1) {
			error("rename\"%s\" to \"%s\": %s", tmp, identity_file,
			    म_त्रुटि(त्रुटि_सं));
			unlink(tmp);
			unlink(old);
			निकास(1);
		}

		म_लिखो("%s updated.\n", identity_file);
		म_लिखो("Original contents retained as %s\n", old);
		अगर (ctx.has_unhashed) {
			logit("WARNING: %s contains unhashed entries", old);
			logit("Delete this file to ensure privacy "
			    "of hostnames");
		}
	}

	निकास (find_host && !ctx.found_कुंजी);
}

/*
 * Perform changing a passphrase.  The argument is the passwd structure
 * for the current user.
 */
अटल व्योम
do_change_passphrase(काष्ठा passwd *pw, अक्षर * स्थिर *opts, माप_प्रकार nopts)
{
	अक्षर *comment;
	अक्षर *old_passphrase, *passphrase1, *passphrase2;
	काष्ठा stat st;
	काष्ठा sshkey *निजी;
	पूर्णांक r;
	माप_प्रकार i;

	अगर (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	अगर (stat(identity_file, &st) == -1)
		fatal("%s: %s", identity_file, म_त्रुटि(त्रुटि_सं));
	/* Try to load the file with empty passphrase. */
	r = sshkey_load_private(identity_file, "", &निजी, &comment);
	अगर (r == SSH_ERR_कुंजी_WRONG_PASSPHRASE) {
		अगर (identity_passphrase)
			old_passphrase = xstrdup(identity_passphrase);
		अन्यथा
			old_passphrase =
			    read_passphrase("Enter old passphrase: ",
			    RP_ALLOW_STDIN);
		r = sshkey_load_private(identity_file, old_passphrase,
		    &निजी, &comment);
		freezero(old_passphrase, म_माप(old_passphrase));
		अगर (r != 0)
			जाओ badkey;
	} अन्यथा अगर (r != 0) {
 badkey:
		fatal_r(r, "Failed to load key %s", identity_file);
	}
	अगर (comment)
		mprintf("Key has comment '%s'\n", comment);

	/* All current -O options relate to FIDO keys only */
	अगर (nopts != 0 && !sshkey_is_sk(निजी)) {
		fatal("FIDO-specific option requested for non-FIDO key %s",
		    identity_file);
	}
	अगर (sshkey_is_sk(निजी)) {
		debug_f("%s: original FIDO key flags: "
		    "%stouch-required %sverify-required", identity_file,
		    (निजी->sk_flags & SSH_SK_USER_PRESENCE_REQD) ? "": "no-",
		    (निजी->sk_flags & SSH_SK_USER_VERIFICATION_REQD) ? "" : "no-");
	}
	क्रम (i = 0; i < nopts; i++) {
		अगर (strcasecmp(opts[i], "touch-required") == 0)
			निजी->sk_flags |= SSH_SK_USER_PRESENCE_REQD;
		अन्यथा अगर (strcasecmp(opts[i], "no-touch-required") == 0)
			निजी->sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
		अन्यथा अगर (strcasecmp(opts[i], "verify-required") == 0)
			निजी->sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
		अन्यथा अगर (strcasecmp(opts[i], "no-verify-required") == 0)
			निजी->sk_flags &= ~SSH_SK_USER_VERIFICATION_REQD;
		अन्यथा {
			fatal("Option \"%s\" is unsupported for "
			    "key passphrase change", opts[i]);
		}
	}
	अगर (sshkey_is_sk(निजी) && nopts != 0) {
		debug_f("%s: updated FIDO key flags: "
		    "%stouch-required %sverify-required", identity_file,
		    (निजी->sk_flags & SSH_SK_USER_PRESENCE_REQD) ? "": "no-",
		    (निजी->sk_flags & SSH_SK_USER_VERIFICATION_REQD) ? "" : "no-");
	}

	/* Ask the new passphrase (twice). */
	अगर (identity_new_passphrase) {
		passphrase1 = xstrdup(identity_new_passphrase);
		passphrase2 = शून्य;
	} अन्यथा {
		passphrase1 =
			read_passphrase("Enter new passphrase (empty for no "
			    "passphrase): ", RP_ALLOW_STDIN);
		passphrase2 = read_passphrase("Enter same passphrase again: ",
		    RP_ALLOW_STDIN);

		/* Verify that they are the same. */
		अगर (म_भेद(passphrase1, passphrase2) != 0) {
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
	अगर ((r = sshkey_save_private(निजी, identity_file, passphrase1,
	    comment, private_कुंजी_format, openssh_format_cipher, rounds)) != 0) {
		error_r(r, "Saving key \"%s\" failed", identity_file);
		freezero(passphrase1, म_माप(passphrase1));
		sshkey_free(निजी);
		मुक्त(comment);
		निकास(1);
	}
	/* Destroy the passphrase and the copy of the key in memory. */
	freezero(passphrase1, म_माप(passphrase1));
	sshkey_free(निजी);		 /* Destroys contents */
	मुक्त(comment);

	म_लिखो("Your identification has been saved with the new passphrase.\n");
	निकास(0);
}

/*
 * Print the SSHFP RR.
 */
अटल पूर्णांक
do_print_resource_record(काष्ठा passwd *pw, अक्षर *fname, अक्षर *hname,
    पूर्णांक print_generic, अक्षर * स्थिर *opts, माप_प्रकार nopts)
{
	काष्ठा sshkey *खुला;
	अक्षर *comment = शून्य;
	स्थिर अक्षर *p;
	काष्ठा stat st;
	पूर्णांक r, hash = -1;
	माप_प्रकार i;

	क्रम (i = 0; i < nopts; i++) {
		अगर ((p = strprefix(opts[i], "hashalg=", 1)) != शून्य) {
			अगर ((hash = ssh_digest_alg_by_name(p)) == -1)
				fatal("Unsupported hash algorithm");
		} अन्यथा {
			error("Invalid option \"%s\"", opts[i]);
			वापस SSH_ERR_INVALID_ARGUMENT;
		}
	}
	अगर (fname == शून्य)
		fatal_f("no filename");
	अगर (stat(fname, &st) == -1) {
		अगर (त्रुटि_सं == ENOENT)
			वापस 0;
		fatal("%s: %s", fname, म_त्रुटि(त्रुटि_सं));
	}
	अगर ((r = sshkey_load_public(fname, &खुला, &comment)) != 0)
		fatal_r(r, "Failed to read v2 public key from \"%s\"", fname);
	export_dns_rr(hname, खुला, मानक_निकास, print_generic, hash);
	sshkey_free(खुला);
	मुक्त(comment);
	वापस 1;
}

/*
 * Change the comment of a private key file.
 */
अटल व्योम
do_change_comment(काष्ठा passwd *pw, स्थिर अक्षर *identity_comment)
{
	अक्षर new_comment[कुंजी_COMMENT_MAX], *comment, *passphrase;
	काष्ठा sshkey *निजी;
	काष्ठा sshkey *खुला;
	काष्ठा stat st;
	पूर्णांक r;

	अगर (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	अगर (stat(identity_file, &st) == -1)
		fatal("%s: %s", identity_file, म_त्रुटि(त्रुटि_सं));
	अगर ((r = sshkey_load_private(identity_file, "",
	    &निजी, &comment)) == 0)
		passphrase = xstrdup("");
	अन्यथा अगर (r != SSH_ERR_कुंजी_WRONG_PASSPHRASE)
		fatal_r(r, "Cannot load private key \"%s\"", identity_file);
	अन्यथा {
		अगर (identity_passphrase)
			passphrase = xstrdup(identity_passphrase);
		अन्यथा अगर (identity_new_passphrase)
			passphrase = xstrdup(identity_new_passphrase);
		अन्यथा
			passphrase = read_passphrase("Enter passphrase: ",
			    RP_ALLOW_STDIN);
		/* Try to load using the passphrase. */
		अगर ((r = sshkey_load_private(identity_file, passphrase,
		    &निजी, &comment)) != 0) {
			freezero(passphrase, म_माप(passphrase));
			fatal_r(r, "Cannot load private key \"%s\"",
			    identity_file);
		}
	}

	अगर (निजी->type != कुंजी_ED25519 &&
	    private_कुंजी_format != SSHKEY_PRIVATE_OPENSSH) {
		error("Comments are only supported for keys stored in "
		    "the new format (-o).");
		explicit_bzero(passphrase, म_माप(passphrase));
		sshkey_free(निजी);
		निकास(1);
	}
	अगर (comment)
		म_लिखो("Old comment: %s\n", comment);
	अन्यथा
		म_लिखो("No existing comment\n");

	अगर (identity_comment) {
		strlcpy(new_comment, identity_comment, माप(new_comment));
	} अन्यथा {
		म_लिखो("New comment: ");
		ख_साफ(मानक_निकास);
		अगर (!ख_माला_लो(new_comment, माप(new_comment), मानक_निवेश)) {
			explicit_bzero(passphrase, म_माप(passphrase));
			sshkey_free(निजी);
			निकास(1);
		}
		new_comment[म_खोज(new_comment, "\n")] = '\0';
	}
	अगर (comment != शून्य && म_भेद(comment, new_comment) == 0) {
		म_लिखो("No change to comment\n");
		मुक्त(passphrase);
		sshkey_free(निजी);
		मुक्त(comment);
		निकास(0);
	}

	/* Save the file using the new passphrase. */
	अगर ((r = sshkey_save_private(निजी, identity_file, passphrase,
	    new_comment, private_कुंजी_format, openssh_format_cipher,
	    rounds)) != 0) {
		error_r(r, "Saving key \"%s\" failed", identity_file);
		freezero(passphrase, म_माप(passphrase));
		sshkey_free(निजी);
		मुक्त(comment);
		निकास(1);
	}
	freezero(passphrase, म_माप(passphrase));
	अगर ((r = sshkey_from_private(निजी, &खुला)) != 0)
		fatal_fr(r, "sshkey_from_private");
	sshkey_free(निजी);

	strlcat(identity_file, ".pub", माप(identity_file));
	अगर ((r = sshkey_save_public(खुला, identity_file, new_comment)) != 0)
		fatal_r(r, "Unable to save public key to %s", identity_file);
	sshkey_free(खुला);
	मुक्त(comment);

	अगर (म_माप(new_comment) > 0)
		म_लिखो("Comment '%s' applied\n", new_comment);
	अन्यथा
		म_लिखो("Comment removed\n");

	निकास(0);
}

अटल व्योम
cert_ext_add(स्थिर अक्षर *कुंजी, स्थिर अक्षर *मूल्य, पूर्णांक iscrit)
{
	cert_ext = xreallocarray(cert_ext, ncert_ext + 1, माप(*cert_ext));
	cert_ext[ncert_ext].कुंजी = xstrdup(कुंजी);
	cert_ext[ncert_ext].val = मूल्य == शून्य ? शून्य : xstrdup(मूल्य);
	cert_ext[ncert_ext].crit = iscrit;
	ncert_ext++;
}

/* qsort(3) comparison function for certificate extensions */
अटल पूर्णांक
cert_ext_cmp(स्थिर व्योम *_a, स्थिर व्योम *_b)
{
	स्थिर काष्ठा cert_ext *a = (स्थिर काष्ठा cert_ext *)_a;
	स्थिर काष्ठा cert_ext *b = (स्थिर काष्ठा cert_ext *)_b;
	पूर्णांक r;

	अगर (a->crit != b->crit)
		वापस (a->crit < b->crit) ? -1 : 1;
	अगर ((r = म_भेद(a->कुंजी, b->कुंजी)) != 0)
		वापस r;
	अगर ((a->val == शून्य) != (b->val == शून्य))
		वापस (a->val == शून्य) ? -1 : 1;
	अगर (a->val != शून्य && (r = म_भेद(a->val, b->val)) != 0)
		वापस r;
	वापस 0;
}

#घोषणा OPTIONS_CRITICAL	1
#घोषणा OPTIONS_EXTENSIONS	2
अटल व्योम
prepare_options_buf(काष्ठा sshbuf *c, पूर्णांक which)
{
	काष्ठा sshbuf *b;
	माप_प्रकार i;
	पूर्णांक r;
	स्थिर काष्ठा cert_ext *ext;

	अगर ((b = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	sshbuf_reset(c);
	क्रम (i = 0; i < ncert_ext; i++) {
		ext = &cert_ext[i];
		अगर ((ext->crit && (which & OPTIONS_EXTENSIONS)) ||
		    (!ext->crit && (which & OPTIONS_CRITICAL)))
			जारी;
		अगर (ext->val == शून्य) {
			/* flag option */
			debug3_f("%s", ext->कुंजी);
			अगर ((r = sshbuf_put_cstring(c, ext->कुंजी)) != 0 ||
			    (r = sshbuf_put_string(c, शून्य, 0)) != 0)
				fatal_fr(r, "prepare flag");
		} अन्यथा {
			/* key/value option */
			debug3_f("%s=%s", ext->कुंजी, ext->val);
			sshbuf_reset(b);
			अगर ((r = sshbuf_put_cstring(c, ext->कुंजी)) != 0 ||
			    (r = sshbuf_put_cstring(b, ext->val)) != 0 ||
			    (r = sshbuf_put_stringb(c, b)) != 0)
				fatal_fr(r, "prepare k/v");
		}
	}
	sshbuf_free(b);
}

अटल व्योम
finalise_cert_exts(व्योम)
{
	/* critical options */
	अगर (certflags_command != शून्य)
		cert_ext_add("force-command", certflags_command, 1);
	अगर (certflags_src_addr != शून्य)
		cert_ext_add("source-address", certflags_src_addr, 1);
	अगर ((certflags_flags & CERTOPT_REQUIRE_VERIFY) != 0)
		cert_ext_add("verify-required", शून्य, 1);
	/* extensions */
	अगर ((certflags_flags & CERTOPT_X_FWD) != 0)
		cert_ext_add("permit-X11-forwarding", शून्य, 0);
	अगर ((certflags_flags & CERTOPT_AGENT_FWD) != 0)
		cert_ext_add("permit-agent-forwarding", शून्य, 0);
	अगर ((certflags_flags & CERTOPT_PORT_FWD) != 0)
		cert_ext_add("permit-port-forwarding", शून्य, 0);
	अगर ((certflags_flags & CERTOPT_PTY) != 0)
		cert_ext_add("permit-pty", शून्य, 0);
	अगर ((certflags_flags & CERTOPT_USER_RC) != 0)
		cert_ext_add("permit-user-rc", शून्य, 0);
	अगर ((certflags_flags & CERTOPT_NO_REQUIRE_USER_PRESENCE) != 0)
		cert_ext_add("no-touch-required", शून्य, 0);
	/* order lexically by key */
	अगर (ncert_ext > 0)
		क्विक(cert_ext, ncert_ext, माप(*cert_ext), cert_ext_cmp);
}

अटल काष्ठा sshkey *
load_pkcs11_कुंजी(अक्षर *path)
{
#अगर_घोषित ENABLE_PKCS11
	काष्ठा sshkey **कुंजियाँ = शून्य, *खुला, *निजी = शून्य;
	पूर्णांक r, i, nkeys;

	अगर ((r = sshkey_load_public(path, &खुला, शून्य)) != 0)
		fatal_r(r, "Couldn't load CA public key \"%s\"", path);

	nkeys = pkcs11_add_provider(pkcs11provider, identity_passphrase,
	    &कुंजियाँ, शून्य);
	debug3_f("%d keys", nkeys);
	अगर (nkeys <= 0)
		fatal("cannot read public key from pkcs11");
	क्रम (i = 0; i < nkeys; i++) {
		अगर (sshkey_equal_public(खुला, कुंजियाँ[i])) {
			निजी = कुंजियाँ[i];
			जारी;
		}
		sshkey_free(कुंजियाँ[i]);
	}
	मुक्त(कुंजियाँ);
	sshkey_free(खुला);
	वापस निजी;
#अन्यथा
	fatal("no pkcs11 support");
#पूर्ण_अगर /* ENABLE_PKCS11 */
}

/* Signer for sshkey_certify_custom that uses the agent */
अटल पूर्णांक
agent_signer(काष्ठा sshkey *कुंजी, u_char **sigp, माप_प्रकार *lenp,
    स्थिर u_char *तथ्य, माप_प्रकार datalen,
    स्थिर अक्षर *alg, स्थिर अक्षर *provider, स्थिर अक्षर *pin,
    u_int compat, व्योम *ctx)
{
	पूर्णांक *agent_fdp = (पूर्णांक *)ctx;

	वापस ssh_agent_sign(*agent_fdp, कुंजी, sigp, lenp,
	    तथ्य, datalen, alg, compat);
}

अटल व्योम
do_ca_sign(काष्ठा passwd *pw, स्थिर अक्षर *ca_कुंजी_path, पूर्णांक prefer_agent,
    अचिन्हित दीर्घ दीर्घ cert_serial, पूर्णांक cert_serial_autoinc,
    पूर्णांक argc, अक्षर **argv)
{
	पूर्णांक r, i, कुंजी_in_agent = 0, agent_fd = -1;
	u_int n;
	काष्ठा sshkey *ca, *खुला;
	अक्षर valid[64], *otmp, *tmp, *cp, *out, *comment;
	अक्षर *ca_fp = शून्य, **plist = शून्य, *pin = शून्य;
	काष्ठा ssh_identitylist *agent_ids;
	माप_प्रकार j;
	काष्ठा notifier_ctx *notifier = शून्य;

#अगर_घोषित ENABLE_PKCS11
	pkcs11_init(1);
#पूर्ण_अगर
	tmp = tilde_expand_filename(ca_कुंजी_path, pw->pw_uid);
	अगर (pkcs11provider != शून्य) {
		/* If a PKCS#11 token was specified then try to use it */
		अगर ((ca = load_pkcs11_कुंजी(tmp)) == शून्य)
			fatal("No PKCS#11 key matching %s found", ca_कुंजी_path);
	} अन्यथा अगर (prefer_agent) {
		/*
		 * Agent signature requested. Try to use agent after making
		 * sure the public key specified is actually present in the
		 * agent.
		 */
		अगर ((r = sshkey_load_public(tmp, &ca, शून्य)) != 0)
			fatal_r(r, "Cannot load CA public key %s", tmp);
		अगर ((r = ssh_get_authentication_socket(&agent_fd)) != 0)
			fatal_r(r, "Cannot use public key for CA signature");
		अगर ((r = ssh_fetch_identitylist(agent_fd, &agent_ids)) != 0)
			fatal_r(r, "Retrieve agent key list");
		क्रम (j = 0; j < agent_ids->nkeys; j++) {
			अगर (sshkey_equal(ca, agent_ids->कुंजियाँ[j])) {
				कुंजी_in_agent = 1;
				/* Replace the CA key with the agent one */
				sshkey_free(ca);
				ca = agent_ids->कुंजियाँ[j];
				agent_ids->कुंजियाँ[j] = शून्य;
				अवरोध;
			}
		}
		अगर (!कुंजी_in_agent)
			fatal("CA key %s not found in agent", tmp);
		ssh_free_identitylist(agent_ids);
	} अन्यथा {
		/* CA key is assumed to be a private key on the filesystem */
		ca = load_identity(tmp, शून्य);
		अगर (sshkey_is_sk(ca) &&
		    (ca->sk_flags & SSH_SK_USER_VERIFICATION_REQD)) {
			अगर ((pin = read_passphrase("Enter PIN for CA key: ",
			    RP_ALLOW_STDIN)) == शून्य)
				fatal_f("couldn't read PIN");
		}
	}
	मुक्त(tmp);

	अगर (कुंजी_type_name != शून्य) {
		अगर (sshkey_type_from_shortname(कुंजी_type_name) != ca->type) {
			fatal("CA key type %s doesn't match specified %s",
			    sshkey_ssh_name(ca), कुंजी_type_name);
		}
	} अन्यथा अगर (ca->type == कुंजी_RSA) {
		/* Default to a good signature algorithm */
		कुंजी_type_name = "rsa-sha2-512";
	}
	ca_fp = sshkey_fingerprint(ca, fingerprint_hash, SSH_FP_DEFAULT);

	finalise_cert_exts();
	क्रम (i = 0; i < argc; i++) {
		/* Split list of principals */
		n = 0;
		अगर (cert_principals != शून्य) {
			otmp = tmp = xstrdup(cert_principals);
			plist = शून्य;
			क्रम (; (cp = strsep(&tmp, ",")) != शून्य; n++) {
				plist = xreallocarray(plist, n + 1, माप(*plist));
				अगर (*(plist[n] = xstrdup(cp)) == '\0')
					fatal("Empty principal name");
			}
			मुक्त(otmp);
		}
		अगर (n > SSHKEY_CERT_MAX_PRINCIPALS)
			fatal("Too many certificate principals specified");

		tmp = tilde_expand_filename(argv[i], pw->pw_uid);
		अगर ((r = sshkey_load_public(tmp, &खुला, &comment)) != 0)
			fatal_r(r, "load pubkey \"%s\"", tmp);
		अगर (sshkey_is_cert(खुला))
			fatal_f("key \"%s\" type %s cannot be certified",
			    tmp, sshkey_type(खुला));

		/* Prepare certificate to sign */
		अगर ((r = sshkey_to_certified(खुला)) != 0)
			fatal_r(r, "Could not upgrade key %s to certificate", tmp);
		खुला->cert->type = cert_कुंजी_type;
		खुला->cert->serial = (uint64_t)cert_serial;
		खुला->cert->कुंजी_id = xstrdup(cert_कुंजी_id);
		खुला->cert->nprincipals = n;
		खुला->cert->principals = plist;
		खुला->cert->valid_after = cert_valid_from;
		खुला->cert->valid_before = cert_valid_to;
		prepare_options_buf(खुला->cert->critical, OPTIONS_CRITICAL);
		prepare_options_buf(खुला->cert->extensions,
		    OPTIONS_EXTENSIONS);
		अगर ((r = sshkey_from_private(ca,
		    &खुला->cert->signature_कुंजी)) != 0)
			fatal_r(r, "sshkey_from_private (ca key)");

		अगर (कुंजी_in_agent) {
			अगर ((r = sshkey_certify_custom(खुला, ca,
			    कुंजी_type_name, sk_provider, शून्य, agent_signer,
			    &agent_fd)) != 0)
				fatal_r(r, "Couldn't certify %s via agent", tmp);
		} अन्यथा {
			अगर (sshkey_is_sk(ca) &&
			    (ca->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
				notifier = notify_start(0,
				    "Confirm user presence for key %s %s",
				    sshkey_type(ca), ca_fp);
			}
			r = sshkey_certify(खुला, ca, कुंजी_type_name,
			    sk_provider, pin);
			notify_complete(notifier, "User presence confirmed");
			अगर (r != 0)
				fatal_r(r, "Couldn't certify key %s", tmp);
		}

		अगर ((cp = म_खोजप(tmp, '.')) != शून्य && म_भेद(cp, ".pub") == 0)
			*cp = '\0';
		xasprintf(&out, "%s-cert.pub", tmp);
		मुक्त(tmp);

		अगर ((r = sshkey_save_public(खुला, out, comment)) != 0) {
			fatal_r(r, "Unable to save public key to %s",
			    identity_file);
		}

		अगर (!quiet) {
			sshkey_format_cert_validity(खुला->cert,
			    valid, माप(valid));
			logit("Signed %s key %s: id \"%s\" serial %llu%s%s "
			    "valid %s", sshkey_cert_type(खुला),
			    out, खुला->cert->कुंजी_id,
			    (अचिन्हित दीर्घ दीर्घ)खुला->cert->serial,
			    cert_principals != शून्य ? " for " : "",
			    cert_principals != शून्य ? cert_principals : "",
			    valid);
		}

		sshkey_free(खुला);
		मुक्त(out);
		मुक्त(comment);
		अगर (cert_serial_autoinc)
			cert_serial++;
	}
	अगर (pin != शून्य)
		freezero(pin, म_माप(pin));
	sshkey_free(ca);
	मुक्त(ca_fp);
#अगर_घोषित ENABLE_PKCS11
	pkcs11_terminate();
#पूर्ण_अगर
}

अटल uint64_t
parse_relative_time(स्थिर अक्षर *s, समय_प्रकार now)
{
	int64_t mul, secs;

	mul = *s == '-' ? -1 : 1;

	अगर ((secs = convtime(s + 1)) == -1)
		fatal("Invalid relative certificate time %s", s);
	अगर (mul == -1 && secs > now)
		fatal("Certificate time %s cannot be represented", s);
	वापस now + (uint64_t)(secs * mul);
}

अटल व्योम
parse_hex_u64(स्थिर अक्षर *s, uint64_t *up)
{
	अक्षर *ep;
	अचिन्हित दीर्घ दीर्घ ull;

	त्रुटि_सं = 0;
	ull = strtoull(s, &ep, 16);
	अगर (*s == '\0' || *ep != '\0')
		fatal("Invalid certificate time: not a number");
	अगर (त्रुटि_सं == दुस्फल && ull == अच_दीर्घ_उच्च)
		fatal_fr(SSH_ERR_SYSTEM_ERROR, "Invalid certificate time");
	*up = (uint64_t)ull;
}

अटल व्योम
parse_cert_times(अक्षर *timespec)
{
	अक्षर *from, *to;
	समय_प्रकार now = समय(शून्य);
	int64_t secs;

	/* +timespec relative to now */
	अगर (*timespec == '+' && म_अक्षर(timespec, ':') == शून्य) {
		अगर ((secs = convtime(timespec + 1)) == -1)
			fatal("Invalid relative certificate life %s", timespec);
		cert_valid_to = now + secs;
		/*
		 * Backdate certificate one minute to avoid problems on hosts
		 * with poorly-synchronised clocks.
		 */
		cert_valid_from = ((now - 59)/ 60) * 60;
		वापस;
	}

	/*
	 * from:to, where
	 * from := [+-]timespec | YYYYMMDD | YYYYMMDDHHMMSS | 0x... | "always"
	 *   to := [+-]timespec | YYYYMMDD | YYYYMMDDHHMMSS | 0x... | "forever"
	 */
	from = xstrdup(timespec);
	to = म_अक्षर(from, ':');
	अगर (to == शून्य || from == to || *(to + 1) == '\0')
		fatal("Invalid certificate life specification %s", timespec);
	*to++ = '\0';

	अगर (*from == '-' || *from == '+')
		cert_valid_from = parse_relative_time(from, now);
	अन्यथा अगर (म_भेद(from, "always") == 0)
		cert_valid_from = 0;
	अन्यथा अगर (म_भेदन(from, "0x", 2) == 0)
		parse_hex_u64(from, &cert_valid_from);
	अन्यथा अगर (parse_absolute_time(from, &cert_valid_from) != 0)
		fatal("Invalid from time \"%s\"", from);

	अगर (*to == '-' || *to == '+')
		cert_valid_to = parse_relative_time(to, now);
	अन्यथा अगर (म_भेद(to, "forever") == 0)
		cert_valid_to = ~(uint64_t)0;
	अन्यथा अगर (म_भेदन(to, "0x", 2) == 0)
		parse_hex_u64(to, &cert_valid_to);
	अन्यथा अगर (parse_absolute_time(to, &cert_valid_to) != 0)
		fatal("Invalid to time \"%s\"", to);

	अगर (cert_valid_to <= cert_valid_from)
		fatal("Empty certificate validity interval");
	मुक्त(from);
}

अटल व्योम
add_cert_option(अक्षर *opt)
{
	अक्षर *val, *cp;
	स्थिर अक्षर *p;
	पूर्णांक iscrit = 0;

	अगर (strcasecmp(opt, "clear") == 0)
		certflags_flags = 0;
	अन्यथा अगर (strcasecmp(opt, "no-x11-forwarding") == 0)
		certflags_flags &= ~CERTOPT_X_FWD;
	अन्यथा अगर (strcasecmp(opt, "permit-x11-forwarding") == 0)
		certflags_flags |= CERTOPT_X_FWD;
	अन्यथा अगर (strcasecmp(opt, "no-agent-forwarding") == 0)
		certflags_flags &= ~CERTOPT_AGENT_FWD;
	अन्यथा अगर (strcasecmp(opt, "permit-agent-forwarding") == 0)
		certflags_flags |= CERTOPT_AGENT_FWD;
	अन्यथा अगर (strcasecmp(opt, "no-port-forwarding") == 0)
		certflags_flags &= ~CERTOPT_PORT_FWD;
	अन्यथा अगर (strcasecmp(opt, "permit-port-forwarding") == 0)
		certflags_flags |= CERTOPT_PORT_FWD;
	अन्यथा अगर (strcasecmp(opt, "no-pty") == 0)
		certflags_flags &= ~CERTOPT_PTY;
	अन्यथा अगर (strcasecmp(opt, "permit-pty") == 0)
		certflags_flags |= CERTOPT_PTY;
	अन्यथा अगर (strcasecmp(opt, "no-user-rc") == 0)
		certflags_flags &= ~CERTOPT_USER_RC;
	अन्यथा अगर (strcasecmp(opt, "permit-user-rc") == 0)
		certflags_flags |= CERTOPT_USER_RC;
	अन्यथा अगर (strcasecmp(opt, "touch-required") == 0)
		certflags_flags &= ~CERTOPT_NO_REQUIRE_USER_PRESENCE;
	अन्यथा अगर (strcasecmp(opt, "no-touch-required") == 0)
		certflags_flags |= CERTOPT_NO_REQUIRE_USER_PRESENCE;
	अन्यथा अगर (strcasecmp(opt, "no-verify-required") == 0)
		certflags_flags &= ~CERTOPT_REQUIRE_VERIFY;
	अन्यथा अगर (strcasecmp(opt, "verify-required") == 0)
		certflags_flags |= CERTOPT_REQUIRE_VERIFY;
	अन्यथा अगर ((p = strprefix(opt, "force-command=", 1)) != शून्य) {
		अगर (*p == '\0')
			fatal("Empty force-command option");
		अगर (certflags_command != शून्य)
			fatal("force-command already specified");
		certflags_command = xstrdup(p);
	} अन्यथा अगर ((p = strprefix(opt, "source-address=", 1)) != शून्य) {
		अगर (*p == '\0')
			fatal("Empty source-address option");
		अगर (certflags_src_addr != शून्य)
			fatal("source-address already specified");
		अगर (addr_match_cidr_list(शून्य, p) != 0)
			fatal("Invalid source-address list");
		certflags_src_addr = xstrdup(p);
	} अन्यथा अगर (strprefix(opt, "extension:", 1) != शून्य ||
		    (iscrit = (strprefix(opt, "critical:", 1) != शून्य))) {
		val = xstrdup(म_अक्षर(opt, ':') + 1);
		अगर ((cp = म_अक्षर(val, '=')) != शून्य)
			*cp++ = '\0';
		cert_ext_add(val, cp, iscrit);
		मुक्त(val);
	} अन्यथा
		fatal("Unsupported certificate option \"%s\"", opt);
}

अटल व्योम
show_options(काष्ठा sshbuf *optbuf, पूर्णांक in_critical)
{
	अक्षर *name, *arg, *hex;
	काष्ठा sshbuf *options, *option = शून्य;
	पूर्णांक r;

	अगर ((options = sshbuf_fromb(optbuf)) == शून्य)
		fatal_f("sshbuf_fromb failed");
	जबतक (sshbuf_len(options) != 0) {
		sshbuf_free(option);
		option = शून्य;
		अगर ((r = sshbuf_get_cstring(options, &name, शून्य)) != 0 ||
		    (r = sshbuf_froms(options, &option)) != 0)
			fatal_fr(r, "parse option");
		म_लिखो("                %s", name);
		अगर (!in_critical &&
		    (म_भेद(name, "permit-X11-forwarding") == 0 ||
		    म_भेद(name, "permit-agent-forwarding") == 0 ||
		    म_भेद(name, "permit-port-forwarding") == 0 ||
		    म_भेद(name, "permit-pty") == 0 ||
		    म_भेद(name, "permit-user-rc") == 0 ||
		    म_भेद(name, "no-touch-required") == 0)) {
			म_लिखो("\n");
		} अन्यथा अगर (in_critical &&
		    (म_भेद(name, "force-command") == 0 ||
		    म_भेद(name, "source-address") == 0)) {
			अगर ((r = sshbuf_get_cstring(option, &arg, शून्य)) != 0)
				fatal_fr(r, "parse critical");
			म_लिखो(" %s\n", arg);
			मुक्त(arg);
		} अन्यथा अगर (in_critical &&
		    म_भेद(name, "verify-required") == 0) {
			म_लिखो("\n");
		} अन्यथा अगर (sshbuf_len(option) > 0) {
			hex = sshbuf_dtob16(option);
			म_लिखो(" UNKNOWN OPTION: %s (len %zu)\n",
			    hex, sshbuf_len(option));
			sshbuf_reset(option);
			मुक्त(hex);
		} अन्यथा
			म_लिखो(" UNKNOWN FLAG OPTION\n");
		मुक्त(name);
		अगर (sshbuf_len(option) != 0)
			fatal("Option corrupt: extra data at end");
	}
	sshbuf_free(option);
	sshbuf_free(options);
}

अटल व्योम
print_cert(काष्ठा sshkey *कुंजी)
{
	अक्षर valid[64], *कुंजी_fp, *ca_fp;
	u_int i;

	कुंजी_fp = sshkey_fingerprint(कुंजी, fingerprint_hash, SSH_FP_DEFAULT);
	ca_fp = sshkey_fingerprint(कुंजी->cert->signature_कुंजी,
	    fingerprint_hash, SSH_FP_DEFAULT);
	अगर (कुंजी_fp == शून्य || ca_fp == शून्य)
		fatal_f("sshkey_fingerprint fail");
	sshkey_format_cert_validity(कुंजी->cert, valid, माप(valid));

	म_लिखो("        Type: %s %s certificate\n", sshkey_ssh_name(कुंजी),
	    sshkey_cert_type(कुंजी));
	म_लिखो("        Public key: %s %s\n", sshkey_type(कुंजी), कुंजी_fp);
	म_लिखो("        Signing CA: %s %s (using %s)\n",
	    sshkey_type(कुंजी->cert->signature_कुंजी), ca_fp,
	    कुंजी->cert->signature_type);
	म_लिखो("        Key ID: \"%s\"\n", कुंजी->cert->कुंजी_id);
	म_लिखो("        Serial: %llu\n", (अचिन्हित दीर्घ दीर्घ)कुंजी->cert->serial);
	म_लिखो("        Valid: %s\n", valid);
	म_लिखो("        Principals: ");
	अगर (कुंजी->cert->nprincipals == 0)
		म_लिखो("(none)\n");
	अन्यथा {
		क्रम (i = 0; i < कुंजी->cert->nprincipals; i++)
			म_लिखो("\n                %s",
			    कुंजी->cert->principals[i]);
		म_लिखो("\n");
	}
	म_लिखो("        Critical Options: ");
	अगर (sshbuf_len(कुंजी->cert->critical) == 0)
		म_लिखो("(none)\n");
	अन्यथा {
		म_लिखो("\n");
		show_options(कुंजी->cert->critical, 1);
	}
	म_लिखो("        Extensions: ");
	अगर (sshbuf_len(कुंजी->cert->extensions) == 0)
		म_लिखो("(none)\n");
	अन्यथा {
		म_लिखो("\n");
		show_options(कुंजी->cert->extensions, 0);
	}
	मुक्त(कुंजी_fp);
	मुक्त(ca_fp);
}

अटल व्योम
do_show_cert(काष्ठा passwd *pw)
{
	काष्ठा sshkey *कुंजी = शून्य;
	काष्ठा stat st;
	पूर्णांक r, is_stdin = 0, ok = 0;
	खाता *f;
	अक्षर *cp, *पंक्ति = शून्य;
	स्थिर अक्षर *path;
	माप_प्रकार linesize = 0;
	u_long lnum = 0;

	अगर (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	अगर (म_भेद(identity_file, "-") != 0 && stat(identity_file, &st) == -1)
		fatal("%s: %s: %s", __progname, identity_file, म_त्रुटि(त्रुटि_सं));

	path = identity_file;
	अगर (म_भेद(path, "-") == 0) {
		f = मानक_निवेश;
		path = "(stdin)";
		is_stdin = 1;
	} अन्यथा अगर ((f = ख_खोलो(identity_file, "r")) == शून्य)
		fatal("fopen %s: %s", identity_file, म_त्रुटि(त्रुटि_सं));

	जबतक (getline(&पंक्ति, &linesize, f) != -1) {
		lnum++;
		sshkey_free(कुंजी);
		कुंजी = शून्य;
		/* Trim leading space and comments */
		cp = पंक्ति + म_अखोज(पंक्ति, " \t");
		अगर (*cp == '#' || *cp == '\0')
			जारी;
		अगर ((कुंजी = sshkey_new(कुंजी_UNSPEC)) == शून्य)
			fatal("sshkey_new");
		अगर ((r = sshkey_read(कुंजी, &cp)) != 0) {
			error_r(r, "%s:%lu: invalid key", path, lnum);
			जारी;
		}
		अगर (!sshkey_is_cert(कुंजी)) {
			error("%s:%lu is not a certificate", path, lnum);
			जारी;
		}
		ok = 1;
		अगर (!is_stdin && lnum == 1)
			म_लिखो("%s:\n", path);
		अन्यथा
			म_लिखो("%s:%lu:\n", path, lnum);
		print_cert(कुंजी);
	}
	मुक्त(पंक्ति);
	sshkey_free(कुंजी);
	ख_बंद(f);
	निकास(ok ? 0 : 1);
}

अटल व्योम
load_krl(स्थिर अक्षर *path, काष्ठा ssh_krl **krlp)
{
	काष्ठा sshbuf *krlbuf;
	पूर्णांक r;

	अगर ((r = sshbuf_load_file(path, &krlbuf)) != 0)
		fatal_r(r, "Unable to load KRL %s", path);
	/* XXX check sigs */
	अगर ((r = ssh_krl_from_blob(krlbuf, krlp)) != 0 ||
	    *krlp == शून्य)
		fatal_r(r, "Invalid KRL file %s", path);
	sshbuf_free(krlbuf);
}

अटल व्योम
hash_to_blob(स्थिर अक्षर *cp, u_char **blobp, माप_प्रकार *lenp,
    स्थिर अक्षर *file, u_long lnum)
{
	अक्षर *tmp;
	माप_प्रकार tlen;
	काष्ठा sshbuf *b;
	पूर्णांक r;

	अगर ((cp = strprefix(cp, "SHA256:", 0)) == शून्य)
		fatal("%s:%lu: unsupported hash algorithm", file, lnum);

	/*
	 * OpenSSH base64 hashes omit trailing '='
	 * characters; put them back for decode.
	 */
	अगर ((tlen = म_माप(cp)) >= SIZE_MAX - 5)
		fatal_f("hash too long: %zu bytes", tlen);
	tmp = xmalloc(tlen + 4 + 1);
	strlcpy(tmp, cp, tlen + 1);
	जबतक ((tlen % 4) != 0) {
		tmp[tlen++] = '=';
		tmp[tlen] = '\0';
	}
	अगर ((b = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = sshbuf_b64tod(b, tmp)) != 0)
		fatal_r(r, "%s:%lu: decode hash failed", file, lnum);
	मुक्त(tmp);
	*lenp = sshbuf_len(b);
	*blobp = xmalloc(*lenp);
	स_नकल(*blobp, sshbuf_ptr(b), *lenp);
	sshbuf_free(b);
}

अटल व्योम
update_krl_from_file(काष्ठा passwd *pw, स्थिर अक्षर *file, पूर्णांक wild_ca,
    स्थिर काष्ठा sshkey *ca, काष्ठा ssh_krl *krl)
{
	काष्ठा sshkey *कुंजी = शून्य;
	u_long lnum = 0;
	अक्षर *path, *cp, *ep, *पंक्ति = शून्य;
	u_char *blob = शून्य;
	माप_प्रकार blen = 0, linesize = 0;
	अचिन्हित दीर्घ दीर्घ serial, serial2;
	पूर्णांक i, was_explicit_कुंजी, was_sha1, was_sha256, was_hash, r;
	खाता *krl_spec;

	path = tilde_expand_filename(file, pw->pw_uid);
	अगर (म_भेद(path, "-") == 0) {
		krl_spec = मानक_निवेश;
		मुक्त(path);
		path = xstrdup("(standard input)");
	} अन्यथा अगर ((krl_spec = ख_खोलो(path, "r")) == शून्य)
		fatal("fopen %s: %s", path, म_त्रुटि(त्रुटि_सं));

	अगर (!quiet)
		म_लिखो("Revoking from %s\n", path);
	जबतक (getline(&पंक्ति, &linesize, krl_spec) != -1) {
		अगर (linesize >= पूर्णांक_उच्च) {
			fatal_f("%s contains unparsable line, len=%zu",
			    path, linesize);
		}
		lnum++;
		was_explicit_कुंजी = was_sha1 = was_sha256 = was_hash = 0;
		cp = पंक्ति + म_अखोज(पंक्ति, " \t");
		/* Trim trailing space, comments and strip \n */
		क्रम (i = 0, r = -1; cp[i] != '\0'; i++) {
			अगर (cp[i] == '#' || cp[i] == '\n') {
				cp[i] = '\0';
				अवरोध;
			}
			अगर (cp[i] == ' ' || cp[i] == '\t') {
				/* Remember the start of a span of whitespace */
				अगर (r == -1)
					r = i;
			} अन्यथा
				r = -1;
		}
		अगर (r != -1)
			cp[r] = '\0';
		अगर (*cp == '\0')
			जारी;
		अगर (strncasecmp(cp, "serial:", 7) == 0) {
			अगर (ca == शून्य && !wild_ca) {
				fatal("revoking certificates by serial number "
				    "requires specification of a CA key");
			}
			cp += 7;
			cp = cp + म_अखोज(cp, " \t");
			त्रुटि_सं = 0;
			serial = strtoull(cp, &ep, 0);
			अगर (*cp == '\0' || (*ep != '\0' && *ep != '-'))
				fatal("%s:%lu: invalid serial \"%s\"",
				    path, lnum, cp);
			अगर (त्रुटि_सं == दुस्फल && serial == ULLONG_MAX)
				fatal("%s:%lu: serial out of range",
				    path, lnum);
			serial2 = serial;
			अगर (*ep == '-') {
				cp = ep + 1;
				त्रुटि_सं = 0;
				serial2 = strtoull(cp, &ep, 0);
				अगर (*cp == '\0' || *ep != '\0')
					fatal("%s:%lu: invalid serial \"%s\"",
					    path, lnum, cp);
				अगर (त्रुटि_सं == दुस्फल && serial2 == ULLONG_MAX)
					fatal("%s:%lu: serial out of range",
					    path, lnum);
				अगर (serial2 <= serial)
					fatal("%s:%lu: invalid serial range "
					    "%llu:%llu", path, lnum,
					    (अचिन्हित दीर्घ दीर्घ)serial,
					    (अचिन्हित दीर्घ दीर्घ)serial2);
			}
			अगर (ssh_krl_revoke_cert_by_serial_range(krl,
			    ca, serial, serial2) != 0) {
				fatal_f("revoke serial failed");
			}
		} अन्यथा अगर (strncasecmp(cp, "id:", 3) == 0) {
			अगर (ca == शून्य && !wild_ca) {
				fatal("revoking certificates by key ID "
				    "requires specification of a CA key");
			}
			cp += 3;
			cp = cp + म_अखोज(cp, " \t");
			अगर (ssh_krl_revoke_cert_by_कुंजी_id(krl, ca, cp) != 0)
				fatal_f("revoke key ID failed");
		} अन्यथा अगर (strncasecmp(cp, "hash:", 5) == 0) {
			cp += 5;
			cp = cp + म_अखोज(cp, " \t");
			hash_to_blob(cp, &blob, &blen, file, lnum);
			अगर ((r = ssh_krl_revoke_कुंजी_sha256(krl,
			    blob, blen)) != 0)
				fatal_fr(r, "revoke key failed");
			मुक्त(blob);
			blob = शून्य;
			blen = 0;
		} अन्यथा {
			अगर (strncasecmp(cp, "key:", 4) == 0) {
				cp += 4;
				cp = cp + म_अखोज(cp, " \t");
				was_explicit_कुंजी = 1;
			} अन्यथा अगर (strncasecmp(cp, "sha1:", 5) == 0) {
				cp += 5;
				cp = cp + म_अखोज(cp, " \t");
				was_sha1 = 1;
			} अन्यथा अगर (strncasecmp(cp, "sha256:", 7) == 0) {
				cp += 7;
				cp = cp + म_अखोज(cp, " \t");
				was_sha256 = 1;
				/*
				 * Just try to process the line as a key.
				 * Parsing will fail if it isn't.
				 */
			}
			अगर ((कुंजी = sshkey_new(कुंजी_UNSPEC)) == शून्य)
				fatal("sshkey_new");
			अगर ((r = sshkey_read(कुंजी, &cp)) != 0)
				fatal_r(r, "%s:%lu: invalid key", path, lnum);
			अगर (was_explicit_कुंजी)
				r = ssh_krl_revoke_कुंजी_explicit(krl, कुंजी);
			अन्यथा अगर (was_sha1) {
				अगर (sshkey_fingerprint_raw(कुंजी,
				    SSH_DIGEST_SHA1, &blob, &blen) != 0) {
					fatal("%s:%lu: fingerprint failed",
					    file, lnum);
				}
				r = ssh_krl_revoke_कुंजी_sha1(krl, blob, blen);
			} अन्यथा अगर (was_sha256) {
				अगर (sshkey_fingerprint_raw(कुंजी,
				    SSH_DIGEST_SHA256, &blob, &blen) != 0) {
					fatal("%s:%lu: fingerprint failed",
					    file, lnum);
				}
				r = ssh_krl_revoke_कुंजी_sha256(krl, blob, blen);
			} अन्यथा
				r = ssh_krl_revoke_कुंजी(krl, कुंजी);
			अगर (r != 0)
				fatal_fr(r, "revoke key failed");
			freezero(blob, blen);
			blob = शून्य;
			blen = 0;
			sshkey_free(कुंजी);
		}
	}
	अगर (म_भेद(path, "-") != 0)
		ख_बंद(krl_spec);
	मुक्त(पंक्ति);
	मुक्त(path);
}

अटल व्योम
do_gen_krl(काष्ठा passwd *pw, पूर्णांक updating, स्थिर अक्षर *ca_कुंजी_path,
    अचिन्हित दीर्घ दीर्घ krl_version, स्थिर अक्षर *krl_comment,
    पूर्णांक argc, अक्षर **argv)
{
	काष्ठा ssh_krl *krl;
	काष्ठा stat sb;
	काष्ठा sshkey *ca = शून्य;
	पूर्णांक i, r, wild_ca = 0;
	अक्षर *tmp;
	काष्ठा sshbuf *kbuf;

	अगर (*identity_file == '\0')
		fatal("KRL generation requires an output file");
	अगर (stat(identity_file, &sb) == -1) {
		अगर (त्रुटि_सं != ENOENT)
			fatal("Cannot access KRL \"%s\": %s",
			    identity_file, म_त्रुटि(त्रुटि_सं));
		अगर (updating)
			fatal("KRL \"%s\" does not exist", identity_file);
	}
	अगर (ca_कुंजी_path != शून्य) {
		अगर (strcasecmp(ca_कुंजी_path, "none") == 0)
			wild_ca = 1;
		अन्यथा {
			tmp = tilde_expand_filename(ca_कुंजी_path, pw->pw_uid);
			अगर ((r = sshkey_load_public(tmp, &ca, शून्य)) != 0)
				fatal_r(r, "Cannot load CA public key %s", tmp);
			मुक्त(tmp);
		}
	}

	अगर (updating)
		load_krl(identity_file, &krl);
	अन्यथा अगर ((krl = ssh_krl_init()) == शून्य)
		fatal("couldn't create KRL");

	अगर (krl_version != 0)
		ssh_krl_set_version(krl, krl_version);
	अगर (krl_comment != शून्य)
		ssh_krl_set_comment(krl, krl_comment);

	क्रम (i = 0; i < argc; i++)
		update_krl_from_file(pw, argv[i], wild_ca, ca, krl);

	अगर ((kbuf = sshbuf_new()) == शून्य)
		fatal("sshbuf_new failed");
	अगर (ssh_krl_to_blob(krl, kbuf) != 0)
		fatal("Couldn't generate KRL");
	अगर ((r = sshbuf_write_file(identity_file, kbuf)) != 0)
		fatal("write %s: %s", identity_file, म_त्रुटि(त्रुटि_सं));
	sshbuf_free(kbuf);
	ssh_krl_free(krl);
	sshkey_free(ca);
}

अटल व्योम
do_check_krl(काष्ठा passwd *pw, पूर्णांक print_krl, पूर्णांक argc, अक्षर **argv)
{
	पूर्णांक i, r, ret = 0;
	अक्षर *comment;
	काष्ठा ssh_krl *krl;
	काष्ठा sshkey *k;

	अगर (*identity_file == '\0')
		fatal("KRL checking requires an input file");
	load_krl(identity_file, &krl);
	अगर (print_krl)
		krl_dump(krl, मानक_निकास);
	क्रम (i = 0; i < argc; i++) {
		अगर ((r = sshkey_load_public(argv[i], &k, &comment)) != 0)
			fatal_r(r, "Cannot load public key %s", argv[i]);
		r = ssh_krl_check_कुंजी(krl, k);
		म_लिखो("%s%s%s%s: %s\n", argv[i],
		    *comment ? " (" : "", comment, *comment ? ")" : "",
		    r == 0 ? "ok" : "REVOKED");
		अगर (r != 0)
			ret = 1;
		sshkey_free(k);
		मुक्त(comment);
	}
	ssh_krl_free(krl);
	निकास(ret);
}

अटल काष्ठा sshkey *
load_sign_कुंजी(स्थिर अक्षर *keypath, स्थिर काष्ठा sshkey *pubkey)
{
	माप_प्रकार i, slen, plen = म_माप(keypath);
	अक्षर *privpath = xstrdup(keypath);
	अटल स्थिर अक्षर * स्थिर suffixes[] = { "-cert.pub", ".pub", शून्य };
	काष्ठा sshkey *ret = शून्य, *privkey = शून्य;
	पूर्णांक r, waspub = 0;
	काष्ठा stat st;

	/*
	 * If passed a public key filename, then try to locate the corresponding
	 * private key. This lets us specify certificates on the command-line
	 * and have ssh-keygen find the appropriate private key.
	 */
	क्रम (i = 0; suffixes[i]; i++) {
		slen = म_माप(suffixes[i]);
		अगर (plen <= slen ||
		    म_भेद(privpath + plen - slen, suffixes[i]) != 0)
			जारी;
		privpath[plen - slen] = '\0';
		debug_f("%s looks like a public key, using private key "
		    "path %s instead", keypath, privpath);
		waspub = 1;
	}
	अगर (waspub && stat(privpath, &st) != 0 && त्रुटि_सं == ENOENT)
		fatal("No private key found for public key \"%s\"", keypath);
	अगर ((r = sshkey_load_private(privpath, "", &privkey, शून्य)) != 0 &&
	    (r != SSH_ERR_कुंजी_WRONG_PASSPHRASE)) {
		debug_fr(r, "load private key \"%s\"", privpath);
		fatal("No private key found for \"%s\"", privpath);
	} अन्यथा अगर (privkey == शून्य)
		privkey = load_identity(privpath, शून्य);

	अगर (!sshkey_equal_public(pubkey, privkey)) {
		error("Public key %s doesn't match private %s",
		    keypath, privpath);
		जाओ done;
	}
	अगर (sshkey_is_cert(pubkey) && !sshkey_is_cert(privkey)) {
		/*
		 * Graft the certificate onto the private key to make
		 * it capable of signing.
		 */
		अगर ((r = sshkey_to_certified(privkey)) != 0) {
			error_fr(r, "sshkey_to_certified");
			जाओ done;
		}
		अगर ((r = sshkey_cert_copy(pubkey, privkey)) != 0) {
			error_fr(r, "sshkey_cert_copy");
			जाओ done;
		}
	}
	/* success */
	ret = privkey;
	privkey = शून्य;
 done:
	sshkey_free(privkey);
	मुक्त(privpath);
	वापस ret;
}

अटल पूर्णांक
sign_one(काष्ठा sshkey *signkey, स्थिर अक्षर *filename, पूर्णांक fd,
    स्थिर अक्षर *sig_namespace, स्थिर अक्षर *hashalg, sshsig_signer *signer,
    व्योम *signer_ctx)
{
	काष्ठा sshbuf *sigbuf = शून्य, *abuf = शून्य;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR, wfd = -1, oerrno;
	अक्षर *wfile = शून्य, *asig = शून्य, *fp = शून्य;
	अक्षर *pin = शून्य, *prompt = शून्य;

	अगर (!quiet) {
		अगर (fd == STDIN_FILENO)
			ख_लिखो(मानक_त्रुटि, "Signing data on standard input\n");
		अन्यथा
			ख_लिखो(मानक_त्रुटि, "Signing file %s\n", filename);
	}
	अगर (signer == शून्य && sshkey_is_sk(signkey)) {
		अगर ((signkey->sk_flags & SSH_SK_USER_VERIFICATION_REQD)) {
			xasprintf(&prompt, "Enter PIN for %s key: ",
			    sshkey_type(signkey));
			अगर ((pin = read_passphrase(prompt,
			    RP_ALLOW_STDIN)) == शून्य)
				fatal_f("couldn't read PIN");
		}
		अगर ((signkey->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
			अगर ((fp = sshkey_fingerprint(signkey, fingerprint_hash,
			    SSH_FP_DEFAULT)) == शून्य)
				fatal_f("fingerprint failed");
			ख_लिखो(मानक_त्रुटि, "Confirm user presence for key %s %s\n",
			    sshkey_type(signkey), fp);
			मुक्त(fp);
		}
	}
	अगर ((r = sshsig_sign_fd(signkey, hashalg, sk_provider, pin,
	    fd, sig_namespace, &sigbuf, signer, signer_ctx)) != 0) {
		error_r(r, "Signing %s failed", filename);
		जाओ out;
	}
	अगर ((r = sshsig_armor(sigbuf, &abuf)) != 0) {
		error_fr(r, "sshsig_armor");
		जाओ out;
	}
	अगर ((asig = sshbuf_dup_string(abuf)) == शून्य) {
		error_f("buffer error");
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}

	अगर (fd == STDIN_FILENO) {
		ख_माला_दो(asig, मानक_निकास);
		ख_साफ(मानक_निकास);
	} अन्यथा {
		xasprintf(&wfile, "%s.sig", filename);
		अगर (confirm_overwrite(wfile)) {
			अगर ((wfd = खोलो(wfile, O_WRONLY|O_CREAT|O_TRUNC,
			    0666)) == -1) {
				oerrno = त्रुटि_सं;
				error("Cannot open %s: %s",
				    wfile, म_त्रुटि(त्रुटि_सं));
				त्रुटि_सं = oerrno;
				r = SSH_ERR_SYSTEM_ERROR;
				जाओ out;
			}
			अगर (atomicio(vwrite, wfd, asig,
			    म_माप(asig)) != म_माप(asig)) {
				oerrno = त्रुटि_सं;
				error("Cannot write to %s: %s",
				    wfile, म_त्रुटि(त्रुटि_सं));
				त्रुटि_सं = oerrno;
				r = SSH_ERR_SYSTEM_ERROR;
				जाओ out;
			}
			अगर (!quiet) {
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
	अगर (pin != शून्य)
		freezero(pin, म_माप(pin));
	sshbuf_free(abuf);
	sshbuf_free(sigbuf);
	अगर (wfd != -1)
		बंद(wfd);
	वापस r;
}

अटल पूर्णांक
sig_process_opts(अक्षर * स्थिर *opts, माप_प्रकार nopts, अक्षर **hashalgp,
    uint64_t *verify_timep, पूर्णांक *print_pubkey)
{
	माप_प्रकार i;
	समय_प्रकार now;
	स्थिर अक्षर *p;

	अगर (verify_timep != शून्य)
		*verify_timep = 0;
	अगर (print_pubkey != शून्य)
		*print_pubkey = 0;
	अगर (hashalgp != शून्य)
		*hashalgp = शून्य;
	क्रम (i = 0; i < nopts; i++) {
		अगर (hashalgp != शून्य &&
		    (p = strprefix(opts[i], "hashalg=", 1)) != शून्य) {
			*hashalgp = xstrdup(p);
		} अन्यथा अगर (verify_timep &&
		    (p = strprefix(opts[i], "verify-time=", 1)) != शून्य) {
			अगर (parse_absolute_time(p, verify_timep) != 0 ||
			    *verify_timep == 0) {
				error("Invalid \"verify-time\" option");
				वापस SSH_ERR_INVALID_ARGUMENT;
			}
		} अन्यथा अगर (print_pubkey &&
		    strcasecmp(opts[i], "print-pubkey") == 0) {
			*print_pubkey = 1;
		} अन्यथा {
			error("Invalid option \"%s\"", opts[i]);
			वापस SSH_ERR_INVALID_ARGUMENT;
		}
	}
	अगर (verify_timep && *verify_timep == 0) {
		अगर ((now = समय(शून्य)) < 0) {
			error("Time is before epoch");
			वापस SSH_ERR_INVALID_ARGUMENT;
		}
		*verify_timep = (uint64_t)now;
	}
	वापस 0;
}


अटल पूर्णांक
sig_sign(स्थिर अक्षर *keypath, स्थिर अक्षर *sig_namespace, पूर्णांक require_agent,
    पूर्णांक argc, अक्षर **argv, अक्षर * स्थिर *opts, माप_प्रकार nopts)
{
	पूर्णांक i, fd = -1, r, ret = -1;
	पूर्णांक agent_fd = -1;
	काष्ठा sshkey *pubkey = शून्य, *privkey = शून्य, *signkey = शून्य;
	sshsig_signer *signer = शून्य;
	अक्षर *hashalg = शून्य;

	/* Check file arguments. */
	क्रम (i = 0; i < argc; i++) {
		अगर (म_भेद(argv[i], "-") != 0)
			जारी;
		अगर (i > 0 || argc > 1)
			fatal("Cannot sign mix of paths and standard input");
	}

	अगर (sig_process_opts(opts, nopts, &hashalg, शून्य, शून्य) != 0)
		जाओ done; /* error already logged */

	अगर ((r = sshkey_load_public(keypath, &pubkey, शून्य)) != 0) {
		error_r(r, "Couldn't load public key %s", keypath);
		जाओ done;
	}

	अगर ((r = ssh_get_authentication_socket(&agent_fd)) != 0) {
		अगर (require_agent)
			fatal("Couldn't get agent socket");
		debug_r(r, "Couldn't get agent socket");
	} अन्यथा {
		अगर ((r = ssh_agent_has_कुंजी(agent_fd, pubkey)) == 0)
			signer = agent_signer;
		अन्यथा {
			अगर (require_agent)
				fatal("Couldn't find key in agent");
			debug_r(r, "Couldn't find key in agent");
		}
	}

	अगर (signer == शून्य) {
		/* Not using agent - try to load private key */
		अगर ((privkey = load_sign_कुंजी(keypath, pubkey)) == शून्य)
			जाओ done;
		signkey = privkey;
	} अन्यथा {
		/* Will use key in agent */
		signkey = pubkey;
	}

	अगर (argc == 0) {
		अगर ((r = sign_one(signkey, "(stdin)", STDIN_FILENO,
		    sig_namespace, hashalg, signer, &agent_fd)) != 0)
			जाओ done;
	} अन्यथा {
		क्रम (i = 0; i < argc; i++) {
			अगर (म_भेद(argv[i], "-") == 0)
				fd = STDIN_FILENO;
			अन्यथा अगर ((fd = खोलो(argv[i], O_RDONLY)) == -1) {
				error("Cannot open %s for signing: %s",
				    argv[i], म_त्रुटि(त्रुटि_सं));
				जाओ done;
			}
			अगर ((r = sign_one(signkey, argv[i], fd, sig_namespace,
			    hashalg, signer, &agent_fd)) != 0)
				जाओ done;
			अगर (fd != STDIN_FILENO)
				बंद(fd);
			fd = -1;
		}
	}

	ret = 0;
done:
	अगर (fd != -1 && fd != STDIN_FILENO)
		बंद(fd);
	sshkey_free(pubkey);
	sshkey_free(privkey);
	मुक्त(hashalg);
	वापस ret;
}

अटल पूर्णांक
sig_verify(स्थिर अक्षर *signature, स्थिर अक्षर *sig_namespace,
    स्थिर अक्षर *principal, स्थिर अक्षर *allowed_कुंजियाँ, स्थिर अक्षर *revoked_कुंजियाँ,
    अक्षर * स्थिर *opts, माप_प्रकार nopts)
{
	पूर्णांक r, ret = -1;
	पूर्णांक print_pubkey = 0;
	काष्ठा sshbuf *sigbuf = शून्य, *abuf = शून्य;
	काष्ठा sshkey *sign_कुंजी = शून्य;
	अक्षर *fp = शून्य;
	काष्ठा sshkey_sig_details *sig_details = शून्य;
	uint64_t verify_time = 0;

	अगर (sig_process_opts(opts, nopts, शून्य, &verify_time,
	    &print_pubkey) != 0)
		जाओ done; /* error already logged */

	स_रखो(&sig_details, 0, माप(sig_details));
	अगर ((r = sshbuf_load_file(signature, &abuf)) != 0) {
		error_r(r, "Couldn't read signature file");
		जाओ done;
	}

	अगर ((r = sshsig_dearmor(abuf, &sigbuf)) != 0) {
		error_fr(r, "sshsig_armor");
		जाओ done;
	}
	अगर ((r = sshsig_verify_fd(sigbuf, STDIN_FILENO, sig_namespace,
	    &sign_कुंजी, &sig_details)) != 0)
		जाओ done; /* sshsig_verify() prints error */

	अगर ((fp = sshkey_fingerprint(sign_कुंजी, fingerprint_hash,
	    SSH_FP_DEFAULT)) == शून्य)
		fatal_f("sshkey_fingerprint failed");
	debug("Valid (unverified) signature from key %s", fp);
	अगर (sig_details != शून्य) {
		debug2_f("signature details: counter = %u, flags = 0x%02x",
		    sig_details->sk_गणक, sig_details->sk_flags);
	}
	मुक्त(fp);
	fp = शून्य;

	अगर (revoked_कुंजियाँ != शून्य) {
		अगर ((r = sshkey_check_revoked(sign_कुंजी, revoked_कुंजियाँ)) != 0) {
			debug3_fr(r, "sshkey_check_revoked");
			जाओ done;
		}
	}

	अगर (allowed_कुंजियाँ != शून्य && (r = sshsig_check_allowed_कुंजियाँ(allowed_कुंजियाँ,
	    sign_कुंजी, principal, sig_namespace, verify_time)) != 0) {
		debug3_fr(r, "sshsig_check_allowed_keys");
		जाओ done;
	}
	/* success */
	ret = 0;
done:
	अगर (!quiet) {
		अगर (ret == 0) {
			अगर ((fp = sshkey_fingerprint(sign_कुंजी, fingerprint_hash,
			    SSH_FP_DEFAULT)) == शून्य)
				fatal_f("sshkey_fingerprint failed");
			अगर (principal == शून्य) {
				म_लिखो("Good \"%s\" signature with %s key %s\n",
				    sig_namespace, sshkey_type(sign_कुंजी), fp);

			} अन्यथा {
				म_लिखो("Good \"%s\" signature for %s with %s key %s\n",
				    sig_namespace, principal,
				    sshkey_type(sign_कुंजी), fp);
			}
		} अन्यथा {
			म_लिखो("Could not verify signature.\n");
		}
	}
	/* Print the signature key if requested */
	अगर (ret == 0 && print_pubkey && sign_कुंजी != शून्य) {
		अगर ((r = sshkey_write(sign_कुंजी, मानक_निकास)) == 0)
			ख_अक्षर_दो('\n', मानक_निकास);
		अन्यथा {
			error_r(r, "Could not print public key.\n");
			ret = -1;
		}
	}
	sshbuf_free(sigbuf);
	sshbuf_free(abuf);
	sshkey_free(sign_कुंजी);
	sshkey_sig_details_free(sig_details);
	मुक्त(fp);
	वापस ret;
}

अटल पूर्णांक
sig_find_principals(स्थिर अक्षर *signature, स्थिर अक्षर *allowed_कुंजियाँ,
    अक्षर * स्थिर *opts, माप_प्रकार nopts)
{
	पूर्णांक r, ret = -1;
	काष्ठा sshbuf *sigbuf = शून्य, *abuf = शून्य;
	काष्ठा sshkey *sign_कुंजी = शून्य;
	अक्षर *principals = शून्य, *cp, *tmp;
	uint64_t verify_time = 0;

	अगर (sig_process_opts(opts, nopts, शून्य, &verify_time, शून्य) != 0)
		जाओ done; /* error already logged */

	अगर ((r = sshbuf_load_file(signature, &abuf)) != 0) {
		error_r(r, "Couldn't read signature file");
		जाओ done;
	}
	अगर ((r = sshsig_dearmor(abuf, &sigbuf)) != 0) {
		error_fr(r, "sshsig_armor");
		जाओ done;
	}
	अगर ((r = sshsig_get_pubkey(sigbuf, &sign_कुंजी)) != 0) {
		error_fr(r, "sshsig_get_pubkey");
		जाओ done;
	}
	अगर ((r = sshsig_find_principals(allowed_कुंजियाँ, sign_कुंजी,
	    verify_time, &principals)) != 0) {
		अगर (r != SSH_ERR_कुंजी_NOT_FOUND)
			error_fr(r, "sshsig_find_principal");
		जाओ done;
	}
	ret = 0;
done:
	अगर (ret == 0 ) {
		/* Emit matching principals one per line */
		tmp = principals;
		जबतक ((cp = strsep(&tmp, ",")) != शून्य && *cp != '\0')
			माला_दो(cp);
	} अन्यथा {
		ख_लिखो(मानक_त्रुटि, "No principal matched.\n");
	}
	sshbuf_free(sigbuf);
	sshbuf_free(abuf);
	sshkey_free(sign_कुंजी);
	मुक्त(principals);
	वापस ret;
}

अटल पूर्णांक
sig_match_principals(स्थिर अक्षर *allowed_कुंजियाँ, अक्षर *principal,
	अक्षर * स्थिर *opts, माप_प्रकार nopts)
{
	पूर्णांक r;
	अक्षर **principals = शून्य;
	माप_प्रकार i, nprincipals = 0;

	अगर ((r = sig_process_opts(opts, nopts, शून्य, शून्य, शून्य)) != 0)
		वापस r; /* error already logged */

	अगर ((r = sshsig_match_principals(allowed_कुंजियाँ, principal,
	    &principals, &nprincipals)) != 0) {
		debug_f("match: %s", ssh_err(r));
		ख_लिखो(मानक_त्रुटि, "No principal matched.\n");
		वापस r;
	}
	क्रम (i = 0; i < nprincipals; i++) {
		म_लिखो("%s\n", principals[i]);
		मुक्त(principals[i]);
	}
	मुक्त(principals);

	वापस 0;
}

अटल व्योम
do_moduli_gen(स्थिर अक्षर *out_file, अक्षर **opts, माप_प्रकार nopts)
{
#अगर_घोषित WITH_OPENSSL
	/* Moduli generation/screening */
	BIGNUM *start = शून्य;
	पूर्णांक moduli_bits = 0;
	खाता *out;
	माप_प्रकार i;
	स्थिर अक्षर *errstr, *p;

	/* Parse options */
	क्रम (i = 0; i < nopts; i++) {
		अगर ((p = strprefix(opts[i], "start=", 0)) != शून्य) {
			/* XXX - also compare length against bits */
			अगर (BN_hex2bn(&start, p) == 0)
				fatal("Invalid start point.");
		} अन्यथा अगर ((p = strprefix(opts[i], "bits=", 0)) != शून्य) {
			moduli_bits = (पूर्णांक)strtonum(p, 1, पूर्णांक_उच्च, &errstr);
			अगर (errstr) {
				fatal("Invalid number: %s (%s)", p, errstr);
			}
		} अन्यथा {
			fatal("Option \"%s\" is unsupported for moduli "
			    "generation", opts[i]);
		}
	}

	अगर (म_भेद(out_file, "-") == 0)
		out = मानक_निकास;
	अन्यथा अगर ((out = ख_खोलो(out_file, "w")) == शून्य) {
		fatal("Couldn't open modulus candidate file \"%s\": %s",
		    out_file, म_त्रुटि(त्रुटि_सं));
	}
	रखो_भबफ(out, शून्य, _IOLBF, 0);

	अगर (moduli_bits == 0)
		moduli_bits = DEFAULT_BITS;
	अगर (gen_candidates(out, moduli_bits, start) != 0)
		fatal("modulus candidate generation failed");
#अन्यथा /* WITH_OPENSSL */
	fatal("Moduli generation is not supported");
#पूर्ण_अगर /* WITH_OPENSSL */
}

अटल व्योम
do_moduli_screen(स्थिर अक्षर *out_file, अक्षर **opts, माप_प्रकार nopts)
{
#अगर_घोषित WITH_OPENSSL
	/* Moduli generation/screening */
	अक्षर *checkpoint = शून्य;
	uint32_t generator_wanted = 0;
	अचिन्हित दीर्घ start_lineno = 0, पंक्तियाँ_to_process = 0;
	पूर्णांक अभाज्य_tests = 0;
	खाता *out, *in = मानक_निवेश;
	माप_प्रकार i;
	स्थिर अक्षर *errstr, *p;

	/* Parse options */
	क्रम (i = 0; i < nopts; i++) {
		अगर ((p = strprefix(opts[i], "lines=", 0)) != शून्य) {
			पंक्तियाँ_to_process = म_से_अदीर्घ(p, शून्य, 10);
		} अन्यथा अगर ((p = strprefix(opts[i], "start-line=", 0)) != शून्य) {
			start_lineno = म_से_अदीर्घ(p, शून्य, 10);
		} अन्यथा अगर ((p = strprefix(opts[i], "checkpoint=", 0)) != शून्य) {
			मुक्त(checkpoint);
			checkpoint = xstrdup(p);
		} अन्यथा अगर ((p = strprefix(opts[i], "generator=", 0)) != शून्य) {
			generator_wanted = (uint32_t)strtonum(p, 1, अच_पूर्णांक_उच्च,
			    &errstr);
			अगर (errstr != शून्य) {
				fatal("Generator invalid: %s (%s)", p, errstr);
			}
		} अन्यथा अगर ((p = strprefix(opts[i], "prime-tests=", 0)) != शून्य) {
			अभाज्य_tests = (पूर्णांक)strtonum(p, 1, पूर्णांक_उच्च, &errstr);
			अगर (errstr) {
				fatal("Invalid number: %s (%s)", p, errstr);
			}
		} अन्यथा {
			fatal("Option \"%s\" is unsupported for moduli "
			    "screening", opts[i]);
		}
	}

	अगर (have_identity && म_भेद(identity_file, "-") != 0) {
		अगर ((in = ख_खोलो(identity_file, "r")) == शून्य) {
			fatal("Couldn't open modulus candidate "
			    "file \"%s\": %s", identity_file,
			    म_त्रुटि(त्रुटि_सं));
		}
	}

	अगर (म_भेद(out_file, "-") == 0)
		out = मानक_निकास;
	अन्यथा अगर ((out = ख_खोलो(out_file, "a")) == शून्य) {
		fatal("Couldn't open moduli file \"%s\": %s",
		    out_file, म_त्रुटि(त्रुटि_सं));
	}
	रखो_भबफ(out, शून्य, _IOLBF, 0);
	अगर (अभाज्य_test(in, out, अभाज्य_tests == 0 ? 100 : अभाज्य_tests,
	    generator_wanted, checkpoint,
	    start_lineno, पंक्तियाँ_to_process) != 0)
		fatal("modulus screening failed");
	अगर (in != मानक_निवेश)
		(व्योम)ख_बंद(in);
	मुक्त(checkpoint);
#अन्यथा /* WITH_OPENSSL */
	fatal("Moduli screening is not supported");
#पूर्ण_अगर /* WITH_OPENSSL */
}

/* Read and confirm a passphrase */
अटल अक्षर *
read_check_passphrase(स्थिर अक्षर *prompt1, स्थिर अक्षर *prompt2,
    स्थिर अक्षर *retry_prompt)
{
	अक्षर *passphrase1, *passphrase2;

	क्रम (;;) {
		passphrase1 = read_passphrase(prompt1, RP_ALLOW_STDIN);
		passphrase2 = read_passphrase(prompt2, RP_ALLOW_STDIN);
		अगर (म_भेद(passphrase1, passphrase2) == 0) {
			freezero(passphrase2, म_माप(passphrase2));
			वापस passphrase1;
		}
		/* The passphrases do not match. Clear them and retry. */
		freezero(passphrase1, म_माप(passphrase1));
		freezero(passphrase2, म_माप(passphrase2));
		ख_माला_दो(retry_prompt, मानक_निकास);
		ख_अक्षर_दो('\n', मानक_निकास);
		ख_साफ(मानक_निकास);
	}
	/* NOTREACHED */
	वापस शून्य;
}

अटल अक्षर *
private_कुंजी_passphrase(स्थिर अक्षर *path)
{
	अक्षर *prompt, *ret;

	अगर (identity_passphrase)
		वापस xstrdup(identity_passphrase);
	अगर (identity_new_passphrase)
		वापस xstrdup(identity_new_passphrase);

	xasprintf(&prompt, "Enter passphrase for \"%s\" "
	    "(empty for no passphrase): ", path);
	ret = read_check_passphrase(prompt,
	    "Enter same passphrase again: ",
	    "Passphrases do not match.  Try again.");
	मुक्त(prompt);
	वापस ret;
}

अटल अक्षर *
sk_suffix(स्थिर अक्षर *application, स्थिर uint8_t *user, माप_प्रकार userlen)
{
	अक्षर *ret, *cp;
	स्थिर अक्षर *p;
	माप_प्रकार slen, i;

	/* Trim off URL-like preamble */
	अगर ((p = strprefix(application, "ssh://", 0)) != शून्य)
		ret =  xstrdup(p);
	अन्यथा अगर ((p = strprefix(application, "ssh:", 0)) != शून्य)
		ret =  xstrdup(p);
	अन्यथा
		ret = xstrdup(application);

	/* Count trailing zeros in user */
	क्रम (i = 0; i < userlen; i++) {
		अगर (user[userlen - i - 1] != 0)
			अवरोध;
	}
	अगर (i >= userlen)
		वापस ret; /* user-id was default all-zeros */

	/* Append user-id, escaping non-UTF-8 characters */
	slen = userlen - i;
	अगर (asmprintf(&cp, पूर्णांक_उच्च, शून्य, "%.*s", (पूर्णांक)slen, user) == -1)
		fatal_f("asmprintf failed");
	/* Don't emit a user-id that contains path or control characters */
	अगर (म_अक्षर(cp, '/') != शून्य || म_माला(cp, "..") != शून्य ||
	    म_अक्षर(cp, '\\') != शून्य) {
		मुक्त(cp);
		cp = tohex(user, slen);
	}
	xextendf(&ret, "_", "%s", cp);
	मुक्त(cp);
	वापस ret;
}

अटल पूर्णांक
do_download_sk(स्थिर अक्षर *skprovider, स्थिर अक्षर *device)
{
	काष्ठा sshsk_resident_कुंजी **srks;
	माप_प्रकार nsrks, i;
	पूर्णांक r, ret = -1;
	अक्षर *fp, *pin = शून्य, *pass = शून्य, *path, *pubpath;
	स्थिर अक्षर *ext;
	काष्ठा sshkey *कुंजी;

	अगर (skprovider == शून्य)
		fatal("Cannot download keys without provider");

	pin = read_passphrase("Enter PIN for authenticator: ", RP_ALLOW_STDIN);
	अगर (!quiet) {
		म_लिखो("You may need to touch your authenticator "
		    "to authorize key download.\n");
	}
	अगर ((r = sshsk_load_resident(skprovider, device, pin, 0,
	    &srks, &nsrks)) != 0) {
		अगर (pin != शून्य)
			freezero(pin, म_माप(pin));
		error_r(r, "Unable to load resident keys");
		वापस -1;
	}
	अगर (nsrks == 0)
		logit("No keys to download");
	अगर (pin != शून्य)
		freezero(pin, म_माप(pin));

	क्रम (i = 0; i < nsrks; i++) {
		कुंजी = srks[i]->कुंजी;
		अगर (कुंजी->type != कुंजी_ECDSA_SK && कुंजी->type != कुंजी_ED25519_SK) {
			error("Unsupported key type %s (%d)",
			    sshkey_type(कुंजी), कुंजी->type);
			जारी;
		}
		अगर ((fp = sshkey_fingerprint(कुंजी, fingerprint_hash,
		    SSH_FP_DEFAULT)) == शून्य)
			fatal_f("sshkey_fingerprint failed");
		debug_f("key %zu: %s %s %s (flags 0x%02x)", i,
		    sshkey_type(कुंजी), fp, कुंजी->sk_application, कुंजी->sk_flags);
		ext = sk_suffix(कुंजी->sk_application,
		    srks[i]->user_id, srks[i]->user_id_len);
		xasprintf(&path, "id_%s_rk%s%s",
		    कुंजी->type == कुंजी_ECDSA_SK ? "ecdsa_sk" : "ed25519_sk",
		    *ext == '\0' ? "" : "_", ext);

		/* If the file already exists, ask the user to confirm. */
		अगर (!confirm_overwrite(path)) {
			मुक्त(path);
			अवरोध;
		}

		/* Save the key with the application string as the comment */
		अगर (pass == शून्य)
			pass = private_कुंजी_passphrase(path);
		अगर ((r = sshkey_save_private(कुंजी, path, pass,
		    कुंजी->sk_application, private_कुंजी_format,
		    openssh_format_cipher, rounds)) != 0) {
			error_r(r, "Saving key \"%s\" failed", path);
			मुक्त(path);
			अवरोध;
		}
		अगर (!quiet) {
			म_लिखो("Saved %s key%s%s to %s\n", sshkey_type(कुंजी),
			    *ext != '\0' ? " " : "",
			    *ext != '\0' ? कुंजी->sk_application : "",
			    path);
		}

		/* Save public key too */
		xasprintf(&pubpath, "%s.pub", path);
		मुक्त(path);
		अगर ((r = sshkey_save_public(कुंजी, pubpath,
		    कुंजी->sk_application)) != 0) {
			error_r(r, "Saving public key \"%s\" failed", pubpath);
			मुक्त(pubpath);
			अवरोध;
		}
		मुक्त(pubpath);
	}

	अगर (i >= nsrks)
		ret = 0; /* success */
	अगर (pass != शून्य)
		freezero(pass, म_माप(pass));
	sshsk_free_resident_कुंजियाँ(srks, nsrks);
	वापस ret;
}

अटल व्योम
save_attestation(काष्ठा sshbuf *attest, स्थिर अक्षर *path)
{
	mode_t omask;
	पूर्णांक r;

	अगर (path == शून्य)
		वापस; /* nothing to do */
	अगर (attest == शून्य || sshbuf_len(attest) == 0)
		fatal("Enrollment did not return attestation data");
	omask = umask(077);
	r = sshbuf_write_file(path, attest);
	umask(omask);
	अगर (r != 0)
		fatal_r(r, "Unable to write attestation data \"%s\"", path);
	अगर (!quiet)
		म_लिखो("Your FIDO attestation certificate has been saved in "
		    "%s\n", path);
}

अटल पूर्णांक
confirm_sk_overwrite(स्थिर अक्षर *application, स्थिर अक्षर *user)
{
	अक्षर yesno[3];

	म_लिखो("A resident key scoped to '%s' with user id '%s' already "
	    "exists.\n", application == शून्य ? "ssh:" : application,
	    user == शून्य ? "null" : user);
	म_लिखो("Overwrite key in token (y/n)? ");
	ख_साफ(मानक_निकास);
	अगर (ख_माला_लो(yesno, माप(yesno), मानक_निवेश) == शून्य)
		वापस 0;
	अगर (yesno[0] != 'y' && yesno[0] != 'Y')
		वापस 0;
	वापस 1;
}

अटल व्योम
usage(व्योम)
{
	ख_लिखो(मानक_त्रुटि,
	    "usage: ssh-keygen [-q] [-a rounds] [-b bits] [-C comment] [-f output_keyfile]\n"
	    "                  [-m format] [-N new_passphrase] [-O option]\n"
	    "                  [-t ecdsa|ecdsa-sk|ed25519|ed25519-sk|mldsa44-ed25519|rsa]\n"
	    "                  [-w provider] [-Z cipher]\n"
	    "       ssh-keygen -p [-a rounds] [-f keyfile] [-m format] [-N new_passphrase]\n"
	    "                   [-P old_passphrase] [-Z cipher]\n"
#अगर_घोषित WITH_OPENSSL
	    "       ssh-keygen -i [-f input_keyfile] [-m key_format]\n"
	    "       ssh-keygen -e [-f input_keyfile] [-m key_format]\n"
#पूर्ण_अगर
	    "       ssh-keygen -y [-f input_keyfile]\n"
	    "       ssh-keygen -c [-a rounds] [-C comment] [-f keyfile] [-P passphrase]\n"
	    "       ssh-keygen -l [-v] [-E fingerprint_hash] [-f input_keyfile]\n"
	    "       ssh-keygen -B [-f input_keyfile]\n");
#अगर_घोषित ENABLE_PKCS11
	ख_लिखो(मानक_त्रुटि,
	    "       ssh-keygen -D pkcs11\n");
#पूर्ण_अगर
	ख_लिखो(मानक_त्रुटि,
	    "       ssh-keygen -F hostname [-lv] [-f known_hosts_file]\n"
	    "       ssh-keygen -H [-f known_hosts_file]\n"
	    "       ssh-keygen -K [-a rounds] [-w provider]\n"
	    "       ssh-keygen -R hostname [-f known_hosts_file]\n"
	    "       ssh-keygen -r hostname [-g] [-f input_keyfile]\n"
#अगर_घोषित WITH_OPENSSL
	    "       ssh-keygen -M generate [-O option] output_file\n"
	    "       ssh-keygen -M screen [-f input_file] [-O option] output_file\n"
#पूर्ण_अगर
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
मुख्य(पूर्णांक argc, अक्षर **argv)
{
	अक्षर comment[कुंजी_COMMENT_MAX], *passphrase = शून्य;
	अक्षर *rr_hostname = शून्य, *ep, *fp, *ra;
	काष्ठा sshkey *निजी = शून्य, *खुला = शून्य;
	काष्ठा passwd *pw;
	पूर्णांक ret = 0, r, opt, type;
	पूर्णांक change_passphrase = 0, change_comment = 0, show_cert = 0;
	पूर्णांक find_host = 0, delete_host = 0, hash_hosts = 0;
	पूर्णांक gen_all_hostkeys = 0, gen_krl = 0, update_krl = 0, check_krl = 0;
	पूर्णांक prefer_agent = 0, convert_to = 0, convert_from = 0;
	पूर्णांक print_public = 0, print_generic = 0, cert_serial_autoinc = 0;
	पूर्णांक do_gen_candidates = 0, do_screen_candidates = 0, download_sk = 0;
	अचिन्हित दीर्घ दीर्घ cert_serial = 0;
	अक्षर *identity_comment = शून्य, *ca_कुंजी_path = शून्य, **opts = शून्य;
	अक्षर *sk_application = शून्य, *sk_device = शून्य, *sk_user = शून्य;
	अक्षर *sk_attestation_path = शून्य;
	काष्ठा sshbuf *challenge = शून्य, *attest = शून्य;
	माप_प्रकार i, nopts = 0;
	uint32_t bits = 0;
	uint8_t sk_flags = SSH_SK_USER_PRESENCE_REQD;
	स्थिर अक्षर *errstr, *p;
	पूर्णांक log_level = SYSLOG_LEVEL_INFO;
	अक्षर *sign_op = शून्य;

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
	अगर (!pw)
		fatal("No user exists for uid %lu", (u_long)getuid());
	pw = pwcopy(pw);
	अगर (gethostname(hostname, माप(hostname)) == -1)
		fatal("gethostname: %s", म_त्रुटि(त्रुटि_सं));

	sk_provider = दो_पर्या("SSH_SK_PROVIDER");

	/* Remaining characters: dGjJSTWx */
	जबतक ((opt = getopt(argc, argv, "ABHKLQUXceghiklopquvy"
	    "C:D:E:F:I:M:N:O:P:R:V:Y:Z:"
	    "a:b:f:g:m:n:r:s:t:w:z:")) != -1) {
		चयन (opt) {
		हाल 'A':
			gen_all_hostkeys = 1;
			अवरोध;
		हाल 'b':
			bits = (uint32_t)strtonum(optarg, 1, UINT32_MAX,
			    &errstr);
			अगर (errstr)
				fatal("Bits has bad value %s (%s)",
					optarg, errstr);
			अवरोध;
		हाल 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			अगर (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			अवरोध;
		हाल 'F':
			find_host = 1;
			rr_hostname = optarg;
			अवरोध;
		हाल 'H':
			hash_hosts = 1;
			अवरोध;
		हाल 'I':
			cert_कुंजी_id = optarg;
			अवरोध;
		हाल 'R':
			delete_host = 1;
			rr_hostname = optarg;
			अवरोध;
		हाल 'L':
			show_cert = 1;
			अवरोध;
		हाल 'l':
			print_fingerprint = 1;
			अवरोध;
		हाल 'B':
			print_bubblebabble = 1;
			अवरोध;
		हाल 'm':
			अगर (strcasecmp(optarg, "RFC4716") == 0 ||
			    strcasecmp(optarg, "ssh2") == 0) {
				convert_format = FMT_RFC4716;
				अवरोध;
			}
			अगर (strcasecmp(optarg, "PKCS8") == 0) {
				convert_format = FMT_PKCS8;
				private_कुंजी_format = SSHKEY_PRIVATE_PKCS8;
				अवरोध;
			}
			अगर (strcasecmp(optarg, "PEM") == 0) {
				convert_format = FMT_PEM;
				private_कुंजी_format = SSHKEY_PRIVATE_PEM;
				अवरोध;
			}
			अगर (strcasecmp(optarg, "hexdump") == 0) {
				convert_format = FMT_HEXDUMP;
				अवरोध;
			}
			fatal("Unsupported conversion format \"%s\"", optarg);
		हाल 'n':
			cert_principals = optarg;
			अवरोध;
		हाल 'o':
			/* no-op; new format is already the default */
			अवरोध;
		हाल 'p':
			change_passphrase = 1;
			अवरोध;
		हाल 'c':
			change_comment = 1;
			अवरोध;
		हाल 'f':
			अगर (strlcpy(identity_file, optarg,
			    माप(identity_file)) >= माप(identity_file))
				fatal("Identity filename too long");
			have_identity = 1;
			अवरोध;
		हाल 'g':
			print_generic = 1;
			अवरोध;
		हाल 'K':
			download_sk = 1;
			अवरोध;
		हाल 'P':
			identity_passphrase = optarg;
			अवरोध;
		हाल 'N':
			identity_new_passphrase = optarg;
			अवरोध;
		हाल 'Q':
			check_krl = 1;
			अवरोध;
		हाल 'O':
			opts = xrecallocarray(opts, nopts, nopts + 1,
			    माप(*opts));
			opts[nopts++] = xstrdup(optarg);
			अवरोध;
		हाल 'Z':
			openssh_format_cipher = optarg;
			अगर (cipher_by_name(openssh_format_cipher) == शून्य)
				fatal("Invalid OpenSSH-format cipher '%s'",
				    openssh_format_cipher);
			अवरोध;
		हाल 'C':
			identity_comment = optarg;
			अवरोध;
		हाल 'q':
			quiet = 1;
			अवरोध;
		हाल 'e':
			/* export key */
			convert_to = 1;
			अवरोध;
		हाल 'h':
			cert_कुंजी_type = SSH2_CERT_TYPE_HOST;
			certflags_flags = 0;
			अवरोध;
		हाल 'k':
			gen_krl = 1;
			अवरोध;
		हाल 'i':
		हाल 'X':
			/* import key */
			convert_from = 1;
			अवरोध;
		हाल 'y':
			print_public = 1;
			अवरोध;
		हाल 's':
			ca_कुंजी_path = optarg;
			अवरोध;
		हाल 't':
			कुंजी_type_name = optarg;
			अवरोध;
		हाल 'D':
			pkcs11provider = optarg;
			अवरोध;
		हाल 'U':
			prefer_agent = 1;
			अवरोध;
		हाल 'u':
			update_krl = 1;
			अवरोध;
		हाल 'v':
			अगर (log_level == SYSLOG_LEVEL_INFO)
				log_level = SYSLOG_LEVEL_DEBUG1;
			अन्यथा {
				अगर (log_level >= SYSLOG_LEVEL_DEBUG1 &&
				    log_level < SYSLOG_LEVEL_DEBUG3)
					log_level++;
			}
			अवरोध;
		हाल 'r':
			rr_hostname = optarg;
			अवरोध;
		हाल 'a':
			rounds = (पूर्णांक)strtonum(optarg, 1, पूर्णांक_उच्च, &errstr);
			अगर (errstr)
				fatal("Invalid number: %s (%s)",
					optarg, errstr);
			अवरोध;
		हाल 'V':
			parse_cert_times(optarg);
			अवरोध;
		हाल 'Y':
			sign_op = optarg;
			अवरोध;
		हाल 'w':
			sk_provider = optarg;
			अवरोध;
		हाल 'z':
			त्रुटि_सं = 0;
			अगर (*optarg == '+') {
				cert_serial_autoinc = 1;
				optarg++;
			}
			cert_serial = strtoull(optarg, &ep, 10);
			अगर (*optarg < '0' || *optarg > '9' || *ep != '\0' ||
			    (त्रुटि_सं == दुस्फल && cert_serial == ULLONG_MAX))
				fatal("Invalid serial number \"%s\"", optarg);
			अवरोध;
		हाल 'M':
			अगर (म_भेद(optarg, "generate") == 0)
				do_gen_candidates = 1;
			अन्यथा अगर (म_भेद(optarg, "screen") == 0)
				do_screen_candidates = 1;
			अन्यथा
				fatal("Unsupported moduli option %s", optarg);
			अवरोध;
		शेष:
			usage();
		}
	}

#अगर_घोषित ENABLE_SK_INTERNAL
	अगर (sk_provider == शून्य)
		sk_provider = "internal";
#पूर्ण_अगर

	/* reinit */
	log_init(argv[0], log_level, SYSLOG_FACILITY_USER, 1);

	argv += optind;
	argc -= optind;

	अगर (sign_op != शून्य) {
		अगर (strprefix(sign_op, "find-principals", 0) != शून्य) {
			अगर (ca_कुंजी_path == शून्य) {
				error("Too few arguments for find-principals:"
				    "missing signature file");
				निकास(1);
			}
			अगर (!have_identity) {
				error("Too few arguments for find-principals:"
				    "missing allowed keys file");
				निकास(1);
			}
			ret = sig_find_principals(ca_कुंजी_path, identity_file,
			    opts, nopts);
			जाओ done;
		} अन्यथा अगर (strprefix(sign_op, "match-principals", 0) != शून्य) {
			अगर (!have_identity) {
				error("Too few arguments for match-principals:"
				    "missing allowed keys file");
				निकास(1);
			}
			अगर (cert_कुंजी_id == शून्य) {
				error("Too few arguments for match-principals: "
				    "missing principal ID");
				निकास(1);
			}
			ret = sig_match_principals(identity_file, cert_कुंजी_id,
			    opts, nopts);
			जाओ done;
		} अन्यथा अगर (strprefix(sign_op, "sign", 0) != शून्य) {
			/* NB. cert_principals is actually namespace, via -n */
			अगर (cert_principals == शून्य ||
			    *cert_principals == '\0') {
				error("Too few arguments for sign: "
				    "missing namespace");
				निकास(1);
			}
			अगर (!have_identity) {
				error("Too few arguments for sign: "
				    "missing key");
				निकास(1);
			}
			ret = sig_sign(identity_file, cert_principals,
			    prefer_agent, argc, argv, opts, nopts);
			जाओ done;
		} अन्यथा अगर (strprefix(sign_op, "check-novalidate", 0) != शून्य) {
			/* NB. cert_principals is actually namespace, via -n */
			अगर (cert_principals == शून्य ||
			    *cert_principals == '\0') {
				error("Too few arguments for check-novalidate: "
				    "missing namespace");
				निकास(1);
			}
			अगर (ca_कुंजी_path == शून्य) {
				error("Too few arguments for check-novalidate: "
				    "missing signature file");
				निकास(1);
			}
			ret = sig_verify(ca_कुंजी_path, cert_principals,
			    शून्य, शून्य, शून्य, opts, nopts);
			जाओ done;
		} अन्यथा अगर (strprefix(sign_op, "verify", 0) != शून्य) {
			/* NB. cert_principals is actually namespace, via -n */
			अगर (cert_principals == शून्य ||
			    *cert_principals == '\0') {
				error("Too few arguments for verify: "
				    "missing namespace");
				निकास(1);
			}
			अगर (ca_कुंजी_path == शून्य) {
				error("Too few arguments for verify: "
				    "missing signature file");
				निकास(1);
			}
			अगर (!have_identity) {
				error("Too few arguments for sign: "
				    "missing allowed keys file");
				निकास(1);
			}
			अगर (cert_कुंजी_id == शून्य) {
				error("Too few arguments for verify: "
				    "missing principal identity");
				निकास(1);
			}
			ret = sig_verify(ca_कुंजी_path, cert_principals,
			    cert_कुंजी_id, identity_file, rr_hostname,
			    opts, nopts);
			जाओ done;
		}
		error("Unsupported operation for -Y: \"%s\"", sign_op);
		usage();
		/* NOTREACHED */
	}

	अगर (ca_कुंजी_path != शून्य) {
		अगर (argc < 1 && !gen_krl) {
			error("Too few arguments.");
			usage();
		}
	} अन्यथा अगर (argc > 0 && !gen_krl && !check_krl &&
	    !do_gen_candidates && !do_screen_candidates) {
		error("Too many arguments.");
		usage();
	}
	अगर (change_passphrase && change_comment) {
		error("Can only have one of -p and -c.");
		usage();
	}
	अगर (print_fingerprint && (delete_host || hash_hosts)) {
		error("Cannot use -l with -H or -R.");
		usage();
	}
	अगर (gen_krl) {
		do_gen_krl(pw, update_krl, ca_कुंजी_path,
		    cert_serial, identity_comment, argc, argv);
		जाओ done;
	}
	अगर (check_krl) {
		do_check_krl(pw, print_fingerprint, argc, argv);
		जाओ done;
	}
	अगर (ca_कुंजी_path != शून्य) {
		अगर (cert_कुंजी_id == शून्य)
			fatal("Must specify key id (-I) when certifying");
		अगर (cert_principals == शून्य) {
			/*
			 * Ideally this would be a fatal(), but we need to
			 * be able to generate such certificates for testing
			 * even though they will be rejected.
			 */
			error("Warning: certificate will contain no "
			    "principals (-n)");
		}
		क्रम (i = 0; i < nopts; i++)
			add_cert_option(opts[i]);
		do_ca_sign(pw, ca_कुंजी_path, prefer_agent,
		    cert_serial, cert_serial_autoinc, argc, argv);
		जाओ done;
	}
	अगर (show_cert)
		do_show_cert(pw);
	अगर (delete_host || hash_hosts || find_host) {
		do_known_hosts(pw, rr_hostname, find_host,
		    delete_host, hash_hosts);
	}
	अगर (pkcs11provider != शून्य)
		do_download(pw);
	अगर (download_sk) {
		क्रम (i = 0; i < nopts; i++) {
			अगर ((p = strprefix(opts[i], "device=", 1)) != शून्य) {
				sk_device = xstrdup(p);
			} अन्यथा {
				fatal("Option \"%s\" is unsupported for "
				    "FIDO authenticator download", opts[i]);
			}
		}
		ret = do_download_sk(sk_provider, sk_device);
		जाओ done;
	}
	अगर (print_fingerprint || print_bubblebabble)
		do_fingerprint(pw);
	अगर (change_passphrase)
		do_change_passphrase(pw, opts, nopts);
	अगर (change_comment)
		do_change_comment(pw, identity_comment);
#अगर_घोषित WITH_OPENSSL
	अगर (convert_to) {
		do_convert_to(pw);
		जाओ done;
	}
	अगर (convert_from) {
		do_convert_from(pw);
		जाओ done;
	}
#अन्यथा /* WITH_OPENSSL */
	अगर (convert_to || convert_from)
		fatal("key conversion disabled at compile time");
#पूर्ण_अगर /* WITH_OPENSSL */
	अगर (print_public)
		do_print_public(pw);
	अगर (rr_hostname != शून्य) {
		अचिन्हित पूर्णांक n = 0;

		अगर (have_identity) {
			n = do_print_resource_record(pw, identity_file,
			    rr_hostname, print_generic, opts, nopts);
			अगर (n == 0)
				fatal("%s: %s", identity_file, म_त्रुटि(त्रुटि_सं));
			निकास(0);
		} अन्यथा {

			n += do_print_resource_record(pw,
			    PATH_HOST_RSA_कुंजी_FILE, rr_hostname,
			    print_generic, opts, nopts);
			n += do_print_resource_record(pw,
			    PATH_HOST_ECDSA_कुंजी_FILE, rr_hostname,
			    print_generic, opts, nopts);
			n += do_print_resource_record(pw,
			    PATH_HOST_ED25519_कुंजी_FILE, rr_hostname,
			    print_generic, opts, nopts);
			अगर (n == 0)
				fatal("no keys found.");
			निकास(0);
		}
	}

	अगर (do_gen_candidates || do_screen_candidates) {
		अगर (argc <= 0)
			fatal("No output file specified");
		अन्यथा अगर (argc > 1)
			fatal("Too many output files specified");
	}
	अगर (do_gen_candidates) {
		do_moduli_gen(argv[0], opts, nopts);
		जाओ done;
	}
	अगर (do_screen_candidates) {
		do_moduli_screen(argv[0], opts, nopts);
		जाओ done;
	}

	अगर (gen_all_hostkeys) {
		do_gen_all_hostkeys(pw);
		जाओ done;
	}

	अगर (कुंजी_type_name == शून्य)
		कुंजी_type_name = DEFAULT_कुंजी_TYPE_NAME;

	type = sshkey_type_from_shortname(कुंजी_type_name);
	type_bits_valid(type, कुंजी_type_name, &bits);

	अगर (!quiet)
		म_लिखो("Generating public/private %s key pair.\n",
		    कुंजी_type_name);
	चयन (type) {
	हाल कुंजी_ECDSA_SK:
	हाल कुंजी_ED25519_SK:
		क्रम (i = 0; i < nopts; i++) {
			अगर (strcasecmp(opts[i], "no-touch-required") == 0) {
				sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
			} अन्यथा अगर (strcasecmp(opts[i], "verify-required") == 0) {
				sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
			} अन्यथा अगर (strcasecmp(opts[i], "resident") == 0) {
				sk_flags |= SSH_SK_RESIDENT_कुंजी;
			} अन्यथा अगर ((p = strprefix(opts[i], "device=", 1))
			    != शून्य ) {
				sk_device = xstrdup(p);
			} अन्यथा अगर ((p = strprefix(opts[i], "user=", 1))
			    != शून्य) {
				sk_user = xstrdup(p);
			} अन्यथा अगर ((p = strprefix(opts[i], "challenge=", 1))
			    != शून्य) {
				अगर ((r = sshbuf_load_file(p,
				    &challenge)) != 0) {
					fatal_r(r, "Unable to load FIDO "
					    "enrollment challenge \"%s\"", p);
				}
			} अन्यथा अगर (strncasecmp(opts[i],
			    "write-attestation=", 18) == 0) {
				sk_attestation_path = opts[i] + 18;
			} अन्यथा अगर (strncasecmp(opts[i],
			    "application=", 12) == 0) {
				sk_application = xstrdup(opts[i] + 12);
				अगर (म_भेदन(sk_application, "ssh:", 4) != 0) {
					fatal("FIDO application string must "
					    "begin with \"ssh:\"");
				}
			} अन्यथा {
				fatal("Option \"%s\" is unsupported for "
				    "FIDO authenticator enrollment", opts[i]);
			}
		}
		अगर ((attest = sshbuf_new()) == शून्य)
			fatal("sshbuf_new failed");
		r = 0;
		क्रम (i = 0 ;;) {
			अगर (!quiet) {
				म_लिखो("You may need to touch your "
				    "authenticator%s to authorize key "
				    "generation.\n",
				    r == 0 ? "" : " again");
			}
			ख_साफ(मानक_निकास);
			r = sshsk_enroll(type, sk_provider, sk_device,
			    sk_application == शून्य ? "ssh:" : sk_application,
			    sk_user, sk_flags, passphrase, challenge,
			    &निजी, attest);
			अगर (r == 0)
				अवरोध;
			अगर (r == SSH_ERR_कुंजी_BAD_PERMISSIONS &&
			    (sk_flags & SSH_SK_RESIDENT_कुंजी) != 0 &&
			    (sk_flags & SSH_SK_FORCE_OPERATION) == 0 &&
			    confirm_sk_overwrite(sk_application, sk_user)) {
				sk_flags |= SSH_SK_FORCE_OPERATION;
				जारी;
			}
			अगर (r != SSH_ERR_कुंजी_WRONG_PASSPHRASE)
				fatal_r(r, "Key enrollment failed");
			अन्यथा अगर (passphrase != शून्य) {
				error("PIN incorrect");
				freezero(passphrase, म_माप(passphrase));
				passphrase = शून्य;
			}
			अगर (++i >= 3)
				fatal("Too many incorrect PINs");
			passphrase = read_passphrase("Enter PIN for "
			    "authenticator: ", RP_ALLOW_STDIN);
		}
		अगर (passphrase != शून्य) {
			freezero(passphrase, म_माप(passphrase));
			passphrase = शून्य;
		}
		अवरोध;
	शेष:
		अगर ((r = sshkey_generate(type, bits, &निजी)) != 0)
			fatal("sshkey_generate failed");
		अवरोध;
	}
	अगर ((r = sshkey_from_private(निजी, &खुला)) != 0)
		fatal_r(r, "sshkey_from_private");

	अगर (!have_identity)
		ask_filename(pw, "Enter file in which to save the key");

	/* Create ~/.ssh directory if it doesn't already exist. */
	hostfile_create_user_ssh_dir(identity_file, !quiet);

	/* If the file already exists, ask the user to confirm. */
	अगर (!confirm_overwrite(identity_file))
		निकास(1);

	/* Determine the passphrase for the private key */
	passphrase = private_कुंजी_passphrase(identity_file);
	अगर (identity_comment) {
		strlcpy(comment, identity_comment, माप(comment));
	} अन्यथा {
		/* Create default comment field for the passphrase. */
		snprintf(comment, माप comment, "%s@%s", pw->pw_name, hostname);
	}



	/* Save the key with the given passphrase and comment. */
	अगर ((r = sshkey_save_private(निजी, identity_file, passphrase,
	    comment, private_कुंजी_format, openssh_format_cipher, rounds)) != 0) {
		error_r(r, "Saving key \"%s\" failed", identity_file);
		freezero(passphrase, म_माप(passphrase));
		निकास(1);
	}
	freezero(passphrase, म_माप(passphrase));
	sshkey_free(निजी);

	अगर (!quiet) {
		म_लिखो("Your identification has been saved in %s\n",
		    identity_file);
	}

	strlcat(identity_file, ".pub", माप(identity_file));
	अगर ((r = sshkey_save_public(खुला, identity_file, comment)) != 0)
		fatal_r(r, "Unable to save public key to %s", identity_file);

	अगर (!quiet) {
		fp = sshkey_fingerprint(खुला, fingerprint_hash,
		    SSH_FP_DEFAULT);
		ra = sshkey_fingerprint(खुला, fingerprint_hash,
		    SSH_FP_RANDOMART);
		अगर (fp == शून्य || ra == शून्य)
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

	अगर (sk_attestation_path != शून्य)
		save_attestation(attest, sk_attestation_path);

 done:
	sshbuf_free(attest);
	sshkey_free(खुला);
	pwfree(pw);
	निकास(ret);
}
