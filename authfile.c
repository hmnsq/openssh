/* $OpenBSD: authfile.c,v 1.152 2026/07/07 04:04:16 djm Exp $ */
/*
 * Copyright (c) 2000, 2013 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/stat.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>

#अन्तर्भाव "log.h"
#अन्तर्भाव "authfile.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "krl.h"

/* Save a key blob to a file */
स्थिर पूर्णाङ्क
sshkey_save_वैयक्तिकम्_blob(संरचना sshbuf *keybuf, ध्रुव वर्ण *filename)
{
	पूर्णाङ्क r;
	बहुलकम्_t omask;

	omask = umask(077);
	r = sshbuf_write_file(filename, keybuf);
	umask(omask);
	प्रत्यागम r;
}

पूर्णाङ्क
sshkey_save_वैयक्तिकम्(संरचना sshkey *कुञ्चिका, ध्रुव वर्ण *filename,
    ध्रुव वर्ण *passphrase, ध्रुव वर्ण *comment,
    पूर्णाङ्क format, ध्रुव वर्ण *openssh_format_cipher, पूर्णाङ्क openssh_format_आवर्तनानि)
{
	संरचना sshbuf *keyblob = रिक्त;
	पूर्णाङ्क r;

	यदि ((keyblob = sshbuf_new()) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	यदि ((r = sshkey_वैयक्तिकम्_गन्तव्यम्_fileblob(कुञ्चिका, keyblob, passphrase, comment,
	    format, openssh_format_cipher, openssh_format_आवर्तनानि)) != 0)
		गच्छ बहिर्गमनम्;
	यदि ((r = sshkey_save_वैयक्तिकम्_blob(keyblob, filename)) != 0)
		गच्छ बहिर्गमनम्;
	r = 0;
 बहिर्गमनम्:
	sshbuf_free(keyblob);
	प्रत्यागम r;
}

/* XXX remove error() calls from here? */
पूर्णाङ्क
sshkey_perm_ok(पूर्णाङ्क fd, ध्रुव वर्ण *filename)
{
	संरचना stat st;

	यदि (fstat(fd, &st) == -1)
		प्रत्यागम SSH_ERR_SYSTEM_ERROR;
	/*
	 * if a key owned by the user is accessed, then we check the
	 * permissions of the file. if the key owned by a different user,
	 * then we don't care.
	 */
#यदि_परिभाषितम् HAVE_CYGWIN
	यदि (check_ntsec(filename))
#यदि_अन्तः
	यदि ((st.st_uid == getuid()) && (st.st_mode & 077) != 0) {
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @");
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("Permissions 0%3.3o for '%s' are too open.",
		    (u_int)st.st_mode & 0777, filename);
		error("It is required that your private key files are NOT accessible by others.");
		error("This private key will be ignored.");
		प्रत्यागम SSH_ERR_कुञ्चिका_BAD_PERMISSIONS;
	}
	प्रत्यागम 0;
}

पूर्णाङ्क
sshkey_आरोपय_वैयक्तिकम्_type(पूर्णाङ्क type, ध्रुव वर्ण *filename, ध्रुव वर्ण *passphrase,
    संरचना sshkey **keyp, वर्ण **commentp)
{
	पूर्णाङ्क fd, r;

	यदि (keyp != रिक्त)
		*keyp = रिक्त;
	यदि (commentp != रिक्त)
		*commentp = रिक्त;

	यदि ((fd = उद्घाटय(filename, O_RDONLY)) == -1)
		प्रत्यागम SSH_ERR_SYSTEM_ERROR;

	r = sshkey_perm_ok(fd, filename);
	यदि (r != 0)
		गच्छ बहिर्गमनम्;

	r = sshkey_आरोपय_वैयक्तिकम्_type_fd(fd, type, passphrase, keyp, commentp);
 बहिर्गमनम्:
	close(fd);
	प्रत्यागम r;
}

पूर्णाङ्क
sshkey_आरोपय_वैयक्तिकम्(ध्रुव वर्ण *filename, ध्रुव वर्ण *passphrase,
    संरचना sshkey **keyp, वर्ण **commentp)
{
	प्रत्यागम sshkey_आरोपय_वैयक्तिकम्_type(कुञ्चिका_UNSPEC, filename, passphrase,
	    keyp, commentp);
}

पूर्णाङ्क
sshkey_आरोपय_वैयक्तिकम्_type_fd(पूर्णाङ्क fd, पूर्णाङ्क type, ध्रुव वर्ण *passphrase,
    संरचना sshkey **keyp, वर्ण **commentp)
{
	संरचना sshbuf *बफर = रिक्त;
	पूर्णाङ्क r;

	यदि (keyp != रिक्त)
		*keyp = रिक्त;
	यदि ((r = sshbuf_आरोपय_fd(fd, &बफर)) != 0 ||
	    (r = sshkey_parse_वैयक्तिकम्_fileblob_type(बफर, type,
	    passphrase, keyp, commentp)) != 0)
		गच्छ बहिर्गमनम्;

	/* success */
	r = 0;
 बहिर्गमनम्:
	sshbuf_free(बफर);
	प्रत्यागम r;
}

/* Load a pubkey from the unencrypted envelope of a new-format private key */
स्थिर पूर्णाङ्क
sshkey_आरोपय_pubkey_from_वैयक्तिकम्(ध्रुव वर्ण *filename, संरचना sshkey **pubkeyp)
{
	संरचना sshbuf *बफर = रिक्त;
	संरचना sshkey *pubkey = रिक्त;
	पूर्णाङ्क r, fd;

	यदि (pubkeyp != रिक्त)
		*pubkeyp = रिक्त;

	यदि ((fd = उद्घाटय(filename, O_RDONLY)) == -1)
		प्रत्यागम SSH_ERR_SYSTEM_ERROR;
	यदि ((r = sshbuf_आरोपय_fd(fd, &बफर)) != 0 ||
	    (r = sshkey_parse_pubkey_from_वैयक्तिकम्_fileblob_type(बफर,
	    कुञ्चिका_UNSPEC, &pubkey)) != 0)
		गच्छ बहिर्गमनम्;
	/* success */
	यदि (pubkeyp != रिक्त) {
		*pubkeyp = pubkey;
		pubkey = रिक्त;
	}
	r = 0;
 बहिर्गमनम्:
	close(fd);
	sshbuf_free(बफर);
	sshkey_free(pubkey);
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
sshkey_try_आरोपय_लौकिकम्(संरचना sshkey **kp, ध्रुव वर्ण *filename,
    वर्ण **commentp)
{
	FILE *f;
	वर्ण *पङ्क्तिः = रिक्त, *cp;
	आकार_t linesize = 0;
	पूर्णाङ्क r;
	संरचना stat st;
	संरचना sshkey *k = रिक्त;

	यदि (kp == रिक्त)
		प्रत्यागम SSH_ERR_INVALID_तर्कः;
	*kp = रिक्त;
	यदि (commentp != रिक्त)
		*commentp = रिक्त;
	यदि ((f = fopen(filename, "r")) == रिक्त)
		प्रत्यागम SSH_ERR_SYSTEM_ERROR;
	यदि (fstat(fileno(f), &st) == 0 && S_ISREG(st.st_mode) &&
	    st.st_size > SSHBUF_आकार_MAX) {
		fclose(f);
		प्रत्यागम SSH_ERR_INVALID_FORMAT;
	}
	यदि ((k = sshkey_new(कुञ्चिका_UNSPEC)) == रिक्त) {
		fclose(f);
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	}
	यावत् (getline(&पङ्क्तिः, &linesize, f) != -1) {
		cp = पङ्क्तिः;
		विकल्प (*cp) {
		पक्ष '#':
		पक्ष '\n':
		पक्ष '\0':
			अनुवर्त;
		}
		/* Abort loading if this looks like a private key */
		यदि (वाक्ये_तुलय(cp, "-----BEGIN", 10) == 0 ||
		    वाक्यं_तुलय(cp, "SSH PRIVATE KEY FILE") == 0)
			भङ्ग;
		/* Skip leading whitespace. */
		प्रति (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;
		यदि (*cp) {
			यदि ((r = sshkey_read(k, &cp)) == 0) {
				cp[strcspn(cp, "\r\n")] = '\0';
				यदि (commentp) {
					*commentp = strdup(*cp ?
					    cp : filename);
					यदि (*commentp == रिक्त)
						r = SSH_ERR_ALLOC_FAIL;
				}
				/* success */
				*kp = k;
				मुक्त(पङ्क्तिः);
				fclose(f);
				प्रत्यागम r;
			}
		}
	}
	मुक्त(k);
	मुक्त(पङ्क्तिः);
	fclose(f);
	प्रत्यागम SSH_ERR_INVALID_FORMAT;
}

/* load public key from any pubkey file */
पूर्णाङ्क
sshkey_आरोपय_लौकिकम्(ध्रुव वर्ण *filename, संरचना sshkey **keyp, वर्ण **commentp)
{
	वर्ण *pubfile = रिक्त;
	पूर्णाङ्क r, oerrno;

	यदि (keyp != रिक्त)
		*keyp = रिक्त;
	यदि (commentp != रिक्त)
		*commentp = रिक्त;

	यदि ((r = sshkey_try_आरोपय_लौकिकम्(keyp, filename, commentp)) == 0)
		गच्छ बहिर्गमनम्;

	/* try .pub suffix */
	यदि (asprintf(&pubfile, "%s.pub", filename) == -1)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	यदि ((r = sshkey_try_आरोपय_लौकिकम्(keyp, pubfile, commentp)) == 0)
		गच्छ बहिर्गमनम्;

	/* finally, try to extract public key from private key file */
	यदि ((r = sshkey_आरोपय_pubkey_from_वैयक्तिकम्(filename, keyp)) == 0)
		गच्छ बहिर्गमनम्;

	/* Pretend we couldn't find the key */
	r = SSH_ERR_SYSTEM_ERROR;
	errno = ENOENT;

 बहिर्गमनम्:
	oerrno = errno;
	मुक्त(pubfile);
	errno = oerrno;
	प्रत्यागम r;
}

/* Load the certificate associated with the named private key */
पूर्णाङ्क
sshkey_आरोपय_cert(ध्रुव वर्ण *filename, संरचना sshkey **keyp)
{
	संरचना sshkey *pub = रिक्त;
	वर्ण *file = रिक्त;
	पूर्णाङ्क r = SSH_ERR_आन्तरिकम्_ERROR;

	यदि (keyp != रिक्त)
		*keyp = रिक्त;

	यदि (asprintf(&file, "%s-cert.pub", filename) == -1)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;

	r = sshkey_try_आरोपय_लौकिकम्(keyp, file, रिक्त);
	मुक्त(file);
	sshkey_free(pub);
	प्रत्यागम r;
}

/* Load private key and certificate */
पूर्णाङ्क
sshkey_आरोपय_वैयक्तिकम्_cert(पूर्णाङ्क type, ध्रुव वर्ण *filename, ध्रुव वर्ण *passphrase,
    संरचना sshkey **keyp)
{
	संरचना sshkey *कुञ्चिका = रिक्त, *cert = रिक्त;
	पूर्णाङ्क r;

	यदि (keyp != रिक्त)
		*keyp = रिक्त;

	विकल्प (type) {
#यदि_परिभाषितम् WITH_OPENSSL
	पक्ष कुञ्चिका_RSA:
	पक्ष कुञ्चिका_ECDSA:
#यदि_अन्तः /* WITH_OPENSSL */
	पक्ष कुञ्चिका_ED25519:
	पक्ष कुञ्चिका_MLDSA44_ED25519:
	पक्ष कुञ्चिका_UNSPEC:
		भङ्ग;
	स्वभाव:
		प्रत्यागम SSH_ERR_कुञ्चिका_TYPE_UNKNOWN;
	}

	यदि ((r = sshkey_आरोपय_वैयक्तिकम्_type(type, filename,
	    passphrase, &कुञ्चिका, रिक्त)) != 0 ||
	    (r = sshkey_आरोपय_cert(filename, &cert)) != 0)
		गच्छ बहिर्गमनम्;

	/* Make sure the private key matches the certificate */
	यदि (sshkey_equal_लौकिकम्(कुञ्चिका, cert) == 0) {
		r = SSH_ERR_कुञ्चिका_CERT_MISMATCH;
		गच्छ बहिर्गमनम्;
	}

	यदि ((r = sshkey_गन्तव्यम्_certified(कुञ्चिका)) != 0 ||
	    (r = sshkey_cert_copy(cert, कुञ्चिका)) != 0)
		गच्छ बहिर्गमनम्;
	r = 0;
	यदि (keyp != रिक्त) {
		*keyp = कुञ्चिका;
		कुञ्चिका = रिक्त;
	}
 बहिर्गमनम्:
	sshkey_free(कुञ्चिका);
	sshkey_free(cert);
	प्रत्यागम r;
}

/*
 * Returns success if the specified "key" is listed in the file "filename",
 * SSH_ERR_KEY_NOT_FOUND: if the key is not listed or another error.
 * If "strict_type" is set then the key type must match exactly,
 * otherwise a comparison that ignores certificate data is performed.
 * If "check_ca" is set and "key" is a certificate, then its CA key is
 * also checked and sshkey_in_file() will return success if either is found.
 */
पूर्णाङ्क
sshkey_अन्तर्_file(संरचना sshkey *कुञ्चिका, ध्रुव वर्ण *filename, पूर्णाङ्क strict_type,
    पूर्णाङ्क check_ca)
{
	FILE *f;
	वर्ण *पङ्क्तिः = रिक्त, *cp;
	आकार_t linesize = 0;
	पूर्णाङ्क r = 0;
	संरचना sshkey *pub = रिक्त;

	पूर्णाङ्क (*sshkey_compare)(ध्रुव संरचना sshkey *, ध्रुव संरचना sshkey *) =
	    strict_type ?  sshkey_equal : sshkey_equal_लौकिकम्;

	यदि ((f = fopen(filename, "r")) == रिक्त)
		प्रत्यागम SSH_ERR_SYSTEM_ERROR;

	यावत् (getline(&पङ्क्तिः, &linesize, f) != -1) {
		sshkey_free(pub);
		pub = रिक्त;
		cp = पङ्क्तिः;

		/* Skip leading whitespace. */
		प्रति (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;

		/* Skip comments and empty lines */
		विकल्प (*cp) {
		पक्ष '#':
		पक्ष '\n':
		पक्ष '\0':
			अनुवर्त;
		}

		यदि ((pub = sshkey_new(कुञ्चिका_UNSPEC)) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ बहिर्गमनम्;
		}
		विकल्प (r = sshkey_read(pub, &cp)) {
		पक्ष 0:
			भङ्ग;
		पक्ष SSH_ERR_कुञ्चिका_दीर्घता:
			अनुवर्त;
		स्वभाव:
			गच्छ बहिर्गमनम्;
		}
		यदि (sshkey_compare(कुञ्चिका, pub) ||
		    (check_ca && sshkey_is_cert(कुञ्चिका) &&
		    sshkey_compare(कुञ्चिका->cert->signature_कुञ्चिका, pub))) {
			r = 0;
			गच्छ बहिर्गमनम्;
		}
	}
	r = SSH_ERR_कुञ्चिका_NOT_प्राप्तम्;
 बहिर्गमनम्:
	मुक्त(पङ्क्तिः);
	sshkey_free(pub);
	fclose(f);
	प्रत्यागम r;
}

/*
 * Checks whether the specified key is revoked, returning 0 if not,
 * SSH_ERR_KEY_REVOKED if it is or another error code if something
 * unexpected happened.
 * This will check both the key and, if it is a certificate, its CA key too.
 * "revoked_keys_file" may be a KRL or a one-per-line list of public keys.
 */
पूर्णाङ्क
sshkey_check_revoked(संरचना sshkey *कुञ्चिका, ध्रुव वर्ण *revoked_कुञ्चिकाः_file)
{
	पूर्णाङ्क r;

	r = ssh_krl_file_अन्तर्भवति_कुञ्चिका(revoked_कुञ्चिकाः_file, कुञ्चिका);
	/* If this was not a KRL to begin with then continue below */
	यदि (r != SSH_ERR_KRL_BAD_MAGIC)
		प्रत्यागम r;

	/*
	 * If the file is not a KRL or we can't handle KRLs then attempt to
	 * parse the file as a flat list of keys.
	 */
	विकल्प ((r = sshkey_अन्तर्_file(कुञ्चिका, revoked_कुञ्चिकाः_file, 0, 1))) {
	पक्ष 0:
		/* Key found => revoked */
		प्रत्यागम SSH_ERR_कुञ्चिका_REVOKED;
	पक्ष SSH_ERR_कुञ्चिका_NOT_प्राप्तम्:
		/* Key not found => not revoked */
		प्रत्यागम 0;
	स्वभाव:
		/* Some other error occurred */
		प्रत्यागम r;
	}
}

/*
 * Advanced *cpp past the end of key options, defined as the first unquoted
 * whitespace character. Returns 0 on success or -1 on failure (e.g.
 * unterminated quotes).
 */
पूर्णाङ्क
sshkey_advance_past_options(वर्ण **cpp)
{
	वर्ण *cp = *cpp;
	पूर्णाङ्क quoted = 0;

	प्रति (; *cp && (quoted || (*cp != ' ' && *cp != '\t')); cp++) {
		यदि (*cp == '\\' && cp[1] == '"')
			cp++;	/* Skip both */
		अन्यथा यदि (*cp == '"')
			quoted = !quoted;
	}
	*cpp = cp;
	/* return failure for unterminated quotes */
	प्रत्यागम (*cp == '\0' && quoted) ? -1 : 0;
}

/* Save a public key */
पूर्णाङ्क
sshkey_save_लौकिकम्(ध्रुव संरचना sshkey *कुञ्चिका, ध्रुव वर्ण *मार्गः,
    ध्रुव वर्ण *comment)
{
	पूर्णाङ्क fd, oerrno;
	FILE *f = रिक्त;
	पूर्णाङ्क r = SSH_ERR_आन्तरिकम्_ERROR;

	यदि ((fd = उद्घाटय(मार्गः, O_WRONLY|O_CREAT|O_TRUNC, 0644)) == -1)
		प्रत्यागम SSH_ERR_SYSTEM_ERROR;
	यदि ((f = fdopen(fd, "w")) == रिक्त) {
		r = SSH_ERR_SYSTEM_ERROR;
		close(fd);
		गच्छ fail;
	}
	यदि ((r = sshkey_write(कुञ्चिका, f)) != 0)
		गच्छ fail;
	fprintf(f, " %s\n", comment);
	यदि (ferror(f)) {
		r = SSH_ERR_SYSTEM_ERROR;
		गच्छ fail;
	}
	यदि (fclose(f) != 0) {
		r = SSH_ERR_SYSTEM_ERROR;
		f = रिक्त;
 fail:
		यदि (f != रिक्त) {
			oerrno = errno;
			fclose(f);
			errno = oerrno;
		}
		प्रत्यागम r;
	}
	प्रत्यागम 0;
}
