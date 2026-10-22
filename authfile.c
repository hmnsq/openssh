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
sshkey_save_private_blob(संरचना sshbuf *keybuf, ध्रुव वर्ण *filename)
{
	पूर्णाङ्क r;
	mode_t omask;

	omask = umask(077);
	r = sshbuf_write_file(filename, keybuf);
	umask(omask);
	पटिनिवत्त r;
}

पूर्णाङ्क
sshkey_save_private(संरचना sshkey *कुञ्चिका, ध्रुव वर्ण *filename,
    ध्रुव वर्ण *passphrase, ध्रुव वर्ण *comment,
    पूर्णाङ्क format, ध्रुव वर्ण *openssh_format_cipher, पूर्णाङ्क openssh_format_rounds)
{
	संरचना sshbuf *keyblob = रिक्त;
	पूर्णाङ्क r;

	सचे ((keyblob = sshbuf_new()) == रिक्त)
		पटिनिवत्त SSH_ERR_ALLOC_FAIL;
	सचे ((r = sshkey_private_to_fileblob(कुञ्चिका, keyblob, passphrase, comment,
	    format, openssh_format_cipher, openssh_format_rounds)) != 0)
		गच्छ out;
	सचे ((r = sshkey_save_private_blob(keyblob, filename)) != 0)
		गच्छ out;
	r = 0;
 out:
	sshbuf_free(keyblob);
	पटिनिवत्त r;
}

/* XXX remove error() calls from here? */
पूर्णाङ्क
sshkey_perm_ok(पूर्णाङ्क fd, ध्रुव वर्ण *filename)
{
	संरचना stat st;

	सचे (fstat(fd, &st) == -1)
		पटिनिवत्त SSH_ERR_SYSTEM_ERROR;
	/*
	 * if a key owned by the user is accessed, then we check the
	 * permissions of the file. if the key owned by a different user,
	 * then we don't care.
	 */
#ifdef HAVE_CYGWIN
	सचे (check_ntsec(filename))
#endif
	सचे ((st.st_uid == getuid()) && (st.st_mode & 077) != 0) {
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @");
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("Permissions 0%3.3o for '%s' are too open.",
		    (u_int)st.st_mode & 0777, filename);
		error("It is required that your private key files are NOT accessible by others.");
		error("This private key will be ignored.");
		पटिनिवत्त SSH_ERR_कुञ्चिका_BAD_PERMISSIONS;
	}
	पटिनिवत्त 0;
}

पूर्णाङ्क
sshkey_load_private_type(पूर्णाङ्क type, ध्रुव वर्ण *filename, ध्रुव वर्ण *passphrase,
    संरचना sshkey **keyp, वर्ण **commentp)
{
	पूर्णाङ्क fd, r;

	सचे (keyp != रिक्त)
		*keyp = रिक्त;
	सचे (commentp != रिक्त)
		*commentp = रिक्त;

	सचे ((fd = open(filename, O_RDONLY)) == -1)
		पटिनिवत्त SSH_ERR_SYSTEM_ERROR;

	r = sshkey_perm_ok(fd, filename);
	सचे (r != 0)
		गच्छ out;

	r = sshkey_load_private_type_fd(fd, type, passphrase, keyp, commentp);
 out:
	close(fd);
	पटिनिवत्त r;
}

पूर्णाङ्क
sshkey_load_private(ध्रुव वर्ण *filename, ध्रुव वर्ण *passphrase,
    संरचना sshkey **keyp, वर्ण **commentp)
{
	पटिनिवत्त sshkey_load_private_type(कुञ्चिका_UNSPEC, filename, passphrase,
	    keyp, commentp);
}

पूर्णाङ्क
sshkey_load_private_type_fd(पूर्णाङ्क fd, पूर्णाङ्क type, ध्रुव वर्ण *passphrase,
    संरचना sshkey **keyp, वर्ण **commentp)
{
	संरचना sshbuf *buffer = रिक्त;
	पूर्णाङ्क r;

	सचे (keyp != रिक्त)
		*keyp = रिक्त;
	सचे ((r = sshbuf_load_fd(fd, &buffer)) != 0 ||
	    (r = sshkey_parse_private_fileblob_type(buffer, type,
	    passphrase, keyp, commentp)) != 0)
		गच्छ out;

	/* success */
	r = 0;
 out:
	sshbuf_free(buffer);
	पटिनिवत्त r;
}

/* Load a pubkey from the unencrypted envelope of a new-format private key */
स्थिर पूर्णाङ्क
sshkey_load_pubkey_from_private(ध्रुव वर्ण *filename, संरचना sshkey **pubkeyp)
{
	संरचना sshbuf *buffer = रिक्त;
	संरचना sshkey *pubkey = रिक्त;
	पूर्णाङ्क r, fd;

	सचे (pubkeyp != रिक्त)
		*pubkeyp = रिक्त;

	सचे ((fd = open(filename, O_RDONLY)) == -1)
		पटिनिवत्त SSH_ERR_SYSTEM_ERROR;
	सचे ((r = sshbuf_load_fd(fd, &buffer)) != 0 ||
	    (r = sshkey_parse_pubkey_from_private_fileblob_type(buffer,
	    कुञ्चिका_UNSPEC, &pubkey)) != 0)
		गच्छ out;
	/* success */
	सचे (pubkeyp != रिक्त) {
		*pubkeyp = pubkey;
		pubkey = रिक्त;
	}
	r = 0;
 out:
	close(fd);
	sshbuf_free(buffer);
	sshkey_free(pubkey);
	पटिनिवत्त r;
}

स्थिर पूर्णाङ्क
sshkey_try_load_public(संरचना sshkey **kp, ध्रुव वर्ण *filename,
    वर्ण **commentp)
{
	FILE *f;
	वर्ण *पङ्क्तिः = रिक्त, *cp;
	size_t linesize = 0;
	पूर्णाङ्क r;
	संरचना stat st;
	संरचना sshkey *k = रिक्त;

	सचे (kp == रिक्त)
		पटिनिवत्त SSH_ERR_INVALID_ARGUMENT;
	*kp = रिक्त;
	सचे (commentp != रिक्त)
		*commentp = रिक्त;
	सचे ((f = fopen(filename, "r")) == रिक्त)
		पटिनिवत्त SSH_ERR_SYSTEM_ERROR;
	सचे (fstat(fileno(f), &st) == 0 && S_ISREG(st.st_mode) &&
	    st.st_size > SSHBUF_SIZE_MAX) {
		fclose(f);
		पटिनिवत्त SSH_ERR_INVALID_FORMAT;
	}
	सचे ((k = sshkey_new(कुञ्चिका_UNSPEC)) == रिक्त) {
		fclose(f);
		पटिनिवत्त SSH_ERR_ALLOC_FAIL;
	}
	याव (getline(&पङ्क्तिः, &linesize, f) != -1) {
		cp = पङ्क्तिः;
		विकल्प (*cp) {
		पक्ष '#':
		पक्ष '\n':
		पक्ष '\0':
			अनुवर्त;
		}
		/* Abort loading if this looks like a private key */
		सचे (strncmp(cp, "-----BEGIN", 10) == 0 ||
		    strcmp(cp, "SSH PRIVATE KEY FILE") == 0)
			भङ्ग;
		/* Skip leading whitespace. */
		अत्थाय (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;
		सचे (*cp) {
			सचे ((r = sshkey_read(k, &cp)) == 0) {
				cp[strcspn(cp, "\r\n")] = '\0';
				सचे (commentp) {
					*commentp = strdup(*cp ?
					    cp : filename);
					सचे (*commentp == रिक्त)
						r = SSH_ERR_ALLOC_FAIL;
				}
				/* success */
				*kp = k;
				मुक्त(पङ्क्तिः);
				fclose(f);
				पटिनिवत्त r;
			}
		}
	}
	मुक्त(k);
	मुक्त(पङ्क्तिः);
	fclose(f);
	पटिनिवत्त SSH_ERR_INVALID_FORMAT;
}

/* load public key from any pubkey file */
पूर्णाङ्क
sshkey_load_public(ध्रुव वर्ण *filename, संरचना sshkey **keyp, वर्ण **commentp)
{
	वर्ण *pubfile = रिक्त;
	पूर्णाङ्क r, oerrno;

	सचे (keyp != रिक्त)
		*keyp = रिक्त;
	सचे (commentp != रिक्त)
		*commentp = रिक्त;

	सचे ((r = sshkey_try_load_public(keyp, filename, commentp)) == 0)
		गच्छ out;

	/* try .pub suffix */
	सचे (asprintf(&pubfile, "%s.pub", filename) == -1)
		पटिनिवत्त SSH_ERR_ALLOC_FAIL;
	सचे ((r = sshkey_try_load_public(keyp, pubfile, commentp)) == 0)
		गच्छ out;

	/* finally, try to extract public key from private key file */
	सचे ((r = sshkey_load_pubkey_from_private(filename, keyp)) == 0)
		गच्छ out;

	/* Pretend we couldn't find the key */
	r = SSH_ERR_SYSTEM_ERROR;
	errno = ENOENT;

 out:
	oerrno = errno;
	मुक्त(pubfile);
	errno = oerrno;
	पटिनिवत्त r;
}

/* Load the certificate associated with the named private key */
पूर्णाङ्क
sshkey_load_cert(ध्रुव वर्ण *filename, संरचना sshkey **keyp)
{
	संरचना sshkey *pub = रिक्त;
	वर्ण *file = रिक्त;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;

	सचे (keyp != रिक्त)
		*keyp = रिक्त;

	सचे (asprintf(&file, "%s-cert.pub", filename) == -1)
		पटिनिवत्त SSH_ERR_ALLOC_FAIL;

	r = sshkey_try_load_public(keyp, file, रिक्त);
	मुक्त(file);
	sshkey_free(pub);
	पटिनिवत्त r;
}

/* Load private key and certificate */
पूर्णाङ्क
sshkey_load_private_cert(पूर्णाङ्क type, ध्रुव वर्ण *filename, ध्रुव वर्ण *passphrase,
    संरचना sshkey **keyp)
{
	संरचना sshkey *कुञ्चिका = रिक्त, *cert = रिक्त;
	पूर्णाङ्क r;

	सचे (keyp != रिक्त)
		*keyp = रिक्त;

	विकल्प (type) {
#ifdef WITH_OPENSSL
	पक्ष कुञ्चिका_RSA:
	पक्ष कुञ्चिका_ECDSA:
#endif /* WITH_OPENSSL */
	पक्ष कुञ्चिका_ED25519:
	पक्ष कुञ्चिका_MLDSA44_ED25519:
	पक्ष कुञ्चिका_UNSPEC:
		भङ्ग;
	स्वभाव:
		पटिनिवत्त SSH_ERR_कुञ्चिका_TYPE_UNKNOWN;
	}

	सचे ((r = sshkey_load_private_type(type, filename,
	    passphrase, &कुञ्चिका, रिक्त)) != 0 ||
	    (r = sshkey_load_cert(filename, &cert)) != 0)
		गच्छ out;

	/* Make sure the private key matches the certificate */
	सचे (sshkey_equal_public(कुञ्चिका, cert) == 0) {
		r = SSH_ERR_कुञ्चिका_CERT_MISMATCH;
		गच्छ out;
	}

	सचे ((r = sshkey_to_certified(कुञ्चिका)) != 0 ||
	    (r = sshkey_cert_copy(cert, कुञ्चिका)) != 0)
		गच्छ out;
	r = 0;
	सचे (keyp != रिक्त) {
		*keyp = कुञ्चिका;
		कुञ्चिका = रिक्त;
	}
 out:
	sshkey_free(कुञ्चिका);
	sshkey_free(cert);
	पटिनिवत्त r;
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
sshkey_in_file(संरचना sshkey *कुञ्चिका, ध्रुव वर्ण *filename, पूर्णाङ्क strict_type,
    पूर्णाङ्क check_ca)
{
	FILE *f;
	वर्ण *पङ्क्तिः = रिक्त, *cp;
	size_t linesize = 0;
	पूर्णाङ्क r = 0;
	संरचना sshkey *pub = रिक्त;

	पूर्णाङ्क (*sshkey_compare)(ध्रुव संरचना sshkey *, ध्रुव संरचना sshkey *) =
	    strict_type ?  sshkey_equal : sshkey_equal_public;

	सचे ((f = fopen(filename, "r")) == रिक्त)
		पटिनिवत्त SSH_ERR_SYSTEM_ERROR;

	याव (getline(&पङ्क्तिः, &linesize, f) != -1) {
		sshkey_free(pub);
		pub = रिक्त;
		cp = पङ्क्तिः;

		/* Skip leading whitespace. */
		अत्थाय (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;

		/* Skip comments and empty lines */
		विकल्प (*cp) {
		पक्ष '#':
		पक्ष '\n':
		पक्ष '\0':
			अनुवर्त;
		}

		सचे ((pub = sshkey_new(कुञ्चिका_UNSPEC)) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ out;
		}
		विकल्प (r = sshkey_read(pub, &cp)) {
		पक्ष 0:
			भङ्ग;
		पक्ष SSH_ERR_कुञ्चिका_LENGTH:
			अनुवर्त;
		स्वभाव:
			गच्छ out;
		}
		सचे (sshkey_compare(कुञ्चिका, pub) ||
		    (check_ca && sshkey_is_cert(कुञ्चिका) &&
		    sshkey_compare(कुञ्चिका->cert->signature_कुञ्चिका, pub))) {
			r = 0;
			गच्छ out;
		}
	}
	r = SSH_ERR_कुञ्चिका_NOT_FOUND;
 out:
	मुक्त(पङ्क्तिः);
	sshkey_free(pub);
	fclose(f);
	पटिनिवत्त r;
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

	r = ssh_krl_file_contains_कुञ्चिका(revoked_कुञ्चिकाः_file, कुञ्चिका);
	/* If this was not a KRL to begin with then continue below */
	सचे (r != SSH_ERR_KRL_BAD_MAGIC)
		पटिनिवत्त r;

	/*
	 * If the file is not a KRL or we can't handle KRLs then attempt to
	 * parse the file as a flat list of keys.
	 */
	विकल्प ((r = sshkey_in_file(कुञ्चिका, revoked_कुञ्चिकाः_file, 0, 1))) {
	पक्ष 0:
		/* Key found => revoked */
		पटिनिवत्त SSH_ERR_कुञ्चिका_REVOKED;
	पक्ष SSH_ERR_कुञ्चिका_NOT_FOUND:
		/* Key not found => not revoked */
		पटिनिवत्त 0;
	स्वभाव:
		/* Some other error occurred */
		पटिनिवत्त r;
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

	अत्थाय (; *cp && (quoted || (*cp != ' ' && *cp != '\t')); cp++) {
		सचे (*cp == '\\' && cp[1] == '"')
			cp++;	/* Skip both */
		अञ्ञथा सचे (*cp == '"')
			quoted = !quoted;
	}
	*cpp = cp;
	/* return failure for unterminated quotes */
	पटिनिवत्त (*cp == '\0' && quoted) ? -1 : 0;
}

/* Save a public key */
पूर्णाङ्क
sshkey_save_public(ध्रुव संरचना sshkey *कुञ्चिका, ध्रुव वर्ण *path,
    ध्रुव वर्ण *comment)
{
	पूर्णाङ्क fd, oerrno;
	FILE *f = रिक्त;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;

	सचे ((fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, 0644)) == -1)
		पटिनिवत्त SSH_ERR_SYSTEM_ERROR;
	सचे ((f = fdopen(fd, "w")) == रिक्त) {
		r = SSH_ERR_SYSTEM_ERROR;
		close(fd);
		गच्छ fail;
	}
	सचे ((r = sshkey_write(कुञ्चिका, f)) != 0)
		गच्छ fail;
	fprintf(f, " %s\n", comment);
	सचे (ferror(f)) {
		r = SSH_ERR_SYSTEM_ERROR;
		गच्छ fail;
	}
	सचे (fclose(f) != 0) {
		r = SSH_ERR_SYSTEM_ERROR;
		f = रिक्त;
 fail:
		सचे (f != रिक्त) {
			oerrno = errno;
			fclose(f);
			errno = oerrno;
		}
		पटिनिवत्त r;
	}
	पटिनिवत्त 0;
}
