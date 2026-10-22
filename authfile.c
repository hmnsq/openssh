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
स्थिर पूर्णांक
sshkey_save_private_blob(संरचना sshbuf *keybuf, स्थिरांक अक्षर *filename)
{
	पूर्णांक r;
	mode_t omask;

	omask = umask(077);
	r = sshbuf_write_file(filename, keybuf);
	umask(omask);
	परत r;
}

पूर्णांक
sshkey_save_private(संरचना sshkey *किल्ली, स्थिरांक अक्षर *filename,
    स्थिरांक अक्षर *passphrase, स्थिरांक अक्षर *comment,
    पूर्णांक format, स्थिरांक अक्षर *openssh_format_cipher, पूर्णांक openssh_format_rounds)
{
	संरचना sshbuf *keyblob = रिक्त;
	पूर्णांक r;

	जर ((keyblob = sshbuf_new()) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;
	जर ((r = sshkey_private_to_fileblob(किल्ली, keyblob, passphrase, comment,
	    format, openssh_format_cipher, openssh_format_rounds)) != 0)
		जा out;
	जर ((r = sshkey_save_private_blob(keyblob, filename)) != 0)
		जा out;
	r = 0;
 out:
	sshbuf_free(keyblob);
	परत r;
}

/* XXX remove error() calls from here? */
पूर्णांक
sshkey_perm_ok(पूर्णांक fd, स्थिरांक अक्षर *filename)
{
	संरचना stat st;

	जर (ख_स्थिति(fd, &st) == -1)
		परत SSH_ERR_SYSTEM_ERROR;
	/*
	 * if a key owned by the user is accessed, then we check the
	 * permissions of the file. if the key owned by a different user,
	 * then we don't care.
	 */
#ifdef HAVE_CYGWIN
	जर (check_ntsec(filename))
#endif
	जर ((st.st_uid == getuid()) && (st.st_mode & 077) != 0) {
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @");
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("Permissions 0%3.3o for '%s' are too open.",
		    (u_int)st.st_mode & 0777, filename);
		error("It is required that your private key files are NOT accessible by others.");
		error("This private key will be ignored.");
		परत SSH_ERR_किल्ली_BAD_PERMISSIONS;
	}
	परत 0;
}

पूर्णांक
sshkey_load_private_type(पूर्णांक type, स्थिरांक अक्षर *filename, स्थिरांक अक्षर *passphrase,
    संरचना sshkey **keyp, अक्षर **commentp)
{
	पूर्णांक fd, r;

	जर (keyp != रिक्त)
		*keyp = रिक्त;
	जर (commentp != रिक्त)
		*commentp = रिक्त;

	जर ((fd = खोलो(filename, O_RDONLY)) == -1)
		परत SSH_ERR_SYSTEM_ERROR;

	r = sshkey_perm_ok(fd, filename);
	जर (r != 0)
		जा out;

	r = sshkey_load_private_type_fd(fd, type, passphrase, keyp, commentp);
 out:
	बंद(fd);
	परत r;
}

पूर्णांक
sshkey_load_private(स्थिरांक अक्षर *filename, स्थिरांक अक्षर *passphrase,
    संरचना sshkey **keyp, अक्षर **commentp)
{
	परत sshkey_load_private_type(किल्ली_UNSPEC, filename, passphrase,
	    keyp, commentp);
}

पूर्णांक
sshkey_load_private_type_fd(पूर्णांक fd, पूर्णांक type, स्थिरांक अक्षर *passphrase,
    संरचना sshkey **keyp, अक्षर **commentp)
{
	संरचना sshbuf *buffer = रिक्त;
	पूर्णांक r;

	जर (keyp != रिक्त)
		*keyp = रिक्त;
	जर ((r = sshbuf_load_fd(fd, &buffer)) != 0 ||
	    (r = sshkey_parse_private_fileblob_type(buffer, type,
	    passphrase, keyp, commentp)) != 0)
		जा out;

	/* success */
	r = 0;
 out:
	sshbuf_free(buffer);
	परत r;
}

/* Load a pubkey from the unencrypted envelope of a new-format private key */
स्थिर पूर्णांक
sshkey_load_pubkey_from_private(स्थिरांक अक्षर *filename, संरचना sshkey **pubkeyp)
{
	संरचना sshbuf *buffer = रिक्त;
	संरचना sshkey *pubkey = रिक्त;
	पूर्णांक r, fd;

	जर (pubkeyp != रिक्त)
		*pubkeyp = रिक्त;

	जर ((fd = खोलो(filename, O_RDONLY)) == -1)
		परत SSH_ERR_SYSTEM_ERROR;
	जर ((r = sshbuf_load_fd(fd, &buffer)) != 0 ||
	    (r = sshkey_parse_pubkey_from_private_fileblob_type(buffer,
	    किल्ली_UNSPEC, &pubkey)) != 0)
		जा out;
	/* success */
	जर (pubkeyp != रिक्त) {
		*pubkeyp = pubkey;
		pubkey = रिक्त;
	}
	r = 0;
 out:
	बंद(fd);
	sshbuf_free(buffer);
	sshkey_free(pubkey);
	परत r;
}

स्थिर पूर्णांक
sshkey_try_load_public(संरचना sshkey **kp, स्थिरांक अक्षर *filename,
    अक्षर **commentp)
{
	खाता *f;
	अक्षर *ओळ = रिक्त, *cp;
	माप_प्रकार linesize = 0;
	पूर्णांक r;
	संरचना stat st;
	संरचना sshkey *k = रिक्त;

	जर (kp == रिक्त)
		परत SSH_ERR_INVALID_ARGUMENT;
	*kp = रिक्त;
	जर (commentp != रिक्त)
		*commentp = रिक्त;
	जर ((f = ख_खोलो(filename, "r")) == रिक्त)
		परत SSH_ERR_SYSTEM_ERROR;
	जर (ख_स्थिति(fileno(f), &st) == 0 && S_ISREG(st.st_mode) &&
	    st.st_size > SSHBUF_SIZE_MAX) {
		ख_बंद(f);
		परत SSH_ERR_INVALID_FORMAT;
	}
	जर ((k = sshkey_new(किल्ली_UNSPEC)) == रिक्त) {
		ख_बंद(f);
		परत SSH_ERR_ALLOC_FAIL;
	}
	पर्यंत (getline(&ओळ, &linesize, f) != -1) {
		cp = ओळ;
		निवड (*cp) {
		स्थिती '#':
		स्थिती '\n':
		स्थिती '\0':
			सुरूठेवा;
		}
		/* Abort loading if this looks like a private key */
		जर (म_भेदन(cp, "-----BEGIN", 10) == 0 ||
		    म_भेद(cp, "SSH PRIVATE KEY FILE") == 0)
			थांबा;
		/* Skip leading whitespace. */
		साठी (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;
		जर (*cp) {
			जर ((r = sshkey_read(k, &cp)) == 0) {
				cp[म_खोज(cp, "\r\n")] = '\0';
				जर (commentp) {
					*commentp = strdup(*cp ?
					    cp : filename);
					जर (*commentp == रिक्त)
						r = SSH_ERR_ALLOC_FAIL;
				}
				/* success */
				*kp = k;
				मुक्त(ओळ);
				ख_बंद(f);
				परत r;
			}
		}
	}
	मुक्त(k);
	मुक्त(ओळ);
	ख_बंद(f);
	परत SSH_ERR_INVALID_FORMAT;
}

/* load public key from any pubkey file */
पूर्णांक
sshkey_load_public(स्थिरांक अक्षर *filename, संरचना sshkey **keyp, अक्षर **commentp)
{
	अक्षर *pubfile = रिक्त;
	पूर्णांक r, oerrno;

	जर (keyp != रिक्त)
		*keyp = रिक्त;
	जर (commentp != रिक्त)
		*commentp = रिक्त;

	जर ((r = sshkey_try_load_public(keyp, filename, commentp)) == 0)
		जा out;

	/* try .pub suffix */
	जर (asprintf(&pubfile, "%s.pub", filename) == -1)
		परत SSH_ERR_ALLOC_FAIL;
	जर ((r = sshkey_try_load_public(keyp, pubfile, commentp)) == 0)
		जा out;

	/* finally, try to extract public key from private key file */
	जर ((r = sshkey_load_pubkey_from_private(filename, keyp)) == 0)
		जा out;

	/* Pretend we couldn't find the key */
	r = SSH_ERR_SYSTEM_ERROR;
	त्रुटि_सं = ENOENT;

 out:
	oerrno = त्रुटि_सं;
	मुक्त(pubfile);
	त्रुटि_सं = oerrno;
	परत r;
}

/* Load the certificate associated with the named private key */
पूर्णांक
sshkey_load_cert(स्थिरांक अक्षर *filename, संरचना sshkey **keyp)
{
	संरचना sshkey *pub = रिक्त;
	अक्षर *file = रिक्त;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	जर (keyp != रिक्त)
		*keyp = रिक्त;

	जर (asprintf(&file, "%s-cert.pub", filename) == -1)
		परत SSH_ERR_ALLOC_FAIL;

	r = sshkey_try_load_public(keyp, file, रिक्त);
	मुक्त(file);
	sshkey_free(pub);
	परत r;
}

/* Load private key and certificate */
पूर्णांक
sshkey_load_private_cert(पूर्णांक type, स्थिरांक अक्षर *filename, स्थिरांक अक्षर *passphrase,
    संरचना sshkey **keyp)
{
	संरचना sshkey *किल्ली = रिक्त, *cert = रिक्त;
	पूर्णांक r;

	जर (keyp != रिक्त)
		*keyp = रिक्त;

	निवड (type) {
#ifdef WITH_OPENSSL
	स्थिती किल्ली_RSA:
	स्थिती किल्ली_ECDSA:
#endif /* WITH_OPENSSL */
	स्थिती किल्ली_ED25519:
	स्थिती किल्ली_MLDSA44_ED25519:
	स्थिती किल्ली_UNSPEC:
		थांबा;
	पूर्वनिर्धारित:
		परत SSH_ERR_किल्ली_TYPE_UNKNOWN;
	}

	जर ((r = sshkey_load_private_type(type, filename,
	    passphrase, &किल्ली, रिक्त)) != 0 ||
	    (r = sshkey_load_cert(filename, &cert)) != 0)
		जा out;

	/* Make sure the private key matches the certificate */
	जर (sshkey_equal_public(किल्ली, cert) == 0) {
		r = SSH_ERR_किल्ली_CERT_MISMATCH;
		जा out;
	}

	जर ((r = sshkey_to_certified(किल्ली)) != 0 ||
	    (r = sshkey_cert_copy(cert, किल्ली)) != 0)
		जा out;
	r = 0;
	जर (keyp != रिक्त) {
		*keyp = किल्ली;
		किल्ली = रिक्त;
	}
 out:
	sshkey_free(किल्ली);
	sshkey_free(cert);
	परत r;
}

/*
 * Returns success if the specified "key" is listed in the file "filename",
 * SSH_ERR_KEY_NOT_FOUND: if the key is not listed or another error.
 * If "strict_type" is set then the key type must match exactly,
 * otherwise a comparison that ignores certificate data is performed.
 * If "check_ca" is set and "key" is a certificate, then its CA key is
 * also checked and sshkey_in_file() will return success if either is found.
 */
पूर्णांक
sshkey_in_file(संरचना sshkey *किल्ली, स्थिरांक अक्षर *filename, पूर्णांक strict_type,
    पूर्णांक check_ca)
{
	खाता *f;
	अक्षर *ओळ = रिक्त, *cp;
	माप_प्रकार linesize = 0;
	पूर्णांक r = 0;
	संरचना sshkey *pub = रिक्त;

	पूर्णांक (*sshkey_compare)(स्थिरांक संरचना sshkey *, स्थिरांक संरचना sshkey *) =
	    strict_type ?  sshkey_equal : sshkey_equal_public;

	जर ((f = ख_खोलो(filename, "r")) == रिक्त)
		परत SSH_ERR_SYSTEM_ERROR;

	पर्यंत (getline(&ओळ, &linesize, f) != -1) {
		sshkey_free(pub);
		pub = रिक्त;
		cp = ओळ;

		/* Skip leading whitespace. */
		साठी (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;

		/* Skip comments and empty lines */
		निवड (*cp) {
		स्थिती '#':
		स्थिती '\n':
		स्थिती '\0':
			सुरूठेवा;
		}

		जर ((pub = sshkey_new(किल्ली_UNSPEC)) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			जा out;
		}
		निवड (r = sshkey_read(pub, &cp)) {
		स्थिती 0:
			थांबा;
		स्थिती SSH_ERR_किल्ली_LENGTH:
			सुरूठेवा;
		पूर्वनिर्धारित:
			जा out;
		}
		जर (sshkey_compare(किल्ली, pub) ||
		    (check_ca && sshkey_is_cert(किल्ली) &&
		    sshkey_compare(किल्ली->cert->signature_किल्ली, pub))) {
			r = 0;
			जा out;
		}
	}
	r = SSH_ERR_किल्ली_NOT_FOUND;
 out:
	मुक्त(ओळ);
	sshkey_free(pub);
	ख_बंद(f);
	परत r;
}

/*
 * Checks whether the specified key is revoked, returning 0 if not,
 * SSH_ERR_KEY_REVOKED if it is or another error code if something
 * unexpected happened.
 * This will check both the key and, if it is a certificate, its CA key too.
 * "revoked_keys_file" may be a KRL or a one-per-line list of public keys.
 */
पूर्णांक
sshkey_check_revoked(संरचना sshkey *किल्ली, स्थिरांक अक्षर *revoked_किल्ल्या_file)
{
	पूर्णांक r;

	r = ssh_krl_file_contains_किल्ली(revoked_किल्ल्या_file, किल्ली);
	/* If this was not a KRL to begin with then continue below */
	जर (r != SSH_ERR_KRL_BAD_MAGIC)
		परत r;

	/*
	 * If the file is not a KRL or we can't handle KRLs then attempt to
	 * parse the file as a flat list of keys.
	 */
	निवड ((r = sshkey_in_file(किल्ली, revoked_किल्ल्या_file, 0, 1))) {
	स्थिती 0:
		/* Key found => revoked */
		परत SSH_ERR_किल्ली_REVOKED;
	स्थिती SSH_ERR_किल्ली_NOT_FOUND:
		/* Key not found => not revoked */
		परत 0;
	पूर्वनिर्धारित:
		/* Some other error occurred */
		परत r;
	}
}

/*
 * Advanced *cpp past the end of key options, defined as the first unquoted
 * whitespace character. Returns 0 on success or -1 on failure (e.g.
 * unterminated quotes).
 */
पूर्णांक
sshkey_advance_past_options(अक्षर **cpp)
{
	अक्षर *cp = *cpp;
	पूर्णांक quoted = 0;

	साठी (; *cp && (quoted || (*cp != ' ' && *cp != '\t')); cp++) {
		जर (*cp == '\\' && cp[1] == '"')
			cp++;	/* Skip both */
		अन्यथा जर (*cp == '"')
			quoted = !quoted;
	}
	*cpp = cp;
	/* return failure for unterminated quotes */
	परत (*cp == '\0' && quoted) ? -1 : 0;
}

/* Save a public key */
पूर्णांक
sshkey_save_public(स्थिरांक संरचना sshkey *किल्ली, स्थिरांक अक्षर *path,
    स्थिरांक अक्षर *comment)
{
	पूर्णांक fd, oerrno;
	खाता *f = रिक्त;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	जर ((fd = खोलो(path, O_WRONLY|O_CREAT|O_TRUNC, 0644)) == -1)
		परत SSH_ERR_SYSTEM_ERROR;
	जर ((f = fdopen(fd, "w")) == रिक्त) {
		r = SSH_ERR_SYSTEM_ERROR;
		बंद(fd);
		जा fail;
	}
	जर ((r = sshkey_write(किल्ली, f)) != 0)
		जा fail;
	ख_लिखो(f, " %s\n", comment);
	जर (ख_त्रुटि(f)) {
		r = SSH_ERR_SYSTEM_ERROR;
		जा fail;
	}
	जर (ख_बंद(f) != 0) {
		r = SSH_ERR_SYSTEM_ERROR;
		f = रिक्त;
 fail:
		जर (f != रिक्त) {
			oerrno = त्रुटि_सं;
			ख_बंद(f);
			त्रुटि_सं = oerrno;
		}
		परत r;
	}
	परत 0;
}
