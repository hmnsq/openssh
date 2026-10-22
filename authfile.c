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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/stat.h>

#समावेश <errno.h>
#समावेश <fcntl.h>
#समावेश <stdio.h>
#समावेश <stdarg.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <unistd.h>

#समावेश "log.h"
#समावेश "authfile.h"
#समावेश "sshkey.h"
#समावेश "sshbuf.h"
#समावेश "ssherr.h"
#समावेश "krl.h"

/* Save a key blob to a file */
अटल पूर्णांक
sshkey_save_private_blob(काष्ठा sshbuf *keybuf, स्थिर अक्षर *filename)
{
	पूर्णांक r;
	mode_t omask;

	omask = umask(077);
	r = sshbuf_write_file(filename, keybuf);
	umask(omask);
	वापस r;
}

पूर्णांक
sshkey_save_private(काष्ठा sshkey *कुंजी, स्थिर अक्षर *filename,
    स्थिर अक्षर *passphrase, स्थिर अक्षर *comment,
    पूर्णांक format, स्थिर अक्षर *openssh_format_cipher, पूर्णांक openssh_format_rounds)
{
	काष्ठा sshbuf *keyblob = शून्य;
	पूर्णांक r;

	अगर ((keyblob = sshbuf_new()) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर ((r = sshkey_private_to_fileblob(कुंजी, keyblob, passphrase, comment,
	    format, openssh_format_cipher, openssh_format_rounds)) != 0)
		जाओ out;
	अगर ((r = sshkey_save_private_blob(keyblob, filename)) != 0)
		जाओ out;
	r = 0;
 out:
	sshbuf_free(keyblob);
	वापस r;
}

/* XXX remove error() calls from here? */
पूर्णांक
sshkey_perm_ok(पूर्णांक fd, स्थिर अक्षर *filename)
{
	काष्ठा stat st;

	अगर (ख_स्थिति(fd, &st) == -1)
		वापस SSH_ERR_SYSTEM_ERROR;
	/*
	 * if a key owned by the user is accessed, then we check the
	 * permissions of the file. if the key owned by a different user,
	 * then we don't care.
	 */
#अगर_घोषित HAVE_CYGWIN
	अगर (check_ntsec(filename))
#पूर्ण_अगर
	अगर ((st.st_uid == getuid()) && (st.st_mode & 077) != 0) {
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @");
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("Permissions 0%3.3o for '%s' are too open.",
		    (u_int)st.st_mode & 0777, filename);
		error("It is required that your private key files are NOT accessible by others.");
		error("This private key will be ignored.");
		वापस SSH_ERR_कुंजी_BAD_PERMISSIONS;
	}
	वापस 0;
}

पूर्णांक
sshkey_load_private_type(पूर्णांक type, स्थिर अक्षर *filename, स्थिर अक्षर *passphrase,
    काष्ठा sshkey **keyp, अक्षर **commentp)
{
	पूर्णांक fd, r;

	अगर (keyp != शून्य)
		*keyp = शून्य;
	अगर (commentp != शून्य)
		*commentp = शून्य;

	अगर ((fd = खोलो(filename, O_RDONLY)) == -1)
		वापस SSH_ERR_SYSTEM_ERROR;

	r = sshkey_perm_ok(fd, filename);
	अगर (r != 0)
		जाओ out;

	r = sshkey_load_private_type_fd(fd, type, passphrase, keyp, commentp);
 out:
	बंद(fd);
	वापस r;
}

पूर्णांक
sshkey_load_private(स्थिर अक्षर *filename, स्थिर अक्षर *passphrase,
    काष्ठा sshkey **keyp, अक्षर **commentp)
{
	वापस sshkey_load_private_type(कुंजी_UNSPEC, filename, passphrase,
	    keyp, commentp);
}

पूर्णांक
sshkey_load_private_type_fd(पूर्णांक fd, पूर्णांक type, स्थिर अक्षर *passphrase,
    काष्ठा sshkey **keyp, अक्षर **commentp)
{
	काष्ठा sshbuf *बफर = शून्य;
	पूर्णांक r;

	अगर (keyp != शून्य)
		*keyp = शून्य;
	अगर ((r = sshbuf_load_fd(fd, &बफर)) != 0 ||
	    (r = sshkey_parse_private_fileblob_type(बफर, type,
	    passphrase, keyp, commentp)) != 0)
		जाओ out;

	/* success */
	r = 0;
 out:
	sshbuf_free(बफर);
	वापस r;
}

/* Load a pubkey from the unencrypted envelope of a new-format private key */
अटल पूर्णांक
sshkey_load_pubkey_from_private(स्थिर अक्षर *filename, काष्ठा sshkey **pubkeyp)
{
	काष्ठा sshbuf *बफर = शून्य;
	काष्ठा sshkey *pubkey = शून्य;
	पूर्णांक r, fd;

	अगर (pubkeyp != शून्य)
		*pubkeyp = शून्य;

	अगर ((fd = खोलो(filename, O_RDONLY)) == -1)
		वापस SSH_ERR_SYSTEM_ERROR;
	अगर ((r = sshbuf_load_fd(fd, &बफर)) != 0 ||
	    (r = sshkey_parse_pubkey_from_private_fileblob_type(बफर,
	    कुंजी_UNSPEC, &pubkey)) != 0)
		जाओ out;
	/* success */
	अगर (pubkeyp != शून्य) {
		*pubkeyp = pubkey;
		pubkey = शून्य;
	}
	r = 0;
 out:
	बंद(fd);
	sshbuf_free(बफर);
	sshkey_free(pubkey);
	वापस r;
}

अटल पूर्णांक
sshkey_try_load_public(काष्ठा sshkey **kp, स्थिर अक्षर *filename,
    अक्षर **commentp)
{
	खाता *f;
	अक्षर *पंक्ति = शून्य, *cp;
	माप_प्रकार linesize = 0;
	पूर्णांक r;
	काष्ठा stat st;
	काष्ठा sshkey *k = शून्य;

	अगर (kp == शून्य)
		वापस SSH_ERR_INVALID_ARGUMENT;
	*kp = शून्य;
	अगर (commentp != शून्य)
		*commentp = शून्य;
	अगर ((f = ख_खोलो(filename, "r")) == शून्य)
		वापस SSH_ERR_SYSTEM_ERROR;
	अगर (ख_स्थिति(fileno(f), &st) == 0 && S_ISREG(st.st_mode) &&
	    st.st_size > SSHBUF_आकार_MAX) {
		ख_बंद(f);
		वापस SSH_ERR_INVALID_FORMAT;
	}
	अगर ((k = sshkey_new(कुंजी_UNSPEC)) == शून्य) {
		ख_बंद(f);
		वापस SSH_ERR_ALLOC_FAIL;
	}
	जबतक (getline(&पंक्ति, &linesize, f) != -1) {
		cp = पंक्ति;
		चयन (*cp) {
		हाल '#':
		हाल '\n':
		हाल '\0':
			जारी;
		}
		/* Abort loading if this looks like a private key */
		अगर (म_भेदन(cp, "-----BEGIN", 10) == 0 ||
		    म_भेद(cp, "SSH PRIVATE KEY FILE") == 0)
			अवरोध;
		/* Skip leading whitespace. */
		क्रम (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;
		अगर (*cp) {
			अगर ((r = sshkey_read(k, &cp)) == 0) {
				cp[म_खोज(cp, "\r\n")] = '\0';
				अगर (commentp) {
					*commentp = strdup(*cp ?
					    cp : filename);
					अगर (*commentp == शून्य)
						r = SSH_ERR_ALLOC_FAIL;
				}
				/* success */
				*kp = k;
				मुक्त(पंक्ति);
				ख_बंद(f);
				वापस r;
			}
		}
	}
	मुक्त(k);
	मुक्त(पंक्ति);
	ख_बंद(f);
	वापस SSH_ERR_INVALID_FORMAT;
}

/* load public key from any pubkey file */
पूर्णांक
sshkey_load_public(स्थिर अक्षर *filename, काष्ठा sshkey **keyp, अक्षर **commentp)
{
	अक्षर *pubfile = शून्य;
	पूर्णांक r, oerrno;

	अगर (keyp != शून्य)
		*keyp = शून्य;
	अगर (commentp != शून्य)
		*commentp = शून्य;

	अगर ((r = sshkey_try_load_public(keyp, filename, commentp)) == 0)
		जाओ out;

	/* try .pub suffix */
	अगर (asprintf(&pubfile, "%s.pub", filename) == -1)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर ((r = sshkey_try_load_public(keyp, pubfile, commentp)) == 0)
		जाओ out;

	/* finally, try to extract public key from private key file */
	अगर ((r = sshkey_load_pubkey_from_private(filename, keyp)) == 0)
		जाओ out;

	/* Pretend we couldn't find the key */
	r = SSH_ERR_SYSTEM_ERROR;
	त्रुटि_सं = ENOENT;

 out:
	oerrno = त्रुटि_सं;
	मुक्त(pubfile);
	त्रुटि_सं = oerrno;
	वापस r;
}

/* Load the certificate associated with the named private key */
पूर्णांक
sshkey_load_cert(स्थिर अक्षर *filename, काष्ठा sshkey **keyp)
{
	काष्ठा sshkey *pub = शून्य;
	अक्षर *file = शून्य;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	अगर (keyp != शून्य)
		*keyp = शून्य;

	अगर (asprintf(&file, "%s-cert.pub", filename) == -1)
		वापस SSH_ERR_ALLOC_FAIL;

	r = sshkey_try_load_public(keyp, file, शून्य);
	मुक्त(file);
	sshkey_free(pub);
	वापस r;
}

/* Load private key and certificate */
पूर्णांक
sshkey_load_private_cert(पूर्णांक type, स्थिर अक्षर *filename, स्थिर अक्षर *passphrase,
    काष्ठा sshkey **keyp)
{
	काष्ठा sshkey *कुंजी = शून्य, *cert = शून्य;
	पूर्णांक r;

	अगर (keyp != शून्य)
		*keyp = शून्य;

	चयन (type) {
#अगर_घोषित WITH_OPENSSL
	हाल कुंजी_RSA:
	हाल कुंजी_ECDSA:
#पूर्ण_अगर /* WITH_OPENSSL */
	हाल कुंजी_ED25519:
	हाल कुंजी_MLDSA44_ED25519:
	हाल कुंजी_UNSPEC:
		अवरोध;
	शेष:
		वापस SSH_ERR_कुंजी_TYPE_UNKNOWN;
	}

	अगर ((r = sshkey_load_private_type(type, filename,
	    passphrase, &कुंजी, शून्य)) != 0 ||
	    (r = sshkey_load_cert(filename, &cert)) != 0)
		जाओ out;

	/* Make sure the private key matches the certificate */
	अगर (sshkey_equal_public(कुंजी, cert) == 0) {
		r = SSH_ERR_कुंजी_CERT_MISMATCH;
		जाओ out;
	}

	अगर ((r = sshkey_to_certified(कुंजी)) != 0 ||
	    (r = sshkey_cert_copy(cert, कुंजी)) != 0)
		जाओ out;
	r = 0;
	अगर (keyp != शून्य) {
		*keyp = कुंजी;
		कुंजी = शून्य;
	}
 out:
	sshkey_free(कुंजी);
	sshkey_free(cert);
	वापस r;
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
sshkey_in_file(काष्ठा sshkey *कुंजी, स्थिर अक्षर *filename, पूर्णांक strict_type,
    पूर्णांक check_ca)
{
	खाता *f;
	अक्षर *पंक्ति = शून्य, *cp;
	माप_प्रकार linesize = 0;
	पूर्णांक r = 0;
	काष्ठा sshkey *pub = शून्य;

	पूर्णांक (*sshkey_compare)(स्थिर काष्ठा sshkey *, स्थिर काष्ठा sshkey *) =
	    strict_type ?  sshkey_equal : sshkey_equal_public;

	अगर ((f = ख_खोलो(filename, "r")) == शून्य)
		वापस SSH_ERR_SYSTEM_ERROR;

	जबतक (getline(&पंक्ति, &linesize, f) != -1) {
		sshkey_free(pub);
		pub = शून्य;
		cp = पंक्ति;

		/* Skip leading whitespace. */
		क्रम (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;

		/* Skip comments and empty lines */
		चयन (*cp) {
		हाल '#':
		हाल '\n':
		हाल '\0':
			जारी;
		}

		अगर ((pub = sshkey_new(कुंजी_UNSPEC)) == शून्य) {
			r = SSH_ERR_ALLOC_FAIL;
			जाओ out;
		}
		चयन (r = sshkey_read(pub, &cp)) {
		हाल 0:
			अवरोध;
		हाल SSH_ERR_कुंजी_लंबाई:
			जारी;
		शेष:
			जाओ out;
		}
		अगर (sshkey_compare(कुंजी, pub) ||
		    (check_ca && sshkey_is_cert(कुंजी) &&
		    sshkey_compare(कुंजी->cert->signature_कुंजी, pub))) {
			r = 0;
			जाओ out;
		}
	}
	r = SSH_ERR_कुंजी_NOT_FOUND;
 out:
	मुक्त(पंक्ति);
	sshkey_free(pub);
	ख_बंद(f);
	वापस r;
}

/*
 * Checks whether the specified key is revoked, returning 0 if not,
 * SSH_ERR_KEY_REVOKED if it is or another error code if something
 * unexpected happened.
 * This will check both the key and, if it is a certificate, its CA key too.
 * "revoked_keys_file" may be a KRL or a one-per-line list of public keys.
 */
पूर्णांक
sshkey_check_revoked(काष्ठा sshkey *कुंजी, स्थिर अक्षर *revoked_कुंजियाँ_file)
{
	पूर्णांक r;

	r = ssh_krl_file_contains_कुंजी(revoked_कुंजियाँ_file, कुंजी);
	/* If this was not a KRL to begin with then continue below */
	अगर (r != SSH_ERR_KRL_BAD_MAGIC)
		वापस r;

	/*
	 * If the file is not a KRL or we can't handle KRLs then attempt to
	 * parse the file as a flat list of keys.
	 */
	चयन ((r = sshkey_in_file(कुंजी, revoked_कुंजियाँ_file, 0, 1))) {
	हाल 0:
		/* Key found => revoked */
		वापस SSH_ERR_कुंजी_REVOKED;
	हाल SSH_ERR_कुंजी_NOT_FOUND:
		/* Key not found => not revoked */
		वापस 0;
	शेष:
		/* Some other error occurred */
		वापस r;
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

	क्रम (; *cp && (quoted || (*cp != ' ' && *cp != '\t')); cp++) {
		अगर (*cp == '\\' && cp[1] == '"')
			cp++;	/* Skip both */
		अन्यथा अगर (*cp == '"')
			quoted = !quoted;
	}
	*cpp = cp;
	/* return failure for unterminated quotes */
	वापस (*cp == '\0' && quoted) ? -1 : 0;
}

/* Save a public key */
पूर्णांक
sshkey_save_public(स्थिर काष्ठा sshkey *कुंजी, स्थिर अक्षर *path,
    स्थिर अक्षर *comment)
{
	पूर्णांक fd, oerrno;
	खाता *f = शून्य;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	अगर ((fd = खोलो(path, O_WRONLY|O_CREAT|O_TRUNC, 0644)) == -1)
		वापस SSH_ERR_SYSTEM_ERROR;
	अगर ((f = fdopen(fd, "w")) == शून्य) {
		r = SSH_ERR_SYSTEM_ERROR;
		बंद(fd);
		जाओ fail;
	}
	अगर ((r = sshkey_write(कुंजी, f)) != 0)
		जाओ fail;
	ख_लिखो(f, " %s\n", comment);
	अगर (ख_त्रुटि(f)) {
		r = SSH_ERR_SYSTEM_ERROR;
		जाओ fail;
	}
	अगर (ख_बंद(f) != 0) {
		r = SSH_ERR_SYSTEM_ERROR;
		f = शून्य;
 fail:
		अगर (f != शून्य) {
			oerrno = त्रुटि_सं;
			ख_बंद(f);
			त्रुटि_सं = oerrno;
		}
		वापस r;
	}
	वापस 0;
}
