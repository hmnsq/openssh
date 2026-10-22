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
sshkey_save_private_blob(संरचना sshbuf *keybuf, अचर वर्ण *filename)
{
	पूर्णाङ्क r;
	mode_t omask;

	omask = umask(077);
	r = sshbuf_write_file(filename, keybuf);
	umask(omask);
	फर्काऊ r;
}

पूर्णाङ्क
sshkey_save_private(संरचना sshkey *साँचो, अचर वर्ण *filename,
    अचर वर्ण *passphrase, अचर वर्ण *comment,
    पूर्णाङ्क format, अचर वर्ण *openssh_format_cipher, पूर्णाङ्क openssh_format_rounds)
{
	संरचना sshbuf *keyblob = रिक्त;
	पूर्णाङ्क r;

	यदि ((keyblob = sshbuf_new()) == रिक्त)
		फर्काऊ SSH_ERR_ALLOC_FAIL;
	यदि ((r = sshkey_private_to_fileblob(साँचो, keyblob, passphrase, comment,
	    format, openssh_format_cipher, openssh_format_rounds)) != 0)
		गच्छ out;
	यदि ((r = sshkey_save_private_blob(keyblob, filename)) != 0)
		गच्छ out;
	r = 0;
 out:
	sshbuf_free(keyblob);
	फर्काऊ r;
}

/* XXX remove error() calls from here? */
पूर्णाङ्क
sshkey_perm_ok(पूर्णाङ्क fd, अचर वर्ण *filename)
{
	संरचना stat st;

	यदि (ख_स्थिति(fd, &st) == -1)
		फर्काऊ SSH_ERR_SYSTEM_ERROR;
	/*
	 * if a key owned by the user is accessed, then we check the
	 * permissions of the file. if the key owned by a different user,
	 * then we don't care.
	 */
#ifdef HAVE_CYGWIN
	यदि (check_ntsec(filename))
#endif
	यदि ((st.st_uid == getuid()) && (st.st_mode & 077) != 0) {
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @");
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("Permissions 0%3.3o for '%s' are too open.",
		    (u_int)st.st_mode & 0777, filename);
		error("It is required that your private key files are NOT accessible by others.");
		error("This private key will be ignored.");
		फर्काऊ SSH_ERR_साँचो_BAD_PERMISSIONS;
	}
	फर्काऊ 0;
}

पूर्णाङ्क
sshkey_load_private_type(पूर्णाङ्क type, अचर वर्ण *filename, अचर वर्ण *passphrase,
    संरचना sshkey **keyp, वर्ण **commentp)
{
	पूर्णाङ्क fd, r;

	यदि (keyp != रिक्त)
		*keyp = रिक्त;
	यदि (commentp != रिक्त)
		*commentp = रिक्त;

	यदि ((fd = खोलो(filename, O_RDONLY)) == -1)
		फर्काऊ SSH_ERR_SYSTEM_ERROR;

	r = sshkey_perm_ok(fd, filename);
	यदि (r != 0)
		गच्छ out;

	r = sshkey_load_private_type_fd(fd, type, passphrase, keyp, commentp);
 out:
	बंद(fd);
	फर्काऊ r;
}

पूर्णाङ्क
sshkey_load_private(अचर वर्ण *filename, अचर वर्ण *passphrase,
    संरचना sshkey **keyp, वर्ण **commentp)
{
	फर्काऊ sshkey_load_private_type(साँचो_UNSPEC, filename, passphrase,
	    keyp, commentp);
}

पूर्णाङ्क
sshkey_load_private_type_fd(पूर्णाङ्क fd, पूर्णाङ्क type, अचर वर्ण *passphrase,
    संरचना sshkey **keyp, वर्ण **commentp)
{
	संरचना sshbuf *buffer = रिक्त;
	पूर्णाङ्क r;

	यदि (keyp != रिक्त)
		*keyp = रिक्त;
	यदि ((r = sshbuf_load_fd(fd, &buffer)) != 0 ||
	    (r = sshkey_parse_private_fileblob_type(buffer, type,
	    passphrase, keyp, commentp)) != 0)
		गच्छ out;

	/* success */
	r = 0;
 out:
	sshbuf_free(buffer);
	फर्काऊ r;
}

/* Load a pubkey from the unencrypted envelope of a new-format private key */
स्थिर पूर्णाङ्क
sshkey_load_pubkey_from_private(अचर वर्ण *filename, संरचना sshkey **pubkeyp)
{
	संरचना sshbuf *buffer = रिक्त;
	संरचना sshkey *pubkey = रिक्त;
	पूर्णाङ्क r, fd;

	यदि (pubkeyp != रिक्त)
		*pubkeyp = रिक्त;

	यदि ((fd = खोलो(filename, O_RDONLY)) == -1)
		फर्काऊ SSH_ERR_SYSTEM_ERROR;
	यदि ((r = sshbuf_load_fd(fd, &buffer)) != 0 ||
	    (r = sshkey_parse_pubkey_from_private_fileblob_type(buffer,
	    साँचो_UNSPEC, &pubkey)) != 0)
		गच्छ out;
	/* success */
	यदि (pubkeyp != रिक्त) {
		*pubkeyp = pubkey;
		pubkey = रिक्त;
	}
	r = 0;
 out:
	बंद(fd);
	sshbuf_free(buffer);
	sshkey_free(pubkey);
	फर्काऊ r;
}

स्थिर पूर्णाङ्क
sshkey_try_load_public(संरचना sshkey **kp, अचर वर्ण *filename,
    वर्ण **commentp)
{
	खाता *f;
	वर्ण *पङ्क्ति = रिक्त, *cp;
	माप_प्रकार linesize = 0;
	पूर्णाङ्क r;
	संरचना stat st;
	संरचना sshkey *k = रिक्त;

	यदि (kp == रिक्त)
		फर्काऊ SSH_ERR_INVALID_ARGUMENT;
	*kp = रिक्त;
	यदि (commentp != रिक्त)
		*commentp = रिक्त;
	यदि ((f = ख_खोलो(filename, "r")) == रिक्त)
		फर्काऊ SSH_ERR_SYSTEM_ERROR;
	यदि (ख_स्थिति(fileno(f), &st) == 0 && S_ISREG(st.st_mode) &&
	    st.st_size > SSHBUF_SIZE_MAX) {
		ख_बंद(f);
		फर्काऊ SSH_ERR_INVALID_FORMAT;
	}
	यदि ((k = sshkey_new(साँचो_UNSPEC)) == रिक्त) {
		ख_बंद(f);
		फर्काऊ SSH_ERR_ALLOC_FAIL;
	}
	जबसम्म (getline(&पङ्क्ति, &linesize, f) != -1) {
		cp = पङ्क्ति;
		विकल्प (*cp) {
		पक्ष '#':
		पक्ष '\n':
		पक्ष '\0':
			जारी;
		}
		/* Abort loading if this looks like a private key */
		यदि (म_भेदन(cp, "-----BEGIN", 10) == 0 ||
		    म_भेद(cp, "SSH PRIVATE KEY FILE") == 0)
			रोक;
		/* Skip leading whitespace. */
		लागि (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;
		यदि (*cp) {
			यदि ((r = sshkey_read(k, &cp)) == 0) {
				cp[म_खोज(cp, "\r\n")] = '\0';
				यदि (commentp) {
					*commentp = strdup(*cp ?
					    cp : filename);
					यदि (*commentp == रिक्त)
						r = SSH_ERR_ALLOC_FAIL;
				}
				/* success */
				*kp = k;
				मुक्त(पङ्क्ति);
				ख_बंद(f);
				फर्काऊ r;
			}
		}
	}
	मुक्त(k);
	मुक्त(पङ्क्ति);
	ख_बंद(f);
	फर्काऊ SSH_ERR_INVALID_FORMAT;
}

/* load public key from any pubkey file */
पूर्णाङ्क
sshkey_load_public(अचर वर्ण *filename, संरचना sshkey **keyp, वर्ण **commentp)
{
	वर्ण *pubfile = रिक्त;
	पूर्णाङ्क r, oerrno;

	यदि (keyp != रिक्त)
		*keyp = रिक्त;
	यदि (commentp != रिक्त)
		*commentp = रिक्त;

	यदि ((r = sshkey_try_load_public(keyp, filename, commentp)) == 0)
		गच्छ out;

	/* try .pub suffix */
	यदि (asprintf(&pubfile, "%s.pub", filename) == -1)
		फर्काऊ SSH_ERR_ALLOC_FAIL;
	यदि ((r = sshkey_try_load_public(keyp, pubfile, commentp)) == 0)
		गच्छ out;

	/* finally, try to extract public key from private key file */
	यदि ((r = sshkey_load_pubkey_from_private(filename, keyp)) == 0)
		गच्छ out;

	/* Pretend we couldn't find the key */
	r = SSH_ERR_SYSTEM_ERROR;
	त्रुटि_सं = ENOENT;

 out:
	oerrno = त्रुटि_सं;
	मुक्त(pubfile);
	त्रुटि_सं = oerrno;
	फर्काऊ r;
}

/* Load the certificate associated with the named private key */
पूर्णाङ्क
sshkey_load_cert(अचर वर्ण *filename, संरचना sshkey **keyp)
{
	संरचना sshkey *pub = रिक्त;
	वर्ण *file = रिक्त;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;

	यदि (keyp != रिक्त)
		*keyp = रिक्त;

	यदि (asprintf(&file, "%s-cert.pub", filename) == -1)
		फर्काऊ SSH_ERR_ALLOC_FAIL;

	r = sshkey_try_load_public(keyp, file, रिक्त);
	मुक्त(file);
	sshkey_free(pub);
	फर्काऊ r;
}

/* Load private key and certificate */
पूर्णाङ्क
sshkey_load_private_cert(पूर्णाङ्क type, अचर वर्ण *filename, अचर वर्ण *passphrase,
    संरचना sshkey **keyp)
{
	संरचना sshkey *साँचो = रिक्त, *cert = रिक्त;
	पूर्णाङ्क r;

	यदि (keyp != रिक्त)
		*keyp = रिक्त;

	विकल्प (type) {
#ifdef WITH_OPENSSL
	पक्ष साँचो_RSA:
	पक्ष साँचो_ECDSA:
#endif /* WITH_OPENSSL */
	पक्ष साँचो_ED25519:
	पक्ष साँचो_MLDSA44_ED25519:
	पक्ष साँचो_UNSPEC:
		रोक;
	स्वभाव:
		फर्काऊ SSH_ERR_साँचो_TYPE_UNKNOWN;
	}

	यदि ((r = sshkey_load_private_type(type, filename,
	    passphrase, &साँचो, रिक्त)) != 0 ||
	    (r = sshkey_load_cert(filename, &cert)) != 0)
		गच्छ out;

	/* Make sure the private key matches the certificate */
	यदि (sshkey_equal_public(साँचो, cert) == 0) {
		r = SSH_ERR_साँचो_CERT_MISMATCH;
		गच्छ out;
	}

	यदि ((r = sshkey_to_certified(साँचो)) != 0 ||
	    (r = sshkey_cert_copy(cert, साँचो)) != 0)
		गच्छ out;
	r = 0;
	यदि (keyp != रिक्त) {
		*keyp = साँचो;
		साँचो = रिक्त;
	}
 out:
	sshkey_free(साँचो);
	sshkey_free(cert);
	फर्काऊ r;
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
sshkey_in_file(संरचना sshkey *साँचो, अचर वर्ण *filename, पूर्णाङ्क strict_type,
    पूर्णाङ्क check_ca)
{
	खाता *f;
	वर्ण *पङ्क्ति = रिक्त, *cp;
	माप_प्रकार linesize = 0;
	पूर्णाङ्क r = 0;
	संरचना sshkey *pub = रिक्त;

	पूर्णाङ्क (*sshkey_compare)(अचर संरचना sshkey *, अचर संरचना sshkey *) =
	    strict_type ?  sshkey_equal : sshkey_equal_public;

	यदि ((f = ख_खोलो(filename, "r")) == रिक्त)
		फर्काऊ SSH_ERR_SYSTEM_ERROR;

	जबसम्म (getline(&पङ्क्ति, &linesize, f) != -1) {
		sshkey_free(pub);
		pub = रिक्त;
		cp = पङ्क्ति;

		/* Skip leading whitespace. */
		लागि (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;

		/* Skip comments and empty lines */
		विकल्प (*cp) {
		पक्ष '#':
		पक्ष '\n':
		पक्ष '\0':
			जारी;
		}

		यदि ((pub = sshkey_new(साँचो_UNSPEC)) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ out;
		}
		विकल्प (r = sshkey_read(pub, &cp)) {
		पक्ष 0:
			रोक;
		पक्ष SSH_ERR_साँचो_LENGTH:
			जारी;
		स्वभाव:
			गच्छ out;
		}
		यदि (sshkey_compare(साँचो, pub) ||
		    (check_ca && sshkey_is_cert(साँचो) &&
		    sshkey_compare(साँचो->cert->signature_साँचो, pub))) {
			r = 0;
			गच्छ out;
		}
	}
	r = SSH_ERR_साँचो_NOT_FOUND;
 out:
	मुक्त(पङ्क्ति);
	sshkey_free(pub);
	ख_बंद(f);
	फर्काऊ r;
}

/*
 * Checks whether the specified key is revoked, returning 0 if not,
 * SSH_ERR_KEY_REVOKED if it is or another error code if something
 * unexpected happened.
 * This will check both the key and, if it is a certificate, its CA key too.
 * "revoked_keys_file" may be a KRL or a one-per-line list of public keys.
 */
पूर्णाङ्क
sshkey_check_revoked(संरचना sshkey *साँचो, अचर वर्ण *revoked_साँचोहरू_file)
{
	पूर्णाङ्क r;

	r = ssh_krl_file_contains_साँचो(revoked_साँचोहरू_file, साँचो);
	/* If this was not a KRL to begin with then continue below */
	यदि (r != SSH_ERR_KRL_BAD_MAGIC)
		फर्काऊ r;

	/*
	 * If the file is not a KRL or we can't handle KRLs then attempt to
	 * parse the file as a flat list of keys.
	 */
	विकल्प ((r = sshkey_in_file(साँचो, revoked_साँचोहरू_file, 0, 1))) {
	पक्ष 0:
		/* Key found => revoked */
		फर्काऊ SSH_ERR_साँचो_REVOKED;
	पक्ष SSH_ERR_साँचो_NOT_FOUND:
		/* Key not found => not revoked */
		फर्काऊ 0;
	स्वभाव:
		/* Some other error occurred */
		फर्काऊ r;
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

	लागि (; *cp && (quoted || (*cp != ' ' && *cp != '\t')); cp++) {
		यदि (*cp == '\\' && cp[1] == '"')
			cp++;	/* Skip both */
		अन्यथा यदि (*cp == '"')
			quoted = !quoted;
	}
	*cpp = cp;
	/* return failure for unterminated quotes */
	फर्काऊ (*cp == '\0' && quoted) ? -1 : 0;
}

/* Save a public key */
पूर्णाङ्क
sshkey_save_public(अचर संरचना sshkey *साँचो, अचर वर्ण *path,
    अचर वर्ण *comment)
{
	पूर्णाङ्क fd, oerrno;
	खाता *f = रिक्त;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;

	यदि ((fd = खोलो(path, O_WRONLY|O_CREAT|O_TRUNC, 0644)) == -1)
		फर्काऊ SSH_ERR_SYSTEM_ERROR;
	यदि ((f = fdopen(fd, "w")) == रिक्त) {
		r = SSH_ERR_SYSTEM_ERROR;
		बंद(fd);
		गच्छ fail;
	}
	यदि ((r = sshkey_write(साँचो, f)) != 0)
		गच्छ fail;
	ख_लिखो(f, " %s\n", comment);
	यदि (ख_त्रुटि(f)) {
		r = SSH_ERR_SYSTEM_ERROR;
		गच्छ fail;
	}
	यदि (ख_बंद(f) != 0) {
		r = SSH_ERR_SYSTEM_ERROR;
		f = रिक्त;
 fail:
		यदि (f != रिक्त) {
			oerrno = त्रुटि_सं;
			ख_बंद(f);
			त्रुटि_सं = oerrno;
		}
		फर्काऊ r;
	}
	फर्काऊ 0;
}
