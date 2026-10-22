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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/stat.h>

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <fcntl.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>

#அந்தர்பாவ "log.h"
#அந்தர்பாவ "authfile.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "krl.h"

/* Save a key blob to a file */
நிலையான முழு
sshkey_save_private_blob(கட்டமைப்பு sshbuf *keybuf, மாறிலி எழுத்து *filename)
{
	முழு r;
	mode_t omask;

	omask = umask(077);
	r = sshbuf_write_file(filename, keybuf);
	umask(omask);
	திரும்பு r;
}

முழு
sshkey_save_private(கட்டமைப்பு sshkey *சாவி, மாறிலி எழுத்து *filename,
    மாறிலி எழுத்து *passphrase, மாறிலி எழுத்து *comment,
    முழு format, மாறிலி எழுத்து *openssh_format_cipher, முழு openssh_format_rounds)
{
	கட்டமைப்பு sshbuf *keyblob = வெற்று;
	முழு r;

	எனில் ((keyblob = sshbuf_new()) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் ((r = sshkey_private_to_fileblob(சாவி, keyblob, passphrase, comment,
	    format, openssh_format_cipher, openssh_format_rounds)) != 0)
		செல் out;
	எனில் ((r = sshkey_save_private_blob(keyblob, filename)) != 0)
		செல் out;
	r = 0;
 out:
	sshbuf_free(keyblob);
	திரும்பு r;
}

/* XXX remove error() calls from here? */
முழு
sshkey_perm_ok(முழு fd, மாறிலி எழுத்து *filename)
{
	கட்டமைப்பு stat st;

	எனில் (fstat(fd, &st) == -1)
		திரும்பு SSH_ERR_SYSTEM_ERROR;
	/*
	 * if a key owned by the user is accessed, then we check the
	 * permissions of the file. if the key owned by a different user,
	 * then we don't care.
	 */
#ifdef HAVE_CYGWIN
	எனில் (check_ntsec(filename))
#endif
	எனில் ((st.st_uid == getuid()) && (st.st_mode & 077) != 0) {
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @");
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("Permissions 0%3.3o for '%s' are too open.",
		    (u_int)st.st_mode & 0777, filename);
		error("It is required that your private key files are NOT accessible by others.");
		error("This private key will be ignored.");
		திரும்பு SSH_ERR_சாவி_BAD_PERMISSIONS;
	}
	திரும்பு 0;
}

முழு
sshkey_load_private_type(முழு type, மாறிலி எழுத்து *filename, மாறிலி எழுத்து *passphrase,
    கட்டமைப்பு sshkey **keyp, எழுத்து **commentp)
{
	முழு fd, r;

	எனில் (keyp != வெற்று)
		*keyp = வெற்று;
	எனில் (commentp != வெற்று)
		*commentp = வெற்று;

	எனில் ((fd = open(filename, O_RDONLY)) == -1)
		திரும்பு SSH_ERR_SYSTEM_ERROR;

	r = sshkey_perm_ok(fd, filename);
	எனில் (r != 0)
		செல் out;

	r = sshkey_load_private_type_fd(fd, type, passphrase, keyp, commentp);
 out:
	close(fd);
	திரும்பு r;
}

முழு
sshkey_load_private(மாறிலி எழுத்து *filename, மாறிலி எழுத்து *passphrase,
    கட்டமைப்பு sshkey **keyp, எழுத்து **commentp)
{
	திரும்பு sshkey_load_private_type(சாவி_UNSPEC, filename, passphrase,
	    keyp, commentp);
}

முழு
sshkey_load_private_type_fd(முழு fd, முழு type, மாறிலி எழுத்து *passphrase,
    கட்டமைப்பு sshkey **keyp, எழுத்து **commentp)
{
	கட்டமைப்பு sshbuf *buffer = வெற்று;
	முழு r;

	எனில் (keyp != வெற்று)
		*keyp = வெற்று;
	எனில் ((r = sshbuf_load_fd(fd, &buffer)) != 0 ||
	    (r = sshkey_parse_private_fileblob_type(buffer, type,
	    passphrase, keyp, commentp)) != 0)
		செல் out;

	/* success */
	r = 0;
 out:
	sshbuf_free(buffer);
	திரும்பு r;
}

/* Load a pubkey from the unencrypted envelope of a new-format private key */
நிலையான முழு
sshkey_load_pubkey_from_private(மாறிலி எழுத்து *filename, கட்டமைப்பு sshkey **pubkeyp)
{
	கட்டமைப்பு sshbuf *buffer = வெற்று;
	கட்டமைப்பு sshkey *pubkey = வெற்று;
	முழு r, fd;

	எனில் (pubkeyp != வெற்று)
		*pubkeyp = வெற்று;

	எனில் ((fd = open(filename, O_RDONLY)) == -1)
		திரும்பு SSH_ERR_SYSTEM_ERROR;
	எனில் ((r = sshbuf_load_fd(fd, &buffer)) != 0 ||
	    (r = sshkey_parse_pubkey_from_private_fileblob_type(buffer,
	    சாவி_UNSPEC, &pubkey)) != 0)
		செல் out;
	/* success */
	எனில் (pubkeyp != வெற்று) {
		*pubkeyp = pubkey;
		pubkey = வெற்று;
	}
	r = 0;
 out:
	close(fd);
	sshbuf_free(buffer);
	sshkey_free(pubkey);
	திரும்பு r;
}

நிலையான முழு
sshkey_try_load_public(கட்டமைப்பு sshkey **kp, மாறிலி எழுத்து *filename,
    எழுத்து **commentp)
{
	FILE *f;
	எழுத்து *வரி = வெற்று, *cp;
	size_t linesize = 0;
	முழு r;
	கட்டமைப்பு stat st;
	கட்டமைப்பு sshkey *k = வெற்று;

	எனில் (kp == வெற்று)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	*kp = வெற்று;
	எனில் (commentp != வெற்று)
		*commentp = வெற்று;
	எனில் ((f = fopen(filename, "r")) == வெற்று)
		திரும்பு SSH_ERR_SYSTEM_ERROR;
	எனில் (fstat(fileno(f), &st) == 0 && S_ISREG(st.st_mode) &&
	    st.st_size > SSHBUF_SIZE_MAX) {
		fclose(f);
		திரும்பு SSH_ERR_INVALID_FORMAT;
	}
	எனில் ((k = sshkey_new(சாவி_UNSPEC)) == வெற்று) {
		fclose(f);
		திரும்பு SSH_ERR_ALLOC_FAIL;
	}
	போது (getline(&வரி, &linesize, f) != -1) {
		cp = வரி;
		தேர்வு (*cp) {
		நிலை '#':
		நிலை '\n':
		நிலை '\0':
			தொடர்;
		}
		/* Abort loading if this looks like a private key */
		எனில் (strncmp(cp, "-----BEGIN", 10) == 0 ||
		    strcmp(cp, "SSH PRIVATE KEY FILE") == 0)
			நிறுத்து;
		/* Skip leading whitespace. */
		க்கு (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;
		எனில் (*cp) {
			எனில் ((r = sshkey_read(k, &cp)) == 0) {
				cp[strcspn(cp, "\r\n")] = '\0';
				எனில் (commentp) {
					*commentp = strdup(*cp ?
					    cp : filename);
					எனில் (*commentp == வெற்று)
						r = SSH_ERR_ALLOC_FAIL;
				}
				/* success */
				*kp = k;
				விடுவி(வரி);
				fclose(f);
				திரும்பு r;
			}
		}
	}
	விடுவி(k);
	விடுவி(வரி);
	fclose(f);
	திரும்பு SSH_ERR_INVALID_FORMAT;
}

/* load public key from any pubkey file */
முழு
sshkey_load_public(மாறிலி எழுத்து *filename, கட்டமைப்பு sshkey **keyp, எழுத்து **commentp)
{
	எழுத்து *pubfile = வெற்று;
	முழு r, oerrno;

	எனில் (keyp != வெற்று)
		*keyp = வெற்று;
	எனில் (commentp != வெற்று)
		*commentp = வெற்று;

	எனில் ((r = sshkey_try_load_public(keyp, filename, commentp)) == 0)
		செல் out;

	/* try .pub suffix */
	எனில் (asprintf(&pubfile, "%s.pub", filename) == -1)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் ((r = sshkey_try_load_public(keyp, pubfile, commentp)) == 0)
		செல் out;

	/* finally, try to extract public key from private key file */
	எனில் ((r = sshkey_load_pubkey_from_private(filename, keyp)) == 0)
		செல் out;

	/* Pretend we couldn't find the key */
	r = SSH_ERR_SYSTEM_ERROR;
	errno = ENOENT;

 out:
	oerrno = errno;
	விடுவி(pubfile);
	errno = oerrno;
	திரும்பு r;
}

/* Load the certificate associated with the named private key */
முழு
sshkey_load_cert(மாறிலி எழுத்து *filename, கட்டமைப்பு sshkey **keyp)
{
	கட்டமைப்பு sshkey *pub = வெற்று;
	எழுத்து *file = வெற்று;
	முழு r = SSH_ERR_INTERNAL_ERROR;

	எனில் (keyp != வெற்று)
		*keyp = வெற்று;

	எனில் (asprintf(&file, "%s-cert.pub", filename) == -1)
		திரும்பு SSH_ERR_ALLOC_FAIL;

	r = sshkey_try_load_public(keyp, file, வெற்று);
	விடுவி(file);
	sshkey_free(pub);
	திரும்பு r;
}

/* Load private key and certificate */
முழு
sshkey_load_private_cert(முழு type, மாறிலி எழுத்து *filename, மாறிலி எழுத்து *passphrase,
    கட்டமைப்பு sshkey **keyp)
{
	கட்டமைப்பு sshkey *சாவி = வெற்று, *cert = வெற்று;
	முழு r;

	எனில் (keyp != வெற்று)
		*keyp = வெற்று;

	தேர்வு (type) {
#ifdef WITH_OPENSSL
	நிலை சாவி_RSA:
	நிலை சாவி_ECDSA:
#endif /* WITH_OPENSSL */
	நிலை சாவி_ED25519:
	நிலை சாவி_MLDSA44_ED25519:
	நிலை சாவி_UNSPEC:
		நிறுத்து;
	இயல்பு:
		திரும்பு SSH_ERR_சாவி_TYPE_UNKNOWN;
	}

	எனில் ((r = sshkey_load_private_type(type, filename,
	    passphrase, &சாவி, வெற்று)) != 0 ||
	    (r = sshkey_load_cert(filename, &cert)) != 0)
		செல் out;

	/* Make sure the private key matches the certificate */
	எனில் (sshkey_equal_public(சாவி, cert) == 0) {
		r = SSH_ERR_சாவி_CERT_MISMATCH;
		செல் out;
	}

	எனில் ((r = sshkey_to_certified(சாவி)) != 0 ||
	    (r = sshkey_cert_copy(cert, சாவி)) != 0)
		செல் out;
	r = 0;
	எனில் (keyp != வெற்று) {
		*keyp = சாவி;
		சாவி = வெற்று;
	}
 out:
	sshkey_free(சாவி);
	sshkey_free(cert);
	திரும்பு r;
}

/*
 * Returns success if the specified "key" is listed in the file "filename",
 * SSH_ERR_KEY_NOT_FOUND: if the key is not listed or another error.
 * If "strict_type" is set then the key type must match exactly,
 * otherwise a comparison that ignores certificate data is performed.
 * If "check_ca" is set and "key" is a certificate, then its CA key is
 * also checked and sshkey_in_file() will return success if either is found.
 */
முழு
sshkey_in_file(கட்டமைப்பு sshkey *சாவி, மாறிலி எழுத்து *filename, முழு strict_type,
    முழு check_ca)
{
	FILE *f;
	எழுத்து *வரி = வெற்று, *cp;
	size_t linesize = 0;
	முழு r = 0;
	கட்டமைப்பு sshkey *pub = வெற்று;

	முழு (*sshkey_compare)(மாறிலி கட்டமைப்பு sshkey *, மாறிலி கட்டமைப்பு sshkey *) =
	    strict_type ?  sshkey_equal : sshkey_equal_public;

	எனில் ((f = fopen(filename, "r")) == வெற்று)
		திரும்பு SSH_ERR_SYSTEM_ERROR;

	போது (getline(&வரி, &linesize, f) != -1) {
		sshkey_free(pub);
		pub = வெற்று;
		cp = வரி;

		/* Skip leading whitespace. */
		க்கு (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;

		/* Skip comments and empty lines */
		தேர்வு (*cp) {
		நிலை '#':
		நிலை '\n':
		நிலை '\0':
			தொடர்;
		}

		எனில் ((pub = sshkey_new(சாவி_UNSPEC)) == வெற்று) {
			r = SSH_ERR_ALLOC_FAIL;
			செல் out;
		}
		தேர்வு (r = sshkey_read(pub, &cp)) {
		நிலை 0:
			நிறுத்து;
		நிலை SSH_ERR_சாவி_LENGTH:
			தொடர்;
		இயல்பு:
			செல் out;
		}
		எனில் (sshkey_compare(சாவி, pub) ||
		    (check_ca && sshkey_is_cert(சாவி) &&
		    sshkey_compare(சாவி->cert->signature_சாவி, pub))) {
			r = 0;
			செல் out;
		}
	}
	r = SSH_ERR_சாவி_NOT_FOUND;
 out:
	விடுவி(வரி);
	sshkey_free(pub);
	fclose(f);
	திரும்பு r;
}

/*
 * Checks whether the specified key is revoked, returning 0 if not,
 * SSH_ERR_KEY_REVOKED if it is or another error code if something
 * unexpected happened.
 * This will check both the key and, if it is a certificate, its CA key too.
 * "revoked_keys_file" may be a KRL or a one-per-line list of public keys.
 */
முழு
sshkey_check_revoked(கட்டமைப்பு sshkey *சாவி, மாறிலி எழுத்து *revoked_சாவிகள்_file)
{
	முழு r;

	r = ssh_krl_file_contains_சாவி(revoked_சாவிகள்_file, சாவி);
	/* If this was not a KRL to begin with then continue below */
	எனில் (r != SSH_ERR_KRL_BAD_MAGIC)
		திரும்பு r;

	/*
	 * If the file is not a KRL or we can't handle KRLs then attempt to
	 * parse the file as a flat list of keys.
	 */
	தேர்வு ((r = sshkey_in_file(சாவி, revoked_சாவிகள்_file, 0, 1))) {
	நிலை 0:
		/* Key found => revoked */
		திரும்பு SSH_ERR_சாவி_REVOKED;
	நிலை SSH_ERR_சாவி_NOT_FOUND:
		/* Key not found => not revoked */
		திரும்பு 0;
	இயல்பு:
		/* Some other error occurred */
		திரும்பு r;
	}
}

/*
 * Advanced *cpp past the end of key options, defined as the first unquoted
 * whitespace character. Returns 0 on success or -1 on failure (e.g.
 * unterminated quotes).
 */
முழு
sshkey_advance_past_options(எழுத்து **cpp)
{
	எழுத்து *cp = *cpp;
	முழு quoted = 0;

	க்கு (; *cp && (quoted || (*cp != ' ' && *cp != '\t')); cp++) {
		எனில் (*cp == '\\' && cp[1] == '"')
			cp++;	/* Skip both */
		இல்லையெனில் எனில் (*cp == '"')
			quoted = !quoted;
	}
	*cpp = cp;
	/* return failure for unterminated quotes */
	திரும்பு (*cp == '\0' && quoted) ? -1 : 0;
}

/* Save a public key */
முழு
sshkey_save_public(மாறிலி கட்டமைப்பு sshkey *சாவி, மாறிலி எழுத்து *path,
    மாறிலி எழுத்து *comment)
{
	முழு fd, oerrno;
	FILE *f = வெற்று;
	முழு r = SSH_ERR_INTERNAL_ERROR;

	எனில் ((fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, 0644)) == -1)
		திரும்பு SSH_ERR_SYSTEM_ERROR;
	எனில் ((f = fdopen(fd, "w")) == வெற்று) {
		r = SSH_ERR_SYSTEM_ERROR;
		close(fd);
		செல் fail;
	}
	எனில் ((r = sshkey_write(சாவி, f)) != 0)
		செல் fail;
	fprintf(f, " %s\n", comment);
	எனில் (ferror(f)) {
		r = SSH_ERR_SYSTEM_ERROR;
		செல் fail;
	}
	எனில் (fclose(f) != 0) {
		r = SSH_ERR_SYSTEM_ERROR;
		f = வெற்று;
 fail:
		எனில் (f != வெற்று) {
			oerrno = errno;
			fclose(f);
			errno = oerrno;
		}
		திரும்பு r;
	}
	திரும்பு 0;
}
