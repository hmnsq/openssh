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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/stat.h>

#ضمن <errno.h>
#ضمن <fcntl.h>
#ضمن <stdio.h>
#ضمن <stdarg.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <unistd.h>

#ضمن "log.h"
#ضمن "authfile.h"
#ضمن "sshkey.h"
#ضمن "sshbuf.h"
#ضمن "ssherr.h"
#ضمن "krl.h"

/* Save a key blob to a file */
ساكن صحيح
sshkey_save_private_blob(بنية sshbuf *keybuf, ثابت حرف *filename)
{
	صحيح r;
	mode_t omask;

	omask = umask(077);
	r = sshbuf_write_file(filename, keybuf);
	umask(omask);
	أرجع r;
}

صحيح
sshkey_save_private(بنية sshkey *key, ثابت حرف *filename,
    ثابت حرف *passphrase, ثابت حرف *comment,
    صحيح format, ثابت حرف *openssh_format_cipher, صحيح openssh_format_rounds)
{
	بنية sshbuf *keyblob = عدم;
	صحيح r;

	𐡄𐡍 ((keyblob = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	𐡄𐡍 ((r = sshkey_private_to_fileblob(key, keyblob, passphrase, comment,
	    format, openssh_format_cipher, openssh_format_rounds)) != 0)
		اذهب out;
	𐡄𐡍 ((r = sshkey_save_private_blob(keyblob, filename)) != 0)
		اذهب out;
	r = 0;
 out:
	sshbuf_free(keyblob);
	أرجع r;
}

/* XXX remove error() calls from here? */
صحيح
sshkey_perm_ok(صحيح fd, ثابت حرف *filename)
{
	بنية stat st;

	𐡄𐡍 (fstat(fd, &st) == -1)
		أرجع SSH_ERR_SYSTEM_ERROR;
	/*
	 * if a key owned by the user is accessed, then we check the
	 * permissions of the file. if the key owned by a different user,
	 * then we don't care.
	 */
#ifdef HAVE_CYGWIN
	𐡄𐡍 (check_ntsec(filename))
#endif
	𐡄𐡍 ((st.st_uid == getuid()) && (st.st_mode & 077) != 0) {
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @");
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("Permissions 0%3.3o for '%s' are too open.",
		    (u_int)st.st_mode & 0777, filename);
		error("It is required that your private key files are NOT accessible by others.");
		error("This private key will be ignored.");
		أرجع SSH_ERR_KEY_BAD_PERMISSIONS;
	}
	أرجع 0;
}

صحيح
sshkey_load_private_type(صحيح type, ثابت حرف *filename, ثابت حرف *passphrase,
    بنية sshkey **keyp, حرف **commentp)
{
	صحيح fd, r;

	𐡄𐡍 (keyp != عدم)
		*keyp = عدم;
	𐡄𐡍 (commentp != عدم)
		*commentp = عدم;

	𐡄𐡍 ((fd = open(filename, O_RDONLY)) == -1)
		أرجع SSH_ERR_SYSTEM_ERROR;

	r = sshkey_perm_ok(fd, filename);
	𐡄𐡍 (r != 0)
		اذهب out;

	r = sshkey_load_private_type_fd(fd, type, passphrase, keyp, commentp);
 out:
	close(fd);
	أرجع r;
}

صحيح
sshkey_load_private(ثابت حرف *filename, ثابت حرف *passphrase,
    بنية sshkey **keyp, حرف **commentp)
{
	أرجع sshkey_load_private_type(KEY_UNSPEC, filename, passphrase,
	    keyp, commentp);
}

صحيح
sshkey_load_private_type_fd(صحيح fd, صحيح type, ثابت حرف *passphrase,
    بنية sshkey **keyp, حرف **commentp)
{
	بنية sshbuf *buffer = عدم;
	صحيح r;

	𐡄𐡍 (keyp != عدم)
		*keyp = عدم;
	𐡄𐡍 ((r = sshbuf_load_fd(fd, &buffer)) != 0 ||
	    (r = sshkey_parse_private_fileblob_type(buffer, type,
	    passphrase, keyp, commentp)) != 0)
		اذهب out;

	/* success */
	r = 0;
 out:
	sshbuf_free(buffer);
	أرجع r;
}

/* Load a pubkey from the unencrypted envelope of a new-format private key */
ساكن صحيح
sshkey_load_pubkey_from_private(ثابت حرف *filename, بنية sshkey **pubkeyp)
{
	بنية sshbuf *buffer = عدم;
	بنية sshkey *pubkey = عدم;
	صحيح r, fd;

	𐡄𐡍 (pubkeyp != عدم)
		*pubkeyp = عدم;

	𐡄𐡍 ((fd = open(filename, O_RDONLY)) == -1)
		أرجع SSH_ERR_SYSTEM_ERROR;
	𐡄𐡍 ((r = sshbuf_load_fd(fd, &buffer)) != 0 ||
	    (r = sshkey_parse_pubkey_from_private_fileblob_type(buffer,
	    KEY_UNSPEC, &pubkey)) != 0)
		اذهب out;
	/* success */
	𐡄𐡍 (pubkeyp != عدم) {
		*pubkeyp = pubkey;
		pubkey = عدم;
	}
	r = 0;
 out:
	close(fd);
	sshbuf_free(buffer);
	sshkey_free(pubkey);
	أرجع r;
}

ساكن صحيح
sshkey_try_load_public(بنية sshkey **kp, ثابت حرف *filename,
    حرف **commentp)
{
	FILE *f;
	حرف *line = عدم, *cp;
	size_t linesize = 0;
	صحيح r;
	بنية stat st;
	بنية sshkey *k = عدم;

	𐡄𐡍 (kp == عدم)
		أرجع SSH_ERR_INVALID_ARGUMENT;
	*kp = عدم;
	𐡄𐡍 (commentp != عدم)
		*commentp = عدم;
	𐡄𐡍 ((f = fopen(filename, "r")) == عدم)
		أرجع SSH_ERR_SYSTEM_ERROR;
	𐡄𐡍 (fstat(fileno(f), &st) == 0 && S_ISREG(st.st_mode) &&
	    st.st_size > SSHBUF_SIZE_MAX) {
		fclose(f);
		أرجع SSH_ERR_INVALID_FORMAT;
	}
	𐡄𐡍 ((k = sshkey_new(KEY_UNSPEC)) == عدم) {
		fclose(f);
		أرجع SSH_ERR_ALLOC_FAIL;
	}
	طالما (getline(&line, &linesize, f) != -1) {
		cp = line;
		بدل (*cp) {
		حالة '#':
		حالة '\n':
		حالة '\0':
			استمر;
		}
		/* Abort loading if this looks like a private key */
		𐡄𐡍 (strncmp(cp, "-----BEGIN", 10) == 0 ||
		    strcmp(cp, "SSH PRIVATE KEY FILE") == 0)
			اكسر;
		/* Skip leading whitespace. */
		لكل (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;
		𐡄𐡍 (*cp) {
			𐡄𐡍 ((r = sshkey_read(k, &cp)) == 0) {
				cp[strcspn(cp, "\r\n")] = '\0';
				𐡄𐡍 (commentp) {
					*commentp = strdup(*cp ?
					    cp : filename);
					𐡄𐡍 (*commentp == عدم)
						r = SSH_ERR_ALLOC_FAIL;
				}
				/* success */
				*kp = k;
				حرر(line);
				fclose(f);
				أرجع r;
			}
		}
	}
	حرر(k);
	حرر(line);
	fclose(f);
	أرجع SSH_ERR_INVALID_FORMAT;
}

/* load public key from any pubkey file */
صحيح
sshkey_load_public(ثابت حرف *filename, بنية sshkey **keyp, حرف **commentp)
{
	حرف *pubfile = عدم;
	صحيح r, oerrno;

	𐡄𐡍 (keyp != عدم)
		*keyp = عدم;
	𐡄𐡍 (commentp != عدم)
		*commentp = عدم;

	𐡄𐡍 ((r = sshkey_try_load_public(keyp, filename, commentp)) == 0)
		اذهب out;

	/* try .pub suffix */
	𐡄𐡍 (asprintf(&pubfile, "%s.pub", filename) == -1)
		أرجع SSH_ERR_ALLOC_FAIL;
	𐡄𐡍 ((r = sshkey_try_load_public(keyp, pubfile, commentp)) == 0)
		اذهب out;

	/* finally, try to extract public key from private key file */
	𐡄𐡍 ((r = sshkey_load_pubkey_from_private(filename, keyp)) == 0)
		اذهب out;

	/* Pretend we couldn't find the key */
	r = SSH_ERR_SYSTEM_ERROR;
	errno = ENOENT;

 out:
	oerrno = errno;
	حرر(pubfile);
	errno = oerrno;
	أرجع r;
}

/* Load the certificate associated with the named private key */
صحيح
sshkey_load_cert(ثابت حرف *filename, بنية sshkey **keyp)
{
	بنية sshkey *pub = عدم;
	حرف *file = عدم;
	صحيح r = SSH_ERR_INTERNAL_ERROR;

	𐡄𐡍 (keyp != عدم)
		*keyp = عدم;

	𐡄𐡍 (asprintf(&file, "%s-cert.pub", filename) == -1)
		أرجع SSH_ERR_ALLOC_FAIL;

	r = sshkey_try_load_public(keyp, file, عدم);
	حرر(file);
	sshkey_free(pub);
	أرجع r;
}

/* Load private key and certificate */
صحيح
sshkey_load_private_cert(صحيح type, ثابت حرف *filename, ثابت حرف *passphrase,
    بنية sshkey **keyp)
{
	بنية sshkey *key = عدم, *cert = عدم;
	صحيح r;

	𐡄𐡍 (keyp != عدم)
		*keyp = عدم;

	بدل (type) {
#ifdef WITH_OPENSSL
	حالة KEY_RSA:
	حالة KEY_ECDSA:
#endif /* WITH_OPENSSL */
	حالة KEY_ED25519:
	حالة KEY_MLDSA44_ED25519:
	حالة KEY_UNSPEC:
		اكسر;
	افتراضي:
		أرجع SSH_ERR_KEY_TYPE_UNKNOWN;
	}

	𐡄𐡍 ((r = sshkey_load_private_type(type, filename,
	    passphrase, &key, عدم)) != 0 ||
	    (r = sshkey_load_cert(filename, &cert)) != 0)
		اذهب out;

	/* Make sure the private key matches the certificate */
	𐡄𐡍 (sshkey_equal_public(key, cert) == 0) {
		r = SSH_ERR_KEY_CERT_MISMATCH;
		اذهب out;
	}

	𐡄𐡍 ((r = sshkey_to_certified(key)) != 0 ||
	    (r = sshkey_cert_copy(cert, key)) != 0)
		اذهب out;
	r = 0;
	𐡄𐡍 (keyp != عدم) {
		*keyp = key;
		key = عدم;
	}
 out:
	sshkey_free(key);
	sshkey_free(cert);
	أرجع r;
}

/*
 * Returns success if the specified "key" is listed in the file "filename",
 * SSH_ERR_KEY_NOT_FOUND: if the key is not listed or another error.
 * If "strict_type" is set then the key type must match exactly,
 * otherwise a comparison that ignores certificate data is performed.
 * If "check_ca" is set and "key" is a certificate, then its CA key is
 * also checked and sshkey_in_file() will return success if either is found.
 */
صحيح
sshkey_in_file(بنية sshkey *key, ثابت حرف *filename, صحيح strict_type,
    صحيح check_ca)
{
	FILE *f;
	حرف *line = عدم, *cp;
	size_t linesize = 0;
	صحيح r = 0;
	بنية sshkey *pub = عدم;

	صحيح (*sshkey_compare)(ثابت بنية sshkey *, ثابت بنية sshkey *) =
	    strict_type ?  sshkey_equal : sshkey_equal_public;

	𐡄𐡍 ((f = fopen(filename, "r")) == عدم)
		أرجع SSH_ERR_SYSTEM_ERROR;

	طالما (getline(&line, &linesize, f) != -1) {
		sshkey_free(pub);
		pub = عدم;
		cp = line;

		/* Skip leading whitespace. */
		لكل (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;

		/* Skip comments and empty lines */
		بدل (*cp) {
		حالة '#':
		حالة '\n':
		حالة '\0':
			استمر;
		}

		𐡄𐡍 ((pub = sshkey_new(KEY_UNSPEC)) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب out;
		}
		بدل (r = sshkey_read(pub, &cp)) {
		حالة 0:
			اكسر;
		حالة SSH_ERR_KEY_LENGTH:
			استمر;
		افتراضي:
			اذهب out;
		}
		𐡄𐡍 (sshkey_compare(key, pub) ||
		    (check_ca && sshkey_is_cert(key) &&
		    sshkey_compare(key->cert->signature_key, pub))) {
			r = 0;
			اذهب out;
		}
	}
	r = SSH_ERR_KEY_NOT_FOUND;
 out:
	حرر(line);
	sshkey_free(pub);
	fclose(f);
	أرجع r;
}

/*
 * Checks whether the specified key is revoked, returning 0 if not,
 * SSH_ERR_KEY_REVOKED if it is or another error code if something
 * unexpected happened.
 * This will check both the key and, if it is a certificate, its CA key too.
 * "revoked_keys_file" may be a KRL or a one-per-line list of public keys.
 */
صحيح
sshkey_check_revoked(بنية sshkey *key, ثابت حرف *revoked_keys_file)
{
	صحيح r;

	r = ssh_krl_file_contains_key(revoked_keys_file, key);
	/* If this was not a KRL to begin with then continue below */
	𐡄𐡍 (r != SSH_ERR_KRL_BAD_MAGIC)
		أرجع r;

	/*
	 * If the file is not a KRL or we can't handle KRLs then attempt to
	 * parse the file as a flat list of keys.
	 */
	بدل ((r = sshkey_in_file(key, revoked_keys_file, 0, 1))) {
	حالة 0:
		/* Key found => revoked */
		أرجع SSH_ERR_KEY_REVOKED;
	حالة SSH_ERR_KEY_NOT_FOUND:
		/* Key not found => not revoked */
		أرجع 0;
	افتراضي:
		/* Some other error occurred */
		أرجع r;
	}
}

/*
 * Advanced *cpp past the end of key options, defined as the first unquoted
 * whitespace character. Returns 0 on success or -1 on failure (e.g.
 * unterminated quotes).
 */
صحيح
sshkey_advance_past_options(حرف **cpp)
{
	حرف *cp = *cpp;
	صحيح quoted = 0;

	لكل (; *cp && (quoted || (*cp != ' ' && *cp != '\t')); cp++) {
		𐡄𐡍 (*cp == '\\' && cp[1] == '"')
			cp++;	/* Skip both */
		وإلا 𐡄𐡍 (*cp == '"')
			quoted = !quoted;
	}
	*cpp = cp;
	/* return failure for unterminated quotes */
	أرجع (*cp == '\0' && quoted) ? -1 : 0;
}

/* Save a public key */
صحيح
sshkey_save_public(ثابت بنية sshkey *key, ثابت حرف *path,
    ثابت حرف *comment)
{
	صحيح fd, oerrno;
	FILE *f = عدم;
	صحيح r = SSH_ERR_INTERNAL_ERROR;

	𐡄𐡍 ((fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, 0644)) == -1)
		أرجع SSH_ERR_SYSTEM_ERROR;
	𐡄𐡍 ((f = fdopen(fd, "w")) == عدم) {
		r = SSH_ERR_SYSTEM_ERROR;
		close(fd);
		اذهب fail;
	}
	𐡄𐡍 ((r = sshkey_write(key, f)) != 0)
		اذهب fail;
	fprintf(f, " %s\n", comment);
	𐡄𐡍 (ferror(f)) {
		r = SSH_ERR_SYSTEM_ERROR;
		اذهب fail;
	}
	𐡄𐡍 (fclose(f) != 0) {
		r = SSH_ERR_SYSTEM_ERROR;
		f = عدم;
 fail:
		𐡄𐡍 (f != عدم) {
			oerrno = errno;
			fclose(f);
			errno = oerrno;
		}
		أرجع r;
	}
	أرجع 0;
}
