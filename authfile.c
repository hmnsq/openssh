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
	החזר r;
}

صحيح
sshkey_save_private(بنية sshkey *key, ثابت حرف *filename,
    ثابت حرف *passphrase, ثابت حرف *comment,
    صحيح format, ثابت حرف *openssh_format_cipher, صحيح openssh_format_rounds)
{
	بنية sshbuf *keyblob = عدم;
	صحيح r;

	אם ((keyblob = sshbuf_new()) == عدم)
		החזר SSH_ERR_ALLOC_FAIL;
	אם ((r = sshkey_private_to_fileblob(key, keyblob, passphrase, comment,
	    format, openssh_format_cipher, openssh_format_rounds)) != 0)
		اذهب out;
	אם ((r = sshkey_save_private_blob(keyblob, filename)) != 0)
		اذهب out;
	r = 0;
 out:
	sshbuf_free(keyblob);
	החזר r;
}

/* XXX remove error() calls from here? */
صحيح
sshkey_perm_ok(صحيح fd, ثابت حرف *filename)
{
	بنية stat st;

	אם (fstat(fd, &st) == -1)
		החזר SSH_ERR_SYSTEM_ERROR;
	/*
	 * if a key owned by the user is accessed, then we check the
	 * permissions of the file. if the key owned by a different user,
	 * then we don't care.
	 */
#ifdef HAVE_CYGWIN
	אם (check_ntsec(filename))
#endif
	אם ((st.st_uid == getuid()) && (st.st_mode & 077) != 0) {
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @");
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("Permissions 0%3.3o for '%s' are too open.",
		    (u_int)st.st_mode & 0777, filename);
		error("It is required that your private key files are NOT accessible by others.");
		error("This private key will be ignored.");
		החזר SSH_ERR_KEY_BAD_PERMISSIONS;
	}
	החזר 0;
}

صحيح
sshkey_load_private_type(صحيح type, ثابت حرف *filename, ثابت حرف *passphrase,
    بنية sshkey **keyp, حرف **commentp)
{
	صحيح fd, r;

	אם (keyp != عدم)
		*keyp = عدم;
	אם (commentp != عدم)
		*commentp = عدم;

	אם ((fd = open(filename, O_RDONLY)) == -1)
		החזר SSH_ERR_SYSTEM_ERROR;

	r = sshkey_perm_ok(fd, filename);
	אם (r != 0)
		اذهب out;

	r = sshkey_load_private_type_fd(fd, type, passphrase, keyp, commentp);
 out:
	close(fd);
	החזר r;
}

صحيح
sshkey_load_private(ثابت حرف *filename, ثابت حرف *passphrase,
    بنية sshkey **keyp, حرف **commentp)
{
	החזר sshkey_load_private_type(KEY_UNSPEC, filename, passphrase,
	    keyp, commentp);
}

صحيح
sshkey_load_private_type_fd(صحيح fd, صحيح type, ثابت حرف *passphrase,
    بنية sshkey **keyp, حرف **commentp)
{
	بنية sshbuf *buffer = عدم;
	صحيح r;

	אם (keyp != عدم)
		*keyp = عدم;
	אם ((r = sshbuf_load_fd(fd, &buffer)) != 0 ||
	    (r = sshkey_parse_private_fileblob_type(buffer, type,
	    passphrase, keyp, commentp)) != 0)
		اذهب out;

	/* success */
	r = 0;
 out:
	sshbuf_free(buffer);
	החזר r;
}

/* Load a pubkey from the unencrypted envelope of a new-format private key */
ساكن صحيح
sshkey_load_pubkey_from_private(ثابت حرف *filename, بنية sshkey **pubkeyp)
{
	بنية sshbuf *buffer = عدم;
	بنية sshkey *pubkey = عدم;
	صحيح r, fd;

	אם (pubkeyp != عدم)
		*pubkeyp = عدم;

	אם ((fd = open(filename, O_RDONLY)) == -1)
		החזר SSH_ERR_SYSTEM_ERROR;
	אם ((r = sshbuf_load_fd(fd, &buffer)) != 0 ||
	    (r = sshkey_parse_pubkey_from_private_fileblob_type(buffer,
	    KEY_UNSPEC, &pubkey)) != 0)
		اذهب out;
	/* success */
	אם (pubkeyp != عدم) {
		*pubkeyp = pubkey;
		pubkey = عدم;
	}
	r = 0;
 out:
	close(fd);
	sshbuf_free(buffer);
	sshkey_free(pubkey);
	החזר r;
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

	אם (kp == عدم)
		החזר SSH_ERR_INVALID_ARGUMENT;
	*kp = عدم;
	אם (commentp != عدم)
		*commentp = عدم;
	אם ((f = fopen(filename, "r")) == عدم)
		החזר SSH_ERR_SYSTEM_ERROR;
	אם (fstat(fileno(f), &st) == 0 && S_ISREG(st.st_mode) &&
	    st.st_size > SSHBUF_SIZE_MAX) {
		fclose(f);
		החזר SSH_ERR_INVALID_FORMAT;
	}
	אם ((k = sshkey_new(KEY_UNSPEC)) == عدم) {
		fclose(f);
		החזר SSH_ERR_ALLOC_FAIL;
	}
	כלעוד (getline(&line, &linesize, f) != -1) {
		cp = line;
		بدل (*cp) {
		حالة '#':
		حالة '\n':
		حالة '\0':
			استمر;
		}
		/* Abort loading if this looks like a private key */
		אם (strncmp(cp, "-----BEGIN", 10) == 0 ||
		    strcmp(cp, "SSH PRIVATE KEY FILE") == 0)
			اكسر;
		/* Skip leading whitespace. */
		עבור (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;
		אם (*cp) {
			אם ((r = sshkey_read(k, &cp)) == 0) {
				cp[strcspn(cp, "\r\n")] = '\0';
				אם (commentp) {
					*commentp = strdup(*cp ?
					    cp : filename);
					אם (*commentp == عدم)
						r = SSH_ERR_ALLOC_FAIL;
				}
				/* success */
				*kp = k;
				حرر(line);
				fclose(f);
				החזר r;
			}
		}
	}
	حرر(k);
	حرر(line);
	fclose(f);
	החזר SSH_ERR_INVALID_FORMAT;
}

/* load public key from any pubkey file */
صحيح
sshkey_load_public(ثابت حرف *filename, بنية sshkey **keyp, حرف **commentp)
{
	حرف *pubfile = عدم;
	صحيح r, oerrno;

	אם (keyp != عدم)
		*keyp = عدم;
	אם (commentp != عدم)
		*commentp = عدم;

	אם ((r = sshkey_try_load_public(keyp, filename, commentp)) == 0)
		اذهب out;

	/* try .pub suffix */
	אם (asprintf(&pubfile, "%s.pub", filename) == -1)
		החזר SSH_ERR_ALLOC_FAIL;
	אם ((r = sshkey_try_load_public(keyp, pubfile, commentp)) == 0)
		اذهب out;

	/* finally, try to extract public key from private key file */
	אם ((r = sshkey_load_pubkey_from_private(filename, keyp)) == 0)
		اذهب out;

	/* Pretend we couldn't find the key */
	r = SSH_ERR_SYSTEM_ERROR;
	errno = ENOENT;

 out:
	oerrno = errno;
	حرر(pubfile);
	errno = oerrno;
	החזר r;
}

/* Load the certificate associated with the named private key */
صحيح
sshkey_load_cert(ثابت حرف *filename, بنية sshkey **keyp)
{
	بنية sshkey *pub = عدم;
	حرف *file = عدم;
	صحيح r = SSH_ERR_INTERNAL_ERROR;

	אם (keyp != عدم)
		*keyp = عدم;

	אם (asprintf(&file, "%s-cert.pub", filename) == -1)
		החזר SSH_ERR_ALLOC_FAIL;

	r = sshkey_try_load_public(keyp, file, عدم);
	حرر(file);
	sshkey_free(pub);
	החזר r;
}

/* Load private key and certificate */
صحيح
sshkey_load_private_cert(صحيح type, ثابت حرف *filename, ثابت حرف *passphrase,
    بنية sshkey **keyp)
{
	بنية sshkey *key = عدم, *cert = عدم;
	صحيح r;

	אם (keyp != عدم)
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
		החזר SSH_ERR_KEY_TYPE_UNKNOWN;
	}

	אם ((r = sshkey_load_private_type(type, filename,
	    passphrase, &key, عدم)) != 0 ||
	    (r = sshkey_load_cert(filename, &cert)) != 0)
		اذهب out;

	/* Make sure the private key matches the certificate */
	אם (sshkey_equal_public(key, cert) == 0) {
		r = SSH_ERR_KEY_CERT_MISMATCH;
		اذهب out;
	}

	אם ((r = sshkey_to_certified(key)) != 0 ||
	    (r = sshkey_cert_copy(cert, key)) != 0)
		اذهب out;
	r = 0;
	אם (keyp != عدم) {
		*keyp = key;
		key = عدم;
	}
 out:
	sshkey_free(key);
	sshkey_free(cert);
	החזר r;
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

	אם ((f = fopen(filename, "r")) == عدم)
		החזר SSH_ERR_SYSTEM_ERROR;

	כלעוד (getline(&line, &linesize, f) != -1) {
		sshkey_free(pub);
		pub = عدم;
		cp = line;

		/* Skip leading whitespace. */
		עבור (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;

		/* Skip comments and empty lines */
		بدل (*cp) {
		حالة '#':
		حالة '\n':
		حالة '\0':
			استمر;
		}

		אם ((pub = sshkey_new(KEY_UNSPEC)) == عدم) {
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
		אם (sshkey_compare(key, pub) ||
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
	החזר r;
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
	אם (r != SSH_ERR_KRL_BAD_MAGIC)
		החזר r;

	/*
	 * If the file is not a KRL or we can't handle KRLs then attempt to
	 * parse the file as a flat list of keys.
	 */
	بدل ((r = sshkey_in_file(key, revoked_keys_file, 0, 1))) {
	حالة 0:
		/* Key found => revoked */
		החזר SSH_ERR_KEY_REVOKED;
	حالة SSH_ERR_KEY_NOT_FOUND:
		/* Key not found => not revoked */
		החזר 0;
	افتراضي:
		/* Some other error occurred */
		החזר r;
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

	עבור (; *cp && (quoted || (*cp != ' ' && *cp != '\t')); cp++) {
		אם (*cp == '\\' && cp[1] == '"')
			cp++;	/* Skip both */
		אחרת אם (*cp == '"')
			quoted = !quoted;
	}
	*cpp = cp;
	/* return failure for unterminated quotes */
	החזר (*cp == '\0' && quoted) ? -1 : 0;
}

/* Save a public key */
صحيح
sshkey_save_public(ثابت بنية sshkey *key, ثابت حرف *path,
    ثابت حرف *comment)
{
	صحيح fd, oerrno;
	FILE *f = عدم;
	صحيح r = SSH_ERR_INTERNAL_ERROR;

	אם ((fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, 0644)) == -1)
		החזר SSH_ERR_SYSTEM_ERROR;
	אם ((f = fdopen(fd, "w")) == عدم) {
		r = SSH_ERR_SYSTEM_ERROR;
		close(fd);
		اذهب fail;
	}
	אם ((r = sshkey_write(key, f)) != 0)
		اذهب fail;
	fprintf(f, " %s\n", comment);
	אם (ferror(f)) {
		r = SSH_ERR_SYSTEM_ERROR;
		اذهب fail;
	}
	אם (fclose(f) != 0) {
		r = SSH_ERR_SYSTEM_ERROR;
		f = عدم;
 fail:
		אם (f != عدم) {
			oerrno = errno;
			fclose(f);
			errno = oerrno;
		}
		החזר r;
	}
	החזר 0;
}
