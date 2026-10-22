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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/stat.h>

#شامل <errno.h>
#شامل <fcntl.h>
#شامل <stdio.h>
#شامل <stdarg.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <unistd.h>

#شامل "log.h"
#شامل "authfile.h"
#شامل "sshkey.h"
#شامل "sshbuf.h"
#شامل "ssherr.h"
#شامل "krl.h"

/* Save a key blob to a file */
ایستا صحیح
sshkey_save_private_blob(ساختار sshbuf *keybuf, ثابت نویسه *filename)
{
	صحیح r;
	mode_t omask;

	omask = umask(077);
	r = sshbuf_write_file(filename, keybuf);
	umask(omask);
	بازگشت r;
}

صحیح
sshkey_save_private(ساختار sshkey *کلید, ثابت نویسه *filename,
    ثابت نویسه *passphrase, ثابت نویسه *comment,
    صحیح format, ثابت نویسه *openssh_format_cipher, صحیح openssh_format_rounds)
{
	ساختار sshbuf *keyblob = پوچ;
	صحیح r;

	اگر ((keyblob = sshbuf_new()) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshkey_private_to_fileblob(کلید, keyblob, passphrase, comment,
	    format, openssh_format_cipher, openssh_format_rounds)) != 0)
		برو out;
	اگر ((r = sshkey_save_private_blob(keyblob, filename)) != 0)
		برو out;
	r = 0;
 out:
	sshbuf_free(keyblob);
	بازگشت r;
}

/* XXX remove error() calls from here? */
صحیح
sshkey_perm_ok(صحیح fd, ثابت نویسه *filename)
{
	ساختار stat st;

	اگر (fstat(fd, &st) == -1)
		بازگشت SSH_ERR_SYSTEM_ERROR;
	/*
	 * if a key owned by the user is accessed, then we check the
	 * permissions of the file. if the key owned by a different user,
	 * then we don't care.
	 */
#ifdef HAVE_CYGWIN
	اگر (check_ntsec(filename))
#endif
	اگر ((st.st_uid == getuid()) && (st.st_mode & 077) != 0) {
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @");
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("Permissions 0%3.3o for '%s' are too open.",
		    (u_int)st.st_mode & 0777, filename);
		error("It is required that your private key files are NOT accessible by others.");
		error("This private key will be ignored.");
		بازگشت SSH_ERR_کلید_BAD_PERMISSIONS;
	}
	بازگشت 0;
}

صحیح
sshkey_load_private_type(صحیح type, ثابت نویسه *filename, ثابت نویسه *passphrase,
    ساختار sshkey **keyp, نویسه **commentp)
{
	صحیح fd, r;

	اگر (keyp != پوچ)
		*keyp = پوچ;
	اگر (commentp != پوچ)
		*commentp = پوچ;

	اگر ((fd = open(filename, O_RDONLY)) == -1)
		بازگشت SSH_ERR_SYSTEM_ERROR;

	r = sshkey_perm_ok(fd, filename);
	اگر (r != 0)
		برو out;

	r = sshkey_load_private_type_fd(fd, type, passphrase, keyp, commentp);
 out:
	close(fd);
	بازگشت r;
}

صحیح
sshkey_load_private(ثابت نویسه *filename, ثابت نویسه *passphrase,
    ساختار sshkey **keyp, نویسه **commentp)
{
	بازگشت sshkey_load_private_type(کلید_UNSPEC, filename, passphrase,
	    keyp, commentp);
}

صحیح
sshkey_load_private_type_fd(صحیح fd, صحیح type, ثابت نویسه *passphrase,
    ساختار sshkey **keyp, نویسه **commentp)
{
	ساختار sshbuf *buffer = پوچ;
	صحیح r;

	اگر (keyp != پوچ)
		*keyp = پوچ;
	اگر ((r = sshbuf_load_fd(fd, &buffer)) != 0 ||
	    (r = sshkey_parse_private_fileblob_type(buffer, type,
	    passphrase, keyp, commentp)) != 0)
		برو out;

	/* success */
	r = 0;
 out:
	sshbuf_free(buffer);
	بازگشت r;
}

/* Load a pubkey from the unencrypted envelope of a new-format private key */
ایستا صحیح
sshkey_load_pubkey_from_private(ثابت نویسه *filename, ساختار sshkey **pubkeyp)
{
	ساختار sshbuf *buffer = پوچ;
	ساختار sshkey *pubkey = پوچ;
	صحیح r, fd;

	اگر (pubkeyp != پوچ)
		*pubkeyp = پوچ;

	اگر ((fd = open(filename, O_RDONLY)) == -1)
		بازگشت SSH_ERR_SYSTEM_ERROR;
	اگر ((r = sshbuf_load_fd(fd, &buffer)) != 0 ||
	    (r = sshkey_parse_pubkey_from_private_fileblob_type(buffer,
	    کلید_UNSPEC, &pubkey)) != 0)
		برو out;
	/* success */
	اگر (pubkeyp != پوچ) {
		*pubkeyp = pubkey;
		pubkey = پوچ;
	}
	r = 0;
 out:
	close(fd);
	sshbuf_free(buffer);
	sshkey_free(pubkey);
	بازگشت r;
}

ایستا صحیح
sshkey_try_load_public(ساختار sshkey **kp, ثابت نویسه *filename,
    نویسه **commentp)
{
	FILE *f;
	نویسه *سطر = پوچ, *cp;
	size_t linesize = 0;
	صحیح r;
	ساختار stat st;
	ساختار sshkey *k = پوچ;

	اگر (kp == پوچ)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	*kp = پوچ;
	اگر (commentp != پوچ)
		*commentp = پوچ;
	اگر ((f = fopen(filename, "r")) == پوچ)
		بازگشت SSH_ERR_SYSTEM_ERROR;
	اگر (fstat(fileno(f), &st) == 0 && S_ISREG(st.st_mode) &&
	    st.st_size > SSHBUF_SIZE_MAX) {
		fclose(f);
		بازگشت SSH_ERR_INVALID_FORMAT;
	}
	اگر ((k = sshkey_new(کلید_UNSPEC)) == پوچ) {
		fclose(f);
		بازگشت SSH_ERR_ALLOC_FAIL;
	}
	وقتی (getline(&سطر, &linesize, f) != -1) {
		cp = سطر;
		انتخاب (*cp) {
		حالت '#':
		حالت '\n':
		حالت '\0':
			ادامه;
		}
		/* Abort loading if this looks like a private key */
		اگر (strncmp(cp, "-----BEGIN", 10) == 0 ||
		    strcmp(cp, "SSH PRIVATE KEY FILE") == 0)
			بشکن;
		/* Skip leading whitespace. */
		برای (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;
		اگر (*cp) {
			اگر ((r = sshkey_read(k, &cp)) == 0) {
				cp[strcspn(cp, "\r\n")] = '\0';
				اگر (commentp) {
					*commentp = strdup(*cp ?
					    cp : filename);
					اگر (*commentp == پوچ)
						r = SSH_ERR_ALLOC_FAIL;
				}
				/* success */
				*kp = k;
				آزاد(سطر);
				fclose(f);
				بازگشت r;
			}
		}
	}
	آزاد(k);
	آزاد(سطر);
	fclose(f);
	بازگشت SSH_ERR_INVALID_FORMAT;
}

/* load public key from any pubkey file */
صحیح
sshkey_load_public(ثابت نویسه *filename, ساختار sshkey **keyp, نویسه **commentp)
{
	نویسه *pubfile = پوچ;
	صحیح r, oerrno;

	اگر (keyp != پوچ)
		*keyp = پوچ;
	اگر (commentp != پوچ)
		*commentp = پوچ;

	اگر ((r = sshkey_try_load_public(keyp, filename, commentp)) == 0)
		برو out;

	/* try .pub suffix */
	اگر (asprintf(&pubfile, "%s.pub", filename) == -1)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshkey_try_load_public(keyp, pubfile, commentp)) == 0)
		برو out;

	/* finally, try to extract public key from private key file */
	اگر ((r = sshkey_load_pubkey_from_private(filename, keyp)) == 0)
		برو out;

	/* Pretend we couldn't find the key */
	r = SSH_ERR_SYSTEM_ERROR;
	errno = ENOENT;

 out:
	oerrno = errno;
	آزاد(pubfile);
	errno = oerrno;
	بازگشت r;
}

/* Load the certificate associated with the named private key */
صحیح
sshkey_load_cert(ثابت نویسه *filename, ساختار sshkey **keyp)
{
	ساختار sshkey *pub = پوچ;
	نویسه *file = پوچ;
	صحیح r = SSH_ERR_INTERNAL_ERROR;

	اگر (keyp != پوچ)
		*keyp = پوچ;

	اگر (asprintf(&file, "%s-cert.pub", filename) == -1)
		بازگشت SSH_ERR_ALLOC_FAIL;

	r = sshkey_try_load_public(keyp, file, پوچ);
	آزاد(file);
	sshkey_free(pub);
	بازگشت r;
}

/* Load private key and certificate */
صحیح
sshkey_load_private_cert(صحیح type, ثابت نویسه *filename, ثابت نویسه *passphrase,
    ساختار sshkey **keyp)
{
	ساختار sshkey *کلید = پوچ, *cert = پوچ;
	صحیح r;

	اگر (keyp != پوچ)
		*keyp = پوچ;

	انتخاب (type) {
#ifdef WITH_OPENSSL
	حالت کلید_RSA:
	حالت کلید_ECDSA:
#endif /* WITH_OPENSSL */
	حالت کلید_ED25519:
	حالت کلید_MLDSA44_ED25519:
	حالت کلید_UNSPEC:
		بشکن;
	پیشفرض:
		بازگشت SSH_ERR_کلید_TYPE_UNKNOWN;
	}

	اگر ((r = sshkey_load_private_type(type, filename,
	    passphrase, &کلید, پوچ)) != 0 ||
	    (r = sshkey_load_cert(filename, &cert)) != 0)
		برو out;

	/* Make sure the private key matches the certificate */
	اگر (sshkey_equal_public(کلید, cert) == 0) {
		r = SSH_ERR_کلید_CERT_MISMATCH;
		برو out;
	}

	اگر ((r = sshkey_to_certified(کلید)) != 0 ||
	    (r = sshkey_cert_copy(cert, کلید)) != 0)
		برو out;
	r = 0;
	اگر (keyp != پوچ) {
		*keyp = کلید;
		کلید = پوچ;
	}
 out:
	sshkey_free(کلید);
	sshkey_free(cert);
	بازگشت r;
}

/*
 * Returns success if the specified "key" is listed in the file "filename",
 * SSH_ERR_KEY_NOT_FOUND: if the key is not listed or another error.
 * If "strict_type" is set then the key type must match exactly,
 * otherwise a comparison that ignores certificate data is performed.
 * If "check_ca" is set and "key" is a certificate, then its CA key is
 * also checked and sshkey_in_file() will return success if either is found.
 */
صحیح
sshkey_in_file(ساختار sshkey *کلید, ثابت نویسه *filename, صحیح strict_type,
    صحیح check_ca)
{
	FILE *f;
	نویسه *سطر = پوچ, *cp;
	size_t linesize = 0;
	صحیح r = 0;
	ساختار sshkey *pub = پوچ;

	صحیح (*sshkey_compare)(ثابت ساختار sshkey *, ثابت ساختار sshkey *) =
	    strict_type ?  sshkey_equal : sshkey_equal_public;

	اگر ((f = fopen(filename, "r")) == پوچ)
		بازگشت SSH_ERR_SYSTEM_ERROR;

	وقتی (getline(&سطر, &linesize, f) != -1) {
		sshkey_free(pub);
		pub = پوچ;
		cp = سطر;

		/* Skip leading whitespace. */
		برای (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;

		/* Skip comments and empty lines */
		انتخاب (*cp) {
		حالت '#':
		حالت '\n':
		حالت '\0':
			ادامه;
		}

		اگر ((pub = sshkey_new(کلید_UNSPEC)) == پوچ) {
			r = SSH_ERR_ALLOC_FAIL;
			برو out;
		}
		انتخاب (r = sshkey_read(pub, &cp)) {
		حالت 0:
			بشکن;
		حالت SSH_ERR_کلید_LENGTH:
			ادامه;
		پیشفرض:
			برو out;
		}
		اگر (sshkey_compare(کلید, pub) ||
		    (check_ca && sshkey_is_cert(کلید) &&
		    sshkey_compare(کلید->cert->signature_کلید, pub))) {
			r = 0;
			برو out;
		}
	}
	r = SSH_ERR_کلید_NOT_FOUND;
 out:
	آزاد(سطر);
	sshkey_free(pub);
	fclose(f);
	بازگشت r;
}

/*
 * Checks whether the specified key is revoked, returning 0 if not,
 * SSH_ERR_KEY_REVOKED if it is or another error code if something
 * unexpected happened.
 * This will check both the key and, if it is a certificate, its CA key too.
 * "revoked_keys_file" may be a KRL or a one-per-line list of public keys.
 */
صحیح
sshkey_check_revoked(ساختار sshkey *کلید, ثابت نویسه *revoked_کلیدها_file)
{
	صحیح r;

	r = ssh_krl_file_contains_کلید(revoked_کلیدها_file, کلید);
	/* If this was not a KRL to begin with then continue below */
	اگر (r != SSH_ERR_KRL_BAD_MAGIC)
		بازگشت r;

	/*
	 * If the file is not a KRL or we can't handle KRLs then attempt to
	 * parse the file as a flat list of keys.
	 */
	انتخاب ((r = sshkey_in_file(کلید, revoked_کلیدها_file, 0, 1))) {
	حالت 0:
		/* Key found => revoked */
		بازگشت SSH_ERR_کلید_REVOKED;
	حالت SSH_ERR_کلید_NOT_FOUND:
		/* Key not found => not revoked */
		بازگشت 0;
	پیشفرض:
		/* Some other error occurred */
		بازگشت r;
	}
}

/*
 * Advanced *cpp past the end of key options, defined as the first unquoted
 * whitespace character. Returns 0 on success or -1 on failure (e.g.
 * unterminated quotes).
 */
صحیح
sshkey_advance_past_options(نویسه **cpp)
{
	نویسه *cp = *cpp;
	صحیح quoted = 0;

	برای (; *cp && (quoted || (*cp != ' ' && *cp != '\t')); cp++) {
		اگر (*cp == '\\' && cp[1] == '"')
			cp++;	/* Skip both */
		وگرنه اگر (*cp == '"')
			quoted = !quoted;
	}
	*cpp = cp;
	/* return failure for unterminated quotes */
	بازگشت (*cp == '\0' && quoted) ? -1 : 0;
}

/* Save a public key */
صحیح
sshkey_save_public(ثابت ساختار sshkey *کلید, ثابت نویسه *path,
    ثابت نویسه *comment)
{
	صحیح fd, oerrno;
	FILE *f = پوچ;
	صحیح r = SSH_ERR_INTERNAL_ERROR;

	اگر ((fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, 0644)) == -1)
		بازگشت SSH_ERR_SYSTEM_ERROR;
	اگر ((f = fdopen(fd, "w")) == پوچ) {
		r = SSH_ERR_SYSTEM_ERROR;
		close(fd);
		برو fail;
	}
	اگر ((r = sshkey_write(کلید, f)) != 0)
		برو fail;
	fprintf(f, " %s\n", comment);
	اگر (ferror(f)) {
		r = SSH_ERR_SYSTEM_ERROR;
		برو fail;
	}
	اگر (fclose(f) != 0) {
		r = SSH_ERR_SYSTEM_ERROR;
		f = پوچ;
 fail:
		اگر (f != پوچ) {
			oerrno = errno;
			fclose(f);
			errno = oerrno;
		}
		بازگشت r;
	}
	بازگشت 0;
}
