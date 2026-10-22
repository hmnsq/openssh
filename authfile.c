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
sshkey_save_خصوصی_blob(بنية sshbuf *keybuf, ثابت حرف *filename)
{
	صحيح r;
	نما_t omask;

	omask = umask(077);
	r = sshbuf_write_file(filename, keybuf);
	umask(omask);
	أرجع r;
}

صحيح
sshkey_save_خصوصی(بنية sshkey *کلید, ثابت حرف *filename,
    ثابت حرف *passphrase, ثابت حرف *comment,
    صحيح format, ثابت حرف *openssh_format_cipher, صحيح openssh_format_دورها)
{
	بنية sshbuf *keyblob = عدم;
	صحيح r;

	إذا ((keyblob = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshkey_خصوصی_مقصد_fileblob(کلید, keyblob, passphrase, comment,
	    format, openssh_format_cipher, openssh_format_دورها)) != 0)
		اذهب بیرون;
	إذا ((r = sshkey_save_خصوصی_blob(keyblob, filename)) != 0)
		اذهب بیرون;
	r = 0;
 بیرون:
	sshbuf_free(keyblob);
	أرجع r;
}

/* XXX remove error() calls from here? */
صحيح
sshkey_perm_ok(صحيح fd, ثابت حرف *filename)
{
	بنية stat st;

	إذا (fstat(fd, &st) == -1)
		أرجع SSH_ERR_SYSTEM_ERROR;
	/*
	 * if a key owned by the user is accessed, then we check the
	 * permissions of the file. if the key owned by a different user,
	 * then we don't care.
	 */
#اگر_تعریف_شده HAVE_CYGWIN
	إذا (check_ntsec(filename))
#پایان_اگر
	إذا ((st.st_uid == getuid()) && (st.st_mode & 077) != 0) {
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @");
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("Permissions 0%3.3o for '%s' are too open.",
		    (u_int)st.st_mode & 0777, filename);
		error("It is required that your private key files are NOT accessible by others.");
		error("This private key will be ignored.");
		أرجع SSH_ERR_کلید_BAD_PERMISSIONS;
	}
	أرجع 0;
}

صحيح
sshkey_بارگیری_خصوصی_type(صحيح type, ثابت حرف *filename, ثابت حرف *passphrase,
    بنية sshkey **keyp, حرف **commentp)
{
	صحيح fd, r;

	إذا (keyp != عدم)
		*keyp = عدم;
	إذا (commentp != عدم)
		*commentp = عدم;

	إذا ((fd = open(filename, O_RDONLY)) == -1)
		أرجع SSH_ERR_SYSTEM_ERROR;

	r = sshkey_perm_ok(fd, filename);
	إذا (r != 0)
		اذهب بیرون;

	r = sshkey_بارگیری_خصوصی_type_fd(fd, type, passphrase, keyp, commentp);
 بیرون:
	close(fd);
	أرجع r;
}

صحيح
sshkey_بارگیری_خصوصی(ثابت حرف *filename, ثابت حرف *passphrase,
    بنية sshkey **keyp, حرف **commentp)
{
	أرجع sshkey_بارگیری_خصوصی_type(کلید_UNSPEC, filename, passphrase,
	    keyp, commentp);
}

صحيح
sshkey_بارگیری_خصوصی_type_fd(صحيح fd, صحيح type, ثابت حرف *passphrase,
    بنية sshkey **keyp, حرف **commentp)
{
	بنية sshbuf *میانگیر = عدم;
	صحيح r;

	إذا (keyp != عدم)
		*keyp = عدم;
	إذا ((r = sshbuf_بارگیری_fd(fd, &میانگیر)) != 0 ||
	    (r = sshkey_parse_خصوصی_fileblob_type(میانگیر, type,
	    passphrase, keyp, commentp)) != 0)
		اذهب بیرون;

	/* success */
	r = 0;
 بیرون:
	sshbuf_free(میانگیر);
	أرجع r;
}

/* Load a pubkey from the unencrypted envelope of a new-format private key */
ساكن صحيح
sshkey_بارگیری_pubkey_from_خصوصی(ثابت حرف *filename, بنية sshkey **pubkeyp)
{
	بنية sshbuf *میانگیر = عدم;
	بنية sshkey *pubkey = عدم;
	صحيح r, fd;

	إذا (pubkeyp != عدم)
		*pubkeyp = عدم;

	إذا ((fd = open(filename, O_RDONLY)) == -1)
		أرجع SSH_ERR_SYSTEM_ERROR;
	إذا ((r = sshbuf_بارگیری_fd(fd, &میانگیر)) != 0 ||
	    (r = sshkey_parse_pubkey_from_خصوصی_fileblob_type(میانگیر,
	    کلید_UNSPEC, &pubkey)) != 0)
		اذهب بیرون;
	/* success */
	إذا (pubkeyp != عدم) {
		*pubkeyp = pubkey;
		pubkey = عدم;
	}
	r = 0;
 بیرون:
	close(fd);
	sshbuf_free(میانگیر);
	sshkey_free(pubkey);
	أرجع r;
}

ساكن صحيح
sshkey_try_بارگیری_عمومی(بنية sshkey **kp, ثابت حرف *filename,
    حرف **commentp)
{
	FILE *f;
	حرف *سطر = عدم, *cp;
	اندازه_t linesize = 0;
	صحيح r;
	بنية stat st;
	بنية sshkey *k = عدم;

	إذا (kp == عدم)
		أرجع SSH_ERR_INVALID_آرگومان;
	*kp = عدم;
	إذا (commentp != عدم)
		*commentp = عدم;
	إذا ((f = fopen(filename, "r")) == عدم)
		أرجع SSH_ERR_SYSTEM_ERROR;
	إذا (fstat(fileno(f), &st) == 0 && S_ISREG(st.st_mode) &&
	    st.st_size > SSHBUF_اندازه_MAX) {
		fclose(f);
		أرجع SSH_ERR_INVALID_FORMAT;
	}
	إذا ((k = sshkey_new(کلید_UNSPEC)) == عدم) {
		fclose(f);
		أرجع SSH_ERR_ALLOC_FAIL;
	}
	طالما (getline(&سطر, &linesize, f) != -1) {
		cp = سطر;
		بدل (*cp) {
		حالة '#':
		حالة '\n':
		حالة '\0':
			استمر;
		}
		/* Abort loading if this looks like a private key */
		إذا (مقایسه_رشته(cp, "-----BEGIN", 10) == 0 ||
		    strcmp(cp, "SSH PRIVATE KEY FILE") == 0)
			اكسر;
		/* Skip leading whitespace. */
		لكل (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;
		إذا (*cp) {
			إذا ((r = sshkey_read(k, &cp)) == 0) {
				cp[strcspn(cp, "\r\n")] = '\0';
				إذا (commentp) {
					*commentp = strdup(*cp ?
					    cp : filename);
					إذا (*commentp == عدم)
						r = SSH_ERR_ALLOC_FAIL;
				}
				/* success */
				*kp = k;
				حرر(سطر);
				fclose(f);
				أرجع r;
			}
		}
	}
	حرر(k);
	حرر(سطر);
	fclose(f);
	أرجع SSH_ERR_INVALID_FORMAT;
}

/* load public key from any pubkey file */
صحيح
sshkey_بارگیری_عمومی(ثابت حرف *filename, بنية sshkey **keyp, حرف **commentp)
{
	حرف *pubfile = عدم;
	صحيح r, oerrno;

	إذا (keyp != عدم)
		*keyp = عدم;
	إذا (commentp != عدم)
		*commentp = عدم;

	إذا ((r = sshkey_try_بارگیری_عمومی(keyp, filename, commentp)) == 0)
		اذهب بیرون;

	/* try .pub suffix */
	إذا (asprintf(&pubfile, "%s.pub", filename) == -1)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshkey_try_بارگیری_عمومی(keyp, pubfile, commentp)) == 0)
		اذهب بیرون;

	/* finally, try to extract public key from private key file */
	إذا ((r = sshkey_بارگیری_pubkey_from_خصوصی(filename, keyp)) == 0)
		اذهب بیرون;

	/* Pretend we couldn't find the key */
	r = SSH_ERR_SYSTEM_ERROR;
	errno = ENOENT;

 بیرون:
	oerrno = errno;
	حرر(pubfile);
	errno = oerrno;
	أرجع r;
}

/* Load the certificate associated with the named private key */
صحيح
sshkey_بارگیری_cert(ثابت حرف *filename, بنية sshkey **keyp)
{
	بنية sshkey *pub = عدم;
	حرف *file = عدم;
	صحيح r = SSH_ERR_داخلی_ERROR;

	إذا (keyp != عدم)
		*keyp = عدم;

	إذا (asprintf(&file, "%s-cert.pub", filename) == -1)
		أرجع SSH_ERR_ALLOC_FAIL;

	r = sshkey_try_بارگیری_عمومی(keyp, file, عدم);
	حرر(file);
	sshkey_free(pub);
	أرجع r;
}

/* Load private key and certificate */
صحيح
sshkey_بارگیری_خصوصی_cert(صحيح type, ثابت حرف *filename, ثابت حرف *passphrase,
    بنية sshkey **keyp)
{
	بنية sshkey *کلید = عدم, *cert = عدم;
	صحيح r;

	إذا (keyp != عدم)
		*keyp = عدم;

	بدل (type) {
#اگر_تعریف_شده WITH_OPENSSL
	حالة کلید_RSA:
	حالة کلید_ECDSA:
#پایان_اگر /* WITH_OPENSSL */
	حالة کلید_ED25519:
	حالة کلید_MLDSA44_ED25519:
	حالة کلید_UNSPEC:
		اكسر;
	افتراضي:
		أرجع SSH_ERR_کلید_TYPE_UNKNOWN;
	}

	إذا ((r = sshkey_بارگیری_خصوصی_type(type, filename,
	    passphrase, &کلید, عدم)) != 0 ||
	    (r = sshkey_بارگیری_cert(filename, &cert)) != 0)
		اذهب بیرون;

	/* Make sure the private key matches the certificate */
	إذا (sshkey_equal_عمومی(کلید, cert) == 0) {
		r = SSH_ERR_کلید_CERT_MISMATCH;
		اذهب بیرون;
	}

	إذا ((r = sshkey_مقصد_certified(کلید)) != 0 ||
	    (r = sshkey_cert_copy(cert, کلید)) != 0)
		اذهب بیرون;
	r = 0;
	إذا (keyp != عدم) {
		*keyp = کلید;
		کلید = عدم;
	}
 بیرون:
	sshkey_free(کلید);
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
sshkey_درون_file(بنية sshkey *کلید, ثابت حرف *filename, صحيح strict_type,
    صحيح check_ca)
{
	FILE *f;
	حرف *سطر = عدم, *cp;
	اندازه_t linesize = 0;
	صحيح r = 0;
	بنية sshkey *pub = عدم;

	صحيح (*sshkey_compare)(ثابت بنية sshkey *, ثابت بنية sshkey *) =
	    strict_type ?  sshkey_equal : sshkey_equal_عمومی;

	إذا ((f = fopen(filename, "r")) == عدم)
		أرجع SSH_ERR_SYSTEM_ERROR;

	طالما (getline(&سطر, &linesize, f) != -1) {
		sshkey_free(pub);
		pub = عدم;
		cp = سطر;

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

		إذا ((pub = sshkey_new(کلید_UNSPEC)) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب بیرون;
		}
		بدل (r = sshkey_read(pub, &cp)) {
		حالة 0:
			اكسر;
		حالة SSH_ERR_کلید_درازی:
			استمر;
		افتراضي:
			اذهب بیرون;
		}
		إذا (sshkey_compare(کلید, pub) ||
		    (check_ca && sshkey_is_cert(کلید) &&
		    sshkey_compare(کلید->cert->signature_کلید, pub))) {
			r = 0;
			اذهب بیرون;
		}
	}
	r = SSH_ERR_کلید_NOT_یافت;
 بیرون:
	حرر(سطر);
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
sshkey_check_revoked(بنية sshkey *کلید, ثابت حرف *revoked_کلیدها_file)
{
	صحيح r;

	r = ssh_krl_file_شامل_است_کلید(revoked_کلیدها_file, کلید);
	/* If this was not a KRL to begin with then continue below */
	إذا (r != SSH_ERR_KRL_BAD_MAGIC)
		أرجع r;

	/*
	 * If the file is not a KRL or we can't handle KRLs then attempt to
	 * parse the file as a flat list of keys.
	 */
	بدل ((r = sshkey_درون_file(کلید, revoked_کلیدها_file, 0, 1))) {
	حالة 0:
		/* Key found => revoked */
		أرجع SSH_ERR_کلید_REVOKED;
	حالة SSH_ERR_کلید_NOT_یافت:
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
		إذا (*cp == '\\' && cp[1] == '"')
			cp++;	/* Skip both */
		وإلا إذا (*cp == '"')
			quoted = !quoted;
	}
	*cpp = cp;
	/* return failure for unterminated quotes */
	أرجع (*cp == '\0' && quoted) ? -1 : 0;
}

/* Save a public key */
صحيح
sshkey_save_عمومی(ثابت بنية sshkey *کلید, ثابت حرف *مسیر,
    ثابت حرف *comment)
{
	صحيح fd, oerrno;
	FILE *f = عدم;
	صحيح r = SSH_ERR_داخلی_ERROR;

	إذا ((fd = open(مسیر, O_WRONLY|O_CREAT|O_TRUNC, 0644)) == -1)
		أرجع SSH_ERR_SYSTEM_ERROR;
	إذا ((f = fdopen(fd, "w")) == عدم) {
		r = SSH_ERR_SYSTEM_ERROR;
		close(fd);
		اذهب fail;
	}
	إذا ((r = sshkey_write(کلید, f)) != 0)
		اذهب fail;
	fprintf(f, " %s\n", comment);
	إذا (ferror(f)) {
		r = SSH_ERR_SYSTEM_ERROR;
		اذهب fail;
	}
	إذا (fclose(f) != 0) {
		r = SSH_ERR_SYSTEM_ERROR;
		f = عدم;
 fail:
		إذا (f != عدم) {
			oerrno = errno;
			fclose(f);
			errno = oerrno;
		}
		أرجع r;
	}
	أرجع 0;
}
