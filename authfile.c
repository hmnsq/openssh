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
sshkey_save_ذاتي_blob(بنية sshbuf *keybuf, ثابت حرف *filename)
{
	صحيح r;
	گهڻائي_t omask;

	omask = umask(077);
	r = sshbuf_write_file(filename, keybuf);
	umask(omask);
	أرجع r;
}

صحيح
sshkey_save_ذاتي(بنية sshkey *ڪنجي, ثابت حرف *filename,
    ثابت حرف *passphrase, ثابت حرف *comment,
    صحيح format, ثابت حرف *openssh_format_cipher, صحيح openssh_format_ڦيرا)
{
	بنية sshbuf *keyblob = عدم;
	صحيح r;

	إذا ((keyblob = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshkey_ذاتي_منزل_fileblob(ڪنجي, keyblob, passphrase, comment,
	    format, openssh_format_cipher, openssh_format_ڦيرا)) != 0)
		اذهب ٻاهريون;
	إذا ((r = sshkey_save_ذاتي_blob(keyblob, filename)) != 0)
		اذهب ٻاهريون;
	r = 0;
 ٻاهريون:
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
#جيڪڏهن_وصف_ٿيل HAVE_CYGWIN
	إذا (check_ntsec(filename))
#جيڪڏهن_پورو
	إذا ((st.st_uid == getuid()) && (st.st_mode & 077) != 0) {
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @");
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("Permissions 0%3.3o for '%s' are too open.",
		    (u_int)st.st_mode & 0777, filename);
		error("It is required that your private key files are NOT accessible by others.");
		error("This private key will be ignored.");
		أرجع SSH_ERR_ڪنجي_BAD_PERMISSIONS;
	}
	أرجع 0;
}

صحيح
sshkey_ڀريو_ذاتي_type(صحيح type, ثابت حرف *filename, ثابت حرف *passphrase,
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
		اذهب ٻاهريون;

	r = sshkey_ڀريو_ذاتي_type_fd(fd, type, passphrase, keyp, commentp);
 ٻاهريون:
	close(fd);
	أرجع r;
}

صحيح
sshkey_ڀريو_ذاتي(ثابت حرف *filename, ثابت حرف *passphrase,
    بنية sshkey **keyp, حرف **commentp)
{
	أرجع sshkey_ڀريو_ذاتي_type(ڪنجي_UNSPEC, filename, passphrase,
	    keyp, commentp);
}

صحيح
sshkey_ڀريو_ذاتي_type_fd(صحيح fd, صحيح type, ثابت حرف *passphrase,
    بنية sshkey **keyp, حرف **commentp)
{
	بنية sshbuf *بفر = عدم;
	صحيح r;

	إذا (keyp != عدم)
		*keyp = عدم;
	إذا ((r = sshbuf_ڀريو_fd(fd, &بفر)) != 0 ||
	    (r = sshkey_parse_ذاتي_fileblob_type(بفر, type,
	    passphrase, keyp, commentp)) != 0)
		اذهب ٻاهريون;

	/* success */
	r = 0;
 ٻاهريون:
	sshbuf_free(بفر);
	أرجع r;
}

/* Load a pubkey from the unencrypted envelope of a new-format private key */
ساكن صحيح
sshkey_ڀريو_pubkey_from_ذاتي(ثابت حرف *filename, بنية sshkey **pubkeyp)
{
	بنية sshbuf *بفر = عدم;
	بنية sshkey *pubkey = عدم;
	صحيح r, fd;

	إذا (pubkeyp != عدم)
		*pubkeyp = عدم;

	إذا ((fd = open(filename, O_RDONLY)) == -1)
		أرجع SSH_ERR_SYSTEM_ERROR;
	إذا ((r = sshbuf_ڀريو_fd(fd, &بفر)) != 0 ||
	    (r = sshkey_parse_pubkey_from_ذاتي_fileblob_type(بفر,
	    ڪنجي_UNSPEC, &pubkey)) != 0)
		اذهب ٻاهريون;
	/* success */
	إذا (pubkeyp != عدم) {
		*pubkeyp = pubkey;
		pubkey = عدم;
	}
	r = 0;
 ٻاهريون:
	close(fd);
	sshbuf_free(بفر);
	sshkey_free(pubkey);
	أرجع r;
}

ساكن صحيح
sshkey_try_ڀريو_عوامي(بنية sshkey **kp, ثابت حرف *filename,
    حرف **commentp)
{
	FILE *f;
	حرف *سٽ = عدم, *cp;
	سائيز_t linesize = 0;
	صحيح r;
	بنية stat st;
	بنية sshkey *k = عدم;

	إذا (kp == عدم)
		أرجع SSH_ERR_INVALID_دليل;
	*kp = عدم;
	إذا (commentp != عدم)
		*commentp = عدم;
	إذا ((f = fopen(filename, "r")) == عدم)
		أرجع SSH_ERR_SYSTEM_ERROR;
	إذا (fstat(fileno(f), &st) == 0 && S_ISREG(st.st_mode) &&
	    st.st_size > SSHBUF_سائيز_MAX) {
		fclose(f);
		أرجع SSH_ERR_INVALID_FORMAT;
	}
	إذا ((k = sshkey_new(ڪنجي_UNSPEC)) == عدم) {
		fclose(f);
		أرجع SSH_ERR_ALLOC_FAIL;
	}
	طالما (getline(&سٽ, &linesize, f) != -1) {
		cp = سٽ;
		بدل (*cp) {
		حالة '#':
		حالة '\n':
		حالة '\0':
			استمر;
		}
		/* Abort loading if this looks like a private key */
		إذا (لڙي_ڀيٽ(cp, "-----BEGIN", 10) == 0 ||
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
				حرر(سٽ);
				fclose(f);
				أرجع r;
			}
		}
	}
	حرر(k);
	حرر(سٽ);
	fclose(f);
	أرجع SSH_ERR_INVALID_FORMAT;
}

/* load public key from any pubkey file */
صحيح
sshkey_ڀريو_عوامي(ثابت حرف *filename, بنية sshkey **keyp, حرف **commentp)
{
	حرف *pubfile = عدم;
	صحيح r, oerrno;

	إذا (keyp != عدم)
		*keyp = عدم;
	إذا (commentp != عدم)
		*commentp = عدم;

	إذا ((r = sshkey_try_ڀريو_عوامي(keyp, filename, commentp)) == 0)
		اذهب ٻاهريون;

	/* try .pub suffix */
	إذا (asprintf(&pubfile, "%s.pub", filename) == -1)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshkey_try_ڀريو_عوامي(keyp, pubfile, commentp)) == 0)
		اذهب ٻاهريون;

	/* finally, try to extract public key from private key file */
	إذا ((r = sshkey_ڀريو_pubkey_from_ذاتي(filename, keyp)) == 0)
		اذهب ٻاهريون;

	/* Pretend we couldn't find the key */
	r = SSH_ERR_SYSTEM_ERROR;
	errno = ENOENT;

 ٻاهريون:
	oerrno = errno;
	حرر(pubfile);
	errno = oerrno;
	أرجع r;
}

/* Load the certificate associated with the named private key */
صحيح
sshkey_ڀريو_cert(ثابت حرف *filename, بنية sshkey **keyp)
{
	بنية sshkey *pub = عدم;
	حرف *file = عدم;
	صحيح r = SSH_ERR_اندروني_ERROR;

	إذا (keyp != عدم)
		*keyp = عدم;

	إذا (asprintf(&file, "%s-cert.pub", filename) == -1)
		أرجع SSH_ERR_ALLOC_FAIL;

	r = sshkey_try_ڀريو_عوامي(keyp, file, عدم);
	حرر(file);
	sshkey_free(pub);
	أرجع r;
}

/* Load private key and certificate */
صحيح
sshkey_ڀريو_ذاتي_cert(صحيح type, ثابت حرف *filename, ثابت حرف *passphrase,
    بنية sshkey **keyp)
{
	بنية sshkey *ڪنجي = عدم, *cert = عدم;
	صحيح r;

	إذا (keyp != عدم)
		*keyp = عدم;

	بدل (type) {
#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
	حالة ڪنجي_RSA:
	حالة ڪنجي_ECDSA:
#جيڪڏهن_پورو /* WITH_OPENSSL */
	حالة ڪنجي_ED25519:
	حالة ڪنجي_MLDSA44_ED25519:
	حالة ڪنجي_UNSPEC:
		اكسر;
	افتراضي:
		أرجع SSH_ERR_ڪنجي_TYPE_UNKNOWN;
	}

	إذا ((r = sshkey_ڀريو_ذاتي_type(type, filename,
	    passphrase, &ڪنجي, عدم)) != 0 ||
	    (r = sshkey_ڀريو_cert(filename, &cert)) != 0)
		اذهب ٻاهريون;

	/* Make sure the private key matches the certificate */
	إذا (sshkey_equal_عوامي(ڪنجي, cert) == 0) {
		r = SSH_ERR_ڪنجي_CERT_MISMATCH;
		اذهب ٻاهريون;
	}

	إذا ((r = sshkey_منزل_certified(ڪنجي)) != 0 ||
	    (r = sshkey_cert_copy(cert, ڪنجي)) != 0)
		اذهب ٻاهريون;
	r = 0;
	إذا (keyp != عدم) {
		*keyp = ڪنجي;
		ڪنجي = عدم;
	}
 ٻاهريون:
	sshkey_free(ڪنجي);
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
sshkey_اندريون_file(بنية sshkey *ڪنجي, ثابت حرف *filename, صحيح strict_type,
    صحيح check_ca)
{
	FILE *f;
	حرف *سٽ = عدم, *cp;
	سائيز_t linesize = 0;
	صحيح r = 0;
	بنية sshkey *pub = عدم;

	صحيح (*sshkey_compare)(ثابت بنية sshkey *, ثابت بنية sshkey *) =
	    strict_type ?  sshkey_equal : sshkey_equal_عوامي;

	إذا ((f = fopen(filename, "r")) == عدم)
		أرجع SSH_ERR_SYSTEM_ERROR;

	طالما (getline(&سٽ, &linesize, f) != -1) {
		sshkey_free(pub);
		pub = عدم;
		cp = سٽ;

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

		إذا ((pub = sshkey_new(ڪنجي_UNSPEC)) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب ٻاهريون;
		}
		بدل (r = sshkey_read(pub, &cp)) {
		حالة 0:
			اكسر;
		حالة SSH_ERR_ڪنجي_ڊيگهائي:
			استمر;
		افتراضي:
			اذهب ٻاهريون;
		}
		إذا (sshkey_compare(ڪنجي, pub) ||
		    (check_ca && sshkey_is_cert(ڪنجي) &&
		    sshkey_compare(ڪنجي->cert->signature_ڪنجي, pub))) {
			r = 0;
			اذهب ٻاهريون;
		}
	}
	r = SSH_ERR_ڪنجي_NOT_مليو;
 ٻاهريون:
	حرر(سٽ);
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
sshkey_check_revoked(بنية sshkey *ڪنجي, ثابت حرف *revoked_ڪنجيون_file)
{
	صحيح r;

	r = ssh_krl_file_شامل_آهي_ڪنجي(revoked_ڪنجيون_file, ڪنجي);
	/* If this was not a KRL to begin with then continue below */
	إذا (r != SSH_ERR_KRL_BAD_MAGIC)
		أرجع r;

	/*
	 * If the file is not a KRL or we can't handle KRLs then attempt to
	 * parse the file as a flat list of keys.
	 */
	بدل ((r = sshkey_اندريون_file(ڪنجي, revoked_ڪنجيون_file, 0, 1))) {
	حالة 0:
		/* Key found => revoked */
		أرجع SSH_ERR_ڪنجي_REVOKED;
	حالة SSH_ERR_ڪنجي_NOT_مليو:
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
sshkey_save_عوامي(ثابت بنية sshkey *ڪنجي, ثابت حرف *رستو,
    ثابت حرف *comment)
{
	صحيح fd, oerrno;
	FILE *f = عدم;
	صحيح r = SSH_ERR_اندروني_ERROR;

	إذا ((fd = open(رستو, O_WRONLY|O_CREAT|O_TRUNC, 0644)) == -1)
		أرجع SSH_ERR_SYSTEM_ERROR;
	إذا ((f = fdopen(fd, "w")) == عدم) {
		r = SSH_ERR_SYSTEM_ERROR;
		close(fd);
		اذهب fail;
	}
	إذا ((r = sshkey_write(ڪنجي, f)) != 0)
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
