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
sshkey_save_شخصي_blob(بنية sshbuf *keybuf, ثابت حرف *filename)
{
	صحيح r;
	ډېرپېښ_t omask;

	omask = umask(077);
	r = sshbuf_write_file(filename, keybuf);
	umask(omask);
	أرجع r;
}

صحيح
sshkey_save_شخصي(بنية sshkey *کلی, ثابت حرف *filename,
    ثابت حرف *passphrase, ثابت حرف *comment,
    صحيح format, ثابت حرف *openssh_format_cipher, صحيح openssh_format_پړاوونه)
{
	بنية sshbuf *keyblob = عدم;
	صحيح r;

	إذا ((keyblob = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshkey_شخصي_منزل_fileblob(کلی, keyblob, passphrase, comment,
	    format, openssh_format_cipher, openssh_format_پړاوونه)) != 0)
		اذهب بهر;
	إذا ((r = sshkey_save_شخصي_blob(keyblob, filename)) != 0)
		اذهب بهر;
	r = 0;
 بهر:
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
#که_تعریف_شوی HAVE_CYGWIN
	إذا (check_ntsec(filename))
#د_که_پای
	إذا ((st.st_uid == getuid()) && (st.st_mode & 077) != 0) {
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @");
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("Permissions 0%3.3o for '%s' are too open.",
		    (u_int)st.st_mode & 0777, filename);
		error("It is required that your private key files are NOT accessible by others.");
		error("This private key will be ignored.");
		أرجع SSH_ERR_کلی_BAD_PERMISSIONS;
	}
	أرجع 0;
}

صحيح
sshkey_بارول_شخصي_type(صحيح type, ثابت حرف *filename, ثابت حرف *passphrase,
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
		اذهب بهر;

	r = sshkey_بارول_شخصي_type_fd(fd, type, passphrase, keyp, commentp);
 بهر:
	close(fd);
	أرجع r;
}

صحيح
sshkey_بارول_شخصي(ثابت حرف *filename, ثابت حرف *passphrase,
    بنية sshkey **keyp, حرف **commentp)
{
	أرجع sshkey_بارول_شخصي_type(کلی_UNSPEC, filename, passphrase,
	    keyp, commentp);
}

صحيح
sshkey_بارول_شخصي_type_fd(صحيح fd, صحيح type, ثابت حرف *passphrase,
    بنية sshkey **keyp, حرف **commentp)
{
	بنية sshbuf *بفر = عدم;
	صحيح r;

	إذا (keyp != عدم)
		*keyp = عدم;
	إذا ((r = sshbuf_بارول_fd(fd, &بفر)) != 0 ||
	    (r = sshkey_parse_شخصي_fileblob_type(بفر, type,
	    passphrase, keyp, commentp)) != 0)
		اذهب بهر;

	/* success */
	r = 0;
 بهر:
	sshbuf_free(بفر);
	أرجع r;
}

/* Load a pubkey from the unencrypted envelope of a new-format private key */
ساكن صحيح
sshkey_بارول_pubkey_from_شخصي(ثابت حرف *filename, بنية sshkey **pubkeyp)
{
	بنية sshbuf *بفر = عدم;
	بنية sshkey *pubkey = عدم;
	صحيح r, fd;

	إذا (pubkeyp != عدم)
		*pubkeyp = عدم;

	إذا ((fd = open(filename, O_RDONLY)) == -1)
		أرجع SSH_ERR_SYSTEM_ERROR;
	إذا ((r = sshbuf_بارول_fd(fd, &بفر)) != 0 ||
	    (r = sshkey_parse_pubkey_from_شخصي_fileblob_type(بفر,
	    کلی_UNSPEC, &pubkey)) != 0)
		اذهب بهر;
	/* success */
	إذا (pubkeyp != عدم) {
		*pubkeyp = pubkey;
		pubkey = عدم;
	}
	r = 0;
 بهر:
	close(fd);
	sshbuf_free(بفر);
	sshkey_free(pubkey);
	أرجع r;
}

ساكن صحيح
sshkey_try_بارول_عامه(بنية sshkey **kp, ثابت حرف *filename,
    حرف **commentp)
{
	FILE *f;
	حرف *کرښه = عدم, *cp;
	اندازه_t linesize = 0;
	صحيح r;
	بنية stat st;
	بنية sshkey *k = عدم;

	إذا (kp == عدم)
		أرجع SSH_ERR_INVALID_دلیل;
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
	إذا ((k = sshkey_new(کلی_UNSPEC)) == عدم) {
		fclose(f);
		أرجع SSH_ERR_ALLOC_FAIL;
	}
	طالما (getline(&کرښه, &linesize, f) != -1) {
		cp = کرښه;
		بدل (*cp) {
		حالة '#':
		حالة '\n':
		حالة '\0':
			استمر;
		}
		/* Abort loading if this looks like a private key */
		إذا (مزي_پرتله(cp, "-----BEGIN", 10) == 0 ||
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
				حرر(کرښه);
				fclose(f);
				أرجع r;
			}
		}
	}
	حرر(k);
	حرر(کرښه);
	fclose(f);
	أرجع SSH_ERR_INVALID_FORMAT;
}

/* load public key from any pubkey file */
صحيح
sshkey_بارول_عامه(ثابت حرف *filename, بنية sshkey **keyp, حرف **commentp)
{
	حرف *pubfile = عدم;
	صحيح r, oerrno;

	إذا (keyp != عدم)
		*keyp = عدم;
	إذا (commentp != عدم)
		*commentp = عدم;

	إذا ((r = sshkey_try_بارول_عامه(keyp, filename, commentp)) == 0)
		اذهب بهر;

	/* try .pub suffix */
	إذا (asprintf(&pubfile, "%s.pub", filename) == -1)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshkey_try_بارول_عامه(keyp, pubfile, commentp)) == 0)
		اذهب بهر;

	/* finally, try to extract public key from private key file */
	إذا ((r = sshkey_بارول_pubkey_from_شخصي(filename, keyp)) == 0)
		اذهب بهر;

	/* Pretend we couldn't find the key */
	r = SSH_ERR_SYSTEM_ERROR;
	errno = ENOENT;

 بهر:
	oerrno = errno;
	حرر(pubfile);
	errno = oerrno;
	أرجع r;
}

/* Load the certificate associated with the named private key */
صحيح
sshkey_بارول_cert(ثابت حرف *filename, بنية sshkey **keyp)
{
	بنية sshkey *pub = عدم;
	حرف *file = عدم;
	صحيح r = SSH_ERR_دننی_ERROR;

	إذا (keyp != عدم)
		*keyp = عدم;

	إذا (asprintf(&file, "%s-cert.pub", filename) == -1)
		أرجع SSH_ERR_ALLOC_FAIL;

	r = sshkey_try_بارول_عامه(keyp, file, عدم);
	حرر(file);
	sshkey_free(pub);
	أرجع r;
}

/* Load private key and certificate */
صحيح
sshkey_بارول_شخصي_cert(صحيح type, ثابت حرف *filename, ثابت حرف *passphrase,
    بنية sshkey **keyp)
{
	بنية sshkey *کلی = عدم, *cert = عدم;
	صحيح r;

	إذا (keyp != عدم)
		*keyp = عدم;

	بدل (type) {
#که_تعریف_شوی WITH_OPENSSL
	حالة کلی_RSA:
	حالة کلی_ECDSA:
#د_که_پای /* WITH_OPENSSL */
	حالة کلی_ED25519:
	حالة کلی_MLDSA44_ED25519:
	حالة کلی_UNSPEC:
		اكسر;
	افتراضي:
		أرجع SSH_ERR_کلی_TYPE_UNKNOWN;
	}

	إذا ((r = sshkey_بارول_شخصي_type(type, filename,
	    passphrase, &کلی, عدم)) != 0 ||
	    (r = sshkey_بارول_cert(filename, &cert)) != 0)
		اذهب بهر;

	/* Make sure the private key matches the certificate */
	إذا (sshkey_equal_عامه(کلی, cert) == 0) {
		r = SSH_ERR_کلی_CERT_MISMATCH;
		اذهب بهر;
	}

	إذا ((r = sshkey_منزل_certified(کلی)) != 0 ||
	    (r = sshkey_cert_copy(cert, کلی)) != 0)
		اذهب بهر;
	r = 0;
	إذا (keyp != عدم) {
		*keyp = کلی;
		کلی = عدم;
	}
 بهر:
	sshkey_free(کلی);
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
sshkey_دننه_file(بنية sshkey *کلی, ثابت حرف *filename, صحيح strict_type,
    صحيح check_ca)
{
	FILE *f;
	حرف *کرښه = عدم, *cp;
	اندازه_t linesize = 0;
	صحيح r = 0;
	بنية sshkey *pub = عدم;

	صحيح (*sshkey_compare)(ثابت بنية sshkey *, ثابت بنية sshkey *) =
	    strict_type ?  sshkey_equal : sshkey_equal_عامه;

	إذا ((f = fopen(filename, "r")) == عدم)
		أرجع SSH_ERR_SYSTEM_ERROR;

	طالما (getline(&کرښه, &linesize, f) != -1) {
		sshkey_free(pub);
		pub = عدم;
		cp = کرښه;

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

		إذا ((pub = sshkey_new(کلی_UNSPEC)) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب بهر;
		}
		بدل (r = sshkey_read(pub, &cp)) {
		حالة 0:
			اكسر;
		حالة SSH_ERR_کلی_اوږدتیا:
			استمر;
		افتراضي:
			اذهب بهر;
		}
		إذا (sshkey_compare(کلی, pub) ||
		    (check_ca && sshkey_is_cert(کلی) &&
		    sshkey_compare(کلی->cert->signature_کلی, pub))) {
			r = 0;
			اذهب بهر;
		}
	}
	r = SSH_ERR_کلی_NOT_وموندل;
 بهر:
	حرر(کرښه);
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
sshkey_check_revoked(بنية sshkey *کلی, ثابت حرف *revoked_کلیګانې_file)
{
	صحيح r;

	r = ssh_krl_file_لري_کلی(revoked_کلیګانې_file, کلی);
	/* If this was not a KRL to begin with then continue below */
	إذا (r != SSH_ERR_KRL_BAD_MAGIC)
		أرجع r;

	/*
	 * If the file is not a KRL or we can't handle KRLs then attempt to
	 * parse the file as a flat list of keys.
	 */
	بدل ((r = sshkey_دننه_file(کلی, revoked_کلیګانې_file, 0, 1))) {
	حالة 0:
		/* Key found => revoked */
		أرجع SSH_ERR_کلی_REVOKED;
	حالة SSH_ERR_کلی_NOT_وموندل:
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
sshkey_save_عامه(ثابت بنية sshkey *کلی, ثابت حرف *لار,
    ثابت حرف *comment)
{
	صحيح fd, oerrno;
	FILE *f = عدم;
	صحيح r = SSH_ERR_دننی_ERROR;

	إذا ((fd = open(لار, O_WRONLY|O_CREAT|O_TRUNC, 0644)) == -1)
		أرجع SSH_ERR_SYSTEM_ERROR;
	إذا ((f = fdopen(fd, "w")) == عدم) {
		r = SSH_ERR_SYSTEM_ERROR;
		close(fd);
		اذهب fail;
	}
	إذا ((r = sshkey_write(کلی, f)) != 0)
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
