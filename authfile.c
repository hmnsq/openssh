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
ساکن صحیح
sshkey_save_نجی_blob(ساخت sshbuf *keybuf, ثابت حرف *filename)
{
	صحیح r;
	منوال_t omask;

	omask = umask(077);
	r = sshbuf_write_file(filename, keybuf);
	umask(omask);
	واپس r;
}

صحیح
sshkey_save_نجی(ساخت sshkey *کلید, ثابت حرف *filename,
    ثابت حرف *passphrase, ثابت حرف *comment,
    صحیح format, ثابت حرف *openssh_format_cipher, صحیح openssh_format_دور)
{
	ساخت sshbuf *keyblob = تہی;
	صحیح r;

	اگر ((keyblob = sshbuf_new()) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshkey_نجی_مقصد_fileblob(کلید, keyblob, passphrase, comment,
	    format, openssh_format_cipher, openssh_format_دور)) != 0)
		جاؤ برآمد;
	اگر ((r = sshkey_save_نجی_blob(keyblob, filename)) != 0)
		جاؤ برآمد;
	r = 0;
 برآمد:
	sshbuf_free(keyblob);
	واپس r;
}

/* XXX remove error() calls from here? */
صحیح
sshkey_perm_ok(صحیح fd, ثابت حرف *filename)
{
	ساخت stat st;

	اگر (fstat(fd, &st) == -1)
		واپس SSH_ERR_SYSTEM_ERROR;
	/*
	 * if a key owned by the user is accessed, then we check the
	 * permissions of the file. if the key owned by a different user,
	 * then we don't care.
	 */
#اگر_تعریف_شدہ HAVE_CYGWIN
	اگر (check_ntsec(filename))
#اگر_ختم
	اگر ((st.st_uid == getuid()) && (st.st_mode & 077) != 0) {
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @");
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("Permissions 0%3.3o for '%s' are too open.",
		    (u_int)st.st_mode & 0777, filename);
		error("It is required that your private key files are NOT accessible by others.");
		error("This private key will be ignored.");
		واپس SSH_ERR_کلید_BAD_PERMISSIONS;
	}
	واپس 0;
}

صحیح
sshkey_بھرو_نجی_type(صحیح type, ثابت حرف *filename, ثابت حرف *passphrase,
    ساخت sshkey **keyp, حرف **commentp)
{
	صحیح fd, r;

	اگر (keyp != تہی)
		*keyp = تہی;
	اگر (commentp != تہی)
		*commentp = تہی;

	اگر ((fd = open(filename, O_RDONLY)) == -1)
		واپس SSH_ERR_SYSTEM_ERROR;

	r = sshkey_perm_ok(fd, filename);
	اگر (r != 0)
		جاؤ برآمد;

	r = sshkey_بھرو_نجی_type_fd(fd, type, passphrase, keyp, commentp);
 برآمد:
	close(fd);
	واپس r;
}

صحیح
sshkey_بھرو_نجی(ثابت حرف *filename, ثابت حرف *passphrase,
    ساخت sshkey **keyp, حرف **commentp)
{
	واپس sshkey_بھرو_نجی_type(کلید_UNSPEC, filename, passphrase,
	    keyp, commentp);
}

صحیح
sshkey_بھرو_نجی_type_fd(صحیح fd, صحیح type, ثابت حرف *passphrase,
    ساخت sshkey **keyp, حرف **commentp)
{
	ساخت sshbuf *بفر = تہی;
	صحیح r;

	اگر (keyp != تہی)
		*keyp = تہی;
	اگر ((r = sshbuf_بھرو_fd(fd, &بفر)) != 0 ||
	    (r = sshkey_parse_نجی_fileblob_type(بفر, type,
	    passphrase, keyp, commentp)) != 0)
		جاؤ برآمد;

	/* success */
	r = 0;
 برآمد:
	sshbuf_free(بفر);
	واپس r;
}

/* Load a pubkey from the unencrypted envelope of a new-format private key */
ساکن صحیح
sshkey_بھرو_pubkey_from_نجی(ثابت حرف *filename, ساخت sshkey **pubkeyp)
{
	ساخت sshbuf *بفر = تہی;
	ساخت sshkey *pubkey = تہی;
	صحیح r, fd;

	اگر (pubkeyp != تہی)
		*pubkeyp = تہی;

	اگر ((fd = open(filename, O_RDONLY)) == -1)
		واپس SSH_ERR_SYSTEM_ERROR;
	اگر ((r = sshbuf_بھرو_fd(fd, &بفر)) != 0 ||
	    (r = sshkey_parse_pubkey_from_نجی_fileblob_type(بفر,
	    کلید_UNSPEC, &pubkey)) != 0)
		جاؤ برآمد;
	/* success */
	اگر (pubkeyp != تہی) {
		*pubkeyp = pubkey;
		pubkey = تہی;
	}
	r = 0;
 برآمد:
	close(fd);
	sshbuf_free(بفر);
	sshkey_free(pubkey);
	واپس r;
}

ساکن صحیح
sshkey_try_بھرو_عوامی(ساخت sshkey **kp, ثابت حرف *filename,
    حرف **commentp)
{
	FILE *f;
	حرف *سطر = تہی, *cp;
	سائز_t linesize = 0;
	صحیح r;
	ساخت stat st;
	ساخت sshkey *k = تہی;

	اگر (kp == تہی)
		واپس SSH_ERR_INVALID_دلیل;
	*kp = تہی;
	اگر (commentp != تہی)
		*commentp = تہی;
	اگر ((f = fopen(filename, "r")) == تہی)
		واپس SSH_ERR_SYSTEM_ERROR;
	اگر (fstat(fileno(f), &st) == 0 && S_ISREG(st.st_mode) &&
	    st.st_size > SSHBUF_سائز_MAX) {
		fclose(f);
		واپس SSH_ERR_INVALID_FORMAT;
	}
	اگر ((k = sshkey_new(کلید_UNSPEC)) == تہی) {
		fclose(f);
		واپس SSH_ERR_ALLOC_FAIL;
	}
	جب (getline(&سطر, &linesize, f) != -1) {
		cp = سطر;
		انتخاب (*cp) {
		حالت '#':
		حالت '\n':
		حالت '\0':
			جاری;
		}
		/* Abort loading if this looks like a private key */
		اگر (لڑی_موازنہ(cp, "-----BEGIN", 10) == 0 ||
		    strcmp(cp, "SSH PRIVATE KEY FILE") == 0)
			توڑو;
		/* Skip leading whitespace. */
		برائے (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;
		اگر (*cp) {
			اگر ((r = sshkey_read(k, &cp)) == 0) {
				cp[strcspn(cp, "\r\n")] = '\0';
				اگر (commentp) {
					*commentp = strdup(*cp ?
					    cp : filename);
					اگر (*commentp == تہی)
						r = SSH_ERR_ALLOC_FAIL;
				}
				/* success */
				*kp = k;
				آزاد(سطر);
				fclose(f);
				واپس r;
			}
		}
	}
	آزاد(k);
	آزاد(سطر);
	fclose(f);
	واپس SSH_ERR_INVALID_FORMAT;
}

/* load public key from any pubkey file */
صحیح
sshkey_بھرو_عوامی(ثابت حرف *filename, ساخت sshkey **keyp, حرف **commentp)
{
	حرف *pubfile = تہی;
	صحیح r, oerrno;

	اگر (keyp != تہی)
		*keyp = تہی;
	اگر (commentp != تہی)
		*commentp = تہی;

	اگر ((r = sshkey_try_بھرو_عوامی(keyp, filename, commentp)) == 0)
		جاؤ برآمد;

	/* try .pub suffix */
	اگر (asprintf(&pubfile, "%s.pub", filename) == -1)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshkey_try_بھرو_عوامی(keyp, pubfile, commentp)) == 0)
		جاؤ برآمد;

	/* finally, try to extract public key from private key file */
	اگر ((r = sshkey_بھرو_pubkey_from_نجی(filename, keyp)) == 0)
		جاؤ برآمد;

	/* Pretend we couldn't find the key */
	r = SSH_ERR_SYSTEM_ERROR;
	errno = ENOENT;

 برآمد:
	oerrno = errno;
	آزاد(pubfile);
	errno = oerrno;
	واپس r;
}

/* Load the certificate associated with the named private key */
صحیح
sshkey_بھرو_cert(ثابت حرف *filename, ساخت sshkey **keyp)
{
	ساخت sshkey *pub = تہی;
	حرف *file = تہی;
	صحیح r = SSH_ERR_اندرونی_ERROR;

	اگر (keyp != تہی)
		*keyp = تہی;

	اگر (asprintf(&file, "%s-cert.pub", filename) == -1)
		واپس SSH_ERR_ALLOC_FAIL;

	r = sshkey_try_بھرو_عوامی(keyp, file, تہی);
	آزاد(file);
	sshkey_free(pub);
	واپس r;
}

/* Load private key and certificate */
صحیح
sshkey_بھرو_نجی_cert(صحیح type, ثابت حرف *filename, ثابت حرف *passphrase,
    ساخت sshkey **keyp)
{
	ساخت sshkey *کلید = تہی, *cert = تہی;
	صحیح r;

	اگر (keyp != تہی)
		*keyp = تہی;

	انتخاب (type) {
#اگر_تعریف_شدہ WITH_OPENSSL
	حالت کلید_RSA:
	حالت کلید_ECDSA:
#اگر_ختم /* WITH_OPENSSL */
	حالت کلید_ED25519:
	حالت کلید_MLDSA44_ED25519:
	حالت کلید_UNSPEC:
		توڑو;
	طےشدہ:
		واپس SSH_ERR_کلید_TYPE_UNKNOWN;
	}

	اگر ((r = sshkey_بھرو_نجی_type(type, filename,
	    passphrase, &کلید, تہی)) != 0 ||
	    (r = sshkey_بھرو_cert(filename, &cert)) != 0)
		جاؤ برآمد;

	/* Make sure the private key matches the certificate */
	اگر (sshkey_equal_عوامی(کلید, cert) == 0) {
		r = SSH_ERR_کلید_CERT_MISMATCH;
		جاؤ برآمد;
	}

	اگر ((r = sshkey_مقصد_certified(کلید)) != 0 ||
	    (r = sshkey_cert_copy(cert, کلید)) != 0)
		جاؤ برآمد;
	r = 0;
	اگر (keyp != تہی) {
		*keyp = کلید;
		کلید = تہی;
	}
 برآمد:
	sshkey_free(کلید);
	sshkey_free(cert);
	واپس r;
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
sshkey_اندر_file(ساخت sshkey *کلید, ثابت حرف *filename, صحیح strict_type,
    صحیح check_ca)
{
	FILE *f;
	حرف *سطر = تہی, *cp;
	سائز_t linesize = 0;
	صحیح r = 0;
	ساخت sshkey *pub = تہی;

	صحیح (*sshkey_compare)(ثابت ساخت sshkey *, ثابت ساخت sshkey *) =
	    strict_type ?  sshkey_equal : sshkey_equal_عوامی;

	اگر ((f = fopen(filename, "r")) == تہی)
		واپس SSH_ERR_SYSTEM_ERROR;

	جب (getline(&سطر, &linesize, f) != -1) {
		sshkey_free(pub);
		pub = تہی;
		cp = سطر;

		/* Skip leading whitespace. */
		برائے (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;

		/* Skip comments and empty lines */
		انتخاب (*cp) {
		حالت '#':
		حالت '\n':
		حالت '\0':
			جاری;
		}

		اگر ((pub = sshkey_new(کلید_UNSPEC)) == تہی) {
			r = SSH_ERR_ALLOC_FAIL;
			جاؤ برآمد;
		}
		انتخاب (r = sshkey_read(pub, &cp)) {
		حالت 0:
			توڑو;
		حالت SSH_ERR_کلید_لمبائی:
			جاری;
		طےشدہ:
			جاؤ برآمد;
		}
		اگر (sshkey_compare(کلید, pub) ||
		    (check_ca && sshkey_is_cert(کلید) &&
		    sshkey_compare(کلید->cert->signature_کلید, pub))) {
			r = 0;
			جاؤ برآمد;
		}
	}
	r = SSH_ERR_کلید_NOT_ملا;
 برآمد:
	آزاد(سطر);
	sshkey_free(pub);
	fclose(f);
	واپس r;
}

/*
 * Checks whether the specified key is revoked, returning 0 if not,
 * SSH_ERR_KEY_REVOKED if it is or another error code if something
 * unexpected happened.
 * This will check both the key and, if it is a certificate, its CA key too.
 * "revoked_keys_file" may be a KRL or a one-per-line list of public keys.
 */
صحیح
sshkey_check_revoked(ساخت sshkey *کلید, ثابت حرف *revoked_کلیدیں_file)
{
	صحیح r;

	r = ssh_krl_file_شامل_ہے_کلید(revoked_کلیدیں_file, کلید);
	/* If this was not a KRL to begin with then continue below */
	اگر (r != SSH_ERR_KRL_BAD_MAGIC)
		واپس r;

	/*
	 * If the file is not a KRL or we can't handle KRLs then attempt to
	 * parse the file as a flat list of keys.
	 */
	انتخاب ((r = sshkey_اندر_file(کلید, revoked_کلیدیں_file, 0, 1))) {
	حالت 0:
		/* Key found => revoked */
		واپس SSH_ERR_کلید_REVOKED;
	حالت SSH_ERR_کلید_NOT_ملا:
		/* Key not found => not revoked */
		واپس 0;
	طےشدہ:
		/* Some other error occurred */
		واپس r;
	}
}

/*
 * Advanced *cpp past the end of key options, defined as the first unquoted
 * whitespace character. Returns 0 on success or -1 on failure (e.g.
 * unterminated quotes).
 */
صحیح
sshkey_advance_past_options(حرف **cpp)
{
	حرف *cp = *cpp;
	صحیح quoted = 0;

	برائے (; *cp && (quoted || (*cp != ' ' && *cp != '\t')); cp++) {
		اگر (*cp == '\\' && cp[1] == '"')
			cp++;	/* Skip both */
		ورنہ اگر (*cp == '"')
			quoted = !quoted;
	}
	*cpp = cp;
	/* return failure for unterminated quotes */
	واپس (*cp == '\0' && quoted) ? -1 : 0;
}

/* Save a public key */
صحیح
sshkey_save_عوامی(ثابت ساخت sshkey *کلید, ثابت حرف *راستہ,
    ثابت حرف *comment)
{
	صحیح fd, oerrno;
	FILE *f = تہی;
	صحیح r = SSH_ERR_اندرونی_ERROR;

	اگر ((fd = open(راستہ, O_WRONLY|O_CREAT|O_TRUNC, 0644)) == -1)
		واپس SSH_ERR_SYSTEM_ERROR;
	اگر ((f = fdopen(fd, "w")) == تہی) {
		r = SSH_ERR_SYSTEM_ERROR;
		close(fd);
		جاؤ fail;
	}
	اگر ((r = sshkey_write(کلید, f)) != 0)
		جاؤ fail;
	fprintf(f, " %s\n", comment);
	اگر (ferror(f)) {
		r = SSH_ERR_SYSTEM_ERROR;
		جاؤ fail;
	}
	اگر (fclose(f) != 0) {
		r = SSH_ERR_SYSTEM_ERROR;
		f = تہی;
 fail:
		اگر (f != تہی) {
			oerrno = errno;
			fclose(f);
			errno = oerrno;
		}
		واپس r;
	}
	واپس 0;
}
