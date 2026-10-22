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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/stat.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "authfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "krl.h"

/* Save a key blob to a file */
ਸਥਿਰ ਪੂਰਨ
sshkey_save_ਨਿੱਜੀ_blob(ਬਣਤਰ sshbuf *keybuf, ਅਚਲ ਅੱਖਰ *filename)
{
	ਪੂਰਨ r;
	ਬਹੁਲਕ_t omask;

	omask = umask(077);
	r = sshbuf_write_file(filename, keybuf);
	umask(omask);
	ਵਾਪਸ r;
}

ਪੂਰਨ
sshkey_save_ਨਿੱਜੀ(ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਅਚਲ ਅੱਖਰ *filename,
    ਅਚਲ ਅੱਖਰ *passphrase, ਅਚਲ ਅੱਖਰ *comment,
    ਪੂਰਨ format, ਅਚਲ ਅੱਖਰ *openssh_format_cipher, ਪੂਰਨ openssh_format_ਗੇੜ)
{
	ਬਣਤਰ sshbuf *keyblob = ਨਿਰਾ;
	ਪੂਰਨ r;

	ਜੇ ((keyblob = sshbuf_new()) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ ((r = sshkey_ਨਿੱਜੀ_ਮੰਜ਼ਿਲ_fileblob(ਕੁੰਜੀ, keyblob, passphrase, comment,
	    format, openssh_format_cipher, openssh_format_ਗੇੜ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ ((r = sshkey_save_ਨਿੱਜੀ_blob(keyblob, filename)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	r = 0;
 ਬਾਹਰਲਾ:
	sshbuf_free(keyblob);
	ਵਾਪਸ r;
}

/* XXX remove error() calls from here? */
ਪੂਰਨ
sshkey_perm_ok(ਪੂਰਨ fd, ਅਚਲ ਅੱਖਰ *filename)
{
	ਬਣਤਰ stat st;

	ਜੇ (fstat(fd, &st) == -1)
		ਵਾਪਸ SSH_ERR_SYSTEM_ERROR;
	/*
	 * if a key owned by the user is accessed, then we check the
	 * permissions of the file. if the key owned by a different user,
	 * then we don't care.
	 */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_CYGWIN
	ਜੇ (check_ntsec(filename))
#ਜੇ_ਅੰਤ
	ਜੇ ((st.st_uid == getuid()) && (st.st_mode & 077) != 0) {
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @");
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("Permissions 0%3.3o for '%s' are too open.",
		    (u_int)st.st_mode & 0777, filename);
		error("It is required that your private key files are NOT accessible by others.");
		error("This private key will be ignored.");
		ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_BAD_PERMISSIONS;
	}
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshkey_ਲੱਦੋ_ਨਿੱਜੀ_type(ਪੂਰਨ type, ਅਚਲ ਅੱਖਰ *filename, ਅਚਲ ਅੱਖਰ *passphrase,
    ਬਣਤਰ sshkey **keyp, ਅੱਖਰ **commentp)
{
	ਪੂਰਨ fd, r;

	ਜੇ (keyp != ਨਿਰਾ)
		*keyp = ਨਿਰਾ;
	ਜੇ (commentp != ਨਿਰਾ)
		*commentp = ਨਿਰਾ;

	ਜੇ ((fd = open(filename, O_RDONLY)) == -1)
		ਵਾਪਸ SSH_ERR_SYSTEM_ERROR;

	r = sshkey_perm_ok(fd, filename);
	ਜੇ (r != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	r = sshkey_ਲੱਦੋ_ਨਿੱਜੀ_type_fd(fd, type, passphrase, keyp, commentp);
 ਬਾਹਰਲਾ:
	close(fd);
	ਵਾਪਸ r;
}

ਪੂਰਨ
sshkey_ਲੱਦੋ_ਨਿੱਜੀ(ਅਚਲ ਅੱਖਰ *filename, ਅਚਲ ਅੱਖਰ *passphrase,
    ਬਣਤਰ sshkey **keyp, ਅੱਖਰ **commentp)
{
	ਵਾਪਸ sshkey_ਲੱਦੋ_ਨਿੱਜੀ_type(ਕੁੰਜੀ_UNSPEC, filename, passphrase,
	    keyp, commentp);
}

ਪੂਰਨ
sshkey_ਲੱਦੋ_ਨਿੱਜੀ_type_fd(ਪੂਰਨ fd, ਪੂਰਨ type, ਅਚਲ ਅੱਖਰ *passphrase,
    ਬਣਤਰ sshkey **keyp, ਅੱਖਰ **commentp)
{
	ਬਣਤਰ sshbuf *ਬਫਰ = ਨਿਰਾ;
	ਪੂਰਨ r;

	ਜੇ (keyp != ਨਿਰਾ)
		*keyp = ਨਿਰਾ;
	ਜੇ ((r = sshbuf_ਲੱਦੋ_fd(fd, &ਬਫਰ)) != 0 ||
	    (r = sshkey_parse_ਨਿੱਜੀ_fileblob_type(ਬਫਰ, type,
	    passphrase, keyp, commentp)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* success */
	r = 0;
 ਬਾਹਰਲਾ:
	sshbuf_free(ਬਫਰ);
	ਵਾਪਸ r;
}

/* Load a pubkey from the unencrypted envelope of a new-format private key */
ਸਥਿਰ ਪੂਰਨ
sshkey_ਲੱਦੋ_pubkey_from_ਨਿੱਜੀ(ਅਚਲ ਅੱਖਰ *filename, ਬਣਤਰ sshkey **pubkeyp)
{
	ਬਣਤਰ sshbuf *ਬਫਰ = ਨਿਰਾ;
	ਬਣਤਰ sshkey *pubkey = ਨਿਰਾ;
	ਪੂਰਨ r, fd;

	ਜੇ (pubkeyp != ਨਿਰਾ)
		*pubkeyp = ਨਿਰਾ;

	ਜੇ ((fd = open(filename, O_RDONLY)) == -1)
		ਵਾਪਸ SSH_ERR_SYSTEM_ERROR;
	ਜੇ ((r = sshbuf_ਲੱਦੋ_fd(fd, &ਬਫਰ)) != 0 ||
	    (r = sshkey_parse_pubkey_from_ਨਿੱਜੀ_fileblob_type(ਬਫਰ,
	    ਕੁੰਜੀ_UNSPEC, &pubkey)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	/* success */
	ਜੇ (pubkeyp != ਨਿਰਾ) {
		*pubkeyp = pubkey;
		pubkey = ਨਿਰਾ;
	}
	r = 0;
 ਬਾਹਰਲਾ:
	close(fd);
	sshbuf_free(ਬਫਰ);
	sshkey_free(pubkey);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਪੂਰਨ
sshkey_try_ਲੱਦੋ_ਜਨਤਕ(ਬਣਤਰ sshkey **kp, ਅਚਲ ਅੱਖਰ *filename,
    ਅੱਖਰ **commentp)
{
	FILE *f;
	ਅੱਖਰ *ਸਤਰ = ਨਿਰਾ, *cp;
	ਮਾਪ_t linesize = 0;
	ਪੂਰਨ r;
	ਬਣਤਰ stat st;
	ਬਣਤਰ sshkey *k = ਨਿਰਾ;

	ਜੇ (kp == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	*kp = ਨਿਰਾ;
	ਜੇ (commentp != ਨਿਰਾ)
		*commentp = ਨਿਰਾ;
	ਜੇ ((f = fopen(filename, "r")) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_SYSTEM_ERROR;
	ਜੇ (fstat(fileno(f), &st) == 0 && S_ISREG(st.st_mode) &&
	    st.st_size > SSHBUF_ਮਾਪ_MAX) {
		fclose(f);
		ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
	}
	ਜੇ ((k = sshkey_new(ਕੁੰਜੀ_UNSPEC)) == ਨਿਰਾ) {
		fclose(f);
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	}
	ਜਦੋਂ (getline(&ਸਤਰ, &linesize, f) != -1) {
		cp = ਸਤਰ;
		ਚੋਣ (*cp) {
		ਹਾਲਤ '#':
		ਹਾਲਤ '\n':
		ਹਾਲਤ '\0':
			ਜਾਰੀ;
		}
		/* Abort loading if this looks like a private key */
		ਜੇ (ਲੜੀ_ਤੁਲਨਾ(cp, "-----BEGIN", 10) == 0 ||
		    strcmp(cp, "SSH PRIVATE KEY FILE") == 0)
			ਰੋਕੋ;
		/* Skip leading whitespace. */
		ਲਈ (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;
		ਜੇ (*cp) {
			ਜੇ ((r = sshkey_read(k, &cp)) == 0) {
				cp[strcspn(cp, "\r\n")] = '\0';
				ਜੇ (commentp) {
					*commentp = strdup(*cp ?
					    cp : filename);
					ਜੇ (*commentp == ਨਿਰਾ)
						r = SSH_ERR_ALLOC_FAIL;
				}
				/* success */
				*kp = k;
				ਮੁਕਤ(ਸਤਰ);
				fclose(f);
				ਵਾਪਸ r;
			}
		}
	}
	ਮੁਕਤ(k);
	ਮੁਕਤ(ਸਤਰ);
	fclose(f);
	ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
}

/* load public key from any pubkey file */
ਪੂਰਨ
sshkey_ਲੱਦੋ_ਜਨਤਕ(ਅਚਲ ਅੱਖਰ *filename, ਬਣਤਰ sshkey **keyp, ਅੱਖਰ **commentp)
{
	ਅੱਖਰ *pubfile = ਨਿਰਾ;
	ਪੂਰਨ r, oerrno;

	ਜੇ (keyp != ਨਿਰਾ)
		*keyp = ਨਿਰਾ;
	ਜੇ (commentp != ਨਿਰਾ)
		*commentp = ਨਿਰਾ;

	ਜੇ ((r = sshkey_try_ਲੱਦੋ_ਜਨਤਕ(keyp, filename, commentp)) == 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* try .pub suffix */
	ਜੇ (asprintf(&pubfile, "%s.pub", filename) == -1)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ ((r = sshkey_try_ਲੱਦੋ_ਜਨਤਕ(keyp, pubfile, commentp)) == 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* finally, try to extract public key from private key file */
	ਜੇ ((r = sshkey_ਲੱਦੋ_pubkey_from_ਨਿੱਜੀ(filename, keyp)) == 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* Pretend we couldn't find the key */
	r = SSH_ERR_SYSTEM_ERROR;
	errno = ENOENT;

 ਬਾਹਰਲਾ:
	oerrno = errno;
	ਮੁਕਤ(pubfile);
	errno = oerrno;
	ਵਾਪਸ r;
}

/* Load the certificate associated with the named private key */
ਪੂਰਨ
sshkey_ਲੱਦੋ_cert(ਅਚਲ ਅੱਖਰ *filename, ਬਣਤਰ sshkey **keyp)
{
	ਬਣਤਰ sshkey *pub = ਨਿਰਾ;
	ਅੱਖਰ *file = ਨਿਰਾ;
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

	ਜੇ (keyp != ਨਿਰਾ)
		*keyp = ਨਿਰਾ;

	ਜੇ (asprintf(&file, "%s-cert.pub", filename) == -1)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;

	r = sshkey_try_ਲੱਦੋ_ਜਨਤਕ(keyp, file, ਨਿਰਾ);
	ਮੁਕਤ(file);
	sshkey_free(pub);
	ਵਾਪਸ r;
}

/* Load private key and certificate */
ਪੂਰਨ
sshkey_ਲੱਦੋ_ਨਿੱਜੀ_cert(ਪੂਰਨ type, ਅਚਲ ਅੱਖਰ *filename, ਅਚਲ ਅੱਖਰ *passphrase,
    ਬਣਤਰ sshkey **keyp)
{
	ਬਣਤਰ sshkey *ਕੁੰਜੀ = ਨਿਰਾ, *cert = ਨਿਰਾ;
	ਪੂਰਨ r;

	ਜੇ (keyp != ਨਿਰਾ)
		*keyp = ਨਿਰਾ;

	ਚੋਣ (type) {
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	ਹਾਲਤ ਕੁੰਜੀ_RSA:
	ਹਾਲਤ ਕੁੰਜੀ_ECDSA:
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
	ਹਾਲਤ ਕੁੰਜੀ_ED25519:
	ਹਾਲਤ ਕੁੰਜੀ_MLDSA44_ED25519:
	ਹਾਲਤ ਕੁੰਜੀ_UNSPEC:
		ਰੋਕੋ;
	ਮੂਲ:
		ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_TYPE_UNKNOWN;
	}

	ਜੇ ((r = sshkey_ਲੱਦੋ_ਨਿੱਜੀ_type(type, filename,
	    passphrase, &ਕੁੰਜੀ, ਨਿਰਾ)) != 0 ||
	    (r = sshkey_ਲੱਦੋ_cert(filename, &cert)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* Make sure the private key matches the certificate */
	ਜੇ (sshkey_equal_ਜਨਤਕ(ਕੁੰਜੀ, cert) == 0) {
		r = SSH_ERR_ਕੁੰਜੀ_CERT_MISMATCH;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ ((r = sshkey_ਮੰਜ਼ਿਲ_certified(ਕੁੰਜੀ)) != 0 ||
	    (r = sshkey_cert_copy(cert, ਕੁੰਜੀ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	r = 0;
	ਜੇ (keyp != ਨਿਰਾ) {
		*keyp = ਕੁੰਜੀ;
		ਕੁੰਜੀ = ਨਿਰਾ;
	}
 ਬਾਹਰਲਾ:
	sshkey_free(ਕੁੰਜੀ);
	sshkey_free(cert);
	ਵਾਪਸ r;
}

/*
 * Returns success if the specified "key" is listed in the file "filename",
 * SSH_ERR_KEY_NOT_FOUND: if the key is not listed or another error.
 * If "strict_type" is set then the key type must match exactly,
 * otherwise a comparison that ignores certificate data is performed.
 * If "check_ca" is set and "key" is a certificate, then its CA key is
 * also checked and sshkey_in_file() will return success if either is found.
 */
ਪੂਰਨ
sshkey_ਵਿੱਚ_file(ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਅਚਲ ਅੱਖਰ *filename, ਪੂਰਨ strict_type,
    ਪੂਰਨ check_ca)
{
	FILE *f;
	ਅੱਖਰ *ਸਤਰ = ਨਿਰਾ, *cp;
	ਮਾਪ_t linesize = 0;
	ਪੂਰਨ r = 0;
	ਬਣਤਰ sshkey *pub = ਨਿਰਾ;

	ਪੂਰਨ (*sshkey_compare)(ਅਚਲ ਬਣਤਰ sshkey *, ਅਚਲ ਬਣਤਰ sshkey *) =
	    strict_type ?  sshkey_equal : sshkey_equal_ਜਨਤਕ;

	ਜੇ ((f = fopen(filename, "r")) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_SYSTEM_ERROR;

	ਜਦੋਂ (getline(&ਸਤਰ, &linesize, f) != -1) {
		sshkey_free(pub);
		pub = ਨਿਰਾ;
		cp = ਸਤਰ;

		/* Skip leading whitespace. */
		ਲਈ (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;

		/* Skip comments and empty lines */
		ਚੋਣ (*cp) {
		ਹਾਲਤ '#':
		ਹਾਲਤ '\n':
		ਹਾਲਤ '\0':
			ਜਾਰੀ;
		}

		ਜੇ ((pub = sshkey_new(ਕੁੰਜੀ_UNSPEC)) == ਨਿਰਾ) {
			r = SSH_ERR_ALLOC_FAIL;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਚੋਣ (r = sshkey_read(pub, &cp)) {
		ਹਾਲਤ 0:
			ਰੋਕੋ;
		ਹਾਲਤ SSH_ERR_ਕੁੰਜੀ_ਲੰਮਾਈ:
			ਜਾਰੀ;
		ਮੂਲ:
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (sshkey_compare(ਕੁੰਜੀ, pub) ||
		    (check_ca && sshkey_is_cert(ਕੁੰਜੀ) &&
		    sshkey_compare(ਕੁੰਜੀ->cert->signature_ਕੁੰਜੀ, pub))) {
			r = 0;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	}
	r = SSH_ERR_ਕੁੰਜੀ_NOT_ਮਿਲਿਆ;
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(ਸਤਰ);
	sshkey_free(pub);
	fclose(f);
	ਵਾਪਸ r;
}

/*
 * Checks whether the specified key is revoked, returning 0 if not,
 * SSH_ERR_KEY_REVOKED if it is or another error code if something
 * unexpected happened.
 * This will check both the key and, if it is a certificate, its CA key too.
 * "revoked_keys_file" may be a KRL or a one-per-line list of public keys.
 */
ਪੂਰਨ
sshkey_check_revoked(ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਅਚਲ ਅੱਖਰ *revoked_ਕੁੰਜੀਆਂ_file)
{
	ਪੂਰਨ r;

	r = ssh_krl_file_ਸ਼ਾਮਲ_ਹੈ_ਕੁੰਜੀ(revoked_ਕੁੰਜੀਆਂ_file, ਕੁੰਜੀ);
	/* If this was not a KRL to begin with then continue below */
	ਜੇ (r != SSH_ERR_KRL_BAD_MAGIC)
		ਵਾਪਸ r;

	/*
	 * If the file is not a KRL or we can't handle KRLs then attempt to
	 * parse the file as a flat list of keys.
	 */
	ਚੋਣ ((r = sshkey_ਵਿੱਚ_file(ਕੁੰਜੀ, revoked_ਕੁੰਜੀਆਂ_file, 0, 1))) {
	ਹਾਲਤ 0:
		/* Key found => revoked */
		ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_REVOKED;
	ਹਾਲਤ SSH_ERR_ਕੁੰਜੀ_NOT_ਮਿਲਿਆ:
		/* Key not found => not revoked */
		ਵਾਪਸ 0;
	ਮੂਲ:
		/* Some other error occurred */
		ਵਾਪਸ r;
	}
}

/*
 * Advanced *cpp past the end of key options, defined as the first unquoted
 * whitespace character. Returns 0 on success or -1 on failure (e.g.
 * unterminated quotes).
 */
ਪੂਰਨ
sshkey_advance_past_options(ਅੱਖਰ **cpp)
{
	ਅੱਖਰ *cp = *cpp;
	ਪੂਰਨ quoted = 0;

	ਲਈ (; *cp && (quoted || (*cp != ' ' && *cp != '\t')); cp++) {
		ਜੇ (*cp == '\\' && cp[1] == '"')
			cp++;	/* Skip both */
		ਨਹੀਂਤਾਂ ਜੇ (*cp == '"')
			quoted = !quoted;
	}
	*cpp = cp;
	/* return failure for unterminated quotes */
	ਵਾਪਸ (*cp == '\0' && quoted) ? -1 : 0;
}

/* Save a public key */
ਪੂਰਨ
sshkey_save_ਜਨਤਕ(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਅਚਲ ਅੱਖਰ *ਰਸਤਾ,
    ਅਚਲ ਅੱਖਰ *comment)
{
	ਪੂਰਨ fd, oerrno;
	FILE *f = ਨਿਰਾ;
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

	ਜੇ ((fd = open(ਰਸਤਾ, O_WRONLY|O_CREAT|O_TRUNC, 0644)) == -1)
		ਵਾਪਸ SSH_ERR_SYSTEM_ERROR;
	ਜੇ ((f = fdopen(fd, "w")) == ਨਿਰਾ) {
		r = SSH_ERR_SYSTEM_ERROR;
		close(fd);
		ਜਾਓ fail;
	}
	ਜੇ ((r = sshkey_write(ਕੁੰਜੀ, f)) != 0)
		ਜਾਓ fail;
	fprintf(f, " %s\n", comment);
	ਜੇ (ferror(f)) {
		r = SSH_ERR_SYSTEM_ERROR;
		ਜਾਓ fail;
	}
	ਜੇ (fclose(f) != 0) {
		r = SSH_ERR_SYSTEM_ERROR;
		f = ਨਿਰਾ;
 fail:
		ਜੇ (f != ਨਿਰਾ) {
			oerrno = errno;
			fclose(f);
			errno = oerrno;
		}
		ਵਾਪਸ r;
	}
	ਵਾਪਸ 0;
}
