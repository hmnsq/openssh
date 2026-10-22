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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "authfile.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "krl.h"

/* Save a key blob to a file */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sshkey_save_ಖಾಸಗಿ_blob(ರಚನೆ sshbuf *keybuf, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename)
{
	ಪೂರ್ಣಾಂಕ r;
	ಬಹುಲಕ_t omask;

	omask = umask(077);
	r = sshbuf_write_file(filename, keybuf);
	umask(omask);
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
sshkey_save_ಖಾಸಗಿ(ರಚನೆ sshkey *ಕೀಲಿ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *passphrase, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *comment,
    ಪೂರ್ಣಾಂಕ format, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *openssh_format_cipher, ಪೂರ್ಣಾಂಕ openssh_format_ಸುತ್ತುಗಳು)
{
	ರಚನೆ sshbuf *keyblob = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((keyblob = sshbuf_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ ((r = sshkey_ಖಾಸಗಿ_ಗಮ್ಯ_fileblob(ಕೀಲಿ, keyblob, passphrase, comment,
	    format, openssh_format_cipher, openssh_format_ಸುತ್ತುಗಳು)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ ((r = sshkey_save_ಖಾಸಗಿ_blob(keyblob, filename)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	r = 0;
 ಹೊರಹೋಗು:
	sshbuf_free(keyblob);
	ಹಿಂತಿರುಗಿ r;
}

/* XXX remove error() calls from here? */
ಪೂರ್ಣಾಂಕ
sshkey_perm_ok(ಪೂರ್ಣಾಂಕ fd, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename)
{
	ರಚನೆ stat st;

	ಆದರೆ (fstat(fd, &st) == -1)
		ಹಿಂತಿರುಗಿ SSH_ERR_SYSTEM_ERROR;
	/*
	 * if a key owned by the user is accessed, then we check the
	 * permissions of the file. if the key owned by a different user,
	 * then we don't care.
	 */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_CYGWIN
	ಆದರೆ (check_ntsec(filename))
#ಆದರೆ_ಅಂತ್ಯ
	ಆದರೆ ((st.st_uid == getuid()) && (st.st_mode & 077) != 0) {
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @");
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("Permissions 0%3.3o for '%s' are too open.",
		    (u_int)st.st_mode & 0777, filename);
		error("It is required that your private key files are NOT accessible by others.");
		error("This private key will be ignored.");
		ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_BAD_PERMISSIONS;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshkey_ತುಂಬು_ಖಾಸಗಿ_type(ಪೂರ್ಣಾಂಕ type, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *passphrase,
    ರಚನೆ sshkey **keyp, ಅಕ್ಷರ **commentp)
{
	ಪೂರ್ಣಾಂಕ fd, r;

	ಆದರೆ (keyp != ಖಾಲಿ)
		*keyp = ಖಾಲಿ;
	ಆದರೆ (commentp != ಖಾಲಿ)
		*commentp = ಖಾಲಿ;

	ಆದರೆ ((fd = open(filename, O_RDONLY)) == -1)
		ಹಿಂತಿರುಗಿ SSH_ERR_SYSTEM_ERROR;

	r = sshkey_perm_ok(fd, filename);
	ಆದರೆ (r != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	r = sshkey_ತುಂಬು_ಖಾಸಗಿ_type_fd(fd, type, passphrase, keyp, commentp);
 ಹೊರಹೋಗು:
	close(fd);
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
sshkey_ತುಂಬು_ಖಾಸಗಿ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *passphrase,
    ರಚನೆ sshkey **keyp, ಅಕ್ಷರ **commentp)
{
	ಹಿಂತಿರುಗಿ sshkey_ತುಂಬು_ಖಾಸಗಿ_type(ಕೀಲಿ_UNSPEC, filename, passphrase,
	    keyp, commentp);
}

ಪೂರ್ಣಾಂಕ
sshkey_ತುಂಬು_ಖಾಸಗಿ_type_fd(ಪೂರ್ಣಾಂಕ fd, ಪೂರ್ಣಾಂಕ type, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *passphrase,
    ರಚನೆ sshkey **keyp, ಅಕ್ಷರ **commentp)
{
	ರಚನೆ sshbuf *ಬಫರ್ = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (keyp != ಖಾಲಿ)
		*keyp = ಖಾಲಿ;
	ಆದರೆ ((r = sshbuf_ತುಂಬು_fd(fd, &ಬಫರ್)) != 0 ||
	    (r = sshkey_parse_ಖಾಸಗಿ_fileblob_type(ಬಫರ್, type,
	    passphrase, keyp, commentp)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* success */
	r = 0;
 ಹೊರಹೋಗು:
	sshbuf_free(ಬಫರ್);
	ಹಿಂತಿರುಗಿ r;
}

/* Load a pubkey from the unencrypted envelope of a new-format private key */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sshkey_ತುಂಬು_pubkey_from_ಖಾಸಗಿ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename, ರಚನೆ sshkey **pubkeyp)
{
	ರಚನೆ sshbuf *ಬಫರ್ = ಖಾಲಿ;
	ರಚನೆ sshkey *pubkey = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r, fd;

	ಆದರೆ (pubkeyp != ಖಾಲಿ)
		*pubkeyp = ಖಾಲಿ;

	ಆದರೆ ((fd = open(filename, O_RDONLY)) == -1)
		ಹಿಂತಿರುಗಿ SSH_ERR_SYSTEM_ERROR;
	ಆದರೆ ((r = sshbuf_ತುಂಬು_fd(fd, &ಬಫರ್)) != 0 ||
	    (r = sshkey_parse_pubkey_from_ಖಾಸಗಿ_fileblob_type(ಬಫರ್,
	    ಕೀಲಿ_UNSPEC, &pubkey)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	/* success */
	ಆದರೆ (pubkeyp != ಖಾಲಿ) {
		*pubkeyp = pubkey;
		pubkey = ಖಾಲಿ;
	}
	r = 0;
 ಹೊರಹೋಗು:
	close(fd);
	sshbuf_free(ಬಫರ್);
	sshkey_free(pubkey);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sshkey_try_ತುಂಬು_ಬಹಿರಂಗ(ರಚನೆ sshkey **kp, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename,
    ಅಕ್ಷರ **commentp)
{
	FILE *f;
	ಅಕ್ಷರ *ಸಾಲು = ಖಾಲಿ, *cp;
	ಗಾತ್ರ_t linesize = 0;
	ಪೂರ್ಣಾಂಕ r;
	ರಚನೆ stat st;
	ರಚನೆ sshkey *k = ಖಾಲಿ;

	ಆದರೆ (kp == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	*kp = ಖಾಲಿ;
	ಆದರೆ (commentp != ಖಾಲಿ)
		*commentp = ಖಾಲಿ;
	ಆದರೆ ((f = fopen(filename, "r")) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_SYSTEM_ERROR;
	ಆದರೆ (fstat(fileno(f), &st) == 0 && S_ISREG(st.st_mode) &&
	    st.st_size > SSHBUF_ಗಾತ್ರ_MAX) {
		fclose(f);
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
	}
	ಆದರೆ ((k = sshkey_new(ಕೀಲಿ_UNSPEC)) == ಖಾಲಿ) {
		fclose(f);
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	}
	ಆಗ (getline(&ಸಾಲು, &linesize, f) != -1) {
		cp = ಸಾಲು;
		ಆಯ್ಕೆ (*cp) {
		ಸ್ಥಿತಿ '#':
		ಸ್ಥಿತಿ '\n':
		ಸ್ಥಿತಿ '\0':
			ಮುಂದುವರಿ;
		}
		/* Abort loading if this looks like a private key */
		ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(cp, "-----BEGIN", 10) == 0 ||
		    strcmp(cp, "SSH PRIVATE KEY FILE") == 0)
			ನಿಲ್ಲಿಸು;
		/* Skip leading whitespace. */
		ಗಾಗಿ (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;
		ಆದರೆ (*cp) {
			ಆದರೆ ((r = sshkey_read(k, &cp)) == 0) {
				cp[strcspn(cp, "\r\n")] = '\0';
				ಆದರೆ (commentp) {
					*commentp = strdup(*cp ?
					    cp : filename);
					ಆದರೆ (*commentp == ಖಾಲಿ)
						r = SSH_ERR_ALLOC_FAIL;
				}
				/* success */
				*kp = k;
				ಬಿಡುಗಡೆ(ಸಾಲು);
				fclose(f);
				ಹಿಂತಿರುಗಿ r;
			}
		}
	}
	ಬಿಡುಗಡೆ(k);
	ಬಿಡುಗಡೆ(ಸಾಲು);
	fclose(f);
	ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
}

/* load public key from any pubkey file */
ಪೂರ್ಣಾಂಕ
sshkey_ತುಂಬು_ಬಹಿರಂಗ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename, ರಚನೆ sshkey **keyp, ಅಕ್ಷರ **commentp)
{
	ಅಕ್ಷರ *pubfile = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r, oerrno;

	ಆದರೆ (keyp != ಖಾಲಿ)
		*keyp = ಖಾಲಿ;
	ಆದರೆ (commentp != ಖಾಲಿ)
		*commentp = ಖಾಲಿ;

	ಆದರೆ ((r = sshkey_try_ತುಂಬು_ಬಹಿರಂಗ(keyp, filename, commentp)) == 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* try .pub suffix */
	ಆದರೆ (asprintf(&pubfile, "%s.pub", filename) == -1)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ ((r = sshkey_try_ತುಂಬು_ಬಹಿರಂಗ(keyp, pubfile, commentp)) == 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* finally, try to extract public key from private key file */
	ಆದರೆ ((r = sshkey_ತುಂಬು_pubkey_from_ಖಾಸಗಿ(filename, keyp)) == 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* Pretend we couldn't find the key */
	r = SSH_ERR_SYSTEM_ERROR;
	errno = ENOENT;

 ಹೊರಹೋಗು:
	oerrno = errno;
	ಬಿಡುಗಡೆ(pubfile);
	errno = oerrno;
	ಹಿಂತಿರುಗಿ r;
}

/* Load the certificate associated with the named private key */
ಪೂರ್ಣಾಂಕ
sshkey_ತುಂಬು_cert(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename, ರಚನೆ sshkey **keyp)
{
	ರಚನೆ sshkey *pub = ಖಾಲಿ;
	ಅಕ್ಷರ *file = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;

	ಆದರೆ (keyp != ಖಾಲಿ)
		*keyp = ಖಾಲಿ;

	ಆದರೆ (asprintf(&file, "%s-cert.pub", filename) == -1)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;

	r = sshkey_try_ತುಂಬು_ಬಹಿರಂಗ(keyp, file, ಖಾಲಿ);
	ಬಿಡುಗಡೆ(file);
	sshkey_free(pub);
	ಹಿಂತಿರುಗಿ r;
}

/* Load private key and certificate */
ಪೂರ್ಣಾಂಕ
sshkey_ತುಂಬು_ಖಾಸಗಿ_cert(ಪೂರ್ಣಾಂಕ type, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *passphrase,
    ರಚನೆ sshkey **keyp)
{
	ರಚನೆ sshkey *ಕೀಲಿ = ಖಾಲಿ, *cert = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (keyp != ಖಾಲಿ)
		*keyp = ಖಾಲಿ;

	ಆಯ್ಕೆ (type) {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	ಸ್ಥಿತಿ ಕೀಲಿ_RSA:
	ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA:
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
	ಸ್ಥಿತಿ ಕೀಲಿ_ED25519:
	ಸ್ಥಿತಿ ಕೀಲಿ_MLDSA44_ED25519:
	ಸ್ಥಿತಿ ಕೀಲಿ_UNSPEC:
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_TYPE_UNKNOWN;
	}

	ಆದರೆ ((r = sshkey_ತುಂಬು_ಖಾಸಗಿ_type(type, filename,
	    passphrase, &ಕೀಲಿ, ಖಾಲಿ)) != 0 ||
	    (r = sshkey_ತುಂಬು_cert(filename, &cert)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* Make sure the private key matches the certificate */
	ಆದರೆ (sshkey_equal_ಬಹಿರಂಗ(ಕೀಲಿ, cert) == 0) {
		r = SSH_ERR_ಕೀಲಿ_CERT_MISMATCH;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ ((r = sshkey_ಗಮ್ಯ_certified(ಕೀಲಿ)) != 0 ||
	    (r = sshkey_cert_copy(cert, ಕೀಲಿ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	r = 0;
	ಆದರೆ (keyp != ಖಾಲಿ) {
		*keyp = ಕೀಲಿ;
		ಕೀಲಿ = ಖಾಲಿ;
	}
 ಹೊರಹೋಗು:
	sshkey_free(ಕೀಲಿ);
	sshkey_free(cert);
	ಹಿಂತಿರುಗಿ r;
}

/*
 * Returns success if the specified "key" is listed in the file "filename",
 * SSH_ERR_KEY_NOT_FOUND: if the key is not listed or another error.
 * If "strict_type" is set then the key type must match exactly,
 * otherwise a comparison that ignores certificate data is performed.
 * If "check_ca" is set and "key" is a certificate, then its CA key is
 * also checked and sshkey_in_file() will return success if either is found.
 */
ಪೂರ್ಣಾಂಕ
sshkey_ಒಳ_file(ರಚನೆ sshkey *ಕೀಲಿ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename, ಪೂರ್ಣಾಂಕ strict_type,
    ಪೂರ್ಣಾಂಕ check_ca)
{
	FILE *f;
	ಅಕ್ಷರ *ಸಾಲು = ಖಾಲಿ, *cp;
	ಗಾತ್ರ_t linesize = 0;
	ಪೂರ್ಣಾಂಕ r = 0;
	ರಚನೆ sshkey *pub = ಖಾಲಿ;

	ಪೂರ್ಣಾಂಕ (*sshkey_compare)(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *) =
	    strict_type ?  sshkey_equal : sshkey_equal_ಬಹಿರಂಗ;

	ಆದರೆ ((f = fopen(filename, "r")) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_SYSTEM_ERROR;

	ಆಗ (getline(&ಸಾಲು, &linesize, f) != -1) {
		sshkey_free(pub);
		pub = ಖಾಲಿ;
		cp = ಸಾಲು;

		/* Skip leading whitespace. */
		ಗಾಗಿ (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;

		/* Skip comments and empty lines */
		ಆಯ್ಕೆ (*cp) {
		ಸ್ಥಿತಿ '#':
		ಸ್ಥಿತಿ '\n':
		ಸ್ಥಿತಿ '\0':
			ಮುಂದುವರಿ;
		}

		ಆದರೆ ((pub = sshkey_new(ಕೀಲಿ_UNSPEC)) == ಖಾಲಿ) {
			r = SSH_ERR_ALLOC_FAIL;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆಯ್ಕೆ (r = sshkey_read(pub, &cp)) {
		ಸ್ಥಿತಿ 0:
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ SSH_ERR_ಕೀಲಿ_ಉದ್ದಳತೆ:
			ಮುಂದುವರಿ;
		ಪೂರ್ವನಿಯೋಜಿತ:
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (sshkey_compare(ಕೀಲಿ, pub) ||
		    (check_ca && sshkey_is_cert(ಕೀಲಿ) &&
		    sshkey_compare(ಕೀಲಿ->cert->signature_ಕೀಲಿ, pub))) {
			r = 0;
			ಹೋಗು ಹೊರಹೋಗು;
		}
	}
	r = SSH_ERR_ಕೀಲಿ_NOT_ಸಿಕ್ಕಿತು;
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(ಸಾಲು);
	sshkey_free(pub);
	fclose(f);
	ಹಿಂತಿರುಗಿ r;
}

/*
 * Checks whether the specified key is revoked, returning 0 if not,
 * SSH_ERR_KEY_REVOKED if it is or another error code if something
 * unexpected happened.
 * This will check both the key and, if it is a certificate, its CA key too.
 * "revoked_keys_file" may be a KRL or a one-per-line list of public keys.
 */
ಪೂರ್ಣಾಂಕ
sshkey_check_revoked(ರಚನೆ sshkey *ಕೀಲಿ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *revoked_ಕೀಲಿಗಳು_file)
{
	ಪೂರ್ಣಾಂಕ r;

	r = ssh_krl_file_ಒಳಗೊಂಡಿದೆ_ಕೀಲಿ(revoked_ಕೀಲಿಗಳು_file, ಕೀಲಿ);
	/* If this was not a KRL to begin with then continue below */
	ಆದರೆ (r != SSH_ERR_KRL_BAD_MAGIC)
		ಹಿಂತಿರುಗಿ r;

	/*
	 * If the file is not a KRL or we can't handle KRLs then attempt to
	 * parse the file as a flat list of keys.
	 */
	ಆಯ್ಕೆ ((r = sshkey_ಒಳ_file(ಕೀಲಿ, revoked_ಕೀಲಿಗಳು_file, 0, 1))) {
	ಸ್ಥಿತಿ 0:
		/* Key found => revoked */
		ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_REVOKED;
	ಸ್ಥಿತಿ SSH_ERR_ಕೀಲಿ_NOT_ಸಿಕ್ಕಿತು:
		/* Key not found => not revoked */
		ಹಿಂತಿರುಗಿ 0;
	ಪೂರ್ವನಿಯೋಜಿತ:
		/* Some other error occurred */
		ಹಿಂತಿರುಗಿ r;
	}
}

/*
 * Advanced *cpp past the end of key options, defined as the first unquoted
 * whitespace character. Returns 0 on success or -1 on failure (e.g.
 * unterminated quotes).
 */
ಪೂರ್ಣಾಂಕ
sshkey_advance_past_options(ಅಕ್ಷರ **cpp)
{
	ಅಕ್ಷರ *cp = *cpp;
	ಪೂರ್ಣಾಂಕ quoted = 0;

	ಗಾಗಿ (; *cp && (quoted || (*cp != ' ' && *cp != '\t')); cp++) {
		ಆದರೆ (*cp == '\\' && cp[1] == '"')
			cp++;	/* Skip both */
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (*cp == '"')
			quoted = !quoted;
	}
	*cpp = cp;
	/* return failure for unterminated quotes */
	ಹಿಂತಿರುಗಿ (*cp == '\0' && quoted) ? -1 : 0;
}

/* Save a public key */
ಪೂರ್ಣಾಂಕ
sshkey_save_ಬಹಿರಂಗ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *comment)
{
	ಪೂರ್ಣಾಂಕ fd, oerrno;
	FILE *f = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;

	ಆದರೆ ((fd = open(ಮಾರ್ಗ, O_WRONLY|O_CREAT|O_TRUNC, 0644)) == -1)
		ಹಿಂತಿರುಗಿ SSH_ERR_SYSTEM_ERROR;
	ಆದರೆ ((f = fdopen(fd, "w")) == ಖಾಲಿ) {
		r = SSH_ERR_SYSTEM_ERROR;
		close(fd);
		ಹೋಗು fail;
	}
	ಆದರೆ ((r = sshkey_write(ಕೀಲಿ, f)) != 0)
		ಹೋಗು fail;
	fprintf(f, " %s\n", comment);
	ಆದರೆ (ferror(f)) {
		r = SSH_ERR_SYSTEM_ERROR;
		ಹೋಗು fail;
	}
	ಆದರೆ (fclose(f) != 0) {
		r = SSH_ERR_SYSTEM_ERROR;
		f = ಖಾಲಿ;
 fail:
		ಆದರೆ (f != ಖಾಲಿ) {
			oerrno = errno;
			fclose(f);
			errno = oerrno;
		}
		ಹಿಂತಿರುಗಿ r;
	}
	ಹಿಂತಿರುಗಿ 0;
}
