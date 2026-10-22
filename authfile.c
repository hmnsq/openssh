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
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sshkey_save_private_blob(ಸಂರಚನಾ sshbuf *keybuf, ಧ್ರುವ ವರ್ಣ *filename)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	mode_t omask;

	omask = umask(077);
	r = sshbuf_write_file(filename, keybuf);
	umask(omask);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_save_private(ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಧ್ರುವ ವರ್ಣ *filename,
    ಧ್ರುವ ವರ್ಣ *passphrase, ಧ್ರುವ ವರ್ಣ *comment,
    ಪೂರ್ಣಾಙ್ಕ format, ಧ್ರುವ ವರ್ಣ *openssh_format_cipher, ಪೂರ್ಣಾಙ್ಕ openssh_format_rounds)
{
	ಸಂರಚನಾ sshbuf *keyblob = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((keyblob = sshbuf_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಯದಿ ((r = sshkey_private_to_fileblob(ಕೀಲಿ, keyblob, passphrase, comment,
	    format, openssh_format_cipher, openssh_format_rounds)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ ((r = sshkey_save_private_blob(keyblob, filename)) != 0)
		ಗಚ್ಛ out;
	r = 0;
 out:
	sshbuf_free(keyblob);
	ಪ್ರತ್ಯಾಗಮ r;
}

/* XXX remove error() calls from here? */
ಪೂರ್ಣಾಙ್ಕ
sshkey_perm_ok(ಪೂರ್ಣಾಙ್ಕ fd, ಧ್ರುವ ವರ್ಣ *filename)
{
	ಸಂರಚನಾ stat st;

	ಯದಿ (fstat(fd, &st) == -1)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_SYSTEM_ERROR;
	/*
	 * if a key owned by the user is accessed, then we check the
	 * permissions of the file. if the key owned by a different user,
	 * then we don't care.
	 */
#ifdef HAVE_CYGWIN
	ಯದಿ (check_ntsec(filename))
#endif
	ಯದಿ ((st.st_uid == getuid()) && (st.st_mode & 077) != 0) {
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @");
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("Permissions 0%3.3o for '%s' are too open.",
		    (u_int)st.st_mode & 0777, filename);
		error("It is required that your private key files are NOT accessible by others.");
		error("This private key will be ignored.");
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_BAD_PERMISSIONS;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_load_private_type(ಪೂರ್ಣಾಙ್ಕ type, ಧ್ರುವ ವರ್ಣ *filename, ಧ್ರುವ ವರ್ಣ *passphrase,
    ಸಂರಚನಾ sshkey **keyp, ವರ್ಣ **commentp)
{
	ಪೂರ್ಣಾಙ್ಕ fd, r;

	ಯದಿ (keyp != ರಿಕ್ತ)
		*keyp = ರಿಕ್ತ;
	ಯದಿ (commentp != ರಿಕ್ತ)
		*commentp = ರಿಕ್ತ;

	ಯದಿ ((fd = open(filename, O_RDONLY)) == -1)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_SYSTEM_ERROR;

	r = sshkey_perm_ok(fd, filename);
	ಯದಿ (r != 0)
		ಗಚ್ಛ out;

	r = sshkey_load_private_type_fd(fd, type, passphrase, keyp, commentp);
 out:
	close(fd);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_load_private(ಧ್ರುವ ವರ್ಣ *filename, ಧ್ರುವ ವರ್ಣ *passphrase,
    ಸಂರಚನಾ sshkey **keyp, ವರ್ಣ **commentp)
{
	ಪ್ರತ್ಯಾಗಮ sshkey_load_private_type(ಕೀಲಿ_UNSPEC, filename, passphrase,
	    keyp, commentp);
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_load_private_type_fd(ಪೂರ್ಣಾಙ್ಕ fd, ಪೂರ್ಣಾಙ್ಕ type, ಧ್ರುವ ವರ್ಣ *passphrase,
    ಸಂರಚನಾ sshkey **keyp, ವರ್ಣ **commentp)
{
	ಸಂರಚನಾ sshbuf *buffer = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (keyp != ರಿಕ್ತ)
		*keyp = ರಿಕ್ತ;
	ಯದಿ ((r = sshbuf_load_fd(fd, &buffer)) != 0 ||
	    (r = sshkey_parse_private_fileblob_type(buffer, type,
	    passphrase, keyp, commentp)) != 0)
		ಗಚ್ಛ out;

	/* success */
	r = 0;
 out:
	sshbuf_free(buffer);
	ಪ್ರತ್ಯಾಗಮ r;
}

/* Load a pubkey from the unencrypted envelope of a new-format private key */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sshkey_load_pubkey_from_private(ಧ್ರುವ ವರ್ಣ *filename, ಸಂರಚನಾ sshkey **pubkeyp)
{
	ಸಂರಚನಾ sshbuf *buffer = ರಿಕ್ತ;
	ಸಂರಚನಾ sshkey *pubkey = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r, fd;

	ಯದಿ (pubkeyp != ರಿಕ್ತ)
		*pubkeyp = ರಿಕ್ತ;

	ಯದಿ ((fd = open(filename, O_RDONLY)) == -1)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_SYSTEM_ERROR;
	ಯದಿ ((r = sshbuf_load_fd(fd, &buffer)) != 0 ||
	    (r = sshkey_parse_pubkey_from_private_fileblob_type(buffer,
	    ಕೀಲಿ_UNSPEC, &pubkey)) != 0)
		ಗಚ್ಛ out;
	/* success */
	ಯದಿ (pubkeyp != ರಿಕ್ತ) {
		*pubkeyp = pubkey;
		pubkey = ರಿಕ್ತ;
	}
	r = 0;
 out:
	close(fd);
	sshbuf_free(buffer);
	sshkey_free(pubkey);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sshkey_try_load_public(ಸಂರಚನಾ sshkey **kp, ಧ್ರುವ ವರ್ಣ *filename,
    ವರ್ಣ **commentp)
{
	FILE *f;
	ವರ್ಣ *ಸಾಲು = ರಿಕ್ತ, *cp;
	size_t linesize = 0;
	ಪೂರ್ಣಾಙ್ಕ r;
	ಸಂರಚನಾ stat st;
	ಸಂರಚನಾ sshkey *k = ರಿಕ್ತ;

	ಯದಿ (kp == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	*kp = ರಿಕ್ತ;
	ಯದಿ (commentp != ರಿಕ್ತ)
		*commentp = ರಿಕ್ತ;
	ಯದಿ ((f = fopen(filename, "r")) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_SYSTEM_ERROR;
	ಯದಿ (fstat(fileno(f), &st) == 0 && S_ISREG(st.st_mode) &&
	    st.st_size > SSHBUF_SIZE_MAX) {
		fclose(f);
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
	}
	ಯದಿ ((k = sshkey_new(ಕೀಲಿ_UNSPEC)) == ರಿಕ್ತ) {
		fclose(f);
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	}
	ಯಾವತ್ (getline(&ಸಾಲು, &linesize, f) != -1) {
		cp = ಸಾಲು;
		ವಿಕಲ್ಪ (*cp) {
		ಪಕ್ಷ '#':
		ಪಕ್ಷ '\n':
		ಪಕ್ಷ '\0':
			ಅನುವರ್ತ;
		}
		/* Abort loading if this looks like a private key */
		ಯದಿ (strncmp(cp, "-----BEGIN", 10) == 0 ||
		    strcmp(cp, "SSH PRIVATE KEY FILE") == 0)
			ಭಙ್ಗ;
		/* Skip leading whitespace. */
		ಪ್ರತಿ (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;
		ಯದಿ (*cp) {
			ಯದಿ ((r = sshkey_read(k, &cp)) == 0) {
				cp[strcspn(cp, "\r\n")] = '\0';
				ಯದಿ (commentp) {
					*commentp = strdup(*cp ?
					    cp : filename);
					ಯದಿ (*commentp == ರಿಕ್ತ)
						r = SSH_ERR_ALLOC_FAIL;
				}
				/* success */
				*kp = k;
				ಮುಕ್ತ(ಸಾಲು);
				fclose(f);
				ಪ್ರತ್ಯಾಗಮ r;
			}
		}
	}
	ಮುಕ್ತ(k);
	ಮುಕ್ತ(ಸಾಲು);
	fclose(f);
	ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
}

/* load public key from any pubkey file */
ಪೂರ್ಣಾಙ್ಕ
sshkey_load_public(ಧ್ರುವ ವರ್ಣ *filename, ಸಂರಚನಾ sshkey **keyp, ವರ್ಣ **commentp)
{
	ವರ್ಣ *pubfile = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r, oerrno;

	ಯದಿ (keyp != ರಿಕ್ತ)
		*keyp = ರಿಕ್ತ;
	ಯದಿ (commentp != ರಿಕ್ತ)
		*commentp = ರಿಕ್ತ;

	ಯದಿ ((r = sshkey_try_load_public(keyp, filename, commentp)) == 0)
		ಗಚ್ಛ out;

	/* try .pub suffix */
	ಯದಿ (asprintf(&pubfile, "%s.pub", filename) == -1)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಯದಿ ((r = sshkey_try_load_public(keyp, pubfile, commentp)) == 0)
		ಗಚ್ಛ out;

	/* finally, try to extract public key from private key file */
	ಯದಿ ((r = sshkey_load_pubkey_from_private(filename, keyp)) == 0)
		ಗಚ್ಛ out;

	/* Pretend we couldn't find the key */
	r = SSH_ERR_SYSTEM_ERROR;
	errno = ENOENT;

 out:
	oerrno = errno;
	ಮುಕ್ತ(pubfile);
	errno = oerrno;
	ಪ್ರತ್ಯಾಗಮ r;
}

/* Load the certificate associated with the named private key */
ಪೂರ್ಣಾಙ್ಕ
sshkey_load_cert(ಧ್ರುವ ವರ್ಣ *filename, ಸಂರಚನಾ sshkey **keyp)
{
	ಸಂರಚನಾ sshkey *pub = ರಿಕ್ತ;
	ವರ್ಣ *file = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;

	ಯದಿ (keyp != ರಿಕ್ತ)
		*keyp = ರಿಕ್ತ;

	ಯದಿ (asprintf(&file, "%s-cert.pub", filename) == -1)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;

	r = sshkey_try_load_public(keyp, file, ರಿಕ್ತ);
	ಮುಕ್ತ(file);
	sshkey_free(pub);
	ಪ್ರತ್ಯಾಗಮ r;
}

/* Load private key and certificate */
ಪೂರ್ಣಾಙ್ಕ
sshkey_load_private_cert(ಪೂರ್ಣಾಙ್ಕ type, ಧ್ರುವ ವರ್ಣ *filename, ಧ್ರುವ ವರ್ಣ *passphrase,
    ಸಂರಚನಾ sshkey **keyp)
{
	ಸಂರಚನಾ sshkey *ಕೀಲಿ = ರಿಕ್ತ, *cert = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (keyp != ರಿಕ್ತ)
		*keyp = ರಿಕ್ತ;

	ವಿಕಲ್ಪ (type) {
#ifdef WITH_OPENSSL
	ಪಕ್ಷ ಕೀಲಿ_RSA:
	ಪಕ್ಷ ಕೀಲಿ_ECDSA:
#endif /* WITH_OPENSSL */
	ಪಕ್ಷ ಕೀಲಿ_ED25519:
	ಪಕ್ಷ ಕೀಲಿ_MLDSA44_ED25519:
	ಪಕ್ಷ ಕೀಲಿ_UNSPEC:
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_TYPE_UNKNOWN;
	}

	ಯದಿ ((r = sshkey_load_private_type(type, filename,
	    passphrase, &ಕೀಲಿ, ರಿಕ್ತ)) != 0 ||
	    (r = sshkey_load_cert(filename, &cert)) != 0)
		ಗಚ್ಛ out;

	/* Make sure the private key matches the certificate */
	ಯದಿ (sshkey_equal_public(ಕೀಲಿ, cert) == 0) {
		r = SSH_ERR_ಕೀಲಿ_CERT_MISMATCH;
		ಗಚ್ಛ out;
	}

	ಯದಿ ((r = sshkey_to_certified(ಕೀಲಿ)) != 0 ||
	    (r = sshkey_cert_copy(cert, ಕೀಲಿ)) != 0)
		ಗಚ್ಛ out;
	r = 0;
	ಯದಿ (keyp != ರಿಕ್ತ) {
		*keyp = ಕೀಲಿ;
		ಕೀಲಿ = ರಿಕ್ತ;
	}
 out:
	sshkey_free(ಕೀಲಿ);
	sshkey_free(cert);
	ಪ್ರತ್ಯಾಗಮ r;
}

/*
 * Returns success if the specified "key" is listed in the file "filename",
 * SSH_ERR_KEY_NOT_FOUND: if the key is not listed or another error.
 * If "strict_type" is set then the key type must match exactly,
 * otherwise a comparison that ignores certificate data is performed.
 * If "check_ca" is set and "key" is a certificate, then its CA key is
 * also checked and sshkey_in_file() will return success if either is found.
 */
ಪೂರ್ಣಾಙ್ಕ
sshkey_in_file(ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಧ್ರುವ ವರ್ಣ *filename, ಪೂರ್ಣಾಙ್ಕ strict_type,
    ಪೂರ್ಣಾಙ್ಕ check_ca)
{
	FILE *f;
	ವರ್ಣ *ಸಾಲು = ರಿಕ್ತ, *cp;
	size_t linesize = 0;
	ಪೂರ್ಣಾಙ್ಕ r = 0;
	ಸಂರಚನಾ sshkey *pub = ರಿಕ್ತ;

	ಪೂರ್ಣಾಙ್ಕ (*sshkey_compare)(ಧ್ರುವ ಸಂರಚನಾ sshkey *, ಧ್ರುವ ಸಂರಚನಾ sshkey *) =
	    strict_type ?  sshkey_equal : sshkey_equal_public;

	ಯದಿ ((f = fopen(filename, "r")) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_SYSTEM_ERROR;

	ಯಾವತ್ (getline(&ಸಾಲು, &linesize, f) != -1) {
		sshkey_free(pub);
		pub = ರಿಕ್ತ;
		cp = ಸಾಲು;

		/* Skip leading whitespace. */
		ಪ್ರತಿ (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;

		/* Skip comments and empty lines */
		ವಿಕಲ್ಪ (*cp) {
		ಪಕ್ಷ '#':
		ಪಕ್ಷ '\n':
		ಪಕ್ಷ '\0':
			ಅನುವರ್ತ;
		}

		ಯದಿ ((pub = sshkey_new(ಕೀಲಿ_UNSPEC)) == ರಿಕ್ತ) {
			r = SSH_ERR_ALLOC_FAIL;
			ಗಚ್ಛ out;
		}
		ವಿಕಲ್ಪ (r = sshkey_read(pub, &cp)) {
		ಪಕ್ಷ 0:
			ಭಙ್ಗ;
		ಪಕ್ಷ SSH_ERR_ಕೀಲಿ_LENGTH:
			ಅನುವರ್ತ;
		ಸ್ವಭಾವ:
			ಗಚ್ಛ out;
		}
		ಯದಿ (sshkey_compare(ಕೀಲಿ, pub) ||
		    (check_ca && sshkey_is_cert(ಕೀಲಿ) &&
		    sshkey_compare(ಕೀಲಿ->cert->signature_ಕೀಲಿ, pub))) {
			r = 0;
			ಗಚ್ಛ out;
		}
	}
	r = SSH_ERR_ಕೀಲಿ_NOT_FOUND;
 out:
	ಮುಕ್ತ(ಸಾಲು);
	sshkey_free(pub);
	fclose(f);
	ಪ್ರತ್ಯಾಗಮ r;
}

/*
 * Checks whether the specified key is revoked, returning 0 if not,
 * SSH_ERR_KEY_REVOKED if it is or another error code if something
 * unexpected happened.
 * This will check both the key and, if it is a certificate, its CA key too.
 * "revoked_keys_file" may be a KRL or a one-per-line list of public keys.
 */
ಪೂರ್ಣಾಙ್ಕ
sshkey_check_revoked(ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಧ್ರುವ ವರ್ಣ *revoked_ಕೀಲಿಗಳು_file)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	r = ssh_krl_file_contains_ಕೀಲಿ(revoked_ಕೀಲಿಗಳು_file, ಕೀಲಿ);
	/* If this was not a KRL to begin with then continue below */
	ಯದಿ (r != SSH_ERR_KRL_BAD_MAGIC)
		ಪ್ರತ್ಯಾಗಮ r;

	/*
	 * If the file is not a KRL or we can't handle KRLs then attempt to
	 * parse the file as a flat list of keys.
	 */
	ವಿಕಲ್ಪ ((r = sshkey_in_file(ಕೀಲಿ, revoked_ಕೀಲಿಗಳು_file, 0, 1))) {
	ಪಕ್ಷ 0:
		/* Key found => revoked */
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_REVOKED;
	ಪಕ್ಷ SSH_ERR_ಕೀಲಿ_NOT_FOUND:
		/* Key not found => not revoked */
		ಪ್ರತ್ಯಾಗಮ 0;
	ಸ್ವಭಾವ:
		/* Some other error occurred */
		ಪ್ರತ್ಯಾಗಮ r;
	}
}

/*
 * Advanced *cpp past the end of key options, defined as the first unquoted
 * whitespace character. Returns 0 on success or -1 on failure (e.g.
 * unterminated quotes).
 */
ಪೂರ್ಣಾಙ್ಕ
sshkey_advance_past_options(ವರ್ಣ **cpp)
{
	ವರ್ಣ *cp = *cpp;
	ಪೂರ್ಣಾಙ್ಕ quoted = 0;

	ಪ್ರತಿ (; *cp && (quoted || (*cp != ' ' && *cp != '\t')); cp++) {
		ಯದಿ (*cp == '\\' && cp[1] == '"')
			cp++;	/* Skip both */
		ಅನ್ಯಥಾ ಯದಿ (*cp == '"')
			quoted = !quoted;
	}
	*cpp = cp;
	/* return failure for unterminated quotes */
	ಪ್ರತ್ಯಾಗಮ (*cp == '\0' && quoted) ? -1 : 0;
}

/* Save a public key */
ಪೂರ್ಣಾಙ್ಕ
sshkey_save_public(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಧ್ರುವ ವರ್ಣ *path,
    ಧ್ರುವ ವರ್ಣ *comment)
{
	ಪೂರ್ಣಾಙ್ಕ fd, oerrno;
	FILE *f = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;

	ಯದಿ ((fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, 0644)) == -1)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_SYSTEM_ERROR;
	ಯದಿ ((f = fdopen(fd, "w")) == ರಿಕ್ತ) {
		r = SSH_ERR_SYSTEM_ERROR;
		close(fd);
		ಗಚ್ಛ fail;
	}
	ಯದಿ ((r = sshkey_write(ಕೀಲಿ, f)) != 0)
		ಗಚ್ಛ fail;
	fprintf(f, " %s\n", comment);
	ಯದಿ (ferror(f)) {
		r = SSH_ERR_SYSTEM_ERROR;
		ಗಚ್ಛ fail;
	}
	ಯದಿ (fclose(f) != 0) {
		r = SSH_ERR_SYSTEM_ERROR;
		f = ರಿಕ್ತ;
 fail:
		ಯದಿ (f != ರಿಕ್ತ) {
			oerrno = errno;
			fclose(f);
			errno = oerrno;
		}
		ಪ್ರತ್ಯಾಗಮ r;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}
