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

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "authfile.h"
#include "sshkey.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "krl.h"

/* Save a key blob to a file */
static ຈຳນວນເຕັມ
sshkey_save_private_blob(sa_nracanaa sshbuf *keybuf, const var_na *filename)
{
	ຈຳນວນເຕັມ r;
	mode_t omask;

	omask = umask(077);
	r = sshbuf_write_file(filename, keybuf);
	umask(omask);
	ສົ່ງຄືນ r;
}

ຈຳນວນເຕັມ
sshkey_save_private(sa_nracanaa sshkey *key, const var_na *filename,
    const var_na *passphrase, const var_na *comment,
    ຈຳນວນເຕັມ format, const var_na *openssh_format_cipher, ຈຳນວນເຕັມ openssh_format_rounds)
{
	sa_nracanaa sshbuf *keyblob = NULL;
	ຈຳນວນເຕັມ r;

	ຖ້າ ((keyblob = sshbuf_new()) == NULL)
		ສົ່ງຄືນ SSH_ERR_ALLOC_FAIL;
	ຖ້າ ((r = sshkey_private_to_fileblob(key, keyblob, passphrase, comment,
	    format, openssh_format_cipher, openssh_format_rounds)) != 0)
		goto out;
	ຖ້າ ((r = sshkey_save_private_blob(keyblob, filename)) != 0)
		goto out;
	r = 0;
 out:
	sshbuf_free(keyblob);
	ສົ່ງຄືນ r;
}

/* XXX remove error() calls from here? */
ຈຳນວນເຕັມ
sshkey_perm_ok(ຈຳນວນເຕັມ fd, const var_na *filename)
{
	sa_nracanaa stat st;

	ຖ້າ (fstat(fd, &st) == -1)
		ສົ່ງຄືນ SSH_ERR_SYSTEM_ERROR;
	/*
	 * if a key owned by the user is accessed, then we check the
	 * permissions of the file. if the key owned by a different user,
	 * then we don't care.
	 */
#ifdef HAVE_CYGWIN
	ຖ້າ (check_ntsec(filename))
#endif
	ຖ້າ ((st.st_uid == getuid()) && (st.st_mode & 077) != 0) {
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @");
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("Permissions 0%3.3o for '%s' are too open.",
		    (u_int)st.st_mode & 0777, filename);
		error("It is required that your private key files are NOT accessible by others.");
		error("This private key will be ignored.");
		ສົ່ງຄືນ SSH_ERR_KEY_BAD_PERMISSIONS;
	}
	ສົ່ງຄືນ 0;
}

ຈຳນວນເຕັມ
sshkey_load_private_type(ຈຳນວນເຕັມ type, const var_na *filename, const var_na *passphrase,
    sa_nracanaa sshkey **keyp, var_na **commentp)
{
	ຈຳນວນເຕັມ fd, r;

	ຖ້າ (keyp != NULL)
		*keyp = NULL;
	ຖ້າ (commentp != NULL)
		*commentp = NULL;

	ຖ້າ ((fd = open(filename, O_RDONLY)) == -1)
		ສົ່ງຄືນ SSH_ERR_SYSTEM_ERROR;

	r = sshkey_perm_ok(fd, filename);
	ຖ້າ (r != 0)
		goto out;

	r = sshkey_load_private_type_fd(fd, type, passphrase, keyp, commentp);
 out:
	close(fd);
	ສົ່ງຄືນ r;
}

ຈຳນວນເຕັມ
sshkey_load_private(const var_na *filename, const var_na *passphrase,
    sa_nracanaa sshkey **keyp, var_na **commentp)
{
	ສົ່ງຄືນ sshkey_load_private_type(KEY_UNSPEC, filename, passphrase,
	    keyp, commentp);
}

ຈຳນວນເຕັມ
sshkey_load_private_type_fd(ຈຳນວນເຕັມ fd, ຈຳນວນເຕັມ type, const var_na *passphrase,
    sa_nracanaa sshkey **keyp, var_na **commentp)
{
	sa_nracanaa sshbuf *buffer = NULL;
	ຈຳນວນເຕັມ r;

	ຖ້າ (keyp != NULL)
		*keyp = NULL;
	ຖ້າ ((r = sshbuf_load_fd(fd, &buffer)) != 0 ||
	    (r = sshkey_parse_private_fileblob_type(buffer, type,
	    passphrase, keyp, commentp)) != 0)
		goto out;

	/* success */
	r = 0;
 out:
	sshbuf_free(buffer);
	ສົ່ງຄືນ r;
}

/* Load a pubkey from the unencrypted envelope of a new-format private key */
static ຈຳນວນເຕັມ
sshkey_load_pubkey_from_private(const var_na *filename, sa_nracanaa sshkey **pubkeyp)
{
	sa_nracanaa sshbuf *buffer = NULL;
	sa_nracanaa sshkey *pubkey = NULL;
	ຈຳນວນເຕັມ r, fd;

	ຖ້າ (pubkeyp != NULL)
		*pubkeyp = NULL;

	ຖ້າ ((fd = open(filename, O_RDONLY)) == -1)
		ສົ່ງຄືນ SSH_ERR_SYSTEM_ERROR;
	ຖ້າ ((r = sshbuf_load_fd(fd, &buffer)) != 0 ||
	    (r = sshkey_parse_pubkey_from_private_fileblob_type(buffer,
	    KEY_UNSPEC, &pubkey)) != 0)
		goto out;
	/* success */
	ຖ້າ (pubkeyp != NULL) {
		*pubkeyp = pubkey;
		pubkey = NULL;
	}
	r = 0;
 out:
	close(fd);
	sshbuf_free(buffer);
	sshkey_free(pubkey);
	ສົ່ງຄືນ r;
}

static ຈຳນວນເຕັມ
sshkey_try_load_public(sa_nracanaa sshkey **kp, const var_na *filename,
    var_na **commentp)
{
	FILE *f;
	var_na *line = NULL, *cp;
	size_t linesize = 0;
	ຈຳນວນເຕັມ r;
	sa_nracanaa stat st;
	sa_nracanaa sshkey *k = NULL;

	ຖ້າ (kp == NULL)
		ສົ່ງຄືນ SSH_ERR_INVALID_ARGUMENT;
	*kp = NULL;
	ຖ້າ (commentp != NULL)
		*commentp = NULL;
	ຖ້າ ((f = fopen(filename, "r")) == NULL)
		ສົ່ງຄືນ SSH_ERR_SYSTEM_ERROR;
	ຖ້າ (fstat(fileno(f), &st) == 0 && S_ISREG(st.st_mode) &&
	    st.st_size > SSHBUF_SIZE_MAX) {
		fclose(f);
		ສົ່ງຄືນ SSH_ERR_INVALID_FORMAT;
	}
	ຖ້າ ((k = sshkey_new(KEY_UNSPEC)) == NULL) {
		fclose(f);
		ສົ່ງຄືນ SSH_ERR_ALLOC_FAIL;
	}
	ໃນຂະນະທີ່ (getline(&line, &linesize, f) != -1) {
		cp = line;
		switch (*cp) {
		pak_sa '#':
		pak_sa '\n':
		pak_sa '\0':
			continue;
		}
		/* Abort loading if this looks like a private key */
		ຖ້າ (strncmp(cp, "-----BEGIN", 10) == 0 ||
		    strcmp(cp, "SSH PRIVATE KEY FILE") == 0)
			bha_nga;
		/* Skip leading whitespace. */
		ສຳລັບ (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;
		ຖ້າ (*cp) {
			ຖ້າ ((r = sshkey_read(k, &cp)) == 0) {
				cp[strcspn(cp, "\r\n")] = '\0';
				ຖ້າ (commentp) {
					*commentp = strdup(*cp ?
					    cp : filename);
					ຖ້າ (*commentp == NULL)
						r = SSH_ERR_ALLOC_FAIL;
				}
				/* success */
				*kp = k;
				free(line);
				fclose(f);
				ສົ່ງຄືນ r;
			}
		}
	}
	free(k);
	free(line);
	fclose(f);
	ສົ່ງຄືນ SSH_ERR_INVALID_FORMAT;
}

/* load public key from any pubkey file */
ຈຳນວນເຕັມ
sshkey_load_public(const var_na *filename, sa_nracanaa sshkey **keyp, var_na **commentp)
{
	var_na *pubfile = NULL;
	ຈຳນວນເຕັມ r, oerrno;

	ຖ້າ (keyp != NULL)
		*keyp = NULL;
	ຖ້າ (commentp != NULL)
		*commentp = NULL;

	ຖ້າ ((r = sshkey_try_load_public(keyp, filename, commentp)) == 0)
		goto out;

	/* try .pub suffix */
	ຖ້າ (asprintf(&pubfile, "%s.pub", filename) == -1)
		ສົ່ງຄືນ SSH_ERR_ALLOC_FAIL;
	ຖ້າ ((r = sshkey_try_load_public(keyp, pubfile, commentp)) == 0)
		goto out;

	/* finally, try to extract public key from private key file */
	ຖ້າ ((r = sshkey_load_pubkey_from_private(filename, keyp)) == 0)
		goto out;

	/* Pretend we couldn't find the key */
	r = SSH_ERR_SYSTEM_ERROR;
	errno = ENOENT;

 out:
	oerrno = errno;
	free(pubfile);
	errno = oerrno;
	ສົ່ງຄືນ r;
}

/* Load the certificate associated with the named private key */
ຈຳນວນເຕັມ
sshkey_load_cert(const var_na *filename, sa_nracanaa sshkey **keyp)
{
	sa_nracanaa sshkey *pub = NULL;
	var_na *file = NULL;
	ຈຳນວນເຕັມ r = SSH_ERR_INTERNAL_ERROR;

	ຖ້າ (keyp != NULL)
		*keyp = NULL;

	ຖ້າ (asprintf(&file, "%s-cert.pub", filename) == -1)
		ສົ່ງຄືນ SSH_ERR_ALLOC_FAIL;

	r = sshkey_try_load_public(keyp, file, NULL);
	free(file);
	sshkey_free(pub);
	ສົ່ງຄືນ r;
}

/* Load private key and certificate */
ຈຳນວນເຕັມ
sshkey_load_private_cert(ຈຳນວນເຕັມ type, const var_na *filename, const var_na *passphrase,
    sa_nracanaa sshkey **keyp)
{
	sa_nracanaa sshkey *key = NULL, *cert = NULL;
	ຈຳນວນເຕັມ r;

	ຖ້າ (keyp != NULL)
		*keyp = NULL;

	switch (type) {
#ifdef WITH_OPENSSL
	pak_sa KEY_RSA:
	pak_sa KEY_ECDSA:
#endif /* WITH_OPENSSL */
	pak_sa KEY_ED25519:
	pak_sa KEY_MLDSA44_ED25519:
	pak_sa KEY_UNSPEC:
		bha_nga;
	default:
		ສົ່ງຄືນ SSH_ERR_KEY_TYPE_UNKNOWN;
	}

	ຖ້າ ((r = sshkey_load_private_type(type, filename,
	    passphrase, &key, NULL)) != 0 ||
	    (r = sshkey_load_cert(filename, &cert)) != 0)
		goto out;

	/* Make sure the private key matches the certificate */
	ຖ້າ (sshkey_equal_public(key, cert) == 0) {
		r = SSH_ERR_KEY_CERT_MISMATCH;
		goto out;
	}

	ຖ້າ ((r = sshkey_to_certified(key)) != 0 ||
	    (r = sshkey_cert_copy(cert, key)) != 0)
		goto out;
	r = 0;
	ຖ້າ (keyp != NULL) {
		*keyp = key;
		key = NULL;
	}
 out:
	sshkey_free(key);
	sshkey_free(cert);
	ສົ່ງຄືນ r;
}

/*
 * Returns success if the specified "key" is listed in the file "filename",
 * SSH_ERR_KEY_NOT_FOUND: if the key is not listed or another error.
 * If "strict_type" is set then the key type must match exactly,
 * otherwise a comparison that ignores certificate data is performed.
 * If "check_ca" is set and "key" is a certificate, then its CA key is
 * also checked and sshkey_in_file() will return success if either is found.
 */
ຈຳນວນເຕັມ
sshkey_in_file(sa_nracanaa sshkey *key, const var_na *filename, ຈຳນວນເຕັມ strict_type,
    ຈຳນວນເຕັມ check_ca)
{
	FILE *f;
	var_na *line = NULL, *cp;
	size_t linesize = 0;
	ຈຳນວນເຕັມ r = 0;
	sa_nracanaa sshkey *pub = NULL;

	ຈຳນວນເຕັມ (*sshkey_compare)(const sa_nracanaa sshkey *, const sa_nracanaa sshkey *) =
	    strict_type ?  sshkey_equal : sshkey_equal_public;

	ຖ້າ ((f = fopen(filename, "r")) == NULL)
		ສົ່ງຄືນ SSH_ERR_SYSTEM_ERROR;

	ໃນຂະນະທີ່ (getline(&line, &linesize, f) != -1) {
		sshkey_free(pub);
		pub = NULL;
		cp = line;

		/* Skip leading whitespace. */
		ສຳລັບ (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;

		/* Skip comments and empty lines */
		switch (*cp) {
		pak_sa '#':
		pak_sa '\n':
		pak_sa '\0':
			continue;
		}

		ຖ້າ ((pub = sshkey_new(KEY_UNSPEC)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		switch (r = sshkey_read(pub, &cp)) {
		pak_sa 0:
			bha_nga;
		pak_sa SSH_ERR_KEY_LENGTH:
			continue;
		default:
			goto out;
		}
		ຖ້າ (sshkey_compare(key, pub) ||
		    (check_ca && sshkey_is_cert(key) &&
		    sshkey_compare(key->cert->signature_key, pub))) {
			r = 0;
			goto out;
		}
	}
	r = SSH_ERR_KEY_NOT_FOUND;
 out:
	free(line);
	sshkey_free(pub);
	fclose(f);
	ສົ່ງຄືນ r;
}

/*
 * Checks whether the specified key is revoked, returning 0 if not,
 * SSH_ERR_KEY_REVOKED if it is or another error code if something
 * unexpected happened.
 * This will check both the key and, if it is a certificate, its CA key too.
 * "revoked_keys_file" may be a KRL or a one-per-line list of public keys.
 */
ຈຳນວນເຕັມ
sshkey_check_revoked(sa_nracanaa sshkey *key, const var_na *revoked_keys_file)
{
	ຈຳນວນເຕັມ r;

	r = ssh_krl_file_contains_key(revoked_keys_file, key);
	/* If this was not a KRL to begin with then continue below */
	ຖ້າ (r != SSH_ERR_KRL_BAD_MAGIC)
		ສົ່ງຄືນ r;

	/*
	 * If the file is not a KRL or we can't handle KRLs then attempt to
	 * parse the file as a flat list of keys.
	 */
	switch ((r = sshkey_in_file(key, revoked_keys_file, 0, 1))) {
	pak_sa 0:
		/* Key found => revoked */
		ສົ່ງຄືນ SSH_ERR_KEY_REVOKED;
	pak_sa SSH_ERR_KEY_NOT_FOUND:
		/* Key not found => not revoked */
		ສົ່ງຄືນ 0;
	default:
		/* Some other error occurred */
		ສົ່ງຄືນ r;
	}
}

/*
 * Advanced *cpp past the end of key options, defined as the first unquoted
 * whitespace character. Returns 0 on success or -1 on failure (e.g.
 * unterminated quotes).
 */
ຈຳນວນເຕັມ
sshkey_advance_past_options(var_na **cpp)
{
	var_na *cp = *cpp;
	ຈຳນວນເຕັມ quoted = 0;

	ສຳລັບ (; *cp && (quoted || (*cp != ' ' && *cp != '\t')); cp++) {
		ຖ້າ (*cp == '\\' && cp[1] == '"')
			cp++;	/* Skip both */
		ບໍ່ດັ່ງນັ້ນ ຖ້າ (*cp == '"')
			quoted = !quoted;
	}
	*cpp = cp;
	/* return failure for unterminated quotes */
	ສົ່ງຄືນ (*cp == '\0' && quoted) ? -1 : 0;
}

/* Save a public key */
ຈຳນວນເຕັມ
sshkey_save_public(const sa_nracanaa sshkey *key, const var_na *path,
    const var_na *comment)
{
	ຈຳນວນເຕັມ fd, oerrno;
	FILE *f = NULL;
	ຈຳນວນເຕັມ r = SSH_ERR_INTERNAL_ERROR;

	ຖ້າ ((fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, 0644)) == -1)
		ສົ່ງຄືນ SSH_ERR_SYSTEM_ERROR;
	ຖ້າ ((f = fdopen(fd, "w")) == NULL) {
		r = SSH_ERR_SYSTEM_ERROR;
		close(fd);
		goto fail;
	}
	ຖ້າ ((r = sshkey_write(key, f)) != 0)
		goto fail;
	fprintf(f, " %s\n", comment);
	ຖ້າ (ferror(f)) {
		r = SSH_ERR_SYSTEM_ERROR;
		goto fail;
	}
	ຖ້າ (fclose(f) != 0) {
		r = SSH_ERR_SYSTEM_ERROR;
		f = NULL;
 fail:
		ຖ້າ (f != NULL) {
			oerrno = errno;
			fclose(f);
			errno = oerrno;
		}
		ສົ່ງຄືນ r;
	}
	ສົ່ງຄືນ 0;
}
