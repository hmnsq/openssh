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
static ကိန်းပြည့်
sshkey_save_private_blob(sa_nracanaa sshbuf *keybuf, const var_na *filename)
{
	ကိန်းပြည့် r;
	mode_t omask;

	omask = umask(077);
	r = sshbuf_write_file(filename, keybuf);
	umask(omask);
	ပြန်ပေး r;
}

ကိန်းပြည့်
sshkey_save_private(sa_nracanaa sshkey *key, const var_na *filename,
    const var_na *passphrase, const var_na *comment,
    ကိန်းပြည့် format, const var_na *openssh_format_cipher, ကိန်းပြည့် openssh_format_rounds)
{
	sa_nracanaa sshbuf *keyblob = NULL;
	ကိန်းပြည့် r;

	အကယ်၍ ((keyblob = sshbuf_new()) == NULL)
		ပြန်ပေး SSH_ERR_ALLOC_FAIL;
	အကယ်၍ ((r = sshkey_private_to_fileblob(key, keyblob, passphrase, comment,
	    format, openssh_format_cipher, openssh_format_rounds)) != 0)
		goto out;
	အကယ်၍ ((r = sshkey_save_private_blob(keyblob, filename)) != 0)
		goto out;
	r = 0;
 out:
	sshbuf_free(keyblob);
	ပြန်ပေး r;
}

/* XXX remove error() calls from here? */
ကိန်းပြည့်
sshkey_perm_ok(ကိန်းပြည့် fd, const var_na *filename)
{
	sa_nracanaa stat st;

	အကယ်၍ (fstat(fd, &st) == -1)
		ပြန်ပေး SSH_ERR_SYSTEM_ERROR;
	/*
	 * if a key owned by the user is accessed, then we check the
	 * permissions of the file. if the key owned by a different user,
	 * then we don't care.
	 */
#ifdef HAVE_CYGWIN
	အကယ်၍ (check_ntsec(filename))
#endif
	အကယ်၍ ((st.st_uid == getuid()) && (st.st_mode & 077) != 0) {
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @");
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("Permissions 0%3.3o for '%s' are too open.",
		    (u_int)st.st_mode & 0777, filename);
		error("It is required that your private key files are NOT accessible by others.");
		error("This private key will be ignored.");
		ပြန်ပေး SSH_ERR_KEY_BAD_PERMISSIONS;
	}
	ပြန်ပေး 0;
}

ကိန်းပြည့်
sshkey_load_private_type(ကိန်းပြည့် type, const var_na *filename, const var_na *passphrase,
    sa_nracanaa sshkey **keyp, var_na **commentp)
{
	ကိန်းပြည့် fd, r;

	အကယ်၍ (keyp != NULL)
		*keyp = NULL;
	အကယ်၍ (commentp != NULL)
		*commentp = NULL;

	အကယ်၍ ((fd = open(filename, O_RDONLY)) == -1)
		ပြန်ပေး SSH_ERR_SYSTEM_ERROR;

	r = sshkey_perm_ok(fd, filename);
	အကယ်၍ (r != 0)
		goto out;

	r = sshkey_load_private_type_fd(fd, type, passphrase, keyp, commentp);
 out:
	close(fd);
	ပြန်ပေး r;
}

ကိန်းပြည့်
sshkey_load_private(const var_na *filename, const var_na *passphrase,
    sa_nracanaa sshkey **keyp, var_na **commentp)
{
	ပြန်ပေး sshkey_load_private_type(KEY_UNSPEC, filename, passphrase,
	    keyp, commentp);
}

ကိန်းပြည့်
sshkey_load_private_type_fd(ကိန်းပြည့် fd, ကိန်းပြည့် type, const var_na *passphrase,
    sa_nracanaa sshkey **keyp, var_na **commentp)
{
	sa_nracanaa sshbuf *buffer = NULL;
	ကိန်းပြည့် r;

	အကယ်၍ (keyp != NULL)
		*keyp = NULL;
	အကယ်၍ ((r = sshbuf_load_fd(fd, &buffer)) != 0 ||
	    (r = sshkey_parse_private_fileblob_type(buffer, type,
	    passphrase, keyp, commentp)) != 0)
		goto out;

	/* success */
	r = 0;
 out:
	sshbuf_free(buffer);
	ပြန်ပေး r;
}

/* Load a pubkey from the unencrypted envelope of a new-format private key */
static ကိန်းပြည့်
sshkey_load_pubkey_from_private(const var_na *filename, sa_nracanaa sshkey **pubkeyp)
{
	sa_nracanaa sshbuf *buffer = NULL;
	sa_nracanaa sshkey *pubkey = NULL;
	ကိန်းပြည့် r, fd;

	အကယ်၍ (pubkeyp != NULL)
		*pubkeyp = NULL;

	အကယ်၍ ((fd = open(filename, O_RDONLY)) == -1)
		ပြန်ပေး SSH_ERR_SYSTEM_ERROR;
	အကယ်၍ ((r = sshbuf_load_fd(fd, &buffer)) != 0 ||
	    (r = sshkey_parse_pubkey_from_private_fileblob_type(buffer,
	    KEY_UNSPEC, &pubkey)) != 0)
		goto out;
	/* success */
	အကယ်၍ (pubkeyp != NULL) {
		*pubkeyp = pubkey;
		pubkey = NULL;
	}
	r = 0;
 out:
	close(fd);
	sshbuf_free(buffer);
	sshkey_free(pubkey);
	ပြန်ပေး r;
}

static ကိန်းပြည့်
sshkey_try_load_public(sa_nracanaa sshkey **kp, const var_na *filename,
    var_na **commentp)
{
	FILE *f;
	var_na *line = NULL, *cp;
	size_t linesize = 0;
	ကိန်းပြည့် r;
	sa_nracanaa stat st;
	sa_nracanaa sshkey *k = NULL;

	အကယ်၍ (kp == NULL)
		ပြန်ပေး SSH_ERR_INVALID_ARGUMENT;
	*kp = NULL;
	အကယ်၍ (commentp != NULL)
		*commentp = NULL;
	အကယ်၍ ((f = fopen(filename, "r")) == NULL)
		ပြန်ပေး SSH_ERR_SYSTEM_ERROR;
	အကယ်၍ (fstat(fileno(f), &st) == 0 && S_ISREG(st.st_mode) &&
	    st.st_size > SSHBUF_SIZE_MAX) {
		fclose(f);
		ပြန်ပေး SSH_ERR_INVALID_FORMAT;
	}
	အကယ်၍ ((k = sshkey_new(KEY_UNSPEC)) == NULL) {
		fclose(f);
		ပြန်ပေး SSH_ERR_ALLOC_FAIL;
	}
	နေစဉ် (getline(&line, &linesize, f) != -1) {
		cp = line;
		switch (*cp) {
		pak_sa '#':
		pak_sa '\n':
		pak_sa '\0':
			continue;
		}
		/* Abort loading if this looks like a private key */
		အကယ်၍ (strncmp(cp, "-----BEGIN", 10) == 0 ||
		    strcmp(cp, "SSH PRIVATE KEY FILE") == 0)
			bha_nga;
		/* Skip leading whitespace. */
		အတွက် (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;
		အကယ်၍ (*cp) {
			အကယ်၍ ((r = sshkey_read(k, &cp)) == 0) {
				cp[strcspn(cp, "\r\n")] = '\0';
				အကယ်၍ (commentp) {
					*commentp = strdup(*cp ?
					    cp : filename);
					အကယ်၍ (*commentp == NULL)
						r = SSH_ERR_ALLOC_FAIL;
				}
				/* success */
				*kp = k;
				free(line);
				fclose(f);
				ပြန်ပေး r;
			}
		}
	}
	free(k);
	free(line);
	fclose(f);
	ပြန်ပေး SSH_ERR_INVALID_FORMAT;
}

/* load public key from any pubkey file */
ကိန်းပြည့်
sshkey_load_public(const var_na *filename, sa_nracanaa sshkey **keyp, var_na **commentp)
{
	var_na *pubfile = NULL;
	ကိန်းပြည့် r, oerrno;

	အကယ်၍ (keyp != NULL)
		*keyp = NULL;
	အကယ်၍ (commentp != NULL)
		*commentp = NULL;

	အကယ်၍ ((r = sshkey_try_load_public(keyp, filename, commentp)) == 0)
		goto out;

	/* try .pub suffix */
	အကယ်၍ (asprintf(&pubfile, "%s.pub", filename) == -1)
		ပြန်ပေး SSH_ERR_ALLOC_FAIL;
	အကယ်၍ ((r = sshkey_try_load_public(keyp, pubfile, commentp)) == 0)
		goto out;

	/* finally, try to extract public key from private key file */
	အကယ်၍ ((r = sshkey_load_pubkey_from_private(filename, keyp)) == 0)
		goto out;

	/* Pretend we couldn't find the key */
	r = SSH_ERR_SYSTEM_ERROR;
	errno = ENOENT;

 out:
	oerrno = errno;
	free(pubfile);
	errno = oerrno;
	ပြန်ပေး r;
}

/* Load the certificate associated with the named private key */
ကိန်းပြည့်
sshkey_load_cert(const var_na *filename, sa_nracanaa sshkey **keyp)
{
	sa_nracanaa sshkey *pub = NULL;
	var_na *file = NULL;
	ကိန်းပြည့် r = SSH_ERR_INTERNAL_ERROR;

	အကယ်၍ (keyp != NULL)
		*keyp = NULL;

	အကယ်၍ (asprintf(&file, "%s-cert.pub", filename) == -1)
		ပြန်ပေး SSH_ERR_ALLOC_FAIL;

	r = sshkey_try_load_public(keyp, file, NULL);
	free(file);
	sshkey_free(pub);
	ပြန်ပေး r;
}

/* Load private key and certificate */
ကိန်းပြည့်
sshkey_load_private_cert(ကိန်းပြည့် type, const var_na *filename, const var_na *passphrase,
    sa_nracanaa sshkey **keyp)
{
	sa_nracanaa sshkey *key = NULL, *cert = NULL;
	ကိန်းပြည့် r;

	အကယ်၍ (keyp != NULL)
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
		ပြန်ပေး SSH_ERR_KEY_TYPE_UNKNOWN;
	}

	အကယ်၍ ((r = sshkey_load_private_type(type, filename,
	    passphrase, &key, NULL)) != 0 ||
	    (r = sshkey_load_cert(filename, &cert)) != 0)
		goto out;

	/* Make sure the private key matches the certificate */
	အကယ်၍ (sshkey_equal_public(key, cert) == 0) {
		r = SSH_ERR_KEY_CERT_MISMATCH;
		goto out;
	}

	အကယ်၍ ((r = sshkey_to_certified(key)) != 0 ||
	    (r = sshkey_cert_copy(cert, key)) != 0)
		goto out;
	r = 0;
	အကယ်၍ (keyp != NULL) {
		*keyp = key;
		key = NULL;
	}
 out:
	sshkey_free(key);
	sshkey_free(cert);
	ပြန်ပေး r;
}

/*
 * Returns success if the specified "key" is listed in the file "filename",
 * SSH_ERR_KEY_NOT_FOUND: if the key is not listed or another error.
 * If "strict_type" is set then the key type must match exactly,
 * otherwise a comparison that ignores certificate data is performed.
 * If "check_ca" is set and "key" is a certificate, then its CA key is
 * also checked and sshkey_in_file() will return success if either is found.
 */
ကိန်းပြည့်
sshkey_in_file(sa_nracanaa sshkey *key, const var_na *filename, ကိန်းပြည့် strict_type,
    ကိန်းပြည့် check_ca)
{
	FILE *f;
	var_na *line = NULL, *cp;
	size_t linesize = 0;
	ကိန်းပြည့် r = 0;
	sa_nracanaa sshkey *pub = NULL;

	ကိန်းပြည့် (*sshkey_compare)(const sa_nracanaa sshkey *, const sa_nracanaa sshkey *) =
	    strict_type ?  sshkey_equal : sshkey_equal_public;

	အကယ်၍ ((f = fopen(filename, "r")) == NULL)
		ပြန်ပေး SSH_ERR_SYSTEM_ERROR;

	နေစဉ် (getline(&line, &linesize, f) != -1) {
		sshkey_free(pub);
		pub = NULL;
		cp = line;

		/* Skip leading whitespace. */
		အတွက် (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;

		/* Skip comments and empty lines */
		switch (*cp) {
		pak_sa '#':
		pak_sa '\n':
		pak_sa '\0':
			continue;
		}

		အကယ်၍ ((pub = sshkey_new(KEY_UNSPEC)) == NULL) {
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
		အကယ်၍ (sshkey_compare(key, pub) ||
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
	ပြန်ပေး r;
}

/*
 * Checks whether the specified key is revoked, returning 0 if not,
 * SSH_ERR_KEY_REVOKED if it is or another error code if something
 * unexpected happened.
 * This will check both the key and, if it is a certificate, its CA key too.
 * "revoked_keys_file" may be a KRL or a one-per-line list of public keys.
 */
ကိန်းပြည့်
sshkey_check_revoked(sa_nracanaa sshkey *key, const var_na *revoked_keys_file)
{
	ကိန်းပြည့် r;

	r = ssh_krl_file_contains_key(revoked_keys_file, key);
	/* If this was not a KRL to begin with then continue below */
	အကယ်၍ (r != SSH_ERR_KRL_BAD_MAGIC)
		ပြန်ပေး r;

	/*
	 * If the file is not a KRL or we can't handle KRLs then attempt to
	 * parse the file as a flat list of keys.
	 */
	switch ((r = sshkey_in_file(key, revoked_keys_file, 0, 1))) {
	pak_sa 0:
		/* Key found => revoked */
		ပြန်ပေး SSH_ERR_KEY_REVOKED;
	pak_sa SSH_ERR_KEY_NOT_FOUND:
		/* Key not found => not revoked */
		ပြန်ပေး 0;
	default:
		/* Some other error occurred */
		ပြန်ပေး r;
	}
}

/*
 * Advanced *cpp past the end of key options, defined as the first unquoted
 * whitespace character. Returns 0 on success or -1 on failure (e.g.
 * unterminated quotes).
 */
ကိန်းပြည့်
sshkey_advance_past_options(var_na **cpp)
{
	var_na *cp = *cpp;
	ကိန်းပြည့် quoted = 0;

	အတွက် (; *cp && (quoted || (*cp != ' ' && *cp != '\t')); cp++) {
		အကယ်၍ (*cp == '\\' && cp[1] == '"')
			cp++;	/* Skip both */
		မဟုတ်ပါက အကယ်၍ (*cp == '"')
			quoted = !quoted;
	}
	*cpp = cp;
	/* return failure for unterminated quotes */
	ပြန်ပေး (*cp == '\0' && quoted) ? -1 : 0;
}

/* Save a public key */
ကိန်းပြည့်
sshkey_save_public(const sa_nracanaa sshkey *key, const var_na *path,
    const var_na *comment)
{
	ကိန်းပြည့် fd, oerrno;
	FILE *f = NULL;
	ကိန်းပြည့် r = SSH_ERR_INTERNAL_ERROR;

	အကယ်၍ ((fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, 0644)) == -1)
		ပြန်ပေး SSH_ERR_SYSTEM_ERROR;
	အကယ်၍ ((f = fdopen(fd, "w")) == NULL) {
		r = SSH_ERR_SYSTEM_ERROR;
		close(fd);
		goto fail;
	}
	အကယ်၍ ((r = sshkey_write(key, f)) != 0)
		goto fail;
	fprintf(f, " %s\n", comment);
	အကယ်၍ (ferror(f)) {
		r = SSH_ERR_SYSTEM_ERROR;
		goto fail;
	}
	အကယ်၍ (fclose(f) != 0) {
		r = SSH_ERR_SYSTEM_ERROR;
		f = NULL;
 fail:
		အကယ်၍ (f != NULL) {
			oerrno = errno;
			fclose(f);
			errno = oerrno;
		}
		ပြန်ပေး r;
	}
	ပြန်ပေး 0;
}
