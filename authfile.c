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
static 整数
sshkey_save_private_blob(struct sshbuf *keybuf, const char *filename)
{
	整数 r;
	mode_t omask;

	omask = umask(077);
	r = sshbuf_write_file(filename, keybuf);
	umask(omask);
	返回 r;
}

整数
sshkey_save_private(struct sshkey *key, const char *filename,
    const char *passphrase, const char *comment,
    整数 format, const char *openssh_format_cipher, 整数 openssh_format_rounds)
{
	struct sshbuf *keyblob = NULL;
	整数 r;

	如果 ((keyblob = sshbuf_new()) == NULL)
		返回 SSH_ERR_ALLOC_FAIL;
	如果 ((r = sshkey_private_to_fileblob(key, keyblob, passphrase, comment,
	    format, openssh_format_cipher, openssh_format_rounds)) != 0)
		goto out;
	如果 ((r = sshkey_save_private_blob(keyblob, filename)) != 0)
		goto out;
	r = 0;
 out:
	sshbuf_free(keyblob);
	返回 r;
}

/* XXX remove error() calls from here? */
整数
sshkey_perm_ok(整数 fd, const char *filename)
{
	struct stat st;

	如果 (fstat(fd, &st) == -1)
		返回 SSH_ERR_SYSTEM_ERROR;
	/*
	 * if a key owned by the user is accessed, then we check the
	 * permissions of the file. if the key owned by a different user,
	 * then we don't care.
	 */
#ifdef HAVE_CYGWIN
	如果 (check_ntsec(filename))
#endif
	如果 ((st.st_uid == getuid()) && (st.st_mode & 077) != 0) {
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @");
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("Permissions 0%3.3o for '%s' are too open.",
		    (u_int)st.st_mode & 0777, filename);
		error("It is required that your private key files are NOT accessible by others.");
		error("This private key will be ignored.");
		返回 SSH_ERR_KEY_BAD_PERMISSIONS;
	}
	返回 0;
}

整数
sshkey_load_private_type(整数 type, const char *filename, const char *passphrase,
    struct sshkey **keyp, char **commentp)
{
	整数 fd, r;

	如果 (keyp != NULL)
		*keyp = NULL;
	如果 (commentp != NULL)
		*commentp = NULL;

	如果 ((fd = open(filename, O_RDONLY)) == -1)
		返回 SSH_ERR_SYSTEM_ERROR;

	r = sshkey_perm_ok(fd, filename);
	如果 (r != 0)
		goto out;

	r = sshkey_load_private_type_fd(fd, type, passphrase, keyp, commentp);
 out:
	close(fd);
	返回 r;
}

整数
sshkey_load_private(const char *filename, const char *passphrase,
    struct sshkey **keyp, char **commentp)
{
	返回 sshkey_load_private_type(KEY_UNSPEC, filename, passphrase,
	    keyp, commentp);
}

整数
sshkey_load_private_type_fd(整数 fd, 整数 type, const char *passphrase,
    struct sshkey **keyp, char **commentp)
{
	struct sshbuf *buffer = NULL;
	整数 r;

	如果 (keyp != NULL)
		*keyp = NULL;
	如果 ((r = sshbuf_load_fd(fd, &buffer)) != 0 ||
	    (r = sshkey_parse_private_fileblob_type(buffer, type,
	    passphrase, keyp, commentp)) != 0)
		goto out;

	/* success */
	r = 0;
 out:
	sshbuf_free(buffer);
	返回 r;
}

/* Load a pubkey from the unencrypted envelope of a new-format private key */
static 整数
sshkey_load_pubkey_from_private(const char *filename, struct sshkey **pubkeyp)
{
	struct sshbuf *buffer = NULL;
	struct sshkey *pubkey = NULL;
	整数 r, fd;

	如果 (pubkeyp != NULL)
		*pubkeyp = NULL;

	如果 ((fd = open(filename, O_RDONLY)) == -1)
		返回 SSH_ERR_SYSTEM_ERROR;
	如果 ((r = sshbuf_load_fd(fd, &buffer)) != 0 ||
	    (r = sshkey_parse_pubkey_from_private_fileblob_type(buffer,
	    KEY_UNSPEC, &pubkey)) != 0)
		goto out;
	/* success */
	如果 (pubkeyp != NULL) {
		*pubkeyp = pubkey;
		pubkey = NULL;
	}
	r = 0;
 out:
	close(fd);
	sshbuf_free(buffer);
	sshkey_free(pubkey);
	返回 r;
}

static 整数
sshkey_try_load_public(struct sshkey **kp, const char *filename,
    char **commentp)
{
	FILE *f;
	char *line = NULL, *cp;
	size_t linesize = 0;
	整数 r;
	struct stat st;
	struct sshkey *k = NULL;

	如果 (kp == NULL)
		返回 SSH_ERR_INVALID_ARGUMENT;
	*kp = NULL;
	如果 (commentp != NULL)
		*commentp = NULL;
	如果 ((f = fopen(filename, "r")) == NULL)
		返回 SSH_ERR_SYSTEM_ERROR;
	如果 (fstat(fileno(f), &st) == 0 && S_ISREG(st.st_mode) &&
	    st.st_size > SSHBUF_SIZE_MAX) {
		fclose(f);
		返回 SSH_ERR_INVALID_FORMAT;
	}
	如果 ((k = sshkey_new(KEY_UNSPEC)) == NULL) {
		fclose(f);
		返回 SSH_ERR_ALLOC_FAIL;
	}
	当 (getline(&line, &linesize, f) != -1) {
		cp = line;
		switch (*cp) {
		case '#':
		case '\n':
		case '\0':
			continue;
		}
		/* Abort loading if this looks like a private key */
		如果 (strncmp(cp, "-----BEGIN", 10) == 0 ||
		    strcmp(cp, "SSH PRIVATE KEY FILE") == 0)
			break;
		/* Skip leading whitespace. */
		为 (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;
		如果 (*cp) {
			如果 ((r = sshkey_read(k, &cp)) == 0) {
				cp[strcspn(cp, "\r\n")] = '\0';
				如果 (commentp) {
					*commentp = strdup(*cp ?
					    cp : filename);
					如果 (*commentp == NULL)
						r = SSH_ERR_ALLOC_FAIL;
				}
				/* success */
				*kp = k;
				free(line);
				fclose(f);
				返回 r;
			}
		}
	}
	free(k);
	free(line);
	fclose(f);
	返回 SSH_ERR_INVALID_FORMAT;
}

/* load public key from any pubkey file */
整数
sshkey_load_public(const char *filename, struct sshkey **keyp, char **commentp)
{
	char *pubfile = NULL;
	整数 r, oerrno;

	如果 (keyp != NULL)
		*keyp = NULL;
	如果 (commentp != NULL)
		*commentp = NULL;

	如果 ((r = sshkey_try_load_public(keyp, filename, commentp)) == 0)
		goto out;

	/* try .pub suffix */
	如果 (asprintf(&pubfile, "%s.pub", filename) == -1)
		返回 SSH_ERR_ALLOC_FAIL;
	如果 ((r = sshkey_try_load_public(keyp, pubfile, commentp)) == 0)
		goto out;

	/* finally, try to extract public key from private key file */
	如果 ((r = sshkey_load_pubkey_from_private(filename, keyp)) == 0)
		goto out;

	/* Pretend we couldn't find the key */
	r = SSH_ERR_SYSTEM_ERROR;
	errno = ENOENT;

 out:
	oerrno = errno;
	free(pubfile);
	errno = oerrno;
	返回 r;
}

/* Load the certificate associated with the named private key */
整数
sshkey_load_cert(const char *filename, struct sshkey **keyp)
{
	struct sshkey *pub = NULL;
	char *file = NULL;
	整数 r = SSH_ERR_INTERNAL_ERROR;

	如果 (keyp != NULL)
		*keyp = NULL;

	如果 (asprintf(&file, "%s-cert.pub", filename) == -1)
		返回 SSH_ERR_ALLOC_FAIL;

	r = sshkey_try_load_public(keyp, file, NULL);
	free(file);
	sshkey_free(pub);
	返回 r;
}

/* Load private key and certificate */
整数
sshkey_load_private_cert(整数 type, const char *filename, const char *passphrase,
    struct sshkey **keyp)
{
	struct sshkey *key = NULL, *cert = NULL;
	整数 r;

	如果 (keyp != NULL)
		*keyp = NULL;

	switch (type) {
#ifdef WITH_OPENSSL
	case KEY_RSA:
	case KEY_ECDSA:
#endif /* WITH_OPENSSL */
	case KEY_ED25519:
	case KEY_MLDSA44_ED25519:
	case KEY_UNSPEC:
		break;
	default:
		返回 SSH_ERR_KEY_TYPE_UNKNOWN;
	}

	如果 ((r = sshkey_load_private_type(type, filename,
	    passphrase, &key, NULL)) != 0 ||
	    (r = sshkey_load_cert(filename, &cert)) != 0)
		goto out;

	/* Make sure the private key matches the certificate */
	如果 (sshkey_equal_public(key, cert) == 0) {
		r = SSH_ERR_KEY_CERT_MISMATCH;
		goto out;
	}

	如果 ((r = sshkey_to_certified(key)) != 0 ||
	    (r = sshkey_cert_copy(cert, key)) != 0)
		goto out;
	r = 0;
	如果 (keyp != NULL) {
		*keyp = key;
		key = NULL;
	}
 out:
	sshkey_free(key);
	sshkey_free(cert);
	返回 r;
}

/*
 * Returns success if the specified "key" is listed in the file "filename",
 * SSH_ERR_KEY_NOT_FOUND: if the key is not listed or another error.
 * If "strict_type" is set then the key type must match exactly,
 * otherwise a comparison that ignores certificate data is performed.
 * If "check_ca" is set and "key" is a certificate, then its CA key is
 * also checked and sshkey_in_file() will return success if either is found.
 */
整数
sshkey_in_file(struct sshkey *key, const char *filename, 整数 strict_type,
    整数 check_ca)
{
	FILE *f;
	char *line = NULL, *cp;
	size_t linesize = 0;
	整数 r = 0;
	struct sshkey *pub = NULL;

	整数 (*sshkey_compare)(const struct sshkey *, const struct sshkey *) =
	    strict_type ?  sshkey_equal : sshkey_equal_public;

	如果 ((f = fopen(filename, "r")) == NULL)
		返回 SSH_ERR_SYSTEM_ERROR;

	当 (getline(&line, &linesize, f) != -1) {
		sshkey_free(pub);
		pub = NULL;
		cp = line;

		/* Skip leading whitespace. */
		为 (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;

		/* Skip comments and empty lines */
		switch (*cp) {
		case '#':
		case '\n':
		case '\0':
			continue;
		}

		如果 ((pub = sshkey_new(KEY_UNSPEC)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		switch (r = sshkey_read(pub, &cp)) {
		case 0:
			break;
		case SSH_ERR_KEY_LENGTH:
			continue;
		default:
			goto out;
		}
		如果 (sshkey_compare(key, pub) ||
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
	返回 r;
}

/*
 * Checks whether the specified key is revoked, returning 0 if not,
 * SSH_ERR_KEY_REVOKED if it is or another error code if something
 * unexpected happened.
 * This will check both the key and, if it is a certificate, its CA key too.
 * "revoked_keys_file" may be a KRL or a one-per-line list of public keys.
 */
整数
sshkey_check_revoked(struct sshkey *key, const char *revoked_keys_file)
{
	整数 r;

	r = ssh_krl_file_contains_key(revoked_keys_file, key);
	/* If this was not a KRL to begin with then continue below */
	如果 (r != SSH_ERR_KRL_BAD_MAGIC)
		返回 r;

	/*
	 * If the file is not a KRL or we can't handle KRLs then attempt to
	 * parse the file as a flat list of keys.
	 */
	switch ((r = sshkey_in_file(key, revoked_keys_file, 0, 1))) {
	case 0:
		/* Key found => revoked */
		返回 SSH_ERR_KEY_REVOKED;
	case SSH_ERR_KEY_NOT_FOUND:
		/* Key not found => not revoked */
		返回 0;
	default:
		/* Some other error occurred */
		返回 r;
	}
}

/*
 * Advanced *cpp past the end of key options, defined as the first unquoted
 * whitespace character. Returns 0 on success or -1 on failure (e.g.
 * unterminated quotes).
 */
整数
sshkey_advance_past_options(char **cpp)
{
	char *cp = *cpp;
	整数 quoted = 0;

	为 (; *cp && (quoted || (*cp != ' ' && *cp != '\t')); cp++) {
		如果 (*cp == '\\' && cp[1] == '"')
			cp++;	/* Skip both */
		否则 如果 (*cp == '"')
			quoted = !quoted;
	}
	*cpp = cp;
	/* return failure for unterminated quotes */
	返回 (*cp == '\0' && quoted) ? -1 : 0;
}

/* Save a public key */
整数
sshkey_save_public(const struct sshkey *key, const char *path,
    const char *comment)
{
	整数 fd, oerrno;
	FILE *f = NULL;
	整数 r = SSH_ERR_INTERNAL_ERROR;

	如果 ((fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, 0644)) == -1)
		返回 SSH_ERR_SYSTEM_ERROR;
	如果 ((f = fdopen(fd, "w")) == NULL) {
		r = SSH_ERR_SYSTEM_ERROR;
		close(fd);
		goto fail;
	}
	如果 ((r = sshkey_write(key, f)) != 0)
		goto fail;
	fprintf(f, " %s\n", comment);
	如果 (ferror(f)) {
		r = SSH_ERR_SYSTEM_ERROR;
		goto fail;
	}
	如果 (fclose(f) != 0) {
		r = SSH_ERR_SYSTEM_ERROR;
		f = NULL;
 fail:
		如果 (f != NULL) {
			oerrno = errno;
			fclose(f);
			errno = oerrno;
		}
		返回 r;
	}
	返回 0;
}
