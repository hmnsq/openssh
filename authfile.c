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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/stat.h>

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <fcntl.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>

#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "authfile.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "krl.h"

/* Save a key blob to a file */
સ્થિર પૂર્ણાંક
sshkey_save_private_blob(સંરચના sshbuf *keybuf, અચલ અક્ષર *filename)
{
	પૂર્ણાંક r;
	mode_t omask;

	omask = umask(077);
	r = sshbuf_write_file(filename, keybuf);
	umask(omask);
	પાછા r;
}

પૂર્ણાંક
sshkey_save_private(સંરચના sshkey *ચાવી, અચલ અક્ષર *filename,
    અચલ અક્ષર *passphrase, અચલ અક્ષર *comment,
    પૂર્ણાંક format, અચલ અક્ષર *openssh_format_cipher, પૂર્ણાંક openssh_format_rounds)
{
	સંરચના sshbuf *keyblob = ખાલી;
	પૂર્ણાંક r;

	જો ((keyblob = sshbuf_new()) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો ((r = sshkey_private_to_fileblob(ચાવી, keyblob, passphrase, comment,
	    format, openssh_format_cipher, openssh_format_rounds)) != 0)
		જાઓ out;
	જો ((r = sshkey_save_private_blob(keyblob, filename)) != 0)
		જાઓ out;
	r = 0;
 out:
	sshbuf_free(keyblob);
	પાછા r;
}

/* XXX remove error() calls from here? */
પૂર્ણાંક
sshkey_perm_ok(પૂર્ણાંક fd, અચલ અક્ષર *filename)
{
	સંરચના stat st;

	જો (fstat(fd, &st) == -1)
		પાછા SSH_ERR_SYSTEM_ERROR;
	/*
	 * if a key owned by the user is accessed, then we check the
	 * permissions of the file. if the key owned by a different user,
	 * then we don't care.
	 */
#ifdef HAVE_CYGWIN
	જો (check_ntsec(filename))
#endif
	જો ((st.st_uid == getuid()) && (st.st_mode & 077) != 0) {
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @");
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("Permissions 0%3.3o for '%s' are too open.",
		    (u_int)st.st_mode & 0777, filename);
		error("It is required that your private key files are NOT accessible by others.");
		error("This private key will be ignored.");
		પાછા SSH_ERR_ચાવી_BAD_PERMISSIONS;
	}
	પાછા 0;
}

પૂર્ણાંક
sshkey_load_private_type(પૂર્ણાંક type, અચલ અક્ષર *filename, અચલ અક્ષર *passphrase,
    સંરચના sshkey **keyp, અક્ષર **commentp)
{
	પૂર્ણાંક fd, r;

	જો (keyp != ખાલી)
		*keyp = ખાલી;
	જો (commentp != ખાલી)
		*commentp = ખાલી;

	જો ((fd = open(filename, O_RDONLY)) == -1)
		પાછા SSH_ERR_SYSTEM_ERROR;

	r = sshkey_perm_ok(fd, filename);
	જો (r != 0)
		જાઓ out;

	r = sshkey_load_private_type_fd(fd, type, passphrase, keyp, commentp);
 out:
	close(fd);
	પાછા r;
}

પૂર્ણાંક
sshkey_load_private(અચલ અક્ષર *filename, અચલ અક્ષર *passphrase,
    સંરચના sshkey **keyp, અક્ષર **commentp)
{
	પાછા sshkey_load_private_type(ચાવી_UNSPEC, filename, passphrase,
	    keyp, commentp);
}

પૂર્ણાંક
sshkey_load_private_type_fd(પૂર્ણાંક fd, પૂર્ણાંક type, અચલ અક્ષર *passphrase,
    સંરચના sshkey **keyp, અક્ષર **commentp)
{
	સંરચના sshbuf *buffer = ખાલી;
	પૂર્ણાંક r;

	જો (keyp != ખાલી)
		*keyp = ખાલી;
	જો ((r = sshbuf_load_fd(fd, &buffer)) != 0 ||
	    (r = sshkey_parse_private_fileblob_type(buffer, type,
	    passphrase, keyp, commentp)) != 0)
		જાઓ out;

	/* success */
	r = 0;
 out:
	sshbuf_free(buffer);
	પાછા r;
}

/* Load a pubkey from the unencrypted envelope of a new-format private key */
સ્થિર પૂર્ણાંક
sshkey_load_pubkey_from_private(અચલ અક્ષર *filename, સંરચના sshkey **pubkeyp)
{
	સંરચના sshbuf *buffer = ખાલી;
	સંરચના sshkey *pubkey = ખાલી;
	પૂર્ણાંક r, fd;

	જો (pubkeyp != ખાલી)
		*pubkeyp = ખાલી;

	જો ((fd = open(filename, O_RDONLY)) == -1)
		પાછા SSH_ERR_SYSTEM_ERROR;
	જો ((r = sshbuf_load_fd(fd, &buffer)) != 0 ||
	    (r = sshkey_parse_pubkey_from_private_fileblob_type(buffer,
	    ચાવી_UNSPEC, &pubkey)) != 0)
		જાઓ out;
	/* success */
	જો (pubkeyp != ખાલી) {
		*pubkeyp = pubkey;
		pubkey = ખાલી;
	}
	r = 0;
 out:
	close(fd);
	sshbuf_free(buffer);
	sshkey_free(pubkey);
	પાછા r;
}

સ્થિર પૂર્ણાંક
sshkey_try_load_public(સંરચના sshkey **kp, અચલ અક્ષર *filename,
    અક્ષર **commentp)
{
	FILE *f;
	અક્ષર *લીટી = ખાલી, *cp;
	size_t linesize = 0;
	પૂર્ણાંક r;
	સંરચના stat st;
	સંરચના sshkey *k = ખાલી;

	જો (kp == ખાલી)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	*kp = ખાલી;
	જો (commentp != ખાલી)
		*commentp = ખાલી;
	જો ((f = fopen(filename, "r")) == ખાલી)
		પાછા SSH_ERR_SYSTEM_ERROR;
	જો (fstat(fileno(f), &st) == 0 && S_ISREG(st.st_mode) &&
	    st.st_size > SSHBUF_SIZE_MAX) {
		fclose(f);
		પાછા SSH_ERR_INVALID_FORMAT;
	}
	જો ((k = sshkey_new(ચાવી_UNSPEC)) == ખાલી) {
		fclose(f);
		પાછા SSH_ERR_ALLOC_FAIL;
	}
	જ્યારે (getline(&લીટી, &linesize, f) != -1) {
		cp = લીટી;
		પસંદગી (*cp) {
		સ્થિતિ '#':
		સ્થિતિ '\n':
		સ્થિતિ '\0':
			ચાલુ;
		}
		/* Abort loading if this looks like a private key */
		જો (strncmp(cp, "-----BEGIN", 10) == 0 ||
		    strcmp(cp, "SSH PRIVATE KEY FILE") == 0)
			તોડો;
		/* Skip leading whitespace. */
		માટે (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;
		જો (*cp) {
			જો ((r = sshkey_read(k, &cp)) == 0) {
				cp[strcspn(cp, "\r\n")] = '\0';
				જો (commentp) {
					*commentp = strdup(*cp ?
					    cp : filename);
					જો (*commentp == ખાલી)
						r = SSH_ERR_ALLOC_FAIL;
				}
				/* success */
				*kp = k;
				મુક્ત(લીટી);
				fclose(f);
				પાછા r;
			}
		}
	}
	મુક્ત(k);
	મુક્ત(લીટી);
	fclose(f);
	પાછા SSH_ERR_INVALID_FORMAT;
}

/* load public key from any pubkey file */
પૂર્ણાંક
sshkey_load_public(અચલ અક્ષર *filename, સંરચના sshkey **keyp, અક્ષર **commentp)
{
	અક્ષર *pubfile = ખાલી;
	પૂર્ણાંક r, oerrno;

	જો (keyp != ખાલી)
		*keyp = ખાલી;
	જો (commentp != ખાલી)
		*commentp = ખાલી;

	જો ((r = sshkey_try_load_public(keyp, filename, commentp)) == 0)
		જાઓ out;

	/* try .pub suffix */
	જો (asprintf(&pubfile, "%s.pub", filename) == -1)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો ((r = sshkey_try_load_public(keyp, pubfile, commentp)) == 0)
		જાઓ out;

	/* finally, try to extract public key from private key file */
	જો ((r = sshkey_load_pubkey_from_private(filename, keyp)) == 0)
		જાઓ out;

	/* Pretend we couldn't find the key */
	r = SSH_ERR_SYSTEM_ERROR;
	errno = ENOENT;

 out:
	oerrno = errno;
	મુક્ત(pubfile);
	errno = oerrno;
	પાછા r;
}

/* Load the certificate associated with the named private key */
પૂર્ણાંક
sshkey_load_cert(અચલ અક્ષર *filename, સંરચના sshkey **keyp)
{
	સંરચના sshkey *pub = ખાલી;
	અક્ષર *file = ખાલી;
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;

	જો (keyp != ખાલી)
		*keyp = ખાલી;

	જો (asprintf(&file, "%s-cert.pub", filename) == -1)
		પાછા SSH_ERR_ALLOC_FAIL;

	r = sshkey_try_load_public(keyp, file, ખાલી);
	મુક્ત(file);
	sshkey_free(pub);
	પાછા r;
}

/* Load private key and certificate */
પૂર્ણાંક
sshkey_load_private_cert(પૂર્ણાંક type, અચલ અક્ષર *filename, અચલ અક્ષર *passphrase,
    સંરચના sshkey **keyp)
{
	સંરચના sshkey *ચાવી = ખાલી, *cert = ખાલી;
	પૂર્ણાંક r;

	જો (keyp != ખાલી)
		*keyp = ખાલી;

	પસંદગી (type) {
#ifdef WITH_OPENSSL
	સ્થિતિ ચાવી_RSA:
	સ્થિતિ ચાવી_ECDSA:
#endif /* WITH_OPENSSL */
	સ્થિતિ ચાવી_ED25519:
	સ્થિતિ ચાવી_MLDSA44_ED25519:
	સ્થિતિ ચાવી_UNSPEC:
		તોડો;
	મૂળભૂત:
		પાછા SSH_ERR_ચાવી_TYPE_UNKNOWN;
	}

	જો ((r = sshkey_load_private_type(type, filename,
	    passphrase, &ચાવી, ખાલી)) != 0 ||
	    (r = sshkey_load_cert(filename, &cert)) != 0)
		જાઓ out;

	/* Make sure the private key matches the certificate */
	જો (sshkey_equal_public(ચાવી, cert) == 0) {
		r = SSH_ERR_ચાવી_CERT_MISMATCH;
		જાઓ out;
	}

	જો ((r = sshkey_to_certified(ચાવી)) != 0 ||
	    (r = sshkey_cert_copy(cert, ચાવી)) != 0)
		જાઓ out;
	r = 0;
	જો (keyp != ખાલી) {
		*keyp = ચાવી;
		ચાવી = ખાલી;
	}
 out:
	sshkey_free(ચાવી);
	sshkey_free(cert);
	પાછા r;
}

/*
 * Returns success if the specified "key" is listed in the file "filename",
 * SSH_ERR_KEY_NOT_FOUND: if the key is not listed or another error.
 * If "strict_type" is set then the key type must match exactly,
 * otherwise a comparison that ignores certificate data is performed.
 * If "check_ca" is set and "key" is a certificate, then its CA key is
 * also checked and sshkey_in_file() will return success if either is found.
 */
પૂર્ણાંક
sshkey_in_file(સંરચના sshkey *ચાવી, અચલ અક્ષર *filename, પૂર્ણાંક strict_type,
    પૂર્ણાંક check_ca)
{
	FILE *f;
	અક્ષર *લીટી = ખાલી, *cp;
	size_t linesize = 0;
	પૂર્ણાંક r = 0;
	સંરચના sshkey *pub = ખાલી;

	પૂર્ણાંક (*sshkey_compare)(અચલ સંરચના sshkey *, અચલ સંરચના sshkey *) =
	    strict_type ?  sshkey_equal : sshkey_equal_public;

	જો ((f = fopen(filename, "r")) == ખાલી)
		પાછા SSH_ERR_SYSTEM_ERROR;

	જ્યારે (getline(&લીટી, &linesize, f) != -1) {
		sshkey_free(pub);
		pub = ખાલી;
		cp = લીટી;

		/* Skip leading whitespace. */
		માટે (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;

		/* Skip comments and empty lines */
		પસંદગી (*cp) {
		સ્થિતિ '#':
		સ્થિતિ '\n':
		સ્થિતિ '\0':
			ચાલુ;
		}

		જો ((pub = sshkey_new(ચાવી_UNSPEC)) == ખાલી) {
			r = SSH_ERR_ALLOC_FAIL;
			જાઓ out;
		}
		પસંદગી (r = sshkey_read(pub, &cp)) {
		સ્થિતિ 0:
			તોડો;
		સ્થિતિ SSH_ERR_ચાવી_LENGTH:
			ચાલુ;
		મૂળભૂત:
			જાઓ out;
		}
		જો (sshkey_compare(ચાવી, pub) ||
		    (check_ca && sshkey_is_cert(ચાવી) &&
		    sshkey_compare(ચાવી->cert->signature_ચાવી, pub))) {
			r = 0;
			જાઓ out;
		}
	}
	r = SSH_ERR_ચાવી_NOT_FOUND;
 out:
	મુક્ત(લીટી);
	sshkey_free(pub);
	fclose(f);
	પાછા r;
}

/*
 * Checks whether the specified key is revoked, returning 0 if not,
 * SSH_ERR_KEY_REVOKED if it is or another error code if something
 * unexpected happened.
 * This will check both the key and, if it is a certificate, its CA key too.
 * "revoked_keys_file" may be a KRL or a one-per-line list of public keys.
 */
પૂર્ણાંક
sshkey_check_revoked(સંરચના sshkey *ચાવી, અચલ અક્ષર *revoked_ચાવીઓ_file)
{
	પૂર્ણાંક r;

	r = ssh_krl_file_contains_ચાવી(revoked_ચાવીઓ_file, ચાવી);
	/* If this was not a KRL to begin with then continue below */
	જો (r != SSH_ERR_KRL_BAD_MAGIC)
		પાછા r;

	/*
	 * If the file is not a KRL or we can't handle KRLs then attempt to
	 * parse the file as a flat list of keys.
	 */
	પસંદગી ((r = sshkey_in_file(ચાવી, revoked_ચાવીઓ_file, 0, 1))) {
	સ્થિતિ 0:
		/* Key found => revoked */
		પાછા SSH_ERR_ચાવી_REVOKED;
	સ્થિતિ SSH_ERR_ચાવી_NOT_FOUND:
		/* Key not found => not revoked */
		પાછા 0;
	મૂળભૂત:
		/* Some other error occurred */
		પાછા r;
	}
}

/*
 * Advanced *cpp past the end of key options, defined as the first unquoted
 * whitespace character. Returns 0 on success or -1 on failure (e.g.
 * unterminated quotes).
 */
પૂર્ણાંક
sshkey_advance_past_options(અક્ષર **cpp)
{
	અક્ષર *cp = *cpp;
	પૂર્ણાંક quoted = 0;

	માટે (; *cp && (quoted || (*cp != ' ' && *cp != '\t')); cp++) {
		જો (*cp == '\\' && cp[1] == '"')
			cp++;	/* Skip both */
		નહીંતર જો (*cp == '"')
			quoted = !quoted;
	}
	*cpp = cp;
	/* return failure for unterminated quotes */
	પાછા (*cp == '\0' && quoted) ? -1 : 0;
}

/* Save a public key */
પૂર્ણાંક
sshkey_save_public(અચલ સંરચના sshkey *ચાવી, અચલ અક્ષર *path,
    અચલ અક્ષર *comment)
{
	પૂર્ણાંક fd, oerrno;
	FILE *f = ખાલી;
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;

	જો ((fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, 0644)) == -1)
		પાછા SSH_ERR_SYSTEM_ERROR;
	જો ((f = fdopen(fd, "w")) == ખાલી) {
		r = SSH_ERR_SYSTEM_ERROR;
		close(fd);
		જાઓ fail;
	}
	જો ((r = sshkey_write(ચાવી, f)) != 0)
		જાઓ fail;
	fprintf(f, " %s\n", comment);
	જો (ferror(f)) {
		r = SSH_ERR_SYSTEM_ERROR;
		જાઓ fail;
	}
	જો (fclose(f) != 0) {
		r = SSH_ERR_SYSTEM_ERROR;
		f = ખાલી;
 fail:
		જો (f != ખાલી) {
			oerrno = errno;
			fclose(f);
			errno = oerrno;
		}
		પાછા r;
	}
	પાછા 0;
}
