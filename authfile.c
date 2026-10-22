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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/stat.h>

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <fcntl.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>

#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "authfile.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "krl.h"

/* Save a key blob to a file */
സ്ഥിതം പൂർണ്ണസംഖ്യ
sshkey_save_private_blob(ഘടന sshbuf *keybuf, സ്ഥിരം അക്ഷരം *filename)
{
	പൂർണ്ണസംഖ്യ r;
	mode_t omask;

	omask = umask(077);
	r = sshbuf_write_file(filename, keybuf);
	umask(omask);
	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
sshkey_save_private(ഘടന sshkey *താക്കോൽ, സ്ഥിരം അക്ഷരം *filename,
    സ്ഥിരം അക്ഷരം *passphrase, സ്ഥിരം അക്ഷരം *comment,
    പൂർണ്ണസംഖ്യ format, സ്ഥിരം അക്ഷരം *openssh_format_cipher, പൂർണ്ണസംഖ്യ openssh_format_rounds)
{
	ഘടന sshbuf *keyblob = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((keyblob = sshbuf_new()) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	എങ്കിൽ ((r = sshkey_private_to_fileblob(താക്കോൽ, keyblob, passphrase, comment,
	    format, openssh_format_cipher, openssh_format_rounds)) != 0)
		പോകുക out;
	എങ്കിൽ ((r = sshkey_save_private_blob(keyblob, filename)) != 0)
		പോകുക out;
	r = 0;
 out:
	sshbuf_free(keyblob);
	തിരികെ r;
}

/* XXX remove error() calls from here? */
പൂർണ്ണസംഖ്യ
sshkey_perm_ok(പൂർണ്ണസംഖ്യ fd, സ്ഥിരം അക്ഷരം *filename)
{
	ഘടന stat st;

	എങ്കിൽ (fstat(fd, &st) == -1)
		തിരികെ SSH_ERR_SYSTEM_ERROR;
	/*
	 * if a key owned by the user is accessed, then we check the
	 * permissions of the file. if the key owned by a different user,
	 * then we don't care.
	 */
#ifdef HAVE_CYGWIN
	എങ്കിൽ (check_ntsec(filename))
#endif
	എങ്കിൽ ((st.st_uid == getuid()) && (st.st_mode & 077) != 0) {
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @");
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("Permissions 0%3.3o for '%s' are too open.",
		    (u_int)st.st_mode & 0777, filename);
		error("It is required that your private key files are NOT accessible by others.");
		error("This private key will be ignored.");
		തിരികെ SSH_ERR_താക്കോൽ_BAD_PERMISSIONS;
	}
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshkey_load_private_type(പൂർണ്ണസംഖ്യ type, സ്ഥിരം അക്ഷരം *filename, സ്ഥിരം അക്ഷരം *passphrase,
    ഘടന sshkey **keyp, അക്ഷരം **commentp)
{
	പൂർണ്ണസംഖ്യ fd, r;

	എങ്കിൽ (keyp != ശൂന്യ)
		*keyp = ശൂന്യ;
	എങ്കിൽ (commentp != ശൂന്യ)
		*commentp = ശൂന്യ;

	എങ്കിൽ ((fd = open(filename, O_RDONLY)) == -1)
		തിരികെ SSH_ERR_SYSTEM_ERROR;

	r = sshkey_perm_ok(fd, filename);
	എങ്കിൽ (r != 0)
		പോകുക out;

	r = sshkey_load_private_type_fd(fd, type, passphrase, keyp, commentp);
 out:
	close(fd);
	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
sshkey_load_private(സ്ഥിരം അക്ഷരം *filename, സ്ഥിരം അക്ഷരം *passphrase,
    ഘടന sshkey **keyp, അക്ഷരം **commentp)
{
	തിരികെ sshkey_load_private_type(താക്കോൽ_UNSPEC, filename, passphrase,
	    keyp, commentp);
}

പൂർണ്ണസംഖ്യ
sshkey_load_private_type_fd(പൂർണ്ണസംഖ്യ fd, പൂർണ്ണസംഖ്യ type, സ്ഥിരം അക്ഷരം *passphrase,
    ഘടന sshkey **keyp, അക്ഷരം **commentp)
{
	ഘടന sshbuf *buffer = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (keyp != ശൂന്യ)
		*keyp = ശൂന്യ;
	എങ്കിൽ ((r = sshbuf_load_fd(fd, &buffer)) != 0 ||
	    (r = sshkey_parse_private_fileblob_type(buffer, type,
	    passphrase, keyp, commentp)) != 0)
		പോകുക out;

	/* success */
	r = 0;
 out:
	sshbuf_free(buffer);
	തിരികെ r;
}

/* Load a pubkey from the unencrypted envelope of a new-format private key */
സ്ഥിതം പൂർണ്ണസംഖ്യ
sshkey_load_pubkey_from_private(സ്ഥിരം അക്ഷരം *filename, ഘടന sshkey **pubkeyp)
{
	ഘടന sshbuf *buffer = ശൂന്യ;
	ഘടന sshkey *pubkey = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r, fd;

	എങ്കിൽ (pubkeyp != ശൂന്യ)
		*pubkeyp = ശൂന്യ;

	എങ്കിൽ ((fd = open(filename, O_RDONLY)) == -1)
		തിരികെ SSH_ERR_SYSTEM_ERROR;
	എങ്കിൽ ((r = sshbuf_load_fd(fd, &buffer)) != 0 ||
	    (r = sshkey_parse_pubkey_from_private_fileblob_type(buffer,
	    താക്കോൽ_UNSPEC, &pubkey)) != 0)
		പോകുക out;
	/* success */
	എങ്കിൽ (pubkeyp != ശൂന്യ) {
		*pubkeyp = pubkey;
		pubkey = ശൂന്യ;
	}
	r = 0;
 out:
	close(fd);
	sshbuf_free(buffer);
	sshkey_free(pubkey);
	തിരികെ r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
sshkey_try_load_public(ഘടന sshkey **kp, സ്ഥിരം അക്ഷരം *filename,
    അക്ഷരം **commentp)
{
	FILE *f;
	അക്ഷരം *വരി = ശൂന്യ, *cp;
	size_t linesize = 0;
	പൂർണ്ണസംഖ്യ r;
	ഘടന stat st;
	ഘടന sshkey *k = ശൂന്യ;

	എങ്കിൽ (kp == ശൂന്യ)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	*kp = ശൂന്യ;
	എങ്കിൽ (commentp != ശൂന്യ)
		*commentp = ശൂന്യ;
	എങ്കിൽ ((f = fopen(filename, "r")) == ശൂന്യ)
		തിരികെ SSH_ERR_SYSTEM_ERROR;
	എങ്കിൽ (fstat(fileno(f), &st) == 0 && S_ISREG(st.st_mode) &&
	    st.st_size > SSHBUF_SIZE_MAX) {
		fclose(f);
		തിരികെ SSH_ERR_INVALID_FORMAT;
	}
	എങ്കിൽ ((k = sshkey_new(താക്കോൽ_UNSPEC)) == ശൂന്യ) {
		fclose(f);
		തിരികെ SSH_ERR_ALLOC_FAIL;
	}
	ആകുമ്പോൾ (getline(&വരി, &linesize, f) != -1) {
		cp = വരി;
		തിരഞ്ഞെടുപ്പ് (*cp) {
		അവസ്ഥ '#':
		അവസ്ഥ '\n':
		അവസ്ഥ '\0':
			തുടരുക;
		}
		/* Abort loading if this looks like a private key */
		എങ്കിൽ (strncmp(cp, "-----BEGIN", 10) == 0 ||
		    strcmp(cp, "SSH PRIVATE KEY FILE") == 0)
			നിർത്തുക;
		/* Skip leading whitespace. */
		വേണ്ടി (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;
		എങ്കിൽ (*cp) {
			എങ്കിൽ ((r = sshkey_read(k, &cp)) == 0) {
				cp[strcspn(cp, "\r\n")] = '\0';
				എങ്കിൽ (commentp) {
					*commentp = strdup(*cp ?
					    cp : filename);
					എങ്കിൽ (*commentp == ശൂന്യ)
						r = SSH_ERR_ALLOC_FAIL;
				}
				/* success */
				*kp = k;
				സ്വതന്ത്രം(വരി);
				fclose(f);
				തിരികെ r;
			}
		}
	}
	സ്വതന്ത്രം(k);
	സ്വതന്ത്രം(വരി);
	fclose(f);
	തിരികെ SSH_ERR_INVALID_FORMAT;
}

/* load public key from any pubkey file */
പൂർണ്ണസംഖ്യ
sshkey_load_public(സ്ഥിരം അക്ഷരം *filename, ഘടന sshkey **keyp, അക്ഷരം **commentp)
{
	അക്ഷരം *pubfile = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r, oerrno;

	എങ്കിൽ (keyp != ശൂന്യ)
		*keyp = ശൂന്യ;
	എങ്കിൽ (commentp != ശൂന്യ)
		*commentp = ശൂന്യ;

	എങ്കിൽ ((r = sshkey_try_load_public(keyp, filename, commentp)) == 0)
		പോകുക out;

	/* try .pub suffix */
	എങ്കിൽ (asprintf(&pubfile, "%s.pub", filename) == -1)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	എങ്കിൽ ((r = sshkey_try_load_public(keyp, pubfile, commentp)) == 0)
		പോകുക out;

	/* finally, try to extract public key from private key file */
	എങ്കിൽ ((r = sshkey_load_pubkey_from_private(filename, keyp)) == 0)
		പോകുക out;

	/* Pretend we couldn't find the key */
	r = SSH_ERR_SYSTEM_ERROR;
	errno = ENOENT;

 out:
	oerrno = errno;
	സ്വതന്ത്രം(pubfile);
	errno = oerrno;
	തിരികെ r;
}

/* Load the certificate associated with the named private key */
പൂർണ്ണസംഖ്യ
sshkey_load_cert(സ്ഥിരം അക്ഷരം *filename, ഘടന sshkey **keyp)
{
	ഘടന sshkey *pub = ശൂന്യ;
	അക്ഷരം *file = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;

	എങ്കിൽ (keyp != ശൂന്യ)
		*keyp = ശൂന്യ;

	എങ്കിൽ (asprintf(&file, "%s-cert.pub", filename) == -1)
		തിരികെ SSH_ERR_ALLOC_FAIL;

	r = sshkey_try_load_public(keyp, file, ശൂന്യ);
	സ്വതന്ത്രം(file);
	sshkey_free(pub);
	തിരികെ r;
}

/* Load private key and certificate */
പൂർണ്ണസംഖ്യ
sshkey_load_private_cert(പൂർണ്ണസംഖ്യ type, സ്ഥിരം അക്ഷരം *filename, സ്ഥിരം അക്ഷരം *passphrase,
    ഘടന sshkey **keyp)
{
	ഘടന sshkey *താക്കോൽ = ശൂന്യ, *cert = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (keyp != ശൂന്യ)
		*keyp = ശൂന്യ;

	തിരഞ്ഞെടുപ്പ് (type) {
#ifdef WITH_OPENSSL
	അവസ്ഥ താക്കോൽ_RSA:
	അവസ്ഥ താക്കോൽ_ECDSA:
#endif /* WITH_OPENSSL */
	അവസ്ഥ താക്കോൽ_ED25519:
	അവസ്ഥ താക്കോൽ_MLDSA44_ED25519:
	അവസ്ഥ താക്കോൽ_UNSPEC:
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		തിരികെ SSH_ERR_താക്കോൽ_TYPE_UNKNOWN;
	}

	എങ്കിൽ ((r = sshkey_load_private_type(type, filename,
	    passphrase, &താക്കോൽ, ശൂന്യ)) != 0 ||
	    (r = sshkey_load_cert(filename, &cert)) != 0)
		പോകുക out;

	/* Make sure the private key matches the certificate */
	എങ്കിൽ (sshkey_equal_public(താക്കോൽ, cert) == 0) {
		r = SSH_ERR_താക്കോൽ_CERT_MISMATCH;
		പോകുക out;
	}

	എങ്കിൽ ((r = sshkey_to_certified(താക്കോൽ)) != 0 ||
	    (r = sshkey_cert_copy(cert, താക്കോൽ)) != 0)
		പോകുക out;
	r = 0;
	എങ്കിൽ (keyp != ശൂന്യ) {
		*keyp = താക്കോൽ;
		താക്കോൽ = ശൂന്യ;
	}
 out:
	sshkey_free(താക്കോൽ);
	sshkey_free(cert);
	തിരികെ r;
}

/*
 * Returns success if the specified "key" is listed in the file "filename",
 * SSH_ERR_KEY_NOT_FOUND: if the key is not listed or another error.
 * If "strict_type" is set then the key type must match exactly,
 * otherwise a comparison that ignores certificate data is performed.
 * If "check_ca" is set and "key" is a certificate, then its CA key is
 * also checked and sshkey_in_file() will return success if either is found.
 */
പൂർണ്ണസംഖ്യ
sshkey_in_file(ഘടന sshkey *താക്കോൽ, സ്ഥിരം അക്ഷരം *filename, പൂർണ്ണസംഖ്യ strict_type,
    പൂർണ്ണസംഖ്യ check_ca)
{
	FILE *f;
	അക്ഷരം *വരി = ശൂന്യ, *cp;
	size_t linesize = 0;
	പൂർണ്ണസംഖ്യ r = 0;
	ഘടന sshkey *pub = ശൂന്യ;

	പൂർണ്ണസംഖ്യ (*sshkey_compare)(സ്ഥിരം ഘടന sshkey *, സ്ഥിരം ഘടന sshkey *) =
	    strict_type ?  sshkey_equal : sshkey_equal_public;

	എങ്കിൽ ((f = fopen(filename, "r")) == ശൂന്യ)
		തിരികെ SSH_ERR_SYSTEM_ERROR;

	ആകുമ്പോൾ (getline(&വരി, &linesize, f) != -1) {
		sshkey_free(pub);
		pub = ശൂന്യ;
		cp = വരി;

		/* Skip leading whitespace. */
		വേണ്ടി (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;

		/* Skip comments and empty lines */
		തിരഞ്ഞെടുപ്പ് (*cp) {
		അവസ്ഥ '#':
		അവസ്ഥ '\n':
		അവസ്ഥ '\0':
			തുടരുക;
		}

		എങ്കിൽ ((pub = sshkey_new(താക്കോൽ_UNSPEC)) == ശൂന്യ) {
			r = SSH_ERR_ALLOC_FAIL;
			പോകുക out;
		}
		തിരഞ്ഞെടുപ്പ് (r = sshkey_read(pub, &cp)) {
		അവസ്ഥ 0:
			നിർത്തുക;
		അവസ്ഥ SSH_ERR_താക്കോൽ_LENGTH:
			തുടരുക;
		സ്ഥിരസ്ഥിതി:
			പോകുക out;
		}
		എങ്കിൽ (sshkey_compare(താക്കോൽ, pub) ||
		    (check_ca && sshkey_is_cert(താക്കോൽ) &&
		    sshkey_compare(താക്കോൽ->cert->signature_താക്കോൽ, pub))) {
			r = 0;
			പോകുക out;
		}
	}
	r = SSH_ERR_താക്കോൽ_NOT_FOUND;
 out:
	സ്വതന്ത്രം(വരി);
	sshkey_free(pub);
	fclose(f);
	തിരികെ r;
}

/*
 * Checks whether the specified key is revoked, returning 0 if not,
 * SSH_ERR_KEY_REVOKED if it is or another error code if something
 * unexpected happened.
 * This will check both the key and, if it is a certificate, its CA key too.
 * "revoked_keys_file" may be a KRL or a one-per-line list of public keys.
 */
പൂർണ്ണസംഖ്യ
sshkey_check_revoked(ഘടന sshkey *താക്കോൽ, സ്ഥിരം അക്ഷരം *revoked_താക്കോലുകൾ_file)
{
	പൂർണ്ണസംഖ്യ r;

	r = ssh_krl_file_contains_താക്കോൽ(revoked_താക്കോലുകൾ_file, താക്കോൽ);
	/* If this was not a KRL to begin with then continue below */
	എങ്കിൽ (r != SSH_ERR_KRL_BAD_MAGIC)
		തിരികെ r;

	/*
	 * If the file is not a KRL or we can't handle KRLs then attempt to
	 * parse the file as a flat list of keys.
	 */
	തിരഞ്ഞെടുപ്പ് ((r = sshkey_in_file(താക്കോൽ, revoked_താക്കോലുകൾ_file, 0, 1))) {
	അവസ്ഥ 0:
		/* Key found => revoked */
		തിരികെ SSH_ERR_താക്കോൽ_REVOKED;
	അവസ്ഥ SSH_ERR_താക്കോൽ_NOT_FOUND:
		/* Key not found => not revoked */
		തിരികെ 0;
	സ്ഥിരസ്ഥിതി:
		/* Some other error occurred */
		തിരികെ r;
	}
}

/*
 * Advanced *cpp past the end of key options, defined as the first unquoted
 * whitespace character. Returns 0 on success or -1 on failure (e.g.
 * unterminated quotes).
 */
പൂർണ്ണസംഖ്യ
sshkey_advance_past_options(അക്ഷരം **cpp)
{
	അക്ഷരം *cp = *cpp;
	പൂർണ്ണസംഖ്യ quoted = 0;

	വേണ്ടി (; *cp && (quoted || (*cp != ' ' && *cp != '\t')); cp++) {
		എങ്കിൽ (*cp == '\\' && cp[1] == '"')
			cp++;	/* Skip both */
		അല്ലെങ്കിൽ എങ്കിൽ (*cp == '"')
			quoted = !quoted;
	}
	*cpp = cp;
	/* return failure for unterminated quotes */
	തിരികെ (*cp == '\0' && quoted) ? -1 : 0;
}

/* Save a public key */
പൂർണ്ണസംഖ്യ
sshkey_save_public(സ്ഥിരം ഘടന sshkey *താക്കോൽ, സ്ഥിരം അക്ഷരം *path,
    സ്ഥിരം അക്ഷരം *comment)
{
	പൂർണ്ണസംഖ്യ fd, oerrno;
	FILE *f = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;

	എങ്കിൽ ((fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, 0644)) == -1)
		തിരികെ SSH_ERR_SYSTEM_ERROR;
	എങ്കിൽ ((f = fdopen(fd, "w")) == ശൂന്യ) {
		r = SSH_ERR_SYSTEM_ERROR;
		close(fd);
		പോകുക fail;
	}
	എങ്കിൽ ((r = sshkey_write(താക്കോൽ, f)) != 0)
		പോകുക fail;
	fprintf(f, " %s\n", comment);
	എങ്കിൽ (ferror(f)) {
		r = SSH_ERR_SYSTEM_ERROR;
		പോകുക fail;
	}
	എങ്കിൽ (fclose(f) != 0) {
		r = SSH_ERR_SYSTEM_ERROR;
		f = ശൂന്യ;
 fail:
		എങ്കിൽ (f != ശൂന്യ) {
			oerrno = errno;
			fclose(f);
			errno = oerrno;
		}
		തിരികെ r;
	}
	തിരികെ 0;
}
