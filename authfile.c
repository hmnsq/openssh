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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/stat.h>

#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <fcntl.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>

#অন্তর্ভাব "log.h"
#অন্তর্ভাব "authfile.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "krl.h"

/* Save a key blob to a file */
স্থির পূর্ণাঙ্ক
sshkey_save_private_blob(সংরচনা sshbuf *keybuf, ধ্রুব বর্ণ *filename)
{
	পূর্ণাঙ্ক r;
	mode_t omask;

	omask = umask(077);
	r = sshbuf_write_file(filename, keybuf);
	umask(omask);
	প্রত্যাগম r;
}

পূর্ণাঙ্ক
sshkey_save_private(সংরচনা sshkey *চাবি, ধ্রুব বর্ণ *filename,
    ধ্রুব বর্ণ *passphrase, ধ্রুব বর্ণ *comment,
    পূর্ণাঙ্ক format, ধ্রুব বর্ণ *openssh_format_cipher, পূর্ণাঙ্ক openssh_format_rounds)
{
	সংরচনা sshbuf *keyblob = রিক্ত;
	পূর্ণাঙ্ক r;

	যদি ((keyblob = sshbuf_new()) == রিক্ত)
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshkey_private_to_fileblob(চাবি, keyblob, passphrase, comment,
	    format, openssh_format_cipher, openssh_format_rounds)) != 0)
		গচ্ছ out;
	যদি ((r = sshkey_save_private_blob(keyblob, filename)) != 0)
		গচ্ছ out;
	r = 0;
 out:
	sshbuf_free(keyblob);
	প্রত্যাগম r;
}

/* XXX remove error() calls from here? */
পূর্ণাঙ্ক
sshkey_perm_ok(পূর্ণাঙ্ক fd, ধ্রুব বর্ণ *filename)
{
	সংরচনা stat st;

	যদি (fstat(fd, &st) == -1)
		প্রত্যাগম SSH_ERR_SYSTEM_ERROR;
	/*
	 * if a key owned by the user is accessed, then we check the
	 * permissions of the file. if the key owned by a different user,
	 * then we don't care.
	 */
#ifdef HAVE_CYGWIN
	যদি (check_ntsec(filename))
#endif
	যদি ((st.st_uid == getuid()) && (st.st_mode & 077) != 0) {
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @");
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("Permissions 0%3.3o for '%s' are too open.",
		    (u_int)st.st_mode & 0777, filename);
		error("It is required that your private key files are NOT accessible by others.");
		error("This private key will be ignored.");
		প্রত্যাগম SSH_ERR_চাবি_BAD_PERMISSIONS;
	}
	প্রত্যাগম 0;
}

পূর্ণাঙ্ক
sshkey_load_private_type(পূর্ণাঙ্ক type, ধ্রুব বর্ণ *filename, ধ্রুব বর্ণ *passphrase,
    সংরচনা sshkey **keyp, বর্ণ **commentp)
{
	পূর্ণাঙ্ক fd, r;

	যদি (keyp != রিক্ত)
		*keyp = রিক্ত;
	যদি (commentp != রিক্ত)
		*commentp = রিক্ত;

	যদি ((fd = open(filename, O_RDONLY)) == -1)
		প্রত্যাগম SSH_ERR_SYSTEM_ERROR;

	r = sshkey_perm_ok(fd, filename);
	যদি (r != 0)
		গচ্ছ out;

	r = sshkey_load_private_type_fd(fd, type, passphrase, keyp, commentp);
 out:
	close(fd);
	প্রত্যাগম r;
}

পূর্ণাঙ্ক
sshkey_load_private(ধ্রুব বর্ণ *filename, ধ্রুব বর্ণ *passphrase,
    সংরচনা sshkey **keyp, বর্ণ **commentp)
{
	প্রত্যাগম sshkey_load_private_type(চাবি_UNSPEC, filename, passphrase,
	    keyp, commentp);
}

পূর্ণাঙ্ক
sshkey_load_private_type_fd(পূর্ণাঙ্ক fd, পূর্ণাঙ্ক type, ধ্রুব বর্ণ *passphrase,
    সংরচনা sshkey **keyp, বর্ণ **commentp)
{
	সংরচনা sshbuf *buffer = রিক্ত;
	পূর্ণাঙ্ক r;

	যদি (keyp != রিক্ত)
		*keyp = রিক্ত;
	যদি ((r = sshbuf_load_fd(fd, &buffer)) != 0 ||
	    (r = sshkey_parse_private_fileblob_type(buffer, type,
	    passphrase, keyp, commentp)) != 0)
		গচ্ছ out;

	/* success */
	r = 0;
 out:
	sshbuf_free(buffer);
	প্রত্যাগম r;
}

/* Load a pubkey from the unencrypted envelope of a new-format private key */
স্থির পূর্ণাঙ্ক
sshkey_load_pubkey_from_private(ধ্রুব বর্ণ *filename, সংরচনা sshkey **pubkeyp)
{
	সংরচনা sshbuf *buffer = রিক্ত;
	সংরচনা sshkey *pubkey = রিক্ত;
	পূর্ণাঙ্ক r, fd;

	যদি (pubkeyp != রিক্ত)
		*pubkeyp = রিক্ত;

	যদি ((fd = open(filename, O_RDONLY)) == -1)
		প্রত্যাগম SSH_ERR_SYSTEM_ERROR;
	যদি ((r = sshbuf_load_fd(fd, &buffer)) != 0 ||
	    (r = sshkey_parse_pubkey_from_private_fileblob_type(buffer,
	    চাবি_UNSPEC, &pubkey)) != 0)
		গচ্ছ out;
	/* success */
	যদি (pubkeyp != রিক্ত) {
		*pubkeyp = pubkey;
		pubkey = রিক্ত;
	}
	r = 0;
 out:
	close(fd);
	sshbuf_free(buffer);
	sshkey_free(pubkey);
	প্রত্যাগম r;
}

স্থির পূর্ণাঙ্ক
sshkey_try_load_public(সংরচনা sshkey **kp, ধ্রুব বর্ণ *filename,
    বর্ণ **commentp)
{
	FILE *f;
	বর্ণ *সারি = রিক্ত, *cp;
	size_t linesize = 0;
	পূর্ণাঙ্ক r;
	সংরচনা stat st;
	সংরচনা sshkey *k = রিক্ত;

	যদি (kp == রিক্ত)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;
	*kp = রিক্ত;
	যদি (commentp != রিক্ত)
		*commentp = রিক্ত;
	যদি ((f = fopen(filename, "r")) == রিক্ত)
		প্রত্যাগম SSH_ERR_SYSTEM_ERROR;
	যদি (fstat(fileno(f), &st) == 0 && S_ISREG(st.st_mode) &&
	    st.st_size > SSHBUF_SIZE_MAX) {
		fclose(f);
		প্রত্যাগম SSH_ERR_INVALID_FORMAT;
	}
	যদি ((k = sshkey_new(চাবি_UNSPEC)) == রিক্ত) {
		fclose(f);
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	}
	যাবত্ (getline(&সারি, &linesize, f) != -1) {
		cp = সারি;
		বিকল্প (*cp) {
		পক্ষ '#':
		পক্ষ '\n':
		পক্ষ '\0':
			অনুবর্ত;
		}
		/* Abort loading if this looks like a private key */
		যদি (strncmp(cp, "-----BEGIN", 10) == 0 ||
		    strcmp(cp, "SSH PRIVATE KEY FILE") == 0)
			ভঙ্গ;
		/* Skip leading whitespace. */
		প্রতি (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;
		যদি (*cp) {
			যদি ((r = sshkey_read(k, &cp)) == 0) {
				cp[strcspn(cp, "\r\n")] = '\0';
				যদি (commentp) {
					*commentp = strdup(*cp ?
					    cp : filename);
					যদি (*commentp == রিক্ত)
						r = SSH_ERR_ALLOC_FAIL;
				}
				/* success */
				*kp = k;
				মুক্ত(সারি);
				fclose(f);
				প্রত্যাগম r;
			}
		}
	}
	মুক্ত(k);
	মুক্ত(সারি);
	fclose(f);
	প্রত্যাগম SSH_ERR_INVALID_FORMAT;
}

/* load public key from any pubkey file */
পূর্ণাঙ্ক
sshkey_load_public(ধ্রুব বর্ণ *filename, সংরচনা sshkey **keyp, বর্ণ **commentp)
{
	বর্ণ *pubfile = রিক্ত;
	পূর্ণাঙ্ক r, oerrno;

	যদি (keyp != রিক্ত)
		*keyp = রিক্ত;
	যদি (commentp != রিক্ত)
		*commentp = রিক্ত;

	যদি ((r = sshkey_try_load_public(keyp, filename, commentp)) == 0)
		গচ্ছ out;

	/* try .pub suffix */
	যদি (asprintf(&pubfile, "%s.pub", filename) == -1)
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshkey_try_load_public(keyp, pubfile, commentp)) == 0)
		গচ্ছ out;

	/* finally, try to extract public key from private key file */
	যদি ((r = sshkey_load_pubkey_from_private(filename, keyp)) == 0)
		গচ্ছ out;

	/* Pretend we couldn't find the key */
	r = SSH_ERR_SYSTEM_ERROR;
	errno = ENOENT;

 out:
	oerrno = errno;
	মুক্ত(pubfile);
	errno = oerrno;
	প্রত্যাগম r;
}

/* Load the certificate associated with the named private key */
পূর্ণাঙ্ক
sshkey_load_cert(ধ্রুব বর্ণ *filename, সংরচনা sshkey **keyp)
{
	সংরচনা sshkey *pub = রিক্ত;
	বর্ণ *file = রিক্ত;
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;

	যদি (keyp != রিক্ত)
		*keyp = রিক্ত;

	যদি (asprintf(&file, "%s-cert.pub", filename) == -1)
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;

	r = sshkey_try_load_public(keyp, file, রিক্ত);
	মুক্ত(file);
	sshkey_free(pub);
	প্রত্যাগম r;
}

/* Load private key and certificate */
পূর্ণাঙ্ক
sshkey_load_private_cert(পূর্ণাঙ্ক type, ধ্রুব বর্ণ *filename, ধ্রুব বর্ণ *passphrase,
    সংরচনা sshkey **keyp)
{
	সংরচনা sshkey *চাবি = রিক্ত, *cert = রিক্ত;
	পূর্ণাঙ্ক r;

	যদি (keyp != রিক্ত)
		*keyp = রিক্ত;

	বিকল্প (type) {
#ifdef WITH_OPENSSL
	পক্ষ চাবি_RSA:
	পক্ষ চাবি_ECDSA:
#endif /* WITH_OPENSSL */
	পক্ষ চাবি_ED25519:
	পক্ষ চাবি_MLDSA44_ED25519:
	পক্ষ চাবি_UNSPEC:
		ভঙ্গ;
	স্বভাব:
		প্রত্যাগম SSH_ERR_চাবি_TYPE_UNKNOWN;
	}

	যদি ((r = sshkey_load_private_type(type, filename,
	    passphrase, &চাবি, রিক্ত)) != 0 ||
	    (r = sshkey_load_cert(filename, &cert)) != 0)
		গচ্ছ out;

	/* Make sure the private key matches the certificate */
	যদি (sshkey_equal_public(চাবি, cert) == 0) {
		r = SSH_ERR_চাবি_CERT_MISMATCH;
		গচ্ছ out;
	}

	যদি ((r = sshkey_to_certified(চাবি)) != 0 ||
	    (r = sshkey_cert_copy(cert, চাবি)) != 0)
		গচ্ছ out;
	r = 0;
	যদি (keyp != রিক্ত) {
		*keyp = চাবি;
		চাবি = রিক্ত;
	}
 out:
	sshkey_free(চাবি);
	sshkey_free(cert);
	প্রত্যাগম r;
}

/*
 * Returns success if the specified "key" is listed in the file "filename",
 * SSH_ERR_KEY_NOT_FOUND: if the key is not listed or another error.
 * If "strict_type" is set then the key type must match exactly,
 * otherwise a comparison that ignores certificate data is performed.
 * If "check_ca" is set and "key" is a certificate, then its CA key is
 * also checked and sshkey_in_file() will return success if either is found.
 */
পূর্ণাঙ্ক
sshkey_in_file(সংরচনা sshkey *চাবি, ধ্রুব বর্ণ *filename, পূর্ণাঙ্ক strict_type,
    পূর্ণাঙ্ক check_ca)
{
	FILE *f;
	বর্ণ *সারি = রিক্ত, *cp;
	size_t linesize = 0;
	পূর্ণাঙ্ক r = 0;
	সংরচনা sshkey *pub = রিক্ত;

	পূর্ণাঙ্ক (*sshkey_compare)(ধ্রুব সংরচনা sshkey *, ধ্রুব সংরচনা sshkey *) =
	    strict_type ?  sshkey_equal : sshkey_equal_public;

	যদি ((f = fopen(filename, "r")) == রিক্ত)
		প্রত্যাগম SSH_ERR_SYSTEM_ERROR;

	যাবত্ (getline(&সারি, &linesize, f) != -1) {
		sshkey_free(pub);
		pub = রিক্ত;
		cp = সারি;

		/* Skip leading whitespace. */
		প্রতি (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;

		/* Skip comments and empty lines */
		বিকল্প (*cp) {
		পক্ষ '#':
		পক্ষ '\n':
		পক্ষ '\0':
			অনুবর্ত;
		}

		যদি ((pub = sshkey_new(চাবি_UNSPEC)) == রিক্ত) {
			r = SSH_ERR_ALLOC_FAIL;
			গচ্ছ out;
		}
		বিকল্প (r = sshkey_read(pub, &cp)) {
		পক্ষ 0:
			ভঙ্গ;
		পক্ষ SSH_ERR_চাবি_LENGTH:
			অনুবর্ত;
		স্বভাব:
			গচ্ছ out;
		}
		যদি (sshkey_compare(চাবি, pub) ||
		    (check_ca && sshkey_is_cert(চাবি) &&
		    sshkey_compare(চাবি->cert->signature_চাবি, pub))) {
			r = 0;
			গচ্ছ out;
		}
	}
	r = SSH_ERR_চাবি_NOT_FOUND;
 out:
	মুক্ত(সারি);
	sshkey_free(pub);
	fclose(f);
	প্রত্যাগম r;
}

/*
 * Checks whether the specified key is revoked, returning 0 if not,
 * SSH_ERR_KEY_REVOKED if it is or another error code if something
 * unexpected happened.
 * This will check both the key and, if it is a certificate, its CA key too.
 * "revoked_keys_file" may be a KRL or a one-per-line list of public keys.
 */
পূর্ণাঙ্ক
sshkey_check_revoked(সংরচনা sshkey *চাবি, ধ্রুব বর্ণ *revoked_চাবিগুলি_file)
{
	পূর্ণাঙ্ক r;

	r = ssh_krl_file_contains_চাবি(revoked_চাবিগুলি_file, চাবি);
	/* If this was not a KRL to begin with then continue below */
	যদি (r != SSH_ERR_KRL_BAD_MAGIC)
		প্রত্যাগম r;

	/*
	 * If the file is not a KRL or we can't handle KRLs then attempt to
	 * parse the file as a flat list of keys.
	 */
	বিকল্প ((r = sshkey_in_file(চাবি, revoked_চাবিগুলি_file, 0, 1))) {
	পক্ষ 0:
		/* Key found => revoked */
		প্রত্যাগম SSH_ERR_চাবি_REVOKED;
	পক্ষ SSH_ERR_চাবি_NOT_FOUND:
		/* Key not found => not revoked */
		প্রত্যাগম 0;
	স্বভাব:
		/* Some other error occurred */
		প্রত্যাগম r;
	}
}

/*
 * Advanced *cpp past the end of key options, defined as the first unquoted
 * whitespace character. Returns 0 on success or -1 on failure (e.g.
 * unterminated quotes).
 */
পূর্ণাঙ্ক
sshkey_advance_past_options(বর্ণ **cpp)
{
	বর্ণ *cp = *cpp;
	পূর্ণাঙ্ক quoted = 0;

	প্রতি (; *cp && (quoted || (*cp != ' ' && *cp != '\t')); cp++) {
		যদি (*cp == '\\' && cp[1] == '"')
			cp++;	/* Skip both */
		অন্যথা যদি (*cp == '"')
			quoted = !quoted;
	}
	*cpp = cp;
	/* return failure for unterminated quotes */
	প্রত্যাগম (*cp == '\0' && quoted) ? -1 : 0;
}

/* Save a public key */
পূর্ণাঙ্ক
sshkey_save_public(ধ্রুব সংরচনা sshkey *চাবি, ধ্রুব বর্ণ *path,
    ধ্রুব বর্ণ *comment)
{
	পূর্ণাঙ্ক fd, oerrno;
	FILE *f = রিক্ত;
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;

	যদি ((fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, 0644)) == -1)
		প্রত্যাগম SSH_ERR_SYSTEM_ERROR;
	যদি ((f = fdopen(fd, "w")) == রিক্ত) {
		r = SSH_ERR_SYSTEM_ERROR;
		close(fd);
		গচ্ছ fail;
	}
	যদি ((r = sshkey_write(চাবি, f)) != 0)
		গচ্ছ fail;
	fprintf(f, " %s\n", comment);
	যদি (ferror(f)) {
		r = SSH_ERR_SYSTEM_ERROR;
		গচ্ছ fail;
	}
	যদি (fclose(f) != 0) {
		r = SSH_ERR_SYSTEM_ERROR;
		f = রিক্ত;
 fail:
		যদি (f != রিক্ত) {
			oerrno = errno;
			fclose(f);
			errno = oerrno;
		}
		প্রত্যাগম r;
	}
	প্রত্যাগম 0;
}
