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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/stat.h>

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <fcntl.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "authfile.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "krl.h"

/* Save a key blob to a file */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_save_private_blob(ସଂରଚନା sshbuf *keybuf, ଅଚଳ ଅକ୍ଷର *filename)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	mode_t omask;

	omask = umask(077);
	r = sshbuf_write_file(filename, keybuf);
	umask(omask);
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_save_private(ସଂରଚନା sshkey *ଚାବି, ଅଚଳ ଅକ୍ଷର *filename,
    ଅଚଳ ଅକ୍ଷର *passphrase, ଅଚଳ ଅକ୍ଷର *comment,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା format, ଅଚଳ ଅକ୍ଷର *openssh_format_cipher, ପୂର୍ଣ୍ଣସଂଖ୍ୟା openssh_format_rounds)
{
	ସଂରଚନା sshbuf *keyblob = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((keyblob = sshbuf_new()) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି ((r = sshkey_private_to_fileblob(ଚାବି, keyblob, passphrase, comment,
	    format, openssh_format_cipher, openssh_format_rounds)) != 0)
		ଯାଅ out;
	ଯଦି ((r = sshkey_save_private_blob(keyblob, filename)) != 0)
		ଯାଅ out;
	r = 0;
 out:
	sshbuf_free(keyblob);
	ଫେରନ୍ତୁ r;
}

/* XXX remove error() calls from here? */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_perm_ok(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, ଅଚଳ ଅକ୍ଷର *filename)
{
	ସଂରଚନା stat st;

	ଯଦି (fstat(fd, &st) == -1)
		ଫେରନ୍ତୁ SSH_ERR_SYSTEM_ERROR;
	/*
	 * if a key owned by the user is accessed, then we check the
	 * permissions of the file. if the key owned by a different user,
	 * then we don't care.
	 */
#ifdef HAVE_CYGWIN
	ଯଦି (check_ntsec(filename))
#endif
	ଯଦି ((st.st_uid == getuid()) && (st.st_mode & 077) != 0) {
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @");
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("Permissions 0%3.3o for '%s' are too open.",
		    (u_int)st.st_mode & 0777, filename);
		error("It is required that your private key files are NOT accessible by others.");
		error("This private key will be ignored.");
		ଫେରନ୍ତୁ SSH_ERR_ଚାବି_BAD_PERMISSIONS;
	}
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_load_private_type(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, ଅଚଳ ଅକ୍ଷର *filename, ଅଚଳ ଅକ୍ଷର *passphrase,
    ସଂରଚନା sshkey **keyp, ଅକ୍ଷର **commentp)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, r;

	ଯଦି (keyp != ଖାଲି)
		*keyp = ଖାଲି;
	ଯଦି (commentp != ଖାଲି)
		*commentp = ଖାଲି;

	ଯଦି ((fd = open(filename, O_RDONLY)) == -1)
		ଫେରନ୍ତୁ SSH_ERR_SYSTEM_ERROR;

	r = sshkey_perm_ok(fd, filename);
	ଯଦି (r != 0)
		ଯାଅ out;

	r = sshkey_load_private_type_fd(fd, type, passphrase, keyp, commentp);
 out:
	close(fd);
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_load_private(ଅଚଳ ଅକ୍ଷର *filename, ଅଚଳ ଅକ୍ଷର *passphrase,
    ସଂରଚନା sshkey **keyp, ଅକ୍ଷର **commentp)
{
	ଫେରନ୍ତୁ sshkey_load_private_type(ଚାବି_UNSPEC, filename, passphrase,
	    keyp, commentp);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_load_private_type_fd(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, ଅଚଳ ଅକ୍ଷର *passphrase,
    ସଂରଚନା sshkey **keyp, ଅକ୍ଷର **commentp)
{
	ସଂରଚନା sshbuf *buffer = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (keyp != ଖାଲି)
		*keyp = ଖାଲି;
	ଯଦି ((r = sshbuf_load_fd(fd, &buffer)) != 0 ||
	    (r = sshkey_parse_private_fileblob_type(buffer, type,
	    passphrase, keyp, commentp)) != 0)
		ଯାଅ out;

	/* success */
	r = 0;
 out:
	sshbuf_free(buffer);
	ଫେରନ୍ତୁ r;
}

/* Load a pubkey from the unencrypted envelope of a new-format private key */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_load_pubkey_from_private(ଅଚଳ ଅକ୍ଷର *filename, ସଂରଚନା sshkey **pubkeyp)
{
	ସଂରଚନା sshbuf *buffer = ଖାଲି;
	ସଂରଚନା sshkey *pubkey = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, fd;

	ଯଦି (pubkeyp != ଖାଲି)
		*pubkeyp = ଖାଲି;

	ଯଦି ((fd = open(filename, O_RDONLY)) == -1)
		ଫେରନ୍ତୁ SSH_ERR_SYSTEM_ERROR;
	ଯଦି ((r = sshbuf_load_fd(fd, &buffer)) != 0 ||
	    (r = sshkey_parse_pubkey_from_private_fileblob_type(buffer,
	    ଚାବି_UNSPEC, &pubkey)) != 0)
		ଯାଅ out;
	/* success */
	ଯଦି (pubkeyp != ଖାଲି) {
		*pubkeyp = pubkey;
		pubkey = ଖାଲି;
	}
	r = 0;
 out:
	close(fd);
	sshbuf_free(buffer);
	sshkey_free(pubkey);
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_try_load_public(ସଂରଚନା sshkey **kp, ଅଚଳ ଅକ୍ଷର *filename,
    ଅକ୍ଷର **commentp)
{
	FILE *f;
	ଅକ୍ଷର *ଧାଡ଼ି = ଖାଲି, *cp;
	size_t linesize = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ସଂରଚନା stat st;
	ସଂରଚନା sshkey *k = ଖାଲି;

	ଯଦି (kp == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	*kp = ଖାଲି;
	ଯଦି (commentp != ଖାଲି)
		*commentp = ଖାଲି;
	ଯଦି ((f = fopen(filename, "r")) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_SYSTEM_ERROR;
	ଯଦି (fstat(fileno(f), &st) == 0 && S_ISREG(st.st_mode) &&
	    st.st_size > SSHBUF_SIZE_MAX) {
		fclose(f);
		ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
	}
	ଯଦି ((k = sshkey_new(ଚାବି_UNSPEC)) == ଖାଲି) {
		fclose(f);
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	}
	ଯେତେବେଳେ (getline(&ଧାଡ଼ି, &linesize, f) != -1) {
		cp = ଧାଡ଼ି;
		ବାଛ (*cp) {
		ସ୍ଥିତି '#':
		ସ୍ଥିତି '\n':
		ସ୍ଥିତି '\0':
			ଜାରି;
		}
		/* Abort loading if this looks like a private key */
		ଯଦି (strncmp(cp, "-----BEGIN", 10) == 0 ||
		    strcmp(cp, "SSH PRIVATE KEY FILE") == 0)
			ଭାଙ୍ଗ;
		/* Skip leading whitespace. */
		ପାଇଁ (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;
		ଯଦି (*cp) {
			ଯଦି ((r = sshkey_read(k, &cp)) == 0) {
				cp[strcspn(cp, "\r\n")] = '\0';
				ଯଦି (commentp) {
					*commentp = strdup(*cp ?
					    cp : filename);
					ଯଦି (*commentp == ଖାଲି)
						r = SSH_ERR_ALLOC_FAIL;
				}
				/* success */
				*kp = k;
				ମୁକ୍ତ(ଧାଡ଼ି);
				fclose(f);
				ଫେରନ୍ତୁ r;
			}
		}
	}
	ମୁକ୍ତ(k);
	ମୁକ୍ତ(ଧାଡ଼ି);
	fclose(f);
	ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
}

/* load public key from any pubkey file */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_load_public(ଅଚଳ ଅକ୍ଷର *filename, ସଂରଚନା sshkey **keyp, ଅକ୍ଷର **commentp)
{
	ଅକ୍ଷର *pubfile = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, oerrno;

	ଯଦି (keyp != ଖାଲି)
		*keyp = ଖାଲି;
	ଯଦି (commentp != ଖାଲି)
		*commentp = ଖାଲି;

	ଯଦି ((r = sshkey_try_load_public(keyp, filename, commentp)) == 0)
		ଯାଅ out;

	/* try .pub suffix */
	ଯଦି (asprintf(&pubfile, "%s.pub", filename) == -1)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି ((r = sshkey_try_load_public(keyp, pubfile, commentp)) == 0)
		ଯାଅ out;

	/* finally, try to extract public key from private key file */
	ଯଦି ((r = sshkey_load_pubkey_from_private(filename, keyp)) == 0)
		ଯାଅ out;

	/* Pretend we couldn't find the key */
	r = SSH_ERR_SYSTEM_ERROR;
	errno = ENOENT;

 out:
	oerrno = errno;
	ମୁକ୍ତ(pubfile);
	errno = oerrno;
	ଫେରନ୍ତୁ r;
}

/* Load the certificate associated with the named private key */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_load_cert(ଅଚଳ ଅକ୍ଷର *filename, ସଂରଚନା sshkey **keyp)
{
	ସଂରଚନା sshkey *pub = ଖାଲି;
	ଅକ୍ଷର *file = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;

	ଯଦି (keyp != ଖାଲି)
		*keyp = ଖାଲି;

	ଯଦି (asprintf(&file, "%s-cert.pub", filename) == -1)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;

	r = sshkey_try_load_public(keyp, file, ଖାଲି);
	ମୁକ୍ତ(file);
	sshkey_free(pub);
	ଫେରନ୍ତୁ r;
}

/* Load private key and certificate */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_load_private_cert(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, ଅଚଳ ଅକ୍ଷର *filename, ଅଚଳ ଅକ୍ଷର *passphrase,
    ସଂରଚନା sshkey **keyp)
{
	ସଂରଚନା sshkey *ଚାବି = ଖାଲି, *cert = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (keyp != ଖାଲି)
		*keyp = ଖାଲି;

	ବାଛ (type) {
#ifdef WITH_OPENSSL
	ସ୍ଥିତି ଚାବି_RSA:
	ସ୍ଥିତି ଚାବି_ECDSA:
#endif /* WITH_OPENSSL */
	ସ୍ଥିତି ଚାବି_ED25519:
	ସ୍ଥିତି ଚାବି_MLDSA44_ED25519:
	ସ୍ଥିତି ଚାବି_UNSPEC:
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ SSH_ERR_ଚାବି_TYPE_UNKNOWN;
	}

	ଯଦି ((r = sshkey_load_private_type(type, filename,
	    passphrase, &ଚାବି, ଖାଲି)) != 0 ||
	    (r = sshkey_load_cert(filename, &cert)) != 0)
		ଯାଅ out;

	/* Make sure the private key matches the certificate */
	ଯଦି (sshkey_equal_public(ଚାବି, cert) == 0) {
		r = SSH_ERR_ଚାବି_CERT_MISMATCH;
		ଯାଅ out;
	}

	ଯଦି ((r = sshkey_to_certified(ଚାବି)) != 0 ||
	    (r = sshkey_cert_copy(cert, ଚାବି)) != 0)
		ଯାଅ out;
	r = 0;
	ଯଦି (keyp != ଖାଲି) {
		*keyp = ଚାବି;
		ଚାବି = ଖାଲି;
	}
 out:
	sshkey_free(ଚାବି);
	sshkey_free(cert);
	ଫେରନ୍ତୁ r;
}

/*
 * Returns success if the specified "key" is listed in the file "filename",
 * SSH_ERR_KEY_NOT_FOUND: if the key is not listed or another error.
 * If "strict_type" is set then the key type must match exactly,
 * otherwise a comparison that ignores certificate data is performed.
 * If "check_ca" is set and "key" is a certificate, then its CA key is
 * also checked and sshkey_in_file() will return success if either is found.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_in_file(ସଂରଚନା sshkey *ଚାବି, ଅଚଳ ଅକ୍ଷର *filename, ପୂର୍ଣ୍ଣସଂଖ୍ୟା strict_type,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା check_ca)
{
	FILE *f;
	ଅକ୍ଷର *ଧାଡ଼ି = ଖାଲି, *cp;
	size_t linesize = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = 0;
	ସଂରଚନା sshkey *pub = ଖାଲି;

	ପୂର୍ଣ୍ଣସଂଖ୍ୟା (*sshkey_compare)(ଅଚଳ ସଂରଚନା sshkey *, ଅଚଳ ସଂରଚନା sshkey *) =
	    strict_type ?  sshkey_equal : sshkey_equal_public;

	ଯଦି ((f = fopen(filename, "r")) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_SYSTEM_ERROR;

	ଯେତେବେଳେ (getline(&ଧାଡ଼ି, &linesize, f) != -1) {
		sshkey_free(pub);
		pub = ଖାଲି;
		cp = ଧାଡ଼ି;

		/* Skip leading whitespace. */
		ପାଇଁ (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;

		/* Skip comments and empty lines */
		ବାଛ (*cp) {
		ସ୍ଥିତି '#':
		ସ୍ଥିତି '\n':
		ସ୍ଥିତି '\0':
			ଜାରି;
		}

		ଯଦି ((pub = sshkey_new(ଚାବି_UNSPEC)) == ଖାଲି) {
			r = SSH_ERR_ALLOC_FAIL;
			ଯାଅ out;
		}
		ବାଛ (r = sshkey_read(pub, &cp)) {
		ସ୍ଥିତି 0:
			ଭାଙ୍ଗ;
		ସ୍ଥିତି SSH_ERR_ଚାବି_LENGTH:
			ଜାରି;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			ଯାଅ out;
		}
		ଯଦି (sshkey_compare(ଚାବି, pub) ||
		    (check_ca && sshkey_is_cert(ଚାବି) &&
		    sshkey_compare(ଚାବି->cert->signature_ଚାବି, pub))) {
			r = 0;
			ଯାଅ out;
		}
	}
	r = SSH_ERR_ଚାବି_NOT_FOUND;
 out:
	ମୁକ୍ତ(ଧାଡ଼ି);
	sshkey_free(pub);
	fclose(f);
	ଫେରନ୍ତୁ r;
}

/*
 * Checks whether the specified key is revoked, returning 0 if not,
 * SSH_ERR_KEY_REVOKED if it is or another error code if something
 * unexpected happened.
 * This will check both the key and, if it is a certificate, its CA key too.
 * "revoked_keys_file" may be a KRL or a one-per-line list of public keys.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_check_revoked(ସଂରଚନା sshkey *ଚାବି, ଅଚଳ ଅକ୍ଷର *revoked_ଚାବିଗୁଡ଼ିକ_file)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	r = ssh_krl_file_contains_ଚାବି(revoked_ଚାବିଗୁଡ଼ିକ_file, ଚାବି);
	/* If this was not a KRL to begin with then continue below */
	ଯଦି (r != SSH_ERR_KRL_BAD_MAGIC)
		ଫେରନ୍ତୁ r;

	/*
	 * If the file is not a KRL or we can't handle KRLs then attempt to
	 * parse the file as a flat list of keys.
	 */
	ବାଛ ((r = sshkey_in_file(ଚାବି, revoked_ଚାବିଗୁଡ଼ିକ_file, 0, 1))) {
	ସ୍ଥିତି 0:
		/* Key found => revoked */
		ଫେରନ୍ତୁ SSH_ERR_ଚାବି_REVOKED;
	ସ୍ଥିତି SSH_ERR_ଚାବି_NOT_FOUND:
		/* Key not found => not revoked */
		ଫେରନ୍ତୁ 0;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		/* Some other error occurred */
		ଫେରନ୍ତୁ r;
	}
}

/*
 * Advanced *cpp past the end of key options, defined as the first unquoted
 * whitespace character. Returns 0 on success or -1 on failure (e.g.
 * unterminated quotes).
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_advance_past_options(ଅକ୍ଷର **cpp)
{
	ଅକ୍ଷର *cp = *cpp;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା quoted = 0;

	ପାଇଁ (; *cp && (quoted || (*cp != ' ' && *cp != '\t')); cp++) {
		ଯଦି (*cp == '\\' && cp[1] == '"')
			cp++;	/* Skip both */
		ଅନ୍ୟଥା ଯଦି (*cp == '"')
			quoted = !quoted;
	}
	*cpp = cp;
	/* return failure for unterminated quotes */
	ଫେରନ୍ତୁ (*cp == '\0' && quoted) ? -1 : 0;
}

/* Save a public key */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_save_public(ଅଚଳ ସଂରଚନା sshkey *ଚାବି, ଅଚଳ ଅକ୍ଷର *path,
    ଅଚଳ ଅକ୍ଷର *comment)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, oerrno;
	FILE *f = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;

	ଯଦି ((fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, 0644)) == -1)
		ଫେରନ୍ତୁ SSH_ERR_SYSTEM_ERROR;
	ଯଦି ((f = fdopen(fd, "w")) == ଖାଲି) {
		r = SSH_ERR_SYSTEM_ERROR;
		close(fd);
		ଯାଅ fail;
	}
	ଯଦି ((r = sshkey_write(ଚାବି, f)) != 0)
		ଯାଅ fail;
	fprintf(f, " %s\n", comment);
	ଯଦି (ferror(f)) {
		r = SSH_ERR_SYSTEM_ERROR;
		ଯାଅ fail;
	}
	ଯଦି (fclose(f) != 0) {
		r = SSH_ERR_SYSTEM_ERROR;
		f = ଖାଲି;
 fail:
		ଯଦି (f != ଖାଲି) {
			oerrno = errno;
			fclose(f);
			errno = oerrno;
		}
		ଫେରନ୍ତୁ r;
	}
	ଫେରନ୍ତୁ 0;
}
