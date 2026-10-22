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
স্থির পূর্ণসংখ্যা
sshkey_save_private_blob(কাঠামো sshbuf *keybuf, ধ্রুবক অক্ষর *filename)
{
	পূর্ণসংখ্যা r;
	mode_t omask;

	omask = umask(077);
	r = sshbuf_write_file(filename, keybuf);
	umask(omask);
	ফেরত r;
}

পূর্ণসংখ্যা
sshkey_save_private(কাঠামো sshkey *চাবি, ধ্রুবক অক্ষর *filename,
    ধ্রুবক অক্ষর *passphrase, ধ্রুবক অক্ষর *comment,
    পূর্ণসংখ্যা format, ধ্রুবক অক্ষর *openssh_format_cipher, পূর্ণসংখ্যা openssh_format_rounds)
{
	কাঠামো sshbuf *keyblob = ফাঁকা;
	পূর্ণসংখ্যা r;

	যদি ((keyblob = sshbuf_new()) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshkey_private_to_fileblob(চাবি, keyblob, passphrase, comment,
	    format, openssh_format_cipher, openssh_format_rounds)) != 0)
		যাও out;
	যদি ((r = sshkey_save_private_blob(keyblob, filename)) != 0)
		যাও out;
	r = 0;
 out:
	sshbuf_free(keyblob);
	ফেরত r;
}

/* XXX remove error() calls from here? */
পূর্ণসংখ্যা
sshkey_perm_ok(পূর্ণসংখ্যা fd, ধ্রুবক অক্ষর *filename)
{
	কাঠামো stat st;

	যদি (fstat(fd, &st) == -1)
		ফেরত SSH_ERR_SYSTEM_ERROR;
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
		ফেরত SSH_ERR_চাবি_BAD_PERMISSIONS;
	}
	ফেরত 0;
}

পূর্ণসংখ্যা
sshkey_load_private_type(পূর্ণসংখ্যা type, ধ্রুবক অক্ষর *filename, ধ্রুবক অক্ষর *passphrase,
    কাঠামো sshkey **keyp, অক্ষর **commentp)
{
	পূর্ণসংখ্যা fd, r;

	যদি (keyp != ফাঁকা)
		*keyp = ফাঁকা;
	যদি (commentp != ফাঁকা)
		*commentp = ফাঁকা;

	যদি ((fd = open(filename, O_RDONLY)) == -1)
		ফেরত SSH_ERR_SYSTEM_ERROR;

	r = sshkey_perm_ok(fd, filename);
	যদি (r != 0)
		যাও out;

	r = sshkey_load_private_type_fd(fd, type, passphrase, keyp, commentp);
 out:
	close(fd);
	ফেরত r;
}

পূর্ণসংখ্যা
sshkey_load_private(ধ্রুবক অক্ষর *filename, ধ্রুবক অক্ষর *passphrase,
    কাঠামো sshkey **keyp, অক্ষর **commentp)
{
	ফেরত sshkey_load_private_type(চাবি_UNSPEC, filename, passphrase,
	    keyp, commentp);
}

পূর্ণসংখ্যা
sshkey_load_private_type_fd(পূর্ণসংখ্যা fd, পূর্ণসংখ্যা type, ধ্রুবক অক্ষর *passphrase,
    কাঠামো sshkey **keyp, অক্ষর **commentp)
{
	কাঠামো sshbuf *বাফার = ফাঁকা;
	পূর্ণসংখ্যা r;

	যদি (keyp != ফাঁকা)
		*keyp = ফাঁকা;
	যদি ((r = sshbuf_load_fd(fd, &বাফার)) != 0 ||
	    (r = sshkey_parse_private_fileblob_type(বাফার, type,
	    passphrase, keyp, commentp)) != 0)
		যাও out;

	/* success */
	r = 0;
 out:
	sshbuf_free(বাফার);
	ফেরত r;
}

/* Load a pubkey from the unencrypted envelope of a new-format private key */
স্থির পূর্ণসংখ্যা
sshkey_load_pubkey_from_private(ধ্রুবক অক্ষর *filename, কাঠামো sshkey **pubkeyp)
{
	কাঠামো sshbuf *বাফার = ফাঁকা;
	কাঠামো sshkey *pubkey = ফাঁকা;
	পূর্ণসংখ্যা r, fd;

	যদি (pubkeyp != ফাঁকা)
		*pubkeyp = ফাঁকা;

	যদি ((fd = open(filename, O_RDONLY)) == -1)
		ফেরত SSH_ERR_SYSTEM_ERROR;
	যদি ((r = sshbuf_load_fd(fd, &বাফার)) != 0 ||
	    (r = sshkey_parse_pubkey_from_private_fileblob_type(বাফার,
	    চাবি_UNSPEC, &pubkey)) != 0)
		যাও out;
	/* success */
	যদি (pubkeyp != ফাঁকা) {
		*pubkeyp = pubkey;
		pubkey = ফাঁকা;
	}
	r = 0;
 out:
	close(fd);
	sshbuf_free(বাফার);
	sshkey_free(pubkey);
	ফেরত r;
}

স্থির পূর্ণসংখ্যা
sshkey_try_load_public(কাঠামো sshkey **kp, ধ্রুবক অক্ষর *filename,
    অক্ষর **commentp)
{
	FILE *f;
	অক্ষর *সারি = ফাঁকা, *cp;
	আকার_t linesize = 0;
	পূর্ণসংখ্যা r;
	কাঠামো stat st;
	কাঠামো sshkey *k = ফাঁকা;

	যদি (kp == ফাঁকা)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	*kp = ফাঁকা;
	যদি (commentp != ফাঁকা)
		*commentp = ফাঁকা;
	যদি ((f = fopen(filename, "r")) == ফাঁকা)
		ফেরত SSH_ERR_SYSTEM_ERROR;
	যদি (fstat(fileno(f), &st) == 0 && S_ISREG(st.st_mode) &&
	    st.st_size > SSHBUF_আকার_MAX) {
		fclose(f);
		ফেরত SSH_ERR_INVALID_FORMAT;
	}
	যদি ((k = sshkey_new(চাবি_UNSPEC)) == ফাঁকা) {
		fclose(f);
		ফেরত SSH_ERR_ALLOC_FAIL;
	}
	যখন (getline(&সারি, &linesize, f) != -1) {
		cp = সারি;
		নির্বাচন (*cp) {
		ক্ষেত্র '#':
		ক্ষেত্র '\n':
		ক্ষেত্র '\0':
			চালু;
		}
		/* Abort loading if this looks like a private key */
		যদি (strncmp(cp, "-----BEGIN", 10) == 0 ||
		    strcmp(cp, "SSH PRIVATE KEY FILE") == 0)
			বিরতি;
		/* Skip leading whitespace. */
		জন্য (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;
		যদি (*cp) {
			যদি ((r = sshkey_read(k, &cp)) == 0) {
				cp[strcspn(cp, "\r\n")] = '\0';
				যদি (commentp) {
					*commentp = strdup(*cp ?
					    cp : filename);
					যদি (*commentp == ফাঁকা)
						r = SSH_ERR_ALLOC_FAIL;
				}
				/* success */
				*kp = k;
				মুক্ত(সারি);
				fclose(f);
				ফেরত r;
			}
		}
	}
	মুক্ত(k);
	মুক্ত(সারি);
	fclose(f);
	ফেরত SSH_ERR_INVALID_FORMAT;
}

/* load public key from any pubkey file */
পূর্ণসংখ্যা
sshkey_load_public(ধ্রুবক অক্ষর *filename, কাঠামো sshkey **keyp, অক্ষর **commentp)
{
	অক্ষর *pubfile = ফাঁকা;
	পূর্ণসংখ্যা r, oerrno;

	যদি (keyp != ফাঁকা)
		*keyp = ফাঁকা;
	যদি (commentp != ফাঁকা)
		*commentp = ফাঁকা;

	যদি ((r = sshkey_try_load_public(keyp, filename, commentp)) == 0)
		যাও out;

	/* try .pub suffix */
	যদি (asprintf(&pubfile, "%s.pub", filename) == -1)
		ফেরত SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshkey_try_load_public(keyp, pubfile, commentp)) == 0)
		যাও out;

	/* finally, try to extract public key from private key file */
	যদি ((r = sshkey_load_pubkey_from_private(filename, keyp)) == 0)
		যাও out;

	/* Pretend we couldn't find the key */
	r = SSH_ERR_SYSTEM_ERROR;
	errno = ENOENT;

 out:
	oerrno = errno;
	মুক্ত(pubfile);
	errno = oerrno;
	ফেরত r;
}

/* Load the certificate associated with the named private key */
পূর্ণসংখ্যা
sshkey_load_cert(ধ্রুবক অক্ষর *filename, কাঠামো sshkey **keyp)
{
	কাঠামো sshkey *pub = ফাঁকা;
	অক্ষর *file = ফাঁকা;
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;

	যদি (keyp != ফাঁকা)
		*keyp = ফাঁকা;

	যদি (asprintf(&file, "%s-cert.pub", filename) == -1)
		ফেরত SSH_ERR_ALLOC_FAIL;

	r = sshkey_try_load_public(keyp, file, ফাঁকা);
	মুক্ত(file);
	sshkey_free(pub);
	ফেরত r;
}

/* Load private key and certificate */
পূর্ণসংখ্যা
sshkey_load_private_cert(পূর্ণসংখ্যা type, ধ্রুবক অক্ষর *filename, ধ্রুবক অক্ষর *passphrase,
    কাঠামো sshkey **keyp)
{
	কাঠামো sshkey *চাবি = ফাঁকা, *cert = ফাঁকা;
	পূর্ণসংখ্যা r;

	যদি (keyp != ফাঁকা)
		*keyp = ফাঁকা;

	নির্বাচন (type) {
#ifdef WITH_OPENSSL
	ক্ষেত্র চাবি_RSA:
	ক্ষেত্র চাবি_ECDSA:
#endif /* WITH_OPENSSL */
	ক্ষেত্র চাবি_ED25519:
	ক্ষেত্র চাবি_MLDSA44_ED25519:
	ক্ষেত্র চাবি_UNSPEC:
		বিরতি;
	পূর্বনির্ধারিত:
		ফেরত SSH_ERR_চাবি_TYPE_UNKNOWN;
	}

	যদি ((r = sshkey_load_private_type(type, filename,
	    passphrase, &চাবি, ফাঁকা)) != 0 ||
	    (r = sshkey_load_cert(filename, &cert)) != 0)
		যাও out;

	/* Make sure the private key matches the certificate */
	যদি (sshkey_equal_public(চাবি, cert) == 0) {
		r = SSH_ERR_চাবি_CERT_MISMATCH;
		যাও out;
	}

	যদি ((r = sshkey_to_certified(চাবি)) != 0 ||
	    (r = sshkey_cert_copy(cert, চাবি)) != 0)
		যাও out;
	r = 0;
	যদি (keyp != ফাঁকা) {
		*keyp = চাবি;
		চাবি = ফাঁকা;
	}
 out:
	sshkey_free(চাবি);
	sshkey_free(cert);
	ফেরত r;
}

/*
 * Returns success if the specified "key" is listed in the file "filename",
 * SSH_ERR_KEY_NOT_FOUND: if the key is not listed or another error.
 * If "strict_type" is set then the key type must match exactly,
 * otherwise a comparison that ignores certificate data is performed.
 * If "check_ca" is set and "key" is a certificate, then its CA key is
 * also checked and sshkey_in_file() will return success if either is found.
 */
পূর্ণসংখ্যা
sshkey_in_file(কাঠামো sshkey *চাবি, ধ্রুবক অক্ষর *filename, পূর্ণসংখ্যা strict_type,
    পূর্ণসংখ্যা check_ca)
{
	FILE *f;
	অক্ষর *সারি = ফাঁকা, *cp;
	আকার_t linesize = 0;
	পূর্ণসংখ্যা r = 0;
	কাঠামো sshkey *pub = ফাঁকা;

	পূর্ণসংখ্যা (*sshkey_compare)(ধ্রুবক কাঠামো sshkey *, ধ্রুবক কাঠামো sshkey *) =
	    strict_type ?  sshkey_equal : sshkey_equal_public;

	যদি ((f = fopen(filename, "r")) == ফাঁকা)
		ফেরত SSH_ERR_SYSTEM_ERROR;

	যখন (getline(&সারি, &linesize, f) != -1) {
		sshkey_free(pub);
		pub = ফাঁকা;
		cp = সারি;

		/* Skip leading whitespace. */
		জন্য (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;

		/* Skip comments and empty lines */
		নির্বাচন (*cp) {
		ক্ষেত্র '#':
		ক্ষেত্র '\n':
		ক্ষেত্র '\0':
			চালু;
		}

		যদি ((pub = sshkey_new(চাবি_UNSPEC)) == ফাঁকা) {
			r = SSH_ERR_ALLOC_FAIL;
			যাও out;
		}
		নির্বাচন (r = sshkey_read(pub, &cp)) {
		ক্ষেত্র 0:
			বিরতি;
		ক্ষেত্র SSH_ERR_চাবি_দৈর্ঘ্য:
			চালু;
		পূর্বনির্ধারিত:
			যাও out;
		}
		যদি (sshkey_compare(চাবি, pub) ||
		    (check_ca && sshkey_is_cert(চাবি) &&
		    sshkey_compare(চাবি->cert->signature_চাবি, pub))) {
			r = 0;
			যাও out;
		}
	}
	r = SSH_ERR_চাবি_NOT_FOUND;
 out:
	মুক্ত(সারি);
	sshkey_free(pub);
	fclose(f);
	ফেরত r;
}

/*
 * Checks whether the specified key is revoked, returning 0 if not,
 * SSH_ERR_KEY_REVOKED if it is or another error code if something
 * unexpected happened.
 * This will check both the key and, if it is a certificate, its CA key too.
 * "revoked_keys_file" may be a KRL or a one-per-line list of public keys.
 */
পূর্ণসংখ্যা
sshkey_check_revoked(কাঠামো sshkey *চাবি, ধ্রুবক অক্ষর *revoked_চাবিগুলি_file)
{
	পূর্ণসংখ্যা r;

	r = ssh_krl_file_contains_চাবি(revoked_চাবিগুলি_file, চাবি);
	/* If this was not a KRL to begin with then continue below */
	যদি (r != SSH_ERR_KRL_BAD_MAGIC)
		ফেরত r;

	/*
	 * If the file is not a KRL or we can't handle KRLs then attempt to
	 * parse the file as a flat list of keys.
	 */
	নির্বাচন ((r = sshkey_in_file(চাবি, revoked_চাবিগুলি_file, 0, 1))) {
	ক্ষেত্র 0:
		/* Key found => revoked */
		ফেরত SSH_ERR_চাবি_REVOKED;
	ক্ষেত্র SSH_ERR_চাবি_NOT_FOUND:
		/* Key not found => not revoked */
		ফেরত 0;
	পূর্বনির্ধারিত:
		/* Some other error occurred */
		ফেরত r;
	}
}

/*
 * Advanced *cpp past the end of key options, defined as the first unquoted
 * whitespace character. Returns 0 on success or -1 on failure (e.g.
 * unterminated quotes).
 */
পূর্ণসংখ্যা
sshkey_advance_past_options(অক্ষর **cpp)
{
	অক্ষর *cp = *cpp;
	পূর্ণসংখ্যা quoted = 0;

	জন্য (; *cp && (quoted || (*cp != ' ' && *cp != '\t')); cp++) {
		যদি (*cp == '\\' && cp[1] == '"')
			cp++;	/* Skip both */
		অন্যথা যদি (*cp == '"')
			quoted = !quoted;
	}
	*cpp = cp;
	/* return failure for unterminated quotes */
	ফেরত (*cp == '\0' && quoted) ? -1 : 0;
}

/* Save a public key */
পূর্ণসংখ্যা
sshkey_save_public(ধ্রুবক কাঠামো sshkey *চাবি, ধ্রুবক অক্ষর *path,
    ধ্রুবক অক্ষর *comment)
{
	পূর্ণসংখ্যা fd, oerrno;
	FILE *f = ফাঁকা;
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;

	যদি ((fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, 0644)) == -1)
		ফেরত SSH_ERR_SYSTEM_ERROR;
	যদি ((f = fdopen(fd, "w")) == ফাঁকা) {
		r = SSH_ERR_SYSTEM_ERROR;
		close(fd);
		যাও fail;
	}
	যদি ((r = sshkey_write(চাবি, f)) != 0)
		যাও fail;
	fprintf(f, " %s\n", comment);
	যদি (ferror(f)) {
		r = SSH_ERR_SYSTEM_ERROR;
		যাও fail;
	}
	যদি (fclose(f) != 0) {
		r = SSH_ERR_SYSTEM_ERROR;
		f = ফাঁকা;
 fail:
		যদি (f != ফাঁকা) {
			oerrno = errno;
			fclose(f);
			errno = oerrno;
		}
		ফেরত r;
	}
	ফেরত 0;
}
