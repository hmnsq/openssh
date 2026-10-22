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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/stat.h>

#అన్తర్భావ <errno.h>
#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>

#అన్తర్భావ "log.h"
#అన్తర్భావ "authfile.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "krl.h"

/* Save a key blob to a file */
స్థిర పూర్ణాంకం
sshkey_save_వ్యక్తిగత_blob(నిర్మాణం sshbuf *keybuf, స్థిరరాశి అక్షరం *filename)
{
	పూర్ణాంకం r;
	బహుళకం_t omask;

	omask = umask(077);
	r = sshbuf_write_file(filename, keybuf);
	umask(omask);
	తిరిగి r;
}

పూర్ణాంకం
sshkey_save_వ్యక్తిగత(నిర్మాణం sshkey *కీలకం, స్థిరరాశి అక్షరం *filename,
    స్థిరరాశి అక్షరం *passphrase, స్థిరరాశి అక్షరం *comment,
    పూర్ణాంకం format, స్థిరరాశి అక్షరం *openssh_format_cipher, పూర్ణాంకం openssh_format_విడతలు)
{
	నిర్మాణం sshbuf *keyblob = ఖాళీ;
	పూర్ణాంకం r;

	ఒకవేళ ((keyblob = sshbuf_new()) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ ((r = sshkey_వ్యక్తిగత_గమ్యం_fileblob(కీలకం, keyblob, passphrase, comment,
	    format, openssh_format_cipher, openssh_format_విడతలు)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ ((r = sshkey_save_వ్యక్తిగత_blob(keyblob, filename)) != 0)
		వెళ్ళు బహిర్గతం;
	r = 0;
 బహిర్గతం:
	sshbuf_free(keyblob);
	తిరిగి r;
}

/* XXX remove error() calls from here? */
పూర్ణాంకం
sshkey_perm_ok(పూర్ణాంకం fd, స్థిరరాశి అక్షరం *filename)
{
	నిర్మాణం stat st;

	ఒకవేళ (fstat(fd, &st) == -1)
		తిరిగి SSH_ERR_SYSTEM_ERROR;
	/*
	 * if a key owned by the user is accessed, then we check the
	 * permissions of the file. if the key owned by a different user,
	 * then we don't care.
	 */
#నిర్వచితమైతే HAVE_CYGWIN
	ఒకవేళ (check_ntsec(filename))
#అయితే_ముగింపు
	ఒకవేళ ((st.st_uid == getuid()) && (st.st_mode & 077) != 0) {
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @");
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("Permissions 0%3.3o for '%s' are too open.",
		    (u_int)st.st_mode & 0777, filename);
		error("It is required that your private key files are NOT accessible by others.");
		error("This private key will be ignored.");
		తిరిగి SSH_ERR_కీలకం_BAD_PERMISSIONS;
	}
	తిరిగి 0;
}

పూర్ణాంకం
sshkey_ఎక్కించు_వ్యక్తిగత_type(పూర్ణాంకం type, స్థిరరాశి అక్షరం *filename, స్థిరరాశి అక్షరం *passphrase,
    నిర్మాణం sshkey **keyp, అక్షరం **commentp)
{
	పూర్ణాంకం fd, r;

	ఒకవేళ (keyp != ఖాళీ)
		*keyp = ఖాళీ;
	ఒకవేళ (commentp != ఖాళీ)
		*commentp = ఖాళీ;

	ఒకవేళ ((fd = open(filename, O_RDONLY)) == -1)
		తిరిగి SSH_ERR_SYSTEM_ERROR;

	r = sshkey_perm_ok(fd, filename);
	ఒకవేళ (r != 0)
		వెళ్ళు బహిర్గతం;

	r = sshkey_ఎక్కించు_వ్యక్తిగత_type_fd(fd, type, passphrase, keyp, commentp);
 బహిర్గతం:
	close(fd);
	తిరిగి r;
}

పూర్ణాంకం
sshkey_ఎక్కించు_వ్యక్తిగత(స్థిరరాశి అక్షరం *filename, స్థిరరాశి అక్షరం *passphrase,
    నిర్మాణం sshkey **keyp, అక్షరం **commentp)
{
	తిరిగి sshkey_ఎక్కించు_వ్యక్తిగత_type(కీలకం_UNSPEC, filename, passphrase,
	    keyp, commentp);
}

పూర్ణాంకం
sshkey_ఎక్కించు_వ్యక్తిగత_type_fd(పూర్ణాంకం fd, పూర్ణాంకం type, స్థిరరాశి అక్షరం *passphrase,
    నిర్మాణం sshkey **keyp, అక్షరం **commentp)
{
	నిర్మాణం sshbuf *బఫరు = ఖాళీ;
	పూర్ణాంకం r;

	ఒకవేళ (keyp != ఖాళీ)
		*keyp = ఖాళీ;
	ఒకవేళ ((r = sshbuf_ఎక్కించు_fd(fd, &బఫరు)) != 0 ||
	    (r = sshkey_parse_వ్యక్తిగత_fileblob_type(బఫరు, type,
	    passphrase, keyp, commentp)) != 0)
		వెళ్ళు బహిర్గతం;

	/* success */
	r = 0;
 బహిర్గతం:
	sshbuf_free(బఫరు);
	తిరిగి r;
}

/* Load a pubkey from the unencrypted envelope of a new-format private key */
స్థిర పూర్ణాంకం
sshkey_ఎక్కించు_pubkey_from_వ్యక్తిగత(స్థిరరాశి అక్షరం *filename, నిర్మాణం sshkey **pubkeyp)
{
	నిర్మాణం sshbuf *బఫరు = ఖాళీ;
	నిర్మాణం sshkey *pubkey = ఖాళీ;
	పూర్ణాంకం r, fd;

	ఒకవేళ (pubkeyp != ఖాళీ)
		*pubkeyp = ఖాళీ;

	ఒకవేళ ((fd = open(filename, O_RDONLY)) == -1)
		తిరిగి SSH_ERR_SYSTEM_ERROR;
	ఒకవేళ ((r = sshbuf_ఎక్కించు_fd(fd, &బఫరు)) != 0 ||
	    (r = sshkey_parse_pubkey_from_వ్యక్తిగత_fileblob_type(బఫరు,
	    కీలకం_UNSPEC, &pubkey)) != 0)
		వెళ్ళు బహిర్గతం;
	/* success */
	ఒకవేళ (pubkeyp != ఖాళీ) {
		*pubkeyp = pubkey;
		pubkey = ఖాళీ;
	}
	r = 0;
 బహిర్గతం:
	close(fd);
	sshbuf_free(బఫరు);
	sshkey_free(pubkey);
	తిరిగి r;
}

స్థిర పూర్ణాంకం
sshkey_try_ఎక్కించు_ప్రజా(నిర్మాణం sshkey **kp, స్థిరరాశి అక్షరం *filename,
    అక్షరం **commentp)
{
	FILE *f;
	అక్షరం *పంక్తి = ఖాళీ, *cp;
	కొలత_t linesize = 0;
	పూర్ణాంకం r;
	నిర్మాణం stat st;
	నిర్మాణం sshkey *k = ఖాళీ;

	ఒకవేళ (kp == ఖాళీ)
		తిరిగి SSH_ERR_INVALID_వాదం;
	*kp = ఖాళీ;
	ఒకవేళ (commentp != ఖాళీ)
		*commentp = ఖాళీ;
	ఒకవేళ ((f = fopen(filename, "r")) == ఖాళీ)
		తిరిగి SSH_ERR_SYSTEM_ERROR;
	ఒకవేళ (fstat(fileno(f), &st) == 0 && S_ISREG(st.st_mode) &&
	    st.st_size > SSHBUF_కొలత_MAX) {
		fclose(f);
		తిరిగి SSH_ERR_INVALID_FORMAT;
	}
	ఒకవేళ ((k = sshkey_new(కీలకం_UNSPEC)) == ఖాళీ) {
		fclose(f);
		తిరిగి SSH_ERR_ALLOC_FAIL;
	}
	అయితే (getline(&పంక్తి, &linesize, f) != -1) {
		cp = పంక్తి;
		ఎంపిక (*cp) {
		స్థితి '#':
		స్థితి '\n':
		స్థితి '\0':
			కొనసాగు;
		}
		/* Abort loading if this looks like a private key */
		ఒకవేళ (అక్షరశ్రేణి_పోలిక(cp, "-----BEGIN", 10) == 0 ||
		    strcmp(cp, "SSH PRIVATE KEY FILE") == 0)
			ఆపు;
		/* Skip leading whitespace. */
		కొరకు (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;
		ఒకవేళ (*cp) {
			ఒకవేళ ((r = sshkey_read(k, &cp)) == 0) {
				cp[strcspn(cp, "\r\n")] = '\0';
				ఒకవేళ (commentp) {
					*commentp = strdup(*cp ?
					    cp : filename);
					ఒకవేళ (*commentp == ఖాళీ)
						r = SSH_ERR_ALLOC_FAIL;
				}
				/* success */
				*kp = k;
				విడుదల(పంక్తి);
				fclose(f);
				తిరిగి r;
			}
		}
	}
	విడుదల(k);
	విడుదల(పంక్తి);
	fclose(f);
	తిరిగి SSH_ERR_INVALID_FORMAT;
}

/* load public key from any pubkey file */
పూర్ణాంకం
sshkey_ఎక్కించు_ప్రజా(స్థిరరాశి అక్షరం *filename, నిర్మాణం sshkey **keyp, అక్షరం **commentp)
{
	అక్షరం *pubfile = ఖాళీ;
	పూర్ణాంకం r, oerrno;

	ఒకవేళ (keyp != ఖాళీ)
		*keyp = ఖాళీ;
	ఒకవేళ (commentp != ఖాళీ)
		*commentp = ఖాళీ;

	ఒకవేళ ((r = sshkey_try_ఎక్కించు_ప్రజా(keyp, filename, commentp)) == 0)
		వెళ్ళు బహిర్గతం;

	/* try .pub suffix */
	ఒకవేళ (asprintf(&pubfile, "%s.pub", filename) == -1)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ ((r = sshkey_try_ఎక్కించు_ప్రజా(keyp, pubfile, commentp)) == 0)
		వెళ్ళు బహిర్గతం;

	/* finally, try to extract public key from private key file */
	ఒకవేళ ((r = sshkey_ఎక్కించు_pubkey_from_వ్యక్తిగత(filename, keyp)) == 0)
		వెళ్ళు బహిర్గతం;

	/* Pretend we couldn't find the key */
	r = SSH_ERR_SYSTEM_ERROR;
	errno = ENOENT;

 బహిర్గతం:
	oerrno = errno;
	విడుదల(pubfile);
	errno = oerrno;
	తిరిగి r;
}

/* Load the certificate associated with the named private key */
పూర్ణాంకం
sshkey_ఎక్కించు_cert(స్థిరరాశి అక్షరం *filename, నిర్మాణం sshkey **keyp)
{
	నిర్మాణం sshkey *pub = ఖాళీ;
	అక్షరం *file = ఖాళీ;
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;

	ఒకవేళ (keyp != ఖాళీ)
		*keyp = ఖాళీ;

	ఒకవేళ (asprintf(&file, "%s-cert.pub", filename) == -1)
		తిరిగి SSH_ERR_ALLOC_FAIL;

	r = sshkey_try_ఎక్కించు_ప్రజా(keyp, file, ఖాళీ);
	విడుదల(file);
	sshkey_free(pub);
	తిరిగి r;
}

/* Load private key and certificate */
పూర్ణాంకం
sshkey_ఎక్కించు_వ్యక్తిగత_cert(పూర్ణాంకం type, స్థిరరాశి అక్షరం *filename, స్థిరరాశి అక్షరం *passphrase,
    నిర్మాణం sshkey **keyp)
{
	నిర్మాణం sshkey *కీలకం = ఖాళీ, *cert = ఖాళీ;
	పూర్ణాంకం r;

	ఒకవేళ (keyp != ఖాళీ)
		*keyp = ఖాళీ;

	ఎంపిక (type) {
#నిర్వచితమైతే WITH_OPENSSL
	స్థితి కీలకం_RSA:
	స్థితి కీలకం_ECDSA:
#అయితే_ముగింపు /* WITH_OPENSSL */
	స్థితి కీలకం_ED25519:
	స్థితి కీలకం_MLDSA44_ED25519:
	స్థితి కీలకం_UNSPEC:
		ఆపు;
	అప్రమేయ:
		తిరిగి SSH_ERR_కీలకం_TYPE_UNKNOWN;
	}

	ఒకవేళ ((r = sshkey_ఎక్కించు_వ్యక్తిగత_type(type, filename,
	    passphrase, &కీలకం, ఖాళీ)) != 0 ||
	    (r = sshkey_ఎక్కించు_cert(filename, &cert)) != 0)
		వెళ్ళు బహిర్గతం;

	/* Make sure the private key matches the certificate */
	ఒకవేళ (sshkey_equal_ప్రజా(కీలకం, cert) == 0) {
		r = SSH_ERR_కీలకం_CERT_MISMATCH;
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ ((r = sshkey_గమ్యం_certified(కీలకం)) != 0 ||
	    (r = sshkey_cert_copy(cert, కీలకం)) != 0)
		వెళ్ళు బహిర్గతం;
	r = 0;
	ఒకవేళ (keyp != ఖాళీ) {
		*keyp = కీలకం;
		కీలకం = ఖాళీ;
	}
 బహిర్గతం:
	sshkey_free(కీలకం);
	sshkey_free(cert);
	తిరిగి r;
}

/*
 * Returns success if the specified "key" is listed in the file "filename",
 * SSH_ERR_KEY_NOT_FOUND: if the key is not listed or another error.
 * If "strict_type" is set then the key type must match exactly,
 * otherwise a comparison that ignores certificate data is performed.
 * If "check_ca" is set and "key" is a certificate, then its CA key is
 * also checked and sshkey_in_file() will return success if either is found.
 */
పూర్ణాంకం
sshkey_లోపల_file(నిర్మాణం sshkey *కీలకం, స్థిరరాశి అక్షరం *filename, పూర్ణాంకం strict_type,
    పూర్ణాంకం check_ca)
{
	FILE *f;
	అక్షరం *పంక్తి = ఖాళీ, *cp;
	కొలత_t linesize = 0;
	పూర్ణాంకం r = 0;
	నిర్మాణం sshkey *pub = ఖాళీ;

	పూర్ణాంకం (*sshkey_compare)(స్థిరరాశి నిర్మాణం sshkey *, స్థిరరాశి నిర్మాణం sshkey *) =
	    strict_type ?  sshkey_equal : sshkey_equal_ప్రజా;

	ఒకవేళ ((f = fopen(filename, "r")) == ఖాళీ)
		తిరిగి SSH_ERR_SYSTEM_ERROR;

	అయితే (getline(&పంక్తి, &linesize, f) != -1) {
		sshkey_free(pub);
		pub = ఖాళీ;
		cp = పంక్తి;

		/* Skip leading whitespace. */
		కొరకు (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;

		/* Skip comments and empty lines */
		ఎంపిక (*cp) {
		స్థితి '#':
		స్థితి '\n':
		స్థితి '\0':
			కొనసాగు;
		}

		ఒకవేళ ((pub = sshkey_new(కీలకం_UNSPEC)) == ఖాళీ) {
			r = SSH_ERR_ALLOC_FAIL;
			వెళ్ళు బహిర్గతం;
		}
		ఎంపిక (r = sshkey_read(pub, &cp)) {
		స్థితి 0:
			ఆపు;
		స్థితి SSH_ERR_కీలకం_నిడివి:
			కొనసాగు;
		అప్రమేయ:
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (sshkey_compare(కీలకం, pub) ||
		    (check_ca && sshkey_is_cert(కీలకం) &&
		    sshkey_compare(కీలకం->cert->signature_కీలకం, pub))) {
			r = 0;
			వెళ్ళు బహిర్గతం;
		}
	}
	r = SSH_ERR_కీలకం_NOT_దొరికింది;
 బహిర్గతం:
	విడుదల(పంక్తి);
	sshkey_free(pub);
	fclose(f);
	తిరిగి r;
}

/*
 * Checks whether the specified key is revoked, returning 0 if not,
 * SSH_ERR_KEY_REVOKED if it is or another error code if something
 * unexpected happened.
 * This will check both the key and, if it is a certificate, its CA key too.
 * "revoked_keys_file" may be a KRL or a one-per-line list of public keys.
 */
పూర్ణాంకం
sshkey_check_revoked(నిర్మాణం sshkey *కీలకం, స్థిరరాశి అక్షరం *revoked_కీలకాలు_file)
{
	పూర్ణాంకం r;

	r = ssh_krl_file_కలిగియుంది_కీలకం(revoked_కీలకాలు_file, కీలకం);
	/* If this was not a KRL to begin with then continue below */
	ఒకవేళ (r != SSH_ERR_KRL_BAD_MAGIC)
		తిరిగి r;

	/*
	 * If the file is not a KRL or we can't handle KRLs then attempt to
	 * parse the file as a flat list of keys.
	 */
	ఎంపిక ((r = sshkey_లోపల_file(కీలకం, revoked_కీలకాలు_file, 0, 1))) {
	స్థితి 0:
		/* Key found => revoked */
		తిరిగి SSH_ERR_కీలకం_REVOKED;
	స్థితి SSH_ERR_కీలకం_NOT_దొరికింది:
		/* Key not found => not revoked */
		తిరిగి 0;
	అప్రమేయ:
		/* Some other error occurred */
		తిరిగి r;
	}
}

/*
 * Advanced *cpp past the end of key options, defined as the first unquoted
 * whitespace character. Returns 0 on success or -1 on failure (e.g.
 * unterminated quotes).
 */
పూర్ణాంకం
sshkey_advance_past_options(అక్షరం **cpp)
{
	అక్షరం *cp = *cpp;
	పూర్ణాంకం quoted = 0;

	కొరకు (; *cp && (quoted || (*cp != ' ' && *cp != '\t')); cp++) {
		ఒకవేళ (*cp == '\\' && cp[1] == '"')
			cp++;	/* Skip both */
		లేకపోతే ఒకవేళ (*cp == '"')
			quoted = !quoted;
	}
	*cpp = cp;
	/* return failure for unterminated quotes */
	తిరిగి (*cp == '\0' && quoted) ? -1 : 0;
}

/* Save a public key */
పూర్ణాంకం
sshkey_save_ప్రజా(స్థిరరాశి నిర్మాణం sshkey *కీలకం, స్థిరరాశి అక్షరం *మార్గం,
    స్థిరరాశి అక్షరం *comment)
{
	పూర్ణాంకం fd, oerrno;
	FILE *f = ఖాళీ;
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;

	ఒకవేళ ((fd = open(మార్గం, O_WRONLY|O_CREAT|O_TRUNC, 0644)) == -1)
		తిరిగి SSH_ERR_SYSTEM_ERROR;
	ఒకవేళ ((f = fdopen(fd, "w")) == ఖాళీ) {
		r = SSH_ERR_SYSTEM_ERROR;
		close(fd);
		వెళ్ళు fail;
	}
	ఒకవేళ ((r = sshkey_write(కీలకం, f)) != 0)
		వెళ్ళు fail;
	fprintf(f, " %s\n", comment);
	ఒకవేళ (ferror(f)) {
		r = SSH_ERR_SYSTEM_ERROR;
		వెళ్ళు fail;
	}
	ఒకవేళ (fclose(f) != 0) {
		r = SSH_ERR_SYSTEM_ERROR;
		f = ఖాళీ;
 fail:
		ఒకవేళ (f != ఖాళీ) {
			oerrno = errno;
			fclose(f);
			errno = oerrno;
		}
		తిరిగి r;
	}
	తిరిగి 0;
}
