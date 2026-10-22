/* $OpenBSD: ssh-add.c,v 1.191 2026/09/17 18:12:10 dtucker Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Adds an identity to the authentication server, or removes an identity.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 * SSH2 implementation,
 * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
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

#ifdef WITH_OPENSSL
# include <openssl/evp.h>
# include "openbsd-compat/openssl-compat.h"
#endif

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <time.h>

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "ssh.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "authfd.h"
#ಅನ್ತರ್ಭಾವ "authfile.h"
#ಅನ್ತರ್ಭಾವ "pathnames.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "digest.h"
#ಅನ್ತರ್ಭಾವ "ssh-sk.h"
#ಅನ್ತರ್ಭಾವ "sk-api.h"
#ಅನ್ತರ್ಭಾವ "hostfile.h"

#define CERT_EXPIRY_GRACE	(5*60)

/* argv0 */
ಬಾಹ್ಯ ವರ್ಣ *__progname;

/* Default files to add */
ಸ್ಥಿರ ವರ್ಣ *default_files[] = {
#ifdef WITH_OPENSSL
	_PATH_SSH_CLIENT_ID_RSA,
	_PATH_SSH_CLIENT_ID_ECDSA,
	_PATH_SSH_CLIENT_ID_ECDSA_SK,
#endif /* WITH_OPENSSL */
	_PATH_SSH_CLIENT_ID_ED25519,
	_PATH_SSH_CLIENT_ID_ED25519_SK,
	_PATH_SSH_CLIENT_ID_MLDSA44_ED25519,
	ರಿಕ್ತ
};

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* Default lifetime (0 == forever) */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ lifetime = 0;

/* User has to confirm key use */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ confirm = 0;

/* we keep a cache of one passphrase */
ಸ್ಥಿರ ವರ್ಣ *pass = ರಿಕ್ತ;
ಸ್ಥಿರ ಶೂನ್ಯ
clear_pass(ಶೂನ್ಯ)
{
	ಯದಿ (pass) {
		freezero(pass, strlen(pass));
		pass = ರಿಕ್ತ;
	}
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
delete_one(ಪೂರ್ಣಾಙ್ಕ agent_fd, ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಧ್ರುವ ವರ್ಣ *comment,
    ಧ್ರುವ ವರ್ಣ *path, ಪೂರ್ಣಾಙ್ಕ qflag)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = ssh_remove_identity(agent_fd, ಕೀಲಿ)) != 0) {
		fprintf(stderr, "Could not remove identity \"%s\": %s\n",
		    path, ssh_err(r));
		ಪ್ರತ್ಯಾಗಮ r;
	}
	ಯದಿ (!qflag) {
		fprintf(stderr, "Identity removed: %s %s (%s)\n", path,
		    sshkey_type(ಕೀಲಿ), comment ? comment : "no comment");
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
delete_stdin(ಪೂರ್ಣಾಙ್ಕ agent_fd, ಪೂರ್ಣಾಙ್ಕ qflag, ಪೂರ್ಣಾಙ್ಕ ಕೀಲಿ_only, ಪೂರ್ಣಾಙ್ಕ cert_only)
{
	ವರ್ಣ *ಸಾಲು = ರಿಕ್ತ, *cp;
	size_t linesize = 0;
	ಸಂರಚನಾ sshkey *ಕೀಲಿ = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ lnum = 0, r, ret = -1;

	ಯಾವತ್ (getline(&ಸಾಲು, &linesize, stdin) != -1) {
		lnum++;
		sshkey_free(ಕೀಲಿ);
		ಕೀಲಿ = ರಿಕ್ತ;
		ಸಾಲು[strcspn(ಸಾಲು, "\n")] = '\0';
		cp = ಸಾಲು + strspn(ಸಾಲು, " \t");
		ಯದಿ (*cp == '#' || *cp == '\0')
			ಅನುವರ್ತ;
		ಯದಿ ((ಕೀಲಿ = sshkey_new(ಕೀಲಿ_UNSPEC)) == ರಿಕ್ತ)
			fatal_f("sshkey_new");
		ಯದಿ ((r = sshkey_read(ಕೀಲಿ, &cp)) != 0) {
			error_r(r, "(stdin):%d: invalid key", lnum);
			ಅನುವರ್ತ;
		}
		ಯದಿ ((!ಕೀಲಿ_only && !cert_only) ||
		    (ಕೀಲಿ_only && !sshkey_is_cert(ಕೀಲಿ)) ||
		    (cert_only && sshkey_is_cert(ಕೀಲಿ))) {
			ಯದಿ (delete_one(agent_fd, ಕೀಲಿ, cp,
			    "(stdin)", qflag) == 0)
				ret = 0;
		}
	}
	sshkey_free(ಕೀಲಿ);
	ಮುಕ್ತ(ಸಾಲು);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
delete_file(ಪೂರ್ಣಾಙ್ಕ agent_fd, ಧ್ರುವ ವರ್ಣ *filename, ಪೂರ್ಣಾಙ್ಕ ಕೀಲಿ_only,
    ಪೂರ್ಣಾಙ್ಕ cert_only, ಪೂರ್ಣಾಙ್ಕ qflag)
{
	ಸಂರಚನಾ sshkey *ಸಾರ್ವಜನಿಕ, *cert = ರಿಕ್ತ;
	ವರ್ಣ *certpath = ರಿಕ್ತ, *comment = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r, ret = -1;

	ಯದಿ (strcmp(filename, "-") == 0)
		ಪ್ರತ್ಯಾಗಮ delete_stdin(agent_fd, qflag, ಕೀಲಿ_only, cert_only);

	ಯದಿ ((r = sshkey_load_public(filename, &ಸಾರ್ವಜನಿಕ,  &comment)) != 0) {
		printf("Bad key file %s: %s\n", filename, ssh_err(r));
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯದಿ ((!ಕೀಲಿ_only && !cert_only) ||
	    (ಕೀಲಿ_only && !sshkey_is_cert(ಸಾರ್ವಜನಿಕ)) ||
	    (cert_only && sshkey_is_cert(ಸಾರ್ವಜನಿಕ))) {
		ಯದಿ (delete_one(agent_fd, ಸಾರ್ವಜನಿಕ, comment, filename, qflag) == 0)
			ret = 0;
	}

	ಯದಿ (ಕೀಲಿ_only)
		ಗಚ್ಛ out;

	/* Now try to delete the corresponding certificate too */
	ಮುಕ್ತ(comment);
	comment = ರಿಕ್ತ;
	xasprintf(&certpath, "%s-cert.pub", filename);
	ಯದಿ ((r = sshkey_load_public(certpath, &cert, &comment)) != 0) {
		ಯದಿ (r != SSH_ERR_SYSTEM_ERROR || errno != ENOENT)
			error_r(r, "Failed to load certificate \"%s\"", certpath);
		ಗಚ್ಛ out;
	}

	ಯದಿ (!sshkey_equal_public(cert, ಸಾರ್ವಜನಿಕ))
		fatal("Certificate %s does not match private key %s",
		    certpath, filename);

	ಯದಿ (delete_one(agent_fd, cert, comment, certpath, qflag) == 0)
		ret = 0;

 out:
	sshkey_free(cert);
	sshkey_free(ಸಾರ್ವಜನಿಕ);
	ಮುಕ್ತ(certpath);
	ಮುಕ್ತ(comment);

	ಪ್ರತ್ಯಾಗಮ ret;
}

/* Send a request to remove all identities. */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
delete_all(ಪೂರ್ಣಾಙ್ಕ agent_fd, ಪೂರ್ಣಾಙ್ಕ qflag)
{
	ಪೂರ್ಣಾಙ್ಕ ret = -1;

	/*
	 * Since the agent might be forwarded, old or non-OpenSSH, when asked
	 * to remove all keys, attempt to remove both protocol v.1 and v.2
	 * keys.
	 */
	ಯದಿ (ssh_remove_all_identities(agent_fd, 2) == 0)
		ret = 0;
	/* ignore error-code for ssh1 */
	ssh_remove_all_identities(agent_fd, 1);

	ಯದಿ (ret != 0)
		fprintf(stderr, "Failed to remove all identities.\n");
	ಅನ್ಯಥಾ ಯದಿ (!qflag)
		fprintf(stderr, "All identities removed.\n");

	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
query_exts(ಪೂರ್ಣಾಙ್ಕ agent_fd)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	ವರ್ಣ **exts = ರಿಕ್ತ;
	size_t i;

	ಯದಿ ((r = ssh_agent_query_extensions(agent_fd, &exts)) != 0)
		fatal_r(r, "unable to query supported extensions");
	ಪ್ರತಿ (i = 0; exts != ರಿಕ್ತ && exts[i] != ರಿಕ್ತ; i++)
		puts(exts[i]);
	stringlist_free(exts);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
check_cert_lifetime(ಧ್ರುವ ಸಂರಚನಾ sshkey *cert, ಪೂರ್ಣಾಙ್ಕ cert_lifetime)
{
	time_t now;
	uint64_t n;

	ಯದಿ (cert == ರಿಕ್ತ || cert->cert == ರಿಕ್ತ || !sshkey_is_cert(cert) ||
	    cert->cert->valid_before == 0xFFFFFFFFFFFFFFFFULL)
		ಪ್ರತ್ಯಾಗಮ cert_lifetime;
	ಯದಿ ((now = time(ರಿಕ್ತ)) <= 0)
		fatal_f("system time is at/before epoch");
	ಯದಿ ((uint64_t)now > (cert->cert->valid_before + CERT_EXPIRY_GRACE))
		ಪ್ರತ್ಯಾಗಮ -1; /* certificate already expired */
	n = (CERT_EXPIRY_GRACE + cert->cert->valid_before) - (uint64_t)now;
	n = MINIMUM(n, INT_MAX);
	ಯದಿ (cert_lifetime <= 0)
		ಪ್ರತ್ಯಾಗಮ (ಪೂರ್ಣಾಙ್ಕ)n;
	ಪ್ರತ್ಯಾಗಮ MINIMUM(cert_lifetime, (ಪೂರ್ಣಾಙ್ಕ)n);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
add_file(ಪೂರ್ಣಾಙ್ಕ agent_fd, ಧ್ರುವ ವರ್ಣ *filename, ಪೂರ್ಣಾಙ್ಕ ಕೀಲಿ_only, ಪೂರ್ಣಾಙ್ಕ cert_only,
    ಪೂರ್ಣಾಙ್ಕ qflag, ಪೂರ್ಣಾಙ್ಕ Nflag, ಧ್ರುವ ವರ್ಣ *skprovider,
    ಸಂರಚನಾ dest_constraint **dest_constraints,
    size_t ndest_constraints)
{
	ಸಂರಚನಾ sshkey *ಗುಪ್ತ = ರಿಕ್ತ, *cert = ರಿಕ್ತ;
	ವರ್ಣ *comment = ರಿಕ್ತ;
	ವರ್ಣ ಸಂದೇಶ[1024], *certpath = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ cert_lifetime, r, fd, ret = -1;
	ಸಂರಚನಾ sshbuf *keyblob;

	ಯದಿ (strcmp(filename, "-") == 0) {
		fd = STDIN_FILENO;
		filename = "(stdin)";
	} ಅನ್ಯಥಾ ಯದಿ ((fd = open(filename, O_RDONLY)) == -1) {
		perror(filename);
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	/*
	 * Since we'll try to load a keyfile multiple times, permission errors
	 * will occur multiple times, so check perms first and bail if wrong.
	 */
	ಯದಿ (fd != STDIN_FILENO) {
		ಯದಿ (sshkey_perm_ok(fd, filename) != 0) {
			close(fd);
			ಪ್ರತ್ಯಾಗಮ -1;
		}
	}
	ಯದಿ ((r = sshbuf_load_fd(fd, &keyblob)) != 0) {
		fprintf(stderr, "Error loading key \"%s\": %s\n",
		    filename, ssh_err(r));
		sshbuf_free(keyblob);
		close(fd);
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	close(fd);

	/* At first, try empty passphrase */
	ಯದಿ ((r = sshkey_parse_private_fileblob(keyblob, "", &ಗುಪ್ತ,
	    &comment)) != 0 && r != SSH_ERR_ಕೀಲಿ_WRONG_PASSPHRASE) {
		fprintf(stderr, "Error loading key \"%s\": %s\n",
		    filename, ssh_err(r));
		ಗಚ್ಛ fail_load;
	}
	/* try last */
	ಯದಿ (ಗುಪ್ತ == ರಿಕ್ತ && pass != ರಿಕ್ತ) {
		ಯದಿ ((r = sshkey_parse_private_fileblob(keyblob, pass, &ಗುಪ್ತ,
		    &comment)) != 0 && r != SSH_ERR_ಕೀಲಿ_WRONG_PASSPHRASE) {
			fprintf(stderr, "Error loading key \"%s\": %s\n",
			    filename, ssh_err(r));
			ಗಚ್ಛ fail_load;
		}
	}
	ಯದಿ (ಗುಪ್ತ == ರಿಕ್ತ) {
		/* clear passphrase since it did not work */
		clear_pass();
		snprintf(ಸಂದೇಶ, ಪರಿಮಾಣ ಸಂದೇಶ, "Enter passphrase for %s%s: ",
		    filename, confirm ? " (will confirm each use)" : "");
		ಪ್ರತಿ (;;) {
			pass = read_passphrase(ಸಂದೇಶ, RP_ALLOW_STDIN);
			ಯದಿ (strcmp(pass, "") == 0)
				ಗಚ್ಛ fail_load;
			ಯದಿ ((r = sshkey_parse_private_fileblob(keyblob, pass,
			    &ಗುಪ್ತ, &comment)) == 0)
				ಭಙ್ಗ;
			ಅನ್ಯಥಾ ಯದಿ (r != SSH_ERR_ಕೀಲಿ_WRONG_PASSPHRASE) {
				fprintf(stderr,
				    "Error loading key \"%s\": %s\n",
				    filename, ssh_err(r));
 fail_load:
				clear_pass();
				sshbuf_free(keyblob);
				ಪ್ರತ್ಯಾಗಮ -1;
			}
			clear_pass();
			snprintf(ಸಂದೇಶ, ಪರಿಮಾಣ ಸಂದೇಶ,
			    "Bad passphrase, try again for %s%s: ", filename,
			    confirm ? " (will confirm each use)" : "");
		}
	}
	ಯದಿ (comment == ರಿಕ್ತ || *comment == '\0')
		comment = xstrdup(filename);
	sshbuf_free(keyblob);

	ಯದಿ (sshkey_is_sk(ಗುಪ್ತ)) {
		ಯದಿ (skprovider == ರಿಕ್ತ) {
			fprintf(stderr, "Cannot load FIDO key %s "
			    "without provider\n", filename);
			ಗಚ್ಛ out;
		}
	} ಅನ್ಯಥಾ {
		/* Don't send provider constraint for other keys */
		skprovider = ರಿಕ್ತ;
	}

	ಯದಿ (!cert_only) {
		ಯದಿ ((r = ssh_add_identity_constrained(agent_fd, ಗುಪ್ತ,
		    comment, lifetime, confirm, skprovider,
		    dest_constraints, ndest_constraints)) == 0) {
			ret = 0;
			ಯದಿ (!qflag) {
				fprintf(stderr, "Identity added: %s (%s)\n",
				    filename, comment);
				ಯದಿ (lifetime != 0) {
					fprintf(stderr, "Lifetime set to %s\n",
					    fmt_timeframe((time_t)lifetime));
				}
				ಯದಿ (confirm != 0) {
					fprintf(stderr, "The user must confirm "
					    "each use of the key\n");
				}
			}
		} ಅನ್ಯಥಾ {
			fprintf(stderr, "Could not add identity \"%s\": %s\n",
			    filename, ssh_err(r));
		}
	}

	/* Skip trying to load the cert if requested */
	ಯದಿ (ಕೀಲಿ_only)
		ಗಚ್ಛ out;

	/* Now try to add the certificate flavour too */
	xasprintf(&certpath, "%s-cert.pub", filename);
	ಯದಿ ((r = sshkey_load_public(certpath, &cert, ರಿಕ್ತ)) != 0) {
		ಯದಿ (r != SSH_ERR_SYSTEM_ERROR || errno != ENOENT)
			error_r(r, "Failed to load certificate \"%s\"",
			    certpath);
		ಗಚ್ಛ out;
	}

	ಯದಿ (!sshkey_equal_public(cert, ಗುಪ್ತ)) {
		error("Certificate %s does not match private key %s",
		    certpath, filename);
		ಗಚ್ಛ out;
	}

	cert_lifetime = lifetime;
	ಯದಿ (!Nflag &&
	    (cert_lifetime = check_cert_lifetime(cert, cert_lifetime)) == -1) {
		logit("Certificate %s has already expired; ignored", certpath);
		ಗಚ್ಛ out;
	}

	/* Graft with private bits */
	ಯದಿ ((r = sshkey_to_certified(ಗುಪ್ತ)) != 0) {
		error_fr(r, "sshkey_to_certified");
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshkey_cert_copy(cert, ಗುಪ್ತ)) != 0) {
		error_fr(r, "sshkey_cert_copy");
		ಗಚ್ಛ out;
	}
	/* send to agent */
	ಯದಿ ((r = ssh_add_identity_constrained(agent_fd, ಗುಪ್ತ, comment,
	    cert_lifetime, confirm, skprovider,
	    dest_constraints, ndest_constraints)) != 0) {
		error_r(r, "Certificate %s (%s) add failed", certpath,
		    ಗುಪ್ತ->cert->ಕೀಲಿ_id);
		ಗಚ್ಛ out;
	}
	/* success */
	ಯದಿ (!qflag) {
		fprintf(stderr, "Certificate added: %s (%s)\n", certpath,
		    ಗುಪ್ತ->cert->ಕೀಲಿ_id);
		ಯದಿ (cert_lifetime != 0) {
			fprintf(stderr, "Lifetime set to %s\n",
			    fmt_timeframe((time_t)cert_lifetime));
		}
		ಯದಿ (confirm != 0) {
			fprintf(stderr, "The user must confirm each use "
			    "of the key\n");
		}
	}

 out:
	ಮುಕ್ತ(certpath);
	ಮುಕ್ತ(comment);
	sshkey_free(cert);
	sshkey_free(ಗುಪ್ತ);

	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
update_card(ಪೂರ್ಣಾಙ್ಕ agent_fd, ಪೂರ್ಣಾಙ್ಕ add, ಧ್ರುವ ವರ್ಣ *id, ಪೂರ್ಣಾಙ್ಕ qflag, ಪೂರ್ಣಾಙ್ಕ no_pin,
    ಪೂರ್ಣಾಙ್ಕ ಕೀಲಿ_only, ಪೂರ್ಣಾಙ್ಕ cert_only,
    ಸಂರಚನಾ dest_constraint **dest_constraints, size_t ndest_constraints,
    ಸಂರಚನಾ sshkey **certs, size_t ncerts)
{
	ವರ್ಣ *pin = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r, ret = -1;

	ಯದಿ (ಕೀಲಿ_only)
		ncerts = 0;

	ಯದಿ (add && !no_pin) {
		ಯದಿ ((pin = read_passphrase("Enter passphrase for PKCS#11: ",
		    RP_ALLOW_STDIN)) == ರಿಕ್ತ)
			ಪ್ರತ್ಯಾಗಮ -1;
	}

	ಯದಿ ((r = ssh_update_card(agent_fd, add, id, pin == ರಿಕ್ತ ? "" : pin,
	    lifetime, confirm, dest_constraints, ndest_constraints,
	    cert_only, certs, ncerts)) == 0) {
		ret = 0;
		ಯದಿ (!qflag) {
			fprintf(stderr, "Card %s: %s\n",
			    add ? "added" : "removed", id);
		}
	} ಅನ್ಯಥಾ {
		fprintf(stderr, "Could not %s card \"%s\": %s\n",
		    add ? "add" : "remove", id, ssh_err(r));
		ret = -1;
	}
	ಮುಕ್ತ(pin);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
test_ಕೀಲಿ(ಪೂರ್ಣಾಙ್ಕ agent_fd, ಧ್ರುವ ವರ್ಣ *filename)
{
	ಸಂರಚನಾ sshkey *ಕೀಲಿ = ರಿಕ್ತ;
	u_char *sig = ರಿಕ್ತ;
	ಧ್ರುವ ವರ್ಣ *alg = ರಿಕ್ತ;
	size_t slen = 0;
	ಪೂರ್ಣಾಙ್ಕ r, ret = -1;
	ವರ್ಣ data[1024];

	ಯದಿ ((r = sshkey_load_public(filename, &ಕೀಲಿ, ರಿಕ್ತ)) != 0) {
		error_r(r, "Couldn't read public key %s", filename);
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯದಿ (sshkey_type_plain(ಕೀಲಿ->type) == ಕೀಲಿ_RSA)
		alg = "rsa-sha2-256";
	arc4random_buf(data, ಪರಿಮಾಣ(data));
	ಯದಿ ((r = ssh_agent_sign(agent_fd, ಕೀಲಿ, &sig, &slen, data, ಪರಿಮಾಣ(data),
	    alg, 0)) != 0) {
		error_r(r, "Agent signature failed for %s", filename);
		ಗಚ್ಛ done;
	}
	ಯದಿ ((r = sshkey_verify(ಕೀಲಿ, sig, slen, data, ಪರಿಮಾಣ(data),
	    alg, 0, ರಿಕ್ತ)) != 0) {
		error_r(r, "Signature verification failed for %s", filename);
		ಗಚ್ಛ done;
	}
	/* success */
	ret = 0;
 done:
	ಮುಕ್ತ(sig);
	sshkey_free(ಕೀಲಿ);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
list_identities(ಪೂರ್ಣಾಙ್ಕ agent_fd, ಪೂರ್ಣಾಙ್ಕ do_fp)
{
	ವರ್ಣ *fp;
	ಪೂರ್ಣಾಙ್ಕ r;
	ಸಂರಚನಾ ssh_identitylist *idlist;
	size_t i;

	ಯದಿ ((r = ssh_fetch_identitylist(agent_fd, &idlist)) != 0) {
		ಯದಿ (r != SSH_ERR_AGENT_NO_IDENTITIES)
			fprintf(stderr, "error fetching identities: %s\n",
			    ssh_err(r));
		ಅನ್ಯಥಾ
			printf("The agent has no identities.\n");
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಪ್ರತಿ (i = 0; i < idlist->nkeys; i++) {
		ಯದಿ (do_fp) {
			fp = sshkey_fingerprint(idlist->ಕೀಲಿಗಳು[i],
			    fingerprint_hash, SSH_FP_DEFAULT);
			printf("%u %s %s (%s)\n", sshkey_size(idlist->ಕೀಲಿಗಳು[i]),
			    fp == ರಿಕ್ತ ? "(null)" : fp, idlist->comments[i],
			    sshkey_type(idlist->ಕೀಲಿಗಳು[i]));
			ಮುಕ್ತ(fp);
		} ಅನ್ಯಥಾ {
			ಯದಿ ((r = sshkey_write(idlist->ಕೀಲಿಗಳು[i], stdout)) != 0) {
				fprintf(stderr, "sshkey_write: %s\n",
				    ssh_err(r));
				ಅನುವರ್ತ;
			}
			fprintf(stdout, " %s\n", idlist->comments[i]);
		}
	}
	ssh_free_identitylist(idlist);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
lock_agent(ಪೂರ್ಣಾಙ್ಕ agent_fd, ಪೂರ್ಣಾಙ್ಕ lock)
{
	ವರ್ಣ prompt[100], *p1, *p2;
	ಪೂರ್ಣಾಙ್ಕ r, passok = 1, ret = -1;

	strlcpy(prompt, "Enter lock password: ", ಪರಿಮಾಣ(prompt));
	p1 = read_passphrase(prompt, RP_ALLOW_STDIN);
	ಯದಿ (lock) {
		strlcpy(prompt, "Again: ", ಪರಿಮಾಣ prompt);
		p2 = read_passphrase(prompt, RP_ALLOW_STDIN);
		ಯದಿ (strcmp(p1, p2) != 0) {
			fprintf(stderr, "Passwords do not match.\n");
			passok = 0;
		}
		freezero(p2, strlen(p2));
	}
	ಯದಿ (passok) {
		ಯದಿ ((r = ssh_lock_agent(agent_fd, lock, p1)) == 0) {
			fprintf(stderr, "Agent %slocked.\n", lock ? "" : "un");
			ret = 0;
		} ಅನ್ಯಥಾ {
			fprintf(stderr, "Failed to %slock agent: %s\n",
			    lock ? "" : "un", ssh_err(r));
		}
	}
	freezero(p1, strlen(p1));
	ಪ್ರತ್ಯಾಗಮ (ret);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
load_resident_ಕೀಲಿಗಳು(ಪೂರ್ಣಾಙ್ಕ agent_fd, ಧ್ರುವ ವರ್ಣ *skprovider, ಪೂರ್ಣಾಙ್ಕ qflag, ಪೂರ್ಣಾಙ್ಕ no_pin,
    ಸಂರಚನಾ dest_constraint **dest_constraints, size_t ndest_constraints)
{
	ಸಂರಚನಾ sshsk_resident_ಕೀಲಿ **srks;
	size_t nsrks, i;
	ಸಂರಚನಾ sshkey *ಕೀಲಿ;
	ಪೂರ್ಣಾಙ್ಕ r, ok = 0;
	ವರ್ಣ *fp, *pin = ರಿಕ್ತ;

	ಯದಿ (!no_pin) {
		pin = read_passphrase("Enter PIN for authenticator: ",
		    RP_ALLOW_STDIN);
	}
	ಯದಿ ((r = sshsk_load_resident(skprovider, ರಿಕ್ತ, pin == ರಿಕ್ತ ? "" : pin,
	    0, &srks, &nsrks)) != 0) {
		error_r(r, "Unable to load resident keys");
		ಮುಕ್ತ(pin);
		ಪ್ರತ್ಯಾಗಮ r;
	}
	ಮುಕ್ತ(pin);
	ಪ್ರತಿ (i = 0; i < nsrks; i++) {
		ಕೀಲಿ = srks[i]->ಕೀಲಿ;
		ಯದಿ ((fp = sshkey_fingerprint(ಕೀಲಿ,
		    fingerprint_hash, SSH_FP_DEFAULT)) == ರಿಕ್ತ)
			fatal_f("sshkey_fingerprint failed");
		ಯದಿ ((r = ssh_add_identity_constrained(agent_fd, ಕೀಲಿ,
		    ಕೀಲಿ->sk_application, lifetime, confirm, skprovider,
		    dest_constraints, ndest_constraints)) != 0) {
			error("Unable to add key %s %s",
			    sshkey_type(ಕೀಲಿ), fp);
			ಮುಕ್ತ(fp);
			ok = r;
			ಅನುವರ್ತ;
		}
		ಯದಿ (ok == 0)
			ok = 1;
		ಯದಿ (!qflag) {
			fprintf(stderr, "Resident identity added: %s %s\n",
			    sshkey_type(ಕೀಲಿ), fp);
			ಯದಿ (lifetime != 0) {
				fprintf(stderr,
				    "Lifetime set to %d seconds\n", lifetime);
			}
			ಯದಿ (confirm != 0) {
				fprintf(stderr, "The user must confirm "
				    "each use of the key\n");
			}
		}
		ಮುಕ್ತ(fp);
	}
	sshsk_free_resident_ಕೀಲಿಗಳು(srks, nsrks);
	ಯದಿ (nsrks == 0)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_NOT_FOUND;
	ಪ್ರತ್ಯಾಗಮ ok == 1 ? 0 : ok;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
do_file(ಪೂರ್ಣಾಙ್ಕ agent_fd, ಪೂರ್ಣಾಙ್ಕ deleting, ಪೂರ್ಣಾಙ್ಕ ಕೀಲಿ_only, ಪೂರ್ಣಾಙ್ಕ cert_only,
    ವರ್ಣ *file, ಪೂರ್ಣಾಙ್ಕ qflag, ಪೂರ್ಣಾಙ್ಕ Nflag, ಧ್ರುವ ವರ್ಣ *skprovider,
    ಸಂರಚನಾ dest_constraint **dest_constraints, size_t ndest_constraints)
{
	ಯದಿ (deleting) {
		ಯದಿ (delete_file(agent_fd, file, ಕೀಲಿ_only,
		    cert_only, qflag) == -1)
			ಪ್ರತ್ಯಾಗಮ -1;
	} ಅನ್ಯಥಾ {
		ಯದಿ (add_file(agent_fd, file, ಕೀಲಿ_only, cert_only, qflag, Nflag,
		    skprovider, dest_constraints, ndest_constraints) == -1)
			ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
free_dest_constraint_hop(ಸಂರಚನಾ dest_constraint_hop *dch)
{
	u_int i;

	ಯದಿ (dch == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	ಮುಕ್ತ(dch->user);
	ಮುಕ್ತ(dch->hostname);
	ಪ್ರತಿ (i = 0; i < dch->nkeys; i++)
		sshkey_free(dch->ಕೀಲಿಗಳು[i]);
	ಮುಕ್ತ(dch->ಕೀಲಿಗಳು);
	ಮುಕ್ತ(dch->ಕೀಲಿ_is_ca);
}

ಸ್ಥಿರ ಶೂನ್ಯ
free_dest_constraints(ಸಂರಚನಾ dest_constraint **dcs, size_t ndcs)
{
	size_t i;

	ಪ್ರತಿ (i = 0; i < ndcs; i++) {
		free_dest_constraint_hop(&dcs[i]->from);
		free_dest_constraint_hop(&dcs[i]->to);
		ಮುಕ್ತ(dcs[i]);
	}
	ಮುಕ್ತ(dcs);
}


ಸ್ಥಿರ ಶೂನ್ಯ
parse_dest_constraint_hop(ಧ್ರುವ ವರ್ಣ *s, ಸಂರಚನಾ dest_constraint_hop *dch,
    ವರ್ಣ **hostkey_files)
{
	ವರ್ಣ *user = ರಿಕ್ತ, *host, *os, *path;
	size_t i;
	ಸಂರಚನಾ hostkeys *hostkeys;
	ಧ್ರುವ ಸಂರಚನಾ hostkey_entry *hke;
	ಪೂರ್ಣಾಙ್ಕ r, want_ca;

	memset(dch, '\0', ಪರಿಮಾಣ(*dch));
	os = xstrdup(s);
	ಯದಿ ((host = strrchr(os, '@')) == ರಿಕ್ತ)
		host = os;
	ಅನ್ಯಥಾ {
		*host++ = '\0';
		user = os;
	}
	cleanhostname(host);
	/* Trivial case: username@ (all hosts) */
	ಯದಿ (*host == '\0') {
		ಯದಿ (user == ರಿಕ್ತ) {
			fatal("Invalid key destination constraint \"%s\": "
			    "does not specify user or host", s);
		}
		dch->user = xstrdup(user);
		/* other fields left blank */
		ಮುಕ್ತ(os);
		ಪ್ರತ್ಯಾಗಮ;
	}
	ಯದಿ (hostkey_files == ರಿಕ್ತ)
		fatal_f("no hostkey files");
	/* Otherwise we need to look up the keys for this hostname */
	hostkeys = init_hostkeys();
	ಪ್ರತಿ (i = 0; hostkey_files[i]; i++) {
		path = tilde_expand_filename(hostkey_files[i], getuid());
		debug2_f("looking up host keys for \"%s\" in %s", host, path);
                load_hostkeys(hostkeys, host, path, 0);
		ಮುಕ್ತ(path);
	}
	dch->user = user == ರಿಕ್ತ ? ರಿಕ್ತ : xstrdup(user);
	dch->hostname = xstrdup(host);
	ಪ್ರತಿ (i = 0; i < hostkeys->ಅಂಕೆ_entries; i++) {
		hke = hostkeys->entries + i;
		want_ca = hke->marker == MRK_CA;
		ಯದಿ (hke->marker != MRK_NONE && !want_ca)
			ಅನುವರ್ತ;
		debug3_f("%s%s%s: adding %s %skey from %s:%lu as key %u",
		    user == ರಿಕ್ತ ? "": user, user == ರಿಕ್ತ ? "" : "@",
		    host, sshkey_type(hke->ಕೀಲಿ), want_ca ? "CA " : "",
		    hke->file, hke->ಸಾಲು, dch->nkeys);
		dch->ಕೀಲಿಗಳು = xrecallocarray(dch->ಕೀಲಿಗಳು, dch->nkeys,
		    dch->nkeys + 1, ಪರಿಮಾಣ(*dch->ಕೀಲಿಗಳು));
		dch->ಕೀಲಿ_is_ca = xrecallocarray(dch->ಕೀಲಿ_is_ca, dch->nkeys,
		    dch->nkeys + 1, ಪರಿಮಾಣ(*dch->ಕೀಲಿ_is_ca));
		ಯದಿ ((r = sshkey_from_private(hke->ಕೀಲಿ,
		    &(dch->ಕೀಲಿಗಳು[dch->nkeys]))) != 0)
			fatal_fr(r, "sshkey_from_private");
		dch->ಕೀಲಿ_is_ca[dch->nkeys] = want_ca;
		dch->nkeys++;
	}
	ಯದಿ (dch->nkeys == 0)
		fatal("No host keys found for destination \"%s\"", host);
	free_hostkeys(hostkeys);
	ಮುಕ್ತ(os);
	ಪ್ರತ್ಯಾಗಮ;
}

ಸ್ಥಿರ ಶೂನ್ಯ
parse_dest_constraint(ಧ್ರುವ ವರ್ಣ *s, ಸಂರಚನಾ dest_constraint ***dcp,
    size_t *ndcp, ವರ್ಣ **hostkey_files)
{
	ಸಂರಚನಾ dest_constraint *dc;
	ವರ್ಣ *os, *cp;

	dc = xcalloc(1, ಪರಿಮಾಣ(*dc));
	os = xstrdup(s);
	ಯದಿ ((cp = strchr(os, '>')) == ರಿಕ್ತ) {
		/* initial hop; no 'from' hop specified */
		parse_dest_constraint_hop(os, &dc->to, hostkey_files);
	} ಅನ್ಯಥಾ {
		/* two hops specified */
		*(cp++) = '\0';
		parse_dest_constraint_hop(os, &dc->from, hostkey_files);
		parse_dest_constraint_hop(cp, &dc->to, hostkey_files);
		ಯದಿ (dc->from.user != ರಿಕ್ತ) {
			fatal("Invalid key constraint %s: cannot specify "
			    "user on 'from' host", os);
		}
	}
	/* XXX eliminate or error on duplicates */
	debug2_f("constraint %zu: %s%s%s (%u keys) > %s%s%s (%u keys)", *ndcp,
	    dc->from.user ? dc->from.user : "", dc->from.user ? "@" : "",
	    dc->from.hostname ? dc->from.hostname : "(ORIGIN)", dc->from.nkeys,
	    dc->to.user ? dc->to.user : "", dc->to.user ? "@" : "",
	    dc->to.hostname ? dc->to.hostname : "(ANY)", dc->to.nkeys);
	*dcp = xrecallocarray(*dcp, *ndcp, *ndcp + 1, ಪರಿಮಾಣ(**dcp));
	(*dcp)[(*ndcp)++] = dc;
	ಮುಕ್ತ(os);
}


ಸ್ಥಿರ ಶೂನ್ಯ
usage(ಶೂನ್ಯ)
{
	fprintf(stderr,
"usage: ssh-add [-CcDdKkLlqvXx] [-E fingerprint_hash] [-H hostkey_file]\n"
"               [-h destination_constraint] [-S provider] [-t life]\n"
"               [file ...]\n"
"       ssh-add -s pkcs11 [-Cv] [certificate ...]\n"
"       ssh-add -e pkcs11\n"
"       ssh-add -T pubkey ...\n"
	);
}

ಪೂರ್ಣಾಙ್ಕ
main(ಪೂರ್ಣಾಙ್ಕ argc, ವರ್ಣ **argv)
{
	ಬಾಹ್ಯ ವರ್ಣ *optarg;
	ಬಾಹ್ಯ ಪೂರ್ಣಾಙ್ಕ optind;
	ಪೂರ್ಣಾಙ್ಕ agent_fd = -1;
	ವರ್ಣ *pkcs11provider = ರಿಕ್ತ, *skprovider = ರಿಕ್ತ;
	ವರ್ಣ **dest_constraint_strings = ರಿಕ್ತ, **hostkey_files = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r, i, ch, deleting = 0, ret = 0, ಕೀಲಿ_only = 0, cert_only = 0;
	ಪೂರ್ಣಾಙ್ಕ do_download = 0, xflag = 0, lflag = 0, Dflag = 0;
	ಪೂರ್ಣಾಙ್ಕ Qflag = 0, qflag = 0, Tflag = 0, Nflag = 0, no_pin = 0;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_INFO;
	ಸಂರಚನಾ sshkey *k, **certs = ರಿಕ್ತ;
	ಸಂರಚನಾ dest_constraint **dest_constraints = ರಿಕ್ತ;
	size_t n, ndest_constraints = 0, ncerts = 0;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	__progname = ssh_get_progname(argv[0]);
	seed_rng();

	log_init(__progname, log_level, log_facility, 1);

	setvbuf(stdout, ರಿಕ್ತ, _IOLBF, 0);

	skprovider = getenv("SSH_SK_PROVIDER");

	ಯಾವತ್ ((ch = getopt(argc, argv, "vkKlLNPCcdDTxXE:e:h:H:M:m:Qqs:S:t:")) != -1) {
		ವಿಕಲ್ಪ (ch) {
		ಪಕ್ಷ 'v':
			ಯದಿ (log_level == SYSLOG_LEVEL_INFO)
				log_level = SYSLOG_LEVEL_DEBUG1;
			ಅನ್ಯಥಾ ಯದಿ (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'N':
			Nflag = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			ಯದಿ (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			ಭಙ್ಗ;
		ಪಕ್ಷ 'H':
			stringlist_append(&hostkey_files, optarg);
			ಭಙ್ಗ;
		ಪಕ್ಷ 'h':
			stringlist_append(&dest_constraint_strings, optarg);
			ಭಙ್ಗ;
		ಪಕ್ಷ 'k':
			ಕೀಲಿ_only = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'C':
			cert_only = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'K':
			do_download = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'l':
		ಪಕ್ಷ 'L':
			ಯದಿ (lflag != 0)
				fatal("-%c flag already specified", lflag);
			lflag = ch;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'x':
		ಪಕ್ಷ 'X':
			ಯದಿ (xflag != 0)
				fatal("-%c flag already specified", xflag);
			xflag = ch;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'c':
			confirm = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'm':
		ಪಕ್ಷ 'M':
			/* deprecated */
			ಭಙ್ಗ;
		ಪಕ್ಷ 'd':
			deleting = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'P':
			no_pin = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'D':
			Dflag = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 's':
			pkcs11provider = optarg;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'S':
			skprovider = optarg;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'e':
			deleting = 1;
			pkcs11provider = optarg;
			ಭಙ್ಗ;
		ಪಕ್ಷ 't':
			ಯದಿ ((lifetime = convtime(optarg)) == -1 ||
			    lifetime < 0 || (u_long)lifetime > UINT32_MAX) {
				fprintf(stderr, "Invalid lifetime\n");
				ret = 1;
				ಗಚ್ಛ done;
			}
			ಭಙ್ಗ;
		ಪಕ್ಷ 'q':
			qflag = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'Q':
			Qflag = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'T':
			Tflag = 1;
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			usage();
			ret = 1;
			ಗಚ್ಛ done;
		}
	}
	log_init(__progname, log_level, log_facility, 1);

	ಯದಿ ((xflag != 0) + (lflag != 0) + (Dflag != 0) + (Qflag != 0) > 1)
		fatal("Invalid combination of actions");

	/* First, get a connection to the authentication agent. */
	ವಿಕಲ್ಪ (r = ssh_get_authentication_socket(&agent_fd)) {
	ಪಕ್ಷ 0:
		ಭಙ್ಗ;
	ಪಕ್ಷ SSH_ERR_AGENT_NOT_PRESENT:
		fprintf(stderr, "Could not open a connection to your "
		    "authentication agent.\n");
		exit(2);
	ಸ್ವಭಾವ:
		fprintf(stderr, "Error connecting to agent: %s\n", ssh_err(r));
		exit(2);
	}

	ಯದಿ (xflag) {
		ಯದಿ (lock_agent(agent_fd, xflag == 'x' ? 1 : 0) == -1)
			ret = 1;
		ಗಚ್ಛ done;
	} ಅನ್ಯಥಾ ಯದಿ (lflag) {
		ಯದಿ (list_identities(agent_fd, lflag == 'l' ? 1 : 0) == -1)
			ret = 1;
		ಗಚ್ಛ done;
	} ಅನ್ಯಥಾ ಯದಿ (Dflag) {
		ಯದಿ (delete_all(agent_fd, qflag) == -1)
			ret = 1;
		ಗಚ್ಛ done;
	} ಅನ್ಯಥಾ ಯದಿ (Qflag) {
		ಯದಿ (query_exts(agent_fd) == -1)
			ret = 1;
		ಗಚ್ಛ done;
	}

#ifdef ENABLE_SK_INTERNAL
	ಯದಿ (skprovider == ರಿಕ್ತ)
		skprovider = "internal";
#endif

	ಯದಿ (hostkey_files == ರಿಕ್ತ) {
		/* use defaults from readconf.c */
		stringlist_append(&hostkey_files, _PATH_SSH_USER_HOSTFILE);
		stringlist_append(&hostkey_files, _PATH_SSH_USER_HOSTFILE2);
		stringlist_append(&hostkey_files, _PATH_SSH_SYSTEM_HOSTFILE);
		stringlist_append(&hostkey_files, _PATH_SSH_SYSTEM_HOSTFILE2);
	}
	ಯದಿ (dest_constraint_strings != ರಿಕ್ತ) {
		ಪ್ರತಿ (i = 0; dest_constraint_strings[i] != ರಿಕ್ತ; i++) {
			parse_dest_constraint(dest_constraint_strings[i],
			  &dest_constraints, &ndest_constraints, hostkey_files);
		}
	}

	argc -= optind;
	argv += optind;
	ಯದಿ (Tflag) {
		ಯದಿ (argc <= 0)
			fatal("no keys to test");
		ಪ್ರತಿ (r = i = 0; i < argc; i++)
			r |= test_ಕೀಲಿ(agent_fd, argv[i]);
		ret = r == 0 ? 0 : 1;
		ಗಚ್ಛ done;
	}
	ಯದಿ (pkcs11provider != ರಿಕ್ತ) {
		ಪ್ರತಿ (i = 0; i < argc; i++) {
			ಯದಿ ((r = sshkey_load_public(argv[i], &k, ರಿಕ್ತ)) != 0)
				fatal_fr(r, "load certificate %s", argv[i]);
			certs = xrecallocarray(certs, ncerts, ncerts + 1,
			    ಪರಿಮಾಣ(*certs));
			debug2("%s: %s", argv[i], sshkey_ssh_name(k));
			certs[ncerts++] = k;
		}
		debug2_f("loaded %zu certificates", ncerts);
		ಯದಿ (update_card(agent_fd, !deleting, pkcs11provider,
		    qflag, no_pin, ಕೀಲಿ_only, cert_only,
		    dest_constraints, ndest_constraints,
		    certs, ncerts) == -1)
			ret = 1;
		ಪ್ರತಿ (n = 0; n < ncerts; n++)
			sshkey_free(certs[n]);
		ಮುಕ್ತ(certs);
		ಗಚ್ಛ done;
	}
	ಯದಿ (do_download) {
		ಯದಿ (skprovider == ರಿಕ್ತ)
			fatal("Cannot download keys without provider");
		ಯದಿ (load_resident_ಕೀಲಿಗಳು(agent_fd, skprovider, qflag, no_pin,
		    dest_constraints, ndest_constraints) != 0)
			ret = 1;
		ಗಚ್ಛ done;
	}
	ಯದಿ (argc == 0) {
		ವರ್ಣ buf[PATH_MAX];
		ಸಂರಚನಾ passwd *pw;
		ಸಂರಚನಾ stat st;
		ಪೂರ್ಣಾಙ್ಕ ಎಣಿಕೆ = 0;

		ಯದಿ ((pw = getpwuid(getuid())) == ರಿಕ್ತ) {
			fprintf(stderr, "No user found with uid %u\n",
			    (u_int)getuid());
			ret = 1;
			ಗಚ್ಛ done;
		}

		ಪ್ರತಿ (i = 0; default_files[i]; i++) {
			snprintf(buf, ಪರಿಮಾಣ(buf), "%s/%s", pw->pw_dir,
			    default_files[i]);
			ಯದಿ (stat(buf, &st) == -1)
				ಅನುವರ್ತ;
			ಯದಿ (do_file(agent_fd, deleting, ಕೀಲಿ_only, cert_only,
			    buf, qflag, Nflag, skprovider,
			    dest_constraints, ndest_constraints) == -1)
				ret = 1;
			ಅನ್ಯಥಾ
				ಎಣಿಕೆ++;
		}
		ಯದಿ (ಎಣಿಕೆ == 0)
			ret = 1;
	} ಅನ್ಯಥಾ {
		ಪ್ರತಿ (i = 0; i < argc; i++) {
			ಯದಿ (do_file(agent_fd, deleting, ಕೀಲಿ_only, cert_only,
			    argv[i], qflag, Nflag, skprovider,
			    dest_constraints, ndest_constraints) == -1)
				ret = 1;
		}
	}
done:
	clear_pass();
	stringlist_free(hostkey_files);
	stringlist_free(dest_constraint_strings);
	free_dest_constraints(dest_constraints, ndest_constraints);
	ssh_close_authentication_socket(agent_fd);
	ಪ್ರತ್ಯಾಗಮ ret;
}
