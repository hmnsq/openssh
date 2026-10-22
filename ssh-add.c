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

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
# include <openssl/evp.h>
# include "openbsd-compat/openssl-compat.h"
#ಆದರೆ_ಅಂತ್ಯ

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

#ವ್ಯಾಖ್ಯಾನಿಸು CERT_EXPIRY_GRACE	(5*60)

/* argv0 */
ಬಾಹ್ಯ ಅಕ್ಷರ *__progname;

/* Default files to add */
ಸ್ಥಿರ ಅಕ್ಷರ *default_files[] = {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	ಮಾರ್ಗ_SSH_CLIENT_ID_RSA,
	ಮಾರ್ಗ_SSH_CLIENT_ID_ECDSA,
	ಮಾರ್ಗ_SSH_CLIENT_ID_ECDSA_SK,
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
	ಮಾರ್ಗ_SSH_CLIENT_ID_ED25519,
	ಮಾರ್ಗ_SSH_CLIENT_ID_ED25519_SK,
	ಮಾರ್ಗ_SSH_CLIENT_ID_MLDSA44_ED25519,
	ಖಾಲಿ
};

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* Default lifetime (0 == forever) */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ lifetime = 0;

/* User has to confirm key use */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ confirm = 0;

/* we keep a cache of one passphrase */
ಸ್ಥಿರ ಅಕ್ಷರ *pass = ಖಾಲಿ;
ಸ್ಥಿರ ಶೂನ್ಯ
clear_pass(ಶೂನ್ಯ)
{
	ಆದರೆ (pass) {
		freezero(pass, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(pass));
		pass = ಖಾಲಿ;
	}
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
delete_one(ಪೂರ್ಣಾಂಕ agent_fd, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *comment,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, ಪೂರ್ಣಾಂಕ qflag)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = ssh_remove_ತಟಸ್ಥ(agent_fd, ಕೀಲಿ)) != 0) {
		fprintf(stderr, "Could not remove identity \"%s\": %s\n",
		    ಮಾರ್ಗ, ssh_err(r));
		ಹಿಂತಿರುಗಿ r;
	}
	ಆದರೆ (!qflag) {
		fprintf(stderr, "Identity removed: %s %s (%s)\n", ಮಾರ್ಗ,
		    sshkey_type(ಕೀಲಿ), comment ? comment : "no comment");
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
delete_stdin(ಪೂರ್ಣಾಂಕ agent_fd, ಪೂರ್ಣಾಂಕ qflag, ಪೂರ್ಣಾಂಕ ಕೀಲಿ_only, ಪೂರ್ಣಾಂಕ cert_only)
{
	ಅಕ್ಷರ *ಸಾಲು = ಖಾಲಿ, *cp;
	ಗಾತ್ರ_t linesize = 0;
	ರಚನೆ sshkey *ಕೀಲಿ = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ lnum = 0, r, ret = -1;

	ಆಗ (getline(&ಸಾಲು, &linesize, stdin) != -1) {
		lnum++;
		sshkey_free(ಕೀಲಿ);
		ಕೀಲಿ = ಖಾಲಿ;
		ಸಾಲು[strcspn(ಸಾಲು, "\n")] = '\0';
		cp = ಸಾಲು + strspn(ಸಾಲು, " \t");
		ಆದರೆ (*cp == '#' || *cp == '\0')
			ಮುಂದುವರಿ;
		ಆದರೆ ((ಕೀಲಿ = sshkey_new(ಕೀಲಿ_UNSPEC)) == ಖಾಲಿ)
			fatal_f("sshkey_new");
		ಆದರೆ ((r = sshkey_read(ಕೀಲಿ, &cp)) != 0) {
			error_r(r, "(stdin):%d: invalid key", lnum);
			ಮುಂದುವರಿ;
		}
		ಆದರೆ ((!ಕೀಲಿ_only && !cert_only) ||
		    (ಕೀಲಿ_only && !sshkey_is_cert(ಕೀಲಿ)) ||
		    (cert_only && sshkey_is_cert(ಕೀಲಿ))) {
			ಆದರೆ (delete_one(agent_fd, ಕೀಲಿ, cp,
			    "(stdin)", qflag) == 0)
				ret = 0;
		}
	}
	sshkey_free(ಕೀಲಿ);
	ಬಿಡುಗಡೆ(ಸಾಲು);
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
delete_file(ಪೂರ್ಣಾಂಕ agent_fd, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename, ಪೂರ್ಣಾಂಕ ಕೀಲಿ_only,
    ಪೂರ್ಣಾಂಕ cert_only, ಪೂರ್ಣಾಂಕ qflag)
{
	ರಚನೆ sshkey *ಸಾರ್ವಜನಿಕ, *cert = ಖಾಲಿ;
	ಅಕ್ಷರ *certpath = ಖಾಲಿ, *comment = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r, ret = -1;

	ಆದರೆ (strcmp(filename, "-") == 0)
		ಹಿಂತಿರುಗಿ delete_stdin(agent_fd, qflag, ಕೀಲಿ_only, cert_only);

	ಆದರೆ ((r = sshkey_ತುಂಬು_ಬಹಿರಂಗ(filename, &ಸಾರ್ವಜನಿಕ,  &comment)) != 0) {
		ಬರೆ("Bad key file %s: %s\n", filename, ssh_err(r));
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ ((!ಕೀಲಿ_only && !cert_only) ||
	    (ಕೀಲಿ_only && !sshkey_is_cert(ಸಾರ್ವಜನಿಕ)) ||
	    (cert_only && sshkey_is_cert(ಸಾರ್ವಜನಿಕ))) {
		ಆದರೆ (delete_one(agent_fd, ಸಾರ್ವಜನಿಕ, comment, filename, qflag) == 0)
			ret = 0;
	}

	ಆದರೆ (ಕೀಲಿ_only)
		ಹೋಗು ಹೊರಹೋಗು;

	/* Now try to delete the corresponding certificate too */
	ಬಿಡುಗಡೆ(comment);
	comment = ಖಾಲಿ;
	xasprintf(&certpath, "%s-cert.pub", filename);
	ಆದರೆ ((r = sshkey_ತುಂಬು_ಬಹಿರಂಗ(certpath, &cert, &comment)) != 0) {
		ಆದರೆ (r != SSH_ERR_SYSTEM_ERROR || errno != ENOENT)
			error_r(r, "Failed to load certificate \"%s\"", certpath);
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ (!sshkey_equal_ಬಹಿರಂಗ(cert, ಸಾರ್ವಜನಿಕ))
		fatal("Certificate %s does not match private key %s",
		    certpath, filename);

	ಆದರೆ (delete_one(agent_fd, cert, comment, certpath, qflag) == 0)
		ret = 0;

 ಹೊರಹೋಗು:
	sshkey_free(cert);
	sshkey_free(ಸಾರ್ವಜನಿಕ);
	ಬಿಡುಗಡೆ(certpath);
	ಬಿಡುಗಡೆ(comment);

	ಹಿಂತಿರುಗಿ ret;
}

/* Send a request to remove all identities. */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
delete_all(ಪೂರ್ಣಾಂಕ agent_fd, ಪೂರ್ಣಾಂಕ qflag)
{
	ಪೂರ್ಣಾಂಕ ret = -1;

	/*
	 * Since the agent might be forwarded, old or non-OpenSSH, when asked
	 * to remove all keys, attempt to remove both protocol v.1 and v.2
	 * keys.
	 */
	ಆದರೆ (ssh_remove_all_identities(agent_fd, 2) == 0)
		ret = 0;
	/* ignore error-code for ssh1 */
	ssh_remove_all_identities(agent_fd, 1);

	ಆದರೆ (ret != 0)
		fprintf(stderr, "Failed to remove all identities.\n");
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (!qflag)
		fprintf(stderr, "All identities removed.\n");

	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
query_exts(ಪೂರ್ಣಾಂಕ agent_fd)
{
	ಪೂರ್ಣಾಂಕ r;
	ಅಕ್ಷರ **exts = ಖಾಲಿ;
	ಗಾತ್ರ_t i;

	ಆದರೆ ((r = ssh_agent_query_extensions(agent_fd, &exts)) != 0)
		fatal_r(r, "unable to query supported extensions");
	ಗಾಗಿ (i = 0; exts != ಖಾಲಿ && exts[i] != ಖಾಲಿ; i++)
		puts(exts[i]);
	stringlist_free(exts);
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
check_cert_lifetime(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *cert, ಪೂರ್ಣಾಂಕ cert_lifetime)
{
	time_t now;
	uint64_t n;

	ಆದರೆ (cert == ಖಾಲಿ || cert->cert == ಖಾಲಿ || !sshkey_is_cert(cert) ||
	    cert->cert->valid_before == 0xFFFFFFFFFFFFFFFFULL)
		ಹಿಂತಿರುಗಿ cert_lifetime;
	ಆದರೆ ((now = time(ಖಾಲಿ)) <= 0)
		fatal_f("system time is at/before epoch");
	ಆದರೆ ((uint64_t)now > (cert->cert->valid_before + CERT_EXPIRY_GRACE))
		ಹಿಂತಿರುಗಿ -1; /* certificate already expired */
	n = (CERT_EXPIRY_GRACE + cert->cert->valid_before) - (uint64_t)now;
	n = MINIMUM(n, ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ);
	ಆದರೆ (cert_lifetime <= 0)
		ಹಿಂತಿರುಗಿ (ಪೂರ್ಣಾಂಕ)n;
	ಹಿಂತಿರುಗಿ MINIMUM(cert_lifetime, (ಪೂರ್ಣಾಂಕ)n);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಕೂಡಿಸು_file(ಪೂರ್ಣಾಂಕ agent_fd, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename, ಪೂರ್ಣಾಂಕ ಕೀಲಿ_only, ಪೂರ್ಣಾಂಕ cert_only,
    ಪೂರ್ಣಾಂಕ qflag, ಪೂರ್ಣಾಂಕ Nflag, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *skprovider,
    ರಚನೆ dest_constraint **dest_constraints,
    ಗಾತ್ರ_t ndest_constraints)
{
	ರಚನೆ sshkey *ಖಾಸಗಿ = ಖಾಲಿ, *cert = ಖಾಲಿ;
	ಅಕ್ಷರ *comment = ಖಾಲಿ;
	ಅಕ್ಷರ ಸಂದೇಶ[1024], *certpath = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ cert_lifetime, r, fd, ret = -1;
	ರಚನೆ sshbuf *keyblob;

	ಆದರೆ (strcmp(filename, "-") == 0) {
		fd = STDIN_FILENO;
		filename = "(stdin)";
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((fd = open(filename, O_RDONLY)) == -1) {
		perror(filename);
		ಹಿಂತಿರುಗಿ -1;
	}

	/*
	 * Since we'll try to load a keyfile multiple times, permission errors
	 * will occur multiple times, so check perms first and bail if wrong.
	 */
	ಆದರೆ (fd != STDIN_FILENO) {
		ಆದರೆ (sshkey_perm_ok(fd, filename) != 0) {
			close(fd);
			ಹಿಂತಿರುಗಿ -1;
		}
	}
	ಆದರೆ ((r = sshbuf_ತುಂಬು_fd(fd, &keyblob)) != 0) {
		fprintf(stderr, "Error loading key \"%s\": %s\n",
		    filename, ssh_err(r));
		sshbuf_free(keyblob);
		close(fd);
		ಹಿಂತಿರುಗಿ -1;
	}
	close(fd);

	/* At first, try empty passphrase */
	ಆದರೆ ((r = sshkey_parse_ಖಾಸಗಿ_fileblob(keyblob, "", &ಖಾಸಗಿ,
	    &comment)) != 0 && r != SSH_ERR_ಕೀಲಿ_WRONG_PASSPHRASE) {
		fprintf(stderr, "Error loading key \"%s\": %s\n",
		    filename, ssh_err(r));
		ಹೋಗು fail_ತುಂಬು;
	}
	/* try last */
	ಆದರೆ (ಖಾಸಗಿ == ಖಾಲಿ && pass != ಖಾಲಿ) {
		ಆದರೆ ((r = sshkey_parse_ಖಾಸಗಿ_fileblob(keyblob, pass, &ಖಾಸಗಿ,
		    &comment)) != 0 && r != SSH_ERR_ಕೀಲಿ_WRONG_PASSPHRASE) {
			fprintf(stderr, "Error loading key \"%s\": %s\n",
			    filename, ssh_err(r));
			ಹೋಗು fail_ತುಂಬು;
		}
	}
	ಆದರೆ (ಖಾಸಗಿ == ಖಾಲಿ) {
		/* clear passphrase since it did not work */
		clear_pass();
		snprintf(ಸಂದೇಶ, ಗಾತ್ರ ಸಂದೇಶ, "Enter passphrase for %s%s: ",
		    filename, confirm ? " (will confirm each use)" : "");
		ಗಾಗಿ (;;) {
			pass = read_passphrase(ಸಂದೇಶ, RP_ALLOW_STDIN);
			ಆದರೆ (strcmp(pass, "") == 0)
				ಹೋಗು fail_ತುಂಬು;
			ಆದರೆ ((r = sshkey_parse_ಖಾಸಗಿ_fileblob(keyblob, pass,
			    &ಖಾಸಗಿ, &comment)) == 0)
				ನಿಲ್ಲಿಸು;
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (r != SSH_ERR_ಕೀಲಿ_WRONG_PASSPHRASE) {
				fprintf(stderr,
				    "Error loading key \"%s\": %s\n",
				    filename, ssh_err(r));
 fail_ತುಂಬು:
				clear_pass();
				sshbuf_free(keyblob);
				ಹಿಂತಿರುಗಿ -1;
			}
			clear_pass();
			snprintf(ಸಂದೇಶ, ಗಾತ್ರ ಸಂದೇಶ,
			    "Bad passphrase, try again for %s%s: ", filename,
			    confirm ? " (will confirm each use)" : "");
		}
	}
	ಆದರೆ (comment == ಖಾಲಿ || *comment == '\0')
		comment = xstrdup(filename);
	sshbuf_free(keyblob);

	ಆದರೆ (sshkey_is_sk(ಖಾಸಗಿ)) {
		ಆದರೆ (skprovider == ಖಾಲಿ) {
			fprintf(stderr, "Cannot load FIDO key %s "
			    "without provider\n", filename);
			ಹೋಗು ಹೊರಹೋಗು;
		}
	} ಇಲ್ಲದಿದ್ದರೆ {
		/* Don't send provider constraint for other keys */
		skprovider = ಖಾಲಿ;
	}

	ಆದರೆ (!cert_only) {
		ಆದರೆ ((r = ssh_ಕೂಡಿಸು_ತಟಸ್ಥ_constrained(agent_fd, ಖಾಸಗಿ,
		    comment, lifetime, confirm, skprovider,
		    dest_constraints, ndest_constraints)) == 0) {
			ret = 0;
			ಆದರೆ (!qflag) {
				fprintf(stderr, "Identity added: %s (%s)\n",
				    filename, comment);
				ಆದರೆ (lifetime != 0) {
					fprintf(stderr, "Lifetime set to %s\n",
					    fmt_timeframe((time_t)lifetime));
				}
				ಆದರೆ (confirm != 0) {
					fprintf(stderr, "The user must confirm "
					    "each use of the key\n");
				}
			}
		} ಇಲ್ಲದಿದ್ದರೆ {
			fprintf(stderr, "Could not add identity \"%s\": %s\n",
			    filename, ssh_err(r));
		}
	}

	/* Skip trying to load the cert if requested */
	ಆದರೆ (ಕೀಲಿ_only)
		ಹೋಗು ಹೊರಹೋಗು;

	/* Now try to add the certificate flavour too */
	xasprintf(&certpath, "%s-cert.pub", filename);
	ಆದರೆ ((r = sshkey_ತುಂಬು_ಬಹಿರಂಗ(certpath, &cert, ಖಾಲಿ)) != 0) {
		ಆದರೆ (r != SSH_ERR_SYSTEM_ERROR || errno != ENOENT)
			error_r(r, "Failed to load certificate \"%s\"",
			    certpath);
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ (!sshkey_equal_ಬಹಿರಂಗ(cert, ಖಾಸಗಿ)) {
		error("Certificate %s does not match private key %s",
		    certpath, filename);
		ಹೋಗು ಹೊರಹೋಗು;
	}

	cert_lifetime = lifetime;
	ಆದರೆ (!Nflag &&
	    (cert_lifetime = check_cert_lifetime(cert, cert_lifetime)) == -1) {
		logit("Certificate %s has already expired; ignored", certpath);
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* Graft with private bits */
	ಆದರೆ ((r = sshkey_ಗಮ್ಯ_certified(ಖಾಸಗಿ)) != 0) {
		error_fr(r, "sshkey_to_certified");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshkey_cert_copy(cert, ಖಾಸಗಿ)) != 0) {
		error_fr(r, "sshkey_cert_copy");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* send to agent */
	ಆದರೆ ((r = ssh_ಕೂಡಿಸು_ತಟಸ್ಥ_constrained(agent_fd, ಖಾಸಗಿ, comment,
	    cert_lifetime, confirm, skprovider,
	    dest_constraints, ndest_constraints)) != 0) {
		error_r(r, "Certificate %s (%s) add failed", certpath,
		    ಖಾಸಗಿ->cert->ಕೀಲಿ_id);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* success */
	ಆದರೆ (!qflag) {
		fprintf(stderr, "Certificate added: %s (%s)\n", certpath,
		    ಖಾಸಗಿ->cert->ಕೀಲಿ_id);
		ಆದರೆ (cert_lifetime != 0) {
			fprintf(stderr, "Lifetime set to %s\n",
			    fmt_timeframe((time_t)cert_lifetime));
		}
		ಆದರೆ (confirm != 0) {
			fprintf(stderr, "The user must confirm each use "
			    "of the key\n");
		}
	}

 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(certpath);
	ಬಿಡುಗಡೆ(comment);
	sshkey_free(cert);
	sshkey_free(ಖಾಸಗಿ);

	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
update_card(ಪೂರ್ಣಾಂಕ agent_fd, ಪೂರ್ಣಾಂಕ ಕೂಡಿಸು, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *id, ಪೂರ್ಣಾಂಕ qflag, ಪೂರ್ಣಾಂಕ no_pin,
    ಪೂರ್ಣಾಂಕ ಕೀಲಿ_only, ಪೂರ್ಣಾಂಕ cert_only,
    ರಚನೆ dest_constraint **dest_constraints, ಗಾತ್ರ_t ndest_constraints,
    ರಚನೆ sshkey **certs, ಗಾತ್ರ_t ncerts)
{
	ಅಕ್ಷರ *pin = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r, ret = -1;

	ಆದರೆ (ಕೀಲಿ_only)
		ncerts = 0;

	ಆದರೆ (ಕೂಡಿಸು && !no_pin) {
		ಆದರೆ ((pin = read_passphrase("Enter passphrase for PKCS#11: ",
		    RP_ALLOW_STDIN)) == ಖಾಲಿ)
			ಹಿಂತಿರುಗಿ -1;
	}

	ಆದರೆ ((r = ssh_update_card(agent_fd, ಕೂಡಿಸು, id, pin == ಖಾಲಿ ? "" : pin,
	    lifetime, confirm, dest_constraints, ndest_constraints,
	    cert_only, certs, ncerts)) == 0) {
		ret = 0;
		ಆದರೆ (!qflag) {
			fprintf(stderr, "Card %s: %s\n",
			    ಕೂಡಿಸು ? "added" : "removed", id);
		}
	} ಇಲ್ಲದಿದ್ದರೆ {
		fprintf(stderr, "Could not %s card \"%s\": %s\n",
		    ಕೂಡಿಸು ? "add" : "remove", id, ssh_err(r));
		ret = -1;
	}
	ಬಿಡುಗಡೆ(pin);
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
test_ಕೀಲಿ(ಪೂರ್ಣಾಂಕ agent_fd, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename)
{
	ರಚನೆ sshkey *ಕೀಲಿ = ಖಾಲಿ;
	u_char *sig = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *alg = ಖಾಲಿ;
	ಗಾತ್ರ_t slen = 0;
	ಪೂರ್ಣಾಂಕ r, ret = -1;
	ಅಕ್ಷರ ದತ್ತಾಂಶ[1024];

	ಆದರೆ ((r = sshkey_ತುಂಬು_ಬಹಿರಂಗ(filename, &ಕೀಲಿ, ಖಾಲಿ)) != 0) {
		error_r(r, "Couldn't read public key %s", filename);
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ (sshkey_type_plain(ಕೀಲಿ->type) == ಕೀಲಿ_RSA)
		alg = "rsa-sha2-256";
	arc4random_buf(ದತ್ತಾಂಶ, ಗಾತ್ರ(ದತ್ತಾಂಶ));
	ಆದರೆ ((r = ssh_agent_sign(agent_fd, ಕೀಲಿ, &sig, &slen, ದತ್ತಾಂಶ, ಗಾತ್ರ(ದತ್ತಾಂಶ),
	    alg, 0)) != 0) {
		error_r(r, "Agent signature failed for %s", filename);
		ಹೋಗು ಮುಗಿದ;
	}
	ಆದರೆ ((r = sshkey_verify(ಕೀಲಿ, sig, slen, ದತ್ತಾಂಶ, ಗಾತ್ರ(ದತ್ತಾಂಶ),
	    alg, 0, ಖಾಲಿ)) != 0) {
		error_r(r, "Signature verification failed for %s", filename);
		ಹೋಗು ಮುಗಿದ;
	}
	/* success */
	ret = 0;
 ಮುಗಿದ:
	ಬಿಡುಗಡೆ(sig);
	sshkey_free(ಕೀಲಿ);
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
list_identities(ಪೂರ್ಣಾಂಕ agent_fd, ಪೂರ್ಣಾಂಕ do_fp)
{
	ಅಕ್ಷರ *fp;
	ಪೂರ್ಣಾಂಕ r;
	ರಚನೆ ssh_identitylist *idlist;
	ಗಾತ್ರ_t i;

	ಆದರೆ ((r = ssh_fetch_identitylist(agent_fd, &idlist)) != 0) {
		ಆದರೆ (r != SSH_ERR_AGENT_NO_IDENTITIES)
			fprintf(stderr, "error fetching identities: %s\n",
			    ssh_err(r));
		ಇಲ್ಲದಿದ್ದರೆ
			ಬರೆ("The agent has no identities.\n");
		ಹಿಂತಿರುಗಿ -1;
	}
	ಗಾಗಿ (i = 0; i < idlist->nkeys; i++) {
		ಆದರೆ (do_fp) {
			fp = sshkey_fingerprint(idlist->ಕೀಲಿಗಳು[i],
			    fingerprint_hash, SSH_FP_DEFAULT);
			ಬರೆ("%u %s %s (%s)\n", sshkey_ಗಾತ್ರ(idlist->ಕೀಲಿಗಳು[i]),
			    fp == ಖಾಲಿ ? "(null)" : fp, idlist->comments[i],
			    sshkey_type(idlist->ಕೀಲಿಗಳು[i]));
			ಬಿಡುಗಡೆ(fp);
		} ಇಲ್ಲದಿದ್ದರೆ {
			ಆದರೆ ((r = sshkey_write(idlist->ಕೀಲಿಗಳು[i], stdout)) != 0) {
				fprintf(stderr, "sshkey_write: %s\n",
				    ssh_err(r));
				ಮುಂದುವರಿ;
			}
			fprintf(stdout, " %s\n", idlist->comments[i]);
		}
	}
	ssh_free_identitylist(idlist);
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಬೀಗ_agent(ಪೂರ್ಣಾಂಕ agent_fd, ಪೂರ್ಣಾಂಕ ಬೀಗ)
{
	ಅಕ್ಷರ prompt[100], *p1, *p2;
	ಪೂರ್ಣಾಂಕ r, passok = 1, ret = -1;

	strlcpy(prompt, "Enter lock password: ", ಗಾತ್ರ(prompt));
	p1 = read_passphrase(prompt, RP_ALLOW_STDIN);
	ಆದರೆ (ಬೀಗ) {
		strlcpy(prompt, "Again: ", ಗಾತ್ರ prompt);
		p2 = read_passphrase(prompt, RP_ALLOW_STDIN);
		ಆದರೆ (strcmp(p1, p2) != 0) {
			fprintf(stderr, "Passwords do not match.\n");
			passok = 0;
		}
		freezero(p2, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(p2));
	}
	ಆದರೆ (passok) {
		ಆದರೆ ((r = ssh_ಬೀಗ_agent(agent_fd, ಬೀಗ, p1)) == 0) {
			fprintf(stderr, "Agent %slocked.\n", ಬೀಗ ? "" : "un");
			ret = 0;
		} ಇಲ್ಲದಿದ್ದರೆ {
			fprintf(stderr, "Failed to %slock agent: %s\n",
			    ಬೀಗ ? "" : "un", ssh_err(r));
		}
	}
	freezero(p1, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(p1));
	ಹಿಂತಿರುಗಿ (ret);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ತುಂಬು_resident_ಕೀಲಿಗಳು(ಪೂರ್ಣಾಂಕ agent_fd, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *skprovider, ಪೂರ್ಣಾಂಕ qflag, ಪೂರ್ಣಾಂಕ no_pin,
    ರಚನೆ dest_constraint **dest_constraints, ಗಾತ್ರ_t ndest_constraints)
{
	ರಚನೆ sshsk_resident_ಕೀಲಿ **srks;
	ಗಾತ್ರ_t nsrks, i;
	ರಚನೆ sshkey *ಕೀಲಿ;
	ಪೂರ್ಣಾಂಕ r, ok = 0;
	ಅಕ್ಷರ *fp, *pin = ಖಾಲಿ;

	ಆದರೆ (!no_pin) {
		pin = read_passphrase("Enter PIN for authenticator: ",
		    RP_ALLOW_STDIN);
	}
	ಆದರೆ ((r = sshsk_ತುಂಬು_resident(skprovider, ಖಾಲಿ, pin == ಖಾಲಿ ? "" : pin,
	    0, &srks, &nsrks)) != 0) {
		error_r(r, "Unable to load resident keys");
		ಬಿಡುಗಡೆ(pin);
		ಹಿಂತಿರುಗಿ r;
	}
	ಬಿಡುಗಡೆ(pin);
	ಗಾಗಿ (i = 0; i < nsrks; i++) {
		ಕೀಲಿ = srks[i]->ಕೀಲಿ;
		ಆದರೆ ((fp = sshkey_fingerprint(ಕೀಲಿ,
		    fingerprint_hash, SSH_FP_DEFAULT)) == ಖಾಲಿ)
			fatal_f("sshkey_fingerprint failed");
		ಆದರೆ ((r = ssh_ಕೂಡಿಸು_ತಟಸ್ಥ_constrained(agent_fd, ಕೀಲಿ,
		    ಕೀಲಿ->sk_application, lifetime, confirm, skprovider,
		    dest_constraints, ndest_constraints)) != 0) {
			error("Unable to add key %s %s",
			    sshkey_type(ಕೀಲಿ), fp);
			ಬಿಡುಗಡೆ(fp);
			ok = r;
			ಮುಂದುವರಿ;
		}
		ಆದರೆ (ok == 0)
			ok = 1;
		ಆದರೆ (!qflag) {
			fprintf(stderr, "Resident identity added: %s %s\n",
			    sshkey_type(ಕೀಲಿ), fp);
			ಆದರೆ (lifetime != 0) {
				fprintf(stderr,
				    "Lifetime set to %d seconds\n", lifetime);
			}
			ಆದರೆ (confirm != 0) {
				fprintf(stderr, "The user must confirm "
				    "each use of the key\n");
			}
		}
		ಬಿಡುಗಡೆ(fp);
	}
	sshsk_free_resident_ಕೀಲಿಗಳು(srks, nsrks);
	ಆದರೆ (nsrks == 0)
		ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_NOT_ಸಿಕ್ಕಿತು;
	ಹಿಂತಿರುಗಿ ok == 1 ? 0 : ok;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
do_file(ಪೂರ್ಣಾಂಕ agent_fd, ಪೂರ್ಣಾಂಕ deleting, ಪೂರ್ಣಾಂಕ ಕೀಲಿ_only, ಪೂರ್ಣಾಂಕ cert_only,
    ಅಕ್ಷರ *file, ಪೂರ್ಣಾಂಕ qflag, ಪೂರ್ಣಾಂಕ Nflag, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *skprovider,
    ರಚನೆ dest_constraint **dest_constraints, ಗಾತ್ರ_t ndest_constraints)
{
	ಆದರೆ (deleting) {
		ಆದರೆ (delete_file(agent_fd, file, ಕೀಲಿ_only,
		    cert_only, qflag) == -1)
			ಹಿಂತಿರುಗಿ -1;
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ (ಕೂಡಿಸು_file(agent_fd, file, ಕೀಲಿ_only, cert_only, qflag, Nflag,
		    skprovider, dest_constraints, ndest_constraints) == -1)
			ಹಿಂತಿರುಗಿ -1;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
free_dest_constraint_hop(ರಚನೆ dest_constraint_hop *dch)
{
	u_int i;

	ಆದರೆ (dch == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	ಬಿಡುಗಡೆ(dch->user);
	ಬಿಡುಗಡೆ(dch->hostname);
	ಗಾಗಿ (i = 0; i < dch->nkeys; i++)
		sshkey_free(dch->ಕೀಲಿಗಳು[i]);
	ಬಿಡುಗಡೆ(dch->ಕೀಲಿಗಳು);
	ಬಿಡುಗಡೆ(dch->ಕೀಲಿ_is_ca);
}

ಸ್ಥಿರ ಶೂನ್ಯ
free_dest_constraints(ರಚನೆ dest_constraint **dcs, ಗಾತ್ರ_t ndcs)
{
	ಗಾತ್ರ_t i;

	ಗಾಗಿ (i = 0; i < ndcs; i++) {
		free_dest_constraint_hop(&dcs[i]->from);
		free_dest_constraint_hop(&dcs[i]->ಗಮ್ಯ);
		ಬಿಡುಗಡೆ(dcs[i]);
	}
	ಬಿಡುಗಡೆ(dcs);
}


ಸ್ಥಿರ ಶೂನ್ಯ
parse_dest_constraint_hop(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s, ರಚನೆ dest_constraint_hop *dch,
    ಅಕ್ಷರ **hostkey_files)
{
	ಅಕ್ಷರ *user = ಖಾಲಿ, *host, *os, *ಮಾರ್ಗ;
	ಗಾತ್ರ_t i;
	ರಚನೆ hostkeys *hostkeys;
	ಸ್ಥಿರಾಂಕ ರಚನೆ hostkey_ನಮೂದು *hke;
	ಪೂರ್ಣಾಂಕ r, want_ca;

	memset(dch, '\0', ಗಾತ್ರ(*dch));
	os = xstrdup(s);
	ಆದರೆ ((host = strrchr(os, '@')) == ಖಾಲಿ)
		host = os;
	ಇಲ್ಲದಿದ್ದರೆ {
		*host++ = '\0';
		user = os;
	}
	cleanhostname(host);
	/* Trivial case: username@ (all hosts) */
	ಆದರೆ (*host == '\0') {
		ಆದರೆ (user == ಖಾಲಿ) {
			fatal("Invalid key destination constraint \"%s\": "
			    "does not specify user or host", s);
		}
		dch->user = xstrdup(user);
		/* other fields left blank */
		ಬಿಡುಗಡೆ(os);
		ಹಿಂತಿರುಗಿ;
	}
	ಆದರೆ (hostkey_files == ಖಾಲಿ)
		fatal_f("no hostkey files");
	/* Otherwise we need to look up the keys for this hostname */
	hostkeys = init_hostkeys();
	ಗಾಗಿ (i = 0; hostkey_files[i]; i++) {
		ಮಾರ್ಗ = tilde_expand_filename(hostkey_files[i], getuid());
		debug2_f("looking up host keys for \"%s\" in %s", host, ಮಾರ್ಗ);
                ತುಂಬು_hostkeys(hostkeys, host, ಮಾರ್ಗ, 0);
		ಬಿಡುಗಡೆ(ಮಾರ್ಗ);
	}
	dch->user = user == ಖಾಲಿ ? ಖಾಲಿ : xstrdup(user);
	dch->hostname = xstrdup(host);
	ಗಾಗಿ (i = 0; i < hostkeys->ಅಂಕೆ_entries; i++) {
		hke = hostkeys->entries + i;
		want_ca = hke->marker == MRK_CA;
		ಆದರೆ (hke->marker != MRK_NONE && !want_ca)
			ಮುಂದುವರಿ;
		debug3_f("%s%s%s: adding %s %skey from %s:%lu as key %u",
		    user == ಖಾಲಿ ? "": user, user == ಖಾಲಿ ? "" : "@",
		    host, sshkey_type(hke->ಕೀಲಿ), want_ca ? "CA " : "",
		    hke->file, hke->ಸಾಲು, dch->nkeys);
		dch->ಕೀಲಿಗಳು = xrecallocarray(dch->ಕೀಲಿಗಳು, dch->nkeys,
		    dch->nkeys + 1, ಗಾತ್ರ(*dch->ಕೀಲಿಗಳು));
		dch->ಕೀಲಿ_is_ca = xrecallocarray(dch->ಕೀಲಿ_is_ca, dch->nkeys,
		    dch->nkeys + 1, ಗಾತ್ರ(*dch->ಕೀಲಿ_is_ca));
		ಆದರೆ ((r = sshkey_from_ಖಾಸಗಿ(hke->ಕೀಲಿ,
		    &(dch->ಕೀಲಿಗಳು[dch->nkeys]))) != 0)
			fatal_fr(r, "sshkey_from_private");
		dch->ಕೀಲಿ_is_ca[dch->nkeys] = want_ca;
		dch->nkeys++;
	}
	ಆದರೆ (dch->nkeys == 0)
		fatal("No host keys found for destination \"%s\"", host);
	free_hostkeys(hostkeys);
	ಬಿಡುಗಡೆ(os);
	ಹಿಂತಿರುಗಿ;
}

ಸ್ಥಿರ ಶೂನ್ಯ
parse_dest_constraint(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s, ರಚನೆ dest_constraint ***dcp,
    ಗಾತ್ರ_t *ndcp, ಅಕ್ಷರ **hostkey_files)
{
	ರಚನೆ dest_constraint *dc;
	ಅಕ್ಷರ *os, *cp;

	dc = xcalloc(1, ಗಾತ್ರ(*dc));
	os = xstrdup(s);
	ಆದರೆ ((cp = strchr(os, '>')) == ಖಾಲಿ) {
		/* initial hop; no 'from' hop specified */
		parse_dest_constraint_hop(os, &dc->ಗಮ್ಯ, hostkey_files);
	} ಇಲ್ಲದಿದ್ದರೆ {
		/* two hops specified */
		*(cp++) = '\0';
		parse_dest_constraint_hop(os, &dc->from, hostkey_files);
		parse_dest_constraint_hop(cp, &dc->ಗಮ್ಯ, hostkey_files);
		ಆದರೆ (dc->from.user != ಖಾಲಿ) {
			fatal("Invalid key constraint %s: cannot specify "
			    "user on 'from' host", os);
		}
	}
	/* XXX eliminate or error on duplicates */
	debug2_f("constraint %zu: %s%s%s (%u keys) > %s%s%s (%u keys)", *ndcp,
	    dc->from.user ? dc->from.user : "", dc->from.user ? "@" : "",
	    dc->from.hostname ? dc->from.hostname : "(ORIGIN)", dc->from.nkeys,
	    dc->ಗಮ್ಯ.user ? dc->ಗಮ್ಯ.user : "", dc->ಗಮ್ಯ.user ? "@" : "",
	    dc->ಗಮ್ಯ.hostname ? dc->ಗಮ್ಯ.hostname : "(ANY)", dc->ಗಮ್ಯ.nkeys);
	*dcp = xrecallocarray(*dcp, *ndcp, *ndcp + 1, ಗಾತ್ರ(**dcp));
	(*dcp)[(*ndcp)++] = dc;
	ಬಿಡುಗಡೆ(os);
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

ಪೂರ್ಣಾಂಕ
ಮುಖ್ಯ(ಪೂರ್ಣಾಂಕ argc, ಅಕ್ಷರ **argv)
{
	ಬಾಹ್ಯ ಅಕ್ಷರ *optarg;
	ಬಾಹ್ಯ ಪೂರ್ಣಾಂಕ optind;
	ಪೂರ್ಣಾಂಕ agent_fd = -1;
	ಅಕ್ಷರ *pkcs11provider = ಖಾಲಿ, *skprovider = ಖಾಲಿ;
	ಅಕ್ಷರ **dest_constraint_ಅಕ್ಷರಸರಣಿಗಳು = ಖಾಲಿ, **hostkey_files = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r, i, ch, deleting = 0, ret = 0, ಕೀಲಿ_only = 0, cert_only = 0;
	ಪೂರ್ಣಾಂಕ do_download = 0, xflag = 0, lflag = 0, Dflag = 0;
	ಪೂರ್ಣಾಂಕ Qflag = 0, qflag = 0, Tflag = 0, Nflag = 0, no_pin = 0;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_INFO;
	ರಚನೆ sshkey *k, **certs = ಖಾಲಿ;
	ರಚನೆ dest_constraint **dest_constraints = ಖಾಲಿ;
	ಗಾತ್ರ_t n, ndest_constraints = 0, ncerts = 0;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	__progname = ssh_get_progname(argv[0]);
	ಬೀಜ_rng();

	log_init(__progname, log_level, log_facility, 1);

	setvbuf(stdout, ಖಾಲಿ, _IOLBF, 0);

	skprovider = getenv("SSH_SK_PROVIDER");

	ಆಗ ((ch = getopt(argc, argv, "vkKlLNPCcdDTxXE:e:h:H:M:m:Qqs:S:t:")) != -1) {
		ಆಯ್ಕೆ (ch) {
		ಸ್ಥಿತಿ 'v':
			ಆದರೆ (log_level == SYSLOG_LEVEL_INFO)
				log_level = SYSLOG_LEVEL_DEBUG1;
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'N':
			Nflag = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			ಆದರೆ (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'H':
			stringlist_append(&hostkey_files, optarg);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'h':
			stringlist_append(&dest_constraint_ಅಕ್ಷರಸರಣಿಗಳು, optarg);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'k':
			ಕೀಲಿ_only = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'C':
			cert_only = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'K':
			do_download = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'l':
		ಸ್ಥಿತಿ 'L':
			ಆದರೆ (lflag != 0)
				fatal("-%c flag already specified", lflag);
			lflag = ch;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'x':
		ಸ್ಥಿತಿ 'X':
			ಆದರೆ (xflag != 0)
				fatal("-%c flag already specified", xflag);
			xflag = ch;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'c':
			confirm = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'm':
		ಸ್ಥಿತಿ 'M':
			/* deprecated */
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'd':
			deleting = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'P':
			no_pin = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'D':
			Dflag = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 's':
			pkcs11provider = optarg;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'S':
			skprovider = optarg;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'e':
			deleting = 1;
			pkcs11provider = optarg;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 't':
			ಆದರೆ ((lifetime = convtime(optarg)) == -1 ||
			    lifetime < 0 || (u_long)lifetime > UINT32_MAX) {
				fprintf(stderr, "Invalid lifetime\n");
				ret = 1;
				ಹೋಗು ಮುಗಿದ;
			}
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'q':
			qflag = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'Q':
			Qflag = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'T':
			Tflag = 1;
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			usage();
			ret = 1;
			ಹೋಗು ಮುಗಿದ;
		}
	}
	log_init(__progname, log_level, log_facility, 1);

	ಆದರೆ ((xflag != 0) + (lflag != 0) + (Dflag != 0) + (Qflag != 0) > 1)
		fatal("Invalid combination of actions");

	/* First, get a connection to the authentication agent. */
	ಆಯ್ಕೆ (r = ssh_get_authentication_socket(&agent_fd)) {
	ಸ್ಥಿತಿ 0:
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SSH_ERR_AGENT_NOT_PRESENT:
		fprintf(stderr, "Could not open a connection to your "
		    "authentication agent.\n");
		ನಿರ್ಗಮಿಸು(2);
	ಪೂರ್ವನಿಯೋಜಿತ:
		fprintf(stderr, "Error connecting to agent: %s\n", ssh_err(r));
		ನಿರ್ಗಮಿಸು(2);
	}

	ಆದರೆ (xflag) {
		ಆದರೆ (ಬೀಗ_agent(agent_fd, xflag == 'x' ? 1 : 0) == -1)
			ret = 1;
		ಹೋಗು ಮುಗಿದ;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (lflag) {
		ಆದರೆ (list_identities(agent_fd, lflag == 'l' ? 1 : 0) == -1)
			ret = 1;
		ಹೋಗು ಮುಗಿದ;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (Dflag) {
		ಆದರೆ (delete_all(agent_fd, qflag) == -1)
			ret = 1;
		ಹೋಗು ಮುಗಿದ;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (Qflag) {
		ಆದರೆ (query_exts(agent_fd) == -1)
			ret = 1;
		ಹೋಗು ಮುಗಿದ;
	}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ ENABLE_SK_ಆಂತರಿಕ
	ಆದರೆ (skprovider == ಖಾಲಿ)
		skprovider = "internal";
#ಆದರೆ_ಅಂತ್ಯ

	ಆದರೆ (hostkey_files == ಖಾಲಿ) {
		/* use defaults from readconf.c */
		stringlist_append(&hostkey_files, ಮಾರ್ಗ_SSH_USER_HOSTFILE);
		stringlist_append(&hostkey_files, ಮಾರ್ಗ_SSH_USER_HOSTFILE2);
		stringlist_append(&hostkey_files, ಮಾರ್ಗ_SSH_SYSTEM_HOSTFILE);
		stringlist_append(&hostkey_files, ಮಾರ್ಗ_SSH_SYSTEM_HOSTFILE2);
	}
	ಆದರೆ (dest_constraint_ಅಕ್ಷರಸರಣಿಗಳು != ಖಾಲಿ) {
		ಗಾಗಿ (i = 0; dest_constraint_ಅಕ್ಷರಸರಣಿಗಳು[i] != ಖಾಲಿ; i++) {
			parse_dest_constraint(dest_constraint_ಅಕ್ಷರಸರಣಿಗಳು[i],
			  &dest_constraints, &ndest_constraints, hostkey_files);
		}
	}

	argc -= optind;
	argv += optind;
	ಆದರೆ (Tflag) {
		ಆದರೆ (argc <= 0)
			fatal("no keys to test");
		ಗಾಗಿ (r = i = 0; i < argc; i++)
			r |= test_ಕೀಲಿ(agent_fd, argv[i]);
		ret = r == 0 ? 0 : 1;
		ಹೋಗು ಮುಗಿದ;
	}
	ಆದರೆ (pkcs11provider != ಖಾಲಿ) {
		ಗಾಗಿ (i = 0; i < argc; i++) {
			ಆದರೆ ((r = sshkey_ತುಂಬು_ಬಹಿರಂಗ(argv[i], &k, ಖಾಲಿ)) != 0)
				fatal_fr(r, "load certificate %s", argv[i]);
			certs = xrecallocarray(certs, ncerts, ncerts + 1,
			    ಗಾತ್ರ(*certs));
			debug2("%s: %s", argv[i], sshkey_ssh_name(k));
			certs[ncerts++] = k;
		}
		debug2_f("loaded %zu certificates", ncerts);
		ಆದರೆ (update_card(agent_fd, !deleting, pkcs11provider,
		    qflag, no_pin, ಕೀಲಿ_only, cert_only,
		    dest_constraints, ndest_constraints,
		    certs, ncerts) == -1)
			ret = 1;
		ಗಾಗಿ (n = 0; n < ncerts; n++)
			sshkey_free(certs[n]);
		ಬಿಡುಗಡೆ(certs);
		ಹೋಗು ಮುಗಿದ;
	}
	ಆದರೆ (do_download) {
		ಆದರೆ (skprovider == ಖಾಲಿ)
			fatal("Cannot download keys without provider");
		ಆದರೆ (ತುಂಬು_resident_ಕೀಲಿಗಳು(agent_fd, skprovider, qflag, no_pin,
		    dest_constraints, ndest_constraints) != 0)
			ret = 1;
		ಹೋಗು ಮುಗಿದ;
	}
	ಆದರೆ (argc == 0) {
		ಅಕ್ಷರ buf[PATH_MAX];
		ರಚನೆ passwd *pw;
		ರಚನೆ stat st;
		ಪೂರ್ಣಾಂಕ ಎಣಿಕೆ_2 = 0;

		ಆದರೆ ((pw = getpwuid(getuid())) == ಖಾಲಿ) {
			fprintf(stderr, "No user found with uid %u\n",
			    (u_int)getuid());
			ret = 1;
			ಹೋಗು ಮುಗಿದ;
		}

		ಗಾಗಿ (i = 0; default_files[i]; i++) {
			snprintf(buf, ಗಾತ್ರ(buf), "%s/%s", pw->pw_dir,
			    default_files[i]);
			ಆದರೆ (stat(buf, &st) == -1)
				ಮುಂದುವರಿ;
			ಆದರೆ (do_file(agent_fd, deleting, ಕೀಲಿ_only, cert_only,
			    buf, qflag, Nflag, skprovider,
			    dest_constraints, ndest_constraints) == -1)
				ret = 1;
			ಇಲ್ಲದಿದ್ದರೆ
				ಎಣಿಕೆ_2++;
		}
		ಆದರೆ (ಎಣಿಕೆ_2 == 0)
			ret = 1;
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಗಾಗಿ (i = 0; i < argc; i++) {
			ಆದರೆ (do_file(agent_fd, deleting, ಕೀಲಿ_only, cert_only,
			    argv[i], qflag, Nflag, skprovider,
			    dest_constraints, ndest_constraints) == -1)
				ret = 1;
		}
	}
ಮುಗಿದ:
	clear_pass();
	stringlist_free(hostkey_files);
	stringlist_free(dest_constraint_ಅಕ್ಷರಸರಣಿಗಳು);
	free_dest_constraints(dest_constraints, ndest_constraints);
	ssh_close_authentication_socket(agent_fd);
	ಹಿಂತಿರುಗಿ ret;
}
