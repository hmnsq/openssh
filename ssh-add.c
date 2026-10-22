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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/stat.h>

#నిర్వచితమైతే WITH_OPENSSL
# include <openssl/evp.h>
# include "openbsd-compat/openssl-compat.h"
#అయితే_ముగింపు

#అన్తర్భావ <errno.h>
#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <pwd.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <limits.h>
#అన్తర్భావ <time.h>

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "ssh.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "authfd.h"
#అన్తర్భావ "authfile.h"
#అన్తర్భావ "pathnames.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "digest.h"
#అన్తర్భావ "ssh-sk.h"
#అన్తర్భావ "sk-api.h"
#అన్తర్భావ "hostfile.h"

#నిర్వచించు CERT_EXPIRY_GRACE	(5*60)

/* argv0 */
బాహ్య అక్షరం *__progname;

/* Default files to add */
స్థిర అక్షరం *default_files[] = {
#నిర్వచితమైతే WITH_OPENSSL
	మార్గం_SSH_CLIENT_ID_RSA,
	మార్గం_SSH_CLIENT_ID_ECDSA,
	మార్గం_SSH_CLIENT_ID_ECDSA_SK,
#అయితే_ముగింపు /* WITH_OPENSSL */
	మార్గం_SSH_CLIENT_ID_ED25519,
	మార్గం_SSH_CLIENT_ID_ED25519_SK,
	మార్గం_SSH_CLIENT_ID_MLDSA44_ED25519,
	ఖాళీ
};

స్థిర పూర్ణాంకం fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* Default lifetime (0 == forever) */
స్థిర పూర్ణాంకం lifetime = 0;

/* User has to confirm key use */
స్థిర పూర్ణాంకం confirm = 0;

/* we keep a cache of one passphrase */
స్థిర అక్షరం *pass = ఖాళీ;
స్థిర శూన్య
clear_pass(శూన్య)
{
	ఒకవేళ (pass) {
		freezero(pass, అక్షరశ్రేణి_పొడవు(pass));
		pass = ఖాళీ;
	}
}

స్థిర పూర్ణాంకం
delete_one(పూర్ణాంకం agent_fd, స్థిరరాశి నిర్మాణం sshkey *కీలకం, స్థిరరాశి అక్షరం *comment,
    స్థిరరాశి అక్షరం *మార్గం, పూర్ణాంకం qflag)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = ssh_remove_తటస్థం(agent_fd, కీలకం)) != 0) {
		fprintf(stderr, "Could not remove identity \"%s\": %s\n",
		    మార్గం, ssh_err(r));
		తిరిగి r;
	}
	ఒకవేళ (!qflag) {
		fprintf(stderr, "Identity removed: %s %s (%s)\n", మార్గం,
		    sshkey_type(కీలకం), comment ? comment : "no comment");
	}
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
delete_stdin(పూర్ణాంకం agent_fd, పూర్ణాంకం qflag, పూర్ణాంకం కీలకం_only, పూర్ణాంకం cert_only)
{
	అక్షరం *పంక్తి = ఖాళీ, *cp;
	కొలత_t linesize = 0;
	నిర్మాణం sshkey *కీలకం = ఖాళీ;
	పూర్ణాంకం lnum = 0, r, ret = -1;

	అయితే (getline(&పంక్తి, &linesize, stdin) != -1) {
		lnum++;
		sshkey_free(కీలకం);
		కీలకం = ఖాళీ;
		పంక్తి[strcspn(పంక్తి, "\n")] = '\0';
		cp = పంక్తి + strspn(పంక్తి, " \t");
		ఒకవేళ (*cp == '#' || *cp == '\0')
			కొనసాగు;
		ఒకవేళ ((కీలకం = sshkey_new(కీలకం_UNSPEC)) == ఖాళీ)
			fatal_f("sshkey_new");
		ఒకవేళ ((r = sshkey_read(కీలకం, &cp)) != 0) {
			error_r(r, "(stdin):%d: invalid key", lnum);
			కొనసాగు;
		}
		ఒకవేళ ((!కీలకం_only && !cert_only) ||
		    (కీలకం_only && !sshkey_is_cert(కీలకం)) ||
		    (cert_only && sshkey_is_cert(కీలకం))) {
			ఒకవేళ (delete_one(agent_fd, కీలకం, cp,
			    "(stdin)", qflag) == 0)
				ret = 0;
		}
	}
	sshkey_free(కీలకం);
	విడుదల(పంక్తి);
	తిరిగి ret;
}

స్థిర పూర్ణాంకం
delete_file(పూర్ణాంకం agent_fd, స్థిరరాశి అక్షరం *filename, పూర్ణాంకం కీలకం_only,
    పూర్ణాంకం cert_only, పూర్ణాంకం qflag)
{
	నిర్మాణం sshkey *బహిరంగ, *cert = ఖాళీ;
	అక్షరం *certpath = ఖాళీ, *comment = ఖాళీ;
	పూర్ణాంకం r, ret = -1;

	ఒకవేళ (strcmp(filename, "-") == 0)
		తిరిగి delete_stdin(agent_fd, qflag, కీలకం_only, cert_only);

	ఒకవేళ ((r = sshkey_ఎక్కించు_ప్రజా(filename, &బహిరంగ,  &comment)) != 0) {
		రాయి("Bad key file %s: %s\n", filename, ssh_err(r));
		తిరిగి -1;
	}
	ఒకవేళ ((!కీలకం_only && !cert_only) ||
	    (కీలకం_only && !sshkey_is_cert(బహిరంగ)) ||
	    (cert_only && sshkey_is_cert(బహిరంగ))) {
		ఒకవేళ (delete_one(agent_fd, బహిరంగ, comment, filename, qflag) == 0)
			ret = 0;
	}

	ఒకవేళ (కీలకం_only)
		వెళ్ళు బహిర్గతం;

	/* Now try to delete the corresponding certificate too */
	విడుదల(comment);
	comment = ఖాళీ;
	xasprintf(&certpath, "%s-cert.pub", filename);
	ఒకవేళ ((r = sshkey_ఎక్కించు_ప్రజా(certpath, &cert, &comment)) != 0) {
		ఒకవేళ (r != SSH_ERR_SYSTEM_ERROR || errno != ENOENT)
			error_r(r, "Failed to load certificate \"%s\"", certpath);
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ (!sshkey_equal_ప్రజా(cert, బహిరంగ))
		fatal("Certificate %s does not match private key %s",
		    certpath, filename);

	ఒకవేళ (delete_one(agent_fd, cert, comment, certpath, qflag) == 0)
		ret = 0;

 బహిర్గతం:
	sshkey_free(cert);
	sshkey_free(బహిరంగ);
	విడుదల(certpath);
	విడుదల(comment);

	తిరిగి ret;
}

/* Send a request to remove all identities. */
స్థిర పూర్ణాంకం
delete_all(పూర్ణాంకం agent_fd, పూర్ణాంకం qflag)
{
	పూర్ణాంకం ret = -1;

	/*
	 * Since the agent might be forwarded, old or non-OpenSSH, when asked
	 * to remove all keys, attempt to remove both protocol v.1 and v.2
	 * keys.
	 */
	ఒకవేళ (ssh_remove_all_identities(agent_fd, 2) == 0)
		ret = 0;
	/* ignore error-code for ssh1 */
	ssh_remove_all_identities(agent_fd, 1);

	ఒకవేళ (ret != 0)
		fprintf(stderr, "Failed to remove all identities.\n");
	లేకపోతే ఒకవేళ (!qflag)
		fprintf(stderr, "All identities removed.\n");

	తిరిగి ret;
}

స్థిర పూర్ణాంకం
query_exts(పూర్ణాంకం agent_fd)
{
	పూర్ణాంకం r;
	అక్షరం **exts = ఖాళీ;
	కొలత_t i;

	ఒకవేళ ((r = ssh_agent_query_extensions(agent_fd, &exts)) != 0)
		fatal_r(r, "unable to query supported extensions");
	కొరకు (i = 0; exts != ఖాళీ && exts[i] != ఖాళీ; i++)
		puts(exts[i]);
	stringlist_free(exts);
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
check_cert_lifetime(స్థిరరాశి నిర్మాణం sshkey *cert, పూర్ణాంకం cert_lifetime)
{
	time_t now;
	uint64_t n;

	ఒకవేళ (cert == ఖాళీ || cert->cert == ఖాళీ || !sshkey_is_cert(cert) ||
	    cert->cert->valid_before == 0xFFFFFFFFFFFFFFFFULL)
		తిరిగి cert_lifetime;
	ఒకవేళ ((now = time(ఖాళీ)) <= 0)
		fatal_f("system time is at/before epoch");
	ఒకవేళ ((uint64_t)now > (cert->cert->valid_before + CERT_EXPIRY_GRACE))
		తిరిగి -1; /* certificate already expired */
	n = (CERT_EXPIRY_GRACE + cert->cert->valid_before) - (uint64_t)now;
	n = MINIMUM(n, గరిష్ఠ_పూర్ణాంకం);
	ఒకవేళ (cert_lifetime <= 0)
		తిరిగి (పూర్ణాంకం)n;
	తిరిగి MINIMUM(cert_lifetime, (పూర్ణాంకం)n);
}

స్థిర పూర్ణాంకం
కూడు_file(పూర్ణాంకం agent_fd, స్థిరరాశి అక్షరం *filename, పూర్ణాంకం కీలకం_only, పూర్ణాంకం cert_only,
    పూర్ణాంకం qflag, పూర్ణాంకం Nflag, స్థిరరాశి అక్షరం *skprovider,
    నిర్మాణం dest_constraint **dest_constraints,
    కొలత_t ndest_constraints)
{
	నిర్మాణం sshkey *అంతరంగ = ఖాళీ, *cert = ఖాళీ;
	అక్షరం *comment = ఖాళీ;
	అక్షరం సందేశం[1024], *certpath = ఖాళీ;
	పూర్ణాంకం cert_lifetime, r, fd, ret = -1;
	నిర్మాణం sshbuf *keyblob;

	ఒకవేళ (strcmp(filename, "-") == 0) {
		fd = STDIN_FILENO;
		filename = "(stdin)";
	} లేకపోతే ఒకవేళ ((fd = open(filename, O_RDONLY)) == -1) {
		perror(filename);
		తిరిగి -1;
	}

	/*
	 * Since we'll try to load a keyfile multiple times, permission errors
	 * will occur multiple times, so check perms first and bail if wrong.
	 */
	ఒకవేళ (fd != STDIN_FILENO) {
		ఒకవేళ (sshkey_perm_ok(fd, filename) != 0) {
			close(fd);
			తిరిగి -1;
		}
	}
	ఒకవేళ ((r = sshbuf_ఎక్కించు_fd(fd, &keyblob)) != 0) {
		fprintf(stderr, "Error loading key \"%s\": %s\n",
		    filename, ssh_err(r));
		sshbuf_free(keyblob);
		close(fd);
		తిరిగి -1;
	}
	close(fd);

	/* At first, try empty passphrase */
	ఒకవేళ ((r = sshkey_parse_వ్యక్తిగత_fileblob(keyblob, "", &అంతరంగ,
	    &comment)) != 0 && r != SSH_ERR_కీలకం_WRONG_PASSPHRASE) {
		fprintf(stderr, "Error loading key \"%s\": %s\n",
		    filename, ssh_err(r));
		వెళ్ళు fail_ఎక్కించు;
	}
	/* try last */
	ఒకవేళ (అంతరంగ == ఖాళీ && pass != ఖాళీ) {
		ఒకవేళ ((r = sshkey_parse_వ్యక్తిగత_fileblob(keyblob, pass, &అంతరంగ,
		    &comment)) != 0 && r != SSH_ERR_కీలకం_WRONG_PASSPHRASE) {
			fprintf(stderr, "Error loading key \"%s\": %s\n",
			    filename, ssh_err(r));
			వెళ్ళు fail_ఎక్కించు;
		}
	}
	ఒకవేళ (అంతరంగ == ఖాళీ) {
		/* clear passphrase since it did not work */
		clear_pass();
		snprintf(సందేశం, పరిమాణం సందేశం, "Enter passphrase for %s%s: ",
		    filename, confirm ? " (will confirm each use)" : "");
		కొరకు (;;) {
			pass = read_passphrase(సందేశం, RP_ALLOW_STDIN);
			ఒకవేళ (strcmp(pass, "") == 0)
				వెళ్ళు fail_ఎక్కించు;
			ఒకవేళ ((r = sshkey_parse_వ్యక్తిగత_fileblob(keyblob, pass,
			    &అంతరంగ, &comment)) == 0)
				ఆపు;
			లేకపోతే ఒకవేళ (r != SSH_ERR_కీలకం_WRONG_PASSPHRASE) {
				fprintf(stderr,
				    "Error loading key \"%s\": %s\n",
				    filename, ssh_err(r));
 fail_ఎక్కించు:
				clear_pass();
				sshbuf_free(keyblob);
				తిరిగి -1;
			}
			clear_pass();
			snprintf(సందేశం, పరిమాణం సందేశం,
			    "Bad passphrase, try again for %s%s: ", filename,
			    confirm ? " (will confirm each use)" : "");
		}
	}
	ఒకవేళ (comment == ఖాళీ || *comment == '\0')
		comment = xstrdup(filename);
	sshbuf_free(keyblob);

	ఒకవేళ (sshkey_is_sk(అంతరంగ)) {
		ఒకవేళ (skprovider == ఖాళీ) {
			fprintf(stderr, "Cannot load FIDO key %s "
			    "without provider\n", filename);
			వెళ్ళు బహిర్గతం;
		}
	} లేకపోతే {
		/* Don't send provider constraint for other keys */
		skprovider = ఖాళీ;
	}

	ఒకవేళ (!cert_only) {
		ఒకవేళ ((r = ssh_కూడు_తటస్థం_constrained(agent_fd, అంతరంగ,
		    comment, lifetime, confirm, skprovider,
		    dest_constraints, ndest_constraints)) == 0) {
			ret = 0;
			ఒకవేళ (!qflag) {
				fprintf(stderr, "Identity added: %s (%s)\n",
				    filename, comment);
				ఒకవేళ (lifetime != 0) {
					fprintf(stderr, "Lifetime set to %s\n",
					    fmt_timeframe((time_t)lifetime));
				}
				ఒకవేళ (confirm != 0) {
					fprintf(stderr, "The user must confirm "
					    "each use of the key\n");
				}
			}
		} లేకపోతే {
			fprintf(stderr, "Could not add identity \"%s\": %s\n",
			    filename, ssh_err(r));
		}
	}

	/* Skip trying to load the cert if requested */
	ఒకవేళ (కీలకం_only)
		వెళ్ళు బహిర్గతం;

	/* Now try to add the certificate flavour too */
	xasprintf(&certpath, "%s-cert.pub", filename);
	ఒకవేళ ((r = sshkey_ఎక్కించు_ప్రజా(certpath, &cert, ఖాళీ)) != 0) {
		ఒకవేళ (r != SSH_ERR_SYSTEM_ERROR || errno != ENOENT)
			error_r(r, "Failed to load certificate \"%s\"",
			    certpath);
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ (!sshkey_equal_ప్రజా(cert, అంతరంగ)) {
		error("Certificate %s does not match private key %s",
		    certpath, filename);
		వెళ్ళు బహిర్గతం;
	}

	cert_lifetime = lifetime;
	ఒకవేళ (!Nflag &&
	    (cert_lifetime = check_cert_lifetime(cert, cert_lifetime)) == -1) {
		logit("Certificate %s has already expired; ignored", certpath);
		వెళ్ళు బహిర్గతం;
	}

	/* Graft with private bits */
	ఒకవేళ ((r = sshkey_గమ్యం_certified(అంతరంగ)) != 0) {
		error_fr(r, "sshkey_to_certified");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshkey_cert_copy(cert, అంతరంగ)) != 0) {
		error_fr(r, "sshkey_cert_copy");
		వెళ్ళు బహిర్గతం;
	}
	/* send to agent */
	ఒకవేళ ((r = ssh_కూడు_తటస్థం_constrained(agent_fd, అంతరంగ, comment,
	    cert_lifetime, confirm, skprovider,
	    dest_constraints, ndest_constraints)) != 0) {
		error_r(r, "Certificate %s (%s) add failed", certpath,
		    అంతరంగ->cert->కీలకం_id);
		వెళ్ళు బహిర్గతం;
	}
	/* success */
	ఒకవేళ (!qflag) {
		fprintf(stderr, "Certificate added: %s (%s)\n", certpath,
		    అంతరంగ->cert->కీలకం_id);
		ఒకవేళ (cert_lifetime != 0) {
			fprintf(stderr, "Lifetime set to %s\n",
			    fmt_timeframe((time_t)cert_lifetime));
		}
		ఒకవేళ (confirm != 0) {
			fprintf(stderr, "The user must confirm each use "
			    "of the key\n");
		}
	}

 బహిర్గతం:
	విడుదల(certpath);
	విడుదల(comment);
	sshkey_free(cert);
	sshkey_free(అంతరంగ);

	తిరిగి ret;
}

స్థిర పూర్ణాంకం
update_card(పూర్ణాంకం agent_fd, పూర్ణాంకం కూడు, స్థిరరాశి అక్షరం *id, పూర్ణాంకం qflag, పూర్ణాంకం no_pin,
    పూర్ణాంకం కీలకం_only, పూర్ణాంకం cert_only,
    నిర్మాణం dest_constraint **dest_constraints, కొలత_t ndest_constraints,
    నిర్మాణం sshkey **certs, కొలత_t ncerts)
{
	అక్షరం *pin = ఖాళీ;
	పూర్ణాంకం r, ret = -1;

	ఒకవేళ (కీలకం_only)
		ncerts = 0;

	ఒకవేళ (కూడు && !no_pin) {
		ఒకవేళ ((pin = read_passphrase("Enter passphrase for PKCS#11: ",
		    RP_ALLOW_STDIN)) == ఖాళీ)
			తిరిగి -1;
	}

	ఒకవేళ ((r = ssh_update_card(agent_fd, కూడు, id, pin == ఖాళీ ? "" : pin,
	    lifetime, confirm, dest_constraints, ndest_constraints,
	    cert_only, certs, ncerts)) == 0) {
		ret = 0;
		ఒకవేళ (!qflag) {
			fprintf(stderr, "Card %s: %s\n",
			    కూడు ? "added" : "removed", id);
		}
	} లేకపోతే {
		fprintf(stderr, "Could not %s card \"%s\": %s\n",
		    కూడు ? "add" : "remove", id, ssh_err(r));
		ret = -1;
	}
	విడుదల(pin);
	తిరిగి ret;
}

స్థిర పూర్ణాంకం
test_కీలకం(పూర్ణాంకం agent_fd, స్థిరరాశి అక్షరం *filename)
{
	నిర్మాణం sshkey *కీలకం = ఖాళీ;
	u_char *sig = ఖాళీ;
	స్థిరరాశి అక్షరం *alg = ఖాళీ;
	కొలత_t slen = 0;
	పూర్ణాంకం r, ret = -1;
	అక్షరం దత్తాంశం[1024];

	ఒకవేళ ((r = sshkey_ఎక్కించు_ప్రజా(filename, &కీలకం, ఖాళీ)) != 0) {
		error_r(r, "Couldn't read public key %s", filename);
		తిరిగి -1;
	}
	ఒకవేళ (sshkey_type_plain(కీలకం->type) == కీలకం_RSA)
		alg = "rsa-sha2-256";
	arc4random_buf(దత్తాంశం, పరిమాణం(దత్తాంశం));
	ఒకవేళ ((r = ssh_agent_sign(agent_fd, కీలకం, &sig, &slen, దత్తాంశం, పరిమాణం(దత్తాంశం),
	    alg, 0)) != 0) {
		error_r(r, "Agent signature failed for %s", filename);
		వెళ్ళు పూర్తి;
	}
	ఒకవేళ ((r = sshkey_verify(కీలకం, sig, slen, దత్తాంశం, పరిమాణం(దత్తాంశం),
	    alg, 0, ఖాళీ)) != 0) {
		error_r(r, "Signature verification failed for %s", filename);
		వెళ్ళు పూర్తి;
	}
	/* success */
	ret = 0;
 పూర్తి:
	విడుదల(sig);
	sshkey_free(కీలకం);
	తిరిగి ret;
}

స్థిర పూర్ణాంకం
list_identities(పూర్ణాంకం agent_fd, పూర్ణాంకం do_fp)
{
	అక్షరం *fp;
	పూర్ణాంకం r;
	నిర్మాణం ssh_identitylist *idlist;
	కొలత_t i;

	ఒకవేళ ((r = ssh_fetch_identitylist(agent_fd, &idlist)) != 0) {
		ఒకవేళ (r != SSH_ERR_AGENT_NO_IDENTITIES)
			fprintf(stderr, "error fetching identities: %s\n",
			    ssh_err(r));
		లేకపోతే
			రాయి("The agent has no identities.\n");
		తిరిగి -1;
	}
	కొరకు (i = 0; i < idlist->nkeys; i++) {
		ఒకవేళ (do_fp) {
			fp = sshkey_fingerprint(idlist->కీలకాలు[i],
			    fingerprint_hash, SSH_FP_DEFAULT);
			రాయి("%u %s %s (%s)\n", sshkey_కొలత(idlist->కీలకాలు[i]),
			    fp == ఖాళీ ? "(null)" : fp, idlist->comments[i],
			    sshkey_type(idlist->కీలకాలు[i]));
			విడుదల(fp);
		} లేకపోతే {
			ఒకవేళ ((r = sshkey_write(idlist->కీలకాలు[i], stdout)) != 0) {
				fprintf(stderr, "sshkey_write: %s\n",
				    ssh_err(r));
				కొనసాగు;
			}
			fprintf(stdout, " %s\n", idlist->comments[i]);
		}
	}
	ssh_free_identitylist(idlist);
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
తాళం_agent(పూర్ణాంకం agent_fd, పూర్ణాంకం తాళం)
{
	అక్షరం prompt[100], *p1, *p2;
	పూర్ణాంకం r, passok = 1, ret = -1;

	strlcpy(prompt, "Enter lock password: ", పరిమాణం(prompt));
	p1 = read_passphrase(prompt, RP_ALLOW_STDIN);
	ఒకవేళ (తాళం) {
		strlcpy(prompt, "Again: ", పరిమాణం prompt);
		p2 = read_passphrase(prompt, RP_ALLOW_STDIN);
		ఒకవేళ (strcmp(p1, p2) != 0) {
			fprintf(stderr, "Passwords do not match.\n");
			passok = 0;
		}
		freezero(p2, అక్షరశ్రేణి_పొడవు(p2));
	}
	ఒకవేళ (passok) {
		ఒకవేళ ((r = ssh_తాళం_agent(agent_fd, తాళం, p1)) == 0) {
			fprintf(stderr, "Agent %slocked.\n", తాళం ? "" : "un");
			ret = 0;
		} లేకపోతే {
			fprintf(stderr, "Failed to %slock agent: %s\n",
			    తాళం ? "" : "un", ssh_err(r));
		}
	}
	freezero(p1, అక్షరశ్రేణి_పొడవు(p1));
	తిరిగి (ret);
}

స్థిర పూర్ణాంకం
ఎక్కించు_resident_కీలకాలు(పూర్ణాంకం agent_fd, స్థిరరాశి అక్షరం *skprovider, పూర్ణాంకం qflag, పూర్ణాంకం no_pin,
    నిర్మాణం dest_constraint **dest_constraints, కొలత_t ndest_constraints)
{
	నిర్మాణం sshsk_resident_కీలకం **srks;
	కొలత_t nsrks, i;
	నిర్మాణం sshkey *కీలకం;
	పూర్ణాంకం r, ok = 0;
	అక్షరం *fp, *pin = ఖాళీ;

	ఒకవేళ (!no_pin) {
		pin = read_passphrase("Enter PIN for authenticator: ",
		    RP_ALLOW_STDIN);
	}
	ఒకవేళ ((r = sshsk_ఎక్కించు_resident(skprovider, ఖాళీ, pin == ఖాళీ ? "" : pin,
	    0, &srks, &nsrks)) != 0) {
		error_r(r, "Unable to load resident keys");
		విడుదల(pin);
		తిరిగి r;
	}
	విడుదల(pin);
	కొరకు (i = 0; i < nsrks; i++) {
		కీలకం = srks[i]->కీలకం;
		ఒకవేళ ((fp = sshkey_fingerprint(కీలకం,
		    fingerprint_hash, SSH_FP_DEFAULT)) == ఖాళీ)
			fatal_f("sshkey_fingerprint failed");
		ఒకవేళ ((r = ssh_కూడు_తటస్థం_constrained(agent_fd, కీలకం,
		    కీలకం->sk_application, lifetime, confirm, skprovider,
		    dest_constraints, ndest_constraints)) != 0) {
			error("Unable to add key %s %s",
			    sshkey_type(కీలకం), fp);
			విడుదల(fp);
			ok = r;
			కొనసాగు;
		}
		ఒకవేళ (ok == 0)
			ok = 1;
		ఒకవేళ (!qflag) {
			fprintf(stderr, "Resident identity added: %s %s\n",
			    sshkey_type(కీలకం), fp);
			ఒకవేళ (lifetime != 0) {
				fprintf(stderr,
				    "Lifetime set to %d seconds\n", lifetime);
			}
			ఒకవేళ (confirm != 0) {
				fprintf(stderr, "The user must confirm "
				    "each use of the key\n");
			}
		}
		విడుదల(fp);
	}
	sshsk_free_resident_కీలకాలు(srks, nsrks);
	ఒకవేళ (nsrks == 0)
		తిరిగి SSH_ERR_కీలకం_NOT_దొరికింది;
	తిరిగి ok == 1 ? 0 : ok;
}

స్థిర పూర్ణాంకం
do_file(పూర్ణాంకం agent_fd, పూర్ణాంకం deleting, పూర్ణాంకం కీలకం_only, పూర్ణాంకం cert_only,
    అక్షరం *file, పూర్ణాంకం qflag, పూర్ణాంకం Nflag, స్థిరరాశి అక్షరం *skprovider,
    నిర్మాణం dest_constraint **dest_constraints, కొలత_t ndest_constraints)
{
	ఒకవేళ (deleting) {
		ఒకవేళ (delete_file(agent_fd, file, కీలకం_only,
		    cert_only, qflag) == -1)
			తిరిగి -1;
	} లేకపోతే {
		ఒకవేళ (కూడు_file(agent_fd, file, కీలకం_only, cert_only, qflag, Nflag,
		    skprovider, dest_constraints, ndest_constraints) == -1)
			తిరిగి -1;
	}
	తిరిగి 0;
}

స్థిర శూన్య
free_dest_constraint_hop(నిర్మాణం dest_constraint_hop *dch)
{
	u_int i;

	ఒకవేళ (dch == ఖాళీ)
		తిరిగి;
	విడుదల(dch->user);
	విడుదల(dch->hostname);
	కొరకు (i = 0; i < dch->nkeys; i++)
		sshkey_free(dch->కీలకాలు[i]);
	విడుదల(dch->కీలకాలు);
	విడుదల(dch->కీలకం_is_ca);
}

స్థిర శూన్య
free_dest_constraints(నిర్మాణం dest_constraint **dcs, కొలత_t ndcs)
{
	కొలత_t i;

	కొరకు (i = 0; i < ndcs; i++) {
		free_dest_constraint_hop(&dcs[i]->from);
		free_dest_constraint_hop(&dcs[i]->గమ్యం);
		విడుదల(dcs[i]);
	}
	విడుదల(dcs);
}


స్థిర శూన్య
parse_dest_constraint_hop(స్థిరరాశి అక్షరం *s, నిర్మాణం dest_constraint_hop *dch,
    అక్షరం **hostkey_files)
{
	అక్షరం *user = ఖాళీ, *host, *os, *మార్గం;
	కొలత_t i;
	నిర్మాణం hostkeys *hostkeys;
	స్థిరరాశి నిర్మాణం hostkey_నమోదు *hke;
	పూర్ణాంకం r, want_ca;

	memset(dch, '\0', పరిమాణం(*dch));
	os = xstrdup(s);
	ఒకవేళ ((host = strrchr(os, '@')) == ఖాళీ)
		host = os;
	లేకపోతే {
		*host++ = '\0';
		user = os;
	}
	cleanhostname(host);
	/* Trivial case: username@ (all hosts) */
	ఒకవేళ (*host == '\0') {
		ఒకవేళ (user == ఖాళీ) {
			fatal("Invalid key destination constraint \"%s\": "
			    "does not specify user or host", s);
		}
		dch->user = xstrdup(user);
		/* other fields left blank */
		విడుదల(os);
		తిరిగి;
	}
	ఒకవేళ (hostkey_files == ఖాళీ)
		fatal_f("no hostkey files");
	/* Otherwise we need to look up the keys for this hostname */
	hostkeys = init_hostkeys();
	కొరకు (i = 0; hostkey_files[i]; i++) {
		మార్గం = tilde_expand_filename(hostkey_files[i], getuid());
		debug2_f("looking up host keys for \"%s\" in %s", host, మార్గం);
                ఎక్కించు_hostkeys(hostkeys, host, మార్గం, 0);
		విడుదల(మార్గం);
	}
	dch->user = user == ఖాళీ ? ఖాళీ : xstrdup(user);
	dch->hostname = xstrdup(host);
	కొరకు (i = 0; i < hostkeys->అంకె_entries; i++) {
		hke = hostkeys->entries + i;
		want_ca = hke->marker == MRK_CA;
		ఒకవేళ (hke->marker != MRK_NONE && !want_ca)
			కొనసాగు;
		debug3_f("%s%s%s: adding %s %skey from %s:%lu as key %u",
		    user == ఖాళీ ? "": user, user == ఖాళీ ? "" : "@",
		    host, sshkey_type(hke->కీలకం), want_ca ? "CA " : "",
		    hke->file, hke->పంక్తి, dch->nkeys);
		dch->కీలకాలు = xrecallocarray(dch->కీలకాలు, dch->nkeys,
		    dch->nkeys + 1, పరిమాణం(*dch->కీలకాలు));
		dch->కీలకం_is_ca = xrecallocarray(dch->కీలకం_is_ca, dch->nkeys,
		    dch->nkeys + 1, పరిమాణం(*dch->కీలకం_is_ca));
		ఒకవేళ ((r = sshkey_from_వ్యక్తిగత(hke->కీలకం,
		    &(dch->కీలకాలు[dch->nkeys]))) != 0)
			fatal_fr(r, "sshkey_from_private");
		dch->కీలకం_is_ca[dch->nkeys] = want_ca;
		dch->nkeys++;
	}
	ఒకవేళ (dch->nkeys == 0)
		fatal("No host keys found for destination \"%s\"", host);
	free_hostkeys(hostkeys);
	విడుదల(os);
	తిరిగి;
}

స్థిర శూన్య
parse_dest_constraint(స్థిరరాశి అక్షరం *s, నిర్మాణం dest_constraint ***dcp,
    కొలత_t *ndcp, అక్షరం **hostkey_files)
{
	నిర్మాణం dest_constraint *dc;
	అక్షరం *os, *cp;

	dc = xcalloc(1, పరిమాణం(*dc));
	os = xstrdup(s);
	ఒకవేళ ((cp = strchr(os, '>')) == ఖాళీ) {
		/* initial hop; no 'from' hop specified */
		parse_dest_constraint_hop(os, &dc->గమ్యం, hostkey_files);
	} లేకపోతే {
		/* two hops specified */
		*(cp++) = '\0';
		parse_dest_constraint_hop(os, &dc->from, hostkey_files);
		parse_dest_constraint_hop(cp, &dc->గమ్యం, hostkey_files);
		ఒకవేళ (dc->from.user != ఖాళీ) {
			fatal("Invalid key constraint %s: cannot specify "
			    "user on 'from' host", os);
		}
	}
	/* XXX eliminate or error on duplicates */
	debug2_f("constraint %zu: %s%s%s (%u keys) > %s%s%s (%u keys)", *ndcp,
	    dc->from.user ? dc->from.user : "", dc->from.user ? "@" : "",
	    dc->from.hostname ? dc->from.hostname : "(ORIGIN)", dc->from.nkeys,
	    dc->గమ్యం.user ? dc->గమ్యం.user : "", dc->గమ్యం.user ? "@" : "",
	    dc->గమ్యం.hostname ? dc->గమ్యం.hostname : "(ANY)", dc->గమ్యం.nkeys);
	*dcp = xrecallocarray(*dcp, *ndcp, *ndcp + 1, పరిమాణం(**dcp));
	(*dcp)[(*ndcp)++] = dc;
	విడుదల(os);
}


స్థిర శూన్య
usage(శూన్య)
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

పూర్ణాంకం
ప్రధాన(పూర్ణాంకం argc, అక్షరం **argv)
{
	బాహ్య అక్షరం *optarg;
	బాహ్య పూర్ణాంకం optind;
	పూర్ణాంకం agent_fd = -1;
	అక్షరం *pkcs11provider = ఖాళీ, *skprovider = ఖాళీ;
	అక్షరం **dest_constraint_అక్షరశ్రేణులు = ఖాళీ, **hostkey_files = ఖాళీ;
	పూర్ణాంకం r, i, ch, deleting = 0, ret = 0, కీలకం_only = 0, cert_only = 0;
	పూర్ణాంకం do_download = 0, xflag = 0, lflag = 0, Dflag = 0;
	పూర్ణాంకం Qflag = 0, qflag = 0, Tflag = 0, Nflag = 0, no_pin = 0;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_INFO;
	నిర్మాణం sshkey *k, **certs = ఖాళీ;
	నిర్మాణం dest_constraint **dest_constraints = ఖాళీ;
	కొలత_t n, ndest_constraints = 0, ncerts = 0;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	__progname = ssh_get_progname(argv[0]);
	విత్తనం_rng();

	log_init(__progname, log_level, log_facility, 1);

	setvbuf(stdout, ఖాళీ, _IOLBF, 0);

	skprovider = getenv("SSH_SK_PROVIDER");

	అయితే ((ch = getopt(argc, argv, "vkKlLNPCcdDTxXE:e:h:H:M:m:Qqs:S:t:")) != -1) {
		ఎంపిక (ch) {
		స్థితి 'v':
			ఒకవేళ (log_level == SYSLOG_LEVEL_INFO)
				log_level = SYSLOG_LEVEL_DEBUG1;
			లేకపోతే ఒకవేళ (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			ఆపు;
		స్థితి 'N':
			Nflag = 1;
			ఆపు;
		స్థితి 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			ఒకవేళ (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			ఆపు;
		స్థితి 'H':
			stringlist_append(&hostkey_files, optarg);
			ఆపు;
		స్థితి 'h':
			stringlist_append(&dest_constraint_అక్షరశ్రేణులు, optarg);
			ఆపు;
		స్థితి 'k':
			కీలకం_only = 1;
			ఆపు;
		స్థితి 'C':
			cert_only = 1;
			ఆపు;
		స్థితి 'K':
			do_download = 1;
			ఆపు;
		స్థితి 'l':
		స్థితి 'L':
			ఒకవేళ (lflag != 0)
				fatal("-%c flag already specified", lflag);
			lflag = ch;
			ఆపు;
		స్థితి 'x':
		స్థితి 'X':
			ఒకవేళ (xflag != 0)
				fatal("-%c flag already specified", xflag);
			xflag = ch;
			ఆపు;
		స్థితి 'c':
			confirm = 1;
			ఆపు;
		స్థితి 'm':
		స్థితి 'M':
			/* deprecated */
			ఆపు;
		స్థితి 'd':
			deleting = 1;
			ఆపు;
		స్థితి 'P':
			no_pin = 1;
			ఆపు;
		స్థితి 'D':
			Dflag = 1;
			ఆపు;
		స్థితి 's':
			pkcs11provider = optarg;
			ఆపు;
		స్థితి 'S':
			skprovider = optarg;
			ఆపు;
		స్థితి 'e':
			deleting = 1;
			pkcs11provider = optarg;
			ఆపు;
		స్థితి 't':
			ఒకవేళ ((lifetime = convtime(optarg)) == -1 ||
			    lifetime < 0 || (u_long)lifetime > UINT32_MAX) {
				fprintf(stderr, "Invalid lifetime\n");
				ret = 1;
				వెళ్ళు పూర్తి;
			}
			ఆపు;
		స్థితి 'q':
			qflag = 1;
			ఆపు;
		స్థితి 'Q':
			Qflag = 1;
			ఆపు;
		స్థితి 'T':
			Tflag = 1;
			ఆపు;
		అప్రమేయ:
			usage();
			ret = 1;
			వెళ్ళు పూర్తి;
		}
	}
	log_init(__progname, log_level, log_facility, 1);

	ఒకవేళ ((xflag != 0) + (lflag != 0) + (Dflag != 0) + (Qflag != 0) > 1)
		fatal("Invalid combination of actions");

	/* First, get a connection to the authentication agent. */
	ఎంపిక (r = ssh_get_authentication_socket(&agent_fd)) {
	స్థితి 0:
		ఆపు;
	స్థితి SSH_ERR_AGENT_NOT_PRESENT:
		fprintf(stderr, "Could not open a connection to your "
		    "authentication agent.\n");
		నిష్క్రమించు(2);
	అప్రమేయ:
		fprintf(stderr, "Error connecting to agent: %s\n", ssh_err(r));
		నిష్క్రమించు(2);
	}

	ఒకవేళ (xflag) {
		ఒకవేళ (తాళం_agent(agent_fd, xflag == 'x' ? 1 : 0) == -1)
			ret = 1;
		వెళ్ళు పూర్తి;
	} లేకపోతే ఒకవేళ (lflag) {
		ఒకవేళ (list_identities(agent_fd, lflag == 'l' ? 1 : 0) == -1)
			ret = 1;
		వెళ్ళు పూర్తి;
	} లేకపోతే ఒకవేళ (Dflag) {
		ఒకవేళ (delete_all(agent_fd, qflag) == -1)
			ret = 1;
		వెళ్ళు పూర్తి;
	} లేకపోతే ఒకవేళ (Qflag) {
		ఒకవేళ (query_exts(agent_fd) == -1)
			ret = 1;
		వెళ్ళు పూర్తి;
	}

#నిర్వచితమైతే ENABLE_SK_అంతర్గత
	ఒకవేళ (skprovider == ఖాళీ)
		skprovider = "internal";
#అయితే_ముగింపు

	ఒకవేళ (hostkey_files == ఖాళీ) {
		/* use defaults from readconf.c */
		stringlist_append(&hostkey_files, మార్గం_SSH_USER_HOSTFILE);
		stringlist_append(&hostkey_files, మార్గం_SSH_USER_HOSTFILE2);
		stringlist_append(&hostkey_files, మార్గం_SSH_SYSTEM_HOSTFILE);
		stringlist_append(&hostkey_files, మార్గం_SSH_SYSTEM_HOSTFILE2);
	}
	ఒకవేళ (dest_constraint_అక్షరశ్రేణులు != ఖాళీ) {
		కొరకు (i = 0; dest_constraint_అక్షరశ్రేణులు[i] != ఖాళీ; i++) {
			parse_dest_constraint(dest_constraint_అక్షరశ్రేణులు[i],
			  &dest_constraints, &ndest_constraints, hostkey_files);
		}
	}

	argc -= optind;
	argv += optind;
	ఒకవేళ (Tflag) {
		ఒకవేళ (argc <= 0)
			fatal("no keys to test");
		కొరకు (r = i = 0; i < argc; i++)
			r |= test_కీలకం(agent_fd, argv[i]);
		ret = r == 0 ? 0 : 1;
		వెళ్ళు పూర్తి;
	}
	ఒకవేళ (pkcs11provider != ఖాళీ) {
		కొరకు (i = 0; i < argc; i++) {
			ఒకవేళ ((r = sshkey_ఎక్కించు_ప్రజా(argv[i], &k, ఖాళీ)) != 0)
				fatal_fr(r, "load certificate %s", argv[i]);
			certs = xrecallocarray(certs, ncerts, ncerts + 1,
			    పరిమాణం(*certs));
			debug2("%s: %s", argv[i], sshkey_ssh_name(k));
			certs[ncerts++] = k;
		}
		debug2_f("loaded %zu certificates", ncerts);
		ఒకవేళ (update_card(agent_fd, !deleting, pkcs11provider,
		    qflag, no_pin, కీలకం_only, cert_only,
		    dest_constraints, ndest_constraints,
		    certs, ncerts) == -1)
			ret = 1;
		కొరకు (n = 0; n < ncerts; n++)
			sshkey_free(certs[n]);
		విడుదల(certs);
		వెళ్ళు పూర్తి;
	}
	ఒకవేళ (do_download) {
		ఒకవేళ (skprovider == ఖాళీ)
			fatal("Cannot download keys without provider");
		ఒకవేళ (ఎక్కించు_resident_కీలకాలు(agent_fd, skprovider, qflag, no_pin,
		    dest_constraints, ndest_constraints) != 0)
			ret = 1;
		వెళ్ళు పూర్తి;
	}
	ఒకవేళ (argc == 0) {
		అక్షరం buf[PATH_MAX];
		నిర్మాణం passwd *pw;
		నిర్మాణం stat st;
		పూర్ణాంకం లెక్క = 0;

		ఒకవేళ ((pw = getpwuid(getuid())) == ఖాళీ) {
			fprintf(stderr, "No user found with uid %u\n",
			    (u_int)getuid());
			ret = 1;
			వెళ్ళు పూర్తి;
		}

		కొరకు (i = 0; default_files[i]; i++) {
			snprintf(buf, పరిమాణం(buf), "%s/%s", pw->pw_dir,
			    default_files[i]);
			ఒకవేళ (stat(buf, &st) == -1)
				కొనసాగు;
			ఒకవేళ (do_file(agent_fd, deleting, కీలకం_only, cert_only,
			    buf, qflag, Nflag, skprovider,
			    dest_constraints, ndest_constraints) == -1)
				ret = 1;
			లేకపోతే
				లెక్క++;
		}
		ఒకవేళ (లెక్క == 0)
			ret = 1;
	} లేకపోతే {
		కొరకు (i = 0; i < argc; i++) {
			ఒకవేళ (do_file(agent_fd, deleting, కీలకం_only, cert_only,
			    argv[i], qflag, Nflag, skprovider,
			    dest_constraints, ndest_constraints) == -1)
				ret = 1;
		}
	}
పూర్తి:
	clear_pass();
	stringlist_free(hostkey_files);
	stringlist_free(dest_constraint_అక్షరశ్రేణులు);
	free_dest_constraints(dest_constraints, ndest_constraints);
	ssh_close_authentication_socket(agent_fd);
	తిరిగి ret;
}
