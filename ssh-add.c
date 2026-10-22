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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/stat.h>

#ifdef WITH_OPENSSL
# include <openssl/evp.h>
# include "openbsd-compat/openssl-compat.h"
#endif

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <fcntl.h>
#ଅନ୍ତର୍ଭାଵ <pwd.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>
#ଅନ୍ତର୍ଭାଵ <time.h>

#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "ssh.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "authfd.h"
#ଅନ୍ତର୍ଭାଵ "authfile.h"
#ଅନ୍ତର୍ଭାଵ "pathnames.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "digest.h"
#ଅନ୍ତର୍ଭାଵ "ssh-sk.h"
#ଅନ୍ତର୍ଭାଵ "sk-api.h"
#ଅନ୍ତର୍ଭାଵ "hostfile.h"

#define CERT_EXPIRY_GRACE	(5*60)

/* argv0 */
ବାହ୍ୟ ଅକ୍ଷର *__progname;

/* Default files to add */
ସ୍ଥିର ଅକ୍ଷର *default_files[] = {
#ifdef WITH_OPENSSL
	_PATH_SSH_CLIENT_ID_RSA,
	_PATH_SSH_CLIENT_ID_ECDSA,
	_PATH_SSH_CLIENT_ID_ECDSA_SK,
#endif /* WITH_OPENSSL */
	_PATH_SSH_CLIENT_ID_ED25519,
	_PATH_SSH_CLIENT_ID_ED25519_SK,
	_PATH_SSH_CLIENT_ID_MLDSA44_ED25519,
	ଖାଲି
};

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* Default lifetime (0 == forever) */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା lifetime = 0;

/* User has to confirm key use */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା confirm = 0;

/* we keep a cache of one passphrase */
ସ୍ଥିର ଅକ୍ଷର *pass = ଖାଲି;
ସ୍ଥିର ଶୂନ୍ୟ
clear_pass(ଶୂନ୍ୟ)
{
	ଯଦି (pass) {
		freezero(pass, strlen(pass));
		pass = ଖାଲି;
	}
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
delete_one(ପୂର୍ଣ୍ଣସଂଖ୍ୟା agent_fd, ଅଚଳ ସଂରଚନା sshkey *ଚାବି, ଅଚଳ ଅକ୍ଷର *comment,
    ଅଚଳ ଅକ୍ଷର *path, ପୂର୍ଣ୍ଣସଂଖ୍ୟା qflag)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = ssh_remove_identity(agent_fd, ଚାବି)) != 0) {
		fprintf(stderr, "Could not remove identity \"%s\": %s\n",
		    path, ssh_err(r));
		ଫେରନ୍ତୁ r;
	}
	ଯଦି (!qflag) {
		fprintf(stderr, "Identity removed: %s %s (%s)\n", path,
		    sshkey_type(ଚାବି), comment ? comment : "no comment");
	}
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
delete_stdin(ପୂର୍ଣ୍ଣସଂଖ୍ୟା agent_fd, ପୂର୍ଣ୍ଣସଂଖ୍ୟା qflag, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଚାବି_only, ପୂର୍ଣ୍ଣସଂଖ୍ୟା cert_only)
{
	ଅକ୍ଷର *ଧାଡ଼ି = ଖାଲି, *cp;
	size_t linesize = 0;
	ସଂରଚନା sshkey *ଚାବି = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା lnum = 0, r, ret = -1;

	ଯେତେବେଳେ (getline(&ଧାଡ଼ି, &linesize, stdin) != -1) {
		lnum++;
		sshkey_free(ଚାବି);
		ଚାବି = ଖାଲି;
		ଧାଡ଼ି[strcspn(ଧାଡ଼ି, "\n")] = '\0';
		cp = ଧାଡ଼ି + strspn(ଧାଡ଼ି, " \t");
		ଯଦି (*cp == '#' || *cp == '\0')
			ଜାରି;
		ଯଦି ((ଚାବି = sshkey_new(ଚାବି_UNSPEC)) == ଖାଲି)
			fatal_f("sshkey_new");
		ଯଦି ((r = sshkey_read(ଚାବି, &cp)) != 0) {
			error_r(r, "(stdin):%d: invalid key", lnum);
			ଜାରି;
		}
		ଯଦି ((!ଚାବି_only && !cert_only) ||
		    (ଚାବି_only && !sshkey_is_cert(ଚାବି)) ||
		    (cert_only && sshkey_is_cert(ଚାବି))) {
			ଯଦି (delete_one(agent_fd, ଚାବି, cp,
			    "(stdin)", qflag) == 0)
				ret = 0;
		}
	}
	sshkey_free(ଚାବି);
	ମୁକ୍ତ(ଧାଡ଼ି);
	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
delete_file(ପୂର୍ଣ୍ଣସଂଖ୍ୟା agent_fd, ଅଚଳ ଅକ୍ଷର *filename, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଚାବି_only,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା cert_only, ପୂର୍ଣ୍ଣସଂଖ୍ୟା qflag)
{
	ସଂରଚନା sshkey *ସର୍ବସାଧାରଣ, *cert = ଖାଲି;
	ଅକ୍ଷର *certpath = ଖାଲି, *comment = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, ret = -1;

	ଯଦି (strcmp(filename, "-") == 0)
		ଫେରନ୍ତୁ delete_stdin(agent_fd, qflag, ଚାବି_only, cert_only);

	ଯଦି ((r = sshkey_load_public(filename, &ସର୍ବସାଧାରଣ,  &comment)) != 0) {
		printf("Bad key file %s: %s\n", filename, ssh_err(r));
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି ((!ଚାବି_only && !cert_only) ||
	    (ଚାବି_only && !sshkey_is_cert(ସର୍ବସାଧାରଣ)) ||
	    (cert_only && sshkey_is_cert(ସର୍ବସାଧାରଣ))) {
		ଯଦି (delete_one(agent_fd, ସର୍ବସାଧାରଣ, comment, filename, qflag) == 0)
			ret = 0;
	}

	ଯଦି (ଚାବି_only)
		ଯାଅ out;

	/* Now try to delete the corresponding certificate too */
	ମୁକ୍ତ(comment);
	comment = ଖାଲି;
	xasprintf(&certpath, "%s-cert.pub", filename);
	ଯଦି ((r = sshkey_load_public(certpath, &cert, &comment)) != 0) {
		ଯଦି (r != SSH_ERR_SYSTEM_ERROR || errno != ENOENT)
			error_r(r, "Failed to load certificate \"%s\"", certpath);
		ଯାଅ out;
	}

	ଯଦି (!sshkey_equal_public(cert, ସର୍ବସାଧାରଣ))
		fatal("Certificate %s does not match private key %s",
		    certpath, filename);

	ଯଦି (delete_one(agent_fd, cert, comment, certpath, qflag) == 0)
		ret = 0;

 out:
	sshkey_free(cert);
	sshkey_free(ସର୍ବସାଧାରଣ);
	ମୁକ୍ତ(certpath);
	ମୁକ୍ତ(comment);

	ଫେରନ୍ତୁ ret;
}

/* Send a request to remove all identities. */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
delete_all(ପୂର୍ଣ୍ଣସଂଖ୍ୟା agent_fd, ପୂର୍ଣ୍ଣସଂଖ୍ୟା qflag)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = -1;

	/*
	 * Since the agent might be forwarded, old or non-OpenSSH, when asked
	 * to remove all keys, attempt to remove both protocol v.1 and v.2
	 * keys.
	 */
	ଯଦି (ssh_remove_all_identities(agent_fd, 2) == 0)
		ret = 0;
	/* ignore error-code for ssh1 */
	ssh_remove_all_identities(agent_fd, 1);

	ଯଦି (ret != 0)
		fprintf(stderr, "Failed to remove all identities.\n");
	ଅନ୍ୟଥା ଯଦି (!qflag)
		fprintf(stderr, "All identities removed.\n");

	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
query_exts(ପୂର୍ଣ୍ଣସଂଖ୍ୟା agent_fd)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ଅକ୍ଷର **exts = ଖାଲି;
	size_t i;

	ଯଦି ((r = ssh_agent_query_extensions(agent_fd, &exts)) != 0)
		fatal_r(r, "unable to query supported extensions");
	ପାଇଁ (i = 0; exts != ଖାଲି && exts[i] != ଖାଲି; i++)
		puts(exts[i]);
	stringlist_free(exts);
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
check_cert_lifetime(ଅଚଳ ସଂରଚନା sshkey *cert, ପୂର୍ଣ୍ଣସଂଖ୍ୟା cert_lifetime)
{
	time_t now;
	uint64_t n;

	ଯଦି (cert == ଖାଲି || cert->cert == ଖାଲି || !sshkey_is_cert(cert) ||
	    cert->cert->valid_before == 0xFFFFFFFFFFFFFFFFULL)
		ଫେରନ୍ତୁ cert_lifetime;
	ଯଦି ((now = time(ଖାଲି)) <= 0)
		fatal_f("system time is at/before epoch");
	ଯଦି ((uint64_t)now > (cert->cert->valid_before + CERT_EXPIRY_GRACE))
		ଫେରନ୍ତୁ -1; /* certificate already expired */
	n = (CERT_EXPIRY_GRACE + cert->cert->valid_before) - (uint64_t)now;
	n = MINIMUM(n, INT_MAX);
	ଯଦି (cert_lifetime <= 0)
		ଫେରନ୍ତୁ (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)n;
	ଫେରନ୍ତୁ MINIMUM(cert_lifetime, (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)n);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
add_file(ପୂର୍ଣ୍ଣସଂଖ୍ୟା agent_fd, ଅଚଳ ଅକ୍ଷର *filename, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଚାବି_only, ପୂର୍ଣ୍ଣସଂଖ୍ୟା cert_only,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା qflag, ପୂର୍ଣ୍ଣସଂଖ୍ୟା Nflag, ଅଚଳ ଅକ୍ଷର *skprovider,
    ସଂରଚନା dest_constraint **dest_constraints,
    size_t ndest_constraints)
{
	ସଂରଚନା sshkey *ବ୍ୟକ୍ତିଗତ = ଖାଲି, *cert = ଖାଲି;
	ଅକ୍ଷର *comment = ଖାଲି;
	ଅକ୍ଷର ସନ୍ଦେଶ[1024], *certpath = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା cert_lifetime, r, fd, ret = -1;
	ସଂରଚନା sshbuf *keyblob;

	ଯଦି (strcmp(filename, "-") == 0) {
		fd = STDIN_FILENO;
		filename = "(stdin)";
	} ଅନ୍ୟଥା ଯଦି ((fd = open(filename, O_RDONLY)) == -1) {
		perror(filename);
		ଫେରନ୍ତୁ -1;
	}

	/*
	 * Since we'll try to load a keyfile multiple times, permission errors
	 * will occur multiple times, so check perms first and bail if wrong.
	 */
	ଯଦି (fd != STDIN_FILENO) {
		ଯଦି (sshkey_perm_ok(fd, filename) != 0) {
			close(fd);
			ଫେରନ୍ତୁ -1;
		}
	}
	ଯଦି ((r = sshbuf_load_fd(fd, &keyblob)) != 0) {
		fprintf(stderr, "Error loading key \"%s\": %s\n",
		    filename, ssh_err(r));
		sshbuf_free(keyblob);
		close(fd);
		ଫେରନ୍ତୁ -1;
	}
	close(fd);

	/* At first, try empty passphrase */
	ଯଦି ((r = sshkey_parse_private_fileblob(keyblob, "", &ବ୍ୟକ୍ତିଗତ,
	    &comment)) != 0 && r != SSH_ERR_ଚାବି_WRONG_PASSPHRASE) {
		fprintf(stderr, "Error loading key \"%s\": %s\n",
		    filename, ssh_err(r));
		ଯାଅ fail_load;
	}
	/* try last */
	ଯଦି (ବ୍ୟକ୍ତିଗତ == ଖାଲି && pass != ଖାଲି) {
		ଯଦି ((r = sshkey_parse_private_fileblob(keyblob, pass, &ବ୍ୟକ୍ତିଗତ,
		    &comment)) != 0 && r != SSH_ERR_ଚାବି_WRONG_PASSPHRASE) {
			fprintf(stderr, "Error loading key \"%s\": %s\n",
			    filename, ssh_err(r));
			ଯାଅ fail_load;
		}
	}
	ଯଦି (ବ୍ୟକ୍ତିଗତ == ଖାଲି) {
		/* clear passphrase since it did not work */
		clear_pass();
		snprintf(ସନ୍ଦେଶ, ଆକାର ସନ୍ଦେଶ, "Enter passphrase for %s%s: ",
		    filename, confirm ? " (will confirm each use)" : "");
		ପାଇଁ (;;) {
			pass = read_passphrase(ସନ୍ଦେଶ, RP_ALLOW_STDIN);
			ଯଦି (strcmp(pass, "") == 0)
				ଯାଅ fail_load;
			ଯଦି ((r = sshkey_parse_private_fileblob(keyblob, pass,
			    &ବ୍ୟକ୍ତିଗତ, &comment)) == 0)
				ଭାଙ୍ଗ;
			ଅନ୍ୟଥା ଯଦି (r != SSH_ERR_ଚାବି_WRONG_PASSPHRASE) {
				fprintf(stderr,
				    "Error loading key \"%s\": %s\n",
				    filename, ssh_err(r));
 fail_load:
				clear_pass();
				sshbuf_free(keyblob);
				ଫେରନ୍ତୁ -1;
			}
			clear_pass();
			snprintf(ସନ୍ଦେଶ, ଆକାର ସନ୍ଦେଶ,
			    "Bad passphrase, try again for %s%s: ", filename,
			    confirm ? " (will confirm each use)" : "");
		}
	}
	ଯଦି (comment == ଖାଲି || *comment == '\0')
		comment = xstrdup(filename);
	sshbuf_free(keyblob);

	ଯଦି (sshkey_is_sk(ବ୍ୟକ୍ତିଗତ)) {
		ଯଦି (skprovider == ଖାଲି) {
			fprintf(stderr, "Cannot load FIDO key %s "
			    "without provider\n", filename);
			ଯାଅ out;
		}
	} ଅନ୍ୟଥା {
		/* Don't send provider constraint for other keys */
		skprovider = ଖାଲି;
	}

	ଯଦି (!cert_only) {
		ଯଦି ((r = ssh_add_identity_constrained(agent_fd, ବ୍ୟକ୍ତିଗତ,
		    comment, lifetime, confirm, skprovider,
		    dest_constraints, ndest_constraints)) == 0) {
			ret = 0;
			ଯଦି (!qflag) {
				fprintf(stderr, "Identity added: %s (%s)\n",
				    filename, comment);
				ଯଦି (lifetime != 0) {
					fprintf(stderr, "Lifetime set to %s\n",
					    fmt_timeframe((time_t)lifetime));
				}
				ଯଦି (confirm != 0) {
					fprintf(stderr, "The user must confirm "
					    "each use of the key\n");
				}
			}
		} ଅନ୍ୟଥା {
			fprintf(stderr, "Could not add identity \"%s\": %s\n",
			    filename, ssh_err(r));
		}
	}

	/* Skip trying to load the cert if requested */
	ଯଦି (ଚାବି_only)
		ଯାଅ out;

	/* Now try to add the certificate flavour too */
	xasprintf(&certpath, "%s-cert.pub", filename);
	ଯଦି ((r = sshkey_load_public(certpath, &cert, ଖାଲି)) != 0) {
		ଯଦି (r != SSH_ERR_SYSTEM_ERROR || errno != ENOENT)
			error_r(r, "Failed to load certificate \"%s\"",
			    certpath);
		ଯାଅ out;
	}

	ଯଦି (!sshkey_equal_public(cert, ବ୍ୟକ୍ତିଗତ)) {
		error("Certificate %s does not match private key %s",
		    certpath, filename);
		ଯାଅ out;
	}

	cert_lifetime = lifetime;
	ଯଦି (!Nflag &&
	    (cert_lifetime = check_cert_lifetime(cert, cert_lifetime)) == -1) {
		logit("Certificate %s has already expired; ignored", certpath);
		ଯାଅ out;
	}

	/* Graft with private bits */
	ଯଦି ((r = sshkey_to_certified(ବ୍ୟକ୍ତିଗତ)) != 0) {
		error_fr(r, "sshkey_to_certified");
		ଯାଅ out;
	}
	ଯଦି ((r = sshkey_cert_copy(cert, ବ୍ୟକ୍ତିଗତ)) != 0) {
		error_fr(r, "sshkey_cert_copy");
		ଯାଅ out;
	}
	/* send to agent */
	ଯଦି ((r = ssh_add_identity_constrained(agent_fd, ବ୍ୟକ୍ତିଗତ, comment,
	    cert_lifetime, confirm, skprovider,
	    dest_constraints, ndest_constraints)) != 0) {
		error_r(r, "Certificate %s (%s) add failed", certpath,
		    ବ୍ୟକ୍ତିଗତ->cert->ଚାବି_id);
		ଯାଅ out;
	}
	/* success */
	ଯଦି (!qflag) {
		fprintf(stderr, "Certificate added: %s (%s)\n", certpath,
		    ବ୍ୟକ୍ତିଗତ->cert->ଚାବି_id);
		ଯଦି (cert_lifetime != 0) {
			fprintf(stderr, "Lifetime set to %s\n",
			    fmt_timeframe((time_t)cert_lifetime));
		}
		ଯଦି (confirm != 0) {
			fprintf(stderr, "The user must confirm each use "
			    "of the key\n");
		}
	}

 out:
	ମୁକ୍ତ(certpath);
	ମୁକ୍ତ(comment);
	sshkey_free(cert);
	sshkey_free(ବ୍ୟକ୍ତିଗତ);

	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
update_card(ପୂର୍ଣ୍ଣସଂଖ୍ୟା agent_fd, ପୂର୍ଣ୍ଣସଂଖ୍ୟା add, ଅଚଳ ଅକ୍ଷର *id, ପୂର୍ଣ୍ଣସଂଖ୍ୟା qflag, ପୂର୍ଣ୍ଣସଂଖ୍ୟା no_pin,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଚାବି_only, ପୂର୍ଣ୍ଣସଂଖ୍ୟା cert_only,
    ସଂରଚନା dest_constraint **dest_constraints, size_t ndest_constraints,
    ସଂରଚନା sshkey **certs, size_t ncerts)
{
	ଅକ୍ଷର *pin = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, ret = -1;

	ଯଦି (ଚାବି_only)
		ncerts = 0;

	ଯଦି (add && !no_pin) {
		ଯଦି ((pin = read_passphrase("Enter passphrase for PKCS#11: ",
		    RP_ALLOW_STDIN)) == ଖାଲି)
			ଫେରନ୍ତୁ -1;
	}

	ଯଦି ((r = ssh_update_card(agent_fd, add, id, pin == ଖାଲି ? "" : pin,
	    lifetime, confirm, dest_constraints, ndest_constraints,
	    cert_only, certs, ncerts)) == 0) {
		ret = 0;
		ଯଦି (!qflag) {
			fprintf(stderr, "Card %s: %s\n",
			    add ? "added" : "removed", id);
		}
	} ଅନ୍ୟଥା {
		fprintf(stderr, "Could not %s card \"%s\": %s\n",
		    add ? "add" : "remove", id, ssh_err(r));
		ret = -1;
	}
	ମୁକ୍ତ(pin);
	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
test_ଚାବି(ପୂର୍ଣ୍ଣସଂଖ୍ୟା agent_fd, ଅଚଳ ଅକ୍ଷର *filename)
{
	ସଂରଚନା sshkey *ଚାବି = ଖାଲି;
	u_char *sig = ଖାଲି;
	ଅଚଳ ଅକ୍ଷର *alg = ଖାଲି;
	size_t slen = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, ret = -1;
	ଅକ୍ଷର data[1024];

	ଯଦି ((r = sshkey_load_public(filename, &ଚାବି, ଖାଲି)) != 0) {
		error_r(r, "Couldn't read public key %s", filename);
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି (sshkey_type_plain(ଚାବି->type) == ଚାବି_RSA)
		alg = "rsa-sha2-256";
	arc4random_buf(data, ଆକାର(data));
	ଯଦି ((r = ssh_agent_sign(agent_fd, ଚାବି, &sig, &slen, data, ଆକାର(data),
	    alg, 0)) != 0) {
		error_r(r, "Agent signature failed for %s", filename);
		ଯାଅ done;
	}
	ଯଦି ((r = sshkey_verify(ଚାବି, sig, slen, data, ଆକାର(data),
	    alg, 0, ଖାଲି)) != 0) {
		error_r(r, "Signature verification failed for %s", filename);
		ଯାଅ done;
	}
	/* success */
	ret = 0;
 done:
	ମୁକ୍ତ(sig);
	sshkey_free(ଚାବି);
	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
list_identities(ପୂର୍ଣ୍ଣସଂଖ୍ୟା agent_fd, ପୂର୍ଣ୍ଣସଂଖ୍ୟା do_fp)
{
	ଅକ୍ଷର *fp;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ସଂରଚନା ssh_identitylist *idlist;
	size_t i;

	ଯଦି ((r = ssh_fetch_identitylist(agent_fd, &idlist)) != 0) {
		ଯଦି (r != SSH_ERR_AGENT_NO_IDENTITIES)
			fprintf(stderr, "error fetching identities: %s\n",
			    ssh_err(r));
		ଅନ୍ୟଥା
			printf("The agent has no identities.\n");
		ଫେରନ୍ତୁ -1;
	}
	ପାଇଁ (i = 0; i < idlist->nkeys; i++) {
		ଯଦି (do_fp) {
			fp = sshkey_fingerprint(idlist->ଚାବିଗୁଡ଼ିକ[i],
			    fingerprint_hash, SSH_FP_DEFAULT);
			printf("%u %s %s (%s)\n", sshkey_size(idlist->ଚାବିଗୁଡ଼ିକ[i]),
			    fp == ଖାଲି ? "(null)" : fp, idlist->comments[i],
			    sshkey_type(idlist->ଚାବିଗୁଡ଼ିକ[i]));
			ମୁକ୍ତ(fp);
		} ଅନ୍ୟଥା {
			ଯଦି ((r = sshkey_write(idlist->ଚାବିଗୁଡ଼ିକ[i], stdout)) != 0) {
				fprintf(stderr, "sshkey_write: %s\n",
				    ssh_err(r));
				ଜାରି;
			}
			fprintf(stdout, " %s\n", idlist->comments[i]);
		}
	}
	ssh_free_identitylist(idlist);
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
lock_agent(ପୂର୍ଣ୍ଣସଂଖ୍ୟା agent_fd, ପୂର୍ଣ୍ଣସଂଖ୍ୟା lock)
{
	ଅକ୍ଷର prompt[100], *p1, *p2;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, passok = 1, ret = -1;

	strlcpy(prompt, "Enter lock password: ", ଆକାର(prompt));
	p1 = read_passphrase(prompt, RP_ALLOW_STDIN);
	ଯଦି (lock) {
		strlcpy(prompt, "Again: ", ଆକାର prompt);
		p2 = read_passphrase(prompt, RP_ALLOW_STDIN);
		ଯଦି (strcmp(p1, p2) != 0) {
			fprintf(stderr, "Passwords do not match.\n");
			passok = 0;
		}
		freezero(p2, strlen(p2));
	}
	ଯଦି (passok) {
		ଯଦି ((r = ssh_lock_agent(agent_fd, lock, p1)) == 0) {
			fprintf(stderr, "Agent %slocked.\n", lock ? "" : "un");
			ret = 0;
		} ଅନ୍ୟଥା {
			fprintf(stderr, "Failed to %slock agent: %s\n",
			    lock ? "" : "un", ssh_err(r));
		}
	}
	freezero(p1, strlen(p1));
	ଫେରନ୍ତୁ (ret);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
load_resident_ଚାବିଗୁଡ଼ିକ(ପୂର୍ଣ୍ଣସଂଖ୍ୟା agent_fd, ଅଚଳ ଅକ୍ଷର *skprovider, ପୂର୍ଣ୍ଣସଂଖ୍ୟା qflag, ପୂର୍ଣ୍ଣସଂଖ୍ୟା no_pin,
    ସଂରଚନା dest_constraint **dest_constraints, size_t ndest_constraints)
{
	ସଂରଚନା sshsk_resident_ଚାବି **srks;
	size_t nsrks, i;
	ସଂରଚନା sshkey *ଚାବି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, ok = 0;
	ଅକ୍ଷର *fp, *pin = ଖାଲି;

	ଯଦି (!no_pin) {
		pin = read_passphrase("Enter PIN for authenticator: ",
		    RP_ALLOW_STDIN);
	}
	ଯଦି ((r = sshsk_load_resident(skprovider, ଖାଲି, pin == ଖାଲି ? "" : pin,
	    0, &srks, &nsrks)) != 0) {
		error_r(r, "Unable to load resident keys");
		ମୁକ୍ତ(pin);
		ଫେରନ୍ତୁ r;
	}
	ମୁକ୍ତ(pin);
	ପାଇଁ (i = 0; i < nsrks; i++) {
		ଚାବି = srks[i]->ଚାବି;
		ଯଦି ((fp = sshkey_fingerprint(ଚାବି,
		    fingerprint_hash, SSH_FP_DEFAULT)) == ଖାଲି)
			fatal_f("sshkey_fingerprint failed");
		ଯଦି ((r = ssh_add_identity_constrained(agent_fd, ଚାବି,
		    ଚାବି->sk_application, lifetime, confirm, skprovider,
		    dest_constraints, ndest_constraints)) != 0) {
			error("Unable to add key %s %s",
			    sshkey_type(ଚାବି), fp);
			ମୁକ୍ତ(fp);
			ok = r;
			ଜାରି;
		}
		ଯଦି (ok == 0)
			ok = 1;
		ଯଦି (!qflag) {
			fprintf(stderr, "Resident identity added: %s %s\n",
			    sshkey_type(ଚାବି), fp);
			ଯଦି (lifetime != 0) {
				fprintf(stderr,
				    "Lifetime set to %d seconds\n", lifetime);
			}
			ଯଦି (confirm != 0) {
				fprintf(stderr, "The user must confirm "
				    "each use of the key\n");
			}
		}
		ମୁକ୍ତ(fp);
	}
	sshsk_free_resident_ଚାବିଗୁଡ଼ିକ(srks, nsrks);
	ଯଦି (nsrks == 0)
		ଫେରନ୍ତୁ SSH_ERR_ଚାବି_NOT_FOUND;
	ଫେରନ୍ତୁ ok == 1 ? 0 : ok;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
do_file(ପୂର୍ଣ୍ଣସଂଖ୍ୟା agent_fd, ପୂର୍ଣ୍ଣସଂଖ୍ୟା deleting, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଚାବି_only, ପୂର୍ଣ୍ଣସଂଖ୍ୟା cert_only,
    ଅକ୍ଷର *file, ପୂର୍ଣ୍ଣସଂଖ୍ୟା qflag, ପୂର୍ଣ୍ଣସଂଖ୍ୟା Nflag, ଅଚଳ ଅକ୍ଷର *skprovider,
    ସଂରଚନା dest_constraint **dest_constraints, size_t ndest_constraints)
{
	ଯଦି (deleting) {
		ଯଦି (delete_file(agent_fd, file, ଚାବି_only,
		    cert_only, qflag) == -1)
			ଫେରନ୍ତୁ -1;
	} ଅନ୍ୟଥା {
		ଯଦି (add_file(agent_fd, file, ଚାବି_only, cert_only, qflag, Nflag,
		    skprovider, dest_constraints, ndest_constraints) == -1)
			ଫେରନ୍ତୁ -1;
	}
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ଶୂନ୍ୟ
free_dest_constraint_hop(ସଂରଚନା dest_constraint_hop *dch)
{
	u_int i;

	ଯଦି (dch == ଖାଲି)
		ଫେରନ୍ତୁ;
	ମୁକ୍ତ(dch->user);
	ମୁକ୍ତ(dch->hostname);
	ପାଇଁ (i = 0; i < dch->nkeys; i++)
		sshkey_free(dch->ଚାବିଗୁଡ଼ିକ[i]);
	ମୁକ୍ତ(dch->ଚାବିଗୁଡ଼ିକ);
	ମୁକ୍ତ(dch->ଚାବି_is_ca);
}

ସ୍ଥିର ଶୂନ୍ୟ
free_dest_constraints(ସଂରଚନା dest_constraint **dcs, size_t ndcs)
{
	size_t i;

	ପାଇଁ (i = 0; i < ndcs; i++) {
		free_dest_constraint_hop(&dcs[i]->from);
		free_dest_constraint_hop(&dcs[i]->to);
		ମୁକ୍ତ(dcs[i]);
	}
	ମୁକ୍ତ(dcs);
}


ସ୍ଥିର ଶୂନ୍ୟ
parse_dest_constraint_hop(ଅଚଳ ଅକ୍ଷର *s, ସଂରଚନା dest_constraint_hop *dch,
    ଅକ୍ଷର **hostkey_files)
{
	ଅକ୍ଷର *user = ଖାଲି, *host, *os, *path;
	size_t i;
	ସଂରଚନା hostkeys *hostkeys;
	ଅଚଳ ସଂରଚନା hostkey_entry *hke;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, want_ca;

	memset(dch, '\0', ଆକାର(*dch));
	os = xstrdup(s);
	ଯଦି ((host = strrchr(os, '@')) == ଖାଲି)
		host = os;
	ଅନ୍ୟଥା {
		*host++ = '\0';
		user = os;
	}
	cleanhostname(host);
	/* Trivial case: username@ (all hosts) */
	ଯଦି (*host == '\0') {
		ଯଦି (user == ଖାଲି) {
			fatal("Invalid key destination constraint \"%s\": "
			    "does not specify user or host", s);
		}
		dch->user = xstrdup(user);
		/* other fields left blank */
		ମୁକ୍ତ(os);
		ଫେରନ୍ତୁ;
	}
	ଯଦି (hostkey_files == ଖାଲି)
		fatal_f("no hostkey files");
	/* Otherwise we need to look up the keys for this hostname */
	hostkeys = init_hostkeys();
	ପାଇଁ (i = 0; hostkey_files[i]; i++) {
		path = tilde_expand_filename(hostkey_files[i], getuid());
		debug2_f("looking up host keys for \"%s\" in %s", host, path);
                load_hostkeys(hostkeys, host, path, 0);
		ମୁକ୍ତ(path);
	}
	dch->user = user == ଖାଲି ? ଖାଲି : xstrdup(user);
	dch->hostname = xstrdup(host);
	ପାଇଁ (i = 0; i < hostkeys->ଅଙ୍କ_entries; i++) {
		hke = hostkeys->entries + i;
		want_ca = hke->marker == MRK_CA;
		ଯଦି (hke->marker != MRK_NONE && !want_ca)
			ଜାରି;
		debug3_f("%s%s%s: adding %s %skey from %s:%lu as key %u",
		    user == ଖାଲି ? "": user, user == ଖାଲି ? "" : "@",
		    host, sshkey_type(hke->ଚାବି), want_ca ? "CA " : "",
		    hke->file, hke->ଧାଡ଼ି, dch->nkeys);
		dch->ଚାବିଗୁଡ଼ିକ = xrecallocarray(dch->ଚାବିଗୁଡ଼ିକ, dch->nkeys,
		    dch->nkeys + 1, ଆକାର(*dch->ଚାବିଗୁଡ଼ିକ));
		dch->ଚାବି_is_ca = xrecallocarray(dch->ଚାବି_is_ca, dch->nkeys,
		    dch->nkeys + 1, ଆକାର(*dch->ଚାବି_is_ca));
		ଯଦି ((r = sshkey_from_private(hke->ଚାବି,
		    &(dch->ଚାବିଗୁଡ଼ିକ[dch->nkeys]))) != 0)
			fatal_fr(r, "sshkey_from_private");
		dch->ଚାବି_is_ca[dch->nkeys] = want_ca;
		dch->nkeys++;
	}
	ଯଦି (dch->nkeys == 0)
		fatal("No host keys found for destination \"%s\"", host);
	free_hostkeys(hostkeys);
	ମୁକ୍ତ(os);
	ଫେରନ୍ତୁ;
}

ସ୍ଥିର ଶୂନ୍ୟ
parse_dest_constraint(ଅଚଳ ଅକ୍ଷର *s, ସଂରଚନା dest_constraint ***dcp,
    size_t *ndcp, ଅକ୍ଷର **hostkey_files)
{
	ସଂରଚନା dest_constraint *dc;
	ଅକ୍ଷର *os, *cp;

	dc = xcalloc(1, ଆକାର(*dc));
	os = xstrdup(s);
	ଯଦି ((cp = strchr(os, '>')) == ଖାଲି) {
		/* initial hop; no 'from' hop specified */
		parse_dest_constraint_hop(os, &dc->to, hostkey_files);
	} ଅନ୍ୟଥା {
		/* two hops specified */
		*(cp++) = '\0';
		parse_dest_constraint_hop(os, &dc->from, hostkey_files);
		parse_dest_constraint_hop(cp, &dc->to, hostkey_files);
		ଯଦି (dc->from.user != ଖାଲି) {
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
	*dcp = xrecallocarray(*dcp, *ndcp, *ndcp + 1, ଆକାର(**dcp));
	(*dcp)[(*ndcp)++] = dc;
	ମୁକ୍ତ(os);
}


ସ୍ଥିର ଶୂନ୍ୟ
usage(ଶୂନ୍ୟ)
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

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ମୁଖ୍ୟ(ପୂର୍ଣ୍ଣସଂଖ୍ୟା argc, ଅକ୍ଷର **argv)
{
	ବାହ୍ୟ ଅକ୍ଷର *optarg;
	ବାହ୍ୟ ପୂର୍ଣ୍ଣସଂଖ୍ୟା optind;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା agent_fd = -1;
	ଅକ୍ଷର *pkcs11provider = ଖାଲି, *skprovider = ଖାଲି;
	ଅକ୍ଷର **dest_constraint_strings = ଖାଲି, **hostkey_files = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, i, ch, deleting = 0, ret = 0, ଚାବି_only = 0, cert_only = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା do_download = 0, xflag = 0, lflag = 0, Dflag = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା Qflag = 0, qflag = 0, Tflag = 0, Nflag = 0, no_pin = 0;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_INFO;
	ସଂରଚନା sshkey *k, **certs = ଖାଲି;
	ସଂରଚନା dest_constraint **dest_constraints = ଖାଲି;
	size_t n, ndest_constraints = 0, ncerts = 0;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	__progname = ssh_get_progname(argv[0]);
	seed_rng();

	log_init(__progname, log_level, log_facility, 1);

	setvbuf(stdout, ଖାଲି, _IOLBF, 0);

	skprovider = getenv("SSH_SK_PROVIDER");

	ଯେତେବେଳେ ((ch = getopt(argc, argv, "vkKlLNPCcdDTxXE:e:h:H:M:m:Qqs:S:t:")) != -1) {
		ବାଛ (ch) {
		ସ୍ଥିତି 'v':
			ଯଦି (log_level == SYSLOG_LEVEL_INFO)
				log_level = SYSLOG_LEVEL_DEBUG1;
			ଅନ୍ୟଥା ଯଦି (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'N':
			Nflag = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			ଯଦି (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'H':
			stringlist_append(&hostkey_files, optarg);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'h':
			stringlist_append(&dest_constraint_strings, optarg);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'k':
			ଚାବି_only = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'C':
			cert_only = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'K':
			do_download = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'l':
		ସ୍ଥିତି 'L':
			ଯଦି (lflag != 0)
				fatal("-%c flag already specified", lflag);
			lflag = ch;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'x':
		ସ୍ଥିତି 'X':
			ଯଦି (xflag != 0)
				fatal("-%c flag already specified", xflag);
			xflag = ch;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'c':
			confirm = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'm':
		ସ୍ଥିତି 'M':
			/* deprecated */
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'd':
			deleting = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'P':
			no_pin = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'D':
			Dflag = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 's':
			pkcs11provider = optarg;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'S':
			skprovider = optarg;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'e':
			deleting = 1;
			pkcs11provider = optarg;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 't':
			ଯଦି ((lifetime = convtime(optarg)) == -1 ||
			    lifetime < 0 || (u_long)lifetime > UINT32_MAX) {
				fprintf(stderr, "Invalid lifetime\n");
				ret = 1;
				ଯାଅ done;
			}
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'q':
			qflag = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'Q':
			Qflag = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'T':
			Tflag = 1;
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			usage();
			ret = 1;
			ଯାଅ done;
		}
	}
	log_init(__progname, log_level, log_facility, 1);

	ଯଦି ((xflag != 0) + (lflag != 0) + (Dflag != 0) + (Qflag != 0) > 1)
		fatal("Invalid combination of actions");

	/* First, get a connection to the authentication agent. */
	ବାଛ (r = ssh_get_authentication_socket(&agent_fd)) {
	ସ୍ଥିତି 0:
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SSH_ERR_AGENT_NOT_PRESENT:
		fprintf(stderr, "Could not open a connection to your "
		    "authentication agent.\n");
		exit(2);
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		fprintf(stderr, "Error connecting to agent: %s\n", ssh_err(r));
		exit(2);
	}

	ଯଦି (xflag) {
		ଯଦି (lock_agent(agent_fd, xflag == 'x' ? 1 : 0) == -1)
			ret = 1;
		ଯାଅ done;
	} ଅନ୍ୟଥା ଯଦି (lflag) {
		ଯଦି (list_identities(agent_fd, lflag == 'l' ? 1 : 0) == -1)
			ret = 1;
		ଯାଅ done;
	} ଅନ୍ୟଥା ଯଦି (Dflag) {
		ଯଦି (delete_all(agent_fd, qflag) == -1)
			ret = 1;
		ଯାଅ done;
	} ଅନ୍ୟଥା ଯଦି (Qflag) {
		ଯଦି (query_exts(agent_fd) == -1)
			ret = 1;
		ଯାଅ done;
	}

#ifdef ENABLE_SK_INTERNAL
	ଯଦି (skprovider == ଖାଲି)
		skprovider = "internal";
#endif

	ଯଦି (hostkey_files == ଖାଲି) {
		/* use defaults from readconf.c */
		stringlist_append(&hostkey_files, _PATH_SSH_USER_HOSTFILE);
		stringlist_append(&hostkey_files, _PATH_SSH_USER_HOSTFILE2);
		stringlist_append(&hostkey_files, _PATH_SSH_SYSTEM_HOSTFILE);
		stringlist_append(&hostkey_files, _PATH_SSH_SYSTEM_HOSTFILE2);
	}
	ଯଦି (dest_constraint_strings != ଖାଲି) {
		ପାଇଁ (i = 0; dest_constraint_strings[i] != ଖାଲି; i++) {
			parse_dest_constraint(dest_constraint_strings[i],
			  &dest_constraints, &ndest_constraints, hostkey_files);
		}
	}

	argc -= optind;
	argv += optind;
	ଯଦି (Tflag) {
		ଯଦି (argc <= 0)
			fatal("no keys to test");
		ପାଇଁ (r = i = 0; i < argc; i++)
			r |= test_ଚାବି(agent_fd, argv[i]);
		ret = r == 0 ? 0 : 1;
		ଯାଅ done;
	}
	ଯଦି (pkcs11provider != ଖାଲି) {
		ପାଇଁ (i = 0; i < argc; i++) {
			ଯଦି ((r = sshkey_load_public(argv[i], &k, ଖାଲି)) != 0)
				fatal_fr(r, "load certificate %s", argv[i]);
			certs = xrecallocarray(certs, ncerts, ncerts + 1,
			    ଆକାର(*certs));
			debug2("%s: %s", argv[i], sshkey_ssh_name(k));
			certs[ncerts++] = k;
		}
		debug2_f("loaded %zu certificates", ncerts);
		ଯଦି (update_card(agent_fd, !deleting, pkcs11provider,
		    qflag, no_pin, ଚାବି_only, cert_only,
		    dest_constraints, ndest_constraints,
		    certs, ncerts) == -1)
			ret = 1;
		ପାଇଁ (n = 0; n < ncerts; n++)
			sshkey_free(certs[n]);
		ମୁକ୍ତ(certs);
		ଯାଅ done;
	}
	ଯଦି (do_download) {
		ଯଦି (skprovider == ଖାଲି)
			fatal("Cannot download keys without provider");
		ଯଦି (load_resident_ଚାବିଗୁଡ଼ିକ(agent_fd, skprovider, qflag, no_pin,
		    dest_constraints, ndest_constraints) != 0)
			ret = 1;
		ଯାଅ done;
	}
	ଯଦି (argc == 0) {
		ଅକ୍ଷର buf[PATH_MAX];
		ସଂରଚନା passwd *pw;
		ସଂରଚନା stat st;
		ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଗଣନା_2 = 0;

		ଯଦି ((pw = getpwuid(getuid())) == ଖାଲି) {
			fprintf(stderr, "No user found with uid %u\n",
			    (u_int)getuid());
			ret = 1;
			ଯାଅ done;
		}

		ପାଇଁ (i = 0; default_files[i]; i++) {
			snprintf(buf, ଆକାର(buf), "%s/%s", pw->pw_dir,
			    default_files[i]);
			ଯଦି (stat(buf, &st) == -1)
				ଜାରି;
			ଯଦି (do_file(agent_fd, deleting, ଚାବି_only, cert_only,
			    buf, qflag, Nflag, skprovider,
			    dest_constraints, ndest_constraints) == -1)
				ret = 1;
			ଅନ୍ୟଥା
				ଗଣନା_2++;
		}
		ଯଦି (ଗଣନା_2 == 0)
			ret = 1;
	} ଅନ୍ୟଥା {
		ପାଇଁ (i = 0; i < argc; i++) {
			ଯଦି (do_file(agent_fd, deleting, ଚାବି_only, cert_only,
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
	ଫେରନ୍ତୁ ret;
}
