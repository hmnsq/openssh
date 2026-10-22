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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/stat.h>

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
# include <openssl/evp.h>
# include "openbsd-compat/openssl-compat.h"
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <pwd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <time.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "authfd.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "authfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "pathnames.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "digest.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh-sk.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sk-api.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "hostfile.h"

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CERT_EXPIRY_GRACE	(5*60)

/* argv0 */
ਬਾਹਰੀ ਅੱਖਰ *__progname;

/* Default files to add */
ਸਥਿਰ ਅੱਖਰ *default_files[] = {
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	ਰਸਤਾ_SSH_CLIENT_ID_RSA,
	ਰਸਤਾ_SSH_CLIENT_ID_ECDSA,
	ਰਸਤਾ_SSH_CLIENT_ID_ECDSA_SK,
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
	ਰਸਤਾ_SSH_CLIENT_ID_ED25519,
	ਰਸਤਾ_SSH_CLIENT_ID_ED25519_SK,
	ਰਸਤਾ_SSH_CLIENT_ID_MLDSA44_ED25519,
	ਨਿਰਾ
};

ਸਥਿਰ ਪੂਰਨ fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* Default lifetime (0 == forever) */
ਸਥਿਰ ਪੂਰਨ lifetime = 0;

/* User has to confirm key use */
ਸਥਿਰ ਪੂਰਨ confirm = 0;

/* we keep a cache of one passphrase */
ਸਥਿਰ ਅੱਖਰ *pass = ਨਿਰਾ;
ਸਥਿਰ ਖਾਲੀ
clear_pass(ਖਾਲੀ)
{
	ਜੇ (pass) {
		freezero(pass, ਲੜੀ_ਲੰਬਾਈ(pass));
		pass = ਨਿਰਾ;
	}
}

ਸਥਿਰ ਪੂਰਨ
delete_one(ਪੂਰਨ agent_fd, ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਅਚਲ ਅੱਖਰ *comment,
    ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, ਪੂਰਨ qflag)
{
	ਪੂਰਨ r;

	ਜੇ ((r = ssh_remove_ਪਛਾਣ_ਤੱਤ(agent_fd, ਕੁੰਜੀ)) != 0) {
		fprintf(stderr, "Could not remove identity \"%s\": %s\n",
		    ਰਸਤਾ, ssh_err(r));
		ਵਾਪਸ r;
	}
	ਜੇ (!qflag) {
		fprintf(stderr, "Identity removed: %s %s (%s)\n", ਰਸਤਾ,
		    sshkey_type(ਕੁੰਜੀ), comment ? comment : "no comment");
	}
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
delete_stdin(ਪੂਰਨ agent_fd, ਪੂਰਨ qflag, ਪੂਰਨ ਕੁੰਜੀ_only, ਪੂਰਨ cert_only)
{
	ਅੱਖਰ *ਸਤਰ = ਨਿਰਾ, *cp;
	ਮਾਪ_t linesize = 0;
	ਬਣਤਰ sshkey *ਕੁੰਜੀ = ਨਿਰਾ;
	ਪੂਰਨ lnum = 0, r, ret = -1;

	ਜਦੋਂ (getline(&ਸਤਰ, &linesize, stdin) != -1) {
		lnum++;
		sshkey_free(ਕੁੰਜੀ);
		ਕੁੰਜੀ = ਨਿਰਾ;
		ਸਤਰ[strcspn(ਸਤਰ, "\n")] = '\0';
		cp = ਸਤਰ + strspn(ਸਤਰ, " \t");
		ਜੇ (*cp == '#' || *cp == '\0')
			ਜਾਰੀ;
		ਜੇ ((ਕੁੰਜੀ = sshkey_new(ਕੁੰਜੀ_UNSPEC)) == ਨਿਰਾ)
			fatal_f("sshkey_new");
		ਜੇ ((r = sshkey_read(ਕੁੰਜੀ, &cp)) != 0) {
			error_r(r, "(stdin):%d: invalid key", lnum);
			ਜਾਰੀ;
		}
		ਜੇ ((!ਕੁੰਜੀ_only && !cert_only) ||
		    (ਕੁੰਜੀ_only && !sshkey_is_cert(ਕੁੰਜੀ)) ||
		    (cert_only && sshkey_is_cert(ਕੁੰਜੀ))) {
			ਜੇ (delete_one(agent_fd, ਕੁੰਜੀ, cp,
			    "(stdin)", qflag) == 0)
				ret = 0;
		}
	}
	sshkey_free(ਕੁੰਜੀ);
	ਮੁਕਤ(ਸਤਰ);
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਪੂਰਨ
delete_file(ਪੂਰਨ agent_fd, ਅਚਲ ਅੱਖਰ *filename, ਪੂਰਨ ਕੁੰਜੀ_only,
    ਪੂਰਨ cert_only, ਪੂਰਨ qflag)
{
	ਬਣਤਰ sshkey *ਜਨਤਕ, *cert = ਨਿਰਾ;
	ਅੱਖਰ *certpath = ਨਿਰਾ, *comment = ਨਿਰਾ;
	ਪੂਰਨ r, ret = -1;

	ਜੇ (strcmp(filename, "-") == 0)
		ਵਾਪਸ delete_stdin(agent_fd, qflag, ਕੁੰਜੀ_only, cert_only);

	ਜੇ ((r = sshkey_ਲੱਦੋ_ਜਨਤਕ(filename, &ਜਨਤਕ,  &comment)) != 0) {
		ਲਿਖੋ("Bad key file %s: %s\n", filename, ssh_err(r));
		ਵਾਪਸ -1;
	}
	ਜੇ ((!ਕੁੰਜੀ_only && !cert_only) ||
	    (ਕੁੰਜੀ_only && !sshkey_is_cert(ਜਨਤਕ)) ||
	    (cert_only && sshkey_is_cert(ਜਨਤਕ))) {
		ਜੇ (delete_one(agent_fd, ਜਨਤਕ, comment, filename, qflag) == 0)
			ret = 0;
	}

	ਜੇ (ਕੁੰਜੀ_only)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* Now try to delete the corresponding certificate too */
	ਮੁਕਤ(comment);
	comment = ਨਿਰਾ;
	xasprintf(&certpath, "%s-cert.pub", filename);
	ਜੇ ((r = sshkey_ਲੱਦੋ_ਜਨਤਕ(certpath, &cert, &comment)) != 0) {
		ਜੇ (r != SSH_ERR_SYSTEM_ERROR || errno != ENOENT)
			error_r(r, "Failed to load certificate \"%s\"", certpath);
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ (!sshkey_equal_ਜਨਤਕ(cert, ਜਨਤਕ))
		fatal("Certificate %s does not match private key %s",
		    certpath, filename);

	ਜੇ (delete_one(agent_fd, cert, comment, certpath, qflag) == 0)
		ret = 0;

 ਬਾਹਰਲਾ:
	sshkey_free(cert);
	sshkey_free(ਜਨਤਕ);
	ਮੁਕਤ(certpath);
	ਮੁਕਤ(comment);

	ਵਾਪਸ ret;
}

/* Send a request to remove all identities. */
ਸਥਿਰ ਪੂਰਨ
delete_all(ਪੂਰਨ agent_fd, ਪੂਰਨ qflag)
{
	ਪੂਰਨ ret = -1;

	/*
	 * Since the agent might be forwarded, old or non-OpenSSH, when asked
	 * to remove all keys, attempt to remove both protocol v.1 and v.2
	 * keys.
	 */
	ਜੇ (ssh_remove_all_identities(agent_fd, 2) == 0)
		ret = 0;
	/* ignore error-code for ssh1 */
	ssh_remove_all_identities(agent_fd, 1);

	ਜੇ (ret != 0)
		fprintf(stderr, "Failed to remove all identities.\n");
	ਨਹੀਂਤਾਂ ਜੇ (!qflag)
		fprintf(stderr, "All identities removed.\n");

	ਵਾਪਸ ret;
}

ਸਥਿਰ ਪੂਰਨ
query_exts(ਪੂਰਨ agent_fd)
{
	ਪੂਰਨ r;
	ਅੱਖਰ **exts = ਨਿਰਾ;
	ਮਾਪ_t i;

	ਜੇ ((r = ssh_agent_query_extensions(agent_fd, &exts)) != 0)
		fatal_r(r, "unable to query supported extensions");
	ਲਈ (i = 0; exts != ਨਿਰਾ && exts[i] != ਨਿਰਾ; i++)
		puts(exts[i]);
	stringlist_free(exts);
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
check_cert_lifetime(ਅਚਲ ਬਣਤਰ sshkey *cert, ਪੂਰਨ cert_lifetime)
{
	time_t now;
	uint64_t n;

	ਜੇ (cert == ਨਿਰਾ || cert->cert == ਨਿਰਾ || !sshkey_is_cert(cert) ||
	    cert->cert->valid_before == 0xFFFFFFFFFFFFFFFFULL)
		ਵਾਪਸ cert_lifetime;
	ਜੇ ((now = time(ਨਿਰਾ)) <= 0)
		fatal_f("system time is at/before epoch");
	ਜੇ ((uint64_t)now > (cert->cert->valid_before + CERT_EXPIRY_GRACE))
		ਵਾਪਸ -1; /* certificate already expired */
	n = (CERT_EXPIRY_GRACE + cert->cert->valid_before) - (uint64_t)now;
	n = MINIMUM(n, ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ);
	ਜੇ (cert_lifetime <= 0)
		ਵਾਪਸ (ਪੂਰਨ)n;
	ਵਾਪਸ MINIMUM(cert_lifetime, (ਪੂਰਨ)n);
}

ਸਥਿਰ ਪੂਰਨ
ਜੋੜੋ_file(ਪੂਰਨ agent_fd, ਅਚਲ ਅੱਖਰ *filename, ਪੂਰਨ ਕੁੰਜੀ_only, ਪੂਰਨ cert_only,
    ਪੂਰਨ qflag, ਪੂਰਨ Nflag, ਅਚਲ ਅੱਖਰ *skprovider,
    ਬਣਤਰ dest_constraint **dest_constraints,
    ਮਾਪ_t ndest_constraints)
{
	ਬਣਤਰ sshkey *ਨਿਜੀ = ਨਿਰਾ, *cert = ਨਿਰਾ;
	ਅੱਖਰ *comment = ਨਿਰਾ;
	ਅੱਖਰ ਸੁਨੇਹਾ[1024], *certpath = ਨਿਰਾ;
	ਪੂਰਨ cert_lifetime, r, fd, ret = -1;
	ਬਣਤਰ sshbuf *keyblob;

	ਜੇ (strcmp(filename, "-") == 0) {
		fd = STDIN_FILENO;
		filename = "(stdin)";
	} ਨਹੀਂਤਾਂ ਜੇ ((fd = open(filename, O_RDONLY)) == -1) {
		perror(filename);
		ਵਾਪਸ -1;
	}

	/*
	 * Since we'll try to load a keyfile multiple times, permission errors
	 * will occur multiple times, so check perms first and bail if wrong.
	 */
	ਜੇ (fd != STDIN_FILENO) {
		ਜੇ (sshkey_perm_ok(fd, filename) != 0) {
			close(fd);
			ਵਾਪਸ -1;
		}
	}
	ਜੇ ((r = sshbuf_ਲੱਦੋ_fd(fd, &keyblob)) != 0) {
		fprintf(stderr, "Error loading key \"%s\": %s\n",
		    filename, ssh_err(r));
		sshbuf_free(keyblob);
		close(fd);
		ਵਾਪਸ -1;
	}
	close(fd);

	/* At first, try empty passphrase */
	ਜੇ ((r = sshkey_parse_ਨਿੱਜੀ_fileblob(keyblob, "", &ਨਿਜੀ,
	    &comment)) != 0 && r != SSH_ERR_ਕੁੰਜੀ_WRONG_PASSPHRASE) {
		fprintf(stderr, "Error loading key \"%s\": %s\n",
		    filename, ssh_err(r));
		ਜਾਓ fail_ਲੱਦੋ;
	}
	/* try last */
	ਜੇ (ਨਿਜੀ == ਨਿਰਾ && pass != ਨਿਰਾ) {
		ਜੇ ((r = sshkey_parse_ਨਿੱਜੀ_fileblob(keyblob, pass, &ਨਿਜੀ,
		    &comment)) != 0 && r != SSH_ERR_ਕੁੰਜੀ_WRONG_PASSPHRASE) {
			fprintf(stderr, "Error loading key \"%s\": %s\n",
			    filename, ssh_err(r));
			ਜਾਓ fail_ਲੱਦੋ;
		}
	}
	ਜੇ (ਨਿਜੀ == ਨਿਰਾ) {
		/* clear passphrase since it did not work */
		clear_pass();
		snprintf(ਸੁਨੇਹਾ, ਆਕਾਰ ਸੁਨੇਹਾ, "Enter passphrase for %s%s: ",
		    filename, confirm ? " (will confirm each use)" : "");
		ਲਈ (;;) {
			pass = read_passphrase(ਸੁਨੇਹਾ, RP_ALLOW_STDIN);
			ਜੇ (strcmp(pass, "") == 0)
				ਜਾਓ fail_ਲੱਦੋ;
			ਜੇ ((r = sshkey_parse_ਨਿੱਜੀ_fileblob(keyblob, pass,
			    &ਨਿਜੀ, &comment)) == 0)
				ਰੋਕੋ;
			ਨਹੀਂਤਾਂ ਜੇ (r != SSH_ERR_ਕੁੰਜੀ_WRONG_PASSPHRASE) {
				fprintf(stderr,
				    "Error loading key \"%s\": %s\n",
				    filename, ssh_err(r));
 fail_ਲੱਦੋ:
				clear_pass();
				sshbuf_free(keyblob);
				ਵਾਪਸ -1;
			}
			clear_pass();
			snprintf(ਸੁਨੇਹਾ, ਆਕਾਰ ਸੁਨੇਹਾ,
			    "Bad passphrase, try again for %s%s: ", filename,
			    confirm ? " (will confirm each use)" : "");
		}
	}
	ਜੇ (comment == ਨਿਰਾ || *comment == '\0')
		comment = xstrdup(filename);
	sshbuf_free(keyblob);

	ਜੇ (sshkey_is_sk(ਨਿਜੀ)) {
		ਜੇ (skprovider == ਨਿਰਾ) {
			fprintf(stderr, "Cannot load FIDO key %s "
			    "without provider\n", filename);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	} ਨਹੀਂਤਾਂ {
		/* Don't send provider constraint for other keys */
		skprovider = ਨਿਰਾ;
	}

	ਜੇ (!cert_only) {
		ਜੇ ((r = ssh_ਜੋੜੋ_ਪਛਾਣ_ਤੱਤ_constrained(agent_fd, ਨਿਜੀ,
		    comment, lifetime, confirm, skprovider,
		    dest_constraints, ndest_constraints)) == 0) {
			ret = 0;
			ਜੇ (!qflag) {
				fprintf(stderr, "Identity added: %s (%s)\n",
				    filename, comment);
				ਜੇ (lifetime != 0) {
					fprintf(stderr, "Lifetime set to %s\n",
					    fmt_timeframe((time_t)lifetime));
				}
				ਜੇ (confirm != 0) {
					fprintf(stderr, "The user must confirm "
					    "each use of the key\n");
				}
			}
		} ਨਹੀਂਤਾਂ {
			fprintf(stderr, "Could not add identity \"%s\": %s\n",
			    filename, ssh_err(r));
		}
	}

	/* Skip trying to load the cert if requested */
	ਜੇ (ਕੁੰਜੀ_only)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* Now try to add the certificate flavour too */
	xasprintf(&certpath, "%s-cert.pub", filename);
	ਜੇ ((r = sshkey_ਲੱਦੋ_ਜਨਤਕ(certpath, &cert, ਨਿਰਾ)) != 0) {
		ਜੇ (r != SSH_ERR_SYSTEM_ERROR || errno != ENOENT)
			error_r(r, "Failed to load certificate \"%s\"",
			    certpath);
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ (!sshkey_equal_ਜਨਤਕ(cert, ਨਿਜੀ)) {
		error("Certificate %s does not match private key %s",
		    certpath, filename);
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	cert_lifetime = lifetime;
	ਜੇ (!Nflag &&
	    (cert_lifetime = check_cert_lifetime(cert, cert_lifetime)) == -1) {
		logit("Certificate %s has already expired; ignored", certpath);
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* Graft with private bits */
	ਜੇ ((r = sshkey_ਮੰਜ਼ਿਲ_certified(ਨਿਜੀ)) != 0) {
		error_fr(r, "sshkey_to_certified");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshkey_cert_copy(cert, ਨਿਜੀ)) != 0) {
		error_fr(r, "sshkey_cert_copy");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* send to agent */
	ਜੇ ((r = ssh_ਜੋੜੋ_ਪਛਾਣ_ਤੱਤ_constrained(agent_fd, ਨਿਜੀ, comment,
	    cert_lifetime, confirm, skprovider,
	    dest_constraints, ndest_constraints)) != 0) {
		error_r(r, "Certificate %s (%s) add failed", certpath,
		    ਨਿਜੀ->cert->ਕੁੰਜੀ_id);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* success */
	ਜੇ (!qflag) {
		fprintf(stderr, "Certificate added: %s (%s)\n", certpath,
		    ਨਿਜੀ->cert->ਕੁੰਜੀ_id);
		ਜੇ (cert_lifetime != 0) {
			fprintf(stderr, "Lifetime set to %s\n",
			    fmt_timeframe((time_t)cert_lifetime));
		}
		ਜੇ (confirm != 0) {
			fprintf(stderr, "The user must confirm each use "
			    "of the key\n");
		}
	}

 ਬਾਹਰਲਾ:
	ਮੁਕਤ(certpath);
	ਮੁਕਤ(comment);
	sshkey_free(cert);
	sshkey_free(ਨਿਜੀ);

	ਵਾਪਸ ret;
}

ਸਥਿਰ ਪੂਰਨ
update_card(ਪੂਰਨ agent_fd, ਪੂਰਨ ਜੋੜੋ, ਅਚਲ ਅੱਖਰ *id, ਪੂਰਨ qflag, ਪੂਰਨ no_pin,
    ਪੂਰਨ ਕੁੰਜੀ_only, ਪੂਰਨ cert_only,
    ਬਣਤਰ dest_constraint **dest_constraints, ਮਾਪ_t ndest_constraints,
    ਬਣਤਰ sshkey **certs, ਮਾਪ_t ncerts)
{
	ਅੱਖਰ *pin = ਨਿਰਾ;
	ਪੂਰਨ r, ret = -1;

	ਜੇ (ਕੁੰਜੀ_only)
		ncerts = 0;

	ਜੇ (ਜੋੜੋ && !no_pin) {
		ਜੇ ((pin = read_passphrase("Enter passphrase for PKCS#11: ",
		    RP_ALLOW_STDIN)) == ਨਿਰਾ)
			ਵਾਪਸ -1;
	}

	ਜੇ ((r = ssh_update_card(agent_fd, ਜੋੜੋ, id, pin == ਨਿਰਾ ? "" : pin,
	    lifetime, confirm, dest_constraints, ndest_constraints,
	    cert_only, certs, ncerts)) == 0) {
		ret = 0;
		ਜੇ (!qflag) {
			fprintf(stderr, "Card %s: %s\n",
			    ਜੋੜੋ ? "added" : "removed", id);
		}
	} ਨਹੀਂਤਾਂ {
		fprintf(stderr, "Could not %s card \"%s\": %s\n",
		    ਜੋੜੋ ? "add" : "remove", id, ssh_err(r));
		ret = -1;
	}
	ਮੁਕਤ(pin);
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਪੂਰਨ
test_ਕੁੰਜੀ(ਪੂਰਨ agent_fd, ਅਚਲ ਅੱਖਰ *filename)
{
	ਬਣਤਰ sshkey *ਕੁੰਜੀ = ਨਿਰਾ;
	u_char *sig = ਨਿਰਾ;
	ਅਚਲ ਅੱਖਰ *alg = ਨਿਰਾ;
	ਮਾਪ_t slen = 0;
	ਪੂਰਨ r, ret = -1;
	ਅੱਖਰ ਅੰਕੜੇ[1024];

	ਜੇ ((r = sshkey_ਲੱਦੋ_ਜਨਤਕ(filename, &ਕੁੰਜੀ, ਨਿਰਾ)) != 0) {
		error_r(r, "Couldn't read public key %s", filename);
		ਵਾਪਸ -1;
	}
	ਜੇ (sshkey_type_plain(ਕੁੰਜੀ->type) == ਕੁੰਜੀ_RSA)
		alg = "rsa-sha2-256";
	arc4random_buf(ਅੰਕੜੇ, ਆਕਾਰ(ਅੰਕੜੇ));
	ਜੇ ((r = ssh_agent_sign(agent_fd, ਕੁੰਜੀ, &sig, &slen, ਅੰਕੜੇ, ਆਕਾਰ(ਅੰਕੜੇ),
	    alg, 0)) != 0) {
		error_r(r, "Agent signature failed for %s", filename);
		ਜਾਓ ਪੂਰਾ;
	}
	ਜੇ ((r = sshkey_verify(ਕੁੰਜੀ, sig, slen, ਅੰਕੜੇ, ਆਕਾਰ(ਅੰਕੜੇ),
	    alg, 0, ਨਿਰਾ)) != 0) {
		error_r(r, "Signature verification failed for %s", filename);
		ਜਾਓ ਪੂਰਾ;
	}
	/* success */
	ret = 0;
 ਪੂਰਾ:
	ਮੁਕਤ(sig);
	sshkey_free(ਕੁੰਜੀ);
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਪੂਰਨ
list_identities(ਪੂਰਨ agent_fd, ਪੂਰਨ do_fp)
{
	ਅੱਖਰ *fp;
	ਪੂਰਨ r;
	ਬਣਤਰ ssh_identitylist *idlist;
	ਮਾਪ_t i;

	ਜੇ ((r = ssh_fetch_identitylist(agent_fd, &idlist)) != 0) {
		ਜੇ (r != SSH_ERR_AGENT_NO_IDENTITIES)
			fprintf(stderr, "error fetching identities: %s\n",
			    ssh_err(r));
		ਨਹੀਂਤਾਂ
			ਲਿਖੋ("The agent has no identities.\n");
		ਵਾਪਸ -1;
	}
	ਲਈ (i = 0; i < idlist->nkeys; i++) {
		ਜੇ (do_fp) {
			fp = sshkey_fingerprint(idlist->ਕੁੰਜੀਆਂ[i],
			    fingerprint_hash, SSH_FP_DEFAULT);
			ਲਿਖੋ("%u %s %s (%s)\n", sshkey_ਮਾਪ(idlist->ਕੁੰਜੀਆਂ[i]),
			    fp == ਨਿਰਾ ? "(null)" : fp, idlist->comments[i],
			    sshkey_type(idlist->ਕੁੰਜੀਆਂ[i]));
			ਮੁਕਤ(fp);
		} ਨਹੀਂਤਾਂ {
			ਜੇ ((r = sshkey_write(idlist->ਕੁੰਜੀਆਂ[i], stdout)) != 0) {
				fprintf(stderr, "sshkey_write: %s\n",
				    ssh_err(r));
				ਜਾਰੀ;
			}
			fprintf(stdout, " %s\n", idlist->comments[i]);
		}
	}
	ssh_free_identitylist(idlist);
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
ਤਾਲਾ_agent(ਪੂਰਨ agent_fd, ਪੂਰਨ ਤਾਲਾ)
{
	ਅੱਖਰ prompt[100], *p1, *p2;
	ਪੂਰਨ r, passok = 1, ret = -1;

	strlcpy(prompt, "Enter lock password: ", ਆਕਾਰ(prompt));
	p1 = read_passphrase(prompt, RP_ALLOW_STDIN);
	ਜੇ (ਤਾਲਾ) {
		strlcpy(prompt, "Again: ", ਆਕਾਰ prompt);
		p2 = read_passphrase(prompt, RP_ALLOW_STDIN);
		ਜੇ (strcmp(p1, p2) != 0) {
			fprintf(stderr, "Passwords do not match.\n");
			passok = 0;
		}
		freezero(p2, ਲੜੀ_ਲੰਬਾਈ(p2));
	}
	ਜੇ (passok) {
		ਜੇ ((r = ssh_ਤਾਲਾ_agent(agent_fd, ਤਾਲਾ, p1)) == 0) {
			fprintf(stderr, "Agent %slocked.\n", ਤਾਲਾ ? "" : "un");
			ret = 0;
		} ਨਹੀਂਤਾਂ {
			fprintf(stderr, "Failed to %slock agent: %s\n",
			    ਤਾਲਾ ? "" : "un", ssh_err(r));
		}
	}
	freezero(p1, ਲੜੀ_ਲੰਬਾਈ(p1));
	ਵਾਪਸ (ret);
}

ਸਥਿਰ ਪੂਰਨ
ਲੱਦੋ_resident_ਕੁੰਜੀਆਂ(ਪੂਰਨ agent_fd, ਅਚਲ ਅੱਖਰ *skprovider, ਪੂਰਨ qflag, ਪੂਰਨ no_pin,
    ਬਣਤਰ dest_constraint **dest_constraints, ਮਾਪ_t ndest_constraints)
{
	ਬਣਤਰ sshsk_resident_ਕੁੰਜੀ **srks;
	ਮਾਪ_t nsrks, i;
	ਬਣਤਰ sshkey *ਕੁੰਜੀ;
	ਪੂਰਨ r, ok = 0;
	ਅੱਖਰ *fp, *pin = ਨਿਰਾ;

	ਜੇ (!no_pin) {
		pin = read_passphrase("Enter PIN for authenticator: ",
		    RP_ALLOW_STDIN);
	}
	ਜੇ ((r = sshsk_ਲੱਦੋ_resident(skprovider, ਨਿਰਾ, pin == ਨਿਰਾ ? "" : pin,
	    0, &srks, &nsrks)) != 0) {
		error_r(r, "Unable to load resident keys");
		ਮੁਕਤ(pin);
		ਵਾਪਸ r;
	}
	ਮੁਕਤ(pin);
	ਲਈ (i = 0; i < nsrks; i++) {
		ਕੁੰਜੀ = srks[i]->ਕੁੰਜੀ;
		ਜੇ ((fp = sshkey_fingerprint(ਕੁੰਜੀ,
		    fingerprint_hash, SSH_FP_DEFAULT)) == ਨਿਰਾ)
			fatal_f("sshkey_fingerprint failed");
		ਜੇ ((r = ssh_ਜੋੜੋ_ਪਛਾਣ_ਤੱਤ_constrained(agent_fd, ਕੁੰਜੀ,
		    ਕੁੰਜੀ->sk_application, lifetime, confirm, skprovider,
		    dest_constraints, ndest_constraints)) != 0) {
			error("Unable to add key %s %s",
			    sshkey_type(ਕੁੰਜੀ), fp);
			ਮੁਕਤ(fp);
			ok = r;
			ਜਾਰੀ;
		}
		ਜੇ (ok == 0)
			ok = 1;
		ਜੇ (!qflag) {
			fprintf(stderr, "Resident identity added: %s %s\n",
			    sshkey_type(ਕੁੰਜੀ), fp);
			ਜੇ (lifetime != 0) {
				fprintf(stderr,
				    "Lifetime set to %d seconds\n", lifetime);
			}
			ਜੇ (confirm != 0) {
				fprintf(stderr, "The user must confirm "
				    "each use of the key\n");
			}
		}
		ਮੁਕਤ(fp);
	}
	sshsk_free_resident_ਕੁੰਜੀਆਂ(srks, nsrks);
	ਜੇ (nsrks == 0)
		ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_NOT_ਮਿਲਿਆ;
	ਵਾਪਸ ok == 1 ? 0 : ok;
}

ਸਥਿਰ ਪੂਰਨ
do_file(ਪੂਰਨ agent_fd, ਪੂਰਨ deleting, ਪੂਰਨ ਕੁੰਜੀ_only, ਪੂਰਨ cert_only,
    ਅੱਖਰ *file, ਪੂਰਨ qflag, ਪੂਰਨ Nflag, ਅਚਲ ਅੱਖਰ *skprovider,
    ਬਣਤਰ dest_constraint **dest_constraints, ਮਾਪ_t ndest_constraints)
{
	ਜੇ (deleting) {
		ਜੇ (delete_file(agent_fd, file, ਕੁੰਜੀ_only,
		    cert_only, qflag) == -1)
			ਵਾਪਸ -1;
	} ਨਹੀਂਤਾਂ {
		ਜੇ (ਜੋੜੋ_file(agent_fd, file, ਕੁੰਜੀ_only, cert_only, qflag, Nflag,
		    skprovider, dest_constraints, ndest_constraints) == -1)
			ਵਾਪਸ -1;
	}
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਖਾਲੀ
free_dest_constraint_hop(ਬਣਤਰ dest_constraint_hop *dch)
{
	u_int i;

	ਜੇ (dch == ਨਿਰਾ)
		ਵਾਪਸ;
	ਮੁਕਤ(dch->user);
	ਮੁਕਤ(dch->hostname);
	ਲਈ (i = 0; i < dch->nkeys; i++)
		sshkey_free(dch->ਕੁੰਜੀਆਂ[i]);
	ਮੁਕਤ(dch->ਕੁੰਜੀਆਂ);
	ਮੁਕਤ(dch->ਕੁੰਜੀ_is_ca);
}

ਸਥਿਰ ਖਾਲੀ
free_dest_constraints(ਬਣਤਰ dest_constraint **dcs, ਮਾਪ_t ndcs)
{
	ਮਾਪ_t i;

	ਲਈ (i = 0; i < ndcs; i++) {
		free_dest_constraint_hop(&dcs[i]->from);
		free_dest_constraint_hop(&dcs[i]->ਮੰਜ਼ਿਲ);
		ਮੁਕਤ(dcs[i]);
	}
	ਮੁਕਤ(dcs);
}


ਸਥਿਰ ਖਾਲੀ
parse_dest_constraint_hop(ਅਚਲ ਅੱਖਰ *s, ਬਣਤਰ dest_constraint_hop *dch,
    ਅੱਖਰ **hostkey_files)
{
	ਅੱਖਰ *user = ਨਿਰਾ, *host, *os, *ਰਸਤਾ;
	ਮਾਪ_t i;
	ਬਣਤਰ hostkeys *hostkeys;
	ਅਚਲ ਬਣਤਰ hostkey_ਇੰਦਰਾਜ *hke;
	ਪੂਰਨ r, want_ca;

	memset(dch, '\0', ਆਕਾਰ(*dch));
	os = xstrdup(s);
	ਜੇ ((host = strrchr(os, '@')) == ਨਿਰਾ)
		host = os;
	ਨਹੀਂਤਾਂ {
		*host++ = '\0';
		user = os;
	}
	cleanhostname(host);
	/* Trivial case: username@ (all hosts) */
	ਜੇ (*host == '\0') {
		ਜੇ (user == ਨਿਰਾ) {
			fatal("Invalid key destination constraint \"%s\": "
			    "does not specify user or host", s);
		}
		dch->user = xstrdup(user);
		/* other fields left blank */
		ਮੁਕਤ(os);
		ਵਾਪਸ;
	}
	ਜੇ (hostkey_files == ਨਿਰਾ)
		fatal_f("no hostkey files");
	/* Otherwise we need to look up the keys for this hostname */
	hostkeys = init_hostkeys();
	ਲਈ (i = 0; hostkey_files[i]; i++) {
		ਰਸਤਾ = tilde_expand_filename(hostkey_files[i], getuid());
		debug2_f("looking up host keys for \"%s\" in %s", host, ਰਸਤਾ);
                ਲੱਦੋ_hostkeys(hostkeys, host, ਰਸਤਾ, 0);
		ਮੁਕਤ(ਰਸਤਾ);
	}
	dch->user = user == ਨਿਰਾ ? ਨਿਰਾ : xstrdup(user);
	dch->hostname = xstrdup(host);
	ਲਈ (i = 0; i < hostkeys->ਅੰਕ_entries; i++) {
		hke = hostkeys->entries + i;
		want_ca = hke->marker == MRK_CA;
		ਜੇ (hke->marker != MRK_NONE && !want_ca)
			ਜਾਰੀ;
		debug3_f("%s%s%s: adding %s %skey from %s:%lu as key %u",
		    user == ਨਿਰਾ ? "": user, user == ਨਿਰਾ ? "" : "@",
		    host, sshkey_type(hke->ਕੁੰਜੀ), want_ca ? "CA " : "",
		    hke->file, hke->ਸਤਰ, dch->nkeys);
		dch->ਕੁੰਜੀਆਂ = xrecallocarray(dch->ਕੁੰਜੀਆਂ, dch->nkeys,
		    dch->nkeys + 1, ਆਕਾਰ(*dch->ਕੁੰਜੀਆਂ));
		dch->ਕੁੰਜੀ_is_ca = xrecallocarray(dch->ਕੁੰਜੀ_is_ca, dch->nkeys,
		    dch->nkeys + 1, ਆਕਾਰ(*dch->ਕੁੰਜੀ_is_ca));
		ਜੇ ((r = sshkey_from_ਨਿੱਜੀ(hke->ਕੁੰਜੀ,
		    &(dch->ਕੁੰਜੀਆਂ[dch->nkeys]))) != 0)
			fatal_fr(r, "sshkey_from_private");
		dch->ਕੁੰਜੀ_is_ca[dch->nkeys] = want_ca;
		dch->nkeys++;
	}
	ਜੇ (dch->nkeys == 0)
		fatal("No host keys found for destination \"%s\"", host);
	free_hostkeys(hostkeys);
	ਮੁਕਤ(os);
	ਵਾਪਸ;
}

ਸਥਿਰ ਖਾਲੀ
parse_dest_constraint(ਅਚਲ ਅੱਖਰ *s, ਬਣਤਰ dest_constraint ***dcp,
    ਮਾਪ_t *ndcp, ਅੱਖਰ **hostkey_files)
{
	ਬਣਤਰ dest_constraint *dc;
	ਅੱਖਰ *os, *cp;

	dc = xcalloc(1, ਆਕਾਰ(*dc));
	os = xstrdup(s);
	ਜੇ ((cp = strchr(os, '>')) == ਨਿਰਾ) {
		/* initial hop; no 'from' hop specified */
		parse_dest_constraint_hop(os, &dc->ਮੰਜ਼ਿਲ, hostkey_files);
	} ਨਹੀਂਤਾਂ {
		/* two hops specified */
		*(cp++) = '\0';
		parse_dest_constraint_hop(os, &dc->from, hostkey_files);
		parse_dest_constraint_hop(cp, &dc->ਮੰਜ਼ਿਲ, hostkey_files);
		ਜੇ (dc->from.user != ਨਿਰਾ) {
			fatal("Invalid key constraint %s: cannot specify "
			    "user on 'from' host", os);
		}
	}
	/* XXX eliminate or error on duplicates */
	debug2_f("constraint %zu: %s%s%s (%u keys) > %s%s%s (%u keys)", *ndcp,
	    dc->from.user ? dc->from.user : "", dc->from.user ? "@" : "",
	    dc->from.hostname ? dc->from.hostname : "(ORIGIN)", dc->from.nkeys,
	    dc->ਮੰਜ਼ਿਲ.user ? dc->ਮੰਜ਼ਿਲ.user : "", dc->ਮੰਜ਼ਿਲ.user ? "@" : "",
	    dc->ਮੰਜ਼ਿਲ.hostname ? dc->ਮੰਜ਼ਿਲ.hostname : "(ANY)", dc->ਮੰਜ਼ਿਲ.nkeys);
	*dcp = xrecallocarray(*dcp, *ndcp, *ndcp + 1, ਆਕਾਰ(**dcp));
	(*dcp)[(*ndcp)++] = dc;
	ਮੁਕਤ(os);
}


ਸਥਿਰ ਖਾਲੀ
usage(ਖਾਲੀ)
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

ਪੂਰਨ
ਮੁੱਖ(ਪੂਰਨ argc, ਅੱਖਰ **argv)
{
	ਬਾਹਰੀ ਅੱਖਰ *optarg;
	ਬਾਹਰੀ ਪੂਰਨ optind;
	ਪੂਰਨ agent_fd = -1;
	ਅੱਖਰ *pkcs11provider = ਨਿਰਾ, *skprovider = ਨਿਰਾ;
	ਅੱਖਰ **dest_constraint_ਲੜੀਆਂ = ਨਿਰਾ, **hostkey_files = ਨਿਰਾ;
	ਪੂਰਨ r, i, ch, deleting = 0, ret = 0, ਕੁੰਜੀ_only = 0, cert_only = 0;
	ਪੂਰਨ do_download = 0, xflag = 0, lflag = 0, Dflag = 0;
	ਪੂਰਨ Qflag = 0, qflag = 0, Tflag = 0, Nflag = 0, no_pin = 0;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_INFO;
	ਬਣਤਰ sshkey *k, **certs = ਨਿਰਾ;
	ਬਣਤਰ dest_constraint **dest_constraints = ਨਿਰਾ;
	ਮਾਪ_t n, ndest_constraints = 0, ncerts = 0;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	__progname = ssh_get_progname(argv[0]);
	ਬੀਜ_rng();

	log_init(__progname, log_level, log_facility, 1);

	setvbuf(stdout, ਨਿਰਾ, _IOLBF, 0);

	skprovider = getenv("SSH_SK_PROVIDER");

	ਜਦੋਂ ((ch = getopt(argc, argv, "vkKlLNPCcdDTxXE:e:h:H:M:m:Qqs:S:t:")) != -1) {
		ਚੋਣ (ch) {
		ਹਾਲਤ 'v':
			ਜੇ (log_level == SYSLOG_LEVEL_INFO)
				log_level = SYSLOG_LEVEL_DEBUG1;
			ਨਹੀਂਤਾਂ ਜੇ (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			ਰੋਕੋ;
		ਹਾਲਤ 'N':
			Nflag = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			ਜੇ (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			ਰੋਕੋ;
		ਹਾਲਤ 'H':
			stringlist_append(&hostkey_files, optarg);
			ਰੋਕੋ;
		ਹਾਲਤ 'h':
			stringlist_append(&dest_constraint_ਲੜੀਆਂ, optarg);
			ਰੋਕੋ;
		ਹਾਲਤ 'k':
			ਕੁੰਜੀ_only = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'C':
			cert_only = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'K':
			do_download = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'l':
		ਹਾਲਤ 'L':
			ਜੇ (lflag != 0)
				fatal("-%c flag already specified", lflag);
			lflag = ch;
			ਰੋਕੋ;
		ਹਾਲਤ 'x':
		ਹਾਲਤ 'X':
			ਜੇ (xflag != 0)
				fatal("-%c flag already specified", xflag);
			xflag = ch;
			ਰੋਕੋ;
		ਹਾਲਤ 'c':
			confirm = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'm':
		ਹਾਲਤ 'M':
			/* deprecated */
			ਰੋਕੋ;
		ਹਾਲਤ 'd':
			deleting = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'P':
			no_pin = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'D':
			Dflag = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 's':
			pkcs11provider = optarg;
			ਰੋਕੋ;
		ਹਾਲਤ 'S':
			skprovider = optarg;
			ਰੋਕੋ;
		ਹਾਲਤ 'e':
			deleting = 1;
			pkcs11provider = optarg;
			ਰੋਕੋ;
		ਹਾਲਤ 't':
			ਜੇ ((lifetime = convtime(optarg)) == -1 ||
			    lifetime < 0 || (u_long)lifetime > UINT32_MAX) {
				fprintf(stderr, "Invalid lifetime\n");
				ret = 1;
				ਜਾਓ ਪੂਰਾ;
			}
			ਰੋਕੋ;
		ਹਾਲਤ 'q':
			qflag = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'Q':
			Qflag = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'T':
			Tflag = 1;
			ਰੋਕੋ;
		ਮੂਲ:
			usage();
			ret = 1;
			ਜਾਓ ਪੂਰਾ;
		}
	}
	log_init(__progname, log_level, log_facility, 1);

	ਜੇ ((xflag != 0) + (lflag != 0) + (Dflag != 0) + (Qflag != 0) > 1)
		fatal("Invalid combination of actions");

	/* First, get a connection to the authentication agent. */
	ਚੋਣ (r = ssh_get_authentication_socket(&agent_fd)) {
	ਹਾਲਤ 0:
		ਰੋਕੋ;
	ਹਾਲਤ SSH_ERR_AGENT_NOT_PRESENT:
		fprintf(stderr, "Could not open a connection to your "
		    "authentication agent.\n");
		ਬਾਹਰ_ਨਿਕਲੋ(2);
	ਮੂਲ:
		fprintf(stderr, "Error connecting to agent: %s\n", ssh_err(r));
		ਬਾਹਰ_ਨਿਕਲੋ(2);
	}

	ਜੇ (xflag) {
		ਜੇ (ਤਾਲਾ_agent(agent_fd, xflag == 'x' ? 1 : 0) == -1)
			ret = 1;
		ਜਾਓ ਪੂਰਾ;
	} ਨਹੀਂਤਾਂ ਜੇ (lflag) {
		ਜੇ (list_identities(agent_fd, lflag == 'l' ? 1 : 0) == -1)
			ret = 1;
		ਜਾਓ ਪੂਰਾ;
	} ਨਹੀਂਤਾਂ ਜੇ (Dflag) {
		ਜੇ (delete_all(agent_fd, qflag) == -1)
			ret = 1;
		ਜਾਓ ਪੂਰਾ;
	} ਨਹੀਂਤਾਂ ਜੇ (Qflag) {
		ਜੇ (query_exts(agent_fd) == -1)
			ret = 1;
		ਜਾਓ ਪੂਰਾ;
	}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ ENABLE_SK_ਅੰਦਰੂਨੀ
	ਜੇ (skprovider == ਨਿਰਾ)
		skprovider = "internal";
#ਜੇ_ਅੰਤ

	ਜੇ (hostkey_files == ਨਿਰਾ) {
		/* use defaults from readconf.c */
		stringlist_append(&hostkey_files, ਰਸਤਾ_SSH_USER_HOSTFILE);
		stringlist_append(&hostkey_files, ਰਸਤਾ_SSH_USER_HOSTFILE2);
		stringlist_append(&hostkey_files, ਰਸਤਾ_SSH_SYSTEM_HOSTFILE);
		stringlist_append(&hostkey_files, ਰਸਤਾ_SSH_SYSTEM_HOSTFILE2);
	}
	ਜੇ (dest_constraint_ਲੜੀਆਂ != ਨਿਰਾ) {
		ਲਈ (i = 0; dest_constraint_ਲੜੀਆਂ[i] != ਨਿਰਾ; i++) {
			parse_dest_constraint(dest_constraint_ਲੜੀਆਂ[i],
			  &dest_constraints, &ndest_constraints, hostkey_files);
		}
	}

	argc -= optind;
	argv += optind;
	ਜੇ (Tflag) {
		ਜੇ (argc <= 0)
			fatal("no keys to test");
		ਲਈ (r = i = 0; i < argc; i++)
			r |= test_ਕੁੰਜੀ(agent_fd, argv[i]);
		ret = r == 0 ? 0 : 1;
		ਜਾਓ ਪੂਰਾ;
	}
	ਜੇ (pkcs11provider != ਨਿਰਾ) {
		ਲਈ (i = 0; i < argc; i++) {
			ਜੇ ((r = sshkey_ਲੱਦੋ_ਜਨਤਕ(argv[i], &k, ਨਿਰਾ)) != 0)
				fatal_fr(r, "load certificate %s", argv[i]);
			certs = xrecallocarray(certs, ncerts, ncerts + 1,
			    ਆਕਾਰ(*certs));
			debug2("%s: %s", argv[i], sshkey_ssh_name(k));
			certs[ncerts++] = k;
		}
		debug2_f("loaded %zu certificates", ncerts);
		ਜੇ (update_card(agent_fd, !deleting, pkcs11provider,
		    qflag, no_pin, ਕੁੰਜੀ_only, cert_only,
		    dest_constraints, ndest_constraints,
		    certs, ncerts) == -1)
			ret = 1;
		ਲਈ (n = 0; n < ncerts; n++)
			sshkey_free(certs[n]);
		ਮੁਕਤ(certs);
		ਜਾਓ ਪੂਰਾ;
	}
	ਜੇ (do_download) {
		ਜੇ (skprovider == ਨਿਰਾ)
			fatal("Cannot download keys without provider");
		ਜੇ (ਲੱਦੋ_resident_ਕੁੰਜੀਆਂ(agent_fd, skprovider, qflag, no_pin,
		    dest_constraints, ndest_constraints) != 0)
			ret = 1;
		ਜਾਓ ਪੂਰਾ;
	}
	ਜੇ (argc == 0) {
		ਅੱਖਰ buf[PATH_MAX];
		ਬਣਤਰ passwd *pw;
		ਬਣਤਰ stat st;
		ਪੂਰਨ ਗਿਣਤੀ_2 = 0;

		ਜੇ ((pw = getpwuid(getuid())) == ਨਿਰਾ) {
			fprintf(stderr, "No user found with uid %u\n",
			    (u_int)getuid());
			ret = 1;
			ਜਾਓ ਪੂਰਾ;
		}

		ਲਈ (i = 0; default_files[i]; i++) {
			snprintf(buf, ਆਕਾਰ(buf), "%s/%s", pw->pw_dir,
			    default_files[i]);
			ਜੇ (stat(buf, &st) == -1)
				ਜਾਰੀ;
			ਜੇ (do_file(agent_fd, deleting, ਕੁੰਜੀ_only, cert_only,
			    buf, qflag, Nflag, skprovider,
			    dest_constraints, ndest_constraints) == -1)
				ret = 1;
			ਨਹੀਂਤਾਂ
				ਗਿਣਤੀ_2++;
		}
		ਜੇ (ਗਿਣਤੀ_2 == 0)
			ret = 1;
	} ਨਹੀਂਤਾਂ {
		ਲਈ (i = 0; i < argc; i++) {
			ਜੇ (do_file(agent_fd, deleting, ਕੁੰਜੀ_only, cert_only,
			    argv[i], qflag, Nflag, skprovider,
			    dest_constraints, ndest_constraints) == -1)
				ret = 1;
		}
	}
ਪੂਰਾ:
	clear_pass();
	stringlist_free(hostkey_files);
	stringlist_free(dest_constraint_ਲੜੀਆਂ);
	free_dest_constraints(dest_constraints, ndest_constraints);
	ssh_close_authentication_socket(agent_fd);
	ਵਾਪਸ ret;
}
