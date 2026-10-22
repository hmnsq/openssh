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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/stat.h>

#ifdef WITH_OPENSSL
# include <openssl/evp.h>
# include "openbsd-compat/openssl-compat.h"
#endif

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <fcntl.h>
#અન્તર્ભાવ <pwd.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <limits.h>
#અન્તર્ભાવ <time.h>

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "ssh.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "authfd.h"
#અન્તર્ભાવ "authfile.h"
#અન્તર્ભાવ "pathnames.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "digest.h"
#અન્તર્ભાવ "ssh-sk.h"
#અન્તર્ભાવ "sk-api.h"
#અન્તર્ભાવ "hostfile.h"

#define CERT_EXPIRY_GRACE	(5*60)

/* argv0 */
બાહ્ય અક્ષર *__progname;

/* Default files to add */
સ્થિર અક્ષર *default_files[] = {
#ifdef WITH_OPENSSL
	_PATH_SSH_CLIENT_ID_RSA,
	_PATH_SSH_CLIENT_ID_ECDSA,
	_PATH_SSH_CLIENT_ID_ECDSA_SK,
#endif /* WITH_OPENSSL */
	_PATH_SSH_CLIENT_ID_ED25519,
	_PATH_SSH_CLIENT_ID_ED25519_SK,
	_PATH_SSH_CLIENT_ID_MLDSA44_ED25519,
	ખાલી
};

સ્થિર પૂર્ણાંક fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* Default lifetime (0 == forever) */
સ્થિર પૂર્ણાંક lifetime = 0;

/* User has to confirm key use */
સ્થિર પૂર્ણાંક confirm = 0;

/* we keep a cache of one passphrase */
સ્થિર અક્ષર *pass = ખાલી;
સ્થિર શૂન્ય
clear_pass(શૂન્ય)
{
	જો (pass) {
		freezero(pass, strlen(pass));
		pass = ખાલી;
	}
}

સ્થિર પૂર્ણાંક
delete_one(પૂર્ણાંક agent_fd, અચલ સંરચના sshkey *ચાવી, અચલ અક્ષર *comment,
    અચલ અક્ષર *path, પૂર્ણાંક qflag)
{
	પૂર્ણાંક r;

	જો ((r = ssh_remove_identity(agent_fd, ચાવી)) != 0) {
		fprintf(stderr, "Could not remove identity \"%s\": %s\n",
		    path, ssh_err(r));
		પાછા r;
	}
	જો (!qflag) {
		fprintf(stderr, "Identity removed: %s %s (%s)\n", path,
		    sshkey_type(ચાવી), comment ? comment : "no comment");
	}
	પાછા 0;
}

સ્થિર પૂર્ણાંક
delete_stdin(પૂર્ણાંક agent_fd, પૂર્ણાંક qflag, પૂર્ણાંક ચાવી_only, પૂર્ણાંક cert_only)
{
	અક્ષર *લીટી = ખાલી, *cp;
	size_t linesize = 0;
	સંરચના sshkey *ચાવી = ખાલી;
	પૂર્ણાંક lnum = 0, r, ret = -1;

	જ્યારે (getline(&લીટી, &linesize, stdin) != -1) {
		lnum++;
		sshkey_free(ચાવી);
		ચાવી = ખાલી;
		લીટી[strcspn(લીટી, "\n")] = '\0';
		cp = લીટી + strspn(લીટી, " \t");
		જો (*cp == '#' || *cp == '\0')
			ચાલુ;
		જો ((ચાવી = sshkey_new(ચાવી_UNSPEC)) == ખાલી)
			fatal_f("sshkey_new");
		જો ((r = sshkey_read(ચાવી, &cp)) != 0) {
			error_r(r, "(stdin):%d: invalid key", lnum);
			ચાલુ;
		}
		જો ((!ચાવી_only && !cert_only) ||
		    (ચાવી_only && !sshkey_is_cert(ચાવી)) ||
		    (cert_only && sshkey_is_cert(ચાવી))) {
			જો (delete_one(agent_fd, ચાવી, cp,
			    "(stdin)", qflag) == 0)
				ret = 0;
		}
	}
	sshkey_free(ચાવી);
	મુક્ત(લીટી);
	પાછા ret;
}

સ્થિર પૂર્ણાંક
delete_file(પૂર્ણાંક agent_fd, અચલ અક્ષર *filename, પૂર્ણાંક ચાવી_only,
    પૂર્ણાંક cert_only, પૂર્ણાંક qflag)
{
	સંરચના sshkey *જાહેર, *cert = ખાલી;
	અક્ષર *certpath = ખાલી, *comment = ખાલી;
	પૂર્ણાંક r, ret = -1;

	જો (strcmp(filename, "-") == 0)
		પાછા delete_stdin(agent_fd, qflag, ચાવી_only, cert_only);

	જો ((r = sshkey_load_public(filename, &જાહેર,  &comment)) != 0) {
		printf("Bad key file %s: %s\n", filename, ssh_err(r));
		પાછા -1;
	}
	જો ((!ચાવી_only && !cert_only) ||
	    (ચાવી_only && !sshkey_is_cert(જાહેર)) ||
	    (cert_only && sshkey_is_cert(જાહેર))) {
		જો (delete_one(agent_fd, જાહેર, comment, filename, qflag) == 0)
			ret = 0;
	}

	જો (ચાવી_only)
		જાઓ out;

	/* Now try to delete the corresponding certificate too */
	મુક્ત(comment);
	comment = ખાલી;
	xasprintf(&certpath, "%s-cert.pub", filename);
	જો ((r = sshkey_load_public(certpath, &cert, &comment)) != 0) {
		જો (r != SSH_ERR_SYSTEM_ERROR || errno != ENOENT)
			error_r(r, "Failed to load certificate \"%s\"", certpath);
		જાઓ out;
	}

	જો (!sshkey_equal_public(cert, જાહેર))
		fatal("Certificate %s does not match private key %s",
		    certpath, filename);

	જો (delete_one(agent_fd, cert, comment, certpath, qflag) == 0)
		ret = 0;

 out:
	sshkey_free(cert);
	sshkey_free(જાહેર);
	મુક્ત(certpath);
	મુક્ત(comment);

	પાછા ret;
}

/* Send a request to remove all identities. */
સ્થિર પૂર્ણાંક
delete_all(પૂર્ણાંક agent_fd, પૂર્ણાંક qflag)
{
	પૂર્ણાંક ret = -1;

	/*
	 * Since the agent might be forwarded, old or non-OpenSSH, when asked
	 * to remove all keys, attempt to remove both protocol v.1 and v.2
	 * keys.
	 */
	જો (ssh_remove_all_identities(agent_fd, 2) == 0)
		ret = 0;
	/* ignore error-code for ssh1 */
	ssh_remove_all_identities(agent_fd, 1);

	જો (ret != 0)
		fprintf(stderr, "Failed to remove all identities.\n");
	નહીંતર જો (!qflag)
		fprintf(stderr, "All identities removed.\n");

	પાછા ret;
}

સ્થિર પૂર્ણાંક
query_exts(પૂર્ણાંક agent_fd)
{
	પૂર્ણાંક r;
	અક્ષર **exts = ખાલી;
	size_t i;

	જો ((r = ssh_agent_query_extensions(agent_fd, &exts)) != 0)
		fatal_r(r, "unable to query supported extensions");
	માટે (i = 0; exts != ખાલી && exts[i] != ખાલી; i++)
		puts(exts[i]);
	stringlist_free(exts);
	પાછા 0;
}

સ્થિર પૂર્ણાંક
check_cert_lifetime(અચલ સંરચના sshkey *cert, પૂર્ણાંક cert_lifetime)
{
	time_t now;
	uint64_t n;

	જો (cert == ખાલી || cert->cert == ખાલી || !sshkey_is_cert(cert) ||
	    cert->cert->valid_before == 0xFFFFFFFFFFFFFFFFULL)
		પાછા cert_lifetime;
	જો ((now = time(ખાલી)) <= 0)
		fatal_f("system time is at/before epoch");
	જો ((uint64_t)now > (cert->cert->valid_before + CERT_EXPIRY_GRACE))
		પાછા -1; /* certificate already expired */
	n = (CERT_EXPIRY_GRACE + cert->cert->valid_before) - (uint64_t)now;
	n = MINIMUM(n, INT_MAX);
	જો (cert_lifetime <= 0)
		પાછા (પૂર્ણાંક)n;
	પાછા MINIMUM(cert_lifetime, (પૂર્ણાંક)n);
}

સ્થિર પૂર્ણાંક
add_file(પૂર્ણાંક agent_fd, અચલ અક્ષર *filename, પૂર્ણાંક ચાવી_only, પૂર્ણાંક cert_only,
    પૂર્ણાંક qflag, પૂર્ણાંક Nflag, અચલ અક્ષર *skprovider,
    સંરચના dest_constraint **dest_constraints,
    size_t ndest_constraints)
{
	સંરચના sshkey *ખાનગી = ખાલી, *cert = ખાલી;
	અક્ષર *comment = ખાલી;
	અક્ષર સંદેશ[1024], *certpath = ખાલી;
	પૂર્ણાંક cert_lifetime, r, fd, ret = -1;
	સંરચના sshbuf *keyblob;

	જો (strcmp(filename, "-") == 0) {
		fd = STDIN_FILENO;
		filename = "(stdin)";
	} નહીંતર જો ((fd = open(filename, O_RDONLY)) == -1) {
		perror(filename);
		પાછા -1;
	}

	/*
	 * Since we'll try to load a keyfile multiple times, permission errors
	 * will occur multiple times, so check perms first and bail if wrong.
	 */
	જો (fd != STDIN_FILENO) {
		જો (sshkey_perm_ok(fd, filename) != 0) {
			close(fd);
			પાછા -1;
		}
	}
	જો ((r = sshbuf_load_fd(fd, &keyblob)) != 0) {
		fprintf(stderr, "Error loading key \"%s\": %s\n",
		    filename, ssh_err(r));
		sshbuf_free(keyblob);
		close(fd);
		પાછા -1;
	}
	close(fd);

	/* At first, try empty passphrase */
	જો ((r = sshkey_parse_private_fileblob(keyblob, "", &ખાનગી,
	    &comment)) != 0 && r != SSH_ERR_ચાવી_WRONG_PASSPHRASE) {
		fprintf(stderr, "Error loading key \"%s\": %s\n",
		    filename, ssh_err(r));
		જાઓ fail_load;
	}
	/* try last */
	જો (ખાનગી == ખાલી && pass != ખાલી) {
		જો ((r = sshkey_parse_private_fileblob(keyblob, pass, &ખાનગી,
		    &comment)) != 0 && r != SSH_ERR_ચાવી_WRONG_PASSPHRASE) {
			fprintf(stderr, "Error loading key \"%s\": %s\n",
			    filename, ssh_err(r));
			જાઓ fail_load;
		}
	}
	જો (ખાનગી == ખાલી) {
		/* clear passphrase since it did not work */
		clear_pass();
		snprintf(સંદેશ, કદ સંદેશ, "Enter passphrase for %s%s: ",
		    filename, confirm ? " (will confirm each use)" : "");
		માટે (;;) {
			pass = read_passphrase(સંદેશ, RP_ALLOW_STDIN);
			જો (strcmp(pass, "") == 0)
				જાઓ fail_load;
			જો ((r = sshkey_parse_private_fileblob(keyblob, pass,
			    &ખાનગી, &comment)) == 0)
				તોડો;
			નહીંતર જો (r != SSH_ERR_ચાવી_WRONG_PASSPHRASE) {
				fprintf(stderr,
				    "Error loading key \"%s\": %s\n",
				    filename, ssh_err(r));
 fail_load:
				clear_pass();
				sshbuf_free(keyblob);
				પાછા -1;
			}
			clear_pass();
			snprintf(સંદેશ, કદ સંદેશ,
			    "Bad passphrase, try again for %s%s: ", filename,
			    confirm ? " (will confirm each use)" : "");
		}
	}
	જો (comment == ખાલી || *comment == '\0')
		comment = xstrdup(filename);
	sshbuf_free(keyblob);

	જો (sshkey_is_sk(ખાનગી)) {
		જો (skprovider == ખાલી) {
			fprintf(stderr, "Cannot load FIDO key %s "
			    "without provider\n", filename);
			જાઓ out;
		}
	} નહીંતર {
		/* Don't send provider constraint for other keys */
		skprovider = ખાલી;
	}

	જો (!cert_only) {
		જો ((r = ssh_add_identity_constrained(agent_fd, ખાનગી,
		    comment, lifetime, confirm, skprovider,
		    dest_constraints, ndest_constraints)) == 0) {
			ret = 0;
			જો (!qflag) {
				fprintf(stderr, "Identity added: %s (%s)\n",
				    filename, comment);
				જો (lifetime != 0) {
					fprintf(stderr, "Lifetime set to %s\n",
					    fmt_timeframe((time_t)lifetime));
				}
				જો (confirm != 0) {
					fprintf(stderr, "The user must confirm "
					    "each use of the key\n");
				}
			}
		} નહીંતર {
			fprintf(stderr, "Could not add identity \"%s\": %s\n",
			    filename, ssh_err(r));
		}
	}

	/* Skip trying to load the cert if requested */
	જો (ચાવી_only)
		જાઓ out;

	/* Now try to add the certificate flavour too */
	xasprintf(&certpath, "%s-cert.pub", filename);
	જો ((r = sshkey_load_public(certpath, &cert, ખાલી)) != 0) {
		જો (r != SSH_ERR_SYSTEM_ERROR || errno != ENOENT)
			error_r(r, "Failed to load certificate \"%s\"",
			    certpath);
		જાઓ out;
	}

	જો (!sshkey_equal_public(cert, ખાનગી)) {
		error("Certificate %s does not match private key %s",
		    certpath, filename);
		જાઓ out;
	}

	cert_lifetime = lifetime;
	જો (!Nflag &&
	    (cert_lifetime = check_cert_lifetime(cert, cert_lifetime)) == -1) {
		logit("Certificate %s has already expired; ignored", certpath);
		જાઓ out;
	}

	/* Graft with private bits */
	જો ((r = sshkey_to_certified(ખાનગી)) != 0) {
		error_fr(r, "sshkey_to_certified");
		જાઓ out;
	}
	જો ((r = sshkey_cert_copy(cert, ખાનગી)) != 0) {
		error_fr(r, "sshkey_cert_copy");
		જાઓ out;
	}
	/* send to agent */
	જો ((r = ssh_add_identity_constrained(agent_fd, ખાનગી, comment,
	    cert_lifetime, confirm, skprovider,
	    dest_constraints, ndest_constraints)) != 0) {
		error_r(r, "Certificate %s (%s) add failed", certpath,
		    ખાનગી->cert->ચાવી_id);
		જાઓ out;
	}
	/* success */
	જો (!qflag) {
		fprintf(stderr, "Certificate added: %s (%s)\n", certpath,
		    ખાનગી->cert->ચાવી_id);
		જો (cert_lifetime != 0) {
			fprintf(stderr, "Lifetime set to %s\n",
			    fmt_timeframe((time_t)cert_lifetime));
		}
		જો (confirm != 0) {
			fprintf(stderr, "The user must confirm each use "
			    "of the key\n");
		}
	}

 out:
	મુક્ત(certpath);
	મુક્ત(comment);
	sshkey_free(cert);
	sshkey_free(ખાનગી);

	પાછા ret;
}

સ્થિર પૂર્ણાંક
update_card(પૂર્ણાંક agent_fd, પૂર્ણાંક add, અચલ અક્ષર *id, પૂર્ણાંક qflag, પૂર્ણાંક no_pin,
    પૂર્ણાંક ચાવી_only, પૂર્ણાંક cert_only,
    સંરચના dest_constraint **dest_constraints, size_t ndest_constraints,
    સંરચના sshkey **certs, size_t ncerts)
{
	અક્ષર *pin = ખાલી;
	પૂર્ણાંક r, ret = -1;

	જો (ચાવી_only)
		ncerts = 0;

	જો (add && !no_pin) {
		જો ((pin = read_passphrase("Enter passphrase for PKCS#11: ",
		    RP_ALLOW_STDIN)) == ખાલી)
			પાછા -1;
	}

	જો ((r = ssh_update_card(agent_fd, add, id, pin == ખાલી ? "" : pin,
	    lifetime, confirm, dest_constraints, ndest_constraints,
	    cert_only, certs, ncerts)) == 0) {
		ret = 0;
		જો (!qflag) {
			fprintf(stderr, "Card %s: %s\n",
			    add ? "added" : "removed", id);
		}
	} નહીંતર {
		fprintf(stderr, "Could not %s card \"%s\": %s\n",
		    add ? "add" : "remove", id, ssh_err(r));
		ret = -1;
	}
	મુક્ત(pin);
	પાછા ret;
}

સ્થિર પૂર્ણાંક
test_ચાવી(પૂર્ણાંક agent_fd, અચલ અક્ષર *filename)
{
	સંરચના sshkey *ચાવી = ખાલી;
	u_char *sig = ખાલી;
	અચલ અક્ષર *alg = ખાલી;
	size_t slen = 0;
	પૂર્ણાંક r, ret = -1;
	અક્ષર data[1024];

	જો ((r = sshkey_load_public(filename, &ચાવી, ખાલી)) != 0) {
		error_r(r, "Couldn't read public key %s", filename);
		પાછા -1;
	}
	જો (sshkey_type_plain(ચાવી->type) == ચાવી_RSA)
		alg = "rsa-sha2-256";
	arc4random_buf(data, કદ(data));
	જો ((r = ssh_agent_sign(agent_fd, ચાવી, &sig, &slen, data, કદ(data),
	    alg, 0)) != 0) {
		error_r(r, "Agent signature failed for %s", filename);
		જાઓ done;
	}
	જો ((r = sshkey_verify(ચાવી, sig, slen, data, કદ(data),
	    alg, 0, ખાલી)) != 0) {
		error_r(r, "Signature verification failed for %s", filename);
		જાઓ done;
	}
	/* success */
	ret = 0;
 done:
	મુક્ત(sig);
	sshkey_free(ચાવી);
	પાછા ret;
}

સ્થિર પૂર્ણાંક
list_identities(પૂર્ણાંક agent_fd, પૂર્ણાંક do_fp)
{
	અક્ષર *fp;
	પૂર્ણાંક r;
	સંરચના ssh_identitylist *idlist;
	size_t i;

	જો ((r = ssh_fetch_identitylist(agent_fd, &idlist)) != 0) {
		જો (r != SSH_ERR_AGENT_NO_IDENTITIES)
			fprintf(stderr, "error fetching identities: %s\n",
			    ssh_err(r));
		નહીંતર
			printf("The agent has no identities.\n");
		પાછા -1;
	}
	માટે (i = 0; i < idlist->nkeys; i++) {
		જો (do_fp) {
			fp = sshkey_fingerprint(idlist->ચાવીઓ[i],
			    fingerprint_hash, SSH_FP_DEFAULT);
			printf("%u %s %s (%s)\n", sshkey_size(idlist->ચાવીઓ[i]),
			    fp == ખાલી ? "(null)" : fp, idlist->comments[i],
			    sshkey_type(idlist->ચાવીઓ[i]));
			મુક્ત(fp);
		} નહીંતર {
			જો ((r = sshkey_write(idlist->ચાવીઓ[i], stdout)) != 0) {
				fprintf(stderr, "sshkey_write: %s\n",
				    ssh_err(r));
				ચાલુ;
			}
			fprintf(stdout, " %s\n", idlist->comments[i]);
		}
	}
	ssh_free_identitylist(idlist);
	પાછા 0;
}

સ્થિર પૂર્ણાંક
lock_agent(પૂર્ણાંક agent_fd, પૂર્ણાંક lock)
{
	અક્ષર prompt[100], *p1, *p2;
	પૂર્ણાંક r, passok = 1, ret = -1;

	strlcpy(prompt, "Enter lock password: ", કદ(prompt));
	p1 = read_passphrase(prompt, RP_ALLOW_STDIN);
	જો (lock) {
		strlcpy(prompt, "Again: ", કદ prompt);
		p2 = read_passphrase(prompt, RP_ALLOW_STDIN);
		જો (strcmp(p1, p2) != 0) {
			fprintf(stderr, "Passwords do not match.\n");
			passok = 0;
		}
		freezero(p2, strlen(p2));
	}
	જો (passok) {
		જો ((r = ssh_lock_agent(agent_fd, lock, p1)) == 0) {
			fprintf(stderr, "Agent %slocked.\n", lock ? "" : "un");
			ret = 0;
		} નહીંતર {
			fprintf(stderr, "Failed to %slock agent: %s\n",
			    lock ? "" : "un", ssh_err(r));
		}
	}
	freezero(p1, strlen(p1));
	પાછા (ret);
}

સ્થિર પૂર્ણાંક
load_resident_ચાવીઓ(પૂર્ણાંક agent_fd, અચલ અક્ષર *skprovider, પૂર્ણાંક qflag, પૂર્ણાંક no_pin,
    સંરચના dest_constraint **dest_constraints, size_t ndest_constraints)
{
	સંરચના sshsk_resident_ચાવી **srks;
	size_t nsrks, i;
	સંરચના sshkey *ચાવી;
	પૂર્ણાંક r, ok = 0;
	અક્ષર *fp, *pin = ખાલી;

	જો (!no_pin) {
		pin = read_passphrase("Enter PIN for authenticator: ",
		    RP_ALLOW_STDIN);
	}
	જો ((r = sshsk_load_resident(skprovider, ખાલી, pin == ખાલી ? "" : pin,
	    0, &srks, &nsrks)) != 0) {
		error_r(r, "Unable to load resident keys");
		મુક્ત(pin);
		પાછા r;
	}
	મુક્ત(pin);
	માટે (i = 0; i < nsrks; i++) {
		ચાવી = srks[i]->ચાવી;
		જો ((fp = sshkey_fingerprint(ચાવી,
		    fingerprint_hash, SSH_FP_DEFAULT)) == ખાલી)
			fatal_f("sshkey_fingerprint failed");
		જો ((r = ssh_add_identity_constrained(agent_fd, ચાવી,
		    ચાવી->sk_application, lifetime, confirm, skprovider,
		    dest_constraints, ndest_constraints)) != 0) {
			error("Unable to add key %s %s",
			    sshkey_type(ચાવી), fp);
			મુક્ત(fp);
			ok = r;
			ચાલુ;
		}
		જો (ok == 0)
			ok = 1;
		જો (!qflag) {
			fprintf(stderr, "Resident identity added: %s %s\n",
			    sshkey_type(ચાવી), fp);
			જો (lifetime != 0) {
				fprintf(stderr,
				    "Lifetime set to %d seconds\n", lifetime);
			}
			જો (confirm != 0) {
				fprintf(stderr, "The user must confirm "
				    "each use of the key\n");
			}
		}
		મુક્ત(fp);
	}
	sshsk_free_resident_ચાવીઓ(srks, nsrks);
	જો (nsrks == 0)
		પાછા SSH_ERR_ચાવી_NOT_FOUND;
	પાછા ok == 1 ? 0 : ok;
}

સ્થિર પૂર્ણાંક
do_file(પૂર્ણાંક agent_fd, પૂર્ણાંક deleting, પૂર્ણાંક ચાવી_only, પૂર્ણાંક cert_only,
    અક્ષર *file, પૂર્ણાંક qflag, પૂર્ણાંક Nflag, અચલ અક્ષર *skprovider,
    સંરચના dest_constraint **dest_constraints, size_t ndest_constraints)
{
	જો (deleting) {
		જો (delete_file(agent_fd, file, ચાવી_only,
		    cert_only, qflag) == -1)
			પાછા -1;
	} નહીંતર {
		જો (add_file(agent_fd, file, ચાવી_only, cert_only, qflag, Nflag,
		    skprovider, dest_constraints, ndest_constraints) == -1)
			પાછા -1;
	}
	પાછા 0;
}

સ્થિર શૂન્ય
free_dest_constraint_hop(સંરચના dest_constraint_hop *dch)
{
	u_int i;

	જો (dch == ખાલી)
		પાછા;
	મુક્ત(dch->user);
	મુક્ત(dch->hostname);
	માટે (i = 0; i < dch->nkeys; i++)
		sshkey_free(dch->ચાવીઓ[i]);
	મુક્ત(dch->ચાવીઓ);
	મુક્ત(dch->ચાવી_is_ca);
}

સ્થિર શૂન્ય
free_dest_constraints(સંરચના dest_constraint **dcs, size_t ndcs)
{
	size_t i;

	માટે (i = 0; i < ndcs; i++) {
		free_dest_constraint_hop(&dcs[i]->from);
		free_dest_constraint_hop(&dcs[i]->to);
		મુક્ત(dcs[i]);
	}
	મુક્ત(dcs);
}


સ્થિર શૂન્ય
parse_dest_constraint_hop(અચલ અક્ષર *s, સંરચના dest_constraint_hop *dch,
    અક્ષર **hostkey_files)
{
	અક્ષર *user = ખાલી, *host, *os, *path;
	size_t i;
	સંરચના hostkeys *hostkeys;
	અચલ સંરચના hostkey_entry *hke;
	પૂર્ણાંક r, want_ca;

	memset(dch, '\0', કદ(*dch));
	os = xstrdup(s);
	જો ((host = strrchr(os, '@')) == ખાલી)
		host = os;
	નહીંતર {
		*host++ = '\0';
		user = os;
	}
	cleanhostname(host);
	/* Trivial case: username@ (all hosts) */
	જો (*host == '\0') {
		જો (user == ખાલી) {
			fatal("Invalid key destination constraint \"%s\": "
			    "does not specify user or host", s);
		}
		dch->user = xstrdup(user);
		/* other fields left blank */
		મુક્ત(os);
		પાછા;
	}
	જો (hostkey_files == ખાલી)
		fatal_f("no hostkey files");
	/* Otherwise we need to look up the keys for this hostname */
	hostkeys = init_hostkeys();
	માટે (i = 0; hostkey_files[i]; i++) {
		path = tilde_expand_filename(hostkey_files[i], getuid());
		debug2_f("looking up host keys for \"%s\" in %s", host, path);
                load_hostkeys(hostkeys, host, path, 0);
		મુક્ત(path);
	}
	dch->user = user == ખાલી ? ખાલી : xstrdup(user);
	dch->hostname = xstrdup(host);
	માટે (i = 0; i < hostkeys->અંક_entries; i++) {
		hke = hostkeys->entries + i;
		want_ca = hke->marker == MRK_CA;
		જો (hke->marker != MRK_NONE && !want_ca)
			ચાલુ;
		debug3_f("%s%s%s: adding %s %skey from %s:%lu as key %u",
		    user == ખાલી ? "": user, user == ખાલી ? "" : "@",
		    host, sshkey_type(hke->ચાવી), want_ca ? "CA " : "",
		    hke->file, hke->લીટી, dch->nkeys);
		dch->ચાવીઓ = xrecallocarray(dch->ચાવીઓ, dch->nkeys,
		    dch->nkeys + 1, કદ(*dch->ચાવીઓ));
		dch->ચાવી_is_ca = xrecallocarray(dch->ચાવી_is_ca, dch->nkeys,
		    dch->nkeys + 1, કદ(*dch->ચાવી_is_ca));
		જો ((r = sshkey_from_private(hke->ચાવી,
		    &(dch->ચાવીઓ[dch->nkeys]))) != 0)
			fatal_fr(r, "sshkey_from_private");
		dch->ચાવી_is_ca[dch->nkeys] = want_ca;
		dch->nkeys++;
	}
	જો (dch->nkeys == 0)
		fatal("No host keys found for destination \"%s\"", host);
	free_hostkeys(hostkeys);
	મુક્ત(os);
	પાછા;
}

સ્થિર શૂન્ય
parse_dest_constraint(અચલ અક્ષર *s, સંરચના dest_constraint ***dcp,
    size_t *ndcp, અક્ષર **hostkey_files)
{
	સંરચના dest_constraint *dc;
	અક્ષર *os, *cp;

	dc = xcalloc(1, કદ(*dc));
	os = xstrdup(s);
	જો ((cp = strchr(os, '>')) == ખાલી) {
		/* initial hop; no 'from' hop specified */
		parse_dest_constraint_hop(os, &dc->to, hostkey_files);
	} નહીંતર {
		/* two hops specified */
		*(cp++) = '\0';
		parse_dest_constraint_hop(os, &dc->from, hostkey_files);
		parse_dest_constraint_hop(cp, &dc->to, hostkey_files);
		જો (dc->from.user != ખાલી) {
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
	*dcp = xrecallocarray(*dcp, *ndcp, *ndcp + 1, કદ(**dcp));
	(*dcp)[(*ndcp)++] = dc;
	મુક્ત(os);
}


સ્થિર શૂન્ય
usage(શૂન્ય)
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

પૂર્ણાંક
મુખ્ય(પૂર્ણાંક argc, અક્ષર **argv)
{
	બાહ્ય અક્ષર *optarg;
	બાહ્ય પૂર્ણાંક optind;
	પૂર્ણાંક agent_fd = -1;
	અક્ષર *pkcs11provider = ખાલી, *skprovider = ખાલી;
	અક્ષર **dest_constraint_strings = ખાલી, **hostkey_files = ખાલી;
	પૂર્ણાંક r, i, ch, deleting = 0, ret = 0, ચાવી_only = 0, cert_only = 0;
	પૂર્ણાંક do_download = 0, xflag = 0, lflag = 0, Dflag = 0;
	પૂર્ણાંક Qflag = 0, qflag = 0, Tflag = 0, Nflag = 0, no_pin = 0;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_INFO;
	સંરચના sshkey *k, **certs = ખાલી;
	સંરચના dest_constraint **dest_constraints = ખાલી;
	size_t n, ndest_constraints = 0, ncerts = 0;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	__progname = ssh_get_progname(argv[0]);
	seed_rng();

	log_init(__progname, log_level, log_facility, 1);

	setvbuf(stdout, ખાલી, _IOLBF, 0);

	skprovider = getenv("SSH_SK_PROVIDER");

	જ્યારે ((ch = getopt(argc, argv, "vkKlLNPCcdDTxXE:e:h:H:M:m:Qqs:S:t:")) != -1) {
		પસંદગી (ch) {
		સ્થિતિ 'v':
			જો (log_level == SYSLOG_LEVEL_INFO)
				log_level = SYSLOG_LEVEL_DEBUG1;
			નહીંતર જો (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			તોડો;
		સ્થિતિ 'N':
			Nflag = 1;
			તોડો;
		સ્થિતિ 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			જો (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			તોડો;
		સ્થિતિ 'H':
			stringlist_append(&hostkey_files, optarg);
			તોડો;
		સ્થિતિ 'h':
			stringlist_append(&dest_constraint_strings, optarg);
			તોડો;
		સ્થિતિ 'k':
			ચાવી_only = 1;
			તોડો;
		સ્થિતિ 'C':
			cert_only = 1;
			તોડો;
		સ્થિતિ 'K':
			do_download = 1;
			તોડો;
		સ્થિતિ 'l':
		સ્થિતિ 'L':
			જો (lflag != 0)
				fatal("-%c flag already specified", lflag);
			lflag = ch;
			તોડો;
		સ્થિતિ 'x':
		સ્થિતિ 'X':
			જો (xflag != 0)
				fatal("-%c flag already specified", xflag);
			xflag = ch;
			તોડો;
		સ્થિતિ 'c':
			confirm = 1;
			તોડો;
		સ્થિતિ 'm':
		સ્થિતિ 'M':
			/* deprecated */
			તોડો;
		સ્થિતિ 'd':
			deleting = 1;
			તોડો;
		સ્થિતિ 'P':
			no_pin = 1;
			તોડો;
		સ્થિતિ 'D':
			Dflag = 1;
			તોડો;
		સ્થિતિ 's':
			pkcs11provider = optarg;
			તોડો;
		સ્થિતિ 'S':
			skprovider = optarg;
			તોડો;
		સ્થિતિ 'e':
			deleting = 1;
			pkcs11provider = optarg;
			તોડો;
		સ્થિતિ 't':
			જો ((lifetime = convtime(optarg)) == -1 ||
			    lifetime < 0 || (u_long)lifetime > UINT32_MAX) {
				fprintf(stderr, "Invalid lifetime\n");
				ret = 1;
				જાઓ done;
			}
			તોડો;
		સ્થિતિ 'q':
			qflag = 1;
			તોડો;
		સ્થિતિ 'Q':
			Qflag = 1;
			તોડો;
		સ્થિતિ 'T':
			Tflag = 1;
			તોડો;
		મૂળભૂત:
			usage();
			ret = 1;
			જાઓ done;
		}
	}
	log_init(__progname, log_level, log_facility, 1);

	જો ((xflag != 0) + (lflag != 0) + (Dflag != 0) + (Qflag != 0) > 1)
		fatal("Invalid combination of actions");

	/* First, get a connection to the authentication agent. */
	પસંદગી (r = ssh_get_authentication_socket(&agent_fd)) {
	સ્થિતિ 0:
		તોડો;
	સ્થિતિ SSH_ERR_AGENT_NOT_PRESENT:
		fprintf(stderr, "Could not open a connection to your "
		    "authentication agent.\n");
		exit(2);
	મૂળભૂત:
		fprintf(stderr, "Error connecting to agent: %s\n", ssh_err(r));
		exit(2);
	}

	જો (xflag) {
		જો (lock_agent(agent_fd, xflag == 'x' ? 1 : 0) == -1)
			ret = 1;
		જાઓ done;
	} નહીંતર જો (lflag) {
		જો (list_identities(agent_fd, lflag == 'l' ? 1 : 0) == -1)
			ret = 1;
		જાઓ done;
	} નહીંતર જો (Dflag) {
		જો (delete_all(agent_fd, qflag) == -1)
			ret = 1;
		જાઓ done;
	} નહીંતર જો (Qflag) {
		જો (query_exts(agent_fd) == -1)
			ret = 1;
		જાઓ done;
	}

#ifdef ENABLE_SK_INTERNAL
	જો (skprovider == ખાલી)
		skprovider = "internal";
#endif

	જો (hostkey_files == ખાલી) {
		/* use defaults from readconf.c */
		stringlist_append(&hostkey_files, _PATH_SSH_USER_HOSTFILE);
		stringlist_append(&hostkey_files, _PATH_SSH_USER_HOSTFILE2);
		stringlist_append(&hostkey_files, _PATH_SSH_SYSTEM_HOSTFILE);
		stringlist_append(&hostkey_files, _PATH_SSH_SYSTEM_HOSTFILE2);
	}
	જો (dest_constraint_strings != ખાલી) {
		માટે (i = 0; dest_constraint_strings[i] != ખાલી; i++) {
			parse_dest_constraint(dest_constraint_strings[i],
			  &dest_constraints, &ndest_constraints, hostkey_files);
		}
	}

	argc -= optind;
	argv += optind;
	જો (Tflag) {
		જો (argc <= 0)
			fatal("no keys to test");
		માટે (r = i = 0; i < argc; i++)
			r |= test_ચાવી(agent_fd, argv[i]);
		ret = r == 0 ? 0 : 1;
		જાઓ done;
	}
	જો (pkcs11provider != ખાલી) {
		માટે (i = 0; i < argc; i++) {
			જો ((r = sshkey_load_public(argv[i], &k, ખાલી)) != 0)
				fatal_fr(r, "load certificate %s", argv[i]);
			certs = xrecallocarray(certs, ncerts, ncerts + 1,
			    કદ(*certs));
			debug2("%s: %s", argv[i], sshkey_ssh_name(k));
			certs[ncerts++] = k;
		}
		debug2_f("loaded %zu certificates", ncerts);
		જો (update_card(agent_fd, !deleting, pkcs11provider,
		    qflag, no_pin, ચાવી_only, cert_only,
		    dest_constraints, ndest_constraints,
		    certs, ncerts) == -1)
			ret = 1;
		માટે (n = 0; n < ncerts; n++)
			sshkey_free(certs[n]);
		મુક્ત(certs);
		જાઓ done;
	}
	જો (do_download) {
		જો (skprovider == ખાલી)
			fatal("Cannot download keys without provider");
		જો (load_resident_ચાવીઓ(agent_fd, skprovider, qflag, no_pin,
		    dest_constraints, ndest_constraints) != 0)
			ret = 1;
		જાઓ done;
	}
	જો (argc == 0) {
		અક્ષર buf[PATH_MAX];
		સંરચના passwd *pw;
		સંરચના stat st;
		પૂર્ણાંક ગણતરી = 0;

		જો ((pw = getpwuid(getuid())) == ખાલી) {
			fprintf(stderr, "No user found with uid %u\n",
			    (u_int)getuid());
			ret = 1;
			જાઓ done;
		}

		માટે (i = 0; default_files[i]; i++) {
			snprintf(buf, કદ(buf), "%s/%s", pw->pw_dir,
			    default_files[i]);
			જો (stat(buf, &st) == -1)
				ચાલુ;
			જો (do_file(agent_fd, deleting, ચાવી_only, cert_only,
			    buf, qflag, Nflag, skprovider,
			    dest_constraints, ndest_constraints) == -1)
				ret = 1;
			નહીંતર
				ગણતરી++;
		}
		જો (ગણતરી == 0)
			ret = 1;
	} નહીંતર {
		માટે (i = 0; i < argc; i++) {
			જો (do_file(agent_fd, deleting, ચાવી_only, cert_only,
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
	પાછા ret;
}
