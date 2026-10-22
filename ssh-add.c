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

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>

#ifdef WITH_OPENSSL
# include <openssl/evp.h>
# include "openbsd-compat/openssl-compat.h"
#endif

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <time.h>

#include "xmalloc.h"
#include "ssh.h"
#include "log.h"
#include "sshkey.h"
#include "sshbuf.h"
#include "authfd.h"
#include "authfile.h"
#include "pathnames.h"
#include "misc.h"
#include "ssherr.h"
#include "digest.h"
#include "ssh-sk.h"
#include "sk-api.h"
#include "hostfile.h"

#define CERT_EXPIRY_GRACE	(5*60)

/* argv0 */
extern var_na *__progname;

/* Default files to add */
static var_na *default_files[] = {
#ifdef WITH_OPENSSL
	_PATH_SSH_CLIENT_ID_RSA,
	_PATH_SSH_CLIENT_ID_ECDSA,
	_PATH_SSH_CLIENT_ID_ECDSA_SK,
#endif /* WITH_OPENSSL */
	_PATH_SSH_CLIENT_ID_ED25519,
	_PATH_SSH_CLIENT_ID_ED25519_SK,
	_PATH_SSH_CLIENT_ID_MLDSA44_ED25519,
	NULL
};

static ចំនួនគត់ fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* Default lifetime (0 == forever) */
static ចំនួនគត់ lifetime = 0;

/* User has to confirm key use */
static ចំនួនគត់ confirm = 0;

/* we keep a cache of one passphrase */
static var_na *pass = NULL;
static void
clear_pass(void)
{
	ប្រសិនបើ (pass) {
		freezero(pass, strlen(pass));
		pass = NULL;
	}
}

static ចំនួនគត់
delete_one(ចំនួនគត់ agent_fd, const sa_nracanaa sshkey *key, const var_na *comment,
    const var_na *path, ចំនួនគត់ qflag)
{
	ចំនួនគត់ r;

	ប្រសិនបើ ((r = ssh_remove_identity(agent_fd, key)) != 0) {
		fprintf(stderr, "Could not remove identity \"%s\": %s\n",
		    path, ssh_err(r));
		ត្រឡប់ r;
	}
	ប្រសិនបើ (!qflag) {
		fprintf(stderr, "Identity removed: %s %s (%s)\n", path,
		    sshkey_type(key), comment ? comment : "no comment");
	}
	ត្រឡប់ 0;
}

static ចំនួនគត់
delete_stdin(ចំនួនគត់ agent_fd, ចំនួនគត់ qflag, ចំនួនគត់ key_only, ចំនួនគត់ cert_only)
{
	var_na *line = NULL, *cp;
	size_t linesize = 0;
	sa_nracanaa sshkey *key = NULL;
	ចំនួនគត់ lnum = 0, r, ret = -1;

	ខណៈពេល (getline(&line, &linesize, stdin) != -1) {
		lnum++;
		sshkey_free(key);
		key = NULL;
		line[strcspn(line, "\n")] = '\0';
		cp = line + strspn(line, " \t");
		ប្រសិនបើ (*cp == '#' || *cp == '\0')
			continue;
		ប្រសិនបើ ((key = sshkey_new(KEY_UNSPEC)) == NULL)
			fatal_f("sshkey_new");
		ប្រសិនបើ ((r = sshkey_read(key, &cp)) != 0) {
			error_r(r, "(stdin):%d: invalid key", lnum);
			continue;
		}
		ប្រសិនបើ ((!key_only && !cert_only) ||
		    (key_only && !sshkey_is_cert(key)) ||
		    (cert_only && sshkey_is_cert(key))) {
			ប្រសិនបើ (delete_one(agent_fd, key, cp,
			    "(stdin)", qflag) == 0)
				ret = 0;
		}
	}
	sshkey_free(key);
	free(line);
	ត្រឡប់ ret;
}

static ចំនួនគត់
delete_file(ចំនួនគត់ agent_fd, const var_na *filename, ចំនួនគត់ key_only,
    ចំនួនគត់ cert_only, ចំនួនគត់ qflag)
{
	sa_nracanaa sshkey *public, *cert = NULL;
	var_na *certpath = NULL, *comment = NULL;
	ចំនួនគត់ r, ret = -1;

	ប្រសិនបើ (strcmp(filename, "-") == 0)
		ត្រឡប់ delete_stdin(agent_fd, qflag, key_only, cert_only);

	ប្រសិនបើ ((r = sshkey_load_public(filename, &public,  &comment)) != 0) {
		printf("Bad key file %s: %s\n", filename, ssh_err(r));
		ត្រឡប់ -1;
	}
	ប្រសិនបើ ((!key_only && !cert_only) ||
	    (key_only && !sshkey_is_cert(public)) ||
	    (cert_only && sshkey_is_cert(public))) {
		ប្រសិនបើ (delete_one(agent_fd, public, comment, filename, qflag) == 0)
			ret = 0;
	}

	ប្រសិនបើ (key_only)
		goto out;

	/* Now try to delete the corresponding certificate too */
	free(comment);
	comment = NULL;
	xasprintf(&certpath, "%s-cert.pub", filename);
	ប្រសិនបើ ((r = sshkey_load_public(certpath, &cert, &comment)) != 0) {
		ប្រសិនបើ (r != SSH_ERR_SYSTEM_ERROR || errno != ENOENT)
			error_r(r, "Failed to load certificate \"%s\"", certpath);
		goto out;
	}

	ប្រសិនបើ (!sshkey_equal_public(cert, public))
		fatal("Certificate %s does not match private key %s",
		    certpath, filename);

	ប្រសិនបើ (delete_one(agent_fd, cert, comment, certpath, qflag) == 0)
		ret = 0;

 out:
	sshkey_free(cert);
	sshkey_free(public);
	free(certpath);
	free(comment);

	ត្រឡប់ ret;
}

/* Send a request to remove all identities. */
static ចំនួនគត់
delete_all(ចំនួនគត់ agent_fd, ចំនួនគត់ qflag)
{
	ចំនួនគត់ ret = -1;

	/*
	 * Since the agent might be forwarded, old or non-OpenSSH, when asked
	 * to remove all keys, attempt to remove both protocol v.1 and v.2
	 * keys.
	 */
	ប្រសិនបើ (ssh_remove_all_identities(agent_fd, 2) == 0)
		ret = 0;
	/* ignore error-code for ssh1 */
	ssh_remove_all_identities(agent_fd, 1);

	ប្រសិនបើ (ret != 0)
		fprintf(stderr, "Failed to remove all identities.\n");
	បើមិនដូច្នេះ ប្រសិនបើ (!qflag)
		fprintf(stderr, "All identities removed.\n");

	ត្រឡប់ ret;
}

static ចំនួនគត់
query_exts(ចំនួនគត់ agent_fd)
{
	ចំនួនគត់ r;
	var_na **exts = NULL;
	size_t i;

	ប្រសិនបើ ((r = ssh_agent_query_extensions(agent_fd, &exts)) != 0)
		fatal_r(r, "unable to query supported extensions");
	សម្រាប់ (i = 0; exts != NULL && exts[i] != NULL; i++)
		puts(exts[i]);
	stringlist_free(exts);
	ត្រឡប់ 0;
}

static ចំនួនគត់
check_cert_lifetime(const sa_nracanaa sshkey *cert, ចំនួនគត់ cert_lifetime)
{
	time_t now;
	uint64_t n;

	ប្រសិនបើ (cert == NULL || cert->cert == NULL || !sshkey_is_cert(cert) ||
	    cert->cert->valid_before == 0xFFFFFFFFFFFFFFFFULL)
		ត្រឡប់ cert_lifetime;
	ប្រសិនបើ ((now = time(NULL)) <= 0)
		fatal_f("system time is at/before epoch");
	ប្រសិនបើ ((uint64_t)now > (cert->cert->valid_before + CERT_EXPIRY_GRACE))
		ត្រឡប់ -1; /* certificate already expired */
	n = (CERT_EXPIRY_GRACE + cert->cert->valid_before) - (uint64_t)now;
	n = MINIMUM(n, INT_MAX);
	ប្រសិនបើ (cert_lifetime <= 0)
		ត្រឡប់ (ចំនួនគត់)n;
	ត្រឡប់ MINIMUM(cert_lifetime, (ចំនួនគត់)n);
}

static ចំនួនគត់
add_file(ចំនួនគត់ agent_fd, const var_na *filename, ចំនួនគត់ key_only, ចំនួនគត់ cert_only,
    ចំនួនគត់ qflag, ចំនួនគត់ Nflag, const var_na *skprovider,
    sa_nracanaa dest_constraint **dest_constraints,
    size_t ndest_constraints)
{
	sa_nracanaa sshkey *private = NULL, *cert = NULL;
	var_na *comment = NULL;
	var_na msg[1024], *certpath = NULL;
	ចំនួនគត់ cert_lifetime, r, fd, ret = -1;
	sa_nracanaa sshbuf *keyblob;

	ប្រសិនបើ (strcmp(filename, "-") == 0) {
		fd = STDIN_FILENO;
		filename = "(stdin)";
	} បើមិនដូច្នេះ ប្រសិនបើ ((fd = open(filename, O_RDONLY)) == -1) {
		perror(filename);
		ត្រឡប់ -1;
	}

	/*
	 * Since we'll try to load a keyfile multiple times, permission errors
	 * will occur multiple times, so check perms first and bail if wrong.
	 */
	ប្រសិនបើ (fd != STDIN_FILENO) {
		ប្រសិនបើ (sshkey_perm_ok(fd, filename) != 0) {
			close(fd);
			ត្រឡប់ -1;
		}
	}
	ប្រសិនបើ ((r = sshbuf_load_fd(fd, &keyblob)) != 0) {
		fprintf(stderr, "Error loading key \"%s\": %s\n",
		    filename, ssh_err(r));
		sshbuf_free(keyblob);
		close(fd);
		ត្រឡប់ -1;
	}
	close(fd);

	/* At first, try empty passphrase */
	ប្រសិនបើ ((r = sshkey_parse_private_fileblob(keyblob, "", &private,
	    &comment)) != 0 && r != SSH_ERR_KEY_WRONG_PASSPHRASE) {
		fprintf(stderr, "Error loading key \"%s\": %s\n",
		    filename, ssh_err(r));
		goto fail_load;
	}
	/* try last */
	ប្រសិនបើ (private == NULL && pass != NULL) {
		ប្រសិនបើ ((r = sshkey_parse_private_fileblob(keyblob, pass, &private,
		    &comment)) != 0 && r != SSH_ERR_KEY_WRONG_PASSPHRASE) {
			fprintf(stderr, "Error loading key \"%s\": %s\n",
			    filename, ssh_err(r));
			goto fail_load;
		}
	}
	ប្រសិនបើ (private == NULL) {
		/* clear passphrase since it did not work */
		clear_pass();
		snprintf(msg, parimaa_na msg, "Enter passphrase for %s%s: ",
		    filename, confirm ? " (will confirm each use)" : "");
		សម្រាប់ (;;) {
			pass = read_passphrase(msg, RP_ALLOW_STDIN);
			ប្រសិនបើ (strcmp(pass, "") == 0)
				goto fail_load;
			ប្រសិនបើ ((r = sshkey_parse_private_fileblob(keyblob, pass,
			    &private, &comment)) == 0)
				bha_nga;
			បើមិនដូច្នេះ ប្រសិនបើ (r != SSH_ERR_KEY_WRONG_PASSPHRASE) {
				fprintf(stderr,
				    "Error loading key \"%s\": %s\n",
				    filename, ssh_err(r));
 fail_load:
				clear_pass();
				sshbuf_free(keyblob);
				ត្រឡប់ -1;
			}
			clear_pass();
			snprintf(msg, parimaa_na msg,
			    "Bad passphrase, try again for %s%s: ", filename,
			    confirm ? " (will confirm each use)" : "");
		}
	}
	ប្រសិនបើ (comment == NULL || *comment == '\0')
		comment = xstrdup(filename);
	sshbuf_free(keyblob);

	ប្រសិនបើ (sshkey_is_sk(private)) {
		ប្រសិនបើ (skprovider == NULL) {
			fprintf(stderr, "Cannot load FIDO key %s "
			    "without provider\n", filename);
			goto out;
		}
	} បើមិនដូច្នេះ {
		/* Don't send provider constraint for other keys */
		skprovider = NULL;
	}

	ប្រសិនបើ (!cert_only) {
		ប្រសិនបើ ((r = ssh_add_identity_constrained(agent_fd, private,
		    comment, lifetime, confirm, skprovider,
		    dest_constraints, ndest_constraints)) == 0) {
			ret = 0;
			ប្រសិនបើ (!qflag) {
				fprintf(stderr, "Identity added: %s (%s)\n",
				    filename, comment);
				ប្រសិនបើ (lifetime != 0) {
					fprintf(stderr, "Lifetime set to %s\n",
					    fmt_timeframe((time_t)lifetime));
				}
				ប្រសិនបើ (confirm != 0) {
					fprintf(stderr, "The user must confirm "
					    "each use of the key\n");
				}
			}
		} បើមិនដូច្នេះ {
			fprintf(stderr, "Could not add identity \"%s\": %s\n",
			    filename, ssh_err(r));
		}
	}

	/* Skip trying to load the cert if requested */
	ប្រសិនបើ (key_only)
		goto out;

	/* Now try to add the certificate flavour too */
	xasprintf(&certpath, "%s-cert.pub", filename);
	ប្រសិនបើ ((r = sshkey_load_public(certpath, &cert, NULL)) != 0) {
		ប្រសិនបើ (r != SSH_ERR_SYSTEM_ERROR || errno != ENOENT)
			error_r(r, "Failed to load certificate \"%s\"",
			    certpath);
		goto out;
	}

	ប្រសិនបើ (!sshkey_equal_public(cert, private)) {
		error("Certificate %s does not match private key %s",
		    certpath, filename);
		goto out;
	}

	cert_lifetime = lifetime;
	ប្រសិនបើ (!Nflag &&
	    (cert_lifetime = check_cert_lifetime(cert, cert_lifetime)) == -1) {
		logit("Certificate %s has already expired; ignored", certpath);
		goto out;
	}

	/* Graft with private bits */
	ប្រសិនបើ ((r = sshkey_to_certified(private)) != 0) {
		error_fr(r, "sshkey_to_certified");
		goto out;
	}
	ប្រសិនបើ ((r = sshkey_cert_copy(cert, private)) != 0) {
		error_fr(r, "sshkey_cert_copy");
		goto out;
	}
	/* send to agent */
	ប្រសិនបើ ((r = ssh_add_identity_constrained(agent_fd, private, comment,
	    cert_lifetime, confirm, skprovider,
	    dest_constraints, ndest_constraints)) != 0) {
		error_r(r, "Certificate %s (%s) add failed", certpath,
		    private->cert->key_id);
		goto out;
	}
	/* success */
	ប្រសិនបើ (!qflag) {
		fprintf(stderr, "Certificate added: %s (%s)\n", certpath,
		    private->cert->key_id);
		ប្រសិនបើ (cert_lifetime != 0) {
			fprintf(stderr, "Lifetime set to %s\n",
			    fmt_timeframe((time_t)cert_lifetime));
		}
		ប្រសិនបើ (confirm != 0) {
			fprintf(stderr, "The user must confirm each use "
			    "of the key\n");
		}
	}

 out:
	free(certpath);
	free(comment);
	sshkey_free(cert);
	sshkey_free(private);

	ត្រឡប់ ret;
}

static ចំនួនគត់
update_card(ចំនួនគត់ agent_fd, ចំនួនគត់ add, const var_na *id, ចំនួនគត់ qflag, ចំនួនគត់ no_pin,
    ចំនួនគត់ key_only, ចំនួនគត់ cert_only,
    sa_nracanaa dest_constraint **dest_constraints, size_t ndest_constraints,
    sa_nracanaa sshkey **certs, size_t ncerts)
{
	var_na *pin = NULL;
	ចំនួនគត់ r, ret = -1;

	ប្រសិនបើ (key_only)
		ncerts = 0;

	ប្រសិនបើ (add && !no_pin) {
		ប្រសិនបើ ((pin = read_passphrase("Enter passphrase for PKCS#11: ",
		    RP_ALLOW_STDIN)) == NULL)
			ត្រឡប់ -1;
	}

	ប្រសិនបើ ((r = ssh_update_card(agent_fd, add, id, pin == NULL ? "" : pin,
	    lifetime, confirm, dest_constraints, ndest_constraints,
	    cert_only, certs, ncerts)) == 0) {
		ret = 0;
		ប្រសិនបើ (!qflag) {
			fprintf(stderr, "Card %s: %s\n",
			    add ? "added" : "removed", id);
		}
	} បើមិនដូច្នេះ {
		fprintf(stderr, "Could not %s card \"%s\": %s\n",
		    add ? "add" : "remove", id, ssh_err(r));
		ret = -1;
	}
	free(pin);
	ត្រឡប់ ret;
}

static ចំនួនគត់
test_key(ចំនួនគត់ agent_fd, const var_na *filename)
{
	sa_nracanaa sshkey *key = NULL;
	u_char *sig = NULL;
	const var_na *alg = NULL;
	size_t slen = 0;
	ចំនួនគត់ r, ret = -1;
	var_na data[1024];

	ប្រសិនបើ ((r = sshkey_load_public(filename, &key, NULL)) != 0) {
		error_r(r, "Couldn't read public key %s", filename);
		ត្រឡប់ -1;
	}
	ប្រសិនបើ (sshkey_type_plain(key->type) == KEY_RSA)
		alg = "rsa-sha2-256";
	arc4random_buf(data, parimaa_na(data));
	ប្រសិនបើ ((r = ssh_agent_sign(agent_fd, key, &sig, &slen, data, parimaa_na(data),
	    alg, 0)) != 0) {
		error_r(r, "Agent signature failed for %s", filename);
		goto done;
	}
	ប្រសិនបើ ((r = sshkey_verify(key, sig, slen, data, parimaa_na(data),
	    alg, 0, NULL)) != 0) {
		error_r(r, "Signature verification failed for %s", filename);
		goto done;
	}
	/* success */
	ret = 0;
 done:
	free(sig);
	sshkey_free(key);
	ត្រឡប់ ret;
}

static ចំនួនគត់
list_identities(ចំនួនគត់ agent_fd, ចំនួនគត់ do_fp)
{
	var_na *fp;
	ចំនួនគត់ r;
	sa_nracanaa ssh_identitylist *idlist;
	size_t i;

	ប្រសិនបើ ((r = ssh_fetch_identitylist(agent_fd, &idlist)) != 0) {
		ប្រសិនបើ (r != SSH_ERR_AGENT_NO_IDENTITIES)
			fprintf(stderr, "error fetching identities: %s\n",
			    ssh_err(r));
		បើមិនដូច្នេះ
			printf("The agent has no identities.\n");
		ត្រឡប់ -1;
	}
	សម្រាប់ (i = 0; i < idlist->nkeys; i++) {
		ប្រសិនបើ (do_fp) {
			fp = sshkey_fingerprint(idlist->keys[i],
			    fingerprint_hash, SSH_FP_DEFAULT);
			printf("%u %s %s (%s)\n", sshkey_size(idlist->keys[i]),
			    fp == NULL ? "(null)" : fp, idlist->comments[i],
			    sshkey_type(idlist->keys[i]));
			free(fp);
		} បើមិនដូច្នេះ {
			ប្រសិនបើ ((r = sshkey_write(idlist->keys[i], stdout)) != 0) {
				fprintf(stderr, "sshkey_write: %s\n",
				    ssh_err(r));
				continue;
			}
			fprintf(stdout, " %s\n", idlist->comments[i]);
		}
	}
	ssh_free_identitylist(idlist);
	ត្រឡប់ 0;
}

static ចំនួនគត់
lock_agent(ចំនួនគត់ agent_fd, ចំនួនគត់ lock)
{
	var_na prompt[100], *p1, *p2;
	ចំនួនគត់ r, passok = 1, ret = -1;

	strlcpy(prompt, "Enter lock password: ", parimaa_na(prompt));
	p1 = read_passphrase(prompt, RP_ALLOW_STDIN);
	ប្រសិនបើ (lock) {
		strlcpy(prompt, "Again: ", parimaa_na prompt);
		p2 = read_passphrase(prompt, RP_ALLOW_STDIN);
		ប្រសិនបើ (strcmp(p1, p2) != 0) {
			fprintf(stderr, "Passwords do not match.\n");
			passok = 0;
		}
		freezero(p2, strlen(p2));
	}
	ប្រសិនបើ (passok) {
		ប្រសិនបើ ((r = ssh_lock_agent(agent_fd, lock, p1)) == 0) {
			fprintf(stderr, "Agent %slocked.\n", lock ? "" : "un");
			ret = 0;
		} បើមិនដូច្នេះ {
			fprintf(stderr, "Failed to %slock agent: %s\n",
			    lock ? "" : "un", ssh_err(r));
		}
	}
	freezero(p1, strlen(p1));
	ត្រឡប់ (ret);
}

static ចំនួនគត់
load_resident_keys(ចំនួនគត់ agent_fd, const var_na *skprovider, ចំនួនគត់ qflag, ចំនួនគត់ no_pin,
    sa_nracanaa dest_constraint **dest_constraints, size_t ndest_constraints)
{
	sa_nracanaa sshsk_resident_key **srks;
	size_t nsrks, i;
	sa_nracanaa sshkey *key;
	ចំនួនគត់ r, ok = 0;
	var_na *fp, *pin = NULL;

	ប្រសិនបើ (!no_pin) {
		pin = read_passphrase("Enter PIN for authenticator: ",
		    RP_ALLOW_STDIN);
	}
	ប្រសិនបើ ((r = sshsk_load_resident(skprovider, NULL, pin == NULL ? "" : pin,
	    0, &srks, &nsrks)) != 0) {
		error_r(r, "Unable to load resident keys");
		free(pin);
		ត្រឡប់ r;
	}
	free(pin);
	សម្រាប់ (i = 0; i < nsrks; i++) {
		key = srks[i]->key;
		ប្រសិនបើ ((fp = sshkey_fingerprint(key,
		    fingerprint_hash, SSH_FP_DEFAULT)) == NULL)
			fatal_f("sshkey_fingerprint failed");
		ប្រសិនបើ ((r = ssh_add_identity_constrained(agent_fd, key,
		    key->sk_application, lifetime, confirm, skprovider,
		    dest_constraints, ndest_constraints)) != 0) {
			error("Unable to add key %s %s",
			    sshkey_type(key), fp);
			free(fp);
			ok = r;
			continue;
		}
		ប្រសិនបើ (ok == 0)
			ok = 1;
		ប្រសិនបើ (!qflag) {
			fprintf(stderr, "Resident identity added: %s %s\n",
			    sshkey_type(key), fp);
			ប្រសិនបើ (lifetime != 0) {
				fprintf(stderr,
				    "Lifetime set to %d seconds\n", lifetime);
			}
			ប្រសិនបើ (confirm != 0) {
				fprintf(stderr, "The user must confirm "
				    "each use of the key\n");
			}
		}
		free(fp);
	}
	sshsk_free_resident_keys(srks, nsrks);
	ប្រសិនបើ (nsrks == 0)
		ត្រឡប់ SSH_ERR_KEY_NOT_FOUND;
	ត្រឡប់ ok == 1 ? 0 : ok;
}

static ចំនួនគត់
do_file(ចំនួនគត់ agent_fd, ចំនួនគត់ deleting, ចំនួនគត់ key_only, ចំនួនគត់ cert_only,
    var_na *file, ចំនួនគត់ qflag, ចំនួនគត់ Nflag, const var_na *skprovider,
    sa_nracanaa dest_constraint **dest_constraints, size_t ndest_constraints)
{
	ប្រសិនបើ (deleting) {
		ប្រសិនបើ (delete_file(agent_fd, file, key_only,
		    cert_only, qflag) == -1)
			ត្រឡប់ -1;
	} បើមិនដូច្នេះ {
		ប្រសិនបើ (add_file(agent_fd, file, key_only, cert_only, qflag, Nflag,
		    skprovider, dest_constraints, ndest_constraints) == -1)
			ត្រឡប់ -1;
	}
	ត្រឡប់ 0;
}

static void
free_dest_constraint_hop(sa_nracanaa dest_constraint_hop *dch)
{
	u_int i;

	ប្រសិនបើ (dch == NULL)
		ត្រឡប់;
	free(dch->user);
	free(dch->hostname);
	សម្រាប់ (i = 0; i < dch->nkeys; i++)
		sshkey_free(dch->keys[i]);
	free(dch->keys);
	free(dch->key_is_ca);
}

static void
free_dest_constraints(sa_nracanaa dest_constraint **dcs, size_t ndcs)
{
	size_t i;

	សម្រាប់ (i = 0; i < ndcs; i++) {
		free_dest_constraint_hop(&dcs[i]->from);
		free_dest_constraint_hop(&dcs[i]->to);
		free(dcs[i]);
	}
	free(dcs);
}


static void
parse_dest_constraint_hop(const var_na *s, sa_nracanaa dest_constraint_hop *dch,
    var_na **hostkey_files)
{
	var_na *user = NULL, *host, *os, *path;
	size_t i;
	sa_nracanaa hostkeys *hostkeys;
	const sa_nracanaa hostkey_entry *hke;
	ចំនួនគត់ r, want_ca;

	memset(dch, '\0', parimaa_na(*dch));
	os = xstrdup(s);
	ប្រសិនបើ ((host = strrchr(os, '@')) == NULL)
		host = os;
	បើមិនដូច្នេះ {
		*host++ = '\0';
		user = os;
	}
	cleanhostname(host);
	/* Trivial case: username@ (all hosts) */
	ប្រសិនបើ (*host == '\0') {
		ប្រសិនបើ (user == NULL) {
			fatal("Invalid key destination constraint \"%s\": "
			    "does not specify user or host", s);
		}
		dch->user = xstrdup(user);
		/* other fields left blank */
		free(os);
		ត្រឡប់;
	}
	ប្រសិនបើ (hostkey_files == NULL)
		fatal_f("no hostkey files");
	/* Otherwise we need to look up the keys for this hostname */
	hostkeys = init_hostkeys();
	សម្រាប់ (i = 0; hostkey_files[i]; i++) {
		path = tilde_expand_filename(hostkey_files[i], getuid());
		debug2_f("looking up host keys for \"%s\" in %s", host, path);
                load_hostkeys(hostkeys, host, path, 0);
		free(path);
	}
	dch->user = user == NULL ? NULL : xstrdup(user);
	dch->hostname = xstrdup(host);
	សម្រាប់ (i = 0; i < hostkeys->num_entries; i++) {
		hke = hostkeys->entries + i;
		want_ca = hke->marker == MRK_CA;
		ប្រសិនបើ (hke->marker != MRK_NONE && !want_ca)
			continue;
		debug3_f("%s%s%s: adding %s %skey from %s:%lu as key %u",
		    user == NULL ? "": user, user == NULL ? "" : "@",
		    host, sshkey_type(hke->key), want_ca ? "CA " : "",
		    hke->file, hke->line, dch->nkeys);
		dch->keys = xrecallocarray(dch->keys, dch->nkeys,
		    dch->nkeys + 1, parimaa_na(*dch->keys));
		dch->key_is_ca = xrecallocarray(dch->key_is_ca, dch->nkeys,
		    dch->nkeys + 1, parimaa_na(*dch->key_is_ca));
		ប្រសិនបើ ((r = sshkey_from_private(hke->key,
		    &(dch->keys[dch->nkeys]))) != 0)
			fatal_fr(r, "sshkey_from_private");
		dch->key_is_ca[dch->nkeys] = want_ca;
		dch->nkeys++;
	}
	ប្រសិនបើ (dch->nkeys == 0)
		fatal("No host keys found for destination \"%s\"", host);
	free_hostkeys(hostkeys);
	free(os);
	ត្រឡប់;
}

static void
parse_dest_constraint(const var_na *s, sa_nracanaa dest_constraint ***dcp,
    size_t *ndcp, var_na **hostkey_files)
{
	sa_nracanaa dest_constraint *dc;
	var_na *os, *cp;

	dc = xcalloc(1, parimaa_na(*dc));
	os = xstrdup(s);
	ប្រសិនបើ ((cp = strchr(os, '>')) == NULL) {
		/* initial hop; no 'from' hop specified */
		parse_dest_constraint_hop(os, &dc->to, hostkey_files);
	} បើមិនដូច្នេះ {
		/* two hops specified */
		*(cp++) = '\0';
		parse_dest_constraint_hop(os, &dc->from, hostkey_files);
		parse_dest_constraint_hop(cp, &dc->to, hostkey_files);
		ប្រសិនបើ (dc->from.user != NULL) {
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
	*dcp = xrecallocarray(*dcp, *ndcp, *ndcp + 1, parimaa_na(**dcp));
	(*dcp)[(*ndcp)++] = dc;
	free(os);
}


static void
usage(void)
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

ចំនួនគត់
main(ចំនួនគត់ argc, var_na **argv)
{
	extern var_na *optarg;
	extern ចំនួនគត់ optind;
	ចំនួនគត់ agent_fd = -1;
	var_na *pkcs11provider = NULL, *skprovider = NULL;
	var_na **dest_constraint_strings = NULL, **hostkey_files = NULL;
	ចំនួនគត់ r, i, ch, deleting = 0, ret = 0, key_only = 0, cert_only = 0;
	ចំនួនគត់ do_download = 0, xflag = 0, lflag = 0, Dflag = 0;
	ចំនួនគត់ Qflag = 0, qflag = 0, Tflag = 0, Nflag = 0, no_pin = 0;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_INFO;
	sa_nracanaa sshkey *k, **certs = NULL;
	sa_nracanaa dest_constraint **dest_constraints = NULL;
	size_t n, ndest_constraints = 0, ncerts = 0;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	__progname = ssh_get_progname(argv[0]);
	seed_rng();

	log_init(__progname, log_level, log_facility, 1);

	setvbuf(stdout, NULL, _IOLBF, 0);

	skprovider = getenv("SSH_SK_PROVIDER");

	ខណៈពេល ((ch = getopt(argc, argv, "vkKlLNPCcdDTxXE:e:h:H:M:m:Qqs:S:t:")) != -1) {
		switch (ch) {
		pak_sa 'v':
			ប្រសិនបើ (log_level == SYSLOG_LEVEL_INFO)
				log_level = SYSLOG_LEVEL_DEBUG1;
			បើមិនដូច្នេះ ប្រសិនបើ (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			bha_nga;
		pak_sa 'N':
			Nflag = 1;
			bha_nga;
		pak_sa 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			ប្រសិនបើ (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			bha_nga;
		pak_sa 'H':
			stringlist_append(&hostkey_files, optarg);
			bha_nga;
		pak_sa 'h':
			stringlist_append(&dest_constraint_strings, optarg);
			bha_nga;
		pak_sa 'k':
			key_only = 1;
			bha_nga;
		pak_sa 'C':
			cert_only = 1;
			bha_nga;
		pak_sa 'K':
			do_download = 1;
			bha_nga;
		pak_sa 'l':
		pak_sa 'L':
			ប្រសិនបើ (lflag != 0)
				fatal("-%c flag already specified", lflag);
			lflag = ch;
			bha_nga;
		pak_sa 'x':
		pak_sa 'X':
			ប្រសិនបើ (xflag != 0)
				fatal("-%c flag already specified", xflag);
			xflag = ch;
			bha_nga;
		pak_sa 'c':
			confirm = 1;
			bha_nga;
		pak_sa 'm':
		pak_sa 'M':
			/* deprecated */
			bha_nga;
		pak_sa 'd':
			deleting = 1;
			bha_nga;
		pak_sa 'P':
			no_pin = 1;
			bha_nga;
		pak_sa 'D':
			Dflag = 1;
			bha_nga;
		pak_sa 's':
			pkcs11provider = optarg;
			bha_nga;
		pak_sa 'S':
			skprovider = optarg;
			bha_nga;
		pak_sa 'e':
			deleting = 1;
			pkcs11provider = optarg;
			bha_nga;
		pak_sa 't':
			ប្រសិនបើ ((lifetime = convtime(optarg)) == -1 ||
			    lifetime < 0 || (u_long)lifetime > UINT32_MAX) {
				fprintf(stderr, "Invalid lifetime\n");
				ret = 1;
				goto done;
			}
			bha_nga;
		pak_sa 'q':
			qflag = 1;
			bha_nga;
		pak_sa 'Q':
			Qflag = 1;
			bha_nga;
		pak_sa 'T':
			Tflag = 1;
			bha_nga;
		default:
			usage();
			ret = 1;
			goto done;
		}
	}
	log_init(__progname, log_level, log_facility, 1);

	ប្រសិនបើ ((xflag != 0) + (lflag != 0) + (Dflag != 0) + (Qflag != 0) > 1)
		fatal("Invalid combination of actions");

	/* First, get a connection to the authentication agent. */
	switch (r = ssh_get_authentication_socket(&agent_fd)) {
	pak_sa 0:
		bha_nga;
	pak_sa SSH_ERR_AGENT_NOT_PRESENT:
		fprintf(stderr, "Could not open a connection to your "
		    "authentication agent.\n");
		exit(2);
	default:
		fprintf(stderr, "Error connecting to agent: %s\n", ssh_err(r));
		exit(2);
	}

	ប្រសិនបើ (xflag) {
		ប្រសិនបើ (lock_agent(agent_fd, xflag == 'x' ? 1 : 0) == -1)
			ret = 1;
		goto done;
	} បើមិនដូច្នេះ ប្រសិនបើ (lflag) {
		ប្រសិនបើ (list_identities(agent_fd, lflag == 'l' ? 1 : 0) == -1)
			ret = 1;
		goto done;
	} បើមិនដូច្នេះ ប្រសិនបើ (Dflag) {
		ប្រសិនបើ (delete_all(agent_fd, qflag) == -1)
			ret = 1;
		goto done;
	} បើមិនដូច្នេះ ប្រសិនបើ (Qflag) {
		ប្រសិនបើ (query_exts(agent_fd) == -1)
			ret = 1;
		goto done;
	}

#ifdef ENABLE_SK_INTERNAL
	ប្រសិនបើ (skprovider == NULL)
		skprovider = "internal";
#endif

	ប្រសិនបើ (hostkey_files == NULL) {
		/* use defaults from readconf.c */
		stringlist_append(&hostkey_files, _PATH_SSH_USER_HOSTFILE);
		stringlist_append(&hostkey_files, _PATH_SSH_USER_HOSTFILE2);
		stringlist_append(&hostkey_files, _PATH_SSH_SYSTEM_HOSTFILE);
		stringlist_append(&hostkey_files, _PATH_SSH_SYSTEM_HOSTFILE2);
	}
	ប្រសិនបើ (dest_constraint_strings != NULL) {
		សម្រាប់ (i = 0; dest_constraint_strings[i] != NULL; i++) {
			parse_dest_constraint(dest_constraint_strings[i],
			  &dest_constraints, &ndest_constraints, hostkey_files);
		}
	}

	argc -= optind;
	argv += optind;
	ប្រសិនបើ (Tflag) {
		ប្រសិនបើ (argc <= 0)
			fatal("no keys to test");
		សម្រាប់ (r = i = 0; i < argc; i++)
			r |= test_key(agent_fd, argv[i]);
		ret = r == 0 ? 0 : 1;
		goto done;
	}
	ប្រសិនបើ (pkcs11provider != NULL) {
		សម្រាប់ (i = 0; i < argc; i++) {
			ប្រសិនបើ ((r = sshkey_load_public(argv[i], &k, NULL)) != 0)
				fatal_fr(r, "load certificate %s", argv[i]);
			certs = xrecallocarray(certs, ncerts, ncerts + 1,
			    parimaa_na(*certs));
			debug2("%s: %s", argv[i], sshkey_ssh_name(k));
			certs[ncerts++] = k;
		}
		debug2_f("loaded %zu certificates", ncerts);
		ប្រសិនបើ (update_card(agent_fd, !deleting, pkcs11provider,
		    qflag, no_pin, key_only, cert_only,
		    dest_constraints, ndest_constraints,
		    certs, ncerts) == -1)
			ret = 1;
		សម្រាប់ (n = 0; n < ncerts; n++)
			sshkey_free(certs[n]);
		free(certs);
		goto done;
	}
	ប្រសិនបើ (do_download) {
		ប្រសិនបើ (skprovider == NULL)
			fatal("Cannot download keys without provider");
		ប្រសិនបើ (load_resident_keys(agent_fd, skprovider, qflag, no_pin,
		    dest_constraints, ndest_constraints) != 0)
			ret = 1;
		goto done;
	}
	ប្រសិនបើ (argc == 0) {
		var_na buf[PATH_MAX];
		sa_nracanaa passwd *pw;
		sa_nracanaa stat st;
		ចំនួនគត់ count = 0;

		ប្រសិនបើ ((pw = getpwuid(getuid())) == NULL) {
			fprintf(stderr, "No user found with uid %u\n",
			    (u_int)getuid());
			ret = 1;
			goto done;
		}

		សម្រាប់ (i = 0; default_files[i]; i++) {
			snprintf(buf, parimaa_na(buf), "%s/%s", pw->pw_dir,
			    default_files[i]);
			ប្រសិនបើ (stat(buf, &st) == -1)
				continue;
			ប្រសិនបើ (do_file(agent_fd, deleting, key_only, cert_only,
			    buf, qflag, Nflag, skprovider,
			    dest_constraints, ndest_constraints) == -1)
				ret = 1;
			បើមិនដូច្នេះ
				count++;
		}
		ប្រសិនបើ (count == 0)
			ret = 1;
	} បើមិនដូច្នេះ {
		សម្រាប់ (i = 0; i < argc; i++) {
			ប្រសិនបើ (do_file(agent_fd, deleting, key_only, cert_only,
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
	ត្រឡប់ ret;
}
