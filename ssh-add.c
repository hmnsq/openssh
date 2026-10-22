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
extern char *__progname;

/* Default files to add */
static char *default_files[] = {
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

static ціле fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* Default lifetime (0 == forever) */
static ціле lifetime = 0;

/* User has to confirm key use */
static ціле confirm = 0;

/* we keep a cache of one passphrase */
static char *pass = NULL;
static void
clear_pass(void)
{
	якщо (pass) {
		freezero(pass, strlen(pass));
		pass = NULL;
	}
}

static ціле
delete_one(ціле agent_fd, const struct sshkey *key, const char *comment,
    const char *path, ціле qflag)
{
	ціле r;

	якщо ((r = ssh_remove_identity(agent_fd, key)) != 0) {
		fprintf(stderr, "Could not remove identity \"%s\": %s\n",
		    path, ssh_err(r));
		повернути r;
	}
	якщо (!qflag) {
		fprintf(stderr, "Identity removed: %s %s (%s)\n", path,
		    sshkey_type(key), comment ? comment : "no comment");
	}
	повернути 0;
}

static ціле
delete_stdin(ціле agent_fd, ціле qflag, ціле key_only, ціле cert_only)
{
	char *line = NULL, *cp;
	size_t linesize = 0;
	struct sshkey *key = NULL;
	ціле lnum = 0, r, ret = -1;

	поки (getline(&line, &linesize, stdin) != -1) {
		lnum++;
		sshkey_free(key);
		key = NULL;
		line[strcspn(line, "\n")] = '\0';
		cp = line + strspn(line, " \t");
		якщо (*cp == '#' || *cp == '\0')
			continue;
		якщо ((key = sshkey_new(KEY_UNSPEC)) == NULL)
			fatal_f("sshkey_new");
		якщо ((r = sshkey_read(key, &cp)) != 0) {
			error_r(r, "(stdin):%d: invalid key", lnum);
			continue;
		}
		якщо ((!key_only && !cert_only) ||
		    (key_only && !sshkey_is_cert(key)) ||
		    (cert_only && sshkey_is_cert(key))) {
			якщо (delete_one(agent_fd, key, cp,
			    "(stdin)", qflag) == 0)
				ret = 0;
		}
	}
	sshkey_free(key);
	free(line);
	повернути ret;
}

static ціле
delete_file(ціле agent_fd, const char *filename, ціле key_only,
    ціле cert_only, ціле qflag)
{
	struct sshkey *public, *cert = NULL;
	char *certpath = NULL, *comment = NULL;
	ціле r, ret = -1;

	якщо (strcmp(filename, "-") == 0)
		повернути delete_stdin(agent_fd, qflag, key_only, cert_only);

	якщо ((r = sshkey_load_public(filename, &public,  &comment)) != 0) {
		printf("Bad key file %s: %s\n", filename, ssh_err(r));
		повернути -1;
	}
	якщо ((!key_only && !cert_only) ||
	    (key_only && !sshkey_is_cert(public)) ||
	    (cert_only && sshkey_is_cert(public))) {
		якщо (delete_one(agent_fd, public, comment, filename, qflag) == 0)
			ret = 0;
	}

	якщо (key_only)
		goto out;

	/* Now try to delete the corresponding certificate too */
	free(comment);
	comment = NULL;
	xasprintf(&certpath, "%s-cert.pub", filename);
	якщо ((r = sshkey_load_public(certpath, &cert, &comment)) != 0) {
		якщо (r != SSH_ERR_SYSTEM_ERROR || errno != ENOENT)
			error_r(r, "Failed to load certificate \"%s\"", certpath);
		goto out;
	}

	якщо (!sshkey_equal_public(cert, public))
		fatal("Certificate %s does not match private key %s",
		    certpath, filename);

	якщо (delete_one(agent_fd, cert, comment, certpath, qflag) == 0)
		ret = 0;

 out:
	sshkey_free(cert);
	sshkey_free(public);
	free(certpath);
	free(comment);

	повернути ret;
}

/* Send a request to remove all identities. */
static ціле
delete_all(ціле agent_fd, ціле qflag)
{
	ціле ret = -1;

	/*
	 * Since the agent might be forwarded, old or non-OpenSSH, when asked
	 * to remove all keys, attempt to remove both protocol v.1 and v.2
	 * keys.
	 */
	якщо (ssh_remove_all_identities(agent_fd, 2) == 0)
		ret = 0;
	/* ignore error-code for ssh1 */
	ssh_remove_all_identities(agent_fd, 1);

	якщо (ret != 0)
		fprintf(stderr, "Failed to remove all identities.\n");
	інакше якщо (!qflag)
		fprintf(stderr, "All identities removed.\n");

	повернути ret;
}

static ціле
query_exts(ціле agent_fd)
{
	ціле r;
	char **exts = NULL;
	size_t i;

	якщо ((r = ssh_agent_query_extensions(agent_fd, &exts)) != 0)
		fatal_r(r, "unable to query supported extensions");
	для (i = 0; exts != NULL && exts[i] != NULL; i++)
		puts(exts[i]);
	stringlist_free(exts);
	повернути 0;
}

static ціле
check_cert_lifetime(const struct sshkey *cert, ціле cert_lifetime)
{
	time_t now;
	uint64_t n;

	якщо (cert == NULL || cert->cert == NULL || !sshkey_is_cert(cert) ||
	    cert->cert->valid_before == 0xFFFFFFFFFFFFFFFFULL)
		повернути cert_lifetime;
	якщо ((now = time(NULL)) <= 0)
		fatal_f("system time is at/before epoch");
	якщо ((uint64_t)now > (cert->cert->valid_before + CERT_EXPIRY_GRACE))
		повернути -1; /* certificate already expired */
	n = (CERT_EXPIRY_GRACE + cert->cert->valid_before) - (uint64_t)now;
	n = MINIMUM(n, INT_MAX);
	якщо (cert_lifetime <= 0)
		повернути (ціле)n;
	повернути MINIMUM(cert_lifetime, (ціле)n);
}

static ціле
add_file(ціле agent_fd, const char *filename, ціле key_only, ціле cert_only,
    ціле qflag, ціле Nflag, const char *skprovider,
    struct dest_constraint **dest_constraints,
    size_t ndest_constraints)
{
	struct sshkey *private = NULL, *cert = NULL;
	char *comment = NULL;
	char msg[1024], *certpath = NULL;
	ціле cert_lifetime, r, fd, ret = -1;
	struct sshbuf *keyblob;

	якщо (strcmp(filename, "-") == 0) {
		fd = STDIN_FILENO;
		filename = "(stdin)";
	} інакше якщо ((fd = open(filename, O_RDONLY)) == -1) {
		perror(filename);
		повернути -1;
	}

	/*
	 * Since we'll try to load a keyfile multiple times, permission errors
	 * will occur multiple times, so check perms first and bail if wrong.
	 */
	якщо (fd != STDIN_FILENO) {
		якщо (sshkey_perm_ok(fd, filename) != 0) {
			close(fd);
			повернути -1;
		}
	}
	якщо ((r = sshbuf_load_fd(fd, &keyblob)) != 0) {
		fprintf(stderr, "Error loading key \"%s\": %s\n",
		    filename, ssh_err(r));
		sshbuf_free(keyblob);
		close(fd);
		повернути -1;
	}
	close(fd);

	/* At first, try empty passphrase */
	якщо ((r = sshkey_parse_private_fileblob(keyblob, "", &private,
	    &comment)) != 0 && r != SSH_ERR_KEY_WRONG_PASSPHRASE) {
		fprintf(stderr, "Error loading key \"%s\": %s\n",
		    filename, ssh_err(r));
		goto fail_load;
	}
	/* try last */
	якщо (private == NULL && pass != NULL) {
		якщо ((r = sshkey_parse_private_fileblob(keyblob, pass, &private,
		    &comment)) != 0 && r != SSH_ERR_KEY_WRONG_PASSPHRASE) {
			fprintf(stderr, "Error loading key \"%s\": %s\n",
			    filename, ssh_err(r));
			goto fail_load;
		}
	}
	якщо (private == NULL) {
		/* clear passphrase since it did not work */
		clear_pass();
		snprintf(msg, sizeof msg, "Enter passphrase for %s%s: ",
		    filename, confirm ? " (will confirm each use)" : "");
		для (;;) {
			pass = read_passphrase(msg, RP_ALLOW_STDIN);
			якщо (strcmp(pass, "") == 0)
				goto fail_load;
			якщо ((r = sshkey_parse_private_fileblob(keyblob, pass,
			    &private, &comment)) == 0)
				break;
			інакше якщо (r != SSH_ERR_KEY_WRONG_PASSPHRASE) {
				fprintf(stderr,
				    "Error loading key \"%s\": %s\n",
				    filename, ssh_err(r));
 fail_load:
				clear_pass();
				sshbuf_free(keyblob);
				повернути -1;
			}
			clear_pass();
			snprintf(msg, sizeof msg,
			    "Bad passphrase, try again for %s%s: ", filename,
			    confirm ? " (will confirm each use)" : "");
		}
	}
	якщо (comment == NULL || *comment == '\0')
		comment = xstrdup(filename);
	sshbuf_free(keyblob);

	якщо (sshkey_is_sk(private)) {
		якщо (skprovider == NULL) {
			fprintf(stderr, "Cannot load FIDO key %s "
			    "without provider\n", filename);
			goto out;
		}
	} інакше {
		/* Don't send provider constraint for other keys */
		skprovider = NULL;
	}

	якщо (!cert_only) {
		якщо ((r = ssh_add_identity_constrained(agent_fd, private,
		    comment, lifetime, confirm, skprovider,
		    dest_constraints, ndest_constraints)) == 0) {
			ret = 0;
			якщо (!qflag) {
				fprintf(stderr, "Identity added: %s (%s)\n",
				    filename, comment);
				якщо (lifetime != 0) {
					fprintf(stderr, "Lifetime set to %s\n",
					    fmt_timeframe((time_t)lifetime));
				}
				якщо (confirm != 0) {
					fprintf(stderr, "The user must confirm "
					    "each use of the key\n");
				}
			}
		} інакше {
			fprintf(stderr, "Could not add identity \"%s\": %s\n",
			    filename, ssh_err(r));
		}
	}

	/* Skip trying to load the cert if requested */
	якщо (key_only)
		goto out;

	/* Now try to add the certificate flavour too */
	xasprintf(&certpath, "%s-cert.pub", filename);
	якщо ((r = sshkey_load_public(certpath, &cert, NULL)) != 0) {
		якщо (r != SSH_ERR_SYSTEM_ERROR || errno != ENOENT)
			error_r(r, "Failed to load certificate \"%s\"",
			    certpath);
		goto out;
	}

	якщо (!sshkey_equal_public(cert, private)) {
		error("Certificate %s does not match private key %s",
		    certpath, filename);
		goto out;
	}

	cert_lifetime = lifetime;
	якщо (!Nflag &&
	    (cert_lifetime = check_cert_lifetime(cert, cert_lifetime)) == -1) {
		logit("Certificate %s has already expired; ignored", certpath);
		goto out;
	}

	/* Graft with private bits */
	якщо ((r = sshkey_to_certified(private)) != 0) {
		error_fr(r, "sshkey_to_certified");
		goto out;
	}
	якщо ((r = sshkey_cert_copy(cert, private)) != 0) {
		error_fr(r, "sshkey_cert_copy");
		goto out;
	}
	/* send to agent */
	якщо ((r = ssh_add_identity_constrained(agent_fd, private, comment,
	    cert_lifetime, confirm, skprovider,
	    dest_constraints, ndest_constraints)) != 0) {
		error_r(r, "Certificate %s (%s) add failed", certpath,
		    private->cert->key_id);
		goto out;
	}
	/* success */
	якщо (!qflag) {
		fprintf(stderr, "Certificate added: %s (%s)\n", certpath,
		    private->cert->key_id);
		якщо (cert_lifetime != 0) {
			fprintf(stderr, "Lifetime set to %s\n",
			    fmt_timeframe((time_t)cert_lifetime));
		}
		якщо (confirm != 0) {
			fprintf(stderr, "The user must confirm each use "
			    "of the key\n");
		}
	}

 out:
	free(certpath);
	free(comment);
	sshkey_free(cert);
	sshkey_free(private);

	повернути ret;
}

static ціле
update_card(ціле agent_fd, ціле add, const char *id, ціле qflag, ціле no_pin,
    ціле key_only, ціле cert_only,
    struct dest_constraint **dest_constraints, size_t ndest_constraints,
    struct sshkey **certs, size_t ncerts)
{
	char *pin = NULL;
	ціле r, ret = -1;

	якщо (key_only)
		ncerts = 0;

	якщо (add && !no_pin) {
		якщо ((pin = read_passphrase("Enter passphrase for PKCS#11: ",
		    RP_ALLOW_STDIN)) == NULL)
			повернути -1;
	}

	якщо ((r = ssh_update_card(agent_fd, add, id, pin == NULL ? "" : pin,
	    lifetime, confirm, dest_constraints, ndest_constraints,
	    cert_only, certs, ncerts)) == 0) {
		ret = 0;
		якщо (!qflag) {
			fprintf(stderr, "Card %s: %s\n",
			    add ? "added" : "removed", id);
		}
	} інакше {
		fprintf(stderr, "Could not %s card \"%s\": %s\n",
		    add ? "add" : "remove", id, ssh_err(r));
		ret = -1;
	}
	free(pin);
	повернути ret;
}

static ціле
test_key(ціле agent_fd, const char *filename)
{
	struct sshkey *key = NULL;
	u_char *sig = NULL;
	const char *alg = NULL;
	size_t slen = 0;
	ціле r, ret = -1;
	char data[1024];

	якщо ((r = sshkey_load_public(filename, &key, NULL)) != 0) {
		error_r(r, "Couldn't read public key %s", filename);
		повернути -1;
	}
	якщо (sshkey_type_plain(key->type) == KEY_RSA)
		alg = "rsa-sha2-256";
	arc4random_buf(data, sizeof(data));
	якщо ((r = ssh_agent_sign(agent_fd, key, &sig, &slen, data, sizeof(data),
	    alg, 0)) != 0) {
		error_r(r, "Agent signature failed for %s", filename);
		goto done;
	}
	якщо ((r = sshkey_verify(key, sig, slen, data, sizeof(data),
	    alg, 0, NULL)) != 0) {
		error_r(r, "Signature verification failed for %s", filename);
		goto done;
	}
	/* success */
	ret = 0;
 done:
	free(sig);
	sshkey_free(key);
	повернути ret;
}

static ціле
list_identities(ціле agent_fd, ціле do_fp)
{
	char *fp;
	ціле r;
	struct ssh_identitylist *idlist;
	size_t i;

	якщо ((r = ssh_fetch_identitylist(agent_fd, &idlist)) != 0) {
		якщо (r != SSH_ERR_AGENT_NO_IDENTITIES)
			fprintf(stderr, "error fetching identities: %s\n",
			    ssh_err(r));
		інакше
			printf("The agent has no identities.\n");
		повернути -1;
	}
	для (i = 0; i < idlist->nkeys; i++) {
		якщо (do_fp) {
			fp = sshkey_fingerprint(idlist->keys[i],
			    fingerprint_hash, SSH_FP_DEFAULT);
			printf("%u %s %s (%s)\n", sshkey_size(idlist->keys[i]),
			    fp == NULL ? "(null)" : fp, idlist->comments[i],
			    sshkey_type(idlist->keys[i]));
			free(fp);
		} інакше {
			якщо ((r = sshkey_write(idlist->keys[i], stdout)) != 0) {
				fprintf(stderr, "sshkey_write: %s\n",
				    ssh_err(r));
				continue;
			}
			fprintf(stdout, " %s\n", idlist->comments[i]);
		}
	}
	ssh_free_identitylist(idlist);
	повернути 0;
}

static ціле
lock_agent(ціле agent_fd, ціле lock)
{
	char prompt[100], *p1, *p2;
	ціле r, passok = 1, ret = -1;

	strlcpy(prompt, "Enter lock password: ", sizeof(prompt));
	p1 = read_passphrase(prompt, RP_ALLOW_STDIN);
	якщо (lock) {
		strlcpy(prompt, "Again: ", sizeof prompt);
		p2 = read_passphrase(prompt, RP_ALLOW_STDIN);
		якщо (strcmp(p1, p2) != 0) {
			fprintf(stderr, "Passwords do not match.\n");
			passok = 0;
		}
		freezero(p2, strlen(p2));
	}
	якщо (passok) {
		якщо ((r = ssh_lock_agent(agent_fd, lock, p1)) == 0) {
			fprintf(stderr, "Agent %slocked.\n", lock ? "" : "un");
			ret = 0;
		} інакше {
			fprintf(stderr, "Failed to %slock agent: %s\n",
			    lock ? "" : "un", ssh_err(r));
		}
	}
	freezero(p1, strlen(p1));
	повернути (ret);
}

static ціле
load_resident_keys(ціле agent_fd, const char *skprovider, ціле qflag, ціле no_pin,
    struct dest_constraint **dest_constraints, size_t ndest_constraints)
{
	struct sshsk_resident_key **srks;
	size_t nsrks, i;
	struct sshkey *key;
	ціле r, ok = 0;
	char *fp, *pin = NULL;

	якщо (!no_pin) {
		pin = read_passphrase("Enter PIN for authenticator: ",
		    RP_ALLOW_STDIN);
	}
	якщо ((r = sshsk_load_resident(skprovider, NULL, pin == NULL ? "" : pin,
	    0, &srks, &nsrks)) != 0) {
		error_r(r, "Unable to load resident keys");
		free(pin);
		повернути r;
	}
	free(pin);
	для (i = 0; i < nsrks; i++) {
		key = srks[i]->key;
		якщо ((fp = sshkey_fingerprint(key,
		    fingerprint_hash, SSH_FP_DEFAULT)) == NULL)
			fatal_f("sshkey_fingerprint failed");
		якщо ((r = ssh_add_identity_constrained(agent_fd, key,
		    key->sk_application, lifetime, confirm, skprovider,
		    dest_constraints, ndest_constraints)) != 0) {
			error("Unable to add key %s %s",
			    sshkey_type(key), fp);
			free(fp);
			ok = r;
			continue;
		}
		якщо (ok == 0)
			ok = 1;
		якщо (!qflag) {
			fprintf(stderr, "Resident identity added: %s %s\n",
			    sshkey_type(key), fp);
			якщо (lifetime != 0) {
				fprintf(stderr,
				    "Lifetime set to %d seconds\n", lifetime);
			}
			якщо (confirm != 0) {
				fprintf(stderr, "The user must confirm "
				    "each use of the key\n");
			}
		}
		free(fp);
	}
	sshsk_free_resident_keys(srks, nsrks);
	якщо (nsrks == 0)
		повернути SSH_ERR_KEY_NOT_FOUND;
	повернути ok == 1 ? 0 : ok;
}

static ціле
do_file(ціле agent_fd, ціле deleting, ціле key_only, ціле cert_only,
    char *file, ціле qflag, ціле Nflag, const char *skprovider,
    struct dest_constraint **dest_constraints, size_t ndest_constraints)
{
	якщо (deleting) {
		якщо (delete_file(agent_fd, file, key_only,
		    cert_only, qflag) == -1)
			повернути -1;
	} інакше {
		якщо (add_file(agent_fd, file, key_only, cert_only, qflag, Nflag,
		    skprovider, dest_constraints, ndest_constraints) == -1)
			повернути -1;
	}
	повернути 0;
}

static void
free_dest_constraint_hop(struct dest_constraint_hop *dch)
{
	u_int i;

	якщо (dch == NULL)
		повернути;
	free(dch->user);
	free(dch->hostname);
	для (i = 0; i < dch->nkeys; i++)
		sshkey_free(dch->keys[i]);
	free(dch->keys);
	free(dch->key_is_ca);
}

static void
free_dest_constraints(struct dest_constraint **dcs, size_t ndcs)
{
	size_t i;

	для (i = 0; i < ndcs; i++) {
		free_dest_constraint_hop(&dcs[i]->from);
		free_dest_constraint_hop(&dcs[i]->to);
		free(dcs[i]);
	}
	free(dcs);
}


static void
parse_dest_constraint_hop(const char *s, struct dest_constraint_hop *dch,
    char **hostkey_files)
{
	char *user = NULL, *host, *os, *path;
	size_t i;
	struct hostkeys *hostkeys;
	const struct hostkey_entry *hke;
	ціле r, want_ca;

	memset(dch, '\0', sizeof(*dch));
	os = xstrdup(s);
	якщо ((host = strrchr(os, '@')) == NULL)
		host = os;
	інакше {
		*host++ = '\0';
		user = os;
	}
	cleanhostname(host);
	/* Trivial case: username@ (all hosts) */
	якщо (*host == '\0') {
		якщо (user == NULL) {
			fatal("Invalid key destination constraint \"%s\": "
			    "does not specify user or host", s);
		}
		dch->user = xstrdup(user);
		/* other fields left blank */
		free(os);
		повернути;
	}
	якщо (hostkey_files == NULL)
		fatal_f("no hostkey files");
	/* Otherwise we need to look up the keys for this hostname */
	hostkeys = init_hostkeys();
	для (i = 0; hostkey_files[i]; i++) {
		path = tilde_expand_filename(hostkey_files[i], getuid());
		debug2_f("looking up host keys for \"%s\" in %s", host, path);
                load_hostkeys(hostkeys, host, path, 0);
		free(path);
	}
	dch->user = user == NULL ? NULL : xstrdup(user);
	dch->hostname = xstrdup(host);
	для (i = 0; i < hostkeys->num_entries; i++) {
		hke = hostkeys->entries + i;
		want_ca = hke->marker == MRK_CA;
		якщо (hke->marker != MRK_NONE && !want_ca)
			continue;
		debug3_f("%s%s%s: adding %s %skey from %s:%lu as key %u",
		    user == NULL ? "": user, user == NULL ? "" : "@",
		    host, sshkey_type(hke->key), want_ca ? "CA " : "",
		    hke->file, hke->line, dch->nkeys);
		dch->keys = xrecallocarray(dch->keys, dch->nkeys,
		    dch->nkeys + 1, sizeof(*dch->keys));
		dch->key_is_ca = xrecallocarray(dch->key_is_ca, dch->nkeys,
		    dch->nkeys + 1, sizeof(*dch->key_is_ca));
		якщо ((r = sshkey_from_private(hke->key,
		    &(dch->keys[dch->nkeys]))) != 0)
			fatal_fr(r, "sshkey_from_private");
		dch->key_is_ca[dch->nkeys] = want_ca;
		dch->nkeys++;
	}
	якщо (dch->nkeys == 0)
		fatal("No host keys found for destination \"%s\"", host);
	free_hostkeys(hostkeys);
	free(os);
	повернути;
}

static void
parse_dest_constraint(const char *s, struct dest_constraint ***dcp,
    size_t *ndcp, char **hostkey_files)
{
	struct dest_constraint *dc;
	char *os, *cp;

	dc = xcalloc(1, sizeof(*dc));
	os = xstrdup(s);
	якщо ((cp = strchr(os, '>')) == NULL) {
		/* initial hop; no 'from' hop specified */
		parse_dest_constraint_hop(os, &dc->to, hostkey_files);
	} інакше {
		/* two hops specified */
		*(cp++) = '\0';
		parse_dest_constraint_hop(os, &dc->from, hostkey_files);
		parse_dest_constraint_hop(cp, &dc->to, hostkey_files);
		якщо (dc->from.user != NULL) {
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
	*dcp = xrecallocarray(*dcp, *ndcp, *ndcp + 1, sizeof(**dcp));
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

ціле
main(ціле argc, char **argv)
{
	extern char *optarg;
	extern ціле optind;
	ціле agent_fd = -1;
	char *pkcs11provider = NULL, *skprovider = NULL;
	char **dest_constraint_strings = NULL, **hostkey_files = NULL;
	ціле r, i, ch, deleting = 0, ret = 0, key_only = 0, cert_only = 0;
	ціле do_download = 0, xflag = 0, lflag = 0, Dflag = 0;
	ціле Qflag = 0, qflag = 0, Tflag = 0, Nflag = 0, no_pin = 0;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_INFO;
	struct sshkey *k, **certs = NULL;
	struct dest_constraint **dest_constraints = NULL;
	size_t n, ndest_constraints = 0, ncerts = 0;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	__progname = ssh_get_progname(argv[0]);
	seed_rng();

	log_init(__progname, log_level, log_facility, 1);

	setvbuf(stdout, NULL, _IOLBF, 0);

	skprovider = getenv("SSH_SK_PROVIDER");

	поки ((ch = getopt(argc, argv, "vkKlLNPCcdDTxXE:e:h:H:M:m:Qqs:S:t:")) != -1) {
		switch (ch) {
		case 'v':
			якщо (log_level == SYSLOG_LEVEL_INFO)
				log_level = SYSLOG_LEVEL_DEBUG1;
			інакше якщо (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			break;
		case 'N':
			Nflag = 1;
			break;
		case 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			якщо (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			break;
		case 'H':
			stringlist_append(&hostkey_files, optarg);
			break;
		case 'h':
			stringlist_append(&dest_constraint_strings, optarg);
			break;
		case 'k':
			key_only = 1;
			break;
		case 'C':
			cert_only = 1;
			break;
		case 'K':
			do_download = 1;
			break;
		case 'l':
		case 'L':
			якщо (lflag != 0)
				fatal("-%c flag already specified", lflag);
			lflag = ch;
			break;
		case 'x':
		case 'X':
			якщо (xflag != 0)
				fatal("-%c flag already specified", xflag);
			xflag = ch;
			break;
		case 'c':
			confirm = 1;
			break;
		case 'm':
		case 'M':
			/* deprecated */
			break;
		case 'd':
			deleting = 1;
			break;
		case 'P':
			no_pin = 1;
			break;
		case 'D':
			Dflag = 1;
			break;
		case 's':
			pkcs11provider = optarg;
			break;
		case 'S':
			skprovider = optarg;
			break;
		case 'e':
			deleting = 1;
			pkcs11provider = optarg;
			break;
		case 't':
			якщо ((lifetime = convtime(optarg)) == -1 ||
			    lifetime < 0 || (u_long)lifetime > UINT32_MAX) {
				fprintf(stderr, "Invalid lifetime\n");
				ret = 1;
				goto done;
			}
			break;
		case 'q':
			qflag = 1;
			break;
		case 'Q':
			Qflag = 1;
			break;
		case 'T':
			Tflag = 1;
			break;
		default:
			usage();
			ret = 1;
			goto done;
		}
	}
	log_init(__progname, log_level, log_facility, 1);

	якщо ((xflag != 0) + (lflag != 0) + (Dflag != 0) + (Qflag != 0) > 1)
		fatal("Invalid combination of actions");

	/* First, get a connection to the authentication agent. */
	switch (r = ssh_get_authentication_socket(&agent_fd)) {
	case 0:
		break;
	case SSH_ERR_AGENT_NOT_PRESENT:
		fprintf(stderr, "Could not open a connection to your "
		    "authentication agent.\n");
		exit(2);
	default:
		fprintf(stderr, "Error connecting to agent: %s\n", ssh_err(r));
		exit(2);
	}

	якщо (xflag) {
		якщо (lock_agent(agent_fd, xflag == 'x' ? 1 : 0) == -1)
			ret = 1;
		goto done;
	} інакше якщо (lflag) {
		якщо (list_identities(agent_fd, lflag == 'l' ? 1 : 0) == -1)
			ret = 1;
		goto done;
	} інакше якщо (Dflag) {
		якщо (delete_all(agent_fd, qflag) == -1)
			ret = 1;
		goto done;
	} інакше якщо (Qflag) {
		якщо (query_exts(agent_fd) == -1)
			ret = 1;
		goto done;
	}

#ifdef ENABLE_SK_INTERNAL
	якщо (skprovider == NULL)
		skprovider = "internal";
#endif

	якщо (hostkey_files == NULL) {
		/* use defaults from readconf.c */
		stringlist_append(&hostkey_files, _PATH_SSH_USER_HOSTFILE);
		stringlist_append(&hostkey_files, _PATH_SSH_USER_HOSTFILE2);
		stringlist_append(&hostkey_files, _PATH_SSH_SYSTEM_HOSTFILE);
		stringlist_append(&hostkey_files, _PATH_SSH_SYSTEM_HOSTFILE2);
	}
	якщо (dest_constraint_strings != NULL) {
		для (i = 0; dest_constraint_strings[i] != NULL; i++) {
			parse_dest_constraint(dest_constraint_strings[i],
			  &dest_constraints, &ndest_constraints, hostkey_files);
		}
	}

	argc -= optind;
	argv += optind;
	якщо (Tflag) {
		якщо (argc <= 0)
			fatal("no keys to test");
		для (r = i = 0; i < argc; i++)
			r |= test_key(agent_fd, argv[i]);
		ret = r == 0 ? 0 : 1;
		goto done;
	}
	якщо (pkcs11provider != NULL) {
		для (i = 0; i < argc; i++) {
			якщо ((r = sshkey_load_public(argv[i], &k, NULL)) != 0)
				fatal_fr(r, "load certificate %s", argv[i]);
			certs = xrecallocarray(certs, ncerts, ncerts + 1,
			    sizeof(*certs));
			debug2("%s: %s", argv[i], sshkey_ssh_name(k));
			certs[ncerts++] = k;
		}
		debug2_f("loaded %zu certificates", ncerts);
		якщо (update_card(agent_fd, !deleting, pkcs11provider,
		    qflag, no_pin, key_only, cert_only,
		    dest_constraints, ndest_constraints,
		    certs, ncerts) == -1)
			ret = 1;
		для (n = 0; n < ncerts; n++)
			sshkey_free(certs[n]);
		free(certs);
		goto done;
	}
	якщо (do_download) {
		якщо (skprovider == NULL)
			fatal("Cannot download keys without provider");
		якщо (load_resident_keys(agent_fd, skprovider, qflag, no_pin,
		    dest_constraints, ndest_constraints) != 0)
			ret = 1;
		goto done;
	}
	якщо (argc == 0) {
		char buf[PATH_MAX];
		struct passwd *pw;
		struct stat st;
		ціле count = 0;

		якщо ((pw = getpwuid(getuid())) == NULL) {
			fprintf(stderr, "No user found with uid %u\n",
			    (u_int)getuid());
			ret = 1;
			goto done;
		}

		для (i = 0; default_files[i]; i++) {
			snprintf(buf, sizeof(buf), "%s/%s", pw->pw_dir,
			    default_files[i]);
			якщо (stat(buf, &st) == -1)
				continue;
			якщо (do_file(agent_fd, deleting, key_only, cert_only,
			    buf, qflag, Nflag, skprovider,
			    dest_constraints, ndest_constraints) == -1)
				ret = 1;
			інакше
				count++;
		}
		якщо (count == 0)
			ret = 1;
	} інакше {
		для (i = 0; i < argc; i++) {
			якщо (do_file(agent_fd, deleting, key_only, cert_only,
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
	повернути ret;
}
