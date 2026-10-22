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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/stat.h>

#ifdef WITH_OPENSSL
# include <openssl/evp.h>
# include "openbsd-compat/openssl-compat.h"
#endif

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <fcntl.h>
#அந்தர்பாவ <pwd.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <limits.h>
#அந்தர்பாவ <time.h>

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "ssh.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "authfd.h"
#அந்தர்பாவ "authfile.h"
#அந்தர்பாவ "pathnames.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "digest.h"
#அந்தர்பாவ "ssh-sk.h"
#அந்தர்பாவ "sk-api.h"
#அந்தர்பாவ "hostfile.h"

#define CERT_EXPIRY_GRACE	(5*60)

/* argv0 */
வெளி எழுத்து *__progname;

/* Default files to add */
நிலையான எழுத்து *default_files[] = {
#ifdef WITH_OPENSSL
	_PATH_SSH_CLIENT_ID_RSA,
	_PATH_SSH_CLIENT_ID_ECDSA,
	_PATH_SSH_CLIENT_ID_ECDSA_SK,
#endif /* WITH_OPENSSL */
	_PATH_SSH_CLIENT_ID_ED25519,
	_PATH_SSH_CLIENT_ID_ED25519_SK,
	_PATH_SSH_CLIENT_ID_MLDSA44_ED25519,
	வெற்று
};

நிலையான முழு fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* Default lifetime (0 == forever) */
நிலையான முழு lifetime = 0;

/* User has to confirm key use */
நிலையான முழு confirm = 0;

/* we keep a cache of one passphrase */
நிலையான எழுத்து *pass = வெற்று;
நிலையான வெறுமை
clear_pass(வெறுமை)
{
	எனில் (pass) {
		freezero(pass, strlen(pass));
		pass = வெற்று;
	}
}

நிலையான முழு
delete_one(முழு agent_fd, மாறிலி கட்டமைப்பு sshkey *சாவி, மாறிலி எழுத்து *comment,
    மாறிலி எழுத்து *path, முழு qflag)
{
	முழு r;

	எனில் ((r = ssh_remove_identity(agent_fd, சாவி)) != 0) {
		fprintf(stderr, "Could not remove identity \"%s\": %s\n",
		    path, ssh_err(r));
		திரும்பு r;
	}
	எனில் (!qflag) {
		fprintf(stderr, "Identity removed: %s %s (%s)\n", path,
		    sshkey_type(சாவி), comment ? comment : "no comment");
	}
	திரும்பு 0;
}

நிலையான முழு
delete_stdin(முழு agent_fd, முழு qflag, முழு சாவி_only, முழு cert_only)
{
	எழுத்து *வரி = வெற்று, *cp;
	size_t linesize = 0;
	கட்டமைப்பு sshkey *சாவி = வெற்று;
	முழு lnum = 0, r, ret = -1;

	போது (getline(&வரி, &linesize, stdin) != -1) {
		lnum++;
		sshkey_free(சாவி);
		சாவி = வெற்று;
		வரி[strcspn(வரி, "\n")] = '\0';
		cp = வரி + strspn(வரி, " \t");
		எனில் (*cp == '#' || *cp == '\0')
			தொடர்;
		எனில் ((சாவி = sshkey_new(சாவி_UNSPEC)) == வெற்று)
			fatal_f("sshkey_new");
		எனில் ((r = sshkey_read(சாவி, &cp)) != 0) {
			error_r(r, "(stdin):%d: invalid key", lnum);
			தொடர்;
		}
		எனில் ((!சாவி_only && !cert_only) ||
		    (சாவி_only && !sshkey_is_cert(சாவி)) ||
		    (cert_only && sshkey_is_cert(சாவி))) {
			எனில் (delete_one(agent_fd, சாவி, cp,
			    "(stdin)", qflag) == 0)
				ret = 0;
		}
	}
	sshkey_free(சாவி);
	விடுவி(வரி);
	திரும்பு ret;
}

நிலையான முழு
delete_file(முழு agent_fd, மாறிலி எழுத்து *filename, முழு சாவி_only,
    முழு cert_only, முழு qflag)
{
	கட்டமைப்பு sshkey *பொது, *cert = வெற்று;
	எழுத்து *certpath = வெற்று, *comment = வெற்று;
	முழு r, ret = -1;

	எனில் (strcmp(filename, "-") == 0)
		திரும்பு delete_stdin(agent_fd, qflag, சாவி_only, cert_only);

	எனில் ((r = sshkey_load_public(filename, &பொது,  &comment)) != 0) {
		printf("Bad key file %s: %s\n", filename, ssh_err(r));
		திரும்பு -1;
	}
	எனில் ((!சாவி_only && !cert_only) ||
	    (சாவி_only && !sshkey_is_cert(பொது)) ||
	    (cert_only && sshkey_is_cert(பொது))) {
		எனில் (delete_one(agent_fd, பொது, comment, filename, qflag) == 0)
			ret = 0;
	}

	எனில் (சாவி_only)
		செல் out;

	/* Now try to delete the corresponding certificate too */
	விடுவி(comment);
	comment = வெற்று;
	xasprintf(&certpath, "%s-cert.pub", filename);
	எனில் ((r = sshkey_load_public(certpath, &cert, &comment)) != 0) {
		எனில் (r != SSH_ERR_SYSTEM_ERROR || errno != ENOENT)
			error_r(r, "Failed to load certificate \"%s\"", certpath);
		செல் out;
	}

	எனில் (!sshkey_equal_public(cert, பொது))
		fatal("Certificate %s does not match private key %s",
		    certpath, filename);

	எனில் (delete_one(agent_fd, cert, comment, certpath, qflag) == 0)
		ret = 0;

 out:
	sshkey_free(cert);
	sshkey_free(பொது);
	விடுவி(certpath);
	விடுவி(comment);

	திரும்பு ret;
}

/* Send a request to remove all identities. */
நிலையான முழு
delete_all(முழு agent_fd, முழு qflag)
{
	முழு ret = -1;

	/*
	 * Since the agent might be forwarded, old or non-OpenSSH, when asked
	 * to remove all keys, attempt to remove both protocol v.1 and v.2
	 * keys.
	 */
	எனில் (ssh_remove_all_identities(agent_fd, 2) == 0)
		ret = 0;
	/* ignore error-code for ssh1 */
	ssh_remove_all_identities(agent_fd, 1);

	எனில் (ret != 0)
		fprintf(stderr, "Failed to remove all identities.\n");
	இல்லையெனில் எனில் (!qflag)
		fprintf(stderr, "All identities removed.\n");

	திரும்பு ret;
}

நிலையான முழு
query_exts(முழு agent_fd)
{
	முழு r;
	எழுத்து **exts = வெற்று;
	size_t i;

	எனில் ((r = ssh_agent_query_extensions(agent_fd, &exts)) != 0)
		fatal_r(r, "unable to query supported extensions");
	க்கு (i = 0; exts != வெற்று && exts[i] != வெற்று; i++)
		puts(exts[i]);
	stringlist_free(exts);
	திரும்பு 0;
}

நிலையான முழு
check_cert_lifetime(மாறிலி கட்டமைப்பு sshkey *cert, முழு cert_lifetime)
{
	time_t now;
	uint64_t n;

	எனில் (cert == வெற்று || cert->cert == வெற்று || !sshkey_is_cert(cert) ||
	    cert->cert->valid_before == 0xFFFFFFFFFFFFFFFFULL)
		திரும்பு cert_lifetime;
	எனில் ((now = time(வெற்று)) <= 0)
		fatal_f("system time is at/before epoch");
	எனில் ((uint64_t)now > (cert->cert->valid_before + CERT_EXPIRY_GRACE))
		திரும்பு -1; /* certificate already expired */
	n = (CERT_EXPIRY_GRACE + cert->cert->valid_before) - (uint64_t)now;
	n = MINIMUM(n, INT_MAX);
	எனில் (cert_lifetime <= 0)
		திரும்பு (முழு)n;
	திரும்பு MINIMUM(cert_lifetime, (முழு)n);
}

நிலையான முழு
add_file(முழு agent_fd, மாறிலி எழுத்து *filename, முழு சாவி_only, முழு cert_only,
    முழு qflag, முழு Nflag, மாறிலி எழுத்து *skprovider,
    கட்டமைப்பு dest_constraint **dest_constraints,
    size_t ndest_constraints)
{
	கட்டமைப்பு sshkey *தனிப்பட்ட = வெற்று, *cert = வெற்று;
	எழுத்து *comment = வெற்று;
	எழுத்து செய்தி[1024], *certpath = வெற்று;
	முழு cert_lifetime, r, fd, ret = -1;
	கட்டமைப்பு sshbuf *keyblob;

	எனில் (strcmp(filename, "-") == 0) {
		fd = STDIN_FILENO;
		filename = "(stdin)";
	} இல்லையெனில் எனில் ((fd = open(filename, O_RDONLY)) == -1) {
		perror(filename);
		திரும்பு -1;
	}

	/*
	 * Since we'll try to load a keyfile multiple times, permission errors
	 * will occur multiple times, so check perms first and bail if wrong.
	 */
	எனில் (fd != STDIN_FILENO) {
		எனில் (sshkey_perm_ok(fd, filename) != 0) {
			close(fd);
			திரும்பு -1;
		}
	}
	எனில் ((r = sshbuf_load_fd(fd, &keyblob)) != 0) {
		fprintf(stderr, "Error loading key \"%s\": %s\n",
		    filename, ssh_err(r));
		sshbuf_free(keyblob);
		close(fd);
		திரும்பு -1;
	}
	close(fd);

	/* At first, try empty passphrase */
	எனில் ((r = sshkey_parse_private_fileblob(keyblob, "", &தனிப்பட்ட,
	    &comment)) != 0 && r != SSH_ERR_சாவி_WRONG_PASSPHRASE) {
		fprintf(stderr, "Error loading key \"%s\": %s\n",
		    filename, ssh_err(r));
		செல் fail_load;
	}
	/* try last */
	எனில் (தனிப்பட்ட == வெற்று && pass != வெற்று) {
		எனில் ((r = sshkey_parse_private_fileblob(keyblob, pass, &தனிப்பட்ட,
		    &comment)) != 0 && r != SSH_ERR_சாவி_WRONG_PASSPHRASE) {
			fprintf(stderr, "Error loading key \"%s\": %s\n",
			    filename, ssh_err(r));
			செல் fail_load;
		}
	}
	எனில் (தனிப்பட்ட == வெற்று) {
		/* clear passphrase since it did not work */
		clear_pass();
		snprintf(செய்தி, அளவு செய்தி, "Enter passphrase for %s%s: ",
		    filename, confirm ? " (will confirm each use)" : "");
		க்கு (;;) {
			pass = read_passphrase(செய்தி, RP_ALLOW_STDIN);
			எனில் (strcmp(pass, "") == 0)
				செல் fail_load;
			எனில் ((r = sshkey_parse_private_fileblob(keyblob, pass,
			    &தனிப்பட்ட, &comment)) == 0)
				நிறுத்து;
			இல்லையெனில் எனில் (r != SSH_ERR_சாவி_WRONG_PASSPHRASE) {
				fprintf(stderr,
				    "Error loading key \"%s\": %s\n",
				    filename, ssh_err(r));
 fail_load:
				clear_pass();
				sshbuf_free(keyblob);
				திரும்பு -1;
			}
			clear_pass();
			snprintf(செய்தி, அளவு செய்தி,
			    "Bad passphrase, try again for %s%s: ", filename,
			    confirm ? " (will confirm each use)" : "");
		}
	}
	எனில் (comment == வெற்று || *comment == '\0')
		comment = xstrdup(filename);
	sshbuf_free(keyblob);

	எனில் (sshkey_is_sk(தனிப்பட்ட)) {
		எனில் (skprovider == வெற்று) {
			fprintf(stderr, "Cannot load FIDO key %s "
			    "without provider\n", filename);
			செல் out;
		}
	} இல்லையெனில் {
		/* Don't send provider constraint for other keys */
		skprovider = வெற்று;
	}

	எனில் (!cert_only) {
		எனில் ((r = ssh_add_identity_constrained(agent_fd, தனிப்பட்ட,
		    comment, lifetime, confirm, skprovider,
		    dest_constraints, ndest_constraints)) == 0) {
			ret = 0;
			எனில் (!qflag) {
				fprintf(stderr, "Identity added: %s (%s)\n",
				    filename, comment);
				எனில் (lifetime != 0) {
					fprintf(stderr, "Lifetime set to %s\n",
					    fmt_timeframe((time_t)lifetime));
				}
				எனில் (confirm != 0) {
					fprintf(stderr, "The user must confirm "
					    "each use of the key\n");
				}
			}
		} இல்லையெனில் {
			fprintf(stderr, "Could not add identity \"%s\": %s\n",
			    filename, ssh_err(r));
		}
	}

	/* Skip trying to load the cert if requested */
	எனில் (சாவி_only)
		செல் out;

	/* Now try to add the certificate flavour too */
	xasprintf(&certpath, "%s-cert.pub", filename);
	எனில் ((r = sshkey_load_public(certpath, &cert, வெற்று)) != 0) {
		எனில் (r != SSH_ERR_SYSTEM_ERROR || errno != ENOENT)
			error_r(r, "Failed to load certificate \"%s\"",
			    certpath);
		செல் out;
	}

	எனில் (!sshkey_equal_public(cert, தனிப்பட்ட)) {
		error("Certificate %s does not match private key %s",
		    certpath, filename);
		செல் out;
	}

	cert_lifetime = lifetime;
	எனில் (!Nflag &&
	    (cert_lifetime = check_cert_lifetime(cert, cert_lifetime)) == -1) {
		logit("Certificate %s has already expired; ignored", certpath);
		செல் out;
	}

	/* Graft with private bits */
	எனில் ((r = sshkey_to_certified(தனிப்பட்ட)) != 0) {
		error_fr(r, "sshkey_to_certified");
		செல் out;
	}
	எனில் ((r = sshkey_cert_copy(cert, தனிப்பட்ட)) != 0) {
		error_fr(r, "sshkey_cert_copy");
		செல் out;
	}
	/* send to agent */
	எனில் ((r = ssh_add_identity_constrained(agent_fd, தனிப்பட்ட, comment,
	    cert_lifetime, confirm, skprovider,
	    dest_constraints, ndest_constraints)) != 0) {
		error_r(r, "Certificate %s (%s) add failed", certpath,
		    தனிப்பட்ட->cert->சாவி_id);
		செல் out;
	}
	/* success */
	எனில் (!qflag) {
		fprintf(stderr, "Certificate added: %s (%s)\n", certpath,
		    தனிப்பட்ட->cert->சாவி_id);
		எனில் (cert_lifetime != 0) {
			fprintf(stderr, "Lifetime set to %s\n",
			    fmt_timeframe((time_t)cert_lifetime));
		}
		எனில் (confirm != 0) {
			fprintf(stderr, "The user must confirm each use "
			    "of the key\n");
		}
	}

 out:
	விடுவி(certpath);
	விடுவி(comment);
	sshkey_free(cert);
	sshkey_free(தனிப்பட்ட);

	திரும்பு ret;
}

நிலையான முழு
update_card(முழு agent_fd, முழு add, மாறிலி எழுத்து *id, முழு qflag, முழு no_pin,
    முழு சாவி_only, முழு cert_only,
    கட்டமைப்பு dest_constraint **dest_constraints, size_t ndest_constraints,
    கட்டமைப்பு sshkey **certs, size_t ncerts)
{
	எழுத்து *pin = வெற்று;
	முழு r, ret = -1;

	எனில் (சாவி_only)
		ncerts = 0;

	எனில் (add && !no_pin) {
		எனில் ((pin = read_passphrase("Enter passphrase for PKCS#11: ",
		    RP_ALLOW_STDIN)) == வெற்று)
			திரும்பு -1;
	}

	எனில் ((r = ssh_update_card(agent_fd, add, id, pin == வெற்று ? "" : pin,
	    lifetime, confirm, dest_constraints, ndest_constraints,
	    cert_only, certs, ncerts)) == 0) {
		ret = 0;
		எனில் (!qflag) {
			fprintf(stderr, "Card %s: %s\n",
			    add ? "added" : "removed", id);
		}
	} இல்லையெனில் {
		fprintf(stderr, "Could not %s card \"%s\": %s\n",
		    add ? "add" : "remove", id, ssh_err(r));
		ret = -1;
	}
	விடுவி(pin);
	திரும்பு ret;
}

நிலையான முழு
test_சாவி(முழு agent_fd, மாறிலி எழுத்து *filename)
{
	கட்டமைப்பு sshkey *சாவி = வெற்று;
	u_char *sig = வெற்று;
	மாறிலி எழுத்து *alg = வெற்று;
	size_t slen = 0;
	முழு r, ret = -1;
	எழுத்து data[1024];

	எனில் ((r = sshkey_load_public(filename, &சாவி, வெற்று)) != 0) {
		error_r(r, "Couldn't read public key %s", filename);
		திரும்பு -1;
	}
	எனில் (sshkey_type_plain(சாவி->type) == சாவி_RSA)
		alg = "rsa-sha2-256";
	arc4random_buf(data, அளவு(data));
	எனில் ((r = ssh_agent_sign(agent_fd, சாவி, &sig, &slen, data, அளவு(data),
	    alg, 0)) != 0) {
		error_r(r, "Agent signature failed for %s", filename);
		செல் done;
	}
	எனில் ((r = sshkey_verify(சாவி, sig, slen, data, அளவு(data),
	    alg, 0, வெற்று)) != 0) {
		error_r(r, "Signature verification failed for %s", filename);
		செல் done;
	}
	/* success */
	ret = 0;
 done:
	விடுவி(sig);
	sshkey_free(சாவி);
	திரும்பு ret;
}

நிலையான முழு
list_identities(முழு agent_fd, முழு do_fp)
{
	எழுத்து *fp;
	முழு r;
	கட்டமைப்பு ssh_identitylist *idlist;
	size_t i;

	எனில் ((r = ssh_fetch_identitylist(agent_fd, &idlist)) != 0) {
		எனில் (r != SSH_ERR_AGENT_NO_IDENTITIES)
			fprintf(stderr, "error fetching identities: %s\n",
			    ssh_err(r));
		இல்லையெனில்
			printf("The agent has no identities.\n");
		திரும்பு -1;
	}
	க்கு (i = 0; i < idlist->nkeys; i++) {
		எனில் (do_fp) {
			fp = sshkey_fingerprint(idlist->சாவிகள்[i],
			    fingerprint_hash, SSH_FP_DEFAULT);
			printf("%u %s %s (%s)\n", sshkey_size(idlist->சாவிகள்[i]),
			    fp == வெற்று ? "(null)" : fp, idlist->comments[i],
			    sshkey_type(idlist->சாவிகள்[i]));
			விடுவி(fp);
		} இல்லையெனில் {
			எனில் ((r = sshkey_write(idlist->சாவிகள்[i], stdout)) != 0) {
				fprintf(stderr, "sshkey_write: %s\n",
				    ssh_err(r));
				தொடர்;
			}
			fprintf(stdout, " %s\n", idlist->comments[i]);
		}
	}
	ssh_free_identitylist(idlist);
	திரும்பு 0;
}

நிலையான முழு
lock_agent(முழு agent_fd, முழு lock)
{
	எழுத்து prompt[100], *p1, *p2;
	முழு r, passok = 1, ret = -1;

	strlcpy(prompt, "Enter lock password: ", அளவு(prompt));
	p1 = read_passphrase(prompt, RP_ALLOW_STDIN);
	எனில் (lock) {
		strlcpy(prompt, "Again: ", அளவு prompt);
		p2 = read_passphrase(prompt, RP_ALLOW_STDIN);
		எனில் (strcmp(p1, p2) != 0) {
			fprintf(stderr, "Passwords do not match.\n");
			passok = 0;
		}
		freezero(p2, strlen(p2));
	}
	எனில் (passok) {
		எனில் ((r = ssh_lock_agent(agent_fd, lock, p1)) == 0) {
			fprintf(stderr, "Agent %slocked.\n", lock ? "" : "un");
			ret = 0;
		} இல்லையெனில் {
			fprintf(stderr, "Failed to %slock agent: %s\n",
			    lock ? "" : "un", ssh_err(r));
		}
	}
	freezero(p1, strlen(p1));
	திரும்பு (ret);
}

நிலையான முழு
load_resident_சாவிகள்(முழு agent_fd, மாறிலி எழுத்து *skprovider, முழு qflag, முழு no_pin,
    கட்டமைப்பு dest_constraint **dest_constraints, size_t ndest_constraints)
{
	கட்டமைப்பு sshsk_resident_சாவி **srks;
	size_t nsrks, i;
	கட்டமைப்பு sshkey *சாவி;
	முழு r, ok = 0;
	எழுத்து *fp, *pin = வெற்று;

	எனில் (!no_pin) {
		pin = read_passphrase("Enter PIN for authenticator: ",
		    RP_ALLOW_STDIN);
	}
	எனில் ((r = sshsk_load_resident(skprovider, வெற்று, pin == வெற்று ? "" : pin,
	    0, &srks, &nsrks)) != 0) {
		error_r(r, "Unable to load resident keys");
		விடுவி(pin);
		திரும்பு r;
	}
	விடுவி(pin);
	க்கு (i = 0; i < nsrks; i++) {
		சாவி = srks[i]->சாவி;
		எனில் ((fp = sshkey_fingerprint(சாவி,
		    fingerprint_hash, SSH_FP_DEFAULT)) == வெற்று)
			fatal_f("sshkey_fingerprint failed");
		எனில் ((r = ssh_add_identity_constrained(agent_fd, சாவி,
		    சாவி->sk_application, lifetime, confirm, skprovider,
		    dest_constraints, ndest_constraints)) != 0) {
			error("Unable to add key %s %s",
			    sshkey_type(சாவி), fp);
			விடுவி(fp);
			ok = r;
			தொடர்;
		}
		எனில் (ok == 0)
			ok = 1;
		எனில் (!qflag) {
			fprintf(stderr, "Resident identity added: %s %s\n",
			    sshkey_type(சாவி), fp);
			எனில் (lifetime != 0) {
				fprintf(stderr,
				    "Lifetime set to %d seconds\n", lifetime);
			}
			எனில் (confirm != 0) {
				fprintf(stderr, "The user must confirm "
				    "each use of the key\n");
			}
		}
		விடுவி(fp);
	}
	sshsk_free_resident_சாவிகள்(srks, nsrks);
	எனில் (nsrks == 0)
		திரும்பு SSH_ERR_சாவி_NOT_FOUND;
	திரும்பு ok == 1 ? 0 : ok;
}

நிலையான முழு
do_file(முழு agent_fd, முழு deleting, முழு சாவி_only, முழு cert_only,
    எழுத்து *file, முழு qflag, முழு Nflag, மாறிலி எழுத்து *skprovider,
    கட்டமைப்பு dest_constraint **dest_constraints, size_t ndest_constraints)
{
	எனில் (deleting) {
		எனில் (delete_file(agent_fd, file, சாவி_only,
		    cert_only, qflag) == -1)
			திரும்பு -1;
	} இல்லையெனில் {
		எனில் (add_file(agent_fd, file, சாவி_only, cert_only, qflag, Nflag,
		    skprovider, dest_constraints, ndest_constraints) == -1)
			திரும்பு -1;
	}
	திரும்பு 0;
}

நிலையான வெறுமை
free_dest_constraint_hop(கட்டமைப்பு dest_constraint_hop *dch)
{
	u_int i;

	எனில் (dch == வெற்று)
		திரும்பு;
	விடுவி(dch->user);
	விடுவி(dch->hostname);
	க்கு (i = 0; i < dch->nkeys; i++)
		sshkey_free(dch->சாவிகள்[i]);
	விடுவி(dch->சாவிகள்);
	விடுவி(dch->சாவி_is_ca);
}

நிலையான வெறுமை
free_dest_constraints(கட்டமைப்பு dest_constraint **dcs, size_t ndcs)
{
	size_t i;

	க்கு (i = 0; i < ndcs; i++) {
		free_dest_constraint_hop(&dcs[i]->from);
		free_dest_constraint_hop(&dcs[i]->to);
		விடுவி(dcs[i]);
	}
	விடுவி(dcs);
}


நிலையான வெறுமை
parse_dest_constraint_hop(மாறிலி எழுத்து *s, கட்டமைப்பு dest_constraint_hop *dch,
    எழுத்து **hostkey_files)
{
	எழுத்து *user = வெற்று, *host, *os, *path;
	size_t i;
	கட்டமைப்பு hostkeys *hostkeys;
	மாறிலி கட்டமைப்பு hostkey_entry *hke;
	முழு r, want_ca;

	memset(dch, '\0', அளவு(*dch));
	os = xstrdup(s);
	எனில் ((host = strrchr(os, '@')) == வெற்று)
		host = os;
	இல்லையெனில் {
		*host++ = '\0';
		user = os;
	}
	cleanhostname(host);
	/* Trivial case: username@ (all hosts) */
	எனில் (*host == '\0') {
		எனில் (user == வெற்று) {
			fatal("Invalid key destination constraint \"%s\": "
			    "does not specify user or host", s);
		}
		dch->user = xstrdup(user);
		/* other fields left blank */
		விடுவி(os);
		திரும்பு;
	}
	எனில் (hostkey_files == வெற்று)
		fatal_f("no hostkey files");
	/* Otherwise we need to look up the keys for this hostname */
	hostkeys = init_hostkeys();
	க்கு (i = 0; hostkey_files[i]; i++) {
		path = tilde_expand_filename(hostkey_files[i], getuid());
		debug2_f("looking up host keys for \"%s\" in %s", host, path);
                load_hostkeys(hostkeys, host, path, 0);
		விடுவி(path);
	}
	dch->user = user == வெற்று ? வெற்று : xstrdup(user);
	dch->hostname = xstrdup(host);
	க்கு (i = 0; i < hostkeys->இலக்கம்_entries; i++) {
		hke = hostkeys->entries + i;
		want_ca = hke->marker == MRK_CA;
		எனில் (hke->marker != MRK_NONE && !want_ca)
			தொடர்;
		debug3_f("%s%s%s: adding %s %skey from %s:%lu as key %u",
		    user == வெற்று ? "": user, user == வெற்று ? "" : "@",
		    host, sshkey_type(hke->சாவி), want_ca ? "CA " : "",
		    hke->file, hke->வரி, dch->nkeys);
		dch->சாவிகள் = xrecallocarray(dch->சாவிகள், dch->nkeys,
		    dch->nkeys + 1, அளவு(*dch->சாவிகள்));
		dch->சாவி_is_ca = xrecallocarray(dch->சாவி_is_ca, dch->nkeys,
		    dch->nkeys + 1, அளவு(*dch->சாவி_is_ca));
		எனில் ((r = sshkey_from_private(hke->சாவி,
		    &(dch->சாவிகள்[dch->nkeys]))) != 0)
			fatal_fr(r, "sshkey_from_private");
		dch->சாவி_is_ca[dch->nkeys] = want_ca;
		dch->nkeys++;
	}
	எனில் (dch->nkeys == 0)
		fatal("No host keys found for destination \"%s\"", host);
	free_hostkeys(hostkeys);
	விடுவி(os);
	திரும்பு;
}

நிலையான வெறுமை
parse_dest_constraint(மாறிலி எழுத்து *s, கட்டமைப்பு dest_constraint ***dcp,
    size_t *ndcp, எழுத்து **hostkey_files)
{
	கட்டமைப்பு dest_constraint *dc;
	எழுத்து *os, *cp;

	dc = xcalloc(1, அளவு(*dc));
	os = xstrdup(s);
	எனில் ((cp = strchr(os, '>')) == வெற்று) {
		/* initial hop; no 'from' hop specified */
		parse_dest_constraint_hop(os, &dc->to, hostkey_files);
	} இல்லையெனில் {
		/* two hops specified */
		*(cp++) = '\0';
		parse_dest_constraint_hop(os, &dc->from, hostkey_files);
		parse_dest_constraint_hop(cp, &dc->to, hostkey_files);
		எனில் (dc->from.user != வெற்று) {
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
	*dcp = xrecallocarray(*dcp, *ndcp, *ndcp + 1, அளவு(**dcp));
	(*dcp)[(*ndcp)++] = dc;
	விடுவி(os);
}


நிலையான வெறுமை
usage(வெறுமை)
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

முழு
முதன்மை(முழு argc, எழுத்து **argv)
{
	வெளி எழுத்து *optarg;
	வெளி முழு optind;
	முழு agent_fd = -1;
	எழுத்து *pkcs11provider = வெற்று, *skprovider = வெற்று;
	எழுத்து **dest_constraint_strings = வெற்று, **hostkey_files = வெற்று;
	முழு r, i, ch, deleting = 0, ret = 0, சாவி_only = 0, cert_only = 0;
	முழு do_download = 0, xflag = 0, lflag = 0, Dflag = 0;
	முழு Qflag = 0, qflag = 0, Tflag = 0, Nflag = 0, no_pin = 0;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_INFO;
	கட்டமைப்பு sshkey *k, **certs = வெற்று;
	கட்டமைப்பு dest_constraint **dest_constraints = வெற்று;
	size_t n, ndest_constraints = 0, ncerts = 0;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	__progname = ssh_get_progname(argv[0]);
	seed_rng();

	log_init(__progname, log_level, log_facility, 1);

	setvbuf(stdout, வெற்று, _IOLBF, 0);

	skprovider = getenv("SSH_SK_PROVIDER");

	போது ((ch = getopt(argc, argv, "vkKlLNPCcdDTxXE:e:h:H:M:m:Qqs:S:t:")) != -1) {
		தேர்வு (ch) {
		நிலை 'v':
			எனில் (log_level == SYSLOG_LEVEL_INFO)
				log_level = SYSLOG_LEVEL_DEBUG1;
			இல்லையெனில் எனில் (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			நிறுத்து;
		நிலை 'N':
			Nflag = 1;
			நிறுத்து;
		நிலை 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			எனில் (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			நிறுத்து;
		நிலை 'H':
			stringlist_append(&hostkey_files, optarg);
			நிறுத்து;
		நிலை 'h':
			stringlist_append(&dest_constraint_strings, optarg);
			நிறுத்து;
		நிலை 'k':
			சாவி_only = 1;
			நிறுத்து;
		நிலை 'C':
			cert_only = 1;
			நிறுத்து;
		நிலை 'K':
			do_download = 1;
			நிறுத்து;
		நிலை 'l':
		நிலை 'L':
			எனில் (lflag != 0)
				fatal("-%c flag already specified", lflag);
			lflag = ch;
			நிறுத்து;
		நிலை 'x':
		நிலை 'X':
			எனில் (xflag != 0)
				fatal("-%c flag already specified", xflag);
			xflag = ch;
			நிறுத்து;
		நிலை 'c':
			confirm = 1;
			நிறுத்து;
		நிலை 'm':
		நிலை 'M':
			/* deprecated */
			நிறுத்து;
		நிலை 'd':
			deleting = 1;
			நிறுத்து;
		நிலை 'P':
			no_pin = 1;
			நிறுத்து;
		நிலை 'D':
			Dflag = 1;
			நிறுத்து;
		நிலை 's':
			pkcs11provider = optarg;
			நிறுத்து;
		நிலை 'S':
			skprovider = optarg;
			நிறுத்து;
		நிலை 'e':
			deleting = 1;
			pkcs11provider = optarg;
			நிறுத்து;
		நிலை 't':
			எனில் ((lifetime = convtime(optarg)) == -1 ||
			    lifetime < 0 || (u_long)lifetime > UINT32_MAX) {
				fprintf(stderr, "Invalid lifetime\n");
				ret = 1;
				செல் done;
			}
			நிறுத்து;
		நிலை 'q':
			qflag = 1;
			நிறுத்து;
		நிலை 'Q':
			Qflag = 1;
			நிறுத்து;
		நிலை 'T':
			Tflag = 1;
			நிறுத்து;
		இயல்பு:
			usage();
			ret = 1;
			செல் done;
		}
	}
	log_init(__progname, log_level, log_facility, 1);

	எனில் ((xflag != 0) + (lflag != 0) + (Dflag != 0) + (Qflag != 0) > 1)
		fatal("Invalid combination of actions");

	/* First, get a connection to the authentication agent. */
	தேர்வு (r = ssh_get_authentication_socket(&agent_fd)) {
	நிலை 0:
		நிறுத்து;
	நிலை SSH_ERR_AGENT_NOT_PRESENT:
		fprintf(stderr, "Could not open a connection to your "
		    "authentication agent.\n");
		exit(2);
	இயல்பு:
		fprintf(stderr, "Error connecting to agent: %s\n", ssh_err(r));
		exit(2);
	}

	எனில் (xflag) {
		எனில் (lock_agent(agent_fd, xflag == 'x' ? 1 : 0) == -1)
			ret = 1;
		செல் done;
	} இல்லையெனில் எனில் (lflag) {
		எனில் (list_identities(agent_fd, lflag == 'l' ? 1 : 0) == -1)
			ret = 1;
		செல் done;
	} இல்லையெனில் எனில் (Dflag) {
		எனில் (delete_all(agent_fd, qflag) == -1)
			ret = 1;
		செல் done;
	} இல்லையெனில் எனில் (Qflag) {
		எனில் (query_exts(agent_fd) == -1)
			ret = 1;
		செல் done;
	}

#ifdef ENABLE_SK_INTERNAL
	எனில் (skprovider == வெற்று)
		skprovider = "internal";
#endif

	எனில் (hostkey_files == வெற்று) {
		/* use defaults from readconf.c */
		stringlist_append(&hostkey_files, _PATH_SSH_USER_HOSTFILE);
		stringlist_append(&hostkey_files, _PATH_SSH_USER_HOSTFILE2);
		stringlist_append(&hostkey_files, _PATH_SSH_SYSTEM_HOSTFILE);
		stringlist_append(&hostkey_files, _PATH_SSH_SYSTEM_HOSTFILE2);
	}
	எனில் (dest_constraint_strings != வெற்று) {
		க்கு (i = 0; dest_constraint_strings[i] != வெற்று; i++) {
			parse_dest_constraint(dest_constraint_strings[i],
			  &dest_constraints, &ndest_constraints, hostkey_files);
		}
	}

	argc -= optind;
	argv += optind;
	எனில் (Tflag) {
		எனில் (argc <= 0)
			fatal("no keys to test");
		க்கு (r = i = 0; i < argc; i++)
			r |= test_சாவி(agent_fd, argv[i]);
		ret = r == 0 ? 0 : 1;
		செல் done;
	}
	எனில் (pkcs11provider != வெற்று) {
		க்கு (i = 0; i < argc; i++) {
			எனில் ((r = sshkey_load_public(argv[i], &k, வெற்று)) != 0)
				fatal_fr(r, "load certificate %s", argv[i]);
			certs = xrecallocarray(certs, ncerts, ncerts + 1,
			    அளவு(*certs));
			debug2("%s: %s", argv[i], sshkey_ssh_name(k));
			certs[ncerts++] = k;
		}
		debug2_f("loaded %zu certificates", ncerts);
		எனில் (update_card(agent_fd, !deleting, pkcs11provider,
		    qflag, no_pin, சாவி_only, cert_only,
		    dest_constraints, ndest_constraints,
		    certs, ncerts) == -1)
			ret = 1;
		க்கு (n = 0; n < ncerts; n++)
			sshkey_free(certs[n]);
		விடுவி(certs);
		செல் done;
	}
	எனில் (do_download) {
		எனில் (skprovider == வெற்று)
			fatal("Cannot download keys without provider");
		எனில் (load_resident_சாவிகள்(agent_fd, skprovider, qflag, no_pin,
		    dest_constraints, ndest_constraints) != 0)
			ret = 1;
		செல் done;
	}
	எனில் (argc == 0) {
		எழுத்து buf[PATH_MAX];
		கட்டமைப்பு passwd *pw;
		கட்டமைப்பு stat st;
		முழு மொத்தம் = 0;

		எனில் ((pw = getpwuid(getuid())) == வெற்று) {
			fprintf(stderr, "No user found with uid %u\n",
			    (u_int)getuid());
			ret = 1;
			செல் done;
		}

		க்கு (i = 0; default_files[i]; i++) {
			snprintf(buf, அளவு(buf), "%s/%s", pw->pw_dir,
			    default_files[i]);
			எனில் (stat(buf, &st) == -1)
				தொடர்;
			எனில் (do_file(agent_fd, deleting, சாவி_only, cert_only,
			    buf, qflag, Nflag, skprovider,
			    dest_constraints, ndest_constraints) == -1)
				ret = 1;
			இல்லையெனில்
				மொத்தம்++;
		}
		எனில் (மொத்தம் == 0)
			ret = 1;
	} இல்லையெனில் {
		க்கு (i = 0; i < argc; i++) {
			எனில் (do_file(agent_fd, deleting, சாவி_only, cert_only,
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
	திரும்பு ret;
}
