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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/stat.h>

#ifdef WITH_OPENSSL
# include <openssl/evp.h>
# include "openbsd-compat/openssl-compat.h"
#endif

#ضمن <errno.h>
#ضمن <fcntl.h>
#ضمن <pwd.h>
#ضمن <stdarg.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <unistd.h>
#ضمن <limits.h>
#ضمن <time.h>

#ضمن "xmalloc.h"
#ضمن "ssh.h"
#ضمن "log.h"
#ضمن "sshkey.h"
#ضمن "sshbuf.h"
#ضمن "authfd.h"
#ضمن "authfile.h"
#ضمن "pathnames.h"
#ضمن "misc.h"
#ضمن "ssherr.h"
#ضمن "digest.h"
#ضمن "ssh-sk.h"
#ضمن "sk-api.h"
#ضمن "hostfile.h"

#define CERT_EXPIRY_GRACE	(5*60)

/* argv0 */
خارجي حرف *__progname;

/* Default files to add */
ساكن حرف *default_files[] = {
#ifdef WITH_OPENSSL
	_PATH_SSH_CLIENT_ID_RSA,
	_PATH_SSH_CLIENT_ID_ECDSA,
	_PATH_SSH_CLIENT_ID_ECDSA_SK,
#endif /* WITH_OPENSSL */
	_PATH_SSH_CLIENT_ID_ED25519,
	_PATH_SSH_CLIENT_ID_ED25519_SK,
	_PATH_SSH_CLIENT_ID_MLDSA44_ED25519,
	عدم
};

ساكن صحيح fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* Default lifetime (0 == forever) */
ساكن صحيح lifetime = 0;

/* User has to confirm key use */
ساكن صحيح confirm = 0;

/* we keep a cache of one passphrase */
ساكن حرف *pass = عدم;
ساكن فراغ
clear_pass(فراغ)
{
	إذا (pass) {
		freezero(pass, strlen(pass));
		pass = عدم;
	}
}

ساكن صحيح
delete_one(صحيح agent_fd, ثابت بنية sshkey *مفتاح, ثابت حرف *comment,
    ثابت حرف *path, صحيح qflag)
{
	صحيح r;

	إذا ((r = ssh_remove_identity(agent_fd, مفتاح)) != 0) {
		fprintf(stderr, "Could not remove identity \"%s\": %s\n",
		    path, ssh_err(r));
		إرجاع r;
	}
	إذا (!qflag) {
		fprintf(stderr, "Identity removed: %s %s (%s)\n", path,
		    sshkey_type(مفتاح), comment ? comment : "no comment");
	}
	إرجاع 0;
}

ساكن صحيح
delete_stdin(صحيح agent_fd, صحيح qflag, صحيح مفتاح_only, صحيح cert_only)
{
	حرف *سطر = عدم, *cp;
	size_t linesize = 0;
	بنية sshkey *مفتاح = عدم;
	صحيح lnum = 0, r, ret = -1;

	بينما (getline(&سطر, &linesize, stdin) != -1) {
		lnum++;
		sshkey_free(مفتاح);
		مفتاح = عدم;
		سطر[strcspn(سطر, "\n")] = '\0';
		cp = سطر + strspn(سطر, " \t");
		إذا (*cp == '#' || *cp == '\0')
			استمر;
		إذا ((مفتاح = sshkey_new(مفتاح_UNSPEC)) == عدم)
			fatal_f("sshkey_new");
		إذا ((r = sshkey_read(مفتاح, &cp)) != 0) {
			error_r(r, "(stdin):%d: invalid key", lnum);
			استمر;
		}
		إذا ((!مفتاح_only && !cert_only) ||
		    (مفتاح_only && !sshkey_is_cert(مفتاح)) ||
		    (cert_only && sshkey_is_cert(مفتاح))) {
			إذا (delete_one(agent_fd, مفتاح, cp,
			    "(stdin)", qflag) == 0)
				ret = 0;
		}
	}
	sshkey_free(مفتاح);
	حرر(سطر);
	إرجاع ret;
}

ساكن صحيح
delete_file(صحيح agent_fd, ثابت حرف *filename, صحيح مفتاح_only,
    صحيح cert_only, صحيح qflag)
{
	بنية sshkey *عام, *cert = عدم;
	حرف *certpath = عدم, *comment = عدم;
	صحيح r, ret = -1;

	إذا (strcmp(filename, "-") == 0)
		إرجاع delete_stdin(agent_fd, qflag, مفتاح_only, cert_only);

	إذا ((r = sshkey_load_public(filename, &عام,  &comment)) != 0) {
		printf("Bad key file %s: %s\n", filename, ssh_err(r));
		إرجاع -1;
	}
	إذا ((!مفتاح_only && !cert_only) ||
	    (مفتاح_only && !sshkey_is_cert(عام)) ||
	    (cert_only && sshkey_is_cert(عام))) {
		إذا (delete_one(agent_fd, عام, comment, filename, qflag) == 0)
			ret = 0;
	}

	إذا (مفتاح_only)
		اذهب out;

	/* Now try to delete the corresponding certificate too */
	حرر(comment);
	comment = عدم;
	xasprintf(&certpath, "%s-cert.pub", filename);
	إذا ((r = sshkey_load_public(certpath, &cert, &comment)) != 0) {
		إذا (r != SSH_ERR_SYSTEM_ERROR || errno != ENOENT)
			error_r(r, "Failed to load certificate \"%s\"", certpath);
		اذهب out;
	}

	إذا (!sshkey_equal_public(cert, عام))
		fatal("Certificate %s does not match private key %s",
		    certpath, filename);

	إذا (delete_one(agent_fd, cert, comment, certpath, qflag) == 0)
		ret = 0;

 out:
	sshkey_free(cert);
	sshkey_free(عام);
	حرر(certpath);
	حرر(comment);

	إرجاع ret;
}

/* Send a request to remove all identities. */
ساكن صحيح
delete_all(صحيح agent_fd, صحيح qflag)
{
	صحيح ret = -1;

	/*
	 * Since the agent might be forwarded, old or non-OpenSSH, when asked
	 * to remove all keys, attempt to remove both protocol v.1 and v.2
	 * keys.
	 */
	إذا (ssh_remove_all_identities(agent_fd, 2) == 0)
		ret = 0;
	/* ignore error-code for ssh1 */
	ssh_remove_all_identities(agent_fd, 1);

	إذا (ret != 0)
		fprintf(stderr, "Failed to remove all identities.\n");
	وإلا إذا (!qflag)
		fprintf(stderr, "All identities removed.\n");

	إرجاع ret;
}

ساكن صحيح
query_exts(صحيح agent_fd)
{
	صحيح r;
	حرف **exts = عدم;
	size_t i;

	إذا ((r = ssh_agent_query_extensions(agent_fd, &exts)) != 0)
		fatal_r(r, "unable to query supported extensions");
	لكل (i = 0; exts != عدم && exts[i] != عدم; i++)
		puts(exts[i]);
	stringlist_free(exts);
	إرجاع 0;
}

ساكن صحيح
check_cert_lifetime(ثابت بنية sshkey *cert, صحيح cert_lifetime)
{
	time_t now;
	uint64_t n;

	إذا (cert == عدم || cert->cert == عدم || !sshkey_is_cert(cert) ||
	    cert->cert->valid_before == 0xFFFFFFFFFFFFFFFFULL)
		إرجاع cert_lifetime;
	إذا ((now = time(عدم)) <= 0)
		fatal_f("system time is at/before epoch");
	إذا ((uint64_t)now > (cert->cert->valid_before + CERT_EXPIRY_GRACE))
		إرجاع -1; /* certificate already expired */
	n = (CERT_EXPIRY_GRACE + cert->cert->valid_before) - (uint64_t)now;
	n = MINIMUM(n, INT_MAX);
	إذا (cert_lifetime <= 0)
		إرجاع (صحيح)n;
	إرجاع MINIMUM(cert_lifetime, (صحيح)n);
}

ساكن صحيح
add_file(صحيح agent_fd, ثابت حرف *filename, صحيح مفتاح_only, صحيح cert_only,
    صحيح qflag, صحيح Nflag, ثابت حرف *skprovider,
    بنية dest_constraint **dest_constraints,
    size_t ndest_constraints)
{
	بنية sshkey *خاص = عدم, *cert = عدم;
	حرف *comment = عدم;
	حرف رسالة[1024], *certpath = عدم;
	صحيح cert_lifetime, r, fd, ret = -1;
	بنية sshbuf *keyblob;

	إذا (strcmp(filename, "-") == 0) {
		fd = STDIN_FILENO;
		filename = "(stdin)";
	} وإلا إذا ((fd = open(filename, O_RDONLY)) == -1) {
		perror(filename);
		إرجاع -1;
	}

	/*
	 * Since we'll try to load a keyfile multiple times, permission errors
	 * will occur multiple times, so check perms first and bail if wrong.
	 */
	إذا (fd != STDIN_FILENO) {
		إذا (sshkey_perm_ok(fd, filename) != 0) {
			close(fd);
			إرجاع -1;
		}
	}
	إذا ((r = sshbuf_load_fd(fd, &keyblob)) != 0) {
		fprintf(stderr, "Error loading key \"%s\": %s\n",
		    filename, ssh_err(r));
		sshbuf_free(keyblob);
		close(fd);
		إرجاع -1;
	}
	close(fd);

	/* At first, try empty passphrase */
	إذا ((r = sshkey_parse_private_fileblob(keyblob, "", &خاص,
	    &comment)) != 0 && r != SSH_ERR_مفتاح_WRONG_PASSPHRASE) {
		fprintf(stderr, "Error loading key \"%s\": %s\n",
		    filename, ssh_err(r));
		اذهب fail_load;
	}
	/* try last */
	إذا (خاص == عدم && pass != عدم) {
		إذا ((r = sshkey_parse_private_fileblob(keyblob, pass, &خاص,
		    &comment)) != 0 && r != SSH_ERR_مفتاح_WRONG_PASSPHRASE) {
			fprintf(stderr, "Error loading key \"%s\": %s\n",
			    filename, ssh_err(r));
			اذهب fail_load;
		}
	}
	إذا (خاص == عدم) {
		/* clear passphrase since it did not work */
		clear_pass();
		snprintf(رسالة, حجم رسالة, "Enter passphrase for %s%s: ",
		    filename, confirm ? " (will confirm each use)" : "");
		لكل (;;) {
			pass = read_passphrase(رسالة, RP_ALLOW_STDIN);
			إذا (strcmp(pass, "") == 0)
				اذهب fail_load;
			إذا ((r = sshkey_parse_private_fileblob(keyblob, pass,
			    &خاص, &comment)) == 0)
				اكسر;
			وإلا إذا (r != SSH_ERR_مفتاح_WRONG_PASSPHRASE) {
				fprintf(stderr,
				    "Error loading key \"%s\": %s\n",
				    filename, ssh_err(r));
 fail_load:
				clear_pass();
				sshbuf_free(keyblob);
				إرجاع -1;
			}
			clear_pass();
			snprintf(رسالة, حجم رسالة,
			    "Bad passphrase, try again for %s%s: ", filename,
			    confirm ? " (will confirm each use)" : "");
		}
	}
	إذا (comment == عدم || *comment == '\0')
		comment = xstrdup(filename);
	sshbuf_free(keyblob);

	إذا (sshkey_is_sk(خاص)) {
		إذا (skprovider == عدم) {
			fprintf(stderr, "Cannot load FIDO key %s "
			    "without provider\n", filename);
			اذهب out;
		}
	} وإلا {
		/* Don't send provider constraint for other keys */
		skprovider = عدم;
	}

	إذا (!cert_only) {
		إذا ((r = ssh_add_identity_constrained(agent_fd, خاص,
		    comment, lifetime, confirm, skprovider,
		    dest_constraints, ndest_constraints)) == 0) {
			ret = 0;
			إذا (!qflag) {
				fprintf(stderr, "Identity added: %s (%s)\n",
				    filename, comment);
				إذا (lifetime != 0) {
					fprintf(stderr, "Lifetime set to %s\n",
					    fmt_timeframe((time_t)lifetime));
				}
				إذا (confirm != 0) {
					fprintf(stderr, "The user must confirm "
					    "each use of the key\n");
				}
			}
		} وإلا {
			fprintf(stderr, "Could not add identity \"%s\": %s\n",
			    filename, ssh_err(r));
		}
	}

	/* Skip trying to load the cert if requested */
	إذا (مفتاح_only)
		اذهب out;

	/* Now try to add the certificate flavour too */
	xasprintf(&certpath, "%s-cert.pub", filename);
	إذا ((r = sshkey_load_public(certpath, &cert, عدم)) != 0) {
		إذا (r != SSH_ERR_SYSTEM_ERROR || errno != ENOENT)
			error_r(r, "Failed to load certificate \"%s\"",
			    certpath);
		اذهب out;
	}

	إذا (!sshkey_equal_public(cert, خاص)) {
		error("Certificate %s does not match private key %s",
		    certpath, filename);
		اذهب out;
	}

	cert_lifetime = lifetime;
	إذا (!Nflag &&
	    (cert_lifetime = check_cert_lifetime(cert, cert_lifetime)) == -1) {
		logit("Certificate %s has already expired; ignored", certpath);
		اذهب out;
	}

	/* Graft with private bits */
	إذا ((r = sshkey_to_certified(خاص)) != 0) {
		error_fr(r, "sshkey_to_certified");
		اذهب out;
	}
	إذا ((r = sshkey_cert_copy(cert, خاص)) != 0) {
		error_fr(r, "sshkey_cert_copy");
		اذهب out;
	}
	/* send to agent */
	إذا ((r = ssh_add_identity_constrained(agent_fd, خاص, comment,
	    cert_lifetime, confirm, skprovider,
	    dest_constraints, ndest_constraints)) != 0) {
		error_r(r, "Certificate %s (%s) add failed", certpath,
		    خاص->cert->مفتاح_id);
		اذهب out;
	}
	/* success */
	إذا (!qflag) {
		fprintf(stderr, "Certificate added: %s (%s)\n", certpath,
		    خاص->cert->مفتاح_id);
		إذا (cert_lifetime != 0) {
			fprintf(stderr, "Lifetime set to %s\n",
			    fmt_timeframe((time_t)cert_lifetime));
		}
		إذا (confirm != 0) {
			fprintf(stderr, "The user must confirm each use "
			    "of the key\n");
		}
	}

 out:
	حرر(certpath);
	حرر(comment);
	sshkey_free(cert);
	sshkey_free(خاص);

	إرجاع ret;
}

ساكن صحيح
update_card(صحيح agent_fd, صحيح add, ثابت حرف *id, صحيح qflag, صحيح no_pin,
    صحيح مفتاح_only, صحيح cert_only,
    بنية dest_constraint **dest_constraints, size_t ndest_constraints,
    بنية sshkey **certs, size_t ncerts)
{
	حرف *pin = عدم;
	صحيح r, ret = -1;

	إذا (مفتاح_only)
		ncerts = 0;

	إذا (add && !no_pin) {
		إذا ((pin = read_passphrase("Enter passphrase for PKCS#11: ",
		    RP_ALLOW_STDIN)) == عدم)
			إرجاع -1;
	}

	إذا ((r = ssh_update_card(agent_fd, add, id, pin == عدم ? "" : pin,
	    lifetime, confirm, dest_constraints, ndest_constraints,
	    cert_only, certs, ncerts)) == 0) {
		ret = 0;
		إذا (!qflag) {
			fprintf(stderr, "Card %s: %s\n",
			    add ? "added" : "removed", id);
		}
	} وإلا {
		fprintf(stderr, "Could not %s card \"%s\": %s\n",
		    add ? "add" : "remove", id, ssh_err(r));
		ret = -1;
	}
	حرر(pin);
	إرجاع ret;
}

ساكن صحيح
test_مفتاح(صحيح agent_fd, ثابت حرف *filename)
{
	بنية sshkey *مفتاح = عدم;
	u_char *sig = عدم;
	ثابت حرف *alg = عدم;
	size_t slen = 0;
	صحيح r, ret = -1;
	حرف data[1024];

	إذا ((r = sshkey_load_public(filename, &مفتاح, عدم)) != 0) {
		error_r(r, "Couldn't read public key %s", filename);
		إرجاع -1;
	}
	إذا (sshkey_type_plain(مفتاح->type) == مفتاح_RSA)
		alg = "rsa-sha2-256";
	arc4random_buf(data, حجم(data));
	إذا ((r = ssh_agent_sign(agent_fd, مفتاح, &sig, &slen, data, حجم(data),
	    alg, 0)) != 0) {
		error_r(r, "Agent signature failed for %s", filename);
		اذهب done;
	}
	إذا ((r = sshkey_verify(مفتاح, sig, slen, data, حجم(data),
	    alg, 0, عدم)) != 0) {
		error_r(r, "Signature verification failed for %s", filename);
		اذهب done;
	}
	/* success */
	ret = 0;
 done:
	حرر(sig);
	sshkey_free(مفتاح);
	إرجاع ret;
}

ساكن صحيح
list_identities(صحيح agent_fd, صحيح do_fp)
{
	حرف *fp;
	صحيح r;
	بنية ssh_identitylist *idlist;
	size_t i;

	إذا ((r = ssh_fetch_identitylist(agent_fd, &idlist)) != 0) {
		إذا (r != SSH_ERR_AGENT_NO_IDENTITIES)
			fprintf(stderr, "error fetching identities: %s\n",
			    ssh_err(r));
		وإلا
			printf("The agent has no identities.\n");
		إرجاع -1;
	}
	لكل (i = 0; i < idlist->nkeys; i++) {
		إذا (do_fp) {
			fp = sshkey_fingerprint(idlist->مفاتيح[i],
			    fingerprint_hash, SSH_FP_DEFAULT);
			printf("%u %s %s (%s)\n", sshkey_size(idlist->مفاتيح[i]),
			    fp == عدم ? "(null)" : fp, idlist->comments[i],
			    sshkey_type(idlist->مفاتيح[i]));
			حرر(fp);
		} وإلا {
			إذا ((r = sshkey_write(idlist->مفاتيح[i], stdout)) != 0) {
				fprintf(stderr, "sshkey_write: %s\n",
				    ssh_err(r));
				استمر;
			}
			fprintf(stdout, " %s\n", idlist->comments[i]);
		}
	}
	ssh_free_identitylist(idlist);
	إرجاع 0;
}

ساكن صحيح
lock_agent(صحيح agent_fd, صحيح lock)
{
	حرف prompt[100], *p1, *p2;
	صحيح r, passok = 1, ret = -1;

	strlcpy(prompt, "Enter lock password: ", حجم(prompt));
	p1 = read_passphrase(prompt, RP_ALLOW_STDIN);
	إذا (lock) {
		strlcpy(prompt, "Again: ", حجم prompt);
		p2 = read_passphrase(prompt, RP_ALLOW_STDIN);
		إذا (strcmp(p1, p2) != 0) {
			fprintf(stderr, "Passwords do not match.\n");
			passok = 0;
		}
		freezero(p2, strlen(p2));
	}
	إذا (passok) {
		إذا ((r = ssh_lock_agent(agent_fd, lock, p1)) == 0) {
			fprintf(stderr, "Agent %slocked.\n", lock ? "" : "un");
			ret = 0;
		} وإلا {
			fprintf(stderr, "Failed to %slock agent: %s\n",
			    lock ? "" : "un", ssh_err(r));
		}
	}
	freezero(p1, strlen(p1));
	إرجاع (ret);
}

ساكن صحيح
load_resident_مفاتيح(صحيح agent_fd, ثابت حرف *skprovider, صحيح qflag, صحيح no_pin,
    بنية dest_constraint **dest_constraints, size_t ndest_constraints)
{
	بنية sshsk_resident_مفتاح **srks;
	size_t nsrks, i;
	بنية sshkey *مفتاح;
	صحيح r, ok = 0;
	حرف *fp, *pin = عدم;

	إذا (!no_pin) {
		pin = read_passphrase("Enter PIN for authenticator: ",
		    RP_ALLOW_STDIN);
	}
	إذا ((r = sshsk_load_resident(skprovider, عدم, pin == عدم ? "" : pin,
	    0, &srks, &nsrks)) != 0) {
		error_r(r, "Unable to load resident keys");
		حرر(pin);
		إرجاع r;
	}
	حرر(pin);
	لكل (i = 0; i < nsrks; i++) {
		مفتاح = srks[i]->مفتاح;
		إذا ((fp = sshkey_fingerprint(مفتاح,
		    fingerprint_hash, SSH_FP_DEFAULT)) == عدم)
			fatal_f("sshkey_fingerprint failed");
		إذا ((r = ssh_add_identity_constrained(agent_fd, مفتاح,
		    مفتاح->sk_application, lifetime, confirm, skprovider,
		    dest_constraints, ndest_constraints)) != 0) {
			error("Unable to add key %s %s",
			    sshkey_type(مفتاح), fp);
			حرر(fp);
			ok = r;
			استمر;
		}
		إذا (ok == 0)
			ok = 1;
		إذا (!qflag) {
			fprintf(stderr, "Resident identity added: %s %s\n",
			    sshkey_type(مفتاح), fp);
			إذا (lifetime != 0) {
				fprintf(stderr,
				    "Lifetime set to %d seconds\n", lifetime);
			}
			إذا (confirm != 0) {
				fprintf(stderr, "The user must confirm "
				    "each use of the key\n");
			}
		}
		حرر(fp);
	}
	sshsk_free_resident_مفاتيح(srks, nsrks);
	إذا (nsrks == 0)
		إرجاع SSH_ERR_مفتاح_NOT_FOUND;
	إرجاع ok == 1 ? 0 : ok;
}

ساكن صحيح
do_file(صحيح agent_fd, صحيح deleting, صحيح مفتاح_only, صحيح cert_only,
    حرف *file, صحيح qflag, صحيح Nflag, ثابت حرف *skprovider,
    بنية dest_constraint **dest_constraints, size_t ndest_constraints)
{
	إذا (deleting) {
		إذا (delete_file(agent_fd, file, مفتاح_only,
		    cert_only, qflag) == -1)
			إرجاع -1;
	} وإلا {
		إذا (add_file(agent_fd, file, مفتاح_only, cert_only, qflag, Nflag,
		    skprovider, dest_constraints, ndest_constraints) == -1)
			إرجاع -1;
	}
	إرجاع 0;
}

ساكن فراغ
free_dest_constraint_hop(بنية dest_constraint_hop *dch)
{
	u_int i;

	إذا (dch == عدم)
		إرجاع;
	حرر(dch->user);
	حرر(dch->hostname);
	لكل (i = 0; i < dch->nkeys; i++)
		sshkey_free(dch->مفاتيح[i]);
	حرر(dch->مفاتيح);
	حرر(dch->مفتاح_is_ca);
}

ساكن فراغ
free_dest_constraints(بنية dest_constraint **dcs, size_t ndcs)
{
	size_t i;

	لكل (i = 0; i < ndcs; i++) {
		free_dest_constraint_hop(&dcs[i]->from);
		free_dest_constraint_hop(&dcs[i]->to);
		حرر(dcs[i]);
	}
	حرر(dcs);
}


ساكن فراغ
parse_dest_constraint_hop(ثابت حرف *s, بنية dest_constraint_hop *dch,
    حرف **hostkey_files)
{
	حرف *user = عدم, *host, *os, *path;
	size_t i;
	بنية hostkeys *hostkeys;
	ثابت بنية hostkey_entry *hke;
	صحيح r, want_ca;

	memset(dch, '\0', حجم(*dch));
	os = xstrdup(s);
	إذا ((host = strrchr(os, '@')) == عدم)
		host = os;
	وإلا {
		*host++ = '\0';
		user = os;
	}
	cleanhostname(host);
	/* Trivial case: username@ (all hosts) */
	إذا (*host == '\0') {
		إذا (user == عدم) {
			fatal("Invalid key destination constraint \"%s\": "
			    "does not specify user or host", s);
		}
		dch->user = xstrdup(user);
		/* other fields left blank */
		حرر(os);
		إرجاع;
	}
	إذا (hostkey_files == عدم)
		fatal_f("no hostkey files");
	/* Otherwise we need to look up the keys for this hostname */
	hostkeys = init_hostkeys();
	لكل (i = 0; hostkey_files[i]; i++) {
		path = tilde_expand_filename(hostkey_files[i], getuid());
		debug2_f("looking up host keys for \"%s\" in %s", host, path);
                load_hostkeys(hostkeys, host, path, 0);
		حرر(path);
	}
	dch->user = user == عدم ? عدم : xstrdup(user);
	dch->hostname = xstrdup(host);
	لكل (i = 0; i < hostkeys->رقم_entries; i++) {
		hke = hostkeys->entries + i;
		want_ca = hke->marker == MRK_CA;
		إذا (hke->marker != MRK_NONE && !want_ca)
			استمر;
		debug3_f("%s%s%s: adding %s %skey from %s:%lu as key %u",
		    user == عدم ? "": user, user == عدم ? "" : "@",
		    host, sshkey_type(hke->مفتاح), want_ca ? "CA " : "",
		    hke->file, hke->سطر, dch->nkeys);
		dch->مفاتيح = xrecallocarray(dch->مفاتيح, dch->nkeys,
		    dch->nkeys + 1, حجم(*dch->مفاتيح));
		dch->مفتاح_is_ca = xrecallocarray(dch->مفتاح_is_ca, dch->nkeys,
		    dch->nkeys + 1, حجم(*dch->مفتاح_is_ca));
		إذا ((r = sshkey_from_private(hke->مفتاح,
		    &(dch->مفاتيح[dch->nkeys]))) != 0)
			fatal_fr(r, "sshkey_from_private");
		dch->مفتاح_is_ca[dch->nkeys] = want_ca;
		dch->nkeys++;
	}
	إذا (dch->nkeys == 0)
		fatal("No host keys found for destination \"%s\"", host);
	free_hostkeys(hostkeys);
	حرر(os);
	إرجاع;
}

ساكن فراغ
parse_dest_constraint(ثابت حرف *s, بنية dest_constraint ***dcp,
    size_t *ndcp, حرف **hostkey_files)
{
	بنية dest_constraint *dc;
	حرف *os, *cp;

	dc = xcalloc(1, حجم(*dc));
	os = xstrdup(s);
	إذا ((cp = strchr(os, '>')) == عدم) {
		/* initial hop; no 'from' hop specified */
		parse_dest_constraint_hop(os, &dc->to, hostkey_files);
	} وإلا {
		/* two hops specified */
		*(cp++) = '\0';
		parse_dest_constraint_hop(os, &dc->from, hostkey_files);
		parse_dest_constraint_hop(cp, &dc->to, hostkey_files);
		إذا (dc->from.user != عدم) {
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
	*dcp = xrecallocarray(*dcp, *ndcp, *ndcp + 1, حجم(**dcp));
	(*dcp)[(*ndcp)++] = dc;
	حرر(os);
}


ساكن فراغ
usage(فراغ)
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

صحيح
الرئيسية(صحيح argc, حرف **argv)
{
	خارجي حرف *optarg;
	خارجي صحيح optind;
	صحيح agent_fd = -1;
	حرف *pkcs11provider = عدم, *skprovider = عدم;
	حرف **dest_constraint_strings = عدم, **hostkey_files = عدم;
	صحيح r, i, ch, deleting = 0, ret = 0, مفتاح_only = 0, cert_only = 0;
	صحيح do_download = 0, xflag = 0, lflag = 0, Dflag = 0;
	صحيح Qflag = 0, qflag = 0, Tflag = 0, Nflag = 0, no_pin = 0;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_INFO;
	بنية sshkey *k, **certs = عدم;
	بنية dest_constraint **dest_constraints = عدم;
	size_t n, ndest_constraints = 0, ncerts = 0;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	__progname = ssh_get_progname(argv[0]);
	seed_rng();

	log_init(__progname, log_level, log_facility, 1);

	setvbuf(stdout, عدم, _IOLBF, 0);

	skprovider = getenv("SSH_SK_PROVIDER");

	بينما ((ch = getopt(argc, argv, "vkKlLNPCcdDTxXE:e:h:H:M:m:Qqs:S:t:")) != -1) {
		بدل (ch) {
		حالة 'v':
			إذا (log_level == SYSLOG_LEVEL_INFO)
				log_level = SYSLOG_LEVEL_DEBUG1;
			وإلا إذا (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			اكسر;
		حالة 'N':
			Nflag = 1;
			اكسر;
		حالة 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			إذا (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			اكسر;
		حالة 'H':
			stringlist_append(&hostkey_files, optarg);
			اكسر;
		حالة 'h':
			stringlist_append(&dest_constraint_strings, optarg);
			اكسر;
		حالة 'k':
			مفتاح_only = 1;
			اكسر;
		حالة 'C':
			cert_only = 1;
			اكسر;
		حالة 'K':
			do_download = 1;
			اكسر;
		حالة 'l':
		حالة 'L':
			إذا (lflag != 0)
				fatal("-%c flag already specified", lflag);
			lflag = ch;
			اكسر;
		حالة 'x':
		حالة 'X':
			إذا (xflag != 0)
				fatal("-%c flag already specified", xflag);
			xflag = ch;
			اكسر;
		حالة 'c':
			confirm = 1;
			اكسر;
		حالة 'm':
		حالة 'M':
			/* deprecated */
			اكسر;
		حالة 'd':
			deleting = 1;
			اكسر;
		حالة 'P':
			no_pin = 1;
			اكسر;
		حالة 'D':
			Dflag = 1;
			اكسر;
		حالة 's':
			pkcs11provider = optarg;
			اكسر;
		حالة 'S':
			skprovider = optarg;
			اكسر;
		حالة 'e':
			deleting = 1;
			pkcs11provider = optarg;
			اكسر;
		حالة 't':
			إذا ((lifetime = convtime(optarg)) == -1 ||
			    lifetime < 0 || (u_long)lifetime > UINT32_MAX) {
				fprintf(stderr, "Invalid lifetime\n");
				ret = 1;
				اذهب done;
			}
			اكسر;
		حالة 'q':
			qflag = 1;
			اكسر;
		حالة 'Q':
			Qflag = 1;
			اكسر;
		حالة 'T':
			Tflag = 1;
			اكسر;
		افتراضي:
			usage();
			ret = 1;
			اذهب done;
		}
	}
	log_init(__progname, log_level, log_facility, 1);

	إذا ((xflag != 0) + (lflag != 0) + (Dflag != 0) + (Qflag != 0) > 1)
		fatal("Invalid combination of actions");

	/* First, get a connection to the authentication agent. */
	بدل (r = ssh_get_authentication_socket(&agent_fd)) {
	حالة 0:
		اكسر;
	حالة SSH_ERR_AGENT_NOT_PRESENT:
		fprintf(stderr, "Could not open a connection to your "
		    "authentication agent.\n");
		exit(2);
	افتراضي:
		fprintf(stderr, "Error connecting to agent: %s\n", ssh_err(r));
		exit(2);
	}

	إذا (xflag) {
		إذا (lock_agent(agent_fd, xflag == 'x' ? 1 : 0) == -1)
			ret = 1;
		اذهب done;
	} وإلا إذا (lflag) {
		إذا (list_identities(agent_fd, lflag == 'l' ? 1 : 0) == -1)
			ret = 1;
		اذهب done;
	} وإلا إذا (Dflag) {
		إذا (delete_all(agent_fd, qflag) == -1)
			ret = 1;
		اذهب done;
	} وإلا إذا (Qflag) {
		إذا (query_exts(agent_fd) == -1)
			ret = 1;
		اذهب done;
	}

#ifdef ENABLE_SK_INTERNAL
	إذا (skprovider == عدم)
		skprovider = "internal";
#endif

	إذا (hostkey_files == عدم) {
		/* use defaults from readconf.c */
		stringlist_append(&hostkey_files, _PATH_SSH_USER_HOSTFILE);
		stringlist_append(&hostkey_files, _PATH_SSH_USER_HOSTFILE2);
		stringlist_append(&hostkey_files, _PATH_SSH_SYSTEM_HOSTFILE);
		stringlist_append(&hostkey_files, _PATH_SSH_SYSTEM_HOSTFILE2);
	}
	إذا (dest_constraint_strings != عدم) {
		لكل (i = 0; dest_constraint_strings[i] != عدم; i++) {
			parse_dest_constraint(dest_constraint_strings[i],
			  &dest_constraints, &ndest_constraints, hostkey_files);
		}
	}

	argc -= optind;
	argv += optind;
	إذا (Tflag) {
		إذا (argc <= 0)
			fatal("no keys to test");
		لكل (r = i = 0; i < argc; i++)
			r |= test_مفتاح(agent_fd, argv[i]);
		ret = r == 0 ? 0 : 1;
		اذهب done;
	}
	إذا (pkcs11provider != عدم) {
		لكل (i = 0; i < argc; i++) {
			إذا ((r = sshkey_load_public(argv[i], &k, عدم)) != 0)
				fatal_fr(r, "load certificate %s", argv[i]);
			certs = xrecallocarray(certs, ncerts, ncerts + 1,
			    حجم(*certs));
			debug2("%s: %s", argv[i], sshkey_ssh_name(k));
			certs[ncerts++] = k;
		}
		debug2_f("loaded %zu certificates", ncerts);
		إذا (update_card(agent_fd, !deleting, pkcs11provider,
		    qflag, no_pin, مفتاح_only, cert_only,
		    dest_constraints, ndest_constraints,
		    certs, ncerts) == -1)
			ret = 1;
		لكل (n = 0; n < ncerts; n++)
			sshkey_free(certs[n]);
		حرر(certs);
		اذهب done;
	}
	إذا (do_download) {
		إذا (skprovider == عدم)
			fatal("Cannot download keys without provider");
		إذا (load_resident_مفاتيح(agent_fd, skprovider, qflag, no_pin,
		    dest_constraints, ndest_constraints) != 0)
			ret = 1;
		اذهب done;
	}
	إذا (argc == 0) {
		حرف buf[PATH_MAX];
		بنية passwd *pw;
		بنية stat st;
		صحيح تعداد_2 = 0;

		إذا ((pw = getpwuid(getuid())) == عدم) {
			fprintf(stderr, "No user found with uid %u\n",
			    (u_int)getuid());
			ret = 1;
			اذهب done;
		}

		لكل (i = 0; default_files[i]; i++) {
			snprintf(buf, حجم(buf), "%s/%s", pw->pw_dir,
			    default_files[i]);
			إذا (stat(buf, &st) == -1)
				استمر;
			إذا (do_file(agent_fd, deleting, مفتاح_only, cert_only,
			    buf, qflag, Nflag, skprovider,
			    dest_constraints, ndest_constraints) == -1)
				ret = 1;
			وإلا
				تعداد_2++;
		}
		إذا (تعداد_2 == 0)
			ret = 1;
	} وإلا {
		لكل (i = 0; i < argc; i++) {
			إذا (do_file(agent_fd, deleting, مفتاح_only, cert_only,
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
	إرجاع ret;
}
