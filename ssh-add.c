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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/stat.h>

#ifdef WITH_OPENSSL
# include <openssl/evp.h>
# include "openbsd-compat/openssl-compat.h"
#endif

#شامل <errno.h>
#شامل <fcntl.h>
#شامل <pwd.h>
#شامل <stdarg.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <unistd.h>
#شامل <limits.h>
#شامل <time.h>

#شامل "xmalloc.h"
#شامل "ssh.h"
#شامل "log.h"
#شامل "sshkey.h"
#شامل "sshbuf.h"
#شامل "authfd.h"
#شامل "authfile.h"
#شامل "pathnames.h"
#شامل "misc.h"
#شامل "ssherr.h"
#شامل "digest.h"
#شامل "ssh-sk.h"
#شامل "sk-api.h"
#شامل "hostfile.h"

#define CERT_EXPIRY_GRACE	(5*60)

/* argv0 */
بیرونی نویسه *__progname;

/* Default files to add */
ایستا نویسه *default_files[] = {
#ifdef WITH_OPENSSL
	_PATH_SSH_CLIENT_ID_RSA,
	_PATH_SSH_CLIENT_ID_ECDSA,
	_PATH_SSH_CLIENT_ID_ECDSA_SK,
#endif /* WITH_OPENSSL */
	_PATH_SSH_CLIENT_ID_ED25519,
	_PATH_SSH_CLIENT_ID_ED25519_SK,
	_PATH_SSH_CLIENT_ID_MLDSA44_ED25519,
	پوچ
};

ایستا صحیح fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* Default lifetime (0 == forever) */
ایستا صحیح lifetime = 0;

/* User has to confirm key use */
ایستا صحیح confirm = 0;

/* we keep a cache of one passphrase */
ایستا نویسه *pass = پوچ;
ایستا تهی
clear_pass(تهی)
{
	اگر (pass) {
		freezero(pass, strlen(pass));
		pass = پوچ;
	}
}

ایستا صحیح
delete_one(صحیح agent_fd, ثابت ساختار sshkey *کلید, ثابت نویسه *comment,
    ثابت نویسه *path, صحیح qflag)
{
	صحیح r;

	اگر ((r = ssh_remove_identity(agent_fd, کلید)) != 0) {
		fprintf(stderr, "Could not remove identity \"%s\": %s\n",
		    path, ssh_err(r));
		بازگشت r;
	}
	اگر (!qflag) {
		fprintf(stderr, "Identity removed: %s %s (%s)\n", path,
		    sshkey_type(کلید), comment ? comment : "no comment");
	}
	بازگشت 0;
}

ایستا صحیح
delete_stdin(صحیح agent_fd, صحیح qflag, صحیح کلید_only, صحیح cert_only)
{
	نویسه *سطر = پوچ, *cp;
	size_t linesize = 0;
	ساختار sshkey *کلید = پوچ;
	صحیح lnum = 0, r, ret = -1;

	وقتی (getline(&سطر, &linesize, stdin) != -1) {
		lnum++;
		sshkey_free(کلید);
		کلید = پوچ;
		سطر[strcspn(سطر, "\n")] = '\0';
		cp = سطر + strspn(سطر, " \t");
		اگر (*cp == '#' || *cp == '\0')
			ادامه;
		اگر ((کلید = sshkey_new(کلید_UNSPEC)) == پوچ)
			fatal_f("sshkey_new");
		اگر ((r = sshkey_read(کلید, &cp)) != 0) {
			error_r(r, "(stdin):%d: invalid key", lnum);
			ادامه;
		}
		اگر ((!کلید_only && !cert_only) ||
		    (کلید_only && !sshkey_is_cert(کلید)) ||
		    (cert_only && sshkey_is_cert(کلید))) {
			اگر (delete_one(agent_fd, کلید, cp,
			    "(stdin)", qflag) == 0)
				ret = 0;
		}
	}
	sshkey_free(کلید);
	آزاد(سطر);
	بازگشت ret;
}

ایستا صحیح
delete_file(صحیح agent_fd, ثابت نویسه *filename, صحیح کلید_only,
    صحیح cert_only, صحیح qflag)
{
	ساختار sshkey *عمومی, *cert = پوچ;
	نویسه *certpath = پوچ, *comment = پوچ;
	صحیح r, ret = -1;

	اگر (strcmp(filename, "-") == 0)
		بازگشت delete_stdin(agent_fd, qflag, کلید_only, cert_only);

	اگر ((r = sshkey_load_public(filename, &عمومی,  &comment)) != 0) {
		printf("Bad key file %s: %s\n", filename, ssh_err(r));
		بازگشت -1;
	}
	اگر ((!کلید_only && !cert_only) ||
	    (کلید_only && !sshkey_is_cert(عمومی)) ||
	    (cert_only && sshkey_is_cert(عمومی))) {
		اگر (delete_one(agent_fd, عمومی, comment, filename, qflag) == 0)
			ret = 0;
	}

	اگر (کلید_only)
		برو out;

	/* Now try to delete the corresponding certificate too */
	آزاد(comment);
	comment = پوچ;
	xasprintf(&certpath, "%s-cert.pub", filename);
	اگر ((r = sshkey_load_public(certpath, &cert, &comment)) != 0) {
		اگر (r != SSH_ERR_SYSTEM_ERROR || errno != ENOENT)
			error_r(r, "Failed to load certificate \"%s\"", certpath);
		برو out;
	}

	اگر (!sshkey_equal_public(cert, عمومی))
		fatal("Certificate %s does not match private key %s",
		    certpath, filename);

	اگر (delete_one(agent_fd, cert, comment, certpath, qflag) == 0)
		ret = 0;

 out:
	sshkey_free(cert);
	sshkey_free(عمومی);
	آزاد(certpath);
	آزاد(comment);

	بازگشت ret;
}

/* Send a request to remove all identities. */
ایستا صحیح
delete_all(صحیح agent_fd, صحیح qflag)
{
	صحیح ret = -1;

	/*
	 * Since the agent might be forwarded, old or non-OpenSSH, when asked
	 * to remove all keys, attempt to remove both protocol v.1 and v.2
	 * keys.
	 */
	اگر (ssh_remove_all_identities(agent_fd, 2) == 0)
		ret = 0;
	/* ignore error-code for ssh1 */
	ssh_remove_all_identities(agent_fd, 1);

	اگر (ret != 0)
		fprintf(stderr, "Failed to remove all identities.\n");
	وگرنه اگر (!qflag)
		fprintf(stderr, "All identities removed.\n");

	بازگشت ret;
}

ایستا صحیح
query_exts(صحیح agent_fd)
{
	صحیح r;
	نویسه **exts = پوچ;
	size_t i;

	اگر ((r = ssh_agent_query_extensions(agent_fd, &exts)) != 0)
		fatal_r(r, "unable to query supported extensions");
	برای (i = 0; exts != پوچ && exts[i] != پوچ; i++)
		puts(exts[i]);
	stringlist_free(exts);
	بازگشت 0;
}

ایستا صحیح
check_cert_lifetime(ثابت ساختار sshkey *cert, صحیح cert_lifetime)
{
	time_t now;
	uint64_t n;

	اگر (cert == پوچ || cert->cert == پوچ || !sshkey_is_cert(cert) ||
	    cert->cert->valid_before == 0xFFFFFFFFFFFFFFFFULL)
		بازگشت cert_lifetime;
	اگر ((now = time(پوچ)) <= 0)
		fatal_f("system time is at/before epoch");
	اگر ((uint64_t)now > (cert->cert->valid_before + CERT_EXPIRY_GRACE))
		بازگشت -1; /* certificate already expired */
	n = (CERT_EXPIRY_GRACE + cert->cert->valid_before) - (uint64_t)now;
	n = MINIMUM(n, INT_MAX);
	اگر (cert_lifetime <= 0)
		بازگشت (صحیح)n;
	بازگشت MINIMUM(cert_lifetime, (صحیح)n);
}

ایستا صحیح
add_file(صحیح agent_fd, ثابت نویسه *filename, صحیح کلید_only, صحیح cert_only,
    صحیح qflag, صحیح Nflag, ثابت نویسه *skprovider,
    ساختار dest_constraint **dest_constraints,
    size_t ndest_constraints)
{
	ساختار sshkey *خصوصی = پوچ, *cert = پوچ;
	نویسه *comment = پوچ;
	نویسه پیام[1024], *certpath = پوچ;
	صحیح cert_lifetime, r, fd, ret = -1;
	ساختار sshbuf *keyblob;

	اگر (strcmp(filename, "-") == 0) {
		fd = STDIN_FILENO;
		filename = "(stdin)";
	} وگرنه اگر ((fd = open(filename, O_RDONLY)) == -1) {
		perror(filename);
		بازگشت -1;
	}

	/*
	 * Since we'll try to load a keyfile multiple times, permission errors
	 * will occur multiple times, so check perms first and bail if wrong.
	 */
	اگر (fd != STDIN_FILENO) {
		اگر (sshkey_perm_ok(fd, filename) != 0) {
			close(fd);
			بازگشت -1;
		}
	}
	اگر ((r = sshbuf_load_fd(fd, &keyblob)) != 0) {
		fprintf(stderr, "Error loading key \"%s\": %s\n",
		    filename, ssh_err(r));
		sshbuf_free(keyblob);
		close(fd);
		بازگشت -1;
	}
	close(fd);

	/* At first, try empty passphrase */
	اگر ((r = sshkey_parse_private_fileblob(keyblob, "", &خصوصی,
	    &comment)) != 0 && r != SSH_ERR_کلید_WRONG_PASSPHRASE) {
		fprintf(stderr, "Error loading key \"%s\": %s\n",
		    filename, ssh_err(r));
		برو fail_load;
	}
	/* try last */
	اگر (خصوصی == پوچ && pass != پوچ) {
		اگر ((r = sshkey_parse_private_fileblob(keyblob, pass, &خصوصی,
		    &comment)) != 0 && r != SSH_ERR_کلید_WRONG_PASSPHRASE) {
			fprintf(stderr, "Error loading key \"%s\": %s\n",
			    filename, ssh_err(r));
			برو fail_load;
		}
	}
	اگر (خصوصی == پوچ) {
		/* clear passphrase since it did not work */
		clear_pass();
		snprintf(پیام, اندازه پیام, "Enter passphrase for %s%s: ",
		    filename, confirm ? " (will confirm each use)" : "");
		برای (;;) {
			pass = read_passphrase(پیام, RP_ALLOW_STDIN);
			اگر (strcmp(pass, "") == 0)
				برو fail_load;
			اگر ((r = sshkey_parse_private_fileblob(keyblob, pass,
			    &خصوصی, &comment)) == 0)
				بشکن;
			وگرنه اگر (r != SSH_ERR_کلید_WRONG_PASSPHRASE) {
				fprintf(stderr,
				    "Error loading key \"%s\": %s\n",
				    filename, ssh_err(r));
 fail_load:
				clear_pass();
				sshbuf_free(keyblob);
				بازگشت -1;
			}
			clear_pass();
			snprintf(پیام, اندازه پیام,
			    "Bad passphrase, try again for %s%s: ", filename,
			    confirm ? " (will confirm each use)" : "");
		}
	}
	اگر (comment == پوچ || *comment == '\0')
		comment = xstrdup(filename);
	sshbuf_free(keyblob);

	اگر (sshkey_is_sk(خصوصی)) {
		اگر (skprovider == پوچ) {
			fprintf(stderr, "Cannot load FIDO key %s "
			    "without provider\n", filename);
			برو out;
		}
	} وگرنه {
		/* Don't send provider constraint for other keys */
		skprovider = پوچ;
	}

	اگر (!cert_only) {
		اگر ((r = ssh_add_identity_constrained(agent_fd, خصوصی,
		    comment, lifetime, confirm, skprovider,
		    dest_constraints, ndest_constraints)) == 0) {
			ret = 0;
			اگر (!qflag) {
				fprintf(stderr, "Identity added: %s (%s)\n",
				    filename, comment);
				اگر (lifetime != 0) {
					fprintf(stderr, "Lifetime set to %s\n",
					    fmt_timeframe((time_t)lifetime));
				}
				اگر (confirm != 0) {
					fprintf(stderr, "The user must confirm "
					    "each use of the key\n");
				}
			}
		} وگرنه {
			fprintf(stderr, "Could not add identity \"%s\": %s\n",
			    filename, ssh_err(r));
		}
	}

	/* Skip trying to load the cert if requested */
	اگر (کلید_only)
		برو out;

	/* Now try to add the certificate flavour too */
	xasprintf(&certpath, "%s-cert.pub", filename);
	اگر ((r = sshkey_load_public(certpath, &cert, پوچ)) != 0) {
		اگر (r != SSH_ERR_SYSTEM_ERROR || errno != ENOENT)
			error_r(r, "Failed to load certificate \"%s\"",
			    certpath);
		برو out;
	}

	اگر (!sshkey_equal_public(cert, خصوصی)) {
		error("Certificate %s does not match private key %s",
		    certpath, filename);
		برو out;
	}

	cert_lifetime = lifetime;
	اگر (!Nflag &&
	    (cert_lifetime = check_cert_lifetime(cert, cert_lifetime)) == -1) {
		logit("Certificate %s has already expired; ignored", certpath);
		برو out;
	}

	/* Graft with private bits */
	اگر ((r = sshkey_to_certified(خصوصی)) != 0) {
		error_fr(r, "sshkey_to_certified");
		برو out;
	}
	اگر ((r = sshkey_cert_copy(cert, خصوصی)) != 0) {
		error_fr(r, "sshkey_cert_copy");
		برو out;
	}
	/* send to agent */
	اگر ((r = ssh_add_identity_constrained(agent_fd, خصوصی, comment,
	    cert_lifetime, confirm, skprovider,
	    dest_constraints, ndest_constraints)) != 0) {
		error_r(r, "Certificate %s (%s) add failed", certpath,
		    خصوصی->cert->کلید_id);
		برو out;
	}
	/* success */
	اگر (!qflag) {
		fprintf(stderr, "Certificate added: %s (%s)\n", certpath,
		    خصوصی->cert->کلید_id);
		اگر (cert_lifetime != 0) {
			fprintf(stderr, "Lifetime set to %s\n",
			    fmt_timeframe((time_t)cert_lifetime));
		}
		اگر (confirm != 0) {
			fprintf(stderr, "The user must confirm each use "
			    "of the key\n");
		}
	}

 out:
	آزاد(certpath);
	آزاد(comment);
	sshkey_free(cert);
	sshkey_free(خصوصی);

	بازگشت ret;
}

ایستا صحیح
update_card(صحیح agent_fd, صحیح add, ثابت نویسه *id, صحیح qflag, صحیح no_pin,
    صحیح کلید_only, صحیح cert_only,
    ساختار dest_constraint **dest_constraints, size_t ndest_constraints,
    ساختار sshkey **certs, size_t ncerts)
{
	نویسه *pin = پوچ;
	صحیح r, ret = -1;

	اگر (کلید_only)
		ncerts = 0;

	اگر (add && !no_pin) {
		اگر ((pin = read_passphrase("Enter passphrase for PKCS#11: ",
		    RP_ALLOW_STDIN)) == پوچ)
			بازگشت -1;
	}

	اگر ((r = ssh_update_card(agent_fd, add, id, pin == پوچ ? "" : pin,
	    lifetime, confirm, dest_constraints, ndest_constraints,
	    cert_only, certs, ncerts)) == 0) {
		ret = 0;
		اگر (!qflag) {
			fprintf(stderr, "Card %s: %s\n",
			    add ? "added" : "removed", id);
		}
	} وگرنه {
		fprintf(stderr, "Could not %s card \"%s\": %s\n",
		    add ? "add" : "remove", id, ssh_err(r));
		ret = -1;
	}
	آزاد(pin);
	بازگشت ret;
}

ایستا صحیح
test_کلید(صحیح agent_fd, ثابت نویسه *filename)
{
	ساختار sshkey *کلید = پوچ;
	u_char *sig = پوچ;
	ثابت نویسه *alg = پوچ;
	size_t slen = 0;
	صحیح r, ret = -1;
	نویسه data[1024];

	اگر ((r = sshkey_load_public(filename, &کلید, پوچ)) != 0) {
		error_r(r, "Couldn't read public key %s", filename);
		بازگشت -1;
	}
	اگر (sshkey_type_plain(کلید->type) == کلید_RSA)
		alg = "rsa-sha2-256";
	arc4random_buf(data, اندازه(data));
	اگر ((r = ssh_agent_sign(agent_fd, کلید, &sig, &slen, data, اندازه(data),
	    alg, 0)) != 0) {
		error_r(r, "Agent signature failed for %s", filename);
		برو done;
	}
	اگر ((r = sshkey_verify(کلید, sig, slen, data, اندازه(data),
	    alg, 0, پوچ)) != 0) {
		error_r(r, "Signature verification failed for %s", filename);
		برو done;
	}
	/* success */
	ret = 0;
 done:
	آزاد(sig);
	sshkey_free(کلید);
	بازگشت ret;
}

ایستا صحیح
list_identities(صحیح agent_fd, صحیح do_fp)
{
	نویسه *fp;
	صحیح r;
	ساختار ssh_identitylist *idlist;
	size_t i;

	اگر ((r = ssh_fetch_identitylist(agent_fd, &idlist)) != 0) {
		اگر (r != SSH_ERR_AGENT_NO_IDENTITIES)
			fprintf(stderr, "error fetching identities: %s\n",
			    ssh_err(r));
		وگرنه
			printf("The agent has no identities.\n");
		بازگشت -1;
	}
	برای (i = 0; i < idlist->nkeys; i++) {
		اگر (do_fp) {
			fp = sshkey_fingerprint(idlist->کلیدها[i],
			    fingerprint_hash, SSH_FP_DEFAULT);
			printf("%u %s %s (%s)\n", sshkey_size(idlist->کلیدها[i]),
			    fp == پوچ ? "(null)" : fp, idlist->comments[i],
			    sshkey_type(idlist->کلیدها[i]));
			آزاد(fp);
		} وگرنه {
			اگر ((r = sshkey_write(idlist->کلیدها[i], stdout)) != 0) {
				fprintf(stderr, "sshkey_write: %s\n",
				    ssh_err(r));
				ادامه;
			}
			fprintf(stdout, " %s\n", idlist->comments[i]);
		}
	}
	ssh_free_identitylist(idlist);
	بازگشت 0;
}

ایستا صحیح
lock_agent(صحیح agent_fd, صحیح lock)
{
	نویسه prompt[100], *p1, *p2;
	صحیح r, passok = 1, ret = -1;

	strlcpy(prompt, "Enter lock password: ", اندازه(prompt));
	p1 = read_passphrase(prompt, RP_ALLOW_STDIN);
	اگر (lock) {
		strlcpy(prompt, "Again: ", اندازه prompt);
		p2 = read_passphrase(prompt, RP_ALLOW_STDIN);
		اگر (strcmp(p1, p2) != 0) {
			fprintf(stderr, "Passwords do not match.\n");
			passok = 0;
		}
		freezero(p2, strlen(p2));
	}
	اگر (passok) {
		اگر ((r = ssh_lock_agent(agent_fd, lock, p1)) == 0) {
			fprintf(stderr, "Agent %slocked.\n", lock ? "" : "un");
			ret = 0;
		} وگرنه {
			fprintf(stderr, "Failed to %slock agent: %s\n",
			    lock ? "" : "un", ssh_err(r));
		}
	}
	freezero(p1, strlen(p1));
	بازگشت (ret);
}

ایستا صحیح
load_resident_کلیدها(صحیح agent_fd, ثابت نویسه *skprovider, صحیح qflag, صحیح no_pin,
    ساختار dest_constraint **dest_constraints, size_t ndest_constraints)
{
	ساختار sshsk_resident_کلید **srks;
	size_t nsrks, i;
	ساختار sshkey *کلید;
	صحیح r, ok = 0;
	نویسه *fp, *pin = پوچ;

	اگر (!no_pin) {
		pin = read_passphrase("Enter PIN for authenticator: ",
		    RP_ALLOW_STDIN);
	}
	اگر ((r = sshsk_load_resident(skprovider, پوچ, pin == پوچ ? "" : pin,
	    0, &srks, &nsrks)) != 0) {
		error_r(r, "Unable to load resident keys");
		آزاد(pin);
		بازگشت r;
	}
	آزاد(pin);
	برای (i = 0; i < nsrks; i++) {
		کلید = srks[i]->کلید;
		اگر ((fp = sshkey_fingerprint(کلید,
		    fingerprint_hash, SSH_FP_DEFAULT)) == پوچ)
			fatal_f("sshkey_fingerprint failed");
		اگر ((r = ssh_add_identity_constrained(agent_fd, کلید,
		    کلید->sk_application, lifetime, confirm, skprovider,
		    dest_constraints, ndest_constraints)) != 0) {
			error("Unable to add key %s %s",
			    sshkey_type(کلید), fp);
			آزاد(fp);
			ok = r;
			ادامه;
		}
		اگر (ok == 0)
			ok = 1;
		اگر (!qflag) {
			fprintf(stderr, "Resident identity added: %s %s\n",
			    sshkey_type(کلید), fp);
			اگر (lifetime != 0) {
				fprintf(stderr,
				    "Lifetime set to %d seconds\n", lifetime);
			}
			اگر (confirm != 0) {
				fprintf(stderr, "The user must confirm "
				    "each use of the key\n");
			}
		}
		آزاد(fp);
	}
	sshsk_free_resident_کلیدها(srks, nsrks);
	اگر (nsrks == 0)
		بازگشت SSH_ERR_کلید_NOT_FOUND;
	بازگشت ok == 1 ? 0 : ok;
}

ایستا صحیح
do_file(صحیح agent_fd, صحیح deleting, صحیح کلید_only, صحیح cert_only,
    نویسه *file, صحیح qflag, صحیح Nflag, ثابت نویسه *skprovider,
    ساختار dest_constraint **dest_constraints, size_t ndest_constraints)
{
	اگر (deleting) {
		اگر (delete_file(agent_fd, file, کلید_only,
		    cert_only, qflag) == -1)
			بازگشت -1;
	} وگرنه {
		اگر (add_file(agent_fd, file, کلید_only, cert_only, qflag, Nflag,
		    skprovider, dest_constraints, ndest_constraints) == -1)
			بازگشت -1;
	}
	بازگشت 0;
}

ایستا تهی
free_dest_constraint_hop(ساختار dest_constraint_hop *dch)
{
	u_int i;

	اگر (dch == پوچ)
		بازگشت;
	آزاد(dch->user);
	آزاد(dch->hostname);
	برای (i = 0; i < dch->nkeys; i++)
		sshkey_free(dch->کلیدها[i]);
	آزاد(dch->کلیدها);
	آزاد(dch->کلید_is_ca);
}

ایستا تهی
free_dest_constraints(ساختار dest_constraint **dcs, size_t ndcs)
{
	size_t i;

	برای (i = 0; i < ndcs; i++) {
		free_dest_constraint_hop(&dcs[i]->from);
		free_dest_constraint_hop(&dcs[i]->to);
		آزاد(dcs[i]);
	}
	آزاد(dcs);
}


ایستا تهی
parse_dest_constraint_hop(ثابت نویسه *s, ساختار dest_constraint_hop *dch,
    نویسه **hostkey_files)
{
	نویسه *user = پوچ, *host, *os, *path;
	size_t i;
	ساختار hostkeys *hostkeys;
	ثابت ساختار hostkey_entry *hke;
	صحیح r, want_ca;

	memset(dch, '\0', اندازه(*dch));
	os = xstrdup(s);
	اگر ((host = strrchr(os, '@')) == پوچ)
		host = os;
	وگرنه {
		*host++ = '\0';
		user = os;
	}
	cleanhostname(host);
	/* Trivial case: username@ (all hosts) */
	اگر (*host == '\0') {
		اگر (user == پوچ) {
			fatal("Invalid key destination constraint \"%s\": "
			    "does not specify user or host", s);
		}
		dch->user = xstrdup(user);
		/* other fields left blank */
		آزاد(os);
		بازگشت;
	}
	اگر (hostkey_files == پوچ)
		fatal_f("no hostkey files");
	/* Otherwise we need to look up the keys for this hostname */
	hostkeys = init_hostkeys();
	برای (i = 0; hostkey_files[i]; i++) {
		path = tilde_expand_filename(hostkey_files[i], getuid());
		debug2_f("looking up host keys for \"%s\" in %s", host, path);
                load_hostkeys(hostkeys, host, path, 0);
		آزاد(path);
	}
	dch->user = user == پوچ ? پوچ : xstrdup(user);
	dch->hostname = xstrdup(host);
	برای (i = 0; i < hostkeys->رقم_entries; i++) {
		hke = hostkeys->entries + i;
		want_ca = hke->marker == MRK_CA;
		اگر (hke->marker != MRK_NONE && !want_ca)
			ادامه;
		debug3_f("%s%s%s: adding %s %skey from %s:%lu as key %u",
		    user == پوچ ? "": user, user == پوچ ? "" : "@",
		    host, sshkey_type(hke->کلید), want_ca ? "CA " : "",
		    hke->file, hke->سطر, dch->nkeys);
		dch->کلیدها = xrecallocarray(dch->کلیدها, dch->nkeys,
		    dch->nkeys + 1, اندازه(*dch->کلیدها));
		dch->کلید_is_ca = xrecallocarray(dch->کلید_is_ca, dch->nkeys,
		    dch->nkeys + 1, اندازه(*dch->کلید_is_ca));
		اگر ((r = sshkey_from_private(hke->کلید,
		    &(dch->کلیدها[dch->nkeys]))) != 0)
			fatal_fr(r, "sshkey_from_private");
		dch->کلید_is_ca[dch->nkeys] = want_ca;
		dch->nkeys++;
	}
	اگر (dch->nkeys == 0)
		fatal("No host keys found for destination \"%s\"", host);
	free_hostkeys(hostkeys);
	آزاد(os);
	بازگشت;
}

ایستا تهی
parse_dest_constraint(ثابت نویسه *s, ساختار dest_constraint ***dcp,
    size_t *ndcp, نویسه **hostkey_files)
{
	ساختار dest_constraint *dc;
	نویسه *os, *cp;

	dc = xcalloc(1, اندازه(*dc));
	os = xstrdup(s);
	اگر ((cp = strchr(os, '>')) == پوچ) {
		/* initial hop; no 'from' hop specified */
		parse_dest_constraint_hop(os, &dc->to, hostkey_files);
	} وگرنه {
		/* two hops specified */
		*(cp++) = '\0';
		parse_dest_constraint_hop(os, &dc->from, hostkey_files);
		parse_dest_constraint_hop(cp, &dc->to, hostkey_files);
		اگر (dc->from.user != پوچ) {
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
	*dcp = xrecallocarray(*dcp, *ndcp, *ndcp + 1, اندازه(**dcp));
	(*dcp)[(*ndcp)++] = dc;
	آزاد(os);
}


ایستا تهی
usage(تهی)
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

صحیح
اصلی(صحیح argc, نویسه **argv)
{
	بیرونی نویسه *optarg;
	بیرونی صحیح optind;
	صحیح agent_fd = -1;
	نویسه *pkcs11provider = پوچ, *skprovider = پوچ;
	نویسه **dest_constraint_strings = پوچ, **hostkey_files = پوچ;
	صحیح r, i, ch, deleting = 0, ret = 0, کلید_only = 0, cert_only = 0;
	صحیح do_download = 0, xflag = 0, lflag = 0, Dflag = 0;
	صحیح Qflag = 0, qflag = 0, Tflag = 0, Nflag = 0, no_pin = 0;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_INFO;
	ساختار sshkey *k, **certs = پوچ;
	ساختار dest_constraint **dest_constraints = پوچ;
	size_t n, ndest_constraints = 0, ncerts = 0;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	__progname = ssh_get_progname(argv[0]);
	seed_rng();

	log_init(__progname, log_level, log_facility, 1);

	setvbuf(stdout, پوچ, _IOLBF, 0);

	skprovider = getenv("SSH_SK_PROVIDER");

	وقتی ((ch = getopt(argc, argv, "vkKlLNPCcdDTxXE:e:h:H:M:m:Qqs:S:t:")) != -1) {
		انتخاب (ch) {
		حالت 'v':
			اگر (log_level == SYSLOG_LEVEL_INFO)
				log_level = SYSLOG_LEVEL_DEBUG1;
			وگرنه اگر (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			بشکن;
		حالت 'N':
			Nflag = 1;
			بشکن;
		حالت 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			اگر (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			بشکن;
		حالت 'H':
			stringlist_append(&hostkey_files, optarg);
			بشکن;
		حالت 'h':
			stringlist_append(&dest_constraint_strings, optarg);
			بشکن;
		حالت 'k':
			کلید_only = 1;
			بشکن;
		حالت 'C':
			cert_only = 1;
			بشکن;
		حالت 'K':
			do_download = 1;
			بشکن;
		حالت 'l':
		حالت 'L':
			اگر (lflag != 0)
				fatal("-%c flag already specified", lflag);
			lflag = ch;
			بشکن;
		حالت 'x':
		حالت 'X':
			اگر (xflag != 0)
				fatal("-%c flag already specified", xflag);
			xflag = ch;
			بشکن;
		حالت 'c':
			confirm = 1;
			بشکن;
		حالت 'm':
		حالت 'M':
			/* deprecated */
			بشکن;
		حالت 'd':
			deleting = 1;
			بشکن;
		حالت 'P':
			no_pin = 1;
			بشکن;
		حالت 'D':
			Dflag = 1;
			بشکن;
		حالت 's':
			pkcs11provider = optarg;
			بشکن;
		حالت 'S':
			skprovider = optarg;
			بشکن;
		حالت 'e':
			deleting = 1;
			pkcs11provider = optarg;
			بشکن;
		حالت 't':
			اگر ((lifetime = convtime(optarg)) == -1 ||
			    lifetime < 0 || (u_long)lifetime > UINT32_MAX) {
				fprintf(stderr, "Invalid lifetime\n");
				ret = 1;
				برو done;
			}
			بشکن;
		حالت 'q':
			qflag = 1;
			بشکن;
		حالت 'Q':
			Qflag = 1;
			بشکن;
		حالت 'T':
			Tflag = 1;
			بشکن;
		پیشفرض:
			usage();
			ret = 1;
			برو done;
		}
	}
	log_init(__progname, log_level, log_facility, 1);

	اگر ((xflag != 0) + (lflag != 0) + (Dflag != 0) + (Qflag != 0) > 1)
		fatal("Invalid combination of actions");

	/* First, get a connection to the authentication agent. */
	انتخاب (r = ssh_get_authentication_socket(&agent_fd)) {
	حالت 0:
		بشکن;
	حالت SSH_ERR_AGENT_NOT_PRESENT:
		fprintf(stderr, "Could not open a connection to your "
		    "authentication agent.\n");
		exit(2);
	پیشفرض:
		fprintf(stderr, "Error connecting to agent: %s\n", ssh_err(r));
		exit(2);
	}

	اگر (xflag) {
		اگر (lock_agent(agent_fd, xflag == 'x' ? 1 : 0) == -1)
			ret = 1;
		برو done;
	} وگرنه اگر (lflag) {
		اگر (list_identities(agent_fd, lflag == 'l' ? 1 : 0) == -1)
			ret = 1;
		برو done;
	} وگرنه اگر (Dflag) {
		اگر (delete_all(agent_fd, qflag) == -1)
			ret = 1;
		برو done;
	} وگرنه اگر (Qflag) {
		اگر (query_exts(agent_fd) == -1)
			ret = 1;
		برو done;
	}

#ifdef ENABLE_SK_INTERNAL
	اگر (skprovider == پوچ)
		skprovider = "internal";
#endif

	اگر (hostkey_files == پوچ) {
		/* use defaults from readconf.c */
		stringlist_append(&hostkey_files, _PATH_SSH_USER_HOSTFILE);
		stringlist_append(&hostkey_files, _PATH_SSH_USER_HOSTFILE2);
		stringlist_append(&hostkey_files, _PATH_SSH_SYSTEM_HOSTFILE);
		stringlist_append(&hostkey_files, _PATH_SSH_SYSTEM_HOSTFILE2);
	}
	اگر (dest_constraint_strings != پوچ) {
		برای (i = 0; dest_constraint_strings[i] != پوچ; i++) {
			parse_dest_constraint(dest_constraint_strings[i],
			  &dest_constraints, &ndest_constraints, hostkey_files);
		}
	}

	argc -= optind;
	argv += optind;
	اگر (Tflag) {
		اگر (argc <= 0)
			fatal("no keys to test");
		برای (r = i = 0; i < argc; i++)
			r |= test_کلید(agent_fd, argv[i]);
		ret = r == 0 ? 0 : 1;
		برو done;
	}
	اگر (pkcs11provider != پوچ) {
		برای (i = 0; i < argc; i++) {
			اگر ((r = sshkey_load_public(argv[i], &k, پوچ)) != 0)
				fatal_fr(r, "load certificate %s", argv[i]);
			certs = xrecallocarray(certs, ncerts, ncerts + 1,
			    اندازه(*certs));
			debug2("%s: %s", argv[i], sshkey_ssh_name(k));
			certs[ncerts++] = k;
		}
		debug2_f("loaded %zu certificates", ncerts);
		اگر (update_card(agent_fd, !deleting, pkcs11provider,
		    qflag, no_pin, کلید_only, cert_only,
		    dest_constraints, ndest_constraints,
		    certs, ncerts) == -1)
			ret = 1;
		برای (n = 0; n < ncerts; n++)
			sshkey_free(certs[n]);
		آزاد(certs);
		برو done;
	}
	اگر (do_download) {
		اگر (skprovider == پوچ)
			fatal("Cannot download keys without provider");
		اگر (load_resident_کلیدها(agent_fd, skprovider, qflag, no_pin,
		    dest_constraints, ndest_constraints) != 0)
			ret = 1;
		برو done;
	}
	اگر (argc == 0) {
		نویسه buf[PATH_MAX];
		ساختار passwd *pw;
		ساختار stat st;
		صحیح شمار = 0;

		اگر ((pw = getpwuid(getuid())) == پوچ) {
			fprintf(stderr, "No user found with uid %u\n",
			    (u_int)getuid());
			ret = 1;
			برو done;
		}

		برای (i = 0; default_files[i]; i++) {
			snprintf(buf, اندازه(buf), "%s/%s", pw->pw_dir,
			    default_files[i]);
			اگر (stat(buf, &st) == -1)
				ادامه;
			اگر (do_file(agent_fd, deleting, کلید_only, cert_only,
			    buf, qflag, Nflag, skprovider,
			    dest_constraints, ndest_constraints) == -1)
				ret = 1;
			وگرنه
				شمار++;
		}
		اگر (شمار == 0)
			ret = 1;
	} وگرنه {
		برای (i = 0; i < argc; i++) {
			اگر (do_file(agent_fd, deleting, کلید_only, cert_only,
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
	بازگشت ret;
}
