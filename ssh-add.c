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

#اگر_تعریف_شدہ WITH_OPENSSL
# include <openssl/evp.h>
# include "openbsd-compat/openssl-compat.h"
#اگر_ختم

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

#تعریف_کرو CERT_EXPIRY_GRACE	(5*60)

/* argv0 */
خارجی حرف *__progname;

/* Default files to add */
ساکن حرف *default_files[] = {
#اگر_تعریف_شدہ WITH_OPENSSL
	راستہ_SSH_CLIENT_ID_RSA,
	راستہ_SSH_CLIENT_ID_ECDSA,
	راستہ_SSH_CLIENT_ID_ECDSA_SK,
#اگر_ختم /* WITH_OPENSSL */
	راستہ_SSH_CLIENT_ID_ED25519,
	راستہ_SSH_CLIENT_ID_ED25519_SK,
	راستہ_SSH_CLIENT_ID_MLDSA44_ED25519,
	تہی
};

ساکن صحیح fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* Default lifetime (0 == forever) */
ساکن صحیح lifetime = 0;

/* User has to confirm key use */
ساکن صحیح confirm = 0;

/* we keep a cache of one passphrase */
ساکن حرف *pass = تہی;
ساکن خالی
clear_pass(خالی)
{
	اگر (pass) {
		freezero(pass, لڑی_لمبائی(pass));
		pass = تہی;
	}
}

ساکن صحیح
delete_one(صحیح agent_fd, ثابت ساخت sshkey *کلید, ثابت حرف *comment,
    ثابت حرف *راستہ, صحیح qflag)
{
	صحیح r;

	اگر ((r = ssh_remove_شناختی_عنصر(agent_fd, کلید)) != 0) {
		fprintf(stderr, "Could not remove identity \"%s\": %s\n",
		    راستہ, ssh_err(r));
		واپس r;
	}
	اگر (!qflag) {
		fprintf(stderr, "Identity removed: %s %s (%s)\n", راستہ,
		    sshkey_type(کلید), comment ? comment : "no comment");
	}
	واپس 0;
}

ساکن صحیح
delete_stdin(صحیح agent_fd, صحیح qflag, صحیح کلید_only, صحیح cert_only)
{
	حرف *سطر = تہی, *cp;
	سائز_t linesize = 0;
	ساخت sshkey *کلید = تہی;
	صحیح lnum = 0, r, ret = -1;

	جب (getline(&سطر, &linesize, stdin) != -1) {
		lnum++;
		sshkey_free(کلید);
		کلید = تہی;
		سطر[strcspn(سطر, "\n")] = '\0';
		cp = سطر + strspn(سطر, " \t");
		اگر (*cp == '#' || *cp == '\0')
			جاری;
		اگر ((کلید = sshkey_new(کلید_UNSPEC)) == تہی)
			fatal_f("sshkey_new");
		اگر ((r = sshkey_read(کلید, &cp)) != 0) {
			error_r(r, "(stdin):%d: invalid key", lnum);
			جاری;
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
	واپس ret;
}

ساکن صحیح
delete_file(صحیح agent_fd, ثابت حرف *filename, صحیح کلید_only,
    صحیح cert_only, صحیح qflag)
{
	ساخت sshkey *عوامی, *cert = تہی;
	حرف *certpath = تہی, *comment = تہی;
	صحیح r, ret = -1;

	اگر (strcmp(filename, "-") == 0)
		واپس delete_stdin(agent_fd, qflag, کلید_only, cert_only);

	اگر ((r = sshkey_بھرو_عوامی(filename, &عوامی,  &comment)) != 0) {
		لکھو("Bad key file %s: %s\n", filename, ssh_err(r));
		واپس -1;
	}
	اگر ((!کلید_only && !cert_only) ||
	    (کلید_only && !sshkey_is_cert(عوامی)) ||
	    (cert_only && sshkey_is_cert(عوامی))) {
		اگر (delete_one(agent_fd, عوامی, comment, filename, qflag) == 0)
			ret = 0;
	}

	اگر (کلید_only)
		جاؤ برآمد;

	/* Now try to delete the corresponding certificate too */
	آزاد(comment);
	comment = تہی;
	xasprintf(&certpath, "%s-cert.pub", filename);
	اگر ((r = sshkey_بھرو_عوامی(certpath, &cert, &comment)) != 0) {
		اگر (r != SSH_ERR_SYSTEM_ERROR || errno != ENOENT)
			error_r(r, "Failed to load certificate \"%s\"", certpath);
		جاؤ برآمد;
	}

	اگر (!sshkey_equal_عوامی(cert, عوامی))
		fatal("Certificate %s does not match private key %s",
		    certpath, filename);

	اگر (delete_one(agent_fd, cert, comment, certpath, qflag) == 0)
		ret = 0;

 برآمد:
	sshkey_free(cert);
	sshkey_free(عوامی);
	آزاد(certpath);
	آزاد(comment);

	واپس ret;
}

/* Send a request to remove all identities. */
ساکن صحیح
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
	ورنہ اگر (!qflag)
		fprintf(stderr, "All identities removed.\n");

	واپس ret;
}

ساکن صحیح
query_exts(صحیح agent_fd)
{
	صحیح r;
	حرف **exts = تہی;
	سائز_t i;

	اگر ((r = ssh_agent_query_extensions(agent_fd, &exts)) != 0)
		fatal_r(r, "unable to query supported extensions");
	برائے (i = 0; exts != تہی && exts[i] != تہی; i++)
		puts(exts[i]);
	stringlist_free(exts);
	واپس 0;
}

ساکن صحیح
check_cert_lifetime(ثابت ساخت sshkey *cert, صحیح cert_lifetime)
{
	time_t now;
	uint64_t n;

	اگر (cert == تہی || cert->cert == تہی || !sshkey_is_cert(cert) ||
	    cert->cert->valid_before == 0xFFFFFFFFFFFFFFFFULL)
		واپس cert_lifetime;
	اگر ((now = time(تہی)) <= 0)
		fatal_f("system time is at/before epoch");
	اگر ((uint64_t)now > (cert->cert->valid_before + CERT_EXPIRY_GRACE))
		واپس -1; /* certificate already expired */
	n = (CERT_EXPIRY_GRACE + cert->cert->valid_before) - (uint64_t)now;
	n = MINIMUM(n, زیادہ_سے_زیادہ_عدد);
	اگر (cert_lifetime <= 0)
		واپس (صحیح)n;
	واپس MINIMUM(cert_lifetime, (صحیح)n);
}

ساکن صحیح
جوڑو_file(صحیح agent_fd, ثابت حرف *filename, صحیح کلید_only, صحیح cert_only,
    صحیح qflag, صحیح Nflag, ثابت حرف *skprovider,
    ساخت dest_constraint **dest_constraints,
    سائز_t ndest_constraints)
{
	ساخت sshkey *نجی = تہی, *cert = تہی;
	حرف *comment = تہی;
	حرف پیغام[1024], *certpath = تہی;
	صحیح cert_lifetime, r, fd, ret = -1;
	ساخت sshbuf *keyblob;

	اگر (strcmp(filename, "-") == 0) {
		fd = STDIN_FILENO;
		filename = "(stdin)";
	} ورنہ اگر ((fd = open(filename, O_RDONLY)) == -1) {
		perror(filename);
		واپس -1;
	}

	/*
	 * Since we'll try to load a keyfile multiple times, permission errors
	 * will occur multiple times, so check perms first and bail if wrong.
	 */
	اگر (fd != STDIN_FILENO) {
		اگر (sshkey_perm_ok(fd, filename) != 0) {
			close(fd);
			واپس -1;
		}
	}
	اگر ((r = sshbuf_بھرو_fd(fd, &keyblob)) != 0) {
		fprintf(stderr, "Error loading key \"%s\": %s\n",
		    filename, ssh_err(r));
		sshbuf_free(keyblob);
		close(fd);
		واپس -1;
	}
	close(fd);

	/* At first, try empty passphrase */
	اگر ((r = sshkey_parse_نجی_fileblob(keyblob, "", &نجی,
	    &comment)) != 0 && r != SSH_ERR_کلید_WRONG_PASSPHRASE) {
		fprintf(stderr, "Error loading key \"%s\": %s\n",
		    filename, ssh_err(r));
		جاؤ fail_بھرو;
	}
	/* try last */
	اگر (نجی == تہی && pass != تہی) {
		اگر ((r = sshkey_parse_نجی_fileblob(keyblob, pass, &نجی,
		    &comment)) != 0 && r != SSH_ERR_کلید_WRONG_PASSPHRASE) {
			fprintf(stderr, "Error loading key \"%s\": %s\n",
			    filename, ssh_err(r));
			جاؤ fail_بھرو;
		}
	}
	اگر (نجی == تہی) {
		/* clear passphrase since it did not work */
		clear_pass();
		snprintf(پیغام, حجم پیغام, "Enter passphrase for %s%s: ",
		    filename, confirm ? " (will confirm each use)" : "");
		برائے (;;) {
			pass = read_passphrase(پیغام, RP_ALLOW_STDIN);
			اگر (strcmp(pass, "") == 0)
				جاؤ fail_بھرو;
			اگر ((r = sshkey_parse_نجی_fileblob(keyblob, pass,
			    &نجی, &comment)) == 0)
				توڑو;
			ورنہ اگر (r != SSH_ERR_کلید_WRONG_PASSPHRASE) {
				fprintf(stderr,
				    "Error loading key \"%s\": %s\n",
				    filename, ssh_err(r));
 fail_بھرو:
				clear_pass();
				sshbuf_free(keyblob);
				واپس -1;
			}
			clear_pass();
			snprintf(پیغام, حجم پیغام,
			    "Bad passphrase, try again for %s%s: ", filename,
			    confirm ? " (will confirm each use)" : "");
		}
	}
	اگر (comment == تہی || *comment == '\0')
		comment = xstrdup(filename);
	sshbuf_free(keyblob);

	اگر (sshkey_is_sk(نجی)) {
		اگر (skprovider == تہی) {
			fprintf(stderr, "Cannot load FIDO key %s "
			    "without provider\n", filename);
			جاؤ برآمد;
		}
	} ورنہ {
		/* Don't send provider constraint for other keys */
		skprovider = تہی;
	}

	اگر (!cert_only) {
		اگر ((r = ssh_جوڑو_شناختی_عنصر_constrained(agent_fd, نجی,
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
		} ورنہ {
			fprintf(stderr, "Could not add identity \"%s\": %s\n",
			    filename, ssh_err(r));
		}
	}

	/* Skip trying to load the cert if requested */
	اگر (کلید_only)
		جاؤ برآمد;

	/* Now try to add the certificate flavour too */
	xasprintf(&certpath, "%s-cert.pub", filename);
	اگر ((r = sshkey_بھرو_عوامی(certpath, &cert, تہی)) != 0) {
		اگر (r != SSH_ERR_SYSTEM_ERROR || errno != ENOENT)
			error_r(r, "Failed to load certificate \"%s\"",
			    certpath);
		جاؤ برآمد;
	}

	اگر (!sshkey_equal_عوامی(cert, نجی)) {
		error("Certificate %s does not match private key %s",
		    certpath, filename);
		جاؤ برآمد;
	}

	cert_lifetime = lifetime;
	اگر (!Nflag &&
	    (cert_lifetime = check_cert_lifetime(cert, cert_lifetime)) == -1) {
		logit("Certificate %s has already expired; ignored", certpath);
		جاؤ برآمد;
	}

	/* Graft with private bits */
	اگر ((r = sshkey_مقصد_certified(نجی)) != 0) {
		error_fr(r, "sshkey_to_certified");
		جاؤ برآمد;
	}
	اگر ((r = sshkey_cert_copy(cert, نجی)) != 0) {
		error_fr(r, "sshkey_cert_copy");
		جاؤ برآمد;
	}
	/* send to agent */
	اگر ((r = ssh_جوڑو_شناختی_عنصر_constrained(agent_fd, نجی, comment,
	    cert_lifetime, confirm, skprovider,
	    dest_constraints, ndest_constraints)) != 0) {
		error_r(r, "Certificate %s (%s) add failed", certpath,
		    نجی->cert->کلید_id);
		جاؤ برآمد;
	}
	/* success */
	اگر (!qflag) {
		fprintf(stderr, "Certificate added: %s (%s)\n", certpath,
		    نجی->cert->کلید_id);
		اگر (cert_lifetime != 0) {
			fprintf(stderr, "Lifetime set to %s\n",
			    fmt_timeframe((time_t)cert_lifetime));
		}
		اگر (confirm != 0) {
			fprintf(stderr, "The user must confirm each use "
			    "of the key\n");
		}
	}

 برآمد:
	آزاد(certpath);
	آزاد(comment);
	sshkey_free(cert);
	sshkey_free(نجی);

	واپس ret;
}

ساکن صحیح
update_card(صحیح agent_fd, صحیح جوڑو, ثابت حرف *id, صحیح qflag, صحیح no_pin,
    صحیح کلید_only, صحیح cert_only,
    ساخت dest_constraint **dest_constraints, سائز_t ndest_constraints,
    ساخت sshkey **certs, سائز_t ncerts)
{
	حرف *pin = تہی;
	صحیح r, ret = -1;

	اگر (کلید_only)
		ncerts = 0;

	اگر (جوڑو && !no_pin) {
		اگر ((pin = read_passphrase("Enter passphrase for PKCS#11: ",
		    RP_ALLOW_STDIN)) == تہی)
			واپس -1;
	}

	اگر ((r = ssh_update_card(agent_fd, جوڑو, id, pin == تہی ? "" : pin,
	    lifetime, confirm, dest_constraints, ndest_constraints,
	    cert_only, certs, ncerts)) == 0) {
		ret = 0;
		اگر (!qflag) {
			fprintf(stderr, "Card %s: %s\n",
			    جوڑو ? "added" : "removed", id);
		}
	} ورنہ {
		fprintf(stderr, "Could not %s card \"%s\": %s\n",
		    جوڑو ? "add" : "remove", id, ssh_err(r));
		ret = -1;
	}
	آزاد(pin);
	واپس ret;
}

ساکن صحیح
test_کلید(صحیح agent_fd, ثابت حرف *filename)
{
	ساخت sshkey *کلید = تہی;
	u_char *sig = تہی;
	ثابت حرف *alg = تہی;
	سائز_t slen = 0;
	صحیح r, ret = -1;
	حرف ڈیٹا[1024];

	اگر ((r = sshkey_بھرو_عوامی(filename, &کلید, تہی)) != 0) {
		error_r(r, "Couldn't read public key %s", filename);
		واپس -1;
	}
	اگر (sshkey_type_plain(کلید->type) == کلید_RSA)
		alg = "rsa-sha2-256";
	arc4random_buf(ڈیٹا, حجم(ڈیٹا));
	اگر ((r = ssh_agent_sign(agent_fd, کلید, &sig, &slen, ڈیٹا, حجم(ڈیٹا),
	    alg, 0)) != 0) {
		error_r(r, "Agent signature failed for %s", filename);
		جاؤ مکمل;
	}
	اگر ((r = sshkey_verify(کلید, sig, slen, ڈیٹا, حجم(ڈیٹا),
	    alg, 0, تہی)) != 0) {
		error_r(r, "Signature verification failed for %s", filename);
		جاؤ مکمل;
	}
	/* success */
	ret = 0;
 مکمل:
	آزاد(sig);
	sshkey_free(کلید);
	واپس ret;
}

ساکن صحیح
list_identities(صحیح agent_fd, صحیح do_fp)
{
	حرف *fp;
	صحیح r;
	ساخت ssh_identitylist *idlist;
	سائز_t i;

	اگر ((r = ssh_fetch_identitylist(agent_fd, &idlist)) != 0) {
		اگر (r != SSH_ERR_AGENT_NO_IDENTITIES)
			fprintf(stderr, "error fetching identities: %s\n",
			    ssh_err(r));
		ورنہ
			لکھو("The agent has no identities.\n");
		واپس -1;
	}
	برائے (i = 0; i < idlist->nkeys; i++) {
		اگر (do_fp) {
			fp = sshkey_fingerprint(idlist->کلیدیں[i],
			    fingerprint_hash, SSH_FP_DEFAULT);
			لکھو("%u %s %s (%s)\n", sshkey_سائز(idlist->کلیدیں[i]),
			    fp == تہی ? "(null)" : fp, idlist->comments[i],
			    sshkey_type(idlist->کلیدیں[i]));
			آزاد(fp);
		} ورنہ {
			اگر ((r = sshkey_write(idlist->کلیدیں[i], stdout)) != 0) {
				fprintf(stderr, "sshkey_write: %s\n",
				    ssh_err(r));
				جاری;
			}
			fprintf(stdout, " %s\n", idlist->comments[i]);
		}
	}
	ssh_free_identitylist(idlist);
	واپس 0;
}

ساکن صحیح
تالا_agent(صحیح agent_fd, صحیح تالا)
{
	حرف prompt[100], *p1, *p2;
	صحیح r, passok = 1, ret = -1;

	strlcpy(prompt, "Enter lock password: ", حجم(prompt));
	p1 = read_passphrase(prompt, RP_ALLOW_STDIN);
	اگر (تالا) {
		strlcpy(prompt, "Again: ", حجم prompt);
		p2 = read_passphrase(prompt, RP_ALLOW_STDIN);
		اگر (strcmp(p1, p2) != 0) {
			fprintf(stderr, "Passwords do not match.\n");
			passok = 0;
		}
		freezero(p2, لڑی_لمبائی(p2));
	}
	اگر (passok) {
		اگر ((r = ssh_تالا_agent(agent_fd, تالا, p1)) == 0) {
			fprintf(stderr, "Agent %slocked.\n", تالا ? "" : "un");
			ret = 0;
		} ورنہ {
			fprintf(stderr, "Failed to %slock agent: %s\n",
			    تالا ? "" : "un", ssh_err(r));
		}
	}
	freezero(p1, لڑی_لمبائی(p1));
	واپس (ret);
}

ساکن صحیح
بھرو_resident_کلیدیں(صحیح agent_fd, ثابت حرف *skprovider, صحیح qflag, صحیح no_pin,
    ساخت dest_constraint **dest_constraints, سائز_t ndest_constraints)
{
	ساخت sshsk_resident_کلید **srks;
	سائز_t nsrks, i;
	ساخت sshkey *کلید;
	صحیح r, ok = 0;
	حرف *fp, *pin = تہی;

	اگر (!no_pin) {
		pin = read_passphrase("Enter PIN for authenticator: ",
		    RP_ALLOW_STDIN);
	}
	اگر ((r = sshsk_بھرو_resident(skprovider, تہی, pin == تہی ? "" : pin,
	    0, &srks, &nsrks)) != 0) {
		error_r(r, "Unable to load resident keys");
		آزاد(pin);
		واپس r;
	}
	آزاد(pin);
	برائے (i = 0; i < nsrks; i++) {
		کلید = srks[i]->کلید;
		اگر ((fp = sshkey_fingerprint(کلید,
		    fingerprint_hash, SSH_FP_DEFAULT)) == تہی)
			fatal_f("sshkey_fingerprint failed");
		اگر ((r = ssh_جوڑو_شناختی_عنصر_constrained(agent_fd, کلید,
		    کلید->sk_application, lifetime, confirm, skprovider,
		    dest_constraints, ndest_constraints)) != 0) {
			error("Unable to add key %s %s",
			    sshkey_type(کلید), fp);
			آزاد(fp);
			ok = r;
			جاری;
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
	sshsk_free_resident_کلیدیں(srks, nsrks);
	اگر (nsrks == 0)
		واپس SSH_ERR_کلید_NOT_ملا;
	واپس ok == 1 ? 0 : ok;
}

ساکن صحیح
do_file(صحیح agent_fd, صحیح deleting, صحیح کلید_only, صحیح cert_only,
    حرف *file, صحیح qflag, صحیح Nflag, ثابت حرف *skprovider,
    ساخت dest_constraint **dest_constraints, سائز_t ndest_constraints)
{
	اگر (deleting) {
		اگر (delete_file(agent_fd, file, کلید_only,
		    cert_only, qflag) == -1)
			واپس -1;
	} ورنہ {
		اگر (جوڑو_file(agent_fd, file, کلید_only, cert_only, qflag, Nflag,
		    skprovider, dest_constraints, ndest_constraints) == -1)
			واپس -1;
	}
	واپس 0;
}

ساکن خالی
free_dest_constraint_hop(ساخت dest_constraint_hop *dch)
{
	u_int i;

	اگر (dch == تہی)
		واپس;
	آزاد(dch->user);
	آزاد(dch->hostname);
	برائے (i = 0; i < dch->nkeys; i++)
		sshkey_free(dch->کلیدیں[i]);
	آزاد(dch->کلیدیں);
	آزاد(dch->کلید_is_ca);
}

ساکن خالی
free_dest_constraints(ساخت dest_constraint **dcs, سائز_t ndcs)
{
	سائز_t i;

	برائے (i = 0; i < ndcs; i++) {
		free_dest_constraint_hop(&dcs[i]->from);
		free_dest_constraint_hop(&dcs[i]->مقصد);
		آزاد(dcs[i]);
	}
	آزاد(dcs);
}


ساکن خالی
parse_dest_constraint_hop(ثابت حرف *s, ساخت dest_constraint_hop *dch,
    حرف **hostkey_files)
{
	حرف *user = تہی, *host, *os, *راستہ;
	سائز_t i;
	ساخت hostkeys *hostkeys;
	ثابت ساخت hostkey_اندراج *hke;
	صحیح r, want_ca;

	memset(dch, '\0', حجم(*dch));
	os = xstrdup(s);
	اگر ((host = strrchr(os, '@')) == تہی)
		host = os;
	ورنہ {
		*host++ = '\0';
		user = os;
	}
	cleanhostname(host);
	/* Trivial case: username@ (all hosts) */
	اگر (*host == '\0') {
		اگر (user == تہی) {
			fatal("Invalid key destination constraint \"%s\": "
			    "does not specify user or host", s);
		}
		dch->user = xstrdup(user);
		/* other fields left blank */
		آزاد(os);
		واپس;
	}
	اگر (hostkey_files == تہی)
		fatal_f("no hostkey files");
	/* Otherwise we need to look up the keys for this hostname */
	hostkeys = init_hostkeys();
	برائے (i = 0; hostkey_files[i]; i++) {
		راستہ = tilde_expand_filename(hostkey_files[i], getuid());
		debug2_f("looking up host keys for \"%s\" in %s", host, راستہ);
                بھرو_hostkeys(hostkeys, host, راستہ, 0);
		آزاد(راستہ);
	}
	dch->user = user == تہی ? تہی : xstrdup(user);
	dch->hostname = xstrdup(host);
	برائے (i = 0; i < hostkeys->عدد_entries; i++) {
		hke = hostkeys->entries + i;
		want_ca = hke->marker == MRK_CA;
		اگر (hke->marker != MRK_NONE && !want_ca)
			جاری;
		debug3_f("%s%s%s: adding %s %skey from %s:%lu as key %u",
		    user == تہی ? "": user, user == تہی ? "" : "@",
		    host, sshkey_type(hke->کلید), want_ca ? "CA " : "",
		    hke->file, hke->سطر, dch->nkeys);
		dch->کلیدیں = xrecallocarray(dch->کلیدیں, dch->nkeys,
		    dch->nkeys + 1, حجم(*dch->کلیدیں));
		dch->کلید_is_ca = xrecallocarray(dch->کلید_is_ca, dch->nkeys,
		    dch->nkeys + 1, حجم(*dch->کلید_is_ca));
		اگر ((r = sshkey_from_نجی(hke->کلید,
		    &(dch->کلیدیں[dch->nkeys]))) != 0)
			fatal_fr(r, "sshkey_from_private");
		dch->کلید_is_ca[dch->nkeys] = want_ca;
		dch->nkeys++;
	}
	اگر (dch->nkeys == 0)
		fatal("No host keys found for destination \"%s\"", host);
	free_hostkeys(hostkeys);
	آزاد(os);
	واپس;
}

ساکن خالی
parse_dest_constraint(ثابت حرف *s, ساخت dest_constraint ***dcp,
    سائز_t *ndcp, حرف **hostkey_files)
{
	ساخت dest_constraint *dc;
	حرف *os, *cp;

	dc = xcalloc(1, حجم(*dc));
	os = xstrdup(s);
	اگر ((cp = strchr(os, '>')) == تہی) {
		/* initial hop; no 'from' hop specified */
		parse_dest_constraint_hop(os, &dc->مقصد, hostkey_files);
	} ورنہ {
		/* two hops specified */
		*(cp++) = '\0';
		parse_dest_constraint_hop(os, &dc->from, hostkey_files);
		parse_dest_constraint_hop(cp, &dc->مقصد, hostkey_files);
		اگر (dc->from.user != تہی) {
			fatal("Invalid key constraint %s: cannot specify "
			    "user on 'from' host", os);
		}
	}
	/* XXX eliminate or error on duplicates */
	debug2_f("constraint %zu: %s%s%s (%u keys) > %s%s%s (%u keys)", *ndcp,
	    dc->from.user ? dc->from.user : "", dc->from.user ? "@" : "",
	    dc->from.hostname ? dc->from.hostname : "(ORIGIN)", dc->from.nkeys,
	    dc->مقصد.user ? dc->مقصد.user : "", dc->مقصد.user ? "@" : "",
	    dc->مقصد.hostname ? dc->مقصد.hostname : "(ANY)", dc->مقصد.nkeys);
	*dcp = xrecallocarray(*dcp, *ndcp, *ndcp + 1, حجم(**dcp));
	(*dcp)[(*ndcp)++] = dc;
	آزاد(os);
}


ساکن خالی
usage(خالی)
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
مین(صحیح argc, حرف **argv)
{
	خارجی حرف *optarg;
	خارجی صحیح optind;
	صحیح agent_fd = -1;
	حرف *pkcs11provider = تہی, *skprovider = تہی;
	حرف **dest_constraint_لڑیاں = تہی, **hostkey_files = تہی;
	صحیح r, i, ch, deleting = 0, ret = 0, کلید_only = 0, cert_only = 0;
	صحیح do_download = 0, xflag = 0, lflag = 0, Dflag = 0;
	صحیح Qflag = 0, qflag = 0, Tflag = 0, Nflag = 0, no_pin = 0;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_INFO;
	ساخت sshkey *k, **certs = تہی;
	ساخت dest_constraint **dest_constraints = تہی;
	سائز_t n, ndest_constraints = 0, ncerts = 0;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	__progname = ssh_get_progname(argv[0]);
	بیج_rng();

	log_init(__progname, log_level, log_facility, 1);

	setvbuf(stdout, تہی, _IOLBF, 0);

	skprovider = getenv("SSH_SK_PROVIDER");

	جب ((ch = getopt(argc, argv, "vkKlLNPCcdDTxXE:e:h:H:M:m:Qqs:S:t:")) != -1) {
		انتخاب (ch) {
		حالت 'v':
			اگر (log_level == SYSLOG_LEVEL_INFO)
				log_level = SYSLOG_LEVEL_DEBUG1;
			ورنہ اگر (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			توڑو;
		حالت 'N':
			Nflag = 1;
			توڑو;
		حالت 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			اگر (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			توڑو;
		حالت 'H':
			stringlist_append(&hostkey_files, optarg);
			توڑو;
		حالت 'h':
			stringlist_append(&dest_constraint_لڑیاں, optarg);
			توڑو;
		حالت 'k':
			کلید_only = 1;
			توڑو;
		حالت 'C':
			cert_only = 1;
			توڑو;
		حالت 'K':
			do_download = 1;
			توڑو;
		حالت 'l':
		حالت 'L':
			اگر (lflag != 0)
				fatal("-%c flag already specified", lflag);
			lflag = ch;
			توڑو;
		حالت 'x':
		حالت 'X':
			اگر (xflag != 0)
				fatal("-%c flag already specified", xflag);
			xflag = ch;
			توڑو;
		حالت 'c':
			confirm = 1;
			توڑو;
		حالت 'm':
		حالت 'M':
			/* deprecated */
			توڑو;
		حالت 'd':
			deleting = 1;
			توڑو;
		حالت 'P':
			no_pin = 1;
			توڑو;
		حالت 'D':
			Dflag = 1;
			توڑو;
		حالت 's':
			pkcs11provider = optarg;
			توڑو;
		حالت 'S':
			skprovider = optarg;
			توڑو;
		حالت 'e':
			deleting = 1;
			pkcs11provider = optarg;
			توڑو;
		حالت 't':
			اگر ((lifetime = convtime(optarg)) == -1 ||
			    lifetime < 0 || (u_long)lifetime > UINT32_MAX) {
				fprintf(stderr, "Invalid lifetime\n");
				ret = 1;
				جاؤ مکمل;
			}
			توڑو;
		حالت 'q':
			qflag = 1;
			توڑو;
		حالت 'Q':
			Qflag = 1;
			توڑو;
		حالت 'T':
			Tflag = 1;
			توڑو;
		طےشدہ:
			usage();
			ret = 1;
			جاؤ مکمل;
		}
	}
	log_init(__progname, log_level, log_facility, 1);

	اگر ((xflag != 0) + (lflag != 0) + (Dflag != 0) + (Qflag != 0) > 1)
		fatal("Invalid combination of actions");

	/* First, get a connection to the authentication agent. */
	انتخاب (r = ssh_get_authentication_socket(&agent_fd)) {
	حالت 0:
		توڑو;
	حالت SSH_ERR_AGENT_NOT_PRESENT:
		fprintf(stderr, "Could not open a connection to your "
		    "authentication agent.\n");
		باہر_نکلو(2);
	طےشدہ:
		fprintf(stderr, "Error connecting to agent: %s\n", ssh_err(r));
		باہر_نکلو(2);
	}

	اگر (xflag) {
		اگر (تالا_agent(agent_fd, xflag == 'x' ? 1 : 0) == -1)
			ret = 1;
		جاؤ مکمل;
	} ورنہ اگر (lflag) {
		اگر (list_identities(agent_fd, lflag == 'l' ? 1 : 0) == -1)
			ret = 1;
		جاؤ مکمل;
	} ورنہ اگر (Dflag) {
		اگر (delete_all(agent_fd, qflag) == -1)
			ret = 1;
		جاؤ مکمل;
	} ورنہ اگر (Qflag) {
		اگر (query_exts(agent_fd) == -1)
			ret = 1;
		جاؤ مکمل;
	}

#اگر_تعریف_شدہ ENABLE_SK_اندرونی
	اگر (skprovider == تہی)
		skprovider = "internal";
#اگر_ختم

	اگر (hostkey_files == تہی) {
		/* use defaults from readconf.c */
		stringlist_append(&hostkey_files, راستہ_SSH_USER_HOSTFILE);
		stringlist_append(&hostkey_files, راستہ_SSH_USER_HOSTFILE2);
		stringlist_append(&hostkey_files, راستہ_SSH_SYSTEM_HOSTFILE);
		stringlist_append(&hostkey_files, راستہ_SSH_SYSTEM_HOSTFILE2);
	}
	اگر (dest_constraint_لڑیاں != تہی) {
		برائے (i = 0; dest_constraint_لڑیاں[i] != تہی; i++) {
			parse_dest_constraint(dest_constraint_لڑیاں[i],
			  &dest_constraints, &ndest_constraints, hostkey_files);
		}
	}

	argc -= optind;
	argv += optind;
	اگر (Tflag) {
		اگر (argc <= 0)
			fatal("no keys to test");
		برائے (r = i = 0; i < argc; i++)
			r |= test_کلید(agent_fd, argv[i]);
		ret = r == 0 ? 0 : 1;
		جاؤ مکمل;
	}
	اگر (pkcs11provider != تہی) {
		برائے (i = 0; i < argc; i++) {
			اگر ((r = sshkey_بھرو_عوامی(argv[i], &k, تہی)) != 0)
				fatal_fr(r, "load certificate %s", argv[i]);
			certs = xrecallocarray(certs, ncerts, ncerts + 1,
			    حجم(*certs));
			debug2("%s: %s", argv[i], sshkey_ssh_name(k));
			certs[ncerts++] = k;
		}
		debug2_f("loaded %zu certificates", ncerts);
		اگر (update_card(agent_fd, !deleting, pkcs11provider,
		    qflag, no_pin, کلید_only, cert_only,
		    dest_constraints, ndest_constraints,
		    certs, ncerts) == -1)
			ret = 1;
		برائے (n = 0; n < ncerts; n++)
			sshkey_free(certs[n]);
		آزاد(certs);
		جاؤ مکمل;
	}
	اگر (do_download) {
		اگر (skprovider == تہی)
			fatal("Cannot download keys without provider");
		اگر (بھرو_resident_کلیدیں(agent_fd, skprovider, qflag, no_pin,
		    dest_constraints, ndest_constraints) != 0)
			ret = 1;
		جاؤ مکمل;
	}
	اگر (argc == 0) {
		حرف buf[PATH_MAX];
		ساخت passwd *pw;
		ساخت stat st;
		صحیح گنتی = 0;

		اگر ((pw = getpwuid(getuid())) == تہی) {
			fprintf(stderr, "No user found with uid %u\n",
			    (u_int)getuid());
			ret = 1;
			جاؤ مکمل;
		}

		برائے (i = 0; default_files[i]; i++) {
			snprintf(buf, حجم(buf), "%s/%s", pw->pw_dir,
			    default_files[i]);
			اگر (stat(buf, &st) == -1)
				جاری;
			اگر (do_file(agent_fd, deleting, کلید_only, cert_only,
			    buf, qflag, Nflag, skprovider,
			    dest_constraints, ndest_constraints) == -1)
				ret = 1;
			ورنہ
				گنتی++;
		}
		اگر (گنتی == 0)
			ret = 1;
	} ورنہ {
		برائے (i = 0; i < argc; i++) {
			اگر (do_file(agent_fd, deleting, کلید_only, cert_only,
			    argv[i], qflag, Nflag, skprovider,
			    dest_constraints, ndest_constraints) == -1)
				ret = 1;
		}
	}
مکمل:
	clear_pass();
	stringlist_free(hostkey_files);
	stringlist_free(dest_constraint_لڑیاں);
	free_dest_constraints(dest_constraints, ndest_constraints);
	ssh_close_authentication_socket(agent_fd);
	واپس ret;
}
