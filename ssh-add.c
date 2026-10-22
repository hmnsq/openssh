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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/stat.h>

#ifdef WITH_OPENSSL
# include <openssl/evp.h>
# include "openbsd-compat/openssl-compat.h"
#endif

#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <fcntl.h>
#অন্তর্ভাব <pwd.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <limits.h>
#অন্তর্ভাব <time.h>

#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "ssh.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "authfd.h"
#অন্তর্ভাব "authfile.h"
#অন্তর্ভাব "pathnames.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "digest.h"
#অন্তর্ভাব "ssh-sk.h"
#অন্তর্ভাব "sk-api.h"
#অন্তর্ভাব "hostfile.h"

#define CERT_EXPIRY_GRACE	(5*60)

/* argv0 */
বাহ্যিক অক্ষর *__progname;

/* Default files to add */
স্থির অক্ষর *default_files[] = {
#ifdef WITH_OPENSSL
	_PATH_SSH_CLIENT_ID_RSA,
	_PATH_SSH_CLIENT_ID_ECDSA,
	_PATH_SSH_CLIENT_ID_ECDSA_SK,
#endif /* WITH_OPENSSL */
	_PATH_SSH_CLIENT_ID_ED25519,
	_PATH_SSH_CLIENT_ID_ED25519_SK,
	_PATH_SSH_CLIENT_ID_MLDSA44_ED25519,
	ফাঁকা
};

স্থির পূর্ণসংখ্যা fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* Default lifetime (0 == forever) */
স্থির পূর্ণসংখ্যা lifetime = 0;

/* User has to confirm key use */
স্থির পূর্ণসংখ্যা confirm = 0;

/* we keep a cache of one passphrase */
স্থির অক্ষর *pass = ফাঁকা;
স্থির শূন্য
clear_pass(শূন্য)
{
	যদি (pass) {
		freezero(pass, strlen(pass));
		pass = ফাঁকা;
	}
}

স্থির পূর্ণসংখ্যা
delete_one(পূর্ণসংখ্যা agent_fd, ধ্রুবক কাঠামো sshkey *চাবি, ধ্রুবক অক্ষর *comment,
    ধ্রুবক অক্ষর *path, পূর্ণসংখ্যা qflag)
{
	পূর্ণসংখ্যা r;

	যদি ((r = ssh_remove_identity(agent_fd, চাবি)) != 0) {
		fprintf(stderr, "Could not remove identity \"%s\": %s\n",
		    path, ssh_err(r));
		ফেরত r;
	}
	যদি (!qflag) {
		fprintf(stderr, "Identity removed: %s %s (%s)\n", path,
		    sshkey_type(চাবি), comment ? comment : "no comment");
	}
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
delete_stdin(পূর্ণসংখ্যা agent_fd, পূর্ণসংখ্যা qflag, পূর্ণসংখ্যা চাবি_only, পূর্ণসংখ্যা cert_only)
{
	অক্ষর *সারি = ফাঁকা, *cp;
	আকার_t linesize = 0;
	কাঠামো sshkey *চাবি = ফাঁকা;
	পূর্ণসংখ্যা lnum = 0, r, ret = -1;

	যখন (getline(&সারি, &linesize, stdin) != -1) {
		lnum++;
		sshkey_free(চাবি);
		চাবি = ফাঁকা;
		সারি[strcspn(সারি, "\n")] = '\0';
		cp = সারি + strspn(সারি, " \t");
		যদি (*cp == '#' || *cp == '\0')
			চালু;
		যদি ((চাবি = sshkey_new(চাবি_UNSPEC)) == ফাঁকা)
			fatal_f("sshkey_new");
		যদি ((r = sshkey_read(চাবি, &cp)) != 0) {
			error_r(r, "(stdin):%d: invalid key", lnum);
			চালু;
		}
		যদি ((!চাবি_only && !cert_only) ||
		    (চাবি_only && !sshkey_is_cert(চাবি)) ||
		    (cert_only && sshkey_is_cert(চাবি))) {
			যদি (delete_one(agent_fd, চাবি, cp,
			    "(stdin)", qflag) == 0)
				ret = 0;
		}
	}
	sshkey_free(চাবি);
	মুক্ত(সারি);
	ফেরত ret;
}

স্থির পূর্ণসংখ্যা
delete_file(পূর্ণসংখ্যা agent_fd, ধ্রুবক অক্ষর *filename, পূর্ণসংখ্যা চাবি_only,
    পূর্ণসংখ্যা cert_only, পূর্ণসংখ্যা qflag)
{
	কাঠামো sshkey *সর্বজনীন, *cert = ফাঁকা;
	অক্ষর *certpath = ফাঁকা, *comment = ফাঁকা;
	পূর্ণসংখ্যা r, ret = -1;

	যদি (strcmp(filename, "-") == 0)
		ফেরত delete_stdin(agent_fd, qflag, চাবি_only, cert_only);

	যদি ((r = sshkey_load_public(filename, &সর্বজনীন,  &comment)) != 0) {
		printf("Bad key file %s: %s\n", filename, ssh_err(r));
		ফেরত -1;
	}
	যদি ((!চাবি_only && !cert_only) ||
	    (চাবি_only && !sshkey_is_cert(সর্বজনীন)) ||
	    (cert_only && sshkey_is_cert(সর্বজনীন))) {
		যদি (delete_one(agent_fd, সর্বজনীন, comment, filename, qflag) == 0)
			ret = 0;
	}

	যদি (চাবি_only)
		যাও out;

	/* Now try to delete the corresponding certificate too */
	মুক্ত(comment);
	comment = ফাঁকা;
	xasprintf(&certpath, "%s-cert.pub", filename);
	যদি ((r = sshkey_load_public(certpath, &cert, &comment)) != 0) {
		যদি (r != SSH_ERR_SYSTEM_ERROR || errno != ENOENT)
			error_r(r, "Failed to load certificate \"%s\"", certpath);
		যাও out;
	}

	যদি (!sshkey_equal_public(cert, সর্বজনীন))
		fatal("Certificate %s does not match private key %s",
		    certpath, filename);

	যদি (delete_one(agent_fd, cert, comment, certpath, qflag) == 0)
		ret = 0;

 out:
	sshkey_free(cert);
	sshkey_free(সর্বজনীন);
	মুক্ত(certpath);
	মুক্ত(comment);

	ফেরত ret;
}

/* Send a request to remove all identities. */
স্থির পূর্ণসংখ্যা
delete_all(পূর্ণসংখ্যা agent_fd, পূর্ণসংখ্যা qflag)
{
	পূর্ণসংখ্যা ret = -1;

	/*
	 * Since the agent might be forwarded, old or non-OpenSSH, when asked
	 * to remove all keys, attempt to remove both protocol v.1 and v.2
	 * keys.
	 */
	যদি (ssh_remove_all_identities(agent_fd, 2) == 0)
		ret = 0;
	/* ignore error-code for ssh1 */
	ssh_remove_all_identities(agent_fd, 1);

	যদি (ret != 0)
		fprintf(stderr, "Failed to remove all identities.\n");
	অন্যথা যদি (!qflag)
		fprintf(stderr, "All identities removed.\n");

	ফেরত ret;
}

স্থির পূর্ণসংখ্যা
query_exts(পূর্ণসংখ্যা agent_fd)
{
	পূর্ণসংখ্যা r;
	অক্ষর **exts = ফাঁকা;
	আকার_t i;

	যদি ((r = ssh_agent_query_extensions(agent_fd, &exts)) != 0)
		fatal_r(r, "unable to query supported extensions");
	জন্য (i = 0; exts != ফাঁকা && exts[i] != ফাঁকা; i++)
		puts(exts[i]);
	stringlist_free(exts);
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
check_cert_lifetime(ধ্রুবক কাঠামো sshkey *cert, পূর্ণসংখ্যা cert_lifetime)
{
	time_t now;
	uint64_t n;

	যদি (cert == ফাঁকা || cert->cert == ফাঁকা || !sshkey_is_cert(cert) ||
	    cert->cert->valid_before == 0xFFFFFFFFFFFFFFFFULL)
		ফেরত cert_lifetime;
	যদি ((now = time(ফাঁকা)) <= 0)
		fatal_f("system time is at/before epoch");
	যদি ((uint64_t)now > (cert->cert->valid_before + CERT_EXPIRY_GRACE))
		ফেরত -1; /* certificate already expired */
	n = (CERT_EXPIRY_GRACE + cert->cert->valid_before) - (uint64_t)now;
	n = MINIMUM(n, INT_MAX);
	যদি (cert_lifetime <= 0)
		ফেরত (পূর্ণসংখ্যা)n;
	ফেরত MINIMUM(cert_lifetime, (পূর্ণসংখ্যা)n);
}

স্থির পূর্ণসংখ্যা
add_file(পূর্ণসংখ্যা agent_fd, ধ্রুবক অক্ষর *filename, পূর্ণসংখ্যা চাবি_only, পূর্ণসংখ্যা cert_only,
    পূর্ণসংখ্যা qflag, পূর্ণসংখ্যা Nflag, ধ্রুবক অক্ষর *skprovider,
    কাঠামো dest_constraint **dest_constraints,
    আকার_t ndest_constraints)
{
	কাঠামো sshkey *ব্যক্তিগত = ফাঁকা, *cert = ফাঁকা;
	অক্ষর *comment = ফাঁকা;
	অক্ষর বার্তা[1024], *certpath = ফাঁকা;
	পূর্ণসংখ্যা cert_lifetime, r, fd, ret = -1;
	কাঠামো sshbuf *keyblob;

	যদি (strcmp(filename, "-") == 0) {
		fd = STDIN_FILENO;
		filename = "(stdin)";
	} অন্যথা যদি ((fd = open(filename, O_RDONLY)) == -1) {
		perror(filename);
		ফেরত -1;
	}

	/*
	 * Since we'll try to load a keyfile multiple times, permission errors
	 * will occur multiple times, so check perms first and bail if wrong.
	 */
	যদি (fd != STDIN_FILENO) {
		যদি (sshkey_perm_ok(fd, filename) != 0) {
			close(fd);
			ফেরত -1;
		}
	}
	যদি ((r = sshbuf_load_fd(fd, &keyblob)) != 0) {
		fprintf(stderr, "Error loading key \"%s\": %s\n",
		    filename, ssh_err(r));
		sshbuf_free(keyblob);
		close(fd);
		ফেরত -1;
	}
	close(fd);

	/* At first, try empty passphrase */
	যদি ((r = sshkey_parse_private_fileblob(keyblob, "", &ব্যক্তিগত,
	    &comment)) != 0 && r != SSH_ERR_চাবি_WRONG_PASSPHRASE) {
		fprintf(stderr, "Error loading key \"%s\": %s\n",
		    filename, ssh_err(r));
		যাও fail_load;
	}
	/* try last */
	যদি (ব্যক্তিগত == ফাঁকা && pass != ফাঁকা) {
		যদি ((r = sshkey_parse_private_fileblob(keyblob, pass, &ব্যক্তিগত,
		    &comment)) != 0 && r != SSH_ERR_চাবি_WRONG_PASSPHRASE) {
			fprintf(stderr, "Error loading key \"%s\": %s\n",
			    filename, ssh_err(r));
			যাও fail_load;
		}
	}
	যদি (ব্যক্তিগত == ফাঁকা) {
		/* clear passphrase since it did not work */
		clear_pass();
		snprintf(বার্তা, আকার বার্তা, "Enter passphrase for %s%s: ",
		    filename, confirm ? " (will confirm each use)" : "");
		জন্য (;;) {
			pass = read_passphrase(বার্তা, RP_ALLOW_STDIN);
			যদি (strcmp(pass, "") == 0)
				যাও fail_load;
			যদি ((r = sshkey_parse_private_fileblob(keyblob, pass,
			    &ব্যক্তিগত, &comment)) == 0)
				বিরতি;
			অন্যথা যদি (r != SSH_ERR_চাবি_WRONG_PASSPHRASE) {
				fprintf(stderr,
				    "Error loading key \"%s\": %s\n",
				    filename, ssh_err(r));
 fail_load:
				clear_pass();
				sshbuf_free(keyblob);
				ফেরত -1;
			}
			clear_pass();
			snprintf(বার্তা, আকার বার্তা,
			    "Bad passphrase, try again for %s%s: ", filename,
			    confirm ? " (will confirm each use)" : "");
		}
	}
	যদি (comment == ফাঁকা || *comment == '\0')
		comment = xstrdup(filename);
	sshbuf_free(keyblob);

	যদি (sshkey_is_sk(ব্যক্তিগত)) {
		যদি (skprovider == ফাঁকা) {
			fprintf(stderr, "Cannot load FIDO key %s "
			    "without provider\n", filename);
			যাও out;
		}
	} অন্যথা {
		/* Don't send provider constraint for other keys */
		skprovider = ফাঁকা;
	}

	যদি (!cert_only) {
		যদি ((r = ssh_add_identity_constrained(agent_fd, ব্যক্তিগত,
		    comment, lifetime, confirm, skprovider,
		    dest_constraints, ndest_constraints)) == 0) {
			ret = 0;
			যদি (!qflag) {
				fprintf(stderr, "Identity added: %s (%s)\n",
				    filename, comment);
				যদি (lifetime != 0) {
					fprintf(stderr, "Lifetime set to %s\n",
					    fmt_timeframe((time_t)lifetime));
				}
				যদি (confirm != 0) {
					fprintf(stderr, "The user must confirm "
					    "each use of the key\n");
				}
			}
		} অন্যথা {
			fprintf(stderr, "Could not add identity \"%s\": %s\n",
			    filename, ssh_err(r));
		}
	}

	/* Skip trying to load the cert if requested */
	যদি (চাবি_only)
		যাও out;

	/* Now try to add the certificate flavour too */
	xasprintf(&certpath, "%s-cert.pub", filename);
	যদি ((r = sshkey_load_public(certpath, &cert, ফাঁকা)) != 0) {
		যদি (r != SSH_ERR_SYSTEM_ERROR || errno != ENOENT)
			error_r(r, "Failed to load certificate \"%s\"",
			    certpath);
		যাও out;
	}

	যদি (!sshkey_equal_public(cert, ব্যক্তিগত)) {
		error("Certificate %s does not match private key %s",
		    certpath, filename);
		যাও out;
	}

	cert_lifetime = lifetime;
	যদি (!Nflag &&
	    (cert_lifetime = check_cert_lifetime(cert, cert_lifetime)) == -1) {
		logit("Certificate %s has already expired; ignored", certpath);
		যাও out;
	}

	/* Graft with private bits */
	যদি ((r = sshkey_to_certified(ব্যক্তিগত)) != 0) {
		error_fr(r, "sshkey_to_certified");
		যাও out;
	}
	যদি ((r = sshkey_cert_copy(cert, ব্যক্তিগত)) != 0) {
		error_fr(r, "sshkey_cert_copy");
		যাও out;
	}
	/* send to agent */
	যদি ((r = ssh_add_identity_constrained(agent_fd, ব্যক্তিগত, comment,
	    cert_lifetime, confirm, skprovider,
	    dest_constraints, ndest_constraints)) != 0) {
		error_r(r, "Certificate %s (%s) add failed", certpath,
		    ব্যক্তিগত->cert->চাবি_id);
		যাও out;
	}
	/* success */
	যদি (!qflag) {
		fprintf(stderr, "Certificate added: %s (%s)\n", certpath,
		    ব্যক্তিগত->cert->চাবি_id);
		যদি (cert_lifetime != 0) {
			fprintf(stderr, "Lifetime set to %s\n",
			    fmt_timeframe((time_t)cert_lifetime));
		}
		যদি (confirm != 0) {
			fprintf(stderr, "The user must confirm each use "
			    "of the key\n");
		}
	}

 out:
	মুক্ত(certpath);
	মুক্ত(comment);
	sshkey_free(cert);
	sshkey_free(ব্যক্তিগত);

	ফেরত ret;
}

স্থির পূর্ণসংখ্যা
update_card(পূর্ণসংখ্যা agent_fd, পূর্ণসংখ্যা add, ধ্রুবক অক্ষর *id, পূর্ণসংখ্যা qflag, পূর্ণসংখ্যা no_pin,
    পূর্ণসংখ্যা চাবি_only, পূর্ণসংখ্যা cert_only,
    কাঠামো dest_constraint **dest_constraints, আকার_t ndest_constraints,
    কাঠামো sshkey **certs, আকার_t ncerts)
{
	অক্ষর *pin = ফাঁকা;
	পূর্ণসংখ্যা r, ret = -1;

	যদি (চাবি_only)
		ncerts = 0;

	যদি (add && !no_pin) {
		যদি ((pin = read_passphrase("Enter passphrase for PKCS#11: ",
		    RP_ALLOW_STDIN)) == ফাঁকা)
			ফেরত -1;
	}

	যদি ((r = ssh_update_card(agent_fd, add, id, pin == ফাঁকা ? "" : pin,
	    lifetime, confirm, dest_constraints, ndest_constraints,
	    cert_only, certs, ncerts)) == 0) {
		ret = 0;
		যদি (!qflag) {
			fprintf(stderr, "Card %s: %s\n",
			    add ? "added" : "removed", id);
		}
	} অন্যথা {
		fprintf(stderr, "Could not %s card \"%s\": %s\n",
		    add ? "add" : "remove", id, ssh_err(r));
		ret = -1;
	}
	মুক্ত(pin);
	ফেরত ret;
}

স্থির পূর্ণসংখ্যা
test_চাবি(পূর্ণসংখ্যা agent_fd, ধ্রুবক অক্ষর *filename)
{
	কাঠামো sshkey *চাবি = ফাঁকা;
	u_char *sig = ফাঁকা;
	ধ্রুবক অক্ষর *alg = ফাঁকা;
	আকার_t slen = 0;
	পূর্ণসংখ্যা r, ret = -1;
	অক্ষর তথ্য[1024];

	যদি ((r = sshkey_load_public(filename, &চাবি, ফাঁকা)) != 0) {
		error_r(r, "Couldn't read public key %s", filename);
		ফেরত -1;
	}
	যদি (sshkey_type_plain(চাবি->type) == চাবি_RSA)
		alg = "rsa-sha2-256";
	arc4random_buf(তথ্য, আকার(তথ্য));
	যদি ((r = ssh_agent_sign(agent_fd, চাবি, &sig, &slen, তথ্য, আকার(তথ্য),
	    alg, 0)) != 0) {
		error_r(r, "Agent signature failed for %s", filename);
		যাও done;
	}
	যদি ((r = sshkey_verify(চাবি, sig, slen, তথ্য, আকার(তথ্য),
	    alg, 0, ফাঁকা)) != 0) {
		error_r(r, "Signature verification failed for %s", filename);
		যাও done;
	}
	/* success */
	ret = 0;
 done:
	মুক্ত(sig);
	sshkey_free(চাবি);
	ফেরত ret;
}

স্থির পূর্ণসংখ্যা
list_identities(পূর্ণসংখ্যা agent_fd, পূর্ণসংখ্যা do_fp)
{
	অক্ষর *fp;
	পূর্ণসংখ্যা r;
	কাঠামো ssh_identitylist *idlist;
	আকার_t i;

	যদি ((r = ssh_fetch_identitylist(agent_fd, &idlist)) != 0) {
		যদি (r != SSH_ERR_AGENT_NO_IDENTITIES)
			fprintf(stderr, "error fetching identities: %s\n",
			    ssh_err(r));
		অন্যথা
			printf("The agent has no identities.\n");
		ফেরত -1;
	}
	জন্য (i = 0; i < idlist->nkeys; i++) {
		যদি (do_fp) {
			fp = sshkey_fingerprint(idlist->চাবিগুলি[i],
			    fingerprint_hash, SSH_FP_DEFAULT);
			printf("%u %s %s (%s)\n", sshkey_আকার(idlist->চাবিগুলি[i]),
			    fp == ফাঁকা ? "(null)" : fp, idlist->comments[i],
			    sshkey_type(idlist->চাবিগুলি[i]));
			মুক্ত(fp);
		} অন্যথা {
			যদি ((r = sshkey_write(idlist->চাবিগুলি[i], stdout)) != 0) {
				fprintf(stderr, "sshkey_write: %s\n",
				    ssh_err(r));
				চালু;
			}
			fprintf(stdout, " %s\n", idlist->comments[i]);
		}
	}
	ssh_free_identitylist(idlist);
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
lock_agent(পূর্ণসংখ্যা agent_fd, পূর্ণসংখ্যা lock)
{
	অক্ষর prompt[100], *p1, *p2;
	পূর্ণসংখ্যা r, passok = 1, ret = -1;

	strlcpy(prompt, "Enter lock password: ", আকার(prompt));
	p1 = read_passphrase(prompt, RP_ALLOW_STDIN);
	যদি (lock) {
		strlcpy(prompt, "Again: ", আকার prompt);
		p2 = read_passphrase(prompt, RP_ALLOW_STDIN);
		যদি (strcmp(p1, p2) != 0) {
			fprintf(stderr, "Passwords do not match.\n");
			passok = 0;
		}
		freezero(p2, strlen(p2));
	}
	যদি (passok) {
		যদি ((r = ssh_lock_agent(agent_fd, lock, p1)) == 0) {
			fprintf(stderr, "Agent %slocked.\n", lock ? "" : "un");
			ret = 0;
		} অন্যথা {
			fprintf(stderr, "Failed to %slock agent: %s\n",
			    lock ? "" : "un", ssh_err(r));
		}
	}
	freezero(p1, strlen(p1));
	ফেরত (ret);
}

স্থির পূর্ণসংখ্যা
load_resident_চাবিগুলি(পূর্ণসংখ্যা agent_fd, ধ্রুবক অক্ষর *skprovider, পূর্ণসংখ্যা qflag, পূর্ণসংখ্যা no_pin,
    কাঠামো dest_constraint **dest_constraints, আকার_t ndest_constraints)
{
	কাঠামো sshsk_resident_চাবি **srks;
	আকার_t nsrks, i;
	কাঠামো sshkey *চাবি;
	পূর্ণসংখ্যা r, ok = 0;
	অক্ষর *fp, *pin = ফাঁকা;

	যদি (!no_pin) {
		pin = read_passphrase("Enter PIN for authenticator: ",
		    RP_ALLOW_STDIN);
	}
	যদি ((r = sshsk_load_resident(skprovider, ফাঁকা, pin == ফাঁকা ? "" : pin,
	    0, &srks, &nsrks)) != 0) {
		error_r(r, "Unable to load resident keys");
		মুক্ত(pin);
		ফেরত r;
	}
	মুক্ত(pin);
	জন্য (i = 0; i < nsrks; i++) {
		চাবি = srks[i]->চাবি;
		যদি ((fp = sshkey_fingerprint(চাবি,
		    fingerprint_hash, SSH_FP_DEFAULT)) == ফাঁকা)
			fatal_f("sshkey_fingerprint failed");
		যদি ((r = ssh_add_identity_constrained(agent_fd, চাবি,
		    চাবি->sk_application, lifetime, confirm, skprovider,
		    dest_constraints, ndest_constraints)) != 0) {
			error("Unable to add key %s %s",
			    sshkey_type(চাবি), fp);
			মুক্ত(fp);
			ok = r;
			চালু;
		}
		যদি (ok == 0)
			ok = 1;
		যদি (!qflag) {
			fprintf(stderr, "Resident identity added: %s %s\n",
			    sshkey_type(চাবি), fp);
			যদি (lifetime != 0) {
				fprintf(stderr,
				    "Lifetime set to %d seconds\n", lifetime);
			}
			যদি (confirm != 0) {
				fprintf(stderr, "The user must confirm "
				    "each use of the key\n");
			}
		}
		মুক্ত(fp);
	}
	sshsk_free_resident_চাবিগুলি(srks, nsrks);
	যদি (nsrks == 0)
		ফেরত SSH_ERR_চাবি_NOT_FOUND;
	ফেরত ok == 1 ? 0 : ok;
}

স্থির পূর্ণসংখ্যা
do_file(পূর্ণসংখ্যা agent_fd, পূর্ণসংখ্যা deleting, পূর্ণসংখ্যা চাবি_only, পূর্ণসংখ্যা cert_only,
    অক্ষর *file, পূর্ণসংখ্যা qflag, পূর্ণসংখ্যা Nflag, ধ্রুবক অক্ষর *skprovider,
    কাঠামো dest_constraint **dest_constraints, আকার_t ndest_constraints)
{
	যদি (deleting) {
		যদি (delete_file(agent_fd, file, চাবি_only,
		    cert_only, qflag) == -1)
			ফেরত -1;
	} অন্যথা {
		যদি (add_file(agent_fd, file, চাবি_only, cert_only, qflag, Nflag,
		    skprovider, dest_constraints, ndest_constraints) == -1)
			ফেরত -1;
	}
	ফেরত 0;
}

স্থির শূন্য
free_dest_constraint_hop(কাঠামো dest_constraint_hop *dch)
{
	u_int i;

	যদি (dch == ফাঁকা)
		ফেরত;
	মুক্ত(dch->user);
	মুক্ত(dch->hostname);
	জন্য (i = 0; i < dch->nkeys; i++)
		sshkey_free(dch->চাবিগুলি[i]);
	মুক্ত(dch->চাবিগুলি);
	মুক্ত(dch->চাবি_is_ca);
}

স্থির শূন্য
free_dest_constraints(কাঠামো dest_constraint **dcs, আকার_t ndcs)
{
	আকার_t i;

	জন্য (i = 0; i < ndcs; i++) {
		free_dest_constraint_hop(&dcs[i]->from);
		free_dest_constraint_hop(&dcs[i]->to);
		মুক্ত(dcs[i]);
	}
	মুক্ত(dcs);
}


স্থির শূন্য
parse_dest_constraint_hop(ধ্রুবক অক্ষর *s, কাঠামো dest_constraint_hop *dch,
    অক্ষর **hostkey_files)
{
	অক্ষর *user = ফাঁকা, *host, *os, *path;
	আকার_t i;
	কাঠামো hostkeys *hostkeys;
	ধ্রুবক কাঠামো hostkey_entry *hke;
	পূর্ণসংখ্যা r, want_ca;

	memset(dch, '\0', আকার(*dch));
	os = xstrdup(s);
	যদি ((host = strrchr(os, '@')) == ফাঁকা)
		host = os;
	অন্যথা {
		*host++ = '\0';
		user = os;
	}
	cleanhostname(host);
	/* Trivial case: username@ (all hosts) */
	যদি (*host == '\0') {
		যদি (user == ফাঁকা) {
			fatal("Invalid key destination constraint \"%s\": "
			    "does not specify user or host", s);
		}
		dch->user = xstrdup(user);
		/* other fields left blank */
		মুক্ত(os);
		ফেরত;
	}
	যদি (hostkey_files == ফাঁকা)
		fatal_f("no hostkey files");
	/* Otherwise we need to look up the keys for this hostname */
	hostkeys = init_hostkeys();
	জন্য (i = 0; hostkey_files[i]; i++) {
		path = tilde_expand_filename(hostkey_files[i], getuid());
		debug2_f("looking up host keys for \"%s\" in %s", host, path);
                load_hostkeys(hostkeys, host, path, 0);
		মুক্ত(path);
	}
	dch->user = user == ফাঁকা ? ফাঁকা : xstrdup(user);
	dch->hostname = xstrdup(host);
	জন্য (i = 0; i < hostkeys->অঙ্ক_entries; i++) {
		hke = hostkeys->entries + i;
		want_ca = hke->marker == MRK_CA;
		যদি (hke->marker != MRK_NONE && !want_ca)
			চালু;
		debug3_f("%s%s%s: adding %s %skey from %s:%lu as key %u",
		    user == ফাঁকা ? "": user, user == ফাঁকা ? "" : "@",
		    host, sshkey_type(hke->চাবি), want_ca ? "CA " : "",
		    hke->file, hke->সারি, dch->nkeys);
		dch->চাবিগুলি = xrecallocarray(dch->চাবিগুলি, dch->nkeys,
		    dch->nkeys + 1, আকার(*dch->চাবিগুলি));
		dch->চাবি_is_ca = xrecallocarray(dch->চাবি_is_ca, dch->nkeys,
		    dch->nkeys + 1, আকার(*dch->চাবি_is_ca));
		যদি ((r = sshkey_from_private(hke->চাবি,
		    &(dch->চাবিগুলি[dch->nkeys]))) != 0)
			fatal_fr(r, "sshkey_from_private");
		dch->চাবি_is_ca[dch->nkeys] = want_ca;
		dch->nkeys++;
	}
	যদি (dch->nkeys == 0)
		fatal("No host keys found for destination \"%s\"", host);
	free_hostkeys(hostkeys);
	মুক্ত(os);
	ফেরত;
}

স্থির শূন্য
parse_dest_constraint(ধ্রুবক অক্ষর *s, কাঠামো dest_constraint ***dcp,
    আকার_t *ndcp, অক্ষর **hostkey_files)
{
	কাঠামো dest_constraint *dc;
	অক্ষর *os, *cp;

	dc = xcalloc(1, আকার(*dc));
	os = xstrdup(s);
	যদি ((cp = strchr(os, '>')) == ফাঁকা) {
		/* initial hop; no 'from' hop specified */
		parse_dest_constraint_hop(os, &dc->to, hostkey_files);
	} অন্যথা {
		/* two hops specified */
		*(cp++) = '\0';
		parse_dest_constraint_hop(os, &dc->from, hostkey_files);
		parse_dest_constraint_hop(cp, &dc->to, hostkey_files);
		যদি (dc->from.user != ফাঁকা) {
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
	*dcp = xrecallocarray(*dcp, *ndcp, *ndcp + 1, আকার(**dcp));
	(*dcp)[(*ndcp)++] = dc;
	মুক্ত(os);
}


স্থির শূন্য
usage(শূন্য)
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

পূর্ণসংখ্যা
প্রধান(পূর্ণসংখ্যা argc, অক্ষর **argv)
{
	বাহ্যিক অক্ষর *optarg;
	বাহ্যিক পূর্ণসংখ্যা optind;
	পূর্ণসংখ্যা agent_fd = -1;
	অক্ষর *pkcs11provider = ফাঁকা, *skprovider = ফাঁকা;
	অক্ষর **dest_constraint_strings = ফাঁকা, **hostkey_files = ফাঁকা;
	পূর্ণসংখ্যা r, i, ch, deleting = 0, ret = 0, চাবি_only = 0, cert_only = 0;
	পূর্ণসংখ্যা do_download = 0, xflag = 0, lflag = 0, Dflag = 0;
	পূর্ণসংখ্যা Qflag = 0, qflag = 0, Tflag = 0, Nflag = 0, no_pin = 0;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_INFO;
	কাঠামো sshkey *k, **certs = ফাঁকা;
	কাঠামো dest_constraint **dest_constraints = ফাঁকা;
	আকার_t n, ndest_constraints = 0, ncerts = 0;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	__progname = ssh_get_progname(argv[0]);
	seed_rng();

	log_init(__progname, log_level, log_facility, 1);

	setvbuf(stdout, ফাঁকা, _IOLBF, 0);

	skprovider = getenv("SSH_SK_PROVIDER");

	যখন ((ch = getopt(argc, argv, "vkKlLNPCcdDTxXE:e:h:H:M:m:Qqs:S:t:")) != -1) {
		নির্বাচন (ch) {
		ক্ষেত্র 'v':
			যদি (log_level == SYSLOG_LEVEL_INFO)
				log_level = SYSLOG_LEVEL_DEBUG1;
			অন্যথা যদি (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			বিরতি;
		ক্ষেত্র 'N':
			Nflag = 1;
			বিরতি;
		ক্ষেত্র 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			যদি (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			বিরতি;
		ক্ষেত্র 'H':
			stringlist_append(&hostkey_files, optarg);
			বিরতি;
		ক্ষেত্র 'h':
			stringlist_append(&dest_constraint_strings, optarg);
			বিরতি;
		ক্ষেত্র 'k':
			চাবি_only = 1;
			বিরতি;
		ক্ষেত্র 'C':
			cert_only = 1;
			বিরতি;
		ক্ষেত্র 'K':
			do_download = 1;
			বিরতি;
		ক্ষেত্র 'l':
		ক্ষেত্র 'L':
			যদি (lflag != 0)
				fatal("-%c flag already specified", lflag);
			lflag = ch;
			বিরতি;
		ক্ষেত্র 'x':
		ক্ষেত্র 'X':
			যদি (xflag != 0)
				fatal("-%c flag already specified", xflag);
			xflag = ch;
			বিরতি;
		ক্ষেত্র 'c':
			confirm = 1;
			বিরতি;
		ক্ষেত্র 'm':
		ক্ষেত্র 'M':
			/* deprecated */
			বিরতি;
		ক্ষেত্র 'd':
			deleting = 1;
			বিরতি;
		ক্ষেত্র 'P':
			no_pin = 1;
			বিরতি;
		ক্ষেত্র 'D':
			Dflag = 1;
			বিরতি;
		ক্ষেত্র 's':
			pkcs11provider = optarg;
			বিরতি;
		ক্ষেত্র 'S':
			skprovider = optarg;
			বিরতি;
		ক্ষেত্র 'e':
			deleting = 1;
			pkcs11provider = optarg;
			বিরতি;
		ক্ষেত্র 't':
			যদি ((lifetime = convtime(optarg)) == -1 ||
			    lifetime < 0 || (u_long)lifetime > UINT32_MAX) {
				fprintf(stderr, "Invalid lifetime\n");
				ret = 1;
				যাও done;
			}
			বিরতি;
		ক্ষেত্র 'q':
			qflag = 1;
			বিরতি;
		ক্ষেত্র 'Q':
			Qflag = 1;
			বিরতি;
		ক্ষেত্র 'T':
			Tflag = 1;
			বিরতি;
		পূর্বনির্ধারিত:
			usage();
			ret = 1;
			যাও done;
		}
	}
	log_init(__progname, log_level, log_facility, 1);

	যদি ((xflag != 0) + (lflag != 0) + (Dflag != 0) + (Qflag != 0) > 1)
		fatal("Invalid combination of actions");

	/* First, get a connection to the authentication agent. */
	নির্বাচন (r = ssh_get_authentication_socket(&agent_fd)) {
	ক্ষেত্র 0:
		বিরতি;
	ক্ষেত্র SSH_ERR_AGENT_NOT_PRESENT:
		fprintf(stderr, "Could not open a connection to your "
		    "authentication agent.\n");
		exit(2);
	পূর্বনির্ধারিত:
		fprintf(stderr, "Error connecting to agent: %s\n", ssh_err(r));
		exit(2);
	}

	যদি (xflag) {
		যদি (lock_agent(agent_fd, xflag == 'x' ? 1 : 0) == -1)
			ret = 1;
		যাও done;
	} অন্যথা যদি (lflag) {
		যদি (list_identities(agent_fd, lflag == 'l' ? 1 : 0) == -1)
			ret = 1;
		যাও done;
	} অন্যথা যদি (Dflag) {
		যদি (delete_all(agent_fd, qflag) == -1)
			ret = 1;
		যাও done;
	} অন্যথা যদি (Qflag) {
		যদি (query_exts(agent_fd) == -1)
			ret = 1;
		যাও done;
	}

#ifdef ENABLE_SK_INTERNAL
	যদি (skprovider == ফাঁকা)
		skprovider = "internal";
#endif

	যদি (hostkey_files == ফাঁকা) {
		/* use defaults from readconf.c */
		stringlist_append(&hostkey_files, _PATH_SSH_USER_HOSTFILE);
		stringlist_append(&hostkey_files, _PATH_SSH_USER_HOSTFILE2);
		stringlist_append(&hostkey_files, _PATH_SSH_SYSTEM_HOSTFILE);
		stringlist_append(&hostkey_files, _PATH_SSH_SYSTEM_HOSTFILE2);
	}
	যদি (dest_constraint_strings != ফাঁকা) {
		জন্য (i = 0; dest_constraint_strings[i] != ফাঁকা; i++) {
			parse_dest_constraint(dest_constraint_strings[i],
			  &dest_constraints, &ndest_constraints, hostkey_files);
		}
	}

	argc -= optind;
	argv += optind;
	যদি (Tflag) {
		যদি (argc <= 0)
			fatal("no keys to test");
		জন্য (r = i = 0; i < argc; i++)
			r |= test_চাবি(agent_fd, argv[i]);
		ret = r == 0 ? 0 : 1;
		যাও done;
	}
	যদি (pkcs11provider != ফাঁকা) {
		জন্য (i = 0; i < argc; i++) {
			যদি ((r = sshkey_load_public(argv[i], &k, ফাঁকা)) != 0)
				fatal_fr(r, "load certificate %s", argv[i]);
			certs = xrecallocarray(certs, ncerts, ncerts + 1,
			    আকার(*certs));
			debug2("%s: %s", argv[i], sshkey_ssh_name(k));
			certs[ncerts++] = k;
		}
		debug2_f("loaded %zu certificates", ncerts);
		যদি (update_card(agent_fd, !deleting, pkcs11provider,
		    qflag, no_pin, চাবি_only, cert_only,
		    dest_constraints, ndest_constraints,
		    certs, ncerts) == -1)
			ret = 1;
		জন্য (n = 0; n < ncerts; n++)
			sshkey_free(certs[n]);
		মুক্ত(certs);
		যাও done;
	}
	যদি (do_download) {
		যদি (skprovider == ফাঁকা)
			fatal("Cannot download keys without provider");
		যদি (load_resident_চাবিগুলি(agent_fd, skprovider, qflag, no_pin,
		    dest_constraints, ndest_constraints) != 0)
			ret = 1;
		যাও done;
	}
	যদি (argc == 0) {
		অক্ষর buf[PATH_MAX];
		কাঠামো passwd *pw;
		কাঠামো stat st;
		পূর্ণসংখ্যা গুনতি = 0;

		যদি ((pw = getpwuid(getuid())) == ফাঁকা) {
			fprintf(stderr, "No user found with uid %u\n",
			    (u_int)getuid());
			ret = 1;
			যাও done;
		}

		জন্য (i = 0; default_files[i]; i++) {
			snprintf(buf, আকার(buf), "%s/%s", pw->pw_dir,
			    default_files[i]);
			যদি (stat(buf, &st) == -1)
				চালু;
			যদি (do_file(agent_fd, deleting, চাবি_only, cert_only,
			    buf, qflag, Nflag, skprovider,
			    dest_constraints, ndest_constraints) == -1)
				ret = 1;
			অন্যথা
				গুনতি++;
		}
		যদি (গুনতি == 0)
			ret = 1;
	} অন্যথা {
		জন্য (i = 0; i < argc; i++) {
			যদি (do_file(agent_fd, deleting, চাবি_only, cert_only,
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
	ফেরত ret;
}
