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

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <sys/stat.h>

#ifdef WITH_OPENSSL
# include <openssl/evp.h>
# include "openbsd-compat/openssl-compat.h"
#endif

#অন্তর্ভাৱ <errno.h>
#অন্তর্ভাৱ <fcntl.h>
#অন্তর্ভাৱ <pwd.h>
#অন্তর্ভাৱ <stdarg.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <unistd.h>
#অন্তর্ভাৱ <limits.h>
#অন্তর্ভাৱ <time.h>

#অন্তর্ভাৱ "xmalloc.h"
#অন্তর্ভাৱ "ssh.h"
#অন্তর্ভাৱ "log.h"
#অন্তর্ভাৱ "sshkey.h"
#অন্তর্ভাৱ "sshbuf.h"
#অন্তর্ভাৱ "authfd.h"
#অন্তর্ভাৱ "authfile.h"
#অন্তর্ভাৱ "pathnames.h"
#অন্তর্ভাৱ "misc.h"
#অন্তর্ভাৱ "ssherr.h"
#অন্তর্ভাৱ "digest.h"
#অন্তর্ভাৱ "ssh-sk.h"
#অন্তর্ভাৱ "sk-api.h"
#অন্তর্ভাৱ "hostfile.h"

#define CERT_EXPIRY_GRACE	(5*60)

/* argv0 */
বাহ্য ৱর্ণ *__progname;

/* Default files to add */
স্থির ৱর্ণ *default_files[] = {
#ifdef WITH_OPENSSL
	_PATH_SSH_CLIENT_ID_RSA,
	_PATH_SSH_CLIENT_ID_ECDSA,
	_PATH_SSH_CLIENT_ID_ECDSA_SK,
#endif /* WITH_OPENSSL */
	_PATH_SSH_CLIENT_ID_ED25519,
	_PATH_SSH_CLIENT_ID_ED25519_SK,
	_PATH_SSH_CLIENT_ID_MLDSA44_ED25519,
	রিক্ত
};

স্থির পূর্ণাঙ্ক fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* Default lifetime (0 == forever) */
স্থির পূর্ণাঙ্ক lifetime = 0;

/* User has to confirm key use */
স্থির পূর্ণাঙ্ক confirm = 0;

/* we keep a cache of one passphrase */
স্থির ৱর্ণ *pass = রিক্ত;
স্থির শূন্য
clear_pass(শূন্য)
{
	যদি (pass) {
		freezero(pass, strlen(pass));
		pass = রিক্ত;
	}
}

স্থির পূর্ণাঙ্ক
delete_one(পূর্ণাঙ্ক agent_fd, ধ্রুৱ সংরচনা sshkey *চাবি, ধ্রুৱ ৱর্ণ *comment,
    ধ্রুৱ ৱর্ণ *path, পূর্ণাঙ্ক qflag)
{
	পূর্ণাঙ্ক r;

	যদি ((r = ssh_remove_identity(agent_fd, চাবি)) != 0) {
		fprintf(stderr, "Could not remove identity \"%s\": %s\n",
		    path, ssh_err(r));
		ঘূৰাই r;
	}
	যদি (!qflag) {
		fprintf(stderr, "Identity removed: %s %s (%s)\n", path,
		    sshkey_type(চাবি), comment ? comment : "no comment");
	}
	ঘূৰাই 0;
}

স্থির পূর্ণাঙ্ক
delete_stdin(পূর্ণাঙ্ক agent_fd, পূর্ণাঙ্ক qflag, পূর্ণাঙ্ক চাবি_only, পূর্ণাঙ্ক cert_only)
{
	ৱর্ণ *সাৰি = রিক্ত, *cp;
	size_t linesize = 0;
	সংরচনা sshkey *চাবি = রিক্ত;
	পূর্ণাঙ্ক lnum = 0, r, ret = -1;

	যেতিয়ালৈ (getline(&সাৰি, &linesize, stdin) != -1) {
		lnum++;
		sshkey_free(চাবি);
		চাবি = রিক্ত;
		সাৰি[strcspn(সাৰি, "\n")] = '\0';
		cp = সাৰি + strspn(সাৰি, " \t");
		যদি (*cp == '#' || *cp == '\0')
			অনুৱর্ত;
		যদি ((চাবি = sshkey_new(চাবি_UNSPEC)) == রিক্ত)
			fatal_f("sshkey_new");
		যদি ((r = sshkey_read(চাবি, &cp)) != 0) {
			error_r(r, "(stdin):%d: invalid key", lnum);
			অনুৱর্ত;
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
	মুক্ত(সাৰি);
	ঘূৰাই ret;
}

স্থির পূর্ণাঙ্ক
delete_file(পূর্ণাঙ্ক agent_fd, ধ্রুৱ ৱর্ণ *filename, পূর্ণাঙ্ক চাবি_only,
    পূর্ণাঙ্ক cert_only, পূর্ণাঙ্ক qflag)
{
	সংরচনা sshkey *সার্ৱজনিক, *cert = রিক্ত;
	ৱর্ণ *certpath = রিক্ত, *comment = রিক্ত;
	পূর্ণাঙ্ক r, ret = -1;

	যদি (strcmp(filename, "-") == 0)
		ঘূৰাই delete_stdin(agent_fd, qflag, চাবি_only, cert_only);

	যদি ((r = sshkey_load_public(filename, &সার্ৱজনিক,  &comment)) != 0) {
		printf("Bad key file %s: %s\n", filename, ssh_err(r));
		ঘূৰাই -1;
	}
	যদি ((!চাবি_only && !cert_only) ||
	    (চাবি_only && !sshkey_is_cert(সার্ৱজনিক)) ||
	    (cert_only && sshkey_is_cert(সার্ৱজনিক))) {
		যদি (delete_one(agent_fd, সার্ৱজনিক, comment, filename, qflag) == 0)
			ret = 0;
	}

	যদি (চাবি_only)
		গচ্ছ out;

	/* Now try to delete the corresponding certificate too */
	মুক্ত(comment);
	comment = রিক্ত;
	xasprintf(&certpath, "%s-cert.pub", filename);
	যদি ((r = sshkey_load_public(certpath, &cert, &comment)) != 0) {
		যদি (r != SSH_ERR_SYSTEM_ERROR || errno != ENOENT)
			error_r(r, "Failed to load certificate \"%s\"", certpath);
		গচ্ছ out;
	}

	যদি (!sshkey_equal_public(cert, সার্ৱজনিক))
		fatal("Certificate %s does not match private key %s",
		    certpath, filename);

	যদি (delete_one(agent_fd, cert, comment, certpath, qflag) == 0)
		ret = 0;

 out:
	sshkey_free(cert);
	sshkey_free(সার্ৱজনিক);
	মুক্ত(certpath);
	মুক্ত(comment);

	ঘূৰাই ret;
}

/* Send a request to remove all identities. */
স্থির পূর্ণাঙ্ক
delete_all(পূর্ণাঙ্ক agent_fd, পূর্ণাঙ্ক qflag)
{
	পূর্ণাঙ্ক ret = -1;

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

	ঘূৰাই ret;
}

স্থির পূর্ণাঙ্ক
query_exts(পূর্ণাঙ্ক agent_fd)
{
	পূর্ণাঙ্ক r;
	ৱর্ণ **exts = রিক্ত;
	size_t i;

	যদি ((r = ssh_agent_query_extensions(agent_fd, &exts)) != 0)
		fatal_r(r, "unable to query supported extensions");
	বাবে (i = 0; exts != রিক্ত && exts[i] != রিক্ত; i++)
		puts(exts[i]);
	stringlist_free(exts);
	ঘূৰাই 0;
}

স্থির পূর্ণাঙ্ক
check_cert_lifetime(ধ্রুৱ সংরচনা sshkey *cert, পূর্ণাঙ্ক cert_lifetime)
{
	time_t now;
	uint64_t n;

	যদি (cert == রিক্ত || cert->cert == রিক্ত || !sshkey_is_cert(cert) ||
	    cert->cert->valid_before == 0xFFFFFFFFFFFFFFFFULL)
		ঘূৰাই cert_lifetime;
	যদি ((now = time(রিক্ত)) <= 0)
		fatal_f("system time is at/before epoch");
	যদি ((uint64_t)now > (cert->cert->valid_before + CERT_EXPIRY_GRACE))
		ঘূৰাই -1; /* certificate already expired */
	n = (CERT_EXPIRY_GRACE + cert->cert->valid_before) - (uint64_t)now;
	n = MINIMUM(n, INT_MAX);
	যদি (cert_lifetime <= 0)
		ঘূৰাই (পূর্ণাঙ্ক)n;
	ঘূৰাই MINIMUM(cert_lifetime, (পূর্ণাঙ্ক)n);
}

স্থির পূর্ণাঙ্ক
add_file(পূর্ণাঙ্ক agent_fd, ধ্রুৱ ৱর্ণ *filename, পূর্ণাঙ্ক চাবি_only, পূর্ণাঙ্ক cert_only,
    পূর্ণাঙ্ক qflag, পূর্ণাঙ্ক Nflag, ধ্রুৱ ৱর্ণ *skprovider,
    সংরচনা dest_constraint **dest_constraints,
    size_t ndest_constraints)
{
	সংরচনা sshkey *গুপ্ত = রিক্ত, *cert = রিক্ত;
	ৱর্ণ *comment = রিক্ত;
	ৱর্ণ বাৰ্তা[1024], *certpath = রিক্ত;
	পূর্ণাঙ্ক cert_lifetime, r, fd, ret = -1;
	সংরচনা sshbuf *keyblob;

	যদি (strcmp(filename, "-") == 0) {
		fd = STDIN_FILENO;
		filename = "(stdin)";
	} অন্যথা যদি ((fd = open(filename, O_RDONLY)) == -1) {
		perror(filename);
		ঘূৰাই -1;
	}

	/*
	 * Since we'll try to load a keyfile multiple times, permission errors
	 * will occur multiple times, so check perms first and bail if wrong.
	 */
	যদি (fd != STDIN_FILENO) {
		যদি (sshkey_perm_ok(fd, filename) != 0) {
			close(fd);
			ঘূৰাই -1;
		}
	}
	যদি ((r = sshbuf_load_fd(fd, &keyblob)) != 0) {
		fprintf(stderr, "Error loading key \"%s\": %s\n",
		    filename, ssh_err(r));
		sshbuf_free(keyblob);
		close(fd);
		ঘূৰাই -1;
	}
	close(fd);

	/* At first, try empty passphrase */
	যদি ((r = sshkey_parse_private_fileblob(keyblob, "", &গুপ্ত,
	    &comment)) != 0 && r != SSH_ERR_চাবি_WRONG_PASSPHRASE) {
		fprintf(stderr, "Error loading key \"%s\": %s\n",
		    filename, ssh_err(r));
		গচ্ছ fail_load;
	}
	/* try last */
	যদি (গুপ্ত == রিক্ত && pass != রিক্ত) {
		যদি ((r = sshkey_parse_private_fileblob(keyblob, pass, &গুপ্ত,
		    &comment)) != 0 && r != SSH_ERR_চাবি_WRONG_PASSPHRASE) {
			fprintf(stderr, "Error loading key \"%s\": %s\n",
			    filename, ssh_err(r));
			গচ্ছ fail_load;
		}
	}
	যদি (গুপ্ত == রিক্ত) {
		/* clear passphrase since it did not work */
		clear_pass();
		snprintf(বাৰ্তা, পরিমাণ বাৰ্তা, "Enter passphrase for %s%s: ",
		    filename, confirm ? " (will confirm each use)" : "");
		বাবে (;;) {
			pass = read_passphrase(বাৰ্তা, RP_ALLOW_STDIN);
			যদি (strcmp(pass, "") == 0)
				গচ্ছ fail_load;
			যদি ((r = sshkey_parse_private_fileblob(keyblob, pass,
			    &গুপ্ত, &comment)) == 0)
				ভঙ্গ;
			অন্যথা যদি (r != SSH_ERR_চাবি_WRONG_PASSPHRASE) {
				fprintf(stderr,
				    "Error loading key \"%s\": %s\n",
				    filename, ssh_err(r));
 fail_load:
				clear_pass();
				sshbuf_free(keyblob);
				ঘূৰাই -1;
			}
			clear_pass();
			snprintf(বাৰ্তা, পরিমাণ বাৰ্তা,
			    "Bad passphrase, try again for %s%s: ", filename,
			    confirm ? " (will confirm each use)" : "");
		}
	}
	যদি (comment == রিক্ত || *comment == '\0')
		comment = xstrdup(filename);
	sshbuf_free(keyblob);

	যদি (sshkey_is_sk(গুপ্ত)) {
		যদি (skprovider == রিক্ত) {
			fprintf(stderr, "Cannot load FIDO key %s "
			    "without provider\n", filename);
			গচ্ছ out;
		}
	} অন্যথা {
		/* Don't send provider constraint for other keys */
		skprovider = রিক্ত;
	}

	যদি (!cert_only) {
		যদি ((r = ssh_add_identity_constrained(agent_fd, গুপ্ত,
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
		গচ্ছ out;

	/* Now try to add the certificate flavour too */
	xasprintf(&certpath, "%s-cert.pub", filename);
	যদি ((r = sshkey_load_public(certpath, &cert, রিক্ত)) != 0) {
		যদি (r != SSH_ERR_SYSTEM_ERROR || errno != ENOENT)
			error_r(r, "Failed to load certificate \"%s\"",
			    certpath);
		গচ্ছ out;
	}

	যদি (!sshkey_equal_public(cert, গুপ্ত)) {
		error("Certificate %s does not match private key %s",
		    certpath, filename);
		গচ্ছ out;
	}

	cert_lifetime = lifetime;
	যদি (!Nflag &&
	    (cert_lifetime = check_cert_lifetime(cert, cert_lifetime)) == -1) {
		logit("Certificate %s has already expired; ignored", certpath);
		গচ্ছ out;
	}

	/* Graft with private bits */
	যদি ((r = sshkey_to_certified(গুপ্ত)) != 0) {
		error_fr(r, "sshkey_to_certified");
		গচ্ছ out;
	}
	যদি ((r = sshkey_cert_copy(cert, গুপ্ত)) != 0) {
		error_fr(r, "sshkey_cert_copy");
		গচ্ছ out;
	}
	/* send to agent */
	যদি ((r = ssh_add_identity_constrained(agent_fd, গুপ্ত, comment,
	    cert_lifetime, confirm, skprovider,
	    dest_constraints, ndest_constraints)) != 0) {
		error_r(r, "Certificate %s (%s) add failed", certpath,
		    গুপ্ত->cert->চাবি_id);
		গচ্ছ out;
	}
	/* success */
	যদি (!qflag) {
		fprintf(stderr, "Certificate added: %s (%s)\n", certpath,
		    গুপ্ত->cert->চাবি_id);
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
	sshkey_free(গুপ্ত);

	ঘূৰাই ret;
}

স্থির পূর্ণাঙ্ক
update_card(পূর্ণাঙ্ক agent_fd, পূর্ণাঙ্ক add, ধ্রুৱ ৱর্ণ *id, পূর্ণাঙ্ক qflag, পূর্ণাঙ্ক no_pin,
    পূর্ণাঙ্ক চাবি_only, পূর্ণাঙ্ক cert_only,
    সংরচনা dest_constraint **dest_constraints, size_t ndest_constraints,
    সংরচনা sshkey **certs, size_t ncerts)
{
	ৱর্ণ *pin = রিক্ত;
	পূর্ণাঙ্ক r, ret = -1;

	যদি (চাবি_only)
		ncerts = 0;

	যদি (add && !no_pin) {
		যদি ((pin = read_passphrase("Enter passphrase for PKCS#11: ",
		    RP_ALLOW_STDIN)) == রিক্ত)
			ঘূৰাই -1;
	}

	যদি ((r = ssh_update_card(agent_fd, add, id, pin == রিক্ত ? "" : pin,
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
	ঘূৰাই ret;
}

স্থির পূর্ণাঙ্ক
test_চাবি(পূর্ণাঙ্ক agent_fd, ধ্রুৱ ৱর্ণ *filename)
{
	সংরচনা sshkey *চাবি = রিক্ত;
	u_char *sig = রিক্ত;
	ধ্রুৱ ৱর্ণ *alg = রিক্ত;
	size_t slen = 0;
	পূর্ণাঙ্ক r, ret = -1;
	ৱর্ণ data[1024];

	যদি ((r = sshkey_load_public(filename, &চাবি, রিক্ত)) != 0) {
		error_r(r, "Couldn't read public key %s", filename);
		ঘূৰাই -1;
	}
	যদি (sshkey_type_plain(চাবি->type) == চাবি_RSA)
		alg = "rsa-sha2-256";
	arc4random_buf(data, পরিমাণ(data));
	যদি ((r = ssh_agent_sign(agent_fd, চাবি, &sig, &slen, data, পরিমাণ(data),
	    alg, 0)) != 0) {
		error_r(r, "Agent signature failed for %s", filename);
		গচ্ছ done;
	}
	যদি ((r = sshkey_verify(চাবি, sig, slen, data, পরিমাণ(data),
	    alg, 0, রিক্ত)) != 0) {
		error_r(r, "Signature verification failed for %s", filename);
		গচ্ছ done;
	}
	/* success */
	ret = 0;
 done:
	মুক্ত(sig);
	sshkey_free(চাবি);
	ঘূৰাই ret;
}

স্থির পূর্ণাঙ্ক
list_identities(পূর্ণাঙ্ক agent_fd, পূর্ণাঙ্ক do_fp)
{
	ৱর্ণ *fp;
	পূর্ণাঙ্ক r;
	সংরচনা ssh_identitylist *idlist;
	size_t i;

	যদি ((r = ssh_fetch_identitylist(agent_fd, &idlist)) != 0) {
		যদি (r != SSH_ERR_AGENT_NO_IDENTITIES)
			fprintf(stderr, "error fetching identities: %s\n",
			    ssh_err(r));
		অন্যথা
			printf("The agent has no identities.\n");
		ঘূৰাই -1;
	}
	বাবে (i = 0; i < idlist->nkeys; i++) {
		যদি (do_fp) {
			fp = sshkey_fingerprint(idlist->চাবিগুলি[i],
			    fingerprint_hash, SSH_FP_DEFAULT);
			printf("%u %s %s (%s)\n", sshkey_size(idlist->চাবিগুলি[i]),
			    fp == রিক্ত ? "(null)" : fp, idlist->comments[i],
			    sshkey_type(idlist->চাবিগুলি[i]));
			মুক্ত(fp);
		} অন্যথা {
			যদি ((r = sshkey_write(idlist->চাবিগুলি[i], stdout)) != 0) {
				fprintf(stderr, "sshkey_write: %s\n",
				    ssh_err(r));
				অনুৱর্ত;
			}
			fprintf(stdout, " %s\n", idlist->comments[i]);
		}
	}
	ssh_free_identitylist(idlist);
	ঘূৰাই 0;
}

স্থির পূর্ণাঙ্ক
lock_agent(পূর্ণাঙ্ক agent_fd, পূর্ণাঙ্ক lock)
{
	ৱর্ণ prompt[100], *p1, *p2;
	পূর্ণাঙ্ক r, passok = 1, ret = -1;

	strlcpy(prompt, "Enter lock password: ", পরিমাণ(prompt));
	p1 = read_passphrase(prompt, RP_ALLOW_STDIN);
	যদি (lock) {
		strlcpy(prompt, "Again: ", পরিমাণ prompt);
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
	ঘূৰাই (ret);
}

স্থির পূর্ণাঙ্ক
load_resident_চাবিগুলি(পূর্ণাঙ্ক agent_fd, ধ্রুৱ ৱর্ণ *skprovider, পূর্ণাঙ্ক qflag, পূর্ণাঙ্ক no_pin,
    সংরচনা dest_constraint **dest_constraints, size_t ndest_constraints)
{
	সংরচনা sshsk_resident_চাবি **srks;
	size_t nsrks, i;
	সংরচনা sshkey *চাবি;
	পূর্ণাঙ্ক r, ok = 0;
	ৱর্ণ *fp, *pin = রিক্ত;

	যদি (!no_pin) {
		pin = read_passphrase("Enter PIN for authenticator: ",
		    RP_ALLOW_STDIN);
	}
	যদি ((r = sshsk_load_resident(skprovider, রিক্ত, pin == রিক্ত ? "" : pin,
	    0, &srks, &nsrks)) != 0) {
		error_r(r, "Unable to load resident keys");
		মুক্ত(pin);
		ঘূৰাই r;
	}
	মুক্ত(pin);
	বাবে (i = 0; i < nsrks; i++) {
		চাবি = srks[i]->চাবি;
		যদি ((fp = sshkey_fingerprint(চাবি,
		    fingerprint_hash, SSH_FP_DEFAULT)) == রিক্ত)
			fatal_f("sshkey_fingerprint failed");
		যদি ((r = ssh_add_identity_constrained(agent_fd, চাবি,
		    চাবি->sk_application, lifetime, confirm, skprovider,
		    dest_constraints, ndest_constraints)) != 0) {
			error("Unable to add key %s %s",
			    sshkey_type(চাবি), fp);
			মুক্ত(fp);
			ok = r;
			অনুৱর্ত;
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
		ঘূৰাই SSH_ERR_চাবি_NOT_FOUND;
	ঘূৰাই ok == 1 ? 0 : ok;
}

স্থির পূর্ণাঙ্ক
do_file(পূর্ণাঙ্ক agent_fd, পূর্ণাঙ্ক deleting, পূর্ণাঙ্ক চাবি_only, পূর্ণাঙ্ক cert_only,
    ৱর্ণ *file, পূর্ণাঙ্ক qflag, পূর্ণাঙ্ক Nflag, ধ্রুৱ ৱর্ণ *skprovider,
    সংরচনা dest_constraint **dest_constraints, size_t ndest_constraints)
{
	যদি (deleting) {
		যদি (delete_file(agent_fd, file, চাবি_only,
		    cert_only, qflag) == -1)
			ঘূৰাই -1;
	} অন্যথা {
		যদি (add_file(agent_fd, file, চাবি_only, cert_only, qflag, Nflag,
		    skprovider, dest_constraints, ndest_constraints) == -1)
			ঘূৰাই -1;
	}
	ঘূৰাই 0;
}

স্থির শূন্য
free_dest_constraint_hop(সংরচনা dest_constraint_hop *dch)
{
	u_int i;

	যদি (dch == রিক্ত)
		ঘূৰাই;
	মুক্ত(dch->user);
	মুক্ত(dch->hostname);
	বাবে (i = 0; i < dch->nkeys; i++)
		sshkey_free(dch->চাবিগুলি[i]);
	মুক্ত(dch->চাবিগুলি);
	মুক্ত(dch->চাবি_is_ca);
}

স্থির শূন্য
free_dest_constraints(সংরচনা dest_constraint **dcs, size_t ndcs)
{
	size_t i;

	বাবে (i = 0; i < ndcs; i++) {
		free_dest_constraint_hop(&dcs[i]->from);
		free_dest_constraint_hop(&dcs[i]->to);
		মুক্ত(dcs[i]);
	}
	মুক্ত(dcs);
}


স্থির শূন্য
parse_dest_constraint_hop(ধ্রুৱ ৱর্ণ *s, সংরচনা dest_constraint_hop *dch,
    ৱর্ণ **hostkey_files)
{
	ৱর্ণ *user = রিক্ত, *host, *os, *path;
	size_t i;
	সংরচনা hostkeys *hostkeys;
	ধ্রুৱ সংরচনা hostkey_entry *hke;
	পূর্ণাঙ্ক r, want_ca;

	memset(dch, '\0', পরিমাণ(*dch));
	os = xstrdup(s);
	যদি ((host = strrchr(os, '@')) == রিক্ত)
		host = os;
	অন্যথা {
		*host++ = '\0';
		user = os;
	}
	cleanhostname(host);
	/* Trivial case: username@ (all hosts) */
	যদি (*host == '\0') {
		যদি (user == রিক্ত) {
			fatal("Invalid key destination constraint \"%s\": "
			    "does not specify user or host", s);
		}
		dch->user = xstrdup(user);
		/* other fields left blank */
		মুক্ত(os);
		ঘূৰাই;
	}
	যদি (hostkey_files == রিক্ত)
		fatal_f("no hostkey files");
	/* Otherwise we need to look up the keys for this hostname */
	hostkeys = init_hostkeys();
	বাবে (i = 0; hostkey_files[i]; i++) {
		path = tilde_expand_filename(hostkey_files[i], getuid());
		debug2_f("looking up host keys for \"%s\" in %s", host, path);
                load_hostkeys(hostkeys, host, path, 0);
		মুক্ত(path);
	}
	dch->user = user == রিক্ত ? রিক্ত : xstrdup(user);
	dch->hostname = xstrdup(host);
	বাবে (i = 0; i < hostkeys->অঙ্ক_entries; i++) {
		hke = hostkeys->entries + i;
		want_ca = hke->marker == MRK_CA;
		যদি (hke->marker != MRK_NONE && !want_ca)
			অনুৱর্ত;
		debug3_f("%s%s%s: adding %s %skey from %s:%lu as key %u",
		    user == রিক্ত ? "": user, user == রিক্ত ? "" : "@",
		    host, sshkey_type(hke->চাবি), want_ca ? "CA " : "",
		    hke->file, hke->সাৰি, dch->nkeys);
		dch->চাবিগুলি = xrecallocarray(dch->চাবিগুলি, dch->nkeys,
		    dch->nkeys + 1, পরিমাণ(*dch->চাবিগুলি));
		dch->চাবি_is_ca = xrecallocarray(dch->চাবি_is_ca, dch->nkeys,
		    dch->nkeys + 1, পরিমাণ(*dch->চাবি_is_ca));
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
	ঘূৰাই;
}

স্থির শূন্য
parse_dest_constraint(ধ্রুৱ ৱর্ণ *s, সংরচনা dest_constraint ***dcp,
    size_t *ndcp, ৱর্ণ **hostkey_files)
{
	সংরচনা dest_constraint *dc;
	ৱর্ণ *os, *cp;

	dc = xcalloc(1, পরিমাণ(*dc));
	os = xstrdup(s);
	যদি ((cp = strchr(os, '>')) == রিক্ত) {
		/* initial hop; no 'from' hop specified */
		parse_dest_constraint_hop(os, &dc->to, hostkey_files);
	} অন্যথা {
		/* two hops specified */
		*(cp++) = '\0';
		parse_dest_constraint_hop(os, &dc->from, hostkey_files);
		parse_dest_constraint_hop(cp, &dc->to, hostkey_files);
		যদি (dc->from.user != রিক্ত) {
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
	*dcp = xrecallocarray(*dcp, *ndcp, *ndcp + 1, পরিমাণ(**dcp));
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

পূর্ণাঙ্ক
main(পূর্ণাঙ্ক argc, ৱর্ণ **argv)
{
	বাহ্য ৱর্ণ *optarg;
	বাহ্য পূর্ণাঙ্ক optind;
	পূর্ণাঙ্ক agent_fd = -1;
	ৱর্ণ *pkcs11provider = রিক্ত, *skprovider = রিক্ত;
	ৱর্ণ **dest_constraint_strings = রিক্ত, **hostkey_files = রিক্ত;
	পূর্ণাঙ্ক r, i, ch, deleting = 0, ret = 0, চাবি_only = 0, cert_only = 0;
	পূর্ণাঙ্ক do_download = 0, xflag = 0, lflag = 0, Dflag = 0;
	পূর্ণাঙ্ক Qflag = 0, qflag = 0, Tflag = 0, Nflag = 0, no_pin = 0;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_INFO;
	সংরচনা sshkey *k, **certs = রিক্ত;
	সংরচনা dest_constraint **dest_constraints = রিক্ত;
	size_t n, ndest_constraints = 0, ncerts = 0;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	__progname = ssh_get_progname(argv[0]);
	seed_rng();

	log_init(__progname, log_level, log_facility, 1);

	setvbuf(stdout, রিক্ত, _IOLBF, 0);

	skprovider = getenv("SSH_SK_PROVIDER");

	যেতিয়ালৈ ((ch = getopt(argc, argv, "vkKlLNPCcdDTxXE:e:h:H:M:m:Qqs:S:t:")) != -1) {
		ৱিকল্প (ch) {
		পক্ষ 'v':
			যদি (log_level == SYSLOG_LEVEL_INFO)
				log_level = SYSLOG_LEVEL_DEBUG1;
			অন্যথা যদি (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			ভঙ্গ;
		পক্ষ 'N':
			Nflag = 1;
			ভঙ্গ;
		পক্ষ 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			যদি (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			ভঙ্গ;
		পক্ষ 'H':
			stringlist_append(&hostkey_files, optarg);
			ভঙ্গ;
		পক্ষ 'h':
			stringlist_append(&dest_constraint_strings, optarg);
			ভঙ্গ;
		পক্ষ 'k':
			চাবি_only = 1;
			ভঙ্গ;
		পক্ষ 'C':
			cert_only = 1;
			ভঙ্গ;
		পক্ষ 'K':
			do_download = 1;
			ভঙ্গ;
		পক্ষ 'l':
		পক্ষ 'L':
			যদি (lflag != 0)
				fatal("-%c flag already specified", lflag);
			lflag = ch;
			ভঙ্গ;
		পক্ষ 'x':
		পক্ষ 'X':
			যদি (xflag != 0)
				fatal("-%c flag already specified", xflag);
			xflag = ch;
			ভঙ্গ;
		পক্ষ 'c':
			confirm = 1;
			ভঙ্গ;
		পক্ষ 'm':
		পক্ষ 'M':
			/* deprecated */
			ভঙ্গ;
		পক্ষ 'd':
			deleting = 1;
			ভঙ্গ;
		পক্ষ 'P':
			no_pin = 1;
			ভঙ্গ;
		পক্ষ 'D':
			Dflag = 1;
			ভঙ্গ;
		পক্ষ 's':
			pkcs11provider = optarg;
			ভঙ্গ;
		পক্ষ 'S':
			skprovider = optarg;
			ভঙ্গ;
		পক্ষ 'e':
			deleting = 1;
			pkcs11provider = optarg;
			ভঙ্গ;
		পক্ষ 't':
			যদি ((lifetime = convtime(optarg)) == -1 ||
			    lifetime < 0 || (u_long)lifetime > UINT32_MAX) {
				fprintf(stderr, "Invalid lifetime\n");
				ret = 1;
				গচ্ছ done;
			}
			ভঙ্গ;
		পক্ষ 'q':
			qflag = 1;
			ভঙ্গ;
		পক্ষ 'Q':
			Qflag = 1;
			ভঙ্গ;
		পক্ষ 'T':
			Tflag = 1;
			ভঙ্গ;
		স্ৱভাৱ:
			usage();
			ret = 1;
			গচ্ছ done;
		}
	}
	log_init(__progname, log_level, log_facility, 1);

	যদি ((xflag != 0) + (lflag != 0) + (Dflag != 0) + (Qflag != 0) > 1)
		fatal("Invalid combination of actions");

	/* First, get a connection to the authentication agent. */
	ৱিকল্প (r = ssh_get_authentication_socket(&agent_fd)) {
	পক্ষ 0:
		ভঙ্গ;
	পক্ষ SSH_ERR_AGENT_NOT_PRESENT:
		fprintf(stderr, "Could not open a connection to your "
		    "authentication agent.\n");
		exit(2);
	স্ৱভাৱ:
		fprintf(stderr, "Error connecting to agent: %s\n", ssh_err(r));
		exit(2);
	}

	যদি (xflag) {
		যদি (lock_agent(agent_fd, xflag == 'x' ? 1 : 0) == -1)
			ret = 1;
		গচ্ছ done;
	} অন্যথা যদি (lflag) {
		যদি (list_identities(agent_fd, lflag == 'l' ? 1 : 0) == -1)
			ret = 1;
		গচ্ছ done;
	} অন্যথা যদি (Dflag) {
		যদি (delete_all(agent_fd, qflag) == -1)
			ret = 1;
		গচ্ছ done;
	} অন্যথা যদি (Qflag) {
		যদি (query_exts(agent_fd) == -1)
			ret = 1;
		গচ্ছ done;
	}

#ifdef ENABLE_SK_INTERNAL
	যদি (skprovider == রিক্ত)
		skprovider = "internal";
#endif

	যদি (hostkey_files == রিক্ত) {
		/* use defaults from readconf.c */
		stringlist_append(&hostkey_files, _PATH_SSH_USER_HOSTFILE);
		stringlist_append(&hostkey_files, _PATH_SSH_USER_HOSTFILE2);
		stringlist_append(&hostkey_files, _PATH_SSH_SYSTEM_HOSTFILE);
		stringlist_append(&hostkey_files, _PATH_SSH_SYSTEM_HOSTFILE2);
	}
	যদি (dest_constraint_strings != রিক্ত) {
		বাবে (i = 0; dest_constraint_strings[i] != রিক্ত; i++) {
			parse_dest_constraint(dest_constraint_strings[i],
			  &dest_constraints, &ndest_constraints, hostkey_files);
		}
	}

	argc -= optind;
	argv += optind;
	যদি (Tflag) {
		যদি (argc <= 0)
			fatal("no keys to test");
		বাবে (r = i = 0; i < argc; i++)
			r |= test_চাবি(agent_fd, argv[i]);
		ret = r == 0 ? 0 : 1;
		গচ্ছ done;
	}
	যদি (pkcs11provider != রিক্ত) {
		বাবে (i = 0; i < argc; i++) {
			যদি ((r = sshkey_load_public(argv[i], &k, রিক্ত)) != 0)
				fatal_fr(r, "load certificate %s", argv[i]);
			certs = xrecallocarray(certs, ncerts, ncerts + 1,
			    পরিমাণ(*certs));
			debug2("%s: %s", argv[i], sshkey_ssh_name(k));
			certs[ncerts++] = k;
		}
		debug2_f("loaded %zu certificates", ncerts);
		যদি (update_card(agent_fd, !deleting, pkcs11provider,
		    qflag, no_pin, চাবি_only, cert_only,
		    dest_constraints, ndest_constraints,
		    certs, ncerts) == -1)
			ret = 1;
		বাবে (n = 0; n < ncerts; n++)
			sshkey_free(certs[n]);
		মুক্ত(certs);
		গচ্ছ done;
	}
	যদি (do_download) {
		যদি (skprovider == রিক্ত)
			fatal("Cannot download keys without provider");
		যদি (load_resident_চাবিগুলি(agent_fd, skprovider, qflag, no_pin,
		    dest_constraints, ndest_constraints) != 0)
			ret = 1;
		গচ্ছ done;
	}
	যদি (argc == 0) {
		ৱর্ণ buf[PATH_MAX];
		সংরচনা passwd *pw;
		সংরচনা stat st;
		পূর্ণাঙ্ক গুনতি = 0;

		যদি ((pw = getpwuid(getuid())) == রিক্ত) {
			fprintf(stderr, "No user found with uid %u\n",
			    (u_int)getuid());
			ret = 1;
			গচ্ছ done;
		}

		বাবে (i = 0; default_files[i]; i++) {
			snprintf(buf, পরিমাণ(buf), "%s/%s", pw->pw_dir,
			    default_files[i]);
			যদি (stat(buf, &st) == -1)
				অনুৱর্ত;
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
		বাবে (i = 0; i < argc; i++) {
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
	ঘূৰাই ret;
}
