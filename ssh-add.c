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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/stat.h>

#ifdef WITH_OPENSSL
# include <openssl/evp.h>
# include "openbsd-compat/openssl-compat.h"
#endif

#अन्तर्भाव <errno.h>
#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <pwd.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <limits.h>
#अन्तर्भाव <time.h>

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "ssh.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "authfd.h"
#अन्तर्भाव "authfile.h"
#अन्तर्भाव "pathnames.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "digest.h"
#अन्तर्भाव "ssh-sk.h"
#अन्तर्भाव "sk-api.h"
#अन्तर्भाव "hostfile.h"

#define CERT_EXPIRY_GRACE	(5*60)

/* argv0 */
बाह्य वर्ण *__progname;

/* Default files to add */
स्थिर वर्ण *default_files[] = {
#ifdef WITH_OPENSSL
	_PATH_SSH_CLIENT_ID_RSA,
	_PATH_SSH_CLIENT_ID_ECDSA,
	_PATH_SSH_CLIENT_ID_ECDSA_SK,
#endif /* WITH_OPENSSL */
	_PATH_SSH_CLIENT_ID_ED25519,
	_PATH_SSH_CLIENT_ID_ED25519_SK,
	_PATH_SSH_CLIENT_ID_MLDSA44_ED25519,
	रिक्त
};

स्थिर पूर्णाङ्क fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* Default lifetime (0 == forever) */
स्थिर पूर्णाङ्क lifetime = 0;

/* User has to confirm key use */
स्थिर पूर्णाङ्क confirm = 0;

/* we keep a cache of one passphrase */
स्थिर वर्ण *pass = रिक्त;
स्थिर शून्य
clear_pass(शून्य)
{
	जइ (pass) {
		freezero(pass, strlen(pass));
		pass = रिक्त;
	}
}

स्थिर पूर्णाङ्क
delete_one(पूर्णाङ्क agent_fd, ध्रुव संरचना sshkey *कुञ्चिका, ध्रुव वर्ण *comment,
    ध्रुव वर्ण *path, पूर्णाङ्क qflag)
{
	पूर्णाङ्क r;

	जइ ((r = ssh_remove_identity(agent_fd, कुञ्चिका)) != 0) {
		fprintf(stderr, "Could not remove identity \"%s\": %s\n",
		    path, ssh_err(r));
		प्रत्यागम r;
	}
	जइ (!qflag) {
		fprintf(stderr, "Identity removed: %s %s (%s)\n", path,
		    sshkey_type(कुञ्चिका), comment ? comment : "no comment");
	}
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
delete_stdin(पूर्णाङ्क agent_fd, पूर्णाङ्क qflag, पूर्णाङ्क कुञ्चिका_only, पूर्णाङ्क cert_only)
{
	वर्ण *पङ्क्तिः = रिक्त, *cp;
	size_t linesize = 0;
	संरचना sshkey *कुञ्चिका = रिक्त;
	पूर्णाङ्क lnum = 0, r, ret = -1;

	जाव (getline(&पङ्क्तिः, &linesize, stdin) != -1) {
		lnum++;
		sshkey_free(कुञ्चिका);
		कुञ्चिका = रिक्त;
		पङ्क्तिः[strcspn(पङ्क्तिः, "\n")] = '\0';
		cp = पङ्क्तिः + strspn(पङ्क्तिः, " \t");
		जइ (*cp == '#' || *cp == '\0')
			अनुवर्त;
		जइ ((कुञ्चिका = sshkey_new(कुञ्चिका_UNSPEC)) == रिक्त)
			fatal_f("sshkey_new");
		जइ ((r = sshkey_read(कुञ्चिका, &cp)) != 0) {
			error_r(r, "(stdin):%d: invalid key", lnum);
			अनुवर्त;
		}
		जइ ((!कुञ्चिका_only && !cert_only) ||
		    (कुञ्चिका_only && !sshkey_is_cert(कुञ्चिका)) ||
		    (cert_only && sshkey_is_cert(कुञ्चिका))) {
			जइ (delete_one(agent_fd, कुञ्चिका, cp,
			    "(stdin)", qflag) == 0)
				ret = 0;
		}
	}
	sshkey_free(कुञ्चिका);
	मुक्त(पङ्क्तिः);
	प्रत्यागम ret;
}

स्थिर पूर्णाङ्क
delete_file(पूर्णाङ्क agent_fd, ध्रुव वर्ण *filename, पूर्णाङ्क कुञ्चिका_only,
    पूर्णाङ्क cert_only, पूर्णाङ्क qflag)
{
	संरचना sshkey *सार्वजनिक, *cert = रिक्त;
	वर्ण *certpath = रिक्त, *comment = रिक्त;
	पूर्णाङ्क r, ret = -1;

	जइ (strcmp(filename, "-") == 0)
		प्रत्यागम delete_stdin(agent_fd, qflag, कुञ्चिका_only, cert_only);

	जइ ((r = sshkey_load_public(filename, &सार्वजनिक,  &comment)) != 0) {
		printf("Bad key file %s: %s\n", filename, ssh_err(r));
		प्रत्यागम -1;
	}
	जइ ((!कुञ्चिका_only && !cert_only) ||
	    (कुञ्चिका_only && !sshkey_is_cert(सार्वजनिक)) ||
	    (cert_only && sshkey_is_cert(सार्वजनिक))) {
		जइ (delete_one(agent_fd, सार्वजनिक, comment, filename, qflag) == 0)
			ret = 0;
	}

	जइ (कुञ्चिका_only)
		गच्छ out;

	/* Now try to delete the corresponding certificate too */
	मुक्त(comment);
	comment = रिक्त;
	xasprintf(&certpath, "%s-cert.pub", filename);
	जइ ((r = sshkey_load_public(certpath, &cert, &comment)) != 0) {
		जइ (r != SSH_ERR_SYSTEM_ERROR || errno != ENOENT)
			error_r(r, "Failed to load certificate \"%s\"", certpath);
		गच्छ out;
	}

	जइ (!sshkey_equal_public(cert, सार्वजनिक))
		fatal("Certificate %s does not match private key %s",
		    certpath, filename);

	जइ (delete_one(agent_fd, cert, comment, certpath, qflag) == 0)
		ret = 0;

 out:
	sshkey_free(cert);
	sshkey_free(सार्वजनिक);
	मुक्त(certpath);
	मुक्त(comment);

	प्रत्यागम ret;
}

/* Send a request to remove all identities. */
स्थिर पूर्णाङ्क
delete_all(पूर्णाङ्क agent_fd, पूर्णाङ्क qflag)
{
	पूर्णाङ्क ret = -1;

	/*
	 * Since the agent might be forwarded, old or non-OpenSSH, when asked
	 * to remove all keys, attempt to remove both protocol v.1 and v.2
	 * keys.
	 */
	जइ (ssh_remove_all_identities(agent_fd, 2) == 0)
		ret = 0;
	/* ignore error-code for ssh1 */
	ssh_remove_all_identities(agent_fd, 1);

	जइ (ret != 0)
		fprintf(stderr, "Failed to remove all identities.\n");
	अण्णहा जइ (!qflag)
		fprintf(stderr, "All identities removed.\n");

	प्रत्यागम ret;
}

स्थिर पूर्णाङ्क
query_exts(पूर्णाङ्क agent_fd)
{
	पूर्णाङ्क r;
	वर्ण **exts = रिक्त;
	size_t i;

	जइ ((r = ssh_agent_query_extensions(agent_fd, &exts)) != 0)
		fatal_r(r, "unable to query supported extensions");
	प्रति (i = 0; exts != रिक्त && exts[i] != रिक्त; i++)
		puts(exts[i]);
	stringlist_free(exts);
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
check_cert_lifetime(ध्रुव संरचना sshkey *cert, पूर्णाङ्क cert_lifetime)
{
	time_t now;
	uint64_t n;

	जइ (cert == रिक्त || cert->cert == रिक्त || !sshkey_is_cert(cert) ||
	    cert->cert->valid_before == 0xFFFFFFFFFFFFFFFFULL)
		प्रत्यागम cert_lifetime;
	जइ ((now = time(रिक्त)) <= 0)
		fatal_f("system time is at/before epoch");
	जइ ((uint64_t)now > (cert->cert->valid_before + CERT_EXPIRY_GRACE))
		प्रत्यागम -1; /* certificate already expired */
	n = (CERT_EXPIRY_GRACE + cert->cert->valid_before) - (uint64_t)now;
	n = MINIMUM(n, INT_MAX);
	जइ (cert_lifetime <= 0)
		प्रत्यागम (पूर्णाङ्क)n;
	प्रत्यागम MINIMUM(cert_lifetime, (पूर्णाङ्क)n);
}

स्थिर पूर्णाङ्क
add_file(पूर्णाङ्क agent_fd, ध्रुव वर्ण *filename, पूर्णाङ्क कुञ्चिका_only, पूर्णाङ्क cert_only,
    पूर्णाङ्क qflag, पूर्णाङ्क Nflag, ध्रुव वर्ण *skprovider,
    संरचना dest_constraint **dest_constraints,
    size_t ndest_constraints)
{
	संरचना sshkey *गुप्त = रिक्त, *cert = रिक्त;
	वर्ण *comment = रिक्त;
	वर्ण सन्देशः[1024], *certpath = रिक्त;
	पूर्णाङ्क cert_lifetime, r, fd, ret = -1;
	संरचना sshbuf *keyblob;

	जइ (strcmp(filename, "-") == 0) {
		fd = STDIN_FILENO;
		filename = "(stdin)";
	} अण्णहा जइ ((fd = open(filename, O_RDONLY)) == -1) {
		perror(filename);
		प्रत्यागम -1;
	}

	/*
	 * Since we'll try to load a keyfile multiple times, permission errors
	 * will occur multiple times, so check perms first and bail if wrong.
	 */
	जइ (fd != STDIN_FILENO) {
		जइ (sshkey_perm_ok(fd, filename) != 0) {
			close(fd);
			प्रत्यागम -1;
		}
	}
	जइ ((r = sshbuf_load_fd(fd, &keyblob)) != 0) {
		fprintf(stderr, "Error loading key \"%s\": %s\n",
		    filename, ssh_err(r));
		sshbuf_free(keyblob);
		close(fd);
		प्रत्यागम -1;
	}
	close(fd);

	/* At first, try empty passphrase */
	जइ ((r = sshkey_parse_private_fileblob(keyblob, "", &गुप्त,
	    &comment)) != 0 && r != SSH_ERR_कुञ्चिका_WRONG_PASSPHRASE) {
		fprintf(stderr, "Error loading key \"%s\": %s\n",
		    filename, ssh_err(r));
		गच्छ fail_load;
	}
	/* try last */
	जइ (गुप्त == रिक्त && pass != रिक्त) {
		जइ ((r = sshkey_parse_private_fileblob(keyblob, pass, &गुप्त,
		    &comment)) != 0 && r != SSH_ERR_कुञ्चिका_WRONG_PASSPHRASE) {
			fprintf(stderr, "Error loading key \"%s\": %s\n",
			    filename, ssh_err(r));
			गच्छ fail_load;
		}
	}
	जइ (गुप्त == रिक्त) {
		/* clear passphrase since it did not work */
		clear_pass();
		snprintf(सन्देशः, परिमाण सन्देशः, "Enter passphrase for %s%s: ",
		    filename, confirm ? " (will confirm each use)" : "");
		प्रति (;;) {
			pass = read_passphrase(सन्देशः, RP_ALLOW_STDIN);
			जइ (strcmp(pass, "") == 0)
				गच्छ fail_load;
			जइ ((r = sshkey_parse_private_fileblob(keyblob, pass,
			    &गुप्त, &comment)) == 0)
				भङ्ग;
			अण्णहा जइ (r != SSH_ERR_कुञ्चिका_WRONG_PASSPHRASE) {
				fprintf(stderr,
				    "Error loading key \"%s\": %s\n",
				    filename, ssh_err(r));
 fail_load:
				clear_pass();
				sshbuf_free(keyblob);
				प्रत्यागम -1;
			}
			clear_pass();
			snprintf(सन्देशः, परिमाण सन्देशः,
			    "Bad passphrase, try again for %s%s: ", filename,
			    confirm ? " (will confirm each use)" : "");
		}
	}
	जइ (comment == रिक्त || *comment == '\0')
		comment = xstrdup(filename);
	sshbuf_free(keyblob);

	जइ (sshkey_is_sk(गुप्त)) {
		जइ (skprovider == रिक्त) {
			fprintf(stderr, "Cannot load FIDO key %s "
			    "without provider\n", filename);
			गच्छ out;
		}
	} अण्णहा {
		/* Don't send provider constraint for other keys */
		skprovider = रिक्त;
	}

	जइ (!cert_only) {
		जइ ((r = ssh_add_identity_constrained(agent_fd, गुप्त,
		    comment, lifetime, confirm, skprovider,
		    dest_constraints, ndest_constraints)) == 0) {
			ret = 0;
			जइ (!qflag) {
				fprintf(stderr, "Identity added: %s (%s)\n",
				    filename, comment);
				जइ (lifetime != 0) {
					fprintf(stderr, "Lifetime set to %s\n",
					    fmt_timeframe((time_t)lifetime));
				}
				जइ (confirm != 0) {
					fprintf(stderr, "The user must confirm "
					    "each use of the key\n");
				}
			}
		} अण्णहा {
			fprintf(stderr, "Could not add identity \"%s\": %s\n",
			    filename, ssh_err(r));
		}
	}

	/* Skip trying to load the cert if requested */
	जइ (कुञ्चिका_only)
		गच्छ out;

	/* Now try to add the certificate flavour too */
	xasprintf(&certpath, "%s-cert.pub", filename);
	जइ ((r = sshkey_load_public(certpath, &cert, रिक्त)) != 0) {
		जइ (r != SSH_ERR_SYSTEM_ERROR || errno != ENOENT)
			error_r(r, "Failed to load certificate \"%s\"",
			    certpath);
		गच्छ out;
	}

	जइ (!sshkey_equal_public(cert, गुप्त)) {
		error("Certificate %s does not match private key %s",
		    certpath, filename);
		गच्छ out;
	}

	cert_lifetime = lifetime;
	जइ (!Nflag &&
	    (cert_lifetime = check_cert_lifetime(cert, cert_lifetime)) == -1) {
		logit("Certificate %s has already expired; ignored", certpath);
		गच्छ out;
	}

	/* Graft with private bits */
	जइ ((r = sshkey_to_certified(गुप्त)) != 0) {
		error_fr(r, "sshkey_to_certified");
		गच्छ out;
	}
	जइ ((r = sshkey_cert_copy(cert, गुप्त)) != 0) {
		error_fr(r, "sshkey_cert_copy");
		गच्छ out;
	}
	/* send to agent */
	जइ ((r = ssh_add_identity_constrained(agent_fd, गुप्त, comment,
	    cert_lifetime, confirm, skprovider,
	    dest_constraints, ndest_constraints)) != 0) {
		error_r(r, "Certificate %s (%s) add failed", certpath,
		    गुप्त->cert->कुञ्चिका_id);
		गच्छ out;
	}
	/* success */
	जइ (!qflag) {
		fprintf(stderr, "Certificate added: %s (%s)\n", certpath,
		    गुप्त->cert->कुञ्चिका_id);
		जइ (cert_lifetime != 0) {
			fprintf(stderr, "Lifetime set to %s\n",
			    fmt_timeframe((time_t)cert_lifetime));
		}
		जइ (confirm != 0) {
			fprintf(stderr, "The user must confirm each use "
			    "of the key\n");
		}
	}

 out:
	मुक्त(certpath);
	मुक्त(comment);
	sshkey_free(cert);
	sshkey_free(गुप्त);

	प्रत्यागम ret;
}

स्थिर पूर्णाङ्क
update_card(पूर्णाङ्क agent_fd, पूर्णाङ्क add, ध्रुव वर्ण *id, पूर्णाङ्क qflag, पूर्णाङ्क no_pin,
    पूर्णाङ्क कुञ्चिका_only, पूर्णाङ्क cert_only,
    संरचना dest_constraint **dest_constraints, size_t ndest_constraints,
    संरचना sshkey **certs, size_t ncerts)
{
	वर्ण *pin = रिक्त;
	पूर्णाङ्क r, ret = -1;

	जइ (कुञ्चिका_only)
		ncerts = 0;

	जइ (add && !no_pin) {
		जइ ((pin = read_passphrase("Enter passphrase for PKCS#11: ",
		    RP_ALLOW_STDIN)) == रिक्त)
			प्रत्यागम -1;
	}

	जइ ((r = ssh_update_card(agent_fd, add, id, pin == रिक्त ? "" : pin,
	    lifetime, confirm, dest_constraints, ndest_constraints,
	    cert_only, certs, ncerts)) == 0) {
		ret = 0;
		जइ (!qflag) {
			fprintf(stderr, "Card %s: %s\n",
			    add ? "added" : "removed", id);
		}
	} अण्णहा {
		fprintf(stderr, "Could not %s card \"%s\": %s\n",
		    add ? "add" : "remove", id, ssh_err(r));
		ret = -1;
	}
	मुक्त(pin);
	प्रत्यागम ret;
}

स्थिर पूर्णाङ्क
test_कुञ्चिका(पूर्णाङ्क agent_fd, ध्रुव वर्ण *filename)
{
	संरचना sshkey *कुञ्चिका = रिक्त;
	u_char *sig = रिक्त;
	ध्रुव वर्ण *alg = रिक्त;
	size_t slen = 0;
	पूर्णाङ्क r, ret = -1;
	वर्ण data[1024];

	जइ ((r = sshkey_load_public(filename, &कुञ्चिका, रिक्त)) != 0) {
		error_r(r, "Couldn't read public key %s", filename);
		प्रत्यागम -1;
	}
	जइ (sshkey_type_plain(कुञ्चिका->type) == कुञ्चिका_RSA)
		alg = "rsa-sha2-256";
	arc4random_buf(data, परिमाण(data));
	जइ ((r = ssh_agent_sign(agent_fd, कुञ्चिका, &sig, &slen, data, परिमाण(data),
	    alg, 0)) != 0) {
		error_r(r, "Agent signature failed for %s", filename);
		गच्छ done;
	}
	जइ ((r = sshkey_verify(कुञ्चिका, sig, slen, data, परिमाण(data),
	    alg, 0, रिक्त)) != 0) {
		error_r(r, "Signature verification failed for %s", filename);
		गच्छ done;
	}
	/* success */
	ret = 0;
 done:
	मुक्त(sig);
	sshkey_free(कुञ्चिका);
	प्रत्यागम ret;
}

स्थिर पूर्णाङ्क
list_identities(पूर्णाङ्क agent_fd, पूर्णाङ्क do_fp)
{
	वर्ण *fp;
	पूर्णाङ्क r;
	संरचना ssh_identitylist *idlist;
	size_t i;

	जइ ((r = ssh_fetch_identitylist(agent_fd, &idlist)) != 0) {
		जइ (r != SSH_ERR_AGENT_NO_IDENTITIES)
			fprintf(stderr, "error fetching identities: %s\n",
			    ssh_err(r));
		अण्णहा
			printf("The agent has no identities.\n");
		प्रत्यागम -1;
	}
	प्रति (i = 0; i < idlist->nkeys; i++) {
		जइ (do_fp) {
			fp = sshkey_fingerprint(idlist->कुञ्चिकाः[i],
			    fingerprint_hash, SSH_FP_DEFAULT);
			printf("%u %s %s (%s)\n", sshkey_size(idlist->कुञ्चिकाः[i]),
			    fp == रिक्त ? "(null)" : fp, idlist->comments[i],
			    sshkey_type(idlist->कुञ्चिकाः[i]));
			मुक्त(fp);
		} अण्णहा {
			जइ ((r = sshkey_write(idlist->कुञ्चिकाः[i], stdout)) != 0) {
				fprintf(stderr, "sshkey_write: %s\n",
				    ssh_err(r));
				अनुवर्त;
			}
			fprintf(stdout, " %s\n", idlist->comments[i]);
		}
	}
	ssh_free_identitylist(idlist);
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
lock_agent(पूर्णाङ्क agent_fd, पूर्णाङ्क lock)
{
	वर्ण prompt[100], *p1, *p2;
	पूर्णाङ्क r, passok = 1, ret = -1;

	strlcpy(prompt, "Enter lock password: ", परिमाण(prompt));
	p1 = read_passphrase(prompt, RP_ALLOW_STDIN);
	जइ (lock) {
		strlcpy(prompt, "Again: ", परिमाण prompt);
		p2 = read_passphrase(prompt, RP_ALLOW_STDIN);
		जइ (strcmp(p1, p2) != 0) {
			fprintf(stderr, "Passwords do not match.\n");
			passok = 0;
		}
		freezero(p2, strlen(p2));
	}
	जइ (passok) {
		जइ ((r = ssh_lock_agent(agent_fd, lock, p1)) == 0) {
			fprintf(stderr, "Agent %slocked.\n", lock ? "" : "un");
			ret = 0;
		} अण्णहा {
			fprintf(stderr, "Failed to %slock agent: %s\n",
			    lock ? "" : "un", ssh_err(r));
		}
	}
	freezero(p1, strlen(p1));
	प्रत्यागम (ret);
}

स्थिर पूर्णाङ्क
load_resident_कुञ्चिकाः(पूर्णाङ्क agent_fd, ध्रुव वर्ण *skprovider, पूर्णाङ्क qflag, पूर्णाङ्क no_pin,
    संरचना dest_constraint **dest_constraints, size_t ndest_constraints)
{
	संरचना sshsk_resident_कुञ्चिका **srks;
	size_t nsrks, i;
	संरचना sshkey *कुञ्चिका;
	पूर्णाङ्क r, ok = 0;
	वर्ण *fp, *pin = रिक्त;

	जइ (!no_pin) {
		pin = read_passphrase("Enter PIN for authenticator: ",
		    RP_ALLOW_STDIN);
	}
	जइ ((r = sshsk_load_resident(skprovider, रिक्त, pin == रिक्त ? "" : pin,
	    0, &srks, &nsrks)) != 0) {
		error_r(r, "Unable to load resident keys");
		मुक्त(pin);
		प्रत्यागम r;
	}
	मुक्त(pin);
	प्रति (i = 0; i < nsrks; i++) {
		कुञ्चिका = srks[i]->कुञ्चिका;
		जइ ((fp = sshkey_fingerprint(कुञ्चिका,
		    fingerprint_hash, SSH_FP_DEFAULT)) == रिक्त)
			fatal_f("sshkey_fingerprint failed");
		जइ ((r = ssh_add_identity_constrained(agent_fd, कुञ्चिका,
		    कुञ्चिका->sk_application, lifetime, confirm, skprovider,
		    dest_constraints, ndest_constraints)) != 0) {
			error("Unable to add key %s %s",
			    sshkey_type(कुञ्चिका), fp);
			मुक्त(fp);
			ok = r;
			अनुवर्त;
		}
		जइ (ok == 0)
			ok = 1;
		जइ (!qflag) {
			fprintf(stderr, "Resident identity added: %s %s\n",
			    sshkey_type(कुञ्चिका), fp);
			जइ (lifetime != 0) {
				fprintf(stderr,
				    "Lifetime set to %d seconds\n", lifetime);
			}
			जइ (confirm != 0) {
				fprintf(stderr, "The user must confirm "
				    "each use of the key\n");
			}
		}
		मुक्त(fp);
	}
	sshsk_free_resident_कुञ्चिकाः(srks, nsrks);
	जइ (nsrks == 0)
		प्रत्यागम SSH_ERR_कुञ्चिका_NOT_FOUND;
	प्रत्यागम ok == 1 ? 0 : ok;
}

स्थिर पूर्णाङ्क
do_file(पूर्णाङ्क agent_fd, पूर्णाङ्क deleting, पूर्णाङ्क कुञ्चिका_only, पूर्णाङ्क cert_only,
    वर्ण *file, पूर्णाङ्क qflag, पूर्णाङ्क Nflag, ध्रुव वर्ण *skprovider,
    संरचना dest_constraint **dest_constraints, size_t ndest_constraints)
{
	जइ (deleting) {
		जइ (delete_file(agent_fd, file, कुञ्चिका_only,
		    cert_only, qflag) == -1)
			प्रत्यागम -1;
	} अण्णहा {
		जइ (add_file(agent_fd, file, कुञ्चिका_only, cert_only, qflag, Nflag,
		    skprovider, dest_constraints, ndest_constraints) == -1)
			प्रत्यागम -1;
	}
	प्रत्यागम 0;
}

स्थिर शून्य
free_dest_constraint_hop(संरचना dest_constraint_hop *dch)
{
	u_int i;

	जइ (dch == रिक्त)
		प्रत्यागम;
	मुक्त(dch->user);
	मुक्त(dch->hostname);
	प्रति (i = 0; i < dch->nkeys; i++)
		sshkey_free(dch->कुञ्चिकाः[i]);
	मुक्त(dch->कुञ्चिकाः);
	मुक्त(dch->कुञ्चिका_is_ca);
}

स्थिर शून्य
free_dest_constraints(संरचना dest_constraint **dcs, size_t ndcs)
{
	size_t i;

	प्रति (i = 0; i < ndcs; i++) {
		free_dest_constraint_hop(&dcs[i]->from);
		free_dest_constraint_hop(&dcs[i]->to);
		मुक्त(dcs[i]);
	}
	मुक्त(dcs);
}


स्थिर शून्य
parse_dest_constraint_hop(ध्रुव वर्ण *s, संरचना dest_constraint_hop *dch,
    वर्ण **hostkey_files)
{
	वर्ण *user = रिक्त, *host, *os, *path;
	size_t i;
	संरचना hostkeys *hostkeys;
	ध्रुव संरचना hostkey_entry *hke;
	पूर्णाङ्क r, want_ca;

	memset(dch, '\0', परिमाण(*dch));
	os = xstrdup(s);
	जइ ((host = strrchr(os, '@')) == रिक्त)
		host = os;
	अण्णहा {
		*host++ = '\0';
		user = os;
	}
	cleanhostname(host);
	/* Trivial case: username@ (all hosts) */
	जइ (*host == '\0') {
		जइ (user == रिक्त) {
			fatal("Invalid key destination constraint \"%s\": "
			    "does not specify user or host", s);
		}
		dch->user = xstrdup(user);
		/* other fields left blank */
		मुक्त(os);
		प्रत्यागम;
	}
	जइ (hostkey_files == रिक्त)
		fatal_f("no hostkey files");
	/* Otherwise we need to look up the keys for this hostname */
	hostkeys = init_hostkeys();
	प्रति (i = 0; hostkey_files[i]; i++) {
		path = tilde_expand_filename(hostkey_files[i], getuid());
		debug2_f("looking up host keys for \"%s\" in %s", host, path);
                load_hostkeys(hostkeys, host, path, 0);
		मुक्त(path);
	}
	dch->user = user == रिक्त ? रिक्त : xstrdup(user);
	dch->hostname = xstrdup(host);
	प्रति (i = 0; i < hostkeys->अङ्कः_entries; i++) {
		hke = hostkeys->entries + i;
		want_ca = hke->marker == MRK_CA;
		जइ (hke->marker != MRK_NONE && !want_ca)
			अनुवर्त;
		debug3_f("%s%s%s: adding %s %skey from %s:%lu as key %u",
		    user == रिक्त ? "": user, user == रिक्त ? "" : "@",
		    host, sshkey_type(hke->कुञ्चिका), want_ca ? "CA " : "",
		    hke->file, hke->पङ्क्तिः, dch->nkeys);
		dch->कुञ्चिकाः = xrecallocarray(dch->कुञ्चिकाः, dch->nkeys,
		    dch->nkeys + 1, परिमाण(*dch->कुञ्चिकाः));
		dch->कुञ्चिका_is_ca = xrecallocarray(dch->कुञ्चिका_is_ca, dch->nkeys,
		    dch->nkeys + 1, परिमाण(*dch->कुञ्चिका_is_ca));
		जइ ((r = sshkey_from_private(hke->कुञ्चिका,
		    &(dch->कुञ्चिकाः[dch->nkeys]))) != 0)
			fatal_fr(r, "sshkey_from_private");
		dch->कुञ्चिका_is_ca[dch->nkeys] = want_ca;
		dch->nkeys++;
	}
	जइ (dch->nkeys == 0)
		fatal("No host keys found for destination \"%s\"", host);
	free_hostkeys(hostkeys);
	मुक्त(os);
	प्रत्यागम;
}

स्थिर शून्य
parse_dest_constraint(ध्रुव वर्ण *s, संरचना dest_constraint ***dcp,
    size_t *ndcp, वर्ण **hostkey_files)
{
	संरचना dest_constraint *dc;
	वर्ण *os, *cp;

	dc = xcalloc(1, परिमाण(*dc));
	os = xstrdup(s);
	जइ ((cp = strchr(os, '>')) == रिक्त) {
		/* initial hop; no 'from' hop specified */
		parse_dest_constraint_hop(os, &dc->to, hostkey_files);
	} अण्णहा {
		/* two hops specified */
		*(cp++) = '\0';
		parse_dest_constraint_hop(os, &dc->from, hostkey_files);
		parse_dest_constraint_hop(cp, &dc->to, hostkey_files);
		जइ (dc->from.user != रिक्त) {
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
	*dcp = xrecallocarray(*dcp, *ndcp, *ndcp + 1, परिमाण(**dcp));
	(*dcp)[(*ndcp)++] = dc;
	मुक्त(os);
}


स्थिर शून्य
usage(शून्य)
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

पूर्णाङ्क
main(पूर्णाङ्क argc, वर्ण **argv)
{
	बाह्य वर्ण *optarg;
	बाह्य पूर्णाङ्क optind;
	पूर्णाङ्क agent_fd = -1;
	वर्ण *pkcs11provider = रिक्त, *skprovider = रिक्त;
	वर्ण **dest_constraint_strings = रिक्त, **hostkey_files = रिक्त;
	पूर्णाङ्क r, i, ch, deleting = 0, ret = 0, कुञ्चिका_only = 0, cert_only = 0;
	पूर्णाङ्क do_download = 0, xflag = 0, lflag = 0, Dflag = 0;
	पूर्णाङ्क Qflag = 0, qflag = 0, Tflag = 0, Nflag = 0, no_pin = 0;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_INFO;
	संरचना sshkey *k, **certs = रिक्त;
	संरचना dest_constraint **dest_constraints = रिक्त;
	size_t n, ndest_constraints = 0, ncerts = 0;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	__progname = ssh_get_progname(argv[0]);
	seed_rng();

	log_init(__progname, log_level, log_facility, 1);

	setvbuf(stdout, रिक्त, _IOLBF, 0);

	skprovider = getenv("SSH_SK_PROVIDER");

	जाव ((ch = getopt(argc, argv, "vkKlLNPCcdDTxXE:e:h:H:M:m:Qqs:S:t:")) != -1) {
		विकल्प (ch) {
		पक्ष 'v':
			जइ (log_level == SYSLOG_LEVEL_INFO)
				log_level = SYSLOG_LEVEL_DEBUG1;
			अण्णहा जइ (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			भङ्ग;
		पक्ष 'N':
			Nflag = 1;
			भङ्ग;
		पक्ष 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			जइ (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			भङ्ग;
		पक्ष 'H':
			stringlist_append(&hostkey_files, optarg);
			भङ्ग;
		पक्ष 'h':
			stringlist_append(&dest_constraint_strings, optarg);
			भङ्ग;
		पक्ष 'k':
			कुञ्चिका_only = 1;
			भङ्ग;
		पक्ष 'C':
			cert_only = 1;
			भङ्ग;
		पक्ष 'K':
			do_download = 1;
			भङ्ग;
		पक्ष 'l':
		पक्ष 'L':
			जइ (lflag != 0)
				fatal("-%c flag already specified", lflag);
			lflag = ch;
			भङ्ग;
		पक्ष 'x':
		पक्ष 'X':
			जइ (xflag != 0)
				fatal("-%c flag already specified", xflag);
			xflag = ch;
			भङ्ग;
		पक्ष 'c':
			confirm = 1;
			भङ्ग;
		पक्ष 'm':
		पक्ष 'M':
			/* deprecated */
			भङ्ग;
		पक्ष 'd':
			deleting = 1;
			भङ्ग;
		पक्ष 'P':
			no_pin = 1;
			भङ्ग;
		पक्ष 'D':
			Dflag = 1;
			भङ्ग;
		पक्ष 's':
			pkcs11provider = optarg;
			भङ्ग;
		पक्ष 'S':
			skprovider = optarg;
			भङ्ग;
		पक्ष 'e':
			deleting = 1;
			pkcs11provider = optarg;
			भङ्ग;
		पक्ष 't':
			जइ ((lifetime = convtime(optarg)) == -1 ||
			    lifetime < 0 || (u_long)lifetime > UINT32_MAX) {
				fprintf(stderr, "Invalid lifetime\n");
				ret = 1;
				गच्छ done;
			}
			भङ्ग;
		पक्ष 'q':
			qflag = 1;
			भङ्ग;
		पक्ष 'Q':
			Qflag = 1;
			भङ्ग;
		पक्ष 'T':
			Tflag = 1;
			भङ्ग;
		स्वभाव:
			usage();
			ret = 1;
			गच्छ done;
		}
	}
	log_init(__progname, log_level, log_facility, 1);

	जइ ((xflag != 0) + (lflag != 0) + (Dflag != 0) + (Qflag != 0) > 1)
		fatal("Invalid combination of actions");

	/* First, get a connection to the authentication agent. */
	विकल्प (r = ssh_get_authentication_socket(&agent_fd)) {
	पक्ष 0:
		भङ्ग;
	पक्ष SSH_ERR_AGENT_NOT_PRESENT:
		fprintf(stderr, "Could not open a connection to your "
		    "authentication agent.\n");
		exit(2);
	स्वभाव:
		fprintf(stderr, "Error connecting to agent: %s\n", ssh_err(r));
		exit(2);
	}

	जइ (xflag) {
		जइ (lock_agent(agent_fd, xflag == 'x' ? 1 : 0) == -1)
			ret = 1;
		गच्छ done;
	} अण्णहा जइ (lflag) {
		जइ (list_identities(agent_fd, lflag == 'l' ? 1 : 0) == -1)
			ret = 1;
		गच्छ done;
	} अण्णहा जइ (Dflag) {
		जइ (delete_all(agent_fd, qflag) == -1)
			ret = 1;
		गच्छ done;
	} अण्णहा जइ (Qflag) {
		जइ (query_exts(agent_fd) == -1)
			ret = 1;
		गच्छ done;
	}

#ifdef ENABLE_SK_INTERNAL
	जइ (skprovider == रिक्त)
		skprovider = "internal";
#endif

	जइ (hostkey_files == रिक्त) {
		/* use defaults from readconf.c */
		stringlist_append(&hostkey_files, _PATH_SSH_USER_HOSTFILE);
		stringlist_append(&hostkey_files, _PATH_SSH_USER_HOSTFILE2);
		stringlist_append(&hostkey_files, _PATH_SSH_SYSTEM_HOSTFILE);
		stringlist_append(&hostkey_files, _PATH_SSH_SYSTEM_HOSTFILE2);
	}
	जइ (dest_constraint_strings != रिक्त) {
		प्रति (i = 0; dest_constraint_strings[i] != रिक्त; i++) {
			parse_dest_constraint(dest_constraint_strings[i],
			  &dest_constraints, &ndest_constraints, hostkey_files);
		}
	}

	argc -= optind;
	argv += optind;
	जइ (Tflag) {
		जइ (argc <= 0)
			fatal("no keys to test");
		प्रति (r = i = 0; i < argc; i++)
			r |= test_कुञ्चिका(agent_fd, argv[i]);
		ret = r == 0 ? 0 : 1;
		गच्छ done;
	}
	जइ (pkcs11provider != रिक्त) {
		प्रति (i = 0; i < argc; i++) {
			जइ ((r = sshkey_load_public(argv[i], &k, रिक्त)) != 0)
				fatal_fr(r, "load certificate %s", argv[i]);
			certs = xrecallocarray(certs, ncerts, ncerts + 1,
			    परिमाण(*certs));
			debug2("%s: %s", argv[i], sshkey_ssh_name(k));
			certs[ncerts++] = k;
		}
		debug2_f("loaded %zu certificates", ncerts);
		जइ (update_card(agent_fd, !deleting, pkcs11provider,
		    qflag, no_pin, कुञ्चिका_only, cert_only,
		    dest_constraints, ndest_constraints,
		    certs, ncerts) == -1)
			ret = 1;
		प्रति (n = 0; n < ncerts; n++)
			sshkey_free(certs[n]);
		मुक्त(certs);
		गच्छ done;
	}
	जइ (do_download) {
		जइ (skprovider == रिक्त)
			fatal("Cannot download keys without provider");
		जइ (load_resident_कुञ्चिकाः(agent_fd, skprovider, qflag, no_pin,
		    dest_constraints, ndest_constraints) != 0)
			ret = 1;
		गच्छ done;
	}
	जइ (argc == 0) {
		वर्ण buf[PATH_MAX];
		संरचना passwd *pw;
		संरचना stat st;
		पूर्णाङ्क गणनम् = 0;

		जइ ((pw = getpwuid(getuid())) == रिक्त) {
			fprintf(stderr, "No user found with uid %u\n",
			    (u_int)getuid());
			ret = 1;
			गच्छ done;
		}

		प्रति (i = 0; default_files[i]; i++) {
			snprintf(buf, परिमाण(buf), "%s/%s", pw->pw_dir,
			    default_files[i]);
			जइ (stat(buf, &st) == -1)
				अनुवर्त;
			जइ (do_file(agent_fd, deleting, कुञ्चिका_only, cert_only,
			    buf, qflag, Nflag, skprovider,
			    dest_constraints, ndest_constraints) == -1)
				ret = 1;
			अण्णहा
				गणनम्++;
		}
		जइ (गणनम् == 0)
			ret = 1;
	} अण्णहा {
		प्रति (i = 0; i < argc; i++) {
			जइ (do_file(agent_fd, deleting, कुञ्चिका_only, cert_only,
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
	प्रत्यागम ret;
}
