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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/stat.h>

#ifdef WITH_OPENSSL
# include <openssl/evp.h>
# include "openbsd-compat/openssl-compat.h"
#endif

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <fcntl.h>
#അന്തര്ഭാവ <pwd.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <limits.h>
#അന്തര്ഭാവ <time.h>

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "ssh.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "authfd.h"
#അന്തര്ഭാവ "authfile.h"
#അന്തര്ഭാവ "pathnames.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "digest.h"
#അന്തര്ഭാവ "ssh-sk.h"
#അന്തര്ഭാവ "sk-api.h"
#അന്തര്ഭാവ "hostfile.h"

#define CERT_EXPIRY_GRACE	(5*60)

/* argv0 */
ബാഹ്യ അക്ഷരം *__progname;

/* Default files to add */
സ്ഥിതം അക്ഷരം *default_files[] = {
#ifdef WITH_OPENSSL
	_PATH_SSH_CLIENT_ID_RSA,
	_PATH_SSH_CLIENT_ID_ECDSA,
	_PATH_SSH_CLIENT_ID_ECDSA_SK,
#endif /* WITH_OPENSSL */
	_PATH_SSH_CLIENT_ID_ED25519,
	_PATH_SSH_CLIENT_ID_ED25519_SK,
	_PATH_SSH_CLIENT_ID_MLDSA44_ED25519,
	ശൂന്യ
};

സ്ഥിതം പൂർണ്ണസംഖ്യ fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* Default lifetime (0 == forever) */
സ്ഥിതം പൂർണ്ണസംഖ്യ lifetime = 0;

/* User has to confirm key use */
സ്ഥിതം പൂർണ്ണസംഖ്യ confirm = 0;

/* we keep a cache of one passphrase */
സ്ഥിതം അക്ഷരം *pass = ശൂന്യ;
സ്ഥിതം ശൂന്യം
clear_pass(ശൂന്യം)
{
	എങ്കിൽ (pass) {
		freezero(pass, strlen(pass));
		pass = ശൂന്യ;
	}
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
delete_one(പൂർണ്ണസംഖ്യ agent_fd, സ്ഥിരം ഘടന sshkey *താക്കോൽ, സ്ഥിരം അക്ഷരം *comment,
    സ്ഥിരം അക്ഷരം *path, പൂർണ്ണസംഖ്യ qflag)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = ssh_remove_identity(agent_fd, താക്കോൽ)) != 0) {
		fprintf(stderr, "Could not remove identity \"%s\": %s\n",
		    path, ssh_err(r));
		തിരികെ r;
	}
	എങ്കിൽ (!qflag) {
		fprintf(stderr, "Identity removed: %s %s (%s)\n", path,
		    sshkey_type(താക്കോൽ), comment ? comment : "no comment");
	}
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
delete_stdin(പൂർണ്ണസംഖ്യ agent_fd, പൂർണ്ണസംഖ്യ qflag, പൂർണ്ണസംഖ്യ താക്കോൽ_only, പൂർണ്ണസംഖ്യ cert_only)
{
	അക്ഷരം *വരി = ശൂന്യ, *cp;
	size_t linesize = 0;
	ഘടന sshkey *താക്കോൽ = ശൂന്യ;
	പൂർണ്ണസംഖ്യ lnum = 0, r, ret = -1;

	ആകുമ്പോൾ (getline(&വരി, &linesize, stdin) != -1) {
		lnum++;
		sshkey_free(താക്കോൽ);
		താക്കോൽ = ശൂന്യ;
		വരി[strcspn(വരി, "\n")] = '\0';
		cp = വരി + strspn(വരി, " \t");
		എങ്കിൽ (*cp == '#' || *cp == '\0')
			തുടരുക;
		എങ്കിൽ ((താക്കോൽ = sshkey_new(താക്കോൽ_UNSPEC)) == ശൂന്യ)
			fatal_f("sshkey_new");
		എങ്കിൽ ((r = sshkey_read(താക്കോൽ, &cp)) != 0) {
			error_r(r, "(stdin):%d: invalid key", lnum);
			തുടരുക;
		}
		എങ്കിൽ ((!താക്കോൽ_only && !cert_only) ||
		    (താക്കോൽ_only && !sshkey_is_cert(താക്കോൽ)) ||
		    (cert_only && sshkey_is_cert(താക്കോൽ))) {
			എങ്കിൽ (delete_one(agent_fd, താക്കോൽ, cp,
			    "(stdin)", qflag) == 0)
				ret = 0;
		}
	}
	sshkey_free(താക്കോൽ);
	സ്വതന്ത്രം(വരി);
	തിരികെ ret;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
delete_file(പൂർണ്ണസംഖ്യ agent_fd, സ്ഥിരം അക്ഷരം *filename, പൂർണ്ണസംഖ്യ താക്കോൽ_only,
    പൂർണ്ണസംഖ്യ cert_only, പൂർണ്ണസംഖ്യ qflag)
{
	ഘടന sshkey *പൊതു, *cert = ശൂന്യ;
	അക്ഷരം *certpath = ശൂന്യ, *comment = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r, ret = -1;

	എങ്കിൽ (strcmp(filename, "-") == 0)
		തിരികെ delete_stdin(agent_fd, qflag, താക്കോൽ_only, cert_only);

	എങ്കിൽ ((r = sshkey_load_public(filename, &പൊതു,  &comment)) != 0) {
		printf("Bad key file %s: %s\n", filename, ssh_err(r));
		തിരികെ -1;
	}
	എങ്കിൽ ((!താക്കോൽ_only && !cert_only) ||
	    (താക്കോൽ_only && !sshkey_is_cert(പൊതു)) ||
	    (cert_only && sshkey_is_cert(പൊതു))) {
		എങ്കിൽ (delete_one(agent_fd, പൊതു, comment, filename, qflag) == 0)
			ret = 0;
	}

	എങ്കിൽ (താക്കോൽ_only)
		പോകുക out;

	/* Now try to delete the corresponding certificate too */
	സ്വതന്ത്രം(comment);
	comment = ശൂന്യ;
	xasprintf(&certpath, "%s-cert.pub", filename);
	എങ്കിൽ ((r = sshkey_load_public(certpath, &cert, &comment)) != 0) {
		എങ്കിൽ (r != SSH_ERR_SYSTEM_ERROR || errno != ENOENT)
			error_r(r, "Failed to load certificate \"%s\"", certpath);
		പോകുക out;
	}

	എങ്കിൽ (!sshkey_equal_public(cert, പൊതു))
		fatal("Certificate %s does not match private key %s",
		    certpath, filename);

	എങ്കിൽ (delete_one(agent_fd, cert, comment, certpath, qflag) == 0)
		ret = 0;

 out:
	sshkey_free(cert);
	sshkey_free(പൊതു);
	സ്വതന്ത്രം(certpath);
	സ്വതന്ത്രം(comment);

	തിരികെ ret;
}

/* Send a request to remove all identities. */
സ്ഥിതം പൂർണ്ണസംഖ്യ
delete_all(പൂർണ്ണസംഖ്യ agent_fd, പൂർണ്ണസംഖ്യ qflag)
{
	പൂർണ്ണസംഖ്യ ret = -1;

	/*
	 * Since the agent might be forwarded, old or non-OpenSSH, when asked
	 * to remove all keys, attempt to remove both protocol v.1 and v.2
	 * keys.
	 */
	എങ്കിൽ (ssh_remove_all_identities(agent_fd, 2) == 0)
		ret = 0;
	/* ignore error-code for ssh1 */
	ssh_remove_all_identities(agent_fd, 1);

	എങ്കിൽ (ret != 0)
		fprintf(stderr, "Failed to remove all identities.\n");
	അല്ലെങ്കിൽ എങ്കിൽ (!qflag)
		fprintf(stderr, "All identities removed.\n");

	തിരികെ ret;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
query_exts(പൂർണ്ണസംഖ്യ agent_fd)
{
	പൂർണ്ണസംഖ്യ r;
	അക്ഷരം **exts = ശൂന്യ;
	size_t i;

	എങ്കിൽ ((r = ssh_agent_query_extensions(agent_fd, &exts)) != 0)
		fatal_r(r, "unable to query supported extensions");
	വേണ്ടി (i = 0; exts != ശൂന്യ && exts[i] != ശൂന്യ; i++)
		puts(exts[i]);
	stringlist_free(exts);
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
check_cert_lifetime(സ്ഥിരം ഘടന sshkey *cert, പൂർണ്ണസംഖ്യ cert_lifetime)
{
	time_t now;
	uint64_t n;

	എങ്കിൽ (cert == ശൂന്യ || cert->cert == ശൂന്യ || !sshkey_is_cert(cert) ||
	    cert->cert->valid_before == 0xFFFFFFFFFFFFFFFFULL)
		തിരികെ cert_lifetime;
	എങ്കിൽ ((now = time(ശൂന്യ)) <= 0)
		fatal_f("system time is at/before epoch");
	എങ്കിൽ ((uint64_t)now > (cert->cert->valid_before + CERT_EXPIRY_GRACE))
		തിരികെ -1; /* certificate already expired */
	n = (CERT_EXPIRY_GRACE + cert->cert->valid_before) - (uint64_t)now;
	n = MINIMUM(n, INT_MAX);
	എങ്കിൽ (cert_lifetime <= 0)
		തിരികെ (പൂർണ്ണസംഖ്യ)n;
	തിരികെ MINIMUM(cert_lifetime, (പൂർണ്ണസംഖ്യ)n);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
add_file(പൂർണ്ണസംഖ്യ agent_fd, സ്ഥിരം അക്ഷരം *filename, പൂർണ്ണസംഖ്യ താക്കോൽ_only, പൂർണ്ണസംഖ്യ cert_only,
    പൂർണ്ണസംഖ്യ qflag, പൂർണ്ണസംഖ്യ Nflag, സ്ഥിരം അക്ഷരം *skprovider,
    ഘടന dest_constraint **dest_constraints,
    size_t ndest_constraints)
{
	ഘടന sshkey *സ്വകാര്യ = ശൂന്യ, *cert = ശൂന്യ;
	അക്ഷരം *comment = ശൂന്യ;
	അക്ഷരം സന്ദേശം[1024], *certpath = ശൂന്യ;
	പൂർണ്ണസംഖ്യ cert_lifetime, r, fd, ret = -1;
	ഘടന sshbuf *keyblob;

	എങ്കിൽ (strcmp(filename, "-") == 0) {
		fd = STDIN_FILENO;
		filename = "(stdin)";
	} അല്ലെങ്കിൽ എങ്കിൽ ((fd = open(filename, O_RDONLY)) == -1) {
		perror(filename);
		തിരികെ -1;
	}

	/*
	 * Since we'll try to load a keyfile multiple times, permission errors
	 * will occur multiple times, so check perms first and bail if wrong.
	 */
	എങ്കിൽ (fd != STDIN_FILENO) {
		എങ്കിൽ (sshkey_perm_ok(fd, filename) != 0) {
			close(fd);
			തിരികെ -1;
		}
	}
	എങ്കിൽ ((r = sshbuf_load_fd(fd, &keyblob)) != 0) {
		fprintf(stderr, "Error loading key \"%s\": %s\n",
		    filename, ssh_err(r));
		sshbuf_free(keyblob);
		close(fd);
		തിരികെ -1;
	}
	close(fd);

	/* At first, try empty passphrase */
	എങ്കിൽ ((r = sshkey_parse_private_fileblob(keyblob, "", &സ്വകാര്യ,
	    &comment)) != 0 && r != SSH_ERR_താക്കോൽ_WRONG_PASSPHRASE) {
		fprintf(stderr, "Error loading key \"%s\": %s\n",
		    filename, ssh_err(r));
		പോകുക fail_load;
	}
	/* try last */
	എങ്കിൽ (സ്വകാര്യ == ശൂന്യ && pass != ശൂന്യ) {
		എങ്കിൽ ((r = sshkey_parse_private_fileblob(keyblob, pass, &സ്വകാര്യ,
		    &comment)) != 0 && r != SSH_ERR_താക്കോൽ_WRONG_PASSPHRASE) {
			fprintf(stderr, "Error loading key \"%s\": %s\n",
			    filename, ssh_err(r));
			പോകുക fail_load;
		}
	}
	എങ്കിൽ (സ്വകാര്യ == ശൂന്യ) {
		/* clear passphrase since it did not work */
		clear_pass();
		snprintf(സന്ദേശം, വലുപ്പം സന്ദേശം, "Enter passphrase for %s%s: ",
		    filename, confirm ? " (will confirm each use)" : "");
		വേണ്ടി (;;) {
			pass = read_passphrase(സന്ദേശം, RP_ALLOW_STDIN);
			എങ്കിൽ (strcmp(pass, "") == 0)
				പോകുക fail_load;
			എങ്കിൽ ((r = sshkey_parse_private_fileblob(keyblob, pass,
			    &സ്വകാര്യ, &comment)) == 0)
				നിർത്തുക;
			അല്ലെങ്കിൽ എങ്കിൽ (r != SSH_ERR_താക്കോൽ_WRONG_PASSPHRASE) {
				fprintf(stderr,
				    "Error loading key \"%s\": %s\n",
				    filename, ssh_err(r));
 fail_load:
				clear_pass();
				sshbuf_free(keyblob);
				തിരികെ -1;
			}
			clear_pass();
			snprintf(സന്ദേശം, വലുപ്പം സന്ദേശം,
			    "Bad passphrase, try again for %s%s: ", filename,
			    confirm ? " (will confirm each use)" : "");
		}
	}
	എങ്കിൽ (comment == ശൂന്യ || *comment == '\0')
		comment = xstrdup(filename);
	sshbuf_free(keyblob);

	എങ്കിൽ (sshkey_is_sk(സ്വകാര്യ)) {
		എങ്കിൽ (skprovider == ശൂന്യ) {
			fprintf(stderr, "Cannot load FIDO key %s "
			    "without provider\n", filename);
			പോകുക out;
		}
	} അല്ലെങ്കിൽ {
		/* Don't send provider constraint for other keys */
		skprovider = ശൂന്യ;
	}

	എങ്കിൽ (!cert_only) {
		എങ്കിൽ ((r = ssh_add_identity_constrained(agent_fd, സ്വകാര്യ,
		    comment, lifetime, confirm, skprovider,
		    dest_constraints, ndest_constraints)) == 0) {
			ret = 0;
			എങ്കിൽ (!qflag) {
				fprintf(stderr, "Identity added: %s (%s)\n",
				    filename, comment);
				എങ്കിൽ (lifetime != 0) {
					fprintf(stderr, "Lifetime set to %s\n",
					    fmt_timeframe((time_t)lifetime));
				}
				എങ്കിൽ (confirm != 0) {
					fprintf(stderr, "The user must confirm "
					    "each use of the key\n");
				}
			}
		} അല്ലെങ്കിൽ {
			fprintf(stderr, "Could not add identity \"%s\": %s\n",
			    filename, ssh_err(r));
		}
	}

	/* Skip trying to load the cert if requested */
	എങ്കിൽ (താക്കോൽ_only)
		പോകുക out;

	/* Now try to add the certificate flavour too */
	xasprintf(&certpath, "%s-cert.pub", filename);
	എങ്കിൽ ((r = sshkey_load_public(certpath, &cert, ശൂന്യ)) != 0) {
		എങ്കിൽ (r != SSH_ERR_SYSTEM_ERROR || errno != ENOENT)
			error_r(r, "Failed to load certificate \"%s\"",
			    certpath);
		പോകുക out;
	}

	എങ്കിൽ (!sshkey_equal_public(cert, സ്വകാര്യ)) {
		error("Certificate %s does not match private key %s",
		    certpath, filename);
		പോകുക out;
	}

	cert_lifetime = lifetime;
	എങ്കിൽ (!Nflag &&
	    (cert_lifetime = check_cert_lifetime(cert, cert_lifetime)) == -1) {
		logit("Certificate %s has already expired; ignored", certpath);
		പോകുക out;
	}

	/* Graft with private bits */
	എങ്കിൽ ((r = sshkey_to_certified(സ്വകാര്യ)) != 0) {
		error_fr(r, "sshkey_to_certified");
		പോകുക out;
	}
	എങ്കിൽ ((r = sshkey_cert_copy(cert, സ്വകാര്യ)) != 0) {
		error_fr(r, "sshkey_cert_copy");
		പോകുക out;
	}
	/* send to agent */
	എങ്കിൽ ((r = ssh_add_identity_constrained(agent_fd, സ്വകാര്യ, comment,
	    cert_lifetime, confirm, skprovider,
	    dest_constraints, ndest_constraints)) != 0) {
		error_r(r, "Certificate %s (%s) add failed", certpath,
		    സ്വകാര്യ->cert->താക്കോൽ_id);
		പോകുക out;
	}
	/* success */
	എങ്കിൽ (!qflag) {
		fprintf(stderr, "Certificate added: %s (%s)\n", certpath,
		    സ്വകാര്യ->cert->താക്കോൽ_id);
		എങ്കിൽ (cert_lifetime != 0) {
			fprintf(stderr, "Lifetime set to %s\n",
			    fmt_timeframe((time_t)cert_lifetime));
		}
		എങ്കിൽ (confirm != 0) {
			fprintf(stderr, "The user must confirm each use "
			    "of the key\n");
		}
	}

 out:
	സ്വതന്ത്രം(certpath);
	സ്വതന്ത്രം(comment);
	sshkey_free(cert);
	sshkey_free(സ്വകാര്യ);

	തിരികെ ret;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
update_card(പൂർണ്ണസംഖ്യ agent_fd, പൂർണ്ണസംഖ്യ add, സ്ഥിരം അക്ഷരം *id, പൂർണ്ണസംഖ്യ qflag, പൂർണ്ണസംഖ്യ no_pin,
    പൂർണ്ണസംഖ്യ താക്കോൽ_only, പൂർണ്ണസംഖ്യ cert_only,
    ഘടന dest_constraint **dest_constraints, size_t ndest_constraints,
    ഘടന sshkey **certs, size_t ncerts)
{
	അക്ഷരം *pin = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r, ret = -1;

	എങ്കിൽ (താക്കോൽ_only)
		ncerts = 0;

	എങ്കിൽ (add && !no_pin) {
		എങ്കിൽ ((pin = read_passphrase("Enter passphrase for PKCS#11: ",
		    RP_ALLOW_STDIN)) == ശൂന്യ)
			തിരികെ -1;
	}

	എങ്കിൽ ((r = ssh_update_card(agent_fd, add, id, pin == ശൂന്യ ? "" : pin,
	    lifetime, confirm, dest_constraints, ndest_constraints,
	    cert_only, certs, ncerts)) == 0) {
		ret = 0;
		എങ്കിൽ (!qflag) {
			fprintf(stderr, "Card %s: %s\n",
			    add ? "added" : "removed", id);
		}
	} അല്ലെങ്കിൽ {
		fprintf(stderr, "Could not %s card \"%s\": %s\n",
		    add ? "add" : "remove", id, ssh_err(r));
		ret = -1;
	}
	സ്വതന്ത്രം(pin);
	തിരികെ ret;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
test_താക്കോൽ(പൂർണ്ണസംഖ്യ agent_fd, സ്ഥിരം അക്ഷരം *filename)
{
	ഘടന sshkey *താക്കോൽ = ശൂന്യ;
	u_char *sig = ശൂന്യ;
	സ്ഥിരം അക്ഷരം *alg = ശൂന്യ;
	size_t slen = 0;
	പൂർണ്ണസംഖ്യ r, ret = -1;
	അക്ഷരം data[1024];

	എങ്കിൽ ((r = sshkey_load_public(filename, &താക്കോൽ, ശൂന്യ)) != 0) {
		error_r(r, "Couldn't read public key %s", filename);
		തിരികെ -1;
	}
	എങ്കിൽ (sshkey_type_plain(താക്കോൽ->type) == താക്കോൽ_RSA)
		alg = "rsa-sha2-256";
	arc4random_buf(data, വലുപ്പം(data));
	എങ്കിൽ ((r = ssh_agent_sign(agent_fd, താക്കോൽ, &sig, &slen, data, വലുപ്പം(data),
	    alg, 0)) != 0) {
		error_r(r, "Agent signature failed for %s", filename);
		പോകുക done;
	}
	എങ്കിൽ ((r = sshkey_verify(താക്കോൽ, sig, slen, data, വലുപ്പം(data),
	    alg, 0, ശൂന്യ)) != 0) {
		error_r(r, "Signature verification failed for %s", filename);
		പോകുക done;
	}
	/* success */
	ret = 0;
 done:
	സ്വതന്ത്രം(sig);
	sshkey_free(താക്കോൽ);
	തിരികെ ret;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
list_identities(പൂർണ്ണസംഖ്യ agent_fd, പൂർണ്ണസംഖ്യ do_fp)
{
	അക്ഷരം *fp;
	പൂർണ്ണസംഖ്യ r;
	ഘടന ssh_identitylist *idlist;
	size_t i;

	എങ്കിൽ ((r = ssh_fetch_identitylist(agent_fd, &idlist)) != 0) {
		എങ്കിൽ (r != SSH_ERR_AGENT_NO_IDENTITIES)
			fprintf(stderr, "error fetching identities: %s\n",
			    ssh_err(r));
		അല്ലെങ്കിൽ
			printf("The agent has no identities.\n");
		തിരികെ -1;
	}
	വേണ്ടി (i = 0; i < idlist->nkeys; i++) {
		എങ്കിൽ (do_fp) {
			fp = sshkey_fingerprint(idlist->താക്കോലുകൾ[i],
			    fingerprint_hash, SSH_FP_DEFAULT);
			printf("%u %s %s (%s)\n", sshkey_size(idlist->താക്കോലുകൾ[i]),
			    fp == ശൂന്യ ? "(null)" : fp, idlist->comments[i],
			    sshkey_type(idlist->താക്കോലുകൾ[i]));
			സ്വതന്ത്രം(fp);
		} അല്ലെങ്കിൽ {
			എങ്കിൽ ((r = sshkey_write(idlist->താക്കോലുകൾ[i], stdout)) != 0) {
				fprintf(stderr, "sshkey_write: %s\n",
				    ssh_err(r));
				തുടരുക;
			}
			fprintf(stdout, " %s\n", idlist->comments[i]);
		}
	}
	ssh_free_identitylist(idlist);
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
lock_agent(പൂർണ്ണസംഖ്യ agent_fd, പൂർണ്ണസംഖ്യ lock)
{
	അക്ഷരം prompt[100], *p1, *p2;
	പൂർണ്ണസംഖ്യ r, passok = 1, ret = -1;

	strlcpy(prompt, "Enter lock password: ", വലുപ്പം(prompt));
	p1 = read_passphrase(prompt, RP_ALLOW_STDIN);
	എങ്കിൽ (lock) {
		strlcpy(prompt, "Again: ", വലുപ്പം prompt);
		p2 = read_passphrase(prompt, RP_ALLOW_STDIN);
		എങ്കിൽ (strcmp(p1, p2) != 0) {
			fprintf(stderr, "Passwords do not match.\n");
			passok = 0;
		}
		freezero(p2, strlen(p2));
	}
	എങ്കിൽ (passok) {
		എങ്കിൽ ((r = ssh_lock_agent(agent_fd, lock, p1)) == 0) {
			fprintf(stderr, "Agent %slocked.\n", lock ? "" : "un");
			ret = 0;
		} അല്ലെങ്കിൽ {
			fprintf(stderr, "Failed to %slock agent: %s\n",
			    lock ? "" : "un", ssh_err(r));
		}
	}
	freezero(p1, strlen(p1));
	തിരികെ (ret);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
load_resident_താക്കോലുകൾ(പൂർണ്ണസംഖ്യ agent_fd, സ്ഥിരം അക്ഷരം *skprovider, പൂർണ്ണസംഖ്യ qflag, പൂർണ്ണസംഖ്യ no_pin,
    ഘടന dest_constraint **dest_constraints, size_t ndest_constraints)
{
	ഘടന sshsk_resident_താക്കോൽ **srks;
	size_t nsrks, i;
	ഘടന sshkey *താക്കോൽ;
	പൂർണ്ണസംഖ്യ r, ok = 0;
	അക്ഷരം *fp, *pin = ശൂന്യ;

	എങ്കിൽ (!no_pin) {
		pin = read_passphrase("Enter PIN for authenticator: ",
		    RP_ALLOW_STDIN);
	}
	എങ്കിൽ ((r = sshsk_load_resident(skprovider, ശൂന്യ, pin == ശൂന്യ ? "" : pin,
	    0, &srks, &nsrks)) != 0) {
		error_r(r, "Unable to load resident keys");
		സ്വതന്ത്രം(pin);
		തിരികെ r;
	}
	സ്വതന്ത്രം(pin);
	വേണ്ടി (i = 0; i < nsrks; i++) {
		താക്കോൽ = srks[i]->താക്കോൽ;
		എങ്കിൽ ((fp = sshkey_fingerprint(താക്കോൽ,
		    fingerprint_hash, SSH_FP_DEFAULT)) == ശൂന്യ)
			fatal_f("sshkey_fingerprint failed");
		എങ്കിൽ ((r = ssh_add_identity_constrained(agent_fd, താക്കോൽ,
		    താക്കോൽ->sk_application, lifetime, confirm, skprovider,
		    dest_constraints, ndest_constraints)) != 0) {
			error("Unable to add key %s %s",
			    sshkey_type(താക്കോൽ), fp);
			സ്വതന്ത്രം(fp);
			ok = r;
			തുടരുക;
		}
		എങ്കിൽ (ok == 0)
			ok = 1;
		എങ്കിൽ (!qflag) {
			fprintf(stderr, "Resident identity added: %s %s\n",
			    sshkey_type(താക്കോൽ), fp);
			എങ്കിൽ (lifetime != 0) {
				fprintf(stderr,
				    "Lifetime set to %d seconds\n", lifetime);
			}
			എങ്കിൽ (confirm != 0) {
				fprintf(stderr, "The user must confirm "
				    "each use of the key\n");
			}
		}
		സ്വതന്ത്രം(fp);
	}
	sshsk_free_resident_താക്കോലുകൾ(srks, nsrks);
	എങ്കിൽ (nsrks == 0)
		തിരികെ SSH_ERR_താക്കോൽ_NOT_FOUND;
	തിരികെ ok == 1 ? 0 : ok;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
do_file(പൂർണ്ണസംഖ്യ agent_fd, പൂർണ്ണസംഖ്യ deleting, പൂർണ്ണസംഖ്യ താക്കോൽ_only, പൂർണ്ണസംഖ്യ cert_only,
    അക്ഷരം *file, പൂർണ്ണസംഖ്യ qflag, പൂർണ്ണസംഖ്യ Nflag, സ്ഥിരം അക്ഷരം *skprovider,
    ഘടന dest_constraint **dest_constraints, size_t ndest_constraints)
{
	എങ്കിൽ (deleting) {
		എങ്കിൽ (delete_file(agent_fd, file, താക്കോൽ_only,
		    cert_only, qflag) == -1)
			തിരികെ -1;
	} അല്ലെങ്കിൽ {
		എങ്കിൽ (add_file(agent_fd, file, താക്കോൽ_only, cert_only, qflag, Nflag,
		    skprovider, dest_constraints, ndest_constraints) == -1)
			തിരികെ -1;
	}
	തിരികെ 0;
}

സ്ഥിതം ശൂന്യം
free_dest_constraint_hop(ഘടന dest_constraint_hop *dch)
{
	u_int i;

	എങ്കിൽ (dch == ശൂന്യ)
		തിരികെ;
	സ്വതന്ത്രം(dch->user);
	സ്വതന്ത്രം(dch->hostname);
	വേണ്ടി (i = 0; i < dch->nkeys; i++)
		sshkey_free(dch->താക്കോലുകൾ[i]);
	സ്വതന്ത്രം(dch->താക്കോലുകൾ);
	സ്വതന്ത്രം(dch->താക്കോൽ_is_ca);
}

സ്ഥിതം ശൂന്യം
free_dest_constraints(ഘടന dest_constraint **dcs, size_t ndcs)
{
	size_t i;

	വേണ്ടി (i = 0; i < ndcs; i++) {
		free_dest_constraint_hop(&dcs[i]->from);
		free_dest_constraint_hop(&dcs[i]->to);
		സ്വതന്ത്രം(dcs[i]);
	}
	സ്വതന്ത്രം(dcs);
}


സ്ഥിതം ശൂന്യം
parse_dest_constraint_hop(സ്ഥിരം അക്ഷരം *s, ഘടന dest_constraint_hop *dch,
    അക്ഷരം **hostkey_files)
{
	അക്ഷരം *user = ശൂന്യ, *host, *os, *path;
	size_t i;
	ഘടന hostkeys *hostkeys;
	സ്ഥിരം ഘടന hostkey_entry *hke;
	പൂർണ്ണസംഖ്യ r, want_ca;

	memset(dch, '\0', വലുപ്പം(*dch));
	os = xstrdup(s);
	എങ്കിൽ ((host = strrchr(os, '@')) == ശൂന്യ)
		host = os;
	അല്ലെങ്കിൽ {
		*host++ = '\0';
		user = os;
	}
	cleanhostname(host);
	/* Trivial case: username@ (all hosts) */
	എങ്കിൽ (*host == '\0') {
		എങ്കിൽ (user == ശൂന്യ) {
			fatal("Invalid key destination constraint \"%s\": "
			    "does not specify user or host", s);
		}
		dch->user = xstrdup(user);
		/* other fields left blank */
		സ്വതന്ത്രം(os);
		തിരികെ;
	}
	എങ്കിൽ (hostkey_files == ശൂന്യ)
		fatal_f("no hostkey files");
	/* Otherwise we need to look up the keys for this hostname */
	hostkeys = init_hostkeys();
	വേണ്ടി (i = 0; hostkey_files[i]; i++) {
		path = tilde_expand_filename(hostkey_files[i], getuid());
		debug2_f("looking up host keys for \"%s\" in %s", host, path);
                load_hostkeys(hostkeys, host, path, 0);
		സ്വതന്ത്രം(path);
	}
	dch->user = user == ശൂന്യ ? ശൂന്യ : xstrdup(user);
	dch->hostname = xstrdup(host);
	വേണ്ടി (i = 0; i < hostkeys->അക്കം_entries; i++) {
		hke = hostkeys->entries + i;
		want_ca = hke->marker == MRK_CA;
		എങ്കിൽ (hke->marker != MRK_NONE && !want_ca)
			തുടരുക;
		debug3_f("%s%s%s: adding %s %skey from %s:%lu as key %u",
		    user == ശൂന്യ ? "": user, user == ശൂന്യ ? "" : "@",
		    host, sshkey_type(hke->താക്കോൽ), want_ca ? "CA " : "",
		    hke->file, hke->വരി, dch->nkeys);
		dch->താക്കോലുകൾ = xrecallocarray(dch->താക്കോലുകൾ, dch->nkeys,
		    dch->nkeys + 1, വലുപ്പം(*dch->താക്കോലുകൾ));
		dch->താക്കോൽ_is_ca = xrecallocarray(dch->താക്കോൽ_is_ca, dch->nkeys,
		    dch->nkeys + 1, വലുപ്പം(*dch->താക്കോൽ_is_ca));
		എങ്കിൽ ((r = sshkey_from_private(hke->താക്കോൽ,
		    &(dch->താക്കോലുകൾ[dch->nkeys]))) != 0)
			fatal_fr(r, "sshkey_from_private");
		dch->താക്കോൽ_is_ca[dch->nkeys] = want_ca;
		dch->nkeys++;
	}
	എങ്കിൽ (dch->nkeys == 0)
		fatal("No host keys found for destination \"%s\"", host);
	free_hostkeys(hostkeys);
	സ്വതന്ത്രം(os);
	തിരികെ;
}

സ്ഥിതം ശൂന്യം
parse_dest_constraint(സ്ഥിരം അക്ഷരം *s, ഘടന dest_constraint ***dcp,
    size_t *ndcp, അക്ഷരം **hostkey_files)
{
	ഘടന dest_constraint *dc;
	അക്ഷരം *os, *cp;

	dc = xcalloc(1, വലുപ്പം(*dc));
	os = xstrdup(s);
	എങ്കിൽ ((cp = strchr(os, '>')) == ശൂന്യ) {
		/* initial hop; no 'from' hop specified */
		parse_dest_constraint_hop(os, &dc->to, hostkey_files);
	} അല്ലെങ്കിൽ {
		/* two hops specified */
		*(cp++) = '\0';
		parse_dest_constraint_hop(os, &dc->from, hostkey_files);
		parse_dest_constraint_hop(cp, &dc->to, hostkey_files);
		എങ്കിൽ (dc->from.user != ശൂന്യ) {
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
	*dcp = xrecallocarray(*dcp, *ndcp, *ndcp + 1, വലുപ്പം(**dcp));
	(*dcp)[(*ndcp)++] = dc;
	സ്വതന്ത്രം(os);
}


സ്ഥിതം ശൂന്യം
usage(ശൂന്യം)
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

പൂർണ്ണസംഖ്യ
പ്രധാന(പൂർണ്ണസംഖ്യ argc, അക്ഷരം **argv)
{
	ബാഹ്യ അക്ഷരം *optarg;
	ബാഹ്യ പൂർണ്ണസംഖ്യ optind;
	പൂർണ്ണസംഖ്യ agent_fd = -1;
	അക്ഷരം *pkcs11provider = ശൂന്യ, *skprovider = ശൂന്യ;
	അക്ഷരം **dest_constraint_strings = ശൂന്യ, **hostkey_files = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r, i, ch, deleting = 0, ret = 0, താക്കോൽ_only = 0, cert_only = 0;
	പൂർണ്ണസംഖ്യ do_download = 0, xflag = 0, lflag = 0, Dflag = 0;
	പൂർണ്ണസംഖ്യ Qflag = 0, qflag = 0, Tflag = 0, Nflag = 0, no_pin = 0;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_INFO;
	ഘടന sshkey *k, **certs = ശൂന്യ;
	ഘടന dest_constraint **dest_constraints = ശൂന്യ;
	size_t n, ndest_constraints = 0, ncerts = 0;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	__progname = ssh_get_progname(argv[0]);
	seed_rng();

	log_init(__progname, log_level, log_facility, 1);

	setvbuf(stdout, ശൂന്യ, _IOLBF, 0);

	skprovider = getenv("SSH_SK_PROVIDER");

	ആകുമ്പോൾ ((ch = getopt(argc, argv, "vkKlLNPCcdDTxXE:e:h:H:M:m:Qqs:S:t:")) != -1) {
		തിരഞ്ഞെടുപ്പ് (ch) {
		അവസ്ഥ 'v':
			എങ്കിൽ (log_level == SYSLOG_LEVEL_INFO)
				log_level = SYSLOG_LEVEL_DEBUG1;
			അല്ലെങ്കിൽ എങ്കിൽ (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			നിർത്തുക;
		അവസ്ഥ 'N':
			Nflag = 1;
			നിർത്തുക;
		അവസ്ഥ 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			എങ്കിൽ (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			നിർത്തുക;
		അവസ്ഥ 'H':
			stringlist_append(&hostkey_files, optarg);
			നിർത്തുക;
		അവസ്ഥ 'h':
			stringlist_append(&dest_constraint_strings, optarg);
			നിർത്തുക;
		അവസ്ഥ 'k':
			താക്കോൽ_only = 1;
			നിർത്തുക;
		അവസ്ഥ 'C':
			cert_only = 1;
			നിർത്തുക;
		അവസ്ഥ 'K':
			do_download = 1;
			നിർത്തുക;
		അവസ്ഥ 'l':
		അവസ്ഥ 'L':
			എങ്കിൽ (lflag != 0)
				fatal("-%c flag already specified", lflag);
			lflag = ch;
			നിർത്തുക;
		അവസ്ഥ 'x':
		അവസ്ഥ 'X':
			എങ്കിൽ (xflag != 0)
				fatal("-%c flag already specified", xflag);
			xflag = ch;
			നിർത്തുക;
		അവസ്ഥ 'c':
			confirm = 1;
			നിർത്തുക;
		അവസ്ഥ 'm':
		അവസ്ഥ 'M':
			/* deprecated */
			നിർത്തുക;
		അവസ്ഥ 'd':
			deleting = 1;
			നിർത്തുക;
		അവസ്ഥ 'P':
			no_pin = 1;
			നിർത്തുക;
		അവസ്ഥ 'D':
			Dflag = 1;
			നിർത്തുക;
		അവസ്ഥ 's':
			pkcs11provider = optarg;
			നിർത്തുക;
		അവസ്ഥ 'S':
			skprovider = optarg;
			നിർത്തുക;
		അവസ്ഥ 'e':
			deleting = 1;
			pkcs11provider = optarg;
			നിർത്തുക;
		അവസ്ഥ 't':
			എങ്കിൽ ((lifetime = convtime(optarg)) == -1 ||
			    lifetime < 0 || (u_long)lifetime > UINT32_MAX) {
				fprintf(stderr, "Invalid lifetime\n");
				ret = 1;
				പോകുക done;
			}
			നിർത്തുക;
		അവസ്ഥ 'q':
			qflag = 1;
			നിർത്തുക;
		അവസ്ഥ 'Q':
			Qflag = 1;
			നിർത്തുക;
		അവസ്ഥ 'T':
			Tflag = 1;
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			usage();
			ret = 1;
			പോകുക done;
		}
	}
	log_init(__progname, log_level, log_facility, 1);

	എങ്കിൽ ((xflag != 0) + (lflag != 0) + (Dflag != 0) + (Qflag != 0) > 1)
		fatal("Invalid combination of actions");

	/* First, get a connection to the authentication agent. */
	തിരഞ്ഞെടുപ്പ് (r = ssh_get_authentication_socket(&agent_fd)) {
	അവസ്ഥ 0:
		നിർത്തുക;
	അവസ്ഥ SSH_ERR_AGENT_NOT_PRESENT:
		fprintf(stderr, "Could not open a connection to your "
		    "authentication agent.\n");
		exit(2);
	സ്ഥിരസ്ഥിതി:
		fprintf(stderr, "Error connecting to agent: %s\n", ssh_err(r));
		exit(2);
	}

	എങ്കിൽ (xflag) {
		എങ്കിൽ (lock_agent(agent_fd, xflag == 'x' ? 1 : 0) == -1)
			ret = 1;
		പോകുക done;
	} അല്ലെങ്കിൽ എങ്കിൽ (lflag) {
		എങ്കിൽ (list_identities(agent_fd, lflag == 'l' ? 1 : 0) == -1)
			ret = 1;
		പോകുക done;
	} അല്ലെങ്കിൽ എങ്കിൽ (Dflag) {
		എങ്കിൽ (delete_all(agent_fd, qflag) == -1)
			ret = 1;
		പോകുക done;
	} അല്ലെങ്കിൽ എങ്കിൽ (Qflag) {
		എങ്കിൽ (query_exts(agent_fd) == -1)
			ret = 1;
		പോകുക done;
	}

#ifdef ENABLE_SK_INTERNAL
	എങ്കിൽ (skprovider == ശൂന്യ)
		skprovider = "internal";
#endif

	എങ്കിൽ (hostkey_files == ശൂന്യ) {
		/* use defaults from readconf.c */
		stringlist_append(&hostkey_files, _PATH_SSH_USER_HOSTFILE);
		stringlist_append(&hostkey_files, _PATH_SSH_USER_HOSTFILE2);
		stringlist_append(&hostkey_files, _PATH_SSH_SYSTEM_HOSTFILE);
		stringlist_append(&hostkey_files, _PATH_SSH_SYSTEM_HOSTFILE2);
	}
	എങ്കിൽ (dest_constraint_strings != ശൂന്യ) {
		വേണ്ടി (i = 0; dest_constraint_strings[i] != ശൂന്യ; i++) {
			parse_dest_constraint(dest_constraint_strings[i],
			  &dest_constraints, &ndest_constraints, hostkey_files);
		}
	}

	argc -= optind;
	argv += optind;
	എങ്കിൽ (Tflag) {
		എങ്കിൽ (argc <= 0)
			fatal("no keys to test");
		വേണ്ടി (r = i = 0; i < argc; i++)
			r |= test_താക്കോൽ(agent_fd, argv[i]);
		ret = r == 0 ? 0 : 1;
		പോകുക done;
	}
	എങ്കിൽ (pkcs11provider != ശൂന്യ) {
		വേണ്ടി (i = 0; i < argc; i++) {
			എങ്കിൽ ((r = sshkey_load_public(argv[i], &k, ശൂന്യ)) != 0)
				fatal_fr(r, "load certificate %s", argv[i]);
			certs = xrecallocarray(certs, ncerts, ncerts + 1,
			    വലുപ്പം(*certs));
			debug2("%s: %s", argv[i], sshkey_ssh_name(k));
			certs[ncerts++] = k;
		}
		debug2_f("loaded %zu certificates", ncerts);
		എങ്കിൽ (update_card(agent_fd, !deleting, pkcs11provider,
		    qflag, no_pin, താക്കോൽ_only, cert_only,
		    dest_constraints, ndest_constraints,
		    certs, ncerts) == -1)
			ret = 1;
		വേണ്ടി (n = 0; n < ncerts; n++)
			sshkey_free(certs[n]);
		സ്വതന്ത്രം(certs);
		പോകുക done;
	}
	എങ്കിൽ (do_download) {
		എങ്കിൽ (skprovider == ശൂന്യ)
			fatal("Cannot download keys without provider");
		എങ്കിൽ (load_resident_താക്കോലുകൾ(agent_fd, skprovider, qflag, no_pin,
		    dest_constraints, ndest_constraints) != 0)
			ret = 1;
		പോകുക done;
	}
	എങ്കിൽ (argc == 0) {
		അക്ഷരം buf[PATH_MAX];
		ഘടന passwd *pw;
		ഘടന stat st;
		പൂർണ്ണസംഖ്യ എണ്ണം = 0;

		എങ്കിൽ ((pw = getpwuid(getuid())) == ശൂന്യ) {
			fprintf(stderr, "No user found with uid %u\n",
			    (u_int)getuid());
			ret = 1;
			പോകുക done;
		}

		വേണ്ടി (i = 0; default_files[i]; i++) {
			snprintf(buf, വലുപ്പം(buf), "%s/%s", pw->pw_dir,
			    default_files[i]);
			എങ്കിൽ (stat(buf, &st) == -1)
				തുടരുക;
			എങ്കിൽ (do_file(agent_fd, deleting, താക്കോൽ_only, cert_only,
			    buf, qflag, Nflag, skprovider,
			    dest_constraints, ndest_constraints) == -1)
				ret = 1;
			അല്ലെങ്കിൽ
				എണ്ണം++;
		}
		എങ്കിൽ (എണ്ണം == 0)
			ret = 1;
	} അല്ലെങ്കിൽ {
		വേണ്ടി (i = 0; i < argc; i++) {
			എങ്കിൽ (do_file(agent_fd, deleting, താക്കോൽ_only, cert_only,
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
	തിരികെ ret;
}
