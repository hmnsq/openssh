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
बाह्य अक्षर *__progname;

/* Default files to add */
स्थिर अक्षर *default_files[] = {
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

स्थिर पूर्णांक fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* Default lifetime (0 == forever) */
स्थिर पूर्णांक lifetime = 0;

/* User has to confirm key use */
स्थिर पूर्णांक confirm = 0;

/* we keep a cache of one passphrase */
स्थिर अक्षर *pass = रिक्त;
स्थिर शून्य
clear_pass(शून्य)
{
	जर (pass) {
		freezero(pass, म_माप(pass));
		pass = रिक्त;
	}
}

स्थिर पूर्णांक
delete_one(पूर्णांक agent_fd, स्थिरांक संरचना sshkey *किल्ली, स्थिरांक अक्षर *comment,
    स्थिरांक अक्षर *path, पूर्णांक qflag)
{
	पूर्णांक r;

	जर ((r = ssh_remove_identity(agent_fd, किल्ली)) != 0) {
		ख_लिखो(मानक_त्रुटि, "Could not remove identity \"%s\": %s\n",
		    path, ssh_err(r));
		परत r;
	}
	जर (!qflag) {
		ख_लिखो(मानक_त्रुटि, "Identity removed: %s %s (%s)\n", path,
		    sshkey_type(किल्ली), comment ? comment : "no comment");
	}
	परत 0;
}

स्थिर पूर्णांक
delete_stdin(पूर्णांक agent_fd, पूर्णांक qflag, पूर्णांक किल्ली_only, पूर्णांक cert_only)
{
	अक्षर *ओळ = रिक्त, *cp;
	माप_प्रकार linesize = 0;
	संरचना sshkey *किल्ली = रिक्त;
	पूर्णांक lnum = 0, r, ret = -1;

	पर्यंत (getline(&ओळ, &linesize, मानक_निवेश) != -1) {
		lnum++;
		sshkey_free(किल्ली);
		किल्ली = रिक्त;
		ओळ[म_खोज(ओळ, "\n")] = '\0';
		cp = ओळ + म_अखोज(ओळ, " \t");
		जर (*cp == '#' || *cp == '\0')
			सुरूठेवा;
		जर ((किल्ली = sshkey_new(किल्ली_UNSPEC)) == रिक्त)
			fatal_f("sshkey_new");
		जर ((r = sshkey_read(किल्ली, &cp)) != 0) {
			error_r(r, "(stdin):%d: invalid key", lnum);
			सुरूठेवा;
		}
		जर ((!किल्ली_only && !cert_only) ||
		    (किल्ली_only && !sshkey_is_cert(किल्ली)) ||
		    (cert_only && sshkey_is_cert(किल्ली))) {
			जर (delete_one(agent_fd, किल्ली, cp,
			    "(stdin)", qflag) == 0)
				ret = 0;
		}
	}
	sshkey_free(किल्ली);
	मुक्त(ओळ);
	परत ret;
}

स्थिर पूर्णांक
delete_file(पूर्णांक agent_fd, स्थिरांक अक्षर *filename, पूर्णांक किल्ली_only,
    पूर्णांक cert_only, पूर्णांक qflag)
{
	संरचना sshkey *सार्वजनिक, *cert = रिक्त;
	अक्षर *certpath = रिक्त, *comment = रिक्त;
	पूर्णांक r, ret = -1;

	जर (म_भेद(filename, "-") == 0)
		परत delete_stdin(agent_fd, qflag, किल्ली_only, cert_only);

	जर ((r = sshkey_load_public(filename, &सार्वजनिक,  &comment)) != 0) {
		म_लिखो("Bad key file %s: %s\n", filename, ssh_err(r));
		परत -1;
	}
	जर ((!किल्ली_only && !cert_only) ||
	    (किल्ली_only && !sshkey_is_cert(सार्वजनिक)) ||
	    (cert_only && sshkey_is_cert(सार्वजनिक))) {
		जर (delete_one(agent_fd, सार्वजनिक, comment, filename, qflag) == 0)
			ret = 0;
	}

	जर (किल्ली_only)
		जा out;

	/* Now try to delete the corresponding certificate too */
	मुक्त(comment);
	comment = रिक्त;
	xasprintf(&certpath, "%s-cert.pub", filename);
	जर ((r = sshkey_load_public(certpath, &cert, &comment)) != 0) {
		जर (r != SSH_ERR_SYSTEM_ERROR || त्रुटि_सं != ENOENT)
			error_r(r, "Failed to load certificate \"%s\"", certpath);
		जा out;
	}

	जर (!sshkey_equal_public(cert, सार्वजनिक))
		fatal("Certificate %s does not match private key %s",
		    certpath, filename);

	जर (delete_one(agent_fd, cert, comment, certpath, qflag) == 0)
		ret = 0;

 out:
	sshkey_free(cert);
	sshkey_free(सार्वजनिक);
	मुक्त(certpath);
	मुक्त(comment);

	परत ret;
}

/* Send a request to remove all identities. */
स्थिर पूर्णांक
delete_all(पूर्णांक agent_fd, पूर्णांक qflag)
{
	पूर्णांक ret = -1;

	/*
	 * Since the agent might be forwarded, old or non-OpenSSH, when asked
	 * to remove all keys, attempt to remove both protocol v.1 and v.2
	 * keys.
	 */
	जर (ssh_remove_all_identities(agent_fd, 2) == 0)
		ret = 0;
	/* ignore error-code for ssh1 */
	ssh_remove_all_identities(agent_fd, 1);

	जर (ret != 0)
		ख_लिखो(मानक_त्रुटि, "Failed to remove all identities.\n");
	अन्यथा जर (!qflag)
		ख_लिखो(मानक_त्रुटि, "All identities removed.\n");

	परत ret;
}

स्थिर पूर्णांक
query_exts(पूर्णांक agent_fd)
{
	पूर्णांक r;
	अक्षर **exts = रिक्त;
	माप_प्रकार i;

	जर ((r = ssh_agent_query_extensions(agent_fd, &exts)) != 0)
		fatal_r(r, "unable to query supported extensions");
	साठी (i = 0; exts != रिक्त && exts[i] != रिक्त; i++)
		माला_दो(exts[i]);
	stringlist_free(exts);
	परत 0;
}

स्थिर पूर्णांक
check_cert_lifetime(स्थिरांक संरचना sshkey *cert, पूर्णांक cert_lifetime)
{
	समय_प्रकार now;
	uint64_t n;

	जर (cert == रिक्त || cert->cert == रिक्त || !sshkey_is_cert(cert) ||
	    cert->cert->valid_before == 0xFFFFFFFFFFFFFFFFULL)
		परत cert_lifetime;
	जर ((now = समय(रिक्त)) <= 0)
		fatal_f("system time is at/before epoch");
	जर ((uint64_t)now > (cert->cert->valid_before + CERT_EXPIRY_GRACE))
		परत -1; /* certificate already expired */
	n = (CERT_EXPIRY_GRACE + cert->cert->valid_before) - (uint64_t)now;
	n = MINIMUM(n, पूर्णांक_उच्च);
	जर (cert_lifetime <= 0)
		परत (पूर्णांक)n;
	परत MINIMUM(cert_lifetime, (पूर्णांक)n);
}

स्थिर पूर्णांक
add_file(पूर्णांक agent_fd, स्थिरांक अक्षर *filename, पूर्णांक किल्ली_only, पूर्णांक cert_only,
    पूर्णांक qflag, पूर्णांक Nflag, स्थिरांक अक्षर *skprovider,
    संरचना dest_constraint **dest_constraints,
    माप_प्रकार ndest_constraints)
{
	संरचना sshkey *खाजगी = रिक्त, *cert = रिक्त;
	अक्षर *comment = रिक्त;
	अक्षर संदेश[1024], *certpath = रिक्त;
	पूर्णांक cert_lifetime, r, fd, ret = -1;
	संरचना sshbuf *keyblob;

	जर (म_भेद(filename, "-") == 0) {
		fd = STDIN_FILENO;
		filename = "(stdin)";
	} अन्यथा जर ((fd = खोलो(filename, O_RDONLY)) == -1) {
		लिखो_त्रुटि(filename);
		परत -1;
	}

	/*
	 * Since we'll try to load a keyfile multiple times, permission errors
	 * will occur multiple times, so check perms first and bail if wrong.
	 */
	जर (fd != STDIN_FILENO) {
		जर (sshkey_perm_ok(fd, filename) != 0) {
			बंद(fd);
			परत -1;
		}
	}
	जर ((r = sshbuf_load_fd(fd, &keyblob)) != 0) {
		ख_लिखो(मानक_त्रुटि, "Error loading key \"%s\": %s\n",
		    filename, ssh_err(r));
		sshbuf_free(keyblob);
		बंद(fd);
		परत -1;
	}
	बंद(fd);

	/* At first, try empty passphrase */
	जर ((r = sshkey_parse_private_fileblob(keyblob, "", &खाजगी,
	    &comment)) != 0 && r != SSH_ERR_किल्ली_WRONG_PASSPHRASE) {
		ख_लिखो(मानक_त्रुटि, "Error loading key \"%s\": %s\n",
		    filename, ssh_err(r));
		जा fail_load;
	}
	/* try last */
	जर (खाजगी == रिक्त && pass != रिक्त) {
		जर ((r = sshkey_parse_private_fileblob(keyblob, pass, &खाजगी,
		    &comment)) != 0 && r != SSH_ERR_किल्ली_WRONG_PASSPHRASE) {
			ख_लिखो(मानक_त्रुटि, "Error loading key \"%s\": %s\n",
			    filename, ssh_err(r));
			जा fail_load;
		}
	}
	जर (खाजगी == रिक्त) {
		/* clear passphrase since it did not work */
		clear_pass();
		snprintf(संदेश, आकार संदेश, "Enter passphrase for %s%s: ",
		    filename, confirm ? " (will confirm each use)" : "");
		साठी (;;) {
			pass = read_passphrase(संदेश, RP_ALLOW_STDIN);
			जर (म_भेद(pass, "") == 0)
				जा fail_load;
			जर ((r = sshkey_parse_private_fileblob(keyblob, pass,
			    &खाजगी, &comment)) == 0)
				थांबा;
			अन्यथा जर (r != SSH_ERR_किल्ली_WRONG_PASSPHRASE) {
				ख_लिखो(मानक_त्रुटि,
				    "Error loading key \"%s\": %s\n",
				    filename, ssh_err(r));
 fail_load:
				clear_pass();
				sshbuf_free(keyblob);
				परत -1;
			}
			clear_pass();
			snprintf(संदेश, आकार संदेश,
			    "Bad passphrase, try again for %s%s: ", filename,
			    confirm ? " (will confirm each use)" : "");
		}
	}
	जर (comment == रिक्त || *comment == '\0')
		comment = xstrdup(filename);
	sshbuf_free(keyblob);

	जर (sshkey_is_sk(खाजगी)) {
		जर (skprovider == रिक्त) {
			ख_लिखो(मानक_त्रुटि, "Cannot load FIDO key %s "
			    "without provider\n", filename);
			जा out;
		}
	} अन्यथा {
		/* Don't send provider constraint for other keys */
		skprovider = रिक्त;
	}

	जर (!cert_only) {
		जर ((r = ssh_add_identity_constrained(agent_fd, खाजगी,
		    comment, lifetime, confirm, skprovider,
		    dest_constraints, ndest_constraints)) == 0) {
			ret = 0;
			जर (!qflag) {
				ख_लिखो(मानक_त्रुटि, "Identity added: %s (%s)\n",
				    filename, comment);
				जर (lifetime != 0) {
					ख_लिखो(मानक_त्रुटि, "Lifetime set to %s\n",
					    fmt_timeframe((समय_प्रकार)lifetime));
				}
				जर (confirm != 0) {
					ख_लिखो(मानक_त्रुटि, "The user must confirm "
					    "each use of the key\n");
				}
			}
		} अन्यथा {
			ख_लिखो(मानक_त्रुटि, "Could not add identity \"%s\": %s\n",
			    filename, ssh_err(r));
		}
	}

	/* Skip trying to load the cert if requested */
	जर (किल्ली_only)
		जा out;

	/* Now try to add the certificate flavour too */
	xasprintf(&certpath, "%s-cert.pub", filename);
	जर ((r = sshkey_load_public(certpath, &cert, रिक्त)) != 0) {
		जर (r != SSH_ERR_SYSTEM_ERROR || त्रुटि_सं != ENOENT)
			error_r(r, "Failed to load certificate \"%s\"",
			    certpath);
		जा out;
	}

	जर (!sshkey_equal_public(cert, खाजगी)) {
		error("Certificate %s does not match private key %s",
		    certpath, filename);
		जा out;
	}

	cert_lifetime = lifetime;
	जर (!Nflag &&
	    (cert_lifetime = check_cert_lifetime(cert, cert_lifetime)) == -1) {
		logit("Certificate %s has already expired; ignored", certpath);
		जा out;
	}

	/* Graft with private bits */
	जर ((r = sshkey_to_certified(खाजगी)) != 0) {
		error_fr(r, "sshkey_to_certified");
		जा out;
	}
	जर ((r = sshkey_cert_copy(cert, खाजगी)) != 0) {
		error_fr(r, "sshkey_cert_copy");
		जा out;
	}
	/* send to agent */
	जर ((r = ssh_add_identity_constrained(agent_fd, खाजगी, comment,
	    cert_lifetime, confirm, skprovider,
	    dest_constraints, ndest_constraints)) != 0) {
		error_r(r, "Certificate %s (%s) add failed", certpath,
		    खाजगी->cert->किल्ली_id);
		जा out;
	}
	/* success */
	जर (!qflag) {
		ख_लिखो(मानक_त्रुटि, "Certificate added: %s (%s)\n", certpath,
		    खाजगी->cert->किल्ली_id);
		जर (cert_lifetime != 0) {
			ख_लिखो(मानक_त्रुटि, "Lifetime set to %s\n",
			    fmt_timeframe((समय_प्रकार)cert_lifetime));
		}
		जर (confirm != 0) {
			ख_लिखो(मानक_त्रुटि, "The user must confirm each use "
			    "of the key\n");
		}
	}

 out:
	मुक्त(certpath);
	मुक्त(comment);
	sshkey_free(cert);
	sshkey_free(खाजगी);

	परत ret;
}

स्थिर पूर्णांक
update_card(पूर्णांक agent_fd, पूर्णांक add, स्थिरांक अक्षर *id, पूर्णांक qflag, पूर्णांक no_pin,
    पूर्णांक किल्ली_only, पूर्णांक cert_only,
    संरचना dest_constraint **dest_constraints, माप_प्रकार ndest_constraints,
    संरचना sshkey **certs, माप_प्रकार ncerts)
{
	अक्षर *pin = रिक्त;
	पूर्णांक r, ret = -1;

	जर (किल्ली_only)
		ncerts = 0;

	जर (add && !no_pin) {
		जर ((pin = read_passphrase("Enter passphrase for PKCS#11: ",
		    RP_ALLOW_STDIN)) == रिक्त)
			परत -1;
	}

	जर ((r = ssh_update_card(agent_fd, add, id, pin == रिक्त ? "" : pin,
	    lifetime, confirm, dest_constraints, ndest_constraints,
	    cert_only, certs, ncerts)) == 0) {
		ret = 0;
		जर (!qflag) {
			ख_लिखो(मानक_त्रुटि, "Card %s: %s\n",
			    add ? "added" : "removed", id);
		}
	} अन्यथा {
		ख_लिखो(मानक_त्रुटि, "Could not %s card \"%s\": %s\n",
		    add ? "add" : "remove", id, ssh_err(r));
		ret = -1;
	}
	मुक्त(pin);
	परत ret;
}

स्थिर पूर्णांक
test_किल्ली(पूर्णांक agent_fd, स्थिरांक अक्षर *filename)
{
	संरचना sshkey *किल्ली = रिक्त;
	u_char *sig = रिक्त;
	स्थिरांक अक्षर *alg = रिक्त;
	माप_प्रकार slen = 0;
	पूर्णांक r, ret = -1;
	अक्षर data[1024];

	जर ((r = sshkey_load_public(filename, &किल्ली, रिक्त)) != 0) {
		error_r(r, "Couldn't read public key %s", filename);
		परत -1;
	}
	जर (sshkey_type_plain(किल्ली->type) == किल्ली_RSA)
		alg = "rsa-sha2-256";
	arc4random_buf(data, आकार(data));
	जर ((r = ssh_agent_sign(agent_fd, किल्ली, &sig, &slen, data, आकार(data),
	    alg, 0)) != 0) {
		error_r(r, "Agent signature failed for %s", filename);
		जा done;
	}
	जर ((r = sshkey_verify(किल्ली, sig, slen, data, आकार(data),
	    alg, 0, रिक्त)) != 0) {
		error_r(r, "Signature verification failed for %s", filename);
		जा done;
	}
	/* success */
	ret = 0;
 done:
	मुक्त(sig);
	sshkey_free(किल्ली);
	परत ret;
}

स्थिर पूर्णांक
list_identities(पूर्णांक agent_fd, पूर्णांक do_fp)
{
	अक्षर *fp;
	पूर्णांक r;
	संरचना ssh_identitylist *idlist;
	माप_प्रकार i;

	जर ((r = ssh_fetch_identitylist(agent_fd, &idlist)) != 0) {
		जर (r != SSH_ERR_AGENT_NO_IDENTITIES)
			ख_लिखो(मानक_त्रुटि, "error fetching identities: %s\n",
			    ssh_err(r));
		अन्यथा
			म_लिखो("The agent has no identities.\n");
		परत -1;
	}
	साठी (i = 0; i < idlist->nkeys; i++) {
		जर (do_fp) {
			fp = sshkey_fingerprint(idlist->किल्ल्या[i],
			    fingerprint_hash, SSH_FP_DEFAULT);
			म_लिखो("%u %s %s (%s)\n", sshkey_size(idlist->किल्ल्या[i]),
			    fp == रिक्त ? "(null)" : fp, idlist->comments[i],
			    sshkey_type(idlist->किल्ल्या[i]));
			मुक्त(fp);
		} अन्यथा {
			जर ((r = sshkey_write(idlist->किल्ल्या[i], मानक_निकास)) != 0) {
				ख_लिखो(मानक_त्रुटि, "sshkey_write: %s\n",
				    ssh_err(r));
				सुरूठेवा;
			}
			ख_लिखो(मानक_निकास, " %s\n", idlist->comments[i]);
		}
	}
	ssh_free_identitylist(idlist);
	परत 0;
}

स्थिर पूर्णांक
lock_agent(पूर्णांक agent_fd, पूर्णांक lock)
{
	अक्षर prompt[100], *p1, *p2;
	पूर्णांक r, passok = 1, ret = -1;

	strlcpy(prompt, "Enter lock password: ", आकार(prompt));
	p1 = read_passphrase(prompt, RP_ALLOW_STDIN);
	जर (lock) {
		strlcpy(prompt, "Again: ", आकार prompt);
		p2 = read_passphrase(prompt, RP_ALLOW_STDIN);
		जर (म_भेद(p1, p2) != 0) {
			ख_लिखो(मानक_त्रुटि, "Passwords do not match.\n");
			passok = 0;
		}
		freezero(p2, म_माप(p2));
	}
	जर (passok) {
		जर ((r = ssh_lock_agent(agent_fd, lock, p1)) == 0) {
			ख_लिखो(मानक_त्रुटि, "Agent %slocked.\n", lock ? "" : "un");
			ret = 0;
		} अन्यथा {
			ख_लिखो(मानक_त्रुटि, "Failed to %slock agent: %s\n",
			    lock ? "" : "un", ssh_err(r));
		}
	}
	freezero(p1, म_माप(p1));
	परत (ret);
}

स्थिर पूर्णांक
load_resident_किल्ल्या(पूर्णांक agent_fd, स्थिरांक अक्षर *skprovider, पूर्णांक qflag, पूर्णांक no_pin,
    संरचना dest_constraint **dest_constraints, माप_प्रकार ndest_constraints)
{
	संरचना sshsk_resident_किल्ली **srks;
	माप_प्रकार nsrks, i;
	संरचना sshkey *किल्ली;
	पूर्णांक r, ok = 0;
	अक्षर *fp, *pin = रिक्त;

	जर (!no_pin) {
		pin = read_passphrase("Enter PIN for authenticator: ",
		    RP_ALLOW_STDIN);
	}
	जर ((r = sshsk_load_resident(skprovider, रिक्त, pin == रिक्त ? "" : pin,
	    0, &srks, &nsrks)) != 0) {
		error_r(r, "Unable to load resident keys");
		मुक्त(pin);
		परत r;
	}
	मुक्त(pin);
	साठी (i = 0; i < nsrks; i++) {
		किल्ली = srks[i]->किल्ली;
		जर ((fp = sshkey_fingerprint(किल्ली,
		    fingerprint_hash, SSH_FP_DEFAULT)) == रिक्त)
			fatal_f("sshkey_fingerprint failed");
		जर ((r = ssh_add_identity_constrained(agent_fd, किल्ली,
		    किल्ली->sk_application, lifetime, confirm, skprovider,
		    dest_constraints, ndest_constraints)) != 0) {
			error("Unable to add key %s %s",
			    sshkey_type(किल्ली), fp);
			मुक्त(fp);
			ok = r;
			सुरूठेवा;
		}
		जर (ok == 0)
			ok = 1;
		जर (!qflag) {
			ख_लिखो(मानक_त्रुटि, "Resident identity added: %s %s\n",
			    sshkey_type(किल्ली), fp);
			जर (lifetime != 0) {
				ख_लिखो(मानक_त्रुटि,
				    "Lifetime set to %d seconds\n", lifetime);
			}
			जर (confirm != 0) {
				ख_लिखो(मानक_त्रुटि, "The user must confirm "
				    "each use of the key\n");
			}
		}
		मुक्त(fp);
	}
	sshsk_free_resident_किल्ल्या(srks, nsrks);
	जर (nsrks == 0)
		परत SSH_ERR_किल्ली_NOT_FOUND;
	परत ok == 1 ? 0 : ok;
}

स्थिर पूर्णांक
do_file(पूर्णांक agent_fd, पूर्णांक deleting, पूर्णांक किल्ली_only, पूर्णांक cert_only,
    अक्षर *file, पूर्णांक qflag, पूर्णांक Nflag, स्थिरांक अक्षर *skprovider,
    संरचना dest_constraint **dest_constraints, माप_प्रकार ndest_constraints)
{
	जर (deleting) {
		जर (delete_file(agent_fd, file, किल्ली_only,
		    cert_only, qflag) == -1)
			परत -1;
	} अन्यथा {
		जर (add_file(agent_fd, file, किल्ली_only, cert_only, qflag, Nflag,
		    skprovider, dest_constraints, ndest_constraints) == -1)
			परत -1;
	}
	परत 0;
}

स्थिर शून्य
free_dest_constraint_hop(संरचना dest_constraint_hop *dch)
{
	u_int i;

	जर (dch == रिक्त)
		परत;
	मुक्त(dch->user);
	मुक्त(dch->hostname);
	साठी (i = 0; i < dch->nkeys; i++)
		sshkey_free(dch->किल्ल्या[i]);
	मुक्त(dch->किल्ल्या);
	मुक्त(dch->किल्ली_is_ca);
}

स्थिर शून्य
free_dest_constraints(संरचना dest_constraint **dcs, माप_प्रकार ndcs)
{
	माप_प्रकार i;

	साठी (i = 0; i < ndcs; i++) {
		free_dest_constraint_hop(&dcs[i]->from);
		free_dest_constraint_hop(&dcs[i]->to);
		मुक्त(dcs[i]);
	}
	मुक्त(dcs);
}


स्थिर शून्य
parse_dest_constraint_hop(स्थिरांक अक्षर *s, संरचना dest_constraint_hop *dch,
    अक्षर **hostkey_files)
{
	अक्षर *user = रिक्त, *host, *os, *path;
	माप_प्रकार i;
	संरचना hostkeys *hostkeys;
	स्थिरांक संरचना hostkey_entry *hke;
	पूर्णांक r, want_ca;

	स_रखो(dch, '\0', आकार(*dch));
	os = xstrdup(s);
	जर ((host = म_खोजप(os, '@')) == रिक्त)
		host = os;
	अन्यथा {
		*host++ = '\0';
		user = os;
	}
	cleanhostname(host);
	/* Trivial case: username@ (all hosts) */
	जर (*host == '\0') {
		जर (user == रिक्त) {
			fatal("Invalid key destination constraint \"%s\": "
			    "does not specify user or host", s);
		}
		dch->user = xstrdup(user);
		/* other fields left blank */
		मुक्त(os);
		परत;
	}
	जर (hostkey_files == रिक्त)
		fatal_f("no hostkey files");
	/* Otherwise we need to look up the keys for this hostname */
	hostkeys = init_hostkeys();
	साठी (i = 0; hostkey_files[i]; i++) {
		path = tilde_expand_filename(hostkey_files[i], getuid());
		debug2_f("looking up host keys for \"%s\" in %s", host, path);
                load_hostkeys(hostkeys, host, path, 0);
		मुक्त(path);
	}
	dch->user = user == रिक्त ? रिक्त : xstrdup(user);
	dch->hostname = xstrdup(host);
	साठी (i = 0; i < hostkeys->अंक_entries; i++) {
		hke = hostkeys->entries + i;
		want_ca = hke->marker == MRK_CA;
		जर (hke->marker != MRK_NONE && !want_ca)
			सुरूठेवा;
		debug3_f("%s%s%s: adding %s %skey from %s:%lu as key %u",
		    user == रिक्त ? "": user, user == रिक्त ? "" : "@",
		    host, sshkey_type(hke->किल्ली), want_ca ? "CA " : "",
		    hke->file, hke->ओळ, dch->nkeys);
		dch->किल्ल्या = xrecallocarray(dch->किल्ल्या, dch->nkeys,
		    dch->nkeys + 1, आकार(*dch->किल्ल्या));
		dch->किल्ली_is_ca = xrecallocarray(dch->किल्ली_is_ca, dch->nkeys,
		    dch->nkeys + 1, आकार(*dch->किल्ली_is_ca));
		जर ((r = sshkey_from_private(hke->किल्ली,
		    &(dch->किल्ल्या[dch->nkeys]))) != 0)
			fatal_fr(r, "sshkey_from_private");
		dch->किल्ली_is_ca[dch->nkeys] = want_ca;
		dch->nkeys++;
	}
	जर (dch->nkeys == 0)
		fatal("No host keys found for destination \"%s\"", host);
	free_hostkeys(hostkeys);
	मुक्त(os);
	परत;
}

स्थिर शून्य
parse_dest_constraint(स्थिरांक अक्षर *s, संरचना dest_constraint ***dcp,
    माप_प्रकार *ndcp, अक्षर **hostkey_files)
{
	संरचना dest_constraint *dc;
	अक्षर *os, *cp;

	dc = xcalloc(1, आकार(*dc));
	os = xstrdup(s);
	जर ((cp = म_अक्षर(os, '>')) == रिक्त) {
		/* initial hop; no 'from' hop specified */
		parse_dest_constraint_hop(os, &dc->to, hostkey_files);
	} अन्यथा {
		/* two hops specified */
		*(cp++) = '\0';
		parse_dest_constraint_hop(os, &dc->from, hostkey_files);
		parse_dest_constraint_hop(cp, &dc->to, hostkey_files);
		जर (dc->from.user != रिक्त) {
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
	*dcp = xrecallocarray(*dcp, *ndcp, *ndcp + 1, आकार(**dcp));
	(*dcp)[(*ndcp)++] = dc;
	मुक्त(os);
}


स्थिर शून्य
usage(शून्य)
{
	ख_लिखो(मानक_त्रुटि,
"usage: ssh-add [-CcDdKkLlqvXx] [-E fingerprint_hash] [-H hostkey_file]\n"
"               [-h destination_constraint] [-S provider] [-t life]\n"
"               [file ...]\n"
"       ssh-add -s pkcs11 [-Cv] [certificate ...]\n"
"       ssh-add -e pkcs11\n"
"       ssh-add -T pubkey ...\n"
	);
}

पूर्णांक
main(पूर्णांक argc, अक्षर **argv)
{
	बाह्य अक्षर *optarg;
	बाह्य पूर्णांक optind;
	पूर्णांक agent_fd = -1;
	अक्षर *pkcs11provider = रिक्त, *skprovider = रिक्त;
	अक्षर **dest_constraint_strings = रिक्त, **hostkey_files = रिक्त;
	पूर्णांक r, i, ch, deleting = 0, ret = 0, किल्ली_only = 0, cert_only = 0;
	पूर्णांक do_download = 0, xflag = 0, lflag = 0, Dflag = 0;
	पूर्णांक Qflag = 0, qflag = 0, Tflag = 0, Nflag = 0, no_pin = 0;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_INFO;
	संरचना sshkey *k, **certs = रिक्त;
	संरचना dest_constraint **dest_constraints = रिक्त;
	माप_प्रकार n, ndest_constraints = 0, ncerts = 0;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	__progname = ssh_get_progname(argv[0]);
	seed_rng();

	log_init(__progname, log_level, log_facility, 1);

	रखो_भबफ(मानक_निकास, रिक्त, _IOLBF, 0);

	skprovider = दो_पर्या("SSH_SK_PROVIDER");

	पर्यंत ((ch = getopt(argc, argv, "vkKlLNPCcdDTxXE:e:h:H:M:m:Qqs:S:t:")) != -1) {
		निवड (ch) {
		स्थिती 'v':
			जर (log_level == SYSLOG_LEVEL_INFO)
				log_level = SYSLOG_LEVEL_DEBUG1;
			अन्यथा जर (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			थांबा;
		स्थिती 'N':
			Nflag = 1;
			थांबा;
		स्थिती 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			जर (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			थांबा;
		स्थिती 'H':
			stringlist_append(&hostkey_files, optarg);
			थांबा;
		स्थिती 'h':
			stringlist_append(&dest_constraint_strings, optarg);
			थांबा;
		स्थिती 'k':
			किल्ली_only = 1;
			थांबा;
		स्थिती 'C':
			cert_only = 1;
			थांबा;
		स्थिती 'K':
			do_download = 1;
			थांबा;
		स्थिती 'l':
		स्थिती 'L':
			जर (lflag != 0)
				fatal("-%c flag already specified", lflag);
			lflag = ch;
			थांबा;
		स्थिती 'x':
		स्थिती 'X':
			जर (xflag != 0)
				fatal("-%c flag already specified", xflag);
			xflag = ch;
			थांबा;
		स्थिती 'c':
			confirm = 1;
			थांबा;
		स्थिती 'm':
		स्थिती 'M':
			/* deprecated */
			थांबा;
		स्थिती 'd':
			deleting = 1;
			थांबा;
		स्थिती 'P':
			no_pin = 1;
			थांबा;
		स्थिती 'D':
			Dflag = 1;
			थांबा;
		स्थिती 's':
			pkcs11provider = optarg;
			थांबा;
		स्थिती 'S':
			skprovider = optarg;
			थांबा;
		स्थिती 'e':
			deleting = 1;
			pkcs11provider = optarg;
			थांबा;
		स्थिती 't':
			जर ((lifetime = convtime(optarg)) == -1 ||
			    lifetime < 0 || (u_long)lifetime > UINT32_MAX) {
				ख_लिखो(मानक_त्रुटि, "Invalid lifetime\n");
				ret = 1;
				जा done;
			}
			थांबा;
		स्थिती 'q':
			qflag = 1;
			थांबा;
		स्थिती 'Q':
			Qflag = 1;
			थांबा;
		स्थिती 'T':
			Tflag = 1;
			थांबा;
		पूर्वनिर्धारित:
			usage();
			ret = 1;
			जा done;
		}
	}
	log_init(__progname, log_level, log_facility, 1);

	जर ((xflag != 0) + (lflag != 0) + (Dflag != 0) + (Qflag != 0) > 1)
		fatal("Invalid combination of actions");

	/* First, get a connection to the authentication agent. */
	निवड (r = ssh_get_authentication_socket(&agent_fd)) {
	स्थिती 0:
		थांबा;
	स्थिती SSH_ERR_AGENT_NOT_PRESENT:
		ख_लिखो(मानक_त्रुटि, "Could not open a connection to your "
		    "authentication agent.\n");
		निकास(2);
	पूर्वनिर्धारित:
		ख_लिखो(मानक_त्रुटि, "Error connecting to agent: %s\n", ssh_err(r));
		निकास(2);
	}

	जर (xflag) {
		जर (lock_agent(agent_fd, xflag == 'x' ? 1 : 0) == -1)
			ret = 1;
		जा done;
	} अन्यथा जर (lflag) {
		जर (list_identities(agent_fd, lflag == 'l' ? 1 : 0) == -1)
			ret = 1;
		जा done;
	} अन्यथा जर (Dflag) {
		जर (delete_all(agent_fd, qflag) == -1)
			ret = 1;
		जा done;
	} अन्यथा जर (Qflag) {
		जर (query_exts(agent_fd) == -1)
			ret = 1;
		जा done;
	}

#ifdef ENABLE_SK_INTERNAL
	जर (skprovider == रिक्त)
		skprovider = "internal";
#endif

	जर (hostkey_files == रिक्त) {
		/* use defaults from readconf.c */
		stringlist_append(&hostkey_files, _PATH_SSH_USER_HOSTFILE);
		stringlist_append(&hostkey_files, _PATH_SSH_USER_HOSTFILE2);
		stringlist_append(&hostkey_files, _PATH_SSH_SYSTEM_HOSTFILE);
		stringlist_append(&hostkey_files, _PATH_SSH_SYSTEM_HOSTFILE2);
	}
	जर (dest_constraint_strings != रिक्त) {
		साठी (i = 0; dest_constraint_strings[i] != रिक्त; i++) {
			parse_dest_constraint(dest_constraint_strings[i],
			  &dest_constraints, &ndest_constraints, hostkey_files);
		}
	}

	argc -= optind;
	argv += optind;
	जर (Tflag) {
		जर (argc <= 0)
			fatal("no keys to test");
		साठी (r = i = 0; i < argc; i++)
			r |= test_किल्ली(agent_fd, argv[i]);
		ret = r == 0 ? 0 : 1;
		जा done;
	}
	जर (pkcs11provider != रिक्त) {
		साठी (i = 0; i < argc; i++) {
			जर ((r = sshkey_load_public(argv[i], &k, रिक्त)) != 0)
				fatal_fr(r, "load certificate %s", argv[i]);
			certs = xrecallocarray(certs, ncerts, ncerts + 1,
			    आकार(*certs));
			debug2("%s: %s", argv[i], sshkey_ssh_name(k));
			certs[ncerts++] = k;
		}
		debug2_f("loaded %zu certificates", ncerts);
		जर (update_card(agent_fd, !deleting, pkcs11provider,
		    qflag, no_pin, किल्ली_only, cert_only,
		    dest_constraints, ndest_constraints,
		    certs, ncerts) == -1)
			ret = 1;
		साठी (n = 0; n < ncerts; n++)
			sshkey_free(certs[n]);
		मुक्त(certs);
		जा done;
	}
	जर (do_download) {
		जर (skprovider == रिक्त)
			fatal("Cannot download keys without provider");
		जर (load_resident_किल्ल्या(agent_fd, skprovider, qflag, no_pin,
		    dest_constraints, ndest_constraints) != 0)
			ret = 1;
		जा done;
	}
	जर (argc == 0) {
		अक्षर buf[PATH_MAX];
		संरचना passwd *pw;
		संरचना stat st;
		पूर्णांक मोजणी = 0;

		जर ((pw = getpwuid(getuid())) == रिक्त) {
			ख_लिखो(मानक_त्रुटि, "No user found with uid %u\n",
			    (u_int)getuid());
			ret = 1;
			जा done;
		}

		साठी (i = 0; default_files[i]; i++) {
			snprintf(buf, आकार(buf), "%s/%s", pw->pw_dir,
			    default_files[i]);
			जर (stat(buf, &st) == -1)
				सुरूठेवा;
			जर (do_file(agent_fd, deleting, किल्ली_only, cert_only,
			    buf, qflag, Nflag, skprovider,
			    dest_constraints, ndest_constraints) == -1)
				ret = 1;
			अन्यथा
				मोजणी++;
		}
		जर (मोजणी == 0)
			ret = 1;
	} अन्यथा {
		साठी (i = 0; i < argc; i++) {
			जर (do_file(agent_fd, deleting, किल्ली_only, cert_only,
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
	परत ret;
}
