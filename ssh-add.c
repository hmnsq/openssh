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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/stat.h>

#अगर_घोषित WITH_OPENSSL
# include <openssl/evp.h>
# include "openbsd-compat/openssl-compat.h"
#पूर्ण_अगर

#समावेश <errno.h>
#समावेश <fcntl.h>
#समावेश <pwd.h>
#समावेश <stdarg.h>
#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <unistd.h>
#समावेश <limits.h>
#समावेश <time.h>

#समावेश "xmalloc.h"
#समावेश "ssh.h"
#समावेश "log.h"
#समावेश "sshkey.h"
#समावेश "sshbuf.h"
#समावेश "authfd.h"
#समावेश "authfile.h"
#समावेश "pathnames.h"
#समावेश "misc.h"
#समावेश "ssherr.h"
#समावेश "digest.h"
#समावेश "ssh-sk.h"
#समावेश "sk-api.h"
#समावेश "hostfile.h"

#घोषणा CERT_EXPIRY_GRACE	(5*60)

/* argv0 */
बाह्य अक्षर *__progname;

/* Default files to add */
अटल अक्षर *default_files[] = {
#अगर_घोषित WITH_OPENSSL
	_PATH_SSH_CLIENT_ID_RSA,
	_PATH_SSH_CLIENT_ID_ECDSA,
	_PATH_SSH_CLIENT_ID_ECDSA_SK,
#पूर्ण_अगर /* WITH_OPENSSL */
	_PATH_SSH_CLIENT_ID_ED25519,
	_PATH_SSH_CLIENT_ID_ED25519_SK,
	_PATH_SSH_CLIENT_ID_MLDSA44_ED25519,
	शून्य
};

अटल पूर्णांक fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* Default lifetime (0 == forever) */
अटल पूर्णांक lifetime = 0;

/* User has to confirm key use */
अटल पूर्णांक confirm = 0;

/* we keep a cache of one passphrase */
अटल अक्षर *pass = शून्य;
अटल व्योम
clear_pass(व्योम)
{
	अगर (pass) {
		freezero(pass, म_माप(pass));
		pass = शून्य;
	}
}

अटल पूर्णांक
delete_one(पूर्णांक agent_fd, स्थिर काष्ठा sshkey *कुंजी, स्थिर अक्षर *comment,
    स्थिर अक्षर *path, पूर्णांक qflag)
{
	पूर्णांक r;

	अगर ((r = ssh_remove_identity(agent_fd, कुंजी)) != 0) {
		ख_लिखो(मानक_त्रुटि, "Could not remove identity \"%s\": %s\n",
		    path, ssh_err(r));
		वापस r;
	}
	अगर (!qflag) {
		ख_लिखो(मानक_त्रुटि, "Identity removed: %s %s (%s)\n", path,
		    sshkey_type(कुंजी), comment ? comment : "no comment");
	}
	वापस 0;
}

अटल पूर्णांक
delete_stdin(पूर्णांक agent_fd, पूर्णांक qflag, पूर्णांक कुंजी_only, पूर्णांक cert_only)
{
	अक्षर *पंक्ति = शून्य, *cp;
	माप_प्रकार linesize = 0;
	काष्ठा sshkey *कुंजी = शून्य;
	पूर्णांक lnum = 0, r, ret = -1;

	जबतक (getline(&पंक्ति, &linesize, मानक_निवेश) != -1) {
		lnum++;
		sshkey_free(कुंजी);
		कुंजी = शून्य;
		पंक्ति[म_खोज(पंक्ति, "\n")] = '\0';
		cp = पंक्ति + म_अखोज(पंक्ति, " \t");
		अगर (*cp == '#' || *cp == '\0')
			जारी;
		अगर ((कुंजी = sshkey_new(कुंजी_UNSPEC)) == शून्य)
			fatal_f("sshkey_new");
		अगर ((r = sshkey_read(कुंजी, &cp)) != 0) {
			error_r(r, "(stdin):%d: invalid key", lnum);
			जारी;
		}
		अगर ((!कुंजी_only && !cert_only) ||
		    (कुंजी_only && !sshkey_is_cert(कुंजी)) ||
		    (cert_only && sshkey_is_cert(कुंजी))) {
			अगर (delete_one(agent_fd, कुंजी, cp,
			    "(stdin)", qflag) == 0)
				ret = 0;
		}
	}
	sshkey_free(कुंजी);
	मुक्त(पंक्ति);
	वापस ret;
}

अटल पूर्णांक
delete_file(पूर्णांक agent_fd, स्थिर अक्षर *filename, पूर्णांक कुंजी_only,
    पूर्णांक cert_only, पूर्णांक qflag)
{
	काष्ठा sshkey *खुला, *cert = शून्य;
	अक्षर *certpath = शून्य, *comment = शून्य;
	पूर्णांक r, ret = -1;

	अगर (म_भेद(filename, "-") == 0)
		वापस delete_stdin(agent_fd, qflag, कुंजी_only, cert_only);

	अगर ((r = sshkey_load_public(filename, &खुला,  &comment)) != 0) {
		म_लिखो("Bad key file %s: %s\n", filename, ssh_err(r));
		वापस -1;
	}
	अगर ((!कुंजी_only && !cert_only) ||
	    (कुंजी_only && !sshkey_is_cert(खुला)) ||
	    (cert_only && sshkey_is_cert(खुला))) {
		अगर (delete_one(agent_fd, खुला, comment, filename, qflag) == 0)
			ret = 0;
	}

	अगर (कुंजी_only)
		जाओ out;

	/* Now try to delete the corresponding certificate too */
	मुक्त(comment);
	comment = शून्य;
	xasprintf(&certpath, "%s-cert.pub", filename);
	अगर ((r = sshkey_load_public(certpath, &cert, &comment)) != 0) {
		अगर (r != SSH_ERR_SYSTEM_ERROR || त्रुटि_सं != ENOENT)
			error_r(r, "Failed to load certificate \"%s\"", certpath);
		जाओ out;
	}

	अगर (!sshkey_equal_public(cert, खुला))
		fatal("Certificate %s does not match private key %s",
		    certpath, filename);

	अगर (delete_one(agent_fd, cert, comment, certpath, qflag) == 0)
		ret = 0;

 out:
	sshkey_free(cert);
	sshkey_free(खुला);
	मुक्त(certpath);
	मुक्त(comment);

	वापस ret;
}

/* Send a request to remove all identities. */
अटल पूर्णांक
delete_all(पूर्णांक agent_fd, पूर्णांक qflag)
{
	पूर्णांक ret = -1;

	/*
	 * Since the agent might be forwarded, old or non-OpenSSH, when asked
	 * to remove all keys, attempt to remove both protocol v.1 and v.2
	 * keys.
	 */
	अगर (ssh_remove_all_identities(agent_fd, 2) == 0)
		ret = 0;
	/* ignore error-code for ssh1 */
	ssh_remove_all_identities(agent_fd, 1);

	अगर (ret != 0)
		ख_लिखो(मानक_त्रुटि, "Failed to remove all identities.\n");
	अन्यथा अगर (!qflag)
		ख_लिखो(मानक_त्रुटि, "All identities removed.\n");

	वापस ret;
}

अटल पूर्णांक
query_exts(पूर्णांक agent_fd)
{
	पूर्णांक r;
	अक्षर **exts = शून्य;
	माप_प्रकार i;

	अगर ((r = ssh_agent_query_extensions(agent_fd, &exts)) != 0)
		fatal_r(r, "unable to query supported extensions");
	क्रम (i = 0; exts != शून्य && exts[i] != शून्य; i++)
		माला_दो(exts[i]);
	stringlist_free(exts);
	वापस 0;
}

अटल पूर्णांक
check_cert_lifetime(स्थिर काष्ठा sshkey *cert, पूर्णांक cert_lifetime)
{
	समय_प्रकार now;
	uint64_t n;

	अगर (cert == शून्य || cert->cert == शून्य || !sshkey_is_cert(cert) ||
	    cert->cert->valid_before == 0xFFFFFFFFFFFFFFFFULL)
		वापस cert_lifetime;
	अगर ((now = समय(शून्य)) <= 0)
		fatal_f("system time is at/before epoch");
	अगर ((uint64_t)now > (cert->cert->valid_before + CERT_EXPIRY_GRACE))
		वापस -1; /* certificate already expired */
	n = (CERT_EXPIRY_GRACE + cert->cert->valid_before) - (uint64_t)now;
	n = MINIMUM(n, पूर्णांक_उच्च);
	अगर (cert_lifetime <= 0)
		वापस (पूर्णांक)n;
	वापस MINIMUM(cert_lifetime, (पूर्णांक)n);
}

अटल पूर्णांक
add_file(पूर्णांक agent_fd, स्थिर अक्षर *filename, पूर्णांक कुंजी_only, पूर्णांक cert_only,
    पूर्णांक qflag, पूर्णांक Nflag, स्थिर अक्षर *skprovider,
    काष्ठा dest_constraint **dest_constraints,
    माप_प्रकार ndest_constraints)
{
	काष्ठा sshkey *निजी = शून्य, *cert = शून्य;
	अक्षर *comment = शून्य;
	अक्षर संदेश[1024], *certpath = शून्य;
	पूर्णांक cert_lifetime, r, fd, ret = -1;
	काष्ठा sshbuf *keyblob;

	अगर (म_भेद(filename, "-") == 0) {
		fd = STDIN_FILENO;
		filename = "(stdin)";
	} अन्यथा अगर ((fd = खोलो(filename, O_RDONLY)) == -1) {
		लिखो_त्रुटि(filename);
		वापस -1;
	}

	/*
	 * Since we'll try to load a keyfile multiple times, permission errors
	 * will occur multiple times, so check perms first and bail if wrong.
	 */
	अगर (fd != STDIN_FILENO) {
		अगर (sshkey_perm_ok(fd, filename) != 0) {
			बंद(fd);
			वापस -1;
		}
	}
	अगर ((r = sshbuf_load_fd(fd, &keyblob)) != 0) {
		ख_लिखो(मानक_त्रुटि, "Error loading key \"%s\": %s\n",
		    filename, ssh_err(r));
		sshbuf_free(keyblob);
		बंद(fd);
		वापस -1;
	}
	बंद(fd);

	/* At first, try empty passphrase */
	अगर ((r = sshkey_parse_private_fileblob(keyblob, "", &निजी,
	    &comment)) != 0 && r != SSH_ERR_कुंजी_WRONG_PASSPHRASE) {
		ख_लिखो(मानक_त्रुटि, "Error loading key \"%s\": %s\n",
		    filename, ssh_err(r));
		जाओ fail_load;
	}
	/* try last */
	अगर (निजी == शून्य && pass != शून्य) {
		अगर ((r = sshkey_parse_private_fileblob(keyblob, pass, &निजी,
		    &comment)) != 0 && r != SSH_ERR_कुंजी_WRONG_PASSPHRASE) {
			ख_लिखो(मानक_त्रुटि, "Error loading key \"%s\": %s\n",
			    filename, ssh_err(r));
			जाओ fail_load;
		}
	}
	अगर (निजी == शून्य) {
		/* clear passphrase since it did not work */
		clear_pass();
		snprintf(संदेश, माप संदेश, "Enter passphrase for %s%s: ",
		    filename, confirm ? " (will confirm each use)" : "");
		क्रम (;;) {
			pass = read_passphrase(संदेश, RP_ALLOW_STDIN);
			अगर (म_भेद(pass, "") == 0)
				जाओ fail_load;
			अगर ((r = sshkey_parse_private_fileblob(keyblob, pass,
			    &निजी, &comment)) == 0)
				अवरोध;
			अन्यथा अगर (r != SSH_ERR_कुंजी_WRONG_PASSPHRASE) {
				ख_लिखो(मानक_त्रुटि,
				    "Error loading key \"%s\": %s\n",
				    filename, ssh_err(r));
 fail_load:
				clear_pass();
				sshbuf_free(keyblob);
				वापस -1;
			}
			clear_pass();
			snprintf(संदेश, माप संदेश,
			    "Bad passphrase, try again for %s%s: ", filename,
			    confirm ? " (will confirm each use)" : "");
		}
	}
	अगर (comment == शून्य || *comment == '\0')
		comment = xstrdup(filename);
	sshbuf_free(keyblob);

	अगर (sshkey_is_sk(निजी)) {
		अगर (skprovider == शून्य) {
			ख_लिखो(मानक_त्रुटि, "Cannot load FIDO key %s "
			    "without provider\n", filename);
			जाओ out;
		}
	} अन्यथा {
		/* Don't send provider constraint for other keys */
		skprovider = शून्य;
	}

	अगर (!cert_only) {
		अगर ((r = ssh_add_identity_constrained(agent_fd, निजी,
		    comment, lifetime, confirm, skprovider,
		    dest_constraints, ndest_constraints)) == 0) {
			ret = 0;
			अगर (!qflag) {
				ख_लिखो(मानक_त्रुटि, "Identity added: %s (%s)\n",
				    filename, comment);
				अगर (lifetime != 0) {
					ख_लिखो(मानक_त्रुटि, "Lifetime set to %s\n",
					    fmt_timeframe((समय_प्रकार)lifetime));
				}
				अगर (confirm != 0) {
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
	अगर (कुंजी_only)
		जाओ out;

	/* Now try to add the certificate flavour too */
	xasprintf(&certpath, "%s-cert.pub", filename);
	अगर ((r = sshkey_load_public(certpath, &cert, शून्य)) != 0) {
		अगर (r != SSH_ERR_SYSTEM_ERROR || त्रुटि_सं != ENOENT)
			error_r(r, "Failed to load certificate \"%s\"",
			    certpath);
		जाओ out;
	}

	अगर (!sshkey_equal_public(cert, निजी)) {
		error("Certificate %s does not match private key %s",
		    certpath, filename);
		जाओ out;
	}

	cert_lifetime = lifetime;
	अगर (!Nflag &&
	    (cert_lifetime = check_cert_lifetime(cert, cert_lifetime)) == -1) {
		logit("Certificate %s has already expired; ignored", certpath);
		जाओ out;
	}

	/* Graft with private bits */
	अगर ((r = sshkey_to_certified(निजी)) != 0) {
		error_fr(r, "sshkey_to_certified");
		जाओ out;
	}
	अगर ((r = sshkey_cert_copy(cert, निजी)) != 0) {
		error_fr(r, "sshkey_cert_copy");
		जाओ out;
	}
	/* send to agent */
	अगर ((r = ssh_add_identity_constrained(agent_fd, निजी, comment,
	    cert_lifetime, confirm, skprovider,
	    dest_constraints, ndest_constraints)) != 0) {
		error_r(r, "Certificate %s (%s) add failed", certpath,
		    निजी->cert->कुंजी_id);
		जाओ out;
	}
	/* success */
	अगर (!qflag) {
		ख_लिखो(मानक_त्रुटि, "Certificate added: %s (%s)\n", certpath,
		    निजी->cert->कुंजी_id);
		अगर (cert_lifetime != 0) {
			ख_लिखो(मानक_त्रुटि, "Lifetime set to %s\n",
			    fmt_timeframe((समय_प्रकार)cert_lifetime));
		}
		अगर (confirm != 0) {
			ख_लिखो(मानक_त्रुटि, "The user must confirm each use "
			    "of the key\n");
		}
	}

 out:
	मुक्त(certpath);
	मुक्त(comment);
	sshkey_free(cert);
	sshkey_free(निजी);

	वापस ret;
}

अटल पूर्णांक
update_card(पूर्णांक agent_fd, पूर्णांक add, स्थिर अक्षर *id, पूर्णांक qflag, पूर्णांक no_pin,
    पूर्णांक कुंजी_only, पूर्णांक cert_only,
    काष्ठा dest_constraint **dest_constraints, माप_प्रकार ndest_constraints,
    काष्ठा sshkey **certs, माप_प्रकार ncerts)
{
	अक्षर *pin = शून्य;
	पूर्णांक r, ret = -1;

	अगर (कुंजी_only)
		ncerts = 0;

	अगर (add && !no_pin) {
		अगर ((pin = read_passphrase("Enter passphrase for PKCS#11: ",
		    RP_ALLOW_STDIN)) == शून्य)
			वापस -1;
	}

	अगर ((r = ssh_update_card(agent_fd, add, id, pin == शून्य ? "" : pin,
	    lifetime, confirm, dest_constraints, ndest_constraints,
	    cert_only, certs, ncerts)) == 0) {
		ret = 0;
		अगर (!qflag) {
			ख_लिखो(मानक_त्रुटि, "Card %s: %s\n",
			    add ? "added" : "removed", id);
		}
	} अन्यथा {
		ख_लिखो(मानक_त्रुटि, "Could not %s card \"%s\": %s\n",
		    add ? "add" : "remove", id, ssh_err(r));
		ret = -1;
	}
	मुक्त(pin);
	वापस ret;
}

अटल पूर्णांक
test_कुंजी(पूर्णांक agent_fd, स्थिर अक्षर *filename)
{
	काष्ठा sshkey *कुंजी = शून्य;
	u_char *sig = शून्य;
	स्थिर अक्षर *alg = शून्य;
	माप_प्रकार slen = 0;
	पूर्णांक r, ret = -1;
	अक्षर तथ्य[1024];

	अगर ((r = sshkey_load_public(filename, &कुंजी, शून्य)) != 0) {
		error_r(r, "Couldn't read public key %s", filename);
		वापस -1;
	}
	अगर (sshkey_type_plain(कुंजी->type) == कुंजी_RSA)
		alg = "rsa-sha2-256";
	arc4random_buf(तथ्य, माप(तथ्य));
	अगर ((r = ssh_agent_sign(agent_fd, कुंजी, &sig, &slen, तथ्य, माप(तथ्य),
	    alg, 0)) != 0) {
		error_r(r, "Agent signature failed for %s", filename);
		जाओ done;
	}
	अगर ((r = sshkey_verify(कुंजी, sig, slen, तथ्य, माप(तथ्य),
	    alg, 0, शून्य)) != 0) {
		error_r(r, "Signature verification failed for %s", filename);
		जाओ done;
	}
	/* success */
	ret = 0;
 done:
	मुक्त(sig);
	sshkey_free(कुंजी);
	वापस ret;
}

अटल पूर्णांक
list_identities(पूर्णांक agent_fd, पूर्णांक do_fp)
{
	अक्षर *fp;
	पूर्णांक r;
	काष्ठा ssh_identitylist *idlist;
	माप_प्रकार i;

	अगर ((r = ssh_fetch_identitylist(agent_fd, &idlist)) != 0) {
		अगर (r != SSH_ERR_AGENT_NO_IDENTITIES)
			ख_लिखो(मानक_त्रुटि, "error fetching identities: %s\n",
			    ssh_err(r));
		अन्यथा
			म_लिखो("The agent has no identities.\n");
		वापस -1;
	}
	क्रम (i = 0; i < idlist->nkeys; i++) {
		अगर (do_fp) {
			fp = sshkey_fingerprint(idlist->कुंजियाँ[i],
			    fingerprint_hash, SSH_FP_DEFAULT);
			म_लिखो("%u %s %s (%s)\n", sshkey_आकार(idlist->कुंजियाँ[i]),
			    fp == शून्य ? "(null)" : fp, idlist->comments[i],
			    sshkey_type(idlist->कुंजियाँ[i]));
			मुक्त(fp);
		} अन्यथा {
			अगर ((r = sshkey_write(idlist->कुंजियाँ[i], मानक_निकास)) != 0) {
				ख_लिखो(मानक_त्रुटि, "sshkey_write: %s\n",
				    ssh_err(r));
				जारी;
			}
			ख_लिखो(मानक_निकास, " %s\n", idlist->comments[i]);
		}
	}
	ssh_free_identitylist(idlist);
	वापस 0;
}

अटल पूर्णांक
lock_agent(पूर्णांक agent_fd, पूर्णांक lock)
{
	अक्षर prompt[100], *p1, *p2;
	पूर्णांक r, passok = 1, ret = -1;

	strlcpy(prompt, "Enter lock password: ", माप(prompt));
	p1 = read_passphrase(prompt, RP_ALLOW_STDIN);
	अगर (lock) {
		strlcpy(prompt, "Again: ", माप prompt);
		p2 = read_passphrase(prompt, RP_ALLOW_STDIN);
		अगर (म_भेद(p1, p2) != 0) {
			ख_लिखो(मानक_त्रुटि, "Passwords do not match.\n");
			passok = 0;
		}
		freezero(p2, म_माप(p2));
	}
	अगर (passok) {
		अगर ((r = ssh_lock_agent(agent_fd, lock, p1)) == 0) {
			ख_लिखो(मानक_त्रुटि, "Agent %slocked.\n", lock ? "" : "un");
			ret = 0;
		} अन्यथा {
			ख_लिखो(मानक_त्रुटि, "Failed to %slock agent: %s\n",
			    lock ? "" : "un", ssh_err(r));
		}
	}
	freezero(p1, म_माप(p1));
	वापस (ret);
}

अटल पूर्णांक
load_resident_कुंजियाँ(पूर्णांक agent_fd, स्थिर अक्षर *skprovider, पूर्णांक qflag, पूर्णांक no_pin,
    काष्ठा dest_constraint **dest_constraints, माप_प्रकार ndest_constraints)
{
	काष्ठा sshsk_resident_कुंजी **srks;
	माप_प्रकार nsrks, i;
	काष्ठा sshkey *कुंजी;
	पूर्णांक r, ok = 0;
	अक्षर *fp, *pin = शून्य;

	अगर (!no_pin) {
		pin = read_passphrase("Enter PIN for authenticator: ",
		    RP_ALLOW_STDIN);
	}
	अगर ((r = sshsk_load_resident(skprovider, शून्य, pin == शून्य ? "" : pin,
	    0, &srks, &nsrks)) != 0) {
		error_r(r, "Unable to load resident keys");
		मुक्त(pin);
		वापस r;
	}
	मुक्त(pin);
	क्रम (i = 0; i < nsrks; i++) {
		कुंजी = srks[i]->कुंजी;
		अगर ((fp = sshkey_fingerprint(कुंजी,
		    fingerprint_hash, SSH_FP_DEFAULT)) == शून्य)
			fatal_f("sshkey_fingerprint failed");
		अगर ((r = ssh_add_identity_constrained(agent_fd, कुंजी,
		    कुंजी->sk_application, lifetime, confirm, skprovider,
		    dest_constraints, ndest_constraints)) != 0) {
			error("Unable to add key %s %s",
			    sshkey_type(कुंजी), fp);
			मुक्त(fp);
			ok = r;
			जारी;
		}
		अगर (ok == 0)
			ok = 1;
		अगर (!qflag) {
			ख_लिखो(मानक_त्रुटि, "Resident identity added: %s %s\n",
			    sshkey_type(कुंजी), fp);
			अगर (lifetime != 0) {
				ख_लिखो(मानक_त्रुटि,
				    "Lifetime set to %d seconds\n", lifetime);
			}
			अगर (confirm != 0) {
				ख_लिखो(मानक_त्रुटि, "The user must confirm "
				    "each use of the key\n");
			}
		}
		मुक्त(fp);
	}
	sshsk_free_resident_कुंजियाँ(srks, nsrks);
	अगर (nsrks == 0)
		वापस SSH_ERR_कुंजी_NOT_FOUND;
	वापस ok == 1 ? 0 : ok;
}

अटल पूर्णांक
do_file(पूर्णांक agent_fd, पूर्णांक deleting, पूर्णांक कुंजी_only, पूर्णांक cert_only,
    अक्षर *file, पूर्णांक qflag, पूर्णांक Nflag, स्थिर अक्षर *skprovider,
    काष्ठा dest_constraint **dest_constraints, माप_प्रकार ndest_constraints)
{
	अगर (deleting) {
		अगर (delete_file(agent_fd, file, कुंजी_only,
		    cert_only, qflag) == -1)
			वापस -1;
	} अन्यथा {
		अगर (add_file(agent_fd, file, कुंजी_only, cert_only, qflag, Nflag,
		    skprovider, dest_constraints, ndest_constraints) == -1)
			वापस -1;
	}
	वापस 0;
}

अटल व्योम
free_dest_constraint_hop(काष्ठा dest_constraint_hop *dch)
{
	u_int i;

	अगर (dch == शून्य)
		वापस;
	मुक्त(dch->user);
	मुक्त(dch->hostname);
	क्रम (i = 0; i < dch->nkeys; i++)
		sshkey_free(dch->कुंजियाँ[i]);
	मुक्त(dch->कुंजियाँ);
	मुक्त(dch->कुंजी_is_ca);
}

अटल व्योम
free_dest_constraints(काष्ठा dest_constraint **dcs, माप_प्रकार ndcs)
{
	माप_प्रकार i;

	क्रम (i = 0; i < ndcs; i++) {
		free_dest_constraint_hop(&dcs[i]->from);
		free_dest_constraint_hop(&dcs[i]->to);
		मुक्त(dcs[i]);
	}
	मुक्त(dcs);
}


अटल व्योम
parse_dest_constraint_hop(स्थिर अक्षर *s, काष्ठा dest_constraint_hop *dch,
    अक्षर **hostkey_files)
{
	अक्षर *user = शून्य, *host, *os, *path;
	माप_प्रकार i;
	काष्ठा hostkeys *hostkeys;
	स्थिर काष्ठा hostkey_entry *hke;
	पूर्णांक r, want_ca;

	स_रखो(dch, '\0', माप(*dch));
	os = xstrdup(s);
	अगर ((host = म_खोजप(os, '@')) == शून्य)
		host = os;
	अन्यथा {
		*host++ = '\0';
		user = os;
	}
	cleanhostname(host);
	/* Trivial case: username@ (all hosts) */
	अगर (*host == '\0') {
		अगर (user == शून्य) {
			fatal("Invalid key destination constraint \"%s\": "
			    "does not specify user or host", s);
		}
		dch->user = xstrdup(user);
		/* other fields left blank */
		मुक्त(os);
		वापस;
	}
	अगर (hostkey_files == शून्य)
		fatal_f("no hostkey files");
	/* Otherwise we need to look up the keys for this hostname */
	hostkeys = init_hostkeys();
	क्रम (i = 0; hostkey_files[i]; i++) {
		path = tilde_expand_filename(hostkey_files[i], getuid());
		debug2_f("looking up host keys for \"%s\" in %s", host, path);
                load_hostkeys(hostkeys, host, path, 0);
		मुक्त(path);
	}
	dch->user = user == शून्य ? शून्य : xstrdup(user);
	dch->hostname = xstrdup(host);
	क्रम (i = 0; i < hostkeys->अंक_entries; i++) {
		hke = hostkeys->entries + i;
		want_ca = hke->marker == MRK_CA;
		अगर (hke->marker != MRK_NONE && !want_ca)
			जारी;
		debug3_f("%s%s%s: adding %s %skey from %s:%lu as key %u",
		    user == शून्य ? "": user, user == शून्य ? "" : "@",
		    host, sshkey_type(hke->कुंजी), want_ca ? "CA " : "",
		    hke->file, hke->पंक्ति, dch->nkeys);
		dch->कुंजियाँ = xrecallocarray(dch->कुंजियाँ, dch->nkeys,
		    dch->nkeys + 1, माप(*dch->कुंजियाँ));
		dch->कुंजी_is_ca = xrecallocarray(dch->कुंजी_is_ca, dch->nkeys,
		    dch->nkeys + 1, माप(*dch->कुंजी_is_ca));
		अगर ((r = sshkey_from_private(hke->कुंजी,
		    &(dch->कुंजियाँ[dch->nkeys]))) != 0)
			fatal_fr(r, "sshkey_from_private");
		dch->कुंजी_is_ca[dch->nkeys] = want_ca;
		dch->nkeys++;
	}
	अगर (dch->nkeys == 0)
		fatal("No host keys found for destination \"%s\"", host);
	free_hostkeys(hostkeys);
	मुक्त(os);
	वापस;
}

अटल व्योम
parse_dest_constraint(स्थिर अक्षर *s, काष्ठा dest_constraint ***dcp,
    माप_प्रकार *ndcp, अक्षर **hostkey_files)
{
	काष्ठा dest_constraint *dc;
	अक्षर *os, *cp;

	dc = xcalloc(1, माप(*dc));
	os = xstrdup(s);
	अगर ((cp = म_अक्षर(os, '>')) == शून्य) {
		/* initial hop; no 'from' hop specified */
		parse_dest_constraint_hop(os, &dc->to, hostkey_files);
	} अन्यथा {
		/* two hops specified */
		*(cp++) = '\0';
		parse_dest_constraint_hop(os, &dc->from, hostkey_files);
		parse_dest_constraint_hop(cp, &dc->to, hostkey_files);
		अगर (dc->from.user != शून्य) {
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
	*dcp = xrecallocarray(*dcp, *ndcp, *ndcp + 1, माप(**dcp));
	(*dcp)[(*ndcp)++] = dc;
	मुक्त(os);
}


अटल व्योम
usage(व्योम)
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
मुख्य(पूर्णांक argc, अक्षर **argv)
{
	बाह्य अक्षर *optarg;
	बाह्य पूर्णांक optind;
	पूर्णांक agent_fd = -1;
	अक्षर *pkcs11provider = शून्य, *skprovider = शून्य;
	अक्षर **dest_constraint_strings = शून्य, **hostkey_files = शून्य;
	पूर्णांक r, i, ch, deleting = 0, ret = 0, कुंजी_only = 0, cert_only = 0;
	पूर्णांक do_download = 0, xflag = 0, lflag = 0, Dflag = 0;
	पूर्णांक Qflag = 0, qflag = 0, Tflag = 0, Nflag = 0, no_pin = 0;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_INFO;
	काष्ठा sshkey *k, **certs = शून्य;
	काष्ठा dest_constraint **dest_constraints = शून्य;
	माप_प्रकार n, ndest_constraints = 0, ncerts = 0;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	__progname = ssh_get_progname(argv[0]);
	seed_rng();

	log_init(__progname, log_level, log_facility, 1);

	रखो_भबफ(मानक_निकास, शून्य, _IOLBF, 0);

	skprovider = दो_पर्या("SSH_SK_PROVIDER");

	जबतक ((ch = getopt(argc, argv, "vkKlLNPCcdDTxXE:e:h:H:M:m:Qqs:S:t:")) != -1) {
		चयन (ch) {
		हाल 'v':
			अगर (log_level == SYSLOG_LEVEL_INFO)
				log_level = SYSLOG_LEVEL_DEBUG1;
			अन्यथा अगर (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			अवरोध;
		हाल 'N':
			Nflag = 1;
			अवरोध;
		हाल 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			अगर (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			अवरोध;
		हाल 'H':
			stringlist_append(&hostkey_files, optarg);
			अवरोध;
		हाल 'h':
			stringlist_append(&dest_constraint_strings, optarg);
			अवरोध;
		हाल 'k':
			कुंजी_only = 1;
			अवरोध;
		हाल 'C':
			cert_only = 1;
			अवरोध;
		हाल 'K':
			do_download = 1;
			अवरोध;
		हाल 'l':
		हाल 'L':
			अगर (lflag != 0)
				fatal("-%c flag already specified", lflag);
			lflag = ch;
			अवरोध;
		हाल 'x':
		हाल 'X':
			अगर (xflag != 0)
				fatal("-%c flag already specified", xflag);
			xflag = ch;
			अवरोध;
		हाल 'c':
			confirm = 1;
			अवरोध;
		हाल 'm':
		हाल 'M':
			/* deprecated */
			अवरोध;
		हाल 'd':
			deleting = 1;
			अवरोध;
		हाल 'P':
			no_pin = 1;
			अवरोध;
		हाल 'D':
			Dflag = 1;
			अवरोध;
		हाल 's':
			pkcs11provider = optarg;
			अवरोध;
		हाल 'S':
			skprovider = optarg;
			अवरोध;
		हाल 'e':
			deleting = 1;
			pkcs11provider = optarg;
			अवरोध;
		हाल 't':
			अगर ((lifetime = convtime(optarg)) == -1 ||
			    lifetime < 0 || (u_long)lifetime > UINT32_MAX) {
				ख_लिखो(मानक_त्रुटि, "Invalid lifetime\n");
				ret = 1;
				जाओ done;
			}
			अवरोध;
		हाल 'q':
			qflag = 1;
			अवरोध;
		हाल 'Q':
			Qflag = 1;
			अवरोध;
		हाल 'T':
			Tflag = 1;
			अवरोध;
		शेष:
			usage();
			ret = 1;
			जाओ done;
		}
	}
	log_init(__progname, log_level, log_facility, 1);

	अगर ((xflag != 0) + (lflag != 0) + (Dflag != 0) + (Qflag != 0) > 1)
		fatal("Invalid combination of actions");

	/* First, get a connection to the authentication agent. */
	चयन (r = ssh_get_authentication_socket(&agent_fd)) {
	हाल 0:
		अवरोध;
	हाल SSH_ERR_AGENT_NOT_PRESENT:
		ख_लिखो(मानक_त्रुटि, "Could not open a connection to your "
		    "authentication agent.\n");
		निकास(2);
	शेष:
		ख_लिखो(मानक_त्रुटि, "Error connecting to agent: %s\n", ssh_err(r));
		निकास(2);
	}

	अगर (xflag) {
		अगर (lock_agent(agent_fd, xflag == 'x' ? 1 : 0) == -1)
			ret = 1;
		जाओ done;
	} अन्यथा अगर (lflag) {
		अगर (list_identities(agent_fd, lflag == 'l' ? 1 : 0) == -1)
			ret = 1;
		जाओ done;
	} अन्यथा अगर (Dflag) {
		अगर (delete_all(agent_fd, qflag) == -1)
			ret = 1;
		जाओ done;
	} अन्यथा अगर (Qflag) {
		अगर (query_exts(agent_fd) == -1)
			ret = 1;
		जाओ done;
	}

#अगर_घोषित ENABLE_SK_INTERNAL
	अगर (skprovider == शून्य)
		skprovider = "internal";
#पूर्ण_अगर

	अगर (hostkey_files == शून्य) {
		/* use defaults from readconf.c */
		stringlist_append(&hostkey_files, _PATH_SSH_USER_HOSTFILE);
		stringlist_append(&hostkey_files, _PATH_SSH_USER_HOSTFILE2);
		stringlist_append(&hostkey_files, _PATH_SSH_SYSTEM_HOSTFILE);
		stringlist_append(&hostkey_files, _PATH_SSH_SYSTEM_HOSTFILE2);
	}
	अगर (dest_constraint_strings != शून्य) {
		क्रम (i = 0; dest_constraint_strings[i] != शून्य; i++) {
			parse_dest_constraint(dest_constraint_strings[i],
			  &dest_constraints, &ndest_constraints, hostkey_files);
		}
	}

	argc -= optind;
	argv += optind;
	अगर (Tflag) {
		अगर (argc <= 0)
			fatal("no keys to test");
		क्रम (r = i = 0; i < argc; i++)
			r |= test_कुंजी(agent_fd, argv[i]);
		ret = r == 0 ? 0 : 1;
		जाओ done;
	}
	अगर (pkcs11provider != शून्य) {
		क्रम (i = 0; i < argc; i++) {
			अगर ((r = sshkey_load_public(argv[i], &k, शून्य)) != 0)
				fatal_fr(r, "load certificate %s", argv[i]);
			certs = xrecallocarray(certs, ncerts, ncerts + 1,
			    माप(*certs));
			debug2("%s: %s", argv[i], sshkey_ssh_name(k));
			certs[ncerts++] = k;
		}
		debug2_f("loaded %zu certificates", ncerts);
		अगर (update_card(agent_fd, !deleting, pkcs11provider,
		    qflag, no_pin, कुंजी_only, cert_only,
		    dest_constraints, ndest_constraints,
		    certs, ncerts) == -1)
			ret = 1;
		क्रम (n = 0; n < ncerts; n++)
			sshkey_free(certs[n]);
		मुक्त(certs);
		जाओ done;
	}
	अगर (do_download) {
		अगर (skprovider == शून्य)
			fatal("Cannot download keys without provider");
		अगर (load_resident_कुंजियाँ(agent_fd, skprovider, qflag, no_pin,
		    dest_constraints, ndest_constraints) != 0)
			ret = 1;
		जाओ done;
	}
	अगर (argc == 0) {
		अक्षर buf[PATH_MAX];
		काष्ठा passwd *pw;
		काष्ठा stat st;
		पूर्णांक गिनती = 0;

		अगर ((pw = getpwuid(getuid())) == शून्य) {
			ख_लिखो(मानक_त्रुटि, "No user found with uid %u\n",
			    (u_int)getuid());
			ret = 1;
			जाओ done;
		}

		क्रम (i = 0; default_files[i]; i++) {
			snprintf(buf, माप(buf), "%s/%s", pw->pw_dir,
			    default_files[i]);
			अगर (stat(buf, &st) == -1)
				जारी;
			अगर (do_file(agent_fd, deleting, कुंजी_only, cert_only,
			    buf, qflag, Nflag, skprovider,
			    dest_constraints, ndest_constraints) == -1)
				ret = 1;
			अन्यथा
				गिनती++;
		}
		अगर (गिनती == 0)
			ret = 1;
	} अन्यथा {
		क्रम (i = 0; i < argc; i++) {
			अगर (do_file(agent_fd, deleting, कुंजी_only, cert_only,
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
	वापस ret;
}
