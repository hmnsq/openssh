/* $OpenBSD: ssh-pkcs11-client.c,v 1.26 2026/02/09 22:11:39 dtucker Exp $ */
/*
 * Copyright (c) 2010 Markus Friedl.  All rights reserved.
 * Copyright (c) 2014 Pedro Martelletto. All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/time.h>
#अन्तर्भाव <sys/socket.h>

#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <errno.h>
#अन्तर्भाव <limits.h>

#अन्तर्भाव "pathnames.h"
#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "authfd.h"
#अन्तर्भाव "atomicio.h"
#अन्तर्भाव "ssh-pkcs11.h"
#अन्तर्भाव "ssherr.h"

/* borrows code from sftp-server and ssh-agent */

/*
 * Maintain a list of ssh-pkcs11-helper subprocesses. These may be looked up
 * by provider path or their unique keyblobs.
 */
संरचना helper {
	अक्षर *path;
	pid_t pid;
	पूर्णांक fd;
	माप_प्रकार nkeyblobs;
	संरचना sshbuf **keyblobs; /* XXX use a tree or something faster */
};
स्थिर संरचना helper **helpers;
स्थिर माप_प्रकार nhelpers;

स्थिर संरचना helper *
helper_by_provider(स्थिरांक अक्षर *path)
{
	माप_प्रकार i;

	साठी (i = 0; i < nhelpers; i++) {
		जर (helpers[i] == रिक्त || helpers[i]->path == रिक्त ||
		    helpers[i]->fd == -1)
			सुरूठेवा;
		जर (म_भेद(helpers[i]->path, path) == 0)
			परत helpers[i];
	}
	परत रिक्त;
}

स्थिर संरचना helper *
helper_by_किल्ली(स्थिरांक संरचना sshkey *किल्ली)
{
	माप_प्रकार i, j;
	संरचना sshbuf *keyblob = रिक्त;
	पूर्णांक r;

	जर ((keyblob = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	जर ((r = sshkey_putb(किल्ली, keyblob)) != 0)
		fatal_fr(r, "serialise key");

	साठी (i = 0; i < nhelpers; i++) {
		जर (helpers[i] == रिक्त)
			सुरूठेवा;
		साठी (j = 0; j < helpers[i]->nkeyblobs; j++) {
			जर (sshbuf_equals(keyblob,
			    helpers[i]->keyblobs[j]) == 0) {
				sshbuf_free(keyblob);
				परत helpers[i];
			}
		}
	}
	sshbuf_free(keyblob);
	परत रिक्त;

}

स्थिर शून्य
helper_add_किल्ली(संरचना helper *helper, संरचना sshkey *किल्ली)
{
	पूर्णांक r;

	helper->keyblobs = xrecallocarray(helper->keyblobs, helper->nkeyblobs,
	    helper->nkeyblobs + 1, आकार(*helper->keyblobs));
	जर ((helper->keyblobs[helper->nkeyblobs] = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	जर ((r = sshkey_putb(किल्ली, helper->keyblobs[helper->nkeyblobs])) != 0)
		fatal_fr(r, "shkey_putb failed");
	helper->nkeyblobs++;
	debug3_f("added %s key for provider %s, now has %zu keys",
	    sshkey_type(किल्ली), helper->path, helper->nkeyblobs);
}

स्थिर शून्य
helper_terminate(संरचना helper *helper)
{
	माप_प्रकार i;
	पूर्णांक found = 0;

	जर (helper == रिक्त)
		परत;
	जर (helper->path == रिक्त)
		fatal_f("inconsistent helper");

	debug3_f("terminating helper for %s; remaining %zu keys",
	    helper->path, helper->nkeyblobs);

	बंद(helper->fd);
	/* XXX waitpid() */
	helper->fd = -1;
	helper->pid = -1;

	/* repack helpers */
	साठी (i = 0; i < nhelpers; i++) {
		जर (helpers[i] == helper) {
			जर (found)
				fatal_f("helper recorded more than once");
			found = 1;
		} अन्यथा जर (found)
			helpers[i - 1] = helpers[i];
	}
	जर (found) {
		helpers = xrecallocarray(helpers, nhelpers,
		    nhelpers - 1, आकार(*helpers));
		nhelpers--;
	}
	साठी (i = 0; i < helper->nkeyblobs; i++)
		sshbuf_free(helper->keyblobs[i]);
	मुक्त(helper->path);
	मुक्त(helper);
}

स्थिर शून्य
send_संदेश(पूर्णांक fd, संरचना sshbuf *m)
{
	u_char buf[4];
	माप_प्रकार mlen = sshbuf_len(m);
	पूर्णांक r;

	जर (fd == -1)
		परत;
	POKE_U32(buf, mlen);
	जर (atomicio(vwrite, fd, buf, 4) != 4 ||
	    atomicio(vwrite, fd, sshbuf_mutable_ptr(m),
	    sshbuf_len(m)) != sshbuf_len(m))
		error("write to helper failed");
	जर ((r = sshbuf_consume(m, mlen)) != 0)
		fatal_fr(r, "consume");
}

स्थिर पूर्णांक
recv_संदेश(पूर्णांक fd, संरचना sshbuf *m)
{
	u_int l, len;
	u_char c, buf[1024];
	पूर्णांक r;

	sshbuf_reset(m);
	जर (fd == -1)
		परत 0; /* XXX */
	जर ((len = atomicio(पठ, fd, buf, 4)) != 4) {
		error("read from helper failed: %u", len);
		परत (0); /* XXX */
	}
	len = PEEK_U32(buf);
	जर (len > 256 * 1024)
		fatal("response too long: %u", len);
	/* read len bytes into m */
	पर्यंत (len > 0) {
		l = len;
		जर (l > आकार(buf))
			l = आकार(buf);
		जर (atomicio(पठ, fd, buf, l) != l) {
			error("response from helper failed.");
			परत (0); /* XXX */
		}
		जर ((r = sshbuf_put(m, buf, l)) != 0)
			fatal_fr(r, "sshbuf_put");
		len -= l;
	}
	जर ((r = sshbuf_get_u8(m, &c)) != 0)
		fatal_fr(r, "parse type");
	परत c;
}

पूर्णांक
pkcs11_init(पूर्णांक interactive)
{
	परत 0;
}

शून्य
pkcs11_terminate(शून्य)
{
	माप_प्रकार i;

	debug3_f("terminating %zu helpers", nhelpers);
	साठी (i = 0; i < nhelpers; i++)
		helper_terminate(helpers[i]);
}

पूर्णांक
pkcs11_sign(संरचना sshkey *किल्ली,
    u_char **sigp, माप_प्रकार *lenp,
    स्थिरांक u_char *data, माप_प्रकार datalen,
    स्थिरांक अक्षर *alg, स्थिरांक अक्षर *sk_provider,
    स्थिरांक अक्षर *sk_pin, u_int compat)
{
	संरचना sshbuf *संदेश = रिक्त;
	संरचना helper *helper;
	पूर्णांक status, r;
	u_char *signature = रिक्त;
	माप_प्रकार signature_len = 0;
	पूर्णांक ret = SSH_ERR_INTERNAL_ERROR;

	जर (sigp != रिक्त)
		*sigp = रिक्त;
	जर (lenp != रिक्त)
		*lenp = 0;

	जर ((helper = helper_by_किल्ली(किल्ली)) == रिक्त || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(किल्ली));

	जर ((संदेश = sshbuf_new()) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;
	जर ((r = sshbuf_put_u8(संदेश, SSH2_AGENTC_SIGN_REQUEST)) != 0 ||
	    (r = sshkey_puts_plain(किल्ली, संदेश)) != 0 ||
	    (r = sshbuf_put_string(संदेश, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, alg == रिक्त ? "" : alg)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, compat)) != 0)
		fatal_fr(r, "compose");
	send_संदेश(helper->fd, संदेश);
	sshbuf_reset(संदेश);

	जर ((status = recv_संदेश(helper->fd, संदेश)) != SSH2_AGENT_SIGN_RESPONSE) {
		/* XXX translate status to something useful */
		debug_fr(r, "recv_msg");
		ret = SSH_ERR_AGENT_FAILURE;
		जा fail;
	}

	जर ((r = sshbuf_get_string(संदेश, &signature, &signature_len)) != 0)
		fatal_fr(r, "parse");

	/* success */
	जर (sigp != रिक्त) {
		*sigp = signature;
		signature = रिक्त;
	}
	जर (lenp != रिक्त)
		*lenp = signature_len;
	ret = 0;

 fail:
	मुक्त(signature);
	sshbuf_free(संदेश);
	परत ret;
}

/*
 * Make a private PKCS#11-backed certificate by grafting a previously-loaded
 * PKCS#11 private key and a public certificate key.
 */
पूर्णांक
pkcs11_make_cert(स्थिरांक संरचना sshkey *priv,
    स्थिरांक संरचना sshkey *certpub, संरचना sshkey **certprivp)
{
	संरचना helper *helper = रिक्त;
	संरचना sshkey *ret;
	पूर्णांक r;

	जर ((helper = helper_by_किल्ली(priv)) == रिक्त || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(priv));

	debug3_f("private key type %s cert type %s on provider %s",
	    sshkey_type(priv), sshkey_type(certpub), helper->path);

	*certprivp = रिक्त;
	जर (!sshkey_is_cert(certpub) || sshkey_is_cert(priv) ||
	    !sshkey_equal_public(priv, certpub)) {
		error_f("private key %s doesn't match cert %s",
		    sshkey_type(priv), sshkey_type(certpub));
		परत SSH_ERR_INVALID_ARGUMENT;
	}
	*certprivp = रिक्त;
	जर ((r = sshkey_from_private(priv, &ret)) != 0)
		fatal_fr(r, "copy key");

	ret->flags |= SSHKEY_FLAG_EXT;
	जर ((r = sshkey_to_certified(ret)) != 0 ||
	    (r = sshkey_cert_copy(certpub, ret)) != 0)
		fatal_fr(r, "graft certificate");

	helper_add_किल्ली(helper, ret);

	debug3_f("provider %s: %zu remaining keys",
	    helper->path, helper->nkeyblobs);

	/* success */
	*certprivp = ret;
	परत 0;
}

स्थिर संरचना helper *
pkcs11_start_helper(स्थिरांक अक्षर *path)
{
	पूर्णांक pair[2];
	अक्षर *prog, *verbosity = रिक्त;
	संरचना helper *helper;
	pid_t pid;

	जर (nhelpers >= पूर्णांक_उच्च)
		fatal_f("too many helpers");
	debug3_f("start helper for %s", path);
	जर (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
		error_f("socketpair: %s", म_त्रुटि(त्रुटि_सं));
		परत रिक्त;
	}
	helper = xcalloc(1, आकार(*helper));
	जर ((pid = विभाजन()) == -1) {
		error_f("fork: %s", म_त्रुटि(त्रुटि_सं));
		बंद(pair[0]);
		बंद(pair[1]);
		मुक्त(helper);
		परत रिक्त;
	} अन्यथा जर (pid == 0) {
		जर ((dup2(pair[1], STDIN_FILENO) == -1) ||
		    (dup2(pair[1], STDOUT_FILENO) == -1)) {
			ख_लिखो(मानक_त्रुटि, "dup2: %s\n", म_त्रुटि(त्रुटि_सं));
			_exit(1);
		}
		बंद(pair[0]);
		बंद(pair[1]);
		closefrom(STDERR_FILENO + 1);
		prog = दो_पर्या("SSH_PKCS11_HELPER");
		जर (prog == रिक्त || म_माप(prog) == 0)
			prog = _PATH_SSH_PKCS11_HELPER;
		जर (log_level_get() >= SYSLOG_LEVEL_DEBUG1)
			verbosity = "-vvv";
		debug_f("starting %s %s", prog,
		    verbosity == रिक्त ? "" : verbosity);
		execlp(prog, prog, verbosity, (अक्षर *)रिक्त);
		ख_लिखो(मानक_त्रुटि, "exec: %s: %s\n", prog, म_त्रुटि(त्रुटि_सं));
		_exit(1);
	}
	बंद(pair[1]);
	helper->fd = pair[0];
	helper->path = xstrdup(path);
	helper->pid = pid;
	debug3_f("helper %zu for \"%s\" on fd %d pid %ld", nhelpers,
	    helper->path, helper->fd, (दीर्घ)helper->pid);
	helpers = xrecallocarray(helpers, nhelpers,
	    nhelpers + 1, आकार(*helpers));
	helpers[nhelpers++] = helper;
	परत helper;
}

पूर्णांक
pkcs11_add_provider(अक्षर *name, अक्षर *pin, संरचना sshkey ***keysp,
    अक्षर ***labelsp)
{
	संरचना sshkey *k;
	पूर्णांक r, type;
	अक्षर *label;
	u_int ret = -1, nkeys, i;
	संरचना sshbuf *संदेश;
	संरचना helper *helper;

	जर ((helper = helper_by_provider(name)) == रिक्त &&
	    (helper = pkcs11_start_helper(name)) == रिक्त)
		परत -1;

	debug3_f("add %s", helper->path);

	जर ((संदेश = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	जर ((r = sshbuf_put_u8(संदेश, SSH_AGENTC_ADD_SMARTCARD_किल्ली)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, name)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, pin)) != 0)
		fatal_fr(r, "compose");
	send_संदेश(helper->fd, संदेश);
	sshbuf_reset(संदेश);

	type = recv_संदेश(helper->fd, संदेश);
	debug3_f("response %d", type);
	जर (type == SSH2_AGENT_IDENTITIES_ANSWER) {
		जर ((r = sshbuf_get_u32(संदेश, &nkeys)) != 0)
			fatal_fr(r, "parse nkeys");
		debug3_f("helper return %u keys", nkeys);
		*keysp = xcalloc(nkeys, आकार(संरचना sshkey *));
		जर (labelsp)
			*labelsp = xcalloc(nkeys, आकार(अक्षर *));
		साठी (i = 0; i < nkeys; i++) {
			/* XXX clean up properly instead of fatal() */
			जर ((r = sshkey_froms(संदेश, &k)) != 0 ||
			    (r = sshbuf_get_cstring(संदेश, &label, रिक्त)) != 0)
				fatal_fr(r, "parse key");
			k->flags |= SSHKEY_FLAG_EXT;
			helper_add_किल्ली(helper, k);
			(*keysp)[i] = k;
			जर (labelsp)
				(*labelsp)[i] = label;
			अन्यथा
				मुक्त(label);
		}
		/* success */
		ret = 0;
	} अन्यथा जर (type == SSH2_AGENT_FAILURE) {
		जर ((r = sshbuf_get_u32(संदेश, &nkeys)) != 0)
			error_fr(r, "failed to parse failure response");
	}
	जर (ret != 0) {
		debug_f("no keys; terminate helper");
		helper_terminate(helper);
	}
	sshbuf_free(संदेश);
	परत ret == 0 ? (पूर्णांक)nkeys : -1;
}

पूर्णांक
pkcs11_del_provider(अक्षर *name)
{
	संरचना helper *helper;

	/*
	 * ssh-agent deletes keys before calling this, so the helper entry
	 * should be gone before we get here.
	 */
	debug3_f("delete %s", name ? name : "(null)");
	जर ((helper = helper_by_provider(name)) != रिक्त)
		helper_terminate(helper);
	परत 0;
}

शून्य
pkcs11_किल्ली_free(संरचना sshkey *किल्ली)
{
	संरचना helper *helper;
	संरचना sshbuf *keyblob = रिक्त;
	माप_प्रकार i;
	पूर्णांक r, found = 0;

	debug3_f("free %s key", sshkey_type(किल्ली));

	जर ((helper = helper_by_किल्ली(किल्ली)) == रिक्त || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(किल्ली));
	जर ((keyblob = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	जर ((r = sshkey_putb(किल्ली, keyblob)) != 0)
		fatal_fr(r, "serialise key");

	/* repack keys */
	साठी (i = 0; i < helper->nkeyblobs; i++) {
		जर (sshbuf_equals(keyblob, helper->keyblobs[i]) == 0) {
			जर (found)
				fatal_f("key recorded more than once");
			found = 1;
		} अन्यथा जर (found)
			helper->keyblobs[i - 1] = helper->keyblobs[i];
	}
	जर (found) {
		helper->keyblobs = xrecallocarray(helper->keyblobs,
		    helper->nkeyblobs, helper->nkeyblobs - 1,
		    आकार(*helper->keyblobs));
		helper->nkeyblobs--;
	}
	जर (helper->nkeyblobs == 0)
		helper_terminate(helper);
}
