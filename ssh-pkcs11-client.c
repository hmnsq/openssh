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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/time.h>
#समावेश <sys/socket.h>

#समावेश <stdarg.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <unistd.h>
#समावेश <errno.h>
#समावेश <limits.h>

#समावेश "pathnames.h"
#समावेश "xmalloc.h"
#समावेश "sshbuf.h"
#समावेश "log.h"
#समावेश "misc.h"
#समावेश "sshkey.h"
#समावेश "authfd.h"
#समावेश "atomicio.h"
#समावेश "ssh-pkcs11.h"
#समावेश "ssherr.h"

/* borrows code from sftp-server and ssh-agent */

/*
 * Maintain a list of ssh-pkcs11-helper subprocesses. These may be looked up
 * by provider path or their unique keyblobs.
 */
काष्ठा helper {
	अक्षर *path;
	pid_t pid;
	पूर्णांक fd;
	माप_प्रकार nkeyblobs;
	काष्ठा sshbuf **keyblobs; /* XXX use a tree or something faster */
};
अटल काष्ठा helper **helpers;
अटल माप_प्रकार nhelpers;

अटल काष्ठा helper *
helper_by_provider(स्थिर अक्षर *path)
{
	माप_प्रकार i;

	क्रम (i = 0; i < nhelpers; i++) {
		अगर (helpers[i] == शून्य || helpers[i]->path == शून्य ||
		    helpers[i]->fd == -1)
			जारी;
		अगर (म_भेद(helpers[i]->path, path) == 0)
			वापस helpers[i];
	}
	वापस शून्य;
}

अटल काष्ठा helper *
helper_by_कुंजी(स्थिर काष्ठा sshkey *कुंजी)
{
	माप_प्रकार i, j;
	काष्ठा sshbuf *keyblob = शून्य;
	पूर्णांक r;

	अगर ((keyblob = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = sshkey_putb(कुंजी, keyblob)) != 0)
		fatal_fr(r, "serialise key");

	क्रम (i = 0; i < nhelpers; i++) {
		अगर (helpers[i] == शून्य)
			जारी;
		क्रम (j = 0; j < helpers[i]->nkeyblobs; j++) {
			अगर (sshbuf_equals(keyblob,
			    helpers[i]->keyblobs[j]) == 0) {
				sshbuf_free(keyblob);
				वापस helpers[i];
			}
		}
	}
	sshbuf_free(keyblob);
	वापस शून्य;

}

अटल व्योम
helper_add_कुंजी(काष्ठा helper *helper, काष्ठा sshkey *कुंजी)
{
	पूर्णांक r;

	helper->keyblobs = xrecallocarray(helper->keyblobs, helper->nkeyblobs,
	    helper->nkeyblobs + 1, माप(*helper->keyblobs));
	अगर ((helper->keyblobs[helper->nkeyblobs] = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = sshkey_putb(कुंजी, helper->keyblobs[helper->nkeyblobs])) != 0)
		fatal_fr(r, "shkey_putb failed");
	helper->nkeyblobs++;
	debug3_f("added %s key for provider %s, now has %zu keys",
	    sshkey_type(कुंजी), helper->path, helper->nkeyblobs);
}

अटल व्योम
helper_terminate(काष्ठा helper *helper)
{
	माप_प्रकार i;
	पूर्णांक found = 0;

	अगर (helper == शून्य)
		वापस;
	अगर (helper->path == शून्य)
		fatal_f("inconsistent helper");

	debug3_f("terminating helper for %s; remaining %zu keys",
	    helper->path, helper->nkeyblobs);

	बंद(helper->fd);
	/* XXX waitpid() */
	helper->fd = -1;
	helper->pid = -1;

	/* repack helpers */
	क्रम (i = 0; i < nhelpers; i++) {
		अगर (helpers[i] == helper) {
			अगर (found)
				fatal_f("helper recorded more than once");
			found = 1;
		} अन्यथा अगर (found)
			helpers[i - 1] = helpers[i];
	}
	अगर (found) {
		helpers = xrecallocarray(helpers, nhelpers,
		    nhelpers - 1, माप(*helpers));
		nhelpers--;
	}
	क्रम (i = 0; i < helper->nkeyblobs; i++)
		sshbuf_free(helper->keyblobs[i]);
	मुक्त(helper->path);
	मुक्त(helper);
}

अटल व्योम
send_संदेश(पूर्णांक fd, काष्ठा sshbuf *m)
{
	u_char buf[4];
	माप_प्रकार mlen = sshbuf_len(m);
	पूर्णांक r;

	अगर (fd == -1)
		वापस;
	POKE_U32(buf, mlen);
	अगर (atomicio(vwrite, fd, buf, 4) != 4 ||
	    atomicio(vwrite, fd, sshbuf_mutable_ptr(m),
	    sshbuf_len(m)) != sshbuf_len(m))
		error("write to helper failed");
	अगर ((r = sshbuf_consume(m, mlen)) != 0)
		fatal_fr(r, "consume");
}

अटल पूर्णांक
recv_संदेश(पूर्णांक fd, काष्ठा sshbuf *m)
{
	u_int l, len;
	u_char c, buf[1024];
	पूर्णांक r;

	sshbuf_reset(m);
	अगर (fd == -1)
		वापस 0; /* XXX */
	अगर ((len = atomicio(पढ़ो, fd, buf, 4)) != 4) {
		error("read from helper failed: %u", len);
		वापस (0); /* XXX */
	}
	len = PEEK_U32(buf);
	अगर (len > 256 * 1024)
		fatal("response too long: %u", len);
	/* read len bytes into m */
	जबतक (len > 0) {
		l = len;
		अगर (l > माप(buf))
			l = माप(buf);
		अगर (atomicio(पढ़ो, fd, buf, l) != l) {
			error("response from helper failed.");
			वापस (0); /* XXX */
		}
		अगर ((r = sshbuf_put(m, buf, l)) != 0)
			fatal_fr(r, "sshbuf_put");
		len -= l;
	}
	अगर ((r = sshbuf_get_u8(m, &c)) != 0)
		fatal_fr(r, "parse type");
	वापस c;
}

पूर्णांक
pkcs11_init(पूर्णांक interactive)
{
	वापस 0;
}

व्योम
pkcs11_terminate(व्योम)
{
	माप_प्रकार i;

	debug3_f("terminating %zu helpers", nhelpers);
	क्रम (i = 0; i < nhelpers; i++)
		helper_terminate(helpers[i]);
}

पूर्णांक
pkcs11_sign(काष्ठा sshkey *कुंजी,
    u_char **sigp, माप_प्रकार *lenp,
    स्थिर u_char *तथ्य, माप_प्रकार datalen,
    स्थिर अक्षर *alg, स्थिर अक्षर *sk_provider,
    स्थिर अक्षर *sk_pin, u_int compat)
{
	काष्ठा sshbuf *संदेश = शून्य;
	काष्ठा helper *helper;
	पूर्णांक status, r;
	u_char *signature = शून्य;
	माप_प्रकार signature_len = 0;
	पूर्णांक ret = SSH_ERR_INTERNAL_ERROR;

	अगर (sigp != शून्य)
		*sigp = शून्य;
	अगर (lenp != शून्य)
		*lenp = 0;

	अगर ((helper = helper_by_कुंजी(कुंजी)) == शून्य || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(कुंजी));

	अगर ((संदेश = sshbuf_new()) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर ((r = sshbuf_put_u8(संदेश, SSH2_AGENTC_SIGN_REQUEST)) != 0 ||
	    (r = sshkey_puts_plain(कुंजी, संदेश)) != 0 ||
	    (r = sshbuf_put_string(संदेश, तथ्य, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, alg == शून्य ? "" : alg)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, compat)) != 0)
		fatal_fr(r, "compose");
	send_संदेश(helper->fd, संदेश);
	sshbuf_reset(संदेश);

	अगर ((status = recv_संदेश(helper->fd, संदेश)) != SSH2_AGENT_SIGN_RESPONSE) {
		/* XXX translate status to something useful */
		debug_fr(r, "recv_msg");
		ret = SSH_ERR_AGENT_FAILURE;
		जाओ fail;
	}

	अगर ((r = sshbuf_get_string(संदेश, &signature, &signature_len)) != 0)
		fatal_fr(r, "parse");

	/* success */
	अगर (sigp != शून्य) {
		*sigp = signature;
		signature = शून्य;
	}
	अगर (lenp != शून्य)
		*lenp = signature_len;
	ret = 0;

 fail:
	मुक्त(signature);
	sshbuf_free(संदेश);
	वापस ret;
}

/*
 * Make a private PKCS#11-backed certificate by grafting a previously-loaded
 * PKCS#11 private key and a public certificate key.
 */
पूर्णांक
pkcs11_make_cert(स्थिर काष्ठा sshkey *priv,
    स्थिर काष्ठा sshkey *certpub, काष्ठा sshkey **certprivp)
{
	काष्ठा helper *helper = शून्य;
	काष्ठा sshkey *ret;
	पूर्णांक r;

	अगर ((helper = helper_by_कुंजी(priv)) == शून्य || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(priv));

	debug3_f("private key type %s cert type %s on provider %s",
	    sshkey_type(priv), sshkey_type(certpub), helper->path);

	*certprivp = शून्य;
	अगर (!sshkey_is_cert(certpub) || sshkey_is_cert(priv) ||
	    !sshkey_equal_public(priv, certpub)) {
		error_f("private key %s doesn't match cert %s",
		    sshkey_type(priv), sshkey_type(certpub));
		वापस SSH_ERR_INVALID_ARGUMENT;
	}
	*certprivp = शून्य;
	अगर ((r = sshkey_from_private(priv, &ret)) != 0)
		fatal_fr(r, "copy key");

	ret->flags |= SSHKEY_FLAG_EXT;
	अगर ((r = sshkey_to_certified(ret)) != 0 ||
	    (r = sshkey_cert_copy(certpub, ret)) != 0)
		fatal_fr(r, "graft certificate");

	helper_add_कुंजी(helper, ret);

	debug3_f("provider %s: %zu remaining keys",
	    helper->path, helper->nkeyblobs);

	/* success */
	*certprivp = ret;
	वापस 0;
}

अटल काष्ठा helper *
pkcs11_start_helper(स्थिर अक्षर *path)
{
	पूर्णांक pair[2];
	अक्षर *prog, *verbosity = शून्य;
	काष्ठा helper *helper;
	pid_t pid;

	अगर (nhelpers >= पूर्णांक_उच्च)
		fatal_f("too many helpers");
	debug3_f("start helper for %s", path);
	अगर (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
		error_f("socketpair: %s", म_त्रुटि(त्रुटि_सं));
		वापस शून्य;
	}
	helper = xcalloc(1, माप(*helper));
	अगर ((pid = विभाजन()) == -1) {
		error_f("fork: %s", म_त्रुटि(त्रुटि_सं));
		बंद(pair[0]);
		बंद(pair[1]);
		मुक्त(helper);
		वापस शून्य;
	} अन्यथा अगर (pid == 0) {
		अगर ((dup2(pair[1], STDIN_FILENO) == -1) ||
		    (dup2(pair[1], STDOUT_FILENO) == -1)) {
			ख_लिखो(मानक_त्रुटि, "dup2: %s\n", म_त्रुटि(त्रुटि_सं));
			_निकास(1);
		}
		बंद(pair[0]);
		बंद(pair[1]);
		closefrom(STDERR_FILENO + 1);
		prog = दो_पर्या("SSH_PKCS11_HELPER");
		अगर (prog == शून्य || म_माप(prog) == 0)
			prog = _PATH_SSH_PKCS11_HELPER;
		अगर (log_level_get() >= SYSLOG_LEVEL_DEBUG1)
			verbosity = "-vvv";
		debug_f("starting %s %s", prog,
		    verbosity == शून्य ? "" : verbosity);
		execlp(prog, prog, verbosity, (अक्षर *)शून्य);
		ख_लिखो(मानक_त्रुटि, "exec: %s: %s\n", prog, म_त्रुटि(त्रुटि_सं));
		_निकास(1);
	}
	बंद(pair[1]);
	helper->fd = pair[0];
	helper->path = xstrdup(path);
	helper->pid = pid;
	debug3_f("helper %zu for \"%s\" on fd %d pid %ld", nhelpers,
	    helper->path, helper->fd, (दीर्घ)helper->pid);
	helpers = xrecallocarray(helpers, nhelpers,
	    nhelpers + 1, माप(*helpers));
	helpers[nhelpers++] = helper;
	वापस helper;
}

पूर्णांक
pkcs11_add_provider(अक्षर *name, अक्षर *pin, काष्ठा sshkey ***keysp,
    अक्षर ***labelsp)
{
	काष्ठा sshkey *k;
	पूर्णांक r, type;
	अक्षर *label;
	u_int ret = -1, nkeys, i;
	काष्ठा sshbuf *संदेश;
	काष्ठा helper *helper;

	अगर ((helper = helper_by_provider(name)) == शून्य &&
	    (helper = pkcs11_start_helper(name)) == शून्य)
		वापस -1;

	debug3_f("add %s", helper->path);

	अगर ((संदेश = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = sshbuf_put_u8(संदेश, SSH_AGENTC_ADD_SMARTCARD_कुंजी)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, name)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, pin)) != 0)
		fatal_fr(r, "compose");
	send_संदेश(helper->fd, संदेश);
	sshbuf_reset(संदेश);

	type = recv_संदेश(helper->fd, संदेश);
	debug3_f("response %d", type);
	अगर (type == SSH2_AGENT_IDENTITIES_ANSWER) {
		अगर ((r = sshbuf_get_u32(संदेश, &nkeys)) != 0)
			fatal_fr(r, "parse nkeys");
		debug3_f("helper return %u keys", nkeys);
		*keysp = xcalloc(nkeys, माप(काष्ठा sshkey *));
		अगर (labelsp)
			*labelsp = xcalloc(nkeys, माप(अक्षर *));
		क्रम (i = 0; i < nkeys; i++) {
			/* XXX clean up properly instead of fatal() */
			अगर ((r = sshkey_froms(संदेश, &k)) != 0 ||
			    (r = sshbuf_get_cstring(संदेश, &label, शून्य)) != 0)
				fatal_fr(r, "parse key");
			k->flags |= SSHKEY_FLAG_EXT;
			helper_add_कुंजी(helper, k);
			(*keysp)[i] = k;
			अगर (labelsp)
				(*labelsp)[i] = label;
			अन्यथा
				मुक्त(label);
		}
		/* success */
		ret = 0;
	} अन्यथा अगर (type == SSH2_AGENT_FAILURE) {
		अगर ((r = sshbuf_get_u32(संदेश, &nkeys)) != 0)
			error_fr(r, "failed to parse failure response");
	}
	अगर (ret != 0) {
		debug_f("no keys; terminate helper");
		helper_terminate(helper);
	}
	sshbuf_free(संदेश);
	वापस ret == 0 ? (पूर्णांक)nkeys : -1;
}

पूर्णांक
pkcs11_del_provider(अक्षर *name)
{
	काष्ठा helper *helper;

	/*
	 * ssh-agent deletes keys before calling this, so the helper entry
	 * should be gone before we get here.
	 */
	debug3_f("delete %s", name ? name : "(null)");
	अगर ((helper = helper_by_provider(name)) != शून्य)
		helper_terminate(helper);
	वापस 0;
}

व्योम
pkcs11_कुंजी_free(काष्ठा sshkey *कुंजी)
{
	काष्ठा helper *helper;
	काष्ठा sshbuf *keyblob = शून्य;
	माप_प्रकार i;
	पूर्णांक r, found = 0;

	debug3_f("free %s key", sshkey_type(कुंजी));

	अगर ((helper = helper_by_कुंजी(कुंजी)) == शून्य || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(कुंजी));
	अगर ((keyblob = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = sshkey_putb(कुंजी, keyblob)) != 0)
		fatal_fr(r, "serialise key");

	/* repack keys */
	क्रम (i = 0; i < helper->nkeyblobs; i++) {
		अगर (sshbuf_equals(keyblob, helper->keyblobs[i]) == 0) {
			अगर (found)
				fatal_f("key recorded more than once");
			found = 1;
		} अन्यथा अगर (found)
			helper->keyblobs[i - 1] = helper->keyblobs[i];
	}
	अगर (found) {
		helper->keyblobs = xrecallocarray(helper->keyblobs,
		    helper->nkeyblobs, helper->nkeyblobs - 1,
		    माप(*helper->keyblobs));
		helper->nkeyblobs--;
	}
	अगर (helper->nkeyblobs == 0)
		helper_terminate(helper);
}
