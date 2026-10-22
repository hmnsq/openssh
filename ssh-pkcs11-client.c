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
	वर्ण *path;
	pid_t pid;
	पूर्णाङ्क fd;
	size_t nkeyblobs;
	संरचना sshbuf **keyblobs; /* XXX use a tree or something faster */
};
स्थिर संरचना helper **helpers;
स्थिर size_t nhelpers;

स्थिर संरचना helper *
helper_by_provider(ध्रुव वर्ण *path)
{
	size_t i;

	प्रति (i = 0; i < nhelpers; i++) {
		यदि (helpers[i] == रिक्त || helpers[i]->path == रिक्त ||
		    helpers[i]->fd == -1)
			अनुवर्त;
		यदि (strcmp(helpers[i]->path, path) == 0)
			प्रत्यागम helpers[i];
	}
	प्रत्यागम रिक्त;
}

स्थिर संरचना helper *
helper_by_कुंजी(ध्रुव संरचना sshkey *कुंजी)
{
	size_t i, j;
	संरचना sshbuf *keyblob = रिक्त;
	पूर्णाङ्क r;

	यदि ((keyblob = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshkey_putb(कुंजी, keyblob)) != 0)
		fatal_fr(r, "serialise key");

	प्रति (i = 0; i < nhelpers; i++) {
		यदि (helpers[i] == रिक्त)
			अनुवर्त;
		प्रति (j = 0; j < helpers[i]->nkeyblobs; j++) {
			यदि (sshbuf_equals(keyblob,
			    helpers[i]->keyblobs[j]) == 0) {
				sshbuf_free(keyblob);
				प्रत्यागम helpers[i];
			}
		}
	}
	sshbuf_free(keyblob);
	प्रत्यागम रिक्त;

}

स्थिर शून्य
helper_add_कुंजी(संरचना helper *helper, संरचना sshkey *कुंजी)
{
	पूर्णाङ्क r;

	helper->keyblobs = xrecallocarray(helper->keyblobs, helper->nkeyblobs,
	    helper->nkeyblobs + 1, परिमाण(*helper->keyblobs));
	यदि ((helper->keyblobs[helper->nkeyblobs] = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshkey_putb(कुंजी, helper->keyblobs[helper->nkeyblobs])) != 0)
		fatal_fr(r, "shkey_putb failed");
	helper->nkeyblobs++;
	debug3_f("added %s key for provider %s, now has %zu keys",
	    sshkey_type(कुंजी), helper->path, helper->nkeyblobs);
}

स्थिर शून्य
helper_terminate(संरचना helper *helper)
{
	size_t i;
	पूर्णाङ्क found = 0;

	यदि (helper == रिक्त)
		प्रत्यागम;
	यदि (helper->path == रिक्त)
		fatal_f("inconsistent helper");

	debug3_f("terminating helper for %s; remaining %zu keys",
	    helper->path, helper->nkeyblobs);

	close(helper->fd);
	/* XXX waitpid() */
	helper->fd = -1;
	helper->pid = -1;

	/* repack helpers */
	प्रति (i = 0; i < nhelpers; i++) {
		यदि (helpers[i] == helper) {
			यदि (found)
				fatal_f("helper recorded more than once");
			found = 1;
		} अन्यथा यदि (found)
			helpers[i - 1] = helpers[i];
	}
	यदि (found) {
		helpers = xrecallocarray(helpers, nhelpers,
		    nhelpers - 1, परिमाण(*helpers));
		nhelpers--;
	}
	प्रति (i = 0; i < helper->nkeyblobs; i++)
		sshbuf_free(helper->keyblobs[i]);
	मुक्त(helper->path);
	मुक्त(helper);
}

स्थिर शून्य
send_संदेश(पूर्णाङ्क fd, संरचना sshbuf *m)
{
	u_char buf[4];
	size_t mlen = sshbuf_len(m);
	पूर्णाङ्क r;

	यदि (fd == -1)
		प्रत्यागम;
	POKE_U32(buf, mlen);
	यदि (atomicio(vwrite, fd, buf, 4) != 4 ||
	    atomicio(vwrite, fd, sshbuf_mutable_ptr(m),
	    sshbuf_len(m)) != sshbuf_len(m))
		error("write to helper failed");
	यदि ((r = sshbuf_consume(m, mlen)) != 0)
		fatal_fr(r, "consume");
}

स्थिर पूर्णाङ्क
recv_संदेश(पूर्णाङ्क fd, संरचना sshbuf *m)
{
	u_int l, len;
	u_char c, buf[1024];
	पूर्णाङ्क r;

	sshbuf_reset(m);
	यदि (fd == -1)
		प्रत्यागम 0; /* XXX */
	यदि ((len = atomicio(पठ, fd, buf, 4)) != 4) {
		error("read from helper failed: %u", len);
		प्रत्यागम (0); /* XXX */
	}
	len = PEEK_U32(buf);
	यदि (len > 256 * 1024)
		fatal("response too long: %u", len);
	/* read len bytes into m */
	यावत् (len > 0) {
		l = len;
		यदि (l > परिमाण(buf))
			l = परिमाण(buf);
		यदि (atomicio(पठ, fd, buf, l) != l) {
			error("response from helper failed.");
			प्रत्यागम (0); /* XXX */
		}
		यदि ((r = sshbuf_put(m, buf, l)) != 0)
			fatal_fr(r, "sshbuf_put");
		len -= l;
	}
	यदि ((r = sshbuf_get_u8(m, &c)) != 0)
		fatal_fr(r, "parse type");
	प्रत्यागम c;
}

पूर्णाङ्क
pkcs11_init(पूर्णाङ्क interactive)
{
	प्रत्यागम 0;
}

शून्य
pkcs11_terminate(शून्य)
{
	size_t i;

	debug3_f("terminating %zu helpers", nhelpers);
	प्रति (i = 0; i < nhelpers; i++)
		helper_terminate(helpers[i]);
}

पूर्णाङ्क
pkcs11_sign(संरचना sshkey *कुंजी,
    u_char **sigp, size_t *lenp,
    ध्रुव u_char *data, size_t datalen,
    ध्रुव वर्ण *alg, ध्रुव वर्ण *sk_provider,
    ध्रुव वर्ण *sk_pin, u_int compat)
{
	संरचना sshbuf *संदेश = रिक्त;
	संरचना helper *helper;
	पूर्णाङ्क status, r;
	u_char *signature = रिक्त;
	size_t signature_len = 0;
	पूर्णाङ्क ret = SSH_ERR_INTERNAL_ERROR;

	यदि (sigp != रिक्त)
		*sigp = रिक्त;
	यदि (lenp != रिक्त)
		*lenp = 0;

	यदि ((helper = helper_by_कुंजी(कुंजी)) == रिक्त || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(कुंजी));

	यदि ((संदेश = sshbuf_new()) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	यदि ((r = sshbuf_put_u8(संदेश, SSH2_AGENTC_SIGN_REQUEST)) != 0 ||
	    (r = sshkey_puts_plain(कुंजी, संदेश)) != 0 ||
	    (r = sshbuf_put_string(संदेश, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, alg == रिक्त ? "" : alg)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, compat)) != 0)
		fatal_fr(r, "compose");
	send_संदेश(helper->fd, संदेश);
	sshbuf_reset(संदेश);

	यदि ((status = recv_संदेश(helper->fd, संदेश)) != SSH2_AGENT_SIGN_RESPONSE) {
		/* XXX translate status to something useful */
		debug_fr(r, "recv_msg");
		ret = SSH_ERR_AGENT_FAILURE;
		गच्छ fail;
	}

	यदि ((r = sshbuf_get_string(संदेश, &signature, &signature_len)) != 0)
		fatal_fr(r, "parse");

	/* success */
	यदि (sigp != रिक्त) {
		*sigp = signature;
		signature = रिक्त;
	}
	यदि (lenp != रिक्त)
		*lenp = signature_len;
	ret = 0;

 fail:
	मुक्त(signature);
	sshbuf_free(संदेश);
	प्रत्यागम ret;
}

/*
 * Make a private PKCS#11-backed certificate by grafting a previously-loaded
 * PKCS#11 private key and a public certificate key.
 */
पूर्णाङ्क
pkcs11_make_cert(ध्रुव संरचना sshkey *priv,
    ध्रुव संरचना sshkey *certpub, संरचना sshkey **certprivp)
{
	संरचना helper *helper = रिक्त;
	संरचना sshkey *ret;
	पूर्णाङ्क r;

	यदि ((helper = helper_by_कुंजी(priv)) == रिक्त || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(priv));

	debug3_f("private key type %s cert type %s on provider %s",
	    sshkey_type(priv), sshkey_type(certpub), helper->path);

	*certprivp = रिक्त;
	यदि (!sshkey_is_cert(certpub) || sshkey_is_cert(priv) ||
	    !sshkey_equal_public(priv, certpub)) {
		error_f("private key %s doesn't match cert %s",
		    sshkey_type(priv), sshkey_type(certpub));
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;
	}
	*certprivp = रिक्त;
	यदि ((r = sshkey_from_private(priv, &ret)) != 0)
		fatal_fr(r, "copy key");

	ret->flags |= SSHKEY_FLAG_EXT;
	यदि ((r = sshkey_to_certified(ret)) != 0 ||
	    (r = sshkey_cert_copy(certpub, ret)) != 0)
		fatal_fr(r, "graft certificate");

	helper_add_कुंजी(helper, ret);

	debug3_f("provider %s: %zu remaining keys",
	    helper->path, helper->nkeyblobs);

	/* success */
	*certprivp = ret;
	प्रत्यागम 0;
}

स्थिर संरचना helper *
pkcs11_start_helper(ध्रुव वर्ण *path)
{
	पूर्णाङ्क pair[2];
	वर्ण *prog, *verbosity = रिक्त;
	संरचना helper *helper;
	pid_t pid;

	यदि (nhelpers >= INT_MAX)
		fatal_f("too many helpers");
	debug3_f("start helper for %s", path);
	यदि (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
		error_f("socketpair: %s", strerror(errno));
		प्रत्यागम रिक्त;
	}
	helper = xcalloc(1, परिमाण(*helper));
	यदि ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		close(pair[0]);
		close(pair[1]);
		मुक्त(helper);
		प्रत्यागम रिक्त;
	} अन्यथा यदि (pid == 0) {
		यदि ((dup2(pair[1], STDIN_FILENO) == -1) ||
		    (dup2(pair[1], STDOUT_FILENO) == -1)) {
			fprintf(stderr, "dup2: %s\n", strerror(errno));
			_exit(1);
		}
		close(pair[0]);
		close(pair[1]);
		closefrom(STDERR_FILENO + 1);
		prog = getenv("SSH_PKCS11_HELPER");
		यदि (prog == रिक्त || strlen(prog) == 0)
			prog = _PATH_SSH_PKCS11_HELPER;
		यदि (log_level_get() >= SYSLOG_LEVEL_DEBUG1)
			verbosity = "-vvv";
		debug_f("starting %s %s", prog,
		    verbosity == रिक्त ? "" : verbosity);
		execlp(prog, prog, verbosity, (वर्ण *)रिक्त);
		fprintf(stderr, "exec: %s: %s\n", prog, strerror(errno));
		_exit(1);
	}
	close(pair[1]);
	helper->fd = pair[0];
	helper->path = xstrdup(path);
	helper->pid = pid;
	debug3_f("helper %zu for \"%s\" on fd %d pid %ld", nhelpers,
	    helper->path, helper->fd, (long)helper->pid);
	helpers = xrecallocarray(helpers, nhelpers,
	    nhelpers + 1, परिमाण(*helpers));
	helpers[nhelpers++] = helper;
	प्रत्यागम helper;
}

पूर्णाङ्क
pkcs11_add_provider(वर्ण *name, वर्ण *pin, संरचना sshkey ***keysp,
    वर्ण ***labelsp)
{
	संरचना sshkey *k;
	पूर्णाङ्क r, type;
	वर्ण *label;
	u_int ret = -1, nkeys, i;
	संरचना sshbuf *संदेश;
	संरचना helper *helper;

	यदि ((helper = helper_by_provider(name)) == रिक्त &&
	    (helper = pkcs11_start_helper(name)) == रिक्त)
		प्रत्यागम -1;

	debug3_f("add %s", helper->path);

	यदि ((संदेश = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshbuf_put_u8(संदेश, SSH_AGENTC_ADD_SMARTCARD_कुंजी)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, name)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, pin)) != 0)
		fatal_fr(r, "compose");
	send_संदेश(helper->fd, संदेश);
	sshbuf_reset(संदेश);

	type = recv_संदेश(helper->fd, संदेश);
	debug3_f("response %d", type);
	यदि (type == SSH2_AGENT_IDENTITIES_ANSWER) {
		यदि ((r = sshbuf_get_u32(संदेश, &nkeys)) != 0)
			fatal_fr(r, "parse nkeys");
		debug3_f("helper return %u keys", nkeys);
		*keysp = xcalloc(nkeys, परिमाण(संरचना sshkey *));
		यदि (labelsp)
			*labelsp = xcalloc(nkeys, परिमाण(वर्ण *));
		प्रति (i = 0; i < nkeys; i++) {
			/* XXX clean up properly instead of fatal() */
			यदि ((r = sshkey_froms(संदेश, &k)) != 0 ||
			    (r = sshbuf_get_cstring(संदेश, &label, रिक्त)) != 0)
				fatal_fr(r, "parse key");
			k->flags |= SSHKEY_FLAG_EXT;
			helper_add_कुंजी(helper, k);
			(*keysp)[i] = k;
			यदि (labelsp)
				(*labelsp)[i] = label;
			अन्यथा
				मुक्त(label);
		}
		/* success */
		ret = 0;
	} अन्यथा यदि (type == SSH2_AGENT_FAILURE) {
		यदि ((r = sshbuf_get_u32(संदेश, &nkeys)) != 0)
			error_fr(r, "failed to parse failure response");
	}
	यदि (ret != 0) {
		debug_f("no keys; terminate helper");
		helper_terminate(helper);
	}
	sshbuf_free(संदेश);
	प्रत्यागम ret == 0 ? (पूर्णाङ्क)nkeys : -1;
}

पूर्णाङ्क
pkcs11_del_provider(वर्ण *name)
{
	संरचना helper *helper;

	/*
	 * ssh-agent deletes keys before calling this, so the helper entry
	 * should be gone before we get here.
	 */
	debug3_f("delete %s", name ? name : "(null)");
	यदि ((helper = helper_by_provider(name)) != रिक्त)
		helper_terminate(helper);
	प्रत्यागम 0;
}

शून्य
pkcs11_कुंजी_free(संरचना sshkey *कुंजी)
{
	संरचना helper *helper;
	संरचना sshbuf *keyblob = रिक्त;
	size_t i;
	पूर्णाङ्क r, found = 0;

	debug3_f("free %s key", sshkey_type(कुंजी));

	यदि ((helper = helper_by_कुंजी(कुंजी)) == रिक्त || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(कुंजी));
	यदि ((keyblob = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshkey_putb(कुंजी, keyblob)) != 0)
		fatal_fr(r, "serialise key");

	/* repack keys */
	प्रति (i = 0; i < helper->nkeyblobs; i++) {
		यदि (sshbuf_equals(keyblob, helper->keyblobs[i]) == 0) {
			यदि (found)
				fatal_f("key recorded more than once");
			found = 1;
		} अन्यथा यदि (found)
			helper->keyblobs[i - 1] = helper->keyblobs[i];
	}
	यदि (found) {
		helper->keyblobs = xrecallocarray(helper->keyblobs,
		    helper->nkeyblobs, helper->nkeyblobs - 1,
		    परिमाण(*helper->keyblobs));
		helper->nkeyblobs--;
	}
	यदि (helper->nkeyblobs == 0)
		helper_terminate(helper);
}
