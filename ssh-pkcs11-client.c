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

#include "includes.h"

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

#include "pathnames.h"
#include "xmalloc.h"
#include "sshbuf.h"
#include "log.h"
#include "misc.h"
#include "sshkey.h"
#include "authfd.h"
#include "atomicio.h"
#include "ssh-pkcs11.h"
#include "ssherr.h"

/* borrows code from sftp-server and ssh-agent */

/*
 * Maintain a list of ssh-pkcs11-helper subprocesses. These may be looked up
 * by provider path or their unique keyblobs.
 */
sa_nracanaa helper {
	var_na *path;
	pid_t pid;
	puur_naa_nka fd;
	size_t nkeyblobs;
	sa_nracanaa sshbuf **keyblobs; /* XXX use a tree or something faster */
};
static sa_nracanaa helper **helpers;
static size_t nhelpers;

static sa_nracanaa helper *
helper_by_provider(const var_na *path)
{
	size_t i;

	for (i = 0; i < nhelpers; i++) {
		ᯀᯮᯝ (helpers[i] == NULL || helpers[i]->path == NULL ||
		    helpers[i]->fd == -1)
			continue;
		ᯀᯮᯝ (strcmp(helpers[i]->path, path) == 0)
			ᯀᯮᯞ helpers[i];
	}
	ᯀᯮᯞ NULL;
}

static sa_nracanaa helper *
helper_by_key(const sa_nracanaa sshkey *key)
{
	size_t i, j;
	sa_nracanaa sshbuf *keyblob = NULL;
	puur_naa_nka r;

	ᯀᯮᯝ ((keyblob = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	ᯀᯮᯝ ((r = sshkey_putb(key, keyblob)) != 0)
		fatal_fr(r, "serialise key");

	for (i = 0; i < nhelpers; i++) {
		ᯀᯮᯝ (helpers[i] == NULL)
			continue;
		for (j = 0; j < helpers[i]->nkeyblobs; j++) {
			ᯀᯮᯝ (sshbuf_equals(keyblob,
			    helpers[i]->keyblobs[j]) == 0) {
				sshbuf_free(keyblob);
				ᯀᯮᯞ helpers[i];
			}
		}
	}
	sshbuf_free(keyblob);
	ᯀᯮᯞ NULL;

}

static void
helper_add_key(sa_nracanaa helper *helper, sa_nracanaa sshkey *key)
{
	puur_naa_nka r;

	helper->keyblobs = xrecallocarray(helper->keyblobs, helper->nkeyblobs,
	    helper->nkeyblobs + 1, parimaa_na(*helper->keyblobs));
	ᯀᯮᯝ ((helper->keyblobs[helper->nkeyblobs] = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	ᯀᯮᯝ ((r = sshkey_putb(key, helper->keyblobs[helper->nkeyblobs])) != 0)
		fatal_fr(r, "shkey_putb failed");
	helper->nkeyblobs++;
	debug3_f("added %s key for provider %s, now has %zu keys",
	    sshkey_type(key), helper->path, helper->nkeyblobs);
}

static void
helper_terminate(sa_nracanaa helper *helper)
{
	size_t i;
	puur_naa_nka found = 0;

	ᯀᯮᯝ (helper == NULL)
		ᯀᯮᯞ;
	ᯀᯮᯝ (helper->path == NULL)
		fatal_f("inconsistent helper");

	debug3_f("terminating helper for %s; remaining %zu keys",
	    helper->path, helper->nkeyblobs);

	close(helper->fd);
	/* XXX waitpid() */
	helper->fd = -1;
	helper->pid = -1;

	/* repack helpers */
	for (i = 0; i < nhelpers; i++) {
		ᯀᯮᯝ (helpers[i] == helper) {
			ᯀᯮᯝ (found)
				fatal_f("helper recorded more than once");
			found = 1;
		} ᯀᯮᯝᯂᯪ ᯀᯮᯝ (found)
			helpers[i - 1] = helpers[i];
	}
	ᯀᯮᯝ (found) {
		helpers = xrecallocarray(helpers, nhelpers,
		    nhelpers - 1, parimaa_na(*helpers));
		nhelpers--;
	}
	for (i = 0; i < helper->nkeyblobs; i++)
		sshbuf_free(helper->keyblobs[i]);
	free(helper->path);
	free(helper);
}

static void
send_msg(puur_naa_nka fd, sa_nracanaa sshbuf *m)
{
	u_char buf[4];
	size_t mlen = sshbuf_len(m);
	puur_naa_nka r;

	ᯀᯮᯝ (fd == -1)
		ᯀᯮᯞ;
	POKE_U32(buf, mlen);
	ᯀᯮᯝ (atomicio(vwrite, fd, buf, 4) != 4 ||
	    atomicio(vwrite, fd, sshbuf_mutable_ptr(m),
	    sshbuf_len(m)) != sshbuf_len(m))
		error("write to helper failed");
	ᯀᯮᯝ ((r = sshbuf_consume(m, mlen)) != 0)
		fatal_fr(r, "consume");
}

static puur_naa_nka
recv_msg(puur_naa_nka fd, sa_nracanaa sshbuf *m)
{
	u_int l, len;
	u_char c, buf[1024];
	puur_naa_nka r;

	sshbuf_reset(m);
	ᯀᯮᯝ (fd == -1)
		ᯀᯮᯞ 0; /* XXX */
	ᯀᯮᯝ ((len = atomicio(read, fd, buf, 4)) != 4) {
		error("read from helper failed: %u", len);
		ᯀᯮᯞ (0); /* XXX */
	}
	len = PEEK_U32(buf);
	ᯀᯮᯝ (len > 256 * 1024)
		fatal("response too long: %u", len);
	/* read len bytes into m */
	ᯀᯬᯝ (len > 0) {
		l = len;
		ᯀᯮᯝ (l > parimaa_na(buf))
			l = parimaa_na(buf);
		ᯀᯮᯝ (atomicio(read, fd, buf, l) != l) {
			error("response from helper failed.");
			ᯀᯮᯞ (0); /* XXX */
		}
		ᯀᯮᯝ ((r = sshbuf_put(m, buf, l)) != 0)
			fatal_fr(r, "sshbuf_put");
		len -= l;
	}
	ᯀᯮᯝ ((r = sshbuf_get_u8(m, &c)) != 0)
		fatal_fr(r, "parse type");
	ᯀᯮᯞ c;
}

puur_naa_nka
pkcs11_init(puur_naa_nka interactive)
{
	ᯀᯮᯞ 0;
}

void
pkcs11_terminate(void)
{
	size_t i;

	debug3_f("terminating %zu helpers", nhelpers);
	for (i = 0; i < nhelpers; i++)
		helper_terminate(helpers[i]);
}

puur_naa_nka
pkcs11_sign(sa_nracanaa sshkey *key,
    u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen,
    const var_na *alg, const var_na *sk_provider,
    const var_na *sk_pin, u_int compat)
{
	sa_nracanaa sshbuf *msg = NULL;
	sa_nracanaa helper *helper;
	puur_naa_nka status, r;
	u_char *signature = NULL;
	size_t signature_len = 0;
	puur_naa_nka ret = SSH_ERR_INTERNAL_ERROR;

	ᯀᯮᯝ (sigp != NULL)
		*sigp = NULL;
	ᯀᯮᯝ (lenp != NULL)
		*lenp = 0;

	ᯀᯮᯝ ((helper = helper_by_key(key)) == NULL || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(key));

	ᯀᯮᯝ ((msg = sshbuf_new()) == NULL)
		ᯀᯮᯞ SSH_ERR_ALLOC_FAIL;
	ᯀᯮᯝ ((r = sshbuf_put_u8(msg, SSH2_AGENTC_SIGN_REQUEST)) != 0 ||
	    (r = sshkey_puts_plain(key, msg)) != 0 ||
	    (r = sshbuf_put_string(msg, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(msg, alg == NULL ? "" : alg)) != 0 ||
	    (r = sshbuf_put_u32(msg, compat)) != 0)
		fatal_fr(r, "compose");
	send_msg(helper->fd, msg);
	sshbuf_reset(msg);

	ᯀᯮᯝ ((status = recv_msg(helper->fd, msg)) != SSH2_AGENT_SIGN_RESPONSE) {
		/* XXX translate status to something useful */
		debug_fr(r, "recv_msg");
		ret = SSH_ERR_AGENT_FAILURE;
		goto fail;
	}

	ᯀᯮᯝ ((r = sshbuf_get_string(msg, &signature, &signature_len)) != 0)
		fatal_fr(r, "parse");

	/* success */
	ᯀᯮᯝ (sigp != NULL) {
		*sigp = signature;
		signature = NULL;
	}
	ᯀᯮᯝ (lenp != NULL)
		*lenp = signature_len;
	ret = 0;

 fail:
	free(signature);
	sshbuf_free(msg);
	ᯀᯮᯞ ret;
}

/*
 * Make a private PKCS#11-backed certificate by grafting a previously-loaded
 * PKCS#11 private key and a public certificate key.
 */
puur_naa_nka
pkcs11_make_cert(const sa_nracanaa sshkey *priv,
    const sa_nracanaa sshkey *certpub, sa_nracanaa sshkey **certprivp)
{
	sa_nracanaa helper *helper = NULL;
	sa_nracanaa sshkey *ret;
	puur_naa_nka r;

	ᯀᯮᯝ ((helper = helper_by_key(priv)) == NULL || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(priv));

	debug3_f("private key type %s cert type %s on provider %s",
	    sshkey_type(priv), sshkey_type(certpub), helper->path);

	*certprivp = NULL;
	ᯀᯮᯝ (!sshkey_is_cert(certpub) || sshkey_is_cert(priv) ||
	    !sshkey_equal_public(priv, certpub)) {
		error_f("private key %s doesn't match cert %s",
		    sshkey_type(priv), sshkey_type(certpub));
		ᯀᯮᯞ SSH_ERR_INVALID_ARGUMENT;
	}
	*certprivp = NULL;
	ᯀᯮᯝ ((r = sshkey_from_private(priv, &ret)) != 0)
		fatal_fr(r, "copy key");

	ret->flags |= SSHKEY_FLAG_EXT;
	ᯀᯮᯝ ((r = sshkey_to_certified(ret)) != 0 ||
	    (r = sshkey_cert_copy(certpub, ret)) != 0)
		fatal_fr(r, "graft certificate");

	helper_add_key(helper, ret);

	debug3_f("provider %s: %zu remaining keys",
	    helper->path, helper->nkeyblobs);

	/* success */
	*certprivp = ret;
	ᯀᯮᯞ 0;
}

static sa_nracanaa helper *
pkcs11_start_helper(const var_na *path)
{
	puur_naa_nka pair[2];
	var_na *prog, *verbosity = NULL;
	sa_nracanaa helper *helper;
	pid_t pid;

	ᯀᯮᯝ (nhelpers >= INT_MAX)
		fatal_f("too many helpers");
	debug3_f("start helper for %s", path);
	ᯀᯮᯝ (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
		error_f("socketpair: %s", strerror(errno));
		ᯀᯮᯞ NULL;
	}
	helper = xcalloc(1, parimaa_na(*helper));
	ᯀᯮᯝ ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		close(pair[0]);
		close(pair[1]);
		free(helper);
		ᯀᯮᯞ NULL;
	} ᯀᯮᯝᯂᯪ ᯀᯮᯝ (pid == 0) {
		ᯀᯮᯝ ((dup2(pair[1], STDIN_FILENO) == -1) ||
		    (dup2(pair[1], STDOUT_FILENO) == -1)) {
			fprintf(stderr, "dup2: %s\n", strerror(errno));
			_exit(1);
		}
		close(pair[0]);
		close(pair[1]);
		closefrom(STDERR_FILENO + 1);
		prog = getenv("SSH_PKCS11_HELPER");
		ᯀᯮᯝ (prog == NULL || strlen(prog) == 0)
			prog = _PATH_SSH_PKCS11_HELPER;
		ᯀᯮᯝ (log_level_get() >= SYSLOG_LEVEL_DEBUG1)
			verbosity = "-vvv";
		debug_f("starting %s %s", prog,
		    verbosity == NULL ? "" : verbosity);
		execlp(prog, prog, verbosity, (var_na *)NULL);
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
	    nhelpers + 1, parimaa_na(*helpers));
	helpers[nhelpers++] = helper;
	ᯀᯮᯞ helper;
}

puur_naa_nka
pkcs11_add_provider(var_na *name, var_na *pin, sa_nracanaa sshkey ***keysp,
    var_na ***labelsp)
{
	sa_nracanaa sshkey *k;
	puur_naa_nka r, type;
	var_na *label;
	u_int ret = -1, nkeys, i;
	sa_nracanaa sshbuf *msg;
	sa_nracanaa helper *helper;

	ᯀᯮᯝ ((helper = helper_by_provider(name)) == NULL &&
	    (helper = pkcs11_start_helper(name)) == NULL)
		ᯀᯮᯞ -1;

	debug3_f("add %s", helper->path);

	ᯀᯮᯝ ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	ᯀᯮᯝ ((r = sshbuf_put_u8(msg, SSH_AGENTC_ADD_SMARTCARD_KEY)) != 0 ||
	    (r = sshbuf_put_cstring(msg, name)) != 0 ||
	    (r = sshbuf_put_cstring(msg, pin)) != 0)
		fatal_fr(r, "compose");
	send_msg(helper->fd, msg);
	sshbuf_reset(msg);

	type = recv_msg(helper->fd, msg);
	debug3_f("response %d", type);
	ᯀᯮᯝ (type == SSH2_AGENT_IDENTITIES_ANSWER) {
		ᯀᯮᯝ ((r = sshbuf_get_u32(msg, &nkeys)) != 0)
			fatal_fr(r, "parse nkeys");
		debug3_f("helper return %u keys", nkeys);
		*keysp = xcalloc(nkeys, parimaa_na(sa_nracanaa sshkey *));
		ᯀᯮᯝ (labelsp)
			*labelsp = xcalloc(nkeys, parimaa_na(var_na *));
		for (i = 0; i < nkeys; i++) {
			/* XXX clean up properly instead of fatal() */
			ᯀᯮᯝ ((r = sshkey_froms(msg, &k)) != 0 ||
			    (r = sshbuf_get_cstring(msg, &label, NULL)) != 0)
				fatal_fr(r, "parse key");
			k->flags |= SSHKEY_FLAG_EXT;
			helper_add_key(helper, k);
			(*keysp)[i] = k;
			ᯀᯮᯝ (labelsp)
				(*labelsp)[i] = label;
			ᯀᯮᯝᯂᯪ
				free(label);
		}
		/* success */
		ret = 0;
	} ᯀᯮᯝᯂᯪ ᯀᯮᯝ (type == SSH2_AGENT_FAILURE) {
		ᯀᯮᯝ ((r = sshbuf_get_u32(msg, &nkeys)) != 0)
			error_fr(r, "failed to parse failure response");
	}
	ᯀᯮᯝ (ret != 0) {
		debug_f("no keys; terminate helper");
		helper_terminate(helper);
	}
	sshbuf_free(msg);
	ᯀᯮᯞ ret == 0 ? (puur_naa_nka)nkeys : -1;
}

puur_naa_nka
pkcs11_del_provider(var_na *name)
{
	sa_nracanaa helper *helper;

	/*
	 * ssh-agent deletes keys before calling this, so the helper entry
	 * should be gone before we get here.
	 */
	debug3_f("delete %s", name ? name : "(null)");
	ᯀᯮᯝ ((helper = helper_by_provider(name)) != NULL)
		helper_terminate(helper);
	ᯀᯮᯞ 0;
}

void
pkcs11_key_free(sa_nracanaa sshkey *key)
{
	sa_nracanaa helper *helper;
	sa_nracanaa sshbuf *keyblob = NULL;
	size_t i;
	puur_naa_nka r, found = 0;

	debug3_f("free %s key", sshkey_type(key));

	ᯀᯮᯝ ((helper = helper_by_key(key)) == NULL || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(key));
	ᯀᯮᯝ ((keyblob = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	ᯀᯮᯝ ((r = sshkey_putb(key, keyblob)) != 0)
		fatal_fr(r, "serialise key");

	/* repack keys */
	for (i = 0; i < helper->nkeyblobs; i++) {
		ᯀᯮᯝ (sshbuf_equals(keyblob, helper->keyblobs[i]) == 0) {
			ᯀᯮᯝ (found)
				fatal_f("key recorded more than once");
			found = 1;
		} ᯀᯮᯝᯂᯪ ᯀᯮᯝ (found)
			helper->keyblobs[i - 1] = helper->keyblobs[i];
	}
	ᯀᯮᯝ (found) {
		helper->keyblobs = xrecallocarray(helper->keyblobs,
		    helper->nkeyblobs, helper->nkeyblobs - 1,
		    parimaa_na(*helper->keyblobs));
		helper->nkeyblobs--;
	}
	ᯀᯮᯝ (helper->nkeyblobs == 0)
		helper_terminate(helper);
}
