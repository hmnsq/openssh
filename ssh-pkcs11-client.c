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
struct helper {
	char *path;
	pid_t pid;
	ціле fd;
	size_t nkeyblobs;
	struct sshbuf **keyblobs; /* XXX use a tree or something faster */
};
static struct helper **helpers;
static size_t nhelpers;

static struct helper *
helper_by_provider(const char *path)
{
	size_t i;

	для (i = 0; i < nhelpers; i++) {
		якщо (helpers[i] == NULL || helpers[i]->path == NULL ||
		    helpers[i]->fd == -1)
			continue;
		якщо (strcmp(helpers[i]->path, path) == 0)
			повернути helpers[i];
	}
	повернути NULL;
}

static struct helper *
helper_by_key(const struct sshkey *key)
{
	size_t i, j;
	struct sshbuf *keyblob = NULL;
	ціле r;

	якщо ((keyblob = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	якщо ((r = sshkey_putb(key, keyblob)) != 0)
		fatal_fr(r, "serialise key");

	для (i = 0; i < nhelpers; i++) {
		якщо (helpers[i] == NULL)
			continue;
		для (j = 0; j < helpers[i]->nkeyblobs; j++) {
			якщо (sshbuf_equals(keyblob,
			    helpers[i]->keyblobs[j]) == 0) {
				sshbuf_free(keyblob);
				повернути helpers[i];
			}
		}
	}
	sshbuf_free(keyblob);
	повернути NULL;

}

static void
helper_add_key(struct helper *helper, struct sshkey *key)
{
	ціле r;

	helper->keyblobs = xrecallocarray(helper->keyblobs, helper->nkeyblobs,
	    helper->nkeyblobs + 1, sizeof(*helper->keyblobs));
	якщо ((helper->keyblobs[helper->nkeyblobs] = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	якщо ((r = sshkey_putb(key, helper->keyblobs[helper->nkeyblobs])) != 0)
		fatal_fr(r, "shkey_putb failed");
	helper->nkeyblobs++;
	debug3_f("added %s key for provider %s, now has %zu keys",
	    sshkey_type(key), helper->path, helper->nkeyblobs);
}

static void
helper_terminate(struct helper *helper)
{
	size_t i;
	ціле found = 0;

	якщо (helper == NULL)
		повернути;
	якщо (helper->path == NULL)
		fatal_f("inconsistent helper");

	debug3_f("terminating helper for %s; remaining %zu keys",
	    helper->path, helper->nkeyblobs);

	close(helper->fd);
	/* XXX waitpid() */
	helper->fd = -1;
	helper->pid = -1;

	/* repack helpers */
	для (i = 0; i < nhelpers; i++) {
		якщо (helpers[i] == helper) {
			якщо (found)
				fatal_f("helper recorded more than once");
			found = 1;
		} інакше якщо (found)
			helpers[i - 1] = helpers[i];
	}
	якщо (found) {
		helpers = xrecallocarray(helpers, nhelpers,
		    nhelpers - 1, sizeof(*helpers));
		nhelpers--;
	}
	для (i = 0; i < helper->nkeyblobs; i++)
		sshbuf_free(helper->keyblobs[i]);
	free(helper->path);
	free(helper);
}

static void
send_msg(ціле fd, struct sshbuf *m)
{
	u_char buf[4];
	size_t mlen = sshbuf_len(m);
	ціле r;

	якщо (fd == -1)
		повернути;
	POKE_U32(buf, mlen);
	якщо (atomicio(vwrite, fd, buf, 4) != 4 ||
	    atomicio(vwrite, fd, sshbuf_mutable_ptr(m),
	    sshbuf_len(m)) != sshbuf_len(m))
		error("write to helper failed");
	якщо ((r = sshbuf_consume(m, mlen)) != 0)
		fatal_fr(r, "consume");
}

static ціле
recv_msg(ціле fd, struct sshbuf *m)
{
	u_int l, len;
	u_char c, buf[1024];
	ціле r;

	sshbuf_reset(m);
	якщо (fd == -1)
		повернути 0; /* XXX */
	якщо ((len = atomicio(read, fd, buf, 4)) != 4) {
		error("read from helper failed: %u", len);
		повернути (0); /* XXX */
	}
	len = PEEK_U32(buf);
	якщо (len > 256 * 1024)
		fatal("response too long: %u", len);
	/* read len bytes into m */
	поки (len > 0) {
		l = len;
		якщо (l > sizeof(buf))
			l = sizeof(buf);
		якщо (atomicio(read, fd, buf, l) != l) {
			error("response from helper failed.");
			повернути (0); /* XXX */
		}
		якщо ((r = sshbuf_put(m, buf, l)) != 0)
			fatal_fr(r, "sshbuf_put");
		len -= l;
	}
	якщо ((r = sshbuf_get_u8(m, &c)) != 0)
		fatal_fr(r, "parse type");
	повернути c;
}

ціле
pkcs11_init(ціле interactive)
{
	повернути 0;
}

void
pkcs11_terminate(void)
{
	size_t i;

	debug3_f("terminating %zu helpers", nhelpers);
	для (i = 0; i < nhelpers; i++)
		helper_terminate(helpers[i]);
}

ціле
pkcs11_sign(struct sshkey *key,
    u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen,
    const char *alg, const char *sk_provider,
    const char *sk_pin, u_int compat)
{
	struct sshbuf *msg = NULL;
	struct helper *helper;
	ціле status, r;
	u_char *signature = NULL;
	size_t signature_len = 0;
	ціле ret = SSH_ERR_INTERNAL_ERROR;

	якщо (sigp != NULL)
		*sigp = NULL;
	якщо (lenp != NULL)
		*lenp = 0;

	якщо ((helper = helper_by_key(key)) == NULL || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(key));

	якщо ((msg = sshbuf_new()) == NULL)
		повернути SSH_ERR_ALLOC_FAIL;
	якщо ((r = sshbuf_put_u8(msg, SSH2_AGENTC_SIGN_REQUEST)) != 0 ||
	    (r = sshkey_puts_plain(key, msg)) != 0 ||
	    (r = sshbuf_put_string(msg, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(msg, alg == NULL ? "" : alg)) != 0 ||
	    (r = sshbuf_put_u32(msg, compat)) != 0)
		fatal_fr(r, "compose");
	send_msg(helper->fd, msg);
	sshbuf_reset(msg);

	якщо ((status = recv_msg(helper->fd, msg)) != SSH2_AGENT_SIGN_RESPONSE) {
		/* XXX translate status to something useful */
		debug_fr(r, "recv_msg");
		ret = SSH_ERR_AGENT_FAILURE;
		goto fail;
	}

	якщо ((r = sshbuf_get_string(msg, &signature, &signature_len)) != 0)
		fatal_fr(r, "parse");

	/* success */
	якщо (sigp != NULL) {
		*sigp = signature;
		signature = NULL;
	}
	якщо (lenp != NULL)
		*lenp = signature_len;
	ret = 0;

 fail:
	free(signature);
	sshbuf_free(msg);
	повернути ret;
}

/*
 * Make a private PKCS#11-backed certificate by grafting a previously-loaded
 * PKCS#11 private key and a public certificate key.
 */
ціле
pkcs11_make_cert(const struct sshkey *priv,
    const struct sshkey *certpub, struct sshkey **certprivp)
{
	struct helper *helper = NULL;
	struct sshkey *ret;
	ціле r;

	якщо ((helper = helper_by_key(priv)) == NULL || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(priv));

	debug3_f("private key type %s cert type %s on provider %s",
	    sshkey_type(priv), sshkey_type(certpub), helper->path);

	*certprivp = NULL;
	якщо (!sshkey_is_cert(certpub) || sshkey_is_cert(priv) ||
	    !sshkey_equal_public(priv, certpub)) {
		error_f("private key %s doesn't match cert %s",
		    sshkey_type(priv), sshkey_type(certpub));
		повернути SSH_ERR_INVALID_ARGUMENT;
	}
	*certprivp = NULL;
	якщо ((r = sshkey_from_private(priv, &ret)) != 0)
		fatal_fr(r, "copy key");

	ret->flags |= SSHKEY_FLAG_EXT;
	якщо ((r = sshkey_to_certified(ret)) != 0 ||
	    (r = sshkey_cert_copy(certpub, ret)) != 0)
		fatal_fr(r, "graft certificate");

	helper_add_key(helper, ret);

	debug3_f("provider %s: %zu remaining keys",
	    helper->path, helper->nkeyblobs);

	/* success */
	*certprivp = ret;
	повернути 0;
}

static struct helper *
pkcs11_start_helper(const char *path)
{
	ціле pair[2];
	char *prog, *verbosity = NULL;
	struct helper *helper;
	pid_t pid;

	якщо (nhelpers >= INT_MAX)
		fatal_f("too many helpers");
	debug3_f("start helper for %s", path);
	якщо (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
		error_f("socketpair: %s", strerror(errno));
		повернути NULL;
	}
	helper = xcalloc(1, sizeof(*helper));
	якщо ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		close(pair[0]);
		close(pair[1]);
		free(helper);
		повернути NULL;
	} інакше якщо (pid == 0) {
		якщо ((dup2(pair[1], STDIN_FILENO) == -1) ||
		    (dup2(pair[1], STDOUT_FILENO) == -1)) {
			fprintf(stderr, "dup2: %s\n", strerror(errno));
			_exit(1);
		}
		close(pair[0]);
		close(pair[1]);
		closefrom(STDERR_FILENO + 1);
		prog = getenv("SSH_PKCS11_HELPER");
		якщо (prog == NULL || strlen(prog) == 0)
			prog = _PATH_SSH_PKCS11_HELPER;
		якщо (log_level_get() >= SYSLOG_LEVEL_DEBUG1)
			verbosity = "-vvv";
		debug_f("starting %s %s", prog,
		    verbosity == NULL ? "" : verbosity);
		execlp(prog, prog, verbosity, (char *)NULL);
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
	    nhelpers + 1, sizeof(*helpers));
	helpers[nhelpers++] = helper;
	повернути helper;
}

ціле
pkcs11_add_provider(char *name, char *pin, struct sshkey ***keysp,
    char ***labelsp)
{
	struct sshkey *k;
	ціле r, type;
	char *label;
	u_int ret = -1, nkeys, i;
	struct sshbuf *msg;
	struct helper *helper;

	якщо ((helper = helper_by_provider(name)) == NULL &&
	    (helper = pkcs11_start_helper(name)) == NULL)
		повернути -1;

	debug3_f("add %s", helper->path);

	якщо ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	якщо ((r = sshbuf_put_u8(msg, SSH_AGENTC_ADD_SMARTCARD_KEY)) != 0 ||
	    (r = sshbuf_put_cstring(msg, name)) != 0 ||
	    (r = sshbuf_put_cstring(msg, pin)) != 0)
		fatal_fr(r, "compose");
	send_msg(helper->fd, msg);
	sshbuf_reset(msg);

	type = recv_msg(helper->fd, msg);
	debug3_f("response %d", type);
	якщо (type == SSH2_AGENT_IDENTITIES_ANSWER) {
		якщо ((r = sshbuf_get_u32(msg, &nkeys)) != 0)
			fatal_fr(r, "parse nkeys");
		debug3_f("helper return %u keys", nkeys);
		*keysp = xcalloc(nkeys, sizeof(struct sshkey *));
		якщо (labelsp)
			*labelsp = xcalloc(nkeys, sizeof(char *));
		для (i = 0; i < nkeys; i++) {
			/* XXX clean up properly instead of fatal() */
			якщо ((r = sshkey_froms(msg, &k)) != 0 ||
			    (r = sshbuf_get_cstring(msg, &label, NULL)) != 0)
				fatal_fr(r, "parse key");
			k->flags |= SSHKEY_FLAG_EXT;
			helper_add_key(helper, k);
			(*keysp)[i] = k;
			якщо (labelsp)
				(*labelsp)[i] = label;
			інакше
				free(label);
		}
		/* success */
		ret = 0;
	} інакше якщо (type == SSH2_AGENT_FAILURE) {
		якщо ((r = sshbuf_get_u32(msg, &nkeys)) != 0)
			error_fr(r, "failed to parse failure response");
	}
	якщо (ret != 0) {
		debug_f("no keys; terminate helper");
		helper_terminate(helper);
	}
	sshbuf_free(msg);
	повернути ret == 0 ? (ціле)nkeys : -1;
}

ціле
pkcs11_del_provider(char *name)
{
	struct helper *helper;

	/*
	 * ssh-agent deletes keys before calling this, so the helper entry
	 * should be gone before we get here.
	 */
	debug3_f("delete %s", name ? name : "(null)");
	якщо ((helper = helper_by_provider(name)) != NULL)
		helper_terminate(helper);
	повернути 0;
}

void
pkcs11_key_free(struct sshkey *key)
{
	struct helper *helper;
	struct sshbuf *keyblob = NULL;
	size_t i;
	ціле r, found = 0;

	debug3_f("free %s key", sshkey_type(key));

	якщо ((helper = helper_by_key(key)) == NULL || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(key));
	якщо ((keyblob = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	якщо ((r = sshkey_putb(key, keyblob)) != 0)
		fatal_fr(r, "serialise key");

	/* repack keys */
	для (i = 0; i < helper->nkeyblobs; i++) {
		якщо (sshbuf_equals(keyblob, helper->keyblobs[i]) == 0) {
			якщо (found)
				fatal_f("key recorded more than once");
			found = 1;
		} інакше якщо (found)
			helper->keyblobs[i - 1] = helper->keyblobs[i];
	}
	якщо (found) {
		helper->keyblobs = xrecallocarray(helper->keyblobs,
		    helper->nkeyblobs, helper->nkeyblobs - 1,
		    sizeof(*helper->keyblobs));
		helper->nkeyblobs--;
	}
	якщо (helper->nkeyblobs == 0)
		helper_terminate(helper);
}
