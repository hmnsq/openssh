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
	ຈຳນວນເຕັມ fd;
	size_t nkeyblobs;
	sa_nracanaa sshbuf **keyblobs; /* XXX use a tree or something faster */
};
static sa_nracanaa helper **helpers;
static size_t nhelpers;

static sa_nracanaa helper *
helper_by_provider(const var_na *path)
{
	size_t i;

	ສຳລັບ (i = 0; i < nhelpers; i++) {
		ຖ້າ (helpers[i] == NULL || helpers[i]->path == NULL ||
		    helpers[i]->fd == -1)
			continue;
		ຖ້າ (strcmp(helpers[i]->path, path) == 0)
			ສົ່ງຄືນ helpers[i];
	}
	ສົ່ງຄືນ NULL;
}

static sa_nracanaa helper *
helper_by_key(const sa_nracanaa sshkey *key)
{
	size_t i, j;
	sa_nracanaa sshbuf *keyblob = NULL;
	ຈຳນວນເຕັມ r;

	ຖ້າ ((keyblob = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	ຖ້າ ((r = sshkey_putb(key, keyblob)) != 0)
		fatal_fr(r, "serialise key");

	ສຳລັບ (i = 0; i < nhelpers; i++) {
		ຖ້າ (helpers[i] == NULL)
			continue;
		ສຳລັບ (j = 0; j < helpers[i]->nkeyblobs; j++) {
			ຖ້າ (sshbuf_equals(keyblob,
			    helpers[i]->keyblobs[j]) == 0) {
				sshbuf_free(keyblob);
				ສົ່ງຄືນ helpers[i];
			}
		}
	}
	sshbuf_free(keyblob);
	ສົ່ງຄືນ NULL;

}

static void
helper_add_key(sa_nracanaa helper *helper, sa_nracanaa sshkey *key)
{
	ຈຳນວນເຕັມ r;

	helper->keyblobs = xrecallocarray(helper->keyblobs, helper->nkeyblobs,
	    helper->nkeyblobs + 1, parimaa_na(*helper->keyblobs));
	ຖ້າ ((helper->keyblobs[helper->nkeyblobs] = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	ຖ້າ ((r = sshkey_putb(key, helper->keyblobs[helper->nkeyblobs])) != 0)
		fatal_fr(r, "shkey_putb failed");
	helper->nkeyblobs++;
	debug3_f("added %s key for provider %s, now has %zu keys",
	    sshkey_type(key), helper->path, helper->nkeyblobs);
}

static void
helper_terminate(sa_nracanaa helper *helper)
{
	size_t i;
	ຈຳນວນເຕັມ found = 0;

	ຖ້າ (helper == NULL)
		ສົ່ງຄືນ;
	ຖ້າ (helper->path == NULL)
		fatal_f("inconsistent helper");

	debug3_f("terminating helper for %s; remaining %zu keys",
	    helper->path, helper->nkeyblobs);

	close(helper->fd);
	/* XXX waitpid() */
	helper->fd = -1;
	helper->pid = -1;

	/* repack helpers */
	ສຳລັບ (i = 0; i < nhelpers; i++) {
		ຖ້າ (helpers[i] == helper) {
			ຖ້າ (found)
				fatal_f("helper recorded more than once");
			found = 1;
		} ບໍ່ດັ່ງນັ້ນ ຖ້າ (found)
			helpers[i - 1] = helpers[i];
	}
	ຖ້າ (found) {
		helpers = xrecallocarray(helpers, nhelpers,
		    nhelpers - 1, parimaa_na(*helpers));
		nhelpers--;
	}
	ສຳລັບ (i = 0; i < helper->nkeyblobs; i++)
		sshbuf_free(helper->keyblobs[i]);
	free(helper->path);
	free(helper);
}

static void
send_msg(ຈຳນວນເຕັມ fd, sa_nracanaa sshbuf *m)
{
	u_char buf[4];
	size_t mlen = sshbuf_len(m);
	ຈຳນວນເຕັມ r;

	ຖ້າ (fd == -1)
		ສົ່ງຄືນ;
	POKE_U32(buf, mlen);
	ຖ້າ (atomicio(vwrite, fd, buf, 4) != 4 ||
	    atomicio(vwrite, fd, sshbuf_mutable_ptr(m),
	    sshbuf_len(m)) != sshbuf_len(m))
		error("write to helper failed");
	ຖ້າ ((r = sshbuf_consume(m, mlen)) != 0)
		fatal_fr(r, "consume");
}

static ຈຳນວນເຕັມ
recv_msg(ຈຳນວນເຕັມ fd, sa_nracanaa sshbuf *m)
{
	u_int l, len;
	u_char c, buf[1024];
	ຈຳນວນເຕັມ r;

	sshbuf_reset(m);
	ຖ້າ (fd == -1)
		ສົ່ງຄືນ 0; /* XXX */
	ຖ້າ ((len = atomicio(read, fd, buf, 4)) != 4) {
		error("read from helper failed: %u", len);
		ສົ່ງຄືນ (0); /* XXX */
	}
	len = PEEK_U32(buf);
	ຖ້າ (len > 256 * 1024)
		fatal("response too long: %u", len);
	/* read len bytes into m */
	ໃນຂະນະທີ່ (len > 0) {
		l = len;
		ຖ້າ (l > parimaa_na(buf))
			l = parimaa_na(buf);
		ຖ້າ (atomicio(read, fd, buf, l) != l) {
			error("response from helper failed.");
			ສົ່ງຄືນ (0); /* XXX */
		}
		ຖ້າ ((r = sshbuf_put(m, buf, l)) != 0)
			fatal_fr(r, "sshbuf_put");
		len -= l;
	}
	ຖ້າ ((r = sshbuf_get_u8(m, &c)) != 0)
		fatal_fr(r, "parse type");
	ສົ່ງຄືນ c;
}

ຈຳນວນເຕັມ
pkcs11_init(ຈຳນວນເຕັມ interactive)
{
	ສົ່ງຄືນ 0;
}

void
pkcs11_terminate(void)
{
	size_t i;

	debug3_f("terminating %zu helpers", nhelpers);
	ສຳລັບ (i = 0; i < nhelpers; i++)
		helper_terminate(helpers[i]);
}

ຈຳນວນເຕັມ
pkcs11_sign(sa_nracanaa sshkey *key,
    u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen,
    const var_na *alg, const var_na *sk_provider,
    const var_na *sk_pin, u_int compat)
{
	sa_nracanaa sshbuf *msg = NULL;
	sa_nracanaa helper *helper;
	ຈຳນວນເຕັມ status, r;
	u_char *signature = NULL;
	size_t signature_len = 0;
	ຈຳນວນເຕັມ ret = SSH_ERR_INTERNAL_ERROR;

	ຖ້າ (sigp != NULL)
		*sigp = NULL;
	ຖ້າ (lenp != NULL)
		*lenp = 0;

	ຖ້າ ((helper = helper_by_key(key)) == NULL || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(key));

	ຖ້າ ((msg = sshbuf_new()) == NULL)
		ສົ່ງຄືນ SSH_ERR_ALLOC_FAIL;
	ຖ້າ ((r = sshbuf_put_u8(msg, SSH2_AGENTC_SIGN_REQUEST)) != 0 ||
	    (r = sshkey_puts_plain(key, msg)) != 0 ||
	    (r = sshbuf_put_string(msg, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(msg, alg == NULL ? "" : alg)) != 0 ||
	    (r = sshbuf_put_u32(msg, compat)) != 0)
		fatal_fr(r, "compose");
	send_msg(helper->fd, msg);
	sshbuf_reset(msg);

	ຖ້າ ((status = recv_msg(helper->fd, msg)) != SSH2_AGENT_SIGN_RESPONSE) {
		/* XXX translate status to something useful */
		debug_fr(r, "recv_msg");
		ret = SSH_ERR_AGENT_FAILURE;
		goto fail;
	}

	ຖ້າ ((r = sshbuf_get_string(msg, &signature, &signature_len)) != 0)
		fatal_fr(r, "parse");

	/* success */
	ຖ້າ (sigp != NULL) {
		*sigp = signature;
		signature = NULL;
	}
	ຖ້າ (lenp != NULL)
		*lenp = signature_len;
	ret = 0;

 fail:
	free(signature);
	sshbuf_free(msg);
	ສົ່ງຄືນ ret;
}

/*
 * Make a private PKCS#11-backed certificate by grafting a previously-loaded
 * PKCS#11 private key and a public certificate key.
 */
ຈຳນວນເຕັມ
pkcs11_make_cert(const sa_nracanaa sshkey *priv,
    const sa_nracanaa sshkey *certpub, sa_nracanaa sshkey **certprivp)
{
	sa_nracanaa helper *helper = NULL;
	sa_nracanaa sshkey *ret;
	ຈຳນວນເຕັມ r;

	ຖ້າ ((helper = helper_by_key(priv)) == NULL || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(priv));

	debug3_f("private key type %s cert type %s on provider %s",
	    sshkey_type(priv), sshkey_type(certpub), helper->path);

	*certprivp = NULL;
	ຖ້າ (!sshkey_is_cert(certpub) || sshkey_is_cert(priv) ||
	    !sshkey_equal_public(priv, certpub)) {
		error_f("private key %s doesn't match cert %s",
		    sshkey_type(priv), sshkey_type(certpub));
		ສົ່ງຄືນ SSH_ERR_INVALID_ARGUMENT;
	}
	*certprivp = NULL;
	ຖ້າ ((r = sshkey_from_private(priv, &ret)) != 0)
		fatal_fr(r, "copy key");

	ret->flags |= SSHKEY_FLAG_EXT;
	ຖ້າ ((r = sshkey_to_certified(ret)) != 0 ||
	    (r = sshkey_cert_copy(certpub, ret)) != 0)
		fatal_fr(r, "graft certificate");

	helper_add_key(helper, ret);

	debug3_f("provider %s: %zu remaining keys",
	    helper->path, helper->nkeyblobs);

	/* success */
	*certprivp = ret;
	ສົ່ງຄືນ 0;
}

static sa_nracanaa helper *
pkcs11_start_helper(const var_na *path)
{
	ຈຳນວນເຕັມ pair[2];
	var_na *prog, *verbosity = NULL;
	sa_nracanaa helper *helper;
	pid_t pid;

	ຖ້າ (nhelpers >= INT_MAX)
		fatal_f("too many helpers");
	debug3_f("start helper for %s", path);
	ຖ້າ (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
		error_f("socketpair: %s", strerror(errno));
		ສົ່ງຄືນ NULL;
	}
	helper = xcalloc(1, parimaa_na(*helper));
	ຖ້າ ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		close(pair[0]);
		close(pair[1]);
		free(helper);
		ສົ່ງຄືນ NULL;
	} ບໍ່ດັ່ງນັ້ນ ຖ້າ (pid == 0) {
		ຖ້າ ((dup2(pair[1], STDIN_FILENO) == -1) ||
		    (dup2(pair[1], STDOUT_FILENO) == -1)) {
			fprintf(stderr, "dup2: %s\n", strerror(errno));
			_exit(1);
		}
		close(pair[0]);
		close(pair[1]);
		closefrom(STDERR_FILENO + 1);
		prog = getenv("SSH_PKCS11_HELPER");
		ຖ້າ (prog == NULL || strlen(prog) == 0)
			prog = _PATH_SSH_PKCS11_HELPER;
		ຖ້າ (log_level_get() >= SYSLOG_LEVEL_DEBUG1)
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
	ສົ່ງຄືນ helper;
}

ຈຳນວນເຕັມ
pkcs11_add_provider(var_na *name, var_na *pin, sa_nracanaa sshkey ***keysp,
    var_na ***labelsp)
{
	sa_nracanaa sshkey *k;
	ຈຳນວນເຕັມ r, type;
	var_na *label;
	u_int ret = -1, nkeys, i;
	sa_nracanaa sshbuf *msg;
	sa_nracanaa helper *helper;

	ຖ້າ ((helper = helper_by_provider(name)) == NULL &&
	    (helper = pkcs11_start_helper(name)) == NULL)
		ສົ່ງຄືນ -1;

	debug3_f("add %s", helper->path);

	ຖ້າ ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	ຖ້າ ((r = sshbuf_put_u8(msg, SSH_AGENTC_ADD_SMARTCARD_KEY)) != 0 ||
	    (r = sshbuf_put_cstring(msg, name)) != 0 ||
	    (r = sshbuf_put_cstring(msg, pin)) != 0)
		fatal_fr(r, "compose");
	send_msg(helper->fd, msg);
	sshbuf_reset(msg);

	type = recv_msg(helper->fd, msg);
	debug3_f("response %d", type);
	ຖ້າ (type == SSH2_AGENT_IDENTITIES_ANSWER) {
		ຖ້າ ((r = sshbuf_get_u32(msg, &nkeys)) != 0)
			fatal_fr(r, "parse nkeys");
		debug3_f("helper return %u keys", nkeys);
		*keysp = xcalloc(nkeys, parimaa_na(sa_nracanaa sshkey *));
		ຖ້າ (labelsp)
			*labelsp = xcalloc(nkeys, parimaa_na(var_na *));
		ສຳລັບ (i = 0; i < nkeys; i++) {
			/* XXX clean up properly instead of fatal() */
			ຖ້າ ((r = sshkey_froms(msg, &k)) != 0 ||
			    (r = sshbuf_get_cstring(msg, &label, NULL)) != 0)
				fatal_fr(r, "parse key");
			k->flags |= SSHKEY_FLAG_EXT;
			helper_add_key(helper, k);
			(*keysp)[i] = k;
			ຖ້າ (labelsp)
				(*labelsp)[i] = label;
			ບໍ່ດັ່ງນັ້ນ
				free(label);
		}
		/* success */
		ret = 0;
	} ບໍ່ດັ່ງນັ້ນ ຖ້າ (type == SSH2_AGENT_FAILURE) {
		ຖ້າ ((r = sshbuf_get_u32(msg, &nkeys)) != 0)
			error_fr(r, "failed to parse failure response");
	}
	ຖ້າ (ret != 0) {
		debug_f("no keys; terminate helper");
		helper_terminate(helper);
	}
	sshbuf_free(msg);
	ສົ່ງຄືນ ret == 0 ? (ຈຳນວນເຕັມ)nkeys : -1;
}

ຈຳນວນເຕັມ
pkcs11_del_provider(var_na *name)
{
	sa_nracanaa helper *helper;

	/*
	 * ssh-agent deletes keys before calling this, so the helper entry
	 * should be gone before we get here.
	 */
	debug3_f("delete %s", name ? name : "(null)");
	ຖ້າ ((helper = helper_by_provider(name)) != NULL)
		helper_terminate(helper);
	ສົ່ງຄືນ 0;
}

void
pkcs11_key_free(sa_nracanaa sshkey *key)
{
	sa_nracanaa helper *helper;
	sa_nracanaa sshbuf *keyblob = NULL;
	size_t i;
	ຈຳນວນເຕັມ r, found = 0;

	debug3_f("free %s key", sshkey_type(key));

	ຖ້າ ((helper = helper_by_key(key)) == NULL || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(key));
	ຖ້າ ((keyblob = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	ຖ້າ ((r = sshkey_putb(key, keyblob)) != 0)
		fatal_fr(r, "serialise key");

	/* repack keys */
	ສຳລັບ (i = 0; i < helper->nkeyblobs; i++) {
		ຖ້າ (sshbuf_equals(keyblob, helper->keyblobs[i]) == 0) {
			ຖ້າ (found)
				fatal_f("key recorded more than once");
			found = 1;
		} ບໍ່ດັ່ງນັ້ນ ຖ້າ (found)
			helper->keyblobs[i - 1] = helper->keyblobs[i];
	}
	ຖ້າ (found) {
		helper->keyblobs = xrecallocarray(helper->keyblobs,
		    helper->nkeyblobs, helper->nkeyblobs - 1,
		    parimaa_na(*helper->keyblobs));
		helper->nkeyblobs--;
	}
	ຖ້າ (helper->nkeyblobs == 0)
		helper_terminate(helper);
}
