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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/time.h>
#ضمن <sys/socket.h>

#ضمن <stdarg.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <unistd.h>
#ضمن <errno.h>
#ضمن <limits.h>

#ضمن "pathnames.h"
#ضمن "xmalloc.h"
#ضمن "sshbuf.h"
#ضمن "log.h"
#ضمن "misc.h"
#ضمن "sshkey.h"
#ضمن "authfd.h"
#ضمن "atomicio.h"
#ضمن "ssh-pkcs11.h"
#ضمن "ssherr.h"

/* borrows code from sftp-server and ssh-agent */

/*
 * Maintain a list of ssh-pkcs11-helper subprocesses. These may be looked up
 * by provider path or their unique keyblobs.
 */
بنية helper {
	حرف *path;
	pid_t pid;
	صحيح fd;
	size_t nkeyblobs;
	بنية sshbuf **keyblobs; /* XXX use a tree or something faster */
};
ساكن بنية helper **helpers;
ساكن size_t nhelpers;

ساكن بنية helper *
helper_by_provider(ثابت حرف *path)
{
	size_t i;

	עבור (i = 0; i < nhelpers; i++) {
		אם (helpers[i] == عدم || helpers[i]->path == عدم ||
		    helpers[i]->fd == -1)
			استمر;
		אם (strcmp(helpers[i]->path, path) == 0)
			החזר helpers[i];
	}
	החזר عدم;
}

ساكن بنية helper *
helper_by_key(ثابت بنية sshkey *key)
{
	size_t i, j;
	بنية sshbuf *keyblob = عدم;
	صحيح r;

	אם ((keyblob = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	אם ((r = sshkey_putb(key, keyblob)) != 0)
		fatal_fr(r, "serialise key");

	עבור (i = 0; i < nhelpers; i++) {
		אם (helpers[i] == عدم)
			استمر;
		עבור (j = 0; j < helpers[i]->nkeyblobs; j++) {
			אם (sshbuf_equals(keyblob,
			    helpers[i]->keyblobs[j]) == 0) {
				sshbuf_free(keyblob);
				החזר helpers[i];
			}
		}
	}
	sshbuf_free(keyblob);
	החזר عدم;

}

ساكن فراغ
helper_add_key(بنية helper *helper, بنية sshkey *key)
{
	صحيح r;

	helper->keyblobs = xrecallocarray(helper->keyblobs, helper->nkeyblobs,
	    helper->nkeyblobs + 1, حجم(*helper->keyblobs));
	אם ((helper->keyblobs[helper->nkeyblobs] = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	אם ((r = sshkey_putb(key, helper->keyblobs[helper->nkeyblobs])) != 0)
		fatal_fr(r, "shkey_putb failed");
	helper->nkeyblobs++;
	debug3_f("added %s key for provider %s, now has %zu keys",
	    sshkey_type(key), helper->path, helper->nkeyblobs);
}

ساكن فراغ
helper_terminate(بنية helper *helper)
{
	size_t i;
	صحيح found = 0;

	אם (helper == عدم)
		החזר;
	אם (helper->path == عدم)
		fatal_f("inconsistent helper");

	debug3_f("terminating helper for %s; remaining %zu keys",
	    helper->path, helper->nkeyblobs);

	close(helper->fd);
	/* XXX waitpid() */
	helper->fd = -1;
	helper->pid = -1;

	/* repack helpers */
	עבור (i = 0; i < nhelpers; i++) {
		אם (helpers[i] == helper) {
			אם (found)
				fatal_f("helper recorded more than once");
			found = 1;
		} אחרת אם (found)
			helpers[i - 1] = helpers[i];
	}
	אם (found) {
		helpers = xrecallocarray(helpers, nhelpers,
		    nhelpers - 1, حجم(*helpers));
		nhelpers--;
	}
	עבור (i = 0; i < helper->nkeyblobs; i++)
		sshbuf_free(helper->keyblobs[i]);
	حرر(helper->path);
	حرر(helper);
}

ساكن فراغ
send_msg(صحيح fd, بنية sshbuf *m)
{
	u_char buf[4];
	size_t mlen = sshbuf_len(m);
	صحيح r;

	אם (fd == -1)
		החזר;
	POKE_U32(buf, mlen);
	אם (atomicio(vwrite, fd, buf, 4) != 4 ||
	    atomicio(vwrite, fd, sshbuf_mutable_ptr(m),
	    sshbuf_len(m)) != sshbuf_len(m))
		error("write to helper failed");
	אם ((r = sshbuf_consume(m, mlen)) != 0)
		fatal_fr(r, "consume");
}

ساكن صحيح
recv_msg(صحيح fd, بنية sshbuf *m)
{
	u_int l, len;
	u_char c, buf[1024];
	صحيح r;

	sshbuf_reset(m);
	אם (fd == -1)
		החזר 0; /* XXX */
	אם ((len = atomicio(اقرأ, fd, buf, 4)) != 4) {
		error("read from helper failed: %u", len);
		החזר (0); /* XXX */
	}
	len = PEEK_U32(buf);
	אם (len > 256 * 1024)
		fatal("response too long: %u", len);
	/* read len bytes into m */
	כלעוד (len > 0) {
		l = len;
		אם (l > حجم(buf))
			l = حجم(buf);
		אם (atomicio(اقرأ, fd, buf, l) != l) {
			error("response from helper failed.");
			החזר (0); /* XXX */
		}
		אם ((r = sshbuf_put(m, buf, l)) != 0)
			fatal_fr(r, "sshbuf_put");
		len -= l;
	}
	אם ((r = sshbuf_get_u8(m, &c)) != 0)
		fatal_fr(r, "parse type");
	החזר c;
}

صحيح
pkcs11_init(صحيح interactive)
{
	החזר 0;
}

فراغ
pkcs11_terminate(فراغ)
{
	size_t i;

	debug3_f("terminating %zu helpers", nhelpers);
	עבור (i = 0; i < nhelpers; i++)
		helper_terminate(helpers[i]);
}

صحيح
pkcs11_sign(بنية sshkey *key,
    u_char **sigp, size_t *lenp,
    ثابت u_char *data, size_t datalen,
    ثابت حرف *alg, ثابت حرف *sk_provider,
    ثابت حرف *sk_pin, u_int compat)
{
	بنية sshbuf *msg = عدم;
	بنية helper *helper;
	صحيح status, r;
	u_char *signature = عدم;
	size_t signature_len = 0;
	صحيح ret = SSH_ERR_INTERNAL_ERROR;

	אם (sigp != عدم)
		*sigp = عدم;
	אם (lenp != عدم)
		*lenp = 0;

	אם ((helper = helper_by_key(key)) == عدم || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(key));

	אם ((msg = sshbuf_new()) == عدم)
		החזר SSH_ERR_ALLOC_FAIL;
	אם ((r = sshbuf_put_u8(msg, SSH2_AGENTC_SIGN_REQUEST)) != 0 ||
	    (r = sshkey_puts_plain(key, msg)) != 0 ||
	    (r = sshbuf_put_string(msg, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(msg, alg == عدم ? "" : alg)) != 0 ||
	    (r = sshbuf_put_u32(msg, compat)) != 0)
		fatal_fr(r, "compose");
	send_msg(helper->fd, msg);
	sshbuf_reset(msg);

	אם ((status = recv_msg(helper->fd, msg)) != SSH2_AGENT_SIGN_RESPONSE) {
		/* XXX translate status to something useful */
		debug_fr(r, "recv_msg");
		ret = SSH_ERR_AGENT_FAILURE;
		اذهب fail;
	}

	אם ((r = sshbuf_get_string(msg, &signature, &signature_len)) != 0)
		fatal_fr(r, "parse");

	/* success */
	אם (sigp != عدم) {
		*sigp = signature;
		signature = عدم;
	}
	אם (lenp != عدم)
		*lenp = signature_len;
	ret = 0;

 fail:
	حرر(signature);
	sshbuf_free(msg);
	החזר ret;
}

/*
 * Make a private PKCS#11-backed certificate by grafting a previously-loaded
 * PKCS#11 private key and a public certificate key.
 */
صحيح
pkcs11_make_cert(ثابت بنية sshkey *priv,
    ثابت بنية sshkey *certpub, بنية sshkey **certprivp)
{
	بنية helper *helper = عدم;
	بنية sshkey *ret;
	صحيح r;

	אם ((helper = helper_by_key(priv)) == عدم || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(priv));

	debug3_f("private key type %s cert type %s on provider %s",
	    sshkey_type(priv), sshkey_type(certpub), helper->path);

	*certprivp = عدم;
	אם (!sshkey_is_cert(certpub) || sshkey_is_cert(priv) ||
	    !sshkey_equal_public(priv, certpub)) {
		error_f("private key %s doesn't match cert %s",
		    sshkey_type(priv), sshkey_type(certpub));
		החזר SSH_ERR_INVALID_ARGUMENT;
	}
	*certprivp = عدم;
	אם ((r = sshkey_from_private(priv, &ret)) != 0)
		fatal_fr(r, "copy key");

	ret->flags |= SSHKEY_FLAG_EXT;
	אם ((r = sshkey_to_certified(ret)) != 0 ||
	    (r = sshkey_cert_copy(certpub, ret)) != 0)
		fatal_fr(r, "graft certificate");

	helper_add_key(helper, ret);

	debug3_f("provider %s: %zu remaining keys",
	    helper->path, helper->nkeyblobs);

	/* success */
	*certprivp = ret;
	החזר 0;
}

ساكن بنية helper *
pkcs11_start_helper(ثابت حرف *path)
{
	صحيح pair[2];
	حرف *prog, *verbosity = عدم;
	بنية helper *helper;
	pid_t pid;

	אם (nhelpers >= INT_MAX)
		fatal_f("too many helpers");
	debug3_f("start helper for %s", path);
	אם (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
		error_f("socketpair: %s", strerror(errno));
		החזר عدم;
	}
	helper = xcalloc(1, حجم(*helper));
	אם ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		close(pair[0]);
		close(pair[1]);
		حرر(helper);
		החזר عدم;
	} אחרת אם (pid == 0) {
		אם ((dup2(pair[1], STDIN_FILENO) == -1) ||
		    (dup2(pair[1], STDOUT_FILENO) == -1)) {
			fprintf(stderr, "dup2: %s\n", strerror(errno));
			_exit(1);
		}
		close(pair[0]);
		close(pair[1]);
		closefrom(STDERR_FILENO + 1);
		prog = getenv("SSH_PKCS11_HELPER");
		אם (prog == عدم || strlen(prog) == 0)
			prog = _PATH_SSH_PKCS11_HELPER;
		אם (log_level_get() >= SYSLOG_LEVEL_DEBUG1)
			verbosity = "-vvv";
		debug_f("starting %s %s", prog,
		    verbosity == عدم ? "" : verbosity);
		execlp(prog, prog, verbosity, (حرف *)عدم);
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
	    nhelpers + 1, حجم(*helpers));
	helpers[nhelpers++] = helper;
	החזר helper;
}

صحيح
pkcs11_add_provider(حرف *name, حرف *pin, بنية sshkey ***keysp,
    حرف ***labelsp)
{
	بنية sshkey *k;
	صحيح r, type;
	حرف *label;
	u_int ret = -1, nkeys, i;
	بنية sshbuf *msg;
	بنية helper *helper;

	אם ((helper = helper_by_provider(name)) == عدم &&
	    (helper = pkcs11_start_helper(name)) == عدم)
		החזר -1;

	debug3_f("add %s", helper->path);

	אם ((msg = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	אם ((r = sshbuf_put_u8(msg, SSH_AGENTC_ADD_SMARTCARD_KEY)) != 0 ||
	    (r = sshbuf_put_cstring(msg, name)) != 0 ||
	    (r = sshbuf_put_cstring(msg, pin)) != 0)
		fatal_fr(r, "compose");
	send_msg(helper->fd, msg);
	sshbuf_reset(msg);

	type = recv_msg(helper->fd, msg);
	debug3_f("response %d", type);
	אם (type == SSH2_AGENT_IDENTITIES_ANSWER) {
		אם ((r = sshbuf_get_u32(msg, &nkeys)) != 0)
			fatal_fr(r, "parse nkeys");
		debug3_f("helper return %u keys", nkeys);
		*keysp = xcalloc(nkeys, حجم(بنية sshkey *));
		אם (labelsp)
			*labelsp = xcalloc(nkeys, حجم(حرف *));
		עבור (i = 0; i < nkeys; i++) {
			/* XXX clean up properly instead of fatal() */
			אם ((r = sshkey_froms(msg, &k)) != 0 ||
			    (r = sshbuf_get_cstring(msg, &label, عدم)) != 0)
				fatal_fr(r, "parse key");
			k->flags |= SSHKEY_FLAG_EXT;
			helper_add_key(helper, k);
			(*keysp)[i] = k;
			אם (labelsp)
				(*labelsp)[i] = label;
			אחרת
				حرر(label);
		}
		/* success */
		ret = 0;
	} אחרת אם (type == SSH2_AGENT_FAILURE) {
		אם ((r = sshbuf_get_u32(msg, &nkeys)) != 0)
			error_fr(r, "failed to parse failure response");
	}
	אם (ret != 0) {
		debug_f("no keys; terminate helper");
		helper_terminate(helper);
	}
	sshbuf_free(msg);
	החזר ret == 0 ? (صحيح)nkeys : -1;
}

صحيح
pkcs11_del_provider(حرف *name)
{
	بنية helper *helper;

	/*
	 * ssh-agent deletes keys before calling this, so the helper entry
	 * should be gone before we get here.
	 */
	debug3_f("delete %s", name ? name : "(null)");
	אם ((helper = helper_by_provider(name)) != عدم)
		helper_terminate(helper);
	החזר 0;
}

فراغ
pkcs11_key_free(بنية sshkey *key)
{
	بنية helper *helper;
	بنية sshbuf *keyblob = عدم;
	size_t i;
	صحيح r, found = 0;

	debug3_f("free %s key", sshkey_type(key));

	אם ((helper = helper_by_key(key)) == عدم || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(key));
	אם ((keyblob = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	אם ((r = sshkey_putb(key, keyblob)) != 0)
		fatal_fr(r, "serialise key");

	/* repack keys */
	עבור (i = 0; i < helper->nkeyblobs; i++) {
		אם (sshbuf_equals(keyblob, helper->keyblobs[i]) == 0) {
			אם (found)
				fatal_f("key recorded more than once");
			found = 1;
		} אחרת אם (found)
			helper->keyblobs[i - 1] = helper->keyblobs[i];
	}
	אם (found) {
		helper->keyblobs = xrecallocarray(helper->keyblobs,
		    helper->nkeyblobs, helper->nkeyblobs - 1,
		    حجم(*helper->keyblobs));
		helper->nkeyblobs--;
	}
	אם (helper->nkeyblobs == 0)
		helper_terminate(helper);
}
