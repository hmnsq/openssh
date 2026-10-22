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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/time.h>
#شامل <sys/socket.h>

#شامل <stdarg.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <unistd.h>
#شامل <errno.h>
#شامل <limits.h>

#شامل "pathnames.h"
#شامل "xmalloc.h"
#شامل "sshbuf.h"
#شامل "log.h"
#شامل "misc.h"
#شامل "sshkey.h"
#شامل "authfd.h"
#شامل "atomicio.h"
#شامل "ssh-pkcs11.h"
#شامل "ssherr.h"

/* borrows code from sftp-server and ssh-agent */

/*
 * Maintain a list of ssh-pkcs11-helper subprocesses. These may be looked up
 * by provider path or their unique keyblobs.
 */
ساختار helper {
	نویسه *path;
	pid_t pid;
	صحیح fd;
	size_t nkeyblobs;
	ساختار sshbuf **keyblobs; /* XXX use a tree or something faster */
};
ایستا ساختار helper **helpers;
ایستا size_t nhelpers;

ایستا ساختار helper *
helper_by_provider(ثابت نویسه *path)
{
	size_t i;

	برای (i = 0; i < nhelpers; i++) {
		اگر (helpers[i] == پوچ || helpers[i]->path == پوچ ||
		    helpers[i]->fd == -1)
			ادامه;
		اگر (strcmp(helpers[i]->path, path) == 0)
			بازگشت helpers[i];
	}
	بازگشت پوچ;
}

ایستا ساختار helper *
helper_by_کلید(ثابت ساختار sshkey *کلید)
{
	size_t i, j;
	ساختار sshbuf *keyblob = پوچ;
	صحیح r;

	اگر ((keyblob = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshkey_putb(کلید, keyblob)) != 0)
		fatal_fr(r, "serialise key");

	برای (i = 0; i < nhelpers; i++) {
		اگر (helpers[i] == پوچ)
			ادامه;
		برای (j = 0; j < helpers[i]->nkeyblobs; j++) {
			اگر (sshbuf_equals(keyblob,
			    helpers[i]->keyblobs[j]) == 0) {
				sshbuf_free(keyblob);
				بازگشت helpers[i];
			}
		}
	}
	sshbuf_free(keyblob);
	بازگشت پوچ;

}

ایستا تهی
helper_add_کلید(ساختار helper *helper, ساختار sshkey *کلید)
{
	صحیح r;

	helper->keyblobs = xrecallocarray(helper->keyblobs, helper->nkeyblobs,
	    helper->nkeyblobs + 1, اندازه(*helper->keyblobs));
	اگر ((helper->keyblobs[helper->nkeyblobs] = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshkey_putb(کلید, helper->keyblobs[helper->nkeyblobs])) != 0)
		fatal_fr(r, "shkey_putb failed");
	helper->nkeyblobs++;
	debug3_f("added %s key for provider %s, now has %zu keys",
	    sshkey_type(کلید), helper->path, helper->nkeyblobs);
}

ایستا تهی
helper_terminate(ساختار helper *helper)
{
	size_t i;
	صحیح found = 0;

	اگر (helper == پوچ)
		بازگشت;
	اگر (helper->path == پوچ)
		fatal_f("inconsistent helper");

	debug3_f("terminating helper for %s; remaining %zu keys",
	    helper->path, helper->nkeyblobs);

	close(helper->fd);
	/* XXX waitpid() */
	helper->fd = -1;
	helper->pid = -1;

	/* repack helpers */
	برای (i = 0; i < nhelpers; i++) {
		اگر (helpers[i] == helper) {
			اگر (found)
				fatal_f("helper recorded more than once");
			found = 1;
		} وگرنه اگر (found)
			helpers[i - 1] = helpers[i];
	}
	اگر (found) {
		helpers = xrecallocarray(helpers, nhelpers,
		    nhelpers - 1, اندازه(*helpers));
		nhelpers--;
	}
	برای (i = 0; i < helper->nkeyblobs; i++)
		sshbuf_free(helper->keyblobs[i]);
	آزاد(helper->path);
	آزاد(helper);
}

ایستا تهی
send_پیام(صحیح fd, ساختار sshbuf *m)
{
	u_char buf[4];
	size_t mlen = sshbuf_len(m);
	صحیح r;

	اگر (fd == -1)
		بازگشت;
	POKE_U32(buf, mlen);
	اگر (atomicio(vwrite, fd, buf, 4) != 4 ||
	    atomicio(vwrite, fd, sshbuf_mutable_ptr(m),
	    sshbuf_len(m)) != sshbuf_len(m))
		error("write to helper failed");
	اگر ((r = sshbuf_consume(m, mlen)) != 0)
		fatal_fr(r, "consume");
}

ایستا صحیح
recv_پیام(صحیح fd, ساختار sshbuf *m)
{
	u_int l, len;
	u_char c, buf[1024];
	صحیح r;

	sshbuf_reset(m);
	اگر (fd == -1)
		بازگشت 0; /* XXX */
	اگر ((len = atomicio(اقرأ, fd, buf, 4)) != 4) {
		error("read from helper failed: %u", len);
		بازگشت (0); /* XXX */
	}
	len = PEEK_U32(buf);
	اگر (len > 256 * 1024)
		fatal("response too long: %u", len);
	/* read len bytes into m */
	وقتی (len > 0) {
		l = len;
		اگر (l > اندازه(buf))
			l = اندازه(buf);
		اگر (atomicio(اقرأ, fd, buf, l) != l) {
			error("response from helper failed.");
			بازگشت (0); /* XXX */
		}
		اگر ((r = sshbuf_put(m, buf, l)) != 0)
			fatal_fr(r, "sshbuf_put");
		len -= l;
	}
	اگر ((r = sshbuf_get_u8(m, &c)) != 0)
		fatal_fr(r, "parse type");
	بازگشت c;
}

صحیح
pkcs11_init(صحیح interactive)
{
	بازگشت 0;
}

تهی
pkcs11_terminate(تهی)
{
	size_t i;

	debug3_f("terminating %zu helpers", nhelpers);
	برای (i = 0; i < nhelpers; i++)
		helper_terminate(helpers[i]);
}

صحیح
pkcs11_sign(ساختار sshkey *کلید,
    u_char **sigp, size_t *lenp,
    ثابت u_char *data, size_t datalen,
    ثابت نویسه *alg, ثابت نویسه *sk_provider,
    ثابت نویسه *sk_pin, u_int compat)
{
	ساختار sshbuf *پیام = پوچ;
	ساختار helper *helper;
	صحیح status, r;
	u_char *signature = پوچ;
	size_t signature_len = 0;
	صحیح ret = SSH_ERR_INTERNAL_ERROR;

	اگر (sigp != پوچ)
		*sigp = پوچ;
	اگر (lenp != پوچ)
		*lenp = 0;

	اگر ((helper = helper_by_کلید(کلید)) == پوچ || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(کلید));

	اگر ((پیام = sshbuf_new()) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshbuf_put_u8(پیام, SSH2_AGENTC_SIGN_REQUEST)) != 0 ||
	    (r = sshkey_puts_plain(کلید, پیام)) != 0 ||
	    (r = sshbuf_put_string(پیام, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(پیام, alg == پوچ ? "" : alg)) != 0 ||
	    (r = sshbuf_put_u32(پیام, compat)) != 0)
		fatal_fr(r, "compose");
	send_پیام(helper->fd, پیام);
	sshbuf_reset(پیام);

	اگر ((status = recv_پیام(helper->fd, پیام)) != SSH2_AGENT_SIGN_RESPONSE) {
		/* XXX translate status to something useful */
		debug_fr(r, "recv_msg");
		ret = SSH_ERR_AGENT_FAILURE;
		برو fail;
	}

	اگر ((r = sshbuf_get_string(پیام, &signature, &signature_len)) != 0)
		fatal_fr(r, "parse");

	/* success */
	اگر (sigp != پوچ) {
		*sigp = signature;
		signature = پوچ;
	}
	اگر (lenp != پوچ)
		*lenp = signature_len;
	ret = 0;

 fail:
	آزاد(signature);
	sshbuf_free(پیام);
	بازگشت ret;
}

/*
 * Make a private PKCS#11-backed certificate by grafting a previously-loaded
 * PKCS#11 private key and a public certificate key.
 */
صحیح
pkcs11_make_cert(ثابت ساختار sshkey *priv,
    ثابت ساختار sshkey *certpub, ساختار sshkey **certprivp)
{
	ساختار helper *helper = پوچ;
	ساختار sshkey *ret;
	صحیح r;

	اگر ((helper = helper_by_کلید(priv)) == پوچ || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(priv));

	debug3_f("private key type %s cert type %s on provider %s",
	    sshkey_type(priv), sshkey_type(certpub), helper->path);

	*certprivp = پوچ;
	اگر (!sshkey_is_cert(certpub) || sshkey_is_cert(priv) ||
	    !sshkey_equal_public(priv, certpub)) {
		error_f("private key %s doesn't match cert %s",
		    sshkey_type(priv), sshkey_type(certpub));
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	}
	*certprivp = پوچ;
	اگر ((r = sshkey_from_private(priv, &ret)) != 0)
		fatal_fr(r, "copy key");

	ret->flags |= SSHKEY_FLAG_EXT;
	اگر ((r = sshkey_to_certified(ret)) != 0 ||
	    (r = sshkey_cert_copy(certpub, ret)) != 0)
		fatal_fr(r, "graft certificate");

	helper_add_کلید(helper, ret);

	debug3_f("provider %s: %zu remaining keys",
	    helper->path, helper->nkeyblobs);

	/* success */
	*certprivp = ret;
	بازگشت 0;
}

ایستا ساختار helper *
pkcs11_start_helper(ثابت نویسه *path)
{
	صحیح pair[2];
	نویسه *prog, *verbosity = پوچ;
	ساختار helper *helper;
	pid_t pid;

	اگر (nhelpers >= INT_MAX)
		fatal_f("too many helpers");
	debug3_f("start helper for %s", path);
	اگر (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
		error_f("socketpair: %s", strerror(errno));
		بازگشت پوچ;
	}
	helper = xcalloc(1, اندازه(*helper));
	اگر ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		close(pair[0]);
		close(pair[1]);
		آزاد(helper);
		بازگشت پوچ;
	} وگرنه اگر (pid == 0) {
		اگر ((dup2(pair[1], STDIN_FILENO) == -1) ||
		    (dup2(pair[1], STDOUT_FILENO) == -1)) {
			fprintf(stderr, "dup2: %s\n", strerror(errno));
			_exit(1);
		}
		close(pair[0]);
		close(pair[1]);
		closefrom(STDERR_FILENO + 1);
		prog = getenv("SSH_PKCS11_HELPER");
		اگر (prog == پوچ || strlen(prog) == 0)
			prog = _PATH_SSH_PKCS11_HELPER;
		اگر (log_level_get() >= SYSLOG_LEVEL_DEBUG1)
			verbosity = "-vvv";
		debug_f("starting %s %s", prog,
		    verbosity == پوچ ? "" : verbosity);
		execlp(prog, prog, verbosity, (نویسه *)پوچ);
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
	    nhelpers + 1, اندازه(*helpers));
	helpers[nhelpers++] = helper;
	بازگشت helper;
}

صحیح
pkcs11_add_provider(نویسه *name, نویسه *pin, ساختار sshkey ***keysp,
    نویسه ***labelsp)
{
	ساختار sshkey *k;
	صحیح r, type;
	نویسه *label;
	u_int ret = -1, nkeys, i;
	ساختار sshbuf *پیام;
	ساختار helper *helper;

	اگر ((helper = helper_by_provider(name)) == پوچ &&
	    (helper = pkcs11_start_helper(name)) == پوچ)
		بازگشت -1;

	debug3_f("add %s", helper->path);

	اگر ((پیام = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_u8(پیام, SSH_AGENTC_ADD_SMARTCARD_کلید)) != 0 ||
	    (r = sshbuf_put_cstring(پیام, name)) != 0 ||
	    (r = sshbuf_put_cstring(پیام, pin)) != 0)
		fatal_fr(r, "compose");
	send_پیام(helper->fd, پیام);
	sshbuf_reset(پیام);

	type = recv_پیام(helper->fd, پیام);
	debug3_f("response %d", type);
	اگر (type == SSH2_AGENT_IDENTITIES_ANSWER) {
		اگر ((r = sshbuf_get_u32(پیام, &nkeys)) != 0)
			fatal_fr(r, "parse nkeys");
		debug3_f("helper return %u keys", nkeys);
		*keysp = xcalloc(nkeys, اندازه(ساختار sshkey *));
		اگر (labelsp)
			*labelsp = xcalloc(nkeys, اندازه(نویسه *));
		برای (i = 0; i < nkeys; i++) {
			/* XXX clean up properly instead of fatal() */
			اگر ((r = sshkey_froms(پیام, &k)) != 0 ||
			    (r = sshbuf_get_cstring(پیام, &label, پوچ)) != 0)
				fatal_fr(r, "parse key");
			k->flags |= SSHKEY_FLAG_EXT;
			helper_add_کلید(helper, k);
			(*keysp)[i] = k;
			اگر (labelsp)
				(*labelsp)[i] = label;
			وگرنه
				آزاد(label);
		}
		/* success */
		ret = 0;
	} وگرنه اگر (type == SSH2_AGENT_FAILURE) {
		اگر ((r = sshbuf_get_u32(پیام, &nkeys)) != 0)
			error_fr(r, "failed to parse failure response");
	}
	اگر (ret != 0) {
		debug_f("no keys; terminate helper");
		helper_terminate(helper);
	}
	sshbuf_free(پیام);
	بازگشت ret == 0 ? (صحیح)nkeys : -1;
}

صحیح
pkcs11_del_provider(نویسه *name)
{
	ساختار helper *helper;

	/*
	 * ssh-agent deletes keys before calling this, so the helper entry
	 * should be gone before we get here.
	 */
	debug3_f("delete %s", name ? name : "(null)");
	اگر ((helper = helper_by_provider(name)) != پوچ)
		helper_terminate(helper);
	بازگشت 0;
}

تهی
pkcs11_کلید_free(ساختار sshkey *کلید)
{
	ساختار helper *helper;
	ساختار sshbuf *keyblob = پوچ;
	size_t i;
	صحیح r, found = 0;

	debug3_f("free %s key", sshkey_type(کلید));

	اگر ((helper = helper_by_کلید(کلید)) == پوچ || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(کلید));
	اگر ((keyblob = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshkey_putb(کلید, keyblob)) != 0)
		fatal_fr(r, "serialise key");

	/* repack keys */
	برای (i = 0; i < helper->nkeyblobs; i++) {
		اگر (sshbuf_equals(keyblob, helper->keyblobs[i]) == 0) {
			اگر (found)
				fatal_f("key recorded more than once");
			found = 1;
		} وگرنه اگر (found)
			helper->keyblobs[i - 1] = helper->keyblobs[i];
	}
	اگر (found) {
		helper->keyblobs = xrecallocarray(helper->keyblobs,
		    helper->nkeyblobs, helper->nkeyblobs - 1,
		    اندازه(*helper->keyblobs));
		helper->nkeyblobs--;
	}
	اگر (helper->nkeyblobs == 0)
		helper_terminate(helper);
}
