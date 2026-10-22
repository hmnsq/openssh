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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/time.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "pathnames.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "authfd.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "atomicio.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh-pkcs11.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"

/* borrows code from sftp-server and ssh-agent */

/*
 * Maintain a list of ssh-pkcs11-helper subprocesses. These may be looked up
 * by provider path or their unique keyblobs.
 */
ਬਣਤਰ helper {
	ਅੱਖਰ *ਰਸਤਾ;
	pid_t pid;
	ਪੂਰਨ fd;
	ਮਾਪ_t nkeyblobs;
	ਬਣਤਰ sshbuf **keyblobs; /* XXX use a tree or something faster */
};
ਸਥਿਰ ਬਣਤਰ helper **helpers;
ਸਥਿਰ ਮਾਪ_t nhelpers;

ਸਥਿਰ ਬਣਤਰ helper *
helper_by_provider(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ)
{
	ਮਾਪ_t i;

	ਲਈ (i = 0; i < nhelpers; i++) {
		ਜੇ (helpers[i] == ਨਿਰਾ || helpers[i]->ਰਸਤਾ == ਨਿਰਾ ||
		    helpers[i]->fd == -1)
			ਜਾਰੀ;
		ਜੇ (strcmp(helpers[i]->ਰਸਤਾ, ਰਸਤਾ) == 0)
			ਵਾਪਸ helpers[i];
	}
	ਵਾਪਸ ਨਿਰਾ;
}

ਸਥਿਰ ਬਣਤਰ helper *
helper_by_ਕੁੰਜੀ(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	ਮਾਪ_t i, j;
	ਬਣਤਰ sshbuf *keyblob = ਨਿਰਾ;
	ਪੂਰਨ r;

	ਜੇ ((keyblob = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = sshkey_putb(ਕੁੰਜੀ, keyblob)) != 0)
		fatal_fr(r, "serialise key");

	ਲਈ (i = 0; i < nhelpers; i++) {
		ਜੇ (helpers[i] == ਨਿਰਾ)
			ਜਾਰੀ;
		ਲਈ (j = 0; j < helpers[i]->nkeyblobs; j++) {
			ਜੇ (sshbuf_equals(keyblob,
			    helpers[i]->keyblobs[j]) == 0) {
				sshbuf_free(keyblob);
				ਵਾਪਸ helpers[i];
			}
		}
	}
	sshbuf_free(keyblob);
	ਵਾਪਸ ਨਿਰਾ;

}

ਸਥਿਰ ਖਾਲੀ
helper_ਜੋੜੋ_ਕੁੰਜੀ(ਬਣਤਰ helper *helper, ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	ਪੂਰਨ r;

	helper->keyblobs = xrecallocarray(helper->keyblobs, helper->nkeyblobs,
	    helper->nkeyblobs + 1, ਆਕਾਰ(*helper->keyblobs));
	ਜੇ ((helper->keyblobs[helper->nkeyblobs] = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = sshkey_putb(ਕੁੰਜੀ, helper->keyblobs[helper->nkeyblobs])) != 0)
		fatal_fr(r, "shkey_putb failed");
	helper->nkeyblobs++;
	debug3_f("added %s key for provider %s, now has %zu keys",
	    sshkey_type(ਕੁੰਜੀ), helper->ਰਸਤਾ, helper->nkeyblobs);
}

ਸਥਿਰ ਖਾਲੀ
helper_terminate(ਬਣਤਰ helper *helper)
{
	ਮਾਪ_t i;
	ਪੂਰਨ ਮਿਲਿਆ = 0;

	ਜੇ (helper == ਨਿਰਾ)
		ਵਾਪਸ;
	ਜੇ (helper->ਰਸਤਾ == ਨਿਰਾ)
		fatal_f("inconsistent helper");

	debug3_f("terminating helper for %s; remaining %zu keys",
	    helper->ਰਸਤਾ, helper->nkeyblobs);

	close(helper->fd);
	/* XXX waitpid() */
	helper->fd = -1;
	helper->pid = -1;

	/* repack helpers */
	ਲਈ (i = 0; i < nhelpers; i++) {
		ਜੇ (helpers[i] == helper) {
			ਜੇ (ਮਿਲਿਆ)
				fatal_f("helper recorded more than once");
			ਮਿਲਿਆ = 1;
		} ਨਹੀਂਤਾਂ ਜੇ (ਮਿਲਿਆ)
			helpers[i - 1] = helpers[i];
	}
	ਜੇ (ਮਿਲਿਆ) {
		helpers = xrecallocarray(helpers, nhelpers,
		    nhelpers - 1, ਆਕਾਰ(*helpers));
		nhelpers--;
	}
	ਲਈ (i = 0; i < helper->nkeyblobs; i++)
		sshbuf_free(helper->keyblobs[i]);
	ਮੁਕਤ(helper->ਰਸਤਾ);
	ਮੁਕਤ(helper);
}

ਸਥਿਰ ਖਾਲੀ
send_ਸੁਨੇਹਾ(ਪੂਰਨ fd, ਬਣਤਰ sshbuf *m)
{
	u_char buf[4];
	ਮਾਪ_t mlen = sshbuf_len(m);
	ਪੂਰਨ r;

	ਜੇ (fd == -1)
		ਵਾਪਸ;
	POKE_U32(buf, mlen);
	ਜੇ (atomicio(vwrite, fd, buf, 4) != 4 ||
	    atomicio(vwrite, fd, sshbuf_mutable_ptr(m),
	    sshbuf_len(m)) != sshbuf_len(m))
		error("write to helper failed");
	ਜੇ ((r = sshbuf_consume(m, mlen)) != 0)
		fatal_fr(r, "consume");
}

ਸਥਿਰ ਪੂਰਨ
recv_ਸੁਨੇਹਾ(ਪੂਰਨ fd, ਬਣਤਰ sshbuf *m)
{
	u_int l, len;
	u_char c, buf[1024];
	ਪੂਰਨ r;

	sshbuf_reset(m);
	ਜੇ (fd == -1)
		ਵਾਪਸ 0; /* XXX */
	ਜੇ ((len = atomicio(ਪਠ, fd, buf, 4)) != 4) {
		error("read from helper failed: %u", len);
		ਵਾਪਸ (0); /* XXX */
	}
	len = PEEK_U32(buf);
	ਜੇ (len > 256 * 1024)
		fatal("response too long: %u", len);
	/* read len bytes into m */
	ਜਦੋਂ (len > 0) {
		l = len;
		ਜੇ (l > ਆਕਾਰ(buf))
			l = ਆਕਾਰ(buf);
		ਜੇ (atomicio(ਪਠ, fd, buf, l) != l) {
			error("response from helper failed.");
			ਵਾਪਸ (0); /* XXX */
		}
		ਜੇ ((r = sshbuf_put(m, buf, l)) != 0)
			fatal_fr(r, "sshbuf_put");
		len -= l;
	}
	ਜੇ ((r = sshbuf_get_u8(m, &c)) != 0)
		fatal_fr(r, "parse type");
	ਵਾਪਸ c;
}

ਪੂਰਨ
pkcs11_init(ਪੂਰਨ interactive)
{
	ਵਾਪਸ 0;
}

ਖਾਲੀ
pkcs11_terminate(ਖਾਲੀ)
{
	ਮਾਪ_t i;

	debug3_f("terminating %zu helpers", nhelpers);
	ਲਈ (i = 0; i < nhelpers; i++)
		helper_terminate(helpers[i]);
}

ਪੂਰਨ
pkcs11_sign(ਬਣਤਰ sshkey *ਕੁੰਜੀ,
    u_char **sigp, ਮਾਪ_t *lenp,
    ਅਚਲ u_char *ਅੰਕੜੇ, ਮਾਪ_t datalen,
    ਅਚਲ ਅੱਖਰ *alg, ਅਚਲ ਅੱਖਰ *sk_provider,
    ਅਚਲ ਅੱਖਰ *sk_pin, u_int compat)
{
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ = ਨਿਰਾ;
	ਬਣਤਰ helper *helper;
	ਪੂਰਨ ਸਥਿਤੀ, r;
	u_char *signature = ਨਿਰਾ;
	ਮਾਪ_t signature_len = 0;
	ਪੂਰਨ ret = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

	ਜੇ (sigp != ਨਿਰਾ)
		*sigp = ਨਿਰਾ;
	ਜੇ (lenp != ਨਿਰਾ)
		*lenp = 0;

	ਜੇ ((helper = helper_by_ਕੁੰਜੀ(ਕੁੰਜੀ)) == ਨਿਰਾ || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(ਕੁੰਜੀ));

	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, SSH2_AGENTC_SIGN_REQUEST)) != 0 ||
	    (r = sshkey_puts_plain(ਕੁੰਜੀ, ਸੁਨੇਹਾ)) != 0 ||
	    (r = sshbuf_put_string(ਸੁਨੇਹਾ, ਅੰਕੜੇ, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(ਸੁਨੇਹਾ, alg == ਨਿਰਾ ? "" : alg)) != 0 ||
	    (r = sshbuf_put_u32(ਸੁਨੇਹਾ, compat)) != 0)
		fatal_fr(r, "compose");
	send_ਸੁਨੇਹਾ(helper->fd, ਸੁਨੇਹਾ);
	sshbuf_reset(ਸੁਨੇਹਾ);

	ਜੇ ((ਸਥਿਤੀ = recv_ਸੁਨੇਹਾ(helper->fd, ਸੁਨੇਹਾ)) != SSH2_AGENT_SIGN_RESPONSE) {
		/* XXX translate status to something useful */
		debug_fr(r, "recv_msg");
		ret = SSH_ERR_AGENT_FAILURE;
		ਜਾਓ fail;
	}

	ਜੇ ((r = sshbuf_get_string(ਸੁਨੇਹਾ, &signature, &signature_len)) != 0)
		fatal_fr(r, "parse");

	/* success */
	ਜੇ (sigp != ਨਿਰਾ) {
		*sigp = signature;
		signature = ਨਿਰਾ;
	}
	ਜੇ (lenp != ਨਿਰਾ)
		*lenp = signature_len;
	ret = 0;

 fail:
	ਮੁਕਤ(signature);
	sshbuf_free(ਸੁਨੇਹਾ);
	ਵਾਪਸ ret;
}

/*
 * Make a private PKCS#11-backed certificate by grafting a previously-loaded
 * PKCS#11 private key and a public certificate key.
 */
ਪੂਰਨ
pkcs11_make_cert(ਅਚਲ ਬਣਤਰ sshkey *priv,
    ਅਚਲ ਬਣਤਰ sshkey *certpub, ਬਣਤਰ sshkey **certprivp)
{
	ਬਣਤਰ helper *helper = ਨਿਰਾ;
	ਬਣਤਰ sshkey *ret;
	ਪੂਰਨ r;

	ਜੇ ((helper = helper_by_ਕੁੰਜੀ(priv)) == ਨਿਰਾ || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(priv));

	debug3_f("private key type %s cert type %s on provider %s",
	    sshkey_type(priv), sshkey_type(certpub), helper->ਰਸਤਾ);

	*certprivp = ਨਿਰਾ;
	ਜੇ (!sshkey_is_cert(certpub) || sshkey_is_cert(priv) ||
	    !sshkey_equal_ਜਨਤਕ(priv, certpub)) {
		error_f("private key %s doesn't match cert %s",
		    sshkey_type(priv), sshkey_type(certpub));
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	}
	*certprivp = ਨਿਰਾ;
	ਜੇ ((r = sshkey_from_ਨਿੱਜੀ(priv, &ret)) != 0)
		fatal_fr(r, "copy key");

	ret->flags |= SSHKEY_FLAG_EXT;
	ਜੇ ((r = sshkey_ਮੰਜ਼ਿਲ_certified(ret)) != 0 ||
	    (r = sshkey_cert_copy(certpub, ret)) != 0)
		fatal_fr(r, "graft certificate");

	helper_ਜੋੜੋ_ਕੁੰਜੀ(helper, ret);

	debug3_f("provider %s: %zu remaining keys",
	    helper->ਰਸਤਾ, helper->nkeyblobs);

	/* success */
	*certprivp = ret;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਬਣਤਰ helper *
pkcs11_ਸ਼ੁਰੂ_helper(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ)
{
	ਪੂਰਨ pair[2];
	ਅੱਖਰ *prog, *verbosity = ਨਿਰਾ;
	ਬਣਤਰ helper *helper;
	pid_t pid;

	ਜੇ (nhelpers >= ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ)
		fatal_f("too many helpers");
	debug3_f("start helper for %s", ਰਸਤਾ);
	ਜੇ (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
		error_f("socketpair: %s", strerror(errno));
		ਵਾਪਸ ਨਿਰਾ;
	}
	helper = xcalloc(1, ਆਕਾਰ(*helper));
	ਜੇ ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		close(pair[0]);
		close(pair[1]);
		ਮੁਕਤ(helper);
		ਵਾਪਸ ਨਿਰਾ;
	} ਨਹੀਂਤਾਂ ਜੇ (pid == 0) {
		ਜੇ ((dup2(pair[1], STDIN_FILENO) == -1) ||
		    (dup2(pair[1], STDOUT_FILENO) == -1)) {
			fprintf(stderr, "dup2: %s\n", strerror(errno));
			_exit(1);
		}
		close(pair[0]);
		close(pair[1]);
		closefrom(STDERR_FILENO + 1);
		prog = getenv("SSH_PKCS11_HELPER");
		ਜੇ (prog == ਨਿਰਾ || ਲੜੀ_ਲੰਬਾਈ(prog) == 0)
			prog = ਰਸਤਾ_SSH_PKCS11_HELPER;
		ਜੇ (log_level_get() >= SYSLOG_LEVEL_DEBUG1)
			verbosity = "-vvv";
		debug_f("starting %s %s", prog,
		    verbosity == ਨਿਰਾ ? "" : verbosity);
		execlp(prog, prog, verbosity, (ਅੱਖਰ *)ਨਿਰਾ);
		fprintf(stderr, "exec: %s: %s\n", prog, strerror(errno));
		_exit(1);
	}
	close(pair[1]);
	helper->fd = pair[0];
	helper->ਰਸਤਾ = xstrdup(ਰਸਤਾ);
	helper->pid = pid;
	debug3_f("helper %zu for \"%s\" on fd %d pid %ld", nhelpers,
	    helper->ਰਸਤਾ, helper->fd, (ਲੰਮਾ)helper->pid);
	helpers = xrecallocarray(helpers, nhelpers,
	    nhelpers + 1, ਆਕਾਰ(*helpers));
	helpers[nhelpers++] = helper;
	ਵਾਪਸ helper;
}

ਪੂਰਨ
pkcs11_ਜੋੜੋ_provider(ਅੱਖਰ *name, ਅੱਖਰ *pin, ਬਣਤਰ sshkey ***keysp,
    ਅੱਖਰ ***labelsp)
{
	ਬਣਤਰ sshkey *k;
	ਪੂਰਨ r, type;
	ਅੱਖਰ *label;
	u_int ret = -1, nkeys, i;
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;
	ਬਣਤਰ helper *helper;

	ਜੇ ((helper = helper_by_provider(name)) == ਨਿਰਾ &&
	    (helper = pkcs11_ਸ਼ੁਰੂ_helper(name)) == ਨਿਰਾ)
		ਵਾਪਸ -1;

	debug3_f("add %s", helper->ਰਸਤਾ);

	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, SSH_AGENTC_ਜੋੜੋ_SMARTCARD_ਕੁੰਜੀ)) != 0 ||
	    (r = sshbuf_put_cstring(ਸੁਨੇਹਾ, name)) != 0 ||
	    (r = sshbuf_put_cstring(ਸੁਨੇਹਾ, pin)) != 0)
		fatal_fr(r, "compose");
	send_ਸੁਨੇਹਾ(helper->fd, ਸੁਨੇਹਾ);
	sshbuf_reset(ਸੁਨੇਹਾ);

	type = recv_ਸੁਨੇਹਾ(helper->fd, ਸੁਨੇਹਾ);
	debug3_f("response %d", type);
	ਜੇ (type == SSH2_AGENT_IDENTITIES_ANSWER) {
		ਜੇ ((r = sshbuf_get_u32(ਸੁਨੇਹਾ, &nkeys)) != 0)
			fatal_fr(r, "parse nkeys");
		debug3_f("helper return %u keys", nkeys);
		*keysp = xcalloc(nkeys, ਆਕਾਰ(ਬਣਤਰ sshkey *));
		ਜੇ (labelsp)
			*labelsp = xcalloc(nkeys, ਆਕਾਰ(ਅੱਖਰ *));
		ਲਈ (i = 0; i < nkeys; i++) {
			/* XXX clean up properly instead of fatal() */
			ਜੇ ((r = sshkey_froms(ਸੁਨੇਹਾ, &k)) != 0 ||
			    (r = sshbuf_get_cstring(ਸੁਨੇਹਾ, &label, ਨਿਰਾ)) != 0)
				fatal_fr(r, "parse key");
			k->flags |= SSHKEY_FLAG_EXT;
			helper_ਜੋੜੋ_ਕੁੰਜੀ(helper, k);
			(*keysp)[i] = k;
			ਜੇ (labelsp)
				(*labelsp)[i] = label;
			ਨਹੀਂਤਾਂ
				ਮੁਕਤ(label);
		}
		/* success */
		ret = 0;
	} ਨਹੀਂਤਾਂ ਜੇ (type == SSH2_AGENT_FAILURE) {
		ਜੇ ((r = sshbuf_get_u32(ਸੁਨੇਹਾ, &nkeys)) != 0)
			error_fr(r, "failed to parse failure response");
	}
	ਜੇ (ret != 0) {
		debug_f("no keys; terminate helper");
		helper_terminate(helper);
	}
	sshbuf_free(ਸੁਨੇਹਾ);
	ਵਾਪਸ ret == 0 ? (ਪੂਰਨ)nkeys : -1;
}

ਪੂਰਨ
pkcs11_del_provider(ਅੱਖਰ *name)
{
	ਬਣਤਰ helper *helper;

	/*
	 * ssh-agent deletes keys before calling this, so the helper entry
	 * should be gone before we get here.
	 */
	debug3_f("delete %s", name ? name : "(null)");
	ਜੇ ((helper = helper_by_provider(name)) != ਨਿਰਾ)
		helper_terminate(helper);
	ਵਾਪਸ 0;
}

ਖਾਲੀ
pkcs11_ਕੁੰਜੀ_free(ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	ਬਣਤਰ helper *helper;
	ਬਣਤਰ sshbuf *keyblob = ਨਿਰਾ;
	ਮਾਪ_t i;
	ਪੂਰਨ r, ਮਿਲਿਆ = 0;

	debug3_f("free %s key", sshkey_type(ਕੁੰਜੀ));

	ਜੇ ((helper = helper_by_ਕੁੰਜੀ(ਕੁੰਜੀ)) == ਨਿਰਾ || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(ਕੁੰਜੀ));
	ਜੇ ((keyblob = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = sshkey_putb(ਕੁੰਜੀ, keyblob)) != 0)
		fatal_fr(r, "serialise key");

	/* repack keys */
	ਲਈ (i = 0; i < helper->nkeyblobs; i++) {
		ਜੇ (sshbuf_equals(keyblob, helper->keyblobs[i]) == 0) {
			ਜੇ (ਮਿਲਿਆ)
				fatal_f("key recorded more than once");
			ਮਿਲਿਆ = 1;
		} ਨਹੀਂਤਾਂ ਜੇ (ਮਿਲਿਆ)
			helper->keyblobs[i - 1] = helper->keyblobs[i];
	}
	ਜੇ (ਮਿਲਿਆ) {
		helper->keyblobs = xrecallocarray(helper->keyblobs,
		    helper->nkeyblobs, helper->nkeyblobs - 1,
		    ਆਕਾਰ(*helper->keyblobs));
		helper->nkeyblobs--;
	}
	ਜੇ (helper->nkeyblobs == 0)
		helper_terminate(helper);
}
