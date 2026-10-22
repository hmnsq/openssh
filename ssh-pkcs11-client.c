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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/time.h>
#અન્તર્ભાવ <sys/socket.h>

#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <limits.h>

#અન્તર્ભાવ "pathnames.h"
#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "authfd.h"
#અન્તર્ભાવ "atomicio.h"
#અન્તર્ભાવ "ssh-pkcs11.h"
#અન્તર્ભાવ "ssherr.h"

/* borrows code from sftp-server and ssh-agent */

/*
 * Maintain a list of ssh-pkcs11-helper subprocesses. These may be looked up
 * by provider path or their unique keyblobs.
 */
સંરચના helper {
	અક્ષર *path;
	pid_t pid;
	પૂર્ણાંક fd;
	size_t nkeyblobs;
	સંરચના sshbuf **keyblobs; /* XXX use a tree or something faster */
};
સ્થિર સંરચના helper **helpers;
સ્થિર size_t nhelpers;

સ્થિર સંરચના helper *
helper_by_provider(અચલ અક્ષર *path)
{
	size_t i;

	માટે (i = 0; i < nhelpers; i++) {
		જો (helpers[i] == ખાલી || helpers[i]->path == ખાલી ||
		    helpers[i]->fd == -1)
			ચાલુ;
		જો (strcmp(helpers[i]->path, path) == 0)
			પાછા helpers[i];
	}
	પાછા ખાલી;
}

સ્થિર સંરચના helper *
helper_by_ચાવી(અચલ સંરચના sshkey *ચાવી)
{
	size_t i, j;
	સંરચના sshbuf *keyblob = ખાલી;
	પૂર્ણાંક r;

	જો ((keyblob = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = sshkey_putb(ચાવી, keyblob)) != 0)
		fatal_fr(r, "serialise key");

	માટે (i = 0; i < nhelpers; i++) {
		જો (helpers[i] == ખાલી)
			ચાલુ;
		માટે (j = 0; j < helpers[i]->nkeyblobs; j++) {
			જો (sshbuf_equals(keyblob,
			    helpers[i]->keyblobs[j]) == 0) {
				sshbuf_free(keyblob);
				પાછા helpers[i];
			}
		}
	}
	sshbuf_free(keyblob);
	પાછા ખાલી;

}

સ્થિર શૂન્ય
helper_add_ચાવી(સંરચના helper *helper, સંરચના sshkey *ચાવી)
{
	પૂર્ણાંક r;

	helper->keyblobs = xrecallocarray(helper->keyblobs, helper->nkeyblobs,
	    helper->nkeyblobs + 1, કદ(*helper->keyblobs));
	જો ((helper->keyblobs[helper->nkeyblobs] = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = sshkey_putb(ચાવી, helper->keyblobs[helper->nkeyblobs])) != 0)
		fatal_fr(r, "shkey_putb failed");
	helper->nkeyblobs++;
	debug3_f("added %s key for provider %s, now has %zu keys",
	    sshkey_type(ચાવી), helper->path, helper->nkeyblobs);
}

સ્થિર શૂન્ય
helper_terminate(સંરચના helper *helper)
{
	size_t i;
	પૂર્ણાંક found = 0;

	જો (helper == ખાલી)
		પાછા;
	જો (helper->path == ખાલી)
		fatal_f("inconsistent helper");

	debug3_f("terminating helper for %s; remaining %zu keys",
	    helper->path, helper->nkeyblobs);

	close(helper->fd);
	/* XXX waitpid() */
	helper->fd = -1;
	helper->pid = -1;

	/* repack helpers */
	માટે (i = 0; i < nhelpers; i++) {
		જો (helpers[i] == helper) {
			જો (found)
				fatal_f("helper recorded more than once");
			found = 1;
		} નહીંતર જો (found)
			helpers[i - 1] = helpers[i];
	}
	જો (found) {
		helpers = xrecallocarray(helpers, nhelpers,
		    nhelpers - 1, કદ(*helpers));
		nhelpers--;
	}
	માટે (i = 0; i < helper->nkeyblobs; i++)
		sshbuf_free(helper->keyblobs[i]);
	મુક્ત(helper->path);
	મુક્ત(helper);
}

સ્થિર શૂન્ય
send_સંદેશ(પૂર્ણાંક fd, સંરચના sshbuf *m)
{
	u_char buf[4];
	size_t mlen = sshbuf_len(m);
	પૂર્ણાંક r;

	જો (fd == -1)
		પાછા;
	POKE_U32(buf, mlen);
	જો (atomicio(vwrite, fd, buf, 4) != 4 ||
	    atomicio(vwrite, fd, sshbuf_mutable_ptr(m),
	    sshbuf_len(m)) != sshbuf_len(m))
		error("write to helper failed");
	જો ((r = sshbuf_consume(m, mlen)) != 0)
		fatal_fr(r, "consume");
}

સ્થિર પૂર્ણાંક
recv_સંદેશ(પૂર્ણાંક fd, સંરચના sshbuf *m)
{
	u_int l, len;
	u_char c, buf[1024];
	પૂર્ણાંક r;

	sshbuf_reset(m);
	જો (fd == -1)
		પાછા 0; /* XXX */
	જો ((len = atomicio(પઠ, fd, buf, 4)) != 4) {
		error("read from helper failed: %u", len);
		પાછા (0); /* XXX */
	}
	len = PEEK_U32(buf);
	જો (len > 256 * 1024)
		fatal("response too long: %u", len);
	/* read len bytes into m */
	જ્યારે (len > 0) {
		l = len;
		જો (l > કદ(buf))
			l = કદ(buf);
		જો (atomicio(પઠ, fd, buf, l) != l) {
			error("response from helper failed.");
			પાછા (0); /* XXX */
		}
		જો ((r = sshbuf_put(m, buf, l)) != 0)
			fatal_fr(r, "sshbuf_put");
		len -= l;
	}
	જો ((r = sshbuf_get_u8(m, &c)) != 0)
		fatal_fr(r, "parse type");
	પાછા c;
}

પૂર્ણાંક
pkcs11_init(પૂર્ણાંક interactive)
{
	પાછા 0;
}

શૂન્ય
pkcs11_terminate(શૂન્ય)
{
	size_t i;

	debug3_f("terminating %zu helpers", nhelpers);
	માટે (i = 0; i < nhelpers; i++)
		helper_terminate(helpers[i]);
}

પૂર્ણાંક
pkcs11_sign(સંરચના sshkey *ચાવી,
    u_char **sigp, size_t *lenp,
    અચલ u_char *data, size_t datalen,
    અચલ અક્ષર *alg, અચલ અક્ષર *sk_provider,
    અચલ અક્ષર *sk_pin, u_int compat)
{
	સંરચના sshbuf *સંદેશ = ખાલી;
	સંરચના helper *helper;
	પૂર્ણાંક status, r;
	u_char *signature = ખાલી;
	size_t signature_len = 0;
	પૂર્ણાંક ret = SSH_ERR_INTERNAL_ERROR;

	જો (sigp != ખાલી)
		*sigp = ખાલી;
	જો (lenp != ખાલી)
		*lenp = 0;

	જો ((helper = helper_by_ચાવી(ચાવી)) == ખાલી || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(ચાવી));

	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો ((r = sshbuf_put_u8(સંદેશ, SSH2_AGENTC_SIGN_REQUEST)) != 0 ||
	    (r = sshkey_puts_plain(ચાવી, સંદેશ)) != 0 ||
	    (r = sshbuf_put_string(સંદેશ, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(સંદેશ, alg == ખાલી ? "" : alg)) != 0 ||
	    (r = sshbuf_put_u32(સંદેશ, compat)) != 0)
		fatal_fr(r, "compose");
	send_સંદેશ(helper->fd, સંદેશ);
	sshbuf_reset(સંદેશ);

	જો ((status = recv_સંદેશ(helper->fd, સંદેશ)) != SSH2_AGENT_SIGN_RESPONSE) {
		/* XXX translate status to something useful */
		debug_fr(r, "recv_msg");
		ret = SSH_ERR_AGENT_FAILURE;
		જાઓ fail;
	}

	જો ((r = sshbuf_get_string(સંદેશ, &signature, &signature_len)) != 0)
		fatal_fr(r, "parse");

	/* success */
	જો (sigp != ખાલી) {
		*sigp = signature;
		signature = ખાલી;
	}
	જો (lenp != ખાલી)
		*lenp = signature_len;
	ret = 0;

 fail:
	મુક્ત(signature);
	sshbuf_free(સંદેશ);
	પાછા ret;
}

/*
 * Make a private PKCS#11-backed certificate by grafting a previously-loaded
 * PKCS#11 private key and a public certificate key.
 */
પૂર્ણાંક
pkcs11_make_cert(અચલ સંરચના sshkey *priv,
    અચલ સંરચના sshkey *certpub, સંરચના sshkey **certprivp)
{
	સંરચના helper *helper = ખાલી;
	સંરચના sshkey *ret;
	પૂર્ણાંક r;

	જો ((helper = helper_by_ચાવી(priv)) == ખાલી || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(priv));

	debug3_f("private key type %s cert type %s on provider %s",
	    sshkey_type(priv), sshkey_type(certpub), helper->path);

	*certprivp = ખાલી;
	જો (!sshkey_is_cert(certpub) || sshkey_is_cert(priv) ||
	    !sshkey_equal_public(priv, certpub)) {
		error_f("private key %s doesn't match cert %s",
		    sshkey_type(priv), sshkey_type(certpub));
		પાછા SSH_ERR_INVALID_ARGUMENT;
	}
	*certprivp = ખાલી;
	જો ((r = sshkey_from_private(priv, &ret)) != 0)
		fatal_fr(r, "copy key");

	ret->flags |= SSHKEY_FLAG_EXT;
	જો ((r = sshkey_to_certified(ret)) != 0 ||
	    (r = sshkey_cert_copy(certpub, ret)) != 0)
		fatal_fr(r, "graft certificate");

	helper_add_ચાવી(helper, ret);

	debug3_f("provider %s: %zu remaining keys",
	    helper->path, helper->nkeyblobs);

	/* success */
	*certprivp = ret;
	પાછા 0;
}

સ્થિર સંરચના helper *
pkcs11_start_helper(અચલ અક્ષર *path)
{
	પૂર્ણાંક pair[2];
	અક્ષર *prog, *verbosity = ખાલી;
	સંરચના helper *helper;
	pid_t pid;

	જો (nhelpers >= INT_MAX)
		fatal_f("too many helpers");
	debug3_f("start helper for %s", path);
	જો (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
		error_f("socketpair: %s", strerror(errno));
		પાછા ખાલી;
	}
	helper = xcalloc(1, કદ(*helper));
	જો ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		close(pair[0]);
		close(pair[1]);
		મુક્ત(helper);
		પાછા ખાલી;
	} નહીંતર જો (pid == 0) {
		જો ((dup2(pair[1], STDIN_FILENO) == -1) ||
		    (dup2(pair[1], STDOUT_FILENO) == -1)) {
			fprintf(stderr, "dup2: %s\n", strerror(errno));
			_exit(1);
		}
		close(pair[0]);
		close(pair[1]);
		closefrom(STDERR_FILENO + 1);
		prog = getenv("SSH_PKCS11_HELPER");
		જો (prog == ખાલી || strlen(prog) == 0)
			prog = _PATH_SSH_PKCS11_HELPER;
		જો (log_level_get() >= SYSLOG_LEVEL_DEBUG1)
			verbosity = "-vvv";
		debug_f("starting %s %s", prog,
		    verbosity == ખાલી ? "" : verbosity);
		execlp(prog, prog, verbosity, (અક્ષર *)ખાલી);
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
	    nhelpers + 1, કદ(*helpers));
	helpers[nhelpers++] = helper;
	પાછા helper;
}

પૂર્ણાંક
pkcs11_add_provider(અક્ષર *name, અક્ષર *pin, સંરચના sshkey ***keysp,
    અક્ષર ***labelsp)
{
	સંરચના sshkey *k;
	પૂર્ણાંક r, type;
	અક્ષર *label;
	u_int ret = -1, nkeys, i;
	સંરચના sshbuf *સંદેશ;
	સંરચના helper *helper;

	જો ((helper = helper_by_provider(name)) == ખાલી &&
	    (helper = pkcs11_start_helper(name)) == ખાલી)
		પાછા -1;

	debug3_f("add %s", helper->path);

	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = sshbuf_put_u8(સંદેશ, SSH_AGENTC_ADD_SMARTCARD_ચાવી)) != 0 ||
	    (r = sshbuf_put_cstring(સંદેશ, name)) != 0 ||
	    (r = sshbuf_put_cstring(સંદેશ, pin)) != 0)
		fatal_fr(r, "compose");
	send_સંદેશ(helper->fd, સંદેશ);
	sshbuf_reset(સંદેશ);

	type = recv_સંદેશ(helper->fd, સંદેશ);
	debug3_f("response %d", type);
	જો (type == SSH2_AGENT_IDENTITIES_ANSWER) {
		જો ((r = sshbuf_get_u32(સંદેશ, &nkeys)) != 0)
			fatal_fr(r, "parse nkeys");
		debug3_f("helper return %u keys", nkeys);
		*keysp = xcalloc(nkeys, કદ(સંરચના sshkey *));
		જો (labelsp)
			*labelsp = xcalloc(nkeys, કદ(અક્ષર *));
		માટે (i = 0; i < nkeys; i++) {
			/* XXX clean up properly instead of fatal() */
			જો ((r = sshkey_froms(સંદેશ, &k)) != 0 ||
			    (r = sshbuf_get_cstring(સંદેશ, &label, ખાલી)) != 0)
				fatal_fr(r, "parse key");
			k->flags |= SSHKEY_FLAG_EXT;
			helper_add_ચાવી(helper, k);
			(*keysp)[i] = k;
			જો (labelsp)
				(*labelsp)[i] = label;
			નહીંતર
				મુક્ત(label);
		}
		/* success */
		ret = 0;
	} નહીંતર જો (type == SSH2_AGENT_FAILURE) {
		જો ((r = sshbuf_get_u32(સંદેશ, &nkeys)) != 0)
			error_fr(r, "failed to parse failure response");
	}
	જો (ret != 0) {
		debug_f("no keys; terminate helper");
		helper_terminate(helper);
	}
	sshbuf_free(સંદેશ);
	પાછા ret == 0 ? (પૂર્ણાંક)nkeys : -1;
}

પૂર્ણાંક
pkcs11_del_provider(અક્ષર *name)
{
	સંરચના helper *helper;

	/*
	 * ssh-agent deletes keys before calling this, so the helper entry
	 * should be gone before we get here.
	 */
	debug3_f("delete %s", name ? name : "(null)");
	જો ((helper = helper_by_provider(name)) != ખાલી)
		helper_terminate(helper);
	પાછા 0;
}

શૂન્ય
pkcs11_ચાવી_free(સંરચના sshkey *ચાવી)
{
	સંરચના helper *helper;
	સંરચના sshbuf *keyblob = ખાલી;
	size_t i;
	પૂર્ણાંક r, found = 0;

	debug3_f("free %s key", sshkey_type(ચાવી));

	જો ((helper = helper_by_ચાવી(ચાવી)) == ખાલી || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(ચાવી));
	જો ((keyblob = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = sshkey_putb(ચાવી, keyblob)) != 0)
		fatal_fr(r, "serialise key");

	/* repack keys */
	માટે (i = 0; i < helper->nkeyblobs; i++) {
		જો (sshbuf_equals(keyblob, helper->keyblobs[i]) == 0) {
			જો (found)
				fatal_f("key recorded more than once");
			found = 1;
		} નહીંતર જો (found)
			helper->keyblobs[i - 1] = helper->keyblobs[i];
	}
	જો (found) {
		helper->keyblobs = xrecallocarray(helper->keyblobs,
		    helper->nkeyblobs, helper->nkeyblobs - 1,
		    કદ(*helper->keyblobs));
		helper->nkeyblobs--;
	}
	જો (helper->nkeyblobs == 0)
		helper_terminate(helper);
}
