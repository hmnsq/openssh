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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/time.h>
#അന്തര്ഭാവ <sys/socket.h>

#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <limits.h>

#അന്തര്ഭാവ "pathnames.h"
#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "authfd.h"
#അന്തര്ഭാവ "atomicio.h"
#അന്തര്ഭാവ "ssh-pkcs11.h"
#അന്തര്ഭാവ "ssherr.h"

/* borrows code from sftp-server and ssh-agent */

/*
 * Maintain a list of ssh-pkcs11-helper subprocesses. These may be looked up
 * by provider path or their unique keyblobs.
 */
ഘടന helper {
	അക്ഷരം *path;
	pid_t pid;
	പൂർണ്ണസംഖ്യ fd;
	size_t nkeyblobs;
	ഘടന sshbuf **keyblobs; /* XXX use a tree or something faster */
};
സ്ഥിതം ഘടന helper **helpers;
സ്ഥിതം size_t nhelpers;

സ്ഥിതം ഘടന helper *
helper_by_provider(സ്ഥിരം അക്ഷരം *path)
{
	size_t i;

	വേണ്ടി (i = 0; i < nhelpers; i++) {
		എങ്കിൽ (helpers[i] == ശൂന്യ || helpers[i]->path == ശൂന്യ ||
		    helpers[i]->fd == -1)
			തുടരുക;
		എങ്കിൽ (strcmp(helpers[i]->path, path) == 0)
			തിരികെ helpers[i];
	}
	തിരികെ ശൂന്യ;
}

സ്ഥിതം ഘടന helper *
helper_by_താക്കോൽ(സ്ഥിരം ഘടന sshkey *താക്കോൽ)
{
	size_t i, j;
	ഘടന sshbuf *keyblob = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((keyblob = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = sshkey_putb(താക്കോൽ, keyblob)) != 0)
		fatal_fr(r, "serialise key");

	വേണ്ടി (i = 0; i < nhelpers; i++) {
		എങ്കിൽ (helpers[i] == ശൂന്യ)
			തുടരുക;
		വേണ്ടി (j = 0; j < helpers[i]->nkeyblobs; j++) {
			എങ്കിൽ (sshbuf_equals(keyblob,
			    helpers[i]->keyblobs[j]) == 0) {
				sshbuf_free(keyblob);
				തിരികെ helpers[i];
			}
		}
	}
	sshbuf_free(keyblob);
	തിരികെ ശൂന്യ;

}

സ്ഥിതം ശൂന്യം
helper_add_താക്കോൽ(ഘടന helper *helper, ഘടന sshkey *താക്കോൽ)
{
	പൂർണ്ണസംഖ്യ r;

	helper->keyblobs = xrecallocarray(helper->keyblobs, helper->nkeyblobs,
	    helper->nkeyblobs + 1, വലുപ്പം(*helper->keyblobs));
	എങ്കിൽ ((helper->keyblobs[helper->nkeyblobs] = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = sshkey_putb(താക്കോൽ, helper->keyblobs[helper->nkeyblobs])) != 0)
		fatal_fr(r, "shkey_putb failed");
	helper->nkeyblobs++;
	debug3_f("added %s key for provider %s, now has %zu keys",
	    sshkey_type(താക്കോൽ), helper->path, helper->nkeyblobs);
}

സ്ഥിതം ശൂന്യം
helper_terminate(ഘടന helper *helper)
{
	size_t i;
	പൂർണ്ണസംഖ്യ found = 0;

	എങ്കിൽ (helper == ശൂന്യ)
		തിരികെ;
	എങ്കിൽ (helper->path == ശൂന്യ)
		fatal_f("inconsistent helper");

	debug3_f("terminating helper for %s; remaining %zu keys",
	    helper->path, helper->nkeyblobs);

	close(helper->fd);
	/* XXX waitpid() */
	helper->fd = -1;
	helper->pid = -1;

	/* repack helpers */
	വേണ്ടി (i = 0; i < nhelpers; i++) {
		എങ്കിൽ (helpers[i] == helper) {
			എങ്കിൽ (found)
				fatal_f("helper recorded more than once");
			found = 1;
		} അല്ലെങ്കിൽ എങ്കിൽ (found)
			helpers[i - 1] = helpers[i];
	}
	എങ്കിൽ (found) {
		helpers = xrecallocarray(helpers, nhelpers,
		    nhelpers - 1, വലുപ്പം(*helpers));
		nhelpers--;
	}
	വേണ്ടി (i = 0; i < helper->nkeyblobs; i++)
		sshbuf_free(helper->keyblobs[i]);
	സ്വതന്ത്രം(helper->path);
	സ്വതന്ത്രം(helper);
}

സ്ഥിതം ശൂന്യം
send_സന്ദേശം(പൂർണ്ണസംഖ്യ fd, ഘടന sshbuf *m)
{
	u_char buf[4];
	size_t mlen = sshbuf_len(m);
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (fd == -1)
		തിരികെ;
	POKE_U32(buf, mlen);
	എങ്കിൽ (atomicio(vwrite, fd, buf, 4) != 4 ||
	    atomicio(vwrite, fd, sshbuf_mutable_ptr(m),
	    sshbuf_len(m)) != sshbuf_len(m))
		error("write to helper failed");
	എങ്കിൽ ((r = sshbuf_consume(m, mlen)) != 0)
		fatal_fr(r, "consume");
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
recv_സന്ദേശം(പൂർണ്ണസംഖ്യ fd, ഘടന sshbuf *m)
{
	u_int l, len;
	u_char c, buf[1024];
	പൂർണ്ണസംഖ്യ r;

	sshbuf_reset(m);
	എങ്കിൽ (fd == -1)
		തിരികെ 0; /* XXX */
	എങ്കിൽ ((len = atomicio(പഠ, fd, buf, 4)) != 4) {
		error("read from helper failed: %u", len);
		തിരികെ (0); /* XXX */
	}
	len = PEEK_U32(buf);
	എങ്കിൽ (len > 256 * 1024)
		fatal("response too long: %u", len);
	/* read len bytes into m */
	ആകുമ്പോൾ (len > 0) {
		l = len;
		എങ്കിൽ (l > വലുപ്പം(buf))
			l = വലുപ്പം(buf);
		എങ്കിൽ (atomicio(പഠ, fd, buf, l) != l) {
			error("response from helper failed.");
			തിരികെ (0); /* XXX */
		}
		എങ്കിൽ ((r = sshbuf_put(m, buf, l)) != 0)
			fatal_fr(r, "sshbuf_put");
		len -= l;
	}
	എങ്കിൽ ((r = sshbuf_get_u8(m, &c)) != 0)
		fatal_fr(r, "parse type");
	തിരികെ c;
}

പൂർണ്ണസംഖ്യ
pkcs11_init(പൂർണ്ണസംഖ്യ interactive)
{
	തിരികെ 0;
}

ശൂന്യം
pkcs11_terminate(ശൂന്യം)
{
	size_t i;

	debug3_f("terminating %zu helpers", nhelpers);
	വേണ്ടി (i = 0; i < nhelpers; i++)
		helper_terminate(helpers[i]);
}

പൂർണ്ണസംഖ്യ
pkcs11_sign(ഘടന sshkey *താക്കോൽ,
    u_char **sigp, size_t *lenp,
    സ്ഥിരം u_char *data, size_t datalen,
    സ്ഥിരം അക്ഷരം *alg, സ്ഥിരം അക്ഷരം *sk_provider,
    സ്ഥിരം അക്ഷരം *sk_pin, u_int compat)
{
	ഘടന sshbuf *സന്ദേശം = ശൂന്യ;
	ഘടന helper *helper;
	പൂർണ്ണസംഖ്യ status, r;
	u_char *signature = ശൂന്യ;
	size_t signature_len = 0;
	പൂർണ്ണസംഖ്യ ret = SSH_ERR_INTERNAL_ERROR;

	എങ്കിൽ (sigp != ശൂന്യ)
		*sigp = ശൂന്യ;
	എങ്കിൽ (lenp != ശൂന്യ)
		*lenp = 0;

	എങ്കിൽ ((helper = helper_by_താക്കോൽ(താക്കോൽ)) == ശൂന്യ || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(താക്കോൽ));

	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, SSH2_AGENTC_SIGN_REQUEST)) != 0 ||
	    (r = sshkey_puts_plain(താക്കോൽ, സന്ദേശം)) != 0 ||
	    (r = sshbuf_put_string(സന്ദേശം, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(സന്ദേശം, alg == ശൂന്യ ? "" : alg)) != 0 ||
	    (r = sshbuf_put_u32(സന്ദേശം, compat)) != 0)
		fatal_fr(r, "compose");
	send_സന്ദേശം(helper->fd, സന്ദേശം);
	sshbuf_reset(സന്ദേശം);

	എങ്കിൽ ((status = recv_സന്ദേശം(helper->fd, സന്ദേശം)) != SSH2_AGENT_SIGN_RESPONSE) {
		/* XXX translate status to something useful */
		debug_fr(r, "recv_msg");
		ret = SSH_ERR_AGENT_FAILURE;
		പോകുക fail;
	}

	എങ്കിൽ ((r = sshbuf_get_string(സന്ദേശം, &signature, &signature_len)) != 0)
		fatal_fr(r, "parse");

	/* success */
	എങ്കിൽ (sigp != ശൂന്യ) {
		*sigp = signature;
		signature = ശൂന്യ;
	}
	എങ്കിൽ (lenp != ശൂന്യ)
		*lenp = signature_len;
	ret = 0;

 fail:
	സ്വതന്ത്രം(signature);
	sshbuf_free(സന്ദേശം);
	തിരികെ ret;
}

/*
 * Make a private PKCS#11-backed certificate by grafting a previously-loaded
 * PKCS#11 private key and a public certificate key.
 */
പൂർണ്ണസംഖ്യ
pkcs11_make_cert(സ്ഥിരം ഘടന sshkey *priv,
    സ്ഥിരം ഘടന sshkey *certpub, ഘടന sshkey **certprivp)
{
	ഘടന helper *helper = ശൂന്യ;
	ഘടന sshkey *ret;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((helper = helper_by_താക്കോൽ(priv)) == ശൂന്യ || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(priv));

	debug3_f("private key type %s cert type %s on provider %s",
	    sshkey_type(priv), sshkey_type(certpub), helper->path);

	*certprivp = ശൂന്യ;
	എങ്കിൽ (!sshkey_is_cert(certpub) || sshkey_is_cert(priv) ||
	    !sshkey_equal_public(priv, certpub)) {
		error_f("private key %s doesn't match cert %s",
		    sshkey_type(priv), sshkey_type(certpub));
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	}
	*certprivp = ശൂന്യ;
	എങ്കിൽ ((r = sshkey_from_private(priv, &ret)) != 0)
		fatal_fr(r, "copy key");

	ret->flags |= SSHKEY_FLAG_EXT;
	എങ്കിൽ ((r = sshkey_to_certified(ret)) != 0 ||
	    (r = sshkey_cert_copy(certpub, ret)) != 0)
		fatal_fr(r, "graft certificate");

	helper_add_താക്കോൽ(helper, ret);

	debug3_f("provider %s: %zu remaining keys",
	    helper->path, helper->nkeyblobs);

	/* success */
	*certprivp = ret;
	തിരികെ 0;
}

സ്ഥിതം ഘടന helper *
pkcs11_start_helper(സ്ഥിരം അക്ഷരം *path)
{
	പൂർണ്ണസംഖ്യ pair[2];
	അക്ഷരം *prog, *verbosity = ശൂന്യ;
	ഘടന helper *helper;
	pid_t pid;

	എങ്കിൽ (nhelpers >= INT_MAX)
		fatal_f("too many helpers");
	debug3_f("start helper for %s", path);
	എങ്കിൽ (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
		error_f("socketpair: %s", strerror(errno));
		തിരികെ ശൂന്യ;
	}
	helper = xcalloc(1, വലുപ്പം(*helper));
	എങ്കിൽ ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		close(pair[0]);
		close(pair[1]);
		സ്വതന്ത്രം(helper);
		തിരികെ ശൂന്യ;
	} അല്ലെങ്കിൽ എങ്കിൽ (pid == 0) {
		എങ്കിൽ ((dup2(pair[1], STDIN_FILENO) == -1) ||
		    (dup2(pair[1], STDOUT_FILENO) == -1)) {
			fprintf(stderr, "dup2: %s\n", strerror(errno));
			_exit(1);
		}
		close(pair[0]);
		close(pair[1]);
		closefrom(STDERR_FILENO + 1);
		prog = getenv("SSH_PKCS11_HELPER");
		എങ്കിൽ (prog == ശൂന്യ || strlen(prog) == 0)
			prog = _PATH_SSH_PKCS11_HELPER;
		എങ്കിൽ (log_level_get() >= SYSLOG_LEVEL_DEBUG1)
			verbosity = "-vvv";
		debug_f("starting %s %s", prog,
		    verbosity == ശൂന്യ ? "" : verbosity);
		execlp(prog, prog, verbosity, (അക്ഷരം *)ശൂന്യ);
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
	    nhelpers + 1, വലുപ്പം(*helpers));
	helpers[nhelpers++] = helper;
	തിരികെ helper;
}

പൂർണ്ണസംഖ്യ
pkcs11_add_provider(അക്ഷരം *name, അക്ഷരം *pin, ഘടന sshkey ***keysp,
    അക്ഷരം ***labelsp)
{
	ഘടന sshkey *k;
	പൂർണ്ണസംഖ്യ r, type;
	അക്ഷരം *label;
	u_int ret = -1, nkeys, i;
	ഘടന sshbuf *സന്ദേശം;
	ഘടന helper *helper;

	എങ്കിൽ ((helper = helper_by_provider(name)) == ശൂന്യ &&
	    (helper = pkcs11_start_helper(name)) == ശൂന്യ)
		തിരികെ -1;

	debug3_f("add %s", helper->path);

	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, SSH_AGENTC_ADD_SMARTCARD_താക്കോൽ)) != 0 ||
	    (r = sshbuf_put_cstring(സന്ദേശം, name)) != 0 ||
	    (r = sshbuf_put_cstring(സന്ദേശം, pin)) != 0)
		fatal_fr(r, "compose");
	send_സന്ദേശം(helper->fd, സന്ദേശം);
	sshbuf_reset(സന്ദേശം);

	type = recv_സന്ദേശം(helper->fd, സന്ദേശം);
	debug3_f("response %d", type);
	എങ്കിൽ (type == SSH2_AGENT_IDENTITIES_ANSWER) {
		എങ്കിൽ ((r = sshbuf_get_u32(സന്ദേശം, &nkeys)) != 0)
			fatal_fr(r, "parse nkeys");
		debug3_f("helper return %u keys", nkeys);
		*keysp = xcalloc(nkeys, വലുപ്പം(ഘടന sshkey *));
		എങ്കിൽ (labelsp)
			*labelsp = xcalloc(nkeys, വലുപ്പം(അക്ഷരം *));
		വേണ്ടി (i = 0; i < nkeys; i++) {
			/* XXX clean up properly instead of fatal() */
			എങ്കിൽ ((r = sshkey_froms(സന്ദേശം, &k)) != 0 ||
			    (r = sshbuf_get_cstring(സന്ദേശം, &label, ശൂന്യ)) != 0)
				fatal_fr(r, "parse key");
			k->flags |= SSHKEY_FLAG_EXT;
			helper_add_താക്കോൽ(helper, k);
			(*keysp)[i] = k;
			എങ്കിൽ (labelsp)
				(*labelsp)[i] = label;
			അല്ലെങ്കിൽ
				സ്വതന്ത്രം(label);
		}
		/* success */
		ret = 0;
	} അല്ലെങ്കിൽ എങ്കിൽ (type == SSH2_AGENT_FAILURE) {
		എങ്കിൽ ((r = sshbuf_get_u32(സന്ദേശം, &nkeys)) != 0)
			error_fr(r, "failed to parse failure response");
	}
	എങ്കിൽ (ret != 0) {
		debug_f("no keys; terminate helper");
		helper_terminate(helper);
	}
	sshbuf_free(സന്ദേശം);
	തിരികെ ret == 0 ? (പൂർണ്ണസംഖ്യ)nkeys : -1;
}

പൂർണ്ണസംഖ്യ
pkcs11_del_provider(അക്ഷരം *name)
{
	ഘടന helper *helper;

	/*
	 * ssh-agent deletes keys before calling this, so the helper entry
	 * should be gone before we get here.
	 */
	debug3_f("delete %s", name ? name : "(null)");
	എങ്കിൽ ((helper = helper_by_provider(name)) != ശൂന്യ)
		helper_terminate(helper);
	തിരികെ 0;
}

ശൂന്യം
pkcs11_താക്കോൽ_free(ഘടന sshkey *താക്കോൽ)
{
	ഘടന helper *helper;
	ഘടന sshbuf *keyblob = ശൂന്യ;
	size_t i;
	പൂർണ്ണസംഖ്യ r, found = 0;

	debug3_f("free %s key", sshkey_type(താക്കോൽ));

	എങ്കിൽ ((helper = helper_by_താക്കോൽ(താക്കോൽ)) == ശൂന്യ || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(താക്കോൽ));
	എങ്കിൽ ((keyblob = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = sshkey_putb(താക്കോൽ, keyblob)) != 0)
		fatal_fr(r, "serialise key");

	/* repack keys */
	വേണ്ടി (i = 0; i < helper->nkeyblobs; i++) {
		എങ്കിൽ (sshbuf_equals(keyblob, helper->keyblobs[i]) == 0) {
			എങ്കിൽ (found)
				fatal_f("key recorded more than once");
			found = 1;
		} അല്ലെങ്കിൽ എങ്കിൽ (found)
			helper->keyblobs[i - 1] = helper->keyblobs[i];
	}
	എങ്കിൽ (found) {
		helper->keyblobs = xrecallocarray(helper->keyblobs,
		    helper->nkeyblobs, helper->nkeyblobs - 1,
		    വലുപ്പം(*helper->keyblobs));
		helper->nkeyblobs--;
	}
	എങ്കിൽ (helper->nkeyblobs == 0)
		helper_terminate(helper);
}
