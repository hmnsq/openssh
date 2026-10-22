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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/time.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>

#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <limits.h>

#ಅನ್ತರ್ಭಾವ "pathnames.h"
#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "authfd.h"
#ಅನ್ತರ್ಭಾವ "atomicio.h"
#ಅನ್ತರ್ಭಾವ "ssh-pkcs11.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"

/* borrows code from sftp-server and ssh-agent */

/*
 * Maintain a list of ssh-pkcs11-helper subprocesses. These may be looked up
 * by provider path or their unique keyblobs.
 */
ಸಂರಚನಾ helper {
	ವರ್ಣ *path;
	pid_t pid;
	ಪೂರ್ಣಾಙ್ಕ fd;
	size_t nkeyblobs;
	ಸಂರಚನಾ sshbuf **keyblobs; /* XXX use a tree or something faster */
};
ಸ್ಥಿರ ಸಂರಚನಾ helper **helpers;
ಸ್ಥಿರ size_t nhelpers;

ಸ್ಥಿರ ಸಂರಚನಾ helper *
helper_by_provider(ಧ್ರುವ ವರ್ಣ *path)
{
	size_t i;

	ಪ್ರತಿ (i = 0; i < nhelpers; i++) {
		ಯದಿ (helpers[i] == ರಿಕ್ತ || helpers[i]->path == ರಿಕ್ತ ||
		    helpers[i]->fd == -1)
			ಅನುವರ್ತ;
		ಯದಿ (strcmp(helpers[i]->path, path) == 0)
			ಪ್ರತ್ಯಾಗಮ helpers[i];
	}
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}

ಸ್ಥಿರ ಸಂರಚನಾ helper *
helper_by_ಕೀಲಿ(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
	size_t i, j;
	ಸಂರಚನಾ sshbuf *keyblob = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((keyblob = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = sshkey_putb(ಕೀಲಿ, keyblob)) != 0)
		fatal_fr(r, "serialise key");

	ಪ್ರತಿ (i = 0; i < nhelpers; i++) {
		ಯದಿ (helpers[i] == ರಿಕ್ತ)
			ಅನುವರ್ತ;
		ಪ್ರತಿ (j = 0; j < helpers[i]->nkeyblobs; j++) {
			ಯದಿ (sshbuf_equals(keyblob,
			    helpers[i]->keyblobs[j]) == 0) {
				sshbuf_free(keyblob);
				ಪ್ರತ್ಯಾಗಮ helpers[i];
			}
		}
	}
	sshbuf_free(keyblob);
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;

}

ಸ್ಥಿರ ಶೂನ್ಯ
helper_add_ಕೀಲಿ(ಸಂರಚನಾ helper *helper, ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	helper->keyblobs = xrecallocarray(helper->keyblobs, helper->nkeyblobs,
	    helper->nkeyblobs + 1, ಪರಿಮಾಣ(*helper->keyblobs));
	ಯದಿ ((helper->keyblobs[helper->nkeyblobs] = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = sshkey_putb(ಕೀಲಿ, helper->keyblobs[helper->nkeyblobs])) != 0)
		fatal_fr(r, "shkey_putb failed");
	helper->nkeyblobs++;
	debug3_f("added %s key for provider %s, now has %zu keys",
	    sshkey_type(ಕೀಲಿ), helper->path, helper->nkeyblobs);
}

ಸ್ಥಿರ ಶೂನ್ಯ
helper_terminate(ಸಂರಚನಾ helper *helper)
{
	size_t i;
	ಪೂರ್ಣಾಙ್ಕ found = 0;

	ಯದಿ (helper == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	ಯದಿ (helper->path == ರಿಕ್ತ)
		fatal_f("inconsistent helper");

	debug3_f("terminating helper for %s; remaining %zu keys",
	    helper->path, helper->nkeyblobs);

	close(helper->fd);
	/* XXX waitpid() */
	helper->fd = -1;
	helper->pid = -1;

	/* repack helpers */
	ಪ್ರತಿ (i = 0; i < nhelpers; i++) {
		ಯದಿ (helpers[i] == helper) {
			ಯದಿ (found)
				fatal_f("helper recorded more than once");
			found = 1;
		} ಅನ್ಯಥಾ ಯದಿ (found)
			helpers[i - 1] = helpers[i];
	}
	ಯದಿ (found) {
		helpers = xrecallocarray(helpers, nhelpers,
		    nhelpers - 1, ಪರಿಮಾಣ(*helpers));
		nhelpers--;
	}
	ಪ್ರತಿ (i = 0; i < helper->nkeyblobs; i++)
		sshbuf_free(helper->keyblobs[i]);
	ಮುಕ್ತ(helper->path);
	ಮುಕ್ತ(helper);
}

ಸ್ಥಿರ ಶೂನ್ಯ
send_ಸಂದೇಶ(ಪೂರ್ಣಾಙ್ಕ fd, ಸಂರಚನಾ sshbuf *m)
{
	u_char buf[4];
	size_t mlen = sshbuf_len(m);
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (fd == -1)
		ಪ್ರತ್ಯಾಗಮ;
	POKE_U32(buf, mlen);
	ಯದಿ (atomicio(vwrite, fd, buf, 4) != 4 ||
	    atomicio(vwrite, fd, sshbuf_mutable_ptr(m),
	    sshbuf_len(m)) != sshbuf_len(m))
		error("write to helper failed");
	ಯದಿ ((r = sshbuf_consume(m, mlen)) != 0)
		fatal_fr(r, "consume");
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
recv_ಸಂದೇಶ(ಪೂರ್ಣಾಙ್ಕ fd, ಸಂರಚನಾ sshbuf *m)
{
	u_int l, len;
	u_char c, buf[1024];
	ಪೂರ್ಣಾಙ್ಕ r;

	sshbuf_reset(m);
	ಯದಿ (fd == -1)
		ಪ್ರತ್ಯಾಗಮ 0; /* XXX */
	ಯದಿ ((len = atomicio(ಪಠ, fd, buf, 4)) != 4) {
		error("read from helper failed: %u", len);
		ಪ್ರತ್ಯಾಗಮ (0); /* XXX */
	}
	len = PEEK_U32(buf);
	ಯದಿ (len > 256 * 1024)
		fatal("response too long: %u", len);
	/* read len bytes into m */
	ಯಾವತ್ (len > 0) {
		l = len;
		ಯದಿ (l > ಪರಿಮಾಣ(buf))
			l = ಪರಿಮಾಣ(buf);
		ಯದಿ (atomicio(ಪಠ, fd, buf, l) != l) {
			error("response from helper failed.");
			ಪ್ರತ್ಯಾಗಮ (0); /* XXX */
		}
		ಯದಿ ((r = sshbuf_put(m, buf, l)) != 0)
			fatal_fr(r, "sshbuf_put");
		len -= l;
	}
	ಯದಿ ((r = sshbuf_get_u8(m, &c)) != 0)
		fatal_fr(r, "parse type");
	ಪ್ರತ್ಯಾಗಮ c;
}

ಪೂರ್ಣಾಙ್ಕ
pkcs11_init(ಪೂರ್ಣಾಙ್ಕ interactive)
{
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಶೂನ್ಯ
pkcs11_terminate(ಶೂನ್ಯ)
{
	size_t i;

	debug3_f("terminating %zu helpers", nhelpers);
	ಪ್ರತಿ (i = 0; i < nhelpers; i++)
		helper_terminate(helpers[i]);
}

ಪೂರ್ಣಾಙ್ಕ
pkcs11_sign(ಸಂರಚನಾ sshkey *ಕೀಲಿ,
    u_char **sigp, size_t *lenp,
    ಧ್ರುವ u_char *data, size_t datalen,
    ಧ್ರುವ ವರ್ಣ *alg, ಧ್ರುವ ವರ್ಣ *sk_provider,
    ಧ್ರುವ ವರ್ಣ *sk_pin, u_int compat)
{
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ = ರಿಕ್ತ;
	ಸಂರಚನಾ helper *helper;
	ಪೂರ್ಣಾಙ್ಕ status, r;
	u_char *signature = ರಿಕ್ತ;
	size_t signature_len = 0;
	ಪೂರ್ಣಾಙ್ಕ ret = SSH_ERR_INTERNAL_ERROR;

	ಯದಿ (sigp != ರಿಕ್ತ)
		*sigp = ರಿಕ್ತ;
	ಯದಿ (lenp != ರಿಕ್ತ)
		*lenp = 0;

	ಯದಿ ((helper = helper_by_ಕೀಲಿ(ಕೀಲಿ)) == ರಿಕ್ತ || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(ಕೀಲಿ));

	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_AGENTC_SIGN_REQUEST)) != 0 ||
	    (r = sshkey_puts_plain(ಕೀಲಿ, ಸಂದೇಶ)) != 0 ||
	    (r = sshbuf_put_string(ಸಂದೇಶ, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, alg == ರಿಕ್ತ ? "" : alg)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, compat)) != 0)
		fatal_fr(r, "compose");
	send_ಸಂದೇಶ(helper->fd, ಸಂದೇಶ);
	sshbuf_reset(ಸಂದೇಶ);

	ಯದಿ ((status = recv_ಸಂದೇಶ(helper->fd, ಸಂದೇಶ)) != SSH2_AGENT_SIGN_RESPONSE) {
		/* XXX translate status to something useful */
		debug_fr(r, "recv_msg");
		ret = SSH_ERR_AGENT_FAILURE;
		ಗಚ್ಛ fail;
	}

	ಯದಿ ((r = sshbuf_get_string(ಸಂದೇಶ, &signature, &signature_len)) != 0)
		fatal_fr(r, "parse");

	/* success */
	ಯದಿ (sigp != ರಿಕ್ತ) {
		*sigp = signature;
		signature = ರಿಕ್ತ;
	}
	ಯದಿ (lenp != ರಿಕ್ತ)
		*lenp = signature_len;
	ret = 0;

 fail:
	ಮುಕ್ತ(signature);
	sshbuf_free(ಸಂದೇಶ);
	ಪ್ರತ್ಯಾಗಮ ret;
}

/*
 * Make a private PKCS#11-backed certificate by grafting a previously-loaded
 * PKCS#11 private key and a public certificate key.
 */
ಪೂರ್ಣಾಙ್ಕ
pkcs11_make_cert(ಧ್ರುವ ಸಂರಚನಾ sshkey *priv,
    ಧ್ರುವ ಸಂರಚನಾ sshkey *certpub, ಸಂರಚನಾ sshkey **certprivp)
{
	ಸಂರಚನಾ helper *helper = ರಿಕ್ತ;
	ಸಂರಚನಾ sshkey *ret;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((helper = helper_by_ಕೀಲಿ(priv)) == ರಿಕ್ತ || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(priv));

	debug3_f("private key type %s cert type %s on provider %s",
	    sshkey_type(priv), sshkey_type(certpub), helper->path);

	*certprivp = ರಿಕ್ತ;
	ಯದಿ (!sshkey_is_cert(certpub) || sshkey_is_cert(priv) ||
	    !sshkey_equal_public(priv, certpub)) {
		error_f("private key %s doesn't match cert %s",
		    sshkey_type(priv), sshkey_type(certpub));
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	}
	*certprivp = ರಿಕ್ತ;
	ಯದಿ ((r = sshkey_from_private(priv, &ret)) != 0)
		fatal_fr(r, "copy key");

	ret->flags |= SSHKEY_FLAG_EXT;
	ಯದಿ ((r = sshkey_to_certified(ret)) != 0 ||
	    (r = sshkey_cert_copy(certpub, ret)) != 0)
		fatal_fr(r, "graft certificate");

	helper_add_ಕೀಲಿ(helper, ret);

	debug3_f("provider %s: %zu remaining keys",
	    helper->path, helper->nkeyblobs);

	/* success */
	*certprivp = ret;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಸಂರಚನಾ helper *
pkcs11_start_helper(ಧ್ರುವ ವರ್ಣ *path)
{
	ಪೂರ್ಣಾಙ್ಕ pair[2];
	ವರ್ಣ *prog, *verbosity = ರಿಕ್ತ;
	ಸಂರಚನಾ helper *helper;
	pid_t pid;

	ಯದಿ (nhelpers >= INT_MAX)
		fatal_f("too many helpers");
	debug3_f("start helper for %s", path);
	ಯದಿ (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
		error_f("socketpair: %s", strerror(errno));
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	helper = xcalloc(1, ಪರಿಮಾಣ(*helper));
	ಯದಿ ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		close(pair[0]);
		close(pair[1]);
		ಮುಕ್ತ(helper);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	} ಅನ್ಯಥಾ ಯದಿ (pid == 0) {
		ಯದಿ ((dup2(pair[1], STDIN_FILENO) == -1) ||
		    (dup2(pair[1], STDOUT_FILENO) == -1)) {
			fprintf(stderr, "dup2: %s\n", strerror(errno));
			_exit(1);
		}
		close(pair[0]);
		close(pair[1]);
		closefrom(STDERR_FILENO + 1);
		prog = getenv("SSH_PKCS11_HELPER");
		ಯದಿ (prog == ರಿಕ್ತ || strlen(prog) == 0)
			prog = _PATH_SSH_PKCS11_HELPER;
		ಯದಿ (log_level_get() >= SYSLOG_LEVEL_DEBUG1)
			verbosity = "-vvv";
		debug_f("starting %s %s", prog,
		    verbosity == ರಿಕ್ತ ? "" : verbosity);
		execlp(prog, prog, verbosity, (ವರ್ಣ *)ರಿಕ್ತ);
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
	    nhelpers + 1, ಪರಿಮಾಣ(*helpers));
	helpers[nhelpers++] = helper;
	ಪ್ರತ್ಯಾಗಮ helper;
}

ಪೂರ್ಣಾಙ್ಕ
pkcs11_add_provider(ವರ್ಣ *name, ವರ್ಣ *pin, ಸಂರಚನಾ sshkey ***keysp,
    ವರ್ಣ ***labelsp)
{
	ಸಂರಚನಾ sshkey *k;
	ಪೂರ್ಣಾಙ್ಕ r, type;
	ವರ್ಣ *label;
	u_int ret = -1, nkeys, i;
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;
	ಸಂರಚನಾ helper *helper;

	ಯದಿ ((helper = helper_by_provider(name)) == ರಿಕ್ತ &&
	    (helper = pkcs11_start_helper(name)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ -1;

	debug3_f("add %s", helper->path);

	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH_AGENTC_ADD_SMARTCARD_ಕೀಲಿ)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, name)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, pin)) != 0)
		fatal_fr(r, "compose");
	send_ಸಂದೇಶ(helper->fd, ಸಂದೇಶ);
	sshbuf_reset(ಸಂದೇಶ);

	type = recv_ಸಂದೇಶ(helper->fd, ಸಂದೇಶ);
	debug3_f("response %d", type);
	ಯದಿ (type == SSH2_AGENT_IDENTITIES_ANSWER) {
		ಯದಿ ((r = sshbuf_get_u32(ಸಂದೇಶ, &nkeys)) != 0)
			fatal_fr(r, "parse nkeys");
		debug3_f("helper return %u keys", nkeys);
		*keysp = xcalloc(nkeys, ಪರಿಮಾಣ(ಸಂರಚನಾ sshkey *));
		ಯದಿ (labelsp)
			*labelsp = xcalloc(nkeys, ಪರಿಮಾಣ(ವರ್ಣ *));
		ಪ್ರತಿ (i = 0; i < nkeys; i++) {
			/* XXX clean up properly instead of fatal() */
			ಯದಿ ((r = sshkey_froms(ಸಂದೇಶ, &k)) != 0 ||
			    (r = sshbuf_get_cstring(ಸಂದೇಶ, &label, ರಿಕ್ತ)) != 0)
				fatal_fr(r, "parse key");
			k->flags |= SSHKEY_FLAG_EXT;
			helper_add_ಕೀಲಿ(helper, k);
			(*keysp)[i] = k;
			ಯದಿ (labelsp)
				(*labelsp)[i] = label;
			ಅನ್ಯಥಾ
				ಮುಕ್ತ(label);
		}
		/* success */
		ret = 0;
	} ಅನ್ಯಥಾ ಯದಿ (type == SSH2_AGENT_FAILURE) {
		ಯದಿ ((r = sshbuf_get_u32(ಸಂದೇಶ, &nkeys)) != 0)
			error_fr(r, "failed to parse failure response");
	}
	ಯದಿ (ret != 0) {
		debug_f("no keys; terminate helper");
		helper_terminate(helper);
	}
	sshbuf_free(ಸಂದೇಶ);
	ಪ್ರತ್ಯಾಗಮ ret == 0 ? (ಪೂರ್ಣಾಙ್ಕ)nkeys : -1;
}

ಪೂರ್ಣಾಙ್ಕ
pkcs11_del_provider(ವರ್ಣ *name)
{
	ಸಂರಚನಾ helper *helper;

	/*
	 * ssh-agent deletes keys before calling this, so the helper entry
	 * should be gone before we get here.
	 */
	debug3_f("delete %s", name ? name : "(null)");
	ಯದಿ ((helper = helper_by_provider(name)) != ರಿಕ್ತ)
		helper_terminate(helper);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಶೂನ್ಯ
pkcs11_ಕೀಲಿ_free(ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
	ಸಂರಚನಾ helper *helper;
	ಸಂರಚನಾ sshbuf *keyblob = ರಿಕ್ತ;
	size_t i;
	ಪೂರ್ಣಾಙ್ಕ r, found = 0;

	debug3_f("free %s key", sshkey_type(ಕೀಲಿ));

	ಯದಿ ((helper = helper_by_ಕೀಲಿ(ಕೀಲಿ)) == ರಿಕ್ತ || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(ಕೀಲಿ));
	ಯದಿ ((keyblob = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = sshkey_putb(ಕೀಲಿ, keyblob)) != 0)
		fatal_fr(r, "serialise key");

	/* repack keys */
	ಪ್ರತಿ (i = 0; i < helper->nkeyblobs; i++) {
		ಯದಿ (sshbuf_equals(keyblob, helper->keyblobs[i]) == 0) {
			ಯದಿ (found)
				fatal_f("key recorded more than once");
			found = 1;
		} ಅನ್ಯಥಾ ಯದಿ (found)
			helper->keyblobs[i - 1] = helper->keyblobs[i];
	}
	ಯದಿ (found) {
		helper->keyblobs = xrecallocarray(helper->keyblobs,
		    helper->nkeyblobs, helper->nkeyblobs - 1,
		    ಪರಿಮಾಣ(*helper->keyblobs));
		helper->nkeyblobs--;
	}
	ಯದಿ (helper->nkeyblobs == 0)
		helper_terminate(helper);
}
