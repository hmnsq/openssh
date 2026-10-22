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
ರಚನೆ helper {
	ಅಕ್ಷರ *ಮಾರ್ಗ;
	pid_t pid;
	ಪೂರ್ಣಾಂಕ fd;
	ಗಾತ್ರ_t nkeyblobs;
	ರಚನೆ sshbuf **keyblobs; /* XXX use a tree or something faster */
};
ಸ್ಥಿರ ರಚನೆ helper **helpers;
ಸ್ಥಿರ ಗಾತ್ರ_t nhelpers;

ಸ್ಥಿರ ರಚನೆ helper *
helper_by_provider(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ)
{
	ಗಾತ್ರ_t i;

	ಗಾಗಿ (i = 0; i < nhelpers; i++) {
		ಆದರೆ (helpers[i] == ಖಾಲಿ || helpers[i]->ಮಾರ್ಗ == ಖಾಲಿ ||
		    helpers[i]->fd == -1)
			ಮುಂದುವರಿ;
		ಆದರೆ (strcmp(helpers[i]->ಮಾರ್ಗ, ಮಾರ್ಗ) == 0)
			ಹಿಂತಿರುಗಿ helpers[i];
	}
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

ಸ್ಥಿರ ರಚನೆ helper *
helper_by_ಕೀಲಿ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ)
{
	ಗಾತ್ರ_t i, j;
	ರಚನೆ sshbuf *keyblob = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((keyblob = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = sshkey_putb(ಕೀಲಿ, keyblob)) != 0)
		fatal_fr(r, "serialise key");

	ಗಾಗಿ (i = 0; i < nhelpers; i++) {
		ಆದರೆ (helpers[i] == ಖಾಲಿ)
			ಮುಂದುವರಿ;
		ಗಾಗಿ (j = 0; j < helpers[i]->nkeyblobs; j++) {
			ಆದರೆ (sshbuf_equals(keyblob,
			    helpers[i]->keyblobs[j]) == 0) {
				sshbuf_free(keyblob);
				ಹಿಂತಿರುಗಿ helpers[i];
			}
		}
	}
	sshbuf_free(keyblob);
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;

}

ಸ್ಥಿರ ಶೂನ್ಯ
helper_ಕೂಡಿಸು_ಕೀಲಿ(ರಚನೆ helper *helper, ರಚನೆ sshkey *ಕೀಲಿ)
{
	ಪೂರ್ಣಾಂಕ r;

	helper->keyblobs = xrecallocarray(helper->keyblobs, helper->nkeyblobs,
	    helper->nkeyblobs + 1, ಗಾತ್ರ(*helper->keyblobs));
	ಆದರೆ ((helper->keyblobs[helper->nkeyblobs] = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = sshkey_putb(ಕೀಲಿ, helper->keyblobs[helper->nkeyblobs])) != 0)
		fatal_fr(r, "shkey_putb failed");
	helper->nkeyblobs++;
	debug3_f("added %s key for provider %s, now has %zu keys",
	    sshkey_type(ಕೀಲಿ), helper->ಮಾರ್ಗ, helper->nkeyblobs);
}

ಸ್ಥಿರ ಶೂನ್ಯ
helper_terminate(ರಚನೆ helper *helper)
{
	ಗಾತ್ರ_t i;
	ಪೂರ್ಣಾಂಕ ಸಿಕ್ಕಿತು = 0;

	ಆದರೆ (helper == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	ಆದರೆ (helper->ಮಾರ್ಗ == ಖಾಲಿ)
		fatal_f("inconsistent helper");

	debug3_f("terminating helper for %s; remaining %zu keys",
	    helper->ಮಾರ್ಗ, helper->nkeyblobs);

	close(helper->fd);
	/* XXX waitpid() */
	helper->fd = -1;
	helper->pid = -1;

	/* repack helpers */
	ಗಾಗಿ (i = 0; i < nhelpers; i++) {
		ಆದರೆ (helpers[i] == helper) {
			ಆದರೆ (ಸಿಕ್ಕಿತು)
				fatal_f("helper recorded more than once");
			ಸಿಕ್ಕಿತು = 1;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ಸಿಕ್ಕಿತು)
			helpers[i - 1] = helpers[i];
	}
	ಆದರೆ (ಸಿಕ್ಕಿತು) {
		helpers = xrecallocarray(helpers, nhelpers,
		    nhelpers - 1, ಗಾತ್ರ(*helpers));
		nhelpers--;
	}
	ಗಾಗಿ (i = 0; i < helper->nkeyblobs; i++)
		sshbuf_free(helper->keyblobs[i]);
	ಬಿಡುಗಡೆ(helper->ಮಾರ್ಗ);
	ಬಿಡುಗಡೆ(helper);
}

ಸ್ಥಿರ ಶೂನ್ಯ
send_ಸಂದೇಶ(ಪೂರ್ಣಾಂಕ fd, ರಚನೆ sshbuf *m)
{
	u_char buf[4];
	ಗಾತ್ರ_t mlen = sshbuf_len(m);
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (fd == -1)
		ಹಿಂತಿರುಗಿ;
	POKE_U32(buf, mlen);
	ಆದರೆ (atomicio(vwrite, fd, buf, 4) != 4 ||
	    atomicio(vwrite, fd, sshbuf_mutable_ptr(m),
	    sshbuf_len(m)) != sshbuf_len(m))
		error("write to helper failed");
	ಆದರೆ ((r = sshbuf_consume(m, mlen)) != 0)
		fatal_fr(r, "consume");
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
recv_ಸಂದೇಶ(ಪೂರ್ಣಾಂಕ fd, ರಚನೆ sshbuf *m)
{
	u_int l, len;
	u_char c, buf[1024];
	ಪೂರ್ಣಾಂಕ r;

	sshbuf_reset(m);
	ಆದರೆ (fd == -1)
		ಹಿಂತಿರುಗಿ 0; /* XXX */
	ಆದರೆ ((len = atomicio(ಪಠ, fd, buf, 4)) != 4) {
		error("read from helper failed: %u", len);
		ಹಿಂತಿರುಗಿ (0); /* XXX */
	}
	len = PEEK_U32(buf);
	ಆದರೆ (len > 256 * 1024)
		fatal("response too long: %u", len);
	/* read len bytes into m */
	ಆಗ (len > 0) {
		l = len;
		ಆದರೆ (l > ಗಾತ್ರ(buf))
			l = ಗಾತ್ರ(buf);
		ಆದರೆ (atomicio(ಪಠ, fd, buf, l) != l) {
			error("response from helper failed.");
			ಹಿಂತಿರುಗಿ (0); /* XXX */
		}
		ಆದರೆ ((r = sshbuf_put(m, buf, l)) != 0)
			fatal_fr(r, "sshbuf_put");
		len -= l;
	}
	ಆದರೆ ((r = sshbuf_get_u8(m, &c)) != 0)
		fatal_fr(r, "parse type");
	ಹಿಂತಿರುಗಿ c;
}

ಪೂರ್ಣಾಂಕ
pkcs11_init(ಪೂರ್ಣಾಂಕ interactive)
{
	ಹಿಂತಿರುಗಿ 0;
}

ಶೂನ್ಯ
pkcs11_terminate(ಶೂನ್ಯ)
{
	ಗಾತ್ರ_t i;

	debug3_f("terminating %zu helpers", nhelpers);
	ಗಾಗಿ (i = 0; i < nhelpers; i++)
		helper_terminate(helpers[i]);
}

ಪೂರ್ಣಾಂಕ
pkcs11_sign(ರಚನೆ sshkey *ಕೀಲಿ,
    u_char **sigp, ಗಾತ್ರ_t *lenp,
    ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ, ಗಾತ್ರ_t datalen,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *alg, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sk_provider,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sk_pin, u_int compat)
{
	ರಚನೆ sshbuf *ಸಂದೇಶ = ಖಾಲಿ;
	ರಚನೆ helper *helper;
	ಪೂರ್ಣಾಂಕ ಸ್ಥಿತಿ_2, r;
	u_char *signature = ಖಾಲಿ;
	ಗಾತ್ರ_t signature_len = 0;
	ಪೂರ್ಣಾಂಕ ret = SSH_ERR_ಆಂತರಿಕ_ERROR;

	ಆದರೆ (sigp != ಖಾಲಿ)
		*sigp = ಖಾಲಿ;
	ಆದರೆ (lenp != ಖಾಲಿ)
		*lenp = 0;

	ಆದರೆ ((helper = helper_by_ಕೀಲಿ(ಕೀಲಿ)) == ಖಾಲಿ || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(ಕೀಲಿ));

	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_AGENTC_SIGN_REQUEST)) != 0 ||
	    (r = sshkey_puts_plain(ಕೀಲಿ, ಸಂದೇಶ)) != 0 ||
	    (r = sshbuf_put_string(ಸಂದೇಶ, ದತ್ತಾಂಶ, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, alg == ಖಾಲಿ ? "" : alg)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, compat)) != 0)
		fatal_fr(r, "compose");
	send_ಸಂದೇಶ(helper->fd, ಸಂದೇಶ);
	sshbuf_reset(ಸಂದೇಶ);

	ಆದರೆ ((ಸ್ಥಿತಿ_2 = recv_ಸಂದೇಶ(helper->fd, ಸಂದೇಶ)) != SSH2_AGENT_SIGN_RESPONSE) {
		/* XXX translate status to something useful */
		debug_fr(r, "recv_msg");
		ret = SSH_ERR_AGENT_FAILURE;
		ಹೋಗು fail;
	}

	ಆದರೆ ((r = sshbuf_get_string(ಸಂದೇಶ, &signature, &signature_len)) != 0)
		fatal_fr(r, "parse");

	/* success */
	ಆದರೆ (sigp != ಖಾಲಿ) {
		*sigp = signature;
		signature = ಖಾಲಿ;
	}
	ಆದರೆ (lenp != ಖಾಲಿ)
		*lenp = signature_len;
	ret = 0;

 fail:
	ಬಿಡುಗಡೆ(signature);
	sshbuf_free(ಸಂದೇಶ);
	ಹಿಂತಿರುಗಿ ret;
}

/*
 * Make a private PKCS#11-backed certificate by grafting a previously-loaded
 * PKCS#11 private key and a public certificate key.
 */
ಪೂರ್ಣಾಂಕ
pkcs11_make_cert(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *priv,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *certpub, ರಚನೆ sshkey **certprivp)
{
	ರಚನೆ helper *helper = ಖಾಲಿ;
	ರಚನೆ sshkey *ret;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((helper = helper_by_ಕೀಲಿ(priv)) == ಖಾಲಿ || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(priv));

	debug3_f("private key type %s cert type %s on provider %s",
	    sshkey_type(priv), sshkey_type(certpub), helper->ಮಾರ್ಗ);

	*certprivp = ಖಾಲಿ;
	ಆದರೆ (!sshkey_is_cert(certpub) || sshkey_is_cert(priv) ||
	    !sshkey_equal_ಬಹಿರಂಗ(priv, certpub)) {
		error_f("private key %s doesn't match cert %s",
		    sshkey_type(priv), sshkey_type(certpub));
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	}
	*certprivp = ಖಾಲಿ;
	ಆದರೆ ((r = sshkey_from_ಖಾಸಗಿ(priv, &ret)) != 0)
		fatal_fr(r, "copy key");

	ret->flags |= SSHKEY_FLAG_EXT;
	ಆದರೆ ((r = sshkey_ಗಮ್ಯ_certified(ret)) != 0 ||
	    (r = sshkey_cert_copy(certpub, ret)) != 0)
		fatal_fr(r, "graft certificate");

	helper_ಕೂಡಿಸು_ಕೀಲಿ(helper, ret);

	debug3_f("provider %s: %zu remaining keys",
	    helper->ಮಾರ್ಗ, helper->nkeyblobs);

	/* success */
	*certprivp = ret;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ರಚನೆ helper *
pkcs11_ಆರಂಭ_helper(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ)
{
	ಪೂರ್ಣಾಂಕ pair[2];
	ಅಕ್ಷರ *prog, *verbosity = ಖಾಲಿ;
	ರಚನೆ helper *helper;
	pid_t pid;

	ಆದರೆ (nhelpers >= ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ)
		fatal_f("too many helpers");
	debug3_f("start helper for %s", ಮಾರ್ಗ);
	ಆದರೆ (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
		error_f("socketpair: %s", strerror(errno));
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	helper = xcalloc(1, ಗಾತ್ರ(*helper));
	ಆದರೆ ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		close(pair[0]);
		close(pair[1]);
		ಬಿಡುಗಡೆ(helper);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (pid == 0) {
		ಆದರೆ ((dup2(pair[1], STDIN_FILENO) == -1) ||
		    (dup2(pair[1], STDOUT_FILENO) == -1)) {
			fprintf(stderr, "dup2: %s\n", strerror(errno));
			_exit(1);
		}
		close(pair[0]);
		close(pair[1]);
		closefrom(STDERR_FILENO + 1);
		prog = getenv("SSH_PKCS11_HELPER");
		ಆದರೆ (prog == ಖಾಲಿ || ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(prog) == 0)
			prog = ಮಾರ್ಗ_SSH_PKCS11_HELPER;
		ಆದರೆ (log_level_get() >= SYSLOG_LEVEL_DEBUG1)
			verbosity = "-vvv";
		debug_f("starting %s %s", prog,
		    verbosity == ಖಾಲಿ ? "" : verbosity);
		execlp(prog, prog, verbosity, (ಅಕ್ಷರ *)ಖಾಲಿ);
		fprintf(stderr, "exec: %s: %s\n", prog, strerror(errno));
		_exit(1);
	}
	close(pair[1]);
	helper->fd = pair[0];
	helper->ಮಾರ್ಗ = xstrdup(ಮಾರ್ಗ);
	helper->pid = pid;
	debug3_f("helper %zu for \"%s\" on fd %d pid %ld", nhelpers,
	    helper->ಮಾರ್ಗ, helper->fd, (ದೀರ್ಘ)helper->pid);
	helpers = xrecallocarray(helpers, nhelpers,
	    nhelpers + 1, ಗಾತ್ರ(*helpers));
	helpers[nhelpers++] = helper;
	ಹಿಂತಿರುಗಿ helper;
}

ಪೂರ್ಣಾಂಕ
pkcs11_ಕೂಡಿಸು_provider(ಅಕ್ಷರ *name, ಅಕ್ಷರ *pin, ರಚನೆ sshkey ***keysp,
    ಅಕ್ಷರ ***labelsp)
{
	ರಚನೆ sshkey *k;
	ಪೂರ್ಣಾಂಕ r, type;
	ಅಕ್ಷರ *label;
	u_int ret = -1, nkeys, i;
	ರಚನೆ sshbuf *ಸಂದೇಶ;
	ರಚನೆ helper *helper;

	ಆದರೆ ((helper = helper_by_provider(name)) == ಖಾಲಿ &&
	    (helper = pkcs11_ಆರಂಭ_helper(name)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ -1;

	debug3_f("add %s", helper->ಮಾರ್ಗ);

	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH_AGENTC_ಕೂಡಿಸು_SMARTCARD_ಕೀಲಿ)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, name)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, pin)) != 0)
		fatal_fr(r, "compose");
	send_ಸಂದೇಶ(helper->fd, ಸಂದೇಶ);
	sshbuf_reset(ಸಂದೇಶ);

	type = recv_ಸಂದೇಶ(helper->fd, ಸಂದೇಶ);
	debug3_f("response %d", type);
	ಆದರೆ (type == SSH2_AGENT_IDENTITIES_ANSWER) {
		ಆದರೆ ((r = sshbuf_get_u32(ಸಂದೇಶ, &nkeys)) != 0)
			fatal_fr(r, "parse nkeys");
		debug3_f("helper return %u keys", nkeys);
		*keysp = xcalloc(nkeys, ಗಾತ್ರ(ರಚನೆ sshkey *));
		ಆದರೆ (labelsp)
			*labelsp = xcalloc(nkeys, ಗಾತ್ರ(ಅಕ್ಷರ *));
		ಗಾಗಿ (i = 0; i < nkeys; i++) {
			/* XXX clean up properly instead of fatal() */
			ಆದರೆ ((r = sshkey_froms(ಸಂದೇಶ, &k)) != 0 ||
			    (r = sshbuf_get_cstring(ಸಂದೇಶ, &label, ಖಾಲಿ)) != 0)
				fatal_fr(r, "parse key");
			k->flags |= SSHKEY_FLAG_EXT;
			helper_ಕೂಡಿಸು_ಕೀಲಿ(helper, k);
			(*keysp)[i] = k;
			ಆದರೆ (labelsp)
				(*labelsp)[i] = label;
			ಇಲ್ಲದಿದ್ದರೆ
				ಬಿಡುಗಡೆ(label);
		}
		/* success */
		ret = 0;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (type == SSH2_AGENT_FAILURE) {
		ಆದರೆ ((r = sshbuf_get_u32(ಸಂದೇಶ, &nkeys)) != 0)
			error_fr(r, "failed to parse failure response");
	}
	ಆದರೆ (ret != 0) {
		debug_f("no keys; terminate helper");
		helper_terminate(helper);
	}
	sshbuf_free(ಸಂದೇಶ);
	ಹಿಂತಿರುಗಿ ret == 0 ? (ಪೂರ್ಣಾಂಕ)nkeys : -1;
}

ಪೂರ್ಣಾಂಕ
pkcs11_del_provider(ಅಕ್ಷರ *name)
{
	ರಚನೆ helper *helper;

	/*
	 * ssh-agent deletes keys before calling this, so the helper entry
	 * should be gone before we get here.
	 */
	debug3_f("delete %s", name ? name : "(null)");
	ಆದರೆ ((helper = helper_by_provider(name)) != ಖಾಲಿ)
		helper_terminate(helper);
	ಹಿಂತಿರುಗಿ 0;
}

ಶೂನ್ಯ
pkcs11_ಕೀಲಿ_free(ರಚನೆ sshkey *ಕೀಲಿ)
{
	ರಚನೆ helper *helper;
	ರಚನೆ sshbuf *keyblob = ಖಾಲಿ;
	ಗಾತ್ರ_t i;
	ಪೂರ್ಣಾಂಕ r, ಸಿಕ್ಕಿತು = 0;

	debug3_f("free %s key", sshkey_type(ಕೀಲಿ));

	ಆದರೆ ((helper = helper_by_ಕೀಲಿ(ಕೀಲಿ)) == ಖಾಲಿ || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(ಕೀಲಿ));
	ಆದರೆ ((keyblob = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = sshkey_putb(ಕೀಲಿ, keyblob)) != 0)
		fatal_fr(r, "serialise key");

	/* repack keys */
	ಗಾಗಿ (i = 0; i < helper->nkeyblobs; i++) {
		ಆದರೆ (sshbuf_equals(keyblob, helper->keyblobs[i]) == 0) {
			ಆದರೆ (ಸಿಕ್ಕಿತು)
				fatal_f("key recorded more than once");
			ಸಿಕ್ಕಿತು = 1;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ಸಿಕ್ಕಿತು)
			helper->keyblobs[i - 1] = helper->keyblobs[i];
	}
	ಆದರೆ (ಸಿಕ್ಕಿತು) {
		helper->keyblobs = xrecallocarray(helper->keyblobs,
		    helper->nkeyblobs, helper->nkeyblobs - 1,
		    ಗಾತ್ರ(*helper->keyblobs));
		helper->nkeyblobs--;
	}
	ಆದರೆ (helper->nkeyblobs == 0)
		helper_terminate(helper);
}
