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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/time.h>
#అన్తర్భావ <sys/socket.h>

#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <errno.h>
#అన్తర్భావ <limits.h>

#అన్తర్భావ "pathnames.h"
#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "authfd.h"
#అన్తర్భావ "atomicio.h"
#అన్తర్భావ "ssh-pkcs11.h"
#అన్తర్భావ "ssherr.h"

/* borrows code from sftp-server and ssh-agent */

/*
 * Maintain a list of ssh-pkcs11-helper subprocesses. These may be looked up
 * by provider path or their unique keyblobs.
 */
నిర్మాణం helper {
	అక్షరం *మార్గం;
	pid_t pid;
	పూర్ణాంకం fd;
	కొలత_t nkeyblobs;
	నిర్మాణం sshbuf **keyblobs; /* XXX use a tree or something faster */
};
స్థిర నిర్మాణం helper **helpers;
స్థిర కొలత_t nhelpers;

స్థిర నిర్మాణం helper *
helper_by_provider(స్థిరరాశి అక్షరం *మార్గం)
{
	కొలత_t i;

	కొరకు (i = 0; i < nhelpers; i++) {
		ఒకవేళ (helpers[i] == ఖాళీ || helpers[i]->మార్గం == ఖాళీ ||
		    helpers[i]->fd == -1)
			కొనసాగు;
		ఒకవేళ (strcmp(helpers[i]->మార్గం, మార్గం) == 0)
			తిరిగి helpers[i];
	}
	తిరిగి ఖాళీ;
}

స్థిర నిర్మాణం helper *
helper_by_కీలకం(స్థిరరాశి నిర్మాణం sshkey *కీలకం)
{
	కొలత_t i, j;
	నిర్మాణం sshbuf *keyblob = ఖాళీ;
	పూర్ణాంకం r;

	ఒకవేళ ((keyblob = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = sshkey_putb(కీలకం, keyblob)) != 0)
		fatal_fr(r, "serialise key");

	కొరకు (i = 0; i < nhelpers; i++) {
		ఒకవేళ (helpers[i] == ఖాళీ)
			కొనసాగు;
		కొరకు (j = 0; j < helpers[i]->nkeyblobs; j++) {
			ఒకవేళ (sshbuf_equals(keyblob,
			    helpers[i]->keyblobs[j]) == 0) {
				sshbuf_free(keyblob);
				తిరిగి helpers[i];
			}
		}
	}
	sshbuf_free(keyblob);
	తిరిగి ఖాళీ;

}

స్థిర శూన్య
helper_కూడు_కీలకం(నిర్మాణం helper *helper, నిర్మాణం sshkey *కీలకం)
{
	పూర్ణాంకం r;

	helper->keyblobs = xrecallocarray(helper->keyblobs, helper->nkeyblobs,
	    helper->nkeyblobs + 1, పరిమాణం(*helper->keyblobs));
	ఒకవేళ ((helper->keyblobs[helper->nkeyblobs] = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = sshkey_putb(కీలకం, helper->keyblobs[helper->nkeyblobs])) != 0)
		fatal_fr(r, "shkey_putb failed");
	helper->nkeyblobs++;
	debug3_f("added %s key for provider %s, now has %zu keys",
	    sshkey_type(కీలకం), helper->మార్గం, helper->nkeyblobs);
}

స్థిర శూన్య
helper_terminate(నిర్మాణం helper *helper)
{
	కొలత_t i;
	పూర్ణాంకం దొరికింది = 0;

	ఒకవేళ (helper == ఖాళీ)
		తిరిగి;
	ఒకవేళ (helper->మార్గం == ఖాళీ)
		fatal_f("inconsistent helper");

	debug3_f("terminating helper for %s; remaining %zu keys",
	    helper->మార్గం, helper->nkeyblobs);

	close(helper->fd);
	/* XXX waitpid() */
	helper->fd = -1;
	helper->pid = -1;

	/* repack helpers */
	కొరకు (i = 0; i < nhelpers; i++) {
		ఒకవేళ (helpers[i] == helper) {
			ఒకవేళ (దొరికింది)
				fatal_f("helper recorded more than once");
			దొరికింది = 1;
		} లేకపోతే ఒకవేళ (దొరికింది)
			helpers[i - 1] = helpers[i];
	}
	ఒకవేళ (దొరికింది) {
		helpers = xrecallocarray(helpers, nhelpers,
		    nhelpers - 1, పరిమాణం(*helpers));
		nhelpers--;
	}
	కొరకు (i = 0; i < helper->nkeyblobs; i++)
		sshbuf_free(helper->keyblobs[i]);
	విడుదల(helper->మార్గం);
	విడుదల(helper);
}

స్థిర శూన్య
send_సందేశం(పూర్ణాంకం fd, నిర్మాణం sshbuf *m)
{
	u_char buf[4];
	కొలత_t mlen = sshbuf_len(m);
	పూర్ణాంకం r;

	ఒకవేళ (fd == -1)
		తిరిగి;
	POKE_U32(buf, mlen);
	ఒకవేళ (atomicio(vwrite, fd, buf, 4) != 4 ||
	    atomicio(vwrite, fd, sshbuf_mutable_ptr(m),
	    sshbuf_len(m)) != sshbuf_len(m))
		error("write to helper failed");
	ఒకవేళ ((r = sshbuf_consume(m, mlen)) != 0)
		fatal_fr(r, "consume");
}

స్థిర పూర్ణాంకం
recv_సందేశం(పూర్ణాంకం fd, నిర్మాణం sshbuf *m)
{
	u_int l, len;
	u_char c, buf[1024];
	పూర్ణాంకం r;

	sshbuf_reset(m);
	ఒకవేళ (fd == -1)
		తిరిగి 0; /* XXX */
	ఒకవేళ ((len = atomicio(పఠ, fd, buf, 4)) != 4) {
		error("read from helper failed: %u", len);
		తిరిగి (0); /* XXX */
	}
	len = PEEK_U32(buf);
	ఒకవేళ (len > 256 * 1024)
		fatal("response too long: %u", len);
	/* read len bytes into m */
	అయితే (len > 0) {
		l = len;
		ఒకవేళ (l > పరిమాణం(buf))
			l = పరిమాణం(buf);
		ఒకవేళ (atomicio(పఠ, fd, buf, l) != l) {
			error("response from helper failed.");
			తిరిగి (0); /* XXX */
		}
		ఒకవేళ ((r = sshbuf_put(m, buf, l)) != 0)
			fatal_fr(r, "sshbuf_put");
		len -= l;
	}
	ఒకవేళ ((r = sshbuf_get_u8(m, &c)) != 0)
		fatal_fr(r, "parse type");
	తిరిగి c;
}

పూర్ణాంకం
pkcs11_init(పూర్ణాంకం interactive)
{
	తిరిగి 0;
}

శూన్య
pkcs11_terminate(శూన్య)
{
	కొలత_t i;

	debug3_f("terminating %zu helpers", nhelpers);
	కొరకు (i = 0; i < nhelpers; i++)
		helper_terminate(helpers[i]);
}

పూర్ణాంకం
pkcs11_sign(నిర్మాణం sshkey *కీలకం,
    u_char **sigp, కొలత_t *lenp,
    స్థిరరాశి u_char *దత్తాంశం, కొలత_t datalen,
    స్థిరరాశి అక్షరం *alg, స్థిరరాశి అక్షరం *sk_provider,
    స్థిరరాశి అక్షరం *sk_pin, u_int compat)
{
	నిర్మాణం sshbuf *సందేశం = ఖాళీ;
	నిర్మాణం helper *helper;
	పూర్ణాంకం స్థితి_2, r;
	u_char *signature = ఖాళీ;
	కొలత_t signature_len = 0;
	పూర్ణాంకం ret = SSH_ERR_అంతర్గత_ERROR;

	ఒకవేళ (sigp != ఖాళీ)
		*sigp = ఖాళీ;
	ఒకవేళ (lenp != ఖాళీ)
		*lenp = 0;

	ఒకవేళ ((helper = helper_by_కీలకం(కీలకం)) == ఖాళీ || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(కీలకం));

	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ ((r = sshbuf_put_u8(సందేశం, SSH2_AGENTC_SIGN_REQUEST)) != 0 ||
	    (r = sshkey_puts_plain(కీలకం, సందేశం)) != 0 ||
	    (r = sshbuf_put_string(సందేశం, దత్తాంశం, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(సందేశం, alg == ఖాళీ ? "" : alg)) != 0 ||
	    (r = sshbuf_put_u32(సందేశం, compat)) != 0)
		fatal_fr(r, "compose");
	send_సందేశం(helper->fd, సందేశం);
	sshbuf_reset(సందేశం);

	ఒకవేళ ((స్థితి_2 = recv_సందేశం(helper->fd, సందేశం)) != SSH2_AGENT_SIGN_RESPONSE) {
		/* XXX translate status to something useful */
		debug_fr(r, "recv_msg");
		ret = SSH_ERR_AGENT_FAILURE;
		వెళ్ళు fail;
	}

	ఒకవేళ ((r = sshbuf_get_string(సందేశం, &signature, &signature_len)) != 0)
		fatal_fr(r, "parse");

	/* success */
	ఒకవేళ (sigp != ఖాళీ) {
		*sigp = signature;
		signature = ఖాళీ;
	}
	ఒకవేళ (lenp != ఖాళీ)
		*lenp = signature_len;
	ret = 0;

 fail:
	విడుదల(signature);
	sshbuf_free(సందేశం);
	తిరిగి ret;
}

/*
 * Make a private PKCS#11-backed certificate by grafting a previously-loaded
 * PKCS#11 private key and a public certificate key.
 */
పూర్ణాంకం
pkcs11_make_cert(స్థిరరాశి నిర్మాణం sshkey *priv,
    స్థిరరాశి నిర్మాణం sshkey *certpub, నిర్మాణం sshkey **certprivp)
{
	నిర్మాణం helper *helper = ఖాళీ;
	నిర్మాణం sshkey *ret;
	పూర్ణాంకం r;

	ఒకవేళ ((helper = helper_by_కీలకం(priv)) == ఖాళీ || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(priv));

	debug3_f("private key type %s cert type %s on provider %s",
	    sshkey_type(priv), sshkey_type(certpub), helper->మార్గం);

	*certprivp = ఖాళీ;
	ఒకవేళ (!sshkey_is_cert(certpub) || sshkey_is_cert(priv) ||
	    !sshkey_equal_ప్రజా(priv, certpub)) {
		error_f("private key %s doesn't match cert %s",
		    sshkey_type(priv), sshkey_type(certpub));
		తిరిగి SSH_ERR_INVALID_వాదం;
	}
	*certprivp = ఖాళీ;
	ఒకవేళ ((r = sshkey_from_వ్యక్తిగత(priv, &ret)) != 0)
		fatal_fr(r, "copy key");

	ret->flags |= SSHKEY_FLAG_EXT;
	ఒకవేళ ((r = sshkey_గమ్యం_certified(ret)) != 0 ||
	    (r = sshkey_cert_copy(certpub, ret)) != 0)
		fatal_fr(r, "graft certificate");

	helper_కూడు_కీలకం(helper, ret);

	debug3_f("provider %s: %zu remaining keys",
	    helper->మార్గం, helper->nkeyblobs);

	/* success */
	*certprivp = ret;
	తిరిగి 0;
}

స్థిర నిర్మాణం helper *
pkcs11_ప్రారంభం_helper(స్థిరరాశి అక్షరం *మార్గం)
{
	పూర్ణాంకం pair[2];
	అక్షరం *prog, *verbosity = ఖాళీ;
	నిర్మాణం helper *helper;
	pid_t pid;

	ఒకవేళ (nhelpers >= గరిష్ఠ_పూర్ణాంకం)
		fatal_f("too many helpers");
	debug3_f("start helper for %s", మార్గం);
	ఒకవేళ (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
		error_f("socketpair: %s", strerror(errno));
		తిరిగి ఖాళీ;
	}
	helper = xcalloc(1, పరిమాణం(*helper));
	ఒకవేళ ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		close(pair[0]);
		close(pair[1]);
		విడుదల(helper);
		తిరిగి ఖాళీ;
	} లేకపోతే ఒకవేళ (pid == 0) {
		ఒకవేళ ((dup2(pair[1], STDIN_FILENO) == -1) ||
		    (dup2(pair[1], STDOUT_FILENO) == -1)) {
			fprintf(stderr, "dup2: %s\n", strerror(errno));
			_exit(1);
		}
		close(pair[0]);
		close(pair[1]);
		closefrom(STDERR_FILENO + 1);
		prog = getenv("SSH_PKCS11_HELPER");
		ఒకవేళ (prog == ఖాళీ || అక్షరశ్రేణి_పొడవు(prog) == 0)
			prog = మార్గం_SSH_PKCS11_HELPER;
		ఒకవేళ (log_level_get() >= SYSLOG_LEVEL_DEBUG1)
			verbosity = "-vvv";
		debug_f("starting %s %s", prog,
		    verbosity == ఖాళీ ? "" : verbosity);
		execlp(prog, prog, verbosity, (అక్షరం *)ఖాళీ);
		fprintf(stderr, "exec: %s: %s\n", prog, strerror(errno));
		_exit(1);
	}
	close(pair[1]);
	helper->fd = pair[0];
	helper->మార్గం = xstrdup(మార్గం);
	helper->pid = pid;
	debug3_f("helper %zu for \"%s\" on fd %d pid %ld", nhelpers,
	    helper->మార్గం, helper->fd, (దీర్ఘ)helper->pid);
	helpers = xrecallocarray(helpers, nhelpers,
	    nhelpers + 1, పరిమాణం(*helpers));
	helpers[nhelpers++] = helper;
	తిరిగి helper;
}

పూర్ణాంకం
pkcs11_కూడు_provider(అక్షరం *name, అక్షరం *pin, నిర్మాణం sshkey ***keysp,
    అక్షరం ***labelsp)
{
	నిర్మాణం sshkey *k;
	పూర్ణాంకం r, type;
	అక్షరం *label;
	u_int ret = -1, nkeys, i;
	నిర్మాణం sshbuf *సందేశం;
	నిర్మాణం helper *helper;

	ఒకవేళ ((helper = helper_by_provider(name)) == ఖాళీ &&
	    (helper = pkcs11_ప్రారంభం_helper(name)) == ఖాళీ)
		తిరిగి -1;

	debug3_f("add %s", helper->మార్గం);

	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = sshbuf_put_u8(సందేశం, SSH_AGENTC_కూడు_SMARTCARD_కీలకం)) != 0 ||
	    (r = sshbuf_put_cstring(సందేశం, name)) != 0 ||
	    (r = sshbuf_put_cstring(సందేశం, pin)) != 0)
		fatal_fr(r, "compose");
	send_సందేశం(helper->fd, సందేశం);
	sshbuf_reset(సందేశం);

	type = recv_సందేశం(helper->fd, సందేశం);
	debug3_f("response %d", type);
	ఒకవేళ (type == SSH2_AGENT_IDENTITIES_ANSWER) {
		ఒకవేళ ((r = sshbuf_get_u32(సందేశం, &nkeys)) != 0)
			fatal_fr(r, "parse nkeys");
		debug3_f("helper return %u keys", nkeys);
		*keysp = xcalloc(nkeys, పరిమాణం(నిర్మాణం sshkey *));
		ఒకవేళ (labelsp)
			*labelsp = xcalloc(nkeys, పరిమాణం(అక్షరం *));
		కొరకు (i = 0; i < nkeys; i++) {
			/* XXX clean up properly instead of fatal() */
			ఒకవేళ ((r = sshkey_froms(సందేశం, &k)) != 0 ||
			    (r = sshbuf_get_cstring(సందేశం, &label, ఖాళీ)) != 0)
				fatal_fr(r, "parse key");
			k->flags |= SSHKEY_FLAG_EXT;
			helper_కూడు_కీలకం(helper, k);
			(*keysp)[i] = k;
			ఒకవేళ (labelsp)
				(*labelsp)[i] = label;
			లేకపోతే
				విడుదల(label);
		}
		/* success */
		ret = 0;
	} లేకపోతే ఒకవేళ (type == SSH2_AGENT_FAILURE) {
		ఒకవేళ ((r = sshbuf_get_u32(సందేశం, &nkeys)) != 0)
			error_fr(r, "failed to parse failure response");
	}
	ఒకవేళ (ret != 0) {
		debug_f("no keys; terminate helper");
		helper_terminate(helper);
	}
	sshbuf_free(సందేశం);
	తిరిగి ret == 0 ? (పూర్ణాంకం)nkeys : -1;
}

పూర్ణాంకం
pkcs11_del_provider(అక్షరం *name)
{
	నిర్మాణం helper *helper;

	/*
	 * ssh-agent deletes keys before calling this, so the helper entry
	 * should be gone before we get here.
	 */
	debug3_f("delete %s", name ? name : "(null)");
	ఒకవేళ ((helper = helper_by_provider(name)) != ఖాళీ)
		helper_terminate(helper);
	తిరిగి 0;
}

శూన్య
pkcs11_కీలకం_free(నిర్మాణం sshkey *కీలకం)
{
	నిర్మాణం helper *helper;
	నిర్మాణం sshbuf *keyblob = ఖాళీ;
	కొలత_t i;
	పూర్ణాంకం r, దొరికింది = 0;

	debug3_f("free %s key", sshkey_type(కీలకం));

	ఒకవేళ ((helper = helper_by_కీలకం(కీలకం)) == ఖాళీ || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(కీలకం));
	ఒకవేళ ((keyblob = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = sshkey_putb(కీలకం, keyblob)) != 0)
		fatal_fr(r, "serialise key");

	/* repack keys */
	కొరకు (i = 0; i < helper->nkeyblobs; i++) {
		ఒకవేళ (sshbuf_equals(keyblob, helper->keyblobs[i]) == 0) {
			ఒకవేళ (దొరికింది)
				fatal_f("key recorded more than once");
			దొరికింది = 1;
		} లేకపోతే ఒకవేళ (దొరికింది)
			helper->keyblobs[i - 1] = helper->keyblobs[i];
	}
	ఒకవేళ (దొరికింది) {
		helper->keyblobs = xrecallocarray(helper->keyblobs,
		    helper->nkeyblobs, helper->nkeyblobs - 1,
		    పరిమాణం(*helper->keyblobs));
		helper->nkeyblobs--;
	}
	ఒకవేళ (helper->nkeyblobs == 0)
		helper_terminate(helper);
}
