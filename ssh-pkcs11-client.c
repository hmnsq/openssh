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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/time.h>
#ଅନ୍ତର୍ଭାଵ <sys/socket.h>

#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>

#ଅନ୍ତର୍ଭାଵ "pathnames.h"
#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "authfd.h"
#ଅନ୍ତର୍ଭାଵ "atomicio.h"
#ଅନ୍ତର୍ଭାଵ "ssh-pkcs11.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"

/* borrows code from sftp-server and ssh-agent */

/*
 * Maintain a list of ssh-pkcs11-helper subprocesses. These may be looked up
 * by provider path or their unique keyblobs.
 */
ସଂରଚନା helper {
	ଅକ୍ଷର *path;
	pid_t pid;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd;
	size_t nkeyblobs;
	ସଂରଚନା sshbuf **keyblobs; /* XXX use a tree or something faster */
};
ସ୍ଥିର ସଂରଚନା helper **helpers;
ସ୍ଥିର size_t nhelpers;

ସ୍ଥିର ସଂରଚନା helper *
helper_by_provider(ଅଚଳ ଅକ୍ଷର *path)
{
	size_t i;

	ପାଇଁ (i = 0; i < nhelpers; i++) {
		ଯଦି (helpers[i] == ଖାଲି || helpers[i]->path == ଖାଲି ||
		    helpers[i]->fd == -1)
			ଜାରି;
		ଯଦି (strcmp(helpers[i]->path, path) == 0)
			ଫେରନ୍ତୁ helpers[i];
	}
	ଫେରନ୍ତୁ ଖାଲି;
}

ସ୍ଥିର ସଂରଚନା helper *
helper_by_ଚାବି(ଅଚଳ ସଂରଚନା sshkey *ଚାବି)
{
	size_t i, j;
	ସଂରଚନା sshbuf *keyblob = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((keyblob = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = sshkey_putb(ଚାବି, keyblob)) != 0)
		fatal_fr(r, "serialise key");

	ପାଇଁ (i = 0; i < nhelpers; i++) {
		ଯଦି (helpers[i] == ଖାଲି)
			ଜାରି;
		ପାଇଁ (j = 0; j < helpers[i]->nkeyblobs; j++) {
			ଯଦି (sshbuf_equals(keyblob,
			    helpers[i]->keyblobs[j]) == 0) {
				sshbuf_free(keyblob);
				ଫେରନ୍ତୁ helpers[i];
			}
		}
	}
	sshbuf_free(keyblob);
	ଫେରନ୍ତୁ ଖାଲି;

}

ସ୍ଥିର ଶୂନ୍ୟ
helper_add_ଚାବି(ସଂରଚନା helper *helper, ସଂରଚନା sshkey *ଚାବି)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	helper->keyblobs = xrecallocarray(helper->keyblobs, helper->nkeyblobs,
	    helper->nkeyblobs + 1, ଆକାର(*helper->keyblobs));
	ଯଦି ((helper->keyblobs[helper->nkeyblobs] = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = sshkey_putb(ଚାବି, helper->keyblobs[helper->nkeyblobs])) != 0)
		fatal_fr(r, "shkey_putb failed");
	helper->nkeyblobs++;
	debug3_f("added %s key for provider %s, now has %zu keys",
	    sshkey_type(ଚାବି), helper->path, helper->nkeyblobs);
}

ସ୍ଥିର ଶୂନ୍ୟ
helper_terminate(ସଂରଚନା helper *helper)
{
	size_t i;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା found = 0;

	ଯଦି (helper == ଖାଲି)
		ଫେରନ୍ତୁ;
	ଯଦି (helper->path == ଖାଲି)
		fatal_f("inconsistent helper");

	debug3_f("terminating helper for %s; remaining %zu keys",
	    helper->path, helper->nkeyblobs);

	close(helper->fd);
	/* XXX waitpid() */
	helper->fd = -1;
	helper->pid = -1;

	/* repack helpers */
	ପାଇଁ (i = 0; i < nhelpers; i++) {
		ଯଦି (helpers[i] == helper) {
			ଯଦି (found)
				fatal_f("helper recorded more than once");
			found = 1;
		} ଅନ୍ୟଥା ଯଦି (found)
			helpers[i - 1] = helpers[i];
	}
	ଯଦି (found) {
		helpers = xrecallocarray(helpers, nhelpers,
		    nhelpers - 1, ଆକାର(*helpers));
		nhelpers--;
	}
	ପାଇଁ (i = 0; i < helper->nkeyblobs; i++)
		sshbuf_free(helper->keyblobs[i]);
	ମୁକ୍ତ(helper->path);
	ମୁକ୍ତ(helper);
}

ସ୍ଥିର ଶୂନ୍ୟ
send_ସନ୍ଦେଶ(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, ସଂରଚନା sshbuf *m)
{
	u_char buf[4];
	size_t mlen = sshbuf_len(m);
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (fd == -1)
		ଫେରନ୍ତୁ;
	POKE_U32(buf, mlen);
	ଯଦି (atomicio(vwrite, fd, buf, 4) != 4 ||
	    atomicio(vwrite, fd, sshbuf_mutable_ptr(m),
	    sshbuf_len(m)) != sshbuf_len(m))
		error("write to helper failed");
	ଯଦି ((r = sshbuf_consume(m, mlen)) != 0)
		fatal_fr(r, "consume");
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
recv_ସନ୍ଦେଶ(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, ସଂରଚନା sshbuf *m)
{
	u_int l, len;
	u_char c, buf[1024];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	sshbuf_reset(m);
	ଯଦି (fd == -1)
		ଫେରନ୍ତୁ 0; /* XXX */
	ଯଦି ((len = atomicio(ପଠ, fd, buf, 4)) != 4) {
		error("read from helper failed: %u", len);
		ଫେରନ୍ତୁ (0); /* XXX */
	}
	len = PEEK_U32(buf);
	ଯଦି (len > 256 * 1024)
		fatal("response too long: %u", len);
	/* read len bytes into m */
	ଯେତେବେଳେ (len > 0) {
		l = len;
		ଯଦି (l > ଆକାର(buf))
			l = ଆକାର(buf);
		ଯଦି (atomicio(ପଠ, fd, buf, l) != l) {
			error("response from helper failed.");
			ଫେରନ୍ତୁ (0); /* XXX */
		}
		ଯଦି ((r = sshbuf_put(m, buf, l)) != 0)
			fatal_fr(r, "sshbuf_put");
		len -= l;
	}
	ଯଦି ((r = sshbuf_get_u8(m, &c)) != 0)
		fatal_fr(r, "parse type");
	ଫେରନ୍ତୁ c;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pkcs11_init(ପୂର୍ଣ୍ଣସଂଖ୍ୟା interactive)
{
	ଫେରନ୍ତୁ 0;
}

ଶୂନ୍ୟ
pkcs11_terminate(ଶୂନ୍ୟ)
{
	size_t i;

	debug3_f("terminating %zu helpers", nhelpers);
	ପାଇଁ (i = 0; i < nhelpers; i++)
		helper_terminate(helpers[i]);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pkcs11_sign(ସଂରଚନା sshkey *ଚାବି,
    u_char **sigp, size_t *lenp,
    ଅଚଳ u_char *data, size_t datalen,
    ଅଚଳ ଅକ୍ଷର *alg, ଅଚଳ ଅକ୍ଷର *sk_provider,
    ଅଚଳ ଅକ୍ଷର *sk_pin, u_int compat)
{
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ = ଖାଲି;
	ସଂରଚନା helper *helper;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା status, r;
	u_char *signature = ଖାଲି;
	size_t signature_len = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = SSH_ERR_INTERNAL_ERROR;

	ଯଦି (sigp != ଖାଲି)
		*sigp = ଖାଲି;
	ଯଦି (lenp != ଖାଲି)
		*lenp = 0;

	ଯଦି ((helper = helper_by_ଚାବି(ଚାବି)) == ଖାଲି || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(ଚାବି));

	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, SSH2_AGENTC_SIGN_REQUEST)) != 0 ||
	    (r = sshkey_puts_plain(ଚାବି, ସନ୍ଦେଶ)) != 0 ||
	    (r = sshbuf_put_string(ସନ୍ଦେଶ, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(ସନ୍ଦେଶ, alg == ଖାଲି ? "" : alg)) != 0 ||
	    (r = sshbuf_put_u32(ସନ୍ଦେଶ, compat)) != 0)
		fatal_fr(r, "compose");
	send_ସନ୍ଦେଶ(helper->fd, ସନ୍ଦେଶ);
	sshbuf_reset(ସନ୍ଦେଶ);

	ଯଦି ((status = recv_ସନ୍ଦେଶ(helper->fd, ସନ୍ଦେଶ)) != SSH2_AGENT_SIGN_RESPONSE) {
		/* XXX translate status to something useful */
		debug_fr(r, "recv_msg");
		ret = SSH_ERR_AGENT_FAILURE;
		ଯାଅ fail;
	}

	ଯଦି ((r = sshbuf_get_string(ସନ୍ଦେଶ, &signature, &signature_len)) != 0)
		fatal_fr(r, "parse");

	/* success */
	ଯଦି (sigp != ଖାଲି) {
		*sigp = signature;
		signature = ଖାଲି;
	}
	ଯଦି (lenp != ଖାଲି)
		*lenp = signature_len;
	ret = 0;

 fail:
	ମୁକ୍ତ(signature);
	sshbuf_free(ସନ୍ଦେଶ);
	ଫେରନ୍ତୁ ret;
}

/*
 * Make a private PKCS#11-backed certificate by grafting a previously-loaded
 * PKCS#11 private key and a public certificate key.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pkcs11_make_cert(ଅଚଳ ସଂରଚନା sshkey *priv,
    ଅଚଳ ସଂରଚନା sshkey *certpub, ସଂରଚନା sshkey **certprivp)
{
	ସଂରଚନା helper *helper = ଖାଲି;
	ସଂରଚନା sshkey *ret;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((helper = helper_by_ଚାବି(priv)) == ଖାଲି || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(priv));

	debug3_f("private key type %s cert type %s on provider %s",
	    sshkey_type(priv), sshkey_type(certpub), helper->path);

	*certprivp = ଖାଲି;
	ଯଦି (!sshkey_is_cert(certpub) || sshkey_is_cert(priv) ||
	    !sshkey_equal_public(priv, certpub)) {
		error_f("private key %s doesn't match cert %s",
		    sshkey_type(priv), sshkey_type(certpub));
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	}
	*certprivp = ଖାଲି;
	ଯଦି ((r = sshkey_from_private(priv, &ret)) != 0)
		fatal_fr(r, "copy key");

	ret->flags |= SSHKEY_FLAG_EXT;
	ଯଦି ((r = sshkey_to_certified(ret)) != 0 ||
	    (r = sshkey_cert_copy(certpub, ret)) != 0)
		fatal_fr(r, "graft certificate");

	helper_add_ଚାବି(helper, ret);

	debug3_f("provider %s: %zu remaining keys",
	    helper->path, helper->nkeyblobs);

	/* success */
	*certprivp = ret;
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ସଂରଚନା helper *
pkcs11_start_helper(ଅଚଳ ଅକ୍ଷର *path)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା pair[2];
	ଅକ୍ଷର *prog, *verbosity = ଖାଲି;
	ସଂରଚନା helper *helper;
	pid_t pid;

	ଯଦି (nhelpers >= INT_MAX)
		fatal_f("too many helpers");
	debug3_f("start helper for %s", path);
	ଯଦି (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
		error_f("socketpair: %s", strerror(errno));
		ଫେରନ୍ତୁ ଖାଲି;
	}
	helper = xcalloc(1, ଆକାର(*helper));
	ଯଦି ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		close(pair[0]);
		close(pair[1]);
		ମୁକ୍ତ(helper);
		ଫେରନ୍ତୁ ଖାଲି;
	} ଅନ୍ୟଥା ଯଦି (pid == 0) {
		ଯଦି ((dup2(pair[1], STDIN_FILENO) == -1) ||
		    (dup2(pair[1], STDOUT_FILENO) == -1)) {
			fprintf(stderr, "dup2: %s\n", strerror(errno));
			_exit(1);
		}
		close(pair[0]);
		close(pair[1]);
		closefrom(STDERR_FILENO + 1);
		prog = getenv("SSH_PKCS11_HELPER");
		ଯଦି (prog == ଖାଲି || strlen(prog) == 0)
			prog = _PATH_SSH_PKCS11_HELPER;
		ଯଦି (log_level_get() >= SYSLOG_LEVEL_DEBUG1)
			verbosity = "-vvv";
		debug_f("starting %s %s", prog,
		    verbosity == ଖାଲି ? "" : verbosity);
		execlp(prog, prog, verbosity, (ଅକ୍ଷର *)ଖାଲି);
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
	    nhelpers + 1, ଆକାର(*helpers));
	helpers[nhelpers++] = helper;
	ଫେରନ୍ତୁ helper;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pkcs11_add_provider(ଅକ୍ଷର *name, ଅକ୍ଷର *pin, ସଂରଚନା sshkey ***keysp,
    ଅକ୍ଷର ***labelsp)
{
	ସଂରଚନା sshkey *k;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, type;
	ଅକ୍ଷର *label;
	u_int ret = -1, nkeys, i;
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;
	ସଂରଚନା helper *helper;

	ଯଦି ((helper = helper_by_provider(name)) == ଖାଲି &&
	    (helper = pkcs11_start_helper(name)) == ଖାଲି)
		ଫେରନ୍ତୁ -1;

	debug3_f("add %s", helper->path);

	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, SSH_AGENTC_ADD_SMARTCARD_ଚାବି)) != 0 ||
	    (r = sshbuf_put_cstring(ସନ୍ଦେଶ, name)) != 0 ||
	    (r = sshbuf_put_cstring(ସନ୍ଦେଶ, pin)) != 0)
		fatal_fr(r, "compose");
	send_ସନ୍ଦେଶ(helper->fd, ସନ୍ଦେଶ);
	sshbuf_reset(ସନ୍ଦେଶ);

	type = recv_ସନ୍ଦେଶ(helper->fd, ସନ୍ଦେଶ);
	debug3_f("response %d", type);
	ଯଦି (type == SSH2_AGENT_IDENTITIES_ANSWER) {
		ଯଦି ((r = sshbuf_get_u32(ସନ୍ଦେଶ, &nkeys)) != 0)
			fatal_fr(r, "parse nkeys");
		debug3_f("helper return %u keys", nkeys);
		*keysp = xcalloc(nkeys, ଆକାର(ସଂରଚନା sshkey *));
		ଯଦି (labelsp)
			*labelsp = xcalloc(nkeys, ଆକାର(ଅକ୍ଷର *));
		ପାଇଁ (i = 0; i < nkeys; i++) {
			/* XXX clean up properly instead of fatal() */
			ଯଦି ((r = sshkey_froms(ସନ୍ଦେଶ, &k)) != 0 ||
			    (r = sshbuf_get_cstring(ସନ୍ଦେଶ, &label, ଖାଲି)) != 0)
				fatal_fr(r, "parse key");
			k->flags |= SSHKEY_FLAG_EXT;
			helper_add_ଚାବି(helper, k);
			(*keysp)[i] = k;
			ଯଦି (labelsp)
				(*labelsp)[i] = label;
			ଅନ୍ୟଥା
				ମୁକ୍ତ(label);
		}
		/* success */
		ret = 0;
	} ଅନ୍ୟଥା ଯଦି (type == SSH2_AGENT_FAILURE) {
		ଯଦି ((r = sshbuf_get_u32(ସନ୍ଦେଶ, &nkeys)) != 0)
			error_fr(r, "failed to parse failure response");
	}
	ଯଦି (ret != 0) {
		debug_f("no keys; terminate helper");
		helper_terminate(helper);
	}
	sshbuf_free(ସନ୍ଦେଶ);
	ଫେରନ୍ତୁ ret == 0 ? (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)nkeys : -1;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pkcs11_del_provider(ଅକ୍ଷର *name)
{
	ସଂରଚନା helper *helper;

	/*
	 * ssh-agent deletes keys before calling this, so the helper entry
	 * should be gone before we get here.
	 */
	debug3_f("delete %s", name ? name : "(null)");
	ଯଦି ((helper = helper_by_provider(name)) != ଖାଲି)
		helper_terminate(helper);
	ଫେରନ୍ତୁ 0;
}

ଶୂନ୍ୟ
pkcs11_ଚାବି_free(ସଂରଚନା sshkey *ଚାବି)
{
	ସଂରଚନା helper *helper;
	ସଂରଚନା sshbuf *keyblob = ଖାଲି;
	size_t i;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, found = 0;

	debug3_f("free %s key", sshkey_type(ଚାବି));

	ଯଦି ((helper = helper_by_ଚାବି(ଚାବି)) == ଖାଲି || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(ଚାବି));
	ଯଦି ((keyblob = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = sshkey_putb(ଚାବି, keyblob)) != 0)
		fatal_fr(r, "serialise key");

	/* repack keys */
	ପାଇଁ (i = 0; i < helper->nkeyblobs; i++) {
		ଯଦି (sshbuf_equals(keyblob, helper->keyblobs[i]) == 0) {
			ଯଦି (found)
				fatal_f("key recorded more than once");
			found = 1;
		} ଅନ୍ୟଥା ଯଦି (found)
			helper->keyblobs[i - 1] = helper->keyblobs[i];
	}
	ଯଦି (found) {
		helper->keyblobs = xrecallocarray(helper->keyblobs,
		    helper->nkeyblobs, helper->nkeyblobs - 1,
		    ଆକାର(*helper->keyblobs));
		helper->nkeyblobs--;
	}
	ଯଦି (helper->nkeyblobs == 0)
		helper_terminate(helper);
}
