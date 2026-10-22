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
	حرف *رستہ;
	pid_t pid;
	صحيح fd;
	ناپ_t nkeyblobs;
	بنية sshbuf **keyblobs; /* XXX use a tree or something faster */
};
ساكن بنية helper **helpers;
ساكن ناپ_t nhelpers;

ساكن بنية helper *
helper_by_provider(ثابت حرف *رستہ)
{
	ناپ_t i;

	لكل (i = 0; i < nhelpers; i++) {
		إذا (helpers[i] == عدم || helpers[i]->رستہ == عدم ||
		    helpers[i]->fd == -1)
			استمر;
		إذا (strcmp(helpers[i]->رستہ, رستہ) == 0)
			أرجع helpers[i];
	}
	أرجع عدم;
}

ساكن بنية helper *
helper_by_کلید(ثابت بنية sshkey *کلید)
{
	ناپ_t i, j;
	بنية sshbuf *keyblob = عدم;
	صحيح r;

	إذا ((keyblob = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshkey_putb(کلید, keyblob)) != 0)
		fatal_fr(r, "serialise key");

	لكل (i = 0; i < nhelpers; i++) {
		إذا (helpers[i] == عدم)
			استمر;
		لكل (j = 0; j < helpers[i]->nkeyblobs; j++) {
			إذا (sshbuf_equals(keyblob,
			    helpers[i]->keyblobs[j]) == 0) {
				sshbuf_free(keyblob);
				أرجع helpers[i];
			}
		}
	}
	sshbuf_free(keyblob);
	أرجع عدم;

}

ساكن فراغ
helper_جوڑو_کلید(بنية helper *helper, بنية sshkey *کلید)
{
	صحيح r;

	helper->keyblobs = xrecallocarray(helper->keyblobs, helper->nkeyblobs,
	    helper->nkeyblobs + 1, حجم(*helper->keyblobs));
	إذا ((helper->keyblobs[helper->nkeyblobs] = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshkey_putb(کلید, helper->keyblobs[helper->nkeyblobs])) != 0)
		fatal_fr(r, "shkey_putb failed");
	helper->nkeyblobs++;
	debug3_f("added %s key for provider %s, now has %zu keys",
	    sshkey_type(کلید), helper->رستہ, helper->nkeyblobs);
}

ساكن فراغ
helper_terminate(بنية helper *helper)
{
	ناپ_t i;
	صحيح لبھیا = 0;

	إذا (helper == عدم)
		أرجع;
	إذا (helper->رستہ == عدم)
		fatal_f("inconsistent helper");

	debug3_f("terminating helper for %s; remaining %zu keys",
	    helper->رستہ, helper->nkeyblobs);

	close(helper->fd);
	/* XXX waitpid() */
	helper->fd = -1;
	helper->pid = -1;

	/* repack helpers */
	لكل (i = 0; i < nhelpers; i++) {
		إذا (helpers[i] == helper) {
			إذا (لبھیا)
				fatal_f("helper recorded more than once");
			لبھیا = 1;
		} وإلا إذا (لبھیا)
			helpers[i - 1] = helpers[i];
	}
	إذا (لبھیا) {
		helpers = xrecallocarray(helpers, nhelpers,
		    nhelpers - 1, حجم(*helpers));
		nhelpers--;
	}
	لكل (i = 0; i < helper->nkeyblobs; i++)
		sshbuf_free(helper->keyblobs[i]);
	حرر(helper->رستہ);
	حرر(helper);
}

ساكن فراغ
send_پیغام(صحيح fd, بنية sshbuf *m)
{
	u_char buf[4];
	ناپ_t mlen = sshbuf_len(m);
	صحيح r;

	إذا (fd == -1)
		أرجع;
	POKE_U32(buf, mlen);
	إذا (atomicio(vwrite, fd, buf, 4) != 4 ||
	    atomicio(vwrite, fd, sshbuf_mutable_ptr(m),
	    sshbuf_len(m)) != sshbuf_len(m))
		error("write to helper failed");
	إذا ((r = sshbuf_consume(m, mlen)) != 0)
		fatal_fr(r, "consume");
}

ساكن صحيح
recv_پیغام(صحيح fd, بنية sshbuf *m)
{
	u_int l, len;
	u_char c, buf[1024];
	صحيح r;

	sshbuf_reset(m);
	إذا (fd == -1)
		أرجع 0; /* XXX */
	إذا ((len = atomicio(اقرأ, fd, buf, 4)) != 4) {
		error("read from helper failed: %u", len);
		أرجع (0); /* XXX */
	}
	len = PEEK_U32(buf);
	إذا (len > 256 * 1024)
		fatal("response too long: %u", len);
	/* read len bytes into m */
	طالما (len > 0) {
		l = len;
		إذا (l > حجم(buf))
			l = حجم(buf);
		إذا (atomicio(اقرأ, fd, buf, l) != l) {
			error("response from helper failed.");
			أرجع (0); /* XXX */
		}
		إذا ((r = sshbuf_put(m, buf, l)) != 0)
			fatal_fr(r, "sshbuf_put");
		len -= l;
	}
	إذا ((r = sshbuf_get_u8(m, &c)) != 0)
		fatal_fr(r, "parse type");
	أرجع c;
}

صحيح
pkcs11_init(صحيح interactive)
{
	أرجع 0;
}

فراغ
pkcs11_terminate(فراغ)
{
	ناپ_t i;

	debug3_f("terminating %zu helpers", nhelpers);
	لكل (i = 0; i < nhelpers; i++)
		helper_terminate(helpers[i]);
}

صحيح
pkcs11_sign(بنية sshkey *کلید,
    u_char **sigp, ناپ_t *lenp,
    ثابت u_char *انکڑے, ناپ_t datalen,
    ثابت حرف *alg, ثابت حرف *sk_provider,
    ثابت حرف *sk_pin, u_int compat)
{
	بنية sshbuf *پیغام = عدم;
	بنية helper *helper;
	صحيح حالت, r;
	u_char *signature = عدم;
	ناپ_t signature_len = 0;
	صحيح ret = SSH_ERR_اندرونی_ERROR;

	إذا (sigp != عدم)
		*sigp = عدم;
	إذا (lenp != عدم)
		*lenp = 0;

	إذا ((helper = helper_by_کلید(کلید)) == عدم || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(کلید));

	إذا ((پیغام = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshbuf_put_u8(پیغام, SSH2_AGENTC_SIGN_REQUEST)) != 0 ||
	    (r = sshkey_puts_plain(کلید, پیغام)) != 0 ||
	    (r = sshbuf_put_string(پیغام, انکڑے, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(پیغام, alg == عدم ? "" : alg)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, compat)) != 0)
		fatal_fr(r, "compose");
	send_پیغام(helper->fd, پیغام);
	sshbuf_reset(پیغام);

	إذا ((حالت = recv_پیغام(helper->fd, پیغام)) != SSH2_AGENT_SIGN_RESPONSE) {
		/* XXX translate status to something useful */
		debug_fr(r, "recv_msg");
		ret = SSH_ERR_AGENT_FAILURE;
		اذهب fail;
	}

	إذا ((r = sshbuf_get_string(پیغام, &signature, &signature_len)) != 0)
		fatal_fr(r, "parse");

	/* success */
	إذا (sigp != عدم) {
		*sigp = signature;
		signature = عدم;
	}
	إذا (lenp != عدم)
		*lenp = signature_len;
	ret = 0;

 fail:
	حرر(signature);
	sshbuf_free(پیغام);
	أرجع ret;
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

	إذا ((helper = helper_by_کلید(priv)) == عدم || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(priv));

	debug3_f("private key type %s cert type %s on provider %s",
	    sshkey_type(priv), sshkey_type(certpub), helper->رستہ);

	*certprivp = عدم;
	إذا (!sshkey_is_cert(certpub) || sshkey_is_cert(priv) ||
	    !sshkey_equal_عوامی(priv, certpub)) {
		error_f("private key %s doesn't match cert %s",
		    sshkey_type(priv), sshkey_type(certpub));
		أرجع SSH_ERR_INVALID_دلیل;
	}
	*certprivp = عدم;
	إذا ((r = sshkey_from_نجی(priv, &ret)) != 0)
		fatal_fr(r, "copy key");

	ret->flags |= SSHKEY_FLAG_EXT;
	إذا ((r = sshkey_منزل_certified(ret)) != 0 ||
	    (r = sshkey_cert_copy(certpub, ret)) != 0)
		fatal_fr(r, "graft certificate");

	helper_جوڑو_کلید(helper, ret);

	debug3_f("provider %s: %zu remaining keys",
	    helper->رستہ, helper->nkeyblobs);

	/* success */
	*certprivp = ret;
	أرجع 0;
}

ساكن بنية helper *
pkcs11_شروع_helper(ثابت حرف *رستہ)
{
	صحيح pair[2];
	حرف *prog, *verbosity = عدم;
	بنية helper *helper;
	pid_t pid;

	إذا (nhelpers >= ودھ_توں_ودھ_عدد)
		fatal_f("too many helpers");
	debug3_f("start helper for %s", رستہ);
	إذا (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
		error_f("socketpair: %s", strerror(errno));
		أرجع عدم;
	}
	helper = xcalloc(1, حجم(*helper));
	إذا ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		close(pair[0]);
		close(pair[1]);
		حرر(helper);
		أرجع عدم;
	} وإلا إذا (pid == 0) {
		إذا ((dup2(pair[1], STDIN_FILENO) == -1) ||
		    (dup2(pair[1], STDOUT_FILENO) == -1)) {
			fprintf(stderr, "dup2: %s\n", strerror(errno));
			_exit(1);
		}
		close(pair[0]);
		close(pair[1]);
		closefrom(STDERR_FILENO + 1);
		prog = getenv("SSH_PKCS11_HELPER");
		إذا (prog == عدم || لڑی_لمبائی(prog) == 0)
			prog = رستہ_SSH_PKCS11_HELPER;
		إذا (log_level_get() >= SYSLOG_LEVEL_DEBUG1)
			verbosity = "-vvv";
		debug_f("starting %s %s", prog,
		    verbosity == عدم ? "" : verbosity);
		execlp(prog, prog, verbosity, (حرف *)عدم);
		fprintf(stderr, "exec: %s: %s\n", prog, strerror(errno));
		_exit(1);
	}
	close(pair[1]);
	helper->fd = pair[0];
	helper->رستہ = xstrdup(رستہ);
	helper->pid = pid;
	debug3_f("helper %zu for \"%s\" on fd %d pid %ld", nhelpers,
	    helper->رستہ, helper->fd, (لما)helper->pid);
	helpers = xrecallocarray(helpers, nhelpers,
	    nhelpers + 1, حجم(*helpers));
	helpers[nhelpers++] = helper;
	أرجع helper;
}

صحيح
pkcs11_جوڑو_provider(حرف *name, حرف *pin, بنية sshkey ***keysp,
    حرف ***labelsp)
{
	بنية sshkey *k;
	صحيح r, type;
	حرف *label;
	u_int ret = -1, nkeys, i;
	بنية sshbuf *پیغام;
	بنية helper *helper;

	إذا ((helper = helper_by_provider(name)) == عدم &&
	    (helper = pkcs11_شروع_helper(name)) == عدم)
		أرجع -1;

	debug3_f("add %s", helper->رستہ);

	إذا ((پیغام = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshbuf_put_u8(پیغام, SSH_AGENTC_جوڑو_SMARTCARD_کلید)) != 0 ||
	    (r = sshbuf_put_cstring(پیغام, name)) != 0 ||
	    (r = sshbuf_put_cstring(پیغام, pin)) != 0)
		fatal_fr(r, "compose");
	send_پیغام(helper->fd, پیغام);
	sshbuf_reset(پیغام);

	type = recv_پیغام(helper->fd, پیغام);
	debug3_f("response %d", type);
	إذا (type == SSH2_AGENT_IDENTITIES_ANSWER) {
		إذا ((r = sshbuf_get_u32(پیغام, &nkeys)) != 0)
			fatal_fr(r, "parse nkeys");
		debug3_f("helper return %u keys", nkeys);
		*keysp = xcalloc(nkeys, حجم(بنية sshkey *));
		إذا (labelsp)
			*labelsp = xcalloc(nkeys, حجم(حرف *));
		لكل (i = 0; i < nkeys; i++) {
			/* XXX clean up properly instead of fatal() */
			إذا ((r = sshkey_froms(پیغام, &k)) != 0 ||
			    (r = sshbuf_get_cstring(پیغام, &label, عدم)) != 0)
				fatal_fr(r, "parse key");
			k->flags |= SSHKEY_FLAG_EXT;
			helper_جوڑو_کلید(helper, k);
			(*keysp)[i] = k;
			إذا (labelsp)
				(*labelsp)[i] = label;
			وإلا
				حرر(label);
		}
		/* success */
		ret = 0;
	} وإلا إذا (type == SSH2_AGENT_FAILURE) {
		إذا ((r = sshbuf_get_u32(پیغام, &nkeys)) != 0)
			error_fr(r, "failed to parse failure response");
	}
	إذا (ret != 0) {
		debug_f("no keys; terminate helper");
		helper_terminate(helper);
	}
	sshbuf_free(پیغام);
	أرجع ret == 0 ? (صحيح)nkeys : -1;
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
	إذا ((helper = helper_by_provider(name)) != عدم)
		helper_terminate(helper);
	أرجع 0;
}

فراغ
pkcs11_کلید_free(بنية sshkey *کلید)
{
	بنية helper *helper;
	بنية sshbuf *keyblob = عدم;
	ناپ_t i;
	صحيح r, لبھیا = 0;

	debug3_f("free %s key", sshkey_type(کلید));

	إذا ((helper = helper_by_کلید(کلید)) == عدم || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(کلید));
	إذا ((keyblob = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshkey_putb(کلید, keyblob)) != 0)
		fatal_fr(r, "serialise key");

	/* repack keys */
	لكل (i = 0; i < helper->nkeyblobs; i++) {
		إذا (sshbuf_equals(keyblob, helper->keyblobs[i]) == 0) {
			إذا (لبھیا)
				fatal_f("key recorded more than once");
			لبھیا = 1;
		} وإلا إذا (لبھیا)
			helper->keyblobs[i - 1] = helper->keyblobs[i];
	}
	إذا (لبھیا) {
		helper->keyblobs = xrecallocarray(helper->keyblobs,
		    helper->nkeyblobs, helper->nkeyblobs - 1,
		    حجم(*helper->keyblobs));
		helper->nkeyblobs--;
	}
	إذا (helper->nkeyblobs == 0)
		helper_terminate(helper);
}
