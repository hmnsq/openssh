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
ساخت helper {
	حرف *راستہ;
	pid_t pid;
	صحیح fd;
	سائز_t nkeyblobs;
	ساخت sshbuf **keyblobs; /* XXX use a tree or something faster */
};
ساکن ساخت helper **helpers;
ساکن سائز_t nhelpers;

ساکن ساخت helper *
helper_by_provider(ثابت حرف *راستہ)
{
	سائز_t i;

	برائے (i = 0; i < nhelpers; i++) {
		اگر (helpers[i] == تہی || helpers[i]->راستہ == تہی ||
		    helpers[i]->fd == -1)
			جاری;
		اگر (strcmp(helpers[i]->راستہ, راستہ) == 0)
			واپس helpers[i];
	}
	واپس تہی;
}

ساکن ساخت helper *
helper_by_کلید(ثابت ساخت sshkey *کلید)
{
	سائز_t i, j;
	ساخت sshbuf *keyblob = تہی;
	صحیح r;

	اگر ((keyblob = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshkey_putb(کلید, keyblob)) != 0)
		fatal_fr(r, "serialise key");

	برائے (i = 0; i < nhelpers; i++) {
		اگر (helpers[i] == تہی)
			جاری;
		برائے (j = 0; j < helpers[i]->nkeyblobs; j++) {
			اگر (sshbuf_equals(keyblob,
			    helpers[i]->keyblobs[j]) == 0) {
				sshbuf_free(keyblob);
				واپس helpers[i];
			}
		}
	}
	sshbuf_free(keyblob);
	واپس تہی;

}

ساکن خالی
helper_جوڑو_کلید(ساخت helper *helper, ساخت sshkey *کلید)
{
	صحیح r;

	helper->keyblobs = xrecallocarray(helper->keyblobs, helper->nkeyblobs,
	    helper->nkeyblobs + 1, حجم(*helper->keyblobs));
	اگر ((helper->keyblobs[helper->nkeyblobs] = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshkey_putb(کلید, helper->keyblobs[helper->nkeyblobs])) != 0)
		fatal_fr(r, "shkey_putb failed");
	helper->nkeyblobs++;
	debug3_f("added %s key for provider %s, now has %zu keys",
	    sshkey_type(کلید), helper->راستہ, helper->nkeyblobs);
}

ساکن خالی
helper_terminate(ساخت helper *helper)
{
	سائز_t i;
	صحیح ملا = 0;

	اگر (helper == تہی)
		واپس;
	اگر (helper->راستہ == تہی)
		fatal_f("inconsistent helper");

	debug3_f("terminating helper for %s; remaining %zu keys",
	    helper->راستہ, helper->nkeyblobs);

	close(helper->fd);
	/* XXX waitpid() */
	helper->fd = -1;
	helper->pid = -1;

	/* repack helpers */
	برائے (i = 0; i < nhelpers; i++) {
		اگر (helpers[i] == helper) {
			اگر (ملا)
				fatal_f("helper recorded more than once");
			ملا = 1;
		} ورنہ اگر (ملا)
			helpers[i - 1] = helpers[i];
	}
	اگر (ملا) {
		helpers = xrecallocarray(helpers, nhelpers,
		    nhelpers - 1, حجم(*helpers));
		nhelpers--;
	}
	برائے (i = 0; i < helper->nkeyblobs; i++)
		sshbuf_free(helper->keyblobs[i]);
	آزاد(helper->راستہ);
	آزاد(helper);
}

ساکن خالی
send_پیغام(صحیح fd, ساخت sshbuf *m)
{
	u_char buf[4];
	سائز_t mlen = sshbuf_len(m);
	صحیح r;

	اگر (fd == -1)
		واپس;
	POKE_U32(buf, mlen);
	اگر (atomicio(vwrite, fd, buf, 4) != 4 ||
	    atomicio(vwrite, fd, sshbuf_mutable_ptr(m),
	    sshbuf_len(m)) != sshbuf_len(m))
		error("write to helper failed");
	اگر ((r = sshbuf_consume(m, mlen)) != 0)
		fatal_fr(r, "consume");
}

ساکن صحیح
recv_پیغام(صحیح fd, ساخت sshbuf *m)
{
	u_int l, len;
	u_char c, buf[1024];
	صحیح r;

	sshbuf_reset(m);
	اگر (fd == -1)
		واپس 0; /* XXX */
	اگر ((len = atomicio(اقرأ, fd, buf, 4)) != 4) {
		error("read from helper failed: %u", len);
		واپس (0); /* XXX */
	}
	len = PEEK_U32(buf);
	اگر (len > 256 * 1024)
		fatal("response too long: %u", len);
	/* read len bytes into m */
	جب (len > 0) {
		l = len;
		اگر (l > حجم(buf))
			l = حجم(buf);
		اگر (atomicio(اقرأ, fd, buf, l) != l) {
			error("response from helper failed.");
			واپس (0); /* XXX */
		}
		اگر ((r = sshbuf_put(m, buf, l)) != 0)
			fatal_fr(r, "sshbuf_put");
		len -= l;
	}
	اگر ((r = sshbuf_get_u8(m, &c)) != 0)
		fatal_fr(r, "parse type");
	واپس c;
}

صحیح
pkcs11_init(صحیح interactive)
{
	واپس 0;
}

خالی
pkcs11_terminate(خالی)
{
	سائز_t i;

	debug3_f("terminating %zu helpers", nhelpers);
	برائے (i = 0; i < nhelpers; i++)
		helper_terminate(helpers[i]);
}

صحیح
pkcs11_sign(ساخت sshkey *کلید,
    u_char **sigp, سائز_t *lenp,
    ثابت u_char *ڈیٹا, سائز_t datalen,
    ثابت حرف *alg, ثابت حرف *sk_provider,
    ثابت حرف *sk_pin, u_int compat)
{
	ساخت sshbuf *پیغام = تہی;
	ساخت helper *helper;
	صحیح حالت_2, r;
	u_char *signature = تہی;
	سائز_t signature_len = 0;
	صحیح ret = SSH_ERR_اندرونی_ERROR;

	اگر (sigp != تہی)
		*sigp = تہی;
	اگر (lenp != تہی)
		*lenp = 0;

	اگر ((helper = helper_by_کلید(کلید)) == تہی || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(کلید));

	اگر ((پیغام = sshbuf_new()) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshbuf_put_u8(پیغام, SSH2_AGENTC_SIGN_REQUEST)) != 0 ||
	    (r = sshkey_puts_plain(کلید, پیغام)) != 0 ||
	    (r = sshbuf_put_string(پیغام, ڈیٹا, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(پیغام, alg == تہی ? "" : alg)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, compat)) != 0)
		fatal_fr(r, "compose");
	send_پیغام(helper->fd, پیغام);
	sshbuf_reset(پیغام);

	اگر ((حالت_2 = recv_پیغام(helper->fd, پیغام)) != SSH2_AGENT_SIGN_RESPONSE) {
		/* XXX translate status to something useful */
		debug_fr(r, "recv_msg");
		ret = SSH_ERR_AGENT_FAILURE;
		جاؤ fail;
	}

	اگر ((r = sshbuf_get_string(پیغام, &signature, &signature_len)) != 0)
		fatal_fr(r, "parse");

	/* success */
	اگر (sigp != تہی) {
		*sigp = signature;
		signature = تہی;
	}
	اگر (lenp != تہی)
		*lenp = signature_len;
	ret = 0;

 fail:
	آزاد(signature);
	sshbuf_free(پیغام);
	واپس ret;
}

/*
 * Make a private PKCS#11-backed certificate by grafting a previously-loaded
 * PKCS#11 private key and a public certificate key.
 */
صحیح
pkcs11_make_cert(ثابت ساخت sshkey *priv,
    ثابت ساخت sshkey *certpub, ساخت sshkey **certprivp)
{
	ساخت helper *helper = تہی;
	ساخت sshkey *ret;
	صحیح r;

	اگر ((helper = helper_by_کلید(priv)) == تہی || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(priv));

	debug3_f("private key type %s cert type %s on provider %s",
	    sshkey_type(priv), sshkey_type(certpub), helper->راستہ);

	*certprivp = تہی;
	اگر (!sshkey_is_cert(certpub) || sshkey_is_cert(priv) ||
	    !sshkey_equal_عوامی(priv, certpub)) {
		error_f("private key %s doesn't match cert %s",
		    sshkey_type(priv), sshkey_type(certpub));
		واپس SSH_ERR_INVALID_دلیل;
	}
	*certprivp = تہی;
	اگر ((r = sshkey_from_نجی(priv, &ret)) != 0)
		fatal_fr(r, "copy key");

	ret->flags |= SSHKEY_FLAG_EXT;
	اگر ((r = sshkey_مقصد_certified(ret)) != 0 ||
	    (r = sshkey_cert_copy(certpub, ret)) != 0)
		fatal_fr(r, "graft certificate");

	helper_جوڑو_کلید(helper, ret);

	debug3_f("provider %s: %zu remaining keys",
	    helper->راستہ, helper->nkeyblobs);

	/* success */
	*certprivp = ret;
	واپس 0;
}

ساکن ساخت helper *
pkcs11_آغاز_helper(ثابت حرف *راستہ)
{
	صحیح pair[2];
	حرف *prog, *verbosity = تہی;
	ساخت helper *helper;
	pid_t pid;

	اگر (nhelpers >= زیادہ_سے_زیادہ_عدد)
		fatal_f("too many helpers");
	debug3_f("start helper for %s", راستہ);
	اگر (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
		error_f("socketpair: %s", strerror(errno));
		واپس تہی;
	}
	helper = xcalloc(1, حجم(*helper));
	اگر ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		close(pair[0]);
		close(pair[1]);
		آزاد(helper);
		واپس تہی;
	} ورنہ اگر (pid == 0) {
		اگر ((dup2(pair[1], STDIN_FILENO) == -1) ||
		    (dup2(pair[1], STDOUT_FILENO) == -1)) {
			fprintf(stderr, "dup2: %s\n", strerror(errno));
			_exit(1);
		}
		close(pair[0]);
		close(pair[1]);
		closefrom(STDERR_FILENO + 1);
		prog = getenv("SSH_PKCS11_HELPER");
		اگر (prog == تہی || لڑی_لمبائی(prog) == 0)
			prog = راستہ_SSH_PKCS11_HELPER;
		اگر (log_level_get() >= SYSLOG_LEVEL_DEBUG1)
			verbosity = "-vvv";
		debug_f("starting %s %s", prog,
		    verbosity == تہی ? "" : verbosity);
		execlp(prog, prog, verbosity, (حرف *)تہی);
		fprintf(stderr, "exec: %s: %s\n", prog, strerror(errno));
		_exit(1);
	}
	close(pair[1]);
	helper->fd = pair[0];
	helper->راستہ = xstrdup(راستہ);
	helper->pid = pid;
	debug3_f("helper %zu for \"%s\" on fd %d pid %ld", nhelpers,
	    helper->راستہ, helper->fd, (طویل)helper->pid);
	helpers = xrecallocarray(helpers, nhelpers,
	    nhelpers + 1, حجم(*helpers));
	helpers[nhelpers++] = helper;
	واپس helper;
}

صحیح
pkcs11_جوڑو_provider(حرف *name, حرف *pin, ساخت sshkey ***keysp,
    حرف ***labelsp)
{
	ساخت sshkey *k;
	صحیح r, type;
	حرف *label;
	u_int ret = -1, nkeys, i;
	ساخت sshbuf *پیغام;
	ساخت helper *helper;

	اگر ((helper = helper_by_provider(name)) == تہی &&
	    (helper = pkcs11_آغاز_helper(name)) == تہی)
		واپس -1;

	debug3_f("add %s", helper->راستہ);

	اگر ((پیغام = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_u8(پیغام, SSH_AGENTC_جوڑو_SMARTCARD_کلید)) != 0 ||
	    (r = sshbuf_put_cstring(پیغام, name)) != 0 ||
	    (r = sshbuf_put_cstring(پیغام, pin)) != 0)
		fatal_fr(r, "compose");
	send_پیغام(helper->fd, پیغام);
	sshbuf_reset(پیغام);

	type = recv_پیغام(helper->fd, پیغام);
	debug3_f("response %d", type);
	اگر (type == SSH2_AGENT_IDENTITIES_ANSWER) {
		اگر ((r = sshbuf_get_u32(پیغام, &nkeys)) != 0)
			fatal_fr(r, "parse nkeys");
		debug3_f("helper return %u keys", nkeys);
		*keysp = xcalloc(nkeys, حجم(ساخت sshkey *));
		اگر (labelsp)
			*labelsp = xcalloc(nkeys, حجم(حرف *));
		برائے (i = 0; i < nkeys; i++) {
			/* XXX clean up properly instead of fatal() */
			اگر ((r = sshkey_froms(پیغام, &k)) != 0 ||
			    (r = sshbuf_get_cstring(پیغام, &label, تہی)) != 0)
				fatal_fr(r, "parse key");
			k->flags |= SSHKEY_FLAG_EXT;
			helper_جوڑو_کلید(helper, k);
			(*keysp)[i] = k;
			اگر (labelsp)
				(*labelsp)[i] = label;
			ورنہ
				آزاد(label);
		}
		/* success */
		ret = 0;
	} ورنہ اگر (type == SSH2_AGENT_FAILURE) {
		اگر ((r = sshbuf_get_u32(پیغام, &nkeys)) != 0)
			error_fr(r, "failed to parse failure response");
	}
	اگر (ret != 0) {
		debug_f("no keys; terminate helper");
		helper_terminate(helper);
	}
	sshbuf_free(پیغام);
	واپس ret == 0 ? (صحیح)nkeys : -1;
}

صحیح
pkcs11_del_provider(حرف *name)
{
	ساخت helper *helper;

	/*
	 * ssh-agent deletes keys before calling this, so the helper entry
	 * should be gone before we get here.
	 */
	debug3_f("delete %s", name ? name : "(null)");
	اگر ((helper = helper_by_provider(name)) != تہی)
		helper_terminate(helper);
	واپس 0;
}

خالی
pkcs11_کلید_free(ساخت sshkey *کلید)
{
	ساخت helper *helper;
	ساخت sshbuf *keyblob = تہی;
	سائز_t i;
	صحیح r, ملا = 0;

	debug3_f("free %s key", sshkey_type(کلید));

	اگر ((helper = helper_by_کلید(کلید)) == تہی || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(کلید));
	اگر ((keyblob = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshkey_putb(کلید, keyblob)) != 0)
		fatal_fr(r, "serialise key");

	/* repack keys */
	برائے (i = 0; i < helper->nkeyblobs; i++) {
		اگر (sshbuf_equals(keyblob, helper->keyblobs[i]) == 0) {
			اگر (ملا)
				fatal_f("key recorded more than once");
			ملا = 1;
		} ورنہ اگر (ملا)
			helper->keyblobs[i - 1] = helper->keyblobs[i];
	}
	اگر (ملا) {
		helper->keyblobs = xrecallocarray(helper->keyblobs,
		    helper->nkeyblobs, helper->nkeyblobs - 1,
		    حجم(*helper->keyblobs));
		helper->nkeyblobs--;
	}
	اگر (helper->nkeyblobs == 0)
		helper_terminate(helper);
}
