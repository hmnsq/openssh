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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/time.h>
#অন্তর্ভাব <sys/socket.h>

#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <limits.h>

#অন্তর্ভাব "pathnames.h"
#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "authfd.h"
#অন্তর্ভাব "atomicio.h"
#অন্তর্ভাব "ssh-pkcs11.h"
#অন্তর্ভাব "ssherr.h"

/* borrows code from sftp-server and ssh-agent */

/*
 * Maintain a list of ssh-pkcs11-helper subprocesses. These may be looked up
 * by provider path or their unique keyblobs.
 */
কাঠামো helper {
	অক্ষর *path;
	pid_t pid;
	পূর্ণসংখ্যা fd;
	আকার_t nkeyblobs;
	কাঠামো sshbuf **keyblobs; /* XXX use a tree or something faster */
};
স্থির কাঠামো helper **helpers;
স্থির আকার_t nhelpers;

স্থির কাঠামো helper *
helper_by_provider(ধ্রুবক অক্ষর *path)
{
	আকার_t i;

	জন্য (i = 0; i < nhelpers; i++) {
		যদি (helpers[i] == ফাঁকা || helpers[i]->path == ফাঁকা ||
		    helpers[i]->fd == -1)
			চালু;
		যদি (strcmp(helpers[i]->path, path) == 0)
			ফেরত helpers[i];
	}
	ফেরত ফাঁকা;
}

স্থির কাঠামো helper *
helper_by_চাবি(ধ্রুবক কাঠামো sshkey *চাবি)
{
	আকার_t i, j;
	কাঠামো sshbuf *keyblob = ফাঁকা;
	পূর্ণসংখ্যা r;

	যদি ((keyblob = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshkey_putb(চাবি, keyblob)) != 0)
		fatal_fr(r, "serialise key");

	জন্য (i = 0; i < nhelpers; i++) {
		যদি (helpers[i] == ফাঁকা)
			চালু;
		জন্য (j = 0; j < helpers[i]->nkeyblobs; j++) {
			যদি (sshbuf_equals(keyblob,
			    helpers[i]->keyblobs[j]) == 0) {
				sshbuf_free(keyblob);
				ফেরত helpers[i];
			}
		}
	}
	sshbuf_free(keyblob);
	ফেরত ফাঁকা;

}

স্থির শূন্য
helper_add_চাবি(কাঠামো helper *helper, কাঠামো sshkey *চাবি)
{
	পূর্ণসংখ্যা r;

	helper->keyblobs = xrecallocarray(helper->keyblobs, helper->nkeyblobs,
	    helper->nkeyblobs + 1, আকার(*helper->keyblobs));
	যদি ((helper->keyblobs[helper->nkeyblobs] = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshkey_putb(চাবি, helper->keyblobs[helper->nkeyblobs])) != 0)
		fatal_fr(r, "shkey_putb failed");
	helper->nkeyblobs++;
	debug3_f("added %s key for provider %s, now has %zu keys",
	    sshkey_type(চাবি), helper->path, helper->nkeyblobs);
}

স্থির শূন্য
helper_terminate(কাঠামো helper *helper)
{
	আকার_t i;
	পূর্ণসংখ্যা found = 0;

	যদি (helper == ফাঁকা)
		ফেরত;
	যদি (helper->path == ফাঁকা)
		fatal_f("inconsistent helper");

	debug3_f("terminating helper for %s; remaining %zu keys",
	    helper->path, helper->nkeyblobs);

	close(helper->fd);
	/* XXX waitpid() */
	helper->fd = -1;
	helper->pid = -1;

	/* repack helpers */
	জন্য (i = 0; i < nhelpers; i++) {
		যদি (helpers[i] == helper) {
			যদি (found)
				fatal_f("helper recorded more than once");
			found = 1;
		} অন্যথা যদি (found)
			helpers[i - 1] = helpers[i];
	}
	যদি (found) {
		helpers = xrecallocarray(helpers, nhelpers,
		    nhelpers - 1, আকার(*helpers));
		nhelpers--;
	}
	জন্য (i = 0; i < helper->nkeyblobs; i++)
		sshbuf_free(helper->keyblobs[i]);
	মুক্ত(helper->path);
	মুক্ত(helper);
}

স্থির শূন্য
send_বার্তা(পূর্ণসংখ্যা fd, কাঠামো sshbuf *m)
{
	u_char buf[4];
	আকার_t mlen = sshbuf_len(m);
	পূর্ণসংখ্যা r;

	যদি (fd == -1)
		ফেরত;
	POKE_U32(buf, mlen);
	যদি (atomicio(vwrite, fd, buf, 4) != 4 ||
	    atomicio(vwrite, fd, sshbuf_mutable_ptr(m),
	    sshbuf_len(m)) != sshbuf_len(m))
		error("write to helper failed");
	যদি ((r = sshbuf_consume(m, mlen)) != 0)
		fatal_fr(r, "consume");
}

স্থির পূর্ণসংখ্যা
recv_বার্তা(পূর্ণসংখ্যা fd, কাঠামো sshbuf *m)
{
	u_int l, len;
	u_char c, buf[1024];
	পূর্ণসংখ্যা r;

	sshbuf_reset(m);
	যদি (fd == -1)
		ফেরত 0; /* XXX */
	যদি ((len = atomicio(পঠ, fd, buf, 4)) != 4) {
		error("read from helper failed: %u", len);
		ফেরত (0); /* XXX */
	}
	len = PEEK_U32(buf);
	যদি (len > 256 * 1024)
		fatal("response too long: %u", len);
	/* read len bytes into m */
	যখন (len > 0) {
		l = len;
		যদি (l > আকার(buf))
			l = আকার(buf);
		যদি (atomicio(পঠ, fd, buf, l) != l) {
			error("response from helper failed.");
			ফেরত (0); /* XXX */
		}
		যদি ((r = sshbuf_put(m, buf, l)) != 0)
			fatal_fr(r, "sshbuf_put");
		len -= l;
	}
	যদি ((r = sshbuf_get_u8(m, &c)) != 0)
		fatal_fr(r, "parse type");
	ফেরত c;
}

পূর্ণসংখ্যা
pkcs11_init(পূর্ণসংখ্যা interactive)
{
	ফেরত 0;
}

শূন্য
pkcs11_terminate(শূন্য)
{
	আকার_t i;

	debug3_f("terminating %zu helpers", nhelpers);
	জন্য (i = 0; i < nhelpers; i++)
		helper_terminate(helpers[i]);
}

পূর্ণসংখ্যা
pkcs11_sign(কাঠামো sshkey *চাবি,
    u_char **sigp, আকার_t *lenp,
    ধ্রুবক u_char *তথ্য, আকার_t datalen,
    ধ্রুবক অক্ষর *alg, ধ্রুবক অক্ষর *sk_provider,
    ধ্রুবক অক্ষর *sk_pin, u_int compat)
{
	কাঠামো sshbuf *বার্তা = ফাঁকা;
	কাঠামো helper *helper;
	পূর্ণসংখ্যা status, r;
	u_char *signature = ফাঁকা;
	আকার_t signature_len = 0;
	পূর্ণসংখ্যা ret = SSH_ERR_INTERNAL_ERROR;

	যদি (sigp != ফাঁকা)
		*sigp = ফাঁকা;
	যদি (lenp != ফাঁকা)
		*lenp = 0;

	যদি ((helper = helper_by_চাবি(চাবি)) == ফাঁকা || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(চাবি));

	যদি ((বার্তা = sshbuf_new()) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshbuf_put_u8(বার্তা, SSH2_AGENTC_SIGN_REQUEST)) != 0 ||
	    (r = sshkey_puts_plain(চাবি, বার্তা)) != 0 ||
	    (r = sshbuf_put_string(বার্তা, তথ্য, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(বার্তা, alg == ফাঁকা ? "" : alg)) != 0 ||
	    (r = sshbuf_put_u32(বার্তা, compat)) != 0)
		fatal_fr(r, "compose");
	send_বার্তা(helper->fd, বার্তা);
	sshbuf_reset(বার্তা);

	যদি ((status = recv_বার্তা(helper->fd, বার্তা)) != SSH2_AGENT_SIGN_RESPONSE) {
		/* XXX translate status to something useful */
		debug_fr(r, "recv_msg");
		ret = SSH_ERR_AGENT_FAILURE;
		যাও fail;
	}

	যদি ((r = sshbuf_get_string(বার্তা, &signature, &signature_len)) != 0)
		fatal_fr(r, "parse");

	/* success */
	যদি (sigp != ফাঁকা) {
		*sigp = signature;
		signature = ফাঁকা;
	}
	যদি (lenp != ফাঁকা)
		*lenp = signature_len;
	ret = 0;

 fail:
	মুক্ত(signature);
	sshbuf_free(বার্তা);
	ফেরত ret;
}

/*
 * Make a private PKCS#11-backed certificate by grafting a previously-loaded
 * PKCS#11 private key and a public certificate key.
 */
পূর্ণসংখ্যা
pkcs11_make_cert(ধ্রুবক কাঠামো sshkey *priv,
    ধ্রুবক কাঠামো sshkey *certpub, কাঠামো sshkey **certprivp)
{
	কাঠামো helper *helper = ফাঁকা;
	কাঠামো sshkey *ret;
	পূর্ণসংখ্যা r;

	যদি ((helper = helper_by_চাবি(priv)) == ফাঁকা || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(priv));

	debug3_f("private key type %s cert type %s on provider %s",
	    sshkey_type(priv), sshkey_type(certpub), helper->path);

	*certprivp = ফাঁকা;
	যদি (!sshkey_is_cert(certpub) || sshkey_is_cert(priv) ||
	    !sshkey_equal_public(priv, certpub)) {
		error_f("private key %s doesn't match cert %s",
		    sshkey_type(priv), sshkey_type(certpub));
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	}
	*certprivp = ফাঁকা;
	যদি ((r = sshkey_from_private(priv, &ret)) != 0)
		fatal_fr(r, "copy key");

	ret->flags |= SSHKEY_FLAG_EXT;
	যদি ((r = sshkey_to_certified(ret)) != 0 ||
	    (r = sshkey_cert_copy(certpub, ret)) != 0)
		fatal_fr(r, "graft certificate");

	helper_add_চাবি(helper, ret);

	debug3_f("provider %s: %zu remaining keys",
	    helper->path, helper->nkeyblobs);

	/* success */
	*certprivp = ret;
	ফেরত 0;
}

স্থির কাঠামো helper *
pkcs11_start_helper(ধ্রুবক অক্ষর *path)
{
	পূর্ণসংখ্যা pair[2];
	অক্ষর *prog, *verbosity = ফাঁকা;
	কাঠামো helper *helper;
	pid_t pid;

	যদি (nhelpers >= INT_MAX)
		fatal_f("too many helpers");
	debug3_f("start helper for %s", path);
	যদি (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
		error_f("socketpair: %s", strerror(errno));
		ফেরত ফাঁকা;
	}
	helper = xcalloc(1, আকার(*helper));
	যদি ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		close(pair[0]);
		close(pair[1]);
		মুক্ত(helper);
		ফেরত ফাঁকা;
	} অন্যথা যদি (pid == 0) {
		যদি ((dup2(pair[1], STDIN_FILENO) == -1) ||
		    (dup2(pair[1], STDOUT_FILENO) == -1)) {
			fprintf(stderr, "dup2: %s\n", strerror(errno));
			_exit(1);
		}
		close(pair[0]);
		close(pair[1]);
		closefrom(STDERR_FILENO + 1);
		prog = getenv("SSH_PKCS11_HELPER");
		যদি (prog == ফাঁকা || strlen(prog) == 0)
			prog = _PATH_SSH_PKCS11_HELPER;
		যদি (log_level_get() >= SYSLOG_LEVEL_DEBUG1)
			verbosity = "-vvv";
		debug_f("starting %s %s", prog,
		    verbosity == ফাঁকা ? "" : verbosity);
		execlp(prog, prog, verbosity, (অক্ষর *)ফাঁকা);
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
	    nhelpers + 1, আকার(*helpers));
	helpers[nhelpers++] = helper;
	ফেরত helper;
}

পূর্ণসংখ্যা
pkcs11_add_provider(অক্ষর *name, অক্ষর *pin, কাঠামো sshkey ***keysp,
    অক্ষর ***labelsp)
{
	কাঠামো sshkey *k;
	পূর্ণসংখ্যা r, type;
	অক্ষর *label;
	u_int ret = -1, nkeys, i;
	কাঠামো sshbuf *বার্তা;
	কাঠামো helper *helper;

	যদি ((helper = helper_by_provider(name)) == ফাঁকা &&
	    (helper = pkcs11_start_helper(name)) == ফাঁকা)
		ফেরত -1;

	debug3_f("add %s", helper->path);

	যদি ((বার্তা = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshbuf_put_u8(বার্তা, SSH_AGENTC_ADD_SMARTCARD_চাবি)) != 0 ||
	    (r = sshbuf_put_cstring(বার্তা, name)) != 0 ||
	    (r = sshbuf_put_cstring(বার্তা, pin)) != 0)
		fatal_fr(r, "compose");
	send_বার্তা(helper->fd, বার্তা);
	sshbuf_reset(বার্তা);

	type = recv_বার্তা(helper->fd, বার্তা);
	debug3_f("response %d", type);
	যদি (type == SSH2_AGENT_IDENTITIES_ANSWER) {
		যদি ((r = sshbuf_get_u32(বার্তা, &nkeys)) != 0)
			fatal_fr(r, "parse nkeys");
		debug3_f("helper return %u keys", nkeys);
		*keysp = xcalloc(nkeys, আকার(কাঠামো sshkey *));
		যদি (labelsp)
			*labelsp = xcalloc(nkeys, আকার(অক্ষর *));
		জন্য (i = 0; i < nkeys; i++) {
			/* XXX clean up properly instead of fatal() */
			যদি ((r = sshkey_froms(বার্তা, &k)) != 0 ||
			    (r = sshbuf_get_cstring(বার্তা, &label, ফাঁকা)) != 0)
				fatal_fr(r, "parse key");
			k->flags |= SSHKEY_FLAG_EXT;
			helper_add_চাবি(helper, k);
			(*keysp)[i] = k;
			যদি (labelsp)
				(*labelsp)[i] = label;
			অন্যথা
				মুক্ত(label);
		}
		/* success */
		ret = 0;
	} অন্যথা যদি (type == SSH2_AGENT_FAILURE) {
		যদি ((r = sshbuf_get_u32(বার্তা, &nkeys)) != 0)
			error_fr(r, "failed to parse failure response");
	}
	যদি (ret != 0) {
		debug_f("no keys; terminate helper");
		helper_terminate(helper);
	}
	sshbuf_free(বার্তা);
	ফেরত ret == 0 ? (পূর্ণসংখ্যা)nkeys : -1;
}

পূর্ণসংখ্যা
pkcs11_del_provider(অক্ষর *name)
{
	কাঠামো helper *helper;

	/*
	 * ssh-agent deletes keys before calling this, so the helper entry
	 * should be gone before we get here.
	 */
	debug3_f("delete %s", name ? name : "(null)");
	যদি ((helper = helper_by_provider(name)) != ফাঁকা)
		helper_terminate(helper);
	ফেরত 0;
}

শূন্য
pkcs11_চাবি_free(কাঠামো sshkey *চাবি)
{
	কাঠামো helper *helper;
	কাঠামো sshbuf *keyblob = ফাঁকা;
	আকার_t i;
	পূর্ণসংখ্যা r, found = 0;

	debug3_f("free %s key", sshkey_type(চাবি));

	যদি ((helper = helper_by_চাবি(চাবি)) == ফাঁকা || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(চাবি));
	যদি ((keyblob = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshkey_putb(চাবি, keyblob)) != 0)
		fatal_fr(r, "serialise key");

	/* repack keys */
	জন্য (i = 0; i < helper->nkeyblobs; i++) {
		যদি (sshbuf_equals(keyblob, helper->keyblobs[i]) == 0) {
			যদি (found)
				fatal_f("key recorded more than once");
			found = 1;
		} অন্যথা যদি (found)
			helper->keyblobs[i - 1] = helper->keyblobs[i];
	}
	যদি (found) {
		helper->keyblobs = xrecallocarray(helper->keyblobs,
		    helper->nkeyblobs, helper->nkeyblobs - 1,
		    আকার(*helper->keyblobs));
		helper->nkeyblobs--;
	}
	যদি (helper->nkeyblobs == 0)
		helper_terminate(helper);
}
