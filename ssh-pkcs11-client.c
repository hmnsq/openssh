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
সংরচনা helper {
	বর্ণ *path;
	pid_t pid;
	পূর্ণাঙ্ক fd;
	size_t nkeyblobs;
	সংরচনা sshbuf **keyblobs; /* XXX use a tree or something faster */
};
স্থির সংরচনা helper **helpers;
স্থির size_t nhelpers;

স্থির সংরচনা helper *
helper_by_provider(ধ্রুব বর্ণ *path)
{
	size_t i;

	প্রতি (i = 0; i < nhelpers; i++) {
		যদি (helpers[i] == রিক্ত || helpers[i]->path == রিক্ত ||
		    helpers[i]->fd == -1)
			অনুবর্ত;
		যদি (strcmp(helpers[i]->path, path) == 0)
			প্রত্যাগম helpers[i];
	}
	প্রত্যাগম রিক্ত;
}

স্থির সংরচনা helper *
helper_by_চাবি(ধ্রুব সংরচনা sshkey *চাবি)
{
	size_t i, j;
	সংরচনা sshbuf *keyblob = রিক্ত;
	পূর্ণাঙ্ক r;

	যদি ((keyblob = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshkey_putb(চাবি, keyblob)) != 0)
		fatal_fr(r, "serialise key");

	প্রতি (i = 0; i < nhelpers; i++) {
		যদি (helpers[i] == রিক্ত)
			অনুবর্ত;
		প্রতি (j = 0; j < helpers[i]->nkeyblobs; j++) {
			যদি (sshbuf_equals(keyblob,
			    helpers[i]->keyblobs[j]) == 0) {
				sshbuf_free(keyblob);
				প্রত্যাগম helpers[i];
			}
		}
	}
	sshbuf_free(keyblob);
	প্রত্যাগম রিক্ত;

}

স্থির শূন্য
helper_add_চাবি(সংরচনা helper *helper, সংরচনা sshkey *চাবি)
{
	পূর্ণাঙ্ক r;

	helper->keyblobs = xrecallocarray(helper->keyblobs, helper->nkeyblobs,
	    helper->nkeyblobs + 1, পরিমাণ(*helper->keyblobs));
	যদি ((helper->keyblobs[helper->nkeyblobs] = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshkey_putb(চাবি, helper->keyblobs[helper->nkeyblobs])) != 0)
		fatal_fr(r, "shkey_putb failed");
	helper->nkeyblobs++;
	debug3_f("added %s key for provider %s, now has %zu keys",
	    sshkey_type(চাবি), helper->path, helper->nkeyblobs);
}

স্থির শূন্য
helper_terminate(সংরচনা helper *helper)
{
	size_t i;
	পূর্ণাঙ্ক found = 0;

	যদি (helper == রিক্ত)
		প্রত্যাগম;
	যদি (helper->path == রিক্ত)
		fatal_f("inconsistent helper");

	debug3_f("terminating helper for %s; remaining %zu keys",
	    helper->path, helper->nkeyblobs);

	close(helper->fd);
	/* XXX waitpid() */
	helper->fd = -1;
	helper->pid = -1;

	/* repack helpers */
	প্রতি (i = 0; i < nhelpers; i++) {
		যদি (helpers[i] == helper) {
			যদি (found)
				fatal_f("helper recorded more than once");
			found = 1;
		} অন্যথা যদি (found)
			helpers[i - 1] = helpers[i];
	}
	যদি (found) {
		helpers = xrecallocarray(helpers, nhelpers,
		    nhelpers - 1, পরিমাণ(*helpers));
		nhelpers--;
	}
	প্রতি (i = 0; i < helper->nkeyblobs; i++)
		sshbuf_free(helper->keyblobs[i]);
	মুক্ত(helper->path);
	মুক্ত(helper);
}

স্থির শূন্য
send_বার্তা(পূর্ণাঙ্ক fd, সংরচনা sshbuf *m)
{
	u_char buf[4];
	size_t mlen = sshbuf_len(m);
	পূর্ণাঙ্ক r;

	যদি (fd == -1)
		প্রত্যাগম;
	POKE_U32(buf, mlen);
	যদি (atomicio(vwrite, fd, buf, 4) != 4 ||
	    atomicio(vwrite, fd, sshbuf_mutable_ptr(m),
	    sshbuf_len(m)) != sshbuf_len(m))
		error("write to helper failed");
	যদি ((r = sshbuf_consume(m, mlen)) != 0)
		fatal_fr(r, "consume");
}

স্থির পূর্ণাঙ্ক
recv_বার্তা(পূর্ণাঙ্ক fd, সংরচনা sshbuf *m)
{
	u_int l, len;
	u_char c, buf[1024];
	পূর্ণাঙ্ক r;

	sshbuf_reset(m);
	যদি (fd == -1)
		প্রত্যাগম 0; /* XXX */
	যদি ((len = atomicio(পঠ, fd, buf, 4)) != 4) {
		error("read from helper failed: %u", len);
		প্রত্যাগম (0); /* XXX */
	}
	len = PEEK_U32(buf);
	যদি (len > 256 * 1024)
		fatal("response too long: %u", len);
	/* read len bytes into m */
	যাবত্ (len > 0) {
		l = len;
		যদি (l > পরিমাণ(buf))
			l = পরিমাণ(buf);
		যদি (atomicio(পঠ, fd, buf, l) != l) {
			error("response from helper failed.");
			প্রত্যাগম (0); /* XXX */
		}
		যদি ((r = sshbuf_put(m, buf, l)) != 0)
			fatal_fr(r, "sshbuf_put");
		len -= l;
	}
	যদি ((r = sshbuf_get_u8(m, &c)) != 0)
		fatal_fr(r, "parse type");
	প্রত্যাগম c;
}

পূর্ণাঙ্ক
pkcs11_init(পূর্ণাঙ্ক interactive)
{
	প্রত্যাগম 0;
}

শূন্য
pkcs11_terminate(শূন্য)
{
	size_t i;

	debug3_f("terminating %zu helpers", nhelpers);
	প্রতি (i = 0; i < nhelpers; i++)
		helper_terminate(helpers[i]);
}

পূর্ণাঙ্ক
pkcs11_sign(সংরচনা sshkey *চাবি,
    u_char **sigp, size_t *lenp,
    ধ্রুব u_char *data, size_t datalen,
    ধ্রুব বর্ণ *alg, ধ্রুব বর্ণ *sk_provider,
    ধ্রুব বর্ণ *sk_pin, u_int compat)
{
	সংরচনা sshbuf *বার্তা = রিক্ত;
	সংরচনা helper *helper;
	পূর্ণাঙ্ক status, r;
	u_char *signature = রিক্ত;
	size_t signature_len = 0;
	পূর্ণাঙ্ক ret = SSH_ERR_INTERNAL_ERROR;

	যদি (sigp != রিক্ত)
		*sigp = রিক্ত;
	যদি (lenp != রিক্ত)
		*lenp = 0;

	যদি ((helper = helper_by_চাবি(চাবি)) == রিক্ত || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(চাবি));

	যদি ((বার্তা = sshbuf_new()) == রিক্ত)
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshbuf_put_u8(বার্তা, SSH2_AGENTC_SIGN_REQUEST)) != 0 ||
	    (r = sshkey_puts_plain(চাবি, বার্তা)) != 0 ||
	    (r = sshbuf_put_string(বার্তা, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(বার্তা, alg == রিক্ত ? "" : alg)) != 0 ||
	    (r = sshbuf_put_u32(বার্তা, compat)) != 0)
		fatal_fr(r, "compose");
	send_বার্তা(helper->fd, বার্তা);
	sshbuf_reset(বার্তা);

	যদি ((status = recv_বার্তা(helper->fd, বার্তা)) != SSH2_AGENT_SIGN_RESPONSE) {
		/* XXX translate status to something useful */
		debug_fr(r, "recv_msg");
		ret = SSH_ERR_AGENT_FAILURE;
		গচ্ছ fail;
	}

	যদি ((r = sshbuf_get_string(বার্তা, &signature, &signature_len)) != 0)
		fatal_fr(r, "parse");

	/* success */
	যদি (sigp != রিক্ত) {
		*sigp = signature;
		signature = রিক্ত;
	}
	যদি (lenp != রিক্ত)
		*lenp = signature_len;
	ret = 0;

 fail:
	মুক্ত(signature);
	sshbuf_free(বার্তা);
	প্রত্যাগম ret;
}

/*
 * Make a private PKCS#11-backed certificate by grafting a previously-loaded
 * PKCS#11 private key and a public certificate key.
 */
পূর্ণাঙ্ক
pkcs11_make_cert(ধ্রুব সংরচনা sshkey *priv,
    ধ্রুব সংরচনা sshkey *certpub, সংরচনা sshkey **certprivp)
{
	সংরচনা helper *helper = রিক্ত;
	সংরচনা sshkey *ret;
	পূর্ণাঙ্ক r;

	যদি ((helper = helper_by_চাবি(priv)) == রিক্ত || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(priv));

	debug3_f("private key type %s cert type %s on provider %s",
	    sshkey_type(priv), sshkey_type(certpub), helper->path);

	*certprivp = রিক্ত;
	যদি (!sshkey_is_cert(certpub) || sshkey_is_cert(priv) ||
	    !sshkey_equal_public(priv, certpub)) {
		error_f("private key %s doesn't match cert %s",
		    sshkey_type(priv), sshkey_type(certpub));
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;
	}
	*certprivp = রিক্ত;
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
	প্রত্যাগম 0;
}

স্থির সংরচনা helper *
pkcs11_start_helper(ধ্রুব বর্ণ *path)
{
	পূর্ণাঙ্ক pair[2];
	বর্ণ *prog, *verbosity = রিক্ত;
	সংরচনা helper *helper;
	pid_t pid;

	যদি (nhelpers >= INT_MAX)
		fatal_f("too many helpers");
	debug3_f("start helper for %s", path);
	যদি (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
		error_f("socketpair: %s", strerror(errno));
		প্রত্যাগম রিক্ত;
	}
	helper = xcalloc(1, পরিমাণ(*helper));
	যদি ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		close(pair[0]);
		close(pair[1]);
		মুক্ত(helper);
		প্রত্যাগম রিক্ত;
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
		যদি (prog == রিক্ত || strlen(prog) == 0)
			prog = _PATH_SSH_PKCS11_HELPER;
		যদি (log_level_get() >= SYSLOG_LEVEL_DEBUG1)
			verbosity = "-vvv";
		debug_f("starting %s %s", prog,
		    verbosity == রিক্ত ? "" : verbosity);
		execlp(prog, prog, verbosity, (বর্ণ *)রিক্ত);
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
	    nhelpers + 1, পরিমাণ(*helpers));
	helpers[nhelpers++] = helper;
	প্রত্যাগম helper;
}

পূর্ণাঙ্ক
pkcs11_add_provider(বর্ণ *name, বর্ণ *pin, সংরচনা sshkey ***keysp,
    বর্ণ ***labelsp)
{
	সংরচনা sshkey *k;
	পূর্ণাঙ্ক r, type;
	বর্ণ *label;
	u_int ret = -1, nkeys, i;
	সংরচনা sshbuf *বার্তা;
	সংরচনা helper *helper;

	যদি ((helper = helper_by_provider(name)) == রিক্ত &&
	    (helper = pkcs11_start_helper(name)) == রিক্ত)
		প্রত্যাগম -1;

	debug3_f("add %s", helper->path);

	যদি ((বার্তা = sshbuf_new()) == রিক্ত)
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
		*keysp = xcalloc(nkeys, পরিমাণ(সংরচনা sshkey *));
		যদি (labelsp)
			*labelsp = xcalloc(nkeys, পরিমাণ(বর্ণ *));
		প্রতি (i = 0; i < nkeys; i++) {
			/* XXX clean up properly instead of fatal() */
			যদি ((r = sshkey_froms(বার্তা, &k)) != 0 ||
			    (r = sshbuf_get_cstring(বার্তা, &label, রিক্ত)) != 0)
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
	প্রত্যাগম ret == 0 ? (পূর্ণাঙ্ক)nkeys : -1;
}

পূর্ণাঙ্ক
pkcs11_del_provider(বর্ণ *name)
{
	সংরচনা helper *helper;

	/*
	 * ssh-agent deletes keys before calling this, so the helper entry
	 * should be gone before we get here.
	 */
	debug3_f("delete %s", name ? name : "(null)");
	যদি ((helper = helper_by_provider(name)) != রিক্ত)
		helper_terminate(helper);
	প্রত্যাগম 0;
}

শূন্য
pkcs11_চাবি_free(সংরচনা sshkey *চাবি)
{
	সংরচনা helper *helper;
	সংরচনা sshbuf *keyblob = রিক্ত;
	size_t i;
	পূর্ণাঙ্ক r, found = 0;

	debug3_f("free %s key", sshkey_type(চাবি));

	যদি ((helper = helper_by_চাবি(চাবি)) == রিক্ত || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(চাবি));
	যদি ((keyblob = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshkey_putb(চাবি, keyblob)) != 0)
		fatal_fr(r, "serialise key");

	/* repack keys */
	প্রতি (i = 0; i < helper->nkeyblobs; i++) {
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
		    পরিমাণ(*helper->keyblobs));
		helper->nkeyblobs--;
	}
	যদি (helper->nkeyblobs == 0)
		helper_terminate(helper);
}
