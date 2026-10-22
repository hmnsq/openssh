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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/time.h>
#அந்தர்பாவ <sys/socket.h>

#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <limits.h>

#அந்தர்பாவ "pathnames.h"
#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "authfd.h"
#அந்தர்பாவ "atomicio.h"
#அந்தர்பாவ "ssh-pkcs11.h"
#அந்தர்பாவ "ssherr.h"

/* borrows code from sftp-server and ssh-agent */

/*
 * Maintain a list of ssh-pkcs11-helper subprocesses. These may be looked up
 * by provider path or their unique keyblobs.
 */
கட்டமைப்பு helper {
	எழுத்து *path;
	pid_t pid;
	முழு fd;
	size_t nkeyblobs;
	கட்டமைப்பு sshbuf **keyblobs; /* XXX use a tree or something faster */
};
நிலையான கட்டமைப்பு helper **helpers;
நிலையான size_t nhelpers;

நிலையான கட்டமைப்பு helper *
helper_by_provider(மாறிலி எழுத்து *path)
{
	size_t i;

	க்கு (i = 0; i < nhelpers; i++) {
		எனில் (helpers[i] == வெற்று || helpers[i]->path == வெற்று ||
		    helpers[i]->fd == -1)
			தொடர்;
		எனில் (strcmp(helpers[i]->path, path) == 0)
			திரும்பு helpers[i];
	}
	திரும்பு வெற்று;
}

நிலையான கட்டமைப்பு helper *
helper_by_சாவி(மாறிலி கட்டமைப்பு sshkey *சாவி)
{
	size_t i, j;
	கட்டமைப்பு sshbuf *keyblob = வெற்று;
	முழு r;

	எனில் ((keyblob = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = sshkey_putb(சாவி, keyblob)) != 0)
		fatal_fr(r, "serialise key");

	க்கு (i = 0; i < nhelpers; i++) {
		எனில் (helpers[i] == வெற்று)
			தொடர்;
		க்கு (j = 0; j < helpers[i]->nkeyblobs; j++) {
			எனில் (sshbuf_equals(keyblob,
			    helpers[i]->keyblobs[j]) == 0) {
				sshbuf_free(keyblob);
				திரும்பு helpers[i];
			}
		}
	}
	sshbuf_free(keyblob);
	திரும்பு வெற்று;

}

நிலையான வெறுமை
helper_add_சாவி(கட்டமைப்பு helper *helper, கட்டமைப்பு sshkey *சாவி)
{
	முழு r;

	helper->keyblobs = xrecallocarray(helper->keyblobs, helper->nkeyblobs,
	    helper->nkeyblobs + 1, அளவு(*helper->keyblobs));
	எனில் ((helper->keyblobs[helper->nkeyblobs] = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = sshkey_putb(சாவி, helper->keyblobs[helper->nkeyblobs])) != 0)
		fatal_fr(r, "shkey_putb failed");
	helper->nkeyblobs++;
	debug3_f("added %s key for provider %s, now has %zu keys",
	    sshkey_type(சாவி), helper->path, helper->nkeyblobs);
}

நிலையான வெறுமை
helper_terminate(கட்டமைப்பு helper *helper)
{
	size_t i;
	முழு found = 0;

	எனில் (helper == வெற்று)
		திரும்பு;
	எனில் (helper->path == வெற்று)
		fatal_f("inconsistent helper");

	debug3_f("terminating helper for %s; remaining %zu keys",
	    helper->path, helper->nkeyblobs);

	close(helper->fd);
	/* XXX waitpid() */
	helper->fd = -1;
	helper->pid = -1;

	/* repack helpers */
	க்கு (i = 0; i < nhelpers; i++) {
		எனில் (helpers[i] == helper) {
			எனில் (found)
				fatal_f("helper recorded more than once");
			found = 1;
		} இல்லையெனில் எனில் (found)
			helpers[i - 1] = helpers[i];
	}
	எனில் (found) {
		helpers = xrecallocarray(helpers, nhelpers,
		    nhelpers - 1, அளவு(*helpers));
		nhelpers--;
	}
	க்கு (i = 0; i < helper->nkeyblobs; i++)
		sshbuf_free(helper->keyblobs[i]);
	விடுவி(helper->path);
	விடுவி(helper);
}

நிலையான வெறுமை
send_செய்தி(முழு fd, கட்டமைப்பு sshbuf *m)
{
	u_char buf[4];
	size_t mlen = sshbuf_len(m);
	முழு r;

	எனில் (fd == -1)
		திரும்பு;
	POKE_U32(buf, mlen);
	எனில் (atomicio(vwrite, fd, buf, 4) != 4 ||
	    atomicio(vwrite, fd, sshbuf_mutable_ptr(m),
	    sshbuf_len(m)) != sshbuf_len(m))
		error("write to helper failed");
	எனில் ((r = sshbuf_consume(m, mlen)) != 0)
		fatal_fr(r, "consume");
}

நிலையான முழு
recv_செய்தி(முழு fd, கட்டமைப்பு sshbuf *m)
{
	u_int l, len;
	u_char c, buf[1024];
	முழு r;

	sshbuf_reset(m);
	எனில் (fd == -1)
		திரும்பு 0; /* XXX */
	எனில் ((len = atomicio(பட, fd, buf, 4)) != 4) {
		error("read from helper failed: %u", len);
		திரும்பு (0); /* XXX */
	}
	len = PEEK_U32(buf);
	எனில் (len > 256 * 1024)
		fatal("response too long: %u", len);
	/* read len bytes into m */
	போது (len > 0) {
		l = len;
		எனில் (l > அளவு(buf))
			l = அளவு(buf);
		எனில் (atomicio(பட, fd, buf, l) != l) {
			error("response from helper failed.");
			திரும்பு (0); /* XXX */
		}
		எனில் ((r = sshbuf_put(m, buf, l)) != 0)
			fatal_fr(r, "sshbuf_put");
		len -= l;
	}
	எனில் ((r = sshbuf_get_u8(m, &c)) != 0)
		fatal_fr(r, "parse type");
	திரும்பு c;
}

முழு
pkcs11_init(முழு interactive)
{
	திரும்பு 0;
}

வெறுமை
pkcs11_terminate(வெறுமை)
{
	size_t i;

	debug3_f("terminating %zu helpers", nhelpers);
	க்கு (i = 0; i < nhelpers; i++)
		helper_terminate(helpers[i]);
}

முழு
pkcs11_sign(கட்டமைப்பு sshkey *சாவி,
    u_char **sigp, size_t *lenp,
    மாறிலி u_char *data, size_t datalen,
    மாறிலி எழுத்து *alg, மாறிலி எழுத்து *sk_provider,
    மாறிலி எழுத்து *sk_pin, u_int compat)
{
	கட்டமைப்பு sshbuf *செய்தி = வெற்று;
	கட்டமைப்பு helper *helper;
	முழு status, r;
	u_char *signature = வெற்று;
	size_t signature_len = 0;
	முழு ret = SSH_ERR_INTERNAL_ERROR;

	எனில் (sigp != வெற்று)
		*sigp = வெற்று;
	எனில் (lenp != வெற்று)
		*lenp = 0;

	எனில் ((helper = helper_by_சாவி(சாவி)) == வெற்று || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(சாவி));

	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் ((r = sshbuf_put_u8(செய்தி, SSH2_AGENTC_SIGN_REQUEST)) != 0 ||
	    (r = sshkey_puts_plain(சாவி, செய்தி)) != 0 ||
	    (r = sshbuf_put_string(செய்தி, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(செய்தி, alg == வெற்று ? "" : alg)) != 0 ||
	    (r = sshbuf_put_u32(செய்தி, compat)) != 0)
		fatal_fr(r, "compose");
	send_செய்தி(helper->fd, செய்தி);
	sshbuf_reset(செய்தி);

	எனில் ((status = recv_செய்தி(helper->fd, செய்தி)) != SSH2_AGENT_SIGN_RESPONSE) {
		/* XXX translate status to something useful */
		debug_fr(r, "recv_msg");
		ret = SSH_ERR_AGENT_FAILURE;
		செல் fail;
	}

	எனில் ((r = sshbuf_get_string(செய்தி, &signature, &signature_len)) != 0)
		fatal_fr(r, "parse");

	/* success */
	எனில் (sigp != வெற்று) {
		*sigp = signature;
		signature = வெற்று;
	}
	எனில் (lenp != வெற்று)
		*lenp = signature_len;
	ret = 0;

 fail:
	விடுவி(signature);
	sshbuf_free(செய்தி);
	திரும்பு ret;
}

/*
 * Make a private PKCS#11-backed certificate by grafting a previously-loaded
 * PKCS#11 private key and a public certificate key.
 */
முழு
pkcs11_make_cert(மாறிலி கட்டமைப்பு sshkey *priv,
    மாறிலி கட்டமைப்பு sshkey *certpub, கட்டமைப்பு sshkey **certprivp)
{
	கட்டமைப்பு helper *helper = வெற்று;
	கட்டமைப்பு sshkey *ret;
	முழு r;

	எனில் ((helper = helper_by_சாவி(priv)) == வெற்று || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(priv));

	debug3_f("private key type %s cert type %s on provider %s",
	    sshkey_type(priv), sshkey_type(certpub), helper->path);

	*certprivp = வெற்று;
	எனில் (!sshkey_is_cert(certpub) || sshkey_is_cert(priv) ||
	    !sshkey_equal_public(priv, certpub)) {
		error_f("private key %s doesn't match cert %s",
		    sshkey_type(priv), sshkey_type(certpub));
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	}
	*certprivp = வெற்று;
	எனில் ((r = sshkey_from_private(priv, &ret)) != 0)
		fatal_fr(r, "copy key");

	ret->flags |= SSHKEY_FLAG_EXT;
	எனில் ((r = sshkey_to_certified(ret)) != 0 ||
	    (r = sshkey_cert_copy(certpub, ret)) != 0)
		fatal_fr(r, "graft certificate");

	helper_add_சாவி(helper, ret);

	debug3_f("provider %s: %zu remaining keys",
	    helper->path, helper->nkeyblobs);

	/* success */
	*certprivp = ret;
	திரும்பு 0;
}

நிலையான கட்டமைப்பு helper *
pkcs11_start_helper(மாறிலி எழுத்து *path)
{
	முழு pair[2];
	எழுத்து *prog, *verbosity = வெற்று;
	கட்டமைப்பு helper *helper;
	pid_t pid;

	எனில் (nhelpers >= INT_MAX)
		fatal_f("too many helpers");
	debug3_f("start helper for %s", path);
	எனில் (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
		error_f("socketpair: %s", strerror(errno));
		திரும்பு வெற்று;
	}
	helper = xcalloc(1, அளவு(*helper));
	எனில் ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		close(pair[0]);
		close(pair[1]);
		விடுவி(helper);
		திரும்பு வெற்று;
	} இல்லையெனில் எனில் (pid == 0) {
		எனில் ((dup2(pair[1], STDIN_FILENO) == -1) ||
		    (dup2(pair[1], STDOUT_FILENO) == -1)) {
			fprintf(stderr, "dup2: %s\n", strerror(errno));
			_exit(1);
		}
		close(pair[0]);
		close(pair[1]);
		closefrom(STDERR_FILENO + 1);
		prog = getenv("SSH_PKCS11_HELPER");
		எனில் (prog == வெற்று || strlen(prog) == 0)
			prog = _PATH_SSH_PKCS11_HELPER;
		எனில் (log_level_get() >= SYSLOG_LEVEL_DEBUG1)
			verbosity = "-vvv";
		debug_f("starting %s %s", prog,
		    verbosity == வெற்று ? "" : verbosity);
		execlp(prog, prog, verbosity, (எழுத்து *)வெற்று);
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
	    nhelpers + 1, அளவு(*helpers));
	helpers[nhelpers++] = helper;
	திரும்பு helper;
}

முழு
pkcs11_add_provider(எழுத்து *name, எழுத்து *pin, கட்டமைப்பு sshkey ***keysp,
    எழுத்து ***labelsp)
{
	கட்டமைப்பு sshkey *k;
	முழு r, type;
	எழுத்து *label;
	u_int ret = -1, nkeys, i;
	கட்டமைப்பு sshbuf *செய்தி;
	கட்டமைப்பு helper *helper;

	எனில் ((helper = helper_by_provider(name)) == வெற்று &&
	    (helper = pkcs11_start_helper(name)) == வெற்று)
		திரும்பு -1;

	debug3_f("add %s", helper->path);

	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = sshbuf_put_u8(செய்தி, SSH_AGENTC_ADD_SMARTCARD_சாவி)) != 0 ||
	    (r = sshbuf_put_cstring(செய்தி, name)) != 0 ||
	    (r = sshbuf_put_cstring(செய்தி, pin)) != 0)
		fatal_fr(r, "compose");
	send_செய்தி(helper->fd, செய்தி);
	sshbuf_reset(செய்தி);

	type = recv_செய்தி(helper->fd, செய்தி);
	debug3_f("response %d", type);
	எனில் (type == SSH2_AGENT_IDENTITIES_ANSWER) {
		எனில் ((r = sshbuf_get_u32(செய்தி, &nkeys)) != 0)
			fatal_fr(r, "parse nkeys");
		debug3_f("helper return %u keys", nkeys);
		*keysp = xcalloc(nkeys, அளவு(கட்டமைப்பு sshkey *));
		எனில் (labelsp)
			*labelsp = xcalloc(nkeys, அளவு(எழுத்து *));
		க்கு (i = 0; i < nkeys; i++) {
			/* XXX clean up properly instead of fatal() */
			எனில் ((r = sshkey_froms(செய்தி, &k)) != 0 ||
			    (r = sshbuf_get_cstring(செய்தி, &label, வெற்று)) != 0)
				fatal_fr(r, "parse key");
			k->flags |= SSHKEY_FLAG_EXT;
			helper_add_சாவி(helper, k);
			(*keysp)[i] = k;
			எனில் (labelsp)
				(*labelsp)[i] = label;
			இல்லையெனில்
				விடுவி(label);
		}
		/* success */
		ret = 0;
	} இல்லையெனில் எனில் (type == SSH2_AGENT_FAILURE) {
		எனில் ((r = sshbuf_get_u32(செய்தி, &nkeys)) != 0)
			error_fr(r, "failed to parse failure response");
	}
	எனில் (ret != 0) {
		debug_f("no keys; terminate helper");
		helper_terminate(helper);
	}
	sshbuf_free(செய்தி);
	திரும்பு ret == 0 ? (முழு)nkeys : -1;
}

முழு
pkcs11_del_provider(எழுத்து *name)
{
	கட்டமைப்பு helper *helper;

	/*
	 * ssh-agent deletes keys before calling this, so the helper entry
	 * should be gone before we get here.
	 */
	debug3_f("delete %s", name ? name : "(null)");
	எனில் ((helper = helper_by_provider(name)) != வெற்று)
		helper_terminate(helper);
	திரும்பு 0;
}

வெறுமை
pkcs11_சாவி_free(கட்டமைப்பு sshkey *சாவி)
{
	கட்டமைப்பு helper *helper;
	கட்டமைப்பு sshbuf *keyblob = வெற்று;
	size_t i;
	முழு r, found = 0;

	debug3_f("free %s key", sshkey_type(சாவி));

	எனில் ((helper = helper_by_சாவி(சாவி)) == வெற்று || helper->fd == -1)
		fatal_f("no helper for %s key", sshkey_type(சாவி));
	எனில் ((keyblob = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = sshkey_putb(சாவி, keyblob)) != 0)
		fatal_fr(r, "serialise key");

	/* repack keys */
	க்கு (i = 0; i < helper->nkeyblobs; i++) {
		எனில் (sshbuf_equals(keyblob, helper->keyblobs[i]) == 0) {
			எனில் (found)
				fatal_f("key recorded more than once");
			found = 1;
		} இல்லையெனில் எனில் (found)
			helper->keyblobs[i - 1] = helper->keyblobs[i];
	}
	எனில் (found) {
		helper->keyblobs = xrecallocarray(helper->keyblobs,
		    helper->nkeyblobs, helper->nkeyblobs - 1,
		    அளவு(*helper->keyblobs));
		helper->nkeyblobs--;
	}
	எனில் (helper->nkeyblobs == 0)
		helper_terminate(helper);
}
