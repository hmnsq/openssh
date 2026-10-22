/* $OpenBSD: ssh-agent.c,v 1.333 2026/09/22 22:30:27 djm Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * The authentication agent program.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/time.h>
#ضمن <sys/queue.h>
#ضمن <sys/resource.h>
#ضمن <sys/socket.h>
#ضمن <sys/stat.h>
#ضمن <sys/un.h>
#ضمن <sys/wait.h>

#ifdef WITH_OPENSSL
#ضمن <openssl/evp.h>
#ضمن "openbsd-compat/openssl-compat.h"
#endif

#ضمن <errno.h>
#ضمن <fcntl.h>
#ضمن <paths.h>
#ضمن <poll.h>
#ضمن <signal.h>
#ضمن <stdlib.h>
#ضمن <stdio.h>
#ضمن <string.h>
#ضمن <stdarg.h>
#ضمن <limits.h>
#ضمن <time.h>
#ضمن <unistd.h>
#ضمن <util.h>
#ضمن <pwd.h>

#ضمن "xmalloc.h"
#ضمن "ssh.h"
#ضمن "ssh2.h"
#ضمن "sshbuf.h"
#ضمن "sshkey.h"
#ضمن "authfd.h"
#ضمن "log.h"
#ضمن "misc.h"
#ضمن "digest.h"
#ضمن "ssherr.h"
#ضمن "match.h"
#ضمن "msg.h"
#ضمن "pathnames.h"
#ضمن "ssh-pkcs11.h"
#ضمن "sk-api.h"
#ضمن "myproposal.h"
#ضمن "version.h"

#ifndef DEFAULT_ALLOWED_PROVIDERS
# define DEFAULT_ALLOWED_PROVIDERS "/usr/lib*/*,/usr/local/lib*/*"
#endif
#ifndef DEFAULT_WEBSAFE_ALLOWLIST
# define DEFAULT_WEBSAFE_ALLOWLIST "ssh:*"
#endif

/* Maximum accepted message length */
#define AGENT_MAX_LEN		(256*1024)
/* Maximum bytes to read from client socket */
#define AGENT_RBUF_LEN		(4096)
/* Maximum number of recorded session IDs/hostkeys per connection */
#define AGENT_MAX_SESSION_IDS		16
/* Maximum size of session ID */
#define AGENT_MAX_SID_LEN		128
/* Maximum number of destination constraints to accept on a key */
#define AGENT_MAX_DEST_CONSTRAINTS	1024
/* Maximum number of associated certificate constraints to accept on a key */
#define AGENT_MAX_EXT_CERTS		1024
/* Max length of username constraint */
#define AGENT_USER_CONSTRAINT_MAX_LEN	256

/* XXX store hostkey_sid in a refcounted tree */

تعريفنوع تعداد {
	AUTH_UNUSED = 0,
	AUTH_SOCKET = 1,
	AUTH_CONNECTION = 2,
} sock_type;

بنية hostkey_sid {
	بنية sshkey *key;
	بنية sshbuf *sid;
	صحيح forwarded;
};

تعريفنوع بنية socket_entry {
	صحيح fd;
	sock_type type;
	بنية sshbuf *input;
	بنية sshbuf *output;
	بنية sshbuf *request;
	size_t nsession_ids;
	بنية hostkey_sid *session_ids;
	صحيح session_bind_attempted;
} SocketEntry;

u_int sockets_alloc = 0;
SocketEntry *sockets = عدم;

تعريفنوع بنية identity {
	TAILQ_ENTRY(identity) next;
	بنية sshkey *key;
	حرف *comment;
	حرف *provider;
	time_t death;
	u_int confirm;
	حرف *sk_provider;
	بنية dest_constraint *dest_constraints;
	size_t ndest_constraints;
} Identity;

بنية idtable {
	صحيح nentries;
	TAILQ_HEAD(idqueue, identity) idlist;
};

/* private key table */
بنية idtable *idtab;

صحيح max_fd = 0;

/* pid of shell == parent of agent */
pid_t parent_pid = -1;
time_t parent_alive_interval = 0;

ساكن sig_atomic_t signalled_exit;
ساكن sig_atomic_t signalled_keydrop;

/* pid of process for which cleanup_socket is applicable */
pid_t cleanup_pid = 0;

/* pathname and directory for AUTH_SOCKET */
ساكن حرف *socket_name;
ساكن حرف *socket_dir;
ساكن حرف *socket_dirspec;

/* Pattern-list of allowed PKCS#11/Security key paths */
ساكن حرف *allowed_providers;

/*
 * Allows PKCS11 providers or SK keys that use non-internal providers to
 * be added over a remote connection (identified by session-bind@openssh.com).
 */
ساكن صحيح remote_add_provider;

/* locking */
#define LOCK_SIZE	32
#define LOCK_SALT_SIZE	16
#define LOCK_ROUNDS	1
صحيح locked = 0;
u_char lock_pwhash[LOCK_SIZE];
u_char lock_salt[LOCK_SALT_SIZE];

خارجي حرف *__progname;

/* Default lifetime in seconds (0 == forever) */
ساكن صحيح lifetime = 0;

ساكن صحيح fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* Refuse signing of non-SSH messages for web-origin FIDO keys */
ساكن صحيح restrict_websafe = 1;
ساكن حرف *websafe_allowlist;

ساكن فراغ
close_socket(SocketEntry *e)
{
	size_t i;

	close(e->fd);
	sshbuf_free(e->input);
	sshbuf_free(e->output);
	sshbuf_free(e->request);
	עבור (i = 0; i < e->nsession_ids; i++) {
		sshkey_free(e->session_ids[i].key);
		sshbuf_free(e->session_ids[i].sid);
	}
	حرر(e->session_ids);
	memset(e, '\0', حجم(*e));
	e->fd = -1;
	e->type = AUTH_UNUSED;
}

ساكن فراغ
idtab_init(فراغ)
{
	idtab = xcalloc(1, حجم(*idtab));
	TAILQ_INIT(&idtab->idlist);
	idtab->nentries = 0;
}

ساكن فراغ
free_dest_constraint_hop(بنية dest_constraint_hop *dch)
{
	u_int i;

	אם (dch == عدم)
		החזר;
	حرر(dch->user);
	حرر(dch->hostname);
	עבור (i = 0; i < dch->nkeys; i++)
		sshkey_free(dch->keys[i]);
	حرر(dch->keys);
	حرر(dch->key_is_ca);
}

ساكن فراغ
free_dest_constraints(بنية dest_constraint *dcs, size_t ndcs)
{
	size_t i;

	עבור (i = 0; i < ndcs; i++) {
		free_dest_constraint_hop(&dcs[i].from);
		free_dest_constraint_hop(&dcs[i].to);
	}
	حرر(dcs);
}

#ifdef ENABLE_PKCS11
ساكن فراغ
dup_dest_constraint_hop(ثابت بنية dest_constraint_hop *dch,
    بنية dest_constraint_hop *out)
{
	u_int i;
	صحيح r;

	out->user = dch->user == عدم ? عدم : xstrdup(dch->user);
	out->hostname = dch->hostname == عدم ? عدم : xstrdup(dch->hostname);
	out->is_ca = dch->is_ca;
	out->nkeys = dch->nkeys;
	out->keys = out->nkeys == 0 ? عدم :
	    xcalloc(out->nkeys, حجم(*out->keys));
	out->key_is_ca = out->nkeys == 0 ? عدم :
	    xcalloc(out->nkeys, حجم(*out->key_is_ca));
	עבור (i = 0; i < dch->nkeys; i++) {
		אם (dch->keys[i] != عدم &&
		    (r = sshkey_from_private(dch->keys[i],
		    &(out->keys[i]))) != 0)
			fatal_fr(r, "copy key");
		out->key_is_ca[i] = dch->key_is_ca[i];
	}
}

ساكن بنية dest_constraint *
dup_dest_constraints(ثابت بنية dest_constraint *dcs, size_t ndcs)
{
	size_t i;
	بنية dest_constraint *ret;

	אם (ndcs == 0)
		החזר عدم;
	ret = xcalloc(ndcs, حجم(*ret));
	עבור (i = 0; i < ndcs; i++) {
		dup_dest_constraint_hop(&dcs[i].from, &ret[i].from);
		dup_dest_constraint_hop(&dcs[i].to, &ret[i].to);
	}
	החזר ret;
}
#endif /* ENABLE_PKCS11 */

#ifdef DEBUG_CONSTRAINTS
ساكن فراغ
dump_dest_constraint_hop(ثابت بنية dest_constraint_hop *dch)
{
	u_int i;
	حرف *fp;

	debug_f("user %s hostname %s is_ca %d nkeys %u",
	    dch->user == عدم ? "(null)" : dch->user,
	    dch->hostname == عدم ? "(null)" : dch->hostname,
	    dch->is_ca, dch->nkeys);
	עבור (i = 0; i < dch->nkeys; i++) {
		fp = عدم;
		אם (dch->keys[i] != عدم &&
		    (fp = sshkey_fingerprint(dch->keys[i],
		    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == عدم)
			fatal_f("fingerprint failed");
		debug_f("key %u/%u: %s%s%s key_is_ca %d", i, dch->nkeys,
		    dch->keys[i] == عدم ? "" : sshkey_ssh_name(dch->keys[i]),
		    dch->keys[i] == عدم ? "" : " ",
		    dch->keys[i] == عدم ? "none" : fp,
		    dch->key_is_ca[i]);
		حرر(fp);
	}
}
#endif /* DEBUG_CONSTRAINTS */

ساكن فراغ
dump_dest_constraints(ثابت حرف *context,
    ثابت بنية dest_constraint *dcs, size_t ndcs)
{
#ifdef DEBUG_CONSTRAINTS
	size_t i;

	debug_f("%s: %zu constraints", context, ndcs);
	עבור (i = 0; i < ndcs; i++) {
		debug_f("constraint %zu / %zu: from: ", i, ndcs);
		dump_dest_constraint_hop(&dcs[i].from);
		debug_f("constraint %zu / %zu: to: ", i, ndcs);
		dump_dest_constraint_hop(&dcs[i].to);
	}
	debug_f("done for %s", context);
#endif /* DEBUG_CONSTRAINTS */
}

ساكن فراغ
free_identity(Identity *id)
{
	sshkey_free(id->key);
	حرر(id->provider);
	حرر(id->comment);
	حرر(id->sk_provider);
	free_dest_constraints(id->dest_constraints, id->ndest_constraints);
	حرر(id);
}

/*
 * Match 'key' against the key/CA list in a destination constraint hop
 * Returns 0 on success or -1 otherwise.
 */
ساكن صحيح
match_key_hop(ثابت حرف *tag, ثابت بنية sshkey *key,
    ثابت بنية dest_constraint_hop *dch)
{
	ثابت حرف *reason = عدم;
	ثابت حرف *hostname = dch->hostname ? dch->hostname : "(ORIGIN)";
	u_int i;
	حرف *fp;

	אם (key == عدم)
		החזר -1;
	/* XXX logspam */
	אם ((fp = sshkey_fingerprint(key, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == عدم)
		fatal_f("fingerprint failed");
	debug3_f("%s: entering hostname %s, requested key %s %s, %u keys avail",
	    tag, hostname, sshkey_type(key), fp, dch->nkeys);
	حرر(fp);
	עבור (i = 0; i < dch->nkeys; i++) {
		אם (dch->keys[i] == عدم)
			החזר -1;
		/* XXX logspam */
		אם ((fp = sshkey_fingerprint(dch->keys[i], SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == عدم)
			fatal_f("fingerprint failed");
		debug3_f("%s: key %u: %s%s %s", tag, i,
		    dch->key_is_ca[i] ? "CA " : "",
		    sshkey_type(dch->keys[i]), fp);
		حرر(fp);
		אם (!sshkey_is_cert(key)) {
			/* plain key */
			אם (dch->key_is_ca[i] ||
			    !sshkey_equal(key, dch->keys[i]))
				استمر;
			החזר 0;
		}
		/* certificate */
		אם (!dch->key_is_ca[i])
			استمر;
		אם (key->cert == عدم || key->cert->signature_key == عدم)
			החזר -1; /* shouldn't happen */
		אם (!sshkey_equal(key->cert->signature_key, dch->keys[i]))
			استمر;
		אם (sshkey_cert_check_host(key, hostname,
		    SSH_ALLOWED_CA_SIGALGS, &reason) != 0) {
			debug_f("cert %s / hostname %s rejected: %s",
			    key->cert->key_id, hostname, reason);
			استمر;
		}
		החזר 0;
	}
	החזר -1;
}

/* Check destination constraints on an identity against the hostkey/user */
ساكن صحيح
permitted_by_dest_constraints(ثابت بنية sshkey *fromkey,
    ثابت بنية sshkey *tokey, Identity *id, ثابت حرف *user,
    ثابت حرف **hostnamep)
{
	size_t i;
	بنية dest_constraint *d;

	אם (hostnamep != عدم)
		*hostnamep = عدم;
	עבור (i = 0; i < id->ndest_constraints; i++) {
		d = id->dest_constraints + i;
		/* XXX remove logspam */
		debug2_f("constraint %zu %s%s%s (%u keys) > %s%s%s (%u keys)",
		    i, d->from.user ? d->from.user : "",
		    d->from.user ? "@" : "",
		    d->from.hostname ? d->from.hostname : "(ORIGIN)",
		    d->from.nkeys,
		    d->to.user ? d->to.user : "", d->to.user ? "@" : "",
		    d->to.hostname ? d->to.hostname : "(ANY)", d->to.nkeys);

		/* Match 'from' key */
		אם (fromkey == عدم) {
			/* We are matching the first hop */
			אם (d->from.hostname != عدم || d->from.nkeys != 0)
				استمر;
		} אחרת אם (match_key_hop("from", fromkey, &d->from) != 0)
			استمر;

		/* Match 'to' key */
		אם (tokey != عدم && match_key_hop("to", tokey, &d->to) != 0)
			استمر;

		/* Match user if specified */
		אם (d->to.user != عدم && user != عدم &&
		    !match_pattern(user, d->to.user))
			استمر;

		/* successfully matched this constraint */
		אם (hostnamep != عدم)
			*hostnamep = d->to.hostname;
		debug2_f("allowed for hostname %s",
		    d->to.hostname == عدم ? "*" : d->to.hostname);
		החזר 0;
	}
	/* no match */
	debug2_f("%s identity \"%s\" not permitted for this destination",
	    sshkey_type(id->key), id->comment);
	החזר -1;
}

/*
 * Check whether hostkeys on a SocketEntry and the optionally specified user
 * are permitted by the destination constraints on the Identity.
 * Returns 0 on success or -1 otherwise.
 */
ساكن صحيح
identity_permitted(Identity *id, SocketEntry *e, حرف *user,
    ثابت حرف **forward_hostnamep, ثابت حرف **last_hostnamep)
{
	size_t i;
	ثابت حرف **hp;
	بنية hostkey_sid *hks;
	ثابت بنية sshkey *fromkey = عدم;
	ثابت حرف *test_user;
	حرف *fp1, *fp2;

	/* XXX remove logspam */
	debug3_f("entering: key %s comment \"%s\", %zu socket bindings, "
	    "%zu constraints", sshkey_type(id->key), id->comment,
	    e->nsession_ids, id->ndest_constraints);
	אם (id->ndest_constraints == 0)
		החזר 0; /* unconstrained */
	אם (e->session_bind_attempted && e->nsession_ids == 0) {
		error_f("previous session bind failed on socket");
		החזר -1;
	}
	אם (e->nsession_ids == 0)
		החזר 0; /* local use */
	/*
	 * Walk through the hops recorded by session_id and try to find a
	 * constraint that satisfies each.
	 */
	עבור (i = 0; i < e->nsession_ids; i++) {
		hks = e->session_ids + i;
		אם (hks->key == عدم)
			fatal_f("internal error: no bound key");
		/* XXX remove logspam */
		fp1 = fp2 = عدم;
		אם (fromkey != عدم &&
		    (fp1 = sshkey_fingerprint(fromkey, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == عدم)
			fatal_f("fingerprint failed");
		אם ((fp2 = sshkey_fingerprint(hks->key, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == عدم)
			fatal_f("fingerprint failed");
		debug3_f("socketentry fd=%d, entry %zu %s, "
		    "from hostkey %s %s to user %s hostkey %s %s",
		    e->fd, i, hks->forwarded ? "FORWARD" : "AUTH",
		    fromkey ? sshkey_type(fromkey) : "(ORIGIN)",
		    fromkey ? fp1 : "", user ? user : "(ANY)",
		    sshkey_type(hks->key), fp2);
		حرر(fp1);
		حرر(fp2);
		/*
		 * Record the hostnames for the initial forwarding and
		 * the final destination.
		 */
		hp = عدم;
		אם (i == e->nsession_ids - 1)
			hp = last_hostnamep;
		אחרת אם (i == 0)
			hp = forward_hostnamep;
		/* Special handling for final recorded binding */
		test_user = عدم;
		אם (i == e->nsession_ids - 1) {
			/* Can only check user at final hop */
			test_user = user;
			/*
			 * user is only presented for signature requests.
			 * If this is the case, make sure last binding is not
			 * for a forwarding.
			 */
			אם (hks->forwarded && user != عدم) {
				error_f("tried to sign on forwarding hop");
				החזר -1;
			}
		} אחרת אם (!hks->forwarded) {
			error_f("tried to forward though signing bind");
			החזר -1;
		}
		אם (permitted_by_dest_constraints(fromkey, hks->key, id,
		    test_user, hp) != 0)
			החזר -1;
		fromkey = hks->key;
	}
	/*
	 * Another special case: if the last bound session ID was for a
	 * forwarding, and this function is not being called to check a sign
	 * request (i.e. no 'user' supplied), then only permit the key if
	 * there is a permission that would allow it to be used at another
	 * destination. This hides keys that are allowed to be used to
	 * authenticate *to* a host but not permitted for *use* beyond it.
	 */
	hks = &e->session_ids[e->nsession_ids - 1];
	אם (hks->forwarded && user == عدم &&
	    permitted_by_dest_constraints(hks->key, عدم, id,
	    عدم, عدم) != 0) {
		debug3_f("key permitted at host but not after");
		החזר -1;
	}

	/* success */
	החזר 0;
}

ساكن صحيح
socket_is_remote(SocketEntry *e)
{
	החזר e->session_bind_attempted || (e->nsession_ids != 0);
}

/* return matching private key for given public key */
ساكن Identity *
lookup_identity(بنية sshkey *key)
{
	Identity *id;

	TAILQ_FOREACH(id, &idtab->idlist, next) {
		אם (sshkey_equal(key, id->key))
			החזר (id);
	}
	החזר (عدم);
}

/* Check confirmation of keysign request */
ساكن صحيح
confirm_key(Identity *id, ثابت حرف *extra)
{
	حرف *p;
	صحيح ret = -1;

	p = sshkey_fingerprint(id->key, fingerprint_hash, SSH_FP_DEFAULT);
	אם (p != عدم &&
	    ask_permission("Allow use of key %s?\nKey fingerprint %s.%s%s",
	    id->comment, p,
	    extra == عدم ? "" : "\n", extra == عدم ? "" : extra))
		ret = 0;
	حرر(p);

	החזר (ret);
}

ساكن فراغ
send_status_generic(SocketEntry *e, u_int code)
{
	صحيح r;

	אם ((r = sshbuf_put_u32(e->output, 1)) != 0 ||
	    (r = sshbuf_put_u8(e->output, code)) != 0)
		fatal_fr(r, "compose");
}

ساكن فراغ
send_status(SocketEntry *e, صحيح success)
{
	send_status_generic(e,
	    success ? SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE);
}

/* send list of supported public keys to 'client' */
ساكن فراغ
process_request_identities(SocketEntry *e)
{
	Identity *id;
	بنية sshbuf *msg, *keys;
	صحيح r;
	u_int i = 0, nentries = 0;
	حرف *fp;

	debug2_f("entering");

	אם ((msg = sshbuf_new()) == عدم || (keys = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	TAILQ_FOREACH(id, &idtab->idlist, next) {
		אם ((fp = sshkey_fingerprint(id->key, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == عدم)
			fatal_f("fingerprint failed");
		debug_f("key %u / %u: %s %s", i++, idtab->nentries,
		    sshkey_ssh_name(id->key), fp);
		dump_dest_constraints(__func__,
		    id->dest_constraints, id->ndest_constraints);
		حرر(fp);
		/* identity not visible, don't include in response */
		אם (identity_permitted(id, e, عدم, عدم, عدم) != 0)
			استمر;
		אם ((r = sshkey_puts(id->key, keys)) != 0 ||
		    (r = sshbuf_put_cstring(keys, id->comment)) != 0) {
			error_fr(r, "compose key/comment");
			استمر;
		}
		nentries++;
	}
	debug2_f("replying with %u allowed of %u available keys",
	    nentries, idtab->nentries);
	אם ((r = sshbuf_put_u8(msg, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
	    (r = sshbuf_put_u32(msg, nentries)) != 0 ||
	    (r = sshbuf_putb(msg, keys)) != 0)
		fatal_fr(r, "compose");
	אם ((r = sshbuf_put_stringb(e->output, msg)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(msg);
	sshbuf_free(keys);
}


ساكن حرف *
agent_decode_alg(بنية sshkey *key, u_int flags)
{
	אם (key->type == KEY_RSA) {
		אם (flags & SSH_AGENT_RSA_SHA2_256)
			החזר "rsa-sha2-256";
		אחרת אם (flags & SSH_AGENT_RSA_SHA2_512)
			החזר "rsa-sha2-512";
	} אחרת אם (key->type == KEY_RSA_CERT) {
		אם (flags & SSH_AGENT_RSA_SHA2_256)
			החזר "rsa-sha2-256-cert-v01@openssh.com";
		אחרת אם (flags & SSH_AGENT_RSA_SHA2_512)
			החזר "rsa-sha2-512-cert-v01@openssh.com";
	}
	החזר عدم;
}

/*
 * Attempt to parse the contents of a buffer as a SSH publickey userauth
 * request, checking its contents for consistency and matching the embedded
 * key against the one that is being used for signing.
 * Note: does not modify msg buffer.
 * Optionally extract the username, session ID and/or hostkey from the request.
 */
ساكن صحيح
parse_userauth_request(بنية sshbuf *msg, ثابت بنية sshkey *expected_key,
    حرف **userp, بنية sshbuf **sess_idp, بنية sshkey **hostkeyp)
{
	بنية sshbuf *b = عدم, *sess_id = عدم;
	حرف *user = عدم, *service = عدم, *method = عدم, *pkalg = عدم;
	صحيح r;
	u_char t, sig_follows;
	بنية sshkey *mkey = عدم, *hostkey = عدم;

	אם (userp != عدم)
		*userp = عدم;
	אם (sess_idp != عدم)
		*sess_idp = عدم;
	אם (hostkeyp != عدم)
		*hostkeyp = عدم;
	אם ((b = sshbuf_fromb(msg)) == عدم)
		fatal_f("sshbuf_fromb");

	/* SSH userauth request */
	אם ((r = sshbuf_froms(b, &sess_id)) != 0)
		اذهب out;
	אם (sshbuf_len(sess_id) == 0) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	אם ((r = sshbuf_get_u8(b, &t)) != 0 || /* SSH2_MSG_USERAUTH_REQUEST */
	    (r = sshbuf_get_cstring(b, &user, عدم)) != 0 || /* server user */
	    (r = sshbuf_get_cstring(b, &service, عدم)) != 0 || /* service */
	    (r = sshbuf_get_cstring(b, &method, عدم)) != 0 || /* method */
	    (r = sshbuf_get_u8(b, &sig_follows)) != 0 || /* sig-follows */
	    (r = sshbuf_get_cstring(b, &pkalg, عدم)) != 0 || /* alg */
	    (r = sshkey_froms(b, &mkey)) != 0) /* key */
		اذهب out;
	אם (t != SSH2_MSG_USERAUTH_REQUEST ||
	    sig_follows != 1 ||
	    strcmp(service, "ssh-connection") != 0 ||
	    !sshkey_equal(expected_key, mkey) ||
	    sshkey_type_from_name(pkalg) != expected_key->type) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	אם (strcmp(method, "publickey-hostbound-v00@openssh.com") == 0) {
		אם ((r = sshkey_froms(b, &hostkey)) != 0)
			اذهب out;
	} אחרת אם (strcmp(method, "publickey") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	אם (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	/* success */
	r = 0;
	debug3_f("well formed userauth");
	אם (userp != عدم) {
		*userp = user;
		user = عدم;
	}
	אם (sess_idp != عدم) {
		*sess_idp = sess_id;
		sess_id = عدم;
	}
	אם (hostkeyp != عدم) {
		*hostkeyp = hostkey;
		hostkey = عدم;
	}
 out:
	sshbuf_free(b);
	sshbuf_free(sess_id);
	حرر(user);
	حرر(service);
	حرر(method);
	حرر(pkalg);
	sshkey_free(mkey);
	sshkey_free(hostkey);
	החזר r;
}

/*
 * Attempt to parse the contents of a buffer as a SSHSIG signature request.
 * Note: does not modify buffer.
 */
ساكن صحيح
parse_sshsig_request(بنية sshbuf *msg)
{
	صحيح r;
	بنية sshbuf *b;

	אם ((b = sshbuf_fromb(msg)) == عدم)
		fatal_f("sshbuf_fromb");

	אם ((r = sshbuf_cmp(b, 0, "SSHSIG", 6)) != 0 ||
	    (r = sshbuf_consume(b, 6)) != 0 ||
	    (r = sshbuf_get_cstring(b, عدم, عدم)) != 0 || /* namespace */
	    (r = sshbuf_get_string_direct(b, عدم, عدم)) != 0 || /* reserved */
	    (r = sshbuf_get_cstring(b, عدم, عدم)) != 0 || /* hashalg */
	    (r = sshbuf_get_string_direct(b, عدم, عدم)) != 0) /* H(msg) */
		اذهب out;
	אם (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	החזר r;
}

/*
 * This function inspects a message to be signed by a FIDO key that has a
 * web-like application string (i.e. one that does not begin with "ssh:".
 * It checks that the message is one of those expected for SSH operations
 * (pubkey userauth, sshsig, CA key signing) to exclude signing challenges
 * for the web.
 */
ساكن صحيح
check_websafe_message_contents(بنية sshkey *key, بنية sshbuf *data)
{
	אם (parse_userauth_request(data, key, عدم, عدم, عدم) == 0) {
		debug_f("signed data matches public key userauth request");
		החזר 1;
	}
	אם (parse_sshsig_request(data) == 0) {
		debug_f("signed data matches SSHSIG signature request");
		החזר 1;
	}

	/* XXX check CA signature operation */

	error("web-origin key attempting to sign non-SSH message");
	החזר 0;
}

ساكن صحيح
buf_equal(ثابت بنية sshbuf *a, ثابت بنية sshbuf *b)
{
	אם (sshbuf_ptr(a) == عدم || sshbuf_ptr(b) == عدم)
		החזר SSH_ERR_INVALID_ARGUMENT;
	אם (sshbuf_len(a) != sshbuf_len(b))
		החזר SSH_ERR_INVALID_FORMAT;
	אם (timingsafe_bcmp(sshbuf_ptr(a), sshbuf_ptr(b), sshbuf_len(a)) != 0)
		החזר SSH_ERR_INVALID_FORMAT;
	החזר 0;
}

/* ssh2 only */
ساكن فراغ
process_sign_request2(SocketEntry *e)
{
	u_char *signature = عدم;
	size_t slen = 0;
	u_int compat = 0, flags;
	صحيح r, ok = -1, retried = 0;
	حرف *fp = عدم, *pin = عدم, *prompt = عدم;
	حرف *user = عدم, *sig_dest = عدم;
	ثابت حرف *fwd_host = عدم, *dest_host = عدم;
	بنية sshbuf *msg = عدم, *data = عدم, *sid = عدم;
	بنية sshkey *key = عدم, *hostkey = عدم;
	بنية identity *id;
	بنية notifier_ctx *notifier = عدم;

	debug_f("entering");

	אם ((msg = sshbuf_new()) == عدم || (data = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	אם ((r = sshkey_froms(e->request, &key)) != 0 ||
	    (r = sshbuf_get_stringb(e->request, data)) != 0 ||
	    (r = sshbuf_get_u32(e->request, &flags)) != 0) {
		error_fr(r, "parse");
		اذهب send;
	}

	אם ((id = lookup_identity(key)) == عدم) {
		verbose_f("%s key not found", sshkey_type(key));
		اذهب send;
	}
	אם ((fp = sshkey_fingerprint(key, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == عدم)
		fatal_f("fingerprint failed");

	אם (id->ndest_constraints != 0) {
		אם (e->nsession_ids == 0) {
			logit_f("refusing use of destination-constrained key "
			    "to sign on unbound connection");
			اذهب send;
		}
		אם (parse_userauth_request(data, key, &user, &sid,
		    &hostkey) != 0) {
			logit_f("refusing use of destination-constrained key "
			   "to sign an unidentified signature");
			اذهب send;
		}
		/* XXX logspam */
		debug_f("user=%s", user);
		אם (identity_permitted(id, e, user, &fwd_host, &dest_host) != 0)
			اذهب send;
		/* XXX display fwd_host/dest_host in askpass UI */
		/*
		 * Ensure that the session ID is the most recent one
		 * registered on the socket - it should have been bound by
		 * ssh immediately before userauth.
		 */
		אם (buf_equal(sid,
		    e->session_ids[e->nsession_ids - 1].sid) != 0) {
			error_f("unexpected session ID (%zu listed) on "
			    "signature request for target user %s with "
			    "key %s %s", e->nsession_ids, user,
			    sshkey_type(id->key), fp);
			اذهب send;
		}
		/*
		 * Ensure that the hostkey embedded in the signature matches
		 * the one most recently bound to the socket. An exception is
		 * made for the initial forwarding hop.
		 */
		אם (e->nsession_ids > 1 && hostkey == عدم) {
			error_f("refusing use of destination-constrained key: "
			    "no hostkey recorded in signature for forwarded "
			    "connection");
			اذهب send;
		}
		אם (hostkey != عدم && !sshkey_equal(hostkey,
		    e->session_ids[e->nsession_ids - 1].key)) {
			error_f("refusing use of destination-constrained key: "
			    "mismatch between hostkey in request and most "
			    "recently bound session");
			اذهب send;
		}
		xasprintf(&sig_dest, "public key authentication request for "
		    "user \"%s\" to listed host", user);
	}
	אם (id->confirm && confirm_key(id, sig_dest) != 0) {
		verbose_f("user refused key");
		اذهب send;
	}
	אם (sshkey_is_sk(id->key)) {
		אם (restrict_websafe &&
		    match_pattern_list(id->key->sk_application,
		    websafe_allowlist, 0) != 1 &&
		    !check_websafe_message_contents(key, data)) {
			/* error already logged */
			اذهب send;
		}
		אם (id->key->sk_flags & SSH_SK_USER_PRESENCE_REQD) {
			notifier = notify_start(0,
			    "Confirm user presence for key %s %s%s%s",
			    sshkey_type(id->key), fp,
			    sig_dest == عدم ? "" : "\n",
			    sig_dest == عدم ? "" : sig_dest);
		}
	}
 retry_pin:
	אם ((r = sshkey_sign(id->key, &signature, &slen,
	    sshbuf_ptr(data), sshbuf_len(data), agent_decode_alg(key, flags),
	    id->sk_provider, pin, compat)) != 0) {
		debug_fr(r, "sshkey_sign");
		אם (pin == عدم && !retried && sshkey_is_sk(id->key) &&
		    r == SSH_ERR_KEY_WRONG_PASSPHRASE) {
			notify_complete(notifier, عدم);
			notifier = عدم;
			/* XXX include sig_dest */
			xasprintf(&prompt, "Enter PIN%sfor %s key %s: ",
			    (id->key->sk_flags & SSH_SK_USER_PRESENCE_REQD) ?
			    " and confirm user presence " : " ",
			    sshkey_type(id->key), fp);
			pin = read_passphrase(prompt, RP_USE_ASKPASS);
			retried = 1;
			اذهب retry_pin;
		}
		error_fr(r, "sshkey_sign");
		اذهب send;
	}
	/* Success */
	ok = 0;
	debug_f("good signature");
 send:
	notify_complete(notifier, "User presence confirmed");

	אם (ok == 0) {
		אם ((r = sshbuf_put_u8(msg, SSH2_AGENT_SIGN_RESPONSE)) != 0 ||
		    (r = sshbuf_put_string(msg, signature, slen)) != 0)
			fatal_fr(r, "compose");
	} אחרת אם ((r = sshbuf_put_u8(msg, SSH_AGENT_FAILURE)) != 0)
		fatal_fr(r, "compose failure");

	אם ((r = sshbuf_put_stringb(e->output, msg)) != 0)
		fatal_fr(r, "enqueue");

	sshbuf_free(sid);
	sshbuf_free(data);
	sshbuf_free(msg);
	sshkey_free(key);
	sshkey_free(hostkey);
	حرر(fp);
	حرر(signature);
	حرر(sig_dest);
	حرر(user);
	حرر(prompt);
	אם (pin != عدم)
		freezero(pin, strlen(pin));
}

/* shared */
ساكن فراغ
process_remove_identity(SocketEntry *e)
{
	صحيح r, success = 0;
	بنية sshkey *key = عدم;
	Identity *id;

	debug2_f("entering");
	אם ((r = sshkey_froms(e->request, &key)) != 0) {
		error_fr(r, "parse key");
		اذهب done;
	}
	אם ((id = lookup_identity(key)) == عدم) {
		debug_f("key not found");
		اذهب done;
	}
	/* identity not visible, cannot be removed */
	אם (identity_permitted(id, e, عدم, عدم, عدم) != 0)
		اذهب done; /* error already logged */
	/* We have this key, free it. */
	אם (idtab->nentries < 1)
		fatal_f("internal error: nentries %d", idtab->nentries);
	TAILQ_REMOVE(&idtab->idlist, id, next);
	free_identity(id);
	idtab->nentries--;
	success = 1;
 done:
	sshkey_free(key);
	send_status(e, success);
}

ساكن فراغ
remove_all_identities(فراغ)
{
	Identity *id;

	debug2_f("entering");
	/* Loop over all identities and clear the keys. */
	עבור (id = TAILQ_FIRST(&idtab->idlist); id;
	    id = TAILQ_FIRST(&idtab->idlist)) {
		TAILQ_REMOVE(&idtab->idlist, id, next);
		free_identity(id);
	}

	/* Mark that there are no identities. */
	idtab->nentries = 0;
}

ساكن فراغ
process_remove_all_identities(SocketEntry *e)
{
	remove_all_identities();

	/* Send success. */
	send_status(e, 1);
}

/* removes expired keys and returns number of seconds until the next expiry */
ساكن time_t
reaper(فراغ)
{
	time_t deadline = 0, now = monotime();
	Identity *id, *nxt;

	עבור (id = TAILQ_FIRST(&idtab->idlist); id; id = nxt) {
		nxt = TAILQ_NEXT(id, next);
		אם (id->death == 0)
			استمر;
		אם (now >= id->death) {
			debug("expiring key '%s'", id->comment);
			TAILQ_REMOVE(&idtab->idlist, id, next);
			free_identity(id);
			idtab->nentries--;
		} אחרת
			deadline = (deadline == 0) ? id->death :
			    MINIMUM(deadline, id->death);
	}
	אם (deadline == 0 || deadline <= now)
		החזר 0;
	אחרת
		החזר (deadline - now);
}

ساكن صحيح
parse_dest_constraint_hop(بنية sshbuf *b, بنية dest_constraint_hop *dch)
{
	u_char key_is_ca;
	size_t elen = 0, userlen = 0;
	صحيح r;
	بنية sshkey *k = عدم;
	حرف *fp;

	memset(dch, '\0', حجم(*dch));
	אם ((r = sshbuf_get_cstring(b, &dch->user, &userlen)) != 0 ||
	    (r = sshbuf_get_cstring(b, &dch->hostname, عدم)) != 0 ||
	    (r = sshbuf_get_string_direct(b, عدم, &elen)) != 0) {
		error_fr(r, "parse");
		اذهب out;
	}
	אם (elen != 0) {
		error_f("unsupported extensions (len %zu)", elen);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		اذهب out;
	}
	אם (*dch->hostname == '\0') {
		حرر(dch->hostname);
		dch->hostname = عدم;
	}
	אם (*dch->user == '\0') {
		حرر(dch->user);
		dch->user = عدم;
	} אחרת אם (userlen > AGENT_USER_CONSTRAINT_MAX_LEN) {
		error_f("user match pattern too long");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	כלעוד (sshbuf_len(b) != 0) {
		dch->keys = xrecallocarray(dch->keys, dch->nkeys,
		    dch->nkeys + 1, حجم(*dch->keys));
		dch->key_is_ca = xrecallocarray(dch->key_is_ca, dch->nkeys,
		    dch->nkeys + 1, حجم(*dch->key_is_ca));
		אם ((r = sshkey_froms(b, &k)) != 0 ||
		    (r = sshbuf_get_u8(b, &key_is_ca)) != 0)
			اذهب out;
		אם ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == عدم)
			fatal_f("fingerprint failed");
		debug3_f("%s%s%s: adding %skey %s %s",
		    dch->user == عدم ? "" : dch->user,
		    dch->user == عدم ? "" : "@",
		    dch->hostname, key_is_ca ? "CA " : "", sshkey_type(k), fp);
		حرر(fp);
		dch->keys[dch->nkeys] = k;
		dch->key_is_ca[dch->nkeys] = key_is_ca != 0;
		dch->nkeys++;
		k = عدم; /* transferred */
	}
	/* success */
	r = 0;
 out:
	sshkey_free(k);
	החזר r;
}

ساكن صحيح
parse_dest_constraint(بنية sshbuf *m, بنية dest_constraint *dc)
{
	بنية sshbuf *b = عدم, *frombuf = عدم, *tobuf = عدم;
	صحيح r;
	size_t elen = 0;

	debug3_f("entering");

	memset(dc, '\0', حجم(*dc));
	אם ((r = sshbuf_froms(m, &b)) != 0 ||
	    (r = sshbuf_froms(b, &frombuf)) != 0 ||
	    (r = sshbuf_froms(b, &tobuf)) != 0 ||
	    (r = sshbuf_get_string_direct(b, عدم, &elen)) != 0) {
		error_fr(r, "parse");
		اذهب out;
	}
	אם ((r = parse_dest_constraint_hop(frombuf, &dc->from)) != 0 ||
	    (r = parse_dest_constraint_hop(tobuf, &dc->to)) != 0)
		اذهب out; /* already logged */
	אם (elen != 0) {
		error_f("unsupported extensions (len %zu)", elen);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		اذهب out;
	}
	debug2_f("parsed %s (%u keys) > %s%s%s (%u keys)",
	    dc->from.hostname ? dc->from.hostname : "(ORIGIN)", dc->from.nkeys,
	    dc->to.user ? dc->to.user : "", dc->to.user ? "@" : "",
	    dc->to.hostname ? dc->to.hostname : "(ANY)", dc->to.nkeys);
	/* check consistency */
	אם ((dc->from.hostname == عدم) != (dc->from.nkeys == 0) ||
	    dc->from.user != عدم) {
		error_f("inconsistent \"from\" specification");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	אם (dc->to.hostname == عدم || dc->to.nkeys == 0) {
		error_f("incomplete \"to\" specification");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	sshbuf_free(frombuf);
	sshbuf_free(tobuf);
	החזר r;
}

ساكن صحيح
parse_key_constraint_extension(بنية sshbuf *m, حرف **sk_providerp,
    بنية dest_constraint **dcsp, size_t *ndcsp, صحيح *cert_onlyp,
    بنية sshkey ***certs, size_t *ncerts)
{
	حرف *ext_name = عدم;
	صحيح r;
	بنية sshbuf *b = عدم;
	u_char v;
	بنية sshkey *k;

	אם ((r = sshbuf_get_cstring(m, &ext_name, عدم)) != 0) {
		error_fr(r, "parse constraint extension");
		اذهب out;
	}
	debug_f("constraint ext %s", ext_name);
	אם (strcmp(ext_name, "sk-provider@openssh.com") == 0) {
		אם (sk_providerp == عدم) {
			error_f("%s not valid here", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			اذهب out;
		}
		אם (*sk_providerp != عدم) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			اذهب out;
		}
		אם ((r = sshbuf_get_cstring(m, sk_providerp, عدم)) != 0) {
			error_fr(r, "parse %s", ext_name);
			اذهب out;
		}
	} אחרת אם (strcmp(ext_name,
	    "restrict-destination-v00@openssh.com") == 0) {
		אם (*dcsp != عدم) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			اذهب out;
		}
		אם ((r = sshbuf_froms(m, &b)) != 0) {
			error_fr(r, "parse %s outer", ext_name);
			اذهب out;
		}
		כלעוד (sshbuf_len(b) != 0) {
			אם (*ndcsp >= AGENT_MAX_DEST_CONSTRAINTS) {
				error_f("too many %s constraints", ext_name);
				r = SSH_ERR_INVALID_FORMAT;
				اذهب out;
			}
			*dcsp = xrecallocarray(*dcsp, *ndcsp, *ndcsp + 1,
			    حجم(**dcsp));
			אם ((r = parse_dest_constraint(b,
			    *dcsp + (*ndcsp)++)) != 0)
				اذهب out; /* error already logged */
		}
	} אחרת אם (strcmp(ext_name,
	    "associated-certs-v00@openssh.com") == 0) {
		אם (certs == عدم || ncerts == عدم || cert_onlyp == عدم) {
			error_f("%s not valid here", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			اذهب out;
		}
		אם (*certs != عدم) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			اذهب out;
		}
		אם ((r = sshbuf_get_u8(m, &v)) != 0 ||
		    (r = sshbuf_froms(m, &b)) != 0) {
			error_fr(r, "parse %s", ext_name);
			اذهب out;
		}
		*cert_onlyp = v != 0;
		כלעוד (sshbuf_len(b) != 0) {
			אם (*ncerts >= AGENT_MAX_EXT_CERTS) {
				error_f("too many %s constraints", ext_name);
				r = SSH_ERR_INVALID_FORMAT;
				اذهب out;
			}
			*certs = xrecallocarray(*certs, *ncerts, *ncerts + 1,
			    حجم(**certs));
			אם ((r = sshkey_froms(b, &k)) != 0) {
				error_fr(r, "parse key");
				اذهب out;
			}
			(*certs)[(*ncerts)++] = k;
		}
	} אחרת {
		error_f("unsupported constraint \"%s\"", ext_name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		اذهب out;
	}
	/* success */
	r = 0;
 out:
	حرر(ext_name);
	sshbuf_free(b);
	החזר r;
}

ساكن صحيح
parse_key_constraints(بنية sshbuf *m, بنية sshkey *k, time_t *deathp,
    u_int *secondsp, صحيح *confirmp, حرف **sk_providerp,
    بنية dest_constraint **dcsp, size_t *ndcsp,
    صحيح *cert_onlyp, size_t *ncerts, بنية sshkey ***certs)
{
	u_char ctype;
	صحيح r;
	u_int seconds;

	כלעוד (sshbuf_len(m)) {
		אם ((r = sshbuf_get_u8(m, &ctype)) != 0) {
			error_fr(r, "parse constraint type");
			اذهب out;
		}
		بدل (ctype) {
		حالة SSH_AGENT_CONSTRAIN_LIFETIME:
			אם (*deathp != 0) {
				error_f("lifetime already set");
				r = SSH_ERR_INVALID_FORMAT;
				اذهب out;
			}
			אם ((r = sshbuf_get_u32(m, &seconds)) != 0) {
				error_fr(r, "parse lifetime constraint");
				اذهب out;
			}
			*deathp = monotime() + seconds;
			*secondsp = seconds;
			اكسر;
		حالة SSH_AGENT_CONSTRAIN_CONFIRM:
			אם (*confirmp != 0) {
				error_f("confirm already set");
				r = SSH_ERR_INVALID_FORMAT;
				اذهب out;
			}
			*confirmp = 1;
			اكسر;
		حالة SSH_AGENT_CONSTRAIN_EXTENSION:
			אם ((r = parse_key_constraint_extension(m,
			    sk_providerp, dcsp, ndcsp,
			    cert_onlyp, certs, ncerts)) != 0)
				اذهب out; /* error already logged */
			اكسر;
		افتراضي:
			error_f("Unknown constraint %d", ctype);
			r = SSH_ERR_FEATURE_UNSUPPORTED;
			اذهب out;
		}
	}
	/* success */
	r = 0;
 out:
	החזר r;
}

ساكن فراغ
process_add_identity(SocketEntry *e)
{
	Identity *id;
	صحيح success = 0, confirm = 0;
	حرف *fp, *comment = عدم, *sk_provider = عدم;
	حرف canonical_provider[PATH_MAX];
	time_t death = 0;
	u_int seconds = 0;
	بنية dest_constraint *dest_constraints = عدم;
	size_t ndest_constraints = 0;
	بنية sshkey *k = عدم;
	صحيح r = SSH_ERR_INTERNAL_ERROR;

	debug2_f("entering");
	אם ((r = sshkey_private_deserialize(e->request, &k)) != 0 ||
	    k == عدم ||
	    (r = sshbuf_get_cstring(e->request, &comment, عدم)) != 0) {
		error_fr(r, "parse");
		اذهب out;
	}
	אם (parse_key_constraints(e->request, k, &death, &seconds, &confirm,
	    &sk_provider, &dest_constraints, &ndest_constraints,
	    عدم, عدم, عدم) != 0) {
		error_f("failed to parse constraints");
		sshbuf_reset(e->request);
		اذهب out;
	}
	dump_dest_constraints(__func__, dest_constraints, ndest_constraints);

	אם (sk_provider != عدم) {
		אם (!sshkey_is_sk(k)) {
			error("Cannot add provider: %s is not an "
			    "authenticator-hosted key", sshkey_type(k));
			اذهب out;
		}
		אם (strcasecmp(sk_provider, "internal") == 0) {
			debug_f("internal provider");
		} אחרת {
			אם (socket_is_remote(e) && !remote_add_provider) {
				verbose("failed add of SK provider \"%.100s\": "
				    "remote addition of providers is disabled",
				    sk_provider);
				اذهب out;
			}
			אם (realpath(sk_provider, canonical_provider) == عدم) {
				verbose("failed provider \"%.100s\": "
				    "realpath: %s", sk_provider,
				    strerror(errno));
				اذهب out;
			}
			حرر(sk_provider);
			sk_provider = xstrdup(canonical_provider);
			אם (match_pattern_list(sk_provider,
			    allowed_providers, 0) != 1) {
				error("Refusing add key: "
				    "provider %s not allowed", sk_provider);
				اذهب out;
			}
		}
	}
	אם ((r = sshkey_shield_private(k)) != 0) {
		error_fr(r, "shield private");
		اذهب out;
	}
	אם (lifetime && !death)
		death = monotime() + lifetime;
	אם ((id = lookup_identity(k)) == عدم) {
		id = xcalloc(1, حجم(Identity));
		TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
		/* Increment the number of identities. */
		idtab->nentries++;
	} אחרת {
		/* identity not visible, do not update */
		אם (identity_permitted(id, e, عدم, عدم, عدم) != 0)
			اذهب out; /* error already logged */
		/* key state might have been updated */
		sshkey_free(id->key);
		حرر(id->comment);
		حرر(id->sk_provider);
		free_dest_constraints(id->dest_constraints,
		    id->ndest_constraints);
	}
	/* success */
	id->key = k;
	id->comment = comment;
	id->death = death;
	id->confirm = confirm;
	id->sk_provider = sk_provider;
	id->dest_constraints = dest_constraints;
	id->ndest_constraints = ndest_constraints;

	אם ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == عدم)
		fatal_f("sshkey_fingerprint failed");
	debug_f("add %s %s \"%.100s\" (life: %u) (confirm: %u) "
	    "(provider: %s) (destination constraints: %zu)",
	    sshkey_ssh_name(k), fp, comment, seconds, confirm,
	    sk_provider == عدم ? "none" : sk_provider, ndest_constraints);
	حرر(fp);
	/* transferred */
	k = عدم;
	comment = عدم;
	sk_provider = عدم;
	dest_constraints = عدم;
	ndest_constraints = 0;
	success = 1;
 out:
	حرر(sk_provider);
	حرر(comment);
	sshkey_free(k);
	free_dest_constraints(dest_constraints, ndest_constraints);
	send_status(e, success);
}

/* XXX todo: encrypt sensitive data with passphrase */
ساكن فراغ
process_lock_agent(SocketEntry *e, صحيح lock)
{
	صحيح r, success = 0, delay;
	حرف *passwd;
	u_char passwdhash[LOCK_SIZE];
	ساكن u_int fail_count = 0;
	size_t pwlen;

	debug2_f("entering");
	/*
	 * This is deliberately fatal: the user has requested that we lock,
	 * but we can't parse their request properly. The only safe thing to
	 * do is abort.
	 */
	אם ((r = sshbuf_get_cstring(e->request, &passwd, &pwlen)) != 0)
		fatal_fr(r, "parse");
	אם (pwlen == 0) {
		debug("empty password not supported");
	} אחרת אם (locked && !lock) {
		אם (bcrypt_pbkdf(passwd, pwlen, lock_salt, حجم(lock_salt),
		    passwdhash, حجم(passwdhash), LOCK_ROUNDS) < 0)
			fatal("bcrypt_pbkdf");
		אם (timingsafe_bcmp(passwdhash, lock_pwhash, LOCK_SIZE) == 0) {
			debug("agent unlocked");
			locked = 0;
			fail_count = 0;
			explicit_bzero(lock_pwhash, حجم(lock_pwhash));
			success = 1;
		} אחרת {
			/* delay in 0.1s increments up to 10s */
			אם (fail_count < 100)
				fail_count++;
			delay = 100000 * fail_count;
			debug("unlock failed, delaying %0.1lf seconds",
			    (مزدوج)delay/1000000);
			usleep(delay);
		}
		explicit_bzero(passwdhash, حجم(passwdhash));
	} אחרת אם (!locked && lock) {
		debug("agent locked");
		locked = 1;
		arc4random_buf(lock_salt, حجم(lock_salt));
		אם (bcrypt_pbkdf(passwd, pwlen, lock_salt, حجم(lock_salt),
		    lock_pwhash, حجم(lock_pwhash), LOCK_ROUNDS) < 0)
			fatal("bcrypt_pbkdf");
		success = 1;
	}
	freezero(passwd, pwlen);
	send_status(e, success);
}

ساكن فراغ
no_identities(SocketEntry *e)
{
	بنية sshbuf *msg;
	صحيح r;

	אם ((msg = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	אם ((r = sshbuf_put_u8(msg, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
	    (r = sshbuf_put_u32(msg, 0)) != 0 ||
	    (r = sshbuf_put_stringb(e->output, msg)) != 0)
		fatal_fr(r, "compose");
	sshbuf_free(msg);
}

#ifdef ENABLE_PKCS11
/* Add an identity to idlist; takes ownership of 'key' and 'comment' */
ساكن فراغ
add_p11_identity(بنية sshkey *key, حرف *comment, ثابت حرف *provider,
    time_t death, u_int confirm, بنية dest_constraint *dest_constraints,
    size_t ndest_constraints)
{
	Identity *id;

	אם (lookup_identity(key) != عدم) {
		sshkey_free(key);
		حرر(comment);
		החזר;
	}
	id = xcalloc(1, حجم(Identity));
	id->key = key;
	id->comment = comment;
	id->provider = xstrdup(provider);
	id->death = death;
	id->confirm = confirm;
	id->dest_constraints = dup_dest_constraints(dest_constraints,
	    ndest_constraints);
	id->ndest_constraints = ndest_constraints;
	TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
	idtab->nentries++;
}

ساكن فراغ
process_add_smartcard_key(SocketEntry *e)
{
	حرف *provider = عدم, *pin = عدم, canonical_provider[PATH_MAX];
	حرف **comments = عدم;
	صحيح r, i, count = 0, success = 0, confirm = 0;
	u_int seconds = 0;
	time_t death = 0;
	بنية sshkey **keys = عدم, *k;
	بنية dest_constraint *dest_constraints = عدم;
	size_t j, ndest_constraints = 0, ncerts = 0;
	بنية sshkey **certs = عدم;
	صحيح cert_only = 0;

	debug2_f("entering");
	אם ((r = sshbuf_get_cstring(e->request, &provider, عدم)) != 0 ||
	    (r = sshbuf_get_cstring(e->request, &pin, عدم)) != 0) {
		error_fr(r, "parse");
		اذهب send;
	}
	אם (parse_key_constraints(e->request, عدم, &death, &seconds, &confirm,
	    عدم, &dest_constraints, &ndest_constraints, &cert_only,
	    &ncerts, &certs) != 0) {
		error_f("failed to parse constraints");
		اذهب send;
	}
	dump_dest_constraints(__func__, dest_constraints, ndest_constraints);
	אם (socket_is_remote(e) && !remote_add_provider) {
		verbose("failed PKCS#11 add of \"%.100s\": remote addition of "
		    "providers is disabled", provider);
		اذهب send;
	}
	אם (realpath(provider, canonical_provider) == عدم) {
		verbose("failed PKCS#11 add of \"%.100s\": realpath: %s",
		    provider, strerror(errno));
		اذهب send;
	}
	אם (match_pattern_list(canonical_provider, allowed_providers, 0) != 1) {
		verbose("refusing PKCS#11 add of \"%.100s\": "
		    "provider not allowed", canonical_provider);
		اذهب send;
	}
	debug_f("add %.100s", canonical_provider);
	אם (lifetime && !death)
		death = monotime() + lifetime;

	count = pkcs11_add_provider(canonical_provider, pin, &keys, &comments);
	עבור (i = 0; i < count; i++) {
		אם (comments[i] == عدم || comments[i][0] == '\0') {
			حرر(comments[i]);
			comments[i] = xstrdup(canonical_provider);
		}
		עבור (j = 0; j < ncerts; j++) {
			אם (!sshkey_is_cert(certs[j]))
				استمر;
			אם (!sshkey_equal_public(keys[i], certs[j]))
				استمر;
			אם (pkcs11_make_cert(keys[i], certs[j], &k) != 0)
				استمر;
			add_p11_identity(k, xstrdup(comments[i]),
			    canonical_provider, death, confirm,
			    dest_constraints, ndest_constraints);
			success = 1;
		}
		אם (!cert_only && lookup_identity(keys[i]) == عدم) {
			add_p11_identity(keys[i], comments[i],
			    canonical_provider, death, confirm,
			    dest_constraints, ndest_constraints);
			keys[i] = عدم;		/* transferred */
			comments[i] = عدم;	/* transferred */
			success = 1;
		}
		/* XXX update constraints for existing keys */
		sshkey_free(keys[i]);
		حرر(comments[i]);
	}
send:
	حرر(pin);
	حرر(provider);
	حرر(keys);
	حرر(comments);
	free_dest_constraints(dest_constraints, ndest_constraints);
	עבור (j = 0; j < ncerts; j++)
		sshkey_free(certs[j]);
	حرر(certs);
	send_status(e, success);
}

ساكن فراغ
process_remove_smartcard_key(SocketEntry *e)
{
	حرف *provider = عدم, *pin = عدم, canonical_provider[PATH_MAX];
	صحيح r, success = 0;
	Identity *id, *nxt;

	debug2_f("entering");
	אם ((r = sshbuf_get_cstring(e->request, &provider, عدم)) != 0 ||
	    (r = sshbuf_get_cstring(e->request, &pin, عدم)) != 0) {
		error_fr(r, "parse");
		اذهب send;
	}
	حرر(pin);

	אם (realpath(provider, canonical_provider) == عدم) {
		verbose("failed PKCS#11 add of \"%.100s\": realpath: %s",
		    provider, strerror(errno));
		اذهب send;
	}

	debug_f("remove %.100s", canonical_provider);
	עבור (id = TAILQ_FIRST(&idtab->idlist); id; id = nxt) {
		nxt = TAILQ_NEXT(id, next);
		/* Skip file--based keys */
		אם (id->provider == عدم)
			استمر;
		אם (!strcmp(canonical_provider, id->provider)) {
			TAILQ_REMOVE(&idtab->idlist, id, next);
			free_identity(id);
			idtab->nentries--;
		}
	}
	אם (pkcs11_del_provider(canonical_provider) == 0)
		success = 1;
	אחרת
		error_f("pkcs11_del_provider failed");
send:
	حرر(provider);
	send_status(e, success);
}
#endif /* ENABLE_PKCS11 */

ساكن صحيح
process_ext_session_bind(SocketEntry *e)
{
	صحيح r, sid_match, key_match;
	بنية sshkey *key = عدم;
	بنية sshbuf *sid = عدم, *sig = عدم;
	حرف *fp = عدم;
	size_t i;
	u_char fwd = 0;

	debug2_f("entering");
	e->session_bind_attempted = 1;
	אם ((r = sshkey_froms(e->request, &key)) != 0 ||
	    (r = sshbuf_froms(e->request, &sid)) != 0 ||
	    (r = sshbuf_froms(e->request, &sig)) != 0 ||
	    (r = sshbuf_get_u8(e->request, &fwd)) != 0) {
		error_fr(r, "parse");
		اذهب out;
	}
	אם (sshbuf_len(sid) > AGENT_MAX_SID_LEN) {
		error_f("session ID too long");
		اذهب out;
	}
	אם ((fp = sshkey_fingerprint(key, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == عدم)
		fatal_f("fingerprint failed");
	/* check signature with hostkey on session ID */
	אם ((r = sshkey_verify(key, sshbuf_ptr(sig), sshbuf_len(sig),
	    sshbuf_ptr(sid), sshbuf_len(sid), عدم, 0, عدم)) != 0) {
		error_fr(r, "sshkey_verify for %s %s", sshkey_type(key), fp);
		اذهب out;
	}
	/* check whether sid/key already recorded */
	עבור (i = 0; i < e->nsession_ids; i++) {
		אם (!e->session_ids[i].forwarded) {
			error_f("attempt to bind session ID to socket "
			    "previously bound for authentication attempt");
			r = -1;
			اذهب out;
		}
		sid_match = buf_equal(sid, e->session_ids[i].sid) == 0;
		key_match = sshkey_equal(key, e->session_ids[i].key);
		אם (sid_match && key_match) {
			debug_f("session ID already recorded for %s %s",
			    sshkey_type(key), fp);
			r = 0;
			اذهب out;
		} אחרת אם (sid_match) {
			error_f("session ID recorded against different key "
			    "for %s %s", sshkey_type(key), fp);
			r = -1;
			اذهب out;
		}
		/*
		 * new sid with previously-seen key can happen, e.g. multiple
		 * connections to the same host.
		 */
	}
	/* record new key/sid */
	אם (e->nsession_ids >= AGENT_MAX_SESSION_IDS) {
		error_f("too many session IDs recorded");
		r = -1;
		اذهب out;
	}
	e->session_ids = xrecallocarray(e->session_ids, e->nsession_ids,
	    e->nsession_ids + 1, حجم(*e->session_ids));
	i = e->nsession_ids++;
	debug_f("recorded %s %s (slot %zu of %d)", sshkey_type(key), fp, i,
	    AGENT_MAX_SESSION_IDS);
	e->session_ids[i].key = key;
	e->session_ids[i].forwarded = fwd != 0;
	key = عدم; /* transferred */
	/* can't transfer sid; it's refcounted and scoped to request's life */
	אם ((e->session_ids[i].sid = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new");
	אם ((r = sshbuf_putb(e->session_ids[i].sid, sid)) != 0)
		fatal_fr(r, "sshbuf_putb session ID");
	/* success */
	r = 0;
 out:
	حرر(fp);
	sshkey_free(key);
	sshbuf_free(sid);
	sshbuf_free(sig);
	החזר r == 0 ? 1 : 0;
}

ساكن صحيح
process_ext_query(SocketEntry *e)
{
	صحيح r;
	بنية sshbuf *msg = عدم;

	debug2_f("entering");
	אם ((msg = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	אם ((r = sshbuf_put_u8(msg, SSH_AGENT_EXTENSION_RESPONSE)) != 0 ||
	    (r = sshbuf_put_cstring(msg, "query")) != 0 ||
	    /* string[]     supported extension types */
	    (r = sshbuf_put_cstring(msg, "session-bind@openssh.com")) != 0)
		fatal_fr(r, "compose");
	אם ((r = sshbuf_put_stringb(e->output, msg)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(msg);
	החזר 1;
}

ساكن فراغ
process_extension(SocketEntry *e)
{
	صحيح r, replied = 0, success = 0;
	حرف *name;

	debug2_f("entering");
	אם ((r = sshbuf_get_cstring(e->request, &name, عدم)) != 0) {
		error_fr(r, "parse");
		send_status(e, 0);
		החזר;
	}

	/*
	 * This function can be called while the agent is locked to allow
	 * session binds to be processed for new channels.
	 * Other operations should be refused when locked.
	 */

	אם (strcmp(name, "session-bind@openssh.com") == 0) {
		success = process_ext_session_bind(e);
	} אחרת אם (locked) {
		debug_f("attempt to use extension \"%s\" while locked", name);
		اذهب generic_fail;
	} אחרת אם (strcmp(name, "query") == 0) {
		replied = success = process_ext_query(e);
	} אחרת {
		debug_f("unsupported extension \"%s\"", name);
 generic_fail:
		حرر(name);
		send_status(e, 0);
		החזר;
	}
	حرر(name);
	/* Agent failures are signalled with a different error code */
	אם (!replied) {
		send_status_generic(e,
		    success ? SSH_AGENT_SUCCESS : SSH_AGENT_EXTENSION_FAILURE);
	}
}

/*
 * dispatch incoming message.
 * returns 1 on success, 0 for incomplete messages or -1 on error.
 */
ساكن صحيح
process_message(u_int socknum)
{
	u_int msg_len;
	u_char type;
	ثابت u_char *cp;
	صحيح r;
	SocketEntry *e;

	אם (socknum >= sockets_alloc)
		fatal_f("sock %u >= allocated %u", socknum, sockets_alloc);
	e = &sockets[socknum];

	אם (sshbuf_len(e->input) < 5)
		החזר 0;		/* Incomplete message header. */
	cp = sshbuf_ptr(e->input);
	msg_len = PEEK_U32(cp);
	אם (msg_len > AGENT_MAX_LEN) {
		debug_f("socket %u (fd=%d) message too long %u > %u",
		    socknum, e->fd, msg_len, AGENT_MAX_LEN);
		החזר -1;
	}
	אם (sshbuf_len(e->input) < msg_len + 4)
		החזר 0;		/* Incomplete message body. */

	/* move the current input to e->request */
	sshbuf_reset(e->request);
	אם ((r = sshbuf_get_stringb(e->input, e->request)) != 0 ||
	    (r = sshbuf_get_u8(e->request, &type)) != 0) {
		אם (r == SSH_ERR_MESSAGE_INCOMPLETE ||
		    r == SSH_ERR_STRING_TOO_LARGE) {
			error_fr(r, "parse");
			החזר -1;
		}
		fatal_fr(r, "parse");
	}

	debug_f("socket %u (fd=%d) type %d", socknum, e->fd, type);

	/* check whether agent is locked */
	אם (locked && type != SSH_AGENTC_UNLOCK) {
		بدل (type) {
		حالة SSH2_AGENTC_REQUEST_IDENTITIES:
			/* send empty lists */
			no_identities(e);
			اكسر;
		حالة SSH_AGENTC_EXTENSION:
			process_extension(e);
			اكسر;
		افتراضي:
			/* send a fail message for all other request types */
			send_status(e, 0);
		}
		sshbuf_reset(e->request);
		החזר 1;
	}

	بدل (type) {
	حالة SSH_AGENTC_LOCK:
	حالة SSH_AGENTC_UNLOCK:
		process_lock_agent(e, type == SSH_AGENTC_LOCK);
		اكسر;
	حالة SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES:
		process_remove_all_identities(e); /* safe for !WITH_SSH1 */
		اكسر;
	/* ssh2 */
	حالة SSH2_AGENTC_SIGN_REQUEST:
		process_sign_request2(e);
		اكسر;
	حالة SSH2_AGENTC_REQUEST_IDENTITIES:
		process_request_identities(e);
		اكسر;
	حالة SSH2_AGENTC_ADD_IDENTITY:
	حالة SSH2_AGENTC_ADD_ID_CONSTRAINED:
		process_add_identity(e);
		اكسر;
	حالة SSH2_AGENTC_REMOVE_IDENTITY:
		process_remove_identity(e);
		اكسر;
	حالة SSH2_AGENTC_REMOVE_ALL_IDENTITIES:
		process_remove_all_identities(e);
		اكسر;
#ifdef ENABLE_PKCS11
	حالة SSH_AGENTC_ADD_SMARTCARD_KEY:
	حالة SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED:
		process_add_smartcard_key(e);
		اكسر;
	حالة SSH_AGENTC_REMOVE_SMARTCARD_KEY:
		process_remove_smartcard_key(e);
		اكسر;
#endif /* ENABLE_PKCS11 */
	حالة SSH_AGENTC_EXTENSION:
		process_extension(e);
		اكسر;
	افتراضي:
		/* Unknown message.  Respond with failure. */
		error("Unknown message %d", type);
		sshbuf_reset(e->request);
		send_status(e, 0);
		اكسر;
	}
	החזר 1;
}

ساكن فراغ
new_socket(sock_type type, صحيح fd)
{
	u_int i, old_alloc, new_alloc;

	debug_f("type = %s", type == AUTH_CONNECTION ? "CONNECTION" :
	    (type == AUTH_SOCKET ? "SOCKET" : "UNKNOWN"));
	set_nonblock(fd);

	אם (fd > max_fd)
		max_fd = fd;

	עבור (i = 0; i < sockets_alloc; i++)
		אם (sockets[i].type == AUTH_UNUSED) {
			sockets[i].fd = fd;
			אם ((sockets[i].input = sshbuf_new()) == عدم ||
			    (sockets[i].output = sshbuf_new()) == عدم ||
			    (sockets[i].request = sshbuf_new()) == عدم)
				fatal_f("sshbuf_new failed");
			sockets[i].type = type;
			החזר;
		}
	old_alloc = sockets_alloc;
	new_alloc = sockets_alloc + 10;
	sockets = xrecallocarray(sockets, old_alloc, new_alloc,
	    حجم(sockets[0]));
	עבור (i = old_alloc; i < new_alloc; i++)
		sockets[i].type = AUTH_UNUSED;
	sockets_alloc = new_alloc;
	sockets[old_alloc].fd = fd;
	אם ((sockets[old_alloc].input = sshbuf_new()) == عدم ||
	    (sockets[old_alloc].output = sshbuf_new()) == عدم ||
	    (sockets[old_alloc].request = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	sockets[old_alloc].type = type;
}

ساكن صحيح
handle_socket_read(u_int socknum)
{
	بنية sockaddr_un sunaddr;
	socklen_t slen;
	uid_t euid;
	gid_t egid;
	صحيح fd;

	slen = حجم(sunaddr);
	fd = accept(sockets[socknum].fd, (بنية sockaddr *)&sunaddr, &slen);
	אם (fd == -1) {
		error("accept from AUTH_SOCKET: %s", strerror(errno));
		החזר -1;
	}
	אם (getpeereid(fd, &euid, &egid) == -1) {
		error("getpeereid %d failed: %s", fd, strerror(errno));
		close(fd);
		החזר -1;
	}
	אם ((euid != 0) && (getuid() != euid)) {
		error("uid mismatch: peer euid %u != uid %u",
		    (u_int) euid, (u_int) getuid());
		close(fd);
		החזר -1;
	}
	new_socket(AUTH_CONNECTION, fd);
	החזר 0;
}

ساكن صحيح
handle_conn_read(u_int socknum)
{
	حرف buf[AGENT_RBUF_LEN];
	ssize_t len;
	صحيح r;

	אם ((len = اقرأ(sockets[socknum].fd, buf, حجم(buf))) <= 0) {
		אם (len == -1) {
			אם (errno == EAGAIN || errno == EINTR)
				החזר 0;
			error_f("read error on socket %u (fd %d): %s",
			    socknum, sockets[socknum].fd, strerror(errno));
		}
		החזר -1;
	}
	אם ((r = sshbuf_put(sockets[socknum].input, buf, len)) != 0)
		fatal_fr(r, "compose");
	explicit_bzero(buf, حجم(buf));
	עבור (;;) {
		אם ((r = process_message(socknum)) == -1)
			החזר -1;
		אחרת אם (r == 0)
			اكسر;
	}
	החזר 0;
}

ساكن صحيح
handle_conn_write(u_int socknum)
{
	ssize_t len;
	صحيح r;

	אם (sshbuf_len(sockets[socknum].output) == 0)
		החזר 0; /* shouldn't happen */
	אם ((len = اكتب(sockets[socknum].fd,
	    sshbuf_ptr(sockets[socknum].output),
	    sshbuf_len(sockets[socknum].output))) <= 0) {
		אם (len == -1) {
			אם (errno == EAGAIN || errno == EINTR)
				החזר 0;
			error_f("read error on socket %u (fd %d): %s",
			    socknum, sockets[socknum].fd, strerror(errno));
		}
		החזר -1;
	}
	אם ((r = sshbuf_consume(sockets[socknum].output, len)) != 0)
		fatal_fr(r, "consume");
	החזר 0;
}

ساكن فراغ
after_poll(بنية pollfd *pfd, size_t npfd, u_int maxfds)
{
	size_t i;
	u_int socknum, activefds = npfd;

	עבור (i = 0; i < npfd; i++) {
		אם (pfd[i].revents == 0)
			استمر;
		/* Find sockets entry */
		עבור (socknum = 0; socknum < sockets_alloc; socknum++) {
			אם (sockets[socknum].type != AUTH_SOCKET &&
			    sockets[socknum].type != AUTH_CONNECTION)
				استمر;
			אם (pfd[i].fd == sockets[socknum].fd)
				اكسر;
		}
		אם (socknum >= sockets_alloc) {
			error_f("no socket for fd %d", pfd[i].fd);
			استمر;
		}
		/* Process events */
		بدل (sockets[socknum].type) {
		حالة AUTH_SOCKET:
			אם ((pfd[i].revents & (POLLIN|POLLERR)) == 0)
				اكسر;
			אם (npfd > maxfds) {
				debug3("out of fds (active %u >= limit %u); "
				    "skipping accept", activefds, maxfds);
				اكسر;
			}
			אם (handle_socket_read(socknum) == 0)
				activefds++;
			اكسر;
		حالة AUTH_CONNECTION:
			אם ((pfd[i].revents & (POLLIN|POLLHUP|POLLERR)) != 0 &&
			    handle_conn_read(socknum) != 0)
				اذهب close_sock;
			אם ((pfd[i].revents & (POLLOUT|POLLHUP)) != 0 &&
			    handle_conn_write(socknum) != 0) {
 close_sock:
				אם (activefds == 0)
					fatal("activefds == 0 at close_sock");
				close_socket(&sockets[socknum]);
				activefds--;
				اكسر;
			}
			اكسر;
		افتراضي:
			اكسر;
		}
	}
}

ساكن صحيح
prepare_poll(بنية pollfd **pfdp, size_t *npfdp, بنية timespec *timeoutp, u_int maxfds)
{
	بنية pollfd *pfd = *pfdp;
	size_t i, j, npfd = 0;
	time_t deadline;
	صحيح r;

	/* Count active sockets */
	עבור (i = 0; i < sockets_alloc; i++) {
		بدل (sockets[i].type) {
		حالة AUTH_SOCKET:
		حالة AUTH_CONNECTION:
			npfd++;
			اكسر;
		حالة AUTH_UNUSED:
			اكسر;
		افتراضي:
			fatal("Unknown socket type %d", sockets[i].type);
			اكسر;
		}
	}
	אם (npfd != *npfdp &&
	    (pfd = recallocarray(pfd, *npfdp, npfd, حجم(*pfd))) == عدم)
		fatal_f("recallocarray failed");
	*pfdp = pfd;
	*npfdp = npfd;

	עבור (i = j = 0; i < sockets_alloc; i++) {
		بدل (sockets[i].type) {
		حالة AUTH_SOCKET:
			אם (npfd > maxfds) {
				debug3("out of fds (active %zu >= limit %u); "
				    "skipping arming listener", npfd, maxfds);
				اكسر;
			}
			pfd[j].fd = sockets[i].fd;
			pfd[j].revents = 0;
			pfd[j].events = POLLIN;
			j++;
			اكسر;
		حالة AUTH_CONNECTION:
			pfd[j].fd = sockets[i].fd;
			pfd[j].revents = 0;
			/*
			 * Only prepare to read if we can handle a full-size
			 * input read buffer and enqueue a max size reply..
			 */
			אם ((r = sshbuf_check_reserve(sockets[i].input,
			    AGENT_RBUF_LEN)) == 0 &&
			    (r = sshbuf_check_reserve(sockets[i].output,
			    AGENT_MAX_LEN)) == 0)
				pfd[j].events = POLLIN;
			אחרת אם (r != SSH_ERR_NO_BUFFER_SPACE)
				fatal_fr(r, "reserve");
			אם (sshbuf_len(sockets[i].output) > 0)
				pfd[j].events |= POLLOUT;
			j++;
			اكسر;
		افتراضي:
			اكسر;
		}
	}
	deadline = reaper();
	אם (parent_alive_interval != 0)
		deadline = (deadline == 0) ? parent_alive_interval :
		    MINIMUM(deadline, parent_alive_interval);
	אם (deadline != 0)
		ptimeout_deadline_sec(timeoutp, deadline);
	החזר (1);
}

ساكن فراغ
cleanup_socket(فراغ)
{
	אם (cleanup_pid != 0 && getpid() != cleanup_pid)
		החזר;
	debug_f("cleanup");
	אם (socket_name != عدم) {
		agent_listener_cleanup(socket_dirspec, socket_name, socket_dir);
		حرر(socket_name);
		socket_name = عدم;
		حرر(socket_dir);
		socket_dir = عدم;
	}
}

فراغ
cleanup_exit(صحيح i)
{
	cleanup_socket();
#ifdef ENABLE_PKCS11
	pkcs11_terminate();
#endif
	_exit(i);
}

ساكن فراغ
cleanup_handler(صحيح sig)
{
	signalled_exit = sig;
}

ساكن فراغ
keydrop_handler(صحيح sig)
{
	signalled_keydrop = sig;
}

ساكن فراغ
check_parent_exists(فراغ)
{
	/*
	 * If our parent has exited then getppid() will return (pid_t)1,
	 * so testing for that should be safe.
	 */
	אם (parent_pid != -1 && getppid() != parent_pid) {
		/* printf("Parent has died - Authentication agent exiting.\n"); */
		cleanup_socket();
		_exit(2);
	}
}

ساكن فراغ
usage(فراغ)
{
	fprintf(stderr,
	    "usage: ssh-agent [-c | -s] [-DdU] [-T | -A directory | -a bind_address]\n"
	    "                 [-E fingerprint_hash] [-O option]\n"
	    "                 [-P allowed_providers] [-t life]\n"
	    "       ssh-agent [-U] [-T | -A directory | -a bind_address]\n"
	    "                 [-E fingerprint_hash] [-O option]\n"
	    "                 [-P allowed_providers] [-t life] command [arg ...]\n"
	    "       ssh-agent [-c | -s] -k\n"
	    "       ssh-agent -u\n"
	    "       ssh-agent -V\n");
	exit(1);
}

صحيح
main(صحيح ac, حرف **av)
{
	صحيح c_flag = 0, d_flag = 0, D_flag = 0, k_flag = 0;
	صحيح s_flag = 0, T_flag = 0, u_flag = 0, U_flag = 0;
	صحيح sock = -1, ch, result, saved_errno;
	pid_t pid;
 	حرف *homedir = عدم, *shell, *format, *pidstr, *agentsocket = عدم;
	حرف *cp, pidstrbuf[1 + 3 * حجم pid];
	حرف *fdstr;
	ثابت حرف *errstr = عدم;
	ثابت حرف *ccp;
#ifdef HAVE_SETRLIMIT
	بنية rlimit rlim;
#endif
	خارجي صحيح optind;
	خارجي حرف *optarg;
	size_t len;
	mode_t prev_mask;
	بنية timespec timeout;
	بنية pollfd *pfd = عدم;
	size_t npfd = 0;
	u_int maxfds;
	sigset_t nsigset, osigset;
	صحيح socket_activated = 0;
	بنية passwd *pw;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* drop */
	(فراغ)setegid(getgid());
	(فراغ)setgid(getgid());

	platform_disable_tracing(0);	/* strict=no */

	אם ((pw = getpwuid(getuid())) == عدم)
		fatal("No user exists for uid %lu", (u_long)getuid());
	pw = pwcopy(pw);

#ifdef RLIMIT_NOFILE
	אם (getrlimit(RLIMIT_NOFILE, &rlim) == -1)
		fatal("%s: getrlimit: %s", __progname, strerror(errno));
#endif

	__progname = ssh_get_progname(av[0]);
	seed_rng();

	כלעוד ((ch = getopt(ac, av, "cDdksTuUVA:E:a:O:P:t:")) != -1) {
		بدل (ch) {
		حالة 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			אם (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			اكسر;
		حالة 'c':
			אם (s_flag)
				usage();
			c_flag++;
			اكسر;
		حالة 'k':
			k_flag++;
			اكسر;
		حالة 'O':
			אם (strcmp(optarg, "no-restrict-websafe") == 0)
				restrict_websafe = 0;
			אחרת אם (strcmp(optarg, "allow-remote-pkcs11") == 0)
				remote_add_provider = 1;
			אחרת אם ((ccp = strprefix(optarg,
			    "websafe-allow=", 0)) != عدم) {
				אם (websafe_allowlist != عدم)
					fatal("websafe-allow already set");
				websafe_allowlist = xstrdup(ccp);
			} אחרת
				fatal("Unknown -O option");
			اكسر;
		حالة 'P':
			אם (allowed_providers != عدم)
				fatal("-P option already specified");
			allowed_providers = xstrdup(optarg);
			اكسر;
		حالة 's':
			אם (c_flag)
				usage();
			s_flag++;
			اكسر;
		حالة 'd':
			אם (d_flag || D_flag)
				usage();
			d_flag++;
			اكسر;
		حالة 'D':
			אם (d_flag || D_flag)
				usage();
			D_flag++;
			اكسر;
		حالة 'a':
			agentsocket = optarg;
			اكسر;
		حالة 'A':
			socket_dirspec = xstrdup(optarg);
			اكسر;
		حالة 't':
			אם ((lifetime = convtime(optarg)) == -1) {
				fprintf(stderr, "Invalid lifetime\n");
				usage();
			}
			اكسر;
		حالة 'T':
			T_flag++;
			اكسر;
		حالة 'u':
			u_flag++;
			اكسر;
		حالة 'U':
			U_flag++;
			اكسر;
		حالة 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_VERSION, SSH_OPENSSL_VERSION);
			exit(0);
		افتراضي:
			usage();
		}
	}
	ac -= optind;
	av += optind;

	אם (ac > 0 &&
	    (c_flag || k_flag || s_flag || d_flag || D_flag || u_flag))
		usage();
	/* only one of -a, -A and -T allowed */
	אם (((socket_dirspec != عدم) + (agentsocket != عدم) + T_flag) > 1)
		usage();

	log_init(__progname,
	    d_flag ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
	    SYSLOG_FACILITY_AUTH, 1);

	אם (allowed_providers == عدم)
		allowed_providers = xstrdup(DEFAULT_ALLOWED_PROVIDERS);
	אם (websafe_allowlist == عدم)
		websafe_allowlist = xstrdup(DEFAULT_WEBSAFE_ALLOWLIST);

	אם (T_flag)
		socket_dirspec = xstrdup(_PATH_SSH_AGENT_SOCKET_TMPDIR);
	אחרת אם (socket_dirspec == عدم && agentsocket == عدم)
		socket_dirspec = xstrdup(_PATH_SSH_AGENT_SOCKET_DIR);

	אם (ac == 0 && !c_flag && !s_flag) {
		shell = getenv("SHELL");
		אם (shell != عدم && (len = strlen(shell)) > 2 &&
		    strncmp(shell + len - 3, "csh", 3) == 0)
			c_flag = 1;
	}
	אם (k_flag) {
		pidstr = getenv(SSH_AGENTPID_ENV_NAME);
		אם (pidstr == عدم) {
			fprintf(stderr, "%s not set, cannot kill agent\n",
			    SSH_AGENTPID_ENV_NAME);
			exit(1);
		}
		pid = (صحيح)strtonum(pidstr, 2, INT_MAX, &errstr);
		אם (errstr) {
			fprintf(stderr,
			    "%s=\"%s\", which is not a good PID: %s\n",
			    SSH_AGENTPID_ENV_NAME, pidstr, errstr);
			exit(1);
		}
		אם (kill(pid, SIGTERM) == -1) {
			perror("kill");
			exit(1);
		}
		format = c_flag ? "unsetenv %s;\n" : "unset %s;\n";
		printf(format, SSH_AUTHSOCKET_ENV_NAME);
		printf(format, SSH_AGENTPID_ENV_NAME);
		printf("echo Agent pid %ld killed;\n", (long)pid);
		exit(0);
	}
	אם (u_flag) {
		אם ((homedir = get_homedir()) == عدم)
			fatal("Couldn't determine home directory");
		agent_cleanup_stale(socket_dirspec,
		    pw->pw_name, pw->pw_uid, homedir, u_flag > 1);
		printf("Deleted stale agent sockets in ~/%s\n",
		    _PATH_SSH_AGENT_SOCKET_DIR);
		exit(0);
	}

	/*
	 * Minimum file descriptors:
	 * stdio (3) + listener (1) + syslog (1 maybe) + connection (1) +
	 * a few spare for libc / stack protectors / sanitisers, etc.
	 */
#define SSH_AGENT_MIN_FDS (3+1+1+1+4)
	אם (rlim.rlim_cur < SSH_AGENT_MIN_FDS)
		fatal("%s: file descriptor rlimit %lld too low (minimum %u)",
		    __progname, (long long)rlim.rlim_cur, SSH_AGENT_MIN_FDS);
	maxfds = rlim.rlim_cur - SSH_AGENT_MIN_FDS;

	parent_pid = getpid();

	/* Has the socket been provided via socket activation? */
	אם (agentsocket == عدم && ac == 0 && (d_flag || D_flag) &&
	    (pidstr = getenv("LISTEN_PID")) != عدم &&
	    (fdstr = getenv("LISTEN_FDS")) != عدم) {
		אם (strcmp(fdstr, "1") != 0) {
			fatal("unexpected LISTEN_FDS contents "
			    "(want: \"1\" got\"%s\"", fdstr);
		}
		אם (fcntl(3, F_GETFL) == -1)
			fatal("LISTEN_FDS set but fd 3 unavailable");
		pid = (صحيح)strtonum(pidstr, 1, INT_MAX, &errstr);
		אם (errstr != عدم)
			fatal("invalid LISTEN_PID: %s", errstr);
		אם (pid != getpid())
			fatal("bad LISTEN_PID: %d vs pid %d", pid, getpid());
		debug("using socket activation on fd=3");
		sock = 3;
		socket_activated = 1;
	}

	אם (sock == -1 && agentsocket == عدم) {
		/* Listen on a socket in/under a given directory */
		אם ((homedir = get_homedir()) == عدم)
			fatal("Couldn't determine home directory");
		אם (!U_flag) {
			agent_cleanup_stale(socket_dirspec,
			    pw->pw_name, pw->pw_uid, homedir, 0);
		}
		אם (agent_listener(socket_dirspec, pw->pw_name, pw->pw_uid,
		    homedir, getpid(), "local", &sock, &socket_name,
		    &socket_dir) != 0)
			fatal_f("Couldn't prepare agent socket");
		حرر(homedir);
	} אחרת אם (sock == -1) {
		/* Listen on explicit socket path */
		prev_mask = umask(0177);
		socket_name = xstrdup(agentsocket);
		אם ((sock = unix_listener(socket_name,
		    SSH_LISTEN_BACKLOG, 0)) < 0) {
			حرر(socket_name);
			socket_name = عدم; /* Don't unlink existing file */
			cleanup_exit(1);
		}
		umask(prev_mask);
	}

	closefrom(sock == -1 ? STDERR_FILENO + 1 : sock + 1);

	/*
	 * Create socket early so it will exist before command gets run from
	 * the parent.
	 */
	אם (sock == -1) {
		prev_mask = umask(0177);
		sock = unix_listener(socket_name, SSH_LISTEN_BACKLOG, 0);
		אם (sock < 0) {
			/* XXX - unix_listener() calls error() not perror() */
			*socket_name = '\0'; /* Don't unlink existing file */
			cleanup_exit(1);
		}
		umask(prev_mask);
	}

	/*
	 * Fork, and have the parent execute the command, if any, or present
	 * the socket data.  The child continues as the authentication agent.
	 */
	אם (D_flag || d_flag) {
		log_init(__progname,
		    d_flag ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
		    SYSLOG_FACILITY_AUTH, 1);
		אם (socket_name != عدم) {
			cp = argv_assemble(1, &socket_name);
			format = c_flag ?
			    "setenv %s %s;\n" : "%s=%s; export %s;\n";
			printf(format, SSH_AUTHSOCKET_ENV_NAME, cp,
			    SSH_AUTHSOCKET_ENV_NAME);
			حرر(cp);
			printf("echo Agent pid %ld;\n", (long)parent_pid);
			fflush(stdout);
		}
		اذهب skip;
	}
	pid = fork();
	אם (pid == -1) {
		perror("fork");
		cleanup_exit(1);
	}
	אם (pid != 0) {		/* Parent - execute the given command. */
		close(sock);
		snprintf(pidstrbuf, حجم pidstrbuf, "%ld", (long)pid);
		אם (ac == 0) {
			format = c_flag ? "setenv %s %s;\n" : "%s=%s; export %s;\n";
			cp = argv_assemble(1, &socket_name);
			printf(format, SSH_AUTHSOCKET_ENV_NAME, cp,
			    SSH_AUTHSOCKET_ENV_NAME);
			printf(format, SSH_AGENTPID_ENV_NAME, pidstrbuf,
			    SSH_AGENTPID_ENV_NAME);
			حرر(cp);
			printf("echo Agent pid %ld;\n", (long)pid);
			exit(0);
		}
		אם (setenv(SSH_AUTHSOCKET_ENV_NAME, socket_name, 1) == -1 ||
		    setenv(SSH_AGENTPID_ENV_NAME, pidstrbuf, 1) == -1) {
			perror("setenv");
			exit(1);
		}
		execvp(av[0], av);
		perror(av[0]);
		exit(1);
	}
	/* child */
	log_init(__progname, SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_AUTH, 0);

	אם (setsid() == -1) {
		error("setsid: %s", strerror(errno));
		cleanup_exit(1);
	}

	(فراغ)chdir("/");
	אם (stdfd_devnull(1, 1, 1) == -1)
		error_f("stdfd_devnull failed");

#ifdef HAVE_SETRLIMIT
	/* deny core dumps, since memory contains unencrypted private keys */
	rlim.rlim_cur = rlim.rlim_max = 0;
	אם (setrlimit(RLIMIT_CORE, &rlim) == -1) {
		error("setrlimit RLIMIT_CORE: %s", strerror(errno));
		cleanup_exit(1);
	}
#endif

skip:

	cleanup_pid = getpid();

#ifdef ENABLE_PKCS11
	pkcs11_init(0);
#endif
	new_socket(AUTH_SOCKET, sock);
	אם (ac > 0)
		parent_alive_interval = 10;
	idtab_init();
	ssh_signal(SIGPIPE, SIG_IGN);
	ssh_signal(SIGINT, (d_flag | D_flag) ? cleanup_handler : SIG_IGN);
	ssh_signal(SIGHUP, cleanup_handler);
	ssh_signal(SIGTERM, cleanup_handler);
	ssh_signal(SIGUSR1, keydrop_handler);

	sigemptyset(&nsigset);
	sigaddset(&nsigset, SIGINT);
	sigaddset(&nsigset, SIGHUP);
	sigaddset(&nsigset, SIGTERM);
	sigaddset(&nsigset, SIGUSR1);

	אם (socket_name != عدم && unveil(socket_name, "c") == -1) {
		fatal("%s: unveil %s %s", __progname, socket_name,
		    strerror(errno));
	}
	אם (socket_dir != عدم && unveil(socket_dir, "c") == -1) {
		fatal("%s: unveil %s %s", __progname, socket_dir,
		    strerror(errno));
	}
	אם (unveil("/", "r") == -1)
		fatal("%s: unveil /: %s", __progname, strerror(errno));
	אם ((ccp = getenv("SSH_SK_HELPER")) == عدم || *ccp == '\0')
		ccp = _PATH_SSH_SK_HELPER;
	אם (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, strerror(errno));
	אם ((ccp = getenv("SSH_PKCS11_HELPER")) == عدم || *ccp == '\0')
		ccp = _PATH_SSH_PKCS11_HELPER;
	אם (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, strerror(errno));
	אם ((ccp = getenv("SSH_ASKPASS")) == عدم || *ccp == '\0')
		ccp = _PATH_SSH_ASKPASS_DEFAULT;
	אם (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, strerror(errno));
	אם (unveil("/dev/null", "rw") == -1)
		fatal("%s: unveil /dev/null: %s", __progname, strerror(errno));
	אם (pledge("stdio rpath cpath wpath unix id proc exec", عدم) == -1)
		fatal("%s: pledge: %s", __progname, strerror(errno));
	platform_pledge_agent();

	כלעוד (1) {
		sigprocmask(SIG_BLOCK, &nsigset, &osigset);
		אם (signalled_exit != 0) {
			logit("exiting on signal %d", (صحيح)signalled_exit);
			cleanup_exit((signalled_exit == SIGTERM &&
			    socket_activated) ? 0 : 2);
		}
		אם (signalled_keydrop) {
			logit("signal %d received; removing all keys",
			    (صحيح)signalled_keydrop);
			remove_all_identities();
			signalled_keydrop = 0;
		}
		ptimeout_init(&timeout);
		prepare_poll(&pfd, &npfd, &timeout, maxfds);
		result = ppoll(pfd, npfd, ptimeout_get_tsp(&timeout), &osigset);
		sigprocmask(SIG_SETMASK, &osigset, عدم);
		saved_errno = errno;
		אם (parent_alive_interval != 0)
			check_parent_exists();
		(فراغ) reaper();	/* remove expired keys */
		אם (result == -1) {
			אם (saved_errno == EINTR)
				استمر;
			fatal("poll: %s", strerror(saved_errno));
		} אחרת אם (result > 0)
			after_poll(pfd, npfd, maxfds);
	}
	/* NOTREACHED */
}
