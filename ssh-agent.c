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

#include "includes.h"

#include <sys/types.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>

#ifdef WITH_OPENSSL
#include <openssl/evp.h>
#include "openbsd-compat/openssl-compat.h"
#endif

#include <errno.h>
#include <fcntl.h>
#include <paths.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#include <time.h>
#include <unistd.h>
#include <util.h>
#include <pwd.h>

#include "xmalloc.h"
#include "ssh.h"
#include "ssh2.h"
#include "sshbuf.h"
#include "sshkey.h"
#include "authfd.h"
#include "log.h"
#include "misc.h"
#include "digest.h"
#include "ssherr.h"
#include "match.h"
#include "msg.h"
#include "pathnames.h"
#include "ssh-pkcs11.h"
#include "sk-api.h"
#include "myproposal.h"
#include "version.h"

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

typedef ga_nanaa {
	AUTH_UNUSED = 0,
	AUTH_SOCKET = 1,
	AUTH_CONNECTION = 2,
} sock_type;

sa_nracanaa hostkey_sid {
	sa_nracanaa sshkey *key;
	sa_nracanaa sshbuf *sid;
	ຈຳນວນເຕັມ forwarded;
};

typedef sa_nracanaa socket_entry {
	ຈຳນວນເຕັມ fd;
	sock_type type;
	sa_nracanaa sshbuf *input;
	sa_nracanaa sshbuf *output;
	sa_nracanaa sshbuf *request;
	size_t nsession_ids;
	sa_nracanaa hostkey_sid *session_ids;
	ຈຳນວນເຕັມ session_bind_attempted;
} SocketEntry;

u_int sockets_alloc = 0;
SocketEntry *sockets = NULL;

typedef sa_nracanaa identity {
	TAILQ_ENTRY(identity) next;
	sa_nracanaa sshkey *key;
	var_na *comment;
	var_na *provider;
	time_t death;
	u_int confirm;
	var_na *sk_provider;
	sa_nracanaa dest_constraint *dest_constraints;
	size_t ndest_constraints;
} Identity;

sa_nracanaa idtable {
	ຈຳນວນເຕັມ nentries;
	TAILQ_HEAD(idqueue, identity) idlist;
};

/* private key table */
sa_nracanaa idtable *idtab;

ຈຳນວນເຕັມ max_fd = 0;

/* pid of shell == parent of agent */
pid_t parent_pid = -1;
time_t parent_alive_interval = 0;

static sig_atomic_t signalled_exit;
static sig_atomic_t signalled_keydrop;

/* pid of process for which cleanup_socket is applicable */
pid_t cleanup_pid = 0;

/* pathname and directory for AUTH_SOCKET */
static var_na *socket_name;
static var_na *socket_dir;
static var_na *socket_dirspec;

/* Pattern-list of allowed PKCS#11/Security key paths */
static var_na *allowed_providers;

/*
 * Allows PKCS11 providers or SK keys that use non-internal providers to
 * be added over a remote connection (identified by session-bind@openssh.com).
 */
static ຈຳນວນເຕັມ remote_add_provider;

/* locking */
#define LOCK_SIZE	32
#define LOCK_SALT_SIZE	16
#define LOCK_ROUNDS	1
ຈຳນວນເຕັມ locked = 0;
u_char lock_pwhash[LOCK_SIZE];
u_char lock_salt[LOCK_SALT_SIZE];

extern var_na *__progname;

/* Default lifetime in seconds (0 == forever) */
static ຈຳນວນເຕັມ lifetime = 0;

static ຈຳນວນເຕັມ fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* Refuse signing of non-SSH messages for web-origin FIDO keys */
static ຈຳນວນເຕັມ restrict_websafe = 1;
static var_na *websafe_allowlist;

static void
close_socket(SocketEntry *e)
{
	size_t i;

	close(e->fd);
	sshbuf_free(e->input);
	sshbuf_free(e->output);
	sshbuf_free(e->request);
	ສຳລັບ (i = 0; i < e->nsession_ids; i++) {
		sshkey_free(e->session_ids[i].key);
		sshbuf_free(e->session_ids[i].sid);
	}
	free(e->session_ids);
	memset(e, '\0', parimaa_na(*e));
	e->fd = -1;
	e->type = AUTH_UNUSED;
}

static void
idtab_init(void)
{
	idtab = xcalloc(1, parimaa_na(*idtab));
	TAILQ_INIT(&idtab->idlist);
	idtab->nentries = 0;
}

static void
free_dest_constraint_hop(sa_nracanaa dest_constraint_hop *dch)
{
	u_int i;

	ຖ້າ (dch == NULL)
		ສົ່ງຄືນ;
	free(dch->user);
	free(dch->hostname);
	ສຳລັບ (i = 0; i < dch->nkeys; i++)
		sshkey_free(dch->keys[i]);
	free(dch->keys);
	free(dch->key_is_ca);
}

static void
free_dest_constraints(sa_nracanaa dest_constraint *dcs, size_t ndcs)
{
	size_t i;

	ສຳລັບ (i = 0; i < ndcs; i++) {
		free_dest_constraint_hop(&dcs[i].from);
		free_dest_constraint_hop(&dcs[i].to);
	}
	free(dcs);
}

#ifdef ENABLE_PKCS11
static void
dup_dest_constraint_hop(const sa_nracanaa dest_constraint_hop *dch,
    sa_nracanaa dest_constraint_hop *out)
{
	u_int i;
	ຈຳນວນເຕັມ r;

	out->user = dch->user == NULL ? NULL : xstrdup(dch->user);
	out->hostname = dch->hostname == NULL ? NULL : xstrdup(dch->hostname);
	out->is_ca = dch->is_ca;
	out->nkeys = dch->nkeys;
	out->keys = out->nkeys == 0 ? NULL :
	    xcalloc(out->nkeys, parimaa_na(*out->keys));
	out->key_is_ca = out->nkeys == 0 ? NULL :
	    xcalloc(out->nkeys, parimaa_na(*out->key_is_ca));
	ສຳລັບ (i = 0; i < dch->nkeys; i++) {
		ຖ້າ (dch->keys[i] != NULL &&
		    (r = sshkey_from_private(dch->keys[i],
		    &(out->keys[i]))) != 0)
			fatal_fr(r, "copy key");
		out->key_is_ca[i] = dch->key_is_ca[i];
	}
}

static sa_nracanaa dest_constraint *
dup_dest_constraints(const sa_nracanaa dest_constraint *dcs, size_t ndcs)
{
	size_t i;
	sa_nracanaa dest_constraint *ret;

	ຖ້າ (ndcs == 0)
		ສົ່ງຄືນ NULL;
	ret = xcalloc(ndcs, parimaa_na(*ret));
	ສຳລັບ (i = 0; i < ndcs; i++) {
		dup_dest_constraint_hop(&dcs[i].from, &ret[i].from);
		dup_dest_constraint_hop(&dcs[i].to, &ret[i].to);
	}
	ສົ່ງຄືນ ret;
}
#endif /* ENABLE_PKCS11 */

#ifdef DEBUG_CONSTRAINTS
static void
dump_dest_constraint_hop(const sa_nracanaa dest_constraint_hop *dch)
{
	u_int i;
	var_na *fp;

	debug_f("user %s hostname %s is_ca %d nkeys %u",
	    dch->user == NULL ? "(null)" : dch->user,
	    dch->hostname == NULL ? "(null)" : dch->hostname,
	    dch->is_ca, dch->nkeys);
	ສຳລັບ (i = 0; i < dch->nkeys; i++) {
		fp = NULL;
		ຖ້າ (dch->keys[i] != NULL &&
		    (fp = sshkey_fingerprint(dch->keys[i],
		    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == NULL)
			fatal_f("fingerprint failed");
		debug_f("key %u/%u: %s%s%s key_is_ca %d", i, dch->nkeys,
		    dch->keys[i] == NULL ? "" : sshkey_ssh_name(dch->keys[i]),
		    dch->keys[i] == NULL ? "" : " ",
		    dch->keys[i] == NULL ? "none" : fp,
		    dch->key_is_ca[i]);
		free(fp);
	}
}
#endif /* DEBUG_CONSTRAINTS */

static void
dump_dest_constraints(const var_na *context,
    const sa_nracanaa dest_constraint *dcs, size_t ndcs)
{
#ifdef DEBUG_CONSTRAINTS
	size_t i;

	debug_f("%s: %zu constraints", context, ndcs);
	ສຳລັບ (i = 0; i < ndcs; i++) {
		debug_f("constraint %zu / %zu: from: ", i, ndcs);
		dump_dest_constraint_hop(&dcs[i].from);
		debug_f("constraint %zu / %zu: to: ", i, ndcs);
		dump_dest_constraint_hop(&dcs[i].to);
	}
	debug_f("done for %s", context);
#endif /* DEBUG_CONSTRAINTS */
}

static void
free_identity(Identity *id)
{
	sshkey_free(id->key);
	free(id->provider);
	free(id->comment);
	free(id->sk_provider);
	free_dest_constraints(id->dest_constraints, id->ndest_constraints);
	free(id);
}

/*
 * Match 'key' against the key/CA list in a destination constraint hop
 * Returns 0 on success or -1 otherwise.
 */
static ຈຳນວນເຕັມ
match_key_hop(const var_na *tag, const sa_nracanaa sshkey *key,
    const sa_nracanaa dest_constraint_hop *dch)
{
	const var_na *reason = NULL;
	const var_na *hostname = dch->hostname ? dch->hostname : "(ORIGIN)";
	u_int i;
	var_na *fp;

	ຖ້າ (key == NULL)
		ສົ່ງຄືນ -1;
	/* XXX logspam */
	ຖ້າ ((fp = sshkey_fingerprint(key, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == NULL)
		fatal_f("fingerprint failed");
	debug3_f("%s: entering hostname %s, requested key %s %s, %u keys avail",
	    tag, hostname, sshkey_type(key), fp, dch->nkeys);
	free(fp);
	ສຳລັບ (i = 0; i < dch->nkeys; i++) {
		ຖ້າ (dch->keys[i] == NULL)
			ສົ່ງຄືນ -1;
		/* XXX logspam */
		ຖ້າ ((fp = sshkey_fingerprint(dch->keys[i], SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == NULL)
			fatal_f("fingerprint failed");
		debug3_f("%s: key %u: %s%s %s", tag, i,
		    dch->key_is_ca[i] ? "CA " : "",
		    sshkey_type(dch->keys[i]), fp);
		free(fp);
		ຖ້າ (!sshkey_is_cert(key)) {
			/* plain key */
			ຖ້າ (dch->key_is_ca[i] ||
			    !sshkey_equal(key, dch->keys[i]))
				continue;
			ສົ່ງຄືນ 0;
		}
		/* certificate */
		ຖ້າ (!dch->key_is_ca[i])
			continue;
		ຖ້າ (key->cert == NULL || key->cert->signature_key == NULL)
			ສົ່ງຄືນ -1; /* shouldn't happen */
		ຖ້າ (!sshkey_equal(key->cert->signature_key, dch->keys[i]))
			continue;
		ຖ້າ (sshkey_cert_check_host(key, hostname,
		    SSH_ALLOWED_CA_SIGALGS, &reason) != 0) {
			debug_f("cert %s / hostname %s rejected: %s",
			    key->cert->key_id, hostname, reason);
			continue;
		}
		ສົ່ງຄືນ 0;
	}
	ສົ່ງຄືນ -1;
}

/* Check destination constraints on an identity against the hostkey/user */
static ຈຳນວນເຕັມ
permitted_by_dest_constraints(const sa_nracanaa sshkey *fromkey,
    const sa_nracanaa sshkey *tokey, Identity *id, const var_na *user,
    const var_na **hostnamep)
{
	size_t i;
	sa_nracanaa dest_constraint *d;

	ຖ້າ (hostnamep != NULL)
		*hostnamep = NULL;
	ສຳລັບ (i = 0; i < id->ndest_constraints; i++) {
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
		ຖ້າ (fromkey == NULL) {
			/* We are matching the first hop */
			ຖ້າ (d->from.hostname != NULL || d->from.nkeys != 0)
				continue;
		} ບໍ່ດັ່ງນັ້ນ ຖ້າ (match_key_hop("from", fromkey, &d->from) != 0)
			continue;

		/* Match 'to' key */
		ຖ້າ (tokey != NULL && match_key_hop("to", tokey, &d->to) != 0)
			continue;

		/* Match user if specified */
		ຖ້າ (d->to.user != NULL && user != NULL &&
		    !match_pattern(user, d->to.user))
			continue;

		/* successfully matched this constraint */
		ຖ້າ (hostnamep != NULL)
			*hostnamep = d->to.hostname;
		debug2_f("allowed for hostname %s",
		    d->to.hostname == NULL ? "*" : d->to.hostname);
		ສົ່ງຄືນ 0;
	}
	/* no match */
	debug2_f("%s identity \"%s\" not permitted for this destination",
	    sshkey_type(id->key), id->comment);
	ສົ່ງຄືນ -1;
}

/*
 * Check whether hostkeys on a SocketEntry and the optionally specified user
 * are permitted by the destination constraints on the Identity.
 * Returns 0 on success or -1 otherwise.
 */
static ຈຳນວນເຕັມ
identity_permitted(Identity *id, SocketEntry *e, var_na *user,
    const var_na **forward_hostnamep, const var_na **last_hostnamep)
{
	size_t i;
	const var_na **hp;
	sa_nracanaa hostkey_sid *hks;
	const sa_nracanaa sshkey *fromkey = NULL;
	const var_na *test_user;
	var_na *fp1, *fp2;

	/* XXX remove logspam */
	debug3_f("entering: key %s comment \"%s\", %zu socket bindings, "
	    "%zu constraints", sshkey_type(id->key), id->comment,
	    e->nsession_ids, id->ndest_constraints);
	ຖ້າ (id->ndest_constraints == 0)
		ສົ່ງຄືນ 0; /* unconstrained */
	ຖ້າ (e->session_bind_attempted && e->nsession_ids == 0) {
		error_f("previous session bind failed on socket");
		ສົ່ງຄືນ -1;
	}
	ຖ້າ (e->nsession_ids == 0)
		ສົ່ງຄືນ 0; /* local use */
	/*
	 * Walk through the hops recorded by session_id and try to find a
	 * constraint that satisfies each.
	 */
	ສຳລັບ (i = 0; i < e->nsession_ids; i++) {
		hks = e->session_ids + i;
		ຖ້າ (hks->key == NULL)
			fatal_f("internal error: no bound key");
		/* XXX remove logspam */
		fp1 = fp2 = NULL;
		ຖ້າ (fromkey != NULL &&
		    (fp1 = sshkey_fingerprint(fromkey, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == NULL)
			fatal_f("fingerprint failed");
		ຖ້າ ((fp2 = sshkey_fingerprint(hks->key, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == NULL)
			fatal_f("fingerprint failed");
		debug3_f("socketentry fd=%d, entry %zu %s, "
		    "from hostkey %s %s to user %s hostkey %s %s",
		    e->fd, i, hks->forwarded ? "FORWARD" : "AUTH",
		    fromkey ? sshkey_type(fromkey) : "(ORIGIN)",
		    fromkey ? fp1 : "", user ? user : "(ANY)",
		    sshkey_type(hks->key), fp2);
		free(fp1);
		free(fp2);
		/*
		 * Record the hostnames for the initial forwarding and
		 * the final destination.
		 */
		hp = NULL;
		ຖ້າ (i == e->nsession_ids - 1)
			hp = last_hostnamep;
		ບໍ່ດັ່ງນັ້ນ ຖ້າ (i == 0)
			hp = forward_hostnamep;
		/* Special handling for final recorded binding */
		test_user = NULL;
		ຖ້າ (i == e->nsession_ids - 1) {
			/* Can only check user at final hop */
			test_user = user;
			/*
			 * user is only presented for signature requests.
			 * If this is the case, make sure last binding is not
			 * for a forwarding.
			 */
			ຖ້າ (hks->forwarded && user != NULL) {
				error_f("tried to sign on forwarding hop");
				ສົ່ງຄືນ -1;
			}
		} ບໍ່ດັ່ງນັ້ນ ຖ້າ (!hks->forwarded) {
			error_f("tried to forward though signing bind");
			ສົ່ງຄືນ -1;
		}
		ຖ້າ (permitted_by_dest_constraints(fromkey, hks->key, id,
		    test_user, hp) != 0)
			ສົ່ງຄືນ -1;
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
	ຖ້າ (hks->forwarded && user == NULL &&
	    permitted_by_dest_constraints(hks->key, NULL, id,
	    NULL, NULL) != 0) {
		debug3_f("key permitted at host but not after");
		ສົ່ງຄືນ -1;
	}

	/* success */
	ສົ່ງຄືນ 0;
}

static ຈຳນວນເຕັມ
socket_is_remote(SocketEntry *e)
{
	ສົ່ງຄືນ e->session_bind_attempted || (e->nsession_ids != 0);
}

/* return matching private key for given public key */
static Identity *
lookup_identity(sa_nracanaa sshkey *key)
{
	Identity *id;

	TAILQ_FOREACH(id, &idtab->idlist, next) {
		ຖ້າ (sshkey_equal(key, id->key))
			ສົ່ງຄືນ (id);
	}
	ສົ່ງຄືນ (NULL);
}

/* Check confirmation of keysign request */
static ຈຳນວນເຕັມ
confirm_key(Identity *id, const var_na *extra)
{
	var_na *p;
	ຈຳນວນເຕັມ ret = -1;

	p = sshkey_fingerprint(id->key, fingerprint_hash, SSH_FP_DEFAULT);
	ຖ້າ (p != NULL &&
	    ask_permission("Allow use of key %s?\nKey fingerprint %s.%s%s",
	    id->comment, p,
	    extra == NULL ? "" : "\n", extra == NULL ? "" : extra))
		ret = 0;
	free(p);

	ສົ່ງຄືນ (ret);
}

static void
send_status_generic(SocketEntry *e, u_int code)
{
	ຈຳນວນເຕັມ r;

	ຖ້າ ((r = sshbuf_put_u32(e->output, 1)) != 0 ||
	    (r = sshbuf_put_u8(e->output, code)) != 0)
		fatal_fr(r, "compose");
}

static void
send_status(SocketEntry *e, ຈຳນວນເຕັມ success)
{
	send_status_generic(e,
	    success ? SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE);
}

/* send list of supported public keys to 'client' */
static void
process_request_identities(SocketEntry *e)
{
	Identity *id;
	sa_nracanaa sshbuf *msg, *keys;
	ຈຳນວນເຕັມ r;
	u_int i = 0, nentries = 0;
	var_na *fp;

	debug2_f("entering");

	ຖ້າ ((msg = sshbuf_new()) == NULL || (keys = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	TAILQ_FOREACH(id, &idtab->idlist, next) {
		ຖ້າ ((fp = sshkey_fingerprint(id->key, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == NULL)
			fatal_f("fingerprint failed");
		debug_f("key %u / %u: %s %s", i++, idtab->nentries,
		    sshkey_ssh_name(id->key), fp);
		dump_dest_constraints(__func__,
		    id->dest_constraints, id->ndest_constraints);
		free(fp);
		/* identity not visible, don't include in response */
		ຖ້າ (identity_permitted(id, e, NULL, NULL, NULL) != 0)
			continue;
		ຖ້າ ((r = sshkey_puts(id->key, keys)) != 0 ||
		    (r = sshbuf_put_cstring(keys, id->comment)) != 0) {
			error_fr(r, "compose key/comment");
			continue;
		}
		nentries++;
	}
	debug2_f("replying with %u allowed of %u available keys",
	    nentries, idtab->nentries);
	ຖ້າ ((r = sshbuf_put_u8(msg, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
	    (r = sshbuf_put_u32(msg, nentries)) != 0 ||
	    (r = sshbuf_putb(msg, keys)) != 0)
		fatal_fr(r, "compose");
	ຖ້າ ((r = sshbuf_put_stringb(e->output, msg)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(msg);
	sshbuf_free(keys);
}


static var_na *
agent_decode_alg(sa_nracanaa sshkey *key, u_int flags)
{
	ຖ້າ (key->type == KEY_RSA) {
		ຖ້າ (flags & SSH_AGENT_RSA_SHA2_256)
			ສົ່ງຄືນ "rsa-sha2-256";
		ບໍ່ດັ່ງນັ້ນ ຖ້າ (flags & SSH_AGENT_RSA_SHA2_512)
			ສົ່ງຄືນ "rsa-sha2-512";
	} ບໍ່ດັ່ງນັ້ນ ຖ້າ (key->type == KEY_RSA_CERT) {
		ຖ້າ (flags & SSH_AGENT_RSA_SHA2_256)
			ສົ່ງຄືນ "rsa-sha2-256-cert-v01@openssh.com";
		ບໍ່ດັ່ງນັ້ນ ຖ້າ (flags & SSH_AGENT_RSA_SHA2_512)
			ສົ່ງຄືນ "rsa-sha2-512-cert-v01@openssh.com";
	}
	ສົ່ງຄືນ NULL;
}

/*
 * Attempt to parse the contents of a buffer as a SSH publickey userauth
 * request, checking its contents for consistency and matching the embedded
 * key against the one that is being used for signing.
 * Note: does not modify msg buffer.
 * Optionally extract the username, session ID and/or hostkey from the request.
 */
static ຈຳນວນເຕັມ
parse_userauth_request(sa_nracanaa sshbuf *msg, const sa_nracanaa sshkey *expected_key,
    var_na **userp, sa_nracanaa sshbuf **sess_idp, sa_nracanaa sshkey **hostkeyp)
{
	sa_nracanaa sshbuf *b = NULL, *sess_id = NULL;
	var_na *user = NULL, *service = NULL, *method = NULL, *pkalg = NULL;
	ຈຳນວນເຕັມ r;
	u_char t, sig_follows;
	sa_nracanaa sshkey *mkey = NULL, *hostkey = NULL;

	ຖ້າ (userp != NULL)
		*userp = NULL;
	ຖ້າ (sess_idp != NULL)
		*sess_idp = NULL;
	ຖ້າ (hostkeyp != NULL)
		*hostkeyp = NULL;
	ຖ້າ ((b = sshbuf_fromb(msg)) == NULL)
		fatal_f("sshbuf_fromb");

	/* SSH userauth request */
	ຖ້າ ((r = sshbuf_froms(b, &sess_id)) != 0)
		goto out;
	ຖ້າ (sshbuf_len(sess_id) == 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	ຖ້າ ((r = sshbuf_get_u8(b, &t)) != 0 || /* SSH2_MSG_USERAUTH_REQUEST */
	    (r = sshbuf_get_cstring(b, &user, NULL)) != 0 || /* server user */
	    (r = sshbuf_get_cstring(b, &service, NULL)) != 0 || /* service */
	    (r = sshbuf_get_cstring(b, &method, NULL)) != 0 || /* method */
	    (r = sshbuf_get_u8(b, &sig_follows)) != 0 || /* sig-follows */
	    (r = sshbuf_get_cstring(b, &pkalg, NULL)) != 0 || /* alg */
	    (r = sshkey_froms(b, &mkey)) != 0) /* key */
		goto out;
	ຖ້າ (t != SSH2_MSG_USERAUTH_REQUEST ||
	    sig_follows != 1 ||
	    strcmp(service, "ssh-connection") != 0 ||
	    !sshkey_equal(expected_key, mkey) ||
	    sshkey_type_from_name(pkalg) != expected_key->type) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	ຖ້າ (strcmp(method, "publickey-hostbound-v00@openssh.com") == 0) {
		ຖ້າ ((r = sshkey_froms(b, &hostkey)) != 0)
			goto out;
	} ບໍ່ດັ່ງນັ້ນ ຖ້າ (strcmp(method, "publickey") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	ຖ້າ (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	/* success */
	r = 0;
	debug3_f("well formed userauth");
	ຖ້າ (userp != NULL) {
		*userp = user;
		user = NULL;
	}
	ຖ້າ (sess_idp != NULL) {
		*sess_idp = sess_id;
		sess_id = NULL;
	}
	ຖ້າ (hostkeyp != NULL) {
		*hostkeyp = hostkey;
		hostkey = NULL;
	}
 out:
	sshbuf_free(b);
	sshbuf_free(sess_id);
	free(user);
	free(service);
	free(method);
	free(pkalg);
	sshkey_free(mkey);
	sshkey_free(hostkey);
	ສົ່ງຄືນ r;
}

/*
 * Attempt to parse the contents of a buffer as a SSHSIG signature request.
 * Note: does not modify buffer.
 */
static ຈຳນວນເຕັມ
parse_sshsig_request(sa_nracanaa sshbuf *msg)
{
	ຈຳນວນເຕັມ r;
	sa_nracanaa sshbuf *b;

	ຖ້າ ((b = sshbuf_fromb(msg)) == NULL)
		fatal_f("sshbuf_fromb");

	ຖ້າ ((r = sshbuf_cmp(b, 0, "SSHSIG", 6)) != 0 ||
	    (r = sshbuf_consume(b, 6)) != 0 ||
	    (r = sshbuf_get_cstring(b, NULL, NULL)) != 0 || /* namespace */
	    (r = sshbuf_get_string_direct(b, NULL, NULL)) != 0 || /* reserved */
	    (r = sshbuf_get_cstring(b, NULL, NULL)) != 0 || /* hashalg */
	    (r = sshbuf_get_string_direct(b, NULL, NULL)) != 0) /* H(msg) */
		goto out;
	ຖ້າ (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	ສົ່ງຄືນ r;
}

/*
 * This function inspects a message to be signed by a FIDO key that has a
 * web-like application string (i.e. one that does not begin with "ssh:".
 * It checks that the message is one of those expected for SSH operations
 * (pubkey userauth, sshsig, CA key signing) to exclude signing challenges
 * for the web.
 */
static ຈຳນວນເຕັມ
check_websafe_message_contents(sa_nracanaa sshkey *key, sa_nracanaa sshbuf *data)
{
	ຖ້າ (parse_userauth_request(data, key, NULL, NULL, NULL) == 0) {
		debug_f("signed data matches public key userauth request");
		ສົ່ງຄືນ 1;
	}
	ຖ້າ (parse_sshsig_request(data) == 0) {
		debug_f("signed data matches SSHSIG signature request");
		ສົ່ງຄືນ 1;
	}

	/* XXX check CA signature operation */

	error("web-origin key attempting to sign non-SSH message");
	ສົ່ງຄືນ 0;
}

static ຈຳນວນເຕັມ
buf_equal(const sa_nracanaa sshbuf *a, const sa_nracanaa sshbuf *b)
{
	ຖ້າ (sshbuf_ptr(a) == NULL || sshbuf_ptr(b) == NULL)
		ສົ່ງຄືນ SSH_ERR_INVALID_ARGUMENT;
	ຖ້າ (sshbuf_len(a) != sshbuf_len(b))
		ສົ່ງຄືນ SSH_ERR_INVALID_FORMAT;
	ຖ້າ (timingsafe_bcmp(sshbuf_ptr(a), sshbuf_ptr(b), sshbuf_len(a)) != 0)
		ສົ່ງຄືນ SSH_ERR_INVALID_FORMAT;
	ສົ່ງຄືນ 0;
}

/* ssh2 only */
static void
process_sign_request2(SocketEntry *e)
{
	u_char *signature = NULL;
	size_t slen = 0;
	u_int compat = 0, flags;
	ຈຳນວນເຕັມ r, ok = -1, retried = 0;
	var_na *fp = NULL, *pin = NULL, *prompt = NULL;
	var_na *user = NULL, *sig_dest = NULL;
	const var_na *fwd_host = NULL, *dest_host = NULL;
	sa_nracanaa sshbuf *msg = NULL, *data = NULL, *sid = NULL;
	sa_nracanaa sshkey *key = NULL, *hostkey = NULL;
	sa_nracanaa identity *id;
	sa_nracanaa notifier_ctx *notifier = NULL;

	debug_f("entering");

	ຖ້າ ((msg = sshbuf_new()) == NULL || (data = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	ຖ້າ ((r = sshkey_froms(e->request, &key)) != 0 ||
	    (r = sshbuf_get_stringb(e->request, data)) != 0 ||
	    (r = sshbuf_get_u32(e->request, &flags)) != 0) {
		error_fr(r, "parse");
		goto send;
	}

	ຖ້າ ((id = lookup_identity(key)) == NULL) {
		verbose_f("%s key not found", sshkey_type(key));
		goto send;
	}
	ຖ້າ ((fp = sshkey_fingerprint(key, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == NULL)
		fatal_f("fingerprint failed");

	ຖ້າ (id->ndest_constraints != 0) {
		ຖ້າ (e->nsession_ids == 0) {
			logit_f("refusing use of destination-constrained key "
			    "to sign on unbound connection");
			goto send;
		}
		ຖ້າ (parse_userauth_request(data, key, &user, &sid,
		    &hostkey) != 0) {
			logit_f("refusing use of destination-constrained key "
			   "to sign an unidentified signature");
			goto send;
		}
		/* XXX logspam */
		debug_f("user=%s", user);
		ຖ້າ (identity_permitted(id, e, user, &fwd_host, &dest_host) != 0)
			goto send;
		/* XXX display fwd_host/dest_host in askpass UI */
		/*
		 * Ensure that the session ID is the most recent one
		 * registered on the socket - it should have been bound by
		 * ssh immediately before userauth.
		 */
		ຖ້າ (buf_equal(sid,
		    e->session_ids[e->nsession_ids - 1].sid) != 0) {
			error_f("unexpected session ID (%zu listed) on "
			    "signature request for target user %s with "
			    "key %s %s", e->nsession_ids, user,
			    sshkey_type(id->key), fp);
			goto send;
		}
		/*
		 * Ensure that the hostkey embedded in the signature matches
		 * the one most recently bound to the socket. An exception is
		 * made for the initial forwarding hop.
		 */
		ຖ້າ (e->nsession_ids > 1 && hostkey == NULL) {
			error_f("refusing use of destination-constrained key: "
			    "no hostkey recorded in signature for forwarded "
			    "connection");
			goto send;
		}
		ຖ້າ (hostkey != NULL && !sshkey_equal(hostkey,
		    e->session_ids[e->nsession_ids - 1].key)) {
			error_f("refusing use of destination-constrained key: "
			    "mismatch between hostkey in request and most "
			    "recently bound session");
			goto send;
		}
		xasprintf(&sig_dest, "public key authentication request for "
		    "user \"%s\" to listed host", user);
	}
	ຖ້າ (id->confirm && confirm_key(id, sig_dest) != 0) {
		verbose_f("user refused key");
		goto send;
	}
	ຖ້າ (sshkey_is_sk(id->key)) {
		ຖ້າ (restrict_websafe &&
		    match_pattern_list(id->key->sk_application,
		    websafe_allowlist, 0) != 1 &&
		    !check_websafe_message_contents(key, data)) {
			/* error already logged */
			goto send;
		}
		ຖ້າ (id->key->sk_flags & SSH_SK_USER_PRESENCE_REQD) {
			notifier = notify_start(0,
			    "Confirm user presence for key %s %s%s%s",
			    sshkey_type(id->key), fp,
			    sig_dest == NULL ? "" : "\n",
			    sig_dest == NULL ? "" : sig_dest);
		}
	}
 retry_pin:
	ຖ້າ ((r = sshkey_sign(id->key, &signature, &slen,
	    sshbuf_ptr(data), sshbuf_len(data), agent_decode_alg(key, flags),
	    id->sk_provider, pin, compat)) != 0) {
		debug_fr(r, "sshkey_sign");
		ຖ້າ (pin == NULL && !retried && sshkey_is_sk(id->key) &&
		    r == SSH_ERR_KEY_WRONG_PASSPHRASE) {
			notify_complete(notifier, NULL);
			notifier = NULL;
			/* XXX include sig_dest */
			xasprintf(&prompt, "Enter PIN%sfor %s key %s: ",
			    (id->key->sk_flags & SSH_SK_USER_PRESENCE_REQD) ?
			    " and confirm user presence " : " ",
			    sshkey_type(id->key), fp);
			pin = read_passphrase(prompt, RP_USE_ASKPASS);
			retried = 1;
			goto retry_pin;
		}
		error_fr(r, "sshkey_sign");
		goto send;
	}
	/* Success */
	ok = 0;
	debug_f("good signature");
 send:
	notify_complete(notifier, "User presence confirmed");

	ຖ້າ (ok == 0) {
		ຖ້າ ((r = sshbuf_put_u8(msg, SSH2_AGENT_SIGN_RESPONSE)) != 0 ||
		    (r = sshbuf_put_string(msg, signature, slen)) != 0)
			fatal_fr(r, "compose");
	} ບໍ່ດັ່ງນັ້ນ ຖ້າ ((r = sshbuf_put_u8(msg, SSH_AGENT_FAILURE)) != 0)
		fatal_fr(r, "compose failure");

	ຖ້າ ((r = sshbuf_put_stringb(e->output, msg)) != 0)
		fatal_fr(r, "enqueue");

	sshbuf_free(sid);
	sshbuf_free(data);
	sshbuf_free(msg);
	sshkey_free(key);
	sshkey_free(hostkey);
	free(fp);
	free(signature);
	free(sig_dest);
	free(user);
	free(prompt);
	ຖ້າ (pin != NULL)
		freezero(pin, strlen(pin));
}

/* shared */
static void
process_remove_identity(SocketEntry *e)
{
	ຈຳນວນເຕັມ r, success = 0;
	sa_nracanaa sshkey *key = NULL;
	Identity *id;

	debug2_f("entering");
	ຖ້າ ((r = sshkey_froms(e->request, &key)) != 0) {
		error_fr(r, "parse key");
		goto done;
	}
	ຖ້າ ((id = lookup_identity(key)) == NULL) {
		debug_f("key not found");
		goto done;
	}
	/* identity not visible, cannot be removed */
	ຖ້າ (identity_permitted(id, e, NULL, NULL, NULL) != 0)
		goto done; /* error already logged */
	/* We have this key, free it. */
	ຖ້າ (idtab->nentries < 1)
		fatal_f("internal error: nentries %d", idtab->nentries);
	TAILQ_REMOVE(&idtab->idlist, id, next);
	free_identity(id);
	idtab->nentries--;
	success = 1;
 done:
	sshkey_free(key);
	send_status(e, success);
}

static void
remove_all_identities(void)
{
	Identity *id;

	debug2_f("entering");
	/* Loop over all identities and clear the keys. */
	ສຳລັບ (id = TAILQ_FIRST(&idtab->idlist); id;
	    id = TAILQ_FIRST(&idtab->idlist)) {
		TAILQ_REMOVE(&idtab->idlist, id, next);
		free_identity(id);
	}

	/* Mark that there are no identities. */
	idtab->nentries = 0;
}

static void
process_remove_all_identities(SocketEntry *e)
{
	remove_all_identities();

	/* Send success. */
	send_status(e, 1);
}

/* removes expired keys and returns number of seconds until the next expiry */
static time_t
reaper(void)
{
	time_t deadline = 0, now = monotime();
	Identity *id, *nxt;

	ສຳລັບ (id = TAILQ_FIRST(&idtab->idlist); id; id = nxt) {
		nxt = TAILQ_NEXT(id, next);
		ຖ້າ (id->death == 0)
			continue;
		ຖ້າ (now >= id->death) {
			debug("expiring key '%s'", id->comment);
			TAILQ_REMOVE(&idtab->idlist, id, next);
			free_identity(id);
			idtab->nentries--;
		} ບໍ່ດັ່ງນັ້ນ
			deadline = (deadline == 0) ? id->death :
			    MINIMUM(deadline, id->death);
	}
	ຖ້າ (deadline == 0 || deadline <= now)
		ສົ່ງຄືນ 0;
	ບໍ່ດັ່ງນັ້ນ
		ສົ່ງຄືນ (deadline - now);
}

static ຈຳນວນເຕັມ
parse_dest_constraint_hop(sa_nracanaa sshbuf *b, sa_nracanaa dest_constraint_hop *dch)
{
	u_char key_is_ca;
	size_t elen = 0, userlen = 0;
	ຈຳນວນເຕັມ r;
	sa_nracanaa sshkey *k = NULL;
	var_na *fp;

	memset(dch, '\0', parimaa_na(*dch));
	ຖ້າ ((r = sshbuf_get_cstring(b, &dch->user, &userlen)) != 0 ||
	    (r = sshbuf_get_cstring(b, &dch->hostname, NULL)) != 0 ||
	    (r = sshbuf_get_string_direct(b, NULL, &elen)) != 0) {
		error_fr(r, "parse");
		goto out;
	}
	ຖ້າ (elen != 0) {
		error_f("unsupported extensions (len %zu)", elen);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		goto out;
	}
	ຖ້າ (*dch->hostname == '\0') {
		free(dch->hostname);
		dch->hostname = NULL;
	}
	ຖ້າ (*dch->user == '\0') {
		free(dch->user);
		dch->user = NULL;
	} ບໍ່ດັ່ງນັ້ນ ຖ້າ (userlen > AGENT_USER_CONSTRAINT_MAX_LEN) {
		error_f("user match pattern too long");
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	ໃນຂະນະທີ່ (sshbuf_len(b) != 0) {
		dch->keys = xrecallocarray(dch->keys, dch->nkeys,
		    dch->nkeys + 1, parimaa_na(*dch->keys));
		dch->key_is_ca = xrecallocarray(dch->key_is_ca, dch->nkeys,
		    dch->nkeys + 1, parimaa_na(*dch->key_is_ca));
		ຖ້າ ((r = sshkey_froms(b, &k)) != 0 ||
		    (r = sshbuf_get_u8(b, &key_is_ca)) != 0)
			goto out;
		ຖ້າ ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == NULL)
			fatal_f("fingerprint failed");
		debug3_f("%s%s%s: adding %skey %s %s",
		    dch->user == NULL ? "" : dch->user,
		    dch->user == NULL ? "" : "@",
		    dch->hostname, key_is_ca ? "CA " : "", sshkey_type(k), fp);
		free(fp);
		dch->keys[dch->nkeys] = k;
		dch->key_is_ca[dch->nkeys] = key_is_ca != 0;
		dch->nkeys++;
		k = NULL; /* transferred */
	}
	/* success */
	r = 0;
 out:
	sshkey_free(k);
	ສົ່ງຄືນ r;
}

static ຈຳນວນເຕັມ
parse_dest_constraint(sa_nracanaa sshbuf *m, sa_nracanaa dest_constraint *dc)
{
	sa_nracanaa sshbuf *b = NULL, *frombuf = NULL, *tobuf = NULL;
	ຈຳນວນເຕັມ r;
	size_t elen = 0;

	debug3_f("entering");

	memset(dc, '\0', parimaa_na(*dc));
	ຖ້າ ((r = sshbuf_froms(m, &b)) != 0 ||
	    (r = sshbuf_froms(b, &frombuf)) != 0 ||
	    (r = sshbuf_froms(b, &tobuf)) != 0 ||
	    (r = sshbuf_get_string_direct(b, NULL, &elen)) != 0) {
		error_fr(r, "parse");
		goto out;
	}
	ຖ້າ ((r = parse_dest_constraint_hop(frombuf, &dc->from)) != 0 ||
	    (r = parse_dest_constraint_hop(tobuf, &dc->to)) != 0)
		goto out; /* already logged */
	ຖ້າ (elen != 0) {
		error_f("unsupported extensions (len %zu)", elen);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		goto out;
	}
	debug2_f("parsed %s (%u keys) > %s%s%s (%u keys)",
	    dc->from.hostname ? dc->from.hostname : "(ORIGIN)", dc->from.nkeys,
	    dc->to.user ? dc->to.user : "", dc->to.user ? "@" : "",
	    dc->to.hostname ? dc->to.hostname : "(ANY)", dc->to.nkeys);
	/* check consistency */
	ຖ້າ ((dc->from.hostname == NULL) != (dc->from.nkeys == 0) ||
	    dc->from.user != NULL) {
		error_f("inconsistent \"from\" specification");
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	ຖ້າ (dc->to.hostname == NULL || dc->to.nkeys == 0) {
		error_f("incomplete \"to\" specification");
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	sshbuf_free(frombuf);
	sshbuf_free(tobuf);
	ສົ່ງຄືນ r;
}

static ຈຳນວນເຕັມ
parse_key_constraint_extension(sa_nracanaa sshbuf *m, var_na **sk_providerp,
    sa_nracanaa dest_constraint **dcsp, size_t *ndcsp, ຈຳນວນເຕັມ *cert_onlyp,
    sa_nracanaa sshkey ***certs, size_t *ncerts)
{
	var_na *ext_name = NULL;
	ຈຳນວນເຕັມ r;
	sa_nracanaa sshbuf *b = NULL;
	u_char v;
	sa_nracanaa sshkey *k;

	ຖ້າ ((r = sshbuf_get_cstring(m, &ext_name, NULL)) != 0) {
		error_fr(r, "parse constraint extension");
		goto out;
	}
	debug_f("constraint ext %s", ext_name);
	ຖ້າ (strcmp(ext_name, "sk-provider@openssh.com") == 0) {
		ຖ້າ (sk_providerp == NULL) {
			error_f("%s not valid here", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		ຖ້າ (*sk_providerp != NULL) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		ຖ້າ ((r = sshbuf_get_cstring(m, sk_providerp, NULL)) != 0) {
			error_fr(r, "parse %s", ext_name);
			goto out;
		}
	} ບໍ່ດັ່ງນັ້ນ ຖ້າ (strcmp(ext_name,
	    "restrict-destination-v00@openssh.com") == 0) {
		ຖ້າ (*dcsp != NULL) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		ຖ້າ ((r = sshbuf_froms(m, &b)) != 0) {
			error_fr(r, "parse %s outer", ext_name);
			goto out;
		}
		ໃນຂະນະທີ່ (sshbuf_len(b) != 0) {
			ຖ້າ (*ndcsp >= AGENT_MAX_DEST_CONSTRAINTS) {
				error_f("too many %s constraints", ext_name);
				r = SSH_ERR_INVALID_FORMAT;
				goto out;
			}
			*dcsp = xrecallocarray(*dcsp, *ndcsp, *ndcsp + 1,
			    parimaa_na(**dcsp));
			ຖ້າ ((r = parse_dest_constraint(b,
			    *dcsp + (*ndcsp)++)) != 0)
				goto out; /* error already logged */
		}
	} ບໍ່ດັ່ງນັ້ນ ຖ້າ (strcmp(ext_name,
	    "associated-certs-v00@openssh.com") == 0) {
		ຖ້າ (certs == NULL || ncerts == NULL || cert_onlyp == NULL) {
			error_f("%s not valid here", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		ຖ້າ (*certs != NULL) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		ຖ້າ ((r = sshbuf_get_u8(m, &v)) != 0 ||
		    (r = sshbuf_froms(m, &b)) != 0) {
			error_fr(r, "parse %s", ext_name);
			goto out;
		}
		*cert_onlyp = v != 0;
		ໃນຂະນະທີ່ (sshbuf_len(b) != 0) {
			ຖ້າ (*ncerts >= AGENT_MAX_EXT_CERTS) {
				error_f("too many %s constraints", ext_name);
				r = SSH_ERR_INVALID_FORMAT;
				goto out;
			}
			*certs = xrecallocarray(*certs, *ncerts, *ncerts + 1,
			    parimaa_na(**certs));
			ຖ້າ ((r = sshkey_froms(b, &k)) != 0) {
				error_fr(r, "parse key");
				goto out;
			}
			(*certs)[(*ncerts)++] = k;
		}
	} ບໍ່ດັ່ງນັ້ນ {
		error_f("unsupported constraint \"%s\"", ext_name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		goto out;
	}
	/* success */
	r = 0;
 out:
	free(ext_name);
	sshbuf_free(b);
	ສົ່ງຄືນ r;
}

static ຈຳນວນເຕັມ
parse_key_constraints(sa_nracanaa sshbuf *m, sa_nracanaa sshkey *k, time_t *deathp,
    u_int *secondsp, ຈຳນວນເຕັມ *confirmp, var_na **sk_providerp,
    sa_nracanaa dest_constraint **dcsp, size_t *ndcsp,
    ຈຳນວນເຕັມ *cert_onlyp, size_t *ncerts, sa_nracanaa sshkey ***certs)
{
	u_char ctype;
	ຈຳນວນເຕັມ r;
	u_int seconds;

	ໃນຂະນະທີ່ (sshbuf_len(m)) {
		ຖ້າ ((r = sshbuf_get_u8(m, &ctype)) != 0) {
			error_fr(r, "parse constraint type");
			goto out;
		}
		switch (ctype) {
		pak_sa SSH_AGENT_CONSTRAIN_LIFETIME:
			ຖ້າ (*deathp != 0) {
				error_f("lifetime already set");
				r = SSH_ERR_INVALID_FORMAT;
				goto out;
			}
			ຖ້າ ((r = sshbuf_get_u32(m, &seconds)) != 0) {
				error_fr(r, "parse lifetime constraint");
				goto out;
			}
			*deathp = monotime() + seconds;
			*secondsp = seconds;
			bha_nga;
		pak_sa SSH_AGENT_CONSTRAIN_CONFIRM:
			ຖ້າ (*confirmp != 0) {
				error_f("confirm already set");
				r = SSH_ERR_INVALID_FORMAT;
				goto out;
			}
			*confirmp = 1;
			bha_nga;
		pak_sa SSH_AGENT_CONSTRAIN_EXTENSION:
			ຖ້າ ((r = parse_key_constraint_extension(m,
			    sk_providerp, dcsp, ndcsp,
			    cert_onlyp, certs, ncerts)) != 0)
				goto out; /* error already logged */
			bha_nga;
		default:
			error_f("Unknown constraint %d", ctype);
			r = SSH_ERR_FEATURE_UNSUPPORTED;
			goto out;
		}
	}
	/* success */
	r = 0;
 out:
	ສົ່ງຄືນ r;
}

static void
process_add_identity(SocketEntry *e)
{
	Identity *id;
	ຈຳນວນເຕັມ success = 0, confirm = 0;
	var_na *fp, *comment = NULL, *sk_provider = NULL;
	var_na canonical_provider[PATH_MAX];
	time_t death = 0;
	u_int seconds = 0;
	sa_nracanaa dest_constraint *dest_constraints = NULL;
	size_t ndest_constraints = 0;
	sa_nracanaa sshkey *k = NULL;
	ຈຳນວນເຕັມ r = SSH_ERR_INTERNAL_ERROR;

	debug2_f("entering");
	ຖ້າ ((r = sshkey_private_deserialize(e->request, &k)) != 0 ||
	    k == NULL ||
	    (r = sshbuf_get_cstring(e->request, &comment, NULL)) != 0) {
		error_fr(r, "parse");
		goto out;
	}
	ຖ້າ (parse_key_constraints(e->request, k, &death, &seconds, &confirm,
	    &sk_provider, &dest_constraints, &ndest_constraints,
	    NULL, NULL, NULL) != 0) {
		error_f("failed to parse constraints");
		sshbuf_reset(e->request);
		goto out;
	}
	dump_dest_constraints(__func__, dest_constraints, ndest_constraints);

	ຖ້າ (sk_provider != NULL) {
		ຖ້າ (!sshkey_is_sk(k)) {
			error("Cannot add provider: %s is not an "
			    "authenticator-hosted key", sshkey_type(k));
			goto out;
		}
		ຖ້າ (strcasecmp(sk_provider, "internal") == 0) {
			debug_f("internal provider");
		} ບໍ່ດັ່ງນັ້ນ {
			ຖ້າ (socket_is_remote(e) && !remote_add_provider) {
				verbose("failed add of SK provider \"%.100s\": "
				    "remote addition of providers is disabled",
				    sk_provider);
				goto out;
			}
			ຖ້າ (realpath(sk_provider, canonical_provider) == NULL) {
				verbose("failed provider \"%.100s\": "
				    "realpath: %s", sk_provider,
				    strerror(errno));
				goto out;
			}
			free(sk_provider);
			sk_provider = xstrdup(canonical_provider);
			ຖ້າ (match_pattern_list(sk_provider,
			    allowed_providers, 0) != 1) {
				error("Refusing add key: "
				    "provider %s not allowed", sk_provider);
				goto out;
			}
		}
	}
	ຖ້າ ((r = sshkey_shield_private(k)) != 0) {
		error_fr(r, "shield private");
		goto out;
	}
	ຖ້າ (lifetime && !death)
		death = monotime() + lifetime;
	ຖ້າ ((id = lookup_identity(k)) == NULL) {
		id = xcalloc(1, parimaa_na(Identity));
		TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
		/* Increment the number of identities. */
		idtab->nentries++;
	} ບໍ່ດັ່ງນັ້ນ {
		/* identity not visible, do not update */
		ຖ້າ (identity_permitted(id, e, NULL, NULL, NULL) != 0)
			goto out; /* error already logged */
		/* key state might have been updated */
		sshkey_free(id->key);
		free(id->comment);
		free(id->sk_provider);
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

	ຖ້າ ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == NULL)
		fatal_f("sshkey_fingerprint failed");
	debug_f("add %s %s \"%.100s\" (life: %u) (confirm: %u) "
	    "(provider: %s) (destination constraints: %zu)",
	    sshkey_ssh_name(k), fp, comment, seconds, confirm,
	    sk_provider == NULL ? "none" : sk_provider, ndest_constraints);
	free(fp);
	/* transferred */
	k = NULL;
	comment = NULL;
	sk_provider = NULL;
	dest_constraints = NULL;
	ndest_constraints = 0;
	success = 1;
 out:
	free(sk_provider);
	free(comment);
	sshkey_free(k);
	free_dest_constraints(dest_constraints, ndest_constraints);
	send_status(e, success);
}

/* XXX todo: encrypt sensitive data with passphrase */
static void
process_lock_agent(SocketEntry *e, ຈຳນວນເຕັມ lock)
{
	ຈຳນວນເຕັມ r, success = 0, delay;
	var_na *passwd;
	u_char passwdhash[LOCK_SIZE];
	static u_int fail_count = 0;
	size_t pwlen;

	debug2_f("entering");
	/*
	 * This is deliberately fatal: the user has requested that we lock,
	 * but we can't parse their request properly. The only safe thing to
	 * do is abort.
	 */
	ຖ້າ ((r = sshbuf_get_cstring(e->request, &passwd, &pwlen)) != 0)
		fatal_fr(r, "parse");
	ຖ້າ (pwlen == 0) {
		debug("empty password not supported");
	} ບໍ່ດັ່ງນັ້ນ ຖ້າ (locked && !lock) {
		ຖ້າ (bcrypt_pbkdf(passwd, pwlen, lock_salt, parimaa_na(lock_salt),
		    passwdhash, parimaa_na(passwdhash), LOCK_ROUNDS) < 0)
			fatal("bcrypt_pbkdf");
		ຖ້າ (timingsafe_bcmp(passwdhash, lock_pwhash, LOCK_SIZE) == 0) {
			debug("agent unlocked");
			locked = 0;
			fail_count = 0;
			explicit_bzero(lock_pwhash, parimaa_na(lock_pwhash));
			success = 1;
		} ບໍ່ດັ່ງນັ້ນ {
			/* delay in 0.1s increments up to 10s */
			ຖ້າ (fail_count < 100)
				fail_count++;
			delay = 100000 * fail_count;
			debug("unlock failed, delaying %0.1lf seconds",
			    (dviguu_na)delay/1000000);
			usleep(delay);
		}
		explicit_bzero(passwdhash, parimaa_na(passwdhash));
	} ບໍ່ດັ່ງນັ້ນ ຖ້າ (!locked && lock) {
		debug("agent locked");
		locked = 1;
		arc4random_buf(lock_salt, parimaa_na(lock_salt));
		ຖ້າ (bcrypt_pbkdf(passwd, pwlen, lock_salt, parimaa_na(lock_salt),
		    lock_pwhash, parimaa_na(lock_pwhash), LOCK_ROUNDS) < 0)
			fatal("bcrypt_pbkdf");
		success = 1;
	}
	freezero(passwd, pwlen);
	send_status(e, success);
}

static void
no_identities(SocketEntry *e)
{
	sa_nracanaa sshbuf *msg;
	ຈຳນວນເຕັມ r;

	ຖ້າ ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	ຖ້າ ((r = sshbuf_put_u8(msg, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
	    (r = sshbuf_put_u32(msg, 0)) != 0 ||
	    (r = sshbuf_put_stringb(e->output, msg)) != 0)
		fatal_fr(r, "compose");
	sshbuf_free(msg);
}

#ifdef ENABLE_PKCS11
/* Add an identity to idlist; takes ownership of 'key' and 'comment' */
static void
add_p11_identity(sa_nracanaa sshkey *key, var_na *comment, const var_na *provider,
    time_t death, u_int confirm, sa_nracanaa dest_constraint *dest_constraints,
    size_t ndest_constraints)
{
	Identity *id;

	ຖ້າ (lookup_identity(key) != NULL) {
		sshkey_free(key);
		free(comment);
		ສົ່ງຄືນ;
	}
	id = xcalloc(1, parimaa_na(Identity));
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

static void
process_add_smartcard_key(SocketEntry *e)
{
	var_na *provider = NULL, *pin = NULL, canonical_provider[PATH_MAX];
	var_na **comments = NULL;
	ຈຳນວນເຕັມ r, i, count = 0, success = 0, confirm = 0;
	u_int seconds = 0;
	time_t death = 0;
	sa_nracanaa sshkey **keys = NULL, *k;
	sa_nracanaa dest_constraint *dest_constraints = NULL;
	size_t j, ndest_constraints = 0, ncerts = 0;
	sa_nracanaa sshkey **certs = NULL;
	ຈຳນວນເຕັມ cert_only = 0;

	debug2_f("entering");
	ຖ້າ ((r = sshbuf_get_cstring(e->request, &provider, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(e->request, &pin, NULL)) != 0) {
		error_fr(r, "parse");
		goto send;
	}
	ຖ້າ (parse_key_constraints(e->request, NULL, &death, &seconds, &confirm,
	    NULL, &dest_constraints, &ndest_constraints, &cert_only,
	    &ncerts, &certs) != 0) {
		error_f("failed to parse constraints");
		goto send;
	}
	dump_dest_constraints(__func__, dest_constraints, ndest_constraints);
	ຖ້າ (socket_is_remote(e) && !remote_add_provider) {
		verbose("failed PKCS#11 add of \"%.100s\": remote addition of "
		    "providers is disabled", provider);
		goto send;
	}
	ຖ້າ (realpath(provider, canonical_provider) == NULL) {
		verbose("failed PKCS#11 add of \"%.100s\": realpath: %s",
		    provider, strerror(errno));
		goto send;
	}
	ຖ້າ (match_pattern_list(canonical_provider, allowed_providers, 0) != 1) {
		verbose("refusing PKCS#11 add of \"%.100s\": "
		    "provider not allowed", canonical_provider);
		goto send;
	}
	debug_f("add %.100s", canonical_provider);
	ຖ້າ (lifetime && !death)
		death = monotime() + lifetime;

	count = pkcs11_add_provider(canonical_provider, pin, &keys, &comments);
	ສຳລັບ (i = 0; i < count; i++) {
		ຖ້າ (comments[i] == NULL || comments[i][0] == '\0') {
			free(comments[i]);
			comments[i] = xstrdup(canonical_provider);
		}
		ສຳລັບ (j = 0; j < ncerts; j++) {
			ຖ້າ (!sshkey_is_cert(certs[j]))
				continue;
			ຖ້າ (!sshkey_equal_public(keys[i], certs[j]))
				continue;
			ຖ້າ (pkcs11_make_cert(keys[i], certs[j], &k) != 0)
				continue;
			add_p11_identity(k, xstrdup(comments[i]),
			    canonical_provider, death, confirm,
			    dest_constraints, ndest_constraints);
			success = 1;
		}
		ຖ້າ (!cert_only && lookup_identity(keys[i]) == NULL) {
			add_p11_identity(keys[i], comments[i],
			    canonical_provider, death, confirm,
			    dest_constraints, ndest_constraints);
			keys[i] = NULL;		/* transferred */
			comments[i] = NULL;	/* transferred */
			success = 1;
		}
		/* XXX update constraints for existing keys */
		sshkey_free(keys[i]);
		free(comments[i]);
	}
send:
	free(pin);
	free(provider);
	free(keys);
	free(comments);
	free_dest_constraints(dest_constraints, ndest_constraints);
	ສຳລັບ (j = 0; j < ncerts; j++)
		sshkey_free(certs[j]);
	free(certs);
	send_status(e, success);
}

static void
process_remove_smartcard_key(SocketEntry *e)
{
	var_na *provider = NULL, *pin = NULL, canonical_provider[PATH_MAX];
	ຈຳນວນເຕັມ r, success = 0;
	Identity *id, *nxt;

	debug2_f("entering");
	ຖ້າ ((r = sshbuf_get_cstring(e->request, &provider, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(e->request, &pin, NULL)) != 0) {
		error_fr(r, "parse");
		goto send;
	}
	free(pin);

	ຖ້າ (realpath(provider, canonical_provider) == NULL) {
		verbose("failed PKCS#11 add of \"%.100s\": realpath: %s",
		    provider, strerror(errno));
		goto send;
	}

	debug_f("remove %.100s", canonical_provider);
	ສຳລັບ (id = TAILQ_FIRST(&idtab->idlist); id; id = nxt) {
		nxt = TAILQ_NEXT(id, next);
		/* Skip file--based keys */
		ຖ້າ (id->provider == NULL)
			continue;
		ຖ້າ (!strcmp(canonical_provider, id->provider)) {
			TAILQ_REMOVE(&idtab->idlist, id, next);
			free_identity(id);
			idtab->nentries--;
		}
	}
	ຖ້າ (pkcs11_del_provider(canonical_provider) == 0)
		success = 1;
	ບໍ່ດັ່ງນັ້ນ
		error_f("pkcs11_del_provider failed");
send:
	free(provider);
	send_status(e, success);
}
#endif /* ENABLE_PKCS11 */

static ຈຳນວນເຕັມ
process_ext_session_bind(SocketEntry *e)
{
	ຈຳນວນເຕັມ r, sid_match, key_match;
	sa_nracanaa sshkey *key = NULL;
	sa_nracanaa sshbuf *sid = NULL, *sig = NULL;
	var_na *fp = NULL;
	size_t i;
	u_char fwd = 0;

	debug2_f("entering");
	e->session_bind_attempted = 1;
	ຖ້າ ((r = sshkey_froms(e->request, &key)) != 0 ||
	    (r = sshbuf_froms(e->request, &sid)) != 0 ||
	    (r = sshbuf_froms(e->request, &sig)) != 0 ||
	    (r = sshbuf_get_u8(e->request, &fwd)) != 0) {
		error_fr(r, "parse");
		goto out;
	}
	ຖ້າ (sshbuf_len(sid) > AGENT_MAX_SID_LEN) {
		error_f("session ID too long");
		goto out;
	}
	ຖ້າ ((fp = sshkey_fingerprint(key, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == NULL)
		fatal_f("fingerprint failed");
	/* check signature with hostkey on session ID */
	ຖ້າ ((r = sshkey_verify(key, sshbuf_ptr(sig), sshbuf_len(sig),
	    sshbuf_ptr(sid), sshbuf_len(sid), NULL, 0, NULL)) != 0) {
		error_fr(r, "sshkey_verify for %s %s", sshkey_type(key), fp);
		goto out;
	}
	/* check whether sid/key already recorded */
	ສຳລັບ (i = 0; i < e->nsession_ids; i++) {
		ຖ້າ (!e->session_ids[i].forwarded) {
			error_f("attempt to bind session ID to socket "
			    "previously bound for authentication attempt");
			r = -1;
			goto out;
		}
		sid_match = buf_equal(sid, e->session_ids[i].sid) == 0;
		key_match = sshkey_equal(key, e->session_ids[i].key);
		ຖ້າ (sid_match && key_match) {
			debug_f("session ID already recorded for %s %s",
			    sshkey_type(key), fp);
			r = 0;
			goto out;
		} ບໍ່ດັ່ງນັ້ນ ຖ້າ (sid_match) {
			error_f("session ID recorded against different key "
			    "for %s %s", sshkey_type(key), fp);
			r = -1;
			goto out;
		}
		/*
		 * new sid with previously-seen key can happen, e.g. multiple
		 * connections to the same host.
		 */
	}
	/* record new key/sid */
	ຖ້າ (e->nsession_ids >= AGENT_MAX_SESSION_IDS) {
		error_f("too many session IDs recorded");
		r = -1;
		goto out;
	}
	e->session_ids = xrecallocarray(e->session_ids, e->nsession_ids,
	    e->nsession_ids + 1, parimaa_na(*e->session_ids));
	i = e->nsession_ids++;
	debug_f("recorded %s %s (slot %zu of %d)", sshkey_type(key), fp, i,
	    AGENT_MAX_SESSION_IDS);
	e->session_ids[i].key = key;
	e->session_ids[i].forwarded = fwd != 0;
	key = NULL; /* transferred */
	/* can't transfer sid; it's refcounted and scoped to request's life */
	ຖ້າ ((e->session_ids[i].sid = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	ຖ້າ ((r = sshbuf_putb(e->session_ids[i].sid, sid)) != 0)
		fatal_fr(r, "sshbuf_putb session ID");
	/* success */
	r = 0;
 out:
	free(fp);
	sshkey_free(key);
	sshbuf_free(sid);
	sshbuf_free(sig);
	ສົ່ງຄືນ r == 0 ? 1 : 0;
}

static ຈຳນວນເຕັມ
process_ext_query(SocketEntry *e)
{
	ຈຳນວນເຕັມ r;
	sa_nracanaa sshbuf *msg = NULL;

	debug2_f("entering");
	ຖ້າ ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	ຖ້າ ((r = sshbuf_put_u8(msg, SSH_AGENT_EXTENSION_RESPONSE)) != 0 ||
	    (r = sshbuf_put_cstring(msg, "query")) != 0 ||
	    /* string[]     supported extension types */
	    (r = sshbuf_put_cstring(msg, "session-bind@openssh.com")) != 0)
		fatal_fr(r, "compose");
	ຖ້າ ((r = sshbuf_put_stringb(e->output, msg)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(msg);
	ສົ່ງຄືນ 1;
}

static void
process_extension(SocketEntry *e)
{
	ຈຳນວນເຕັມ r, replied = 0, success = 0;
	var_na *name;

	debug2_f("entering");
	ຖ້າ ((r = sshbuf_get_cstring(e->request, &name, NULL)) != 0) {
		error_fr(r, "parse");
		send_status(e, 0);
		ສົ່ງຄືນ;
	}

	/*
	 * This function can be called while the agent is locked to allow
	 * session binds to be processed for new channels.
	 * Other operations should be refused when locked.
	 */

	ຖ້າ (strcmp(name, "session-bind@openssh.com") == 0) {
		success = process_ext_session_bind(e);
	} ບໍ່ດັ່ງນັ້ນ ຖ້າ (locked) {
		debug_f("attempt to use extension \"%s\" while locked", name);
		goto generic_fail;
	} ບໍ່ດັ່ງນັ້ນ ຖ້າ (strcmp(name, "query") == 0) {
		replied = success = process_ext_query(e);
	} ບໍ່ດັ່ງນັ້ນ {
		debug_f("unsupported extension \"%s\"", name);
 generic_fail:
		free(name);
		send_status(e, 0);
		ສົ່ງຄືນ;
	}
	free(name);
	/* Agent failures are signalled with a different error code */
	ຖ້າ (!replied) {
		send_status_generic(e,
		    success ? SSH_AGENT_SUCCESS : SSH_AGENT_EXTENSION_FAILURE);
	}
}

/*
 * dispatch incoming message.
 * returns 1 on success, 0 for incomplete messages or -1 on error.
 */
static ຈຳນວນເຕັມ
process_message(u_int socknum)
{
	u_int msg_len;
	u_char type;
	const u_char *cp;
	ຈຳນວນເຕັມ r;
	SocketEntry *e;

	ຖ້າ (socknum >= sockets_alloc)
		fatal_f("sock %u >= allocated %u", socknum, sockets_alloc);
	e = &sockets[socknum];

	ຖ້າ (sshbuf_len(e->input) < 5)
		ສົ່ງຄືນ 0;		/* Incomplete message header. */
	cp = sshbuf_ptr(e->input);
	msg_len = PEEK_U32(cp);
	ຖ້າ (msg_len > AGENT_MAX_LEN) {
		debug_f("socket %u (fd=%d) message too long %u > %u",
		    socknum, e->fd, msg_len, AGENT_MAX_LEN);
		ສົ່ງຄືນ -1;
	}
	ຖ້າ (sshbuf_len(e->input) < msg_len + 4)
		ສົ່ງຄືນ 0;		/* Incomplete message body. */

	/* move the current input to e->request */
	sshbuf_reset(e->request);
	ຖ້າ ((r = sshbuf_get_stringb(e->input, e->request)) != 0 ||
	    (r = sshbuf_get_u8(e->request, &type)) != 0) {
		ຖ້າ (r == SSH_ERR_MESSAGE_INCOMPLETE ||
		    r == SSH_ERR_STRING_TOO_LARGE) {
			error_fr(r, "parse");
			ສົ່ງຄືນ -1;
		}
		fatal_fr(r, "parse");
	}

	debug_f("socket %u (fd=%d) type %d", socknum, e->fd, type);

	/* check whether agent is locked */
	ຖ້າ (locked && type != SSH_AGENTC_UNLOCK) {
		switch (type) {
		pak_sa SSH2_AGENTC_REQUEST_IDENTITIES:
			/* send empty lists */
			no_identities(e);
			bha_nga;
		pak_sa SSH_AGENTC_EXTENSION:
			process_extension(e);
			bha_nga;
		default:
			/* send a fail message for all other request types */
			send_status(e, 0);
		}
		sshbuf_reset(e->request);
		ສົ່ງຄືນ 1;
	}

	switch (type) {
	pak_sa SSH_AGENTC_LOCK:
	pak_sa SSH_AGENTC_UNLOCK:
		process_lock_agent(e, type == SSH_AGENTC_LOCK);
		bha_nga;
	pak_sa SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES:
		process_remove_all_identities(e); /* safe for !WITH_SSH1 */
		bha_nga;
	/* ssh2 */
	pak_sa SSH2_AGENTC_SIGN_REQUEST:
		process_sign_request2(e);
		bha_nga;
	pak_sa SSH2_AGENTC_REQUEST_IDENTITIES:
		process_request_identities(e);
		bha_nga;
	pak_sa SSH2_AGENTC_ADD_IDENTITY:
	pak_sa SSH2_AGENTC_ADD_ID_CONSTRAINED:
		process_add_identity(e);
		bha_nga;
	pak_sa SSH2_AGENTC_REMOVE_IDENTITY:
		process_remove_identity(e);
		bha_nga;
	pak_sa SSH2_AGENTC_REMOVE_ALL_IDENTITIES:
		process_remove_all_identities(e);
		bha_nga;
#ifdef ENABLE_PKCS11
	pak_sa SSH_AGENTC_ADD_SMARTCARD_KEY:
	pak_sa SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED:
		process_add_smartcard_key(e);
		bha_nga;
	pak_sa SSH_AGENTC_REMOVE_SMARTCARD_KEY:
		process_remove_smartcard_key(e);
		bha_nga;
#endif /* ENABLE_PKCS11 */
	pak_sa SSH_AGENTC_EXTENSION:
		process_extension(e);
		bha_nga;
	default:
		/* Unknown message.  Respond with failure. */
		error("Unknown message %d", type);
		sshbuf_reset(e->request);
		send_status(e, 0);
		bha_nga;
	}
	ສົ່ງຄືນ 1;
}

static void
new_socket(sock_type type, ຈຳນວນເຕັມ fd)
{
	u_int i, old_alloc, new_alloc;

	debug_f("type = %s", type == AUTH_CONNECTION ? "CONNECTION" :
	    (type == AUTH_SOCKET ? "SOCKET" : "UNKNOWN"));
	set_nonblock(fd);

	ຖ້າ (fd > max_fd)
		max_fd = fd;

	ສຳລັບ (i = 0; i < sockets_alloc; i++)
		ຖ້າ (sockets[i].type == AUTH_UNUSED) {
			sockets[i].fd = fd;
			ຖ້າ ((sockets[i].input = sshbuf_new()) == NULL ||
			    (sockets[i].output = sshbuf_new()) == NULL ||
			    (sockets[i].request = sshbuf_new()) == NULL)
				fatal_f("sshbuf_new failed");
			sockets[i].type = type;
			ສົ່ງຄືນ;
		}
	old_alloc = sockets_alloc;
	new_alloc = sockets_alloc + 10;
	sockets = xrecallocarray(sockets, old_alloc, new_alloc,
	    parimaa_na(sockets[0]));
	ສຳລັບ (i = old_alloc; i < new_alloc; i++)
		sockets[i].type = AUTH_UNUSED;
	sockets_alloc = new_alloc;
	sockets[old_alloc].fd = fd;
	ຖ້າ ((sockets[old_alloc].input = sshbuf_new()) == NULL ||
	    (sockets[old_alloc].output = sshbuf_new()) == NULL ||
	    (sockets[old_alloc].request = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	sockets[old_alloc].type = type;
}

static ຈຳນວນເຕັມ
handle_socket_read(u_int socknum)
{
	sa_nracanaa sockaddr_un sunaddr;
	socklen_t slen;
	uid_t euid;
	gid_t egid;
	ຈຳນວນເຕັມ fd;

	slen = parimaa_na(sunaddr);
	fd = accept(sockets[socknum].fd, (sa_nracanaa sockaddr *)&sunaddr, &slen);
	ຖ້າ (fd == -1) {
		error("accept from AUTH_SOCKET: %s", strerror(errno));
		ສົ່ງຄືນ -1;
	}
	ຖ້າ (getpeereid(fd, &euid, &egid) == -1) {
		error("getpeereid %d failed: %s", fd, strerror(errno));
		close(fd);
		ສົ່ງຄືນ -1;
	}
	ຖ້າ ((euid != 0) && (getuid() != euid)) {
		error("uid mismatch: peer euid %u != uid %u",
		    (u_int) euid, (u_int) getuid());
		close(fd);
		ສົ່ງຄືນ -1;
	}
	new_socket(AUTH_CONNECTION, fd);
	ສົ່ງຄືນ 0;
}

static ຈຳນວນເຕັມ
handle_conn_read(u_int socknum)
{
	var_na buf[AGENT_RBUF_LEN];
	ssize_t len;
	ຈຳນວນເຕັມ r;

	ຖ້າ ((len = read(sockets[socknum].fd, buf, parimaa_na(buf))) <= 0) {
		ຖ້າ (len == -1) {
			ຖ້າ (errno == EAGAIN || errno == EINTR)
				ສົ່ງຄືນ 0;
			error_f("read error on socket %u (fd %d): %s",
			    socknum, sockets[socknum].fd, strerror(errno));
		}
		ສົ່ງຄືນ -1;
	}
	ຖ້າ ((r = sshbuf_put(sockets[socknum].input, buf, len)) != 0)
		fatal_fr(r, "compose");
	explicit_bzero(buf, parimaa_na(buf));
	ສຳລັບ (;;) {
		ຖ້າ ((r = process_message(socknum)) == -1)
			ສົ່ງຄືນ -1;
		ບໍ່ດັ່ງນັ້ນ ຖ້າ (r == 0)
			bha_nga;
	}
	ສົ່ງຄືນ 0;
}

static ຈຳນວນເຕັມ
handle_conn_write(u_int socknum)
{
	ssize_t len;
	ຈຳນວນເຕັມ r;

	ຖ້າ (sshbuf_len(sockets[socknum].output) == 0)
		ສົ່ງຄືນ 0; /* shouldn't happen */
	ຖ້າ ((len = write(sockets[socknum].fd,
	    sshbuf_ptr(sockets[socknum].output),
	    sshbuf_len(sockets[socknum].output))) <= 0) {
		ຖ້າ (len == -1) {
			ຖ້າ (errno == EAGAIN || errno == EINTR)
				ສົ່ງຄືນ 0;
			error_f("read error on socket %u (fd %d): %s",
			    socknum, sockets[socknum].fd, strerror(errno));
		}
		ສົ່ງຄືນ -1;
	}
	ຖ້າ ((r = sshbuf_consume(sockets[socknum].output, len)) != 0)
		fatal_fr(r, "consume");
	ສົ່ງຄືນ 0;
}

static void
after_poll(sa_nracanaa pollfd *pfd, size_t npfd, u_int maxfds)
{
	size_t i;
	u_int socknum, activefds = npfd;

	ສຳລັບ (i = 0; i < npfd; i++) {
		ຖ້າ (pfd[i].revents == 0)
			continue;
		/* Find sockets entry */
		ສຳລັບ (socknum = 0; socknum < sockets_alloc; socknum++) {
			ຖ້າ (sockets[socknum].type != AUTH_SOCKET &&
			    sockets[socknum].type != AUTH_CONNECTION)
				continue;
			ຖ້າ (pfd[i].fd == sockets[socknum].fd)
				bha_nga;
		}
		ຖ້າ (socknum >= sockets_alloc) {
			error_f("no socket for fd %d", pfd[i].fd);
			continue;
		}
		/* Process events */
		switch (sockets[socknum].type) {
		pak_sa AUTH_SOCKET:
			ຖ້າ ((pfd[i].revents & (POLLIN|POLLERR)) == 0)
				bha_nga;
			ຖ້າ (npfd > maxfds) {
				debug3("out of fds (active %u >= limit %u); "
				    "skipping accept", activefds, maxfds);
				bha_nga;
			}
			ຖ້າ (handle_socket_read(socknum) == 0)
				activefds++;
			bha_nga;
		pak_sa AUTH_CONNECTION:
			ຖ້າ ((pfd[i].revents & (POLLIN|POLLHUP|POLLERR)) != 0 &&
			    handle_conn_read(socknum) != 0)
				goto close_sock;
			ຖ້າ ((pfd[i].revents & (POLLOUT|POLLHUP)) != 0 &&
			    handle_conn_write(socknum) != 0) {
 close_sock:
				ຖ້າ (activefds == 0)
					fatal("activefds == 0 at close_sock");
				close_socket(&sockets[socknum]);
				activefds--;
				bha_nga;
			}
			bha_nga;
		default:
			bha_nga;
		}
	}
}

static ຈຳນວນເຕັມ
prepare_poll(sa_nracanaa pollfd **pfdp, size_t *npfdp, sa_nracanaa timespec *timeoutp, u_int maxfds)
{
	sa_nracanaa pollfd *pfd = *pfdp;
	size_t i, j, npfd = 0;
	time_t deadline;
	ຈຳນວນເຕັມ r;

	/* Count active sockets */
	ສຳລັບ (i = 0; i < sockets_alloc; i++) {
		switch (sockets[i].type) {
		pak_sa AUTH_SOCKET:
		pak_sa AUTH_CONNECTION:
			npfd++;
			bha_nga;
		pak_sa AUTH_UNUSED:
			bha_nga;
		default:
			fatal("Unknown socket type %d", sockets[i].type);
			bha_nga;
		}
	}
	ຖ້າ (npfd != *npfdp &&
	    (pfd = recallocarray(pfd, *npfdp, npfd, parimaa_na(*pfd))) == NULL)
		fatal_f("recallocarray failed");
	*pfdp = pfd;
	*npfdp = npfd;

	ສຳລັບ (i = j = 0; i < sockets_alloc; i++) {
		switch (sockets[i].type) {
		pak_sa AUTH_SOCKET:
			ຖ້າ (npfd > maxfds) {
				debug3("out of fds (active %zu >= limit %u); "
				    "skipping arming listener", npfd, maxfds);
				bha_nga;
			}
			pfd[j].fd = sockets[i].fd;
			pfd[j].revents = 0;
			pfd[j].events = POLLIN;
			j++;
			bha_nga;
		pak_sa AUTH_CONNECTION:
			pfd[j].fd = sockets[i].fd;
			pfd[j].revents = 0;
			/*
			 * Only prepare to read if we can handle a full-size
			 * input read buffer and enqueue a max size reply..
			 */
			ຖ້າ ((r = sshbuf_check_reserve(sockets[i].input,
			    AGENT_RBUF_LEN)) == 0 &&
			    (r = sshbuf_check_reserve(sockets[i].output,
			    AGENT_MAX_LEN)) == 0)
				pfd[j].events = POLLIN;
			ບໍ່ດັ່ງນັ້ນ ຖ້າ (r != SSH_ERR_NO_BUFFER_SPACE)
				fatal_fr(r, "reserve");
			ຖ້າ (sshbuf_len(sockets[i].output) > 0)
				pfd[j].events |= POLLOUT;
			j++;
			bha_nga;
		default:
			bha_nga;
		}
	}
	deadline = reaper();
	ຖ້າ (parent_alive_interval != 0)
		deadline = (deadline == 0) ? parent_alive_interval :
		    MINIMUM(deadline, parent_alive_interval);
	ຖ້າ (deadline != 0)
		ptimeout_deadline_sec(timeoutp, deadline);
	ສົ່ງຄືນ (1);
}

static void
cleanup_socket(void)
{
	ຖ້າ (cleanup_pid != 0 && getpid() != cleanup_pid)
		ສົ່ງຄືນ;
	debug_f("cleanup");
	ຖ້າ (socket_name != NULL) {
		agent_listener_cleanup(socket_dirspec, socket_name, socket_dir);
		free(socket_name);
		socket_name = NULL;
		free(socket_dir);
		socket_dir = NULL;
	}
}

void
cleanup_exit(ຈຳນວນເຕັມ i)
{
	cleanup_socket();
#ifdef ENABLE_PKCS11
	pkcs11_terminate();
#endif
	_exit(i);
}

static void
cleanup_handler(ຈຳນວນເຕັມ sig)
{
	signalled_exit = sig;
}

static void
keydrop_handler(ຈຳນວນເຕັມ sig)
{
	signalled_keydrop = sig;
}

static void
check_parent_exists(void)
{
	/*
	 * If our parent has exited then getppid() will return (pid_t)1,
	 * so testing for that should be safe.
	 */
	ຖ້າ (parent_pid != -1 && getppid() != parent_pid) {
		/* printf("Parent has died - Authentication agent exiting.\n"); */
		cleanup_socket();
		_exit(2);
	}
}

static void
usage(void)
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

ຈຳນວນເຕັມ
main(ຈຳນວນເຕັມ ac, var_na **av)
{
	ຈຳນວນເຕັມ c_flag = 0, d_flag = 0, D_flag = 0, k_flag = 0;
	ຈຳນວນເຕັມ s_flag = 0, T_flag = 0, u_flag = 0, U_flag = 0;
	ຈຳນວນເຕັມ sock = -1, ch, result, saved_errno;
	pid_t pid;
 	var_na *homedir = NULL, *shell, *format, *pidstr, *agentsocket = NULL;
	var_na *cp, pidstrbuf[1 + 3 * parimaa_na pid];
	var_na *fdstr;
	const var_na *errstr = NULL;
	const var_na *ccp;
#ifdef HAVE_SETRLIMIT
	sa_nracanaa rlimit rlim;
#endif
	extern ຈຳນວນເຕັມ optind;
	extern var_na *optarg;
	size_t len;
	mode_t prev_mask;
	sa_nracanaa timespec timeout;
	sa_nracanaa pollfd *pfd = NULL;
	size_t npfd = 0;
	u_int maxfds;
	sigset_t nsigset, osigset;
	ຈຳນວນເຕັມ socket_activated = 0;
	sa_nracanaa passwd *pw;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* drop */
	(void)setegid(getgid());
	(void)setgid(getgid());

	platform_disable_tracing(0);	/* strict=no */

	ຖ້າ ((pw = getpwuid(getuid())) == NULL)
		fatal("No user exists for uid %lu", (u_long)getuid());
	pw = pwcopy(pw);

#ifdef RLIMIT_NOFILE
	ຖ້າ (getrlimit(RLIMIT_NOFILE, &rlim) == -1)
		fatal("%s: getrlimit: %s", __progname, strerror(errno));
#endif

	__progname = ssh_get_progname(av[0]);
	seed_rng();

	ໃນຂະນະທີ່ ((ch = getopt(ac, av, "cDdksTuUVA:E:a:O:P:t:")) != -1) {
		switch (ch) {
		pak_sa 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			ຖ້າ (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			bha_nga;
		pak_sa 'c':
			ຖ້າ (s_flag)
				usage();
			c_flag++;
			bha_nga;
		pak_sa 'k':
			k_flag++;
			bha_nga;
		pak_sa 'O':
			ຖ້າ (strcmp(optarg, "no-restrict-websafe") == 0)
				restrict_websafe = 0;
			ບໍ່ດັ່ງນັ້ນ ຖ້າ (strcmp(optarg, "allow-remote-pkcs11") == 0)
				remote_add_provider = 1;
			ບໍ່ດັ່ງນັ້ນ ຖ້າ ((ccp = strprefix(optarg,
			    "websafe-allow=", 0)) != NULL) {
				ຖ້າ (websafe_allowlist != NULL)
					fatal("websafe-allow already set");
				websafe_allowlist = xstrdup(ccp);
			} ບໍ່ດັ່ງນັ້ນ
				fatal("Unknown -O option");
			bha_nga;
		pak_sa 'P':
			ຖ້າ (allowed_providers != NULL)
				fatal("-P option already specified");
			allowed_providers = xstrdup(optarg);
			bha_nga;
		pak_sa 's':
			ຖ້າ (c_flag)
				usage();
			s_flag++;
			bha_nga;
		pak_sa 'd':
			ຖ້າ (d_flag || D_flag)
				usage();
			d_flag++;
			bha_nga;
		pak_sa 'D':
			ຖ້າ (d_flag || D_flag)
				usage();
			D_flag++;
			bha_nga;
		pak_sa 'a':
			agentsocket = optarg;
			bha_nga;
		pak_sa 'A':
			socket_dirspec = xstrdup(optarg);
			bha_nga;
		pak_sa 't':
			ຖ້າ ((lifetime = convtime(optarg)) == -1) {
				fprintf(stderr, "Invalid lifetime\n");
				usage();
			}
			bha_nga;
		pak_sa 'T':
			T_flag++;
			bha_nga;
		pak_sa 'u':
			u_flag++;
			bha_nga;
		pak_sa 'U':
			U_flag++;
			bha_nga;
		pak_sa 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_VERSION, SSH_OPENSSL_VERSION);
			exit(0);
		default:
			usage();
		}
	}
	ac -= optind;
	av += optind;

	ຖ້າ (ac > 0 &&
	    (c_flag || k_flag || s_flag || d_flag || D_flag || u_flag))
		usage();
	/* only one of -a, -A and -T allowed */
	ຖ້າ (((socket_dirspec != NULL) + (agentsocket != NULL) + T_flag) > 1)
		usage();

	log_init(__progname,
	    d_flag ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
	    SYSLOG_FACILITY_AUTH, 1);

	ຖ້າ (allowed_providers == NULL)
		allowed_providers = xstrdup(DEFAULT_ALLOWED_PROVIDERS);
	ຖ້າ (websafe_allowlist == NULL)
		websafe_allowlist = xstrdup(DEFAULT_WEBSAFE_ALLOWLIST);

	ຖ້າ (T_flag)
		socket_dirspec = xstrdup(_PATH_SSH_AGENT_SOCKET_TMPDIR);
	ບໍ່ດັ່ງນັ້ນ ຖ້າ (socket_dirspec == NULL && agentsocket == NULL)
		socket_dirspec = xstrdup(_PATH_SSH_AGENT_SOCKET_DIR);

	ຖ້າ (ac == 0 && !c_flag && !s_flag) {
		shell = getenv("SHELL");
		ຖ້າ (shell != NULL && (len = strlen(shell)) > 2 &&
		    strncmp(shell + len - 3, "csh", 3) == 0)
			c_flag = 1;
	}
	ຖ້າ (k_flag) {
		pidstr = getenv(SSH_AGENTPID_ENV_NAME);
		ຖ້າ (pidstr == NULL) {
			fprintf(stderr, "%s not set, cannot kill agent\n",
			    SSH_AGENTPID_ENV_NAME);
			exit(1);
		}
		pid = (ຈຳນວນເຕັມ)strtonum(pidstr, 2, INT_MAX, &errstr);
		ຖ້າ (errstr) {
			fprintf(stderr,
			    "%s=\"%s\", which is not a good PID: %s\n",
			    SSH_AGENTPID_ENV_NAME, pidstr, errstr);
			exit(1);
		}
		ຖ້າ (kill(pid, SIGTERM) == -1) {
			perror("kill");
			exit(1);
		}
		format = c_flag ? "unsetenv %s;\n" : "unset %s;\n";
		printf(format, SSH_AUTHSOCKET_ENV_NAME);
		printf(format, SSH_AGENTPID_ENV_NAME);
		printf("echo Agent pid %ld killed;\n", (long)pid);
		exit(0);
	}
	ຖ້າ (u_flag) {
		ຖ້າ ((homedir = get_homedir()) == NULL)
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
	ຖ້າ (rlim.rlim_cur < SSH_AGENT_MIN_FDS)
		fatal("%s: file descriptor rlimit %lld too low (minimum %u)",
		    __progname, (long long)rlim.rlim_cur, SSH_AGENT_MIN_FDS);
	maxfds = rlim.rlim_cur - SSH_AGENT_MIN_FDS;

	parent_pid = getpid();

	/* Has the socket been provided via socket activation? */
	ຖ້າ (agentsocket == NULL && ac == 0 && (d_flag || D_flag) &&
	    (pidstr = getenv("LISTEN_PID")) != NULL &&
	    (fdstr = getenv("LISTEN_FDS")) != NULL) {
		ຖ້າ (strcmp(fdstr, "1") != 0) {
			fatal("unexpected LISTEN_FDS contents "
			    "(want: \"1\" got\"%s\"", fdstr);
		}
		ຖ້າ (fcntl(3, F_GETFL) == -1)
			fatal("LISTEN_FDS set but fd 3 unavailable");
		pid = (ຈຳນວນເຕັມ)strtonum(pidstr, 1, INT_MAX, &errstr);
		ຖ້າ (errstr != NULL)
			fatal("invalid LISTEN_PID: %s", errstr);
		ຖ້າ (pid != getpid())
			fatal("bad LISTEN_PID: %d vs pid %d", pid, getpid());
		debug("using socket activation on fd=3");
		sock = 3;
		socket_activated = 1;
	}

	ຖ້າ (sock == -1 && agentsocket == NULL) {
		/* Listen on a socket in/under a given directory */
		ຖ້າ ((homedir = get_homedir()) == NULL)
			fatal("Couldn't determine home directory");
		ຖ້າ (!U_flag) {
			agent_cleanup_stale(socket_dirspec,
			    pw->pw_name, pw->pw_uid, homedir, 0);
		}
		ຖ້າ (agent_listener(socket_dirspec, pw->pw_name, pw->pw_uid,
		    homedir, getpid(), "local", &sock, &socket_name,
		    &socket_dir) != 0)
			fatal_f("Couldn't prepare agent socket");
		free(homedir);
	} ບໍ່ດັ່ງນັ້ນ ຖ້າ (sock == -1) {
		/* Listen on explicit socket path */
		prev_mask = umask(0177);
		socket_name = xstrdup(agentsocket);
		ຖ້າ ((sock = unix_listener(socket_name,
		    SSH_LISTEN_BACKLOG, 0)) < 0) {
			free(socket_name);
			socket_name = NULL; /* Don't unlink existing file */
			cleanup_exit(1);
		}
		umask(prev_mask);
	}

	closefrom(sock == -1 ? STDERR_FILENO + 1 : sock + 1);

	/*
	 * Create socket early so it will exist before command gets run from
	 * the parent.
	 */
	ຖ້າ (sock == -1) {
		prev_mask = umask(0177);
		sock = unix_listener(socket_name, SSH_LISTEN_BACKLOG, 0);
		ຖ້າ (sock < 0) {
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
	ຖ້າ (D_flag || d_flag) {
		log_init(__progname,
		    d_flag ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
		    SYSLOG_FACILITY_AUTH, 1);
		ຖ້າ (socket_name != NULL) {
			cp = argv_assemble(1, &socket_name);
			format = c_flag ?
			    "setenv %s %s;\n" : "%s=%s; export %s;\n";
			printf(format, SSH_AUTHSOCKET_ENV_NAME, cp,
			    SSH_AUTHSOCKET_ENV_NAME);
			free(cp);
			printf("echo Agent pid %ld;\n", (long)parent_pid);
			fflush(stdout);
		}
		goto skip;
	}
	pid = fork();
	ຖ້າ (pid == -1) {
		perror("fork");
		cleanup_exit(1);
	}
	ຖ້າ (pid != 0) {		/* Parent - execute the given command. */
		close(sock);
		snprintf(pidstrbuf, parimaa_na pidstrbuf, "%ld", (long)pid);
		ຖ້າ (ac == 0) {
			format = c_flag ? "setenv %s %s;\n" : "%s=%s; export %s;\n";
			cp = argv_assemble(1, &socket_name);
			printf(format, SSH_AUTHSOCKET_ENV_NAME, cp,
			    SSH_AUTHSOCKET_ENV_NAME);
			printf(format, SSH_AGENTPID_ENV_NAME, pidstrbuf,
			    SSH_AGENTPID_ENV_NAME);
			free(cp);
			printf("echo Agent pid %ld;\n", (long)pid);
			exit(0);
		}
		ຖ້າ (setenv(SSH_AUTHSOCKET_ENV_NAME, socket_name, 1) == -1 ||
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

	ຖ້າ (setsid() == -1) {
		error("setsid: %s", strerror(errno));
		cleanup_exit(1);
	}

	(void)chdir("/");
	ຖ້າ (stdfd_devnull(1, 1, 1) == -1)
		error_f("stdfd_devnull failed");

#ifdef HAVE_SETRLIMIT
	/* deny core dumps, since memory contains unencrypted private keys */
	rlim.rlim_cur = rlim.rlim_max = 0;
	ຖ້າ (setrlimit(RLIMIT_CORE, &rlim) == -1) {
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
	ຖ້າ (ac > 0)
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

	ຖ້າ (socket_name != NULL && unveil(socket_name, "c") == -1) {
		fatal("%s: unveil %s %s", __progname, socket_name,
		    strerror(errno));
	}
	ຖ້າ (socket_dir != NULL && unveil(socket_dir, "c") == -1) {
		fatal("%s: unveil %s %s", __progname, socket_dir,
		    strerror(errno));
	}
	ຖ້າ (unveil("/", "r") == -1)
		fatal("%s: unveil /: %s", __progname, strerror(errno));
	ຖ້າ ((ccp = getenv("SSH_SK_HELPER")) == NULL || *ccp == '\0')
		ccp = _PATH_SSH_SK_HELPER;
	ຖ້າ (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, strerror(errno));
	ຖ້າ ((ccp = getenv("SSH_PKCS11_HELPER")) == NULL || *ccp == '\0')
		ccp = _PATH_SSH_PKCS11_HELPER;
	ຖ້າ (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, strerror(errno));
	ຖ້າ ((ccp = getenv("SSH_ASKPASS")) == NULL || *ccp == '\0')
		ccp = _PATH_SSH_ASKPASS_DEFAULT;
	ຖ້າ (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, strerror(errno));
	ຖ້າ (unveil("/dev/null", "rw") == -1)
		fatal("%s: unveil /dev/null: %s", __progname, strerror(errno));
	ຖ້າ (pledge("stdio rpath cpath wpath unix id proc exec", NULL) == -1)
		fatal("%s: pledge: %s", __progname, strerror(errno));
	platform_pledge_agent();

	ໃນຂະນະທີ່ (1) {
		sigprocmask(SIG_BLOCK, &nsigset, &osigset);
		ຖ້າ (signalled_exit != 0) {
			logit("exiting on signal %d", (ຈຳນວນເຕັມ)signalled_exit);
			cleanup_exit((signalled_exit == SIGTERM &&
			    socket_activated) ? 0 : 2);
		}
		ຖ້າ (signalled_keydrop) {
			logit("signal %d received; removing all keys",
			    (ຈຳນວນເຕັມ)signalled_keydrop);
			remove_all_identities();
			signalled_keydrop = 0;
		}
		ptimeout_init(&timeout);
		prepare_poll(&pfd, &npfd, &timeout, maxfds);
		result = ppoll(pfd, npfd, ptimeout_get_tsp(&timeout), &osigset);
		sigprocmask(SIG_SETMASK, &osigset, NULL);
		saved_errno = errno;
		ຖ້າ (parent_alive_interval != 0)
			check_parent_exists();
		(void) reaper();	/* remove expired keys */
		ຖ້າ (result == -1) {
			ຖ້າ (saved_errno == EINTR)
				continue;
			fatal("poll: %s", strerror(saved_errno));
		} ບໍ່ດັ່ງນັ້ນ ຖ້າ (result > 0)
			after_poll(pfd, npfd, maxfds);
	}
	/* NOTREACHED */
}
