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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/time.h>
#شامل <sys/queue.h>
#شامل <sys/resource.h>
#شامل <sys/socket.h>
#شامل <sys/stat.h>
#شامل <sys/un.h>
#شامل <sys/wait.h>

#ifdef WITH_OPENSSL
#شامل <openssl/evp.h>
#شامل "openbsd-compat/openssl-compat.h"
#endif

#شامل <errno.h>
#شامل <fcntl.h>
#شامل <paths.h>
#شامل <poll.h>
#شامل <signal.h>
#شامل <stdlib.h>
#شامل <stdio.h>
#شامل <string.h>
#شامل <stdarg.h>
#شامل <limits.h>
#شامل <time.h>
#شامل <unistd.h>
#شامل <util.h>
#شامل <pwd.h>

#شامل "xmalloc.h"
#شامل "ssh.h"
#شامل "ssh2.h"
#شامل "sshbuf.h"
#شامل "sshkey.h"
#شامل "authfd.h"
#شامل "log.h"
#شامل "misc.h"
#شامل "digest.h"
#شامل "ssherr.h"
#شامل "match.h"
#شامل "msg.h"
#شامل "pathnames.h"
#شامل "ssh-pkcs11.h"
#شامل "sk-api.h"
#شامل "myproposal.h"
#شامل "version.h"

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

تعریفنوع شمارش {
	AUTH_UNUSED = 0,
	AUTH_SOCKET = 1,
	AUTH_CONNECTION = 2,
} sock_type;

ساختار hostkey_sid {
	ساختار sshkey *کلید;
	ساختار sshbuf *sid;
	صحیح forwarded;
};

تعریفنوع ساختار socket_entry {
	صحیح fd;
	sock_type type;
	ساختار sshbuf *درون_داد;
	ساختار sshbuf *output;
	ساختار sshbuf *request;
	size_t nsession_ids;
	ساختار hostkey_sid *session_ids;
	صحیح session_bind_attempted;
} SocketEntry;

u_int sockets_alloc = 0;
SocketEntry *sockets = پوچ;

تعریفنوع ساختار identity {
	TAILQ_ENTRY(identity) next;
	ساختار sshkey *کلید;
	نویسه *comment;
	نویسه *provider;
	time_t death;
	u_int confirm;
	نویسه *sk_provider;
	ساختار dest_constraint *dest_constraints;
	size_t ndest_constraints;
} Identity;

ساختار idtable {
	صحیح nentries;
	TAILQ_HEAD(idqueue, identity) idlist;
};

/* private key table */
ساختار idtable *idtab;

صحیح max_fd = 0;

/* pid of shell == parent of agent */
pid_t parent_pid = -1;
time_t parent_alive_interval = 0;

ایستا sig_atomic_t signalled_exit;
ایستا sig_atomic_t signalled_keydrop;

/* pid of process for which cleanup_socket is applicable */
pid_t cleanup_pid = 0;

/* pathname and directory for AUTH_SOCKET */
ایستا نویسه *socket_name;
ایستا نویسه *socket_dir;
ایستا نویسه *socket_dirspec;

/* Pattern-list of allowed PKCS#11/Security key paths */
ایستا نویسه *allowed_providers;

/*
 * Allows PKCS11 providers or SK keys that use non-internal providers to
 * be added over a remote connection (identified by session-bind@openssh.com).
 */
ایستا صحیح remote_add_provider;

/* locking */
#define LOCK_SIZE	32
#define LOCK_SALT_SIZE	16
#define LOCK_ROUNDS	1
صحیح locked = 0;
u_char lock_pwhash[LOCK_SIZE];
u_char lock_salt[LOCK_SALT_SIZE];

بیرونی نویسه *__progname;

/* Default lifetime in seconds (0 == forever) */
ایستا صحیح lifetime = 0;

ایستا صحیح fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* Refuse signing of non-SSH messages for web-origin FIDO keys */
ایستا صحیح restrict_websafe = 1;
ایستا نویسه *websafe_allowlist;

ایستا تهی
close_socket(SocketEntry *e)
{
	size_t i;

	close(e->fd);
	sshbuf_free(e->درون_داد);
	sshbuf_free(e->output);
	sshbuf_free(e->request);
	برای (i = 0; i < e->nsession_ids; i++) {
		sshkey_free(e->session_ids[i].کلید);
		sshbuf_free(e->session_ids[i].sid);
	}
	آزاد(e->session_ids);
	memset(e, '\0', اندازه(*e));
	e->fd = -1;
	e->type = AUTH_UNUSED;
}

ایستا تهی
idtab_init(تهی)
{
	idtab = xcalloc(1, اندازه(*idtab));
	TAILQ_INIT(&idtab->idlist);
	idtab->nentries = 0;
}

ایستا تهی
free_dest_constraint_hop(ساختار dest_constraint_hop *dch)
{
	u_int i;

	اگر (dch == پوچ)
		بازگشت;
	آزاد(dch->user);
	آزاد(dch->hostname);
	برای (i = 0; i < dch->nkeys; i++)
		sshkey_free(dch->کلیدها[i]);
	آزاد(dch->کلیدها);
	آزاد(dch->کلید_is_ca);
}

ایستا تهی
free_dest_constraints(ساختار dest_constraint *dcs, size_t ndcs)
{
	size_t i;

	برای (i = 0; i < ndcs; i++) {
		free_dest_constraint_hop(&dcs[i].from);
		free_dest_constraint_hop(&dcs[i].to);
	}
	آزاد(dcs);
}

#ifdef ENABLE_PKCS11
ایستا تهی
dup_dest_constraint_hop(ثابت ساختار dest_constraint_hop *dch,
    ساختار dest_constraint_hop *out)
{
	u_int i;
	صحیح r;

	out->user = dch->user == پوچ ? پوچ : xstrdup(dch->user);
	out->hostname = dch->hostname == پوچ ? پوچ : xstrdup(dch->hostname);
	out->is_ca = dch->is_ca;
	out->nkeys = dch->nkeys;
	out->کلیدها = out->nkeys == 0 ? پوچ :
	    xcalloc(out->nkeys, اندازه(*out->کلیدها));
	out->کلید_is_ca = out->nkeys == 0 ? پوچ :
	    xcalloc(out->nkeys, اندازه(*out->کلید_is_ca));
	برای (i = 0; i < dch->nkeys; i++) {
		اگر (dch->کلیدها[i] != پوچ &&
		    (r = sshkey_from_private(dch->کلیدها[i],
		    &(out->کلیدها[i]))) != 0)
			fatal_fr(r, "copy key");
		out->کلید_is_ca[i] = dch->کلید_is_ca[i];
	}
}

ایستا ساختار dest_constraint *
dup_dest_constraints(ثابت ساختار dest_constraint *dcs, size_t ndcs)
{
	size_t i;
	ساختار dest_constraint *ret;

	اگر (ndcs == 0)
		بازگشت پوچ;
	ret = xcalloc(ndcs, اندازه(*ret));
	برای (i = 0; i < ndcs; i++) {
		dup_dest_constraint_hop(&dcs[i].from, &ret[i].from);
		dup_dest_constraint_hop(&dcs[i].to, &ret[i].to);
	}
	بازگشت ret;
}
#endif /* ENABLE_PKCS11 */

#ifdef DEBUG_CONSTRAINTS
ایستا تهی
dump_dest_constraint_hop(ثابت ساختار dest_constraint_hop *dch)
{
	u_int i;
	نویسه *fp;

	debug_f("user %s hostname %s is_ca %d nkeys %u",
	    dch->user == پوچ ? "(null)" : dch->user,
	    dch->hostname == پوچ ? "(null)" : dch->hostname,
	    dch->is_ca, dch->nkeys);
	برای (i = 0; i < dch->nkeys; i++) {
		fp = پوچ;
		اگر (dch->کلیدها[i] != پوچ &&
		    (fp = sshkey_fingerprint(dch->کلیدها[i],
		    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == پوچ)
			fatal_f("fingerprint failed");
		debug_f("key %u/%u: %s%s%s key_is_ca %d", i, dch->nkeys,
		    dch->کلیدها[i] == پوچ ? "" : sshkey_ssh_name(dch->کلیدها[i]),
		    dch->کلیدها[i] == پوچ ? "" : " ",
		    dch->کلیدها[i] == پوچ ? "none" : fp,
		    dch->کلید_is_ca[i]);
		آزاد(fp);
	}
}
#endif /* DEBUG_CONSTRAINTS */

ایستا تهی
dump_dest_constraints(ثابت نویسه *context,
    ثابت ساختار dest_constraint *dcs, size_t ndcs)
{
#ifdef DEBUG_CONSTRAINTS
	size_t i;

	debug_f("%s: %zu constraints", context, ndcs);
	برای (i = 0; i < ndcs; i++) {
		debug_f("constraint %zu / %zu: from: ", i, ndcs);
		dump_dest_constraint_hop(&dcs[i].from);
		debug_f("constraint %zu / %zu: to: ", i, ndcs);
		dump_dest_constraint_hop(&dcs[i].to);
	}
	debug_f("done for %s", context);
#endif /* DEBUG_CONSTRAINTS */
}

ایستا تهی
free_identity(Identity *id)
{
	sshkey_free(id->کلید);
	آزاد(id->provider);
	آزاد(id->comment);
	آزاد(id->sk_provider);
	free_dest_constraints(id->dest_constraints, id->ndest_constraints);
	آزاد(id);
}

/*
 * Match 'key' against the key/CA list in a destination constraint hop
 * Returns 0 on success or -1 otherwise.
 */
ایستا صحیح
match_کلید_hop(ثابت نویسه *tag, ثابت ساختار sshkey *کلید,
    ثابت ساختار dest_constraint_hop *dch)
{
	ثابت نویسه *reason = پوچ;
	ثابت نویسه *hostname = dch->hostname ? dch->hostname : "(ORIGIN)";
	u_int i;
	نویسه *fp;

	اگر (کلید == پوچ)
		بازگشت -1;
	/* XXX logspam */
	اگر ((fp = sshkey_fingerprint(کلید, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == پوچ)
		fatal_f("fingerprint failed");
	debug3_f("%s: entering hostname %s, requested key %s %s, %u keys avail",
	    tag, hostname, sshkey_type(کلید), fp, dch->nkeys);
	آزاد(fp);
	برای (i = 0; i < dch->nkeys; i++) {
		اگر (dch->کلیدها[i] == پوچ)
			بازگشت -1;
		/* XXX logspam */
		اگر ((fp = sshkey_fingerprint(dch->کلیدها[i], SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == پوچ)
			fatal_f("fingerprint failed");
		debug3_f("%s: key %u: %s%s %s", tag, i,
		    dch->کلید_is_ca[i] ? "CA " : "",
		    sshkey_type(dch->کلیدها[i]), fp);
		آزاد(fp);
		اگر (!sshkey_is_cert(کلید)) {
			/* plain key */
			اگر (dch->کلید_is_ca[i] ||
			    !sshkey_equal(کلید, dch->کلیدها[i]))
				ادامه;
			بازگشت 0;
		}
		/* certificate */
		اگر (!dch->کلید_is_ca[i])
			ادامه;
		اگر (کلید->cert == پوچ || کلید->cert->signature_کلید == پوچ)
			بازگشت -1; /* shouldn't happen */
		اگر (!sshkey_equal(کلید->cert->signature_کلید, dch->کلیدها[i]))
			ادامه;
		اگر (sshkey_cert_check_host(کلید, hostname,
		    SSH_ALLOWED_CA_SIGALGS, &reason) != 0) {
			debug_f("cert %s / hostname %s rejected: %s",
			    کلید->cert->کلید_id, hostname, reason);
			ادامه;
		}
		بازگشت 0;
	}
	بازگشت -1;
}

/* Check destination constraints on an identity against the hostkey/user */
ایستا صحیح
permitted_by_dest_constraints(ثابت ساختار sshkey *fromkey,
    ثابت ساختار sshkey *tokey, Identity *id, ثابت نویسه *user,
    ثابت نویسه **hostnamep)
{
	size_t i;
	ساختار dest_constraint *d;

	اگر (hostnamep != پوچ)
		*hostnamep = پوچ;
	برای (i = 0; i < id->ndest_constraints; i++) {
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
		اگر (fromkey == پوچ) {
			/* We are matching the first hop */
			اگر (d->from.hostname != پوچ || d->from.nkeys != 0)
				ادامه;
		} وگرنه اگر (match_کلید_hop("from", fromkey, &d->from) != 0)
			ادامه;

		/* Match 'to' key */
		اگر (tokey != پوچ && match_کلید_hop("to", tokey, &d->to) != 0)
			ادامه;

		/* Match user if specified */
		اگر (d->to.user != پوچ && user != پوچ &&
		    !match_pattern(user, d->to.user))
			ادامه;

		/* successfully matched this constraint */
		اگر (hostnamep != پوچ)
			*hostnamep = d->to.hostname;
		debug2_f("allowed for hostname %s",
		    d->to.hostname == پوچ ? "*" : d->to.hostname);
		بازگشت 0;
	}
	/* no match */
	debug2_f("%s identity \"%s\" not permitted for this destination",
	    sshkey_type(id->کلید), id->comment);
	بازگشت -1;
}

/*
 * Check whether hostkeys on a SocketEntry and the optionally specified user
 * are permitted by the destination constraints on the Identity.
 * Returns 0 on success or -1 otherwise.
 */
ایستا صحیح
identity_permitted(Identity *id, SocketEntry *e, نویسه *user,
    ثابت نویسه **forward_hostnamep, ثابت نویسه **last_hostnamep)
{
	size_t i;
	ثابت نویسه **hp;
	ساختار hostkey_sid *hks;
	ثابت ساختار sshkey *fromkey = پوچ;
	ثابت نویسه *test_user;
	نویسه *fp1, *fp2;

	/* XXX remove logspam */
	debug3_f("entering: key %s comment \"%s\", %zu socket bindings, "
	    "%zu constraints", sshkey_type(id->کلید), id->comment,
	    e->nsession_ids, id->ndest_constraints);
	اگر (id->ndest_constraints == 0)
		بازگشت 0; /* unconstrained */
	اگر (e->session_bind_attempted && e->nsession_ids == 0) {
		error_f("previous session bind failed on socket");
		بازگشت -1;
	}
	اگر (e->nsession_ids == 0)
		بازگشت 0; /* local use */
	/*
	 * Walk through the hops recorded by session_id and try to find a
	 * constraint that satisfies each.
	 */
	برای (i = 0; i < e->nsession_ids; i++) {
		hks = e->session_ids + i;
		اگر (hks->کلید == پوچ)
			fatal_f("internal error: no bound key");
		/* XXX remove logspam */
		fp1 = fp2 = پوچ;
		اگر (fromkey != پوچ &&
		    (fp1 = sshkey_fingerprint(fromkey, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == پوچ)
			fatal_f("fingerprint failed");
		اگر ((fp2 = sshkey_fingerprint(hks->کلید, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == پوچ)
			fatal_f("fingerprint failed");
		debug3_f("socketentry fd=%d, entry %zu %s, "
		    "from hostkey %s %s to user %s hostkey %s %s",
		    e->fd, i, hks->forwarded ? "FORWARD" : "AUTH",
		    fromkey ? sshkey_type(fromkey) : "(ORIGIN)",
		    fromkey ? fp1 : "", user ? user : "(ANY)",
		    sshkey_type(hks->کلید), fp2);
		آزاد(fp1);
		آزاد(fp2);
		/*
		 * Record the hostnames for the initial forwarding and
		 * the final destination.
		 */
		hp = پوچ;
		اگر (i == e->nsession_ids - 1)
			hp = last_hostnamep;
		وگرنه اگر (i == 0)
			hp = forward_hostnamep;
		/* Special handling for final recorded binding */
		test_user = پوچ;
		اگر (i == e->nsession_ids - 1) {
			/* Can only check user at final hop */
			test_user = user;
			/*
			 * user is only presented for signature requests.
			 * If this is the case, make sure last binding is not
			 * for a forwarding.
			 */
			اگر (hks->forwarded && user != پوچ) {
				error_f("tried to sign on forwarding hop");
				بازگشت -1;
			}
		} وگرنه اگر (!hks->forwarded) {
			error_f("tried to forward though signing bind");
			بازگشت -1;
		}
		اگر (permitted_by_dest_constraints(fromkey, hks->کلید, id,
		    test_user, hp) != 0)
			بازگشت -1;
		fromkey = hks->کلید;
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
	اگر (hks->forwarded && user == پوچ &&
	    permitted_by_dest_constraints(hks->کلید, پوچ, id,
	    پوچ, پوچ) != 0) {
		debug3_f("key permitted at host but not after");
		بازگشت -1;
	}

	/* success */
	بازگشت 0;
}

ایستا صحیح
socket_is_remote(SocketEntry *e)
{
	بازگشت e->session_bind_attempted || (e->nsession_ids != 0);
}

/* return matching private key for given public key */
ایستا Identity *
lookup_identity(ساختار sshkey *کلید)
{
	Identity *id;

	TAILQ_FOREACH(id, &idtab->idlist, next) {
		اگر (sshkey_equal(کلید, id->کلید))
			بازگشت (id);
	}
	بازگشت (پوچ);
}

/* Check confirmation of keysign request */
ایستا صحیح
confirm_کلید(Identity *id, ثابت نویسه *extra)
{
	نویسه *p;
	صحیح ret = -1;

	p = sshkey_fingerprint(id->کلید, fingerprint_hash, SSH_FP_DEFAULT);
	اگر (p != پوچ &&
	    ask_permission("Allow use of key %s?\nKey fingerprint %s.%s%s",
	    id->comment, p,
	    extra == پوچ ? "" : "\n", extra == پوچ ? "" : extra))
		ret = 0;
	آزاد(p);

	بازگشت (ret);
}

ایستا تهی
send_status_generic(SocketEntry *e, u_int code)
{
	صحیح r;

	اگر ((r = sshbuf_put_u32(e->output, 1)) != 0 ||
	    (r = sshbuf_put_u8(e->output, code)) != 0)
		fatal_fr(r, "compose");
}

ایستا تهی
send_status(SocketEntry *e, صحیح success)
{
	send_status_generic(e,
	    success ? SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE);
}

/* send list of supported public keys to 'client' */
ایستا تهی
process_request_identities(SocketEntry *e)
{
	Identity *id;
	ساختار sshbuf *پیام, *کلیدها;
	صحیح r;
	u_int i = 0, nentries = 0;
	نویسه *fp;

	debug2_f("entering");

	اگر ((پیام = sshbuf_new()) == پوچ || (کلیدها = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	TAILQ_FOREACH(id, &idtab->idlist, next) {
		اگر ((fp = sshkey_fingerprint(id->کلید, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == پوچ)
			fatal_f("fingerprint failed");
		debug_f("key %u / %u: %s %s", i++, idtab->nentries,
		    sshkey_ssh_name(id->کلید), fp);
		dump_dest_constraints(__func__,
		    id->dest_constraints, id->ndest_constraints);
		آزاد(fp);
		/* identity not visible, don't include in response */
		اگر (identity_permitted(id, e, پوچ, پوچ, پوچ) != 0)
			ادامه;
		اگر ((r = sshkey_puts(id->کلید, کلیدها)) != 0 ||
		    (r = sshbuf_put_cstring(کلیدها, id->comment)) != 0) {
			error_fr(r, "compose key/comment");
			ادامه;
		}
		nentries++;
	}
	debug2_f("replying with %u allowed of %u available keys",
	    nentries, idtab->nentries);
	اگر ((r = sshbuf_put_u8(پیام, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
	    (r = sshbuf_put_u32(پیام, nentries)) != 0 ||
	    (r = sshbuf_putb(پیام, کلیدها)) != 0)
		fatal_fr(r, "compose");
	اگر ((r = sshbuf_put_stringb(e->output, پیام)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(پیام);
	sshbuf_free(کلیدها);
}


ایستا نویسه *
agent_decode_alg(ساختار sshkey *کلید, u_int flags)
{
	اگر (کلید->type == کلید_RSA) {
		اگر (flags & SSH_AGENT_RSA_SHA2_256)
			بازگشت "rsa-sha2-256";
		وگرنه اگر (flags & SSH_AGENT_RSA_SHA2_512)
			بازگشت "rsa-sha2-512";
	} وگرنه اگر (کلید->type == کلید_RSA_CERT) {
		اگر (flags & SSH_AGENT_RSA_SHA2_256)
			بازگشت "rsa-sha2-256-cert-v01@openssh.com";
		وگرنه اگر (flags & SSH_AGENT_RSA_SHA2_512)
			بازگشت "rsa-sha2-512-cert-v01@openssh.com";
	}
	بازگشت پوچ;
}

/*
 * Attempt to parse the contents of a buffer as a SSH publickey userauth
 * request, checking its contents for consistency and matching the embedded
 * key against the one that is being used for signing.
 * Note: does not modify msg buffer.
 * Optionally extract the username, session ID and/or hostkey from the request.
 */
ایستا صحیح
parse_userauth_request(ساختار sshbuf *پیام, ثابت ساختار sshkey *expected_کلید,
    نویسه **userp, ساختار sshbuf **sess_idp, ساختار sshkey **hostkeyp)
{
	ساختار sshbuf *b = پوچ, *sess_id = پوچ;
	نویسه *user = پوچ, *service = پوچ, *method = پوچ, *pkalg = پوچ;
	صحیح r;
	u_char t, sig_follows;
	ساختار sshkey *mkey = پوچ, *hostkey = پوچ;

	اگر (userp != پوچ)
		*userp = پوچ;
	اگر (sess_idp != پوچ)
		*sess_idp = پوچ;
	اگر (hostkeyp != پوچ)
		*hostkeyp = پوچ;
	اگر ((b = sshbuf_fromb(پیام)) == پوچ)
		fatal_f("sshbuf_fromb");

	/* SSH userauth request */
	اگر ((r = sshbuf_froms(b, &sess_id)) != 0)
		برو out;
	اگر (sshbuf_len(sess_id) == 0) {
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	اگر ((r = sshbuf_get_u8(b, &t)) != 0 || /* SSH2_MSG_USERAUTH_REQUEST */
	    (r = sshbuf_get_cstring(b, &user, پوچ)) != 0 || /* server user */
	    (r = sshbuf_get_cstring(b, &service, پوچ)) != 0 || /* service */
	    (r = sshbuf_get_cstring(b, &method, پوچ)) != 0 || /* method */
	    (r = sshbuf_get_u8(b, &sig_follows)) != 0 || /* sig-follows */
	    (r = sshbuf_get_cstring(b, &pkalg, پوچ)) != 0 || /* alg */
	    (r = sshkey_froms(b, &mkey)) != 0) /*کلید*/
		برو out;
	اگر (t != SSH2_پیام_USERAUTH_REQUEST ||
	    sig_follows != 1 ||
	    strcmp(service, "ssh-connection") != 0 ||
	    !sshkey_equal(expected_کلید, mkey) ||
	    sshkey_type_from_name(pkalg) != expected_کلید->type) {
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	اگر (strcmp(method, "publickey-hostbound-v00@openssh.com") == 0) {
		اگر ((r = sshkey_froms(b, &hostkey)) != 0)
			برو out;
	} وگرنه اگر (strcmp(method, "publickey") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	اگر (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	/* success */
	r = 0;
	debug3_f("well formed userauth");
	اگر (userp != پوچ) {
		*userp = user;
		user = پوچ;
	}
	اگر (sess_idp != پوچ) {
		*sess_idp = sess_id;
		sess_id = پوچ;
	}
	اگر (hostkeyp != پوچ) {
		*hostkeyp = hostkey;
		hostkey = پوچ;
	}
 out:
	sshbuf_free(b);
	sshbuf_free(sess_id);
	آزاد(user);
	آزاد(service);
	آزاد(method);
	آزاد(pkalg);
	sshkey_free(mkey);
	sshkey_free(hostkey);
	بازگشت r;
}

/*
 * Attempt to parse the contents of a buffer as a SSHSIG signature request.
 * Note: does not modify buffer.
 */
ایستا صحیح
parse_sshsig_request(ساختار sshbuf *پیام)
{
	صحیح r;
	ساختار sshbuf *b;

	اگر ((b = sshbuf_fromb(پیام)) == پوچ)
		fatal_f("sshbuf_fromb");

	اگر ((r = sshbuf_cmp(b, 0, "SSHSIG", 6)) != 0 ||
	    (r = sshbuf_consume(b, 6)) != 0 ||
	    (r = sshbuf_get_cstring(b, پوچ, پوچ)) != 0 || /* namespace */
	    (r = sshbuf_get_string_direct(b, پوچ, پوچ)) != 0 || /* reserved */
	    (r = sshbuf_get_cstring(b, پوچ, پوچ)) != 0 || /* hashalg */
	    (r = sshbuf_get_string_direct(b, پوچ, پوچ)) != 0) /* H(msg) */
		برو out;
	اگر (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	بازگشت r;
}

/*
 * This function inspects a message to be signed by a FIDO key that has a
 * web-like application string (i.e. one that does not begin with "ssh:".
 * It checks that the message is one of those expected for SSH operations
 * (pubkey userauth, sshsig, CA key signing) to exclude signing challenges
 * for the web.
 */
ایستا صحیح
check_websafe_message_contents(ساختار sshkey *کلید, ساختار sshbuf *data)
{
	اگر (parse_userauth_request(data, کلید, پوچ, پوچ, پوچ) == 0) {
		debug_f("signed data matches public key userauth request");
		بازگشت 1;
	}
	اگر (parse_sshsig_request(data) == 0) {
		debug_f("signed data matches SSHSIG signature request");
		بازگشت 1;
	}

	/* XXX check CA signature operation */

	error("web-origin key attempting to sign non-SSH message");
	بازگشت 0;
}

ایستا صحیح
buf_equal(ثابت ساختار sshbuf *a, ثابت ساختار sshbuf *b)
{
	اگر (sshbuf_ptr(a) == پوچ || sshbuf_ptr(b) == پوچ)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	اگر (sshbuf_len(a) != sshbuf_len(b))
		بازگشت SSH_ERR_INVALID_FORMAT;
	اگر (timingsafe_bcmp(sshbuf_ptr(a), sshbuf_ptr(b), sshbuf_len(a)) != 0)
		بازگشت SSH_ERR_INVALID_FORMAT;
	بازگشت 0;
}

/* ssh2 only */
ایستا تهی
process_sign_request2(SocketEntry *e)
{
	u_char *signature = پوچ;
	size_t slen = 0;
	u_int compat = 0, flags;
	صحیح r, ok = -1, retried = 0;
	نویسه *fp = پوچ, *pin = پوچ, *prompt = پوچ;
	نویسه *user = پوچ, *sig_dest = پوچ;
	ثابت نویسه *fwd_host = پوچ, *dest_host = پوچ;
	ساختار sshbuf *پیام = پوچ, *data = پوچ, *sid = پوچ;
	ساختار sshkey *کلید = پوچ, *hostkey = پوچ;
	ساختار identity *id;
	ساختار notifier_ctx *notifier = پوچ;

	debug_f("entering");

	اگر ((پیام = sshbuf_new()) == پوچ || (data = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshkey_froms(e->request, &کلید)) != 0 ||
	    (r = sshbuf_get_stringb(e->request, data)) != 0 ||
	    (r = sshbuf_get_u32(e->request, &flags)) != 0) {
		error_fr(r, "parse");
		برو send;
	}

	اگر ((id = lookup_identity(کلید)) == پوچ) {
		verbose_f("%s key not found", sshkey_type(کلید));
		برو send;
	}
	اگر ((fp = sshkey_fingerprint(کلید, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == پوچ)
		fatal_f("fingerprint failed");

	اگر (id->ndest_constraints != 0) {
		اگر (e->nsession_ids == 0) {
			logit_f("refusing use of destination-constrained key "
			    "to sign on unbound connection");
			برو send;
		}
		اگر (parse_userauth_request(data, کلید, &user, &sid,
		    &hostkey) != 0) {
			logit_f("refusing use of destination-constrained key "
			   "to sign an unidentified signature");
			برو send;
		}
		/* XXX logspam */
		debug_f("user=%s", user);
		اگر (identity_permitted(id, e, user, &fwd_host, &dest_host) != 0)
			برو send;
		/* XXX display fwd_host/dest_host in askpass UI */
		/*
		 * Ensure that the session ID is the most recent one
		 * registered on the socket - it should have been bound by
		 * ssh immediately before userauth.
		 */
		اگر (buf_equal(sid,
		    e->session_ids[e->nsession_ids - 1].sid) != 0) {
			error_f("unexpected session ID (%zu listed) on "
			    "signature request for target user %s with "
			    "key %s %s", e->nsession_ids, user,
			    sshkey_type(id->کلید), fp);
			برو send;
		}
		/*
		 * Ensure that the hostkey embedded in the signature matches
		 * the one most recently bound to the socket. An exception is
		 * made for the initial forwarding hop.
		 */
		اگر (e->nsession_ids > 1 && hostkey == پوچ) {
			error_f("refusing use of destination-constrained key: "
			    "no hostkey recorded in signature for forwarded "
			    "connection");
			برو send;
		}
		اگر (hostkey != پوچ && !sshkey_equal(hostkey,
		    e->session_ids[e->nsession_ids - 1].کلید)) {
			error_f("refusing use of destination-constrained key: "
			    "mismatch between hostkey in request and most "
			    "recently bound session");
			برو send;
		}
		xasprintf(&sig_dest, "public key authentication request for "
		    "user \"%s\" to listed host", user);
	}
	اگر (id->confirm && confirm_کلید(id, sig_dest) != 0) {
		verbose_f("user refused key");
		برو send;
	}
	اگر (sshkey_is_sk(id->کلید)) {
		اگر (restrict_websafe &&
		    match_pattern_list(id->کلید->sk_application,
		    websafe_allowlist, 0) != 1 &&
		    !check_websafe_message_contents(کلید, data)) {
			/* error already logged */
			برو send;
		}
		اگر (id->کلید->sk_flags & SSH_SK_USER_PRESENCE_REQD) {
			notifier = notify_start(0,
			    "Confirm user presence for key %s %s%s%s",
			    sshkey_type(id->کلید), fp,
			    sig_dest == پوچ ? "" : "\n",
			    sig_dest == پوچ ? "" : sig_dest);
		}
	}
 retry_pin:
	اگر ((r = sshkey_sign(id->کلید, &signature, &slen,
	    sshbuf_ptr(data), sshbuf_len(data), agent_decode_alg(کلید, flags),
	    id->sk_provider, pin, compat)) != 0) {
		debug_fr(r, "sshkey_sign");
		اگر (pin == پوچ && !retried && sshkey_is_sk(id->کلید) &&
		    r == SSH_ERR_کلید_WRONG_PASSPHRASE) {
			notify_complete(notifier, پوچ);
			notifier = پوچ;
			/* XXX include sig_dest */
			xasprintf(&prompt, "Enter PIN%sfor %s key %s: ",
			    (id->کلید->sk_flags & SSH_SK_USER_PRESENCE_REQD) ?
			    " and confirm user presence " : " ",
			    sshkey_type(id->کلید), fp);
			pin = read_passphrase(prompt, RP_USE_ASKPASS);
			retried = 1;
			برو retry_pin;
		}
		error_fr(r, "sshkey_sign");
		برو send;
	}
	/* Success */
	ok = 0;
	debug_f("good signature");
 send:
	notify_complete(notifier, "User presence confirmed");

	اگر (ok == 0) {
		اگر ((r = sshbuf_put_u8(پیام, SSH2_AGENT_SIGN_RESPONSE)) != 0 ||
		    (r = sshbuf_put_string(پیام, signature, slen)) != 0)
			fatal_fr(r, "compose");
	} وگرنه اگر ((r = sshbuf_put_u8(پیام, SSH_AGENT_FAILURE)) != 0)
		fatal_fr(r, "compose failure");

	اگر ((r = sshbuf_put_stringb(e->output, پیام)) != 0)
		fatal_fr(r, "enqueue");

	sshbuf_free(sid);
	sshbuf_free(data);
	sshbuf_free(پیام);
	sshkey_free(کلید);
	sshkey_free(hostkey);
	آزاد(fp);
	آزاد(signature);
	آزاد(sig_dest);
	آزاد(user);
	آزاد(prompt);
	اگر (pin != پوچ)
		freezero(pin, strlen(pin));
}

/* shared */
ایستا تهی
process_remove_identity(SocketEntry *e)
{
	صحیح r, success = 0;
	ساختار sshkey *کلید = پوچ;
	Identity *id;

	debug2_f("entering");
	اگر ((r = sshkey_froms(e->request, &کلید)) != 0) {
		error_fr(r, "parse key");
		برو done;
	}
	اگر ((id = lookup_identity(کلید)) == پوچ) {
		debug_f("key not found");
		برو done;
	}
	/* identity not visible, cannot be removed */
	اگر (identity_permitted(id, e, پوچ, پوچ, پوچ) != 0)
		برو done; /* error already logged */
	/* We have this key, free it. */
	اگر (idtab->nentries < 1)
		fatal_f("internal error: nentries %d", idtab->nentries);
	TAILQ_REMOVE(&idtab->idlist, id, next);
	free_identity(id);
	idtab->nentries--;
	success = 1;
 done:
	sshkey_free(کلید);
	send_status(e, success);
}

ایستا تهی
remove_all_identities(تهی)
{
	Identity *id;

	debug2_f("entering");
	/* Loop over all identities and clear the keys. */
	برای (id = TAILQ_FIRST(&idtab->idlist); id;
	    id = TAILQ_FIRST(&idtab->idlist)) {
		TAILQ_REMOVE(&idtab->idlist, id, next);
		free_identity(id);
	}

	/* Mark that there are no identities. */
	idtab->nentries = 0;
}

ایستا تهی
process_remove_all_identities(SocketEntry *e)
{
	remove_all_identities();

	/* Send success. */
	send_status(e, 1);
}

/* removes expired keys and returns number of seconds until the next expiry */
ایستا time_t
reaper(تهی)
{
	time_t deadline = 0, now = monotime();
	Identity *id, *nxt;

	برای (id = TAILQ_FIRST(&idtab->idlist); id; id = nxt) {
		nxt = TAILQ_NEXT(id, next);
		اگر (id->death == 0)
			ادامه;
		اگر (now >= id->death) {
			debug("expiring key '%s'", id->comment);
			TAILQ_REMOVE(&idtab->idlist, id, next);
			free_identity(id);
			idtab->nentries--;
		} وگرنه
			deadline = (deadline == 0) ? id->death :
			    MINIMUM(deadline, id->death);
	}
	اگر (deadline == 0 || deadline <= now)
		بازگشت 0;
	وگرنه
		بازگشت (deadline - now);
}

ایستا صحیح
parse_dest_constraint_hop(ساختار sshbuf *b, ساختار dest_constraint_hop *dch)
{
	u_char کلید_is_ca;
	size_t elen = 0, userlen = 0;
	صحیح r;
	ساختار sshkey *k = پوچ;
	نویسه *fp;

	memset(dch, '\0', اندازه(*dch));
	اگر ((r = sshbuf_get_cstring(b, &dch->user, &userlen)) != 0 ||
	    (r = sshbuf_get_cstring(b, &dch->hostname, پوچ)) != 0 ||
	    (r = sshbuf_get_string_direct(b, پوچ, &elen)) != 0) {
		error_fr(r, "parse");
		برو out;
	}
	اگر (elen != 0) {
		error_f("unsupported extensions (len %zu)", elen);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		برو out;
	}
	اگر (*dch->hostname == '\0') {
		آزاد(dch->hostname);
		dch->hostname = پوچ;
	}
	اگر (*dch->user == '\0') {
		آزاد(dch->user);
		dch->user = پوچ;
	} وگرنه اگر (userlen > AGENT_USER_CONSTRAINT_MAX_LEN) {
		error_f("user match pattern too long");
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	وقتی (sshbuf_len(b) != 0) {
		dch->کلیدها = xrecallocarray(dch->کلیدها, dch->nkeys,
		    dch->nkeys + 1, اندازه(*dch->کلیدها));
		dch->کلید_is_ca = xrecallocarray(dch->کلید_is_ca, dch->nkeys,
		    dch->nkeys + 1, اندازه(*dch->کلید_is_ca));
		اگر ((r = sshkey_froms(b, &k)) != 0 ||
		    (r = sshbuf_get_u8(b, &کلید_is_ca)) != 0)
			برو out;
		اگر ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == پوچ)
			fatal_f("fingerprint failed");
		debug3_f("%s%s%s: adding %skey %s %s",
		    dch->user == پوچ ? "" : dch->user,
		    dch->user == پوچ ? "" : "@",
		    dch->hostname, کلید_is_ca ? "CA " : "", sshkey_type(k), fp);
		آزاد(fp);
		dch->کلیدها[dch->nkeys] = k;
		dch->کلید_is_ca[dch->nkeys] = کلید_is_ca != 0;
		dch->nkeys++;
		k = پوچ; /* transferred */
	}
	/* success */
	r = 0;
 out:
	sshkey_free(k);
	بازگشت r;
}

ایستا صحیح
parse_dest_constraint(ساختار sshbuf *m, ساختار dest_constraint *dc)
{
	ساختار sshbuf *b = پوچ, *frombuf = پوچ, *tobuf = پوچ;
	صحیح r;
	size_t elen = 0;

	debug3_f("entering");

	memset(dc, '\0', اندازه(*dc));
	اگر ((r = sshbuf_froms(m, &b)) != 0 ||
	    (r = sshbuf_froms(b, &frombuf)) != 0 ||
	    (r = sshbuf_froms(b, &tobuf)) != 0 ||
	    (r = sshbuf_get_string_direct(b, پوچ, &elen)) != 0) {
		error_fr(r, "parse");
		برو out;
	}
	اگر ((r = parse_dest_constraint_hop(frombuf, &dc->from)) != 0 ||
	    (r = parse_dest_constraint_hop(tobuf, &dc->to)) != 0)
		برو out; /* already logged */
	اگر (elen != 0) {
		error_f("unsupported extensions (len %zu)", elen);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		برو out;
	}
	debug2_f("parsed %s (%u keys) > %s%s%s (%u keys)",
	    dc->from.hostname ? dc->from.hostname : "(ORIGIN)", dc->from.nkeys,
	    dc->to.user ? dc->to.user : "", dc->to.user ? "@" : "",
	    dc->to.hostname ? dc->to.hostname : "(ANY)", dc->to.nkeys);
	/* check consistency */
	اگر ((dc->from.hostname == پوچ) != (dc->from.nkeys == 0) ||
	    dc->from.user != پوچ) {
		error_f("inconsistent \"from\" specification");
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	اگر (dc->to.hostname == پوچ || dc->to.nkeys == 0) {
		error_f("incomplete \"to\" specification");
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	sshbuf_free(frombuf);
	sshbuf_free(tobuf);
	بازگشت r;
}

ایستا صحیح
parse_کلید_constraint_extension(ساختار sshbuf *m, نویسه **sk_providerp,
    ساختار dest_constraint **dcsp, size_t *ndcsp, صحیح *cert_onlyp,
    ساختار sshkey ***certs, size_t *ncerts)
{
	نویسه *ext_name = پوچ;
	صحیح r;
	ساختار sshbuf *b = پوچ;
	u_char v;
	ساختار sshkey *k;

	اگر ((r = sshbuf_get_cstring(m, &ext_name, پوچ)) != 0) {
		error_fr(r, "parse constraint extension");
		برو out;
	}
	debug_f("constraint ext %s", ext_name);
	اگر (strcmp(ext_name, "sk-provider@openssh.com") == 0) {
		اگر (sk_providerp == پوچ) {
			error_f("%s not valid here", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			برو out;
		}
		اگر (*sk_providerp != پوچ) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			برو out;
		}
		اگر ((r = sshbuf_get_cstring(m, sk_providerp, پوچ)) != 0) {
			error_fr(r, "parse %s", ext_name);
			برو out;
		}
	} وگرنه اگر (strcmp(ext_name,
	    "restrict-destination-v00@openssh.com") == 0) {
		اگر (*dcsp != پوچ) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			برو out;
		}
		اگر ((r = sshbuf_froms(m, &b)) != 0) {
			error_fr(r, "parse %s outer", ext_name);
			برو out;
		}
		وقتی (sshbuf_len(b) != 0) {
			اگر (*ndcsp >= AGENT_MAX_DEST_CONSTRAINTS) {
				error_f("too many %s constraints", ext_name);
				r = SSH_ERR_INVALID_FORMAT;
				برو out;
			}
			*dcsp = xrecallocarray(*dcsp, *ndcsp, *ndcsp + 1,
			    اندازه(**dcsp));
			اگر ((r = parse_dest_constraint(b,
			    *dcsp + (*ndcsp)++)) != 0)
				برو out; /* error already logged */
		}
	} وگرنه اگر (strcmp(ext_name,
	    "associated-certs-v00@openssh.com") == 0) {
		اگر (certs == پوچ || ncerts == پوچ || cert_onlyp == پوچ) {
			error_f("%s not valid here", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			برو out;
		}
		اگر (*certs != پوچ) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			برو out;
		}
		اگر ((r = sshbuf_get_u8(m, &v)) != 0 ||
		    (r = sshbuf_froms(m, &b)) != 0) {
			error_fr(r, "parse %s", ext_name);
			برو out;
		}
		*cert_onlyp = v != 0;
		وقتی (sshbuf_len(b) != 0) {
			اگر (*ncerts >= AGENT_MAX_EXT_CERTS) {
				error_f("too many %s constraints", ext_name);
				r = SSH_ERR_INVALID_FORMAT;
				برو out;
			}
			*certs = xrecallocarray(*certs, *ncerts, *ncerts + 1,
			    اندازه(**certs));
			اگر ((r = sshkey_froms(b, &k)) != 0) {
				error_fr(r, "parse key");
				برو out;
			}
			(*certs)[(*ncerts)++] = k;
		}
	} وگرنه {
		error_f("unsupported constraint \"%s\"", ext_name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		برو out;
	}
	/* success */
	r = 0;
 out:
	آزاد(ext_name);
	sshbuf_free(b);
	بازگشت r;
}

ایستا صحیح
parse_کلید_constraints(ساختار sshbuf *m, ساختار sshkey *k, time_t *deathp,
    u_int *secondsp, صحیح *confirmp, نویسه **sk_providerp,
    ساختار dest_constraint **dcsp, size_t *ndcsp,
    صحیح *cert_onlyp, size_t *ncerts, ساختار sshkey ***certs)
{
	u_char ctype;
	صحیح r;
	u_int seconds;

	وقتی (sshbuf_len(m)) {
		اگر ((r = sshbuf_get_u8(m, &ctype)) != 0) {
			error_fr(r, "parse constraint type");
			برو out;
		}
		انتخاب (ctype) {
		حالت SSH_AGENT_CONSTRAIN_LIFETIME:
			اگر (*deathp != 0) {
				error_f("lifetime already set");
				r = SSH_ERR_INVALID_FORMAT;
				برو out;
			}
			اگر ((r = sshbuf_get_u32(m, &seconds)) != 0) {
				error_fr(r, "parse lifetime constraint");
				برو out;
			}
			*deathp = monotime() + seconds;
			*secondsp = seconds;
			بشکن;
		حالت SSH_AGENT_CONSTRAIN_CONFIRM:
			اگر (*confirmp != 0) {
				error_f("confirm already set");
				r = SSH_ERR_INVALID_FORMAT;
				برو out;
			}
			*confirmp = 1;
			بشکن;
		حالت SSH_AGENT_CONSTRAIN_EXTENSION:
			اگر ((r = parse_کلید_constraint_extension(m,
			    sk_providerp, dcsp, ndcsp,
			    cert_onlyp, certs, ncerts)) != 0)
				برو out; /* error already logged */
			بشکن;
		پیشفرض:
			error_f("Unknown constraint %d", ctype);
			r = SSH_ERR_FEATURE_UNSUPPORTED;
			برو out;
		}
	}
	/* success */
	r = 0;
 out:
	بازگشت r;
}

ایستا تهی
process_add_identity(SocketEntry *e)
{
	Identity *id;
	صحیح success = 0, confirm = 0;
	نویسه *fp, *comment = پوچ, *sk_provider = پوچ;
	نویسه canonical_provider[PATH_MAX];
	time_t death = 0;
	u_int seconds = 0;
	ساختار dest_constraint *dest_constraints = پوچ;
	size_t ndest_constraints = 0;
	ساختار sshkey *k = پوچ;
	صحیح r = SSH_ERR_INTERNAL_ERROR;

	debug2_f("entering");
	اگر ((r = sshkey_private_deserialize(e->request, &k)) != 0 ||
	    k == پوچ ||
	    (r = sshbuf_get_cstring(e->request, &comment, پوچ)) != 0) {
		error_fr(r, "parse");
		برو out;
	}
	اگر (parse_کلید_constraints(e->request, k, &death, &seconds, &confirm,
	    &sk_provider, &dest_constraints, &ndest_constraints,
	    پوچ, پوچ, پوچ) != 0) {
		error_f("failed to parse constraints");
		sshbuf_reset(e->request);
		برو out;
	}
	dump_dest_constraints(__func__, dest_constraints, ndest_constraints);

	اگر (sk_provider != پوچ) {
		اگر (!sshkey_is_sk(k)) {
			error("Cannot add provider: %s is not an "
			    "authenticator-hosted key", sshkey_type(k));
			برو out;
		}
		اگر (strcasecmp(sk_provider, "internal") == 0) {
			debug_f("internal provider");
		} وگرنه {
			اگر (socket_is_remote(e) && !remote_add_provider) {
				verbose("failed add of SK provider \"%.100s\": "
				    "remote addition of providers is disabled",
				    sk_provider);
				برو out;
			}
			اگر (realpath(sk_provider, canonical_provider) == پوچ) {
				verbose("failed provider \"%.100s\": "
				    "realpath: %s", sk_provider,
				    strerror(errno));
				برو out;
			}
			آزاد(sk_provider);
			sk_provider = xstrdup(canonical_provider);
			اگر (match_pattern_list(sk_provider,
			    allowed_providers, 0) != 1) {
				error("Refusing add key: "
				    "provider %s not allowed", sk_provider);
				برو out;
			}
		}
	}
	اگر ((r = sshkey_shield_private(k)) != 0) {
		error_fr(r, "shield private");
		برو out;
	}
	اگر (lifetime && !death)
		death = monotime() + lifetime;
	اگر ((id = lookup_identity(k)) == پوچ) {
		id = xcalloc(1, اندازه(Identity));
		TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
		/* Increment the number of identities. */
		idtab->nentries++;
	} وگرنه {
		/* identity not visible, do not update */
		اگر (identity_permitted(id, e, پوچ, پوچ, پوچ) != 0)
			برو out; /* error already logged */
		/* key state might have been updated */
		sshkey_free(id->کلید);
		آزاد(id->comment);
		آزاد(id->sk_provider);
		free_dest_constraints(id->dest_constraints,
		    id->ndest_constraints);
	}
	/* success */
	id->کلید = k;
	id->comment = comment;
	id->death = death;
	id->confirm = confirm;
	id->sk_provider = sk_provider;
	id->dest_constraints = dest_constraints;
	id->ndest_constraints = ndest_constraints;

	اگر ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == پوچ)
		fatal_f("sshkey_fingerprint failed");
	debug_f("add %s %s \"%.100s\" (life: %u) (confirm: %u) "
	    "(provider: %s) (destination constraints: %zu)",
	    sshkey_ssh_name(k), fp, comment, seconds, confirm,
	    sk_provider == پوچ ? "none" : sk_provider, ndest_constraints);
	آزاد(fp);
	/* transferred */
	k = پوچ;
	comment = پوچ;
	sk_provider = پوچ;
	dest_constraints = پوچ;
	ndest_constraints = 0;
	success = 1;
 out:
	آزاد(sk_provider);
	آزاد(comment);
	sshkey_free(k);
	free_dest_constraints(dest_constraints, ndest_constraints);
	send_status(e, success);
}

/* XXX todo: encrypt sensitive data with passphrase */
ایستا تهی
process_lock_agent(SocketEntry *e, صحیح lock)
{
	صحیح r, success = 0, delay;
	نویسه *passwd;
	u_char passwdhash[LOCK_SIZE];
	ایستا u_int fail_شمار = 0;
	size_t pwlen;

	debug2_f("entering");
	/*
	 * This is deliberately fatal: the user has requested that we lock,
	 * but we can't parse their request properly. The only safe thing to
	 * do is abort.
	 */
	اگر ((r = sshbuf_get_cstring(e->request, &passwd, &pwlen)) != 0)
		fatal_fr(r, "parse");
	اگر (pwlen == 0) {
		debug("empty password not supported");
	} وگرنه اگر (locked && !lock) {
		اگر (bcrypt_pbkdf(passwd, pwlen, lock_salt, اندازه(lock_salt),
		    passwdhash, اندازه(passwdhash), LOCK_ROUNDS) < 0)
			fatal("bcrypt_pbkdf");
		اگر (timingsafe_bcmp(passwdhash, lock_pwhash, LOCK_SIZE) == 0) {
			debug("agent unlocked");
			locked = 0;
			fail_شمار = 0;
			explicit_bzero(lock_pwhash, اندازه(lock_pwhash));
			success = 1;
		} وگرنه {
			/* delay in 0.1s increments up to 10s */
			اگر (fail_شمار < 100)
				fail_شمار++;
			delay = 100000 * fail_شمار;
			debug("unlock failed, delaying %0.1lf seconds",
			    (دوگانه)delay/1000000);
			usleep(delay);
		}
		explicit_bzero(passwdhash, اندازه(passwdhash));
	} وگرنه اگر (!locked && lock) {
		debug("agent locked");
		locked = 1;
		arc4random_buf(lock_salt, اندازه(lock_salt));
		اگر (bcrypt_pbkdf(passwd, pwlen, lock_salt, اندازه(lock_salt),
		    lock_pwhash, اندازه(lock_pwhash), LOCK_ROUNDS) < 0)
			fatal("bcrypt_pbkdf");
		success = 1;
	}
	freezero(passwd, pwlen);
	send_status(e, success);
}

ایستا تهی
no_identities(SocketEntry *e)
{
	ساختار sshbuf *پیام;
	صحیح r;

	اگر ((پیام = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_u8(پیام, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
	    (r = sshbuf_put_u32(پیام, 0)) != 0 ||
	    (r = sshbuf_put_stringb(e->output, پیام)) != 0)
		fatal_fr(r, "compose");
	sshbuf_free(پیام);
}

#ifdef ENABLE_PKCS11
/* Add an identity to idlist; takes ownership of 'key' and 'comment' */
ایستا تهی
add_p11_identity(ساختار sshkey *کلید, نویسه *comment, ثابت نویسه *provider,
    time_t death, u_int confirm, ساختار dest_constraint *dest_constraints,
    size_t ndest_constraints)
{
	Identity *id;

	اگر (lookup_identity(کلید) != پوچ) {
		sshkey_free(کلید);
		آزاد(comment);
		بازگشت;
	}
	id = xcalloc(1, اندازه(Identity));
	id->کلید = کلید;
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

ایستا تهی
process_add_smartcard_کلید(SocketEntry *e)
{
	نویسه *provider = پوچ, *pin = پوچ, canonical_provider[PATH_MAX];
	نویسه **comments = پوچ;
	صحیح r, i, شمار = 0, success = 0, confirm = 0;
	u_int seconds = 0;
	time_t death = 0;
	ساختار sshkey **کلیدها = پوچ, *k;
	ساختار dest_constraint *dest_constraints = پوچ;
	size_t j, ndest_constraints = 0, ncerts = 0;
	ساختار sshkey **certs = پوچ;
	صحیح cert_only = 0;

	debug2_f("entering");
	اگر ((r = sshbuf_get_cstring(e->request, &provider, پوچ)) != 0 ||
	    (r = sshbuf_get_cstring(e->request, &pin, پوچ)) != 0) {
		error_fr(r, "parse");
		برو send;
	}
	اگر (parse_کلید_constraints(e->request, پوچ, &death, &seconds, &confirm,
	    پوچ, &dest_constraints, &ndest_constraints, &cert_only,
	    &ncerts, &certs) != 0) {
		error_f("failed to parse constraints");
		برو send;
	}
	dump_dest_constraints(__func__, dest_constraints, ndest_constraints);
	اگر (socket_is_remote(e) && !remote_add_provider) {
		verbose("failed PKCS#11 add of \"%.100s\": remote addition of "
		    "providers is disabled", provider);
		برو send;
	}
	اگر (realpath(provider, canonical_provider) == پوچ) {
		verbose("failed PKCS#11 add of \"%.100s\": realpath: %s",
		    provider, strerror(errno));
		برو send;
	}
	اگر (match_pattern_list(canonical_provider, allowed_providers, 0) != 1) {
		verbose("refusing PKCS#11 add of \"%.100s\": "
		    "provider not allowed", canonical_provider);
		برو send;
	}
	debug_f("add %.100s", canonical_provider);
	اگر (lifetime && !death)
		death = monotime() + lifetime;

	شمار = pkcs11_add_provider(canonical_provider, pin, &کلیدها, &comments);
	برای (i = 0; i < شمار; i++) {
		اگر (comments[i] == پوچ || comments[i][0] == '\0') {
			آزاد(comments[i]);
			comments[i] = xstrdup(canonical_provider);
		}
		برای (j = 0; j < ncerts; j++) {
			اگر (!sshkey_is_cert(certs[j]))
				ادامه;
			اگر (!sshkey_equal_public(کلیدها[i], certs[j]))
				ادامه;
			اگر (pkcs11_make_cert(کلیدها[i], certs[j], &k) != 0)
				ادامه;
			add_p11_identity(k, xstrdup(comments[i]),
			    canonical_provider, death, confirm,
			    dest_constraints, ndest_constraints);
			success = 1;
		}
		اگر (!cert_only && lookup_identity(کلیدها[i]) == پوچ) {
			add_p11_identity(کلیدها[i], comments[i],
			    canonical_provider, death, confirm,
			    dest_constraints, ndest_constraints);
			کلیدها[i] = پوچ;		/* transferred */
			comments[i] = پوچ;	/* transferred */
			success = 1;
		}
		/* XXX update constraints for existing keys */
		sshkey_free(کلیدها[i]);
		آزاد(comments[i]);
	}
send:
	آزاد(pin);
	آزاد(provider);
	آزاد(کلیدها);
	آزاد(comments);
	free_dest_constraints(dest_constraints, ndest_constraints);
	برای (j = 0; j < ncerts; j++)
		sshkey_free(certs[j]);
	آزاد(certs);
	send_status(e, success);
}

ایستا تهی
process_remove_smartcard_کلید(SocketEntry *e)
{
	نویسه *provider = پوچ, *pin = پوچ, canonical_provider[PATH_MAX];
	صحیح r, success = 0;
	Identity *id, *nxt;

	debug2_f("entering");
	اگر ((r = sshbuf_get_cstring(e->request, &provider, پوچ)) != 0 ||
	    (r = sshbuf_get_cstring(e->request, &pin, پوچ)) != 0) {
		error_fr(r, "parse");
		برو send;
	}
	آزاد(pin);

	اگر (realpath(provider, canonical_provider) == پوچ) {
		verbose("failed PKCS#11 add of \"%.100s\": realpath: %s",
		    provider, strerror(errno));
		برو send;
	}

	debug_f("remove %.100s", canonical_provider);
	برای (id = TAILQ_FIRST(&idtab->idlist); id; id = nxt) {
		nxt = TAILQ_NEXT(id, next);
		/* Skip file--based keys */
		اگر (id->provider == پوچ)
			ادامه;
		اگر (!strcmp(canonical_provider, id->provider)) {
			TAILQ_REMOVE(&idtab->idlist, id, next);
			free_identity(id);
			idtab->nentries--;
		}
	}
	اگر (pkcs11_del_provider(canonical_provider) == 0)
		success = 1;
	وگرنه
		error_f("pkcs11_del_provider failed");
send:
	آزاد(provider);
	send_status(e, success);
}
#endif /* ENABLE_PKCS11 */

ایستا صحیح
process_ext_session_bind(SocketEntry *e)
{
	صحیح r, sid_match, کلید_match;
	ساختار sshkey *کلید = پوچ;
	ساختار sshbuf *sid = پوچ, *sig = پوچ;
	نویسه *fp = پوچ;
	size_t i;
	u_char fwd = 0;

	debug2_f("entering");
	e->session_bind_attempted = 1;
	اگر ((r = sshkey_froms(e->request, &کلید)) != 0 ||
	    (r = sshbuf_froms(e->request, &sid)) != 0 ||
	    (r = sshbuf_froms(e->request, &sig)) != 0 ||
	    (r = sshbuf_get_u8(e->request, &fwd)) != 0) {
		error_fr(r, "parse");
		برو out;
	}
	اگر (sshbuf_len(sid) > AGENT_MAX_SID_LEN) {
		error_f("session ID too long");
		برو out;
	}
	اگر ((fp = sshkey_fingerprint(کلید, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == پوچ)
		fatal_f("fingerprint failed");
	/* check signature with hostkey on session ID */
	اگر ((r = sshkey_verify(کلید, sshbuf_ptr(sig), sshbuf_len(sig),
	    sshbuf_ptr(sid), sshbuf_len(sid), پوچ, 0, پوچ)) != 0) {
		error_fr(r, "sshkey_verify for %s %s", sshkey_type(کلید), fp);
		برو out;
	}
	/* check whether sid/key already recorded */
	برای (i = 0; i < e->nsession_ids; i++) {
		اگر (!e->session_ids[i].forwarded) {
			error_f("attempt to bind session ID to socket "
			    "previously bound for authentication attempt");
			r = -1;
			برو out;
		}
		sid_match = buf_equal(sid, e->session_ids[i].sid) == 0;
		کلید_match = sshkey_equal(کلید, e->session_ids[i].کلید);
		اگر (sid_match && کلید_match) {
			debug_f("session ID already recorded for %s %s",
			    sshkey_type(کلید), fp);
			r = 0;
			برو out;
		} وگرنه اگر (sid_match) {
			error_f("session ID recorded against different key "
			    "for %s %s", sshkey_type(کلید), fp);
			r = -1;
			برو out;
		}
		/*
		 * new sid with previously-seen key can happen, e.g. multiple
		 * connections to the same host.
		 */
	}
	/* record new key/sid */
	اگر (e->nsession_ids >= AGENT_MAX_SESSION_IDS) {
		error_f("too many session IDs recorded");
		r = -1;
		برو out;
	}
	e->session_ids = xrecallocarray(e->session_ids, e->nsession_ids,
	    e->nsession_ids + 1, اندازه(*e->session_ids));
	i = e->nsession_ids++;
	debug_f("recorded %s %s (slot %zu of %d)", sshkey_type(کلید), fp, i,
	    AGENT_MAX_SESSION_IDS);
	e->session_ids[i].کلید = کلید;
	e->session_ids[i].forwarded = fwd != 0;
	کلید = پوچ; /* transferred */
	/* can't transfer sid; it's refcounted and scoped to request's life */
	اگر ((e->session_ids[i].sid = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new");
	اگر ((r = sshbuf_putb(e->session_ids[i].sid, sid)) != 0)
		fatal_fr(r, "sshbuf_putb session ID");
	/* success */
	r = 0;
 out:
	آزاد(fp);
	sshkey_free(کلید);
	sshbuf_free(sid);
	sshbuf_free(sig);
	بازگشت r == 0 ? 1 : 0;
}

ایستا صحیح
process_ext_query(SocketEntry *e)
{
	صحیح r;
	ساختار sshbuf *پیام = پوچ;

	debug2_f("entering");
	اگر ((پیام = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshbuf_put_u8(پیام, SSH_AGENT_EXTENSION_RESPONSE)) != 0 ||
	    (r = sshbuf_put_cstring(پیام, "query")) != 0 ||
	    /* string[]     supported extension types */
	    (r = sshbuf_put_cstring(پیام, "session-bind@openssh.com")) != 0)
		fatal_fr(r, "compose");
	اگر ((r = sshbuf_put_stringb(e->output, پیام)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(پیام);
	بازگشت 1;
}

ایستا تهی
process_extension(SocketEntry *e)
{
	صحیح r, replied = 0, success = 0;
	نویسه *name;

	debug2_f("entering");
	اگر ((r = sshbuf_get_cstring(e->request, &name, پوچ)) != 0) {
		error_fr(r, "parse");
		send_status(e, 0);
		بازگشت;
	}

	/*
	 * This function can be called while the agent is locked to allow
	 * session binds to be processed for new channels.
	 * Other operations should be refused when locked.
	 */

	اگر (strcmp(name, "session-bind@openssh.com") == 0) {
		success = process_ext_session_bind(e);
	} وگرنه اگر (locked) {
		debug_f("attempt to use extension \"%s\" while locked", name);
		برو generic_fail;
	} وگرنه اگر (strcmp(name, "query") == 0) {
		replied = success = process_ext_query(e);
	} وگرنه {
		debug_f("unsupported extension \"%s\"", name);
 generic_fail:
		آزاد(name);
		send_status(e, 0);
		بازگشت;
	}
	آزاد(name);
	/* Agent failures are signalled with a different error code */
	اگر (!replied) {
		send_status_generic(e,
		    success ? SSH_AGENT_SUCCESS : SSH_AGENT_EXTENSION_FAILURE);
	}
}

/*
 * dispatch incoming message.
 * returns 1 on success, 0 for incomplete messages or -1 on error.
 */
ایستا صحیح
process_message(u_int socknum)
{
	u_int پیام_len;
	u_char type;
	ثابت u_char *cp;
	صحیح r;
	SocketEntry *e;

	اگر (socknum >= sockets_alloc)
		fatal_f("sock %u >= allocated %u", socknum, sockets_alloc);
	e = &sockets[socknum];

	اگر (sshbuf_len(e->درون_داد) < 5)
		بازگشت 0;		/* Incomplete message header. */
	cp = sshbuf_ptr(e->درون_داد);
	پیام_len = PEEK_U32(cp);
	اگر (پیام_len > AGENT_MAX_LEN) {
		debug_f("socket %u (fd=%d) message too long %u > %u",
		    socknum, e->fd, پیام_len, AGENT_MAX_LEN);
		بازگشت -1;
	}
	اگر (sshbuf_len(e->درون_داد) < پیام_len + 4)
		بازگشت 0;		/* Incomplete message body. */

	/* move the current input to e->request */
	sshbuf_reset(e->request);
	اگر ((r = sshbuf_get_stringb(e->درون_داد, e->request)) != 0 ||
	    (r = sshbuf_get_u8(e->request, &type)) != 0) {
		اگر (r == SSH_ERR_MESSAGE_INCOMPLETE ||
		    r == SSH_ERR_STRING_TOO_LARGE) {
			error_fr(r, "parse");
			بازگشت -1;
		}
		fatal_fr(r, "parse");
	}

	debug_f("socket %u (fd=%d) type %d", socknum, e->fd, type);

	/* check whether agent is locked */
	اگر (locked && type != SSH_AGENTC_UNLOCK) {
		انتخاب (type) {
		حالت SSH2_AGENTC_REQUEST_IDENTITIES:
			/* send empty lists */
			no_identities(e);
			بشکن;
		حالت SSH_AGENTC_EXTENSION:
			process_extension(e);
			بشکن;
		پیشفرض:
			/* send a fail message for all other request types */
			send_status(e, 0);
		}
		sshbuf_reset(e->request);
		بازگشت 1;
	}

	انتخاب (type) {
	حالت SSH_AGENTC_LOCK:
	حالت SSH_AGENTC_UNLOCK:
		process_lock_agent(e, type == SSH_AGENTC_LOCK);
		بشکن;
	حالت SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES:
		process_remove_all_identities(e); /* safe for !WITH_SSH1 */
		بشکن;
	/* ssh2 */
	حالت SSH2_AGENTC_SIGN_REQUEST:
		process_sign_request2(e);
		بشکن;
	حالت SSH2_AGENTC_REQUEST_IDENTITIES:
		process_request_identities(e);
		بشکن;
	حالت SSH2_AGENTC_ADD_IDENTITY:
	حالت SSH2_AGENTC_ADD_ID_CONSTRAINED:
		process_add_identity(e);
		بشکن;
	حالت SSH2_AGENTC_REMOVE_IDENTITY:
		process_remove_identity(e);
		بشکن;
	حالت SSH2_AGENTC_REMOVE_ALL_IDENTITIES:
		process_remove_all_identities(e);
		بشکن;
#ifdef ENABLE_PKCS11
	حالت SSH_AGENTC_ADD_SMARTCARD_کلید:
	حالت SSH_AGENTC_ADD_SMARTCARD_کلید_CONSTRAINED:
		process_add_smartcard_کلید(e);
		بشکن;
	حالت SSH_AGENTC_REMOVE_SMARTCARD_کلید:
		process_remove_smartcard_کلید(e);
		بشکن;
#endif /* ENABLE_PKCS11 */
	حالت SSH_AGENTC_EXTENSION:
		process_extension(e);
		بشکن;
	پیشفرض:
		/* Unknown message.  Respond with failure. */
		error("Unknown message %d", type);
		sshbuf_reset(e->request);
		send_status(e, 0);
		بشکن;
	}
	بازگشت 1;
}

ایستا تهی
new_socket(sock_type type, صحیح fd)
{
	u_int i, old_alloc, new_alloc;

	debug_f("type = %s", type == AUTH_CONNECTION ? "CONNECTION" :
	    (type == AUTH_SOCKET ? "SOCKET" : "UNKNOWN"));
	set_nonblock(fd);

	اگر (fd > max_fd)
		max_fd = fd;

	برای (i = 0; i < sockets_alloc; i++)
		اگر (sockets[i].type == AUTH_UNUSED) {
			sockets[i].fd = fd;
			اگر ((sockets[i].درون_داد = sshbuf_new()) == پوچ ||
			    (sockets[i].output = sshbuf_new()) == پوچ ||
			    (sockets[i].request = sshbuf_new()) == پوچ)
				fatal_f("sshbuf_new failed");
			sockets[i].type = type;
			بازگشت;
		}
	old_alloc = sockets_alloc;
	new_alloc = sockets_alloc + 10;
	sockets = xrecallocarray(sockets, old_alloc, new_alloc,
	    اندازه(sockets[0]));
	برای (i = old_alloc; i < new_alloc; i++)
		sockets[i].type = AUTH_UNUSED;
	sockets_alloc = new_alloc;
	sockets[old_alloc].fd = fd;
	اگر ((sockets[old_alloc].درون_داد = sshbuf_new()) == پوچ ||
	    (sockets[old_alloc].output = sshbuf_new()) == پوچ ||
	    (sockets[old_alloc].request = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	sockets[old_alloc].type = type;
}

ایستا صحیح
handle_socket_read(u_int socknum)
{
	ساختار sockaddr_un sunaddr;
	socklen_t slen;
	uid_t euid;
	gid_t egid;
	صحیح fd;

	slen = اندازه(sunaddr);
	fd = accept(sockets[socknum].fd, (ساختار sockaddr *)&sunaddr, &slen);
	اگر (fd == -1) {
		error("accept from AUTH_SOCKET: %s", strerror(errno));
		بازگشت -1;
	}
	اگر (getpeereid(fd, &euid, &egid) == -1) {
		error("getpeereid %d failed: %s", fd, strerror(errno));
		close(fd);
		بازگشت -1;
	}
	اگر ((euid != 0) && (getuid() != euid)) {
		error("uid mismatch: peer euid %u != uid %u",
		    (u_int) euid, (u_int) getuid());
		close(fd);
		بازگشت -1;
	}
	new_socket(AUTH_CONNECTION, fd);
	بازگشت 0;
}

ایستا صحیح
handle_conn_read(u_int socknum)
{
	نویسه buf[AGENT_RBUF_LEN];
	ssize_t len;
	صحیح r;

	اگر ((len = اقرأ(sockets[socknum].fd, buf, اندازه(buf))) <= 0) {
		اگر (len == -1) {
			اگر (errno == EAGAIN || errno == EINTR)
				بازگشت 0;
			error_f("read error on socket %u (fd %d): %s",
			    socknum, sockets[socknum].fd, strerror(errno));
		}
		بازگشت -1;
	}
	اگر ((r = sshbuf_put(sockets[socknum].درون_داد, buf, len)) != 0)
		fatal_fr(r, "compose");
	explicit_bzero(buf, اندازه(buf));
	برای (;;) {
		اگر ((r = process_message(socknum)) == -1)
			بازگشت -1;
		وگرنه اگر (r == 0)
			بشکن;
	}
	بازگشت 0;
}

ایستا صحیح
handle_conn_write(u_int socknum)
{
	ssize_t len;
	صحیح r;

	اگر (sshbuf_len(sockets[socknum].output) == 0)
		بازگشت 0; /* shouldn't happen */
	اگر ((len = اكتب(sockets[socknum].fd,
	    sshbuf_ptr(sockets[socknum].output),
	    sshbuf_len(sockets[socknum].output))) <= 0) {
		اگر (len == -1) {
			اگر (errno == EAGAIN || errno == EINTR)
				بازگشت 0;
			error_f("read error on socket %u (fd %d): %s",
			    socknum, sockets[socknum].fd, strerror(errno));
		}
		بازگشت -1;
	}
	اگر ((r = sshbuf_consume(sockets[socknum].output, len)) != 0)
		fatal_fr(r, "consume");
	بازگشت 0;
}

ایستا تهی
after_poll(ساختار pollfd *pfd, size_t npfd, u_int maxfds)
{
	size_t i;
	u_int socknum, activefds = npfd;

	برای (i = 0; i < npfd; i++) {
		اگر (pfd[i].revents == 0)
			ادامه;
		/* Find sockets entry */
		برای (socknum = 0; socknum < sockets_alloc; socknum++) {
			اگر (sockets[socknum].type != AUTH_SOCKET &&
			    sockets[socknum].type != AUTH_CONNECTION)
				ادامه;
			اگر (pfd[i].fd == sockets[socknum].fd)
				بشکن;
		}
		اگر (socknum >= sockets_alloc) {
			error_f("no socket for fd %d", pfd[i].fd);
			ادامه;
		}
		/* Process events */
		انتخاب (sockets[socknum].type) {
		حالت AUTH_SOCKET:
			اگر ((pfd[i].revents & (POLLIN|POLLERR)) == 0)
				بشکن;
			اگر (npfd > maxfds) {
				debug3("out of fds (active %u >= limit %u); "
				    "skipping accept", activefds, maxfds);
				بشکن;
			}
			اگر (handle_socket_read(socknum) == 0)
				activefds++;
			بشکن;
		حالت AUTH_CONNECTION:
			اگر ((pfd[i].revents & (POLLIN|POLLHUP|POLLERR)) != 0 &&
			    handle_conn_read(socknum) != 0)
				برو close_sock;
			اگر ((pfd[i].revents & (POLLOUT|POLLHUP)) != 0 &&
			    handle_conn_write(socknum) != 0) {
 close_sock:
				اگر (activefds == 0)
					fatal("activefds == 0 at close_sock");
				close_socket(&sockets[socknum]);
				activefds--;
				بشکن;
			}
			بشکن;
		پیشفرض:
			بشکن;
		}
	}
}

ایستا صحیح
prepare_poll(ساختار pollfd **pfdp, size_t *npfdp, ساختار timespec *timeoutp, u_int maxfds)
{
	ساختار pollfd *pfd = *pfdp;
	size_t i, j, npfd = 0;
	time_t deadline;
	صحیح r;

	/* Count active sockets */
	برای (i = 0; i < sockets_alloc; i++) {
		انتخاب (sockets[i].type) {
		حالت AUTH_SOCKET:
		حالت AUTH_CONNECTION:
			npfd++;
			بشکن;
		حالت AUTH_UNUSED:
			بشکن;
		پیشفرض:
			fatal("Unknown socket type %d", sockets[i].type);
			بشکن;
		}
	}
	اگر (npfd != *npfdp &&
	    (pfd = recallocarray(pfd, *npfdp, npfd, اندازه(*pfd))) == پوچ)
		fatal_f("recallocarray failed");
	*pfdp = pfd;
	*npfdp = npfd;

	برای (i = j = 0; i < sockets_alloc; i++) {
		انتخاب (sockets[i].type) {
		حالت AUTH_SOCKET:
			اگر (npfd > maxfds) {
				debug3("out of fds (active %zu >= limit %u); "
				    "skipping arming listener", npfd, maxfds);
				بشکن;
			}
			pfd[j].fd = sockets[i].fd;
			pfd[j].revents = 0;
			pfd[j].events = POLLIN;
			j++;
			بشکن;
		حالت AUTH_CONNECTION:
			pfd[j].fd = sockets[i].fd;
			pfd[j].revents = 0;
			/*
			 * Only prepare to read if we can handle a full-size
			 * input read buffer and enqueue a max size reply..
			 */
			اگر ((r = sshbuf_check_reserve(sockets[i].درون_داد,
			    AGENT_RBUF_LEN)) == 0 &&
			    (r = sshbuf_check_reserve(sockets[i].output,
			    AGENT_MAX_LEN)) == 0)
				pfd[j].events = POLLIN;
			وگرنه اگر (r != SSH_ERR_NO_BUFFER_SPACE)
				fatal_fr(r, "reserve");
			اگر (sshbuf_len(sockets[i].output) > 0)
				pfd[j].events |= POLLOUT;
			j++;
			بشکن;
		پیشفرض:
			بشکن;
		}
	}
	deadline = reaper();
	اگر (parent_alive_interval != 0)
		deadline = (deadline == 0) ? parent_alive_interval :
		    MINIMUM(deadline, parent_alive_interval);
	اگر (deadline != 0)
		ptimeout_deadline_sec(timeoutp, deadline);
	بازگشت (1);
}

ایستا تهی
cleanup_socket(تهی)
{
	اگر (cleanup_pid != 0 && getpid() != cleanup_pid)
		بازگشت;
	debug_f("cleanup");
	اگر (socket_name != پوچ) {
		agent_listener_cleanup(socket_dirspec, socket_name, socket_dir);
		آزاد(socket_name);
		socket_name = پوچ;
		آزاد(socket_dir);
		socket_dir = پوچ;
	}
}

تهی
cleanup_exit(صحیح i)
{
	cleanup_socket();
#ifdef ENABLE_PKCS11
	pkcs11_terminate();
#endif
	_exit(i);
}

ایستا تهی
cleanup_handler(صحیح sig)
{
	signalled_exit = sig;
}

ایستا تهی
keydrop_handler(صحیح sig)
{
	signalled_keydrop = sig;
}

ایستا تهی
check_parent_exists(تهی)
{
	/*
	 * If our parent has exited then getppid() will return (pid_t)1,
	 * so testing for that should be safe.
	 */
	اگر (parent_pid != -1 && getppid() != parent_pid) {
		/* printf("Parent has died - Authentication agent exiting.\n"); */
		cleanup_socket();
		_exit(2);
	}
}

ایستا تهی
usage(تهی)
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

صحیح
اصلی(صحیح ac, نویسه **av)
{
	صحیح c_flag = 0, d_flag = 0, D_flag = 0, k_flag = 0;
	صحیح s_flag = 0, T_flag = 0, u_flag = 0, U_flag = 0;
	صحیح sock = -1, ch, result, saved_errno;
	pid_t pid;
 	نویسه *homedir = پوچ, *shell, *format, *pidstr, *agentsocket = پوچ;
	نویسه *cp, pidstrbuf[1 + 3 * اندازه pid];
	نویسه *fdstr;
	ثابت نویسه *errstr = پوچ;
	ثابت نویسه *ccp;
#ifdef HAVE_SETRLIMIT
	ساختار rlimit rlim;
#endif
	بیرونی صحیح optind;
	بیرونی نویسه *optarg;
	size_t len;
	mode_t prev_mask;
	ساختار timespec timeout;
	ساختار pollfd *pfd = پوچ;
	size_t npfd = 0;
	u_int maxfds;
	sigset_t nsigset, osigset;
	صحیح socket_activated = 0;
	ساختار passwd *pw;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* drop */
	(تهی)setegid(getgid());
	(تهی)setgid(getgid());

	platform_disable_tracing(0);	/* strict=no */

	اگر ((pw = getpwuid(getuid())) == پوچ)
		fatal("No user exists for uid %lu", (u_long)getuid());
	pw = pwcopy(pw);

#ifdef RLIMIT_NOFILE
	اگر (getrlimit(RLIMIT_NOFILE, &rlim) == -1)
		fatal("%s: getrlimit: %s", __progname, strerror(errno));
#endif

	__progname = ssh_get_progname(av[0]);
	seed_rng();

	وقتی ((ch = getopt(ac, av, "cDdksTuUVA:E:a:O:P:t:")) != -1) {
		انتخاب (ch) {
		حالت 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			اگر (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			بشکن;
		حالت 'c':
			اگر (s_flag)
				usage();
			c_flag++;
			بشکن;
		حالت 'k':
			k_flag++;
			بشکن;
		حالت 'O':
			اگر (strcmp(optarg, "no-restrict-websafe") == 0)
				restrict_websafe = 0;
			وگرنه اگر (strcmp(optarg, "allow-remote-pkcs11") == 0)
				remote_add_provider = 1;
			وگرنه اگر ((ccp = strprefix(optarg,
			    "websafe-allow=", 0)) != پوچ) {
				اگر (websafe_allowlist != پوچ)
					fatal("websafe-allow already set");
				websafe_allowlist = xstrdup(ccp);
			} وگرنه
				fatal("Unknown -O option");
			بشکن;
		حالت 'P':
			اگر (allowed_providers != پوچ)
				fatal("-P option already specified");
			allowed_providers = xstrdup(optarg);
			بشکن;
		حالت 's':
			اگر (c_flag)
				usage();
			s_flag++;
			بشکن;
		حالت 'd':
			اگر (d_flag || D_flag)
				usage();
			d_flag++;
			بشکن;
		حالت 'D':
			اگر (d_flag || D_flag)
				usage();
			D_flag++;
			بشکن;
		حالت 'a':
			agentsocket = optarg;
			بشکن;
		حالت 'A':
			socket_dirspec = xstrdup(optarg);
			بشکن;
		حالت 't':
			اگر ((lifetime = convtime(optarg)) == -1) {
				fprintf(stderr, "Invalid lifetime\n");
				usage();
			}
			بشکن;
		حالت 'T':
			T_flag++;
			بشکن;
		حالت 'u':
			u_flag++;
			بشکن;
		حالت 'U':
			U_flag++;
			بشکن;
		حالت 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_VERSION, SSH_OPENSSL_VERSION);
			exit(0);
		پیشفرض:
			usage();
		}
	}
	ac -= optind;
	av += optind;

	اگر (ac > 0 &&
	    (c_flag || k_flag || s_flag || d_flag || D_flag || u_flag))
		usage();
	/* only one of -a, -A and -T allowed */
	اگر (((socket_dirspec != پوچ) + (agentsocket != پوچ) + T_flag) > 1)
		usage();

	log_init(__progname,
	    d_flag ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
	    SYSLOG_FACILITY_AUTH, 1);

	اگر (allowed_providers == پوچ)
		allowed_providers = xstrdup(DEFAULT_ALLOWED_PROVIDERS);
	اگر (websafe_allowlist == پوچ)
		websafe_allowlist = xstrdup(DEFAULT_WEBSAFE_ALLOWLIST);

	اگر (T_flag)
		socket_dirspec = xstrdup(_PATH_SSH_AGENT_SOCKET_TMPDIR);
	وگرنه اگر (socket_dirspec == پوچ && agentsocket == پوچ)
		socket_dirspec = xstrdup(_PATH_SSH_AGENT_SOCKET_DIR);

	اگر (ac == 0 && !c_flag && !s_flag) {
		shell = getenv("SHELL");
		اگر (shell != پوچ && (len = strlen(shell)) > 2 &&
		    strncmp(shell + len - 3, "csh", 3) == 0)
			c_flag = 1;
	}
	اگر (k_flag) {
		pidstr = getenv(SSH_AGENTPID_ENV_NAME);
		اگر (pidstr == پوچ) {
			fprintf(stderr, "%s not set, cannot kill agent\n",
			    SSH_AGENTPID_ENV_NAME);
			exit(1);
		}
		pid = (صحیح)strtonum(pidstr, 2, INT_MAX, &errstr);
		اگر (errstr) {
			fprintf(stderr,
			    "%s=\"%s\", which is not a good PID: %s\n",
			    SSH_AGENTPID_ENV_NAME, pidstr, errstr);
			exit(1);
		}
		اگر (kill(pid, SIGTERM) == -1) {
			perror("kill");
			exit(1);
		}
		format = c_flag ? "unsetenv %s;\n" : "unset %s;\n";
		printf(format, SSH_AUTHSOCKET_ENV_NAME);
		printf(format, SSH_AGENTPID_ENV_NAME);
		printf("echo Agent pid %ld killed;\n", (long)pid);
		exit(0);
	}
	اگر (u_flag) {
		اگر ((homedir = get_homedir()) == پوچ)
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
	اگر (rlim.rlim_cur < SSH_AGENT_MIN_FDS)
		fatal("%s: file descriptor rlimit %lld too low (minimum %u)",
		    __progname, (long long)rlim.rlim_cur, SSH_AGENT_MIN_FDS);
	maxfds = rlim.rlim_cur - SSH_AGENT_MIN_FDS;

	parent_pid = getpid();

	/* Has the socket been provided via socket activation? */
	اگر (agentsocket == پوچ && ac == 0 && (d_flag || D_flag) &&
	    (pidstr = getenv("LISTEN_PID")) != پوچ &&
	    (fdstr = getenv("LISTEN_FDS")) != پوچ) {
		اگر (strcmp(fdstr, "1") != 0) {
			fatal("unexpected LISTEN_FDS contents "
			    "(want: \"1\" got\"%s\"", fdstr);
		}
		اگر (fcntl(3, F_GETFL) == -1)
			fatal("LISTEN_FDS set but fd 3 unavailable");
		pid = (صحیح)strtonum(pidstr, 1, INT_MAX, &errstr);
		اگر (errstr != پوچ)
			fatal("invalid LISTEN_PID: %s", errstr);
		اگر (pid != getpid())
			fatal("bad LISTEN_PID: %d vs pid %d", pid, getpid());
		debug("using socket activation on fd=3");
		sock = 3;
		socket_activated = 1;
	}

	اگر (sock == -1 && agentsocket == پوچ) {
		/* Listen on a socket in/under a given directory */
		اگر ((homedir = get_homedir()) == پوچ)
			fatal("Couldn't determine home directory");
		اگر (!U_flag) {
			agent_cleanup_stale(socket_dirspec,
			    pw->pw_name, pw->pw_uid, homedir, 0);
		}
		اگر (agent_listener(socket_dirspec, pw->pw_name, pw->pw_uid,
		    homedir, getpid(), "local", &sock, &socket_name,
		    &socket_dir) != 0)
			fatal_f("Couldn't prepare agent socket");
		آزاد(homedir);
	} وگرنه اگر (sock == -1) {
		/* Listen on explicit socket path */
		prev_mask = umask(0177);
		socket_name = xstrdup(agentsocket);
		اگر ((sock = unix_listener(socket_name,
		    SSH_LISTEN_BACKLOG, 0)) < 0) {
			آزاد(socket_name);
			socket_name = پوچ; /* Don't unlink existing file */
			cleanup_exit(1);
		}
		umask(prev_mask);
	}

	closefrom(sock == -1 ? STDERR_FILENO + 1 : sock + 1);

	/*
	 * Create socket early so it will exist before command gets run from
	 * the parent.
	 */
	اگر (sock == -1) {
		prev_mask = umask(0177);
		sock = unix_listener(socket_name, SSH_LISTEN_BACKLOG, 0);
		اگر (sock < 0) {
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
	اگر (D_flag || d_flag) {
		log_init(__progname,
		    d_flag ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
		    SYSLOG_FACILITY_AUTH, 1);
		اگر (socket_name != پوچ) {
			cp = argv_assemble(1, &socket_name);
			format = c_flag ?
			    "setenv %s %s;\n" : "%s=%s; export %s;\n";
			printf(format, SSH_AUTHSOCKET_ENV_NAME, cp,
			    SSH_AUTHSOCKET_ENV_NAME);
			آزاد(cp);
			printf("echo Agent pid %ld;\n", (long)parent_pid);
			fflush(stdout);
		}
		برو skip;
	}
	pid = fork();
	اگر (pid == -1) {
		perror("fork");
		cleanup_exit(1);
	}
	اگر (pid != 0) {		/* Parent - execute the given command. */
		close(sock);
		snprintf(pidstrbuf, اندازه pidstrbuf, "%ld", (long)pid);
		اگر (ac == 0) {
			format = c_flag ? "setenv %s %s;\n" : "%s=%s; export %s;\n";
			cp = argv_assemble(1, &socket_name);
			printf(format, SSH_AUTHSOCKET_ENV_NAME, cp,
			    SSH_AUTHSOCKET_ENV_NAME);
			printf(format, SSH_AGENTPID_ENV_NAME, pidstrbuf,
			    SSH_AGENTPID_ENV_NAME);
			آزاد(cp);
			printf("echo Agent pid %ld;\n", (long)pid);
			exit(0);
		}
		اگر (setenv(SSH_AUTHSOCKET_ENV_NAME, socket_name, 1) == -1 ||
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

	اگر (setsid() == -1) {
		error("setsid: %s", strerror(errno));
		cleanup_exit(1);
	}

	(تهی)chdir("/");
	اگر (stdfd_devnull(1, 1, 1) == -1)
		error_f("stdfd_devnull failed");

#ifdef HAVE_SETRLIMIT
	/* deny core dumps, since memory contains unencrypted private keys */
	rlim.rlim_cur = rlim.rlim_max = 0;
	اگر (setrlimit(RLIMIT_CORE, &rlim) == -1) {
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
	اگر (ac > 0)
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

	اگر (socket_name != پوچ && unveil(socket_name, "c") == -1) {
		fatal("%s: unveil %s %s", __progname, socket_name,
		    strerror(errno));
	}
	اگر (socket_dir != پوچ && unveil(socket_dir, "c") == -1) {
		fatal("%s: unveil %s %s", __progname, socket_dir,
		    strerror(errno));
	}
	اگر (unveil("/", "r") == -1)
		fatal("%s: unveil /: %s", __progname, strerror(errno));
	اگر ((ccp = getenv("SSH_SK_HELPER")) == پوچ || *ccp == '\0')
		ccp = _PATH_SSH_SK_HELPER;
	اگر (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, strerror(errno));
	اگر ((ccp = getenv("SSH_PKCS11_HELPER")) == پوچ || *ccp == '\0')
		ccp = _PATH_SSH_PKCS11_HELPER;
	اگر (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, strerror(errno));
	اگر ((ccp = getenv("SSH_ASKPASS")) == پوچ || *ccp == '\0')
		ccp = _PATH_SSH_ASKPASS_DEFAULT;
	اگر (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, strerror(errno));
	اگر (unveil("/dev/null", "rw") == -1)
		fatal("%s: unveil /dev/null: %s", __progname, strerror(errno));
	اگر (pledge("stdio rpath cpath wpath unix id proc exec", پوچ) == -1)
		fatal("%s: pledge: %s", __progname, strerror(errno));
	platform_pledge_agent();

	وقتی (1) {
		sigprocmask(SIG_BLOCK, &nsigset, &osigset);
		اگر (signalled_exit != 0) {
			logit("exiting on signal %d", (صحیح)signalled_exit);
			cleanup_exit((signalled_exit == SIGTERM &&
			    socket_activated) ? 0 : 2);
		}
		اگر (signalled_keydrop) {
			logit("signal %d received; removing all keys",
			    (صحیح)signalled_keydrop);
			remove_all_identities();
			signalled_keydrop = 0;
		}
		ptimeout_init(&timeout);
		prepare_poll(&pfd, &npfd, &timeout, maxfds);
		result = ppoll(pfd, npfd, ptimeout_get_tsp(&timeout), &osigset);
		sigprocmask(SIG_SETMASK, &osigset, پوچ);
		saved_errno = errno;
		اگر (parent_alive_interval != 0)
			check_parent_exists();
		(تهی) reaper();	/* remove expired keys */
		اگر (result == -1) {
			اگر (saved_errno == EINTR)
				ادامه;
			fatal("poll: %s", strerror(saved_errno));
		} وگرنه اگر (result > 0)
			after_poll(pfd, npfd, maxfds);
	}
	/* NOTREACHED */
}
