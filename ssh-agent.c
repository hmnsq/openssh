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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/time.h>
#અન્તર્ભાવ <sys/queue.h>
#અન્તર્ભાવ <sys/resource.h>
#અન્તર્ભાવ <sys/socket.h>
#અન્તર્ભાવ <sys/stat.h>
#અન્તર્ભાવ <sys/un.h>
#અન્તર્ભાવ <sys/wait.h>

#ifdef WITH_OPENSSL
#અન્તર્ભાવ <openssl/evp.h>
#અન્તર્ભાવ "openbsd-compat/openssl-compat.h"
#endif

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <fcntl.h>
#અન્તર્ભાવ <paths.h>
#અન્તર્ભાવ <poll.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <limits.h>
#અન્તર્ભાવ <time.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <util.h>
#અન્તર્ભાવ <pwd.h>

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "ssh.h"
#અન્તર્ભાવ "ssh2.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "authfd.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "digest.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "match.h"
#અન્તર્ભાવ "msg.h"
#અન્તર્ભાવ "pathnames.h"
#અન્તર્ભાવ "ssh-pkcs11.h"
#અન્તર્ભાવ "sk-api.h"
#અન્તર્ભાવ "myproposal.h"
#અન્તર્ભાવ "version.h"

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

પ્રકારવ્યાખ્યા ગણના {
	AUTH_UNUSED = 0,
	AUTH_SOCKET = 1,
	AUTH_CONNECTION = 2,
} sock_type;

સંરચના hostkey_sid {
	સંરચના sshkey *ચાવી;
	સંરચના sshbuf *sid;
	પૂર્ણાંક forwarded;
};

પ્રકારવ્યાખ્યા સંરચના socket_entry {
	પૂર્ણાંક fd;
	sock_type type;
	સંરચના sshbuf *આગત;
	સંરચના sshbuf *output;
	સંરચના sshbuf *request;
	size_t nsession_ids;
	સંરચના hostkey_sid *session_ids;
	પૂર્ણાંક session_bind_attempted;
} SocketEntry;

u_int sockets_alloc = 0;
SocketEntry *sockets = ખાલી;

પ્રકારવ્યાખ્યા સંરચના identity {
	TAILQ_ENTRY(identity) next;
	સંરચના sshkey *ચાવી;
	અક્ષર *comment;
	અક્ષર *provider;
	time_t death;
	u_int confirm;
	અક્ષર *sk_provider;
	સંરચના dest_constraint *dest_constraints;
	size_t ndest_constraints;
} Identity;

સંરચના idtable {
	પૂર્ણાંક nentries;
	TAILQ_HEAD(idqueue, identity) idlist;
};

/* private key table */
સંરચના idtable *idtab;

પૂર્ણાંક max_fd = 0;

/* pid of shell == parent of agent */
pid_t parent_pid = -1;
time_t parent_alive_interval = 0;

સ્થિર sig_atomic_t signalled_exit;
સ્થિર sig_atomic_t signalled_keydrop;

/* pid of process for which cleanup_socket is applicable */
pid_t cleanup_pid = 0;

/* pathname and directory for AUTH_SOCKET */
સ્થિર અક્ષર *socket_name;
સ્થિર અક્ષર *socket_dir;
સ્થિર અક્ષર *socket_dirspec;

/* Pattern-list of allowed PKCS#11/Security key paths */
સ્થિર અક્ષર *allowed_providers;

/*
 * Allows PKCS11 providers or SK keys that use non-internal providers to
 * be added over a remote connection (identified by session-bind@openssh.com).
 */
સ્થિર પૂર્ણાંક remote_add_provider;

/* locking */
#define LOCK_SIZE	32
#define LOCK_SALT_SIZE	16
#define LOCK_ROUNDS	1
પૂર્ણાંક locked = 0;
u_char lock_pwhash[LOCK_SIZE];
u_char lock_salt[LOCK_SALT_SIZE];

બાહ્ય અક્ષર *__progname;

/* Default lifetime in seconds (0 == forever) */
સ્થિર પૂર્ણાંક lifetime = 0;

સ્થિર પૂર્ણાંક fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* Refuse signing of non-SSH messages for web-origin FIDO keys */
સ્થિર પૂર્ણાંક restrict_websafe = 1;
સ્થિર અક્ષર *websafe_allowlist;

સ્થિર શૂન્ય
close_socket(SocketEntry *e)
{
	size_t i;

	close(e->fd);
	sshbuf_free(e->આગત);
	sshbuf_free(e->output);
	sshbuf_free(e->request);
	માટે (i = 0; i < e->nsession_ids; i++) {
		sshkey_free(e->session_ids[i].ચાવી);
		sshbuf_free(e->session_ids[i].sid);
	}
	મુક્ત(e->session_ids);
	memset(e, '\0', કદ(*e));
	e->fd = -1;
	e->type = AUTH_UNUSED;
}

સ્થિર શૂન્ય
idtab_init(શૂન્ય)
{
	idtab = xcalloc(1, કદ(*idtab));
	TAILQ_INIT(&idtab->idlist);
	idtab->nentries = 0;
}

સ્થિર શૂન્ય
free_dest_constraint_hop(સંરચના dest_constraint_hop *dch)
{
	u_int i;

	જો (dch == ખાલી)
		પાછા;
	મુક્ત(dch->user);
	મુક્ત(dch->hostname);
	માટે (i = 0; i < dch->nkeys; i++)
		sshkey_free(dch->ચાવીઓ[i]);
	મુક્ત(dch->ચાવીઓ);
	મુક્ત(dch->ચાવી_is_ca);
}

સ્થિર શૂન્ય
free_dest_constraints(સંરચના dest_constraint *dcs, size_t ndcs)
{
	size_t i;

	માટે (i = 0; i < ndcs; i++) {
		free_dest_constraint_hop(&dcs[i].from);
		free_dest_constraint_hop(&dcs[i].to);
	}
	મુક્ત(dcs);
}

#ifdef ENABLE_PKCS11
સ્થિર શૂન્ય
dup_dest_constraint_hop(અચલ સંરચના dest_constraint_hop *dch,
    સંરચના dest_constraint_hop *out)
{
	u_int i;
	પૂર્ણાંક r;

	out->user = dch->user == ખાલી ? ખાલી : xstrdup(dch->user);
	out->hostname = dch->hostname == ખાલી ? ખાલી : xstrdup(dch->hostname);
	out->is_ca = dch->is_ca;
	out->nkeys = dch->nkeys;
	out->ચાવીઓ = out->nkeys == 0 ? ખાલી :
	    xcalloc(out->nkeys, કદ(*out->ચાવીઓ));
	out->ચાવી_is_ca = out->nkeys == 0 ? ખાલી :
	    xcalloc(out->nkeys, કદ(*out->ચાવી_is_ca));
	માટે (i = 0; i < dch->nkeys; i++) {
		જો (dch->ચાવીઓ[i] != ખાલી &&
		    (r = sshkey_from_private(dch->ચાવીઓ[i],
		    &(out->ચાવીઓ[i]))) != 0)
			fatal_fr(r, "copy key");
		out->ચાવી_is_ca[i] = dch->ચાવી_is_ca[i];
	}
}

સ્થિર સંરચના dest_constraint *
dup_dest_constraints(અચલ સંરચના dest_constraint *dcs, size_t ndcs)
{
	size_t i;
	સંરચના dest_constraint *ret;

	જો (ndcs == 0)
		પાછા ખાલી;
	ret = xcalloc(ndcs, કદ(*ret));
	માટે (i = 0; i < ndcs; i++) {
		dup_dest_constraint_hop(&dcs[i].from, &ret[i].from);
		dup_dest_constraint_hop(&dcs[i].to, &ret[i].to);
	}
	પાછા ret;
}
#endif /* ENABLE_PKCS11 */

#ifdef DEBUG_CONSTRAINTS
સ્થિર શૂન્ય
dump_dest_constraint_hop(અચલ સંરચના dest_constraint_hop *dch)
{
	u_int i;
	અક્ષર *fp;

	debug_f("user %s hostname %s is_ca %d nkeys %u",
	    dch->user == ખાલી ? "(null)" : dch->user,
	    dch->hostname == ખાલી ? "(null)" : dch->hostname,
	    dch->is_ca, dch->nkeys);
	માટે (i = 0; i < dch->nkeys; i++) {
		fp = ખાલી;
		જો (dch->ચાવીઓ[i] != ખાલી &&
		    (fp = sshkey_fingerprint(dch->ચાવીઓ[i],
		    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == ખાલી)
			fatal_f("fingerprint failed");
		debug_f("key %u/%u: %s%s%s key_is_ca %d", i, dch->nkeys,
		    dch->ચાવીઓ[i] == ખાલી ? "" : sshkey_ssh_name(dch->ચાવીઓ[i]),
		    dch->ચાવીઓ[i] == ખાલી ? "" : " ",
		    dch->ચાવીઓ[i] == ખાલી ? "none" : fp,
		    dch->ચાવી_is_ca[i]);
		મુક્ત(fp);
	}
}
#endif /* DEBUG_CONSTRAINTS */

સ્થિર શૂન્ય
dump_dest_constraints(અચલ અક્ષર *context,
    અચલ સંરચના dest_constraint *dcs, size_t ndcs)
{
#ifdef DEBUG_CONSTRAINTS
	size_t i;

	debug_f("%s: %zu constraints", context, ndcs);
	માટે (i = 0; i < ndcs; i++) {
		debug_f("constraint %zu / %zu: from: ", i, ndcs);
		dump_dest_constraint_hop(&dcs[i].from);
		debug_f("constraint %zu / %zu: to: ", i, ndcs);
		dump_dest_constraint_hop(&dcs[i].to);
	}
	debug_f("done for %s", context);
#endif /* DEBUG_CONSTRAINTS */
}

સ્થિર શૂન્ય
free_identity(Identity *id)
{
	sshkey_free(id->ચાવી);
	મુક્ત(id->provider);
	મુક્ત(id->comment);
	મુક્ત(id->sk_provider);
	free_dest_constraints(id->dest_constraints, id->ndest_constraints);
	મુક્ત(id);
}

/*
 * Match 'key' against the key/CA list in a destination constraint hop
 * Returns 0 on success or -1 otherwise.
 */
સ્થિર પૂર્ણાંક
match_ચાવી_hop(અચલ અક્ષર *tag, અચલ સંરચના sshkey *ચાવી,
    અચલ સંરચના dest_constraint_hop *dch)
{
	અચલ અક્ષર *reason = ખાલી;
	અચલ અક્ષર *hostname = dch->hostname ? dch->hostname : "(ORIGIN)";
	u_int i;
	અક્ષર *fp;

	જો (ચાવી == ખાલી)
		પાછા -1;
	/* XXX logspam */
	જો ((fp = sshkey_fingerprint(ચાવી, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ખાલી)
		fatal_f("fingerprint failed");
	debug3_f("%s: entering hostname %s, requested key %s %s, %u keys avail",
	    tag, hostname, sshkey_type(ચાવી), fp, dch->nkeys);
	મુક્ત(fp);
	માટે (i = 0; i < dch->nkeys; i++) {
		જો (dch->ચાવીઓ[i] == ખાલી)
			પાછા -1;
		/* XXX logspam */
		જો ((fp = sshkey_fingerprint(dch->ચાવીઓ[i], SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ખાલી)
			fatal_f("fingerprint failed");
		debug3_f("%s: key %u: %s%s %s", tag, i,
		    dch->ચાવી_is_ca[i] ? "CA " : "",
		    sshkey_type(dch->ચાવીઓ[i]), fp);
		મુક્ત(fp);
		જો (!sshkey_is_cert(ચાવી)) {
			/* plain key */
			જો (dch->ચાવી_is_ca[i] ||
			    !sshkey_equal(ચાવી, dch->ચાવીઓ[i]))
				ચાલુ;
			પાછા 0;
		}
		/* certificate */
		જો (!dch->ચાવી_is_ca[i])
			ચાલુ;
		જો (ચાવી->cert == ખાલી || ચાવી->cert->signature_ચાવી == ખાલી)
			પાછા -1; /* shouldn't happen */
		જો (!sshkey_equal(ચાવી->cert->signature_ચાવી, dch->ચાવીઓ[i]))
			ચાલુ;
		જો (sshkey_cert_check_host(ચાવી, hostname,
		    SSH_ALLOWED_CA_SIGALGS, &reason) != 0) {
			debug_f("cert %s / hostname %s rejected: %s",
			    ચાવી->cert->ચાવી_id, hostname, reason);
			ચાલુ;
		}
		પાછા 0;
	}
	પાછા -1;
}

/* Check destination constraints on an identity against the hostkey/user */
સ્થિર પૂર્ણાંક
permitted_by_dest_constraints(અચલ સંરચના sshkey *fromkey,
    અચલ સંરચના sshkey *tokey, Identity *id, અચલ અક્ષર *user,
    અચલ અક્ષર **hostnamep)
{
	size_t i;
	સંરચના dest_constraint *d;

	જો (hostnamep != ખાલી)
		*hostnamep = ખાલી;
	માટે (i = 0; i < id->ndest_constraints; i++) {
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
		જો (fromkey == ખાલી) {
			/* We are matching the first hop */
			જો (d->from.hostname != ખાલી || d->from.nkeys != 0)
				ચાલુ;
		} નહીંતર જો (match_ચાવી_hop("from", fromkey, &d->from) != 0)
			ચાલુ;

		/* Match 'to' key */
		જો (tokey != ખાલી && match_ચાવી_hop("to", tokey, &d->to) != 0)
			ચાલુ;

		/* Match user if specified */
		જો (d->to.user != ખાલી && user != ખાલી &&
		    !match_pattern(user, d->to.user))
			ચાલુ;

		/* successfully matched this constraint */
		જો (hostnamep != ખાલી)
			*hostnamep = d->to.hostname;
		debug2_f("allowed for hostname %s",
		    d->to.hostname == ખાલી ? "*" : d->to.hostname);
		પાછા 0;
	}
	/* no match */
	debug2_f("%s identity \"%s\" not permitted for this destination",
	    sshkey_type(id->ચાવી), id->comment);
	પાછા -1;
}

/*
 * Check whether hostkeys on a SocketEntry and the optionally specified user
 * are permitted by the destination constraints on the Identity.
 * Returns 0 on success or -1 otherwise.
 */
સ્થિર પૂર્ણાંક
identity_permitted(Identity *id, SocketEntry *e, અક્ષર *user,
    અચલ અક્ષર **forward_hostnamep, અચલ અક્ષર **last_hostnamep)
{
	size_t i;
	અચલ અક્ષર **hp;
	સંરચના hostkey_sid *hks;
	અચલ સંરચના sshkey *fromkey = ખાલી;
	અચલ અક્ષર *test_user;
	અક્ષર *fp1, *fp2;

	/* XXX remove logspam */
	debug3_f("entering: key %s comment \"%s\", %zu socket bindings, "
	    "%zu constraints", sshkey_type(id->ચાવી), id->comment,
	    e->nsession_ids, id->ndest_constraints);
	જો (id->ndest_constraints == 0)
		પાછા 0; /* unconstrained */
	જો (e->session_bind_attempted && e->nsession_ids == 0) {
		error_f("previous session bind failed on socket");
		પાછા -1;
	}
	જો (e->nsession_ids == 0)
		પાછા 0; /* local use */
	/*
	 * Walk through the hops recorded by session_id and try to find a
	 * constraint that satisfies each.
	 */
	માટે (i = 0; i < e->nsession_ids; i++) {
		hks = e->session_ids + i;
		જો (hks->ચાવી == ખાલી)
			fatal_f("internal error: no bound key");
		/* XXX remove logspam */
		fp1 = fp2 = ખાલી;
		જો (fromkey != ખાલી &&
		    (fp1 = sshkey_fingerprint(fromkey, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ખાલી)
			fatal_f("fingerprint failed");
		જો ((fp2 = sshkey_fingerprint(hks->ચાવી, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ખાલી)
			fatal_f("fingerprint failed");
		debug3_f("socketentry fd=%d, entry %zu %s, "
		    "from hostkey %s %s to user %s hostkey %s %s",
		    e->fd, i, hks->forwarded ? "FORWARD" : "AUTH",
		    fromkey ? sshkey_type(fromkey) : "(ORIGIN)",
		    fromkey ? fp1 : "", user ? user : "(ANY)",
		    sshkey_type(hks->ચાવી), fp2);
		મુક્ત(fp1);
		મુક્ત(fp2);
		/*
		 * Record the hostnames for the initial forwarding and
		 * the final destination.
		 */
		hp = ખાલી;
		જો (i == e->nsession_ids - 1)
			hp = last_hostnamep;
		નહીંતર જો (i == 0)
			hp = forward_hostnamep;
		/* Special handling for final recorded binding */
		test_user = ખાલી;
		જો (i == e->nsession_ids - 1) {
			/* Can only check user at final hop */
			test_user = user;
			/*
			 * user is only presented for signature requests.
			 * If this is the case, make sure last binding is not
			 * for a forwarding.
			 */
			જો (hks->forwarded && user != ખાલી) {
				error_f("tried to sign on forwarding hop");
				પાછા -1;
			}
		} નહીંતર જો (!hks->forwarded) {
			error_f("tried to forward though signing bind");
			પાછા -1;
		}
		જો (permitted_by_dest_constraints(fromkey, hks->ચાવી, id,
		    test_user, hp) != 0)
			પાછા -1;
		fromkey = hks->ચાવી;
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
	જો (hks->forwarded && user == ખાલી &&
	    permitted_by_dest_constraints(hks->ચાવી, ખાલી, id,
	    ખાલી, ખાલી) != 0) {
		debug3_f("key permitted at host but not after");
		પાછા -1;
	}

	/* success */
	પાછા 0;
}

સ્થિર પૂર્ણાંક
socket_is_remote(SocketEntry *e)
{
	પાછા e->session_bind_attempted || (e->nsession_ids != 0);
}

/* return matching private key for given public key */
સ્થિર Identity *
lookup_identity(સંરચના sshkey *ચાવી)
{
	Identity *id;

	TAILQ_FOREACH(id, &idtab->idlist, next) {
		જો (sshkey_equal(ચાવી, id->ચાવી))
			પાછા (id);
	}
	પાછા (ખાલી);
}

/* Check confirmation of keysign request */
સ્થિર પૂર્ણાંક
confirm_ચાવી(Identity *id, અચલ અક્ષર *extra)
{
	અક્ષર *p;
	પૂર્ણાંક ret = -1;

	p = sshkey_fingerprint(id->ચાવી, fingerprint_hash, SSH_FP_DEFAULT);
	જો (p != ખાલી &&
	    ask_permission("Allow use of key %s?\nKey fingerprint %s.%s%s",
	    id->comment, p,
	    extra == ખાલી ? "" : "\n", extra == ખાલી ? "" : extra))
		ret = 0;
	મુક્ત(p);

	પાછા (ret);
}

સ્થિર શૂન્ય
send_status_generic(SocketEntry *e, u_int code)
{
	પૂર્ણાંક r;

	જો ((r = sshbuf_put_u32(e->output, 1)) != 0 ||
	    (r = sshbuf_put_u8(e->output, code)) != 0)
		fatal_fr(r, "compose");
}

સ્થિર શૂન્ય
send_status(SocketEntry *e, પૂર્ણાંક success)
{
	send_status_generic(e,
	    success ? SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE);
}

/* send list of supported public keys to 'client' */
સ્થિર શૂન્ય
process_request_identities(SocketEntry *e)
{
	Identity *id;
	સંરચના sshbuf *સંદેશ, *ચાવીઓ;
	પૂર્ણાંક r;
	u_int i = 0, nentries = 0;
	અક્ષર *fp;

	debug2_f("entering");

	જો ((સંદેશ = sshbuf_new()) == ખાલી || (ચાવીઓ = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	TAILQ_FOREACH(id, &idtab->idlist, next) {
		જો ((fp = sshkey_fingerprint(id->ચાવી, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ખાલી)
			fatal_f("fingerprint failed");
		debug_f("key %u / %u: %s %s", i++, idtab->nentries,
		    sshkey_ssh_name(id->ચાવી), fp);
		dump_dest_constraints(__func__,
		    id->dest_constraints, id->ndest_constraints);
		મુક્ત(fp);
		/* identity not visible, don't include in response */
		જો (identity_permitted(id, e, ખાલી, ખાલી, ખાલી) != 0)
			ચાલુ;
		જો ((r = sshkey_puts(id->ચાવી, ચાવીઓ)) != 0 ||
		    (r = sshbuf_put_cstring(ચાવીઓ, id->comment)) != 0) {
			error_fr(r, "compose key/comment");
			ચાલુ;
		}
		nentries++;
	}
	debug2_f("replying with %u allowed of %u available keys",
	    nentries, idtab->nentries);
	જો ((r = sshbuf_put_u8(સંદેશ, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
	    (r = sshbuf_put_u32(સંદેશ, nentries)) != 0 ||
	    (r = sshbuf_putb(સંદેશ, ચાવીઓ)) != 0)
		fatal_fr(r, "compose");
	જો ((r = sshbuf_put_stringb(e->output, સંદેશ)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(સંદેશ);
	sshbuf_free(ચાવીઓ);
}


સ્થિર અક્ષર *
agent_decode_alg(સંરચના sshkey *ચાવી, u_int flags)
{
	જો (ચાવી->type == ચાવી_RSA) {
		જો (flags & SSH_AGENT_RSA_SHA2_256)
			પાછા "rsa-sha2-256";
		નહીંતર જો (flags & SSH_AGENT_RSA_SHA2_512)
			પાછા "rsa-sha2-512";
	} નહીંતર જો (ચાવી->type == ચાવી_RSA_CERT) {
		જો (flags & SSH_AGENT_RSA_SHA2_256)
			પાછા "rsa-sha2-256-cert-v01@openssh.com";
		નહીંતર જો (flags & SSH_AGENT_RSA_SHA2_512)
			પાછા "rsa-sha2-512-cert-v01@openssh.com";
	}
	પાછા ખાલી;
}

/*
 * Attempt to parse the contents of a buffer as a SSH publickey userauth
 * request, checking its contents for consistency and matching the embedded
 * key against the one that is being used for signing.
 * Note: does not modify msg buffer.
 * Optionally extract the username, session ID and/or hostkey from the request.
 */
સ્થિર પૂર્ણાંક
parse_userauth_request(સંરચના sshbuf *સંદેશ, અચલ સંરચના sshkey *expected_ચાવી,
    અક્ષર **userp, સંરચના sshbuf **sess_idp, સંરચના sshkey **hostkeyp)
{
	સંરચના sshbuf *b = ખાલી, *sess_id = ખાલી;
	અક્ષર *user = ખાલી, *service = ખાલી, *method = ખાલી, *pkalg = ખાલી;
	પૂર્ણાંક r;
	u_char t, sig_follows;
	સંરચના sshkey *mkey = ખાલી, *hostkey = ખાલી;

	જો (userp != ખાલી)
		*userp = ખાલી;
	જો (sess_idp != ખાલી)
		*sess_idp = ખાલી;
	જો (hostkeyp != ખાલી)
		*hostkeyp = ખાલી;
	જો ((b = sshbuf_fromb(સંદેશ)) == ખાલી)
		fatal_f("sshbuf_fromb");

	/* SSH userauth request */
	જો ((r = sshbuf_froms(b, &sess_id)) != 0)
		જાઓ out;
	જો (sshbuf_len(sess_id) == 0) {
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	જો ((r = sshbuf_get_u8(b, &t)) != 0 || /* SSH2_MSG_USERAUTH_REQUEST */
	    (r = sshbuf_get_cstring(b, &user, ખાલી)) != 0 || /* server user */
	    (r = sshbuf_get_cstring(b, &service, ખાલી)) != 0 || /* service */
	    (r = sshbuf_get_cstring(b, &method, ખાલી)) != 0 || /* method */
	    (r = sshbuf_get_u8(b, &sig_follows)) != 0 || /* sig-follows */
	    (r = sshbuf_get_cstring(b, &pkalg, ખાલી)) != 0 || /* alg */
	    (r = sshkey_froms(b, &mkey)) != 0) /*ચાવી*/
		જાઓ out;
	જો (t != SSH2_સંદેશ_USERAUTH_REQUEST ||
	    sig_follows != 1 ||
	    strcmp(service, "ssh-connection") != 0 ||
	    !sshkey_equal(expected_ચાવી, mkey) ||
	    sshkey_type_from_name(pkalg) != expected_ચાવી->type) {
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	જો (strcmp(method, "publickey-hostbound-v00@openssh.com") == 0) {
		જો ((r = sshkey_froms(b, &hostkey)) != 0)
			જાઓ out;
	} નહીંતર જો (strcmp(method, "publickey") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	જો (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	/* success */
	r = 0;
	debug3_f("well formed userauth");
	જો (userp != ખાલી) {
		*userp = user;
		user = ખાલી;
	}
	જો (sess_idp != ખાલી) {
		*sess_idp = sess_id;
		sess_id = ખાલી;
	}
	જો (hostkeyp != ખાલી) {
		*hostkeyp = hostkey;
		hostkey = ખાલી;
	}
 out:
	sshbuf_free(b);
	sshbuf_free(sess_id);
	મુક્ત(user);
	મુક્ત(service);
	મુક્ત(method);
	મુક્ત(pkalg);
	sshkey_free(mkey);
	sshkey_free(hostkey);
	પાછા r;
}

/*
 * Attempt to parse the contents of a buffer as a SSHSIG signature request.
 * Note: does not modify buffer.
 */
સ્થિર પૂર્ણાંક
parse_sshsig_request(સંરચના sshbuf *સંદેશ)
{
	પૂર્ણાંક r;
	સંરચના sshbuf *b;

	જો ((b = sshbuf_fromb(સંદેશ)) == ખાલી)
		fatal_f("sshbuf_fromb");

	જો ((r = sshbuf_cmp(b, 0, "SSHSIG", 6)) != 0 ||
	    (r = sshbuf_consume(b, 6)) != 0 ||
	    (r = sshbuf_get_cstring(b, ખાલી, ખાલી)) != 0 || /* namespace */
	    (r = sshbuf_get_string_direct(b, ખાલી, ખાલી)) != 0 || /* reserved */
	    (r = sshbuf_get_cstring(b, ખાલી, ખાલી)) != 0 || /* hashalg */
	    (r = sshbuf_get_string_direct(b, ખાલી, ખાલી)) != 0) /* H(msg) */
		જાઓ out;
	જો (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	પાછા r;
}

/*
 * This function inspects a message to be signed by a FIDO key that has a
 * web-like application string (i.e. one that does not begin with "ssh:".
 * It checks that the message is one of those expected for SSH operations
 * (pubkey userauth, sshsig, CA key signing) to exclude signing challenges
 * for the web.
 */
સ્થિર પૂર્ણાંક
check_websafe_message_contents(સંરચના sshkey *ચાવી, સંરચના sshbuf *data)
{
	જો (parse_userauth_request(data, ચાવી, ખાલી, ખાલી, ખાલી) == 0) {
		debug_f("signed data matches public key userauth request");
		પાછા 1;
	}
	જો (parse_sshsig_request(data) == 0) {
		debug_f("signed data matches SSHSIG signature request");
		પાછા 1;
	}

	/* XXX check CA signature operation */

	error("web-origin key attempting to sign non-SSH message");
	પાછા 0;
}

સ્થિર પૂર્ણાંક
buf_equal(અચલ સંરચના sshbuf *a, અચલ સંરચના sshbuf *b)
{
	જો (sshbuf_ptr(a) == ખાલી || sshbuf_ptr(b) == ખાલી)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	જો (sshbuf_len(a) != sshbuf_len(b))
		પાછા SSH_ERR_INVALID_FORMAT;
	જો (timingsafe_bcmp(sshbuf_ptr(a), sshbuf_ptr(b), sshbuf_len(a)) != 0)
		પાછા SSH_ERR_INVALID_FORMAT;
	પાછા 0;
}

/* ssh2 only */
સ્થિર શૂન્ય
process_sign_request2(SocketEntry *e)
{
	u_char *signature = ખાલી;
	size_t slen = 0;
	u_int compat = 0, flags;
	પૂર્ણાંક r, ok = -1, retried = 0;
	અક્ષર *fp = ખાલી, *pin = ખાલી, *prompt = ખાલી;
	અક્ષર *user = ખાલી, *sig_dest = ખાલી;
	અચલ અક્ષર *fwd_host = ખાલી, *dest_host = ખાલી;
	સંરચના sshbuf *સંદેશ = ખાલી, *data = ખાલી, *sid = ખાલી;
	સંરચના sshkey *ચાવી = ખાલી, *hostkey = ખાલી;
	સંરચના identity *id;
	સંરચના notifier_ctx *notifier = ખાલી;

	debug_f("entering");

	જો ((સંદેશ = sshbuf_new()) == ખાલી || (data = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = sshkey_froms(e->request, &ચાવી)) != 0 ||
	    (r = sshbuf_get_stringb(e->request, data)) != 0 ||
	    (r = sshbuf_get_u32(e->request, &flags)) != 0) {
		error_fr(r, "parse");
		જાઓ send;
	}

	જો ((id = lookup_identity(ચાવી)) == ખાલી) {
		verbose_f("%s key not found", sshkey_type(ચાવી));
		જાઓ send;
	}
	જો ((fp = sshkey_fingerprint(ચાવી, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ખાલી)
		fatal_f("fingerprint failed");

	જો (id->ndest_constraints != 0) {
		જો (e->nsession_ids == 0) {
			logit_f("refusing use of destination-constrained key "
			    "to sign on unbound connection");
			જાઓ send;
		}
		જો (parse_userauth_request(data, ચાવી, &user, &sid,
		    &hostkey) != 0) {
			logit_f("refusing use of destination-constrained key "
			   "to sign an unidentified signature");
			જાઓ send;
		}
		/* XXX logspam */
		debug_f("user=%s", user);
		જો (identity_permitted(id, e, user, &fwd_host, &dest_host) != 0)
			જાઓ send;
		/* XXX display fwd_host/dest_host in askpass UI */
		/*
		 * Ensure that the session ID is the most recent one
		 * registered on the socket - it should have been bound by
		 * ssh immediately before userauth.
		 */
		જો (buf_equal(sid,
		    e->session_ids[e->nsession_ids - 1].sid) != 0) {
			error_f("unexpected session ID (%zu listed) on "
			    "signature request for target user %s with "
			    "key %s %s", e->nsession_ids, user,
			    sshkey_type(id->ચાવી), fp);
			જાઓ send;
		}
		/*
		 * Ensure that the hostkey embedded in the signature matches
		 * the one most recently bound to the socket. An exception is
		 * made for the initial forwarding hop.
		 */
		જો (e->nsession_ids > 1 && hostkey == ખાલી) {
			error_f("refusing use of destination-constrained key: "
			    "no hostkey recorded in signature for forwarded "
			    "connection");
			જાઓ send;
		}
		જો (hostkey != ખાલી && !sshkey_equal(hostkey,
		    e->session_ids[e->nsession_ids - 1].ચાવી)) {
			error_f("refusing use of destination-constrained key: "
			    "mismatch between hostkey in request and most "
			    "recently bound session");
			જાઓ send;
		}
		xasprintf(&sig_dest, "public key authentication request for "
		    "user \"%s\" to listed host", user);
	}
	જો (id->confirm && confirm_ચાવી(id, sig_dest) != 0) {
		verbose_f("user refused key");
		જાઓ send;
	}
	જો (sshkey_is_sk(id->ચાવી)) {
		જો (restrict_websafe &&
		    match_pattern_list(id->ચાવી->sk_application,
		    websafe_allowlist, 0) != 1 &&
		    !check_websafe_message_contents(ચાવી, data)) {
			/* error already logged */
			જાઓ send;
		}
		જો (id->ચાવી->sk_flags & SSH_SK_USER_PRESENCE_REQD) {
			notifier = notify_start(0,
			    "Confirm user presence for key %s %s%s%s",
			    sshkey_type(id->ચાવી), fp,
			    sig_dest == ખાલી ? "" : "\n",
			    sig_dest == ખાલી ? "" : sig_dest);
		}
	}
 retry_pin:
	જો ((r = sshkey_sign(id->ચાવી, &signature, &slen,
	    sshbuf_ptr(data), sshbuf_len(data), agent_decode_alg(ચાવી, flags),
	    id->sk_provider, pin, compat)) != 0) {
		debug_fr(r, "sshkey_sign");
		જો (pin == ખાલી && !retried && sshkey_is_sk(id->ચાવી) &&
		    r == SSH_ERR_ચાવી_WRONG_PASSPHRASE) {
			notify_complete(notifier, ખાલી);
			notifier = ખાલી;
			/* XXX include sig_dest */
			xasprintf(&prompt, "Enter PIN%sfor %s key %s: ",
			    (id->ચાવી->sk_flags & SSH_SK_USER_PRESENCE_REQD) ?
			    " and confirm user presence " : " ",
			    sshkey_type(id->ચાવી), fp);
			pin = read_passphrase(prompt, RP_USE_ASKPASS);
			retried = 1;
			જાઓ retry_pin;
		}
		error_fr(r, "sshkey_sign");
		જાઓ send;
	}
	/* Success */
	ok = 0;
	debug_f("good signature");
 send:
	notify_complete(notifier, "User presence confirmed");

	જો (ok == 0) {
		જો ((r = sshbuf_put_u8(સંદેશ, SSH2_AGENT_SIGN_RESPONSE)) != 0 ||
		    (r = sshbuf_put_string(સંદેશ, signature, slen)) != 0)
			fatal_fr(r, "compose");
	} નહીંતર જો ((r = sshbuf_put_u8(સંદેશ, SSH_AGENT_FAILURE)) != 0)
		fatal_fr(r, "compose failure");

	જો ((r = sshbuf_put_stringb(e->output, સંદેશ)) != 0)
		fatal_fr(r, "enqueue");

	sshbuf_free(sid);
	sshbuf_free(data);
	sshbuf_free(સંદેશ);
	sshkey_free(ચાવી);
	sshkey_free(hostkey);
	મુક્ત(fp);
	મુક્ત(signature);
	મુક્ત(sig_dest);
	મુક્ત(user);
	મુક્ત(prompt);
	જો (pin != ખાલી)
		freezero(pin, strlen(pin));
}

/* shared */
સ્થિર શૂન્ય
process_remove_identity(SocketEntry *e)
{
	પૂર્ણાંક r, success = 0;
	સંરચના sshkey *ચાવી = ખાલી;
	Identity *id;

	debug2_f("entering");
	જો ((r = sshkey_froms(e->request, &ચાવી)) != 0) {
		error_fr(r, "parse key");
		જાઓ done;
	}
	જો ((id = lookup_identity(ચાવી)) == ખાલી) {
		debug_f("key not found");
		જાઓ done;
	}
	/* identity not visible, cannot be removed */
	જો (identity_permitted(id, e, ખાલી, ખાલી, ખાલી) != 0)
		જાઓ done; /* error already logged */
	/* We have this key, free it. */
	જો (idtab->nentries < 1)
		fatal_f("internal error: nentries %d", idtab->nentries);
	TAILQ_REMOVE(&idtab->idlist, id, next);
	free_identity(id);
	idtab->nentries--;
	success = 1;
 done:
	sshkey_free(ચાવી);
	send_status(e, success);
}

સ્થિર શૂન્ય
remove_all_identities(શૂન્ય)
{
	Identity *id;

	debug2_f("entering");
	/* Loop over all identities and clear the keys. */
	માટે (id = TAILQ_FIRST(&idtab->idlist); id;
	    id = TAILQ_FIRST(&idtab->idlist)) {
		TAILQ_REMOVE(&idtab->idlist, id, next);
		free_identity(id);
	}

	/* Mark that there are no identities. */
	idtab->nentries = 0;
}

સ્થિર શૂન્ય
process_remove_all_identities(SocketEntry *e)
{
	remove_all_identities();

	/* Send success. */
	send_status(e, 1);
}

/* removes expired keys and returns number of seconds until the next expiry */
સ્થિર time_t
reaper(શૂન્ય)
{
	time_t deadline = 0, now = monotime();
	Identity *id, *nxt;

	માટે (id = TAILQ_FIRST(&idtab->idlist); id; id = nxt) {
		nxt = TAILQ_NEXT(id, next);
		જો (id->death == 0)
			ચાલુ;
		જો (now >= id->death) {
			debug("expiring key '%s'", id->comment);
			TAILQ_REMOVE(&idtab->idlist, id, next);
			free_identity(id);
			idtab->nentries--;
		} નહીંતર
			deadline = (deadline == 0) ? id->death :
			    MINIMUM(deadline, id->death);
	}
	જો (deadline == 0 || deadline <= now)
		પાછા 0;
	નહીંતર
		પાછા (deadline - now);
}

સ્થિર પૂર્ણાંક
parse_dest_constraint_hop(સંરચના sshbuf *b, સંરચના dest_constraint_hop *dch)
{
	u_char ચાવી_is_ca;
	size_t elen = 0, userlen = 0;
	પૂર્ણાંક r;
	સંરચના sshkey *k = ખાલી;
	અક્ષર *fp;

	memset(dch, '\0', કદ(*dch));
	જો ((r = sshbuf_get_cstring(b, &dch->user, &userlen)) != 0 ||
	    (r = sshbuf_get_cstring(b, &dch->hostname, ખાલી)) != 0 ||
	    (r = sshbuf_get_string_direct(b, ખાલી, &elen)) != 0) {
		error_fr(r, "parse");
		જાઓ out;
	}
	જો (elen != 0) {
		error_f("unsupported extensions (len %zu)", elen);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		જાઓ out;
	}
	જો (*dch->hostname == '\0') {
		મુક્ત(dch->hostname);
		dch->hostname = ખાલી;
	}
	જો (*dch->user == '\0') {
		મુક્ત(dch->user);
		dch->user = ખાલી;
	} નહીંતર જો (userlen > AGENT_USER_CONSTRAINT_MAX_LEN) {
		error_f("user match pattern too long");
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	જ્યારે (sshbuf_len(b) != 0) {
		dch->ચાવીઓ = xrecallocarray(dch->ચાવીઓ, dch->nkeys,
		    dch->nkeys + 1, કદ(*dch->ચાવીઓ));
		dch->ચાવી_is_ca = xrecallocarray(dch->ચાવી_is_ca, dch->nkeys,
		    dch->nkeys + 1, કદ(*dch->ચાવી_is_ca));
		જો ((r = sshkey_froms(b, &k)) != 0 ||
		    (r = sshbuf_get_u8(b, &ચાવી_is_ca)) != 0)
			જાઓ out;
		જો ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ખાલી)
			fatal_f("fingerprint failed");
		debug3_f("%s%s%s: adding %skey %s %s",
		    dch->user == ખાલી ? "" : dch->user,
		    dch->user == ખાલી ? "" : "@",
		    dch->hostname, ચાવી_is_ca ? "CA " : "", sshkey_type(k), fp);
		મુક્ત(fp);
		dch->ચાવીઓ[dch->nkeys] = k;
		dch->ચાવી_is_ca[dch->nkeys] = ચાવી_is_ca != 0;
		dch->nkeys++;
		k = ખાલી; /* transferred */
	}
	/* success */
	r = 0;
 out:
	sshkey_free(k);
	પાછા r;
}

સ્થિર પૂર્ણાંક
parse_dest_constraint(સંરચના sshbuf *m, સંરચના dest_constraint *dc)
{
	સંરચના sshbuf *b = ખાલી, *frombuf = ખાલી, *tobuf = ખાલી;
	પૂર્ણાંક r;
	size_t elen = 0;

	debug3_f("entering");

	memset(dc, '\0', કદ(*dc));
	જો ((r = sshbuf_froms(m, &b)) != 0 ||
	    (r = sshbuf_froms(b, &frombuf)) != 0 ||
	    (r = sshbuf_froms(b, &tobuf)) != 0 ||
	    (r = sshbuf_get_string_direct(b, ખાલી, &elen)) != 0) {
		error_fr(r, "parse");
		જાઓ out;
	}
	જો ((r = parse_dest_constraint_hop(frombuf, &dc->from)) != 0 ||
	    (r = parse_dest_constraint_hop(tobuf, &dc->to)) != 0)
		જાઓ out; /* already logged */
	જો (elen != 0) {
		error_f("unsupported extensions (len %zu)", elen);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		જાઓ out;
	}
	debug2_f("parsed %s (%u keys) > %s%s%s (%u keys)",
	    dc->from.hostname ? dc->from.hostname : "(ORIGIN)", dc->from.nkeys,
	    dc->to.user ? dc->to.user : "", dc->to.user ? "@" : "",
	    dc->to.hostname ? dc->to.hostname : "(ANY)", dc->to.nkeys);
	/* check consistency */
	જો ((dc->from.hostname == ખાલી) != (dc->from.nkeys == 0) ||
	    dc->from.user != ખાલી) {
		error_f("inconsistent \"from\" specification");
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	જો (dc->to.hostname == ખાલી || dc->to.nkeys == 0) {
		error_f("incomplete \"to\" specification");
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	sshbuf_free(frombuf);
	sshbuf_free(tobuf);
	પાછા r;
}

સ્થિર પૂર્ણાંક
parse_ચાવી_constraint_extension(સંરચના sshbuf *m, અક્ષર **sk_providerp,
    સંરચના dest_constraint **dcsp, size_t *ndcsp, પૂર્ણાંક *cert_onlyp,
    સંરચના sshkey ***certs, size_t *ncerts)
{
	અક્ષર *ext_name = ખાલી;
	પૂર્ણાંક r;
	સંરચના sshbuf *b = ખાલી;
	u_char v;
	સંરચના sshkey *k;

	જો ((r = sshbuf_get_cstring(m, &ext_name, ખાલી)) != 0) {
		error_fr(r, "parse constraint extension");
		જાઓ out;
	}
	debug_f("constraint ext %s", ext_name);
	જો (strcmp(ext_name, "sk-provider@openssh.com") == 0) {
		જો (sk_providerp == ખાલી) {
			error_f("%s not valid here", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			જાઓ out;
		}
		જો (*sk_providerp != ખાલી) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			જાઓ out;
		}
		જો ((r = sshbuf_get_cstring(m, sk_providerp, ખાલી)) != 0) {
			error_fr(r, "parse %s", ext_name);
			જાઓ out;
		}
	} નહીંતર જો (strcmp(ext_name,
	    "restrict-destination-v00@openssh.com") == 0) {
		જો (*dcsp != ખાલી) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			જાઓ out;
		}
		જો ((r = sshbuf_froms(m, &b)) != 0) {
			error_fr(r, "parse %s outer", ext_name);
			જાઓ out;
		}
		જ્યારે (sshbuf_len(b) != 0) {
			જો (*ndcsp >= AGENT_MAX_DEST_CONSTRAINTS) {
				error_f("too many %s constraints", ext_name);
				r = SSH_ERR_INVALID_FORMAT;
				જાઓ out;
			}
			*dcsp = xrecallocarray(*dcsp, *ndcsp, *ndcsp + 1,
			    કદ(**dcsp));
			જો ((r = parse_dest_constraint(b,
			    *dcsp + (*ndcsp)++)) != 0)
				જાઓ out; /* error already logged */
		}
	} નહીંતર જો (strcmp(ext_name,
	    "associated-certs-v00@openssh.com") == 0) {
		જો (certs == ખાલી || ncerts == ખાલી || cert_onlyp == ખાલી) {
			error_f("%s not valid here", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			જાઓ out;
		}
		જો (*certs != ખાલી) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			જાઓ out;
		}
		જો ((r = sshbuf_get_u8(m, &v)) != 0 ||
		    (r = sshbuf_froms(m, &b)) != 0) {
			error_fr(r, "parse %s", ext_name);
			જાઓ out;
		}
		*cert_onlyp = v != 0;
		જ્યારે (sshbuf_len(b) != 0) {
			જો (*ncerts >= AGENT_MAX_EXT_CERTS) {
				error_f("too many %s constraints", ext_name);
				r = SSH_ERR_INVALID_FORMAT;
				જાઓ out;
			}
			*certs = xrecallocarray(*certs, *ncerts, *ncerts + 1,
			    કદ(**certs));
			જો ((r = sshkey_froms(b, &k)) != 0) {
				error_fr(r, "parse key");
				જાઓ out;
			}
			(*certs)[(*ncerts)++] = k;
		}
	} નહીંતર {
		error_f("unsupported constraint \"%s\"", ext_name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		જાઓ out;
	}
	/* success */
	r = 0;
 out:
	મુક્ત(ext_name);
	sshbuf_free(b);
	પાછા r;
}

સ્થિર પૂર્ણાંક
parse_ચાવી_constraints(સંરચના sshbuf *m, સંરચના sshkey *k, time_t *deathp,
    u_int *secondsp, પૂર્ણાંક *confirmp, અક્ષર **sk_providerp,
    સંરચના dest_constraint **dcsp, size_t *ndcsp,
    પૂર્ણાંક *cert_onlyp, size_t *ncerts, સંરચના sshkey ***certs)
{
	u_char ctype;
	પૂર્ણાંક r;
	u_int seconds;

	જ્યારે (sshbuf_len(m)) {
		જો ((r = sshbuf_get_u8(m, &ctype)) != 0) {
			error_fr(r, "parse constraint type");
			જાઓ out;
		}
		પસંદગી (ctype) {
		સ્થિતિ SSH_AGENT_CONSTRAIN_LIFETIME:
			જો (*deathp != 0) {
				error_f("lifetime already set");
				r = SSH_ERR_INVALID_FORMAT;
				જાઓ out;
			}
			જો ((r = sshbuf_get_u32(m, &seconds)) != 0) {
				error_fr(r, "parse lifetime constraint");
				જાઓ out;
			}
			*deathp = monotime() + seconds;
			*secondsp = seconds;
			તોડો;
		સ્થિતિ SSH_AGENT_CONSTRAIN_CONFIRM:
			જો (*confirmp != 0) {
				error_f("confirm already set");
				r = SSH_ERR_INVALID_FORMAT;
				જાઓ out;
			}
			*confirmp = 1;
			તોડો;
		સ્થિતિ SSH_AGENT_CONSTRAIN_EXTENSION:
			જો ((r = parse_ચાવી_constraint_extension(m,
			    sk_providerp, dcsp, ndcsp,
			    cert_onlyp, certs, ncerts)) != 0)
				જાઓ out; /* error already logged */
			તોડો;
		મૂળભૂત:
			error_f("Unknown constraint %d", ctype);
			r = SSH_ERR_FEATURE_UNSUPPORTED;
			જાઓ out;
		}
	}
	/* success */
	r = 0;
 out:
	પાછા r;
}

સ્થિર શૂન્ય
process_add_identity(SocketEntry *e)
{
	Identity *id;
	પૂર્ણાંક success = 0, confirm = 0;
	અક્ષર *fp, *comment = ખાલી, *sk_provider = ખાલી;
	અક્ષર canonical_provider[PATH_MAX];
	time_t death = 0;
	u_int seconds = 0;
	સંરચના dest_constraint *dest_constraints = ખાલી;
	size_t ndest_constraints = 0;
	સંરચના sshkey *k = ખાલી;
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;

	debug2_f("entering");
	જો ((r = sshkey_private_deserialize(e->request, &k)) != 0 ||
	    k == ખાલી ||
	    (r = sshbuf_get_cstring(e->request, &comment, ખાલી)) != 0) {
		error_fr(r, "parse");
		જાઓ out;
	}
	જો (parse_ચાવી_constraints(e->request, k, &death, &seconds, &confirm,
	    &sk_provider, &dest_constraints, &ndest_constraints,
	    ખાલી, ખાલી, ખાલી) != 0) {
		error_f("failed to parse constraints");
		sshbuf_reset(e->request);
		જાઓ out;
	}
	dump_dest_constraints(__func__, dest_constraints, ndest_constraints);

	જો (sk_provider != ખાલી) {
		જો (!sshkey_is_sk(k)) {
			error("Cannot add provider: %s is not an "
			    "authenticator-hosted key", sshkey_type(k));
			જાઓ out;
		}
		જો (strcasecmp(sk_provider, "internal") == 0) {
			debug_f("internal provider");
		} નહીંતર {
			જો (socket_is_remote(e) && !remote_add_provider) {
				verbose("failed add of SK provider \"%.100s\": "
				    "remote addition of providers is disabled",
				    sk_provider);
				જાઓ out;
			}
			જો (realpath(sk_provider, canonical_provider) == ખાલી) {
				verbose("failed provider \"%.100s\": "
				    "realpath: %s", sk_provider,
				    strerror(errno));
				જાઓ out;
			}
			મુક્ત(sk_provider);
			sk_provider = xstrdup(canonical_provider);
			જો (match_pattern_list(sk_provider,
			    allowed_providers, 0) != 1) {
				error("Refusing add key: "
				    "provider %s not allowed", sk_provider);
				જાઓ out;
			}
		}
	}
	જો ((r = sshkey_shield_private(k)) != 0) {
		error_fr(r, "shield private");
		જાઓ out;
	}
	જો (lifetime && !death)
		death = monotime() + lifetime;
	જો ((id = lookup_identity(k)) == ખાલી) {
		id = xcalloc(1, કદ(Identity));
		TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
		/* Increment the number of identities. */
		idtab->nentries++;
	} નહીંતર {
		/* identity not visible, do not update */
		જો (identity_permitted(id, e, ખાલી, ખાલી, ખાલી) != 0)
			જાઓ out; /* error already logged */
		/* key state might have been updated */
		sshkey_free(id->ચાવી);
		મુક્ત(id->comment);
		મુક્ત(id->sk_provider);
		free_dest_constraints(id->dest_constraints,
		    id->ndest_constraints);
	}
	/* success */
	id->ચાવી = k;
	id->comment = comment;
	id->death = death;
	id->confirm = confirm;
	id->sk_provider = sk_provider;
	id->dest_constraints = dest_constraints;
	id->ndest_constraints = ndest_constraints;

	જો ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ખાલી)
		fatal_f("sshkey_fingerprint failed");
	debug_f("add %s %s \"%.100s\" (life: %u) (confirm: %u) "
	    "(provider: %s) (destination constraints: %zu)",
	    sshkey_ssh_name(k), fp, comment, seconds, confirm,
	    sk_provider == ખાલી ? "none" : sk_provider, ndest_constraints);
	મુક્ત(fp);
	/* transferred */
	k = ખાલી;
	comment = ખાલી;
	sk_provider = ખાલી;
	dest_constraints = ખાલી;
	ndest_constraints = 0;
	success = 1;
 out:
	મુક્ત(sk_provider);
	મુક્ત(comment);
	sshkey_free(k);
	free_dest_constraints(dest_constraints, ndest_constraints);
	send_status(e, success);
}

/* XXX todo: encrypt sensitive data with passphrase */
સ્થિર શૂન્ય
process_lock_agent(SocketEntry *e, પૂર્ણાંક lock)
{
	પૂર્ણાંક r, success = 0, delay;
	અક્ષર *passwd;
	u_char passwdhash[LOCK_SIZE];
	સ્થિર u_int fail_ગણતરી = 0;
	size_t pwlen;

	debug2_f("entering");
	/*
	 * This is deliberately fatal: the user has requested that we lock,
	 * but we can't parse their request properly. The only safe thing to
	 * do is abort.
	 */
	જો ((r = sshbuf_get_cstring(e->request, &passwd, &pwlen)) != 0)
		fatal_fr(r, "parse");
	જો (pwlen == 0) {
		debug("empty password not supported");
	} નહીંતર જો (locked && !lock) {
		જો (bcrypt_pbkdf(passwd, pwlen, lock_salt, કદ(lock_salt),
		    passwdhash, કદ(passwdhash), LOCK_ROUNDS) < 0)
			fatal("bcrypt_pbkdf");
		જો (timingsafe_bcmp(passwdhash, lock_pwhash, LOCK_SIZE) == 0) {
			debug("agent unlocked");
			locked = 0;
			fail_ગણતરી = 0;
			explicit_bzero(lock_pwhash, કદ(lock_pwhash));
			success = 1;
		} નહીંતર {
			/* delay in 0.1s increments up to 10s */
			જો (fail_ગણતરી < 100)
				fail_ગણતરી++;
			delay = 100000 * fail_ગણતરી;
			debug("unlock failed, delaying %0.1lf seconds",
			    (દ્વિગુણ)delay/1000000);
			usleep(delay);
		}
		explicit_bzero(passwdhash, કદ(passwdhash));
	} નહીંતર જો (!locked && lock) {
		debug("agent locked");
		locked = 1;
		arc4random_buf(lock_salt, કદ(lock_salt));
		જો (bcrypt_pbkdf(passwd, pwlen, lock_salt, કદ(lock_salt),
		    lock_pwhash, કદ(lock_pwhash), LOCK_ROUNDS) < 0)
			fatal("bcrypt_pbkdf");
		success = 1;
	}
	freezero(passwd, pwlen);
	send_status(e, success);
}

સ્થિર શૂન્ય
no_identities(SocketEntry *e)
{
	સંરચના sshbuf *સંદેશ;
	પૂર્ણાંક r;

	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = sshbuf_put_u8(સંદેશ, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
	    (r = sshbuf_put_u32(સંદેશ, 0)) != 0 ||
	    (r = sshbuf_put_stringb(e->output, સંદેશ)) != 0)
		fatal_fr(r, "compose");
	sshbuf_free(સંદેશ);
}

#ifdef ENABLE_PKCS11
/* Add an identity to idlist; takes ownership of 'key' and 'comment' */
સ્થિર શૂન્ય
add_p11_identity(સંરચના sshkey *ચાવી, અક્ષર *comment, અચલ અક્ષર *provider,
    time_t death, u_int confirm, સંરચના dest_constraint *dest_constraints,
    size_t ndest_constraints)
{
	Identity *id;

	જો (lookup_identity(ચાવી) != ખાલી) {
		sshkey_free(ચાવી);
		મુક્ત(comment);
		પાછા;
	}
	id = xcalloc(1, કદ(Identity));
	id->ચાવી = ચાવી;
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

સ્થિર શૂન્ય
process_add_smartcard_ચાવી(SocketEntry *e)
{
	અક્ષર *provider = ખાલી, *pin = ખાલી, canonical_provider[PATH_MAX];
	અક્ષર **comments = ખાલી;
	પૂર્ણાંક r, i, ગણતરી = 0, success = 0, confirm = 0;
	u_int seconds = 0;
	time_t death = 0;
	સંરચના sshkey **ચાવીઓ = ખાલી, *k;
	સંરચના dest_constraint *dest_constraints = ખાલી;
	size_t j, ndest_constraints = 0, ncerts = 0;
	સંરચના sshkey **certs = ખાલી;
	પૂર્ણાંક cert_only = 0;

	debug2_f("entering");
	જો ((r = sshbuf_get_cstring(e->request, &provider, ખાલી)) != 0 ||
	    (r = sshbuf_get_cstring(e->request, &pin, ખાલી)) != 0) {
		error_fr(r, "parse");
		જાઓ send;
	}
	જો (parse_ચાવી_constraints(e->request, ખાલી, &death, &seconds, &confirm,
	    ખાલી, &dest_constraints, &ndest_constraints, &cert_only,
	    &ncerts, &certs) != 0) {
		error_f("failed to parse constraints");
		જાઓ send;
	}
	dump_dest_constraints(__func__, dest_constraints, ndest_constraints);
	જો (socket_is_remote(e) && !remote_add_provider) {
		verbose("failed PKCS#11 add of \"%.100s\": remote addition of "
		    "providers is disabled", provider);
		જાઓ send;
	}
	જો (realpath(provider, canonical_provider) == ખાલી) {
		verbose("failed PKCS#11 add of \"%.100s\": realpath: %s",
		    provider, strerror(errno));
		જાઓ send;
	}
	જો (match_pattern_list(canonical_provider, allowed_providers, 0) != 1) {
		verbose("refusing PKCS#11 add of \"%.100s\": "
		    "provider not allowed", canonical_provider);
		જાઓ send;
	}
	debug_f("add %.100s", canonical_provider);
	જો (lifetime && !death)
		death = monotime() + lifetime;

	ગણતરી = pkcs11_add_provider(canonical_provider, pin, &ચાવીઓ, &comments);
	માટે (i = 0; i < ગણતરી; i++) {
		જો (comments[i] == ખાલી || comments[i][0] == '\0') {
			મુક્ત(comments[i]);
			comments[i] = xstrdup(canonical_provider);
		}
		માટે (j = 0; j < ncerts; j++) {
			જો (!sshkey_is_cert(certs[j]))
				ચાલુ;
			જો (!sshkey_equal_public(ચાવીઓ[i], certs[j]))
				ચાલુ;
			જો (pkcs11_make_cert(ચાવીઓ[i], certs[j], &k) != 0)
				ચાલુ;
			add_p11_identity(k, xstrdup(comments[i]),
			    canonical_provider, death, confirm,
			    dest_constraints, ndest_constraints);
			success = 1;
		}
		જો (!cert_only && lookup_identity(ચાવીઓ[i]) == ખાલી) {
			add_p11_identity(ચાવીઓ[i], comments[i],
			    canonical_provider, death, confirm,
			    dest_constraints, ndest_constraints);
			ચાવીઓ[i] = ખાલી;		/* transferred */
			comments[i] = ખાલી;	/* transferred */
			success = 1;
		}
		/* XXX update constraints for existing keys */
		sshkey_free(ચાવીઓ[i]);
		મુક્ત(comments[i]);
	}
send:
	મુક્ત(pin);
	મુક્ત(provider);
	મુક્ત(ચાવીઓ);
	મુક્ત(comments);
	free_dest_constraints(dest_constraints, ndest_constraints);
	માટે (j = 0; j < ncerts; j++)
		sshkey_free(certs[j]);
	મુક્ત(certs);
	send_status(e, success);
}

સ્થિર શૂન્ય
process_remove_smartcard_ચાવી(SocketEntry *e)
{
	અક્ષર *provider = ખાલી, *pin = ખાલી, canonical_provider[PATH_MAX];
	પૂર્ણાંક r, success = 0;
	Identity *id, *nxt;

	debug2_f("entering");
	જો ((r = sshbuf_get_cstring(e->request, &provider, ખાલી)) != 0 ||
	    (r = sshbuf_get_cstring(e->request, &pin, ખાલી)) != 0) {
		error_fr(r, "parse");
		જાઓ send;
	}
	મુક્ત(pin);

	જો (realpath(provider, canonical_provider) == ખાલી) {
		verbose("failed PKCS#11 add of \"%.100s\": realpath: %s",
		    provider, strerror(errno));
		જાઓ send;
	}

	debug_f("remove %.100s", canonical_provider);
	માટે (id = TAILQ_FIRST(&idtab->idlist); id; id = nxt) {
		nxt = TAILQ_NEXT(id, next);
		/* Skip file--based keys */
		જો (id->provider == ખાલી)
			ચાલુ;
		જો (!strcmp(canonical_provider, id->provider)) {
			TAILQ_REMOVE(&idtab->idlist, id, next);
			free_identity(id);
			idtab->nentries--;
		}
	}
	જો (pkcs11_del_provider(canonical_provider) == 0)
		success = 1;
	નહીંતર
		error_f("pkcs11_del_provider failed");
send:
	મુક્ત(provider);
	send_status(e, success);
}
#endif /* ENABLE_PKCS11 */

સ્થિર પૂર્ણાંક
process_ext_session_bind(SocketEntry *e)
{
	પૂર્ણાંક r, sid_match, ચાવી_match;
	સંરચના sshkey *ચાવી = ખાલી;
	સંરચના sshbuf *sid = ખાલી, *sig = ખાલી;
	અક્ષર *fp = ખાલી;
	size_t i;
	u_char fwd = 0;

	debug2_f("entering");
	e->session_bind_attempted = 1;
	જો ((r = sshkey_froms(e->request, &ચાવી)) != 0 ||
	    (r = sshbuf_froms(e->request, &sid)) != 0 ||
	    (r = sshbuf_froms(e->request, &sig)) != 0 ||
	    (r = sshbuf_get_u8(e->request, &fwd)) != 0) {
		error_fr(r, "parse");
		જાઓ out;
	}
	જો (sshbuf_len(sid) > AGENT_MAX_SID_LEN) {
		error_f("session ID too long");
		જાઓ out;
	}
	જો ((fp = sshkey_fingerprint(ચાવી, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ખાલી)
		fatal_f("fingerprint failed");
	/* check signature with hostkey on session ID */
	જો ((r = sshkey_verify(ચાવી, sshbuf_ptr(sig), sshbuf_len(sig),
	    sshbuf_ptr(sid), sshbuf_len(sid), ખાલી, 0, ખાલી)) != 0) {
		error_fr(r, "sshkey_verify for %s %s", sshkey_type(ચાવી), fp);
		જાઓ out;
	}
	/* check whether sid/key already recorded */
	માટે (i = 0; i < e->nsession_ids; i++) {
		જો (!e->session_ids[i].forwarded) {
			error_f("attempt to bind session ID to socket "
			    "previously bound for authentication attempt");
			r = -1;
			જાઓ out;
		}
		sid_match = buf_equal(sid, e->session_ids[i].sid) == 0;
		ચાવી_match = sshkey_equal(ચાવી, e->session_ids[i].ચાવી);
		જો (sid_match && ચાવી_match) {
			debug_f("session ID already recorded for %s %s",
			    sshkey_type(ચાવી), fp);
			r = 0;
			જાઓ out;
		} નહીંતર જો (sid_match) {
			error_f("session ID recorded against different key "
			    "for %s %s", sshkey_type(ચાવી), fp);
			r = -1;
			જાઓ out;
		}
		/*
		 * new sid with previously-seen key can happen, e.g. multiple
		 * connections to the same host.
		 */
	}
	/* record new key/sid */
	જો (e->nsession_ids >= AGENT_MAX_SESSION_IDS) {
		error_f("too many session IDs recorded");
		r = -1;
		જાઓ out;
	}
	e->session_ids = xrecallocarray(e->session_ids, e->nsession_ids,
	    e->nsession_ids + 1, કદ(*e->session_ids));
	i = e->nsession_ids++;
	debug_f("recorded %s %s (slot %zu of %d)", sshkey_type(ચાવી), fp, i,
	    AGENT_MAX_SESSION_IDS);
	e->session_ids[i].ચાવી = ચાવી;
	e->session_ids[i].forwarded = fwd != 0;
	ચાવી = ખાલી; /* transferred */
	/* can't transfer sid; it's refcounted and scoped to request's life */
	જો ((e->session_ids[i].sid = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new");
	જો ((r = sshbuf_putb(e->session_ids[i].sid, sid)) != 0)
		fatal_fr(r, "sshbuf_putb session ID");
	/* success */
	r = 0;
 out:
	મુક્ત(fp);
	sshkey_free(ચાવી);
	sshbuf_free(sid);
	sshbuf_free(sig);
	પાછા r == 0 ? 1 : 0;
}

સ્થિર પૂર્ણાંક
process_ext_query(SocketEntry *e)
{
	પૂર્ણાંક r;
	સંરચના sshbuf *સંદેશ = ખાલી;

	debug2_f("entering");
	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = sshbuf_put_u8(સંદેશ, SSH_AGENT_EXTENSION_RESPONSE)) != 0 ||
	    (r = sshbuf_put_cstring(સંદેશ, "query")) != 0 ||
	    /* string[]     supported extension types */
	    (r = sshbuf_put_cstring(સંદેશ, "session-bind@openssh.com")) != 0)
		fatal_fr(r, "compose");
	જો ((r = sshbuf_put_stringb(e->output, સંદેશ)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(સંદેશ);
	પાછા 1;
}

સ્થિર શૂન્ય
process_extension(SocketEntry *e)
{
	પૂર્ણાંક r, replied = 0, success = 0;
	અક્ષર *name;

	debug2_f("entering");
	જો ((r = sshbuf_get_cstring(e->request, &name, ખાલી)) != 0) {
		error_fr(r, "parse");
		send_status(e, 0);
		પાછા;
	}

	/*
	 * This function can be called while the agent is locked to allow
	 * session binds to be processed for new channels.
	 * Other operations should be refused when locked.
	 */

	જો (strcmp(name, "session-bind@openssh.com") == 0) {
		success = process_ext_session_bind(e);
	} નહીંતર જો (locked) {
		debug_f("attempt to use extension \"%s\" while locked", name);
		જાઓ generic_fail;
	} નહીંતર જો (strcmp(name, "query") == 0) {
		replied = success = process_ext_query(e);
	} નહીંતર {
		debug_f("unsupported extension \"%s\"", name);
 generic_fail:
		મુક્ત(name);
		send_status(e, 0);
		પાછા;
	}
	મુક્ત(name);
	/* Agent failures are signalled with a different error code */
	જો (!replied) {
		send_status_generic(e,
		    success ? SSH_AGENT_SUCCESS : SSH_AGENT_EXTENSION_FAILURE);
	}
}

/*
 * dispatch incoming message.
 * returns 1 on success, 0 for incomplete messages or -1 on error.
 */
સ્થિર પૂર્ણાંક
process_message(u_int socknum)
{
	u_int સંદેશ_len;
	u_char type;
	અચલ u_char *cp;
	પૂર્ણાંક r;
	SocketEntry *e;

	જો (socknum >= sockets_alloc)
		fatal_f("sock %u >= allocated %u", socknum, sockets_alloc);
	e = &sockets[socknum];

	જો (sshbuf_len(e->આગત) < 5)
		પાછા 0;		/* Incomplete message header. */
	cp = sshbuf_ptr(e->આગત);
	સંદેશ_len = PEEK_U32(cp);
	જો (સંદેશ_len > AGENT_MAX_LEN) {
		debug_f("socket %u (fd=%d) message too long %u > %u",
		    socknum, e->fd, સંદેશ_len, AGENT_MAX_LEN);
		પાછા -1;
	}
	જો (sshbuf_len(e->આગત) < સંદેશ_len + 4)
		પાછા 0;		/* Incomplete message body. */

	/* move the current input to e->request */
	sshbuf_reset(e->request);
	જો ((r = sshbuf_get_stringb(e->આગત, e->request)) != 0 ||
	    (r = sshbuf_get_u8(e->request, &type)) != 0) {
		જો (r == SSH_ERR_MESSAGE_INCOMPLETE ||
		    r == SSH_ERR_STRING_TOO_LARGE) {
			error_fr(r, "parse");
			પાછા -1;
		}
		fatal_fr(r, "parse");
	}

	debug_f("socket %u (fd=%d) type %d", socknum, e->fd, type);

	/* check whether agent is locked */
	જો (locked && type != SSH_AGENTC_UNLOCK) {
		પસંદગી (type) {
		સ્થિતિ SSH2_AGENTC_REQUEST_IDENTITIES:
			/* send empty lists */
			no_identities(e);
			તોડો;
		સ્થિતિ SSH_AGENTC_EXTENSION:
			process_extension(e);
			તોડો;
		મૂળભૂત:
			/* send a fail message for all other request types */
			send_status(e, 0);
		}
		sshbuf_reset(e->request);
		પાછા 1;
	}

	પસંદગી (type) {
	સ્થિતિ SSH_AGENTC_LOCK:
	સ્થિતિ SSH_AGENTC_UNLOCK:
		process_lock_agent(e, type == SSH_AGENTC_LOCK);
		તોડો;
	સ્થિતિ SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES:
		process_remove_all_identities(e); /* safe for !WITH_SSH1 */
		તોડો;
	/* ssh2 */
	સ્થિતિ SSH2_AGENTC_SIGN_REQUEST:
		process_sign_request2(e);
		તોડો;
	સ્થિતિ SSH2_AGENTC_REQUEST_IDENTITIES:
		process_request_identities(e);
		તોડો;
	સ્થિતિ SSH2_AGENTC_ADD_IDENTITY:
	સ્થિતિ SSH2_AGENTC_ADD_ID_CONSTRAINED:
		process_add_identity(e);
		તોડો;
	સ્થિતિ SSH2_AGENTC_REMOVE_IDENTITY:
		process_remove_identity(e);
		તોડો;
	સ્થિતિ SSH2_AGENTC_REMOVE_ALL_IDENTITIES:
		process_remove_all_identities(e);
		તોડો;
#ifdef ENABLE_PKCS11
	સ્થિતિ SSH_AGENTC_ADD_SMARTCARD_ચાવી:
	સ્થિતિ SSH_AGENTC_ADD_SMARTCARD_ચાવી_CONSTRAINED:
		process_add_smartcard_ચાવી(e);
		તોડો;
	સ્થિતિ SSH_AGENTC_REMOVE_SMARTCARD_ચાવી:
		process_remove_smartcard_ચાવી(e);
		તોડો;
#endif /* ENABLE_PKCS11 */
	સ્થિતિ SSH_AGENTC_EXTENSION:
		process_extension(e);
		તોડો;
	મૂળભૂત:
		/* Unknown message.  Respond with failure. */
		error("Unknown message %d", type);
		sshbuf_reset(e->request);
		send_status(e, 0);
		તોડો;
	}
	પાછા 1;
}

સ્થિર શૂન્ય
new_socket(sock_type type, પૂર્ણાંક fd)
{
	u_int i, old_alloc, new_alloc;

	debug_f("type = %s", type == AUTH_CONNECTION ? "CONNECTION" :
	    (type == AUTH_SOCKET ? "SOCKET" : "UNKNOWN"));
	set_nonblock(fd);

	જો (fd > max_fd)
		max_fd = fd;

	માટે (i = 0; i < sockets_alloc; i++)
		જો (sockets[i].type == AUTH_UNUSED) {
			sockets[i].fd = fd;
			જો ((sockets[i].આગત = sshbuf_new()) == ખાલી ||
			    (sockets[i].output = sshbuf_new()) == ખાલી ||
			    (sockets[i].request = sshbuf_new()) == ખાલી)
				fatal_f("sshbuf_new failed");
			sockets[i].type = type;
			પાછા;
		}
	old_alloc = sockets_alloc;
	new_alloc = sockets_alloc + 10;
	sockets = xrecallocarray(sockets, old_alloc, new_alloc,
	    કદ(sockets[0]));
	માટે (i = old_alloc; i < new_alloc; i++)
		sockets[i].type = AUTH_UNUSED;
	sockets_alloc = new_alloc;
	sockets[old_alloc].fd = fd;
	જો ((sockets[old_alloc].આગત = sshbuf_new()) == ખાલી ||
	    (sockets[old_alloc].output = sshbuf_new()) == ખાલી ||
	    (sockets[old_alloc].request = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	sockets[old_alloc].type = type;
}

સ્થિર પૂર્ણાંક
handle_socket_read(u_int socknum)
{
	સંરચના sockaddr_un sunaddr;
	socklen_t slen;
	uid_t euid;
	gid_t egid;
	પૂર્ણાંક fd;

	slen = કદ(sunaddr);
	fd = accept(sockets[socknum].fd, (સંરચના sockaddr *)&sunaddr, &slen);
	જો (fd == -1) {
		error("accept from AUTH_SOCKET: %s", strerror(errno));
		પાછા -1;
	}
	જો (getpeereid(fd, &euid, &egid) == -1) {
		error("getpeereid %d failed: %s", fd, strerror(errno));
		close(fd);
		પાછા -1;
	}
	જો ((euid != 0) && (getuid() != euid)) {
		error("uid mismatch: peer euid %u != uid %u",
		    (u_int) euid, (u_int) getuid());
		close(fd);
		પાછા -1;
	}
	new_socket(AUTH_CONNECTION, fd);
	પાછા 0;
}

સ્થિર પૂર્ણાંક
handle_conn_read(u_int socknum)
{
	અક્ષર buf[AGENT_RBUF_LEN];
	ssize_t len;
	પૂર્ણાંક r;

	જો ((len = પઠ(sockets[socknum].fd, buf, કદ(buf))) <= 0) {
		જો (len == -1) {
			જો (errno == EAGAIN || errno == EINTR)
				પાછા 0;
			error_f("read error on socket %u (fd %d): %s",
			    socknum, sockets[socknum].fd, strerror(errno));
		}
		પાછા -1;
	}
	જો ((r = sshbuf_put(sockets[socknum].આગત, buf, len)) != 0)
		fatal_fr(r, "compose");
	explicit_bzero(buf, કદ(buf));
	માટે (;;) {
		જો ((r = process_message(socknum)) == -1)
			પાછા -1;
		નહીંતર જો (r == 0)
			તોડો;
	}
	પાછા 0;
}

સ્થિર પૂર્ણાંક
handle_conn_write(u_int socknum)
{
	ssize_t len;
	પૂર્ણાંક r;

	જો (sshbuf_len(sockets[socknum].output) == 0)
		પાછા 0; /* shouldn't happen */
	જો ((len = લિખ(sockets[socknum].fd,
	    sshbuf_ptr(sockets[socknum].output),
	    sshbuf_len(sockets[socknum].output))) <= 0) {
		જો (len == -1) {
			જો (errno == EAGAIN || errno == EINTR)
				પાછા 0;
			error_f("read error on socket %u (fd %d): %s",
			    socknum, sockets[socknum].fd, strerror(errno));
		}
		પાછા -1;
	}
	જો ((r = sshbuf_consume(sockets[socknum].output, len)) != 0)
		fatal_fr(r, "consume");
	પાછા 0;
}

સ્થિર શૂન્ય
after_poll(સંરચના pollfd *pfd, size_t npfd, u_int maxfds)
{
	size_t i;
	u_int socknum, activefds = npfd;

	માટે (i = 0; i < npfd; i++) {
		જો (pfd[i].revents == 0)
			ચાલુ;
		/* Find sockets entry */
		માટે (socknum = 0; socknum < sockets_alloc; socknum++) {
			જો (sockets[socknum].type != AUTH_SOCKET &&
			    sockets[socknum].type != AUTH_CONNECTION)
				ચાલુ;
			જો (pfd[i].fd == sockets[socknum].fd)
				તોડો;
		}
		જો (socknum >= sockets_alloc) {
			error_f("no socket for fd %d", pfd[i].fd);
			ચાલુ;
		}
		/* Process events */
		પસંદગી (sockets[socknum].type) {
		સ્થિતિ AUTH_SOCKET:
			જો ((pfd[i].revents & (POLLIN|POLLERR)) == 0)
				તોડો;
			જો (npfd > maxfds) {
				debug3("out of fds (active %u >= limit %u); "
				    "skipping accept", activefds, maxfds);
				તોડો;
			}
			જો (handle_socket_read(socknum) == 0)
				activefds++;
			તોડો;
		સ્થિતિ AUTH_CONNECTION:
			જો ((pfd[i].revents & (POLLIN|POLLHUP|POLLERR)) != 0 &&
			    handle_conn_read(socknum) != 0)
				જાઓ close_sock;
			જો ((pfd[i].revents & (POLLOUT|POLLHUP)) != 0 &&
			    handle_conn_write(socknum) != 0) {
 close_sock:
				જો (activefds == 0)
					fatal("activefds == 0 at close_sock");
				close_socket(&sockets[socknum]);
				activefds--;
				તોડો;
			}
			તોડો;
		મૂળભૂત:
			તોડો;
		}
	}
}

સ્થિર પૂર્ણાંક
prepare_poll(સંરચના pollfd **pfdp, size_t *npfdp, સંરચના timespec *timeoutp, u_int maxfds)
{
	સંરચના pollfd *pfd = *pfdp;
	size_t i, j, npfd = 0;
	time_t deadline;
	પૂર્ણાંક r;

	/* Count active sockets */
	માટે (i = 0; i < sockets_alloc; i++) {
		પસંદગી (sockets[i].type) {
		સ્થિતિ AUTH_SOCKET:
		સ્થિતિ AUTH_CONNECTION:
			npfd++;
			તોડો;
		સ્થિતિ AUTH_UNUSED:
			તોડો;
		મૂળભૂત:
			fatal("Unknown socket type %d", sockets[i].type);
			તોડો;
		}
	}
	જો (npfd != *npfdp &&
	    (pfd = recallocarray(pfd, *npfdp, npfd, કદ(*pfd))) == ખાલી)
		fatal_f("recallocarray failed");
	*pfdp = pfd;
	*npfdp = npfd;

	માટે (i = j = 0; i < sockets_alloc; i++) {
		પસંદગી (sockets[i].type) {
		સ્થિતિ AUTH_SOCKET:
			જો (npfd > maxfds) {
				debug3("out of fds (active %zu >= limit %u); "
				    "skipping arming listener", npfd, maxfds);
				તોડો;
			}
			pfd[j].fd = sockets[i].fd;
			pfd[j].revents = 0;
			pfd[j].events = POLLIN;
			j++;
			તોડો;
		સ્થિતિ AUTH_CONNECTION:
			pfd[j].fd = sockets[i].fd;
			pfd[j].revents = 0;
			/*
			 * Only prepare to read if we can handle a full-size
			 * input read buffer and enqueue a max size reply..
			 */
			જો ((r = sshbuf_check_reserve(sockets[i].આગત,
			    AGENT_RBUF_LEN)) == 0 &&
			    (r = sshbuf_check_reserve(sockets[i].output,
			    AGENT_MAX_LEN)) == 0)
				pfd[j].events = POLLIN;
			નહીંતર જો (r != SSH_ERR_NO_BUFFER_SPACE)
				fatal_fr(r, "reserve");
			જો (sshbuf_len(sockets[i].output) > 0)
				pfd[j].events |= POLLOUT;
			j++;
			તોડો;
		મૂળભૂત:
			તોડો;
		}
	}
	deadline = reaper();
	જો (parent_alive_interval != 0)
		deadline = (deadline == 0) ? parent_alive_interval :
		    MINIMUM(deadline, parent_alive_interval);
	જો (deadline != 0)
		ptimeout_deadline_sec(timeoutp, deadline);
	પાછા (1);
}

સ્થિર શૂન્ય
cleanup_socket(શૂન્ય)
{
	જો (cleanup_pid != 0 && getpid() != cleanup_pid)
		પાછા;
	debug_f("cleanup");
	જો (socket_name != ખાલી) {
		agent_listener_cleanup(socket_dirspec, socket_name, socket_dir);
		મુક્ત(socket_name);
		socket_name = ખાલી;
		મુક્ત(socket_dir);
		socket_dir = ખાલી;
	}
}

શૂન્ય
cleanup_exit(પૂર્ણાંક i)
{
	cleanup_socket();
#ifdef ENABLE_PKCS11
	pkcs11_terminate();
#endif
	_exit(i);
}

સ્થિર શૂન્ય
cleanup_handler(પૂર્ણાંક sig)
{
	signalled_exit = sig;
}

સ્થિર શૂન્ય
keydrop_handler(પૂર્ણાંક sig)
{
	signalled_keydrop = sig;
}

સ્થિર શૂન્ય
check_parent_exists(શૂન્ય)
{
	/*
	 * If our parent has exited then getppid() will return (pid_t)1,
	 * so testing for that should be safe.
	 */
	જો (parent_pid != -1 && getppid() != parent_pid) {
		/* printf("Parent has died - Authentication agent exiting.\n"); */
		cleanup_socket();
		_exit(2);
	}
}

સ્થિર શૂન્ય
usage(શૂન્ય)
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

પૂર્ણાંક
મુખ્ય(પૂર્ણાંક ac, અક્ષર **av)
{
	પૂર્ણાંક c_flag = 0, d_flag = 0, D_flag = 0, k_flag = 0;
	પૂર્ણાંક s_flag = 0, T_flag = 0, u_flag = 0, U_flag = 0;
	પૂર્ણાંક sock = -1, ch, result, saved_errno;
	pid_t pid;
 	અક્ષર *homedir = ખાલી, *shell, *format, *pidstr, *agentsocket = ખાલી;
	અક્ષર *cp, pidstrbuf[1 + 3 * કદ pid];
	અક્ષર *fdstr;
	અચલ અક્ષર *errstr = ખાલી;
	અચલ અક્ષર *ccp;
#ifdef HAVE_SETRLIMIT
	સંરચના rlimit rlim;
#endif
	બાહ્ય પૂર્ણાંક optind;
	બાહ્ય અક્ષર *optarg;
	size_t len;
	mode_t prev_mask;
	સંરચના timespec timeout;
	સંરચના pollfd *pfd = ખાલી;
	size_t npfd = 0;
	u_int maxfds;
	sigset_t nsigset, osigset;
	પૂર્ણાંક socket_activated = 0;
	સંરચના passwd *pw;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* drop */
	(શૂન્ય)setegid(getgid());
	(શૂન્ય)setgid(getgid());

	platform_disable_tracing(0);	/* strict=no */

	જો ((pw = getpwuid(getuid())) == ખાલી)
		fatal("No user exists for uid %lu", (u_long)getuid());
	pw = pwcopy(pw);

#ifdef RLIMIT_NOFILE
	જો (getrlimit(RLIMIT_NOFILE, &rlim) == -1)
		fatal("%s: getrlimit: %s", __progname, strerror(errno));
#endif

	__progname = ssh_get_progname(av[0]);
	seed_rng();

	જ્યારે ((ch = getopt(ac, av, "cDdksTuUVA:E:a:O:P:t:")) != -1) {
		પસંદગી (ch) {
		સ્થિતિ 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			જો (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			તોડો;
		સ્થિતિ 'c':
			જો (s_flag)
				usage();
			c_flag++;
			તોડો;
		સ્થિતિ 'k':
			k_flag++;
			તોડો;
		સ્થિતિ 'O':
			જો (strcmp(optarg, "no-restrict-websafe") == 0)
				restrict_websafe = 0;
			નહીંતર જો (strcmp(optarg, "allow-remote-pkcs11") == 0)
				remote_add_provider = 1;
			નહીંતર જો ((ccp = strprefix(optarg,
			    "websafe-allow=", 0)) != ખાલી) {
				જો (websafe_allowlist != ખાલી)
					fatal("websafe-allow already set");
				websafe_allowlist = xstrdup(ccp);
			} નહીંતર
				fatal("Unknown -O option");
			તોડો;
		સ્થિતિ 'P':
			જો (allowed_providers != ખાલી)
				fatal("-P option already specified");
			allowed_providers = xstrdup(optarg);
			તોડો;
		સ્થિતિ 's':
			જો (c_flag)
				usage();
			s_flag++;
			તોડો;
		સ્થિતિ 'd':
			જો (d_flag || D_flag)
				usage();
			d_flag++;
			તોડો;
		સ્થિતિ 'D':
			જો (d_flag || D_flag)
				usage();
			D_flag++;
			તોડો;
		સ્થિતિ 'a':
			agentsocket = optarg;
			તોડો;
		સ્થિતિ 'A':
			socket_dirspec = xstrdup(optarg);
			તોડો;
		સ્થિતિ 't':
			જો ((lifetime = convtime(optarg)) == -1) {
				fprintf(stderr, "Invalid lifetime\n");
				usage();
			}
			તોડો;
		સ્થિતિ 'T':
			T_flag++;
			તોડો;
		સ્થિતિ 'u':
			u_flag++;
			તોડો;
		સ્થિતિ 'U':
			U_flag++;
			તોડો;
		સ્થિતિ 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_VERSION, SSH_OPENSSL_VERSION);
			exit(0);
		મૂળભૂત:
			usage();
		}
	}
	ac -= optind;
	av += optind;

	જો (ac > 0 &&
	    (c_flag || k_flag || s_flag || d_flag || D_flag || u_flag))
		usage();
	/* only one of -a, -A and -T allowed */
	જો (((socket_dirspec != ખાલી) + (agentsocket != ખાલી) + T_flag) > 1)
		usage();

	log_init(__progname,
	    d_flag ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
	    SYSLOG_FACILITY_AUTH, 1);

	જો (allowed_providers == ખાલી)
		allowed_providers = xstrdup(DEFAULT_ALLOWED_PROVIDERS);
	જો (websafe_allowlist == ખાલી)
		websafe_allowlist = xstrdup(DEFAULT_WEBSAFE_ALLOWLIST);

	જો (T_flag)
		socket_dirspec = xstrdup(_PATH_SSH_AGENT_SOCKET_TMPDIR);
	નહીંતર જો (socket_dirspec == ખાલી && agentsocket == ખાલી)
		socket_dirspec = xstrdup(_PATH_SSH_AGENT_SOCKET_DIR);

	જો (ac == 0 && !c_flag && !s_flag) {
		shell = getenv("SHELL");
		જો (shell != ખાલી && (len = strlen(shell)) > 2 &&
		    strncmp(shell + len - 3, "csh", 3) == 0)
			c_flag = 1;
	}
	જો (k_flag) {
		pidstr = getenv(SSH_AGENTPID_ENV_NAME);
		જો (pidstr == ખાલી) {
			fprintf(stderr, "%s not set, cannot kill agent\n",
			    SSH_AGENTPID_ENV_NAME);
			exit(1);
		}
		pid = (પૂર્ણાંક)strtonum(pidstr, 2, INT_MAX, &errstr);
		જો (errstr) {
			fprintf(stderr,
			    "%s=\"%s\", which is not a good PID: %s\n",
			    SSH_AGENTPID_ENV_NAME, pidstr, errstr);
			exit(1);
		}
		જો (kill(pid, SIGTERM) == -1) {
			perror("kill");
			exit(1);
		}
		format = c_flag ? "unsetenv %s;\n" : "unset %s;\n";
		printf(format, SSH_AUTHSOCKET_ENV_NAME);
		printf(format, SSH_AGENTPID_ENV_NAME);
		printf("echo Agent pid %ld killed;\n", (long)pid);
		exit(0);
	}
	જો (u_flag) {
		જો ((homedir = get_homedir()) == ખાલી)
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
	જો (rlim.rlim_cur < SSH_AGENT_MIN_FDS)
		fatal("%s: file descriptor rlimit %lld too low (minimum %u)",
		    __progname, (long long)rlim.rlim_cur, SSH_AGENT_MIN_FDS);
	maxfds = rlim.rlim_cur - SSH_AGENT_MIN_FDS;

	parent_pid = getpid();

	/* Has the socket been provided via socket activation? */
	જો (agentsocket == ખાલી && ac == 0 && (d_flag || D_flag) &&
	    (pidstr = getenv("LISTEN_PID")) != ખાલી &&
	    (fdstr = getenv("LISTEN_FDS")) != ખાલી) {
		જો (strcmp(fdstr, "1") != 0) {
			fatal("unexpected LISTEN_FDS contents "
			    "(want: \"1\" got\"%s\"", fdstr);
		}
		જો (fcntl(3, F_GETFL) == -1)
			fatal("LISTEN_FDS set but fd 3 unavailable");
		pid = (પૂર્ણાંક)strtonum(pidstr, 1, INT_MAX, &errstr);
		જો (errstr != ખાલી)
			fatal("invalid LISTEN_PID: %s", errstr);
		જો (pid != getpid())
			fatal("bad LISTEN_PID: %d vs pid %d", pid, getpid());
		debug("using socket activation on fd=3");
		sock = 3;
		socket_activated = 1;
	}

	જો (sock == -1 && agentsocket == ખાલી) {
		/* Listen on a socket in/under a given directory */
		જો ((homedir = get_homedir()) == ખાલી)
			fatal("Couldn't determine home directory");
		જો (!U_flag) {
			agent_cleanup_stale(socket_dirspec,
			    pw->pw_name, pw->pw_uid, homedir, 0);
		}
		જો (agent_listener(socket_dirspec, pw->pw_name, pw->pw_uid,
		    homedir, getpid(), "local", &sock, &socket_name,
		    &socket_dir) != 0)
			fatal_f("Couldn't prepare agent socket");
		મુક્ત(homedir);
	} નહીંતર જો (sock == -1) {
		/* Listen on explicit socket path */
		prev_mask = umask(0177);
		socket_name = xstrdup(agentsocket);
		જો ((sock = unix_listener(socket_name,
		    SSH_LISTEN_BACKLOG, 0)) < 0) {
			મુક્ત(socket_name);
			socket_name = ખાલી; /* Don't unlink existing file */
			cleanup_exit(1);
		}
		umask(prev_mask);
	}

	closefrom(sock == -1 ? STDERR_FILENO + 1 : sock + 1);

	/*
	 * Create socket early so it will exist before command gets run from
	 * the parent.
	 */
	જો (sock == -1) {
		prev_mask = umask(0177);
		sock = unix_listener(socket_name, SSH_LISTEN_BACKLOG, 0);
		જો (sock < 0) {
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
	જો (D_flag || d_flag) {
		log_init(__progname,
		    d_flag ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
		    SYSLOG_FACILITY_AUTH, 1);
		જો (socket_name != ખાલી) {
			cp = argv_assemble(1, &socket_name);
			format = c_flag ?
			    "setenv %s %s;\n" : "%s=%s; export %s;\n";
			printf(format, SSH_AUTHSOCKET_ENV_NAME, cp,
			    SSH_AUTHSOCKET_ENV_NAME);
			મુક્ત(cp);
			printf("echo Agent pid %ld;\n", (long)parent_pid);
			fflush(stdout);
		}
		જાઓ skip;
	}
	pid = fork();
	જો (pid == -1) {
		perror("fork");
		cleanup_exit(1);
	}
	જો (pid != 0) {		/* Parent - execute the given command. */
		close(sock);
		snprintf(pidstrbuf, કદ pidstrbuf, "%ld", (long)pid);
		જો (ac == 0) {
			format = c_flag ? "setenv %s %s;\n" : "%s=%s; export %s;\n";
			cp = argv_assemble(1, &socket_name);
			printf(format, SSH_AUTHSOCKET_ENV_NAME, cp,
			    SSH_AUTHSOCKET_ENV_NAME);
			printf(format, SSH_AGENTPID_ENV_NAME, pidstrbuf,
			    SSH_AGENTPID_ENV_NAME);
			મુક્ત(cp);
			printf("echo Agent pid %ld;\n", (long)pid);
			exit(0);
		}
		જો (setenv(SSH_AUTHSOCKET_ENV_NAME, socket_name, 1) == -1 ||
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

	જો (setsid() == -1) {
		error("setsid: %s", strerror(errno));
		cleanup_exit(1);
	}

	(શૂન્ય)chdir("/");
	જો (stdfd_devnull(1, 1, 1) == -1)
		error_f("stdfd_devnull failed");

#ifdef HAVE_SETRLIMIT
	/* deny core dumps, since memory contains unencrypted private keys */
	rlim.rlim_cur = rlim.rlim_max = 0;
	જો (setrlimit(RLIMIT_CORE, &rlim) == -1) {
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
	જો (ac > 0)
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

	જો (socket_name != ખાલી && unveil(socket_name, "c") == -1) {
		fatal("%s: unveil %s %s", __progname, socket_name,
		    strerror(errno));
	}
	જો (socket_dir != ખાલી && unveil(socket_dir, "c") == -1) {
		fatal("%s: unveil %s %s", __progname, socket_dir,
		    strerror(errno));
	}
	જો (unveil("/", "r") == -1)
		fatal("%s: unveil /: %s", __progname, strerror(errno));
	જો ((ccp = getenv("SSH_SK_HELPER")) == ખાલી || *ccp == '\0')
		ccp = _PATH_SSH_SK_HELPER;
	જો (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, strerror(errno));
	જો ((ccp = getenv("SSH_PKCS11_HELPER")) == ખાલી || *ccp == '\0')
		ccp = _PATH_SSH_PKCS11_HELPER;
	જો (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, strerror(errno));
	જો ((ccp = getenv("SSH_ASKPASS")) == ખાલી || *ccp == '\0')
		ccp = _PATH_SSH_ASKPASS_DEFAULT;
	જો (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, strerror(errno));
	જો (unveil("/dev/null", "rw") == -1)
		fatal("%s: unveil /dev/null: %s", __progname, strerror(errno));
	જો (pledge("stdio rpath cpath wpath unix id proc exec", ખાલી) == -1)
		fatal("%s: pledge: %s", __progname, strerror(errno));
	platform_pledge_agent();

	જ્યારે (1) {
		sigprocmask(SIG_BLOCK, &nsigset, &osigset);
		જો (signalled_exit != 0) {
			logit("exiting on signal %d", (પૂર્ણાંક)signalled_exit);
			cleanup_exit((signalled_exit == SIGTERM &&
			    socket_activated) ? 0 : 2);
		}
		જો (signalled_keydrop) {
			logit("signal %d received; removing all keys",
			    (પૂર્ણાંક)signalled_keydrop);
			remove_all_identities();
			signalled_keydrop = 0;
		}
		ptimeout_init(&timeout);
		prepare_poll(&pfd, &npfd, &timeout, maxfds);
		result = ppoll(pfd, npfd, ptimeout_get_tsp(&timeout), &osigset);
		sigprocmask(SIG_SETMASK, &osigset, ખાલી);
		saved_errno = errno;
		જો (parent_alive_interval != 0)
			check_parent_exists();
		(શૂન્ય) reaper();	/* remove expired keys */
		જો (result == -1) {
			જો (saved_errno == EINTR)
				ચાલુ;
			fatal("poll: %s", strerror(saved_errno));
		} નહીંતર જો (result > 0)
			after_poll(pfd, npfd, maxfds);
	}
	/* NOTREACHED */
}
