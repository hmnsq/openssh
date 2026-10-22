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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/time.h>
#அந்தர்பாவ <sys/queue.h>
#அந்தர்பாவ <sys/resource.h>
#அந்தர்பாவ <sys/socket.h>
#அந்தர்பாவ <sys/stat.h>
#அந்தர்பாவ <sys/un.h>
#அந்தர்பாவ <sys/wait.h>

#ifdef WITH_OPENSSL
#அந்தர்பாவ <openssl/evp.h>
#அந்தர்பாவ "openbsd-compat/openssl-compat.h"
#endif

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <fcntl.h>
#அந்தர்பாவ <paths.h>
#அந்தர்பாவ <poll.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <limits.h>
#அந்தர்பாவ <time.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <util.h>
#அந்தர்பாவ <pwd.h>

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "ssh.h"
#அந்தர்பாவ "ssh2.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "authfd.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "digest.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "match.h"
#அந்தர்பாவ "msg.h"
#அந்தர்பாவ "pathnames.h"
#அந்தர்பாவ "ssh-pkcs11.h"
#அந்தர்பாவ "sk-api.h"
#அந்தர்பாவ "myproposal.h"
#அந்தர்பாவ "version.h"

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

வகைவரை எண்ணிக்கை {
	AUTH_UNUSED = 0,
	AUTH_SOCKET = 1,
	AUTH_CONNECTION = 2,
} sock_type;

கட்டமைப்பு hostkey_sid {
	கட்டமைப்பு sshkey *சாவி;
	கட்டமைப்பு sshbuf *sid;
	முழு forwarded;
};

வகைவரை கட்டமைப்பு socket_entry {
	முழு fd;
	sock_type type;
	கட்டமைப்பு sshbuf *உள்ளீடு;
	கட்டமைப்பு sshbuf *output;
	கட்டமைப்பு sshbuf *request;
	size_t nsession_ids;
	கட்டமைப்பு hostkey_sid *session_ids;
	முழு session_bind_attempted;
} SocketEntry;

u_int sockets_alloc = 0;
SocketEntry *sockets = வெற்று;

வகைவரை கட்டமைப்பு identity {
	TAILQ_ENTRY(identity) next;
	கட்டமைப்பு sshkey *சாவி;
	எழுத்து *comment;
	எழுத்து *provider;
	time_t death;
	u_int confirm;
	எழுத்து *sk_provider;
	கட்டமைப்பு dest_constraint *dest_constraints;
	size_t ndest_constraints;
} Identity;

கட்டமைப்பு idtable {
	முழு nentries;
	TAILQ_HEAD(idqueue, identity) idlist;
};

/* private key table */
கட்டமைப்பு idtable *idtab;

முழு max_fd = 0;

/* pid of shell == parent of agent */
pid_t parent_pid = -1;
time_t parent_alive_interval = 0;

நிலையான sig_atomic_t signalled_exit;
நிலையான sig_atomic_t signalled_keydrop;

/* pid of process for which cleanup_socket is applicable */
pid_t cleanup_pid = 0;

/* pathname and directory for AUTH_SOCKET */
நிலையான எழுத்து *socket_name;
நிலையான எழுத்து *socket_dir;
நிலையான எழுத்து *socket_dirspec;

/* Pattern-list of allowed PKCS#11/Security key paths */
நிலையான எழுத்து *allowed_providers;

/*
 * Allows PKCS11 providers or SK keys that use non-internal providers to
 * be added over a remote connection (identified by session-bind@openssh.com).
 */
நிலையான முழு remote_add_provider;

/* locking */
#define LOCK_SIZE	32
#define LOCK_SALT_SIZE	16
#define LOCK_ROUNDS	1
முழு locked = 0;
u_char lock_pwhash[LOCK_SIZE];
u_char lock_salt[LOCK_SALT_SIZE];

வெளி எழுத்து *__progname;

/* Default lifetime in seconds (0 == forever) */
நிலையான முழு lifetime = 0;

நிலையான முழு fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* Refuse signing of non-SSH messages for web-origin FIDO keys */
நிலையான முழு restrict_websafe = 1;
நிலையான எழுத்து *websafe_allowlist;

நிலையான வெறுமை
close_socket(SocketEntry *e)
{
	size_t i;

	close(e->fd);
	sshbuf_free(e->உள்ளீடு);
	sshbuf_free(e->output);
	sshbuf_free(e->request);
	க்கு (i = 0; i < e->nsession_ids; i++) {
		sshkey_free(e->session_ids[i].சாவி);
		sshbuf_free(e->session_ids[i].sid);
	}
	விடுவி(e->session_ids);
	memset(e, '\0', அளவு(*e));
	e->fd = -1;
	e->type = AUTH_UNUSED;
}

நிலையான வெறுமை
idtab_init(வெறுமை)
{
	idtab = xcalloc(1, அளவு(*idtab));
	TAILQ_INIT(&idtab->idlist);
	idtab->nentries = 0;
}

நிலையான வெறுமை
free_dest_constraint_hop(கட்டமைப்பு dest_constraint_hop *dch)
{
	u_int i;

	எனில் (dch == வெற்று)
		திரும்பு;
	விடுவி(dch->user);
	விடுவி(dch->hostname);
	க்கு (i = 0; i < dch->nkeys; i++)
		sshkey_free(dch->சாவிகள்[i]);
	விடுவி(dch->சாவிகள்);
	விடுவி(dch->சாவி_is_ca);
}

நிலையான வெறுமை
free_dest_constraints(கட்டமைப்பு dest_constraint *dcs, size_t ndcs)
{
	size_t i;

	க்கு (i = 0; i < ndcs; i++) {
		free_dest_constraint_hop(&dcs[i].from);
		free_dest_constraint_hop(&dcs[i].to);
	}
	விடுவி(dcs);
}

#ifdef ENABLE_PKCS11
நிலையான வெறுமை
dup_dest_constraint_hop(மாறிலி கட்டமைப்பு dest_constraint_hop *dch,
    கட்டமைப்பு dest_constraint_hop *out)
{
	u_int i;
	முழு r;

	out->user = dch->user == வெற்று ? வெற்று : xstrdup(dch->user);
	out->hostname = dch->hostname == வெற்று ? வெற்று : xstrdup(dch->hostname);
	out->is_ca = dch->is_ca;
	out->nkeys = dch->nkeys;
	out->சாவிகள் = out->nkeys == 0 ? வெற்று :
	    xcalloc(out->nkeys, அளவு(*out->சாவிகள்));
	out->சாவி_is_ca = out->nkeys == 0 ? வெற்று :
	    xcalloc(out->nkeys, அளவு(*out->சாவி_is_ca));
	க்கு (i = 0; i < dch->nkeys; i++) {
		எனில் (dch->சாவிகள்[i] != வெற்று &&
		    (r = sshkey_from_private(dch->சாவிகள்[i],
		    &(out->சாவிகள்[i]))) != 0)
			fatal_fr(r, "copy key");
		out->சாவி_is_ca[i] = dch->சாவி_is_ca[i];
	}
}

நிலையான கட்டமைப்பு dest_constraint *
dup_dest_constraints(மாறிலி கட்டமைப்பு dest_constraint *dcs, size_t ndcs)
{
	size_t i;
	கட்டமைப்பு dest_constraint *ret;

	எனில் (ndcs == 0)
		திரும்பு வெற்று;
	ret = xcalloc(ndcs, அளவு(*ret));
	க்கு (i = 0; i < ndcs; i++) {
		dup_dest_constraint_hop(&dcs[i].from, &ret[i].from);
		dup_dest_constraint_hop(&dcs[i].to, &ret[i].to);
	}
	திரும்பு ret;
}
#endif /* ENABLE_PKCS11 */

#ifdef DEBUG_CONSTRAINTS
நிலையான வெறுமை
dump_dest_constraint_hop(மாறிலி கட்டமைப்பு dest_constraint_hop *dch)
{
	u_int i;
	எழுத்து *fp;

	debug_f("user %s hostname %s is_ca %d nkeys %u",
	    dch->user == வெற்று ? "(null)" : dch->user,
	    dch->hostname == வெற்று ? "(null)" : dch->hostname,
	    dch->is_ca, dch->nkeys);
	க்கு (i = 0; i < dch->nkeys; i++) {
		fp = வெற்று;
		எனில் (dch->சாவிகள்[i] != வெற்று &&
		    (fp = sshkey_fingerprint(dch->சாவிகள்[i],
		    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == வெற்று)
			fatal_f("fingerprint failed");
		debug_f("key %u/%u: %s%s%s key_is_ca %d", i, dch->nkeys,
		    dch->சாவிகள்[i] == வெற்று ? "" : sshkey_ssh_name(dch->சாவிகள்[i]),
		    dch->சாவிகள்[i] == வெற்று ? "" : " ",
		    dch->சாவிகள்[i] == வெற்று ? "none" : fp,
		    dch->சாவி_is_ca[i]);
		விடுவி(fp);
	}
}
#endif /* DEBUG_CONSTRAINTS */

நிலையான வெறுமை
dump_dest_constraints(மாறிலி எழுத்து *context,
    மாறிலி கட்டமைப்பு dest_constraint *dcs, size_t ndcs)
{
#ifdef DEBUG_CONSTRAINTS
	size_t i;

	debug_f("%s: %zu constraints", context, ndcs);
	க்கு (i = 0; i < ndcs; i++) {
		debug_f("constraint %zu / %zu: from: ", i, ndcs);
		dump_dest_constraint_hop(&dcs[i].from);
		debug_f("constraint %zu / %zu: to: ", i, ndcs);
		dump_dest_constraint_hop(&dcs[i].to);
	}
	debug_f("done for %s", context);
#endif /* DEBUG_CONSTRAINTS */
}

நிலையான வெறுமை
free_identity(Identity *id)
{
	sshkey_free(id->சாவி);
	விடுவி(id->provider);
	விடுவி(id->comment);
	விடுவி(id->sk_provider);
	free_dest_constraints(id->dest_constraints, id->ndest_constraints);
	விடுவி(id);
}

/*
 * Match 'key' against the key/CA list in a destination constraint hop
 * Returns 0 on success or -1 otherwise.
 */
நிலையான முழு
match_சாவி_hop(மாறிலி எழுத்து *tag, மாறிலி கட்டமைப்பு sshkey *சாவி,
    மாறிலி கட்டமைப்பு dest_constraint_hop *dch)
{
	மாறிலி எழுத்து *reason = வெற்று;
	மாறிலி எழுத்து *hostname = dch->hostname ? dch->hostname : "(ORIGIN)";
	u_int i;
	எழுத்து *fp;

	எனில் (சாவி == வெற்று)
		திரும்பு -1;
	/* XXX logspam */
	எனில் ((fp = sshkey_fingerprint(சாவி, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == வெற்று)
		fatal_f("fingerprint failed");
	debug3_f("%s: entering hostname %s, requested key %s %s, %u keys avail",
	    tag, hostname, sshkey_type(சாவி), fp, dch->nkeys);
	விடுவி(fp);
	க்கு (i = 0; i < dch->nkeys; i++) {
		எனில் (dch->சாவிகள்[i] == வெற்று)
			திரும்பு -1;
		/* XXX logspam */
		எனில் ((fp = sshkey_fingerprint(dch->சாவிகள்[i], SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == வெற்று)
			fatal_f("fingerprint failed");
		debug3_f("%s: key %u: %s%s %s", tag, i,
		    dch->சாவி_is_ca[i] ? "CA " : "",
		    sshkey_type(dch->சாவிகள்[i]), fp);
		விடுவி(fp);
		எனில் (!sshkey_is_cert(சாவி)) {
			/* plain key */
			எனில் (dch->சாவி_is_ca[i] ||
			    !sshkey_equal(சாவி, dch->சாவிகள்[i]))
				தொடர்;
			திரும்பு 0;
		}
		/* certificate */
		எனில் (!dch->சாவி_is_ca[i])
			தொடர்;
		எனில் (சாவி->cert == வெற்று || சாவி->cert->signature_சாவி == வெற்று)
			திரும்பு -1; /* shouldn't happen */
		எனில் (!sshkey_equal(சாவி->cert->signature_சாவி, dch->சாவிகள்[i]))
			தொடர்;
		எனில் (sshkey_cert_check_host(சாவி, hostname,
		    SSH_ALLOWED_CA_SIGALGS, &reason) != 0) {
			debug_f("cert %s / hostname %s rejected: %s",
			    சாவி->cert->சாவி_id, hostname, reason);
			தொடர்;
		}
		திரும்பு 0;
	}
	திரும்பு -1;
}

/* Check destination constraints on an identity against the hostkey/user */
நிலையான முழு
permitted_by_dest_constraints(மாறிலி கட்டமைப்பு sshkey *fromkey,
    மாறிலி கட்டமைப்பு sshkey *tokey, Identity *id, மாறிலி எழுத்து *user,
    மாறிலி எழுத்து **hostnamep)
{
	size_t i;
	கட்டமைப்பு dest_constraint *d;

	எனில் (hostnamep != வெற்று)
		*hostnamep = வெற்று;
	க்கு (i = 0; i < id->ndest_constraints; i++) {
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
		எனில் (fromkey == வெற்று) {
			/* We are matching the first hop */
			எனில் (d->from.hostname != வெற்று || d->from.nkeys != 0)
				தொடர்;
		} இல்லையெனில் எனில் (match_சாவி_hop("from", fromkey, &d->from) != 0)
			தொடர்;

		/* Match 'to' key */
		எனில் (tokey != வெற்று && match_சாவி_hop("to", tokey, &d->to) != 0)
			தொடர்;

		/* Match user if specified */
		எனில் (d->to.user != வெற்று && user != வெற்று &&
		    !match_pattern(user, d->to.user))
			தொடர்;

		/* successfully matched this constraint */
		எனில் (hostnamep != வெற்று)
			*hostnamep = d->to.hostname;
		debug2_f("allowed for hostname %s",
		    d->to.hostname == வெற்று ? "*" : d->to.hostname);
		திரும்பு 0;
	}
	/* no match */
	debug2_f("%s identity \"%s\" not permitted for this destination",
	    sshkey_type(id->சாவி), id->comment);
	திரும்பு -1;
}

/*
 * Check whether hostkeys on a SocketEntry and the optionally specified user
 * are permitted by the destination constraints on the Identity.
 * Returns 0 on success or -1 otherwise.
 */
நிலையான முழு
identity_permitted(Identity *id, SocketEntry *e, எழுத்து *user,
    மாறிலி எழுத்து **forward_hostnamep, மாறிலி எழுத்து **last_hostnamep)
{
	size_t i;
	மாறிலி எழுத்து **hp;
	கட்டமைப்பு hostkey_sid *hks;
	மாறிலி கட்டமைப்பு sshkey *fromkey = வெற்று;
	மாறிலி எழுத்து *test_user;
	எழுத்து *fp1, *fp2;

	/* XXX remove logspam */
	debug3_f("entering: key %s comment \"%s\", %zu socket bindings, "
	    "%zu constraints", sshkey_type(id->சாவி), id->comment,
	    e->nsession_ids, id->ndest_constraints);
	எனில் (id->ndest_constraints == 0)
		திரும்பு 0; /* unconstrained */
	எனில் (e->session_bind_attempted && e->nsession_ids == 0) {
		error_f("previous session bind failed on socket");
		திரும்பு -1;
	}
	எனில் (e->nsession_ids == 0)
		திரும்பு 0; /* local use */
	/*
	 * Walk through the hops recorded by session_id and try to find a
	 * constraint that satisfies each.
	 */
	க்கு (i = 0; i < e->nsession_ids; i++) {
		hks = e->session_ids + i;
		எனில் (hks->சாவி == வெற்று)
			fatal_f("internal error: no bound key");
		/* XXX remove logspam */
		fp1 = fp2 = வெற்று;
		எனில் (fromkey != வெற்று &&
		    (fp1 = sshkey_fingerprint(fromkey, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == வெற்று)
			fatal_f("fingerprint failed");
		எனில் ((fp2 = sshkey_fingerprint(hks->சாவி, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == வெற்று)
			fatal_f("fingerprint failed");
		debug3_f("socketentry fd=%d, entry %zu %s, "
		    "from hostkey %s %s to user %s hostkey %s %s",
		    e->fd, i, hks->forwarded ? "FORWARD" : "AUTH",
		    fromkey ? sshkey_type(fromkey) : "(ORIGIN)",
		    fromkey ? fp1 : "", user ? user : "(ANY)",
		    sshkey_type(hks->சாவி), fp2);
		விடுவி(fp1);
		விடுவி(fp2);
		/*
		 * Record the hostnames for the initial forwarding and
		 * the final destination.
		 */
		hp = வெற்று;
		எனில் (i == e->nsession_ids - 1)
			hp = last_hostnamep;
		இல்லையெனில் எனில் (i == 0)
			hp = forward_hostnamep;
		/* Special handling for final recorded binding */
		test_user = வெற்று;
		எனில் (i == e->nsession_ids - 1) {
			/* Can only check user at final hop */
			test_user = user;
			/*
			 * user is only presented for signature requests.
			 * If this is the case, make sure last binding is not
			 * for a forwarding.
			 */
			எனில் (hks->forwarded && user != வெற்று) {
				error_f("tried to sign on forwarding hop");
				திரும்பு -1;
			}
		} இல்லையெனில் எனில் (!hks->forwarded) {
			error_f("tried to forward though signing bind");
			திரும்பு -1;
		}
		எனில் (permitted_by_dest_constraints(fromkey, hks->சாவி, id,
		    test_user, hp) != 0)
			திரும்பு -1;
		fromkey = hks->சாவி;
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
	எனில் (hks->forwarded && user == வெற்று &&
	    permitted_by_dest_constraints(hks->சாவி, வெற்று, id,
	    வெற்று, வெற்று) != 0) {
		debug3_f("key permitted at host but not after");
		திரும்பு -1;
	}

	/* success */
	திரும்பு 0;
}

நிலையான முழு
socket_is_remote(SocketEntry *e)
{
	திரும்பு e->session_bind_attempted || (e->nsession_ids != 0);
}

/* return matching private key for given public key */
நிலையான Identity *
lookup_identity(கட்டமைப்பு sshkey *சாவி)
{
	Identity *id;

	TAILQ_FOREACH(id, &idtab->idlist, next) {
		எனில் (sshkey_equal(சாவி, id->சாவி))
			திரும்பு (id);
	}
	திரும்பு (வெற்று);
}

/* Check confirmation of keysign request */
நிலையான முழு
confirm_சாவி(Identity *id, மாறிலி எழுத்து *extra)
{
	எழுத்து *p;
	முழு ret = -1;

	p = sshkey_fingerprint(id->சாவி, fingerprint_hash, SSH_FP_DEFAULT);
	எனில் (p != வெற்று &&
	    ask_permission("Allow use of key %s?\nKey fingerprint %s.%s%s",
	    id->comment, p,
	    extra == வெற்று ? "" : "\n", extra == வெற்று ? "" : extra))
		ret = 0;
	விடுவி(p);

	திரும்பு (ret);
}

நிலையான வெறுமை
send_status_generic(SocketEntry *e, u_int code)
{
	முழு r;

	எனில் ((r = sshbuf_put_u32(e->output, 1)) != 0 ||
	    (r = sshbuf_put_u8(e->output, code)) != 0)
		fatal_fr(r, "compose");
}

நிலையான வெறுமை
send_status(SocketEntry *e, முழு success)
{
	send_status_generic(e,
	    success ? SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE);
}

/* send list of supported public keys to 'client' */
நிலையான வெறுமை
process_request_identities(SocketEntry *e)
{
	Identity *id;
	கட்டமைப்பு sshbuf *செய்தி, *சாவிகள்;
	முழு r;
	u_int i = 0, nentries = 0;
	எழுத்து *fp;

	debug2_f("entering");

	எனில் ((செய்தி = sshbuf_new()) == வெற்று || (சாவிகள் = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	TAILQ_FOREACH(id, &idtab->idlist, next) {
		எனில் ((fp = sshkey_fingerprint(id->சாவி, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == வெற்று)
			fatal_f("fingerprint failed");
		debug_f("key %u / %u: %s %s", i++, idtab->nentries,
		    sshkey_ssh_name(id->சாவி), fp);
		dump_dest_constraints(__func__,
		    id->dest_constraints, id->ndest_constraints);
		விடுவி(fp);
		/* identity not visible, don't include in response */
		எனில் (identity_permitted(id, e, வெற்று, வெற்று, வெற்று) != 0)
			தொடர்;
		எனில் ((r = sshkey_puts(id->சாவி, சாவிகள்)) != 0 ||
		    (r = sshbuf_put_cstring(சாவிகள், id->comment)) != 0) {
			error_fr(r, "compose key/comment");
			தொடர்;
		}
		nentries++;
	}
	debug2_f("replying with %u allowed of %u available keys",
	    nentries, idtab->nentries);
	எனில் ((r = sshbuf_put_u8(செய்தி, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
	    (r = sshbuf_put_u32(செய்தி, nentries)) != 0 ||
	    (r = sshbuf_putb(செய்தி, சாவிகள்)) != 0)
		fatal_fr(r, "compose");
	எனில் ((r = sshbuf_put_stringb(e->output, செய்தி)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(செய்தி);
	sshbuf_free(சாவிகள்);
}


நிலையான எழுத்து *
agent_decode_alg(கட்டமைப்பு sshkey *சாவி, u_int flags)
{
	எனில் (சாவி->type == சாவி_RSA) {
		எனில் (flags & SSH_AGENT_RSA_SHA2_256)
			திரும்பு "rsa-sha2-256";
		இல்லையெனில் எனில் (flags & SSH_AGENT_RSA_SHA2_512)
			திரும்பு "rsa-sha2-512";
	} இல்லையெனில் எனில் (சாவி->type == சாவி_RSA_CERT) {
		எனில் (flags & SSH_AGENT_RSA_SHA2_256)
			திரும்பு "rsa-sha2-256-cert-v01@openssh.com";
		இல்லையெனில் எனில் (flags & SSH_AGENT_RSA_SHA2_512)
			திரும்பு "rsa-sha2-512-cert-v01@openssh.com";
	}
	திரும்பு வெற்று;
}

/*
 * Attempt to parse the contents of a buffer as a SSH publickey userauth
 * request, checking its contents for consistency and matching the embedded
 * key against the one that is being used for signing.
 * Note: does not modify msg buffer.
 * Optionally extract the username, session ID and/or hostkey from the request.
 */
நிலையான முழு
parse_userauth_request(கட்டமைப்பு sshbuf *செய்தி, மாறிலி கட்டமைப்பு sshkey *expected_சாவி,
    எழுத்து **userp, கட்டமைப்பு sshbuf **sess_idp, கட்டமைப்பு sshkey **hostkeyp)
{
	கட்டமைப்பு sshbuf *b = வெற்று, *sess_id = வெற்று;
	எழுத்து *user = வெற்று, *service = வெற்று, *method = வெற்று, *pkalg = வெற்று;
	முழு r;
	u_char t, sig_follows;
	கட்டமைப்பு sshkey *mkey = வெற்று, *hostkey = வெற்று;

	எனில் (userp != வெற்று)
		*userp = வெற்று;
	எனில் (sess_idp != வெற்று)
		*sess_idp = வெற்று;
	எனில் (hostkeyp != வெற்று)
		*hostkeyp = வெற்று;
	எனில் ((b = sshbuf_fromb(செய்தி)) == வெற்று)
		fatal_f("sshbuf_fromb");

	/* SSH userauth request */
	எனில் ((r = sshbuf_froms(b, &sess_id)) != 0)
		செல் out;
	எனில் (sshbuf_len(sess_id) == 0) {
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	எனில் ((r = sshbuf_get_u8(b, &t)) != 0 || /* SSH2_MSG_USERAUTH_REQUEST */
	    (r = sshbuf_get_cstring(b, &user, வெற்று)) != 0 || /* server user */
	    (r = sshbuf_get_cstring(b, &service, வெற்று)) != 0 || /* service */
	    (r = sshbuf_get_cstring(b, &method, வெற்று)) != 0 || /* method */
	    (r = sshbuf_get_u8(b, &sig_follows)) != 0 || /* sig-follows */
	    (r = sshbuf_get_cstring(b, &pkalg, வெற்று)) != 0 || /* alg */
	    (r = sshkey_froms(b, &mkey)) != 0) /*சாவி*/
		செல் out;
	எனில் (t != SSH2_செய்தி_USERAUTH_REQUEST ||
	    sig_follows != 1 ||
	    strcmp(service, "ssh-connection") != 0 ||
	    !sshkey_equal(expected_சாவி, mkey) ||
	    sshkey_type_from_name(pkalg) != expected_சாவி->type) {
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	எனில் (strcmp(method, "publickey-hostbound-v00@openssh.com") == 0) {
		எனில் ((r = sshkey_froms(b, &hostkey)) != 0)
			செல் out;
	} இல்லையெனில் எனில் (strcmp(method, "publickey") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	எனில் (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	/* success */
	r = 0;
	debug3_f("well formed userauth");
	எனில் (userp != வெற்று) {
		*userp = user;
		user = வெற்று;
	}
	எனில் (sess_idp != வெற்று) {
		*sess_idp = sess_id;
		sess_id = வெற்று;
	}
	எனில் (hostkeyp != வெற்று) {
		*hostkeyp = hostkey;
		hostkey = வெற்று;
	}
 out:
	sshbuf_free(b);
	sshbuf_free(sess_id);
	விடுவி(user);
	விடுவி(service);
	விடுவி(method);
	விடுவி(pkalg);
	sshkey_free(mkey);
	sshkey_free(hostkey);
	திரும்பு r;
}

/*
 * Attempt to parse the contents of a buffer as a SSHSIG signature request.
 * Note: does not modify buffer.
 */
நிலையான முழு
parse_sshsig_request(கட்டமைப்பு sshbuf *செய்தி)
{
	முழு r;
	கட்டமைப்பு sshbuf *b;

	எனில் ((b = sshbuf_fromb(செய்தி)) == வெற்று)
		fatal_f("sshbuf_fromb");

	எனில் ((r = sshbuf_cmp(b, 0, "SSHSIG", 6)) != 0 ||
	    (r = sshbuf_consume(b, 6)) != 0 ||
	    (r = sshbuf_get_cstring(b, வெற்று, வெற்று)) != 0 || /* namespace */
	    (r = sshbuf_get_string_direct(b, வெற்று, வெற்று)) != 0 || /* reserved */
	    (r = sshbuf_get_cstring(b, வெற்று, வெற்று)) != 0 || /* hashalg */
	    (r = sshbuf_get_string_direct(b, வெற்று, வெற்று)) != 0) /* H(msg) */
		செல் out;
	எனில் (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	திரும்பு r;
}

/*
 * This function inspects a message to be signed by a FIDO key that has a
 * web-like application string (i.e. one that does not begin with "ssh:".
 * It checks that the message is one of those expected for SSH operations
 * (pubkey userauth, sshsig, CA key signing) to exclude signing challenges
 * for the web.
 */
நிலையான முழு
check_websafe_message_contents(கட்டமைப்பு sshkey *சாவி, கட்டமைப்பு sshbuf *data)
{
	எனில் (parse_userauth_request(data, சாவி, வெற்று, வெற்று, வெற்று) == 0) {
		debug_f("signed data matches public key userauth request");
		திரும்பு 1;
	}
	எனில் (parse_sshsig_request(data) == 0) {
		debug_f("signed data matches SSHSIG signature request");
		திரும்பு 1;
	}

	/* XXX check CA signature operation */

	error("web-origin key attempting to sign non-SSH message");
	திரும்பு 0;
}

நிலையான முழு
buf_equal(மாறிலி கட்டமைப்பு sshbuf *a, மாறிலி கட்டமைப்பு sshbuf *b)
{
	எனில் (sshbuf_ptr(a) == வெற்று || sshbuf_ptr(b) == வெற்று)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	எனில் (sshbuf_len(a) != sshbuf_len(b))
		திரும்பு SSH_ERR_INVALID_FORMAT;
	எனில் (timingsafe_bcmp(sshbuf_ptr(a), sshbuf_ptr(b), sshbuf_len(a)) != 0)
		திரும்பு SSH_ERR_INVALID_FORMAT;
	திரும்பு 0;
}

/* ssh2 only */
நிலையான வெறுமை
process_sign_request2(SocketEntry *e)
{
	u_char *signature = வெற்று;
	size_t slen = 0;
	u_int compat = 0, flags;
	முழு r, ok = -1, retried = 0;
	எழுத்து *fp = வெற்று, *pin = வெற்று, *prompt = வெற்று;
	எழுத்து *user = வெற்று, *sig_dest = வெற்று;
	மாறிலி எழுத்து *fwd_host = வெற்று, *dest_host = வெற்று;
	கட்டமைப்பு sshbuf *செய்தி = வெற்று, *data = வெற்று, *sid = வெற்று;
	கட்டமைப்பு sshkey *சாவி = வெற்று, *hostkey = வெற்று;
	கட்டமைப்பு identity *id;
	கட்டமைப்பு notifier_ctx *notifier = வெற்று;

	debug_f("entering");

	எனில் ((செய்தி = sshbuf_new()) == வெற்று || (data = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = sshkey_froms(e->request, &சாவி)) != 0 ||
	    (r = sshbuf_get_stringb(e->request, data)) != 0 ||
	    (r = sshbuf_get_u32(e->request, &flags)) != 0) {
		error_fr(r, "parse");
		செல் send;
	}

	எனில் ((id = lookup_identity(சாவி)) == வெற்று) {
		verbose_f("%s key not found", sshkey_type(சாவி));
		செல் send;
	}
	எனில் ((fp = sshkey_fingerprint(சாவி, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == வெற்று)
		fatal_f("fingerprint failed");

	எனில் (id->ndest_constraints != 0) {
		எனில் (e->nsession_ids == 0) {
			logit_f("refusing use of destination-constrained key "
			    "to sign on unbound connection");
			செல் send;
		}
		எனில் (parse_userauth_request(data, சாவி, &user, &sid,
		    &hostkey) != 0) {
			logit_f("refusing use of destination-constrained key "
			   "to sign an unidentified signature");
			செல் send;
		}
		/* XXX logspam */
		debug_f("user=%s", user);
		எனில் (identity_permitted(id, e, user, &fwd_host, &dest_host) != 0)
			செல் send;
		/* XXX display fwd_host/dest_host in askpass UI */
		/*
		 * Ensure that the session ID is the most recent one
		 * registered on the socket - it should have been bound by
		 * ssh immediately before userauth.
		 */
		எனில் (buf_equal(sid,
		    e->session_ids[e->nsession_ids - 1].sid) != 0) {
			error_f("unexpected session ID (%zu listed) on "
			    "signature request for target user %s with "
			    "key %s %s", e->nsession_ids, user,
			    sshkey_type(id->சாவி), fp);
			செல் send;
		}
		/*
		 * Ensure that the hostkey embedded in the signature matches
		 * the one most recently bound to the socket. An exception is
		 * made for the initial forwarding hop.
		 */
		எனில் (e->nsession_ids > 1 && hostkey == வெற்று) {
			error_f("refusing use of destination-constrained key: "
			    "no hostkey recorded in signature for forwarded "
			    "connection");
			செல் send;
		}
		எனில் (hostkey != வெற்று && !sshkey_equal(hostkey,
		    e->session_ids[e->nsession_ids - 1].சாவி)) {
			error_f("refusing use of destination-constrained key: "
			    "mismatch between hostkey in request and most "
			    "recently bound session");
			செல் send;
		}
		xasprintf(&sig_dest, "public key authentication request for "
		    "user \"%s\" to listed host", user);
	}
	எனில் (id->confirm && confirm_சாவி(id, sig_dest) != 0) {
		verbose_f("user refused key");
		செல் send;
	}
	எனில் (sshkey_is_sk(id->சாவி)) {
		எனில் (restrict_websafe &&
		    match_pattern_list(id->சாவி->sk_application,
		    websafe_allowlist, 0) != 1 &&
		    !check_websafe_message_contents(சாவி, data)) {
			/* error already logged */
			செல் send;
		}
		எனில் (id->சாவி->sk_flags & SSH_SK_USER_PRESENCE_REQD) {
			notifier = notify_start(0,
			    "Confirm user presence for key %s %s%s%s",
			    sshkey_type(id->சாவி), fp,
			    sig_dest == வெற்று ? "" : "\n",
			    sig_dest == வெற்று ? "" : sig_dest);
		}
	}
 retry_pin:
	எனில் ((r = sshkey_sign(id->சாவி, &signature, &slen,
	    sshbuf_ptr(data), sshbuf_len(data), agent_decode_alg(சாவி, flags),
	    id->sk_provider, pin, compat)) != 0) {
		debug_fr(r, "sshkey_sign");
		எனில் (pin == வெற்று && !retried && sshkey_is_sk(id->சாவி) &&
		    r == SSH_ERR_சாவி_WRONG_PASSPHRASE) {
			notify_complete(notifier, வெற்று);
			notifier = வெற்று;
			/* XXX include sig_dest */
			xasprintf(&prompt, "Enter PIN%sfor %s key %s: ",
			    (id->சாவி->sk_flags & SSH_SK_USER_PRESENCE_REQD) ?
			    " and confirm user presence " : " ",
			    sshkey_type(id->சாவி), fp);
			pin = read_passphrase(prompt, RP_USE_ASKPASS);
			retried = 1;
			செல் retry_pin;
		}
		error_fr(r, "sshkey_sign");
		செல் send;
	}
	/* Success */
	ok = 0;
	debug_f("good signature");
 send:
	notify_complete(notifier, "User presence confirmed");

	எனில் (ok == 0) {
		எனில் ((r = sshbuf_put_u8(செய்தி, SSH2_AGENT_SIGN_RESPONSE)) != 0 ||
		    (r = sshbuf_put_string(செய்தி, signature, slen)) != 0)
			fatal_fr(r, "compose");
	} இல்லையெனில் எனில் ((r = sshbuf_put_u8(செய்தி, SSH_AGENT_FAILURE)) != 0)
		fatal_fr(r, "compose failure");

	எனில் ((r = sshbuf_put_stringb(e->output, செய்தி)) != 0)
		fatal_fr(r, "enqueue");

	sshbuf_free(sid);
	sshbuf_free(data);
	sshbuf_free(செய்தி);
	sshkey_free(சாவி);
	sshkey_free(hostkey);
	விடுவி(fp);
	விடுவி(signature);
	விடுவி(sig_dest);
	விடுவி(user);
	விடுவி(prompt);
	எனில் (pin != வெற்று)
		freezero(pin, strlen(pin));
}

/* shared */
நிலையான வெறுமை
process_remove_identity(SocketEntry *e)
{
	முழு r, success = 0;
	கட்டமைப்பு sshkey *சாவி = வெற்று;
	Identity *id;

	debug2_f("entering");
	எனில் ((r = sshkey_froms(e->request, &சாவி)) != 0) {
		error_fr(r, "parse key");
		செல் done;
	}
	எனில் ((id = lookup_identity(சாவி)) == வெற்று) {
		debug_f("key not found");
		செல் done;
	}
	/* identity not visible, cannot be removed */
	எனில் (identity_permitted(id, e, வெற்று, வெற்று, வெற்று) != 0)
		செல் done; /* error already logged */
	/* We have this key, free it. */
	எனில் (idtab->nentries < 1)
		fatal_f("internal error: nentries %d", idtab->nentries);
	TAILQ_REMOVE(&idtab->idlist, id, next);
	free_identity(id);
	idtab->nentries--;
	success = 1;
 done:
	sshkey_free(சாவி);
	send_status(e, success);
}

நிலையான வெறுமை
remove_all_identities(வெறுமை)
{
	Identity *id;

	debug2_f("entering");
	/* Loop over all identities and clear the keys. */
	க்கு (id = TAILQ_FIRST(&idtab->idlist); id;
	    id = TAILQ_FIRST(&idtab->idlist)) {
		TAILQ_REMOVE(&idtab->idlist, id, next);
		free_identity(id);
	}

	/* Mark that there are no identities. */
	idtab->nentries = 0;
}

நிலையான வெறுமை
process_remove_all_identities(SocketEntry *e)
{
	remove_all_identities();

	/* Send success. */
	send_status(e, 1);
}

/* removes expired keys and returns number of seconds until the next expiry */
நிலையான time_t
reaper(வெறுமை)
{
	time_t deadline = 0, now = monotime();
	Identity *id, *nxt;

	க்கு (id = TAILQ_FIRST(&idtab->idlist); id; id = nxt) {
		nxt = TAILQ_NEXT(id, next);
		எனில் (id->death == 0)
			தொடர்;
		எனில் (now >= id->death) {
			debug("expiring key '%s'", id->comment);
			TAILQ_REMOVE(&idtab->idlist, id, next);
			free_identity(id);
			idtab->nentries--;
		} இல்லையெனில்
			deadline = (deadline == 0) ? id->death :
			    MINIMUM(deadline, id->death);
	}
	எனில் (deadline == 0 || deadline <= now)
		திரும்பு 0;
	இல்லையெனில்
		திரும்பு (deadline - now);
}

நிலையான முழு
parse_dest_constraint_hop(கட்டமைப்பு sshbuf *b, கட்டமைப்பு dest_constraint_hop *dch)
{
	u_char சாவி_is_ca;
	size_t elen = 0, userlen = 0;
	முழு r;
	கட்டமைப்பு sshkey *k = வெற்று;
	எழுத்து *fp;

	memset(dch, '\0', அளவு(*dch));
	எனில் ((r = sshbuf_get_cstring(b, &dch->user, &userlen)) != 0 ||
	    (r = sshbuf_get_cstring(b, &dch->hostname, வெற்று)) != 0 ||
	    (r = sshbuf_get_string_direct(b, வெற்று, &elen)) != 0) {
		error_fr(r, "parse");
		செல் out;
	}
	எனில் (elen != 0) {
		error_f("unsupported extensions (len %zu)", elen);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		செல் out;
	}
	எனில் (*dch->hostname == '\0') {
		விடுவி(dch->hostname);
		dch->hostname = வெற்று;
	}
	எனில் (*dch->user == '\0') {
		விடுவி(dch->user);
		dch->user = வெற்று;
	} இல்லையெனில் எனில் (userlen > AGENT_USER_CONSTRAINT_MAX_LEN) {
		error_f("user match pattern too long");
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	போது (sshbuf_len(b) != 0) {
		dch->சாவிகள் = xrecallocarray(dch->சாவிகள், dch->nkeys,
		    dch->nkeys + 1, அளவு(*dch->சாவிகள்));
		dch->சாவி_is_ca = xrecallocarray(dch->சாவி_is_ca, dch->nkeys,
		    dch->nkeys + 1, அளவு(*dch->சாவி_is_ca));
		எனில் ((r = sshkey_froms(b, &k)) != 0 ||
		    (r = sshbuf_get_u8(b, &சாவி_is_ca)) != 0)
			செல் out;
		எனில் ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == வெற்று)
			fatal_f("fingerprint failed");
		debug3_f("%s%s%s: adding %skey %s %s",
		    dch->user == வெற்று ? "" : dch->user,
		    dch->user == வெற்று ? "" : "@",
		    dch->hostname, சாவி_is_ca ? "CA " : "", sshkey_type(k), fp);
		விடுவி(fp);
		dch->சாவிகள்[dch->nkeys] = k;
		dch->சாவி_is_ca[dch->nkeys] = சாவி_is_ca != 0;
		dch->nkeys++;
		k = வெற்று; /* transferred */
	}
	/* success */
	r = 0;
 out:
	sshkey_free(k);
	திரும்பு r;
}

நிலையான முழு
parse_dest_constraint(கட்டமைப்பு sshbuf *m, கட்டமைப்பு dest_constraint *dc)
{
	கட்டமைப்பு sshbuf *b = வெற்று, *frombuf = வெற்று, *tobuf = வெற்று;
	முழு r;
	size_t elen = 0;

	debug3_f("entering");

	memset(dc, '\0', அளவு(*dc));
	எனில் ((r = sshbuf_froms(m, &b)) != 0 ||
	    (r = sshbuf_froms(b, &frombuf)) != 0 ||
	    (r = sshbuf_froms(b, &tobuf)) != 0 ||
	    (r = sshbuf_get_string_direct(b, வெற்று, &elen)) != 0) {
		error_fr(r, "parse");
		செல் out;
	}
	எனில் ((r = parse_dest_constraint_hop(frombuf, &dc->from)) != 0 ||
	    (r = parse_dest_constraint_hop(tobuf, &dc->to)) != 0)
		செல் out; /* already logged */
	எனில் (elen != 0) {
		error_f("unsupported extensions (len %zu)", elen);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		செல் out;
	}
	debug2_f("parsed %s (%u keys) > %s%s%s (%u keys)",
	    dc->from.hostname ? dc->from.hostname : "(ORIGIN)", dc->from.nkeys,
	    dc->to.user ? dc->to.user : "", dc->to.user ? "@" : "",
	    dc->to.hostname ? dc->to.hostname : "(ANY)", dc->to.nkeys);
	/* check consistency */
	எனில் ((dc->from.hostname == வெற்று) != (dc->from.nkeys == 0) ||
	    dc->from.user != வெற்று) {
		error_f("inconsistent \"from\" specification");
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	எனில் (dc->to.hostname == வெற்று || dc->to.nkeys == 0) {
		error_f("incomplete \"to\" specification");
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	sshbuf_free(frombuf);
	sshbuf_free(tobuf);
	திரும்பு r;
}

நிலையான முழு
parse_சாவி_constraint_extension(கட்டமைப்பு sshbuf *m, எழுத்து **sk_providerp,
    கட்டமைப்பு dest_constraint **dcsp, size_t *ndcsp, முழு *cert_onlyp,
    கட்டமைப்பு sshkey ***certs, size_t *ncerts)
{
	எழுத்து *ext_name = வெற்று;
	முழு r;
	கட்டமைப்பு sshbuf *b = வெற்று;
	u_char v;
	கட்டமைப்பு sshkey *k;

	எனில் ((r = sshbuf_get_cstring(m, &ext_name, வெற்று)) != 0) {
		error_fr(r, "parse constraint extension");
		செல் out;
	}
	debug_f("constraint ext %s", ext_name);
	எனில் (strcmp(ext_name, "sk-provider@openssh.com") == 0) {
		எனில் (sk_providerp == வெற்று) {
			error_f("%s not valid here", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			செல் out;
		}
		எனில் (*sk_providerp != வெற்று) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			செல் out;
		}
		எனில் ((r = sshbuf_get_cstring(m, sk_providerp, வெற்று)) != 0) {
			error_fr(r, "parse %s", ext_name);
			செல் out;
		}
	} இல்லையெனில் எனில் (strcmp(ext_name,
	    "restrict-destination-v00@openssh.com") == 0) {
		எனில் (*dcsp != வெற்று) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			செல் out;
		}
		எனில் ((r = sshbuf_froms(m, &b)) != 0) {
			error_fr(r, "parse %s outer", ext_name);
			செல் out;
		}
		போது (sshbuf_len(b) != 0) {
			எனில் (*ndcsp >= AGENT_MAX_DEST_CONSTRAINTS) {
				error_f("too many %s constraints", ext_name);
				r = SSH_ERR_INVALID_FORMAT;
				செல் out;
			}
			*dcsp = xrecallocarray(*dcsp, *ndcsp, *ndcsp + 1,
			    அளவு(**dcsp));
			எனில் ((r = parse_dest_constraint(b,
			    *dcsp + (*ndcsp)++)) != 0)
				செல் out; /* error already logged */
		}
	} இல்லையெனில் எனில் (strcmp(ext_name,
	    "associated-certs-v00@openssh.com") == 0) {
		எனில் (certs == வெற்று || ncerts == வெற்று || cert_onlyp == வெற்று) {
			error_f("%s not valid here", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			செல் out;
		}
		எனில் (*certs != வெற்று) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			செல் out;
		}
		எனில் ((r = sshbuf_get_u8(m, &v)) != 0 ||
		    (r = sshbuf_froms(m, &b)) != 0) {
			error_fr(r, "parse %s", ext_name);
			செல் out;
		}
		*cert_onlyp = v != 0;
		போது (sshbuf_len(b) != 0) {
			எனில் (*ncerts >= AGENT_MAX_EXT_CERTS) {
				error_f("too many %s constraints", ext_name);
				r = SSH_ERR_INVALID_FORMAT;
				செல் out;
			}
			*certs = xrecallocarray(*certs, *ncerts, *ncerts + 1,
			    அளவு(**certs));
			எனில் ((r = sshkey_froms(b, &k)) != 0) {
				error_fr(r, "parse key");
				செல் out;
			}
			(*certs)[(*ncerts)++] = k;
		}
	} இல்லையெனில் {
		error_f("unsupported constraint \"%s\"", ext_name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		செல் out;
	}
	/* success */
	r = 0;
 out:
	விடுவி(ext_name);
	sshbuf_free(b);
	திரும்பு r;
}

நிலையான முழு
parse_சாவி_constraints(கட்டமைப்பு sshbuf *m, கட்டமைப்பு sshkey *k, time_t *deathp,
    u_int *secondsp, முழு *confirmp, எழுத்து **sk_providerp,
    கட்டமைப்பு dest_constraint **dcsp, size_t *ndcsp,
    முழு *cert_onlyp, size_t *ncerts, கட்டமைப்பு sshkey ***certs)
{
	u_char ctype;
	முழு r;
	u_int seconds;

	போது (sshbuf_len(m)) {
		எனில் ((r = sshbuf_get_u8(m, &ctype)) != 0) {
			error_fr(r, "parse constraint type");
			செல் out;
		}
		தேர்வு (ctype) {
		நிலை SSH_AGENT_CONSTRAIN_LIFETIME:
			எனில் (*deathp != 0) {
				error_f("lifetime already set");
				r = SSH_ERR_INVALID_FORMAT;
				செல் out;
			}
			எனில் ((r = sshbuf_get_u32(m, &seconds)) != 0) {
				error_fr(r, "parse lifetime constraint");
				செல் out;
			}
			*deathp = monotime() + seconds;
			*secondsp = seconds;
			நிறுத்து;
		நிலை SSH_AGENT_CONSTRAIN_CONFIRM:
			எனில் (*confirmp != 0) {
				error_f("confirm already set");
				r = SSH_ERR_INVALID_FORMAT;
				செல் out;
			}
			*confirmp = 1;
			நிறுத்து;
		நிலை SSH_AGENT_CONSTRAIN_EXTENSION:
			எனில் ((r = parse_சாவி_constraint_extension(m,
			    sk_providerp, dcsp, ndcsp,
			    cert_onlyp, certs, ncerts)) != 0)
				செல் out; /* error already logged */
			நிறுத்து;
		இயல்பு:
			error_f("Unknown constraint %d", ctype);
			r = SSH_ERR_FEATURE_UNSUPPORTED;
			செல் out;
		}
	}
	/* success */
	r = 0;
 out:
	திரும்பு r;
}

நிலையான வெறுமை
process_add_identity(SocketEntry *e)
{
	Identity *id;
	முழு success = 0, confirm = 0;
	எழுத்து *fp, *comment = வெற்று, *sk_provider = வெற்று;
	எழுத்து canonical_provider[PATH_MAX];
	time_t death = 0;
	u_int seconds = 0;
	கட்டமைப்பு dest_constraint *dest_constraints = வெற்று;
	size_t ndest_constraints = 0;
	கட்டமைப்பு sshkey *k = வெற்று;
	முழு r = SSH_ERR_INTERNAL_ERROR;

	debug2_f("entering");
	எனில் ((r = sshkey_private_deserialize(e->request, &k)) != 0 ||
	    k == வெற்று ||
	    (r = sshbuf_get_cstring(e->request, &comment, வெற்று)) != 0) {
		error_fr(r, "parse");
		செல் out;
	}
	எனில் (parse_சாவி_constraints(e->request, k, &death, &seconds, &confirm,
	    &sk_provider, &dest_constraints, &ndest_constraints,
	    வெற்று, வெற்று, வெற்று) != 0) {
		error_f("failed to parse constraints");
		sshbuf_reset(e->request);
		செல் out;
	}
	dump_dest_constraints(__func__, dest_constraints, ndest_constraints);

	எனில் (sk_provider != வெற்று) {
		எனில் (!sshkey_is_sk(k)) {
			error("Cannot add provider: %s is not an "
			    "authenticator-hosted key", sshkey_type(k));
			செல் out;
		}
		எனில் (strcasecmp(sk_provider, "internal") == 0) {
			debug_f("internal provider");
		} இல்லையெனில் {
			எனில் (socket_is_remote(e) && !remote_add_provider) {
				verbose("failed add of SK provider \"%.100s\": "
				    "remote addition of providers is disabled",
				    sk_provider);
				செல் out;
			}
			எனில் (realpath(sk_provider, canonical_provider) == வெற்று) {
				verbose("failed provider \"%.100s\": "
				    "realpath: %s", sk_provider,
				    strerror(errno));
				செல் out;
			}
			விடுவி(sk_provider);
			sk_provider = xstrdup(canonical_provider);
			எனில் (match_pattern_list(sk_provider,
			    allowed_providers, 0) != 1) {
				error("Refusing add key: "
				    "provider %s not allowed", sk_provider);
				செல் out;
			}
		}
	}
	எனில் ((r = sshkey_shield_private(k)) != 0) {
		error_fr(r, "shield private");
		செல் out;
	}
	எனில் (lifetime && !death)
		death = monotime() + lifetime;
	எனில் ((id = lookup_identity(k)) == வெற்று) {
		id = xcalloc(1, அளவு(Identity));
		TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
		/* Increment the number of identities. */
		idtab->nentries++;
	} இல்லையெனில் {
		/* identity not visible, do not update */
		எனில் (identity_permitted(id, e, வெற்று, வெற்று, வெற்று) != 0)
			செல் out; /* error already logged */
		/* key state might have been updated */
		sshkey_free(id->சாவி);
		விடுவி(id->comment);
		விடுவி(id->sk_provider);
		free_dest_constraints(id->dest_constraints,
		    id->ndest_constraints);
	}
	/* success */
	id->சாவி = k;
	id->comment = comment;
	id->death = death;
	id->confirm = confirm;
	id->sk_provider = sk_provider;
	id->dest_constraints = dest_constraints;
	id->ndest_constraints = ndest_constraints;

	எனில் ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == வெற்று)
		fatal_f("sshkey_fingerprint failed");
	debug_f("add %s %s \"%.100s\" (life: %u) (confirm: %u) "
	    "(provider: %s) (destination constraints: %zu)",
	    sshkey_ssh_name(k), fp, comment, seconds, confirm,
	    sk_provider == வெற்று ? "none" : sk_provider, ndest_constraints);
	விடுவி(fp);
	/* transferred */
	k = வெற்று;
	comment = வெற்று;
	sk_provider = வெற்று;
	dest_constraints = வெற்று;
	ndest_constraints = 0;
	success = 1;
 out:
	விடுவி(sk_provider);
	விடுவி(comment);
	sshkey_free(k);
	free_dest_constraints(dest_constraints, ndest_constraints);
	send_status(e, success);
}

/* XXX todo: encrypt sensitive data with passphrase */
நிலையான வெறுமை
process_lock_agent(SocketEntry *e, முழு lock)
{
	முழு r, success = 0, delay;
	எழுத்து *passwd;
	u_char passwdhash[LOCK_SIZE];
	நிலையான u_int fail_மொத்தம் = 0;
	size_t pwlen;

	debug2_f("entering");
	/*
	 * This is deliberately fatal: the user has requested that we lock,
	 * but we can't parse their request properly. The only safe thing to
	 * do is abort.
	 */
	எனில் ((r = sshbuf_get_cstring(e->request, &passwd, &pwlen)) != 0)
		fatal_fr(r, "parse");
	எனில் (pwlen == 0) {
		debug("empty password not supported");
	} இல்லையெனில் எனில் (locked && !lock) {
		எனில் (bcrypt_pbkdf(passwd, pwlen, lock_salt, அளவு(lock_salt),
		    passwdhash, அளவு(passwdhash), LOCK_ROUNDS) < 0)
			fatal("bcrypt_pbkdf");
		எனில் (timingsafe_bcmp(passwdhash, lock_pwhash, LOCK_SIZE) == 0) {
			debug("agent unlocked");
			locked = 0;
			fail_மொத்தம் = 0;
			explicit_bzero(lock_pwhash, அளவு(lock_pwhash));
			success = 1;
		} இல்லையெனில் {
			/* delay in 0.1s increments up to 10s */
			எனில் (fail_மொத்தம் < 100)
				fail_மொத்தம்++;
			delay = 100000 * fail_மொத்தம்;
			debug("unlock failed, delaying %0.1lf seconds",
			    (இரட்டை)delay/1000000);
			usleep(delay);
		}
		explicit_bzero(passwdhash, அளவு(passwdhash));
	} இல்லையெனில் எனில் (!locked && lock) {
		debug("agent locked");
		locked = 1;
		arc4random_buf(lock_salt, அளவு(lock_salt));
		எனில் (bcrypt_pbkdf(passwd, pwlen, lock_salt, அளவு(lock_salt),
		    lock_pwhash, அளவு(lock_pwhash), LOCK_ROUNDS) < 0)
			fatal("bcrypt_pbkdf");
		success = 1;
	}
	freezero(passwd, pwlen);
	send_status(e, success);
}

நிலையான வெறுமை
no_identities(SocketEntry *e)
{
	கட்டமைப்பு sshbuf *செய்தி;
	முழு r;

	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = sshbuf_put_u8(செய்தி, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
	    (r = sshbuf_put_u32(செய்தி, 0)) != 0 ||
	    (r = sshbuf_put_stringb(e->output, செய்தி)) != 0)
		fatal_fr(r, "compose");
	sshbuf_free(செய்தி);
}

#ifdef ENABLE_PKCS11
/* Add an identity to idlist; takes ownership of 'key' and 'comment' */
நிலையான வெறுமை
add_p11_identity(கட்டமைப்பு sshkey *சாவி, எழுத்து *comment, மாறிலி எழுத்து *provider,
    time_t death, u_int confirm, கட்டமைப்பு dest_constraint *dest_constraints,
    size_t ndest_constraints)
{
	Identity *id;

	எனில் (lookup_identity(சாவி) != வெற்று) {
		sshkey_free(சாவி);
		விடுவி(comment);
		திரும்பு;
	}
	id = xcalloc(1, அளவு(Identity));
	id->சாவி = சாவி;
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

நிலையான வெறுமை
process_add_smartcard_சாவி(SocketEntry *e)
{
	எழுத்து *provider = வெற்று, *pin = வெற்று, canonical_provider[PATH_MAX];
	எழுத்து **comments = வெற்று;
	முழு r, i, மொத்தம் = 0, success = 0, confirm = 0;
	u_int seconds = 0;
	time_t death = 0;
	கட்டமைப்பு sshkey **சாவிகள் = வெற்று, *k;
	கட்டமைப்பு dest_constraint *dest_constraints = வெற்று;
	size_t j, ndest_constraints = 0, ncerts = 0;
	கட்டமைப்பு sshkey **certs = வெற்று;
	முழு cert_only = 0;

	debug2_f("entering");
	எனில் ((r = sshbuf_get_cstring(e->request, &provider, வெற்று)) != 0 ||
	    (r = sshbuf_get_cstring(e->request, &pin, வெற்று)) != 0) {
		error_fr(r, "parse");
		செல் send;
	}
	எனில் (parse_சாவி_constraints(e->request, வெற்று, &death, &seconds, &confirm,
	    வெற்று, &dest_constraints, &ndest_constraints, &cert_only,
	    &ncerts, &certs) != 0) {
		error_f("failed to parse constraints");
		செல் send;
	}
	dump_dest_constraints(__func__, dest_constraints, ndest_constraints);
	எனில் (socket_is_remote(e) && !remote_add_provider) {
		verbose("failed PKCS#11 add of \"%.100s\": remote addition of "
		    "providers is disabled", provider);
		செல் send;
	}
	எனில் (realpath(provider, canonical_provider) == வெற்று) {
		verbose("failed PKCS#11 add of \"%.100s\": realpath: %s",
		    provider, strerror(errno));
		செல் send;
	}
	எனில் (match_pattern_list(canonical_provider, allowed_providers, 0) != 1) {
		verbose("refusing PKCS#11 add of \"%.100s\": "
		    "provider not allowed", canonical_provider);
		செல் send;
	}
	debug_f("add %.100s", canonical_provider);
	எனில் (lifetime && !death)
		death = monotime() + lifetime;

	மொத்தம் = pkcs11_add_provider(canonical_provider, pin, &சாவிகள், &comments);
	க்கு (i = 0; i < மொத்தம்; i++) {
		எனில் (comments[i] == வெற்று || comments[i][0] == '\0') {
			விடுவி(comments[i]);
			comments[i] = xstrdup(canonical_provider);
		}
		க்கு (j = 0; j < ncerts; j++) {
			எனில் (!sshkey_is_cert(certs[j]))
				தொடர்;
			எனில் (!sshkey_equal_public(சாவிகள்[i], certs[j]))
				தொடர்;
			எனில் (pkcs11_make_cert(சாவிகள்[i], certs[j], &k) != 0)
				தொடர்;
			add_p11_identity(k, xstrdup(comments[i]),
			    canonical_provider, death, confirm,
			    dest_constraints, ndest_constraints);
			success = 1;
		}
		எனில் (!cert_only && lookup_identity(சாவிகள்[i]) == வெற்று) {
			add_p11_identity(சாவிகள்[i], comments[i],
			    canonical_provider, death, confirm,
			    dest_constraints, ndest_constraints);
			சாவிகள்[i] = வெற்று;		/* transferred */
			comments[i] = வெற்று;	/* transferred */
			success = 1;
		}
		/* XXX update constraints for existing keys */
		sshkey_free(சாவிகள்[i]);
		விடுவி(comments[i]);
	}
send:
	விடுவி(pin);
	விடுவி(provider);
	விடுவி(சாவிகள்);
	விடுவி(comments);
	free_dest_constraints(dest_constraints, ndest_constraints);
	க்கு (j = 0; j < ncerts; j++)
		sshkey_free(certs[j]);
	விடுவி(certs);
	send_status(e, success);
}

நிலையான வெறுமை
process_remove_smartcard_சாவி(SocketEntry *e)
{
	எழுத்து *provider = வெற்று, *pin = வெற்று, canonical_provider[PATH_MAX];
	முழு r, success = 0;
	Identity *id, *nxt;

	debug2_f("entering");
	எனில் ((r = sshbuf_get_cstring(e->request, &provider, வெற்று)) != 0 ||
	    (r = sshbuf_get_cstring(e->request, &pin, வெற்று)) != 0) {
		error_fr(r, "parse");
		செல் send;
	}
	விடுவி(pin);

	எனில் (realpath(provider, canonical_provider) == வெற்று) {
		verbose("failed PKCS#11 add of \"%.100s\": realpath: %s",
		    provider, strerror(errno));
		செல் send;
	}

	debug_f("remove %.100s", canonical_provider);
	க்கு (id = TAILQ_FIRST(&idtab->idlist); id; id = nxt) {
		nxt = TAILQ_NEXT(id, next);
		/* Skip file--based keys */
		எனில் (id->provider == வெற்று)
			தொடர்;
		எனில் (!strcmp(canonical_provider, id->provider)) {
			TAILQ_REMOVE(&idtab->idlist, id, next);
			free_identity(id);
			idtab->nentries--;
		}
	}
	எனில் (pkcs11_del_provider(canonical_provider) == 0)
		success = 1;
	இல்லையெனில்
		error_f("pkcs11_del_provider failed");
send:
	விடுவி(provider);
	send_status(e, success);
}
#endif /* ENABLE_PKCS11 */

நிலையான முழு
process_ext_session_bind(SocketEntry *e)
{
	முழு r, sid_match, சாவி_match;
	கட்டமைப்பு sshkey *சாவி = வெற்று;
	கட்டமைப்பு sshbuf *sid = வெற்று, *sig = வெற்று;
	எழுத்து *fp = வெற்று;
	size_t i;
	u_char fwd = 0;

	debug2_f("entering");
	e->session_bind_attempted = 1;
	எனில் ((r = sshkey_froms(e->request, &சாவி)) != 0 ||
	    (r = sshbuf_froms(e->request, &sid)) != 0 ||
	    (r = sshbuf_froms(e->request, &sig)) != 0 ||
	    (r = sshbuf_get_u8(e->request, &fwd)) != 0) {
		error_fr(r, "parse");
		செல் out;
	}
	எனில் (sshbuf_len(sid) > AGENT_MAX_SID_LEN) {
		error_f("session ID too long");
		செல் out;
	}
	எனில் ((fp = sshkey_fingerprint(சாவி, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == வெற்று)
		fatal_f("fingerprint failed");
	/* check signature with hostkey on session ID */
	எனில் ((r = sshkey_verify(சாவி, sshbuf_ptr(sig), sshbuf_len(sig),
	    sshbuf_ptr(sid), sshbuf_len(sid), வெற்று, 0, வெற்று)) != 0) {
		error_fr(r, "sshkey_verify for %s %s", sshkey_type(சாவி), fp);
		செல் out;
	}
	/* check whether sid/key already recorded */
	க்கு (i = 0; i < e->nsession_ids; i++) {
		எனில் (!e->session_ids[i].forwarded) {
			error_f("attempt to bind session ID to socket "
			    "previously bound for authentication attempt");
			r = -1;
			செல் out;
		}
		sid_match = buf_equal(sid, e->session_ids[i].sid) == 0;
		சாவி_match = sshkey_equal(சாவி, e->session_ids[i].சாவி);
		எனில் (sid_match && சாவி_match) {
			debug_f("session ID already recorded for %s %s",
			    sshkey_type(சாவி), fp);
			r = 0;
			செல் out;
		} இல்லையெனில் எனில் (sid_match) {
			error_f("session ID recorded against different key "
			    "for %s %s", sshkey_type(சாவி), fp);
			r = -1;
			செல் out;
		}
		/*
		 * new sid with previously-seen key can happen, e.g. multiple
		 * connections to the same host.
		 */
	}
	/* record new key/sid */
	எனில் (e->nsession_ids >= AGENT_MAX_SESSION_IDS) {
		error_f("too many session IDs recorded");
		r = -1;
		செல் out;
	}
	e->session_ids = xrecallocarray(e->session_ids, e->nsession_ids,
	    e->nsession_ids + 1, அளவு(*e->session_ids));
	i = e->nsession_ids++;
	debug_f("recorded %s %s (slot %zu of %d)", sshkey_type(சாவி), fp, i,
	    AGENT_MAX_SESSION_IDS);
	e->session_ids[i].சாவி = சாவி;
	e->session_ids[i].forwarded = fwd != 0;
	சாவி = வெற்று; /* transferred */
	/* can't transfer sid; it's refcounted and scoped to request's life */
	எனில் ((e->session_ids[i].sid = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new");
	எனில் ((r = sshbuf_putb(e->session_ids[i].sid, sid)) != 0)
		fatal_fr(r, "sshbuf_putb session ID");
	/* success */
	r = 0;
 out:
	விடுவி(fp);
	sshkey_free(சாவி);
	sshbuf_free(sid);
	sshbuf_free(sig);
	திரும்பு r == 0 ? 1 : 0;
}

நிலையான முழு
process_ext_query(SocketEntry *e)
{
	முழு r;
	கட்டமைப்பு sshbuf *செய்தி = வெற்று;

	debug2_f("entering");
	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = sshbuf_put_u8(செய்தி, SSH_AGENT_EXTENSION_RESPONSE)) != 0 ||
	    (r = sshbuf_put_cstring(செய்தி, "query")) != 0 ||
	    /* string[]     supported extension types */
	    (r = sshbuf_put_cstring(செய்தி, "session-bind@openssh.com")) != 0)
		fatal_fr(r, "compose");
	எனில் ((r = sshbuf_put_stringb(e->output, செய்தி)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(செய்தி);
	திரும்பு 1;
}

நிலையான வெறுமை
process_extension(SocketEntry *e)
{
	முழு r, replied = 0, success = 0;
	எழுத்து *name;

	debug2_f("entering");
	எனில் ((r = sshbuf_get_cstring(e->request, &name, வெற்று)) != 0) {
		error_fr(r, "parse");
		send_status(e, 0);
		திரும்பு;
	}

	/*
	 * This function can be called while the agent is locked to allow
	 * session binds to be processed for new channels.
	 * Other operations should be refused when locked.
	 */

	எனில் (strcmp(name, "session-bind@openssh.com") == 0) {
		success = process_ext_session_bind(e);
	} இல்லையெனில் எனில் (locked) {
		debug_f("attempt to use extension \"%s\" while locked", name);
		செல் generic_fail;
	} இல்லையெனில் எனில் (strcmp(name, "query") == 0) {
		replied = success = process_ext_query(e);
	} இல்லையெனில் {
		debug_f("unsupported extension \"%s\"", name);
 generic_fail:
		விடுவி(name);
		send_status(e, 0);
		திரும்பு;
	}
	விடுவி(name);
	/* Agent failures are signalled with a different error code */
	எனில் (!replied) {
		send_status_generic(e,
		    success ? SSH_AGENT_SUCCESS : SSH_AGENT_EXTENSION_FAILURE);
	}
}

/*
 * dispatch incoming message.
 * returns 1 on success, 0 for incomplete messages or -1 on error.
 */
நிலையான முழு
process_message(u_int socknum)
{
	u_int செய்தி_len;
	u_char type;
	மாறிலி u_char *cp;
	முழு r;
	SocketEntry *e;

	எனில் (socknum >= sockets_alloc)
		fatal_f("sock %u >= allocated %u", socknum, sockets_alloc);
	e = &sockets[socknum];

	எனில் (sshbuf_len(e->உள்ளீடு) < 5)
		திரும்பு 0;		/* Incomplete message header. */
	cp = sshbuf_ptr(e->உள்ளீடு);
	செய்தி_len = PEEK_U32(cp);
	எனில் (செய்தி_len > AGENT_MAX_LEN) {
		debug_f("socket %u (fd=%d) message too long %u > %u",
		    socknum, e->fd, செய்தி_len, AGENT_MAX_LEN);
		திரும்பு -1;
	}
	எனில் (sshbuf_len(e->உள்ளீடு) < செய்தி_len + 4)
		திரும்பு 0;		/* Incomplete message body. */

	/* move the current input to e->request */
	sshbuf_reset(e->request);
	எனில் ((r = sshbuf_get_stringb(e->உள்ளீடு, e->request)) != 0 ||
	    (r = sshbuf_get_u8(e->request, &type)) != 0) {
		எனில் (r == SSH_ERR_MESSAGE_INCOMPLETE ||
		    r == SSH_ERR_STRING_TOO_LARGE) {
			error_fr(r, "parse");
			திரும்பு -1;
		}
		fatal_fr(r, "parse");
	}

	debug_f("socket %u (fd=%d) type %d", socknum, e->fd, type);

	/* check whether agent is locked */
	எனில் (locked && type != SSH_AGENTC_UNLOCK) {
		தேர்வு (type) {
		நிலை SSH2_AGENTC_REQUEST_IDENTITIES:
			/* send empty lists */
			no_identities(e);
			நிறுத்து;
		நிலை SSH_AGENTC_EXTENSION:
			process_extension(e);
			நிறுத்து;
		இயல்பு:
			/* send a fail message for all other request types */
			send_status(e, 0);
		}
		sshbuf_reset(e->request);
		திரும்பு 1;
	}

	தேர்வு (type) {
	நிலை SSH_AGENTC_LOCK:
	நிலை SSH_AGENTC_UNLOCK:
		process_lock_agent(e, type == SSH_AGENTC_LOCK);
		நிறுத்து;
	நிலை SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES:
		process_remove_all_identities(e); /* safe for !WITH_SSH1 */
		நிறுத்து;
	/* ssh2 */
	நிலை SSH2_AGENTC_SIGN_REQUEST:
		process_sign_request2(e);
		நிறுத்து;
	நிலை SSH2_AGENTC_REQUEST_IDENTITIES:
		process_request_identities(e);
		நிறுத்து;
	நிலை SSH2_AGENTC_ADD_IDENTITY:
	நிலை SSH2_AGENTC_ADD_ID_CONSTRAINED:
		process_add_identity(e);
		நிறுத்து;
	நிலை SSH2_AGENTC_REMOVE_IDENTITY:
		process_remove_identity(e);
		நிறுத்து;
	நிலை SSH2_AGENTC_REMOVE_ALL_IDENTITIES:
		process_remove_all_identities(e);
		நிறுத்து;
#ifdef ENABLE_PKCS11
	நிலை SSH_AGENTC_ADD_SMARTCARD_சாவி:
	நிலை SSH_AGENTC_ADD_SMARTCARD_சாவி_CONSTRAINED:
		process_add_smartcard_சாவி(e);
		நிறுத்து;
	நிலை SSH_AGENTC_REMOVE_SMARTCARD_சாவி:
		process_remove_smartcard_சாவி(e);
		நிறுத்து;
#endif /* ENABLE_PKCS11 */
	நிலை SSH_AGENTC_EXTENSION:
		process_extension(e);
		நிறுத்து;
	இயல்பு:
		/* Unknown message.  Respond with failure. */
		error("Unknown message %d", type);
		sshbuf_reset(e->request);
		send_status(e, 0);
		நிறுத்து;
	}
	திரும்பு 1;
}

நிலையான வெறுமை
new_socket(sock_type type, முழு fd)
{
	u_int i, old_alloc, new_alloc;

	debug_f("type = %s", type == AUTH_CONNECTION ? "CONNECTION" :
	    (type == AUTH_SOCKET ? "SOCKET" : "UNKNOWN"));
	set_nonblock(fd);

	எனில் (fd > max_fd)
		max_fd = fd;

	க்கு (i = 0; i < sockets_alloc; i++)
		எனில் (sockets[i].type == AUTH_UNUSED) {
			sockets[i].fd = fd;
			எனில் ((sockets[i].உள்ளீடு = sshbuf_new()) == வெற்று ||
			    (sockets[i].output = sshbuf_new()) == வெற்று ||
			    (sockets[i].request = sshbuf_new()) == வெற்று)
				fatal_f("sshbuf_new failed");
			sockets[i].type = type;
			திரும்பு;
		}
	old_alloc = sockets_alloc;
	new_alloc = sockets_alloc + 10;
	sockets = xrecallocarray(sockets, old_alloc, new_alloc,
	    அளவு(sockets[0]));
	க்கு (i = old_alloc; i < new_alloc; i++)
		sockets[i].type = AUTH_UNUSED;
	sockets_alloc = new_alloc;
	sockets[old_alloc].fd = fd;
	எனில் ((sockets[old_alloc].உள்ளீடு = sshbuf_new()) == வெற்று ||
	    (sockets[old_alloc].output = sshbuf_new()) == வெற்று ||
	    (sockets[old_alloc].request = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	sockets[old_alloc].type = type;
}

நிலையான முழு
handle_socket_read(u_int socknum)
{
	கட்டமைப்பு sockaddr_un sunaddr;
	socklen_t slen;
	uid_t euid;
	gid_t egid;
	முழு fd;

	slen = அளவு(sunaddr);
	fd = accept(sockets[socknum].fd, (கட்டமைப்பு sockaddr *)&sunaddr, &slen);
	எனில் (fd == -1) {
		error("accept from AUTH_SOCKET: %s", strerror(errno));
		திரும்பு -1;
	}
	எனில் (getpeereid(fd, &euid, &egid) == -1) {
		error("getpeereid %d failed: %s", fd, strerror(errno));
		close(fd);
		திரும்பு -1;
	}
	எனில் ((euid != 0) && (getuid() != euid)) {
		error("uid mismatch: peer euid %u != uid %u",
		    (u_int) euid, (u_int) getuid());
		close(fd);
		திரும்பு -1;
	}
	new_socket(AUTH_CONNECTION, fd);
	திரும்பு 0;
}

நிலையான முழு
handle_conn_read(u_int socknum)
{
	எழுத்து buf[AGENT_RBUF_LEN];
	ssize_t len;
	முழு r;

	எனில் ((len = பட(sockets[socknum].fd, buf, அளவு(buf))) <= 0) {
		எனில் (len == -1) {
			எனில் (errno == EAGAIN || errno == EINTR)
				திரும்பு 0;
			error_f("read error on socket %u (fd %d): %s",
			    socknum, sockets[socknum].fd, strerror(errno));
		}
		திரும்பு -1;
	}
	எனில் ((r = sshbuf_put(sockets[socknum].உள்ளீடு, buf, len)) != 0)
		fatal_fr(r, "compose");
	explicit_bzero(buf, அளவு(buf));
	க்கு (;;) {
		எனில் ((r = process_message(socknum)) == -1)
			திரும்பு -1;
		இல்லையெனில் எனில் (r == 0)
			நிறுத்து;
	}
	திரும்பு 0;
}

நிலையான முழு
handle_conn_write(u_int socknum)
{
	ssize_t len;
	முழு r;

	எனில் (sshbuf_len(sockets[socknum].output) == 0)
		திரும்பு 0; /* shouldn't happen */
	எனில் ((len = லிக(sockets[socknum].fd,
	    sshbuf_ptr(sockets[socknum].output),
	    sshbuf_len(sockets[socknum].output))) <= 0) {
		எனில் (len == -1) {
			எனில் (errno == EAGAIN || errno == EINTR)
				திரும்பு 0;
			error_f("read error on socket %u (fd %d): %s",
			    socknum, sockets[socknum].fd, strerror(errno));
		}
		திரும்பு -1;
	}
	எனில் ((r = sshbuf_consume(sockets[socknum].output, len)) != 0)
		fatal_fr(r, "consume");
	திரும்பு 0;
}

நிலையான வெறுமை
after_poll(கட்டமைப்பு pollfd *pfd, size_t npfd, u_int maxfds)
{
	size_t i;
	u_int socknum, activefds = npfd;

	க்கு (i = 0; i < npfd; i++) {
		எனில் (pfd[i].revents == 0)
			தொடர்;
		/* Find sockets entry */
		க்கு (socknum = 0; socknum < sockets_alloc; socknum++) {
			எனில் (sockets[socknum].type != AUTH_SOCKET &&
			    sockets[socknum].type != AUTH_CONNECTION)
				தொடர்;
			எனில் (pfd[i].fd == sockets[socknum].fd)
				நிறுத்து;
		}
		எனில் (socknum >= sockets_alloc) {
			error_f("no socket for fd %d", pfd[i].fd);
			தொடர்;
		}
		/* Process events */
		தேர்வு (sockets[socknum].type) {
		நிலை AUTH_SOCKET:
			எனில் ((pfd[i].revents & (POLLIN|POLLERR)) == 0)
				நிறுத்து;
			எனில் (npfd > maxfds) {
				debug3("out of fds (active %u >= limit %u); "
				    "skipping accept", activefds, maxfds);
				நிறுத்து;
			}
			எனில் (handle_socket_read(socknum) == 0)
				activefds++;
			நிறுத்து;
		நிலை AUTH_CONNECTION:
			எனில் ((pfd[i].revents & (POLLIN|POLLHUP|POLLERR)) != 0 &&
			    handle_conn_read(socknum) != 0)
				செல் close_sock;
			எனில் ((pfd[i].revents & (POLLOUT|POLLHUP)) != 0 &&
			    handle_conn_write(socknum) != 0) {
 close_sock:
				எனில் (activefds == 0)
					fatal("activefds == 0 at close_sock");
				close_socket(&sockets[socknum]);
				activefds--;
				நிறுத்து;
			}
			நிறுத்து;
		இயல்பு:
			நிறுத்து;
		}
	}
}

நிலையான முழு
prepare_poll(கட்டமைப்பு pollfd **pfdp, size_t *npfdp, கட்டமைப்பு timespec *timeoutp, u_int maxfds)
{
	கட்டமைப்பு pollfd *pfd = *pfdp;
	size_t i, j, npfd = 0;
	time_t deadline;
	முழு r;

	/* Count active sockets */
	க்கு (i = 0; i < sockets_alloc; i++) {
		தேர்வு (sockets[i].type) {
		நிலை AUTH_SOCKET:
		நிலை AUTH_CONNECTION:
			npfd++;
			நிறுத்து;
		நிலை AUTH_UNUSED:
			நிறுத்து;
		இயல்பு:
			fatal("Unknown socket type %d", sockets[i].type);
			நிறுத்து;
		}
	}
	எனில் (npfd != *npfdp &&
	    (pfd = recallocarray(pfd, *npfdp, npfd, அளவு(*pfd))) == வெற்று)
		fatal_f("recallocarray failed");
	*pfdp = pfd;
	*npfdp = npfd;

	க்கு (i = j = 0; i < sockets_alloc; i++) {
		தேர்வு (sockets[i].type) {
		நிலை AUTH_SOCKET:
			எனில் (npfd > maxfds) {
				debug3("out of fds (active %zu >= limit %u); "
				    "skipping arming listener", npfd, maxfds);
				நிறுத்து;
			}
			pfd[j].fd = sockets[i].fd;
			pfd[j].revents = 0;
			pfd[j].events = POLLIN;
			j++;
			நிறுத்து;
		நிலை AUTH_CONNECTION:
			pfd[j].fd = sockets[i].fd;
			pfd[j].revents = 0;
			/*
			 * Only prepare to read if we can handle a full-size
			 * input read buffer and enqueue a max size reply..
			 */
			எனில் ((r = sshbuf_check_reserve(sockets[i].உள்ளீடு,
			    AGENT_RBUF_LEN)) == 0 &&
			    (r = sshbuf_check_reserve(sockets[i].output,
			    AGENT_MAX_LEN)) == 0)
				pfd[j].events = POLLIN;
			இல்லையெனில் எனில் (r != SSH_ERR_NO_BUFFER_SPACE)
				fatal_fr(r, "reserve");
			எனில் (sshbuf_len(sockets[i].output) > 0)
				pfd[j].events |= POLLOUT;
			j++;
			நிறுத்து;
		இயல்பு:
			நிறுத்து;
		}
	}
	deadline = reaper();
	எனில் (parent_alive_interval != 0)
		deadline = (deadline == 0) ? parent_alive_interval :
		    MINIMUM(deadline, parent_alive_interval);
	எனில் (deadline != 0)
		ptimeout_deadline_sec(timeoutp, deadline);
	திரும்பு (1);
}

நிலையான வெறுமை
cleanup_socket(வெறுமை)
{
	எனில் (cleanup_pid != 0 && getpid() != cleanup_pid)
		திரும்பு;
	debug_f("cleanup");
	எனில் (socket_name != வெற்று) {
		agent_listener_cleanup(socket_dirspec, socket_name, socket_dir);
		விடுவி(socket_name);
		socket_name = வெற்று;
		விடுவி(socket_dir);
		socket_dir = வெற்று;
	}
}

வெறுமை
cleanup_exit(முழு i)
{
	cleanup_socket();
#ifdef ENABLE_PKCS11
	pkcs11_terminate();
#endif
	_exit(i);
}

நிலையான வெறுமை
cleanup_handler(முழு sig)
{
	signalled_exit = sig;
}

நிலையான வெறுமை
keydrop_handler(முழு sig)
{
	signalled_keydrop = sig;
}

நிலையான வெறுமை
check_parent_exists(வெறுமை)
{
	/*
	 * If our parent has exited then getppid() will return (pid_t)1,
	 * so testing for that should be safe.
	 */
	எனில் (parent_pid != -1 && getppid() != parent_pid) {
		/* printf("Parent has died - Authentication agent exiting.\n"); */
		cleanup_socket();
		_exit(2);
	}
}

நிலையான வெறுமை
usage(வெறுமை)
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

முழு
முதன்மை(முழு ac, எழுத்து **av)
{
	முழு c_flag = 0, d_flag = 0, D_flag = 0, k_flag = 0;
	முழு s_flag = 0, T_flag = 0, u_flag = 0, U_flag = 0;
	முழு sock = -1, ch, result, saved_errno;
	pid_t pid;
 	எழுத்து *homedir = வெற்று, *shell, *format, *pidstr, *agentsocket = வெற்று;
	எழுத்து *cp, pidstrbuf[1 + 3 * அளவு pid];
	எழுத்து *fdstr;
	மாறிலி எழுத்து *errstr = வெற்று;
	மாறிலி எழுத்து *ccp;
#ifdef HAVE_SETRLIMIT
	கட்டமைப்பு rlimit rlim;
#endif
	வெளி முழு optind;
	வெளி எழுத்து *optarg;
	size_t len;
	mode_t prev_mask;
	கட்டமைப்பு timespec timeout;
	கட்டமைப்பு pollfd *pfd = வெற்று;
	size_t npfd = 0;
	u_int maxfds;
	sigset_t nsigset, osigset;
	முழு socket_activated = 0;
	கட்டமைப்பு passwd *pw;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* drop */
	(வெறுமை)setegid(getgid());
	(வெறுமை)setgid(getgid());

	platform_disable_tracing(0);	/* strict=no */

	எனில் ((pw = getpwuid(getuid())) == வெற்று)
		fatal("No user exists for uid %lu", (u_long)getuid());
	pw = pwcopy(pw);

#ifdef RLIMIT_NOFILE
	எனில் (getrlimit(RLIMIT_NOFILE, &rlim) == -1)
		fatal("%s: getrlimit: %s", __progname, strerror(errno));
#endif

	__progname = ssh_get_progname(av[0]);
	seed_rng();

	போது ((ch = getopt(ac, av, "cDdksTuUVA:E:a:O:P:t:")) != -1) {
		தேர்வு (ch) {
		நிலை 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			எனில் (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			நிறுத்து;
		நிலை 'c':
			எனில் (s_flag)
				usage();
			c_flag++;
			நிறுத்து;
		நிலை 'k':
			k_flag++;
			நிறுத்து;
		நிலை 'O':
			எனில் (strcmp(optarg, "no-restrict-websafe") == 0)
				restrict_websafe = 0;
			இல்லையெனில் எனில் (strcmp(optarg, "allow-remote-pkcs11") == 0)
				remote_add_provider = 1;
			இல்லையெனில் எனில் ((ccp = strprefix(optarg,
			    "websafe-allow=", 0)) != வெற்று) {
				எனில் (websafe_allowlist != வெற்று)
					fatal("websafe-allow already set");
				websafe_allowlist = xstrdup(ccp);
			} இல்லையெனில்
				fatal("Unknown -O option");
			நிறுத்து;
		நிலை 'P':
			எனில் (allowed_providers != வெற்று)
				fatal("-P option already specified");
			allowed_providers = xstrdup(optarg);
			நிறுத்து;
		நிலை 's':
			எனில் (c_flag)
				usage();
			s_flag++;
			நிறுத்து;
		நிலை 'd':
			எனில் (d_flag || D_flag)
				usage();
			d_flag++;
			நிறுத்து;
		நிலை 'D':
			எனில் (d_flag || D_flag)
				usage();
			D_flag++;
			நிறுத்து;
		நிலை 'a':
			agentsocket = optarg;
			நிறுத்து;
		நிலை 'A':
			socket_dirspec = xstrdup(optarg);
			நிறுத்து;
		நிலை 't':
			எனில் ((lifetime = convtime(optarg)) == -1) {
				fprintf(stderr, "Invalid lifetime\n");
				usage();
			}
			நிறுத்து;
		நிலை 'T':
			T_flag++;
			நிறுத்து;
		நிலை 'u':
			u_flag++;
			நிறுத்து;
		நிலை 'U':
			U_flag++;
			நிறுத்து;
		நிலை 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_VERSION, SSH_OPENSSL_VERSION);
			exit(0);
		இயல்பு:
			usage();
		}
	}
	ac -= optind;
	av += optind;

	எனில் (ac > 0 &&
	    (c_flag || k_flag || s_flag || d_flag || D_flag || u_flag))
		usage();
	/* only one of -a, -A and -T allowed */
	எனில் (((socket_dirspec != வெற்று) + (agentsocket != வெற்று) + T_flag) > 1)
		usage();

	log_init(__progname,
	    d_flag ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
	    SYSLOG_FACILITY_AUTH, 1);

	எனில் (allowed_providers == வெற்று)
		allowed_providers = xstrdup(DEFAULT_ALLOWED_PROVIDERS);
	எனில் (websafe_allowlist == வெற்று)
		websafe_allowlist = xstrdup(DEFAULT_WEBSAFE_ALLOWLIST);

	எனில் (T_flag)
		socket_dirspec = xstrdup(_PATH_SSH_AGENT_SOCKET_TMPDIR);
	இல்லையெனில் எனில் (socket_dirspec == வெற்று && agentsocket == வெற்று)
		socket_dirspec = xstrdup(_PATH_SSH_AGENT_SOCKET_DIR);

	எனில் (ac == 0 && !c_flag && !s_flag) {
		shell = getenv("SHELL");
		எனில் (shell != வெற்று && (len = strlen(shell)) > 2 &&
		    strncmp(shell + len - 3, "csh", 3) == 0)
			c_flag = 1;
	}
	எனில் (k_flag) {
		pidstr = getenv(SSH_AGENTPID_ENV_NAME);
		எனில் (pidstr == வெற்று) {
			fprintf(stderr, "%s not set, cannot kill agent\n",
			    SSH_AGENTPID_ENV_NAME);
			exit(1);
		}
		pid = (முழு)strtonum(pidstr, 2, INT_MAX, &errstr);
		எனில் (errstr) {
			fprintf(stderr,
			    "%s=\"%s\", which is not a good PID: %s\n",
			    SSH_AGENTPID_ENV_NAME, pidstr, errstr);
			exit(1);
		}
		எனில் (kill(pid, SIGTERM) == -1) {
			perror("kill");
			exit(1);
		}
		format = c_flag ? "unsetenv %s;\n" : "unset %s;\n";
		printf(format, SSH_AUTHSOCKET_ENV_NAME);
		printf(format, SSH_AGENTPID_ENV_NAME);
		printf("echo Agent pid %ld killed;\n", (long)pid);
		exit(0);
	}
	எனில் (u_flag) {
		எனில் ((homedir = get_homedir()) == வெற்று)
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
	எனில் (rlim.rlim_cur < SSH_AGENT_MIN_FDS)
		fatal("%s: file descriptor rlimit %lld too low (minimum %u)",
		    __progname, (long long)rlim.rlim_cur, SSH_AGENT_MIN_FDS);
	maxfds = rlim.rlim_cur - SSH_AGENT_MIN_FDS;

	parent_pid = getpid();

	/* Has the socket been provided via socket activation? */
	எனில் (agentsocket == வெற்று && ac == 0 && (d_flag || D_flag) &&
	    (pidstr = getenv("LISTEN_PID")) != வெற்று &&
	    (fdstr = getenv("LISTEN_FDS")) != வெற்று) {
		எனில் (strcmp(fdstr, "1") != 0) {
			fatal("unexpected LISTEN_FDS contents "
			    "(want: \"1\" got\"%s\"", fdstr);
		}
		எனில் (fcntl(3, F_GETFL) == -1)
			fatal("LISTEN_FDS set but fd 3 unavailable");
		pid = (முழு)strtonum(pidstr, 1, INT_MAX, &errstr);
		எனில் (errstr != வெற்று)
			fatal("invalid LISTEN_PID: %s", errstr);
		எனில் (pid != getpid())
			fatal("bad LISTEN_PID: %d vs pid %d", pid, getpid());
		debug("using socket activation on fd=3");
		sock = 3;
		socket_activated = 1;
	}

	எனில் (sock == -1 && agentsocket == வெற்று) {
		/* Listen on a socket in/under a given directory */
		எனில் ((homedir = get_homedir()) == வெற்று)
			fatal("Couldn't determine home directory");
		எனில் (!U_flag) {
			agent_cleanup_stale(socket_dirspec,
			    pw->pw_name, pw->pw_uid, homedir, 0);
		}
		எனில் (agent_listener(socket_dirspec, pw->pw_name, pw->pw_uid,
		    homedir, getpid(), "local", &sock, &socket_name,
		    &socket_dir) != 0)
			fatal_f("Couldn't prepare agent socket");
		விடுவி(homedir);
	} இல்லையெனில் எனில் (sock == -1) {
		/* Listen on explicit socket path */
		prev_mask = umask(0177);
		socket_name = xstrdup(agentsocket);
		எனில் ((sock = unix_listener(socket_name,
		    SSH_LISTEN_BACKLOG, 0)) < 0) {
			விடுவி(socket_name);
			socket_name = வெற்று; /* Don't unlink existing file */
			cleanup_exit(1);
		}
		umask(prev_mask);
	}

	closefrom(sock == -1 ? STDERR_FILENO + 1 : sock + 1);

	/*
	 * Create socket early so it will exist before command gets run from
	 * the parent.
	 */
	எனில் (sock == -1) {
		prev_mask = umask(0177);
		sock = unix_listener(socket_name, SSH_LISTEN_BACKLOG, 0);
		எனில் (sock < 0) {
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
	எனில் (D_flag || d_flag) {
		log_init(__progname,
		    d_flag ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
		    SYSLOG_FACILITY_AUTH, 1);
		எனில் (socket_name != வெற்று) {
			cp = argv_assemble(1, &socket_name);
			format = c_flag ?
			    "setenv %s %s;\n" : "%s=%s; export %s;\n";
			printf(format, SSH_AUTHSOCKET_ENV_NAME, cp,
			    SSH_AUTHSOCKET_ENV_NAME);
			விடுவி(cp);
			printf("echo Agent pid %ld;\n", (long)parent_pid);
			fflush(stdout);
		}
		செல் skip;
	}
	pid = fork();
	எனில் (pid == -1) {
		perror("fork");
		cleanup_exit(1);
	}
	எனில் (pid != 0) {		/* Parent - execute the given command. */
		close(sock);
		snprintf(pidstrbuf, அளவு pidstrbuf, "%ld", (long)pid);
		எனில் (ac == 0) {
			format = c_flag ? "setenv %s %s;\n" : "%s=%s; export %s;\n";
			cp = argv_assemble(1, &socket_name);
			printf(format, SSH_AUTHSOCKET_ENV_NAME, cp,
			    SSH_AUTHSOCKET_ENV_NAME);
			printf(format, SSH_AGENTPID_ENV_NAME, pidstrbuf,
			    SSH_AGENTPID_ENV_NAME);
			விடுவி(cp);
			printf("echo Agent pid %ld;\n", (long)pid);
			exit(0);
		}
		எனில் (setenv(SSH_AUTHSOCKET_ENV_NAME, socket_name, 1) == -1 ||
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

	எனில் (setsid() == -1) {
		error("setsid: %s", strerror(errno));
		cleanup_exit(1);
	}

	(வெறுமை)chdir("/");
	எனில் (stdfd_devnull(1, 1, 1) == -1)
		error_f("stdfd_devnull failed");

#ifdef HAVE_SETRLIMIT
	/* deny core dumps, since memory contains unencrypted private keys */
	rlim.rlim_cur = rlim.rlim_max = 0;
	எனில் (setrlimit(RLIMIT_CORE, &rlim) == -1) {
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
	எனில் (ac > 0)
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

	எனில் (socket_name != வெற்று && unveil(socket_name, "c") == -1) {
		fatal("%s: unveil %s %s", __progname, socket_name,
		    strerror(errno));
	}
	எனில் (socket_dir != வெற்று && unveil(socket_dir, "c") == -1) {
		fatal("%s: unveil %s %s", __progname, socket_dir,
		    strerror(errno));
	}
	எனில் (unveil("/", "r") == -1)
		fatal("%s: unveil /: %s", __progname, strerror(errno));
	எனில் ((ccp = getenv("SSH_SK_HELPER")) == வெற்று || *ccp == '\0')
		ccp = _PATH_SSH_SK_HELPER;
	எனில் (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, strerror(errno));
	எனில் ((ccp = getenv("SSH_PKCS11_HELPER")) == வெற்று || *ccp == '\0')
		ccp = _PATH_SSH_PKCS11_HELPER;
	எனில் (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, strerror(errno));
	எனில் ((ccp = getenv("SSH_ASKPASS")) == வெற்று || *ccp == '\0')
		ccp = _PATH_SSH_ASKPASS_DEFAULT;
	எனில் (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, strerror(errno));
	எனில் (unveil("/dev/null", "rw") == -1)
		fatal("%s: unveil /dev/null: %s", __progname, strerror(errno));
	எனில் (pledge("stdio rpath cpath wpath unix id proc exec", வெற்று) == -1)
		fatal("%s: pledge: %s", __progname, strerror(errno));
	platform_pledge_agent();

	போது (1) {
		sigprocmask(SIG_BLOCK, &nsigset, &osigset);
		எனில் (signalled_exit != 0) {
			logit("exiting on signal %d", (முழு)signalled_exit);
			cleanup_exit((signalled_exit == SIGTERM &&
			    socket_activated) ? 0 : 2);
		}
		எனில் (signalled_keydrop) {
			logit("signal %d received; removing all keys",
			    (முழு)signalled_keydrop);
			remove_all_identities();
			signalled_keydrop = 0;
		}
		ptimeout_init(&timeout);
		prepare_poll(&pfd, &npfd, &timeout, maxfds);
		result = ppoll(pfd, npfd, ptimeout_get_tsp(&timeout), &osigset);
		sigprocmask(SIG_SETMASK, &osigset, வெற்று);
		saved_errno = errno;
		எனில் (parent_alive_interval != 0)
			check_parent_exists();
		(வெறுமை) reaper();	/* remove expired keys */
		எனில் (result == -1) {
			எனில் (saved_errno == EINTR)
				தொடர்;
			fatal("poll: %s", strerror(saved_errno));
		} இல்லையெனில் எனில் (result > 0)
			after_poll(pfd, npfd, maxfds);
	}
	/* NOTREACHED */
}
