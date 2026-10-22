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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/time.h>
#অন্তর্ভাব <sys/queue.h>
#অন্তর্ভাব <sys/resource.h>
#অন্তর্ভাব <sys/socket.h>
#অন্তর্ভাব <sys/stat.h>
#অন্তর্ভাব <sys/un.h>
#অন্তর্ভাব <sys/wait.h>

#ifdef WITH_OPENSSL
#অন্তর্ভাব <openssl/evp.h>
#অন্তর্ভাব "openbsd-compat/openssl-compat.h"
#endif

#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <fcntl.h>
#অন্তর্ভাব <paths.h>
#অন্তর্ভাব <poll.h>
#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <limits.h>
#অন্তর্ভাব <time.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <util.h>
#অন্তর্ভাব <pwd.h>

#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "ssh.h"
#অন্তর্ভাব "ssh2.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "authfd.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "digest.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "match.h"
#অন্তর্ভাব "msg.h"
#অন্তর্ভাব "pathnames.h"
#অন্তর্ভাব "ssh-pkcs11.h"
#অন্তর্ভাব "sk-api.h"
#অন্তর্ভাব "myproposal.h"
#অন্তর্ভাব "version.h"

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

প্রকারলেখ গণনা {
	AUTH_UNUSED = 0,
	AUTH_SOCKET = 1,
	AUTH_CONNECTION = 2,
} sock_type;

কাঠামো hostkey_sid {
	কাঠামো sshkey *চাবি;
	কাঠামো sshbuf *sid;
	পূর্ণসংখ্যা forwarded;
};

প্রকারলেখ কাঠামো socket_entry {
	পূর্ণসংখ্যা fd;
	sock_type type;
	কাঠামো sshbuf *প্রবেশ;
	কাঠামো sshbuf *output;
	কাঠামো sshbuf *request;
	আকার_t nsession_ids;
	কাঠামো hostkey_sid *session_ids;
	পূর্ণসংখ্যা session_bind_attempted;
} SocketEntry;

u_int sockets_alloc = 0;
SocketEntry *sockets = ফাঁকা;

প্রকারলেখ কাঠামো identity {
	TAILQ_ENTRY(identity) পরবর্তী;
	কাঠামো sshkey *চাবি;
	অক্ষর *comment;
	অক্ষর *provider;
	time_t death;
	u_int confirm;
	অক্ষর *sk_provider;
	কাঠামো dest_constraint *dest_constraints;
	আকার_t ndest_constraints;
} Identity;

কাঠামো idtable {
	পূর্ণসংখ্যা nentries;
	TAILQ_HEAD(idqueue, identity) idlist;
};

/* private key table */
কাঠামো idtable *idtab;

পূর্ণসংখ্যা max_fd = 0;

/* pid of shell == parent of agent */
pid_t parent_pid = -1;
time_t parent_alive_interval = 0;

স্থির sig_atomic_t signalled_exit;
স্থির sig_atomic_t signalled_keydrop;

/* pid of process for which cleanup_socket is applicable */
pid_t cleanup_pid = 0;

/* pathname and directory for AUTH_SOCKET */
স্থির অক্ষর *socket_name;
স্থির অক্ষর *socket_dir;
স্থির অক্ষর *socket_dirspec;

/* Pattern-list of allowed PKCS#11/Security key paths */
স্থির অক্ষর *allowed_providers;

/*
 * Allows PKCS11 providers or SK keys that use non-internal providers to
 * be added over a remote connection (identified by session-bind@openssh.com).
 */
স্থির পূর্ণসংখ্যা remote_add_provider;

/* locking */
#define LOCK_আকার	32
#define LOCK_SALT_আকার	16
#define LOCK_ROUNDS	1
পূর্ণসংখ্যা locked = 0;
u_char lock_pwhash[LOCK_আকার];
u_char lock_salt[LOCK_SALT_আকার];

বাহ্যিক অক্ষর *__progname;

/* Default lifetime in seconds (0 == forever) */
স্থির পূর্ণসংখ্যা lifetime = 0;

স্থির পূর্ণসংখ্যা fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* Refuse signing of non-SSH messages for web-origin FIDO keys */
স্থির পূর্ণসংখ্যা restrict_websafe = 1;
স্থির অক্ষর *websafe_allowlist;

স্থির শূন্য
close_socket(SocketEntry *e)
{
	আকার_t i;

	close(e->fd);
	sshbuf_free(e->প্রবেশ);
	sshbuf_free(e->output);
	sshbuf_free(e->request);
	জন্য (i = 0; i < e->nsession_ids; i++) {
		sshkey_free(e->session_ids[i].চাবি);
		sshbuf_free(e->session_ids[i].sid);
	}
	মুক্ত(e->session_ids);
	memset(e, '\0', আকার(*e));
	e->fd = -1;
	e->type = AUTH_UNUSED;
}

স্থির শূন্য
idtab_init(শূন্য)
{
	idtab = xcalloc(1, আকার(*idtab));
	TAILQ_INIT(&idtab->idlist);
	idtab->nentries = 0;
}

স্থির শূন্য
free_dest_constraint_hop(কাঠামো dest_constraint_hop *dch)
{
	u_int i;

	যদি (dch == ফাঁকা)
		ফেরত;
	মুক্ত(dch->user);
	মুক্ত(dch->hostname);
	জন্য (i = 0; i < dch->nkeys; i++)
		sshkey_free(dch->চাবিগুলি[i]);
	মুক্ত(dch->চাবিগুলি);
	মুক্ত(dch->চাবি_is_ca);
}

স্থির শূন্য
free_dest_constraints(কাঠামো dest_constraint *dcs, আকার_t ndcs)
{
	আকার_t i;

	জন্য (i = 0; i < ndcs; i++) {
		free_dest_constraint_hop(&dcs[i].from);
		free_dest_constraint_hop(&dcs[i].to);
	}
	মুক্ত(dcs);
}

#ifdef ENABLE_PKCS11
স্থির শূন্য
dup_dest_constraint_hop(ধ্রুবক কাঠামো dest_constraint_hop *dch,
    কাঠামো dest_constraint_hop *out)
{
	u_int i;
	পূর্ণসংখ্যা r;

	out->user = dch->user == ফাঁকা ? ফাঁকা : xstrdup(dch->user);
	out->hostname = dch->hostname == ফাঁকা ? ফাঁকা : xstrdup(dch->hostname);
	out->is_ca = dch->is_ca;
	out->nkeys = dch->nkeys;
	out->চাবিগুলি = out->nkeys == 0 ? ফাঁকা :
	    xcalloc(out->nkeys, আকার(*out->চাবিগুলি));
	out->চাবি_is_ca = out->nkeys == 0 ? ফাঁকা :
	    xcalloc(out->nkeys, আকার(*out->চাবি_is_ca));
	জন্য (i = 0; i < dch->nkeys; i++) {
		যদি (dch->চাবিগুলি[i] != ফাঁকা &&
		    (r = sshkey_from_private(dch->চাবিগুলি[i],
		    &(out->চাবিগুলি[i]))) != 0)
			fatal_fr(r, "copy key");
		out->চাবি_is_ca[i] = dch->চাবি_is_ca[i];
	}
}

স্থির কাঠামো dest_constraint *
dup_dest_constraints(ধ্রুবক কাঠামো dest_constraint *dcs, আকার_t ndcs)
{
	আকার_t i;
	কাঠামো dest_constraint *ret;

	যদি (ndcs == 0)
		ফেরত ফাঁকা;
	ret = xcalloc(ndcs, আকার(*ret));
	জন্য (i = 0; i < ndcs; i++) {
		dup_dest_constraint_hop(&dcs[i].from, &ret[i].from);
		dup_dest_constraint_hop(&dcs[i].to, &ret[i].to);
	}
	ফেরত ret;
}
#endif /* ENABLE_PKCS11 */

#ifdef DEBUG_CONSTRAINTS
স্থির শূন্য
dump_dest_constraint_hop(ধ্রুবক কাঠামো dest_constraint_hop *dch)
{
	u_int i;
	অক্ষর *fp;

	debug_f("user %s hostname %s is_ca %d nkeys %u",
	    dch->user == ফাঁকা ? "(null)" : dch->user,
	    dch->hostname == ফাঁকা ? "(null)" : dch->hostname,
	    dch->is_ca, dch->nkeys);
	জন্য (i = 0; i < dch->nkeys; i++) {
		fp = ফাঁকা;
		যদি (dch->চাবিগুলি[i] != ফাঁকা &&
		    (fp = sshkey_fingerprint(dch->চাবিগুলি[i],
		    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == ফাঁকা)
			fatal_f("fingerprint failed");
		debug_f("key %u/%u: %s%s%s key_is_ca %d", i, dch->nkeys,
		    dch->চাবিগুলি[i] == ফাঁকা ? "" : sshkey_ssh_name(dch->চাবিগুলি[i]),
		    dch->চাবিগুলি[i] == ফাঁকা ? "" : " ",
		    dch->চাবিগুলি[i] == ফাঁকা ? "none" : fp,
		    dch->চাবি_is_ca[i]);
		মুক্ত(fp);
	}
}
#endif /* DEBUG_CONSTRAINTS */

স্থির শূন্য
dump_dest_constraints(ধ্রুবক অক্ষর *context,
    ধ্রুবক কাঠামো dest_constraint *dcs, আকার_t ndcs)
{
#ifdef DEBUG_CONSTRAINTS
	আকার_t i;

	debug_f("%s: %zu constraints", context, ndcs);
	জন্য (i = 0; i < ndcs; i++) {
		debug_f("constraint %zu / %zu: from: ", i, ndcs);
		dump_dest_constraint_hop(&dcs[i].from);
		debug_f("constraint %zu / %zu: to: ", i, ndcs);
		dump_dest_constraint_hop(&dcs[i].to);
	}
	debug_f("done for %s", context);
#endif /* DEBUG_CONSTRAINTS */
}

স্থির শূন্য
free_identity(Identity *id)
{
	sshkey_free(id->চাবি);
	মুক্ত(id->provider);
	মুক্ত(id->comment);
	মুক্ত(id->sk_provider);
	free_dest_constraints(id->dest_constraints, id->ndest_constraints);
	মুক্ত(id);
}

/*
 * Match 'key' against the key/CA list in a destination constraint hop
 * Returns 0 on success or -1 otherwise.
 */
স্থির পূর্ণসংখ্যা
match_চাবি_hop(ধ্রুবক অক্ষর *tag, ধ্রুবক কাঠামো sshkey *চাবি,
    ধ্রুবক কাঠামো dest_constraint_hop *dch)
{
	ধ্রুবক অক্ষর *reason = ফাঁকা;
	ধ্রুবক অক্ষর *hostname = dch->hostname ? dch->hostname : "(ORIGIN)";
	u_int i;
	অক্ষর *fp;

	যদি (চাবি == ফাঁকা)
		ফেরত -1;
	/* XXX logspam */
	যদি ((fp = sshkey_fingerprint(চাবি, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ফাঁকা)
		fatal_f("fingerprint failed");
	debug3_f("%s: entering hostname %s, requested key %s %s, %u keys avail",
	    tag, hostname, sshkey_type(চাবি), fp, dch->nkeys);
	মুক্ত(fp);
	জন্য (i = 0; i < dch->nkeys; i++) {
		যদি (dch->চাবিগুলি[i] == ফাঁকা)
			ফেরত -1;
		/* XXX logspam */
		যদি ((fp = sshkey_fingerprint(dch->চাবিগুলি[i], SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ফাঁকা)
			fatal_f("fingerprint failed");
		debug3_f("%s: key %u: %s%s %s", tag, i,
		    dch->চাবি_is_ca[i] ? "CA " : "",
		    sshkey_type(dch->চাবিগুলি[i]), fp);
		মুক্ত(fp);
		যদি (!sshkey_is_cert(চাবি)) {
			/* plain key */
			যদি (dch->চাবি_is_ca[i] ||
			    !sshkey_equal(চাবি, dch->চাবিগুলি[i]))
				চালু;
			ফেরত 0;
		}
		/* certificate */
		যদি (!dch->চাবি_is_ca[i])
			চালু;
		যদি (চাবি->cert == ফাঁকা || চাবি->cert->signature_চাবি == ফাঁকা)
			ফেরত -1; /* shouldn't happen */
		যদি (!sshkey_equal(চাবি->cert->signature_চাবি, dch->চাবিগুলি[i]))
			চালু;
		যদি (sshkey_cert_check_host(চাবি, hostname,
		    SSH_ALLOWED_CA_SIGALGS, &reason) != 0) {
			debug_f("cert %s / hostname %s rejected: %s",
			    চাবি->cert->চাবি_id, hostname, reason);
			চালু;
		}
		ফেরত 0;
	}
	ফেরত -1;
}

/* Check destination constraints on an identity against the hostkey/user */
স্থির পূর্ণসংখ্যা
permitted_by_dest_constraints(ধ্রুবক কাঠামো sshkey *fromkey,
    ধ্রুবক কাঠামো sshkey *tokey, Identity *id, ধ্রুবক অক্ষর *user,
    ধ্রুবক অক্ষর **hostnamep)
{
	আকার_t i;
	কাঠামো dest_constraint *d;

	যদি (hostnamep != ফাঁকা)
		*hostnamep = ফাঁকা;
	জন্য (i = 0; i < id->ndest_constraints; i++) {
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
		যদি (fromkey == ফাঁকা) {
			/* We are matching the first hop */
			যদি (d->from.hostname != ফাঁকা || d->from.nkeys != 0)
				চালু;
		} অন্যথা যদি (match_চাবি_hop("from", fromkey, &d->from) != 0)
			চালু;

		/* Match 'to' key */
		যদি (tokey != ফাঁকা && match_চাবি_hop("to", tokey, &d->to) != 0)
			চালু;

		/* Match user if specified */
		যদি (d->to.user != ফাঁকা && user != ফাঁকা &&
		    !match_pattern(user, d->to.user))
			চালু;

		/* successfully matched this constraint */
		যদি (hostnamep != ফাঁকা)
			*hostnamep = d->to.hostname;
		debug2_f("allowed for hostname %s",
		    d->to.hostname == ফাঁকা ? "*" : d->to.hostname);
		ফেরত 0;
	}
	/* no match */
	debug2_f("%s identity \"%s\" not permitted for this destination",
	    sshkey_type(id->চাবি), id->comment);
	ফেরত -1;
}

/*
 * Check whether hostkeys on a SocketEntry and the optionally specified user
 * are permitted by the destination constraints on the Identity.
 * Returns 0 on success or -1 otherwise.
 */
স্থির পূর্ণসংখ্যা
identity_permitted(Identity *id, SocketEntry *e, অক্ষর *user,
    ধ্রুবক অক্ষর **forward_hostnamep, ধ্রুবক অক্ষর **last_hostnamep)
{
	আকার_t i;
	ধ্রুবক অক্ষর **hp;
	কাঠামো hostkey_sid *hks;
	ধ্রুবক কাঠামো sshkey *fromkey = ফাঁকা;
	ধ্রুবক অক্ষর *test_user;
	অক্ষর *fp1, *fp2;

	/* XXX remove logspam */
	debug3_f("entering: key %s comment \"%s\", %zu socket bindings, "
	    "%zu constraints", sshkey_type(id->চাবি), id->comment,
	    e->nsession_ids, id->ndest_constraints);
	যদি (id->ndest_constraints == 0)
		ফেরত 0; /* unconstrained */
	যদি (e->session_bind_attempted && e->nsession_ids == 0) {
		error_f("previous session bind failed on socket");
		ফেরত -1;
	}
	যদি (e->nsession_ids == 0)
		ফেরত 0; /* local use */
	/*
	 * Walk through the hops recorded by session_id and try to find a
	 * constraint that satisfies each.
	 */
	জন্য (i = 0; i < e->nsession_ids; i++) {
		hks = e->session_ids + i;
		যদি (hks->চাবি == ফাঁকা)
			fatal_f("internal error: no bound key");
		/* XXX remove logspam */
		fp1 = fp2 = ফাঁকা;
		যদি (fromkey != ফাঁকা &&
		    (fp1 = sshkey_fingerprint(fromkey, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ফাঁকা)
			fatal_f("fingerprint failed");
		যদি ((fp2 = sshkey_fingerprint(hks->চাবি, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ফাঁকা)
			fatal_f("fingerprint failed");
		debug3_f("socketentry fd=%d, entry %zu %s, "
		    "from hostkey %s %s to user %s hostkey %s %s",
		    e->fd, i, hks->forwarded ? "FORWARD" : "AUTH",
		    fromkey ? sshkey_type(fromkey) : "(ORIGIN)",
		    fromkey ? fp1 : "", user ? user : "(ANY)",
		    sshkey_type(hks->চাবি), fp2);
		মুক্ত(fp1);
		মুক্ত(fp2);
		/*
		 * Record the hostnames for the initial forwarding and
		 * the final destination.
		 */
		hp = ফাঁকা;
		যদি (i == e->nsession_ids - 1)
			hp = last_hostnamep;
		অন্যথা যদি (i == 0)
			hp = forward_hostnamep;
		/* Special handling for final recorded binding */
		test_user = ফাঁকা;
		যদি (i == e->nsession_ids - 1) {
			/* Can only check user at final hop */
			test_user = user;
			/*
			 * user is only presented for signature requests.
			 * If this is the case, make sure last binding is not
			 * for a forwarding.
			 */
			যদি (hks->forwarded && user != ফাঁকা) {
				error_f("tried to sign on forwarding hop");
				ফেরত -1;
			}
		} অন্যথা যদি (!hks->forwarded) {
			error_f("tried to forward though signing bind");
			ফেরত -1;
		}
		যদি (permitted_by_dest_constraints(fromkey, hks->চাবি, id,
		    test_user, hp) != 0)
			ফেরত -1;
		fromkey = hks->চাবি;
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
	যদি (hks->forwarded && user == ফাঁকা &&
	    permitted_by_dest_constraints(hks->চাবি, ফাঁকা, id,
	    ফাঁকা, ফাঁকা) != 0) {
		debug3_f("key permitted at host but not after");
		ফেরত -1;
	}

	/* success */
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
socket_is_remote(SocketEntry *e)
{
	ফেরত e->session_bind_attempted || (e->nsession_ids != 0);
}

/* return matching private key for given public key */
স্থির Identity *
lookup_identity(কাঠামো sshkey *চাবি)
{
	Identity *id;

	TAILQ_FOREACH(id, &idtab->idlist, পরবর্তী) {
		যদি (sshkey_equal(চাবি, id->চাবি))
			ফেরত (id);
	}
	ফেরত (ফাঁকা);
}

/* Check confirmation of keysign request */
স্থির পূর্ণসংখ্যা
confirm_চাবি(Identity *id, ধ্রুবক অক্ষর *extra)
{
	অক্ষর *p;
	পূর্ণসংখ্যা ret = -1;

	p = sshkey_fingerprint(id->চাবি, fingerprint_hash, SSH_FP_DEFAULT);
	যদি (p != ফাঁকা &&
	    ask_permission("Allow use of key %s?\nKey fingerprint %s.%s%s",
	    id->comment, p,
	    extra == ফাঁকা ? "" : "\n", extra == ফাঁকা ? "" : extra))
		ret = 0;
	মুক্ত(p);

	ফেরত (ret);
}

স্থির শূন্য
send_status_generic(SocketEntry *e, u_int code)
{
	পূর্ণসংখ্যা r;

	যদি ((r = sshbuf_put_u32(e->output, 1)) != 0 ||
	    (r = sshbuf_put_u8(e->output, code)) != 0)
		fatal_fr(r, "compose");
}

স্থির শূন্য
send_status(SocketEntry *e, পূর্ণসংখ্যা success)
{
	send_status_generic(e,
	    success ? SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE);
}

/* send list of supported public keys to 'client' */
স্থির শূন্য
process_request_identities(SocketEntry *e)
{
	Identity *id;
	কাঠামো sshbuf *বার্তা, *চাবিগুলি;
	পূর্ণসংখ্যা r;
	u_int i = 0, nentries = 0;
	অক্ষর *fp;

	debug2_f("entering");

	যদি ((বার্তা = sshbuf_new()) == ফাঁকা || (চাবিগুলি = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");
	TAILQ_FOREACH(id, &idtab->idlist, পরবর্তী) {
		যদি ((fp = sshkey_fingerprint(id->চাবি, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ফাঁকা)
			fatal_f("fingerprint failed");
		debug_f("key %u / %u: %s %s", i++, idtab->nentries,
		    sshkey_ssh_name(id->চাবি), fp);
		dump_dest_constraints(__func__,
		    id->dest_constraints, id->ndest_constraints);
		মুক্ত(fp);
		/* identity not visible, don't include in response */
		যদি (identity_permitted(id, e, ফাঁকা, ফাঁকা, ফাঁকা) != 0)
			চালু;
		যদি ((r = sshkey_puts(id->চাবি, চাবিগুলি)) != 0 ||
		    (r = sshbuf_put_cstring(চাবিগুলি, id->comment)) != 0) {
			error_fr(r, "compose key/comment");
			চালু;
		}
		nentries++;
	}
	debug2_f("replying with %u allowed of %u available keys",
	    nentries, idtab->nentries);
	যদি ((r = sshbuf_put_u8(বার্তা, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
	    (r = sshbuf_put_u32(বার্তা, nentries)) != 0 ||
	    (r = sshbuf_putb(বার্তা, চাবিগুলি)) != 0)
		fatal_fr(r, "compose");
	যদি ((r = sshbuf_put_stringb(e->output, বার্তা)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(বার্তা);
	sshbuf_free(চাবিগুলি);
}


স্থির অক্ষর *
agent_decode_alg(কাঠামো sshkey *চাবি, u_int flags)
{
	যদি (চাবি->type == চাবি_RSA) {
		যদি (flags & SSH_AGENT_RSA_SHA2_256)
			ফেরত "rsa-sha2-256";
		অন্যথা যদি (flags & SSH_AGENT_RSA_SHA2_512)
			ফেরত "rsa-sha2-512";
	} অন্যথা যদি (চাবি->type == চাবি_RSA_CERT) {
		যদি (flags & SSH_AGENT_RSA_SHA2_256)
			ফেরত "rsa-sha2-256-cert-v01@openssh.com";
		অন্যথা যদি (flags & SSH_AGENT_RSA_SHA2_512)
			ফেরত "rsa-sha2-512-cert-v01@openssh.com";
	}
	ফেরত ফাঁকা;
}

/*
 * Attempt to parse the contents of a buffer as a SSH publickey userauth
 * request, checking its contents for consistency and matching the embedded
 * key against the one that is being used for signing.
 * Note: does not modify msg buffer.
 * Optionally extract the username, session ID and/or hostkey from the request.
 */
স্থির পূর্ণসংখ্যা
parse_userauth_request(কাঠামো sshbuf *বার্তা, ধ্রুবক কাঠামো sshkey *expected_চাবি,
    অক্ষর **userp, কাঠামো sshbuf **sess_idp, কাঠামো sshkey **hostkeyp)
{
	কাঠামো sshbuf *b = ফাঁকা, *sess_id = ফাঁকা;
	অক্ষর *user = ফাঁকা, *service = ফাঁকা, *method = ফাঁকা, *pkalg = ফাঁকা;
	পূর্ণসংখ্যা r;
	u_char t, sig_follows;
	কাঠামো sshkey *mkey = ফাঁকা, *hostkey = ফাঁকা;

	যদি (userp != ফাঁকা)
		*userp = ফাঁকা;
	যদি (sess_idp != ফাঁকা)
		*sess_idp = ফাঁকা;
	যদি (hostkeyp != ফাঁকা)
		*hostkeyp = ফাঁকা;
	যদি ((b = sshbuf_fromb(বার্তা)) == ফাঁকা)
		fatal_f("sshbuf_fromb");

	/* SSH userauth request */
	যদি ((r = sshbuf_froms(b, &sess_id)) != 0)
		যাও out;
	যদি (sshbuf_len(sess_id) == 0) {
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	যদি ((r = sshbuf_get_u8(b, &t)) != 0 || /* SSH2_MSG_USERAUTH_REQUEST */
	    (r = sshbuf_get_cstring(b, &user, ফাঁকা)) != 0 || /* server user */
	    (r = sshbuf_get_cstring(b, &service, ফাঁকা)) != 0 || /* service */
	    (r = sshbuf_get_cstring(b, &method, ফাঁকা)) != 0 || /* method */
	    (r = sshbuf_get_u8(b, &sig_follows)) != 0 || /* sig-follows */
	    (r = sshbuf_get_cstring(b, &pkalg, ফাঁকা)) != 0 || /* alg */
	    (r = sshkey_froms(b, &mkey)) != 0) /*চাবি*/
		যাও out;
	যদি (t != SSH2_বার্তা_USERAUTH_REQUEST ||
	    sig_follows != 1 ||
	    strcmp(service, "ssh-connection") != 0 ||
	    !sshkey_equal(expected_চাবি, mkey) ||
	    sshkey_type_from_name(pkalg) != expected_চাবি->type) {
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	যদি (strcmp(method, "publickey-hostbound-v00@openssh.com") == 0) {
		যদি ((r = sshkey_froms(b, &hostkey)) != 0)
			যাও out;
	} অন্যথা যদি (strcmp(method, "publickey") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	যদি (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	/* success */
	r = 0;
	debug3_f("well formed userauth");
	যদি (userp != ফাঁকা) {
		*userp = user;
		user = ফাঁকা;
	}
	যদি (sess_idp != ফাঁকা) {
		*sess_idp = sess_id;
		sess_id = ফাঁকা;
	}
	যদি (hostkeyp != ফাঁকা) {
		*hostkeyp = hostkey;
		hostkey = ফাঁকা;
	}
 out:
	sshbuf_free(b);
	sshbuf_free(sess_id);
	মুক্ত(user);
	মুক্ত(service);
	মুক্ত(method);
	মুক্ত(pkalg);
	sshkey_free(mkey);
	sshkey_free(hostkey);
	ফেরত r;
}

/*
 * Attempt to parse the contents of a buffer as a SSHSIG signature request.
 * Note: does not modify buffer.
 */
স্থির পূর্ণসংখ্যা
parse_sshsig_request(কাঠামো sshbuf *বার্তা)
{
	পূর্ণসংখ্যা r;
	কাঠামো sshbuf *b;

	যদি ((b = sshbuf_fromb(বার্তা)) == ফাঁকা)
		fatal_f("sshbuf_fromb");

	যদি ((r = sshbuf_cmp(b, 0, "SSHSIG", 6)) != 0 ||
	    (r = sshbuf_consume(b, 6)) != 0 ||
	    (r = sshbuf_get_cstring(b, ফাঁকা, ফাঁকা)) != 0 || /* namespace */
	    (r = sshbuf_get_string_direct(b, ফাঁকা, ফাঁকা)) != 0 || /* reserved */
	    (r = sshbuf_get_cstring(b, ফাঁকা, ফাঁকা)) != 0 || /* hashalg */
	    (r = sshbuf_get_string_direct(b, ফাঁকা, ফাঁকা)) != 0) /* H(msg) */
		যাও out;
	যদি (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	ফেরত r;
}

/*
 * This function inspects a message to be signed by a FIDO key that has a
 * web-like application string (i.e. one that does not begin with "ssh:".
 * It checks that the message is one of those expected for SSH operations
 * (pubkey userauth, sshsig, CA key signing) to exclude signing challenges
 * for the web.
 */
স্থির পূর্ণসংখ্যা
check_websafe_message_contents(কাঠামো sshkey *চাবি, কাঠামো sshbuf *তথ্য)
{
	যদি (parse_userauth_request(তথ্য, চাবি, ফাঁকা, ফাঁকা, ফাঁকা) == 0) {
		debug_f("signed data matches public key userauth request");
		ফেরত 1;
	}
	যদি (parse_sshsig_request(তথ্য) == 0) {
		debug_f("signed data matches SSHSIG signature request");
		ফেরত 1;
	}

	/* XXX check CA signature operation */

	error("web-origin key attempting to sign non-SSH message");
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
buf_equal(ধ্রুবক কাঠামো sshbuf *a, ধ্রুবক কাঠামো sshbuf *b)
{
	যদি (sshbuf_ptr(a) == ফাঁকা || sshbuf_ptr(b) == ফাঁকা)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	যদি (sshbuf_len(a) != sshbuf_len(b))
		ফেরত SSH_ERR_INVALID_FORMAT;
	যদি (timingsafe_bcmp(sshbuf_ptr(a), sshbuf_ptr(b), sshbuf_len(a)) != 0)
		ফেরত SSH_ERR_INVALID_FORMAT;
	ফেরত 0;
}

/* ssh2 only */
স্থির শূন্য
process_sign_request2(SocketEntry *e)
{
	u_char *signature = ফাঁকা;
	আকার_t slen = 0;
	u_int compat = 0, flags;
	পূর্ণসংখ্যা r, ok = -1, retried = 0;
	অক্ষর *fp = ফাঁকা, *pin = ফাঁকা, *prompt = ফাঁকা;
	অক্ষর *user = ফাঁকা, *sig_dest = ফাঁকা;
	ধ্রুবক অক্ষর *fwd_host = ফাঁকা, *dest_host = ফাঁকা;
	কাঠামো sshbuf *বার্তা = ফাঁকা, *তথ্য = ফাঁকা, *sid = ফাঁকা;
	কাঠামো sshkey *চাবি = ফাঁকা, *hostkey = ফাঁকা;
	কাঠামো identity *id;
	কাঠামো notifier_ctx *notifier = ফাঁকা;

	debug_f("entering");

	যদি ((বার্তা = sshbuf_new()) == ফাঁকা || (তথ্য = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshkey_froms(e->request, &চাবি)) != 0 ||
	    (r = sshbuf_get_stringb(e->request, তথ্য)) != 0 ||
	    (r = sshbuf_get_u32(e->request, &flags)) != 0) {
		error_fr(r, "parse");
		যাও send;
	}

	যদি ((id = lookup_identity(চাবি)) == ফাঁকা) {
		verbose_f("%s key not found", sshkey_type(চাবি));
		যাও send;
	}
	যদি ((fp = sshkey_fingerprint(চাবি, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ফাঁকা)
		fatal_f("fingerprint failed");

	যদি (id->ndest_constraints != 0) {
		যদি (e->nsession_ids == 0) {
			logit_f("refusing use of destination-constrained key "
			    "to sign on unbound connection");
			যাও send;
		}
		যদি (parse_userauth_request(তথ্য, চাবি, &user, &sid,
		    &hostkey) != 0) {
			logit_f("refusing use of destination-constrained key "
			   "to sign an unidentified signature");
			যাও send;
		}
		/* XXX logspam */
		debug_f("user=%s", user);
		যদি (identity_permitted(id, e, user, &fwd_host, &dest_host) != 0)
			যাও send;
		/* XXX display fwd_host/dest_host in askpass UI */
		/*
		 * Ensure that the session ID is the most recent one
		 * registered on the socket - it should have been bound by
		 * ssh immediately before userauth.
		 */
		যদি (buf_equal(sid,
		    e->session_ids[e->nsession_ids - 1].sid) != 0) {
			error_f("unexpected session ID (%zu listed) on "
			    "signature request for target user %s with "
			    "key %s %s", e->nsession_ids, user,
			    sshkey_type(id->চাবি), fp);
			যাও send;
		}
		/*
		 * Ensure that the hostkey embedded in the signature matches
		 * the one most recently bound to the socket. An exception is
		 * made for the initial forwarding hop.
		 */
		যদি (e->nsession_ids > 1 && hostkey == ফাঁকা) {
			error_f("refusing use of destination-constrained key: "
			    "no hostkey recorded in signature for forwarded "
			    "connection");
			যাও send;
		}
		যদি (hostkey != ফাঁকা && !sshkey_equal(hostkey,
		    e->session_ids[e->nsession_ids - 1].চাবি)) {
			error_f("refusing use of destination-constrained key: "
			    "mismatch between hostkey in request and most "
			    "recently bound session");
			যাও send;
		}
		xasprintf(&sig_dest, "public key authentication request for "
		    "user \"%s\" to listed host", user);
	}
	যদি (id->confirm && confirm_চাবি(id, sig_dest) != 0) {
		verbose_f("user refused key");
		যাও send;
	}
	যদি (sshkey_is_sk(id->চাবি)) {
		যদি (restrict_websafe &&
		    match_pattern_list(id->চাবি->sk_application,
		    websafe_allowlist, 0) != 1 &&
		    !check_websafe_message_contents(চাবি, তথ্য)) {
			/* error already logged */
			যাও send;
		}
		যদি (id->চাবি->sk_flags & SSH_SK_USER_PRESENCE_REQD) {
			notifier = notify_start(0,
			    "Confirm user presence for key %s %s%s%s",
			    sshkey_type(id->চাবি), fp,
			    sig_dest == ফাঁকা ? "" : "\n",
			    sig_dest == ফাঁকা ? "" : sig_dest);
		}
	}
 retry_pin:
	যদি ((r = sshkey_sign(id->চাবি, &signature, &slen,
	    sshbuf_ptr(তথ্য), sshbuf_len(তথ্য), agent_decode_alg(চাবি, flags),
	    id->sk_provider, pin, compat)) != 0) {
		debug_fr(r, "sshkey_sign");
		যদি (pin == ফাঁকা && !retried && sshkey_is_sk(id->চাবি) &&
		    r == SSH_ERR_চাবি_WRONG_PASSPHRASE) {
			notify_complete(notifier, ফাঁকা);
			notifier = ফাঁকা;
			/* XXX include sig_dest */
			xasprintf(&prompt, "Enter PIN%sfor %s key %s: ",
			    (id->চাবি->sk_flags & SSH_SK_USER_PRESENCE_REQD) ?
			    " and confirm user presence " : " ",
			    sshkey_type(id->চাবি), fp);
			pin = read_passphrase(prompt, RP_USE_ASKPASS);
			retried = 1;
			যাও retry_pin;
		}
		error_fr(r, "sshkey_sign");
		যাও send;
	}
	/* Success */
	ok = 0;
	debug_f("good signature");
 send:
	notify_complete(notifier, "User presence confirmed");

	যদি (ok == 0) {
		যদি ((r = sshbuf_put_u8(বার্তা, SSH2_AGENT_SIGN_RESPONSE)) != 0 ||
		    (r = sshbuf_put_string(বার্তা, signature, slen)) != 0)
			fatal_fr(r, "compose");
	} অন্যথা যদি ((r = sshbuf_put_u8(বার্তা, SSH_AGENT_FAILURE)) != 0)
		fatal_fr(r, "compose failure");

	যদি ((r = sshbuf_put_stringb(e->output, বার্তা)) != 0)
		fatal_fr(r, "enqueue");

	sshbuf_free(sid);
	sshbuf_free(তথ্য);
	sshbuf_free(বার্তা);
	sshkey_free(চাবি);
	sshkey_free(hostkey);
	মুক্ত(fp);
	মুক্ত(signature);
	মুক্ত(sig_dest);
	মুক্ত(user);
	মুক্ত(prompt);
	যদি (pin != ফাঁকা)
		freezero(pin, strlen(pin));
}

/* shared */
স্থির শূন্য
process_remove_identity(SocketEntry *e)
{
	পূর্ণসংখ্যা r, success = 0;
	কাঠামো sshkey *চাবি = ফাঁকা;
	Identity *id;

	debug2_f("entering");
	যদি ((r = sshkey_froms(e->request, &চাবি)) != 0) {
		error_fr(r, "parse key");
		যাও done;
	}
	যদি ((id = lookup_identity(চাবি)) == ফাঁকা) {
		debug_f("key not found");
		যাও done;
	}
	/* identity not visible, cannot be removed */
	যদি (identity_permitted(id, e, ফাঁকা, ফাঁকা, ফাঁকা) != 0)
		যাও done; /* error already logged */
	/* We have this key, free it. */
	যদি (idtab->nentries < 1)
		fatal_f("internal error: nentries %d", idtab->nentries);
	TAILQ_REMOVE(&idtab->idlist, id, পরবর্তী);
	free_identity(id);
	idtab->nentries--;
	success = 1;
 done:
	sshkey_free(চাবি);
	send_status(e, success);
}

স্থির শূন্য
remove_all_identities(শূন্য)
{
	Identity *id;

	debug2_f("entering");
	/* Loop over all identities and clear the keys. */
	জন্য (id = TAILQ_FIRST(&idtab->idlist); id;
	    id = TAILQ_FIRST(&idtab->idlist)) {
		TAILQ_REMOVE(&idtab->idlist, id, পরবর্তী);
		free_identity(id);
	}

	/* Mark that there are no identities. */
	idtab->nentries = 0;
}

স্থির শূন্য
process_remove_all_identities(SocketEntry *e)
{
	remove_all_identities();

	/* Send success. */
	send_status(e, 1);
}

/* removes expired keys and returns number of seconds until the next expiry */
স্থির time_t
reaper(শূন্য)
{
	time_t deadline = 0, now = monotime();
	Identity *id, *nxt;

	জন্য (id = TAILQ_FIRST(&idtab->idlist); id; id = nxt) {
		nxt = TAILQ_NEXT(id, পরবর্তী);
		যদি (id->death == 0)
			চালু;
		যদি (now >= id->death) {
			debug("expiring key '%s'", id->comment);
			TAILQ_REMOVE(&idtab->idlist, id, পরবর্তী);
			free_identity(id);
			idtab->nentries--;
		} অন্যথা
			deadline = (deadline == 0) ? id->death :
			    MINIMUM(deadline, id->death);
	}
	যদি (deadline == 0 || deadline <= now)
		ফেরত 0;
	অন্যথা
		ফেরত (deadline - now);
}

স্থির পূর্ণসংখ্যা
parse_dest_constraint_hop(কাঠামো sshbuf *b, কাঠামো dest_constraint_hop *dch)
{
	u_char চাবি_is_ca;
	আকার_t elen = 0, userlen = 0;
	পূর্ণসংখ্যা r;
	কাঠামো sshkey *k = ফাঁকা;
	অক্ষর *fp;

	memset(dch, '\0', আকার(*dch));
	যদি ((r = sshbuf_get_cstring(b, &dch->user, &userlen)) != 0 ||
	    (r = sshbuf_get_cstring(b, &dch->hostname, ফাঁকা)) != 0 ||
	    (r = sshbuf_get_string_direct(b, ফাঁকা, &elen)) != 0) {
		error_fr(r, "parse");
		যাও out;
	}
	যদি (elen != 0) {
		error_f("unsupported extensions (len %zu)", elen);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		যাও out;
	}
	যদি (*dch->hostname == '\0') {
		মুক্ত(dch->hostname);
		dch->hostname = ফাঁকা;
	}
	যদি (*dch->user == '\0') {
		মুক্ত(dch->user);
		dch->user = ফাঁকা;
	} অন্যথা যদি (userlen > AGENT_USER_CONSTRAINT_MAX_LEN) {
		error_f("user match pattern too long");
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	যখন (sshbuf_len(b) != 0) {
		dch->চাবিগুলি = xrecallocarray(dch->চাবিগুলি, dch->nkeys,
		    dch->nkeys + 1, আকার(*dch->চাবিগুলি));
		dch->চাবি_is_ca = xrecallocarray(dch->চাবি_is_ca, dch->nkeys,
		    dch->nkeys + 1, আকার(*dch->চাবি_is_ca));
		যদি ((r = sshkey_froms(b, &k)) != 0 ||
		    (r = sshbuf_get_u8(b, &চাবি_is_ca)) != 0)
			যাও out;
		যদি ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ফাঁকা)
			fatal_f("fingerprint failed");
		debug3_f("%s%s%s: adding %skey %s %s",
		    dch->user == ফাঁকা ? "" : dch->user,
		    dch->user == ফাঁকা ? "" : "@",
		    dch->hostname, চাবি_is_ca ? "CA " : "", sshkey_type(k), fp);
		মুক্ত(fp);
		dch->চাবিগুলি[dch->nkeys] = k;
		dch->চাবি_is_ca[dch->nkeys] = চাবি_is_ca != 0;
		dch->nkeys++;
		k = ফাঁকা; /* transferred */
	}
	/* success */
	r = 0;
 out:
	sshkey_free(k);
	ফেরত r;
}

স্থির পূর্ণসংখ্যা
parse_dest_constraint(কাঠামো sshbuf *m, কাঠামো dest_constraint *dc)
{
	কাঠামো sshbuf *b = ফাঁকা, *frombuf = ফাঁকা, *tobuf = ফাঁকা;
	পূর্ণসংখ্যা r;
	আকার_t elen = 0;

	debug3_f("entering");

	memset(dc, '\0', আকার(*dc));
	যদি ((r = sshbuf_froms(m, &b)) != 0 ||
	    (r = sshbuf_froms(b, &frombuf)) != 0 ||
	    (r = sshbuf_froms(b, &tobuf)) != 0 ||
	    (r = sshbuf_get_string_direct(b, ফাঁকা, &elen)) != 0) {
		error_fr(r, "parse");
		যাও out;
	}
	যদি ((r = parse_dest_constraint_hop(frombuf, &dc->from)) != 0 ||
	    (r = parse_dest_constraint_hop(tobuf, &dc->to)) != 0)
		যাও out; /* already logged */
	যদি (elen != 0) {
		error_f("unsupported extensions (len %zu)", elen);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		যাও out;
	}
	debug2_f("parsed %s (%u keys) > %s%s%s (%u keys)",
	    dc->from.hostname ? dc->from.hostname : "(ORIGIN)", dc->from.nkeys,
	    dc->to.user ? dc->to.user : "", dc->to.user ? "@" : "",
	    dc->to.hostname ? dc->to.hostname : "(ANY)", dc->to.nkeys);
	/* check consistency */
	যদি ((dc->from.hostname == ফাঁকা) != (dc->from.nkeys == 0) ||
	    dc->from.user != ফাঁকা) {
		error_f("inconsistent \"from\" specification");
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	যদি (dc->to.hostname == ফাঁকা || dc->to.nkeys == 0) {
		error_f("incomplete \"to\" specification");
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	sshbuf_free(frombuf);
	sshbuf_free(tobuf);
	ফেরত r;
}

স্থির পূর্ণসংখ্যা
parse_চাবি_constraint_extension(কাঠামো sshbuf *m, অক্ষর **sk_providerp,
    কাঠামো dest_constraint **dcsp, আকার_t *ndcsp, পূর্ণসংখ্যা *cert_onlyp,
    কাঠামো sshkey ***certs, আকার_t *ncerts)
{
	অক্ষর *ext_name = ফাঁকা;
	পূর্ণসংখ্যা r;
	কাঠামো sshbuf *b = ফাঁকা;
	u_char v;
	কাঠামো sshkey *k;

	যদি ((r = sshbuf_get_cstring(m, &ext_name, ফাঁকা)) != 0) {
		error_fr(r, "parse constraint extension");
		যাও out;
	}
	debug_f("constraint ext %s", ext_name);
	যদি (strcmp(ext_name, "sk-provider@openssh.com") == 0) {
		যদি (sk_providerp == ফাঁকা) {
			error_f("%s not valid here", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			যাও out;
		}
		যদি (*sk_providerp != ফাঁকা) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			যাও out;
		}
		যদি ((r = sshbuf_get_cstring(m, sk_providerp, ফাঁকা)) != 0) {
			error_fr(r, "parse %s", ext_name);
			যাও out;
		}
	} অন্যথা যদি (strcmp(ext_name,
	    "restrict-destination-v00@openssh.com") == 0) {
		যদি (*dcsp != ফাঁকা) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			যাও out;
		}
		যদি ((r = sshbuf_froms(m, &b)) != 0) {
			error_fr(r, "parse %s outer", ext_name);
			যাও out;
		}
		যখন (sshbuf_len(b) != 0) {
			যদি (*ndcsp >= AGENT_MAX_DEST_CONSTRAINTS) {
				error_f("too many %s constraints", ext_name);
				r = SSH_ERR_INVALID_FORMAT;
				যাও out;
			}
			*dcsp = xrecallocarray(*dcsp, *ndcsp, *ndcsp + 1,
			    আকার(**dcsp));
			যদি ((r = parse_dest_constraint(b,
			    *dcsp + (*ndcsp)++)) != 0)
				যাও out; /* error already logged */
		}
	} অন্যথা যদি (strcmp(ext_name,
	    "associated-certs-v00@openssh.com") == 0) {
		যদি (certs == ফাঁকা || ncerts == ফাঁকা || cert_onlyp == ফাঁকা) {
			error_f("%s not valid here", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			যাও out;
		}
		যদি (*certs != ফাঁকা) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			যাও out;
		}
		যদি ((r = sshbuf_get_u8(m, &v)) != 0 ||
		    (r = sshbuf_froms(m, &b)) != 0) {
			error_fr(r, "parse %s", ext_name);
			যাও out;
		}
		*cert_onlyp = v != 0;
		যখন (sshbuf_len(b) != 0) {
			যদি (*ncerts >= AGENT_MAX_EXT_CERTS) {
				error_f("too many %s constraints", ext_name);
				r = SSH_ERR_INVALID_FORMAT;
				যাও out;
			}
			*certs = xrecallocarray(*certs, *ncerts, *ncerts + 1,
			    আকার(**certs));
			যদি ((r = sshkey_froms(b, &k)) != 0) {
				error_fr(r, "parse key");
				যাও out;
			}
			(*certs)[(*ncerts)++] = k;
		}
	} অন্যথা {
		error_f("unsupported constraint \"%s\"", ext_name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		যাও out;
	}
	/* success */
	r = 0;
 out:
	মুক্ত(ext_name);
	sshbuf_free(b);
	ফেরত r;
}

স্থির পূর্ণসংখ্যা
parse_চাবি_constraints(কাঠামো sshbuf *m, কাঠামো sshkey *k, time_t *deathp,
    u_int *secondsp, পূর্ণসংখ্যা *confirmp, অক্ষর **sk_providerp,
    কাঠামো dest_constraint **dcsp, আকার_t *ndcsp,
    পূর্ণসংখ্যা *cert_onlyp, আকার_t *ncerts, কাঠামো sshkey ***certs)
{
	u_char ctype;
	পূর্ণসংখ্যা r;
	u_int seconds;

	যখন (sshbuf_len(m)) {
		যদি ((r = sshbuf_get_u8(m, &ctype)) != 0) {
			error_fr(r, "parse constraint type");
			যাও out;
		}
		নির্বাচন (ctype) {
		ক্ষেত্র SSH_AGENT_CONSTRAIN_LIFETIME:
			যদি (*deathp != 0) {
				error_f("lifetime already set");
				r = SSH_ERR_INVALID_FORMAT;
				যাও out;
			}
			যদি ((r = sshbuf_get_u32(m, &seconds)) != 0) {
				error_fr(r, "parse lifetime constraint");
				যাও out;
			}
			*deathp = monotime() + seconds;
			*secondsp = seconds;
			বিরতি;
		ক্ষেত্র SSH_AGENT_CONSTRAIN_CONFIRM:
			যদি (*confirmp != 0) {
				error_f("confirm already set");
				r = SSH_ERR_INVALID_FORMAT;
				যাও out;
			}
			*confirmp = 1;
			বিরতি;
		ক্ষেত্র SSH_AGENT_CONSTRAIN_EXTENSION:
			যদি ((r = parse_চাবি_constraint_extension(m,
			    sk_providerp, dcsp, ndcsp,
			    cert_onlyp, certs, ncerts)) != 0)
				যাও out; /* error already logged */
			বিরতি;
		পূর্বনির্ধারিত:
			error_f("Unknown constraint %d", ctype);
			r = SSH_ERR_FEATURE_UNSUPPORTED;
			যাও out;
		}
	}
	/* success */
	r = 0;
 out:
	ফেরত r;
}

স্থির শূন্য
process_add_identity(SocketEntry *e)
{
	Identity *id;
	পূর্ণসংখ্যা success = 0, confirm = 0;
	অক্ষর *fp, *comment = ফাঁকা, *sk_provider = ফাঁকা;
	অক্ষর canonical_provider[PATH_MAX];
	time_t death = 0;
	u_int seconds = 0;
	কাঠামো dest_constraint *dest_constraints = ফাঁকা;
	আকার_t ndest_constraints = 0;
	কাঠামো sshkey *k = ফাঁকা;
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;

	debug2_f("entering");
	যদি ((r = sshkey_private_deserialize(e->request, &k)) != 0 ||
	    k == ফাঁকা ||
	    (r = sshbuf_get_cstring(e->request, &comment, ফাঁকা)) != 0) {
		error_fr(r, "parse");
		যাও out;
	}
	যদি (parse_চাবি_constraints(e->request, k, &death, &seconds, &confirm,
	    &sk_provider, &dest_constraints, &ndest_constraints,
	    ফাঁকা, ফাঁকা, ফাঁকা) != 0) {
		error_f("failed to parse constraints");
		sshbuf_reset(e->request);
		যাও out;
	}
	dump_dest_constraints(__func__, dest_constraints, ndest_constraints);

	যদি (sk_provider != ফাঁকা) {
		যদি (!sshkey_is_sk(k)) {
			error("Cannot add provider: %s is not an "
			    "authenticator-hosted key", sshkey_type(k));
			যাও out;
		}
		যদি (strcasecmp(sk_provider, "internal") == 0) {
			debug_f("internal provider");
		} অন্যথা {
			যদি (socket_is_remote(e) && !remote_add_provider) {
				verbose("failed add of SK provider \"%.100s\": "
				    "remote addition of providers is disabled",
				    sk_provider);
				যাও out;
			}
			যদি (realpath(sk_provider, canonical_provider) == ফাঁকা) {
				verbose("failed provider \"%.100s\": "
				    "realpath: %s", sk_provider,
				    strerror(errno));
				যাও out;
			}
			মুক্ত(sk_provider);
			sk_provider = xstrdup(canonical_provider);
			যদি (match_pattern_list(sk_provider,
			    allowed_providers, 0) != 1) {
				error("Refusing add key: "
				    "provider %s not allowed", sk_provider);
				যাও out;
			}
		}
	}
	যদি ((r = sshkey_shield_private(k)) != 0) {
		error_fr(r, "shield private");
		যাও out;
	}
	যদি (lifetime && !death)
		death = monotime() + lifetime;
	যদি ((id = lookup_identity(k)) == ফাঁকা) {
		id = xcalloc(1, আকার(Identity));
		TAILQ_INSERT_TAIL(&idtab->idlist, id, পরবর্তী);
		/* Increment the number of identities. */
		idtab->nentries++;
	} অন্যথা {
		/* identity not visible, do not update */
		যদি (identity_permitted(id, e, ফাঁকা, ফাঁকা, ফাঁকা) != 0)
			যাও out; /* error already logged */
		/* key state might have been updated */
		sshkey_free(id->চাবি);
		মুক্ত(id->comment);
		মুক্ত(id->sk_provider);
		free_dest_constraints(id->dest_constraints,
		    id->ndest_constraints);
	}
	/* success */
	id->চাবি = k;
	id->comment = comment;
	id->death = death;
	id->confirm = confirm;
	id->sk_provider = sk_provider;
	id->dest_constraints = dest_constraints;
	id->ndest_constraints = ndest_constraints;

	যদি ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ফাঁকা)
		fatal_f("sshkey_fingerprint failed");
	debug_f("add %s %s \"%.100s\" (life: %u) (confirm: %u) "
	    "(provider: %s) (destination constraints: %zu)",
	    sshkey_ssh_name(k), fp, comment, seconds, confirm,
	    sk_provider == ফাঁকা ? "none" : sk_provider, ndest_constraints);
	মুক্ত(fp);
	/* transferred */
	k = ফাঁকা;
	comment = ফাঁকা;
	sk_provider = ফাঁকা;
	dest_constraints = ফাঁকা;
	ndest_constraints = 0;
	success = 1;
 out:
	মুক্ত(sk_provider);
	মুক্ত(comment);
	sshkey_free(k);
	free_dest_constraints(dest_constraints, ndest_constraints);
	send_status(e, success);
}

/* XXX todo: encrypt sensitive data with passphrase */
স্থির শূন্য
process_lock_agent(SocketEntry *e, পূর্ণসংখ্যা lock)
{
	পূর্ণসংখ্যা r, success = 0, delay;
	অক্ষর *passwd;
	u_char passwdhash[LOCK_আকার];
	স্থির u_int fail_গুনতি = 0;
	আকার_t pwlen;

	debug2_f("entering");
	/*
	 * This is deliberately fatal: the user has requested that we lock,
	 * but we can't parse their request properly. The only safe thing to
	 * do is abort.
	 */
	যদি ((r = sshbuf_get_cstring(e->request, &passwd, &pwlen)) != 0)
		fatal_fr(r, "parse");
	যদি (pwlen == 0) {
		debug("empty password not supported");
	} অন্যথা যদি (locked && !lock) {
		যদি (bcrypt_pbkdf(passwd, pwlen, lock_salt, আকার(lock_salt),
		    passwdhash, আকার(passwdhash), LOCK_ROUNDS) < 0)
			fatal("bcrypt_pbkdf");
		যদি (timingsafe_bcmp(passwdhash, lock_pwhash, LOCK_আকার) == 0) {
			debug("agent unlocked");
			locked = 0;
			fail_গুনতি = 0;
			explicit_bzero(lock_pwhash, আকার(lock_pwhash));
			success = 1;
		} অন্যথা {
			/* delay in 0.1s increments up to 10s */
			যদি (fail_গুনতি < 100)
				fail_গুনতি++;
			delay = 100000 * fail_গুনতি;
			debug("unlock failed, delaying %0.1lf seconds",
			    (দ্বিগুণ)delay/1000000);
			usleep(delay);
		}
		explicit_bzero(passwdhash, আকার(passwdhash));
	} অন্যথা যদি (!locked && lock) {
		debug("agent locked");
		locked = 1;
		arc4random_buf(lock_salt, আকার(lock_salt));
		যদি (bcrypt_pbkdf(passwd, pwlen, lock_salt, আকার(lock_salt),
		    lock_pwhash, আকার(lock_pwhash), LOCK_ROUNDS) < 0)
			fatal("bcrypt_pbkdf");
		success = 1;
	}
	freezero(passwd, pwlen);
	send_status(e, success);
}

স্থির শূন্য
no_identities(SocketEntry *e)
{
	কাঠামো sshbuf *বার্তা;
	পূর্ণসংখ্যা r;

	যদি ((বার্তা = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshbuf_put_u8(বার্তা, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
	    (r = sshbuf_put_u32(বার্তা, 0)) != 0 ||
	    (r = sshbuf_put_stringb(e->output, বার্তা)) != 0)
		fatal_fr(r, "compose");
	sshbuf_free(বার্তা);
}

#ifdef ENABLE_PKCS11
/* Add an identity to idlist; takes ownership of 'key' and 'comment' */
স্থির শূন্য
add_p11_identity(কাঠামো sshkey *চাবি, অক্ষর *comment, ধ্রুবক অক্ষর *provider,
    time_t death, u_int confirm, কাঠামো dest_constraint *dest_constraints,
    আকার_t ndest_constraints)
{
	Identity *id;

	যদি (lookup_identity(চাবি) != ফাঁকা) {
		sshkey_free(চাবি);
		মুক্ত(comment);
		ফেরত;
	}
	id = xcalloc(1, আকার(Identity));
	id->চাবি = চাবি;
	id->comment = comment;
	id->provider = xstrdup(provider);
	id->death = death;
	id->confirm = confirm;
	id->dest_constraints = dup_dest_constraints(dest_constraints,
	    ndest_constraints);
	id->ndest_constraints = ndest_constraints;
	TAILQ_INSERT_TAIL(&idtab->idlist, id, পরবর্তী);
	idtab->nentries++;
}

স্থির শূন্য
process_add_smartcard_চাবি(SocketEntry *e)
{
	অক্ষর *provider = ফাঁকা, *pin = ফাঁকা, canonical_provider[PATH_MAX];
	অক্ষর **comments = ফাঁকা;
	পূর্ণসংখ্যা r, i, গুনতি = 0, success = 0, confirm = 0;
	u_int seconds = 0;
	time_t death = 0;
	কাঠামো sshkey **চাবিগুলি = ফাঁকা, *k;
	কাঠামো dest_constraint *dest_constraints = ফাঁকা;
	আকার_t j, ndest_constraints = 0, ncerts = 0;
	কাঠামো sshkey **certs = ফাঁকা;
	পূর্ণসংখ্যা cert_only = 0;

	debug2_f("entering");
	যদি ((r = sshbuf_get_cstring(e->request, &provider, ফাঁকা)) != 0 ||
	    (r = sshbuf_get_cstring(e->request, &pin, ফাঁকা)) != 0) {
		error_fr(r, "parse");
		যাও send;
	}
	যদি (parse_চাবি_constraints(e->request, ফাঁকা, &death, &seconds, &confirm,
	    ফাঁকা, &dest_constraints, &ndest_constraints, &cert_only,
	    &ncerts, &certs) != 0) {
		error_f("failed to parse constraints");
		যাও send;
	}
	dump_dest_constraints(__func__, dest_constraints, ndest_constraints);
	যদি (socket_is_remote(e) && !remote_add_provider) {
		verbose("failed PKCS#11 add of \"%.100s\": remote addition of "
		    "providers is disabled", provider);
		যাও send;
	}
	যদি (realpath(provider, canonical_provider) == ফাঁকা) {
		verbose("failed PKCS#11 add of \"%.100s\": realpath: %s",
		    provider, strerror(errno));
		যাও send;
	}
	যদি (match_pattern_list(canonical_provider, allowed_providers, 0) != 1) {
		verbose("refusing PKCS#11 add of \"%.100s\": "
		    "provider not allowed", canonical_provider);
		যাও send;
	}
	debug_f("add %.100s", canonical_provider);
	যদি (lifetime && !death)
		death = monotime() + lifetime;

	গুনতি = pkcs11_add_provider(canonical_provider, pin, &চাবিগুলি, &comments);
	জন্য (i = 0; i < গুনতি; i++) {
		যদি (comments[i] == ফাঁকা || comments[i][0] == '\0') {
			মুক্ত(comments[i]);
			comments[i] = xstrdup(canonical_provider);
		}
		জন্য (j = 0; j < ncerts; j++) {
			যদি (!sshkey_is_cert(certs[j]))
				চালু;
			যদি (!sshkey_equal_public(চাবিগুলি[i], certs[j]))
				চালু;
			যদি (pkcs11_make_cert(চাবিগুলি[i], certs[j], &k) != 0)
				চালু;
			add_p11_identity(k, xstrdup(comments[i]),
			    canonical_provider, death, confirm,
			    dest_constraints, ndest_constraints);
			success = 1;
		}
		যদি (!cert_only && lookup_identity(চাবিগুলি[i]) == ফাঁকা) {
			add_p11_identity(চাবিগুলি[i], comments[i],
			    canonical_provider, death, confirm,
			    dest_constraints, ndest_constraints);
			চাবিগুলি[i] = ফাঁকা;		/* transferred */
			comments[i] = ফাঁকা;	/* transferred */
			success = 1;
		}
		/* XXX update constraints for existing keys */
		sshkey_free(চাবিগুলি[i]);
		মুক্ত(comments[i]);
	}
send:
	মুক্ত(pin);
	মুক্ত(provider);
	মুক্ত(চাবিগুলি);
	মুক্ত(comments);
	free_dest_constraints(dest_constraints, ndest_constraints);
	জন্য (j = 0; j < ncerts; j++)
		sshkey_free(certs[j]);
	মুক্ত(certs);
	send_status(e, success);
}

স্থির শূন্য
process_remove_smartcard_চাবি(SocketEntry *e)
{
	অক্ষর *provider = ফাঁকা, *pin = ফাঁকা, canonical_provider[PATH_MAX];
	পূর্ণসংখ্যা r, success = 0;
	Identity *id, *nxt;

	debug2_f("entering");
	যদি ((r = sshbuf_get_cstring(e->request, &provider, ফাঁকা)) != 0 ||
	    (r = sshbuf_get_cstring(e->request, &pin, ফাঁকা)) != 0) {
		error_fr(r, "parse");
		যাও send;
	}
	মুক্ত(pin);

	যদি (realpath(provider, canonical_provider) == ফাঁকা) {
		verbose("failed PKCS#11 add of \"%.100s\": realpath: %s",
		    provider, strerror(errno));
		যাও send;
	}

	debug_f("remove %.100s", canonical_provider);
	জন্য (id = TAILQ_FIRST(&idtab->idlist); id; id = nxt) {
		nxt = TAILQ_NEXT(id, পরবর্তী);
		/* Skip file--based keys */
		যদি (id->provider == ফাঁকা)
			চালু;
		যদি (!strcmp(canonical_provider, id->provider)) {
			TAILQ_REMOVE(&idtab->idlist, id, পরবর্তী);
			free_identity(id);
			idtab->nentries--;
		}
	}
	যদি (pkcs11_del_provider(canonical_provider) == 0)
		success = 1;
	অন্যথা
		error_f("pkcs11_del_provider failed");
send:
	মুক্ত(provider);
	send_status(e, success);
}
#endif /* ENABLE_PKCS11 */

স্থির পূর্ণসংখ্যা
process_ext_session_bind(SocketEntry *e)
{
	পূর্ণসংখ্যা r, sid_match, চাবি_match;
	কাঠামো sshkey *চাবি = ফাঁকা;
	কাঠামো sshbuf *sid = ফাঁকা, *sig = ফাঁকা;
	অক্ষর *fp = ফাঁকা;
	আকার_t i;
	u_char fwd = 0;

	debug2_f("entering");
	e->session_bind_attempted = 1;
	যদি ((r = sshkey_froms(e->request, &চাবি)) != 0 ||
	    (r = sshbuf_froms(e->request, &sid)) != 0 ||
	    (r = sshbuf_froms(e->request, &sig)) != 0 ||
	    (r = sshbuf_get_u8(e->request, &fwd)) != 0) {
		error_fr(r, "parse");
		যাও out;
	}
	যদি (sshbuf_len(sid) > AGENT_MAX_SID_LEN) {
		error_f("session ID too long");
		যাও out;
	}
	যদি ((fp = sshkey_fingerprint(চাবি, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ফাঁকা)
		fatal_f("fingerprint failed");
	/* check signature with hostkey on session ID */
	যদি ((r = sshkey_verify(চাবি, sshbuf_ptr(sig), sshbuf_len(sig),
	    sshbuf_ptr(sid), sshbuf_len(sid), ফাঁকা, 0, ফাঁকা)) != 0) {
		error_fr(r, "sshkey_verify for %s %s", sshkey_type(চাবি), fp);
		যাও out;
	}
	/* check whether sid/key already recorded */
	জন্য (i = 0; i < e->nsession_ids; i++) {
		যদি (!e->session_ids[i].forwarded) {
			error_f("attempt to bind session ID to socket "
			    "previously bound for authentication attempt");
			r = -1;
			যাও out;
		}
		sid_match = buf_equal(sid, e->session_ids[i].sid) == 0;
		চাবি_match = sshkey_equal(চাবি, e->session_ids[i].চাবি);
		যদি (sid_match && চাবি_match) {
			debug_f("session ID already recorded for %s %s",
			    sshkey_type(চাবি), fp);
			r = 0;
			যাও out;
		} অন্যথা যদি (sid_match) {
			error_f("session ID recorded against different key "
			    "for %s %s", sshkey_type(চাবি), fp);
			r = -1;
			যাও out;
		}
		/*
		 * new sid with previously-seen key can happen, e.g. multiple
		 * connections to the same host.
		 */
	}
	/* record new key/sid */
	যদি (e->nsession_ids >= AGENT_MAX_SESSION_IDS) {
		error_f("too many session IDs recorded");
		r = -1;
		যাও out;
	}
	e->session_ids = xrecallocarray(e->session_ids, e->nsession_ids,
	    e->nsession_ids + 1, আকার(*e->session_ids));
	i = e->nsession_ids++;
	debug_f("recorded %s %s (slot %zu of %d)", sshkey_type(চাবি), fp, i,
	    AGENT_MAX_SESSION_IDS);
	e->session_ids[i].চাবি = চাবি;
	e->session_ids[i].forwarded = fwd != 0;
	চাবি = ফাঁকা; /* transferred */
	/* can't transfer sid; it's refcounted and scoped to request's life */
	যদি ((e->session_ids[i].sid = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new");
	যদি ((r = sshbuf_putb(e->session_ids[i].sid, sid)) != 0)
		fatal_fr(r, "sshbuf_putb session ID");
	/* success */
	r = 0;
 out:
	মুক্ত(fp);
	sshkey_free(চাবি);
	sshbuf_free(sid);
	sshbuf_free(sig);
	ফেরত r == 0 ? 1 : 0;
}

স্থির পূর্ণসংখ্যা
process_ext_query(SocketEntry *e)
{
	পূর্ণসংখ্যা r;
	কাঠামো sshbuf *বার্তা = ফাঁকা;

	debug2_f("entering");
	যদি ((বার্তা = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshbuf_put_u8(বার্তা, SSH_AGENT_EXTENSION_RESPONSE)) != 0 ||
	    (r = sshbuf_put_cstring(বার্তা, "query")) != 0 ||
	    /* string[]     supported extension types */
	    (r = sshbuf_put_cstring(বার্তা, "session-bind@openssh.com")) != 0)
		fatal_fr(r, "compose");
	যদি ((r = sshbuf_put_stringb(e->output, বার্তা)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(বার্তা);
	ফেরত 1;
}

স্থির শূন্য
process_extension(SocketEntry *e)
{
	পূর্ণসংখ্যা r, replied = 0, success = 0;
	অক্ষর *name;

	debug2_f("entering");
	যদি ((r = sshbuf_get_cstring(e->request, &name, ফাঁকা)) != 0) {
		error_fr(r, "parse");
		send_status(e, 0);
		ফেরত;
	}

	/*
	 * This function can be called while the agent is locked to allow
	 * session binds to be processed for new channels.
	 * Other operations should be refused when locked.
	 */

	যদি (strcmp(name, "session-bind@openssh.com") == 0) {
		success = process_ext_session_bind(e);
	} অন্যথা যদি (locked) {
		debug_f("attempt to use extension \"%s\" while locked", name);
		যাও generic_fail;
	} অন্যথা যদি (strcmp(name, "query") == 0) {
		replied = success = process_ext_query(e);
	} অন্যথা {
		debug_f("unsupported extension \"%s\"", name);
 generic_fail:
		মুক্ত(name);
		send_status(e, 0);
		ফেরত;
	}
	মুক্ত(name);
	/* Agent failures are signalled with a different error code */
	যদি (!replied) {
		send_status_generic(e,
		    success ? SSH_AGENT_SUCCESS : SSH_AGENT_EXTENSION_FAILURE);
	}
}

/*
 * dispatch incoming message.
 * returns 1 on success, 0 for incomplete messages or -1 on error.
 */
স্থির পূর্ণসংখ্যা
process_message(u_int socknum)
{
	u_int বার্তা_len;
	u_char type;
	ধ্রুবক u_char *cp;
	পূর্ণসংখ্যা r;
	SocketEntry *e;

	যদি (socknum >= sockets_alloc)
		fatal_f("sock %u >= allocated %u", socknum, sockets_alloc);
	e = &sockets[socknum];

	যদি (sshbuf_len(e->প্রবেশ) < 5)
		ফেরত 0;		/* Incomplete message header. */
	cp = sshbuf_ptr(e->প্রবেশ);
	বার্তা_len = PEEK_U32(cp);
	যদি (বার্তা_len > AGENT_MAX_LEN) {
		debug_f("socket %u (fd=%d) message too long %u > %u",
		    socknum, e->fd, বার্তা_len, AGENT_MAX_LEN);
		ফেরত -1;
	}
	যদি (sshbuf_len(e->প্রবেশ) < বার্তা_len + 4)
		ফেরত 0;		/* Incomplete message body. */

	/* move the current input to e->request */
	sshbuf_reset(e->request);
	যদি ((r = sshbuf_get_stringb(e->প্রবেশ, e->request)) != 0 ||
	    (r = sshbuf_get_u8(e->request, &type)) != 0) {
		যদি (r == SSH_ERR_MESSAGE_INCOMPLETE ||
		    r == SSH_ERR_STRING_TOO_LARGE) {
			error_fr(r, "parse");
			ফেরত -1;
		}
		fatal_fr(r, "parse");
	}

	debug_f("socket %u (fd=%d) type %d", socknum, e->fd, type);

	/* check whether agent is locked */
	যদি (locked && type != SSH_AGENTC_UNLOCK) {
		নির্বাচন (type) {
		ক্ষেত্র SSH2_AGENTC_REQUEST_IDENTITIES:
			/* send empty lists */
			no_identities(e);
			বিরতি;
		ক্ষেত্র SSH_AGENTC_EXTENSION:
			process_extension(e);
			বিরতি;
		পূর্বনির্ধারিত:
			/* send a fail message for all other request types */
			send_status(e, 0);
		}
		sshbuf_reset(e->request);
		ফেরত 1;
	}

	নির্বাচন (type) {
	ক্ষেত্র SSH_AGENTC_LOCK:
	ক্ষেত্র SSH_AGENTC_UNLOCK:
		process_lock_agent(e, type == SSH_AGENTC_LOCK);
		বিরতি;
	ক্ষেত্র SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES:
		process_remove_all_identities(e); /* safe for !WITH_SSH1 */
		বিরতি;
	/* ssh2 */
	ক্ষেত্র SSH2_AGENTC_SIGN_REQUEST:
		process_sign_request2(e);
		বিরতি;
	ক্ষেত্র SSH2_AGENTC_REQUEST_IDENTITIES:
		process_request_identities(e);
		বিরতি;
	ক্ষেত্র SSH2_AGENTC_ADD_IDENTITY:
	ক্ষেত্র SSH2_AGENTC_ADD_ID_CONSTRAINED:
		process_add_identity(e);
		বিরতি;
	ক্ষেত্র SSH2_AGENTC_REMOVE_IDENTITY:
		process_remove_identity(e);
		বিরতি;
	ক্ষেত্র SSH2_AGENTC_REMOVE_ALL_IDENTITIES:
		process_remove_all_identities(e);
		বিরতি;
#ifdef ENABLE_PKCS11
	ক্ষেত্র SSH_AGENTC_ADD_SMARTCARD_চাবি:
	ক্ষেত্র SSH_AGENTC_ADD_SMARTCARD_চাবি_CONSTRAINED:
		process_add_smartcard_চাবি(e);
		বিরতি;
	ক্ষেত্র SSH_AGENTC_REMOVE_SMARTCARD_চাবি:
		process_remove_smartcard_চাবি(e);
		বিরতি;
#endif /* ENABLE_PKCS11 */
	ক্ষেত্র SSH_AGENTC_EXTENSION:
		process_extension(e);
		বিরতি;
	পূর্বনির্ধারিত:
		/* Unknown message.  Respond with failure. */
		error("Unknown message %d", type);
		sshbuf_reset(e->request);
		send_status(e, 0);
		বিরতি;
	}
	ফেরত 1;
}

স্থির শূন্য
new_socket(sock_type type, পূর্ণসংখ্যা fd)
{
	u_int i, old_alloc, new_alloc;

	debug_f("type = %s", type == AUTH_CONNECTION ? "CONNECTION" :
	    (type == AUTH_SOCKET ? "SOCKET" : "UNKNOWN"));
	set_nonblock(fd);

	যদি (fd > max_fd)
		max_fd = fd;

	জন্য (i = 0; i < sockets_alloc; i++)
		যদি (sockets[i].type == AUTH_UNUSED) {
			sockets[i].fd = fd;
			যদি ((sockets[i].প্রবেশ = sshbuf_new()) == ফাঁকা ||
			    (sockets[i].output = sshbuf_new()) == ফাঁকা ||
			    (sockets[i].request = sshbuf_new()) == ফাঁকা)
				fatal_f("sshbuf_new failed");
			sockets[i].type = type;
			ফেরত;
		}
	old_alloc = sockets_alloc;
	new_alloc = sockets_alloc + 10;
	sockets = xrecallocarray(sockets, old_alloc, new_alloc,
	    আকার(sockets[0]));
	জন্য (i = old_alloc; i < new_alloc; i++)
		sockets[i].type = AUTH_UNUSED;
	sockets_alloc = new_alloc;
	sockets[old_alloc].fd = fd;
	যদি ((sockets[old_alloc].প্রবেশ = sshbuf_new()) == ফাঁকা ||
	    (sockets[old_alloc].output = sshbuf_new()) == ফাঁকা ||
	    (sockets[old_alloc].request = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");
	sockets[old_alloc].type = type;
}

স্থির পূর্ণসংখ্যা
handle_socket_read(u_int socknum)
{
	কাঠামো sockaddr_un sunaddr;
	socklen_t slen;
	uid_t euid;
	gid_t egid;
	পূর্ণসংখ্যা fd;

	slen = আকার(sunaddr);
	fd = accept(sockets[socknum].fd, (কাঠামো sockaddr *)&sunaddr, &slen);
	যদি (fd == -1) {
		error("accept from AUTH_SOCKET: %s", strerror(errno));
		ফেরত -1;
	}
	যদি (getpeereid(fd, &euid, &egid) == -1) {
		error("getpeereid %d failed: %s", fd, strerror(errno));
		close(fd);
		ফেরত -1;
	}
	যদি ((euid != 0) && (getuid() != euid)) {
		error("uid mismatch: peer euid %u != uid %u",
		    (u_int) euid, (u_int) getuid());
		close(fd);
		ফেরত -1;
	}
	new_socket(AUTH_CONNECTION, fd);
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
handle_conn_read(u_int socknum)
{
	অক্ষর buf[AGENT_RBUF_LEN];
	ssize_t len;
	পূর্ণসংখ্যা r;

	যদি ((len = পঠ(sockets[socknum].fd, buf, আকার(buf))) <= 0) {
		যদি (len == -1) {
			যদি (errno == EAGAIN || errno == EINTR)
				ফেরত 0;
			error_f("read error on socket %u (fd %d): %s",
			    socknum, sockets[socknum].fd, strerror(errno));
		}
		ফেরত -1;
	}
	যদি ((r = sshbuf_put(sockets[socknum].প্রবেশ, buf, len)) != 0)
		fatal_fr(r, "compose");
	explicit_bzero(buf, আকার(buf));
	জন্য (;;) {
		যদি ((r = process_message(socknum)) == -1)
			ফেরত -1;
		অন্যথা যদি (r == 0)
			বিরতি;
	}
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
handle_conn_write(u_int socknum)
{
	ssize_t len;
	পূর্ণসংখ্যা r;

	যদি (sshbuf_len(sockets[socknum].output) == 0)
		ফেরত 0; /* shouldn't happen */
	যদি ((len = লিখ(sockets[socknum].fd,
	    sshbuf_ptr(sockets[socknum].output),
	    sshbuf_len(sockets[socknum].output))) <= 0) {
		যদি (len == -1) {
			যদি (errno == EAGAIN || errno == EINTR)
				ফেরত 0;
			error_f("read error on socket %u (fd %d): %s",
			    socknum, sockets[socknum].fd, strerror(errno));
		}
		ফেরত -1;
	}
	যদি ((r = sshbuf_consume(sockets[socknum].output, len)) != 0)
		fatal_fr(r, "consume");
	ফেরত 0;
}

স্থির শূন্য
after_poll(কাঠামো pollfd *pfd, আকার_t npfd, u_int maxfds)
{
	আকার_t i;
	u_int socknum, activefds = npfd;

	জন্য (i = 0; i < npfd; i++) {
		যদি (pfd[i].revents == 0)
			চালু;
		/* Find sockets entry */
		জন্য (socknum = 0; socknum < sockets_alloc; socknum++) {
			যদি (sockets[socknum].type != AUTH_SOCKET &&
			    sockets[socknum].type != AUTH_CONNECTION)
				চালু;
			যদি (pfd[i].fd == sockets[socknum].fd)
				বিরতি;
		}
		যদি (socknum >= sockets_alloc) {
			error_f("no socket for fd %d", pfd[i].fd);
			চালু;
		}
		/* Process events */
		নির্বাচন (sockets[socknum].type) {
		ক্ষেত্র AUTH_SOCKET:
			যদি ((pfd[i].revents & (POLLIN|POLLERR)) == 0)
				বিরতি;
			যদি (npfd > maxfds) {
				debug3("out of fds (active %u >= limit %u); "
				    "skipping accept", activefds, maxfds);
				বিরতি;
			}
			যদি (handle_socket_read(socknum) == 0)
				activefds++;
			বিরতি;
		ক্ষেত্র AUTH_CONNECTION:
			যদি ((pfd[i].revents & (POLLIN|POLLHUP|POLLERR)) != 0 &&
			    handle_conn_read(socknum) != 0)
				যাও close_sock;
			যদি ((pfd[i].revents & (POLLOUT|POLLHUP)) != 0 &&
			    handle_conn_write(socknum) != 0) {
 close_sock:
				যদি (activefds == 0)
					fatal("activefds == 0 at close_sock");
				close_socket(&sockets[socknum]);
				activefds--;
				বিরতি;
			}
			বিরতি;
		পূর্বনির্ধারিত:
			বিরতি;
		}
	}
}

স্থির পূর্ণসংখ্যা
prepare_poll(কাঠামো pollfd **pfdp, আকার_t *npfdp, কাঠামো timespec *timeoutp, u_int maxfds)
{
	কাঠামো pollfd *pfd = *pfdp;
	আকার_t i, j, npfd = 0;
	time_t deadline;
	পূর্ণসংখ্যা r;

	/* Count active sockets */
	জন্য (i = 0; i < sockets_alloc; i++) {
		নির্বাচন (sockets[i].type) {
		ক্ষেত্র AUTH_SOCKET:
		ক্ষেত্র AUTH_CONNECTION:
			npfd++;
			বিরতি;
		ক্ষেত্র AUTH_UNUSED:
			বিরতি;
		পূর্বনির্ধারিত:
			fatal("Unknown socket type %d", sockets[i].type);
			বিরতি;
		}
	}
	যদি (npfd != *npfdp &&
	    (pfd = recallocarray(pfd, *npfdp, npfd, আকার(*pfd))) == ফাঁকা)
		fatal_f("recallocarray failed");
	*pfdp = pfd;
	*npfdp = npfd;

	জন্য (i = j = 0; i < sockets_alloc; i++) {
		নির্বাচন (sockets[i].type) {
		ক্ষেত্র AUTH_SOCKET:
			যদি (npfd > maxfds) {
				debug3("out of fds (active %zu >= limit %u); "
				    "skipping arming listener", npfd, maxfds);
				বিরতি;
			}
			pfd[j].fd = sockets[i].fd;
			pfd[j].revents = 0;
			pfd[j].events = POLLIN;
			j++;
			বিরতি;
		ক্ষেত্র AUTH_CONNECTION:
			pfd[j].fd = sockets[i].fd;
			pfd[j].revents = 0;
			/*
			 * Only prepare to read if we can handle a full-size
			 * input read buffer and enqueue a max size reply..
			 */
			যদি ((r = sshbuf_check_reserve(sockets[i].প্রবেশ,
			    AGENT_RBUF_LEN)) == 0 &&
			    (r = sshbuf_check_reserve(sockets[i].output,
			    AGENT_MAX_LEN)) == 0)
				pfd[j].events = POLLIN;
			অন্যথা যদি (r != SSH_ERR_NO_বাফার_SPACE)
				fatal_fr(r, "reserve");
			যদি (sshbuf_len(sockets[i].output) > 0)
				pfd[j].events |= POLLOUT;
			j++;
			বিরতি;
		পূর্বনির্ধারিত:
			বিরতি;
		}
	}
	deadline = reaper();
	যদি (parent_alive_interval != 0)
		deadline = (deadline == 0) ? parent_alive_interval :
		    MINIMUM(deadline, parent_alive_interval);
	যদি (deadline != 0)
		ptimeout_deadline_sec(timeoutp, deadline);
	ফেরত (1);
}

স্থির শূন্য
cleanup_socket(শূন্য)
{
	যদি (cleanup_pid != 0 && getpid() != cleanup_pid)
		ফেরত;
	debug_f("cleanup");
	যদি (socket_name != ফাঁকা) {
		agent_listener_cleanup(socket_dirspec, socket_name, socket_dir);
		মুক্ত(socket_name);
		socket_name = ফাঁকা;
		মুক্ত(socket_dir);
		socket_dir = ফাঁকা;
	}
}

শূন্য
cleanup_exit(পূর্ণসংখ্যা i)
{
	cleanup_socket();
#ifdef ENABLE_PKCS11
	pkcs11_terminate();
#endif
	_exit(i);
}

স্থির শূন্য
cleanup_handler(পূর্ণসংখ্যা sig)
{
	signalled_exit = sig;
}

স্থির শূন্য
keydrop_handler(পূর্ণসংখ্যা sig)
{
	signalled_keydrop = sig;
}

স্থির শূন্য
check_parent_exists(শূন্য)
{
	/*
	 * If our parent has exited then getppid() will return (pid_t)1,
	 * so testing for that should be safe.
	 */
	যদি (parent_pid != -1 && getppid() != parent_pid) {
		/* printf("Parent has died - Authentication agent exiting.\n"); */
		cleanup_socket();
		_exit(2);
	}
}

স্থির শূন্য
usage(শূন্য)
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

পূর্ণসংখ্যা
প্রধান(পূর্ণসংখ্যা ac, অক্ষর **av)
{
	পূর্ণসংখ্যা c_flag = 0, d_flag = 0, D_flag = 0, k_flag = 0;
	পূর্ণসংখ্যা s_flag = 0, T_flag = 0, u_flag = 0, U_flag = 0;
	পূর্ণসংখ্যা sock = -1, ch, ফলাফল, saved_errno;
	pid_t pid;
 	অক্ষর *homedir = ফাঁকা, *shell, *format, *pidstr, *agentsocket = ফাঁকা;
	অক্ষর *cp, pidstrbuf[1 + 3 * আকার pid];
	অক্ষর *fdstr;
	ধ্রুবক অক্ষর *errstr = ফাঁকা;
	ধ্রুবক অক্ষর *ccp;
#ifdef HAVE_SETRLIMIT
	কাঠামো rlimit rlim;
#endif
	বাহ্যিক পূর্ণসংখ্যা optind;
	বাহ্যিক অক্ষর *optarg;
	আকার_t len;
	mode_t পূর্ব_mask;
	কাঠামো timespec timeout;
	কাঠামো pollfd *pfd = ফাঁকা;
	আকার_t npfd = 0;
	u_int maxfds;
	sigset_t nsigset, osigset;
	পূর্ণসংখ্যা socket_activated = 0;
	কাঠামো passwd *pw;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* drop */
	(শূন্য)setegid(getgid());
	(শূন্য)setgid(getgid());

	platform_disable_tracing(0);	/* strict=no */

	যদি ((pw = getpwuid(getuid())) == ফাঁকা)
		fatal("No user exists for uid %lu", (u_long)getuid());
	pw = pwcopy(pw);

#ifdef RLIMIT_NOFILE
	যদি (getrlimit(RLIMIT_NOFILE, &rlim) == -1)
		fatal("%s: getrlimit: %s", __progname, strerror(errno));
#endif

	__progname = ssh_get_progname(av[0]);
	seed_rng();

	যখন ((ch = getopt(ac, av, "cDdksTuUVA:E:a:O:P:t:")) != -1) {
		নির্বাচন (ch) {
		ক্ষেত্র 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			যদি (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			বিরতি;
		ক্ষেত্র 'c':
			যদি (s_flag)
				usage();
			c_flag++;
			বিরতি;
		ক্ষেত্র 'k':
			k_flag++;
			বিরতি;
		ক্ষেত্র 'O':
			যদি (strcmp(optarg, "no-restrict-websafe") == 0)
				restrict_websafe = 0;
			অন্যথা যদি (strcmp(optarg, "allow-remote-pkcs11") == 0)
				remote_add_provider = 1;
			অন্যথা যদি ((ccp = strprefix(optarg,
			    "websafe-allow=", 0)) != ফাঁকা) {
				যদি (websafe_allowlist != ফাঁকা)
					fatal("websafe-allow already set");
				websafe_allowlist = xstrdup(ccp);
			} অন্যথা
				fatal("Unknown -O option");
			বিরতি;
		ক্ষেত্র 'P':
			যদি (allowed_providers != ফাঁকা)
				fatal("-P option already specified");
			allowed_providers = xstrdup(optarg);
			বিরতি;
		ক্ষেত্র 's':
			যদি (c_flag)
				usage();
			s_flag++;
			বিরতি;
		ক্ষেত্র 'd':
			যদি (d_flag || D_flag)
				usage();
			d_flag++;
			বিরতি;
		ক্ষেত্র 'D':
			যদি (d_flag || D_flag)
				usage();
			D_flag++;
			বিরতি;
		ক্ষেত্র 'a':
			agentsocket = optarg;
			বিরতি;
		ক্ষেত্র 'A':
			socket_dirspec = xstrdup(optarg);
			বিরতি;
		ক্ষেত্র 't':
			যদি ((lifetime = convtime(optarg)) == -1) {
				fprintf(stderr, "Invalid lifetime\n");
				usage();
			}
			বিরতি;
		ক্ষেত্র 'T':
			T_flag++;
			বিরতি;
		ক্ষেত্র 'u':
			u_flag++;
			বিরতি;
		ক্ষেত্র 'U':
			U_flag++;
			বিরতি;
		ক্ষেত্র 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_VERSION, SSH_OPENSSL_VERSION);
			exit(0);
		পূর্বনির্ধারিত:
			usage();
		}
	}
	ac -= optind;
	av += optind;

	যদি (ac > 0 &&
	    (c_flag || k_flag || s_flag || d_flag || D_flag || u_flag))
		usage();
	/* only one of -a, -A and -T allowed */
	যদি (((socket_dirspec != ফাঁকা) + (agentsocket != ফাঁকা) + T_flag) > 1)
		usage();

	log_init(__progname,
	    d_flag ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
	    SYSLOG_FACILITY_AUTH, 1);

	যদি (allowed_providers == ফাঁকা)
		allowed_providers = xstrdup(DEFAULT_ALLOWED_PROVIDERS);
	যদি (websafe_allowlist == ফাঁকা)
		websafe_allowlist = xstrdup(DEFAULT_WEBSAFE_ALLOWLIST);

	যদি (T_flag)
		socket_dirspec = xstrdup(_PATH_SSH_AGENT_SOCKET_TMPDIR);
	অন্যথা যদি (socket_dirspec == ফাঁকা && agentsocket == ফাঁকা)
		socket_dirspec = xstrdup(_PATH_SSH_AGENT_SOCKET_DIR);

	যদি (ac == 0 && !c_flag && !s_flag) {
		shell = getenv("SHELL");
		যদি (shell != ফাঁকা && (len = strlen(shell)) > 2 &&
		    strncmp(shell + len - 3, "csh", 3) == 0)
			c_flag = 1;
	}
	যদি (k_flag) {
		pidstr = getenv(SSH_AGENTPID_ENV_NAME);
		যদি (pidstr == ফাঁকা) {
			fprintf(stderr, "%s not set, cannot kill agent\n",
			    SSH_AGENTPID_ENV_NAME);
			exit(1);
		}
		pid = (পূর্ণসংখ্যা)strtonum(pidstr, 2, INT_MAX, &errstr);
		যদি (errstr) {
			fprintf(stderr,
			    "%s=\"%s\", which is not a good PID: %s\n",
			    SSH_AGENTPID_ENV_NAME, pidstr, errstr);
			exit(1);
		}
		যদি (kill(pid, SIGTERM) == -1) {
			perror("kill");
			exit(1);
		}
		format = c_flag ? "unsetenv %s;\n" : "unset %s;\n";
		printf(format, SSH_AUTHSOCKET_ENV_NAME);
		printf(format, SSH_AGENTPID_ENV_NAME);
		printf("echo Agent pid %ld killed;\n", (long)pid);
		exit(0);
	}
	যদি (u_flag) {
		যদি ((homedir = get_homedir()) == ফাঁকা)
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
	যদি (rlim.rlim_cur < SSH_AGENT_MIN_FDS)
		fatal("%s: file descriptor rlimit %lld too low (minimum %u)",
		    __progname, (long long)rlim.rlim_cur, SSH_AGENT_MIN_FDS);
	maxfds = rlim.rlim_cur - SSH_AGENT_MIN_FDS;

	parent_pid = getpid();

	/* Has the socket been provided via socket activation? */
	যদি (agentsocket == ফাঁকা && ac == 0 && (d_flag || D_flag) &&
	    (pidstr = getenv("LISTEN_PID")) != ফাঁকা &&
	    (fdstr = getenv("LISTEN_FDS")) != ফাঁকা) {
		যদি (strcmp(fdstr, "1") != 0) {
			fatal("unexpected LISTEN_FDS contents "
			    "(want: \"1\" got\"%s\"", fdstr);
		}
		যদি (fcntl(3, F_GETFL) == -1)
			fatal("LISTEN_FDS set but fd 3 unavailable");
		pid = (পূর্ণসংখ্যা)strtonum(pidstr, 1, INT_MAX, &errstr);
		যদি (errstr != ফাঁকা)
			fatal("invalid LISTEN_PID: %s", errstr);
		যদি (pid != getpid())
			fatal("bad LISTEN_PID: %d vs pid %d", pid, getpid());
		debug("using socket activation on fd=3");
		sock = 3;
		socket_activated = 1;
	}

	যদি (sock == -1 && agentsocket == ফাঁকা) {
		/* Listen on a socket in/under a given directory */
		যদি ((homedir = get_homedir()) == ফাঁকা)
			fatal("Couldn't determine home directory");
		যদি (!U_flag) {
			agent_cleanup_stale(socket_dirspec,
			    pw->pw_name, pw->pw_uid, homedir, 0);
		}
		যদি (agent_listener(socket_dirspec, pw->pw_name, pw->pw_uid,
		    homedir, getpid(), "local", &sock, &socket_name,
		    &socket_dir) != 0)
			fatal_f("Couldn't prepare agent socket");
		মুক্ত(homedir);
	} অন্যথা যদি (sock == -1) {
		/* Listen on explicit socket path */
		পূর্ব_mask = umask(0177);
		socket_name = xstrdup(agentsocket);
		যদি ((sock = unix_listener(socket_name,
		    SSH_LISTEN_BACKLOG, 0)) < 0) {
			মুক্ত(socket_name);
			socket_name = ফাঁকা; /* Don't unlink existing file */
			cleanup_exit(1);
		}
		umask(পূর্ব_mask);
	}

	closefrom(sock == -1 ? STDERR_FILENO + 1 : sock + 1);

	/*
	 * Create socket early so it will exist before command gets run from
	 * the parent.
	 */
	যদি (sock == -1) {
		পূর্ব_mask = umask(0177);
		sock = unix_listener(socket_name, SSH_LISTEN_BACKLOG, 0);
		যদি (sock < 0) {
			/* XXX - unix_listener() calls error() not perror() */
			*socket_name = '\0'; /* Don't unlink existing file */
			cleanup_exit(1);
		}
		umask(পূর্ব_mask);
	}

	/*
	 * Fork, and have the parent execute the command, if any, or present
	 * the socket data.  The child continues as the authentication agent.
	 */
	যদি (D_flag || d_flag) {
		log_init(__progname,
		    d_flag ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
		    SYSLOG_FACILITY_AUTH, 1);
		যদি (socket_name != ফাঁকা) {
			cp = argv_assemble(1, &socket_name);
			format = c_flag ?
			    "setenv %s %s;\n" : "%s=%s; export %s;\n";
			printf(format, SSH_AUTHSOCKET_ENV_NAME, cp,
			    SSH_AUTHSOCKET_ENV_NAME);
			মুক্ত(cp);
			printf("echo Agent pid %ld;\n", (long)parent_pid);
			fflush(stdout);
		}
		যাও skip;
	}
	pid = fork();
	যদি (pid == -1) {
		perror("fork");
		cleanup_exit(1);
	}
	যদি (pid != 0) {		/* Parent - execute the given command. */
		close(sock);
		snprintf(pidstrbuf, আকার pidstrbuf, "%ld", (long)pid);
		যদি (ac == 0) {
			format = c_flag ? "setenv %s %s;\n" : "%s=%s; export %s;\n";
			cp = argv_assemble(1, &socket_name);
			printf(format, SSH_AUTHSOCKET_ENV_NAME, cp,
			    SSH_AUTHSOCKET_ENV_NAME);
			printf(format, SSH_AGENTPID_ENV_NAME, pidstrbuf,
			    SSH_AGENTPID_ENV_NAME);
			মুক্ত(cp);
			printf("echo Agent pid %ld;\n", (long)pid);
			exit(0);
		}
		যদি (setenv(SSH_AUTHSOCKET_ENV_NAME, socket_name, 1) == -1 ||
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

	যদি (setsid() == -1) {
		error("setsid: %s", strerror(errno));
		cleanup_exit(1);
	}

	(শূন্য)chdir("/");
	যদি (stdfd_devnull(1, 1, 1) == -1)
		error_f("stdfd_devnull failed");

#ifdef HAVE_SETRLIMIT
	/* deny core dumps, since memory contains unencrypted private keys */
	rlim.rlim_cur = rlim.rlim_max = 0;
	যদি (setrlimit(RLIMIT_CORE, &rlim) == -1) {
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
	যদি (ac > 0)
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

	যদি (socket_name != ফাঁকা && unveil(socket_name, "c") == -1) {
		fatal("%s: unveil %s %s", __progname, socket_name,
		    strerror(errno));
	}
	যদি (socket_dir != ফাঁকা && unveil(socket_dir, "c") == -1) {
		fatal("%s: unveil %s %s", __progname, socket_dir,
		    strerror(errno));
	}
	যদি (unveil("/", "r") == -1)
		fatal("%s: unveil /: %s", __progname, strerror(errno));
	যদি ((ccp = getenv("SSH_SK_HELPER")) == ফাঁকা || *ccp == '\0')
		ccp = _PATH_SSH_SK_HELPER;
	যদি (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, strerror(errno));
	যদি ((ccp = getenv("SSH_PKCS11_HELPER")) == ফাঁকা || *ccp == '\0')
		ccp = _PATH_SSH_PKCS11_HELPER;
	যদি (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, strerror(errno));
	যদি ((ccp = getenv("SSH_ASKPASS")) == ফাঁকা || *ccp == '\0')
		ccp = _PATH_SSH_ASKPASS_DEFAULT;
	যদি (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, strerror(errno));
	যদি (unveil("/dev/null", "rw") == -1)
		fatal("%s: unveil /dev/null: %s", __progname, strerror(errno));
	যদি (pledge("stdio rpath cpath wpath unix id proc exec", ফাঁকা) == -1)
		fatal("%s: pledge: %s", __progname, strerror(errno));
	platform_pledge_agent();

	যখন (1) {
		sigprocmask(SIG_BLOCK, &nsigset, &osigset);
		যদি (signalled_exit != 0) {
			logit("exiting on signal %d", (পূর্ণসংখ্যা)signalled_exit);
			cleanup_exit((signalled_exit == SIGTERM &&
			    socket_activated) ? 0 : 2);
		}
		যদি (signalled_keydrop) {
			logit("signal %d received; removing all keys",
			    (পূর্ণসংখ্যা)signalled_keydrop);
			remove_all_identities();
			signalled_keydrop = 0;
		}
		ptimeout_init(&timeout);
		prepare_poll(&pfd, &npfd, &timeout, maxfds);
		ফলাফল = ppoll(pfd, npfd, ptimeout_get_tsp(&timeout), &osigset);
		sigprocmask(SIG_SETMASK, &osigset, ফাঁকা);
		saved_errno = errno;
		যদি (parent_alive_interval != 0)
			check_parent_exists();
		(শূন্য) reaper();	/* remove expired keys */
		যদি (ফলাফল == -1) {
			যদি (saved_errno == EINTR)
				চালু;
			fatal("poll: %s", strerror(saved_errno));
		} অন্যথা যদি (ফলাফল > 0)
			after_poll(pfd, npfd, maxfds);
	}
	/* NOTREACHED */
}
