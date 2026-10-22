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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/time.h>
#अन्तर्भाव <sys/queue.h>
#अन्तर्भाव <sys/resource.h>
#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <sys/stat.h>
#अन्तर्भाव <sys/un.h>
#अन्तर्भाव <sys/wait.h>

#ifdef WITH_OPENSSL
#अन्तर्भाव <openssl/evp.h>
#अन्तर्भाव "openbsd-compat/openssl-compat.h"
#endif

#अन्तर्भाव <errno.h>
#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <paths.h>
#अन्तर्भाव <poll.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <limits.h>
#अन्तर्भाव <time.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <util.h>
#अन्तर्भाव <pwd.h>

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "ssh.h"
#अन्तर्भाव "ssh2.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "authfd.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "digest.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "match.h"
#अन्तर्भाव "msg.h"
#अन्तर्भाव "pathnames.h"
#अन्तर्भाव "ssh-pkcs11.h"
#अन्तर्भाव "sk-api.h"
#अन्तर्भाव "myproposal.h"
#अन्तर्भाव "version.h"

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

प्रकारनिर्देश गणना {
	AUTH_UNUSED = 0,
	AUTH_SOCKET = 1,
	AUTH_CONNECTION = 2,
} sock_type;

संरचना hostkey_sid {
	संरचना sshkey *कुञ्चिका;
	संरचना sshbuf *sid;
	पूर्णाङ्क forwarded;
};

प्रकारनिर्देश संरचना socket_entry {
	पूर्णाङ्क fd;
	sock_type type;
	संरचना sshbuf *निवेशः;
	संरचना sshbuf *output;
	संरचना sshbuf *request;
	size_t nsession_ids;
	संरचना hostkey_sid *session_ids;
	पूर्णाङ्क session_bind_attempted;
} SocketEntry;

u_int sockets_alloc = 0;
SocketEntry *sockets = रिक्त;

प्रकारनिर्देश संरचना identity {
	TAILQ_ENTRY(identity) next;
	संरचना sshkey *कुञ्चिका;
	वर्ण *comment;
	वर्ण *provider;
	time_t death;
	u_int confirm;
	वर्ण *sk_provider;
	संरचना dest_constraint *dest_constraints;
	size_t ndest_constraints;
} Identity;

संरचना idtable {
	पूर्णाङ्क nentries;
	TAILQ_HEAD(idqueue, identity) idlist;
};

/* private key table */
संरचना idtable *idtab;

पूर्णाङ्क max_fd = 0;

/* pid of shell == parent of agent */
pid_t parent_pid = -1;
time_t parent_alive_interval = 0;

स्थिर sig_atomic_t signalled_exit;
स्थिर sig_atomic_t signalled_keydrop;

/* pid of process for which cleanup_socket is applicable */
pid_t cleanup_pid = 0;

/* pathname and directory for AUTH_SOCKET */
स्थिर वर्ण *socket_name;
स्थिर वर्ण *socket_dir;
स्थिर वर्ण *socket_dirspec;

/* Pattern-list of allowed PKCS#11/Security key paths */
स्थिर वर्ण *allowed_providers;

/*
 * Allows PKCS11 providers or SK keys that use non-internal providers to
 * be added over a remote connection (identified by session-bind@openssh.com).
 */
स्थिर पूर्णाङ्क remote_add_provider;

/* locking */
#define LOCK_SIZE	32
#define LOCK_SALT_SIZE	16
#define LOCK_ROUNDS	1
पूर्णाङ्क locked = 0;
u_char lock_pwhash[LOCK_SIZE];
u_char lock_salt[LOCK_SALT_SIZE];

बाह्य वर्ण *__progname;

/* Default lifetime in seconds (0 == forever) */
स्थिर पूर्णाङ्क lifetime = 0;

स्थिर पूर्णाङ्क fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* Refuse signing of non-SSH messages for web-origin FIDO keys */
स्थिर पूर्णाङ्क restrict_websafe = 1;
स्थिर वर्ण *websafe_allowlist;

स्थिर शून्य
close_socket(SocketEntry *e)
{
	size_t i;

	close(e->fd);
	sshbuf_free(e->निवेशः);
	sshbuf_free(e->output);
	sshbuf_free(e->request);
	प्रति (i = 0; i < e->nsession_ids; i++) {
		sshkey_free(e->session_ids[i].कुञ्चिका);
		sshbuf_free(e->session_ids[i].sid);
	}
	मुक्त(e->session_ids);
	memset(e, '\0', परिमाण(*e));
	e->fd = -1;
	e->type = AUTH_UNUSED;
}

स्थिर शून्य
idtab_init(शून्य)
{
	idtab = xcalloc(1, परिमाण(*idtab));
	TAILQ_INIT(&idtab->idlist);
	idtab->nentries = 0;
}

स्थिर शून्य
free_dest_constraint_hop(संरचना dest_constraint_hop *dch)
{
	u_int i;

	जइ (dch == रिक्त)
		प्रत्यागम;
	मुक्त(dch->user);
	मुक्त(dch->hostname);
	प्रति (i = 0; i < dch->nkeys; i++)
		sshkey_free(dch->कुञ्चिकाः[i]);
	मुक्त(dch->कुञ्चिकाः);
	मुक्त(dch->कुञ्चिका_is_ca);
}

स्थिर शून्य
free_dest_constraints(संरचना dest_constraint *dcs, size_t ndcs)
{
	size_t i;

	प्रति (i = 0; i < ndcs; i++) {
		free_dest_constraint_hop(&dcs[i].from);
		free_dest_constraint_hop(&dcs[i].to);
	}
	मुक्त(dcs);
}

#ifdef ENABLE_PKCS11
स्थिर शून्य
dup_dest_constraint_hop(ध्रुव संरचना dest_constraint_hop *dch,
    संरचना dest_constraint_hop *out)
{
	u_int i;
	पूर्णाङ्क r;

	out->user = dch->user == रिक्त ? रिक्त : xstrdup(dch->user);
	out->hostname = dch->hostname == रिक्त ? रिक्त : xstrdup(dch->hostname);
	out->is_ca = dch->is_ca;
	out->nkeys = dch->nkeys;
	out->कुञ्चिकाः = out->nkeys == 0 ? रिक्त :
	    xcalloc(out->nkeys, परिमाण(*out->कुञ्चिकाः));
	out->कुञ्चिका_is_ca = out->nkeys == 0 ? रिक्त :
	    xcalloc(out->nkeys, परिमाण(*out->कुञ्चिका_is_ca));
	प्रति (i = 0; i < dch->nkeys; i++) {
		जइ (dch->कुञ्चिकाः[i] != रिक्त &&
		    (r = sshkey_from_private(dch->कुञ्चिकाः[i],
		    &(out->कुञ्चिकाः[i]))) != 0)
			fatal_fr(r, "copy key");
		out->कुञ्चिका_is_ca[i] = dch->कुञ्चिका_is_ca[i];
	}
}

स्थिर संरचना dest_constraint *
dup_dest_constraints(ध्रुव संरचना dest_constraint *dcs, size_t ndcs)
{
	size_t i;
	संरचना dest_constraint *ret;

	जइ (ndcs == 0)
		प्रत्यागम रिक्त;
	ret = xcalloc(ndcs, परिमाण(*ret));
	प्रति (i = 0; i < ndcs; i++) {
		dup_dest_constraint_hop(&dcs[i].from, &ret[i].from);
		dup_dest_constraint_hop(&dcs[i].to, &ret[i].to);
	}
	प्रत्यागम ret;
}
#endif /* ENABLE_PKCS11 */

#ifdef DEBUG_CONSTRAINTS
स्थिर शून्य
dump_dest_constraint_hop(ध्रुव संरचना dest_constraint_hop *dch)
{
	u_int i;
	वर्ण *fp;

	debug_f("user %s hostname %s is_ca %d nkeys %u",
	    dch->user == रिक्त ? "(null)" : dch->user,
	    dch->hostname == रिक्त ? "(null)" : dch->hostname,
	    dch->is_ca, dch->nkeys);
	प्रति (i = 0; i < dch->nkeys; i++) {
		fp = रिक्त;
		जइ (dch->कुञ्चिकाः[i] != रिक्त &&
		    (fp = sshkey_fingerprint(dch->कुञ्चिकाः[i],
		    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == रिक्त)
			fatal_f("fingerprint failed");
		debug_f("key %u/%u: %s%s%s key_is_ca %d", i, dch->nkeys,
		    dch->कुञ्चिकाः[i] == रिक्त ? "" : sshkey_ssh_name(dch->कुञ्चिकाः[i]),
		    dch->कुञ्चिकाः[i] == रिक्त ? "" : " ",
		    dch->कुञ्चिकाः[i] == रिक्त ? "none" : fp,
		    dch->कुञ्चिका_is_ca[i]);
		मुक्त(fp);
	}
}
#endif /* DEBUG_CONSTRAINTS */

स्थिर शून्य
dump_dest_constraints(ध्रुव वर्ण *context,
    ध्रुव संरचना dest_constraint *dcs, size_t ndcs)
{
#ifdef DEBUG_CONSTRAINTS
	size_t i;

	debug_f("%s: %zu constraints", context, ndcs);
	प्रति (i = 0; i < ndcs; i++) {
		debug_f("constraint %zu / %zu: from: ", i, ndcs);
		dump_dest_constraint_hop(&dcs[i].from);
		debug_f("constraint %zu / %zu: to: ", i, ndcs);
		dump_dest_constraint_hop(&dcs[i].to);
	}
	debug_f("done for %s", context);
#endif /* DEBUG_CONSTRAINTS */
}

स्थिर शून्य
free_identity(Identity *id)
{
	sshkey_free(id->कुञ्चिका);
	मुक्त(id->provider);
	मुक्त(id->comment);
	मुक्त(id->sk_provider);
	free_dest_constraints(id->dest_constraints, id->ndest_constraints);
	मुक्त(id);
}

/*
 * Match 'key' against the key/CA list in a destination constraint hop
 * Returns 0 on success or -1 otherwise.
 */
स्थिर पूर्णाङ्क
match_कुञ्चिका_hop(ध्रुव वर्ण *tag, ध्रुव संरचना sshkey *कुञ्चिका,
    ध्रुव संरचना dest_constraint_hop *dch)
{
	ध्रुव वर्ण *reason = रिक्त;
	ध्रुव वर्ण *hostname = dch->hostname ? dch->hostname : "(ORIGIN)";
	u_int i;
	वर्ण *fp;

	जइ (कुञ्चिका == रिक्त)
		प्रत्यागम -1;
	/* XXX logspam */
	जइ ((fp = sshkey_fingerprint(कुञ्चिका, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == रिक्त)
		fatal_f("fingerprint failed");
	debug3_f("%s: entering hostname %s, requested key %s %s, %u keys avail",
	    tag, hostname, sshkey_type(कुञ्चिका), fp, dch->nkeys);
	मुक्त(fp);
	प्रति (i = 0; i < dch->nkeys; i++) {
		जइ (dch->कुञ्चिकाः[i] == रिक्त)
			प्रत्यागम -1;
		/* XXX logspam */
		जइ ((fp = sshkey_fingerprint(dch->कुञ्चिकाः[i], SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == रिक्त)
			fatal_f("fingerprint failed");
		debug3_f("%s: key %u: %s%s %s", tag, i,
		    dch->कुञ्चिका_is_ca[i] ? "CA " : "",
		    sshkey_type(dch->कुञ्चिकाः[i]), fp);
		मुक्त(fp);
		जइ (!sshkey_is_cert(कुञ्चिका)) {
			/* plain key */
			जइ (dch->कुञ्चिका_is_ca[i] ||
			    !sshkey_equal(कुञ्चिका, dch->कुञ्चिकाः[i]))
				अनुवर्त;
			प्रत्यागम 0;
		}
		/* certificate */
		जइ (!dch->कुञ्चिका_is_ca[i])
			अनुवर्त;
		जइ (कुञ्चिका->cert == रिक्त || कुञ्चिका->cert->signature_कुञ्चिका == रिक्त)
			प्रत्यागम -1; /* shouldn't happen */
		जइ (!sshkey_equal(कुञ्चिका->cert->signature_कुञ्चिका, dch->कुञ्चिकाः[i]))
			अनुवर्त;
		जइ (sshkey_cert_check_host(कुञ्चिका, hostname,
		    SSH_ALLOWED_CA_SIGALGS, &reason) != 0) {
			debug_f("cert %s / hostname %s rejected: %s",
			    कुञ्चिका->cert->कुञ्चिका_id, hostname, reason);
			अनुवर्त;
		}
		प्रत्यागम 0;
	}
	प्रत्यागम -1;
}

/* Check destination constraints on an identity against the hostkey/user */
स्थिर पूर्णाङ्क
permitted_by_dest_constraints(ध्रुव संरचना sshkey *fromkey,
    ध्रुव संरचना sshkey *tokey, Identity *id, ध्रुव वर्ण *user,
    ध्रुव वर्ण **hostnamep)
{
	size_t i;
	संरचना dest_constraint *d;

	जइ (hostnamep != रिक्त)
		*hostnamep = रिक्त;
	प्रति (i = 0; i < id->ndest_constraints; i++) {
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
		जइ (fromkey == रिक्त) {
			/* We are matching the first hop */
			जइ (d->from.hostname != रिक्त || d->from.nkeys != 0)
				अनुवर्त;
		} अण्णहा जइ (match_कुञ्चिका_hop("from", fromkey, &d->from) != 0)
			अनुवर्त;

		/* Match 'to' key */
		जइ (tokey != रिक्त && match_कुञ्चिका_hop("to", tokey, &d->to) != 0)
			अनुवर्त;

		/* Match user if specified */
		जइ (d->to.user != रिक्त && user != रिक्त &&
		    !match_pattern(user, d->to.user))
			अनुवर्त;

		/* successfully matched this constraint */
		जइ (hostnamep != रिक्त)
			*hostnamep = d->to.hostname;
		debug2_f("allowed for hostname %s",
		    d->to.hostname == रिक्त ? "*" : d->to.hostname);
		प्रत्यागम 0;
	}
	/* no match */
	debug2_f("%s identity \"%s\" not permitted for this destination",
	    sshkey_type(id->कुञ्चिका), id->comment);
	प्रत्यागम -1;
}

/*
 * Check whether hostkeys on a SocketEntry and the optionally specified user
 * are permitted by the destination constraints on the Identity.
 * Returns 0 on success or -1 otherwise.
 */
स्थिर पूर्णाङ्क
identity_permitted(Identity *id, SocketEntry *e, वर्ण *user,
    ध्रुव वर्ण **forward_hostnamep, ध्रुव वर्ण **last_hostnamep)
{
	size_t i;
	ध्रुव वर्ण **hp;
	संरचना hostkey_sid *hks;
	ध्रुव संरचना sshkey *fromkey = रिक्त;
	ध्रुव वर्ण *test_user;
	वर्ण *fp1, *fp2;

	/* XXX remove logspam */
	debug3_f("entering: key %s comment \"%s\", %zu socket bindings, "
	    "%zu constraints", sshkey_type(id->कुञ्चिका), id->comment,
	    e->nsession_ids, id->ndest_constraints);
	जइ (id->ndest_constraints == 0)
		प्रत्यागम 0; /* unconstrained */
	जइ (e->session_bind_attempted && e->nsession_ids == 0) {
		error_f("previous session bind failed on socket");
		प्रत्यागम -1;
	}
	जइ (e->nsession_ids == 0)
		प्रत्यागम 0; /* local use */
	/*
	 * Walk through the hops recorded by session_id and try to find a
	 * constraint that satisfies each.
	 */
	प्रति (i = 0; i < e->nsession_ids; i++) {
		hks = e->session_ids + i;
		जइ (hks->कुञ्चिका == रिक्त)
			fatal_f("internal error: no bound key");
		/* XXX remove logspam */
		fp1 = fp2 = रिक्त;
		जइ (fromkey != रिक्त &&
		    (fp1 = sshkey_fingerprint(fromkey, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == रिक्त)
			fatal_f("fingerprint failed");
		जइ ((fp2 = sshkey_fingerprint(hks->कुञ्चिका, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == रिक्त)
			fatal_f("fingerprint failed");
		debug3_f("socketentry fd=%d, entry %zu %s, "
		    "from hostkey %s %s to user %s hostkey %s %s",
		    e->fd, i, hks->forwarded ? "FORWARD" : "AUTH",
		    fromkey ? sshkey_type(fromkey) : "(ORIGIN)",
		    fromkey ? fp1 : "", user ? user : "(ANY)",
		    sshkey_type(hks->कुञ्चिका), fp2);
		मुक्त(fp1);
		मुक्त(fp2);
		/*
		 * Record the hostnames for the initial forwarding and
		 * the final destination.
		 */
		hp = रिक्त;
		जइ (i == e->nsession_ids - 1)
			hp = last_hostnamep;
		अण्णहा जइ (i == 0)
			hp = forward_hostnamep;
		/* Special handling for final recorded binding */
		test_user = रिक्त;
		जइ (i == e->nsession_ids - 1) {
			/* Can only check user at final hop */
			test_user = user;
			/*
			 * user is only presented for signature requests.
			 * If this is the case, make sure last binding is not
			 * for a forwarding.
			 */
			जइ (hks->forwarded && user != रिक्त) {
				error_f("tried to sign on forwarding hop");
				प्रत्यागम -1;
			}
		} अण्णहा जइ (!hks->forwarded) {
			error_f("tried to forward though signing bind");
			प्रत्यागम -1;
		}
		जइ (permitted_by_dest_constraints(fromkey, hks->कुञ्चिका, id,
		    test_user, hp) != 0)
			प्रत्यागम -1;
		fromkey = hks->कुञ्चिका;
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
	जइ (hks->forwarded && user == रिक्त &&
	    permitted_by_dest_constraints(hks->कुञ्चिका, रिक्त, id,
	    रिक्त, रिक्त) != 0) {
		debug3_f("key permitted at host but not after");
		प्रत्यागम -1;
	}

	/* success */
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
socket_is_remote(SocketEntry *e)
{
	प्रत्यागम e->session_bind_attempted || (e->nsession_ids != 0);
}

/* return matching private key for given public key */
स्थिर Identity *
lookup_identity(संरचना sshkey *कुञ्चिका)
{
	Identity *id;

	TAILQ_FOREACH(id, &idtab->idlist, next) {
		जइ (sshkey_equal(कुञ्चिका, id->कुञ्चिका))
			प्रत्यागम (id);
	}
	प्रत्यागम (रिक्त);
}

/* Check confirmation of keysign request */
स्थिर पूर्णाङ्क
confirm_कुञ्चिका(Identity *id, ध्रुव वर्ण *extra)
{
	वर्ण *p;
	पूर्णाङ्क ret = -1;

	p = sshkey_fingerprint(id->कुञ्चिका, fingerprint_hash, SSH_FP_DEFAULT);
	जइ (p != रिक्त &&
	    ask_permission("Allow use of key %s?\nKey fingerprint %s.%s%s",
	    id->comment, p,
	    extra == रिक्त ? "" : "\n", extra == रिक्त ? "" : extra))
		ret = 0;
	मुक्त(p);

	प्रत्यागम (ret);
}

स्थिर शून्य
send_status_generic(SocketEntry *e, u_int code)
{
	पूर्णाङ्क r;

	जइ ((r = sshbuf_put_u32(e->output, 1)) != 0 ||
	    (r = sshbuf_put_u8(e->output, code)) != 0)
		fatal_fr(r, "compose");
}

स्थिर शून्य
send_status(SocketEntry *e, पूर्णाङ्क success)
{
	send_status_generic(e,
	    success ? SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE);
}

/* send list of supported public keys to 'client' */
स्थिर शून्य
process_request_identities(SocketEntry *e)
{
	Identity *id;
	संरचना sshbuf *सन्देशः, *कुञ्चिकाः;
	पूर्णाङ्क r;
	u_int i = 0, nentries = 0;
	वर्ण *fp;

	debug2_f("entering");

	जइ ((सन्देशः = sshbuf_new()) == रिक्त || (कुञ्चिकाः = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	TAILQ_FOREACH(id, &idtab->idlist, next) {
		जइ ((fp = sshkey_fingerprint(id->कुञ्चिका, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == रिक्त)
			fatal_f("fingerprint failed");
		debug_f("key %u / %u: %s %s", i++, idtab->nentries,
		    sshkey_ssh_name(id->कुञ्चिका), fp);
		dump_dest_constraints(__func__,
		    id->dest_constraints, id->ndest_constraints);
		मुक्त(fp);
		/* identity not visible, don't include in response */
		जइ (identity_permitted(id, e, रिक्त, रिक्त, रिक्त) != 0)
			अनुवर्त;
		जइ ((r = sshkey_puts(id->कुञ्चिका, कुञ्चिकाः)) != 0 ||
		    (r = sshbuf_put_cstring(कुञ्चिकाः, id->comment)) != 0) {
			error_fr(r, "compose key/comment");
			अनुवर्त;
		}
		nentries++;
	}
	debug2_f("replying with %u allowed of %u available keys",
	    nentries, idtab->nentries);
	जइ ((r = sshbuf_put_u8(सन्देशः, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
	    (r = sshbuf_put_u32(सन्देशः, nentries)) != 0 ||
	    (r = sshbuf_putb(सन्देशः, कुञ्चिकाः)) != 0)
		fatal_fr(r, "compose");
	जइ ((r = sshbuf_put_stringb(e->output, सन्देशः)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(सन्देशः);
	sshbuf_free(कुञ्चिकाः);
}


स्थिर वर्ण *
agent_decode_alg(संरचना sshkey *कुञ्चिका, u_int flags)
{
	जइ (कुञ्चिका->type == कुञ्चिका_RSA) {
		जइ (flags & SSH_AGENT_RSA_SHA2_256)
			प्रत्यागम "rsa-sha2-256";
		अण्णहा जइ (flags & SSH_AGENT_RSA_SHA2_512)
			प्रत्यागम "rsa-sha2-512";
	} अण्णहा जइ (कुञ्चिका->type == कुञ्चिका_RSA_CERT) {
		जइ (flags & SSH_AGENT_RSA_SHA2_256)
			प्रत्यागम "rsa-sha2-256-cert-v01@openssh.com";
		अण्णहा जइ (flags & SSH_AGENT_RSA_SHA2_512)
			प्रत्यागम "rsa-sha2-512-cert-v01@openssh.com";
	}
	प्रत्यागम रिक्त;
}

/*
 * Attempt to parse the contents of a buffer as a SSH publickey userauth
 * request, checking its contents for consistency and matching the embedded
 * key against the one that is being used for signing.
 * Note: does not modify msg buffer.
 * Optionally extract the username, session ID and/or hostkey from the request.
 */
स्थिर पूर्णाङ्क
parse_userauth_request(संरचना sshbuf *सन्देशः, ध्रुव संरचना sshkey *expected_कुञ्चिका,
    वर्ण **userp, संरचना sshbuf **sess_idp, संरचना sshkey **hostkeyp)
{
	संरचना sshbuf *b = रिक्त, *sess_id = रिक्त;
	वर्ण *user = रिक्त, *service = रिक्त, *method = रिक्त, *pkalg = रिक्त;
	पूर्णाङ्क r;
	u_char t, sig_follows;
	संरचना sshkey *mkey = रिक्त, *hostkey = रिक्त;

	जइ (userp != रिक्त)
		*userp = रिक्त;
	जइ (sess_idp != रिक्त)
		*sess_idp = रिक्त;
	जइ (hostkeyp != रिक्त)
		*hostkeyp = रिक्त;
	जइ ((b = sshbuf_fromb(सन्देशः)) == रिक्त)
		fatal_f("sshbuf_fromb");

	/* SSH userauth request */
	जइ ((r = sshbuf_froms(b, &sess_id)) != 0)
		गच्छ out;
	जइ (sshbuf_len(sess_id) == 0) {
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	जइ ((r = sshbuf_get_u8(b, &t)) != 0 || /* SSH2_MSG_USERAUTH_REQUEST */
	    (r = sshbuf_get_cstring(b, &user, रिक्त)) != 0 || /* server user */
	    (r = sshbuf_get_cstring(b, &service, रिक्त)) != 0 || /* service */
	    (r = sshbuf_get_cstring(b, &method, रिक्त)) != 0 || /* method */
	    (r = sshbuf_get_u8(b, &sig_follows)) != 0 || /* sig-follows */
	    (r = sshbuf_get_cstring(b, &pkalg, रिक्त)) != 0 || /* alg */
	    (r = sshkey_froms(b, &mkey)) != 0) /*कुञ्चिका*/
		गच्छ out;
	जइ (t != SSH2_सन्देशः_USERAUTH_REQUEST ||
	    sig_follows != 1 ||
	    strcmp(service, "ssh-connection") != 0 ||
	    !sshkey_equal(expected_कुञ्चिका, mkey) ||
	    sshkey_type_from_name(pkalg) != expected_कुञ्चिका->type) {
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	जइ (strcmp(method, "publickey-hostbound-v00@openssh.com") == 0) {
		जइ ((r = sshkey_froms(b, &hostkey)) != 0)
			गच्छ out;
	} अण्णहा जइ (strcmp(method, "publickey") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	जइ (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	/* success */
	r = 0;
	debug3_f("well formed userauth");
	जइ (userp != रिक्त) {
		*userp = user;
		user = रिक्त;
	}
	जइ (sess_idp != रिक्त) {
		*sess_idp = sess_id;
		sess_id = रिक्त;
	}
	जइ (hostkeyp != रिक्त) {
		*hostkeyp = hostkey;
		hostkey = रिक्त;
	}
 out:
	sshbuf_free(b);
	sshbuf_free(sess_id);
	मुक्त(user);
	मुक्त(service);
	मुक्त(method);
	मुक्त(pkalg);
	sshkey_free(mkey);
	sshkey_free(hostkey);
	प्रत्यागम r;
}

/*
 * Attempt to parse the contents of a buffer as a SSHSIG signature request.
 * Note: does not modify buffer.
 */
स्थिर पूर्णाङ्क
parse_sshsig_request(संरचना sshbuf *सन्देशः)
{
	पूर्णाङ्क r;
	संरचना sshbuf *b;

	जइ ((b = sshbuf_fromb(सन्देशः)) == रिक्त)
		fatal_f("sshbuf_fromb");

	जइ ((r = sshbuf_cmp(b, 0, "SSHSIG", 6)) != 0 ||
	    (r = sshbuf_consume(b, 6)) != 0 ||
	    (r = sshbuf_get_cstring(b, रिक्त, रिक्त)) != 0 || /* namespace */
	    (r = sshbuf_get_string_direct(b, रिक्त, रिक्त)) != 0 || /* reserved */
	    (r = sshbuf_get_cstring(b, रिक्त, रिक्त)) != 0 || /* hashalg */
	    (r = sshbuf_get_string_direct(b, रिक्त, रिक्त)) != 0) /* H(msg) */
		गच्छ out;
	जइ (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	प्रत्यागम r;
}

/*
 * This function inspects a message to be signed by a FIDO key that has a
 * web-like application string (i.e. one that does not begin with "ssh:".
 * It checks that the message is one of those expected for SSH operations
 * (pubkey userauth, sshsig, CA key signing) to exclude signing challenges
 * for the web.
 */
स्थिर पूर्णाङ्क
check_websafe_message_contents(संरचना sshkey *कुञ्चिका, संरचना sshbuf *data)
{
	जइ (parse_userauth_request(data, कुञ्चिका, रिक्त, रिक्त, रिक्त) == 0) {
		debug_f("signed data matches public key userauth request");
		प्रत्यागम 1;
	}
	जइ (parse_sshsig_request(data) == 0) {
		debug_f("signed data matches SSHSIG signature request");
		प्रत्यागम 1;
	}

	/* XXX check CA signature operation */

	error("web-origin key attempting to sign non-SSH message");
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
buf_equal(ध्रुव संरचना sshbuf *a, ध्रुव संरचना sshbuf *b)
{
	जइ (sshbuf_ptr(a) == रिक्त || sshbuf_ptr(b) == रिक्त)
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;
	जइ (sshbuf_len(a) != sshbuf_len(b))
		प्रत्यागम SSH_ERR_INVALID_FORMAT;
	जइ (timingsafe_bcmp(sshbuf_ptr(a), sshbuf_ptr(b), sshbuf_len(a)) != 0)
		प्रत्यागम SSH_ERR_INVALID_FORMAT;
	प्रत्यागम 0;
}

/* ssh2 only */
स्थिर शून्य
process_sign_request2(SocketEntry *e)
{
	u_char *signature = रिक्त;
	size_t slen = 0;
	u_int compat = 0, flags;
	पूर्णाङ्क r, ok = -1, retried = 0;
	वर्ण *fp = रिक्त, *pin = रिक्त, *prompt = रिक्त;
	वर्ण *user = रिक्त, *sig_dest = रिक्त;
	ध्रुव वर्ण *fwd_host = रिक्त, *dest_host = रिक्त;
	संरचना sshbuf *सन्देशः = रिक्त, *data = रिक्त, *sid = रिक्त;
	संरचना sshkey *कुञ्चिका = रिक्त, *hostkey = रिक्त;
	संरचना identity *id;
	संरचना notifier_ctx *notifier = रिक्त;

	debug_f("entering");

	जइ ((सन्देशः = sshbuf_new()) == रिक्त || (data = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	जइ ((r = sshkey_froms(e->request, &कुञ्चिका)) != 0 ||
	    (r = sshbuf_get_stringb(e->request, data)) != 0 ||
	    (r = sshbuf_get_u32(e->request, &flags)) != 0) {
		error_fr(r, "parse");
		गच्छ send;
	}

	जइ ((id = lookup_identity(कुञ्चिका)) == रिक्त) {
		verbose_f("%s key not found", sshkey_type(कुञ्चिका));
		गच्छ send;
	}
	जइ ((fp = sshkey_fingerprint(कुञ्चिका, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == रिक्त)
		fatal_f("fingerprint failed");

	जइ (id->ndest_constraints != 0) {
		जइ (e->nsession_ids == 0) {
			logit_f("refusing use of destination-constrained key "
			    "to sign on unbound connection");
			गच्छ send;
		}
		जइ (parse_userauth_request(data, कुञ्चिका, &user, &sid,
		    &hostkey) != 0) {
			logit_f("refusing use of destination-constrained key "
			   "to sign an unidentified signature");
			गच्छ send;
		}
		/* XXX logspam */
		debug_f("user=%s", user);
		जइ (identity_permitted(id, e, user, &fwd_host, &dest_host) != 0)
			गच्छ send;
		/* XXX display fwd_host/dest_host in askpass UI */
		/*
		 * Ensure that the session ID is the most recent one
		 * registered on the socket - it should have been bound by
		 * ssh immediately before userauth.
		 */
		जइ (buf_equal(sid,
		    e->session_ids[e->nsession_ids - 1].sid) != 0) {
			error_f("unexpected session ID (%zu listed) on "
			    "signature request for target user %s with "
			    "key %s %s", e->nsession_ids, user,
			    sshkey_type(id->कुञ्चिका), fp);
			गच्छ send;
		}
		/*
		 * Ensure that the hostkey embedded in the signature matches
		 * the one most recently bound to the socket. An exception is
		 * made for the initial forwarding hop.
		 */
		जइ (e->nsession_ids > 1 && hostkey == रिक्त) {
			error_f("refusing use of destination-constrained key: "
			    "no hostkey recorded in signature for forwarded "
			    "connection");
			गच्छ send;
		}
		जइ (hostkey != रिक्त && !sshkey_equal(hostkey,
		    e->session_ids[e->nsession_ids - 1].कुञ्चिका)) {
			error_f("refusing use of destination-constrained key: "
			    "mismatch between hostkey in request and most "
			    "recently bound session");
			गच्छ send;
		}
		xasprintf(&sig_dest, "public key authentication request for "
		    "user \"%s\" to listed host", user);
	}
	जइ (id->confirm && confirm_कुञ्चिका(id, sig_dest) != 0) {
		verbose_f("user refused key");
		गच्छ send;
	}
	जइ (sshkey_is_sk(id->कुञ्चिका)) {
		जइ (restrict_websafe &&
		    match_pattern_list(id->कुञ्चिका->sk_application,
		    websafe_allowlist, 0) != 1 &&
		    !check_websafe_message_contents(कुञ्चिका, data)) {
			/* error already logged */
			गच्छ send;
		}
		जइ (id->कुञ्चिका->sk_flags & SSH_SK_USER_PRESENCE_REQD) {
			notifier = notify_start(0,
			    "Confirm user presence for key %s %s%s%s",
			    sshkey_type(id->कुञ्चिका), fp,
			    sig_dest == रिक्त ? "" : "\n",
			    sig_dest == रिक्त ? "" : sig_dest);
		}
	}
 retry_pin:
	जइ ((r = sshkey_sign(id->कुञ्चिका, &signature, &slen,
	    sshbuf_ptr(data), sshbuf_len(data), agent_decode_alg(कुञ्चिका, flags),
	    id->sk_provider, pin, compat)) != 0) {
		debug_fr(r, "sshkey_sign");
		जइ (pin == रिक्त && !retried && sshkey_is_sk(id->कुञ्चिका) &&
		    r == SSH_ERR_कुञ्चिका_WRONG_PASSPHRASE) {
			notify_complete(notifier, रिक्त);
			notifier = रिक्त;
			/* XXX include sig_dest */
			xasprintf(&prompt, "Enter PIN%sfor %s key %s: ",
			    (id->कुञ्चिका->sk_flags & SSH_SK_USER_PRESENCE_REQD) ?
			    " and confirm user presence " : " ",
			    sshkey_type(id->कुञ्चिका), fp);
			pin = read_passphrase(prompt, RP_USE_ASKPASS);
			retried = 1;
			गच्छ retry_pin;
		}
		error_fr(r, "sshkey_sign");
		गच्छ send;
	}
	/* Success */
	ok = 0;
	debug_f("good signature");
 send:
	notify_complete(notifier, "User presence confirmed");

	जइ (ok == 0) {
		जइ ((r = sshbuf_put_u8(सन्देशः, SSH2_AGENT_SIGN_RESPONSE)) != 0 ||
		    (r = sshbuf_put_string(सन्देशः, signature, slen)) != 0)
			fatal_fr(r, "compose");
	} अण्णहा जइ ((r = sshbuf_put_u8(सन्देशः, SSH_AGENT_FAILURE)) != 0)
		fatal_fr(r, "compose failure");

	जइ ((r = sshbuf_put_stringb(e->output, सन्देशः)) != 0)
		fatal_fr(r, "enqueue");

	sshbuf_free(sid);
	sshbuf_free(data);
	sshbuf_free(सन्देशः);
	sshkey_free(कुञ्चिका);
	sshkey_free(hostkey);
	मुक्त(fp);
	मुक्त(signature);
	मुक्त(sig_dest);
	मुक्त(user);
	मुक्त(prompt);
	जइ (pin != रिक्त)
		freezero(pin, strlen(pin));
}

/* shared */
स्थिर शून्य
process_remove_identity(SocketEntry *e)
{
	पूर्णाङ्क r, success = 0;
	संरचना sshkey *कुञ्चिका = रिक्त;
	Identity *id;

	debug2_f("entering");
	जइ ((r = sshkey_froms(e->request, &कुञ्चिका)) != 0) {
		error_fr(r, "parse key");
		गच्छ done;
	}
	जइ ((id = lookup_identity(कुञ्चिका)) == रिक्त) {
		debug_f("key not found");
		गच्छ done;
	}
	/* identity not visible, cannot be removed */
	जइ (identity_permitted(id, e, रिक्त, रिक्त, रिक्त) != 0)
		गच्छ done; /* error already logged */
	/* We have this key, free it. */
	जइ (idtab->nentries < 1)
		fatal_f("internal error: nentries %d", idtab->nentries);
	TAILQ_REMOVE(&idtab->idlist, id, next);
	free_identity(id);
	idtab->nentries--;
	success = 1;
 done:
	sshkey_free(कुञ्चिका);
	send_status(e, success);
}

स्थिर शून्य
remove_all_identities(शून्य)
{
	Identity *id;

	debug2_f("entering");
	/* Loop over all identities and clear the keys. */
	प्रति (id = TAILQ_FIRST(&idtab->idlist); id;
	    id = TAILQ_FIRST(&idtab->idlist)) {
		TAILQ_REMOVE(&idtab->idlist, id, next);
		free_identity(id);
	}

	/* Mark that there are no identities. */
	idtab->nentries = 0;
}

स्थिर शून्य
process_remove_all_identities(SocketEntry *e)
{
	remove_all_identities();

	/* Send success. */
	send_status(e, 1);
}

/* removes expired keys and returns number of seconds until the next expiry */
स्थिर time_t
reaper(शून्य)
{
	time_t deadline = 0, now = monotime();
	Identity *id, *nxt;

	प्रति (id = TAILQ_FIRST(&idtab->idlist); id; id = nxt) {
		nxt = TAILQ_NEXT(id, next);
		जइ (id->death == 0)
			अनुवर्त;
		जइ (now >= id->death) {
			debug("expiring key '%s'", id->comment);
			TAILQ_REMOVE(&idtab->idlist, id, next);
			free_identity(id);
			idtab->nentries--;
		} अण्णहा
			deadline = (deadline == 0) ? id->death :
			    MINIMUM(deadline, id->death);
	}
	जइ (deadline == 0 || deadline <= now)
		प्रत्यागम 0;
	अण्णहा
		प्रत्यागम (deadline - now);
}

स्थिर पूर्णाङ्क
parse_dest_constraint_hop(संरचना sshbuf *b, संरचना dest_constraint_hop *dch)
{
	u_char कुञ्चिका_is_ca;
	size_t elen = 0, userlen = 0;
	पूर्णाङ्क r;
	संरचना sshkey *k = रिक्त;
	वर्ण *fp;

	memset(dch, '\0', परिमाण(*dch));
	जइ ((r = sshbuf_get_cstring(b, &dch->user, &userlen)) != 0 ||
	    (r = sshbuf_get_cstring(b, &dch->hostname, रिक्त)) != 0 ||
	    (r = sshbuf_get_string_direct(b, रिक्त, &elen)) != 0) {
		error_fr(r, "parse");
		गच्छ out;
	}
	जइ (elen != 0) {
		error_f("unsupported extensions (len %zu)", elen);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		गच्छ out;
	}
	जइ (*dch->hostname == '\0') {
		मुक्त(dch->hostname);
		dch->hostname = रिक्त;
	}
	जइ (*dch->user == '\0') {
		मुक्त(dch->user);
		dch->user = रिक्त;
	} अण्णहा जइ (userlen > AGENT_USER_CONSTRAINT_MAX_LEN) {
		error_f("user match pattern too long");
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	जाव (sshbuf_len(b) != 0) {
		dch->कुञ्चिकाः = xrecallocarray(dch->कुञ्चिकाः, dch->nkeys,
		    dch->nkeys + 1, परिमाण(*dch->कुञ्चिकाः));
		dch->कुञ्चिका_is_ca = xrecallocarray(dch->कुञ्चिका_is_ca, dch->nkeys,
		    dch->nkeys + 1, परिमाण(*dch->कुञ्चिका_is_ca));
		जइ ((r = sshkey_froms(b, &k)) != 0 ||
		    (r = sshbuf_get_u8(b, &कुञ्चिका_is_ca)) != 0)
			गच्छ out;
		जइ ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == रिक्त)
			fatal_f("fingerprint failed");
		debug3_f("%s%s%s: adding %skey %s %s",
		    dch->user == रिक्त ? "" : dch->user,
		    dch->user == रिक्त ? "" : "@",
		    dch->hostname, कुञ्चिका_is_ca ? "CA " : "", sshkey_type(k), fp);
		मुक्त(fp);
		dch->कुञ्चिकाः[dch->nkeys] = k;
		dch->कुञ्चिका_is_ca[dch->nkeys] = कुञ्चिका_is_ca != 0;
		dch->nkeys++;
		k = रिक्त; /* transferred */
	}
	/* success */
	r = 0;
 out:
	sshkey_free(k);
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
parse_dest_constraint(संरचना sshbuf *m, संरचना dest_constraint *dc)
{
	संरचना sshbuf *b = रिक्त, *frombuf = रिक्त, *tobuf = रिक्त;
	पूर्णाङ्क r;
	size_t elen = 0;

	debug3_f("entering");

	memset(dc, '\0', परिमाण(*dc));
	जइ ((r = sshbuf_froms(m, &b)) != 0 ||
	    (r = sshbuf_froms(b, &frombuf)) != 0 ||
	    (r = sshbuf_froms(b, &tobuf)) != 0 ||
	    (r = sshbuf_get_string_direct(b, रिक्त, &elen)) != 0) {
		error_fr(r, "parse");
		गच्छ out;
	}
	जइ ((r = parse_dest_constraint_hop(frombuf, &dc->from)) != 0 ||
	    (r = parse_dest_constraint_hop(tobuf, &dc->to)) != 0)
		गच्छ out; /* already logged */
	जइ (elen != 0) {
		error_f("unsupported extensions (len %zu)", elen);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		गच्छ out;
	}
	debug2_f("parsed %s (%u keys) > %s%s%s (%u keys)",
	    dc->from.hostname ? dc->from.hostname : "(ORIGIN)", dc->from.nkeys,
	    dc->to.user ? dc->to.user : "", dc->to.user ? "@" : "",
	    dc->to.hostname ? dc->to.hostname : "(ANY)", dc->to.nkeys);
	/* check consistency */
	जइ ((dc->from.hostname == रिक्त) != (dc->from.nkeys == 0) ||
	    dc->from.user != रिक्त) {
		error_f("inconsistent \"from\" specification");
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	जइ (dc->to.hostname == रिक्त || dc->to.nkeys == 0) {
		error_f("incomplete \"to\" specification");
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	sshbuf_free(frombuf);
	sshbuf_free(tobuf);
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
parse_कुञ्चिका_constraint_extension(संरचना sshbuf *m, वर्ण **sk_providerp,
    संरचना dest_constraint **dcsp, size_t *ndcsp, पूर्णाङ्क *cert_onlyp,
    संरचना sshkey ***certs, size_t *ncerts)
{
	वर्ण *ext_name = रिक्त;
	पूर्णाङ्क r;
	संरचना sshbuf *b = रिक्त;
	u_char v;
	संरचना sshkey *k;

	जइ ((r = sshbuf_get_cstring(m, &ext_name, रिक्त)) != 0) {
		error_fr(r, "parse constraint extension");
		गच्छ out;
	}
	debug_f("constraint ext %s", ext_name);
	जइ (strcmp(ext_name, "sk-provider@openssh.com") == 0) {
		जइ (sk_providerp == रिक्त) {
			error_f("%s not valid here", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			गच्छ out;
		}
		जइ (*sk_providerp != रिक्त) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			गच्छ out;
		}
		जइ ((r = sshbuf_get_cstring(m, sk_providerp, रिक्त)) != 0) {
			error_fr(r, "parse %s", ext_name);
			गच्छ out;
		}
	} अण्णहा जइ (strcmp(ext_name,
	    "restrict-destination-v00@openssh.com") == 0) {
		जइ (*dcsp != रिक्त) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			गच्छ out;
		}
		जइ ((r = sshbuf_froms(m, &b)) != 0) {
			error_fr(r, "parse %s outer", ext_name);
			गच्छ out;
		}
		जाव (sshbuf_len(b) != 0) {
			जइ (*ndcsp >= AGENT_MAX_DEST_CONSTRAINTS) {
				error_f("too many %s constraints", ext_name);
				r = SSH_ERR_INVALID_FORMAT;
				गच्छ out;
			}
			*dcsp = xrecallocarray(*dcsp, *ndcsp, *ndcsp + 1,
			    परिमाण(**dcsp));
			जइ ((r = parse_dest_constraint(b,
			    *dcsp + (*ndcsp)++)) != 0)
				गच्छ out; /* error already logged */
		}
	} अण्णहा जइ (strcmp(ext_name,
	    "associated-certs-v00@openssh.com") == 0) {
		जइ (certs == रिक्त || ncerts == रिक्त || cert_onlyp == रिक्त) {
			error_f("%s not valid here", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			गच्छ out;
		}
		जइ (*certs != रिक्त) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			गच्छ out;
		}
		जइ ((r = sshbuf_get_u8(m, &v)) != 0 ||
		    (r = sshbuf_froms(m, &b)) != 0) {
			error_fr(r, "parse %s", ext_name);
			गच्छ out;
		}
		*cert_onlyp = v != 0;
		जाव (sshbuf_len(b) != 0) {
			जइ (*ncerts >= AGENT_MAX_EXT_CERTS) {
				error_f("too many %s constraints", ext_name);
				r = SSH_ERR_INVALID_FORMAT;
				गच्छ out;
			}
			*certs = xrecallocarray(*certs, *ncerts, *ncerts + 1,
			    परिमाण(**certs));
			जइ ((r = sshkey_froms(b, &k)) != 0) {
				error_fr(r, "parse key");
				गच्छ out;
			}
			(*certs)[(*ncerts)++] = k;
		}
	} अण्णहा {
		error_f("unsupported constraint \"%s\"", ext_name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		गच्छ out;
	}
	/* success */
	r = 0;
 out:
	मुक्त(ext_name);
	sshbuf_free(b);
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
parse_कुञ्चिका_constraints(संरचना sshbuf *m, संरचना sshkey *k, time_t *deathp,
    u_int *secondsp, पूर्णाङ्क *confirmp, वर्ण **sk_providerp,
    संरचना dest_constraint **dcsp, size_t *ndcsp,
    पूर्णाङ्क *cert_onlyp, size_t *ncerts, संरचना sshkey ***certs)
{
	u_char ctype;
	पूर्णाङ्क r;
	u_int seconds;

	जाव (sshbuf_len(m)) {
		जइ ((r = sshbuf_get_u8(m, &ctype)) != 0) {
			error_fr(r, "parse constraint type");
			गच्छ out;
		}
		विकल्प (ctype) {
		पक्ष SSH_AGENT_CONSTRAIN_LIFETIME:
			जइ (*deathp != 0) {
				error_f("lifetime already set");
				r = SSH_ERR_INVALID_FORMAT;
				गच्छ out;
			}
			जइ ((r = sshbuf_get_u32(m, &seconds)) != 0) {
				error_fr(r, "parse lifetime constraint");
				गच्छ out;
			}
			*deathp = monotime() + seconds;
			*secondsp = seconds;
			भङ्ग;
		पक्ष SSH_AGENT_CONSTRAIN_CONFIRM:
			जइ (*confirmp != 0) {
				error_f("confirm already set");
				r = SSH_ERR_INVALID_FORMAT;
				गच्छ out;
			}
			*confirmp = 1;
			भङ्ग;
		पक्ष SSH_AGENT_CONSTRAIN_EXTENSION:
			जइ ((r = parse_कुञ्चिका_constraint_extension(m,
			    sk_providerp, dcsp, ndcsp,
			    cert_onlyp, certs, ncerts)) != 0)
				गच्छ out; /* error already logged */
			भङ्ग;
		स्वभाव:
			error_f("Unknown constraint %d", ctype);
			r = SSH_ERR_FEATURE_UNSUPPORTED;
			गच्छ out;
		}
	}
	/* success */
	r = 0;
 out:
	प्रत्यागम r;
}

स्थिर शून्य
process_add_identity(SocketEntry *e)
{
	Identity *id;
	पूर्णाङ्क success = 0, confirm = 0;
	वर्ण *fp, *comment = रिक्त, *sk_provider = रिक्त;
	वर्ण canonical_provider[PATH_MAX];
	time_t death = 0;
	u_int seconds = 0;
	संरचना dest_constraint *dest_constraints = रिक्त;
	size_t ndest_constraints = 0;
	संरचना sshkey *k = रिक्त;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;

	debug2_f("entering");
	जइ ((r = sshkey_private_deserialize(e->request, &k)) != 0 ||
	    k == रिक्त ||
	    (r = sshbuf_get_cstring(e->request, &comment, रिक्त)) != 0) {
		error_fr(r, "parse");
		गच्छ out;
	}
	जइ (parse_कुञ्चिका_constraints(e->request, k, &death, &seconds, &confirm,
	    &sk_provider, &dest_constraints, &ndest_constraints,
	    रिक्त, रिक्त, रिक्त) != 0) {
		error_f("failed to parse constraints");
		sshbuf_reset(e->request);
		गच्छ out;
	}
	dump_dest_constraints(__func__, dest_constraints, ndest_constraints);

	जइ (sk_provider != रिक्त) {
		जइ (!sshkey_is_sk(k)) {
			error("Cannot add provider: %s is not an "
			    "authenticator-hosted key", sshkey_type(k));
			गच्छ out;
		}
		जइ (strcasecmp(sk_provider, "internal") == 0) {
			debug_f("internal provider");
		} अण्णहा {
			जइ (socket_is_remote(e) && !remote_add_provider) {
				verbose("failed add of SK provider \"%.100s\": "
				    "remote addition of providers is disabled",
				    sk_provider);
				गच्छ out;
			}
			जइ (realpath(sk_provider, canonical_provider) == रिक्त) {
				verbose("failed provider \"%.100s\": "
				    "realpath: %s", sk_provider,
				    strerror(errno));
				गच्छ out;
			}
			मुक्त(sk_provider);
			sk_provider = xstrdup(canonical_provider);
			जइ (match_pattern_list(sk_provider,
			    allowed_providers, 0) != 1) {
				error("Refusing add key: "
				    "provider %s not allowed", sk_provider);
				गच्छ out;
			}
		}
	}
	जइ ((r = sshkey_shield_private(k)) != 0) {
		error_fr(r, "shield private");
		गच्छ out;
	}
	जइ (lifetime && !death)
		death = monotime() + lifetime;
	जइ ((id = lookup_identity(k)) == रिक्त) {
		id = xcalloc(1, परिमाण(Identity));
		TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
		/* Increment the number of identities. */
		idtab->nentries++;
	} अण्णहा {
		/* identity not visible, do not update */
		जइ (identity_permitted(id, e, रिक्त, रिक्त, रिक्त) != 0)
			गच्छ out; /* error already logged */
		/* key state might have been updated */
		sshkey_free(id->कुञ्चिका);
		मुक्त(id->comment);
		मुक्त(id->sk_provider);
		free_dest_constraints(id->dest_constraints,
		    id->ndest_constraints);
	}
	/* success */
	id->कुञ्चिका = k;
	id->comment = comment;
	id->death = death;
	id->confirm = confirm;
	id->sk_provider = sk_provider;
	id->dest_constraints = dest_constraints;
	id->ndest_constraints = ndest_constraints;

	जइ ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == रिक्त)
		fatal_f("sshkey_fingerprint failed");
	debug_f("add %s %s \"%.100s\" (life: %u) (confirm: %u) "
	    "(provider: %s) (destination constraints: %zu)",
	    sshkey_ssh_name(k), fp, comment, seconds, confirm,
	    sk_provider == रिक्त ? "none" : sk_provider, ndest_constraints);
	मुक्त(fp);
	/* transferred */
	k = रिक्त;
	comment = रिक्त;
	sk_provider = रिक्त;
	dest_constraints = रिक्त;
	ndest_constraints = 0;
	success = 1;
 out:
	मुक्त(sk_provider);
	मुक्त(comment);
	sshkey_free(k);
	free_dest_constraints(dest_constraints, ndest_constraints);
	send_status(e, success);
}

/* XXX todo: encrypt sensitive data with passphrase */
स्थिर शून्य
process_lock_agent(SocketEntry *e, पूर्णाङ्क lock)
{
	पूर्णाङ्क r, success = 0, delay;
	वर्ण *passwd;
	u_char passwdhash[LOCK_SIZE];
	स्थिर u_int fail_गणनम् = 0;
	size_t pwlen;

	debug2_f("entering");
	/*
	 * This is deliberately fatal: the user has requested that we lock,
	 * but we can't parse their request properly. The only safe thing to
	 * do is abort.
	 */
	जइ ((r = sshbuf_get_cstring(e->request, &passwd, &pwlen)) != 0)
		fatal_fr(r, "parse");
	जइ (pwlen == 0) {
		debug("empty password not supported");
	} अण्णहा जइ (locked && !lock) {
		जइ (bcrypt_pbkdf(passwd, pwlen, lock_salt, परिमाण(lock_salt),
		    passwdhash, परिमाण(passwdhash), LOCK_ROUNDS) < 0)
			fatal("bcrypt_pbkdf");
		जइ (timingsafe_bcmp(passwdhash, lock_pwhash, LOCK_SIZE) == 0) {
			debug("agent unlocked");
			locked = 0;
			fail_गणनम् = 0;
			explicit_bzero(lock_pwhash, परिमाण(lock_pwhash));
			success = 1;
		} अण्णहा {
			/* delay in 0.1s increments up to 10s */
			जइ (fail_गणनम् < 100)
				fail_गणनम्++;
			delay = 100000 * fail_गणनम्;
			debug("unlock failed, delaying %0.1lf seconds",
			    (द्विगुण)delay/1000000);
			usleep(delay);
		}
		explicit_bzero(passwdhash, परिमाण(passwdhash));
	} अण्णहा जइ (!locked && lock) {
		debug("agent locked");
		locked = 1;
		arc4random_buf(lock_salt, परिमाण(lock_salt));
		जइ (bcrypt_pbkdf(passwd, pwlen, lock_salt, परिमाण(lock_salt),
		    lock_pwhash, परिमाण(lock_pwhash), LOCK_ROUNDS) < 0)
			fatal("bcrypt_pbkdf");
		success = 1;
	}
	freezero(passwd, pwlen);
	send_status(e, success);
}

स्थिर शून्य
no_identities(SocketEntry *e)
{
	संरचना sshbuf *सन्देशः;
	पूर्णाङ्क r;

	जइ ((सन्देशः = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	जइ ((r = sshbuf_put_u8(सन्देशः, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
	    (r = sshbuf_put_u32(सन्देशः, 0)) != 0 ||
	    (r = sshbuf_put_stringb(e->output, सन्देशः)) != 0)
		fatal_fr(r, "compose");
	sshbuf_free(सन्देशः);
}

#ifdef ENABLE_PKCS11
/* Add an identity to idlist; takes ownership of 'key' and 'comment' */
स्थिर शून्य
add_p11_identity(संरचना sshkey *कुञ्चिका, वर्ण *comment, ध्रुव वर्ण *provider,
    time_t death, u_int confirm, संरचना dest_constraint *dest_constraints,
    size_t ndest_constraints)
{
	Identity *id;

	जइ (lookup_identity(कुञ्चिका) != रिक्त) {
		sshkey_free(कुञ्चिका);
		मुक्त(comment);
		प्रत्यागम;
	}
	id = xcalloc(1, परिमाण(Identity));
	id->कुञ्चिका = कुञ्चिका;
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

स्थिर शून्य
process_add_smartcard_कुञ्चिका(SocketEntry *e)
{
	वर्ण *provider = रिक्त, *pin = रिक्त, canonical_provider[PATH_MAX];
	वर्ण **comments = रिक्त;
	पूर्णाङ्क r, i, गणनम् = 0, success = 0, confirm = 0;
	u_int seconds = 0;
	time_t death = 0;
	संरचना sshkey **कुञ्चिकाः = रिक्त, *k;
	संरचना dest_constraint *dest_constraints = रिक्त;
	size_t j, ndest_constraints = 0, ncerts = 0;
	संरचना sshkey **certs = रिक्त;
	पूर्णाङ्क cert_only = 0;

	debug2_f("entering");
	जइ ((r = sshbuf_get_cstring(e->request, &provider, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(e->request, &pin, रिक्त)) != 0) {
		error_fr(r, "parse");
		गच्छ send;
	}
	जइ (parse_कुञ्चिका_constraints(e->request, रिक्त, &death, &seconds, &confirm,
	    रिक्त, &dest_constraints, &ndest_constraints, &cert_only,
	    &ncerts, &certs) != 0) {
		error_f("failed to parse constraints");
		गच्छ send;
	}
	dump_dest_constraints(__func__, dest_constraints, ndest_constraints);
	जइ (socket_is_remote(e) && !remote_add_provider) {
		verbose("failed PKCS#11 add of \"%.100s\": remote addition of "
		    "providers is disabled", provider);
		गच्छ send;
	}
	जइ (realpath(provider, canonical_provider) == रिक्त) {
		verbose("failed PKCS#11 add of \"%.100s\": realpath: %s",
		    provider, strerror(errno));
		गच्छ send;
	}
	जइ (match_pattern_list(canonical_provider, allowed_providers, 0) != 1) {
		verbose("refusing PKCS#11 add of \"%.100s\": "
		    "provider not allowed", canonical_provider);
		गच्छ send;
	}
	debug_f("add %.100s", canonical_provider);
	जइ (lifetime && !death)
		death = monotime() + lifetime;

	गणनम् = pkcs11_add_provider(canonical_provider, pin, &कुञ्चिकाः, &comments);
	प्रति (i = 0; i < गणनम्; i++) {
		जइ (comments[i] == रिक्त || comments[i][0] == '\0') {
			मुक्त(comments[i]);
			comments[i] = xstrdup(canonical_provider);
		}
		प्रति (j = 0; j < ncerts; j++) {
			जइ (!sshkey_is_cert(certs[j]))
				अनुवर्त;
			जइ (!sshkey_equal_public(कुञ्चिकाः[i], certs[j]))
				अनुवर्त;
			जइ (pkcs11_make_cert(कुञ्चिकाः[i], certs[j], &k) != 0)
				अनुवर्त;
			add_p11_identity(k, xstrdup(comments[i]),
			    canonical_provider, death, confirm,
			    dest_constraints, ndest_constraints);
			success = 1;
		}
		जइ (!cert_only && lookup_identity(कुञ्चिकाः[i]) == रिक्त) {
			add_p11_identity(कुञ्चिकाः[i], comments[i],
			    canonical_provider, death, confirm,
			    dest_constraints, ndest_constraints);
			कुञ्चिकाः[i] = रिक्त;		/* transferred */
			comments[i] = रिक्त;	/* transferred */
			success = 1;
		}
		/* XXX update constraints for existing keys */
		sshkey_free(कुञ्चिकाः[i]);
		मुक्त(comments[i]);
	}
send:
	मुक्त(pin);
	मुक्त(provider);
	मुक्त(कुञ्चिकाः);
	मुक्त(comments);
	free_dest_constraints(dest_constraints, ndest_constraints);
	प्रति (j = 0; j < ncerts; j++)
		sshkey_free(certs[j]);
	मुक्त(certs);
	send_status(e, success);
}

स्थिर शून्य
process_remove_smartcard_कुञ्चिका(SocketEntry *e)
{
	वर्ण *provider = रिक्त, *pin = रिक्त, canonical_provider[PATH_MAX];
	पूर्णाङ्क r, success = 0;
	Identity *id, *nxt;

	debug2_f("entering");
	जइ ((r = sshbuf_get_cstring(e->request, &provider, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(e->request, &pin, रिक्त)) != 0) {
		error_fr(r, "parse");
		गच्छ send;
	}
	मुक्त(pin);

	जइ (realpath(provider, canonical_provider) == रिक्त) {
		verbose("failed PKCS#11 add of \"%.100s\": realpath: %s",
		    provider, strerror(errno));
		गच्छ send;
	}

	debug_f("remove %.100s", canonical_provider);
	प्रति (id = TAILQ_FIRST(&idtab->idlist); id; id = nxt) {
		nxt = TAILQ_NEXT(id, next);
		/* Skip file--based keys */
		जइ (id->provider == रिक्त)
			अनुवर्त;
		जइ (!strcmp(canonical_provider, id->provider)) {
			TAILQ_REMOVE(&idtab->idlist, id, next);
			free_identity(id);
			idtab->nentries--;
		}
	}
	जइ (pkcs11_del_provider(canonical_provider) == 0)
		success = 1;
	अण्णहा
		error_f("pkcs11_del_provider failed");
send:
	मुक्त(provider);
	send_status(e, success);
}
#endif /* ENABLE_PKCS11 */

स्थिर पूर्णाङ्क
process_ext_session_bind(SocketEntry *e)
{
	पूर्णाङ्क r, sid_match, कुञ्चिका_match;
	संरचना sshkey *कुञ्चिका = रिक्त;
	संरचना sshbuf *sid = रिक्त, *sig = रिक्त;
	वर्ण *fp = रिक्त;
	size_t i;
	u_char fwd = 0;

	debug2_f("entering");
	e->session_bind_attempted = 1;
	जइ ((r = sshkey_froms(e->request, &कुञ्चिका)) != 0 ||
	    (r = sshbuf_froms(e->request, &sid)) != 0 ||
	    (r = sshbuf_froms(e->request, &sig)) != 0 ||
	    (r = sshbuf_get_u8(e->request, &fwd)) != 0) {
		error_fr(r, "parse");
		गच्छ out;
	}
	जइ (sshbuf_len(sid) > AGENT_MAX_SID_LEN) {
		error_f("session ID too long");
		गच्छ out;
	}
	जइ ((fp = sshkey_fingerprint(कुञ्चिका, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == रिक्त)
		fatal_f("fingerprint failed");
	/* check signature with hostkey on session ID */
	जइ ((r = sshkey_verify(कुञ्चिका, sshbuf_ptr(sig), sshbuf_len(sig),
	    sshbuf_ptr(sid), sshbuf_len(sid), रिक्त, 0, रिक्त)) != 0) {
		error_fr(r, "sshkey_verify for %s %s", sshkey_type(कुञ्चिका), fp);
		गच्छ out;
	}
	/* check whether sid/key already recorded */
	प्रति (i = 0; i < e->nsession_ids; i++) {
		जइ (!e->session_ids[i].forwarded) {
			error_f("attempt to bind session ID to socket "
			    "previously bound for authentication attempt");
			r = -1;
			गच्छ out;
		}
		sid_match = buf_equal(sid, e->session_ids[i].sid) == 0;
		कुञ्चिका_match = sshkey_equal(कुञ्चिका, e->session_ids[i].कुञ्चिका);
		जइ (sid_match && कुञ्चिका_match) {
			debug_f("session ID already recorded for %s %s",
			    sshkey_type(कुञ्चिका), fp);
			r = 0;
			गच्छ out;
		} अण्णहा जइ (sid_match) {
			error_f("session ID recorded against different key "
			    "for %s %s", sshkey_type(कुञ्चिका), fp);
			r = -1;
			गच्छ out;
		}
		/*
		 * new sid with previously-seen key can happen, e.g. multiple
		 * connections to the same host.
		 */
	}
	/* record new key/sid */
	जइ (e->nsession_ids >= AGENT_MAX_SESSION_IDS) {
		error_f("too many session IDs recorded");
		r = -1;
		गच्छ out;
	}
	e->session_ids = xrecallocarray(e->session_ids, e->nsession_ids,
	    e->nsession_ids + 1, परिमाण(*e->session_ids));
	i = e->nsession_ids++;
	debug_f("recorded %s %s (slot %zu of %d)", sshkey_type(कुञ्चिका), fp, i,
	    AGENT_MAX_SESSION_IDS);
	e->session_ids[i].कुञ्चिका = कुञ्चिका;
	e->session_ids[i].forwarded = fwd != 0;
	कुञ्चिका = रिक्त; /* transferred */
	/* can't transfer sid; it's refcounted and scoped to request's life */
	जइ ((e->session_ids[i].sid = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");
	जइ ((r = sshbuf_putb(e->session_ids[i].sid, sid)) != 0)
		fatal_fr(r, "sshbuf_putb session ID");
	/* success */
	r = 0;
 out:
	मुक्त(fp);
	sshkey_free(कुञ्चिका);
	sshbuf_free(sid);
	sshbuf_free(sig);
	प्रत्यागम r == 0 ? 1 : 0;
}

स्थिर पूर्णाङ्क
process_ext_query(SocketEntry *e)
{
	पूर्णाङ्क r;
	संरचना sshbuf *सन्देशः = रिक्त;

	debug2_f("entering");
	जइ ((सन्देशः = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	जइ ((r = sshbuf_put_u8(सन्देशः, SSH_AGENT_EXTENSION_RESPONSE)) != 0 ||
	    (r = sshbuf_put_cstring(सन्देशः, "query")) != 0 ||
	    /* string[]     supported extension types */
	    (r = sshbuf_put_cstring(सन्देशः, "session-bind@openssh.com")) != 0)
		fatal_fr(r, "compose");
	जइ ((r = sshbuf_put_stringb(e->output, सन्देशः)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(सन्देशः);
	प्रत्यागम 1;
}

स्थिर शून्य
process_extension(SocketEntry *e)
{
	पूर्णाङ्क r, replied = 0, success = 0;
	वर्ण *name;

	debug2_f("entering");
	जइ ((r = sshbuf_get_cstring(e->request, &name, रिक्त)) != 0) {
		error_fr(r, "parse");
		send_status(e, 0);
		प्रत्यागम;
	}

	/*
	 * This function can be called while the agent is locked to allow
	 * session binds to be processed for new channels.
	 * Other operations should be refused when locked.
	 */

	जइ (strcmp(name, "session-bind@openssh.com") == 0) {
		success = process_ext_session_bind(e);
	} अण्णहा जइ (locked) {
		debug_f("attempt to use extension \"%s\" while locked", name);
		गच्छ generic_fail;
	} अण्णहा जइ (strcmp(name, "query") == 0) {
		replied = success = process_ext_query(e);
	} अण्णहा {
		debug_f("unsupported extension \"%s\"", name);
 generic_fail:
		मुक्त(name);
		send_status(e, 0);
		प्रत्यागम;
	}
	मुक्त(name);
	/* Agent failures are signalled with a different error code */
	जइ (!replied) {
		send_status_generic(e,
		    success ? SSH_AGENT_SUCCESS : SSH_AGENT_EXTENSION_FAILURE);
	}
}

/*
 * dispatch incoming message.
 * returns 1 on success, 0 for incomplete messages or -1 on error.
 */
स्थिर पूर्णाङ्क
process_message(u_int socknum)
{
	u_int सन्देशः_len;
	u_char type;
	ध्रुव u_char *cp;
	पूर्णाङ्क r;
	SocketEntry *e;

	जइ (socknum >= sockets_alloc)
		fatal_f("sock %u >= allocated %u", socknum, sockets_alloc);
	e = &sockets[socknum];

	जइ (sshbuf_len(e->निवेशः) < 5)
		प्रत्यागम 0;		/* Incomplete message header. */
	cp = sshbuf_ptr(e->निवेशः);
	सन्देशः_len = PEEK_U32(cp);
	जइ (सन्देशः_len > AGENT_MAX_LEN) {
		debug_f("socket %u (fd=%d) message too long %u > %u",
		    socknum, e->fd, सन्देशः_len, AGENT_MAX_LEN);
		प्रत्यागम -1;
	}
	जइ (sshbuf_len(e->निवेशः) < सन्देशः_len + 4)
		प्रत्यागम 0;		/* Incomplete message body. */

	/* move the current input to e->request */
	sshbuf_reset(e->request);
	जइ ((r = sshbuf_get_stringb(e->निवेशः, e->request)) != 0 ||
	    (r = sshbuf_get_u8(e->request, &type)) != 0) {
		जइ (r == SSH_ERR_MESSAGE_INCOMPLETE ||
		    r == SSH_ERR_STRING_TOO_LARGE) {
			error_fr(r, "parse");
			प्रत्यागम -1;
		}
		fatal_fr(r, "parse");
	}

	debug_f("socket %u (fd=%d) type %d", socknum, e->fd, type);

	/* check whether agent is locked */
	जइ (locked && type != SSH_AGENTC_UNLOCK) {
		विकल्प (type) {
		पक्ष SSH2_AGENTC_REQUEST_IDENTITIES:
			/* send empty lists */
			no_identities(e);
			भङ्ग;
		पक्ष SSH_AGENTC_EXTENSION:
			process_extension(e);
			भङ्ग;
		स्वभाव:
			/* send a fail message for all other request types */
			send_status(e, 0);
		}
		sshbuf_reset(e->request);
		प्रत्यागम 1;
	}

	विकल्प (type) {
	पक्ष SSH_AGENTC_LOCK:
	पक्ष SSH_AGENTC_UNLOCK:
		process_lock_agent(e, type == SSH_AGENTC_LOCK);
		भङ्ग;
	पक्ष SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES:
		process_remove_all_identities(e); /* safe for !WITH_SSH1 */
		भङ्ग;
	/* ssh2 */
	पक्ष SSH2_AGENTC_SIGN_REQUEST:
		process_sign_request2(e);
		भङ्ग;
	पक्ष SSH2_AGENTC_REQUEST_IDENTITIES:
		process_request_identities(e);
		भङ्ग;
	पक्ष SSH2_AGENTC_ADD_IDENTITY:
	पक्ष SSH2_AGENTC_ADD_ID_CONSTRAINED:
		process_add_identity(e);
		भङ्ग;
	पक्ष SSH2_AGENTC_REMOVE_IDENTITY:
		process_remove_identity(e);
		भङ्ग;
	पक्ष SSH2_AGENTC_REMOVE_ALL_IDENTITIES:
		process_remove_all_identities(e);
		भङ्ग;
#ifdef ENABLE_PKCS11
	पक्ष SSH_AGENTC_ADD_SMARTCARD_कुञ्चिका:
	पक्ष SSH_AGENTC_ADD_SMARTCARD_कुञ्चिका_CONSTRAINED:
		process_add_smartcard_कुञ्चिका(e);
		भङ्ग;
	पक्ष SSH_AGENTC_REMOVE_SMARTCARD_कुञ्चिका:
		process_remove_smartcard_कुञ्चिका(e);
		भङ्ग;
#endif /* ENABLE_PKCS11 */
	पक्ष SSH_AGENTC_EXTENSION:
		process_extension(e);
		भङ्ग;
	स्वभाव:
		/* Unknown message.  Respond with failure. */
		error("Unknown message %d", type);
		sshbuf_reset(e->request);
		send_status(e, 0);
		भङ्ग;
	}
	प्रत्यागम 1;
}

स्थिर शून्य
new_socket(sock_type type, पूर्णाङ्क fd)
{
	u_int i, old_alloc, new_alloc;

	debug_f("type = %s", type == AUTH_CONNECTION ? "CONNECTION" :
	    (type == AUTH_SOCKET ? "SOCKET" : "UNKNOWN"));
	set_nonblock(fd);

	जइ (fd > max_fd)
		max_fd = fd;

	प्रति (i = 0; i < sockets_alloc; i++)
		जइ (sockets[i].type == AUTH_UNUSED) {
			sockets[i].fd = fd;
			जइ ((sockets[i].निवेशः = sshbuf_new()) == रिक्त ||
			    (sockets[i].output = sshbuf_new()) == रिक्त ||
			    (sockets[i].request = sshbuf_new()) == रिक्त)
				fatal_f("sshbuf_new failed");
			sockets[i].type = type;
			प्रत्यागम;
		}
	old_alloc = sockets_alloc;
	new_alloc = sockets_alloc + 10;
	sockets = xrecallocarray(sockets, old_alloc, new_alloc,
	    परिमाण(sockets[0]));
	प्रति (i = old_alloc; i < new_alloc; i++)
		sockets[i].type = AUTH_UNUSED;
	sockets_alloc = new_alloc;
	sockets[old_alloc].fd = fd;
	जइ ((sockets[old_alloc].निवेशः = sshbuf_new()) == रिक्त ||
	    (sockets[old_alloc].output = sshbuf_new()) == रिक्त ||
	    (sockets[old_alloc].request = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	sockets[old_alloc].type = type;
}

स्थिर पूर्णाङ्क
handle_socket_read(u_int socknum)
{
	संरचना sockaddr_un sunaddr;
	socklen_t slen;
	uid_t euid;
	gid_t egid;
	पूर्णाङ्क fd;

	slen = परिमाण(sunaddr);
	fd = accept(sockets[socknum].fd, (संरचना sockaddr *)&sunaddr, &slen);
	जइ (fd == -1) {
		error("accept from AUTH_SOCKET: %s", strerror(errno));
		प्रत्यागम -1;
	}
	जइ (getpeereid(fd, &euid, &egid) == -1) {
		error("getpeereid %d failed: %s", fd, strerror(errno));
		close(fd);
		प्रत्यागम -1;
	}
	जइ ((euid != 0) && (getuid() != euid)) {
		error("uid mismatch: peer euid %u != uid %u",
		    (u_int) euid, (u_int) getuid());
		close(fd);
		प्रत्यागम -1;
	}
	new_socket(AUTH_CONNECTION, fd);
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
handle_conn_read(u_int socknum)
{
	वर्ण buf[AGENT_RBUF_LEN];
	ssize_t len;
	पूर्णाङ्क r;

	जइ ((len = पठ(sockets[socknum].fd, buf, परिमाण(buf))) <= 0) {
		जइ (len == -1) {
			जइ (errno == EAGAIN || errno == EINTR)
				प्रत्यागम 0;
			error_f("read error on socket %u (fd %d): %s",
			    socknum, sockets[socknum].fd, strerror(errno));
		}
		प्रत्यागम -1;
	}
	जइ ((r = sshbuf_put(sockets[socknum].निवेशः, buf, len)) != 0)
		fatal_fr(r, "compose");
	explicit_bzero(buf, परिमाण(buf));
	प्रति (;;) {
		जइ ((r = process_message(socknum)) == -1)
			प्रत्यागम -1;
		अण्णहा जइ (r == 0)
			भङ्ग;
	}
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
handle_conn_write(u_int socknum)
{
	ssize_t len;
	पूर्णाङ्क r;

	जइ (sshbuf_len(sockets[socknum].output) == 0)
		प्रत्यागम 0; /* shouldn't happen */
	जइ ((len = लिख(sockets[socknum].fd,
	    sshbuf_ptr(sockets[socknum].output),
	    sshbuf_len(sockets[socknum].output))) <= 0) {
		जइ (len == -1) {
			जइ (errno == EAGAIN || errno == EINTR)
				प्रत्यागम 0;
			error_f("read error on socket %u (fd %d): %s",
			    socknum, sockets[socknum].fd, strerror(errno));
		}
		प्रत्यागम -1;
	}
	जइ ((r = sshbuf_consume(sockets[socknum].output, len)) != 0)
		fatal_fr(r, "consume");
	प्रत्यागम 0;
}

स्थिर शून्य
after_poll(संरचना pollfd *pfd, size_t npfd, u_int maxfds)
{
	size_t i;
	u_int socknum, activefds = npfd;

	प्रति (i = 0; i < npfd; i++) {
		जइ (pfd[i].revents == 0)
			अनुवर्त;
		/* Find sockets entry */
		प्रति (socknum = 0; socknum < sockets_alloc; socknum++) {
			जइ (sockets[socknum].type != AUTH_SOCKET &&
			    sockets[socknum].type != AUTH_CONNECTION)
				अनुवर्त;
			जइ (pfd[i].fd == sockets[socknum].fd)
				भङ्ग;
		}
		जइ (socknum >= sockets_alloc) {
			error_f("no socket for fd %d", pfd[i].fd);
			अनुवर्त;
		}
		/* Process events */
		विकल्प (sockets[socknum].type) {
		पक्ष AUTH_SOCKET:
			जइ ((pfd[i].revents & (POLLIN|POLLERR)) == 0)
				भङ्ग;
			जइ (npfd > maxfds) {
				debug3("out of fds (active %u >= limit %u); "
				    "skipping accept", activefds, maxfds);
				भङ्ग;
			}
			जइ (handle_socket_read(socknum) == 0)
				activefds++;
			भङ्ग;
		पक्ष AUTH_CONNECTION:
			जइ ((pfd[i].revents & (POLLIN|POLLHUP|POLLERR)) != 0 &&
			    handle_conn_read(socknum) != 0)
				गच्छ close_sock;
			जइ ((pfd[i].revents & (POLLOUT|POLLHUP)) != 0 &&
			    handle_conn_write(socknum) != 0) {
 close_sock:
				जइ (activefds == 0)
					fatal("activefds == 0 at close_sock");
				close_socket(&sockets[socknum]);
				activefds--;
				भङ्ग;
			}
			भङ्ग;
		स्वभाव:
			भङ्ग;
		}
	}
}

स्थिर पूर्णाङ्क
prepare_poll(संरचना pollfd **pfdp, size_t *npfdp, संरचना timespec *timeoutp, u_int maxfds)
{
	संरचना pollfd *pfd = *pfdp;
	size_t i, j, npfd = 0;
	time_t deadline;
	पूर्णाङ्क r;

	/* Count active sockets */
	प्रति (i = 0; i < sockets_alloc; i++) {
		विकल्प (sockets[i].type) {
		पक्ष AUTH_SOCKET:
		पक्ष AUTH_CONNECTION:
			npfd++;
			भङ्ग;
		पक्ष AUTH_UNUSED:
			भङ्ग;
		स्वभाव:
			fatal("Unknown socket type %d", sockets[i].type);
			भङ्ग;
		}
	}
	जइ (npfd != *npfdp &&
	    (pfd = recallocarray(pfd, *npfdp, npfd, परिमाण(*pfd))) == रिक्त)
		fatal_f("recallocarray failed");
	*pfdp = pfd;
	*npfdp = npfd;

	प्रति (i = j = 0; i < sockets_alloc; i++) {
		विकल्प (sockets[i].type) {
		पक्ष AUTH_SOCKET:
			जइ (npfd > maxfds) {
				debug3("out of fds (active %zu >= limit %u); "
				    "skipping arming listener", npfd, maxfds);
				भङ्ग;
			}
			pfd[j].fd = sockets[i].fd;
			pfd[j].revents = 0;
			pfd[j].events = POLLIN;
			j++;
			भङ्ग;
		पक्ष AUTH_CONNECTION:
			pfd[j].fd = sockets[i].fd;
			pfd[j].revents = 0;
			/*
			 * Only prepare to read if we can handle a full-size
			 * input read buffer and enqueue a max size reply..
			 */
			जइ ((r = sshbuf_check_reserve(sockets[i].निवेशः,
			    AGENT_RBUF_LEN)) == 0 &&
			    (r = sshbuf_check_reserve(sockets[i].output,
			    AGENT_MAX_LEN)) == 0)
				pfd[j].events = POLLIN;
			अण्णहा जइ (r != SSH_ERR_NO_BUFFER_SPACE)
				fatal_fr(r, "reserve");
			जइ (sshbuf_len(sockets[i].output) > 0)
				pfd[j].events |= POLLOUT;
			j++;
			भङ्ग;
		स्वभाव:
			भङ्ग;
		}
	}
	deadline = reaper();
	जइ (parent_alive_interval != 0)
		deadline = (deadline == 0) ? parent_alive_interval :
		    MINIMUM(deadline, parent_alive_interval);
	जइ (deadline != 0)
		ptimeout_deadline_sec(timeoutp, deadline);
	प्रत्यागम (1);
}

स्थिर शून्य
cleanup_socket(शून्य)
{
	जइ (cleanup_pid != 0 && getpid() != cleanup_pid)
		प्रत्यागम;
	debug_f("cleanup");
	जइ (socket_name != रिक्त) {
		agent_listener_cleanup(socket_dirspec, socket_name, socket_dir);
		मुक्त(socket_name);
		socket_name = रिक्त;
		मुक्त(socket_dir);
		socket_dir = रिक्त;
	}
}

शून्य
cleanup_exit(पूर्णाङ्क i)
{
	cleanup_socket();
#ifdef ENABLE_PKCS11
	pkcs11_terminate();
#endif
	_exit(i);
}

स्थिर शून्य
cleanup_handler(पूर्णाङ्क sig)
{
	signalled_exit = sig;
}

स्थिर शून्य
keydrop_handler(पूर्णाङ्क sig)
{
	signalled_keydrop = sig;
}

स्थिर शून्य
check_parent_exists(शून्य)
{
	/*
	 * If our parent has exited then getppid() will return (pid_t)1,
	 * so testing for that should be safe.
	 */
	जइ (parent_pid != -1 && getppid() != parent_pid) {
		/* printf("Parent has died - Authentication agent exiting.\n"); */
		cleanup_socket();
		_exit(2);
	}
}

स्थिर शून्य
usage(शून्य)
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

पूर्णाङ्क
main(पूर्णाङ्क ac, वर्ण **av)
{
	पूर्णाङ्क c_flag = 0, d_flag = 0, D_flag = 0, k_flag = 0;
	पूर्णाङ्क s_flag = 0, T_flag = 0, u_flag = 0, U_flag = 0;
	पूर्णाङ्क sock = -1, ch, result, saved_errno;
	pid_t pid;
 	वर्ण *homedir = रिक्त, *shell, *format, *pidstr, *agentsocket = रिक्त;
	वर्ण *cp, pidstrbuf[1 + 3 * परिमाण pid];
	वर्ण *fdstr;
	ध्रुव वर्ण *errstr = रिक्त;
	ध्रुव वर्ण *ccp;
#ifdef HAVE_SETRLIMIT
	संरचना rlimit rlim;
#endif
	बाह्य पूर्णाङ्क optind;
	बाह्य वर्ण *optarg;
	size_t len;
	mode_t prev_mask;
	संरचना timespec timeout;
	संरचना pollfd *pfd = रिक्त;
	size_t npfd = 0;
	u_int maxfds;
	sigset_t nsigset, osigset;
	पूर्णाङ्क socket_activated = 0;
	संरचना passwd *pw;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* drop */
	(शून्य)setegid(getgid());
	(शून्य)setgid(getgid());

	platform_disable_tracing(0);	/* strict=no */

	जइ ((pw = getpwuid(getuid())) == रिक्त)
		fatal("No user exists for uid %lu", (u_long)getuid());
	pw = pwcopy(pw);

#ifdef RLIMIT_NOFILE
	जइ (getrlimit(RLIMIT_NOFILE, &rlim) == -1)
		fatal("%s: getrlimit: %s", __progname, strerror(errno));
#endif

	__progname = ssh_get_progname(av[0]);
	seed_rng();

	जाव ((ch = getopt(ac, av, "cDdksTuUVA:E:a:O:P:t:")) != -1) {
		विकल्प (ch) {
		पक्ष 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			जइ (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			भङ्ग;
		पक्ष 'c':
			जइ (s_flag)
				usage();
			c_flag++;
			भङ्ग;
		पक्ष 'k':
			k_flag++;
			भङ्ग;
		पक्ष 'O':
			जइ (strcmp(optarg, "no-restrict-websafe") == 0)
				restrict_websafe = 0;
			अण्णहा जइ (strcmp(optarg, "allow-remote-pkcs11") == 0)
				remote_add_provider = 1;
			अण्णहा जइ ((ccp = strprefix(optarg,
			    "websafe-allow=", 0)) != रिक्त) {
				जइ (websafe_allowlist != रिक्त)
					fatal("websafe-allow already set");
				websafe_allowlist = xstrdup(ccp);
			} अण्णहा
				fatal("Unknown -O option");
			भङ्ग;
		पक्ष 'P':
			जइ (allowed_providers != रिक्त)
				fatal("-P option already specified");
			allowed_providers = xstrdup(optarg);
			भङ्ग;
		पक्ष 's':
			जइ (c_flag)
				usage();
			s_flag++;
			भङ्ग;
		पक्ष 'd':
			जइ (d_flag || D_flag)
				usage();
			d_flag++;
			भङ्ग;
		पक्ष 'D':
			जइ (d_flag || D_flag)
				usage();
			D_flag++;
			भङ्ग;
		पक्ष 'a':
			agentsocket = optarg;
			भङ्ग;
		पक्ष 'A':
			socket_dirspec = xstrdup(optarg);
			भङ्ग;
		पक्ष 't':
			जइ ((lifetime = convtime(optarg)) == -1) {
				fprintf(stderr, "Invalid lifetime\n");
				usage();
			}
			भङ्ग;
		पक्ष 'T':
			T_flag++;
			भङ्ग;
		पक्ष 'u':
			u_flag++;
			भङ्ग;
		पक्ष 'U':
			U_flag++;
			भङ्ग;
		पक्ष 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_VERSION, SSH_OPENSSL_VERSION);
			exit(0);
		स्वभाव:
			usage();
		}
	}
	ac -= optind;
	av += optind;

	जइ (ac > 0 &&
	    (c_flag || k_flag || s_flag || d_flag || D_flag || u_flag))
		usage();
	/* only one of -a, -A and -T allowed */
	जइ (((socket_dirspec != रिक्त) + (agentsocket != रिक्त) + T_flag) > 1)
		usage();

	log_init(__progname,
	    d_flag ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
	    SYSLOG_FACILITY_AUTH, 1);

	जइ (allowed_providers == रिक्त)
		allowed_providers = xstrdup(DEFAULT_ALLOWED_PROVIDERS);
	जइ (websafe_allowlist == रिक्त)
		websafe_allowlist = xstrdup(DEFAULT_WEBSAFE_ALLOWLIST);

	जइ (T_flag)
		socket_dirspec = xstrdup(_PATH_SSH_AGENT_SOCKET_TMPDIR);
	अण्णहा जइ (socket_dirspec == रिक्त && agentsocket == रिक्त)
		socket_dirspec = xstrdup(_PATH_SSH_AGENT_SOCKET_DIR);

	जइ (ac == 0 && !c_flag && !s_flag) {
		shell = getenv("SHELL");
		जइ (shell != रिक्त && (len = strlen(shell)) > 2 &&
		    strncmp(shell + len - 3, "csh", 3) == 0)
			c_flag = 1;
	}
	जइ (k_flag) {
		pidstr = getenv(SSH_AGENTPID_ENV_NAME);
		जइ (pidstr == रिक्त) {
			fprintf(stderr, "%s not set, cannot kill agent\n",
			    SSH_AGENTPID_ENV_NAME);
			exit(1);
		}
		pid = (पूर्णाङ्क)strtonum(pidstr, 2, INT_MAX, &errstr);
		जइ (errstr) {
			fprintf(stderr,
			    "%s=\"%s\", which is not a good PID: %s\n",
			    SSH_AGENTPID_ENV_NAME, pidstr, errstr);
			exit(1);
		}
		जइ (kill(pid, SIGTERM) == -1) {
			perror("kill");
			exit(1);
		}
		format = c_flag ? "unsetenv %s;\n" : "unset %s;\n";
		printf(format, SSH_AUTHSOCKET_ENV_NAME);
		printf(format, SSH_AGENTPID_ENV_NAME);
		printf("echo Agent pid %ld killed;\n", (long)pid);
		exit(0);
	}
	जइ (u_flag) {
		जइ ((homedir = get_homedir()) == रिक्त)
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
	जइ (rlim.rlim_cur < SSH_AGENT_MIN_FDS)
		fatal("%s: file descriptor rlimit %lld too low (minimum %u)",
		    __progname, (long long)rlim.rlim_cur, SSH_AGENT_MIN_FDS);
	maxfds = rlim.rlim_cur - SSH_AGENT_MIN_FDS;

	parent_pid = getpid();

	/* Has the socket been provided via socket activation? */
	जइ (agentsocket == रिक्त && ac == 0 && (d_flag || D_flag) &&
	    (pidstr = getenv("LISTEN_PID")) != रिक्त &&
	    (fdstr = getenv("LISTEN_FDS")) != रिक्त) {
		जइ (strcmp(fdstr, "1") != 0) {
			fatal("unexpected LISTEN_FDS contents "
			    "(want: \"1\" got\"%s\"", fdstr);
		}
		जइ (fcntl(3, F_GETFL) == -1)
			fatal("LISTEN_FDS set but fd 3 unavailable");
		pid = (पूर्णाङ्क)strtonum(pidstr, 1, INT_MAX, &errstr);
		जइ (errstr != रिक्त)
			fatal("invalid LISTEN_PID: %s", errstr);
		जइ (pid != getpid())
			fatal("bad LISTEN_PID: %d vs pid %d", pid, getpid());
		debug("using socket activation on fd=3");
		sock = 3;
		socket_activated = 1;
	}

	जइ (sock == -1 && agentsocket == रिक्त) {
		/* Listen on a socket in/under a given directory */
		जइ ((homedir = get_homedir()) == रिक्त)
			fatal("Couldn't determine home directory");
		जइ (!U_flag) {
			agent_cleanup_stale(socket_dirspec,
			    pw->pw_name, pw->pw_uid, homedir, 0);
		}
		जइ (agent_listener(socket_dirspec, pw->pw_name, pw->pw_uid,
		    homedir, getpid(), "local", &sock, &socket_name,
		    &socket_dir) != 0)
			fatal_f("Couldn't prepare agent socket");
		मुक्त(homedir);
	} अण्णहा जइ (sock == -1) {
		/* Listen on explicit socket path */
		prev_mask = umask(0177);
		socket_name = xstrdup(agentsocket);
		जइ ((sock = unix_listener(socket_name,
		    SSH_LISTEN_BACKLOG, 0)) < 0) {
			मुक्त(socket_name);
			socket_name = रिक्त; /* Don't unlink existing file */
			cleanup_exit(1);
		}
		umask(prev_mask);
	}

	closefrom(sock == -1 ? STDERR_FILENO + 1 : sock + 1);

	/*
	 * Create socket early so it will exist before command gets run from
	 * the parent.
	 */
	जइ (sock == -1) {
		prev_mask = umask(0177);
		sock = unix_listener(socket_name, SSH_LISTEN_BACKLOG, 0);
		जइ (sock < 0) {
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
	जइ (D_flag || d_flag) {
		log_init(__progname,
		    d_flag ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
		    SYSLOG_FACILITY_AUTH, 1);
		जइ (socket_name != रिक्त) {
			cp = argv_assemble(1, &socket_name);
			format = c_flag ?
			    "setenv %s %s;\n" : "%s=%s; export %s;\n";
			printf(format, SSH_AUTHSOCKET_ENV_NAME, cp,
			    SSH_AUTHSOCKET_ENV_NAME);
			मुक्त(cp);
			printf("echo Agent pid %ld;\n", (long)parent_pid);
			fflush(stdout);
		}
		गच्छ skip;
	}
	pid = fork();
	जइ (pid == -1) {
		perror("fork");
		cleanup_exit(1);
	}
	जइ (pid != 0) {		/* Parent - execute the given command. */
		close(sock);
		snprintf(pidstrbuf, परिमाण pidstrbuf, "%ld", (long)pid);
		जइ (ac == 0) {
			format = c_flag ? "setenv %s %s;\n" : "%s=%s; export %s;\n";
			cp = argv_assemble(1, &socket_name);
			printf(format, SSH_AUTHSOCKET_ENV_NAME, cp,
			    SSH_AUTHSOCKET_ENV_NAME);
			printf(format, SSH_AGENTPID_ENV_NAME, pidstrbuf,
			    SSH_AGENTPID_ENV_NAME);
			मुक्त(cp);
			printf("echo Agent pid %ld;\n", (long)pid);
			exit(0);
		}
		जइ (setenv(SSH_AUTHSOCKET_ENV_NAME, socket_name, 1) == -1 ||
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

	जइ (setsid() == -1) {
		error("setsid: %s", strerror(errno));
		cleanup_exit(1);
	}

	(शून्य)chdir("/");
	जइ (stdfd_devnull(1, 1, 1) == -1)
		error_f("stdfd_devnull failed");

#ifdef HAVE_SETRLIMIT
	/* deny core dumps, since memory contains unencrypted private keys */
	rlim.rlim_cur = rlim.rlim_max = 0;
	जइ (setrlimit(RLIMIT_CORE, &rlim) == -1) {
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
	जइ (ac > 0)
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

	जइ (socket_name != रिक्त && unveil(socket_name, "c") == -1) {
		fatal("%s: unveil %s %s", __progname, socket_name,
		    strerror(errno));
	}
	जइ (socket_dir != रिक्त && unveil(socket_dir, "c") == -1) {
		fatal("%s: unveil %s %s", __progname, socket_dir,
		    strerror(errno));
	}
	जइ (unveil("/", "r") == -1)
		fatal("%s: unveil /: %s", __progname, strerror(errno));
	जइ ((ccp = getenv("SSH_SK_HELPER")) == रिक्त || *ccp == '\0')
		ccp = _PATH_SSH_SK_HELPER;
	जइ (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, strerror(errno));
	जइ ((ccp = getenv("SSH_PKCS11_HELPER")) == रिक्त || *ccp == '\0')
		ccp = _PATH_SSH_PKCS11_HELPER;
	जइ (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, strerror(errno));
	जइ ((ccp = getenv("SSH_ASKPASS")) == रिक्त || *ccp == '\0')
		ccp = _PATH_SSH_ASKPASS_DEFAULT;
	जइ (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, strerror(errno));
	जइ (unveil("/dev/null", "rw") == -1)
		fatal("%s: unveil /dev/null: %s", __progname, strerror(errno));
	जइ (pledge("stdio rpath cpath wpath unix id proc exec", रिक्त) == -1)
		fatal("%s: pledge: %s", __progname, strerror(errno));
	platform_pledge_agent();

	जाव (1) {
		sigprocmask(SIG_BLOCK, &nsigset, &osigset);
		जइ (signalled_exit != 0) {
			logit("exiting on signal %d", (पूर्णाङ्क)signalled_exit);
			cleanup_exit((signalled_exit == SIGTERM &&
			    socket_activated) ? 0 : 2);
		}
		जइ (signalled_keydrop) {
			logit("signal %d received; removing all keys",
			    (पूर्णाङ्क)signalled_keydrop);
			remove_all_identities();
			signalled_keydrop = 0;
		}
		ptimeout_init(&timeout);
		prepare_poll(&pfd, &npfd, &timeout, maxfds);
		result = ppoll(pfd, npfd, ptimeout_get_tsp(&timeout), &osigset);
		sigprocmask(SIG_SETMASK, &osigset, रिक्त);
		saved_errno = errno;
		जइ (parent_alive_interval != 0)
			check_parent_exists();
		(शून्य) reaper();	/* remove expired keys */
		जइ (result == -1) {
			जइ (saved_errno == EINTR)
				अनुवर्त;
			fatal("poll: %s", strerror(saved_errno));
		} अण्णहा जइ (result > 0)
			after_poll(pfd, npfd, maxfds);
	}
	/* NOTREACHED */
}
