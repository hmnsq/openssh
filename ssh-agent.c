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

#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
#ضمن <openssl/evp.h>
#ضمن "openbsd-compat/openssl-compat.h"
#جيڪڏهن_پورو

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

#جيڪڏهن_وصف_نه_ٿيل DEFAULT_ALLOWED_PROVIDERS
# define DEFAULT_ALLOWED_PROVIDERS "/usr/lib*/*,/usr/local/lib*/*"
#جيڪڏهن_پورو
#جيڪڏهن_وصف_نه_ٿيل DEFAULT_WEBSAFE_ALLOWLIST
# define DEFAULT_WEBSAFE_ALLOWLIST "ssh:*"
#جيڪڏهن_پورو

/* Maximum accepted message length */
#وصف_ڪريو AGENT_MAX_LEN		(256*1024)
/* Maximum bytes to read from client socket */
#وصف_ڪريو AGENT_RBUF_LEN		(4096)
/* Maximum number of recorded session IDs/hostkeys per connection */
#وصف_ڪريو AGENT_MAX_SESSION_IDS		16
/* Maximum size of session ID */
#وصف_ڪريو AGENT_MAX_SID_LEN		128
/* Maximum number of destination constraints to accept on a key */
#وصف_ڪريو AGENT_MAX_DEST_CONSTRAINTS	1024
/* Maximum number of associated certificate constraints to accept on a key */
#وصف_ڪريو AGENT_MAX_EXT_CERTS		1024
/* Max length of username constraint */
#وصف_ڪريو AGENT_USER_CONSTRAINT_MAX_LEN	256

/* XXX store hostkey_sid in a refcounted tree */

تعريفنوع تعداد {
	AUTH_اڻ_استعمال_ٿيل = 0,
	AUTH_SOCKET = 1,
	AUTH_CONNECTION = 2,
} sock_type;

بنية hostkey_sid {
	بنية sshkey *ڪنجي;
	بنية sshbuf *sid;
	صحيح forwarded;
};

تعريفنوع بنية socket_داخلا {
	صحيح fd;
	sock_type type;
	بنية sshbuf *داخلا_2;
	بنية sshbuf *output;
	بنية sshbuf *request;
	سائيز_t nsession_ids;
	بنية hostkey_sid *session_ids;
	صحيح session_bind_attempted;
} Socket_داخلا;

u_int sockets_alloc = 0;
Socket_داخلا *sockets = عدم;

تعريفنوع بنية سڃاڻپ_عنصر_2 {
	TAILQ_ENTRY(سڃاڻپ_عنصر_2) ايندڙ;
	بنية sshkey *ڪنجي;
	حرف *comment;
	حرف *provider;
	time_t death;
	u_int confirm;
	حرف *sk_provider;
	بنية dest_constraint *dest_constraints;
	سائيز_t ndest_constraints;
} سڃاڻپ_عنصر;

بنية idtable {
	صحيح nentries;
	TAILQ_HEAD(idqueue, سڃاڻپ_عنصر_2) idlist;
};

/* private key table */
بنية idtable *idtab;

صحيح max_fd = 0;

/* pid of shell == parent of agent */
pid_t والد_pid = -1;
time_t والد_alive_interval = 0;

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
ساكن صحيح remote_جوڙيو_provider;

/* locking */
#وصف_ڪريو تالو_سائيز	32
#وصف_ڪريو تالو_SALT_سائيز	16
#وصف_ڪريو تالو_ڦيرا	1
صحيح locked = 0;
u_char تالو_pwhash[تالو_سائيز];
u_char تالو_salt[تالو_SALT_سائيز];

خارجي حرف *__progname;

/* Default lifetime in seconds (0 == forever) */
ساكن صحيح lifetime = 0;

ساكن صحيح fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* Refuse signing of non-SSH messages for web-origin FIDO keys */
ساكن صحيح restrict_websafe = 1;
ساكن حرف *websafe_allowlist;

ساكن فراغ
close_socket(Socket_داخلا *e)
{
	سائيز_t i;

	close(e->fd);
	sshbuf_free(e->داخلا_2);
	sshbuf_free(e->output);
	sshbuf_free(e->request);
	لكل (i = 0; i < e->nsession_ids; i++) {
		sshkey_free(e->session_ids[i].ڪنجي);
		sshbuf_free(e->session_ids[i].sid);
	}
	حرر(e->session_ids);
	memset(e, '\0', حجم(*e));
	e->fd = -1;
	e->type = AUTH_اڻ_استعمال_ٿيل;
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

	إذا (dch == عدم)
		أرجع;
	حرر(dch->user);
	حرر(dch->hostname);
	لكل (i = 0; i < dch->nkeys; i++)
		sshkey_free(dch->ڪنجيون[i]);
	حرر(dch->ڪنجيون);
	حرر(dch->ڪنجي_is_ca);
}

ساكن فراغ
free_dest_constraints(بنية dest_constraint *dcs, سائيز_t ndcs)
{
	سائيز_t i;

	لكل (i = 0; i < ndcs; i++) {
		free_dest_constraint_hop(&dcs[i].from);
		free_dest_constraint_hop(&dcs[i].منزل);
	}
	حرر(dcs);
}

#جيڪڏهن_وصف_ٿيل ENABLE_PKCS11
ساكن فراغ
dup_dest_constraint_hop(ثابت بنية dest_constraint_hop *dch,
    بنية dest_constraint_hop *ٻاهريون)
{
	u_int i;
	صحيح r;

	ٻاهريون->user = dch->user == عدم ? عدم : xstrdup(dch->user);
	ٻاهريون->hostname = dch->hostname == عدم ? عدم : xstrdup(dch->hostname);
	ٻاهريون->is_ca = dch->is_ca;
	ٻاهريون->nkeys = dch->nkeys;
	ٻاهريون->ڪنجيون = ٻاهريون->nkeys == 0 ? عدم :
	    xcalloc(ٻاهريون->nkeys, حجم(*ٻاهريون->ڪنجيون));
	ٻاهريون->ڪنجي_is_ca = ٻاهريون->nkeys == 0 ? عدم :
	    xcalloc(ٻاهريون->nkeys, حجم(*ٻاهريون->ڪنجي_is_ca));
	لكل (i = 0; i < dch->nkeys; i++) {
		إذا (dch->ڪنجيون[i] != عدم &&
		    (r = sshkey_from_ذاتي(dch->ڪنجيون[i],
		    &(ٻاهريون->ڪنجيون[i]))) != 0)
			fatal_fr(r, "copy key");
		ٻاهريون->ڪنجي_is_ca[i] = dch->ڪنجي_is_ca[i];
	}
}

ساكن بنية dest_constraint *
dup_dest_constraints(ثابت بنية dest_constraint *dcs, سائيز_t ndcs)
{
	سائيز_t i;
	بنية dest_constraint *ret;

	إذا (ndcs == 0)
		أرجع عدم;
	ret = xcalloc(ndcs, حجم(*ret));
	لكل (i = 0; i < ndcs; i++) {
		dup_dest_constraint_hop(&dcs[i].from, &ret[i].from);
		dup_dest_constraint_hop(&dcs[i].منزل, &ret[i].منزل);
	}
	أرجع ret;
}
#جيڪڏهن_پورو /* ENABLE_PKCS11 */

#جيڪڏهن_وصف_ٿيل DEBUG_CONSTRAINTS
ساكن فراغ
dump_dest_constraint_hop(ثابت بنية dest_constraint_hop *dch)
{
	u_int i;
	حرف *fp;

	debug_f("user %s hostname %s is_ca %d nkeys %u",
	    dch->user == عدم ? "(null)" : dch->user,
	    dch->hostname == عدم ? "(null)" : dch->hostname,
	    dch->is_ca, dch->nkeys);
	لكل (i = 0; i < dch->nkeys; i++) {
		fp = عدم;
		إذا (dch->ڪنجيون[i] != عدم &&
		    (fp = sshkey_fingerprint(dch->ڪنجيون[i],
		    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == عدم)
			fatal_f("fingerprint failed");
		debug_f("key %u/%u: %s%s%s key_is_ca %d", i, dch->nkeys,
		    dch->ڪنجيون[i] == عدم ? "" : sshkey_ssh_name(dch->ڪنجيون[i]),
		    dch->ڪنجيون[i] == عدم ? "" : " ",
		    dch->ڪنجيون[i] == عدم ? "none" : fp,
		    dch->ڪنجي_is_ca[i]);
		حرر(fp);
	}
}
#جيڪڏهن_پورو /* DEBUG_CONSTRAINTS */

ساكن فراغ
dump_dest_constraints(ثابت حرف *context,
    ثابت بنية dest_constraint *dcs, سائيز_t ndcs)
{
#جيڪڏهن_وصف_ٿيل DEBUG_CONSTRAINTS
	سائيز_t i;

	debug_f("%s: %zu constraints", context, ndcs);
	لكل (i = 0; i < ndcs; i++) {
		debug_f("constraint %zu / %zu: from: ", i, ndcs);
		dump_dest_constraint_hop(&dcs[i].from);
		debug_f("constraint %zu / %zu: to: ", i, ndcs);
		dump_dest_constraint_hop(&dcs[i].منزل);
	}
	debug_f("done for %s", context);
#جيڪڏهن_پورو /* DEBUG_CONSTRAINTS */
}

ساكن فراغ
free_سڃاڻپ_عنصر(سڃاڻپ_عنصر *id)
{
	sshkey_free(id->ڪنجي);
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
ميلاپ_ڪنجي_hop(ثابت حرف *ٽيگ, ثابت بنية sshkey *ڪنجي,
    ثابت بنية dest_constraint_hop *dch)
{
	ثابت حرف *reason = عدم;
	ثابت حرف *hostname = dch->hostname ? dch->hostname : "(ORIGIN)";
	u_int i;
	حرف *fp;

	إذا (ڪنجي == عدم)
		أرجع -1;
	/* XXX logspam */
	إذا ((fp = sshkey_fingerprint(ڪنجي, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == عدم)
		fatal_f("fingerprint failed");
	debug3_f("%s: entering hostname %s, requested key %s %s, %u keys avail",
	    ٽيگ, hostname, sshkey_type(ڪنجي), fp, dch->nkeys);
	حرر(fp);
	لكل (i = 0; i < dch->nkeys; i++) {
		إذا (dch->ڪنجيون[i] == عدم)
			أرجع -1;
		/* XXX logspam */
		إذا ((fp = sshkey_fingerprint(dch->ڪنجيون[i], SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == عدم)
			fatal_f("fingerprint failed");
		debug3_f("%s: key %u: %s%s %s", ٽيگ, i,
		    dch->ڪنجي_is_ca[i] ? "CA " : "",
		    sshkey_type(dch->ڪنجيون[i]), fp);
		حرر(fp);
		إذا (!sshkey_is_cert(ڪنجي)) {
			/* plain key */
			إذا (dch->ڪنجي_is_ca[i] ||
			    !sshkey_equal(ڪنجي, dch->ڪنجيون[i]))
				استمر;
			أرجع 0;
		}
		/* certificate */
		إذا (!dch->ڪنجي_is_ca[i])
			استمر;
		إذا (ڪنجي->cert == عدم || ڪنجي->cert->signature_ڪنجي == عدم)
			أرجع -1; /* shouldn't happen */
		إذا (!sshkey_equal(ڪنجي->cert->signature_ڪنجي, dch->ڪنجيون[i]))
			استمر;
		إذا (sshkey_cert_check_host(ڪنجي, hostname,
		    SSH_ALLOWED_CA_SIGALGS, &reason) != 0) {
			debug_f("cert %s / hostname %s rejected: %s",
			    ڪنجي->cert->ڪنجي_id, hostname, reason);
			استمر;
		}
		أرجع 0;
	}
	أرجع -1;
}

/* Check destination constraints on an identity against the hostkey/user */
ساكن صحيح
permitted_by_dest_constraints(ثابت بنية sshkey *fromkey,
    ثابت بنية sshkey *tokey, سڃاڻپ_عنصر *id, ثابت حرف *user,
    ثابت حرف **hostnamep)
{
	سائيز_t i;
	بنية dest_constraint *d;

	إذا (hostnamep != عدم)
		*hostnamep = عدم;
	لكل (i = 0; i < id->ndest_constraints; i++) {
		d = id->dest_constraints + i;
		/* XXX remove logspam */
		debug2_f("constraint %zu %s%s%s (%u keys) > %s%s%s (%u keys)",
		    i, d->from.user ? d->from.user : "",
		    d->from.user ? "@" : "",
		    d->from.hostname ? d->from.hostname : "(ORIGIN)",
		    d->from.nkeys,
		    d->منزل.user ? d->منزل.user : "", d->منزل.user ? "@" : "",
		    d->منزل.hostname ? d->منزل.hostname : "(ANY)", d->منزل.nkeys);

		/* Match 'from' key */
		إذا (fromkey == عدم) {
			/* We are matching the first hop */
			إذا (d->from.hostname != عدم || d->from.nkeys != 0)
				استمر;
		} وإلا إذا (ميلاپ_ڪنجي_hop("from", fromkey, &d->from) != 0)
			استمر;

		/* Match 'to' key */
		إذا (tokey != عدم && ميلاپ_ڪنجي_hop("to", tokey, &d->منزل) != 0)
			استمر;

		/* Match user if specified */
		إذا (d->منزل.user != عدم && user != عدم &&
		    !ميلاپ_نمونو(user, d->منزل.user))
			استمر;

		/* successfully matched this constraint */
		إذا (hostnamep != عدم)
			*hostnamep = d->منزل.hostname;
		debug2_f("allowed for hostname %s",
		    d->منزل.hostname == عدم ? "*" : d->منزل.hostname);
		أرجع 0;
	}
	/* no match */
	debug2_f("%s identity \"%s\" not permitted for this destination",
	    sshkey_type(id->ڪنجي), id->comment);
	أرجع -1;
}

/*
 * Check whether hostkeys on a SocketEntry and the optionally specified user
 * are permitted by the destination constraints on the Identity.
 * Returns 0 on success or -1 otherwise.
 */
ساكن صحيح
سڃاڻپ_عنصر_permitted(سڃاڻپ_عنصر *id, Socket_داخلا *e, حرف *user,
    ثابت حرف **forward_hostnamep, ثابت حرف **آخري_hostnamep)
{
	سائيز_t i;
	ثابت حرف **hp;
	بنية hostkey_sid *hks;
	ثابت بنية sshkey *fromkey = عدم;
	ثابت حرف *test_user;
	حرف *fp1, *fp2;

	/* XXX remove logspam */
	debug3_f("entering: key %s comment \"%s\", %zu socket bindings, "
	    "%zu constraints", sshkey_type(id->ڪنجي), id->comment,
	    e->nsession_ids, id->ndest_constraints);
	إذا (id->ndest_constraints == 0)
		أرجع 0; /* unconstrained */
	إذا (e->session_bind_attempted && e->nsession_ids == 0) {
		error_f("previous session bind failed on socket");
		أرجع -1;
	}
	إذا (e->nsession_ids == 0)
		أرجع 0; /* local use */
	/*
	 * Walk through the hops recorded by session_id and try to find a
	 * constraint that satisfies each.
	 */
	لكل (i = 0; i < e->nsession_ids; i++) {
		hks = e->session_ids + i;
		إذا (hks->ڪنجي == عدم)
			fatal_f("internal error: no bound key");
		/* XXX remove logspam */
		fp1 = fp2 = عدم;
		إذا (fromkey != عدم &&
		    (fp1 = sshkey_fingerprint(fromkey, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == عدم)
			fatal_f("fingerprint failed");
		إذا ((fp2 = sshkey_fingerprint(hks->ڪنجي, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == عدم)
			fatal_f("fingerprint failed");
		debug3_f("socketentry fd=%d, entry %zu %s, "
		    "from hostkey %s %s to user %s hostkey %s %s",
		    e->fd, i, hks->forwarded ? "FORWARD" : "AUTH",
		    fromkey ? sshkey_type(fromkey) : "(ORIGIN)",
		    fromkey ? fp1 : "", user ? user : "(ANY)",
		    sshkey_type(hks->ڪنجي), fp2);
		حرر(fp1);
		حرر(fp2);
		/*
		 * Record the hostnames for the initial forwarding and
		 * the final destination.
		 */
		hp = عدم;
		إذا (i == e->nsession_ids - 1)
			hp = آخري_hostnamep;
		وإلا إذا (i == 0)
			hp = forward_hostnamep;
		/* Special handling for final recorded binding */
		test_user = عدم;
		إذا (i == e->nsession_ids - 1) {
			/* Can only check user at final hop */
			test_user = user;
			/*
			 * user is only presented for signature requests.
			 * If this is the case, make sure last binding is not
			 * for a forwarding.
			 */
			إذا (hks->forwarded && user != عدم) {
				error_f("tried to sign on forwarding hop");
				أرجع -1;
			}
		} وإلا إذا (!hks->forwarded) {
			error_f("tried to forward though signing bind");
			أرجع -1;
		}
		إذا (permitted_by_dest_constraints(fromkey, hks->ڪنجي, id,
		    test_user, hp) != 0)
			أرجع -1;
		fromkey = hks->ڪنجي;
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
	إذا (hks->forwarded && user == عدم &&
	    permitted_by_dest_constraints(hks->ڪنجي, عدم, id,
	    عدم, عدم) != 0) {
		debug3_f("key permitted at host but not after");
		أرجع -1;
	}

	/* success */
	أرجع 0;
}

ساكن صحيح
socket_is_remote(Socket_داخلا *e)
{
	أرجع e->session_bind_attempted || (e->nsession_ids != 0);
}

/* return matching private key for given public key */
ساكن سڃاڻپ_عنصر *
lookup_سڃاڻپ_عنصر(بنية sshkey *ڪنجي)
{
	سڃاڻپ_عنصر *id;

	TAILQ_FOREACH(id, &idtab->idlist, ايندڙ) {
		إذا (sshkey_equal(ڪنجي, id->ڪنجي))
			أرجع (id);
	}
	أرجع (عدم);
}

/* Check confirmation of keysign request */
ساكن صحيح
confirm_ڪنجي(سڃاڻپ_عنصر *id, ثابت حرف *extra)
{
	حرف *p;
	صحيح ret = -1;

	p = sshkey_fingerprint(id->ڪنجي, fingerprint_hash, SSH_FP_DEFAULT);
	إذا (p != عدم &&
	    ask_permission("Allow use of key %s?\nKey fingerprint %s.%s%s",
	    id->comment, p,
	    extra == عدم ? "" : "\n", extra == عدم ? "" : extra))
		ret = 0;
	حرر(p);

	أرجع (ret);
}

ساكن فراغ
send_حالت_generic(Socket_داخلا *e, u_int ڪوڊ)
{
	صحيح r;

	إذا ((r = sshbuf_put_u32(e->output, 1)) != 0 ||
	    (r = sshbuf_put_u8(e->output, ڪوڊ)) != 0)
		fatal_fr(r, "compose");
}

ساكن فراغ
send_حالت(Socket_داخلا *e, صحيح success)
{
	send_حالت_generic(e,
	    success ? SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE);
}

/* send list of supported public keys to 'client' */
ساكن فراغ
process_request_identities(Socket_داخلا *e)
{
	سڃاڻپ_عنصر *id;
	بنية sshbuf *نياپو, *ڪنجيون;
	صحيح r;
	u_int i = 0, nentries = 0;
	حرف *fp;

	debug2_f("entering");

	إذا ((نياپو = sshbuf_new()) == عدم || (ڪنجيون = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	TAILQ_FOREACH(id, &idtab->idlist, ايندڙ) {
		إذا ((fp = sshkey_fingerprint(id->ڪنجي, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == عدم)
			fatal_f("fingerprint failed");
		debug_f("key %u / %u: %s %s", i++, idtab->nentries,
		    sshkey_ssh_name(id->ڪنجي), fp);
		dump_dest_constraints(__func__,
		    id->dest_constraints, id->ndest_constraints);
		حرر(fp);
		/* identity not visible, don't include in response */
		إذا (سڃاڻپ_عنصر_permitted(id, e, عدم, عدم, عدم) != 0)
			استمر;
		إذا ((r = sshkey_puts(id->ڪنجي, ڪنجيون)) != 0 ||
		    (r = sshbuf_put_cstring(ڪنجيون, id->comment)) != 0) {
			error_fr(r, "compose key/comment");
			استمر;
		}
		nentries++;
	}
	debug2_f("replying with %u allowed of %u available keys",
	    nentries, idtab->nentries);
	إذا ((r = sshbuf_put_u8(نياپو, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
	    (r = sshbuf_put_u32(نياپو, nentries)) != 0 ||
	    (r = sshbuf_putb(نياپو, ڪنجيون)) != 0)
		fatal_fr(r, "compose");
	إذا ((r = sshbuf_put_stringb(e->output, نياپو)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(نياپو);
	sshbuf_free(ڪنجيون);
}


ساكن حرف *
agent_decode_alg(بنية sshkey *ڪنجي, u_int flags)
{
	إذا (ڪنجي->type == ڪنجي_RSA) {
		إذا (flags & SSH_AGENT_RSA_SHA2_256)
			أرجع "rsa-sha2-256";
		وإلا إذا (flags & SSH_AGENT_RSA_SHA2_512)
			أرجع "rsa-sha2-512";
	} وإلا إذا (ڪنجي->type == ڪنجي_RSA_CERT) {
		إذا (flags & SSH_AGENT_RSA_SHA2_256)
			أرجع "rsa-sha2-256-cert-v01@openssh.com";
		وإلا إذا (flags & SSH_AGENT_RSA_SHA2_512)
			أرجع "rsa-sha2-512-cert-v01@openssh.com";
	}
	أرجع عدم;
}

/*
 * Attempt to parse the contents of a buffer as a SSH publickey userauth
 * request, checking its contents for consistency and matching the embedded
 * key against the one that is being used for signing.
 * Note: does not modify msg buffer.
 * Optionally extract the username, session ID and/or hostkey from the request.
 */
ساكن صحيح
parse_userauth_request(بنية sshbuf *نياپو, ثابت بنية sshkey *expected_ڪنجي,
    حرف **userp, بنية sshbuf **sess_idp, بنية sshkey **hostkeyp)
{
	بنية sshbuf *b = عدم, *sess_id = عدم;
	حرف *user = عدم, *service = عدم, *طريقو = عدم, *pkalg = عدم;
	صحيح r;
	u_char t, sig_follows;
	بنية sshkey *mkey = عدم, *hostkey = عدم;

	إذا (userp != عدم)
		*userp = عدم;
	إذا (sess_idp != عدم)
		*sess_idp = عدم;
	إذا (hostkeyp != عدم)
		*hostkeyp = عدم;
	إذا ((b = sshbuf_fromb(نياپو)) == عدم)
		fatal_f("sshbuf_fromb");

	/* SSH userauth request */
	إذا ((r = sshbuf_froms(b, &sess_id)) != 0)
		اذهب ٻاهريون;
	إذا (sshbuf_len(sess_id) == 0) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب ٻاهريون;
	}
	إذا ((r = sshbuf_get_u8(b, &t)) != 0 || /* SSH2_MSG_USERAUTH_REQUEST */
	    (r = sshbuf_get_cstring(b, &user, عدم)) != 0 || /* server user */
	    (r = sshbuf_get_cstring(b, &service, عدم)) != 0 || /* service */
	    (r = sshbuf_get_cstring(b, &طريقو, عدم)) != 0 || /*طريقو*/
	    (r = sshbuf_get_u8(b, &sig_follows)) != 0 || /* sig-follows */
	    (r = sshbuf_get_cstring(b, &pkalg, عدم)) != 0 || /* alg */
	    (r = sshkey_froms(b, &mkey)) != 0) /*ڪنجي*/
		اذهب ٻاهريون;
	إذا (t != SSH2_نياپو_USERAUTH_REQUEST ||
	    sig_follows != 1 ||
	    strcmp(service, "ssh-connection") != 0 ||
	    !sshkey_equal(expected_ڪنجي, mkey) ||
	    sshkey_type_from_name(pkalg) != expected_ڪنجي->type) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب ٻاهريون;
	}
	إذا (strcmp(طريقو, "publickey-hostbound-v00@openssh.com") == 0) {
		إذا ((r = sshkey_froms(b, &hostkey)) != 0)
			اذهب ٻاهريون;
	} وإلا إذا (strcmp(طريقو, "publickey") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب ٻاهريون;
	}
	إذا (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب ٻاهريون;
	}
	/* success */
	r = 0;
	debug3_f("well formed userauth");
	إذا (userp != عدم) {
		*userp = user;
		user = عدم;
	}
	إذا (sess_idp != عدم) {
		*sess_idp = sess_id;
		sess_id = عدم;
	}
	إذا (hostkeyp != عدم) {
		*hostkeyp = hostkey;
		hostkey = عدم;
	}
 ٻاهريون:
	sshbuf_free(b);
	sshbuf_free(sess_id);
	حرر(user);
	حرر(service);
	حرر(طريقو);
	حرر(pkalg);
	sshkey_free(mkey);
	sshkey_free(hostkey);
	أرجع r;
}

/*
 * Attempt to parse the contents of a buffer as a SSHSIG signature request.
 * Note: does not modify buffer.
 */
ساكن صحيح
parse_sshsig_request(بنية sshbuf *نياپو)
{
	صحيح r;
	بنية sshbuf *b;

	إذا ((b = sshbuf_fromb(نياپو)) == عدم)
		fatal_f("sshbuf_fromb");

	إذا ((r = sshbuf_cmp(b, 0, "SSHSIG", 6)) != 0 ||
	    (r = sshbuf_consume(b, 6)) != 0 ||
	    (r = sshbuf_get_cstring(b, عدم, عدم)) != 0 || /* namespace */
	    (r = sshbuf_get_string_سڌو(b, عدم, عدم)) != 0 || /* reserved */
	    (r = sshbuf_get_cstring(b, عدم, عدم)) != 0 || /* hashalg */
	    (r = sshbuf_get_string_سڌو(b, عدم, عدم)) != 0) /* H(msg) */
		اذهب ٻاهريون;
	إذا (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب ٻاهريون;
	}
	/* success */
	r = 0;
 ٻاهريون:
	sshbuf_free(b);
	أرجع r;
}

/*
 * This function inspects a message to be signed by a FIDO key that has a
 * web-like application string (i.e. one that does not begin with "ssh:".
 * It checks that the message is one of those expected for SSH operations
 * (pubkey userauth, sshsig, CA key signing) to exclude signing challenges
 * for the web.
 */
ساكن صحيح
check_websafe_پيغام_contents(بنية sshkey *ڪنجي, بنية sshbuf *معلومات)
{
	إذا (parse_userauth_request(معلومات, ڪنجي, عدم, عدم, عدم) == 0) {
		debug_f("signed data matches public key userauth request");
		أرجع 1;
	}
	إذا (parse_sshsig_request(معلومات) == 0) {
		debug_f("signed data matches SSHSIG signature request");
		أرجع 1;
	}

	/* XXX check CA signature operation */

	error("web-origin key attempting to sign non-SSH message");
	أرجع 0;
}

ساكن صحيح
buf_equal(ثابت بنية sshbuf *a, ثابت بنية sshbuf *b)
{
	إذا (sshbuf_ptr(a) == عدم || sshbuf_ptr(b) == عدم)
		أرجع SSH_ERR_INVALID_دليل;
	إذا (sshbuf_len(a) != sshbuf_len(b))
		أرجع SSH_ERR_INVALID_FORMAT;
	إذا (timingsafe_bcmp(sshbuf_ptr(a), sshbuf_ptr(b), sshbuf_len(a)) != 0)
		أرجع SSH_ERR_INVALID_FORMAT;
	أرجع 0;
}

/* ssh2 only */
ساكن فراغ
process_sign_request2(Socket_داخلا *e)
{
	u_char *signature = عدم;
	سائيز_t slen = 0;
	u_int compat = 0, flags;
	صحيح r, ok = -1, retried = 0;
	حرف *fp = عدم, *pin = عدم, *prompt = عدم;
	حرف *user = عدم, *sig_dest = عدم;
	ثابت حرف *fwd_host = عدم, *dest_host = عدم;
	بنية sshbuf *نياپو = عدم, *معلومات = عدم, *sid = عدم;
	بنية sshkey *ڪنجي = عدم, *hostkey = عدم;
	بنية سڃاڻپ_عنصر_2 *id;
	بنية notifier_ctx *notifier = عدم;

	debug_f("entering");

	إذا ((نياپو = sshbuf_new()) == عدم || (معلومات = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshkey_froms(e->request, &ڪنجي)) != 0 ||
	    (r = sshbuf_get_stringb(e->request, معلومات)) != 0 ||
	    (r = sshbuf_get_u32(e->request, &flags)) != 0) {
		error_fr(r, "parse");
		اذهب send;
	}

	إذا ((id = lookup_سڃاڻپ_عنصر(ڪنجي)) == عدم) {
		verbose_f("%s key not found", sshkey_type(ڪنجي));
		اذهب send;
	}
	إذا ((fp = sshkey_fingerprint(ڪنجي, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == عدم)
		fatal_f("fingerprint failed");

	إذا (id->ndest_constraints != 0) {
		إذا (e->nsession_ids == 0) {
			logit_f("refusing use of destination-constrained key "
			    "to sign on unbound connection");
			اذهب send;
		}
		إذا (parse_userauth_request(معلومات, ڪنجي, &user, &sid,
		    &hostkey) != 0) {
			logit_f("refusing use of destination-constrained key "
			   "to sign an unidentified signature");
			اذهب send;
		}
		/* XXX logspam */
		debug_f("user=%s", user);
		إذا (سڃاڻپ_عنصر_permitted(id, e, user, &fwd_host, &dest_host) != 0)
			اذهب send;
		/* XXX display fwd_host/dest_host in askpass UI */
		/*
		 * Ensure that the session ID is the most recent one
		 * registered on the socket - it should have been bound by
		 * ssh immediately before userauth.
		 */
		إذا (buf_equal(sid,
		    e->session_ids[e->nsession_ids - 1].sid) != 0) {
			error_f("unexpected session ID (%zu listed) on "
			    "signature request for target user %s with "
			    "key %s %s", e->nsession_ids, user,
			    sshkey_type(id->ڪنجي), fp);
			اذهب send;
		}
		/*
		 * Ensure that the hostkey embedded in the signature matches
		 * the one most recently bound to the socket. An exception is
		 * made for the initial forwarding hop.
		 */
		إذا (e->nsession_ids > 1 && hostkey == عدم) {
			error_f("refusing use of destination-constrained key: "
			    "no hostkey recorded in signature for forwarded "
			    "connection");
			اذهب send;
		}
		إذا (hostkey != عدم && !sshkey_equal(hostkey,
		    e->session_ids[e->nsession_ids - 1].ڪنجي)) {
			error_f("refusing use of destination-constrained key: "
			    "mismatch between hostkey in request and most "
			    "recently bound session");
			اذهب send;
		}
		xasprintf(&sig_dest, "public key authentication request for "
		    "user \"%s\" to listed host", user);
	}
	إذا (id->confirm && confirm_ڪنجي(id, sig_dest) != 0) {
		verbose_f("user refused key");
		اذهب send;
	}
	إذا (sshkey_is_sk(id->ڪنجي)) {
		إذا (restrict_websafe &&
		    ميلاپ_نمونو_list(id->ڪنجي->sk_application,
		    websafe_allowlist, 0) != 1 &&
		    !check_websafe_پيغام_contents(ڪنجي, معلومات)) {
			/* error already logged */
			اذهب send;
		}
		إذا (id->ڪنجي->sk_flags & SSH_SK_USER_PRESENCE_REQD) {
			notifier = notify_شروعات(0,
			    "Confirm user presence for key %s %s%s%s",
			    sshkey_type(id->ڪنجي), fp,
			    sig_dest == عدم ? "" : "\n",
			    sig_dest == عدم ? "" : sig_dest);
		}
	}
 retry_pin:
	إذا ((r = sshkey_sign(id->ڪنجي, &signature, &slen,
	    sshbuf_ptr(معلومات), sshbuf_len(معلومات), agent_decode_alg(ڪنجي, flags),
	    id->sk_provider, pin, compat)) != 0) {
		debug_fr(r, "sshkey_sign");
		إذا (pin == عدم && !retried && sshkey_is_sk(id->ڪنجي) &&
		    r == SSH_ERR_ڪنجي_WRONG_PASSPHRASE) {
			notify_complete(notifier, عدم);
			notifier = عدم;
			/* XXX include sig_dest */
			xasprintf(&prompt, "Enter PIN%sfor %s key %s: ",
			    (id->ڪنجي->sk_flags & SSH_SK_USER_PRESENCE_REQD) ?
			    " and confirm user presence " : " ",
			    sshkey_type(id->ڪنجي), fp);
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

	إذا (ok == 0) {
		إذا ((r = sshbuf_put_u8(نياپو, SSH2_AGENT_SIGN_RESPONSE)) != 0 ||
		    (r = sshbuf_put_string(نياپو, signature, slen)) != 0)
			fatal_fr(r, "compose");
	} وإلا إذا ((r = sshbuf_put_u8(نياپو, SSH_AGENT_FAILURE)) != 0)
		fatal_fr(r, "compose failure");

	إذا ((r = sshbuf_put_stringb(e->output, نياپو)) != 0)
		fatal_fr(r, "enqueue");

	sshbuf_free(sid);
	sshbuf_free(معلومات);
	sshbuf_free(نياپو);
	sshkey_free(ڪنجي);
	sshkey_free(hostkey);
	حرر(fp);
	حرر(signature);
	حرر(sig_dest);
	حرر(user);
	حرر(prompt);
	إذا (pin != عدم)
		freezero(pin, لڙي_ڊيگهه(pin));
}

/* shared */
ساكن فراغ
process_remove_سڃاڻپ_عنصر(Socket_داخلا *e)
{
	صحيح r, success = 0;
	بنية sshkey *ڪنجي = عدم;
	سڃاڻپ_عنصر *id;

	debug2_f("entering");
	إذا ((r = sshkey_froms(e->request, &ڪنجي)) != 0) {
		error_fr(r, "parse key");
		اذهب پورو;
	}
	إذا ((id = lookup_سڃاڻپ_عنصر(ڪنجي)) == عدم) {
		debug_f("key not found");
		اذهب پورو;
	}
	/* identity not visible, cannot be removed */
	إذا (سڃاڻپ_عنصر_permitted(id, e, عدم, عدم, عدم) != 0)
		اذهب پورو; /* error already logged */
	/* We have this key, free it. */
	إذا (idtab->nentries < 1)
		fatal_f("internal error: nentries %d", idtab->nentries);
	TAILQ_REMOVE(&idtab->idlist, id, ايندڙ);
	free_سڃاڻپ_عنصر(id);
	idtab->nentries--;
	success = 1;
 پورو:
	sshkey_free(ڪنجي);
	send_حالت(e, success);
}

ساكن فراغ
remove_all_identities(فراغ)
{
	سڃاڻپ_عنصر *id;

	debug2_f("entering");
	/* Loop over all identities and clear the keys. */
	لكل (id = TAILQ_FIRST(&idtab->idlist); id;
	    id = TAILQ_FIRST(&idtab->idlist)) {
		TAILQ_REMOVE(&idtab->idlist, id, ايندڙ);
		free_سڃاڻپ_عنصر(id);
	}

	/* Mark that there are no identities. */
	idtab->nentries = 0;
}

ساكن فراغ
process_remove_all_identities(Socket_داخلا *e)
{
	remove_all_identities();

	/* Send success. */
	send_حالت(e, 1);
}

/* removes expired keys and returns number of seconds until the next expiry */
ساكن time_t
reaper(فراغ)
{
	time_t deadline = 0, now = monotime();
	سڃاڻپ_عنصر *id, *nxt;

	لكل (id = TAILQ_FIRST(&idtab->idlist); id; id = nxt) {
		nxt = TAILQ_NEXT(id, ايندڙ);
		إذا (id->death == 0)
			استمر;
		إذا (now >= id->death) {
			debug("expiring key '%s'", id->comment);
			TAILQ_REMOVE(&idtab->idlist, id, ايندڙ);
			free_سڃاڻپ_عنصر(id);
			idtab->nentries--;
		} وإلا
			deadline = (deadline == 0) ? id->death :
			    MINIMUM(deadline, id->death);
	}
	إذا (deadline == 0 || deadline <= now)
		أرجع 0;
	وإلا
		أرجع (deadline - now);
}

ساكن صحيح
parse_dest_constraint_hop(بنية sshbuf *b, بنية dest_constraint_hop *dch)
{
	u_char ڪنجي_is_ca;
	سائيز_t elen = 0, userlen = 0;
	صحيح r;
	بنية sshkey *k = عدم;
	حرف *fp;

	memset(dch, '\0', حجم(*dch));
	إذا ((r = sshbuf_get_cstring(b, &dch->user, &userlen)) != 0 ||
	    (r = sshbuf_get_cstring(b, &dch->hostname, عدم)) != 0 ||
	    (r = sshbuf_get_string_سڌو(b, عدم, &elen)) != 0) {
		error_fr(r, "parse");
		اذهب ٻاهريون;
	}
	إذا (elen != 0) {
		error_f("unsupported extensions (len %zu)", elen);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		اذهب ٻاهريون;
	}
	إذا (*dch->hostname == '\0') {
		حرر(dch->hostname);
		dch->hostname = عدم;
	}
	إذا (*dch->user == '\0') {
		حرر(dch->user);
		dch->user = عدم;
	} وإلا إذا (userlen > AGENT_USER_CONSTRAINT_MAX_LEN) {
		error_f("user match pattern too long");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب ٻاهريون;
	}
	طالما (sshbuf_len(b) != 0) {
		dch->ڪنجيون = xrecallocarray(dch->ڪنجيون, dch->nkeys,
		    dch->nkeys + 1, حجم(*dch->ڪنجيون));
		dch->ڪنجي_is_ca = xrecallocarray(dch->ڪنجي_is_ca, dch->nkeys,
		    dch->nkeys + 1, حجم(*dch->ڪنجي_is_ca));
		إذا ((r = sshkey_froms(b, &k)) != 0 ||
		    (r = sshbuf_get_u8(b, &ڪنجي_is_ca)) != 0)
			اذهب ٻاهريون;
		إذا ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == عدم)
			fatal_f("fingerprint failed");
		debug3_f("%s%s%s: adding %skey %s %s",
		    dch->user == عدم ? "" : dch->user,
		    dch->user == عدم ? "" : "@",
		    dch->hostname, ڪنجي_is_ca ? "CA " : "", sshkey_type(k), fp);
		حرر(fp);
		dch->ڪنجيون[dch->nkeys] = k;
		dch->ڪنجي_is_ca[dch->nkeys] = ڪنجي_is_ca != 0;
		dch->nkeys++;
		k = عدم; /* transferred */
	}
	/* success */
	r = 0;
 ٻاهريون:
	sshkey_free(k);
	أرجع r;
}

ساكن صحيح
parse_dest_constraint(بنية sshbuf *m, بنية dest_constraint *dc)
{
	بنية sshbuf *b = عدم, *frombuf = عدم, *tobuf = عدم;
	صحيح r;
	سائيز_t elen = 0;

	debug3_f("entering");

	memset(dc, '\0', حجم(*dc));
	إذا ((r = sshbuf_froms(m, &b)) != 0 ||
	    (r = sshbuf_froms(b, &frombuf)) != 0 ||
	    (r = sshbuf_froms(b, &tobuf)) != 0 ||
	    (r = sshbuf_get_string_سڌو(b, عدم, &elen)) != 0) {
		error_fr(r, "parse");
		اذهب ٻاهريون;
	}
	إذا ((r = parse_dest_constraint_hop(frombuf, &dc->from)) != 0 ||
	    (r = parse_dest_constraint_hop(tobuf, &dc->منزل)) != 0)
		اذهب ٻاهريون; /* already logged */
	إذا (elen != 0) {
		error_f("unsupported extensions (len %zu)", elen);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		اذهب ٻاهريون;
	}
	debug2_f("parsed %s (%u keys) > %s%s%s (%u keys)",
	    dc->from.hostname ? dc->from.hostname : "(ORIGIN)", dc->from.nkeys,
	    dc->منزل.user ? dc->منزل.user : "", dc->منزل.user ? "@" : "",
	    dc->منزل.hostname ? dc->منزل.hostname : "(ANY)", dc->منزل.nkeys);
	/* check consistency */
	إذا ((dc->from.hostname == عدم) != (dc->from.nkeys == 0) ||
	    dc->from.user != عدم) {
		error_f("inconsistent \"from\" specification");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب ٻاهريون;
	}
	إذا (dc->منزل.hostname == عدم || dc->منزل.nkeys == 0) {
		error_f("incomplete \"to\" specification");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب ٻاهريون;
	}
	/* success */
	r = 0;
 ٻاهريون:
	sshbuf_free(b);
	sshbuf_free(frombuf);
	sshbuf_free(tobuf);
	أرجع r;
}

ساكن صحيح
parse_ڪنجي_constraint_extension(بنية sshbuf *m, حرف **sk_providerp,
    بنية dest_constraint **dcsp, سائيز_t *ndcsp, صحيح *cert_onlyp,
    بنية sshkey ***certs, سائيز_t *ncerts)
{
	حرف *ext_name = عدم;
	صحيح r;
	بنية sshbuf *b = عدم;
	u_char v;
	بنية sshkey *k;

	إذا ((r = sshbuf_get_cstring(m, &ext_name, عدم)) != 0) {
		error_fr(r, "parse constraint extension");
		اذهب ٻاهريون;
	}
	debug_f("constraint ext %s", ext_name);
	إذا (strcmp(ext_name, "sk-provider@openssh.com") == 0) {
		إذا (sk_providerp == عدم) {
			error_f("%s not valid here", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			اذهب ٻاهريون;
		}
		إذا (*sk_providerp != عدم) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			اذهب ٻاهريون;
		}
		إذا ((r = sshbuf_get_cstring(m, sk_providerp, عدم)) != 0) {
			error_fr(r, "parse %s", ext_name);
			اذهب ٻاهريون;
		}
	} وإلا إذا (strcmp(ext_name,
	    "restrict-destination-v00@openssh.com") == 0) {
		إذا (*dcsp != عدم) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			اذهب ٻاهريون;
		}
		إذا ((r = sshbuf_froms(m, &b)) != 0) {
			error_fr(r, "parse %s outer", ext_name);
			اذهب ٻاهريون;
		}
		طالما (sshbuf_len(b) != 0) {
			إذا (*ndcsp >= AGENT_MAX_DEST_CONSTRAINTS) {
				error_f("too many %s constraints", ext_name);
				r = SSH_ERR_INVALID_FORMAT;
				اذهب ٻاهريون;
			}
			*dcsp = xrecallocarray(*dcsp, *ndcsp, *ndcsp + 1,
			    حجم(**dcsp));
			إذا ((r = parse_dest_constraint(b,
			    *dcsp + (*ndcsp)++)) != 0)
				اذهب ٻاهريون; /* error already logged */
		}
	} وإلا إذا (strcmp(ext_name,
	    "associated-certs-v00@openssh.com") == 0) {
		إذا (certs == عدم || ncerts == عدم || cert_onlyp == عدم) {
			error_f("%s not valid here", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			اذهب ٻاهريون;
		}
		إذا (*certs != عدم) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			اذهب ٻاهريون;
		}
		إذا ((r = sshbuf_get_u8(m, &v)) != 0 ||
		    (r = sshbuf_froms(m, &b)) != 0) {
			error_fr(r, "parse %s", ext_name);
			اذهب ٻاهريون;
		}
		*cert_onlyp = v != 0;
		طالما (sshbuf_len(b) != 0) {
			إذا (*ncerts >= AGENT_MAX_EXT_CERTS) {
				error_f("too many %s constraints", ext_name);
				r = SSH_ERR_INVALID_FORMAT;
				اذهب ٻاهريون;
			}
			*certs = xrecallocarray(*certs, *ncerts, *ncerts + 1,
			    حجم(**certs));
			إذا ((r = sshkey_froms(b, &k)) != 0) {
				error_fr(r, "parse key");
				اذهب ٻاهريون;
			}
			(*certs)[(*ncerts)++] = k;
		}
	} وإلا {
		error_f("unsupported constraint \"%s\"", ext_name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		اذهب ٻاهريون;
	}
	/* success */
	r = 0;
 ٻاهريون:
	حرر(ext_name);
	sshbuf_free(b);
	أرجع r;
}

ساكن صحيح
parse_ڪنجي_constraints(بنية sshbuf *m, بنية sshkey *k, time_t *deathp,
    u_int *secondsp, صحيح *confirmp, حرف **sk_providerp,
    بنية dest_constraint **dcsp, سائيز_t *ndcsp,
    صحيح *cert_onlyp, سائيز_t *ncerts, بنية sshkey ***certs)
{
	u_char ctype;
	صحيح r;
	u_int seconds;

	طالما (sshbuf_len(m)) {
		إذا ((r = sshbuf_get_u8(m, &ctype)) != 0) {
			error_fr(r, "parse constraint type");
			اذهب ٻاهريون;
		}
		بدل (ctype) {
		حالة SSH_AGENT_CONSTRAIN_LIFETIME:
			إذا (*deathp != 0) {
				error_f("lifetime already set");
				r = SSH_ERR_INVALID_FORMAT;
				اذهب ٻاهريون;
			}
			إذا ((r = sshbuf_get_u32(m, &seconds)) != 0) {
				error_fr(r, "parse lifetime constraint");
				اذهب ٻاهريون;
			}
			*deathp = monotime() + seconds;
			*secondsp = seconds;
			اكسر;
		حالة SSH_AGENT_CONSTRAIN_CONFIRM:
			إذا (*confirmp != 0) {
				error_f("confirm already set");
				r = SSH_ERR_INVALID_FORMAT;
				اذهب ٻاهريون;
			}
			*confirmp = 1;
			اكسر;
		حالة SSH_AGENT_CONSTRAIN_EXTENSION:
			إذا ((r = parse_ڪنجي_constraint_extension(m,
			    sk_providerp, dcsp, ndcsp,
			    cert_onlyp, certs, ncerts)) != 0)
				اذهب ٻاهريون; /* error already logged */
			اكسر;
		افتراضي:
			error_f("Unknown constraint %d", ctype);
			r = SSH_ERR_FEATURE_UNSUPPORTED;
			اذهب ٻاهريون;
		}
	}
	/* success */
	r = 0;
 ٻاهريون:
	أرجع r;
}

ساكن فراغ
process_جوڙيو_سڃاڻپ_عنصر(Socket_داخلا *e)
{
	سڃاڻپ_عنصر *id;
	صحيح success = 0, confirm = 0;
	حرف *fp, *comment = عدم, *sk_provider = عدم;
	حرف canonical_provider[PATH_MAX];
	time_t death = 0;
	u_int seconds = 0;
	بنية dest_constraint *dest_constraints = عدم;
	سائيز_t ndest_constraints = 0;
	بنية sshkey *k = عدم;
	صحيح r = SSH_ERR_اندروني_ERROR;

	debug2_f("entering");
	إذا ((r = sshkey_ذاتي_deserialize(e->request, &k)) != 0 ||
	    k == عدم ||
	    (r = sshbuf_get_cstring(e->request, &comment, عدم)) != 0) {
		error_fr(r, "parse");
		اذهب ٻاهريون;
	}
	إذا (parse_ڪنجي_constraints(e->request, k, &death, &seconds, &confirm,
	    &sk_provider, &dest_constraints, &ndest_constraints,
	    عدم, عدم, عدم) != 0) {
		error_f("failed to parse constraints");
		sshbuf_reset(e->request);
		اذهب ٻاهريون;
	}
	dump_dest_constraints(__func__, dest_constraints, ndest_constraints);

	إذا (sk_provider != عدم) {
		إذا (!sshkey_is_sk(k)) {
			error("Cannot add provider: %s is not an "
			    "authenticator-hosted key", sshkey_type(k));
			اذهب ٻاهريون;
		}
		إذا (strcasecmp(sk_provider, "internal") == 0) {
			debug_f("internal provider");
		} وإلا {
			إذا (socket_is_remote(e) && !remote_جوڙيو_provider) {
				verbose("failed add of SK provider \"%.100s\": "
				    "remote addition of providers is disabled",
				    sk_provider);
				اذهب ٻاهريون;
			}
			إذا (realpath(sk_provider, canonical_provider) == عدم) {
				verbose("failed provider \"%.100s\": "
				    "realpath: %s", sk_provider,
				    strerror(errno));
				اذهب ٻاهريون;
			}
			حرر(sk_provider);
			sk_provider = xstrdup(canonical_provider);
			إذا (ميلاپ_نمونو_list(sk_provider,
			    allowed_providers, 0) != 1) {
				error("Refusing add key: "
				    "provider %s not allowed", sk_provider);
				اذهب ٻاهريون;
			}
		}
	}
	إذا ((r = sshkey_shield_ذاتي(k)) != 0) {
		error_fr(r, "shield private");
		اذهب ٻاهريون;
	}
	إذا (lifetime && !death)
		death = monotime() + lifetime;
	إذا ((id = lookup_سڃاڻپ_عنصر(k)) == عدم) {
		id = xcalloc(1, حجم(سڃاڻپ_عنصر));
		TAILQ_INSERT_TAIL(&idtab->idlist, id, ايندڙ);
		/* Increment the number of identities. */
		idtab->nentries++;
	} وإلا {
		/* identity not visible, do not update */
		إذا (سڃاڻپ_عنصر_permitted(id, e, عدم, عدم, عدم) != 0)
			اذهب ٻاهريون; /* error already logged */
		/* key state might have been updated */
		sshkey_free(id->ڪنجي);
		حرر(id->comment);
		حرر(id->sk_provider);
		free_dest_constraints(id->dest_constraints,
		    id->ndest_constraints);
	}
	/* success */
	id->ڪنجي = k;
	id->comment = comment;
	id->death = death;
	id->confirm = confirm;
	id->sk_provider = sk_provider;
	id->dest_constraints = dest_constraints;
	id->ndest_constraints = ndest_constraints;

	إذا ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
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
 ٻاهريون:
	حرر(sk_provider);
	حرر(comment);
	sshkey_free(k);
	free_dest_constraints(dest_constraints, ndest_constraints);
	send_حالت(e, success);
}

/* XXX todo: encrypt sensitive data with passphrase */
ساكن فراغ
process_تالو_agent(Socket_داخلا *e, صحيح تالو)
{
	صحيح r, success = 0, delay;
	حرف *passwd;
	u_char passwdhash[تالو_سائيز];
	ساكن u_int fail_ڳڻپ = 0;
	سائيز_t pwlen;

	debug2_f("entering");
	/*
	 * This is deliberately fatal: the user has requested that we lock,
	 * but we can't parse their request properly. The only safe thing to
	 * do is abort.
	 */
	إذا ((r = sshbuf_get_cstring(e->request, &passwd, &pwlen)) != 0)
		fatal_fr(r, "parse");
	إذا (pwlen == 0) {
		debug("empty password not supported");
	} وإلا إذا (locked && !تالو) {
		إذا (bcrypt_pbkdf(passwd, pwlen, تالو_salt, حجم(تالو_salt),
		    passwdhash, حجم(passwdhash), تالو_ڦيرا) < 0)
			fatal("bcrypt_pbkdf");
		إذا (timingsafe_bcmp(passwdhash, تالو_pwhash, تالو_سائيز) == 0) {
			debug("agent unlocked");
			locked = 0;
			fail_ڳڻپ = 0;
			explicit_bzero(تالو_pwhash, حجم(تالو_pwhash));
			success = 1;
		} وإلا {
			/* delay in 0.1s increments up to 10s */
			إذا (fail_ڳڻپ < 100)
				fail_ڳڻپ++;
			delay = 100000 * fail_ڳڻپ;
			debug("unlock failed, delaying %0.1lf seconds",
			    (مزدوج)delay/1000000);
			usleep(delay);
		}
		explicit_bzero(passwdhash, حجم(passwdhash));
	} وإلا إذا (!locked && تالو) {
		debug("agent locked");
		locked = 1;
		arc4random_buf(تالو_salt, حجم(تالو_salt));
		إذا (bcrypt_pbkdf(passwd, pwlen, تالو_salt, حجم(تالو_salt),
		    تالو_pwhash, حجم(تالو_pwhash), تالو_ڦيرا) < 0)
			fatal("bcrypt_pbkdf");
		success = 1;
	}
	freezero(passwd, pwlen);
	send_حالت(e, success);
}

ساكن فراغ
no_identities(Socket_داخلا *e)
{
	بنية sshbuf *نياپو;
	صحيح r;

	إذا ((نياپو = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshbuf_put_u8(نياپو, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
	    (r = sshbuf_put_u32(نياپو, 0)) != 0 ||
	    (r = sshbuf_put_stringb(e->output, نياپو)) != 0)
		fatal_fr(r, "compose");
	sshbuf_free(نياپو);
}

#جيڪڏهن_وصف_ٿيل ENABLE_PKCS11
/* Add an identity to idlist; takes ownership of 'key' and 'comment' */
ساكن فراغ
جوڙيو_p11_سڃاڻپ_عنصر(بنية sshkey *ڪنجي, حرف *comment, ثابت حرف *provider,
    time_t death, u_int confirm, بنية dest_constraint *dest_constraints,
    سائيز_t ndest_constraints)
{
	سڃاڻپ_عنصر *id;

	إذا (lookup_سڃاڻپ_عنصر(ڪنجي) != عدم) {
		sshkey_free(ڪنجي);
		حرر(comment);
		أرجع;
	}
	id = xcalloc(1, حجم(سڃاڻپ_عنصر));
	id->ڪنجي = ڪنجي;
	id->comment = comment;
	id->provider = xstrdup(provider);
	id->death = death;
	id->confirm = confirm;
	id->dest_constraints = dup_dest_constraints(dest_constraints,
	    ndest_constraints);
	id->ndest_constraints = ndest_constraints;
	TAILQ_INSERT_TAIL(&idtab->idlist, id, ايندڙ);
	idtab->nentries++;
}

ساكن فراغ
process_جوڙيو_smartcard_ڪنجي(Socket_داخلا *e)
{
	حرف *provider = عدم, *pin = عدم, canonical_provider[PATH_MAX];
	حرف **comments = عدم;
	صحيح r, i, ڳڻپ = 0, success = 0, confirm = 0;
	u_int seconds = 0;
	time_t death = 0;
	بنية sshkey **ڪنجيون = عدم, *k;
	بنية dest_constraint *dest_constraints = عدم;
	سائيز_t j, ndest_constraints = 0, ncerts = 0;
	بنية sshkey **certs = عدم;
	صحيح cert_only = 0;

	debug2_f("entering");
	إذا ((r = sshbuf_get_cstring(e->request, &provider, عدم)) != 0 ||
	    (r = sshbuf_get_cstring(e->request, &pin, عدم)) != 0) {
		error_fr(r, "parse");
		اذهب send;
	}
	إذا (parse_ڪنجي_constraints(e->request, عدم, &death, &seconds, &confirm,
	    عدم, &dest_constraints, &ndest_constraints, &cert_only,
	    &ncerts, &certs) != 0) {
		error_f("failed to parse constraints");
		اذهب send;
	}
	dump_dest_constraints(__func__, dest_constraints, ndest_constraints);
	إذا (socket_is_remote(e) && !remote_جوڙيو_provider) {
		verbose("failed PKCS#11 add of \"%.100s\": remote addition of "
		    "providers is disabled", provider);
		اذهب send;
	}
	إذا (realpath(provider, canonical_provider) == عدم) {
		verbose("failed PKCS#11 add of \"%.100s\": realpath: %s",
		    provider, strerror(errno));
		اذهب send;
	}
	إذا (ميلاپ_نمونو_list(canonical_provider, allowed_providers, 0) != 1) {
		verbose("refusing PKCS#11 add of \"%.100s\": "
		    "provider not allowed", canonical_provider);
		اذهب send;
	}
	debug_f("add %.100s", canonical_provider);
	إذا (lifetime && !death)
		death = monotime() + lifetime;

	ڳڻپ = pkcs11_جوڙيو_provider(canonical_provider, pin, &ڪنجيون, &comments);
	لكل (i = 0; i < ڳڻپ; i++) {
		إذا (comments[i] == عدم || comments[i][0] == '\0') {
			حرر(comments[i]);
			comments[i] = xstrdup(canonical_provider);
		}
		لكل (j = 0; j < ncerts; j++) {
			إذا (!sshkey_is_cert(certs[j]))
				استمر;
			إذا (!sshkey_equal_عوامي(ڪنجيون[i], certs[j]))
				استمر;
			إذا (pkcs11_make_cert(ڪنجيون[i], certs[j], &k) != 0)
				استمر;
			جوڙيو_p11_سڃاڻپ_عنصر(k, xstrdup(comments[i]),
			    canonical_provider, death, confirm,
			    dest_constraints, ndest_constraints);
			success = 1;
		}
		إذا (!cert_only && lookup_سڃاڻپ_عنصر(ڪنجيون[i]) == عدم) {
			جوڙيو_p11_سڃاڻپ_عنصر(ڪنجيون[i], comments[i],
			    canonical_provider, death, confirm,
			    dest_constraints, ndest_constraints);
			ڪنجيون[i] = عدم;		/* transferred */
			comments[i] = عدم;	/* transferred */
			success = 1;
		}
		/* XXX update constraints for existing keys */
		sshkey_free(ڪنجيون[i]);
		حرر(comments[i]);
	}
send:
	حرر(pin);
	حرر(provider);
	حرر(ڪنجيون);
	حرر(comments);
	free_dest_constraints(dest_constraints, ndest_constraints);
	لكل (j = 0; j < ncerts; j++)
		sshkey_free(certs[j]);
	حرر(certs);
	send_حالت(e, success);
}

ساكن فراغ
process_remove_smartcard_ڪنجي(Socket_داخلا *e)
{
	حرف *provider = عدم, *pin = عدم, canonical_provider[PATH_MAX];
	صحيح r, success = 0;
	سڃاڻپ_عنصر *id, *nxt;

	debug2_f("entering");
	إذا ((r = sshbuf_get_cstring(e->request, &provider, عدم)) != 0 ||
	    (r = sshbuf_get_cstring(e->request, &pin, عدم)) != 0) {
		error_fr(r, "parse");
		اذهب send;
	}
	حرر(pin);

	إذا (realpath(provider, canonical_provider) == عدم) {
		verbose("failed PKCS#11 add of \"%.100s\": realpath: %s",
		    provider, strerror(errno));
		اذهب send;
	}

	debug_f("remove %.100s", canonical_provider);
	لكل (id = TAILQ_FIRST(&idtab->idlist); id; id = nxt) {
		nxt = TAILQ_NEXT(id, ايندڙ);
		/* Skip file--based keys */
		إذا (id->provider == عدم)
			استمر;
		إذا (!strcmp(canonical_provider, id->provider)) {
			TAILQ_REMOVE(&idtab->idlist, id, ايندڙ);
			free_سڃاڻپ_عنصر(id);
			idtab->nentries--;
		}
	}
	إذا (pkcs11_del_provider(canonical_provider) == 0)
		success = 1;
	وإلا
		error_f("pkcs11_del_provider failed");
send:
	حرر(provider);
	send_حالت(e, success);
}
#جيڪڏهن_پورو /* ENABLE_PKCS11 */

ساكن صحيح
process_ext_session_bind(Socket_داخلا *e)
{
	صحيح r, sid_ميلاپ, ڪنجي_ميلاپ;
	بنية sshkey *ڪنجي = عدم;
	بنية sshbuf *sid = عدم, *sig = عدم;
	حرف *fp = عدم;
	سائيز_t i;
	u_char fwd = 0;

	debug2_f("entering");
	e->session_bind_attempted = 1;
	إذا ((r = sshkey_froms(e->request, &ڪنجي)) != 0 ||
	    (r = sshbuf_froms(e->request, &sid)) != 0 ||
	    (r = sshbuf_froms(e->request, &sig)) != 0 ||
	    (r = sshbuf_get_u8(e->request, &fwd)) != 0) {
		error_fr(r, "parse");
		اذهب ٻاهريون;
	}
	إذا (sshbuf_len(sid) > AGENT_MAX_SID_LEN) {
		error_f("session ID too long");
		اذهب ٻاهريون;
	}
	إذا ((fp = sshkey_fingerprint(ڪنجي, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == عدم)
		fatal_f("fingerprint failed");
	/* check signature with hostkey on session ID */
	إذا ((r = sshkey_verify(ڪنجي, sshbuf_ptr(sig), sshbuf_len(sig),
	    sshbuf_ptr(sid), sshbuf_len(sid), عدم, 0, عدم)) != 0) {
		error_fr(r, "sshkey_verify for %s %s", sshkey_type(ڪنجي), fp);
		اذهب ٻاهريون;
	}
	/* check whether sid/key already recorded */
	لكل (i = 0; i < e->nsession_ids; i++) {
		إذا (!e->session_ids[i].forwarded) {
			error_f("attempt to bind session ID to socket "
			    "previously bound for authentication attempt");
			r = -1;
			اذهب ٻاهريون;
		}
		sid_ميلاپ = buf_equal(sid, e->session_ids[i].sid) == 0;
		ڪنجي_ميلاپ = sshkey_equal(ڪنجي, e->session_ids[i].ڪنجي);
		إذا (sid_ميلاپ && ڪنجي_ميلاپ) {
			debug_f("session ID already recorded for %s %s",
			    sshkey_type(ڪنجي), fp);
			r = 0;
			اذهب ٻاهريون;
		} وإلا إذا (sid_ميلاپ) {
			error_f("session ID recorded against different key "
			    "for %s %s", sshkey_type(ڪنجي), fp);
			r = -1;
			اذهب ٻاهريون;
		}
		/*
		 * new sid with previously-seen key can happen, e.g. multiple
		 * connections to the same host.
		 */
	}
	/* record new key/sid */
	إذا (e->nsession_ids >= AGENT_MAX_SESSION_IDS) {
		error_f("too many session IDs recorded");
		r = -1;
		اذهب ٻاهريون;
	}
	e->session_ids = xrecallocarray(e->session_ids, e->nsession_ids,
	    e->nsession_ids + 1, حجم(*e->session_ids));
	i = e->nsession_ids++;
	debug_f("recorded %s %s (slot %zu of %d)", sshkey_type(ڪنجي), fp, i,
	    AGENT_MAX_SESSION_IDS);
	e->session_ids[i].ڪنجي = ڪنجي;
	e->session_ids[i].forwarded = fwd != 0;
	ڪنجي = عدم; /* transferred */
	/* can't transfer sid; it's refcounted and scoped to request's life */
	إذا ((e->session_ids[i].sid = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new");
	إذا ((r = sshbuf_putb(e->session_ids[i].sid, sid)) != 0)
		fatal_fr(r, "sshbuf_putb session ID");
	/* success */
	r = 0;
 ٻاهريون:
	حرر(fp);
	sshkey_free(ڪنجي);
	sshbuf_free(sid);
	sshbuf_free(sig);
	أرجع r == 0 ? 1 : 0;
}

ساكن صحيح
process_ext_query(Socket_داخلا *e)
{
	صحيح r;
	بنية sshbuf *نياپو = عدم;

	debug2_f("entering");
	إذا ((نياپو = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshbuf_put_u8(نياپو, SSH_AGENT_EXTENSION_RESPONSE)) != 0 ||
	    (r = sshbuf_put_cstring(نياپو, "query")) != 0 ||
	    /* string[]     supported extension types */
	    (r = sshbuf_put_cstring(نياپو, "session-bind@openssh.com")) != 0)
		fatal_fr(r, "compose");
	إذا ((r = sshbuf_put_stringb(e->output, نياپو)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(نياپو);
	أرجع 1;
}

ساكن فراغ
process_extension(Socket_داخلا *e)
{
	صحيح r, replied = 0, success = 0;
	حرف *name;

	debug2_f("entering");
	إذا ((r = sshbuf_get_cstring(e->request, &name, عدم)) != 0) {
		error_fr(r, "parse");
		send_حالت(e, 0);
		أرجع;
	}

	/*
	 * This function can be called while the agent is locked to allow
	 * session binds to be processed for new channels.
	 * Other operations should be refused when locked.
	 */

	إذا (strcmp(name, "session-bind@openssh.com") == 0) {
		success = process_ext_session_bind(e);
	} وإلا إذا (locked) {
		debug_f("attempt to use extension \"%s\" while locked", name);
		اذهب generic_fail;
	} وإلا إذا (strcmp(name, "query") == 0) {
		replied = success = process_ext_query(e);
	} وإلا {
		debug_f("unsupported extension \"%s\"", name);
 generic_fail:
		حرر(name);
		send_حالت(e, 0);
		أرجع;
	}
	حرر(name);
	/* Agent failures are signalled with a different error code */
	إذا (!replied) {
		send_حالت_generic(e,
		    success ? SSH_AGENT_SUCCESS : SSH_AGENT_EXTENSION_FAILURE);
	}
}

/*
 * dispatch incoming message.
 * returns 1 on success, 0 for incomplete messages or -1 on error.
 */
ساكن صحيح
process_پيغام(u_int socknum)
{
	u_int نياپو_len;
	u_char type;
	ثابت u_char *cp;
	صحيح r;
	Socket_داخلا *e;

	إذا (socknum >= sockets_alloc)
		fatal_f("sock %u >= allocated %u", socknum, sockets_alloc);
	e = &sockets[socknum];

	إذا (sshbuf_len(e->داخلا_2) < 5)
		أرجع 0;		/* Incomplete message header. */
	cp = sshbuf_ptr(e->داخلا_2);
	نياپو_len = PEEK_U32(cp);
	إذا (نياپو_len > AGENT_MAX_LEN) {
		debug_f("socket %u (fd=%d) message too long %u > %u",
		    socknum, e->fd, نياپو_len, AGENT_MAX_LEN);
		أرجع -1;
	}
	إذا (sshbuf_len(e->داخلا_2) < نياپو_len + 4)
		أرجع 0;		/* Incomplete message body. */

	/* move the current input to e->request */
	sshbuf_reset(e->request);
	إذا ((r = sshbuf_get_stringb(e->داخلا_2, e->request)) != 0 ||
	    (r = sshbuf_get_u8(e->request, &type)) != 0) {
		إذا (r == SSH_ERR_پيغام_INCOMPLETE ||
		    r == SSH_ERR_STRING_TOO_LARGE) {
			error_fr(r, "parse");
			أرجع -1;
		}
		fatal_fr(r, "parse");
	}

	debug_f("socket %u (fd=%d) type %d", socknum, e->fd, type);

	/* check whether agent is locked */
	إذا (locked && type != SSH_AGENTC_UNLOCK) {
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
			send_حالت(e, 0);
		}
		sshbuf_reset(e->request);
		أرجع 1;
	}

	بدل (type) {
	حالة SSH_AGENTC_تالو:
	حالة SSH_AGENTC_UNLOCK:
		process_تالو_agent(e, type == SSH_AGENTC_تالو);
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
	حالة SSH2_AGENTC_جوڙيو_سڃاڻپ_عنصر:
	حالة SSH2_AGENTC_جوڙيو_ID_CONSTRAINED:
		process_جوڙيو_سڃاڻپ_عنصر(e);
		اكسر;
	حالة SSH2_AGENTC_REMOVE_سڃاڻپ_عنصر:
		process_remove_سڃاڻپ_عنصر(e);
		اكسر;
	حالة SSH2_AGENTC_REMOVE_ALL_IDENTITIES:
		process_remove_all_identities(e);
		اكسر;
#جيڪڏهن_وصف_ٿيل ENABLE_PKCS11
	حالة SSH_AGENTC_جوڙيو_SMARTCARD_ڪنجي:
	حالة SSH_AGENTC_جوڙيو_SMARTCARD_ڪنجي_CONSTRAINED:
		process_جوڙيو_smartcard_ڪنجي(e);
		اكسر;
	حالة SSH_AGENTC_REMOVE_SMARTCARD_ڪنجي:
		process_remove_smartcard_ڪنجي(e);
		اكسر;
#جيڪڏهن_پورو /* ENABLE_PKCS11 */
	حالة SSH_AGENTC_EXTENSION:
		process_extension(e);
		اكسر;
	افتراضي:
		/* Unknown message.  Respond with failure. */
		error("Unknown message %d", type);
		sshbuf_reset(e->request);
		send_حالت(e, 0);
		اكسر;
	}
	أرجع 1;
}

ساكن فراغ
new_socket(sock_type type, صحيح fd)
{
	u_int i, old_alloc, new_alloc;

	debug_f("type = %s", type == AUTH_CONNECTION ? "CONNECTION" :
	    (type == AUTH_SOCKET ? "SOCKET" : "UNKNOWN"));
	سيٽ_nonblock(fd);

	إذا (fd > max_fd)
		max_fd = fd;

	لكل (i = 0; i < sockets_alloc; i++)
		إذا (sockets[i].type == AUTH_اڻ_استعمال_ٿيل) {
			sockets[i].fd = fd;
			إذا ((sockets[i].داخلا_2 = sshbuf_new()) == عدم ||
			    (sockets[i].output = sshbuf_new()) == عدم ||
			    (sockets[i].request = sshbuf_new()) == عدم)
				fatal_f("sshbuf_new failed");
			sockets[i].type = type;
			أرجع;
		}
	old_alloc = sockets_alloc;
	new_alloc = sockets_alloc + 10;
	sockets = xrecallocarray(sockets, old_alloc, new_alloc,
	    حجم(sockets[0]));
	لكل (i = old_alloc; i < new_alloc; i++)
		sockets[i].type = AUTH_اڻ_استعمال_ٿيل;
	sockets_alloc = new_alloc;
	sockets[old_alloc].fd = fd;
	إذا ((sockets[old_alloc].داخلا_2 = sshbuf_new()) == عدم ||
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
	إذا (fd == -1) {
		error("accept from AUTH_SOCKET: %s", strerror(errno));
		أرجع -1;
	}
	إذا (getpeereid(fd, &euid, &egid) == -1) {
		error("getpeereid %d failed: %s", fd, strerror(errno));
		close(fd);
		أرجع -1;
	}
	إذا ((euid != 0) && (getuid() != euid)) {
		error("uid mismatch: peer euid %u != uid %u",
		    (u_int) euid, (u_int) getuid());
		close(fd);
		أرجع -1;
	}
	new_socket(AUTH_CONNECTION, fd);
	أرجع 0;
}

ساكن صحيح
handle_conn_read(u_int socknum)
{
	حرف buf[AGENT_RBUF_LEN];
	ssize_t len;
	صحيح r;

	إذا ((len = اقرأ(sockets[socknum].fd, buf, حجم(buf))) <= 0) {
		إذا (len == -1) {
			إذا (errno == EAGAIN || errno == EINTR)
				أرجع 0;
			error_f("read error on socket %u (fd %d): %s",
			    socknum, sockets[socknum].fd, strerror(errno));
		}
		أرجع -1;
	}
	إذا ((r = sshbuf_put(sockets[socknum].داخلا_2, buf, len)) != 0)
		fatal_fr(r, "compose");
	explicit_bzero(buf, حجم(buf));
	لكل (;;) {
		إذا ((r = process_پيغام(socknum)) == -1)
			أرجع -1;
		وإلا إذا (r == 0)
			اكسر;
	}
	أرجع 0;
}

ساكن صحيح
handle_conn_write(u_int socknum)
{
	ssize_t len;
	صحيح r;

	إذا (sshbuf_len(sockets[socknum].output) == 0)
		أرجع 0; /* shouldn't happen */
	إذا ((len = اكتب(sockets[socknum].fd,
	    sshbuf_ptr(sockets[socknum].output),
	    sshbuf_len(sockets[socknum].output))) <= 0) {
		إذا (len == -1) {
			إذا (errno == EAGAIN || errno == EINTR)
				أرجع 0;
			error_f("read error on socket %u (fd %d): %s",
			    socknum, sockets[socknum].fd, strerror(errno));
		}
		أرجع -1;
	}
	إذا ((r = sshbuf_consume(sockets[socknum].output, len)) != 0)
		fatal_fr(r, "consume");
	أرجع 0;
}

ساكن فراغ
after_poll(بنية pollfd *pfd, سائيز_t npfd, u_int maxfds)
{
	سائيز_t i;
	u_int socknum, activefds = npfd;

	لكل (i = 0; i < npfd; i++) {
		إذا (pfd[i].revents == 0)
			استمر;
		/* Find sockets entry */
		لكل (socknum = 0; socknum < sockets_alloc; socknum++) {
			إذا (sockets[socknum].type != AUTH_SOCKET &&
			    sockets[socknum].type != AUTH_CONNECTION)
				استمر;
			إذا (pfd[i].fd == sockets[socknum].fd)
				اكسر;
		}
		إذا (socknum >= sockets_alloc) {
			error_f("no socket for fd %d", pfd[i].fd);
			استمر;
		}
		/* Process events */
		بدل (sockets[socknum].type) {
		حالة AUTH_SOCKET:
			إذا ((pfd[i].revents & (POLLIN|POLLERR)) == 0)
				اكسر;
			إذا (npfd > maxfds) {
				debug3("out of fds (active %u >= limit %u); "
				    "skipping accept", activefds, maxfds);
				اكسر;
			}
			إذا (handle_socket_read(socknum) == 0)
				activefds++;
			اكسر;
		حالة AUTH_CONNECTION:
			إذا ((pfd[i].revents & (POLLIN|POLLHUP|POLLERR)) != 0 &&
			    handle_conn_read(socknum) != 0)
				اذهب close_sock;
			إذا ((pfd[i].revents & (POLLOUT|POLLHUP)) != 0 &&
			    handle_conn_write(socknum) != 0) {
 close_sock:
				إذا (activefds == 0)
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
prepare_poll(بنية pollfd **pfdp, سائيز_t *npfdp, بنية timespec *timeoutp, u_int maxfds)
{
	بنية pollfd *pfd = *pfdp;
	سائيز_t i, j, npfd = 0;
	time_t deadline;
	صحيح r;

	/* Count active sockets */
	لكل (i = 0; i < sockets_alloc; i++) {
		بدل (sockets[i].type) {
		حالة AUTH_SOCKET:
		حالة AUTH_CONNECTION:
			npfd++;
			اكسر;
		حالة AUTH_اڻ_استعمال_ٿيل:
			اكسر;
		افتراضي:
			fatal("Unknown socket type %d", sockets[i].type);
			اكسر;
		}
	}
	إذا (npfd != *npfdp &&
	    (pfd = recallocarray(pfd, *npfdp, npfd, حجم(*pfd))) == عدم)
		fatal_f("recallocarray failed");
	*pfdp = pfd;
	*npfdp = npfd;

	لكل (i = j = 0; i < sockets_alloc; i++) {
		بدل (sockets[i].type) {
		حالة AUTH_SOCKET:
			إذا (npfd > maxfds) {
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
			إذا ((r = sshbuf_check_reserve(sockets[i].داخلا_2,
			    AGENT_RBUF_LEN)) == 0 &&
			    (r = sshbuf_check_reserve(sockets[i].output,
			    AGENT_MAX_LEN)) == 0)
				pfd[j].events = POLLIN;
			وإلا إذا (r != SSH_ERR_NO_بفر_SPACE)
				fatal_fr(r, "reserve");
			إذا (sshbuf_len(sockets[i].output) > 0)
				pfd[j].events |= POLLOUT;
			j++;
			اكسر;
		افتراضي:
			اكسر;
		}
	}
	deadline = reaper();
	إذا (والد_alive_interval != 0)
		deadline = (deadline == 0) ? والد_alive_interval :
		    MINIMUM(deadline, والد_alive_interval);
	إذا (deadline != 0)
		ptimeout_deadline_sec(timeoutp, deadline);
	أرجع (1);
}

ساكن فراغ
cleanup_socket(فراغ)
{
	إذا (cleanup_pid != 0 && getpid() != cleanup_pid)
		أرجع;
	debug_f("cleanup");
	إذا (socket_name != عدم) {
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
#جيڪڏهن_وصف_ٿيل ENABLE_PKCS11
	pkcs11_terminate();
#جيڪڏهن_پورو
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
check_والد_exists(فراغ)
{
	/*
	 * If our parent has exited then getppid() will return (pid_t)1,
	 * so testing for that should be safe.
	 */
	إذا (والد_pid != -1 && getppid() != والد_pid) {
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
	ٻاهر_نڪرو(1);
}

صحيح
مکيه(صحيح ac, حرف **av)
{
	صحيح c_flag = 0, d_flag = 0, D_flag = 0, k_flag = 0;
	صحيح s_flag = 0, T_flag = 0, u_flag = 0, U_flag = 0;
	صحيح sock = -1, ch, نتيجو, saved_errno;
	pid_t pid;
 	حرف *homedir = عدم, *shell, *format, *pidstr, *agentsocket = عدم;
	حرف *cp, pidstrbuf[1 + 3 * حجم pid];
	حرف *fdstr;
	ثابت حرف *errstr = عدم;
	ثابت حرف *ccp;
#جيڪڏهن_وصف_ٿيل HAVE_SETRLIMIT
	بنية rlimit rlim;
#جيڪڏهن_پورو
	خارجي صحيح optind;
	خارجي حرف *optarg;
	سائيز_t len;
	گهڻائي_t prev_نقاب;
	بنية timespec timeout;
	بنية pollfd *pfd = عدم;
	سائيز_t npfd = 0;
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

	إذا ((pw = getpwuid(getuid())) == عدم)
		fatal("No user exists for uid %lu", (u_long)getuid());
	pw = pwcopy(pw);

#جيڪڏهن_وصف_ٿيل RLIMIT_NOFILE
	إذا (getrlimit(RLIMIT_NOFILE, &rlim) == -1)
		fatal("%s: getrlimit: %s", __progname, strerror(errno));
#جيڪڏهن_پورو

	__progname = ssh_get_progname(av[0]);
	ٻج_rng();

	طالما ((ch = getopt(ac, av, "cDdksTuUVA:E:a:O:P:t:")) != -1) {
		بدل (ch) {
		حالة 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			إذا (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			اكسر;
		حالة 'c':
			إذا (s_flag)
				usage();
			c_flag++;
			اكسر;
		حالة 'k':
			k_flag++;
			اكسر;
		حالة 'O':
			إذا (strcmp(optarg, "no-restrict-websafe") == 0)
				restrict_websafe = 0;
			وإلا إذا (strcmp(optarg, "allow-remote-pkcs11") == 0)
				remote_جوڙيو_provider = 1;
			وإلا إذا ((ccp = strprefix(optarg,
			    "websafe-allow=", 0)) != عدم) {
				إذا (websafe_allowlist != عدم)
					fatal("websafe-allow already set");
				websafe_allowlist = xstrdup(ccp);
			} وإلا
				fatal("Unknown -O option");
			اكسر;
		حالة 'P':
			إذا (allowed_providers != عدم)
				fatal("-P option already specified");
			allowed_providers = xstrdup(optarg);
			اكسر;
		حالة 's':
			إذا (c_flag)
				usage();
			s_flag++;
			اكسر;
		حالة 'd':
			إذا (d_flag || D_flag)
				usage();
			d_flag++;
			اكسر;
		حالة 'D':
			إذا (d_flag || D_flag)
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
			إذا ((lifetime = convtime(optarg)) == -1) {
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
			    SSH_نسخو, SSH_OPENSSL_نسخو);
			ٻاهر_نڪرو(0);
		افتراضي:
			usage();
		}
	}
	ac -= optind;
	av += optind;

	إذا (ac > 0 &&
	    (c_flag || k_flag || s_flag || d_flag || D_flag || u_flag))
		usage();
	/* only one of -a, -A and -T allowed */
	إذا (((socket_dirspec != عدم) + (agentsocket != عدم) + T_flag) > 1)
		usage();

	log_init(__progname,
	    d_flag ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
	    SYSLOG_FACILITY_AUTH, 1);

	إذا (allowed_providers == عدم)
		allowed_providers = xstrdup(DEFAULT_ALLOWED_PROVIDERS);
	إذا (websafe_allowlist == عدم)
		websafe_allowlist = xstrdup(DEFAULT_WEBSAFE_ALLOWLIST);

	إذا (T_flag)
		socket_dirspec = xstrdup(رستو_SSH_AGENT_SOCKET_TMPDIR);
	وإلا إذا (socket_dirspec == عدم && agentsocket == عدم)
		socket_dirspec = xstrdup(رستو_SSH_AGENT_SOCKET_DIR);

	إذا (ac == 0 && !c_flag && !s_flag) {
		shell = getenv("SHELL");
		إذا (shell != عدم && (len = لڙي_ڊيگهه(shell)) > 2 &&
		    لڙي_ڀيٽ(shell + len - 3, "csh", 3) == 0)
			c_flag = 1;
	}
	إذا (k_flag) {
		pidstr = getenv(SSH_AGENTPID_ENV_NAME);
		إذا (pidstr == عدم) {
			fprintf(stderr, "%s not set, cannot kill agent\n",
			    SSH_AGENTPID_ENV_NAME);
			ٻاهر_نڪرو(1);
		}
		pid = (صحيح)strtonum(pidstr, 2, وڌ_کان_وڌ_عدد, &errstr);
		إذا (errstr) {
			fprintf(stderr,
			    "%s=\"%s\", which is not a good PID: %s\n",
			    SSH_AGENTPID_ENV_NAME, pidstr, errstr);
			ٻاهر_نڪرو(1);
		}
		إذا (kill(pid, SIGTERM) == -1) {
			perror("kill");
			ٻاهر_نڪرو(1);
		}
		format = c_flag ? "unsetenv %s;\n" : "unset %s;\n";
		لکو(format, SSH_AUTHSOCKET_ENV_NAME);
		لکو(format, SSH_AGENTPID_ENV_NAME);
		لکو("echo Agent pid %ld killed;\n", (ڊگهو)pid);
		ٻاهر_نڪرو(0);
	}
	إذا (u_flag) {
		إذا ((homedir = get_homedir()) == عدم)
			fatal("Couldn't determine home directory");
		agent_cleanup_stale(socket_dirspec,
		    pw->pw_name, pw->pw_uid, homedir, u_flag > 1);
		لکو("Deleted stale agent sockets in ~/%s\n",
		    رستو_SSH_AGENT_SOCKET_DIR);
		ٻاهر_نڪرو(0);
	}

	/*
	 * Minimum file descriptors:
	 * stdio (3) + listener (1) + syslog (1 maybe) + connection (1) +
	 * a few spare for libc / stack protectors / sanitisers, etc.
	 */
#وصف_ڪريو SSH_AGENT_MIN_FDS (3+1+1+1+4)
	إذا (rlim.rlim_cur < SSH_AGENT_MIN_FDS)
		fatal("%s: file descriptor rlimit %lld too low (minimum %u)",
		    __progname, (ڊگهو ڊگهو)rlim.rlim_cur, SSH_AGENT_MIN_FDS);
	maxfds = rlim.rlim_cur - SSH_AGENT_MIN_FDS;

	والد_pid = getpid();

	/* Has the socket been provided via socket activation? */
	إذا (agentsocket == عدم && ac == 0 && (d_flag || D_flag) &&
	    (pidstr = getenv("LISTEN_PID")) != عدم &&
	    (fdstr = getenv("LISTEN_FDS")) != عدم) {
		إذا (strcmp(fdstr, "1") != 0) {
			fatal("unexpected LISTEN_FDS contents "
			    "(want: \"1\" got\"%s\"", fdstr);
		}
		إذا (fcntl(3, F_GETFL) == -1)
			fatal("LISTEN_FDS set but fd 3 unavailable");
		pid = (صحيح)strtonum(pidstr, 1, وڌ_کان_وڌ_عدد, &errstr);
		إذا (errstr != عدم)
			fatal("invalid LISTEN_PID: %s", errstr);
		إذا (pid != getpid())
			fatal("bad LISTEN_PID: %d vs pid %d", pid, getpid());
		debug("using socket activation on fd=3");
		sock = 3;
		socket_activated = 1;
	}

	إذا (sock == -1 && agentsocket == عدم) {
		/* Listen on a socket in/under a given directory */
		إذا ((homedir = get_homedir()) == عدم)
			fatal("Couldn't determine home directory");
		إذا (!U_flag) {
			agent_cleanup_stale(socket_dirspec,
			    pw->pw_name, pw->pw_uid, homedir, 0);
		}
		إذا (agent_listener(socket_dirspec, pw->pw_name, pw->pw_uid,
		    homedir, getpid(), "local", &sock, &socket_name,
		    &socket_dir) != 0)
			fatal_f("Couldn't prepare agent socket");
		حرر(homedir);
	} وإلا إذا (sock == -1) {
		/* Listen on explicit socket path */
		prev_نقاب = umask(0177);
		socket_name = xstrdup(agentsocket);
		إذا ((sock = unix_listener(socket_name,
		    SSH_LISTEN_BACKLOG, 0)) < 0) {
			حرر(socket_name);
			socket_name = عدم; /* Don't unlink existing file */
			cleanup_exit(1);
		}
		umask(prev_نقاب);
	}

	closefrom(sock == -1 ? STDERR_FILENO + 1 : sock + 1);

	/*
	 * Create socket early so it will exist before command gets run from
	 * the parent.
	 */
	إذا (sock == -1) {
		prev_نقاب = umask(0177);
		sock = unix_listener(socket_name, SSH_LISTEN_BACKLOG, 0);
		إذا (sock < 0) {
			/* XXX - unix_listener() calls error() not perror() */
			*socket_name = '\0'; /* Don't unlink existing file */
			cleanup_exit(1);
		}
		umask(prev_نقاب);
	}

	/*
	 * Fork, and have the parent execute the command, if any, or present
	 * the socket data.  The child continues as the authentication agent.
	 */
	إذا (D_flag || d_flag) {
		log_init(__progname,
		    d_flag ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
		    SYSLOG_FACILITY_AUTH, 1);
		إذا (socket_name != عدم) {
			cp = argv_assemble(1, &socket_name);
			format = c_flag ?
			    "setenv %s %s;\n" : "%s=%s; export %s;\n";
			لکو(format, SSH_AUTHSOCKET_ENV_NAME, cp,
			    SSH_AUTHSOCKET_ENV_NAME);
			حرر(cp);
			لکو("echo Agent pid %ld;\n", (ڊگهو)والد_pid);
			fflush(stdout);
		}
		اذهب skip;
	}
	pid = fork();
	إذا (pid == -1) {
		perror("fork");
		cleanup_exit(1);
	}
	إذا (pid != 0) {		/* Parent - execute the given command. */
		close(sock);
		snprintf(pidstrbuf, حجم pidstrbuf, "%ld", (ڊگهو)pid);
		إذا (ac == 0) {
			format = c_flag ? "setenv %s %s;\n" : "%s=%s; export %s;\n";
			cp = argv_assemble(1, &socket_name);
			لکو(format, SSH_AUTHSOCKET_ENV_NAME, cp,
			    SSH_AUTHSOCKET_ENV_NAME);
			لکو(format, SSH_AGENTPID_ENV_NAME, pidstrbuf,
			    SSH_AGENTPID_ENV_NAME);
			حرر(cp);
			لکو("echo Agent pid %ld;\n", (ڊگهو)pid);
			ٻاهر_نڪرو(0);
		}
		إذا (setenv(SSH_AUTHSOCKET_ENV_NAME, socket_name, 1) == -1 ||
		    setenv(SSH_AGENTPID_ENV_NAME, pidstrbuf, 1) == -1) {
			perror("setenv");
			ٻاهر_نڪرو(1);
		}
		execvp(av[0], av);
		perror(av[0]);
		ٻاهر_نڪرو(1);
	}
	/*ٻار*/
	log_init(__progname, SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_AUTH, 0);

	إذا (setsid() == -1) {
		error("setsid: %s", strerror(errno));
		cleanup_exit(1);
	}

	(فراغ)chdir("/");
	إذا (stdfd_devnull(1, 1, 1) == -1)
		error_f("stdfd_devnull failed");

#جيڪڏهن_وصف_ٿيل HAVE_SETRLIMIT
	/* deny core dumps, since memory contains unencrypted private keys */
	rlim.rlim_cur = rlim.rlim_max = 0;
	إذا (setrlimit(RLIMIT_CORE, &rlim) == -1) {
		error("setrlimit RLIMIT_CORE: %s", strerror(errno));
		cleanup_exit(1);
	}
#جيڪڏهن_پورو

skip:

	cleanup_pid = getpid();

#جيڪڏهن_وصف_ٿيل ENABLE_PKCS11
	pkcs11_init(0);
#جيڪڏهن_پورو
	new_socket(AUTH_SOCKET, sock);
	إذا (ac > 0)
		والد_alive_interval = 10;
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

	إذا (socket_name != عدم && unveil(socket_name, "c") == -1) {
		fatal("%s: unveil %s %s", __progname, socket_name,
		    strerror(errno));
	}
	إذا (socket_dir != عدم && unveil(socket_dir, "c") == -1) {
		fatal("%s: unveil %s %s", __progname, socket_dir,
		    strerror(errno));
	}
	إذا (unveil("/", "r") == -1)
		fatal("%s: unveil /: %s", __progname, strerror(errno));
	إذا ((ccp = getenv("SSH_SK_HELPER")) == عدم || *ccp == '\0')
		ccp = رستو_SSH_SK_HELPER;
	إذا (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, strerror(errno));
	إذا ((ccp = getenv("SSH_PKCS11_HELPER")) == عدم || *ccp == '\0')
		ccp = رستو_SSH_PKCS11_HELPER;
	إذا (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, strerror(errno));
	إذا ((ccp = getenv("SSH_ASKPASS")) == عدم || *ccp == '\0')
		ccp = رستو_SSH_ASKPASS_DEFAULT;
	إذا (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, strerror(errno));
	إذا (unveil("/dev/null", "rw") == -1)
		fatal("%s: unveil /dev/null: %s", __progname, strerror(errno));
	إذا (pledge("stdio rpath cpath wpath unix id proc exec", عدم) == -1)
		fatal("%s: pledge: %s", __progname, strerror(errno));
	platform_pledge_agent();

	طالما (1) {
		sigprocmask(SIG_BLOCK, &nsigset, &osigset);
		إذا (signalled_exit != 0) {
			logit("exiting on signal %d", (صحيح)signalled_exit);
			cleanup_exit((signalled_exit == SIGTERM &&
			    socket_activated) ? 0 : 2);
		}
		إذا (signalled_keydrop) {
			logit("signal %d received; removing all keys",
			    (صحيح)signalled_keydrop);
			remove_all_identities();
			signalled_keydrop = 0;
		}
		ptimeout_init(&timeout);
		prepare_poll(&pfd, &npfd, &timeout, maxfds);
		نتيجو = ppoll(pfd, npfd, ptimeout_get_tsp(&timeout), &osigset);
		sigprocmask(SIG_SETMASK, &osigset, عدم);
		saved_errno = errno;
		إذا (والد_alive_interval != 0)
			check_والد_exists();
		(فراغ) reaper();	/* remove expired keys */
		إذا (نتيجو == -1) {
			إذا (saved_errno == EINTR)
				استمر;
			fatal("poll: %s", strerror(saved_errno));
		} وإلا إذا (نتيجو > 0)
			after_poll(pfd, npfd, maxfds);
	}
	/* NOTREACHED */
}
