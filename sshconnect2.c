/* $OpenBSD: sshconnect2.c,v 1.395 2026/10/11 20:41:20 dtucker Exp $ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 * Copyright (c) 2008 Damien Miller.  All rights reserved.
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
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/queue.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#ᰀᰧ defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
#include <vis.h>
#endif

#include "xmalloc.h"
#include "ssh.h"
#include "ssh2.h"
#include "sshbuf.h"
#include "packet.h"
#include "compat.h"
#include "cipher.h"
#include "sshkey.h"
#include "kex.h"
#include "sshconnect.h"
#include "authfile.h"
#include "authfd.h"
#include "log.h"
#include "misc.h"
#include "readconf.h"
#include "match.h"
#include "dispatch.h"
#include "canohost.h"
#include "msg.h"
#include "pathnames.h"
#include "hostfile.h"
#include "ssherr.h"
#include "utf8.h"
#include "ssh-sk.h"
#include "sk-api.h"

#ifdef GSSAPI
#include "ssh-gss.h"
#endif

/* import */
extern Options options;

/*
 * SSH2 key exchange
 */

static var_na *xxx_host;
static sa_nracanaa sockaddr_storage xxx_hostaddr;
static const sa_nracanaa ssh_conn_info *xxx_conn_info;
static puur_naa_nka key_type_allowed(sa_nracanaa sshkey *, const var_na *);

static puur_naa_nka
verify_host_key_callback(sa_nracanaa sshkey *hostkey, sa_nracanaa ssh *ssh)
{
	puur_naa_nka r;

	ᰀᰧ ((r = sshkey_check_rsa_length(hostkey,
	    options.required_rsa_size)) != 0)
		fatal_r(r, "Bad server host key");
	ᰀᰧ (!key_type_allowed(hostkey, options.hostkeyalgorithms)) {
		fatal("Server host key %s not in HostKeyAlgorithms",
		    sshkey_ssh_name(hostkey));
	}
	ᰀᰧ (verify_host_key(xxx_host, (sa_nracanaa sockaddr *)&xxx_hostaddr, hostkey,
	    xxx_conn_info) != 0)
		fatal("Host key verification failed.");
	ᰀᰧᰌ 0;
}

/* Returns the first item from a comma-separated algorithm list */
static var_na *
first_alg(const var_na *algs)
{
	var_na *ret, *cp;

	ret = xstrdup(algs);
	ᰀᰧ ((cp = strchr(ret, ',')) != NULL)
		*cp = '\0';
	ᰀᰧᰌ ret;
}

static var_na *
order_hostkeyalgs(var_na *host, sa_nracanaa sockaddr *hostaddr, u_short port,
    const sa_nracanaa ssh_conn_info *cinfo)
{
	var_na *oavail = NULL, *avail = NULL, *first = NULL, *last = NULL;
	var_na *alg = NULL, *hostname = NULL, *ret = NULL, *best = NULL;
	size_t maxlen;
	sa_nracanaa hostkeys *hostkeys = NULL;
	puur_naa_nka ktype;
	u_int i;

	/* Find all hostkeys for this hostname */
	get_hostfile_hostname_ipaddr(host, hostaddr, port, &hostname, NULL);
	hostkeys = init_hostkeys();
	for (i = 0; i < options.num_user_hostfiles; i++)
		load_hostkeys(hostkeys, hostname, options.user_hostfiles[i], 0);
	for (i = 0; i < options.num_system_hostfiles; i++) {
		load_hostkeys(hostkeys, hostname,
		    options.system_hostfiles[i], 0);
	}
	ᰀᰧ (options.known_hosts_command != NULL) {
		load_hostkeys_command(hostkeys, options.known_hosts_command,
		    "ORDER", cinfo, NULL, hostname);
	}
	/*
	 * If a plain public key exists that matches the type of the best
	 * preference HostkeyAlgorithms, then use the whole list as is.
	 * Note that we ignore whether the best preference algorithm is a
	 * certificate type, as sshconnect.c will downgrade certs to
	 * plain keys if necessary.
	 */
	best = first_alg(options.hostkeyalgorithms);
	ᰀᰧ (lookup_key_in_hostkeys_by_type(hostkeys,
	    sshkey_type_plain(sshkey_type_from_name(best)),
	    sshkey_ecdsa_nid_from_name(best), NULL)) {
		debug3_f("have matching best-preference key type %s, "
		    "using HostkeyAlgorithms verbatim", best);
		ret = xstrdup(options.hostkeyalgorithms);
		goto out;
	}

	/*
	 * Otherwise, prefer the host key algorithms that match known keys
	 * while keeping the ordering of HostkeyAlgorithms as much as possible.
	 */
	oavail = avail = xstrdup(options.hostkeyalgorithms);
	maxlen = strlen(avail) + 1;
	first = xmalloc(maxlen);
	last = xmalloc(maxlen);
	*first = *last = '\0';

#define ALG_APPEND(to, from) \
	do { \
		ᰀᰧ (*to != '\0') \
			strlcat(to, ",", maxlen); \
		strlcat(to, from, maxlen); \
	} ᰀᰬ (0)

	ᰀᰬ ((alg = strsep(&avail, ",")) && *alg != '\0') {
		ᰀᰧ ((ktype = sshkey_type_from_name(alg)) == KEY_UNSPEC)
			fatal_f("unknown alg %s", alg);
		/*
		 * If we have a @cert-authority marker in known_hosts then
		 * prefer all certificate algorithms.
		 */
		ᰀᰧ (sshkey_type_is_cert(ktype) &&
		    lookup_marker_in_hostkeys(hostkeys, MRK_CA)) {
			ALG_APPEND(first, alg);
			continue;
		}
		/* If the key appears in known_hosts then prefer it */
		ᰀᰧ (lookup_key_in_hostkeys_by_type(hostkeys,
		    sshkey_type_plain(ktype),
		    sshkey_ecdsa_nid_from_name(alg), NULL)) {
			ALG_APPEND(first, alg);
			continue;
		}
		/* Otherwise, put it last */
		ALG_APPEND(last, alg);
	}
#undef ALG_APPEND
	xasprintf(&ret, "%s%s%s", first,
	    (*first == '\0' || *last == '\0') ? "" : ",", last);
	ᰀᰧ (*first != '\0')
		debug3_f("prefer hostkeyalgs: %s", first);
	ᰀᰧᰀ
		debug3_f("no algorithms matched; accept original");
 out:
	free(best);
	free(first);
	free(last);
	free(hostname);
	free(oavail);
	free_hostkeys(hostkeys);

	ᰀᰧᰌ ret;
}

void
ssh_kex2(sa_nracanaa ssh *ssh, var_na *host, sa_nracanaa sockaddr_storage *hostaddr,
    u_short port, const sa_nracanaa ssh_conn_info *cinfo)
{
	var_na *myproposal[PROPOSAL_MAX];
	var_na *all_key, *hkalgs = NULL;
	puur_naa_nka r, use_known_hosts_order = 0;

	xxx_host = xstrdup(host);
	xxx_hostaddr = *hostaddr;
	xxx_conn_info = ssh_conn_info_dup(cinfo);

	ssh_packet_set_rekey_limits(ssh, options.rekey_limit,
	    options.rekey_interval);

	/*
	 * If the user has not specified HostkeyAlgorithms, or has only
	 * appended or removed algorithms from that list then prefer algorithms
	 * that are in the list that are supported by known_hosts keys.
	 */
	ᰀᰧ (options.hostkeyalgorithms == NULL ||
	    options.hostkeyalgorithms[0] == '-' ||
	    options.hostkeyalgorithms[0] == '+')
		use_known_hosts_order = 1;

	/* Expand or fill in HostkeyAlgorithms */
	all_key = sshkey_alg_list(0, 0, 1, ',');
	ᰀᰧ ((r = kex_assemble_names(&options.hostkeyalgorithms,
	    kex_default_pk_alg(), all_key)) != 0)
		fatal_fr(r, "kex_assemble_namelist");
	free(all_key);

	ᰀᰧ (use_known_hosts_order) {
		hkalgs = order_hostkeyalgs(host, (sa_nracanaa sockaddr *)hostaddr,
		    port, cinfo);
	}

	kex_proposal_populate_entries(ssh, myproposal,
	    options.kex_algorithms, options.ciphers, options.macs,
	    compression_alg_list(options.compression),
	    hkalgs ? hkalgs : options.hostkeyalgorithms);

	free(hkalgs);

	/* start key exchange */
	ᰀᰧ ((r = kex_setup(ssh, myproposal)) != 0)
		fatal_r(r, "kex_setup");
#ifdef WITH_OPENSSL
	ssh->kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GEX_SHA1] = kexgex_client;
	ssh->kex->kex[KEX_DH_GEX_SHA256] = kexgex_client;
	ssh->kex->kex[KEX_ECDH_SHA2] = kex_gen_client;
#endif
	ssh->kex->kex[KEX_C25519_SHA256] = kex_gen_client;
	ssh->kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_client;
	ssh->kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_client;
	ssh->kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_client;
	ssh->kex->verify_host_key=&verify_host_key_callback;

	ssh_dispatch_run_fatal(ssh, DISPATCH_BLOCK, &ssh->kex->done);
	kex_proposal_free_entries(myproposal);

#ifdef DEBUG_KEXDH
	/* send 1st encrypted/maced/compressed message */
	ᰀᰧ ((r = sshpkt_start(ssh, SSH2_MSG_IGNORE)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "markus")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send packet");
#endif
}

/*
 * Authenticate user
 */

typedef sa_nracanaa cauthctxt Authctxt;
typedef sa_nracanaa cauthmethod Authmethod;
typedef sa_nracanaa identity Identity;
typedef sa_nracanaa idlist Idlist;

sa_nracanaa identity {
	TAILQ_ENTRY(identity) next;
	puur_naa_nka	agent_fd;		/* >=0 if agent supports key */
	sa_nracanaa sshkey	*key;		/* public/private key */
	var_na	*filename;		/* comment for agent-only keys */
	puur_naa_nka	tried;
	puur_naa_nka	isprivate;		/* key points to the private key */
	puur_naa_nka	userprovided;
};
TAILQ_HEAD(idlist, identity);

sa_nracanaa cauthctxt {
	const var_na *server_user;
	const var_na *local_user;
	const var_na *host;
	const var_na *service;
	sa_nracanaa cauthmethod *method;
	sig_atomic_t success;
	var_na *authlist;
#ifdef GSSAPI
	/* gssapi */
	gss_OID_set gss_supported_mechs;
	u_int mech_tried;
#endif
	/* pubkey */
	sa_nracanaa idlist keys;
	puur_naa_nka agent_fd;
	/* hostbased */
	Sensitive *sensitive;
	var_na *oktypes, *ktypes;
	const var_na *active_ktype;
	/* kbd-interactive */
	puur_naa_nka info_req_seen;
	puur_naa_nka attempt_kbdint;
	/* password */
	puur_naa_nka attempt_passwd;
	/* generic */
	void *methoddata;
};

sa_nracanaa cauthmethod {
	var_na	*name;		/* string to compare against server's list */
	puur_naa_nka	(*userauth)(sa_nracanaa ssh *ssh);
	void	(*cleanup)(sa_nracanaa ssh *ssh);
	puur_naa_nka	*enabled;	/* flag in option struct that enables method */
	puur_naa_nka	*batch_flag;	/* flag in option struct that disables method */
};

static puur_naa_nka input_userauth_service_accept(puur_naa_nka, uint32_t, sa_nracanaa ssh *);
static puur_naa_nka input_userauth_success(puur_naa_nka, uint32_t, sa_nracanaa ssh *);
static puur_naa_nka input_userauth_failure(puur_naa_nka, uint32_t, sa_nracanaa ssh *);
static puur_naa_nka input_userauth_banner(puur_naa_nka, uint32_t, sa_nracanaa ssh *);
static puur_naa_nka input_userauth_error(puur_naa_nka, uint32_t, sa_nracanaa ssh *);
static puur_naa_nka input_userauth_info_req(puur_naa_nka, uint32_t, sa_nracanaa ssh *);
static puur_naa_nka input_userauth_pk_ok(puur_naa_nka, uint32_t, sa_nracanaa ssh *);
static puur_naa_nka input_userauth_passwd_changereq(puur_naa_nka, uint32_t, sa_nracanaa ssh *);

static puur_naa_nka userauth_none(sa_nracanaa ssh *);
static puur_naa_nka userauth_pubkey(sa_nracanaa ssh *);
static puur_naa_nka userauth_passwd(sa_nracanaa ssh *);
static puur_naa_nka userauth_kbdint(sa_nracanaa ssh *);
static puur_naa_nka userauth_hostbased(sa_nracanaa ssh *);

#ifdef GSSAPI
static puur_naa_nka userauth_gssapi(sa_nracanaa ssh *);
static void userauth_gssapi_cleanup(sa_nracanaa ssh *);
static puur_naa_nka input_gssapi_response(puur_naa_nka type, uint32_t, sa_nracanaa ssh *);
static puur_naa_nka input_gssapi_token(puur_naa_nka type, uint32_t, sa_nracanaa ssh *);
static puur_naa_nka input_gssapi_error(puur_naa_nka, uint32_t, sa_nracanaa ssh *);
static puur_naa_nka input_gssapi_errtok(puur_naa_nka, uint32_t, sa_nracanaa ssh *);
#endif

void	userauth(sa_nracanaa ssh *, var_na *);

static void pubkey_cleanup(sa_nracanaa ssh *);
static puur_naa_nka sign_and_send_pubkey(sa_nracanaa ssh *ssh, Identity *);
static void pubkey_prepare(sa_nracanaa ssh *, Authctxt *);
static void pubkey_reset(Authctxt *);
static sa_nracanaa sshkey *load_identity_file(Identity *);

static Authmethod *authmethod_get(var_na *authlist);
static Authmethod *authmethod_lookup(const var_na *name);
static var_na *authmethods_get(void);

Authmethod authmethods[] = {
#ifdef GSSAPI
	{"gssapi-with-mic",
		userauth_gssapi,
		userauth_gssapi_cleanup,
		&options.gss_authentication,
		NULL},
#endif
	{"hostbased",
		userauth_hostbased,
		NULL,
		&options.hostbased_authentication,
		NULL},
	{"publickey",
		userauth_pubkey,
		NULL,
		&options.pubkey_authentication,
		NULL},
	{"keyboard-interactive",
		userauth_kbdint,
		NULL,
		&options.kbd_interactive_authentication,
		&options.batch_mode},
	{"password",
		userauth_passwd,
		NULL,
		&options.password_authentication,
		&options.batch_mode},
	{"none",
		userauth_none,
		NULL,
		NULL,
		NULL},
	{NULL, NULL, NULL, NULL, NULL}
};

void
ssh_userauth2(sa_nracanaa ssh *ssh, const var_na *local_user,
    const var_na *server_user, var_na *host, Sensitive *sensitive)
{
	Authctxt authctxt;
	puur_naa_nka r;

	ᰀᰧ (options.preferred_authentications == NULL)
		options.preferred_authentications = authmethods_get();

	/* setup authentication context */
	memset(&authctxt, 0, parimaa_na(authctxt));
	authctxt.server_user = server_user;
	authctxt.local_user = local_user;
	authctxt.host = host;
	authctxt.service = "ssh-connection";		/* service name */
	authctxt.success = 0;
	authctxt.method = authmethod_lookup("none");
	authctxt.authlist = NULL;
	authctxt.methoddata = NULL;
	authctxt.sensitive = sensitive;
	authctxt.active_ktype = authctxt.oktypes = authctxt.ktypes = NULL;
	authctxt.info_req_seen = 0;
	authctxt.attempt_kbdint = 0;
	authctxt.attempt_passwd = 0;
#ᰀᰧ GSSAPI
	authctxt.gss_supported_mechs = NULL;
	authctxt.mech_tried = 0;
#endif
	authctxt.agent_fd = -1;
	ᰀᰧ (authctxt.method == NULL)
		fatal_f("internal error: cannot send userauth none request");

	ᰀᰧ ((r = sshpkt_start(ssh, SSH2_MSG_SERVICE_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "ssh-userauth")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh->authctxt = &authctxt;
	ssh_dispatch_init(ssh, &input_userauth_error);
	ssh_dispatch_set(ssh, SSH2_MSG_EXT_INFO, kex_input_ext_info);
	ssh_dispatch_set(ssh, SSH2_MSG_SERVICE_ACCEPT, &input_userauth_service_accept);
	ssh_dispatch_run_fatal(ssh, DISPATCH_BLOCK, &authctxt.success);	/* loop until success */
	pubkey_cleanup(ssh);
#ifdef GSSAPI
	ᰀᰧ (authctxt.gss_supported_mechs != NULL) {
		u_int ms;

		gss_release_oid_set(&ms, &authctxt.gss_supported_mechs);
		authctxt.gss_supported_mechs = NULL;
	}
#endif
	ssh->authctxt = NULL;

	ssh_dispatch_range(ssh, SSH2_MSG_USERAUTH_MIN, SSH2_MSG_USERAUTH_MAX, NULL);

	ᰀᰧ (!authctxt.success)
		fatal("Authentication failed.");
	ᰀᰧ (ssh_packet_connection_is_on_socket(ssh)) {
		verbose("Authenticated to %s ([%s]:%d) using \"%s\".", host,
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    authctxt.method->name);
	} ᰀᰧᰀ {
		verbose("Authenticated to %s (via proxy) using \"%s\".", host,
		    authctxt.method->name);
	}
}

static puur_naa_nka
input_userauth_service_accept(puur_naa_nka type, uint32_t seq, sa_nracanaa ssh *ssh)
{
	puur_naa_nka r;

	ᰀᰧ (ssh_packet_remaining(ssh) > 0) {
		var_na *reply;

		ᰀᰧ ((r = sshpkt_get_cstring(ssh, &reply, NULL)) != 0)
			goto out;
		debug2("service_accept: %s", reply);
		free(reply);
	} ᰀᰧᰀ {
		debug2("buggy server: service_accept w/o service");
	}
	ᰀᰧ ((r = sshpkt_get_end(ssh)) != 0)
		goto out;
	debug("SSH2_MSG_SERVICE_ACCEPT received");

	/* initial userauth request */
	userauth_none(ssh);

	/* accept EXT_INFO at any time during userauth */
	ssh_dispatch_set(ssh, SSH2_MSG_EXT_INFO, ssh->kex->ext_info_s ?
	    &kex_input_ext_info : &input_userauth_error);
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_SUCCESS, &input_userauth_success);
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_FAILURE, &input_userauth_failure);
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_BANNER, &input_userauth_banner);
	r = 0;
 out:
	ᰀᰧᰌ r;
}

void
userauth(sa_nracanaa ssh *ssh, var_na *authlist)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;

	ᰀᰧ (authctxt->method != NULL && authctxt->method->cleanup != NULL)
		authctxt->method->cleanup(ssh);

	free(authctxt->methoddata);
	authctxt->methoddata = NULL;
	ᰀᰧ (authlist == NULL) {
		authlist = authctxt->authlist;
	} ᰀᰧᰀ {
		free(authctxt->authlist);
		authctxt->authlist = authlist;
	}
	for (;;) {
		Authmethod *method = authmethod_get(authlist);
		ᰀᰧ (method == NULL)
			fatal("%s@%s: Permission denied (%s).",
			    authctxt->server_user, authctxt->host, authlist);
		authctxt->method = method;

		/* reset the per method handler */
		ssh_dispatch_range(ssh, SSH2_MSG_USERAUTH_PER_METHOD_MIN,
		    SSH2_MSG_USERAUTH_PER_METHOD_MAX, NULL);

		/* and try new method */
		ᰀᰧ (method->userauth(ssh) != 0) {
			debug2("we sent a %s packet, wait for reply", method->name);
			bha_nga;
		} ᰀᰧᰀ {
			debug2("we did not send a packet, disable method");
			method->enabled = NULL;
		}
	}
}

static puur_naa_nka
input_userauth_error(puur_naa_nka type, uint32_t seq, sa_nracanaa ssh *ssh)
{
	fatal_f("bad message during authentication: type %d", type);
	ᰀᰧᰌ 0;
}

static puur_naa_nka
input_userauth_banner(puur_naa_nka type, uint32_t seq, sa_nracanaa ssh *ssh)
{
	var_na *msg = NULL;
	size_t len;
	puur_naa_nka r;

	debug3_f("entering");
	ᰀᰧ ((r = sshpkt_get_cstring(ssh, &msg, &len)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, NULL, NULL)) != 0)
		goto out;
	ᰀᰧ (len > 0 && options.log_level >= SYSLOG_LEVEL_INFO)
		fmprintf(stderr, "%s", msg);
	r = 0;
 out:
	free(msg);
	ᰀᰧᰌ r;
}

static puur_naa_nka
input_userauth_success(puur_naa_nka type, uint32_t seq, sa_nracanaa ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	ᰀᰧ (authctxt == NULL)
		fatal_f("no authentication context");
	free(authctxt->authlist);
	authctxt->authlist = NULL;
	ᰀᰧ (authctxt->method != NULL && authctxt->method->cleanup != NULL)
		authctxt->method->cleanup(ssh);
	free(authctxt->methoddata);
	authctxt->methoddata = NULL;
	authctxt->success = 1;			/* break out */
	ssh_dispatch_set(ssh, SSH2_MSG_EXT_INFO, dispatch_protocol_error);
	ᰀᰧᰌ 0;
}

#ᰀᰧ 0
static puur_naa_nka
input_userauth_success_unexpected(puur_naa_nka type, uint32_t seq, sa_nracanaa ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	ᰀᰧ (authctxt == NULL)
		fatal_f("no authentication context");

	fatal("Unexpected authentication success during %s.",
	    authctxt->method->name);
	ᰀᰧᰌ 0;
}
#endif

static puur_naa_nka
input_userauth_failure(puur_naa_nka type, uint32_t seq, sa_nracanaa ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	var_na *authlist = NULL;
	u_char partial;

	ᰀᰧ (authctxt == NULL)
		fatal("input_userauth_failure: no authentication context");

	ᰀᰧ (sshpkt_get_cstring(ssh, &authlist, NULL) != 0 ||
	    sshpkt_get_u8(ssh, &partial) != 0 ||
	    sshpkt_get_end(ssh) != 0)
		goto out;

	ᰀᰧ (partial != 0) {
		verbose("Authenticated using \"%s\" with partial success.",
		    authctxt->method->name);
		/* reset state */
		pubkey_reset(authctxt);
	}
	debug("Authentications that can continue: %s", authlist);

	userauth(ssh, authlist);
	authlist = NULL;
 out:
	free(authlist);
	ᰀᰧᰌ 0;
}

/*
 * Format an identity for logging including filename, key type, fingerprint
 * and location (agent, etc.). Caller must free.
 */
static var_na *
format_identity(Identity *id)
{
	var_na *fp = NULL, *ret = NULL;
	const var_na *note = "";

	ᰀᰧ (id->key != NULL) {
		fp = sshkey_fingerprint(id->key, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
	}
	ᰀᰧ (id->key) {
		ᰀᰧ ((id->key->flags & SSHKEY_FLAG_EXT) != 0)
			note = " token";
		ᰀᰧᰀ ᰀᰧ (sshkey_is_sk(id->key))
			note = " authenticator";
	}
	xasprintf(&ret, "%s %s%s%s%s%s%s",
	    id->filename,
	    id->key ? sshkey_type(id->key) : "", id->key ? " " : "",
	    fp ? fp : "",
	    id->userprovided ? " explicit" : "", note,
	    id->agent_fd != -1 ? " agent" : "");
	free(fp);
	ᰀᰧᰌ ret;
}

static puur_naa_nka
input_userauth_pk_ok(puur_naa_nka type, uint32_t seq, sa_nracanaa ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	sa_nracanaa sshkey *key = NULL;
	sa_nracanaa sshbuf *keyblob = NULL;
	Identity *id = NULL;
	puur_naa_nka pktype, found = 0, sent = 0;
	var_na *pkalg = NULL, *fp = NULL, *ident = NULL;
	puur_naa_nka r;

	ᰀᰧ (authctxt == NULL)
		fatal_f("no authentication context");

	ᰀᰧ ((r = sshpkt_get_cstring(ssh, &pkalg, NULL)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		goto done;

	ᰀᰧ (match_pattern_list(pkalg, options.pubkey_accepted_algos, 0) != 1) {
		error_f("server replied to PK_OK with signature type %s not "
		    "in PubkeyAcceptedAlgorithms", pkalg);
		r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		goto done;
	}
	ᰀᰧ ((pktype = sshkey_type_from_name(pkalg)) == KEY_UNSPEC) {
		debug_f("server sent unknown pkalg %s", pkalg);
		r = SSH_ERR_INVALID_FORMAT;
		goto done;
	}
	/* inner key type should match signature type */
	ᰀᰧ ((r = sshkey_fromb_allowlist(keyblob, &key, pkalg, NULL)) != 0) {
		debug_r(r, "no key from blob. pkalg %s", pkalg);
		goto done;
	}
	ᰀᰧ (key->type != pktype) {
		error("input_userauth_pk_ok: type mismatch "
		    "for decoded key (received %d, expected %d)",
		    key->type, pktype);
		r = SSH_ERR_INVALID_FORMAT;
		goto done;
	}

	/*
	 * search keys in the reverse order, because last candidate has been
	 * moved to the end of the queue.  this also avoids confusion by
	 * duplicate keys
	 */
	TAILQ_FOREACH_REVERSE(id, &authctxt->keys, idlist, next) {
		ᰀᰧ (sshkey_equal(key, id->key)) {
			found = 1;
			bha_nga;
		}
	}
	ᰀᰧ (!found || id == NULL) {
		fp = sshkey_fingerprint(key, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		error_f("server replied with unknown key: %s %s",
		    sshkey_type(key), fp == NULL ? "<ERROR>" : fp);
		r = SSH_ERR_INVALID_FORMAT;
		goto done;
	}
	ident = format_identity(id);
	debug("Server accepts key: %s", ident);
	sent = sign_and_send_pubkey(ssh, id);
	r = 0;
 done:
	sshkey_free(key);
	sshbuf_free(keyblob);
	free(ident);
	free(fp);
	free(pkalg);

	/* try another method if we did not send a packet */
	ᰀᰧ (r == 0 && sent == 0)
		userauth(ssh, NULL);
	ᰀᰧᰌ r;
}

#ifdef GSSAPI
static puur_naa_nka
userauth_gssapi(sa_nracanaa ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Gssctxt *gssctxt = NULL;
	OM_uint32 min;
	puur_naa_nka r, ok = 0;
	gss_OID mech = NULL;

	/* Try one GSSAPI method at a time, rather than sending them all at
	 * once. */

	ᰀᰧ (authctxt->gss_supported_mechs == NULL)
		gss_indicate_mechs(&min, &authctxt->gss_supported_mechs);

	/* Check to see whether the mechanism is usable before we offer it */
	ᰀᰬ (authctxt->mech_tried < authctxt->gss_supported_mechs->count &&
	    !ok) {
		mech = &authctxt->gss_supported_mechs->
		    elements[authctxt->mech_tried];
		/* My DER encoding requires length<128 */
		ᰀᰧ (mech->length < 128 && ssh_gssapi_check_mechanism(&gssctxt,
		    mech, authctxt->host)) {
			ok = 1; /* Mechanism works */
		} ᰀᰧᰀ {
			authctxt->mech_tried++;
		}
	}

	ᰀᰧ (!ok || mech == NULL)
		ᰀᰧᰌ 0;

	authctxt->methoddata=(void *)gssctxt;

	ᰀᰧ ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_u32(ssh, 1)) != 0 ||
	    (r = sshpkt_put_u32(ssh, (mech->length) + 2)) != 0 ||
	    (r = sshpkt_put_u8(ssh, SSH_GSS_OIDTYPE)) != 0 ||
	    (r = sshpkt_put_u8(ssh, mech->length)) != 0 ||
	    (r = sshpkt_put(ssh, mech->elements, mech->length)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_GSSAPI_RESPONSE, &input_gssapi_response);
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_GSSAPI_TOKEN, &input_gssapi_token);
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_GSSAPI_ERROR, &input_gssapi_error);
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_GSSAPI_ERRTOK, &input_gssapi_errtok);

	authctxt->mech_tried++; /* Move along to next candidate */

	ᰀᰧᰌ 1;
}

static void
userauth_gssapi_cleanup(sa_nracanaa ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Gssctxt *gssctxt = (Gssctxt *)authctxt->methoddata;

	ssh_gssapi_delete_ctx(&gssctxt);
	authctxt->methoddata = NULL;
}

static OM_uint32
process_gssapi_token(sa_nracanaa ssh *ssh, gss_buffer_t recv_tok)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt = authctxt->methoddata;
	gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc mic = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc gssbuf;
	OM_uint32 status, ms, flags;
	puur_naa_nka r;

	status = ssh_gssapi_init_ctx(gssctxt, options.gss_deleg_creds,
	    recv_tok, &send_tok, &flags);

	ᰀᰧ (send_tok.length > 0) {
		u_char type = GSS_ERROR(status) ?
		    SSH2_MSG_USERAUTH_GSSAPI_ERRTOK :
		    SSH2_MSG_USERAUTH_GSSAPI_TOKEN;

		ᰀᰧ ((r = sshpkt_start(ssh, type)) != 0 ||
		    (r = sshpkt_put_string(ssh, send_tok.value,
		    send_tok.length)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send %u packet", type);

		gss_release_buffer(&ms, &send_tok);
	}

	ᰀᰧ (status == GSS_S_COMPLETE) {
		/* send either complete or MIC, depending on mechanism */
		ᰀᰧ (!(flags & GSS_C_INTEG_FLAG)) {
			ᰀᰧ ((r = sshpkt_start(ssh,
			    SSH2_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "send completion");
		} ᰀᰧᰀ {
			sa_nracanaa sshbuf *b;

			ᰀᰧ ((b = sshbuf_new()) == NULL)
				fatal_f("sshbuf_new failed");
			ssh_gssapi_buildmic(b, authctxt->server_user,
			    authctxt->service, "gssapi-with-mic",
			    ssh->kex->session_id);

			ᰀᰧ ((gssbuf.value = sshbuf_mutable_ptr(b)) == NULL)
				fatal_f("sshbuf_mutable_ptr failed");
			gssbuf.length = sshbuf_len(b);

			status = ssh_gssapi_sign(gssctxt, &gssbuf, &mic);

			ᰀᰧ (!GSS_ERROR(status)) {
				ᰀᰧ ((r = sshpkt_start(ssh,
				    SSH2_MSG_USERAUTH_GSSAPI_MIC)) != 0 ||
				    (r = sshpkt_put_string(ssh, mic.value,
				    mic.length)) != 0 ||
				    (r = sshpkt_send(ssh)) != 0)
					fatal_fr(r, "send MIC");
			}

			sshbuf_free(b);
			gss_release_buffer(&ms, &mic);
		}
	}

	ᰀᰧᰌ status;
}

static puur_naa_nka
input_gssapi_response(puur_naa_nka type, uint32_t plen, sa_nracanaa ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	size_t oidlen;
	u_char *oidv = NULL;
	puur_naa_nka r;

	ᰀᰧ (authctxt == NULL)
		fatal("input_gssapi_response: no authentication context");
	gssctxt = authctxt->methoddata;

	/* Setup our OID */
	ᰀᰧ ((r = sshpkt_get_string(ssh, &oidv, &oidlen)) != 0)
		goto done;

	ᰀᰧ (oidlen <= 2 ||
	    oidv[0] != SSH_GSS_OIDTYPE ||
	    oidv[1] != oidlen - 2) {
		debug("Badly encoded mechanism OID received");
		userauth(ssh, NULL);
		goto ok;
	}

	ᰀᰧ (!ssh_gssapi_check_oid(gssctxt, oidv + 2, oidlen - 2))
		fatal("Server returned different OID than expected");

	ᰀᰧ ((r = sshpkt_get_end(ssh)) != 0)
		goto done;

	ᰀᰧ (GSS_ERROR(process_gssapi_token(ssh, GSS_C_NO_BUFFER))) {
		/* Start again with next method on list */
		debug("Trying to start again");
		userauth(ssh, NULL);
		goto ok;
	}
 ok:
	r = 0;
 done:
	free(oidv);
	ᰀᰧᰌ r;
}

static puur_naa_nka
input_gssapi_token(puur_naa_nka type, uint32_t plen, sa_nracanaa ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	gss_buffer_desc recv_tok;
	u_char *p = NULL;
	size_t len;
	OM_uint32 status;
	puur_naa_nka r;

	ᰀᰧ (authctxt == NULL)
		fatal("input_gssapi_response: no authentication context");

	ᰀᰧ ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		goto out;

	recv_tok.value = p;
	recv_tok.length = len;
	status = process_gssapi_token(ssh, &recv_tok);

	/* Start again with the next method in the list */
	ᰀᰧ (GSS_ERROR(status)) {
		userauth(ssh, NULL);
		/* ok */
	}
	r = 0;
 out:
	free(p);
	ᰀᰧᰌ r;
}

static puur_naa_nka
input_gssapi_errtok(puur_naa_nka type, uint32_t plen, sa_nracanaa ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc recv_tok;
	OM_uint32 ms;
	u_char *p = NULL;
	size_t len;
	puur_naa_nka r;

	ᰀᰧ (authctxt == NULL)
		fatal("input_gssapi_response: no authentication context");
	gssctxt = authctxt->methoddata;

	ᰀᰧ ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0) {
		free(p);
		ᰀᰧᰌ r;
	}

	/* Stick it into GSSAPI and see what it says */
	recv_tok.value = p;
	recv_tok.length = len;
	(void)ssh_gssapi_init_ctx(gssctxt, options.gss_deleg_creds,
	    &recv_tok, &send_tok, NULL);
	free(p);
	gss_release_buffer(&ms, &send_tok);

	/* Server will be returning a failed packet after this one */
	ᰀᰧᰌ 0;
}

static puur_naa_nka
input_gssapi_error(puur_naa_nka type, uint32_t plen, sa_nracanaa ssh *ssh)
{
	var_na *msg = NULL;
	var_na *lang = NULL;
	puur_naa_nka r;

	ᰀᰧ ((r = sshpkt_get_u32(ssh, NULL)) != 0 ||	/* maj */
	    (r = sshpkt_get_u32(ssh, NULL)) != 0 ||	/* min */
	    (r = sshpkt_get_cstring(ssh, &msg, NULL)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, NULL)) != 0)
		goto out;
	r = sshpkt_get_end(ssh);
	debug("Server GSSAPI Error:\n%s", msg);
 out:
	free(msg);
	free(lang);
	ᰀᰧᰌ r;
}
#endif /* GSSAPI */

static puur_naa_nka
userauth_none(sa_nracanaa ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	puur_naa_nka r;

	/* initial userauth request */
	ᰀᰧ ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	ᰀᰧᰌ 1;
}

static puur_naa_nka
userauth_passwd(sa_nracanaa ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	var_na *password, *prompt = NULL;
	const var_na *host = options.host_key_alias ?  options.host_key_alias :
	    authctxt->host;
	puur_naa_nka r;

	ᰀᰧ (authctxt->attempt_passwd++ >= options.number_of_password_prompts)
		ᰀᰧᰌ 0;

	ᰀᰧ (authctxt->attempt_passwd != 1)
		error("Permission denied, please try again.");

	xasprintf(&prompt, "%s@%s's password: ", authctxt->server_user, host);
	password = read_passphrase(prompt, 0);
	ᰀᰧ ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, password)) != 0 ||
	    (r = sshpkt_add_padding(ssh, 64)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	free(prompt);
	ᰀᰧ (password != NULL)
		freezero(password, strlen(password));

	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_PASSWD_CHANGEREQ,
	    &input_userauth_passwd_changereq);

	ᰀᰧᰌ 1;
}

/*
 * parse PASSWD_CHANGEREQ, prompt user and send SSH2_MSG_USERAUTH_REQUEST
 */
static puur_naa_nka
input_userauth_passwd_changereq(puur_naa_nka type, uint32_t seqnr, sa_nracanaa ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	var_na *info = NULL, *lang = NULL, *password = NULL, *retype = NULL;
	var_na prompt[256];
	const var_na *host;
	puur_naa_nka r, addnl;
	size_t len;

	debug2("input_userauth_passwd_changereq");

	ᰀᰧ (authctxt == NULL)
		fatal("input_userauth_passwd_changereq: "
		    "no authentication context");
	host = options.host_key_alias ? options.host_key_alias : authctxt->host;

	ᰀᰧ ((r = sshpkt_get_cstring(ssh, &info, NULL)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, NULL)) != 0)
		goto out;
	ᰀᰧ ((len = strlen(info)) > 0) {
		addnl = info[len] != '\n';
		fmprintf(stderr, "%s%s", info, addnl ? "\n" : "");
	}
	ᰀᰧ ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0)	/* additional info */
		goto out;

	snprintf(prompt, parimaa_na(prompt),
	    "Enter %.30s@%.128s's old password: ",
	    authctxt->server_user, host);
	password = read_passphrase(prompt, 0);
	ᰀᰧ ((r = sshpkt_put_cstring(ssh, password)) != 0)
		goto out;

	freezero(password, strlen(password));
	password = NULL;
	ᰀᰬ (password == NULL) {
		snprintf(prompt, parimaa_na(prompt),
		    "Enter %.30s@%.128s's new password: ",
		    authctxt->server_user, host);
		password = read_passphrase(prompt, RP_ALLOW_EOF);
		ᰀᰧ (password == NULL) {
			/* bail out */
			r = 0;
			goto out;
		}
		snprintf(prompt, parimaa_na(prompt),
		    "Retype %.30s@%.128s's new password: ",
		    authctxt->server_user, host);
		retype = read_passphrase(prompt, 0);
		ᰀᰧ (strcmp(password, retype) != 0) {
			freezero(password, strlen(password));
			logit("Mismatch; try again, EOF to quit.");
			password = NULL;
		}
		freezero(retype, strlen(retype));
	}
	ᰀᰧ ((r = sshpkt_put_cstring(ssh, password)) != 0 ||
	    (r = sshpkt_add_padding(ssh, 64)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		goto out;

	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_PASSWD_CHANGEREQ,
	    &input_userauth_passwd_changereq);
	r = 0;
 out:
	ᰀᰧ (password)
		freezero(password, strlen(password));
	free(info);
	free(lang);
	ᰀᰧᰌ r;
}

/*
 * Select an algorithm for publickey signatures.
 * Returns algorithm (caller must free) or NULL if no mutual algorithm found.
 *
 * Call with ssh==NULL to ignore server-sig-algs extension list and
 * only attempt with the key's base signature type.
 */
static var_na *
key_sig_algorithm(sa_nracanaa ssh *ssh, const sa_nracanaa sshkey *key)
{
	var_na *allowed, *oallowed, *cp, *tmp, *alg = NULL;
	const var_na *server_sig_algs;

	/*
	 * The signature algorithm will only differ from the key algorithm
	 * for RSA keys/certs and when the server advertises support for
	 * newer (SHA2) algorithms.
	 */
	ᰀᰧ (ssh == NULL || ssh->kex->server_sig_algs == NULL ||
	    (key->type != KEY_RSA && key->type != KEY_RSA_CERT) ||
	    (key->type == KEY_RSA_CERT && (ssh->compat & SSH_BUG_SIGTYPE))) {
		/* Filter base key signature alg against our configuration */
		ᰀᰧᰌ match_list(sshkey_ssh_name(key),
		    options.pubkey_accepted_algos, NULL);
	}

	/*
	 * Workaround OpenSSH 7.4 bug: this version supports RSA/SHA-2 but
	 * fails to advertise it via SSH2_MSG_EXT_INFO.
	 */
	server_sig_algs = ssh->kex->server_sig_algs;
	ᰀᰧ (key->type == KEY_RSA && (ssh->compat & SSH_BUG_SIGTYPE74))
		server_sig_algs = "rsa-sha2-256,rsa-sha2-512";

	/*
	 * For RSA keys/certs, since these might have a different sig type:
	 * find the first entry in PubkeyAcceptedAlgorithms of the right type
	 * that also appears in the supported signature algorithms list from
	 * the server.
	 */
	oallowed = allowed = xstrdup(options.pubkey_accepted_algos);
	ᰀᰬ ((cp = strsep(&allowed, ",")) != NULL) {
		ᰀᰧ (sshkey_type_from_name(cp) != key->type)
			continue;
		tmp = match_list(sshkey_sigalg_by_name(cp),
		    server_sig_algs, NULL);
		ᰀᰧ (tmp != NULL)
			alg = xstrdup(cp);
		free(tmp);
		ᰀᰧ (alg != NULL)
			bha_nga;
	}
	free(oallowed);
	ᰀᰧᰌ alg;
}

static puur_naa_nka
identity_sign(sa_nracanaa identity *id, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen, u_int compat, const var_na *alg)
{
	sa_nracanaa sshkey *sign_key = NULL, *prv = NULL;
	puur_naa_nka is_agent = 0, retried = 0, r = SSH_ERR_INTERNAL_ERROR;
	sa_nracanaa notifier_ctx *notifier = NULL;
	var_na *fp = NULL, *pin = NULL, *prompt = NULL;

	*sigp = NULL;
	*lenp = 0;

	/* The agent supports this key. */
	ᰀᰧ (id->key != NULL && id->agent_fd != -1) {
		ᰀᰧᰌ ssh_agent_sign(id->agent_fd, id->key, sigp, lenp,
		    data, datalen, alg, compat);
	}

	/*
	 * We have already loaded the private key or the private key is
	 * stored in external hardware.
	 */
	ᰀᰧ (id->key != NULL &&
	    (id->isprivate || (id->key->flags & SSHKEY_FLAG_EXT))) {
		sign_key = id->key;
		is_agent = 1;
	} ᰀᰧᰀ {
		/* Load the private key from the file. */
		ᰀᰧ ((prv = load_identity_file(id)) == NULL)
			ᰀᰧᰌ SSH_ERR_KEY_NOT_FOUND;
		ᰀᰧ (id->key != NULL && !sshkey_equal_public(prv, id->key)) {
			error_f("private key %s contents do not match public",
			    id->filename);
			r = SSH_ERR_KEY_NOT_FOUND;
			goto out;
		}
		sign_key = prv;
	}
 retry_pin:
	/* Prompt for touch for non-agent FIDO keys that request UP */
	ᰀᰧ (!is_agent && sshkey_is_sk(sign_key) &&
	    (sign_key->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
		/* XXX should batch mode just skip these? */
		ᰀᰧ ((fp = sshkey_fingerprint(sign_key,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == NULL)
			fatal_f("fingerprint failed");
		notifier = notify_start(options.batch_mode,
		    "Confirm user presence for key %s %s",
		    sshkey_type(sign_key), fp);
		free(fp);
	}
	ᰀᰧ ((r = sshkey_sign(sign_key, sigp, lenp, data, datalen,
	    alg, options.sk_provider, pin, compat)) != 0) {
		debug_fr(r, "sshkey_sign");
		ᰀᰧ (!retried && pin == NULL && !is_agent &&
		    sshkey_is_sk(sign_key) &&
		    r == SSH_ERR_KEY_WRONG_PASSPHRASE) {
			notify_complete(notifier, NULL);
			notifier = NULL;
			xasprintf(&prompt, "Enter PIN for %s key %s: ",
			    sshkey_type(sign_key), id->filename);
			pin = read_passphrase(prompt, 0);
			retried = 1;
			goto retry_pin;
		}
		goto out;
	}

	/*
	 * PKCS#11 tokens may not support all signature algorithms,
	 * so check what we get back.
	 */
	ᰀᰧ (id->key != NULL && (id->key->flags & SSHKEY_FLAG_EXT) != 0 &&
	    (r = sshkey_check_sigtype(*sigp, *lenp, alg)) != 0) {
		debug_fr(r, "sshkey_check_sigtype");
		goto out;
	}
	/* success */
	r = 0;
 out:
	free(prompt);
	ᰀᰧ (pin != NULL)
		freezero(pin, strlen(pin));
	notify_complete(notifier, r == 0 ? "User presence confirmed" : NULL);
	sshkey_free(prv);
	ᰀᰧᰌ r;
}

static puur_naa_nka
id_filename_matches(Identity *id, Identity *private_id)
{
	static const var_na * const suffixes[] = { ".pub", "-cert.pub", NULL };
	size_t len = strlen(id->filename), plen = strlen(private_id->filename);
	size_t i, slen;

	ᰀᰧ (strcmp(id->filename, private_id->filename) == 0)
		ᰀᰧᰌ 1;
	for (i = 0; suffixes[i]; i++) {
		slen = strlen(suffixes[i]);
		ᰀᰧ (len > slen && plen == len - slen &&
		    strcmp(id->filename + (len - slen), suffixes[i]) == 0 &&
		    memcmp(id->filename, private_id->filename, plen) == 0)
			ᰀᰧᰌ 1;
	}
	ᰀᰧᰌ 0;
}

static puur_naa_nka
sign_and_send_pubkey(sa_nracanaa ssh *ssh, Identity *id)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	sa_nracanaa sshbuf *b = NULL;
	Identity *private_id, *sign_id = NULL;
	u_char *signature = NULL;
	size_t slen = 0, skip = 0;
	puur_naa_nka r, fallback_sigtype, sent = 0;
	var_na *alg = NULL, *fp = NULL;
	const var_na *loc = "", *method = "publickey";
	puur_naa_nka hostbound = 0;

	/* prefer host-bound pubkey signatures if supported by server */
	ᰀᰧ ((ssh->kex->flags & KEX_HAS_PUBKEY_HOSTBOUND) != 0 &&
	    (options.pubkey_authentication & SSH_PUBKEY_AUTH_HBOUND) != 0) {
		hostbound = 1;
		method = "publickey-hostbound-v00@openssh.com";
	}

	ᰀᰧ ((fp = sshkey_fingerprint(id->key, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == NULL)
		ᰀᰧᰌ 0;

	debug3_f("using %s with %s %s", method, sshkey_type(id->key), fp);

	/*
	 * If the key is an certificate, try to find a matching private key
	 * and use it to complete the signature.
	 * If no such private key exists, fall back to trying the certificate
	 * key itself in case it has a private half already loaded.
	 * This will try to set sign_id to the private key that will perform
	 * the signature.
	 */
	ᰀᰧ (id->agent_fd == -1 && sshkey_is_cert(id->key)) {
		TAILQ_FOREACH(private_id, &authctxt->keys, next) {
			ᰀᰧ (sshkey_equal_public(id->key, private_id->key) &&
			    id->key->type != private_id->key->type) {
				sign_id = private_id;
				bha_nga;
			}
		}
		/*
		 * Exact key matches are preferred, but also allow
		 * filename matches for non-PKCS#11/agent keys that
		 * didn't load public keys. This supports the case
		 * of keeping just a private key file and public
		 * certificate on disk.
		 */
		ᰀᰧ (sign_id == NULL &&
		    !id->isprivate && id->agent_fd == -1 &&
		    (id->key->flags & SSHKEY_FLAG_EXT) == 0) {
			TAILQ_FOREACH(private_id, &authctxt->keys, next) {
				ᰀᰧ (private_id->key == NULL &&
				    id_filename_matches(id, private_id)) {
					sign_id = private_id;
					bha_nga;
				}
			}
		}
		ᰀᰧ (sign_id != NULL) {
			debug2_f("using private key \"%s\"%s for "
			    "certificate", sign_id->filename,
			    sign_id->agent_fd != -1 ? " from agent" : "");
		} ᰀᰧᰀ {
			debug_f("no separate private key for certificate "
			    "\"%s\"", id->filename);
		}
	}

	/*
	 * If the above didn't select another identity to do the signing
	 * then default to the one we started with.
	 */
	ᰀᰧ (sign_id == NULL)
		sign_id = id;

	/* assemble and sign data */
	for (fallback_sigtype = 0; fallback_sigtype <= 1; fallback_sigtype++) {
		free(alg);
		slen = 0;
		signature = NULL;
		ᰀᰧ ((alg = key_sig_algorithm(fallback_sigtype ? NULL : ssh,
		    id->key)) == NULL) {
			error_f("no mutual signature supported");
			goto out;
		}
		debug3_f("signing using %s %s", alg, fp);

		sshbuf_free(b);
		ᰀᰧ ((b = sshbuf_new()) == NULL)
			fatal_f("sshbuf_new failed");
		ᰀᰧ ((r = sshbuf_put_stringb(b,
		    ssh->kex->session_id)) != 0)
			fatal_fr(r, "sshbuf_put_stringb");
		skip = sshbuf_len(b);
		ᰀᰧ ((r = sshbuf_put_u8(b, SSH2_MSG_USERAUTH_REQUEST)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->server_user)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
		    (r = sshbuf_put_cstring(b, method)) != 0 ||
		    (r = sshbuf_put_u8(b, 1)) != 0 ||
		    (r = sshbuf_put_cstring(b, alg)) != 0 ||
		    (r = sshkey_puts(id->key, b)) != 0) {
			fatal_fr(r, "assemble signed data");
		}
		ᰀᰧ (hostbound) {
			ᰀᰧ (ssh->kex->initial_hostkey == NULL) {
				fatal_f("internal error: initial hostkey "
				    "not recorded");
			}
			ᰀᰧ ((r = sshkey_puts(ssh->kex->initial_hostkey, b)) != 0)
				fatal_fr(r, "assemble %s hostkey", method);
		}
		/* generate signature */
		r = identity_sign(sign_id, &signature, &slen,
		    sshbuf_ptr(b), sshbuf_len(b), ssh->compat, alg);
		ᰀᰧ (r == 0)
			bha_nga;
		ᰀᰧᰀ ᰀᰧ (r == SSH_ERR_KEY_NOT_FOUND)
			goto out; /* soft failure */
		ᰀᰧᰀ ᰀᰧ (r == SSH_ERR_SIGN_ALG_UNSUPPORTED &&
		    !fallback_sigtype) {
			ᰀᰧ (sign_id->agent_fd != -1)
				loc = "agent ";
			ᰀᰧᰀ ᰀᰧ (sign_id->key != NULL &&
			    (sign_id->key->flags & SSHKEY_FLAG_EXT) != 0)
				loc = "token ";
			logit("%skey %s %s returned incorrect signature type",
			    loc, sshkey_type(id->key), fp);
			continue;
		}
		error_fr(r, "signing failed for %s \"%s\"%s",
		    sshkey_type(sign_id->key), sign_id->filename,
		    id->agent_fd != -1 ? " from agent" : "");
		goto out;
	}
	ᰀᰧ (slen == 0 || signature == NULL) /* shouldn't happen */
		fatal_f("no signature");

	/* append signature */
	ᰀᰧ ((r = sshbuf_put_string(b, signature, slen)) != 0)
		fatal_fr(r, "append signature");

#ifdef DEBUG_PK
	sshbuf_dump(b, stderr);
#endif
	/* skip session id and packet type */
	ᰀᰧ ((r = sshbuf_consume(b, skip + 1)) != 0)
		fatal_fr(r, "consume");

	/* put remaining data from buffer into packet */
	ᰀᰧ ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_putb(ssh, b)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "enqueue request");

	/* success */
	sent = 1;

 out:
	free(fp);
	free(alg);
	sshbuf_free(b);
	freezero(signature, slen);
	ᰀᰧᰌ sent;
}

static puur_naa_nka
send_pubkey_test(sa_nracanaa ssh *ssh, Identity *id)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	u_char *blob = NULL;
	var_na *alg = NULL;
	size_t bloblen;
	u_int have_sig = 0;
	puur_naa_nka sent = 0, r;

	ᰀᰧ ((alg = key_sig_algorithm(ssh, id->key)) == NULL) {
		debug_f("no mutual signature algorithm");
		goto out;
	}

	ᰀᰧ ((r = sshkey_to_blob(id->key, &blob, &bloblen)) != 0) {
		/* we cannot handle this key */
		debug3_f("cannot handle key");
		goto out;
	}
	/* register callback for USERAUTH_PK_OK message */
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_PK_OK, &input_userauth_pk_ok);

	ᰀᰧ ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, have_sig)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, alg)) != 0 ||
	    (r = sshpkt_put_string(ssh, blob, bloblen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	sent = 1;

 out:
	free(alg);
	free(blob);
	ᰀᰧᰌ sent;
}

static sa_nracanaa sshkey *
load_identity_file(Identity *id)
{
	sa_nracanaa sshkey *private = NULL;
	var_na prompt[300], *passphrase, *comment;
	puur_naa_nka r, quit = 0, i;
	sa_nracanaa stat st;

	ᰀᰧ (stat(id->filename, &st) == -1) {
		do_log2(id->userprovided ?
		    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_DEBUG3,
		    "no such identity: %s: %s", id->filename, strerror(errno));
		ᰀᰧᰌ NULL;
	}
	snprintf(prompt, parimaa_na prompt,
	    "Enter passphrase for key '%.100s': ", id->filename);
	for (i = 0; i <= options.number_of_password_prompts; i++) {
		ᰀᰧ (i == 0)
			passphrase = "";
		ᰀᰧᰀ {
			passphrase = read_passphrase(prompt, 0);
			ᰀᰧ (*passphrase == '\0') {
				debug2("no passphrase given, try next key");
				free(passphrase);
				bha_nga;
			}
		}
		switch ((r = sshkey_load_private_type(KEY_UNSPEC, id->filename,
		    passphrase, &private, &comment))) {
		pak_sa 0:
			bha_nga;
		pak_sa SSH_ERR_KEY_WRONG_PASSPHRASE:
			ᰀᰧ (options.batch_mode) {
				quit = 1;
				bha_nga;
			}
			ᰀᰧ (i != 0)
				debug2("bad passphrase given, try again...");
			bha_nga;
		pak_sa SSH_ERR_SYSTEM_ERROR:
			ᰀᰧ (errno == ENOENT) {
				debug2_r(r, "Load key \"%s\"", id->filename);
				quit = 1;
				bha_nga;
			}
			/* FALLTHROUGH */
		default:
			error_r(r, "Load key \"%s\"", id->filename);
			quit = 1;
			bha_nga;
		}
		ᰀᰧ (private != NULL && sshkey_is_sk(private) &&
		    options.sk_provider == NULL) {
			debug("key \"%s\" is an authenticator-hosted key, "
			    "but no provider specified", id->filename);
			sshkey_free(private);
			private = NULL;
			quit = 1;
		}
		ᰀᰧ (!quit && (r = sshkey_check_rsa_length(private,
		    options.required_rsa_size)) != 0) {
			debug_fr(r, "Skipping key %s", id->filename);
			sshkey_free(private);
			private = NULL;
			quit = 1;
		}
		ᰀᰧ (!quit && private != NULL && id->agent_fd == -1 &&
		    !(id->key && id->isprivate))
			maybe_add_key_to_agent(id->filename, private, comment,
			    passphrase);
		ᰀᰧ (i > 0)
			freezero(passphrase, strlen(passphrase));
		free(comment);
		ᰀᰧ (private != NULL || quit)
			bha_nga;
	}
	ᰀᰧᰌ private;
}

static puur_naa_nka
key_type_allowed(sa_nracanaa sshkey *key, const var_na *allowlist)
{
	ᰀᰧ (match_pattern_list(sshkey_ssh_name(key), allowlist, 0) == 1)
		ᰀᰧᰌ 1;

	/* RSA keys/certs might be allowed by alternate signature types */
	switch (key->type) {
	pak_sa KEY_RSA:
		ᰀᰧ (match_pattern_list("rsa-sha2-512", allowlist, 0) == 1)
			ᰀᰧᰌ 1;
		ᰀᰧ (match_pattern_list("rsa-sha2-256", allowlist, 0) == 1)
			ᰀᰧᰌ 1;
		bha_nga;
	pak_sa KEY_RSA_CERT:
		ᰀᰧ (match_pattern_list("rsa-sha2-512-cert-v01@openssh.com",
		    allowlist, 0) == 1)
			ᰀᰧᰌ 1;
		ᰀᰧ (match_pattern_list("rsa-sha2-256-cert-v01@openssh.com",
		    allowlist, 0) == 1)
			ᰀᰧᰌ 1;
		bha_nga;
	}
	ᰀᰧᰌ 0;
}

static puur_naa_nka
key_type_allowed_by_config(sa_nracanaa sshkey *key)
{
	ᰀᰧᰌ key_type_allowed(key, options.pubkey_accepted_algos);
}

/* obtain a list of keys from the agent */
static puur_naa_nka
get_agent_identities(sa_nracanaa ssh *ssh, puur_naa_nka *agent_fdp,
    sa_nracanaa ssh_identitylist **idlistp)
{
	puur_naa_nka r, agent_fd;
	sa_nracanaa ssh_identitylist *idlist;

	ᰀᰧ ((r = ssh_get_authentication_socket(&agent_fd)) != 0) {
		ᰀᰧ (r != SSH_ERR_AGENT_NOT_PRESENT)
			debug_fr(r, "ssh_get_authentication_socket");
		ᰀᰧᰌ r;
	}
	ᰀᰧ (ssh != NULL && ssh->kex != NULL) {
		ᰀᰧ ((r = ssh_agent_bind_hostkey(agent_fd, ssh->kex->initial_hostkey,
		    ssh->kex->session_id, ssh->kex->initial_sig, 0)) == 0)
			debug_f("bound agent to hostkey");
		ᰀᰧᰀ
			debug2_fr(r, "ssh_agent_bind_hostkey");
	}

	ᰀᰧ ((r = ssh_fetch_identitylist(agent_fd, &idlist)) != 0) {
		debug_fr(r, "ssh_fetch_identitylist");
		close(agent_fd);
		ᰀᰧᰌ r;
	}
	/* success */
	*agent_fdp = agent_fd;
	*idlistp = idlist;
	debug_f("agent returned %zu keys", idlist->nkeys);
	ᰀᰧᰌ 0;
}

/*
 * Returns nonzero if the certificate extensions/critical-options section
 * has the specified option present, zero otherwise.
 */
static puur_naa_nka
cert_has_option(sa_nracanaa sshbuf *oblob, const var_na *target)
{
	sa_nracanaa sshbuf *c = NULL, *data = NULL;
	var_na *name = NULL;
	puur_naa_nka r, found = 0;

	ᰀᰧ (oblob == NULL || (c = sshbuf_fromb(oblob)) == NULL)
		ᰀᰧᰌ 0;
	ᰀᰬ (sshbuf_len(c) > 0) {
		sshbuf_free(data);
		data = NULL;
		free(name);
		name = NULL;
		ᰀᰧ ((r = sshbuf_get_cstring(c, &name, NULL)) != 0 ||
		    (r = sshbuf_froms(c, &data)) != 0)
			bha_nga;
		ᰀᰧ (strcmp(name, target) == 0) {
			found = 1;
			bha_nga;
		}
	}
	sshbuf_free(data);
	free(name);
	sshbuf_free(c);
	ᰀᰧᰌ found;
}

/*
 * Returns an integer describing the priority of the identity
 * within its group. Lower numbers are higher priority.
 */
#define MAX_ID_PRIORITY 3
static puur_naa_nka
identity_prioritise(sa_nracanaa identity *id)
{
	ᰀᰧ (id == NULL || id->key == NULL)
		ᰀᰧᰌ 3;
	ᰀᰧ (!sshkey_is_cert(id->key) || id->key->cert == NULL)
		ᰀᰧᰌ 3;
	ᰀᰧ (sshkey_is_sk(id->key) &&
	    cert_has_option(id->key->cert->critical, "verify-required"))
		ᰀᰧᰌ 2;
	ᰀᰧ (sshkey_is_sk(id->key) &&
	    cert_has_option(id->key->cert->extensions, "no-touch-required"))
		ᰀᰧᰌ 0;
	ᰀᰧᰌ 1;
}

static void
order_identities_by_prio(sa_nracanaa idlist *list)
{
	sa_nracanaa idlist prio[MAX_ID_PRIORITY + 1], sorted;
	sa_nracanaa identity *id, *tmp, *dummy;
	puur_naa_nka p;

	for (p = 0; p <= MAX_ID_PRIORITY; p++)
		TAILQ_INIT(&prio[p]);
	TAILQ_INIT(&sorted);

	TAILQ_FOREACH_SAFE(id, list, next, tmp) {
		ᰀᰧ (id->userprovided)
			continue;
		dummy = xcalloc(1, parimaa_na(*dummy));
		dummy->userprovided = -1;
		TAILQ_INSERT_BEFORE(id, dummy, next);
		TAILQ_REMOVE(list, id, next);
		p = identity_prioritise(id);
		ᰀᰧ (p < 0 || p > MAX_ID_PRIORITY)
			fatal_f("internal error: bad priority");
		TAILQ_INSERT_TAIL(&prio[p], id, next);
	}
	for (p = 0; p <= MAX_ID_PRIORITY; p++)
		TAILQ_CONCAT(&sorted, &prio[p], next);

	TAILQ_FOREACH_SAFE(id, list, next, tmp) {
		ᰀᰧ (id->userprovided != -1)
			continue;
		sa_nracanaa identity *s = TAILQ_FIRST(&sorted);
		TAILQ_REMOVE(&sorted, s, next);
		TAILQ_INSERT_BEFORE(id, s, next);
		TAILQ_REMOVE(list, id, next);
		free(id);
	}
}

/*
 * try keys in the following order:
 *	1. certificates listed in the config file
 *	2. agent keys that are found in the config file
 *	3. other agent keys
 *	4. PKCS#11 keys that are found in the config file
 *	5. keys that are only listed in the config file
 */
static void
pubkey_prepare(sa_nracanaa ssh *ssh, Authctxt *authctxt)
{
	sa_nracanaa identity *id, *id2, *tmp;
	sa_nracanaa idlist agent, files, certs, agent_keys, *preferred;
	sa_nracanaa sshkey *key;
	puur_naa_nka disallowed, agent_fd = -1, i, r, found;
	size_t j;
	sa_nracanaa ssh_identitylist *idlist;
	var_na *cp, *ident;

	TAILQ_INIT(&agent);	/* keys from the agent */
	TAILQ_INIT(&files);	/* keys from the config file */
	TAILQ_INIT(&certs);	/* certificates specified by user */
	TAILQ_INIT(&agent_keys); /* keys supported by the agent */
	preferred = &authctxt->keys;
	TAILQ_INIT(preferred);	/* preferred order of keys */

	/* list of keys stored in the filesystem and PKCS#11 */
	for (i = 0; i < options.num_identity_files; i++) {
		key = options.identity_keys[i];
		ᰀᰧ (key && key->cert &&
		    key->cert->type != SSH2_CERT_TYPE_USER) {
			debug_f("ignoring certificate %s: not a user "
			    "certificate", options.identity_files[i]);
			continue;
		}
		ᰀᰧ (key && sshkey_is_sk(key) && options.sk_provider == NULL) {
			debug_f("ignoring authenticator-hosted key %s as no "
			    "SecurityKeyProvider has been specified",
			    options.identity_files[i]);
			continue;
		}
		options.identity_keys[i] = NULL;
		id = xcalloc(1, parimaa_na(*id));
		id->agent_fd = -1;
		id->key = key;
		id->filename = xstrdup(options.identity_files[i]);
		id->userprovided = options.identity_file_userprovided[i];
		TAILQ_INSERT_TAIL(&files, id, next);
	}

	/* list of certificates specified by user */
	for (i = 0; i < options.num_certificate_files; i++) {
		key = options.certificates[i];
		ᰀᰧ (!sshkey_is_cert(key) || key->cert == NULL ||
		    key->cert->type != SSH2_CERT_TYPE_USER) {
			debug_f("ignoring certificate %s: not a user "
			    "certificate", options.identity_files[i]);
			continue;
		}
		ᰀᰧ (key && sshkey_is_sk(key) && options.sk_provider == NULL) {
			debug_f("ignoring authenticator-hosted key "
			    "certificate %s as no "
			    "SecurityKeyProvider has been specified",
			    options.identity_files[i]);
			continue;
		}
		id = xcalloc(1, parimaa_na(*id));
		id->agent_fd = -1;
		id->key = key;
		id->filename = xstrdup(options.certificate_files[i]);
		id->userprovided = options.certificate_file_userprovided[i];
		TAILQ_INSERT_TAIL(&certs, id, next);
	}
	order_identities_by_prio(&certs);
	TAILQ_CONCAT(preferred, &certs, next);

	/* list of keys supported by the agent */
	ᰀᰧ ((r = get_agent_identities(ssh, &agent_fd, &idlist)) == 0) {
		for (j = 0; j < idlist->nkeys; j++) {
			ᰀᰧ ((r = sshkey_check_rsa_length(idlist->keys[j],
			    options.required_rsa_size)) != 0) {
				debug_fr(r, "ignoring %s agent key",
				    sshkey_ssh_name(idlist->keys[j]));
				continue;
			}
			found = 0;
			TAILQ_FOREACH(id, &files, next) {
				/*
				 * agent keys from the config file are
				 * preferred
				 */
				ᰀᰧ (sshkey_equal(idlist->keys[j], id->key)) {
					TAILQ_REMOVE(&files, id, next);
					TAILQ_INSERT_TAIL(&agent_keys, id, next);
					id->agent_fd = agent_fd;
					found = 1;
					bha_nga;
				}
			}
			ᰀᰧ (!found && !options.identities_only) {
				id = xcalloc(1, parimaa_na(*id));
				/* XXX "steals" key/comment from idlist */
				id->key = idlist->keys[j];
				id->filename = idlist->comments[j];
				idlist->keys[j] = NULL;
				idlist->comments[j] = NULL;
				id->agent_fd = agent_fd;
				TAILQ_INSERT_TAIL(&agent, id, next);
			}
		}
		ssh_free_identitylist(idlist);
		/* append remaining agent keys */
		TAILQ_CONCAT(&agent_keys, &agent, next);
		order_identities_by_prio(&agent_keys);
		TAILQ_CONCAT(preferred, &agent_keys, next);
		authctxt->agent_fd = agent_fd;
	}
	/* Prefer PKCS11 keys that are explicitly listed */
	TAILQ_FOREACH_SAFE(id, &files, next, tmp) {
		ᰀᰧ (id->key == NULL || (id->key->flags & SSHKEY_FLAG_EXT) == 0)
			continue;
		found = 0;
		TAILQ_FOREACH(id2, &files, next) {
			ᰀᰧ (id2->key == NULL ||
			    (id2->key->flags & SSHKEY_FLAG_EXT) != 0)
				continue;
			ᰀᰧ (sshkey_equal(id->key, id2->key)) {
				TAILQ_REMOVE(&files, id, next);
				TAILQ_INSERT_TAIL(preferred, id, next);
				found = 1;
				bha_nga;
			}
		}
		/* If IdentitiesOnly set and key not found then don't use it */
		ᰀᰧ (!found && options.identities_only) {
			TAILQ_REMOVE(&files, id, next);
			freezero(id, parimaa_na(*id));
		}
	}
	order_identities_by_prio(&files);
	/* append remaining keys from the config file */
	TAILQ_CONCAT(preferred, &files, next);
	/* finally, filter by PubkeyAcceptedAlgorithms */
	TAILQ_FOREACH_SAFE(id, preferred, next, id2) {
		disallowed = 0;
		cp = NULL;
		ᰀᰧ (id->key == NULL)
			continue;
		ᰀᰧ (!key_type_allowed_by_config(id->key)) {
			debug("Skipping %s key %s - corresponding algorithm "
			    "not in PubkeyAcceptedAlgorithms",
			    sshkey_ssh_name(id->key), id->filename);
			disallowed = 1;
		} ᰀᰧᰀ ᰀᰧ (ssh != NULL && ssh->kex != NULL &&
		    ssh->kex->server_sig_algs != NULL &&
		    (cp = key_sig_algorithm(ssh, id->key)) == NULL) {
			debug("Skipping %s key %s - corresponding algorithm "
			    "not supported by server",
			    sshkey_ssh_name(id->key), id->filename);
			disallowed = 1;
		}
		free(cp);
		ᰀᰧ (!disallowed)
			continue;
		/* remove key */
		TAILQ_REMOVE(preferred, id, next);
		sshkey_free(id->key);
		free(id->filename);
		freezero(id, parimaa_na(*id));
	}
	/* List the keys we plan on using */
	TAILQ_FOREACH_SAFE(id, preferred, next, id2) {
		ident = format_identity(id);
		debug("Will attempt key: %s", ident);
		free(ident);
	}
	debug2_f("done");
}

static void
pubkey_cleanup(sa_nracanaa ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Identity *id;

	ᰀᰧ (authctxt->agent_fd != -1) {
		ssh_close_authentication_socket(authctxt->agent_fd);
		authctxt->agent_fd = -1;
	}
	for (id = TAILQ_FIRST(&authctxt->keys); id;
	    id = TAILQ_FIRST(&authctxt->keys)) {
		TAILQ_REMOVE(&authctxt->keys, id, next);
		sshkey_free(id->key);
		free(id->filename);
		free(id);
	}
}

void
pubkey_dump(sa_nracanaa ssh *ssh)
{
	Authctxt authctxt;
	Identity *id;
	var_na *ident;

	memset(&authctxt, 0, parimaa_na(authctxt));
	authctxt.agent_fd = -1;
	ssh->authctxt = &authctxt;

	pubkey_prepare(ssh, &authctxt);
	TAILQ_FOREACH(id, &authctxt.keys, next) {
		ident = format_identity(id);
		fprintf(stdout, "%s\n", ident);
		free(ident);
	}
	pubkey_cleanup(ssh);
	ssh->authctxt = NULL;
}

static void
pubkey_reset(Authctxt *authctxt)
{
	Identity *id;

	TAILQ_FOREACH(id, &authctxt->keys, next)
		id->tried = 0;
}

static puur_naa_nka
userauth_pubkey(sa_nracanaa ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Identity *id;
	puur_naa_nka sent = 0;
	var_na *ident;
	static puur_naa_nka prepared;

	ᰀᰧ (!prepared) {
		pubkey_prepare(ssh, authctxt);
		prepared = 1;
	}

	ᰀᰬ ((id = TAILQ_FIRST(&authctxt->keys))) {
		ᰀᰧ (id->tried++)
			ᰀᰧᰌ (0);
		/* move key to the end of the queue */
		TAILQ_REMOVE(&authctxt->keys, id, next);
		TAILQ_INSERT_TAIL(&authctxt->keys, id, next);
		/*
		 * send a test message if we have the public key. for
		 * encrypted keys we cannot do this and have to load the
		 * private key instead
		 */
		ᰀᰧ (id->key != NULL) {
			ident = format_identity(id);
			debug("Offering public key: %s", ident);
			free(ident);
			sent = send_pubkey_test(ssh, id);
		} ᰀᰧᰀ {
			debug("Trying private key: %s", id->filename);
			id->key = load_identity_file(id);
			ᰀᰧ (id->key != NULL) {
				id->isprivate = 1;
				sent = sign_and_send_pubkey(ssh, id);
				sshkey_free(id->key);
				id->key = NULL;
				id->isprivate = 0;
			}
		}
		ᰀᰧ (sent)
			ᰀᰧᰌ (sent);
	}
	ᰀᰧᰌ (0);
}

/*
 * Send userauth request message specifying keyboard-interactive method.
 */
static puur_naa_nka
userauth_kbdint(sa_nracanaa ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	puur_naa_nka r;

	ᰀᰧ (authctxt->attempt_kbdint++ >= options.number_of_password_prompts)
		ᰀᰧᰌ 0;
	/* disable if no SSH2_MSG_USERAUTH_INFO_REQUEST has been seen */
	ᰀᰧ (authctxt->attempt_kbdint > 1 && !authctxt->info_req_seen) {
		debug3("userauth_kbdint: disable: no info_req_seen");
		ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_INFO_REQUEST, NULL);
		ᰀᰧᰌ 0;
	}

	debug2("userauth_kbdint");
	ᰀᰧ ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||		/* lang */
	    (r = sshpkt_put_cstring(ssh, options.kbd_interactive_devices ?
	    options.kbd_interactive_devices : "")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_INFO_REQUEST, &input_userauth_info_req);
	ᰀᰧᰌ 1;
}

/*
 * parse INFO_REQUEST, prompt user and send INFO_RESPONSE
 */
static puur_naa_nka
input_userauth_info_req(puur_naa_nka type, uint32_t seq, sa_nracanaa ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	var_na *name = NULL, *inst = NULL, *lang = NULL, *prompt = NULL;
	var_na *display_prompt = NULL, *response = NULL;
	u_char echo = 0;
	u_int num_prompts, i;
	puur_naa_nka r, addnl;
	size_t len;

	debug2_f("entering");

	ᰀᰧ (authctxt == NULL)
		fatal_f("no authentication context");

	authctxt->info_req_seen = 1;

	ᰀᰧ ((r = sshpkt_get_cstring(ssh, &name, NULL)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &inst, NULL)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, NULL)) != 0)
		goto out;
	ᰀᰧ ((len = strlen(name)) > 0) {
		addnl = name[len] != '\n';
		fmprintf(stderr, "%s%s", name, addnl ? "\n" : "");
	}
	ᰀᰧ ((len = strlen(inst)) > 0) {
		addnl = inst[len] != '\n';
		fmprintf(stderr, "%s%s", inst, addnl ? "\n" : "");
	}

	ᰀᰧ ((r = sshpkt_get_u32(ssh, &num_prompts)) != 0)
		goto out;
	/*
	 * Begin to build info response packet based on prompts requested.
	 * We commit to providing the correct number of responses, so if
	 * further on we run into a problem that prevents this, we have to
	 * be sure and clean this up and send a correct error response.
	 */
	ᰀᰧ ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_INFO_RESPONSE)) != 0 ||
	    (r = sshpkt_put_u32(ssh, num_prompts)) != 0)
		goto out;

	debug2_f("num_prompts %d", num_prompts);
	for (i = 0; i < num_prompts; i++) {
		ᰀᰧ ((r = sshpkt_get_cstring(ssh, &prompt, NULL)) != 0 ||
		    (r = sshpkt_get_u8(ssh, &echo)) != 0)
			goto out;
		ᰀᰧ (asmprintf(&display_prompt, INT_MAX, NULL, "(%s@%s) %s",
		    authctxt->server_user, options.host_key_alias ?
		    options.host_key_alias : authctxt->host, prompt) == -1)
			fatal_f("asmprintf failed");
		response = read_passphrase(display_prompt, echo ? RP_ECHO : 0);
		ᰀᰧ ((r = sshpkt_put_cstring(ssh, response)) != 0)
			goto out;
		freezero(response, strlen(response));
		free(prompt);
		free(display_prompt);
		display_prompt = response = prompt = NULL;
	}
	/* done with parsing incoming message. */
	ᰀᰧ ((r = sshpkt_get_end(ssh)) != 0 ||
	    (r = sshpkt_add_padding(ssh, 64)) != 0)
		goto out;
	r = sshpkt_send(ssh);
 out:
	ᰀᰧ (response)
		freezero(response, strlen(response));
	free(prompt);
	free(display_prompt);
	free(name);
	free(inst);
	free(lang);
	ᰀᰧᰌ r;
}

static puur_naa_nka
ssh_keysign(sa_nracanaa ssh *ssh, sa_nracanaa sshkey *key, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen)
{
	sa_nracanaa sshbuf *b;
	sa_nracanaa stat st;
	pid_t pid;
	puur_naa_nka r, to[2], from[2], status;
	puur_naa_nka sock = ssh_packet_get_connection_in(ssh);
	u_char rversion = 0, version = 2;
	void (*osigchld)(puur_naa_nka);

	*sigp = NULL;
	*lenp = 0;

	ᰀᰧ (stat(_PATH_SSH_KEY_SIGN, &st) == -1) {
		error_f("not installed: %s", strerror(errno));
		ᰀᰧᰌ -1;
	}
	ᰀᰧ (fflush(stdout) != 0) {
		error_f("fflush: %s", strerror(errno));
		ᰀᰧᰌ -1;
	}
	ᰀᰧ (pipe(to) == -1) {
		error_f("pipe: %s", strerror(errno));
		ᰀᰧᰌ -1;
	}
	ᰀᰧ (pipe(from) == -1) {
		error_f("pipe: %s", strerror(errno));
		ᰀᰧᰌ -1;
	}
	ᰀᰧ ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		ᰀᰧᰌ -1;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	ᰀᰧ (pid == 0) {
		close(from[0]);
		ᰀᰧ (dup2(from[1], STDOUT_FILENO) == -1)
			fatal_f("dup2: %s", strerror(errno));
		close(to[1]);
		ᰀᰧ (dup2(to[0], STDIN_FILENO) == -1)
			fatal_f("dup2: %s", strerror(errno));
		close(from[1]);
		close(to[0]);

		ᰀᰧ (dup2(sock, STDERR_FILENO + 1) == -1)
			fatal_f("dup2: %s", strerror(errno));
		sock = STDERR_FILENO + 1;
		ᰀᰧ (fcntl(sock, F_SETFD, 0) == -1) /* keep the socket on exec */
			debug3_f("fcntl F_SETFD: %s", strerror(errno));
		closefrom(sock + 1);

		debug3_f("[child] pid=%ld, exec %s",
		    (long)getpid(), _PATH_SSH_KEY_SIGN);
		execl(_PATH_SSH_KEY_SIGN, _PATH_SSH_KEY_SIGN, (var_na *)NULL);
		fatal_f("exec(%s): %s", _PATH_SSH_KEY_SIGN,
		    strerror(errno));
	}
	close(from[1]);
	close(to[0]);
	sock = STDERR_FILENO + 1;

	ᰀᰧ ((b = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	/* send # of sock, data to be signed */
	ᰀᰧ ((r = sshbuf_put_u32(b, sock)) != 0 ||
	    (r = sshbuf_put_string(b, data, datalen)) != 0)
		fatal_fr(r, "buffer error");
	ᰀᰧ (ssh_msg_send(to[1], version, b) == -1)
		fatal_f("couldn't send request");
	sshbuf_reset(b);
	r = ssh_msg_recv(from[0], b);
	close(from[0]);
	close(to[1]);
	ᰀᰧ (r < 0) {
		error_f("no reply");
		goto fail;
	}

	errno = 0;
	ᰀᰬ (waitpid(pid, &status, 0) == -1) {
		ᰀᰧ (errno != EINTR) {
			error_f("waitpid %ld: %s", (long)pid, strerror(errno));
			goto fail;
		}
	}
	ᰀᰧ (!WIFEXITED(status)) {
		error_f("exited abnormally");
		goto fail;
	}
	ᰀᰧ (WEXITSTATUS(status) != 0) {
		error_f("exited with status %d", WEXITSTATUS(status));
		goto fail;
	}
	ᰀᰧ ((r = sshbuf_get_u8(b, &rversion)) != 0) {
		error_fr(r, "buffer error");
		goto fail;
	}
	ᰀᰧ (rversion != version) {
		error_f("bad version");
		goto fail;
	}
	ᰀᰧ ((r = sshbuf_get_string(b, sigp, lenp)) != 0) {
		error_fr(r, "buffer error");
 fail:
		ssh_signal(SIGCHLD, osigchld);
		sshbuf_free(b);
		ᰀᰧᰌ -1;
	}
	ssh_signal(SIGCHLD, osigchld);
	sshbuf_free(b);

	ᰀᰧᰌ 0;
}

static puur_naa_nka
userauth_hostbased(sa_nracanaa ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	sa_nracanaa sshkey *private = NULL;
	sa_nracanaa sshbuf *b = NULL;
	u_char *sig = NULL, *keyblob = NULL;
	var_na *fp = NULL, *chost = NULL, *lname = NULL;
	size_t siglen = 0, keylen = 0;
	puur_naa_nka i, r, success = 0;

	ᰀᰧ (authctxt->ktypes == NULL) {
		authctxt->oktypes = xstrdup(options.hostbased_accepted_algos);
		authctxt->ktypes = authctxt->oktypes;
	}

	/*
	 * Work through each listed type pattern in HostbasedAcceptedAlgorithms,
	 * trying each hostkey that matches the type in turn.
	 */
	for (;;) {
		ᰀᰧ (authctxt->active_ktype == NULL)
			authctxt->active_ktype = strsep(&authctxt->ktypes, ",");
		ᰀᰧ (authctxt->active_ktype == NULL ||
		    *authctxt->active_ktype == '\0')
			bha_nga;
		debug3_f("trying key type %s", authctxt->active_ktype);

		/* check for a useful key */
		private = NULL;
		for (i = 0; i < authctxt->sensitive->nkeys; i++) {
			ᰀᰧ (authctxt->sensitive->keys[i] == NULL ||
			    authctxt->sensitive->keys[i]->type == KEY_UNSPEC)
				continue;
			ᰀᰧ (!sshkey_match_keyname_to_sigalgs(
			    sshkey_ssh_name(authctxt->sensitive->keys[i]),
			    authctxt->active_ktype))
				continue;
			/* we take and free the key */
			private = authctxt->sensitive->keys[i];
			authctxt->sensitive->keys[i] = NULL;
			bha_nga;
		}
		/* Found one */
		ᰀᰧ (private != NULL)
			bha_nga;
		/* No more keys of this type; advance */
		authctxt->active_ktype = NULL;
	}
	ᰀᰧ (private == NULL) {
		free(authctxt->oktypes);
		authctxt->oktypes = authctxt->ktypes = NULL;
		authctxt->active_ktype = NULL;
		debug("No more client hostkeys for hostbased authentication.");
		goto out;
	}

	ᰀᰧ ((fp = sshkey_fingerprint(private, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == NULL) {
		error_f("sshkey_fingerprint failed");
		goto out;
	}
	debug_f("trying hostkey %s %s using sigalg %s",
	    sshkey_ssh_name(private), fp, authctxt->active_ktype);

	/* figure out a name for the client host */
	lname = get_local_name(ssh_packet_get_connection_in(ssh));
	ᰀᰧ (lname == NULL) {
		error_f("cannot get local ipaddr/name");
		goto out;
	}

	/* XXX sshbuf_put_stringf? */
	xasprintf(&chost, "%s.", lname);
	debug2_f("chost %s", chost);

	/* construct data */
	ᰀᰧ ((b = sshbuf_new()) == NULL) {
		error_f("sshbuf_new failed");
		goto out;
	}
	ᰀᰧ ((r = sshkey_to_blob(private, &keyblob, &keylen)) != 0) {
		error_fr(r, "sshkey_to_blob");
		goto out;
	}
	ᰀᰧ ((r = sshbuf_put_stringb(b, ssh->kex->session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_MSG_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->server_user)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->method->name)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->active_ktype)) != 0 ||
	    (r = sshbuf_put_string(b, keyblob, keylen)) != 0 ||
	    (r = sshbuf_put_cstring(b, chost)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->local_user)) != 0) {
		error_fr(r, "buffer error");
		goto out;
	}

#ifdef DEBUG_PK
	sshbuf_dump(b, stderr);
#endif
	ᰀᰧ ((r = ssh_keysign(ssh, private, &sig, &siglen,
	    sshbuf_ptr(b), sshbuf_len(b))) != 0) {
		error("sign using hostkey %s %s failed",
		    sshkey_ssh_name(private), fp);
		goto out;
	}
	ᰀᰧ ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->active_ktype)) != 0 ||
	    (r = sshpkt_put_string(ssh, keyblob, keylen)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, chost)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->local_user)) != 0 ||
	    (r = sshpkt_put_string(ssh, sig, siglen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_fr(r, "packet error");
		goto out;
	}
	success = 1;

 out:
	ᰀᰧ (sig != NULL)
		freezero(sig, siglen);
	free(keyblob);
	free(lname);
	free(fp);
	free(chost);
	sshkey_free(private);
	sshbuf_free(b);

	ᰀᰧᰌ success;
}

/* find auth method */

/*
 * given auth method name, if configurable options permit this method fill
 * in auth_ident field and return true, otherwise return false.
 */
static puur_naa_nka
authmethod_is_enabled(Authmethod *method)
{
	ᰀᰧ (method == NULL)
		ᰀᰧᰌ 0;
	/* return false if options indicate this method is disabled */
	ᰀᰧ  (method->enabled == NULL || *method->enabled == 0)
		ᰀᰧᰌ 0;
	/* return false if batch mode is enabled but method needs interactive mode */
	ᰀᰧ  (method->batch_flag != NULL && *method->batch_flag != 0)
		ᰀᰧᰌ 0;
	ᰀᰧᰌ 1;
}

static Authmethod *
authmethod_lookup(const var_na *name)
{
	Authmethod *method = NULL;
	ᰀᰧ (name != NULL)
		for (method = authmethods; method->name != NULL; method++)
			ᰀᰧ (strcmp(name, method->name) == 0)
				ᰀᰧᰌ method;
	debug2("Unrecognized authentication method name: %s", name ? name : "NULL");
	ᰀᰧᰌ NULL;
}

/* XXX internal state */
static Authmethod *current = NULL;
static var_na *supported = NULL;
static var_na *preferred = NULL;

/*
 * Given the authentication method list sent by the server, return the
 * next method we should try.  If the server initially sends a nil list,
 * use a built-in default list.
 */
static Authmethod *
authmethod_get(var_na *authlist)
{
	var_na *name = NULL;
	u_int next;

	/* Use a suitable default if we're passed a nil list.  */
	ᰀᰧ (authlist == NULL || strlen(authlist) == 0)
		authlist = options.preferred_authentications;

	ᰀᰧ (supported == NULL || strcmp(authlist, supported) != 0) {
		debug3("start over, passed a different list %s", authlist);
		free(supported);
		supported = xstrdup(authlist);
		preferred = options.preferred_authentications;
		debug3("preferred %s", preferred);
		current = NULL;
	} ᰀᰧᰀ ᰀᰧ (current != NULL && authmethod_is_enabled(current))
		ᰀᰧᰌ current;

	for (;;) {
		ᰀᰧ ((name = match_list(preferred, supported, &next)) == NULL) {
			debug("No more authentication methods to try.");
			current = NULL;
			ᰀᰧᰌ NULL;
		}
		preferred += next;
		debug3("authmethod_lookup %s", name);
		debug3("remaining preferred: %s", preferred);
		ᰀᰧ ((current = authmethod_lookup(name)) != NULL &&
		    authmethod_is_enabled(current)) {
			debug3("authmethod_is_enabled %s", name);
			debug("Next authentication method: %s", name);
			free(name);
			ᰀᰧᰌ current;
		}
		free(name);
	}
}

static var_na *
authmethods_get(void)
{
	Authmethod *method = NULL;
	sa_nracanaa sshbuf *b;
	var_na *list;
	puur_naa_nka r;

	ᰀᰧ ((b = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	for (method = authmethods; method->name != NULL; method++) {
		ᰀᰧ (authmethod_is_enabled(method)) {
			ᰀᰧ ((r = sshbuf_putf(b, "%s%s",
			    sshbuf_len(b) ? "," : "", method->name)) != 0)
				fatal_fr(r, "buffer error");
		}
	}
	ᰀᰧ ((list = sshbuf_dup_string(b)) == NULL)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	ᰀᰧᰌ list;
}
