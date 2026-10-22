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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/socket.h>
#ضمن <sys/wait.h>
#ضمن <sys/queue.h>
#ضمن <sys/stat.h>

#ضمن <errno.h>
#ضمن <fcntl.h>
#ضمن <limits.h>
#ضمن <pwd.h>
#ضمن <signal.h>
#ضمن <stdio.h>
#ضمن <string.h>
#ضمن <stdarg.h>
#ضمن <unistd.h>
#إذا defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
#ضمن <vis.h>
#endif

#ضمن "xmalloc.h"
#ضمن "ssh.h"
#ضمن "ssh2.h"
#ضمن "sshbuf.h"
#ضمن "packet.h"
#ضمن "compat.h"
#ضمن "cipher.h"
#ضمن "sshkey.h"
#ضمن "kex.h"
#ضمن "sshconnect.h"
#ضمن "authfile.h"
#ضمن "authfd.h"
#ضمن "log.h"
#ضمن "misc.h"
#ضمن "readconf.h"
#ضمن "match.h"
#ضمن "dispatch.h"
#ضمن "canohost.h"
#ضمن "msg.h"
#ضمن "pathnames.h"
#ضمن "hostfile.h"
#ضمن "ssherr.h"
#ضمن "utf8.h"
#ضمن "ssh-sk.h"
#ضمن "sk-api.h"

#ifdef GSSAPI
#ضمن "ssh-gss.h"
#endif

/* import */
خارجي Options options;

/*
 * SSH2 key exchange
 */

ساكن حرف *xxx_host;
ساكن بنية sockaddr_storage xxx_hostaddr;
ساكن ثابت بنية ssh_conn_info *xxx_conn_info;
ساكن صحيح ئاچقۇچ_type_allowed(بنية sshkey *, ثابت حرف *);

ساكن صحيح
verify_host_ئاچقۇچ_callback(بنية sshkey *hostkey, بنية ssh *ssh)
{
	صحيح r;

	إذا ((r = sshkey_check_rsa_length(hostkey,
	    options.required_rsa_size)) != 0)
		fatal_r(r, "Bad server host key");
	إذا (!ئاچقۇچ_type_allowed(hostkey, options.hostkeyalgorithms)) {
		fatal("Server host key %s not in HostKeyAlgorithms",
		    sshkey_ssh_name(hostkey));
	}
	إذا (verify_host_ئاچقۇچ(xxx_host, (بنية sockaddr *)&xxx_hostaddr, hostkey,
	    xxx_conn_info) != 0)
		fatal("Host key verification failed.");
	أرجع 0;
}

/* Returns the first item from a comma-separated algorithm list */
ساكن حرف *
first_alg(ثابت حرف *algs)
{
	حرف *ret, *cp;

	ret = xstrdup(algs);
	إذا ((cp = strchr(ret, ',')) != عدم)
		*cp = '\0';
	أرجع ret;
}

ساكن حرف *
order_hostkeyalgs(حرف *host, بنية sockaddr *hostaddr, u_short port,
    ثابت بنية ssh_conn_info *cinfo)
{
	حرف *oavail = عدم, *avail = عدم, *first = عدم, *last = عدم;
	حرف *alg = عدم, *hostname = عدم, *ret = عدم, *best = عدم;
	size_t maxlen;
	بنية hostkeys *hostkeys = عدم;
	صحيح ktype;
	u_int i;

	/* Find all hostkeys for this hostname */
	get_hostfile_hostname_ipaddr(host, hostaddr, port, &hostname, عدم);
	hostkeys = init_hostkeys();
	لكل (i = 0; i < options.رەقەم_user_hostfiles; i++)
		load_hostkeys(hostkeys, hostname, options.user_hostfiles[i], 0);
	لكل (i = 0; i < options.رەقەم_system_hostfiles; i++) {
		load_hostkeys(hostkeys, hostname,
		    options.system_hostfiles[i], 0);
	}
	إذا (options.known_hosts_command != عدم) {
		load_hostkeys_command(hostkeys, options.known_hosts_command,
		    "ORDER", cinfo, عدم, hostname);
	}
	/*
	 * If a plain public key exists that matches the type of the best
	 * preference HostkeyAlgorithms, then use the whole list as is.
	 * Note that we ignore whether the best preference algorithm is a
	 * certificate type, as sshconnect.c will downgrade certs to
	 * plain keys if necessary.
	 */
	best = first_alg(options.hostkeyalgorithms);
	إذا (lookup_ئاچقۇچ_in_hostkeys_by_type(hostkeys,
	    sshkey_type_plain(sshkey_type_from_name(best)),
	    sshkey_ecdsa_nid_from_name(best), عدم)) {
		debug3_f("have matching best-preference key type %s, "
		    "using HostkeyAlgorithms verbatim", best);
		ret = xstrdup(options.hostkeyalgorithms);
		اذهب out;
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
	افعل { \
		إذا (*to != '\0') \
			strlcat(to, ",", maxlen); \
		strlcat(to, from, maxlen); \
	} طالما (0)

	طالما ((alg = strsep(&avail, ",")) && *alg != '\0') {
		إذا ((ktype = sshkey_type_from_name(alg)) == ئاچقۇچ_UNSPEC)
			fatal_f("unknown alg %s", alg);
		/*
		 * If we have a @cert-authority marker in known_hosts then
		 * prefer all certificate algorithms.
		 */
		إذا (sshkey_type_is_cert(ktype) &&
		    lookup_marker_in_hostkeys(hostkeys, MRK_CA)) {
			ALG_APPEND(first, alg);
			استمر;
		}
		/* If the key appears in known_hosts then prefer it */
		إذا (lookup_ئاچقۇچ_in_hostkeys_by_type(hostkeys,
		    sshkey_type_plain(ktype),
		    sshkey_ecdsa_nid_from_name(alg), عدم)) {
			ALG_APPEND(first, alg);
			استمر;
		}
		/* Otherwise, put it last */
		ALG_APPEND(last, alg);
	}
#undef ALG_APPEND
	xasprintf(&ret, "%s%s%s", first,
	    (*first == '\0' || *last == '\0') ? "" : ",", last);
	إذا (*first != '\0')
		debug3_f("prefer hostkeyalgs: %s", first);
	وإلا
		debug3_f("no algorithms matched; accept original");
 out:
	حرر(best);
	حرر(first);
	حرر(last);
	حرر(hostname);
	حرر(oavail);
	free_hostkeys(hostkeys);

	أرجع ret;
}

فراغ
ssh_kex2(بنية ssh *ssh, حرف *host, بنية sockaddr_storage *hostaddr,
    u_short port, ثابت بنية ssh_conn_info *cinfo)
{
	حرف *myproposal[PROPOSAL_MAX];
	حرف *all_ئاچقۇچ, *hkalgs = عدم;
	صحيح r, use_known_hosts_order = 0;

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
	إذا (options.hostkeyalgorithms == عدم ||
	    options.hostkeyalgorithms[0] == '-' ||
	    options.hostkeyalgorithms[0] == '+')
		use_known_hosts_order = 1;

	/* Expand or fill in HostkeyAlgorithms */
	all_ئاچقۇچ = sshkey_alg_list(0, 0, 1, ',');
	إذا ((r = kex_assemble_names(&options.hostkeyalgorithms,
	    kex_default_pk_alg(), all_ئاچقۇچ)) != 0)
		fatal_fr(r, "kex_assemble_namelist");
	حرر(all_ئاچقۇچ);

	إذا (use_known_hosts_order) {
		hkalgs = order_hostkeyalgs(host, (بنية sockaddr *)hostaddr,
		    port, cinfo);
	}

	kex_proposal_populate_entries(ssh, myproposal,
	    options.kex_algorithms, options.ciphers, options.macs,
	    compression_alg_list(options.compression),
	    hkalgs ? hkalgs : options.hostkeyalgorithms);

	حرر(hkalgs);

	/* start key exchange */
	إذا ((r = kex_setup(ssh, myproposal)) != 0)
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
	ssh->kex->verify_host_ئاچقۇچ=&verify_host_ئاچقۇچ_callback;

	ssh_dispatch_run_fatal(ssh, DISPATCH_BLOCK, &ssh->kex->done);
	kex_proposal_free_entries(myproposal);

#ifdef DEBUG_KEXDH
	/* send 1st encrypted/maced/compressed message */
	إذا ((r = sshpkt_start(ssh, SSH2_ئۇچۇر_IGNORE)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "markus")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send packet");
#endif
}

/*
 * Authenticate user
 */

تعريفنوع بنية cauthctxt Authctxt;
تعريفنوع بنية cauthmethod Authmethod;
تعريفنوع بنية identity Identity;
تعريفنوع بنية idlist Idlist;

بنية identity {
	TAILQ_ENTRY(identity) next;
	صحيح	agent_fd;		/* >=0 if agent supports key */
	بنية sshkey	*ئاچقۇچ;		/* public/private key */
	حرف	*filename;		/* comment for agent-only keys */
	صحيح	tried;
	صحيح	isprivate;		/* key points to the private key */
	صحيح	userprovided;
};
TAILQ_HEAD(idlist, identity);

بنية cauthctxt {
	ثابت حرف *server_user;
	ثابت حرف *local_user;
	ثابت حرف *host;
	ثابت حرف *service;
	بنية cauthmethod *method;
	sig_atomic_t success;
	حرف *authlist;
#ifdef GSSAPI
	/* gssapi */
	gss_OID_set gss_supported_mechs;
	u_int mech_tried;
#endif
	/* pubkey */
	بنية idlist ئاچقۇچلار;
	صحيح agent_fd;
	/* hostbased */
	Sensitive *sensitive;
	حرف *oktypes, *ktypes;
	ثابت حرف *active_ktype;
	/* kbd-interactive */
	صحيح info_req_seen;
	صحيح attempt_kbdint;
	/* password */
	صحيح attempt_passwd;
	/* generic */
	فراغ *methoddata;
};

بنية cauthmethod {
	حرف	*name;		/* string to compare against server's list */
	صحيح	(*userauth)(بنية ssh *ssh);
	فراغ	(*cleanup)(بنية ssh *ssh);
	صحيح	*enabled;	/* flag in option struct that enables method */
	صحيح	*batch_flag;	/* flag in option struct that disables method */
};

ساكن صحيح كىرگۈزۈش_userauth_service_accept(صحيح, uint32_t, بنية ssh *);
ساكن صحيح كىرگۈزۈش_userauth_success(صحيح, uint32_t, بنية ssh *);
ساكن صحيح كىرگۈزۈش_userauth_failure(صحيح, uint32_t, بنية ssh *);
ساكن صحيح كىرگۈزۈش_userauth_banner(صحيح, uint32_t, بنية ssh *);
ساكن صحيح كىرگۈزۈش_userauth_error(صحيح, uint32_t, بنية ssh *);
ساكن صحيح كىرگۈزۈش_userauth_info_req(صحيح, uint32_t, بنية ssh *);
ساكن صحيح كىرگۈزۈش_userauth_pk_ok(صحيح, uint32_t, بنية ssh *);
ساكن صحيح كىرگۈزۈش_userauth_passwd_changereq(صحيح, uint32_t, بنية ssh *);

ساكن صحيح userauth_none(بنية ssh *);
ساكن صحيح userauth_pubkey(بنية ssh *);
ساكن صحيح userauth_passwd(بنية ssh *);
ساكن صحيح userauth_kbdint(بنية ssh *);
ساكن صحيح userauth_hostbased(بنية ssh *);

#ifdef GSSAPI
ساكن صحيح userauth_gssapi(بنية ssh *);
ساكن فراغ userauth_gssapi_cleanup(بنية ssh *);
ساكن صحيح كىرگۈزۈش_gssapi_response(صحيح type, uint32_t, بنية ssh *);
ساكن صحيح كىرگۈزۈش_gssapi_token(صحيح type, uint32_t, بنية ssh *);
ساكن صحيح كىرگۈزۈش_gssapi_error(صحيح, uint32_t, بنية ssh *);
ساكن صحيح كىرگۈزۈش_gssapi_errtok(صحيح, uint32_t, بنية ssh *);
#endif

فراغ	userauth(بنية ssh *, حرف *);

ساكن فراغ pubkey_cleanup(بنية ssh *);
ساكن صحيح sign_and_send_pubkey(بنية ssh *ssh, Identity *);
ساكن فراغ pubkey_prepare(بنية ssh *, Authctxt *);
ساكن فراغ pubkey_reset(Authctxt *);
ساكن بنية sshkey *load_identity_file(Identity *);

ساكن Authmethod *authmethod_get(حرف *authlist);
ساكن Authmethod *authmethod_lookup(ثابت حرف *name);
ساكن حرف *authmethods_get(فراغ);

Authmethod authmethods[] = {
#ifdef GSSAPI
	{"gssapi-with-mic",
		userauth_gssapi,
		userauth_gssapi_cleanup,
		&options.gss_authentication,
		عدم},
#endif
	{"hostbased",
		userauth_hostbased,
		عدم,
		&options.hostbased_authentication,
		عدم},
	{"publickey",
		userauth_pubkey,
		عدم,
		&options.pubkey_authentication,
		عدم},
	{"keyboard-interactive",
		userauth_kbdint,
		عدم,
		&options.kbd_interactive_authentication,
		&options.batch_mode},
	{"password",
		userauth_passwd,
		عدم,
		&options.password_authentication,
		&options.batch_mode},
	{"none",
		userauth_none,
		عدم,
		عدم,
		عدم},
	{عدم, عدم, عدم, عدم, عدم}
};

فراغ
ssh_userauth2(بنية ssh *ssh, ثابت حرف *local_user,
    ثابت حرف *server_user, حرف *host, Sensitive *sensitive)
{
	Authctxt authctxt;
	صحيح r;

	إذا (options.preferred_authentications == عدم)
		options.preferred_authentications = authmethods_get();

	/* setup authentication context */
	memset(&authctxt, 0, حجم(authctxt));
	authctxt.server_user = server_user;
	authctxt.local_user = local_user;
	authctxt.host = host;
	authctxt.service = "ssh-connection";		/* service name */
	authctxt.success = 0;
	authctxt.method = authmethod_lookup("none");
	authctxt.authlist = عدم;
	authctxt.methoddata = عدم;
	authctxt.sensitive = sensitive;
	authctxt.active_ktype = authctxt.oktypes = authctxt.ktypes = عدم;
	authctxt.info_req_seen = 0;
	authctxt.attempt_kbdint = 0;
	authctxt.attempt_passwd = 0;
#إذا GSSAPI
	authctxt.gss_supported_mechs = عدم;
	authctxt.mech_tried = 0;
#endif
	authctxt.agent_fd = -1;
	إذا (authctxt.method == عدم)
		fatal_f("internal error: cannot send userauth none request");

	إذا ((r = sshpkt_start(ssh, SSH2_ئۇچۇر_SERVICE_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "ssh-userauth")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh->authctxt = &authctxt;
	ssh_dispatch_init(ssh, &كىرگۈزۈش_userauth_error);
	ssh_dispatch_set(ssh, SSH2_ئۇچۇر_EXT_INFO, kex_كىرگۈزۈش_ext_info);
	ssh_dispatch_set(ssh, SSH2_ئۇچۇر_SERVICE_ACCEPT, &كىرگۈزۈش_userauth_service_accept);
	ssh_dispatch_run_fatal(ssh, DISPATCH_BLOCK, &authctxt.success);	/* loop until success */
	pubkey_cleanup(ssh);
#ifdef GSSAPI
	إذا (authctxt.gss_supported_mechs != عدم) {
		u_int ms;

		gss_release_oid_set(&ms, &authctxt.gss_supported_mechs);
		authctxt.gss_supported_mechs = عدم;
	}
#endif
	ssh->authctxt = عدم;

	ssh_dispatch_range(ssh, SSH2_ئۇچۇر_USERAUTH_MIN, SSH2_ئۇچۇر_USERAUTH_MAX, عدم);

	إذا (!authctxt.success)
		fatal("Authentication failed.");
	إذا (ssh_packet_connection_is_on_socket(ssh)) {
		verbose("Authenticated to %s ([%s]:%d) using \"%s\".", host,
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    authctxt.method->name);
	} وإلا {
		verbose("Authenticated to %s (via proxy) using \"%s\".", host,
		    authctxt.method->name);
	}
}

ساكن صحيح
كىرگۈزۈش_userauth_service_accept(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	صحيح r;

	إذا (ssh_packet_remaining(ssh) > 0) {
		حرف *reply;

		إذا ((r = sshpkt_get_cstring(ssh, &reply, عدم)) != 0)
			اذهب out;
		debug2("service_accept: %s", reply);
		حرر(reply);
	} وإلا {
		debug2("buggy server: service_accept w/o service");
	}
	إذا ((r = sshpkt_get_end(ssh)) != 0)
		اذهب out;
	debug("SSH2_MSG_SERVICE_ACCEPT received");

	/* initial userauth request */
	userauth_none(ssh);

	/* accept EXT_INFO at any time during userauth */
	ssh_dispatch_set(ssh, SSH2_ئۇچۇر_EXT_INFO, ssh->kex->ext_info_s ?
	    &kex_كىرگۈزۈش_ext_info : &كىرگۈزۈش_userauth_error);
	ssh_dispatch_set(ssh, SSH2_ئۇچۇر_USERAUTH_SUCCESS, &كىرگۈزۈش_userauth_success);
	ssh_dispatch_set(ssh, SSH2_ئۇچۇر_USERAUTH_FAILURE, &كىرگۈزۈش_userauth_failure);
	ssh_dispatch_set(ssh, SSH2_ئۇچۇر_USERAUTH_BANNER, &كىرگۈزۈش_userauth_banner);
	r = 0;
 out:
	أرجع r;
}

فراغ
userauth(بنية ssh *ssh, حرف *authlist)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;

	إذا (authctxt->method != عدم && authctxt->method->cleanup != عدم)
		authctxt->method->cleanup(ssh);

	حرر(authctxt->methoddata);
	authctxt->methoddata = عدم;
	إذا (authlist == عدم) {
		authlist = authctxt->authlist;
	} وإلا {
		حرر(authctxt->authlist);
		authctxt->authlist = authlist;
	}
	لكل (;;) {
		Authmethod *method = authmethod_get(authlist);
		إذا (method == عدم)
			fatal("%s@%s: Permission denied (%s).",
			    authctxt->server_user, authctxt->host, authlist);
		authctxt->method = method;

		/* reset the per method handler */
		ssh_dispatch_range(ssh, SSH2_ئۇچۇر_USERAUTH_PER_METHOD_MIN,
		    SSH2_ئۇچۇر_USERAUTH_PER_METHOD_MAX, عدم);

		/* and try new method */
		إذا (method->userauth(ssh) != 0) {
			debug2("we sent a %s packet, wait for reply", method->name);
			اكسر;
		} وإلا {
			debug2("we did not send a packet, disable method");
			method->enabled = عدم;
		}
	}
}

ساكن صحيح
كىرگۈزۈش_userauth_error(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	fatal_f("bad message during authentication: type %d", type);
	أرجع 0;
}

ساكن صحيح
كىرگۈزۈش_userauth_banner(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	حرف *ئۇچۇر = عدم;
	size_t len;
	صحيح r;

	debug3_f("entering");
	إذا ((r = sshpkt_get_cstring(ssh, &ئۇچۇر, &len)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, عدم, عدم)) != 0)
		اذهب out;
	إذا (len > 0 && options.log_level >= SYSLOG_LEVEL_INFO)
		fmprintf(stderr, "%s", ئۇچۇر);
	r = 0;
 out:
	حرر(ئۇچۇر);
	أرجع r;
}

ساكن صحيح
كىرگۈزۈش_userauth_success(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	إذا (authctxt == عدم)
		fatal_f("no authentication context");
	حرر(authctxt->authlist);
	authctxt->authlist = عدم;
	إذا (authctxt->method != عدم && authctxt->method->cleanup != عدم)
		authctxt->method->cleanup(ssh);
	حرر(authctxt->methoddata);
	authctxt->methoddata = عدم;
	authctxt->success = 1;			/* break out */
	ssh_dispatch_set(ssh, SSH2_ئۇچۇر_EXT_INFO, dispatch_protocol_error);
	أرجع 0;
}

#إذا 0
ساكن صحيح
كىرگۈزۈش_userauth_success_unexpected(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	إذا (authctxt == عدم)
		fatal_f("no authentication context");

	fatal("Unexpected authentication success during %s.",
	    authctxt->method->name);
	أرجع 0;
}
#endif

ساكن صحيح
كىرگۈزۈش_userauth_failure(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	حرف *authlist = عدم;
	u_char partial;

	إذا (authctxt == عدم)
		fatal("input_userauth_failure: no authentication context");

	إذا (sshpkt_get_cstring(ssh, &authlist, عدم) != 0 ||
	    sshpkt_get_u8(ssh, &partial) != 0 ||
	    sshpkt_get_end(ssh) != 0)
		اذهب out;

	إذا (partial != 0) {
		verbose("Authenticated using \"%s\" with partial success.",
		    authctxt->method->name);
		/* reset state */
		pubkey_reset(authctxt);
	}
	debug("Authentications that can continue: %s", authlist);

	userauth(ssh, authlist);
	authlist = عدم;
 out:
	حرر(authlist);
	أرجع 0;
}

/*
 * Format an identity for logging including filename, key type, fingerprint
 * and location (agent, etc.). Caller must free.
 */
ساكن حرف *
format_identity(Identity *id)
{
	حرف *fp = عدم, *ret = عدم;
	ثابت حرف *note = "";

	إذا (id->ئاچقۇچ != عدم) {
		fp = sshkey_fingerprint(id->ئاچقۇچ, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
	}
	إذا (id->ئاچقۇچ) {
		إذا ((id->ئاچقۇچ->flags & SSHKEY_FLAG_EXT) != 0)
			note = " token";
		وإلا إذا (sshkey_is_sk(id->ئاچقۇچ))
			note = " authenticator";
	}
	xasprintf(&ret, "%s %s%s%s%s%s%s",
	    id->filename,
	    id->ئاچقۇچ ? sshkey_type(id->ئاچقۇچ) : "", id->ئاچقۇچ ? " " : "",
	    fp ? fp : "",
	    id->userprovided ? " explicit" : "", note,
	    id->agent_fd != -1 ? " agent" : "");
	حرر(fp);
	أرجع ret;
}

ساكن صحيح
كىرگۈزۈش_userauth_pk_ok(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	بنية sshkey *ئاچقۇچ = عدم;
	بنية sshbuf *keyblob = عدم;
	Identity *id = عدم;
	صحيح pktype, found = 0, sent = 0;
	حرف *pkalg = عدم, *fp = عدم, *ident = عدم;
	صحيح r;

	إذا (authctxt == عدم)
		fatal_f("no authentication context");

	إذا ((r = sshpkt_get_cstring(ssh, &pkalg, عدم)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		اذهب done;

	إذا (match_pattern_list(pkalg, options.pubkey_accepted_algos, 0) != 1) {
		error_f("server replied to PK_OK with signature type %s not "
		    "in PubkeyAcceptedAlgorithms", pkalg);
		r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		اذهب done;
	}
	إذا ((pktype = sshkey_type_from_name(pkalg)) == ئاچقۇچ_UNSPEC) {
		debug_f("server sent unknown pkalg %s", pkalg);
		r = SSH_ERR_INVALID_FORMAT;
		اذهب done;
	}
	/* inner key type should match signature type */
	إذا ((r = sshkey_fromb_allowlist(keyblob, &ئاچقۇچ, pkalg, عدم)) != 0) {
		debug_r(r, "no key from blob. pkalg %s", pkalg);
		اذهب done;
	}
	إذا (ئاچقۇچ->type != pktype) {
		error("input_userauth_pk_ok: type mismatch "
		    "for decoded key (received %d, expected %d)",
		    ئاچقۇچ->type, pktype);
		r = SSH_ERR_INVALID_FORMAT;
		اذهب done;
	}

	/*
	 * search keys in the reverse order, because last candidate has been
	 * moved to the end of the queue.  this also avoids confusion by
	 * duplicate keys
	 */
	TAILQ_FOREACH_REVERSE(id, &authctxt->ئاچقۇچلار, idlist, next) {
		إذا (sshkey_equal(ئاچقۇچ, id->ئاچقۇچ)) {
			found = 1;
			اكسر;
		}
	}
	إذا (!found || id == عدم) {
		fp = sshkey_fingerprint(ئاچقۇچ, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		error_f("server replied with unknown key: %s %s",
		    sshkey_type(ئاچقۇچ), fp == عدم ? "<ERROR>" : fp);
		r = SSH_ERR_INVALID_FORMAT;
		اذهب done;
	}
	ident = format_identity(id);
	debug("Server accepts key: %s", ident);
	sent = sign_and_send_pubkey(ssh, id);
	r = 0;
 done:
	sshkey_free(ئاچقۇچ);
	sshbuf_free(keyblob);
	حرر(ident);
	حرر(fp);
	حرر(pkalg);

	/* try another method if we did not send a packet */
	إذا (r == 0 && sent == 0)
		userauth(ssh, عدم);
	أرجع r;
}

#ifdef GSSAPI
ساكن صحيح
userauth_gssapi(بنية ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Gssctxt *gssctxt = عدم;
	OM_uint32 min;
	صحيح r, ok = 0;
	gss_OID mech = عدم;

	/* Try one GSSAPI method at a time, rather than sending them all at
	 * once. */

	إذا (authctxt->gss_supported_mechs == عدم)
		gss_indicate_mechs(&min, &authctxt->gss_supported_mechs);

	/* Check to see whether the mechanism is usable before we offer it */
	طالما (authctxt->mech_tried < authctxt->gss_supported_mechs->سانى &&
	    !ok) {
		mech = &authctxt->gss_supported_mechs->
		    elements[authctxt->mech_tried];
		/* My DER encoding requires length<128 */
		إذا (mech->length < 128 && ssh_gssapi_check_mechanism(&gssctxt,
		    mech, authctxt->host)) {
			ok = 1; /* Mechanism works */
		} وإلا {
			authctxt->mech_tried++;
		}
	}

	إذا (!ok || mech == عدم)
		أرجع 0;

	authctxt->methoddata=(فراغ *)gssctxt;

	إذا ((r = sshpkt_start(ssh, SSH2_ئۇچۇر_USERAUTH_REQUEST)) != 0 ||
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

	ssh_dispatch_set(ssh, SSH2_ئۇچۇر_USERAUTH_GSSAPI_RESPONSE, &كىرگۈزۈش_gssapi_response);
	ssh_dispatch_set(ssh, SSH2_ئۇچۇر_USERAUTH_GSSAPI_TOKEN, &كىرگۈزۈش_gssapi_token);
	ssh_dispatch_set(ssh, SSH2_ئۇچۇر_USERAUTH_GSSAPI_ERROR, &كىرگۈزۈش_gssapi_error);
	ssh_dispatch_set(ssh, SSH2_ئۇچۇر_USERAUTH_GSSAPI_ERRTOK, &كىرگۈزۈش_gssapi_errtok);

	authctxt->mech_tried++; /* Move along to next candidate */

	أرجع 1;
}

ساكن فراغ
userauth_gssapi_cleanup(بنية ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Gssctxt *gssctxt = (Gssctxt *)authctxt->methoddata;

	ssh_gssapi_delete_ctx(&gssctxt);
	authctxt->methoddata = عدم;
}

ساكن OM_uint32
process_gssapi_token(بنية ssh *ssh, gss_buffer_t recv_tok)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt = authctxt->methoddata;
	gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc mic = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc gssbuf;
	OM_uint32 status, ms, flags;
	صحيح r;

	status = ssh_gssapi_init_ctx(gssctxt, options.gss_deleg_creds,
	    recv_tok, &send_tok, &flags);

	إذا (send_tok.length > 0) {
		u_char type = GSS_ERROR(status) ?
		    SSH2_ئۇچۇر_USERAUTH_GSSAPI_ERRTOK :
		    SSH2_ئۇچۇر_USERAUTH_GSSAPI_TOKEN;

		إذا ((r = sshpkt_start(ssh, type)) != 0 ||
		    (r = sshpkt_put_string(ssh, send_tok.قىممەت,
		    send_tok.length)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send %u packet", type);

		gss_release_buffer(&ms, &send_tok);
	}

	إذا (status == GSS_S_COMPLETE) {
		/* send either complete or MIC, depending on mechanism */
		إذا (!(flags & GSS_C_INTEG_FLAG)) {
			إذا ((r = sshpkt_start(ssh,
			    SSH2_ئۇچۇر_USERAUTH_GSSAPI_EXCHANGE_COMPLETE)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "send completion");
		} وإلا {
			بنية sshbuf *b;

			إذا ((b = sshbuf_new()) == عدم)
				fatal_f("sshbuf_new failed");
			ssh_gssapi_buildmic(b, authctxt->server_user,
			    authctxt->service, "gssapi-with-mic",
			    ssh->kex->session_id);

			إذا ((gssbuf.قىممەت = sshbuf_mutable_ptr(b)) == عدم)
				fatal_f("sshbuf_mutable_ptr failed");
			gssbuf.length = sshbuf_len(b);

			status = ssh_gssapi_sign(gssctxt, &gssbuf, &mic);

			إذا (!GSS_ERROR(status)) {
				إذا ((r = sshpkt_start(ssh,
				    SSH2_ئۇچۇر_USERAUTH_GSSAPI_MIC)) != 0 ||
				    (r = sshpkt_put_string(ssh, mic.قىممەت,
				    mic.length)) != 0 ||
				    (r = sshpkt_send(ssh)) != 0)
					fatal_fr(r, "send MIC");
			}

			sshbuf_free(b);
			gss_release_buffer(&ms, &mic);
		}
	}

	أرجع status;
}

ساكن صحيح
كىرگۈزۈش_gssapi_response(صحيح type, uint32_t plen, بنية ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	size_t oidlen;
	u_char *oidv = عدم;
	صحيح r;

	إذا (authctxt == عدم)
		fatal("input_gssapi_response: no authentication context");
	gssctxt = authctxt->methoddata;

	/* Setup our OID */
	إذا ((r = sshpkt_get_string(ssh, &oidv, &oidlen)) != 0)
		اذهب done;

	إذا (oidlen <= 2 ||
	    oidv[0] != SSH_GSS_OIDTYPE ||
	    oidv[1] != oidlen - 2) {
		debug("Badly encoded mechanism OID received");
		userauth(ssh, عدم);
		اذهب ok;
	}

	إذا (!ssh_gssapi_check_oid(gssctxt, oidv + 2, oidlen - 2))
		fatal("Server returned different OID than expected");

	إذا ((r = sshpkt_get_end(ssh)) != 0)
		اذهب done;

	إذا (GSS_ERROR(process_gssapi_token(ssh, GSS_C_NO_BUFFER))) {
		/* Start again with next method on list */
		debug("Trying to start again");
		userauth(ssh, عدم);
		اذهب ok;
	}
 ok:
	r = 0;
 done:
	حرر(oidv);
	أرجع r;
}

ساكن صحيح
كىرگۈزۈش_gssapi_token(صحيح type, uint32_t plen, بنية ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	gss_buffer_desc recv_tok;
	u_char *p = عدم;
	size_t len;
	OM_uint32 status;
	صحيح r;

	إذا (authctxt == عدم)
		fatal("input_gssapi_response: no authentication context");

	إذا ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		اذهب out;

	recv_tok.قىممەت = p;
	recv_tok.length = len;
	status = process_gssapi_token(ssh, &recv_tok);

	/* Start again with the next method in the list */
	إذا (GSS_ERROR(status)) {
		userauth(ssh, عدم);
		/* ok */
	}
	r = 0;
 out:
	حرر(p);
	أرجع r;
}

ساكن صحيح
كىرگۈزۈش_gssapi_errtok(صحيح type, uint32_t plen, بنية ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc recv_tok;
	OM_uint32 ms;
	u_char *p = عدم;
	size_t len;
	صحيح r;

	إذا (authctxt == عدم)
		fatal("input_gssapi_response: no authentication context");
	gssctxt = authctxt->methoddata;

	إذا ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0) {
		حرر(p);
		أرجع r;
	}

	/* Stick it into GSSAPI and see what it says */
	recv_tok.قىممەت = p;
	recv_tok.length = len;
	(فراغ)ssh_gssapi_init_ctx(gssctxt, options.gss_deleg_creds,
	    &recv_tok, &send_tok, عدم);
	حرر(p);
	gss_release_buffer(&ms, &send_tok);

	/* Server will be returning a failed packet after this one */
	أرجع 0;
}

ساكن صحيح
كىرگۈزۈش_gssapi_error(صحيح type, uint32_t plen, بنية ssh *ssh)
{
	حرف *ئۇچۇر = عدم;
	حرف *lang = عدم;
	صحيح r;

	إذا ((r = sshpkt_get_u32(ssh, عدم)) != 0 ||	/* maj */
	    (r = sshpkt_get_u32(ssh, عدم)) != 0 ||	/* min */
	    (r = sshpkt_get_cstring(ssh, &ئۇچۇر, عدم)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, عدم)) != 0)
		اذهب out;
	r = sshpkt_get_end(ssh);
	debug("Server GSSAPI Error:\n%s", ئۇچۇر);
 out:
	حرر(ئۇچۇر);
	حرر(lang);
	أرجع r;
}
#endif /* GSSAPI */

ساكن صحيح
userauth_none(بنية ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	صحيح r;

	/* initial userauth request */
	إذا ((r = sshpkt_start(ssh, SSH2_ئۇچۇر_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	أرجع 1;
}

ساكن صحيح
userauth_passwd(بنية ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	حرف *password, *prompt = عدم;
	ثابت حرف *host = options.host_ئاچقۇچ_alias ?  options.host_ئاچقۇچ_alias :
	    authctxt->host;
	صحيح r;

	إذا (authctxt->attempt_passwd++ >= options.سان_of_password_prompts)
		أرجع 0;

	إذا (authctxt->attempt_passwd != 1)
		error("Permission denied, please try again.");

	xasprintf(&prompt, "%s@%s's password: ", authctxt->server_user, host);
	password = read_passphrase(prompt, 0);
	إذا ((r = sshpkt_start(ssh, SSH2_ئۇچۇر_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, password)) != 0 ||
	    (r = sshpkt_add_padding(ssh, 64)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	حرر(prompt);
	إذا (password != عدم)
		freezero(password, strlen(password));

	ssh_dispatch_set(ssh, SSH2_ئۇچۇر_USERAUTH_PASSWD_CHANGEREQ,
	    &كىرگۈزۈش_userauth_passwd_changereq);

	أرجع 1;
}

/*
 * parse PASSWD_CHANGEREQ, prompt user and send SSH2_MSG_USERAUTH_REQUEST
 */
ساكن صحيح
كىرگۈزۈش_userauth_passwd_changereq(صحيح type, uint32_t seqnr, بنية ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	حرف *info = عدم, *lang = عدم, *password = عدم, *retype = عدم;
	حرف prompt[256];
	ثابت حرف *host;
	صحيح r, addnl;
	size_t len;

	debug2("input_userauth_passwd_changereq");

	إذا (authctxt == عدم)
		fatal("input_userauth_passwd_changereq: "
		    "no authentication context");
	host = options.host_ئاچقۇچ_alias ? options.host_ئاچقۇچ_alias : authctxt->host;

	إذا ((r = sshpkt_get_cstring(ssh, &info, عدم)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, عدم)) != 0)
		اذهب out;
	إذا ((len = strlen(info)) > 0) {
		addnl = info[len] != '\n';
		fmprintf(stderr, "%s%s", info, addnl ? "\n" : "");
	}
	إذا ((r = sshpkt_start(ssh, SSH2_ئۇچۇر_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0)	/* additional info */
		اذهب out;

	snprintf(prompt, حجم(prompt),
	    "Enter %.30s@%.128s's old password: ",
	    authctxt->server_user, host);
	password = read_passphrase(prompt, 0);
	إذا ((r = sshpkt_put_cstring(ssh, password)) != 0)
		اذهب out;

	freezero(password, strlen(password));
	password = عدم;
	طالما (password == عدم) {
		snprintf(prompt, حجم(prompt),
		    "Enter %.30s@%.128s's new password: ",
		    authctxt->server_user, host);
		password = read_passphrase(prompt, RP_ALLOW_EOF);
		إذا (password == عدم) {
			/* bail out */
			r = 0;
			اذهب out;
		}
		snprintf(prompt, حجم(prompt),
		    "Retype %.30s@%.128s's new password: ",
		    authctxt->server_user, host);
		retype = read_passphrase(prompt, 0);
		إذا (strcmp(password, retype) != 0) {
			freezero(password, strlen(password));
			logit("Mismatch; try again, EOF to quit.");
			password = عدم;
		}
		freezero(retype, strlen(retype));
	}
	إذا ((r = sshpkt_put_cstring(ssh, password)) != 0 ||
	    (r = sshpkt_add_padding(ssh, 64)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		اذهب out;

	ssh_dispatch_set(ssh, SSH2_ئۇچۇر_USERAUTH_PASSWD_CHANGEREQ,
	    &كىرگۈزۈش_userauth_passwd_changereq);
	r = 0;
 out:
	إذا (password)
		freezero(password, strlen(password));
	حرر(info);
	حرر(lang);
	أرجع r;
}

/*
 * Select an algorithm for publickey signatures.
 * Returns algorithm (caller must free) or NULL if no mutual algorithm found.
 *
 * Call with ssh==NULL to ignore server-sig-algs extension list and
 * only attempt with the key's base signature type.
 */
ساكن حرف *
ئاچقۇچ_sig_algorithm(بنية ssh *ssh, ثابت بنية sshkey *ئاچقۇچ)
{
	حرف *allowed, *oallowed, *cp, *tmp, *alg = عدم;
	ثابت حرف *server_sig_algs;

	/*
	 * The signature algorithm will only differ from the key algorithm
	 * for RSA keys/certs and when the server advertises support for
	 * newer (SHA2) algorithms.
	 */
	إذا (ssh == عدم || ssh->kex->server_sig_algs == عدم ||
	    (ئاچقۇچ->type != ئاچقۇچ_RSA && ئاچقۇچ->type != ئاچقۇچ_RSA_CERT) ||
	    (ئاچقۇچ->type == ئاچقۇچ_RSA_CERT && (ssh->compat & SSH_BUG_SIGTYPE))) {
		/* Filter base key signature alg against our configuration */
		أرجع match_list(sshkey_ssh_name(ئاچقۇچ),
		    options.pubkey_accepted_algos, عدم);
	}

	/*
	 * Workaround OpenSSH 7.4 bug: this version supports RSA/SHA-2 but
	 * fails to advertise it via SSH2_MSG_EXT_INFO.
	 */
	server_sig_algs = ssh->kex->server_sig_algs;
	إذا (ئاچقۇچ->type == ئاچقۇچ_RSA && (ssh->compat & SSH_BUG_SIGTYPE74))
		server_sig_algs = "rsa-sha2-256,rsa-sha2-512";

	/*
	 * For RSA keys/certs, since these might have a different sig type:
	 * find the first entry in PubkeyAcceptedAlgorithms of the right type
	 * that also appears in the supported signature algorithms list from
	 * the server.
	 */
	oallowed = allowed = xstrdup(options.pubkey_accepted_algos);
	طالما ((cp = strsep(&allowed, ",")) != عدم) {
		إذا (sshkey_type_from_name(cp) != ئاچقۇچ->type)
			استمر;
		tmp = match_list(sshkey_sigalg_by_name(cp),
		    server_sig_algs, عدم);
		إذا (tmp != عدم)
			alg = xstrdup(cp);
		حرر(tmp);
		إذا (alg != عدم)
			اكسر;
	}
	حرر(oallowed);
	أرجع alg;
}

ساكن صحيح
identity_sign(بنية identity *id, u_char **sigp, size_t *lenp,
    ثابت u_char *data, size_t datalen, u_int compat, ثابت حرف *alg)
{
	بنية sshkey *sign_ئاچقۇچ = عدم, *prv = عدم;
	صحيح is_agent = 0, retried = 0, r = SSH_ERR_INTERNAL_ERROR;
	بنية notifier_ctx *notifier = عدم;
	حرف *fp = عدم, *pin = عدم, *prompt = عدم;

	*sigp = عدم;
	*lenp = 0;

	/* The agent supports this key. */
	إذا (id->ئاچقۇچ != عدم && id->agent_fd != -1) {
		أرجع ssh_agent_sign(id->agent_fd, id->ئاچقۇچ, sigp, lenp,
		    data, datalen, alg, compat);
	}

	/*
	 * We have already loaded the private key or the private key is
	 * stored in external hardware.
	 */
	إذا (id->ئاچقۇچ != عدم &&
	    (id->isprivate || (id->ئاچقۇچ->flags & SSHKEY_FLAG_EXT))) {
		sign_ئاچقۇچ = id->ئاچقۇچ;
		is_agent = 1;
	} وإلا {
		/* Load the private key from the file. */
		إذا ((prv = load_identity_file(id)) == عدم)
			أرجع SSH_ERR_ئاچقۇچ_NOT_FOUND;
		إذا (id->ئاچقۇچ != عدم && !sshkey_equal_public(prv, id->ئاچقۇچ)) {
			error_f("private key %s contents do not match public",
			    id->filename);
			r = SSH_ERR_ئاچقۇچ_NOT_FOUND;
			اذهب out;
		}
		sign_ئاچقۇچ = prv;
	}
 retry_pin:
	/* Prompt for touch for non-agent FIDO keys that request UP */
	إذا (!is_agent && sshkey_is_sk(sign_ئاچقۇچ) &&
	    (sign_ئاچقۇچ->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
		/* XXX should batch mode just skip these? */
		إذا ((fp = sshkey_fingerprint(sign_ئاچقۇچ,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == عدم)
			fatal_f("fingerprint failed");
		notifier = notify_start(options.batch_mode,
		    "Confirm user presence for key %s %s",
		    sshkey_type(sign_ئاچقۇچ), fp);
		حرر(fp);
	}
	إذا ((r = sshkey_sign(sign_ئاچقۇچ, sigp, lenp, data, datalen,
	    alg, options.sk_provider, pin, compat)) != 0) {
		debug_fr(r, "sshkey_sign");
		إذا (!retried && pin == عدم && !is_agent &&
		    sshkey_is_sk(sign_ئاچقۇچ) &&
		    r == SSH_ERR_ئاچقۇچ_WRONG_PASSPHRASE) {
			notify_complete(notifier, عدم);
			notifier = عدم;
			xasprintf(&prompt, "Enter PIN for %s key %s: ",
			    sshkey_type(sign_ئاچقۇچ), id->filename);
			pin = read_passphrase(prompt, 0);
			retried = 1;
			اذهب retry_pin;
		}
		اذهب out;
	}

	/*
	 * PKCS#11 tokens may not support all signature algorithms,
	 * so check what we get back.
	 */
	إذا (id->ئاچقۇچ != عدم && (id->ئاچقۇچ->flags & SSHKEY_FLAG_EXT) != 0 &&
	    (r = sshkey_check_sigtype(*sigp, *lenp, alg)) != 0) {
		debug_fr(r, "sshkey_check_sigtype");
		اذهب out;
	}
	/* success */
	r = 0;
 out:
	حرر(prompt);
	إذا (pin != عدم)
		freezero(pin, strlen(pin));
	notify_complete(notifier, r == 0 ? "User presence confirmed" : عدم);
	sshkey_free(prv);
	أرجع r;
}

ساكن صحيح
id_filename_matches(Identity *id, Identity *private_id)
{
	ساكن ثابت حرف * ثابت suffixes[] = { ".pub", "-cert.pub", عدم };
	size_t len = strlen(id->filename), plen = strlen(private_id->filename);
	size_t i, slen;

	إذا (strcmp(id->filename, private_id->filename) == 0)
		أرجع 1;
	لكل (i = 0; suffixes[i]; i++) {
		slen = strlen(suffixes[i]);
		إذا (len > slen && plen == len - slen &&
		    strcmp(id->filename + (len - slen), suffixes[i]) == 0 &&
		    memcmp(id->filename, private_id->filename, plen) == 0)
			أرجع 1;
	}
	أرجع 0;
}

ساكن صحيح
sign_and_send_pubkey(بنية ssh *ssh, Identity *id)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	بنية sshbuf *b = عدم;
	Identity *private_id, *sign_id = عدم;
	u_char *signature = عدم;
	size_t slen = 0, skip = 0;
	صحيح r, fallback_sigtype, sent = 0;
	حرف *alg = عدم, *fp = عدم;
	ثابت حرف *loc = "", *method = "publickey";
	صحيح hostbound = 0;

	/* prefer host-bound pubkey signatures if supported by server */
	إذا ((ssh->kex->flags & KEX_HAS_PUBKEY_HOSTBOUND) != 0 &&
	    (options.pubkey_authentication & SSH_PUBKEY_AUTH_HBOUND) != 0) {
		hostbound = 1;
		method = "publickey-hostbound-v00@openssh.com";
	}

	إذا ((fp = sshkey_fingerprint(id->ئاچقۇچ, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == عدم)
		أرجع 0;

	debug3_f("using %s with %s %s", method, sshkey_type(id->ئاچقۇچ), fp);

	/*
	 * If the key is an certificate, try to find a matching private key
	 * and use it to complete the signature.
	 * If no such private key exists, fall back to trying the certificate
	 * key itself in case it has a private half already loaded.
	 * This will try to set sign_id to the private key that will perform
	 * the signature.
	 */
	إذا (id->agent_fd == -1 && sshkey_is_cert(id->ئاچقۇچ)) {
		TAILQ_FOREACH(private_id, &authctxt->ئاچقۇچلار, next) {
			إذا (sshkey_equal_public(id->ئاچقۇچ, private_id->ئاچقۇچ) &&
			    id->ئاچقۇچ->type != private_id->ئاچقۇچ->type) {
				sign_id = private_id;
				اكسر;
			}
		}
		/*
		 * Exact key matches are preferred, but also allow
		 * filename matches for non-PKCS#11/agent keys that
		 * didn't load public keys. This supports the case
		 * of keeping just a private key file and public
		 * certificate on disk.
		 */
		إذا (sign_id == عدم &&
		    !id->isprivate && id->agent_fd == -1 &&
		    (id->ئاچقۇچ->flags & SSHKEY_FLAG_EXT) == 0) {
			TAILQ_FOREACH(private_id, &authctxt->ئاچقۇچلار, next) {
				إذا (private_id->ئاچقۇچ == عدم &&
				    id_filename_matches(id, private_id)) {
					sign_id = private_id;
					اكسر;
				}
			}
		}
		إذا (sign_id != عدم) {
			debug2_f("using private key \"%s\"%s for "
			    "certificate", sign_id->filename,
			    sign_id->agent_fd != -1 ? " from agent" : "");
		} وإلا {
			debug_f("no separate private key for certificate "
			    "\"%s\"", id->filename);
		}
	}

	/*
	 * If the above didn't select another identity to do the signing
	 * then default to the one we started with.
	 */
	إذا (sign_id == عدم)
		sign_id = id;

	/* assemble and sign data */
	لكل (fallback_sigtype = 0; fallback_sigtype <= 1; fallback_sigtype++) {
		حرر(alg);
		slen = 0;
		signature = عدم;
		إذا ((alg = ئاچقۇچ_sig_algorithm(fallback_sigtype ? عدم : ssh,
		    id->ئاچقۇچ)) == عدم) {
			error_f("no mutual signature supported");
			اذهب out;
		}
		debug3_f("signing using %s %s", alg, fp);

		sshbuf_free(b);
		إذا ((b = sshbuf_new()) == عدم)
			fatal_f("sshbuf_new failed");
		إذا ((r = sshbuf_put_stringb(b,
		    ssh->kex->session_id)) != 0)
			fatal_fr(r, "sshbuf_put_stringb");
		skip = sshbuf_len(b);
		إذا ((r = sshbuf_put_u8(b, SSH2_ئۇچۇر_USERAUTH_REQUEST)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->server_user)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
		    (r = sshbuf_put_cstring(b, method)) != 0 ||
		    (r = sshbuf_put_u8(b, 1)) != 0 ||
		    (r = sshbuf_put_cstring(b, alg)) != 0 ||
		    (r = sshkey_puts(id->ئاچقۇچ, b)) != 0) {
			fatal_fr(r, "assemble signed data");
		}
		إذا (hostbound) {
			إذا (ssh->kex->initial_hostkey == عدم) {
				fatal_f("internal error: initial hostkey "
				    "not recorded");
			}
			إذا ((r = sshkey_puts(ssh->kex->initial_hostkey, b)) != 0)
				fatal_fr(r, "assemble %s hostkey", method);
		}
		/* generate signature */
		r = identity_sign(sign_id, &signature, &slen,
		    sshbuf_ptr(b), sshbuf_len(b), ssh->compat, alg);
		إذا (r == 0)
			اكسر;
		وإلا إذا (r == SSH_ERR_ئاچقۇچ_NOT_FOUND)
			اذهب out; /* soft failure */
		وإلا إذا (r == SSH_ERR_SIGN_ALG_UNSUPPORTED &&
		    !fallback_sigtype) {
			إذا (sign_id->agent_fd != -1)
				loc = "agent ";
			وإلا إذا (sign_id->ئاچقۇچ != عدم &&
			    (sign_id->ئاچقۇچ->flags & SSHKEY_FLAG_EXT) != 0)
				loc = "token ";
			logit("%skey %s %s returned incorrect signature type",
			    loc, sshkey_type(id->ئاچقۇچ), fp);
			استمر;
		}
		error_fr(r, "signing failed for %s \"%s\"%s",
		    sshkey_type(sign_id->ئاچقۇچ), sign_id->filename,
		    id->agent_fd != -1 ? " from agent" : "");
		اذهب out;
	}
	إذا (slen == 0 || signature == عدم) /* shouldn't happen */
		fatal_f("no signature");

	/* append signature */
	إذا ((r = sshbuf_put_string(b, signature, slen)) != 0)
		fatal_fr(r, "append signature");

#ifdef DEBUG_PK
	sshbuf_dump(b, stderr);
#endif
	/* skip session id and packet type */
	إذا ((r = sshbuf_consume(b, skip + 1)) != 0)
		fatal_fr(r, "consume");

	/* put remaining data from buffer into packet */
	إذا ((r = sshpkt_start(ssh, SSH2_ئۇچۇر_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_putb(ssh, b)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "enqueue request");

	/* success */
	sent = 1;

 out:
	حرر(fp);
	حرر(alg);
	sshbuf_free(b);
	freezero(signature, slen);
	أرجع sent;
}

ساكن صحيح
send_pubkey_test(بنية ssh *ssh, Identity *id)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	u_char *blob = عدم;
	حرف *alg = عدم;
	size_t bloblen;
	u_int have_sig = 0;
	صحيح sent = 0, r;

	إذا ((alg = ئاچقۇچ_sig_algorithm(ssh, id->ئاچقۇچ)) == عدم) {
		debug_f("no mutual signature algorithm");
		اذهب out;
	}

	إذا ((r = sshkey_to_blob(id->ئاچقۇچ, &blob, &bloblen)) != 0) {
		/* we cannot handle this key */
		debug3_f("cannot handle key");
		اذهب out;
	}
	/* register callback for USERAUTH_PK_OK message */
	ssh_dispatch_set(ssh, SSH2_ئۇچۇر_USERAUTH_PK_OK, &كىرگۈزۈش_userauth_pk_ok);

	إذا ((r = sshpkt_start(ssh, SSH2_ئۇچۇر_USERAUTH_REQUEST)) != 0 ||
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
	حرر(alg);
	حرر(blob);
	أرجع sent;
}

ساكن بنية sshkey *
load_identity_file(Identity *id)
{
	بنية sshkey *خاص = عدم;
	حرف prompt[300], *passphrase, *comment;
	صحيح r, quit = 0, i;
	بنية stat st;

	إذا (stat(id->filename, &st) == -1) {
		do_log2(id->userprovided ?
		    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_DEBUG3,
		    "no such identity: %s: %s", id->filename, strerror(errno));
		أرجع عدم;
	}
	snprintf(prompt, حجم prompt,
	    "Enter passphrase for key '%.100s': ", id->filename);
	لكل (i = 0; i <= options.سان_of_password_prompts; i++) {
		إذا (i == 0)
			passphrase = "";
		وإلا {
			passphrase = read_passphrase(prompt, 0);
			إذا (*passphrase == '\0') {
				debug2("no passphrase given, try next key");
				حرر(passphrase);
				اكسر;
			}
		}
		بدل ((r = sshkey_load_private_type(ئاچقۇچ_UNSPEC, id->filename,
		    passphrase, &خاص, &comment))) {
		حالة 0:
			اكسر;
		حالة SSH_ERR_ئاچقۇچ_WRONG_PASSPHRASE:
			إذا (options.batch_mode) {
				quit = 1;
				اكسر;
			}
			إذا (i != 0)
				debug2("bad passphrase given, try again...");
			اكسر;
		حالة SSH_ERR_SYSTEM_ERROR:
			إذا (errno == ENOENT) {
				debug2_r(r, "Load key \"%s\"", id->filename);
				quit = 1;
				اكسر;
			}
			/* FALLTHROUGH */
		افتراضي:
			error_r(r, "Load key \"%s\"", id->filename);
			quit = 1;
			اكسر;
		}
		إذا (خاص != عدم && sshkey_is_sk(خاص) &&
		    options.sk_provider == عدم) {
			debug("key \"%s\" is an authenticator-hosted key, "
			    "but no provider specified", id->filename);
			sshkey_free(خاص);
			خاص = عدم;
			quit = 1;
		}
		إذا (!quit && (r = sshkey_check_rsa_length(خاص,
		    options.required_rsa_size)) != 0) {
			debug_fr(r, "Skipping key %s", id->filename);
			sshkey_free(خاص);
			خاص = عدم;
			quit = 1;
		}
		إذا (!quit && خاص != عدم && id->agent_fd == -1 &&
		    !(id->ئاچقۇچ && id->isprivate))
			maybe_add_ئاچقۇچ_to_agent(id->filename, خاص, comment,
			    passphrase);
		إذا (i > 0)
			freezero(passphrase, strlen(passphrase));
		حرر(comment);
		إذا (خاص != عدم || quit)
			اكسر;
	}
	أرجع خاص;
}

ساكن صحيح
ئاچقۇچ_type_allowed(بنية sshkey *ئاچقۇچ, ثابت حرف *allowlist)
{
	إذا (match_pattern_list(sshkey_ssh_name(ئاچقۇچ), allowlist, 0) == 1)
		أرجع 1;

	/* RSA keys/certs might be allowed by alternate signature types */
	بدل (ئاچقۇچ->type) {
	حالة ئاچقۇچ_RSA:
		إذا (match_pattern_list("rsa-sha2-512", allowlist, 0) == 1)
			أرجع 1;
		إذا (match_pattern_list("rsa-sha2-256", allowlist, 0) == 1)
			أرجع 1;
		اكسر;
	حالة ئاچقۇچ_RSA_CERT:
		إذا (match_pattern_list("rsa-sha2-512-cert-v01@openssh.com",
		    allowlist, 0) == 1)
			أرجع 1;
		إذا (match_pattern_list("rsa-sha2-256-cert-v01@openssh.com",
		    allowlist, 0) == 1)
			أرجع 1;
		اكسر;
	}
	أرجع 0;
}

ساكن صحيح
ئاچقۇچ_type_allowed_by_config(بنية sshkey *ئاچقۇچ)
{
	أرجع ئاچقۇچ_type_allowed(ئاچقۇچ, options.pubkey_accepted_algos);
}

/* obtain a list of keys from the agent */
ساكن صحيح
get_agent_identities(بنية ssh *ssh, صحيح *agent_fdp,
    بنية ssh_identitylist **idlistp)
{
	صحيح r, agent_fd;
	بنية ssh_identitylist *idlist;

	إذا ((r = ssh_get_authentication_socket(&agent_fd)) != 0) {
		إذا (r != SSH_ERR_AGENT_NOT_PRESENT)
			debug_fr(r, "ssh_get_authentication_socket");
		أرجع r;
	}
	إذا (ssh != عدم && ssh->kex != عدم) {
		إذا ((r = ssh_agent_bind_hostkey(agent_fd, ssh->kex->initial_hostkey,
		    ssh->kex->session_id, ssh->kex->initial_sig, 0)) == 0)
			debug_f("bound agent to hostkey");
		وإلا
			debug2_fr(r, "ssh_agent_bind_hostkey");
	}

	إذا ((r = ssh_fetch_identitylist(agent_fd, &idlist)) != 0) {
		debug_fr(r, "ssh_fetch_identitylist");
		close(agent_fd);
		أرجع r;
	}
	/* success */
	*agent_fdp = agent_fd;
	*idlistp = idlist;
	debug_f("agent returned %zu keys", idlist->nkeys);
	أرجع 0;
}

/*
 * Returns nonzero if the certificate extensions/critical-options section
 * has the specified option present, zero otherwise.
 */
ساكن صحيح
cert_has_option(بنية sshbuf *oblob, ثابت حرف *target)
{
	بنية sshbuf *c = عدم, *data = عدم;
	حرف *name = عدم;
	صحيح r, found = 0;

	إذا (oblob == عدم || (c = sshbuf_fromb(oblob)) == عدم)
		أرجع 0;
	طالما (sshbuf_len(c) > 0) {
		sshbuf_free(data);
		data = عدم;
		حرر(name);
		name = عدم;
		إذا ((r = sshbuf_get_cstring(c, &name, عدم)) != 0 ||
		    (r = sshbuf_froms(c, &data)) != 0)
			اكسر;
		إذا (strcmp(name, target) == 0) {
			found = 1;
			اكسر;
		}
	}
	sshbuf_free(data);
	حرر(name);
	sshbuf_free(c);
	أرجع found;
}

/*
 * Returns an integer describing the priority of the identity
 * within its group. Lower numbers are higher priority.
 */
#define MAX_ID_PRIORITY 3
ساكن صحيح
identity_prioritise(بنية identity *id)
{
	إذا (id == عدم || id->ئاچقۇچ == عدم)
		أرجع 3;
	إذا (!sshkey_is_cert(id->ئاچقۇچ) || id->ئاچقۇچ->cert == عدم)
		أرجع 3;
	إذا (sshkey_is_sk(id->ئاچقۇچ) &&
	    cert_has_option(id->ئاچقۇچ->cert->critical, "verify-required"))
		أرجع 2;
	إذا (sshkey_is_sk(id->ئاچقۇچ) &&
	    cert_has_option(id->ئاچقۇچ->cert->extensions, "no-touch-required"))
		أرجع 0;
	أرجع 1;
}

ساكن فراغ
order_identities_by_prio(بنية idlist *list)
{
	بنية idlist prio[MAX_ID_PRIORITY + 1], sorted;
	بنية identity *id, *tmp, *dummy;
	صحيح p;

	لكل (p = 0; p <= MAX_ID_PRIORITY; p++)
		TAILQ_INIT(&prio[p]);
	TAILQ_INIT(&sorted);

	TAILQ_FOREACH_SAFE(id, list, next, tmp) {
		إذا (id->userprovided)
			استمر;
		dummy = xcalloc(1, حجم(*dummy));
		dummy->userprovided = -1;
		TAILQ_INSERT_BEFORE(id, dummy, next);
		TAILQ_REMOVE(list, id, next);
		p = identity_prioritise(id);
		إذا (p < 0 || p > MAX_ID_PRIORITY)
			fatal_f("internal error: bad priority");
		TAILQ_INSERT_TAIL(&prio[p], id, next);
	}
	لكل (p = 0; p <= MAX_ID_PRIORITY; p++)
		TAILQ_CONCAT(&sorted, &prio[p], next);

	TAILQ_FOREACH_SAFE(id, list, next, tmp) {
		إذا (id->userprovided != -1)
			استمر;
		بنية identity *s = TAILQ_FIRST(&sorted);
		TAILQ_REMOVE(&sorted, s, next);
		TAILQ_INSERT_BEFORE(id, s, next);
		TAILQ_REMOVE(list, id, next);
		حرر(id);
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
ساكن فراغ
pubkey_prepare(بنية ssh *ssh, Authctxt *authctxt)
{
	بنية identity *id, *id2, *tmp;
	بنية idlist agent, files, certs, agent_ئاچقۇچلار, *preferred;
	بنية sshkey *ئاچقۇچ;
	صحيح disallowed, agent_fd = -1, i, r, found;
	size_t j;
	بنية ssh_identitylist *idlist;
	حرف *cp, *ident;

	TAILQ_INIT(&agent);	/* keys from the agent */
	TAILQ_INIT(&files);	/* keys from the config file */
	TAILQ_INIT(&certs);	/* certificates specified by user */
	TAILQ_INIT(&agent_ئاچقۇچلار); /* keys supported by the agent */
	preferred = &authctxt->ئاچقۇچلار;
	TAILQ_INIT(preferred);	/* preferred order of keys */

	/* list of keys stored in the filesystem and PKCS#11 */
	لكل (i = 0; i < options.رەقەم_identity_files; i++) {
		ئاچقۇچ = options.identity_ئاچقۇچلار[i];
		إذا (ئاچقۇچ && ئاچقۇچ->cert &&
		    ئاچقۇچ->cert->type != SSH2_CERT_TYPE_USER) {
			debug_f("ignoring certificate %s: not a user "
			    "certificate", options.identity_files[i]);
			استمر;
		}
		إذا (ئاچقۇچ && sshkey_is_sk(ئاچقۇچ) && options.sk_provider == عدم) {
			debug_f("ignoring authenticator-hosted key %s as no "
			    "SecurityKeyProvider has been specified",
			    options.identity_files[i]);
			استمر;
		}
		options.identity_ئاچقۇچلار[i] = عدم;
		id = xcalloc(1, حجم(*id));
		id->agent_fd = -1;
		id->ئاچقۇچ = ئاچقۇچ;
		id->filename = xstrdup(options.identity_files[i]);
		id->userprovided = options.identity_file_userprovided[i];
		TAILQ_INSERT_TAIL(&files, id, next);
	}

	/* list of certificates specified by user */
	لكل (i = 0; i < options.رەقەم_certificate_files; i++) {
		ئاچقۇچ = options.certificates[i];
		إذا (!sshkey_is_cert(ئاچقۇچ) || ئاچقۇچ->cert == عدم ||
		    ئاچقۇچ->cert->type != SSH2_CERT_TYPE_USER) {
			debug_f("ignoring certificate %s: not a user "
			    "certificate", options.identity_files[i]);
			استمر;
		}
		إذا (ئاچقۇچ && sshkey_is_sk(ئاچقۇچ) && options.sk_provider == عدم) {
			debug_f("ignoring authenticator-hosted key "
			    "certificate %s as no "
			    "SecurityKeyProvider has been specified",
			    options.identity_files[i]);
			استمر;
		}
		id = xcalloc(1, حجم(*id));
		id->agent_fd = -1;
		id->ئاچقۇچ = ئاچقۇچ;
		id->filename = xstrdup(options.certificate_files[i]);
		id->userprovided = options.certificate_file_userprovided[i];
		TAILQ_INSERT_TAIL(&certs, id, next);
	}
	order_identities_by_prio(&certs);
	TAILQ_CONCAT(preferred, &certs, next);

	/* list of keys supported by the agent */
	إذا ((r = get_agent_identities(ssh, &agent_fd, &idlist)) == 0) {
		لكل (j = 0; j < idlist->nkeys; j++) {
			إذا ((r = sshkey_check_rsa_length(idlist->ئاچقۇچلار[j],
			    options.required_rsa_size)) != 0) {
				debug_fr(r, "ignoring %s agent key",
				    sshkey_ssh_name(idlist->ئاچقۇچلار[j]));
				استمر;
			}
			found = 0;
			TAILQ_FOREACH(id, &files, next) {
				/*
				 * agent keys from the config file are
				 * preferred
				 */
				إذا (sshkey_equal(idlist->ئاچقۇچلار[j], id->ئاچقۇچ)) {
					TAILQ_REMOVE(&files, id, next);
					TAILQ_INSERT_TAIL(&agent_ئاچقۇچلار, id, next);
					id->agent_fd = agent_fd;
					found = 1;
					اكسر;
				}
			}
			إذا (!found && !options.identities_only) {
				id = xcalloc(1, حجم(*id));
				/* XXX "steals" key/comment from idlist */
				id->ئاچقۇچ = idlist->ئاچقۇچلار[j];
				id->filename = idlist->comments[j];
				idlist->ئاچقۇچلار[j] = عدم;
				idlist->comments[j] = عدم;
				id->agent_fd = agent_fd;
				TAILQ_INSERT_TAIL(&agent, id, next);
			}
		}
		ssh_free_identitylist(idlist);
		/* append remaining agent keys */
		TAILQ_CONCAT(&agent_ئاچقۇچلار, &agent, next);
		order_identities_by_prio(&agent_ئاچقۇچلار);
		TAILQ_CONCAT(preferred, &agent_ئاچقۇچلار, next);
		authctxt->agent_fd = agent_fd;
	}
	/* Prefer PKCS11 keys that are explicitly listed */
	TAILQ_FOREACH_SAFE(id, &files, next, tmp) {
		إذا (id->ئاچقۇچ == عدم || (id->ئاچقۇچ->flags & SSHKEY_FLAG_EXT) == 0)
			استمر;
		found = 0;
		TAILQ_FOREACH(id2, &files, next) {
			إذا (id2->ئاچقۇچ == عدم ||
			    (id2->ئاچقۇچ->flags & SSHKEY_FLAG_EXT) != 0)
				استمر;
			إذا (sshkey_equal(id->ئاچقۇچ, id2->ئاچقۇچ)) {
				TAILQ_REMOVE(&files, id, next);
				TAILQ_INSERT_TAIL(preferred, id, next);
				found = 1;
				اكسر;
			}
		}
		/* If IdentitiesOnly set and key not found then don't use it */
		إذا (!found && options.identities_only) {
			TAILQ_REMOVE(&files, id, next);
			freezero(id, حجم(*id));
		}
	}
	order_identities_by_prio(&files);
	/* append remaining keys from the config file */
	TAILQ_CONCAT(preferred, &files, next);
	/* finally, filter by PubkeyAcceptedAlgorithms */
	TAILQ_FOREACH_SAFE(id, preferred, next, id2) {
		disallowed = 0;
		cp = عدم;
		إذا (id->ئاچقۇچ == عدم)
			استمر;
		إذا (!ئاچقۇچ_type_allowed_by_config(id->ئاچقۇچ)) {
			debug("Skipping %s key %s - corresponding algorithm "
			    "not in PubkeyAcceptedAlgorithms",
			    sshkey_ssh_name(id->ئاچقۇچ), id->filename);
			disallowed = 1;
		} وإلا إذا (ssh != عدم && ssh->kex != عدم &&
		    ssh->kex->server_sig_algs != عدم &&
		    (cp = ئاچقۇچ_sig_algorithm(ssh, id->ئاچقۇچ)) == عدم) {
			debug("Skipping %s key %s - corresponding algorithm "
			    "not supported by server",
			    sshkey_ssh_name(id->ئاچقۇچ), id->filename);
			disallowed = 1;
		}
		حرر(cp);
		إذا (!disallowed)
			استمر;
		/* remove key */
		TAILQ_REMOVE(preferred, id, next);
		sshkey_free(id->ئاچقۇچ);
		حرر(id->filename);
		freezero(id, حجم(*id));
	}
	/* List the keys we plan on using */
	TAILQ_FOREACH_SAFE(id, preferred, next, id2) {
		ident = format_identity(id);
		debug("Will attempt key: %s", ident);
		حرر(ident);
	}
	debug2_f("done");
}

ساكن فراغ
pubkey_cleanup(بنية ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Identity *id;

	إذا (authctxt->agent_fd != -1) {
		ssh_close_authentication_socket(authctxt->agent_fd);
		authctxt->agent_fd = -1;
	}
	لكل (id = TAILQ_FIRST(&authctxt->ئاچقۇچلار); id;
	    id = TAILQ_FIRST(&authctxt->ئاچقۇچلار)) {
		TAILQ_REMOVE(&authctxt->ئاچقۇچلار, id, next);
		sshkey_free(id->ئاچقۇچ);
		حرر(id->filename);
		حرر(id);
	}
}

فراغ
pubkey_dump(بنية ssh *ssh)
{
	Authctxt authctxt;
	Identity *id;
	حرف *ident;

	memset(&authctxt, 0, حجم(authctxt));
	authctxt.agent_fd = -1;
	ssh->authctxt = &authctxt;

	pubkey_prepare(ssh, &authctxt);
	TAILQ_FOREACH(id, &authctxt.ئاچقۇچلار, next) {
		ident = format_identity(id);
		fprintf(stdout, "%s\n", ident);
		حرر(ident);
	}
	pubkey_cleanup(ssh);
	ssh->authctxt = عدم;
}

ساكن فراغ
pubkey_reset(Authctxt *authctxt)
{
	Identity *id;

	TAILQ_FOREACH(id, &authctxt->ئاچقۇچلار, next)
		id->tried = 0;
}

ساكن صحيح
userauth_pubkey(بنية ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Identity *id;
	صحيح sent = 0;
	حرف *ident;
	ساكن صحيح prepared;

	إذا (!prepared) {
		pubkey_prepare(ssh, authctxt);
		prepared = 1;
	}

	طالما ((id = TAILQ_FIRST(&authctxt->ئاچقۇچلار))) {
		إذا (id->tried++)
			أرجع (0);
		/* move key to the end of the queue */
		TAILQ_REMOVE(&authctxt->ئاچقۇچلار, id, next);
		TAILQ_INSERT_TAIL(&authctxt->ئاچقۇچلار, id, next);
		/*
		 * send a test message if we have the public key. for
		 * encrypted keys we cannot do this and have to load the
		 * private key instead
		 */
		إذا (id->ئاچقۇچ != عدم) {
			ident = format_identity(id);
			debug("Offering public key: %s", ident);
			حرر(ident);
			sent = send_pubkey_test(ssh, id);
		} وإلا {
			debug("Trying private key: %s", id->filename);
			id->ئاچقۇچ = load_identity_file(id);
			إذا (id->ئاچقۇچ != عدم) {
				id->isprivate = 1;
				sent = sign_and_send_pubkey(ssh, id);
				sshkey_free(id->ئاچقۇچ);
				id->ئاچقۇچ = عدم;
				id->isprivate = 0;
			}
		}
		إذا (sent)
			أرجع (sent);
	}
	أرجع (0);
}

/*
 * Send userauth request message specifying keyboard-interactive method.
 */
ساكن صحيح
userauth_kbdint(بنية ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	صحيح r;

	إذا (authctxt->attempt_kbdint++ >= options.سان_of_password_prompts)
		أرجع 0;
	/* disable if no SSH2_MSG_USERAUTH_INFO_REQUEST has been seen */
	إذا (authctxt->attempt_kbdint > 1 && !authctxt->info_req_seen) {
		debug3("userauth_kbdint: disable: no info_req_seen");
		ssh_dispatch_set(ssh, SSH2_ئۇچۇر_USERAUTH_INFO_REQUEST, عدم);
		أرجع 0;
	}

	debug2("userauth_kbdint");
	إذا ((r = sshpkt_start(ssh, SSH2_ئۇچۇر_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||		/* lang */
	    (r = sshpkt_put_cstring(ssh, options.kbd_interactive_devices ?
	    options.kbd_interactive_devices : "")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh_dispatch_set(ssh, SSH2_ئۇچۇر_USERAUTH_INFO_REQUEST, &كىرگۈزۈش_userauth_info_req);
	أرجع 1;
}

/*
 * parse INFO_REQUEST, prompt user and send INFO_RESPONSE
 */
ساكن صحيح
كىرگۈزۈش_userauth_info_req(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	حرف *name = عدم, *inst = عدم, *lang = عدم, *prompt = عدم;
	حرف *display_prompt = عدم, *response = عدم;
	u_char echo = 0;
	u_int رەقەم_prompts, i;
	صحيح r, addnl;
	size_t len;

	debug2_f("entering");

	إذا (authctxt == عدم)
		fatal_f("no authentication context");

	authctxt->info_req_seen = 1;

	إذا ((r = sshpkt_get_cstring(ssh, &name, عدم)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &inst, عدم)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, عدم)) != 0)
		اذهب out;
	إذا ((len = strlen(name)) > 0) {
		addnl = name[len] != '\n';
		fmprintf(stderr, "%s%s", name, addnl ? "\n" : "");
	}
	إذا ((len = strlen(inst)) > 0) {
		addnl = inst[len] != '\n';
		fmprintf(stderr, "%s%s", inst, addnl ? "\n" : "");
	}

	إذا ((r = sshpkt_get_u32(ssh, &رەقەم_prompts)) != 0)
		اذهب out;
	/*
	 * Begin to build info response packet based on prompts requested.
	 * We commit to providing the correct number of responses, so if
	 * further on we run into a problem that prevents this, we have to
	 * be sure and clean this up and send a correct error response.
	 */
	إذا ((r = sshpkt_start(ssh, SSH2_ئۇچۇر_USERAUTH_INFO_RESPONSE)) != 0 ||
	    (r = sshpkt_put_u32(ssh, رەقەم_prompts)) != 0)
		اذهب out;

	debug2_f("num_prompts %d", رەقەم_prompts);
	لكل (i = 0; i < رەقەم_prompts; i++) {
		إذا ((r = sshpkt_get_cstring(ssh, &prompt, عدم)) != 0 ||
		    (r = sshpkt_get_u8(ssh, &echo)) != 0)
			اذهب out;
		إذا (asmprintf(&display_prompt, INT_MAX, عدم, "(%s@%s) %s",
		    authctxt->server_user, options.host_ئاچقۇچ_alias ?
		    options.host_ئاچقۇچ_alias : authctxt->host, prompt) == -1)
			fatal_f("asmprintf failed");
		response = read_passphrase(display_prompt, echo ? RP_ECHO : 0);
		إذا ((r = sshpkt_put_cstring(ssh, response)) != 0)
			اذهب out;
		freezero(response, strlen(response));
		حرر(prompt);
		حرر(display_prompt);
		display_prompt = response = prompt = عدم;
	}
	/* done with parsing incoming message. */
	إذا ((r = sshpkt_get_end(ssh)) != 0 ||
	    (r = sshpkt_add_padding(ssh, 64)) != 0)
		اذهب out;
	r = sshpkt_send(ssh);
 out:
	إذا (response)
		freezero(response, strlen(response));
	حرر(prompt);
	حرر(display_prompt);
	حرر(name);
	حرر(inst);
	حرر(lang);
	أرجع r;
}

ساكن صحيح
ssh_keysign(بنية ssh *ssh, بنية sshkey *ئاچقۇچ, u_char **sigp, size_t *lenp,
    ثابت u_char *data, size_t datalen)
{
	بنية sshbuf *b;
	بنية stat st;
	pid_t pid;
	صحيح r, to[2], from[2], status;
	صحيح sock = ssh_packet_get_connection_in(ssh);
	u_char rversion = 0, version = 2;
	فراغ (*osigchld)(صحيح);

	*sigp = عدم;
	*lenp = 0;

	إذا (stat(PATH_SSH_ئاچقۇچ_SIGN, &st) == -1) {
		error_f("not installed: %s", strerror(errno));
		أرجع -1;
	}
	إذا (fflush(stdout) != 0) {
		error_f("fflush: %s", strerror(errno));
		أرجع -1;
	}
	إذا (pipe(to) == -1) {
		error_f("pipe: %s", strerror(errno));
		أرجع -1;
	}
	إذا (pipe(from) == -1) {
		error_f("pipe: %s", strerror(errno));
		أرجع -1;
	}
	إذا ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		أرجع -1;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	إذا (pid == 0) {
		close(from[0]);
		إذا (dup2(from[1], STDOUT_FILENO) == -1)
			fatal_f("dup2: %s", strerror(errno));
		close(to[1]);
		إذا (dup2(to[0], STDIN_FILENO) == -1)
			fatal_f("dup2: %s", strerror(errno));
		close(from[1]);
		close(to[0]);

		إذا (dup2(sock, STDERR_FILENO + 1) == -1)
			fatal_f("dup2: %s", strerror(errno));
		sock = STDERR_FILENO + 1;
		إذا (fcntl(sock, F_SETFD, 0) == -1) /* keep the socket on exec */
			debug3_f("fcntl F_SETFD: %s", strerror(errno));
		closefrom(sock + 1);

		debug3_f("[child] pid=%ld, exec %s",
		    (long)getpid(), PATH_SSH_ئاچقۇچ_SIGN);
		execl(PATH_SSH_ئاچقۇچ_SIGN, PATH_SSH_ئاچقۇچ_SIGN, (حرف *)عدم);
		fatal_f("exec(%s): %s", PATH_SSH_ئاچقۇچ_SIGN,
		    strerror(errno));
	}
	close(from[1]);
	close(to[0]);
	sock = STDERR_FILENO + 1;

	إذا ((b = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	/* send # of sock, data to be signed */
	إذا ((r = sshbuf_put_u32(b, sock)) != 0 ||
	    (r = sshbuf_put_string(b, data, datalen)) != 0)
		fatal_fr(r, "buffer error");
	إذا (ssh_ئۇچۇر_send(to[1], version, b) == -1)
		fatal_f("couldn't send request");
	sshbuf_reset(b);
	r = ssh_ئۇچۇر_recv(from[0], b);
	close(from[0]);
	close(to[1]);
	إذا (r < 0) {
		error_f("no reply");
		اذهب fail;
	}

	errno = 0;
	طالما (waitpid(pid, &status, 0) == -1) {
		إذا (errno != EINTR) {
			error_f("waitpid %ld: %s", (long)pid, strerror(errno));
			اذهب fail;
		}
	}
	إذا (!WIFEXITED(status)) {
		error_f("exited abnormally");
		اذهب fail;
	}
	إذا (WEXITSTATUS(status) != 0) {
		error_f("exited with status %d", WEXITSTATUS(status));
		اذهب fail;
	}
	إذا ((r = sshbuf_get_u8(b, &rversion)) != 0) {
		error_fr(r, "buffer error");
		اذهب fail;
	}
	إذا (rversion != version) {
		error_f("bad version");
		اذهب fail;
	}
	إذا ((r = sshbuf_get_string(b, sigp, lenp)) != 0) {
		error_fr(r, "buffer error");
 fail:
		ssh_signal(SIGCHLD, osigchld);
		sshbuf_free(b);
		أرجع -1;
	}
	ssh_signal(SIGCHLD, osigchld);
	sshbuf_free(b);

	أرجع 0;
}

ساكن صحيح
userauth_hostbased(بنية ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	بنية sshkey *خاص = عدم;
	بنية sshbuf *b = عدم;
	u_char *sig = عدم, *keyblob = عدم;
	حرف *fp = عدم, *chost = عدم, *lname = عدم;
	size_t siglen = 0, keylen = 0;
	صحيح i, r, success = 0;

	إذا (authctxt->ktypes == عدم) {
		authctxt->oktypes = xstrdup(options.hostbased_accepted_algos);
		authctxt->ktypes = authctxt->oktypes;
	}

	/*
	 * Work through each listed type pattern in HostbasedAcceptedAlgorithms,
	 * trying each hostkey that matches the type in turn.
	 */
	لكل (;;) {
		إذا (authctxt->active_ktype == عدم)
			authctxt->active_ktype = strsep(&authctxt->ktypes, ",");
		إذا (authctxt->active_ktype == عدم ||
		    *authctxt->active_ktype == '\0')
			اكسر;
		debug3_f("trying key type %s", authctxt->active_ktype);

		/* check for a useful key */
		خاص = عدم;
		لكل (i = 0; i < authctxt->sensitive->nkeys; i++) {
			إذا (authctxt->sensitive->ئاچقۇچلار[i] == عدم ||
			    authctxt->sensitive->ئاچقۇچلار[i]->type == ئاچقۇچ_UNSPEC)
				استمر;
			إذا (!sshkey_match_keyname_to_sigalgs(
			    sshkey_ssh_name(authctxt->sensitive->ئاچقۇچلار[i]),
			    authctxt->active_ktype))
				استمر;
			/* we take and free the key */
			خاص = authctxt->sensitive->ئاچقۇچلار[i];
			authctxt->sensitive->ئاچقۇچلار[i] = عدم;
			اكسر;
		}
		/* Found one */
		إذا (خاص != عدم)
			اكسر;
		/* No more keys of this type; advance */
		authctxt->active_ktype = عدم;
	}
	إذا (خاص == عدم) {
		حرر(authctxt->oktypes);
		authctxt->oktypes = authctxt->ktypes = عدم;
		authctxt->active_ktype = عدم;
		debug("No more client hostkeys for hostbased authentication.");
		اذهب out;
	}

	إذا ((fp = sshkey_fingerprint(خاص, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == عدم) {
		error_f("sshkey_fingerprint failed");
		اذهب out;
	}
	debug_f("trying hostkey %s %s using sigalg %s",
	    sshkey_ssh_name(خاص), fp, authctxt->active_ktype);

	/* figure out a name for the client host */
	lname = get_local_name(ssh_packet_get_connection_in(ssh));
	إذا (lname == عدم) {
		error_f("cannot get local ipaddr/name");
		اذهب out;
	}

	/* XXX sshbuf_put_stringf? */
	xasprintf(&chost, "%s.", lname);
	debug2_f("chost %s", chost);

	/* construct data */
	إذا ((b = sshbuf_new()) == عدم) {
		error_f("sshbuf_new failed");
		اذهب out;
	}
	إذا ((r = sshkey_to_blob(خاص, &keyblob, &keylen)) != 0) {
		error_fr(r, "sshkey_to_blob");
		اذهب out;
	}
	إذا ((r = sshbuf_put_stringb(b, ssh->kex->session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_ئۇچۇر_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->server_user)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->method->name)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->active_ktype)) != 0 ||
	    (r = sshbuf_put_string(b, keyblob, keylen)) != 0 ||
	    (r = sshbuf_put_cstring(b, chost)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->local_user)) != 0) {
		error_fr(r, "buffer error");
		اذهب out;
	}

#ifdef DEBUG_PK
	sshbuf_dump(b, stderr);
#endif
	إذا ((r = ssh_keysign(ssh, خاص, &sig, &siglen,
	    sshbuf_ptr(b), sshbuf_len(b))) != 0) {
		error("sign using hostkey %s %s failed",
		    sshkey_ssh_name(خاص), fp);
		اذهب out;
	}
	إذا ((r = sshpkt_start(ssh, SSH2_ئۇچۇر_USERAUTH_REQUEST)) != 0 ||
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
		اذهب out;
	}
	success = 1;

 out:
	إذا (sig != عدم)
		freezero(sig, siglen);
	حرر(keyblob);
	حرر(lname);
	حرر(fp);
	حرر(chost);
	sshkey_free(خاص);
	sshbuf_free(b);

	أرجع success;
}

/* find auth method */

/*
 * given auth method name, if configurable options permit this method fill
 * in auth_ident field and return true, otherwise return false.
 */
ساكن صحيح
authmethod_is_enabled(Authmethod *method)
{
	إذا (method == عدم)
		أرجع 0;
	/* return false if options indicate this method is disabled */
	إذا  (method->enabled == عدم || *method->enabled == 0)
		أرجع 0;
	/* return false if batch mode is enabled but method needs interactive mode */
	إذا  (method->batch_flag != عدم && *method->batch_flag != 0)
		أرجع 0;
	أرجع 1;
}

ساكن Authmethod *
authmethod_lookup(ثابت حرف *name)
{
	Authmethod *method = عدم;
	إذا (name != عدم)
		لكل (method = authmethods; method->name != عدم; method++)
			إذا (strcmp(name, method->name) == 0)
				أرجع method;
	debug2("Unrecognized authentication method name: %s", name ? name : "NULL");
	أرجع عدم;
}

/* XXX internal state */
ساكن Authmethod *current = عدم;
ساكن حرف *supported = عدم;
ساكن حرف *preferred = عدم;

/*
 * Given the authentication method list sent by the server, return the
 * next method we should try.  If the server initially sends a nil list,
 * use a built-in default list.
 */
ساكن Authmethod *
authmethod_get(حرف *authlist)
{
	حرف *name = عدم;
	u_int next;

	/* Use a suitable default if we're passed a nil list.  */
	إذا (authlist == عدم || strlen(authlist) == 0)
		authlist = options.preferred_authentications;

	إذا (supported == عدم || strcmp(authlist, supported) != 0) {
		debug3("start over, passed a different list %s", authlist);
		حرر(supported);
		supported = xstrdup(authlist);
		preferred = options.preferred_authentications;
		debug3("preferred %s", preferred);
		current = عدم;
	} وإلا إذا (current != عدم && authmethod_is_enabled(current))
		أرجع current;

	لكل (;;) {
		إذا ((name = match_list(preferred, supported, &next)) == عدم) {
			debug("No more authentication methods to try.");
			current = عدم;
			أرجع عدم;
		}
		preferred += next;
		debug3("authmethod_lookup %s", name);
		debug3("remaining preferred: %s", preferred);
		إذا ((current = authmethod_lookup(name)) != عدم &&
		    authmethod_is_enabled(current)) {
			debug3("authmethod_is_enabled %s", name);
			debug("Next authentication method: %s", name);
			حرر(name);
			أرجع current;
		}
		حرر(name);
	}
}

ساكن حرف *
authmethods_get(فراغ)
{
	Authmethod *method = عدم;
	بنية sshbuf *b;
	حرف *list;
	صحيح r;

	إذا ((b = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	لكل (method = authmethods; method->name != عدم; method++) {
		إذا (authmethod_is_enabled(method)) {
			إذا ((r = sshbuf_putf(b, "%s%s",
			    sshbuf_len(b) ? "," : "", method->name)) != 0)
				fatal_fr(r, "buffer error");
		}
	}
	إذا ((list = sshbuf_dup_string(b)) == عدم)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	أرجع list;
}
