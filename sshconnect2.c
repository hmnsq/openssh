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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/socket.h>
#شامل <sys/wait.h>
#شامل <sys/queue.h>
#شامل <sys/stat.h>

#شامل <errno.h>
#شامل <fcntl.h>
#شامل <limits.h>
#شامل <pwd.h>
#شامل <signal.h>
#شامل <stdio.h>
#شامل <string.h>
#شامل <stdarg.h>
#شامل <unistd.h>
#اگر defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
#شامل <vis.h>
#endif

#شامل "xmalloc.h"
#شامل "ssh.h"
#شامل "ssh2.h"
#شامل "sshbuf.h"
#شامل "packet.h"
#شامل "compat.h"
#شامل "cipher.h"
#شامل "sshkey.h"
#شامل "kex.h"
#شامل "sshconnect.h"
#شامل "authfile.h"
#شامل "authfd.h"
#شامل "log.h"
#شامل "misc.h"
#شامل "readconf.h"
#شامل "match.h"
#شامل "dispatch.h"
#شامل "canohost.h"
#شامل "msg.h"
#شامل "pathnames.h"
#شامل "hostfile.h"
#شامل "ssherr.h"
#شامل "utf8.h"
#شامل "ssh-sk.h"
#شامل "sk-api.h"

#ifdef GSSAPI
#شامل "ssh-gss.h"
#endif

/* import */
بیرونی Options options;

/*
 * SSH2 key exchange
 */

ایستا نویسه *xxx_host;
ایستا ساختار sockaddr_storage xxx_hostaddr;
ایستا ثابت ساختار ssh_conn_info *xxx_conn_info;
ایستا صحیح کلید_type_allowed(ساختار sshkey *, ثابت نویسه *);

ایستا صحیح
verify_host_کلید_callback(ساختار sshkey *hostkey, ساختار ssh *ssh)
{
	صحیح r;

	اگر ((r = sshkey_check_rsa_length(hostkey,
	    options.required_rsa_size)) != 0)
		fatal_r(r, "Bad server host key");
	اگر (!کلید_type_allowed(hostkey, options.hostkeyalgorithms)) {
		fatal("Server host key %s not in HostKeyAlgorithms",
		    sshkey_ssh_name(hostkey));
	}
	اگر (verify_host_کلید(xxx_host, (ساختار sockaddr *)&xxx_hostaddr, hostkey,
	    xxx_conn_info) != 0)
		fatal("Host key verification failed.");
	بازگشت 0;
}

/* Returns the first item from a comma-separated algorithm list */
ایستا نویسه *
first_alg(ثابت نویسه *algs)
{
	نویسه *ret, *cp;

	ret = xstrdup(algs);
	اگر ((cp = strchr(ret, ',')) != پوچ)
		*cp = '\0';
	بازگشت ret;
}

ایستا نویسه *
order_hostkeyalgs(نویسه *host, ساختار sockaddr *hostaddr, u_short port,
    ثابت ساختار ssh_conn_info *cinfo)
{
	نویسه *oavail = پوچ, *avail = پوچ, *first = پوچ, *last = پوچ;
	نویسه *alg = پوچ, *hostname = پوچ, *ret = پوچ, *best = پوچ;
	size_t maxlen;
	ساختار hostkeys *hostkeys = پوچ;
	صحیح ktype;
	u_int i;

	/* Find all hostkeys for this hostname */
	get_hostfile_hostname_ipaddr(host, hostaddr, port, &hostname, پوچ);
	hostkeys = init_hostkeys();
	برای (i = 0; i < options.رقم_user_hostfiles; i++)
		load_hostkeys(hostkeys, hostname, options.user_hostfiles[i], 0);
	برای (i = 0; i < options.رقم_system_hostfiles; i++) {
		load_hostkeys(hostkeys, hostname,
		    options.system_hostfiles[i], 0);
	}
	اگر (options.known_hosts_command != پوچ) {
		load_hostkeys_command(hostkeys, options.known_hosts_command,
		    "ORDER", cinfo, پوچ, hostname);
	}
	/*
	 * If a plain public key exists that matches the type of the best
	 * preference HostkeyAlgorithms, then use the whole list as is.
	 * Note that we ignore whether the best preference algorithm is a
	 * certificate type, as sshconnect.c will downgrade certs to
	 * plain keys if necessary.
	 */
	best = first_alg(options.hostkeyalgorithms);
	اگر (lookup_کلید_in_hostkeys_by_type(hostkeys,
	    sshkey_type_plain(sshkey_type_from_name(best)),
	    sshkey_ecdsa_nid_from_name(best), پوچ)) {
		debug3_f("have matching best-preference key type %s, "
		    "using HostkeyAlgorithms verbatim", best);
		ret = xstrdup(options.hostkeyalgorithms);
		برو out;
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
	انجامبده { \
		اگر (*to != '\0') \
			strlcat(to, ",", maxlen); \
		strlcat(to, from, maxlen); \
	} وقتی (0)

	وقتی ((alg = strsep(&avail, ",")) && *alg != '\0') {
		اگر ((ktype = sshkey_type_from_name(alg)) == کلید_UNSPEC)
			fatal_f("unknown alg %s", alg);
		/*
		 * If we have a @cert-authority marker in known_hosts then
		 * prefer all certificate algorithms.
		 */
		اگر (sshkey_type_is_cert(ktype) &&
		    lookup_marker_in_hostkeys(hostkeys, MRK_CA)) {
			ALG_APPEND(first, alg);
			ادامه;
		}
		/* If the key appears in known_hosts then prefer it */
		اگر (lookup_کلید_in_hostkeys_by_type(hostkeys,
		    sshkey_type_plain(ktype),
		    sshkey_ecdsa_nid_from_name(alg), پوچ)) {
			ALG_APPEND(first, alg);
			ادامه;
		}
		/* Otherwise, put it last */
		ALG_APPEND(last, alg);
	}
#undef ALG_APPEND
	xasprintf(&ret, "%s%s%s", first,
	    (*first == '\0' || *last == '\0') ? "" : ",", last);
	اگر (*first != '\0')
		debug3_f("prefer hostkeyalgs: %s", first);
	وگرنه
		debug3_f("no algorithms matched; accept original");
 out:
	آزاد(best);
	آزاد(first);
	آزاد(last);
	آزاد(hostname);
	آزاد(oavail);
	free_hostkeys(hostkeys);

	بازگشت ret;
}

تهی
ssh_kex2(ساختار ssh *ssh, نویسه *host, ساختار sockaddr_storage *hostaddr,
    u_short port, ثابت ساختار ssh_conn_info *cinfo)
{
	نویسه *myproposal[PROPOSAL_MAX];
	نویسه *all_کلید, *hkalgs = پوچ;
	صحیح r, use_known_hosts_order = 0;

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
	اگر (options.hostkeyalgorithms == پوچ ||
	    options.hostkeyalgorithms[0] == '-' ||
	    options.hostkeyalgorithms[0] == '+')
		use_known_hosts_order = 1;

	/* Expand or fill in HostkeyAlgorithms */
	all_کلید = sshkey_alg_list(0, 0, 1, ',');
	اگر ((r = kex_assemble_names(&options.hostkeyalgorithms,
	    kex_default_pk_alg(), all_کلید)) != 0)
		fatal_fr(r, "kex_assemble_namelist");
	آزاد(all_کلید);

	اگر (use_known_hosts_order) {
		hkalgs = order_hostkeyalgs(host, (ساختار sockaddr *)hostaddr,
		    port, cinfo);
	}

	kex_proposal_populate_entries(ssh, myproposal,
	    options.kex_algorithms, options.ciphers, options.macs,
	    compression_alg_list(options.compression),
	    hkalgs ? hkalgs : options.hostkeyalgorithms);

	آزاد(hkalgs);

	/* start key exchange */
	اگر ((r = kex_setup(ssh, myproposal)) != 0)
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
	ssh->kex->verify_host_کلید=&verify_host_کلید_callback;

	ssh_dispatch_run_fatal(ssh, DISPATCH_BLOCK, &ssh->kex->done);
	kex_proposal_free_entries(myproposal);

#ifdef DEBUG_KEXDH
	/* send 1st encrypted/maced/compressed message */
	اگر ((r = sshpkt_start(ssh, SSH2_پیام_IGNORE)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "markus")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send packet");
#endif
}

/*
 * Authenticate user
 */

تعریفنوع ساختار cauthctxt Authctxt;
تعریفنوع ساختار cauthmethod Authmethod;
تعریفنوع ساختار identity Identity;
تعریفنوع ساختار idlist Idlist;

ساختار identity {
	TAILQ_ENTRY(identity) next;
	صحیح	agent_fd;		/* >=0 if agent supports key */
	ساختار sshkey	*کلید;		/* public/private key */
	نویسه	*filename;		/* comment for agent-only keys */
	صحیح	tried;
	صحیح	isprivate;		/* key points to the private key */
	صحیح	userprovided;
};
TAILQ_HEAD(idlist, identity);

ساختار cauthctxt {
	ثابت نویسه *server_user;
	ثابت نویسه *local_user;
	ثابت نویسه *host;
	ثابت نویسه *service;
	ساختار cauthmethod *method;
	sig_atomic_t success;
	نویسه *authlist;
#ifdef GSSAPI
	/* gssapi */
	gss_OID_set gss_supported_mechs;
	u_int mech_tried;
#endif
	/* pubkey */
	ساختار idlist کلیدها;
	صحیح agent_fd;
	/* hostbased */
	Sensitive *sensitive;
	نویسه *oktypes, *ktypes;
	ثابت نویسه *active_ktype;
	/* kbd-interactive */
	صحیح info_req_seen;
	صحیح attempt_kbdint;
	/* password */
	صحیح attempt_passwd;
	/* generic */
	تهی *methoddata;
};

ساختار cauthmethod {
	نویسه	*name;		/* string to compare against server's list */
	صحیح	(*userauth)(ساختار ssh *ssh);
	تهی	(*cleanup)(ساختار ssh *ssh);
	صحیح	*enabled;	/* flag in option struct that enables method */
	صحیح	*batch_flag;	/* flag in option struct that disables method */
};

ایستا صحیح درون_داد_userauth_service_accept(صحیح, uint32_t, ساختار ssh *);
ایستا صحیح درون_داد_userauth_success(صحیح, uint32_t, ساختار ssh *);
ایستا صحیح درون_داد_userauth_failure(صحیح, uint32_t, ساختار ssh *);
ایستا صحیح درون_داد_userauth_banner(صحیح, uint32_t, ساختار ssh *);
ایستا صحیح درون_داد_userauth_error(صحیح, uint32_t, ساختار ssh *);
ایستا صحیح درون_داد_userauth_info_req(صحیح, uint32_t, ساختار ssh *);
ایستا صحیح درون_داد_userauth_pk_ok(صحیح, uint32_t, ساختار ssh *);
ایستا صحیح درون_داد_userauth_passwd_changereq(صحیح, uint32_t, ساختار ssh *);

ایستا صحیح userauth_none(ساختار ssh *);
ایستا صحیح userauth_pubkey(ساختار ssh *);
ایستا صحیح userauth_passwd(ساختار ssh *);
ایستا صحیح userauth_kbdint(ساختار ssh *);
ایستا صحیح userauth_hostbased(ساختار ssh *);

#ifdef GSSAPI
ایستا صحیح userauth_gssapi(ساختار ssh *);
ایستا تهی userauth_gssapi_cleanup(ساختار ssh *);
ایستا صحیح درون_داد_gssapi_response(صحیح type, uint32_t, ساختار ssh *);
ایستا صحیح درون_داد_gssapi_token(صحیح type, uint32_t, ساختار ssh *);
ایستا صحیح درون_داد_gssapi_error(صحیح, uint32_t, ساختار ssh *);
ایستا صحیح درون_داد_gssapi_errtok(صحیح, uint32_t, ساختار ssh *);
#endif

تهی	userauth(ساختار ssh *, نویسه *);

ایستا تهی pubkey_cleanup(ساختار ssh *);
ایستا صحیح sign_and_send_pubkey(ساختار ssh *ssh, Identity *);
ایستا تهی pubkey_prepare(ساختار ssh *, Authctxt *);
ایستا تهی pubkey_reset(Authctxt *);
ایستا ساختار sshkey *load_identity_file(Identity *);

ایستا Authmethod *authmethod_get(نویسه *authlist);
ایستا Authmethod *authmethod_lookup(ثابت نویسه *name);
ایستا نویسه *authmethods_get(تهی);

Authmethod authmethods[] = {
#ifdef GSSAPI
	{"gssapi-with-mic",
		userauth_gssapi,
		userauth_gssapi_cleanup,
		&options.gss_authentication,
		پوچ},
#endif
	{"hostbased",
		userauth_hostbased,
		پوچ,
		&options.hostbased_authentication,
		پوچ},
	{"publickey",
		userauth_pubkey,
		پوچ,
		&options.pubkey_authentication,
		پوچ},
	{"keyboard-interactive",
		userauth_kbdint,
		پوچ,
		&options.kbd_interactive_authentication,
		&options.batch_mode},
	{"password",
		userauth_passwd,
		پوچ,
		&options.password_authentication,
		&options.batch_mode},
	{"none",
		userauth_none,
		پوچ,
		پوچ,
		پوچ},
	{پوچ, پوچ, پوچ, پوچ, پوچ}
};

تهی
ssh_userauth2(ساختار ssh *ssh, ثابت نویسه *local_user,
    ثابت نویسه *server_user, نویسه *host, Sensitive *sensitive)
{
	Authctxt authctxt;
	صحیح r;

	اگر (options.preferred_authentications == پوچ)
		options.preferred_authentications = authmethods_get();

	/* setup authentication context */
	memset(&authctxt, 0, اندازه(authctxt));
	authctxt.server_user = server_user;
	authctxt.local_user = local_user;
	authctxt.host = host;
	authctxt.service = "ssh-connection";		/* service name */
	authctxt.success = 0;
	authctxt.method = authmethod_lookup("none");
	authctxt.authlist = پوچ;
	authctxt.methoddata = پوچ;
	authctxt.sensitive = sensitive;
	authctxt.active_ktype = authctxt.oktypes = authctxt.ktypes = پوچ;
	authctxt.info_req_seen = 0;
	authctxt.attempt_kbdint = 0;
	authctxt.attempt_passwd = 0;
#اگر GSSAPI
	authctxt.gss_supported_mechs = پوچ;
	authctxt.mech_tried = 0;
#endif
	authctxt.agent_fd = -1;
	اگر (authctxt.method == پوچ)
		fatal_f("internal error: cannot send userauth none request");

	اگر ((r = sshpkt_start(ssh, SSH2_پیام_SERVICE_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "ssh-userauth")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh->authctxt = &authctxt;
	ssh_dispatch_init(ssh, &درون_داد_userauth_error);
	ssh_dispatch_set(ssh, SSH2_پیام_EXT_INFO, kex_درون_داد_ext_info);
	ssh_dispatch_set(ssh, SSH2_پیام_SERVICE_ACCEPT, &درون_داد_userauth_service_accept);
	ssh_dispatch_run_fatal(ssh, DISPATCH_BLOCK, &authctxt.success);	/* loop until success */
	pubkey_cleanup(ssh);
#ifdef GSSAPI
	اگر (authctxt.gss_supported_mechs != پوچ) {
		u_int ms;

		gss_release_oid_set(&ms, &authctxt.gss_supported_mechs);
		authctxt.gss_supported_mechs = پوچ;
	}
#endif
	ssh->authctxt = پوچ;

	ssh_dispatch_range(ssh, SSH2_پیام_USERAUTH_MIN, SSH2_پیام_USERAUTH_MAX, پوچ);

	اگر (!authctxt.success)
		fatal("Authentication failed.");
	اگر (ssh_packet_connection_is_on_socket(ssh)) {
		verbose("Authenticated to %s ([%s]:%d) using \"%s\".", host,
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    authctxt.method->name);
	} وگرنه {
		verbose("Authenticated to %s (via proxy) using \"%s\".", host,
		    authctxt.method->name);
	}
}

ایستا صحیح
درون_داد_userauth_service_accept(صحیح type, uint32_t seq, ساختار ssh *ssh)
{
	صحیح r;

	اگر (ssh_packet_remaining(ssh) > 0) {
		نویسه *reply;

		اگر ((r = sshpkt_get_cstring(ssh, &reply, پوچ)) != 0)
			برو out;
		debug2("service_accept: %s", reply);
		آزاد(reply);
	} وگرنه {
		debug2("buggy server: service_accept w/o service");
	}
	اگر ((r = sshpkt_get_end(ssh)) != 0)
		برو out;
	debug("SSH2_MSG_SERVICE_ACCEPT received");

	/* initial userauth request */
	userauth_none(ssh);

	/* accept EXT_INFO at any time during userauth */
	ssh_dispatch_set(ssh, SSH2_پیام_EXT_INFO, ssh->kex->ext_info_s ?
	    &kex_درون_داد_ext_info : &درون_داد_userauth_error);
	ssh_dispatch_set(ssh, SSH2_پیام_USERAUTH_SUCCESS, &درون_داد_userauth_success);
	ssh_dispatch_set(ssh, SSH2_پیام_USERAUTH_FAILURE, &درون_داد_userauth_failure);
	ssh_dispatch_set(ssh, SSH2_پیام_USERAUTH_BANNER, &درون_داد_userauth_banner);
	r = 0;
 out:
	بازگشت r;
}

تهی
userauth(ساختار ssh *ssh, نویسه *authlist)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;

	اگر (authctxt->method != پوچ && authctxt->method->cleanup != پوچ)
		authctxt->method->cleanup(ssh);

	آزاد(authctxt->methoddata);
	authctxt->methoddata = پوچ;
	اگر (authlist == پوچ) {
		authlist = authctxt->authlist;
	} وگرنه {
		آزاد(authctxt->authlist);
		authctxt->authlist = authlist;
	}
	برای (;;) {
		Authmethod *method = authmethod_get(authlist);
		اگر (method == پوچ)
			fatal("%s@%s: Permission denied (%s).",
			    authctxt->server_user, authctxt->host, authlist);
		authctxt->method = method;

		/* reset the per method handler */
		ssh_dispatch_range(ssh, SSH2_پیام_USERAUTH_PER_METHOD_MIN,
		    SSH2_پیام_USERAUTH_PER_METHOD_MAX, پوچ);

		/* and try new method */
		اگر (method->userauth(ssh) != 0) {
			debug2("we sent a %s packet, wait for reply", method->name);
			بشکن;
		} وگرنه {
			debug2("we did not send a packet, disable method");
			method->enabled = پوچ;
		}
	}
}

ایستا صحیح
درون_داد_userauth_error(صحیح type, uint32_t seq, ساختار ssh *ssh)
{
	fatal_f("bad message during authentication: type %d", type);
	بازگشت 0;
}

ایستا صحیح
درون_داد_userauth_banner(صحیح type, uint32_t seq, ساختار ssh *ssh)
{
	نویسه *پیام = پوچ;
	size_t len;
	صحیح r;

	debug3_f("entering");
	اگر ((r = sshpkt_get_cstring(ssh, &پیام, &len)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, پوچ, پوچ)) != 0)
		برو out;
	اگر (len > 0 && options.log_level >= SYSLOG_LEVEL_INFO)
		fmprintf(stderr, "%s", پیام);
	r = 0;
 out:
	آزاد(پیام);
	بازگشت r;
}

ایستا صحیح
درون_داد_userauth_success(صحیح type, uint32_t seq, ساختار ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	اگر (authctxt == پوچ)
		fatal_f("no authentication context");
	آزاد(authctxt->authlist);
	authctxt->authlist = پوچ;
	اگر (authctxt->method != پوچ && authctxt->method->cleanup != پوچ)
		authctxt->method->cleanup(ssh);
	آزاد(authctxt->methoddata);
	authctxt->methoddata = پوچ;
	authctxt->success = 1;			/* break out */
	ssh_dispatch_set(ssh, SSH2_پیام_EXT_INFO, dispatch_protocol_error);
	بازگشت 0;
}

#اگر 0
ایستا صحیح
درون_داد_userauth_success_unexpected(صحیح type, uint32_t seq, ساختار ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	اگر (authctxt == پوچ)
		fatal_f("no authentication context");

	fatal("Unexpected authentication success during %s.",
	    authctxt->method->name);
	بازگشت 0;
}
#endif

ایستا صحیح
درون_داد_userauth_failure(صحیح type, uint32_t seq, ساختار ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	نویسه *authlist = پوچ;
	u_char partial;

	اگر (authctxt == پوچ)
		fatal("input_userauth_failure: no authentication context");

	اگر (sshpkt_get_cstring(ssh, &authlist, پوچ) != 0 ||
	    sshpkt_get_u8(ssh, &partial) != 0 ||
	    sshpkt_get_end(ssh) != 0)
		برو out;

	اگر (partial != 0) {
		verbose("Authenticated using \"%s\" with partial success.",
		    authctxt->method->name);
		/* reset state */
		pubkey_reset(authctxt);
	}
	debug("Authentications that can continue: %s", authlist);

	userauth(ssh, authlist);
	authlist = پوچ;
 out:
	آزاد(authlist);
	بازگشت 0;
}

/*
 * Format an identity for logging including filename, key type, fingerprint
 * and location (agent, etc.). Caller must free.
 */
ایستا نویسه *
format_identity(Identity *id)
{
	نویسه *fp = پوچ, *ret = پوچ;
	ثابت نویسه *note = "";

	اگر (id->کلید != پوچ) {
		fp = sshkey_fingerprint(id->کلید, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
	}
	اگر (id->کلید) {
		اگر ((id->کلید->flags & SSHKEY_FLAG_EXT) != 0)
			note = " token";
		وگرنه اگر (sshkey_is_sk(id->کلید))
			note = " authenticator";
	}
	xasprintf(&ret, "%s %s%s%s%s%s%s",
	    id->filename,
	    id->کلید ? sshkey_type(id->کلید) : "", id->کلید ? " " : "",
	    fp ? fp : "",
	    id->userprovided ? " explicit" : "", note,
	    id->agent_fd != -1 ? " agent" : "");
	آزاد(fp);
	بازگشت ret;
}

ایستا صحیح
درون_داد_userauth_pk_ok(صحیح type, uint32_t seq, ساختار ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	ساختار sshkey *کلید = پوچ;
	ساختار sshbuf *keyblob = پوچ;
	Identity *id = پوچ;
	صحیح pktype, found = 0, sent = 0;
	نویسه *pkalg = پوچ, *fp = پوچ, *ident = پوچ;
	صحیح r;

	اگر (authctxt == پوچ)
		fatal_f("no authentication context");

	اگر ((r = sshpkt_get_cstring(ssh, &pkalg, پوچ)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		برو done;

	اگر (match_pattern_list(pkalg, options.pubkey_accepted_algos, 0) != 1) {
		error_f("server replied to PK_OK with signature type %s not "
		    "in PubkeyAcceptedAlgorithms", pkalg);
		r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		برو done;
	}
	اگر ((pktype = sshkey_type_from_name(pkalg)) == کلید_UNSPEC) {
		debug_f("server sent unknown pkalg %s", pkalg);
		r = SSH_ERR_INVALID_FORMAT;
		برو done;
	}
	/* inner key type should match signature type */
	اگر ((r = sshkey_fromb_allowlist(keyblob, &کلید, pkalg, پوچ)) != 0) {
		debug_r(r, "no key from blob. pkalg %s", pkalg);
		برو done;
	}
	اگر (کلید->type != pktype) {
		error("input_userauth_pk_ok: type mismatch "
		    "for decoded key (received %d, expected %d)",
		    کلید->type, pktype);
		r = SSH_ERR_INVALID_FORMAT;
		برو done;
	}

	/*
	 * search keys in the reverse order, because last candidate has been
	 * moved to the end of the queue.  this also avoids confusion by
	 * duplicate keys
	 */
	TAILQ_FOREACH_REVERSE(id, &authctxt->کلیدها, idlist, next) {
		اگر (sshkey_equal(کلید, id->کلید)) {
			found = 1;
			بشکن;
		}
	}
	اگر (!found || id == پوچ) {
		fp = sshkey_fingerprint(کلید, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		error_f("server replied with unknown key: %s %s",
		    sshkey_type(کلید), fp == پوچ ? "<ERROR>" : fp);
		r = SSH_ERR_INVALID_FORMAT;
		برو done;
	}
	ident = format_identity(id);
	debug("Server accepts key: %s", ident);
	sent = sign_and_send_pubkey(ssh, id);
	r = 0;
 done:
	sshkey_free(کلید);
	sshbuf_free(keyblob);
	آزاد(ident);
	آزاد(fp);
	آزاد(pkalg);

	/* try another method if we did not send a packet */
	اگر (r == 0 && sent == 0)
		userauth(ssh, پوچ);
	بازگشت r;
}

#ifdef GSSAPI
ایستا صحیح
userauth_gssapi(ساختار ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Gssctxt *gssctxt = پوچ;
	OM_uint32 min;
	صحیح r, ok = 0;
	gss_OID mech = پوچ;

	/* Try one GSSAPI method at a time, rather than sending them all at
	 * once. */

	اگر (authctxt->gss_supported_mechs == پوچ)
		gss_indicate_mechs(&min, &authctxt->gss_supported_mechs);

	/* Check to see whether the mechanism is usable before we offer it */
	وقتی (authctxt->mech_tried < authctxt->gss_supported_mechs->شمار &&
	    !ok) {
		mech = &authctxt->gss_supported_mechs->
		    elements[authctxt->mech_tried];
		/* My DER encoding requires length<128 */
		اگر (mech->length < 128 && ssh_gssapi_check_mechanism(&gssctxt,
		    mech, authctxt->host)) {
			ok = 1; /* Mechanism works */
		} وگرنه {
			authctxt->mech_tried++;
		}
	}

	اگر (!ok || mech == پوچ)
		بازگشت 0;

	authctxt->methoddata=(تهی *)gssctxt;

	اگر ((r = sshpkt_start(ssh, SSH2_پیام_USERAUTH_REQUEST)) != 0 ||
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

	ssh_dispatch_set(ssh, SSH2_پیام_USERAUTH_GSSAPI_RESPONSE, &درون_داد_gssapi_response);
	ssh_dispatch_set(ssh, SSH2_پیام_USERAUTH_GSSAPI_TOKEN, &درون_داد_gssapi_token);
	ssh_dispatch_set(ssh, SSH2_پیام_USERAUTH_GSSAPI_ERROR, &درون_داد_gssapi_error);
	ssh_dispatch_set(ssh, SSH2_پیام_USERAUTH_GSSAPI_ERRTOK, &درون_داد_gssapi_errtok);

	authctxt->mech_tried++; /* Move along to next candidate */

	بازگشت 1;
}

ایستا تهی
userauth_gssapi_cleanup(ساختار ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Gssctxt *gssctxt = (Gssctxt *)authctxt->methoddata;

	ssh_gssapi_delete_ctx(&gssctxt);
	authctxt->methoddata = پوچ;
}

ایستا OM_uint32
process_gssapi_token(ساختار ssh *ssh, gss_buffer_t recv_tok)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt = authctxt->methoddata;
	gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc mic = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc gssbuf;
	OM_uint32 status, ms, flags;
	صحیح r;

	status = ssh_gssapi_init_ctx(gssctxt, options.gss_deleg_creds,
	    recv_tok, &send_tok, &flags);

	اگر (send_tok.length > 0) {
		u_char type = GSS_ERROR(status) ?
		    SSH2_پیام_USERAUTH_GSSAPI_ERRTOK :
		    SSH2_پیام_USERAUTH_GSSAPI_TOKEN;

		اگر ((r = sshpkt_start(ssh, type)) != 0 ||
		    (r = sshpkt_put_string(ssh, send_tok.مقدار,
		    send_tok.length)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send %u packet", type);

		gss_release_buffer(&ms, &send_tok);
	}

	اگر (status == GSS_S_COMPLETE) {
		/* send either complete or MIC, depending on mechanism */
		اگر (!(flags & GSS_C_INTEG_FLAG)) {
			اگر ((r = sshpkt_start(ssh,
			    SSH2_پیام_USERAUTH_GSSAPI_EXCHANGE_COMPLETE)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "send completion");
		} وگرنه {
			ساختار sshbuf *b;

			اگر ((b = sshbuf_new()) == پوچ)
				fatal_f("sshbuf_new failed");
			ssh_gssapi_buildmic(b, authctxt->server_user,
			    authctxt->service, "gssapi-with-mic",
			    ssh->kex->session_id);

			اگر ((gssbuf.مقدار = sshbuf_mutable_ptr(b)) == پوچ)
				fatal_f("sshbuf_mutable_ptr failed");
			gssbuf.length = sshbuf_len(b);

			status = ssh_gssapi_sign(gssctxt, &gssbuf, &mic);

			اگر (!GSS_ERROR(status)) {
				اگر ((r = sshpkt_start(ssh,
				    SSH2_پیام_USERAUTH_GSSAPI_MIC)) != 0 ||
				    (r = sshpkt_put_string(ssh, mic.مقدار,
				    mic.length)) != 0 ||
				    (r = sshpkt_send(ssh)) != 0)
					fatal_fr(r, "send MIC");
			}

			sshbuf_free(b);
			gss_release_buffer(&ms, &mic);
		}
	}

	بازگشت status;
}

ایستا صحیح
درون_داد_gssapi_response(صحیح type, uint32_t plen, ساختار ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	size_t oidlen;
	u_char *oidv = پوچ;
	صحیح r;

	اگر (authctxt == پوچ)
		fatal("input_gssapi_response: no authentication context");
	gssctxt = authctxt->methoddata;

	/* Setup our OID */
	اگر ((r = sshpkt_get_string(ssh, &oidv, &oidlen)) != 0)
		برو done;

	اگر (oidlen <= 2 ||
	    oidv[0] != SSH_GSS_OIDTYPE ||
	    oidv[1] != oidlen - 2) {
		debug("Badly encoded mechanism OID received");
		userauth(ssh, پوچ);
		برو ok;
	}

	اگر (!ssh_gssapi_check_oid(gssctxt, oidv + 2, oidlen - 2))
		fatal("Server returned different OID than expected");

	اگر ((r = sshpkt_get_end(ssh)) != 0)
		برو done;

	اگر (GSS_ERROR(process_gssapi_token(ssh, GSS_C_NO_BUFFER))) {
		/* Start again with next method on list */
		debug("Trying to start again");
		userauth(ssh, پوچ);
		برو ok;
	}
 ok:
	r = 0;
 done:
	آزاد(oidv);
	بازگشت r;
}

ایستا صحیح
درون_داد_gssapi_token(صحیح type, uint32_t plen, ساختار ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	gss_buffer_desc recv_tok;
	u_char *p = پوچ;
	size_t len;
	OM_uint32 status;
	صحیح r;

	اگر (authctxt == پوچ)
		fatal("input_gssapi_response: no authentication context");

	اگر ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		برو out;

	recv_tok.مقدار = p;
	recv_tok.length = len;
	status = process_gssapi_token(ssh, &recv_tok);

	/* Start again with the next method in the list */
	اگر (GSS_ERROR(status)) {
		userauth(ssh, پوچ);
		/* ok */
	}
	r = 0;
 out:
	آزاد(p);
	بازگشت r;
}

ایستا صحیح
درون_داد_gssapi_errtok(صحیح type, uint32_t plen, ساختار ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc recv_tok;
	OM_uint32 ms;
	u_char *p = پوچ;
	size_t len;
	صحیح r;

	اگر (authctxt == پوچ)
		fatal("input_gssapi_response: no authentication context");
	gssctxt = authctxt->methoddata;

	اگر ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0) {
		آزاد(p);
		بازگشت r;
	}

	/* Stick it into GSSAPI and see what it says */
	recv_tok.مقدار = p;
	recv_tok.length = len;
	(تهی)ssh_gssapi_init_ctx(gssctxt, options.gss_deleg_creds,
	    &recv_tok, &send_tok, پوچ);
	آزاد(p);
	gss_release_buffer(&ms, &send_tok);

	/* Server will be returning a failed packet after this one */
	بازگشت 0;
}

ایستا صحیح
درون_داد_gssapi_error(صحیح type, uint32_t plen, ساختار ssh *ssh)
{
	نویسه *پیام = پوچ;
	نویسه *lang = پوچ;
	صحیح r;

	اگر ((r = sshpkt_get_u32(ssh, پوچ)) != 0 ||	/* maj */
	    (r = sshpkt_get_u32(ssh, پوچ)) != 0 ||	/* min */
	    (r = sshpkt_get_cstring(ssh, &پیام, پوچ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, پوچ)) != 0)
		برو out;
	r = sshpkt_get_end(ssh);
	debug("Server GSSAPI Error:\n%s", پیام);
 out:
	آزاد(پیام);
	آزاد(lang);
	بازگشت r;
}
#endif /* GSSAPI */

ایستا صحیح
userauth_none(ساختار ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	صحیح r;

	/* initial userauth request */
	اگر ((r = sshpkt_start(ssh, SSH2_پیام_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	بازگشت 1;
}

ایستا صحیح
userauth_passwd(ساختار ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	نویسه *password, *prompt = پوچ;
	ثابت نویسه *host = options.host_کلید_alias ?  options.host_کلید_alias :
	    authctxt->host;
	صحیح r;

	اگر (authctxt->attempt_passwd++ >= options.عدد_of_password_prompts)
		بازگشت 0;

	اگر (authctxt->attempt_passwd != 1)
		error("Permission denied, please try again.");

	xasprintf(&prompt, "%s@%s's password: ", authctxt->server_user, host);
	password = read_passphrase(prompt, 0);
	اگر ((r = sshpkt_start(ssh, SSH2_پیام_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, password)) != 0 ||
	    (r = sshpkt_add_padding(ssh, 64)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	آزاد(prompt);
	اگر (password != پوچ)
		freezero(password, strlen(password));

	ssh_dispatch_set(ssh, SSH2_پیام_USERAUTH_PASSWD_CHANGEREQ,
	    &درون_داد_userauth_passwd_changereq);

	بازگشت 1;
}

/*
 * parse PASSWD_CHANGEREQ, prompt user and send SSH2_MSG_USERAUTH_REQUEST
 */
ایستا صحیح
درون_داد_userauth_passwd_changereq(صحیح type, uint32_t seqnr, ساختار ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	نویسه *info = پوچ, *lang = پوچ, *password = پوچ, *retype = پوچ;
	نویسه prompt[256];
	ثابت نویسه *host;
	صحیح r, addnl;
	size_t len;

	debug2("input_userauth_passwd_changereq");

	اگر (authctxt == پوچ)
		fatal("input_userauth_passwd_changereq: "
		    "no authentication context");
	host = options.host_کلید_alias ? options.host_کلید_alias : authctxt->host;

	اگر ((r = sshpkt_get_cstring(ssh, &info, پوچ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, پوچ)) != 0)
		برو out;
	اگر ((len = strlen(info)) > 0) {
		addnl = info[len] != '\n';
		fmprintf(stderr, "%s%s", info, addnl ? "\n" : "");
	}
	اگر ((r = sshpkt_start(ssh, SSH2_پیام_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0)	/* additional info */
		برو out;

	snprintf(prompt, اندازه(prompt),
	    "Enter %.30s@%.128s's old password: ",
	    authctxt->server_user, host);
	password = read_passphrase(prompt, 0);
	اگر ((r = sshpkt_put_cstring(ssh, password)) != 0)
		برو out;

	freezero(password, strlen(password));
	password = پوچ;
	وقتی (password == پوچ) {
		snprintf(prompt, اندازه(prompt),
		    "Enter %.30s@%.128s's new password: ",
		    authctxt->server_user, host);
		password = read_passphrase(prompt, RP_ALLOW_EOF);
		اگر (password == پوچ) {
			/* bail out */
			r = 0;
			برو out;
		}
		snprintf(prompt, اندازه(prompt),
		    "Retype %.30s@%.128s's new password: ",
		    authctxt->server_user, host);
		retype = read_passphrase(prompt, 0);
		اگر (strcmp(password, retype) != 0) {
			freezero(password, strlen(password));
			logit("Mismatch; try again, EOF to quit.");
			password = پوچ;
		}
		freezero(retype, strlen(retype));
	}
	اگر ((r = sshpkt_put_cstring(ssh, password)) != 0 ||
	    (r = sshpkt_add_padding(ssh, 64)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		برو out;

	ssh_dispatch_set(ssh, SSH2_پیام_USERAUTH_PASSWD_CHANGEREQ,
	    &درون_داد_userauth_passwd_changereq);
	r = 0;
 out:
	اگر (password)
		freezero(password, strlen(password));
	آزاد(info);
	آزاد(lang);
	بازگشت r;
}

/*
 * Select an algorithm for publickey signatures.
 * Returns algorithm (caller must free) or NULL if no mutual algorithm found.
 *
 * Call with ssh==NULL to ignore server-sig-algs extension list and
 * only attempt with the key's base signature type.
 */
ایستا نویسه *
کلید_sig_algorithm(ساختار ssh *ssh, ثابت ساختار sshkey *کلید)
{
	نویسه *allowed, *oallowed, *cp, *tmp, *alg = پوچ;
	ثابت نویسه *server_sig_algs;

	/*
	 * The signature algorithm will only differ from the key algorithm
	 * for RSA keys/certs and when the server advertises support for
	 * newer (SHA2) algorithms.
	 */
	اگر (ssh == پوچ || ssh->kex->server_sig_algs == پوچ ||
	    (کلید->type != کلید_RSA && کلید->type != کلید_RSA_CERT) ||
	    (کلید->type == کلید_RSA_CERT && (ssh->compat & SSH_BUG_SIGTYPE))) {
		/* Filter base key signature alg against our configuration */
		بازگشت match_list(sshkey_ssh_name(کلید),
		    options.pubkey_accepted_algos, پوچ);
	}

	/*
	 * Workaround OpenSSH 7.4 bug: this version supports RSA/SHA-2 but
	 * fails to advertise it via SSH2_MSG_EXT_INFO.
	 */
	server_sig_algs = ssh->kex->server_sig_algs;
	اگر (کلید->type == کلید_RSA && (ssh->compat & SSH_BUG_SIGTYPE74))
		server_sig_algs = "rsa-sha2-256,rsa-sha2-512";

	/*
	 * For RSA keys/certs, since these might have a different sig type:
	 * find the first entry in PubkeyAcceptedAlgorithms of the right type
	 * that also appears in the supported signature algorithms list from
	 * the server.
	 */
	oallowed = allowed = xstrdup(options.pubkey_accepted_algos);
	وقتی ((cp = strsep(&allowed, ",")) != پوچ) {
		اگر (sshkey_type_from_name(cp) != کلید->type)
			ادامه;
		tmp = match_list(sshkey_sigalg_by_name(cp),
		    server_sig_algs, پوچ);
		اگر (tmp != پوچ)
			alg = xstrdup(cp);
		آزاد(tmp);
		اگر (alg != پوچ)
			بشکن;
	}
	آزاد(oallowed);
	بازگشت alg;
}

ایستا صحیح
identity_sign(ساختار identity *id, u_char **sigp, size_t *lenp,
    ثابت u_char *data, size_t datalen, u_int compat, ثابت نویسه *alg)
{
	ساختار sshkey *sign_کلید = پوچ, *prv = پوچ;
	صحیح is_agent = 0, retried = 0, r = SSH_ERR_INTERNAL_ERROR;
	ساختار notifier_ctx *notifier = پوچ;
	نویسه *fp = پوچ, *pin = پوچ, *prompt = پوچ;

	*sigp = پوچ;
	*lenp = 0;

	/* The agent supports this key. */
	اگر (id->کلید != پوچ && id->agent_fd != -1) {
		بازگشت ssh_agent_sign(id->agent_fd, id->کلید, sigp, lenp,
		    data, datalen, alg, compat);
	}

	/*
	 * We have already loaded the private key or the private key is
	 * stored in external hardware.
	 */
	اگر (id->کلید != پوچ &&
	    (id->isprivate || (id->کلید->flags & SSHKEY_FLAG_EXT))) {
		sign_کلید = id->کلید;
		is_agent = 1;
	} وگرنه {
		/* Load the private key from the file. */
		اگر ((prv = load_identity_file(id)) == پوچ)
			بازگشت SSH_ERR_کلید_NOT_FOUND;
		اگر (id->کلید != پوچ && !sshkey_equal_public(prv, id->کلید)) {
			error_f("private key %s contents do not match public",
			    id->filename);
			r = SSH_ERR_کلید_NOT_FOUND;
			برو out;
		}
		sign_کلید = prv;
	}
 retry_pin:
	/* Prompt for touch for non-agent FIDO keys that request UP */
	اگر (!is_agent && sshkey_is_sk(sign_کلید) &&
	    (sign_کلید->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
		/* XXX should batch mode just skip these? */
		اگر ((fp = sshkey_fingerprint(sign_کلید,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == پوچ)
			fatal_f("fingerprint failed");
		notifier = notify_start(options.batch_mode,
		    "Confirm user presence for key %s %s",
		    sshkey_type(sign_کلید), fp);
		آزاد(fp);
	}
	اگر ((r = sshkey_sign(sign_کلید, sigp, lenp, data, datalen,
	    alg, options.sk_provider, pin, compat)) != 0) {
		debug_fr(r, "sshkey_sign");
		اگر (!retried && pin == پوچ && !is_agent &&
		    sshkey_is_sk(sign_کلید) &&
		    r == SSH_ERR_کلید_WRONG_PASSPHRASE) {
			notify_complete(notifier, پوچ);
			notifier = پوچ;
			xasprintf(&prompt, "Enter PIN for %s key %s: ",
			    sshkey_type(sign_کلید), id->filename);
			pin = read_passphrase(prompt, 0);
			retried = 1;
			برو retry_pin;
		}
		برو out;
	}

	/*
	 * PKCS#11 tokens may not support all signature algorithms,
	 * so check what we get back.
	 */
	اگر (id->کلید != پوچ && (id->کلید->flags & SSHKEY_FLAG_EXT) != 0 &&
	    (r = sshkey_check_sigtype(*sigp, *lenp, alg)) != 0) {
		debug_fr(r, "sshkey_check_sigtype");
		برو out;
	}
	/* success */
	r = 0;
 out:
	آزاد(prompt);
	اگر (pin != پوچ)
		freezero(pin, strlen(pin));
	notify_complete(notifier, r == 0 ? "User presence confirmed" : پوچ);
	sshkey_free(prv);
	بازگشت r;
}

ایستا صحیح
id_filename_matches(Identity *id, Identity *private_id)
{
	ایستا ثابت نویسه * ثابت suffixes[] = { ".pub", "-cert.pub", پوچ };
	size_t len = strlen(id->filename), plen = strlen(private_id->filename);
	size_t i, slen;

	اگر (strcmp(id->filename, private_id->filename) == 0)
		بازگشت 1;
	برای (i = 0; suffixes[i]; i++) {
		slen = strlen(suffixes[i]);
		اگر (len > slen && plen == len - slen &&
		    strcmp(id->filename + (len - slen), suffixes[i]) == 0 &&
		    memcmp(id->filename, private_id->filename, plen) == 0)
			بازگشت 1;
	}
	بازگشت 0;
}

ایستا صحیح
sign_and_send_pubkey(ساختار ssh *ssh, Identity *id)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	ساختار sshbuf *b = پوچ;
	Identity *private_id, *sign_id = پوچ;
	u_char *signature = پوچ;
	size_t slen = 0, skip = 0;
	صحیح r, fallback_sigtype, sent = 0;
	نویسه *alg = پوچ, *fp = پوچ;
	ثابت نویسه *loc = "", *method = "publickey";
	صحیح hostbound = 0;

	/* prefer host-bound pubkey signatures if supported by server */
	اگر ((ssh->kex->flags & KEX_HAS_PUBKEY_HOSTBOUND) != 0 &&
	    (options.pubkey_authentication & SSH_PUBKEY_AUTH_HBOUND) != 0) {
		hostbound = 1;
		method = "publickey-hostbound-v00@openssh.com";
	}

	اگر ((fp = sshkey_fingerprint(id->کلید, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == پوچ)
		بازگشت 0;

	debug3_f("using %s with %s %s", method, sshkey_type(id->کلید), fp);

	/*
	 * If the key is an certificate, try to find a matching private key
	 * and use it to complete the signature.
	 * If no such private key exists, fall back to trying the certificate
	 * key itself in case it has a private half already loaded.
	 * This will try to set sign_id to the private key that will perform
	 * the signature.
	 */
	اگر (id->agent_fd == -1 && sshkey_is_cert(id->کلید)) {
		TAILQ_FOREACH(private_id, &authctxt->کلیدها, next) {
			اگر (sshkey_equal_public(id->کلید, private_id->کلید) &&
			    id->کلید->type != private_id->کلید->type) {
				sign_id = private_id;
				بشکن;
			}
		}
		/*
		 * Exact key matches are preferred, but also allow
		 * filename matches for non-PKCS#11/agent keys that
		 * didn't load public keys. This supports the case
		 * of keeping just a private key file and public
		 * certificate on disk.
		 */
		اگر (sign_id == پوچ &&
		    !id->isprivate && id->agent_fd == -1 &&
		    (id->کلید->flags & SSHKEY_FLAG_EXT) == 0) {
			TAILQ_FOREACH(private_id, &authctxt->کلیدها, next) {
				اگر (private_id->کلید == پوچ &&
				    id_filename_matches(id, private_id)) {
					sign_id = private_id;
					بشکن;
				}
			}
		}
		اگر (sign_id != پوچ) {
			debug2_f("using private key \"%s\"%s for "
			    "certificate", sign_id->filename,
			    sign_id->agent_fd != -1 ? " from agent" : "");
		} وگرنه {
			debug_f("no separate private key for certificate "
			    "\"%s\"", id->filename);
		}
	}

	/*
	 * If the above didn't select another identity to do the signing
	 * then default to the one we started with.
	 */
	اگر (sign_id == پوچ)
		sign_id = id;

	/* assemble and sign data */
	برای (fallback_sigtype = 0; fallback_sigtype <= 1; fallback_sigtype++) {
		آزاد(alg);
		slen = 0;
		signature = پوچ;
		اگر ((alg = کلید_sig_algorithm(fallback_sigtype ? پوچ : ssh,
		    id->کلید)) == پوچ) {
			error_f("no mutual signature supported");
			برو out;
		}
		debug3_f("signing using %s %s", alg, fp);

		sshbuf_free(b);
		اگر ((b = sshbuf_new()) == پوچ)
			fatal_f("sshbuf_new failed");
		اگر ((r = sshbuf_put_stringb(b,
		    ssh->kex->session_id)) != 0)
			fatal_fr(r, "sshbuf_put_stringb");
		skip = sshbuf_len(b);
		اگر ((r = sshbuf_put_u8(b, SSH2_پیام_USERAUTH_REQUEST)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->server_user)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
		    (r = sshbuf_put_cstring(b, method)) != 0 ||
		    (r = sshbuf_put_u8(b, 1)) != 0 ||
		    (r = sshbuf_put_cstring(b, alg)) != 0 ||
		    (r = sshkey_puts(id->کلید, b)) != 0) {
			fatal_fr(r, "assemble signed data");
		}
		اگر (hostbound) {
			اگر (ssh->kex->initial_hostkey == پوچ) {
				fatal_f("internal error: initial hostkey "
				    "not recorded");
			}
			اگر ((r = sshkey_puts(ssh->kex->initial_hostkey, b)) != 0)
				fatal_fr(r, "assemble %s hostkey", method);
		}
		/* generate signature */
		r = identity_sign(sign_id, &signature, &slen,
		    sshbuf_ptr(b), sshbuf_len(b), ssh->compat, alg);
		اگر (r == 0)
			بشکن;
		وگرنه اگر (r == SSH_ERR_کلید_NOT_FOUND)
			برو out; /* soft failure */
		وگرنه اگر (r == SSH_ERR_SIGN_ALG_UNSUPPORTED &&
		    !fallback_sigtype) {
			اگر (sign_id->agent_fd != -1)
				loc = "agent ";
			وگرنه اگر (sign_id->کلید != پوچ &&
			    (sign_id->کلید->flags & SSHKEY_FLAG_EXT) != 0)
				loc = "token ";
			logit("%skey %s %s returned incorrect signature type",
			    loc, sshkey_type(id->کلید), fp);
			ادامه;
		}
		error_fr(r, "signing failed for %s \"%s\"%s",
		    sshkey_type(sign_id->کلید), sign_id->filename,
		    id->agent_fd != -1 ? " from agent" : "");
		برو out;
	}
	اگر (slen == 0 || signature == پوچ) /* shouldn't happen */
		fatal_f("no signature");

	/* append signature */
	اگر ((r = sshbuf_put_string(b, signature, slen)) != 0)
		fatal_fr(r, "append signature");

#ifdef DEBUG_PK
	sshbuf_dump(b, stderr);
#endif
	/* skip session id and packet type */
	اگر ((r = sshbuf_consume(b, skip + 1)) != 0)
		fatal_fr(r, "consume");

	/* put remaining data from buffer into packet */
	اگر ((r = sshpkt_start(ssh, SSH2_پیام_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_putb(ssh, b)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "enqueue request");

	/* success */
	sent = 1;

 out:
	آزاد(fp);
	آزاد(alg);
	sshbuf_free(b);
	freezero(signature, slen);
	بازگشت sent;
}

ایستا صحیح
send_pubkey_test(ساختار ssh *ssh, Identity *id)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	u_char *blob = پوچ;
	نویسه *alg = پوچ;
	size_t bloblen;
	u_int have_sig = 0;
	صحیح sent = 0, r;

	اگر ((alg = کلید_sig_algorithm(ssh, id->کلید)) == پوچ) {
		debug_f("no mutual signature algorithm");
		برو out;
	}

	اگر ((r = sshkey_to_blob(id->کلید, &blob, &bloblen)) != 0) {
		/* we cannot handle this key */
		debug3_f("cannot handle key");
		برو out;
	}
	/* register callback for USERAUTH_PK_OK message */
	ssh_dispatch_set(ssh, SSH2_پیام_USERAUTH_PK_OK, &درون_داد_userauth_pk_ok);

	اگر ((r = sshpkt_start(ssh, SSH2_پیام_USERAUTH_REQUEST)) != 0 ||
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
	آزاد(alg);
	آزاد(blob);
	بازگشت sent;
}

ایستا ساختار sshkey *
load_identity_file(Identity *id)
{
	ساختار sshkey *خصوصی = پوچ;
	نویسه prompt[300], *passphrase, *comment;
	صحیح r, quit = 0, i;
	ساختار stat st;

	اگر (stat(id->filename, &st) == -1) {
		do_log2(id->userprovided ?
		    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_DEBUG3,
		    "no such identity: %s: %s", id->filename, strerror(errno));
		بازگشت پوچ;
	}
	snprintf(prompt, اندازه prompt,
	    "Enter passphrase for key '%.100s': ", id->filename);
	برای (i = 0; i <= options.عدد_of_password_prompts; i++) {
		اگر (i == 0)
			passphrase = "";
		وگرنه {
			passphrase = read_passphrase(prompt, 0);
			اگر (*passphrase == '\0') {
				debug2("no passphrase given, try next key");
				آزاد(passphrase);
				بشکن;
			}
		}
		انتخاب ((r = sshkey_load_private_type(کلید_UNSPEC, id->filename,
		    passphrase, &خصوصی, &comment))) {
		حالت 0:
			بشکن;
		حالت SSH_ERR_کلید_WRONG_PASSPHRASE:
			اگر (options.batch_mode) {
				quit = 1;
				بشکن;
			}
			اگر (i != 0)
				debug2("bad passphrase given, try again...");
			بشکن;
		حالت SSH_ERR_SYSTEM_ERROR:
			اگر (errno == ENOENT) {
				debug2_r(r, "Load key \"%s\"", id->filename);
				quit = 1;
				بشکن;
			}
			/* FALLTHROUGH */
		پیشفرض:
			error_r(r, "Load key \"%s\"", id->filename);
			quit = 1;
			بشکن;
		}
		اگر (خصوصی != پوچ && sshkey_is_sk(خصوصی) &&
		    options.sk_provider == پوچ) {
			debug("key \"%s\" is an authenticator-hosted key, "
			    "but no provider specified", id->filename);
			sshkey_free(خصوصی);
			خصوصی = پوچ;
			quit = 1;
		}
		اگر (!quit && (r = sshkey_check_rsa_length(خصوصی,
		    options.required_rsa_size)) != 0) {
			debug_fr(r, "Skipping key %s", id->filename);
			sshkey_free(خصوصی);
			خصوصی = پوچ;
			quit = 1;
		}
		اگر (!quit && خصوصی != پوچ && id->agent_fd == -1 &&
		    !(id->کلید && id->isprivate))
			maybe_add_کلید_to_agent(id->filename, خصوصی, comment,
			    passphrase);
		اگر (i > 0)
			freezero(passphrase, strlen(passphrase));
		آزاد(comment);
		اگر (خصوصی != پوچ || quit)
			بشکن;
	}
	بازگشت خصوصی;
}

ایستا صحیح
کلید_type_allowed(ساختار sshkey *کلید, ثابت نویسه *allowlist)
{
	اگر (match_pattern_list(sshkey_ssh_name(کلید), allowlist, 0) == 1)
		بازگشت 1;

	/* RSA keys/certs might be allowed by alternate signature types */
	انتخاب (کلید->type) {
	حالت کلید_RSA:
		اگر (match_pattern_list("rsa-sha2-512", allowlist, 0) == 1)
			بازگشت 1;
		اگر (match_pattern_list("rsa-sha2-256", allowlist, 0) == 1)
			بازگشت 1;
		بشکن;
	حالت کلید_RSA_CERT:
		اگر (match_pattern_list("rsa-sha2-512-cert-v01@openssh.com",
		    allowlist, 0) == 1)
			بازگشت 1;
		اگر (match_pattern_list("rsa-sha2-256-cert-v01@openssh.com",
		    allowlist, 0) == 1)
			بازگشت 1;
		بشکن;
	}
	بازگشت 0;
}

ایستا صحیح
کلید_type_allowed_by_config(ساختار sshkey *کلید)
{
	بازگشت کلید_type_allowed(کلید, options.pubkey_accepted_algos);
}

/* obtain a list of keys from the agent */
ایستا صحیح
get_agent_identities(ساختار ssh *ssh, صحیح *agent_fdp,
    ساختار ssh_identitylist **idlistp)
{
	صحیح r, agent_fd;
	ساختار ssh_identitylist *idlist;

	اگر ((r = ssh_get_authentication_socket(&agent_fd)) != 0) {
		اگر (r != SSH_ERR_AGENT_NOT_PRESENT)
			debug_fr(r, "ssh_get_authentication_socket");
		بازگشت r;
	}
	اگر (ssh != پوچ && ssh->kex != پوچ) {
		اگر ((r = ssh_agent_bind_hostkey(agent_fd, ssh->kex->initial_hostkey,
		    ssh->kex->session_id, ssh->kex->initial_sig, 0)) == 0)
			debug_f("bound agent to hostkey");
		وگرنه
			debug2_fr(r, "ssh_agent_bind_hostkey");
	}

	اگر ((r = ssh_fetch_identitylist(agent_fd, &idlist)) != 0) {
		debug_fr(r, "ssh_fetch_identitylist");
		close(agent_fd);
		بازگشت r;
	}
	/* success */
	*agent_fdp = agent_fd;
	*idlistp = idlist;
	debug_f("agent returned %zu keys", idlist->nkeys);
	بازگشت 0;
}

/*
 * Returns nonzero if the certificate extensions/critical-options section
 * has the specified option present, zero otherwise.
 */
ایستا صحیح
cert_has_option(ساختار sshbuf *oblob, ثابت نویسه *target)
{
	ساختار sshbuf *c = پوچ, *data = پوچ;
	نویسه *name = پوچ;
	صحیح r, found = 0;

	اگر (oblob == پوچ || (c = sshbuf_fromb(oblob)) == پوچ)
		بازگشت 0;
	وقتی (sshbuf_len(c) > 0) {
		sshbuf_free(data);
		data = پوچ;
		آزاد(name);
		name = پوچ;
		اگر ((r = sshbuf_get_cstring(c, &name, پوچ)) != 0 ||
		    (r = sshbuf_froms(c, &data)) != 0)
			بشکن;
		اگر (strcmp(name, target) == 0) {
			found = 1;
			بشکن;
		}
	}
	sshbuf_free(data);
	آزاد(name);
	sshbuf_free(c);
	بازگشت found;
}

/*
 * Returns an integer describing the priority of the identity
 * within its group. Lower numbers are higher priority.
 */
#define MAX_ID_PRIORITY 3
ایستا صحیح
identity_prioritise(ساختار identity *id)
{
	اگر (id == پوچ || id->کلید == پوچ)
		بازگشت 3;
	اگر (!sshkey_is_cert(id->کلید) || id->کلید->cert == پوچ)
		بازگشت 3;
	اگر (sshkey_is_sk(id->کلید) &&
	    cert_has_option(id->کلید->cert->critical, "verify-required"))
		بازگشت 2;
	اگر (sshkey_is_sk(id->کلید) &&
	    cert_has_option(id->کلید->cert->extensions, "no-touch-required"))
		بازگشت 0;
	بازگشت 1;
}

ایستا تهی
order_identities_by_prio(ساختار idlist *list)
{
	ساختار idlist prio[MAX_ID_PRIORITY + 1], sorted;
	ساختار identity *id, *tmp, *dummy;
	صحیح p;

	برای (p = 0; p <= MAX_ID_PRIORITY; p++)
		TAILQ_INIT(&prio[p]);
	TAILQ_INIT(&sorted);

	TAILQ_FOREACH_SAFE(id, list, next, tmp) {
		اگر (id->userprovided)
			ادامه;
		dummy = xcalloc(1, اندازه(*dummy));
		dummy->userprovided = -1;
		TAILQ_INSERT_BEFORE(id, dummy, next);
		TAILQ_REMOVE(list, id, next);
		p = identity_prioritise(id);
		اگر (p < 0 || p > MAX_ID_PRIORITY)
			fatal_f("internal error: bad priority");
		TAILQ_INSERT_TAIL(&prio[p], id, next);
	}
	برای (p = 0; p <= MAX_ID_PRIORITY; p++)
		TAILQ_CONCAT(&sorted, &prio[p], next);

	TAILQ_FOREACH_SAFE(id, list, next, tmp) {
		اگر (id->userprovided != -1)
			ادامه;
		ساختار identity *s = TAILQ_FIRST(&sorted);
		TAILQ_REMOVE(&sorted, s, next);
		TAILQ_INSERT_BEFORE(id, s, next);
		TAILQ_REMOVE(list, id, next);
		آزاد(id);
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
ایستا تهی
pubkey_prepare(ساختار ssh *ssh, Authctxt *authctxt)
{
	ساختار identity *id, *id2, *tmp;
	ساختار idlist agent, files, certs, agent_کلیدها, *preferred;
	ساختار sshkey *کلید;
	صحیح disallowed, agent_fd = -1, i, r, found;
	size_t j;
	ساختار ssh_identitylist *idlist;
	نویسه *cp, *ident;

	TAILQ_INIT(&agent);	/* keys from the agent */
	TAILQ_INIT(&files);	/* keys from the config file */
	TAILQ_INIT(&certs);	/* certificates specified by user */
	TAILQ_INIT(&agent_کلیدها); /* keys supported by the agent */
	preferred = &authctxt->کلیدها;
	TAILQ_INIT(preferred);	/* preferred order of keys */

	/* list of keys stored in the filesystem and PKCS#11 */
	برای (i = 0; i < options.رقم_identity_files; i++) {
		کلید = options.identity_کلیدها[i];
		اگر (کلید && کلید->cert &&
		    کلید->cert->type != SSH2_CERT_TYPE_USER) {
			debug_f("ignoring certificate %s: not a user "
			    "certificate", options.identity_files[i]);
			ادامه;
		}
		اگر (کلید && sshkey_is_sk(کلید) && options.sk_provider == پوچ) {
			debug_f("ignoring authenticator-hosted key %s as no "
			    "SecurityKeyProvider has been specified",
			    options.identity_files[i]);
			ادامه;
		}
		options.identity_کلیدها[i] = پوچ;
		id = xcalloc(1, اندازه(*id));
		id->agent_fd = -1;
		id->کلید = کلید;
		id->filename = xstrdup(options.identity_files[i]);
		id->userprovided = options.identity_file_userprovided[i];
		TAILQ_INSERT_TAIL(&files, id, next);
	}

	/* list of certificates specified by user */
	برای (i = 0; i < options.رقم_certificate_files; i++) {
		کلید = options.certificates[i];
		اگر (!sshkey_is_cert(کلید) || کلید->cert == پوچ ||
		    کلید->cert->type != SSH2_CERT_TYPE_USER) {
			debug_f("ignoring certificate %s: not a user "
			    "certificate", options.identity_files[i]);
			ادامه;
		}
		اگر (کلید && sshkey_is_sk(کلید) && options.sk_provider == پوچ) {
			debug_f("ignoring authenticator-hosted key "
			    "certificate %s as no "
			    "SecurityKeyProvider has been specified",
			    options.identity_files[i]);
			ادامه;
		}
		id = xcalloc(1, اندازه(*id));
		id->agent_fd = -1;
		id->کلید = کلید;
		id->filename = xstrdup(options.certificate_files[i]);
		id->userprovided = options.certificate_file_userprovided[i];
		TAILQ_INSERT_TAIL(&certs, id, next);
	}
	order_identities_by_prio(&certs);
	TAILQ_CONCAT(preferred, &certs, next);

	/* list of keys supported by the agent */
	اگر ((r = get_agent_identities(ssh, &agent_fd, &idlist)) == 0) {
		برای (j = 0; j < idlist->nkeys; j++) {
			اگر ((r = sshkey_check_rsa_length(idlist->کلیدها[j],
			    options.required_rsa_size)) != 0) {
				debug_fr(r, "ignoring %s agent key",
				    sshkey_ssh_name(idlist->کلیدها[j]));
				ادامه;
			}
			found = 0;
			TAILQ_FOREACH(id, &files, next) {
				/*
				 * agent keys from the config file are
				 * preferred
				 */
				اگر (sshkey_equal(idlist->کلیدها[j], id->کلید)) {
					TAILQ_REMOVE(&files, id, next);
					TAILQ_INSERT_TAIL(&agent_کلیدها, id, next);
					id->agent_fd = agent_fd;
					found = 1;
					بشکن;
				}
			}
			اگر (!found && !options.identities_only) {
				id = xcalloc(1, اندازه(*id));
				/* XXX "steals" key/comment from idlist */
				id->کلید = idlist->کلیدها[j];
				id->filename = idlist->comments[j];
				idlist->کلیدها[j] = پوچ;
				idlist->comments[j] = پوچ;
				id->agent_fd = agent_fd;
				TAILQ_INSERT_TAIL(&agent, id, next);
			}
		}
		ssh_free_identitylist(idlist);
		/* append remaining agent keys */
		TAILQ_CONCAT(&agent_کلیدها, &agent, next);
		order_identities_by_prio(&agent_کلیدها);
		TAILQ_CONCAT(preferred, &agent_کلیدها, next);
		authctxt->agent_fd = agent_fd;
	}
	/* Prefer PKCS11 keys that are explicitly listed */
	TAILQ_FOREACH_SAFE(id, &files, next, tmp) {
		اگر (id->کلید == پوچ || (id->کلید->flags & SSHKEY_FLAG_EXT) == 0)
			ادامه;
		found = 0;
		TAILQ_FOREACH(id2, &files, next) {
			اگر (id2->کلید == پوچ ||
			    (id2->کلید->flags & SSHKEY_FLAG_EXT) != 0)
				ادامه;
			اگر (sshkey_equal(id->کلید, id2->کلید)) {
				TAILQ_REMOVE(&files, id, next);
				TAILQ_INSERT_TAIL(preferred, id, next);
				found = 1;
				بشکن;
			}
		}
		/* If IdentitiesOnly set and key not found then don't use it */
		اگر (!found && options.identities_only) {
			TAILQ_REMOVE(&files, id, next);
			freezero(id, اندازه(*id));
		}
	}
	order_identities_by_prio(&files);
	/* append remaining keys from the config file */
	TAILQ_CONCAT(preferred, &files, next);
	/* finally, filter by PubkeyAcceptedAlgorithms */
	TAILQ_FOREACH_SAFE(id, preferred, next, id2) {
		disallowed = 0;
		cp = پوچ;
		اگر (id->کلید == پوچ)
			ادامه;
		اگر (!کلید_type_allowed_by_config(id->کلید)) {
			debug("Skipping %s key %s - corresponding algorithm "
			    "not in PubkeyAcceptedAlgorithms",
			    sshkey_ssh_name(id->کلید), id->filename);
			disallowed = 1;
		} وگرنه اگر (ssh != پوچ && ssh->kex != پوچ &&
		    ssh->kex->server_sig_algs != پوچ &&
		    (cp = کلید_sig_algorithm(ssh, id->کلید)) == پوچ) {
			debug("Skipping %s key %s - corresponding algorithm "
			    "not supported by server",
			    sshkey_ssh_name(id->کلید), id->filename);
			disallowed = 1;
		}
		آزاد(cp);
		اگر (!disallowed)
			ادامه;
		/* remove key */
		TAILQ_REMOVE(preferred, id, next);
		sshkey_free(id->کلید);
		آزاد(id->filename);
		freezero(id, اندازه(*id));
	}
	/* List the keys we plan on using */
	TAILQ_FOREACH_SAFE(id, preferred, next, id2) {
		ident = format_identity(id);
		debug("Will attempt key: %s", ident);
		آزاد(ident);
	}
	debug2_f("done");
}

ایستا تهی
pubkey_cleanup(ساختار ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Identity *id;

	اگر (authctxt->agent_fd != -1) {
		ssh_close_authentication_socket(authctxt->agent_fd);
		authctxt->agent_fd = -1;
	}
	برای (id = TAILQ_FIRST(&authctxt->کلیدها); id;
	    id = TAILQ_FIRST(&authctxt->کلیدها)) {
		TAILQ_REMOVE(&authctxt->کلیدها, id, next);
		sshkey_free(id->کلید);
		آزاد(id->filename);
		آزاد(id);
	}
}

تهی
pubkey_dump(ساختار ssh *ssh)
{
	Authctxt authctxt;
	Identity *id;
	نویسه *ident;

	memset(&authctxt, 0, اندازه(authctxt));
	authctxt.agent_fd = -1;
	ssh->authctxt = &authctxt;

	pubkey_prepare(ssh, &authctxt);
	TAILQ_FOREACH(id, &authctxt.کلیدها, next) {
		ident = format_identity(id);
		fprintf(stdout, "%s\n", ident);
		آزاد(ident);
	}
	pubkey_cleanup(ssh);
	ssh->authctxt = پوچ;
}

ایستا تهی
pubkey_reset(Authctxt *authctxt)
{
	Identity *id;

	TAILQ_FOREACH(id, &authctxt->کلیدها, next)
		id->tried = 0;
}

ایستا صحیح
userauth_pubkey(ساختار ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Identity *id;
	صحیح sent = 0;
	نویسه *ident;
	ایستا صحیح prepared;

	اگر (!prepared) {
		pubkey_prepare(ssh, authctxt);
		prepared = 1;
	}

	وقتی ((id = TAILQ_FIRST(&authctxt->کلیدها))) {
		اگر (id->tried++)
			بازگشت (0);
		/* move key to the end of the queue */
		TAILQ_REMOVE(&authctxt->کلیدها, id, next);
		TAILQ_INSERT_TAIL(&authctxt->کلیدها, id, next);
		/*
		 * send a test message if we have the public key. for
		 * encrypted keys we cannot do this and have to load the
		 * private key instead
		 */
		اگر (id->کلید != پوچ) {
			ident = format_identity(id);
			debug("Offering public key: %s", ident);
			آزاد(ident);
			sent = send_pubkey_test(ssh, id);
		} وگرنه {
			debug("Trying private key: %s", id->filename);
			id->کلید = load_identity_file(id);
			اگر (id->کلید != پوچ) {
				id->isprivate = 1;
				sent = sign_and_send_pubkey(ssh, id);
				sshkey_free(id->کلید);
				id->کلید = پوچ;
				id->isprivate = 0;
			}
		}
		اگر (sent)
			بازگشت (sent);
	}
	بازگشت (0);
}

/*
 * Send userauth request message specifying keyboard-interactive method.
 */
ایستا صحیح
userauth_kbdint(ساختار ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	صحیح r;

	اگر (authctxt->attempt_kbdint++ >= options.عدد_of_password_prompts)
		بازگشت 0;
	/* disable if no SSH2_MSG_USERAUTH_INFO_REQUEST has been seen */
	اگر (authctxt->attempt_kbdint > 1 && !authctxt->info_req_seen) {
		debug3("userauth_kbdint: disable: no info_req_seen");
		ssh_dispatch_set(ssh, SSH2_پیام_USERAUTH_INFO_REQUEST, پوچ);
		بازگشت 0;
	}

	debug2("userauth_kbdint");
	اگر ((r = sshpkt_start(ssh, SSH2_پیام_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||		/* lang */
	    (r = sshpkt_put_cstring(ssh, options.kbd_interactive_devices ?
	    options.kbd_interactive_devices : "")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh_dispatch_set(ssh, SSH2_پیام_USERAUTH_INFO_REQUEST, &درون_داد_userauth_info_req);
	بازگشت 1;
}

/*
 * parse INFO_REQUEST, prompt user and send INFO_RESPONSE
 */
ایستا صحیح
درون_داد_userauth_info_req(صحیح type, uint32_t seq, ساختار ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	نویسه *name = پوچ, *inst = پوچ, *lang = پوچ, *prompt = پوچ;
	نویسه *display_prompt = پوچ, *response = پوچ;
	u_char echo = 0;
	u_int رقم_prompts, i;
	صحیح r, addnl;
	size_t len;

	debug2_f("entering");

	اگر (authctxt == پوچ)
		fatal_f("no authentication context");

	authctxt->info_req_seen = 1;

	اگر ((r = sshpkt_get_cstring(ssh, &name, پوچ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &inst, پوچ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, پوچ)) != 0)
		برو out;
	اگر ((len = strlen(name)) > 0) {
		addnl = name[len] != '\n';
		fmprintf(stderr, "%s%s", name, addnl ? "\n" : "");
	}
	اگر ((len = strlen(inst)) > 0) {
		addnl = inst[len] != '\n';
		fmprintf(stderr, "%s%s", inst, addnl ? "\n" : "");
	}

	اگر ((r = sshpkt_get_u32(ssh, &رقم_prompts)) != 0)
		برو out;
	/*
	 * Begin to build info response packet based on prompts requested.
	 * We commit to providing the correct number of responses, so if
	 * further on we run into a problem that prevents this, we have to
	 * be sure and clean this up and send a correct error response.
	 */
	اگر ((r = sshpkt_start(ssh, SSH2_پیام_USERAUTH_INFO_RESPONSE)) != 0 ||
	    (r = sshpkt_put_u32(ssh, رقم_prompts)) != 0)
		برو out;

	debug2_f("num_prompts %d", رقم_prompts);
	برای (i = 0; i < رقم_prompts; i++) {
		اگر ((r = sshpkt_get_cstring(ssh, &prompt, پوچ)) != 0 ||
		    (r = sshpkt_get_u8(ssh, &echo)) != 0)
			برو out;
		اگر (asmprintf(&display_prompt, INT_MAX, پوچ, "(%s@%s) %s",
		    authctxt->server_user, options.host_کلید_alias ?
		    options.host_کلید_alias : authctxt->host, prompt) == -1)
			fatal_f("asmprintf failed");
		response = read_passphrase(display_prompt, echo ? RP_ECHO : 0);
		اگر ((r = sshpkt_put_cstring(ssh, response)) != 0)
			برو out;
		freezero(response, strlen(response));
		آزاد(prompt);
		آزاد(display_prompt);
		display_prompt = response = prompt = پوچ;
	}
	/* done with parsing incoming message. */
	اگر ((r = sshpkt_get_end(ssh)) != 0 ||
	    (r = sshpkt_add_padding(ssh, 64)) != 0)
		برو out;
	r = sshpkt_send(ssh);
 out:
	اگر (response)
		freezero(response, strlen(response));
	آزاد(prompt);
	آزاد(display_prompt);
	آزاد(name);
	آزاد(inst);
	آزاد(lang);
	بازگشت r;
}

ایستا صحیح
ssh_keysign(ساختار ssh *ssh, ساختار sshkey *کلید, u_char **sigp, size_t *lenp,
    ثابت u_char *data, size_t datalen)
{
	ساختار sshbuf *b;
	ساختار stat st;
	pid_t pid;
	صحیح r, to[2], from[2], status;
	صحیح sock = ssh_packet_get_connection_in(ssh);
	u_char rversion = 0, version = 2;
	تهی (*osigchld)(صحیح);

	*sigp = پوچ;
	*lenp = 0;

	اگر (stat(PATH_SSH_کلید_SIGN, &st) == -1) {
		error_f("not installed: %s", strerror(errno));
		بازگشت -1;
	}
	اگر (fflush(stdout) != 0) {
		error_f("fflush: %s", strerror(errno));
		بازگشت -1;
	}
	اگر (pipe(to) == -1) {
		error_f("pipe: %s", strerror(errno));
		بازگشت -1;
	}
	اگر (pipe(from) == -1) {
		error_f("pipe: %s", strerror(errno));
		بازگشت -1;
	}
	اگر ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		بازگشت -1;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	اگر (pid == 0) {
		close(from[0]);
		اگر (dup2(from[1], STDOUT_FILENO) == -1)
			fatal_f("dup2: %s", strerror(errno));
		close(to[1]);
		اگر (dup2(to[0], STDIN_FILENO) == -1)
			fatal_f("dup2: %s", strerror(errno));
		close(from[1]);
		close(to[0]);

		اگر (dup2(sock, STDERR_FILENO + 1) == -1)
			fatal_f("dup2: %s", strerror(errno));
		sock = STDERR_FILENO + 1;
		اگر (fcntl(sock, F_SETFD, 0) == -1) /* keep the socket on exec */
			debug3_f("fcntl F_SETFD: %s", strerror(errno));
		closefrom(sock + 1);

		debug3_f("[child] pid=%ld, exec %s",
		    (long)getpid(), PATH_SSH_کلید_SIGN);
		execl(PATH_SSH_کلید_SIGN, PATH_SSH_کلید_SIGN, (نویسه *)پوچ);
		fatal_f("exec(%s): %s", PATH_SSH_کلید_SIGN,
		    strerror(errno));
	}
	close(from[1]);
	close(to[0]);
	sock = STDERR_FILENO + 1;

	اگر ((b = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	/* send # of sock, data to be signed */
	اگر ((r = sshbuf_put_u32(b, sock)) != 0 ||
	    (r = sshbuf_put_string(b, data, datalen)) != 0)
		fatal_fr(r, "buffer error");
	اگر (ssh_پیام_send(to[1], version, b) == -1)
		fatal_f("couldn't send request");
	sshbuf_reset(b);
	r = ssh_پیام_recv(from[0], b);
	close(from[0]);
	close(to[1]);
	اگر (r < 0) {
		error_f("no reply");
		برو fail;
	}

	errno = 0;
	وقتی (waitpid(pid, &status, 0) == -1) {
		اگر (errno != EINTR) {
			error_f("waitpid %ld: %s", (long)pid, strerror(errno));
			برو fail;
		}
	}
	اگر (!WIFEXITED(status)) {
		error_f("exited abnormally");
		برو fail;
	}
	اگر (WEXITSTATUS(status) != 0) {
		error_f("exited with status %d", WEXITSTATUS(status));
		برو fail;
	}
	اگر ((r = sshbuf_get_u8(b, &rversion)) != 0) {
		error_fr(r, "buffer error");
		برو fail;
	}
	اگر (rversion != version) {
		error_f("bad version");
		برو fail;
	}
	اگر ((r = sshbuf_get_string(b, sigp, lenp)) != 0) {
		error_fr(r, "buffer error");
 fail:
		ssh_signal(SIGCHLD, osigchld);
		sshbuf_free(b);
		بازگشت -1;
	}
	ssh_signal(SIGCHLD, osigchld);
	sshbuf_free(b);

	بازگشت 0;
}

ایستا صحیح
userauth_hostbased(ساختار ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	ساختار sshkey *خصوصی = پوچ;
	ساختار sshbuf *b = پوچ;
	u_char *sig = پوچ, *keyblob = پوچ;
	نویسه *fp = پوچ, *chost = پوچ, *lname = پوچ;
	size_t siglen = 0, keylen = 0;
	صحیح i, r, success = 0;

	اگر (authctxt->ktypes == پوچ) {
		authctxt->oktypes = xstrdup(options.hostbased_accepted_algos);
		authctxt->ktypes = authctxt->oktypes;
	}

	/*
	 * Work through each listed type pattern in HostbasedAcceptedAlgorithms,
	 * trying each hostkey that matches the type in turn.
	 */
	برای (;;) {
		اگر (authctxt->active_ktype == پوچ)
			authctxt->active_ktype = strsep(&authctxt->ktypes, ",");
		اگر (authctxt->active_ktype == پوچ ||
		    *authctxt->active_ktype == '\0')
			بشکن;
		debug3_f("trying key type %s", authctxt->active_ktype);

		/* check for a useful key */
		خصوصی = پوچ;
		برای (i = 0; i < authctxt->sensitive->nkeys; i++) {
			اگر (authctxt->sensitive->کلیدها[i] == پوچ ||
			    authctxt->sensitive->کلیدها[i]->type == کلید_UNSPEC)
				ادامه;
			اگر (!sshkey_match_keyname_to_sigalgs(
			    sshkey_ssh_name(authctxt->sensitive->کلیدها[i]),
			    authctxt->active_ktype))
				ادامه;
			/* we take and free the key */
			خصوصی = authctxt->sensitive->کلیدها[i];
			authctxt->sensitive->کلیدها[i] = پوچ;
			بشکن;
		}
		/* Found one */
		اگر (خصوصی != پوچ)
			بشکن;
		/* No more keys of this type; advance */
		authctxt->active_ktype = پوچ;
	}
	اگر (خصوصی == پوچ) {
		آزاد(authctxt->oktypes);
		authctxt->oktypes = authctxt->ktypes = پوچ;
		authctxt->active_ktype = پوچ;
		debug("No more client hostkeys for hostbased authentication.");
		برو out;
	}

	اگر ((fp = sshkey_fingerprint(خصوصی, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == پوچ) {
		error_f("sshkey_fingerprint failed");
		برو out;
	}
	debug_f("trying hostkey %s %s using sigalg %s",
	    sshkey_ssh_name(خصوصی), fp, authctxt->active_ktype);

	/* figure out a name for the client host */
	lname = get_local_name(ssh_packet_get_connection_in(ssh));
	اگر (lname == پوچ) {
		error_f("cannot get local ipaddr/name");
		برو out;
	}

	/* XXX sshbuf_put_stringf? */
	xasprintf(&chost, "%s.", lname);
	debug2_f("chost %s", chost);

	/* construct data */
	اگر ((b = sshbuf_new()) == پوچ) {
		error_f("sshbuf_new failed");
		برو out;
	}
	اگر ((r = sshkey_to_blob(خصوصی, &keyblob, &keylen)) != 0) {
		error_fr(r, "sshkey_to_blob");
		برو out;
	}
	اگر ((r = sshbuf_put_stringb(b, ssh->kex->session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_پیام_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->server_user)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->method->name)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->active_ktype)) != 0 ||
	    (r = sshbuf_put_string(b, keyblob, keylen)) != 0 ||
	    (r = sshbuf_put_cstring(b, chost)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->local_user)) != 0) {
		error_fr(r, "buffer error");
		برو out;
	}

#ifdef DEBUG_PK
	sshbuf_dump(b, stderr);
#endif
	اگر ((r = ssh_keysign(ssh, خصوصی, &sig, &siglen,
	    sshbuf_ptr(b), sshbuf_len(b))) != 0) {
		error("sign using hostkey %s %s failed",
		    sshkey_ssh_name(خصوصی), fp);
		برو out;
	}
	اگر ((r = sshpkt_start(ssh, SSH2_پیام_USERAUTH_REQUEST)) != 0 ||
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
		برو out;
	}
	success = 1;

 out:
	اگر (sig != پوچ)
		freezero(sig, siglen);
	آزاد(keyblob);
	آزاد(lname);
	آزاد(fp);
	آزاد(chost);
	sshkey_free(خصوصی);
	sshbuf_free(b);

	بازگشت success;
}

/* find auth method */

/*
 * given auth method name, if configurable options permit this method fill
 * in auth_ident field and return true, otherwise return false.
 */
ایستا صحیح
authmethod_is_enabled(Authmethod *method)
{
	اگر (method == پوچ)
		بازگشت 0;
	/* return false if options indicate this method is disabled */
	اگر  (method->enabled == پوچ || *method->enabled == 0)
		بازگشت 0;
	/* return false if batch mode is enabled but method needs interactive mode */
	اگر  (method->batch_flag != پوچ && *method->batch_flag != 0)
		بازگشت 0;
	بازگشت 1;
}

ایستا Authmethod *
authmethod_lookup(ثابت نویسه *name)
{
	Authmethod *method = پوچ;
	اگر (name != پوچ)
		برای (method = authmethods; method->name != پوچ; method++)
			اگر (strcmp(name, method->name) == 0)
				بازگشت method;
	debug2("Unrecognized authentication method name: %s", name ? name : "NULL");
	بازگشت پوچ;
}

/* XXX internal state */
ایستا Authmethod *current = پوچ;
ایستا نویسه *supported = پوچ;
ایستا نویسه *preferred = پوچ;

/*
 * Given the authentication method list sent by the server, return the
 * next method we should try.  If the server initially sends a nil list,
 * use a built-in default list.
 */
ایستا Authmethod *
authmethod_get(نویسه *authlist)
{
	نویسه *name = پوچ;
	u_int next;

	/* Use a suitable default if we're passed a nil list.  */
	اگر (authlist == پوچ || strlen(authlist) == 0)
		authlist = options.preferred_authentications;

	اگر (supported == پوچ || strcmp(authlist, supported) != 0) {
		debug3("start over, passed a different list %s", authlist);
		آزاد(supported);
		supported = xstrdup(authlist);
		preferred = options.preferred_authentications;
		debug3("preferred %s", preferred);
		current = پوچ;
	} وگرنه اگر (current != پوچ && authmethod_is_enabled(current))
		بازگشت current;

	برای (;;) {
		اگر ((name = match_list(preferred, supported, &next)) == پوچ) {
			debug("No more authentication methods to try.");
			current = پوچ;
			بازگشت پوچ;
		}
		preferred += next;
		debug3("authmethod_lookup %s", name);
		debug3("remaining preferred: %s", preferred);
		اگر ((current = authmethod_lookup(name)) != پوچ &&
		    authmethod_is_enabled(current)) {
			debug3("authmethod_is_enabled %s", name);
			debug("Next authentication method: %s", name);
			آزاد(name);
			بازگشت current;
		}
		آزاد(name);
	}
}

ایستا نویسه *
authmethods_get(تهی)
{
	Authmethod *method = پوچ;
	ساختار sshbuf *b;
	نویسه *list;
	صحیح r;

	اگر ((b = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	برای (method = authmethods; method->name != پوچ; method++) {
		اگر (authmethod_is_enabled(method)) {
			اگر ((r = sshbuf_putf(b, "%s%s",
			    sshbuf_len(b) ? "," : "", method->name)) != 0)
				fatal_fr(r, "buffer error");
		}
	}
	اگر ((list = sshbuf_dup_string(b)) == پوچ)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	بازگشت list;
}
