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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/socket.h>
#অন্তর্ভাব <sys/wait.h>
#অন্তর্ভাব <sys/queue.h>
#অন্তর্ভাব <sys/stat.h>

#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <fcntl.h>
#অন্তর্ভাব <limits.h>
#অন্তর্ভাব <pwd.h>
#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <unistd.h>
#যদি defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
#অন্তর্ভাব <vis.h>
#endif

#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "ssh.h"
#অন্তর্ভাব "ssh2.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "packet.h"
#অন্তর্ভাব "compat.h"
#অন্তর্ভাব "cipher.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "kex.h"
#অন্তর্ভাব "sshconnect.h"
#অন্তর্ভাব "authfile.h"
#অন্তর্ভাব "authfd.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "readconf.h"
#অন্তর্ভাব "match.h"
#অন্তর্ভাব "dispatch.h"
#অন্তর্ভাব "canohost.h"
#অন্তর্ভাব "msg.h"
#অন্তর্ভাব "pathnames.h"
#অন্তর্ভাব "hostfile.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "utf8.h"
#অন্তর্ভাব "ssh-sk.h"
#অন্তর্ভাব "sk-api.h"

#ifdef GSSAPI
#অন্তর্ভাব "ssh-gss.h"
#endif

/* import */
বাহ্যিক Options options;

/*
 * SSH2 key exchange
 */

স্থির অক্ষর *xxx_host;
স্থির কাঠামো sockaddr_storage xxx_hostaddr;
স্থির ধ্রুবক কাঠামো ssh_conn_info *xxx_conn_info;
স্থির পূর্ণসংখ্যা চাবি_type_allowed(কাঠামো sshkey *, ধ্রুবক অক্ষর *);

স্থির পূর্ণসংখ্যা
verify_host_চাবি_callback(কাঠামো sshkey *hostkey, কাঠামো ssh *ssh)
{
	পূর্ণসংখ্যা r;

	যদি ((r = sshkey_check_rsa_দৈর্ঘ্য(hostkey,
	    options.required_rsa_আকার)) != 0)
		fatal_r(r, "Bad server host key");
	যদি (!চাবি_type_allowed(hostkey, options.hostkeyalgorithms)) {
		fatal("Server host key %s not in HostKeyAlgorithms",
		    sshkey_ssh_name(hostkey));
	}
	যদি (verify_host_চাবি(xxx_host, (কাঠামো sockaddr *)&xxx_hostaddr, hostkey,
	    xxx_conn_info) != 0)
		fatal("Host key verification failed.");
	ফেরত 0;
}

/* Returns the first item from a comma-separated algorithm list */
স্থির অক্ষর *
first_alg(ধ্রুবক অক্ষর *algs)
{
	অক্ষর *ret, *cp;

	ret = xstrdup(algs);
	যদি ((cp = strchr(ret, ',')) != ফাঁকা)
		*cp = '\0';
	ফেরত ret;
}

স্থির অক্ষর *
order_hostkeyalgs(অক্ষর *host, কাঠামো sockaddr *hostaddr, u_short port,
    ধ্রুবক কাঠামো ssh_conn_info *cinfo)
{
	অক্ষর *oavail = ফাঁকা, *avail = ফাঁকা, *first = ফাঁকা, *last = ফাঁকা;
	অক্ষর *alg = ফাঁকা, *hostname = ফাঁকা, *ret = ফাঁকা, *best = ফাঁকা;
	আকার_t maxlen;
	কাঠামো hostkeys *hostkeys = ফাঁকা;
	পূর্ণসংখ্যা ktype;
	u_int i;

	/* Find all hostkeys for this hostname */
	get_hostfile_hostname_ipaddr(host, hostaddr, port, &hostname, ফাঁকা);
	hostkeys = init_hostkeys();
	জন্য (i = 0; i < options.অঙ্ক_user_hostfiles; i++)
		load_hostkeys(hostkeys, hostname, options.user_hostfiles[i], 0);
	জন্য (i = 0; i < options.অঙ্ক_system_hostfiles; i++) {
		load_hostkeys(hostkeys, hostname,
		    options.system_hostfiles[i], 0);
	}
	যদি (options.known_hosts_command != ফাঁকা) {
		load_hostkeys_command(hostkeys, options.known_hosts_command,
		    "ORDER", cinfo, ফাঁকা, hostname);
	}
	/*
	 * If a plain public key exists that matches the type of the best
	 * preference HostkeyAlgorithms, then use the whole list as is.
	 * Note that we ignore whether the best preference algorithm is a
	 * certificate type, as sshconnect.c will downgrade certs to
	 * plain keys if necessary.
	 */
	best = first_alg(options.hostkeyalgorithms);
	যদি (lookup_চাবি_in_hostkeys_by_type(hostkeys,
	    sshkey_type_plain(sshkey_type_from_name(best)),
	    sshkey_ecdsa_nid_from_name(best), ফাঁকা)) {
		debug3_f("have matching best-preference key type %s, "
		    "using HostkeyAlgorithms verbatim", best);
		ret = xstrdup(options.hostkeyalgorithms);
		যাও out;
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
	করো { \
		যদি (*to != '\0') \
			strlcat(to, ",", maxlen); \
		strlcat(to, from, maxlen); \
	} যখন (0)

	যখন ((alg = strsep(&avail, ",")) && *alg != '\0') {
		যদি ((ktype = sshkey_type_from_name(alg)) == চাবি_UNSPEC)
			fatal_f("unknown alg %s", alg);
		/*
		 * If we have a @cert-authority marker in known_hosts then
		 * prefer all certificate algorithms.
		 */
		যদি (sshkey_type_is_cert(ktype) &&
		    lookup_marker_in_hostkeys(hostkeys, MRK_CA)) {
			ALG_APPEND(first, alg);
			চালু;
		}
		/* If the key appears in known_hosts then prefer it */
		যদি (lookup_চাবি_in_hostkeys_by_type(hostkeys,
		    sshkey_type_plain(ktype),
		    sshkey_ecdsa_nid_from_name(alg), ফাঁকা)) {
			ALG_APPEND(first, alg);
			চালু;
		}
		/* Otherwise, put it last */
		ALG_APPEND(last, alg);
	}
#undef ALG_APPEND
	xasprintf(&ret, "%s%s%s", first,
	    (*first == '\0' || *last == '\0') ? "" : ",", last);
	যদি (*first != '\0')
		debug3_f("prefer hostkeyalgs: %s", first);
	অন্যথা
		debug3_f("no algorithms matched; accept original");
 out:
	মুক্ত(best);
	মুক্ত(first);
	মুক্ত(last);
	মুক্ত(hostname);
	মুক্ত(oavail);
	free_hostkeys(hostkeys);

	ফেরত ret;
}

শূন্য
ssh_kex2(কাঠামো ssh *ssh, অক্ষর *host, কাঠামো sockaddr_storage *hostaddr,
    u_short port, ধ্রুবক কাঠামো ssh_conn_info *cinfo)
{
	অক্ষর *myproposal[PROPOSAL_MAX];
	অক্ষর *all_চাবি, *hkalgs = ফাঁকা;
	পূর্ণসংখ্যা r, use_known_hosts_order = 0;

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
	যদি (options.hostkeyalgorithms == ফাঁকা ||
	    options.hostkeyalgorithms[0] == '-' ||
	    options.hostkeyalgorithms[0] == '+')
		use_known_hosts_order = 1;

	/* Expand or fill in HostkeyAlgorithms */
	all_চাবি = sshkey_alg_list(0, 0, 1, ',');
	যদি ((r = kex_assemble_names(&options.hostkeyalgorithms,
	    kex_default_pk_alg(), all_চাবি)) != 0)
		fatal_fr(r, "kex_assemble_namelist");
	মুক্ত(all_চাবি);

	যদি (use_known_hosts_order) {
		hkalgs = order_hostkeyalgs(host, (কাঠামো sockaddr *)hostaddr,
		    port, cinfo);
	}

	kex_proposal_populate_entries(ssh, myproposal,
	    options.kex_algorithms, options.ciphers, options.macs,
	    compression_alg_list(options.compression),
	    hkalgs ? hkalgs : options.hostkeyalgorithms);

	মুক্ত(hkalgs);

	/* start key exchange */
	যদি ((r = kex_setup(ssh, myproposal)) != 0)
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
	ssh->kex->verify_host_চাবি=&verify_host_চাবি_callback;

	ssh_dispatch_run_fatal(ssh, DISPATCH_BLOCK, &ssh->kex->done);
	kex_proposal_free_entries(myproposal);

#ifdef DEBUG_KEXDH
	/* send 1st encrypted/maced/compressed message */
	যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_IGNORE)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "markus")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send packet");
#endif
}

/*
 * Authenticate user
 */

প্রকারলেখ কাঠামো cauthctxt Authctxt;
প্রকারলেখ কাঠামো cauthmethod Authmethod;
প্রকারলেখ কাঠামো identity Identity;
প্রকারলেখ কাঠামো idlist Idlist;

কাঠামো identity {
	TAILQ_ENTRY(identity) পরবর্তী;
	পূর্ণসংখ্যা	agent_fd;		/* >=0 if agent supports key */
	কাঠামো sshkey	*চাবি;		/* public/private key */
	অক্ষর	*filename;		/* comment for agent-only keys */
	পূর্ণসংখ্যা	tried;
	পূর্ণসংখ্যা	isprivate;		/* key points to the private key */
	পূর্ণসংখ্যা	userprovided;
};
TAILQ_HEAD(idlist, identity);

কাঠামো cauthctxt {
	ধ্রুবক অক্ষর *server_user;
	ধ্রুবক অক্ষর *local_user;
	ধ্রুবক অক্ষর *host;
	ধ্রুবক অক্ষর *service;
	কাঠামো cauthmethod *method;
	sig_atomic_t success;
	অক্ষর *authlist;
#ifdef GSSAPI
	/* gssapi */
	gss_OID_set gss_supported_mechs;
	u_int mech_tried;
#endif
	/* pubkey */
	কাঠামো idlist চাবিগুলি;
	পূর্ণসংখ্যা agent_fd;
	/* hostbased */
	Sensitive *sensitive;
	অক্ষর *oktypes, *ktypes;
	ধ্রুবক অক্ষর *active_ktype;
	/* kbd-interactive */
	পূর্ণসংখ্যা info_req_seen;
	পূর্ণসংখ্যা attempt_kbdint;
	/* password */
	পূর্ণসংখ্যা attempt_passwd;
	/* generic */
	শূন্য *methoddata;
};

কাঠামো cauthmethod {
	অক্ষর	*name;		/* string to compare against server's list */
	পূর্ণসংখ্যা	(*userauth)(কাঠামো ssh *ssh);
	শূন্য	(*cleanup)(কাঠামো ssh *ssh);
	পূর্ণসংখ্যা	*enabled;	/* flag in option struct that enables method */
	পূর্ণসংখ্যা	*batch_flag;	/* flag in option struct that disables method */
};

স্থির পূর্ণসংখ্যা প্রবেশ_userauth_service_accept(পূর্ণসংখ্যা, uint32_t, কাঠামো ssh *);
স্থির পূর্ণসংখ্যা প্রবেশ_userauth_success(পূর্ণসংখ্যা, uint32_t, কাঠামো ssh *);
স্থির পূর্ণসংখ্যা প্রবেশ_userauth_failure(পূর্ণসংখ্যা, uint32_t, কাঠামো ssh *);
স্থির পূর্ণসংখ্যা প্রবেশ_userauth_banner(পূর্ণসংখ্যা, uint32_t, কাঠামো ssh *);
স্থির পূর্ণসংখ্যা প্রবেশ_userauth_error(পূর্ণসংখ্যা, uint32_t, কাঠামো ssh *);
স্থির পূর্ণসংখ্যা প্রবেশ_userauth_info_req(পূর্ণসংখ্যা, uint32_t, কাঠামো ssh *);
স্থির পূর্ণসংখ্যা প্রবেশ_userauth_pk_ok(পূর্ণসংখ্যা, uint32_t, কাঠামো ssh *);
স্থির পূর্ণসংখ্যা প্রবেশ_userauth_passwd_changereq(পূর্ণসংখ্যা, uint32_t, কাঠামো ssh *);

স্থির পূর্ণসংখ্যা userauth_none(কাঠামো ssh *);
স্থির পূর্ণসংখ্যা userauth_pubkey(কাঠামো ssh *);
স্থির পূর্ণসংখ্যা userauth_passwd(কাঠামো ssh *);
স্থির পূর্ণসংখ্যা userauth_kbdint(কাঠামো ssh *);
স্থির পূর্ণসংখ্যা userauth_hostbased(কাঠামো ssh *);

#ifdef GSSAPI
স্থির পূর্ণসংখ্যা userauth_gssapi(কাঠামো ssh *);
স্থির শূন্য userauth_gssapi_cleanup(কাঠামো ssh *);
স্থির পূর্ণসংখ্যা প্রবেশ_gssapi_response(পূর্ণসংখ্যা type, uint32_t, কাঠামো ssh *);
স্থির পূর্ণসংখ্যা প্রবেশ_gssapi_token(পূর্ণসংখ্যা type, uint32_t, কাঠামো ssh *);
স্থির পূর্ণসংখ্যা প্রবেশ_gssapi_error(পূর্ণসংখ্যা, uint32_t, কাঠামো ssh *);
স্থির পূর্ণসংখ্যা প্রবেশ_gssapi_errtok(পূর্ণসংখ্যা, uint32_t, কাঠামো ssh *);
#endif

শূন্য	userauth(কাঠামো ssh *, অক্ষর *);

স্থির শূন্য pubkey_cleanup(কাঠামো ssh *);
স্থির পূর্ণসংখ্যা sign_and_send_pubkey(কাঠামো ssh *ssh, Identity *);
স্থির শূন্য pubkey_prepare(কাঠামো ssh *, Authctxt *);
স্থির শূন্য pubkey_reset(Authctxt *);
স্থির কাঠামো sshkey *load_identity_file(Identity *);

স্থির Authmethod *authmethod_get(অক্ষর *authlist);
স্থির Authmethod *authmethod_lookup(ধ্রুবক অক্ষর *name);
স্থির অক্ষর *authmethods_get(শূন্য);

Authmethod authmethods[] = {
#ifdef GSSAPI
	{"gssapi-with-mic",
		userauth_gssapi,
		userauth_gssapi_cleanup,
		&options.gss_authentication,
		ফাঁকা},
#endif
	{"hostbased",
		userauth_hostbased,
		ফাঁকা,
		&options.hostbased_authentication,
		ফাঁকা},
	{"publickey",
		userauth_pubkey,
		ফাঁকা,
		&options.pubkey_authentication,
		ফাঁকা},
	{"keyboard-interactive",
		userauth_kbdint,
		ফাঁকা,
		&options.kbd_interactive_authentication,
		&options.batch_mode},
	{"password",
		userauth_passwd,
		ফাঁকা,
		&options.password_authentication,
		&options.batch_mode},
	{"none",
		userauth_none,
		ফাঁকা,
		ফাঁকা,
		ফাঁকা},
	{ফাঁকা, ফাঁকা, ফাঁকা, ফাঁকা, ফাঁকা}
};

শূন্য
ssh_userauth2(কাঠামো ssh *ssh, ধ্রুবক অক্ষর *local_user,
    ধ্রুবক অক্ষর *server_user, অক্ষর *host, Sensitive *sensitive)
{
	Authctxt authctxt;
	পূর্ণসংখ্যা r;

	যদি (options.preferred_authentications == ফাঁকা)
		options.preferred_authentications = authmethods_get();

	/* setup authentication context */
	memset(&authctxt, 0, আকার(authctxt));
	authctxt.server_user = server_user;
	authctxt.local_user = local_user;
	authctxt.host = host;
	authctxt.service = "ssh-connection";		/* service name */
	authctxt.success = 0;
	authctxt.method = authmethod_lookup("none");
	authctxt.authlist = ফাঁকা;
	authctxt.methoddata = ফাঁকা;
	authctxt.sensitive = sensitive;
	authctxt.active_ktype = authctxt.oktypes = authctxt.ktypes = ফাঁকা;
	authctxt.info_req_seen = 0;
	authctxt.attempt_kbdint = 0;
	authctxt.attempt_passwd = 0;
#যদি GSSAPI
	authctxt.gss_supported_mechs = ফাঁকা;
	authctxt.mech_tried = 0;
#endif
	authctxt.agent_fd = -1;
	যদি (authctxt.method == ফাঁকা)
		fatal_f("internal error: cannot send userauth none request");

	যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_SERVICE_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "ssh-userauth")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh->authctxt = &authctxt;
	ssh_dispatch_init(ssh, &প্রবেশ_userauth_error);
	ssh_dispatch_set(ssh, SSH2_বার্তা_EXT_INFO, kex_প্রবেশ_ext_info);
	ssh_dispatch_set(ssh, SSH2_বার্তা_SERVICE_ACCEPT, &প্রবেশ_userauth_service_accept);
	ssh_dispatch_run_fatal(ssh, DISPATCH_BLOCK, &authctxt.success);	/* loop until success */
	pubkey_cleanup(ssh);
#ifdef GSSAPI
	যদি (authctxt.gss_supported_mechs != ফাঁকা) {
		u_int ms;

		gss_release_oid_set(&ms, &authctxt.gss_supported_mechs);
		authctxt.gss_supported_mechs = ফাঁকা;
	}
#endif
	ssh->authctxt = ফাঁকা;

	ssh_dispatch_range(ssh, SSH2_বার্তা_USERAUTH_MIN, SSH2_বার্তা_USERAUTH_MAX, ফাঁকা);

	যদি (!authctxt.success)
		fatal("Authentication failed.");
	যদি (ssh_packet_connection_is_on_socket(ssh)) {
		verbose("Authenticated to %s ([%s]:%d) using \"%s\".", host,
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    authctxt.method->name);
	} অন্যথা {
		verbose("Authenticated to %s (via proxy) using \"%s\".", host,
		    authctxt.method->name);
	}
}

স্থির পূর্ণসংখ্যা
প্রবেশ_userauth_service_accept(পূর্ণসংখ্যা type, uint32_t seq, কাঠামো ssh *ssh)
{
	পূর্ণসংখ্যা r;

	যদি (ssh_packet_remaining(ssh) > 0) {
		অক্ষর *reply;

		যদি ((r = sshpkt_get_cstring(ssh, &reply, ফাঁকা)) != 0)
			যাও out;
		debug2("service_accept: %s", reply);
		মুক্ত(reply);
	} অন্যথা {
		debug2("buggy server: service_accept w/o service");
	}
	যদি ((r = sshpkt_get_end(ssh)) != 0)
		যাও out;
	debug("SSH2_MSG_SERVICE_ACCEPT received");

	/* initial userauth request */
	userauth_none(ssh);

	/* accept EXT_INFO at any time during userauth */
	ssh_dispatch_set(ssh, SSH2_বার্তা_EXT_INFO, ssh->kex->ext_info_s ?
	    &kex_প্রবেশ_ext_info : &প্রবেশ_userauth_error);
	ssh_dispatch_set(ssh, SSH2_বার্তা_USERAUTH_SUCCESS, &প্রবেশ_userauth_success);
	ssh_dispatch_set(ssh, SSH2_বার্তা_USERAUTH_FAILURE, &প্রবেশ_userauth_failure);
	ssh_dispatch_set(ssh, SSH2_বার্তা_USERAUTH_BANNER, &প্রবেশ_userauth_banner);
	r = 0;
 out:
	ফেরত r;
}

শূন্য
userauth(কাঠামো ssh *ssh, অক্ষর *authlist)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;

	যদি (authctxt->method != ফাঁকা && authctxt->method->cleanup != ফাঁকা)
		authctxt->method->cleanup(ssh);

	মুক্ত(authctxt->methoddata);
	authctxt->methoddata = ফাঁকা;
	যদি (authlist == ফাঁকা) {
		authlist = authctxt->authlist;
	} অন্যথা {
		মুক্ত(authctxt->authlist);
		authctxt->authlist = authlist;
	}
	জন্য (;;) {
		Authmethod *method = authmethod_get(authlist);
		যদি (method == ফাঁকা)
			fatal("%s@%s: Permission denied (%s).",
			    authctxt->server_user, authctxt->host, authlist);
		authctxt->method = method;

		/* reset the per method handler */
		ssh_dispatch_range(ssh, SSH2_বার্তা_USERAUTH_PER_METHOD_MIN,
		    SSH2_বার্তা_USERAUTH_PER_METHOD_MAX, ফাঁকা);

		/* and try new method */
		যদি (method->userauth(ssh) != 0) {
			debug2("we sent a %s packet, wait for reply", method->name);
			বিরতি;
		} অন্যথা {
			debug2("we did not send a packet, disable method");
			method->enabled = ফাঁকা;
		}
	}
}

স্থির পূর্ণসংখ্যা
প্রবেশ_userauth_error(পূর্ণসংখ্যা type, uint32_t seq, কাঠামো ssh *ssh)
{
	fatal_f("bad message during authentication: type %d", type);
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
প্রবেশ_userauth_banner(পূর্ণসংখ্যা type, uint32_t seq, কাঠামো ssh *ssh)
{
	অক্ষর *বার্তা = ফাঁকা;
	আকার_t len;
	পূর্ণসংখ্যা r;

	debug3_f("entering");
	যদি ((r = sshpkt_get_cstring(ssh, &বার্তা, &len)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, ফাঁকা, ফাঁকা)) != 0)
		যাও out;
	যদি (len > 0 && options.log_level >= SYSLOG_LEVEL_INFO)
		fmprintf(stderr, "%s", বার্তা);
	r = 0;
 out:
	মুক্ত(বার্তা);
	ফেরত r;
}

স্থির পূর্ণসংখ্যা
প্রবেশ_userauth_success(পূর্ণসংখ্যা type, uint32_t seq, কাঠামো ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	যদি (authctxt == ফাঁকা)
		fatal_f("no authentication context");
	মুক্ত(authctxt->authlist);
	authctxt->authlist = ফাঁকা;
	যদি (authctxt->method != ফাঁকা && authctxt->method->cleanup != ফাঁকা)
		authctxt->method->cleanup(ssh);
	মুক্ত(authctxt->methoddata);
	authctxt->methoddata = ফাঁকা;
	authctxt->success = 1;			/* break out */
	ssh_dispatch_set(ssh, SSH2_বার্তা_EXT_INFO, dispatch_protocol_error);
	ফেরত 0;
}

#যদি 0
স্থির পূর্ণসংখ্যা
প্রবেশ_userauth_success_unexpected(পূর্ণসংখ্যা type, uint32_t seq, কাঠামো ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	যদি (authctxt == ফাঁকা)
		fatal_f("no authentication context");

	fatal("Unexpected authentication success during %s.",
	    authctxt->method->name);
	ফেরত 0;
}
#endif

স্থির পূর্ণসংখ্যা
প্রবেশ_userauth_failure(পূর্ণসংখ্যা type, uint32_t seq, কাঠামো ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	অক্ষর *authlist = ফাঁকা;
	u_char partial;

	যদি (authctxt == ফাঁকা)
		fatal("input_userauth_failure: no authentication context");

	যদি (sshpkt_get_cstring(ssh, &authlist, ফাঁকা) != 0 ||
	    sshpkt_get_u8(ssh, &partial) != 0 ||
	    sshpkt_get_end(ssh) != 0)
		যাও out;

	যদি (partial != 0) {
		verbose("Authenticated using \"%s\" with partial success.",
		    authctxt->method->name);
		/* reset state */
		pubkey_reset(authctxt);
	}
	debug("Authentications that can continue: %s", authlist);

	userauth(ssh, authlist);
	authlist = ফাঁকা;
 out:
	মুক্ত(authlist);
	ফেরত 0;
}

/*
 * Format an identity for logging including filename, key type, fingerprint
 * and location (agent, etc.). Caller must free.
 */
স্থির অক্ষর *
format_identity(Identity *id)
{
	অক্ষর *fp = ফাঁকা, *ret = ফাঁকা;
	ধ্রুবক অক্ষর *note = "";

	যদি (id->চাবি != ফাঁকা) {
		fp = sshkey_fingerprint(id->চাবি, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
	}
	যদি (id->চাবি) {
		যদি ((id->চাবি->flags & SSHKEY_FLAG_EXT) != 0)
			note = " token";
		অন্যথা যদি (sshkey_is_sk(id->চাবি))
			note = " authenticator";
	}
	xasprintf(&ret, "%s %s%s%s%s%s%s",
	    id->filename,
	    id->চাবি ? sshkey_type(id->চাবি) : "", id->চাবি ? " " : "",
	    fp ? fp : "",
	    id->userprovided ? " explicit" : "", note,
	    id->agent_fd != -1 ? " agent" : "");
	মুক্ত(fp);
	ফেরত ret;
}

স্থির পূর্ণসংখ্যা
প্রবেশ_userauth_pk_ok(পূর্ণসংখ্যা type, uint32_t seq, কাঠামো ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	কাঠামো sshkey *চাবি = ফাঁকা;
	কাঠামো sshbuf *keyblob = ফাঁকা;
	Identity *id = ফাঁকা;
	পূর্ণসংখ্যা pktype, found = 0, sent = 0;
	অক্ষর *pkalg = ফাঁকা, *fp = ফাঁকা, *ident = ফাঁকা;
	পূর্ণসংখ্যা r;

	যদি (authctxt == ফাঁকা)
		fatal_f("no authentication context");

	যদি ((r = sshpkt_get_cstring(ssh, &pkalg, ফাঁকা)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		যাও done;

	যদি (match_pattern_list(pkalg, options.pubkey_accepted_algos, 0) != 1) {
		error_f("server replied to PK_OK with signature type %s not "
		    "in PubkeyAcceptedAlgorithms", pkalg);
		r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		যাও done;
	}
	যদি ((pktype = sshkey_type_from_name(pkalg)) == চাবি_UNSPEC) {
		debug_f("server sent unknown pkalg %s", pkalg);
		r = SSH_ERR_INVALID_FORMAT;
		যাও done;
	}
	/* inner key type should match signature type */
	যদি ((r = sshkey_fromb_allowlist(keyblob, &চাবি, pkalg, ফাঁকা)) != 0) {
		debug_r(r, "no key from blob. pkalg %s", pkalg);
		যাও done;
	}
	যদি (চাবি->type != pktype) {
		error("input_userauth_pk_ok: type mismatch "
		    "for decoded key (received %d, expected %d)",
		    চাবি->type, pktype);
		r = SSH_ERR_INVALID_FORMAT;
		যাও done;
	}

	/*
	 * search keys in the reverse order, because last candidate has been
	 * moved to the end of the queue.  this also avoids confusion by
	 * duplicate keys
	 */
	TAILQ_FOREACH_REVERSE(id, &authctxt->চাবিগুলি, idlist, পরবর্তী) {
		যদি (sshkey_equal(চাবি, id->চাবি)) {
			found = 1;
			বিরতি;
		}
	}
	যদি (!found || id == ফাঁকা) {
		fp = sshkey_fingerprint(চাবি, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		error_f("server replied with unknown key: %s %s",
		    sshkey_type(চাবি), fp == ফাঁকা ? "<ERROR>" : fp);
		r = SSH_ERR_INVALID_FORMAT;
		যাও done;
	}
	ident = format_identity(id);
	debug("Server accepts key: %s", ident);
	sent = sign_and_send_pubkey(ssh, id);
	r = 0;
 done:
	sshkey_free(চাবি);
	sshbuf_free(keyblob);
	মুক্ত(ident);
	মুক্ত(fp);
	মুক্ত(pkalg);

	/* try another method if we did not send a packet */
	যদি (r == 0 && sent == 0)
		userauth(ssh, ফাঁকা);
	ফেরত r;
}

#ifdef GSSAPI
স্থির পূর্ণসংখ্যা
userauth_gssapi(কাঠামো ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Gssctxt *gssctxt = ফাঁকা;
	OM_uint32 min;
	পূর্ণসংখ্যা r, ok = 0;
	gss_OID mech = ফাঁকা;

	/* Try one GSSAPI method at a time, rather than sending them all at
	 * once. */

	যদি (authctxt->gss_supported_mechs == ফাঁকা)
		gss_indicate_mechs(&min, &authctxt->gss_supported_mechs);

	/* Check to see whether the mechanism is usable before we offer it */
	যখন (authctxt->mech_tried < authctxt->gss_supported_mechs->গুনতি &&
	    !ok) {
		mech = &authctxt->gss_supported_mechs->
		    elements[authctxt->mech_tried];
		/* My DER encoding requires length<128 */
		যদি (mech->দৈর্ঘ্য < 128 && ssh_gssapi_check_mechanism(&gssctxt,
		    mech, authctxt->host)) {
			ok = 1; /* Mechanism works */
		} অন্যথা {
			authctxt->mech_tried++;
		}
	}

	যদি (!ok || mech == ফাঁকা)
		ফেরত 0;

	authctxt->methoddata=(শূন্য *)gssctxt;

	যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_u32(ssh, 1)) != 0 ||
	    (r = sshpkt_put_u32(ssh, (mech->দৈর্ঘ্য) + 2)) != 0 ||
	    (r = sshpkt_put_u8(ssh, SSH_GSS_OIDTYPE)) != 0 ||
	    (r = sshpkt_put_u8(ssh, mech->দৈর্ঘ্য)) != 0 ||
	    (r = sshpkt_put(ssh, mech->elements, mech->দৈর্ঘ্য)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh_dispatch_set(ssh, SSH2_বার্তা_USERAUTH_GSSAPI_RESPONSE, &প্রবেশ_gssapi_response);
	ssh_dispatch_set(ssh, SSH2_বার্তা_USERAUTH_GSSAPI_TOKEN, &প্রবেশ_gssapi_token);
	ssh_dispatch_set(ssh, SSH2_বার্তা_USERAUTH_GSSAPI_ERROR, &প্রবেশ_gssapi_error);
	ssh_dispatch_set(ssh, SSH2_বার্তা_USERAUTH_GSSAPI_ERRTOK, &প্রবেশ_gssapi_errtok);

	authctxt->mech_tried++; /* Move along to next candidate */

	ফেরত 1;
}

স্থির শূন্য
userauth_gssapi_cleanup(কাঠামো ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Gssctxt *gssctxt = (Gssctxt *)authctxt->methoddata;

	ssh_gssapi_delete_ctx(&gssctxt);
	authctxt->methoddata = ফাঁকা;
}

স্থির OM_uint32
process_gssapi_token(কাঠামো ssh *ssh, gss_বাফার_t recv_tok)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt = authctxt->methoddata;
	gss_বাফার_desc send_tok = GSS_C_EMPTY_বাফার;
	gss_বাফার_desc mic = GSS_C_EMPTY_বাফার;
	gss_বাফার_desc gssbuf;
	OM_uint32 status, ms, flags;
	পূর্ণসংখ্যা r;

	status = ssh_gssapi_init_ctx(gssctxt, options.gss_deleg_creds,
	    recv_tok, &send_tok, &flags);

	যদি (send_tok.দৈর্ঘ্য > 0) {
		u_char type = GSS_ERROR(status) ?
		    SSH2_বার্তা_USERAUTH_GSSAPI_ERRTOK :
		    SSH2_বার্তা_USERAUTH_GSSAPI_TOKEN;

		যদি ((r = sshpkt_start(ssh, type)) != 0 ||
		    (r = sshpkt_put_string(ssh, send_tok.মান,
		    send_tok.দৈর্ঘ্য)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send %u packet", type);

		gss_release_বাফার(&ms, &send_tok);
	}

	যদি (status == GSS_S_COMPLETE) {
		/* send either complete or MIC, depending on mechanism */
		যদি (!(flags & GSS_C_INTEG_FLAG)) {
			যদি ((r = sshpkt_start(ssh,
			    SSH2_বার্তা_USERAUTH_GSSAPI_EXCHANGE_COMPLETE)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "send completion");
		} অন্যথা {
			কাঠামো sshbuf *b;

			যদি ((b = sshbuf_new()) == ফাঁকা)
				fatal_f("sshbuf_new failed");
			ssh_gssapi_buildmic(b, authctxt->server_user,
			    authctxt->service, "gssapi-with-mic",
			    ssh->kex->session_id);

			যদি ((gssbuf.মান = sshbuf_mutable_ptr(b)) == ফাঁকা)
				fatal_f("sshbuf_mutable_ptr failed");
			gssbuf.দৈর্ঘ্য = sshbuf_len(b);

			status = ssh_gssapi_sign(gssctxt, &gssbuf, &mic);

			যদি (!GSS_ERROR(status)) {
				যদি ((r = sshpkt_start(ssh,
				    SSH2_বার্তা_USERAUTH_GSSAPI_MIC)) != 0 ||
				    (r = sshpkt_put_string(ssh, mic.মান,
				    mic.দৈর্ঘ্য)) != 0 ||
				    (r = sshpkt_send(ssh)) != 0)
					fatal_fr(r, "send MIC");
			}

			sshbuf_free(b);
			gss_release_বাফার(&ms, &mic);
		}
	}

	ফেরত status;
}

স্থির পূর্ণসংখ্যা
প্রবেশ_gssapi_response(পূর্ণসংখ্যা type, uint32_t plen, কাঠামো ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	আকার_t oidlen;
	u_char *oidv = ফাঁকা;
	পূর্ণসংখ্যা r;

	যদি (authctxt == ফাঁকা)
		fatal("input_gssapi_response: no authentication context");
	gssctxt = authctxt->methoddata;

	/* Setup our OID */
	যদি ((r = sshpkt_get_string(ssh, &oidv, &oidlen)) != 0)
		যাও done;

	যদি (oidlen <= 2 ||
	    oidv[0] != SSH_GSS_OIDTYPE ||
	    oidv[1] != oidlen - 2) {
		debug("Badly encoded mechanism OID received");
		userauth(ssh, ফাঁকা);
		যাও ok;
	}

	যদি (!ssh_gssapi_check_oid(gssctxt, oidv + 2, oidlen - 2))
		fatal("Server returned different OID than expected");

	যদি ((r = sshpkt_get_end(ssh)) != 0)
		যাও done;

	যদি (GSS_ERROR(process_gssapi_token(ssh, GSS_C_NO_বাফার))) {
		/* Start again with next method on list */
		debug("Trying to start again");
		userauth(ssh, ফাঁকা);
		যাও ok;
	}
 ok:
	r = 0;
 done:
	মুক্ত(oidv);
	ফেরত r;
}

স্থির পূর্ণসংখ্যা
প্রবেশ_gssapi_token(পূর্ণসংখ্যা type, uint32_t plen, কাঠামো ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	gss_বাফার_desc recv_tok;
	u_char *p = ফাঁকা;
	আকার_t len;
	OM_uint32 status;
	পূর্ণসংখ্যা r;

	যদি (authctxt == ফাঁকা)
		fatal("input_gssapi_response: no authentication context");

	যদি ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		যাও out;

	recv_tok.মান = p;
	recv_tok.দৈর্ঘ্য = len;
	status = process_gssapi_token(ssh, &recv_tok);

	/* Start again with the next method in the list */
	যদি (GSS_ERROR(status)) {
		userauth(ssh, ফাঁকা);
		/* ok */
	}
	r = 0;
 out:
	মুক্ত(p);
	ফেরত r;
}

স্থির পূর্ণসংখ্যা
প্রবেশ_gssapi_errtok(পূর্ণসংখ্যা type, uint32_t plen, কাঠামো ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	gss_বাফার_desc send_tok = GSS_C_EMPTY_বাফার;
	gss_বাফার_desc recv_tok;
	OM_uint32 ms;
	u_char *p = ফাঁকা;
	আকার_t len;
	পূর্ণসংখ্যা r;

	যদি (authctxt == ফাঁকা)
		fatal("input_gssapi_response: no authentication context");
	gssctxt = authctxt->methoddata;

	যদি ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0) {
		মুক্ত(p);
		ফেরত r;
	}

	/* Stick it into GSSAPI and see what it says */
	recv_tok.মান = p;
	recv_tok.দৈর্ঘ্য = len;
	(শূন্য)ssh_gssapi_init_ctx(gssctxt, options.gss_deleg_creds,
	    &recv_tok, &send_tok, ফাঁকা);
	মুক্ত(p);
	gss_release_বাফার(&ms, &send_tok);

	/* Server will be returning a failed packet after this one */
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
প্রবেশ_gssapi_error(পূর্ণসংখ্যা type, uint32_t plen, কাঠামো ssh *ssh)
{
	অক্ষর *বার্তা = ফাঁকা;
	অক্ষর *lang = ফাঁকা;
	পূর্ণসংখ্যা r;

	যদি ((r = sshpkt_get_u32(ssh, ফাঁকা)) != 0 ||	/* maj */
	    (r = sshpkt_get_u32(ssh, ফাঁকা)) != 0 ||	/* min */
	    (r = sshpkt_get_cstring(ssh, &বার্তা, ফাঁকা)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, ফাঁকা)) != 0)
		যাও out;
	r = sshpkt_get_end(ssh);
	debug("Server GSSAPI Error:\n%s", বার্তা);
 out:
	মুক্ত(বার্তা);
	মুক্ত(lang);
	ফেরত r;
}
#endif /* GSSAPI */

স্থির পূর্ণসংখ্যা
userauth_none(কাঠামো ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	পূর্ণসংখ্যা r;

	/* initial userauth request */
	যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	ফেরত 1;
}

স্থির পূর্ণসংখ্যা
userauth_passwd(কাঠামো ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	অক্ষর *password, *prompt = ফাঁকা;
	ধ্রুবক অক্ষর *host = options.host_চাবি_alias ?  options.host_চাবি_alias :
	    authctxt->host;
	পূর্ণসংখ্যা r;

	যদি (authctxt->attempt_passwd++ >= options.সংখ্যা_of_password_prompts)
		ফেরত 0;

	যদি (authctxt->attempt_passwd != 1)
		error("Permission denied, please try again.");

	xasprintf(&prompt, "%s@%s's password: ", authctxt->server_user, host);
	password = read_passphrase(prompt, 0);
	যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, password)) != 0 ||
	    (r = sshpkt_add_padding(ssh, 64)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	মুক্ত(prompt);
	যদি (password != ফাঁকা)
		freezero(password, strlen(password));

	ssh_dispatch_set(ssh, SSH2_বার্তা_USERAUTH_PASSWD_CHANGEREQ,
	    &প্রবেশ_userauth_passwd_changereq);

	ফেরত 1;
}

/*
 * parse PASSWD_CHANGEREQ, prompt user and send SSH2_MSG_USERAUTH_REQUEST
 */
স্থির পূর্ণসংখ্যা
প্রবেশ_userauth_passwd_changereq(পূর্ণসংখ্যা type, uint32_t seqnr, কাঠামো ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	অক্ষর *info = ফাঁকা, *lang = ফাঁকা, *password = ফাঁকা, *retype = ফাঁকা;
	অক্ষর prompt[256];
	ধ্রুবক অক্ষর *host;
	পূর্ণসংখ্যা r, addnl;
	আকার_t len;

	debug2("input_userauth_passwd_changereq");

	যদি (authctxt == ফাঁকা)
		fatal("input_userauth_passwd_changereq: "
		    "no authentication context");
	host = options.host_চাবি_alias ? options.host_চাবি_alias : authctxt->host;

	যদি ((r = sshpkt_get_cstring(ssh, &info, ফাঁকা)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, ফাঁকা)) != 0)
		যাও out;
	যদি ((len = strlen(info)) > 0) {
		addnl = info[len] != '\n';
		fmprintf(stderr, "%s%s", info, addnl ? "\n" : "");
	}
	যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0)	/* additional info */
		যাও out;

	snprintf(prompt, আকার(prompt),
	    "Enter %.30s@%.128s's old password: ",
	    authctxt->server_user, host);
	password = read_passphrase(prompt, 0);
	যদি ((r = sshpkt_put_cstring(ssh, password)) != 0)
		যাও out;

	freezero(password, strlen(password));
	password = ফাঁকা;
	যখন (password == ফাঁকা) {
		snprintf(prompt, আকার(prompt),
		    "Enter %.30s@%.128s's new password: ",
		    authctxt->server_user, host);
		password = read_passphrase(prompt, RP_ALLOW_EOF);
		যদি (password == ফাঁকা) {
			/* bail out */
			r = 0;
			যাও out;
		}
		snprintf(prompt, আকার(prompt),
		    "Retype %.30s@%.128s's new password: ",
		    authctxt->server_user, host);
		retype = read_passphrase(prompt, 0);
		যদি (strcmp(password, retype) != 0) {
			freezero(password, strlen(password));
			logit("Mismatch; try again, EOF to quit.");
			password = ফাঁকা;
		}
		freezero(retype, strlen(retype));
	}
	যদি ((r = sshpkt_put_cstring(ssh, password)) != 0 ||
	    (r = sshpkt_add_padding(ssh, 64)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		যাও out;

	ssh_dispatch_set(ssh, SSH2_বার্তা_USERAUTH_PASSWD_CHANGEREQ,
	    &প্রবেশ_userauth_passwd_changereq);
	r = 0;
 out:
	যদি (password)
		freezero(password, strlen(password));
	মুক্ত(info);
	মুক্ত(lang);
	ফেরত r;
}

/*
 * Select an algorithm for publickey signatures.
 * Returns algorithm (caller must free) or NULL if no mutual algorithm found.
 *
 * Call with ssh==NULL to ignore server-sig-algs extension list and
 * only attempt with the key's base signature type.
 */
স্থির অক্ষর *
চাবি_sig_algorithm(কাঠামো ssh *ssh, ধ্রুবক কাঠামো sshkey *চাবি)
{
	অক্ষর *allowed, *oallowed, *cp, *tmp, *alg = ফাঁকা;
	ধ্রুবক অক্ষর *server_sig_algs;

	/*
	 * The signature algorithm will only differ from the key algorithm
	 * for RSA keys/certs and when the server advertises support for
	 * newer (SHA2) algorithms.
	 */
	যদি (ssh == ফাঁকা || ssh->kex->server_sig_algs == ফাঁকা ||
	    (চাবি->type != চাবি_RSA && চাবি->type != চাবি_RSA_CERT) ||
	    (চাবি->type == চাবি_RSA_CERT && (ssh->compat & SSH_BUG_SIGTYPE))) {
		/* Filter base key signature alg against our configuration */
		ফেরত match_list(sshkey_ssh_name(চাবি),
		    options.pubkey_accepted_algos, ফাঁকা);
	}

	/*
	 * Workaround OpenSSH 7.4 bug: this version supports RSA/SHA-2 but
	 * fails to advertise it via SSH2_MSG_EXT_INFO.
	 */
	server_sig_algs = ssh->kex->server_sig_algs;
	যদি (চাবি->type == চাবি_RSA && (ssh->compat & SSH_BUG_SIGTYPE74))
		server_sig_algs = "rsa-sha2-256,rsa-sha2-512";

	/*
	 * For RSA keys/certs, since these might have a different sig type:
	 * find the first entry in PubkeyAcceptedAlgorithms of the right type
	 * that also appears in the supported signature algorithms list from
	 * the server.
	 */
	oallowed = allowed = xstrdup(options.pubkey_accepted_algos);
	যখন ((cp = strsep(&allowed, ",")) != ফাঁকা) {
		যদি (sshkey_type_from_name(cp) != চাবি->type)
			চালু;
		tmp = match_list(sshkey_sigalg_by_name(cp),
		    server_sig_algs, ফাঁকা);
		যদি (tmp != ফাঁকা)
			alg = xstrdup(cp);
		মুক্ত(tmp);
		যদি (alg != ফাঁকা)
			বিরতি;
	}
	মুক্ত(oallowed);
	ফেরত alg;
}

স্থির পূর্ণসংখ্যা
identity_sign(কাঠামো identity *id, u_char **sigp, আকার_t *lenp,
    ধ্রুবক u_char *তথ্য, আকার_t datalen, u_int compat, ধ্রুবক অক্ষর *alg)
{
	কাঠামো sshkey *sign_চাবি = ফাঁকা, *prv = ফাঁকা;
	পূর্ণসংখ্যা is_agent = 0, retried = 0, r = SSH_ERR_INTERNAL_ERROR;
	কাঠামো notifier_ctx *notifier = ফাঁকা;
	অক্ষর *fp = ফাঁকা, *pin = ফাঁকা, *prompt = ফাঁকা;

	*sigp = ফাঁকা;
	*lenp = 0;

	/* The agent supports this key. */
	যদি (id->চাবি != ফাঁকা && id->agent_fd != -1) {
		ফেরত ssh_agent_sign(id->agent_fd, id->চাবি, sigp, lenp,
		    তথ্য, datalen, alg, compat);
	}

	/*
	 * We have already loaded the private key or the private key is
	 * stored in external hardware.
	 */
	যদি (id->চাবি != ফাঁকা &&
	    (id->isprivate || (id->চাবি->flags & SSHKEY_FLAG_EXT))) {
		sign_চাবি = id->চাবি;
		is_agent = 1;
	} অন্যথা {
		/* Load the private key from the file. */
		যদি ((prv = load_identity_file(id)) == ফাঁকা)
			ফেরত SSH_ERR_চাবি_NOT_FOUND;
		যদি (id->চাবি != ফাঁকা && !sshkey_equal_public(prv, id->চাবি)) {
			error_f("private key %s contents do not match public",
			    id->filename);
			r = SSH_ERR_চাবি_NOT_FOUND;
			যাও out;
		}
		sign_চাবি = prv;
	}
 retry_pin:
	/* Prompt for touch for non-agent FIDO keys that request UP */
	যদি (!is_agent && sshkey_is_sk(sign_চাবি) &&
	    (sign_চাবি->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
		/* XXX should batch mode just skip these? */
		যদি ((fp = sshkey_fingerprint(sign_চাবি,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ফাঁকা)
			fatal_f("fingerprint failed");
		notifier = notify_start(options.batch_mode,
		    "Confirm user presence for key %s %s",
		    sshkey_type(sign_চাবি), fp);
		মুক্ত(fp);
	}
	যদি ((r = sshkey_sign(sign_চাবি, sigp, lenp, তথ্য, datalen,
	    alg, options.sk_provider, pin, compat)) != 0) {
		debug_fr(r, "sshkey_sign");
		যদি (!retried && pin == ফাঁকা && !is_agent &&
		    sshkey_is_sk(sign_চাবি) &&
		    r == SSH_ERR_চাবি_WRONG_PASSPHRASE) {
			notify_complete(notifier, ফাঁকা);
			notifier = ফাঁকা;
			xasprintf(&prompt, "Enter PIN for %s key %s: ",
			    sshkey_type(sign_চাবি), id->filename);
			pin = read_passphrase(prompt, 0);
			retried = 1;
			যাও retry_pin;
		}
		যাও out;
	}

	/*
	 * PKCS#11 tokens may not support all signature algorithms,
	 * so check what we get back.
	 */
	যদি (id->চাবি != ফাঁকা && (id->চাবি->flags & SSHKEY_FLAG_EXT) != 0 &&
	    (r = sshkey_check_sigtype(*sigp, *lenp, alg)) != 0) {
		debug_fr(r, "sshkey_check_sigtype");
		যাও out;
	}
	/* success */
	r = 0;
 out:
	মুক্ত(prompt);
	যদি (pin != ফাঁকা)
		freezero(pin, strlen(pin));
	notify_complete(notifier, r == 0 ? "User presence confirmed" : ফাঁকা);
	sshkey_free(prv);
	ফেরত r;
}

স্থির পূর্ণসংখ্যা
id_filename_matches(Identity *id, Identity *private_id)
{
	স্থির ধ্রুবক অক্ষর * ধ্রুবক suffixes[] = { ".pub", "-cert.pub", ফাঁকা };
	আকার_t len = strlen(id->filename), plen = strlen(private_id->filename);
	আকার_t i, slen;

	যদি (strcmp(id->filename, private_id->filename) == 0)
		ফেরত 1;
	জন্য (i = 0; suffixes[i]; i++) {
		slen = strlen(suffixes[i]);
		যদি (len > slen && plen == len - slen &&
		    strcmp(id->filename + (len - slen), suffixes[i]) == 0 &&
		    memcmp(id->filename, private_id->filename, plen) == 0)
			ফেরত 1;
	}
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
sign_and_send_pubkey(কাঠামো ssh *ssh, Identity *id)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	কাঠামো sshbuf *b = ফাঁকা;
	Identity *private_id, *sign_id = ফাঁকা;
	u_char *signature = ফাঁকা;
	আকার_t slen = 0, skip = 0;
	পূর্ণসংখ্যা r, fallback_sigtype, sent = 0;
	অক্ষর *alg = ফাঁকা, *fp = ফাঁকা;
	ধ্রুবক অক্ষর *loc = "", *method = "publickey";
	পূর্ণসংখ্যা hostbound = 0;

	/* prefer host-bound pubkey signatures if supported by server */
	যদি ((ssh->kex->flags & KEX_HAS_PUBKEY_HOSTBOUND) != 0 &&
	    (options.pubkey_authentication & SSH_PUBKEY_AUTH_HBOUND) != 0) {
		hostbound = 1;
		method = "publickey-hostbound-v00@openssh.com";
	}

	যদি ((fp = sshkey_fingerprint(id->চাবি, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == ফাঁকা)
		ফেরত 0;

	debug3_f("using %s with %s %s", method, sshkey_type(id->চাবি), fp);

	/*
	 * If the key is an certificate, try to find a matching private key
	 * and use it to complete the signature.
	 * If no such private key exists, fall back to trying the certificate
	 * key itself in case it has a private half already loaded.
	 * This will try to set sign_id to the private key that will perform
	 * the signature.
	 */
	যদি (id->agent_fd == -1 && sshkey_is_cert(id->চাবি)) {
		TAILQ_FOREACH(private_id, &authctxt->চাবিগুলি, পরবর্তী) {
			যদি (sshkey_equal_public(id->চাবি, private_id->চাবি) &&
			    id->চাবি->type != private_id->চাবি->type) {
				sign_id = private_id;
				বিরতি;
			}
		}
		/*
		 * Exact key matches are preferred, but also allow
		 * filename matches for non-PKCS#11/agent keys that
		 * didn't load public keys. This supports the case
		 * of keeping just a private key file and public
		 * certificate on disk.
		 */
		যদি (sign_id == ফাঁকা &&
		    !id->isprivate && id->agent_fd == -1 &&
		    (id->চাবি->flags & SSHKEY_FLAG_EXT) == 0) {
			TAILQ_FOREACH(private_id, &authctxt->চাবিগুলি, পরবর্তী) {
				যদি (private_id->চাবি == ফাঁকা &&
				    id_filename_matches(id, private_id)) {
					sign_id = private_id;
					বিরতি;
				}
			}
		}
		যদি (sign_id != ফাঁকা) {
			debug2_f("using private key \"%s\"%s for "
			    "certificate", sign_id->filename,
			    sign_id->agent_fd != -1 ? " from agent" : "");
		} অন্যথা {
			debug_f("no separate private key for certificate "
			    "\"%s\"", id->filename);
		}
	}

	/*
	 * If the above didn't select another identity to do the signing
	 * then default to the one we started with.
	 */
	যদি (sign_id == ফাঁকা)
		sign_id = id;

	/* assemble and sign data */
	জন্য (fallback_sigtype = 0; fallback_sigtype <= 1; fallback_sigtype++) {
		মুক্ত(alg);
		slen = 0;
		signature = ফাঁকা;
		যদি ((alg = চাবি_sig_algorithm(fallback_sigtype ? ফাঁকা : ssh,
		    id->চাবি)) == ফাঁকা) {
			error_f("no mutual signature supported");
			যাও out;
		}
		debug3_f("signing using %s %s", alg, fp);

		sshbuf_free(b);
		যদি ((b = sshbuf_new()) == ফাঁকা)
			fatal_f("sshbuf_new failed");
		যদি ((r = sshbuf_put_stringb(b,
		    ssh->kex->session_id)) != 0)
			fatal_fr(r, "sshbuf_put_stringb");
		skip = sshbuf_len(b);
		যদি ((r = sshbuf_put_u8(b, SSH2_বার্তা_USERAUTH_REQUEST)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->server_user)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
		    (r = sshbuf_put_cstring(b, method)) != 0 ||
		    (r = sshbuf_put_u8(b, 1)) != 0 ||
		    (r = sshbuf_put_cstring(b, alg)) != 0 ||
		    (r = sshkey_puts(id->চাবি, b)) != 0) {
			fatal_fr(r, "assemble signed data");
		}
		যদি (hostbound) {
			যদি (ssh->kex->initial_hostkey == ফাঁকা) {
				fatal_f("internal error: initial hostkey "
				    "not recorded");
			}
			যদি ((r = sshkey_puts(ssh->kex->initial_hostkey, b)) != 0)
				fatal_fr(r, "assemble %s hostkey", method);
		}
		/* generate signature */
		r = identity_sign(sign_id, &signature, &slen,
		    sshbuf_ptr(b), sshbuf_len(b), ssh->compat, alg);
		যদি (r == 0)
			বিরতি;
		অন্যথা যদি (r == SSH_ERR_চাবি_NOT_FOUND)
			যাও out; /* soft failure */
		অন্যথা যদি (r == SSH_ERR_SIGN_ALG_UNSUPPORTED &&
		    !fallback_sigtype) {
			যদি (sign_id->agent_fd != -1)
				loc = "agent ";
			অন্যথা যদি (sign_id->চাবি != ফাঁকা &&
			    (sign_id->চাবি->flags & SSHKEY_FLAG_EXT) != 0)
				loc = "token ";
			logit("%skey %s %s returned incorrect signature type",
			    loc, sshkey_type(id->চাবি), fp);
			চালু;
		}
		error_fr(r, "signing failed for %s \"%s\"%s",
		    sshkey_type(sign_id->চাবি), sign_id->filename,
		    id->agent_fd != -1 ? " from agent" : "");
		যাও out;
	}
	যদি (slen == 0 || signature == ফাঁকা) /* shouldn't happen */
		fatal_f("no signature");

	/* append signature */
	যদি ((r = sshbuf_put_string(b, signature, slen)) != 0)
		fatal_fr(r, "append signature");

#ifdef DEBUG_PK
	sshbuf_dump(b, stderr);
#endif
	/* skip session id and packet type */
	যদি ((r = sshbuf_consume(b, skip + 1)) != 0)
		fatal_fr(r, "consume");

	/* put remaining data from buffer into packet */
	যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_putb(ssh, b)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "enqueue request");

	/* success */
	sent = 1;

 out:
	মুক্ত(fp);
	মুক্ত(alg);
	sshbuf_free(b);
	freezero(signature, slen);
	ফেরত sent;
}

স্থির পূর্ণসংখ্যা
send_pubkey_test(কাঠামো ssh *ssh, Identity *id)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	u_char *blob = ফাঁকা;
	অক্ষর *alg = ফাঁকা;
	আকার_t bloblen;
	u_int have_sig = 0;
	পূর্ণসংখ্যা sent = 0, r;

	যদি ((alg = চাবি_sig_algorithm(ssh, id->চাবি)) == ফাঁকা) {
		debug_f("no mutual signature algorithm");
		যাও out;
	}

	যদি ((r = sshkey_to_blob(id->চাবি, &blob, &bloblen)) != 0) {
		/* we cannot handle this key */
		debug3_f("cannot handle key");
		যাও out;
	}
	/* register callback for USERAUTH_PK_OK message */
	ssh_dispatch_set(ssh, SSH2_বার্তা_USERAUTH_PK_OK, &প্রবেশ_userauth_pk_ok);

	যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_USERAUTH_REQUEST)) != 0 ||
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
	মুক্ত(alg);
	মুক্ত(blob);
	ফেরত sent;
}

স্থির কাঠামো sshkey *
load_identity_file(Identity *id)
{
	কাঠামো sshkey *ব্যক্তিগত = ফাঁকা;
	অক্ষর prompt[300], *passphrase, *comment;
	পূর্ণসংখ্যা r, quit = 0, i;
	কাঠামো stat st;

	যদি (stat(id->filename, &st) == -1) {
		do_log2(id->userprovided ?
		    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_DEBUG3,
		    "no such identity: %s: %s", id->filename, strerror(errno));
		ফেরত ফাঁকা;
	}
	snprintf(prompt, আকার prompt,
	    "Enter passphrase for key '%.100s': ", id->filename);
	জন্য (i = 0; i <= options.সংখ্যা_of_password_prompts; i++) {
		যদি (i == 0)
			passphrase = "";
		অন্যথা {
			passphrase = read_passphrase(prompt, 0);
			যদি (*passphrase == '\0') {
				debug2("no passphrase given, try next key");
				মুক্ত(passphrase);
				বিরতি;
			}
		}
		নির্বাচন ((r = sshkey_load_private_type(চাবি_UNSPEC, id->filename,
		    passphrase, &ব্যক্তিগত, &comment))) {
		ক্ষেত্র 0:
			বিরতি;
		ক্ষেত্র SSH_ERR_চাবি_WRONG_PASSPHRASE:
			যদি (options.batch_mode) {
				quit = 1;
				বিরতি;
			}
			যদি (i != 0)
				debug2("bad passphrase given, try again...");
			বিরতি;
		ক্ষেত্র SSH_ERR_SYSTEM_ERROR:
			যদি (errno == ENOENT) {
				debug2_r(r, "Load key \"%s\"", id->filename);
				quit = 1;
				বিরতি;
			}
			/* FALLTHROUGH */
		পূর্বনির্ধারিত:
			error_r(r, "Load key \"%s\"", id->filename);
			quit = 1;
			বিরতি;
		}
		যদি (ব্যক্তিগত != ফাঁকা && sshkey_is_sk(ব্যক্তিগত) &&
		    options.sk_provider == ফাঁকা) {
			debug("key \"%s\" is an authenticator-hosted key, "
			    "but no provider specified", id->filename);
			sshkey_free(ব্যক্তিগত);
			ব্যক্তিগত = ফাঁকা;
			quit = 1;
		}
		যদি (!quit && (r = sshkey_check_rsa_দৈর্ঘ্য(ব্যক্তিগত,
		    options.required_rsa_আকার)) != 0) {
			debug_fr(r, "Skipping key %s", id->filename);
			sshkey_free(ব্যক্তিগত);
			ব্যক্তিগত = ফাঁকা;
			quit = 1;
		}
		যদি (!quit && ব্যক্তিগত != ফাঁকা && id->agent_fd == -1 &&
		    !(id->চাবি && id->isprivate))
			maybe_add_চাবি_to_agent(id->filename, ব্যক্তিগত, comment,
			    passphrase);
		যদি (i > 0)
			freezero(passphrase, strlen(passphrase));
		মুক্ত(comment);
		যদি (ব্যক্তিগত != ফাঁকা || quit)
			বিরতি;
	}
	ফেরত ব্যক্তিগত;
}

স্থির পূর্ণসংখ্যা
চাবি_type_allowed(কাঠামো sshkey *চাবি, ধ্রুবক অক্ষর *allowlist)
{
	যদি (match_pattern_list(sshkey_ssh_name(চাবি), allowlist, 0) == 1)
		ফেরত 1;

	/* RSA keys/certs might be allowed by alternate signature types */
	নির্বাচন (চাবি->type) {
	ক্ষেত্র চাবি_RSA:
		যদি (match_pattern_list("rsa-sha2-512", allowlist, 0) == 1)
			ফেরত 1;
		যদি (match_pattern_list("rsa-sha2-256", allowlist, 0) == 1)
			ফেরত 1;
		বিরতি;
	ক্ষেত্র চাবি_RSA_CERT:
		যদি (match_pattern_list("rsa-sha2-512-cert-v01@openssh.com",
		    allowlist, 0) == 1)
			ফেরত 1;
		যদি (match_pattern_list("rsa-sha2-256-cert-v01@openssh.com",
		    allowlist, 0) == 1)
			ফেরত 1;
		বিরতি;
	}
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
চাবি_type_allowed_by_config(কাঠামো sshkey *চাবি)
{
	ফেরত চাবি_type_allowed(চাবি, options.pubkey_accepted_algos);
}

/* obtain a list of keys from the agent */
স্থির পূর্ণসংখ্যা
get_agent_identities(কাঠামো ssh *ssh, পূর্ণসংখ্যা *agent_fdp,
    কাঠামো ssh_identitylist **idlistp)
{
	পূর্ণসংখ্যা r, agent_fd;
	কাঠামো ssh_identitylist *idlist;

	যদি ((r = ssh_get_authentication_socket(&agent_fd)) != 0) {
		যদি (r != SSH_ERR_AGENT_NOT_PRESENT)
			debug_fr(r, "ssh_get_authentication_socket");
		ফেরত r;
	}
	যদি (ssh != ফাঁকা && ssh->kex != ফাঁকা) {
		যদি ((r = ssh_agent_bind_hostkey(agent_fd, ssh->kex->initial_hostkey,
		    ssh->kex->session_id, ssh->kex->initial_sig, 0)) == 0)
			debug_f("bound agent to hostkey");
		অন্যথা
			debug2_fr(r, "ssh_agent_bind_hostkey");
	}

	যদি ((r = ssh_fetch_identitylist(agent_fd, &idlist)) != 0) {
		debug_fr(r, "ssh_fetch_identitylist");
		close(agent_fd);
		ফেরত r;
	}
	/* success */
	*agent_fdp = agent_fd;
	*idlistp = idlist;
	debug_f("agent returned %zu keys", idlist->nkeys);
	ফেরত 0;
}

/*
 * Returns nonzero if the certificate extensions/critical-options section
 * has the specified option present, zero otherwise.
 */
স্থির পূর্ণসংখ্যা
cert_has_option(কাঠামো sshbuf *oblob, ধ্রুবক অক্ষর *target)
{
	কাঠামো sshbuf *c = ফাঁকা, *তথ্য = ফাঁকা;
	অক্ষর *name = ফাঁকা;
	পূর্ণসংখ্যা r, found = 0;

	যদি (oblob == ফাঁকা || (c = sshbuf_fromb(oblob)) == ফাঁকা)
		ফেরত 0;
	যখন (sshbuf_len(c) > 0) {
		sshbuf_free(তথ্য);
		তথ্য = ফাঁকা;
		মুক্ত(name);
		name = ফাঁকা;
		যদি ((r = sshbuf_get_cstring(c, &name, ফাঁকা)) != 0 ||
		    (r = sshbuf_froms(c, &তথ্য)) != 0)
			বিরতি;
		যদি (strcmp(name, target) == 0) {
			found = 1;
			বিরতি;
		}
	}
	sshbuf_free(তথ্য);
	মুক্ত(name);
	sshbuf_free(c);
	ফেরত found;
}

/*
 * Returns an integer describing the priority of the identity
 * within its group. Lower numbers are higher priority.
 */
#define MAX_ID_PRIORITY 3
স্থির পূর্ণসংখ্যা
identity_prioritise(কাঠামো identity *id)
{
	যদি (id == ফাঁকা || id->চাবি == ফাঁকা)
		ফেরত 3;
	যদি (!sshkey_is_cert(id->চাবি) || id->চাবি->cert == ফাঁকা)
		ফেরত 3;
	যদি (sshkey_is_sk(id->চাবি) &&
	    cert_has_option(id->চাবি->cert->critical, "verify-required"))
		ফেরত 2;
	যদি (sshkey_is_sk(id->চাবি) &&
	    cert_has_option(id->চাবি->cert->extensions, "no-touch-required"))
		ফেরত 0;
	ফেরত 1;
}

স্থির শূন্য
order_identities_by_prio(কাঠামো idlist *list)
{
	কাঠামো idlist prio[MAX_ID_PRIORITY + 1], sorted;
	কাঠামো identity *id, *tmp, *dummy;
	পূর্ণসংখ্যা p;

	জন্য (p = 0; p <= MAX_ID_PRIORITY; p++)
		TAILQ_INIT(&prio[p]);
	TAILQ_INIT(&sorted);

	TAILQ_FOREACH_SAFE(id, list, পরবর্তী, tmp) {
		যদি (id->userprovided)
			চালু;
		dummy = xcalloc(1, আকার(*dummy));
		dummy->userprovided = -1;
		TAILQ_INSERT_BEFORE(id, dummy, পরবর্তী);
		TAILQ_REMOVE(list, id, পরবর্তী);
		p = identity_prioritise(id);
		যদি (p < 0 || p > MAX_ID_PRIORITY)
			fatal_f("internal error: bad priority");
		TAILQ_INSERT_TAIL(&prio[p], id, পরবর্তী);
	}
	জন্য (p = 0; p <= MAX_ID_PRIORITY; p++)
		TAILQ_CONCAT(&sorted, &prio[p], পরবর্তী);

	TAILQ_FOREACH_SAFE(id, list, পরবর্তী, tmp) {
		যদি (id->userprovided != -1)
			চালু;
		কাঠামো identity *s = TAILQ_FIRST(&sorted);
		TAILQ_REMOVE(&sorted, s, পরবর্তী);
		TAILQ_INSERT_BEFORE(id, s, পরবর্তী);
		TAILQ_REMOVE(list, id, পরবর্তী);
		মুক্ত(id);
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
স্থির শূন্য
pubkey_prepare(কাঠামো ssh *ssh, Authctxt *authctxt)
{
	কাঠামো identity *id, *id2, *tmp;
	কাঠামো idlist agent, files, certs, agent_চাবিগুলি, *preferred;
	কাঠামো sshkey *চাবি;
	পূর্ণসংখ্যা disallowed, agent_fd = -1, i, r, found;
	আকার_t j;
	কাঠামো ssh_identitylist *idlist;
	অক্ষর *cp, *ident;

	TAILQ_INIT(&agent);	/* keys from the agent */
	TAILQ_INIT(&files);	/* keys from the config file */
	TAILQ_INIT(&certs);	/* certificates specified by user */
	TAILQ_INIT(&agent_চাবিগুলি); /* keys supported by the agent */
	preferred = &authctxt->চাবিগুলি;
	TAILQ_INIT(preferred);	/* preferred order of keys */

	/* list of keys stored in the filesystem and PKCS#11 */
	জন্য (i = 0; i < options.অঙ্ক_identity_files; i++) {
		চাবি = options.identity_চাবিগুলি[i];
		যদি (চাবি && চাবি->cert &&
		    চাবি->cert->type != SSH2_CERT_TYPE_USER) {
			debug_f("ignoring certificate %s: not a user "
			    "certificate", options.identity_files[i]);
			চালু;
		}
		যদি (চাবি && sshkey_is_sk(চাবি) && options.sk_provider == ফাঁকা) {
			debug_f("ignoring authenticator-hosted key %s as no "
			    "SecurityKeyProvider has been specified",
			    options.identity_files[i]);
			চালু;
		}
		options.identity_চাবিগুলি[i] = ফাঁকা;
		id = xcalloc(1, আকার(*id));
		id->agent_fd = -1;
		id->চাবি = চাবি;
		id->filename = xstrdup(options.identity_files[i]);
		id->userprovided = options.identity_file_userprovided[i];
		TAILQ_INSERT_TAIL(&files, id, পরবর্তী);
	}

	/* list of certificates specified by user */
	জন্য (i = 0; i < options.অঙ্ক_certificate_files; i++) {
		চাবি = options.certificates[i];
		যদি (!sshkey_is_cert(চাবি) || চাবি->cert == ফাঁকা ||
		    চাবি->cert->type != SSH2_CERT_TYPE_USER) {
			debug_f("ignoring certificate %s: not a user "
			    "certificate", options.identity_files[i]);
			চালু;
		}
		যদি (চাবি && sshkey_is_sk(চাবি) && options.sk_provider == ফাঁকা) {
			debug_f("ignoring authenticator-hosted key "
			    "certificate %s as no "
			    "SecurityKeyProvider has been specified",
			    options.identity_files[i]);
			চালু;
		}
		id = xcalloc(1, আকার(*id));
		id->agent_fd = -1;
		id->চাবি = চাবি;
		id->filename = xstrdup(options.certificate_files[i]);
		id->userprovided = options.certificate_file_userprovided[i];
		TAILQ_INSERT_TAIL(&certs, id, পরবর্তী);
	}
	order_identities_by_prio(&certs);
	TAILQ_CONCAT(preferred, &certs, পরবর্তী);

	/* list of keys supported by the agent */
	যদি ((r = get_agent_identities(ssh, &agent_fd, &idlist)) == 0) {
		জন্য (j = 0; j < idlist->nkeys; j++) {
			যদি ((r = sshkey_check_rsa_দৈর্ঘ্য(idlist->চাবিগুলি[j],
			    options.required_rsa_আকার)) != 0) {
				debug_fr(r, "ignoring %s agent key",
				    sshkey_ssh_name(idlist->চাবিগুলি[j]));
				চালু;
			}
			found = 0;
			TAILQ_FOREACH(id, &files, পরবর্তী) {
				/*
				 * agent keys from the config file are
				 * preferred
				 */
				যদি (sshkey_equal(idlist->চাবিগুলি[j], id->চাবি)) {
					TAILQ_REMOVE(&files, id, পরবর্তী);
					TAILQ_INSERT_TAIL(&agent_চাবিগুলি, id, পরবর্তী);
					id->agent_fd = agent_fd;
					found = 1;
					বিরতি;
				}
			}
			যদি (!found && !options.identities_only) {
				id = xcalloc(1, আকার(*id));
				/* XXX "steals" key/comment from idlist */
				id->চাবি = idlist->চাবিগুলি[j];
				id->filename = idlist->comments[j];
				idlist->চাবিগুলি[j] = ফাঁকা;
				idlist->comments[j] = ফাঁকা;
				id->agent_fd = agent_fd;
				TAILQ_INSERT_TAIL(&agent, id, পরবর্তী);
			}
		}
		ssh_free_identitylist(idlist);
		/* append remaining agent keys */
		TAILQ_CONCAT(&agent_চাবিগুলি, &agent, পরবর্তী);
		order_identities_by_prio(&agent_চাবিগুলি);
		TAILQ_CONCAT(preferred, &agent_চাবিগুলি, পরবর্তী);
		authctxt->agent_fd = agent_fd;
	}
	/* Prefer PKCS11 keys that are explicitly listed */
	TAILQ_FOREACH_SAFE(id, &files, পরবর্তী, tmp) {
		যদি (id->চাবি == ফাঁকা || (id->চাবি->flags & SSHKEY_FLAG_EXT) == 0)
			চালু;
		found = 0;
		TAILQ_FOREACH(id2, &files, পরবর্তী) {
			যদি (id2->চাবি == ফাঁকা ||
			    (id2->চাবি->flags & SSHKEY_FLAG_EXT) != 0)
				চালু;
			যদি (sshkey_equal(id->চাবি, id2->চাবি)) {
				TAILQ_REMOVE(&files, id, পরবর্তী);
				TAILQ_INSERT_TAIL(preferred, id, পরবর্তী);
				found = 1;
				বিরতি;
			}
		}
		/* If IdentitiesOnly set and key not found then don't use it */
		যদি (!found && options.identities_only) {
			TAILQ_REMOVE(&files, id, পরবর্তী);
			freezero(id, আকার(*id));
		}
	}
	order_identities_by_prio(&files);
	/* append remaining keys from the config file */
	TAILQ_CONCAT(preferred, &files, পরবর্তী);
	/* finally, filter by PubkeyAcceptedAlgorithms */
	TAILQ_FOREACH_SAFE(id, preferred, পরবর্তী, id2) {
		disallowed = 0;
		cp = ফাঁকা;
		যদি (id->চাবি == ফাঁকা)
			চালু;
		যদি (!চাবি_type_allowed_by_config(id->চাবি)) {
			debug("Skipping %s key %s - corresponding algorithm "
			    "not in PubkeyAcceptedAlgorithms",
			    sshkey_ssh_name(id->চাবি), id->filename);
			disallowed = 1;
		} অন্যথা যদি (ssh != ফাঁকা && ssh->kex != ফাঁকা &&
		    ssh->kex->server_sig_algs != ফাঁকা &&
		    (cp = চাবি_sig_algorithm(ssh, id->চাবি)) == ফাঁকা) {
			debug("Skipping %s key %s - corresponding algorithm "
			    "not supported by server",
			    sshkey_ssh_name(id->চাবি), id->filename);
			disallowed = 1;
		}
		মুক্ত(cp);
		যদি (!disallowed)
			চালু;
		/* remove key */
		TAILQ_REMOVE(preferred, id, পরবর্তী);
		sshkey_free(id->চাবি);
		মুক্ত(id->filename);
		freezero(id, আকার(*id));
	}
	/* List the keys we plan on using */
	TAILQ_FOREACH_SAFE(id, preferred, পরবর্তী, id2) {
		ident = format_identity(id);
		debug("Will attempt key: %s", ident);
		মুক্ত(ident);
	}
	debug2_f("done");
}

স্থির শূন্য
pubkey_cleanup(কাঠামো ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Identity *id;

	যদি (authctxt->agent_fd != -1) {
		ssh_close_authentication_socket(authctxt->agent_fd);
		authctxt->agent_fd = -1;
	}
	জন্য (id = TAILQ_FIRST(&authctxt->চাবিগুলি); id;
	    id = TAILQ_FIRST(&authctxt->চাবিগুলি)) {
		TAILQ_REMOVE(&authctxt->চাবিগুলি, id, পরবর্তী);
		sshkey_free(id->চাবি);
		মুক্ত(id->filename);
		মুক্ত(id);
	}
}

শূন্য
pubkey_dump(কাঠামো ssh *ssh)
{
	Authctxt authctxt;
	Identity *id;
	অক্ষর *ident;

	memset(&authctxt, 0, আকার(authctxt));
	authctxt.agent_fd = -1;
	ssh->authctxt = &authctxt;

	pubkey_prepare(ssh, &authctxt);
	TAILQ_FOREACH(id, &authctxt.চাবিগুলি, পরবর্তী) {
		ident = format_identity(id);
		fprintf(stdout, "%s\n", ident);
		মুক্ত(ident);
	}
	pubkey_cleanup(ssh);
	ssh->authctxt = ফাঁকা;
}

স্থির শূন্য
pubkey_reset(Authctxt *authctxt)
{
	Identity *id;

	TAILQ_FOREACH(id, &authctxt->চাবিগুলি, পরবর্তী)
		id->tried = 0;
}

স্থির পূর্ণসংখ্যা
userauth_pubkey(কাঠামো ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Identity *id;
	পূর্ণসংখ্যা sent = 0;
	অক্ষর *ident;
	স্থির পূর্ণসংখ্যা prepared;

	যদি (!prepared) {
		pubkey_prepare(ssh, authctxt);
		prepared = 1;
	}

	যখন ((id = TAILQ_FIRST(&authctxt->চাবিগুলি))) {
		যদি (id->tried++)
			ফেরত (0);
		/* move key to the end of the queue */
		TAILQ_REMOVE(&authctxt->চাবিগুলি, id, পরবর্তী);
		TAILQ_INSERT_TAIL(&authctxt->চাবিগুলি, id, পরবর্তী);
		/*
		 * send a test message if we have the public key. for
		 * encrypted keys we cannot do this and have to load the
		 * private key instead
		 */
		যদি (id->চাবি != ফাঁকা) {
			ident = format_identity(id);
			debug("Offering public key: %s", ident);
			মুক্ত(ident);
			sent = send_pubkey_test(ssh, id);
		} অন্যথা {
			debug("Trying private key: %s", id->filename);
			id->চাবি = load_identity_file(id);
			যদি (id->চাবি != ফাঁকা) {
				id->isprivate = 1;
				sent = sign_and_send_pubkey(ssh, id);
				sshkey_free(id->চাবি);
				id->চাবি = ফাঁকা;
				id->isprivate = 0;
			}
		}
		যদি (sent)
			ফেরত (sent);
	}
	ফেরত (0);
}

/*
 * Send userauth request message specifying keyboard-interactive method.
 */
স্থির পূর্ণসংখ্যা
userauth_kbdint(কাঠামো ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	পূর্ণসংখ্যা r;

	যদি (authctxt->attempt_kbdint++ >= options.সংখ্যা_of_password_prompts)
		ফেরত 0;
	/* disable if no SSH2_MSG_USERAUTH_INFO_REQUEST has been seen */
	যদি (authctxt->attempt_kbdint > 1 && !authctxt->info_req_seen) {
		debug3("userauth_kbdint: disable: no info_req_seen");
		ssh_dispatch_set(ssh, SSH2_বার্তা_USERAUTH_INFO_REQUEST, ফাঁকা);
		ফেরত 0;
	}

	debug2("userauth_kbdint");
	যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||		/* lang */
	    (r = sshpkt_put_cstring(ssh, options.kbd_interactive_devices ?
	    options.kbd_interactive_devices : "")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh_dispatch_set(ssh, SSH2_বার্তা_USERAUTH_INFO_REQUEST, &প্রবেশ_userauth_info_req);
	ফেরত 1;
}

/*
 * parse INFO_REQUEST, prompt user and send INFO_RESPONSE
 */
স্থির পূর্ণসংখ্যা
প্রবেশ_userauth_info_req(পূর্ণসংখ্যা type, uint32_t seq, কাঠামো ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	অক্ষর *name = ফাঁকা, *inst = ফাঁকা, *lang = ফাঁকা, *prompt = ফাঁকা;
	অক্ষর *display_prompt = ফাঁকা, *response = ফাঁকা;
	u_char echo = 0;
	u_int অঙ্ক_prompts, i;
	পূর্ণসংখ্যা r, addnl;
	আকার_t len;

	debug2_f("entering");

	যদি (authctxt == ফাঁকা)
		fatal_f("no authentication context");

	authctxt->info_req_seen = 1;

	যদি ((r = sshpkt_get_cstring(ssh, &name, ফাঁকা)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &inst, ফাঁকা)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, ফাঁকা)) != 0)
		যাও out;
	যদি ((len = strlen(name)) > 0) {
		addnl = name[len] != '\n';
		fmprintf(stderr, "%s%s", name, addnl ? "\n" : "");
	}
	যদি ((len = strlen(inst)) > 0) {
		addnl = inst[len] != '\n';
		fmprintf(stderr, "%s%s", inst, addnl ? "\n" : "");
	}

	যদি ((r = sshpkt_get_u32(ssh, &অঙ্ক_prompts)) != 0)
		যাও out;
	/*
	 * Begin to build info response packet based on prompts requested.
	 * We commit to providing the correct number of responses, so if
	 * further on we run into a problem that prevents this, we have to
	 * be sure and clean this up and send a correct error response.
	 */
	যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_USERAUTH_INFO_RESPONSE)) != 0 ||
	    (r = sshpkt_put_u32(ssh, অঙ্ক_prompts)) != 0)
		যাও out;

	debug2_f("num_prompts %d", অঙ্ক_prompts);
	জন্য (i = 0; i < অঙ্ক_prompts; i++) {
		যদি ((r = sshpkt_get_cstring(ssh, &prompt, ফাঁকা)) != 0 ||
		    (r = sshpkt_get_u8(ssh, &echo)) != 0)
			যাও out;
		যদি (asmprintf(&display_prompt, INT_MAX, ফাঁকা, "(%s@%s) %s",
		    authctxt->server_user, options.host_চাবি_alias ?
		    options.host_চাবি_alias : authctxt->host, prompt) == -1)
			fatal_f("asmprintf failed");
		response = read_passphrase(display_prompt, echo ? RP_ECHO : 0);
		যদি ((r = sshpkt_put_cstring(ssh, response)) != 0)
			যাও out;
		freezero(response, strlen(response));
		মুক্ত(prompt);
		মুক্ত(display_prompt);
		display_prompt = response = prompt = ফাঁকা;
	}
	/* done with parsing incoming message. */
	যদি ((r = sshpkt_get_end(ssh)) != 0 ||
	    (r = sshpkt_add_padding(ssh, 64)) != 0)
		যাও out;
	r = sshpkt_send(ssh);
 out:
	যদি (response)
		freezero(response, strlen(response));
	মুক্ত(prompt);
	মুক্ত(display_prompt);
	মুক্ত(name);
	মুক্ত(inst);
	মুক্ত(lang);
	ফেরত r;
}

স্থির পূর্ণসংখ্যা
ssh_keysign(কাঠামো ssh *ssh, কাঠামো sshkey *চাবি, u_char **sigp, আকার_t *lenp,
    ধ্রুবক u_char *তথ্য, আকার_t datalen)
{
	কাঠামো sshbuf *b;
	কাঠামো stat st;
	pid_t pid;
	পূর্ণসংখ্যা r, to[2], from[2], status;
	পূর্ণসংখ্যা sock = ssh_packet_get_connection_in(ssh);
	u_char rversion = 0, version = 2;
	শূন্য (*osigchld)(পূর্ণসংখ্যা);

	*sigp = ফাঁকা;
	*lenp = 0;

	যদি (stat(PATH_SSH_চাবি_SIGN, &st) == -1) {
		error_f("not installed: %s", strerror(errno));
		ফেরত -1;
	}
	যদি (fflush(stdout) != 0) {
		error_f("fflush: %s", strerror(errno));
		ফেরত -1;
	}
	যদি (pipe(to) == -1) {
		error_f("pipe: %s", strerror(errno));
		ফেরত -1;
	}
	যদি (pipe(from) == -1) {
		error_f("pipe: %s", strerror(errno));
		ফেরত -1;
	}
	যদি ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		ফেরত -1;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	যদি (pid == 0) {
		close(from[0]);
		যদি (dup2(from[1], STDOUT_FILENO) == -1)
			fatal_f("dup2: %s", strerror(errno));
		close(to[1]);
		যদি (dup2(to[0], STDIN_FILENO) == -1)
			fatal_f("dup2: %s", strerror(errno));
		close(from[1]);
		close(to[0]);

		যদি (dup2(sock, STDERR_FILENO + 1) == -1)
			fatal_f("dup2: %s", strerror(errno));
		sock = STDERR_FILENO + 1;
		যদি (fcntl(sock, F_SETFD, 0) == -1) /* keep the socket on exec */
			debug3_f("fcntl F_SETFD: %s", strerror(errno));
		closefrom(sock + 1);

		debug3_f("[child] pid=%ld, exec %s",
		    (long)getpid(), PATH_SSH_চাবি_SIGN);
		execl(PATH_SSH_চাবি_SIGN, PATH_SSH_চাবি_SIGN, (অক্ষর *)ফাঁকা);
		fatal_f("exec(%s): %s", PATH_SSH_চাবি_SIGN,
		    strerror(errno));
	}
	close(from[1]);
	close(to[0]);
	sock = STDERR_FILENO + 1;

	যদি ((b = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");
	/* send # of sock, data to be signed */
	যদি ((r = sshbuf_put_u32(b, sock)) != 0 ||
	    (r = sshbuf_put_string(b, তথ্য, datalen)) != 0)
		fatal_fr(r, "buffer error");
	যদি (ssh_বার্তা_send(to[1], version, b) == -1)
		fatal_f("couldn't send request");
	sshbuf_reset(b);
	r = ssh_বার্তা_recv(from[0], b);
	close(from[0]);
	close(to[1]);
	যদি (r < 0) {
		error_f("no reply");
		যাও fail;
	}

	errno = 0;
	যখন (waitpid(pid, &status, 0) == -1) {
		যদি (errno != EINTR) {
			error_f("waitpid %ld: %s", (long)pid, strerror(errno));
			যাও fail;
		}
	}
	যদি (!WIFEXITED(status)) {
		error_f("exited abnormally");
		যাও fail;
	}
	যদি (WEXITSTATUS(status) != 0) {
		error_f("exited with status %d", WEXITSTATUS(status));
		যাও fail;
	}
	যদি ((r = sshbuf_get_u8(b, &rversion)) != 0) {
		error_fr(r, "buffer error");
		যাও fail;
	}
	যদি (rversion != version) {
		error_f("bad version");
		যাও fail;
	}
	যদি ((r = sshbuf_get_string(b, sigp, lenp)) != 0) {
		error_fr(r, "buffer error");
 fail:
		ssh_signal(SIGCHLD, osigchld);
		sshbuf_free(b);
		ফেরত -1;
	}
	ssh_signal(SIGCHLD, osigchld);
	sshbuf_free(b);

	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
userauth_hostbased(কাঠামো ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	কাঠামো sshkey *ব্যক্তিগত = ফাঁকা;
	কাঠামো sshbuf *b = ফাঁকা;
	u_char *sig = ফাঁকা, *keyblob = ফাঁকা;
	অক্ষর *fp = ফাঁকা, *chost = ফাঁকা, *lname = ফাঁকা;
	আকার_t siglen = 0, keylen = 0;
	পূর্ণসংখ্যা i, r, success = 0;

	যদি (authctxt->ktypes == ফাঁকা) {
		authctxt->oktypes = xstrdup(options.hostbased_accepted_algos);
		authctxt->ktypes = authctxt->oktypes;
	}

	/*
	 * Work through each listed type pattern in HostbasedAcceptedAlgorithms,
	 * trying each hostkey that matches the type in turn.
	 */
	জন্য (;;) {
		যদি (authctxt->active_ktype == ফাঁকা)
			authctxt->active_ktype = strsep(&authctxt->ktypes, ",");
		যদি (authctxt->active_ktype == ফাঁকা ||
		    *authctxt->active_ktype == '\0')
			বিরতি;
		debug3_f("trying key type %s", authctxt->active_ktype);

		/* check for a useful key */
		ব্যক্তিগত = ফাঁকা;
		জন্য (i = 0; i < authctxt->sensitive->nkeys; i++) {
			যদি (authctxt->sensitive->চাবিগুলি[i] == ফাঁকা ||
			    authctxt->sensitive->চাবিগুলি[i]->type == চাবি_UNSPEC)
				চালু;
			যদি (!sshkey_match_keyname_to_sigalgs(
			    sshkey_ssh_name(authctxt->sensitive->চাবিগুলি[i]),
			    authctxt->active_ktype))
				চালু;
			/* we take and free the key */
			ব্যক্তিগত = authctxt->sensitive->চাবিগুলি[i];
			authctxt->sensitive->চাবিগুলি[i] = ফাঁকা;
			বিরতি;
		}
		/* Found one */
		যদি (ব্যক্তিগত != ফাঁকা)
			বিরতি;
		/* No more keys of this type; advance */
		authctxt->active_ktype = ফাঁকা;
	}
	যদি (ব্যক্তিগত == ফাঁকা) {
		মুক্ত(authctxt->oktypes);
		authctxt->oktypes = authctxt->ktypes = ফাঁকা;
		authctxt->active_ktype = ফাঁকা;
		debug("No more client hostkeys for hostbased authentication.");
		যাও out;
	}

	যদি ((fp = sshkey_fingerprint(ব্যক্তিগত, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == ফাঁকা) {
		error_f("sshkey_fingerprint failed");
		যাও out;
	}
	debug_f("trying hostkey %s %s using sigalg %s",
	    sshkey_ssh_name(ব্যক্তিগত), fp, authctxt->active_ktype);

	/* figure out a name for the client host */
	lname = get_local_name(ssh_packet_get_connection_in(ssh));
	যদি (lname == ফাঁকা) {
		error_f("cannot get local ipaddr/name");
		যাও out;
	}

	/* XXX sshbuf_put_stringf? */
	xasprintf(&chost, "%s.", lname);
	debug2_f("chost %s", chost);

	/* construct data */
	যদি ((b = sshbuf_new()) == ফাঁকা) {
		error_f("sshbuf_new failed");
		যাও out;
	}
	যদি ((r = sshkey_to_blob(ব্যক্তিগত, &keyblob, &keylen)) != 0) {
		error_fr(r, "sshkey_to_blob");
		যাও out;
	}
	যদি ((r = sshbuf_put_stringb(b, ssh->kex->session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_বার্তা_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->server_user)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->method->name)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->active_ktype)) != 0 ||
	    (r = sshbuf_put_string(b, keyblob, keylen)) != 0 ||
	    (r = sshbuf_put_cstring(b, chost)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->local_user)) != 0) {
		error_fr(r, "buffer error");
		যাও out;
	}

#ifdef DEBUG_PK
	sshbuf_dump(b, stderr);
#endif
	যদি ((r = ssh_keysign(ssh, ব্যক্তিগত, &sig, &siglen,
	    sshbuf_ptr(b), sshbuf_len(b))) != 0) {
		error("sign using hostkey %s %s failed",
		    sshkey_ssh_name(ব্যক্তিগত), fp);
		যাও out;
	}
	যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_USERAUTH_REQUEST)) != 0 ||
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
		যাও out;
	}
	success = 1;

 out:
	যদি (sig != ফাঁকা)
		freezero(sig, siglen);
	মুক্ত(keyblob);
	মুক্ত(lname);
	মুক্ত(fp);
	মুক্ত(chost);
	sshkey_free(ব্যক্তিগত);
	sshbuf_free(b);

	ফেরত success;
}

/* find auth method */

/*
 * given auth method name, if configurable options permit this method fill
 * in auth_ident field and return true, otherwise return false.
 */
স্থির পূর্ণসংখ্যা
authmethod_is_enabled(Authmethod *method)
{
	যদি (method == ফাঁকা)
		ফেরত 0;
	/* return false if options indicate this method is disabled */
	যদি  (method->enabled == ফাঁকা || *method->enabled == 0)
		ফেরত 0;
	/* return false if batch mode is enabled but method needs interactive mode */
	যদি  (method->batch_flag != ফাঁকা && *method->batch_flag != 0)
		ফেরত 0;
	ফেরত 1;
}

স্থির Authmethod *
authmethod_lookup(ধ্রুবক অক্ষর *name)
{
	Authmethod *method = ফাঁকা;
	যদি (name != ফাঁকা)
		জন্য (method = authmethods; method->name != ফাঁকা; method++)
			যদি (strcmp(name, method->name) == 0)
				ফেরত method;
	debug2("Unrecognized authentication method name: %s", name ? name : "NULL");
	ফেরত ফাঁকা;
}

/* XXX internal state */
স্থির Authmethod *current = ফাঁকা;
স্থির অক্ষর *supported = ফাঁকা;
স্থির অক্ষর *preferred = ফাঁকা;

/*
 * Given the authentication method list sent by the server, return the
 * next method we should try.  If the server initially sends a nil list,
 * use a built-in default list.
 */
স্থির Authmethod *
authmethod_get(অক্ষর *authlist)
{
	অক্ষর *name = ফাঁকা;
	u_int পরবর্তী;

	/* Use a suitable default if we're passed a nil list.  */
	যদি (authlist == ফাঁকা || strlen(authlist) == 0)
		authlist = options.preferred_authentications;

	যদি (supported == ফাঁকা || strcmp(authlist, supported) != 0) {
		debug3("start over, passed a different list %s", authlist);
		মুক্ত(supported);
		supported = xstrdup(authlist);
		preferred = options.preferred_authentications;
		debug3("preferred %s", preferred);
		current = ফাঁকা;
	} অন্যথা যদি (current != ফাঁকা && authmethod_is_enabled(current))
		ফেরত current;

	জন্য (;;) {
		যদি ((name = match_list(preferred, supported, &পরবর্তী)) == ফাঁকা) {
			debug("No more authentication methods to try.");
			current = ফাঁকা;
			ফেরত ফাঁকা;
		}
		preferred += পরবর্তী;
		debug3("authmethod_lookup %s", name);
		debug3("remaining preferred: %s", preferred);
		যদি ((current = authmethod_lookup(name)) != ফাঁকা &&
		    authmethod_is_enabled(current)) {
			debug3("authmethod_is_enabled %s", name);
			debug("Next authentication method: %s", name);
			মুক্ত(name);
			ফেরত current;
		}
		মুক্ত(name);
	}
}

স্থির অক্ষর *
authmethods_get(শূন্য)
{
	Authmethod *method = ফাঁকা;
	কাঠামো sshbuf *b;
	অক্ষর *list;
	পূর্ণসংখ্যা r;

	যদি ((b = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");
	জন্য (method = authmethods; method->name != ফাঁকা; method++) {
		যদি (authmethod_is_enabled(method)) {
			যদি ((r = sshbuf_putf(b, "%s%s",
			    sshbuf_len(b) ? "," : "", method->name)) != 0)
				fatal_fr(r, "buffer error");
		}
	}
	যদি ((list = sshbuf_dup_string(b)) == ফাঁকা)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	ফেরত list;
}
