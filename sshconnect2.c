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
বাহ্য Options options;

/*
 * SSH2 key exchange
 */

স্থির বর্ণ *xxx_host;
স্থির সংরচনা sockaddr_storage xxx_hostaddr;
স্থির ধ্রুব সংরচনা ssh_conn_info *xxx_conn_info;
স্থির পূর্ণাঙ্ক চাবি_type_allowed(সংরচনা sshkey *, ধ্রুব বর্ণ *);

স্থির পূর্ণাঙ্ক
verify_host_চাবি_callback(সংরচনা sshkey *hostkey, সংরচনা ssh *ssh)
{
	পূর্ণাঙ্ক r;

	যদি ((r = sshkey_check_rsa_length(hostkey,
	    options.required_rsa_size)) != 0)
		fatal_r(r, "Bad server host key");
	যদি (!চাবি_type_allowed(hostkey, options.hostkeyalgorithms)) {
		fatal("Server host key %s not in HostKeyAlgorithms",
		    sshkey_ssh_name(hostkey));
	}
	যদি (verify_host_চাবি(xxx_host, (সংরচনা sockaddr *)&xxx_hostaddr, hostkey,
	    xxx_conn_info) != 0)
		fatal("Host key verification failed.");
	প্রত্যাগম 0;
}

/* Returns the first item from a comma-separated algorithm list */
স্থির বর্ণ *
first_alg(ধ্রুব বর্ণ *algs)
{
	বর্ণ *ret, *cp;

	ret = xstrdup(algs);
	যদি ((cp = strchr(ret, ',')) != রিক্ত)
		*cp = '\0';
	প্রত্যাগম ret;
}

স্থির বর্ণ *
order_hostkeyalgs(বর্ণ *host, সংরচনা sockaddr *hostaddr, u_short port,
    ধ্রুব সংরচনা ssh_conn_info *cinfo)
{
	বর্ণ *oavail = রিক্ত, *avail = রিক্ত, *first = রিক্ত, *last = রিক্ত;
	বর্ণ *alg = রিক্ত, *hostname = রিক্ত, *ret = রিক্ত, *best = রিক্ত;
	size_t maxlen;
	সংরচনা hostkeys *hostkeys = রিক্ত;
	পূর্ণাঙ্ক ktype;
	u_int i;

	/* Find all hostkeys for this hostname */
	get_hostfile_hostname_ipaddr(host, hostaddr, port, &hostname, রিক্ত);
	hostkeys = init_hostkeys();
	প্রতি (i = 0; i < options.অঙ্ক_user_hostfiles; i++)
		load_hostkeys(hostkeys, hostname, options.user_hostfiles[i], 0);
	প্রতি (i = 0; i < options.অঙ্ক_system_hostfiles; i++) {
		load_hostkeys(hostkeys, hostname,
		    options.system_hostfiles[i], 0);
	}
	যদি (options.known_hosts_command != রিক্ত) {
		load_hostkeys_command(hostkeys, options.known_hosts_command,
		    "ORDER", cinfo, রিক্ত, hostname);
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
	    sshkey_ecdsa_nid_from_name(best), রিক্ত)) {
		debug3_f("have matching best-preference key type %s, "
		    "using HostkeyAlgorithms verbatim", best);
		ret = xstrdup(options.hostkeyalgorithms);
		গচ্ছ out;
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
	কুরু { \
		যদি (*to != '\0') \
			strlcat(to, ",", maxlen); \
		strlcat(to, from, maxlen); \
	} যাবত্ (0)

	যাবত্ ((alg = strsep(&avail, ",")) && *alg != '\0') {
		যদি ((ktype = sshkey_type_from_name(alg)) == চাবি_UNSPEC)
			fatal_f("unknown alg %s", alg);
		/*
		 * If we have a @cert-authority marker in known_hosts then
		 * prefer all certificate algorithms.
		 */
		যদি (sshkey_type_is_cert(ktype) &&
		    lookup_marker_in_hostkeys(hostkeys, MRK_CA)) {
			ALG_APPEND(first, alg);
			অনুবর্ত;
		}
		/* If the key appears in known_hosts then prefer it */
		যদি (lookup_চাবি_in_hostkeys_by_type(hostkeys,
		    sshkey_type_plain(ktype),
		    sshkey_ecdsa_nid_from_name(alg), রিক্ত)) {
			ALG_APPEND(first, alg);
			অনুবর্ত;
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

	প্রত্যাগম ret;
}

শূন্য
ssh_kex2(সংরচনা ssh *ssh, বর্ণ *host, সংরচনা sockaddr_storage *hostaddr,
    u_short port, ধ্রুব সংরচনা ssh_conn_info *cinfo)
{
	বর্ণ *myproposal[PROPOSAL_MAX];
	বর্ণ *all_চাবি, *hkalgs = রিক্ত;
	পূর্ণাঙ্ক r, use_known_hosts_order = 0;

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
	যদি (options.hostkeyalgorithms == রিক্ত ||
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
		hkalgs = order_hostkeyalgs(host, (সংরচনা sockaddr *)hostaddr,
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

প্রকারনির্দেশ সংরচনা cauthctxt Authctxt;
প্রকারনির্দেশ সংরচনা cauthmethod Authmethod;
প্রকারনির্দেশ সংরচনা identity Identity;
প্রকারনির্দেশ সংরচনা idlist Idlist;

সংরচনা identity {
	TAILQ_ENTRY(identity) next;
	পূর্ণাঙ্ক	agent_fd;		/* >=0 if agent supports key */
	সংরচনা sshkey	*চাবি;		/* public/private key */
	বর্ণ	*filename;		/* comment for agent-only keys */
	পূর্ণাঙ্ক	tried;
	পূর্ণাঙ্ক	isprivate;		/* key points to the private key */
	পূর্ণাঙ্ক	userprovided;
};
TAILQ_HEAD(idlist, identity);

সংরচনা cauthctxt {
	ধ্রুব বর্ণ *server_user;
	ধ্রুব বর্ণ *local_user;
	ধ্রুব বর্ণ *host;
	ধ্রুব বর্ণ *service;
	সংরচনা cauthmethod *method;
	sig_atomic_t success;
	বর্ণ *authlist;
#ifdef GSSAPI
	/* gssapi */
	gss_OID_set gss_supported_mechs;
	u_int mech_tried;
#endif
	/* pubkey */
	সংরচনা idlist চাবিগুলি;
	পূর্ণাঙ্ক agent_fd;
	/* hostbased */
	Sensitive *sensitive;
	বর্ণ *oktypes, *ktypes;
	ধ্রুব বর্ণ *active_ktype;
	/* kbd-interactive */
	পূর্ণাঙ্ক info_req_seen;
	পূর্ণাঙ্ক attempt_kbdint;
	/* password */
	পূর্ণাঙ্ক attempt_passwd;
	/* generic */
	শূন্য *methoddata;
};

সংরচনা cauthmethod {
	বর্ণ	*name;		/* string to compare against server's list */
	পূর্ণাঙ্ক	(*userauth)(সংরচনা ssh *ssh);
	শূন্য	(*cleanup)(সংরচনা ssh *ssh);
	পূর্ণাঙ্ক	*enabled;	/* flag in option struct that enables method */
	পূর্ণাঙ্ক	*batch_flag;	/* flag in option struct that disables method */
};

স্থির পূর্ণাঙ্ক প্রবেশ_userauth_service_accept(পূর্ণাঙ্ক, uint32_t, সংরচনা ssh *);
স্থির পূর্ণাঙ্ক প্রবেশ_userauth_success(পূর্ণাঙ্ক, uint32_t, সংরচনা ssh *);
স্থির পূর্ণাঙ্ক প্রবেশ_userauth_failure(পূর্ণাঙ্ক, uint32_t, সংরচনা ssh *);
স্থির পূর্ণাঙ্ক প্রবেশ_userauth_banner(পূর্ণাঙ্ক, uint32_t, সংরচনা ssh *);
স্থির পূর্ণাঙ্ক প্রবেশ_userauth_error(পূর্ণাঙ্ক, uint32_t, সংরচনা ssh *);
স্থির পূর্ণাঙ্ক প্রবেশ_userauth_info_req(পূর্ণাঙ্ক, uint32_t, সংরচনা ssh *);
স্থির পূর্ণাঙ্ক প্রবেশ_userauth_pk_ok(পূর্ণাঙ্ক, uint32_t, সংরচনা ssh *);
স্থির পূর্ণাঙ্ক প্রবেশ_userauth_passwd_changereq(পূর্ণাঙ্ক, uint32_t, সংরচনা ssh *);

স্থির পূর্ণাঙ্ক userauth_none(সংরচনা ssh *);
স্থির পূর্ণাঙ্ক userauth_pubkey(সংরচনা ssh *);
স্থির পূর্ণাঙ্ক userauth_passwd(সংরচনা ssh *);
স্থির পূর্ণাঙ্ক userauth_kbdint(সংরচনা ssh *);
স্থির পূর্ণাঙ্ক userauth_hostbased(সংরচনা ssh *);

#ifdef GSSAPI
স্থির পূর্ণাঙ্ক userauth_gssapi(সংরচনা ssh *);
স্থির শূন্য userauth_gssapi_cleanup(সংরচনা ssh *);
স্থির পূর্ণাঙ্ক প্রবেশ_gssapi_response(পূর্ণাঙ্ক type, uint32_t, সংরচনা ssh *);
স্থির পূর্ণাঙ্ক প্রবেশ_gssapi_token(পূর্ণাঙ্ক type, uint32_t, সংরচনা ssh *);
স্থির পূর্ণাঙ্ক প্রবেশ_gssapi_error(পূর্ণাঙ্ক, uint32_t, সংরচনা ssh *);
স্থির পূর্ণাঙ্ক প্রবেশ_gssapi_errtok(পূর্ণাঙ্ক, uint32_t, সংরচনা ssh *);
#endif

শূন্য	userauth(সংরচনা ssh *, বর্ণ *);

স্থির শূন্য pubkey_cleanup(সংরচনা ssh *);
স্থির পূর্ণাঙ্ক sign_and_send_pubkey(সংরচনা ssh *ssh, Identity *);
স্থির শূন্য pubkey_prepare(সংরচনা ssh *, Authctxt *);
স্থির শূন্য pubkey_reset(Authctxt *);
স্থির সংরচনা sshkey *load_identity_file(Identity *);

স্থির Authmethod *authmethod_get(বর্ণ *authlist);
স্থির Authmethod *authmethod_lookup(ধ্রুব বর্ণ *name);
স্থির বর্ণ *authmethods_get(শূন্য);

Authmethod authmethods[] = {
#ifdef GSSAPI
	{"gssapi-with-mic",
		userauth_gssapi,
		userauth_gssapi_cleanup,
		&options.gss_authentication,
		রিক্ত},
#endif
	{"hostbased",
		userauth_hostbased,
		রিক্ত,
		&options.hostbased_authentication,
		রিক্ত},
	{"publickey",
		userauth_pubkey,
		রিক্ত,
		&options.pubkey_authentication,
		রিক্ত},
	{"keyboard-interactive",
		userauth_kbdint,
		রিক্ত,
		&options.kbd_interactive_authentication,
		&options.batch_mode},
	{"password",
		userauth_passwd,
		রিক্ত,
		&options.password_authentication,
		&options.batch_mode},
	{"none",
		userauth_none,
		রিক্ত,
		রিক্ত,
		রিক্ত},
	{রিক্ত, রিক্ত, রিক্ত, রিক্ত, রিক্ত}
};

শূন্য
ssh_userauth2(সংরচনা ssh *ssh, ধ্রুব বর্ণ *local_user,
    ধ্রুব বর্ণ *server_user, বর্ণ *host, Sensitive *sensitive)
{
	Authctxt authctxt;
	পূর্ণাঙ্ক r;

	যদি (options.preferred_authentications == রিক্ত)
		options.preferred_authentications = authmethods_get();

	/* setup authentication context */
	memset(&authctxt, 0, পরিমাণ(authctxt));
	authctxt.server_user = server_user;
	authctxt.local_user = local_user;
	authctxt.host = host;
	authctxt.service = "ssh-connection";		/* service name */
	authctxt.success = 0;
	authctxt.method = authmethod_lookup("none");
	authctxt.authlist = রিক্ত;
	authctxt.methoddata = রিক্ত;
	authctxt.sensitive = sensitive;
	authctxt.active_ktype = authctxt.oktypes = authctxt.ktypes = রিক্ত;
	authctxt.info_req_seen = 0;
	authctxt.attempt_kbdint = 0;
	authctxt.attempt_passwd = 0;
#যদি GSSAPI
	authctxt.gss_supported_mechs = রিক্ত;
	authctxt.mech_tried = 0;
#endif
	authctxt.agent_fd = -1;
	যদি (authctxt.method == রিক্ত)
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
	যদি (authctxt.gss_supported_mechs != রিক্ত) {
		u_int ms;

		gss_release_oid_set(&ms, &authctxt.gss_supported_mechs);
		authctxt.gss_supported_mechs = রিক্ত;
	}
#endif
	ssh->authctxt = রিক্ত;

	ssh_dispatch_range(ssh, SSH2_বার্তা_USERAUTH_MIN, SSH2_বার্তা_USERAUTH_MAX, রিক্ত);

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

স্থির পূর্ণাঙ্ক
প্রবেশ_userauth_service_accept(পূর্ণাঙ্ক type, uint32_t seq, সংরচনা ssh *ssh)
{
	পূর্ণাঙ্ক r;

	যদি (ssh_packet_remaining(ssh) > 0) {
		বর্ণ *reply;

		যদি ((r = sshpkt_get_cstring(ssh, &reply, রিক্ত)) != 0)
			গচ্ছ out;
		debug2("service_accept: %s", reply);
		মুক্ত(reply);
	} অন্যথা {
		debug2("buggy server: service_accept w/o service");
	}
	যদি ((r = sshpkt_get_end(ssh)) != 0)
		গচ্ছ out;
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
	প্রত্যাগম r;
}

শূন্য
userauth(সংরচনা ssh *ssh, বর্ণ *authlist)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;

	যদি (authctxt->method != রিক্ত && authctxt->method->cleanup != রিক্ত)
		authctxt->method->cleanup(ssh);

	মুক্ত(authctxt->methoddata);
	authctxt->methoddata = রিক্ত;
	যদি (authlist == রিক্ত) {
		authlist = authctxt->authlist;
	} অন্যথা {
		মুক্ত(authctxt->authlist);
		authctxt->authlist = authlist;
	}
	প্রতি (;;) {
		Authmethod *method = authmethod_get(authlist);
		যদি (method == রিক্ত)
			fatal("%s@%s: Permission denied (%s).",
			    authctxt->server_user, authctxt->host, authlist);
		authctxt->method = method;

		/* reset the per method handler */
		ssh_dispatch_range(ssh, SSH2_বার্তা_USERAUTH_PER_METHOD_MIN,
		    SSH2_বার্তা_USERAUTH_PER_METHOD_MAX, রিক্ত);

		/* and try new method */
		যদি (method->userauth(ssh) != 0) {
			debug2("we sent a %s packet, wait for reply", method->name);
			ভঙ্গ;
		} অন্যথা {
			debug2("we did not send a packet, disable method");
			method->enabled = রিক্ত;
		}
	}
}

স্থির পূর্ণাঙ্ক
প্রবেশ_userauth_error(পূর্ণাঙ্ক type, uint32_t seq, সংরচনা ssh *ssh)
{
	fatal_f("bad message during authentication: type %d", type);
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
প্রবেশ_userauth_banner(পূর্ণাঙ্ক type, uint32_t seq, সংরচনা ssh *ssh)
{
	বর্ণ *বার্তা = রিক্ত;
	size_t len;
	পূর্ণাঙ্ক r;

	debug3_f("entering");
	যদি ((r = sshpkt_get_cstring(ssh, &বার্তা, &len)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, রিক্ত, রিক্ত)) != 0)
		গচ্ছ out;
	যদি (len > 0 && options.log_level >= SYSLOG_LEVEL_INFO)
		fmprintf(stderr, "%s", বার্তা);
	r = 0;
 out:
	মুক্ত(বার্তা);
	প্রত্যাগম r;
}

স্থির পূর্ণাঙ্ক
প্রবেশ_userauth_success(পূর্ণাঙ্ক type, uint32_t seq, সংরচনা ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	যদি (authctxt == রিক্ত)
		fatal_f("no authentication context");
	মুক্ত(authctxt->authlist);
	authctxt->authlist = রিক্ত;
	যদি (authctxt->method != রিক্ত && authctxt->method->cleanup != রিক্ত)
		authctxt->method->cleanup(ssh);
	মুক্ত(authctxt->methoddata);
	authctxt->methoddata = রিক্ত;
	authctxt->success = 1;			/* break out */
	ssh_dispatch_set(ssh, SSH2_বার্তা_EXT_INFO, dispatch_protocol_error);
	প্রত্যাগম 0;
}

#যদি 0
স্থির পূর্ণাঙ্ক
প্রবেশ_userauth_success_unexpected(পূর্ণাঙ্ক type, uint32_t seq, সংরচনা ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	যদি (authctxt == রিক্ত)
		fatal_f("no authentication context");

	fatal("Unexpected authentication success during %s.",
	    authctxt->method->name);
	প্রত্যাগম 0;
}
#endif

স্থির পূর্ণাঙ্ক
প্রবেশ_userauth_failure(পূর্ণাঙ্ক type, uint32_t seq, সংরচনা ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	বর্ণ *authlist = রিক্ত;
	u_char partial;

	যদি (authctxt == রিক্ত)
		fatal("input_userauth_failure: no authentication context");

	যদি (sshpkt_get_cstring(ssh, &authlist, রিক্ত) != 0 ||
	    sshpkt_get_u8(ssh, &partial) != 0 ||
	    sshpkt_get_end(ssh) != 0)
		গচ্ছ out;

	যদি (partial != 0) {
		verbose("Authenticated using \"%s\" with partial success.",
		    authctxt->method->name);
		/* reset state */
		pubkey_reset(authctxt);
	}
	debug("Authentications that can continue: %s", authlist);

	userauth(ssh, authlist);
	authlist = রিক্ত;
 out:
	মুক্ত(authlist);
	প্রত্যাগম 0;
}

/*
 * Format an identity for logging including filename, key type, fingerprint
 * and location (agent, etc.). Caller must free.
 */
স্থির বর্ণ *
format_identity(Identity *id)
{
	বর্ণ *fp = রিক্ত, *ret = রিক্ত;
	ধ্রুব বর্ণ *note = "";

	যদি (id->চাবি != রিক্ত) {
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
	প্রত্যাগম ret;
}

স্থির পূর্ণাঙ্ক
প্রবেশ_userauth_pk_ok(পূর্ণাঙ্ক type, uint32_t seq, সংরচনা ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	সংরচনা sshkey *চাবি = রিক্ত;
	সংরচনা sshbuf *keyblob = রিক্ত;
	Identity *id = রিক্ত;
	পূর্ণাঙ্ক pktype, found = 0, sent = 0;
	বর্ণ *pkalg = রিক্ত, *fp = রিক্ত, *ident = রিক্ত;
	পূর্ণাঙ্ক r;

	যদি (authctxt == রিক্ত)
		fatal_f("no authentication context");

	যদি ((r = sshpkt_get_cstring(ssh, &pkalg, রিক্ত)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		গচ্ছ done;

	যদি (match_pattern_list(pkalg, options.pubkey_accepted_algos, 0) != 1) {
		error_f("server replied to PK_OK with signature type %s not "
		    "in PubkeyAcceptedAlgorithms", pkalg);
		r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		গচ্ছ done;
	}
	যদি ((pktype = sshkey_type_from_name(pkalg)) == চাবি_UNSPEC) {
		debug_f("server sent unknown pkalg %s", pkalg);
		r = SSH_ERR_INVALID_FORMAT;
		গচ্ছ done;
	}
	/* inner key type should match signature type */
	যদি ((r = sshkey_fromb_allowlist(keyblob, &চাবি, pkalg, রিক্ত)) != 0) {
		debug_r(r, "no key from blob. pkalg %s", pkalg);
		গচ্ছ done;
	}
	যদি (চাবি->type != pktype) {
		error("input_userauth_pk_ok: type mismatch "
		    "for decoded key (received %d, expected %d)",
		    চাবি->type, pktype);
		r = SSH_ERR_INVALID_FORMAT;
		গচ্ছ done;
	}

	/*
	 * search keys in the reverse order, because last candidate has been
	 * moved to the end of the queue.  this also avoids confusion by
	 * duplicate keys
	 */
	TAILQ_FOREACH_REVERSE(id, &authctxt->চাবিগুলি, idlist, next) {
		যদি (sshkey_equal(চাবি, id->চাবি)) {
			found = 1;
			ভঙ্গ;
		}
	}
	যদি (!found || id == রিক্ত) {
		fp = sshkey_fingerprint(চাবি, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		error_f("server replied with unknown key: %s %s",
		    sshkey_type(চাবি), fp == রিক্ত ? "<ERROR>" : fp);
		r = SSH_ERR_INVALID_FORMAT;
		গচ্ছ done;
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
		userauth(ssh, রিক্ত);
	প্রত্যাগম r;
}

#ifdef GSSAPI
স্থির পূর্ণাঙ্ক
userauth_gssapi(সংরচনা ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Gssctxt *gssctxt = রিক্ত;
	OM_uint32 min;
	পূর্ণাঙ্ক r, ok = 0;
	gss_OID mech = রিক্ত;

	/* Try one GSSAPI method at a time, rather than sending them all at
	 * once. */

	যদি (authctxt->gss_supported_mechs == রিক্ত)
		gss_indicate_mechs(&min, &authctxt->gss_supported_mechs);

	/* Check to see whether the mechanism is usable before we offer it */
	যাবত্ (authctxt->mech_tried < authctxt->gss_supported_mechs->গুনতি &&
	    !ok) {
		mech = &authctxt->gss_supported_mechs->
		    elements[authctxt->mech_tried];
		/* My DER encoding requires length<128 */
		যদি (mech->length < 128 && ssh_gssapi_check_mechanism(&gssctxt,
		    mech, authctxt->host)) {
			ok = 1; /* Mechanism works */
		} অন্যথা {
			authctxt->mech_tried++;
		}
	}

	যদি (!ok || mech == রিক্ত)
		প্রত্যাগম 0;

	authctxt->methoddata=(শূন্য *)gssctxt;

	যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_USERAUTH_REQUEST)) != 0 ||
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

	ssh_dispatch_set(ssh, SSH2_বার্তা_USERAUTH_GSSAPI_RESPONSE, &প্রবেশ_gssapi_response);
	ssh_dispatch_set(ssh, SSH2_বার্তা_USERAUTH_GSSAPI_TOKEN, &প্রবেশ_gssapi_token);
	ssh_dispatch_set(ssh, SSH2_বার্তা_USERAUTH_GSSAPI_ERROR, &প্রবেশ_gssapi_error);
	ssh_dispatch_set(ssh, SSH2_বার্তা_USERAUTH_GSSAPI_ERRTOK, &প্রবেশ_gssapi_errtok);

	authctxt->mech_tried++; /* Move along to next candidate */

	প্রত্যাগম 1;
}

স্থির শূন্য
userauth_gssapi_cleanup(সংরচনা ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Gssctxt *gssctxt = (Gssctxt *)authctxt->methoddata;

	ssh_gssapi_delete_ctx(&gssctxt);
	authctxt->methoddata = রিক্ত;
}

স্থির OM_uint32
process_gssapi_token(সংরচনা ssh *ssh, gss_buffer_t recv_tok)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt = authctxt->methoddata;
	gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc mic = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc gssbuf;
	OM_uint32 status, ms, flags;
	পূর্ণাঙ্ক r;

	status = ssh_gssapi_init_ctx(gssctxt, options.gss_deleg_creds,
	    recv_tok, &send_tok, &flags);

	যদি (send_tok.length > 0) {
		u_char type = GSS_ERROR(status) ?
		    SSH2_বার্তা_USERAUTH_GSSAPI_ERRTOK :
		    SSH2_বার্তা_USERAUTH_GSSAPI_TOKEN;

		যদি ((r = sshpkt_start(ssh, type)) != 0 ||
		    (r = sshpkt_put_string(ssh, send_tok.মান,
		    send_tok.length)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send %u packet", type);

		gss_release_buffer(&ms, &send_tok);
	}

	যদি (status == GSS_S_COMPLETE) {
		/* send either complete or MIC, depending on mechanism */
		যদি (!(flags & GSS_C_INTEG_FLAG)) {
			যদি ((r = sshpkt_start(ssh,
			    SSH2_বার্তা_USERAUTH_GSSAPI_EXCHANGE_COMPLETE)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "send completion");
		} অন্যথা {
			সংরচনা sshbuf *b;

			যদি ((b = sshbuf_new()) == রিক্ত)
				fatal_f("sshbuf_new failed");
			ssh_gssapi_buildmic(b, authctxt->server_user,
			    authctxt->service, "gssapi-with-mic",
			    ssh->kex->session_id);

			যদি ((gssbuf.মান = sshbuf_mutable_ptr(b)) == রিক্ত)
				fatal_f("sshbuf_mutable_ptr failed");
			gssbuf.length = sshbuf_len(b);

			status = ssh_gssapi_sign(gssctxt, &gssbuf, &mic);

			যদি (!GSS_ERROR(status)) {
				যদি ((r = sshpkt_start(ssh,
				    SSH2_বার্তা_USERAUTH_GSSAPI_MIC)) != 0 ||
				    (r = sshpkt_put_string(ssh, mic.মান,
				    mic.length)) != 0 ||
				    (r = sshpkt_send(ssh)) != 0)
					fatal_fr(r, "send MIC");
			}

			sshbuf_free(b);
			gss_release_buffer(&ms, &mic);
		}
	}

	প্রত্যাগম status;
}

স্থির পূর্ণাঙ্ক
প্রবেশ_gssapi_response(পূর্ণাঙ্ক type, uint32_t plen, সংরচনা ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	size_t oidlen;
	u_char *oidv = রিক্ত;
	পূর্ণাঙ্ক r;

	যদি (authctxt == রিক্ত)
		fatal("input_gssapi_response: no authentication context");
	gssctxt = authctxt->methoddata;

	/* Setup our OID */
	যদি ((r = sshpkt_get_string(ssh, &oidv, &oidlen)) != 0)
		গচ্ছ done;

	যদি (oidlen <= 2 ||
	    oidv[0] != SSH_GSS_OIDTYPE ||
	    oidv[1] != oidlen - 2) {
		debug("Badly encoded mechanism OID received");
		userauth(ssh, রিক্ত);
		গচ্ছ ok;
	}

	যদি (!ssh_gssapi_check_oid(gssctxt, oidv + 2, oidlen - 2))
		fatal("Server returned different OID than expected");

	যদি ((r = sshpkt_get_end(ssh)) != 0)
		গচ্ছ done;

	যদি (GSS_ERROR(process_gssapi_token(ssh, GSS_C_NO_BUFFER))) {
		/* Start again with next method on list */
		debug("Trying to start again");
		userauth(ssh, রিক্ত);
		গচ্ছ ok;
	}
 ok:
	r = 0;
 done:
	মুক্ত(oidv);
	প্রত্যাগম r;
}

স্থির পূর্ণাঙ্ক
প্রবেশ_gssapi_token(পূর্ণাঙ্ক type, uint32_t plen, সংরচনা ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	gss_buffer_desc recv_tok;
	u_char *p = রিক্ত;
	size_t len;
	OM_uint32 status;
	পূর্ণাঙ্ক r;

	যদি (authctxt == রিক্ত)
		fatal("input_gssapi_response: no authentication context");

	যদি ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		গচ্ছ out;

	recv_tok.মান = p;
	recv_tok.length = len;
	status = process_gssapi_token(ssh, &recv_tok);

	/* Start again with the next method in the list */
	যদি (GSS_ERROR(status)) {
		userauth(ssh, রিক্ত);
		/* ok */
	}
	r = 0;
 out:
	মুক্ত(p);
	প্রত্যাগম r;
}

স্থির পূর্ণাঙ্ক
প্রবেশ_gssapi_errtok(পূর্ণাঙ্ক type, uint32_t plen, সংরচনা ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc recv_tok;
	OM_uint32 ms;
	u_char *p = রিক্ত;
	size_t len;
	পূর্ণাঙ্ক r;

	যদি (authctxt == রিক্ত)
		fatal("input_gssapi_response: no authentication context");
	gssctxt = authctxt->methoddata;

	যদি ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0) {
		মুক্ত(p);
		প্রত্যাগম r;
	}

	/* Stick it into GSSAPI and see what it says */
	recv_tok.মান = p;
	recv_tok.length = len;
	(শূন্য)ssh_gssapi_init_ctx(gssctxt, options.gss_deleg_creds,
	    &recv_tok, &send_tok, রিক্ত);
	মুক্ত(p);
	gss_release_buffer(&ms, &send_tok);

	/* Server will be returning a failed packet after this one */
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
প্রবেশ_gssapi_error(পূর্ণাঙ্ক type, uint32_t plen, সংরচনা ssh *ssh)
{
	বর্ণ *বার্তা = রিক্ত;
	বর্ণ *lang = রিক্ত;
	পূর্ণাঙ্ক r;

	যদি ((r = sshpkt_get_u32(ssh, রিক্ত)) != 0 ||	/* maj */
	    (r = sshpkt_get_u32(ssh, রিক্ত)) != 0 ||	/* min */
	    (r = sshpkt_get_cstring(ssh, &বার্তা, রিক্ত)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, রিক্ত)) != 0)
		গচ্ছ out;
	r = sshpkt_get_end(ssh);
	debug("Server GSSAPI Error:\n%s", বার্তা);
 out:
	মুক্ত(বার্তা);
	মুক্ত(lang);
	প্রত্যাগম r;
}
#endif /* GSSAPI */

স্থির পূর্ণাঙ্ক
userauth_none(সংরচনা ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	পূর্ণাঙ্ক r;

	/* initial userauth request */
	যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	প্রত্যাগম 1;
}

স্থির পূর্ণাঙ্ক
userauth_passwd(সংরচনা ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	বর্ণ *password, *prompt = রিক্ত;
	ধ্রুব বর্ণ *host = options.host_চাবি_alias ?  options.host_চাবি_alias :
	    authctxt->host;
	পূর্ণাঙ্ক r;

	যদি (authctxt->attempt_passwd++ >= options.সংখ্যা_of_password_prompts)
		প্রত্যাগম 0;

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
	যদি (password != রিক্ত)
		freezero(password, strlen(password));

	ssh_dispatch_set(ssh, SSH2_বার্তা_USERAUTH_PASSWD_CHANGEREQ,
	    &প্রবেশ_userauth_passwd_changereq);

	প্রত্যাগম 1;
}

/*
 * parse PASSWD_CHANGEREQ, prompt user and send SSH2_MSG_USERAUTH_REQUEST
 */
স্থির পূর্ণাঙ্ক
প্রবেশ_userauth_passwd_changereq(পূর্ণাঙ্ক type, uint32_t seqnr, সংরচনা ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	বর্ণ *info = রিক্ত, *lang = রিক্ত, *password = রিক্ত, *retype = রিক্ত;
	বর্ণ prompt[256];
	ধ্রুব বর্ণ *host;
	পূর্ণাঙ্ক r, addnl;
	size_t len;

	debug2("input_userauth_passwd_changereq");

	যদি (authctxt == রিক্ত)
		fatal("input_userauth_passwd_changereq: "
		    "no authentication context");
	host = options.host_চাবি_alias ? options.host_চাবি_alias : authctxt->host;

	যদি ((r = sshpkt_get_cstring(ssh, &info, রিক্ত)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, রিক্ত)) != 0)
		গচ্ছ out;
	যদি ((len = strlen(info)) > 0) {
		addnl = info[len] != '\n';
		fmprintf(stderr, "%s%s", info, addnl ? "\n" : "");
	}
	যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0)	/* additional info */
		গচ্ছ out;

	snprintf(prompt, পরিমাণ(prompt),
	    "Enter %.30s@%.128s's old password: ",
	    authctxt->server_user, host);
	password = read_passphrase(prompt, 0);
	যদি ((r = sshpkt_put_cstring(ssh, password)) != 0)
		গচ্ছ out;

	freezero(password, strlen(password));
	password = রিক্ত;
	যাবত্ (password == রিক্ত) {
		snprintf(prompt, পরিমাণ(prompt),
		    "Enter %.30s@%.128s's new password: ",
		    authctxt->server_user, host);
		password = read_passphrase(prompt, RP_ALLOW_EOF);
		যদি (password == রিক্ত) {
			/* bail out */
			r = 0;
			গচ্ছ out;
		}
		snprintf(prompt, পরিমাণ(prompt),
		    "Retype %.30s@%.128s's new password: ",
		    authctxt->server_user, host);
		retype = read_passphrase(prompt, 0);
		যদি (strcmp(password, retype) != 0) {
			freezero(password, strlen(password));
			logit("Mismatch; try again, EOF to quit.");
			password = রিক্ত;
		}
		freezero(retype, strlen(retype));
	}
	যদি ((r = sshpkt_put_cstring(ssh, password)) != 0 ||
	    (r = sshpkt_add_padding(ssh, 64)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		গচ্ছ out;

	ssh_dispatch_set(ssh, SSH2_বার্তা_USERAUTH_PASSWD_CHANGEREQ,
	    &প্রবেশ_userauth_passwd_changereq);
	r = 0;
 out:
	যদি (password)
		freezero(password, strlen(password));
	মুক্ত(info);
	মুক্ত(lang);
	প্রত্যাগম r;
}

/*
 * Select an algorithm for publickey signatures.
 * Returns algorithm (caller must free) or NULL if no mutual algorithm found.
 *
 * Call with ssh==NULL to ignore server-sig-algs extension list and
 * only attempt with the key's base signature type.
 */
স্থির বর্ণ *
চাবি_sig_algorithm(সংরচনা ssh *ssh, ধ্রুব সংরচনা sshkey *চাবি)
{
	বর্ণ *allowed, *oallowed, *cp, *tmp, *alg = রিক্ত;
	ধ্রুব বর্ণ *server_sig_algs;

	/*
	 * The signature algorithm will only differ from the key algorithm
	 * for RSA keys/certs and when the server advertises support for
	 * newer (SHA2) algorithms.
	 */
	যদি (ssh == রিক্ত || ssh->kex->server_sig_algs == রিক্ত ||
	    (চাবি->type != চাবি_RSA && চাবি->type != চাবি_RSA_CERT) ||
	    (চাবি->type == চাবি_RSA_CERT && (ssh->compat & SSH_BUG_SIGTYPE))) {
		/* Filter base key signature alg against our configuration */
		প্রত্যাগম match_list(sshkey_ssh_name(চাবি),
		    options.pubkey_accepted_algos, রিক্ত);
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
	যাবত্ ((cp = strsep(&allowed, ",")) != রিক্ত) {
		যদি (sshkey_type_from_name(cp) != চাবি->type)
			অনুবর্ত;
		tmp = match_list(sshkey_sigalg_by_name(cp),
		    server_sig_algs, রিক্ত);
		যদি (tmp != রিক্ত)
			alg = xstrdup(cp);
		মুক্ত(tmp);
		যদি (alg != রিক্ত)
			ভঙ্গ;
	}
	মুক্ত(oallowed);
	প্রত্যাগম alg;
}

স্থির পূর্ণাঙ্ক
identity_sign(সংরচনা identity *id, u_char **sigp, size_t *lenp,
    ধ্রুব u_char *data, size_t datalen, u_int compat, ধ্রুব বর্ণ *alg)
{
	সংরচনা sshkey *sign_চাবি = রিক্ত, *prv = রিক্ত;
	পূর্ণাঙ্ক is_agent = 0, retried = 0, r = SSH_ERR_INTERNAL_ERROR;
	সংরচনা notifier_ctx *notifier = রিক্ত;
	বর্ণ *fp = রিক্ত, *pin = রিক্ত, *prompt = রিক্ত;

	*sigp = রিক্ত;
	*lenp = 0;

	/* The agent supports this key. */
	যদি (id->চাবি != রিক্ত && id->agent_fd != -1) {
		প্রত্যাগম ssh_agent_sign(id->agent_fd, id->চাবি, sigp, lenp,
		    data, datalen, alg, compat);
	}

	/*
	 * We have already loaded the private key or the private key is
	 * stored in external hardware.
	 */
	যদি (id->চাবি != রিক্ত &&
	    (id->isprivate || (id->চাবি->flags & SSHKEY_FLAG_EXT))) {
		sign_চাবি = id->চাবি;
		is_agent = 1;
	} অন্যথা {
		/* Load the private key from the file. */
		যদি ((prv = load_identity_file(id)) == রিক্ত)
			প্রত্যাগম SSH_ERR_চাবি_NOT_FOUND;
		যদি (id->চাবি != রিক্ত && !sshkey_equal_public(prv, id->চাবি)) {
			error_f("private key %s contents do not match public",
			    id->filename);
			r = SSH_ERR_চাবি_NOT_FOUND;
			গচ্ছ out;
		}
		sign_চাবি = prv;
	}
 retry_pin:
	/* Prompt for touch for non-agent FIDO keys that request UP */
	যদি (!is_agent && sshkey_is_sk(sign_চাবি) &&
	    (sign_চাবি->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
		/* XXX should batch mode just skip these? */
		যদি ((fp = sshkey_fingerprint(sign_চাবি,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == রিক্ত)
			fatal_f("fingerprint failed");
		notifier = notify_start(options.batch_mode,
		    "Confirm user presence for key %s %s",
		    sshkey_type(sign_চাবি), fp);
		মুক্ত(fp);
	}
	যদি ((r = sshkey_sign(sign_চাবি, sigp, lenp, data, datalen,
	    alg, options.sk_provider, pin, compat)) != 0) {
		debug_fr(r, "sshkey_sign");
		যদি (!retried && pin == রিক্ত && !is_agent &&
		    sshkey_is_sk(sign_চাবি) &&
		    r == SSH_ERR_চাবি_WRONG_PASSPHRASE) {
			notify_complete(notifier, রিক্ত);
			notifier = রিক্ত;
			xasprintf(&prompt, "Enter PIN for %s key %s: ",
			    sshkey_type(sign_চাবি), id->filename);
			pin = read_passphrase(prompt, 0);
			retried = 1;
			গচ্ছ retry_pin;
		}
		গচ্ছ out;
	}

	/*
	 * PKCS#11 tokens may not support all signature algorithms,
	 * so check what we get back.
	 */
	যদি (id->চাবি != রিক্ত && (id->চাবি->flags & SSHKEY_FLAG_EXT) != 0 &&
	    (r = sshkey_check_sigtype(*sigp, *lenp, alg)) != 0) {
		debug_fr(r, "sshkey_check_sigtype");
		গচ্ছ out;
	}
	/* success */
	r = 0;
 out:
	মুক্ত(prompt);
	যদি (pin != রিক্ত)
		freezero(pin, strlen(pin));
	notify_complete(notifier, r == 0 ? "User presence confirmed" : রিক্ত);
	sshkey_free(prv);
	প্রত্যাগম r;
}

স্থির পূর্ণাঙ্ক
id_filename_matches(Identity *id, Identity *private_id)
{
	স্থির ধ্রুব বর্ণ * ধ্রুব suffixes[] = { ".pub", "-cert.pub", রিক্ত };
	size_t len = strlen(id->filename), plen = strlen(private_id->filename);
	size_t i, slen;

	যদি (strcmp(id->filename, private_id->filename) == 0)
		প্রত্যাগম 1;
	প্রতি (i = 0; suffixes[i]; i++) {
		slen = strlen(suffixes[i]);
		যদি (len > slen && plen == len - slen &&
		    strcmp(id->filename + (len - slen), suffixes[i]) == 0 &&
		    memcmp(id->filename, private_id->filename, plen) == 0)
			প্রত্যাগম 1;
	}
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
sign_and_send_pubkey(সংরচনা ssh *ssh, Identity *id)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	সংরচনা sshbuf *b = রিক্ত;
	Identity *private_id, *sign_id = রিক্ত;
	u_char *signature = রিক্ত;
	size_t slen = 0, skip = 0;
	পূর্ণাঙ্ক r, fallback_sigtype, sent = 0;
	বর্ণ *alg = রিক্ত, *fp = রিক্ত;
	ধ্রুব বর্ণ *loc = "", *method = "publickey";
	পূর্ণাঙ্ক hostbound = 0;

	/* prefer host-bound pubkey signatures if supported by server */
	যদি ((ssh->kex->flags & KEX_HAS_PUBKEY_HOSTBOUND) != 0 &&
	    (options.pubkey_authentication & SSH_PUBKEY_AUTH_HBOUND) != 0) {
		hostbound = 1;
		method = "publickey-hostbound-v00@openssh.com";
	}

	যদি ((fp = sshkey_fingerprint(id->চাবি, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == রিক্ত)
		প্রত্যাগম 0;

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
		TAILQ_FOREACH(private_id, &authctxt->চাবিগুলি, next) {
			যদি (sshkey_equal_public(id->চাবি, private_id->চাবি) &&
			    id->চাবি->type != private_id->চাবি->type) {
				sign_id = private_id;
				ভঙ্গ;
			}
		}
		/*
		 * Exact key matches are preferred, but also allow
		 * filename matches for non-PKCS#11/agent keys that
		 * didn't load public keys. This supports the case
		 * of keeping just a private key file and public
		 * certificate on disk.
		 */
		যদি (sign_id == রিক্ত &&
		    !id->isprivate && id->agent_fd == -1 &&
		    (id->চাবি->flags & SSHKEY_FLAG_EXT) == 0) {
			TAILQ_FOREACH(private_id, &authctxt->চাবিগুলি, next) {
				যদি (private_id->চাবি == রিক্ত &&
				    id_filename_matches(id, private_id)) {
					sign_id = private_id;
					ভঙ্গ;
				}
			}
		}
		যদি (sign_id != রিক্ত) {
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
	যদি (sign_id == রিক্ত)
		sign_id = id;

	/* assemble and sign data */
	প্রতি (fallback_sigtype = 0; fallback_sigtype <= 1; fallback_sigtype++) {
		মুক্ত(alg);
		slen = 0;
		signature = রিক্ত;
		যদি ((alg = চাবি_sig_algorithm(fallback_sigtype ? রিক্ত : ssh,
		    id->চাবি)) == রিক্ত) {
			error_f("no mutual signature supported");
			গচ্ছ out;
		}
		debug3_f("signing using %s %s", alg, fp);

		sshbuf_free(b);
		যদি ((b = sshbuf_new()) == রিক্ত)
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
			যদি (ssh->kex->initial_hostkey == রিক্ত) {
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
			ভঙ্গ;
		অন্যথা যদি (r == SSH_ERR_চাবি_NOT_FOUND)
			গচ্ছ out; /* soft failure */
		অন্যথা যদি (r == SSH_ERR_SIGN_ALG_UNSUPPORTED &&
		    !fallback_sigtype) {
			যদি (sign_id->agent_fd != -1)
				loc = "agent ";
			অন্যথা যদি (sign_id->চাবি != রিক্ত &&
			    (sign_id->চাবি->flags & SSHKEY_FLAG_EXT) != 0)
				loc = "token ";
			logit("%skey %s %s returned incorrect signature type",
			    loc, sshkey_type(id->চাবি), fp);
			অনুবর্ত;
		}
		error_fr(r, "signing failed for %s \"%s\"%s",
		    sshkey_type(sign_id->চাবি), sign_id->filename,
		    id->agent_fd != -1 ? " from agent" : "");
		গচ্ছ out;
	}
	যদি (slen == 0 || signature == রিক্ত) /* shouldn't happen */
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
	প্রত্যাগম sent;
}

স্থির পূর্ণাঙ্ক
send_pubkey_test(সংরচনা ssh *ssh, Identity *id)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	u_char *blob = রিক্ত;
	বর্ণ *alg = রিক্ত;
	size_t bloblen;
	u_int have_sig = 0;
	পূর্ণাঙ্ক sent = 0, r;

	যদি ((alg = চাবি_sig_algorithm(ssh, id->চাবি)) == রিক্ত) {
		debug_f("no mutual signature algorithm");
		গচ্ছ out;
	}

	যদি ((r = sshkey_to_blob(id->চাবি, &blob, &bloblen)) != 0) {
		/* we cannot handle this key */
		debug3_f("cannot handle key");
		গচ্ছ out;
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
	প্রত্যাগম sent;
}

স্থির সংরচনা sshkey *
load_identity_file(Identity *id)
{
	সংরচনা sshkey *গুপ্ত = রিক্ত;
	বর্ণ prompt[300], *passphrase, *comment;
	পূর্ণাঙ্ক r, quit = 0, i;
	সংরচনা stat st;

	যদি (stat(id->filename, &st) == -1) {
		do_log2(id->userprovided ?
		    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_DEBUG3,
		    "no such identity: %s: %s", id->filename, strerror(errno));
		প্রত্যাগম রিক্ত;
	}
	snprintf(prompt, পরিমাণ prompt,
	    "Enter passphrase for key '%.100s': ", id->filename);
	প্রতি (i = 0; i <= options.সংখ্যা_of_password_prompts; i++) {
		যদি (i == 0)
			passphrase = "";
		অন্যথা {
			passphrase = read_passphrase(prompt, 0);
			যদি (*passphrase == '\0') {
				debug2("no passphrase given, try next key");
				মুক্ত(passphrase);
				ভঙ্গ;
			}
		}
		বিকল্প ((r = sshkey_load_private_type(চাবি_UNSPEC, id->filename,
		    passphrase, &গুপ্ত, &comment))) {
		পক্ষ 0:
			ভঙ্গ;
		পক্ষ SSH_ERR_চাবি_WRONG_PASSPHRASE:
			যদি (options.batch_mode) {
				quit = 1;
				ভঙ্গ;
			}
			যদি (i != 0)
				debug2("bad passphrase given, try again...");
			ভঙ্গ;
		পক্ষ SSH_ERR_SYSTEM_ERROR:
			যদি (errno == ENOENT) {
				debug2_r(r, "Load key \"%s\"", id->filename);
				quit = 1;
				ভঙ্গ;
			}
			/* FALLTHROUGH */
		স্বভাব:
			error_r(r, "Load key \"%s\"", id->filename);
			quit = 1;
			ভঙ্গ;
		}
		যদি (গুপ্ত != রিক্ত && sshkey_is_sk(গুপ্ত) &&
		    options.sk_provider == রিক্ত) {
			debug("key \"%s\" is an authenticator-hosted key, "
			    "but no provider specified", id->filename);
			sshkey_free(গুপ্ত);
			গুপ্ত = রিক্ত;
			quit = 1;
		}
		যদি (!quit && (r = sshkey_check_rsa_length(গুপ্ত,
		    options.required_rsa_size)) != 0) {
			debug_fr(r, "Skipping key %s", id->filename);
			sshkey_free(গুপ্ত);
			গুপ্ত = রিক্ত;
			quit = 1;
		}
		যদি (!quit && গুপ্ত != রিক্ত && id->agent_fd == -1 &&
		    !(id->চাবি && id->isprivate))
			maybe_add_চাবি_to_agent(id->filename, গুপ্ত, comment,
			    passphrase);
		যদি (i > 0)
			freezero(passphrase, strlen(passphrase));
		মুক্ত(comment);
		যদি (গুপ্ত != রিক্ত || quit)
			ভঙ্গ;
	}
	প্রত্যাগম গুপ্ত;
}

স্থির পূর্ণাঙ্ক
চাবি_type_allowed(সংরচনা sshkey *চাবি, ধ্রুব বর্ণ *allowlist)
{
	যদি (match_pattern_list(sshkey_ssh_name(চাবি), allowlist, 0) == 1)
		প্রত্যাগম 1;

	/* RSA keys/certs might be allowed by alternate signature types */
	বিকল্প (চাবি->type) {
	পক্ষ চাবি_RSA:
		যদি (match_pattern_list("rsa-sha2-512", allowlist, 0) == 1)
			প্রত্যাগম 1;
		যদি (match_pattern_list("rsa-sha2-256", allowlist, 0) == 1)
			প্রত্যাগম 1;
		ভঙ্গ;
	পক্ষ চাবি_RSA_CERT:
		যদি (match_pattern_list("rsa-sha2-512-cert-v01@openssh.com",
		    allowlist, 0) == 1)
			প্রত্যাগম 1;
		যদি (match_pattern_list("rsa-sha2-256-cert-v01@openssh.com",
		    allowlist, 0) == 1)
			প্রত্যাগম 1;
		ভঙ্গ;
	}
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
চাবি_type_allowed_by_config(সংরচনা sshkey *চাবি)
{
	প্রত্যাগম চাবি_type_allowed(চাবি, options.pubkey_accepted_algos);
}

/* obtain a list of keys from the agent */
স্থির পূর্ণাঙ্ক
get_agent_identities(সংরচনা ssh *ssh, পূর্ণাঙ্ক *agent_fdp,
    সংরচনা ssh_identitylist **idlistp)
{
	পূর্ণাঙ্ক r, agent_fd;
	সংরচনা ssh_identitylist *idlist;

	যদি ((r = ssh_get_authentication_socket(&agent_fd)) != 0) {
		যদি (r != SSH_ERR_AGENT_NOT_PRESENT)
			debug_fr(r, "ssh_get_authentication_socket");
		প্রত্যাগম r;
	}
	যদি (ssh != রিক্ত && ssh->kex != রিক্ত) {
		যদি ((r = ssh_agent_bind_hostkey(agent_fd, ssh->kex->initial_hostkey,
		    ssh->kex->session_id, ssh->kex->initial_sig, 0)) == 0)
			debug_f("bound agent to hostkey");
		অন্যথা
			debug2_fr(r, "ssh_agent_bind_hostkey");
	}

	যদি ((r = ssh_fetch_identitylist(agent_fd, &idlist)) != 0) {
		debug_fr(r, "ssh_fetch_identitylist");
		close(agent_fd);
		প্রত্যাগম r;
	}
	/* success */
	*agent_fdp = agent_fd;
	*idlistp = idlist;
	debug_f("agent returned %zu keys", idlist->nkeys);
	প্রত্যাগম 0;
}

/*
 * Returns nonzero if the certificate extensions/critical-options section
 * has the specified option present, zero otherwise.
 */
স্থির পূর্ণাঙ্ক
cert_has_option(সংরচনা sshbuf *oblob, ধ্রুব বর্ণ *target)
{
	সংরচনা sshbuf *c = রিক্ত, *data = রিক্ত;
	বর্ণ *name = রিক্ত;
	পূর্ণাঙ্ক r, found = 0;

	যদি (oblob == রিক্ত || (c = sshbuf_fromb(oblob)) == রিক্ত)
		প্রত্যাগম 0;
	যাবত্ (sshbuf_len(c) > 0) {
		sshbuf_free(data);
		data = রিক্ত;
		মুক্ত(name);
		name = রিক্ত;
		যদি ((r = sshbuf_get_cstring(c, &name, রিক্ত)) != 0 ||
		    (r = sshbuf_froms(c, &data)) != 0)
			ভঙ্গ;
		যদি (strcmp(name, target) == 0) {
			found = 1;
			ভঙ্গ;
		}
	}
	sshbuf_free(data);
	মুক্ত(name);
	sshbuf_free(c);
	প্রত্যাগম found;
}

/*
 * Returns an integer describing the priority of the identity
 * within its group. Lower numbers are higher priority.
 */
#define MAX_ID_PRIORITY 3
স্থির পূর্ণাঙ্ক
identity_prioritise(সংরচনা identity *id)
{
	যদি (id == রিক্ত || id->চাবি == রিক্ত)
		প্রত্যাগম 3;
	যদি (!sshkey_is_cert(id->চাবি) || id->চাবি->cert == রিক্ত)
		প্রত্যাগম 3;
	যদি (sshkey_is_sk(id->চাবি) &&
	    cert_has_option(id->চাবি->cert->critical, "verify-required"))
		প্রত্যাগম 2;
	যদি (sshkey_is_sk(id->চাবি) &&
	    cert_has_option(id->চাবি->cert->extensions, "no-touch-required"))
		প্রত্যাগম 0;
	প্রত্যাগম 1;
}

স্থির শূন্য
order_identities_by_prio(সংরচনা idlist *list)
{
	সংরচনা idlist prio[MAX_ID_PRIORITY + 1], sorted;
	সংরচনা identity *id, *tmp, *dummy;
	পূর্ণাঙ্ক p;

	প্রতি (p = 0; p <= MAX_ID_PRIORITY; p++)
		TAILQ_INIT(&prio[p]);
	TAILQ_INIT(&sorted);

	TAILQ_FOREACH_SAFE(id, list, next, tmp) {
		যদি (id->userprovided)
			অনুবর্ত;
		dummy = xcalloc(1, পরিমাণ(*dummy));
		dummy->userprovided = -1;
		TAILQ_INSERT_BEFORE(id, dummy, next);
		TAILQ_REMOVE(list, id, next);
		p = identity_prioritise(id);
		যদি (p < 0 || p > MAX_ID_PRIORITY)
			fatal_f("internal error: bad priority");
		TAILQ_INSERT_TAIL(&prio[p], id, next);
	}
	প্রতি (p = 0; p <= MAX_ID_PRIORITY; p++)
		TAILQ_CONCAT(&sorted, &prio[p], next);

	TAILQ_FOREACH_SAFE(id, list, next, tmp) {
		যদি (id->userprovided != -1)
			অনুবর্ত;
		সংরচনা identity *s = TAILQ_FIRST(&sorted);
		TAILQ_REMOVE(&sorted, s, next);
		TAILQ_INSERT_BEFORE(id, s, next);
		TAILQ_REMOVE(list, id, next);
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
pubkey_prepare(সংরচনা ssh *ssh, Authctxt *authctxt)
{
	সংরচনা identity *id, *id2, *tmp;
	সংরচনা idlist agent, files, certs, agent_চাবিগুলি, *preferred;
	সংরচনা sshkey *চাবি;
	পূর্ণাঙ্ক disallowed, agent_fd = -1, i, r, found;
	size_t j;
	সংরচনা ssh_identitylist *idlist;
	বর্ণ *cp, *ident;

	TAILQ_INIT(&agent);	/* keys from the agent */
	TAILQ_INIT(&files);	/* keys from the config file */
	TAILQ_INIT(&certs);	/* certificates specified by user */
	TAILQ_INIT(&agent_চাবিগুলি); /* keys supported by the agent */
	preferred = &authctxt->চাবিগুলি;
	TAILQ_INIT(preferred);	/* preferred order of keys */

	/* list of keys stored in the filesystem and PKCS#11 */
	প্রতি (i = 0; i < options.অঙ্ক_identity_files; i++) {
		চাবি = options.identity_চাবিগুলি[i];
		যদি (চাবি && চাবি->cert &&
		    চাবি->cert->type != SSH2_CERT_TYPE_USER) {
			debug_f("ignoring certificate %s: not a user "
			    "certificate", options.identity_files[i]);
			অনুবর্ত;
		}
		যদি (চাবি && sshkey_is_sk(চাবি) && options.sk_provider == রিক্ত) {
			debug_f("ignoring authenticator-hosted key %s as no "
			    "SecurityKeyProvider has been specified",
			    options.identity_files[i]);
			অনুবর্ত;
		}
		options.identity_চাবিগুলি[i] = রিক্ত;
		id = xcalloc(1, পরিমাণ(*id));
		id->agent_fd = -1;
		id->চাবি = চাবি;
		id->filename = xstrdup(options.identity_files[i]);
		id->userprovided = options.identity_file_userprovided[i];
		TAILQ_INSERT_TAIL(&files, id, next);
	}

	/* list of certificates specified by user */
	প্রতি (i = 0; i < options.অঙ্ক_certificate_files; i++) {
		চাবি = options.certificates[i];
		যদি (!sshkey_is_cert(চাবি) || চাবি->cert == রিক্ত ||
		    চাবি->cert->type != SSH2_CERT_TYPE_USER) {
			debug_f("ignoring certificate %s: not a user "
			    "certificate", options.identity_files[i]);
			অনুবর্ত;
		}
		যদি (চাবি && sshkey_is_sk(চাবি) && options.sk_provider == রিক্ত) {
			debug_f("ignoring authenticator-hosted key "
			    "certificate %s as no "
			    "SecurityKeyProvider has been specified",
			    options.identity_files[i]);
			অনুবর্ত;
		}
		id = xcalloc(1, পরিমাণ(*id));
		id->agent_fd = -1;
		id->চাবি = চাবি;
		id->filename = xstrdup(options.certificate_files[i]);
		id->userprovided = options.certificate_file_userprovided[i];
		TAILQ_INSERT_TAIL(&certs, id, next);
	}
	order_identities_by_prio(&certs);
	TAILQ_CONCAT(preferred, &certs, next);

	/* list of keys supported by the agent */
	যদি ((r = get_agent_identities(ssh, &agent_fd, &idlist)) == 0) {
		প্রতি (j = 0; j < idlist->nkeys; j++) {
			যদি ((r = sshkey_check_rsa_length(idlist->চাবিগুলি[j],
			    options.required_rsa_size)) != 0) {
				debug_fr(r, "ignoring %s agent key",
				    sshkey_ssh_name(idlist->চাবিগুলি[j]));
				অনুবর্ত;
			}
			found = 0;
			TAILQ_FOREACH(id, &files, next) {
				/*
				 * agent keys from the config file are
				 * preferred
				 */
				যদি (sshkey_equal(idlist->চাবিগুলি[j], id->চাবি)) {
					TAILQ_REMOVE(&files, id, next);
					TAILQ_INSERT_TAIL(&agent_চাবিগুলি, id, next);
					id->agent_fd = agent_fd;
					found = 1;
					ভঙ্গ;
				}
			}
			যদি (!found && !options.identities_only) {
				id = xcalloc(1, পরিমাণ(*id));
				/* XXX "steals" key/comment from idlist */
				id->চাবি = idlist->চাবিগুলি[j];
				id->filename = idlist->comments[j];
				idlist->চাবিগুলি[j] = রিক্ত;
				idlist->comments[j] = রিক্ত;
				id->agent_fd = agent_fd;
				TAILQ_INSERT_TAIL(&agent, id, next);
			}
		}
		ssh_free_identitylist(idlist);
		/* append remaining agent keys */
		TAILQ_CONCAT(&agent_চাবিগুলি, &agent, next);
		order_identities_by_prio(&agent_চাবিগুলি);
		TAILQ_CONCAT(preferred, &agent_চাবিগুলি, next);
		authctxt->agent_fd = agent_fd;
	}
	/* Prefer PKCS11 keys that are explicitly listed */
	TAILQ_FOREACH_SAFE(id, &files, next, tmp) {
		যদি (id->চাবি == রিক্ত || (id->চাবি->flags & SSHKEY_FLAG_EXT) == 0)
			অনুবর্ত;
		found = 0;
		TAILQ_FOREACH(id2, &files, next) {
			যদি (id2->চাবি == রিক্ত ||
			    (id2->চাবি->flags & SSHKEY_FLAG_EXT) != 0)
				অনুবর্ত;
			যদি (sshkey_equal(id->চাবি, id2->চাবি)) {
				TAILQ_REMOVE(&files, id, next);
				TAILQ_INSERT_TAIL(preferred, id, next);
				found = 1;
				ভঙ্গ;
			}
		}
		/* If IdentitiesOnly set and key not found then don't use it */
		যদি (!found && options.identities_only) {
			TAILQ_REMOVE(&files, id, next);
			freezero(id, পরিমাণ(*id));
		}
	}
	order_identities_by_prio(&files);
	/* append remaining keys from the config file */
	TAILQ_CONCAT(preferred, &files, next);
	/* finally, filter by PubkeyAcceptedAlgorithms */
	TAILQ_FOREACH_SAFE(id, preferred, next, id2) {
		disallowed = 0;
		cp = রিক্ত;
		যদি (id->চাবি == রিক্ত)
			অনুবর্ত;
		যদি (!চাবি_type_allowed_by_config(id->চাবি)) {
			debug("Skipping %s key %s - corresponding algorithm "
			    "not in PubkeyAcceptedAlgorithms",
			    sshkey_ssh_name(id->চাবি), id->filename);
			disallowed = 1;
		} অন্যথা যদি (ssh != রিক্ত && ssh->kex != রিক্ত &&
		    ssh->kex->server_sig_algs != রিক্ত &&
		    (cp = চাবি_sig_algorithm(ssh, id->চাবি)) == রিক্ত) {
			debug("Skipping %s key %s - corresponding algorithm "
			    "not supported by server",
			    sshkey_ssh_name(id->চাবি), id->filename);
			disallowed = 1;
		}
		মুক্ত(cp);
		যদি (!disallowed)
			অনুবর্ত;
		/* remove key */
		TAILQ_REMOVE(preferred, id, next);
		sshkey_free(id->চাবি);
		মুক্ত(id->filename);
		freezero(id, পরিমাণ(*id));
	}
	/* List the keys we plan on using */
	TAILQ_FOREACH_SAFE(id, preferred, next, id2) {
		ident = format_identity(id);
		debug("Will attempt key: %s", ident);
		মুক্ত(ident);
	}
	debug2_f("done");
}

স্থির শূন্য
pubkey_cleanup(সংরচনা ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Identity *id;

	যদি (authctxt->agent_fd != -1) {
		ssh_close_authentication_socket(authctxt->agent_fd);
		authctxt->agent_fd = -1;
	}
	প্রতি (id = TAILQ_FIRST(&authctxt->চাবিগুলি); id;
	    id = TAILQ_FIRST(&authctxt->চাবিগুলি)) {
		TAILQ_REMOVE(&authctxt->চাবিগুলি, id, next);
		sshkey_free(id->চাবি);
		মুক্ত(id->filename);
		মুক্ত(id);
	}
}

শূন্য
pubkey_dump(সংরচনা ssh *ssh)
{
	Authctxt authctxt;
	Identity *id;
	বর্ণ *ident;

	memset(&authctxt, 0, পরিমাণ(authctxt));
	authctxt.agent_fd = -1;
	ssh->authctxt = &authctxt;

	pubkey_prepare(ssh, &authctxt);
	TAILQ_FOREACH(id, &authctxt.চাবিগুলি, next) {
		ident = format_identity(id);
		fprintf(stdout, "%s\n", ident);
		মুক্ত(ident);
	}
	pubkey_cleanup(ssh);
	ssh->authctxt = রিক্ত;
}

স্থির শূন্য
pubkey_reset(Authctxt *authctxt)
{
	Identity *id;

	TAILQ_FOREACH(id, &authctxt->চাবিগুলি, next)
		id->tried = 0;
}

স্থির পূর্ণাঙ্ক
userauth_pubkey(সংরচনা ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Identity *id;
	পূর্ণাঙ্ক sent = 0;
	বর্ণ *ident;
	স্থির পূর্ণাঙ্ক prepared;

	যদি (!prepared) {
		pubkey_prepare(ssh, authctxt);
		prepared = 1;
	}

	যাবত্ ((id = TAILQ_FIRST(&authctxt->চাবিগুলি))) {
		যদি (id->tried++)
			প্রত্যাগম (0);
		/* move key to the end of the queue */
		TAILQ_REMOVE(&authctxt->চাবিগুলি, id, next);
		TAILQ_INSERT_TAIL(&authctxt->চাবিগুলি, id, next);
		/*
		 * send a test message if we have the public key. for
		 * encrypted keys we cannot do this and have to load the
		 * private key instead
		 */
		যদি (id->চাবি != রিক্ত) {
			ident = format_identity(id);
			debug("Offering public key: %s", ident);
			মুক্ত(ident);
			sent = send_pubkey_test(ssh, id);
		} অন্যথা {
			debug("Trying private key: %s", id->filename);
			id->চাবি = load_identity_file(id);
			যদি (id->চাবি != রিক্ত) {
				id->isprivate = 1;
				sent = sign_and_send_pubkey(ssh, id);
				sshkey_free(id->চাবি);
				id->চাবি = রিক্ত;
				id->isprivate = 0;
			}
		}
		যদি (sent)
			প্রত্যাগম (sent);
	}
	প্রত্যাগম (0);
}

/*
 * Send userauth request message specifying keyboard-interactive method.
 */
স্থির পূর্ণাঙ্ক
userauth_kbdint(সংরচনা ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	পূর্ণাঙ্ক r;

	যদি (authctxt->attempt_kbdint++ >= options.সংখ্যা_of_password_prompts)
		প্রত্যাগম 0;
	/* disable if no SSH2_MSG_USERAUTH_INFO_REQUEST has been seen */
	যদি (authctxt->attempt_kbdint > 1 && !authctxt->info_req_seen) {
		debug3("userauth_kbdint: disable: no info_req_seen");
		ssh_dispatch_set(ssh, SSH2_বার্তা_USERAUTH_INFO_REQUEST, রিক্ত);
		প্রত্যাগম 0;
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
	প্রত্যাগম 1;
}

/*
 * parse INFO_REQUEST, prompt user and send INFO_RESPONSE
 */
স্থির পূর্ণাঙ্ক
প্রবেশ_userauth_info_req(পূর্ণাঙ্ক type, uint32_t seq, সংরচনা ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	বর্ণ *name = রিক্ত, *inst = রিক্ত, *lang = রিক্ত, *prompt = রিক্ত;
	বর্ণ *display_prompt = রিক্ত, *response = রিক্ত;
	u_char echo = 0;
	u_int অঙ্ক_prompts, i;
	পূর্ণাঙ্ক r, addnl;
	size_t len;

	debug2_f("entering");

	যদি (authctxt == রিক্ত)
		fatal_f("no authentication context");

	authctxt->info_req_seen = 1;

	যদি ((r = sshpkt_get_cstring(ssh, &name, রিক্ত)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &inst, রিক্ত)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, রিক্ত)) != 0)
		গচ্ছ out;
	যদি ((len = strlen(name)) > 0) {
		addnl = name[len] != '\n';
		fmprintf(stderr, "%s%s", name, addnl ? "\n" : "");
	}
	যদি ((len = strlen(inst)) > 0) {
		addnl = inst[len] != '\n';
		fmprintf(stderr, "%s%s", inst, addnl ? "\n" : "");
	}

	যদি ((r = sshpkt_get_u32(ssh, &অঙ্ক_prompts)) != 0)
		গচ্ছ out;
	/*
	 * Begin to build info response packet based on prompts requested.
	 * We commit to providing the correct number of responses, so if
	 * further on we run into a problem that prevents this, we have to
	 * be sure and clean this up and send a correct error response.
	 */
	যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_USERAUTH_INFO_RESPONSE)) != 0 ||
	    (r = sshpkt_put_u32(ssh, অঙ্ক_prompts)) != 0)
		গচ্ছ out;

	debug2_f("num_prompts %d", অঙ্ক_prompts);
	প্রতি (i = 0; i < অঙ্ক_prompts; i++) {
		যদি ((r = sshpkt_get_cstring(ssh, &prompt, রিক্ত)) != 0 ||
		    (r = sshpkt_get_u8(ssh, &echo)) != 0)
			গচ্ছ out;
		যদি (asmprintf(&display_prompt, INT_MAX, রিক্ত, "(%s@%s) %s",
		    authctxt->server_user, options.host_চাবি_alias ?
		    options.host_চাবি_alias : authctxt->host, prompt) == -1)
			fatal_f("asmprintf failed");
		response = read_passphrase(display_prompt, echo ? RP_ECHO : 0);
		যদি ((r = sshpkt_put_cstring(ssh, response)) != 0)
			গচ্ছ out;
		freezero(response, strlen(response));
		মুক্ত(prompt);
		মুক্ত(display_prompt);
		display_prompt = response = prompt = রিক্ত;
	}
	/* done with parsing incoming message. */
	যদি ((r = sshpkt_get_end(ssh)) != 0 ||
	    (r = sshpkt_add_padding(ssh, 64)) != 0)
		গচ্ছ out;
	r = sshpkt_send(ssh);
 out:
	যদি (response)
		freezero(response, strlen(response));
	মুক্ত(prompt);
	মুক্ত(display_prompt);
	মুক্ত(name);
	মুক্ত(inst);
	মুক্ত(lang);
	প্রত্যাগম r;
}

স্থির পূর্ণাঙ্ক
ssh_keysign(সংরচনা ssh *ssh, সংরচনা sshkey *চাবি, u_char **sigp, size_t *lenp,
    ধ্রুব u_char *data, size_t datalen)
{
	সংরচনা sshbuf *b;
	সংরচনা stat st;
	pid_t pid;
	পূর্ণাঙ্ক r, to[2], from[2], status;
	পূর্ণাঙ্ক sock = ssh_packet_get_connection_in(ssh);
	u_char rversion = 0, version = 2;
	শূন্য (*osigchld)(পূর্ণাঙ্ক);

	*sigp = রিক্ত;
	*lenp = 0;

	যদি (stat(PATH_SSH_চাবি_SIGN, &st) == -1) {
		error_f("not installed: %s", strerror(errno));
		প্রত্যাগম -1;
	}
	যদি (fflush(stdout) != 0) {
		error_f("fflush: %s", strerror(errno));
		প্রত্যাগম -1;
	}
	যদি (pipe(to) == -1) {
		error_f("pipe: %s", strerror(errno));
		প্রত্যাগম -1;
	}
	যদি (pipe(from) == -1) {
		error_f("pipe: %s", strerror(errno));
		প্রত্যাগম -1;
	}
	যদি ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		প্রত্যাগম -1;
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
		execl(PATH_SSH_চাবি_SIGN, PATH_SSH_চাবি_SIGN, (বর্ণ *)রিক্ত);
		fatal_f("exec(%s): %s", PATH_SSH_চাবি_SIGN,
		    strerror(errno));
	}
	close(from[1]);
	close(to[0]);
	sock = STDERR_FILENO + 1;

	যদি ((b = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	/* send # of sock, data to be signed */
	যদি ((r = sshbuf_put_u32(b, sock)) != 0 ||
	    (r = sshbuf_put_string(b, data, datalen)) != 0)
		fatal_fr(r, "buffer error");
	যদি (ssh_বার্তা_send(to[1], version, b) == -1)
		fatal_f("couldn't send request");
	sshbuf_reset(b);
	r = ssh_বার্তা_recv(from[0], b);
	close(from[0]);
	close(to[1]);
	যদি (r < 0) {
		error_f("no reply");
		গচ্ছ fail;
	}

	errno = 0;
	যাবত্ (waitpid(pid, &status, 0) == -1) {
		যদি (errno != EINTR) {
			error_f("waitpid %ld: %s", (long)pid, strerror(errno));
			গচ্ছ fail;
		}
	}
	যদি (!WIFEXITED(status)) {
		error_f("exited abnormally");
		গচ্ছ fail;
	}
	যদি (WEXITSTATUS(status) != 0) {
		error_f("exited with status %d", WEXITSTATUS(status));
		গচ্ছ fail;
	}
	যদি ((r = sshbuf_get_u8(b, &rversion)) != 0) {
		error_fr(r, "buffer error");
		গচ্ছ fail;
	}
	যদি (rversion != version) {
		error_f("bad version");
		গচ্ছ fail;
	}
	যদি ((r = sshbuf_get_string(b, sigp, lenp)) != 0) {
		error_fr(r, "buffer error");
 fail:
		ssh_signal(SIGCHLD, osigchld);
		sshbuf_free(b);
		প্রত্যাগম -1;
	}
	ssh_signal(SIGCHLD, osigchld);
	sshbuf_free(b);

	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
userauth_hostbased(সংরচনা ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	সংরচনা sshkey *গুপ্ত = রিক্ত;
	সংরচনা sshbuf *b = রিক্ত;
	u_char *sig = রিক্ত, *keyblob = রিক্ত;
	বর্ণ *fp = রিক্ত, *chost = রিক্ত, *lname = রিক্ত;
	size_t siglen = 0, keylen = 0;
	পূর্ণাঙ্ক i, r, success = 0;

	যদি (authctxt->ktypes == রিক্ত) {
		authctxt->oktypes = xstrdup(options.hostbased_accepted_algos);
		authctxt->ktypes = authctxt->oktypes;
	}

	/*
	 * Work through each listed type pattern in HostbasedAcceptedAlgorithms,
	 * trying each hostkey that matches the type in turn.
	 */
	প্রতি (;;) {
		যদি (authctxt->active_ktype == রিক্ত)
			authctxt->active_ktype = strsep(&authctxt->ktypes, ",");
		যদি (authctxt->active_ktype == রিক্ত ||
		    *authctxt->active_ktype == '\0')
			ভঙ্গ;
		debug3_f("trying key type %s", authctxt->active_ktype);

		/* check for a useful key */
		গুপ্ত = রিক্ত;
		প্রতি (i = 0; i < authctxt->sensitive->nkeys; i++) {
			যদি (authctxt->sensitive->চাবিগুলি[i] == রিক্ত ||
			    authctxt->sensitive->চাবিগুলি[i]->type == চাবি_UNSPEC)
				অনুবর্ত;
			যদি (!sshkey_match_keyname_to_sigalgs(
			    sshkey_ssh_name(authctxt->sensitive->চাবিগুলি[i]),
			    authctxt->active_ktype))
				অনুবর্ত;
			/* we take and free the key */
			গুপ্ত = authctxt->sensitive->চাবিগুলি[i];
			authctxt->sensitive->চাবিগুলি[i] = রিক্ত;
			ভঙ্গ;
		}
		/* Found one */
		যদি (গুপ্ত != রিক্ত)
			ভঙ্গ;
		/* No more keys of this type; advance */
		authctxt->active_ktype = রিক্ত;
	}
	যদি (গুপ্ত == রিক্ত) {
		মুক্ত(authctxt->oktypes);
		authctxt->oktypes = authctxt->ktypes = রিক্ত;
		authctxt->active_ktype = রিক্ত;
		debug("No more client hostkeys for hostbased authentication.");
		গচ্ছ out;
	}

	যদি ((fp = sshkey_fingerprint(গুপ্ত, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == রিক্ত) {
		error_f("sshkey_fingerprint failed");
		গচ্ছ out;
	}
	debug_f("trying hostkey %s %s using sigalg %s",
	    sshkey_ssh_name(গুপ্ত), fp, authctxt->active_ktype);

	/* figure out a name for the client host */
	lname = get_local_name(ssh_packet_get_connection_in(ssh));
	যদি (lname == রিক্ত) {
		error_f("cannot get local ipaddr/name");
		গচ্ছ out;
	}

	/* XXX sshbuf_put_stringf? */
	xasprintf(&chost, "%s.", lname);
	debug2_f("chost %s", chost);

	/* construct data */
	যদি ((b = sshbuf_new()) == রিক্ত) {
		error_f("sshbuf_new failed");
		গচ্ছ out;
	}
	যদি ((r = sshkey_to_blob(গুপ্ত, &keyblob, &keylen)) != 0) {
		error_fr(r, "sshkey_to_blob");
		গচ্ছ out;
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
		গচ্ছ out;
	}

#ifdef DEBUG_PK
	sshbuf_dump(b, stderr);
#endif
	যদি ((r = ssh_keysign(ssh, গুপ্ত, &sig, &siglen,
	    sshbuf_ptr(b), sshbuf_len(b))) != 0) {
		error("sign using hostkey %s %s failed",
		    sshkey_ssh_name(গুপ্ত), fp);
		গচ্ছ out;
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
		গচ্ছ out;
	}
	success = 1;

 out:
	যদি (sig != রিক্ত)
		freezero(sig, siglen);
	মুক্ত(keyblob);
	মুক্ত(lname);
	মুক্ত(fp);
	মুক্ত(chost);
	sshkey_free(গুপ্ত);
	sshbuf_free(b);

	প্রত্যাগম success;
}

/* find auth method */

/*
 * given auth method name, if configurable options permit this method fill
 * in auth_ident field and return true, otherwise return false.
 */
স্থির পূর্ণাঙ্ক
authmethod_is_enabled(Authmethod *method)
{
	যদি (method == রিক্ত)
		প্রত্যাগম 0;
	/* return false if options indicate this method is disabled */
	যদি  (method->enabled == রিক্ত || *method->enabled == 0)
		প্রত্যাগম 0;
	/* return false if batch mode is enabled but method needs interactive mode */
	যদি  (method->batch_flag != রিক্ত && *method->batch_flag != 0)
		প্রত্যাগম 0;
	প্রত্যাগম 1;
}

স্থির Authmethod *
authmethod_lookup(ধ্রুব বর্ণ *name)
{
	Authmethod *method = রিক্ত;
	যদি (name != রিক্ত)
		প্রতি (method = authmethods; method->name != রিক্ত; method++)
			যদি (strcmp(name, method->name) == 0)
				প্রত্যাগম method;
	debug2("Unrecognized authentication method name: %s", name ? name : "NULL");
	প্রত্যাগম রিক্ত;
}

/* XXX internal state */
স্থির Authmethod *current = রিক্ত;
স্থির বর্ণ *supported = রিক্ত;
স্থির বর্ণ *preferred = রিক্ত;

/*
 * Given the authentication method list sent by the server, return the
 * next method we should try.  If the server initially sends a nil list,
 * use a built-in default list.
 */
স্থির Authmethod *
authmethod_get(বর্ণ *authlist)
{
	বর্ণ *name = রিক্ত;
	u_int next;

	/* Use a suitable default if we're passed a nil list.  */
	যদি (authlist == রিক্ত || strlen(authlist) == 0)
		authlist = options.preferred_authentications;

	যদি (supported == রিক্ত || strcmp(authlist, supported) != 0) {
		debug3("start over, passed a different list %s", authlist);
		মুক্ত(supported);
		supported = xstrdup(authlist);
		preferred = options.preferred_authentications;
		debug3("preferred %s", preferred);
		current = রিক্ত;
	} অন্যথা যদি (current != রিক্ত && authmethod_is_enabled(current))
		প্রত্যাগম current;

	প্রতি (;;) {
		যদি ((name = match_list(preferred, supported, &next)) == রিক্ত) {
			debug("No more authentication methods to try.");
			current = রিক্ত;
			প্রত্যাগম রিক্ত;
		}
		preferred += next;
		debug3("authmethod_lookup %s", name);
		debug3("remaining preferred: %s", preferred);
		যদি ((current = authmethod_lookup(name)) != রিক্ত &&
		    authmethod_is_enabled(current)) {
			debug3("authmethod_is_enabled %s", name);
			debug("Next authentication method: %s", name);
			মুক্ত(name);
			প্রত্যাগম current;
		}
		মুক্ত(name);
	}
}

স্থির বর্ণ *
authmethods_get(শূন্য)
{
	Authmethod *method = রিক্ত;
	সংরচনা sshbuf *b;
	বর্ণ *list;
	পূর্ণাঙ্ক r;

	যদি ((b = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	প্রতি (method = authmethods; method->name != রিক্ত; method++) {
		যদি (authmethod_is_enabled(method)) {
			যদি ((r = sshbuf_putf(b, "%s%s",
			    sshbuf_len(b) ? "," : "", method->name)) != 0)
				fatal_fr(r, "buffer error");
		}
	}
	যদি ((list = sshbuf_dup_string(b)) == রিক্ত)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	প্রত্যাগম list;
}
