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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <sys/wait.h>
#अन्तर्भाव <sys/queue.h>
#अन्तर्भाव <sys/stat.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <limits.h>
#अन्तर्भाव <pwd.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <unistd.h>
#जर defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
#अन्तर्भाव <vis.h>
#endif

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "ssh.h"
#अन्तर्भाव "ssh2.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "packet.h"
#अन्तर्भाव "compat.h"
#अन्तर्भाव "cipher.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "kex.h"
#अन्तर्भाव "sshconnect.h"
#अन्तर्भाव "authfile.h"
#अन्तर्भाव "authfd.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "readconf.h"
#अन्तर्भाव "match.h"
#अन्तर्भाव "dispatch.h"
#अन्तर्भाव "canohost.h"
#अन्तर्भाव "msg.h"
#अन्तर्भाव "pathnames.h"
#अन्तर्भाव "hostfile.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "utf8.h"
#अन्तर्भाव "ssh-sk.h"
#अन्तर्भाव "sk-api.h"

#ifdef GSSAPI
#अन्तर्भाव "ssh-gss.h"
#endif

/* import */
बाह्य Options options;

/*
 * SSH2 key exchange
 */

स्थिर अक्षर *xxx_host;
स्थिर संरचना sockaddr_storage xxx_hostaddr;
स्थिर स्थिरांक संरचना ssh_conn_info *xxx_conn_info;
स्थिर पूर्णांक किल्ली_type_allowed(संरचना sshkey *, स्थिरांक अक्षर *);

स्थिर पूर्णांक
verify_host_किल्ली_callback(संरचना sshkey *hostkey, संरचना ssh *ssh)
{
	पूर्णांक r;

	जर ((r = sshkey_check_rsa_length(hostkey,
	    options.required_rsa_size)) != 0)
		fatal_r(r, "Bad server host key");
	जर (!किल्ली_type_allowed(hostkey, options.hostkeyalgorithms)) {
		fatal("Server host key %s not in HostKeyAlgorithms",
		    sshkey_ssh_name(hostkey));
	}
	जर (verify_host_किल्ली(xxx_host, (संरचना sockaddr *)&xxx_hostaddr, hostkey,
	    xxx_conn_info) != 0)
		fatal("Host key verification failed.");
	परत 0;
}

/* Returns the first item from a comma-separated algorithm list */
स्थिर अक्षर *
first_alg(स्थिरांक अक्षर *algs)
{
	अक्षर *ret, *cp;

	ret = xstrdup(algs);
	जर ((cp = म_अक्षर(ret, ',')) != रिक्त)
		*cp = '\0';
	परत ret;
}

स्थिर अक्षर *
order_hostkeyalgs(अक्षर *host, संरचना sockaddr *hostaddr, u_short port,
    स्थिरांक संरचना ssh_conn_info *cinfo)
{
	अक्षर *oavail = रिक्त, *avail = रिक्त, *first = रिक्त, *last = रिक्त;
	अक्षर *alg = रिक्त, *hostname = रिक्त, *ret = रिक्त, *best = रिक्त;
	माप_प्रकार maxlen;
	संरचना hostkeys *hostkeys = रिक्त;
	पूर्णांक ktype;
	u_int i;

	/* Find all hostkeys for this hostname */
	get_hostfile_hostname_ipaddr(host, hostaddr, port, &hostname, रिक्त);
	hostkeys = init_hostkeys();
	साठी (i = 0; i < options.अंक_user_hostfiles; i++)
		load_hostkeys(hostkeys, hostname, options.user_hostfiles[i], 0);
	साठी (i = 0; i < options.अंक_system_hostfiles; i++) {
		load_hostkeys(hostkeys, hostname,
		    options.system_hostfiles[i], 0);
	}
	जर (options.known_hosts_command != रिक्त) {
		load_hostkeys_command(hostkeys, options.known_hosts_command,
		    "ORDER", cinfo, रिक्त, hostname);
	}
	/*
	 * If a plain public key exists that matches the type of the best
	 * preference HostkeyAlgorithms, then use the whole list as is.
	 * Note that we ignore whether the best preference algorithm is a
	 * certificate type, as sshconnect.c will downgrade certs to
	 * plain keys if necessary.
	 */
	best = first_alg(options.hostkeyalgorithms);
	जर (lookup_किल्ली_in_hostkeys_by_type(hostkeys,
	    sshkey_type_plain(sshkey_type_from_name(best)),
	    sshkey_ecdsa_nid_from_name(best), रिक्त)) {
		debug3_f("have matching best-preference key type %s, "
		    "using HostkeyAlgorithms verbatim", best);
		ret = xstrdup(options.hostkeyalgorithms);
		जा out;
	}

	/*
	 * Otherwise, prefer the host key algorithms that match known keys
	 * while keeping the ordering of HostkeyAlgorithms as much as possible.
	 */
	oavail = avail = xstrdup(options.hostkeyalgorithms);
	maxlen = म_माप(avail) + 1;
	first = xmalloc(maxlen);
	last = xmalloc(maxlen);
	*first = *last = '\0';

#define ALG_APPEND(to, from) \
	करा { \
		जर (*to != '\0') \
			strlcat(to, ",", maxlen); \
		strlcat(to, from, maxlen); \
	} पर्यंत (0)

	पर्यंत ((alg = strsep(&avail, ",")) && *alg != '\0') {
		जर ((ktype = sshkey_type_from_name(alg)) == किल्ली_UNSPEC)
			fatal_f("unknown alg %s", alg);
		/*
		 * If we have a @cert-authority marker in known_hosts then
		 * prefer all certificate algorithms.
		 */
		जर (sshkey_type_is_cert(ktype) &&
		    lookup_marker_in_hostkeys(hostkeys, MRK_CA)) {
			ALG_APPEND(first, alg);
			सुरूठेवा;
		}
		/* If the key appears in known_hosts then prefer it */
		जर (lookup_किल्ली_in_hostkeys_by_type(hostkeys,
		    sshkey_type_plain(ktype),
		    sshkey_ecdsa_nid_from_name(alg), रिक्त)) {
			ALG_APPEND(first, alg);
			सुरूठेवा;
		}
		/* Otherwise, put it last */
		ALG_APPEND(last, alg);
	}
#undef ALG_APPEND
	xasprintf(&ret, "%s%s%s", first,
	    (*first == '\0' || *last == '\0') ? "" : ",", last);
	जर (*first != '\0')
		debug3_f("prefer hostkeyalgs: %s", first);
	अन्यथा
		debug3_f("no algorithms matched; accept original");
 out:
	मुक्त(best);
	मुक्त(first);
	मुक्त(last);
	मुक्त(hostname);
	मुक्त(oavail);
	free_hostkeys(hostkeys);

	परत ret;
}

शून्य
ssh_kex2(संरचना ssh *ssh, अक्षर *host, संरचना sockaddr_storage *hostaddr,
    u_short port, स्थिरांक संरचना ssh_conn_info *cinfo)
{
	अक्षर *myproposal[PROPOSAL_MAX];
	अक्षर *all_किल्ली, *hkalgs = रिक्त;
	पूर्णांक r, use_known_hosts_order = 0;

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
	जर (options.hostkeyalgorithms == रिक्त ||
	    options.hostkeyalgorithms[0] == '-' ||
	    options.hostkeyalgorithms[0] == '+')
		use_known_hosts_order = 1;

	/* Expand or fill in HostkeyAlgorithms */
	all_किल्ली = sshkey_alg_list(0, 0, 1, ',');
	जर ((r = kex_assemble_names(&options.hostkeyalgorithms,
	    kex_default_pk_alg(), all_किल्ली)) != 0)
		fatal_fr(r, "kex_assemble_namelist");
	मुक्त(all_किल्ली);

	जर (use_known_hosts_order) {
		hkalgs = order_hostkeyalgs(host, (संरचना sockaddr *)hostaddr,
		    port, cinfo);
	}

	kex_proposal_populate_entries(ssh, myproposal,
	    options.kex_algorithms, options.ciphers, options.macs,
	    compression_alg_list(options.compression),
	    hkalgs ? hkalgs : options.hostkeyalgorithms);

	मुक्त(hkalgs);

	/* start key exchange */
	जर ((r = kex_setup(ssh, myproposal)) != 0)
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
	ssh->kex->verify_host_किल्ली=&verify_host_किल्ली_callback;

	ssh_dispatch_run_fatal(ssh, DISPATCH_BLOCK, &ssh->kex->done);
	kex_proposal_free_entries(myproposal);

#ifdef DEBUG_KEXDH
	/* send 1st encrypted/maced/compressed message */
	जर ((r = sshpkt_start(ssh, SSH2_संदेश_IGNORE)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "markus")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send packet");
#endif
}

/*
 * Authenticate user
 */

प्रकारव्याख्या संरचना cauthctxt Authctxt;
प्रकारव्याख्या संरचना cauthmethod Authmethod;
प्रकारव्याख्या संरचना identity Identity;
प्रकारव्याख्या संरचना idlist Idlist;

संरचना identity {
	TAILQ_ENTRY(identity) next;
	पूर्णांक	agent_fd;		/* >=0 if agent supports key */
	संरचना sshkey	*किल्ली;		/* public/private key */
	अक्षर	*filename;		/* comment for agent-only keys */
	पूर्णांक	tried;
	पूर्णांक	isprivate;		/* key points to the private key */
	पूर्णांक	userprovided;
};
TAILQ_HEAD(idlist, identity);

संरचना cauthctxt {
	स्थिरांक अक्षर *server_user;
	स्थिरांक अक्षर *local_user;
	स्थिरांक अक्षर *host;
	स्थिरांक अक्षर *service;
	संरचना cauthmethod *method;
	संक_पूर्ण_प्रकार success;
	अक्षर *authlist;
#ifdef GSSAPI
	/* gssapi */
	gss_OID_set gss_supported_mechs;
	u_int mech_tried;
#endif
	/* pubkey */
	संरचना idlist किल्ल्या;
	पूर्णांक agent_fd;
	/* hostbased */
	Sensitive *sensitive;
	अक्षर *oktypes, *ktypes;
	स्थिरांक अक्षर *active_ktype;
	/* kbd-interactive */
	पूर्णांक info_req_seen;
	पूर्णांक attempt_kbdint;
	/* password */
	पूर्णांक attempt_passwd;
	/* generic */
	शून्य *methoddata;
};

संरचना cauthmethod {
	अक्षर	*name;		/* string to compare against server's list */
	पूर्णांक	(*userauth)(संरचना ssh *ssh);
	शून्य	(*cleanup)(संरचना ssh *ssh);
	पूर्णांक	*enabled;	/* flag in option struct that enables method */
	पूर्णांक	*batch_flag;	/* flag in option struct that disables method */
};

स्थिर पूर्णांक आदान_userauth_service_accept(पूर्णांक, uint32_t, संरचना ssh *);
स्थिर पूर्णांक आदान_userauth_success(पूर्णांक, uint32_t, संरचना ssh *);
स्थिर पूर्णांक आदान_userauth_failure(पूर्णांक, uint32_t, संरचना ssh *);
स्थिर पूर्णांक आदान_userauth_banner(पूर्णांक, uint32_t, संरचना ssh *);
स्थिर पूर्णांक आदान_userauth_error(पूर्णांक, uint32_t, संरचना ssh *);
स्थिर पूर्णांक आदान_userauth_info_req(पूर्णांक, uint32_t, संरचना ssh *);
स्थिर पूर्णांक आदान_userauth_pk_ok(पूर्णांक, uint32_t, संरचना ssh *);
स्थिर पूर्णांक आदान_userauth_passwd_changereq(पूर्णांक, uint32_t, संरचना ssh *);

स्थिर पूर्णांक userauth_none(संरचना ssh *);
स्थिर पूर्णांक userauth_pubkey(संरचना ssh *);
स्थिर पूर्णांक userauth_passwd(संरचना ssh *);
स्थिर पूर्णांक userauth_kbdint(संरचना ssh *);
स्थिर पूर्णांक userauth_hostbased(संरचना ssh *);

#ifdef GSSAPI
स्थिर पूर्णांक userauth_gssapi(संरचना ssh *);
स्थिर शून्य userauth_gssapi_cleanup(संरचना ssh *);
स्थिर पूर्णांक आदान_gssapi_response(पूर्णांक type, uint32_t, संरचना ssh *);
स्थिर पूर्णांक आदान_gssapi_token(पूर्णांक type, uint32_t, संरचना ssh *);
स्थिर पूर्णांक आदान_gssapi_error(पूर्णांक, uint32_t, संरचना ssh *);
स्थिर पूर्णांक आदान_gssapi_errtok(पूर्णांक, uint32_t, संरचना ssh *);
#endif

शून्य	userauth(संरचना ssh *, अक्षर *);

स्थिर शून्य pubkey_cleanup(संरचना ssh *);
स्थिर पूर्णांक sign_and_send_pubkey(संरचना ssh *ssh, Identity *);
स्थिर शून्य pubkey_prepare(संरचना ssh *, Authctxt *);
स्थिर शून्य pubkey_reset(Authctxt *);
स्थिर संरचना sshkey *load_identity_file(Identity *);

स्थिर Authmethod *authmethod_get(अक्षर *authlist);
स्थिर Authmethod *authmethod_lookup(स्थिरांक अक्षर *name);
स्थिर अक्षर *authmethods_get(शून्य);

Authmethod authmethods[] = {
#ifdef GSSAPI
	{"gssapi-with-mic",
		userauth_gssapi,
		userauth_gssapi_cleanup,
		&options.gss_authentication,
		रिक्त},
#endif
	{"hostbased",
		userauth_hostbased,
		रिक्त,
		&options.hostbased_authentication,
		रिक्त},
	{"publickey",
		userauth_pubkey,
		रिक्त,
		&options.pubkey_authentication,
		रिक्त},
	{"keyboard-interactive",
		userauth_kbdint,
		रिक्त,
		&options.kbd_interactive_authentication,
		&options.batch_mode},
	{"password",
		userauth_passwd,
		रिक्त,
		&options.password_authentication,
		&options.batch_mode},
	{"none",
		userauth_none,
		रिक्त,
		रिक्त,
		रिक्त},
	{रिक्त, रिक्त, रिक्त, रिक्त, रिक्त}
};

शून्य
ssh_userauth2(संरचना ssh *ssh, स्थिरांक अक्षर *local_user,
    स्थिरांक अक्षर *server_user, अक्षर *host, Sensitive *sensitive)
{
	Authctxt authctxt;
	पूर्णांक r;

	जर (options.preferred_authentications == रिक्त)
		options.preferred_authentications = authmethods_get();

	/* setup authentication context */
	स_रखो(&authctxt, 0, आकार(authctxt));
	authctxt.server_user = server_user;
	authctxt.local_user = local_user;
	authctxt.host = host;
	authctxt.service = "ssh-connection";		/* service name */
	authctxt.success = 0;
	authctxt.method = authmethod_lookup("none");
	authctxt.authlist = रिक्त;
	authctxt.methoddata = रिक्त;
	authctxt.sensitive = sensitive;
	authctxt.active_ktype = authctxt.oktypes = authctxt.ktypes = रिक्त;
	authctxt.info_req_seen = 0;
	authctxt.attempt_kbdint = 0;
	authctxt.attempt_passwd = 0;
#जर GSSAPI
	authctxt.gss_supported_mechs = रिक्त;
	authctxt.mech_tried = 0;
#endif
	authctxt.agent_fd = -1;
	जर (authctxt.method == रिक्त)
		fatal_f("internal error: cannot send userauth none request");

	जर ((r = sshpkt_start(ssh, SSH2_संदेश_SERVICE_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "ssh-userauth")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh->authctxt = &authctxt;
	ssh_dispatch_init(ssh, &आदान_userauth_error);
	ssh_dispatch_set(ssh, SSH2_संदेश_EXT_INFO, kex_आदान_ext_info);
	ssh_dispatch_set(ssh, SSH2_संदेश_SERVICE_ACCEPT, &आदान_userauth_service_accept);
	ssh_dispatch_run_fatal(ssh, DISPATCH_BLOCK, &authctxt.success);	/* loop until success */
	pubkey_cleanup(ssh);
#ifdef GSSAPI
	जर (authctxt.gss_supported_mechs != रिक्त) {
		u_int ms;

		gss_release_oid_set(&ms, &authctxt.gss_supported_mechs);
		authctxt.gss_supported_mechs = रिक्त;
	}
#endif
	ssh->authctxt = रिक्त;

	ssh_dispatch_range(ssh, SSH2_संदेश_USERAUTH_MIN, SSH2_संदेश_USERAUTH_MAX, रिक्त);

	जर (!authctxt.success)
		fatal("Authentication failed.");
	जर (ssh_packet_connection_is_on_socket(ssh)) {
		verbose("Authenticated to %s ([%s]:%d) using \"%s\".", host,
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    authctxt.method->name);
	} अन्यथा {
		verbose("Authenticated to %s (via proxy) using \"%s\".", host,
		    authctxt.method->name);
	}
}

स्थिर पूर्णांक
आदान_userauth_service_accept(पूर्णांक type, uint32_t seq, संरचना ssh *ssh)
{
	पूर्णांक r;

	जर (ssh_packet_remaining(ssh) > 0) {
		अक्षर *reply;

		जर ((r = sshpkt_get_cstring(ssh, &reply, रिक्त)) != 0)
			जा out;
		debug2("service_accept: %s", reply);
		मुक्त(reply);
	} अन्यथा {
		debug2("buggy server: service_accept w/o service");
	}
	जर ((r = sshpkt_get_end(ssh)) != 0)
		जा out;
	debug("SSH2_MSG_SERVICE_ACCEPT received");

	/* initial userauth request */
	userauth_none(ssh);

	/* accept EXT_INFO at any time during userauth */
	ssh_dispatch_set(ssh, SSH2_संदेश_EXT_INFO, ssh->kex->ext_info_s ?
	    &kex_आदान_ext_info : &आदान_userauth_error);
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_SUCCESS, &आदान_userauth_success);
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_FAILURE, &आदान_userauth_failure);
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_BANNER, &आदान_userauth_banner);
	r = 0;
 out:
	परत r;
}

शून्य
userauth(संरचना ssh *ssh, अक्षर *authlist)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;

	जर (authctxt->method != रिक्त && authctxt->method->cleanup != रिक्त)
		authctxt->method->cleanup(ssh);

	मुक्त(authctxt->methoddata);
	authctxt->methoddata = रिक्त;
	जर (authlist == रिक्त) {
		authlist = authctxt->authlist;
	} अन्यथा {
		मुक्त(authctxt->authlist);
		authctxt->authlist = authlist;
	}
	साठी (;;) {
		Authmethod *method = authmethod_get(authlist);
		जर (method == रिक्त)
			fatal("%s@%s: Permission denied (%s).",
			    authctxt->server_user, authctxt->host, authlist);
		authctxt->method = method;

		/* reset the per method handler */
		ssh_dispatch_range(ssh, SSH2_संदेश_USERAUTH_PER_METHOD_MIN,
		    SSH2_संदेश_USERAUTH_PER_METHOD_MAX, रिक्त);

		/* and try new method */
		जर (method->userauth(ssh) != 0) {
			debug2("we sent a %s packet, wait for reply", method->name);
			थांबा;
		} अन्यथा {
			debug2("we did not send a packet, disable method");
			method->enabled = रिक्त;
		}
	}
}

स्थिर पूर्णांक
आदान_userauth_error(पूर्णांक type, uint32_t seq, संरचना ssh *ssh)
{
	fatal_f("bad message during authentication: type %d", type);
	परत 0;
}

स्थिर पूर्णांक
आदान_userauth_banner(पूर्णांक type, uint32_t seq, संरचना ssh *ssh)
{
	अक्षर *संदेश = रिक्त;
	माप_प्रकार len;
	पूर्णांक r;

	debug3_f("entering");
	जर ((r = sshpkt_get_cstring(ssh, &संदेश, &len)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, रिक्त, रिक्त)) != 0)
		जा out;
	जर (len > 0 && options.log_level >= SYSLOG_LEVEL_INFO)
		fmprintf(मानक_त्रुटि, "%s", संदेश);
	r = 0;
 out:
	मुक्त(संदेश);
	परत r;
}

स्थिर पूर्णांक
आदान_userauth_success(पूर्णांक type, uint32_t seq, संरचना ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	जर (authctxt == रिक्त)
		fatal_f("no authentication context");
	मुक्त(authctxt->authlist);
	authctxt->authlist = रिक्त;
	जर (authctxt->method != रिक्त && authctxt->method->cleanup != रिक्त)
		authctxt->method->cleanup(ssh);
	मुक्त(authctxt->methoddata);
	authctxt->methoddata = रिक्त;
	authctxt->success = 1;			/* break out */
	ssh_dispatch_set(ssh, SSH2_संदेश_EXT_INFO, dispatch_protocol_error);
	परत 0;
}

#जर 0
स्थिर पूर्णांक
आदान_userauth_success_unexpected(पूर्णांक type, uint32_t seq, संरचना ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	जर (authctxt == रिक्त)
		fatal_f("no authentication context");

	fatal("Unexpected authentication success during %s.",
	    authctxt->method->name);
	परत 0;
}
#endif

स्थिर पूर्णांक
आदान_userauth_failure(पूर्णांक type, uint32_t seq, संरचना ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	अक्षर *authlist = रिक्त;
	u_char partial;

	जर (authctxt == रिक्त)
		fatal("input_userauth_failure: no authentication context");

	जर (sshpkt_get_cstring(ssh, &authlist, रिक्त) != 0 ||
	    sshpkt_get_u8(ssh, &partial) != 0 ||
	    sshpkt_get_end(ssh) != 0)
		जा out;

	जर (partial != 0) {
		verbose("Authenticated using \"%s\" with partial success.",
		    authctxt->method->name);
		/* reset state */
		pubkey_reset(authctxt);
	}
	debug("Authentications that can continue: %s", authlist);

	userauth(ssh, authlist);
	authlist = रिक्त;
 out:
	मुक्त(authlist);
	परत 0;
}

/*
 * Format an identity for logging including filename, key type, fingerprint
 * and location (agent, etc.). Caller must free.
 */
स्थिर अक्षर *
format_identity(Identity *id)
{
	अक्षर *fp = रिक्त, *ret = रिक्त;
	स्थिरांक अक्षर *note = "";

	जर (id->किल्ली != रिक्त) {
		fp = sshkey_fingerprint(id->किल्ली, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
	}
	जर (id->किल्ली) {
		जर ((id->किल्ली->flags & SSHKEY_FLAG_EXT) != 0)
			note = " token";
		अन्यथा जर (sshkey_is_sk(id->किल्ली))
			note = " authenticator";
	}
	xasprintf(&ret, "%s %s%s%s%s%s%s",
	    id->filename,
	    id->किल्ली ? sshkey_type(id->किल्ली) : "", id->किल्ली ? " " : "",
	    fp ? fp : "",
	    id->userprovided ? " explicit" : "", note,
	    id->agent_fd != -1 ? " agent" : "");
	मुक्त(fp);
	परत ret;
}

स्थिर पूर्णांक
आदान_userauth_pk_ok(पूर्णांक type, uint32_t seq, संरचना ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	संरचना sshkey *किल्ली = रिक्त;
	संरचना sshbuf *keyblob = रिक्त;
	Identity *id = रिक्त;
	पूर्णांक pktype, found = 0, sent = 0;
	अक्षर *pkalg = रिक्त, *fp = रिक्त, *ident = रिक्त;
	पूर्णांक r;

	जर (authctxt == रिक्त)
		fatal_f("no authentication context");

	जर ((r = sshpkt_get_cstring(ssh, &pkalg, रिक्त)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		जा done;

	जर (match_pattern_list(pkalg, options.pubkey_accepted_algos, 0) != 1) {
		error_f("server replied to PK_OK with signature type %s not "
		    "in PubkeyAcceptedAlgorithms", pkalg);
		r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		जा done;
	}
	जर ((pktype = sshkey_type_from_name(pkalg)) == किल्ली_UNSPEC) {
		debug_f("server sent unknown pkalg %s", pkalg);
		r = SSH_ERR_INVALID_FORMAT;
		जा done;
	}
	/* inner key type should match signature type */
	जर ((r = sshkey_fromb_allowlist(keyblob, &किल्ली, pkalg, रिक्त)) != 0) {
		debug_r(r, "no key from blob. pkalg %s", pkalg);
		जा done;
	}
	जर (किल्ली->type != pktype) {
		error("input_userauth_pk_ok: type mismatch "
		    "for decoded key (received %d, expected %d)",
		    किल्ली->type, pktype);
		r = SSH_ERR_INVALID_FORMAT;
		जा done;
	}

	/*
	 * search keys in the reverse order, because last candidate has been
	 * moved to the end of the queue.  this also avoids confusion by
	 * duplicate keys
	 */
	TAILQ_FOREACH_REVERSE(id, &authctxt->किल्ल्या, idlist, next) {
		जर (sshkey_equal(किल्ली, id->किल्ली)) {
			found = 1;
			थांबा;
		}
	}
	जर (!found || id == रिक्त) {
		fp = sshkey_fingerprint(किल्ली, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		error_f("server replied with unknown key: %s %s",
		    sshkey_type(किल्ली), fp == रिक्त ? "<ERROR>" : fp);
		r = SSH_ERR_INVALID_FORMAT;
		जा done;
	}
	ident = format_identity(id);
	debug("Server accepts key: %s", ident);
	sent = sign_and_send_pubkey(ssh, id);
	r = 0;
 done:
	sshkey_free(किल्ली);
	sshbuf_free(keyblob);
	मुक्त(ident);
	मुक्त(fp);
	मुक्त(pkalg);

	/* try another method if we did not send a packet */
	जर (r == 0 && sent == 0)
		userauth(ssh, रिक्त);
	परत r;
}

#ifdef GSSAPI
स्थिर पूर्णांक
userauth_gssapi(संरचना ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Gssctxt *gssctxt = रिक्त;
	OM_uint32 min;
	पूर्णांक r, ok = 0;
	gss_OID mech = रिक्त;

	/* Try one GSSAPI method at a time, rather than sending them all at
	 * once. */

	जर (authctxt->gss_supported_mechs == रिक्त)
		gss_indicate_mechs(&min, &authctxt->gss_supported_mechs);

	/* Check to see whether the mechanism is usable before we offer it */
	पर्यंत (authctxt->mech_tried < authctxt->gss_supported_mechs->मोजणी &&
	    !ok) {
		mech = &authctxt->gss_supported_mechs->
		    elements[authctxt->mech_tried];
		/* My DER encoding requires length<128 */
		जर (mech->length < 128 && ssh_gssapi_check_mechanism(&gssctxt,
		    mech, authctxt->host)) {
			ok = 1; /* Mechanism works */
		} अन्यथा {
			authctxt->mech_tried++;
		}
	}

	जर (!ok || mech == रिक्त)
		परत 0;

	authctxt->methoddata=(शून्य *)gssctxt;

	जर ((r = sshpkt_start(ssh, SSH2_संदेश_USERAUTH_REQUEST)) != 0 ||
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

	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_GSSAPI_RESPONSE, &आदान_gssapi_response);
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_GSSAPI_TOKEN, &आदान_gssapi_token);
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_GSSAPI_ERROR, &आदान_gssapi_error);
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_GSSAPI_ERRTOK, &आदान_gssapi_errtok);

	authctxt->mech_tried++; /* Move along to next candidate */

	परत 1;
}

स्थिर शून्य
userauth_gssapi_cleanup(संरचना ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Gssctxt *gssctxt = (Gssctxt *)authctxt->methoddata;

	ssh_gssapi_delete_ctx(&gssctxt);
	authctxt->methoddata = रिक्त;
}

स्थिर OM_uint32
process_gssapi_token(संरचना ssh *ssh, gss_buffer_t recv_tok)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt = authctxt->methoddata;
	gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc mic = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc gssbuf;
	OM_uint32 status, ms, flags;
	पूर्णांक r;

	status = ssh_gssapi_init_ctx(gssctxt, options.gss_deleg_creds,
	    recv_tok, &send_tok, &flags);

	जर (send_tok.length > 0) {
		u_char type = GSS_ERROR(status) ?
		    SSH2_संदेश_USERAUTH_GSSAPI_ERRTOK :
		    SSH2_संदेश_USERAUTH_GSSAPI_TOKEN;

		जर ((r = sshpkt_start(ssh, type)) != 0 ||
		    (r = sshpkt_put_string(ssh, send_tok.मूल्य,
		    send_tok.length)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send %u packet", type);

		gss_release_buffer(&ms, &send_tok);
	}

	जर (status == GSS_S_COMPLETE) {
		/* send either complete or MIC, depending on mechanism */
		जर (!(flags & GSS_C_INTEG_FLAG)) {
			जर ((r = sshpkt_start(ssh,
			    SSH2_संदेश_USERAUTH_GSSAPI_EXCHANGE_COMPLETE)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "send completion");
		} अन्यथा {
			संरचना sshbuf *b;

			जर ((b = sshbuf_new()) == रिक्त)
				fatal_f("sshbuf_new failed");
			ssh_gssapi_buildmic(b, authctxt->server_user,
			    authctxt->service, "gssapi-with-mic",
			    ssh->kex->session_id);

			जर ((gssbuf.मूल्य = sshbuf_mutable_ptr(b)) == रिक्त)
				fatal_f("sshbuf_mutable_ptr failed");
			gssbuf.length = sshbuf_len(b);

			status = ssh_gssapi_sign(gssctxt, &gssbuf, &mic);

			जर (!GSS_ERROR(status)) {
				जर ((r = sshpkt_start(ssh,
				    SSH2_संदेश_USERAUTH_GSSAPI_MIC)) != 0 ||
				    (r = sshpkt_put_string(ssh, mic.मूल्य,
				    mic.length)) != 0 ||
				    (r = sshpkt_send(ssh)) != 0)
					fatal_fr(r, "send MIC");
			}

			sshbuf_free(b);
			gss_release_buffer(&ms, &mic);
		}
	}

	परत status;
}

स्थिर पूर्णांक
आदान_gssapi_response(पूर्णांक type, uint32_t plen, संरचना ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	माप_प्रकार oidlen;
	u_char *oidv = रिक्त;
	पूर्णांक r;

	जर (authctxt == रिक्त)
		fatal("input_gssapi_response: no authentication context");
	gssctxt = authctxt->methoddata;

	/* Setup our OID */
	जर ((r = sshpkt_get_string(ssh, &oidv, &oidlen)) != 0)
		जा done;

	जर (oidlen <= 2 ||
	    oidv[0] != SSH_GSS_OIDTYPE ||
	    oidv[1] != oidlen - 2) {
		debug("Badly encoded mechanism OID received");
		userauth(ssh, रिक्त);
		जा ok;
	}

	जर (!ssh_gssapi_check_oid(gssctxt, oidv + 2, oidlen - 2))
		fatal("Server returned different OID than expected");

	जर ((r = sshpkt_get_end(ssh)) != 0)
		जा done;

	जर (GSS_ERROR(process_gssapi_token(ssh, GSS_C_NO_BUFFER))) {
		/* Start again with next method on list */
		debug("Trying to start again");
		userauth(ssh, रिक्त);
		जा ok;
	}
 ok:
	r = 0;
 done:
	मुक्त(oidv);
	परत r;
}

स्थिर पूर्णांक
आदान_gssapi_token(पूर्णांक type, uint32_t plen, संरचना ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	gss_buffer_desc recv_tok;
	u_char *p = रिक्त;
	माप_प्रकार len;
	OM_uint32 status;
	पूर्णांक r;

	जर (authctxt == रिक्त)
		fatal("input_gssapi_response: no authentication context");

	जर ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		जा out;

	recv_tok.मूल्य = p;
	recv_tok.length = len;
	status = process_gssapi_token(ssh, &recv_tok);

	/* Start again with the next method in the list */
	जर (GSS_ERROR(status)) {
		userauth(ssh, रिक्त);
		/* ok */
	}
	r = 0;
 out:
	मुक्त(p);
	परत r;
}

स्थिर पूर्णांक
आदान_gssapi_errtok(पूर्णांक type, uint32_t plen, संरचना ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc recv_tok;
	OM_uint32 ms;
	u_char *p = रिक्त;
	माप_प्रकार len;
	पूर्णांक r;

	जर (authctxt == रिक्त)
		fatal("input_gssapi_response: no authentication context");
	gssctxt = authctxt->methoddata;

	जर ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0) {
		मुक्त(p);
		परत r;
	}

	/* Stick it into GSSAPI and see what it says */
	recv_tok.मूल्य = p;
	recv_tok.length = len;
	(शून्य)ssh_gssapi_init_ctx(gssctxt, options.gss_deleg_creds,
	    &recv_tok, &send_tok, रिक्त);
	मुक्त(p);
	gss_release_buffer(&ms, &send_tok);

	/* Server will be returning a failed packet after this one */
	परत 0;
}

स्थिर पूर्णांक
आदान_gssapi_error(पूर्णांक type, uint32_t plen, संरचना ssh *ssh)
{
	अक्षर *संदेश = रिक्त;
	अक्षर *lang = रिक्त;
	पूर्णांक r;

	जर ((r = sshpkt_get_u32(ssh, रिक्त)) != 0 ||	/* maj */
	    (r = sshpkt_get_u32(ssh, रिक्त)) != 0 ||	/* min */
	    (r = sshpkt_get_cstring(ssh, &संदेश, रिक्त)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, रिक्त)) != 0)
		जा out;
	r = sshpkt_get_end(ssh);
	debug("Server GSSAPI Error:\n%s", संदेश);
 out:
	मुक्त(संदेश);
	मुक्त(lang);
	परत r;
}
#endif /* GSSAPI */

स्थिर पूर्णांक
userauth_none(संरचना ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	पूर्णांक r;

	/* initial userauth request */
	जर ((r = sshpkt_start(ssh, SSH2_संदेश_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	परत 1;
}

स्थिर पूर्णांक
userauth_passwd(संरचना ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	अक्षर *password, *prompt = रिक्त;
	स्थिरांक अक्षर *host = options.host_किल्ली_alias ?  options.host_किल्ली_alias :
	    authctxt->host;
	पूर्णांक r;

	जर (authctxt->attempt_passwd++ >= options.संख्या_of_password_prompts)
		परत 0;

	जर (authctxt->attempt_passwd != 1)
		error("Permission denied, please try again.");

	xasprintf(&prompt, "%s@%s's password: ", authctxt->server_user, host);
	password = read_passphrase(prompt, 0);
	जर ((r = sshpkt_start(ssh, SSH2_संदेश_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, password)) != 0 ||
	    (r = sshpkt_add_padding(ssh, 64)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	मुक्त(prompt);
	जर (password != रिक्त)
		freezero(password, म_माप(password));

	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_PASSWD_CHANGEREQ,
	    &आदान_userauth_passwd_changereq);

	परत 1;
}

/*
 * parse PASSWD_CHANGEREQ, prompt user and send SSH2_MSG_USERAUTH_REQUEST
 */
स्थिर पूर्णांक
आदान_userauth_passwd_changereq(पूर्णांक type, uint32_t seqnr, संरचना ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	अक्षर *info = रिक्त, *lang = रिक्त, *password = रिक्त, *retype = रिक्त;
	अक्षर prompt[256];
	स्थिरांक अक्षर *host;
	पूर्णांक r, addnl;
	माप_प्रकार len;

	debug2("input_userauth_passwd_changereq");

	जर (authctxt == रिक्त)
		fatal("input_userauth_passwd_changereq: "
		    "no authentication context");
	host = options.host_किल्ली_alias ? options.host_किल्ली_alias : authctxt->host;

	जर ((r = sshpkt_get_cstring(ssh, &info, रिक्त)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, रिक्त)) != 0)
		जा out;
	जर ((len = म_माप(info)) > 0) {
		addnl = info[len] != '\n';
		fmprintf(मानक_त्रुटि, "%s%s", info, addnl ? "\n" : "");
	}
	जर ((r = sshpkt_start(ssh, SSH2_संदेश_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0)	/* additional info */
		जा out;

	snprintf(prompt, आकार(prompt),
	    "Enter %.30s@%.128s's old password: ",
	    authctxt->server_user, host);
	password = read_passphrase(prompt, 0);
	जर ((r = sshpkt_put_cstring(ssh, password)) != 0)
		जा out;

	freezero(password, म_माप(password));
	password = रिक्त;
	पर्यंत (password == रिक्त) {
		snprintf(prompt, आकार(prompt),
		    "Enter %.30s@%.128s's new password: ",
		    authctxt->server_user, host);
		password = read_passphrase(prompt, RP_ALLOW_EOF);
		जर (password == रिक्त) {
			/* bail out */
			r = 0;
			जा out;
		}
		snprintf(prompt, आकार(prompt),
		    "Retype %.30s@%.128s's new password: ",
		    authctxt->server_user, host);
		retype = read_passphrase(prompt, 0);
		जर (म_भेद(password, retype) != 0) {
			freezero(password, म_माप(password));
			logit("Mismatch; try again, EOF to quit.");
			password = रिक्त;
		}
		freezero(retype, म_माप(retype));
	}
	जर ((r = sshpkt_put_cstring(ssh, password)) != 0 ||
	    (r = sshpkt_add_padding(ssh, 64)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		जा out;

	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_PASSWD_CHANGEREQ,
	    &आदान_userauth_passwd_changereq);
	r = 0;
 out:
	जर (password)
		freezero(password, म_माप(password));
	मुक्त(info);
	मुक्त(lang);
	परत r;
}

/*
 * Select an algorithm for publickey signatures.
 * Returns algorithm (caller must free) or NULL if no mutual algorithm found.
 *
 * Call with ssh==NULL to ignore server-sig-algs extension list and
 * only attempt with the key's base signature type.
 */
स्थिर अक्षर *
किल्ली_sig_algorithm(संरचना ssh *ssh, स्थिरांक संरचना sshkey *किल्ली)
{
	अक्षर *allowed, *oallowed, *cp, *tmp, *alg = रिक्त;
	स्थिरांक अक्षर *server_sig_algs;

	/*
	 * The signature algorithm will only differ from the key algorithm
	 * for RSA keys/certs and when the server advertises support for
	 * newer (SHA2) algorithms.
	 */
	जर (ssh == रिक्त || ssh->kex->server_sig_algs == रिक्त ||
	    (किल्ली->type != किल्ली_RSA && किल्ली->type != किल्ली_RSA_CERT) ||
	    (किल्ली->type == किल्ली_RSA_CERT && (ssh->compat & SSH_BUG_SIGTYPE))) {
		/* Filter base key signature alg against our configuration */
		परत match_list(sshkey_ssh_name(किल्ली),
		    options.pubkey_accepted_algos, रिक्त);
	}

	/*
	 * Workaround OpenSSH 7.4 bug: this version supports RSA/SHA-2 but
	 * fails to advertise it via SSH2_MSG_EXT_INFO.
	 */
	server_sig_algs = ssh->kex->server_sig_algs;
	जर (किल्ली->type == किल्ली_RSA && (ssh->compat & SSH_BUG_SIGTYPE74))
		server_sig_algs = "rsa-sha2-256,rsa-sha2-512";

	/*
	 * For RSA keys/certs, since these might have a different sig type:
	 * find the first entry in PubkeyAcceptedAlgorithms of the right type
	 * that also appears in the supported signature algorithms list from
	 * the server.
	 */
	oallowed = allowed = xstrdup(options.pubkey_accepted_algos);
	पर्यंत ((cp = strsep(&allowed, ",")) != रिक्त) {
		जर (sshkey_type_from_name(cp) != किल्ली->type)
			सुरूठेवा;
		tmp = match_list(sshkey_sigalg_by_name(cp),
		    server_sig_algs, रिक्त);
		जर (tmp != रिक्त)
			alg = xstrdup(cp);
		मुक्त(tmp);
		जर (alg != रिक्त)
			थांबा;
	}
	मुक्त(oallowed);
	परत alg;
}

स्थिर पूर्णांक
identity_sign(संरचना identity *id, u_char **sigp, माप_प्रकार *lenp,
    स्थिरांक u_char *data, माप_प्रकार datalen, u_int compat, स्थिरांक अक्षर *alg)
{
	संरचना sshkey *sign_किल्ली = रिक्त, *prv = रिक्त;
	पूर्णांक is_agent = 0, retried = 0, r = SSH_ERR_INTERNAL_ERROR;
	संरचना notifier_ctx *notifier = रिक्त;
	अक्षर *fp = रिक्त, *pin = रिक्त, *prompt = रिक्त;

	*sigp = रिक्त;
	*lenp = 0;

	/* The agent supports this key. */
	जर (id->किल्ली != रिक्त && id->agent_fd != -1) {
		परत ssh_agent_sign(id->agent_fd, id->किल्ली, sigp, lenp,
		    data, datalen, alg, compat);
	}

	/*
	 * We have already loaded the private key or the private key is
	 * stored in external hardware.
	 */
	जर (id->किल्ली != रिक्त &&
	    (id->isprivate || (id->किल्ली->flags & SSHKEY_FLAG_EXT))) {
		sign_किल्ली = id->किल्ली;
		is_agent = 1;
	} अन्यथा {
		/* Load the private key from the file. */
		जर ((prv = load_identity_file(id)) == रिक्त)
			परत SSH_ERR_किल्ली_NOT_FOUND;
		जर (id->किल्ली != रिक्त && !sshkey_equal_public(prv, id->किल्ली)) {
			error_f("private key %s contents do not match public",
			    id->filename);
			r = SSH_ERR_किल्ली_NOT_FOUND;
			जा out;
		}
		sign_किल्ली = prv;
	}
 retry_pin:
	/* Prompt for touch for non-agent FIDO keys that request UP */
	जर (!is_agent && sshkey_is_sk(sign_किल्ली) &&
	    (sign_किल्ली->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
		/* XXX should batch mode just skip these? */
		जर ((fp = sshkey_fingerprint(sign_किल्ली,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == रिक्त)
			fatal_f("fingerprint failed");
		notifier = notify_start(options.batch_mode,
		    "Confirm user presence for key %s %s",
		    sshkey_type(sign_किल्ली), fp);
		मुक्त(fp);
	}
	जर ((r = sshkey_sign(sign_किल्ली, sigp, lenp, data, datalen,
	    alg, options.sk_provider, pin, compat)) != 0) {
		debug_fr(r, "sshkey_sign");
		जर (!retried && pin == रिक्त && !is_agent &&
		    sshkey_is_sk(sign_किल्ली) &&
		    r == SSH_ERR_किल्ली_WRONG_PASSPHRASE) {
			notify_complete(notifier, रिक्त);
			notifier = रिक्त;
			xasprintf(&prompt, "Enter PIN for %s key %s: ",
			    sshkey_type(sign_किल्ली), id->filename);
			pin = read_passphrase(prompt, 0);
			retried = 1;
			जा retry_pin;
		}
		जा out;
	}

	/*
	 * PKCS#11 tokens may not support all signature algorithms,
	 * so check what we get back.
	 */
	जर (id->किल्ली != रिक्त && (id->किल्ली->flags & SSHKEY_FLAG_EXT) != 0 &&
	    (r = sshkey_check_sigtype(*sigp, *lenp, alg)) != 0) {
		debug_fr(r, "sshkey_check_sigtype");
		जा out;
	}
	/* success */
	r = 0;
 out:
	मुक्त(prompt);
	जर (pin != रिक्त)
		freezero(pin, म_माप(pin));
	notify_complete(notifier, r == 0 ? "User presence confirmed" : रिक्त);
	sshkey_free(prv);
	परत r;
}

स्थिर पूर्णांक
id_filename_matches(Identity *id, Identity *private_id)
{
	स्थिर स्थिरांक अक्षर * स्थिरांक suffixes[] = { ".pub", "-cert.pub", रिक्त };
	माप_प्रकार len = म_माप(id->filename), plen = म_माप(private_id->filename);
	माप_प्रकार i, slen;

	जर (म_भेद(id->filename, private_id->filename) == 0)
		परत 1;
	साठी (i = 0; suffixes[i]; i++) {
		slen = म_माप(suffixes[i]);
		जर (len > slen && plen == len - slen &&
		    म_भेद(id->filename + (len - slen), suffixes[i]) == 0 &&
		    स_भेद(id->filename, private_id->filename, plen) == 0)
			परत 1;
	}
	परत 0;
}

स्थिर पूर्णांक
sign_and_send_pubkey(संरचना ssh *ssh, Identity *id)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	संरचना sshbuf *b = रिक्त;
	Identity *private_id, *sign_id = रिक्त;
	u_char *signature = रिक्त;
	माप_प्रकार slen = 0, skip = 0;
	पूर्णांक r, fallback_sigtype, sent = 0;
	अक्षर *alg = रिक्त, *fp = रिक्त;
	स्थिरांक अक्षर *loc = "", *method = "publickey";
	पूर्णांक hostbound = 0;

	/* prefer host-bound pubkey signatures if supported by server */
	जर ((ssh->kex->flags & KEX_HAS_PUBKEY_HOSTBOUND) != 0 &&
	    (options.pubkey_authentication & SSH_PUBKEY_AUTH_HBOUND) != 0) {
		hostbound = 1;
		method = "publickey-hostbound-v00@openssh.com";
	}

	जर ((fp = sshkey_fingerprint(id->किल्ली, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == रिक्त)
		परत 0;

	debug3_f("using %s with %s %s", method, sshkey_type(id->किल्ली), fp);

	/*
	 * If the key is an certificate, try to find a matching private key
	 * and use it to complete the signature.
	 * If no such private key exists, fall back to trying the certificate
	 * key itself in case it has a private half already loaded.
	 * This will try to set sign_id to the private key that will perform
	 * the signature.
	 */
	जर (id->agent_fd == -1 && sshkey_is_cert(id->किल्ली)) {
		TAILQ_FOREACH(private_id, &authctxt->किल्ल्या, next) {
			जर (sshkey_equal_public(id->किल्ली, private_id->किल्ली) &&
			    id->किल्ली->type != private_id->किल्ली->type) {
				sign_id = private_id;
				थांबा;
			}
		}
		/*
		 * Exact key matches are preferred, but also allow
		 * filename matches for non-PKCS#11/agent keys that
		 * didn't load public keys. This supports the case
		 * of keeping just a private key file and public
		 * certificate on disk.
		 */
		जर (sign_id == रिक्त &&
		    !id->isprivate && id->agent_fd == -1 &&
		    (id->किल्ली->flags & SSHKEY_FLAG_EXT) == 0) {
			TAILQ_FOREACH(private_id, &authctxt->किल्ल्या, next) {
				जर (private_id->किल्ली == रिक्त &&
				    id_filename_matches(id, private_id)) {
					sign_id = private_id;
					थांबा;
				}
			}
		}
		जर (sign_id != रिक्त) {
			debug2_f("using private key \"%s\"%s for "
			    "certificate", sign_id->filename,
			    sign_id->agent_fd != -1 ? " from agent" : "");
		} अन्यथा {
			debug_f("no separate private key for certificate "
			    "\"%s\"", id->filename);
		}
	}

	/*
	 * If the above didn't select another identity to do the signing
	 * then default to the one we started with.
	 */
	जर (sign_id == रिक्त)
		sign_id = id;

	/* assemble and sign data */
	साठी (fallback_sigtype = 0; fallback_sigtype <= 1; fallback_sigtype++) {
		मुक्त(alg);
		slen = 0;
		signature = रिक्त;
		जर ((alg = किल्ली_sig_algorithm(fallback_sigtype ? रिक्त : ssh,
		    id->किल्ली)) == रिक्त) {
			error_f("no mutual signature supported");
			जा out;
		}
		debug3_f("signing using %s %s", alg, fp);

		sshbuf_free(b);
		जर ((b = sshbuf_new()) == रिक्त)
			fatal_f("sshbuf_new failed");
		जर ((r = sshbuf_put_stringb(b,
		    ssh->kex->session_id)) != 0)
			fatal_fr(r, "sshbuf_put_stringb");
		skip = sshbuf_len(b);
		जर ((r = sshbuf_put_u8(b, SSH2_संदेश_USERAUTH_REQUEST)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->server_user)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
		    (r = sshbuf_put_cstring(b, method)) != 0 ||
		    (r = sshbuf_put_u8(b, 1)) != 0 ||
		    (r = sshbuf_put_cstring(b, alg)) != 0 ||
		    (r = sshkey_puts(id->किल्ली, b)) != 0) {
			fatal_fr(r, "assemble signed data");
		}
		जर (hostbound) {
			जर (ssh->kex->initial_hostkey == रिक्त) {
				fatal_f("internal error: initial hostkey "
				    "not recorded");
			}
			जर ((r = sshkey_puts(ssh->kex->initial_hostkey, b)) != 0)
				fatal_fr(r, "assemble %s hostkey", method);
		}
		/* generate signature */
		r = identity_sign(sign_id, &signature, &slen,
		    sshbuf_ptr(b), sshbuf_len(b), ssh->compat, alg);
		जर (r == 0)
			थांबा;
		अन्यथा जर (r == SSH_ERR_किल्ली_NOT_FOUND)
			जा out; /* soft failure */
		अन्यथा जर (r == SSH_ERR_SIGN_ALG_UNSUPPORTED &&
		    !fallback_sigtype) {
			जर (sign_id->agent_fd != -1)
				loc = "agent ";
			अन्यथा जर (sign_id->किल्ली != रिक्त &&
			    (sign_id->किल्ली->flags & SSHKEY_FLAG_EXT) != 0)
				loc = "token ";
			logit("%skey %s %s returned incorrect signature type",
			    loc, sshkey_type(id->किल्ली), fp);
			सुरूठेवा;
		}
		error_fr(r, "signing failed for %s \"%s\"%s",
		    sshkey_type(sign_id->किल्ली), sign_id->filename,
		    id->agent_fd != -1 ? " from agent" : "");
		जा out;
	}
	जर (slen == 0 || signature == रिक्त) /* shouldn't happen */
		fatal_f("no signature");

	/* append signature */
	जर ((r = sshbuf_put_string(b, signature, slen)) != 0)
		fatal_fr(r, "append signature");

#ifdef DEBUG_PK
	sshbuf_dump(b, मानक_त्रुटि);
#endif
	/* skip session id and packet type */
	जर ((r = sshbuf_consume(b, skip + 1)) != 0)
		fatal_fr(r, "consume");

	/* put remaining data from buffer into packet */
	जर ((r = sshpkt_start(ssh, SSH2_संदेश_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_putb(ssh, b)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "enqueue request");

	/* success */
	sent = 1;

 out:
	मुक्त(fp);
	मुक्त(alg);
	sshbuf_free(b);
	freezero(signature, slen);
	परत sent;
}

स्थिर पूर्णांक
send_pubkey_test(संरचना ssh *ssh, Identity *id)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	u_char *blob = रिक्त;
	अक्षर *alg = रिक्त;
	माप_प्रकार bloblen;
	u_int have_sig = 0;
	पूर्णांक sent = 0, r;

	जर ((alg = किल्ली_sig_algorithm(ssh, id->किल्ली)) == रिक्त) {
		debug_f("no mutual signature algorithm");
		जा out;
	}

	जर ((r = sshkey_to_blob(id->किल्ली, &blob, &bloblen)) != 0) {
		/* we cannot handle this key */
		debug3_f("cannot handle key");
		जा out;
	}
	/* register callback for USERAUTH_PK_OK message */
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_PK_OK, &आदान_userauth_pk_ok);

	जर ((r = sshpkt_start(ssh, SSH2_संदेश_USERAUTH_REQUEST)) != 0 ||
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
	मुक्त(alg);
	मुक्त(blob);
	परत sent;
}

स्थिर संरचना sshkey *
load_identity_file(Identity *id)
{
	संरचना sshkey *खाजगी = रिक्त;
	अक्षर prompt[300], *passphrase, *comment;
	पूर्णांक r, quit = 0, i;
	संरचना stat st;

	जर (stat(id->filename, &st) == -1) {
		do_log2(id->userprovided ?
		    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_DEBUG3,
		    "no such identity: %s: %s", id->filename, म_त्रुटि(त्रुटि_सं));
		परत रिक्त;
	}
	snprintf(prompt, आकार prompt,
	    "Enter passphrase for key '%.100s': ", id->filename);
	साठी (i = 0; i <= options.संख्या_of_password_prompts; i++) {
		जर (i == 0)
			passphrase = "";
		अन्यथा {
			passphrase = read_passphrase(prompt, 0);
			जर (*passphrase == '\0') {
				debug2("no passphrase given, try next key");
				मुक्त(passphrase);
				थांबा;
			}
		}
		निवड ((r = sshkey_load_private_type(किल्ली_UNSPEC, id->filename,
		    passphrase, &खाजगी, &comment))) {
		स्थिती 0:
			थांबा;
		स्थिती SSH_ERR_किल्ली_WRONG_PASSPHRASE:
			जर (options.batch_mode) {
				quit = 1;
				थांबा;
			}
			जर (i != 0)
				debug2("bad passphrase given, try again...");
			थांबा;
		स्थिती SSH_ERR_SYSTEM_ERROR:
			जर (त्रुटि_सं == ENOENT) {
				debug2_r(r, "Load key \"%s\"", id->filename);
				quit = 1;
				थांबा;
			}
			/* FALLTHROUGH */
		पूर्वनिर्धारित:
			error_r(r, "Load key \"%s\"", id->filename);
			quit = 1;
			थांबा;
		}
		जर (खाजगी != रिक्त && sshkey_is_sk(खाजगी) &&
		    options.sk_provider == रिक्त) {
			debug("key \"%s\" is an authenticator-hosted key, "
			    "but no provider specified", id->filename);
			sshkey_free(खाजगी);
			खाजगी = रिक्त;
			quit = 1;
		}
		जर (!quit && (r = sshkey_check_rsa_length(खाजगी,
		    options.required_rsa_size)) != 0) {
			debug_fr(r, "Skipping key %s", id->filename);
			sshkey_free(खाजगी);
			खाजगी = रिक्त;
			quit = 1;
		}
		जर (!quit && खाजगी != रिक्त && id->agent_fd == -1 &&
		    !(id->किल्ली && id->isprivate))
			maybe_add_किल्ली_to_agent(id->filename, खाजगी, comment,
			    passphrase);
		जर (i > 0)
			freezero(passphrase, म_माप(passphrase));
		मुक्त(comment);
		जर (खाजगी != रिक्त || quit)
			थांबा;
	}
	परत खाजगी;
}

स्थिर पूर्णांक
किल्ली_type_allowed(संरचना sshkey *किल्ली, स्थिरांक अक्षर *allowlist)
{
	जर (match_pattern_list(sshkey_ssh_name(किल्ली), allowlist, 0) == 1)
		परत 1;

	/* RSA keys/certs might be allowed by alternate signature types */
	निवड (किल्ली->type) {
	स्थिती किल्ली_RSA:
		जर (match_pattern_list("rsa-sha2-512", allowlist, 0) == 1)
			परत 1;
		जर (match_pattern_list("rsa-sha2-256", allowlist, 0) == 1)
			परत 1;
		थांबा;
	स्थिती किल्ली_RSA_CERT:
		जर (match_pattern_list("rsa-sha2-512-cert-v01@openssh.com",
		    allowlist, 0) == 1)
			परत 1;
		जर (match_pattern_list("rsa-sha2-256-cert-v01@openssh.com",
		    allowlist, 0) == 1)
			परत 1;
		थांबा;
	}
	परत 0;
}

स्थिर पूर्णांक
किल्ली_type_allowed_by_config(संरचना sshkey *किल्ली)
{
	परत किल्ली_type_allowed(किल्ली, options.pubkey_accepted_algos);
}

/* obtain a list of keys from the agent */
स्थिर पूर्णांक
get_agent_identities(संरचना ssh *ssh, पूर्णांक *agent_fdp,
    संरचना ssh_identitylist **idlistp)
{
	पूर्णांक r, agent_fd;
	संरचना ssh_identitylist *idlist;

	जर ((r = ssh_get_authentication_socket(&agent_fd)) != 0) {
		जर (r != SSH_ERR_AGENT_NOT_PRESENT)
			debug_fr(r, "ssh_get_authentication_socket");
		परत r;
	}
	जर (ssh != रिक्त && ssh->kex != रिक्त) {
		जर ((r = ssh_agent_bind_hostkey(agent_fd, ssh->kex->initial_hostkey,
		    ssh->kex->session_id, ssh->kex->initial_sig, 0)) == 0)
			debug_f("bound agent to hostkey");
		अन्यथा
			debug2_fr(r, "ssh_agent_bind_hostkey");
	}

	जर ((r = ssh_fetch_identitylist(agent_fd, &idlist)) != 0) {
		debug_fr(r, "ssh_fetch_identitylist");
		बंद(agent_fd);
		परत r;
	}
	/* success */
	*agent_fdp = agent_fd;
	*idlistp = idlist;
	debug_f("agent returned %zu keys", idlist->nkeys);
	परत 0;
}

/*
 * Returns nonzero if the certificate extensions/critical-options section
 * has the specified option present, zero otherwise.
 */
स्थिर पूर्णांक
cert_has_option(संरचना sshbuf *oblob, स्थिरांक अक्षर *target)
{
	संरचना sshbuf *c = रिक्त, *data = रिक्त;
	अक्षर *name = रिक्त;
	पूर्णांक r, found = 0;

	जर (oblob == रिक्त || (c = sshbuf_fromb(oblob)) == रिक्त)
		परत 0;
	पर्यंत (sshbuf_len(c) > 0) {
		sshbuf_free(data);
		data = रिक्त;
		मुक्त(name);
		name = रिक्त;
		जर ((r = sshbuf_get_cstring(c, &name, रिक्त)) != 0 ||
		    (r = sshbuf_froms(c, &data)) != 0)
			थांबा;
		जर (म_भेद(name, target) == 0) {
			found = 1;
			थांबा;
		}
	}
	sshbuf_free(data);
	मुक्त(name);
	sshbuf_free(c);
	परत found;
}

/*
 * Returns an integer describing the priority of the identity
 * within its group. Lower numbers are higher priority.
 */
#define MAX_ID_PRIORITY 3
स्थिर पूर्णांक
identity_prioritise(संरचना identity *id)
{
	जर (id == रिक्त || id->किल्ली == रिक्त)
		परत 3;
	जर (!sshkey_is_cert(id->किल्ली) || id->किल्ली->cert == रिक्त)
		परत 3;
	जर (sshkey_is_sk(id->किल्ली) &&
	    cert_has_option(id->किल्ली->cert->critical, "verify-required"))
		परत 2;
	जर (sshkey_is_sk(id->किल्ली) &&
	    cert_has_option(id->किल्ली->cert->extensions, "no-touch-required"))
		परत 0;
	परत 1;
}

स्थिर शून्य
order_identities_by_prio(संरचना idlist *list)
{
	संरचना idlist prio[MAX_ID_PRIORITY + 1], sorted;
	संरचना identity *id, *tmp, *dummy;
	पूर्णांक p;

	साठी (p = 0; p <= MAX_ID_PRIORITY; p++)
		TAILQ_INIT(&prio[p]);
	TAILQ_INIT(&sorted);

	TAILQ_FOREACH_SAFE(id, list, next, tmp) {
		जर (id->userprovided)
			सुरूठेवा;
		dummy = xcalloc(1, आकार(*dummy));
		dummy->userprovided = -1;
		TAILQ_INSERT_BEFORE(id, dummy, next);
		TAILQ_REMOVE(list, id, next);
		p = identity_prioritise(id);
		जर (p < 0 || p > MAX_ID_PRIORITY)
			fatal_f("internal error: bad priority");
		TAILQ_INSERT_TAIL(&prio[p], id, next);
	}
	साठी (p = 0; p <= MAX_ID_PRIORITY; p++)
		TAILQ_CONCAT(&sorted, &prio[p], next);

	TAILQ_FOREACH_SAFE(id, list, next, tmp) {
		जर (id->userprovided != -1)
			सुरूठेवा;
		संरचना identity *s = TAILQ_FIRST(&sorted);
		TAILQ_REMOVE(&sorted, s, next);
		TAILQ_INSERT_BEFORE(id, s, next);
		TAILQ_REMOVE(list, id, next);
		मुक्त(id);
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
स्थिर शून्य
pubkey_prepare(संरचना ssh *ssh, Authctxt *authctxt)
{
	संरचना identity *id, *id2, *tmp;
	संरचना idlist agent, files, certs, agent_किल्ल्या, *preferred;
	संरचना sshkey *किल्ली;
	पूर्णांक disallowed, agent_fd = -1, i, r, found;
	माप_प्रकार j;
	संरचना ssh_identitylist *idlist;
	अक्षर *cp, *ident;

	TAILQ_INIT(&agent);	/* keys from the agent */
	TAILQ_INIT(&files);	/* keys from the config file */
	TAILQ_INIT(&certs);	/* certificates specified by user */
	TAILQ_INIT(&agent_किल्ल्या); /* keys supported by the agent */
	preferred = &authctxt->किल्ल्या;
	TAILQ_INIT(preferred);	/* preferred order of keys */

	/* list of keys stored in the filesystem and PKCS#11 */
	साठी (i = 0; i < options.अंक_identity_files; i++) {
		किल्ली = options.identity_किल्ल्या[i];
		जर (किल्ली && किल्ली->cert &&
		    किल्ली->cert->type != SSH2_CERT_TYPE_USER) {
			debug_f("ignoring certificate %s: not a user "
			    "certificate", options.identity_files[i]);
			सुरूठेवा;
		}
		जर (किल्ली && sshkey_is_sk(किल्ली) && options.sk_provider == रिक्त) {
			debug_f("ignoring authenticator-hosted key %s as no "
			    "SecurityKeyProvider has been specified",
			    options.identity_files[i]);
			सुरूठेवा;
		}
		options.identity_किल्ल्या[i] = रिक्त;
		id = xcalloc(1, आकार(*id));
		id->agent_fd = -1;
		id->किल्ली = किल्ली;
		id->filename = xstrdup(options.identity_files[i]);
		id->userprovided = options.identity_file_userprovided[i];
		TAILQ_INSERT_TAIL(&files, id, next);
	}

	/* list of certificates specified by user */
	साठी (i = 0; i < options.अंक_certificate_files; i++) {
		किल्ली = options.certificates[i];
		जर (!sshkey_is_cert(किल्ली) || किल्ली->cert == रिक्त ||
		    किल्ली->cert->type != SSH2_CERT_TYPE_USER) {
			debug_f("ignoring certificate %s: not a user "
			    "certificate", options.identity_files[i]);
			सुरूठेवा;
		}
		जर (किल्ली && sshkey_is_sk(किल्ली) && options.sk_provider == रिक्त) {
			debug_f("ignoring authenticator-hosted key "
			    "certificate %s as no "
			    "SecurityKeyProvider has been specified",
			    options.identity_files[i]);
			सुरूठेवा;
		}
		id = xcalloc(1, आकार(*id));
		id->agent_fd = -1;
		id->किल्ली = किल्ली;
		id->filename = xstrdup(options.certificate_files[i]);
		id->userprovided = options.certificate_file_userprovided[i];
		TAILQ_INSERT_TAIL(&certs, id, next);
	}
	order_identities_by_prio(&certs);
	TAILQ_CONCAT(preferred, &certs, next);

	/* list of keys supported by the agent */
	जर ((r = get_agent_identities(ssh, &agent_fd, &idlist)) == 0) {
		साठी (j = 0; j < idlist->nkeys; j++) {
			जर ((r = sshkey_check_rsa_length(idlist->किल्ल्या[j],
			    options.required_rsa_size)) != 0) {
				debug_fr(r, "ignoring %s agent key",
				    sshkey_ssh_name(idlist->किल्ल्या[j]));
				सुरूठेवा;
			}
			found = 0;
			TAILQ_FOREACH(id, &files, next) {
				/*
				 * agent keys from the config file are
				 * preferred
				 */
				जर (sshkey_equal(idlist->किल्ल्या[j], id->किल्ली)) {
					TAILQ_REMOVE(&files, id, next);
					TAILQ_INSERT_TAIL(&agent_किल्ल्या, id, next);
					id->agent_fd = agent_fd;
					found = 1;
					थांबा;
				}
			}
			जर (!found && !options.identities_only) {
				id = xcalloc(1, आकार(*id));
				/* XXX "steals" key/comment from idlist */
				id->किल्ली = idlist->किल्ल्या[j];
				id->filename = idlist->comments[j];
				idlist->किल्ल्या[j] = रिक्त;
				idlist->comments[j] = रिक्त;
				id->agent_fd = agent_fd;
				TAILQ_INSERT_TAIL(&agent, id, next);
			}
		}
		ssh_free_identitylist(idlist);
		/* append remaining agent keys */
		TAILQ_CONCAT(&agent_किल्ल्या, &agent, next);
		order_identities_by_prio(&agent_किल्ल्या);
		TAILQ_CONCAT(preferred, &agent_किल्ल्या, next);
		authctxt->agent_fd = agent_fd;
	}
	/* Prefer PKCS11 keys that are explicitly listed */
	TAILQ_FOREACH_SAFE(id, &files, next, tmp) {
		जर (id->किल्ली == रिक्त || (id->किल्ली->flags & SSHKEY_FLAG_EXT) == 0)
			सुरूठेवा;
		found = 0;
		TAILQ_FOREACH(id2, &files, next) {
			जर (id2->किल्ली == रिक्त ||
			    (id2->किल्ली->flags & SSHKEY_FLAG_EXT) != 0)
				सुरूठेवा;
			जर (sshkey_equal(id->किल्ली, id2->किल्ली)) {
				TAILQ_REMOVE(&files, id, next);
				TAILQ_INSERT_TAIL(preferred, id, next);
				found = 1;
				थांबा;
			}
		}
		/* If IdentitiesOnly set and key not found then don't use it */
		जर (!found && options.identities_only) {
			TAILQ_REMOVE(&files, id, next);
			freezero(id, आकार(*id));
		}
	}
	order_identities_by_prio(&files);
	/* append remaining keys from the config file */
	TAILQ_CONCAT(preferred, &files, next);
	/* finally, filter by PubkeyAcceptedAlgorithms */
	TAILQ_FOREACH_SAFE(id, preferred, next, id2) {
		disallowed = 0;
		cp = रिक्त;
		जर (id->किल्ली == रिक्त)
			सुरूठेवा;
		जर (!किल्ली_type_allowed_by_config(id->किल्ली)) {
			debug("Skipping %s key %s - corresponding algorithm "
			    "not in PubkeyAcceptedAlgorithms",
			    sshkey_ssh_name(id->किल्ली), id->filename);
			disallowed = 1;
		} अन्यथा जर (ssh != रिक्त && ssh->kex != रिक्त &&
		    ssh->kex->server_sig_algs != रिक्त &&
		    (cp = किल्ली_sig_algorithm(ssh, id->किल्ली)) == रिक्त) {
			debug("Skipping %s key %s - corresponding algorithm "
			    "not supported by server",
			    sshkey_ssh_name(id->किल्ली), id->filename);
			disallowed = 1;
		}
		मुक्त(cp);
		जर (!disallowed)
			सुरूठेवा;
		/* remove key */
		TAILQ_REMOVE(preferred, id, next);
		sshkey_free(id->किल्ली);
		मुक्त(id->filename);
		freezero(id, आकार(*id));
	}
	/* List the keys we plan on using */
	TAILQ_FOREACH_SAFE(id, preferred, next, id2) {
		ident = format_identity(id);
		debug("Will attempt key: %s", ident);
		मुक्त(ident);
	}
	debug2_f("done");
}

स्थिर शून्य
pubkey_cleanup(संरचना ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Identity *id;

	जर (authctxt->agent_fd != -1) {
		ssh_close_authentication_socket(authctxt->agent_fd);
		authctxt->agent_fd = -1;
	}
	साठी (id = TAILQ_FIRST(&authctxt->किल्ल्या); id;
	    id = TAILQ_FIRST(&authctxt->किल्ल्या)) {
		TAILQ_REMOVE(&authctxt->किल्ल्या, id, next);
		sshkey_free(id->किल्ली);
		मुक्त(id->filename);
		मुक्त(id);
	}
}

शून्य
pubkey_dump(संरचना ssh *ssh)
{
	Authctxt authctxt;
	Identity *id;
	अक्षर *ident;

	स_रखो(&authctxt, 0, आकार(authctxt));
	authctxt.agent_fd = -1;
	ssh->authctxt = &authctxt;

	pubkey_prepare(ssh, &authctxt);
	TAILQ_FOREACH(id, &authctxt.किल्ल्या, next) {
		ident = format_identity(id);
		ख_लिखो(मानक_निकास, "%s\n", ident);
		मुक्त(ident);
	}
	pubkey_cleanup(ssh);
	ssh->authctxt = रिक्त;
}

स्थिर शून्य
pubkey_reset(Authctxt *authctxt)
{
	Identity *id;

	TAILQ_FOREACH(id, &authctxt->किल्ल्या, next)
		id->tried = 0;
}

स्थिर पूर्णांक
userauth_pubkey(संरचना ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Identity *id;
	पूर्णांक sent = 0;
	अक्षर *ident;
	स्थिर पूर्णांक prepared;

	जर (!prepared) {
		pubkey_prepare(ssh, authctxt);
		prepared = 1;
	}

	पर्यंत ((id = TAILQ_FIRST(&authctxt->किल्ल्या))) {
		जर (id->tried++)
			परत (0);
		/* move key to the end of the queue */
		TAILQ_REMOVE(&authctxt->किल्ल्या, id, next);
		TAILQ_INSERT_TAIL(&authctxt->किल्ल्या, id, next);
		/*
		 * send a test message if we have the public key. for
		 * encrypted keys we cannot do this and have to load the
		 * private key instead
		 */
		जर (id->किल्ली != रिक्त) {
			ident = format_identity(id);
			debug("Offering public key: %s", ident);
			मुक्त(ident);
			sent = send_pubkey_test(ssh, id);
		} अन्यथा {
			debug("Trying private key: %s", id->filename);
			id->किल्ली = load_identity_file(id);
			जर (id->किल्ली != रिक्त) {
				id->isprivate = 1;
				sent = sign_and_send_pubkey(ssh, id);
				sshkey_free(id->किल्ली);
				id->किल्ली = रिक्त;
				id->isprivate = 0;
			}
		}
		जर (sent)
			परत (sent);
	}
	परत (0);
}

/*
 * Send userauth request message specifying keyboard-interactive method.
 */
स्थिर पूर्णांक
userauth_kbdint(संरचना ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	पूर्णांक r;

	जर (authctxt->attempt_kbdint++ >= options.संख्या_of_password_prompts)
		परत 0;
	/* disable if no SSH2_MSG_USERAUTH_INFO_REQUEST has been seen */
	जर (authctxt->attempt_kbdint > 1 && !authctxt->info_req_seen) {
		debug3("userauth_kbdint: disable: no info_req_seen");
		ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_INFO_REQUEST, रिक्त);
		परत 0;
	}

	debug2("userauth_kbdint");
	जर ((r = sshpkt_start(ssh, SSH2_संदेश_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||		/* lang */
	    (r = sshpkt_put_cstring(ssh, options.kbd_interactive_devices ?
	    options.kbd_interactive_devices : "")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_INFO_REQUEST, &आदान_userauth_info_req);
	परत 1;
}

/*
 * parse INFO_REQUEST, prompt user and send INFO_RESPONSE
 */
स्थिर पूर्णांक
आदान_userauth_info_req(पूर्णांक type, uint32_t seq, संरचना ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	अक्षर *name = रिक्त, *inst = रिक्त, *lang = रिक्त, *prompt = रिक्त;
	अक्षर *display_prompt = रिक्त, *response = रिक्त;
	u_char echo = 0;
	u_int अंक_prompts, i;
	पूर्णांक r, addnl;
	माप_प्रकार len;

	debug2_f("entering");

	जर (authctxt == रिक्त)
		fatal_f("no authentication context");

	authctxt->info_req_seen = 1;

	जर ((r = sshpkt_get_cstring(ssh, &name, रिक्त)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &inst, रिक्त)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, रिक्त)) != 0)
		जा out;
	जर ((len = म_माप(name)) > 0) {
		addnl = name[len] != '\n';
		fmprintf(मानक_त्रुटि, "%s%s", name, addnl ? "\n" : "");
	}
	जर ((len = म_माप(inst)) > 0) {
		addnl = inst[len] != '\n';
		fmprintf(मानक_त्रुटि, "%s%s", inst, addnl ? "\n" : "");
	}

	जर ((r = sshpkt_get_u32(ssh, &अंक_prompts)) != 0)
		जा out;
	/*
	 * Begin to build info response packet based on prompts requested.
	 * We commit to providing the correct number of responses, so if
	 * further on we run into a problem that prevents this, we have to
	 * be sure and clean this up and send a correct error response.
	 */
	जर ((r = sshpkt_start(ssh, SSH2_संदेश_USERAUTH_INFO_RESPONSE)) != 0 ||
	    (r = sshpkt_put_u32(ssh, अंक_prompts)) != 0)
		जा out;

	debug2_f("num_prompts %d", अंक_prompts);
	साठी (i = 0; i < अंक_prompts; i++) {
		जर ((r = sshpkt_get_cstring(ssh, &prompt, रिक्त)) != 0 ||
		    (r = sshpkt_get_u8(ssh, &echo)) != 0)
			जा out;
		जर (asmprintf(&display_prompt, पूर्णांक_उच्च, रिक्त, "(%s@%s) %s",
		    authctxt->server_user, options.host_किल्ली_alias ?
		    options.host_किल्ली_alias : authctxt->host, prompt) == -1)
			fatal_f("asmprintf failed");
		response = read_passphrase(display_prompt, echo ? RP_ECHO : 0);
		जर ((r = sshpkt_put_cstring(ssh, response)) != 0)
			जा out;
		freezero(response, म_माप(response));
		मुक्त(prompt);
		मुक्त(display_prompt);
		display_prompt = response = prompt = रिक्त;
	}
	/* done with parsing incoming message. */
	जर ((r = sshpkt_get_end(ssh)) != 0 ||
	    (r = sshpkt_add_padding(ssh, 64)) != 0)
		जा out;
	r = sshpkt_send(ssh);
 out:
	जर (response)
		freezero(response, म_माप(response));
	मुक्त(prompt);
	मुक्त(display_prompt);
	मुक्त(name);
	मुक्त(inst);
	मुक्त(lang);
	परत r;
}

स्थिर पूर्णांक
ssh_keysign(संरचना ssh *ssh, संरचना sshkey *किल्ली, u_char **sigp, माप_प्रकार *lenp,
    स्थिरांक u_char *data, माप_प्रकार datalen)
{
	संरचना sshbuf *b;
	संरचना stat st;
	pid_t pid;
	पूर्णांक r, to[2], from[2], status;
	पूर्णांक sock = ssh_packet_get_connection_in(ssh);
	u_char rversion = 0, version = 2;
	शून्य (*osigchld)(पूर्णांक);

	*sigp = रिक्त;
	*lenp = 0;

	जर (stat(PATH_SSH_किल्ली_SIGN, &st) == -1) {
		error_f("not installed: %s", म_त्रुटि(त्रुटि_सं));
		परत -1;
	}
	जर (ख_साफ(मानक_निकास) != 0) {
		error_f("fflush: %s", म_त्रुटि(त्रुटि_सं));
		परत -1;
	}
	जर (pipe(to) == -1) {
		error_f("pipe: %s", म_त्रुटि(त्रुटि_सं));
		परत -1;
	}
	जर (pipe(from) == -1) {
		error_f("pipe: %s", म_त्रुटि(त्रुटि_सं));
		परत -1;
	}
	जर ((pid = विभाजन()) == -1) {
		error_f("fork: %s", म_त्रुटि(त्रुटि_सं));
		परत -1;
	}
	osigchld = ssh_signal(SIGCHLD, संक_पूर्व);
	जर (pid == 0) {
		बंद(from[0]);
		जर (dup2(from[1], STDOUT_FILENO) == -1)
			fatal_f("dup2: %s", म_त्रुटि(त्रुटि_सं));
		बंद(to[1]);
		जर (dup2(to[0], STDIN_FILENO) == -1)
			fatal_f("dup2: %s", म_त्रुटि(त्रुटि_सं));
		बंद(from[1]);
		बंद(to[0]);

		जर (dup2(sock, STDERR_FILENO + 1) == -1)
			fatal_f("dup2: %s", म_त्रुटि(त्रुटि_सं));
		sock = STDERR_FILENO + 1;
		जर (fcntl(sock, F_SETFD, 0) == -1) /* keep the socket on exec */
			debug3_f("fcntl F_SETFD: %s", म_त्रुटि(त्रुटि_सं));
		closefrom(sock + 1);

		debug3_f("[child] pid=%ld, exec %s",
		    (दीर्घ)getpid(), PATH_SSH_किल्ली_SIGN);
		execl(PATH_SSH_किल्ली_SIGN, PATH_SSH_किल्ली_SIGN, (अक्षर *)रिक्त);
		fatal_f("exec(%s): %s", PATH_SSH_किल्ली_SIGN,
		    म_त्रुटि(त्रुटि_सं));
	}
	बंद(from[1]);
	बंद(to[0]);
	sock = STDERR_FILENO + 1;

	जर ((b = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	/* send # of sock, data to be signed */
	जर ((r = sshbuf_put_u32(b, sock)) != 0 ||
	    (r = sshbuf_put_string(b, data, datalen)) != 0)
		fatal_fr(r, "buffer error");
	जर (ssh_संदेश_send(to[1], version, b) == -1)
		fatal_f("couldn't send request");
	sshbuf_reset(b);
	r = ssh_संदेश_recv(from[0], b);
	बंद(from[0]);
	बंद(to[1]);
	जर (r < 0) {
		error_f("no reply");
		जा fail;
	}

	त्रुटि_सं = 0;
	पर्यंत (waitpid(pid, &status, 0) == -1) {
		जर (त्रुटि_सं != EINTR) {
			error_f("waitpid %ld: %s", (दीर्घ)pid, म_त्रुटि(त्रुटि_सं));
			जा fail;
		}
	}
	जर (!WIFEXITED(status)) {
		error_f("exited abnormally");
		जा fail;
	}
	जर (WEXITSTATUS(status) != 0) {
		error_f("exited with status %d", WEXITSTATUS(status));
		जा fail;
	}
	जर ((r = sshbuf_get_u8(b, &rversion)) != 0) {
		error_fr(r, "buffer error");
		जा fail;
	}
	जर (rversion != version) {
		error_f("bad version");
		जा fail;
	}
	जर ((r = sshbuf_get_string(b, sigp, lenp)) != 0) {
		error_fr(r, "buffer error");
 fail:
		ssh_signal(SIGCHLD, osigchld);
		sshbuf_free(b);
		परत -1;
	}
	ssh_signal(SIGCHLD, osigchld);
	sshbuf_free(b);

	परत 0;
}

स्थिर पूर्णांक
userauth_hostbased(संरचना ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	संरचना sshkey *खाजगी = रिक्त;
	संरचना sshbuf *b = रिक्त;
	u_char *sig = रिक्त, *keyblob = रिक्त;
	अक्षर *fp = रिक्त, *chost = रिक्त, *lname = रिक्त;
	माप_प्रकार siglen = 0, keylen = 0;
	पूर्णांक i, r, success = 0;

	जर (authctxt->ktypes == रिक्त) {
		authctxt->oktypes = xstrdup(options.hostbased_accepted_algos);
		authctxt->ktypes = authctxt->oktypes;
	}

	/*
	 * Work through each listed type pattern in HostbasedAcceptedAlgorithms,
	 * trying each hostkey that matches the type in turn.
	 */
	साठी (;;) {
		जर (authctxt->active_ktype == रिक्त)
			authctxt->active_ktype = strsep(&authctxt->ktypes, ",");
		जर (authctxt->active_ktype == रिक्त ||
		    *authctxt->active_ktype == '\0')
			थांबा;
		debug3_f("trying key type %s", authctxt->active_ktype);

		/* check for a useful key */
		खाजगी = रिक्त;
		साठी (i = 0; i < authctxt->sensitive->nkeys; i++) {
			जर (authctxt->sensitive->किल्ल्या[i] == रिक्त ||
			    authctxt->sensitive->किल्ल्या[i]->type == किल्ली_UNSPEC)
				सुरूठेवा;
			जर (!sshkey_match_keyname_to_sigalgs(
			    sshkey_ssh_name(authctxt->sensitive->किल्ल्या[i]),
			    authctxt->active_ktype))
				सुरूठेवा;
			/* we take and free the key */
			खाजगी = authctxt->sensitive->किल्ल्या[i];
			authctxt->sensitive->किल्ल्या[i] = रिक्त;
			थांबा;
		}
		/* Found one */
		जर (खाजगी != रिक्त)
			थांबा;
		/* No more keys of this type; advance */
		authctxt->active_ktype = रिक्त;
	}
	जर (खाजगी == रिक्त) {
		मुक्त(authctxt->oktypes);
		authctxt->oktypes = authctxt->ktypes = रिक्त;
		authctxt->active_ktype = रिक्त;
		debug("No more client hostkeys for hostbased authentication.");
		जा out;
	}

	जर ((fp = sshkey_fingerprint(खाजगी, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == रिक्त) {
		error_f("sshkey_fingerprint failed");
		जा out;
	}
	debug_f("trying hostkey %s %s using sigalg %s",
	    sshkey_ssh_name(खाजगी), fp, authctxt->active_ktype);

	/* figure out a name for the client host */
	lname = get_local_name(ssh_packet_get_connection_in(ssh));
	जर (lname == रिक्त) {
		error_f("cannot get local ipaddr/name");
		जा out;
	}

	/* XXX sshbuf_put_stringf? */
	xasprintf(&chost, "%s.", lname);
	debug2_f("chost %s", chost);

	/* construct data */
	जर ((b = sshbuf_new()) == रिक्त) {
		error_f("sshbuf_new failed");
		जा out;
	}
	जर ((r = sshkey_to_blob(खाजगी, &keyblob, &keylen)) != 0) {
		error_fr(r, "sshkey_to_blob");
		जा out;
	}
	जर ((r = sshbuf_put_stringb(b, ssh->kex->session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_संदेश_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->server_user)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->method->name)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->active_ktype)) != 0 ||
	    (r = sshbuf_put_string(b, keyblob, keylen)) != 0 ||
	    (r = sshbuf_put_cstring(b, chost)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->local_user)) != 0) {
		error_fr(r, "buffer error");
		जा out;
	}

#ifdef DEBUG_PK
	sshbuf_dump(b, मानक_त्रुटि);
#endif
	जर ((r = ssh_keysign(ssh, खाजगी, &sig, &siglen,
	    sshbuf_ptr(b), sshbuf_len(b))) != 0) {
		error("sign using hostkey %s %s failed",
		    sshkey_ssh_name(खाजगी), fp);
		जा out;
	}
	जर ((r = sshpkt_start(ssh, SSH2_संदेश_USERAUTH_REQUEST)) != 0 ||
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
		जा out;
	}
	success = 1;

 out:
	जर (sig != रिक्त)
		freezero(sig, siglen);
	मुक्त(keyblob);
	मुक्त(lname);
	मुक्त(fp);
	मुक्त(chost);
	sshkey_free(खाजगी);
	sshbuf_free(b);

	परत success;
}

/* find auth method */

/*
 * given auth method name, if configurable options permit this method fill
 * in auth_ident field and return true, otherwise return false.
 */
स्थिर पूर्णांक
authmethod_is_enabled(Authmethod *method)
{
	जर (method == रिक्त)
		परत 0;
	/* return false if options indicate this method is disabled */
	जर  (method->enabled == रिक्त || *method->enabled == 0)
		परत 0;
	/* return false if batch mode is enabled but method needs interactive mode */
	जर  (method->batch_flag != रिक्त && *method->batch_flag != 0)
		परत 0;
	परत 1;
}

स्थिर Authmethod *
authmethod_lookup(स्थिरांक अक्षर *name)
{
	Authmethod *method = रिक्त;
	जर (name != रिक्त)
		साठी (method = authmethods; method->name != रिक्त; method++)
			जर (म_भेद(name, method->name) == 0)
				परत method;
	debug2("Unrecognized authentication method name: %s", name ? name : "NULL");
	परत रिक्त;
}

/* XXX internal state */
स्थिर Authmethod *current = रिक्त;
स्थिर अक्षर *supported = रिक्त;
स्थिर अक्षर *preferred = रिक्त;

/*
 * Given the authentication method list sent by the server, return the
 * next method we should try.  If the server initially sends a nil list,
 * use a built-in default list.
 */
स्थिर Authmethod *
authmethod_get(अक्षर *authlist)
{
	अक्षर *name = रिक्त;
	u_int next;

	/* Use a suitable default if we're passed a nil list.  */
	जर (authlist == रिक्त || म_माप(authlist) == 0)
		authlist = options.preferred_authentications;

	जर (supported == रिक्त || म_भेद(authlist, supported) != 0) {
		debug3("start over, passed a different list %s", authlist);
		मुक्त(supported);
		supported = xstrdup(authlist);
		preferred = options.preferred_authentications;
		debug3("preferred %s", preferred);
		current = रिक्त;
	} अन्यथा जर (current != रिक्त && authmethod_is_enabled(current))
		परत current;

	साठी (;;) {
		जर ((name = match_list(preferred, supported, &next)) == रिक्त) {
			debug("No more authentication methods to try.");
			current = रिक्त;
			परत रिक्त;
		}
		preferred += next;
		debug3("authmethod_lookup %s", name);
		debug3("remaining preferred: %s", preferred);
		जर ((current = authmethod_lookup(name)) != रिक्त &&
		    authmethod_is_enabled(current)) {
			debug3("authmethod_is_enabled %s", name);
			debug("Next authentication method: %s", name);
			मुक्त(name);
			परत current;
		}
		मुक्त(name);
	}
}

स्थिर अक्षर *
authmethods_get(शून्य)
{
	Authmethod *method = रिक्त;
	संरचना sshbuf *b;
	अक्षर *list;
	पूर्णांक r;

	जर ((b = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	साठी (method = authmethods; method->name != रिक्त; method++) {
		जर (authmethod_is_enabled(method)) {
			जर ((r = sshbuf_putf(b, "%s%s",
			    sshbuf_len(b) ? "," : "", method->name)) != 0)
				fatal_fr(r, "buffer error");
		}
	}
	जर ((list = sshbuf_dup_string(b)) == रिक्त)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	परत list;
}
