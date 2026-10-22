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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/socket.h>
#समावेश <sys/wait.h>
#समावेश <sys/queue.h>
#समावेश <sys/stat.h>

#समावेश <errno.h>
#समावेश <fcntl.h>
#समावेश <limits.h>
#समावेश <pwd.h>
#समावेश <signal.h>
#समावेश <stdio.h>
#समावेश <string.h>
#समावेश <stdarg.h>
#समावेश <unistd.h>
#अगर defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
#समावेश <vis.h>
#पूर्ण_अगर

#समावेश "xmalloc.h"
#समावेश "ssh.h"
#समावेश "ssh2.h"
#समावेश "sshbuf.h"
#समावेश "packet.h"
#समावेश "compat.h"
#समावेश "cipher.h"
#समावेश "sshkey.h"
#समावेश "kex.h"
#समावेश "sshconnect.h"
#समावेश "authfile.h"
#समावेश "authfd.h"
#समावेश "log.h"
#समावेश "misc.h"
#समावेश "readconf.h"
#समावेश "match.h"
#समावेश "dispatch.h"
#समावेश "canohost.h"
#समावेश "msg.h"
#समावेश "pathnames.h"
#समावेश "hostfile.h"
#समावेश "ssherr.h"
#समावेश "utf8.h"
#समावेश "ssh-sk.h"
#समावेश "sk-api.h"

#अगर_घोषित GSSAPI
#समावेश "ssh-gss.h"
#पूर्ण_अगर

/* import */
बाह्य Options options;

/*
 * SSH2 key exchange
 */

अटल अक्षर *xxx_host;
अटल काष्ठा sockaddr_storage xxx_hostaddr;
अटल स्थिर काष्ठा ssh_conn_info *xxx_conn_info;
अटल पूर्णांक कुंजी_type_allowed(काष्ठा sshkey *, स्थिर अक्षर *);

अटल पूर्णांक
verify_host_कुंजी_callback(काष्ठा sshkey *hostkey, काष्ठा ssh *ssh)
{
	पूर्णांक r;

	अगर ((r = sshkey_check_rsa_लंबाई(hostkey,
	    options.required_rsa_आकार)) != 0)
		fatal_r(r, "Bad server host key");
	अगर (!कुंजी_type_allowed(hostkey, options.hostkeyalgorithms)) {
		fatal("Server host key %s not in HostKeyAlgorithms",
		    sshkey_ssh_name(hostkey));
	}
	अगर (verify_host_कुंजी(xxx_host, (काष्ठा sockaddr *)&xxx_hostaddr, hostkey,
	    xxx_conn_info) != 0)
		fatal("Host key verification failed.");
	वापस 0;
}

/* Returns the first item from a comma-separated algorithm list */
अटल अक्षर *
first_alg(स्थिर अक्षर *algs)
{
	अक्षर *ret, *cp;

	ret = xstrdup(algs);
	अगर ((cp = म_अक्षर(ret, ',')) != शून्य)
		*cp = '\0';
	वापस ret;
}

अटल अक्षर *
order_hostkeyalgs(अक्षर *host, काष्ठा sockaddr *hostaddr, u_short port,
    स्थिर काष्ठा ssh_conn_info *cinfo)
{
	अक्षर *oavail = शून्य, *avail = शून्य, *first = शून्य, *last = शून्य;
	अक्षर *alg = शून्य, *hostname = शून्य, *ret = शून्य, *best = शून्य;
	माप_प्रकार maxlen;
	काष्ठा hostkeys *hostkeys = शून्य;
	पूर्णांक ktype;
	u_int i;

	/* Find all hostkeys for this hostname */
	get_hostfile_hostname_ipaddr(host, hostaddr, port, &hostname, शून्य);
	hostkeys = init_hostkeys();
	क्रम (i = 0; i < options.अंक_user_hostfiles; i++)
		load_hostkeys(hostkeys, hostname, options.user_hostfiles[i], 0);
	क्रम (i = 0; i < options.अंक_system_hostfiles; i++) {
		load_hostkeys(hostkeys, hostname,
		    options.system_hostfiles[i], 0);
	}
	अगर (options.known_hosts_command != शून्य) {
		load_hostkeys_command(hostkeys, options.known_hosts_command,
		    "ORDER", cinfo, शून्य, hostname);
	}
	/*
	 * If a plain public key exists that matches the type of the best
	 * preference HostkeyAlgorithms, then use the whole list as is.
	 * Note that we ignore whether the best preference algorithm is a
	 * certificate type, as sshconnect.c will downgrade certs to
	 * plain keys if necessary.
	 */
	best = first_alg(options.hostkeyalgorithms);
	अगर (lookup_कुंजी_in_hostkeys_by_type(hostkeys,
	    sshkey_type_plain(sshkey_type_from_name(best)),
	    sshkey_ecdsa_nid_from_name(best), शून्य)) {
		debug3_f("have matching best-preference key type %s, "
		    "using HostkeyAlgorithms verbatim", best);
		ret = xstrdup(options.hostkeyalgorithms);
		जाओ out;
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

#घोषणा ALG_APPEND(to, from) \
	करो { \
		अगर (*to != '\0') \
			strlcat(to, ",", maxlen); \
		strlcat(to, from, maxlen); \
	} जबतक (0)

	जबतक ((alg = strsep(&avail, ",")) && *alg != '\0') {
		अगर ((ktype = sshkey_type_from_name(alg)) == कुंजी_UNSPEC)
			fatal_f("unknown alg %s", alg);
		/*
		 * If we have a @cert-authority marker in known_hosts then
		 * prefer all certificate algorithms.
		 */
		अगर (sshkey_type_is_cert(ktype) &&
		    lookup_marker_in_hostkeys(hostkeys, MRK_CA)) {
			ALG_APPEND(first, alg);
			जारी;
		}
		/* If the key appears in known_hosts then prefer it */
		अगर (lookup_कुंजी_in_hostkeys_by_type(hostkeys,
		    sshkey_type_plain(ktype),
		    sshkey_ecdsa_nid_from_name(alg), शून्य)) {
			ALG_APPEND(first, alg);
			जारी;
		}
		/* Otherwise, put it last */
		ALG_APPEND(last, alg);
	}
#अघोषित ALG_APPEND
	xasprintf(&ret, "%s%s%s", first,
	    (*first == '\0' || *last == '\0') ? "" : ",", last);
	अगर (*first != '\0')
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

	वापस ret;
}

व्योम
ssh_kex2(काष्ठा ssh *ssh, अक्षर *host, काष्ठा sockaddr_storage *hostaddr,
    u_short port, स्थिर काष्ठा ssh_conn_info *cinfo)
{
	अक्षर *myproposal[PROPOSAL_MAX];
	अक्षर *all_कुंजी, *hkalgs = शून्य;
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
	अगर (options.hostkeyalgorithms == शून्य ||
	    options.hostkeyalgorithms[0] == '-' ||
	    options.hostkeyalgorithms[0] == '+')
		use_known_hosts_order = 1;

	/* Expand or fill in HostkeyAlgorithms */
	all_कुंजी = sshkey_alg_list(0, 0, 1, ',');
	अगर ((r = kex_assemble_names(&options.hostkeyalgorithms,
	    kex_default_pk_alg(), all_कुंजी)) != 0)
		fatal_fr(r, "kex_assemble_namelist");
	मुक्त(all_कुंजी);

	अगर (use_known_hosts_order) {
		hkalgs = order_hostkeyalgs(host, (काष्ठा sockaddr *)hostaddr,
		    port, cinfo);
	}

	kex_proposal_populate_entries(ssh, myproposal,
	    options.kex_algorithms, options.ciphers, options.macs,
	    compression_alg_list(options.compression),
	    hkalgs ? hkalgs : options.hostkeyalgorithms);

	मुक्त(hkalgs);

	/* start key exchange */
	अगर ((r = kex_setup(ssh, myproposal)) != 0)
		fatal_r(r, "kex_setup");
#अगर_घोषित WITH_OPENSSL
	ssh->kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GEX_SHA1] = kexgex_client;
	ssh->kex->kex[KEX_DH_GEX_SHA256] = kexgex_client;
	ssh->kex->kex[KEX_ECDH_SHA2] = kex_gen_client;
#पूर्ण_अगर
	ssh->kex->kex[KEX_C25519_SHA256] = kex_gen_client;
	ssh->kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_client;
	ssh->kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_client;
	ssh->kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_client;
	ssh->kex->verify_host_कुंजी=&verify_host_कुंजी_callback;

	ssh_dispatch_run_fatal(ssh, DISPATCH_BLOCK, &ssh->kex->done);
	kex_proposal_free_entries(myproposal);

#अगर_घोषित DEBUG_KEXDH
	/* send 1st encrypted/maced/compressed message */
	अगर ((r = sshpkt_start(ssh, SSH2_संदेश_IGNORE)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "markus")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send packet");
#पूर्ण_अगर
}

/*
 * Authenticate user
 */

प्रकार काष्ठा cauthctxt Authctxt;
प्रकार काष्ठा cauthmethod Authmethod;
प्रकार काष्ठा identity Identity;
प्रकार काष्ठा idlist Idlist;

काष्ठा identity {
	TAILQ_ENTRY(identity) अग्र;
	पूर्णांक	agent_fd;		/* >=0 if agent supports key */
	काष्ठा sshkey	*कुंजी;		/* public/private key */
	अक्षर	*filename;		/* comment for agent-only keys */
	पूर्णांक	tried;
	पूर्णांक	isprivate;		/* key points to the private key */
	पूर्णांक	userprovided;
};
TAILQ_HEAD(idlist, identity);

काष्ठा cauthctxt {
	स्थिर अक्षर *server_user;
	स्थिर अक्षर *local_user;
	स्थिर अक्षर *host;
	स्थिर अक्षर *service;
	काष्ठा cauthmethod *method;
	संक_पूर्ण_प्रकार success;
	अक्षर *authlist;
#अगर_घोषित GSSAPI
	/* gssapi */
	gss_OID_set gss_supported_mechs;
	u_int mech_tried;
#पूर्ण_अगर
	/* pubkey */
	काष्ठा idlist कुंजियाँ;
	पूर्णांक agent_fd;
	/* hostbased */
	Sensitive *sensitive;
	अक्षर *oktypes, *ktypes;
	स्थिर अक्षर *active_ktype;
	/* kbd-interactive */
	पूर्णांक info_req_seen;
	पूर्णांक attempt_kbdint;
	/* password */
	पूर्णांक attempt_passwd;
	/* generic */
	व्योम *methoddata;
};

काष्ठा cauthmethod {
	अक्षर	*name;		/* string to compare against server's list */
	पूर्णांक	(*userauth)(काष्ठा ssh *ssh);
	व्योम	(*cleanup)(काष्ठा ssh *ssh);
	पूर्णांक	*enabled;	/* flag in option struct that enables method */
	पूर्णांक	*batch_flag;	/* flag in option struct that disables method */
};

अटल पूर्णांक निवेश_userauth_service_accept(पूर्णांक, uint32_t, काष्ठा ssh *);
अटल पूर्णांक निवेश_userauth_success(पूर्णांक, uint32_t, काष्ठा ssh *);
अटल पूर्णांक निवेश_userauth_failure(पूर्णांक, uint32_t, काष्ठा ssh *);
अटल पूर्णांक निवेश_userauth_banner(पूर्णांक, uint32_t, काष्ठा ssh *);
अटल पूर्णांक निवेश_userauth_error(पूर्णांक, uint32_t, काष्ठा ssh *);
अटल पूर्णांक निवेश_userauth_info_req(पूर्णांक, uint32_t, काष्ठा ssh *);
अटल पूर्णांक निवेश_userauth_pk_ok(पूर्णांक, uint32_t, काष्ठा ssh *);
अटल पूर्णांक निवेश_userauth_passwd_changereq(पूर्णांक, uint32_t, काष्ठा ssh *);

अटल पूर्णांक userauth_none(काष्ठा ssh *);
अटल पूर्णांक userauth_pubkey(काष्ठा ssh *);
अटल पूर्णांक userauth_passwd(काष्ठा ssh *);
अटल पूर्णांक userauth_kbdint(काष्ठा ssh *);
अटल पूर्णांक userauth_hostbased(काष्ठा ssh *);

#अगर_घोषित GSSAPI
अटल पूर्णांक userauth_gssapi(काष्ठा ssh *);
अटल व्योम userauth_gssapi_cleanup(काष्ठा ssh *);
अटल पूर्णांक निवेश_gssapi_response(पूर्णांक type, uint32_t, काष्ठा ssh *);
अटल पूर्णांक निवेश_gssapi_token(पूर्णांक type, uint32_t, काष्ठा ssh *);
अटल पूर्णांक निवेश_gssapi_error(पूर्णांक, uint32_t, काष्ठा ssh *);
अटल पूर्णांक निवेश_gssapi_errtok(पूर्णांक, uint32_t, काष्ठा ssh *);
#पूर्ण_अगर

व्योम	userauth(काष्ठा ssh *, अक्षर *);

अटल व्योम pubkey_cleanup(काष्ठा ssh *);
अटल पूर्णांक sign_and_send_pubkey(काष्ठा ssh *ssh, Identity *);
अटल व्योम pubkey_prepare(काष्ठा ssh *, Authctxt *);
अटल व्योम pubkey_reset(Authctxt *);
अटल काष्ठा sshkey *load_identity_file(Identity *);

अटल Authmethod *authmethod_get(अक्षर *authlist);
अटल Authmethod *authmethod_lookup(स्थिर अक्षर *name);
अटल अक्षर *authmethods_get(व्योम);

Authmethod authmethods[] = {
#अगर_घोषित GSSAPI
	{"gssapi-with-mic",
		userauth_gssapi,
		userauth_gssapi_cleanup,
		&options.gss_authentication,
		शून्य},
#पूर्ण_अगर
	{"hostbased",
		userauth_hostbased,
		शून्य,
		&options.hostbased_authentication,
		शून्य},
	{"publickey",
		userauth_pubkey,
		शून्य,
		&options.pubkey_authentication,
		शून्य},
	{"keyboard-interactive",
		userauth_kbdint,
		शून्य,
		&options.kbd_interactive_authentication,
		&options.batch_mode},
	{"password",
		userauth_passwd,
		शून्य,
		&options.password_authentication,
		&options.batch_mode},
	{"none",
		userauth_none,
		शून्य,
		शून्य,
		शून्य},
	{शून्य, शून्य, शून्य, शून्य, शून्य}
};

व्योम
ssh_userauth2(काष्ठा ssh *ssh, स्थिर अक्षर *local_user,
    स्थिर अक्षर *server_user, अक्षर *host, Sensitive *sensitive)
{
	Authctxt authctxt;
	पूर्णांक r;

	अगर (options.preferred_authentications == शून्य)
		options.preferred_authentications = authmethods_get();

	/* setup authentication context */
	स_रखो(&authctxt, 0, माप(authctxt));
	authctxt.server_user = server_user;
	authctxt.local_user = local_user;
	authctxt.host = host;
	authctxt.service = "ssh-connection";		/* service name */
	authctxt.success = 0;
	authctxt.method = authmethod_lookup("none");
	authctxt.authlist = शून्य;
	authctxt.methoddata = शून्य;
	authctxt.sensitive = sensitive;
	authctxt.active_ktype = authctxt.oktypes = authctxt.ktypes = शून्य;
	authctxt.info_req_seen = 0;
	authctxt.attempt_kbdint = 0;
	authctxt.attempt_passwd = 0;
#अगर GSSAPI
	authctxt.gss_supported_mechs = शून्य;
	authctxt.mech_tried = 0;
#पूर्ण_अगर
	authctxt.agent_fd = -1;
	अगर (authctxt.method == शून्य)
		fatal_f("internal error: cannot send userauth none request");

	अगर ((r = sshpkt_start(ssh, SSH2_संदेश_SERVICE_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "ssh-userauth")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh->authctxt = &authctxt;
	ssh_dispatch_init(ssh, &निवेश_userauth_error);
	ssh_dispatch_set(ssh, SSH2_संदेश_EXT_INFO, kex_निवेश_ext_info);
	ssh_dispatch_set(ssh, SSH2_संदेश_SERVICE_ACCEPT, &निवेश_userauth_service_accept);
	ssh_dispatch_run_fatal(ssh, DISPATCH_BLOCK, &authctxt.success);	/* loop until success */
	pubkey_cleanup(ssh);
#अगर_घोषित GSSAPI
	अगर (authctxt.gss_supported_mechs != शून्य) {
		u_int ms;

		gss_release_oid_set(&ms, &authctxt.gss_supported_mechs);
		authctxt.gss_supported_mechs = शून्य;
	}
#पूर्ण_अगर
	ssh->authctxt = शून्य;

	ssh_dispatch_range(ssh, SSH2_संदेश_USERAUTH_MIN, SSH2_संदेश_USERAUTH_MAX, शून्य);

	अगर (!authctxt.success)
		fatal("Authentication failed.");
	अगर (ssh_packet_connection_is_on_socket(ssh)) {
		verbose("Authenticated to %s ([%s]:%d) using \"%s\".", host,
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    authctxt.method->name);
	} अन्यथा {
		verbose("Authenticated to %s (via proxy) using \"%s\".", host,
		    authctxt.method->name);
	}
}

अटल पूर्णांक
निवेश_userauth_service_accept(पूर्णांक type, uint32_t seq, काष्ठा ssh *ssh)
{
	पूर्णांक r;

	अगर (ssh_packet_remaining(ssh) > 0) {
		अक्षर *reply;

		अगर ((r = sshpkt_get_cstring(ssh, &reply, शून्य)) != 0)
			जाओ out;
		debug2("service_accept: %s", reply);
		मुक्त(reply);
	} अन्यथा {
		debug2("buggy server: service_accept w/o service");
	}
	अगर ((r = sshpkt_get_end(ssh)) != 0)
		जाओ out;
	debug("SSH2_MSG_SERVICE_ACCEPT received");

	/* initial userauth request */
	userauth_none(ssh);

	/* accept EXT_INFO at any time during userauth */
	ssh_dispatch_set(ssh, SSH2_संदेश_EXT_INFO, ssh->kex->ext_info_s ?
	    &kex_निवेश_ext_info : &निवेश_userauth_error);
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_SUCCESS, &निवेश_userauth_success);
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_FAILURE, &निवेश_userauth_failure);
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_BANNER, &निवेश_userauth_banner);
	r = 0;
 out:
	वापस r;
}

व्योम
userauth(काष्ठा ssh *ssh, अक्षर *authlist)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;

	अगर (authctxt->method != शून्य && authctxt->method->cleanup != शून्य)
		authctxt->method->cleanup(ssh);

	मुक्त(authctxt->methoddata);
	authctxt->methoddata = शून्य;
	अगर (authlist == शून्य) {
		authlist = authctxt->authlist;
	} अन्यथा {
		मुक्त(authctxt->authlist);
		authctxt->authlist = authlist;
	}
	क्रम (;;) {
		Authmethod *method = authmethod_get(authlist);
		अगर (method == शून्य)
			fatal("%s@%s: Permission denied (%s).",
			    authctxt->server_user, authctxt->host, authlist);
		authctxt->method = method;

		/* reset the per method handler */
		ssh_dispatch_range(ssh, SSH2_संदेश_USERAUTH_PER_METHOD_MIN,
		    SSH2_संदेश_USERAUTH_PER_METHOD_MAX, शून्य);

		/* and try new method */
		अगर (method->userauth(ssh) != 0) {
			debug2("we sent a %s packet, wait for reply", method->name);
			अवरोध;
		} अन्यथा {
			debug2("we did not send a packet, disable method");
			method->enabled = शून्य;
		}
	}
}

अटल पूर्णांक
निवेश_userauth_error(पूर्णांक type, uint32_t seq, काष्ठा ssh *ssh)
{
	fatal_f("bad message during authentication: type %d", type);
	वापस 0;
}

अटल पूर्णांक
निवेश_userauth_banner(पूर्णांक type, uint32_t seq, काष्ठा ssh *ssh)
{
	अक्षर *संदेश = शून्य;
	माप_प्रकार len;
	पूर्णांक r;

	debug3_f("entering");
	अगर ((r = sshpkt_get_cstring(ssh, &संदेश, &len)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, शून्य, शून्य)) != 0)
		जाओ out;
	अगर (len > 0 && options.log_level >= SYSLOG_LEVEL_INFO)
		fmprintf(मानक_त्रुटि, "%s", संदेश);
	r = 0;
 out:
	मुक्त(संदेश);
	वापस r;
}

अटल पूर्णांक
निवेश_userauth_success(पूर्णांक type, uint32_t seq, काष्ठा ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	अगर (authctxt == शून्य)
		fatal_f("no authentication context");
	मुक्त(authctxt->authlist);
	authctxt->authlist = शून्य;
	अगर (authctxt->method != शून्य && authctxt->method->cleanup != शून्य)
		authctxt->method->cleanup(ssh);
	मुक्त(authctxt->methoddata);
	authctxt->methoddata = शून्य;
	authctxt->success = 1;			/* break out */
	ssh_dispatch_set(ssh, SSH2_संदेश_EXT_INFO, dispatch_protocol_error);
	वापस 0;
}

#अगर 0
अटल पूर्णांक
निवेश_userauth_success_unexpected(पूर्णांक type, uint32_t seq, काष्ठा ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	अगर (authctxt == शून्य)
		fatal_f("no authentication context");

	fatal("Unexpected authentication success during %s.",
	    authctxt->method->name);
	वापस 0;
}
#पूर्ण_अगर

अटल पूर्णांक
निवेश_userauth_failure(पूर्णांक type, uint32_t seq, काष्ठा ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	अक्षर *authlist = शून्य;
	u_char partial;

	अगर (authctxt == शून्य)
		fatal("input_userauth_failure: no authentication context");

	अगर (sshpkt_get_cstring(ssh, &authlist, शून्य) != 0 ||
	    sshpkt_get_u8(ssh, &partial) != 0 ||
	    sshpkt_get_end(ssh) != 0)
		जाओ out;

	अगर (partial != 0) {
		verbose("Authenticated using \"%s\" with partial success.",
		    authctxt->method->name);
		/* reset state */
		pubkey_reset(authctxt);
	}
	debug("Authentications that can continue: %s", authlist);

	userauth(ssh, authlist);
	authlist = शून्य;
 out:
	मुक्त(authlist);
	वापस 0;
}

/*
 * Format an identity for logging including filename, key type, fingerprint
 * and location (agent, etc.). Caller must free.
 */
अटल अक्षर *
format_identity(Identity *id)
{
	अक्षर *fp = शून्य, *ret = शून्य;
	स्थिर अक्षर *note = "";

	अगर (id->कुंजी != शून्य) {
		fp = sshkey_fingerprint(id->कुंजी, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
	}
	अगर (id->कुंजी) {
		अगर ((id->कुंजी->flags & SSHKEY_FLAG_EXT) != 0)
			note = " token";
		अन्यथा अगर (sshkey_is_sk(id->कुंजी))
			note = " authenticator";
	}
	xasprintf(&ret, "%s %s%s%s%s%s%s",
	    id->filename,
	    id->कुंजी ? sshkey_type(id->कुंजी) : "", id->कुंजी ? " " : "",
	    fp ? fp : "",
	    id->userprovided ? " explicit" : "", note,
	    id->agent_fd != -1 ? " agent" : "");
	मुक्त(fp);
	वापस ret;
}

अटल पूर्णांक
निवेश_userauth_pk_ok(पूर्णांक type, uint32_t seq, काष्ठा ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	काष्ठा sshkey *कुंजी = शून्य;
	काष्ठा sshbuf *keyblob = शून्य;
	Identity *id = शून्य;
	पूर्णांक pktype, found = 0, sent = 0;
	अक्षर *pkalg = शून्य, *fp = शून्य, *ident = शून्य;
	पूर्णांक r;

	अगर (authctxt == शून्य)
		fatal_f("no authentication context");

	अगर ((r = sshpkt_get_cstring(ssh, &pkalg, शून्य)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		जाओ done;

	अगर (match_pattern_list(pkalg, options.pubkey_accepted_algos, 0) != 1) {
		error_f("server replied to PK_OK with signature type %s not "
		    "in PubkeyAcceptedAlgorithms", pkalg);
		r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		जाओ done;
	}
	अगर ((pktype = sshkey_type_from_name(pkalg)) == कुंजी_UNSPEC) {
		debug_f("server sent unknown pkalg %s", pkalg);
		r = SSH_ERR_INVALID_FORMAT;
		जाओ done;
	}
	/* inner key type should match signature type */
	अगर ((r = sshkey_fromb_allowlist(keyblob, &कुंजी, pkalg, शून्य)) != 0) {
		debug_r(r, "no key from blob. pkalg %s", pkalg);
		जाओ done;
	}
	अगर (कुंजी->type != pktype) {
		error("input_userauth_pk_ok: type mismatch "
		    "for decoded key (received %d, expected %d)",
		    कुंजी->type, pktype);
		r = SSH_ERR_INVALID_FORMAT;
		जाओ done;
	}

	/*
	 * search keys in the reverse order, because last candidate has been
	 * moved to the end of the queue.  this also avoids confusion by
	 * duplicate keys
	 */
	TAILQ_FOREACH_REVERSE(id, &authctxt->कुंजियाँ, idlist, अग्र) {
		अगर (sshkey_equal(कुंजी, id->कुंजी)) {
			found = 1;
			अवरोध;
		}
	}
	अगर (!found || id == शून्य) {
		fp = sshkey_fingerprint(कुंजी, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		error_f("server replied with unknown key: %s %s",
		    sshkey_type(कुंजी), fp == शून्य ? "<ERROR>" : fp);
		r = SSH_ERR_INVALID_FORMAT;
		जाओ done;
	}
	ident = format_identity(id);
	debug("Server accepts key: %s", ident);
	sent = sign_and_send_pubkey(ssh, id);
	r = 0;
 done:
	sshkey_free(कुंजी);
	sshbuf_free(keyblob);
	मुक्त(ident);
	मुक्त(fp);
	मुक्त(pkalg);

	/* try another method if we did not send a packet */
	अगर (r == 0 && sent == 0)
		userauth(ssh, शून्य);
	वापस r;
}

#अगर_घोषित GSSAPI
अटल पूर्णांक
userauth_gssapi(काष्ठा ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Gssctxt *gssctxt = शून्य;
	OM_uint32 min;
	पूर्णांक r, ok = 0;
	gss_OID mech = शून्य;

	/* Try one GSSAPI method at a time, rather than sending them all at
	 * once. */

	अगर (authctxt->gss_supported_mechs == शून्य)
		gss_indicate_mechs(&min, &authctxt->gss_supported_mechs);

	/* Check to see whether the mechanism is usable before we offer it */
	जबतक (authctxt->mech_tried < authctxt->gss_supported_mechs->गिनती &&
	    !ok) {
		mech = &authctxt->gss_supported_mechs->
		    elements[authctxt->mech_tried];
		/* My DER encoding requires length<128 */
		अगर (mech->लंबाई < 128 && ssh_gssapi_check_mechanism(&gssctxt,
		    mech, authctxt->host)) {
			ok = 1; /* Mechanism works */
		} अन्यथा {
			authctxt->mech_tried++;
		}
	}

	अगर (!ok || mech == शून्य)
		वापस 0;

	authctxt->methoddata=(व्योम *)gssctxt;

	अगर ((r = sshpkt_start(ssh, SSH2_संदेश_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_u32(ssh, 1)) != 0 ||
	    (r = sshpkt_put_u32(ssh, (mech->लंबाई) + 2)) != 0 ||
	    (r = sshpkt_put_u8(ssh, SSH_GSS_OIDTYPE)) != 0 ||
	    (r = sshpkt_put_u8(ssh, mech->लंबाई)) != 0 ||
	    (r = sshpkt_put(ssh, mech->elements, mech->लंबाई)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_GSSAPI_RESPONSE, &निवेश_gssapi_response);
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_GSSAPI_TOKEN, &निवेश_gssapi_token);
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_GSSAPI_ERROR, &निवेश_gssapi_error);
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_GSSAPI_ERRTOK, &निवेश_gssapi_errtok);

	authctxt->mech_tried++; /* Move along to next candidate */

	वापस 1;
}

अटल व्योम
userauth_gssapi_cleanup(काष्ठा ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Gssctxt *gssctxt = (Gssctxt *)authctxt->methoddata;

	ssh_gssapi_delete_ctx(&gssctxt);
	authctxt->methoddata = शून्य;
}

अटल OM_uint32
process_gssapi_token(काष्ठा ssh *ssh, gss_बफर_t recv_tok)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt = authctxt->methoddata;
	gss_बफर_desc send_tok = GSS_C_EMPTY_बफर;
	gss_बफर_desc mic = GSS_C_EMPTY_बफर;
	gss_बफर_desc gssbuf;
	OM_uint32 status, ms, flags;
	पूर्णांक r;

	status = ssh_gssapi_init_ctx(gssctxt, options.gss_deleg_creds,
	    recv_tok, &send_tok, &flags);

	अगर (send_tok.लंबाई > 0) {
		u_char type = GSS_ERROR(status) ?
		    SSH2_संदेश_USERAUTH_GSSAPI_ERRTOK :
		    SSH2_संदेश_USERAUTH_GSSAPI_TOKEN;

		अगर ((r = sshpkt_start(ssh, type)) != 0 ||
		    (r = sshpkt_put_string(ssh, send_tok.मूल्य,
		    send_tok.लंबाई)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send %u packet", type);

		gss_release_बफर(&ms, &send_tok);
	}

	अगर (status == GSS_S_COMPLETE) {
		/* send either complete or MIC, depending on mechanism */
		अगर (!(flags & GSS_C_INTEG_FLAG)) {
			अगर ((r = sshpkt_start(ssh,
			    SSH2_संदेश_USERAUTH_GSSAPI_EXCHANGE_COMPLETE)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "send completion");
		} अन्यथा {
			काष्ठा sshbuf *b;

			अगर ((b = sshbuf_new()) == शून्य)
				fatal_f("sshbuf_new failed");
			ssh_gssapi_buildmic(b, authctxt->server_user,
			    authctxt->service, "gssapi-with-mic",
			    ssh->kex->session_id);

			अगर ((gssbuf.मूल्य = sshbuf_mutable_ptr(b)) == शून्य)
				fatal_f("sshbuf_mutable_ptr failed");
			gssbuf.लंबाई = sshbuf_len(b);

			status = ssh_gssapi_sign(gssctxt, &gssbuf, &mic);

			अगर (!GSS_ERROR(status)) {
				अगर ((r = sshpkt_start(ssh,
				    SSH2_संदेश_USERAUTH_GSSAPI_MIC)) != 0 ||
				    (r = sshpkt_put_string(ssh, mic.मूल्य,
				    mic.लंबाई)) != 0 ||
				    (r = sshpkt_send(ssh)) != 0)
					fatal_fr(r, "send MIC");
			}

			sshbuf_free(b);
			gss_release_बफर(&ms, &mic);
		}
	}

	वापस status;
}

अटल पूर्णांक
निवेश_gssapi_response(पूर्णांक type, uint32_t plen, काष्ठा ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	माप_प्रकार oidlen;
	u_char *oidv = शून्य;
	पूर्णांक r;

	अगर (authctxt == शून्य)
		fatal("input_gssapi_response: no authentication context");
	gssctxt = authctxt->methoddata;

	/* Setup our OID */
	अगर ((r = sshpkt_get_string(ssh, &oidv, &oidlen)) != 0)
		जाओ done;

	अगर (oidlen <= 2 ||
	    oidv[0] != SSH_GSS_OIDTYPE ||
	    oidv[1] != oidlen - 2) {
		debug("Badly encoded mechanism OID received");
		userauth(ssh, शून्य);
		जाओ ok;
	}

	अगर (!ssh_gssapi_check_oid(gssctxt, oidv + 2, oidlen - 2))
		fatal("Server returned different OID than expected");

	अगर ((r = sshpkt_get_end(ssh)) != 0)
		जाओ done;

	अगर (GSS_ERROR(process_gssapi_token(ssh, GSS_C_NO_बफर))) {
		/* Start again with next method on list */
		debug("Trying to start again");
		userauth(ssh, शून्य);
		जाओ ok;
	}
 ok:
	r = 0;
 done:
	मुक्त(oidv);
	वापस r;
}

अटल पूर्णांक
निवेश_gssapi_token(पूर्णांक type, uint32_t plen, काष्ठा ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	gss_बफर_desc recv_tok;
	u_char *p = शून्य;
	माप_प्रकार len;
	OM_uint32 status;
	पूर्णांक r;

	अगर (authctxt == शून्य)
		fatal("input_gssapi_response: no authentication context");

	अगर ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		जाओ out;

	recv_tok.मूल्य = p;
	recv_tok.लंबाई = len;
	status = process_gssapi_token(ssh, &recv_tok);

	/* Start again with the next method in the list */
	अगर (GSS_ERROR(status)) {
		userauth(ssh, शून्य);
		/* ok */
	}
	r = 0;
 out:
	मुक्त(p);
	वापस r;
}

अटल पूर्णांक
निवेश_gssapi_errtok(पूर्णांक type, uint32_t plen, काष्ठा ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	gss_बफर_desc send_tok = GSS_C_EMPTY_बफर;
	gss_बफर_desc recv_tok;
	OM_uint32 ms;
	u_char *p = शून्य;
	माप_प्रकार len;
	पूर्णांक r;

	अगर (authctxt == शून्य)
		fatal("input_gssapi_response: no authentication context");
	gssctxt = authctxt->methoddata;

	अगर ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0) {
		मुक्त(p);
		वापस r;
	}

	/* Stick it into GSSAPI and see what it says */
	recv_tok.मूल्य = p;
	recv_tok.लंबाई = len;
	(व्योम)ssh_gssapi_init_ctx(gssctxt, options.gss_deleg_creds,
	    &recv_tok, &send_tok, शून्य);
	मुक्त(p);
	gss_release_बफर(&ms, &send_tok);

	/* Server will be returning a failed packet after this one */
	वापस 0;
}

अटल पूर्णांक
निवेश_gssapi_error(पूर्णांक type, uint32_t plen, काष्ठा ssh *ssh)
{
	अक्षर *संदेश = शून्य;
	अक्षर *lang = शून्य;
	पूर्णांक r;

	अगर ((r = sshpkt_get_u32(ssh, शून्य)) != 0 ||	/* maj */
	    (r = sshpkt_get_u32(ssh, शून्य)) != 0 ||	/* min */
	    (r = sshpkt_get_cstring(ssh, &संदेश, शून्य)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, शून्य)) != 0)
		जाओ out;
	r = sshpkt_get_end(ssh);
	debug("Server GSSAPI Error:\n%s", संदेश);
 out:
	मुक्त(संदेश);
	मुक्त(lang);
	वापस r;
}
#पूर्ण_अगर /* GSSAPI */

अटल पूर्णांक
userauth_none(काष्ठा ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	पूर्णांक r;

	/* initial userauth request */
	अगर ((r = sshpkt_start(ssh, SSH2_संदेश_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	वापस 1;
}

अटल पूर्णांक
userauth_passwd(काष्ठा ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	अक्षर *password, *prompt = शून्य;
	स्थिर अक्षर *host = options.host_कुंजी_alias ?  options.host_कुंजी_alias :
	    authctxt->host;
	पूर्णांक r;

	अगर (authctxt->attempt_passwd++ >= options.संख्या_of_password_prompts)
		वापस 0;

	अगर (authctxt->attempt_passwd != 1)
		error("Permission denied, please try again.");

	xasprintf(&prompt, "%s@%s's password: ", authctxt->server_user, host);
	password = read_passphrase(prompt, 0);
	अगर ((r = sshpkt_start(ssh, SSH2_संदेश_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, password)) != 0 ||
	    (r = sshpkt_add_padding(ssh, 64)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	मुक्त(prompt);
	अगर (password != शून्य)
		freezero(password, म_माप(password));

	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_PASSWD_CHANGEREQ,
	    &निवेश_userauth_passwd_changereq);

	वापस 1;
}

/*
 * parse PASSWD_CHANGEREQ, prompt user and send SSH2_MSG_USERAUTH_REQUEST
 */
अटल पूर्णांक
निवेश_userauth_passwd_changereq(पूर्णांक type, uint32_t seqnr, काष्ठा ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	अक्षर *info = शून्य, *lang = शून्य, *password = शून्य, *retype = शून्य;
	अक्षर prompt[256];
	स्थिर अक्षर *host;
	पूर्णांक r, addnl;
	माप_प्रकार len;

	debug2("input_userauth_passwd_changereq");

	अगर (authctxt == शून्य)
		fatal("input_userauth_passwd_changereq: "
		    "no authentication context");
	host = options.host_कुंजी_alias ? options.host_कुंजी_alias : authctxt->host;

	अगर ((r = sshpkt_get_cstring(ssh, &info, शून्य)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, शून्य)) != 0)
		जाओ out;
	अगर ((len = म_माप(info)) > 0) {
		addnl = info[len] != '\n';
		fmprintf(मानक_त्रुटि, "%s%s", info, addnl ? "\n" : "");
	}
	अगर ((r = sshpkt_start(ssh, SSH2_संदेश_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0)	/* additional info */
		जाओ out;

	snprintf(prompt, माप(prompt),
	    "Enter %.30s@%.128s's old password: ",
	    authctxt->server_user, host);
	password = read_passphrase(prompt, 0);
	अगर ((r = sshpkt_put_cstring(ssh, password)) != 0)
		जाओ out;

	freezero(password, म_माप(password));
	password = शून्य;
	जबतक (password == शून्य) {
		snprintf(prompt, माप(prompt),
		    "Enter %.30s@%.128s's new password: ",
		    authctxt->server_user, host);
		password = read_passphrase(prompt, RP_ALLOW_EOF);
		अगर (password == शून्य) {
			/* bail out */
			r = 0;
			जाओ out;
		}
		snprintf(prompt, माप(prompt),
		    "Retype %.30s@%.128s's new password: ",
		    authctxt->server_user, host);
		retype = read_passphrase(prompt, 0);
		अगर (म_भेद(password, retype) != 0) {
			freezero(password, म_माप(password));
			logit("Mismatch; try again, EOF to quit.");
			password = शून्य;
		}
		freezero(retype, म_माप(retype));
	}
	अगर ((r = sshpkt_put_cstring(ssh, password)) != 0 ||
	    (r = sshpkt_add_padding(ssh, 64)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		जाओ out;

	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_PASSWD_CHANGEREQ,
	    &निवेश_userauth_passwd_changereq);
	r = 0;
 out:
	अगर (password)
		freezero(password, म_माप(password));
	मुक्त(info);
	मुक्त(lang);
	वापस r;
}

/*
 * Select an algorithm for publickey signatures.
 * Returns algorithm (caller must free) or NULL if no mutual algorithm found.
 *
 * Call with ssh==NULL to ignore server-sig-algs extension list and
 * only attempt with the key's base signature type.
 */
अटल अक्षर *
कुंजी_sig_algorithm(काष्ठा ssh *ssh, स्थिर काष्ठा sshkey *कुंजी)
{
	अक्षर *allowed, *oallowed, *cp, *tmp, *alg = शून्य;
	स्थिर अक्षर *server_sig_algs;

	/*
	 * The signature algorithm will only differ from the key algorithm
	 * for RSA keys/certs and when the server advertises support for
	 * newer (SHA2) algorithms.
	 */
	अगर (ssh == शून्य || ssh->kex->server_sig_algs == शून्य ||
	    (कुंजी->type != कुंजी_RSA && कुंजी->type != कुंजी_RSA_CERT) ||
	    (कुंजी->type == कुंजी_RSA_CERT && (ssh->compat & SSH_BUG_SIGTYPE))) {
		/* Filter base key signature alg against our configuration */
		वापस match_list(sshkey_ssh_name(कुंजी),
		    options.pubkey_accepted_algos, शून्य);
	}

	/*
	 * Workaround OpenSSH 7.4 bug: this version supports RSA/SHA-2 but
	 * fails to advertise it via SSH2_MSG_EXT_INFO.
	 */
	server_sig_algs = ssh->kex->server_sig_algs;
	अगर (कुंजी->type == कुंजी_RSA && (ssh->compat & SSH_BUG_SIGTYPE74))
		server_sig_algs = "rsa-sha2-256,rsa-sha2-512";

	/*
	 * For RSA keys/certs, since these might have a different sig type:
	 * find the first entry in PubkeyAcceptedAlgorithms of the right type
	 * that also appears in the supported signature algorithms list from
	 * the server.
	 */
	oallowed = allowed = xstrdup(options.pubkey_accepted_algos);
	जबतक ((cp = strsep(&allowed, ",")) != शून्य) {
		अगर (sshkey_type_from_name(cp) != कुंजी->type)
			जारी;
		tmp = match_list(sshkey_sigalg_by_name(cp),
		    server_sig_algs, शून्य);
		अगर (tmp != शून्य)
			alg = xstrdup(cp);
		मुक्त(tmp);
		अगर (alg != शून्य)
			अवरोध;
	}
	मुक्त(oallowed);
	वापस alg;
}

अटल पूर्णांक
identity_sign(काष्ठा identity *id, u_char **sigp, माप_प्रकार *lenp,
    स्थिर u_char *तथ्य, माप_प्रकार datalen, u_int compat, स्थिर अक्षर *alg)
{
	काष्ठा sshkey *sign_कुंजी = शून्य, *prv = शून्य;
	पूर्णांक is_agent = 0, retried = 0, r = SSH_ERR_INTERNAL_ERROR;
	काष्ठा notifier_ctx *notifier = शून्य;
	अक्षर *fp = शून्य, *pin = शून्य, *prompt = शून्य;

	*sigp = शून्य;
	*lenp = 0;

	/* The agent supports this key. */
	अगर (id->कुंजी != शून्य && id->agent_fd != -1) {
		वापस ssh_agent_sign(id->agent_fd, id->कुंजी, sigp, lenp,
		    तथ्य, datalen, alg, compat);
	}

	/*
	 * We have already loaded the private key or the private key is
	 * stored in external hardware.
	 */
	अगर (id->कुंजी != शून्य &&
	    (id->isprivate || (id->कुंजी->flags & SSHKEY_FLAG_EXT))) {
		sign_कुंजी = id->कुंजी;
		is_agent = 1;
	} अन्यथा {
		/* Load the private key from the file. */
		अगर ((prv = load_identity_file(id)) == शून्य)
			वापस SSH_ERR_कुंजी_NOT_FOUND;
		अगर (id->कुंजी != शून्य && !sshkey_equal_public(prv, id->कुंजी)) {
			error_f("private key %s contents do not match public",
			    id->filename);
			r = SSH_ERR_कुंजी_NOT_FOUND;
			जाओ out;
		}
		sign_कुंजी = prv;
	}
 retry_pin:
	/* Prompt for touch for non-agent FIDO keys that request UP */
	अगर (!is_agent && sshkey_is_sk(sign_कुंजी) &&
	    (sign_कुंजी->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
		/* XXX should batch mode just skip these? */
		अगर ((fp = sshkey_fingerprint(sign_कुंजी,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == शून्य)
			fatal_f("fingerprint failed");
		notifier = notify_start(options.batch_mode,
		    "Confirm user presence for key %s %s",
		    sshkey_type(sign_कुंजी), fp);
		मुक्त(fp);
	}
	अगर ((r = sshkey_sign(sign_कुंजी, sigp, lenp, तथ्य, datalen,
	    alg, options.sk_provider, pin, compat)) != 0) {
		debug_fr(r, "sshkey_sign");
		अगर (!retried && pin == शून्य && !is_agent &&
		    sshkey_is_sk(sign_कुंजी) &&
		    r == SSH_ERR_कुंजी_WRONG_PASSPHRASE) {
			notify_complete(notifier, शून्य);
			notifier = शून्य;
			xasprintf(&prompt, "Enter PIN for %s key %s: ",
			    sshkey_type(sign_कुंजी), id->filename);
			pin = read_passphrase(prompt, 0);
			retried = 1;
			जाओ retry_pin;
		}
		जाओ out;
	}

	/*
	 * PKCS#11 tokens may not support all signature algorithms,
	 * so check what we get back.
	 */
	अगर (id->कुंजी != शून्य && (id->कुंजी->flags & SSHKEY_FLAG_EXT) != 0 &&
	    (r = sshkey_check_sigtype(*sigp, *lenp, alg)) != 0) {
		debug_fr(r, "sshkey_check_sigtype");
		जाओ out;
	}
	/* success */
	r = 0;
 out:
	मुक्त(prompt);
	अगर (pin != शून्य)
		freezero(pin, म_माप(pin));
	notify_complete(notifier, r == 0 ? "User presence confirmed" : शून्य);
	sshkey_free(prv);
	वापस r;
}

अटल पूर्णांक
id_filename_matches(Identity *id, Identity *private_id)
{
	अटल स्थिर अक्षर * स्थिर suffixes[] = { ".pub", "-cert.pub", शून्य };
	माप_प्रकार len = म_माप(id->filename), plen = म_माप(private_id->filename);
	माप_प्रकार i, slen;

	अगर (म_भेद(id->filename, private_id->filename) == 0)
		वापस 1;
	क्रम (i = 0; suffixes[i]; i++) {
		slen = म_माप(suffixes[i]);
		अगर (len > slen && plen == len - slen &&
		    म_भेद(id->filename + (len - slen), suffixes[i]) == 0 &&
		    स_भेद(id->filename, private_id->filename, plen) == 0)
			वापस 1;
	}
	वापस 0;
}

अटल पूर्णांक
sign_and_send_pubkey(काष्ठा ssh *ssh, Identity *id)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	काष्ठा sshbuf *b = शून्य;
	Identity *private_id, *sign_id = शून्य;
	u_char *signature = शून्य;
	माप_प्रकार slen = 0, skip = 0;
	पूर्णांक r, fallback_sigtype, sent = 0;
	अक्षर *alg = शून्य, *fp = शून्य;
	स्थिर अक्षर *loc = "", *method = "publickey";
	पूर्णांक hostbound = 0;

	/* prefer host-bound pubkey signatures if supported by server */
	अगर ((ssh->kex->flags & KEX_HAS_PUBKEY_HOSTBOUND) != 0 &&
	    (options.pubkey_authentication & SSH_PUBKEY_AUTH_HBOUND) != 0) {
		hostbound = 1;
		method = "publickey-hostbound-v00@openssh.com";
	}

	अगर ((fp = sshkey_fingerprint(id->कुंजी, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == शून्य)
		वापस 0;

	debug3_f("using %s with %s %s", method, sshkey_type(id->कुंजी), fp);

	/*
	 * If the key is an certificate, try to find a matching private key
	 * and use it to complete the signature.
	 * If no such private key exists, fall back to trying the certificate
	 * key itself in case it has a private half already loaded.
	 * This will try to set sign_id to the private key that will perform
	 * the signature.
	 */
	अगर (id->agent_fd == -1 && sshkey_is_cert(id->कुंजी)) {
		TAILQ_FOREACH(private_id, &authctxt->कुंजियाँ, अग्र) {
			अगर (sshkey_equal_public(id->कुंजी, private_id->कुंजी) &&
			    id->कुंजी->type != private_id->कुंजी->type) {
				sign_id = private_id;
				अवरोध;
			}
		}
		/*
		 * Exact key matches are preferred, but also allow
		 * filename matches for non-PKCS#11/agent keys that
		 * didn't load public keys. This supports the case
		 * of keeping just a private key file and public
		 * certificate on disk.
		 */
		अगर (sign_id == शून्य &&
		    !id->isprivate && id->agent_fd == -1 &&
		    (id->कुंजी->flags & SSHKEY_FLAG_EXT) == 0) {
			TAILQ_FOREACH(private_id, &authctxt->कुंजियाँ, अग्र) {
				अगर (private_id->कुंजी == शून्य &&
				    id_filename_matches(id, private_id)) {
					sign_id = private_id;
					अवरोध;
				}
			}
		}
		अगर (sign_id != शून्य) {
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
	अगर (sign_id == शून्य)
		sign_id = id;

	/* assemble and sign data */
	क्रम (fallback_sigtype = 0; fallback_sigtype <= 1; fallback_sigtype++) {
		मुक्त(alg);
		slen = 0;
		signature = शून्य;
		अगर ((alg = कुंजी_sig_algorithm(fallback_sigtype ? शून्य : ssh,
		    id->कुंजी)) == शून्य) {
			error_f("no mutual signature supported");
			जाओ out;
		}
		debug3_f("signing using %s %s", alg, fp);

		sshbuf_free(b);
		अगर ((b = sshbuf_new()) == शून्य)
			fatal_f("sshbuf_new failed");
		अगर ((r = sshbuf_put_stringb(b,
		    ssh->kex->session_id)) != 0)
			fatal_fr(r, "sshbuf_put_stringb");
		skip = sshbuf_len(b);
		अगर ((r = sshbuf_put_u8(b, SSH2_संदेश_USERAUTH_REQUEST)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->server_user)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
		    (r = sshbuf_put_cstring(b, method)) != 0 ||
		    (r = sshbuf_put_u8(b, 1)) != 0 ||
		    (r = sshbuf_put_cstring(b, alg)) != 0 ||
		    (r = sshkey_puts(id->कुंजी, b)) != 0) {
			fatal_fr(r, "assemble signed data");
		}
		अगर (hostbound) {
			अगर (ssh->kex->initial_hostkey == शून्य) {
				fatal_f("internal error: initial hostkey "
				    "not recorded");
			}
			अगर ((r = sshkey_puts(ssh->kex->initial_hostkey, b)) != 0)
				fatal_fr(r, "assemble %s hostkey", method);
		}
		/* generate signature */
		r = identity_sign(sign_id, &signature, &slen,
		    sshbuf_ptr(b), sshbuf_len(b), ssh->compat, alg);
		अगर (r == 0)
			अवरोध;
		अन्यथा अगर (r == SSH_ERR_कुंजी_NOT_FOUND)
			जाओ out; /* soft failure */
		अन्यथा अगर (r == SSH_ERR_SIGN_ALG_UNSUPPORTED &&
		    !fallback_sigtype) {
			अगर (sign_id->agent_fd != -1)
				loc = "agent ";
			अन्यथा अगर (sign_id->कुंजी != शून्य &&
			    (sign_id->कुंजी->flags & SSHKEY_FLAG_EXT) != 0)
				loc = "token ";
			logit("%skey %s %s returned incorrect signature type",
			    loc, sshkey_type(id->कुंजी), fp);
			जारी;
		}
		error_fr(r, "signing failed for %s \"%s\"%s",
		    sshkey_type(sign_id->कुंजी), sign_id->filename,
		    id->agent_fd != -1 ? " from agent" : "");
		जाओ out;
	}
	अगर (slen == 0 || signature == शून्य) /* shouldn't happen */
		fatal_f("no signature");

	/* append signature */
	अगर ((r = sshbuf_put_string(b, signature, slen)) != 0)
		fatal_fr(r, "append signature");

#अगर_घोषित DEBUG_PK
	sshbuf_dump(b, मानक_त्रुटि);
#पूर्ण_अगर
	/* skip session id and packet type */
	अगर ((r = sshbuf_consume(b, skip + 1)) != 0)
		fatal_fr(r, "consume");

	/* put remaining data from buffer into packet */
	अगर ((r = sshpkt_start(ssh, SSH2_संदेश_USERAUTH_REQUEST)) != 0 ||
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
	वापस sent;
}

अटल पूर्णांक
send_pubkey_test(काष्ठा ssh *ssh, Identity *id)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	u_char *blob = शून्य;
	अक्षर *alg = शून्य;
	माप_प्रकार bloblen;
	u_int have_sig = 0;
	पूर्णांक sent = 0, r;

	अगर ((alg = कुंजी_sig_algorithm(ssh, id->कुंजी)) == शून्य) {
		debug_f("no mutual signature algorithm");
		जाओ out;
	}

	अगर ((r = sshkey_to_blob(id->कुंजी, &blob, &bloblen)) != 0) {
		/* we cannot handle this key */
		debug3_f("cannot handle key");
		जाओ out;
	}
	/* register callback for USERAUTH_PK_OK message */
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_PK_OK, &निवेश_userauth_pk_ok);

	अगर ((r = sshpkt_start(ssh, SSH2_संदेश_USERAUTH_REQUEST)) != 0 ||
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
	वापस sent;
}

अटल काष्ठा sshkey *
load_identity_file(Identity *id)
{
	काष्ठा sshkey *निजी = शून्य;
	अक्षर prompt[300], *passphrase, *comment;
	पूर्णांक r, quit = 0, i;
	काष्ठा stat st;

	अगर (stat(id->filename, &st) == -1) {
		do_log2(id->userprovided ?
		    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_DEBUG3,
		    "no such identity: %s: %s", id->filename, म_त्रुटि(त्रुटि_सं));
		वापस शून्य;
	}
	snprintf(prompt, माप prompt,
	    "Enter passphrase for key '%.100s': ", id->filename);
	क्रम (i = 0; i <= options.संख्या_of_password_prompts; i++) {
		अगर (i == 0)
			passphrase = "";
		अन्यथा {
			passphrase = read_passphrase(prompt, 0);
			अगर (*passphrase == '\0') {
				debug2("no passphrase given, try next key");
				मुक्त(passphrase);
				अवरोध;
			}
		}
		चयन ((r = sshkey_load_private_type(कुंजी_UNSPEC, id->filename,
		    passphrase, &निजी, &comment))) {
		हाल 0:
			अवरोध;
		हाल SSH_ERR_कुंजी_WRONG_PASSPHRASE:
			अगर (options.batch_mode) {
				quit = 1;
				अवरोध;
			}
			अगर (i != 0)
				debug2("bad passphrase given, try again...");
			अवरोध;
		हाल SSH_ERR_SYSTEM_ERROR:
			अगर (त्रुटि_सं == ENOENT) {
				debug2_r(r, "Load key \"%s\"", id->filename);
				quit = 1;
				अवरोध;
			}
			/* FALLTHROUGH */
		शेष:
			error_r(r, "Load key \"%s\"", id->filename);
			quit = 1;
			अवरोध;
		}
		अगर (निजी != शून्य && sshkey_is_sk(निजी) &&
		    options.sk_provider == शून्य) {
			debug("key \"%s\" is an authenticator-hosted key, "
			    "but no provider specified", id->filename);
			sshkey_free(निजी);
			निजी = शून्य;
			quit = 1;
		}
		अगर (!quit && (r = sshkey_check_rsa_लंबाई(निजी,
		    options.required_rsa_आकार)) != 0) {
			debug_fr(r, "Skipping key %s", id->filename);
			sshkey_free(निजी);
			निजी = शून्य;
			quit = 1;
		}
		अगर (!quit && निजी != शून्य && id->agent_fd == -1 &&
		    !(id->कुंजी && id->isprivate))
			maybe_add_कुंजी_to_agent(id->filename, निजी, comment,
			    passphrase);
		अगर (i > 0)
			freezero(passphrase, म_माप(passphrase));
		मुक्त(comment);
		अगर (निजी != शून्य || quit)
			अवरोध;
	}
	वापस निजी;
}

अटल पूर्णांक
कुंजी_type_allowed(काष्ठा sshkey *कुंजी, स्थिर अक्षर *allowlist)
{
	अगर (match_pattern_list(sshkey_ssh_name(कुंजी), allowlist, 0) == 1)
		वापस 1;

	/* RSA keys/certs might be allowed by alternate signature types */
	चयन (कुंजी->type) {
	हाल कुंजी_RSA:
		अगर (match_pattern_list("rsa-sha2-512", allowlist, 0) == 1)
			वापस 1;
		अगर (match_pattern_list("rsa-sha2-256", allowlist, 0) == 1)
			वापस 1;
		अवरोध;
	हाल कुंजी_RSA_CERT:
		अगर (match_pattern_list("rsa-sha2-512-cert-v01@openssh.com",
		    allowlist, 0) == 1)
			वापस 1;
		अगर (match_pattern_list("rsa-sha2-256-cert-v01@openssh.com",
		    allowlist, 0) == 1)
			वापस 1;
		अवरोध;
	}
	वापस 0;
}

अटल पूर्णांक
कुंजी_type_allowed_by_config(काष्ठा sshkey *कुंजी)
{
	वापस कुंजी_type_allowed(कुंजी, options.pubkey_accepted_algos);
}

/* obtain a list of keys from the agent */
अटल पूर्णांक
get_agent_identities(काष्ठा ssh *ssh, पूर्णांक *agent_fdp,
    काष्ठा ssh_identitylist **idlistp)
{
	पूर्णांक r, agent_fd;
	काष्ठा ssh_identitylist *idlist;

	अगर ((r = ssh_get_authentication_socket(&agent_fd)) != 0) {
		अगर (r != SSH_ERR_AGENT_NOT_PRESENT)
			debug_fr(r, "ssh_get_authentication_socket");
		वापस r;
	}
	अगर (ssh != शून्य && ssh->kex != शून्य) {
		अगर ((r = ssh_agent_bind_hostkey(agent_fd, ssh->kex->initial_hostkey,
		    ssh->kex->session_id, ssh->kex->initial_sig, 0)) == 0)
			debug_f("bound agent to hostkey");
		अन्यथा
			debug2_fr(r, "ssh_agent_bind_hostkey");
	}

	अगर ((r = ssh_fetch_identitylist(agent_fd, &idlist)) != 0) {
		debug_fr(r, "ssh_fetch_identitylist");
		बंद(agent_fd);
		वापस r;
	}
	/* success */
	*agent_fdp = agent_fd;
	*idlistp = idlist;
	debug_f("agent returned %zu keys", idlist->nkeys);
	वापस 0;
}

/*
 * Returns nonzero if the certificate extensions/critical-options section
 * has the specified option present, zero otherwise.
 */
अटल पूर्णांक
cert_has_option(काष्ठा sshbuf *oblob, स्थिर अक्षर *target)
{
	काष्ठा sshbuf *c = शून्य, *तथ्य = शून्य;
	अक्षर *name = शून्य;
	पूर्णांक r, found = 0;

	अगर (oblob == शून्य || (c = sshbuf_fromb(oblob)) == शून्य)
		वापस 0;
	जबतक (sshbuf_len(c) > 0) {
		sshbuf_free(तथ्य);
		तथ्य = शून्य;
		मुक्त(name);
		name = शून्य;
		अगर ((r = sshbuf_get_cstring(c, &name, शून्य)) != 0 ||
		    (r = sshbuf_froms(c, &तथ्य)) != 0)
			अवरोध;
		अगर (म_भेद(name, target) == 0) {
			found = 1;
			अवरोध;
		}
	}
	sshbuf_free(तथ्य);
	मुक्त(name);
	sshbuf_free(c);
	वापस found;
}

/*
 * Returns an integer describing the priority of the identity
 * within its group. Lower numbers are higher priority.
 */
#घोषणा MAX_ID_PRIORITY 3
अटल पूर्णांक
identity_prioritise(काष्ठा identity *id)
{
	अगर (id == शून्य || id->कुंजी == शून्य)
		वापस 3;
	अगर (!sshkey_is_cert(id->कुंजी) || id->कुंजी->cert == शून्य)
		वापस 3;
	अगर (sshkey_is_sk(id->कुंजी) &&
	    cert_has_option(id->कुंजी->cert->critical, "verify-required"))
		वापस 2;
	अगर (sshkey_is_sk(id->कुंजी) &&
	    cert_has_option(id->कुंजी->cert->extensions, "no-touch-required"))
		वापस 0;
	वापस 1;
}

अटल व्योम
order_identities_by_prio(काष्ठा idlist *list)
{
	काष्ठा idlist prio[MAX_ID_PRIORITY + 1], sorted;
	काष्ठा identity *id, *tmp, *dummy;
	पूर्णांक p;

	क्रम (p = 0; p <= MAX_ID_PRIORITY; p++)
		TAILQ_INIT(&prio[p]);
	TAILQ_INIT(&sorted);

	TAILQ_FOREACH_SAFE(id, list, अग्र, tmp) {
		अगर (id->userprovided)
			जारी;
		dummy = xcalloc(1, माप(*dummy));
		dummy->userprovided = -1;
		TAILQ_INSERT_BEFORE(id, dummy, अग्र);
		TAILQ_REMOVE(list, id, अग्र);
		p = identity_prioritise(id);
		अगर (p < 0 || p > MAX_ID_PRIORITY)
			fatal_f("internal error: bad priority");
		TAILQ_INSERT_TAIL(&prio[p], id, अग्र);
	}
	क्रम (p = 0; p <= MAX_ID_PRIORITY; p++)
		TAILQ_CONCAT(&sorted, &prio[p], अग्र);

	TAILQ_FOREACH_SAFE(id, list, अग्र, tmp) {
		अगर (id->userprovided != -1)
			जारी;
		काष्ठा identity *s = TAILQ_FIRST(&sorted);
		TAILQ_REMOVE(&sorted, s, अग्र);
		TAILQ_INSERT_BEFORE(id, s, अग्र);
		TAILQ_REMOVE(list, id, अग्र);
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
अटल व्योम
pubkey_prepare(काष्ठा ssh *ssh, Authctxt *authctxt)
{
	काष्ठा identity *id, *id2, *tmp;
	काष्ठा idlist agent, files, certs, agent_कुंजियाँ, *preferred;
	काष्ठा sshkey *कुंजी;
	पूर्णांक disallowed, agent_fd = -1, i, r, found;
	माप_प्रकार j;
	काष्ठा ssh_identitylist *idlist;
	अक्षर *cp, *ident;

	TAILQ_INIT(&agent);	/* keys from the agent */
	TAILQ_INIT(&files);	/* keys from the config file */
	TAILQ_INIT(&certs);	/* certificates specified by user */
	TAILQ_INIT(&agent_कुंजियाँ); /* keys supported by the agent */
	preferred = &authctxt->कुंजियाँ;
	TAILQ_INIT(preferred);	/* preferred order of keys */

	/* list of keys stored in the filesystem and PKCS#11 */
	क्रम (i = 0; i < options.अंक_identity_files; i++) {
		कुंजी = options.identity_कुंजियाँ[i];
		अगर (कुंजी && कुंजी->cert &&
		    कुंजी->cert->type != SSH2_CERT_TYPE_USER) {
			debug_f("ignoring certificate %s: not a user "
			    "certificate", options.identity_files[i]);
			जारी;
		}
		अगर (कुंजी && sshkey_is_sk(कुंजी) && options.sk_provider == शून्य) {
			debug_f("ignoring authenticator-hosted key %s as no "
			    "SecurityKeyProvider has been specified",
			    options.identity_files[i]);
			जारी;
		}
		options.identity_कुंजियाँ[i] = शून्य;
		id = xcalloc(1, माप(*id));
		id->agent_fd = -1;
		id->कुंजी = कुंजी;
		id->filename = xstrdup(options.identity_files[i]);
		id->userprovided = options.identity_file_userprovided[i];
		TAILQ_INSERT_TAIL(&files, id, अग्र);
	}

	/* list of certificates specified by user */
	क्रम (i = 0; i < options.अंक_certificate_files; i++) {
		कुंजी = options.certificates[i];
		अगर (!sshkey_is_cert(कुंजी) || कुंजी->cert == शून्य ||
		    कुंजी->cert->type != SSH2_CERT_TYPE_USER) {
			debug_f("ignoring certificate %s: not a user "
			    "certificate", options.identity_files[i]);
			जारी;
		}
		अगर (कुंजी && sshkey_is_sk(कुंजी) && options.sk_provider == शून्य) {
			debug_f("ignoring authenticator-hosted key "
			    "certificate %s as no "
			    "SecurityKeyProvider has been specified",
			    options.identity_files[i]);
			जारी;
		}
		id = xcalloc(1, माप(*id));
		id->agent_fd = -1;
		id->कुंजी = कुंजी;
		id->filename = xstrdup(options.certificate_files[i]);
		id->userprovided = options.certificate_file_userprovided[i];
		TAILQ_INSERT_TAIL(&certs, id, अग्र);
	}
	order_identities_by_prio(&certs);
	TAILQ_CONCAT(preferred, &certs, अग्र);

	/* list of keys supported by the agent */
	अगर ((r = get_agent_identities(ssh, &agent_fd, &idlist)) == 0) {
		क्रम (j = 0; j < idlist->nkeys; j++) {
			अगर ((r = sshkey_check_rsa_लंबाई(idlist->कुंजियाँ[j],
			    options.required_rsa_आकार)) != 0) {
				debug_fr(r, "ignoring %s agent key",
				    sshkey_ssh_name(idlist->कुंजियाँ[j]));
				जारी;
			}
			found = 0;
			TAILQ_FOREACH(id, &files, अग्र) {
				/*
				 * agent keys from the config file are
				 * preferred
				 */
				अगर (sshkey_equal(idlist->कुंजियाँ[j], id->कुंजी)) {
					TAILQ_REMOVE(&files, id, अग्र);
					TAILQ_INSERT_TAIL(&agent_कुंजियाँ, id, अग्र);
					id->agent_fd = agent_fd;
					found = 1;
					अवरोध;
				}
			}
			अगर (!found && !options.identities_only) {
				id = xcalloc(1, माप(*id));
				/* XXX "steals" key/comment from idlist */
				id->कुंजी = idlist->कुंजियाँ[j];
				id->filename = idlist->comments[j];
				idlist->कुंजियाँ[j] = शून्य;
				idlist->comments[j] = शून्य;
				id->agent_fd = agent_fd;
				TAILQ_INSERT_TAIL(&agent, id, अग्र);
			}
		}
		ssh_free_identitylist(idlist);
		/* append remaining agent keys */
		TAILQ_CONCAT(&agent_कुंजियाँ, &agent, अग्र);
		order_identities_by_prio(&agent_कुंजियाँ);
		TAILQ_CONCAT(preferred, &agent_कुंजियाँ, अग्र);
		authctxt->agent_fd = agent_fd;
	}
	/* Prefer PKCS11 keys that are explicitly listed */
	TAILQ_FOREACH_SAFE(id, &files, अग्र, tmp) {
		अगर (id->कुंजी == शून्य || (id->कुंजी->flags & SSHKEY_FLAG_EXT) == 0)
			जारी;
		found = 0;
		TAILQ_FOREACH(id2, &files, अग्र) {
			अगर (id2->कुंजी == शून्य ||
			    (id2->कुंजी->flags & SSHKEY_FLAG_EXT) != 0)
				जारी;
			अगर (sshkey_equal(id->कुंजी, id2->कुंजी)) {
				TAILQ_REMOVE(&files, id, अग्र);
				TAILQ_INSERT_TAIL(preferred, id, अग्र);
				found = 1;
				अवरोध;
			}
		}
		/* If IdentitiesOnly set and key not found then don't use it */
		अगर (!found && options.identities_only) {
			TAILQ_REMOVE(&files, id, अग्र);
			freezero(id, माप(*id));
		}
	}
	order_identities_by_prio(&files);
	/* append remaining keys from the config file */
	TAILQ_CONCAT(preferred, &files, अग्र);
	/* finally, filter by PubkeyAcceptedAlgorithms */
	TAILQ_FOREACH_SAFE(id, preferred, अग्र, id2) {
		disallowed = 0;
		cp = शून्य;
		अगर (id->कुंजी == शून्य)
			जारी;
		अगर (!कुंजी_type_allowed_by_config(id->कुंजी)) {
			debug("Skipping %s key %s - corresponding algorithm "
			    "not in PubkeyAcceptedAlgorithms",
			    sshkey_ssh_name(id->कुंजी), id->filename);
			disallowed = 1;
		} अन्यथा अगर (ssh != शून्य && ssh->kex != शून्य &&
		    ssh->kex->server_sig_algs != शून्य &&
		    (cp = कुंजी_sig_algorithm(ssh, id->कुंजी)) == शून्य) {
			debug("Skipping %s key %s - corresponding algorithm "
			    "not supported by server",
			    sshkey_ssh_name(id->कुंजी), id->filename);
			disallowed = 1;
		}
		मुक्त(cp);
		अगर (!disallowed)
			जारी;
		/* remove key */
		TAILQ_REMOVE(preferred, id, अग्र);
		sshkey_free(id->कुंजी);
		मुक्त(id->filename);
		freezero(id, माप(*id));
	}
	/* List the keys we plan on using */
	TAILQ_FOREACH_SAFE(id, preferred, अग्र, id2) {
		ident = format_identity(id);
		debug("Will attempt key: %s", ident);
		मुक्त(ident);
	}
	debug2_f("done");
}

अटल व्योम
pubkey_cleanup(काष्ठा ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Identity *id;

	अगर (authctxt->agent_fd != -1) {
		ssh_close_authentication_socket(authctxt->agent_fd);
		authctxt->agent_fd = -1;
	}
	क्रम (id = TAILQ_FIRST(&authctxt->कुंजियाँ); id;
	    id = TAILQ_FIRST(&authctxt->कुंजियाँ)) {
		TAILQ_REMOVE(&authctxt->कुंजियाँ, id, अग्र);
		sshkey_free(id->कुंजी);
		मुक्त(id->filename);
		मुक्त(id);
	}
}

व्योम
pubkey_dump(काष्ठा ssh *ssh)
{
	Authctxt authctxt;
	Identity *id;
	अक्षर *ident;

	स_रखो(&authctxt, 0, माप(authctxt));
	authctxt.agent_fd = -1;
	ssh->authctxt = &authctxt;

	pubkey_prepare(ssh, &authctxt);
	TAILQ_FOREACH(id, &authctxt.कुंजियाँ, अग्र) {
		ident = format_identity(id);
		ख_लिखो(मानक_निकास, "%s\n", ident);
		मुक्त(ident);
	}
	pubkey_cleanup(ssh);
	ssh->authctxt = शून्य;
}

अटल व्योम
pubkey_reset(Authctxt *authctxt)
{
	Identity *id;

	TAILQ_FOREACH(id, &authctxt->कुंजियाँ, अग्र)
		id->tried = 0;
}

अटल पूर्णांक
userauth_pubkey(काष्ठा ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Identity *id;
	पूर्णांक sent = 0;
	अक्षर *ident;
	अटल पूर्णांक prepared;

	अगर (!prepared) {
		pubkey_prepare(ssh, authctxt);
		prepared = 1;
	}

	जबतक ((id = TAILQ_FIRST(&authctxt->कुंजियाँ))) {
		अगर (id->tried++)
			वापस (0);
		/* move key to the end of the queue */
		TAILQ_REMOVE(&authctxt->कुंजियाँ, id, अग्र);
		TAILQ_INSERT_TAIL(&authctxt->कुंजियाँ, id, अग्र);
		/*
		 * send a test message if we have the public key. for
		 * encrypted keys we cannot do this and have to load the
		 * private key instead
		 */
		अगर (id->कुंजी != शून्य) {
			ident = format_identity(id);
			debug("Offering public key: %s", ident);
			मुक्त(ident);
			sent = send_pubkey_test(ssh, id);
		} अन्यथा {
			debug("Trying private key: %s", id->filename);
			id->कुंजी = load_identity_file(id);
			अगर (id->कुंजी != शून्य) {
				id->isprivate = 1;
				sent = sign_and_send_pubkey(ssh, id);
				sshkey_free(id->कुंजी);
				id->कुंजी = शून्य;
				id->isprivate = 0;
			}
		}
		अगर (sent)
			वापस (sent);
	}
	वापस (0);
}

/*
 * Send userauth request message specifying keyboard-interactive method.
 */
अटल पूर्णांक
userauth_kbdint(काष्ठा ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	पूर्णांक r;

	अगर (authctxt->attempt_kbdint++ >= options.संख्या_of_password_prompts)
		वापस 0;
	/* disable if no SSH2_MSG_USERAUTH_INFO_REQUEST has been seen */
	अगर (authctxt->attempt_kbdint > 1 && !authctxt->info_req_seen) {
		debug3("userauth_kbdint: disable: no info_req_seen");
		ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_INFO_REQUEST, शून्य);
		वापस 0;
	}

	debug2("userauth_kbdint");
	अगर ((r = sshpkt_start(ssh, SSH2_संदेश_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||		/* lang */
	    (r = sshpkt_put_cstring(ssh, options.kbd_interactive_devices ?
	    options.kbd_interactive_devices : "")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_INFO_REQUEST, &निवेश_userauth_info_req);
	वापस 1;
}

/*
 * parse INFO_REQUEST, prompt user and send INFO_RESPONSE
 */
अटल पूर्णांक
निवेश_userauth_info_req(पूर्णांक type, uint32_t seq, काष्ठा ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	अक्षर *name = शून्य, *inst = शून्य, *lang = शून्य, *prompt = शून्य;
	अक्षर *display_prompt = शून्य, *response = शून्य;
	u_char echo = 0;
	u_int अंक_prompts, i;
	पूर्णांक r, addnl;
	माप_प्रकार len;

	debug2_f("entering");

	अगर (authctxt == शून्य)
		fatal_f("no authentication context");

	authctxt->info_req_seen = 1;

	अगर ((r = sshpkt_get_cstring(ssh, &name, शून्य)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &inst, शून्य)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, शून्य)) != 0)
		जाओ out;
	अगर ((len = म_माप(name)) > 0) {
		addnl = name[len] != '\n';
		fmprintf(मानक_त्रुटि, "%s%s", name, addnl ? "\n" : "");
	}
	अगर ((len = म_माप(inst)) > 0) {
		addnl = inst[len] != '\n';
		fmprintf(मानक_त्रुटि, "%s%s", inst, addnl ? "\n" : "");
	}

	अगर ((r = sshpkt_get_u32(ssh, &अंक_prompts)) != 0)
		जाओ out;
	/*
	 * Begin to build info response packet based on prompts requested.
	 * We commit to providing the correct number of responses, so if
	 * further on we run into a problem that prevents this, we have to
	 * be sure and clean this up and send a correct error response.
	 */
	अगर ((r = sshpkt_start(ssh, SSH2_संदेश_USERAUTH_INFO_RESPONSE)) != 0 ||
	    (r = sshpkt_put_u32(ssh, अंक_prompts)) != 0)
		जाओ out;

	debug2_f("num_prompts %d", अंक_prompts);
	क्रम (i = 0; i < अंक_prompts; i++) {
		अगर ((r = sshpkt_get_cstring(ssh, &prompt, शून्य)) != 0 ||
		    (r = sshpkt_get_u8(ssh, &echo)) != 0)
			जाओ out;
		अगर (asmprintf(&display_prompt, पूर्णांक_उच्च, शून्य, "(%s@%s) %s",
		    authctxt->server_user, options.host_कुंजी_alias ?
		    options.host_कुंजी_alias : authctxt->host, prompt) == -1)
			fatal_f("asmprintf failed");
		response = read_passphrase(display_prompt, echo ? RP_ECHO : 0);
		अगर ((r = sshpkt_put_cstring(ssh, response)) != 0)
			जाओ out;
		freezero(response, म_माप(response));
		मुक्त(prompt);
		मुक्त(display_prompt);
		display_prompt = response = prompt = शून्य;
	}
	/* done with parsing incoming message. */
	अगर ((r = sshpkt_get_end(ssh)) != 0 ||
	    (r = sshpkt_add_padding(ssh, 64)) != 0)
		जाओ out;
	r = sshpkt_send(ssh);
 out:
	अगर (response)
		freezero(response, म_माप(response));
	मुक्त(prompt);
	मुक्त(display_prompt);
	मुक्त(name);
	मुक्त(inst);
	मुक्त(lang);
	वापस r;
}

अटल पूर्णांक
ssh_keysign(काष्ठा ssh *ssh, काष्ठा sshkey *कुंजी, u_char **sigp, माप_प्रकार *lenp,
    स्थिर u_char *तथ्य, माप_प्रकार datalen)
{
	काष्ठा sshbuf *b;
	काष्ठा stat st;
	pid_t pid;
	पूर्णांक r, to[2], from[2], status;
	पूर्णांक sock = ssh_packet_get_connection_in(ssh);
	u_char rversion = 0, version = 2;
	व्योम (*osigchld)(पूर्णांक);

	*sigp = शून्य;
	*lenp = 0;

	अगर (stat(PATH_SSH_कुंजी_SIGN, &st) == -1) {
		error_f("not installed: %s", म_त्रुटि(त्रुटि_सं));
		वापस -1;
	}
	अगर (ख_साफ(मानक_निकास) != 0) {
		error_f("fflush: %s", म_त्रुटि(त्रुटि_सं));
		वापस -1;
	}
	अगर (pipe(to) == -1) {
		error_f("pipe: %s", म_त्रुटि(त्रुटि_सं));
		वापस -1;
	}
	अगर (pipe(from) == -1) {
		error_f("pipe: %s", म_त्रुटि(त्रुटि_सं));
		वापस -1;
	}
	अगर ((pid = विभाजन()) == -1) {
		error_f("fork: %s", म_त्रुटि(त्रुटि_सं));
		वापस -1;
	}
	osigchld = ssh_signal(SIGCHLD, संक_पूर्व);
	अगर (pid == 0) {
		बंद(from[0]);
		अगर (dup2(from[1], STDOUT_FILENO) == -1)
			fatal_f("dup2: %s", म_त्रुटि(त्रुटि_सं));
		बंद(to[1]);
		अगर (dup2(to[0], STDIN_FILENO) == -1)
			fatal_f("dup2: %s", म_त्रुटि(त्रुटि_सं));
		बंद(from[1]);
		बंद(to[0]);

		अगर (dup2(sock, STDERR_FILENO + 1) == -1)
			fatal_f("dup2: %s", म_त्रुटि(त्रुटि_सं));
		sock = STDERR_FILENO + 1;
		अगर (fcntl(sock, F_SETFD, 0) == -1) /* keep the socket on exec */
			debug3_f("fcntl F_SETFD: %s", म_त्रुटि(त्रुटि_सं));
		closefrom(sock + 1);

		debug3_f("[child] pid=%ld, exec %s",
		    (दीर्घ)getpid(), PATH_SSH_कुंजी_SIGN);
		execl(PATH_SSH_कुंजी_SIGN, PATH_SSH_कुंजी_SIGN, (अक्षर *)शून्य);
		fatal_f("exec(%s): %s", PATH_SSH_कुंजी_SIGN,
		    म_त्रुटि(त्रुटि_सं));
	}
	बंद(from[1]);
	बंद(to[0]);
	sock = STDERR_FILENO + 1;

	अगर ((b = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	/* send # of sock, data to be signed */
	अगर ((r = sshbuf_put_u32(b, sock)) != 0 ||
	    (r = sshbuf_put_string(b, तथ्य, datalen)) != 0)
		fatal_fr(r, "buffer error");
	अगर (ssh_संदेश_send(to[1], version, b) == -1)
		fatal_f("couldn't send request");
	sshbuf_reset(b);
	r = ssh_संदेश_recv(from[0], b);
	बंद(from[0]);
	बंद(to[1]);
	अगर (r < 0) {
		error_f("no reply");
		जाओ fail;
	}

	त्रुटि_सं = 0;
	जबतक (waitpid(pid, &status, 0) == -1) {
		अगर (त्रुटि_सं != EINTR) {
			error_f("waitpid %ld: %s", (दीर्घ)pid, म_त्रुटि(त्रुटि_सं));
			जाओ fail;
		}
	}
	अगर (!WIFEXITED(status)) {
		error_f("exited abnormally");
		जाओ fail;
	}
	अगर (WEXITSTATUS(status) != 0) {
		error_f("exited with status %d", WEXITSTATUS(status));
		जाओ fail;
	}
	अगर ((r = sshbuf_get_u8(b, &rversion)) != 0) {
		error_fr(r, "buffer error");
		जाओ fail;
	}
	अगर (rversion != version) {
		error_f("bad version");
		जाओ fail;
	}
	अगर ((r = sshbuf_get_string(b, sigp, lenp)) != 0) {
		error_fr(r, "buffer error");
 fail:
		ssh_signal(SIGCHLD, osigchld);
		sshbuf_free(b);
		वापस -1;
	}
	ssh_signal(SIGCHLD, osigchld);
	sshbuf_free(b);

	वापस 0;
}

अटल पूर्णांक
userauth_hostbased(काष्ठा ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	काष्ठा sshkey *निजी = शून्य;
	काष्ठा sshbuf *b = शून्य;
	u_char *sig = शून्य, *keyblob = शून्य;
	अक्षर *fp = शून्य, *chost = शून्य, *lname = शून्य;
	माप_प्रकार siglen = 0, keylen = 0;
	पूर्णांक i, r, success = 0;

	अगर (authctxt->ktypes == शून्य) {
		authctxt->oktypes = xstrdup(options.hostbased_accepted_algos);
		authctxt->ktypes = authctxt->oktypes;
	}

	/*
	 * Work through each listed type pattern in HostbasedAcceptedAlgorithms,
	 * trying each hostkey that matches the type in turn.
	 */
	क्रम (;;) {
		अगर (authctxt->active_ktype == शून्य)
			authctxt->active_ktype = strsep(&authctxt->ktypes, ",");
		अगर (authctxt->active_ktype == शून्य ||
		    *authctxt->active_ktype == '\0')
			अवरोध;
		debug3_f("trying key type %s", authctxt->active_ktype);

		/* check for a useful key */
		निजी = शून्य;
		क्रम (i = 0; i < authctxt->sensitive->nkeys; i++) {
			अगर (authctxt->sensitive->कुंजियाँ[i] == शून्य ||
			    authctxt->sensitive->कुंजियाँ[i]->type == कुंजी_UNSPEC)
				जारी;
			अगर (!sshkey_match_keyname_to_sigalgs(
			    sshkey_ssh_name(authctxt->sensitive->कुंजियाँ[i]),
			    authctxt->active_ktype))
				जारी;
			/* we take and free the key */
			निजी = authctxt->sensitive->कुंजियाँ[i];
			authctxt->sensitive->कुंजियाँ[i] = शून्य;
			अवरोध;
		}
		/* Found one */
		अगर (निजी != शून्य)
			अवरोध;
		/* No more keys of this type; advance */
		authctxt->active_ktype = शून्य;
	}
	अगर (निजी == शून्य) {
		मुक्त(authctxt->oktypes);
		authctxt->oktypes = authctxt->ktypes = शून्य;
		authctxt->active_ktype = शून्य;
		debug("No more client hostkeys for hostbased authentication.");
		जाओ out;
	}

	अगर ((fp = sshkey_fingerprint(निजी, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == शून्य) {
		error_f("sshkey_fingerprint failed");
		जाओ out;
	}
	debug_f("trying hostkey %s %s using sigalg %s",
	    sshkey_ssh_name(निजी), fp, authctxt->active_ktype);

	/* figure out a name for the client host */
	lname = get_local_name(ssh_packet_get_connection_in(ssh));
	अगर (lname == शून्य) {
		error_f("cannot get local ipaddr/name");
		जाओ out;
	}

	/* XXX sshbuf_put_stringf? */
	xasprintf(&chost, "%s.", lname);
	debug2_f("chost %s", chost);

	/* construct data */
	अगर ((b = sshbuf_new()) == शून्य) {
		error_f("sshbuf_new failed");
		जाओ out;
	}
	अगर ((r = sshkey_to_blob(निजी, &keyblob, &keylen)) != 0) {
		error_fr(r, "sshkey_to_blob");
		जाओ out;
	}
	अगर ((r = sshbuf_put_stringb(b, ssh->kex->session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_संदेश_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->server_user)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->method->name)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->active_ktype)) != 0 ||
	    (r = sshbuf_put_string(b, keyblob, keylen)) != 0 ||
	    (r = sshbuf_put_cstring(b, chost)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->local_user)) != 0) {
		error_fr(r, "buffer error");
		जाओ out;
	}

#अगर_घोषित DEBUG_PK
	sshbuf_dump(b, मानक_त्रुटि);
#पूर्ण_अगर
	अगर ((r = ssh_keysign(ssh, निजी, &sig, &siglen,
	    sshbuf_ptr(b), sshbuf_len(b))) != 0) {
		error("sign using hostkey %s %s failed",
		    sshkey_ssh_name(निजी), fp);
		जाओ out;
	}
	अगर ((r = sshpkt_start(ssh, SSH2_संदेश_USERAUTH_REQUEST)) != 0 ||
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
		जाओ out;
	}
	success = 1;

 out:
	अगर (sig != शून्य)
		freezero(sig, siglen);
	मुक्त(keyblob);
	मुक्त(lname);
	मुक्त(fp);
	मुक्त(chost);
	sshkey_free(निजी);
	sshbuf_free(b);

	वापस success;
}

/* find auth method */

/*
 * given auth method name, if configurable options permit this method fill
 * in auth_ident field and return true, otherwise return false.
 */
अटल पूर्णांक
authmethod_is_enabled(Authmethod *method)
{
	अगर (method == शून्य)
		वापस 0;
	/* return false if options indicate this method is disabled */
	अगर  (method->enabled == शून्य || *method->enabled == 0)
		वापस 0;
	/* return false if batch mode is enabled but method needs interactive mode */
	अगर  (method->batch_flag != शून्य && *method->batch_flag != 0)
		वापस 0;
	वापस 1;
}

अटल Authmethod *
authmethod_lookup(स्थिर अक्षर *name)
{
	Authmethod *method = शून्य;
	अगर (name != शून्य)
		क्रम (method = authmethods; method->name != शून्य; method++)
			अगर (म_भेद(name, method->name) == 0)
				वापस method;
	debug2("Unrecognized authentication method name: %s", name ? name : "NULL");
	वापस शून्य;
}

/* XXX internal state */
अटल Authmethod *current = शून्य;
अटल अक्षर *supported = शून्य;
अटल अक्षर *preferred = शून्य;

/*
 * Given the authentication method list sent by the server, return the
 * next method we should try.  If the server initially sends a nil list,
 * use a built-in default list.
 */
अटल Authmethod *
authmethod_get(अक्षर *authlist)
{
	अक्षर *name = शून्य;
	u_int अग्र;

	/* Use a suitable default if we're passed a nil list.  */
	अगर (authlist == शून्य || म_माप(authlist) == 0)
		authlist = options.preferred_authentications;

	अगर (supported == शून्य || म_भेद(authlist, supported) != 0) {
		debug3("start over, passed a different list %s", authlist);
		मुक्त(supported);
		supported = xstrdup(authlist);
		preferred = options.preferred_authentications;
		debug3("preferred %s", preferred);
		current = शून्य;
	} अन्यथा अगर (current != शून्य && authmethod_is_enabled(current))
		वापस current;

	क्रम (;;) {
		अगर ((name = match_list(preferred, supported, &अग्र)) == शून्य) {
			debug("No more authentication methods to try.");
			current = शून्य;
			वापस शून्य;
		}
		preferred += अग्र;
		debug3("authmethod_lookup %s", name);
		debug3("remaining preferred: %s", preferred);
		अगर ((current = authmethod_lookup(name)) != शून्य &&
		    authmethod_is_enabled(current)) {
			debug3("authmethod_is_enabled %s", name);
			debug("Next authentication method: %s", name);
			मुक्त(name);
			वापस current;
		}
		मुक्त(name);
	}
}

अटल अक्षर *
authmethods_get(व्योम)
{
	Authmethod *method = शून्य;
	काष्ठा sshbuf *b;
	अक्षर *list;
	पूर्णांक r;

	अगर ((b = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	क्रम (method = authmethods; method->name != शून्य; method++) {
		अगर (authmethod_is_enabled(method)) {
			अगर ((r = sshbuf_putf(b, "%s%s",
			    sshbuf_len(b) ? "," : "", method->name)) != 0)
				fatal_fr(r, "buffer error");
		}
	}
	अगर ((list = sshbuf_dup_string(b)) == शून्य)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	वापस list;
}
