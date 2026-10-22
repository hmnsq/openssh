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
#यदि defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
#अन्तर्भाव <vis.h>
#यदि_अन्तः

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

#यदि_परिभाषितम् GSSAPI
#अन्तर्भाव "ssh-gss.h"
#यदि_अन्तः

/* import */
बाह्य Options options;

/*
 * SSH2 key exchange
 */

स्थिर वर्ण *xxx_host;
स्थिर संरचना sockaddr_storage xxx_hostaddr;
स्थिर ध्रुव संरचना ssh_conn_info *xxx_conn_info;
स्थिर पूर्णाङ्क कुञ्चिका_type_allowed(संरचना sshkey *, ध्रुव वर्ण *);

स्थिर पूर्णाङ्क
verify_host_कुञ्चिका_callback(संरचना sshkey *hostkey, संरचना ssh *ssh)
{
	पूर्णाङ्क r;

	यदि ((r = sshkey_check_rsa_दीर्घता(hostkey,
	    options.required_rsa_आकार)) != 0)
		fatal_r(r, "Bad server host key");
	यदि (!कुञ्चिका_type_allowed(hostkey, options.hostkeyalgorithms)) {
		fatal("Server host key %s not in HostKeyAlgorithms",
		    sshkey_ssh_name(hostkey));
	}
	यदि (verify_host_कुञ्चिका(xxx_host, (संरचना sockaddr *)&xxx_hostaddr, hostkey,
	    xxx_conn_info) != 0)
		fatal("Host key verification failed.");
	प्रत्यागम 0;
}

/* Returns the first item from a comma-separated algorithm list */
स्थिर वर्ण *
first_alg(ध्रुव वर्ण *algs)
{
	वर्ण *ret, *cp;

	ret = xstrdup(algs);
	यदि ((cp = strchr(ret, ',')) != रिक्त)
		*cp = '\0';
	प्रत्यागम ret;
}

स्थिर वर्ण *
क्रमः_hostkeyalgs(वर्ण *host, संरचना sockaddr *hostaddr, u_short पत्तनम्,
    ध्रुव संरचना ssh_conn_info *cinfo)
{
	वर्ण *oavail = रिक्त, *avail = रिक्त, *first = रिक्त, *चरमः = रिक्त;
	वर्ण *alg = रिक्त, *hostname = रिक्त, *ret = रिक्त, *best = रिक्त;
	आकार_t maxlen;
	संरचना hostkeys *hostkeys = रिक्त;
	पूर्णाङ्क ktype;
	u_int i;

	/* Find all hostkeys for this hostname */
	get_hostfile_hostname_ipaddr(host, hostaddr, पत्तनम्, &hostname, रिक्त);
	hostkeys = init_hostkeys();
	प्रति (i = 0; i < options.अङ्कः_user_hostfiles; i++)
		आरोपय_hostkeys(hostkeys, hostname, options.user_hostfiles[i], 0);
	प्रति (i = 0; i < options.अङ्कः_system_hostfiles; i++) {
		आरोपय_hostkeys(hostkeys, hostname,
		    options.system_hostfiles[i], 0);
	}
	यदि (options.ज्ञातम्_hosts_command != रिक्त) {
		आरोपय_hostkeys_command(hostkeys, options.ज्ञातम्_hosts_command,
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
	यदि (lookup_कुञ्चिका_अन्तर्_hostkeys_by_type(hostkeys,
	    sshkey_type_plain(sshkey_type_from_name(best)),
	    sshkey_ecdsa_nid_from_name(best), रिक्त)) {
		debug3_f("have matching best-preference key type %s, "
		    "using HostkeyAlgorithms verbatim", best);
		ret = xstrdup(options.hostkeyalgorithms);
		गच्छ बहिर्गमनम्;
	}

	/*
	 * Otherwise, prefer the host key algorithms that match known keys
	 * while keeping the ordering of HostkeyAlgorithms as much as possible.
	 */
	oavail = avail = xstrdup(options.hostkeyalgorithms);
	maxlen = वाक्यदैर्घ्यम्(avail) + 1;
	first = xmalloc(maxlen);
	चरमः = xmalloc(maxlen);
	*first = *चरमः = '\0';

#परिभाषय ALG_APPEND(गन्तव्यम्, from) \
	कुरु { \
		यदि (*गन्तव्यम् != '\0') \
			strlcat(गन्तव्यम्, ",", maxlen); \
		strlcat(गन्तव्यम्, from, maxlen); \
	} यावत् (0)

	यावत् ((alg = strsep(&avail, ",")) && *alg != '\0') {
		यदि ((ktype = sshkey_type_from_name(alg)) == कुञ्चिका_UNSPEC)
			fatal_f("unknown alg %s", alg);
		/*
		 * If we have a @cert-authority marker in known_hosts then
		 * prefer all certificate algorithms.
		 */
		यदि (sshkey_type_is_cert(ktype) &&
		    lookup_marker_अन्तर्_hostkeys(hostkeys, MRK_CA)) {
			ALG_APPEND(first, alg);
			अनुवर्त;
		}
		/* If the key appears in known_hosts then prefer it */
		यदि (lookup_कुञ्चिका_अन्तर्_hostkeys_by_type(hostkeys,
		    sshkey_type_plain(ktype),
		    sshkey_ecdsa_nid_from_name(alg), रिक्त)) {
			ALG_APPEND(first, alg);
			अनुवर्त;
		}
		/* Otherwise, put it last */
		ALG_APPEND(चरमः, alg);
	}
#अपरिभाषय ALG_APPEND
	xasprintf(&ret, "%s%s%s", first,
	    (*first == '\0' || *चरमः == '\0') ? "" : ",", चरमः);
	यदि (*first != '\0')
		debug3_f("prefer hostkeyalgs: %s", first);
	अन्यथा
		debug3_f("no algorithms matched; accept original");
 बहिर्गमनम्:
	मुक्त(best);
	मुक्त(first);
	मुक्त(चरमः);
	मुक्त(hostname);
	मुक्त(oavail);
	free_hostkeys(hostkeys);

	प्रत्यागम ret;
}

शून्य
ssh_kex2(संरचना ssh *ssh, वर्ण *host, संरचना sockaddr_storage *hostaddr,
    u_short पत्तनम्, ध्रुव संरचना ssh_conn_info *cinfo)
{
	वर्ण *myproposal[PROPOSAL_MAX];
	वर्ण *all_कुञ्चिका, *hkalgs = रिक्त;
	पूर्णाङ्क r, use_ज्ञातम्_hosts_क्रमः = 0;

	xxx_host = xstrdup(host);
	xxx_hostaddr = *hostaddr;
	xxx_conn_info = ssh_conn_info_dup(cinfo);

	ssh_packet_समुच्चयः_rekey_limits(ssh, options.rekey_सीमा,
	    options.rekey_interval);

	/*
	 * If the user has not specified HostkeyAlgorithms, or has only
	 * appended or removed algorithms from that list then prefer algorithms
	 * that are in the list that are supported by known_hosts keys.
	 */
	यदि (options.hostkeyalgorithms == रिक्त ||
	    options.hostkeyalgorithms[0] == '-' ||
	    options.hostkeyalgorithms[0] == '+')
		use_ज्ञातम्_hosts_क्रमः = 1;

	/* Expand or fill in HostkeyAlgorithms */
	all_कुञ्चिका = sshkey_alg_list(0, 0, 1, ',');
	यदि ((r = kex_assemble_नामानि(&options.hostkeyalgorithms,
	    kex_default_pk_alg(), all_कुञ्चिका)) != 0)
		fatal_fr(r, "kex_assemble_namelist");
	मुक्त(all_कुञ्चिका);

	यदि (use_ज्ञातम्_hosts_क्रमः) {
		hkalgs = क्रमः_hostkeyalgs(host, (संरचना sockaddr *)hostaddr,
		    पत्तनम्, cinfo);
	}

	kex_proposal_populate_entries(ssh, myproposal,
	    options.kex_algorithms, options.ciphers, options.macs,
	    compression_alg_list(options.compression),
	    hkalgs ? hkalgs : options.hostkeyalgorithms);

	मुक्त(hkalgs);

	/* start key exchange */
	यदि ((r = kex_सज्जता(ssh, myproposal)) != 0)
		fatal_r(r, "kex_setup");
#यदि_परिभाषितम् WITH_OPENSSL
	ssh->kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GEX_SHA1] = kexgex_client;
	ssh->kex->kex[KEX_DH_GEX_SHA256] = kexgex_client;
	ssh->kex->kex[KEX_ECDH_SHA2] = kex_gen_client;
#यदि_अन्तः
	ssh->kex->kex[KEX_C25519_SHA256] = kex_gen_client;
	ssh->kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_client;
	ssh->kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_client;
	ssh->kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_client;
	ssh->kex->verify_host_कुञ्चिका=&verify_host_कुञ्चिका_callback;

	ssh_dispatch_सततम्_fatal(ssh, DISPATCH_खण्डम्, &ssh->kex->समाप्तम्);
	kex_proposal_free_entries(myproposal);

#यदि_परिभाषितम् DEBUG_KEXDH
	/* send 1st encrypted/maced/compressed message */
	यदि ((r = sshpkt_start(ssh, SSH2_सन्देशः_IGNORE)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "markus")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send packet");
#यदि_अन्तः
}

/*
 * Authenticate user
 */

प्रकारनिर्देश संरचना cauthctxt Authctxt;
प्रकारनिर्देश संरचना cauthmethod Authmethod;
प्रकारनिर्देश संरचना तटस्थः_2 तटस्थः;
प्रकारनिर्देश संरचना idlist Idlist;

संरचना तटस्थः_2 {
	TAILQ_ENTRY(तटस्थः_2) अग्र;
	पूर्णाङ्क	agent_fd;		/* >=0 if agent supports key */
	संरचना sshkey	*कुञ्चिका;		/* public/private key */
	वर्ण	*filename;		/* comment for agent-only keys */
	पूर्णाङ्क	tried;
	पूर्णाङ्क	isprivate;		/* key points to the private key */
	पूर्णाङ्क	userprovided;
};
TAILQ_HEAD(idlist, तटस्थः_2);

संरचना cauthctxt {
	ध्रुव वर्ण *server_user;
	ध्रुव वर्ण *local_user;
	ध्रुव वर्ण *host;
	ध्रुव वर्ण *service;
	संरचना cauthmethod *विधानम्;
	sig_atomic_t success;
	वर्ण *authlist;
#यदि_परिभाषितम् GSSAPI
	/* gssapi */
	gss_OID_समुच्चयः gss_supported_mechs;
	u_int mech_tried;
#यदि_अन्तः
	/* pubkey */
	संरचना idlist कुञ्चिकाः;
	पूर्णाङ्क agent_fd;
	/* hostbased */
	Sensitive *sensitive;
	वर्ण *oktypes, *ktypes;
	ध्रुव वर्ण *सक्रिय_ktype;
	/* kbd-interactive */
	पूर्णाङ्क info_req_आलोकितम्;
	पूर्णाङ्क attempt_kbdint;
	/* password */
	पूर्णाङ्क attempt_passwd;
	/* generic */
	शून्य *methoddata;
};

संरचना cauthmethod {
	वर्ण	*name;		/* string to compare against server's list */
	पूर्णाङ्क	(*userauth)(संरचना ssh *ssh);
	शून्य	(*cleanup)(संरचना ssh *ssh);
	पूर्णाङ्क	*enabled;	/* flag in option struct that enables method */
	पूर्णाङ्क	*batch_flag;	/* flag in option struct that disables method */
};

स्थिर पूर्णाङ्क निवेशः_userauth_service_accept(पूर्णाङ्क, uint32_t, संरचना ssh *);
स्थिर पूर्णाङ्क निवेशः_userauth_success(पूर्णाङ्क, uint32_t, संरचना ssh *);
स्थिर पूर्णाङ्क निवेशः_userauth_failure(पूर्णाङ्क, uint32_t, संरचना ssh *);
स्थिर पूर्णाङ्क निवेशः_userauth_banner(पूर्णाङ्क, uint32_t, संरचना ssh *);
स्थिर पूर्णाङ्क निवेशः_userauth_error(पूर्णाङ्क, uint32_t, संरचना ssh *);
स्थिर पूर्णाङ्क निवेशः_userauth_info_req(पूर्णाङ्क, uint32_t, संरचना ssh *);
स्थिर पूर्णाङ्क निवेशः_userauth_pk_ok(पूर्णाङ्क, uint32_t, संरचना ssh *);
स्थिर पूर्णाङ्क निवेशः_userauth_passwd_changereq(पूर्णाङ्क, uint32_t, संरचना ssh *);

स्थिर पूर्णाङ्क userauth_none(संरचना ssh *);
स्थिर पूर्णाङ्क userauth_pubkey(संरचना ssh *);
स्थिर पूर्णाङ्क userauth_passwd(संरचना ssh *);
स्थिर पूर्णाङ्क userauth_kbdint(संरचना ssh *);
स्थिर पूर्णाङ्क userauth_hostbased(संरचना ssh *);

#यदि_परिभाषितम् GSSAPI
स्थिर पूर्णाङ्क userauth_gssapi(संरचना ssh *);
स्थिर शून्य userauth_gssapi_cleanup(संरचना ssh *);
स्थिर पूर्णाङ्क निवेशः_gssapi_response(पूर्णाङ्क type, uint32_t, संरचना ssh *);
स्थिर पूर्णाङ्क निवेशः_gssapi_token(पूर्णाङ्क type, uint32_t, संरचना ssh *);
स्थिर पूर्णाङ्क निवेशः_gssapi_error(पूर्णाङ्क, uint32_t, संरचना ssh *);
स्थिर पूर्णाङ्क निवेशः_gssapi_errtok(पूर्णाङ्क, uint32_t, संरचना ssh *);
#यदि_अन्तः

शून्य	userauth(संरचना ssh *, वर्ण *);

स्थिर शून्य pubkey_cleanup(संरचना ssh *);
स्थिर पूर्णाङ्क sign_and_send_pubkey(संरचना ssh *ssh, तटस्थः *);
स्थिर शून्य pubkey_prepare(संरचना ssh *, Authctxt *);
स्थिर शून्य pubkey_reset(Authctxt *);
स्थिर संरचना sshkey *आरोपय_तटस्थः_file(तटस्थः *);

स्थिर Authmethod *authmethod_get(वर्ण *authlist);
स्थिर Authmethod *authmethod_lookup(ध्रुव वर्ण *name);
स्थिर वर्ण *authmethods_get(शून्य);

Authmethod authmethods[] = {
#यदि_परिभाषितम् GSSAPI
	{"gssapi-with-mic",
		userauth_gssapi,
		userauth_gssapi_cleanup,
		&options.gss_authentication,
		रिक्त},
#यदि_अन्तः
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
		&options.batch_बहुलकम्},
	{"password",
		userauth_passwd,
		रिक्त,
		&options.password_authentication,
		&options.batch_बहुलकम्},
	{"none",
		userauth_none,
		रिक्त,
		रिक्त,
		रिक्त},
	{रिक्त, रिक्त, रिक्त, रिक्त, रिक्त}
};

शून्य
ssh_userauth2(संरचना ssh *ssh, ध्रुव वर्ण *local_user,
    ध्रुव वर्ण *server_user, वर्ण *host, Sensitive *sensitive)
{
	Authctxt authctxt;
	पूर्णाङ्क r;

	यदि (options.preferred_authentications == रिक्त)
		options.preferred_authentications = authmethods_get();

	/* setup authentication context */
	स्मृतिं_पूरय(&authctxt, 0, परिमाण(authctxt));
	authctxt.server_user = server_user;
	authctxt.local_user = local_user;
	authctxt.host = host;
	authctxt.service = "ssh-connection";		/* service name */
	authctxt.success = 0;
	authctxt.विधानम् = authmethod_lookup("none");
	authctxt.authlist = रिक्त;
	authctxt.methoddata = रिक्त;
	authctxt.sensitive = sensitive;
	authctxt.सक्रिय_ktype = authctxt.oktypes = authctxt.ktypes = रिक्त;
	authctxt.info_req_आलोकितम् = 0;
	authctxt.attempt_kbdint = 0;
	authctxt.attempt_passwd = 0;
#यदि GSSAPI
	authctxt.gss_supported_mechs = रिक्त;
	authctxt.mech_tried = 0;
#यदि_अन्तः
	authctxt.agent_fd = -1;
	यदि (authctxt.विधानम् == रिक्त)
		fatal_f("internal error: cannot send userauth none request");

	यदि ((r = sshpkt_start(ssh, SSH2_सन्देशः_SERVICE_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "ssh-userauth")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh->authctxt = &authctxt;
	ssh_dispatch_init(ssh, &निवेशः_userauth_error);
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_EXT_INFO, kex_निवेशः_ext_info);
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_SERVICE_ACCEPT, &निवेशः_userauth_service_accept);
	ssh_dispatch_सततम्_fatal(ssh, DISPATCH_खण्डम्, &authctxt.success);	/* loop until success */
	pubkey_cleanup(ssh);
#यदि_परिभाषितम् GSSAPI
	यदि (authctxt.gss_supported_mechs != रिक्त) {
		u_int ms;

		gss_release_oid_समुच्चयः(&ms, &authctxt.gss_supported_mechs);
		authctxt.gss_supported_mechs = रिक्त;
	}
#यदि_अन्तः
	ssh->authctxt = रिक्त;

	ssh_dispatch_range(ssh, SSH2_सन्देशः_USERAUTH_MIN, SSH2_सन्देशः_USERAUTH_MAX, रिक्त);

	यदि (!authctxt.success)
		fatal("Authentication failed.");
	यदि (ssh_packet_connection_is_on_socket(ssh)) {
		verbose("Authenticated to %s ([%s]:%d) using \"%s\".", host,
		    ssh_remote_ipaddr(ssh), ssh_remote_पत्तनम्(ssh),
		    authctxt.विधानम्->name);
	} अन्यथा {
		verbose("Authenticated to %s (via proxy) using \"%s\".", host,
		    authctxt.विधानम्->name);
	}
}

स्थिर पूर्णाङ्क
निवेशः_userauth_service_accept(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	पूर्णाङ्क r;

	यदि (ssh_packet_remaining(ssh) > 0) {
		वर्ण *प्रत्युत्तरम्;

		यदि ((r = sshpkt_get_cstring(ssh, &प्रत्युत्तरम्, रिक्त)) != 0)
			गच्छ बहिर्गमनम्;
		debug2("service_accept: %s", प्रत्युत्तरम्);
		मुक्त(प्रत्युत्तरम्);
	} अन्यथा {
		debug2("buggy server: service_accept w/o service");
	}
	यदि ((r = sshpkt_get_अन्तः(ssh)) != 0)
		गच्छ बहिर्गमनम्;
	debug("SSH2_MSG_SERVICE_ACCEPT received");

	/* initial userauth request */
	userauth_none(ssh);

	/* accept EXT_INFO at any time during userauth */
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_EXT_INFO, ssh->kex->ext_info_s ?
	    &kex_निवेशः_ext_info : &निवेशः_userauth_error);
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_USERAUTH_SUCCESS, &निवेशः_userauth_success);
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_USERAUTH_FAILURE, &निवेशः_userauth_failure);
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_USERAUTH_BANNER, &निवेशः_userauth_banner);
	r = 0;
 बहिर्गमनम्:
	प्रत्यागम r;
}

शून्य
userauth(संरचना ssh *ssh, वर्ण *authlist)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;

	यदि (authctxt->विधानम् != रिक्त && authctxt->विधानम्->cleanup != रिक्त)
		authctxt->विधानम्->cleanup(ssh);

	मुक्त(authctxt->methoddata);
	authctxt->methoddata = रिक्त;
	यदि (authlist == रिक्त) {
		authlist = authctxt->authlist;
	} अन्यथा {
		मुक्त(authctxt->authlist);
		authctxt->authlist = authlist;
	}
	प्रति (;;) {
		Authmethod *विधानम् = authmethod_get(authlist);
		यदि (विधानम् == रिक्त)
			fatal("%s@%s: Permission denied (%s).",
			    authctxt->server_user, authctxt->host, authlist);
		authctxt->विधानम् = विधानम्;

		/* reset the per method handler */
		ssh_dispatch_range(ssh, SSH2_सन्देशः_USERAUTH_प्रत्येकम्_विधानम्_MIN,
		    SSH2_सन्देशः_USERAUTH_प्रत्येकम्_विधानम्_MAX, रिक्त);

		/* and try new method */
		यदि (विधानम्->userauth(ssh) != 0) {
			debug2("we sent a %s packet, wait for reply", विधानम्->name);
			भङ्ग;
		} अन्यथा {
			debug2("we did not send a packet, disable method");
			विधानम्->enabled = रिक्त;
		}
	}
}

स्थिर पूर्णाङ्क
निवेशः_userauth_error(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	fatal_f("bad message during authentication: type %d", type);
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
निवेशः_userauth_banner(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	वर्ण *सन्देशः = रिक्त;
	आकार_t len;
	पूर्णाङ्क r;

	debug3_f("entering");
	यदि ((r = sshpkt_get_cstring(ssh, &सन्देशः, &len)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, रिक्त, रिक्त)) != 0)
		गच्छ बहिर्गमनम्;
	यदि (len > 0 && options.log_level >= SYSLOG_LEVEL_INFO)
		fmprintf(stderr, "%s", सन्देशः);
	r = 0;
 बहिर्गमनम्:
	मुक्त(सन्देशः);
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
निवेशः_userauth_success(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	यदि (authctxt == रिक्त)
		fatal_f("no authentication context");
	मुक्त(authctxt->authlist);
	authctxt->authlist = रिक्त;
	यदि (authctxt->विधानम् != रिक्त && authctxt->विधानम्->cleanup != रिक्त)
		authctxt->विधानम्->cleanup(ssh);
	मुक्त(authctxt->methoddata);
	authctxt->methoddata = रिक्त;
	authctxt->success = 1;			/* break out */
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_EXT_INFO, dispatch_protocol_error);
	प्रत्यागम 0;
}

#यदि 0
स्थिर पूर्णाङ्क
निवेशः_userauth_success_unexpected(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	यदि (authctxt == रिक्त)
		fatal_f("no authentication context");

	fatal("Unexpected authentication success during %s.",
	    authctxt->विधानम्->name);
	प्रत्यागम 0;
}
#यदि_अन्तः

स्थिर पूर्णाङ्क
निवेशः_userauth_failure(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	वर्ण *authlist = रिक्त;
	u_char partial;

	यदि (authctxt == रिक्त)
		fatal("input_userauth_failure: no authentication context");

	यदि (sshpkt_get_cstring(ssh, &authlist, रिक्त) != 0 ||
	    sshpkt_get_u8(ssh, &partial) != 0 ||
	    sshpkt_get_अन्तः(ssh) != 0)
		गच्छ बहिर्गमनम्;

	यदि (partial != 0) {
		verbose("Authenticated using \"%s\" with partial success.",
		    authctxt->विधानम्->name);
		/* reset state */
		pubkey_reset(authctxt);
	}
	debug("Authentications that can continue: %s", authlist);

	userauth(ssh, authlist);
	authlist = रिक्त;
 बहिर्गमनम्:
	मुक्त(authlist);
	प्रत्यागम 0;
}

/*
 * Format an identity for logging including filename, key type, fingerprint
 * and location (agent, etc.). Caller must free.
 */
स्थिर वर्ण *
format_तटस्थः(तटस्थः *id)
{
	वर्ण *fp = रिक्त, *ret = रिक्त;
	ध्रुव वर्ण *note = "";

	यदि (id->कुञ्चिका != रिक्त) {
		fp = sshkey_fingerprint(id->कुञ्चिका, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
	}
	यदि (id->कुञ्चिका) {
		यदि ((id->कुञ्चिका->flags & SSHKEY_FLAG_EXT) != 0)
			note = " token";
		अन्यथा यदि (sshkey_is_sk(id->कुञ्चिका))
			note = " authenticator";
	}
	xasprintf(&ret, "%s %s%s%s%s%s%s",
	    id->filename,
	    id->कुञ्चिका ? sshkey_type(id->कुञ्चिका) : "", id->कुञ्चिका ? " " : "",
	    fp ? fp : "",
	    id->userprovided ? " explicit" : "", note,
	    id->agent_fd != -1 ? " agent" : "");
	मुक्त(fp);
	प्रत्यागम ret;
}

स्थिर पूर्णाङ्क
निवेशः_userauth_pk_ok(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	संरचना sshkey *कुञ्चिका = रिक्त;
	संरचना sshbuf *keyblob = रिक्त;
	तटस्थः *id = रिक्त;
	पूर्णाङ्क pktype, प्राप्तम् = 0, प्रेषितम् = 0;
	वर्ण *pkalg = रिक्त, *fp = रिक्त, *ident = रिक्त;
	पूर्णाङ्क r;

	यदि (authctxt == रिक्त)
		fatal_f("no authentication context");

	यदि ((r = sshpkt_get_cstring(ssh, &pkalg, रिक्त)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0 ||
	    (r = sshpkt_get_अन्तः(ssh)) != 0)
		गच्छ समाप्तम्;

	यदि (मेलनम्_आदर्शः_list(pkalg, options.pubkey_accepted_algos, 0) != 1) {
		error_f("server replied to PK_OK with signature type %s not "
		    "in PubkeyAcceptedAlgorithms", pkalg);
		r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		गच्छ समाप्तम्;
	}
	यदि ((pktype = sshkey_type_from_name(pkalg)) == कुञ्चिका_UNSPEC) {
		debug_f("server sent unknown pkalg %s", pkalg);
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ समाप्तम्;
	}
	/* inner key type should match signature type */
	यदि ((r = sshkey_fromb_allowlist(keyblob, &कुञ्चिका, pkalg, रिक्त)) != 0) {
		debug_r(r, "no key from blob. pkalg %s", pkalg);
		गच्छ समाप्तम्;
	}
	यदि (कुञ्चिका->type != pktype) {
		error("input_userauth_pk_ok: type mismatch "
		    "for decoded key (received %d, expected %d)",
		    कुञ्चिका->type, pktype);
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ समाप्तम्;
	}

	/*
	 * search keys in the reverse order, because last candidate has been
	 * moved to the end of the queue.  this also avoids confusion by
	 * duplicate keys
	 */
	TAILQ_FOREACH_REVERSE(id, &authctxt->कुञ्चिकाः, idlist, अग्र) {
		यदि (sshkey_equal(कुञ्चिका, id->कुञ्चिका)) {
			प्राप्तम् = 1;
			भङ्ग;
		}
	}
	यदि (!प्राप्तम् || id == रिक्त) {
		fp = sshkey_fingerprint(कुञ्चिका, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		error_f("server replied with unknown key: %s %s",
		    sshkey_type(कुञ्चिका), fp == रिक्त ? "<ERROR>" : fp);
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ समाप्तम्;
	}
	ident = format_तटस्थः(id);
	debug("Server accepts key: %s", ident);
	प्रेषितम् = sign_and_send_pubkey(ssh, id);
	r = 0;
 समाप्तम्:
	sshkey_free(कुञ्चिका);
	sshbuf_free(keyblob);
	मुक्त(ident);
	मुक्त(fp);
	मुक्त(pkalg);

	/* try another method if we did not send a packet */
	यदि (r == 0 && प्रेषितम् == 0)
		userauth(ssh, रिक्त);
	प्रत्यागम r;
}

#यदि_परिभाषितम् GSSAPI
स्थिर पूर्णाङ्क
userauth_gssapi(संरचना ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Gssctxt *gssctxt = रिक्त;
	OM_uint32 min;
	पूर्णाङ्क r, ok = 0;
	gss_OID mech = रिक्त;

	/* Try one GSSAPI method at a time, rather than sending them all at
	 * once. */

	यदि (authctxt->gss_supported_mechs == रिक्त)
		gss_indicate_mechs(&min, &authctxt->gss_supported_mechs);

	/* Check to see whether the mechanism is usable before we offer it */
	यावत् (authctxt->mech_tried < authctxt->gss_supported_mechs->गणनम् &&
	    !ok) {
		mech = &authctxt->gss_supported_mechs->
		    elements[authctxt->mech_tried];
		/* My DER encoding requires length<128 */
		यदि (mech->दीर्घता < 128 && ssh_gssapi_check_mechanism(&gssctxt,
		    mech, authctxt->host)) {
			ok = 1; /* Mechanism works */
		} अन्यथा {
			authctxt->mech_tried++;
		}
	}

	यदि (!ok || mech == रिक्त)
		प्रत्यागम 0;

	authctxt->methoddata=(शून्य *)gssctxt;

	यदि ((r = sshpkt_start(ssh, SSH2_सन्देशः_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->विधानम्->name)) != 0 ||
	    (r = sshpkt_put_u32(ssh, 1)) != 0 ||
	    (r = sshpkt_put_u32(ssh, (mech->दीर्घता) + 2)) != 0 ||
	    (r = sshpkt_put_u8(ssh, SSH_GSS_OIDTYPE)) != 0 ||
	    (r = sshpkt_put_u8(ssh, mech->दीर्घता)) != 0 ||
	    (r = sshpkt_put(ssh, mech->elements, mech->दीर्घता)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_USERAUTH_GSSAPI_RESPONSE, &निवेशः_gssapi_response);
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_USERAUTH_GSSAPI_TOKEN, &निवेशः_gssapi_token);
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_USERAUTH_GSSAPI_ERROR, &निवेशः_gssapi_error);
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_USERAUTH_GSSAPI_ERRTOK, &निवेशः_gssapi_errtok);

	authctxt->mech_tried++; /* Move along to next candidate */

	प्रत्यागम 1;
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
process_gssapi_token(संरचना ssh *ssh, gss_बफर_t recv_tok)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt = authctxt->methoddata;
	gss_बफर_desc send_tok = GSS_C_रिक्तानि_बफर;
	gss_बफर_desc mic = GSS_C_रिक्तानि_बफर;
	gss_बफर_desc gssbuf;
	OM_uint32 स्थितिः, ms, flags;
	पूर्णाङ्क r;

	स्थितिः = ssh_gssapi_init_ctx(gssctxt, options.gss_deleg_creds,
	    recv_tok, &send_tok, &flags);

	यदि (send_tok.दीर्घता > 0) {
		u_char type = GSS_ERROR(स्थितिः) ?
		    SSH2_सन्देशः_USERAUTH_GSSAPI_ERRTOK :
		    SSH2_सन्देशः_USERAUTH_GSSAPI_TOKEN;

		यदि ((r = sshpkt_start(ssh, type)) != 0 ||
		    (r = sshpkt_put_string(ssh, send_tok.मानम्,
		    send_tok.दीर्घता)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send %u packet", type);

		gss_release_बफर(&ms, &send_tok);
	}

	यदि (स्थितिः == GSS_S_COMPLETE) {
		/* send either complete or MIC, depending on mechanism */
		यदि (!(flags & GSS_C_INTEG_FLAG)) {
			यदि ((r = sshpkt_start(ssh,
			    SSH2_सन्देशः_USERAUTH_GSSAPI_EXCHANGE_COMPLETE)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "send completion");
		} अन्यथा {
			संरचना sshbuf *b;

			यदि ((b = sshbuf_new()) == रिक्त)
				fatal_f("sshbuf_new failed");
			ssh_gssapi_buildmic(b, authctxt->server_user,
			    authctxt->service, "gssapi-with-mic",
			    ssh->kex->session_id);

			यदि ((gssbuf.मानम् = sshbuf_mutable_ptr(b)) == रिक्त)
				fatal_f("sshbuf_mutable_ptr failed");
			gssbuf.दीर्घता = sshbuf_len(b);

			स्थितिः = ssh_gssapi_sign(gssctxt, &gssbuf, &mic);

			यदि (!GSS_ERROR(स्थितिः)) {
				यदि ((r = sshpkt_start(ssh,
				    SSH2_सन्देशः_USERAUTH_GSSAPI_MIC)) != 0 ||
				    (r = sshpkt_put_string(ssh, mic.मानम्,
				    mic.दीर्घता)) != 0 ||
				    (r = sshpkt_send(ssh)) != 0)
					fatal_fr(r, "send MIC");
			}

			sshbuf_free(b);
			gss_release_बफर(&ms, &mic);
		}
	}

	प्रत्यागम स्थितिः;
}

स्थिर पूर्णाङ्क
निवेशः_gssapi_response(पूर्णाङ्क type, uint32_t plen, संरचना ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	आकार_t oidlen;
	u_char *oidv = रिक्त;
	पूर्णाङ्क r;

	यदि (authctxt == रिक्त)
		fatal("input_gssapi_response: no authentication context");
	gssctxt = authctxt->methoddata;

	/* Setup our OID */
	यदि ((r = sshpkt_get_string(ssh, &oidv, &oidlen)) != 0)
		गच्छ समाप्तम्;

	यदि (oidlen <= 2 ||
	    oidv[0] != SSH_GSS_OIDTYPE ||
	    oidv[1] != oidlen - 2) {
		debug("Badly encoded mechanism OID received");
		userauth(ssh, रिक्त);
		गच्छ ok;
	}

	यदि (!ssh_gssapi_check_oid(gssctxt, oidv + 2, oidlen - 2))
		fatal("Server returned different OID than expected");

	यदि ((r = sshpkt_get_अन्तः(ssh)) != 0)
		गच्छ समाप्तम्;

	यदि (GSS_ERROR(process_gssapi_token(ssh, GSS_C_NO_बफर))) {
		/* Start again with next method on list */
		debug("Trying to start again");
		userauth(ssh, रिक्त);
		गच्छ ok;
	}
 ok:
	r = 0;
 समाप्तम्:
	मुक्त(oidv);
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
निवेशः_gssapi_token(पूर्णाङ्क type, uint32_t plen, संरचना ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	gss_बफर_desc recv_tok;
	u_char *p = रिक्त;
	आकार_t len;
	OM_uint32 स्थितिः;
	पूर्णाङ्क r;

	यदि (authctxt == रिक्त)
		fatal("input_gssapi_response: no authentication context");

	यदि ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_अन्तः(ssh)) != 0)
		गच्छ बहिर्गमनम्;

	recv_tok.मानम् = p;
	recv_tok.दीर्घता = len;
	स्थितिः = process_gssapi_token(ssh, &recv_tok);

	/* Start again with the next method in the list */
	यदि (GSS_ERROR(स्थितिः)) {
		userauth(ssh, रिक्त);
		/* ok */
	}
	r = 0;
 बहिर्गमनम्:
	मुक्त(p);
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
निवेशः_gssapi_errtok(पूर्णाङ्क type, uint32_t plen, संरचना ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	gss_बफर_desc send_tok = GSS_C_रिक्तानि_बफर;
	gss_बफर_desc recv_tok;
	OM_uint32 ms;
	u_char *p = रिक्त;
	आकार_t len;
	पूर्णाङ्क r;

	यदि (authctxt == रिक्त)
		fatal("input_gssapi_response: no authentication context");
	gssctxt = authctxt->methoddata;

	यदि ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_अन्तः(ssh)) != 0) {
		मुक्त(p);
		प्रत्यागम r;
	}

	/* Stick it into GSSAPI and see what it says */
	recv_tok.मानम् = p;
	recv_tok.दीर्घता = len;
	(शून्य)ssh_gssapi_init_ctx(gssctxt, options.gss_deleg_creds,
	    &recv_tok, &send_tok, रिक्त);
	मुक्त(p);
	gss_release_बफर(&ms, &send_tok);

	/* Server will be returning a failed packet after this one */
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
निवेशः_gssapi_error(पूर्णाङ्क type, uint32_t plen, संरचना ssh *ssh)
{
	वर्ण *सन्देशः = रिक्त;
	वर्ण *lang = रिक्त;
	पूर्णाङ्क r;

	यदि ((r = sshpkt_get_u32(ssh, रिक्त)) != 0 ||	/* maj */
	    (r = sshpkt_get_u32(ssh, रिक्त)) != 0 ||	/* min */
	    (r = sshpkt_get_cstring(ssh, &सन्देशः, रिक्त)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, रिक्त)) != 0)
		गच्छ बहिर्गमनम्;
	r = sshpkt_get_अन्तः(ssh);
	debug("Server GSSAPI Error:\n%s", सन्देशः);
 बहिर्गमनम्:
	मुक्त(सन्देशः);
	मुक्त(lang);
	प्रत्यागम r;
}
#यदि_अन्तः /* GSSAPI */

स्थिर पूर्णाङ्क
userauth_none(संरचना ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	पूर्णाङ्क r;

	/* initial userauth request */
	यदि ((r = sshpkt_start(ssh, SSH2_सन्देशः_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->विधानम्->name)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	प्रत्यागम 1;
}

स्थिर पूर्णाङ्क
userauth_passwd(संरचना ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	वर्ण *password, *prompt = रिक्त;
	ध्रुव वर्ण *host = options.host_कुञ्चिका_alias ?  options.host_कुञ्चिका_alias :
	    authctxt->host;
	पूर्णाङ्क r;

	यदि (authctxt->attempt_passwd++ >= options.सङ्ख्या_सम्बन्धि_password_prompts)
		प्रत्यागम 0;

	यदि (authctxt->attempt_passwd != 1)
		error("Permission denied, please try again.");

	xasprintf(&prompt, "%s@%s's password: ", authctxt->server_user, host);
	password = read_passphrase(prompt, 0);
	यदि ((r = sshpkt_start(ssh, SSH2_सन्देशः_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->विधानम्->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, password)) != 0 ||
	    (r = sshpkt_सङ्कलय_padding(ssh, 64)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	मुक्त(prompt);
	यदि (password != रिक्त)
		freezero(password, वाक्यदैर्घ्यम्(password));

	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_USERAUTH_PASSWD_CHANGEREQ,
	    &निवेशः_userauth_passwd_changereq);

	प्रत्यागम 1;
}

/*
 * parse PASSWD_CHANGEREQ, prompt user and send SSH2_MSG_USERAUTH_REQUEST
 */
स्थिर पूर्णाङ्क
निवेशः_userauth_passwd_changereq(पूर्णाङ्क type, uint32_t seqnr, संरचना ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	वर्ण *info = रिक्त, *lang = रिक्त, *password = रिक्त, *retype = रिक्त;
	वर्ण prompt[256];
	ध्रुव वर्ण *host;
	पूर्णाङ्क r, addnl;
	आकार_t len;

	debug2("input_userauth_passwd_changereq");

	यदि (authctxt == रिक्त)
		fatal("input_userauth_passwd_changereq: "
		    "no authentication context");
	host = options.host_कुञ्चिका_alias ? options.host_कुञ्चिका_alias : authctxt->host;

	यदि ((r = sshpkt_get_cstring(ssh, &info, रिक्त)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, रिक्त)) != 0)
		गच्छ बहिर्गमनम्;
	यदि ((len = वाक्यदैर्घ्यम्(info)) > 0) {
		addnl = info[len] != '\n';
		fmprintf(stderr, "%s%s", info, addnl ? "\n" : "");
	}
	यदि ((r = sshpkt_start(ssh, SSH2_सन्देशः_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->विधानम्->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0)	/* additional info */
		गच्छ बहिर्गमनम्;

	snprintf(prompt, परिमाण(prompt),
	    "Enter %.30s@%.128s's old password: ",
	    authctxt->server_user, host);
	password = read_passphrase(prompt, 0);
	यदि ((r = sshpkt_put_cstring(ssh, password)) != 0)
		गच्छ बहिर्गमनम्;

	freezero(password, वाक्यदैर्घ्यम्(password));
	password = रिक्त;
	यावत् (password == रिक्त) {
		snprintf(prompt, परिमाण(prompt),
		    "Enter %.30s@%.128s's new password: ",
		    authctxt->server_user, host);
		password = read_passphrase(prompt, RP_ALLOW_EOF);
		यदि (password == रिक्त) {
			/* bail out */
			r = 0;
			गच्छ बहिर्गमनम्;
		}
		snprintf(prompt, परिमाण(prompt),
		    "Retype %.30s@%.128s's new password: ",
		    authctxt->server_user, host);
		retype = read_passphrase(prompt, 0);
		यदि (वाक्यं_तुलय(password, retype) != 0) {
			freezero(password, वाक्यदैर्घ्यम्(password));
			logit("Mismatch; try again, EOF to quit.");
			password = रिक्त;
		}
		freezero(retype, वाक्यदैर्घ्यम्(retype));
	}
	यदि ((r = sshpkt_put_cstring(ssh, password)) != 0 ||
	    (r = sshpkt_सङ्कलय_padding(ssh, 64)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		गच्छ बहिर्गमनम्;

	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_USERAUTH_PASSWD_CHANGEREQ,
	    &निवेशः_userauth_passwd_changereq);
	r = 0;
 बहिर्गमनम्:
	यदि (password)
		freezero(password, वाक्यदैर्घ्यम्(password));
	मुक्त(info);
	मुक्त(lang);
	प्रत्यागम r;
}

/*
 * Select an algorithm for publickey signatures.
 * Returns algorithm (caller must free) or NULL if no mutual algorithm found.
 *
 * Call with ssh==NULL to ignore server-sig-algs extension list and
 * only attempt with the key's base signature type.
 */
स्थिर वर्ण *
कुञ्चिका_sig_algorithm(संरचना ssh *ssh, ध्रुव संरचना sshkey *कुञ्चिका)
{
	वर्ण *allowed, *oallowed, *cp, *tmp, *alg = रिक्त;
	ध्रुव वर्ण *server_sig_algs;

	/*
	 * The signature algorithm will only differ from the key algorithm
	 * for RSA keys/certs and when the server advertises support for
	 * newer (SHA2) algorithms.
	 */
	यदि (ssh == रिक्त || ssh->kex->server_sig_algs == रिक्त ||
	    (कुञ्चिका->type != कुञ्चिका_RSA && कुञ्चिका->type != कुञ्चिका_RSA_CERT) ||
	    (कुञ्चिका->type == कुञ्चिका_RSA_CERT && (ssh->compat & SSH_BUG_SIGTYPE))) {
		/* Filter base key signature alg against our configuration */
		प्रत्यागम मेलनम्_list(sshkey_ssh_name(कुञ्चिका),
		    options.pubkey_accepted_algos, रिक्त);
	}

	/*
	 * Workaround OpenSSH 7.4 bug: this version supports RSA/SHA-2 but
	 * fails to advertise it via SSH2_MSG_EXT_INFO.
	 */
	server_sig_algs = ssh->kex->server_sig_algs;
	यदि (कुञ्चिका->type == कुञ्चिका_RSA && (ssh->compat & SSH_BUG_SIGTYPE74))
		server_sig_algs = "rsa-sha2-256,rsa-sha2-512";

	/*
	 * For RSA keys/certs, since these might have a different sig type:
	 * find the first entry in PubkeyAcceptedAlgorithms of the right type
	 * that also appears in the supported signature algorithms list from
	 * the server.
	 */
	oallowed = allowed = xstrdup(options.pubkey_accepted_algos);
	यावत् ((cp = strsep(&allowed, ",")) != रिक्त) {
		यदि (sshkey_type_from_name(cp) != कुञ्चिका->type)
			अनुवर्त;
		tmp = मेलनम्_list(sshkey_sigalg_by_name(cp),
		    server_sig_algs, रिक्त);
		यदि (tmp != रिक्त)
			alg = xstrdup(cp);
		मुक्त(tmp);
		यदि (alg != रिक्त)
			भङ्ग;
	}
	मुक्त(oallowed);
	प्रत्यागम alg;
}

स्थिर पूर्णाङ्क
तटस्थः_sign(संरचना तटस्थः_2 *id, u_char **sigp, आकार_t *lenp,
    ध्रुव u_char *दत्त, आकार_t datalen, u_int compat, ध्रुव वर्ण *alg)
{
	संरचना sshkey *sign_कुञ्चिका = रिक्त, *prv = रिक्त;
	पूर्णाङ्क is_agent = 0, retried = 0, r = SSH_ERR_आन्तरिकम्_ERROR;
	संरचना notifier_ctx *notifier = रिक्त;
	वर्ण *fp = रिक्त, *pin = रिक्त, *prompt = रिक्त;

	*sigp = रिक्त;
	*lenp = 0;

	/* The agent supports this key. */
	यदि (id->कुञ्चिका != रिक्त && id->agent_fd != -1) {
		प्रत्यागम ssh_agent_sign(id->agent_fd, id->कुञ्चिका, sigp, lenp,
		    दत्त, datalen, alg, compat);
	}

	/*
	 * We have already loaded the private key or the private key is
	 * stored in external hardware.
	 */
	यदि (id->कुञ्चिका != रिक्त &&
	    (id->isprivate || (id->कुञ्चिका->flags & SSHKEY_FLAG_EXT))) {
		sign_कुञ्चिका = id->कुञ्चिका;
		is_agent = 1;
	} अन्यथा {
		/* Load the private key from the file. */
		यदि ((prv = आरोपय_तटस्थः_file(id)) == रिक्त)
			प्रत्यागम SSH_ERR_कुञ्चिका_NOT_प्राप्तम्;
		यदि (id->कुञ्चिका != रिक्त && !sshkey_equal_लौकिकम्(prv, id->कुञ्चिका)) {
			error_f("private key %s contents do not match public",
			    id->filename);
			r = SSH_ERR_कुञ्चिका_NOT_प्राप्तम्;
			गच्छ बहिर्गमनम्;
		}
		sign_कुञ्चिका = prv;
	}
 retry_pin:
	/* Prompt for touch for non-agent FIDO keys that request UP */
	यदि (!is_agent && sshkey_is_sk(sign_कुञ्चिका) &&
	    (sign_कुञ्चिका->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
		/* XXX should batch mode just skip these? */
		यदि ((fp = sshkey_fingerprint(sign_कुञ्चिका,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == रिक्त)
			fatal_f("fingerprint failed");
		notifier = notify_start(options.batch_बहुलकम्,
		    "Confirm user presence for key %s %s",
		    sshkey_type(sign_कुञ्चिका), fp);
		मुक्त(fp);
	}
	यदि ((r = sshkey_sign(sign_कुञ्चिका, sigp, lenp, दत्त, datalen,
	    alg, options.sk_provider, pin, compat)) != 0) {
		debug_fr(r, "sshkey_sign");
		यदि (!retried && pin == रिक्त && !is_agent &&
		    sshkey_is_sk(sign_कुञ्चिका) &&
		    r == SSH_ERR_कुञ्चिका_WRONG_PASSPHRASE) {
			notify_complete(notifier, रिक्त);
			notifier = रिक्त;
			xasprintf(&prompt, "Enter PIN for %s key %s: ",
			    sshkey_type(sign_कुञ्चिका), id->filename);
			pin = read_passphrase(prompt, 0);
			retried = 1;
			गच्छ retry_pin;
		}
		गच्छ बहिर्गमनम्;
	}

	/*
	 * PKCS#11 tokens may not support all signature algorithms,
	 * so check what we get back.
	 */
	यदि (id->कुञ्चिका != रिक्त && (id->कुञ्चिका->flags & SSHKEY_FLAG_EXT) != 0 &&
	    (r = sshkey_check_sigtype(*sigp, *lenp, alg)) != 0) {
		debug_fr(r, "sshkey_check_sigtype");
		गच्छ बहिर्गमनम्;
	}
	/* success */
	r = 0;
 बहिर्गमनम्:
	मुक्त(prompt);
	यदि (pin != रिक्त)
		freezero(pin, वाक्यदैर्घ्यम्(pin));
	notify_complete(notifier, r == 0 ? "User presence confirmed" : रिक्त);
	sshkey_free(prv);
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
id_filename_matches(तटस्थः *id, तटस्थः *वैयक्तिकम्_id)
{
	स्थिर ध्रुव वर्ण * ध्रुव suffixes[] = { ".pub", "-cert.pub", रिक्त };
	आकार_t len = वाक्यदैर्घ्यम्(id->filename), plen = वाक्यदैर्घ्यम्(वैयक्तिकम्_id->filename);
	आकार_t i, slen;

	यदि (वाक्यं_तुलय(id->filename, वैयक्तिकम्_id->filename) == 0)
		प्रत्यागम 1;
	प्रति (i = 0; suffixes[i]; i++) {
		slen = वाक्यदैर्घ्यम्(suffixes[i]);
		यदि (len > slen && plen == len - slen &&
		    वाक्यं_तुलय(id->filename + (len - slen), suffixes[i]) == 0 &&
		    memcmp(id->filename, वैयक्तिकम्_id->filename, plen) == 0)
			प्रत्यागम 1;
	}
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
sign_and_send_pubkey(संरचना ssh *ssh, तटस्थः *id)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	संरचना sshbuf *b = रिक्त;
	तटस्थः *वैयक्तिकम्_id, *sign_id = रिक्त;
	u_char *signature = रिक्त;
	आकार_t slen = 0, skip = 0;
	पूर्णाङ्क r, fallback_sigtype, प्रेषितम् = 0;
	वर्ण *alg = रिक्त, *fp = रिक्त;
	ध्रुव वर्ण *loc = "", *विधानम् = "publickey";
	पूर्णाङ्क hostbound = 0;

	/* prefer host-bound pubkey signatures if supported by server */
	यदि ((ssh->kex->flags & KEX_HAS_PUBKEY_HOSTBOUND) != 0 &&
	    (options.pubkey_authentication & SSH_PUBKEY_AUTH_HBOUND) != 0) {
		hostbound = 1;
		विधानम् = "publickey-hostbound-v00@openssh.com";
	}

	यदि ((fp = sshkey_fingerprint(id->कुञ्चिका, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == रिक्त)
		प्रत्यागम 0;

	debug3_f("using %s with %s %s", विधानम्, sshkey_type(id->कुञ्चिका), fp);

	/*
	 * If the key is an certificate, try to find a matching private key
	 * and use it to complete the signature.
	 * If no such private key exists, fall back to trying the certificate
	 * key itself in case it has a private half already loaded.
	 * This will try to set sign_id to the private key that will perform
	 * the signature.
	 */
	यदि (id->agent_fd == -1 && sshkey_is_cert(id->कुञ्चिका)) {
		TAILQ_FOREACH(वैयक्तिकम्_id, &authctxt->कुञ्चिकाः, अग्र) {
			यदि (sshkey_equal_लौकिकम्(id->कुञ्चिका, वैयक्तिकम्_id->कुञ्चिका) &&
			    id->कुञ्चिका->type != वैयक्तिकम्_id->कुञ्चिका->type) {
				sign_id = वैयक्तिकम्_id;
				भङ्ग;
			}
		}
		/*
		 * Exact key matches are preferred, but also allow
		 * filename matches for non-PKCS#11/agent keys that
		 * didn't load public keys. This supports the case
		 * of keeping just a private key file and public
		 * certificate on disk.
		 */
		यदि (sign_id == रिक्त &&
		    !id->isprivate && id->agent_fd == -1 &&
		    (id->कुञ्चिका->flags & SSHKEY_FLAG_EXT) == 0) {
			TAILQ_FOREACH(वैयक्तिकम्_id, &authctxt->कुञ्चिकाः, अग्र) {
				यदि (वैयक्तिकम्_id->कुञ्चिका == रिक्त &&
				    id_filename_matches(id, वैयक्तिकम्_id)) {
					sign_id = वैयक्तिकम्_id;
					भङ्ग;
				}
			}
		}
		यदि (sign_id != रिक्त) {
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
	यदि (sign_id == रिक्त)
		sign_id = id;

	/* assemble and sign data */
	प्रति (fallback_sigtype = 0; fallback_sigtype <= 1; fallback_sigtype++) {
		मुक्त(alg);
		slen = 0;
		signature = रिक्त;
		यदि ((alg = कुञ्चिका_sig_algorithm(fallback_sigtype ? रिक्त : ssh,
		    id->कुञ्चिका)) == रिक्त) {
			error_f("no mutual signature supported");
			गच्छ बहिर्गमनम्;
		}
		debug3_f("signing using %s %s", alg, fp);

		sshbuf_free(b);
		यदि ((b = sshbuf_new()) == रिक्त)
			fatal_f("sshbuf_new failed");
		यदि ((r = sshbuf_put_stringb(b,
		    ssh->kex->session_id)) != 0)
			fatal_fr(r, "sshbuf_put_stringb");
		skip = sshbuf_len(b);
		यदि ((r = sshbuf_put_u8(b, SSH2_सन्देशः_USERAUTH_REQUEST)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->server_user)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
		    (r = sshbuf_put_cstring(b, विधानम्)) != 0 ||
		    (r = sshbuf_put_u8(b, 1)) != 0 ||
		    (r = sshbuf_put_cstring(b, alg)) != 0 ||
		    (r = sshkey_puts(id->कुञ्चिका, b)) != 0) {
			fatal_fr(r, "assemble signed data");
		}
		यदि (hostbound) {
			यदि (ssh->kex->initial_hostkey == रिक्त) {
				fatal_f("internal error: initial hostkey "
				    "not recorded");
			}
			यदि ((r = sshkey_puts(ssh->kex->initial_hostkey, b)) != 0)
				fatal_fr(r, "assemble %s hostkey", विधानम्);
		}
		/* generate signature */
		r = तटस्थः_sign(sign_id, &signature, &slen,
		    sshbuf_ptr(b), sshbuf_len(b), ssh->compat, alg);
		यदि (r == 0)
			भङ्ग;
		अन्यथा यदि (r == SSH_ERR_कुञ्चिका_NOT_प्राप्तम्)
			गच्छ बहिर्गमनम्; /* soft failure */
		अन्यथा यदि (r == SSH_ERR_SIGN_ALG_UNSUPPORTED &&
		    !fallback_sigtype) {
			यदि (sign_id->agent_fd != -1)
				loc = "agent ";
			अन्यथा यदि (sign_id->कुञ्चिका != रिक्त &&
			    (sign_id->कुञ्चिका->flags & SSHKEY_FLAG_EXT) != 0)
				loc = "token ";
			logit("%skey %s %s returned incorrect signature type",
			    loc, sshkey_type(id->कुञ्चिका), fp);
			अनुवर्त;
		}
		error_fr(r, "signing failed for %s \"%s\"%s",
		    sshkey_type(sign_id->कुञ्चिका), sign_id->filename,
		    id->agent_fd != -1 ? " from agent" : "");
		गच्छ बहिर्गमनम्;
	}
	यदि (slen == 0 || signature == रिक्त) /* shouldn't happen */
		fatal_f("no signature");

	/* append signature */
	यदि ((r = sshbuf_put_string(b, signature, slen)) != 0)
		fatal_fr(r, "append signature");

#यदि_परिभाषितम् DEBUG_PK
	sshbuf_dump(b, stderr);
#यदि_अन्तः
	/* skip session id and packet type */
	यदि ((r = sshbuf_consume(b, skip + 1)) != 0)
		fatal_fr(r, "consume");

	/* put remaining data from buffer into packet */
	यदि ((r = sshpkt_start(ssh, SSH2_सन्देशः_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_putb(ssh, b)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "enqueue request");

	/* success */
	प्रेषितम् = 1;

 बहिर्गमनम्:
	मुक्त(fp);
	मुक्त(alg);
	sshbuf_free(b);
	freezero(signature, slen);
	प्रत्यागम प्रेषितम्;
}

स्थिर पूर्णाङ्क
send_pubkey_test(संरचना ssh *ssh, तटस्थः *id)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	u_char *blob = रिक्त;
	वर्ण *alg = रिक्त;
	आकार_t bloblen;
	u_int have_sig = 0;
	पूर्णाङ्क प्रेषितम् = 0, r;

	यदि ((alg = कुञ्चिका_sig_algorithm(ssh, id->कुञ्चिका)) == रिक्त) {
		debug_f("no mutual signature algorithm");
		गच्छ बहिर्गमनम्;
	}

	यदि ((r = sshkey_गन्तव्यम्_blob(id->कुञ्चिका, &blob, &bloblen)) != 0) {
		/* we cannot handle this key */
		debug3_f("cannot handle key");
		गच्छ बहिर्गमनम्;
	}
	/* register callback for USERAUTH_PK_OK message */
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_USERAUTH_PK_OK, &निवेशः_userauth_pk_ok);

	यदि ((r = sshpkt_start(ssh, SSH2_सन्देशः_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->विधानम्->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, have_sig)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, alg)) != 0 ||
	    (r = sshpkt_put_string(ssh, blob, bloblen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	प्रेषितम् = 1;

 बहिर्गमनम्:
	मुक्त(alg);
	मुक्त(blob);
	प्रत्यागम प्रेषितम्;
}

स्थिर संरचना sshkey *
आरोपय_तटस्थः_file(तटस्थः *id)
{
	संरचना sshkey *गुप्त = रिक्त;
	वर्ण prompt[300], *passphrase, *comment;
	पूर्णाङ्क r, quit = 0, i;
	संरचना stat st;

	यदि (stat(id->filename, &st) == -1) {
		do_log2(id->userprovided ?
		    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_DEBUG3,
		    "no such identity: %s: %s", id->filename, strerror(errno));
		प्रत्यागम रिक्त;
	}
	snprintf(prompt, परिमाण prompt,
	    "Enter passphrase for key '%.100s': ", id->filename);
	प्रति (i = 0; i <= options.सङ्ख्या_सम्बन्धि_password_prompts; i++) {
		यदि (i == 0)
			passphrase = "";
		अन्यथा {
			passphrase = read_passphrase(prompt, 0);
			यदि (*passphrase == '\0') {
				debug2("no passphrase given, try next key");
				मुक्त(passphrase);
				भङ्ग;
			}
		}
		विकल्प ((r = sshkey_आरोपय_वैयक्तिकम्_type(कुञ्चिका_UNSPEC, id->filename,
		    passphrase, &गुप्त, &comment))) {
		पक्ष 0:
			भङ्ग;
		पक्ष SSH_ERR_कुञ्चिका_WRONG_PASSPHRASE:
			यदि (options.batch_बहुलकम्) {
				quit = 1;
				भङ्ग;
			}
			यदि (i != 0)
				debug2("bad passphrase given, try again...");
			भङ्ग;
		पक्ष SSH_ERR_SYSTEM_ERROR:
			यदि (errno == ENOENT) {
				debug2_r(r, "Load key \"%s\"", id->filename);
				quit = 1;
				भङ्ग;
			}
			/* FALLTHROUGH */
		स्वभाव:
			error_r(r, "Load key \"%s\"", id->filename);
			quit = 1;
			भङ्ग;
		}
		यदि (गुप्त != रिक्त && sshkey_is_sk(गुप्त) &&
		    options.sk_provider == रिक्त) {
			debug("key \"%s\" is an authenticator-hosted key, "
			    "but no provider specified", id->filename);
			sshkey_free(गुप्त);
			गुप्त = रिक्त;
			quit = 1;
		}
		यदि (!quit && (r = sshkey_check_rsa_दीर्घता(गुप्त,
		    options.required_rsa_आकार)) != 0) {
			debug_fr(r, "Skipping key %s", id->filename);
			sshkey_free(गुप्त);
			गुप्त = रिक्त;
			quit = 1;
		}
		यदि (!quit && गुप्त != रिक्त && id->agent_fd == -1 &&
		    !(id->कुञ्चिका && id->isprivate))
			maybe_सङ्कलय_कुञ्चिका_गन्तव्यम्_agent(id->filename, गुप्त, comment,
			    passphrase);
		यदि (i > 0)
			freezero(passphrase, वाक्यदैर्घ्यम्(passphrase));
		मुक्त(comment);
		यदि (गुप्त != रिक्त || quit)
			भङ्ग;
	}
	प्रत्यागम गुप्त;
}

स्थिर पूर्णाङ्क
कुञ्चिका_type_allowed(संरचना sshkey *कुञ्चिका, ध्रुव वर्ण *allowlist)
{
	यदि (मेलनम्_आदर्शः_list(sshkey_ssh_name(कुञ्चिका), allowlist, 0) == 1)
		प्रत्यागम 1;

	/* RSA keys/certs might be allowed by alternate signature types */
	विकल्प (कुञ्चिका->type) {
	पक्ष कुञ्चिका_RSA:
		यदि (मेलनम्_आदर्शः_list("rsa-sha2-512", allowlist, 0) == 1)
			प्रत्यागम 1;
		यदि (मेलनम्_आदर्शः_list("rsa-sha2-256", allowlist, 0) == 1)
			प्रत्यागम 1;
		भङ्ग;
	पक्ष कुञ्चिका_RSA_CERT:
		यदि (मेलनम्_आदर्शः_list("rsa-sha2-512-cert-v01@openssh.com",
		    allowlist, 0) == 1)
			प्रत्यागम 1;
		यदि (मेलनम्_आदर्शः_list("rsa-sha2-256-cert-v01@openssh.com",
		    allowlist, 0) == 1)
			प्रत्यागम 1;
		भङ्ग;
	}
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
कुञ्चिका_type_allowed_by_config(संरचना sshkey *कुञ्चिका)
{
	प्रत्यागम कुञ्चिका_type_allowed(कुञ्चिका, options.pubkey_accepted_algos);
}

/* obtain a list of keys from the agent */
स्थिर पूर्णाङ्क
get_agent_identities(संरचना ssh *ssh, पूर्णाङ्क *agent_fdp,
    संरचना ssh_identitylist **idlistp)
{
	पूर्णाङ्क r, agent_fd;
	संरचना ssh_identitylist *idlist;

	यदि ((r = ssh_get_authentication_socket(&agent_fd)) != 0) {
		यदि (r != SSH_ERR_AGENT_NOT_PRESENT)
			debug_fr(r, "ssh_get_authentication_socket");
		प्रत्यागम r;
	}
	यदि (ssh != रिक्त && ssh->kex != रिक्त) {
		यदि ((r = ssh_agent_bind_hostkey(agent_fd, ssh->kex->initial_hostkey,
		    ssh->kex->session_id, ssh->kex->initial_sig, 0)) == 0)
			debug_f("bound agent to hostkey");
		अन्यथा
			debug2_fr(r, "ssh_agent_bind_hostkey");
	}

	यदि ((r = ssh_fetch_identitylist(agent_fd, &idlist)) != 0) {
		debug_fr(r, "ssh_fetch_identitylist");
		close(agent_fd);
		प्रत्यागम r;
	}
	/* success */
	*agent_fdp = agent_fd;
	*idlistp = idlist;
	debug_f("agent returned %zu keys", idlist->nkeys);
	प्रत्यागम 0;
}

/*
 * Returns nonzero if the certificate extensions/critical-options section
 * has the specified option present, zero otherwise.
 */
स्थिर पूर्णाङ्क
cert_has_option(संरचना sshbuf *oblob, ध्रुव वर्ण *target)
{
	संरचना sshbuf *c = रिक्त, *दत्त = रिक्त;
	वर्ण *name = रिक्त;
	पूर्णाङ्क r, प्राप्तम् = 0;

	यदि (oblob == रिक्त || (c = sshbuf_fromb(oblob)) == रिक्त)
		प्रत्यागम 0;
	यावत् (sshbuf_len(c) > 0) {
		sshbuf_free(दत्त);
		दत्त = रिक्त;
		मुक्त(name);
		name = रिक्त;
		यदि ((r = sshbuf_get_cstring(c, &name, रिक्त)) != 0 ||
		    (r = sshbuf_froms(c, &दत्त)) != 0)
			भङ्ग;
		यदि (वाक्यं_तुलय(name, target) == 0) {
			प्राप्तम् = 1;
			भङ्ग;
		}
	}
	sshbuf_free(दत्त);
	मुक्त(name);
	sshbuf_free(c);
	प्रत्यागम प्राप्तम्;
}

/*
 * Returns an integer describing the priority of the identity
 * within its group. Lower numbers are higher priority.
 */
#परिभाषय MAX_ID_प्राथमिकता 3
स्थिर पूर्णाङ्क
तटस्थः_prioritise(संरचना तटस्थः_2 *id)
{
	यदि (id == रिक्त || id->कुञ्चिका == रिक्त)
		प्रत्यागम 3;
	यदि (!sshkey_is_cert(id->कुञ्चिका) || id->कुञ्चिका->cert == रिक्त)
		प्रत्यागम 3;
	यदि (sshkey_is_sk(id->कुञ्चिका) &&
	    cert_has_option(id->कुञ्चिका->cert->critical, "verify-required"))
		प्रत्यागम 2;
	यदि (sshkey_is_sk(id->कुञ्चिका) &&
	    cert_has_option(id->कुञ्चिका->cert->extensions, "no-touch-required"))
		प्रत्यागम 0;
	प्रत्यागम 1;
}

स्थिर शून्य
क्रमः_identities_by_prio(संरचना idlist *list)
{
	संरचना idlist prio[MAX_ID_प्राथमिकता + 1], sorted;
	संरचना तटस्थः_2 *id, *tmp, *dummy;
	पूर्णाङ्क p;

	प्रति (p = 0; p <= MAX_ID_प्राथमिकता; p++)
		TAILQ_INIT(&prio[p]);
	TAILQ_INIT(&sorted);

	TAILQ_FOREACH_SAFE(id, list, अग्र, tmp) {
		यदि (id->userprovided)
			अनुवर्त;
		dummy = xcalloc(1, परिमाण(*dummy));
		dummy->userprovided = -1;
		TAILQ_INSERT_BEFORE(id, dummy, अग्र);
		TAILQ_REMOVE(list, id, अग्र);
		p = तटस्थः_prioritise(id);
		यदि (p < 0 || p > MAX_ID_प्राथमिकता)
			fatal_f("internal error: bad priority");
		TAILQ_INSERT_TAIL(&prio[p], id, अग्र);
	}
	प्रति (p = 0; p <= MAX_ID_प्राथमिकता; p++)
		TAILQ_CONCAT(&sorted, &prio[p], अग्र);

	TAILQ_FOREACH_SAFE(id, list, अग्र, tmp) {
		यदि (id->userprovided != -1)
			अनुवर्त;
		संरचना तटस्थः_2 *s = TAILQ_FIRST(&sorted);
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
स्थिर शून्य
pubkey_prepare(संरचना ssh *ssh, Authctxt *authctxt)
{
	संरचना तटस्थः_2 *id, *id2, *tmp;
	संरचना idlist agent, files, certs, agent_कुञ्चिकाः, *preferred;
	संरचना sshkey *कुञ्चिका;
	पूर्णाङ्क disallowed, agent_fd = -1, i, r, प्राप्तम्;
	आकार_t j;
	संरचना ssh_identitylist *idlist;
	वर्ण *cp, *ident;

	TAILQ_INIT(&agent);	/* keys from the agent */
	TAILQ_INIT(&files);	/* keys from the config file */
	TAILQ_INIT(&certs);	/* certificates specified by user */
	TAILQ_INIT(&agent_कुञ्चिकाः); /* keys supported by the agent */
	preferred = &authctxt->कुञ्चिकाः;
	TAILQ_INIT(preferred);	/* preferred order of keys */

	/* list of keys stored in the filesystem and PKCS#11 */
	प्रति (i = 0; i < options.अङ्कः_तटस्थः_files; i++) {
		कुञ्चिका = options.तटस्थः_कुञ्चिकाः[i];
		यदि (कुञ्चिका && कुञ्चिका->cert &&
		    कुञ्चिका->cert->type != SSH2_CERT_TYPE_USER) {
			debug_f("ignoring certificate %s: not a user "
			    "certificate", options.तटस्थः_files[i]);
			अनुवर्त;
		}
		यदि (कुञ्चिका && sshkey_is_sk(कुञ्चिका) && options.sk_provider == रिक्त) {
			debug_f("ignoring authenticator-hosted key %s as no "
			    "SecurityKeyProvider has been specified",
			    options.तटस्थः_files[i]);
			अनुवर्त;
		}
		options.तटस्थः_कुञ्चिकाः[i] = रिक्त;
		id = xcalloc(1, परिमाण(*id));
		id->agent_fd = -1;
		id->कुञ्चिका = कुञ्चिका;
		id->filename = xstrdup(options.तटस्थः_files[i]);
		id->userprovided = options.तटस्थः_file_userprovided[i];
		TAILQ_INSERT_TAIL(&files, id, अग्र);
	}

	/* list of certificates specified by user */
	प्रति (i = 0; i < options.अङ्कः_certificate_files; i++) {
		कुञ्चिका = options.certificates[i];
		यदि (!sshkey_is_cert(कुञ्चिका) || कुञ्चिका->cert == रिक्त ||
		    कुञ्चिका->cert->type != SSH2_CERT_TYPE_USER) {
			debug_f("ignoring certificate %s: not a user "
			    "certificate", options.तटस्थः_files[i]);
			अनुवर्त;
		}
		यदि (कुञ्चिका && sshkey_is_sk(कुञ्चिका) && options.sk_provider == रिक्त) {
			debug_f("ignoring authenticator-hosted key "
			    "certificate %s as no "
			    "SecurityKeyProvider has been specified",
			    options.तटस्थः_files[i]);
			अनुवर्त;
		}
		id = xcalloc(1, परिमाण(*id));
		id->agent_fd = -1;
		id->कुञ्चिका = कुञ्चिका;
		id->filename = xstrdup(options.certificate_files[i]);
		id->userprovided = options.certificate_file_userprovided[i];
		TAILQ_INSERT_TAIL(&certs, id, अग्र);
	}
	क्रमः_identities_by_prio(&certs);
	TAILQ_CONCAT(preferred, &certs, अग्र);

	/* list of keys supported by the agent */
	यदि ((r = get_agent_identities(ssh, &agent_fd, &idlist)) == 0) {
		प्रति (j = 0; j < idlist->nkeys; j++) {
			यदि ((r = sshkey_check_rsa_दीर्घता(idlist->कुञ्चिकाः[j],
			    options.required_rsa_आकार)) != 0) {
				debug_fr(r, "ignoring %s agent key",
				    sshkey_ssh_name(idlist->कुञ्चिकाः[j]));
				अनुवर्त;
			}
			प्राप्तम् = 0;
			TAILQ_FOREACH(id, &files, अग्र) {
				/*
				 * agent keys from the config file are
				 * preferred
				 */
				यदि (sshkey_equal(idlist->कुञ्चिकाः[j], id->कुञ्चिका)) {
					TAILQ_REMOVE(&files, id, अग्र);
					TAILQ_INSERT_TAIL(&agent_कुञ्चिकाः, id, अग्र);
					id->agent_fd = agent_fd;
					प्राप्तम् = 1;
					भङ्ग;
				}
			}
			यदि (!प्राप्तम् && !options.identities_only) {
				id = xcalloc(1, परिमाण(*id));
				/* XXX "steals" key/comment from idlist */
				id->कुञ्चिका = idlist->कुञ्चिकाः[j];
				id->filename = idlist->comments[j];
				idlist->कुञ्चिकाः[j] = रिक्त;
				idlist->comments[j] = रिक्त;
				id->agent_fd = agent_fd;
				TAILQ_INSERT_TAIL(&agent, id, अग्र);
			}
		}
		ssh_free_identitylist(idlist);
		/* append remaining agent keys */
		TAILQ_CONCAT(&agent_कुञ्चिकाः, &agent, अग्र);
		क्रमः_identities_by_prio(&agent_कुञ्चिकाः);
		TAILQ_CONCAT(preferred, &agent_कुञ्चिकाः, अग्र);
		authctxt->agent_fd = agent_fd;
	}
	/* Prefer PKCS11 keys that are explicitly listed */
	TAILQ_FOREACH_SAFE(id, &files, अग्र, tmp) {
		यदि (id->कुञ्चिका == रिक्त || (id->कुञ्चिका->flags & SSHKEY_FLAG_EXT) == 0)
			अनुवर्त;
		प्राप्तम् = 0;
		TAILQ_FOREACH(id2, &files, अग्र) {
			यदि (id2->कुञ्चिका == रिक्त ||
			    (id2->कुञ्चिका->flags & SSHKEY_FLAG_EXT) != 0)
				अनुवर्त;
			यदि (sshkey_equal(id->कुञ्चिका, id2->कुञ्चिका)) {
				TAILQ_REMOVE(&files, id, अग्र);
				TAILQ_INSERT_TAIL(preferred, id, अग्र);
				प्राप्तम् = 1;
				भङ्ग;
			}
		}
		/* If IdentitiesOnly set and key not found then don't use it */
		यदि (!प्राप्तम् && options.identities_only) {
			TAILQ_REMOVE(&files, id, अग्र);
			freezero(id, परिमाण(*id));
		}
	}
	क्रमः_identities_by_prio(&files);
	/* append remaining keys from the config file */
	TAILQ_CONCAT(preferred, &files, अग्र);
	/* finally, filter by PubkeyAcceptedAlgorithms */
	TAILQ_FOREACH_SAFE(id, preferred, अग्र, id2) {
		disallowed = 0;
		cp = रिक्त;
		यदि (id->कुञ्चिका == रिक्त)
			अनुवर्त;
		यदि (!कुञ्चिका_type_allowed_by_config(id->कुञ्चिका)) {
			debug("Skipping %s key %s - corresponding algorithm "
			    "not in PubkeyAcceptedAlgorithms",
			    sshkey_ssh_name(id->कुञ्चिका), id->filename);
			disallowed = 1;
		} अन्यथा यदि (ssh != रिक्त && ssh->kex != रिक्त &&
		    ssh->kex->server_sig_algs != रिक्त &&
		    (cp = कुञ्चिका_sig_algorithm(ssh, id->कुञ्चिका)) == रिक्त) {
			debug("Skipping %s key %s - corresponding algorithm "
			    "not supported by server",
			    sshkey_ssh_name(id->कुञ्चिका), id->filename);
			disallowed = 1;
		}
		मुक्त(cp);
		यदि (!disallowed)
			अनुवर्त;
		/* remove key */
		TAILQ_REMOVE(preferred, id, अग्र);
		sshkey_free(id->कुञ्चिका);
		मुक्त(id->filename);
		freezero(id, परिमाण(*id));
	}
	/* List the keys we plan on using */
	TAILQ_FOREACH_SAFE(id, preferred, अग्र, id2) {
		ident = format_तटस्थः(id);
		debug("Will attempt key: %s", ident);
		मुक्त(ident);
	}
	debug2_f("done");
}

स्थिर शून्य
pubkey_cleanup(संरचना ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	तटस्थः *id;

	यदि (authctxt->agent_fd != -1) {
		ssh_close_authentication_socket(authctxt->agent_fd);
		authctxt->agent_fd = -1;
	}
	प्रति (id = TAILQ_FIRST(&authctxt->कुञ्चिकाः); id;
	    id = TAILQ_FIRST(&authctxt->कुञ्चिकाः)) {
		TAILQ_REMOVE(&authctxt->कुञ्चिकाः, id, अग्र);
		sshkey_free(id->कुञ्चिका);
		मुक्त(id->filename);
		मुक्त(id);
	}
}

शून्य
pubkey_dump(संरचना ssh *ssh)
{
	Authctxt authctxt;
	तटस्थः *id;
	वर्ण *ident;

	स्मृतिं_पूरय(&authctxt, 0, परिमाण(authctxt));
	authctxt.agent_fd = -1;
	ssh->authctxt = &authctxt;

	pubkey_prepare(ssh, &authctxt);
	TAILQ_FOREACH(id, &authctxt.कुञ्चिकाः, अग्र) {
		ident = format_तटस्थः(id);
		fprintf(stdout, "%s\n", ident);
		मुक्त(ident);
	}
	pubkey_cleanup(ssh);
	ssh->authctxt = रिक्त;
}

स्थिर शून्य
pubkey_reset(Authctxt *authctxt)
{
	तटस्थः *id;

	TAILQ_FOREACH(id, &authctxt->कुञ्चिकाः, अग्र)
		id->tried = 0;
}

स्थिर पूर्णाङ्क
userauth_pubkey(संरचना ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	तटस्थः *id;
	पूर्णाङ्क प्रेषितम् = 0;
	वर्ण *ident;
	स्थिर पूर्णाङ्क prepared;

	यदि (!prepared) {
		pubkey_prepare(ssh, authctxt);
		prepared = 1;
	}

	यावत् ((id = TAILQ_FIRST(&authctxt->कुञ्चिकाः))) {
		यदि (id->tried++)
			प्रत्यागम (0);
		/* move key to the end of the queue */
		TAILQ_REMOVE(&authctxt->कुञ्चिकाः, id, अग्र);
		TAILQ_INSERT_TAIL(&authctxt->कुञ्चिकाः, id, अग्र);
		/*
		 * send a test message if we have the public key. for
		 * encrypted keys we cannot do this and have to load the
		 * private key instead
		 */
		यदि (id->कुञ्चिका != रिक्त) {
			ident = format_तटस्थः(id);
			debug("Offering public key: %s", ident);
			मुक्त(ident);
			प्रेषितम् = send_pubkey_test(ssh, id);
		} अन्यथा {
			debug("Trying private key: %s", id->filename);
			id->कुञ्चिका = आरोपय_तटस्थः_file(id);
			यदि (id->कुञ्चिका != रिक्त) {
				id->isprivate = 1;
				प्रेषितम् = sign_and_send_pubkey(ssh, id);
				sshkey_free(id->कुञ्चिका);
				id->कुञ्चिका = रिक्त;
				id->isprivate = 0;
			}
		}
		यदि (प्रेषितम्)
			प्रत्यागम (प्रेषितम्);
	}
	प्रत्यागम (0);
}

/*
 * Send userauth request message specifying keyboard-interactive method.
 */
स्थिर पूर्णाङ्क
userauth_kbdint(संरचना ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	पूर्णाङ्क r;

	यदि (authctxt->attempt_kbdint++ >= options.सङ्ख्या_सम्बन्धि_password_prompts)
		प्रत्यागम 0;
	/* disable if no SSH2_MSG_USERAUTH_INFO_REQUEST has been seen */
	यदि (authctxt->attempt_kbdint > 1 && !authctxt->info_req_आलोकितम्) {
		debug3("userauth_kbdint: disable: no info_req_seen");
		ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_USERAUTH_INFO_REQUEST, रिक्त);
		प्रत्यागम 0;
	}

	debug2("userauth_kbdint");
	यदि ((r = sshpkt_start(ssh, SSH2_सन्देशः_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->विधानम्->name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||		/* lang */
	    (r = sshpkt_put_cstring(ssh, options.kbd_interactive_devices ?
	    options.kbd_interactive_devices : "")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_USERAUTH_INFO_REQUEST, &निवेशः_userauth_info_req);
	प्रत्यागम 1;
}

/*
 * parse INFO_REQUEST, prompt user and send INFO_RESPONSE
 */
स्थिर पूर्णाङ्क
निवेशः_userauth_info_req(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	वर्ण *name = रिक्त, *inst = रिक्त, *lang = रिक्त, *prompt = रिक्त;
	वर्ण *display_prompt = रिक्त, *response = रिक्त;
	u_char echo = 0;
	u_int अङ्कः_prompts, i;
	पूर्णाङ्क r, addnl;
	आकार_t len;

	debug2_f("entering");

	यदि (authctxt == रिक्त)
		fatal_f("no authentication context");

	authctxt->info_req_आलोकितम् = 1;

	यदि ((r = sshpkt_get_cstring(ssh, &name, रिक्त)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &inst, रिक्त)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, रिक्त)) != 0)
		गच्छ बहिर्गमनम्;
	यदि ((len = वाक्यदैर्घ्यम्(name)) > 0) {
		addnl = name[len] != '\n';
		fmprintf(stderr, "%s%s", name, addnl ? "\n" : "");
	}
	यदि ((len = वाक्यदैर्घ्यम्(inst)) > 0) {
		addnl = inst[len] != '\n';
		fmprintf(stderr, "%s%s", inst, addnl ? "\n" : "");
	}

	यदि ((r = sshpkt_get_u32(ssh, &अङ्कः_prompts)) != 0)
		गच्छ बहिर्गमनम्;
	/*
	 * Begin to build info response packet based on prompts requested.
	 * We commit to providing the correct number of responses, so if
	 * further on we run into a problem that prevents this, we have to
	 * be sure and clean this up and send a correct error response.
	 */
	यदि ((r = sshpkt_start(ssh, SSH2_सन्देशः_USERAUTH_INFO_RESPONSE)) != 0 ||
	    (r = sshpkt_put_u32(ssh, अङ्कः_prompts)) != 0)
		गच्छ बहिर्गमनम्;

	debug2_f("num_prompts %d", अङ्कः_prompts);
	प्रति (i = 0; i < अङ्कः_prompts; i++) {
		यदि ((r = sshpkt_get_cstring(ssh, &prompt, रिक्त)) != 0 ||
		    (r = sshpkt_get_u8(ssh, &echo)) != 0)
			गच्छ बहिर्गमनम्;
		यदि (asmprintf(&display_prompt, अधिकतम_पूर्णाङ्कः, रिक्त, "(%s@%s) %s",
		    authctxt->server_user, options.host_कुञ्चिका_alias ?
		    options.host_कुञ्चिका_alias : authctxt->host, prompt) == -1)
			fatal_f("asmprintf failed");
		response = read_passphrase(display_prompt, echo ? RP_ECHO : 0);
		यदि ((r = sshpkt_put_cstring(ssh, response)) != 0)
			गच्छ बहिर्गमनम्;
		freezero(response, वाक्यदैर्घ्यम्(response));
		मुक्त(prompt);
		मुक्त(display_prompt);
		display_prompt = response = prompt = रिक्त;
	}
	/* done with parsing incoming message. */
	यदि ((r = sshpkt_get_अन्तः(ssh)) != 0 ||
	    (r = sshpkt_सङ्कलय_padding(ssh, 64)) != 0)
		गच्छ बहिर्गमनम्;
	r = sshpkt_send(ssh);
 बहिर्गमनम्:
	यदि (response)
		freezero(response, वाक्यदैर्घ्यम्(response));
	मुक्त(prompt);
	मुक्त(display_prompt);
	मुक्त(name);
	मुक्त(inst);
	मुक्त(lang);
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
ssh_keysign(संरचना ssh *ssh, संरचना sshkey *कुञ्चिका, u_char **sigp, आकार_t *lenp,
    ध्रुव u_char *दत्त, आकार_t datalen)
{
	संरचना sshbuf *b;
	संरचना stat st;
	pid_t pid;
	पूर्णाङ्क r, गन्तव्यम्[2], from[2], स्थितिः;
	पूर्णाङ्क sock = ssh_packet_get_connection_अन्तर्(ssh);
	u_char rversion = 0, संस्करणम् = 2;
	शून्य (*osigchld)(पूर्णाङ्क);

	*sigp = रिक्त;
	*lenp = 0;

	यदि (stat(मार्गः_SSH_कुञ्चिका_SIGN, &st) == -1) {
		error_f("not installed: %s", strerror(errno));
		प्रत्यागम -1;
	}
	यदि (fflush(stdout) != 0) {
		error_f("fflush: %s", strerror(errno));
		प्रत्यागम -1;
	}
	यदि (pipe(गन्तव्यम्) == -1) {
		error_f("pipe: %s", strerror(errno));
		प्रत्यागम -1;
	}
	यदि (pipe(from) == -1) {
		error_f("pipe: %s", strerror(errno));
		प्रत्यागम -1;
	}
	यदि ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		प्रत्यागम -1;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	यदि (pid == 0) {
		close(from[0]);
		यदि (dup2(from[1], STDOUT_FILENO) == -1)
			fatal_f("dup2: %s", strerror(errno));
		close(गन्तव्यम्[1]);
		यदि (dup2(गन्तव्यम्[0], STDIN_FILENO) == -1)
			fatal_f("dup2: %s", strerror(errno));
		close(from[1]);
		close(गन्तव्यम्[0]);

		यदि (dup2(sock, STDERR_FILENO + 1) == -1)
			fatal_f("dup2: %s", strerror(errno));
		sock = STDERR_FILENO + 1;
		यदि (fcntl(sock, F_SETFD, 0) == -1) /* keep the socket on exec */
			debug3_f("fcntl F_SETFD: %s", strerror(errno));
		closefrom(sock + 1);

		debug3_f("[child] pid=%ld, exec %s",
		    (दीर्घ)getpid(), मार्गः_SSH_कुञ्चिका_SIGN);
		execl(मार्गः_SSH_कुञ्चिका_SIGN, मार्गः_SSH_कुञ्चिका_SIGN, (वर्ण *)रिक्त);
		fatal_f("exec(%s): %s", मार्गः_SSH_कुञ्चिका_SIGN,
		    strerror(errno));
	}
	close(from[1]);
	close(गन्तव्यम्[0]);
	sock = STDERR_FILENO + 1;

	यदि ((b = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	/* send # of sock, data to be signed */
	यदि ((r = sshbuf_put_u32(b, sock)) != 0 ||
	    (r = sshbuf_put_string(b, दत्त, datalen)) != 0)
		fatal_fr(r, "buffer error");
	यदि (ssh_सन्देशः_send(गन्तव्यम्[1], संस्करणम्, b) == -1)
		fatal_f("couldn't send request");
	sshbuf_reset(b);
	r = ssh_सन्देशः_recv(from[0], b);
	close(from[0]);
	close(गन्तव्यम्[1]);
	यदि (r < 0) {
		error_f("no reply");
		गच्छ fail;
	}

	errno = 0;
	यावत् (waitpid(pid, &स्थितिः, 0) == -1) {
		यदि (errno != EINTR) {
			error_f("waitpid %ld: %s", (दीर्घ)pid, strerror(errno));
			गच्छ fail;
		}
	}
	यदि (!WIFEXITED(स्थितिः)) {
		error_f("exited abnormally");
		गच्छ fail;
	}
	यदि (WEXITSTATUS(स्थितिः) != 0) {
		error_f("exited with status %d", WEXITSTATUS(स्थितिः));
		गच्छ fail;
	}
	यदि ((r = sshbuf_get_u8(b, &rversion)) != 0) {
		error_fr(r, "buffer error");
		गच्छ fail;
	}
	यदि (rversion != संस्करणम्) {
		error_f("bad version");
		गच्छ fail;
	}
	यदि ((r = sshbuf_get_string(b, sigp, lenp)) != 0) {
		error_fr(r, "buffer error");
 fail:
		ssh_signal(SIGCHLD, osigchld);
		sshbuf_free(b);
		प्रत्यागम -1;
	}
	ssh_signal(SIGCHLD, osigchld);
	sshbuf_free(b);

	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
userauth_hostbased(संरचना ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	संरचना sshkey *गुप्त = रिक्त;
	संरचना sshbuf *b = रिक्त;
	u_char *sig = रिक्त, *keyblob = रिक्त;
	वर्ण *fp = रिक्त, *chost = रिक्त, *lname = रिक्त;
	आकार_t siglen = 0, keylen = 0;
	पूर्णाङ्क i, r, success = 0;

	यदि (authctxt->ktypes == रिक्त) {
		authctxt->oktypes = xstrdup(options.hostbased_accepted_algos);
		authctxt->ktypes = authctxt->oktypes;
	}

	/*
	 * Work through each listed type pattern in HostbasedAcceptedAlgorithms,
	 * trying each hostkey that matches the type in turn.
	 */
	प्रति (;;) {
		यदि (authctxt->सक्रिय_ktype == रिक्त)
			authctxt->सक्रिय_ktype = strsep(&authctxt->ktypes, ",");
		यदि (authctxt->सक्रिय_ktype == रिक्त ||
		    *authctxt->सक्रिय_ktype == '\0')
			भङ्ग;
		debug3_f("trying key type %s", authctxt->सक्रिय_ktype);

		/* check for a useful key */
		गुप्त = रिक्त;
		प्रति (i = 0; i < authctxt->sensitive->nkeys; i++) {
			यदि (authctxt->sensitive->कुञ्चिकाः[i] == रिक्त ||
			    authctxt->sensitive->कुञ्चिकाः[i]->type == कुञ्चिका_UNSPEC)
				अनुवर्त;
			यदि (!sshkey_मेलनम्_keyname_गन्तव्यम्_sigalgs(
			    sshkey_ssh_name(authctxt->sensitive->कुञ्चिकाः[i]),
			    authctxt->सक्रिय_ktype))
				अनुवर्त;
			/* we take and free the key */
			गुप्त = authctxt->sensitive->कुञ्चिकाः[i];
			authctxt->sensitive->कुञ्चिकाः[i] = रिक्त;
			भङ्ग;
		}
		/* Found one */
		यदि (गुप्त != रिक्त)
			भङ्ग;
		/* No more keys of this type; advance */
		authctxt->सक्रिय_ktype = रिक्त;
	}
	यदि (गुप्त == रिक्त) {
		मुक्त(authctxt->oktypes);
		authctxt->oktypes = authctxt->ktypes = रिक्त;
		authctxt->सक्रिय_ktype = रिक्त;
		debug("No more client hostkeys for hostbased authentication.");
		गच्छ बहिर्गमनम्;
	}

	यदि ((fp = sshkey_fingerprint(गुप्त, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == रिक्त) {
		error_f("sshkey_fingerprint failed");
		गच्छ बहिर्गमनम्;
	}
	debug_f("trying hostkey %s %s using sigalg %s",
	    sshkey_ssh_name(गुप्त), fp, authctxt->सक्रिय_ktype);

	/* figure out a name for the client host */
	lname = get_local_name(ssh_packet_get_connection_अन्तर्(ssh));
	यदि (lname == रिक्त) {
		error_f("cannot get local ipaddr/name");
		गच्छ बहिर्गमनम्;
	}

	/* XXX sshbuf_put_stringf? */
	xasprintf(&chost, "%s.", lname);
	debug2_f("chost %s", chost);

	/* construct data */
	यदि ((b = sshbuf_new()) == रिक्त) {
		error_f("sshbuf_new failed");
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = sshkey_गन्तव्यम्_blob(गुप्त, &keyblob, &keylen)) != 0) {
		error_fr(r, "sshkey_to_blob");
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = sshbuf_put_stringb(b, ssh->kex->session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_सन्देशः_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->server_user)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->विधानम्->name)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->सक्रिय_ktype)) != 0 ||
	    (r = sshbuf_put_string(b, keyblob, keylen)) != 0 ||
	    (r = sshbuf_put_cstring(b, chost)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->local_user)) != 0) {
		error_fr(r, "buffer error");
		गच्छ बहिर्गमनम्;
	}

#यदि_परिभाषितम् DEBUG_PK
	sshbuf_dump(b, stderr);
#यदि_अन्तः
	यदि ((r = ssh_keysign(ssh, गुप्त, &sig, &siglen,
	    sshbuf_ptr(b), sshbuf_len(b))) != 0) {
		error("sign using hostkey %s %s failed",
		    sshkey_ssh_name(गुप्त), fp);
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = sshpkt_start(ssh, SSH2_सन्देशः_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->विधानम्->name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->सक्रिय_ktype)) != 0 ||
	    (r = sshpkt_put_string(ssh, keyblob, keylen)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, chost)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->local_user)) != 0 ||
	    (r = sshpkt_put_string(ssh, sig, siglen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_fr(r, "packet error");
		गच्छ बहिर्गमनम्;
	}
	success = 1;

 बहिर्गमनम्:
	यदि (sig != रिक्त)
		freezero(sig, siglen);
	मुक्त(keyblob);
	मुक्त(lname);
	मुक्त(fp);
	मुक्त(chost);
	sshkey_free(गुप्त);
	sshbuf_free(b);

	प्रत्यागम success;
}

/* find auth method */

/*
 * given auth method name, if configurable options permit this method fill
 * in auth_ident field and return true, otherwise return false.
 */
स्थिर पूर्णाङ्क
authmethod_is_enabled(Authmethod *विधानम्)
{
	यदि (विधानम् == रिक्त)
		प्रत्यागम 0;
	/* return false if options indicate this method is disabled */
	यदि  (विधानम्->enabled == रिक्त || *विधानम्->enabled == 0)
		प्रत्यागम 0;
	/* return false if batch mode is enabled but method needs interactive mode */
	यदि  (विधानम्->batch_flag != रिक्त && *विधानम्->batch_flag != 0)
		प्रत्यागम 0;
	प्रत्यागम 1;
}

स्थिर Authmethod *
authmethod_lookup(ध्रुव वर्ण *name)
{
	Authmethod *विधानम् = रिक्त;
	यदि (name != रिक्त)
		प्रति (विधानम् = authmethods; विधानम्->name != रिक्त; विधानम्++)
			यदि (वाक्यं_तुलय(name, विधानम्->name) == 0)
				प्रत्यागम विधानम्;
	debug2("Unrecognized authentication method name: %s", name ? name : "NULL");
	प्रत्यागम रिक्त;
}

/* XXX internal state */
स्थिर Authmethod *current = रिक्त;
स्थिर वर्ण *supported = रिक्त;
स्थिर वर्ण *preferred = रिक्त;

/*
 * Given the authentication method list sent by the server, return the
 * next method we should try.  If the server initially sends a nil list,
 * use a built-in default list.
 */
स्थिर Authmethod *
authmethod_get(वर्ण *authlist)
{
	वर्ण *name = रिक्त;
	u_int अग्र;

	/* Use a suitable default if we're passed a nil list.  */
	यदि (authlist == रिक्त || वाक्यदैर्घ्यम्(authlist) == 0)
		authlist = options.preferred_authentications;

	यदि (supported == रिक्त || वाक्यं_तुलय(authlist, supported) != 0) {
		debug3("start over, passed a different list %s", authlist);
		मुक्त(supported);
		supported = xstrdup(authlist);
		preferred = options.preferred_authentications;
		debug3("preferred %s", preferred);
		current = रिक्त;
	} अन्यथा यदि (current != रिक्त && authmethod_is_enabled(current))
		प्रत्यागम current;

	प्रति (;;) {
		यदि ((name = मेलनम्_list(preferred, supported, &अग्र)) == रिक्त) {
			debug("No more authentication methods to try.");
			current = रिक्त;
			प्रत्यागम रिक्त;
		}
		preferred += अग्र;
		debug3("authmethod_lookup %s", name);
		debug3("remaining preferred: %s", preferred);
		यदि ((current = authmethod_lookup(name)) != रिक्त &&
		    authmethod_is_enabled(current)) {
			debug3("authmethod_is_enabled %s", name);
			debug("Next authentication method: %s", name);
			मुक्त(name);
			प्रत्यागम current;
		}
		मुक्त(name);
	}
}

स्थिर वर्ण *
authmethods_get(शून्य)
{
	Authmethod *विधानम् = रिक्त;
	संरचना sshbuf *b;
	वर्ण *list;
	पूर्णाङ्क r;

	यदि ((b = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	प्रति (विधानम् = authmethods; विधानम्->name != रिक्त; विधानम्++) {
		यदि (authmethod_is_enabled(विधानम्)) {
			यदि ((r = sshbuf_putf(b, "%s%s",
			    sshbuf_len(b) ? "," : "", विधानम्->name)) != 0)
				fatal_fr(r, "buffer error");
		}
	}
	यदि ((list = sshbuf_dup_string(b)) == रिक्त)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	प्रत्यागम list;
}
