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
#د_که_پای

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

#که_تعریف_شوی GSSAPI
#ضمن "ssh-gss.h"
#د_که_پای

/* import */
خارجي Options options;

/*
 * SSH2 key exchange
 */

ساكن حرف *xxx_host;
ساكن بنية sockaddr_storage xxx_hostaddr;
ساكن ثابت بنية ssh_conn_info *xxx_conn_info;
ساكن صحيح کلی_type_allowed(بنية sshkey *, ثابت حرف *);

ساكن صحيح
verify_host_کلی_callback(بنية sshkey *hostkey, بنية ssh *ssh)
{
	صحيح r;

	إذا ((r = sshkey_check_rsa_اوږدتیا(hostkey,
	    options.required_rsa_اندازه)) != 0)
		fatal_r(r, "Bad server host key");
	إذا (!کلی_type_allowed(hostkey, options.hostkeyalgorithms)) {
		fatal("Server host key %s not in HostKeyAlgorithms",
		    sshkey_ssh_name(hostkey));
	}
	إذا (verify_host_کلی(xxx_host, (بنية sockaddr *)&xxx_hostaddr, hostkey,
	    xxx_conn_info) != 0)
		fatal("Host key verification failed.");
	أرجع 0;
}

/* Returns the first item from a comma-separated algorithm list */
ساكن حرف *
لومړی_alg(ثابت حرف *algs)
{
	حرف *ret, *cp;

	ret = xstrdup(algs);
	إذا ((cp = strchr(ret, ',')) != عدم)
		*cp = '\0';
	أرجع ret;
}

ساكن حرف *
ترتیب_hostkeyalgs(حرف *host, بنية sockaddr *hostaddr, u_short پورټ,
    ثابت بنية ssh_conn_info *cinfo)
{
	حرف *oavail = عدم, *avail = عدم, *لومړی = عدم, *وروستی = عدم;
	حرف *alg = عدم, *hostname = عدم, *ret = عدم, *غوره = عدم;
	اندازه_t maxlen;
	بنية hostkeys *hostkeys = عدم;
	صحيح ktype;
	u_int i;

	/* Find all hostkeys for this hostname */
	get_hostfile_hostname_ipaddr(host, hostaddr, پورټ, &hostname, عدم);
	hostkeys = init_hostkeys();
	لكل (i = 0; i < options.عدد_user_hostfiles; i++)
		بارول_hostkeys(hostkeys, hostname, options.user_hostfiles[i], 0);
	لكل (i = 0; i < options.عدد_system_hostfiles; i++) {
		بارول_hostkeys(hostkeys, hostname,
		    options.system_hostfiles[i], 0);
	}
	إذا (options.معلوم_hosts_command != عدم) {
		بارول_hostkeys_command(hostkeys, options.معلوم_hosts_command,
		    "ORDER", cinfo, عدم, hostname);
	}
	/*
	 * If a plain public key exists that matches the type of the best
	 * preference HostkeyAlgorithms, then use the whole list as is.
	 * Note that we ignore whether the best preference algorithm is a
	 * certificate type, as sshconnect.c will downgrade certs to
	 * plain keys if necessary.
	 */
	غوره = لومړی_alg(options.hostkeyalgorithms);
	إذا (lookup_کلی_دننه_hostkeys_by_type(hostkeys,
	    sshkey_type_plain(sshkey_type_from_name(غوره)),
	    sshkey_ecdsa_nid_from_name(غوره), عدم)) {
		debug3_f("have matching best-preference key type %s, "
		    "using HostkeyAlgorithms verbatim", غوره);
		ret = xstrdup(options.hostkeyalgorithms);
		اذهب بهر;
	}

	/*
	 * Otherwise, prefer the host key algorithms that match known keys
	 * while keeping the ordering of HostkeyAlgorithms as much as possible.
	 */
	oavail = avail = xstrdup(options.hostkeyalgorithms);
	maxlen = مزي_اوږدوالی(avail) + 1;
	لومړی = xmalloc(maxlen);
	وروستی = xmalloc(maxlen);
	*لومړی = *وروستی = '\0';

#تعریف_کړه ALG_APPEND(منزل, from) \
	افعل { \
		إذا (*منزل != '\0') \
			strlcat(منزل, ",", maxlen); \
		strlcat(منزل, from, maxlen); \
	} طالما (0)

	طالما ((alg = strsep(&avail, ",")) && *alg != '\0') {
		إذا ((ktype = sshkey_type_from_name(alg)) == کلی_UNSPEC)
			fatal_f("unknown alg %s", alg);
		/*
		 * If we have a @cert-authority marker in known_hosts then
		 * prefer all certificate algorithms.
		 */
		إذا (sshkey_type_is_cert(ktype) &&
		    lookup_marker_دننه_hostkeys(hostkeys, MRK_CA)) {
			ALG_APPEND(لومړی, alg);
			استمر;
		}
		/* If the key appears in known_hosts then prefer it */
		إذا (lookup_کلی_دننه_hostkeys_by_type(hostkeys,
		    sshkey_type_plain(ktype),
		    sshkey_ecdsa_nid_from_name(alg), عدم)) {
			ALG_APPEND(لومړی, alg);
			استمر;
		}
		/* Otherwise, put it last */
		ALG_APPEND(وروستی, alg);
	}
#تعریف_لغوه ALG_APPEND
	xasprintf(&ret, "%s%s%s", لومړی,
	    (*لومړی == '\0' || *وروستی == '\0') ? "" : ",", وروستی);
	إذا (*لومړی != '\0')
		debug3_f("prefer hostkeyalgs: %s", لومړی);
	وإلا
		debug3_f("no algorithms matched; accept original");
 بهر:
	حرر(غوره);
	حرر(لومړی);
	حرر(وروستی);
	حرر(hostname);
	حرر(oavail);
	free_hostkeys(hostkeys);

	أرجع ret;
}

فراغ
ssh_kex2(بنية ssh *ssh, حرف *host, بنية sockaddr_storage *hostaddr,
    u_short پورټ, ثابت بنية ssh_conn_info *cinfo)
{
	حرف *myproposal[PROPOSAL_MAX];
	حرف *all_کلی, *hkalgs = عدم;
	صحيح r, use_معلوم_hosts_ترتیب = 0;

	xxx_host = xstrdup(host);
	xxx_hostaddr = *hostaddr;
	xxx_conn_info = ssh_conn_info_dup(cinfo);

	ssh_packet_سېټ_rekey_limits(ssh, options.rekey_حد,
	    options.rekey_interval);

	/*
	 * If the user has not specified HostkeyAlgorithms, or has only
	 * appended or removed algorithms from that list then prefer algorithms
	 * that are in the list that are supported by known_hosts keys.
	 */
	إذا (options.hostkeyalgorithms == عدم ||
	    options.hostkeyalgorithms[0] == '-' ||
	    options.hostkeyalgorithms[0] == '+')
		use_معلوم_hosts_ترتیب = 1;

	/* Expand or fill in HostkeyAlgorithms */
	all_کلی = sshkey_alg_list(0, 0, 1, ',');
	إذا ((r = kex_assemble_نومونه(&options.hostkeyalgorithms,
	    kex_default_pk_alg(), all_کلی)) != 0)
		fatal_fr(r, "kex_assemble_namelist");
	حرر(all_کلی);

	إذا (use_معلوم_hosts_ترتیب) {
		hkalgs = ترتیب_hostkeyalgs(host, (بنية sockaddr *)hostaddr,
		    پورټ, cinfo);
	}

	kex_proposal_populate_entries(ssh, myproposal,
	    options.kex_algorithms, options.ciphers, options.macs,
	    compression_alg_list(options.compression),
	    hkalgs ? hkalgs : options.hostkeyalgorithms);

	حرر(hkalgs);

	/* start key exchange */
	إذا ((r = kex_تیاری(ssh, myproposal)) != 0)
		fatal_r(r, "kex_setup");
#که_تعریف_شوی WITH_OPENSSL
	ssh->kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GEX_SHA1] = kexgex_client;
	ssh->kex->kex[KEX_DH_GEX_SHA256] = kexgex_client;
	ssh->kex->kex[KEX_ECDH_SHA2] = kex_gen_client;
#د_که_پای
	ssh->kex->kex[KEX_C25519_SHA256] = kex_gen_client;
	ssh->kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_client;
	ssh->kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_client;
	ssh->kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_client;
	ssh->kex->verify_host_کلی=&verify_host_کلی_callback;

	ssh_dispatch_پرلپسې_fatal(ssh, DISPATCH_بلاک, &ssh->kex->بشپړ);
	kex_proposal_free_entries(myproposal);

#که_تعریف_شوی DEBUG_KEXDH
	/* send 1st encrypted/maced/compressed message */
	إذا ((r = sshpkt_پیل(ssh, SSH2_پیغام_IGNORE)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "markus")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send packet");
#د_که_پای
}

/*
 * Authenticate user
 */

تعريفنوع بنية cauthctxt Authctxt;
تعريفنوع بنية cauthmethod Authmethod;
تعريفنوع بنية بې_اغېزه_عنصر_2 بې_اغېزه_عنصر;
تعريفنوع بنية idlist Idlist;

بنية بې_اغېزه_عنصر_2 {
	TAILQ_ENTRY(بې_اغېزه_عنصر_2) بل;
	صحيح	agent_fd;		/* >=0 if agent supports key */
	بنية sshkey	*کلی;		/* public/private key */
	حرف	*filename;		/* comment for agent-only keys */
	صحيح	tried;
	صحيح	isprivate;		/* key points to the private key */
	صحيح	userprovided;
};
TAILQ_HEAD(idlist, بې_اغېزه_عنصر_2);

بنية cauthctxt {
	ثابت حرف *server_user;
	ثابت حرف *local_user;
	ثابت حرف *host;
	ثابت حرف *service;
	بنية cauthmethod *لاره;
	sig_atomic_t success;
	حرف *authlist;
#که_تعریف_شوی GSSAPI
	/* gssapi */
	gss_OID_سېټ gss_supported_mechs;
	u_int mech_tried;
#د_که_پای
	/* pubkey */
	بنية idlist کلیګانې;
	صحيح agent_fd;
	/* hostbased */
	Sensitive *sensitive;
	حرف *oktypes, *ktypes;
	ثابت حرف *فعال_ktype;
	/* kbd-interactive */
	صحيح info_req_کتل_شوی;
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

ساكن صحيح ننوت_userauth_service_accept(صحيح, uint32_t, بنية ssh *);
ساكن صحيح ننوت_userauth_success(صحيح, uint32_t, بنية ssh *);
ساكن صحيح ننوت_userauth_failure(صحيح, uint32_t, بنية ssh *);
ساكن صحيح ننوت_userauth_banner(صحيح, uint32_t, بنية ssh *);
ساكن صحيح ننوت_userauth_error(صحيح, uint32_t, بنية ssh *);
ساكن صحيح ننوت_userauth_info_req(صحيح, uint32_t, بنية ssh *);
ساكن صحيح ننوت_userauth_pk_ok(صحيح, uint32_t, بنية ssh *);
ساكن صحيح ننوت_userauth_passwd_changereq(صحيح, uint32_t, بنية ssh *);

ساكن صحيح userauth_none(بنية ssh *);
ساكن صحيح userauth_pubkey(بنية ssh *);
ساكن صحيح userauth_passwd(بنية ssh *);
ساكن صحيح userauth_kbdint(بنية ssh *);
ساكن صحيح userauth_hostbased(بنية ssh *);

#که_تعریف_شوی GSSAPI
ساكن صحيح userauth_gssapi(بنية ssh *);
ساكن فراغ userauth_gssapi_cleanup(بنية ssh *);
ساكن صحيح ننوت_gssapi_response(صحيح type, uint32_t, بنية ssh *);
ساكن صحيح ننوت_gssapi_token(صحيح type, uint32_t, بنية ssh *);
ساكن صحيح ننوت_gssapi_error(صحيح, uint32_t, بنية ssh *);
ساكن صحيح ننوت_gssapi_errtok(صحيح, uint32_t, بنية ssh *);
#د_که_پای

فراغ	userauth(بنية ssh *, حرف *);

ساكن فراغ pubkey_cleanup(بنية ssh *);
ساكن صحيح sign_and_send_pubkey(بنية ssh *ssh, بې_اغېزه_عنصر *);
ساكن فراغ pubkey_prepare(بنية ssh *, Authctxt *);
ساكن فراغ pubkey_reset(Authctxt *);
ساكن بنية sshkey *بارول_بې_اغېزه_عنصر_file(بې_اغېزه_عنصر *);

ساكن Authmethod *authmethod_get(حرف *authlist);
ساكن Authmethod *authmethod_lookup(ثابت حرف *name);
ساكن حرف *authmethods_get(فراغ);

Authmethod authmethods[] = {
#که_تعریف_شوی GSSAPI
	{"gssapi-with-mic",
		userauth_gssapi,
		userauth_gssapi_cleanup,
		&options.gss_authentication,
		عدم},
#د_که_پای
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
		&options.batch_ډېرپېښ},
	{"password",
		userauth_passwd,
		عدم,
		&options.password_authentication,
		&options.batch_ډېرپېښ},
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
	authctxt.لاره = authmethod_lookup("none");
	authctxt.authlist = عدم;
	authctxt.methoddata = عدم;
	authctxt.sensitive = sensitive;
	authctxt.فعال_ktype = authctxt.oktypes = authctxt.ktypes = عدم;
	authctxt.info_req_کتل_شوی = 0;
	authctxt.attempt_kbdint = 0;
	authctxt.attempt_passwd = 0;
#إذا GSSAPI
	authctxt.gss_supported_mechs = عدم;
	authctxt.mech_tried = 0;
#د_که_پای
	authctxt.agent_fd = -1;
	إذا (authctxt.لاره == عدم)
		fatal_f("internal error: cannot send userauth none request");

	إذا ((r = sshpkt_پیل(ssh, SSH2_پیغام_SERVICE_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "ssh-userauth")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh->authctxt = &authctxt;
	ssh_dispatch_init(ssh, &ننوت_userauth_error);
	ssh_dispatch_سېټ(ssh, SSH2_پیغام_EXT_INFO, kex_ننوت_ext_info);
	ssh_dispatch_سېټ(ssh, SSH2_پیغام_SERVICE_ACCEPT, &ننوت_userauth_service_accept);
	ssh_dispatch_پرلپسې_fatal(ssh, DISPATCH_بلاک, &authctxt.success);	/* loop until success */
	pubkey_cleanup(ssh);
#که_تعریف_شوی GSSAPI
	إذا (authctxt.gss_supported_mechs != عدم) {
		u_int ms;

		gss_release_oid_سېټ(&ms, &authctxt.gss_supported_mechs);
		authctxt.gss_supported_mechs = عدم;
	}
#د_که_پای
	ssh->authctxt = عدم;

	ssh_dispatch_range(ssh, SSH2_پیغام_USERAUTH_MIN, SSH2_پیغام_USERAUTH_MAX, عدم);

	إذا (!authctxt.success)
		fatal("Authentication failed.");
	إذا (ssh_packet_connection_is_on_socket(ssh)) {
		verbose("Authenticated to %s ([%s]:%d) using \"%s\".", host,
		    ssh_remote_ipaddr(ssh), ssh_remote_پورټ(ssh),
		    authctxt.لاره->name);
	} وإلا {
		verbose("Authenticated to %s (via proxy) using \"%s\".", host,
		    authctxt.لاره->name);
	}
}

ساكن صحيح
ننوت_userauth_service_accept(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	صحيح r;

	إذا (ssh_packet_پاتې_شوی(ssh) > 0) {
		حرف *ځواب;

		إذا ((r = sshpkt_get_cstring(ssh, &ځواب, عدم)) != 0)
			اذهب بهر;
		debug2("service_accept: %s", ځواب);
		حرر(ځواب);
	} وإلا {
		debug2("buggy server: service_accept w/o service");
	}
	إذا ((r = sshpkt_get_پای_ټکی(ssh)) != 0)
		اذهب بهر;
	debug("SSH2_MSG_SERVICE_ACCEPT received");

	/* initial userauth request */
	userauth_none(ssh);

	/* accept EXT_INFO at any time during userauth */
	ssh_dispatch_سېټ(ssh, SSH2_پیغام_EXT_INFO, ssh->kex->ext_info_s ?
	    &kex_ننوت_ext_info : &ننوت_userauth_error);
	ssh_dispatch_سېټ(ssh, SSH2_پیغام_USERAUTH_SUCCESS, &ننوت_userauth_success);
	ssh_dispatch_سېټ(ssh, SSH2_پیغام_USERAUTH_FAILURE, &ننوت_userauth_failure);
	ssh_dispatch_سېټ(ssh, SSH2_پیغام_USERAUTH_BANNER, &ننوت_userauth_banner);
	r = 0;
 بهر:
	أرجع r;
}

فراغ
userauth(بنية ssh *ssh, حرف *authlist)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;

	إذا (authctxt->لاره != عدم && authctxt->لاره->cleanup != عدم)
		authctxt->لاره->cleanup(ssh);

	حرر(authctxt->methoddata);
	authctxt->methoddata = عدم;
	إذا (authlist == عدم) {
		authlist = authctxt->authlist;
	} وإلا {
		حرر(authctxt->authlist);
		authctxt->authlist = authlist;
	}
	لكل (;;) {
		Authmethod *لاره = authmethod_get(authlist);
		إذا (لاره == عدم)
			fatal("%s@%s: Permission denied (%s).",
			    authctxt->server_user, authctxt->host, authlist);
		authctxt->لاره = لاره;

		/* reset the per method handler */
		ssh_dispatch_range(ssh, SSH2_پیغام_USERAUTH_فی_لاره_MIN,
		    SSH2_پیغام_USERAUTH_فی_لاره_MAX, عدم);

		/* and try new method */
		إذا (لاره->userauth(ssh) != 0) {
			debug2("we sent a %s packet, wait for reply", لاره->name);
			اكسر;
		} وإلا {
			debug2("we did not send a packet, disable method");
			لاره->enabled = عدم;
		}
	}
}

ساكن صحيح
ننوت_userauth_error(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	fatal_f("bad message during authentication: type %d", type);
	أرجع 0;
}

ساكن صحيح
ننوت_userauth_banner(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	حرف *پیغام = عدم;
	اندازه_t len;
	صحيح r;

	debug3_f("entering");
	إذا ((r = sshpkt_get_cstring(ssh, &پیغام, &len)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, عدم, عدم)) != 0)
		اذهب بهر;
	إذا (len > 0 && options.log_level >= SYSLOG_LEVEL_INFO)
		fmprintf(stderr, "%s", پیغام);
	r = 0;
 بهر:
	حرر(پیغام);
	أرجع r;
}

ساكن صحيح
ننوت_userauth_success(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	إذا (authctxt == عدم)
		fatal_f("no authentication context");
	حرر(authctxt->authlist);
	authctxt->authlist = عدم;
	إذا (authctxt->لاره != عدم && authctxt->لاره->cleanup != عدم)
		authctxt->لاره->cleanup(ssh);
	حرر(authctxt->methoddata);
	authctxt->methoddata = عدم;
	authctxt->success = 1;			/* break out */
	ssh_dispatch_سېټ(ssh, SSH2_پیغام_EXT_INFO, dispatch_protocol_error);
	أرجع 0;
}

#إذا 0
ساكن صحيح
ننوت_userauth_success_unexpected(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	إذا (authctxt == عدم)
		fatal_f("no authentication context");

	fatal("Unexpected authentication success during %s.",
	    authctxt->لاره->name);
	أرجع 0;
}
#د_که_پای

ساكن صحيح
ننوت_userauth_failure(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	حرف *authlist = عدم;
	u_char partial;

	إذا (authctxt == عدم)
		fatal("input_userauth_failure: no authentication context");

	إذا (sshpkt_get_cstring(ssh, &authlist, عدم) != 0 ||
	    sshpkt_get_u8(ssh, &partial) != 0 ||
	    sshpkt_get_پای_ټکی(ssh) != 0)
		اذهب بهر;

	إذا (partial != 0) {
		verbose("Authenticated using \"%s\" with partial success.",
		    authctxt->لاره->name);
		/* reset state */
		pubkey_reset(authctxt);
	}
	debug("Authentications that can continue: %s", authlist);

	userauth(ssh, authlist);
	authlist = عدم;
 بهر:
	حرر(authlist);
	أرجع 0;
}

/*
 * Format an identity for logging including filename, key type, fingerprint
 * and location (agent, etc.). Caller must free.
 */
ساكن حرف *
format_بې_اغېزه_عنصر(بې_اغېزه_عنصر *id)
{
	حرف *fp = عدم, *ret = عدم;
	ثابت حرف *note = "";

	إذا (id->کلی != عدم) {
		fp = sshkey_fingerprint(id->کلی, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
	}
	إذا (id->کلی) {
		إذا ((id->کلی->flags & SSHKEY_FLAG_EXT) != 0)
			note = " token";
		وإلا إذا (sshkey_is_sk(id->کلی))
			note = " authenticator";
	}
	xasprintf(&ret, "%s %s%s%s%s%s%s",
	    id->filename,
	    id->کلی ? sshkey_type(id->کلی) : "", id->کلی ? " " : "",
	    fp ? fp : "",
	    id->userprovided ? " explicit" : "", note,
	    id->agent_fd != -1 ? " agent" : "");
	حرر(fp);
	أرجع ret;
}

ساكن صحيح
ننوت_userauth_pk_ok(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	بنية sshkey *کلی = عدم;
	بنية sshbuf *keyblob = عدم;
	بې_اغېزه_عنصر *id = عدم;
	صحيح pktype, وموندل = 0, لېږل_شوی = 0;
	حرف *pkalg = عدم, *fp = عدم, *ident = عدم;
	صحيح r;

	إذا (authctxt == عدم)
		fatal_f("no authentication context");

	إذا ((r = sshpkt_get_cstring(ssh, &pkalg, عدم)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0 ||
	    (r = sshpkt_get_پای_ټکی(ssh)) != 0)
		اذهب بشپړ;

	إذا (سمون_نمونه_list(pkalg, options.pubkey_accepted_algos, 0) != 1) {
		error_f("server replied to PK_OK with signature type %s not "
		    "in PubkeyAcceptedAlgorithms", pkalg);
		r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		اذهب بشپړ;
	}
	إذا ((pktype = sshkey_type_from_name(pkalg)) == کلی_UNSPEC) {
		debug_f("server sent unknown pkalg %s", pkalg);
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بشپړ;
	}
	/* inner key type should match signature type */
	إذا ((r = sshkey_fromb_allowlist(keyblob, &کلی, pkalg, عدم)) != 0) {
		debug_r(r, "no key from blob. pkalg %s", pkalg);
		اذهب بشپړ;
	}
	إذا (کلی->type != pktype) {
		error("input_userauth_pk_ok: type mismatch "
		    "for decoded key (received %d, expected %d)",
		    کلی->type, pktype);
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بشپړ;
	}

	/*
	 * search keys in the reverse order, because last candidate has been
	 * moved to the end of the queue.  this also avoids confusion by
	 * duplicate keys
	 */
	TAILQ_FOREACH_سرچپه(id, &authctxt->کلیګانې, idlist, بل) {
		إذا (sshkey_equal(کلی, id->کلی)) {
			وموندل = 1;
			اكسر;
		}
	}
	إذا (!وموندل || id == عدم) {
		fp = sshkey_fingerprint(کلی, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		error_f("server replied with unknown key: %s %s",
		    sshkey_type(کلی), fp == عدم ? "<ERROR>" : fp);
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بشپړ;
	}
	ident = format_بې_اغېزه_عنصر(id);
	debug("Server accepts key: %s", ident);
	لېږل_شوی = sign_and_send_pubkey(ssh, id);
	r = 0;
 بشپړ:
	sshkey_free(کلی);
	sshbuf_free(keyblob);
	حرر(ident);
	حرر(fp);
	حرر(pkalg);

	/* try another method if we did not send a packet */
	إذا (r == 0 && لېږل_شوی == 0)
		userauth(ssh, عدم);
	أرجع r;
}

#که_تعریف_شوی GSSAPI
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
	طالما (authctxt->mech_tried < authctxt->gss_supported_mechs->شمېر &&
	    !ok) {
		mech = &authctxt->gss_supported_mechs->
		    elements[authctxt->mech_tried];
		/* My DER encoding requires length<128 */
		إذا (mech->اوږدتیا < 128 && ssh_gssapi_check_mechanism(&gssctxt,
		    mech, authctxt->host)) {
			ok = 1; /* Mechanism works */
		} وإلا {
			authctxt->mech_tried++;
		}
	}

	إذا (!ok || mech == عدم)
		أرجع 0;

	authctxt->methoddata=(فراغ *)gssctxt;

	إذا ((r = sshpkt_پیل(ssh, SSH2_پیغام_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->لاره->name)) != 0 ||
	    (r = sshpkt_put_u32(ssh, 1)) != 0 ||
	    (r = sshpkt_put_u32(ssh, (mech->اوږدتیا) + 2)) != 0 ||
	    (r = sshpkt_put_u8(ssh, SSH_GSS_OIDTYPE)) != 0 ||
	    (r = sshpkt_put_u8(ssh, mech->اوږدتیا)) != 0 ||
	    (r = sshpkt_put(ssh, mech->elements, mech->اوږدتیا)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh_dispatch_سېټ(ssh, SSH2_پیغام_USERAUTH_GSSAPI_RESPONSE, &ننوت_gssapi_response);
	ssh_dispatch_سېټ(ssh, SSH2_پیغام_USERAUTH_GSSAPI_TOKEN, &ننوت_gssapi_token);
	ssh_dispatch_سېټ(ssh, SSH2_پیغام_USERAUTH_GSSAPI_ERROR, &ننوت_gssapi_error);
	ssh_dispatch_سېټ(ssh, SSH2_پیغام_USERAUTH_GSSAPI_ERRTOK, &ننوت_gssapi_errtok);

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
process_gssapi_token(بنية ssh *ssh, gss_بفر_t recv_tok)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt = authctxt->methoddata;
	gss_بفر_desc send_tok = GSS_C_تشه_بفر;
	gss_بفر_desc mic = GSS_C_تشه_بفر;
	gss_بفر_desc gssbuf;
	OM_uint32 حالت, ms, flags;
	صحيح r;

	حالت = ssh_gssapi_init_ctx(gssctxt, options.gss_deleg_creds,
	    recv_tok, &send_tok, &flags);

	إذا (send_tok.اوږدتیا > 0) {
		u_char type = GSS_ERROR(حالت) ?
		    SSH2_پیغام_USERAUTH_GSSAPI_ERRTOK :
		    SSH2_پیغام_USERAUTH_GSSAPI_TOKEN;

		إذا ((r = sshpkt_پیل(ssh, type)) != 0 ||
		    (r = sshpkt_put_string(ssh, send_tok.ارزښت,
		    send_tok.اوږدتیا)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send %u packet", type);

		gss_release_بفر(&ms, &send_tok);
	}

	إذا (حالت == GSS_S_COMPLETE) {
		/* send either complete or MIC, depending on mechanism */
		إذا (!(flags & GSS_C_INTEG_FLAG)) {
			إذا ((r = sshpkt_پیل(ssh,
			    SSH2_پیغام_USERAUTH_GSSAPI_EXCHANGE_COMPLETE)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "send completion");
		} وإلا {
			بنية sshbuf *b;

			إذا ((b = sshbuf_new()) == عدم)
				fatal_f("sshbuf_new failed");
			ssh_gssapi_buildmic(b, authctxt->server_user,
			    authctxt->service, "gssapi-with-mic",
			    ssh->kex->session_id);

			إذا ((gssbuf.ارزښت = sshbuf_mutable_ptr(b)) == عدم)
				fatal_f("sshbuf_mutable_ptr failed");
			gssbuf.اوږدتیا = sshbuf_len(b);

			حالت = ssh_gssapi_sign(gssctxt, &gssbuf, &mic);

			إذا (!GSS_ERROR(حالت)) {
				إذا ((r = sshpkt_پیل(ssh,
				    SSH2_پیغام_USERAUTH_GSSAPI_MIC)) != 0 ||
				    (r = sshpkt_put_string(ssh, mic.ارزښت,
				    mic.اوږدتیا)) != 0 ||
				    (r = sshpkt_send(ssh)) != 0)
					fatal_fr(r, "send MIC");
			}

			sshbuf_free(b);
			gss_release_بفر(&ms, &mic);
		}
	}

	أرجع حالت;
}

ساكن صحيح
ننوت_gssapi_response(صحيح type, uint32_t plen, بنية ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	اندازه_t oidlen;
	u_char *oidv = عدم;
	صحيح r;

	إذا (authctxt == عدم)
		fatal("input_gssapi_response: no authentication context");
	gssctxt = authctxt->methoddata;

	/* Setup our OID */
	إذا ((r = sshpkt_get_string(ssh, &oidv, &oidlen)) != 0)
		اذهب بشپړ;

	إذا (oidlen <= 2 ||
	    oidv[0] != SSH_GSS_OIDTYPE ||
	    oidv[1] != oidlen - 2) {
		debug("Badly encoded mechanism OID received");
		userauth(ssh, عدم);
		اذهب ok;
	}

	إذا (!ssh_gssapi_check_oid(gssctxt, oidv + 2, oidlen - 2))
		fatal("Server returned different OID than expected");

	إذا ((r = sshpkt_get_پای_ټکی(ssh)) != 0)
		اذهب بشپړ;

	إذا (GSS_ERROR(process_gssapi_token(ssh, GSS_C_NO_بفر))) {
		/* Start again with next method on list */
		debug("Trying to start again");
		userauth(ssh, عدم);
		اذهب ok;
	}
 ok:
	r = 0;
 بشپړ:
	حرر(oidv);
	أرجع r;
}

ساكن صحيح
ننوت_gssapi_token(صحيح type, uint32_t plen, بنية ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	gss_بفر_desc recv_tok;
	u_char *p = عدم;
	اندازه_t len;
	OM_uint32 حالت;
	صحيح r;

	إذا (authctxt == عدم)
		fatal("input_gssapi_response: no authentication context");

	إذا ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_پای_ټکی(ssh)) != 0)
		اذهب بهر;

	recv_tok.ارزښت = p;
	recv_tok.اوږدتیا = len;
	حالت = process_gssapi_token(ssh, &recv_tok);

	/* Start again with the next method in the list */
	إذا (GSS_ERROR(حالت)) {
		userauth(ssh, عدم);
		/* ok */
	}
	r = 0;
 بهر:
	حرر(p);
	أرجع r;
}

ساكن صحيح
ننوت_gssapi_errtok(صحيح type, uint32_t plen, بنية ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	gss_بفر_desc send_tok = GSS_C_تشه_بفر;
	gss_بفر_desc recv_tok;
	OM_uint32 ms;
	u_char *p = عدم;
	اندازه_t len;
	صحيح r;

	إذا (authctxt == عدم)
		fatal("input_gssapi_response: no authentication context");
	gssctxt = authctxt->methoddata;

	إذا ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_پای_ټکی(ssh)) != 0) {
		حرر(p);
		أرجع r;
	}

	/* Stick it into GSSAPI and see what it says */
	recv_tok.ارزښت = p;
	recv_tok.اوږدتیا = len;
	(فراغ)ssh_gssapi_init_ctx(gssctxt, options.gss_deleg_creds,
	    &recv_tok, &send_tok, عدم);
	حرر(p);
	gss_release_بفر(&ms, &send_tok);

	/* Server will be returning a failed packet after this one */
	أرجع 0;
}

ساكن صحيح
ننوت_gssapi_error(صحيح type, uint32_t plen, بنية ssh *ssh)
{
	حرف *پیغام = عدم;
	حرف *lang = عدم;
	صحيح r;

	إذا ((r = sshpkt_get_u32(ssh, عدم)) != 0 ||	/* maj */
	    (r = sshpkt_get_u32(ssh, عدم)) != 0 ||	/* min */
	    (r = sshpkt_get_cstring(ssh, &پیغام, عدم)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, عدم)) != 0)
		اذهب بهر;
	r = sshpkt_get_پای_ټکی(ssh);
	debug("Server GSSAPI Error:\n%s", پیغام);
 بهر:
	حرر(پیغام);
	حرر(lang);
	أرجع r;
}
#د_که_پای /* GSSAPI */

ساكن صحيح
userauth_none(بنية ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	صحيح r;

	/* initial userauth request */
	إذا ((r = sshpkt_پیل(ssh, SSH2_پیغام_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->لاره->name)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	أرجع 1;
}

ساكن صحيح
userauth_passwd(بنية ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	حرف *password, *prompt = عدم;
	ثابت حرف *host = options.host_کلی_alias ?  options.host_کلی_alias :
	    authctxt->host;
	صحيح r;

	إذا (authctxt->attempt_passwd++ >= options.شمېره_د_password_prompts)
		أرجع 0;

	إذا (authctxt->attempt_passwd != 1)
		error("Permission denied, please try again.");

	xasprintf(&prompt, "%s@%s's password: ", authctxt->server_user, host);
	password = read_passphrase(prompt, 0);
	إذا ((r = sshpkt_پیل(ssh, SSH2_پیغام_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->لاره->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, password)) != 0 ||
	    (r = sshpkt_جمع_کړه_padding(ssh, 64)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	حرر(prompt);
	إذا (password != عدم)
		freezero(password, مزي_اوږدوالی(password));

	ssh_dispatch_سېټ(ssh, SSH2_پیغام_USERAUTH_PASSWD_CHANGEREQ,
	    &ننوت_userauth_passwd_changereq);

	أرجع 1;
}

/*
 * parse PASSWD_CHANGEREQ, prompt user and send SSH2_MSG_USERAUTH_REQUEST
 */
ساكن صحيح
ننوت_userauth_passwd_changereq(صحيح type, uint32_t seqnr, بنية ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	حرف *info = عدم, *lang = عدم, *password = عدم, *retype = عدم;
	حرف prompt[256];
	ثابت حرف *host;
	صحيح r, addnl;
	اندازه_t len;

	debug2("input_userauth_passwd_changereq");

	إذا (authctxt == عدم)
		fatal("input_userauth_passwd_changereq: "
		    "no authentication context");
	host = options.host_کلی_alias ? options.host_کلی_alias : authctxt->host;

	إذا ((r = sshpkt_get_cstring(ssh, &info, عدم)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, عدم)) != 0)
		اذهب بهر;
	إذا ((len = مزي_اوږدوالی(info)) > 0) {
		addnl = info[len] != '\n';
		fmprintf(stderr, "%s%s", info, addnl ? "\n" : "");
	}
	إذا ((r = sshpkt_پیل(ssh, SSH2_پیغام_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->لاره->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0)	/* additional info */
		اذهب بهر;

	snprintf(prompt, حجم(prompt),
	    "Enter %.30s@%.128s's old password: ",
	    authctxt->server_user, host);
	password = read_passphrase(prompt, 0);
	إذا ((r = sshpkt_put_cstring(ssh, password)) != 0)
		اذهب بهر;

	freezero(password, مزي_اوږدوالی(password));
	password = عدم;
	طالما (password == عدم) {
		snprintf(prompt, حجم(prompt),
		    "Enter %.30s@%.128s's new password: ",
		    authctxt->server_user, host);
		password = read_passphrase(prompt, RP_ALLOW_EOF);
		إذا (password == عدم) {
			/* bail out */
			r = 0;
			اذهب بهر;
		}
		snprintf(prompt, حجم(prompt),
		    "Retype %.30s@%.128s's new password: ",
		    authctxt->server_user, host);
		retype = read_passphrase(prompt, 0);
		إذا (strcmp(password, retype) != 0) {
			freezero(password, مزي_اوږدوالی(password));
			logit("Mismatch; try again, EOF to quit.");
			password = عدم;
		}
		freezero(retype, مزي_اوږدوالی(retype));
	}
	إذا ((r = sshpkt_put_cstring(ssh, password)) != 0 ||
	    (r = sshpkt_جمع_کړه_padding(ssh, 64)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		اذهب بهر;

	ssh_dispatch_سېټ(ssh, SSH2_پیغام_USERAUTH_PASSWD_CHANGEREQ,
	    &ننوت_userauth_passwd_changereq);
	r = 0;
 بهر:
	إذا (password)
		freezero(password, مزي_اوږدوالی(password));
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
کلی_sig_algorithm(بنية ssh *ssh, ثابت بنية sshkey *کلی)
{
	حرف *allowed, *oallowed, *cp, *tmp, *alg = عدم;
	ثابت حرف *server_sig_algs;

	/*
	 * The signature algorithm will only differ from the key algorithm
	 * for RSA keys/certs and when the server advertises support for
	 * newer (SHA2) algorithms.
	 */
	إذا (ssh == عدم || ssh->kex->server_sig_algs == عدم ||
	    (کلی->type != کلی_RSA && کلی->type != کلی_RSA_CERT) ||
	    (کلی->type == کلی_RSA_CERT && (ssh->compat & SSH_BUG_SIGTYPE))) {
		/* Filter base key signature alg against our configuration */
		أرجع سمون_list(sshkey_ssh_name(کلی),
		    options.pubkey_accepted_algos, عدم);
	}

	/*
	 * Workaround OpenSSH 7.4 bug: this version supports RSA/SHA-2 but
	 * fails to advertise it via SSH2_MSG_EXT_INFO.
	 */
	server_sig_algs = ssh->kex->server_sig_algs;
	إذا (کلی->type == کلی_RSA && (ssh->compat & SSH_BUG_SIGTYPE74))
		server_sig_algs = "rsa-sha2-256,rsa-sha2-512";

	/*
	 * For RSA keys/certs, since these might have a different sig type:
	 * find the first entry in PubkeyAcceptedAlgorithms of the right type
	 * that also appears in the supported signature algorithms list from
	 * the server.
	 */
	oallowed = allowed = xstrdup(options.pubkey_accepted_algos);
	طالما ((cp = strsep(&allowed, ",")) != عدم) {
		إذا (sshkey_type_from_name(cp) != کلی->type)
			استمر;
		tmp = سمون_list(sshkey_sigalg_by_name(cp),
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
بې_اغېزه_عنصر_sign(بنية بې_اغېزه_عنصر_2 *id, u_char **sigp, اندازه_t *lenp,
    ثابت u_char *معلومات, اندازه_t datalen, u_int compat, ثابت حرف *alg)
{
	بنية sshkey *sign_کلی = عدم, *prv = عدم;
	صحيح is_agent = 0, retried = 0, r = SSH_ERR_دننی_ERROR;
	بنية notifier_ctx *notifier = عدم;
	حرف *fp = عدم, *pin = عدم, *prompt = عدم;

	*sigp = عدم;
	*lenp = 0;

	/* The agent supports this key. */
	إذا (id->کلی != عدم && id->agent_fd != -1) {
		أرجع ssh_agent_sign(id->agent_fd, id->کلی, sigp, lenp,
		    معلومات, datalen, alg, compat);
	}

	/*
	 * We have already loaded the private key or the private key is
	 * stored in external hardware.
	 */
	إذا (id->کلی != عدم &&
	    (id->isprivate || (id->کلی->flags & SSHKEY_FLAG_EXT))) {
		sign_کلی = id->کلی;
		is_agent = 1;
	} وإلا {
		/* Load the private key from the file. */
		إذا ((prv = بارول_بې_اغېزه_عنصر_file(id)) == عدم)
			أرجع SSH_ERR_کلی_NOT_وموندل;
		إذا (id->کلی != عدم && !sshkey_equal_عامه(prv, id->کلی)) {
			error_f("private key %s contents do not match public",
			    id->filename);
			r = SSH_ERR_کلی_NOT_وموندل;
			اذهب بهر;
		}
		sign_کلی = prv;
	}
 retry_pin:
	/* Prompt for touch for non-agent FIDO keys that request UP */
	إذا (!is_agent && sshkey_is_sk(sign_کلی) &&
	    (sign_کلی->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
		/* XXX should batch mode just skip these? */
		إذا ((fp = sshkey_fingerprint(sign_کلی,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == عدم)
			fatal_f("fingerprint failed");
		notifier = notify_پیل(options.batch_ډېرپېښ,
		    "Confirm user presence for key %s %s",
		    sshkey_type(sign_کلی), fp);
		حرر(fp);
	}
	إذا ((r = sshkey_sign(sign_کلی, sigp, lenp, معلومات, datalen,
	    alg, options.sk_provider, pin, compat)) != 0) {
		debug_fr(r, "sshkey_sign");
		إذا (!retried && pin == عدم && !is_agent &&
		    sshkey_is_sk(sign_کلی) &&
		    r == SSH_ERR_کلی_WRONG_PASSPHRASE) {
			notify_complete(notifier, عدم);
			notifier = عدم;
			xasprintf(&prompt, "Enter PIN for %s key %s: ",
			    sshkey_type(sign_کلی), id->filename);
			pin = read_passphrase(prompt, 0);
			retried = 1;
			اذهب retry_pin;
		}
		اذهب بهر;
	}

	/*
	 * PKCS#11 tokens may not support all signature algorithms,
	 * so check what we get back.
	 */
	إذا (id->کلی != عدم && (id->کلی->flags & SSHKEY_FLAG_EXT) != 0 &&
	    (r = sshkey_check_sigtype(*sigp, *lenp, alg)) != 0) {
		debug_fr(r, "sshkey_check_sigtype");
		اذهب بهر;
	}
	/* success */
	r = 0;
 بهر:
	حرر(prompt);
	إذا (pin != عدم)
		freezero(pin, مزي_اوږدوالی(pin));
	notify_complete(notifier, r == 0 ? "User presence confirmed" : عدم);
	sshkey_free(prv);
	أرجع r;
}

ساكن صحيح
id_filename_matches(بې_اغېزه_عنصر *id, بې_اغېزه_عنصر *شخصي_id)
{
	ساكن ثابت حرف * ثابت suffixes[] = { ".pub", "-cert.pub", عدم };
	اندازه_t len = مزي_اوږدوالی(id->filename), plen = مزي_اوږدوالی(شخصي_id->filename);
	اندازه_t i, slen;

	إذا (strcmp(id->filename, شخصي_id->filename) == 0)
		أرجع 1;
	لكل (i = 0; suffixes[i]; i++) {
		slen = مزي_اوږدوالی(suffixes[i]);
		إذا (len > slen && plen == len - slen &&
		    strcmp(id->filename + (len - slen), suffixes[i]) == 0 &&
		    memcmp(id->filename, شخصي_id->filename, plen) == 0)
			أرجع 1;
	}
	أرجع 0;
}

ساكن صحيح
sign_and_send_pubkey(بنية ssh *ssh, بې_اغېزه_عنصر *id)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	بنية sshbuf *b = عدم;
	بې_اغېزه_عنصر *شخصي_id, *sign_id = عدم;
	u_char *signature = عدم;
	اندازه_t slen = 0, skip = 0;
	صحيح r, fallback_sigtype, لېږل_شوی = 0;
	حرف *alg = عدم, *fp = عدم;
	ثابت حرف *loc = "", *لاره = "publickey";
	صحيح hostbound = 0;

	/* prefer host-bound pubkey signatures if supported by server */
	إذا ((ssh->kex->flags & KEX_HAS_PUBKEY_HOSTBOUND) != 0 &&
	    (options.pubkey_authentication & SSH_PUBKEY_AUTH_HBOUND) != 0) {
		hostbound = 1;
		لاره = "publickey-hostbound-v00@openssh.com";
	}

	إذا ((fp = sshkey_fingerprint(id->کلی, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == عدم)
		أرجع 0;

	debug3_f("using %s with %s %s", لاره, sshkey_type(id->کلی), fp);

	/*
	 * If the key is an certificate, try to find a matching private key
	 * and use it to complete the signature.
	 * If no such private key exists, fall back to trying the certificate
	 * key itself in case it has a private half already loaded.
	 * This will try to set sign_id to the private key that will perform
	 * the signature.
	 */
	إذا (id->agent_fd == -1 && sshkey_is_cert(id->کلی)) {
		TAILQ_FOREACH(شخصي_id, &authctxt->کلیګانې, بل) {
			إذا (sshkey_equal_عامه(id->کلی, شخصي_id->کلی) &&
			    id->کلی->type != شخصي_id->کلی->type) {
				sign_id = شخصي_id;
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
		    (id->کلی->flags & SSHKEY_FLAG_EXT) == 0) {
			TAILQ_FOREACH(شخصي_id, &authctxt->کلیګانې, بل) {
				إذا (شخصي_id->کلی == عدم &&
				    id_filename_matches(id, شخصي_id)) {
					sign_id = شخصي_id;
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
		إذا ((alg = کلی_sig_algorithm(fallback_sigtype ? عدم : ssh,
		    id->کلی)) == عدم) {
			error_f("no mutual signature supported");
			اذهب بهر;
		}
		debug3_f("signing using %s %s", alg, fp);

		sshbuf_free(b);
		إذا ((b = sshbuf_new()) == عدم)
			fatal_f("sshbuf_new failed");
		إذا ((r = sshbuf_put_stringb(b,
		    ssh->kex->session_id)) != 0)
			fatal_fr(r, "sshbuf_put_stringb");
		skip = sshbuf_len(b);
		إذا ((r = sshbuf_put_u8(b, SSH2_پیغام_USERAUTH_REQUEST)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->server_user)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
		    (r = sshbuf_put_cstring(b, لاره)) != 0 ||
		    (r = sshbuf_put_u8(b, 1)) != 0 ||
		    (r = sshbuf_put_cstring(b, alg)) != 0 ||
		    (r = sshkey_puts(id->کلی, b)) != 0) {
			fatal_fr(r, "assemble signed data");
		}
		إذا (hostbound) {
			إذا (ssh->kex->initial_hostkey == عدم) {
				fatal_f("internal error: initial hostkey "
				    "not recorded");
			}
			إذا ((r = sshkey_puts(ssh->kex->initial_hostkey, b)) != 0)
				fatal_fr(r, "assemble %s hostkey", لاره);
		}
		/* generate signature */
		r = بې_اغېزه_عنصر_sign(sign_id, &signature, &slen,
		    sshbuf_ptr(b), sshbuf_len(b), ssh->compat, alg);
		إذا (r == 0)
			اكسر;
		وإلا إذا (r == SSH_ERR_کلی_NOT_وموندل)
			اذهب بهر; /* soft failure */
		وإلا إذا (r == SSH_ERR_SIGN_ALG_UNSUPPORTED &&
		    !fallback_sigtype) {
			إذا (sign_id->agent_fd != -1)
				loc = "agent ";
			وإلا إذا (sign_id->کلی != عدم &&
			    (sign_id->کلی->flags & SSHKEY_FLAG_EXT) != 0)
				loc = "token ";
			logit("%skey %s %s returned incorrect signature type",
			    loc, sshkey_type(id->کلی), fp);
			استمر;
		}
		error_fr(r, "signing failed for %s \"%s\"%s",
		    sshkey_type(sign_id->کلی), sign_id->filename,
		    id->agent_fd != -1 ? " from agent" : "");
		اذهب بهر;
	}
	إذا (slen == 0 || signature == عدم) /* shouldn't happen */
		fatal_f("no signature");

	/* append signature */
	إذا ((r = sshbuf_put_string(b, signature, slen)) != 0)
		fatal_fr(r, "append signature");

#که_تعریف_شوی DEBUG_PK
	sshbuf_dump(b, stderr);
#د_که_پای
	/* skip session id and packet type */
	إذا ((r = sshbuf_consume(b, skip + 1)) != 0)
		fatal_fr(r, "consume");

	/* put remaining data from buffer into packet */
	إذا ((r = sshpkt_پیل(ssh, SSH2_پیغام_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_putb(ssh, b)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "enqueue request");

	/* success */
	لېږل_شوی = 1;

 بهر:
	حرر(fp);
	حرر(alg);
	sshbuf_free(b);
	freezero(signature, slen);
	أرجع لېږل_شوی;
}

ساكن صحيح
send_pubkey_test(بنية ssh *ssh, بې_اغېزه_عنصر *id)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	u_char *blob = عدم;
	حرف *alg = عدم;
	اندازه_t bloblen;
	u_int have_sig = 0;
	صحيح لېږل_شوی = 0, r;

	إذا ((alg = کلی_sig_algorithm(ssh, id->کلی)) == عدم) {
		debug_f("no mutual signature algorithm");
		اذهب بهر;
	}

	إذا ((r = sshkey_منزل_blob(id->کلی, &blob, &bloblen)) != 0) {
		/* we cannot handle this key */
		debug3_f("cannot handle key");
		اذهب بهر;
	}
	/* register callback for USERAUTH_PK_OK message */
	ssh_dispatch_سېټ(ssh, SSH2_پیغام_USERAUTH_PK_OK, &ننوت_userauth_pk_ok);

	إذا ((r = sshpkt_پیل(ssh, SSH2_پیغام_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->لاره->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, have_sig)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, alg)) != 0 ||
	    (r = sshpkt_put_string(ssh, blob, bloblen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	لېږل_شوی = 1;

 بهر:
	حرر(alg);
	حرر(blob);
	أرجع لېږل_شوی;
}

ساكن بنية sshkey *
بارول_بې_اغېزه_عنصر_file(بې_اغېزه_عنصر *id)
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
	لكل (i = 0; i <= options.شمېره_د_password_prompts; i++) {
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
		بدل ((r = sshkey_بارول_شخصي_type(کلی_UNSPEC, id->filename,
		    passphrase, &خاص, &comment))) {
		حالة 0:
			اكسر;
		حالة SSH_ERR_کلی_WRONG_PASSPHRASE:
			إذا (options.batch_ډېرپېښ) {
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
		إذا (!quit && (r = sshkey_check_rsa_اوږدتیا(خاص,
		    options.required_rsa_اندازه)) != 0) {
			debug_fr(r, "Skipping key %s", id->filename);
			sshkey_free(خاص);
			خاص = عدم;
			quit = 1;
		}
		إذا (!quit && خاص != عدم && id->agent_fd == -1 &&
		    !(id->کلی && id->isprivate))
			maybe_جمع_کړه_کلی_منزل_agent(id->filename, خاص, comment,
			    passphrase);
		إذا (i > 0)
			freezero(passphrase, مزي_اوږدوالی(passphrase));
		حرر(comment);
		إذا (خاص != عدم || quit)
			اكسر;
	}
	أرجع خاص;
}

ساكن صحيح
کلی_type_allowed(بنية sshkey *کلی, ثابت حرف *allowlist)
{
	إذا (سمون_نمونه_list(sshkey_ssh_name(کلی), allowlist, 0) == 1)
		أرجع 1;

	/* RSA keys/certs might be allowed by alternate signature types */
	بدل (کلی->type) {
	حالة کلی_RSA:
		إذا (سمون_نمونه_list("rsa-sha2-512", allowlist, 0) == 1)
			أرجع 1;
		إذا (سمون_نمونه_list("rsa-sha2-256", allowlist, 0) == 1)
			أرجع 1;
		اكسر;
	حالة کلی_RSA_CERT:
		إذا (سمون_نمونه_list("rsa-sha2-512-cert-v01@openssh.com",
		    allowlist, 0) == 1)
			أرجع 1;
		إذا (سمون_نمونه_list("rsa-sha2-256-cert-v01@openssh.com",
		    allowlist, 0) == 1)
			أرجع 1;
		اكسر;
	}
	أرجع 0;
}

ساكن صحيح
کلی_type_allowed_by_config(بنية sshkey *کلی)
{
	أرجع کلی_type_allowed(کلی, options.pubkey_accepted_algos);
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
cert_has_option(بنية sshbuf *oblob, ثابت حرف *موخه)
{
	بنية sshbuf *c = عدم, *معلومات = عدم;
	حرف *name = عدم;
	صحيح r, وموندل = 0;

	إذا (oblob == عدم || (c = sshbuf_fromb(oblob)) == عدم)
		أرجع 0;
	طالما (sshbuf_len(c) > 0) {
		sshbuf_free(معلومات);
		معلومات = عدم;
		حرر(name);
		name = عدم;
		إذا ((r = sshbuf_get_cstring(c, &name, عدم)) != 0 ||
		    (r = sshbuf_froms(c, &معلومات)) != 0)
			اكسر;
		إذا (strcmp(name, موخه) == 0) {
			وموندل = 1;
			اكسر;
		}
	}
	sshbuf_free(معلومات);
	حرر(name);
	sshbuf_free(c);
	أرجع وموندل;
}

/*
 * Returns an integer describing the priority of the identity
 * within its group. Lower numbers are higher priority.
 */
#تعریف_کړه MAX_ID_لومړیتوب 3
ساكن صحيح
بې_اغېزه_عنصر_prioritise(بنية بې_اغېزه_عنصر_2 *id)
{
	إذا (id == عدم || id->کلی == عدم)
		أرجع 3;
	إذا (!sshkey_is_cert(id->کلی) || id->کلی->cert == عدم)
		أرجع 3;
	إذا (sshkey_is_sk(id->کلی) &&
	    cert_has_option(id->کلی->cert->critical, "verify-required"))
		أرجع 2;
	إذا (sshkey_is_sk(id->کلی) &&
	    cert_has_option(id->کلی->cert->extensions, "no-touch-required"))
		أرجع 0;
	أرجع 1;
}

ساكن فراغ
ترتیب_identities_by_prio(بنية idlist *list)
{
	بنية idlist prio[MAX_ID_لومړیتوب + 1], sorted;
	بنية بې_اغېزه_عنصر_2 *id, *tmp, *dummy;
	صحيح p;

	لكل (p = 0; p <= MAX_ID_لومړیتوب; p++)
		TAILQ_INIT(&prio[p]);
	TAILQ_INIT(&sorted);

	TAILQ_FOREACH_خوندي(id, list, بل, tmp) {
		إذا (id->userprovided)
			استمر;
		dummy = xcalloc(1, حجم(*dummy));
		dummy->userprovided = -1;
		TAILQ_INSERT_BEFORE(id, dummy, بل);
		TAILQ_REMOVE(list, id, بل);
		p = بې_اغېزه_عنصر_prioritise(id);
		إذا (p < 0 || p > MAX_ID_لومړیتوب)
			fatal_f("internal error: bad priority");
		TAILQ_INSERT_TAIL(&prio[p], id, بل);
	}
	لكل (p = 0; p <= MAX_ID_لومړیتوب; p++)
		TAILQ_CONCAT(&sorted, &prio[p], بل);

	TAILQ_FOREACH_خوندي(id, list, بل, tmp) {
		إذا (id->userprovided != -1)
			استمر;
		بنية بې_اغېزه_عنصر_2 *s = TAILQ_FIRST(&sorted);
		TAILQ_REMOVE(&sorted, s, بل);
		TAILQ_INSERT_BEFORE(id, s, بل);
		TAILQ_REMOVE(list, id, بل);
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
	بنية بې_اغېزه_عنصر_2 *id, *id2, *tmp;
	بنية idlist agent, files, certs, agent_کلیګانې, *preferred;
	بنية sshkey *کلی;
	صحيح disallowed, agent_fd = -1, i, r, وموندل;
	اندازه_t j;
	بنية ssh_identitylist *idlist;
	حرف *cp, *ident;

	TAILQ_INIT(&agent);	/* keys from the agent */
	TAILQ_INIT(&files);	/* keys from the config file */
	TAILQ_INIT(&certs);	/* certificates specified by user */
	TAILQ_INIT(&agent_کلیګانې); /* keys supported by the agent */
	preferred = &authctxt->کلیګانې;
	TAILQ_INIT(preferred);	/* preferred order of keys */

	/* list of keys stored in the filesystem and PKCS#11 */
	لكل (i = 0; i < options.عدد_بې_اغېزه_عنصر_files; i++) {
		کلی = options.بې_اغېزه_عنصر_کلیګانې[i];
		إذا (کلی && کلی->cert &&
		    کلی->cert->type != SSH2_CERT_TYPE_USER) {
			debug_f("ignoring certificate %s: not a user "
			    "certificate", options.بې_اغېزه_عنصر_files[i]);
			استمر;
		}
		إذا (کلی && sshkey_is_sk(کلی) && options.sk_provider == عدم) {
			debug_f("ignoring authenticator-hosted key %s as no "
			    "SecurityKeyProvider has been specified",
			    options.بې_اغېزه_عنصر_files[i]);
			استمر;
		}
		options.بې_اغېزه_عنصر_کلیګانې[i] = عدم;
		id = xcalloc(1, حجم(*id));
		id->agent_fd = -1;
		id->کلی = کلی;
		id->filename = xstrdup(options.بې_اغېزه_عنصر_files[i]);
		id->userprovided = options.بې_اغېزه_عنصر_file_userprovided[i];
		TAILQ_INSERT_TAIL(&files, id, بل);
	}

	/* list of certificates specified by user */
	لكل (i = 0; i < options.عدد_certificate_files; i++) {
		کلی = options.certificates[i];
		إذا (!sshkey_is_cert(کلی) || کلی->cert == عدم ||
		    کلی->cert->type != SSH2_CERT_TYPE_USER) {
			debug_f("ignoring certificate %s: not a user "
			    "certificate", options.بې_اغېزه_عنصر_files[i]);
			استمر;
		}
		إذا (کلی && sshkey_is_sk(کلی) && options.sk_provider == عدم) {
			debug_f("ignoring authenticator-hosted key "
			    "certificate %s as no "
			    "SecurityKeyProvider has been specified",
			    options.بې_اغېزه_عنصر_files[i]);
			استمر;
		}
		id = xcalloc(1, حجم(*id));
		id->agent_fd = -1;
		id->کلی = کلی;
		id->filename = xstrdup(options.certificate_files[i]);
		id->userprovided = options.certificate_file_userprovided[i];
		TAILQ_INSERT_TAIL(&certs, id, بل);
	}
	ترتیب_identities_by_prio(&certs);
	TAILQ_CONCAT(preferred, &certs, بل);

	/* list of keys supported by the agent */
	إذا ((r = get_agent_identities(ssh, &agent_fd, &idlist)) == 0) {
		لكل (j = 0; j < idlist->nkeys; j++) {
			إذا ((r = sshkey_check_rsa_اوږدتیا(idlist->کلیګانې[j],
			    options.required_rsa_اندازه)) != 0) {
				debug_fr(r, "ignoring %s agent key",
				    sshkey_ssh_name(idlist->کلیګانې[j]));
				استمر;
			}
			وموندل = 0;
			TAILQ_FOREACH(id, &files, بل) {
				/*
				 * agent keys from the config file are
				 * preferred
				 */
				إذا (sshkey_equal(idlist->کلیګانې[j], id->کلی)) {
					TAILQ_REMOVE(&files, id, بل);
					TAILQ_INSERT_TAIL(&agent_کلیګانې, id, بل);
					id->agent_fd = agent_fd;
					وموندل = 1;
					اكسر;
				}
			}
			إذا (!وموندل && !options.identities_only) {
				id = xcalloc(1, حجم(*id));
				/* XXX "steals" key/comment from idlist */
				id->کلی = idlist->کلیګانې[j];
				id->filename = idlist->comments[j];
				idlist->کلیګانې[j] = عدم;
				idlist->comments[j] = عدم;
				id->agent_fd = agent_fd;
				TAILQ_INSERT_TAIL(&agent, id, بل);
			}
		}
		ssh_free_identitylist(idlist);
		/* append remaining agent keys */
		TAILQ_CONCAT(&agent_کلیګانې, &agent, بل);
		ترتیب_identities_by_prio(&agent_کلیګانې);
		TAILQ_CONCAT(preferred, &agent_کلیګانې, بل);
		authctxt->agent_fd = agent_fd;
	}
	/* Prefer PKCS11 keys that are explicitly listed */
	TAILQ_FOREACH_خوندي(id, &files, بل, tmp) {
		إذا (id->کلی == عدم || (id->کلی->flags & SSHKEY_FLAG_EXT) == 0)
			استمر;
		وموندل = 0;
		TAILQ_FOREACH(id2, &files, بل) {
			إذا (id2->کلی == عدم ||
			    (id2->کلی->flags & SSHKEY_FLAG_EXT) != 0)
				استمر;
			إذا (sshkey_equal(id->کلی, id2->کلی)) {
				TAILQ_REMOVE(&files, id, بل);
				TAILQ_INSERT_TAIL(preferred, id, بل);
				وموندل = 1;
				اكسر;
			}
		}
		/* If IdentitiesOnly set and key not found then don't use it */
		إذا (!وموندل && options.identities_only) {
			TAILQ_REMOVE(&files, id, بل);
			freezero(id, حجم(*id));
		}
	}
	ترتیب_identities_by_prio(&files);
	/* append remaining keys from the config file */
	TAILQ_CONCAT(preferred, &files, بل);
	/* finally, filter by PubkeyAcceptedAlgorithms */
	TAILQ_FOREACH_خوندي(id, preferred, بل, id2) {
		disallowed = 0;
		cp = عدم;
		إذا (id->کلی == عدم)
			استمر;
		إذا (!کلی_type_allowed_by_config(id->کلی)) {
			debug("Skipping %s key %s - corresponding algorithm "
			    "not in PubkeyAcceptedAlgorithms",
			    sshkey_ssh_name(id->کلی), id->filename);
			disallowed = 1;
		} وإلا إذا (ssh != عدم && ssh->kex != عدم &&
		    ssh->kex->server_sig_algs != عدم &&
		    (cp = کلی_sig_algorithm(ssh, id->کلی)) == عدم) {
			debug("Skipping %s key %s - corresponding algorithm "
			    "not supported by server",
			    sshkey_ssh_name(id->کلی), id->filename);
			disallowed = 1;
		}
		حرر(cp);
		إذا (!disallowed)
			استمر;
		/* remove key */
		TAILQ_REMOVE(preferred, id, بل);
		sshkey_free(id->کلی);
		حرر(id->filename);
		freezero(id, حجم(*id));
	}
	/* List the keys we plan on using */
	TAILQ_FOREACH_خوندي(id, preferred, بل, id2) {
		ident = format_بې_اغېزه_عنصر(id);
		debug("Will attempt key: %s", ident);
		حرر(ident);
	}
	debug2_f("done");
}

ساكن فراغ
pubkey_cleanup(بنية ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	بې_اغېزه_عنصر *id;

	إذا (authctxt->agent_fd != -1) {
		ssh_close_authentication_socket(authctxt->agent_fd);
		authctxt->agent_fd = -1;
	}
	لكل (id = TAILQ_FIRST(&authctxt->کلیګانې); id;
	    id = TAILQ_FIRST(&authctxt->کلیګانې)) {
		TAILQ_REMOVE(&authctxt->کلیګانې, id, بل);
		sshkey_free(id->کلی);
		حرر(id->filename);
		حرر(id);
	}
}

فراغ
pubkey_dump(بنية ssh *ssh)
{
	Authctxt authctxt;
	بې_اغېزه_عنصر *id;
	حرف *ident;

	memset(&authctxt, 0, حجم(authctxt));
	authctxt.agent_fd = -1;
	ssh->authctxt = &authctxt;

	pubkey_prepare(ssh, &authctxt);
	TAILQ_FOREACH(id, &authctxt.کلیګانې, بل) {
		ident = format_بې_اغېزه_عنصر(id);
		fprintf(stdout, "%s\n", ident);
		حرر(ident);
	}
	pubkey_cleanup(ssh);
	ssh->authctxt = عدم;
}

ساكن فراغ
pubkey_reset(Authctxt *authctxt)
{
	بې_اغېزه_عنصر *id;

	TAILQ_FOREACH(id, &authctxt->کلیګانې, بل)
		id->tried = 0;
}

ساكن صحيح
userauth_pubkey(بنية ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	بې_اغېزه_عنصر *id;
	صحيح لېږل_شوی = 0;
	حرف *ident;
	ساكن صحيح prepared;

	إذا (!prepared) {
		pubkey_prepare(ssh, authctxt);
		prepared = 1;
	}

	طالما ((id = TAILQ_FIRST(&authctxt->کلیګانې))) {
		إذا (id->tried++)
			أرجع (0);
		/* move key to the end of the queue */
		TAILQ_REMOVE(&authctxt->کلیګانې, id, بل);
		TAILQ_INSERT_TAIL(&authctxt->کلیګانې, id, بل);
		/*
		 * send a test message if we have the public key. for
		 * encrypted keys we cannot do this and have to load the
		 * private key instead
		 */
		إذا (id->کلی != عدم) {
			ident = format_بې_اغېزه_عنصر(id);
			debug("Offering public key: %s", ident);
			حرر(ident);
			لېږل_شوی = send_pubkey_test(ssh, id);
		} وإلا {
			debug("Trying private key: %s", id->filename);
			id->کلی = بارول_بې_اغېزه_عنصر_file(id);
			إذا (id->کلی != عدم) {
				id->isprivate = 1;
				لېږل_شوی = sign_and_send_pubkey(ssh, id);
				sshkey_free(id->کلی);
				id->کلی = عدم;
				id->isprivate = 0;
			}
		}
		إذا (لېږل_شوی)
			أرجع (لېږل_شوی);
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

	إذا (authctxt->attempt_kbdint++ >= options.شمېره_د_password_prompts)
		أرجع 0;
	/* disable if no SSH2_MSG_USERAUTH_INFO_REQUEST has been seen */
	إذا (authctxt->attempt_kbdint > 1 && !authctxt->info_req_کتل_شوی) {
		debug3("userauth_kbdint: disable: no info_req_seen");
		ssh_dispatch_سېټ(ssh, SSH2_پیغام_USERAUTH_INFO_REQUEST, عدم);
		أرجع 0;
	}

	debug2("userauth_kbdint");
	إذا ((r = sshpkt_پیل(ssh, SSH2_پیغام_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->لاره->name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||		/* lang */
	    (r = sshpkt_put_cstring(ssh, options.kbd_interactive_devices ?
	    options.kbd_interactive_devices : "")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh_dispatch_سېټ(ssh, SSH2_پیغام_USERAUTH_INFO_REQUEST, &ننوت_userauth_info_req);
	أرجع 1;
}

/*
 * parse INFO_REQUEST, prompt user and send INFO_RESPONSE
 */
ساكن صحيح
ننوت_userauth_info_req(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	حرف *name = عدم, *inst = عدم, *lang = عدم, *prompt = عدم;
	حرف *display_prompt = عدم, *response = عدم;
	u_char echo = 0;
	u_int عدد_prompts, i;
	صحيح r, addnl;
	اندازه_t len;

	debug2_f("entering");

	إذا (authctxt == عدم)
		fatal_f("no authentication context");

	authctxt->info_req_کتل_شوی = 1;

	إذا ((r = sshpkt_get_cstring(ssh, &name, عدم)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &inst, عدم)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, عدم)) != 0)
		اذهب بهر;
	إذا ((len = مزي_اوږدوالی(name)) > 0) {
		addnl = name[len] != '\n';
		fmprintf(stderr, "%s%s", name, addnl ? "\n" : "");
	}
	إذا ((len = مزي_اوږدوالی(inst)) > 0) {
		addnl = inst[len] != '\n';
		fmprintf(stderr, "%s%s", inst, addnl ? "\n" : "");
	}

	إذا ((r = sshpkt_get_u32(ssh, &عدد_prompts)) != 0)
		اذهب بهر;
	/*
	 * Begin to build info response packet based on prompts requested.
	 * We commit to providing the correct number of responses, so if
	 * further on we run into a problem that prevents this, we have to
	 * be sure and clean this up and send a correct error response.
	 */
	إذا ((r = sshpkt_پیل(ssh, SSH2_پیغام_USERAUTH_INFO_RESPONSE)) != 0 ||
	    (r = sshpkt_put_u32(ssh, عدد_prompts)) != 0)
		اذهب بهر;

	debug2_f("num_prompts %d", عدد_prompts);
	لكل (i = 0; i < عدد_prompts; i++) {
		إذا ((r = sshpkt_get_cstring(ssh, &prompt, عدم)) != 0 ||
		    (r = sshpkt_get_u8(ssh, &echo)) != 0)
			اذهب بهر;
		إذا (asmprintf(&display_prompt, لوی_عدد, عدم, "(%s@%s) %s",
		    authctxt->server_user, options.host_کلی_alias ?
		    options.host_کلی_alias : authctxt->host, prompt) == -1)
			fatal_f("asmprintf failed");
		response = read_passphrase(display_prompt, echo ? RP_ECHO : 0);
		إذا ((r = sshpkt_put_cstring(ssh, response)) != 0)
			اذهب بهر;
		freezero(response, مزي_اوږدوالی(response));
		حرر(prompt);
		حرر(display_prompt);
		display_prompt = response = prompt = عدم;
	}
	/* done with parsing incoming message. */
	إذا ((r = sshpkt_get_پای_ټکی(ssh)) != 0 ||
	    (r = sshpkt_جمع_کړه_padding(ssh, 64)) != 0)
		اذهب بهر;
	r = sshpkt_send(ssh);
 بهر:
	إذا (response)
		freezero(response, مزي_اوږدوالی(response));
	حرر(prompt);
	حرر(display_prompt);
	حرر(name);
	حرر(inst);
	حرر(lang);
	أرجع r;
}

ساكن صحيح
ssh_keysign(بنية ssh *ssh, بنية sshkey *کلی, u_char **sigp, اندازه_t *lenp,
    ثابت u_char *معلومات, اندازه_t datalen)
{
	بنية sshbuf *b;
	بنية stat st;
	pid_t pid;
	صحيح r, منزل[2], from[2], حالت;
	صحيح sock = ssh_packet_get_connection_دننه(ssh);
	u_char rversion = 0, نسخه = 2;
	فراغ (*osigchld)(صحيح);

	*sigp = عدم;
	*lenp = 0;

	إذا (stat(لار_SSH_کلی_SIGN, &st) == -1) {
		error_f("not installed: %s", strerror(errno));
		أرجع -1;
	}
	إذا (fflush(stdout) != 0) {
		error_f("fflush: %s", strerror(errno));
		أرجع -1;
	}
	إذا (pipe(منزل) == -1) {
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
		close(منزل[1]);
		إذا (dup2(منزل[0], STDIN_FILENO) == -1)
			fatal_f("dup2: %s", strerror(errno));
		close(from[1]);
		close(منزل[0]);

		إذا (dup2(sock, STDERR_FILENO + 1) == -1)
			fatal_f("dup2: %s", strerror(errno));
		sock = STDERR_FILENO + 1;
		إذا (fcntl(sock, F_SETFD, 0) == -1) /* keep the socket on exec */
			debug3_f("fcntl F_SETFD: %s", strerror(errno));
		closefrom(sock + 1);

		debug3_f("[child] pid=%ld, exec %s",
		    (اوږد)getpid(), لار_SSH_کلی_SIGN);
		execl(لار_SSH_کلی_SIGN, لار_SSH_کلی_SIGN, (حرف *)عدم);
		fatal_f("exec(%s): %s", لار_SSH_کلی_SIGN,
		    strerror(errno));
	}
	close(from[1]);
	close(منزل[0]);
	sock = STDERR_FILENO + 1;

	إذا ((b = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	/* send # of sock, data to be signed */
	إذا ((r = sshbuf_put_u32(b, sock)) != 0 ||
	    (r = sshbuf_put_string(b, معلومات, datalen)) != 0)
		fatal_fr(r, "buffer error");
	إذا (ssh_پیغام_send(منزل[1], نسخه, b) == -1)
		fatal_f("couldn't send request");
	sshbuf_reset(b);
	r = ssh_پیغام_recv(from[0], b);
	close(from[0]);
	close(منزل[1]);
	إذا (r < 0) {
		error_f("no reply");
		اذهب fail;
	}

	errno = 0;
	طالما (waitpid(pid, &حالت, 0) == -1) {
		إذا (errno != EINTR) {
			error_f("waitpid %ld: %s", (اوږد)pid, strerror(errno));
			اذهب fail;
		}
	}
	إذا (!WIFEXITED(حالت)) {
		error_f("exited abnormally");
		اذهب fail;
	}
	إذا (WEXITSTATUS(حالت) != 0) {
		error_f("exited with status %d", WEXITSTATUS(حالت));
		اذهب fail;
	}
	إذا ((r = sshbuf_get_u8(b, &rversion)) != 0) {
		error_fr(r, "buffer error");
		اذهب fail;
	}
	إذا (rversion != نسخه) {
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
	اندازه_t siglen = 0, keylen = 0;
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
		إذا (authctxt->فعال_ktype == عدم)
			authctxt->فعال_ktype = strsep(&authctxt->ktypes, ",");
		إذا (authctxt->فعال_ktype == عدم ||
		    *authctxt->فعال_ktype == '\0')
			اكسر;
		debug3_f("trying key type %s", authctxt->فعال_ktype);

		/* check for a useful key */
		خاص = عدم;
		لكل (i = 0; i < authctxt->sensitive->nkeys; i++) {
			إذا (authctxt->sensitive->کلیګانې[i] == عدم ||
			    authctxt->sensitive->کلیګانې[i]->type == کلی_UNSPEC)
				استمر;
			إذا (!sshkey_سمون_keyname_منزل_sigalgs(
			    sshkey_ssh_name(authctxt->sensitive->کلیګانې[i]),
			    authctxt->فعال_ktype))
				استمر;
			/* we take and free the key */
			خاص = authctxt->sensitive->کلیګانې[i];
			authctxt->sensitive->کلیګانې[i] = عدم;
			اكسر;
		}
		/* Found one */
		إذا (خاص != عدم)
			اكسر;
		/* No more keys of this type; advance */
		authctxt->فعال_ktype = عدم;
	}
	إذا (خاص == عدم) {
		حرر(authctxt->oktypes);
		authctxt->oktypes = authctxt->ktypes = عدم;
		authctxt->فعال_ktype = عدم;
		debug("No more client hostkeys for hostbased authentication.");
		اذهب بهر;
	}

	إذا ((fp = sshkey_fingerprint(خاص, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == عدم) {
		error_f("sshkey_fingerprint failed");
		اذهب بهر;
	}
	debug_f("trying hostkey %s %s using sigalg %s",
	    sshkey_ssh_name(خاص), fp, authctxt->فعال_ktype);

	/* figure out a name for the client host */
	lname = get_local_name(ssh_packet_get_connection_دننه(ssh));
	إذا (lname == عدم) {
		error_f("cannot get local ipaddr/name");
		اذهب بهر;
	}

	/* XXX sshbuf_put_stringf? */
	xasprintf(&chost, "%s.", lname);
	debug2_f("chost %s", chost);

	/* construct data */
	إذا ((b = sshbuf_new()) == عدم) {
		error_f("sshbuf_new failed");
		اذهب بهر;
	}
	إذا ((r = sshkey_منزل_blob(خاص, &keyblob, &keylen)) != 0) {
		error_fr(r, "sshkey_to_blob");
		اذهب بهر;
	}
	إذا ((r = sshbuf_put_stringb(b, ssh->kex->session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_پیغام_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->server_user)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->لاره->name)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->فعال_ktype)) != 0 ||
	    (r = sshbuf_put_string(b, keyblob, keylen)) != 0 ||
	    (r = sshbuf_put_cstring(b, chost)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->local_user)) != 0) {
		error_fr(r, "buffer error");
		اذهب بهر;
	}

#که_تعریف_شوی DEBUG_PK
	sshbuf_dump(b, stderr);
#د_که_پای
	إذا ((r = ssh_keysign(ssh, خاص, &sig, &siglen,
	    sshbuf_ptr(b), sshbuf_len(b))) != 0) {
		error("sign using hostkey %s %s failed",
		    sshkey_ssh_name(خاص), fp);
		اذهب بهر;
	}
	إذا ((r = sshpkt_پیل(ssh, SSH2_پیغام_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->لاره->name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->فعال_ktype)) != 0 ||
	    (r = sshpkt_put_string(ssh, keyblob, keylen)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, chost)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->local_user)) != 0 ||
	    (r = sshpkt_put_string(ssh, sig, siglen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_fr(r, "packet error");
		اذهب بهر;
	}
	success = 1;

 بهر:
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
authmethod_is_enabled(Authmethod *لاره)
{
	إذا (لاره == عدم)
		أرجع 0;
	/* return false if options indicate this method is disabled */
	إذا  (لاره->enabled == عدم || *لاره->enabled == 0)
		أرجع 0;
	/* return false if batch mode is enabled but method needs interactive mode */
	إذا  (لاره->batch_flag != عدم && *لاره->batch_flag != 0)
		أرجع 0;
	أرجع 1;
}

ساكن Authmethod *
authmethod_lookup(ثابت حرف *name)
{
	Authmethod *لاره = عدم;
	إذا (name != عدم)
		لكل (لاره = authmethods; لاره->name != عدم; لاره++)
			إذا (strcmp(name, لاره->name) == 0)
				أرجع لاره;
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
	u_int بل;

	/* Use a suitable default if we're passed a nil list.  */
	إذا (authlist == عدم || مزي_اوږدوالی(authlist) == 0)
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
		إذا ((name = سمون_list(preferred, supported, &بل)) == عدم) {
			debug("No more authentication methods to try.");
			current = عدم;
			أرجع عدم;
		}
		preferred += بل;
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
	Authmethod *لاره = عدم;
	بنية sshbuf *b;
	حرف *list;
	صحيح r;

	إذا ((b = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	لكل (لاره = authmethods; لاره->name != عدم; لاره++) {
		إذا (authmethod_is_enabled(لاره)) {
			إذا ((r = sshbuf_putf(b, "%s%s",
			    sshbuf_len(b) ? "," : "", لاره->name)) != 0)
				fatal_fr(r, "buffer error");
		}
	}
	إذا ((list = sshbuf_dup_string(b)) == عدم)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	أرجع list;
}
