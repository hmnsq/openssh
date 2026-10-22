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
#اگر_ختم

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

#اگر_تعریف_شدہ GSSAPI
#شامل "ssh-gss.h"
#اگر_ختم

/* import */
خارجی Options options;

/*
 * SSH2 key exchange
 */

ساکن حرف *xxx_host;
ساکن ساخت sockaddr_storage xxx_hostaddr;
ساکن ثابت ساخت ssh_conn_info *xxx_conn_info;
ساکن صحیح کلید_type_allowed(ساخت sshkey *, ثابت حرف *);

ساکن صحیح
verify_host_کلید_callback(ساخت sshkey *hostkey, ساخت ssh *ssh)
{
	صحیح r;

	اگر ((r = sshkey_check_rsa_لمبائی(hostkey,
	    options.required_rsa_سائز)) != 0)
		fatal_r(r, "Bad server host key");
	اگر (!کلید_type_allowed(hostkey, options.hostkeyalgorithms)) {
		fatal("Server host key %s not in HostKeyAlgorithms",
		    sshkey_ssh_name(hostkey));
	}
	اگر (verify_host_کلید(xxx_host, (ساخت sockaddr *)&xxx_hostaddr, hostkey,
	    xxx_conn_info) != 0)
		fatal("Host key verification failed.");
	واپس 0;
}

/* Returns the first item from a comma-separated algorithm list */
ساکن حرف *
پہلا_alg(ثابت حرف *algs)
{
	حرف *ret, *cp;

	ret = xstrdup(algs);
	اگر ((cp = strchr(ret, ',')) != تہی)
		*cp = '\0';
	واپس ret;
}

ساکن حرف *
ترتیب_hostkeyalgs(حرف *host, ساخت sockaddr *hostaddr, u_short پورٹ,
    ثابت ساخت ssh_conn_info *cinfo)
{
	حرف *oavail = تہی, *avail = تہی, *پہلا = تہی, *آخری = تہی;
	حرف *alg = تہی, *hostname = تہی, *ret = تہی, *بہترین = تہی;
	سائز_t maxlen;
	ساخت hostkeys *hostkeys = تہی;
	صحیح ktype;
	u_int i;

	/* Find all hostkeys for this hostname */
	get_hostfile_hostname_ipaddr(host, hostaddr, پورٹ, &hostname, تہی);
	hostkeys = init_hostkeys();
	برائے (i = 0; i < options.عدد_user_hostfiles; i++)
		بھرو_hostkeys(hostkeys, hostname, options.user_hostfiles[i], 0);
	برائے (i = 0; i < options.عدد_system_hostfiles; i++) {
		بھرو_hostkeys(hostkeys, hostname,
		    options.system_hostfiles[i], 0);
	}
	اگر (options.معلوم_hosts_command != تہی) {
		بھرو_hostkeys_command(hostkeys, options.معلوم_hosts_command,
		    "ORDER", cinfo, تہی, hostname);
	}
	/*
	 * If a plain public key exists that matches the type of the best
	 * preference HostkeyAlgorithms, then use the whole list as is.
	 * Note that we ignore whether the best preference algorithm is a
	 * certificate type, as sshconnect.c will downgrade certs to
	 * plain keys if necessary.
	 */
	بہترین = پہلا_alg(options.hostkeyalgorithms);
	اگر (lookup_کلید_اندر_hostkeys_by_type(hostkeys,
	    sshkey_type_plain(sshkey_type_from_name(بہترین)),
	    sshkey_ecdsa_nid_from_name(بہترین), تہی)) {
		debug3_f("have matching best-preference key type %s, "
		    "using HostkeyAlgorithms verbatim", بہترین);
		ret = xstrdup(options.hostkeyalgorithms);
		جاؤ برآمد;
	}

	/*
	 * Otherwise, prefer the host key algorithms that match known keys
	 * while keeping the ordering of HostkeyAlgorithms as much as possible.
	 */
	oavail = avail = xstrdup(options.hostkeyalgorithms);
	maxlen = لڑی_لمبائی(avail) + 1;
	پہلا = xmalloc(maxlen);
	آخری = xmalloc(maxlen);
	*پہلا = *آخری = '\0';

#تعریف_کرو ALG_APPEND(مقصد, from) \
	کرو { \
		اگر (*مقصد != '\0') \
			strlcat(مقصد, ",", maxlen); \
		strlcat(مقصد, from, maxlen); \
	} جب (0)

	جب ((alg = strsep(&avail, ",")) && *alg != '\0') {
		اگر ((ktype = sshkey_type_from_name(alg)) == کلید_UNSPEC)
			fatal_f("unknown alg %s", alg);
		/*
		 * If we have a @cert-authority marker in known_hosts then
		 * prefer all certificate algorithms.
		 */
		اگر (sshkey_type_is_cert(ktype) &&
		    lookup_marker_اندر_hostkeys(hostkeys, MRK_CA)) {
			ALG_APPEND(پہلا, alg);
			جاری;
		}
		/* If the key appears in known_hosts then prefer it */
		اگر (lookup_کلید_اندر_hostkeys_by_type(hostkeys,
		    sshkey_type_plain(ktype),
		    sshkey_ecdsa_nid_from_name(alg), تہی)) {
			ALG_APPEND(پہلا, alg);
			جاری;
		}
		/* Otherwise, put it last */
		ALG_APPEND(آخری, alg);
	}
#تعریف_منسوخ ALG_APPEND
	xasprintf(&ret, "%s%s%s", پہلا,
	    (*پہلا == '\0' || *آخری == '\0') ? "" : ",", آخری);
	اگر (*پہلا != '\0')
		debug3_f("prefer hostkeyalgs: %s", پہلا);
	ورنہ
		debug3_f("no algorithms matched; accept original");
 برآمد:
	آزاد(بہترین);
	آزاد(پہلا);
	آزاد(آخری);
	آزاد(hostname);
	آزاد(oavail);
	free_hostkeys(hostkeys);

	واپس ret;
}

خالی
ssh_kex2(ساخت ssh *ssh, حرف *host, ساخت sockaddr_storage *hostaddr,
    u_short پورٹ, ثابت ساخت ssh_conn_info *cinfo)
{
	حرف *myproposal[PROPOSAL_MAX];
	حرف *all_کلید, *hkalgs = تہی;
	صحیح r, use_معلوم_hosts_ترتیب = 0;

	xxx_host = xstrdup(host);
	xxx_hostaddr = *hostaddr;
	xxx_conn_info = ssh_conn_info_dup(cinfo);

	ssh_packet_سیٹ_rekey_limits(ssh, options.rekey_حد_بندی,
	    options.rekey_interval);

	/*
	 * If the user has not specified HostkeyAlgorithms, or has only
	 * appended or removed algorithms from that list then prefer algorithms
	 * that are in the list that are supported by known_hosts keys.
	 */
	اگر (options.hostkeyalgorithms == تہی ||
	    options.hostkeyalgorithms[0] == '-' ||
	    options.hostkeyalgorithms[0] == '+')
		use_معلوم_hosts_ترتیب = 1;

	/* Expand or fill in HostkeyAlgorithms */
	all_کلید = sshkey_alg_list(0, 0, 1, ',');
	اگر ((r = kex_assemble_نام(&options.hostkeyalgorithms,
	    kex_default_pk_alg(), all_کلید)) != 0)
		fatal_fr(r, "kex_assemble_namelist");
	آزاد(all_کلید);

	اگر (use_معلوم_hosts_ترتیب) {
		hkalgs = ترتیب_hostkeyalgs(host, (ساخت sockaddr *)hostaddr,
		    پورٹ, cinfo);
	}

	kex_proposal_populate_entries(ssh, myproposal,
	    options.kex_algorithms, options.ciphers, options.macs,
	    compression_alg_list(options.compression),
	    hkalgs ? hkalgs : options.hostkeyalgorithms);

	آزاد(hkalgs);

	/* start key exchange */
	اگر ((r = kex_تیاری(ssh, myproposal)) != 0)
		fatal_r(r, "kex_setup");
#اگر_تعریف_شدہ WITH_OPENSSL
	ssh->kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GEX_SHA1] = kexgex_client;
	ssh->kex->kex[KEX_DH_GEX_SHA256] = kexgex_client;
	ssh->kex->kex[KEX_ECDH_SHA2] = kex_gen_client;
#اگر_ختم
	ssh->kex->kex[KEX_C25519_SHA256] = kex_gen_client;
	ssh->kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_client;
	ssh->kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_client;
	ssh->kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_client;
	ssh->kex->verify_host_کلید=&verify_host_کلید_callback;

	ssh_dispatch_تسلسل_fatal(ssh, DISPATCH_بلاک, &ssh->kex->مکمل);
	kex_proposal_free_entries(myproposal);

#اگر_تعریف_شدہ DEBUG_KEXDH
	/* send 1st encrypted/maced/compressed message */
	اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_IGNORE)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "markus")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send packet");
#اگر_ختم
}

/*
 * Authenticate user
 */

قسمتعریف ساخت cauthctxt Authctxt;
قسمتعریف ساخت cauthmethod Authmethod;
قسمتعریف ساخت شناختی_عنصر_2 شناختی_عنصر;
قسمتعریف ساخت idlist Idlist;

ساخت شناختی_عنصر_2 {
	TAILQ_ENTRY(شناختی_عنصر_2) اگلا;
	صحیح	agent_fd;		/* >=0 if agent supports key */
	ساخت sshkey	*کلید;		/* public/private key */
	حرف	*filename;		/* comment for agent-only keys */
	صحیح	tried;
	صحیح	isprivate;		/* key points to the private key */
	صحیح	userprovided;
};
TAILQ_HEAD(idlist, شناختی_عنصر_2);

ساخت cauthctxt {
	ثابت حرف *server_user;
	ثابت حرف *local_user;
	ثابت حرف *host;
	ثابت حرف *service;
	ساخت cauthmethod *طریقہ;
	sig_atomic_t success;
	حرف *authlist;
#اگر_تعریف_شدہ GSSAPI
	/* gssapi */
	gss_OID_سیٹ gss_supported_mechs;
	u_int mech_tried;
#اگر_ختم
	/* pubkey */
	ساخت idlist کلیدیں;
	صحیح agent_fd;
	/* hostbased */
	Sensitive *sensitive;
	حرف *oktypes, *ktypes;
	ثابت حرف *فعال_ktype;
	/* kbd-interactive */
	صحیح info_req_نظر_آیا;
	صحیح attempt_kbdint;
	/* password */
	صحیح attempt_passwd;
	/* generic */
	خالی *methoddata;
};

ساخت cauthmethod {
	حرف	*name;		/* string to compare against server's list */
	صحیح	(*userauth)(ساخت ssh *ssh);
	خالی	(*cleanup)(ساخت ssh *ssh);
	صحیح	*enabled;	/* flag in option struct that enables method */
	صحیح	*batch_flag;	/* flag in option struct that disables method */
};

ساکن صحیح داخلہ_userauth_service_accept(صحیح, uint32_t, ساخت ssh *);
ساکن صحیح داخلہ_userauth_success(صحیح, uint32_t, ساخت ssh *);
ساکن صحیح داخلہ_userauth_failure(صحیح, uint32_t, ساخت ssh *);
ساکن صحیح داخلہ_userauth_banner(صحیح, uint32_t, ساخت ssh *);
ساکن صحیح داخلہ_userauth_error(صحیح, uint32_t, ساخت ssh *);
ساکن صحیح داخلہ_userauth_info_req(صحیح, uint32_t, ساخت ssh *);
ساکن صحیح داخلہ_userauth_pk_ok(صحیح, uint32_t, ساخت ssh *);
ساکن صحیح داخلہ_userauth_passwd_changereq(صحیح, uint32_t, ساخت ssh *);

ساکن صحیح userauth_none(ساخت ssh *);
ساکن صحیح userauth_pubkey(ساخت ssh *);
ساکن صحیح userauth_passwd(ساخت ssh *);
ساکن صحیح userauth_kbdint(ساخت ssh *);
ساکن صحیح userauth_hostbased(ساخت ssh *);

#اگر_تعریف_شدہ GSSAPI
ساکن صحیح userauth_gssapi(ساخت ssh *);
ساکن خالی userauth_gssapi_cleanup(ساخت ssh *);
ساکن صحیح داخلہ_gssapi_response(صحیح type, uint32_t, ساخت ssh *);
ساکن صحیح داخلہ_gssapi_token(صحیح type, uint32_t, ساخت ssh *);
ساکن صحیح داخلہ_gssapi_error(صحیح, uint32_t, ساخت ssh *);
ساکن صحیح داخلہ_gssapi_errtok(صحیح, uint32_t, ساخت ssh *);
#اگر_ختم

خالی	userauth(ساخت ssh *, حرف *);

ساکن خالی pubkey_cleanup(ساخت ssh *);
ساکن صحیح sign_and_send_pubkey(ساخت ssh *ssh, شناختی_عنصر *);
ساکن خالی pubkey_prepare(ساخت ssh *, Authctxt *);
ساکن خالی pubkey_reset(Authctxt *);
ساکن ساخت sshkey *بھرو_شناختی_عنصر_file(شناختی_عنصر *);

ساکن Authmethod *authmethod_get(حرف *authlist);
ساکن Authmethod *authmethod_lookup(ثابت حرف *name);
ساکن حرف *authmethods_get(خالی);

Authmethod authmethods[] = {
#اگر_تعریف_شدہ GSSAPI
	{"gssapi-with-mic",
		userauth_gssapi,
		userauth_gssapi_cleanup,
		&options.gss_authentication,
		تہی},
#اگر_ختم
	{"hostbased",
		userauth_hostbased,
		تہی,
		&options.hostbased_authentication,
		تہی},
	{"publickey",
		userauth_pubkey,
		تہی,
		&options.pubkey_authentication,
		تہی},
	{"keyboard-interactive",
		userauth_kbdint,
		تہی,
		&options.kbd_interactive_authentication,
		&options.batch_منوال},
	{"password",
		userauth_passwd,
		تہی,
		&options.password_authentication,
		&options.batch_منوال},
	{"none",
		userauth_none,
		تہی,
		تہی,
		تہی},
	{تہی, تہی, تہی, تہی, تہی}
};

خالی
ssh_userauth2(ساخت ssh *ssh, ثابت حرف *local_user,
    ثابت حرف *server_user, حرف *host, Sensitive *sensitive)
{
	Authctxt authctxt;
	صحیح r;

	اگر (options.preferred_authentications == تہی)
		options.preferred_authentications = authmethods_get();

	/* setup authentication context */
	memset(&authctxt, 0, حجم(authctxt));
	authctxt.server_user = server_user;
	authctxt.local_user = local_user;
	authctxt.host = host;
	authctxt.service = "ssh-connection";		/* service name */
	authctxt.success = 0;
	authctxt.طریقہ = authmethod_lookup("none");
	authctxt.authlist = تہی;
	authctxt.methoddata = تہی;
	authctxt.sensitive = sensitive;
	authctxt.فعال_ktype = authctxt.oktypes = authctxt.ktypes = تہی;
	authctxt.info_req_نظر_آیا = 0;
	authctxt.attempt_kbdint = 0;
	authctxt.attempt_passwd = 0;
#اگر GSSAPI
	authctxt.gss_supported_mechs = تہی;
	authctxt.mech_tried = 0;
#اگر_ختم
	authctxt.agent_fd = -1;
	اگر (authctxt.طریقہ == تہی)
		fatal_f("internal error: cannot send userauth none request");

	اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_SERVICE_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "ssh-userauth")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh->authctxt = &authctxt;
	ssh_dispatch_init(ssh, &داخلہ_userauth_error);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_EXT_INFO, kex_داخلہ_ext_info);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_SERVICE_ACCEPT, &داخلہ_userauth_service_accept);
	ssh_dispatch_تسلسل_fatal(ssh, DISPATCH_بلاک, &authctxt.success);	/* loop until success */
	pubkey_cleanup(ssh);
#اگر_تعریف_شدہ GSSAPI
	اگر (authctxt.gss_supported_mechs != تہی) {
		u_int ms;

		gss_release_oid_سیٹ(&ms, &authctxt.gss_supported_mechs);
		authctxt.gss_supported_mechs = تہی;
	}
#اگر_ختم
	ssh->authctxt = تہی;

	ssh_dispatch_range(ssh, SSH2_پیغام_USERAUTH_MIN, SSH2_پیغام_USERAUTH_MAX, تہی);

	اگر (!authctxt.success)
		fatal("Authentication failed.");
	اگر (ssh_packet_connection_is_on_socket(ssh)) {
		verbose("Authenticated to %s ([%s]:%d) using \"%s\".", host,
		    ssh_remote_ipaddr(ssh), ssh_remote_پورٹ(ssh),
		    authctxt.طریقہ->name);
	} ورنہ {
		verbose("Authenticated to %s (via proxy) using \"%s\".", host,
		    authctxt.طریقہ->name);
	}
}

ساکن صحیح
داخلہ_userauth_service_accept(صحیح type, uint32_t seq, ساخت ssh *ssh)
{
	صحیح r;

	اگر (ssh_packet_بقایا(ssh) > 0) {
		حرف *جواب;

		اگر ((r = sshpkt_get_cstring(ssh, &جواب, تہی)) != 0)
			جاؤ برآمد;
		debug2("service_accept: %s", جواب);
		آزاد(جواب);
	} ورنہ {
		debug2("buggy server: service_accept w/o service");
	}
	اگر ((r = sshpkt_get_انتہا(ssh)) != 0)
		جاؤ برآمد;
	debug("SSH2_MSG_SERVICE_ACCEPT received");

	/* initial userauth request */
	userauth_none(ssh);

	/* accept EXT_INFO at any time during userauth */
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_EXT_INFO, ssh->kex->ext_info_s ?
	    &kex_داخلہ_ext_info : &داخلہ_userauth_error);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_SUCCESS, &داخلہ_userauth_success);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_FAILURE, &داخلہ_userauth_failure);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_BANNER, &داخلہ_userauth_banner);
	r = 0;
 برآمد:
	واپس r;
}

خالی
userauth(ساخت ssh *ssh, حرف *authlist)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;

	اگر (authctxt->طریقہ != تہی && authctxt->طریقہ->cleanup != تہی)
		authctxt->طریقہ->cleanup(ssh);

	آزاد(authctxt->methoddata);
	authctxt->methoddata = تہی;
	اگر (authlist == تہی) {
		authlist = authctxt->authlist;
	} ورنہ {
		آزاد(authctxt->authlist);
		authctxt->authlist = authlist;
	}
	برائے (;;) {
		Authmethod *طریقہ = authmethod_get(authlist);
		اگر (طریقہ == تہی)
			fatal("%s@%s: Permission denied (%s).",
			    authctxt->server_user, authctxt->host, authlist);
		authctxt->طریقہ = طریقہ;

		/* reset the per method handler */
		ssh_dispatch_range(ssh, SSH2_پیغام_USERAUTH_فی_طریقہ_MIN,
		    SSH2_پیغام_USERAUTH_فی_طریقہ_MAX, تہی);

		/* and try new method */
		اگر (طریقہ->userauth(ssh) != 0) {
			debug2("we sent a %s packet, wait for reply", طریقہ->name);
			توڑو;
		} ورنہ {
			debug2("we did not send a packet, disable method");
			طریقہ->enabled = تہی;
		}
	}
}

ساکن صحیح
داخلہ_userauth_error(صحیح type, uint32_t seq, ساخت ssh *ssh)
{
	fatal_f("bad message during authentication: type %d", type);
	واپس 0;
}

ساکن صحیح
داخلہ_userauth_banner(صحیح type, uint32_t seq, ساخت ssh *ssh)
{
	حرف *پیغام = تہی;
	سائز_t len;
	صحیح r;

	debug3_f("entering");
	اگر ((r = sshpkt_get_cstring(ssh, &پیغام, &len)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, تہی, تہی)) != 0)
		جاؤ برآمد;
	اگر (len > 0 && options.log_level >= SYSLOG_LEVEL_INFO)
		fmprintf(stderr, "%s", پیغام);
	r = 0;
 برآمد:
	آزاد(پیغام);
	واپس r;
}

ساکن صحیح
داخلہ_userauth_success(صحیح type, uint32_t seq, ساخت ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	اگر (authctxt == تہی)
		fatal_f("no authentication context");
	آزاد(authctxt->authlist);
	authctxt->authlist = تہی;
	اگر (authctxt->طریقہ != تہی && authctxt->طریقہ->cleanup != تہی)
		authctxt->طریقہ->cleanup(ssh);
	آزاد(authctxt->methoddata);
	authctxt->methoddata = تہی;
	authctxt->success = 1;			/* break out */
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_EXT_INFO, dispatch_protocol_error);
	واپس 0;
}

#اگر 0
ساکن صحیح
داخلہ_userauth_success_unexpected(صحیح type, uint32_t seq, ساخت ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	اگر (authctxt == تہی)
		fatal_f("no authentication context");

	fatal("Unexpected authentication success during %s.",
	    authctxt->طریقہ->name);
	واپس 0;
}
#اگر_ختم

ساکن صحیح
داخلہ_userauth_failure(صحیح type, uint32_t seq, ساخت ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	حرف *authlist = تہی;
	u_char partial;

	اگر (authctxt == تہی)
		fatal("input_userauth_failure: no authentication context");

	اگر (sshpkt_get_cstring(ssh, &authlist, تہی) != 0 ||
	    sshpkt_get_u8(ssh, &partial) != 0 ||
	    sshpkt_get_انتہا(ssh) != 0)
		جاؤ برآمد;

	اگر (partial != 0) {
		verbose("Authenticated using \"%s\" with partial success.",
		    authctxt->طریقہ->name);
		/* reset state */
		pubkey_reset(authctxt);
	}
	debug("Authentications that can continue: %s", authlist);

	userauth(ssh, authlist);
	authlist = تہی;
 برآمد:
	آزاد(authlist);
	واپس 0;
}

/*
 * Format an identity for logging including filename, key type, fingerprint
 * and location (agent, etc.). Caller must free.
 */
ساکن حرف *
format_شناختی_عنصر(شناختی_عنصر *id)
{
	حرف *fp = تہی, *ret = تہی;
	ثابت حرف *note = "";

	اگر (id->کلید != تہی) {
		fp = sshkey_fingerprint(id->کلید, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
	}
	اگر (id->کلید) {
		اگر ((id->کلید->flags & SSHKEY_FLAG_EXT) != 0)
			note = " token";
		ورنہ اگر (sshkey_is_sk(id->کلید))
			note = " authenticator";
	}
	xasprintf(&ret, "%s %s%s%s%s%s%s",
	    id->filename,
	    id->کلید ? sshkey_type(id->کلید) : "", id->کلید ? " " : "",
	    fp ? fp : "",
	    id->userprovided ? " explicit" : "", note,
	    id->agent_fd != -1 ? " agent" : "");
	آزاد(fp);
	واپس ret;
}

ساکن صحیح
داخلہ_userauth_pk_ok(صحیح type, uint32_t seq, ساخت ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	ساخت sshkey *کلید = تہی;
	ساخت sshbuf *keyblob = تہی;
	شناختی_عنصر *id = تہی;
	صحیح pktype, ملا = 0, بھیجا = 0;
	حرف *pkalg = تہی, *fp = تہی, *ident = تہی;
	صحیح r;

	اگر (authctxt == تہی)
		fatal_f("no authentication context");

	اگر ((r = sshpkt_get_cstring(ssh, &pkalg, تہی)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0 ||
	    (r = sshpkt_get_انتہا(ssh)) != 0)
		جاؤ مکمل;

	اگر (مطابقت_نمونہ_list(pkalg, options.pubkey_accepted_algos, 0) != 1) {
		error_f("server replied to PK_OK with signature type %s not "
		    "in PubkeyAcceptedAlgorithms", pkalg);
		r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		جاؤ مکمل;
	}
	اگر ((pktype = sshkey_type_from_name(pkalg)) == کلید_UNSPEC) {
		debug_f("server sent unknown pkalg %s", pkalg);
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ مکمل;
	}
	/* inner key type should match signature type */
	اگر ((r = sshkey_fromb_allowlist(keyblob, &کلید, pkalg, تہی)) != 0) {
		debug_r(r, "no key from blob. pkalg %s", pkalg);
		جاؤ مکمل;
	}
	اگر (کلید->type != pktype) {
		error("input_userauth_pk_ok: type mismatch "
		    "for decoded key (received %d, expected %d)",
		    کلید->type, pktype);
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ مکمل;
	}

	/*
	 * search keys in the reverse order, because last candidate has been
	 * moved to the end of the queue.  this also avoids confusion by
	 * duplicate keys
	 */
	TAILQ_FOREACH_الٹ(id, &authctxt->کلیدیں, idlist, اگلا) {
		اگر (sshkey_equal(کلید, id->کلید)) {
			ملا = 1;
			توڑو;
		}
	}
	اگر (!ملا || id == تہی) {
		fp = sshkey_fingerprint(کلید, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		error_f("server replied with unknown key: %s %s",
		    sshkey_type(کلید), fp == تہی ? "<ERROR>" : fp);
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ مکمل;
	}
	ident = format_شناختی_عنصر(id);
	debug("Server accepts key: %s", ident);
	بھیجا = sign_and_send_pubkey(ssh, id);
	r = 0;
 مکمل:
	sshkey_free(کلید);
	sshbuf_free(keyblob);
	آزاد(ident);
	آزاد(fp);
	آزاد(pkalg);

	/* try another method if we did not send a packet */
	اگر (r == 0 && بھیجا == 0)
		userauth(ssh, تہی);
	واپس r;
}

#اگر_تعریف_شدہ GSSAPI
ساکن صحیح
userauth_gssapi(ساخت ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Gssctxt *gssctxt = تہی;
	OM_uint32 min;
	صحیح r, ok = 0;
	gss_OID mech = تہی;

	/* Try one GSSAPI method at a time, rather than sending them all at
	 * once. */

	اگر (authctxt->gss_supported_mechs == تہی)
		gss_indicate_mechs(&min, &authctxt->gss_supported_mechs);

	/* Check to see whether the mechanism is usable before we offer it */
	جب (authctxt->mech_tried < authctxt->gss_supported_mechs->گنتی &&
	    !ok) {
		mech = &authctxt->gss_supported_mechs->
		    elements[authctxt->mech_tried];
		/* My DER encoding requires length<128 */
		اگر (mech->لمبائی < 128 && ssh_gssapi_check_mechanism(&gssctxt,
		    mech, authctxt->host)) {
			ok = 1; /* Mechanism works */
		} ورنہ {
			authctxt->mech_tried++;
		}
	}

	اگر (!ok || mech == تہی)
		واپس 0;

	authctxt->methoddata=(خالی *)gssctxt;

	اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->طریقہ->name)) != 0 ||
	    (r = sshpkt_put_u32(ssh, 1)) != 0 ||
	    (r = sshpkt_put_u32(ssh, (mech->لمبائی) + 2)) != 0 ||
	    (r = sshpkt_put_u8(ssh, SSH_GSS_OIDTYPE)) != 0 ||
	    (r = sshpkt_put_u8(ssh, mech->لمبائی)) != 0 ||
	    (r = sshpkt_put(ssh, mech->elements, mech->لمبائی)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_GSSAPI_RESPONSE, &داخلہ_gssapi_response);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_GSSAPI_TOKEN, &داخلہ_gssapi_token);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_GSSAPI_ERROR, &داخلہ_gssapi_error);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_GSSAPI_ERRTOK, &داخلہ_gssapi_errtok);

	authctxt->mech_tried++; /* Move along to next candidate */

	واپس 1;
}

ساکن خالی
userauth_gssapi_cleanup(ساخت ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Gssctxt *gssctxt = (Gssctxt *)authctxt->methoddata;

	ssh_gssapi_delete_ctx(&gssctxt);
	authctxt->methoddata = تہی;
}

ساکن OM_uint32
process_gssapi_token(ساخت ssh *ssh, gss_بفر_t recv_tok)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt = authctxt->methoddata;
	gss_بفر_desc send_tok = GSS_C_خالی_خانے_بفر;
	gss_بفر_desc mic = GSS_C_خالی_خانے_بفر;
	gss_بفر_desc gssbuf;
	OM_uint32 حالت_2, ms, flags;
	صحیح r;

	حالت_2 = ssh_gssapi_init_ctx(gssctxt, options.gss_deleg_creds,
	    recv_tok, &send_tok, &flags);

	اگر (send_tok.لمبائی > 0) {
		u_char type = GSS_ERROR(حالت_2) ?
		    SSH2_پیغام_USERAUTH_GSSAPI_ERRTOK :
		    SSH2_پیغام_USERAUTH_GSSAPI_TOKEN;

		اگر ((r = sshpkt_آغاز(ssh, type)) != 0 ||
		    (r = sshpkt_put_string(ssh, send_tok.قدر,
		    send_tok.لمبائی)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send %u packet", type);

		gss_release_بفر(&ms, &send_tok);
	}

	اگر (حالت_2 == GSS_S_COMPLETE) {
		/* send either complete or MIC, depending on mechanism */
		اگر (!(flags & GSS_C_INTEG_FLAG)) {
			اگر ((r = sshpkt_آغاز(ssh,
			    SSH2_پیغام_USERAUTH_GSSAPI_EXCHANGE_COMPLETE)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "send completion");
		} ورنہ {
			ساخت sshbuf *b;

			اگر ((b = sshbuf_new()) == تہی)
				fatal_f("sshbuf_new failed");
			ssh_gssapi_buildmic(b, authctxt->server_user,
			    authctxt->service, "gssapi-with-mic",
			    ssh->kex->session_id);

			اگر ((gssbuf.قدر = sshbuf_mutable_ptr(b)) == تہی)
				fatal_f("sshbuf_mutable_ptr failed");
			gssbuf.لمبائی = sshbuf_len(b);

			حالت_2 = ssh_gssapi_sign(gssctxt, &gssbuf, &mic);

			اگر (!GSS_ERROR(حالت_2)) {
				اگر ((r = sshpkt_آغاز(ssh,
				    SSH2_پیغام_USERAUTH_GSSAPI_MIC)) != 0 ||
				    (r = sshpkt_put_string(ssh, mic.قدر,
				    mic.لمبائی)) != 0 ||
				    (r = sshpkt_send(ssh)) != 0)
					fatal_fr(r, "send MIC");
			}

			sshbuf_free(b);
			gss_release_بفر(&ms, &mic);
		}
	}

	واپس حالت_2;
}

ساکن صحیح
داخلہ_gssapi_response(صحیح type, uint32_t plen, ساخت ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	سائز_t oidlen;
	u_char *oidv = تہی;
	صحیح r;

	اگر (authctxt == تہی)
		fatal("input_gssapi_response: no authentication context");
	gssctxt = authctxt->methoddata;

	/* Setup our OID */
	اگر ((r = sshpkt_get_string(ssh, &oidv, &oidlen)) != 0)
		جاؤ مکمل;

	اگر (oidlen <= 2 ||
	    oidv[0] != SSH_GSS_OIDTYPE ||
	    oidv[1] != oidlen - 2) {
		debug("Badly encoded mechanism OID received");
		userauth(ssh, تہی);
		جاؤ ok;
	}

	اگر (!ssh_gssapi_check_oid(gssctxt, oidv + 2, oidlen - 2))
		fatal("Server returned different OID than expected");

	اگر ((r = sshpkt_get_انتہا(ssh)) != 0)
		جاؤ مکمل;

	اگر (GSS_ERROR(process_gssapi_token(ssh, GSS_C_NO_بفر))) {
		/* Start again with next method on list */
		debug("Trying to start again");
		userauth(ssh, تہی);
		جاؤ ok;
	}
 ok:
	r = 0;
 مکمل:
	آزاد(oidv);
	واپس r;
}

ساکن صحیح
داخلہ_gssapi_token(صحیح type, uint32_t plen, ساخت ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	gss_بفر_desc recv_tok;
	u_char *p = تہی;
	سائز_t len;
	OM_uint32 حالت_2;
	صحیح r;

	اگر (authctxt == تہی)
		fatal("input_gssapi_response: no authentication context");

	اگر ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_انتہا(ssh)) != 0)
		جاؤ برآمد;

	recv_tok.قدر = p;
	recv_tok.لمبائی = len;
	حالت_2 = process_gssapi_token(ssh, &recv_tok);

	/* Start again with the next method in the list */
	اگر (GSS_ERROR(حالت_2)) {
		userauth(ssh, تہی);
		/* ok */
	}
	r = 0;
 برآمد:
	آزاد(p);
	واپس r;
}

ساکن صحیح
داخلہ_gssapi_errtok(صحیح type, uint32_t plen, ساخت ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	gss_بفر_desc send_tok = GSS_C_خالی_خانے_بفر;
	gss_بفر_desc recv_tok;
	OM_uint32 ms;
	u_char *p = تہی;
	سائز_t len;
	صحیح r;

	اگر (authctxt == تہی)
		fatal("input_gssapi_response: no authentication context");
	gssctxt = authctxt->methoddata;

	اگر ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_انتہا(ssh)) != 0) {
		آزاد(p);
		واپس r;
	}

	/* Stick it into GSSAPI and see what it says */
	recv_tok.قدر = p;
	recv_tok.لمبائی = len;
	(خالی)ssh_gssapi_init_ctx(gssctxt, options.gss_deleg_creds,
	    &recv_tok, &send_tok, تہی);
	آزاد(p);
	gss_release_بفر(&ms, &send_tok);

	/* Server will be returning a failed packet after this one */
	واپس 0;
}

ساکن صحیح
داخلہ_gssapi_error(صحیح type, uint32_t plen, ساخت ssh *ssh)
{
	حرف *پیغام = تہی;
	حرف *lang = تہی;
	صحیح r;

	اگر ((r = sshpkt_get_u32(ssh, تہی)) != 0 ||	/* maj */
	    (r = sshpkt_get_u32(ssh, تہی)) != 0 ||	/* min */
	    (r = sshpkt_get_cstring(ssh, &پیغام, تہی)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, تہی)) != 0)
		جاؤ برآمد;
	r = sshpkt_get_انتہا(ssh);
	debug("Server GSSAPI Error:\n%s", پیغام);
 برآمد:
	آزاد(پیغام);
	آزاد(lang);
	واپس r;
}
#اگر_ختم /* GSSAPI */

ساکن صحیح
userauth_none(ساخت ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	صحیح r;

	/* initial userauth request */
	اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->طریقہ->name)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	واپس 1;
}

ساکن صحیح
userauth_passwd(ساخت ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	حرف *password, *prompt = تہی;
	ثابت حرف *host = options.host_کلید_alias ?  options.host_کلید_alias :
	    authctxt->host;
	صحیح r;

	اگر (authctxt->attempt_passwd++ >= options.نمبر_کا_password_prompts)
		واپس 0;

	اگر (authctxt->attempt_passwd != 1)
		error("Permission denied, please try again.");

	xasprintf(&prompt, "%s@%s's password: ", authctxt->server_user, host);
	password = read_passphrase(prompt, 0);
	اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->طریقہ->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, password)) != 0 ||
	    (r = sshpkt_جوڑو_padding(ssh, 64)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	آزاد(prompt);
	اگر (password != تہی)
		freezero(password, لڑی_لمبائی(password));

	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_PASSWD_CHANGEREQ,
	    &داخلہ_userauth_passwd_changereq);

	واپس 1;
}

/*
 * parse PASSWD_CHANGEREQ, prompt user and send SSH2_MSG_USERAUTH_REQUEST
 */
ساکن صحیح
داخلہ_userauth_passwd_changereq(صحیح type, uint32_t seqnr, ساخت ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	حرف *info = تہی, *lang = تہی, *password = تہی, *retype = تہی;
	حرف prompt[256];
	ثابت حرف *host;
	صحیح r, addnl;
	سائز_t len;

	debug2("input_userauth_passwd_changereq");

	اگر (authctxt == تہی)
		fatal("input_userauth_passwd_changereq: "
		    "no authentication context");
	host = options.host_کلید_alias ? options.host_کلید_alias : authctxt->host;

	اگر ((r = sshpkt_get_cstring(ssh, &info, تہی)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, تہی)) != 0)
		جاؤ برآمد;
	اگر ((len = لڑی_لمبائی(info)) > 0) {
		addnl = info[len] != '\n';
		fmprintf(stderr, "%s%s", info, addnl ? "\n" : "");
	}
	اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->طریقہ->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0)	/* additional info */
		جاؤ برآمد;

	snprintf(prompt, حجم(prompt),
	    "Enter %.30s@%.128s's old password: ",
	    authctxt->server_user, host);
	password = read_passphrase(prompt, 0);
	اگر ((r = sshpkt_put_cstring(ssh, password)) != 0)
		جاؤ برآمد;

	freezero(password, لڑی_لمبائی(password));
	password = تہی;
	جب (password == تہی) {
		snprintf(prompt, حجم(prompt),
		    "Enter %.30s@%.128s's new password: ",
		    authctxt->server_user, host);
		password = read_passphrase(prompt, RP_ALLOW_EOF);
		اگر (password == تہی) {
			/* bail out */
			r = 0;
			جاؤ برآمد;
		}
		snprintf(prompt, حجم(prompt),
		    "Retype %.30s@%.128s's new password: ",
		    authctxt->server_user, host);
		retype = read_passphrase(prompt, 0);
		اگر (strcmp(password, retype) != 0) {
			freezero(password, لڑی_لمبائی(password));
			logit("Mismatch; try again, EOF to quit.");
			password = تہی;
		}
		freezero(retype, لڑی_لمبائی(retype));
	}
	اگر ((r = sshpkt_put_cstring(ssh, password)) != 0 ||
	    (r = sshpkt_جوڑو_padding(ssh, 64)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		جاؤ برآمد;

	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_PASSWD_CHANGEREQ,
	    &داخلہ_userauth_passwd_changereq);
	r = 0;
 برآمد:
	اگر (password)
		freezero(password, لڑی_لمبائی(password));
	آزاد(info);
	آزاد(lang);
	واپس r;
}

/*
 * Select an algorithm for publickey signatures.
 * Returns algorithm (caller must free) or NULL if no mutual algorithm found.
 *
 * Call with ssh==NULL to ignore server-sig-algs extension list and
 * only attempt with the key's base signature type.
 */
ساکن حرف *
کلید_sig_algorithm(ساخت ssh *ssh, ثابت ساخت sshkey *کلید)
{
	حرف *allowed, *oallowed, *cp, *tmp, *alg = تہی;
	ثابت حرف *server_sig_algs;

	/*
	 * The signature algorithm will only differ from the key algorithm
	 * for RSA keys/certs and when the server advertises support for
	 * newer (SHA2) algorithms.
	 */
	اگر (ssh == تہی || ssh->kex->server_sig_algs == تہی ||
	    (کلید->type != کلید_RSA && کلید->type != کلید_RSA_CERT) ||
	    (کلید->type == کلید_RSA_CERT && (ssh->compat & SSH_BUG_SIGTYPE))) {
		/* Filter base key signature alg against our configuration */
		واپس مطابقت_list(sshkey_ssh_name(کلید),
		    options.pubkey_accepted_algos, تہی);
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
	جب ((cp = strsep(&allowed, ",")) != تہی) {
		اگر (sshkey_type_from_name(cp) != کلید->type)
			جاری;
		tmp = مطابقت_list(sshkey_sigalg_by_name(cp),
		    server_sig_algs, تہی);
		اگر (tmp != تہی)
			alg = xstrdup(cp);
		آزاد(tmp);
		اگر (alg != تہی)
			توڑو;
	}
	آزاد(oallowed);
	واپس alg;
}

ساکن صحیح
شناختی_عنصر_sign(ساخت شناختی_عنصر_2 *id, u_char **sigp, سائز_t *lenp,
    ثابت u_char *ڈیٹا, سائز_t datalen, u_int compat, ثابت حرف *alg)
{
	ساخت sshkey *sign_کلید = تہی, *prv = تہی;
	صحیح is_agent = 0, retried = 0, r = SSH_ERR_اندرونی_ERROR;
	ساخت notifier_ctx *notifier = تہی;
	حرف *fp = تہی, *pin = تہی, *prompt = تہی;

	*sigp = تہی;
	*lenp = 0;

	/* The agent supports this key. */
	اگر (id->کلید != تہی && id->agent_fd != -1) {
		واپس ssh_agent_sign(id->agent_fd, id->کلید, sigp, lenp,
		    ڈیٹا, datalen, alg, compat);
	}

	/*
	 * We have already loaded the private key or the private key is
	 * stored in external hardware.
	 */
	اگر (id->کلید != تہی &&
	    (id->isprivate || (id->کلید->flags & SSHKEY_FLAG_EXT))) {
		sign_کلید = id->کلید;
		is_agent = 1;
	} ورنہ {
		/* Load the private key from the file. */
		اگر ((prv = بھرو_شناختی_عنصر_file(id)) == تہی)
			واپس SSH_ERR_کلید_NOT_ملا;
		اگر (id->کلید != تہی && !sshkey_equal_عوامی(prv, id->کلید)) {
			error_f("private key %s contents do not match public",
			    id->filename);
			r = SSH_ERR_کلید_NOT_ملا;
			جاؤ برآمد;
		}
		sign_کلید = prv;
	}
 retry_pin:
	/* Prompt for touch for non-agent FIDO keys that request UP */
	اگر (!is_agent && sshkey_is_sk(sign_کلید) &&
	    (sign_کلید->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
		/* XXX should batch mode just skip these? */
		اگر ((fp = sshkey_fingerprint(sign_کلید,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == تہی)
			fatal_f("fingerprint failed");
		notifier = notify_آغاز(options.batch_منوال,
		    "Confirm user presence for key %s %s",
		    sshkey_type(sign_کلید), fp);
		آزاد(fp);
	}
	اگر ((r = sshkey_sign(sign_کلید, sigp, lenp, ڈیٹا, datalen,
	    alg, options.sk_provider, pin, compat)) != 0) {
		debug_fr(r, "sshkey_sign");
		اگر (!retried && pin == تہی && !is_agent &&
		    sshkey_is_sk(sign_کلید) &&
		    r == SSH_ERR_کلید_WRONG_PASSPHRASE) {
			notify_complete(notifier, تہی);
			notifier = تہی;
			xasprintf(&prompt, "Enter PIN for %s key %s: ",
			    sshkey_type(sign_کلید), id->filename);
			pin = read_passphrase(prompt, 0);
			retried = 1;
			جاؤ retry_pin;
		}
		جاؤ برآمد;
	}

	/*
	 * PKCS#11 tokens may not support all signature algorithms,
	 * so check what we get back.
	 */
	اگر (id->کلید != تہی && (id->کلید->flags & SSHKEY_FLAG_EXT) != 0 &&
	    (r = sshkey_check_sigtype(*sigp, *lenp, alg)) != 0) {
		debug_fr(r, "sshkey_check_sigtype");
		جاؤ برآمد;
	}
	/* success */
	r = 0;
 برآمد:
	آزاد(prompt);
	اگر (pin != تہی)
		freezero(pin, لڑی_لمبائی(pin));
	notify_complete(notifier, r == 0 ? "User presence confirmed" : تہی);
	sshkey_free(prv);
	واپس r;
}

ساکن صحیح
id_filename_matches(شناختی_عنصر *id, شناختی_عنصر *نجی_id)
{
	ساکن ثابت حرف * ثابت suffixes[] = { ".pub", "-cert.pub", تہی };
	سائز_t len = لڑی_لمبائی(id->filename), plen = لڑی_لمبائی(نجی_id->filename);
	سائز_t i, slen;

	اگر (strcmp(id->filename, نجی_id->filename) == 0)
		واپس 1;
	برائے (i = 0; suffixes[i]; i++) {
		slen = لڑی_لمبائی(suffixes[i]);
		اگر (len > slen && plen == len - slen &&
		    strcmp(id->filename + (len - slen), suffixes[i]) == 0 &&
		    memcmp(id->filename, نجی_id->filename, plen) == 0)
			واپس 1;
	}
	واپس 0;
}

ساکن صحیح
sign_and_send_pubkey(ساخت ssh *ssh, شناختی_عنصر *id)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	ساخت sshbuf *b = تہی;
	شناختی_عنصر *نجی_id, *sign_id = تہی;
	u_char *signature = تہی;
	سائز_t slen = 0, skip = 0;
	صحیح r, fallback_sigtype, بھیجا = 0;
	حرف *alg = تہی, *fp = تہی;
	ثابت حرف *loc = "", *طریقہ = "publickey";
	صحیح hostbound = 0;

	/* prefer host-bound pubkey signatures if supported by server */
	اگر ((ssh->kex->flags & KEX_HAS_PUBKEY_HOSTBOUND) != 0 &&
	    (options.pubkey_authentication & SSH_PUBKEY_AUTH_HBOUND) != 0) {
		hostbound = 1;
		طریقہ = "publickey-hostbound-v00@openssh.com";
	}

	اگر ((fp = sshkey_fingerprint(id->کلید, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == تہی)
		واپس 0;

	debug3_f("using %s with %s %s", طریقہ, sshkey_type(id->کلید), fp);

	/*
	 * If the key is an certificate, try to find a matching private key
	 * and use it to complete the signature.
	 * If no such private key exists, fall back to trying the certificate
	 * key itself in case it has a private half already loaded.
	 * This will try to set sign_id to the private key that will perform
	 * the signature.
	 */
	اگر (id->agent_fd == -1 && sshkey_is_cert(id->کلید)) {
		TAILQ_FOREACH(نجی_id, &authctxt->کلیدیں, اگلا) {
			اگر (sshkey_equal_عوامی(id->کلید, نجی_id->کلید) &&
			    id->کلید->type != نجی_id->کلید->type) {
				sign_id = نجی_id;
				توڑو;
			}
		}
		/*
		 * Exact key matches are preferred, but also allow
		 * filename matches for non-PKCS#11/agent keys that
		 * didn't load public keys. This supports the case
		 * of keeping just a private key file and public
		 * certificate on disk.
		 */
		اگر (sign_id == تہی &&
		    !id->isprivate && id->agent_fd == -1 &&
		    (id->کلید->flags & SSHKEY_FLAG_EXT) == 0) {
			TAILQ_FOREACH(نجی_id, &authctxt->کلیدیں, اگلا) {
				اگر (نجی_id->کلید == تہی &&
				    id_filename_matches(id, نجی_id)) {
					sign_id = نجی_id;
					توڑو;
				}
			}
		}
		اگر (sign_id != تہی) {
			debug2_f("using private key \"%s\"%s for "
			    "certificate", sign_id->filename,
			    sign_id->agent_fd != -1 ? " from agent" : "");
		} ورنہ {
			debug_f("no separate private key for certificate "
			    "\"%s\"", id->filename);
		}
	}

	/*
	 * If the above didn't select another identity to do the signing
	 * then default to the one we started with.
	 */
	اگر (sign_id == تہی)
		sign_id = id;

	/* assemble and sign data */
	برائے (fallback_sigtype = 0; fallback_sigtype <= 1; fallback_sigtype++) {
		آزاد(alg);
		slen = 0;
		signature = تہی;
		اگر ((alg = کلید_sig_algorithm(fallback_sigtype ? تہی : ssh,
		    id->کلید)) == تہی) {
			error_f("no mutual signature supported");
			جاؤ برآمد;
		}
		debug3_f("signing using %s %s", alg, fp);

		sshbuf_free(b);
		اگر ((b = sshbuf_new()) == تہی)
			fatal_f("sshbuf_new failed");
		اگر ((r = sshbuf_put_stringb(b,
		    ssh->kex->session_id)) != 0)
			fatal_fr(r, "sshbuf_put_stringb");
		skip = sshbuf_len(b);
		اگر ((r = sshbuf_put_u8(b, SSH2_پیغام_USERAUTH_REQUEST)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->server_user)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
		    (r = sshbuf_put_cstring(b, طریقہ)) != 0 ||
		    (r = sshbuf_put_u8(b, 1)) != 0 ||
		    (r = sshbuf_put_cstring(b, alg)) != 0 ||
		    (r = sshkey_puts(id->کلید, b)) != 0) {
			fatal_fr(r, "assemble signed data");
		}
		اگر (hostbound) {
			اگر (ssh->kex->initial_hostkey == تہی) {
				fatal_f("internal error: initial hostkey "
				    "not recorded");
			}
			اگر ((r = sshkey_puts(ssh->kex->initial_hostkey, b)) != 0)
				fatal_fr(r, "assemble %s hostkey", طریقہ);
		}
		/* generate signature */
		r = شناختی_عنصر_sign(sign_id, &signature, &slen,
		    sshbuf_ptr(b), sshbuf_len(b), ssh->compat, alg);
		اگر (r == 0)
			توڑو;
		ورنہ اگر (r == SSH_ERR_کلید_NOT_ملا)
			جاؤ برآمد; /* soft failure */
		ورنہ اگر (r == SSH_ERR_SIGN_ALG_UNSUPPORTED &&
		    !fallback_sigtype) {
			اگر (sign_id->agent_fd != -1)
				loc = "agent ";
			ورنہ اگر (sign_id->کلید != تہی &&
			    (sign_id->کلید->flags & SSHKEY_FLAG_EXT) != 0)
				loc = "token ";
			logit("%skey %s %s returned incorrect signature type",
			    loc, sshkey_type(id->کلید), fp);
			جاری;
		}
		error_fr(r, "signing failed for %s \"%s\"%s",
		    sshkey_type(sign_id->کلید), sign_id->filename,
		    id->agent_fd != -1 ? " from agent" : "");
		جاؤ برآمد;
	}
	اگر (slen == 0 || signature == تہی) /* shouldn't happen */
		fatal_f("no signature");

	/* append signature */
	اگر ((r = sshbuf_put_string(b, signature, slen)) != 0)
		fatal_fr(r, "append signature");

#اگر_تعریف_شدہ DEBUG_PK
	sshbuf_dump(b, stderr);
#اگر_ختم
	/* skip session id and packet type */
	اگر ((r = sshbuf_consume(b, skip + 1)) != 0)
		fatal_fr(r, "consume");

	/* put remaining data from buffer into packet */
	اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_putb(ssh, b)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "enqueue request");

	/* success */
	بھیجا = 1;

 برآمد:
	آزاد(fp);
	آزاد(alg);
	sshbuf_free(b);
	freezero(signature, slen);
	واپس بھیجا;
}

ساکن صحیح
send_pubkey_test(ساخت ssh *ssh, شناختی_عنصر *id)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	u_char *blob = تہی;
	حرف *alg = تہی;
	سائز_t bloblen;
	u_int have_sig = 0;
	صحیح بھیجا = 0, r;

	اگر ((alg = کلید_sig_algorithm(ssh, id->کلید)) == تہی) {
		debug_f("no mutual signature algorithm");
		جاؤ برآمد;
	}

	اگر ((r = sshkey_مقصد_blob(id->کلید, &blob, &bloblen)) != 0) {
		/* we cannot handle this key */
		debug3_f("cannot handle key");
		جاؤ برآمد;
	}
	/* register callback for USERAUTH_PK_OK message */
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_PK_OK, &داخلہ_userauth_pk_ok);

	اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->طریقہ->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, have_sig)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, alg)) != 0 ||
	    (r = sshpkt_put_string(ssh, blob, bloblen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	بھیجا = 1;

 برآمد:
	آزاد(alg);
	آزاد(blob);
	واپس بھیجا;
}

ساکن ساخت sshkey *
بھرو_شناختی_عنصر_file(شناختی_عنصر *id)
{
	ساخت sshkey *نجی = تہی;
	حرف prompt[300], *passphrase, *comment;
	صحیح r, quit = 0, i;
	ساخت stat st;

	اگر (stat(id->filename, &st) == -1) {
		do_log2(id->userprovided ?
		    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_DEBUG3,
		    "no such identity: %s: %s", id->filename, strerror(errno));
		واپس تہی;
	}
	snprintf(prompt, حجم prompt,
	    "Enter passphrase for key '%.100s': ", id->filename);
	برائے (i = 0; i <= options.نمبر_کا_password_prompts; i++) {
		اگر (i == 0)
			passphrase = "";
		ورنہ {
			passphrase = read_passphrase(prompt, 0);
			اگر (*passphrase == '\0') {
				debug2("no passphrase given, try next key");
				آزاد(passphrase);
				توڑو;
			}
		}
		انتخاب ((r = sshkey_بھرو_نجی_type(کلید_UNSPEC, id->filename,
		    passphrase, &نجی, &comment))) {
		حالت 0:
			توڑو;
		حالت SSH_ERR_کلید_WRONG_PASSPHRASE:
			اگر (options.batch_منوال) {
				quit = 1;
				توڑو;
			}
			اگر (i != 0)
				debug2("bad passphrase given, try again...");
			توڑو;
		حالت SSH_ERR_SYSTEM_ERROR:
			اگر (errno == ENOENT) {
				debug2_r(r, "Load key \"%s\"", id->filename);
				quit = 1;
				توڑو;
			}
			/* FALLTHROUGH */
		طےشدہ:
			error_r(r, "Load key \"%s\"", id->filename);
			quit = 1;
			توڑو;
		}
		اگر (نجی != تہی && sshkey_is_sk(نجی) &&
		    options.sk_provider == تہی) {
			debug("key \"%s\" is an authenticator-hosted key, "
			    "but no provider specified", id->filename);
			sshkey_free(نجی);
			نجی = تہی;
			quit = 1;
		}
		اگر (!quit && (r = sshkey_check_rsa_لمبائی(نجی,
		    options.required_rsa_سائز)) != 0) {
			debug_fr(r, "Skipping key %s", id->filename);
			sshkey_free(نجی);
			نجی = تہی;
			quit = 1;
		}
		اگر (!quit && نجی != تہی && id->agent_fd == -1 &&
		    !(id->کلید && id->isprivate))
			maybe_جوڑو_کلید_مقصد_agent(id->filename, نجی, comment,
			    passphrase);
		اگر (i > 0)
			freezero(passphrase, لڑی_لمبائی(passphrase));
		آزاد(comment);
		اگر (نجی != تہی || quit)
			توڑو;
	}
	واپس نجی;
}

ساکن صحیح
کلید_type_allowed(ساخت sshkey *کلید, ثابت حرف *allowlist)
{
	اگر (مطابقت_نمونہ_list(sshkey_ssh_name(کلید), allowlist, 0) == 1)
		واپس 1;

	/* RSA keys/certs might be allowed by alternate signature types */
	انتخاب (کلید->type) {
	حالت کلید_RSA:
		اگر (مطابقت_نمونہ_list("rsa-sha2-512", allowlist, 0) == 1)
			واپس 1;
		اگر (مطابقت_نمونہ_list("rsa-sha2-256", allowlist, 0) == 1)
			واپس 1;
		توڑو;
	حالت کلید_RSA_CERT:
		اگر (مطابقت_نمونہ_list("rsa-sha2-512-cert-v01@openssh.com",
		    allowlist, 0) == 1)
			واپس 1;
		اگر (مطابقت_نمونہ_list("rsa-sha2-256-cert-v01@openssh.com",
		    allowlist, 0) == 1)
			واپس 1;
		توڑو;
	}
	واپس 0;
}

ساکن صحیح
کلید_type_allowed_by_config(ساخت sshkey *کلید)
{
	واپس کلید_type_allowed(کلید, options.pubkey_accepted_algos);
}

/* obtain a list of keys from the agent */
ساکن صحیح
get_agent_identities(ساخت ssh *ssh, صحیح *agent_fdp,
    ساخت ssh_identitylist **idlistp)
{
	صحیح r, agent_fd;
	ساخت ssh_identitylist *idlist;

	اگر ((r = ssh_get_authentication_socket(&agent_fd)) != 0) {
		اگر (r != SSH_ERR_AGENT_NOT_PRESENT)
			debug_fr(r, "ssh_get_authentication_socket");
		واپس r;
	}
	اگر (ssh != تہی && ssh->kex != تہی) {
		اگر ((r = ssh_agent_bind_hostkey(agent_fd, ssh->kex->initial_hostkey,
		    ssh->kex->session_id, ssh->kex->initial_sig, 0)) == 0)
			debug_f("bound agent to hostkey");
		ورنہ
			debug2_fr(r, "ssh_agent_bind_hostkey");
	}

	اگر ((r = ssh_fetch_identitylist(agent_fd, &idlist)) != 0) {
		debug_fr(r, "ssh_fetch_identitylist");
		close(agent_fd);
		واپس r;
	}
	/* success */
	*agent_fdp = agent_fd;
	*idlistp = idlist;
	debug_f("agent returned %zu keys", idlist->nkeys);
	واپس 0;
}

/*
 * Returns nonzero if the certificate extensions/critical-options section
 * has the specified option present, zero otherwise.
 */
ساکن صحیح
cert_has_option(ساخت sshbuf *oblob, ثابت حرف *ہدف)
{
	ساخت sshbuf *c = تہی, *ڈیٹا = تہی;
	حرف *name = تہی;
	صحیح r, ملا = 0;

	اگر (oblob == تہی || (c = sshbuf_fromb(oblob)) == تہی)
		واپس 0;
	جب (sshbuf_len(c) > 0) {
		sshbuf_free(ڈیٹا);
		ڈیٹا = تہی;
		آزاد(name);
		name = تہی;
		اگر ((r = sshbuf_get_cstring(c, &name, تہی)) != 0 ||
		    (r = sshbuf_froms(c, &ڈیٹا)) != 0)
			توڑو;
		اگر (strcmp(name, ہدف) == 0) {
			ملا = 1;
			توڑو;
		}
	}
	sshbuf_free(ڈیٹا);
	آزاد(name);
	sshbuf_free(c);
	واپس ملا;
}

/*
 * Returns an integer describing the priority of the identity
 * within its group. Lower numbers are higher priority.
 */
#تعریف_کرو MAX_ID_ترجیح 3
ساکن صحیح
شناختی_عنصر_prioritise(ساخت شناختی_عنصر_2 *id)
{
	اگر (id == تہی || id->کلید == تہی)
		واپس 3;
	اگر (!sshkey_is_cert(id->کلید) || id->کلید->cert == تہی)
		واپس 3;
	اگر (sshkey_is_sk(id->کلید) &&
	    cert_has_option(id->کلید->cert->critical, "verify-required"))
		واپس 2;
	اگر (sshkey_is_sk(id->کلید) &&
	    cert_has_option(id->کلید->cert->extensions, "no-touch-required"))
		واپس 0;
	واپس 1;
}

ساکن خالی
ترتیب_identities_by_prio(ساخت idlist *list)
{
	ساخت idlist prio[MAX_ID_ترجیح + 1], sorted;
	ساخت شناختی_عنصر_2 *id, *tmp, *dummy;
	صحیح p;

	برائے (p = 0; p <= MAX_ID_ترجیح; p++)
		TAILQ_INIT(&prio[p]);
	TAILQ_INIT(&sorted);

	TAILQ_FOREACH_محفوظ(id, list, اگلا, tmp) {
		اگر (id->userprovided)
			جاری;
		dummy = xcalloc(1, حجم(*dummy));
		dummy->userprovided = -1;
		TAILQ_INSERT_BEFORE(id, dummy, اگلا);
		TAILQ_REMOVE(list, id, اگلا);
		p = شناختی_عنصر_prioritise(id);
		اگر (p < 0 || p > MAX_ID_ترجیح)
			fatal_f("internal error: bad priority");
		TAILQ_INSERT_TAIL(&prio[p], id, اگلا);
	}
	برائے (p = 0; p <= MAX_ID_ترجیح; p++)
		TAILQ_CONCAT(&sorted, &prio[p], اگلا);

	TAILQ_FOREACH_محفوظ(id, list, اگلا, tmp) {
		اگر (id->userprovided != -1)
			جاری;
		ساخت شناختی_عنصر_2 *s = TAILQ_FIRST(&sorted);
		TAILQ_REMOVE(&sorted, s, اگلا);
		TAILQ_INSERT_BEFORE(id, s, اگلا);
		TAILQ_REMOVE(list, id, اگلا);
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
ساکن خالی
pubkey_prepare(ساخت ssh *ssh, Authctxt *authctxt)
{
	ساخت شناختی_عنصر_2 *id, *id2, *tmp;
	ساخت idlist agent, files, certs, agent_کلیدیں, *preferred;
	ساخت sshkey *کلید;
	صحیح disallowed, agent_fd = -1, i, r, ملا;
	سائز_t j;
	ساخت ssh_identitylist *idlist;
	حرف *cp, *ident;

	TAILQ_INIT(&agent);	/* keys from the agent */
	TAILQ_INIT(&files);	/* keys from the config file */
	TAILQ_INIT(&certs);	/* certificates specified by user */
	TAILQ_INIT(&agent_کلیدیں); /* keys supported by the agent */
	preferred = &authctxt->کلیدیں;
	TAILQ_INIT(preferred);	/* preferred order of keys */

	/* list of keys stored in the filesystem and PKCS#11 */
	برائے (i = 0; i < options.عدد_شناختی_عنصر_files; i++) {
		کلید = options.شناختی_عنصر_کلیدیں[i];
		اگر (کلید && کلید->cert &&
		    کلید->cert->type != SSH2_CERT_TYPE_USER) {
			debug_f("ignoring certificate %s: not a user "
			    "certificate", options.شناختی_عنصر_files[i]);
			جاری;
		}
		اگر (کلید && sshkey_is_sk(کلید) && options.sk_provider == تہی) {
			debug_f("ignoring authenticator-hosted key %s as no "
			    "SecurityKeyProvider has been specified",
			    options.شناختی_عنصر_files[i]);
			جاری;
		}
		options.شناختی_عنصر_کلیدیں[i] = تہی;
		id = xcalloc(1, حجم(*id));
		id->agent_fd = -1;
		id->کلید = کلید;
		id->filename = xstrdup(options.شناختی_عنصر_files[i]);
		id->userprovided = options.شناختی_عنصر_file_userprovided[i];
		TAILQ_INSERT_TAIL(&files, id, اگلا);
	}

	/* list of certificates specified by user */
	برائے (i = 0; i < options.عدد_certificate_files; i++) {
		کلید = options.certificates[i];
		اگر (!sshkey_is_cert(کلید) || کلید->cert == تہی ||
		    کلید->cert->type != SSH2_CERT_TYPE_USER) {
			debug_f("ignoring certificate %s: not a user "
			    "certificate", options.شناختی_عنصر_files[i]);
			جاری;
		}
		اگر (کلید && sshkey_is_sk(کلید) && options.sk_provider == تہی) {
			debug_f("ignoring authenticator-hosted key "
			    "certificate %s as no "
			    "SecurityKeyProvider has been specified",
			    options.شناختی_عنصر_files[i]);
			جاری;
		}
		id = xcalloc(1, حجم(*id));
		id->agent_fd = -1;
		id->کلید = کلید;
		id->filename = xstrdup(options.certificate_files[i]);
		id->userprovided = options.certificate_file_userprovided[i];
		TAILQ_INSERT_TAIL(&certs, id, اگلا);
	}
	ترتیب_identities_by_prio(&certs);
	TAILQ_CONCAT(preferred, &certs, اگلا);

	/* list of keys supported by the agent */
	اگر ((r = get_agent_identities(ssh, &agent_fd, &idlist)) == 0) {
		برائے (j = 0; j < idlist->nkeys; j++) {
			اگر ((r = sshkey_check_rsa_لمبائی(idlist->کلیدیں[j],
			    options.required_rsa_سائز)) != 0) {
				debug_fr(r, "ignoring %s agent key",
				    sshkey_ssh_name(idlist->کلیدیں[j]));
				جاری;
			}
			ملا = 0;
			TAILQ_FOREACH(id, &files, اگلا) {
				/*
				 * agent keys from the config file are
				 * preferred
				 */
				اگر (sshkey_equal(idlist->کلیدیں[j], id->کلید)) {
					TAILQ_REMOVE(&files, id, اگلا);
					TAILQ_INSERT_TAIL(&agent_کلیدیں, id, اگلا);
					id->agent_fd = agent_fd;
					ملا = 1;
					توڑو;
				}
			}
			اگر (!ملا && !options.identities_only) {
				id = xcalloc(1, حجم(*id));
				/* XXX "steals" key/comment from idlist */
				id->کلید = idlist->کلیدیں[j];
				id->filename = idlist->comments[j];
				idlist->کلیدیں[j] = تہی;
				idlist->comments[j] = تہی;
				id->agent_fd = agent_fd;
				TAILQ_INSERT_TAIL(&agent, id, اگلا);
			}
		}
		ssh_free_identitylist(idlist);
		/* append remaining agent keys */
		TAILQ_CONCAT(&agent_کلیدیں, &agent, اگلا);
		ترتیب_identities_by_prio(&agent_کلیدیں);
		TAILQ_CONCAT(preferred, &agent_کلیدیں, اگلا);
		authctxt->agent_fd = agent_fd;
	}
	/* Prefer PKCS11 keys that are explicitly listed */
	TAILQ_FOREACH_محفوظ(id, &files, اگلا, tmp) {
		اگر (id->کلید == تہی || (id->کلید->flags & SSHKEY_FLAG_EXT) == 0)
			جاری;
		ملا = 0;
		TAILQ_FOREACH(id2, &files, اگلا) {
			اگر (id2->کلید == تہی ||
			    (id2->کلید->flags & SSHKEY_FLAG_EXT) != 0)
				جاری;
			اگر (sshkey_equal(id->کلید, id2->کلید)) {
				TAILQ_REMOVE(&files, id, اگلا);
				TAILQ_INSERT_TAIL(preferred, id, اگلا);
				ملا = 1;
				توڑو;
			}
		}
		/* If IdentitiesOnly set and key not found then don't use it */
		اگر (!ملا && options.identities_only) {
			TAILQ_REMOVE(&files, id, اگلا);
			freezero(id, حجم(*id));
		}
	}
	ترتیب_identities_by_prio(&files);
	/* append remaining keys from the config file */
	TAILQ_CONCAT(preferred, &files, اگلا);
	/* finally, filter by PubkeyAcceptedAlgorithms */
	TAILQ_FOREACH_محفوظ(id, preferred, اگلا, id2) {
		disallowed = 0;
		cp = تہی;
		اگر (id->کلید == تہی)
			جاری;
		اگر (!کلید_type_allowed_by_config(id->کلید)) {
			debug("Skipping %s key %s - corresponding algorithm "
			    "not in PubkeyAcceptedAlgorithms",
			    sshkey_ssh_name(id->کلید), id->filename);
			disallowed = 1;
		} ورنہ اگر (ssh != تہی && ssh->kex != تہی &&
		    ssh->kex->server_sig_algs != تہی &&
		    (cp = کلید_sig_algorithm(ssh, id->کلید)) == تہی) {
			debug("Skipping %s key %s - corresponding algorithm "
			    "not supported by server",
			    sshkey_ssh_name(id->کلید), id->filename);
			disallowed = 1;
		}
		آزاد(cp);
		اگر (!disallowed)
			جاری;
		/* remove key */
		TAILQ_REMOVE(preferred, id, اگلا);
		sshkey_free(id->کلید);
		آزاد(id->filename);
		freezero(id, حجم(*id));
	}
	/* List the keys we plan on using */
	TAILQ_FOREACH_محفوظ(id, preferred, اگلا, id2) {
		ident = format_شناختی_عنصر(id);
		debug("Will attempt key: %s", ident);
		آزاد(ident);
	}
	debug2_f("done");
}

ساکن خالی
pubkey_cleanup(ساخت ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	شناختی_عنصر *id;

	اگر (authctxt->agent_fd != -1) {
		ssh_close_authentication_socket(authctxt->agent_fd);
		authctxt->agent_fd = -1;
	}
	برائے (id = TAILQ_FIRST(&authctxt->کلیدیں); id;
	    id = TAILQ_FIRST(&authctxt->کلیدیں)) {
		TAILQ_REMOVE(&authctxt->کلیدیں, id, اگلا);
		sshkey_free(id->کلید);
		آزاد(id->filename);
		آزاد(id);
	}
}

خالی
pubkey_dump(ساخت ssh *ssh)
{
	Authctxt authctxt;
	شناختی_عنصر *id;
	حرف *ident;

	memset(&authctxt, 0, حجم(authctxt));
	authctxt.agent_fd = -1;
	ssh->authctxt = &authctxt;

	pubkey_prepare(ssh, &authctxt);
	TAILQ_FOREACH(id, &authctxt.کلیدیں, اگلا) {
		ident = format_شناختی_عنصر(id);
		fprintf(stdout, "%s\n", ident);
		آزاد(ident);
	}
	pubkey_cleanup(ssh);
	ssh->authctxt = تہی;
}

ساکن خالی
pubkey_reset(Authctxt *authctxt)
{
	شناختی_عنصر *id;

	TAILQ_FOREACH(id, &authctxt->کلیدیں, اگلا)
		id->tried = 0;
}

ساکن صحیح
userauth_pubkey(ساخت ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	شناختی_عنصر *id;
	صحیح بھیجا = 0;
	حرف *ident;
	ساکن صحیح prepared;

	اگر (!prepared) {
		pubkey_prepare(ssh, authctxt);
		prepared = 1;
	}

	جب ((id = TAILQ_FIRST(&authctxt->کلیدیں))) {
		اگر (id->tried++)
			واپس (0);
		/* move key to the end of the queue */
		TAILQ_REMOVE(&authctxt->کلیدیں, id, اگلا);
		TAILQ_INSERT_TAIL(&authctxt->کلیدیں, id, اگلا);
		/*
		 * send a test message if we have the public key. for
		 * encrypted keys we cannot do this and have to load the
		 * private key instead
		 */
		اگر (id->کلید != تہی) {
			ident = format_شناختی_عنصر(id);
			debug("Offering public key: %s", ident);
			آزاد(ident);
			بھیجا = send_pubkey_test(ssh, id);
		} ورنہ {
			debug("Trying private key: %s", id->filename);
			id->کلید = بھرو_شناختی_عنصر_file(id);
			اگر (id->کلید != تہی) {
				id->isprivate = 1;
				بھیجا = sign_and_send_pubkey(ssh, id);
				sshkey_free(id->کلید);
				id->کلید = تہی;
				id->isprivate = 0;
			}
		}
		اگر (بھیجا)
			واپس (بھیجا);
	}
	واپس (0);
}

/*
 * Send userauth request message specifying keyboard-interactive method.
 */
ساکن صحیح
userauth_kbdint(ساخت ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	صحیح r;

	اگر (authctxt->attempt_kbdint++ >= options.نمبر_کا_password_prompts)
		واپس 0;
	/* disable if no SSH2_MSG_USERAUTH_INFO_REQUEST has been seen */
	اگر (authctxt->attempt_kbdint > 1 && !authctxt->info_req_نظر_آیا) {
		debug3("userauth_kbdint: disable: no info_req_seen");
		ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_INFO_REQUEST, تہی);
		واپس 0;
	}

	debug2("userauth_kbdint");
	اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->طریقہ->name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||		/* lang */
	    (r = sshpkt_put_cstring(ssh, options.kbd_interactive_devices ?
	    options.kbd_interactive_devices : "")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_INFO_REQUEST, &داخلہ_userauth_info_req);
	واپس 1;
}

/*
 * parse INFO_REQUEST, prompt user and send INFO_RESPONSE
 */
ساکن صحیح
داخلہ_userauth_info_req(صحیح type, uint32_t seq, ساخت ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	حرف *name = تہی, *inst = تہی, *lang = تہی, *prompt = تہی;
	حرف *display_prompt = تہی, *response = تہی;
	u_char echo = 0;
	u_int عدد_prompts, i;
	صحیح r, addnl;
	سائز_t len;

	debug2_f("entering");

	اگر (authctxt == تہی)
		fatal_f("no authentication context");

	authctxt->info_req_نظر_آیا = 1;

	اگر ((r = sshpkt_get_cstring(ssh, &name, تہی)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &inst, تہی)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, تہی)) != 0)
		جاؤ برآمد;
	اگر ((len = لڑی_لمبائی(name)) > 0) {
		addnl = name[len] != '\n';
		fmprintf(stderr, "%s%s", name, addnl ? "\n" : "");
	}
	اگر ((len = لڑی_لمبائی(inst)) > 0) {
		addnl = inst[len] != '\n';
		fmprintf(stderr, "%s%s", inst, addnl ? "\n" : "");
	}

	اگر ((r = sshpkt_get_u32(ssh, &عدد_prompts)) != 0)
		جاؤ برآمد;
	/*
	 * Begin to build info response packet based on prompts requested.
	 * We commit to providing the correct number of responses, so if
	 * further on we run into a problem that prevents this, we have to
	 * be sure and clean this up and send a correct error response.
	 */
	اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_USERAUTH_INFO_RESPONSE)) != 0 ||
	    (r = sshpkt_put_u32(ssh, عدد_prompts)) != 0)
		جاؤ برآمد;

	debug2_f("num_prompts %d", عدد_prompts);
	برائے (i = 0; i < عدد_prompts; i++) {
		اگر ((r = sshpkt_get_cstring(ssh, &prompt, تہی)) != 0 ||
		    (r = sshpkt_get_u8(ssh, &echo)) != 0)
			جاؤ برآمد;
		اگر (asmprintf(&display_prompt, زیادہ_سے_زیادہ_عدد, تہی, "(%s@%s) %s",
		    authctxt->server_user, options.host_کلید_alias ?
		    options.host_کلید_alias : authctxt->host, prompt) == -1)
			fatal_f("asmprintf failed");
		response = read_passphrase(display_prompt, echo ? RP_ECHO : 0);
		اگر ((r = sshpkt_put_cstring(ssh, response)) != 0)
			جاؤ برآمد;
		freezero(response, لڑی_لمبائی(response));
		آزاد(prompt);
		آزاد(display_prompt);
		display_prompt = response = prompt = تہی;
	}
	/* done with parsing incoming message. */
	اگر ((r = sshpkt_get_انتہا(ssh)) != 0 ||
	    (r = sshpkt_جوڑو_padding(ssh, 64)) != 0)
		جاؤ برآمد;
	r = sshpkt_send(ssh);
 برآمد:
	اگر (response)
		freezero(response, لڑی_لمبائی(response));
	آزاد(prompt);
	آزاد(display_prompt);
	آزاد(name);
	آزاد(inst);
	آزاد(lang);
	واپس r;
}

ساکن صحیح
ssh_keysign(ساخت ssh *ssh, ساخت sshkey *کلید, u_char **sigp, سائز_t *lenp,
    ثابت u_char *ڈیٹا, سائز_t datalen)
{
	ساخت sshbuf *b;
	ساخت stat st;
	pid_t pid;
	صحیح r, مقصد[2], from[2], حالت_2;
	صحیح sock = ssh_packet_get_connection_اندر(ssh);
	u_char rversion = 0, نسخہ = 2;
	خالی (*osigchld)(صحیح);

	*sigp = تہی;
	*lenp = 0;

	اگر (stat(راستہ_SSH_کلید_SIGN, &st) == -1) {
		error_f("not installed: %s", strerror(errno));
		واپس -1;
	}
	اگر (fflush(stdout) != 0) {
		error_f("fflush: %s", strerror(errno));
		واپس -1;
	}
	اگر (pipe(مقصد) == -1) {
		error_f("pipe: %s", strerror(errno));
		واپس -1;
	}
	اگر (pipe(from) == -1) {
		error_f("pipe: %s", strerror(errno));
		واپس -1;
	}
	اگر ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		واپس -1;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	اگر (pid == 0) {
		close(from[0]);
		اگر (dup2(from[1], STDOUT_FILENO) == -1)
			fatal_f("dup2: %s", strerror(errno));
		close(مقصد[1]);
		اگر (dup2(مقصد[0], STDIN_FILENO) == -1)
			fatal_f("dup2: %s", strerror(errno));
		close(from[1]);
		close(مقصد[0]);

		اگر (dup2(sock, STDERR_FILENO + 1) == -1)
			fatal_f("dup2: %s", strerror(errno));
		sock = STDERR_FILENO + 1;
		اگر (fcntl(sock, F_SETFD, 0) == -1) /* keep the socket on exec */
			debug3_f("fcntl F_SETFD: %s", strerror(errno));
		closefrom(sock + 1);

		debug3_f("[child] pid=%ld, exec %s",
		    (طویل)getpid(), راستہ_SSH_کلید_SIGN);
		execl(راستہ_SSH_کلید_SIGN, راستہ_SSH_کلید_SIGN, (حرف *)تہی);
		fatal_f("exec(%s): %s", راستہ_SSH_کلید_SIGN,
		    strerror(errno));
	}
	close(from[1]);
	close(مقصد[0]);
	sock = STDERR_FILENO + 1;

	اگر ((b = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	/* send # of sock, data to be signed */
	اگر ((r = sshbuf_put_u32(b, sock)) != 0 ||
	    (r = sshbuf_put_string(b, ڈیٹا, datalen)) != 0)
		fatal_fr(r, "buffer error");
	اگر (ssh_پیغام_send(مقصد[1], نسخہ, b) == -1)
		fatal_f("couldn't send request");
	sshbuf_reset(b);
	r = ssh_پیغام_recv(from[0], b);
	close(from[0]);
	close(مقصد[1]);
	اگر (r < 0) {
		error_f("no reply");
		جاؤ fail;
	}

	errno = 0;
	جب (waitpid(pid, &حالت_2, 0) == -1) {
		اگر (errno != EINTR) {
			error_f("waitpid %ld: %s", (طویل)pid, strerror(errno));
			جاؤ fail;
		}
	}
	اگر (!WIFEXITED(حالت_2)) {
		error_f("exited abnormally");
		جاؤ fail;
	}
	اگر (WEXITSTATUS(حالت_2) != 0) {
		error_f("exited with status %d", WEXITSTATUS(حالت_2));
		جاؤ fail;
	}
	اگر ((r = sshbuf_get_u8(b, &rversion)) != 0) {
		error_fr(r, "buffer error");
		جاؤ fail;
	}
	اگر (rversion != نسخہ) {
		error_f("bad version");
		جاؤ fail;
	}
	اگر ((r = sshbuf_get_string(b, sigp, lenp)) != 0) {
		error_fr(r, "buffer error");
 fail:
		ssh_signal(SIGCHLD, osigchld);
		sshbuf_free(b);
		واپس -1;
	}
	ssh_signal(SIGCHLD, osigchld);
	sshbuf_free(b);

	واپس 0;
}

ساکن صحیح
userauth_hostbased(ساخت ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	ساخت sshkey *نجی = تہی;
	ساخت sshbuf *b = تہی;
	u_char *sig = تہی, *keyblob = تہی;
	حرف *fp = تہی, *chost = تہی, *lname = تہی;
	سائز_t siglen = 0, keylen = 0;
	صحیح i, r, success = 0;

	اگر (authctxt->ktypes == تہی) {
		authctxt->oktypes = xstrdup(options.hostbased_accepted_algos);
		authctxt->ktypes = authctxt->oktypes;
	}

	/*
	 * Work through each listed type pattern in HostbasedAcceptedAlgorithms,
	 * trying each hostkey that matches the type in turn.
	 */
	برائے (;;) {
		اگر (authctxt->فعال_ktype == تہی)
			authctxt->فعال_ktype = strsep(&authctxt->ktypes, ",");
		اگر (authctxt->فعال_ktype == تہی ||
		    *authctxt->فعال_ktype == '\0')
			توڑو;
		debug3_f("trying key type %s", authctxt->فعال_ktype);

		/* check for a useful key */
		نجی = تہی;
		برائے (i = 0; i < authctxt->sensitive->nkeys; i++) {
			اگر (authctxt->sensitive->کلیدیں[i] == تہی ||
			    authctxt->sensitive->کلیدیں[i]->type == کلید_UNSPEC)
				جاری;
			اگر (!sshkey_مطابقت_keyname_مقصد_sigalgs(
			    sshkey_ssh_name(authctxt->sensitive->کلیدیں[i]),
			    authctxt->فعال_ktype))
				جاری;
			/* we take and free the key */
			نجی = authctxt->sensitive->کلیدیں[i];
			authctxt->sensitive->کلیدیں[i] = تہی;
			توڑو;
		}
		/* Found one */
		اگر (نجی != تہی)
			توڑو;
		/* No more keys of this type; advance */
		authctxt->فعال_ktype = تہی;
	}
	اگر (نجی == تہی) {
		آزاد(authctxt->oktypes);
		authctxt->oktypes = authctxt->ktypes = تہی;
		authctxt->فعال_ktype = تہی;
		debug("No more client hostkeys for hostbased authentication.");
		جاؤ برآمد;
	}

	اگر ((fp = sshkey_fingerprint(نجی, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == تہی) {
		error_f("sshkey_fingerprint failed");
		جاؤ برآمد;
	}
	debug_f("trying hostkey %s %s using sigalg %s",
	    sshkey_ssh_name(نجی), fp, authctxt->فعال_ktype);

	/* figure out a name for the client host */
	lname = get_local_name(ssh_packet_get_connection_اندر(ssh));
	اگر (lname == تہی) {
		error_f("cannot get local ipaddr/name");
		جاؤ برآمد;
	}

	/* XXX sshbuf_put_stringf? */
	xasprintf(&chost, "%s.", lname);
	debug2_f("chost %s", chost);

	/* construct data */
	اگر ((b = sshbuf_new()) == تہی) {
		error_f("sshbuf_new failed");
		جاؤ برآمد;
	}
	اگر ((r = sshkey_مقصد_blob(نجی, &keyblob, &keylen)) != 0) {
		error_fr(r, "sshkey_to_blob");
		جاؤ برآمد;
	}
	اگر ((r = sshbuf_put_stringb(b, ssh->kex->session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_پیغام_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->server_user)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->طریقہ->name)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->فعال_ktype)) != 0 ||
	    (r = sshbuf_put_string(b, keyblob, keylen)) != 0 ||
	    (r = sshbuf_put_cstring(b, chost)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->local_user)) != 0) {
		error_fr(r, "buffer error");
		جاؤ برآمد;
	}

#اگر_تعریف_شدہ DEBUG_PK
	sshbuf_dump(b, stderr);
#اگر_ختم
	اگر ((r = ssh_keysign(ssh, نجی, &sig, &siglen,
	    sshbuf_ptr(b), sshbuf_len(b))) != 0) {
		error("sign using hostkey %s %s failed",
		    sshkey_ssh_name(نجی), fp);
		جاؤ برآمد;
	}
	اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->طریقہ->name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->فعال_ktype)) != 0 ||
	    (r = sshpkt_put_string(ssh, keyblob, keylen)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, chost)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->local_user)) != 0 ||
	    (r = sshpkt_put_string(ssh, sig, siglen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_fr(r, "packet error");
		جاؤ برآمد;
	}
	success = 1;

 برآمد:
	اگر (sig != تہی)
		freezero(sig, siglen);
	آزاد(keyblob);
	آزاد(lname);
	آزاد(fp);
	آزاد(chost);
	sshkey_free(نجی);
	sshbuf_free(b);

	واپس success;
}

/* find auth method */

/*
 * given auth method name, if configurable options permit this method fill
 * in auth_ident field and return true, otherwise return false.
 */
ساکن صحیح
authmethod_is_enabled(Authmethod *طریقہ)
{
	اگر (طریقہ == تہی)
		واپس 0;
	/* return false if options indicate this method is disabled */
	اگر  (طریقہ->enabled == تہی || *طریقہ->enabled == 0)
		واپس 0;
	/* return false if batch mode is enabled but method needs interactive mode */
	اگر  (طریقہ->batch_flag != تہی && *طریقہ->batch_flag != 0)
		واپس 0;
	واپس 1;
}

ساکن Authmethod *
authmethod_lookup(ثابت حرف *name)
{
	Authmethod *طریقہ = تہی;
	اگر (name != تہی)
		برائے (طریقہ = authmethods; طریقہ->name != تہی; طریقہ++)
			اگر (strcmp(name, طریقہ->name) == 0)
				واپس طریقہ;
	debug2("Unrecognized authentication method name: %s", name ? name : "NULL");
	واپس تہی;
}

/* XXX internal state */
ساکن Authmethod *current = تہی;
ساکن حرف *supported = تہی;
ساکن حرف *preferred = تہی;

/*
 * Given the authentication method list sent by the server, return the
 * next method we should try.  If the server initially sends a nil list,
 * use a built-in default list.
 */
ساکن Authmethod *
authmethod_get(حرف *authlist)
{
	حرف *name = تہی;
	u_int اگلا;

	/* Use a suitable default if we're passed a nil list.  */
	اگر (authlist == تہی || لڑی_لمبائی(authlist) == 0)
		authlist = options.preferred_authentications;

	اگر (supported == تہی || strcmp(authlist, supported) != 0) {
		debug3("start over, passed a different list %s", authlist);
		آزاد(supported);
		supported = xstrdup(authlist);
		preferred = options.preferred_authentications;
		debug3("preferred %s", preferred);
		current = تہی;
	} ورنہ اگر (current != تہی && authmethod_is_enabled(current))
		واپس current;

	برائے (;;) {
		اگر ((name = مطابقت_list(preferred, supported, &اگلا)) == تہی) {
			debug("No more authentication methods to try.");
			current = تہی;
			واپس تہی;
		}
		preferred += اگلا;
		debug3("authmethod_lookup %s", name);
		debug3("remaining preferred: %s", preferred);
		اگر ((current = authmethod_lookup(name)) != تہی &&
		    authmethod_is_enabled(current)) {
			debug3("authmethod_is_enabled %s", name);
			debug("Next authentication method: %s", name);
			آزاد(name);
			واپس current;
		}
		آزاد(name);
	}
}

ساکن حرف *
authmethods_get(خالی)
{
	Authmethod *طریقہ = تہی;
	ساخت sshbuf *b;
	حرف *list;
	صحیح r;

	اگر ((b = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	برائے (طریقہ = authmethods; طریقہ->name != تہی; طریقہ++) {
		اگر (authmethod_is_enabled(طریقہ)) {
			اگر ((r = sshbuf_putf(b, "%s%s",
			    sshbuf_len(b) ? "," : "", طریقہ->name)) != 0)
				fatal_fr(r, "buffer error");
		}
	}
	اگر ((list = sshbuf_dup_string(b)) == تہی)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	واپس list;
}
