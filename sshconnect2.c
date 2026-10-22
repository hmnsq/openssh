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
#جے_انت

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

#جے_تعریف_شدہ GSSAPI
#ضمن "ssh-gss.h"
#جے_انت

/* import */
خارجي Options options;

/*
 * SSH2 key exchange
 */

ساكن حرف *xxx_host;
ساكن بنية sockaddr_storage xxx_hostaddr;
ساكن ثابت بنية ssh_conn_info *xxx_conn_info;
ساكن صحيح کلید_type_allowed(بنية sshkey *, ثابت حرف *);

ساكن صحيح
verify_host_کلید_callback(بنية sshkey *hostkey, بنية ssh *ssh)
{
	صحيح r;

	إذا ((r = sshkey_check_rsa_لمائی(hostkey,
	    options.required_rsa_ناپ)) != 0)
		fatal_r(r, "Bad server host key");
	إذا (!کلید_type_allowed(hostkey, options.hostkeyalgorithms)) {
		fatal("Server host key %s not in HostKeyAlgorithms",
		    sshkey_ssh_name(hostkey));
	}
	إذا (verify_host_کلید(xxx_host, (بنية sockaddr *)&xxx_hostaddr, hostkey,
	    xxx_conn_info) != 0)
		fatal("Host key verification failed.");
	أرجع 0;
}

/* Returns the first item from a comma-separated algorithm list */
ساكن حرف *
پہلا_alg(ثابت حرف *algs)
{
	حرف *ret, *cp;

	ret = xstrdup(algs);
	إذا ((cp = strchr(ret, ',')) != عدم)
		*cp = '\0';
	أرجع ret;
}

ساكن حرف *
ترتیب_hostkeyalgs(حرف *host, بنية sockaddr *hostaddr, u_short پورٹ,
    ثابت بنية ssh_conn_info *cinfo)
{
	حرف *oavail = عدم, *avail = عدم, *پہلا = عدم, *آخری = عدم;
	حرف *alg = عدم, *hostname = عدم, *ret = عدم, *بہترین = عدم;
	ناپ_t maxlen;
	بنية hostkeys *hostkeys = عدم;
	صحيح ktype;
	u_int i;

	/* Find all hostkeys for this hostname */
	get_hostfile_hostname_ipaddr(host, hostaddr, پورٹ, &hostname, عدم);
	hostkeys = init_hostkeys();
	لكل (i = 0; i < options.عدد_user_hostfiles; i++)
		لدو_hostkeys(hostkeys, hostname, options.user_hostfiles[i], 0);
	لكل (i = 0; i < options.عدد_system_hostfiles; i++) {
		لدو_hostkeys(hostkeys, hostname,
		    options.system_hostfiles[i], 0);
	}
	إذا (options.معلوم_hosts_command != عدم) {
		لدو_hostkeys_command(hostkeys, options.معلوم_hosts_command,
		    "ORDER", cinfo, عدم, hostname);
	}
	/*
	 * If a plain public key exists that matches the type of the best
	 * preference HostkeyAlgorithms, then use the whole list as is.
	 * Note that we ignore whether the best preference algorithm is a
	 * certificate type, as sshconnect.c will downgrade certs to
	 * plain keys if necessary.
	 */
	بہترین = پہلا_alg(options.hostkeyalgorithms);
	إذا (lookup_کلید_وچ_hostkeys_by_type(hostkeys,
	    sshkey_type_plain(sshkey_type_from_name(بہترین)),
	    sshkey_ecdsa_nid_from_name(بہترین), عدم)) {
		debug3_f("have matching best-preference key type %s, "
		    "using HostkeyAlgorithms verbatim", بہترین);
		ret = xstrdup(options.hostkeyalgorithms);
		اذهب باہرلا;
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

#تعریف_کرو ALG_APPEND(منزل, from) \
	افعل { \
		إذا (*منزل != '\0') \
			strlcat(منزل, ",", maxlen); \
		strlcat(منزل, from, maxlen); \
	} طالما (0)

	طالما ((alg = strsep(&avail, ",")) && *alg != '\0') {
		إذا ((ktype = sshkey_type_from_name(alg)) == کلید_UNSPEC)
			fatal_f("unknown alg %s", alg);
		/*
		 * If we have a @cert-authority marker in known_hosts then
		 * prefer all certificate algorithms.
		 */
		إذا (sshkey_type_is_cert(ktype) &&
		    lookup_marker_وچ_hostkeys(hostkeys, MRK_CA)) {
			ALG_APPEND(پہلا, alg);
			استمر;
		}
		/* If the key appears in known_hosts then prefer it */
		إذا (lookup_کلید_وچ_hostkeys_by_type(hostkeys,
		    sshkey_type_plain(ktype),
		    sshkey_ecdsa_nid_from_name(alg), عدم)) {
			ALG_APPEND(پہلا, alg);
			استمر;
		}
		/* Otherwise, put it last */
		ALG_APPEND(آخری, alg);
	}
#تعریف_رد ALG_APPEND
	xasprintf(&ret, "%s%s%s", پہلا,
	    (*پہلا == '\0' || *آخری == '\0') ? "" : ",", آخری);
	إذا (*پہلا != '\0')
		debug3_f("prefer hostkeyalgs: %s", پہلا);
	وإلا
		debug3_f("no algorithms matched; accept original");
 باہرلا:
	حرر(بہترین);
	حرر(پہلا);
	حرر(آخری);
	حرر(hostname);
	حرر(oavail);
	free_hostkeys(hostkeys);

	أرجع ret;
}

فراغ
ssh_kex2(بنية ssh *ssh, حرف *host, بنية sockaddr_storage *hostaddr,
    u_short پورٹ, ثابت بنية ssh_conn_info *cinfo)
{
	حرف *myproposal[PROPOSAL_MAX];
	حرف *all_کلید, *hkalgs = عدم;
	صحيح r, use_معلوم_hosts_ترتیب = 0;

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
	إذا (options.hostkeyalgorithms == عدم ||
	    options.hostkeyalgorithms[0] == '-' ||
	    options.hostkeyalgorithms[0] == '+')
		use_معلوم_hosts_ترتیب = 1;

	/* Expand or fill in HostkeyAlgorithms */
	all_کلید = sshkey_alg_list(0, 0, 1, ',');
	إذا ((r = kex_assemble_ناں(&options.hostkeyalgorithms,
	    kex_default_pk_alg(), all_کلید)) != 0)
		fatal_fr(r, "kex_assemble_namelist");
	حرر(all_کلید);

	إذا (use_معلوم_hosts_ترتیب) {
		hkalgs = ترتیب_hostkeyalgs(host, (بنية sockaddr *)hostaddr,
		    پورٹ, cinfo);
	}

	kex_proposal_populate_entries(ssh, myproposal,
	    options.kex_algorithms, options.ciphers, options.macs,
	    compression_alg_list(options.compression),
	    hkalgs ? hkalgs : options.hostkeyalgorithms);

	حرر(hkalgs);

	/* start key exchange */
	إذا ((r = kex_تیاری(ssh, myproposal)) != 0)
		fatal_r(r, "kex_setup");
#جے_تعریف_شدہ WITH_OPENSSL
	ssh->kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GEX_SHA1] = kexgex_client;
	ssh->kex->kex[KEX_DH_GEX_SHA256] = kexgex_client;
	ssh->kex->kex[KEX_ECDH_SHA2] = kex_gen_client;
#جے_انت
	ssh->kex->kex[KEX_C25519_SHA256] = kex_gen_client;
	ssh->kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_client;
	ssh->kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_client;
	ssh->kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_client;
	ssh->kex->verify_host_کلید=&verify_host_کلید_callback;

	ssh_dispatch_لگاتار_fatal(ssh, DISPATCH_بلاک, &ssh->kex->پورا);
	kex_proposal_free_entries(myproposal);

#جے_تعریف_شدہ DEBUG_KEXDH
	/* send 1st encrypted/maced/compressed message */
	إذا ((r = sshpkt_شروع(ssh, SSH2_پیغام_IGNORE)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "markus")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send packet");
#جے_انت
}

/*
 * Authenticate user
 */

تعريفنوع بنية cauthctxt Authctxt;
تعريفنوع بنية cauthmethod Authmethod;
تعريفنوع بنية پچھان_تت_2 پچھان_تت;
تعريفنوع بنية idlist Idlist;

بنية پچھان_تت_2 {
	TAILQ_ENTRY(پچھان_تت_2) اگلا;
	صحيح	agent_fd;		/* >=0 if agent supports key */
	بنية sshkey	*کلید;		/* public/private key */
	حرف	*filename;		/* comment for agent-only keys */
	صحيح	tried;
	صحيح	isprivate;		/* key points to the private key */
	صحيح	userprovided;
};
TAILQ_HEAD(idlist, پچھان_تت_2);

بنية cauthctxt {
	ثابت حرف *server_user;
	ثابت حرف *local_user;
	ثابت حرف *host;
	ثابت حرف *service;
	بنية cauthmethod *طریقہ;
	sig_atomic_t success;
	حرف *authlist;
#جے_تعریف_شدہ GSSAPI
	/* gssapi */
	gss_OID_سیٹ gss_supported_mechs;
	u_int mech_tried;
#جے_انت
	/* pubkey */
	بنية idlist کلیدیں;
	صحيح agent_fd;
	/* hostbased */
	Sensitive *sensitive;
	حرف *oktypes, *ktypes;
	ثابت حرف *سرگرم_ktype;
	/* kbd-interactive */
	صحيح info_req_تکیا;
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

ساكن صحيح داخلہ_userauth_service_accept(صحيح, uint32_t, بنية ssh *);
ساكن صحيح داخلہ_userauth_success(صحيح, uint32_t, بنية ssh *);
ساكن صحيح داخلہ_userauth_failure(صحيح, uint32_t, بنية ssh *);
ساكن صحيح داخلہ_userauth_banner(صحيح, uint32_t, بنية ssh *);
ساكن صحيح داخلہ_userauth_error(صحيح, uint32_t, بنية ssh *);
ساكن صحيح داخلہ_userauth_info_req(صحيح, uint32_t, بنية ssh *);
ساكن صحيح داخلہ_userauth_pk_ok(صحيح, uint32_t, بنية ssh *);
ساكن صحيح داخلہ_userauth_passwd_changereq(صحيح, uint32_t, بنية ssh *);

ساكن صحيح userauth_none(بنية ssh *);
ساكن صحيح userauth_pubkey(بنية ssh *);
ساكن صحيح userauth_passwd(بنية ssh *);
ساكن صحيح userauth_kbdint(بنية ssh *);
ساكن صحيح userauth_hostbased(بنية ssh *);

#جے_تعریف_شدہ GSSAPI
ساكن صحيح userauth_gssapi(بنية ssh *);
ساكن فراغ userauth_gssapi_cleanup(بنية ssh *);
ساكن صحيح داخلہ_gssapi_response(صحيح type, uint32_t, بنية ssh *);
ساكن صحيح داخلہ_gssapi_token(صحيح type, uint32_t, بنية ssh *);
ساكن صحيح داخلہ_gssapi_error(صحيح, uint32_t, بنية ssh *);
ساكن صحيح داخلہ_gssapi_errtok(صحيح, uint32_t, بنية ssh *);
#جے_انت

فراغ	userauth(بنية ssh *, حرف *);

ساكن فراغ pubkey_cleanup(بنية ssh *);
ساكن صحيح sign_and_send_pubkey(بنية ssh *ssh, پچھان_تت *);
ساكن فراغ pubkey_prepare(بنية ssh *, Authctxt *);
ساكن فراغ pubkey_reset(Authctxt *);
ساكن بنية sshkey *لدو_پچھان_تت_file(پچھان_تت *);

ساكن Authmethod *authmethod_get(حرف *authlist);
ساكن Authmethod *authmethod_lookup(ثابت حرف *name);
ساكن حرف *authmethods_get(فراغ);

Authmethod authmethods[] = {
#جے_تعریف_شدہ GSSAPI
	{"gssapi-with-mic",
		userauth_gssapi,
		userauth_gssapi_cleanup,
		&options.gss_authentication,
		عدم},
#جے_انت
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
		&options.batch_منوال},
	{"password",
		userauth_passwd,
		عدم,
		&options.password_authentication,
		&options.batch_منوال},
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
	authctxt.طریقہ = authmethod_lookup("none");
	authctxt.authlist = عدم;
	authctxt.methoddata = عدم;
	authctxt.sensitive = sensitive;
	authctxt.سرگرم_ktype = authctxt.oktypes = authctxt.ktypes = عدم;
	authctxt.info_req_تکیا = 0;
	authctxt.attempt_kbdint = 0;
	authctxt.attempt_passwd = 0;
#إذا GSSAPI
	authctxt.gss_supported_mechs = عدم;
	authctxt.mech_tried = 0;
#جے_انت
	authctxt.agent_fd = -1;
	إذا (authctxt.طریقہ == عدم)
		fatal_f("internal error: cannot send userauth none request");

	إذا ((r = sshpkt_شروع(ssh, SSH2_پیغام_SERVICE_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "ssh-userauth")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh->authctxt = &authctxt;
	ssh_dispatch_init(ssh, &داخلہ_userauth_error);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_EXT_INFO, kex_داخلہ_ext_info);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_SERVICE_ACCEPT, &داخلہ_userauth_service_accept);
	ssh_dispatch_لگاتار_fatal(ssh, DISPATCH_بلاک, &authctxt.success);	/* loop until success */
	pubkey_cleanup(ssh);
#جے_تعریف_شدہ GSSAPI
	إذا (authctxt.gss_supported_mechs != عدم) {
		u_int ms;

		gss_release_oid_سیٹ(&ms, &authctxt.gss_supported_mechs);
		authctxt.gss_supported_mechs = عدم;
	}
#جے_انت
	ssh->authctxt = عدم;

	ssh_dispatch_range(ssh, SSH2_پیغام_USERAUTH_MIN, SSH2_پیغام_USERAUTH_MAX, عدم);

	إذا (!authctxt.success)
		fatal("Authentication failed.");
	إذا (ssh_packet_connection_is_on_socket(ssh)) {
		verbose("Authenticated to %s ([%s]:%d) using \"%s\".", host,
		    ssh_remote_ipaddr(ssh), ssh_remote_پورٹ(ssh),
		    authctxt.طریقہ->name);
	} وإلا {
		verbose("Authenticated to %s (via proxy) using \"%s\".", host,
		    authctxt.طریقہ->name);
	}
}

ساكن صحيح
داخلہ_userauth_service_accept(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	صحيح r;

	إذا (ssh_packet_بچیا(ssh) > 0) {
		حرف *جواب;

		إذا ((r = sshpkt_get_cstring(ssh, &جواب, عدم)) != 0)
			اذهب باہرلا;
		debug2("service_accept: %s", جواب);
		حرر(جواب);
	} وإلا {
		debug2("buggy server: service_accept w/o service");
	}
	إذا ((r = sshpkt_get_سرا(ssh)) != 0)
		اذهب باہرلا;
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
 باہرلا:
	أرجع r;
}

فراغ
userauth(بنية ssh *ssh, حرف *authlist)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;

	إذا (authctxt->طریقہ != عدم && authctxt->طریقہ->cleanup != عدم)
		authctxt->طریقہ->cleanup(ssh);

	حرر(authctxt->methoddata);
	authctxt->methoddata = عدم;
	إذا (authlist == عدم) {
		authlist = authctxt->authlist;
	} وإلا {
		حرر(authctxt->authlist);
		authctxt->authlist = authlist;
	}
	لكل (;;) {
		Authmethod *طریقہ = authmethod_get(authlist);
		إذا (طریقہ == عدم)
			fatal("%s@%s: Permission denied (%s).",
			    authctxt->server_user, authctxt->host, authlist);
		authctxt->طریقہ = طریقہ;

		/* reset the per method handler */
		ssh_dispatch_range(ssh, SSH2_پیغام_USERAUTH_فی_طریقہ_MIN,
		    SSH2_پیغام_USERAUTH_فی_طریقہ_MAX, عدم);

		/* and try new method */
		إذا (طریقہ->userauth(ssh) != 0) {
			debug2("we sent a %s packet, wait for reply", طریقہ->name);
			اكسر;
		} وإلا {
			debug2("we did not send a packet, disable method");
			طریقہ->enabled = عدم;
		}
	}
}

ساكن صحيح
داخلہ_userauth_error(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	fatal_f("bad message during authentication: type %d", type);
	أرجع 0;
}

ساكن صحيح
داخلہ_userauth_banner(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	حرف *پیغام = عدم;
	ناپ_t len;
	صحيح r;

	debug3_f("entering");
	إذا ((r = sshpkt_get_cstring(ssh, &پیغام, &len)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, عدم, عدم)) != 0)
		اذهب باہرلا;
	إذا (len > 0 && options.log_level >= SYSLOG_LEVEL_INFO)
		fmprintf(stderr, "%s", پیغام);
	r = 0;
 باہرلا:
	حرر(پیغام);
	أرجع r;
}

ساكن صحيح
داخلہ_userauth_success(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	إذا (authctxt == عدم)
		fatal_f("no authentication context");
	حرر(authctxt->authlist);
	authctxt->authlist = عدم;
	إذا (authctxt->طریقہ != عدم && authctxt->طریقہ->cleanup != عدم)
		authctxt->طریقہ->cleanup(ssh);
	حرر(authctxt->methoddata);
	authctxt->methoddata = عدم;
	authctxt->success = 1;			/* break out */
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_EXT_INFO, dispatch_protocol_error);
	أرجع 0;
}

#إذا 0
ساكن صحيح
داخلہ_userauth_success_unexpected(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	إذا (authctxt == عدم)
		fatal_f("no authentication context");

	fatal("Unexpected authentication success during %s.",
	    authctxt->طریقہ->name);
	أرجع 0;
}
#جے_انت

ساكن صحيح
داخلہ_userauth_failure(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	حرف *authlist = عدم;
	u_char partial;

	إذا (authctxt == عدم)
		fatal("input_userauth_failure: no authentication context");

	إذا (sshpkt_get_cstring(ssh, &authlist, عدم) != 0 ||
	    sshpkt_get_u8(ssh, &partial) != 0 ||
	    sshpkt_get_سرا(ssh) != 0)
		اذهب باہرلا;

	إذا (partial != 0) {
		verbose("Authenticated using \"%s\" with partial success.",
		    authctxt->طریقہ->name);
		/* reset state */
		pubkey_reset(authctxt);
	}
	debug("Authentications that can continue: %s", authlist);

	userauth(ssh, authlist);
	authlist = عدم;
 باہرلا:
	حرر(authlist);
	أرجع 0;
}

/*
 * Format an identity for logging including filename, key type, fingerprint
 * and location (agent, etc.). Caller must free.
 */
ساكن حرف *
format_پچھان_تت(پچھان_تت *id)
{
	حرف *fp = عدم, *ret = عدم;
	ثابت حرف *note = "";

	إذا (id->کلید != عدم) {
		fp = sshkey_fingerprint(id->کلید, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
	}
	إذا (id->کلید) {
		إذا ((id->کلید->flags & SSHKEY_FLAG_EXT) != 0)
			note = " token";
		وإلا إذا (sshkey_is_sk(id->کلید))
			note = " authenticator";
	}
	xasprintf(&ret, "%s %s%s%s%s%s%s",
	    id->filename,
	    id->کلید ? sshkey_type(id->کلید) : "", id->کلید ? " " : "",
	    fp ? fp : "",
	    id->userprovided ? " explicit" : "", note,
	    id->agent_fd != -1 ? " agent" : "");
	حرر(fp);
	أرجع ret;
}

ساكن صحيح
داخلہ_userauth_pk_ok(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	بنية sshkey *کلید = عدم;
	بنية sshbuf *keyblob = عدم;
	پچھان_تت *id = عدم;
	صحيح pktype, لبھیا = 0, گھلیا = 0;
	حرف *pkalg = عدم, *fp = عدم, *ident = عدم;
	صحيح r;

	إذا (authctxt == عدم)
		fatal_f("no authentication context");

	إذا ((r = sshpkt_get_cstring(ssh, &pkalg, عدم)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0 ||
	    (r = sshpkt_get_سرا(ssh)) != 0)
		اذهب پورا;

	إذا (میل_نمونہ_list(pkalg, options.pubkey_accepted_algos, 0) != 1) {
		error_f("server replied to PK_OK with signature type %s not "
		    "in PubkeyAcceptedAlgorithms", pkalg);
		r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		اذهب پورا;
	}
	إذا ((pktype = sshkey_type_from_name(pkalg)) == کلید_UNSPEC) {
		debug_f("server sent unknown pkalg %s", pkalg);
		r = SSH_ERR_INVALID_FORMAT;
		اذهب پورا;
	}
	/* inner key type should match signature type */
	إذا ((r = sshkey_fromb_allowlist(keyblob, &کلید, pkalg, عدم)) != 0) {
		debug_r(r, "no key from blob. pkalg %s", pkalg);
		اذهب پورا;
	}
	إذا (کلید->type != pktype) {
		error("input_userauth_pk_ok: type mismatch "
		    "for decoded key (received %d, expected %d)",
		    کلید->type, pktype);
		r = SSH_ERR_INVALID_FORMAT;
		اذهب پورا;
	}

	/*
	 * search keys in the reverse order, because last candidate has been
	 * moved to the end of the queue.  this also avoids confusion by
	 * duplicate keys
	 */
	TAILQ_FOREACH_الٹ(id, &authctxt->کلیدیں, idlist, اگلا) {
		إذا (sshkey_equal(کلید, id->کلید)) {
			لبھیا = 1;
			اكسر;
		}
	}
	إذا (!لبھیا || id == عدم) {
		fp = sshkey_fingerprint(کلید, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		error_f("server replied with unknown key: %s %s",
		    sshkey_type(کلید), fp == عدم ? "<ERROR>" : fp);
		r = SSH_ERR_INVALID_FORMAT;
		اذهب پورا;
	}
	ident = format_پچھان_تت(id);
	debug("Server accepts key: %s", ident);
	گھلیا = sign_and_send_pubkey(ssh, id);
	r = 0;
 پورا:
	sshkey_free(کلید);
	sshbuf_free(keyblob);
	حرر(ident);
	حرر(fp);
	حرر(pkalg);

	/* try another method if we did not send a packet */
	إذا (r == 0 && گھلیا == 0)
		userauth(ssh, عدم);
	أرجع r;
}

#جے_تعریف_شدہ GSSAPI
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
	طالما (authctxt->mech_tried < authctxt->gss_supported_mechs->گنتی &&
	    !ok) {
		mech = &authctxt->gss_supported_mechs->
		    elements[authctxt->mech_tried];
		/* My DER encoding requires length<128 */
		إذا (mech->لمائی < 128 && ssh_gssapi_check_mechanism(&gssctxt,
		    mech, authctxt->host)) {
			ok = 1; /* Mechanism works */
		} وإلا {
			authctxt->mech_tried++;
		}
	}

	إذا (!ok || mech == عدم)
		أرجع 0;

	authctxt->methoddata=(فراغ *)gssctxt;

	إذا ((r = sshpkt_شروع(ssh, SSH2_پیغام_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->طریقہ->name)) != 0 ||
	    (r = sshpkt_put_u32(ssh, 1)) != 0 ||
	    (r = sshpkt_put_u32(ssh, (mech->لمائی) + 2)) != 0 ||
	    (r = sshpkt_put_u8(ssh, SSH_GSS_OIDTYPE)) != 0 ||
	    (r = sshpkt_put_u8(ssh, mech->لمائی)) != 0 ||
	    (r = sshpkt_put(ssh, mech->elements, mech->لمائی)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_GSSAPI_RESPONSE, &داخلہ_gssapi_response);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_GSSAPI_TOKEN, &داخلہ_gssapi_token);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_GSSAPI_ERROR, &داخلہ_gssapi_error);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_GSSAPI_ERRTOK, &داخلہ_gssapi_errtok);

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
	gss_بفر_desc send_tok = GSS_C_خالی_تھاواں_بفر;
	gss_بفر_desc mic = GSS_C_خالی_تھاواں_بفر;
	gss_بفر_desc gssbuf;
	OM_uint32 حالت, ms, flags;
	صحيح r;

	حالت = ssh_gssapi_init_ctx(gssctxt, options.gss_deleg_creds,
	    recv_tok, &send_tok, &flags);

	إذا (send_tok.لمائی > 0) {
		u_char type = GSS_ERROR(حالت) ?
		    SSH2_پیغام_USERAUTH_GSSAPI_ERRTOK :
		    SSH2_پیغام_USERAUTH_GSSAPI_TOKEN;

		إذا ((r = sshpkt_شروع(ssh, type)) != 0 ||
		    (r = sshpkt_put_string(ssh, send_tok.قدر,
		    send_tok.لمائی)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send %u packet", type);

		gss_release_بفر(&ms, &send_tok);
	}

	إذا (حالت == GSS_S_COMPLETE) {
		/* send either complete or MIC, depending on mechanism */
		إذا (!(flags & GSS_C_INTEG_FLAG)) {
			إذا ((r = sshpkt_شروع(ssh,
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

			إذا ((gssbuf.قدر = sshbuf_mutable_ptr(b)) == عدم)
				fatal_f("sshbuf_mutable_ptr failed");
			gssbuf.لمائی = sshbuf_len(b);

			حالت = ssh_gssapi_sign(gssctxt, &gssbuf, &mic);

			إذا (!GSS_ERROR(حالت)) {
				إذا ((r = sshpkt_شروع(ssh,
				    SSH2_پیغام_USERAUTH_GSSAPI_MIC)) != 0 ||
				    (r = sshpkt_put_string(ssh, mic.قدر,
				    mic.لمائی)) != 0 ||
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
داخلہ_gssapi_response(صحيح type, uint32_t plen, بنية ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	ناپ_t oidlen;
	u_char *oidv = عدم;
	صحيح r;

	إذا (authctxt == عدم)
		fatal("input_gssapi_response: no authentication context");
	gssctxt = authctxt->methoddata;

	/* Setup our OID */
	إذا ((r = sshpkt_get_string(ssh, &oidv, &oidlen)) != 0)
		اذهب پورا;

	إذا (oidlen <= 2 ||
	    oidv[0] != SSH_GSS_OIDTYPE ||
	    oidv[1] != oidlen - 2) {
		debug("Badly encoded mechanism OID received");
		userauth(ssh, عدم);
		اذهب ok;
	}

	إذا (!ssh_gssapi_check_oid(gssctxt, oidv + 2, oidlen - 2))
		fatal("Server returned different OID than expected");

	إذا ((r = sshpkt_get_سرا(ssh)) != 0)
		اذهب پورا;

	إذا (GSS_ERROR(process_gssapi_token(ssh, GSS_C_NO_بفر))) {
		/* Start again with next method on list */
		debug("Trying to start again");
		userauth(ssh, عدم);
		اذهب ok;
	}
 ok:
	r = 0;
 پورا:
	حرر(oidv);
	أرجع r;
}

ساكن صحيح
داخلہ_gssapi_token(صحيح type, uint32_t plen, بنية ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	gss_بفر_desc recv_tok;
	u_char *p = عدم;
	ناپ_t len;
	OM_uint32 حالت;
	صحيح r;

	إذا (authctxt == عدم)
		fatal("input_gssapi_response: no authentication context");

	إذا ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_سرا(ssh)) != 0)
		اذهب باہرلا;

	recv_tok.قدر = p;
	recv_tok.لمائی = len;
	حالت = process_gssapi_token(ssh, &recv_tok);

	/* Start again with the next method in the list */
	إذا (GSS_ERROR(حالت)) {
		userauth(ssh, عدم);
		/* ok */
	}
	r = 0;
 باہرلا:
	حرر(p);
	أرجع r;
}

ساكن صحيح
داخلہ_gssapi_errtok(صحيح type, uint32_t plen, بنية ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	gss_بفر_desc send_tok = GSS_C_خالی_تھاواں_بفر;
	gss_بفر_desc recv_tok;
	OM_uint32 ms;
	u_char *p = عدم;
	ناپ_t len;
	صحيح r;

	إذا (authctxt == عدم)
		fatal("input_gssapi_response: no authentication context");
	gssctxt = authctxt->methoddata;

	إذا ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_سرا(ssh)) != 0) {
		حرر(p);
		أرجع r;
	}

	/* Stick it into GSSAPI and see what it says */
	recv_tok.قدر = p;
	recv_tok.لمائی = len;
	(فراغ)ssh_gssapi_init_ctx(gssctxt, options.gss_deleg_creds,
	    &recv_tok, &send_tok, عدم);
	حرر(p);
	gss_release_بفر(&ms, &send_tok);

	/* Server will be returning a failed packet after this one */
	أرجع 0;
}

ساكن صحيح
داخلہ_gssapi_error(صحيح type, uint32_t plen, بنية ssh *ssh)
{
	حرف *پیغام = عدم;
	حرف *lang = عدم;
	صحيح r;

	إذا ((r = sshpkt_get_u32(ssh, عدم)) != 0 ||	/* maj */
	    (r = sshpkt_get_u32(ssh, عدم)) != 0 ||	/* min */
	    (r = sshpkt_get_cstring(ssh, &پیغام, عدم)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, عدم)) != 0)
		اذهب باہرلا;
	r = sshpkt_get_سرا(ssh);
	debug("Server GSSAPI Error:\n%s", پیغام);
 باہرلا:
	حرر(پیغام);
	حرر(lang);
	أرجع r;
}
#جے_انت /* GSSAPI */

ساكن صحيح
userauth_none(بنية ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	صحيح r;

	/* initial userauth request */
	إذا ((r = sshpkt_شروع(ssh, SSH2_پیغام_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->طریقہ->name)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	أرجع 1;
}

ساكن صحيح
userauth_passwd(بنية ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	حرف *password, *prompt = عدم;
	ثابت حرف *host = options.host_کلید_alias ?  options.host_کلید_alias :
	    authctxt->host;
	صحيح r;

	إذا (authctxt->attempt_passwd++ >= options.نمبر_دا_password_prompts)
		أرجع 0;

	إذا (authctxt->attempt_passwd != 1)
		error("Permission denied, please try again.");

	xasprintf(&prompt, "%s@%s's password: ", authctxt->server_user, host);
	password = read_passphrase(prompt, 0);
	إذا ((r = sshpkt_شروع(ssh, SSH2_پیغام_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->طریقہ->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, password)) != 0 ||
	    (r = sshpkt_جوڑو_padding(ssh, 64)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	حرر(prompt);
	إذا (password != عدم)
		freezero(password, لڑی_لمبائی(password));

	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_PASSWD_CHANGEREQ,
	    &داخلہ_userauth_passwd_changereq);

	أرجع 1;
}

/*
 * parse PASSWD_CHANGEREQ, prompt user and send SSH2_MSG_USERAUTH_REQUEST
 */
ساكن صحيح
داخلہ_userauth_passwd_changereq(صحيح type, uint32_t seqnr, بنية ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	حرف *info = عدم, *lang = عدم, *password = عدم, *retype = عدم;
	حرف prompt[256];
	ثابت حرف *host;
	صحيح r, addnl;
	ناپ_t len;

	debug2("input_userauth_passwd_changereq");

	إذا (authctxt == عدم)
		fatal("input_userauth_passwd_changereq: "
		    "no authentication context");
	host = options.host_کلید_alias ? options.host_کلید_alias : authctxt->host;

	إذا ((r = sshpkt_get_cstring(ssh, &info, عدم)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, عدم)) != 0)
		اذهب باہرلا;
	إذا ((len = لڑی_لمبائی(info)) > 0) {
		addnl = info[len] != '\n';
		fmprintf(stderr, "%s%s", info, addnl ? "\n" : "");
	}
	إذا ((r = sshpkt_شروع(ssh, SSH2_پیغام_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->طریقہ->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0)	/* additional info */
		اذهب باہرلا;

	snprintf(prompt, حجم(prompt),
	    "Enter %.30s@%.128s's old password: ",
	    authctxt->server_user, host);
	password = read_passphrase(prompt, 0);
	إذا ((r = sshpkt_put_cstring(ssh, password)) != 0)
		اذهب باہرلا;

	freezero(password, لڑی_لمبائی(password));
	password = عدم;
	طالما (password == عدم) {
		snprintf(prompt, حجم(prompt),
		    "Enter %.30s@%.128s's new password: ",
		    authctxt->server_user, host);
		password = read_passphrase(prompt, RP_ALLOW_EOF);
		إذا (password == عدم) {
			/* bail out */
			r = 0;
			اذهب باہرلا;
		}
		snprintf(prompt, حجم(prompt),
		    "Retype %.30s@%.128s's new password: ",
		    authctxt->server_user, host);
		retype = read_passphrase(prompt, 0);
		إذا (strcmp(password, retype) != 0) {
			freezero(password, لڑی_لمبائی(password));
			logit("Mismatch; try again, EOF to quit.");
			password = عدم;
		}
		freezero(retype, لڑی_لمبائی(retype));
	}
	إذا ((r = sshpkt_put_cstring(ssh, password)) != 0 ||
	    (r = sshpkt_جوڑو_padding(ssh, 64)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		اذهب باہرلا;

	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_PASSWD_CHANGEREQ,
	    &داخلہ_userauth_passwd_changereq);
	r = 0;
 باہرلا:
	إذا (password)
		freezero(password, لڑی_لمبائی(password));
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
کلید_sig_algorithm(بنية ssh *ssh, ثابت بنية sshkey *کلید)
{
	حرف *allowed, *oallowed, *cp, *tmp, *alg = عدم;
	ثابت حرف *server_sig_algs;

	/*
	 * The signature algorithm will only differ from the key algorithm
	 * for RSA keys/certs and when the server advertises support for
	 * newer (SHA2) algorithms.
	 */
	إذا (ssh == عدم || ssh->kex->server_sig_algs == عدم ||
	    (کلید->type != کلید_RSA && کلید->type != کلید_RSA_CERT) ||
	    (کلید->type == کلید_RSA_CERT && (ssh->compat & SSH_BUG_SIGTYPE))) {
		/* Filter base key signature alg against our configuration */
		أرجع میل_list(sshkey_ssh_name(کلید),
		    options.pubkey_accepted_algos, عدم);
	}

	/*
	 * Workaround OpenSSH 7.4 bug: this version supports RSA/SHA-2 but
	 * fails to advertise it via SSH2_MSG_EXT_INFO.
	 */
	server_sig_algs = ssh->kex->server_sig_algs;
	إذا (کلید->type == کلید_RSA && (ssh->compat & SSH_BUG_SIGTYPE74))
		server_sig_algs = "rsa-sha2-256,rsa-sha2-512";

	/*
	 * For RSA keys/certs, since these might have a different sig type:
	 * find the first entry in PubkeyAcceptedAlgorithms of the right type
	 * that also appears in the supported signature algorithms list from
	 * the server.
	 */
	oallowed = allowed = xstrdup(options.pubkey_accepted_algos);
	طالما ((cp = strsep(&allowed, ",")) != عدم) {
		إذا (sshkey_type_from_name(cp) != کلید->type)
			استمر;
		tmp = میل_list(sshkey_sigalg_by_name(cp),
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
پچھان_تت_sign(بنية پچھان_تت_2 *id, u_char **sigp, ناپ_t *lenp,
    ثابت u_char *انکڑے, ناپ_t datalen, u_int compat, ثابت حرف *alg)
{
	بنية sshkey *sign_کلید = عدم, *prv = عدم;
	صحيح is_agent = 0, retried = 0, r = SSH_ERR_اندرونی_ERROR;
	بنية notifier_ctx *notifier = عدم;
	حرف *fp = عدم, *pin = عدم, *prompt = عدم;

	*sigp = عدم;
	*lenp = 0;

	/* The agent supports this key. */
	إذا (id->کلید != عدم && id->agent_fd != -1) {
		أرجع ssh_agent_sign(id->agent_fd, id->کلید, sigp, lenp,
		    انکڑے, datalen, alg, compat);
	}

	/*
	 * We have already loaded the private key or the private key is
	 * stored in external hardware.
	 */
	إذا (id->کلید != عدم &&
	    (id->isprivate || (id->کلید->flags & SSHKEY_FLAG_EXT))) {
		sign_کلید = id->کلید;
		is_agent = 1;
	} وإلا {
		/* Load the private key from the file. */
		إذا ((prv = لدو_پچھان_تت_file(id)) == عدم)
			أرجع SSH_ERR_کلید_NOT_لبھیا;
		إذا (id->کلید != عدم && !sshkey_equal_عوامی(prv, id->کلید)) {
			error_f("private key %s contents do not match public",
			    id->filename);
			r = SSH_ERR_کلید_NOT_لبھیا;
			اذهب باہرلا;
		}
		sign_کلید = prv;
	}
 retry_pin:
	/* Prompt for touch for non-agent FIDO keys that request UP */
	إذا (!is_agent && sshkey_is_sk(sign_کلید) &&
	    (sign_کلید->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
		/* XXX should batch mode just skip these? */
		إذا ((fp = sshkey_fingerprint(sign_کلید,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == عدم)
			fatal_f("fingerprint failed");
		notifier = notify_شروع(options.batch_منوال,
		    "Confirm user presence for key %s %s",
		    sshkey_type(sign_کلید), fp);
		حرر(fp);
	}
	إذا ((r = sshkey_sign(sign_کلید, sigp, lenp, انکڑے, datalen,
	    alg, options.sk_provider, pin, compat)) != 0) {
		debug_fr(r, "sshkey_sign");
		إذا (!retried && pin == عدم && !is_agent &&
		    sshkey_is_sk(sign_کلید) &&
		    r == SSH_ERR_کلید_WRONG_PASSPHRASE) {
			notify_complete(notifier, عدم);
			notifier = عدم;
			xasprintf(&prompt, "Enter PIN for %s key %s: ",
			    sshkey_type(sign_کلید), id->filename);
			pin = read_passphrase(prompt, 0);
			retried = 1;
			اذهب retry_pin;
		}
		اذهب باہرلا;
	}

	/*
	 * PKCS#11 tokens may not support all signature algorithms,
	 * so check what we get back.
	 */
	إذا (id->کلید != عدم && (id->کلید->flags & SSHKEY_FLAG_EXT) != 0 &&
	    (r = sshkey_check_sigtype(*sigp, *lenp, alg)) != 0) {
		debug_fr(r, "sshkey_check_sigtype");
		اذهب باہرلا;
	}
	/* success */
	r = 0;
 باہرلا:
	حرر(prompt);
	إذا (pin != عدم)
		freezero(pin, لڑی_لمبائی(pin));
	notify_complete(notifier, r == 0 ? "User presence confirmed" : عدم);
	sshkey_free(prv);
	أرجع r;
}

ساكن صحيح
id_filename_matches(پچھان_تت *id, پچھان_تت *نجی_id)
{
	ساكن ثابت حرف * ثابت suffixes[] = { ".pub", "-cert.pub", عدم };
	ناپ_t len = لڑی_لمبائی(id->filename), plen = لڑی_لمبائی(نجی_id->filename);
	ناپ_t i, slen;

	إذا (strcmp(id->filename, نجی_id->filename) == 0)
		أرجع 1;
	لكل (i = 0; suffixes[i]; i++) {
		slen = لڑی_لمبائی(suffixes[i]);
		إذا (len > slen && plen == len - slen &&
		    strcmp(id->filename + (len - slen), suffixes[i]) == 0 &&
		    memcmp(id->filename, نجی_id->filename, plen) == 0)
			أرجع 1;
	}
	أرجع 0;
}

ساكن صحيح
sign_and_send_pubkey(بنية ssh *ssh, پچھان_تت *id)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	بنية sshbuf *b = عدم;
	پچھان_تت *نجی_id, *sign_id = عدم;
	u_char *signature = عدم;
	ناپ_t slen = 0, skip = 0;
	صحيح r, fallback_sigtype, گھلیا = 0;
	حرف *alg = عدم, *fp = عدم;
	ثابت حرف *loc = "", *طریقہ = "publickey";
	صحيح hostbound = 0;

	/* prefer host-bound pubkey signatures if supported by server */
	إذا ((ssh->kex->flags & KEX_HAS_PUBKEY_HOSTBOUND) != 0 &&
	    (options.pubkey_authentication & SSH_PUBKEY_AUTH_HBOUND) != 0) {
		hostbound = 1;
		طریقہ = "publickey-hostbound-v00@openssh.com";
	}

	إذا ((fp = sshkey_fingerprint(id->کلید, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == عدم)
		أرجع 0;

	debug3_f("using %s with %s %s", طریقہ, sshkey_type(id->کلید), fp);

	/*
	 * If the key is an certificate, try to find a matching private key
	 * and use it to complete the signature.
	 * If no such private key exists, fall back to trying the certificate
	 * key itself in case it has a private half already loaded.
	 * This will try to set sign_id to the private key that will perform
	 * the signature.
	 */
	إذا (id->agent_fd == -1 && sshkey_is_cert(id->کلید)) {
		TAILQ_FOREACH(نجی_id, &authctxt->کلیدیں, اگلا) {
			إذا (sshkey_equal_عوامی(id->کلید, نجی_id->کلید) &&
			    id->کلید->type != نجی_id->کلید->type) {
				sign_id = نجی_id;
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
		    (id->کلید->flags & SSHKEY_FLAG_EXT) == 0) {
			TAILQ_FOREACH(نجی_id, &authctxt->کلیدیں, اگلا) {
				إذا (نجی_id->کلید == عدم &&
				    id_filename_matches(id, نجی_id)) {
					sign_id = نجی_id;
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
		إذا ((alg = کلید_sig_algorithm(fallback_sigtype ? عدم : ssh,
		    id->کلید)) == عدم) {
			error_f("no mutual signature supported");
			اذهب باہرلا;
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
		    (r = sshbuf_put_cstring(b, طریقہ)) != 0 ||
		    (r = sshbuf_put_u8(b, 1)) != 0 ||
		    (r = sshbuf_put_cstring(b, alg)) != 0 ||
		    (r = sshkey_puts(id->کلید, b)) != 0) {
			fatal_fr(r, "assemble signed data");
		}
		إذا (hostbound) {
			إذا (ssh->kex->initial_hostkey == عدم) {
				fatal_f("internal error: initial hostkey "
				    "not recorded");
			}
			إذا ((r = sshkey_puts(ssh->kex->initial_hostkey, b)) != 0)
				fatal_fr(r, "assemble %s hostkey", طریقہ);
		}
		/* generate signature */
		r = پچھان_تت_sign(sign_id, &signature, &slen,
		    sshbuf_ptr(b), sshbuf_len(b), ssh->compat, alg);
		إذا (r == 0)
			اكسر;
		وإلا إذا (r == SSH_ERR_کلید_NOT_لبھیا)
			اذهب باہرلا; /* soft failure */
		وإلا إذا (r == SSH_ERR_SIGN_ALG_UNSUPPORTED &&
		    !fallback_sigtype) {
			إذا (sign_id->agent_fd != -1)
				loc = "agent ";
			وإلا إذا (sign_id->کلید != عدم &&
			    (sign_id->کلید->flags & SSHKEY_FLAG_EXT) != 0)
				loc = "token ";
			logit("%skey %s %s returned incorrect signature type",
			    loc, sshkey_type(id->کلید), fp);
			استمر;
		}
		error_fr(r, "signing failed for %s \"%s\"%s",
		    sshkey_type(sign_id->کلید), sign_id->filename,
		    id->agent_fd != -1 ? " from agent" : "");
		اذهب باہرلا;
	}
	إذا (slen == 0 || signature == عدم) /* shouldn't happen */
		fatal_f("no signature");

	/* append signature */
	إذا ((r = sshbuf_put_string(b, signature, slen)) != 0)
		fatal_fr(r, "append signature");

#جے_تعریف_شدہ DEBUG_PK
	sshbuf_dump(b, stderr);
#جے_انت
	/* skip session id and packet type */
	إذا ((r = sshbuf_consume(b, skip + 1)) != 0)
		fatal_fr(r, "consume");

	/* put remaining data from buffer into packet */
	إذا ((r = sshpkt_شروع(ssh, SSH2_پیغام_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_putb(ssh, b)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "enqueue request");

	/* success */
	گھلیا = 1;

 باہرلا:
	حرر(fp);
	حرر(alg);
	sshbuf_free(b);
	freezero(signature, slen);
	أرجع گھلیا;
}

ساكن صحيح
send_pubkey_test(بنية ssh *ssh, پچھان_تت *id)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	u_char *blob = عدم;
	حرف *alg = عدم;
	ناپ_t bloblen;
	u_int have_sig = 0;
	صحيح گھلیا = 0, r;

	إذا ((alg = کلید_sig_algorithm(ssh, id->کلید)) == عدم) {
		debug_f("no mutual signature algorithm");
		اذهب باہرلا;
	}

	إذا ((r = sshkey_منزل_blob(id->کلید, &blob, &bloblen)) != 0) {
		/* we cannot handle this key */
		debug3_f("cannot handle key");
		اذهب باہرلا;
	}
	/* register callback for USERAUTH_PK_OK message */
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_PK_OK, &داخلہ_userauth_pk_ok);

	إذا ((r = sshpkt_شروع(ssh, SSH2_پیغام_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->طریقہ->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, have_sig)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, alg)) != 0 ||
	    (r = sshpkt_put_string(ssh, blob, bloblen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	گھلیا = 1;

 باہرلا:
	حرر(alg);
	حرر(blob);
	أرجع گھلیا;
}

ساكن بنية sshkey *
لدو_پچھان_تت_file(پچھان_تت *id)
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
	لكل (i = 0; i <= options.نمبر_دا_password_prompts; i++) {
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
		بدل ((r = sshkey_لدو_نجی_type(کلید_UNSPEC, id->filename,
		    passphrase, &خاص, &comment))) {
		حالة 0:
			اكسر;
		حالة SSH_ERR_کلید_WRONG_PASSPHRASE:
			إذا (options.batch_منوال) {
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
		إذا (!quit && (r = sshkey_check_rsa_لمائی(خاص,
		    options.required_rsa_ناپ)) != 0) {
			debug_fr(r, "Skipping key %s", id->filename);
			sshkey_free(خاص);
			خاص = عدم;
			quit = 1;
		}
		إذا (!quit && خاص != عدم && id->agent_fd == -1 &&
		    !(id->کلید && id->isprivate))
			maybe_جوڑو_کلید_منزل_agent(id->filename, خاص, comment,
			    passphrase);
		إذا (i > 0)
			freezero(passphrase, لڑی_لمبائی(passphrase));
		حرر(comment);
		إذا (خاص != عدم || quit)
			اكسر;
	}
	أرجع خاص;
}

ساكن صحيح
کلید_type_allowed(بنية sshkey *کلید, ثابت حرف *allowlist)
{
	إذا (میل_نمونہ_list(sshkey_ssh_name(کلید), allowlist, 0) == 1)
		أرجع 1;

	/* RSA keys/certs might be allowed by alternate signature types */
	بدل (کلید->type) {
	حالة کلید_RSA:
		إذا (میل_نمونہ_list("rsa-sha2-512", allowlist, 0) == 1)
			أرجع 1;
		إذا (میل_نمونہ_list("rsa-sha2-256", allowlist, 0) == 1)
			أرجع 1;
		اكسر;
	حالة کلید_RSA_CERT:
		إذا (میل_نمونہ_list("rsa-sha2-512-cert-v01@openssh.com",
		    allowlist, 0) == 1)
			أرجع 1;
		إذا (میل_نمونہ_list("rsa-sha2-256-cert-v01@openssh.com",
		    allowlist, 0) == 1)
			أرجع 1;
		اكسر;
	}
	أرجع 0;
}

ساكن صحيح
کلید_type_allowed_by_config(بنية sshkey *کلید)
{
	أرجع کلید_type_allowed(کلید, options.pubkey_accepted_algos);
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
cert_has_option(بنية sshbuf *oblob, ثابت حرف *نشانہ)
{
	بنية sshbuf *c = عدم, *انکڑے = عدم;
	حرف *name = عدم;
	صحيح r, لبھیا = 0;

	إذا (oblob == عدم || (c = sshbuf_fromb(oblob)) == عدم)
		أرجع 0;
	طالما (sshbuf_len(c) > 0) {
		sshbuf_free(انکڑے);
		انکڑے = عدم;
		حرر(name);
		name = عدم;
		إذا ((r = sshbuf_get_cstring(c, &name, عدم)) != 0 ||
		    (r = sshbuf_froms(c, &انکڑے)) != 0)
			اكسر;
		إذا (strcmp(name, نشانہ) == 0) {
			لبھیا = 1;
			اكسر;
		}
	}
	sshbuf_free(انکڑے);
	حرر(name);
	sshbuf_free(c);
	أرجع لبھیا;
}

/*
 * Returns an integer describing the priority of the identity
 * within its group. Lower numbers are higher priority.
 */
#تعریف_کرو MAX_ID_ترجیح 3
ساكن صحيح
پچھان_تت_prioritise(بنية پچھان_تت_2 *id)
{
	إذا (id == عدم || id->کلید == عدم)
		أرجع 3;
	إذا (!sshkey_is_cert(id->کلید) || id->کلید->cert == عدم)
		أرجع 3;
	إذا (sshkey_is_sk(id->کلید) &&
	    cert_has_option(id->کلید->cert->critical, "verify-required"))
		أرجع 2;
	إذا (sshkey_is_sk(id->کلید) &&
	    cert_has_option(id->کلید->cert->extensions, "no-touch-required"))
		أرجع 0;
	أرجع 1;
}

ساكن فراغ
ترتیب_identities_by_prio(بنية idlist *list)
{
	بنية idlist prio[MAX_ID_ترجیح + 1], sorted;
	بنية پچھان_تت_2 *id, *tmp, *dummy;
	صحيح p;

	لكل (p = 0; p <= MAX_ID_ترجیح; p++)
		TAILQ_INIT(&prio[p]);
	TAILQ_INIT(&sorted);

	TAILQ_FOREACH_محفوظ(id, list, اگلا, tmp) {
		إذا (id->userprovided)
			استمر;
		dummy = xcalloc(1, حجم(*dummy));
		dummy->userprovided = -1;
		TAILQ_INSERT_BEFORE(id, dummy, اگلا);
		TAILQ_REMOVE(list, id, اگلا);
		p = پچھان_تت_prioritise(id);
		إذا (p < 0 || p > MAX_ID_ترجیح)
			fatal_f("internal error: bad priority");
		TAILQ_INSERT_TAIL(&prio[p], id, اگلا);
	}
	لكل (p = 0; p <= MAX_ID_ترجیح; p++)
		TAILQ_CONCAT(&sorted, &prio[p], اگلا);

	TAILQ_FOREACH_محفوظ(id, list, اگلا, tmp) {
		إذا (id->userprovided != -1)
			استمر;
		بنية پچھان_تت_2 *s = TAILQ_FIRST(&sorted);
		TAILQ_REMOVE(&sorted, s, اگلا);
		TAILQ_INSERT_BEFORE(id, s, اگلا);
		TAILQ_REMOVE(list, id, اگلا);
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
	بنية پچھان_تت_2 *id, *id2, *tmp;
	بنية idlist agent, files, certs, agent_کلیدیں, *preferred;
	بنية sshkey *کلید;
	صحيح disallowed, agent_fd = -1, i, r, لبھیا;
	ناپ_t j;
	بنية ssh_identitylist *idlist;
	حرف *cp, *ident;

	TAILQ_INIT(&agent);	/* keys from the agent */
	TAILQ_INIT(&files);	/* keys from the config file */
	TAILQ_INIT(&certs);	/* certificates specified by user */
	TAILQ_INIT(&agent_کلیدیں); /* keys supported by the agent */
	preferred = &authctxt->کلیدیں;
	TAILQ_INIT(preferred);	/* preferred order of keys */

	/* list of keys stored in the filesystem and PKCS#11 */
	لكل (i = 0; i < options.عدد_پچھان_تت_files; i++) {
		کلید = options.پچھان_تت_کلیدیں[i];
		إذا (کلید && کلید->cert &&
		    کلید->cert->type != SSH2_CERT_TYPE_USER) {
			debug_f("ignoring certificate %s: not a user "
			    "certificate", options.پچھان_تت_files[i]);
			استمر;
		}
		إذا (کلید && sshkey_is_sk(کلید) && options.sk_provider == عدم) {
			debug_f("ignoring authenticator-hosted key %s as no "
			    "SecurityKeyProvider has been specified",
			    options.پچھان_تت_files[i]);
			استمر;
		}
		options.پچھان_تت_کلیدیں[i] = عدم;
		id = xcalloc(1, حجم(*id));
		id->agent_fd = -1;
		id->کلید = کلید;
		id->filename = xstrdup(options.پچھان_تت_files[i]);
		id->userprovided = options.پچھان_تت_file_userprovided[i];
		TAILQ_INSERT_TAIL(&files, id, اگلا);
	}

	/* list of certificates specified by user */
	لكل (i = 0; i < options.عدد_certificate_files; i++) {
		کلید = options.certificates[i];
		إذا (!sshkey_is_cert(کلید) || کلید->cert == عدم ||
		    کلید->cert->type != SSH2_CERT_TYPE_USER) {
			debug_f("ignoring certificate %s: not a user "
			    "certificate", options.پچھان_تت_files[i]);
			استمر;
		}
		إذا (کلید && sshkey_is_sk(کلید) && options.sk_provider == عدم) {
			debug_f("ignoring authenticator-hosted key "
			    "certificate %s as no "
			    "SecurityKeyProvider has been specified",
			    options.پچھان_تت_files[i]);
			استمر;
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
	إذا ((r = get_agent_identities(ssh, &agent_fd, &idlist)) == 0) {
		لكل (j = 0; j < idlist->nkeys; j++) {
			إذا ((r = sshkey_check_rsa_لمائی(idlist->کلیدیں[j],
			    options.required_rsa_ناپ)) != 0) {
				debug_fr(r, "ignoring %s agent key",
				    sshkey_ssh_name(idlist->کلیدیں[j]));
				استمر;
			}
			لبھیا = 0;
			TAILQ_FOREACH(id, &files, اگلا) {
				/*
				 * agent keys from the config file are
				 * preferred
				 */
				إذا (sshkey_equal(idlist->کلیدیں[j], id->کلید)) {
					TAILQ_REMOVE(&files, id, اگلا);
					TAILQ_INSERT_TAIL(&agent_کلیدیں, id, اگلا);
					id->agent_fd = agent_fd;
					لبھیا = 1;
					اكسر;
				}
			}
			إذا (!لبھیا && !options.identities_only) {
				id = xcalloc(1, حجم(*id));
				/* XXX "steals" key/comment from idlist */
				id->کلید = idlist->کلیدیں[j];
				id->filename = idlist->comments[j];
				idlist->کلیدیں[j] = عدم;
				idlist->comments[j] = عدم;
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
		إذا (id->کلید == عدم || (id->کلید->flags & SSHKEY_FLAG_EXT) == 0)
			استمر;
		لبھیا = 0;
		TAILQ_FOREACH(id2, &files, اگلا) {
			إذا (id2->کلید == عدم ||
			    (id2->کلید->flags & SSHKEY_FLAG_EXT) != 0)
				استمر;
			إذا (sshkey_equal(id->کلید, id2->کلید)) {
				TAILQ_REMOVE(&files, id, اگلا);
				TAILQ_INSERT_TAIL(preferred, id, اگلا);
				لبھیا = 1;
				اكسر;
			}
		}
		/* If IdentitiesOnly set and key not found then don't use it */
		إذا (!لبھیا && options.identities_only) {
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
		cp = عدم;
		إذا (id->کلید == عدم)
			استمر;
		إذا (!کلید_type_allowed_by_config(id->کلید)) {
			debug("Skipping %s key %s - corresponding algorithm "
			    "not in PubkeyAcceptedAlgorithms",
			    sshkey_ssh_name(id->کلید), id->filename);
			disallowed = 1;
		} وإلا إذا (ssh != عدم && ssh->kex != عدم &&
		    ssh->kex->server_sig_algs != عدم &&
		    (cp = کلید_sig_algorithm(ssh, id->کلید)) == عدم) {
			debug("Skipping %s key %s - corresponding algorithm "
			    "not supported by server",
			    sshkey_ssh_name(id->کلید), id->filename);
			disallowed = 1;
		}
		حرر(cp);
		إذا (!disallowed)
			استمر;
		/* remove key */
		TAILQ_REMOVE(preferred, id, اگلا);
		sshkey_free(id->کلید);
		حرر(id->filename);
		freezero(id, حجم(*id));
	}
	/* List the keys we plan on using */
	TAILQ_FOREACH_محفوظ(id, preferred, اگلا, id2) {
		ident = format_پچھان_تت(id);
		debug("Will attempt key: %s", ident);
		حرر(ident);
	}
	debug2_f("done");
}

ساكن فراغ
pubkey_cleanup(بنية ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	پچھان_تت *id;

	إذا (authctxt->agent_fd != -1) {
		ssh_close_authentication_socket(authctxt->agent_fd);
		authctxt->agent_fd = -1;
	}
	لكل (id = TAILQ_FIRST(&authctxt->کلیدیں); id;
	    id = TAILQ_FIRST(&authctxt->کلیدیں)) {
		TAILQ_REMOVE(&authctxt->کلیدیں, id, اگلا);
		sshkey_free(id->کلید);
		حرر(id->filename);
		حرر(id);
	}
}

فراغ
pubkey_dump(بنية ssh *ssh)
{
	Authctxt authctxt;
	پچھان_تت *id;
	حرف *ident;

	memset(&authctxt, 0, حجم(authctxt));
	authctxt.agent_fd = -1;
	ssh->authctxt = &authctxt;

	pubkey_prepare(ssh, &authctxt);
	TAILQ_FOREACH(id, &authctxt.کلیدیں, اگلا) {
		ident = format_پچھان_تت(id);
		fprintf(stdout, "%s\n", ident);
		حرر(ident);
	}
	pubkey_cleanup(ssh);
	ssh->authctxt = عدم;
}

ساكن فراغ
pubkey_reset(Authctxt *authctxt)
{
	پچھان_تت *id;

	TAILQ_FOREACH(id, &authctxt->کلیدیں, اگلا)
		id->tried = 0;
}

ساكن صحيح
userauth_pubkey(بنية ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	پچھان_تت *id;
	صحيح گھلیا = 0;
	حرف *ident;
	ساكن صحيح prepared;

	إذا (!prepared) {
		pubkey_prepare(ssh, authctxt);
		prepared = 1;
	}

	طالما ((id = TAILQ_FIRST(&authctxt->کلیدیں))) {
		إذا (id->tried++)
			أرجع (0);
		/* move key to the end of the queue */
		TAILQ_REMOVE(&authctxt->کلیدیں, id, اگلا);
		TAILQ_INSERT_TAIL(&authctxt->کلیدیں, id, اگلا);
		/*
		 * send a test message if we have the public key. for
		 * encrypted keys we cannot do this and have to load the
		 * private key instead
		 */
		إذا (id->کلید != عدم) {
			ident = format_پچھان_تت(id);
			debug("Offering public key: %s", ident);
			حرر(ident);
			گھلیا = send_pubkey_test(ssh, id);
		} وإلا {
			debug("Trying private key: %s", id->filename);
			id->کلید = لدو_پچھان_تت_file(id);
			إذا (id->کلید != عدم) {
				id->isprivate = 1;
				گھلیا = sign_and_send_pubkey(ssh, id);
				sshkey_free(id->کلید);
				id->کلید = عدم;
				id->isprivate = 0;
			}
		}
		إذا (گھلیا)
			أرجع (گھلیا);
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

	إذا (authctxt->attempt_kbdint++ >= options.نمبر_دا_password_prompts)
		أرجع 0;
	/* disable if no SSH2_MSG_USERAUTH_INFO_REQUEST has been seen */
	إذا (authctxt->attempt_kbdint > 1 && !authctxt->info_req_تکیا) {
		debug3("userauth_kbdint: disable: no info_req_seen");
		ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_INFO_REQUEST, عدم);
		أرجع 0;
	}

	debug2("userauth_kbdint");
	إذا ((r = sshpkt_شروع(ssh, SSH2_پیغام_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->طریقہ->name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||		/* lang */
	    (r = sshpkt_put_cstring(ssh, options.kbd_interactive_devices ?
	    options.kbd_interactive_devices : "")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_INFO_REQUEST, &داخلہ_userauth_info_req);
	أرجع 1;
}

/*
 * parse INFO_REQUEST, prompt user and send INFO_RESPONSE
 */
ساكن صحيح
داخلہ_userauth_info_req(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	حرف *name = عدم, *inst = عدم, *lang = عدم, *prompt = عدم;
	حرف *display_prompt = عدم, *response = عدم;
	u_char echo = 0;
	u_int عدد_prompts, i;
	صحيح r, addnl;
	ناپ_t len;

	debug2_f("entering");

	إذا (authctxt == عدم)
		fatal_f("no authentication context");

	authctxt->info_req_تکیا = 1;

	إذا ((r = sshpkt_get_cstring(ssh, &name, عدم)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &inst, عدم)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, عدم)) != 0)
		اذهب باہرلا;
	إذا ((len = لڑی_لمبائی(name)) > 0) {
		addnl = name[len] != '\n';
		fmprintf(stderr, "%s%s", name, addnl ? "\n" : "");
	}
	إذا ((len = لڑی_لمبائی(inst)) > 0) {
		addnl = inst[len] != '\n';
		fmprintf(stderr, "%s%s", inst, addnl ? "\n" : "");
	}

	إذا ((r = sshpkt_get_u32(ssh, &عدد_prompts)) != 0)
		اذهب باہرلا;
	/*
	 * Begin to build info response packet based on prompts requested.
	 * We commit to providing the correct number of responses, so if
	 * further on we run into a problem that prevents this, we have to
	 * be sure and clean this up and send a correct error response.
	 */
	إذا ((r = sshpkt_شروع(ssh, SSH2_پیغام_USERAUTH_INFO_RESPONSE)) != 0 ||
	    (r = sshpkt_put_u32(ssh, عدد_prompts)) != 0)
		اذهب باہرلا;

	debug2_f("num_prompts %d", عدد_prompts);
	لكل (i = 0; i < عدد_prompts; i++) {
		إذا ((r = sshpkt_get_cstring(ssh, &prompt, عدم)) != 0 ||
		    (r = sshpkt_get_u8(ssh, &echo)) != 0)
			اذهب باہرلا;
		إذا (asmprintf(&display_prompt, ودھ_توں_ودھ_عدد, عدم, "(%s@%s) %s",
		    authctxt->server_user, options.host_کلید_alias ?
		    options.host_کلید_alias : authctxt->host, prompt) == -1)
			fatal_f("asmprintf failed");
		response = read_passphrase(display_prompt, echo ? RP_ECHO : 0);
		إذا ((r = sshpkt_put_cstring(ssh, response)) != 0)
			اذهب باہرلا;
		freezero(response, لڑی_لمبائی(response));
		حرر(prompt);
		حرر(display_prompt);
		display_prompt = response = prompt = عدم;
	}
	/* done with parsing incoming message. */
	إذا ((r = sshpkt_get_سرا(ssh)) != 0 ||
	    (r = sshpkt_جوڑو_padding(ssh, 64)) != 0)
		اذهب باہرلا;
	r = sshpkt_send(ssh);
 باہرلا:
	إذا (response)
		freezero(response, لڑی_لمبائی(response));
	حرر(prompt);
	حرر(display_prompt);
	حرر(name);
	حرر(inst);
	حرر(lang);
	أرجع r;
}

ساكن صحيح
ssh_keysign(بنية ssh *ssh, بنية sshkey *کلید, u_char **sigp, ناپ_t *lenp,
    ثابت u_char *انکڑے, ناپ_t datalen)
{
	بنية sshbuf *b;
	بنية stat st;
	pid_t pid;
	صحيح r, منزل[2], from[2], حالت;
	صحيح sock = ssh_packet_get_connection_وچ(ssh);
	u_char rversion = 0, نسخہ = 2;
	فراغ (*osigchld)(صحيح);

	*sigp = عدم;
	*lenp = 0;

	إذا (stat(رستہ_SSH_کلید_SIGN, &st) == -1) {
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
		    (لما)getpid(), رستہ_SSH_کلید_SIGN);
		execl(رستہ_SSH_کلید_SIGN, رستہ_SSH_کلید_SIGN, (حرف *)عدم);
		fatal_f("exec(%s): %s", رستہ_SSH_کلید_SIGN,
		    strerror(errno));
	}
	close(from[1]);
	close(منزل[0]);
	sock = STDERR_FILENO + 1;

	إذا ((b = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	/* send # of sock, data to be signed */
	إذا ((r = sshbuf_put_u32(b, sock)) != 0 ||
	    (r = sshbuf_put_string(b, انکڑے, datalen)) != 0)
		fatal_fr(r, "buffer error");
	إذا (ssh_پیغام_send(منزل[1], نسخہ, b) == -1)
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
			error_f("waitpid %ld: %s", (لما)pid, strerror(errno));
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
	إذا (rversion != نسخہ) {
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
	ناپ_t siglen = 0, keylen = 0;
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
		إذا (authctxt->سرگرم_ktype == عدم)
			authctxt->سرگرم_ktype = strsep(&authctxt->ktypes, ",");
		إذا (authctxt->سرگرم_ktype == عدم ||
		    *authctxt->سرگرم_ktype == '\0')
			اكسر;
		debug3_f("trying key type %s", authctxt->سرگرم_ktype);

		/* check for a useful key */
		خاص = عدم;
		لكل (i = 0; i < authctxt->sensitive->nkeys; i++) {
			إذا (authctxt->sensitive->کلیدیں[i] == عدم ||
			    authctxt->sensitive->کلیدیں[i]->type == کلید_UNSPEC)
				استمر;
			إذا (!sshkey_میل_keyname_منزل_sigalgs(
			    sshkey_ssh_name(authctxt->sensitive->کلیدیں[i]),
			    authctxt->سرگرم_ktype))
				استمر;
			/* we take and free the key */
			خاص = authctxt->sensitive->کلیدیں[i];
			authctxt->sensitive->کلیدیں[i] = عدم;
			اكسر;
		}
		/* Found one */
		إذا (خاص != عدم)
			اكسر;
		/* No more keys of this type; advance */
		authctxt->سرگرم_ktype = عدم;
	}
	إذا (خاص == عدم) {
		حرر(authctxt->oktypes);
		authctxt->oktypes = authctxt->ktypes = عدم;
		authctxt->سرگرم_ktype = عدم;
		debug("No more client hostkeys for hostbased authentication.");
		اذهب باہرلا;
	}

	إذا ((fp = sshkey_fingerprint(خاص, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == عدم) {
		error_f("sshkey_fingerprint failed");
		اذهب باہرلا;
	}
	debug_f("trying hostkey %s %s using sigalg %s",
	    sshkey_ssh_name(خاص), fp, authctxt->سرگرم_ktype);

	/* figure out a name for the client host */
	lname = get_local_name(ssh_packet_get_connection_وچ(ssh));
	إذا (lname == عدم) {
		error_f("cannot get local ipaddr/name");
		اذهب باہرلا;
	}

	/* XXX sshbuf_put_stringf? */
	xasprintf(&chost, "%s.", lname);
	debug2_f("chost %s", chost);

	/* construct data */
	إذا ((b = sshbuf_new()) == عدم) {
		error_f("sshbuf_new failed");
		اذهب باہرلا;
	}
	إذا ((r = sshkey_منزل_blob(خاص, &keyblob, &keylen)) != 0) {
		error_fr(r, "sshkey_to_blob");
		اذهب باہرلا;
	}
	إذا ((r = sshbuf_put_stringb(b, ssh->kex->session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_پیغام_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->server_user)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->طریقہ->name)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->سرگرم_ktype)) != 0 ||
	    (r = sshbuf_put_string(b, keyblob, keylen)) != 0 ||
	    (r = sshbuf_put_cstring(b, chost)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->local_user)) != 0) {
		error_fr(r, "buffer error");
		اذهب باہرلا;
	}

#جے_تعریف_شدہ DEBUG_PK
	sshbuf_dump(b, stderr);
#جے_انت
	إذا ((r = ssh_keysign(ssh, خاص, &sig, &siglen,
	    sshbuf_ptr(b), sshbuf_len(b))) != 0) {
		error("sign using hostkey %s %s failed",
		    sshkey_ssh_name(خاص), fp);
		اذهب باہرلا;
	}
	إذا ((r = sshpkt_شروع(ssh, SSH2_پیغام_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->طریقہ->name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->سرگرم_ktype)) != 0 ||
	    (r = sshpkt_put_string(ssh, keyblob, keylen)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, chost)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->local_user)) != 0 ||
	    (r = sshpkt_put_string(ssh, sig, siglen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_fr(r, "packet error");
		اذهب باہرلا;
	}
	success = 1;

 باہرلا:
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
authmethod_is_enabled(Authmethod *طریقہ)
{
	إذا (طریقہ == عدم)
		أرجع 0;
	/* return false if options indicate this method is disabled */
	إذا  (طریقہ->enabled == عدم || *طریقہ->enabled == 0)
		أرجع 0;
	/* return false if batch mode is enabled but method needs interactive mode */
	إذا  (طریقہ->batch_flag != عدم && *طریقہ->batch_flag != 0)
		أرجع 0;
	أرجع 1;
}

ساكن Authmethod *
authmethod_lookup(ثابت حرف *name)
{
	Authmethod *طریقہ = عدم;
	إذا (name != عدم)
		لكل (طریقہ = authmethods; طریقہ->name != عدم; طریقہ++)
			إذا (strcmp(name, طریقہ->name) == 0)
				أرجع طریقہ;
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
	u_int اگلا;

	/* Use a suitable default if we're passed a nil list.  */
	إذا (authlist == عدم || لڑی_لمبائی(authlist) == 0)
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
		إذا ((name = میل_list(preferred, supported, &اگلا)) == عدم) {
			debug("No more authentication methods to try.");
			current = عدم;
			أرجع عدم;
		}
		preferred += اگلا;
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
	Authmethod *طریقہ = عدم;
	بنية sshbuf *b;
	حرف *list;
	صحيح r;

	إذا ((b = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	لكل (طریقہ = authmethods; طریقہ->name != عدم; طریقہ++) {
		إذا (authmethod_is_enabled(طریقہ)) {
			إذا ((r = sshbuf_putf(b, "%s%s",
			    sshbuf_len(b) ? "," : "", طریقہ->name)) != 0)
				fatal_fr(r, "buffer error");
		}
	}
	إذا ((list = sshbuf_dup_string(b)) == عدم)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	أرجع list;
}
