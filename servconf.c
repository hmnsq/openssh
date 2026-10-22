/* $OpenBSD: servconf.c,v 1.459 2026/10/09 10:48:43 dtucker Exp $ */
/*
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/socket.h>
#ضمن <sys/queue.h>
#ضمن <sys/stat.h>
#جيڪڏهن_وصف_ٿيل __OpenBSD__
#ضمن <sys/sysctl.h>
#جيڪڏهن_پورو

#ضمن <netinet/in.h>
#ضمن <netinet/ip.h>
#جيڪڏهن_وصف_ٿيل HAVE_NET_ROUTE_H
#ضمن <net/route.h>
#جيڪڏهن_پورو

#ضمن <ctype.h>
#ضمن <glob.h>
#ضمن <netdb.h>
#ضمن <pwd.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <signal.h>
#ضمن <unistd.h>
#ضمن <limits.h>
#ضمن <stdarg.h>
#ضمن <errno.h>
#ضمن <util.h>

#ضمن "xmalloc.h"
#ضمن "ssh.h"
#ضمن "log.h"
#ضمن "sshbuf.h"
#ضمن "misc.h"
#ضمن "servconf.h"
#ضمن "pathnames.h"
#ضمن "cipher.h"
#ضمن "sshkey.h"
#ضمن "kex.h"
#ضمن "mac.h"
#ضمن "match.h"
#ضمن "channels.h"
#ضمن "groupaccess.h"
#ضمن "canohost.h"
#ضمن "packet.h"
#ضمن "ssherr.h"
#ضمن "hostfile.h"
#ضمن "auth.h"
#ضمن "myproposal.h"
#ضمن "digest.h"
#ضمن "version.h"

#وصف_ڪريو SSHD_CONFIG_BLOB_نسخو	1

#إذا !defined(SSHD_PAM_SERVICE)
# define SSHD_PAM_SERVICE		"sshd"
#جيڪڏهن_پورو

ساكن فراغ جوڙيو_listen_addr(ServerOptions *, ثابت حرف *,
    ثابت حرف *, صحيح);
ساكن فراغ جوڙيو_one_listen_addr(ServerOptions *, ثابت حرف *,
    ثابت حرف *, صحيح);
ساكن فراغ parse_server_config_اونهائي(ServerOptions *options,
    ثابت حرف *filename, بنية sshbuf *conf, بنية include_list *includes,
    بنية connection_info *connectinfo, صحيح flags, صحيح *activep, صحيح اونهائي);

خارجي بنية sshbuf *cfg;

/* Initializes the server options to their default values. */

فراغ
initialize_server_options(ServerOptions *options)
{
	memset(options, 0, حجم(*options));
#وصف_ڪريو SSHCONF_INT(var, conf, flags, ms, def, cp)	options->var = -1;
#وصف_ڪريو SSHCONF_INTFLAG(var, conf, flags, def, cp)	options->var = -1;
#وصف_ڪريو SSHCONF_STRING(var, conf, flags, cp)		options->var = عدم;
#وصف_ڪريو SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	options->nvar = 0; \
	options->var = عدم;
#وصف_ڪريو SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	init_##funcsuffix(options)
#وصف_ڪريو SSHCONF_NONCONF(funcsuffix) \
	init_##funcsuffix(options)
#وصف_ڪريو SSHCONF_DEPRECATE(conf, flags, opcode)		/*خالي_جايون*/
#وصف_ڪريو SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#وصف_ڪريو SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	options->var = عدم;
#وصف_ڪريو SSHCONF_ALIAS(old, conf, flags)			/*خالي_جايون*/

	/* Using macros for these is a bit overkill but forces consistency */
#وصف_ڪريو init_hostkeyfile(options) \
	options->host_ڪنجي_files = 0; \
	options->انگ_host_ڪنجي_files = 0; \
	options->host_ڪنجي_file_userprovided = عدم;
#وصف_ڪريو init_ipqos(options) \
	options->ip_qos_interactive = -1; \
	options->ip_qos_bulk = -1;
#وصف_ڪريو init_listenaddress(options) \
	options->queued_listen_addrs = عدم; \
	options->انگ_queued_listens = 0; \
	options->listen_addrs = عدم; \
	options->انگ_listen_addrs = 0;
#وصف_ڪريو init_logfacility(options) \
	options->log_facility = SYSLOG_FACILITY_NOT_سيٽ;
#وصف_ڪريو init_loglevel(options) \
	options->log_level = SYSLOG_LEVEL_NOT_سيٽ;
#وصف_ڪريو init_پورٽ(options) \
	options->انگ_ports = 0; \
	options->ports_from_cmdline = 0;
#وصف_ڪريو init_gatewayports(options) \
	options->fwd_opts.gateway_ports = -1;
#وصف_ڪريو init_streamlocalbindmask(options) \
	options->fwd_opts.streamlocal_bind_نقاب = (گهڻائي_t)-1;
#وصف_ڪريو init_streamlocalbindunlink(options) \
	options->fwd_opts.streamlocal_bind_unlink = -1;
#وصف_ڪريو init_maxstartups(options) \
	options->max_startups_begin = -1; \
	options->max_startups_شرح = -1; \
	options->max_startups = -1;
#وصف_ڪريو init_permituserenv(options) \
	options->permit_user_env = -1; \
	options->permit_user_env_allowlist = عدم;
#وصف_ڪريو init_persourcenetblocksize(options) \
	options->في_ذريعو_masklen_ipv4 = -1; \
	options->في_ذريعو_masklen_ipv6 = -1;
#وصف_ڪريو init_persourcepenalties(options) \
	options->في_ذريعو_penalty_exempt = عدم; \
	options->في_ذريعو_penalty.enabled = -1; \
	options->في_ذريعو_penalty.max_sources4 = -1; \
	options->في_ذريعو_penalty.max_sources6 = -1; \
	options->في_ذريعو_penalty.حد_کان_مٿي_گهڻائي = -1; \
	options->في_ذريعو_penalty.حد_کان_مٿي_mode6 = -1; \
	options->في_ذريعو_penalty.penalty_crash = -1.0; \
	options->في_ذريعو_penalty.penalty_authfail = -1.0; \
	options->في_ذريعو_penalty.penalty_invaliduser = -1.0; \
	options->في_ذريعو_penalty.penalty_noauth = -1.0; \
	options->في_ذريعو_penalty.penalty_grace = -1.0; \
	options->في_ذريعو_penalty.penalty_refuseconnection = -1.0; \
	options->في_ذريعو_penalty.penalty_max = -1.0; \
	options->في_ذريعو_penalty.penalty_min = -1.0;
#وصف_ڪريو init_rekeylimit(options) \
	options->rekey_حد_بندي = -1; \
	options->rekey_interval = -1;
#وصف_ڪريو init_subsystem(options) \
	options->انگ_subsystems = 0; \
	options->subsystem_name = عدم; \
	options->subsystem_command = عدم; \
	options->subsystem_دليلون = عدم;
#وصف_ڪريو init_pubkey_auth_options(options) \
	options->pubkey_auth_options = -1; \
	options->max_pubkey_ok = -1;
#وصف_ڪريو init_timingsecret(options) \
	options->timing_secret = 0;

	SSHD_CONFIG_ENTRIES

#وصف_رد init_hostkeyfile
#وصف_رد init_ipqos
#وصف_رد init_listenaddress
#وصف_رد init_logfacility
#وصف_رد init_loglevel
#وصف_رد init_پورٽ
#وصف_رد init_gatewayports
#وصف_رد init_streamlocalbindmask
#وصف_رد init_streamlocalbindunlink
#وصف_رد init_maxstartups
#وصف_رد init_permituserenv
#وصف_رد init_persourcenetblocksize
#وصف_رد init_persourcepenalties
#وصف_رد init_rekeylimit
#وصف_رد init_subsystem
#وصف_رد init_timingsecret
#وصف_رد SSHCONF_INT
#وصف_رد SSHCONF_INTFLAG
#وصف_رد SSHCONF_STRING
#وصف_رد SSHCONF_STRARRAY
#وصف_رد SSHCONF_CUSTOM
#وصف_رد SSHCONF_NONCONF
#وصف_رد SSHCONF_DEPRECATE
#وصف_رد SSHCONF_UNSUPPORTED_INT
#وصف_رد SSHCONF_UNSUPPORTED_STRING
#وصف_رد SSHCONF_ALIAS
}

/* Returns 1 if a string option is unset or set to "none" or 0 otherwise. */
ساكن صحيح
option_clear_or_none(ثابت حرف *o)
{
	أرجع o == عدم || strcasecmp(o, "none") == 0;
}

ساكن فراغ
assemble_algorithms(ServerOptions *o)
{
	حرف *all_cipher, *all_mac, *all_kex, *all_ڪنجي, *all_sig;
	حرف *def_cipher, *def_mac, *def_kex, *def_ڪنجي, *def_sig;
	صحيح r;

	all_cipher = cipher_alg_list(',', 0);
	all_mac = mac_alg_list(',');
	all_kex = kex_alg_list(',');
	all_ڪنجي = sshkey_alg_list(0, 0, 1, ',');
	all_sig = sshkey_alg_list(0, 1, 1, ',');
	/* remove unsupported algos from default lists */
	def_cipher = ميلاپ_filter_allowlist(KEX_SERVER_ENCRYPT, all_cipher);
	def_mac = ميلاپ_filter_allowlist(KEX_SERVER_MAC, all_mac);
	def_kex = ميلاپ_filter_allowlist(KEX_SERVER_KEX, all_kex);
	def_ڪنجي = ميلاپ_filter_allowlist(KEX_DEFAULT_PK_ALG, all_ڪنجي);
	def_sig = ميلاپ_filter_allowlist(SSH_ALLOWED_CA_SIGALGS, all_sig);
#وصف_ڪريو ASSEMBLE(what, defaults, all) \
	افعل { \
		إذا ((r = kex_assemble_نالا(&o->what, defaults, all)) != 0) \
			fatal_fr(r, "%s", #what); \
	} طالما (0)
	ASSEMBLE(ciphers, def_cipher, all_cipher);
	ASSEMBLE(macs, def_mac, all_mac);
	ASSEMBLE(kex_algorithms, def_kex, all_kex);
	ASSEMBLE(hostkeyalgorithms, def_ڪنجي, all_ڪنجي);
	ASSEMBLE(hostbased_accepted_algos, def_ڪنجي, all_ڪنجي);
	ASSEMBLE(pubkey_accepted_algos, def_ڪنجي, all_ڪنجي);
	ASSEMBLE(ca_sign_algorithms, def_sig, all_sig);
#وصف_رد ASSEMBLE
	حرر(all_cipher);
	حرر(all_mac);
	حرر(all_kex);
	حرر(all_ڪنجي);
	حرر(all_sig);
	حرر(def_cipher);
	حرر(def_mac);
	حرر(def_kex);
	حرر(def_ڪنجي);
	حرر(def_sig);
}

فراغ
servconf_جوڙيو_hostkey(ثابت حرف *file, ثابت صحيح سٽ,
    ServerOptions *options, ثابت حرف *رستو, صحيح userprovided)
{
	حرف *apath = derelativise_رستو(رستو);

	opt_array_append2(file, سٽ, "HostKey",
	    &options->host_ڪنجي_files, &options->host_ڪنجي_file_userprovided,
	    &options->انگ_host_ڪنجي_files, apath, userprovided);
	حرر(apath);
}

فراغ
servconf_جوڙيو_hostcert(ثابت حرف *file, ثابت صحيح سٽ,
    ServerOptions *options, ثابت حرف *رستو)
{
	حرف *apath = derelativise_رستو(رستو);

	opt_array_append(file, سٽ, "HostCertificate",
	    &options->host_cert_files, &options->انگ_host_cert_files, apath);
	حرر(apath);
}

فراغ
fill_default_server_options(ServerOptions *options)
{
	u_int i;

	/* Portable-specific overrides */
#جيڪڏهن_وصف_ٿيل SKIP_PRIVDROP
	إذا (options->allow_streamlocal_forwarding != -1 &&
	    options->allow_streamlocal_forwarding != FORWARD_DENY)
		logit("StreamlocalForwarding is not supported on this system");
	options->allow_streamlocal_forwarding = 0;
	إذا (options->fwd_opts.gateway_ports != -1 &&
	    options->fwd_opts.gateway_ports != 0)
		logit("GatewayPorts is not supported on this system");
	options->fwd_opts.gateway_ports = 0;
#جيڪڏهن_پورو

#وصف_ڪريو SSHCONF_INT(var, conf, flags, ms, def, cp) \
	إذا (options->var == -1) \
		options->var = def;
#وصف_ڪريو SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	إذا (options->var == -1) \
		options->var = def;
#وصف_ڪريو SSHCONF_STRING(var, conf, flags, cp)		/* done manually */
#وصف_ڪريو SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	/* done manually */
#وصف_ڪريو SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	/* done manually */
#وصف_ڪريو SSHCONF_NONCONF(funcsuffix)			/* done manually */
#وصف_ڪريو SSHCONF_DEPRECATE(conf, flags, opcode)		/*خالي_جايون*/
#وصف_ڪريو SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#وصف_ڪريو SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	افعل { \
		حرر(options->var); \
		options->var = عدم; \
	} طالما (0);
#وصف_ڪريو SSHCONF_ALIAS(old, conf, flags)			/*خالي_جايون*/

	/* XXX maybe use macros here too to force consistency? */

	SSHD_CONFIG_ENTRIES

#وصف_رد SSHCONF_INT
#وصف_رد SSHCONF_INTFLAG
#وصف_رد SSHCONF_STRING
#وصف_رد SSHCONF_STRARRAY
#وصف_رد SSHCONF_CUSTOM
#وصف_رد SSHCONF_NONCONF
#وصف_رد SSHCONF_DEPRECATE
#وصف_رد SSHCONF_UNSUPPORTED_INT
#وصف_رد SSHCONF_UNSUPPORTED_STRING
#وصف_رد SSHCONF_ALIAS

#جيڪڏهن_وصف_ٿيل USE_PAM
	إذا (options->pam_service_name == عدم)
		options->pam_service_name = xstrdup(SSHD_PAM_SERVICE);
#جيڪڏهن_پورو

	إذا (options->انگ_host_ڪنجي_files == 0) {
		/* fill default hostkeys */
		servconf_جوڙيو_hostkey("[default]", 0, options,
		    رستو_HOST_RSA_ڪنجي_FILE, 0);
		servconf_جوڙيو_hostkey("[default]", 0, options,
		    رستو_HOST_ECDSA_ڪنجي_FILE, 0);
		servconf_جوڙيو_hostkey("[default]", 0, options,
		    رستو_HOST_ED25519_ڪنجي_FILE, 0);
		servconf_جوڙيو_hostkey("[default]", 0, options,
		    رستو_HOST_MLDSA44_ED25519_ڪنجي_FILE, 0);
	}
	/* No certificates by default */
	إذا (options->انگ_ports == 0)
		options->ports[options->انگ_ports++] = SSH_DEFAULT_پورٽ;
	إذا (options->listen_addrs == عدم)
		جوڙيو_listen_addr(options, عدم, عدم, 0);
	إذا (options->pid_file == عدم)
		options->pid_file = xstrdup(رستو_SSH_DAEMON_PID_FILE);
	إذا (options->moduli_file == عدم)
		options->moduli_file = xstrdup(رستو_DH_MODULI);
	إذا (options->xauth_location == عدم)
		options->xauth_location = xstrdup(رستو_XAUTH);
	إذا (options->log_facility == SYSLOG_FACILITY_NOT_سيٽ)
		options->log_facility = SYSLOG_FACILITY_AUTH;
	إذا (options->log_level == SYSLOG_LEVEL_NOT_سيٽ)
		options->log_level = SYSLOG_LEVEL_INFO;
	إذا (options->permit_user_env == -1) {
		options->permit_user_env = 0;
		options->permit_user_env_allowlist = عدم;
	}
	إذا (options->rekey_حد_بندي == -1)
		options->rekey_حد_بندي = 0;
	إذا (options->rekey_interval == -1)
		options->rekey_interval = 0;
	إذا (options->fwd_opts.gateway_ports == -1)
		options->fwd_opts.gateway_ports = 0;
	إذا (options->max_startups == -1)
		options->max_startups = 100;
	إذا (options->max_startups_شرح == -1)
		options->max_startups_شرح = 30;		/* 30% */
	إذا (options->max_startups_begin == -1)
		options->max_startups_begin = 10;
	إذا (options->في_ذريعو_masklen_ipv4 == -1)
		options->في_ذريعو_masklen_ipv4 = 32;
	إذا (options->في_ذريعو_masklen_ipv6 == -1)
		options->في_ذريعو_masklen_ipv6 = 128;
	إذا (options->في_ذريعو_penalty.enabled == -1)
		options->في_ذريعو_penalty.enabled = 1;
	إذا (options->في_ذريعو_penalty.max_sources4 == -1)
		options->في_ذريعو_penalty.max_sources4 = 65536;
	إذا (options->في_ذريعو_penalty.max_sources6 == -1)
		options->في_ذريعو_penalty.max_sources6 = 65536;
	إذا (options->في_ذريعو_penalty.حد_کان_مٿي_گهڻائي == -1)
		options->في_ذريعو_penalty.حد_کان_مٿي_گهڻائي = في_ذريعو_PENALTY_حد_کان_مٿي_PERMISSIVE;
	إذا (options->في_ذريعو_penalty.حد_کان_مٿي_mode6 == -1)
		options->في_ذريعو_penalty.حد_کان_مٿي_mode6 = options->في_ذريعو_penalty.حد_کان_مٿي_گهڻائي;
	إذا (options->في_ذريعو_penalty.penalty_crash < 0.0)
		options->في_ذريعو_penalty.penalty_crash = 90.0;
	إذا (options->في_ذريعو_penalty.penalty_grace < 0.0)
		options->في_ذريعو_penalty.penalty_grace = 10.0;
	إذا (options->في_ذريعو_penalty.penalty_authfail < 0.0)
		options->في_ذريعو_penalty.penalty_authfail = 5.0;
	إذا (options->في_ذريعو_penalty.penalty_invaliduser < 0.0)
		options->في_ذريعو_penalty.penalty_invaliduser = 5.0;
	إذا (options->في_ذريعو_penalty.penalty_noauth < 0.0)
		options->في_ذريعو_penalty.penalty_noauth = 1.0;
	إذا (options->في_ذريعو_penalty.penalty_refuseconnection < 0.0)
		options->في_ذريعو_penalty.penalty_refuseconnection = 10.0;
	إذا (options->في_ذريعو_penalty.penalty_min < 0.0)
		options->في_ذريعو_penalty.penalty_min = 15.0;
	إذا (options->في_ذريعو_penalty.penalty_max < 0.0)
		options->في_ذريعو_penalty.penalty_max = 600.0;
	إذا (options->انگ_authkeys_files == 0) {
		opt_array_append("[default]", 0, "AuthorizedKeysFiles",
		    &options->authorized_ڪنجيون_files,
		    &options->انگ_authkeys_files,
		    رستو_SSH_USER_PERMITTED_ڪنجيون);
		opt_array_append("[default]", 0, "AuthorizedKeysFiles",
		    &options->authorized_ڪنجيون_files,
		    &options->انگ_authkeys_files,
		    رستو_SSH_USER_PERMITTED_KEYS2);
	}
	إذا (options->ip_qos_interactive == -1)
		options->ip_qos_interactive = IPTOS_DSCP_EF;
	إذا (options->ip_qos_bulk == -1)
		options->ip_qos_bulk = IPTOS_DSCP_CS0;
	إذا (options->نسخو_addendum == عدم)
		options->نسخو_addendum = xstrdup("");
	إذا (options->fwd_opts.streamlocal_bind_نقاب == (گهڻائي_t)-1)
		options->fwd_opts.streamlocal_bind_نقاب = 0177;
	إذا (options->fwd_opts.streamlocal_bind_unlink == -1)
		options->fwd_opts.streamlocal_bind_unlink = 0;
	إذا (options->sk_provider == عدم)
		options->sk_provider = xstrdup("internal");
	إذا (options->sshd_session_رستو == عدم)
		options->sshd_session_رستو = xstrdup(رستو_SSHD_SESSION);
	إذا (options->sshd_auth_رستو == عدم)
		options->sshd_auth_رستو = xstrdup(رستو_SSHD_AUTH);
	إذا (options->pubkey_auth_options == -1) {
		options->pubkey_auth_options = 0;
		options->max_pubkey_ok = DEFAULT_AUTH_FAIL_MAX;
	}
	إذا (options->agent_socket_رستو == عدم)
		options->agent_socket_رستو = xstrdup(رستو_SSH_AGENT_SOCKET_DIR);

	assemble_algorithms(options);

#وصف_ڪريو CLEAR_ON_NONE(v) \
	افعل { \
		إذا (option_clear_or_none(v)) { \
			حرر(v); \
			v = عدم; \
		} \
	} طالما(0)
#وصف_ڪريو CLEAR_ON_NONE_ARRAY(v, nv, none) \
	افعل { \
		إذا (options->nv == 1 && \
		    strcasecmp(options->v[0], none) == 0) { \
			حرر(options->v[0]); \
			حرر(options->v); \
			options->v = عدم; \
			options->nv = 0; \
		} \
	} طالما (0)
	CLEAR_ON_NONE(options->pid_file);
	CLEAR_ON_NONE(options->xauth_location);
	CLEAR_ON_NONE(options->banner);
	CLEAR_ON_NONE(options->trusted_user_ca_ڪنجيون);
	CLEAR_ON_NONE(options->sk_provider);
	CLEAR_ON_NONE(options->authorized_principals_file);
	CLEAR_ON_NONE(options->adm_forced_command);
	CLEAR_ON_NONE(options->chroot_directory);
	CLEAR_ON_NONE(options->routing_domain);
	CLEAR_ON_NONE(options->host_ڪنجي_agent);
	CLEAR_ON_NONE(options->في_ذريعو_penalty_exempt);
	CLEAR_ON_NONE(options->agent_socket_رستو);

	لكل (i = 0; i < options->انگ_host_ڪنجي_files; i++)
		CLEAR_ON_NONE(options->host_ڪنجي_files[i]);
	لكل (i = 0; i < options->انگ_host_cert_files; i++)
		CLEAR_ON_NONE(options->host_cert_files[i]);

	CLEAR_ON_NONE_ARRAY(channel_timeouts, انگ_channel_timeouts, "none");
	CLEAR_ON_NONE_ARRAY(auth_methods, انگ_auth_methods, "any");
	CLEAR_ON_NONE_ARRAY(revoked_ڪنجيون_files, انگ_revoked_ڪنجيون_files, "none");
	CLEAR_ON_NONE_ARRAY(authorized_ڪنجيون_files, انگ_authkeys_files, "none");
#وصف_رد CLEAR_ON_NONE
#وصف_رد CLEAR_ON_NONE_ARRAY
}

/* Macros to declare ServerOpCodes enum values */
#وصف_ڪريو SSHCONF_INT(var, conf, flags, ms, def, cp)	s##conf,
#وصف_ڪريو SSHCONF_INTFLAG(var, conf, flags, def, cp)	s##conf,
#وصف_ڪريو SSHCONF_STRING(var, conf, flags, cp)		s##conf,
#وصف_ڪريو SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	s##conf,
#وصف_ڪريو SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	s##conf,
#وصف_ڪريو SSHCONF_NONCONF(funcsuffix)			/*خالي_جايون*/
#وصف_ڪريو SSHCONF_DEPRECATE(conf, flags, opcode)		/*خالي_جايون*/
#وصف_ڪريو SSHCONF_UNSUPPORTED_INT(var, conf, flags)	/*خالي_جايون*/
#وصف_ڪريو SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	/*خالي_جايون*/
#وصف_ڪريو SSHCONF_ALIAS(old, conf, flags)			/*خالي_جايون*/

/* Keyword tokens. */
تعريفنوع تعداد {
	sBadOption,		/* == unknown option */
	SSHD_CONFIG_ENTRIES
	s_ميلاپ, sInclude,
	sDeprecated, sIgnore, sUnsupported
} ServerOpCodes;
#وصف_رد SSHCONF_INT
#وصف_رد SSHCONF_INTFLAG
#وصف_رد SSHCONF_STRING
#وصف_رد SSHCONF_STRARRAY
#وصف_رد SSHCONF_CUSTOM
#وصف_رد SSHCONF_NONCONF
#وصف_رد SSHCONF_DEPRECATE
#وصف_رد SSHCONF_UNSUPPORTED_INT
#وصف_رد SSHCONF_UNSUPPORTED_STRING
#وصف_رد SSHCONF_ALIAS

#وصف_ڪريو SSHCFG_GLOBAL		0x01	/* allowed in main section of config */
#وصف_ڪريو SSHCFG_ميلاپ		0x02	/* allowed inside a Match section */
#وصف_ڪريو SSHCFG_ALL		(SSHCFG_GLOBAL|SSHCFG_ميلاپ)
#وصف_ڪريو SSHCFG_NEVERMATCH	0x04  /* Match never matches; internal only */
#وصف_ڪريو SSHCFG_ميلاپ_ONLY	0x08  /* Match only in conditional blocks; internal only */

/* Macros to define keywords[] entries */
#وصف_ڪريو SSHCONF_KW(conf, flags)		{ #conf, s##conf, flags },
#وصف_ڪريو SSHCONF_INT(var, conf, flags, ms, def, cp)	SSHCONF_KW(conf, flags)
#وصف_ڪريو SSHCONF_INTFLAG(var, conf, flags, def, cp)	SSHCONF_KW(conf, flags)
#وصف_ڪريو SSHCONF_STRING(var, conf, flags, cp)		SSHCONF_KW(conf, flags)
#وصف_ڪريو SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	SSHCONF_KW(conf, flags)
#وصف_ڪريو SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	SSHCONF_KW(conf, flags)
#وصف_ڪريو SSHCONF_NONCONF(funcsuffix)			/*خالي_جايون*/
#وصف_ڪريو SSHCONF_DEPRECATED				sDeprecated
#وصف_ڪريو SSHCONF_IGNORE					sIgnore
#وصف_ڪريو SSHCONF_DEPRECATE(conf, flags, opcode) \
	{ #conf, opcode, flags },
#وصف_ڪريو SSHCONF_UNSUPPORTED_INT(var, conf, flags) \
	{ #conf, sUnsupported, flags },
#وصف_ڪريو SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	{ #conf, sUnsupported, flags },
#وصف_ڪريو SSHCONF_ALIAS(old, conf, flags) \
	{ #old, s##conf, flags },

/* Textual representation of the tokens. */
ساكن بنية {
	ثابت حرف *name;
	ServerOpCodes opcode;
	u_int flags;
} keywords[] = {
	SSHD_CONFIG_ENTRIES
	{ "match", s_ميلاپ, SSHCFG_ALL },
	{ "include", sInclude, SSHCFG_ALL },
	{ عدم, sBadOption, 0 }
};
#وصف_رد SSHCONF_INT
#وصف_رد SSHCONF_INTFLAG
#وصف_رد SSHCONF_STRING
#وصف_رد SSHCONF_STRARRAY
#وصف_رد SSHCONF_CUSTOM
#وصف_رد SSHCONF_NONCONF
#وصف_رد SSHCONF_DEPRECATED
#وصف_رد SSHCONF_IGNORE
#وصف_رد SSHCONF_DEPRECATE
#وصف_رد SSHCONF_UNSUPPORTED_INT
#وصف_رد SSHCONF_UNSUPPORTED_STRING
#وصف_رد SSHCONF_ALIAS

ساكن بنية {
	صحيح val;
	حرف *متن;
} tunmode_desc[] = {
	{ SSH_TUNMODE_NO, "no" },
	{ SSH_TUNMODE_POINTOPOINT, "point-to-point" },
	{ SSH_TUNMODE_ETHERNET, "ethernet" },
	{ SSH_TUNMODE_YES, "yes" },
	{ -1, عدم }
};

/* Returns an opcode name from its number */

ساكن ثابت حرف *
lookup_opcode_name(ServerOpCodes ڪوڊ)
{
	u_int i;

	لكل (i = 0; keywords[i].name != عدم; i++)
		إذا (keywords[i].opcode == ڪوڊ)
			أرجع(keywords[i].name);
	أرجع "UNKNOWN";
}


/*
 * Returns the number of the token pointed to by cp or sBadOption.
 */

ساكن ServerOpCodes
parse_token(ثابت حرف *cp, ثابت حرف *filename,
	    صحيح linenum, u_int *flags)
{
	u_int i;

	لكل (i = 0; keywords[i].name; i++)
		إذا (strcasecmp(cp, keywords[i].name) == 0) {
			*flags = keywords[i].flags;
			أرجع keywords[i].opcode;
		}

	error("%s: line %d: Bad configuration option: %s",
	    filename, linenum, cp);
	أرجع sBadOption;
}

حرف *
derelativise_رستو(ثابت حرف *رستو)
{
	حرف *expanded, *ret, cwd[PATH_MAX];

	إذا (strcasecmp(رستو, "none") == 0)
		أرجع xstrdup("none");
	expanded = tilde_expand_filename(رستو, getuid());
	إذا (رستو_absolute(expanded))
		أرجع expanded;
	إذا (getcwd(cwd, حجم(cwd)) == عدم)
		fatal_f("getcwd: %s", strerror(errno));
	xasprintf(&ret, "%s/%s", cwd, expanded);
	حرر(expanded);
	أرجع ret;
}

ساكن فراغ
جوڙيو_listen_addr(ServerOptions *options, ثابت حرف *addr,
    ثابت حرف *rdomain, صحيح پورٽ)
{
	u_int i;

	إذا (پورٽ > 0)
		جوڙيو_one_listen_addr(options, addr, rdomain, پورٽ);
	وإلا {
		لكل (i = 0; i < options->انگ_ports; i++) {
			جوڙيو_one_listen_addr(options, addr, rdomain,
			    options->ports[i]);
		}
	}
}

ساكن فراغ
جوڙيو_one_listen_addr(ServerOptions *options, ثابت حرف *addr,
    ثابت حرف *rdomain, صحيح پورٽ)
{
	بنية addrinfo hints, *ai, *aitop;
	حرف strport[NI_MAXSERV];
	صحيح gaierr;
	u_int i;

	/* Find listen_addrs entry for this rdomain */
	لكل (i = 0; i < options->انگ_listen_addrs; i++) {
		إذا (rdomain == عدم && options->listen_addrs[i].rdomain == عدم)
			اكسر;
		إذا (rdomain == عدم || options->listen_addrs[i].rdomain == عدم)
			استمر;
		إذا (strcmp(rdomain, options->listen_addrs[i].rdomain) == 0)
			اكسر;
	}
	إذا (i >= options->انگ_listen_addrs) {
		/* No entry for this rdomain; allocate one */
		إذا (i >= وڌ_کان_وڌ_عدد)
			fatal_f("too many listen addresses");
		options->listen_addrs = xrecallocarray(options->listen_addrs,
		    options->انگ_listen_addrs, options->انگ_listen_addrs + 1,
		    حجم(*options->listen_addrs));
		i = options->انگ_listen_addrs++;
		إذا (rdomain != عدم)
			options->listen_addrs[i].rdomain = xstrdup(rdomain);
	}
	/* options->listen_addrs[i] points to the addresses for this rdomain */

	memset(&hints, 0, حجم(hints));
	hints.ai_family = options->پتو_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = (addr == عدم) ? AI_PASSIVE : 0;
	snprintf(strport, حجم strport, "%d", پورٽ);
	إذا ((gaierr = getaddrinfo(addr, strport, &hints, &aitop)) != 0)
		fatal("bad addr or host: %s (%s)",
		    addr ? addr : "<NULL>",
		    ssh_gai_strerror(gaierr));
	لكل (ai = aitop; ai->ai_next; ai = ai->ai_next)
		;
	ai->ai_next = options->listen_addrs[i].addrs;
	options->listen_addrs[i].addrs = aitop;
}

/* Returns nonzero if the routing domain name is valid */
ساكن صحيح
valid_rdomain(ثابت حرف *name)
{
#إذا defined(HAVE_SYS_VALID_RDOMAIN)
	أرجع sys_valid_rdomain(name);
#وإلاإذا defined(__OpenBSD__)
	ثابت حرف *errstr;
	ڊگهو ڊگهو انگ;
	بنية rt_tableinfo info;
	صحيح mib[6];
	سائيز_t miblen = حجم(mib);

	إذا (name == عدم)
		أرجع 1;

	انگ = strtonum(name, 0, 255, &errstr);
	إذا (errstr != عدم)
		أرجع 0;

	/* Check whether the table actually exists */
	memset(mib, 0, حجم(mib));
	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[4] = NET_RT_جدول;
	mib[5] = (صحيح)انگ;
	إذا (sysctl(mib, 6, &info, &miblen, عدم, 0) == -1)
		أرجع 0;

	أرجع 1;
#وإلا /* defined(__OpenBSD__) */
	error("Routing domains are not supported on this platform");
	أرجع 0;
#جيڪڏهن_پورو
}

/*
 * Queue a ListenAddress to be processed once we have all of the Ports
 * and AddressFamily options.
 */
ساكن فراغ
قطار_listen_addr(ServerOptions *options, ثابت حرف *addr,
    ثابت حرف *rdomain, صحيح پورٽ)
{
	بنية queued_listenaddr *qla;

	options->queued_listen_addrs = xrecallocarray(
	    options->queued_listen_addrs,
	    options->انگ_queued_listens, options->انگ_queued_listens + 1,
	    حجم(*options->queued_listen_addrs));
	qla = &options->queued_listen_addrs[options->انگ_queued_listens++];
	qla->addr = xstrdup(addr);
	qla->پورٽ = پورٽ;
	qla->rdomain = rdomain == عدم ? عدم : xstrdup(rdomain);
}

/*
 * Process queued (text) ListenAddress entries.
 */
ساكن فراغ
process_queued_listen_addrs(ServerOptions *options)
{
	u_int i;
	بنية queued_listenaddr *qla;

	إذا (options->انگ_ports == 0)
		options->ports[options->انگ_ports++] = SSH_DEFAULT_پورٽ;
	إذا (options->پتو_family == -1)
		options->پتو_family = AF_UNSPEC;

	لكل (i = 0; i < options->انگ_queued_listens; i++) {
		qla = &options->queued_listen_addrs[i];
		جوڙيو_listen_addr(options, qla->addr, qla->rdomain, qla->پورٽ);
		حرر(qla->addr);
		حرر(qla->rdomain);
	}
	حرر(options->queued_listen_addrs);
	options->queued_listen_addrs = عدم;
	options->انگ_queued_listens = 0;
}

/*
 * The strategy for the Match blocks is that the config file is parsed twice.
 *
 * The first time is at startup.  activep is initialized to 1 and the
 * directives in the global context are processed and acted on.  Hitting a
 * Match directive unsets activep and the directives inside the block are
 * checked for syntax only.
 *
 * The second time is after a connection has been established but before
 * authentication.  activep is initialized to 2 and global config directives
 * are ignored since they have already been processed.  If the criteria in a
 * Match block is met, activep is set and the subsequent directives
 * processed and actioned until EOF or another Match block unsets it.  Any
 * options set are copied into the main server config.
 *
 * Potential additions/improvements:
 *  - Add Match support for pre-kex directives, eg. Ciphers.
 *
 *  - Add a Tag directive (idea from David Leonard) ala pf, eg:
 *	Match Address 192.168.0.*
 *		Tag trusted
 *	Match Group wheel
 *		Tag trusted
 *	Match Tag trusted
 *		AllowTcpForwarding yes
 *		GatewayPorts clientspecified
 *		[...]
 *
 *  - Add a PermittedChannelRequests directive
 *	Match Group shell
 *		PermittedChannelRequests session,forwarded-tcpip
 */

ساكن صحيح
ميلاپ_cfg_سٽ_گروهه(ثابت حرف *grps, صحيح سٽ, ثابت حرف *user)
{
	صحيح نتيجو = 0;
	بنية passwd *pw;

	إذا (user == عدم)
		اذهب ٻاهريون;

	إذا ((pw = getpwnam(user)) == عدم) {
		debug("Can't match group at line %d because user %.100s does "
		    "not exist", سٽ, user);
	} وإلا إذا (ga_init(pw->pw_name, pw->pw_gid) == 0) {
		debug("Can't Match group because user %.100s not in any group "
		    "at line %d", user, سٽ);
	} وإلا إذا (ga_ميلاپ_نمونو_list(grps) != 1) {
		debug("user %.100s does not match group list %.100s at line %d",
		    user, grps, سٽ);
	} وإلا {
		debug("user %.100s matched group list %.100s at line %d", user,
		    grps, سٽ);
		نتيجو = 1;
	}
ٻاهريون:
	ga_free();
	أرجع نتيجو;
}

ساكن فراغ
ميلاپ_test_missing_fatal(ثابت حرف *criteria, ثابت حرف *attrib)
{
	fatal("'Match %s' in configuration but '%s' not in connection "
	    "test specification.", criteria, attrib);
}

/*
 * All of the attributes on a single Match line are ANDed together, so we need
 * to check every attribute and set the result to zero if any attribute does
 * not match.
 */
ساكن صحيح
ميلاپ_cfg_سٽ(ثابت حرف *ڀريل_سٽ, صحيح *acp, حرف ***avp,
    صحيح سٽ, بنية connection_info *ci)
{
	صحيح نتيجو = 1, خاصيتون = 0, پورٽ;
	حرف *arg, *attrib = عدم, *oattrib;

	إذا (ci == عدم) {
		debug3("checking syntax for 'Match %s' on line %d",
		    ڀريل_سٽ, سٽ);
	} وإلا {
		debug3("checking match for '%s' user %s%s host %s addr %s "
		    "laddr %s lport %d rdomain %s on line %d", ڀريل_سٽ,
		    ci->user ? ci->user : "(null)",
		    ci->user_invalid ? " (invalid)" : "",
		    ci->host ? ci->host : "(null)",
		    ci->پتو ? ci->پتو : "(null)",
		    ci->laddress ? ci->laddress : "(null)", ci->lport,
		    ci->rdomain ? ci->rdomain : "(null)", سٽ);
	}

	طالما ((oattrib = argv_ايندڙ(acp, avp)) != عدم) {
		/* Terminate on comment */
		إذا (*oattrib == '#') {
			argv_consume(acp); /* mark all arguments consumed */
			اكسر;
		}
		attrib = xstrdup(oattrib);
		arg = عدم;
		خاصيتون++;
		/* Criterion "all" has no argument and must appear alone */
		إذا (strcasecmp(attrib, "all") == 0) {
			إذا (خاصيتون > 1 ||
			    ((arg = argv_ايندڙ(acp, avp)) != عدم &&
			    *arg != '\0' && *arg != '#')) {
				error("'all' cannot be combined with other "
				    "Match attributes");
				نتيجو = -1;
				اذهب ٻاهريون;
			}
			إذا (arg != عدم && *arg == '#')
				argv_consume(acp); /* consume remaining args */
			نتيجو = 1;
			اذهب ٻاهريون;
		}
		/* Criterion "invalid-user" also has no argument */
		إذا (strcasecmp(attrib, "invalid-user") == 0) {
			إذا (ci == عدم) {
				نتيجو = 0;
				اذهب ايندڙ;
			}
			إذا (ci->user_invalid == 0)
				نتيجو = 0;
			وإلا
				debug("matched invalid-user at line %d", سٽ);
			اذهب ايندڙ;
		}

		/* Keep this list in sync with below */
		إذا (strprefix(attrib, "user=", 1) != عدم ||
		    strprefix(attrib, "group=", 1) != عدم ||
		    strprefix(attrib, "host=", 1) != عدم ||
		    strprefix(attrib, "address=", 1) != عدم ||
		    strprefix(attrib, "localaddress=", 1) != عدم ||
		    strprefix(attrib, "localport=", 1) != عدم ||
		    strprefix(attrib, "rdomain=", 1) != عدم ||
		    strprefix(attrib, "version=", 1) != عدم) {
			arg = strchr(attrib, '=');
			*(arg++) = '\0';
		} وإلا {
			arg = argv_ايندڙ(acp, avp);
		}

		/* All other criteria require an argument */
		إذا (arg == عدم || *arg == '\0' || *arg == '#') {
			error("Missing Match criteria for %s", attrib);
			نتيجو = -1;
			اذهب ٻاهريون;
		}
		إذا (strcasecmp(attrib, "user") == 0) {
			إذا (ci == عدم || (ci->test && ci->user == عدم)) {
				نتيجو = 0;
				اذهب ايندڙ;
			}
			إذا (ci->user == عدم)
				ميلاپ_test_missing_fatal("User", "user");
			إذا (ميلاپ_usergroup_نمونو_list(ci->user, arg) != 1)
				نتيجو = 0;
			وإلا
				debug("user %.100s matched 'User %.100s' at "
				    "line %d", ci->user, arg, سٽ);
		} وإلا إذا (strcasecmp(attrib, "group") == 0) {
			إذا (ci == عدم || (ci->test && ci->user == عدم)) {
				نتيجو = 0;
				اذهب ايندڙ;
			}
			إذا (ci->user == عدم)
				ميلاپ_test_missing_fatal("Group", "user");
			بدل (ميلاپ_cfg_سٽ_گروهه(arg, سٽ, ci->user)) {
			حالة -1:
				نتيجو = -1;
				اذهب ٻاهريون;
			حالة 0:
				نتيجو = 0;
			}
		} وإلا إذا (strcasecmp(attrib, "host") == 0) {
			إذا (ci == عدم || (ci->test && ci->host == عدم)) {
				نتيجو = 0;
				اذهب ايندڙ;
			}
			إذا (ci->host == عدم)
				ميلاپ_test_missing_fatal("Host", "host");
			إذا (ميلاپ_hostname(ci->host, arg) != 1)
				نتيجو = 0;
			وإلا
				debug("connection from %.100s matched 'Host "
				    "%.100s' at line %d", ci->host, arg, سٽ);
		} وإلا إذا (strcasecmp(attrib, "address") == 0) {
			إذا (ci == عدم || (ci->test && ci->پتو == عدم)) {
				إذا (addr_ميلاپ_list(عدم, arg) != 0)
					fatal("Invalid Match address argument "
					    "'%s' at line %d", arg, سٽ);
				نتيجو = 0;
				اذهب ايندڙ;
			}
			إذا (ci->پتو == عدم)
				ميلاپ_test_missing_fatal("Address", "addr");
			بدل (addr_ميلاپ_list(ci->پتو, arg)) {
			حالة 1:
				debug("connection from %.100s matched 'Address "
				    "%.100s' at line %d", ci->پتو, arg, سٽ);
				اكسر;
			حالة 0:
			حالة -1:
				نتيجو = 0;
				اكسر;
			حالة -2:
				نتيجو = -1;
				اذهب ٻاهريون;
			}
		} وإلا إذا (strcasecmp(attrib, "localaddress") == 0){
			إذا (ci == عدم || (ci->test && ci->laddress == عدم)) {
				إذا (addr_ميلاپ_list(عدم, arg) != 0)
					fatal("Invalid Match localaddress "
					    "argument '%s' at line %d", arg,
					    سٽ);
				نتيجو = 0;
				اذهب ايندڙ;
			}
			إذا (ci->laddress == عدم)
				ميلاپ_test_missing_fatal("LocalAddress",
				    "laddr");
			بدل (addr_ميلاپ_list(ci->laddress, arg)) {
			حالة 1:
				debug("connection from %.100s matched "
				    "'LocalAddress %.100s' at line %d",
				    ci->laddress, arg, سٽ);
				اكسر;
			حالة 0:
			حالة -1:
				نتيجو = 0;
				اكسر;
			حالة -2:
				نتيجو = -1;
				اذهب ٻاهريون;
			}
		} وإلا إذا (strcasecmp(attrib, "localport") == 0) {
			إذا ((پورٽ = a2port(arg)) == -1) {
				error("Invalid LocalPort '%s' on Match line",
				    arg);
				نتيجو = -1;
				اذهب ٻاهريون;
			}
			إذا (ci == عدم || (ci->test && ci->lport == -1)) {
				نتيجو = 0;
				اذهب ايندڙ;
			}
			إذا (ci->lport == 0)
				ميلاپ_test_missing_fatal("LocalPort", "lport");
			/* TODO support port lists */
			إذا (پورٽ == ci->lport)
				debug("connection from %.100s matched "
				    "'LocalPort %d' at line %d",
				    ci->laddress, پورٽ, سٽ);
			وإلا
				نتيجو = 0;
		} وإلا إذا (strcasecmp(attrib, "rdomain") == 0) {
			إذا (ci == عدم || (ci->test && ci->rdomain == عدم)) {
				نتيجو = 0;
				اذهب ايندڙ;
			}
			إذا (ci->rdomain == عدم)
				ميلاپ_test_missing_fatal("RDomain", "rdomain");
			إذا (ميلاپ_نمونو_list(ci->rdomain, arg, 0) != 1)
				نتيجو = 0;
			وإلا
				debug("connection RDomain %.100s matched "
				    "'RDomain %.100s' at line %d",
				    ci->rdomain, arg, سٽ);
		} وإلا إذا (strcasecmp(attrib, "version") == 0) {
			إذا (ميلاپ_نمونو_list(SSH_RELEASE, arg, 0) != 1)
				نتيجو = 0;
			وإلا
				debug("version %.100s matched "
				    "'version %.100s' at line %d",
				    SSH_RELEASE, arg, سٽ);
		} وإلا {
			error("Unsupported Match attribute %s", oattrib);
			نتيجو = -1;
			اذهب ٻاهريون;
		}
 ايندڙ:
		حرر(attrib);
		attrib = عدم;
	}
	إذا (خاصيتون == 0) {
		error("One or more attributes required for Match");
		أرجع -1;
	}
 ٻاهريون:
	إذا (ci != عدم && نتيجو != -1)
		debug3("match %sfound on line %d", نتيجو ? "" : "not ", سٽ);
	حرر(attrib);
	أرجع نتيجو;
}

#وصف_ڪريو WHITESPACE " \t\r\n"

/* Multistate option parsing */
بنية multistate {
	حرف *ڪنجي;
	صحيح قدر;
};
ساكن ثابت بنية multistate multistate_flag[] = {
	{ "yes",			1 },
	{ "no",				0 },
	{ عدم, -1 }
};
ساكن ثابت بنية multistate multistate_ignore_rhosts[] = {
	{ "yes",			IGNORE_RHOSTS_YES },
	{ "no",				IGNORE_RHOSTS_NO },
	{ "shosts-only",		IGNORE_RHOSTS_SHOSTS },
	{ عدم, -1 }
};
ساكن ثابت بنية multistate multistate_addressfamily[] = {
	{ "inet",			AF_INET },
	{ "inet6",			AF_INET6 },
	{ "any",			AF_UNSPEC },
	{ عدم, -1 }
};
ساكن ثابت بنية multistate multistate_permitrootlogin[] = {
	{ "prohibit-password",		PERMIT_NO_PASSWD },
	{ "without-password",		PERMIT_NO_PASSWD },
	{ "forced-commands-only",	PERMIT_FORCED_ONLY },
	{ "yes",			PERMIT_YES },
	{ "no",				PERMIT_NO },
	{ عدم, -1 }
};
ساكن ثابت بنية multistate multistate_compression[] = {
#جيڪڏهن_وصف_ٿيل WITH_ZLIB
	{ "yes",			COMP_DELAYED },
	{ "delayed",			COMP_DELAYED },
#جيڪڏهن_پورو
	{ "no",				COMP_NONE },
	{ عدم, -1 }
};
ساكن ثابت بنية multistate multistate_gatewayports[] = {
	{ "clientspecified",		2 },
	{ "yes",			1 },
	{ "no",				0 },
	{ عدم, -1 }
};
ساكن ثابت بنية multistate multistate_tcpfwd[] = {
	{ "yes",			FORWARD_ALLOW },
	{ "all",			FORWARD_ALLOW },
	{ "no",				FORWARD_DENY },
	{ "remote",			FORWARD_REMOTE },
	{ "local",			FORWARD_LOCAL },
	{ عدم, -1 }
};
ساكن ثابت بنية multistate multistate_keepalives[] = {
	{ "true",			SSH_KEEPALIVES_TRANSPORT },
	{ "false",			SSH_KEEPALIVES_OFF },
	{ "yes",			SSH_KEEPALIVES_TRANSPORT },
	{ "no",				SSH_KEEPALIVES_OFF },
	{ "transport",			SSH_KEEPALIVES_TRANSPORT },
	{ "all",			SSH_KEEPALIVES_ALL },
	{ عدم, -1 }
};
ساكن ثابت بنية multistate multistate_warnweakcrypto[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "no-pq-kex",			0 },
	{ عدم, -1 }
};

ساكن صحيح
process_server_config_سٽ_اونهائي(ServerOptions *options, حرف *سٽ,
    ثابت حرف *filename, صحيح linenum, صحيح *activep,
    بنية connection_info *connectinfo, صحيح *inc_flags, صحيح اونهائي,
    بنية include_list *includes)
{
	حرف *str, ***chararrayptr, **charptr, *arg, *arg2, *p, *keyword;
	صحيح cmdline = 0, *intptr, قدر, value2, value3, n, پورٽ, oactive, r;
	مزدوج dvalue, *doubleptr = عدم;
	صحيح ca_only = 0, مليو = 0;
	SyslogFacility *log_facility_ptr;
	LogLevel *log_level_ptr;
	ServerOpCodes opcode;
	u_int i, *uintptr, flags = 0;
	سائيز_t len;
	ڊگهو ڊگهو val64;
	ثابت بنية multistate *multistate_ptr;
	ثابت حرف *errstr;
	بنية include_شي *شي;
	glob_t gbuf;
	حرف **oav = عدم, **av;
	صحيح oac = 0, ac;
	صحيح ret = -1;
	حرف **strs = عدم; /* string array arguments; freed implicitly */
	u_int nstrs = 0;

	/* Strip trailing whitespace. Allow \f (form feed) at EOL only */
	إذا ((len = لڙي_ڊيگهه(سٽ)) == 0)
		أرجع 0;
	لكل (len--; len > 0; len--) {
		إذا (strchr(WHITESPACE "\f", سٽ[len]) == عدم)
			اكسر;
		سٽ[len] = '\0';
	}

	str = سٽ;
	إذا ((keyword = strdelim(&str)) == عدم)
		أرجع 0;
	/* Ignore leading whitespace */
	إذا (*keyword == '\0')
		keyword = strdelim(&str);
	إذا (!keyword || !*keyword || *keyword == '#')
		أرجع 0;
	إذا (str == عدم || *str == '\0') {
		error("%s line %d: no argument after keyword \"%s\"",
		    filename, linenum, keyword);
		أرجع -1;
	}
	intptr = عدم;
	charptr = عدم;
	opcode = parse_token(keyword, filename, linenum, &flags);

	إذا (argv_ورهايو(str, &oac, &oav, 1) != 0) {
		error("%s line %d: invalid quotes", filename, linenum);
		أرجع -1;
	}
	ac = oac;
	av = oav;

	إذا (activep == عدم) { /* We are processing a command line directive */
		cmdline = 1;
		activep = &cmdline;
	}
	إذا (*activep && opcode != s_ميلاپ && opcode != sInclude)
		debug3("%s:%d setting %s %s", filename, linenum, keyword, str);
	إذا (*activep == 0 && !(flags & SSHCFG_ميلاپ)) {
		إذا (connectinfo == عدم) {
			fatal("%s line %d: Directive '%s' is not allowed "
			    "within a Match block", filename, linenum, keyword);
		} وإلا { /* this is a directive we have already processed */
			ret = 0;
			اذهب ٻاهريون;
		}
	}

	بدل (opcode) {
	/* Portable-specific options */
#جيڪڏهن_وصف_ٿيل USE_PAM
	حالة sUsePAM:
		intptr = &options->use_pam;
		اذهب parse_flag;
	حالة sPAMServiceName:
		charptr = &options->pam_service_name;
		arg = argv_ايندڙ(&ac, &av);
		إذا (!arg || *arg == '\0') {
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		}
		إذا (*activep && *charptr == عدم)
			*charptr = xstrdup(arg);
		اكسر;
#جيڪڏهن_پورو

	/* Standard Options */
	حالة sBadOption:
		اذهب ٻاهريون;
	حالة s_پورٽ:
		/* ignore ports from configfile if cmdline specifies ports */
		إذا (options->ports_from_cmdline) {
			argv_consume(&ac);
			اكسر;
		}
		إذا (options->انگ_ports >= MAX_PORTS)
			fatal("%s line %d: too many ports.",
			    filename, linenum);
		arg = argv_ايندڙ(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: missing port number.",
			    filename, linenum);
		options->ports[options->انگ_ports++] = a2port(arg);
		إذا (options->ports[options->انگ_ports-1] <= 0)
			fatal("%s line %d: Badly formatted port number.",
			    filename, linenum);
		اكسر;

	حالة s_Login_Grace_وقت:
		intptr = &options->login_grace_وقت;
 parse_وقت:
		arg = argv_ايندڙ(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: missing time value.",
			    filename, linenum);
		إذا ((قدر = convtime(arg)) == -1)
			fatal("%s line %d: invalid time value.",
			    filename, linenum);
		إذا (*activep && *intptr == -1)
			*intptr = قدر;
		اكسر;

	حالة s_Listen_پتو:
		arg = argv_ايندڙ(&ac, &av);
		إذا (arg == عدم || *arg == '\0')
			fatal("%s line %d: missing address",
			    filename, linenum);
		/* check for bare IPv6 address: no "[]" and 2 or more ":" */
		إذا (strchr(arg, '[') == عدم && (p = strchr(arg, ':')) != عدم
		    && strchr(p+1, ':') != عدم) {
			پورٽ = 0;
			p = arg;
		} وإلا {
			arg2 = عدم;
			p = hpdelim(&arg);
			إذا (p == عدم)
				fatal("%s line %d: bad address:port usage",
				    filename, linenum);
			p = cleanhostname(p);
			إذا (arg == عدم)
				پورٽ = 0;
			وإلا إذا ((پورٽ = a2port(arg)) <= 0)
				fatal("%s line %d: bad port number",
				    filename, linenum);
		}
		/* Optional routing table */
		arg2 = عدم;
		إذا ((arg = argv_ايندڙ(&ac, &av)) != عدم) {
			إذا (strcmp(arg, "rdomain") != 0 ||
			    (arg2 = argv_ايندڙ(&ac, &av)) == عدم)
				fatal("%s line %d: bad ListenAddress syntax",
				    filename, linenum);
			إذا (!valid_rdomain(arg2))
				fatal("%s line %d: bad routing domain",
				    filename, linenum);
		}
		قطار_listen_addr(options, p, arg2, پورٽ);

		اكسر;

	حالة s_پتو_Family:
		intptr = &options->پتو_family;
		multistate_ptr = multistate_addressfamily;
 parse_multistate:
		arg = argv_ايندڙ(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		قدر = -1;
		لكل (i = 0; multistate_ptr[i].ڪنجي != عدم; i++) {
			إذا (strcasecmp(arg, multistate_ptr[i].ڪنجي) == 0) {
				قدر = multistate_ptr[i].قدر;
				اكسر;
			}
		}
		إذا (قدر == -1)
			fatal("%s line %d: unsupported option \"%s\".",
			    filename, linenum, arg);
		إذا (*activep && *intptr == -1)
			*intptr = قدر;
		اكسر;

	حالة s_Host_ڪنجي:
		arg = argv_ايندڙ(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		إذا (*activep) {
			servconf_جوڙيو_hostkey(filename, linenum,
			    options, arg, 1);
		}
		اكسر;

	حالة s_Host_ڪنجي_Agent:
		charptr = &options->host_ڪنجي_agent;
		arg = argv_ايندڙ(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: missing socket name.",
			    filename, linenum);
		إذا (*activep && *charptr == عدم)
			*charptr = !strcmp(arg, SSH_AUTHSOCKET_ENV_NAME) ?
			    xstrdup(arg) : derelativise_رستو(arg);
		اكسر;

	حالة sHostCertificate:
		arg = argv_ايندڙ(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		إذا (*activep)
			servconf_جوڙيو_hostcert(filename, linenum, options, arg);
		اكسر;

	حالة sPidFile:
		charptr = &options->pid_file;
 parse_filename:
		arg = argv_ايندڙ(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		إذا (*activep && *charptr == عدم) {
			*charptr = derelativise_رستو(arg);
			/* increase optional counter */
			إذا (intptr != عدم)
				*intptr = *intptr + 1;
		}
		اكسر;

	حالة sModuliFile:
		charptr = &options->moduli_file;
		اذهب parse_filename;

	حالة s_Permit_پاڙ_Login:
		intptr = &options->permit_پاڙ_login;
		multistate_ptr = multistate_permitrootlogin;
		اذهب parse_multistate;

	حالة sIgnoreRhosts:
		intptr = &options->ignore_rhosts;
		multistate_ptr = multistate_ignore_rhosts;
		اذهب parse_multistate;

	حالة s_Ignore_User_معلوم_Hosts:
		intptr = &options->ignore_user_معلوم_hosts;
 parse_flag:
		multistate_ptr = multistate_flag;
		اذهب parse_multistate;

	حالة sHostbasedAuthentication:
		intptr = &options->hostbased_authentication;
		اذهب parse_flag;

	حالة s_Hostbased_استعمال_ڪري_Name_From_Packet_Only:
		intptr = &options->hostbased_استعمال_ڪري_name_from_packet_only;
		اذهب parse_flag;

	حالة sHostbasedAcceptedAlgorithms:
		charptr = &options->hostbased_accepted_algos;
		ca_only = 0;
 parse_pubkey_algos:
		arg = argv_ايندڙ(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: Missing argument.",
			    filename, linenum);
		إذا (*arg != '-' &&
		    !sshkey_نالا_valid2(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg, 1, ca_only))
			fatal("%s line %d: Bad key types '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		إذا (*activep && *charptr == عدم)
			*charptr = xstrdup(arg);
		اكسر;

	حالة s_Host_ڪنجي_Algorithms:
		charptr = &options->hostkeyalgorithms;
		ca_only = 0;
		اذهب parse_pubkey_algos;

	حالة sCASignatureAlgorithms:
		charptr = &options->ca_sign_algorithms;
		ca_only = 1;
		اذهب parse_pubkey_algos;

	حالة sPubkeyAuthentication:
		intptr = &options->pubkey_authentication;
		ca_only = 0;
		اذهب parse_flag;

	حالة sPubkeyAcceptedAlgorithms:
		charptr = &options->pubkey_accepted_algos;
		ca_only = 0;
		اذهب parse_pubkey_algos;

	حالة sPubkeyAuthOptions:
		intptr = &options->pubkey_auth_options;
		قدر = 0;
		value2 = -1;
		طالما ((arg = argv_ايندڙ(&ac, &av)) != عدم) {
			إذا (strcasecmp(arg, "none") == 0)
				استمر;
			إذا (strcasecmp(arg, "touch-required") == 0)
				قدر |= PUBKEYAUTH_TOUCH_REQUIRED;
			وإلا إذا (strcasecmp(arg, "verify-required") == 0)
				قدر |= PUBKEYAUTH_VERIFY_REQUIRED;
			وإلا إذا (strncasecmp(arg, "max-pk-ok:", 10) == 0) {
				value2 = strtonum(arg + 10, 0, 255, &errstr);
				إذا (errstr != عدم) {
					error("%s line %d: bad %s max-pk-ok "
					    "value: %s", filename, linenum,
					keyword, errstr);
					اذهب ٻاهريون;
				}
			} وإلا {
				error("%s line %d: unsupported %s option %s",
				    filename, linenum, keyword, arg);
				اذهب ٻاهريون;
			}
		}
		إذا (*activep && options->pubkey_auth_options == -1) {
			options->pubkey_auth_options = قدر;
			options->max_pubkey_ok = value2;
		}
		اكسر;

#جيڪڏهن_وصف_ٿيل KRB5
	حالة sKerberosAuthentication:
		intptr = &options->kerberos_authentication;
		اذهب parse_flag;

	حالة sKerberosOrLocalPasswd:
		intptr = &options->kerberos_or_local_passwd;
		اذهب parse_flag;

	حالة sKerberosTicketCleanup:
		intptr = &options->kerberos_ticket_cleanup;
		اذهب parse_flag;
#جيڪڏهن_وصف_ٿيل USE_AFS
	حالة sKerberosGetAFSToken:
		intptr = &options->kerberos_get_afs_token;
		اذهب parse_flag;
#جيڪڏهن_پورو /* USE_AFS */
#جيڪڏهن_پورو /* KRB5 */

#جيڪڏهن_وصف_ٿيل GSSAPI
	حالة sGSSAPIAuthentication:
		intptr = &options->gss_authentication;
		اذهب parse_flag;

	حالة sGSSAPICleanupCredentials:
		intptr = &options->gss_cleanup_creds;
		اذهب parse_flag;

	حالة sGSSAPIDelegateCredentials:
		intptr = &options->gss_deleg_creds;
		اذهب parse_flag;

	حالة sGSSAPIStrictAcceptorCheck:
		intptr = &options->gss_strict_acceptor;
		اذهب parse_flag;
#جيڪڏهن_پورو /* GSSAPI */

	حالة sPasswordAuthentication:
		intptr = &options->password_authentication;
		اذهب parse_flag;

	حالة sKbdInteractiveAuthentication:
		intptr = &options->kbd_interactive_authentication;
		اذهب parse_flag;

	حالة sPrintMotd:
		intptr = &options->print_motd;
		اذهب parse_flag;

#جيڪڏهن_وصف_نه_ٿيل DISABLE_LASTLOG
	حالة s_Print_آخري_Log:
		intptr = &options->print_lastlog;
		اذهب parse_flag;
#جيڪڏهن_پورو

	حالة sX11Forwarding:
		intptr = &options->x11_forwarding;
		اذهب parse_flag;

	حالة s_X11_Display_وٿي:
		intptr = &options->x11_display_وٿي;
 parse_int:
		arg = argv_ايندڙ(&ac, &av);
		إذا ((errstr = atoi_err(arg, &قدر)) != عدم)
			fatal("%s line %d: %s integer value %s.",
			    filename, linenum, keyword, errstr);
		إذا (*activep && *intptr == -1)
			*intptr = قدر;
		اكسر;

	حالة sX11UseLocalhost:
		intptr = &options->x11_use_localhost;
		اذهب parse_flag;

	حالة sXAuthLocation:
		charptr = &options->xauth_location;
		اذهب parse_filename;

	حالة sPermitTTY:
		intptr = &options->permit_tty;
		اذهب parse_flag;

	حالة sPermitUserRC:
		intptr = &options->permit_user_rc;
		اذهب parse_flag;

	حالة sStrictModes:
		intptr = &options->strict_modes;
		اذهب parse_flag;

	حالة sTCPKeepAlive:
		intptr = &options->tcp_keep_alive;
		multistate_ptr = multistate_keepalives;
		اذهب parse_multistate;

	حالة s_Permit_خالي_جايون_Passwords:
		intptr = &options->permit_خالي_جايون_passwd;
		اذهب parse_flag;

	حالة sPermitUserEnvironment:
		intptr = &options->permit_user_env;
		charptr = &options->permit_user_env_allowlist;
		arg = argv_ايندڙ(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		قدر = 0;
		p = عدم;
		إذا (strcmp(arg, "yes") == 0)
			قدر = 1;
		وإلا إذا (strcmp(arg, "no") == 0)
			قدر = 0;
		وإلا {
			/* Pattern-list specified */
			قدر = 1;
			p = xstrdup(arg);
		}
		إذا (*activep && *intptr == -1) {
			*intptr = قدر;
			*charptr = p;
			p = عدم;
		}
		حرر(p);
		اكسر;

	حالة sCompression:
		intptr = &options->compression;
		multistate_ptr = multistate_compression;
		اذهب parse_multistate;

	حالة s_Rekey_حد_بندي:
		arg = argv_ايندڙ(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		إذا (strcmp(arg, "default") == 0) {
			val64 = 0;
		} وإلا {
			إذا (جاچ_scaled(arg, &val64) == -1)
				fatal("%.200s line %d: Bad %s number '%s': %s",
				    filename, linenum, keyword,
				    arg, strerror(errno));
			إذا (val64 != 0 && val64 < 16)
				fatal("%.200s line %d: %s too small",
				    filename, linenum, keyword);
		}
		إذا (*activep && options->rekey_حد_بندي == -1)
			options->rekey_حد_بندي = val64;
		إذا (ac != 0) { /* optional rekey interval present */
			إذا (strcmp(av[0], "none") == 0) {
				(فراغ)argv_ايندڙ(&ac, &av);	/* discard */
				اكسر;
			}
			intptr = &options->rekey_interval;
			اذهب parse_وقت;
		}
		اكسر;

	حالة sGatewayPorts:
		intptr = &options->fwd_opts.gateway_ports;
		multistate_ptr = multistate_gatewayports;
		اذهب parse_multistate;

	حالة sUseDNS:
		intptr = &options->use_dns;
		اذهب parse_flag;

	حالة sSyslogFacility:
		log_facility_ptr = &options->log_facility;
		arg = argv_ايندڙ(&ac, &av);
		قدر = log_facility_عدد(arg);
		إذا (قدر == SYSLOG_FACILITY_NOT_سيٽ)
			fatal("%.200s line %d: unsupported log facility '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
		إذا (*log_facility_ptr == -1)
			*log_facility_ptr = (SyslogFacility) قدر;
		اكسر;

	حالة sLogLevel:
		log_level_ptr = &options->log_level;
		arg = argv_ايندڙ(&ac, &av);
		قدر = log_level_عدد(arg);
		إذا (قدر == SYSLOG_LEVEL_NOT_سيٽ)
			fatal("%.200s line %d: unsupported log level '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
		إذا (*activep && *log_level_ptr == -1)
			*log_level_ptr = (LogLevel) قدر;
		اكسر;

	حالة sLogVerbose:
		مليو = options->انگ_log_verbose == 0;
		طالما ((arg = argv_ايندڙ(&ac, &av)) != عدم) {
			إذا (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				اذهب ٻاهريون;
			}
			/* Allow "none" only in first position */
			إذا (strcasecmp(arg, "none") == 0) {
				إذا (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					اذهب ٻاهريون;
				}
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		إذا (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		إذا (مليو && *activep) {
			options->log_verbose = strs;
			options->انگ_log_verbose = nstrs;
			strs = عدم; /* transferred */
			nstrs = 0;
		}
		اكسر;

	حالة sAllowTcpForwarding:
		intptr = &options->allow_tcp_forwarding;
		multistate_ptr = multistate_tcpfwd;
		اذهب parse_multistate;

	حالة s_Allow_وهڪرو_Local_Forwarding:
		intptr = &options->allow_streamlocal_forwarding;
		multistate_ptr = multistate_tcpfwd;
		اذهب parse_multistate;

	حالة sAllowAgentForwarding:
		intptr = &options->allow_agent_forwarding;
		اذهب parse_flag;

	حالة s_Agent_Socket_رستو:
		charptr = &options->agent_socket_رستو;
		arg = argv_ايندڙ(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: missing path.", filename, linenum);
		إذا (لڙي_ڀيٽ(arg, "shared:", 7) == 0) {
			/* Shared paths must be absolute */
			إذا (arg[7] != '/') {
				fatal("%s line %d: invalid shared path.",
				    filename, linenum);
			}
		} وإلا إذا (لڙي_ڀيٽ(arg, "user:", 5) == 0) {
			/* User paths must not be empty */
			إذا (arg[5] == '\0') {
				fatal("%s line %d: invalid user path.",
				    filename, linenum);
			}
		} وإلا إذا (strcmp(arg, "none") != 0)
			fatal("%s line %d: invalid path.", filename, linenum);
		إذا (*activep && *charptr == عدم)
			*charptr = xstrdup(arg);
		اكسر;

	حالة sDisableForwarding:
		intptr = &options->disable_forwarding;
		اذهب parse_flag;

	حالة sAllowUsers:
		chararrayptr = &options->allow_users;
		uintptr = &options->انگ_allow_users;
 parse_allowdenyusers:
		/* XXX appends to list; doesn't respect first-match-wins */
		طالما ((arg = argv_ايندڙ(&ac, &av)) != عدم) {
			إذا (*arg == '\0' ||
			    ميلاپ_user(عدم, عدم, عدم, arg) == -1)
				fatal("%s line %d: invalid %s pattern: \"%s\"",
				    filename, linenum, keyword, arg);
			مليو = 1;
			إذا (!*activep)
				استمر;
			opt_array_append(filename, linenum, keyword,
			    chararrayptr, uintptr, arg);
		}
		إذا (!مليو) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		اكسر;

	حالة sDenyUsers:
		chararrayptr = &options->deny_users;
		uintptr = &options->انگ_deny_users;
		اذهب parse_allowdenyusers;

	حالة sAllowGroups:
		chararrayptr = &options->allow_groups;
		uintptr = &options->انگ_allow_groups;
		/* XXX appends to list; doesn't respect first-match-wins */
 parse_allowdenygroups:
		طالما ((arg = argv_ايندڙ(&ac, &av)) != عدم) {
			إذا (*arg == '\0')
				fatal("%s line %d: empty %s pattern",
				    filename, linenum, keyword);
			مليو = 1;
			إذا (!*activep)
				استمر;
			opt_array_append(filename, linenum, keyword,
			    chararrayptr, uintptr, arg);
		}
		إذا (!مليو) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		اكسر;

	حالة sDenyGroups:
		chararrayptr = &options->deny_groups;
		uintptr = &options->انگ_deny_groups;
		اذهب parse_allowdenygroups;

	حالة sCiphers:
		arg = argv_ايندڙ(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		إذا (*arg != '-' &&
		    !ciphers_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 cipher spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		إذا (options->ciphers == عدم)
			options->ciphers = xstrdup(arg);
		اكسر;

	حالة sMacs:
		arg = argv_ايندڙ(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		إذا (*arg != '-' &&
		    !mac_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 mac spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		إذا (options->macs == عدم)
			options->macs = xstrdup(arg);
		اكسر;

	حالة sKexAlgorithms:
		arg = argv_ايندڙ(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		إذا (*arg != '-' &&
		    !kex_نالا_valid(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 KexAlgorithms '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		إذا (options->kex_algorithms == عدم)
			options->kex_algorithms = xstrdup(arg);
		اكسر;

	حالة sSubsystem:
		إذا ((arg = argv_ايندڙ(&ac, &av)) == عدم || *arg == '\0' ||
		   ((arg2 = argv_ايندڙ(&ac, &av)) == عدم || *arg2 == '\0'))
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		إذا (!*activep) {
			argv_consume(&ac);
			اكسر;
		}
		مليو = 0;
		لكل (i = 0; i < options->انگ_subsystems; i++) {
			إذا (strcmp(arg, options->subsystem_name[i]) == 0) {
				مليو = 1;
				اكسر;
			}
		}
		إذا (مليو) {
			debug("%s line %d: Subsystem '%s' already defined.",
			    filename, linenum, arg);
			argv_consume(&ac);
			اكسر;
		}
		options->subsystem_name = xrecallocarray(
		    options->subsystem_name, options->انگ_subsystems,
		    options->انگ_subsystems + 1,
		    حجم(*options->subsystem_name));
		options->subsystem_command = xrecallocarray(
		    options->subsystem_command, options->انگ_subsystems,
		    options->انگ_subsystems + 1,
		    حجم(*options->subsystem_command));
		options->subsystem_دليلون = xrecallocarray(
		    options->subsystem_دليلون, options->انگ_subsystems,
		    options->انگ_subsystems + 1,
		    حجم(*options->subsystem_دليلون));
		options->subsystem_name[options->انگ_subsystems] = xstrdup(arg);
		options->subsystem_command[options->انگ_subsystems] =
		    xstrdup(arg2);
		/* Collect arguments (separate to executable) */
		arg = argv_assemble(1, &arg2); /* quote command correctly */
		arg2 = argv_assemble(ac, av); /* rest of command */
		xasprintf(&options->subsystem_دليلون[options->انگ_subsystems],
		    "%s%s%s", arg, *arg2 == '\0' ? "" : " ", arg2);
		حرر(arg2);
		حرر(arg);
		argv_consume(&ac);
		options->انگ_subsystems++;
		اكسر;

	حالة sMaxStartups:
		arg = argv_ايندڙ(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		/* begin:rate:max */
		إذا ((n = لڙي_مان_پڙهو(arg, "%d:%d:%d",
		    &قدر, &value2, &value3)) == 3) {
			إذا (قدر > value3 || value2 > 100 || value2 < 1)
				fatal("%s line %d: Invalid %s spec.",
				    filename, linenum, keyword);
		} وإلا إذا (n == 1) {
			value3 = قدر;
			value2 = -1;
		} وإلا {
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		}
		إذا (قدر <= 0 || value3 <= 0)
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		إذا (*activep && options->max_startups == -1) {
			options->max_startups_begin = قدر;
			options->max_startups_شرح = value2;
			options->max_startups = value3;
		}
		اكسر;

	حالة s_في_ذريعو_Net_بلاڪ_سائيز:
		arg = argv_ايندڙ(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		بدل (n = لڙي_مان_پڙهو(arg, "%d:%d", &قدر, &value2)) {
		حالة 2:
			إذا (value2 < 0 || value2 > 128)
				n = -1;
			/* FALLTHROUGH */
		حالة 1:
			إذا (قدر < 0 || قدر > 32)
				n = -1;
		}
		إذا (n != 1 && n != 2)
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		إذا (*activep && options->في_ذريعو_masklen_ipv4 == -1) {
			options->في_ذريعو_masklen_ipv4 = قدر;
			إذا (n == 2)
				options->في_ذريعو_masklen_ipv6 = value2;
		}
		اكسر;

	حالة s_في_ذريعو_Max_Startups:
		arg = argv_ايندڙ(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		إذا (strcmp(arg, "none") == 0) { /* no limit */
			قدر = وڌ_کان_وڌ_عدد;
		} وإلا {
			إذا ((errstr = atoi_err(arg, &قدر)) != عدم)
				fatal("%s line %d: %s integer value %s.",
				    filename, linenum, keyword, errstr);
		}
		إذا (*activep && options->في_ذريعو_max_startups == -1)
			options->في_ذريعو_max_startups = قدر;
		اكسر;

	حالة s_في_ذريعو_Penalty_Exempt_List:
		charptr = &options->في_ذريعو_penalty_exempt;
		arg = argv_ايندڙ(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		إذا (addr_ميلاپ_list(عدم, arg) != 0) {
			fatal("%s line %d: keyword %s "
			    "invalid address argument.",
			    filename, linenum, keyword);
		}
		إذا (*activep && *charptr == عدم)
			*charptr = xstrdup(arg);
		اكسر;

	حالة s_في_ذريعو_Penalties:
		طالما ((arg = argv_ايندڙ(&ac, &av)) != عدم) {
			ثابت حرف *q = عدم;

			مليو = 1;
			intptr = عدم;
			doubleptr = عدم;
			قدر = -1;
			value2 = 0;
			/* Allow no/yes only in first position */
			إذا (strcasecmp(arg, "no") == 0 ||
			    (value2 = (strcasecmp(arg, "yes") == 0))) {
				إذا (ac > 0) {
					fatal("%s line %d: keyword %s \"%s\" "
					    "argument must appear alone.",
					    filename, linenum, keyword, arg);
				}
				إذا (*activep &&
				    options->في_ذريعو_penalty.enabled == -1)
					options->في_ذريعو_penalty.enabled = value2;
				استمر;
			} وإلا إذا ((q = strprefix(arg, "crash:", 0)) != عدم) {
				doubleptr = &options->في_ذريعو_penalty.penalty_crash;
			} وإلا إذا ((q = strprefix(arg, "authfail:", 0)) != عدم) {
				doubleptr = &options->في_ذريعو_penalty.penalty_authfail;
			} وإلا إذا ((q = strprefix(arg, "invaliduser:", 0)) != عدم) {
				doubleptr = &options->في_ذريعو_penalty.penalty_invaliduser;
			} وإلا إذا ((q = strprefix(arg, "noauth:", 0)) != عدم) {
				doubleptr = &options->في_ذريعو_penalty.penalty_noauth;
			} وإلا إذا ((q = strprefix(arg, "grace-exceeded:", 0)) != عدم) {
				doubleptr = &options->في_ذريعو_penalty.penalty_grace;
			} وإلا إذا ((q = strprefix(arg, "refuseconnection:", 0)) != عدم) {
				doubleptr = &options->في_ذريعو_penalty.penalty_refuseconnection;
			} وإلا إذا ((q = strprefix(arg, "max:", 0)) != عدم) {
				doubleptr = &options->في_ذريعو_penalty.penalty_max;
			} وإلا إذا ((q = strprefix(arg, "min:", 0)) != عدم) {
				doubleptr = &options->في_ذريعو_penalty.penalty_min;
			} وإلا إذا ((q = strprefix(arg, "max-sources4:", 0)) != عدم) {
				intptr = &options->في_ذريعو_penalty.max_sources4;
				إذا ((errstr = atoi_err(q, &قدر)) != عدم)
					fatal("%s line %d: %s value %s.",
					    filename, linenum, keyword, errstr);
			} وإلا إذا ((q = strprefix(arg, "max-sources6:", 0)) != عدم) {
				intptr = &options->في_ذريعو_penalty.max_sources6;
				إذا ((errstr = atoi_err(q, &قدر)) != عدم)
					fatal("%s line %d: %s value %s.",
					    filename, linenum, keyword, errstr);
			} وإلا إذا (strcmp(arg, "overflow:deny-all") == 0) {
				intptr = &options->في_ذريعو_penalty.حد_کان_مٿي_گهڻائي;
				قدر = في_ذريعو_PENALTY_حد_کان_مٿي_DENY_ALL;
			} وإلا إذا (strcmp(arg, "overflow:permissive") == 0) {
				intptr = &options->في_ذريعو_penalty.حد_کان_مٿي_گهڻائي;
				قدر = في_ذريعو_PENALTY_حد_کان_مٿي_PERMISSIVE;
			} وإلا إذا (strcmp(arg, "overflow6:deny-all") == 0) {
				intptr = &options->في_ذريعو_penalty.حد_کان_مٿي_mode6;
				قدر = في_ذريعو_PENALTY_حد_کان_مٿي_DENY_ALL;
			} وإلا إذا (strcmp(arg, "overflow6:permissive") == 0) {
				intptr = &options->في_ذريعو_penalty.حد_کان_مٿي_mode6;
				قدر = في_ذريعو_PENALTY_حد_کان_مٿي_PERMISSIVE;
			} وإلا {
				fatal("%s line %d: unsupported %s keyword %s",
				    filename, linenum, keyword, arg);
			}

			إذا (doubleptr != عدم) {
				إذا ((dvalue = convtime_double(q)) < 0) {
					fatal("%s line %d: invalid %s time value.",
					    filename, linenum, keyword);
				}
				إذا (*activep && *doubleptr < 0.0) {
					*doubleptr = dvalue;
					options->في_ذريعو_penalty.enabled = 1;
				}
			} وإلا إذا (intptr != عدم) {
				إذا (*activep && *intptr == -1) {
					*intptr = قدر;
					options->في_ذريعو_penalty.enabled = 1;
				}
			} وإلا {
				fatal_f("%s line %d: internal error",
				    filename, linenum);
			}
		}
		إذا (!مليو) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		اكسر;

	حالة sMaxAuthTries:
		intptr = &options->max_authtries;
		اذهب parse_int;

	حالة sMaxSessions:
		intptr = &options->max_sessions;
		اذهب parse_int;

	حالة sBanner:
		charptr = &options->banner;
		اذهب parse_filename;

	/*
	 * These options can contain %X options expanded at
	 * connect time, so that you can specify paths like:
	 *
	 * AuthorizedKeysFile	/etc/ssh_keys/%u
	 */
	حالة s_Authorized_ڪنجيون_File:
		uintptr = &options->انگ_authkeys_files;
		chararrayptr = &options->authorized_ڪنجيون_files;
 parse_filenames:
		مليو = *uintptr == 0;
		طالما ((arg = argv_ايندڙ(&ac, &av)) != عدم) {
			إذا (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				اذهب ٻاهريون;
			}
			/* Allow "none" only in first position */
			إذا (strcasecmp(arg, "none") == 0) {
				إذا (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					اذهب ٻاهريون;
				}
			}
			arg2 = tilde_expand_filename(arg, getuid());
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg2);
			حرر(arg2);
		}
		إذا (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		إذا (مليو && *activep) {
			*chararrayptr = strs;
			*uintptr = nstrs;
			strs = عدم; /* transferred */
			nstrs = 0;
		}
		اكسر;

	حالة sAuthorizedPrincipalsFile:
		charptr = &options->authorized_principals_file;
		arg = argv_ايندڙ(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		إذا (*activep && *charptr == عدم) {
			*charptr = tilde_expand_filename(arg, getuid());
			/* increase optional counter */
			إذا (intptr != عدم)
				*intptr = *intptr + 1;
		}
		اكسر;

	حالة sClientAliveInterval:
		intptr = &options->client_alive_interval;
		اذهب parse_وقت;

	حالة s_Client_Alive_ڳڻپ_Max:
		intptr = &options->client_alive_ڳڻپ_max;
		اذهب parse_int;

	حالة sAcceptEnv:
		/* XXX appends to list; doesn't respect first-match-wins */
		طالما ((arg = argv_ايندڙ(&ac, &av)) != عدم) {
			إذا (*arg == '\0' || strchr(arg, '=') != عدم)
				fatal("%s line %d: Invalid environment name.",
				    filename, linenum);
			مليو = 1;
			إذا (!*activep)
				استمر;
			opt_array_append(filename, linenum, keyword,
			    &options->accept_env, &options->انگ_accept_env,
			    arg);
		}
		إذا (!مليو) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		اكسر;

	حالة s_سيٽ_Env:
		مليو = options->انگ_setenv == 0;
		طالما ((arg = argv_ايندڙ(&ac, &av)) != عدم) {
			إذا (*arg == '\0' || strchr(arg, '=') == عدم)
				fatal("%s line %d: Invalid environment.",
				    filename, linenum);
			إذا (lookup_setenv_اندريون_list(arg, strs, nstrs) != عدم) {
				debug2("%s line %d: ignoring duplicate env "
				    "name \"%.64s\"", filename, linenum, arg);
				استمر;
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		إذا (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		إذا (مليو && *activep) {
			options->setenv = strs;
			options->انگ_setenv = nstrs;
			strs = عدم; /* transferred */
			nstrs = 0;
		}
		اكسر;

	حالة sPermitTunnel:
		intptr = &options->permit_tun;
		arg = argv_ايندڙ(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		قدر = -1;
		لكل (i = 0; tunmode_desc[i].val != -1; i++)
			إذا (strcmp(tunmode_desc[i].متن, arg) == 0) {
				قدر = tunmode_desc[i].val;
				اكسر;
			}
		إذا (قدر == -1)
			fatal("%s line %d: bad %s argument %s",
			    filename, linenum, keyword, arg);
		إذا (*activep && *intptr == -1)
			*intptr = قدر;
		اكسر;

	حالة sInclude:
		إذا (cmdline) {
			fatal("Include directive not supported as a "
			    "command-line option");
		}
		قدر = 0;
		طالما ((arg2 = argv_ايندڙ(&ac, &av)) != عدم) {
			إذا (*arg2 == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				اذهب ٻاهريون;
			}
			قدر++;
			مليو = 0;
			إذا (*arg2 != '/' && *arg2 != '~') {
				xasprintf(&arg, "%s/%s", SSHDIR, arg2);
			} وإلا
				arg = xstrdup(arg2);

			/*
			 * Don't let included files clobber the containing
			 * file's Match state.
			 */
			oactive = *activep;

			/* consult cache of include files */
			TAILQ_FOREACH(شي, includes, داخلا) {
				إذا (strcmp(شي->selector, arg) != 0)
					استمر;
				إذا (شي->filename != عدم) {
					parse_server_config_اونهائي(options,
					    شي->filename, شي->contents,
					    includes, connectinfo,
					    (*inc_flags & SSHCFG_ميلاپ_ONLY
					        ? SSHCFG_ميلاپ_ONLY : (oactive
					            ? 0 : SSHCFG_NEVERMATCH)),
					    activep, اونهائي + 1);
				}
				مليو = 1;
				*activep = oactive;
			}
			إذا (مليو != 0) {
				حرر(arg);
				استمر;
			}

			/* requested glob was not in cache */
			debug2("%s line %d: new include %s",
			    filename, linenum, arg);
			إذا ((r = glob(arg, 0, عدم, &gbuf)) != 0) {
				إذا (r != GLOB_NOMATCH) {
					fatal("%s line %d: include \"%s\" glob "
					    "failed", filename, linenum, arg);
				}
				/*
				 * If no entry matched then record a
				 * placeholder to skip later glob calls.
				 */
				debug2("%s line %d: no match for %s",
				    filename, linenum, arg);
				شي = xcalloc(1, حجم(*شي));
				شي->selector = xstrdup(arg);
				TAILQ_INSERT_TAIL(includes,
				    شي, داخلا);
			}
			إذا (gbuf.gl_pathc > وڌ_کان_وڌ_عدد)
				fatal_f("too many glob results");
			لكل (n = 0; n < (صحيح)gbuf.gl_pathc; n++) {
				debug2("%s line %d: including %s",
				    filename, linenum, gbuf.gl_pathv[n]);
				شي = xcalloc(1, حجم(*شي));
				شي->selector = xstrdup(arg);
				شي->filename = xstrdup(gbuf.gl_pathv[n]);
				إذا ((شي->contents = sshbuf_new()) == عدم)
					fatal_f("sshbuf_new failed");
				ڀريو_server_config(شي->filename,
				    شي->contents);
				parse_server_config_اونهائي(options,
				    شي->filename, شي->contents,
				    includes, connectinfo,
				    (*inc_flags & SSHCFG_ميلاپ_ONLY
				        ? SSHCFG_ميلاپ_ONLY : (oactive
				            ? 0 : SSHCFG_NEVERMATCH)),
				    activep, اونهائي + 1);
				*activep = oactive;
				TAILQ_INSERT_TAIL(includes, شي, داخلا);
			}
			globfree(&gbuf);
			حرر(arg);
		}
		إذا (قدر == 0) {
			fatal("%s line %d: %s missing filename argument",
			    filename, linenum, keyword);
		}
		اكسر;

	حالة s_ميلاپ:
		إذا (cmdline)
			fatal("Match directive not supported as a command-line "
			    "option");
		قدر = ميلاپ_cfg_سٽ(str, &ac, &av, linenum,
		    (*inc_flags & SSHCFG_NEVERMATCH ? عدم : connectinfo));
		إذا (قدر < 0)
			fatal("%s line %d: Bad Match condition", filename,
			    linenum);
		*activep = (*inc_flags & SSHCFG_NEVERMATCH) ? 0 : قدر;
		/*
		 * The MATCH_ONLY flag is applicable only until the first
		 * match block.
		 */
		*inc_flags &= ~SSHCFG_ميلاپ_ONLY;
		اكسر;

	حالة sPermitListen:
	حالة sPermitOpen:
		إذا (opcode == sPermitListen) {
			uintptr = &options->انگ_permitted_listens;
			chararrayptr = &options->permitted_listens;
		} وإلا {
			uintptr = &options->انگ_permitted_opens;
			chararrayptr = &options->permitted_opens;
		}
		مليو = *uintptr == 0;
		طالما ((arg = argv_ايندڙ(&ac, &av)) != عدم) {
			إذا (strcmp(arg, "any") == 0 ||
			    strcmp(arg, "none") == 0) {
				إذا (nstrs != 0) {
					fatal("%s line %d: %s must appear "
					    "alone on a %s line.",
					    filename, linenum, arg, keyword);
				}
				opt_array_append(filename, linenum, keyword,
				    &strs, &nstrs, arg);
				استمر;
			}

			إذا (opcode == sPermitListen &&
			    strchr(arg, ':') == عدم) {
				/*
				 * Allow bare port number for PermitListen
				 * to indicate a wildcard listen host.
				 */
				xasprintf(&arg2, "*:%s", arg);
			} وإلا {
				arg2 = xstrdup(arg);
				p = hpdelim(&arg);
				إذا (p == عدم) {
					fatal("%s line %d: %s missing host",
					    filename, linenum, keyword);
				}
				p = cleanhostname(p);
			}
			إذا (arg == عدم ||
			    ((پورٽ = permitopen_پورٽ(arg)) < 0)) {
				fatal("%s line %d: %s bad port number",
				    filename, linenum, keyword);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg2);
			حرر(arg2);
		}
		إذا (nstrs == 0) {
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		}
		إذا (مليو && *activep) {
			*chararrayptr = strs;
			*uintptr = nstrs;
			strs = عدم; /* transferred */
			nstrs = 0;
		}
		اكسر;

	حالة sForceCommand:
		إذا (str == عدم || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		إذا (*activep && options->adm_forced_command == عدم)
			options->adm_forced_command = xstrdup(str + len);
		argv_consume(&ac);
		اكسر;

	حالة sChrootDirectory:
		charptr = &options->chroot_directory;

		arg = argv_ايندڙ(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		إذا (*activep && *charptr == عدم)
			*charptr = xstrdup(arg);
		اكسر;

	حالة sTrustedUserCAKeys:
		charptr = &options->trusted_user_ca_ڪنجيون;
		اذهب parse_filename;

	حالة s_Revoked_ڪنجيون:
		uintptr = &options->انگ_revoked_ڪنجيون_files;
		chararrayptr = &options->revoked_ڪنجيون_files;
		اذهب parse_filenames;

	حالة s_Security_ڪنجي_Provider:
		charptr = &options->sk_provider;
		arg = argv_ايندڙ(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		إذا (*activep && *charptr == عدم) {
			*charptr = strcasecmp(arg, "internal") == 0 ?
			    xstrdup(arg) : derelativise_رستو(arg);
			/* increase optional counter */
			إذا (intptr != عدم)
				*intptr = *intptr + 1;
		}
		اكسر;

	حالة sIPQoS:
		arg = argv_ايندڙ(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		إذا ((قدر = parse_ipqos(arg)) == -1)
			fatal("%s line %d: Bad %s value: %s",
			    filename, linenum, keyword, arg);
		إذا (قدر == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			قدر = وڌ_کان_وڌ_عدد;
		}
		arg = argv_ايندڙ(&ac, &av);
		إذا (arg == عدم)
			value2 = قدر;
		وإلا إذا ((value2 = parse_ipqos(arg)) == -1)
			fatal("%s line %d: Bad %s value: %s",
			    filename, linenum, keyword, arg);
		إذا (value2 == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			value2 = وڌ_کان_وڌ_عدد;
		}
		إذا (*activep && options->ip_qos_interactive == -1) {
			options->ip_qos_interactive = قدر;
			options->ip_qos_bulk = value2;
		}
		اكسر;

	حالة s_نسخو_Addendum:
		إذا (str == عدم || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		إذا (strchr(str + len, '\r') != عدم) {
			fatal("%.200s line %d: Invalid %s argument",
			    filename, linenum, keyword);
		}
		إذا ((arg = strchr(سٽ, '#')) != عدم) {
			*arg = '\0';
			rtrim(سٽ);
		}
		إذا (*activep && options->نسخو_addendum == عدم) {
			إذا (strcasecmp(str + len, "none") == 0)
				options->نسخو_addendum = xstrdup("");
			وإلا
				options->نسخو_addendum = xstrdup(str + len);
		}
		argv_consume(&ac);
		اكسر;

	حالة s_Authorized_ڪنجيون_Command:
		charptr = &options->authorized_ڪنجيون_command;
 parse_command:
		len = strspn(str, WHITESPACE);
		إذا (str[len] != '/' && strcasecmp(str + len, "none") != 0) {
			fatal("%.200s line %d: %s must be an absolute path",
			    filename, linenum, keyword);
		}
		إذا (*activep && *charptr == عدم)
			*charptr = xstrdup(str + len);
		argv_consume(&ac);
		اكسر;

	حالة s_Authorized_ڪنجيون_Command_User:
		charptr = &options->authorized_ڪنجيون_command_user;
 parse_localuser:
		arg = argv_ايندڙ(&ac, &av);
		إذا (!arg || *arg == '\0') {
			fatal("%s line %d: missing %s argument.",
			    filename, linenum, keyword);
		}
		إذا (*activep && *charptr == عدم)
			*charptr = xstrdup(arg);
		اكسر;

	حالة sAuthorizedPrincipalsCommand:
		charptr = &options->authorized_principals_command;
		اذهب parse_command;

	حالة sAuthorizedPrincipalsCommandUser:
		charptr = &options->authorized_principals_command_user;
		اذهب parse_localuser;

	حالة sAuthenticationMethods:
		مليو = options->انگ_auth_methods == 0;
		قدر = 0; /* seen "any" pseudo-method */
		طالما ((arg = argv_ايندڙ(&ac, &av)) != عدم) {
			إذا (strcmp(arg, "any") == 0) {
				إذا (nstrs > 0) {
					fatal("%s line %d: \"any\" must "
					    "appear alone in %s",
					    filename, linenum, keyword);
				}
				قدر = 1;
			} وإلا إذا (قدر) {
				fatal("%s line %d: \"any\" must appear "
				    "alone in %s", filename, linenum, keyword);
			} وإلا إذا (auth2_methods_valid(arg, 0) != 0) {
				fatal("%s line %d: invalid %s method list.",
				    filename, linenum, keyword);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		إذا (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		إذا (مليو && *activep) {
			options->auth_methods = strs;
			options->انگ_auth_methods = nstrs;
			strs = عدم; /* transferred */
			nstrs = 0;
		}
		اكسر;

	حالة s_وهڪرو_Local_Bind_نقاب:
		arg = argv_ايندڙ(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		/* Parse mode in octal format */
		قدر = strtol(arg, &p, 8);
		إذا (arg == p || قدر < 0 || قدر > 0777)
			fatal("%s line %d: Invalid %s.",
			    filename, linenum, keyword);
		إذا (*activep &&
		    options->fwd_opts.streamlocal_bind_نقاب == (گهڻائي_t)-1)
			options->fwd_opts.streamlocal_bind_نقاب = (گهڻائي_t)قدر;
		اكسر;

	حالة s_وهڪرو_Local_Bind_Unlink:
		intptr = &options->fwd_opts.streamlocal_bind_unlink;
		اذهب parse_flag;

	حالة sFingerprintHash:
		arg = argv_ايندڙ(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		إذا ((قدر = ssh_digest_alg_by_name(arg)) == -1)
			fatal("%.200s line %d: Invalid %s algorithm \"%s\".",
			    filename, linenum, keyword, arg);
		إذا (*activep)
			options->fingerprint_hash = قدر;
		اكسر;

	حالة sExposeAuthInfo:
		intptr = &options->expose_userauth_info;
		اذهب parse_flag;

	حالة sRDomain:
#إذا !defined(__OpenBSD__) && !defined(HAVE_SYS_سيٽ_PROCESS_RDOMAIN)
		fatal("%s line %d: setting RDomain not supported on this "
		    "platform.", filename, linenum);
#جيڪڏهن_پورو
		charptr = &options->routing_domain;
		arg = argv_ايندڙ(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		إذا (strcasecmp(arg, "none") != 0 && strcmp(arg, "%D") != 0 &&
		    !valid_rdomain(arg))
			fatal("%s line %d: invalid routing domain",
			    filename, linenum);
		إذا (*activep && *charptr == عدم)
			*charptr = xstrdup(arg);
		اكسر;

	حالة sRequiredRSASize:
		intptr = &options->required_rsa_سائيز;
		اذهب parse_int;

	حالة sChannelTimeout:
		مليو = options->انگ_channel_timeouts == 0;
		طالما ((arg = argv_ايندڙ(&ac, &av)) != عدم) {
			/* Allow "none" only in first position */
			إذا (strcasecmp(arg, "none") == 0) {
				إذا (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					اذهب ٻاهريون;
				}
			} وإلا إذا (parse_نمونو_interval(arg,
			    عدم, عدم) != 0) {
				fatal("%s line %d: invalid channel timeout %s",
				    filename, linenum, arg);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		إذا (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		إذا (مليو && *activep) {
			options->channel_timeouts = strs;
			options->انگ_channel_timeouts = nstrs;
			strs = عدم; /* transferred */
			nstrs = 0;
		}
		اكسر;

	حالة s_اڻ_استعمال_ٿيل_Connection_Timeout:
		intptr = &options->اڻ_استعمال_ٿيل_connection_timeout;
		/* peek at first arg for "none" so we can reuse parse_time */
		إذا (av[0] != عدم && strcasecmp(av[0], "none") == 0) {
			(فراغ)argv_ايندڙ(&ac, &av); /* consume arg */
			إذا (*activep)
				*intptr = 0;
			اكسر;
		}
		اذهب parse_وقت;

	حالة s_Sshd_Session_رستو:
		charptr = &options->sshd_session_رستو;
		اذهب parse_filename;

	حالة s_Sshd_Auth_رستو:
		charptr = &options->sshd_auth_رستو;
		اذهب parse_filename;

	حالة sRefuseConnection:
		intptr = &options->refuse_connection;
		multistate_ptr = multistate_flag;
		اذهب parse_multistate;

	حالة sWarnWeakCrypto:
		intptr = &options->warn_weak_crypto;
		multistate_ptr = multistate_warnweakcrypto;
		اذهب parse_multistate;

	حالة sDeprecated:
	حالة sIgnore:
	حالة sUnsupported:
		do_log2(opcode == sIgnore ?
		    SYSLOG_LEVEL_DEBUG2 : SYSLOG_LEVEL_INFO,
		    "%s line %d: %s option %s", filename, linenum,
		    opcode == sUnsupported ? "Unsupported" : "Deprecated",
		    keyword);
		argv_consume(&ac);
		اكسر;

	افتراضي:
		fatal("%s line %d: Missing handler for opcode %s (%d)",
		    filename, linenum, keyword, opcode);
	}
	/* Check that there is no garbage at end of line. */
	إذا (ac > 0) {
		error("%.200s line %d: keyword %s extra arguments "
		    "at end of line", filename, linenum, keyword);
		اذهب ٻاهريون;
	}

	/* success */
	ret = 0;
 ٻاهريون:
	opt_array_free2(strs, عدم, nstrs);
	argv_free(oav, oac);
	أرجع ret;
}

صحيح
process_server_config_سٽ(ServerOptions *options, حرف *سٽ,
    ثابت حرف *filename, صحيح linenum, صحيح *activep,
    بنية connection_info *connectinfo, بنية include_list *includes)
{
	صحيح inc_flags = 0;

	أرجع process_server_config_سٽ_اونهائي(options, سٽ, filename,
	    linenum, activep, connectinfo, &inc_flags, 0, includes);
}


/* Reads the server configuration file. */

فراغ
ڀريو_server_config(ثابت حرف *filename, بنية sshbuf *conf)
{
	بنية stat st;
	حرف *سٽ = عدم, *cp;
	سائيز_t linesize = 0;
	FILE *f;
	صحيح r;

	debug2_f("filename %s", filename);
	إذا ((f = fopen(filename, "r")) == عدم) {
		perror(filename);
		ٻاهر_نڪرو(1);
	}
	sshbuf_reset(conf);
	/* grow buffer, so realloc is avoided for large config files */
	إذا (fstat(fileno(f), &st) == 0 && st.st_size > 0 &&
	    (r = sshbuf_allocate(conf, st.st_size)) != 0)
		fatal_fr(r, "allocate");
	طالما (getline(&سٽ, &linesize, f) != -1) {
		/*
		 * Strip whitespace
		 * NB - preserve newlines, they are needed to reproduce
		 * line numbers later for error messages
		 */
		cp = سٽ + strspn(سٽ, " \t\r");
		إذا ((r = sshbuf_put(conf, cp, لڙي_ڊيگهه(cp))) != 0)
			fatal_fr(r, "sshbuf_put");
	}
	حرر(سٽ);
	إذا ((r = sshbuf_put_u8(conf, 0)) != 0)
		fatal_fr(r, "sshbuf_put_u8");
	fclose(f);
	debug2_f("done config len = %zu", sshbuf_len(conf));
}

فراغ
parse_server_ميلاپ_config(ServerOptions *options,
   بنية include_list *includes, بنية connection_info *connectinfo)
{
	ServerOptions mo;

	initialize_server_options(&mo);
	parse_server_config(&mo, "reprocess config", cfg, includes,
	    connectinfo, 0);
	copy_سيٽ_server_options(options, &mo, 0);
	free_server_options(&mo);
}

صحيح
parse_server_ميلاپ_testspec(بنية connection_info *ci, حرف *spec)
{
	حرف *p;
	ثابت حرف *val;

	طالما ((p = strsep(&spec, ",")) && *p != '\0') {
		إذا ((val = strprefix(p, "addr=", 0)) != عدم) {
			ci->پتو = xstrdup(val);
		} وإلا إذا ((val = strprefix(p, "host=", 0)) != عدم) {
			ci->host = xstrdup(val);
		} وإلا إذا ((val = strprefix(p, "user=", 0)) != عدم) {
			ci->user = xstrdup(val);
		} وإلا إذا ((val = strprefix(p, "laddr=", 0)) != عدم) {
			ci->laddress = xstrdup(val);
		} وإلا إذا ((val = strprefix(p, "rdomain=", 0)) != عدم) {
			ci->rdomain = xstrdup(val);
		} وإلا إذا ((val = strprefix(p, "lport=", 0)) != عدم) {
			ci->lport = a2port(val);
			إذا (ci->lport == -1) {
				fprintf(stderr, "Invalid port '%s' in test mode"
				    " specification %s\n", p+6, p);
				أرجع -1;
			}
		} وإلا إذا (strcmp(p, "invalid-user") == 0) {
			ci->user_invalid = 1;
		} وإلا {
			fprintf(stderr, "Invalid test mode specification %s\n",
			    p);
			أرجع -1;
		}
	}
	أرجع 0;
}

فراغ
servconf_ملايو_subsystems(ServerOptions *dst, ServerOptions *src)
{
	u_int i, j, مليو;

	لكل (i = 0; i < src->انگ_subsystems; i++) {
		مليو = 0;
		لكل (j = 0; j < dst->انگ_subsystems; j++) {
			إذا (strcmp(src->subsystem_name[i],
			    dst->subsystem_name[j]) == 0) {
				مليو = 1;
				اكسر;
			}
		}
		إذا (مليو) {
			debug_f("override \"%s\"", dst->subsystem_name[j]);
			حرر(dst->subsystem_command[j]);
			حرر(dst->subsystem_دليلون[j]);
			dst->subsystem_command[j] =
			    xstrdup(src->subsystem_command[i]);
			dst->subsystem_دليلون[j] =
			    xstrdup(src->subsystem_دليلون[i]);
			استمر;
		}
		debug_f("add \"%s\"", src->subsystem_name[i]);
		dst->subsystem_name = xrecallocarray(
		    dst->subsystem_name, dst->انگ_subsystems,
		    dst->انگ_subsystems + 1, حجم(*dst->subsystem_name));
		dst->subsystem_command = xrecallocarray(
		    dst->subsystem_command, dst->انگ_subsystems,
		    dst->انگ_subsystems + 1, حجم(*dst->subsystem_command));
		dst->subsystem_دليلون = xrecallocarray(
		    dst->subsystem_دليلون, dst->انگ_subsystems,
		    dst->انگ_subsystems + 1, حجم(*dst->subsystem_دليلون));
		j = dst->انگ_subsystems++;
		dst->subsystem_name[j] = xstrdup(src->subsystem_name[i]);
		dst->subsystem_command[j] = xstrdup(src->subsystem_command[i]);
		dst->subsystem_دليلون[j] = xstrdup(src->subsystem_دليلون[i]);
	}
}

ساكن صحيح
serialise_s32(بنية sshbuf *buf, صحيح v)
{
	uint32_t uv;
	صحيح r;

	uv = v < 0 ? (uint32_t)(-(v + 1)) + 1 : (uint32_t)v;
	إذا ((r = sshbuf_put_u8(buf, v < 0)) != 0 ||
	    (r = sshbuf_put_u32(buf, uv)) != 0)
		أرجع r;
	أرجع 0;
}

ساكن صحيح
serialise_s64(بنية sshbuf *buf, int64_t v)
{
	uint64_t uv;
	صحيح r;

	uv = v < 0 ? (uint64_t)(-(v + 1)) + 1 : (uint64_t)v;
	إذا ((r = sshbuf_put_u8(buf, v < 0)) != 0 ||
	    (r = sshbuf_put_u64(buf, uv)) != 0)
		أرجع r;
	أرجع 0;
}

ساكن صحيح
serialise_گهڻائي(بنية sshbuf *buf, گهڻائي_t v)
{
	u_int uv;

	إذا (v == (گهڻائي_t)-1)
		أرجع serialise_s32(buf, -1);
	uv = (u_int)v;
	إذا ((گهڻائي_t)uv != v || uv > 0777)
		أرجع SSH_ERR_INVALID_FORMAT;
	أرجع serialise_s32(buf, (صحيح)uv);
}

ساكن صحيح
serialise_double(بنية sshbuf *buf, مزدوج v)
{
	/*
	 * XXX this is no good for a wire encoding.
	 * It's fine for passing configurations via RPC, but it would
	 * be nicer to have an exact binary encoding here.
	 */
	أرجع sshbuf_put(buf, &v, حجم(v));
}

ساكن صحيح
serialise_nullable_string(بنية sshbuf *buf, ثابت حرف *s)
{
	صحيح r;

	إذا ((r = sshbuf_put_u8(buf, s != عدم)) != 0)
		أرجع r;
	إذا (s == عدم)
		أرجع 0;
	أرجع sshbuf_put_cstring(buf, s);
}

ساكن صحيح
serialise_nullable_string_array(بنية sshbuf *buf, حرف **a, u_int n)
{
	صحيح r;
	u_int i;

	إذا ((r = sshbuf_put_u32(buf, n)) != 0)
		أرجع r;
	لكل (i = 0; i < n; i++) {
		إذا ((r = serialise_nullable_string(buf, a[i])) != 0)
			أرجع r;
	}
	أرجع 0;
}

ساكن صحيح
serialise_hostkeyfile(ثابت ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;
	u_int i;

	إذا ((r = sshbuf_put_u32(buf, options->انگ_host_ڪنجي_files)) != 0) {
		error_fr(r, "serialise length");
		أرجع r;
	}
	لكل (i = 0; i < options->انگ_host_ڪنجي_files; i++) {
		إذا ((r = serialise_s32(buf,
		    options->host_ڪنجي_file_userprovided[i])) != 0 ||
		    (r = serialise_nullable_string(buf,
		    options->host_ڪنجي_files[i])) != 0) {
			error_fr(r, "serialise member");
			أرجع r;
		}
	}
	أرجع 0;
}

ساكن صحيح
serialise_ipqos(ثابت ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;

	إذا ((r = serialise_s32(buf, options->ip_qos_interactive)) != 0 ||
	    (r = serialise_s32(buf, options->ip_qos_bulk)) != 0) {
		error_fr(r, "serialise");
		أرجع r;
	}

	أرجع 0;
}

ساكن صحيح
serialise_listenaddress(ثابت ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;
	u_int i;

	/* Note: only serialises queued listen addresses */
	إذا ((r = sshbuf_put_u32(buf, options->انگ_queued_listens)) != 0) {
		error_fr(r, "serialise length");
		أرجع r;
	}
	لكل (i = 0; i < options->انگ_queued_listens; i++) {
		ثابت بنية queued_listenaddr *qla =
		    options->queued_listen_addrs + i;

		إذا ((r = sshbuf_put_cstring(buf, qla->addr)) != 0 ||
		    (r = serialise_s32(buf, qla->پورٽ)) != 0 ||
		    (r = serialise_nullable_string(buf, qla->rdomain)) != 0) {
			error_fr(r, "serialise member");
			أرجع r;
		}
	}
	أرجع 0;
}

ساكن صحيح
serialise_logfacility(ثابت ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;

	إذا ((r = serialise_s32(buf, (صحيح)options->log_facility)) != 0) {
		error_fr(r, "serialise");
		أرجع r;
	}

	أرجع 0;
}

ساكن صحيح
serialise_loglevel(ثابت ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;

	إذا ((r = serialise_s32(buf, (صحيح)options->log_level)) != 0) {
		error_fr(r, "serialise");
		أرجع r;
	}

	أرجع 0;
}

ساكن صحيح
serialise_پورٽ(ثابت ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;
	u_int i;

	إذا ((r = sshbuf_put_u32(buf, options->انگ_ports)) != 0) {
		error_fr(r, "serialise length");
		أرجع r;
	}
	لكل (i = 0; i < options->انگ_ports; i++) {
		إذا ((r = serialise_s32(buf, options->ports[i])) != 0) {
			error_fr(r, "serialise port");
			أرجع r;
		}
	}
	أرجع 0;
}

ساكن صحيح
serialise_gatewayports(ثابت ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;

	إذا ((r = serialise_s32(buf, options->fwd_opts.gateway_ports)) != 0) {
		error_fr(r, "serialise");
		أرجع r;
	}
	أرجع 0;
}

ساكن صحيح
serialise_streamlocalbindmask(ثابت ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;

	إذا ((r = serialise_گهڻائي(buf,
	    options->fwd_opts.streamlocal_bind_نقاب)) != 0) {
		error_fr(r, "serialise");
		أرجع r;
	}
	أرجع 0;
}

ساكن صحيح
serialise_streamlocalbindunlink(ثابت ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;

	إذا ((r = sshbuf_put_u8(buf,
	    (options->fwd_opts.streamlocal_bind_unlink != 0))) != 0) {
		error_fr(r, "serialise");
		أرجع r;
	}
	أرجع 0;
}

ساكن صحيح
serialise_maxstartups(ثابت ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;

	إذا ((r = serialise_s32(buf, options->max_startups_begin)) != 0 ||
	    (r = serialise_s32(buf, options->max_startups_شرح)) != 0 ||
	    (r = serialise_s32(buf, options->max_startups)) != 0) {
		error_fr(r, "serialise");
		أرجع r;
	}

	أرجع 0;
}

ساكن صحيح
serialise_permituserenv(ثابت ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;

	إذا ((r = serialise_s32(buf, options->permit_user_env)) != 0 ||
	    (r = serialise_nullable_string(buf,
	    options->permit_user_env_allowlist)) != 0) {
		error_fr(r, "serialise");
		أرجع r;
	}

	أرجع 0;
}

ساكن صحيح
serialise_persourcenetblocksize(ثابت ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;

	إذا ((r = serialise_s32(buf, options->في_ذريعو_masklen_ipv4)) != 0 ||
	    (r = serialise_s32(buf, options->في_ذريعو_masklen_ipv6)) != 0) {
		error_fr(r, "serialise");
		أرجع r;
	}

	أرجع 0;
}

ساكن صحيح
serialise_persourcepenalties(ثابت ServerOptions *options, بنية sshbuf *buf)
{
	ثابت بنية في_ذريعو_penalty *psp = &options->في_ذريعو_penalty;
	صحيح r;

	إذا ((r = serialise_s32(buf, psp->enabled)) != 0 ||
	    (r = serialise_s32(buf, psp->max_sources4)) != 0 ||
	    (r = serialise_s32(buf, psp->max_sources6)) != 0 ||
	    (r = serialise_s32(buf, psp->حد_کان_مٿي_گهڻائي)) != 0 ||
	    (r = serialise_s32(buf, psp->حد_کان_مٿي_mode6)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_crash)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_grace)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_authfail)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_invaliduser)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_noauth)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_refuseconnection)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_max)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_min)) != 0) {
		error_fr(r, "serialise");
		أرجع r;
	}

	أرجع 0;
}

ساكن صحيح
serialise_rekeylimit(ثابت ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;

	إذا ((r = serialise_s64(buf, options->rekey_حد_بندي)) != 0 ||
	    (r = serialise_s32(buf, options->rekey_interval)) != 0) {
		error_fr(r, "serialise");
		أرجع r;
	}

	أرجع 0;
}

ساكن صحيح
serialise_subsystem(ثابت ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;
	u_int i;

	إذا ((r = sshbuf_put_u32(buf, options->انگ_subsystems)) != 0) {
		error_fr(r, "serialise length");
		أرجع r;
	}
	لكل (i = 0; i < options->انگ_subsystems; i++) {
		إذا ((r = sshbuf_put_cstring(buf,
		    options->subsystem_name[i])) != 0 ||
		    (r = sshbuf_put_cstring(buf,
		    options->subsystem_command[i])) != 0 ||
		    (r = sshbuf_put_cstring(buf,
		    options->subsystem_دليلون[i])) != 0) {
			error_fr(r, "serialise member");
			أرجع r;
		}
	}
	أرجع 0;
}

ساكن صحيح
serialise_pubkey_auth_options(ثابت ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;

	إذا ((r = serialise_s32(buf, options->pubkey_auth_options)) != 0 ||
	    (r = serialise_s32(buf, options->max_pubkey_ok)) != 0) {
		error_fr(r, "serialise");
		أرجع r;
	}
	أرجع 0;
}

ساكن صحيح
serialise_timingsecret(ثابت ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;

	إذا ((r = sshbuf_put_u64(buf, options->timing_secret)) != 0) {
		error_fr(r, "serialise");
		أرجع r;
	}
	أرجع 0;
}


صحيح
serialise_server_options(ثابت ServerOptions *options, بنية sshbuf **bufp)
{
	بنية sshbuf *buf = عدم;
	صحيح r = SSH_ERR_اندروني_ERROR;

	*bufp = عدم;

	إذا ((buf = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshbuf_put_u32(buf, SSHD_CONFIG_BLOB_نسخو)) != 0) {
		error_fr(r, "serialise version");
		اذهب ٻاهريون;
	}

#وصف_ڪريو SSHCONF_INT(var, conf, flags, ms, def, cp) \
	إذا ((r = serialise_s32(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		اذهب ٻاهريون; \
	}
#وصف_ڪريو SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	إذا ((r = serialise_s32(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		اذهب ٻاهريون; \
	}
#وصف_ڪريو SSHCONF_STRING(var, conf, flags, cp) \
	إذا ((r = serialise_nullable_string(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		اذهب ٻاهريون; \
	}
#وصف_ڪريو SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	إذا ((r = serialise_nullable_string_array(buf, options->var, \
	    options->nvar)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		اذهب ٻاهريون; \
	}
#وصف_ڪريو SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	إذا ((r = serialise_##funcsuffix(options, buf)) != 0) \
		اذهب ٻاهريون;
#وصف_ڪريو SSHCONF_NONCONF(funcsuffix) \
	إذا ((r = serialise_##funcsuffix(options, buf)) != 0) \
		اذهب ٻاهريون;
#وصف_ڪريو SSHCONF_DEPRECATE(conf, flags, opcode)		/*خالي_جايون*/
#وصف_ڪريو SSHCONF_UNSUPPORTED_INT(var, conf, flags)	/*خالي_جايون*/
#وصف_ڪريو SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	/*خالي_جايون*/
#وصف_ڪريو SSHCONF_ALIAS(old, conf, flags)			/*خالي_جايون*/

	SSHD_CONFIG_ENTRIES

#وصف_رد SSHCONF_INT
#وصف_رد SSHCONF_INTFLAG
#وصف_رد SSHCONF_STRING
#وصف_رد SSHCONF_STRARRAY
#وصف_رد SSHCONF_CUSTOM
#وصف_رد SSHCONF_NONCONF
#وصف_رد SSHCONF_DEPRECATE
#وصف_رد SSHCONF_UNSUPPORTED_INT
#وصف_رد SSHCONF_UNSUPPORTED_STRING
#وصف_رد SSHCONF_ALIAS

	/* success */
	r = 0;
	*bufp = buf;
	buf = عدم; /* transferred */
 ٻاهريون:
	sshbuf_free(buf);
	أرجع r;
}

ساكن صحيح
deserialise_s32(بنية sshbuf *buf, صحيح *v)
{
	uint32_t tmp;
	صحيح r;
	u_char was_signed;

	إذا ((r = sshbuf_get_u8(buf, &was_signed)) != 0 ||
	    (r = sshbuf_get_u32(buf, &tmp)) != 0)
		أرجع r;
	إذا (was_signed > 1)
		أرجع SSH_ERR_INVALID_FORMAT;
	إذا (was_signed) {
		إذا (tmp > (uint32_t)وڌ_کان_وڌ_عدد + 1)
			أرجع SSH_ERR_INVALID_FORMAT;
		*v = tmp == (uint32_t)وڌ_کان_وڌ_عدد + 1 ? INT_MIN : -(صحيح)tmp;
	} وإلا {
		إذا (tmp > وڌ_کان_وڌ_عدد)
			أرجع SSH_ERR_INVALID_FORMAT;
		*v = (صحيح)tmp;
	}
	أرجع 0;
}

ساكن صحيح
deserialise_s64(بنية sshbuf *buf, int64_t *v)
{
	uint64_t tmp;
	صحيح r;
	u_char was_signed;

	إذا ((r = sshbuf_get_u8(buf, &was_signed)) != 0 ||
	    (r = sshbuf_get_u64(buf, &tmp)) != 0)
		أرجع r;
	إذا (was_signed > 1)
		أرجع SSH_ERR_INVALID_FORMAT;
	إذا (was_signed) {
		إذا (tmp > (uint64_t)INT64_MAX + 1)
			أرجع SSH_ERR_INVALID_FORMAT;
		*v = tmp == (uint64_t)INT64_MAX + 1 ?
		    INT64_MIN : -(int64_t)tmp;
	} وإلا {
		إذا (tmp > INT64_MAX)
			أرجع SSH_ERR_INVALID_FORMAT;
		*v = (int64_t)tmp;
	}
	أرجع 0;
}

ساكن صحيح
deserialise_گهڻائي(بنية sshbuf *buf, گهڻائي_t *v)
{
	صحيح r, tmp;

	إذا ((r = deserialise_s32(buf, &tmp)) != 0)
		أرجع r;
	إذا (tmp == -1) {
		*v = (گهڻائي_t)-1;
		أرجع 0;
	}
	إذا (tmp < 0 || tmp > 0777)
		أرجع SSH_ERR_INVALID_FORMAT;
	*v = (گهڻائي_t)tmp;
	أرجع 0;
}

ساكن صحيح
deserialise_double(بنية sshbuf *buf, مزدوج *v)
{
	أرجع sshbuf_get(buf, v, حجم(*v));
}

ساكن صحيح
deserialise_nullable_string(بنية sshbuf *buf, حرف **sp)
{
	صحيح r;
	u_char present;

	إذا ((r = sshbuf_get_u8(buf, &present)) != 0)
		أرجع r;
	إذا (present == 0) {
		*sp = عدم;
		أرجع 0;
	}
	إذا (present != 1)
		أرجع SSH_ERR_INVALID_FORMAT;
	أرجع sshbuf_get_cstring(buf, sp, عدم);
}

ساكن فراغ
free_string_array(حرف **a, u_int n)
{
	u_int i;

	إذا (a == عدم)
		أرجع;
	لكل (i = 0; i < n; i++)
		حرر(a[i]);
	حرر(a);
}

ساكن صحيح
deserialise_ڳڻپ(بنية sshbuf *buf, u_int *np, ثابت حرف *what)
{
	صحيح r;
	uint32_t n;

	إذا ((r = sshbuf_get_u32(buf, &n)) != 0) {
		error_fr(r, "deserialise %s length", what);
		أرجع r;
	}
	إذا (n > UINT_MAX) {
		error_f("bad number of %s", what);
		أرجع SSH_ERR_INVALID_FORMAT;
	}
	إذا (n > sshbuf_len(buf)) {
		error_f("bad number of %s", what);
		أرجع SSH_ERR_INVALID_FORMAT;
	}
	*np = n;
	أرجع 0;
}

ساكن صحيح
deserialise_nullable_string_array(بنية sshbuf *buf, حرف ***arrayp,
    u_int *np)
{
	حرف **a = عدم;
	صحيح r;
	u_int i, n;

	*arrayp = عدم;
	*np = 0;
	إذا ((r = deserialise_ڳڻپ(buf, &n, "strings")) != 0)
		أرجع r;
	إذا (n > 0)
		a = xcalloc(n, حجم(*a));
	لكل (i = 0; i < n; i++) {
		إذا ((r = deserialise_nullable_string(buf, a + i)) != 0) {
			free_string_array(a, i + 1);
			أرجع r;
		}
	}
	*arrayp = a;
	*np = n;
	أرجع 0;
}

ساكن فراغ
free_queued_listen_addrs(بنية queued_listenaddr *qla, u_int n)
{
	u_int i;

	إذا (qla == عدم)
		أرجع;
	لكل (i = 0; i < n; i++) {
		حرر(qla[i].addr);
		حرر(qla[i].rdomain);
	}
	حرر(qla);
}

ساكن صحيح
deserialise_hostkeyfile(ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r, *userprovided = عدم;
	u_int i, n;
	حرف **files = عدم;

	إذا ((r = deserialise_ڳڻپ(buf, &n, "host key files")) != 0)
		أرجع r;
	إذا (n > 0) {
		userprovided = xcalloc(n, حجم(*userprovided));
		files = xcalloc(n, حجم(*files));
	}
	لكل (i = 0; i < n; i++) {
		إذا ((r = deserialise_s32(buf, userprovided + i)) != 0 ||
		    (r = deserialise_nullable_string(buf, files + i)) != 0) {
			error_fr(r, "deserialise member");
			free_string_array(files, i + 1);
			حرر(userprovided);
			أرجع r;
		}
	}
	options->انگ_host_ڪنجي_files = n;
	options->host_ڪنجي_file_userprovided = userprovided;
	options->host_ڪنجي_files = files;
	أرجع 0;
}

ساكن صحيح
deserialise_ipqos(ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;

	إذا ((r = deserialise_s32(buf, &options->ip_qos_interactive)) != 0 ||
	    (r = deserialise_s32(buf, &options->ip_qos_bulk)) != 0) {
		error_fr(r, "deserialise");
		أرجع r;
	}

	أرجع 0;
}

ساكن صحيح
deserialise_listenaddress(ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;
	u_int i, n;
	بنية queued_listenaddr *qla = عدم;

	إذا ((r = deserialise_ڳڻپ(buf, &n, "listen addresses")) != 0)
		أرجع r;
	إذا (n > 0)
		qla = xcalloc(n, حجم(*qla));
	لكل (i = 0; i < n; i++) {
		إذا ((r = sshbuf_get_cstring(buf, &qla[i].addr, عدم)) != 0 ||
		    (r = deserialise_s32(buf, &qla[i].پورٽ)) != 0 ||
		    (r = deserialise_nullable_string(buf,
		    &qla[i].rdomain)) != 0) {
			error_fr(r, "deserialise member");
			free_queued_listen_addrs(qla, i + 1);
			أرجع r;
		}
	}
	options->انگ_queued_listens = n;
	options->queued_listen_addrs = qla;
	أرجع 0;
}

ساكن صحيح
deserialise_logfacility(ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r, tmp;

	إذا ((r = deserialise_s32(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		أرجع r;
	}
	إذا (tmp != SYSLOG_FACILITY_NOT_سيٽ &&
	    log_facility_name((SyslogFacility)tmp) == عدم) {
		error_f("bad syslog facility");
		أرجع SSH_ERR_INVALID_FORMAT;
	}
	options->log_facility = (SyslogFacility)tmp;

	أرجع 0;
}

ساكن صحيح
deserialise_loglevel(ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r, tmp;

	إذا ((r = deserialise_s32(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		أرجع r;
	}
	إذا (tmp != SYSLOG_LEVEL_NOT_سيٽ &&
	    log_level_name((LogLevel)tmp) == عدم) {
		error_f("bad log level");
		أرجع SSH_ERR_INVALID_FORMAT;
	}
	options->log_level = (LogLevel)tmp;

	أرجع 0;
}

ساكن صحيح
deserialise_پورٽ(ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;
	u_int i, n;

	إذا ((r = deserialise_ڳڻپ(buf, &n, "ports")) != 0)
		أرجع r;
	إذا (n > MAX_PORTS) {
		error_f("bad number of ports");
		أرجع SSH_ERR_INVALID_FORMAT;
	}
	options->انگ_ports = n;
	memset(options->ports, 0, حجم(options->ports));
	لكل (i = 0; i < options->انگ_ports; i++) {
		إذا ((r = deserialise_s32(buf, options->ports + i)) != 0) {
			error_fr(r, "deserialise port");
			أرجع r;
		}
	}
	أرجع 0;
}

ساكن صحيح
deserialise_gatewayports(ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;

	إذا ((r = deserialise_s32(buf, &options->fwd_opts.gateway_ports)) != 0) {
		error_fr(r, "deserialise");
		أرجع r;
	}
	أرجع 0;
}

ساكن صحيح
deserialise_streamlocalbindmask(ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;

	إذا ((r = deserialise_گهڻائي(buf,
	    &options->fwd_opts.streamlocal_bind_نقاب)) != 0) {
		error_fr(r, "deserialise");
		أرجع r;
	}
	أرجع 0;
}

ساكن صحيح
deserialise_streamlocalbindunlink(ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;
	u_char tmp;

	إذا ((r = sshbuf_get_u8(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		أرجع r;
	}
	إذا (tmp > 1) {
		error_f("bad boolean");
		أرجع SSH_ERR_INVALID_FORMAT;
	}
	options->fwd_opts.streamlocal_bind_unlink = tmp;
	أرجع 0;
}

ساكن صحيح
deserialise_maxstartups(ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;

	إذا ((r = deserialise_s32(buf, &options->max_startups_begin)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_startups_شرح)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_startups)) != 0) {
		error_fr(r, "deserialise");
		أرجع r;
	}

	أرجع 0;
}

ساكن صحيح
deserialise_permituserenv(ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;

	إذا ((r = deserialise_s32(buf, &options->permit_user_env)) != 0 ||
	    (r = deserialise_nullable_string(buf,
	    &options->permit_user_env_allowlist)) != 0) {
		error_fr(r, "deserialise");
		أرجع r;
	}
	أرجع 0;
}

ساكن صحيح
deserialise_persourcenetblocksize(ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;

	إذا ((r = deserialise_s32(buf,
	    &options->في_ذريعو_masklen_ipv4)) != 0 ||
	    (r = deserialise_s32(buf,
	    &options->في_ذريعو_masklen_ipv6)) != 0) {
		error_fr(r, "deserialise");
		أرجع r;
	}

	أرجع 0;
}

ساكن صحيح
deserialise_persourcepenalties(ServerOptions *options, بنية sshbuf *buf)
{
	بنية في_ذريعو_penalty *psp = &options->في_ذريعو_penalty;
	صحيح r;

	إذا ((r = deserialise_s32(buf, &psp->enabled)) != 0 ||
	    (r = deserialise_s32(buf, &psp->max_sources4)) != 0 ||
	    (r = deserialise_s32(buf, &psp->max_sources6)) != 0 ||
	    (r = deserialise_s32(buf, &psp->حد_کان_مٿي_گهڻائي)) != 0 ||
	    (r = deserialise_s32(buf, &psp->حد_کان_مٿي_mode6)) != 0 ||
	    (r = deserialise_double(buf, &psp->penalty_crash)) != 0 ||
	    (r = deserialise_double(buf, &psp->penalty_grace)) != 0 ||
	    (r = deserialise_double(buf, &psp->penalty_authfail)) != 0 ||
	    (r = deserialise_double(buf, &psp->penalty_invaliduser)) != 0 ||
	    (r = deserialise_double(buf, &psp->penalty_noauth)) != 0 ||
	    (r = deserialise_double(buf,
	    &psp->penalty_refuseconnection)) != 0 ||
	    (r = deserialise_double(buf, &psp->penalty_max)) != 0 ||
	    (r = deserialise_double(buf, &psp->penalty_min)) != 0) {
		error_fr(r, "deserialise");
		أرجع r;
	}

	أرجع 0;
}

ساكن صحيح
deserialise_rekeylimit(ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;

	إذا ((r = deserialise_s64(buf, &options->rekey_حد_بندي)) != 0 ||
	    (r = deserialise_s32(buf, &options->rekey_interval)) != 0) {
		error_fr(r, "deserialise");
		أرجع r;
	}

	أرجع 0;
}

ساكن صحيح
deserialise_subsystem(ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;
	u_int i, n;
	حرف **نالا = عدم, **commands = عدم, **دليلون = عدم;

	إذا ((r = deserialise_ڳڻپ(buf, &n, "subsystems")) != 0)
		أرجع r;
	إذا (n > 0) {
		نالا = xcalloc(n, حجم(*نالا));
		commands = xcalloc(n, حجم(*نالا));
		دليلون = xcalloc(n, حجم(*دليلون));
	}
	لكل (i = 0; i < n; i++) {
		إذا ((r = sshbuf_get_cstring(buf, نالا + i, عدم)) != 0 ||
		    (r = sshbuf_get_cstring(buf, commands + i, عدم)) != 0 ||
		    (r = sshbuf_get_cstring(buf, دليلون + i, عدم)) != 0) {
			error_fr(r, "deserialise member");
			free_string_array(نالا, i + 1);
			free_string_array(commands, i + 1);
			free_string_array(دليلون, i + 1);
			أرجع r;
		}
	}
	options->انگ_subsystems = n;
	options->subsystem_name = نالا;
	options->subsystem_command = commands;
	options->subsystem_دليلون = دليلون;
	أرجع 0;
}

ساكن صحيح
deserialise_pubkey_auth_options(ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;

	إذا ((r = deserialise_s32(buf, &options->pubkey_auth_options)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_pubkey_ok)) != 0) {
		error_fr(r, "deserialise");
		أرجع r;
	}
	أرجع 0;
}

ساكن صحيح
deserialise_timingsecret(ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;

	إذا ((r = sshbuf_get_u64(buf, &options->timing_secret)) != 0) {
		error_fr(r, "deserialise");
		أرجع r;
	}
	أرجع 0;
}

صحيح
deserialise_server_options(بنية sshbuf *buf, ServerOptions *options)
{
	صحيح r = SSH_ERR_اندروني_ERROR;
	uint32_t نسخو;
	ServerOptions new_options;

	initialize_server_options(&new_options);
	إذا ((r = sshbuf_get_u32(buf, &نسخو)) != 0) {
		error_fr(r, "deserialise version");
		اذهب ٻاهريون;
	}
	إذا (نسخو != SSHD_CONFIG_BLOB_نسخو) {
		error_f("unsupported config blob version %u", نسخو);
		r = SSH_ERR_INVALID_FORMAT;
		اذهب ٻاهريون;
	}
#وصف_ڪريو SSHCONF_INT(var, conf, flags, ms, def, cp) \
	إذا ((r = deserialise_s32(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		اذهب ٻاهريون; \
	}
#وصف_ڪريو SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	إذا ((r = deserialise_s32(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		اذهب ٻاهريون; \
	}
#وصف_ڪريو SSHCONF_STRING(var, conf, flags, cp) \
	إذا ((r = deserialise_nullable_string(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		اذهب ٻاهريون; \
	}
#وصف_ڪريو SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	إذا ((r = deserialise_nullable_string_array(buf, &new_options.var, \
	    &new_options.nvar)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		اذهب ٻاهريون; \
	}
#وصف_ڪريو SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	إذا ((r = deserialise_##funcsuffix(&new_options, buf)) != 0) \
		اذهب ٻاهريون;
#وصف_ڪريو SSHCONF_NONCONF(funcsuffix) \
	إذا ((r = deserialise_##funcsuffix(&new_options, buf)) != 0) \
		اذهب ٻاهريون;
#وصف_ڪريو SSHCONF_DEPRECATE(conf, flags, opcode)		/*خالي_جايون*/
#وصف_ڪريو SSHCONF_UNSUPPORTED_INT(var, conf, flags)	new_options.var = 0;
#وصف_ڪريو SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	افعل { \
		حرر(new_options.var); \
		new_options.var = عدم; \
	} طالما (0);
#وصف_ڪريو SSHCONF_ALIAS(old, conf, flags)			/*خالي_جايون*/

	SSHD_CONFIG_ENTRIES

	إذا (sshbuf_len(buf) != 0) {
		error_f("trailing data in config blob");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب ٻاهريون;
	}

#وصف_رد SSHCONF_INT
#وصف_رد SSHCONF_INTFLAG
#وصف_رد SSHCONF_STRING
#وصف_رد SSHCONF_STRARRAY
#وصف_رد SSHCONF_CUSTOM
#وصف_رد SSHCONF_NONCONF
#وصف_رد SSHCONF_DEPRECATE
#وصف_رد SSHCONF_UNSUPPORTED_INT
#وصف_رد SSHCONF_UNSUPPORTED_STRING
#وصف_رد SSHCONF_ALIAS

	/* success */
	r = 0;
	free_server_options(options);
	*options = new_options;
	memset(&new_options, 0, حجم(new_options));
 ٻاهريون:
	free_server_options(&new_options);
	أرجع r;
}

ساكن فراغ
free_hostkeyfile(ServerOptions *options)
{
	u_int i;

	لكل (i = 0; i < options->انگ_host_ڪنجي_files; i++)
		حرر(options->host_ڪنجي_files[i]);
	حرر(options->host_ڪنجي_files);
	حرر(options->host_ڪنجي_file_userprovided);
}

ساكن فراغ
free_listenaddress(ServerOptions *options)
{
	u_int i;

	free_queued_listen_addrs(options->queued_listen_addrs,
	    options->انگ_queued_listens);

	لكل (i = 0; i < options->انگ_listen_addrs; i++) {
		حرر(options->listen_addrs[i].rdomain);
		إذا (options->listen_addrs[i].addrs != عدم)
			freeaddrinfo(options->listen_addrs[i].addrs);
	}
	حرر(options->listen_addrs);
}

ساكن فراغ
free_permituserenv(ServerOptions *options)
{
	حرر(options->permit_user_env_allowlist);
}

ساكن فراغ
free_subsystem(ServerOptions *options)
{
	u_int i;

	لكل (i = 0; i < options->انگ_subsystems; i++) {
		حرر(options->subsystem_name[i]);
		حرر(options->subsystem_command[i]);
		حرر(options->subsystem_دليلون[i]);
	}
	حرر(options->subsystem_name);
	حرر(options->subsystem_command);
	حرر(options->subsystem_دليلون);
}

فراغ
free_server_options(ServerOptions *options)
{
#وصف_ڪريو SSHCONF_INT(var, conf, flags, ms, def, cp)	/*خالي_جايون*/
#وصف_ڪريو SSHCONF_INTFLAG(var, conf, flags, def, cp)	/*خالي_جايون*/
#وصف_ڪريو SSHCONF_STRING(var, conf, flags, cp)		حرر(options->var);
#وصف_ڪريو SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	free_string_array(options->var, options->nvar);
#وصف_ڪريو SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	free_##funcsuffix(options);
#وصف_ڪريو SSHCONF_NONCONF(funcsuffix) \
	free_##funcsuffix(options);
#وصف_ڪريو SSHCONF_DEPRECATE(conf, flags, opcode)		/*خالي_جايون*/
#وصف_ڪريو SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#وصف_ڪريو SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	افعل { \
		حرر(options->var); \
		options->var = عدم; \
	} طالما (0);
#وصف_ڪريو SSHCONF_ALIAS(old, conf, flags)			/*خالي_جايون*/

#وصف_ڪريو free_ipqos(options)
#وصف_ڪريو free_logfacility(options)
#وصف_ڪريو free_loglevel(options)
#وصف_ڪريو free_پورٽ(options)
#وصف_ڪريو free_gatewayports(options)
#وصف_ڪريو free_streamlocalbindmask(options)
#وصف_ڪريو free_streamlocalbindunlink(options)
#وصف_ڪريو free_maxstartups(options)
#وصف_ڪريو free_persourcenetblocksize(options)
#وصف_ڪريو free_persourcepenalties(options)
#وصف_ڪريو free_rekeylimit(options)
#وصف_ڪريو free_pubkey_auth_options(options)
#وصف_ڪريو free_timingsecret(options)

	SSHD_CONFIG_ENTRIES

#وصف_رد free_ipqos
#وصف_رد free_logfacility
#وصف_رد free_loglevel
#وصف_رد free_پورٽ
#وصف_رد free_gatewayports
#وصف_رد free_streamlocalbindmask
#وصف_رد free_streamlocalbindunlink
#وصف_رد free_maxstartups
#وصف_رد free_persourcenetblocksize
#وصف_رد free_persourcepenalties
#وصف_رد free_rekeylimit
#وصف_رد free_timingsecret

#وصف_رد SSHCONF_INT
#وصف_رد SSHCONF_INTFLAG
#وصف_رد SSHCONF_STRING
#وصف_رد SSHCONF_STRARRAY
#وصف_رد SSHCONF_CUSTOM
#وصف_رد SSHCONF_NONCONF
#وصف_رد SSHCONF_DEPRECATE
#وصف_رد SSHCONF_UNSUPPORTED_INT
#وصف_رد SSHCONF_UNSUPPORTED_STRING
#وصف_رد SSHCONF_ALIAS

	initialize_server_options(options);
}

ساكن فراغ
copy_server_option_int(صحيح *dst, صحيح src)
{
	إذا (src != -1)
		*dst = src;
}

ساكن فراغ
copy_server_option_int64(int64_t *dst, int64_t src)
{
	إذا (src != -1)
		*dst = src;
}

ساكن فراغ
copy_server_option_string(حرف **dst, ثابت حرف *src)
{
	إذا (src != عدم && *dst != src) {
		حرر(*dst);
		*dst = xstrdup(src);
	}
}

ساكن فراغ
copy_server_option_strarray_قدرون(حرف ***dst, u_int ndst,
    حرف * ثابت *src, u_int nsrc)
{
	u_int i;

	إذا (nsrc == 0)
		أرجع;
	لكل (i = 0; i < ndst; i++)
		حرر((*dst)[i]);
	حرر(*dst);
	*dst = xcalloc(nsrc, حجم(**dst));
	لكل (i = 0; i < nsrc; i++)
		(*dst)[i] = src[i] == عدم ? عدم : xstrdup(src[i]);
}

ساكن فراغ
copy_server_option_strarray(حرف ***dst, u_int *ndst,
    حرف * ثابت *src, u_int nsrc)
{
	إذا (nsrc == 0)
		أرجع;
	copy_server_option_strarray_قدرون(dst, *ndst, src, nsrc);
	*ndst = nsrc;
}

ساكن فراغ
copy_ipqos(ServerOptions *dst, ثابت ServerOptions *src)
{
	copy_server_option_int(&dst->ip_qos_interactive,
	    src->ip_qos_interactive);
	copy_server_option_int(&dst->ip_qos_bulk, src->ip_qos_bulk);
}

ساكن فراغ
copy_gatewayports(ServerOptions *dst, ثابت ServerOptions *src)
{
	copy_server_option_int(&dst->fwd_opts.gateway_ports,
	    src->fwd_opts.gateway_ports);
}

ساكن فراغ
copy_streamlocalbindunlink(ServerOptions *dst, ثابت ServerOptions *src)
{
	copy_server_option_int(&dst->fwd_opts.streamlocal_bind_unlink,
	    src->fwd_opts.streamlocal_bind_unlink);
}

ساكن فراغ
copy_loglevel(ServerOptions *dst, ثابت ServerOptions *src)
{
	إذا (src->log_level != -1)
		dst->log_level = src->log_level;
}

ساكن فراغ
copy_rekeylimit(ServerOptions *dst, ثابت ServerOptions *src)
{
	copy_server_option_int64(&dst->rekey_حد_بندي, src->rekey_حد_بندي);
	copy_server_option_int(&dst->rekey_interval, src->rekey_interval);
}

ساكن فراغ
copy_subsystem(ServerOptions *dst, ثابت ServerOptions *src)
{
	u_int old_انگ_subsystems = dst->انگ_subsystems;

	إذا (src->انگ_subsystems == 0)
		أرجع;
	copy_server_option_strarray_قدرون(&dst->subsystem_name,
	    old_انگ_subsystems, src->subsystem_name, src->انگ_subsystems);
	copy_server_option_strarray_قدرون(&dst->subsystem_command,
	    old_انگ_subsystems, src->subsystem_command, src->انگ_subsystems);
	copy_server_option_strarray_قدرون(&dst->subsystem_دليلون,
	    old_انگ_subsystems, src->subsystem_دليلون, src->انگ_subsystems);
	dst->انگ_subsystems = src->انگ_subsystems;
}

ساكن فراغ
copy_pubkey_auth_options(ServerOptions *dst, ثابت ServerOptions *src)
{
	إذا (src->pubkey_auth_options != -1) {
		dst->pubkey_auth_options = src->pubkey_auth_options;
		dst->max_pubkey_ok = src->max_pubkey_ok;
	}
}

/*
 * Copy any supported values that are set.
 *
 * If the preauth flag is set, skip the post-authentication-only manual
 * string cleanup and subsystem merge below.
 */
فراغ
copy_سيٽ_server_options(ServerOptions *dst, ServerOptions *src, صحيح preauth)
{
	إذا (dst == src)
		أرجع;

#وصف_ڪريو SSHCONF_INT(var, conf, flags, ms, def, cp) \
	cp(copy_server_option_int(&dst->var, src->var);)
#وصف_ڪريو SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	cp(copy_server_option_int(&dst->var, src->var);)
#وصف_ڪريو SSHCONF_STRING(var, conf, flags, cp) \
	cp(copy_server_option_string(&dst->var, src->var);)
#وصف_ڪريو SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	cp(copy_server_option_strarray(&dst->var, &dst->nvar, \
	    src->var, src->nvar);)
#وصف_ڪريو SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	cp(copy_##funcsuffix(dst, src);)
#وصف_ڪريو SSHCONF_NONCONF(funcsuffix)			/*خالي_جايون*/
#وصف_ڪريو SSHCONF_DEPRECATE(conf, flags, opcode)		/*خالي_جايون*/
#وصف_ڪريو SSHCONF_UNSUPPORTED_INT(var, conf, flags)	dst->var = 0;
#وصف_ڪريو SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	افعل { \
		حرر(dst->var); \
		dst->var = عدم; \
	} طالما (0);
#وصف_ڪريو SSHCONF_ALIAS(old, conf, flags)			/*خالي_جايون*/

	SSHD_CONFIG_ENTRIES

#وصف_رد SSHCONF_INT
#وصف_رد SSHCONF_INTFLAG
#وصف_رد SSHCONF_STRING
#وصف_رد SSHCONF_STRARRAY
#وصف_رد SSHCONF_CUSTOM
#وصف_رد SSHCONF_NONCONF
#وصف_رد SSHCONF_DEPRECATE
#وصف_رد SSHCONF_UNSUPPORTED_INT
#وصف_رد SSHCONF_UNSUPPORTED_STRING
#وصف_رد SSHCONF_ALIAS

	/*
	 * The bind_mask is a mode_t that may be unsigned, so we can't use
	 * copy_server_option_int - it does a signed comparison that causes
	 * compiler warnings.
	 */
	إذا (src->fwd_opts.streamlocal_bind_نقاب != (گهڻائي_t)-1) {
		dst->fwd_opts.streamlocal_bind_نقاب =
		    src->fwd_opts.streamlocal_bind_نقاب;
	}

	/* Arguments that accept '+...' need to be expanded */
	assemble_algorithms(dst);

	/*
	 * These options may be "none" to clear a global setting.  They are
	 * consulted before authentication, so they must be cleared here
	 * rather than in the post-auth section below.
	 */
#وصف_ڪريو CLEAR_ON_NONE(v) \
	افعل { \
		إذا (option_clear_or_none(v)) { \
			حرر(v); \
			v = عدم; \
		} \
	} طالما(0)
	CLEAR_ON_NONE(dst->authorized_principals_file);
	CLEAR_ON_NONE(dst->trusted_user_ca_ڪنجيون);
	CLEAR_ON_NONE(dst->banner);

	/*
	 * The only things that should be below this point are string options
	 * which are only used after authentication.
	 */
	إذا (preauth)
		أرجع;

	/* These options may be "none" to clear a global setting */
	copy_server_option_string(&dst->adm_forced_command,
	    src->adm_forced_command);
	copy_server_option_string(&dst->chroot_directory,
	    src->chroot_directory);
	CLEAR_ON_NONE(dst->chroot_directory);
	CLEAR_ON_NONE(dst->adm_forced_command);
#وصف_رد CLEAR_ON_NONE

	/* Subsystems require merging. */
	servconf_ملايو_subsystems(dst, src);
}

#وصف_ڪريو SERVCONF_MAX_اونهائي	16
ساكن فراغ
parse_server_config_اونهائي(ServerOptions *options, ثابت حرف *filename,
    بنية sshbuf *conf, بنية include_list *includes,
    بنية connection_info *connectinfo, صحيح flags, صحيح *activep, صحيح اونهائي)
{
	صحيح linenum, bad_options = 0;
	حرف *cp, *obuf, *cbuf;

	إذا (اونهائي < 0 || اونهائي > SERVCONF_MAX_اونهائي)
		fatal("Too many recursive configuration includes");

	debug2_f("config %s len %zu%s", filename, sshbuf_len(conf),
	    (flags & SSHCFG_NEVERMATCH ? " [checking syntax only]" : ""));

	إذا ((obuf = cbuf = sshbuf_dup_string(conf)) == عدم)
		fatal_f("sshbuf_dup_string failed");
	linenum = 1;
	طالما ((cp = strsep(&cbuf, "\n")) != عدم) {
		إذا (process_server_config_سٽ_اونهائي(options, cp,
		    filename, linenum++, activep, connectinfo, &flags,
		    اونهائي, includes) != 0)
			bad_options++;
	}
	حرر(obuf);
	إذا (bad_options > 0)
		fatal("%s: terminating, %d bad configuration options",
		    filename, bad_options);
}

فراغ
parse_server_config(ServerOptions *options, ثابت حرف *filename,
    بنية sshbuf *conf, بنية include_list *includes,
    بنية connection_info *connectinfo, صحيح reexec)
{
	صحيح سرگرم = connectinfo ? 0 : 1;
	parse_server_config_اونهائي(options, filename, conf, includes,
	    connectinfo, (connectinfo ? SSHCFG_ميلاپ_ONLY : 0), &سرگرم, 0);
	إذا (!reexec)
		process_queued_listen_addrs(options);
}

ساكن ثابت حرف *
fmt_multistate_int(صحيح val, ثابت بنية multistate *m)
{
	u_int i;

	لكل (i = 0; m[i].ڪنجي != عدم; i++) {
		إذا (m[i].قدر == val)
			أرجع m[i].ڪنجي;
	}
	أرجع "UNKNOWN";
}

ساكن ثابت حرف *
fmt_intarg(ServerOpCodes ڪوڊ, صحيح val)
{
	إذا (val == -1)
		أرجع "unset";
	بدل (ڪوڊ) {
	حالة s_پتو_Family:
		أرجع fmt_multistate_int(val, multistate_addressfamily);
	حالة s_Permit_پاڙ_Login:
		أرجع fmt_multistate_int(val, multistate_permitrootlogin);
	حالة sGatewayPorts:
		أرجع fmt_multistate_int(val, multistate_gatewayports);
	حالة sCompression:
		أرجع fmt_multistate_int(val, multistate_compression);
	حالة sAllowTcpForwarding:
		أرجع fmt_multistate_int(val, multistate_tcpfwd);
	حالة s_Allow_وهڪرو_Local_Forwarding:
		أرجع fmt_multistate_int(val, multistate_tcpfwd);
	حالة sIgnoreRhosts:
		أرجع fmt_multistate_int(val, multistate_ignore_rhosts);
	حالة sTCPKeepAlive:
		أرجع fmt_multistate_int(val, multistate_keepalives);
	حالة sWarnWeakCrypto:
		أرجع fmt_multistate_int(val, multistate_warnweakcrypto);
	حالة sFingerprintHash:
		أرجع ssh_digest_alg_name(val);
	افتراضي:
		بدل (val) {
		حالة 0:
			أرجع "no";
		حالة 1:
			أرجع "yes";
		افتراضي:
			أرجع "UNKNOWN";
		}
	}
}

ساكن فراغ
dump_cfg_int(ServerOpCodes ڪوڊ, صحيح val)
{
	إذا (ڪوڊ == s_اڻ_استعمال_ٿيل_Connection_Timeout && val == 0) {
		لکو("%s none\n", lookup_opcode_name(ڪوڊ));
		أرجع;
	}
	لکو("%s %d\n", lookup_opcode_name(ڪوڊ), val);
}

ساكن فراغ
dump_cfg_oct(ServerOpCodes ڪوڊ, صحيح val)
{
	لکو("%s 0%o\n", lookup_opcode_name(ڪوڊ), val);
}

ساكن فراغ
dump_cfg_fmtint(ServerOpCodes ڪوڊ, صحيح val)
{
	لکو("%s %s\n", lookup_opcode_name(ڪوڊ), fmt_intarg(ڪوڊ, val));
}

ساكن فراغ
dump_cfg_string(ServerOpCodes ڪوڊ, ثابت حرف *val)
{
	لکو("%s %s\n", lookup_opcode_name(ڪوڊ),
	    val == عدم ? "none" : val);
}

ساكن فراغ
dump_cfg_strarray(ServerOpCodes ڪوڊ, u_int ڳڻپ, حرف **vals)
{
	u_int i;

	لكل (i = 0; i < ڳڻپ; i++)
		لکو("%s %s\n", lookup_opcode_name(ڪوڊ), vals[i]);
}

ساكن فراغ
dump_cfg_strarray_oneline(ServerOpCodes ڪوڊ, u_int ڳڻپ, حرف **vals)
{
	u_int i;

	بدل (ڪوڊ) {
	حالة sAuthenticationMethods:
	حالة sChannelTimeout:
		اكسر;
	افتراضي:
		إذا (ڳڻپ <= 0)
			أرجع;
		اكسر;
	}

	لکو("%s", lookup_opcode_name(ڪوڊ));
	لكل (i = 0; i < ڳڻپ; i++)
		لکو(" %s",  vals[i]);
	إذا (ڪوڊ == sAuthenticationMethods && ڳڻپ == 0)
		لکو(" any");
	وإلا إذا (ڪوڊ == sChannelTimeout && ڳڻپ == 0)
		لکو(" none");
	لکو("\n");
}

ساكن حرف *
format_listen_addrs(بنية listenaddr *la)
{
	صحيح r;
	بنية addrinfo *ai;
	حرف addr[NI_MAXHOST], پورٽ[NI_MAXSERV];
	حرف *laddr1 = xstrdup(""), *laddr2 = عدم;

	/*
	 * ListenAddress must be after Port.  add_one_listen_addr pushes
	 * addresses onto a stack, so to maintain ordering we need to
	 * print these in reverse order.
	 */
	لكل (ai = la->addrs; ai; ai = ai->ai_next) {
		إذا ((r = getnameinfo(ai->ai_addr, ai->ai_addrlen, addr,
		    حجم(addr), پورٽ, حجم(پورٽ),
		    NI_NUMERICHOST|NI_NUMERICSERV)) != 0) {
			error("getnameinfo: %.100s", ssh_gai_strerror(r));
			استمر;
		}
		laddr2 = laddr1;
		إذا (ai->ai_family == AF_INET6) {
			xasprintf(&laddr1, "ListenAddress [%s]:%s%s%s\n%s",
			    addr, پورٽ,
			    la->rdomain == عدم ? "" : " rdomain ",
			    la->rdomain == عدم ? "" : la->rdomain,
			    laddr2);
		} وإلا {
			xasprintf(&laddr1, "ListenAddress %s:%s%s%s\n%s",
			    addr, پورٽ,
			    la->rdomain == عدم ? "" : " rdomain ",
			    la->rdomain == عدم ? "" : la->rdomain,
			    laddr2);
		}
		حرر(laddr2);
	}
	أرجع laddr1;
}

فراغ
dump_config(ServerOptions *o)
{
	حرف *s;
	u_int i;

	/* these are usually at the top of the config */
	لكل (i = 0; i < o->انگ_ports; i++)
		لکو("Port %d\n", o->ports[i]);
	dump_cfg_fmtint(s_پتو_Family, o->پتو_family);

	لكل (i = 0; i < o->انگ_listen_addrs; i++) {
		s = format_listen_addrs(&o->listen_addrs[i]);
		لکو("%s", s);
		حرر(s);
	}

	/* integer arguments */
#جيڪڏهن_وصف_ٿيل USE_PAM
	dump_cfg_fmtint(sUsePAM, o->use_pam);
	dump_cfg_string(sPAMServiceName, o->pam_service_name);
#جيڪڏهن_پورو
	dump_cfg_int(s_Login_Grace_وقت, o->login_grace_وقت);
	dump_cfg_int(s_X11_Display_وٿي, o->x11_display_وٿي);
	dump_cfg_int(sMaxAuthTries, o->max_authtries);
	dump_cfg_int(sMaxSessions, o->max_sessions);
	dump_cfg_int(sClientAliveInterval, o->client_alive_interval);
	dump_cfg_int(s_Client_Alive_ڳڻپ_Max, o->client_alive_ڳڻپ_max);
	dump_cfg_int(sRequiredRSASize, o->required_rsa_سائيز);
	dump_cfg_oct(s_وهڪرو_Local_Bind_نقاب, o->fwd_opts.streamlocal_bind_نقاب);
	dump_cfg_int(s_اڻ_استعمال_ٿيل_Connection_Timeout, o->اڻ_استعمال_ٿيل_connection_timeout);

	/* formatted integer arguments */
	dump_cfg_fmtint(s_Permit_پاڙ_Login, o->permit_پاڙ_login);
	dump_cfg_fmtint(sIgnoreRhosts, o->ignore_rhosts);
	dump_cfg_fmtint(s_Ignore_User_معلوم_Hosts, o->ignore_user_معلوم_hosts);
	dump_cfg_fmtint(sHostbasedAuthentication, o->hostbased_authentication);
	dump_cfg_fmtint(s_Hostbased_استعمال_ڪري_Name_From_Packet_Only,
	    o->hostbased_استعمال_ڪري_name_from_packet_only);
	dump_cfg_fmtint(sPubkeyAuthentication, o->pubkey_authentication);
#جيڪڏهن_وصف_ٿيل KRB5
	dump_cfg_fmtint(sKerberosAuthentication, o->kerberos_authentication);
	dump_cfg_fmtint(sKerberosOrLocalPasswd, o->kerberos_or_local_passwd);
	dump_cfg_fmtint(sKerberosTicketCleanup, o->kerberos_ticket_cleanup);
# ifdef USE_AFS
	dump_cfg_fmtint(sKerberosGetAFSToken, o->kerberos_get_afs_token);
# endif
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل GSSAPI
	dump_cfg_fmtint(sGSSAPIAuthentication, o->gss_authentication);
	dump_cfg_fmtint(sGSSAPICleanupCredentials, o->gss_cleanup_creds);
	dump_cfg_fmtint(sGSSAPIDelegateCredentials, o->gss_deleg_creds);
	dump_cfg_fmtint(sGSSAPIStrictAcceptorCheck, o->gss_strict_acceptor);
#جيڪڏهن_پورو
	dump_cfg_fmtint(sPasswordAuthentication, o->password_authentication);
	dump_cfg_fmtint(sKbdInteractiveAuthentication,
	    o->kbd_interactive_authentication);
	dump_cfg_fmtint(sPrintMotd, o->print_motd);
#جيڪڏهن_وصف_نه_ٿيل DISABLE_LASTLOG
	dump_cfg_fmtint(s_Print_آخري_Log, o->print_lastlog);
#جيڪڏهن_پورو
	dump_cfg_fmtint(sX11Forwarding, o->x11_forwarding);
	dump_cfg_fmtint(sX11UseLocalhost, o->x11_use_localhost);
	dump_cfg_fmtint(sPermitTTY, o->permit_tty);
	dump_cfg_fmtint(sPermitUserRC, o->permit_user_rc);
	dump_cfg_fmtint(sStrictModes, o->strict_modes);
	dump_cfg_fmtint(sTCPKeepAlive, o->tcp_keep_alive);
	dump_cfg_fmtint(s_Permit_خالي_جايون_Passwords, o->permit_خالي_جايون_passwd);
	dump_cfg_fmtint(sCompression, o->compression);
	dump_cfg_fmtint(sGatewayPorts, o->fwd_opts.gateway_ports);
	dump_cfg_fmtint(sUseDNS, o->use_dns);
	dump_cfg_fmtint(sAllowTcpForwarding, o->allow_tcp_forwarding);
	dump_cfg_fmtint(sAllowAgentForwarding, o->allow_agent_forwarding);
	dump_cfg_fmtint(sDisableForwarding, o->disable_forwarding);
	dump_cfg_fmtint(s_Allow_وهڪرو_Local_Forwarding, o->allow_streamlocal_forwarding);
	dump_cfg_fmtint(s_وهڪرو_Local_Bind_Unlink, o->fwd_opts.streamlocal_bind_unlink);
	dump_cfg_fmtint(sFingerprintHash, o->fingerprint_hash);
	dump_cfg_fmtint(sExposeAuthInfo, o->expose_userauth_info);
	dump_cfg_fmtint(sWarnWeakCrypto, o->warn_weak_crypto);
	dump_cfg_fmtint(sRefuseConnection, o->refuse_connection);

	/* string arguments */
	dump_cfg_string(sPidFile, o->pid_file);
	dump_cfg_string(sModuliFile, o->moduli_file);
	dump_cfg_string(sXAuthLocation, o->xauth_location);
	dump_cfg_string(sCiphers, o->ciphers);
	dump_cfg_string(sMacs, o->macs);
	dump_cfg_string(sBanner, o->banner);
	dump_cfg_string(sForceCommand, o->adm_forced_command);
	dump_cfg_string(sChrootDirectory, o->chroot_directory);
	dump_cfg_string(sTrustedUserCAKeys, o->trusted_user_ca_ڪنجيون);
	dump_cfg_string(s_Security_ڪنجي_Provider, o->sk_provider);
	dump_cfg_string(sAuthorizedPrincipalsFile,
	    o->authorized_principals_file);
	dump_cfg_string(s_نسخو_Addendum, *o->نسخو_addendum == '\0'
	    ? "none" : o->نسخو_addendum);
	dump_cfg_string(s_Authorized_ڪنجيون_Command, o->authorized_ڪنجيون_command);
	dump_cfg_string(s_Authorized_ڪنجيون_Command_User, o->authorized_ڪنجيون_command_user);
	dump_cfg_string(sAuthorizedPrincipalsCommand, o->authorized_principals_command);
	dump_cfg_string(sAuthorizedPrincipalsCommandUser, o->authorized_principals_command_user);
	dump_cfg_string(s_Host_ڪنجي_Agent, o->host_ڪنجي_agent);
	dump_cfg_string(sKexAlgorithms, o->kex_algorithms);
	dump_cfg_string(sCASignatureAlgorithms, o->ca_sign_algorithms);
	dump_cfg_string(sHostbasedAcceptedAlgorithms, o->hostbased_accepted_algos);
	dump_cfg_string(s_Host_ڪنجي_Algorithms, o->hostkeyalgorithms);
	dump_cfg_string(sPubkeyAcceptedAlgorithms, o->pubkey_accepted_algos);
#إذا defined(__OpenBSD__) || defined(HAVE_SYS_سيٽ_PROCESS_RDOMAIN)
	dump_cfg_string(sRDomain, o->routing_domain);
#جيڪڏهن_پورو
	dump_cfg_string(s_Sshd_Session_رستو, o->sshd_session_رستو);
	dump_cfg_string(s_Sshd_Auth_رستو, o->sshd_auth_رستو);
	dump_cfg_string(s_في_ذريعو_Penalty_Exempt_List, o->في_ذريعو_penalty_exempt);
	dump_cfg_string(s_Agent_Socket_رستو, o->agent_socket_رستو);

	/* string arguments requiring a lookup */
	dump_cfg_string(sLogLevel, log_level_name(o->log_level));
	dump_cfg_string(sSyslogFacility, log_facility_name(o->log_facility));

	/* string array arguments */
	dump_cfg_strarray_oneline(s_Authorized_ڪنجيون_File, o->انگ_authkeys_files,
	    o->authorized_ڪنجيون_files);
	dump_cfg_strarray_oneline(s_Revoked_ڪنجيون, o->انگ_revoked_ڪنجيون_files,
	    o->revoked_ڪنجيون_files);
	dump_cfg_strarray(s_Host_ڪنجي, o->انگ_host_ڪنجي_files, o->host_ڪنجي_files);
	dump_cfg_strarray(sHostCertificate, o->انگ_host_cert_files,
	    o->host_cert_files);
	dump_cfg_strarray(sAllowUsers, o->انگ_allow_users, o->allow_users);
	dump_cfg_strarray(sDenyUsers, o->انگ_deny_users, o->deny_users);
	dump_cfg_strarray(sAllowGroups, o->انگ_allow_groups, o->allow_groups);
	dump_cfg_strarray(sDenyGroups, o->انگ_deny_groups, o->deny_groups);
	dump_cfg_strarray(sAcceptEnv, o->انگ_accept_env, o->accept_env);
	dump_cfg_strarray(s_سيٽ_Env, o->انگ_setenv, o->setenv);
	dump_cfg_strarray_oneline(sAuthenticationMethods,
	    o->انگ_auth_methods, o->auth_methods);
	dump_cfg_strarray_oneline(sLogVerbose,
	    o->انگ_log_verbose, o->log_verbose);
	dump_cfg_strarray_oneline(sChannelTimeout,
	    o->انگ_channel_timeouts, o->channel_timeouts);

	/* other arguments */
	لكل (i = 0; i < o->انگ_subsystems; i++)
		لکو("Subsystem %s %s\n", o->subsystem_name[i],
		    o->subsystem_دليلون[i]);

	لکو("MaxStartups %d:%d:%d\n", o->max_startups_begin,
	    o->max_startups_شرح, o->max_startups);
	لکو("PerSourceMaxStartups ");
	إذا (o->في_ذريعو_max_startups == وڌ_کان_وڌ_عدد)
		لکو("none\n");
	وإلا
		لکو("%d\n", o->في_ذريعو_max_startups);
	لکو("PerSourceNetBlockSize %d:%d\n", o->في_ذريعو_masklen_ipv4,
	    o->في_ذريعو_masklen_ipv6);

	s = عدم;
	لكل (i = 0; tunmode_desc[i].val != -1; i++) {
		إذا (tunmode_desc[i].val == o->permit_tun) {
			s = tunmode_desc[i].متن;
			اكسر;
		}
	}
	dump_cfg_string(sPermitTunnel, s);

	لکو("IPQoS %s ", iptos2str(o->ip_qos_interactive));
	لکو("%s\n", iptos2str(o->ip_qos_bulk));

	لکو("RekeyLimit %llu %d\n", (بنانشان ڊگهو ڊگهو)o->rekey_حد_بندي,
	    o->rekey_interval);

	لکو("PermitOpen");
	إذا (o->انگ_permitted_opens == 0)
		لکو(" any");
	وإلا {
		لكل (i = 0; i < o->انگ_permitted_opens; i++)
			لکو(" %s", o->permitted_opens[i]);
	}
	لکو("\n");
	لکو("PermitListen");
	إذا (o->انگ_permitted_listens == 0)
		لکو(" any");
	وإلا {
		لكل (i = 0; i < o->انگ_permitted_listens; i++)
			لکو(" %s", o->permitted_listens[i]);
	}
	لکو("\n");

	إذا (o->permit_user_env_allowlist == عدم) {
		dump_cfg_fmtint(sPermitUserEnvironment, o->permit_user_env);
	} وإلا {
		لکو("PermitUserEnvironment %s\n",
		    o->permit_user_env_allowlist);
	}

	لکو("PubkeyAuthOptions");
	إذا (o->pubkey_auth_options == 0)
		لکو(" none");
	إذا (o->pubkey_auth_options & PUBKEYAUTH_TOUCH_REQUIRED)
		لکو(" touch-required");
	إذا (o->pubkey_auth_options & PUBKEYAUTH_VERIFY_REQUIRED)
		لکو(" verify-required");
	إذا (o->max_pubkey_ok != -1)
		لکو(" max-pk-ok:%d", o->max_pubkey_ok);
	لکو("\n");

	إذا (o->في_ذريعو_penalty.enabled) {
		لکو("PerSourcePenalties crash:%f authfail:%f noauth:%f "
		    "invaliduser:%f "
		    "grace-exceeded:%f refuseconnection:%f max:%f min:%f "
		    "max-sources4:%d max-sources6:%d "
		    "overflow:%s overflow6:%s\n",
		    o->في_ذريعو_penalty.penalty_crash,
		    o->في_ذريعو_penalty.penalty_authfail,
		    o->في_ذريعو_penalty.penalty_noauth,
		    o->في_ذريعو_penalty.penalty_invaliduser,
		    o->في_ذريعو_penalty.penalty_grace,
		    o->في_ذريعو_penalty.penalty_refuseconnection,
		    o->في_ذريعو_penalty.penalty_max,
		    o->في_ذريعو_penalty.penalty_min,
		    o->في_ذريعو_penalty.max_sources4,
		    o->في_ذريعو_penalty.max_sources6,
		    o->في_ذريعو_penalty.حد_کان_مٿي_گهڻائي ==
		    في_ذريعو_PENALTY_حد_کان_مٿي_DENY_ALL ?
		    "deny-all" : "permissive",
		    o->في_ذريعو_penalty.حد_کان_مٿي_mode6 ==
		    في_ذريعو_PENALTY_حد_کان_مٿي_DENY_ALL ?
		    "deny-all" : "permissive");
	} وإلا
		لکو("PerSourcePenalties no\n");
}
