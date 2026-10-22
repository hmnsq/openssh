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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/socket.h>
#شامل <sys/queue.h>
#شامل <sys/stat.h>
#اگر_تعریف_شدہ __OpenBSD__
#شامل <sys/sysctl.h>
#اگر_ختم

#شامل <netinet/in.h>
#شامل <netinet/ip.h>
#اگر_تعریف_شدہ HAVE_NET_ROUTE_H
#شامل <net/route.h>
#اگر_ختم

#شامل <ctype.h>
#شامل <glob.h>
#شامل <netdb.h>
#شامل <pwd.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <signal.h>
#شامل <unistd.h>
#شامل <limits.h>
#شامل <stdarg.h>
#شامل <errno.h>
#شامل <util.h>

#شامل "xmalloc.h"
#شامل "ssh.h"
#شامل "log.h"
#شامل "sshbuf.h"
#شامل "misc.h"
#شامل "servconf.h"
#شامل "pathnames.h"
#شامل "cipher.h"
#شامل "sshkey.h"
#شامل "kex.h"
#شامل "mac.h"
#شامل "match.h"
#شامل "channels.h"
#شامل "groupaccess.h"
#شامل "canohost.h"
#شامل "packet.h"
#شامل "ssherr.h"
#شامل "hostfile.h"
#شامل "auth.h"
#شامل "myproposal.h"
#شامل "digest.h"
#شامل "version.h"

#تعریف_کرو SSHD_CONFIG_BLOB_نسخہ	1

#اگر !defined(SSHD_PAM_SERVICE)
# define SSHD_PAM_SERVICE		"sshd"
#اگر_ختم

ساکن خالی جوڑو_listen_addr(ServerOptions *, ثابت حرف *,
    ثابت حرف *, صحیح);
ساکن خالی جوڑو_one_listen_addr(ServerOptions *, ثابت حرف *,
    ثابت حرف *, صحیح);
ساکن خالی parse_server_config_گہرائی(ServerOptions *options,
    ثابت حرف *filename, ساخت sshbuf *conf, ساخت include_list *includes,
    ساخت connection_info *connectinfo, صحیح flags, صحیح *activep, صحیح گہرائی);

خارجی ساخت sshbuf *cfg;

/* Initializes the server options to their default values. */

خالی
initialize_server_options(ServerOptions *options)
{
	memset(options, 0, حجم(*options));
#تعریف_کرو SSHCONF_INT(var, conf, flags, ms, def, cp)	options->var = -1;
#تعریف_کرو SSHCONF_INTFLAG(var, conf, flags, def, cp)	options->var = -1;
#تعریف_کرو SSHCONF_STRING(var, conf, flags, cp)		options->var = تہی;
#تعریف_کرو SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	options->nvar = 0; \
	options->var = تہی;
#تعریف_کرو SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	init_##funcsuffix(options)
#تعریف_کرو SSHCONF_NONCONF(funcsuffix) \
	init_##funcsuffix(options)
#تعریف_کرو SSHCONF_DEPRECATE(conf, flags, opcode)		/*خالی_خانے*/
#تعریف_کرو SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#تعریف_کرو SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	options->var = تہی;
#تعریف_کرو SSHCONF_ALIAS(old, conf, flags)			/*خالی_خانے*/

	/* Using macros for these is a bit overkill but forces consistency */
#تعریف_کرو init_hostkeyfile(options) \
	options->host_کلید_files = 0; \
	options->عدد_host_کلید_files = 0; \
	options->host_کلید_file_userprovided = تہی;
#تعریف_کرو init_ipqos(options) \
	options->ip_qos_interactive = -1; \
	options->ip_qos_bulk = -1;
#تعریف_کرو init_listenaddress(options) \
	options->queued_listen_addrs = تہی; \
	options->عدد_queued_listens = 0; \
	options->listen_addrs = تہی; \
	options->عدد_listen_addrs = 0;
#تعریف_کرو init_logfacility(options) \
	options->log_facility = SYSLOG_FACILITY_NOT_سیٹ;
#تعریف_کرو init_loglevel(options) \
	options->log_level = SYSLOG_LEVEL_NOT_سیٹ;
#تعریف_کرو init_پورٹ(options) \
	options->عدد_ports = 0; \
	options->ports_from_cmdline = 0;
#تعریف_کرو init_gatewayports(options) \
	options->fwd_opts.gateway_ports = -1;
#تعریف_کرو init_streamlocalbindmask(options) \
	options->fwd_opts.streamlocal_bind_نقاب = (منوال_t)-1;
#تعریف_کرو init_streamlocalbindunlink(options) \
	options->fwd_opts.streamlocal_bind_unlink = -1;
#تعریف_کرو init_maxstartups(options) \
	options->max_startups_begin = -1; \
	options->max_startups_شرح = -1; \
	options->max_startups = -1;
#تعریف_کرو init_permituserenv(options) \
	options->permit_user_env = -1; \
	options->permit_user_env_allowlist = تہی;
#تعریف_کرو init_persourcenetblocksize(options) \
	options->فی_ماخذ_masklen_ipv4 = -1; \
	options->فی_ماخذ_masklen_ipv6 = -1;
#تعریف_کرو init_persourcepenalties(options) \
	options->فی_ماخذ_penalty_exempt = تہی; \
	options->فی_ماخذ_penalty.enabled = -1; \
	options->فی_ماخذ_penalty.max_sources4 = -1; \
	options->فی_ماخذ_penalty.max_sources6 = -1; \
	options->فی_ماخذ_penalty.حد_سے_تجاوز_منوال = -1; \
	options->فی_ماخذ_penalty.حد_سے_تجاوز_mode6 = -1; \
	options->فی_ماخذ_penalty.penalty_crash = -1.0; \
	options->فی_ماخذ_penalty.penalty_authfail = -1.0; \
	options->فی_ماخذ_penalty.penalty_invaliduser = -1.0; \
	options->فی_ماخذ_penalty.penalty_noauth = -1.0; \
	options->فی_ماخذ_penalty.penalty_grace = -1.0; \
	options->فی_ماخذ_penalty.penalty_refuseconnection = -1.0; \
	options->فی_ماخذ_penalty.penalty_max = -1.0; \
	options->فی_ماخذ_penalty.penalty_min = -1.0;
#تعریف_کرو init_rekeylimit(options) \
	options->rekey_حد_بندی = -1; \
	options->rekey_interval = -1;
#تعریف_کرو init_subsystem(options) \
	options->عدد_subsystems = 0; \
	options->subsystem_name = تہی; \
	options->subsystem_command = تہی; \
	options->subsystem_دلائل = تہی;
#تعریف_کرو init_pubkey_auth_options(options) \
	options->pubkey_auth_options = -1; \
	options->max_pubkey_ok = -1;
#تعریف_کرو init_timingsecret(options) \
	options->timing_secret = 0;

	SSHD_CONFIG_ENTRIES

#تعریف_منسوخ init_hostkeyfile
#تعریف_منسوخ init_ipqos
#تعریف_منسوخ init_listenaddress
#تعریف_منسوخ init_logfacility
#تعریف_منسوخ init_loglevel
#تعریف_منسوخ init_پورٹ
#تعریف_منسوخ init_gatewayports
#تعریف_منسوخ init_streamlocalbindmask
#تعریف_منسوخ init_streamlocalbindunlink
#تعریف_منسوخ init_maxstartups
#تعریف_منسوخ init_permituserenv
#تعریف_منسوخ init_persourcenetblocksize
#تعریف_منسوخ init_persourcepenalties
#تعریف_منسوخ init_rekeylimit
#تعریف_منسوخ init_subsystem
#تعریف_منسوخ init_timingsecret
#تعریف_منسوخ SSHCONF_INT
#تعریف_منسوخ SSHCONF_INTFLAG
#تعریف_منسوخ SSHCONF_STRING
#تعریف_منسوخ SSHCONF_STRARRAY
#تعریف_منسوخ SSHCONF_CUSTOM
#تعریف_منسوخ SSHCONF_NONCONF
#تعریف_منسوخ SSHCONF_DEPRECATE
#تعریف_منسوخ SSHCONF_UNSUPPORTED_INT
#تعریف_منسوخ SSHCONF_UNSUPPORTED_STRING
#تعریف_منسوخ SSHCONF_ALIAS
}

/* Returns 1 if a string option is unset or set to "none" or 0 otherwise. */
ساکن صحیح
option_clear_or_none(ثابت حرف *o)
{
	واپس o == تہی || strcasecmp(o, "none") == 0;
}

ساکن خالی
assemble_algorithms(ServerOptions *o)
{
	حرف *all_cipher, *all_mac, *all_kex, *all_کلید, *all_sig;
	حرف *def_cipher, *def_mac, *def_kex, *def_کلید, *def_sig;
	صحیح r;

	all_cipher = cipher_alg_list(',', 0);
	all_mac = mac_alg_list(',');
	all_kex = kex_alg_list(',');
	all_کلید = sshkey_alg_list(0, 0, 1, ',');
	all_sig = sshkey_alg_list(0, 1, 1, ',');
	/* remove unsupported algos from default lists */
	def_cipher = مطابقت_filter_allowlist(KEX_SERVER_ENCRYPT, all_cipher);
	def_mac = مطابقت_filter_allowlist(KEX_SERVER_MAC, all_mac);
	def_kex = مطابقت_filter_allowlist(KEX_SERVER_KEX, all_kex);
	def_کلید = مطابقت_filter_allowlist(KEX_DEFAULT_PK_ALG, all_کلید);
	def_sig = مطابقت_filter_allowlist(SSH_ALLOWED_CA_SIGALGS, all_sig);
#تعریف_کرو ASSEMBLE(what, defaults, all) \
	کرو { \
		اگر ((r = kex_assemble_نام(&o->what, defaults, all)) != 0) \
			fatal_fr(r, "%s", #what); \
	} جب (0)
	ASSEMBLE(ciphers, def_cipher, all_cipher);
	ASSEMBLE(macs, def_mac, all_mac);
	ASSEMBLE(kex_algorithms, def_kex, all_kex);
	ASSEMBLE(hostkeyalgorithms, def_کلید, all_کلید);
	ASSEMBLE(hostbased_accepted_algos, def_کلید, all_کلید);
	ASSEMBLE(pubkey_accepted_algos, def_کلید, all_کلید);
	ASSEMBLE(ca_sign_algorithms, def_sig, all_sig);
#تعریف_منسوخ ASSEMBLE
	آزاد(all_cipher);
	آزاد(all_mac);
	آزاد(all_kex);
	آزاد(all_کلید);
	آزاد(all_sig);
	آزاد(def_cipher);
	آزاد(def_mac);
	آزاد(def_kex);
	آزاد(def_کلید);
	آزاد(def_sig);
}

خالی
servconf_جوڑو_hostkey(ثابت حرف *file, ثابت صحیح سطر,
    ServerOptions *options, ثابت حرف *راستہ, صحیح userprovided)
{
	حرف *apath = derelativise_راستہ(راستہ);

	opt_array_append2(file, سطر, "HostKey",
	    &options->host_کلید_files, &options->host_کلید_file_userprovided,
	    &options->عدد_host_کلید_files, apath, userprovided);
	آزاد(apath);
}

خالی
servconf_جوڑو_hostcert(ثابت حرف *file, ثابت صحیح سطر,
    ServerOptions *options, ثابت حرف *راستہ)
{
	حرف *apath = derelativise_راستہ(راستہ);

	opt_array_append(file, سطر, "HostCertificate",
	    &options->host_cert_files, &options->عدد_host_cert_files, apath);
	آزاد(apath);
}

خالی
fill_default_server_options(ServerOptions *options)
{
	u_int i;

	/* Portable-specific overrides */
#اگر_تعریف_شدہ SKIP_PRIVDROP
	اگر (options->allow_streamlocal_forwarding != -1 &&
	    options->allow_streamlocal_forwarding != FORWARD_DENY)
		logit("StreamlocalForwarding is not supported on this system");
	options->allow_streamlocal_forwarding = 0;
	اگر (options->fwd_opts.gateway_ports != -1 &&
	    options->fwd_opts.gateway_ports != 0)
		logit("GatewayPorts is not supported on this system");
	options->fwd_opts.gateway_ports = 0;
#اگر_ختم

#تعریف_کرو SSHCONF_INT(var, conf, flags, ms, def, cp) \
	اگر (options->var == -1) \
		options->var = def;
#تعریف_کرو SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	اگر (options->var == -1) \
		options->var = def;
#تعریف_کرو SSHCONF_STRING(var, conf, flags, cp)		/* done manually */
#تعریف_کرو SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	/* done manually */
#تعریف_کرو SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	/* done manually */
#تعریف_کرو SSHCONF_NONCONF(funcsuffix)			/* done manually */
#تعریف_کرو SSHCONF_DEPRECATE(conf, flags, opcode)		/*خالی_خانے*/
#تعریف_کرو SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#تعریف_کرو SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	کرو { \
		آزاد(options->var); \
		options->var = تہی; \
	} جب (0);
#تعریف_کرو SSHCONF_ALIAS(old, conf, flags)			/*خالی_خانے*/

	/* XXX maybe use macros here too to force consistency? */

	SSHD_CONFIG_ENTRIES

#تعریف_منسوخ SSHCONF_INT
#تعریف_منسوخ SSHCONF_INTFLAG
#تعریف_منسوخ SSHCONF_STRING
#تعریف_منسوخ SSHCONF_STRARRAY
#تعریف_منسوخ SSHCONF_CUSTOM
#تعریف_منسوخ SSHCONF_NONCONF
#تعریف_منسوخ SSHCONF_DEPRECATE
#تعریف_منسوخ SSHCONF_UNSUPPORTED_INT
#تعریف_منسوخ SSHCONF_UNSUPPORTED_STRING
#تعریف_منسوخ SSHCONF_ALIAS

#اگر_تعریف_شدہ USE_PAM
	اگر (options->pam_service_name == تہی)
		options->pam_service_name = xstrdup(SSHD_PAM_SERVICE);
#اگر_ختم

	اگر (options->عدد_host_کلید_files == 0) {
		/* fill default hostkeys */
		servconf_جوڑو_hostkey("[default]", 0, options,
		    راستہ_HOST_RSA_کلید_FILE, 0);
		servconf_جوڑو_hostkey("[default]", 0, options,
		    راستہ_HOST_ECDSA_کلید_FILE, 0);
		servconf_جوڑو_hostkey("[default]", 0, options,
		    راستہ_HOST_ED25519_کلید_FILE, 0);
		servconf_جوڑو_hostkey("[default]", 0, options,
		    راستہ_HOST_MLDSA44_ED25519_کلید_FILE, 0);
	}
	/* No certificates by default */
	اگر (options->عدد_ports == 0)
		options->ports[options->عدد_ports++] = SSH_DEFAULT_پورٹ;
	اگر (options->listen_addrs == تہی)
		جوڑو_listen_addr(options, تہی, تہی, 0);
	اگر (options->pid_file == تہی)
		options->pid_file = xstrdup(راستہ_SSH_DAEMON_PID_FILE);
	اگر (options->moduli_file == تہی)
		options->moduli_file = xstrdup(راستہ_DH_MODULI);
	اگر (options->xauth_location == تہی)
		options->xauth_location = xstrdup(راستہ_XAUTH);
	اگر (options->log_facility == SYSLOG_FACILITY_NOT_سیٹ)
		options->log_facility = SYSLOG_FACILITY_AUTH;
	اگر (options->log_level == SYSLOG_LEVEL_NOT_سیٹ)
		options->log_level = SYSLOG_LEVEL_INFO;
	اگر (options->permit_user_env == -1) {
		options->permit_user_env = 0;
		options->permit_user_env_allowlist = تہی;
	}
	اگر (options->rekey_حد_بندی == -1)
		options->rekey_حد_بندی = 0;
	اگر (options->rekey_interval == -1)
		options->rekey_interval = 0;
	اگر (options->fwd_opts.gateway_ports == -1)
		options->fwd_opts.gateway_ports = 0;
	اگر (options->max_startups == -1)
		options->max_startups = 100;
	اگر (options->max_startups_شرح == -1)
		options->max_startups_شرح = 30;		/* 30% */
	اگر (options->max_startups_begin == -1)
		options->max_startups_begin = 10;
	اگر (options->فی_ماخذ_masklen_ipv4 == -1)
		options->فی_ماخذ_masklen_ipv4 = 32;
	اگر (options->فی_ماخذ_masklen_ipv6 == -1)
		options->فی_ماخذ_masklen_ipv6 = 128;
	اگر (options->فی_ماخذ_penalty.enabled == -1)
		options->فی_ماخذ_penalty.enabled = 1;
	اگر (options->فی_ماخذ_penalty.max_sources4 == -1)
		options->فی_ماخذ_penalty.max_sources4 = 65536;
	اگر (options->فی_ماخذ_penalty.max_sources6 == -1)
		options->فی_ماخذ_penalty.max_sources6 = 65536;
	اگر (options->فی_ماخذ_penalty.حد_سے_تجاوز_منوال == -1)
		options->فی_ماخذ_penalty.حد_سے_تجاوز_منوال = فی_ماخذ_PENALTY_حد_سے_تجاوز_PERMISSIVE;
	اگر (options->فی_ماخذ_penalty.حد_سے_تجاوز_mode6 == -1)
		options->فی_ماخذ_penalty.حد_سے_تجاوز_mode6 = options->فی_ماخذ_penalty.حد_سے_تجاوز_منوال;
	اگر (options->فی_ماخذ_penalty.penalty_crash < 0.0)
		options->فی_ماخذ_penalty.penalty_crash = 90.0;
	اگر (options->فی_ماخذ_penalty.penalty_grace < 0.0)
		options->فی_ماخذ_penalty.penalty_grace = 10.0;
	اگر (options->فی_ماخذ_penalty.penalty_authfail < 0.0)
		options->فی_ماخذ_penalty.penalty_authfail = 5.0;
	اگر (options->فی_ماخذ_penalty.penalty_invaliduser < 0.0)
		options->فی_ماخذ_penalty.penalty_invaliduser = 5.0;
	اگر (options->فی_ماخذ_penalty.penalty_noauth < 0.0)
		options->فی_ماخذ_penalty.penalty_noauth = 1.0;
	اگر (options->فی_ماخذ_penalty.penalty_refuseconnection < 0.0)
		options->فی_ماخذ_penalty.penalty_refuseconnection = 10.0;
	اگر (options->فی_ماخذ_penalty.penalty_min < 0.0)
		options->فی_ماخذ_penalty.penalty_min = 15.0;
	اگر (options->فی_ماخذ_penalty.penalty_max < 0.0)
		options->فی_ماخذ_penalty.penalty_max = 600.0;
	اگر (options->عدد_authkeys_files == 0) {
		opt_array_append("[default]", 0, "AuthorizedKeysFiles",
		    &options->authorized_کلیدیں_files,
		    &options->عدد_authkeys_files,
		    راستہ_SSH_USER_PERMITTED_کلیدیں);
		opt_array_append("[default]", 0, "AuthorizedKeysFiles",
		    &options->authorized_کلیدیں_files,
		    &options->عدد_authkeys_files,
		    راستہ_SSH_USER_PERMITTED_KEYS2);
	}
	اگر (options->ip_qos_interactive == -1)
		options->ip_qos_interactive = IPTOS_DSCP_EF;
	اگر (options->ip_qos_bulk == -1)
		options->ip_qos_bulk = IPTOS_DSCP_CS0;
	اگر (options->نسخہ_addendum == تہی)
		options->نسخہ_addendum = xstrdup("");
	اگر (options->fwd_opts.streamlocal_bind_نقاب == (منوال_t)-1)
		options->fwd_opts.streamlocal_bind_نقاب = 0177;
	اگر (options->fwd_opts.streamlocal_bind_unlink == -1)
		options->fwd_opts.streamlocal_bind_unlink = 0;
	اگر (options->sk_provider == تہی)
		options->sk_provider = xstrdup("internal");
	اگر (options->sshd_session_راستہ == تہی)
		options->sshd_session_راستہ = xstrdup(راستہ_SSHD_SESSION);
	اگر (options->sshd_auth_راستہ == تہی)
		options->sshd_auth_راستہ = xstrdup(راستہ_SSHD_AUTH);
	اگر (options->pubkey_auth_options == -1) {
		options->pubkey_auth_options = 0;
		options->max_pubkey_ok = DEFAULT_AUTH_FAIL_MAX;
	}
	اگر (options->agent_socket_راستہ == تہی)
		options->agent_socket_راستہ = xstrdup(راستہ_SSH_AGENT_SOCKET_DIR);

	assemble_algorithms(options);

#تعریف_کرو CLEAR_ON_NONE(v) \
	کرو { \
		اگر (option_clear_or_none(v)) { \
			آزاد(v); \
			v = تہی; \
		} \
	} جب(0)
#تعریف_کرو CLEAR_ON_NONE_ARRAY(v, nv, none) \
	کرو { \
		اگر (options->nv == 1 && \
		    strcasecmp(options->v[0], none) == 0) { \
			آزاد(options->v[0]); \
			آزاد(options->v); \
			options->v = تہی; \
			options->nv = 0; \
		} \
	} جب (0)
	CLEAR_ON_NONE(options->pid_file);
	CLEAR_ON_NONE(options->xauth_location);
	CLEAR_ON_NONE(options->banner);
	CLEAR_ON_NONE(options->trusted_user_ca_کلیدیں);
	CLEAR_ON_NONE(options->sk_provider);
	CLEAR_ON_NONE(options->authorized_principals_file);
	CLEAR_ON_NONE(options->adm_forced_command);
	CLEAR_ON_NONE(options->chroot_directory);
	CLEAR_ON_NONE(options->routing_domain);
	CLEAR_ON_NONE(options->host_کلید_agent);
	CLEAR_ON_NONE(options->فی_ماخذ_penalty_exempt);
	CLEAR_ON_NONE(options->agent_socket_راستہ);

	برائے (i = 0; i < options->عدد_host_کلید_files; i++)
		CLEAR_ON_NONE(options->host_کلید_files[i]);
	برائے (i = 0; i < options->عدد_host_cert_files; i++)
		CLEAR_ON_NONE(options->host_cert_files[i]);

	CLEAR_ON_NONE_ARRAY(channel_timeouts, عدد_channel_timeouts, "none");
	CLEAR_ON_NONE_ARRAY(auth_methods, عدد_auth_methods, "any");
	CLEAR_ON_NONE_ARRAY(revoked_کلیدیں_files, عدد_revoked_کلیدیں_files, "none");
	CLEAR_ON_NONE_ARRAY(authorized_کلیدیں_files, عدد_authkeys_files, "none");
#تعریف_منسوخ CLEAR_ON_NONE
#تعریف_منسوخ CLEAR_ON_NONE_ARRAY
}

/* Macros to declare ServerOpCodes enum values */
#تعریف_کرو SSHCONF_INT(var, conf, flags, ms, def, cp)	s##conf,
#تعریف_کرو SSHCONF_INTFLAG(var, conf, flags, def, cp)	s##conf,
#تعریف_کرو SSHCONF_STRING(var, conf, flags, cp)		s##conf,
#تعریف_کرو SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	s##conf,
#تعریف_کرو SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	s##conf,
#تعریف_کرو SSHCONF_NONCONF(funcsuffix)			/*خالی_خانے*/
#تعریف_کرو SSHCONF_DEPRECATE(conf, flags, opcode)		/*خالی_خانے*/
#تعریف_کرو SSHCONF_UNSUPPORTED_INT(var, conf, flags)	/*خالی_خانے*/
#تعریف_کرو SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	/*خالی_خانے*/
#تعریف_کرو SSHCONF_ALIAS(old, conf, flags)			/*خالی_خانے*/

/* Keyword tokens. */
قسمتعریف شمار {
	sBadOption,		/* == unknown option */
	SSHD_CONFIG_ENTRIES
	s_مطابقت, sInclude,
	sDeprecated, sIgnore, sUnsupported
} ServerOpCodes;
#تعریف_منسوخ SSHCONF_INT
#تعریف_منسوخ SSHCONF_INTFLAG
#تعریف_منسوخ SSHCONF_STRING
#تعریف_منسوخ SSHCONF_STRARRAY
#تعریف_منسوخ SSHCONF_CUSTOM
#تعریف_منسوخ SSHCONF_NONCONF
#تعریف_منسوخ SSHCONF_DEPRECATE
#تعریف_منسوخ SSHCONF_UNSUPPORTED_INT
#تعریف_منسوخ SSHCONF_UNSUPPORTED_STRING
#تعریف_منسوخ SSHCONF_ALIAS

#تعریف_کرو SSHCFG_GLOBAL		0x01	/* allowed in main section of config */
#تعریف_کرو SSHCFG_مطابقت		0x02	/* allowed inside a Match section */
#تعریف_کرو SSHCFG_ALL		(SSHCFG_GLOBAL|SSHCFG_مطابقت)
#تعریف_کرو SSHCFG_NEVERMATCH	0x04  /* Match never matches; internal only */
#تعریف_کرو SSHCFG_مطابقت_ONLY	0x08  /* Match only in conditional blocks; internal only */

/* Macros to define keywords[] entries */
#تعریف_کرو SSHCONF_KW(conf, flags)		{ #conf, s##conf, flags },
#تعریف_کرو SSHCONF_INT(var, conf, flags, ms, def, cp)	SSHCONF_KW(conf, flags)
#تعریف_کرو SSHCONF_INTFLAG(var, conf, flags, def, cp)	SSHCONF_KW(conf, flags)
#تعریف_کرو SSHCONF_STRING(var, conf, flags, cp)		SSHCONF_KW(conf, flags)
#تعریف_کرو SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	SSHCONF_KW(conf, flags)
#تعریف_کرو SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	SSHCONF_KW(conf, flags)
#تعریف_کرو SSHCONF_NONCONF(funcsuffix)			/*خالی_خانے*/
#تعریف_کرو SSHCONF_DEPRECATED				sDeprecated
#تعریف_کرو SSHCONF_IGNORE					sIgnore
#تعریف_کرو SSHCONF_DEPRECATE(conf, flags, opcode) \
	{ #conf, opcode, flags },
#تعریف_کرو SSHCONF_UNSUPPORTED_INT(var, conf, flags) \
	{ #conf, sUnsupported, flags },
#تعریف_کرو SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	{ #conf, sUnsupported, flags },
#تعریف_کرو SSHCONF_ALIAS(old, conf, flags) \
	{ #old, s##conf, flags },

/* Textual representation of the tokens. */
ساکن ساخت {
	ثابت حرف *name;
	ServerOpCodes opcode;
	u_int flags;
} keywords[] = {
	SSHD_CONFIG_ENTRIES
	{ "match", s_مطابقت, SSHCFG_ALL },
	{ "include", sInclude, SSHCFG_ALL },
	{ تہی, sBadOption, 0 }
};
#تعریف_منسوخ SSHCONF_INT
#تعریف_منسوخ SSHCONF_INTFLAG
#تعریف_منسوخ SSHCONF_STRING
#تعریف_منسوخ SSHCONF_STRARRAY
#تعریف_منسوخ SSHCONF_CUSTOM
#تعریف_منسوخ SSHCONF_NONCONF
#تعریف_منسوخ SSHCONF_DEPRECATED
#تعریف_منسوخ SSHCONF_IGNORE
#تعریف_منسوخ SSHCONF_DEPRECATE
#تعریف_منسوخ SSHCONF_UNSUPPORTED_INT
#تعریف_منسوخ SSHCONF_UNSUPPORTED_STRING
#تعریف_منسوخ SSHCONF_ALIAS

ساکن ساخت {
	صحیح val;
	حرف *متن;
} tunmode_desc[] = {
	{ SSH_TUNMODE_NO, "no" },
	{ SSH_TUNMODE_POINTOPOINT, "point-to-point" },
	{ SSH_TUNMODE_ETHERNET, "ethernet" },
	{ SSH_TUNMODE_YES, "yes" },
	{ -1, تہی }
};

/* Returns an opcode name from its number */

ساکن ثابت حرف *
lookup_opcode_name(ServerOpCodes رمز)
{
	u_int i;

	برائے (i = 0; keywords[i].name != تہی; i++)
		اگر (keywords[i].opcode == رمز)
			واپس(keywords[i].name);
	واپس "UNKNOWN";
}


/*
 * Returns the number of the token pointed to by cp or sBadOption.
 */

ساکن ServerOpCodes
parse_token(ثابت حرف *cp, ثابت حرف *filename,
	    صحیح linenum, u_int *flags)
{
	u_int i;

	برائے (i = 0; keywords[i].name; i++)
		اگر (strcasecmp(cp, keywords[i].name) == 0) {
			*flags = keywords[i].flags;
			واپس keywords[i].opcode;
		}

	error("%s: line %d: Bad configuration option: %s",
	    filename, linenum, cp);
	واپس sBadOption;
}

حرف *
derelativise_راستہ(ثابت حرف *راستہ)
{
	حرف *expanded, *ret, cwd[PATH_MAX];

	اگر (strcasecmp(راستہ, "none") == 0)
		واپس xstrdup("none");
	expanded = tilde_expand_filename(راستہ, getuid());
	اگر (راستہ_absolute(expanded))
		واپس expanded;
	اگر (getcwd(cwd, حجم(cwd)) == تہی)
		fatal_f("getcwd: %s", strerror(errno));
	xasprintf(&ret, "%s/%s", cwd, expanded);
	آزاد(expanded);
	واپس ret;
}

ساکن خالی
جوڑو_listen_addr(ServerOptions *options, ثابت حرف *addr,
    ثابت حرف *rdomain, صحیح پورٹ)
{
	u_int i;

	اگر (پورٹ > 0)
		جوڑو_one_listen_addr(options, addr, rdomain, پورٹ);
	ورنہ {
		برائے (i = 0; i < options->عدد_ports; i++) {
			جوڑو_one_listen_addr(options, addr, rdomain,
			    options->ports[i]);
		}
	}
}

ساکن خالی
جوڑو_one_listen_addr(ServerOptions *options, ثابت حرف *addr,
    ثابت حرف *rdomain, صحیح پورٹ)
{
	ساخت addrinfo hints, *ai, *aitop;
	حرف strport[NI_MAXSERV];
	صحیح gaierr;
	u_int i;

	/* Find listen_addrs entry for this rdomain */
	برائے (i = 0; i < options->عدد_listen_addrs; i++) {
		اگر (rdomain == تہی && options->listen_addrs[i].rdomain == تہی)
			توڑو;
		اگر (rdomain == تہی || options->listen_addrs[i].rdomain == تہی)
			جاری;
		اگر (strcmp(rdomain, options->listen_addrs[i].rdomain) == 0)
			توڑو;
	}
	اگر (i >= options->عدد_listen_addrs) {
		/* No entry for this rdomain; allocate one */
		اگر (i >= زیادہ_سے_زیادہ_عدد)
			fatal_f("too many listen addresses");
		options->listen_addrs = xrecallocarray(options->listen_addrs,
		    options->عدد_listen_addrs, options->عدد_listen_addrs + 1,
		    حجم(*options->listen_addrs));
		i = options->عدد_listen_addrs++;
		اگر (rdomain != تہی)
			options->listen_addrs[i].rdomain = xstrdup(rdomain);
	}
	/* options->listen_addrs[i] points to the addresses for this rdomain */

	memset(&hints, 0, حجم(hints));
	hints.ai_family = options->پتہ_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = (addr == تہی) ? AI_PASSIVE : 0;
	snprintf(strport, حجم strport, "%d", پورٹ);
	اگر ((gaierr = getaddrinfo(addr, strport, &hints, &aitop)) != 0)
		fatal("bad addr or host: %s (%s)",
		    addr ? addr : "<NULL>",
		    ssh_gai_strerror(gaierr));
	برائے (ai = aitop; ai->ai_next; ai = ai->ai_next)
		;
	ai->ai_next = options->listen_addrs[i].addrs;
	options->listen_addrs[i].addrs = aitop;
}

/* Returns nonzero if the routing domain name is valid */
ساکن صحیح
valid_rdomain(ثابت حرف *name)
{
#اگر defined(HAVE_SYS_VALID_RDOMAIN)
	واپس sys_valid_rdomain(name);
#وگرنہ_اگر defined(__OpenBSD__)
	ثابت حرف *errstr;
	طویل طویل عدد;
	ساخت rt_tableinfo info;
	صحیح mib[6];
	سائز_t miblen = حجم(mib);

	اگر (name == تہی)
		واپس 1;

	عدد = strtonum(name, 0, 255, &errstr);
	اگر (errstr != تہی)
		واپس 0;

	/* Check whether the table actually exists */
	memset(mib, 0, حجم(mib));
	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[4] = NET_RT_جدول;
	mib[5] = (صحیح)عدد;
	اگر (sysctl(mib, 6, &info, &miblen, تہی, 0) == -1)
		واپس 0;

	واپس 1;
#ورنہ /* defined(__OpenBSD__) */
	error("Routing domains are not supported on this platform");
	واپس 0;
#اگر_ختم
}

/*
 * Queue a ListenAddress to be processed once we have all of the Ports
 * and AddressFamily options.
 */
ساکن خالی
قطار_listen_addr(ServerOptions *options, ثابت حرف *addr,
    ثابت حرف *rdomain, صحیح پورٹ)
{
	ساخت queued_listenaddr *qla;

	options->queued_listen_addrs = xrecallocarray(
	    options->queued_listen_addrs,
	    options->عدد_queued_listens, options->عدد_queued_listens + 1,
	    حجم(*options->queued_listen_addrs));
	qla = &options->queued_listen_addrs[options->عدد_queued_listens++];
	qla->addr = xstrdup(addr);
	qla->پورٹ = پورٹ;
	qla->rdomain = rdomain == تہی ? تہی : xstrdup(rdomain);
}

/*
 * Process queued (text) ListenAddress entries.
 */
ساکن خالی
process_queued_listen_addrs(ServerOptions *options)
{
	u_int i;
	ساخت queued_listenaddr *qla;

	اگر (options->عدد_ports == 0)
		options->ports[options->عدد_ports++] = SSH_DEFAULT_پورٹ;
	اگر (options->پتہ_family == -1)
		options->پتہ_family = AF_UNSPEC;

	برائے (i = 0; i < options->عدد_queued_listens; i++) {
		qla = &options->queued_listen_addrs[i];
		جوڑو_listen_addr(options, qla->addr, qla->rdomain, qla->پورٹ);
		آزاد(qla->addr);
		آزاد(qla->rdomain);
	}
	آزاد(options->queued_listen_addrs);
	options->queued_listen_addrs = تہی;
	options->عدد_queued_listens = 0;
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

ساکن صحیح
مطابقت_cfg_سطر_گروہ(ثابت حرف *grps, صحیح سطر, ثابت حرف *user)
{
	صحیح نتیجہ = 0;
	ساخت passwd *pw;

	اگر (user == تہی)
		جاؤ برآمد;

	اگر ((pw = getpwnam(user)) == تہی) {
		debug("Can't match group at line %d because user %.100s does "
		    "not exist", سطر, user);
	} ورنہ اگر (ga_init(pw->pw_name, pw->pw_gid) == 0) {
		debug("Can't Match group because user %.100s not in any group "
		    "at line %d", user, سطر);
	} ورنہ اگر (ga_مطابقت_نمونہ_list(grps) != 1) {
		debug("user %.100s does not match group list %.100s at line %d",
		    user, grps, سطر);
	} ورنہ {
		debug("user %.100s matched group list %.100s at line %d", user,
		    grps, سطر);
		نتیجہ = 1;
	}
برآمد:
	ga_free();
	واپس نتیجہ;
}

ساکن خالی
مطابقت_test_missing_fatal(ثابت حرف *criteria, ثابت حرف *attrib)
{
	fatal("'Match %s' in configuration but '%s' not in connection "
	    "test specification.", criteria, attrib);
}

/*
 * All of the attributes on a single Match line are ANDed together, so we need
 * to check every attribute and set the result to zero if any attribute does
 * not match.
 */
ساکن صحیح
مطابقت_cfg_سطر(ثابت حرف *بھرا_سطر, صحیح *acp, حرف ***avp,
    صحیح سطر, ساخت connection_info *ci)
{
	صحیح نتیجہ = 1, اوصاف = 0, پورٹ;
	حرف *arg, *attrib = تہی, *oattrib;

	اگر (ci == تہی) {
		debug3("checking syntax for 'Match %s' on line %d",
		    بھرا_سطر, سطر);
	} ورنہ {
		debug3("checking match for '%s' user %s%s host %s addr %s "
		    "laddr %s lport %d rdomain %s on line %d", بھرا_سطر,
		    ci->user ? ci->user : "(null)",
		    ci->user_invalid ? " (invalid)" : "",
		    ci->host ? ci->host : "(null)",
		    ci->پتہ ? ci->پتہ : "(null)",
		    ci->laddress ? ci->laddress : "(null)", ci->lport,
		    ci->rdomain ? ci->rdomain : "(null)", سطر);
	}

	جب ((oattrib = argv_اگلا(acp, avp)) != تہی) {
		/* Terminate on comment */
		اگر (*oattrib == '#') {
			argv_consume(acp); /* mark all arguments consumed */
			توڑو;
		}
		attrib = xstrdup(oattrib);
		arg = تہی;
		اوصاف++;
		/* Criterion "all" has no argument and must appear alone */
		اگر (strcasecmp(attrib, "all") == 0) {
			اگر (اوصاف > 1 ||
			    ((arg = argv_اگلا(acp, avp)) != تہی &&
			    *arg != '\0' && *arg != '#')) {
				error("'all' cannot be combined with other "
				    "Match attributes");
				نتیجہ = -1;
				جاؤ برآمد;
			}
			اگر (arg != تہی && *arg == '#')
				argv_consume(acp); /* consume remaining args */
			نتیجہ = 1;
			جاؤ برآمد;
		}
		/* Criterion "invalid-user" also has no argument */
		اگر (strcasecmp(attrib, "invalid-user") == 0) {
			اگر (ci == تہی) {
				نتیجہ = 0;
				جاؤ اگلا;
			}
			اگر (ci->user_invalid == 0)
				نتیجہ = 0;
			ورنہ
				debug("matched invalid-user at line %d", سطر);
			جاؤ اگلا;
		}

		/* Keep this list in sync with below */
		اگر (strprefix(attrib, "user=", 1) != تہی ||
		    strprefix(attrib, "group=", 1) != تہی ||
		    strprefix(attrib, "host=", 1) != تہی ||
		    strprefix(attrib, "address=", 1) != تہی ||
		    strprefix(attrib, "localaddress=", 1) != تہی ||
		    strprefix(attrib, "localport=", 1) != تہی ||
		    strprefix(attrib, "rdomain=", 1) != تہی ||
		    strprefix(attrib, "version=", 1) != تہی) {
			arg = strchr(attrib, '=');
			*(arg++) = '\0';
		} ورنہ {
			arg = argv_اگلا(acp, avp);
		}

		/* All other criteria require an argument */
		اگر (arg == تہی || *arg == '\0' || *arg == '#') {
			error("Missing Match criteria for %s", attrib);
			نتیجہ = -1;
			جاؤ برآمد;
		}
		اگر (strcasecmp(attrib, "user") == 0) {
			اگر (ci == تہی || (ci->test && ci->user == تہی)) {
				نتیجہ = 0;
				جاؤ اگلا;
			}
			اگر (ci->user == تہی)
				مطابقت_test_missing_fatal("User", "user");
			اگر (مطابقت_usergroup_نمونہ_list(ci->user, arg) != 1)
				نتیجہ = 0;
			ورنہ
				debug("user %.100s matched 'User %.100s' at "
				    "line %d", ci->user, arg, سطر);
		} ورنہ اگر (strcasecmp(attrib, "group") == 0) {
			اگر (ci == تہی || (ci->test && ci->user == تہی)) {
				نتیجہ = 0;
				جاؤ اگلا;
			}
			اگر (ci->user == تہی)
				مطابقت_test_missing_fatal("Group", "user");
			انتخاب (مطابقت_cfg_سطر_گروہ(arg, سطر, ci->user)) {
			حالت -1:
				نتیجہ = -1;
				جاؤ برآمد;
			حالت 0:
				نتیجہ = 0;
			}
		} ورنہ اگر (strcasecmp(attrib, "host") == 0) {
			اگر (ci == تہی || (ci->test && ci->host == تہی)) {
				نتیجہ = 0;
				جاؤ اگلا;
			}
			اگر (ci->host == تہی)
				مطابقت_test_missing_fatal("Host", "host");
			اگر (مطابقت_hostname(ci->host, arg) != 1)
				نتیجہ = 0;
			ورنہ
				debug("connection from %.100s matched 'Host "
				    "%.100s' at line %d", ci->host, arg, سطر);
		} ورنہ اگر (strcasecmp(attrib, "address") == 0) {
			اگر (ci == تہی || (ci->test && ci->پتہ == تہی)) {
				اگر (addr_مطابقت_list(تہی, arg) != 0)
					fatal("Invalid Match address argument "
					    "'%s' at line %d", arg, سطر);
				نتیجہ = 0;
				جاؤ اگلا;
			}
			اگر (ci->پتہ == تہی)
				مطابقت_test_missing_fatal("Address", "addr");
			انتخاب (addr_مطابقت_list(ci->پتہ, arg)) {
			حالت 1:
				debug("connection from %.100s matched 'Address "
				    "%.100s' at line %d", ci->پتہ, arg, سطر);
				توڑو;
			حالت 0:
			حالت -1:
				نتیجہ = 0;
				توڑو;
			حالت -2:
				نتیجہ = -1;
				جاؤ برآمد;
			}
		} ورنہ اگر (strcasecmp(attrib, "localaddress") == 0){
			اگر (ci == تہی || (ci->test && ci->laddress == تہی)) {
				اگر (addr_مطابقت_list(تہی, arg) != 0)
					fatal("Invalid Match localaddress "
					    "argument '%s' at line %d", arg,
					    سطر);
				نتیجہ = 0;
				جاؤ اگلا;
			}
			اگر (ci->laddress == تہی)
				مطابقت_test_missing_fatal("LocalAddress",
				    "laddr");
			انتخاب (addr_مطابقت_list(ci->laddress, arg)) {
			حالت 1:
				debug("connection from %.100s matched "
				    "'LocalAddress %.100s' at line %d",
				    ci->laddress, arg, سطر);
				توڑو;
			حالت 0:
			حالت -1:
				نتیجہ = 0;
				توڑو;
			حالت -2:
				نتیجہ = -1;
				جاؤ برآمد;
			}
		} ورنہ اگر (strcasecmp(attrib, "localport") == 0) {
			اگر ((پورٹ = a2port(arg)) == -1) {
				error("Invalid LocalPort '%s' on Match line",
				    arg);
				نتیجہ = -1;
				جاؤ برآمد;
			}
			اگر (ci == تہی || (ci->test && ci->lport == -1)) {
				نتیجہ = 0;
				جاؤ اگلا;
			}
			اگر (ci->lport == 0)
				مطابقت_test_missing_fatal("LocalPort", "lport");
			/* TODO support port lists */
			اگر (پورٹ == ci->lport)
				debug("connection from %.100s matched "
				    "'LocalPort %d' at line %d",
				    ci->laddress, پورٹ, سطر);
			ورنہ
				نتیجہ = 0;
		} ورنہ اگر (strcasecmp(attrib, "rdomain") == 0) {
			اگر (ci == تہی || (ci->test && ci->rdomain == تہی)) {
				نتیجہ = 0;
				جاؤ اگلا;
			}
			اگر (ci->rdomain == تہی)
				مطابقت_test_missing_fatal("RDomain", "rdomain");
			اگر (مطابقت_نمونہ_list(ci->rdomain, arg, 0) != 1)
				نتیجہ = 0;
			ورنہ
				debug("connection RDomain %.100s matched "
				    "'RDomain %.100s' at line %d",
				    ci->rdomain, arg, سطر);
		} ورنہ اگر (strcasecmp(attrib, "version") == 0) {
			اگر (مطابقت_نمونہ_list(SSH_RELEASE, arg, 0) != 1)
				نتیجہ = 0;
			ورنہ
				debug("version %.100s matched "
				    "'version %.100s' at line %d",
				    SSH_RELEASE, arg, سطر);
		} ورنہ {
			error("Unsupported Match attribute %s", oattrib);
			نتیجہ = -1;
			جاؤ برآمد;
		}
 اگلا:
		آزاد(attrib);
		attrib = تہی;
	}
	اگر (اوصاف == 0) {
		error("One or more attributes required for Match");
		واپس -1;
	}
 برآمد:
	اگر (ci != تہی && نتیجہ != -1)
		debug3("match %sfound on line %d", نتیجہ ? "" : "not ", سطر);
	آزاد(attrib);
	واپس نتیجہ;
}

#تعریف_کرو WHITESPACE " \t\r\n"

/* Multistate option parsing */
ساخت multistate {
	حرف *کلید;
	صحیح قدر;
};
ساکن ثابت ساخت multistate multistate_flag[] = {
	{ "yes",			1 },
	{ "no",				0 },
	{ تہی, -1 }
};
ساکن ثابت ساخت multistate multistate_ignore_rhosts[] = {
	{ "yes",			IGNORE_RHOSTS_YES },
	{ "no",				IGNORE_RHOSTS_NO },
	{ "shosts-only",		IGNORE_RHOSTS_SHOSTS },
	{ تہی, -1 }
};
ساکن ثابت ساخت multistate multistate_addressfamily[] = {
	{ "inet",			AF_INET },
	{ "inet6",			AF_INET6 },
	{ "any",			AF_UNSPEC },
	{ تہی, -1 }
};
ساکن ثابت ساخت multistate multistate_permitrootlogin[] = {
	{ "prohibit-password",		PERMIT_NO_PASSWD },
	{ "without-password",		PERMIT_NO_PASSWD },
	{ "forced-commands-only",	PERMIT_FORCED_ONLY },
	{ "yes",			PERMIT_YES },
	{ "no",				PERMIT_NO },
	{ تہی, -1 }
};
ساکن ثابت ساخت multistate multistate_compression[] = {
#اگر_تعریف_شدہ WITH_ZLIB
	{ "yes",			COMP_DELAYED },
	{ "delayed",			COMP_DELAYED },
#اگر_ختم
	{ "no",				COMP_NONE },
	{ تہی, -1 }
};
ساکن ثابت ساخت multistate multistate_gatewayports[] = {
	{ "clientspecified",		2 },
	{ "yes",			1 },
	{ "no",				0 },
	{ تہی, -1 }
};
ساکن ثابت ساخت multistate multistate_tcpfwd[] = {
	{ "yes",			FORWARD_ALLOW },
	{ "all",			FORWARD_ALLOW },
	{ "no",				FORWARD_DENY },
	{ "remote",			FORWARD_REMOTE },
	{ "local",			FORWARD_LOCAL },
	{ تہی, -1 }
};
ساکن ثابت ساخت multistate multistate_keepalives[] = {
	{ "true",			SSH_KEEPALIVES_TRANSPORT },
	{ "false",			SSH_KEEPALIVES_OFF },
	{ "yes",			SSH_KEEPALIVES_TRANSPORT },
	{ "no",				SSH_KEEPALIVES_OFF },
	{ "transport",			SSH_KEEPALIVES_TRANSPORT },
	{ "all",			SSH_KEEPALIVES_ALL },
	{ تہی, -1 }
};
ساکن ثابت ساخت multistate multistate_warnweakcrypto[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "no-pq-kex",			0 },
	{ تہی, -1 }
};

ساکن صحیح
process_server_config_سطر_گہرائی(ServerOptions *options, حرف *سطر,
    ثابت حرف *filename, صحیح linenum, صحیح *activep,
    ساخت connection_info *connectinfo, صحیح *inc_flags, صحیح گہرائی,
    ساخت include_list *includes)
{
	حرف *str, ***chararrayptr, **charptr, *arg, *arg2, *p, *keyword;
	صحیح cmdline = 0, *intptr, قدر, value2, value3, n, پورٹ, oactive, r;
	دوہرا dvalue, *doubleptr = تہی;
	صحیح ca_only = 0, ملا = 0;
	SyslogFacility *log_facility_ptr;
	LogLevel *log_level_ptr;
	ServerOpCodes opcode;
	u_int i, *uintptr, flags = 0;
	سائز_t len;
	طویل طویل val64;
	ثابت ساخت multistate *multistate_ptr;
	ثابت حرف *errstr;
	ساخت include_شے *شے;
	glob_t gbuf;
	حرف **oav = تہی, **av;
	صحیح oac = 0, ac;
	صحیح ret = -1;
	حرف **strs = تہی; /* string array arguments; freed implicitly */
	u_int nstrs = 0;

	/* Strip trailing whitespace. Allow \f (form feed) at EOL only */
	اگر ((len = لڑی_لمبائی(سطر)) == 0)
		واپس 0;
	برائے (len--; len > 0; len--) {
		اگر (strchr(WHITESPACE "\f", سطر[len]) == تہی)
			توڑو;
		سطر[len] = '\0';
	}

	str = سطر;
	اگر ((keyword = strdelim(&str)) == تہی)
		واپس 0;
	/* Ignore leading whitespace */
	اگر (*keyword == '\0')
		keyword = strdelim(&str);
	اگر (!keyword || !*keyword || *keyword == '#')
		واپس 0;
	اگر (str == تہی || *str == '\0') {
		error("%s line %d: no argument after keyword \"%s\"",
		    filename, linenum, keyword);
		واپس -1;
	}
	intptr = تہی;
	charptr = تہی;
	opcode = parse_token(keyword, filename, linenum, &flags);

	اگر (argv_بانٹو(str, &oac, &oav, 1) != 0) {
		error("%s line %d: invalid quotes", filename, linenum);
		واپس -1;
	}
	ac = oac;
	av = oav;

	اگر (activep == تہی) { /* We are processing a command line directive */
		cmdline = 1;
		activep = &cmdline;
	}
	اگر (*activep && opcode != s_مطابقت && opcode != sInclude)
		debug3("%s:%d setting %s %s", filename, linenum, keyword, str);
	اگر (*activep == 0 && !(flags & SSHCFG_مطابقت)) {
		اگر (connectinfo == تہی) {
			fatal("%s line %d: Directive '%s' is not allowed "
			    "within a Match block", filename, linenum, keyword);
		} ورنہ { /* this is a directive we have already processed */
			ret = 0;
			جاؤ برآمد;
		}
	}

	انتخاب (opcode) {
	/* Portable-specific options */
#اگر_تعریف_شدہ USE_PAM
	حالت sUsePAM:
		intptr = &options->use_pam;
		جاؤ parse_flag;
	حالت sPAMServiceName:
		charptr = &options->pam_service_name;
		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0') {
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		}
		اگر (*activep && *charptr == تہی)
			*charptr = xstrdup(arg);
		توڑو;
#اگر_ختم

	/* Standard Options */
	حالت sBadOption:
		جاؤ برآمد;
	حالت s_پورٹ:
		/* ignore ports from configfile if cmdline specifies ports */
		اگر (options->ports_from_cmdline) {
			argv_consume(&ac);
			توڑو;
		}
		اگر (options->عدد_ports >= MAX_PORTS)
			fatal("%s line %d: too many ports.",
			    filename, linenum);
		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: missing port number.",
			    filename, linenum);
		options->ports[options->عدد_ports++] = a2port(arg);
		اگر (options->ports[options->عدد_ports-1] <= 0)
			fatal("%s line %d: Badly formatted port number.",
			    filename, linenum);
		توڑو;

	حالت s_Login_Grace_وقت:
		intptr = &options->login_grace_وقت;
 parse_وقت:
		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: missing time value.",
			    filename, linenum);
		اگر ((قدر = convtime(arg)) == -1)
			fatal("%s line %d: invalid time value.",
			    filename, linenum);
		اگر (*activep && *intptr == -1)
			*intptr = قدر;
		توڑو;

	حالت s_Listen_پتہ:
		arg = argv_اگلا(&ac, &av);
		اگر (arg == تہی || *arg == '\0')
			fatal("%s line %d: missing address",
			    filename, linenum);
		/* check for bare IPv6 address: no "[]" and 2 or more ":" */
		اگر (strchr(arg, '[') == تہی && (p = strchr(arg, ':')) != تہی
		    && strchr(p+1, ':') != تہی) {
			پورٹ = 0;
			p = arg;
		} ورنہ {
			arg2 = تہی;
			p = hpdelim(&arg);
			اگر (p == تہی)
				fatal("%s line %d: bad address:port usage",
				    filename, linenum);
			p = cleanhostname(p);
			اگر (arg == تہی)
				پورٹ = 0;
			ورنہ اگر ((پورٹ = a2port(arg)) <= 0)
				fatal("%s line %d: bad port number",
				    filename, linenum);
		}
		/* Optional routing table */
		arg2 = تہی;
		اگر ((arg = argv_اگلا(&ac, &av)) != تہی) {
			اگر (strcmp(arg, "rdomain") != 0 ||
			    (arg2 = argv_اگلا(&ac, &av)) == تہی)
				fatal("%s line %d: bad ListenAddress syntax",
				    filename, linenum);
			اگر (!valid_rdomain(arg2))
				fatal("%s line %d: bad routing domain",
				    filename, linenum);
		}
		قطار_listen_addr(options, p, arg2, پورٹ);

		توڑو;

	حالت s_پتہ_Family:
		intptr = &options->پتہ_family;
		multistate_ptr = multistate_addressfamily;
 parse_multistate:
		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		قدر = -1;
		برائے (i = 0; multistate_ptr[i].کلید != تہی; i++) {
			اگر (strcasecmp(arg, multistate_ptr[i].کلید) == 0) {
				قدر = multistate_ptr[i].قدر;
				توڑو;
			}
		}
		اگر (قدر == -1)
			fatal("%s line %d: unsupported option \"%s\".",
			    filename, linenum, arg);
		اگر (*activep && *intptr == -1)
			*intptr = قدر;
		توڑو;

	حالت s_Host_کلید:
		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		اگر (*activep) {
			servconf_جوڑو_hostkey(filename, linenum,
			    options, arg, 1);
		}
		توڑو;

	حالت s_Host_کلید_Agent:
		charptr = &options->host_کلید_agent;
		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: missing socket name.",
			    filename, linenum);
		اگر (*activep && *charptr == تہی)
			*charptr = !strcmp(arg, SSH_AUTHSOCKET_ENV_NAME) ?
			    xstrdup(arg) : derelativise_راستہ(arg);
		توڑو;

	حالت sHostCertificate:
		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		اگر (*activep)
			servconf_جوڑو_hostcert(filename, linenum, options, arg);
		توڑو;

	حالت sPidFile:
		charptr = &options->pid_file;
 parse_filename:
		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		اگر (*activep && *charptr == تہی) {
			*charptr = derelativise_راستہ(arg);
			/* increase optional counter */
			اگر (intptr != تہی)
				*intptr = *intptr + 1;
		}
		توڑو;

	حالت sModuliFile:
		charptr = &options->moduli_file;
		جاؤ parse_filename;

	حالت s_Permit_جڑ_Login:
		intptr = &options->permit_جڑ_login;
		multistate_ptr = multistate_permitrootlogin;
		جاؤ parse_multistate;

	حالت sIgnoreRhosts:
		intptr = &options->ignore_rhosts;
		multistate_ptr = multistate_ignore_rhosts;
		جاؤ parse_multistate;

	حالت s_Ignore_User_معلوم_Hosts:
		intptr = &options->ignore_user_معلوم_hosts;
 parse_flag:
		multistate_ptr = multistate_flag;
		جاؤ parse_multistate;

	حالت sHostbasedAuthentication:
		intptr = &options->hostbased_authentication;
		جاؤ parse_flag;

	حالت s_Hostbased_استعمال_کرتا_Name_From_Packet_Only:
		intptr = &options->hostbased_استعمال_کرتا_name_from_packet_only;
		جاؤ parse_flag;

	حالت sHostbasedAcceptedAlgorithms:
		charptr = &options->hostbased_accepted_algos;
		ca_only = 0;
 parse_pubkey_algos:
		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: Missing argument.",
			    filename, linenum);
		اگر (*arg != '-' &&
		    !sshkey_نام_valid2(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg, 1, ca_only))
			fatal("%s line %d: Bad key types '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		اگر (*activep && *charptr == تہی)
			*charptr = xstrdup(arg);
		توڑو;

	حالت s_Host_کلید_Algorithms:
		charptr = &options->hostkeyalgorithms;
		ca_only = 0;
		جاؤ parse_pubkey_algos;

	حالت sCASignatureAlgorithms:
		charptr = &options->ca_sign_algorithms;
		ca_only = 1;
		جاؤ parse_pubkey_algos;

	حالت sPubkeyAuthentication:
		intptr = &options->pubkey_authentication;
		ca_only = 0;
		جاؤ parse_flag;

	حالت sPubkeyAcceptedAlgorithms:
		charptr = &options->pubkey_accepted_algos;
		ca_only = 0;
		جاؤ parse_pubkey_algos;

	حالت sPubkeyAuthOptions:
		intptr = &options->pubkey_auth_options;
		قدر = 0;
		value2 = -1;
		جب ((arg = argv_اگلا(&ac, &av)) != تہی) {
			اگر (strcasecmp(arg, "none") == 0)
				جاری;
			اگر (strcasecmp(arg, "touch-required") == 0)
				قدر |= PUBKEYAUTH_TOUCH_REQUIRED;
			ورنہ اگر (strcasecmp(arg, "verify-required") == 0)
				قدر |= PUBKEYAUTH_VERIFY_REQUIRED;
			ورنہ اگر (strncasecmp(arg, "max-pk-ok:", 10) == 0) {
				value2 = strtonum(arg + 10, 0, 255, &errstr);
				اگر (errstr != تہی) {
					error("%s line %d: bad %s max-pk-ok "
					    "value: %s", filename, linenum,
					keyword, errstr);
					جاؤ برآمد;
				}
			} ورنہ {
				error("%s line %d: unsupported %s option %s",
				    filename, linenum, keyword, arg);
				جاؤ برآمد;
			}
		}
		اگر (*activep && options->pubkey_auth_options == -1) {
			options->pubkey_auth_options = قدر;
			options->max_pubkey_ok = value2;
		}
		توڑو;

#اگر_تعریف_شدہ KRB5
	حالت sKerberosAuthentication:
		intptr = &options->kerberos_authentication;
		جاؤ parse_flag;

	حالت sKerberosOrLocalPasswd:
		intptr = &options->kerberos_or_local_passwd;
		جاؤ parse_flag;

	حالت sKerberosTicketCleanup:
		intptr = &options->kerberos_ticket_cleanup;
		جاؤ parse_flag;
#اگر_تعریف_شدہ USE_AFS
	حالت sKerberosGetAFSToken:
		intptr = &options->kerberos_get_afs_token;
		جاؤ parse_flag;
#اگر_ختم /* USE_AFS */
#اگر_ختم /* KRB5 */

#اگر_تعریف_شدہ GSSAPI
	حالت sGSSAPIAuthentication:
		intptr = &options->gss_authentication;
		جاؤ parse_flag;

	حالت sGSSAPICleanupCredentials:
		intptr = &options->gss_cleanup_creds;
		جاؤ parse_flag;

	حالت sGSSAPIDelegateCredentials:
		intptr = &options->gss_deleg_creds;
		جاؤ parse_flag;

	حالت sGSSAPIStrictAcceptorCheck:
		intptr = &options->gss_strict_acceptor;
		جاؤ parse_flag;
#اگر_ختم /* GSSAPI */

	حالت sPasswordAuthentication:
		intptr = &options->password_authentication;
		جاؤ parse_flag;

	حالت sKbdInteractiveAuthentication:
		intptr = &options->kbd_interactive_authentication;
		جاؤ parse_flag;

	حالت sPrintMotd:
		intptr = &options->print_motd;
		جاؤ parse_flag;

#اگر_غیر_تعریف_شدہ DISABLE_LASTLOG
	حالت s_Print_آخری_Log:
		intptr = &options->print_lastlog;
		جاؤ parse_flag;
#اگر_ختم

	حالت sX11Forwarding:
		intptr = &options->x11_forwarding;
		جاؤ parse_flag;

	حالت s_X11_Display_انحراف:
		intptr = &options->x11_display_انحراف;
 parse_int:
		arg = argv_اگلا(&ac, &av);
		اگر ((errstr = atoi_err(arg, &قدر)) != تہی)
			fatal("%s line %d: %s integer value %s.",
			    filename, linenum, keyword, errstr);
		اگر (*activep && *intptr == -1)
			*intptr = قدر;
		توڑو;

	حالت sX11UseLocalhost:
		intptr = &options->x11_use_localhost;
		جاؤ parse_flag;

	حالت sXAuthLocation:
		charptr = &options->xauth_location;
		جاؤ parse_filename;

	حالت sPermitTTY:
		intptr = &options->permit_tty;
		جاؤ parse_flag;

	حالت sPermitUserRC:
		intptr = &options->permit_user_rc;
		جاؤ parse_flag;

	حالت sStrictModes:
		intptr = &options->strict_modes;
		جاؤ parse_flag;

	حالت sTCPKeepAlive:
		intptr = &options->tcp_keep_alive;
		multistate_ptr = multistate_keepalives;
		جاؤ parse_multistate;

	حالت s_Permit_خالی_خانے_Passwords:
		intptr = &options->permit_خالی_خانے_passwd;
		جاؤ parse_flag;

	حالت sPermitUserEnvironment:
		intptr = &options->permit_user_env;
		charptr = &options->permit_user_env_allowlist;
		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		قدر = 0;
		p = تہی;
		اگر (strcmp(arg, "yes") == 0)
			قدر = 1;
		ورنہ اگر (strcmp(arg, "no") == 0)
			قدر = 0;
		ورنہ {
			/* Pattern-list specified */
			قدر = 1;
			p = xstrdup(arg);
		}
		اگر (*activep && *intptr == -1) {
			*intptr = قدر;
			*charptr = p;
			p = تہی;
		}
		آزاد(p);
		توڑو;

	حالت sCompression:
		intptr = &options->compression;
		multistate_ptr = multistate_compression;
		جاؤ parse_multistate;

	حالت s_Rekey_حد_بندی:
		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		اگر (strcmp(arg, "default") == 0) {
			val64 = 0;
		} ورنہ {
			اگر (جائزہ_scaled(arg, &val64) == -1)
				fatal("%.200s line %d: Bad %s number '%s': %s",
				    filename, linenum, keyword,
				    arg, strerror(errno));
			اگر (val64 != 0 && val64 < 16)
				fatal("%.200s line %d: %s too small",
				    filename, linenum, keyword);
		}
		اگر (*activep && options->rekey_حد_بندی == -1)
			options->rekey_حد_بندی = val64;
		اگر (ac != 0) { /* optional rekey interval present */
			اگر (strcmp(av[0], "none") == 0) {
				(خالی)argv_اگلا(&ac, &av);	/* discard */
				توڑو;
			}
			intptr = &options->rekey_interval;
			جاؤ parse_وقت;
		}
		توڑو;

	حالت sGatewayPorts:
		intptr = &options->fwd_opts.gateway_ports;
		multistate_ptr = multistate_gatewayports;
		جاؤ parse_multistate;

	حالت sUseDNS:
		intptr = &options->use_dns;
		جاؤ parse_flag;

	حالت sSyslogFacility:
		log_facility_ptr = &options->log_facility;
		arg = argv_اگلا(&ac, &av);
		قدر = log_facility_نمبر(arg);
		اگر (قدر == SYSLOG_FACILITY_NOT_سیٹ)
			fatal("%.200s line %d: unsupported log facility '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
		اگر (*log_facility_ptr == -1)
			*log_facility_ptr = (SyslogFacility) قدر;
		توڑو;

	حالت sLogLevel:
		log_level_ptr = &options->log_level;
		arg = argv_اگلا(&ac, &av);
		قدر = log_level_نمبر(arg);
		اگر (قدر == SYSLOG_LEVEL_NOT_سیٹ)
			fatal("%.200s line %d: unsupported log level '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
		اگر (*activep && *log_level_ptr == -1)
			*log_level_ptr = (LogLevel) قدر;
		توڑو;

	حالت sLogVerbose:
		ملا = options->عدد_log_verbose == 0;
		جب ((arg = argv_اگلا(&ac, &av)) != تہی) {
			اگر (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				جاؤ برآمد;
			}
			/* Allow "none" only in first position */
			اگر (strcasecmp(arg, "none") == 0) {
				اگر (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					جاؤ برآمد;
				}
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		اگر (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		اگر (ملا && *activep) {
			options->log_verbose = strs;
			options->عدد_log_verbose = nstrs;
			strs = تہی; /* transferred */
			nstrs = 0;
		}
		توڑو;

	حالت sAllowTcpForwarding:
		intptr = &options->allow_tcp_forwarding;
		multistate_ptr = multistate_tcpfwd;
		جاؤ parse_multistate;

	حالت s_Allow_دھارا_Local_Forwarding:
		intptr = &options->allow_streamlocal_forwarding;
		multistate_ptr = multistate_tcpfwd;
		جاؤ parse_multistate;

	حالت sAllowAgentForwarding:
		intptr = &options->allow_agent_forwarding;
		جاؤ parse_flag;

	حالت s_Agent_Socket_راستہ:
		charptr = &options->agent_socket_راستہ;
		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: missing path.", filename, linenum);
		اگر (لڑی_موازنہ(arg, "shared:", 7) == 0) {
			/* Shared paths must be absolute */
			اگر (arg[7] != '/') {
				fatal("%s line %d: invalid shared path.",
				    filename, linenum);
			}
		} ورنہ اگر (لڑی_موازنہ(arg, "user:", 5) == 0) {
			/* User paths must not be empty */
			اگر (arg[5] == '\0') {
				fatal("%s line %d: invalid user path.",
				    filename, linenum);
			}
		} ورنہ اگر (strcmp(arg, "none") != 0)
			fatal("%s line %d: invalid path.", filename, linenum);
		اگر (*activep && *charptr == تہی)
			*charptr = xstrdup(arg);
		توڑو;

	حالت sDisableForwarding:
		intptr = &options->disable_forwarding;
		جاؤ parse_flag;

	حالت sAllowUsers:
		chararrayptr = &options->allow_users;
		uintptr = &options->عدد_allow_users;
 parse_allowdenyusers:
		/* XXX appends to list; doesn't respect first-match-wins */
		جب ((arg = argv_اگلا(&ac, &av)) != تہی) {
			اگر (*arg == '\0' ||
			    مطابقت_user(تہی, تہی, تہی, arg) == -1)
				fatal("%s line %d: invalid %s pattern: \"%s\"",
				    filename, linenum, keyword, arg);
			ملا = 1;
			اگر (!*activep)
				جاری;
			opt_array_append(filename, linenum, keyword,
			    chararrayptr, uintptr, arg);
		}
		اگر (!ملا) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		توڑو;

	حالت sDenyUsers:
		chararrayptr = &options->deny_users;
		uintptr = &options->عدد_deny_users;
		جاؤ parse_allowdenyusers;

	حالت sAllowGroups:
		chararrayptr = &options->allow_groups;
		uintptr = &options->عدد_allow_groups;
		/* XXX appends to list; doesn't respect first-match-wins */
 parse_allowdenygroups:
		جب ((arg = argv_اگلا(&ac, &av)) != تہی) {
			اگر (*arg == '\0')
				fatal("%s line %d: empty %s pattern",
				    filename, linenum, keyword);
			ملا = 1;
			اگر (!*activep)
				جاری;
			opt_array_append(filename, linenum, keyword,
			    chararrayptr, uintptr, arg);
		}
		اگر (!ملا) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		توڑو;

	حالت sDenyGroups:
		chararrayptr = &options->deny_groups;
		uintptr = &options->عدد_deny_groups;
		جاؤ parse_allowdenygroups;

	حالت sCiphers:
		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		اگر (*arg != '-' &&
		    !ciphers_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 cipher spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		اگر (options->ciphers == تہی)
			options->ciphers = xstrdup(arg);
		توڑو;

	حالت sMacs:
		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		اگر (*arg != '-' &&
		    !mac_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 mac spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		اگر (options->macs == تہی)
			options->macs = xstrdup(arg);
		توڑو;

	حالت sKexAlgorithms:
		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		اگر (*arg != '-' &&
		    !kex_نام_valid(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 KexAlgorithms '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		اگر (options->kex_algorithms == تہی)
			options->kex_algorithms = xstrdup(arg);
		توڑو;

	حالت sSubsystem:
		اگر ((arg = argv_اگلا(&ac, &av)) == تہی || *arg == '\0' ||
		   ((arg2 = argv_اگلا(&ac, &av)) == تہی || *arg2 == '\0'))
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		اگر (!*activep) {
			argv_consume(&ac);
			توڑو;
		}
		ملا = 0;
		برائے (i = 0; i < options->عدد_subsystems; i++) {
			اگر (strcmp(arg, options->subsystem_name[i]) == 0) {
				ملا = 1;
				توڑو;
			}
		}
		اگر (ملا) {
			debug("%s line %d: Subsystem '%s' already defined.",
			    filename, linenum, arg);
			argv_consume(&ac);
			توڑو;
		}
		options->subsystem_name = xrecallocarray(
		    options->subsystem_name, options->عدد_subsystems,
		    options->عدد_subsystems + 1,
		    حجم(*options->subsystem_name));
		options->subsystem_command = xrecallocarray(
		    options->subsystem_command, options->عدد_subsystems,
		    options->عدد_subsystems + 1,
		    حجم(*options->subsystem_command));
		options->subsystem_دلائل = xrecallocarray(
		    options->subsystem_دلائل, options->عدد_subsystems,
		    options->عدد_subsystems + 1,
		    حجم(*options->subsystem_دلائل));
		options->subsystem_name[options->عدد_subsystems] = xstrdup(arg);
		options->subsystem_command[options->عدد_subsystems] =
		    xstrdup(arg2);
		/* Collect arguments (separate to executable) */
		arg = argv_assemble(1, &arg2); /* quote command correctly */
		arg2 = argv_assemble(ac, av); /* rest of command */
		xasprintf(&options->subsystem_دلائل[options->عدد_subsystems],
		    "%s%s%s", arg, *arg2 == '\0' ? "" : " ", arg2);
		آزاد(arg2);
		آزاد(arg);
		argv_consume(&ac);
		options->عدد_subsystems++;
		توڑو;

	حالت sMaxStartups:
		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		/* begin:rate:max */
		اگر ((n = لڑی_سے_پڑھو(arg, "%d:%d:%d",
		    &قدر, &value2, &value3)) == 3) {
			اگر (قدر > value3 || value2 > 100 || value2 < 1)
				fatal("%s line %d: Invalid %s spec.",
				    filename, linenum, keyword);
		} ورنہ اگر (n == 1) {
			value3 = قدر;
			value2 = -1;
		} ورنہ {
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		}
		اگر (قدر <= 0 || value3 <= 0)
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		اگر (*activep && options->max_startups == -1) {
			options->max_startups_begin = قدر;
			options->max_startups_شرح = value2;
			options->max_startups = value3;
		}
		توڑو;

	حالت s_فی_ماخذ_Net_بلاک_سائز:
		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		انتخاب (n = لڑی_سے_پڑھو(arg, "%d:%d", &قدر, &value2)) {
		حالت 2:
			اگر (value2 < 0 || value2 > 128)
				n = -1;
			/* FALLTHROUGH */
		حالت 1:
			اگر (قدر < 0 || قدر > 32)
				n = -1;
		}
		اگر (n != 1 && n != 2)
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		اگر (*activep && options->فی_ماخذ_masklen_ipv4 == -1) {
			options->فی_ماخذ_masklen_ipv4 = قدر;
			اگر (n == 2)
				options->فی_ماخذ_masklen_ipv6 = value2;
		}
		توڑو;

	حالت s_فی_ماخذ_Max_Startups:
		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		اگر (strcmp(arg, "none") == 0) { /* no limit */
			قدر = زیادہ_سے_زیادہ_عدد;
		} ورنہ {
			اگر ((errstr = atoi_err(arg, &قدر)) != تہی)
				fatal("%s line %d: %s integer value %s.",
				    filename, linenum, keyword, errstr);
		}
		اگر (*activep && options->فی_ماخذ_max_startups == -1)
			options->فی_ماخذ_max_startups = قدر;
		توڑو;

	حالت s_فی_ماخذ_Penalty_Exempt_List:
		charptr = &options->فی_ماخذ_penalty_exempt;
		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		اگر (addr_مطابقت_list(تہی, arg) != 0) {
			fatal("%s line %d: keyword %s "
			    "invalid address argument.",
			    filename, linenum, keyword);
		}
		اگر (*activep && *charptr == تہی)
			*charptr = xstrdup(arg);
		توڑو;

	حالت s_فی_ماخذ_Penalties:
		جب ((arg = argv_اگلا(&ac, &av)) != تہی) {
			ثابت حرف *q = تہی;

			ملا = 1;
			intptr = تہی;
			doubleptr = تہی;
			قدر = -1;
			value2 = 0;
			/* Allow no/yes only in first position */
			اگر (strcasecmp(arg, "no") == 0 ||
			    (value2 = (strcasecmp(arg, "yes") == 0))) {
				اگر (ac > 0) {
					fatal("%s line %d: keyword %s \"%s\" "
					    "argument must appear alone.",
					    filename, linenum, keyword, arg);
				}
				اگر (*activep &&
				    options->فی_ماخذ_penalty.enabled == -1)
					options->فی_ماخذ_penalty.enabled = value2;
				جاری;
			} ورنہ اگر ((q = strprefix(arg, "crash:", 0)) != تہی) {
				doubleptr = &options->فی_ماخذ_penalty.penalty_crash;
			} ورنہ اگر ((q = strprefix(arg, "authfail:", 0)) != تہی) {
				doubleptr = &options->فی_ماخذ_penalty.penalty_authfail;
			} ورنہ اگر ((q = strprefix(arg, "invaliduser:", 0)) != تہی) {
				doubleptr = &options->فی_ماخذ_penalty.penalty_invaliduser;
			} ورنہ اگر ((q = strprefix(arg, "noauth:", 0)) != تہی) {
				doubleptr = &options->فی_ماخذ_penalty.penalty_noauth;
			} ورنہ اگر ((q = strprefix(arg, "grace-exceeded:", 0)) != تہی) {
				doubleptr = &options->فی_ماخذ_penalty.penalty_grace;
			} ورنہ اگر ((q = strprefix(arg, "refuseconnection:", 0)) != تہی) {
				doubleptr = &options->فی_ماخذ_penalty.penalty_refuseconnection;
			} ورنہ اگر ((q = strprefix(arg, "max:", 0)) != تہی) {
				doubleptr = &options->فی_ماخذ_penalty.penalty_max;
			} ورنہ اگر ((q = strprefix(arg, "min:", 0)) != تہی) {
				doubleptr = &options->فی_ماخذ_penalty.penalty_min;
			} ورنہ اگر ((q = strprefix(arg, "max-sources4:", 0)) != تہی) {
				intptr = &options->فی_ماخذ_penalty.max_sources4;
				اگر ((errstr = atoi_err(q, &قدر)) != تہی)
					fatal("%s line %d: %s value %s.",
					    filename, linenum, keyword, errstr);
			} ورنہ اگر ((q = strprefix(arg, "max-sources6:", 0)) != تہی) {
				intptr = &options->فی_ماخذ_penalty.max_sources6;
				اگر ((errstr = atoi_err(q, &قدر)) != تہی)
					fatal("%s line %d: %s value %s.",
					    filename, linenum, keyword, errstr);
			} ورنہ اگر (strcmp(arg, "overflow:deny-all") == 0) {
				intptr = &options->فی_ماخذ_penalty.حد_سے_تجاوز_منوال;
				قدر = فی_ماخذ_PENALTY_حد_سے_تجاوز_DENY_ALL;
			} ورنہ اگر (strcmp(arg, "overflow:permissive") == 0) {
				intptr = &options->فی_ماخذ_penalty.حد_سے_تجاوز_منوال;
				قدر = فی_ماخذ_PENALTY_حد_سے_تجاوز_PERMISSIVE;
			} ورنہ اگر (strcmp(arg, "overflow6:deny-all") == 0) {
				intptr = &options->فی_ماخذ_penalty.حد_سے_تجاوز_mode6;
				قدر = فی_ماخذ_PENALTY_حد_سے_تجاوز_DENY_ALL;
			} ورنہ اگر (strcmp(arg, "overflow6:permissive") == 0) {
				intptr = &options->فی_ماخذ_penalty.حد_سے_تجاوز_mode6;
				قدر = فی_ماخذ_PENALTY_حد_سے_تجاوز_PERMISSIVE;
			} ورنہ {
				fatal("%s line %d: unsupported %s keyword %s",
				    filename, linenum, keyword, arg);
			}

			اگر (doubleptr != تہی) {
				اگر ((dvalue = convtime_double(q)) < 0) {
					fatal("%s line %d: invalid %s time value.",
					    filename, linenum, keyword);
				}
				اگر (*activep && *doubleptr < 0.0) {
					*doubleptr = dvalue;
					options->فی_ماخذ_penalty.enabled = 1;
				}
			} ورنہ اگر (intptr != تہی) {
				اگر (*activep && *intptr == -1) {
					*intptr = قدر;
					options->فی_ماخذ_penalty.enabled = 1;
				}
			} ورنہ {
				fatal_f("%s line %d: internal error",
				    filename, linenum);
			}
		}
		اگر (!ملا) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		توڑو;

	حالت sMaxAuthTries:
		intptr = &options->max_authtries;
		جاؤ parse_int;

	حالت sMaxSessions:
		intptr = &options->max_sessions;
		جاؤ parse_int;

	حالت sBanner:
		charptr = &options->banner;
		جاؤ parse_filename;

	/*
	 * These options can contain %X options expanded at
	 * connect time, so that you can specify paths like:
	 *
	 * AuthorizedKeysFile	/etc/ssh_keys/%u
	 */
	حالت s_Authorized_کلیدیں_File:
		uintptr = &options->عدد_authkeys_files;
		chararrayptr = &options->authorized_کلیدیں_files;
 parse_filenames:
		ملا = *uintptr == 0;
		جب ((arg = argv_اگلا(&ac, &av)) != تہی) {
			اگر (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				جاؤ برآمد;
			}
			/* Allow "none" only in first position */
			اگر (strcasecmp(arg, "none") == 0) {
				اگر (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					جاؤ برآمد;
				}
			}
			arg2 = tilde_expand_filename(arg, getuid());
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg2);
			آزاد(arg2);
		}
		اگر (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		اگر (ملا && *activep) {
			*chararrayptr = strs;
			*uintptr = nstrs;
			strs = تہی; /* transferred */
			nstrs = 0;
		}
		توڑو;

	حالت sAuthorizedPrincipalsFile:
		charptr = &options->authorized_principals_file;
		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		اگر (*activep && *charptr == تہی) {
			*charptr = tilde_expand_filename(arg, getuid());
			/* increase optional counter */
			اگر (intptr != تہی)
				*intptr = *intptr + 1;
		}
		توڑو;

	حالت sClientAliveInterval:
		intptr = &options->client_alive_interval;
		جاؤ parse_وقت;

	حالت s_Client_Alive_گنتی_Max:
		intptr = &options->client_alive_گنتی_max;
		جاؤ parse_int;

	حالت sAcceptEnv:
		/* XXX appends to list; doesn't respect first-match-wins */
		جب ((arg = argv_اگلا(&ac, &av)) != تہی) {
			اگر (*arg == '\0' || strchr(arg, '=') != تہی)
				fatal("%s line %d: Invalid environment name.",
				    filename, linenum);
			ملا = 1;
			اگر (!*activep)
				جاری;
			opt_array_append(filename, linenum, keyword,
			    &options->accept_env, &options->عدد_accept_env,
			    arg);
		}
		اگر (!ملا) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		توڑو;

	حالت s_سیٹ_Env:
		ملا = options->عدد_setenv == 0;
		جب ((arg = argv_اگلا(&ac, &av)) != تہی) {
			اگر (*arg == '\0' || strchr(arg, '=') == تہی)
				fatal("%s line %d: Invalid environment.",
				    filename, linenum);
			اگر (lookup_setenv_اندر_list(arg, strs, nstrs) != تہی) {
				debug2("%s line %d: ignoring duplicate env "
				    "name \"%.64s\"", filename, linenum, arg);
				جاری;
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		اگر (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		اگر (ملا && *activep) {
			options->setenv = strs;
			options->عدد_setenv = nstrs;
			strs = تہی; /* transferred */
			nstrs = 0;
		}
		توڑو;

	حالت sPermitTunnel:
		intptr = &options->permit_tun;
		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		قدر = -1;
		برائے (i = 0; tunmode_desc[i].val != -1; i++)
			اگر (strcmp(tunmode_desc[i].متن, arg) == 0) {
				قدر = tunmode_desc[i].val;
				توڑو;
			}
		اگر (قدر == -1)
			fatal("%s line %d: bad %s argument %s",
			    filename, linenum, keyword, arg);
		اگر (*activep && *intptr == -1)
			*intptr = قدر;
		توڑو;

	حالت sInclude:
		اگر (cmdline) {
			fatal("Include directive not supported as a "
			    "command-line option");
		}
		قدر = 0;
		جب ((arg2 = argv_اگلا(&ac, &av)) != تہی) {
			اگر (*arg2 == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				جاؤ برآمد;
			}
			قدر++;
			ملا = 0;
			اگر (*arg2 != '/' && *arg2 != '~') {
				xasprintf(&arg, "%s/%s", SSHDIR, arg2);
			} ورنہ
				arg = xstrdup(arg2);

			/*
			 * Don't let included files clobber the containing
			 * file's Match state.
			 */
			oactive = *activep;

			/* consult cache of include files */
			TAILQ_FOREACH(شے, includes, اندراج_2) {
				اگر (strcmp(شے->selector, arg) != 0)
					جاری;
				اگر (شے->filename != تہی) {
					parse_server_config_گہرائی(options,
					    شے->filename, شے->contents,
					    includes, connectinfo,
					    (*inc_flags & SSHCFG_مطابقت_ONLY
					        ? SSHCFG_مطابقت_ONLY : (oactive
					            ? 0 : SSHCFG_NEVERMATCH)),
					    activep, گہرائی + 1);
				}
				ملا = 1;
				*activep = oactive;
			}
			اگر (ملا != 0) {
				آزاد(arg);
				جاری;
			}

			/* requested glob was not in cache */
			debug2("%s line %d: new include %s",
			    filename, linenum, arg);
			اگر ((r = glob(arg, 0, تہی, &gbuf)) != 0) {
				اگر (r != GLOB_NOMATCH) {
					fatal("%s line %d: include \"%s\" glob "
					    "failed", filename, linenum, arg);
				}
				/*
				 * If no entry matched then record a
				 * placeholder to skip later glob calls.
				 */
				debug2("%s line %d: no match for %s",
				    filename, linenum, arg);
				شے = xcalloc(1, حجم(*شے));
				شے->selector = xstrdup(arg);
				TAILQ_INSERT_TAIL(includes,
				    شے, اندراج_2);
			}
			اگر (gbuf.gl_pathc > زیادہ_سے_زیادہ_عدد)
				fatal_f("too many glob results");
			برائے (n = 0; n < (صحیح)gbuf.gl_pathc; n++) {
				debug2("%s line %d: including %s",
				    filename, linenum, gbuf.gl_pathv[n]);
				شے = xcalloc(1, حجم(*شے));
				شے->selector = xstrdup(arg);
				شے->filename = xstrdup(gbuf.gl_pathv[n]);
				اگر ((شے->contents = sshbuf_new()) == تہی)
					fatal_f("sshbuf_new failed");
				بھرو_server_config(شے->filename,
				    شے->contents);
				parse_server_config_گہرائی(options,
				    شے->filename, شے->contents,
				    includes, connectinfo,
				    (*inc_flags & SSHCFG_مطابقت_ONLY
				        ? SSHCFG_مطابقت_ONLY : (oactive
				            ? 0 : SSHCFG_NEVERMATCH)),
				    activep, گہرائی + 1);
				*activep = oactive;
				TAILQ_INSERT_TAIL(includes, شے, اندراج_2);
			}
			globfree(&gbuf);
			آزاد(arg);
		}
		اگر (قدر == 0) {
			fatal("%s line %d: %s missing filename argument",
			    filename, linenum, keyword);
		}
		توڑو;

	حالت s_مطابقت:
		اگر (cmdline)
			fatal("Match directive not supported as a command-line "
			    "option");
		قدر = مطابقت_cfg_سطر(str, &ac, &av, linenum,
		    (*inc_flags & SSHCFG_NEVERMATCH ? تہی : connectinfo));
		اگر (قدر < 0)
			fatal("%s line %d: Bad Match condition", filename,
			    linenum);
		*activep = (*inc_flags & SSHCFG_NEVERMATCH) ? 0 : قدر;
		/*
		 * The MATCH_ONLY flag is applicable only until the first
		 * match block.
		 */
		*inc_flags &= ~SSHCFG_مطابقت_ONLY;
		توڑو;

	حالت sPermitListen:
	حالت sPermitOpen:
		اگر (opcode == sPermitListen) {
			uintptr = &options->عدد_permitted_listens;
			chararrayptr = &options->permitted_listens;
		} ورنہ {
			uintptr = &options->عدد_permitted_opens;
			chararrayptr = &options->permitted_opens;
		}
		ملا = *uintptr == 0;
		جب ((arg = argv_اگلا(&ac, &av)) != تہی) {
			اگر (strcmp(arg, "any") == 0 ||
			    strcmp(arg, "none") == 0) {
				اگر (nstrs != 0) {
					fatal("%s line %d: %s must appear "
					    "alone on a %s line.",
					    filename, linenum, arg, keyword);
				}
				opt_array_append(filename, linenum, keyword,
				    &strs, &nstrs, arg);
				جاری;
			}

			اگر (opcode == sPermitListen &&
			    strchr(arg, ':') == تہی) {
				/*
				 * Allow bare port number for PermitListen
				 * to indicate a wildcard listen host.
				 */
				xasprintf(&arg2, "*:%s", arg);
			} ورنہ {
				arg2 = xstrdup(arg);
				p = hpdelim(&arg);
				اگر (p == تہی) {
					fatal("%s line %d: %s missing host",
					    filename, linenum, keyword);
				}
				p = cleanhostname(p);
			}
			اگر (arg == تہی ||
			    ((پورٹ = permitopen_پورٹ(arg)) < 0)) {
				fatal("%s line %d: %s bad port number",
				    filename, linenum, keyword);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg2);
			آزاد(arg2);
		}
		اگر (nstrs == 0) {
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		}
		اگر (ملا && *activep) {
			*chararrayptr = strs;
			*uintptr = nstrs;
			strs = تہی; /* transferred */
			nstrs = 0;
		}
		توڑو;

	حالت sForceCommand:
		اگر (str == تہی || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		اگر (*activep && options->adm_forced_command == تہی)
			options->adm_forced_command = xstrdup(str + len);
		argv_consume(&ac);
		توڑو;

	حالت sChrootDirectory:
		charptr = &options->chroot_directory;

		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		اگر (*activep && *charptr == تہی)
			*charptr = xstrdup(arg);
		توڑو;

	حالت sTrustedUserCAKeys:
		charptr = &options->trusted_user_ca_کلیدیں;
		جاؤ parse_filename;

	حالت s_Revoked_کلیدیں:
		uintptr = &options->عدد_revoked_کلیدیں_files;
		chararrayptr = &options->revoked_کلیدیں_files;
		جاؤ parse_filenames;

	حالت s_Security_کلید_Provider:
		charptr = &options->sk_provider;
		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		اگر (*activep && *charptr == تہی) {
			*charptr = strcasecmp(arg, "internal") == 0 ?
			    xstrdup(arg) : derelativise_راستہ(arg);
			/* increase optional counter */
			اگر (intptr != تہی)
				*intptr = *intptr + 1;
		}
		توڑو;

	حالت sIPQoS:
		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		اگر ((قدر = parse_ipqos(arg)) == -1)
			fatal("%s line %d: Bad %s value: %s",
			    filename, linenum, keyword, arg);
		اگر (قدر == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			قدر = زیادہ_سے_زیادہ_عدد;
		}
		arg = argv_اگلا(&ac, &av);
		اگر (arg == تہی)
			value2 = قدر;
		ورنہ اگر ((value2 = parse_ipqos(arg)) == -1)
			fatal("%s line %d: Bad %s value: %s",
			    filename, linenum, keyword, arg);
		اگر (value2 == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			value2 = زیادہ_سے_زیادہ_عدد;
		}
		اگر (*activep && options->ip_qos_interactive == -1) {
			options->ip_qos_interactive = قدر;
			options->ip_qos_bulk = value2;
		}
		توڑو;

	حالت s_نسخہ_Addendum:
		اگر (str == تہی || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		اگر (strchr(str + len, '\r') != تہی) {
			fatal("%.200s line %d: Invalid %s argument",
			    filename, linenum, keyword);
		}
		اگر ((arg = strchr(سطر, '#')) != تہی) {
			*arg = '\0';
			rtrim(سطر);
		}
		اگر (*activep && options->نسخہ_addendum == تہی) {
			اگر (strcasecmp(str + len, "none") == 0)
				options->نسخہ_addendum = xstrdup("");
			ورنہ
				options->نسخہ_addendum = xstrdup(str + len);
		}
		argv_consume(&ac);
		توڑو;

	حالت s_Authorized_کلیدیں_Command:
		charptr = &options->authorized_کلیدیں_command;
 parse_command:
		len = strspn(str, WHITESPACE);
		اگر (str[len] != '/' && strcasecmp(str + len, "none") != 0) {
			fatal("%.200s line %d: %s must be an absolute path",
			    filename, linenum, keyword);
		}
		اگر (*activep && *charptr == تہی)
			*charptr = xstrdup(str + len);
		argv_consume(&ac);
		توڑو;

	حالت s_Authorized_کلیدیں_Command_User:
		charptr = &options->authorized_کلیدیں_command_user;
 parse_localuser:
		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0') {
			fatal("%s line %d: missing %s argument.",
			    filename, linenum, keyword);
		}
		اگر (*activep && *charptr == تہی)
			*charptr = xstrdup(arg);
		توڑو;

	حالت sAuthorizedPrincipalsCommand:
		charptr = &options->authorized_principals_command;
		جاؤ parse_command;

	حالت sAuthorizedPrincipalsCommandUser:
		charptr = &options->authorized_principals_command_user;
		جاؤ parse_localuser;

	حالت sAuthenticationMethods:
		ملا = options->عدد_auth_methods == 0;
		قدر = 0; /* seen "any" pseudo-method */
		جب ((arg = argv_اگلا(&ac, &av)) != تہی) {
			اگر (strcmp(arg, "any") == 0) {
				اگر (nstrs > 0) {
					fatal("%s line %d: \"any\" must "
					    "appear alone in %s",
					    filename, linenum, keyword);
				}
				قدر = 1;
			} ورنہ اگر (قدر) {
				fatal("%s line %d: \"any\" must appear "
				    "alone in %s", filename, linenum, keyword);
			} ورنہ اگر (auth2_methods_valid(arg, 0) != 0) {
				fatal("%s line %d: invalid %s method list.",
				    filename, linenum, keyword);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		اگر (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		اگر (ملا && *activep) {
			options->auth_methods = strs;
			options->عدد_auth_methods = nstrs;
			strs = تہی; /* transferred */
			nstrs = 0;
		}
		توڑو;

	حالت s_دھارا_Local_Bind_نقاب:
		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		/* Parse mode in octal format */
		قدر = strtol(arg, &p, 8);
		اگر (arg == p || قدر < 0 || قدر > 0777)
			fatal("%s line %d: Invalid %s.",
			    filename, linenum, keyword);
		اگر (*activep &&
		    options->fwd_opts.streamlocal_bind_نقاب == (منوال_t)-1)
			options->fwd_opts.streamlocal_bind_نقاب = (منوال_t)قدر;
		توڑو;

	حالت s_دھارا_Local_Bind_Unlink:
		intptr = &options->fwd_opts.streamlocal_bind_unlink;
		جاؤ parse_flag;

	حالت sFingerprintHash:
		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		اگر ((قدر = ssh_digest_alg_by_name(arg)) == -1)
			fatal("%.200s line %d: Invalid %s algorithm \"%s\".",
			    filename, linenum, keyword, arg);
		اگر (*activep)
			options->fingerprint_hash = قدر;
		توڑو;

	حالت sExposeAuthInfo:
		intptr = &options->expose_userauth_info;
		جاؤ parse_flag;

	حالت sRDomain:
#اگر !defined(__OpenBSD__) && !defined(HAVE_SYS_سیٹ_PROCESS_RDOMAIN)
		fatal("%s line %d: setting RDomain not supported on this "
		    "platform.", filename, linenum);
#اگر_ختم
		charptr = &options->routing_domain;
		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		اگر (strcasecmp(arg, "none") != 0 && strcmp(arg, "%D") != 0 &&
		    !valid_rdomain(arg))
			fatal("%s line %d: invalid routing domain",
			    filename, linenum);
		اگر (*activep && *charptr == تہی)
			*charptr = xstrdup(arg);
		توڑو;

	حالت sRequiredRSASize:
		intptr = &options->required_rsa_سائز;
		جاؤ parse_int;

	حالت sChannelTimeout:
		ملا = options->عدد_channel_timeouts == 0;
		جب ((arg = argv_اگلا(&ac, &av)) != تہی) {
			/* Allow "none" only in first position */
			اگر (strcasecmp(arg, "none") == 0) {
				اگر (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					جاؤ برآمد;
				}
			} ورنہ اگر (parse_نمونہ_interval(arg,
			    تہی, تہی) != 0) {
				fatal("%s line %d: invalid channel timeout %s",
				    filename, linenum, arg);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		اگر (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		اگر (ملا && *activep) {
			options->channel_timeouts = strs;
			options->عدد_channel_timeouts = nstrs;
			strs = تہی; /* transferred */
			nstrs = 0;
		}
		توڑو;

	حالت s_غیر_مستعمل_Connection_Timeout:
		intptr = &options->غیر_مستعمل_connection_timeout;
		/* peek at first arg for "none" so we can reuse parse_time */
		اگر (av[0] != تہی && strcasecmp(av[0], "none") == 0) {
			(خالی)argv_اگلا(&ac, &av); /* consume arg */
			اگر (*activep)
				*intptr = 0;
			توڑو;
		}
		جاؤ parse_وقت;

	حالت s_Sshd_Session_راستہ:
		charptr = &options->sshd_session_راستہ;
		جاؤ parse_filename;

	حالت s_Sshd_Auth_راستہ:
		charptr = &options->sshd_auth_راستہ;
		جاؤ parse_filename;

	حالت sRefuseConnection:
		intptr = &options->refuse_connection;
		multistate_ptr = multistate_flag;
		جاؤ parse_multistate;

	حالت sWarnWeakCrypto:
		intptr = &options->warn_weak_crypto;
		multistate_ptr = multistate_warnweakcrypto;
		جاؤ parse_multistate;

	حالت sDeprecated:
	حالت sIgnore:
	حالت sUnsupported:
		do_log2(opcode == sIgnore ?
		    SYSLOG_LEVEL_DEBUG2 : SYSLOG_LEVEL_INFO,
		    "%s line %d: %s option %s", filename, linenum,
		    opcode == sUnsupported ? "Unsupported" : "Deprecated",
		    keyword);
		argv_consume(&ac);
		توڑو;

	طےشدہ:
		fatal("%s line %d: Missing handler for opcode %s (%d)",
		    filename, linenum, keyword, opcode);
	}
	/* Check that there is no garbage at end of line. */
	اگر (ac > 0) {
		error("%.200s line %d: keyword %s extra arguments "
		    "at end of line", filename, linenum, keyword);
		جاؤ برآمد;
	}

	/* success */
	ret = 0;
 برآمد:
	opt_array_free2(strs, تہی, nstrs);
	argv_free(oav, oac);
	واپس ret;
}

صحیح
process_server_config_سطر(ServerOptions *options, حرف *سطر,
    ثابت حرف *filename, صحیح linenum, صحیح *activep,
    ساخت connection_info *connectinfo, ساخت include_list *includes)
{
	صحیح inc_flags = 0;

	واپس process_server_config_سطر_گہرائی(options, سطر, filename,
	    linenum, activep, connectinfo, &inc_flags, 0, includes);
}


/* Reads the server configuration file. */

خالی
بھرو_server_config(ثابت حرف *filename, ساخت sshbuf *conf)
{
	ساخت stat st;
	حرف *سطر = تہی, *cp;
	سائز_t linesize = 0;
	FILE *f;
	صحیح r;

	debug2_f("filename %s", filename);
	اگر ((f = fopen(filename, "r")) == تہی) {
		perror(filename);
		باہر_نکلو(1);
	}
	sshbuf_reset(conf);
	/* grow buffer, so realloc is avoided for large config files */
	اگر (fstat(fileno(f), &st) == 0 && st.st_size > 0 &&
	    (r = sshbuf_allocate(conf, st.st_size)) != 0)
		fatal_fr(r, "allocate");
	جب (getline(&سطر, &linesize, f) != -1) {
		/*
		 * Strip whitespace
		 * NB - preserve newlines, they are needed to reproduce
		 * line numbers later for error messages
		 */
		cp = سطر + strspn(سطر, " \t\r");
		اگر ((r = sshbuf_put(conf, cp, لڑی_لمبائی(cp))) != 0)
			fatal_fr(r, "sshbuf_put");
	}
	آزاد(سطر);
	اگر ((r = sshbuf_put_u8(conf, 0)) != 0)
		fatal_fr(r, "sshbuf_put_u8");
	fclose(f);
	debug2_f("done config len = %zu", sshbuf_len(conf));
}

خالی
parse_server_مطابقت_config(ServerOptions *options,
   ساخت include_list *includes, ساخت connection_info *connectinfo)
{
	ServerOptions mo;

	initialize_server_options(&mo);
	parse_server_config(&mo, "reprocess config", cfg, includes,
	    connectinfo, 0);
	copy_سیٹ_server_options(options, &mo, 0);
	free_server_options(&mo);
}

صحیح
parse_server_مطابقت_testspec(ساخت connection_info *ci, حرف *spec)
{
	حرف *p;
	ثابت حرف *val;

	جب ((p = strsep(&spec, ",")) && *p != '\0') {
		اگر ((val = strprefix(p, "addr=", 0)) != تہی) {
			ci->پتہ = xstrdup(val);
		} ورنہ اگر ((val = strprefix(p, "host=", 0)) != تہی) {
			ci->host = xstrdup(val);
		} ورنہ اگر ((val = strprefix(p, "user=", 0)) != تہی) {
			ci->user = xstrdup(val);
		} ورنہ اگر ((val = strprefix(p, "laddr=", 0)) != تہی) {
			ci->laddress = xstrdup(val);
		} ورنہ اگر ((val = strprefix(p, "rdomain=", 0)) != تہی) {
			ci->rdomain = xstrdup(val);
		} ورنہ اگر ((val = strprefix(p, "lport=", 0)) != تہی) {
			ci->lport = a2port(val);
			اگر (ci->lport == -1) {
				fprintf(stderr, "Invalid port '%s' in test mode"
				    " specification %s\n", p+6, p);
				واپس -1;
			}
		} ورنہ اگر (strcmp(p, "invalid-user") == 0) {
			ci->user_invalid = 1;
		} ورنہ {
			fprintf(stderr, "Invalid test mode specification %s\n",
			    p);
			واپس -1;
		}
	}
	واپس 0;
}

خالی
servconf_ملاؤ_subsystems(ServerOptions *dst, ServerOptions *src)
{
	u_int i, j, ملا;

	برائے (i = 0; i < src->عدد_subsystems; i++) {
		ملا = 0;
		برائے (j = 0; j < dst->عدد_subsystems; j++) {
			اگر (strcmp(src->subsystem_name[i],
			    dst->subsystem_name[j]) == 0) {
				ملا = 1;
				توڑو;
			}
		}
		اگر (ملا) {
			debug_f("override \"%s\"", dst->subsystem_name[j]);
			آزاد(dst->subsystem_command[j]);
			آزاد(dst->subsystem_دلائل[j]);
			dst->subsystem_command[j] =
			    xstrdup(src->subsystem_command[i]);
			dst->subsystem_دلائل[j] =
			    xstrdup(src->subsystem_دلائل[i]);
			جاری;
		}
		debug_f("add \"%s\"", src->subsystem_name[i]);
		dst->subsystem_name = xrecallocarray(
		    dst->subsystem_name, dst->عدد_subsystems,
		    dst->عدد_subsystems + 1, حجم(*dst->subsystem_name));
		dst->subsystem_command = xrecallocarray(
		    dst->subsystem_command, dst->عدد_subsystems,
		    dst->عدد_subsystems + 1, حجم(*dst->subsystem_command));
		dst->subsystem_دلائل = xrecallocarray(
		    dst->subsystem_دلائل, dst->عدد_subsystems,
		    dst->عدد_subsystems + 1, حجم(*dst->subsystem_دلائل));
		j = dst->عدد_subsystems++;
		dst->subsystem_name[j] = xstrdup(src->subsystem_name[i]);
		dst->subsystem_command[j] = xstrdup(src->subsystem_command[i]);
		dst->subsystem_دلائل[j] = xstrdup(src->subsystem_دلائل[i]);
	}
}

ساکن صحیح
serialise_s32(ساخت sshbuf *buf, صحیح v)
{
	uint32_t uv;
	صحیح r;

	uv = v < 0 ? (uint32_t)(-(v + 1)) + 1 : (uint32_t)v;
	اگر ((r = sshbuf_put_u8(buf, v < 0)) != 0 ||
	    (r = sshbuf_put_u32(buf, uv)) != 0)
		واپس r;
	واپس 0;
}

ساکن صحیح
serialise_s64(ساخت sshbuf *buf, int64_t v)
{
	uint64_t uv;
	صحیح r;

	uv = v < 0 ? (uint64_t)(-(v + 1)) + 1 : (uint64_t)v;
	اگر ((r = sshbuf_put_u8(buf, v < 0)) != 0 ||
	    (r = sshbuf_put_u64(buf, uv)) != 0)
		واپس r;
	واپس 0;
}

ساکن صحیح
serialise_منوال(ساخت sshbuf *buf, منوال_t v)
{
	u_int uv;

	اگر (v == (منوال_t)-1)
		واپس serialise_s32(buf, -1);
	uv = (u_int)v;
	اگر ((منوال_t)uv != v || uv > 0777)
		واپس SSH_ERR_INVALID_FORMAT;
	واپس serialise_s32(buf, (صحیح)uv);
}

ساکن صحیح
serialise_double(ساخت sshbuf *buf, دوہرا v)
{
	/*
	 * XXX this is no good for a wire encoding.
	 * It's fine for passing configurations via RPC, but it would
	 * be nicer to have an exact binary encoding here.
	 */
	واپس sshbuf_put(buf, &v, حجم(v));
}

ساکن صحیح
serialise_nullable_string(ساخت sshbuf *buf, ثابت حرف *s)
{
	صحیح r;

	اگر ((r = sshbuf_put_u8(buf, s != تہی)) != 0)
		واپس r;
	اگر (s == تہی)
		واپس 0;
	واپس sshbuf_put_cstring(buf, s);
}

ساکن صحیح
serialise_nullable_string_array(ساخت sshbuf *buf, حرف **a, u_int n)
{
	صحیح r;
	u_int i;

	اگر ((r = sshbuf_put_u32(buf, n)) != 0)
		واپس r;
	برائے (i = 0; i < n; i++) {
		اگر ((r = serialise_nullable_string(buf, a[i])) != 0)
			واپس r;
	}
	واپس 0;
}

ساکن صحیح
serialise_hostkeyfile(ثابت ServerOptions *options, ساخت sshbuf *buf)
{
	صحیح r;
	u_int i;

	اگر ((r = sshbuf_put_u32(buf, options->عدد_host_کلید_files)) != 0) {
		error_fr(r, "serialise length");
		واپس r;
	}
	برائے (i = 0; i < options->عدد_host_کلید_files; i++) {
		اگر ((r = serialise_s32(buf,
		    options->host_کلید_file_userprovided[i])) != 0 ||
		    (r = serialise_nullable_string(buf,
		    options->host_کلید_files[i])) != 0) {
			error_fr(r, "serialise member");
			واپس r;
		}
	}
	واپس 0;
}

ساکن صحیح
serialise_ipqos(ثابت ServerOptions *options, ساخت sshbuf *buf)
{
	صحیح r;

	اگر ((r = serialise_s32(buf, options->ip_qos_interactive)) != 0 ||
	    (r = serialise_s32(buf, options->ip_qos_bulk)) != 0) {
		error_fr(r, "serialise");
		واپس r;
	}

	واپس 0;
}

ساکن صحیح
serialise_listenaddress(ثابت ServerOptions *options, ساخت sshbuf *buf)
{
	صحیح r;
	u_int i;

	/* Note: only serialises queued listen addresses */
	اگر ((r = sshbuf_put_u32(buf, options->عدد_queued_listens)) != 0) {
		error_fr(r, "serialise length");
		واپس r;
	}
	برائے (i = 0; i < options->عدد_queued_listens; i++) {
		ثابت ساخت queued_listenaddr *qla =
		    options->queued_listen_addrs + i;

		اگر ((r = sshbuf_put_cstring(buf, qla->addr)) != 0 ||
		    (r = serialise_s32(buf, qla->پورٹ)) != 0 ||
		    (r = serialise_nullable_string(buf, qla->rdomain)) != 0) {
			error_fr(r, "serialise member");
			واپس r;
		}
	}
	واپس 0;
}

ساکن صحیح
serialise_logfacility(ثابت ServerOptions *options, ساخت sshbuf *buf)
{
	صحیح r;

	اگر ((r = serialise_s32(buf, (صحیح)options->log_facility)) != 0) {
		error_fr(r, "serialise");
		واپس r;
	}

	واپس 0;
}

ساکن صحیح
serialise_loglevel(ثابت ServerOptions *options, ساخت sshbuf *buf)
{
	صحیح r;

	اگر ((r = serialise_s32(buf, (صحیح)options->log_level)) != 0) {
		error_fr(r, "serialise");
		واپس r;
	}

	واپس 0;
}

ساکن صحیح
serialise_پورٹ(ثابت ServerOptions *options, ساخت sshbuf *buf)
{
	صحیح r;
	u_int i;

	اگر ((r = sshbuf_put_u32(buf, options->عدد_ports)) != 0) {
		error_fr(r, "serialise length");
		واپس r;
	}
	برائے (i = 0; i < options->عدد_ports; i++) {
		اگر ((r = serialise_s32(buf, options->ports[i])) != 0) {
			error_fr(r, "serialise port");
			واپس r;
		}
	}
	واپس 0;
}

ساکن صحیح
serialise_gatewayports(ثابت ServerOptions *options, ساخت sshbuf *buf)
{
	صحیح r;

	اگر ((r = serialise_s32(buf, options->fwd_opts.gateway_ports)) != 0) {
		error_fr(r, "serialise");
		واپس r;
	}
	واپس 0;
}

ساکن صحیح
serialise_streamlocalbindmask(ثابت ServerOptions *options, ساخت sshbuf *buf)
{
	صحیح r;

	اگر ((r = serialise_منوال(buf,
	    options->fwd_opts.streamlocal_bind_نقاب)) != 0) {
		error_fr(r, "serialise");
		واپس r;
	}
	واپس 0;
}

ساکن صحیح
serialise_streamlocalbindunlink(ثابت ServerOptions *options, ساخت sshbuf *buf)
{
	صحیح r;

	اگر ((r = sshbuf_put_u8(buf,
	    (options->fwd_opts.streamlocal_bind_unlink != 0))) != 0) {
		error_fr(r, "serialise");
		واپس r;
	}
	واپس 0;
}

ساکن صحیح
serialise_maxstartups(ثابت ServerOptions *options, ساخت sshbuf *buf)
{
	صحیح r;

	اگر ((r = serialise_s32(buf, options->max_startups_begin)) != 0 ||
	    (r = serialise_s32(buf, options->max_startups_شرح)) != 0 ||
	    (r = serialise_s32(buf, options->max_startups)) != 0) {
		error_fr(r, "serialise");
		واپس r;
	}

	واپس 0;
}

ساکن صحیح
serialise_permituserenv(ثابت ServerOptions *options, ساخت sshbuf *buf)
{
	صحیح r;

	اگر ((r = serialise_s32(buf, options->permit_user_env)) != 0 ||
	    (r = serialise_nullable_string(buf,
	    options->permit_user_env_allowlist)) != 0) {
		error_fr(r, "serialise");
		واپس r;
	}

	واپس 0;
}

ساکن صحیح
serialise_persourcenetblocksize(ثابت ServerOptions *options, ساخت sshbuf *buf)
{
	صحیح r;

	اگر ((r = serialise_s32(buf, options->فی_ماخذ_masklen_ipv4)) != 0 ||
	    (r = serialise_s32(buf, options->فی_ماخذ_masklen_ipv6)) != 0) {
		error_fr(r, "serialise");
		واپس r;
	}

	واپس 0;
}

ساکن صحیح
serialise_persourcepenalties(ثابت ServerOptions *options, ساخت sshbuf *buf)
{
	ثابت ساخت فی_ماخذ_penalty *psp = &options->فی_ماخذ_penalty;
	صحیح r;

	اگر ((r = serialise_s32(buf, psp->enabled)) != 0 ||
	    (r = serialise_s32(buf, psp->max_sources4)) != 0 ||
	    (r = serialise_s32(buf, psp->max_sources6)) != 0 ||
	    (r = serialise_s32(buf, psp->حد_سے_تجاوز_منوال)) != 0 ||
	    (r = serialise_s32(buf, psp->حد_سے_تجاوز_mode6)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_crash)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_grace)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_authfail)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_invaliduser)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_noauth)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_refuseconnection)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_max)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_min)) != 0) {
		error_fr(r, "serialise");
		واپس r;
	}

	واپس 0;
}

ساکن صحیح
serialise_rekeylimit(ثابت ServerOptions *options, ساخت sshbuf *buf)
{
	صحیح r;

	اگر ((r = serialise_s64(buf, options->rekey_حد_بندی)) != 0 ||
	    (r = serialise_s32(buf, options->rekey_interval)) != 0) {
		error_fr(r, "serialise");
		واپس r;
	}

	واپس 0;
}

ساکن صحیح
serialise_subsystem(ثابت ServerOptions *options, ساخت sshbuf *buf)
{
	صحیح r;
	u_int i;

	اگر ((r = sshbuf_put_u32(buf, options->عدد_subsystems)) != 0) {
		error_fr(r, "serialise length");
		واپس r;
	}
	برائے (i = 0; i < options->عدد_subsystems; i++) {
		اگر ((r = sshbuf_put_cstring(buf,
		    options->subsystem_name[i])) != 0 ||
		    (r = sshbuf_put_cstring(buf,
		    options->subsystem_command[i])) != 0 ||
		    (r = sshbuf_put_cstring(buf,
		    options->subsystem_دلائل[i])) != 0) {
			error_fr(r, "serialise member");
			واپس r;
		}
	}
	واپس 0;
}

ساکن صحیح
serialise_pubkey_auth_options(ثابت ServerOptions *options, ساخت sshbuf *buf)
{
	صحیح r;

	اگر ((r = serialise_s32(buf, options->pubkey_auth_options)) != 0 ||
	    (r = serialise_s32(buf, options->max_pubkey_ok)) != 0) {
		error_fr(r, "serialise");
		واپس r;
	}
	واپس 0;
}

ساکن صحیح
serialise_timingsecret(ثابت ServerOptions *options, ساخت sshbuf *buf)
{
	صحیح r;

	اگر ((r = sshbuf_put_u64(buf, options->timing_secret)) != 0) {
		error_fr(r, "serialise");
		واپس r;
	}
	واپس 0;
}


صحیح
serialise_server_options(ثابت ServerOptions *options, ساخت sshbuf **bufp)
{
	ساخت sshbuf *buf = تہی;
	صحیح r = SSH_ERR_اندرونی_ERROR;

	*bufp = تہی;

	اگر ((buf = sshbuf_new()) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshbuf_put_u32(buf, SSHD_CONFIG_BLOB_نسخہ)) != 0) {
		error_fr(r, "serialise version");
		جاؤ برآمد;
	}

#تعریف_کرو SSHCONF_INT(var, conf, flags, ms, def, cp) \
	اگر ((r = serialise_s32(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		جاؤ برآمد; \
	}
#تعریف_کرو SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	اگر ((r = serialise_s32(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		جاؤ برآمد; \
	}
#تعریف_کرو SSHCONF_STRING(var, conf, flags, cp) \
	اگر ((r = serialise_nullable_string(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		جاؤ برآمد; \
	}
#تعریف_کرو SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	اگر ((r = serialise_nullable_string_array(buf, options->var, \
	    options->nvar)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		جاؤ برآمد; \
	}
#تعریف_کرو SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	اگر ((r = serialise_##funcsuffix(options, buf)) != 0) \
		جاؤ برآمد;
#تعریف_کرو SSHCONF_NONCONF(funcsuffix) \
	اگر ((r = serialise_##funcsuffix(options, buf)) != 0) \
		جاؤ برآمد;
#تعریف_کرو SSHCONF_DEPRECATE(conf, flags, opcode)		/*خالی_خانے*/
#تعریف_کرو SSHCONF_UNSUPPORTED_INT(var, conf, flags)	/*خالی_خانے*/
#تعریف_کرو SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	/*خالی_خانے*/
#تعریف_کرو SSHCONF_ALIAS(old, conf, flags)			/*خالی_خانے*/

	SSHD_CONFIG_ENTRIES

#تعریف_منسوخ SSHCONF_INT
#تعریف_منسوخ SSHCONF_INTFLAG
#تعریف_منسوخ SSHCONF_STRING
#تعریف_منسوخ SSHCONF_STRARRAY
#تعریف_منسوخ SSHCONF_CUSTOM
#تعریف_منسوخ SSHCONF_NONCONF
#تعریف_منسوخ SSHCONF_DEPRECATE
#تعریف_منسوخ SSHCONF_UNSUPPORTED_INT
#تعریف_منسوخ SSHCONF_UNSUPPORTED_STRING
#تعریف_منسوخ SSHCONF_ALIAS

	/* success */
	r = 0;
	*bufp = buf;
	buf = تہی; /* transferred */
 برآمد:
	sshbuf_free(buf);
	واپس r;
}

ساکن صحیح
deserialise_s32(ساخت sshbuf *buf, صحیح *v)
{
	uint32_t tmp;
	صحیح r;
	u_char was_signed;

	اگر ((r = sshbuf_get_u8(buf, &was_signed)) != 0 ||
	    (r = sshbuf_get_u32(buf, &tmp)) != 0)
		واپس r;
	اگر (was_signed > 1)
		واپس SSH_ERR_INVALID_FORMAT;
	اگر (was_signed) {
		اگر (tmp > (uint32_t)زیادہ_سے_زیادہ_عدد + 1)
			واپس SSH_ERR_INVALID_FORMAT;
		*v = tmp == (uint32_t)زیادہ_سے_زیادہ_عدد + 1 ? INT_MIN : -(صحیح)tmp;
	} ورنہ {
		اگر (tmp > زیادہ_سے_زیادہ_عدد)
			واپس SSH_ERR_INVALID_FORMAT;
		*v = (صحیح)tmp;
	}
	واپس 0;
}

ساکن صحیح
deserialise_s64(ساخت sshbuf *buf, int64_t *v)
{
	uint64_t tmp;
	صحیح r;
	u_char was_signed;

	اگر ((r = sshbuf_get_u8(buf, &was_signed)) != 0 ||
	    (r = sshbuf_get_u64(buf, &tmp)) != 0)
		واپس r;
	اگر (was_signed > 1)
		واپس SSH_ERR_INVALID_FORMAT;
	اگر (was_signed) {
		اگر (tmp > (uint64_t)INT64_MAX + 1)
			واپس SSH_ERR_INVALID_FORMAT;
		*v = tmp == (uint64_t)INT64_MAX + 1 ?
		    INT64_MIN : -(int64_t)tmp;
	} ورنہ {
		اگر (tmp > INT64_MAX)
			واپس SSH_ERR_INVALID_FORMAT;
		*v = (int64_t)tmp;
	}
	واپس 0;
}

ساکن صحیح
deserialise_منوال(ساخت sshbuf *buf, منوال_t *v)
{
	صحیح r, tmp;

	اگر ((r = deserialise_s32(buf, &tmp)) != 0)
		واپس r;
	اگر (tmp == -1) {
		*v = (منوال_t)-1;
		واپس 0;
	}
	اگر (tmp < 0 || tmp > 0777)
		واپس SSH_ERR_INVALID_FORMAT;
	*v = (منوال_t)tmp;
	واپس 0;
}

ساکن صحیح
deserialise_double(ساخت sshbuf *buf, دوہرا *v)
{
	واپس sshbuf_get(buf, v, حجم(*v));
}

ساکن صحیح
deserialise_nullable_string(ساخت sshbuf *buf, حرف **sp)
{
	صحیح r;
	u_char present;

	اگر ((r = sshbuf_get_u8(buf, &present)) != 0)
		واپس r;
	اگر (present == 0) {
		*sp = تہی;
		واپس 0;
	}
	اگر (present != 1)
		واپس SSH_ERR_INVALID_FORMAT;
	واپس sshbuf_get_cstring(buf, sp, تہی);
}

ساکن خالی
free_string_array(حرف **a, u_int n)
{
	u_int i;

	اگر (a == تہی)
		واپس;
	برائے (i = 0; i < n; i++)
		آزاد(a[i]);
	آزاد(a);
}

ساکن صحیح
deserialise_گنتی(ساخت sshbuf *buf, u_int *np, ثابت حرف *what)
{
	صحیح r;
	uint32_t n;

	اگر ((r = sshbuf_get_u32(buf, &n)) != 0) {
		error_fr(r, "deserialise %s length", what);
		واپس r;
	}
	اگر (n > UINT_MAX) {
		error_f("bad number of %s", what);
		واپس SSH_ERR_INVALID_FORMAT;
	}
	اگر (n > sshbuf_len(buf)) {
		error_f("bad number of %s", what);
		واپس SSH_ERR_INVALID_FORMAT;
	}
	*np = n;
	واپس 0;
}

ساکن صحیح
deserialise_nullable_string_array(ساخت sshbuf *buf, حرف ***arrayp,
    u_int *np)
{
	حرف **a = تہی;
	صحیح r;
	u_int i, n;

	*arrayp = تہی;
	*np = 0;
	اگر ((r = deserialise_گنتی(buf, &n, "strings")) != 0)
		واپس r;
	اگر (n > 0)
		a = xcalloc(n, حجم(*a));
	برائے (i = 0; i < n; i++) {
		اگر ((r = deserialise_nullable_string(buf, a + i)) != 0) {
			free_string_array(a, i + 1);
			واپس r;
		}
	}
	*arrayp = a;
	*np = n;
	واپس 0;
}

ساکن خالی
free_queued_listen_addrs(ساخت queued_listenaddr *qla, u_int n)
{
	u_int i;

	اگر (qla == تہی)
		واپس;
	برائے (i = 0; i < n; i++) {
		آزاد(qla[i].addr);
		آزاد(qla[i].rdomain);
	}
	آزاد(qla);
}

ساکن صحیح
deserialise_hostkeyfile(ServerOptions *options, ساخت sshbuf *buf)
{
	صحیح r, *userprovided = تہی;
	u_int i, n;
	حرف **files = تہی;

	اگر ((r = deserialise_گنتی(buf, &n, "host key files")) != 0)
		واپس r;
	اگر (n > 0) {
		userprovided = xcalloc(n, حجم(*userprovided));
		files = xcalloc(n, حجم(*files));
	}
	برائے (i = 0; i < n; i++) {
		اگر ((r = deserialise_s32(buf, userprovided + i)) != 0 ||
		    (r = deserialise_nullable_string(buf, files + i)) != 0) {
			error_fr(r, "deserialise member");
			free_string_array(files, i + 1);
			آزاد(userprovided);
			واپس r;
		}
	}
	options->عدد_host_کلید_files = n;
	options->host_کلید_file_userprovided = userprovided;
	options->host_کلید_files = files;
	واپس 0;
}

ساکن صحیح
deserialise_ipqos(ServerOptions *options, ساخت sshbuf *buf)
{
	صحیح r;

	اگر ((r = deserialise_s32(buf, &options->ip_qos_interactive)) != 0 ||
	    (r = deserialise_s32(buf, &options->ip_qos_bulk)) != 0) {
		error_fr(r, "deserialise");
		واپس r;
	}

	واپس 0;
}

ساکن صحیح
deserialise_listenaddress(ServerOptions *options, ساخت sshbuf *buf)
{
	صحیح r;
	u_int i, n;
	ساخت queued_listenaddr *qla = تہی;

	اگر ((r = deserialise_گنتی(buf, &n, "listen addresses")) != 0)
		واپس r;
	اگر (n > 0)
		qla = xcalloc(n, حجم(*qla));
	برائے (i = 0; i < n; i++) {
		اگر ((r = sshbuf_get_cstring(buf, &qla[i].addr, تہی)) != 0 ||
		    (r = deserialise_s32(buf, &qla[i].پورٹ)) != 0 ||
		    (r = deserialise_nullable_string(buf,
		    &qla[i].rdomain)) != 0) {
			error_fr(r, "deserialise member");
			free_queued_listen_addrs(qla, i + 1);
			واپس r;
		}
	}
	options->عدد_queued_listens = n;
	options->queued_listen_addrs = qla;
	واپس 0;
}

ساکن صحیح
deserialise_logfacility(ServerOptions *options, ساخت sshbuf *buf)
{
	صحیح r, tmp;

	اگر ((r = deserialise_s32(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		واپس r;
	}
	اگر (tmp != SYSLOG_FACILITY_NOT_سیٹ &&
	    log_facility_name((SyslogFacility)tmp) == تہی) {
		error_f("bad syslog facility");
		واپس SSH_ERR_INVALID_FORMAT;
	}
	options->log_facility = (SyslogFacility)tmp;

	واپس 0;
}

ساکن صحیح
deserialise_loglevel(ServerOptions *options, ساخت sshbuf *buf)
{
	صحیح r, tmp;

	اگر ((r = deserialise_s32(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		واپس r;
	}
	اگر (tmp != SYSLOG_LEVEL_NOT_سیٹ &&
	    log_level_name((LogLevel)tmp) == تہی) {
		error_f("bad log level");
		واپس SSH_ERR_INVALID_FORMAT;
	}
	options->log_level = (LogLevel)tmp;

	واپس 0;
}

ساکن صحیح
deserialise_پورٹ(ServerOptions *options, ساخت sshbuf *buf)
{
	صحیح r;
	u_int i, n;

	اگر ((r = deserialise_گنتی(buf, &n, "ports")) != 0)
		واپس r;
	اگر (n > MAX_PORTS) {
		error_f("bad number of ports");
		واپس SSH_ERR_INVALID_FORMAT;
	}
	options->عدد_ports = n;
	memset(options->ports, 0, حجم(options->ports));
	برائے (i = 0; i < options->عدد_ports; i++) {
		اگر ((r = deserialise_s32(buf, options->ports + i)) != 0) {
			error_fr(r, "deserialise port");
			واپس r;
		}
	}
	واپس 0;
}

ساکن صحیح
deserialise_gatewayports(ServerOptions *options, ساخت sshbuf *buf)
{
	صحیح r;

	اگر ((r = deserialise_s32(buf, &options->fwd_opts.gateway_ports)) != 0) {
		error_fr(r, "deserialise");
		واپس r;
	}
	واپس 0;
}

ساکن صحیح
deserialise_streamlocalbindmask(ServerOptions *options, ساخت sshbuf *buf)
{
	صحیح r;

	اگر ((r = deserialise_منوال(buf,
	    &options->fwd_opts.streamlocal_bind_نقاب)) != 0) {
		error_fr(r, "deserialise");
		واپس r;
	}
	واپس 0;
}

ساکن صحیح
deserialise_streamlocalbindunlink(ServerOptions *options, ساخت sshbuf *buf)
{
	صحیح r;
	u_char tmp;

	اگر ((r = sshbuf_get_u8(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		واپس r;
	}
	اگر (tmp > 1) {
		error_f("bad boolean");
		واپس SSH_ERR_INVALID_FORMAT;
	}
	options->fwd_opts.streamlocal_bind_unlink = tmp;
	واپس 0;
}

ساکن صحیح
deserialise_maxstartups(ServerOptions *options, ساخت sshbuf *buf)
{
	صحیح r;

	اگر ((r = deserialise_s32(buf, &options->max_startups_begin)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_startups_شرح)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_startups)) != 0) {
		error_fr(r, "deserialise");
		واپس r;
	}

	واپس 0;
}

ساکن صحیح
deserialise_permituserenv(ServerOptions *options, ساخت sshbuf *buf)
{
	صحیح r;

	اگر ((r = deserialise_s32(buf, &options->permit_user_env)) != 0 ||
	    (r = deserialise_nullable_string(buf,
	    &options->permit_user_env_allowlist)) != 0) {
		error_fr(r, "deserialise");
		واپس r;
	}
	واپس 0;
}

ساکن صحیح
deserialise_persourcenetblocksize(ServerOptions *options, ساخت sshbuf *buf)
{
	صحیح r;

	اگر ((r = deserialise_s32(buf,
	    &options->فی_ماخذ_masklen_ipv4)) != 0 ||
	    (r = deserialise_s32(buf,
	    &options->فی_ماخذ_masklen_ipv6)) != 0) {
		error_fr(r, "deserialise");
		واپس r;
	}

	واپس 0;
}

ساکن صحیح
deserialise_persourcepenalties(ServerOptions *options, ساخت sshbuf *buf)
{
	ساخت فی_ماخذ_penalty *psp = &options->فی_ماخذ_penalty;
	صحیح r;

	اگر ((r = deserialise_s32(buf, &psp->enabled)) != 0 ||
	    (r = deserialise_s32(buf, &psp->max_sources4)) != 0 ||
	    (r = deserialise_s32(buf, &psp->max_sources6)) != 0 ||
	    (r = deserialise_s32(buf, &psp->حد_سے_تجاوز_منوال)) != 0 ||
	    (r = deserialise_s32(buf, &psp->حد_سے_تجاوز_mode6)) != 0 ||
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
		واپس r;
	}

	واپس 0;
}

ساکن صحیح
deserialise_rekeylimit(ServerOptions *options, ساخت sshbuf *buf)
{
	صحیح r;

	اگر ((r = deserialise_s64(buf, &options->rekey_حد_بندی)) != 0 ||
	    (r = deserialise_s32(buf, &options->rekey_interval)) != 0) {
		error_fr(r, "deserialise");
		واپس r;
	}

	واپس 0;
}

ساکن صحیح
deserialise_subsystem(ServerOptions *options, ساخت sshbuf *buf)
{
	صحیح r;
	u_int i, n;
	حرف **نام = تہی, **commands = تہی, **دلائل = تہی;

	اگر ((r = deserialise_گنتی(buf, &n, "subsystems")) != 0)
		واپس r;
	اگر (n > 0) {
		نام = xcalloc(n, حجم(*نام));
		commands = xcalloc(n, حجم(*نام));
		دلائل = xcalloc(n, حجم(*دلائل));
	}
	برائے (i = 0; i < n; i++) {
		اگر ((r = sshbuf_get_cstring(buf, نام + i, تہی)) != 0 ||
		    (r = sshbuf_get_cstring(buf, commands + i, تہی)) != 0 ||
		    (r = sshbuf_get_cstring(buf, دلائل + i, تہی)) != 0) {
			error_fr(r, "deserialise member");
			free_string_array(نام, i + 1);
			free_string_array(commands, i + 1);
			free_string_array(دلائل, i + 1);
			واپس r;
		}
	}
	options->عدد_subsystems = n;
	options->subsystem_name = نام;
	options->subsystem_command = commands;
	options->subsystem_دلائل = دلائل;
	واپس 0;
}

ساکن صحیح
deserialise_pubkey_auth_options(ServerOptions *options, ساخت sshbuf *buf)
{
	صحیح r;

	اگر ((r = deserialise_s32(buf, &options->pubkey_auth_options)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_pubkey_ok)) != 0) {
		error_fr(r, "deserialise");
		واپس r;
	}
	واپس 0;
}

ساکن صحیح
deserialise_timingsecret(ServerOptions *options, ساخت sshbuf *buf)
{
	صحیح r;

	اگر ((r = sshbuf_get_u64(buf, &options->timing_secret)) != 0) {
		error_fr(r, "deserialise");
		واپس r;
	}
	واپس 0;
}

صحیح
deserialise_server_options(ساخت sshbuf *buf, ServerOptions *options)
{
	صحیح r = SSH_ERR_اندرونی_ERROR;
	uint32_t نسخہ;
	ServerOptions new_options;

	initialize_server_options(&new_options);
	اگر ((r = sshbuf_get_u32(buf, &نسخہ)) != 0) {
		error_fr(r, "deserialise version");
		جاؤ برآمد;
	}
	اگر (نسخہ != SSHD_CONFIG_BLOB_نسخہ) {
		error_f("unsupported config blob version %u", نسخہ);
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
#تعریف_کرو SSHCONF_INT(var, conf, flags, ms, def, cp) \
	اگر ((r = deserialise_s32(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		جاؤ برآمد; \
	}
#تعریف_کرو SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	اگر ((r = deserialise_s32(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		جاؤ برآمد; \
	}
#تعریف_کرو SSHCONF_STRING(var, conf, flags, cp) \
	اگر ((r = deserialise_nullable_string(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		جاؤ برآمد; \
	}
#تعریف_کرو SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	اگر ((r = deserialise_nullable_string_array(buf, &new_options.var, \
	    &new_options.nvar)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		جاؤ برآمد; \
	}
#تعریف_کرو SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	اگر ((r = deserialise_##funcsuffix(&new_options, buf)) != 0) \
		جاؤ برآمد;
#تعریف_کرو SSHCONF_NONCONF(funcsuffix) \
	اگر ((r = deserialise_##funcsuffix(&new_options, buf)) != 0) \
		جاؤ برآمد;
#تعریف_کرو SSHCONF_DEPRECATE(conf, flags, opcode)		/*خالی_خانے*/
#تعریف_کرو SSHCONF_UNSUPPORTED_INT(var, conf, flags)	new_options.var = 0;
#تعریف_کرو SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	کرو { \
		آزاد(new_options.var); \
		new_options.var = تہی; \
	} جب (0);
#تعریف_کرو SSHCONF_ALIAS(old, conf, flags)			/*خالی_خانے*/

	SSHD_CONFIG_ENTRIES

	اگر (sshbuf_len(buf) != 0) {
		error_f("trailing data in config blob");
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}

#تعریف_منسوخ SSHCONF_INT
#تعریف_منسوخ SSHCONF_INTFLAG
#تعریف_منسوخ SSHCONF_STRING
#تعریف_منسوخ SSHCONF_STRARRAY
#تعریف_منسوخ SSHCONF_CUSTOM
#تعریف_منسوخ SSHCONF_NONCONF
#تعریف_منسوخ SSHCONF_DEPRECATE
#تعریف_منسوخ SSHCONF_UNSUPPORTED_INT
#تعریف_منسوخ SSHCONF_UNSUPPORTED_STRING
#تعریف_منسوخ SSHCONF_ALIAS

	/* success */
	r = 0;
	free_server_options(options);
	*options = new_options;
	memset(&new_options, 0, حجم(new_options));
 برآمد:
	free_server_options(&new_options);
	واپس r;
}

ساکن خالی
free_hostkeyfile(ServerOptions *options)
{
	u_int i;

	برائے (i = 0; i < options->عدد_host_کلید_files; i++)
		آزاد(options->host_کلید_files[i]);
	آزاد(options->host_کلید_files);
	آزاد(options->host_کلید_file_userprovided);
}

ساکن خالی
free_listenaddress(ServerOptions *options)
{
	u_int i;

	free_queued_listen_addrs(options->queued_listen_addrs,
	    options->عدد_queued_listens);

	برائے (i = 0; i < options->عدد_listen_addrs; i++) {
		آزاد(options->listen_addrs[i].rdomain);
		اگر (options->listen_addrs[i].addrs != تہی)
			freeaddrinfo(options->listen_addrs[i].addrs);
	}
	آزاد(options->listen_addrs);
}

ساکن خالی
free_permituserenv(ServerOptions *options)
{
	آزاد(options->permit_user_env_allowlist);
}

ساکن خالی
free_subsystem(ServerOptions *options)
{
	u_int i;

	برائے (i = 0; i < options->عدد_subsystems; i++) {
		آزاد(options->subsystem_name[i]);
		آزاد(options->subsystem_command[i]);
		آزاد(options->subsystem_دلائل[i]);
	}
	آزاد(options->subsystem_name);
	آزاد(options->subsystem_command);
	آزاد(options->subsystem_دلائل);
}

خالی
free_server_options(ServerOptions *options)
{
#تعریف_کرو SSHCONF_INT(var, conf, flags, ms, def, cp)	/*خالی_خانے*/
#تعریف_کرو SSHCONF_INTFLAG(var, conf, flags, def, cp)	/*خالی_خانے*/
#تعریف_کرو SSHCONF_STRING(var, conf, flags, cp)		آزاد(options->var);
#تعریف_کرو SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	free_string_array(options->var, options->nvar);
#تعریف_کرو SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	free_##funcsuffix(options);
#تعریف_کرو SSHCONF_NONCONF(funcsuffix) \
	free_##funcsuffix(options);
#تعریف_کرو SSHCONF_DEPRECATE(conf, flags, opcode)		/*خالی_خانے*/
#تعریف_کرو SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#تعریف_کرو SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	کرو { \
		آزاد(options->var); \
		options->var = تہی; \
	} جب (0);
#تعریف_کرو SSHCONF_ALIAS(old, conf, flags)			/*خالی_خانے*/

#تعریف_کرو free_ipqos(options)
#تعریف_کرو free_logfacility(options)
#تعریف_کرو free_loglevel(options)
#تعریف_کرو free_پورٹ(options)
#تعریف_کرو free_gatewayports(options)
#تعریف_کرو free_streamlocalbindmask(options)
#تعریف_کرو free_streamlocalbindunlink(options)
#تعریف_کرو free_maxstartups(options)
#تعریف_کرو free_persourcenetblocksize(options)
#تعریف_کرو free_persourcepenalties(options)
#تعریف_کرو free_rekeylimit(options)
#تعریف_کرو free_pubkey_auth_options(options)
#تعریف_کرو free_timingsecret(options)

	SSHD_CONFIG_ENTRIES

#تعریف_منسوخ free_ipqos
#تعریف_منسوخ free_logfacility
#تعریف_منسوخ free_loglevel
#تعریف_منسوخ free_پورٹ
#تعریف_منسوخ free_gatewayports
#تعریف_منسوخ free_streamlocalbindmask
#تعریف_منسوخ free_streamlocalbindunlink
#تعریف_منسوخ free_maxstartups
#تعریف_منسوخ free_persourcenetblocksize
#تعریف_منسوخ free_persourcepenalties
#تعریف_منسوخ free_rekeylimit
#تعریف_منسوخ free_timingsecret

#تعریف_منسوخ SSHCONF_INT
#تعریف_منسوخ SSHCONF_INTFLAG
#تعریف_منسوخ SSHCONF_STRING
#تعریف_منسوخ SSHCONF_STRARRAY
#تعریف_منسوخ SSHCONF_CUSTOM
#تعریف_منسوخ SSHCONF_NONCONF
#تعریف_منسوخ SSHCONF_DEPRECATE
#تعریف_منسوخ SSHCONF_UNSUPPORTED_INT
#تعریف_منسوخ SSHCONF_UNSUPPORTED_STRING
#تعریف_منسوخ SSHCONF_ALIAS

	initialize_server_options(options);
}

ساکن خالی
copy_server_option_int(صحیح *dst, صحیح src)
{
	اگر (src != -1)
		*dst = src;
}

ساکن خالی
copy_server_option_int64(int64_t *dst, int64_t src)
{
	اگر (src != -1)
		*dst = src;
}

ساکن خالی
copy_server_option_string(حرف **dst, ثابت حرف *src)
{
	اگر (src != تہی && *dst != src) {
		آزاد(*dst);
		*dst = xstrdup(src);
	}
}

ساکن خالی
copy_server_option_strarray_اقدار(حرف ***dst, u_int ndst,
    حرف * ثابت *src, u_int nsrc)
{
	u_int i;

	اگر (nsrc == 0)
		واپس;
	برائے (i = 0; i < ndst; i++)
		آزاد((*dst)[i]);
	آزاد(*dst);
	*dst = xcalloc(nsrc, حجم(**dst));
	برائے (i = 0; i < nsrc; i++)
		(*dst)[i] = src[i] == تہی ? تہی : xstrdup(src[i]);
}

ساکن خالی
copy_server_option_strarray(حرف ***dst, u_int *ndst,
    حرف * ثابت *src, u_int nsrc)
{
	اگر (nsrc == 0)
		واپس;
	copy_server_option_strarray_اقدار(dst, *ndst, src, nsrc);
	*ndst = nsrc;
}

ساکن خالی
copy_ipqos(ServerOptions *dst, ثابت ServerOptions *src)
{
	copy_server_option_int(&dst->ip_qos_interactive,
	    src->ip_qos_interactive);
	copy_server_option_int(&dst->ip_qos_bulk, src->ip_qos_bulk);
}

ساکن خالی
copy_gatewayports(ServerOptions *dst, ثابت ServerOptions *src)
{
	copy_server_option_int(&dst->fwd_opts.gateway_ports,
	    src->fwd_opts.gateway_ports);
}

ساکن خالی
copy_streamlocalbindunlink(ServerOptions *dst, ثابت ServerOptions *src)
{
	copy_server_option_int(&dst->fwd_opts.streamlocal_bind_unlink,
	    src->fwd_opts.streamlocal_bind_unlink);
}

ساکن خالی
copy_loglevel(ServerOptions *dst, ثابت ServerOptions *src)
{
	اگر (src->log_level != -1)
		dst->log_level = src->log_level;
}

ساکن خالی
copy_rekeylimit(ServerOptions *dst, ثابت ServerOptions *src)
{
	copy_server_option_int64(&dst->rekey_حد_بندی, src->rekey_حد_بندی);
	copy_server_option_int(&dst->rekey_interval, src->rekey_interval);
}

ساکن خالی
copy_subsystem(ServerOptions *dst, ثابت ServerOptions *src)
{
	u_int old_عدد_subsystems = dst->عدد_subsystems;

	اگر (src->عدد_subsystems == 0)
		واپس;
	copy_server_option_strarray_اقدار(&dst->subsystem_name,
	    old_عدد_subsystems, src->subsystem_name, src->عدد_subsystems);
	copy_server_option_strarray_اقدار(&dst->subsystem_command,
	    old_عدد_subsystems, src->subsystem_command, src->عدد_subsystems);
	copy_server_option_strarray_اقدار(&dst->subsystem_دلائل,
	    old_عدد_subsystems, src->subsystem_دلائل, src->عدد_subsystems);
	dst->عدد_subsystems = src->عدد_subsystems;
}

ساکن خالی
copy_pubkey_auth_options(ServerOptions *dst, ثابت ServerOptions *src)
{
	اگر (src->pubkey_auth_options != -1) {
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
خالی
copy_سیٹ_server_options(ServerOptions *dst, ServerOptions *src, صحیح preauth)
{
	اگر (dst == src)
		واپس;

#تعریف_کرو SSHCONF_INT(var, conf, flags, ms, def, cp) \
	cp(copy_server_option_int(&dst->var, src->var);)
#تعریف_کرو SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	cp(copy_server_option_int(&dst->var, src->var);)
#تعریف_کرو SSHCONF_STRING(var, conf, flags, cp) \
	cp(copy_server_option_string(&dst->var, src->var);)
#تعریف_کرو SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	cp(copy_server_option_strarray(&dst->var, &dst->nvar, \
	    src->var, src->nvar);)
#تعریف_کرو SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	cp(copy_##funcsuffix(dst, src);)
#تعریف_کرو SSHCONF_NONCONF(funcsuffix)			/*خالی_خانے*/
#تعریف_کرو SSHCONF_DEPRECATE(conf, flags, opcode)		/*خالی_خانے*/
#تعریف_کرو SSHCONF_UNSUPPORTED_INT(var, conf, flags)	dst->var = 0;
#تعریف_کرو SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	کرو { \
		آزاد(dst->var); \
		dst->var = تہی; \
	} جب (0);
#تعریف_کرو SSHCONF_ALIAS(old, conf, flags)			/*خالی_خانے*/

	SSHD_CONFIG_ENTRIES

#تعریف_منسوخ SSHCONF_INT
#تعریف_منسوخ SSHCONF_INTFLAG
#تعریف_منسوخ SSHCONF_STRING
#تعریف_منسوخ SSHCONF_STRARRAY
#تعریف_منسوخ SSHCONF_CUSTOM
#تعریف_منسوخ SSHCONF_NONCONF
#تعریف_منسوخ SSHCONF_DEPRECATE
#تعریف_منسوخ SSHCONF_UNSUPPORTED_INT
#تعریف_منسوخ SSHCONF_UNSUPPORTED_STRING
#تعریف_منسوخ SSHCONF_ALIAS

	/*
	 * The bind_mask is a mode_t that may be unsigned, so we can't use
	 * copy_server_option_int - it does a signed comparison that causes
	 * compiler warnings.
	 */
	اگر (src->fwd_opts.streamlocal_bind_نقاب != (منوال_t)-1) {
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
#تعریف_کرو CLEAR_ON_NONE(v) \
	کرو { \
		اگر (option_clear_or_none(v)) { \
			آزاد(v); \
			v = تہی; \
		} \
	} جب(0)
	CLEAR_ON_NONE(dst->authorized_principals_file);
	CLEAR_ON_NONE(dst->trusted_user_ca_کلیدیں);
	CLEAR_ON_NONE(dst->banner);

	/*
	 * The only things that should be below this point are string options
	 * which are only used after authentication.
	 */
	اگر (preauth)
		واپس;

	/* These options may be "none" to clear a global setting */
	copy_server_option_string(&dst->adm_forced_command,
	    src->adm_forced_command);
	copy_server_option_string(&dst->chroot_directory,
	    src->chroot_directory);
	CLEAR_ON_NONE(dst->chroot_directory);
	CLEAR_ON_NONE(dst->adm_forced_command);
#تعریف_منسوخ CLEAR_ON_NONE

	/* Subsystems require merging. */
	servconf_ملاؤ_subsystems(dst, src);
}

#تعریف_کرو SERVCONF_MAX_گہرائی	16
ساکن خالی
parse_server_config_گہرائی(ServerOptions *options, ثابت حرف *filename,
    ساخت sshbuf *conf, ساخت include_list *includes,
    ساخت connection_info *connectinfo, صحیح flags, صحیح *activep, صحیح گہرائی)
{
	صحیح linenum, bad_options = 0;
	حرف *cp, *obuf, *cbuf;

	اگر (گہرائی < 0 || گہرائی > SERVCONF_MAX_گہرائی)
		fatal("Too many recursive configuration includes");

	debug2_f("config %s len %zu%s", filename, sshbuf_len(conf),
	    (flags & SSHCFG_NEVERMATCH ? " [checking syntax only]" : ""));

	اگر ((obuf = cbuf = sshbuf_dup_string(conf)) == تہی)
		fatal_f("sshbuf_dup_string failed");
	linenum = 1;
	جب ((cp = strsep(&cbuf, "\n")) != تہی) {
		اگر (process_server_config_سطر_گہرائی(options, cp,
		    filename, linenum++, activep, connectinfo, &flags,
		    گہرائی, includes) != 0)
			bad_options++;
	}
	آزاد(obuf);
	اگر (bad_options > 0)
		fatal("%s: terminating, %d bad configuration options",
		    filename, bad_options);
}

خالی
parse_server_config(ServerOptions *options, ثابت حرف *filename,
    ساخت sshbuf *conf, ساخت include_list *includes,
    ساخت connection_info *connectinfo, صحیح reexec)
{
	صحیح فعال = connectinfo ? 0 : 1;
	parse_server_config_گہرائی(options, filename, conf, includes,
	    connectinfo, (connectinfo ? SSHCFG_مطابقت_ONLY : 0), &فعال, 0);
	اگر (!reexec)
		process_queued_listen_addrs(options);
}

ساکن ثابت حرف *
fmt_multistate_int(صحیح val, ثابت ساخت multistate *m)
{
	u_int i;

	برائے (i = 0; m[i].کلید != تہی; i++) {
		اگر (m[i].قدر == val)
			واپس m[i].کلید;
	}
	واپس "UNKNOWN";
}

ساکن ثابت حرف *
fmt_intarg(ServerOpCodes رمز, صحیح val)
{
	اگر (val == -1)
		واپس "unset";
	انتخاب (رمز) {
	حالت s_پتہ_Family:
		واپس fmt_multistate_int(val, multistate_addressfamily);
	حالت s_Permit_جڑ_Login:
		واپس fmt_multistate_int(val, multistate_permitrootlogin);
	حالت sGatewayPorts:
		واپس fmt_multistate_int(val, multistate_gatewayports);
	حالت sCompression:
		واپس fmt_multistate_int(val, multistate_compression);
	حالت sAllowTcpForwarding:
		واپس fmt_multistate_int(val, multistate_tcpfwd);
	حالت s_Allow_دھارا_Local_Forwarding:
		واپس fmt_multistate_int(val, multistate_tcpfwd);
	حالت sIgnoreRhosts:
		واپس fmt_multistate_int(val, multistate_ignore_rhosts);
	حالت sTCPKeepAlive:
		واپس fmt_multistate_int(val, multistate_keepalives);
	حالت sWarnWeakCrypto:
		واپس fmt_multistate_int(val, multistate_warnweakcrypto);
	حالت sFingerprintHash:
		واپس ssh_digest_alg_name(val);
	طےشدہ:
		انتخاب (val) {
		حالت 0:
			واپس "no";
		حالت 1:
			واپس "yes";
		طےشدہ:
			واپس "UNKNOWN";
		}
	}
}

ساکن خالی
dump_cfg_int(ServerOpCodes رمز, صحیح val)
{
	اگر (رمز == s_غیر_مستعمل_Connection_Timeout && val == 0) {
		لکھو("%s none\n", lookup_opcode_name(رمز));
		واپس;
	}
	لکھو("%s %d\n", lookup_opcode_name(رمز), val);
}

ساکن خالی
dump_cfg_oct(ServerOpCodes رمز, صحیح val)
{
	لکھو("%s 0%o\n", lookup_opcode_name(رمز), val);
}

ساکن خالی
dump_cfg_fmtint(ServerOpCodes رمز, صحیح val)
{
	لکھو("%s %s\n", lookup_opcode_name(رمز), fmt_intarg(رمز, val));
}

ساکن خالی
dump_cfg_string(ServerOpCodes رمز, ثابت حرف *val)
{
	لکھو("%s %s\n", lookup_opcode_name(رمز),
	    val == تہی ? "none" : val);
}

ساکن خالی
dump_cfg_strarray(ServerOpCodes رمز, u_int گنتی, حرف **vals)
{
	u_int i;

	برائے (i = 0; i < گنتی; i++)
		لکھو("%s %s\n", lookup_opcode_name(رمز), vals[i]);
}

ساکن خالی
dump_cfg_strarray_oneline(ServerOpCodes رمز, u_int گنتی, حرف **vals)
{
	u_int i;

	انتخاب (رمز) {
	حالت sAuthenticationMethods:
	حالت sChannelTimeout:
		توڑو;
	طےشدہ:
		اگر (گنتی <= 0)
			واپس;
		توڑو;
	}

	لکھو("%s", lookup_opcode_name(رمز));
	برائے (i = 0; i < گنتی; i++)
		لکھو(" %s",  vals[i]);
	اگر (رمز == sAuthenticationMethods && گنتی == 0)
		لکھو(" any");
	ورنہ اگر (رمز == sChannelTimeout && گنتی == 0)
		لکھو(" none");
	لکھو("\n");
}

ساکن حرف *
format_listen_addrs(ساخت listenaddr *la)
{
	صحیح r;
	ساخت addrinfo *ai;
	حرف addr[NI_MAXHOST], پورٹ[NI_MAXSERV];
	حرف *laddr1 = xstrdup(""), *laddr2 = تہی;

	/*
	 * ListenAddress must be after Port.  add_one_listen_addr pushes
	 * addresses onto a stack, so to maintain ordering we need to
	 * print these in reverse order.
	 */
	برائے (ai = la->addrs; ai; ai = ai->ai_next) {
		اگر ((r = getnameinfo(ai->ai_addr, ai->ai_addrlen, addr,
		    حجم(addr), پورٹ, حجم(پورٹ),
		    NI_NUMERICHOST|NI_NUMERICSERV)) != 0) {
			error("getnameinfo: %.100s", ssh_gai_strerror(r));
			جاری;
		}
		laddr2 = laddr1;
		اگر (ai->ai_family == AF_INET6) {
			xasprintf(&laddr1, "ListenAddress [%s]:%s%s%s\n%s",
			    addr, پورٹ,
			    la->rdomain == تہی ? "" : " rdomain ",
			    la->rdomain == تہی ? "" : la->rdomain,
			    laddr2);
		} ورنہ {
			xasprintf(&laddr1, "ListenAddress %s:%s%s%s\n%s",
			    addr, پورٹ,
			    la->rdomain == تہی ? "" : " rdomain ",
			    la->rdomain == تہی ? "" : la->rdomain,
			    laddr2);
		}
		آزاد(laddr2);
	}
	واپس laddr1;
}

خالی
dump_config(ServerOptions *o)
{
	حرف *s;
	u_int i;

	/* these are usually at the top of the config */
	برائے (i = 0; i < o->عدد_ports; i++)
		لکھو("Port %d\n", o->ports[i]);
	dump_cfg_fmtint(s_پتہ_Family, o->پتہ_family);

	برائے (i = 0; i < o->عدد_listen_addrs; i++) {
		s = format_listen_addrs(&o->listen_addrs[i]);
		لکھو("%s", s);
		آزاد(s);
	}

	/* integer arguments */
#اگر_تعریف_شدہ USE_PAM
	dump_cfg_fmtint(sUsePAM, o->use_pam);
	dump_cfg_string(sPAMServiceName, o->pam_service_name);
#اگر_ختم
	dump_cfg_int(s_Login_Grace_وقت, o->login_grace_وقت);
	dump_cfg_int(s_X11_Display_انحراف, o->x11_display_انحراف);
	dump_cfg_int(sMaxAuthTries, o->max_authtries);
	dump_cfg_int(sMaxSessions, o->max_sessions);
	dump_cfg_int(sClientAliveInterval, o->client_alive_interval);
	dump_cfg_int(s_Client_Alive_گنتی_Max, o->client_alive_گنتی_max);
	dump_cfg_int(sRequiredRSASize, o->required_rsa_سائز);
	dump_cfg_oct(s_دھارا_Local_Bind_نقاب, o->fwd_opts.streamlocal_bind_نقاب);
	dump_cfg_int(s_غیر_مستعمل_Connection_Timeout, o->غیر_مستعمل_connection_timeout);

	/* formatted integer arguments */
	dump_cfg_fmtint(s_Permit_جڑ_Login, o->permit_جڑ_login);
	dump_cfg_fmtint(sIgnoreRhosts, o->ignore_rhosts);
	dump_cfg_fmtint(s_Ignore_User_معلوم_Hosts, o->ignore_user_معلوم_hosts);
	dump_cfg_fmtint(sHostbasedAuthentication, o->hostbased_authentication);
	dump_cfg_fmtint(s_Hostbased_استعمال_کرتا_Name_From_Packet_Only,
	    o->hostbased_استعمال_کرتا_name_from_packet_only);
	dump_cfg_fmtint(sPubkeyAuthentication, o->pubkey_authentication);
#اگر_تعریف_شدہ KRB5
	dump_cfg_fmtint(sKerberosAuthentication, o->kerberos_authentication);
	dump_cfg_fmtint(sKerberosOrLocalPasswd, o->kerberos_or_local_passwd);
	dump_cfg_fmtint(sKerberosTicketCleanup, o->kerberos_ticket_cleanup);
# ifdef USE_AFS
	dump_cfg_fmtint(sKerberosGetAFSToken, o->kerberos_get_afs_token);
# endif
#اگر_ختم
#اگر_تعریف_شدہ GSSAPI
	dump_cfg_fmtint(sGSSAPIAuthentication, o->gss_authentication);
	dump_cfg_fmtint(sGSSAPICleanupCredentials, o->gss_cleanup_creds);
	dump_cfg_fmtint(sGSSAPIDelegateCredentials, o->gss_deleg_creds);
	dump_cfg_fmtint(sGSSAPIStrictAcceptorCheck, o->gss_strict_acceptor);
#اگر_ختم
	dump_cfg_fmtint(sPasswordAuthentication, o->password_authentication);
	dump_cfg_fmtint(sKbdInteractiveAuthentication,
	    o->kbd_interactive_authentication);
	dump_cfg_fmtint(sPrintMotd, o->print_motd);
#اگر_غیر_تعریف_شدہ DISABLE_LASTLOG
	dump_cfg_fmtint(s_Print_آخری_Log, o->print_lastlog);
#اگر_ختم
	dump_cfg_fmtint(sX11Forwarding, o->x11_forwarding);
	dump_cfg_fmtint(sX11UseLocalhost, o->x11_use_localhost);
	dump_cfg_fmtint(sPermitTTY, o->permit_tty);
	dump_cfg_fmtint(sPermitUserRC, o->permit_user_rc);
	dump_cfg_fmtint(sStrictModes, o->strict_modes);
	dump_cfg_fmtint(sTCPKeepAlive, o->tcp_keep_alive);
	dump_cfg_fmtint(s_Permit_خالی_خانے_Passwords, o->permit_خالی_خانے_passwd);
	dump_cfg_fmtint(sCompression, o->compression);
	dump_cfg_fmtint(sGatewayPorts, o->fwd_opts.gateway_ports);
	dump_cfg_fmtint(sUseDNS, o->use_dns);
	dump_cfg_fmtint(sAllowTcpForwarding, o->allow_tcp_forwarding);
	dump_cfg_fmtint(sAllowAgentForwarding, o->allow_agent_forwarding);
	dump_cfg_fmtint(sDisableForwarding, o->disable_forwarding);
	dump_cfg_fmtint(s_Allow_دھارا_Local_Forwarding, o->allow_streamlocal_forwarding);
	dump_cfg_fmtint(s_دھارا_Local_Bind_Unlink, o->fwd_opts.streamlocal_bind_unlink);
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
	dump_cfg_string(sTrustedUserCAKeys, o->trusted_user_ca_کلیدیں);
	dump_cfg_string(s_Security_کلید_Provider, o->sk_provider);
	dump_cfg_string(sAuthorizedPrincipalsFile,
	    o->authorized_principals_file);
	dump_cfg_string(s_نسخہ_Addendum, *o->نسخہ_addendum == '\0'
	    ? "none" : o->نسخہ_addendum);
	dump_cfg_string(s_Authorized_کلیدیں_Command, o->authorized_کلیدیں_command);
	dump_cfg_string(s_Authorized_کلیدیں_Command_User, o->authorized_کلیدیں_command_user);
	dump_cfg_string(sAuthorizedPrincipalsCommand, o->authorized_principals_command);
	dump_cfg_string(sAuthorizedPrincipalsCommandUser, o->authorized_principals_command_user);
	dump_cfg_string(s_Host_کلید_Agent, o->host_کلید_agent);
	dump_cfg_string(sKexAlgorithms, o->kex_algorithms);
	dump_cfg_string(sCASignatureAlgorithms, o->ca_sign_algorithms);
	dump_cfg_string(sHostbasedAcceptedAlgorithms, o->hostbased_accepted_algos);
	dump_cfg_string(s_Host_کلید_Algorithms, o->hostkeyalgorithms);
	dump_cfg_string(sPubkeyAcceptedAlgorithms, o->pubkey_accepted_algos);
#اگر defined(__OpenBSD__) || defined(HAVE_SYS_سیٹ_PROCESS_RDOMAIN)
	dump_cfg_string(sRDomain, o->routing_domain);
#اگر_ختم
	dump_cfg_string(s_Sshd_Session_راستہ, o->sshd_session_راستہ);
	dump_cfg_string(s_Sshd_Auth_راستہ, o->sshd_auth_راستہ);
	dump_cfg_string(s_فی_ماخذ_Penalty_Exempt_List, o->فی_ماخذ_penalty_exempt);
	dump_cfg_string(s_Agent_Socket_راستہ, o->agent_socket_راستہ);

	/* string arguments requiring a lookup */
	dump_cfg_string(sLogLevel, log_level_name(o->log_level));
	dump_cfg_string(sSyslogFacility, log_facility_name(o->log_facility));

	/* string array arguments */
	dump_cfg_strarray_oneline(s_Authorized_کلیدیں_File, o->عدد_authkeys_files,
	    o->authorized_کلیدیں_files);
	dump_cfg_strarray_oneline(s_Revoked_کلیدیں, o->عدد_revoked_کلیدیں_files,
	    o->revoked_کلیدیں_files);
	dump_cfg_strarray(s_Host_کلید, o->عدد_host_کلید_files, o->host_کلید_files);
	dump_cfg_strarray(sHostCertificate, o->عدد_host_cert_files,
	    o->host_cert_files);
	dump_cfg_strarray(sAllowUsers, o->عدد_allow_users, o->allow_users);
	dump_cfg_strarray(sDenyUsers, o->عدد_deny_users, o->deny_users);
	dump_cfg_strarray(sAllowGroups, o->عدد_allow_groups, o->allow_groups);
	dump_cfg_strarray(sDenyGroups, o->عدد_deny_groups, o->deny_groups);
	dump_cfg_strarray(sAcceptEnv, o->عدد_accept_env, o->accept_env);
	dump_cfg_strarray(s_سیٹ_Env, o->عدد_setenv, o->setenv);
	dump_cfg_strarray_oneline(sAuthenticationMethods,
	    o->عدد_auth_methods, o->auth_methods);
	dump_cfg_strarray_oneline(sLogVerbose,
	    o->عدد_log_verbose, o->log_verbose);
	dump_cfg_strarray_oneline(sChannelTimeout,
	    o->عدد_channel_timeouts, o->channel_timeouts);

	/* other arguments */
	برائے (i = 0; i < o->عدد_subsystems; i++)
		لکھو("Subsystem %s %s\n", o->subsystem_name[i],
		    o->subsystem_دلائل[i]);

	لکھو("MaxStartups %d:%d:%d\n", o->max_startups_begin,
	    o->max_startups_شرح, o->max_startups);
	لکھو("PerSourceMaxStartups ");
	اگر (o->فی_ماخذ_max_startups == زیادہ_سے_زیادہ_عدد)
		لکھو("none\n");
	ورنہ
		لکھو("%d\n", o->فی_ماخذ_max_startups);
	لکھو("PerSourceNetBlockSize %d:%d\n", o->فی_ماخذ_masklen_ipv4,
	    o->فی_ماخذ_masklen_ipv6);

	s = تہی;
	برائے (i = 0; tunmode_desc[i].val != -1; i++) {
		اگر (tunmode_desc[i].val == o->permit_tun) {
			s = tunmode_desc[i].متن;
			توڑو;
		}
	}
	dump_cfg_string(sPermitTunnel, s);

	لکھو("IPQoS %s ", iptos2str(o->ip_qos_interactive));
	لکھو("%s\n", iptos2str(o->ip_qos_bulk));

	لکھو("RekeyLimit %llu %d\n", (غیرعلامتی طویل طویل)o->rekey_حد_بندی,
	    o->rekey_interval);

	لکھو("PermitOpen");
	اگر (o->عدد_permitted_opens == 0)
		لکھو(" any");
	ورنہ {
		برائے (i = 0; i < o->عدد_permitted_opens; i++)
			لکھو(" %s", o->permitted_opens[i]);
	}
	لکھو("\n");
	لکھو("PermitListen");
	اگر (o->عدد_permitted_listens == 0)
		لکھو(" any");
	ورنہ {
		برائے (i = 0; i < o->عدد_permitted_listens; i++)
			لکھو(" %s", o->permitted_listens[i]);
	}
	لکھو("\n");

	اگر (o->permit_user_env_allowlist == تہی) {
		dump_cfg_fmtint(sPermitUserEnvironment, o->permit_user_env);
	} ورنہ {
		لکھو("PermitUserEnvironment %s\n",
		    o->permit_user_env_allowlist);
	}

	لکھو("PubkeyAuthOptions");
	اگر (o->pubkey_auth_options == 0)
		لکھو(" none");
	اگر (o->pubkey_auth_options & PUBKEYAUTH_TOUCH_REQUIRED)
		لکھو(" touch-required");
	اگر (o->pubkey_auth_options & PUBKEYAUTH_VERIFY_REQUIRED)
		لکھو(" verify-required");
	اگر (o->max_pubkey_ok != -1)
		لکھو(" max-pk-ok:%d", o->max_pubkey_ok);
	لکھو("\n");

	اگر (o->فی_ماخذ_penalty.enabled) {
		لکھو("PerSourcePenalties crash:%f authfail:%f noauth:%f "
		    "invaliduser:%f "
		    "grace-exceeded:%f refuseconnection:%f max:%f min:%f "
		    "max-sources4:%d max-sources6:%d "
		    "overflow:%s overflow6:%s\n",
		    o->فی_ماخذ_penalty.penalty_crash,
		    o->فی_ماخذ_penalty.penalty_authfail,
		    o->فی_ماخذ_penalty.penalty_noauth,
		    o->فی_ماخذ_penalty.penalty_invaliduser,
		    o->فی_ماخذ_penalty.penalty_grace,
		    o->فی_ماخذ_penalty.penalty_refuseconnection,
		    o->فی_ماخذ_penalty.penalty_max,
		    o->فی_ماخذ_penalty.penalty_min,
		    o->فی_ماخذ_penalty.max_sources4,
		    o->فی_ماخذ_penalty.max_sources6,
		    o->فی_ماخذ_penalty.حد_سے_تجاوز_منوال ==
		    فی_ماخذ_PENALTY_حد_سے_تجاوز_DENY_ALL ?
		    "deny-all" : "permissive",
		    o->فی_ماخذ_penalty.حد_سے_تجاوز_mode6 ==
		    فی_ماخذ_PENALTY_حد_سے_تجاوز_DENY_ALL ?
		    "deny-all" : "permissive");
	} ورنہ
		لکھو("PerSourcePenalties no\n");
}
