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
#اگر_تعریف_شده __OpenBSD__
#ضمن <sys/sysctl.h>
#پایان_اگر

#ضمن <netinet/in.h>
#ضمن <netinet/ip.h>
#اگر_تعریف_شده HAVE_NET_ROUTE_H
#ضمن <net/route.h>
#پایان_اگر

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

#تعریف_کن SSHD_CONFIG_BLOB_نسخه	1

#إذا !defined(SSHD_PAM_SERVICE)
# define SSHD_PAM_SERVICE		"sshd"
#پایان_اگر

ساكن فراغ جمع_کن_listen_addr(ServerOptions *, ثابت حرف *,
    ثابت حرف *, صحيح);
ساكن فراغ جمع_کن_one_listen_addr(ServerOptions *, ثابت حرف *,
    ثابت حرف *, صحيح);
ساكن فراغ parse_server_config_عمق(ServerOptions *options,
    ثابت حرف *filename, بنية sshbuf *conf, بنية include_list *includes,
    بنية connection_info *connectinfo, صحيح flags, صحيح *activep, صحيح عمق);

خارجي بنية sshbuf *cfg;

/* Initializes the server options to their default values. */

فراغ
initialize_server_options(ServerOptions *options)
{
	memset(options, 0, حجم(*options));
#تعریف_کن SSHCONF_INT(var, conf, flags, ms, def, cp)	options->var = -1;
#تعریف_کن SSHCONF_INTFLAG(var, conf, flags, def, cp)	options->var = -1;
#تعریف_کن SSHCONF_STRING(var, conf, flags, cp)		options->var = عدم;
#تعریف_کن SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	options->nvar = 0; \
	options->var = عدم;
#تعریف_کن SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	init_##funcsuffix(options)
#تعریف_کن SSHCONF_NONCONF(funcsuffix) \
	init_##funcsuffix(options)
#تعریف_کن SSHCONF_DEPRECATE(conf, flags, opcode)		/*خالی*/
#تعریف_کن SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#تعریف_کن SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	options->var = عدم;
#تعریف_کن SSHCONF_ALIAS(old, conf, flags)			/*خالی*/

	/* Using macros for these is a bit overkill but forces consistency */
#تعریف_کن init_hostkeyfile(options) \
	options->host_کلید_files = 0; \
	options->رقم_host_کلید_files = 0; \
	options->host_کلید_file_userprovided = عدم;
#تعریف_کن init_ipqos(options) \
	options->ip_qos_interactive = -1; \
	options->ip_qos_bulk = -1;
#تعریف_کن init_listenaddress(options) \
	options->queued_listen_addrs = عدم; \
	options->رقم_queued_listens = 0; \
	options->listen_addrs = عدم; \
	options->رقم_listen_addrs = 0;
#تعریف_کن init_logfacility(options) \
	options->log_facility = SYSLOG_FACILITY_NOT_مجموعه;
#تعریف_کن init_loglevel(options) \
	options->log_level = SYSLOG_LEVEL_NOT_مجموعه;
#تعریف_کن init_پورت(options) \
	options->رقم_ports = 0; \
	options->ports_from_cmdline = 0;
#تعریف_کن init_gatewayports(options) \
	options->fwd_opts.gateway_ports = -1;
#تعریف_کن init_streamlocalbindmask(options) \
	options->fwd_opts.streamlocal_bind_ماسک = (نما_t)-1;
#تعریف_کن init_streamlocalbindunlink(options) \
	options->fwd_opts.streamlocal_bind_unlink = -1;
#تعریف_کن init_maxstartups(options) \
	options->max_startups_begin = -1; \
	options->max_startups_نرخ = -1; \
	options->max_startups = -1;
#تعریف_کن init_permituserenv(options) \
	options->permit_user_env = -1; \
	options->permit_user_env_allowlist = عدم;
#تعریف_کن init_persourcenetblocksize(options) \
	options->در_هر_منبع_masklen_ipv4 = -1; \
	options->در_هر_منبع_masklen_ipv6 = -1;
#تعریف_کن init_persourcepenalties(options) \
	options->در_هر_منبع_penalty_exempt = عدم; \
	options->در_هر_منبع_penalty.enabled = -1; \
	options->در_هر_منبع_penalty.max_sources4 = -1; \
	options->در_هر_منبع_penalty.max_sources6 = -1; \
	options->در_هر_منبع_penalty.سرریز_نما = -1; \
	options->در_هر_منبع_penalty.سرریز_mode6 = -1; \
	options->در_هر_منبع_penalty.penalty_crash = -1.0; \
	options->در_هر_منبع_penalty.penalty_authfail = -1.0; \
	options->در_هر_منبع_penalty.penalty_invaliduser = -1.0; \
	options->در_هر_منبع_penalty.penalty_noauth = -1.0; \
	options->در_هر_منبع_penalty.penalty_grace = -1.0; \
	options->در_هر_منبع_penalty.penalty_refuseconnection = -1.0; \
	options->در_هر_منبع_penalty.penalty_max = -1.0; \
	options->در_هر_منبع_penalty.penalty_min = -1.0;
#تعریف_کن init_rekeylimit(options) \
	options->rekey_حد = -1; \
	options->rekey_interval = -1;
#تعریف_کن init_subsystem(options) \
	options->رقم_subsystems = 0; \
	options->subsystem_name = عدم; \
	options->subsystem_command = عدم; \
	options->subsystem_آرگومانها = عدم;
#تعریف_کن init_pubkey_auth_options(options) \
	options->pubkey_auth_options = -1; \
	options->max_pubkey_ok = -1;
#تعریف_کن init_timingsecret(options) \
	options->timing_secret = 0;

	SSHD_CONFIG_ENTRIES

#لغو_تعریف init_hostkeyfile
#لغو_تعریف init_ipqos
#لغو_تعریف init_listenaddress
#لغو_تعریف init_logfacility
#لغو_تعریف init_loglevel
#لغو_تعریف init_پورت
#لغو_تعریف init_gatewayports
#لغو_تعریف init_streamlocalbindmask
#لغو_تعریف init_streamlocalbindunlink
#لغو_تعریف init_maxstartups
#لغو_تعریف init_permituserenv
#لغو_تعریف init_persourcenetblocksize
#لغو_تعریف init_persourcepenalties
#لغو_تعریف init_rekeylimit
#لغو_تعریف init_subsystem
#لغو_تعریف init_timingsecret
#لغو_تعریف SSHCONF_INT
#لغو_تعریف SSHCONF_INTFLAG
#لغو_تعریف SSHCONF_STRING
#لغو_تعریف SSHCONF_STRARRAY
#لغو_تعریف SSHCONF_CUSTOM
#لغو_تعریف SSHCONF_NONCONF
#لغو_تعریف SSHCONF_DEPRECATE
#لغو_تعریف SSHCONF_UNSUPPORTED_INT
#لغو_تعریف SSHCONF_UNSUPPORTED_STRING
#لغو_تعریف SSHCONF_ALIAS
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
	حرف *all_cipher, *all_mac, *all_kex, *all_کلید, *all_sig;
	حرف *def_cipher, *def_mac, *def_kex, *def_کلید, *def_sig;
	صحيح r;

	all_cipher = cipher_alg_list(',', 0);
	all_mac = mac_alg_list(',');
	all_kex = kex_alg_list(',');
	all_کلید = sshkey_alg_list(0, 0, 1, ',');
	all_sig = sshkey_alg_list(0, 1, 1, ',');
	/* remove unsupported algos from default lists */
	def_cipher = تطابق_filter_allowlist(KEX_SERVER_ENCRYPT, all_cipher);
	def_mac = تطابق_filter_allowlist(KEX_SERVER_MAC, all_mac);
	def_kex = تطابق_filter_allowlist(KEX_SERVER_KEX, all_kex);
	def_کلید = تطابق_filter_allowlist(KEX_DEFAULT_PK_ALG, all_کلید);
	def_sig = تطابق_filter_allowlist(SSH_ALLOWED_CA_SIGALGS, all_sig);
#تعریف_کن ASSEMBLE(what, defaults, all) \
	افعل { \
		إذا ((r = kex_assemble_نامها(&o->what, defaults, all)) != 0) \
			fatal_fr(r, "%s", #what); \
	} طالما (0)
	ASSEMBLE(ciphers, def_cipher, all_cipher);
	ASSEMBLE(macs, def_mac, all_mac);
	ASSEMBLE(kex_algorithms, def_kex, all_kex);
	ASSEMBLE(hostkeyalgorithms, def_کلید, all_کلید);
	ASSEMBLE(hostbased_accepted_algos, def_کلید, all_کلید);
	ASSEMBLE(pubkey_accepted_algos, def_کلید, all_کلید);
	ASSEMBLE(ca_sign_algorithms, def_sig, all_sig);
#لغو_تعریف ASSEMBLE
	حرر(all_cipher);
	حرر(all_mac);
	حرر(all_kex);
	حرر(all_کلید);
	حرر(all_sig);
	حرر(def_cipher);
	حرر(def_mac);
	حرر(def_kex);
	حرر(def_کلید);
	حرر(def_sig);
}

فراغ
servconf_جمع_کن_hostkey(ثابت حرف *file, ثابت صحيح سطر,
    ServerOptions *options, ثابت حرف *مسیر, صحيح userprovided)
{
	حرف *apath = derelativise_مسیر(مسیر);

	opt_array_append2(file, سطر, "HostKey",
	    &options->host_کلید_files, &options->host_کلید_file_userprovided,
	    &options->رقم_host_کلید_files, apath, userprovided);
	حرر(apath);
}

فراغ
servconf_جمع_کن_hostcert(ثابت حرف *file, ثابت صحيح سطر,
    ServerOptions *options, ثابت حرف *مسیر)
{
	حرف *apath = derelativise_مسیر(مسیر);

	opt_array_append(file, سطر, "HostCertificate",
	    &options->host_cert_files, &options->رقم_host_cert_files, apath);
	حرر(apath);
}

فراغ
fill_default_server_options(ServerOptions *options)
{
	u_int i;

	/* Portable-specific overrides */
#اگر_تعریف_شده SKIP_PRIVDROP
	إذا (options->allow_streamlocal_forwarding != -1 &&
	    options->allow_streamlocal_forwarding != FORWARD_DENY)
		logit("StreamlocalForwarding is not supported on this system");
	options->allow_streamlocal_forwarding = 0;
	إذا (options->fwd_opts.gateway_ports != -1 &&
	    options->fwd_opts.gateway_ports != 0)
		logit("GatewayPorts is not supported on this system");
	options->fwd_opts.gateway_ports = 0;
#پایان_اگر

#تعریف_کن SSHCONF_INT(var, conf, flags, ms, def, cp) \
	إذا (options->var == -1) \
		options->var = def;
#تعریف_کن SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	إذا (options->var == -1) \
		options->var = def;
#تعریف_کن SSHCONF_STRING(var, conf, flags, cp)		/* done manually */
#تعریف_کن SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	/* done manually */
#تعریف_کن SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	/* done manually */
#تعریف_کن SSHCONF_NONCONF(funcsuffix)			/* done manually */
#تعریف_کن SSHCONF_DEPRECATE(conf, flags, opcode)		/*خالی*/
#تعریف_کن SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#تعریف_کن SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	افعل { \
		حرر(options->var); \
		options->var = عدم; \
	} طالما (0);
#تعریف_کن SSHCONF_ALIAS(old, conf, flags)			/*خالی*/

	/* XXX maybe use macros here too to force consistency? */

	SSHD_CONFIG_ENTRIES

#لغو_تعریف SSHCONF_INT
#لغو_تعریف SSHCONF_INTFLAG
#لغو_تعریف SSHCONF_STRING
#لغو_تعریف SSHCONF_STRARRAY
#لغو_تعریف SSHCONF_CUSTOM
#لغو_تعریف SSHCONF_NONCONF
#لغو_تعریف SSHCONF_DEPRECATE
#لغو_تعریف SSHCONF_UNSUPPORTED_INT
#لغو_تعریف SSHCONF_UNSUPPORTED_STRING
#لغو_تعریف SSHCONF_ALIAS

#اگر_تعریف_شده USE_PAM
	إذا (options->pam_service_name == عدم)
		options->pam_service_name = xstrdup(SSHD_PAM_SERVICE);
#پایان_اگر

	إذا (options->رقم_host_کلید_files == 0) {
		/* fill default hostkeys */
		servconf_جمع_کن_hostkey("[default]", 0, options,
		    مسیر_HOST_RSA_کلید_FILE, 0);
		servconf_جمع_کن_hostkey("[default]", 0, options,
		    مسیر_HOST_ECDSA_کلید_FILE, 0);
		servconf_جمع_کن_hostkey("[default]", 0, options,
		    مسیر_HOST_ED25519_کلید_FILE, 0);
		servconf_جمع_کن_hostkey("[default]", 0, options,
		    مسیر_HOST_MLDSA44_ED25519_کلید_FILE, 0);
	}
	/* No certificates by default */
	إذا (options->رقم_ports == 0)
		options->ports[options->رقم_ports++] = SSH_DEFAULT_پورت;
	إذا (options->listen_addrs == عدم)
		جمع_کن_listen_addr(options, عدم, عدم, 0);
	إذا (options->pid_file == عدم)
		options->pid_file = xstrdup(مسیر_SSH_DAEMON_PID_FILE);
	إذا (options->moduli_file == عدم)
		options->moduli_file = xstrdup(مسیر_DH_MODULI);
	إذا (options->xauth_location == عدم)
		options->xauth_location = xstrdup(مسیر_XAUTH);
	إذا (options->log_facility == SYSLOG_FACILITY_NOT_مجموعه)
		options->log_facility = SYSLOG_FACILITY_AUTH;
	إذا (options->log_level == SYSLOG_LEVEL_NOT_مجموعه)
		options->log_level = SYSLOG_LEVEL_INFO;
	إذا (options->permit_user_env == -1) {
		options->permit_user_env = 0;
		options->permit_user_env_allowlist = عدم;
	}
	إذا (options->rekey_حد == -1)
		options->rekey_حد = 0;
	إذا (options->rekey_interval == -1)
		options->rekey_interval = 0;
	إذا (options->fwd_opts.gateway_ports == -1)
		options->fwd_opts.gateway_ports = 0;
	إذا (options->max_startups == -1)
		options->max_startups = 100;
	إذا (options->max_startups_نرخ == -1)
		options->max_startups_نرخ = 30;		/* 30% */
	إذا (options->max_startups_begin == -1)
		options->max_startups_begin = 10;
	إذا (options->در_هر_منبع_masklen_ipv4 == -1)
		options->در_هر_منبع_masklen_ipv4 = 32;
	إذا (options->در_هر_منبع_masklen_ipv6 == -1)
		options->در_هر_منبع_masklen_ipv6 = 128;
	إذا (options->در_هر_منبع_penalty.enabled == -1)
		options->در_هر_منبع_penalty.enabled = 1;
	إذا (options->در_هر_منبع_penalty.max_sources4 == -1)
		options->در_هر_منبع_penalty.max_sources4 = 65536;
	إذا (options->در_هر_منبع_penalty.max_sources6 == -1)
		options->در_هر_منبع_penalty.max_sources6 = 65536;
	إذا (options->در_هر_منبع_penalty.سرریز_نما == -1)
		options->در_هر_منبع_penalty.سرریز_نما = در_هر_منبع_PENALTY_سرریز_PERMISSIVE;
	إذا (options->در_هر_منبع_penalty.سرریز_mode6 == -1)
		options->در_هر_منبع_penalty.سرریز_mode6 = options->در_هر_منبع_penalty.سرریز_نما;
	إذا (options->در_هر_منبع_penalty.penalty_crash < 0.0)
		options->در_هر_منبع_penalty.penalty_crash = 90.0;
	إذا (options->در_هر_منبع_penalty.penalty_grace < 0.0)
		options->در_هر_منبع_penalty.penalty_grace = 10.0;
	إذا (options->در_هر_منبع_penalty.penalty_authfail < 0.0)
		options->در_هر_منبع_penalty.penalty_authfail = 5.0;
	إذا (options->در_هر_منبع_penalty.penalty_invaliduser < 0.0)
		options->در_هر_منبع_penalty.penalty_invaliduser = 5.0;
	إذا (options->در_هر_منبع_penalty.penalty_noauth < 0.0)
		options->در_هر_منبع_penalty.penalty_noauth = 1.0;
	إذا (options->در_هر_منبع_penalty.penalty_refuseconnection < 0.0)
		options->در_هر_منبع_penalty.penalty_refuseconnection = 10.0;
	إذا (options->در_هر_منبع_penalty.penalty_min < 0.0)
		options->در_هر_منبع_penalty.penalty_min = 15.0;
	إذا (options->در_هر_منبع_penalty.penalty_max < 0.0)
		options->در_هر_منبع_penalty.penalty_max = 600.0;
	إذا (options->رقم_authkeys_files == 0) {
		opt_array_append("[default]", 0, "AuthorizedKeysFiles",
		    &options->authorized_کلیدها_files,
		    &options->رقم_authkeys_files,
		    مسیر_SSH_USER_PERMITTED_کلیدها);
		opt_array_append("[default]", 0, "AuthorizedKeysFiles",
		    &options->authorized_کلیدها_files,
		    &options->رقم_authkeys_files,
		    مسیر_SSH_USER_PERMITTED_KEYS2);
	}
	إذا (options->ip_qos_interactive == -1)
		options->ip_qos_interactive = IPTOS_DSCP_EF;
	إذا (options->ip_qos_bulk == -1)
		options->ip_qos_bulk = IPTOS_DSCP_CS0;
	إذا (options->نسخه_addendum == عدم)
		options->نسخه_addendum = xstrdup("");
	إذا (options->fwd_opts.streamlocal_bind_ماسک == (نما_t)-1)
		options->fwd_opts.streamlocal_bind_ماسک = 0177;
	إذا (options->fwd_opts.streamlocal_bind_unlink == -1)
		options->fwd_opts.streamlocal_bind_unlink = 0;
	إذا (options->sk_provider == عدم)
		options->sk_provider = xstrdup("internal");
	إذا (options->sshd_session_مسیر == عدم)
		options->sshd_session_مسیر = xstrdup(مسیر_SSHD_SESSION);
	إذا (options->sshd_auth_مسیر == عدم)
		options->sshd_auth_مسیر = xstrdup(مسیر_SSHD_AUTH);
	إذا (options->pubkey_auth_options == -1) {
		options->pubkey_auth_options = 0;
		options->max_pubkey_ok = DEFAULT_AUTH_FAIL_MAX;
	}
	إذا (options->agent_socket_مسیر == عدم)
		options->agent_socket_مسیر = xstrdup(مسیر_SSH_AGENT_SOCKET_DIR);

	assemble_algorithms(options);

#تعریف_کن CLEAR_ON_NONE(v) \
	افعل { \
		إذا (option_clear_or_none(v)) { \
			حرر(v); \
			v = عدم; \
		} \
	} طالما(0)
#تعریف_کن CLEAR_ON_NONE_ARRAY(v, nv, none) \
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
	CLEAR_ON_NONE(options->trusted_user_ca_کلیدها);
	CLEAR_ON_NONE(options->sk_provider);
	CLEAR_ON_NONE(options->authorized_principals_file);
	CLEAR_ON_NONE(options->adm_forced_command);
	CLEAR_ON_NONE(options->chroot_directory);
	CLEAR_ON_NONE(options->routing_domain);
	CLEAR_ON_NONE(options->host_کلید_agent);
	CLEAR_ON_NONE(options->در_هر_منبع_penalty_exempt);
	CLEAR_ON_NONE(options->agent_socket_مسیر);

	لكل (i = 0; i < options->رقم_host_کلید_files; i++)
		CLEAR_ON_NONE(options->host_کلید_files[i]);
	لكل (i = 0; i < options->رقم_host_cert_files; i++)
		CLEAR_ON_NONE(options->host_cert_files[i]);

	CLEAR_ON_NONE_ARRAY(channel_timeouts, رقم_channel_timeouts, "none");
	CLEAR_ON_NONE_ARRAY(auth_methods, رقم_auth_methods, "any");
	CLEAR_ON_NONE_ARRAY(revoked_کلیدها_files, رقم_revoked_کلیدها_files, "none");
	CLEAR_ON_NONE_ARRAY(authorized_کلیدها_files, رقم_authkeys_files, "none");
#لغو_تعریف CLEAR_ON_NONE
#لغو_تعریف CLEAR_ON_NONE_ARRAY
}

/* Macros to declare ServerOpCodes enum values */
#تعریف_کن SSHCONF_INT(var, conf, flags, ms, def, cp)	s##conf,
#تعریف_کن SSHCONF_INTFLAG(var, conf, flags, def, cp)	s##conf,
#تعریف_کن SSHCONF_STRING(var, conf, flags, cp)		s##conf,
#تعریف_کن SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	s##conf,
#تعریف_کن SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	s##conf,
#تعریف_کن SSHCONF_NONCONF(funcsuffix)			/*خالی*/
#تعریف_کن SSHCONF_DEPRECATE(conf, flags, opcode)		/*خالی*/
#تعریف_کن SSHCONF_UNSUPPORTED_INT(var, conf, flags)	/*خالی*/
#تعریف_کن SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	/*خالی*/
#تعریف_کن SSHCONF_ALIAS(old, conf, flags)			/*خالی*/

/* Keyword tokens. */
تعريفنوع تعداد {
	sBadOption,		/* == unknown option */
	SSHD_CONFIG_ENTRIES
	s_تطابق, sInclude,
	sDeprecated, sIgnore, sUnsupported
} ServerOpCodes;
#لغو_تعریف SSHCONF_INT
#لغو_تعریف SSHCONF_INTFLAG
#لغو_تعریف SSHCONF_STRING
#لغو_تعریف SSHCONF_STRARRAY
#لغو_تعریف SSHCONF_CUSTOM
#لغو_تعریف SSHCONF_NONCONF
#لغو_تعریف SSHCONF_DEPRECATE
#لغو_تعریف SSHCONF_UNSUPPORTED_INT
#لغو_تعریف SSHCONF_UNSUPPORTED_STRING
#لغو_تعریف SSHCONF_ALIAS

#تعریف_کن SSHCFG_GLOBAL		0x01	/* allowed in main section of config */
#تعریف_کن SSHCFG_تطابق		0x02	/* allowed inside a Match section */
#تعریف_کن SSHCFG_ALL		(SSHCFG_GLOBAL|SSHCFG_تطابق)
#تعریف_کن SSHCFG_NEVERMATCH	0x04  /* Match never matches; internal only */
#تعریف_کن SSHCFG_تطابق_ONLY	0x08  /* Match only in conditional blocks; internal only */

/* Macros to define keywords[] entries */
#تعریف_کن SSHCONF_KW(conf, flags)		{ #conf, s##conf, flags },
#تعریف_کن SSHCONF_INT(var, conf, flags, ms, def, cp)	SSHCONF_KW(conf, flags)
#تعریف_کن SSHCONF_INTFLAG(var, conf, flags, def, cp)	SSHCONF_KW(conf, flags)
#تعریف_کن SSHCONF_STRING(var, conf, flags, cp)		SSHCONF_KW(conf, flags)
#تعریف_کن SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	SSHCONF_KW(conf, flags)
#تعریف_کن SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	SSHCONF_KW(conf, flags)
#تعریف_کن SSHCONF_NONCONF(funcsuffix)			/*خالی*/
#تعریف_کن SSHCONF_DEPRECATED				sDeprecated
#تعریف_کن SSHCONF_IGNORE					sIgnore
#تعریف_کن SSHCONF_DEPRECATE(conf, flags, opcode) \
	{ #conf, opcode, flags },
#تعریف_کن SSHCONF_UNSUPPORTED_INT(var, conf, flags) \
	{ #conf, sUnsupported, flags },
#تعریف_کن SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	{ #conf, sUnsupported, flags },
#تعریف_کن SSHCONF_ALIAS(old, conf, flags) \
	{ #old, s##conf, flags },

/* Textual representation of the tokens. */
ساكن بنية {
	ثابت حرف *name;
	ServerOpCodes opcode;
	u_int flags;
} keywords[] = {
	SSHD_CONFIG_ENTRIES
	{ "match", s_تطابق, SSHCFG_ALL },
	{ "include", sInclude, SSHCFG_ALL },
	{ عدم, sBadOption, 0 }
};
#لغو_تعریف SSHCONF_INT
#لغو_تعریف SSHCONF_INTFLAG
#لغو_تعریف SSHCONF_STRING
#لغو_تعریف SSHCONF_STRARRAY
#لغو_تعریف SSHCONF_CUSTOM
#لغو_تعریف SSHCONF_NONCONF
#لغو_تعریف SSHCONF_DEPRECATED
#لغو_تعریف SSHCONF_IGNORE
#لغو_تعریف SSHCONF_DEPRECATE
#لغو_تعریف SSHCONF_UNSUPPORTED_INT
#لغو_تعریف SSHCONF_UNSUPPORTED_STRING
#لغو_تعریف SSHCONF_ALIAS

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
lookup_opcode_name(ServerOpCodes کد)
{
	u_int i;

	لكل (i = 0; keywords[i].name != عدم; i++)
		إذا (keywords[i].opcode == کد)
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
derelativise_مسیر(ثابت حرف *مسیر)
{
	حرف *expanded, *ret, cwd[PATH_MAX];

	إذا (strcasecmp(مسیر, "none") == 0)
		أرجع xstrdup("none");
	expanded = tilde_expand_filename(مسیر, getuid());
	إذا (مسیر_absolute(expanded))
		أرجع expanded;
	إذا (getcwd(cwd, حجم(cwd)) == عدم)
		fatal_f("getcwd: %s", strerror(errno));
	xasprintf(&ret, "%s/%s", cwd, expanded);
	حرر(expanded);
	أرجع ret;
}

ساكن فراغ
جمع_کن_listen_addr(ServerOptions *options, ثابت حرف *addr,
    ثابت حرف *rdomain, صحيح پورت)
{
	u_int i;

	إذا (پورت > 0)
		جمع_کن_one_listen_addr(options, addr, rdomain, پورت);
	وإلا {
		لكل (i = 0; i < options->رقم_ports; i++) {
			جمع_کن_one_listen_addr(options, addr, rdomain,
			    options->ports[i]);
		}
	}
}

ساكن فراغ
جمع_کن_one_listen_addr(ServerOptions *options, ثابت حرف *addr,
    ثابت حرف *rdomain, صحيح پورت)
{
	بنية addrinfo hints, *ai, *aitop;
	حرف strport[NI_MAXSERV];
	صحيح gaierr;
	u_int i;

	/* Find listen_addrs entry for this rdomain */
	لكل (i = 0; i < options->رقم_listen_addrs; i++) {
		إذا (rdomain == عدم && options->listen_addrs[i].rdomain == عدم)
			اكسر;
		إذا (rdomain == عدم || options->listen_addrs[i].rdomain == عدم)
			استمر;
		إذا (strcmp(rdomain, options->listen_addrs[i].rdomain) == 0)
			اكسر;
	}
	إذا (i >= options->رقم_listen_addrs) {
		/* No entry for this rdomain; allocate one */
		إذا (i >= بیشترین_صحیح)
			fatal_f("too many listen addresses");
		options->listen_addrs = xrecallocarray(options->listen_addrs,
		    options->رقم_listen_addrs, options->رقم_listen_addrs + 1,
		    حجم(*options->listen_addrs));
		i = options->رقم_listen_addrs++;
		إذا (rdomain != عدم)
			options->listen_addrs[i].rdomain = xstrdup(rdomain);
	}
	/* options->listen_addrs[i] points to the addresses for this rdomain */

	memset(&hints, 0, حجم(hints));
	hints.ai_family = options->آدرس_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = (addr == عدم) ? AI_PASSIVE : 0;
	snprintf(strport, حجم strport, "%d", پورت);
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
	دراز دراز رقم;
	بنية rt_tableinfo info;
	صحيح mib[6];
	اندازه_t miblen = حجم(mib);

	إذا (name == عدم)
		أرجع 1;

	رقم = strtonum(name, 0, 255, &errstr);
	إذا (errstr != عدم)
		أرجع 0;

	/* Check whether the table actually exists */
	memset(mib, 0, حجم(mib));
	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[4] = NET_RT_جدول;
	mib[5] = (صحيح)رقم;
	إذا (sysctl(mib, 6, &info, &miblen, عدم, 0) == -1)
		أرجع 0;

	أرجع 1;
#وإلا /* defined(__OpenBSD__) */
	error("Routing domains are not supported on this platform");
	أرجع 0;
#پایان_اگر
}

/*
 * Queue a ListenAddress to be processed once we have all of the Ports
 * and AddressFamily options.
 */
ساكن فراغ
صف_listen_addr(ServerOptions *options, ثابت حرف *addr,
    ثابت حرف *rdomain, صحيح پورت)
{
	بنية queued_listenaddr *qla;

	options->queued_listen_addrs = xrecallocarray(
	    options->queued_listen_addrs,
	    options->رقم_queued_listens, options->رقم_queued_listens + 1,
	    حجم(*options->queued_listen_addrs));
	qla = &options->queued_listen_addrs[options->رقم_queued_listens++];
	qla->addr = xstrdup(addr);
	qla->پورت = پورت;
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

	إذا (options->رقم_ports == 0)
		options->ports[options->رقم_ports++] = SSH_DEFAULT_پورت;
	إذا (options->آدرس_family == -1)
		options->آدرس_family = AF_UNSPEC;

	لكل (i = 0; i < options->رقم_queued_listens; i++) {
		qla = &options->queued_listen_addrs[i];
		جمع_کن_listen_addr(options, qla->addr, qla->rdomain, qla->پورت);
		حرر(qla->addr);
		حرر(qla->rdomain);
	}
	حرر(options->queued_listen_addrs);
	options->queued_listen_addrs = عدم;
	options->رقم_queued_listens = 0;
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
تطابق_cfg_سطر_گروه(ثابت حرف *grps, صحيح سطر, ثابت حرف *user)
{
	صحيح نتیجه = 0;
	بنية passwd *pw;

	إذا (user == عدم)
		اذهب بیرون;

	إذا ((pw = getpwnam(user)) == عدم) {
		debug("Can't match group at line %d because user %.100s does "
		    "not exist", سطر, user);
	} وإلا إذا (ga_init(pw->pw_name, pw->pw_gid) == 0) {
		debug("Can't Match group because user %.100s not in any group "
		    "at line %d", user, سطر);
	} وإلا إذا (ga_تطابق_الگو_list(grps) != 1) {
		debug("user %.100s does not match group list %.100s at line %d",
		    user, grps, سطر);
	} وإلا {
		debug("user %.100s matched group list %.100s at line %d", user,
		    grps, سطر);
		نتیجه = 1;
	}
بیرون:
	ga_free();
	أرجع نتیجه;
}

ساكن فراغ
تطابق_test_missing_fatal(ثابت حرف *criteria, ثابت حرف *attrib)
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
تطابق_cfg_سطر(ثابت حرف *پر_سطر, صحيح *acp, حرف ***avp,
    صحيح سطر, بنية connection_info *ci)
{
	صحيح نتیجه = 1, صفات = 0, پورت;
	حرف *arg, *attrib = عدم, *oattrib;

	إذا (ci == عدم) {
		debug3("checking syntax for 'Match %s' on line %d",
		    پر_سطر, سطر);
	} وإلا {
		debug3("checking match for '%s' user %s%s host %s addr %s "
		    "laddr %s lport %d rdomain %s on line %d", پر_سطر,
		    ci->user ? ci->user : "(null)",
		    ci->user_invalid ? " (invalid)" : "",
		    ci->host ? ci->host : "(null)",
		    ci->آدرس ? ci->آدرس : "(null)",
		    ci->laddress ? ci->laddress : "(null)", ci->lport,
		    ci->rdomain ? ci->rdomain : "(null)", سطر);
	}

	طالما ((oattrib = argv_بعدی(acp, avp)) != عدم) {
		/* Terminate on comment */
		إذا (*oattrib == '#') {
			argv_consume(acp); /* mark all arguments consumed */
			اكسر;
		}
		attrib = xstrdup(oattrib);
		arg = عدم;
		صفات++;
		/* Criterion "all" has no argument and must appear alone */
		إذا (strcasecmp(attrib, "all") == 0) {
			إذا (صفات > 1 ||
			    ((arg = argv_بعدی(acp, avp)) != عدم &&
			    *arg != '\0' && *arg != '#')) {
				error("'all' cannot be combined with other "
				    "Match attributes");
				نتیجه = -1;
				اذهب بیرون;
			}
			إذا (arg != عدم && *arg == '#')
				argv_consume(acp); /* consume remaining args */
			نتیجه = 1;
			اذهب بیرون;
		}
		/* Criterion "invalid-user" also has no argument */
		إذا (strcasecmp(attrib, "invalid-user") == 0) {
			إذا (ci == عدم) {
				نتیجه = 0;
				اذهب بعدی;
			}
			إذا (ci->user_invalid == 0)
				نتیجه = 0;
			وإلا
				debug("matched invalid-user at line %d", سطر);
			اذهب بعدی;
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
			arg = argv_بعدی(acp, avp);
		}

		/* All other criteria require an argument */
		إذا (arg == عدم || *arg == '\0' || *arg == '#') {
			error("Missing Match criteria for %s", attrib);
			نتیجه = -1;
			اذهب بیرون;
		}
		إذا (strcasecmp(attrib, "user") == 0) {
			إذا (ci == عدم || (ci->test && ci->user == عدم)) {
				نتیجه = 0;
				اذهب بعدی;
			}
			إذا (ci->user == عدم)
				تطابق_test_missing_fatal("User", "user");
			إذا (تطابق_usergroup_الگو_list(ci->user, arg) != 1)
				نتیجه = 0;
			وإلا
				debug("user %.100s matched 'User %.100s' at "
				    "line %d", ci->user, arg, سطر);
		} وإلا إذا (strcasecmp(attrib, "group") == 0) {
			إذا (ci == عدم || (ci->test && ci->user == عدم)) {
				نتیجه = 0;
				اذهب بعدی;
			}
			إذا (ci->user == عدم)
				تطابق_test_missing_fatal("Group", "user");
			بدل (تطابق_cfg_سطر_گروه(arg, سطر, ci->user)) {
			حالة -1:
				نتیجه = -1;
				اذهب بیرون;
			حالة 0:
				نتیجه = 0;
			}
		} وإلا إذا (strcasecmp(attrib, "host") == 0) {
			إذا (ci == عدم || (ci->test && ci->host == عدم)) {
				نتیجه = 0;
				اذهب بعدی;
			}
			إذا (ci->host == عدم)
				تطابق_test_missing_fatal("Host", "host");
			إذا (تطابق_hostname(ci->host, arg) != 1)
				نتیجه = 0;
			وإلا
				debug("connection from %.100s matched 'Host "
				    "%.100s' at line %d", ci->host, arg, سطر);
		} وإلا إذا (strcasecmp(attrib, "address") == 0) {
			إذا (ci == عدم || (ci->test && ci->آدرس == عدم)) {
				إذا (addr_تطابق_list(عدم, arg) != 0)
					fatal("Invalid Match address argument "
					    "'%s' at line %d", arg, سطر);
				نتیجه = 0;
				اذهب بعدی;
			}
			إذا (ci->آدرس == عدم)
				تطابق_test_missing_fatal("Address", "addr");
			بدل (addr_تطابق_list(ci->آدرس, arg)) {
			حالة 1:
				debug("connection from %.100s matched 'Address "
				    "%.100s' at line %d", ci->آدرس, arg, سطر);
				اكسر;
			حالة 0:
			حالة -1:
				نتیجه = 0;
				اكسر;
			حالة -2:
				نتیجه = -1;
				اذهب بیرون;
			}
		} وإلا إذا (strcasecmp(attrib, "localaddress") == 0){
			إذا (ci == عدم || (ci->test && ci->laddress == عدم)) {
				إذا (addr_تطابق_list(عدم, arg) != 0)
					fatal("Invalid Match localaddress "
					    "argument '%s' at line %d", arg,
					    سطر);
				نتیجه = 0;
				اذهب بعدی;
			}
			إذا (ci->laddress == عدم)
				تطابق_test_missing_fatal("LocalAddress",
				    "laddr");
			بدل (addr_تطابق_list(ci->laddress, arg)) {
			حالة 1:
				debug("connection from %.100s matched "
				    "'LocalAddress %.100s' at line %d",
				    ci->laddress, arg, سطر);
				اكسر;
			حالة 0:
			حالة -1:
				نتیجه = 0;
				اكسر;
			حالة -2:
				نتیجه = -1;
				اذهب بیرون;
			}
		} وإلا إذا (strcasecmp(attrib, "localport") == 0) {
			إذا ((پورت = a2port(arg)) == -1) {
				error("Invalid LocalPort '%s' on Match line",
				    arg);
				نتیجه = -1;
				اذهب بیرون;
			}
			إذا (ci == عدم || (ci->test && ci->lport == -1)) {
				نتیجه = 0;
				اذهب بعدی;
			}
			إذا (ci->lport == 0)
				تطابق_test_missing_fatal("LocalPort", "lport");
			/* TODO support port lists */
			إذا (پورت == ci->lport)
				debug("connection from %.100s matched "
				    "'LocalPort %d' at line %d",
				    ci->laddress, پورت, سطر);
			وإلا
				نتیجه = 0;
		} وإلا إذا (strcasecmp(attrib, "rdomain") == 0) {
			إذا (ci == عدم || (ci->test && ci->rdomain == عدم)) {
				نتیجه = 0;
				اذهب بعدی;
			}
			إذا (ci->rdomain == عدم)
				تطابق_test_missing_fatal("RDomain", "rdomain");
			إذا (تطابق_الگو_list(ci->rdomain, arg, 0) != 1)
				نتیجه = 0;
			وإلا
				debug("connection RDomain %.100s matched "
				    "'RDomain %.100s' at line %d",
				    ci->rdomain, arg, سطر);
		} وإلا إذا (strcasecmp(attrib, "version") == 0) {
			إذا (تطابق_الگو_list(SSH_RELEASE, arg, 0) != 1)
				نتیجه = 0;
			وإلا
				debug("version %.100s matched "
				    "'version %.100s' at line %d",
				    SSH_RELEASE, arg, سطر);
		} وإلا {
			error("Unsupported Match attribute %s", oattrib);
			نتیجه = -1;
			اذهب بیرون;
		}
 بعدی:
		حرر(attrib);
		attrib = عدم;
	}
	إذا (صفات == 0) {
		error("One or more attributes required for Match");
		أرجع -1;
	}
 بیرون:
	إذا (ci != عدم && نتیجه != -1)
		debug3("match %sfound on line %d", نتیجه ? "" : "not ", سطر);
	حرر(attrib);
	أرجع نتیجه;
}

#تعریف_کن WHITESPACE " \t\r\n"

/* Multistate option parsing */
بنية multistate {
	حرف *کلید;
	صحيح مقدار;
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
#اگر_تعریف_شده WITH_ZLIB
	{ "yes",			COMP_DELAYED },
	{ "delayed",			COMP_DELAYED },
#پایان_اگر
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
process_server_config_سطر_عمق(ServerOptions *options, حرف *سطر,
    ثابت حرف *filename, صحيح linenum, صحيح *activep,
    بنية connection_info *connectinfo, صحيح *inc_flags, صحيح عمق,
    بنية include_list *includes)
{
	حرف *str, ***chararrayptr, **charptr, *arg, *arg2, *p, *keyword;
	صحيح cmdline = 0, *intptr, مقدار, value2, value3, n, پورت, oactive, r;
	مزدوج dvalue, *doubleptr = عدم;
	صحيح ca_only = 0, یافت = 0;
	SyslogFacility *log_facility_ptr;
	LogLevel *log_level_ptr;
	ServerOpCodes opcode;
	u_int i, *uintptr, flags = 0;
	اندازه_t len;
	دراز دراز val64;
	ثابت بنية multistate *multistate_ptr;
	ثابت حرف *errstr;
	بنية include_قلم *قلم;
	glob_t gbuf;
	حرف **oav = عدم, **av;
	صحيح oac = 0, ac;
	صحيح ret = -1;
	حرف **strs = عدم; /* string array arguments; freed implicitly */
	u_int nstrs = 0;

	/* Strip trailing whitespace. Allow \f (form feed) at EOL only */
	إذا ((len = طول_رشته(سطر)) == 0)
		أرجع 0;
	لكل (len--; len > 0; len--) {
		إذا (strchr(WHITESPACE "\f", سطر[len]) == عدم)
			اكسر;
		سطر[len] = '\0';
	}

	str = سطر;
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

	إذا (argv_تقسیم(str, &oac, &oav, 1) != 0) {
		error("%s line %d: invalid quotes", filename, linenum);
		أرجع -1;
	}
	ac = oac;
	av = oav;

	إذا (activep == عدم) { /* We are processing a command line directive */
		cmdline = 1;
		activep = &cmdline;
	}
	إذا (*activep && opcode != s_تطابق && opcode != sInclude)
		debug3("%s:%d setting %s %s", filename, linenum, keyword, str);
	إذا (*activep == 0 && !(flags & SSHCFG_تطابق)) {
		إذا (connectinfo == عدم) {
			fatal("%s line %d: Directive '%s' is not allowed "
			    "within a Match block", filename, linenum, keyword);
		} وإلا { /* this is a directive we have already processed */
			ret = 0;
			اذهب بیرون;
		}
	}

	بدل (opcode) {
	/* Portable-specific options */
#اگر_تعریف_شده USE_PAM
	حالة sUsePAM:
		intptr = &options->use_pam;
		اذهب parse_flag;
	حالة sPAMServiceName:
		charptr = &options->pam_service_name;
		arg = argv_بعدی(&ac, &av);
		إذا (!arg || *arg == '\0') {
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		}
		إذا (*activep && *charptr == عدم)
			*charptr = xstrdup(arg);
		اكسر;
#پایان_اگر

	/* Standard Options */
	حالة sBadOption:
		اذهب بیرون;
	حالة s_پورت:
		/* ignore ports from configfile if cmdline specifies ports */
		إذا (options->ports_from_cmdline) {
			argv_consume(&ac);
			اكسر;
		}
		إذا (options->رقم_ports >= MAX_PORTS)
			fatal("%s line %d: too many ports.",
			    filename, linenum);
		arg = argv_بعدی(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: missing port number.",
			    filename, linenum);
		options->ports[options->رقم_ports++] = a2port(arg);
		إذا (options->ports[options->رقم_ports-1] <= 0)
			fatal("%s line %d: Badly formatted port number.",
			    filename, linenum);
		اكسر;

	حالة s_Login_Grace_زمان:
		intptr = &options->login_grace_زمان;
 parse_زمان:
		arg = argv_بعدی(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: missing time value.",
			    filename, linenum);
		إذا ((مقدار = convtime(arg)) == -1)
			fatal("%s line %d: invalid time value.",
			    filename, linenum);
		إذا (*activep && *intptr == -1)
			*intptr = مقدار;
		اكسر;

	حالة s_Listen_آدرس:
		arg = argv_بعدی(&ac, &av);
		إذا (arg == عدم || *arg == '\0')
			fatal("%s line %d: missing address",
			    filename, linenum);
		/* check for bare IPv6 address: no "[]" and 2 or more ":" */
		إذا (strchr(arg, '[') == عدم && (p = strchr(arg, ':')) != عدم
		    && strchr(p+1, ':') != عدم) {
			پورت = 0;
			p = arg;
		} وإلا {
			arg2 = عدم;
			p = hpdelim(&arg);
			إذا (p == عدم)
				fatal("%s line %d: bad address:port usage",
				    filename, linenum);
			p = cleanhostname(p);
			إذا (arg == عدم)
				پورت = 0;
			وإلا إذا ((پورت = a2port(arg)) <= 0)
				fatal("%s line %d: bad port number",
				    filename, linenum);
		}
		/* Optional routing table */
		arg2 = عدم;
		إذا ((arg = argv_بعدی(&ac, &av)) != عدم) {
			إذا (strcmp(arg, "rdomain") != 0 ||
			    (arg2 = argv_بعدی(&ac, &av)) == عدم)
				fatal("%s line %d: bad ListenAddress syntax",
				    filename, linenum);
			إذا (!valid_rdomain(arg2))
				fatal("%s line %d: bad routing domain",
				    filename, linenum);
		}
		صف_listen_addr(options, p, arg2, پورت);

		اكسر;

	حالة s_آدرس_Family:
		intptr = &options->آدرس_family;
		multistate_ptr = multistate_addressfamily;
 parse_multistate:
		arg = argv_بعدی(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		مقدار = -1;
		لكل (i = 0; multistate_ptr[i].کلید != عدم; i++) {
			إذا (strcasecmp(arg, multistate_ptr[i].کلید) == 0) {
				مقدار = multistate_ptr[i].مقدار;
				اكسر;
			}
		}
		إذا (مقدار == -1)
			fatal("%s line %d: unsupported option \"%s\".",
			    filename, linenum, arg);
		إذا (*activep && *intptr == -1)
			*intptr = مقدار;
		اكسر;

	حالة s_Host_کلید:
		arg = argv_بعدی(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		إذا (*activep) {
			servconf_جمع_کن_hostkey(filename, linenum,
			    options, arg, 1);
		}
		اكسر;

	حالة s_Host_کلید_Agent:
		charptr = &options->host_کلید_agent;
		arg = argv_بعدی(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: missing socket name.",
			    filename, linenum);
		إذا (*activep && *charptr == عدم)
			*charptr = !strcmp(arg, SSH_AUTHSOCKET_ENV_NAME) ?
			    xstrdup(arg) : derelativise_مسیر(arg);
		اكسر;

	حالة sHostCertificate:
		arg = argv_بعدی(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		إذا (*activep)
			servconf_جمع_کن_hostcert(filename, linenum, options, arg);
		اكسر;

	حالة sPidFile:
		charptr = &options->pid_file;
 parse_filename:
		arg = argv_بعدی(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		إذا (*activep && *charptr == عدم) {
			*charptr = derelativise_مسیر(arg);
			/* increase optional counter */
			إذا (intptr != عدم)
				*intptr = *intptr + 1;
		}
		اكسر;

	حالة sModuliFile:
		charptr = &options->moduli_file;
		اذهب parse_filename;

	حالة s_Permit_ریشه_Login:
		intptr = &options->permit_ریشه_login;
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

	حالة s_Hostbased_استفاده_میکند_Name_From_Packet_Only:
		intptr = &options->hostbased_استفاده_میکند_name_from_packet_only;
		اذهب parse_flag;

	حالة sHostbasedAcceptedAlgorithms:
		charptr = &options->hostbased_accepted_algos;
		ca_only = 0;
 parse_pubkey_algos:
		arg = argv_بعدی(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: Missing argument.",
			    filename, linenum);
		إذا (*arg != '-' &&
		    !sshkey_نامها_valid2(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg, 1, ca_only))
			fatal("%s line %d: Bad key types '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		إذا (*activep && *charptr == عدم)
			*charptr = xstrdup(arg);
		اكسر;

	حالة s_Host_کلید_Algorithms:
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
		مقدار = 0;
		value2 = -1;
		طالما ((arg = argv_بعدی(&ac, &av)) != عدم) {
			إذا (strcasecmp(arg, "none") == 0)
				استمر;
			إذا (strcasecmp(arg, "touch-required") == 0)
				مقدار |= PUBKEYAUTH_TOUCH_REQUIRED;
			وإلا إذا (strcasecmp(arg, "verify-required") == 0)
				مقدار |= PUBKEYAUTH_VERIFY_REQUIRED;
			وإلا إذا (strncasecmp(arg, "max-pk-ok:", 10) == 0) {
				value2 = strtonum(arg + 10, 0, 255, &errstr);
				إذا (errstr != عدم) {
					error("%s line %d: bad %s max-pk-ok "
					    "value: %s", filename, linenum,
					keyword, errstr);
					اذهب بیرون;
				}
			} وإلا {
				error("%s line %d: unsupported %s option %s",
				    filename, linenum, keyword, arg);
				اذهب بیرون;
			}
		}
		إذا (*activep && options->pubkey_auth_options == -1) {
			options->pubkey_auth_options = مقدار;
			options->max_pubkey_ok = value2;
		}
		اكسر;

#اگر_تعریف_شده KRB5
	حالة sKerberosAuthentication:
		intptr = &options->kerberos_authentication;
		اذهب parse_flag;

	حالة sKerberosOrLocalPasswd:
		intptr = &options->kerberos_or_local_passwd;
		اذهب parse_flag;

	حالة sKerberosTicketCleanup:
		intptr = &options->kerberos_ticket_cleanup;
		اذهب parse_flag;
#اگر_تعریف_شده USE_AFS
	حالة sKerberosGetAFSToken:
		intptr = &options->kerberos_get_afs_token;
		اذهب parse_flag;
#پایان_اگر /* USE_AFS */
#پایان_اگر /* KRB5 */

#اگر_تعریف_شده GSSAPI
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
#پایان_اگر /* GSSAPI */

	حالة sPasswordAuthentication:
		intptr = &options->password_authentication;
		اذهب parse_flag;

	حالة sKbdInteractiveAuthentication:
		intptr = &options->kbd_interactive_authentication;
		اذهب parse_flag;

	حالة sPrintMotd:
		intptr = &options->print_motd;
		اذهب parse_flag;

#اگر_تعریف_نشده DISABLE_LASTLOG
	حالة s_Print_آخرین_Log:
		intptr = &options->print_lastlog;
		اذهب parse_flag;
#پایان_اگر

	حالة sX11Forwarding:
		intptr = &options->x11_forwarding;
		اذهب parse_flag;

	حالة s_X11_Display_جابه_جایی:
		intptr = &options->x11_display_جابه_جایی;
 parse_int:
		arg = argv_بعدی(&ac, &av);
		إذا ((errstr = atoi_err(arg, &مقدار)) != عدم)
			fatal("%s line %d: %s integer value %s.",
			    filename, linenum, keyword, errstr);
		إذا (*activep && *intptr == -1)
			*intptr = مقدار;
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

	حالة s_Permit_خالی_Passwords:
		intptr = &options->permit_خالی_passwd;
		اذهب parse_flag;

	حالة sPermitUserEnvironment:
		intptr = &options->permit_user_env;
		charptr = &options->permit_user_env_allowlist;
		arg = argv_بعدی(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		مقدار = 0;
		p = عدم;
		إذا (strcmp(arg, "yes") == 0)
			مقدار = 1;
		وإلا إذا (strcmp(arg, "no") == 0)
			مقدار = 0;
		وإلا {
			/* Pattern-list specified */
			مقدار = 1;
			p = xstrdup(arg);
		}
		إذا (*activep && *intptr == -1) {
			*intptr = مقدار;
			*charptr = p;
			p = عدم;
		}
		حرر(p);
		اكسر;

	حالة sCompression:
		intptr = &options->compression;
		multistate_ptr = multistate_compression;
		اذهب parse_multistate;

	حالة s_Rekey_حد:
		arg = argv_بعدی(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		إذا (strcmp(arg, "default") == 0) {
			val64 = 0;
		} وإلا {
			إذا (پیمایش_scaled(arg, &val64) == -1)
				fatal("%.200s line %d: Bad %s number '%s': %s",
				    filename, linenum, keyword,
				    arg, strerror(errno));
			إذا (val64 != 0 && val64 < 16)
				fatal("%.200s line %d: %s too small",
				    filename, linenum, keyword);
		}
		إذا (*activep && options->rekey_حد == -1)
			options->rekey_حد = val64;
		إذا (ac != 0) { /* optional rekey interval present */
			إذا (strcmp(av[0], "none") == 0) {
				(فراغ)argv_بعدی(&ac, &av);	/* discard */
				اكسر;
			}
			intptr = &options->rekey_interval;
			اذهب parse_زمان;
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
		arg = argv_بعدی(&ac, &av);
		مقدار = log_facility_عدد(arg);
		إذا (مقدار == SYSLOG_FACILITY_NOT_مجموعه)
			fatal("%.200s line %d: unsupported log facility '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
		إذا (*log_facility_ptr == -1)
			*log_facility_ptr = (SyslogFacility) مقدار;
		اكسر;

	حالة sLogLevel:
		log_level_ptr = &options->log_level;
		arg = argv_بعدی(&ac, &av);
		مقدار = log_level_عدد(arg);
		إذا (مقدار == SYSLOG_LEVEL_NOT_مجموعه)
			fatal("%.200s line %d: unsupported log level '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
		إذا (*activep && *log_level_ptr == -1)
			*log_level_ptr = (LogLevel) مقدار;
		اكسر;

	حالة sLogVerbose:
		یافت = options->رقم_log_verbose == 0;
		طالما ((arg = argv_بعدی(&ac, &av)) != عدم) {
			إذا (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				اذهب بیرون;
			}
			/* Allow "none" only in first position */
			إذا (strcasecmp(arg, "none") == 0) {
				إذا (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					اذهب بیرون;
				}
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		إذا (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		إذا (یافت && *activep) {
			options->log_verbose = strs;
			options->رقم_log_verbose = nstrs;
			strs = عدم; /* transferred */
			nstrs = 0;
		}
		اكسر;

	حالة sAllowTcpForwarding:
		intptr = &options->allow_tcp_forwarding;
		multistate_ptr = multistate_tcpfwd;
		اذهب parse_multistate;

	حالة s_Allow_جریان_Local_Forwarding:
		intptr = &options->allow_streamlocal_forwarding;
		multistate_ptr = multistate_tcpfwd;
		اذهب parse_multistate;

	حالة sAllowAgentForwarding:
		intptr = &options->allow_agent_forwarding;
		اذهب parse_flag;

	حالة s_Agent_Socket_مسیر:
		charptr = &options->agent_socket_مسیر;
		arg = argv_بعدی(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: missing path.", filename, linenum);
		إذا (مقایسه_رشته(arg, "shared:", 7) == 0) {
			/* Shared paths must be absolute */
			إذا (arg[7] != '/') {
				fatal("%s line %d: invalid shared path.",
				    filename, linenum);
			}
		} وإلا إذا (مقایسه_رشته(arg, "user:", 5) == 0) {
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
		uintptr = &options->رقم_allow_users;
 parse_allowdenyusers:
		/* XXX appends to list; doesn't respect first-match-wins */
		طالما ((arg = argv_بعدی(&ac, &av)) != عدم) {
			إذا (*arg == '\0' ||
			    تطابق_user(عدم, عدم, عدم, arg) == -1)
				fatal("%s line %d: invalid %s pattern: \"%s\"",
				    filename, linenum, keyword, arg);
			یافت = 1;
			إذا (!*activep)
				استمر;
			opt_array_append(filename, linenum, keyword,
			    chararrayptr, uintptr, arg);
		}
		إذا (!یافت) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		اكسر;

	حالة sDenyUsers:
		chararrayptr = &options->deny_users;
		uintptr = &options->رقم_deny_users;
		اذهب parse_allowdenyusers;

	حالة sAllowGroups:
		chararrayptr = &options->allow_groups;
		uintptr = &options->رقم_allow_groups;
		/* XXX appends to list; doesn't respect first-match-wins */
 parse_allowdenygroups:
		طالما ((arg = argv_بعدی(&ac, &av)) != عدم) {
			إذا (*arg == '\0')
				fatal("%s line %d: empty %s pattern",
				    filename, linenum, keyword);
			یافت = 1;
			إذا (!*activep)
				استمر;
			opt_array_append(filename, linenum, keyword,
			    chararrayptr, uintptr, arg);
		}
		إذا (!یافت) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		اكسر;

	حالة sDenyGroups:
		chararrayptr = &options->deny_groups;
		uintptr = &options->رقم_deny_groups;
		اذهب parse_allowdenygroups;

	حالة sCiphers:
		arg = argv_بعدی(&ac, &av);
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
		arg = argv_بعدی(&ac, &av);
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
		arg = argv_بعدی(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		إذا (*arg != '-' &&
		    !kex_نامها_valid(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 KexAlgorithms '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		إذا (options->kex_algorithms == عدم)
			options->kex_algorithms = xstrdup(arg);
		اكسر;

	حالة sSubsystem:
		إذا ((arg = argv_بعدی(&ac, &av)) == عدم || *arg == '\0' ||
		   ((arg2 = argv_بعدی(&ac, &av)) == عدم || *arg2 == '\0'))
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		إذا (!*activep) {
			argv_consume(&ac);
			اكسر;
		}
		یافت = 0;
		لكل (i = 0; i < options->رقم_subsystems; i++) {
			إذا (strcmp(arg, options->subsystem_name[i]) == 0) {
				یافت = 1;
				اكسر;
			}
		}
		إذا (یافت) {
			debug("%s line %d: Subsystem '%s' already defined.",
			    filename, linenum, arg);
			argv_consume(&ac);
			اكسر;
		}
		options->subsystem_name = xrecallocarray(
		    options->subsystem_name, options->رقم_subsystems,
		    options->رقم_subsystems + 1,
		    حجم(*options->subsystem_name));
		options->subsystem_command = xrecallocarray(
		    options->subsystem_command, options->رقم_subsystems,
		    options->رقم_subsystems + 1,
		    حجم(*options->subsystem_command));
		options->subsystem_آرگومانها = xrecallocarray(
		    options->subsystem_آرگومانها, options->رقم_subsystems,
		    options->رقم_subsystems + 1,
		    حجم(*options->subsystem_آرگومانها));
		options->subsystem_name[options->رقم_subsystems] = xstrdup(arg);
		options->subsystem_command[options->رقم_subsystems] =
		    xstrdup(arg2);
		/* Collect arguments (separate to executable) */
		arg = argv_assemble(1, &arg2); /* quote command correctly */
		arg2 = argv_assemble(ac, av); /* rest of command */
		xasprintf(&options->subsystem_آرگومانها[options->رقم_subsystems],
		    "%s%s%s", arg, *arg2 == '\0' ? "" : " ", arg2);
		حرر(arg2);
		حرر(arg);
		argv_consume(&ac);
		options->رقم_subsystems++;
		اكسر;

	حالة sMaxStartups:
		arg = argv_بعدی(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		/* begin:rate:max */
		إذا ((n = از_رشته_بخوان(arg, "%d:%d:%d",
		    &مقدار, &value2, &value3)) == 3) {
			إذا (مقدار > value3 || value2 > 100 || value2 < 1)
				fatal("%s line %d: Invalid %s spec.",
				    filename, linenum, keyword);
		} وإلا إذا (n == 1) {
			value3 = مقدار;
			value2 = -1;
		} وإلا {
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		}
		إذا (مقدار <= 0 || value3 <= 0)
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		إذا (*activep && options->max_startups == -1) {
			options->max_startups_begin = مقدار;
			options->max_startups_نرخ = value2;
			options->max_startups = value3;
		}
		اكسر;

	حالة s_در_هر_منبع_Net_بلوک_اندازه:
		arg = argv_بعدی(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		بدل (n = از_رشته_بخوان(arg, "%d:%d", &مقدار, &value2)) {
		حالة 2:
			إذا (value2 < 0 || value2 > 128)
				n = -1;
			/* FALLTHROUGH */
		حالة 1:
			إذا (مقدار < 0 || مقدار > 32)
				n = -1;
		}
		إذا (n != 1 && n != 2)
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		إذا (*activep && options->در_هر_منبع_masklen_ipv4 == -1) {
			options->در_هر_منبع_masklen_ipv4 = مقدار;
			إذا (n == 2)
				options->در_هر_منبع_masklen_ipv6 = value2;
		}
		اكسر;

	حالة s_در_هر_منبع_Max_Startups:
		arg = argv_بعدی(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		إذا (strcmp(arg, "none") == 0) { /* no limit */
			مقدار = بیشترین_صحیح;
		} وإلا {
			إذا ((errstr = atoi_err(arg, &مقدار)) != عدم)
				fatal("%s line %d: %s integer value %s.",
				    filename, linenum, keyword, errstr);
		}
		إذا (*activep && options->در_هر_منبع_max_startups == -1)
			options->در_هر_منبع_max_startups = مقدار;
		اكسر;

	حالة s_در_هر_منبع_Penalty_Exempt_List:
		charptr = &options->در_هر_منبع_penalty_exempt;
		arg = argv_بعدی(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		إذا (addr_تطابق_list(عدم, arg) != 0) {
			fatal("%s line %d: keyword %s "
			    "invalid address argument.",
			    filename, linenum, keyword);
		}
		إذا (*activep && *charptr == عدم)
			*charptr = xstrdup(arg);
		اكسر;

	حالة s_در_هر_منبع_Penalties:
		طالما ((arg = argv_بعدی(&ac, &av)) != عدم) {
			ثابت حرف *q = عدم;

			یافت = 1;
			intptr = عدم;
			doubleptr = عدم;
			مقدار = -1;
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
				    options->در_هر_منبع_penalty.enabled == -1)
					options->در_هر_منبع_penalty.enabled = value2;
				استمر;
			} وإلا إذا ((q = strprefix(arg, "crash:", 0)) != عدم) {
				doubleptr = &options->در_هر_منبع_penalty.penalty_crash;
			} وإلا إذا ((q = strprefix(arg, "authfail:", 0)) != عدم) {
				doubleptr = &options->در_هر_منبع_penalty.penalty_authfail;
			} وإلا إذا ((q = strprefix(arg, "invaliduser:", 0)) != عدم) {
				doubleptr = &options->در_هر_منبع_penalty.penalty_invaliduser;
			} وإلا إذا ((q = strprefix(arg, "noauth:", 0)) != عدم) {
				doubleptr = &options->در_هر_منبع_penalty.penalty_noauth;
			} وإلا إذا ((q = strprefix(arg, "grace-exceeded:", 0)) != عدم) {
				doubleptr = &options->در_هر_منبع_penalty.penalty_grace;
			} وإلا إذا ((q = strprefix(arg, "refuseconnection:", 0)) != عدم) {
				doubleptr = &options->در_هر_منبع_penalty.penalty_refuseconnection;
			} وإلا إذا ((q = strprefix(arg, "max:", 0)) != عدم) {
				doubleptr = &options->در_هر_منبع_penalty.penalty_max;
			} وإلا إذا ((q = strprefix(arg, "min:", 0)) != عدم) {
				doubleptr = &options->در_هر_منبع_penalty.penalty_min;
			} وإلا إذا ((q = strprefix(arg, "max-sources4:", 0)) != عدم) {
				intptr = &options->در_هر_منبع_penalty.max_sources4;
				إذا ((errstr = atoi_err(q, &مقدار)) != عدم)
					fatal("%s line %d: %s value %s.",
					    filename, linenum, keyword, errstr);
			} وإلا إذا ((q = strprefix(arg, "max-sources6:", 0)) != عدم) {
				intptr = &options->در_هر_منبع_penalty.max_sources6;
				إذا ((errstr = atoi_err(q, &مقدار)) != عدم)
					fatal("%s line %d: %s value %s.",
					    filename, linenum, keyword, errstr);
			} وإلا إذا (strcmp(arg, "overflow:deny-all") == 0) {
				intptr = &options->در_هر_منبع_penalty.سرریز_نما;
				مقدار = در_هر_منبع_PENALTY_سرریز_DENY_ALL;
			} وإلا إذا (strcmp(arg, "overflow:permissive") == 0) {
				intptr = &options->در_هر_منبع_penalty.سرریز_نما;
				مقدار = در_هر_منبع_PENALTY_سرریز_PERMISSIVE;
			} وإلا إذا (strcmp(arg, "overflow6:deny-all") == 0) {
				intptr = &options->در_هر_منبع_penalty.سرریز_mode6;
				مقدار = در_هر_منبع_PENALTY_سرریز_DENY_ALL;
			} وإلا إذا (strcmp(arg, "overflow6:permissive") == 0) {
				intptr = &options->در_هر_منبع_penalty.سرریز_mode6;
				مقدار = در_هر_منبع_PENALTY_سرریز_PERMISSIVE;
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
					options->در_هر_منبع_penalty.enabled = 1;
				}
			} وإلا إذا (intptr != عدم) {
				إذا (*activep && *intptr == -1) {
					*intptr = مقدار;
					options->در_هر_منبع_penalty.enabled = 1;
				}
			} وإلا {
				fatal_f("%s line %d: internal error",
				    filename, linenum);
			}
		}
		إذا (!یافت) {
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
	حالة s_Authorized_کلیدها_File:
		uintptr = &options->رقم_authkeys_files;
		chararrayptr = &options->authorized_کلیدها_files;
 parse_filenames:
		یافت = *uintptr == 0;
		طالما ((arg = argv_بعدی(&ac, &av)) != عدم) {
			إذا (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				اذهب بیرون;
			}
			/* Allow "none" only in first position */
			إذا (strcasecmp(arg, "none") == 0) {
				إذا (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					اذهب بیرون;
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
		إذا (یافت && *activep) {
			*chararrayptr = strs;
			*uintptr = nstrs;
			strs = عدم; /* transferred */
			nstrs = 0;
		}
		اكسر;

	حالة sAuthorizedPrincipalsFile:
		charptr = &options->authorized_principals_file;
		arg = argv_بعدی(&ac, &av);
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
		اذهب parse_زمان;

	حالة s_Client_Alive_شمار_Max:
		intptr = &options->client_alive_شمار_max;
		اذهب parse_int;

	حالة sAcceptEnv:
		/* XXX appends to list; doesn't respect first-match-wins */
		طالما ((arg = argv_بعدی(&ac, &av)) != عدم) {
			إذا (*arg == '\0' || strchr(arg, '=') != عدم)
				fatal("%s line %d: Invalid environment name.",
				    filename, linenum);
			یافت = 1;
			إذا (!*activep)
				استمر;
			opt_array_append(filename, linenum, keyword,
			    &options->accept_env, &options->رقم_accept_env,
			    arg);
		}
		إذا (!یافت) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		اكسر;

	حالة s_مجموعه_Env:
		یافت = options->رقم_setenv == 0;
		طالما ((arg = argv_بعدی(&ac, &av)) != عدم) {
			إذا (*arg == '\0' || strchr(arg, '=') == عدم)
				fatal("%s line %d: Invalid environment.",
				    filename, linenum);
			إذا (lookup_setenv_درون_list(arg, strs, nstrs) != عدم) {
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
		إذا (یافت && *activep) {
			options->setenv = strs;
			options->رقم_setenv = nstrs;
			strs = عدم; /* transferred */
			nstrs = 0;
		}
		اكسر;

	حالة sPermitTunnel:
		intptr = &options->permit_tun;
		arg = argv_بعدی(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		مقدار = -1;
		لكل (i = 0; tunmode_desc[i].val != -1; i++)
			إذا (strcmp(tunmode_desc[i].متن, arg) == 0) {
				مقدار = tunmode_desc[i].val;
				اكسر;
			}
		إذا (مقدار == -1)
			fatal("%s line %d: bad %s argument %s",
			    filename, linenum, keyword, arg);
		إذا (*activep && *intptr == -1)
			*intptr = مقدار;
		اكسر;

	حالة sInclude:
		إذا (cmdline) {
			fatal("Include directive not supported as a "
			    "command-line option");
		}
		مقدار = 0;
		طالما ((arg2 = argv_بعدی(&ac, &av)) != عدم) {
			إذا (*arg2 == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				اذهب بیرون;
			}
			مقدار++;
			یافت = 0;
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
			TAILQ_FOREACH(قلم, includes, مدخل) {
				إذا (strcmp(قلم->selector, arg) != 0)
					استمر;
				إذا (قلم->filename != عدم) {
					parse_server_config_عمق(options,
					    قلم->filename, قلم->contents,
					    includes, connectinfo,
					    (*inc_flags & SSHCFG_تطابق_ONLY
					        ? SSHCFG_تطابق_ONLY : (oactive
					            ? 0 : SSHCFG_NEVERMATCH)),
					    activep, عمق + 1);
				}
				یافت = 1;
				*activep = oactive;
			}
			إذا (یافت != 0) {
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
				قلم = xcalloc(1, حجم(*قلم));
				قلم->selector = xstrdup(arg);
				TAILQ_INSERT_TAIL(includes,
				    قلم, مدخل);
			}
			إذا (gbuf.gl_pathc > بیشترین_صحیح)
				fatal_f("too many glob results");
			لكل (n = 0; n < (صحيح)gbuf.gl_pathc; n++) {
				debug2("%s line %d: including %s",
				    filename, linenum, gbuf.gl_pathv[n]);
				قلم = xcalloc(1, حجم(*قلم));
				قلم->selector = xstrdup(arg);
				قلم->filename = xstrdup(gbuf.gl_pathv[n]);
				إذا ((قلم->contents = sshbuf_new()) == عدم)
					fatal_f("sshbuf_new failed");
				بارگیری_server_config(قلم->filename,
				    قلم->contents);
				parse_server_config_عمق(options,
				    قلم->filename, قلم->contents,
				    includes, connectinfo,
				    (*inc_flags & SSHCFG_تطابق_ONLY
				        ? SSHCFG_تطابق_ONLY : (oactive
				            ? 0 : SSHCFG_NEVERMATCH)),
				    activep, عمق + 1);
				*activep = oactive;
				TAILQ_INSERT_TAIL(includes, قلم, مدخل);
			}
			globfree(&gbuf);
			حرر(arg);
		}
		إذا (مقدار == 0) {
			fatal("%s line %d: %s missing filename argument",
			    filename, linenum, keyword);
		}
		اكسر;

	حالة s_تطابق:
		إذا (cmdline)
			fatal("Match directive not supported as a command-line "
			    "option");
		مقدار = تطابق_cfg_سطر(str, &ac, &av, linenum,
		    (*inc_flags & SSHCFG_NEVERMATCH ? عدم : connectinfo));
		إذا (مقدار < 0)
			fatal("%s line %d: Bad Match condition", filename,
			    linenum);
		*activep = (*inc_flags & SSHCFG_NEVERMATCH) ? 0 : مقدار;
		/*
		 * The MATCH_ONLY flag is applicable only until the first
		 * match block.
		 */
		*inc_flags &= ~SSHCFG_تطابق_ONLY;
		اكسر;

	حالة sPermitListen:
	حالة sPermitOpen:
		إذا (opcode == sPermitListen) {
			uintptr = &options->رقم_permitted_listens;
			chararrayptr = &options->permitted_listens;
		} وإلا {
			uintptr = &options->رقم_permitted_opens;
			chararrayptr = &options->permitted_opens;
		}
		یافت = *uintptr == 0;
		طالما ((arg = argv_بعدی(&ac, &av)) != عدم) {
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
			    ((پورت = permitopen_پورت(arg)) < 0)) {
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
		إذا (یافت && *activep) {
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

		arg = argv_بعدی(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		إذا (*activep && *charptr == عدم)
			*charptr = xstrdup(arg);
		اكسر;

	حالة sTrustedUserCAKeys:
		charptr = &options->trusted_user_ca_کلیدها;
		اذهب parse_filename;

	حالة s_Revoked_کلیدها:
		uintptr = &options->رقم_revoked_کلیدها_files;
		chararrayptr = &options->revoked_کلیدها_files;
		اذهب parse_filenames;

	حالة s_Security_کلید_Provider:
		charptr = &options->sk_provider;
		arg = argv_بعدی(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		إذا (*activep && *charptr == عدم) {
			*charptr = strcasecmp(arg, "internal") == 0 ?
			    xstrdup(arg) : derelativise_مسیر(arg);
			/* increase optional counter */
			إذا (intptr != عدم)
				*intptr = *intptr + 1;
		}
		اكسر;

	حالة sIPQoS:
		arg = argv_بعدی(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		إذا ((مقدار = parse_ipqos(arg)) == -1)
			fatal("%s line %d: Bad %s value: %s",
			    filename, linenum, keyword, arg);
		إذا (مقدار == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			مقدار = بیشترین_صحیح;
		}
		arg = argv_بعدی(&ac, &av);
		إذا (arg == عدم)
			value2 = مقدار;
		وإلا إذا ((value2 = parse_ipqos(arg)) == -1)
			fatal("%s line %d: Bad %s value: %s",
			    filename, linenum, keyword, arg);
		إذا (value2 == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			value2 = بیشترین_صحیح;
		}
		إذا (*activep && options->ip_qos_interactive == -1) {
			options->ip_qos_interactive = مقدار;
			options->ip_qos_bulk = value2;
		}
		اكسر;

	حالة s_نسخه_Addendum:
		إذا (str == عدم || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		إذا (strchr(str + len, '\r') != عدم) {
			fatal("%.200s line %d: Invalid %s argument",
			    filename, linenum, keyword);
		}
		إذا ((arg = strchr(سطر, '#')) != عدم) {
			*arg = '\0';
			rtrim(سطر);
		}
		إذا (*activep && options->نسخه_addendum == عدم) {
			إذا (strcasecmp(str + len, "none") == 0)
				options->نسخه_addendum = xstrdup("");
			وإلا
				options->نسخه_addendum = xstrdup(str + len);
		}
		argv_consume(&ac);
		اكسر;

	حالة s_Authorized_کلیدها_Command:
		charptr = &options->authorized_کلیدها_command;
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

	حالة s_Authorized_کلیدها_Command_User:
		charptr = &options->authorized_کلیدها_command_user;
 parse_localuser:
		arg = argv_بعدی(&ac, &av);
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
		یافت = options->رقم_auth_methods == 0;
		مقدار = 0; /* seen "any" pseudo-method */
		طالما ((arg = argv_بعدی(&ac, &av)) != عدم) {
			إذا (strcmp(arg, "any") == 0) {
				إذا (nstrs > 0) {
					fatal("%s line %d: \"any\" must "
					    "appear alone in %s",
					    filename, linenum, keyword);
				}
				مقدار = 1;
			} وإلا إذا (مقدار) {
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
		إذا (یافت && *activep) {
			options->auth_methods = strs;
			options->رقم_auth_methods = nstrs;
			strs = عدم; /* transferred */
			nstrs = 0;
		}
		اكسر;

	حالة s_جریان_Local_Bind_ماسک:
		arg = argv_بعدی(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		/* Parse mode in octal format */
		مقدار = strtol(arg, &p, 8);
		إذا (arg == p || مقدار < 0 || مقدار > 0777)
			fatal("%s line %d: Invalid %s.",
			    filename, linenum, keyword);
		إذا (*activep &&
		    options->fwd_opts.streamlocal_bind_ماسک == (نما_t)-1)
			options->fwd_opts.streamlocal_bind_ماسک = (نما_t)مقدار;
		اكسر;

	حالة s_جریان_Local_Bind_Unlink:
		intptr = &options->fwd_opts.streamlocal_bind_unlink;
		اذهب parse_flag;

	حالة sFingerprintHash:
		arg = argv_بعدی(&ac, &av);
		إذا (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		إذا ((مقدار = ssh_digest_alg_by_name(arg)) == -1)
			fatal("%.200s line %d: Invalid %s algorithm \"%s\".",
			    filename, linenum, keyword, arg);
		إذا (*activep)
			options->fingerprint_hash = مقدار;
		اكسر;

	حالة sExposeAuthInfo:
		intptr = &options->expose_userauth_info;
		اذهب parse_flag;

	حالة sRDomain:
#إذا !defined(__OpenBSD__) && !defined(HAVE_SYS_مجموعه_PROCESS_RDOMAIN)
		fatal("%s line %d: setting RDomain not supported on this "
		    "platform.", filename, linenum);
#پایان_اگر
		charptr = &options->routing_domain;
		arg = argv_بعدی(&ac, &av);
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
		intptr = &options->required_rsa_اندازه;
		اذهب parse_int;

	حالة sChannelTimeout:
		یافت = options->رقم_channel_timeouts == 0;
		طالما ((arg = argv_بعدی(&ac, &av)) != عدم) {
			/* Allow "none" only in first position */
			إذا (strcasecmp(arg, "none") == 0) {
				إذا (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					اذهب بیرون;
				}
			} وإلا إذا (parse_الگو_interval(arg,
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
		إذا (یافت && *activep) {
			options->channel_timeouts = strs;
			options->رقم_channel_timeouts = nstrs;
			strs = عدم; /* transferred */
			nstrs = 0;
		}
		اكسر;

	حالة s_استفادهنشده_Connection_Timeout:
		intptr = &options->استفادهنشده_connection_timeout;
		/* peek at first arg for "none" so we can reuse parse_time */
		إذا (av[0] != عدم && strcasecmp(av[0], "none") == 0) {
			(فراغ)argv_بعدی(&ac, &av); /* consume arg */
			إذا (*activep)
				*intptr = 0;
			اكسر;
		}
		اذهب parse_زمان;

	حالة s_Sshd_Session_مسیر:
		charptr = &options->sshd_session_مسیر;
		اذهب parse_filename;

	حالة s_Sshd_Auth_مسیر:
		charptr = &options->sshd_auth_مسیر;
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
		اذهب بیرون;
	}

	/* success */
	ret = 0;
 بیرون:
	opt_array_free2(strs, عدم, nstrs);
	argv_free(oav, oac);
	أرجع ret;
}

صحيح
process_server_config_سطر(ServerOptions *options, حرف *سطر,
    ثابت حرف *filename, صحيح linenum, صحيح *activep,
    بنية connection_info *connectinfo, بنية include_list *includes)
{
	صحيح inc_flags = 0;

	أرجع process_server_config_سطر_عمق(options, سطر, filename,
	    linenum, activep, connectinfo, &inc_flags, 0, includes);
}


/* Reads the server configuration file. */

فراغ
بارگیری_server_config(ثابت حرف *filename, بنية sshbuf *conf)
{
	بنية stat st;
	حرف *سطر = عدم, *cp;
	اندازه_t linesize = 0;
	FILE *f;
	صحيح r;

	debug2_f("filename %s", filename);
	إذا ((f = fopen(filename, "r")) == عدم) {
		perror(filename);
		خروج(1);
	}
	sshbuf_reset(conf);
	/* grow buffer, so realloc is avoided for large config files */
	إذا (fstat(fileno(f), &st) == 0 && st.st_size > 0 &&
	    (r = sshbuf_allocate(conf, st.st_size)) != 0)
		fatal_fr(r, "allocate");
	طالما (getline(&سطر, &linesize, f) != -1) {
		/*
		 * Strip whitespace
		 * NB - preserve newlines, they are needed to reproduce
		 * line numbers later for error messages
		 */
		cp = سطر + strspn(سطر, " \t\r");
		إذا ((r = sshbuf_put(conf, cp, طول_رشته(cp))) != 0)
			fatal_fr(r, "sshbuf_put");
	}
	حرر(سطر);
	إذا ((r = sshbuf_put_u8(conf, 0)) != 0)
		fatal_fr(r, "sshbuf_put_u8");
	fclose(f);
	debug2_f("done config len = %zu", sshbuf_len(conf));
}

فراغ
parse_server_تطابق_config(ServerOptions *options,
   بنية include_list *includes, بنية connection_info *connectinfo)
{
	ServerOptions mo;

	initialize_server_options(&mo);
	parse_server_config(&mo, "reprocess config", cfg, includes,
	    connectinfo, 0);
	copy_مجموعه_server_options(options, &mo, 0);
	free_server_options(&mo);
}

صحيح
parse_server_تطابق_testspec(بنية connection_info *ci, حرف *spec)
{
	حرف *p;
	ثابت حرف *val;

	طالما ((p = strsep(&spec, ",")) && *p != '\0') {
		إذا ((val = strprefix(p, "addr=", 0)) != عدم) {
			ci->آدرس = xstrdup(val);
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
servconf_ادغام_subsystems(ServerOptions *dst, ServerOptions *src)
{
	u_int i, j, یافت;

	لكل (i = 0; i < src->رقم_subsystems; i++) {
		یافت = 0;
		لكل (j = 0; j < dst->رقم_subsystems; j++) {
			إذا (strcmp(src->subsystem_name[i],
			    dst->subsystem_name[j]) == 0) {
				یافت = 1;
				اكسر;
			}
		}
		إذا (یافت) {
			debug_f("override \"%s\"", dst->subsystem_name[j]);
			حرر(dst->subsystem_command[j]);
			حرر(dst->subsystem_آرگومانها[j]);
			dst->subsystem_command[j] =
			    xstrdup(src->subsystem_command[i]);
			dst->subsystem_آرگومانها[j] =
			    xstrdup(src->subsystem_آرگومانها[i]);
			استمر;
		}
		debug_f("add \"%s\"", src->subsystem_name[i]);
		dst->subsystem_name = xrecallocarray(
		    dst->subsystem_name, dst->رقم_subsystems,
		    dst->رقم_subsystems + 1, حجم(*dst->subsystem_name));
		dst->subsystem_command = xrecallocarray(
		    dst->subsystem_command, dst->رقم_subsystems,
		    dst->رقم_subsystems + 1, حجم(*dst->subsystem_command));
		dst->subsystem_آرگومانها = xrecallocarray(
		    dst->subsystem_آرگومانها, dst->رقم_subsystems,
		    dst->رقم_subsystems + 1, حجم(*dst->subsystem_آرگومانها));
		j = dst->رقم_subsystems++;
		dst->subsystem_name[j] = xstrdup(src->subsystem_name[i]);
		dst->subsystem_command[j] = xstrdup(src->subsystem_command[i]);
		dst->subsystem_آرگومانها[j] = xstrdup(src->subsystem_آرگومانها[i]);
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
serialise_نما(بنية sshbuf *buf, نما_t v)
{
	u_int uv;

	إذا (v == (نما_t)-1)
		أرجع serialise_s32(buf, -1);
	uv = (u_int)v;
	إذا ((نما_t)uv != v || uv > 0777)
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

	إذا ((r = sshbuf_put_u32(buf, options->رقم_host_کلید_files)) != 0) {
		error_fr(r, "serialise length");
		أرجع r;
	}
	لكل (i = 0; i < options->رقم_host_کلید_files; i++) {
		إذا ((r = serialise_s32(buf,
		    options->host_کلید_file_userprovided[i])) != 0 ||
		    (r = serialise_nullable_string(buf,
		    options->host_کلید_files[i])) != 0) {
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
	إذا ((r = sshbuf_put_u32(buf, options->رقم_queued_listens)) != 0) {
		error_fr(r, "serialise length");
		أرجع r;
	}
	لكل (i = 0; i < options->رقم_queued_listens; i++) {
		ثابت بنية queued_listenaddr *qla =
		    options->queued_listen_addrs + i;

		إذا ((r = sshbuf_put_cstring(buf, qla->addr)) != 0 ||
		    (r = serialise_s32(buf, qla->پورت)) != 0 ||
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
serialise_پورت(ثابت ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;
	u_int i;

	إذا ((r = sshbuf_put_u32(buf, options->رقم_ports)) != 0) {
		error_fr(r, "serialise length");
		أرجع r;
	}
	لكل (i = 0; i < options->رقم_ports; i++) {
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

	إذا ((r = serialise_نما(buf,
	    options->fwd_opts.streamlocal_bind_ماسک)) != 0) {
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
	    (r = serialise_s32(buf, options->max_startups_نرخ)) != 0 ||
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

	إذا ((r = serialise_s32(buf, options->در_هر_منبع_masklen_ipv4)) != 0 ||
	    (r = serialise_s32(buf, options->در_هر_منبع_masklen_ipv6)) != 0) {
		error_fr(r, "serialise");
		أرجع r;
	}

	أرجع 0;
}

ساكن صحيح
serialise_persourcepenalties(ثابت ServerOptions *options, بنية sshbuf *buf)
{
	ثابت بنية در_هر_منبع_penalty *psp = &options->در_هر_منبع_penalty;
	صحيح r;

	إذا ((r = serialise_s32(buf, psp->enabled)) != 0 ||
	    (r = serialise_s32(buf, psp->max_sources4)) != 0 ||
	    (r = serialise_s32(buf, psp->max_sources6)) != 0 ||
	    (r = serialise_s32(buf, psp->سرریز_نما)) != 0 ||
	    (r = serialise_s32(buf, psp->سرریز_mode6)) != 0 ||
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

	إذا ((r = serialise_s64(buf, options->rekey_حد)) != 0 ||
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

	إذا ((r = sshbuf_put_u32(buf, options->رقم_subsystems)) != 0) {
		error_fr(r, "serialise length");
		أرجع r;
	}
	لكل (i = 0; i < options->رقم_subsystems; i++) {
		إذا ((r = sshbuf_put_cstring(buf,
		    options->subsystem_name[i])) != 0 ||
		    (r = sshbuf_put_cstring(buf,
		    options->subsystem_command[i])) != 0 ||
		    (r = sshbuf_put_cstring(buf,
		    options->subsystem_آرگومانها[i])) != 0) {
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
	صحيح r = SSH_ERR_داخلی_ERROR;

	*bufp = عدم;

	إذا ((buf = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshbuf_put_u32(buf, SSHD_CONFIG_BLOB_نسخه)) != 0) {
		error_fr(r, "serialise version");
		اذهب بیرون;
	}

#تعریف_کن SSHCONF_INT(var, conf, flags, ms, def, cp) \
	إذا ((r = serialise_s32(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		اذهب بیرون; \
	}
#تعریف_کن SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	إذا ((r = serialise_s32(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		اذهب بیرون; \
	}
#تعریف_کن SSHCONF_STRING(var, conf, flags, cp) \
	إذا ((r = serialise_nullable_string(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		اذهب بیرون; \
	}
#تعریف_کن SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	إذا ((r = serialise_nullable_string_array(buf, options->var, \
	    options->nvar)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		اذهب بیرون; \
	}
#تعریف_کن SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	إذا ((r = serialise_##funcsuffix(options, buf)) != 0) \
		اذهب بیرون;
#تعریف_کن SSHCONF_NONCONF(funcsuffix) \
	إذا ((r = serialise_##funcsuffix(options, buf)) != 0) \
		اذهب بیرون;
#تعریف_کن SSHCONF_DEPRECATE(conf, flags, opcode)		/*خالی*/
#تعریف_کن SSHCONF_UNSUPPORTED_INT(var, conf, flags)	/*خالی*/
#تعریف_کن SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	/*خالی*/
#تعریف_کن SSHCONF_ALIAS(old, conf, flags)			/*خالی*/

	SSHD_CONFIG_ENTRIES

#لغو_تعریف SSHCONF_INT
#لغو_تعریف SSHCONF_INTFLAG
#لغو_تعریف SSHCONF_STRING
#لغو_تعریف SSHCONF_STRARRAY
#لغو_تعریف SSHCONF_CUSTOM
#لغو_تعریف SSHCONF_NONCONF
#لغو_تعریف SSHCONF_DEPRECATE
#لغو_تعریف SSHCONF_UNSUPPORTED_INT
#لغو_تعریف SSHCONF_UNSUPPORTED_STRING
#لغو_تعریف SSHCONF_ALIAS

	/* success */
	r = 0;
	*bufp = buf;
	buf = عدم; /* transferred */
 بیرون:
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
		إذا (tmp > (uint32_t)بیشترین_صحیح + 1)
			أرجع SSH_ERR_INVALID_FORMAT;
		*v = tmp == (uint32_t)بیشترین_صحیح + 1 ? INT_MIN : -(صحيح)tmp;
	} وإلا {
		إذا (tmp > بیشترین_صحیح)
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
deserialise_نما(بنية sshbuf *buf, نما_t *v)
{
	صحيح r, tmp;

	إذا ((r = deserialise_s32(buf, &tmp)) != 0)
		أرجع r;
	إذا (tmp == -1) {
		*v = (نما_t)-1;
		أرجع 0;
	}
	إذا (tmp < 0 || tmp > 0777)
		أرجع SSH_ERR_INVALID_FORMAT;
	*v = (نما_t)tmp;
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
deserialise_شمار(بنية sshbuf *buf, u_int *np, ثابت حرف *what)
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
	إذا ((r = deserialise_شمار(buf, &n, "strings")) != 0)
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

	إذا ((r = deserialise_شمار(buf, &n, "host key files")) != 0)
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
	options->رقم_host_کلید_files = n;
	options->host_کلید_file_userprovided = userprovided;
	options->host_کلید_files = files;
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

	إذا ((r = deserialise_شمار(buf, &n, "listen addresses")) != 0)
		أرجع r;
	إذا (n > 0)
		qla = xcalloc(n, حجم(*qla));
	لكل (i = 0; i < n; i++) {
		إذا ((r = sshbuf_get_cstring(buf, &qla[i].addr, عدم)) != 0 ||
		    (r = deserialise_s32(buf, &qla[i].پورت)) != 0 ||
		    (r = deserialise_nullable_string(buf,
		    &qla[i].rdomain)) != 0) {
			error_fr(r, "deserialise member");
			free_queued_listen_addrs(qla, i + 1);
			أرجع r;
		}
	}
	options->رقم_queued_listens = n;
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
	إذا (tmp != SYSLOG_FACILITY_NOT_مجموعه &&
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
	إذا (tmp != SYSLOG_LEVEL_NOT_مجموعه &&
	    log_level_name((LogLevel)tmp) == عدم) {
		error_f("bad log level");
		أرجع SSH_ERR_INVALID_FORMAT;
	}
	options->log_level = (LogLevel)tmp;

	أرجع 0;
}

ساكن صحيح
deserialise_پورت(ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;
	u_int i, n;

	إذا ((r = deserialise_شمار(buf, &n, "ports")) != 0)
		أرجع r;
	إذا (n > MAX_PORTS) {
		error_f("bad number of ports");
		أرجع SSH_ERR_INVALID_FORMAT;
	}
	options->رقم_ports = n;
	memset(options->ports, 0, حجم(options->ports));
	لكل (i = 0; i < options->رقم_ports; i++) {
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

	إذا ((r = deserialise_نما(buf,
	    &options->fwd_opts.streamlocal_bind_ماسک)) != 0) {
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
	    (r = deserialise_s32(buf, &options->max_startups_نرخ)) != 0 ||
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
	    &options->در_هر_منبع_masklen_ipv4)) != 0 ||
	    (r = deserialise_s32(buf,
	    &options->در_هر_منبع_masklen_ipv6)) != 0) {
		error_fr(r, "deserialise");
		أرجع r;
	}

	أرجع 0;
}

ساكن صحيح
deserialise_persourcepenalties(ServerOptions *options, بنية sshbuf *buf)
{
	بنية در_هر_منبع_penalty *psp = &options->در_هر_منبع_penalty;
	صحيح r;

	إذا ((r = deserialise_s32(buf, &psp->enabled)) != 0 ||
	    (r = deserialise_s32(buf, &psp->max_sources4)) != 0 ||
	    (r = deserialise_s32(buf, &psp->max_sources6)) != 0 ||
	    (r = deserialise_s32(buf, &psp->سرریز_نما)) != 0 ||
	    (r = deserialise_s32(buf, &psp->سرریز_mode6)) != 0 ||
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

	إذا ((r = deserialise_s64(buf, &options->rekey_حد)) != 0 ||
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
	حرف **نامها = عدم, **commands = عدم, **آرگومانها = عدم;

	إذا ((r = deserialise_شمار(buf, &n, "subsystems")) != 0)
		أرجع r;
	إذا (n > 0) {
		نامها = xcalloc(n, حجم(*نامها));
		commands = xcalloc(n, حجم(*نامها));
		آرگومانها = xcalloc(n, حجم(*آرگومانها));
	}
	لكل (i = 0; i < n; i++) {
		إذا ((r = sshbuf_get_cstring(buf, نامها + i, عدم)) != 0 ||
		    (r = sshbuf_get_cstring(buf, commands + i, عدم)) != 0 ||
		    (r = sshbuf_get_cstring(buf, آرگومانها + i, عدم)) != 0) {
			error_fr(r, "deserialise member");
			free_string_array(نامها, i + 1);
			free_string_array(commands, i + 1);
			free_string_array(آرگومانها, i + 1);
			أرجع r;
		}
	}
	options->رقم_subsystems = n;
	options->subsystem_name = نامها;
	options->subsystem_command = commands;
	options->subsystem_آرگومانها = آرگومانها;
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
	صحيح r = SSH_ERR_داخلی_ERROR;
	uint32_t نسخه;
	ServerOptions new_options;

	initialize_server_options(&new_options);
	إذا ((r = sshbuf_get_u32(buf, &نسخه)) != 0) {
		error_fr(r, "deserialise version");
		اذهب بیرون;
	}
	إذا (نسخه != SSHD_CONFIG_BLOB_نسخه) {
		error_f("unsupported config blob version %u", نسخه);
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بیرون;
	}
#تعریف_کن SSHCONF_INT(var, conf, flags, ms, def, cp) \
	إذا ((r = deserialise_s32(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		اذهب بیرون; \
	}
#تعریف_کن SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	إذا ((r = deserialise_s32(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		اذهب بیرون; \
	}
#تعریف_کن SSHCONF_STRING(var, conf, flags, cp) \
	إذا ((r = deserialise_nullable_string(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		اذهب بیرون; \
	}
#تعریف_کن SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	إذا ((r = deserialise_nullable_string_array(buf, &new_options.var, \
	    &new_options.nvar)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		اذهب بیرون; \
	}
#تعریف_کن SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	إذا ((r = deserialise_##funcsuffix(&new_options, buf)) != 0) \
		اذهب بیرون;
#تعریف_کن SSHCONF_NONCONF(funcsuffix) \
	إذا ((r = deserialise_##funcsuffix(&new_options, buf)) != 0) \
		اذهب بیرون;
#تعریف_کن SSHCONF_DEPRECATE(conf, flags, opcode)		/*خالی*/
#تعریف_کن SSHCONF_UNSUPPORTED_INT(var, conf, flags)	new_options.var = 0;
#تعریف_کن SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	افعل { \
		حرر(new_options.var); \
		new_options.var = عدم; \
	} طالما (0);
#تعریف_کن SSHCONF_ALIAS(old, conf, flags)			/*خالی*/

	SSHD_CONFIG_ENTRIES

	إذا (sshbuf_len(buf) != 0) {
		error_f("trailing data in config blob");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بیرون;
	}

#لغو_تعریف SSHCONF_INT
#لغو_تعریف SSHCONF_INTFLAG
#لغو_تعریف SSHCONF_STRING
#لغو_تعریف SSHCONF_STRARRAY
#لغو_تعریف SSHCONF_CUSTOM
#لغو_تعریف SSHCONF_NONCONF
#لغو_تعریف SSHCONF_DEPRECATE
#لغو_تعریف SSHCONF_UNSUPPORTED_INT
#لغو_تعریف SSHCONF_UNSUPPORTED_STRING
#لغو_تعریف SSHCONF_ALIAS

	/* success */
	r = 0;
	free_server_options(options);
	*options = new_options;
	memset(&new_options, 0, حجم(new_options));
 بیرون:
	free_server_options(&new_options);
	أرجع r;
}

ساكن فراغ
free_hostkeyfile(ServerOptions *options)
{
	u_int i;

	لكل (i = 0; i < options->رقم_host_کلید_files; i++)
		حرر(options->host_کلید_files[i]);
	حرر(options->host_کلید_files);
	حرر(options->host_کلید_file_userprovided);
}

ساكن فراغ
free_listenaddress(ServerOptions *options)
{
	u_int i;

	free_queued_listen_addrs(options->queued_listen_addrs,
	    options->رقم_queued_listens);

	لكل (i = 0; i < options->رقم_listen_addrs; i++) {
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

	لكل (i = 0; i < options->رقم_subsystems; i++) {
		حرر(options->subsystem_name[i]);
		حرر(options->subsystem_command[i]);
		حرر(options->subsystem_آرگومانها[i]);
	}
	حرر(options->subsystem_name);
	حرر(options->subsystem_command);
	حرر(options->subsystem_آرگومانها);
}

فراغ
free_server_options(ServerOptions *options)
{
#تعریف_کن SSHCONF_INT(var, conf, flags, ms, def, cp)	/*خالی*/
#تعریف_کن SSHCONF_INTFLAG(var, conf, flags, def, cp)	/*خالی*/
#تعریف_کن SSHCONF_STRING(var, conf, flags, cp)		حرر(options->var);
#تعریف_کن SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	free_string_array(options->var, options->nvar);
#تعریف_کن SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	free_##funcsuffix(options);
#تعریف_کن SSHCONF_NONCONF(funcsuffix) \
	free_##funcsuffix(options);
#تعریف_کن SSHCONF_DEPRECATE(conf, flags, opcode)		/*خالی*/
#تعریف_کن SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#تعریف_کن SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	افعل { \
		حرر(options->var); \
		options->var = عدم; \
	} طالما (0);
#تعریف_کن SSHCONF_ALIAS(old, conf, flags)			/*خالی*/

#تعریف_کن free_ipqos(options)
#تعریف_کن free_logfacility(options)
#تعریف_کن free_loglevel(options)
#تعریف_کن free_پورت(options)
#تعریف_کن free_gatewayports(options)
#تعریف_کن free_streamlocalbindmask(options)
#تعریف_کن free_streamlocalbindunlink(options)
#تعریف_کن free_maxstartups(options)
#تعریف_کن free_persourcenetblocksize(options)
#تعریف_کن free_persourcepenalties(options)
#تعریف_کن free_rekeylimit(options)
#تعریف_کن free_pubkey_auth_options(options)
#تعریف_کن free_timingsecret(options)

	SSHD_CONFIG_ENTRIES

#لغو_تعریف free_ipqos
#لغو_تعریف free_logfacility
#لغو_تعریف free_loglevel
#لغو_تعریف free_پورت
#لغو_تعریف free_gatewayports
#لغو_تعریف free_streamlocalbindmask
#لغو_تعریف free_streamlocalbindunlink
#لغو_تعریف free_maxstartups
#لغو_تعریف free_persourcenetblocksize
#لغو_تعریف free_persourcepenalties
#لغو_تعریف free_rekeylimit
#لغو_تعریف free_timingsecret

#لغو_تعریف SSHCONF_INT
#لغو_تعریف SSHCONF_INTFLAG
#لغو_تعریف SSHCONF_STRING
#لغو_تعریف SSHCONF_STRARRAY
#لغو_تعریف SSHCONF_CUSTOM
#لغو_تعریف SSHCONF_NONCONF
#لغو_تعریف SSHCONF_DEPRECATE
#لغو_تعریف SSHCONF_UNSUPPORTED_INT
#لغو_تعریف SSHCONF_UNSUPPORTED_STRING
#لغو_تعریف SSHCONF_ALIAS

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
copy_server_option_strarray_مقادیر(حرف ***dst, u_int ndst,
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
	copy_server_option_strarray_مقادیر(dst, *ndst, src, nsrc);
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
	copy_server_option_int64(&dst->rekey_حد, src->rekey_حد);
	copy_server_option_int(&dst->rekey_interval, src->rekey_interval);
}

ساكن فراغ
copy_subsystem(ServerOptions *dst, ثابت ServerOptions *src)
{
	u_int old_رقم_subsystems = dst->رقم_subsystems;

	إذا (src->رقم_subsystems == 0)
		أرجع;
	copy_server_option_strarray_مقادیر(&dst->subsystem_name,
	    old_رقم_subsystems, src->subsystem_name, src->رقم_subsystems);
	copy_server_option_strarray_مقادیر(&dst->subsystem_command,
	    old_رقم_subsystems, src->subsystem_command, src->رقم_subsystems);
	copy_server_option_strarray_مقادیر(&dst->subsystem_آرگومانها,
	    old_رقم_subsystems, src->subsystem_آرگومانها, src->رقم_subsystems);
	dst->رقم_subsystems = src->رقم_subsystems;
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
copy_مجموعه_server_options(ServerOptions *dst, ServerOptions *src, صحيح preauth)
{
	إذا (dst == src)
		أرجع;

#تعریف_کن SSHCONF_INT(var, conf, flags, ms, def, cp) \
	cp(copy_server_option_int(&dst->var, src->var);)
#تعریف_کن SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	cp(copy_server_option_int(&dst->var, src->var);)
#تعریف_کن SSHCONF_STRING(var, conf, flags, cp) \
	cp(copy_server_option_string(&dst->var, src->var);)
#تعریف_کن SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	cp(copy_server_option_strarray(&dst->var, &dst->nvar, \
	    src->var, src->nvar);)
#تعریف_کن SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	cp(copy_##funcsuffix(dst, src);)
#تعریف_کن SSHCONF_NONCONF(funcsuffix)			/*خالی*/
#تعریف_کن SSHCONF_DEPRECATE(conf, flags, opcode)		/*خالی*/
#تعریف_کن SSHCONF_UNSUPPORTED_INT(var, conf, flags)	dst->var = 0;
#تعریف_کن SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	افعل { \
		حرر(dst->var); \
		dst->var = عدم; \
	} طالما (0);
#تعریف_کن SSHCONF_ALIAS(old, conf, flags)			/*خالی*/

	SSHD_CONFIG_ENTRIES

#لغو_تعریف SSHCONF_INT
#لغو_تعریف SSHCONF_INTFLAG
#لغو_تعریف SSHCONF_STRING
#لغو_تعریف SSHCONF_STRARRAY
#لغو_تعریف SSHCONF_CUSTOM
#لغو_تعریف SSHCONF_NONCONF
#لغو_تعریف SSHCONF_DEPRECATE
#لغو_تعریف SSHCONF_UNSUPPORTED_INT
#لغو_تعریف SSHCONF_UNSUPPORTED_STRING
#لغو_تعریف SSHCONF_ALIAS

	/*
	 * The bind_mask is a mode_t that may be unsigned, so we can't use
	 * copy_server_option_int - it does a signed comparison that causes
	 * compiler warnings.
	 */
	إذا (src->fwd_opts.streamlocal_bind_ماسک != (نما_t)-1) {
		dst->fwd_opts.streamlocal_bind_ماسک =
		    src->fwd_opts.streamlocal_bind_ماسک;
	}

	/* Arguments that accept '+...' need to be expanded */
	assemble_algorithms(dst);

	/*
	 * These options may be "none" to clear a global setting.  They are
	 * consulted before authentication, so they must be cleared here
	 * rather than in the post-auth section below.
	 */
#تعریف_کن CLEAR_ON_NONE(v) \
	افعل { \
		إذا (option_clear_or_none(v)) { \
			حرر(v); \
			v = عدم; \
		} \
	} طالما(0)
	CLEAR_ON_NONE(dst->authorized_principals_file);
	CLEAR_ON_NONE(dst->trusted_user_ca_کلیدها);
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
#لغو_تعریف CLEAR_ON_NONE

	/* Subsystems require merging. */
	servconf_ادغام_subsystems(dst, src);
}

#تعریف_کن SERVCONF_MAX_عمق	16
ساكن فراغ
parse_server_config_عمق(ServerOptions *options, ثابت حرف *filename,
    بنية sshbuf *conf, بنية include_list *includes,
    بنية connection_info *connectinfo, صحيح flags, صحيح *activep, صحيح عمق)
{
	صحيح linenum, bad_options = 0;
	حرف *cp, *obuf, *cbuf;

	إذا (عمق < 0 || عمق > SERVCONF_MAX_عمق)
		fatal("Too many recursive configuration includes");

	debug2_f("config %s len %zu%s", filename, sshbuf_len(conf),
	    (flags & SSHCFG_NEVERMATCH ? " [checking syntax only]" : ""));

	إذا ((obuf = cbuf = sshbuf_dup_string(conf)) == عدم)
		fatal_f("sshbuf_dup_string failed");
	linenum = 1;
	طالما ((cp = strsep(&cbuf, "\n")) != عدم) {
		إذا (process_server_config_سطر_عمق(options, cp,
		    filename, linenum++, activep, connectinfo, &flags,
		    عمق, includes) != 0)
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
	صحيح فعال = connectinfo ? 0 : 1;
	parse_server_config_عمق(options, filename, conf, includes,
	    connectinfo, (connectinfo ? SSHCFG_تطابق_ONLY : 0), &فعال, 0);
	إذا (!reexec)
		process_queued_listen_addrs(options);
}

ساكن ثابت حرف *
fmt_multistate_int(صحيح val, ثابت بنية multistate *m)
{
	u_int i;

	لكل (i = 0; m[i].کلید != عدم; i++) {
		إذا (m[i].مقدار == val)
			أرجع m[i].کلید;
	}
	أرجع "UNKNOWN";
}

ساكن ثابت حرف *
fmt_intarg(ServerOpCodes کد, صحيح val)
{
	إذا (val == -1)
		أرجع "unset";
	بدل (کد) {
	حالة s_آدرس_Family:
		أرجع fmt_multistate_int(val, multistate_addressfamily);
	حالة s_Permit_ریشه_Login:
		أرجع fmt_multistate_int(val, multistate_permitrootlogin);
	حالة sGatewayPorts:
		أرجع fmt_multistate_int(val, multistate_gatewayports);
	حالة sCompression:
		أرجع fmt_multistate_int(val, multistate_compression);
	حالة sAllowTcpForwarding:
		أرجع fmt_multistate_int(val, multistate_tcpfwd);
	حالة s_Allow_جریان_Local_Forwarding:
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
dump_cfg_int(ServerOpCodes کد, صحيح val)
{
	إذا (کد == s_استفادهنشده_Connection_Timeout && val == 0) {
		چاپ_کن("%s none\n", lookup_opcode_name(کد));
		أرجع;
	}
	چاپ_کن("%s %d\n", lookup_opcode_name(کد), val);
}

ساكن فراغ
dump_cfg_oct(ServerOpCodes کد, صحيح val)
{
	چاپ_کن("%s 0%o\n", lookup_opcode_name(کد), val);
}

ساكن فراغ
dump_cfg_fmtint(ServerOpCodes کد, صحيح val)
{
	چاپ_کن("%s %s\n", lookup_opcode_name(کد), fmt_intarg(کد, val));
}

ساكن فراغ
dump_cfg_string(ServerOpCodes کد, ثابت حرف *val)
{
	چاپ_کن("%s %s\n", lookup_opcode_name(کد),
	    val == عدم ? "none" : val);
}

ساكن فراغ
dump_cfg_strarray(ServerOpCodes کد, u_int شمار, حرف **vals)
{
	u_int i;

	لكل (i = 0; i < شمار; i++)
		چاپ_کن("%s %s\n", lookup_opcode_name(کد), vals[i]);
}

ساكن فراغ
dump_cfg_strarray_oneline(ServerOpCodes کد, u_int شمار, حرف **vals)
{
	u_int i;

	بدل (کد) {
	حالة sAuthenticationMethods:
	حالة sChannelTimeout:
		اكسر;
	افتراضي:
		إذا (شمار <= 0)
			أرجع;
		اكسر;
	}

	چاپ_کن("%s", lookup_opcode_name(کد));
	لكل (i = 0; i < شمار; i++)
		چاپ_کن(" %s",  vals[i]);
	إذا (کد == sAuthenticationMethods && شمار == 0)
		چاپ_کن(" any");
	وإلا إذا (کد == sChannelTimeout && شمار == 0)
		چاپ_کن(" none");
	چاپ_کن("\n");
}

ساكن حرف *
format_listen_addrs(بنية listenaddr *la)
{
	صحيح r;
	بنية addrinfo *ai;
	حرف addr[NI_MAXHOST], پورت[NI_MAXSERV];
	حرف *laddr1 = xstrdup(""), *laddr2 = عدم;

	/*
	 * ListenAddress must be after Port.  add_one_listen_addr pushes
	 * addresses onto a stack, so to maintain ordering we need to
	 * print these in reverse order.
	 */
	لكل (ai = la->addrs; ai; ai = ai->ai_next) {
		إذا ((r = getnameinfo(ai->ai_addr, ai->ai_addrlen, addr,
		    حجم(addr), پورت, حجم(پورت),
		    NI_NUMERICHOST|NI_NUMERICSERV)) != 0) {
			error("getnameinfo: %.100s", ssh_gai_strerror(r));
			استمر;
		}
		laddr2 = laddr1;
		إذا (ai->ai_family == AF_INET6) {
			xasprintf(&laddr1, "ListenAddress [%s]:%s%s%s\n%s",
			    addr, پورت,
			    la->rdomain == عدم ? "" : " rdomain ",
			    la->rdomain == عدم ? "" : la->rdomain,
			    laddr2);
		} وإلا {
			xasprintf(&laddr1, "ListenAddress %s:%s%s%s\n%s",
			    addr, پورت,
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
	لكل (i = 0; i < o->رقم_ports; i++)
		چاپ_کن("Port %d\n", o->ports[i]);
	dump_cfg_fmtint(s_آدرس_Family, o->آدرس_family);

	لكل (i = 0; i < o->رقم_listen_addrs; i++) {
		s = format_listen_addrs(&o->listen_addrs[i]);
		چاپ_کن("%s", s);
		حرر(s);
	}

	/* integer arguments */
#اگر_تعریف_شده USE_PAM
	dump_cfg_fmtint(sUsePAM, o->use_pam);
	dump_cfg_string(sPAMServiceName, o->pam_service_name);
#پایان_اگر
	dump_cfg_int(s_Login_Grace_زمان, o->login_grace_زمان);
	dump_cfg_int(s_X11_Display_جابه_جایی, o->x11_display_جابه_جایی);
	dump_cfg_int(sMaxAuthTries, o->max_authtries);
	dump_cfg_int(sMaxSessions, o->max_sessions);
	dump_cfg_int(sClientAliveInterval, o->client_alive_interval);
	dump_cfg_int(s_Client_Alive_شمار_Max, o->client_alive_شمار_max);
	dump_cfg_int(sRequiredRSASize, o->required_rsa_اندازه);
	dump_cfg_oct(s_جریان_Local_Bind_ماسک, o->fwd_opts.streamlocal_bind_ماسک);
	dump_cfg_int(s_استفادهنشده_Connection_Timeout, o->استفادهنشده_connection_timeout);

	/* formatted integer arguments */
	dump_cfg_fmtint(s_Permit_ریشه_Login, o->permit_ریشه_login);
	dump_cfg_fmtint(sIgnoreRhosts, o->ignore_rhosts);
	dump_cfg_fmtint(s_Ignore_User_معلوم_Hosts, o->ignore_user_معلوم_hosts);
	dump_cfg_fmtint(sHostbasedAuthentication, o->hostbased_authentication);
	dump_cfg_fmtint(s_Hostbased_استفاده_میکند_Name_From_Packet_Only,
	    o->hostbased_استفاده_میکند_name_from_packet_only);
	dump_cfg_fmtint(sPubkeyAuthentication, o->pubkey_authentication);
#اگر_تعریف_شده KRB5
	dump_cfg_fmtint(sKerberosAuthentication, o->kerberos_authentication);
	dump_cfg_fmtint(sKerberosOrLocalPasswd, o->kerberos_or_local_passwd);
	dump_cfg_fmtint(sKerberosTicketCleanup, o->kerberos_ticket_cleanup);
# ifdef USE_AFS
	dump_cfg_fmtint(sKerberosGetAFSToken, o->kerberos_get_afs_token);
# endif
#پایان_اگر
#اگر_تعریف_شده GSSAPI
	dump_cfg_fmtint(sGSSAPIAuthentication, o->gss_authentication);
	dump_cfg_fmtint(sGSSAPICleanupCredentials, o->gss_cleanup_creds);
	dump_cfg_fmtint(sGSSAPIDelegateCredentials, o->gss_deleg_creds);
	dump_cfg_fmtint(sGSSAPIStrictAcceptorCheck, o->gss_strict_acceptor);
#پایان_اگر
	dump_cfg_fmtint(sPasswordAuthentication, o->password_authentication);
	dump_cfg_fmtint(sKbdInteractiveAuthentication,
	    o->kbd_interactive_authentication);
	dump_cfg_fmtint(sPrintMotd, o->print_motd);
#اگر_تعریف_نشده DISABLE_LASTLOG
	dump_cfg_fmtint(s_Print_آخرین_Log, o->print_lastlog);
#پایان_اگر
	dump_cfg_fmtint(sX11Forwarding, o->x11_forwarding);
	dump_cfg_fmtint(sX11UseLocalhost, o->x11_use_localhost);
	dump_cfg_fmtint(sPermitTTY, o->permit_tty);
	dump_cfg_fmtint(sPermitUserRC, o->permit_user_rc);
	dump_cfg_fmtint(sStrictModes, o->strict_modes);
	dump_cfg_fmtint(sTCPKeepAlive, o->tcp_keep_alive);
	dump_cfg_fmtint(s_Permit_خالی_Passwords, o->permit_خالی_passwd);
	dump_cfg_fmtint(sCompression, o->compression);
	dump_cfg_fmtint(sGatewayPorts, o->fwd_opts.gateway_ports);
	dump_cfg_fmtint(sUseDNS, o->use_dns);
	dump_cfg_fmtint(sAllowTcpForwarding, o->allow_tcp_forwarding);
	dump_cfg_fmtint(sAllowAgentForwarding, o->allow_agent_forwarding);
	dump_cfg_fmtint(sDisableForwarding, o->disable_forwarding);
	dump_cfg_fmtint(s_Allow_جریان_Local_Forwarding, o->allow_streamlocal_forwarding);
	dump_cfg_fmtint(s_جریان_Local_Bind_Unlink, o->fwd_opts.streamlocal_bind_unlink);
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
	dump_cfg_string(sTrustedUserCAKeys, o->trusted_user_ca_کلیدها);
	dump_cfg_string(s_Security_کلید_Provider, o->sk_provider);
	dump_cfg_string(sAuthorizedPrincipalsFile,
	    o->authorized_principals_file);
	dump_cfg_string(s_نسخه_Addendum, *o->نسخه_addendum == '\0'
	    ? "none" : o->نسخه_addendum);
	dump_cfg_string(s_Authorized_کلیدها_Command, o->authorized_کلیدها_command);
	dump_cfg_string(s_Authorized_کلیدها_Command_User, o->authorized_کلیدها_command_user);
	dump_cfg_string(sAuthorizedPrincipalsCommand, o->authorized_principals_command);
	dump_cfg_string(sAuthorizedPrincipalsCommandUser, o->authorized_principals_command_user);
	dump_cfg_string(s_Host_کلید_Agent, o->host_کلید_agent);
	dump_cfg_string(sKexAlgorithms, o->kex_algorithms);
	dump_cfg_string(sCASignatureAlgorithms, o->ca_sign_algorithms);
	dump_cfg_string(sHostbasedAcceptedAlgorithms, o->hostbased_accepted_algos);
	dump_cfg_string(s_Host_کلید_Algorithms, o->hostkeyalgorithms);
	dump_cfg_string(sPubkeyAcceptedAlgorithms, o->pubkey_accepted_algos);
#إذا defined(__OpenBSD__) || defined(HAVE_SYS_مجموعه_PROCESS_RDOMAIN)
	dump_cfg_string(sRDomain, o->routing_domain);
#پایان_اگر
	dump_cfg_string(s_Sshd_Session_مسیر, o->sshd_session_مسیر);
	dump_cfg_string(s_Sshd_Auth_مسیر, o->sshd_auth_مسیر);
	dump_cfg_string(s_در_هر_منبع_Penalty_Exempt_List, o->در_هر_منبع_penalty_exempt);
	dump_cfg_string(s_Agent_Socket_مسیر, o->agent_socket_مسیر);

	/* string arguments requiring a lookup */
	dump_cfg_string(sLogLevel, log_level_name(o->log_level));
	dump_cfg_string(sSyslogFacility, log_facility_name(o->log_facility));

	/* string array arguments */
	dump_cfg_strarray_oneline(s_Authorized_کلیدها_File, o->رقم_authkeys_files,
	    o->authorized_کلیدها_files);
	dump_cfg_strarray_oneline(s_Revoked_کلیدها, o->رقم_revoked_کلیدها_files,
	    o->revoked_کلیدها_files);
	dump_cfg_strarray(s_Host_کلید, o->رقم_host_کلید_files, o->host_کلید_files);
	dump_cfg_strarray(sHostCertificate, o->رقم_host_cert_files,
	    o->host_cert_files);
	dump_cfg_strarray(sAllowUsers, o->رقم_allow_users, o->allow_users);
	dump_cfg_strarray(sDenyUsers, o->رقم_deny_users, o->deny_users);
	dump_cfg_strarray(sAllowGroups, o->رقم_allow_groups, o->allow_groups);
	dump_cfg_strarray(sDenyGroups, o->رقم_deny_groups, o->deny_groups);
	dump_cfg_strarray(sAcceptEnv, o->رقم_accept_env, o->accept_env);
	dump_cfg_strarray(s_مجموعه_Env, o->رقم_setenv, o->setenv);
	dump_cfg_strarray_oneline(sAuthenticationMethods,
	    o->رقم_auth_methods, o->auth_methods);
	dump_cfg_strarray_oneline(sLogVerbose,
	    o->رقم_log_verbose, o->log_verbose);
	dump_cfg_strarray_oneline(sChannelTimeout,
	    o->رقم_channel_timeouts, o->channel_timeouts);

	/* other arguments */
	لكل (i = 0; i < o->رقم_subsystems; i++)
		چاپ_کن("Subsystem %s %s\n", o->subsystem_name[i],
		    o->subsystem_آرگومانها[i]);

	چاپ_کن("MaxStartups %d:%d:%d\n", o->max_startups_begin,
	    o->max_startups_نرخ, o->max_startups);
	چاپ_کن("PerSourceMaxStartups ");
	إذا (o->در_هر_منبع_max_startups == بیشترین_صحیح)
		چاپ_کن("none\n");
	وإلا
		چاپ_کن("%d\n", o->در_هر_منبع_max_startups);
	چاپ_کن("PerSourceNetBlockSize %d:%d\n", o->در_هر_منبع_masklen_ipv4,
	    o->در_هر_منبع_masklen_ipv6);

	s = عدم;
	لكل (i = 0; tunmode_desc[i].val != -1; i++) {
		إذا (tunmode_desc[i].val == o->permit_tun) {
			s = tunmode_desc[i].متن;
			اكسر;
		}
	}
	dump_cfg_string(sPermitTunnel, s);

	چاپ_کن("IPQoS %s ", iptos2str(o->ip_qos_interactive));
	چاپ_کن("%s\n", iptos2str(o->ip_qos_bulk));

	چاپ_کن("RekeyLimit %llu %d\n", (بیعلامت دراز دراز)o->rekey_حد,
	    o->rekey_interval);

	چاپ_کن("PermitOpen");
	إذا (o->رقم_permitted_opens == 0)
		چاپ_کن(" any");
	وإلا {
		لكل (i = 0; i < o->رقم_permitted_opens; i++)
			چاپ_کن(" %s", o->permitted_opens[i]);
	}
	چاپ_کن("\n");
	چاپ_کن("PermitListen");
	إذا (o->رقم_permitted_listens == 0)
		چاپ_کن(" any");
	وإلا {
		لكل (i = 0; i < o->رقم_permitted_listens; i++)
			چاپ_کن(" %s", o->permitted_listens[i]);
	}
	چاپ_کن("\n");

	إذا (o->permit_user_env_allowlist == عدم) {
		dump_cfg_fmtint(sPermitUserEnvironment, o->permit_user_env);
	} وإلا {
		چاپ_کن("PermitUserEnvironment %s\n",
		    o->permit_user_env_allowlist);
	}

	چاپ_کن("PubkeyAuthOptions");
	إذا (o->pubkey_auth_options == 0)
		چاپ_کن(" none");
	إذا (o->pubkey_auth_options & PUBKEYAUTH_TOUCH_REQUIRED)
		چاپ_کن(" touch-required");
	إذا (o->pubkey_auth_options & PUBKEYAUTH_VERIFY_REQUIRED)
		چاپ_کن(" verify-required");
	إذا (o->max_pubkey_ok != -1)
		چاپ_کن(" max-pk-ok:%d", o->max_pubkey_ok);
	چاپ_کن("\n");

	إذا (o->در_هر_منبع_penalty.enabled) {
		چاپ_کن("PerSourcePenalties crash:%f authfail:%f noauth:%f "
		    "invaliduser:%f "
		    "grace-exceeded:%f refuseconnection:%f max:%f min:%f "
		    "max-sources4:%d max-sources6:%d "
		    "overflow:%s overflow6:%s\n",
		    o->در_هر_منبع_penalty.penalty_crash,
		    o->در_هر_منبع_penalty.penalty_authfail,
		    o->در_هر_منبع_penalty.penalty_noauth,
		    o->در_هر_منبع_penalty.penalty_invaliduser,
		    o->در_هر_منبع_penalty.penalty_grace,
		    o->در_هر_منبع_penalty.penalty_refuseconnection,
		    o->در_هر_منبع_penalty.penalty_max,
		    o->در_هر_منبع_penalty.penalty_min,
		    o->در_هر_منبع_penalty.max_sources4,
		    o->در_هر_منبع_penalty.max_sources6,
		    o->در_هر_منبع_penalty.سرریز_نما ==
		    در_هر_منبع_PENALTY_سرریز_DENY_ALL ?
		    "deny-all" : "permissive",
		    o->در_هر_منبع_penalty.سرریز_mode6 ==
		    در_هر_منبع_PENALTY_سرریز_DENY_ALL ?
		    "deny-all" : "permissive");
	} وإلا
		چاپ_کن("PerSourcePenalties no\n");
}
