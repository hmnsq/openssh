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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <sys/queue.h>
#अन्तर्भाव <sys/stat.h>
#ifdef __OpenBSD__
#अन्तर्भाव <sys/sysctl.h>
#endif

#अन्तर्भाव <netinet/in.h>
#अन्तर्भाव <netinet/ip.h>
#ifdef HAVE_NET_ROUTE_H
#अन्तर्भाव <net/route.h>
#endif

#अन्तर्भाव <ctype.h>
#अन्तर्भाव <glob.h>
#अन्तर्भाव <netdb.h>
#अन्तर्भाव <pwd.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <limits.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <errno.h>
#अन्तर्भाव <util.h>

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "ssh.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "servconf.h"
#अन्तर्भाव "pathnames.h"
#अन्तर्भाव "cipher.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "kex.h"
#अन्तर्भाव "mac.h"
#अन्तर्भाव "match.h"
#अन्तर्भाव "channels.h"
#अन्तर्भाव "groupaccess.h"
#अन्तर्भाव "canohost.h"
#अन्तर्भाव "packet.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "hostfile.h"
#अन्तर्भाव "auth.h"
#अन्तर्भाव "myproposal.h"
#अन्तर्भाव "digest.h"
#अन्तर्भाव "version.h"

#define SSHD_CONFIG_BLOB_VERSION	1

#सचे !defined(SSHD_PAM_SERVICE)
# define SSHD_PAM_SERVICE		"sshd"
#endif

स्थिर शून्य add_listen_addr(ServerOptions *, ध्रुव वर्ण *,
    ध्रुव वर्ण *, पूर्णाङ्क);
स्थिर शून्य add_one_listen_addr(ServerOptions *, ध्रुव वर्ण *,
    ध्रुव वर्ण *, पूर्णाङ्क);
स्थिर शून्य parse_server_config_depth(ServerOptions *options,
    ध्रुव वर्ण *filename, संरचना sshbuf *conf, संरचना include_list *includes,
    संरचना connection_info *connectinfo, पूर्णाङ्क flags, पूर्णाङ्क *activep, पूर्णाङ्क depth);

बाह्य संरचना sshbuf *cfg;

/* Initializes the server options to their default values. */

शून्य
initialize_server_options(ServerOptions *options)
{
	memset(options, 0, परिमाण(*options));
#define SSHCONF_INT(var, conf, flags, ms, def, cp)	options->var = -1;
#define SSHCONF_INTFLAG(var, conf, flags, def, cp)	options->var = -1;
#define SSHCONF_STRING(var, conf, flags, cp)		options->var = रिक्त;
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	options->nvar = 0; \
	options->var = रिक्त;
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	init_##funcsuffix(options)
#define SSHCONF_NONCONF(funcsuffix) \
	init_##funcsuffix(options)
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	options->var = रिक्त;
#define SSHCONF_ALIAS(old, conf, flags)			/* empty */

	/* Using macros for these is a bit overkill but forces consistency */
#define init_hostkeyfile(options) \
	options->host_कुञ्चिका_files = 0; \
	options->अङ्कः_host_कुञ्चिका_files = 0; \
	options->host_कुञ्चिका_file_userprovided = रिक्त;
#define init_ipqos(options) \
	options->ip_qos_interactive = -1; \
	options->ip_qos_bulk = -1;
#define init_listenaddress(options) \
	options->queued_listen_addrs = रिक्त; \
	options->अङ्कः_queued_listens = 0; \
	options->listen_addrs = रिक्त; \
	options->अङ्कः_listen_addrs = 0;
#define init_logfacility(options) \
	options->log_facility = SYSLOG_FACILITY_NOT_SET;
#define init_loglevel(options) \
	options->log_level = SYSLOG_LEVEL_NOT_SET;
#define init_port(options) \
	options->अङ्कः_ports = 0; \
	options->ports_from_cmdline = 0;
#define init_gatewayports(options) \
	options->fwd_opts.gateway_ports = -1;
#define init_streamlocalbindmask(options) \
	options->fwd_opts.streamlocal_bind_mask = (mode_t)-1;
#define init_streamlocalbindunlink(options) \
	options->fwd_opts.streamlocal_bind_unlink = -1;
#define init_maxstartups(options) \
	options->max_startups_begin = -1; \
	options->max_startups_rate = -1; \
	options->max_startups = -1;
#define init_permituserenv(options) \
	options->permit_user_env = -1; \
	options->permit_user_env_allowlist = रिक्त;
#define init_persourcenetblocksize(options) \
	options->per_source_masklen_ipv4 = -1; \
	options->per_source_masklen_ipv6 = -1;
#define init_persourcepenalties(options) \
	options->per_source_penalty_exempt = रिक्त; \
	options->per_source_penalty.enabled = -1; \
	options->per_source_penalty.max_sources4 = -1; \
	options->per_source_penalty.max_sources6 = -1; \
	options->per_source_penalty.overflow_mode = -1; \
	options->per_source_penalty.overflow_mode6 = -1; \
	options->per_source_penalty.penalty_crash = -1.0; \
	options->per_source_penalty.penalty_authfail = -1.0; \
	options->per_source_penalty.penalty_invaliduser = -1.0; \
	options->per_source_penalty.penalty_noauth = -1.0; \
	options->per_source_penalty.penalty_grace = -1.0; \
	options->per_source_penalty.penalty_refuseconnection = -1.0; \
	options->per_source_penalty.penalty_max = -1.0; \
	options->per_source_penalty.penalty_min = -1.0;
#define init_rekeylimit(options) \
	options->rekey_limit = -1; \
	options->rekey_interval = -1;
#define init_subsystem(options) \
	options->अङ्कः_subsystems = 0; \
	options->subsystem_name = रिक्त; \
	options->subsystem_command = रिक्त; \
	options->subsystem_args = रिक्त;
#define init_pubkey_auth_options(options) \
	options->pubkey_auth_options = -1; \
	options->max_pubkey_ok = -1;
#define init_timingsecret(options) \
	options->timing_secret = 0;

	SSHD_CONFIG_ENTRIES

#undef init_hostkeyfile
#undef init_ipqos
#undef init_listenaddress
#undef init_logfacility
#undef init_loglevel
#undef init_port
#undef init_gatewayports
#undef init_streamlocalbindmask
#undef init_streamlocalbindunlink
#undef init_maxstartups
#undef init_permituserenv
#undef init_persourcenetblocksize
#undef init_persourcepenalties
#undef init_rekeylimit
#undef init_subsystem
#undef init_timingsecret
#undef SSHCONF_INT
#undef SSHCONF_INTFLAG
#undef SSHCONF_STRING
#undef SSHCONF_STRARRAY
#undef SSHCONF_CUSTOM
#undef SSHCONF_NONCONF
#undef SSHCONF_DEPRECATE
#undef SSHCONF_UNSUPPORTED_INT
#undef SSHCONF_UNSUPPORTED_STRING
#undef SSHCONF_ALIAS
}

/* Returns 1 if a string option is unset or set to "none" or 0 otherwise. */
स्थिर पूर्णाङ्क
option_clear_or_none(ध्रुव वर्ण *o)
{
	पटिनिवत्त o == रिक्त || strcasecmp(o, "none") == 0;
}

स्थिर शून्य
assemble_algorithms(ServerOptions *o)
{
	वर्ण *all_cipher, *all_mac, *all_kex, *all_कुञ्चिका, *all_sig;
	वर्ण *def_cipher, *def_mac, *def_kex, *def_कुञ्चिका, *def_sig;
	पूर्णाङ्क r;

	all_cipher = cipher_alg_list(',', 0);
	all_mac = mac_alg_list(',');
	all_kex = kex_alg_list(',');
	all_कुञ्चिका = sshkey_alg_list(0, 0, 1, ',');
	all_sig = sshkey_alg_list(0, 1, 1, ',');
	/* remove unsupported algos from default lists */
	def_cipher = match_filter_allowlist(KEX_SERVER_ENCRYPT, all_cipher);
	def_mac = match_filter_allowlist(KEX_SERVER_MAC, all_mac);
	def_kex = match_filter_allowlist(KEX_SERVER_KEX, all_kex);
	def_कुञ्चिका = match_filter_allowlist(KEX_DEFAULT_PK_ALG, all_कुञ्चिका);
	def_sig = match_filter_allowlist(SSH_ALLOWED_CA_SIGALGS, all_sig);
#define ASSEMBLE(what, defaults, all) \
	करोहि { \
		सचे ((r = kex_assemble_names(&o->what, defaults, all)) != 0) \
			fatal_fr(r, "%s", #what); \
	} याव (0)
	ASSEMBLE(ciphers, def_cipher, all_cipher);
	ASSEMBLE(macs, def_mac, all_mac);
	ASSEMBLE(kex_algorithms, def_kex, all_kex);
	ASSEMBLE(hostkeyalgorithms, def_कुञ्चिका, all_कुञ्चिका);
	ASSEMBLE(hostbased_accepted_algos, def_कुञ्चिका, all_कुञ्चिका);
	ASSEMBLE(pubkey_accepted_algos, def_कुञ्चिका, all_कुञ्चिका);
	ASSEMBLE(ca_sign_algorithms, def_sig, all_sig);
#undef ASSEMBLE
	मुक्त(all_cipher);
	मुक्त(all_mac);
	मुक्त(all_kex);
	मुक्त(all_कुञ्चिका);
	मुक्त(all_sig);
	मुक्त(def_cipher);
	मुक्त(def_mac);
	मुक्त(def_kex);
	मुक्त(def_कुञ्चिका);
	मुक्त(def_sig);
}

शून्य
servconf_add_hostkey(ध्रुव वर्ण *file, ध्रुव पूर्णाङ्क पङ्क्तिः,
    ServerOptions *options, ध्रुव वर्ण *path, पूर्णाङ्क userprovided)
{
	वर्ण *apath = derelativise_path(path);

	opt_array_append2(file, पङ्क्तिः, "HostKey",
	    &options->host_कुञ्चिका_files, &options->host_कुञ्चिका_file_userprovided,
	    &options->अङ्कः_host_कुञ्चिका_files, apath, userprovided);
	मुक्त(apath);
}

शून्य
servconf_add_hostcert(ध्रुव वर्ण *file, ध्रुव पूर्णाङ्क पङ्क्तिः,
    ServerOptions *options, ध्रुव वर्ण *path)
{
	वर्ण *apath = derelativise_path(path);

	opt_array_append(file, पङ्क्तिः, "HostCertificate",
	    &options->host_cert_files, &options->अङ्कः_host_cert_files, apath);
	मुक्त(apath);
}

शून्य
fill_default_server_options(ServerOptions *options)
{
	u_int i;

	/* Portable-specific overrides */
#ifdef SKIP_PRIVDROP
	सचे (options->allow_streamlocal_forwarding != -1 &&
	    options->allow_streamlocal_forwarding != FORWARD_DENY)
		logit("StreamlocalForwarding is not supported on this system");
	options->allow_streamlocal_forwarding = 0;
	सचे (options->fwd_opts.gateway_ports != -1 &&
	    options->fwd_opts.gateway_ports != 0)
		logit("GatewayPorts is not supported on this system");
	options->fwd_opts.gateway_ports = 0;
#endif

#define SSHCONF_INT(var, conf, flags, ms, def, cp) \
	सचे (options->var == -1) \
		options->var = def;
#define SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	सचे (options->var == -1) \
		options->var = def;
#define SSHCONF_STRING(var, conf, flags, cp)		/* done manually */
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	/* done manually */
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	/* done manually */
#define SSHCONF_NONCONF(funcsuffix)			/* done manually */
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	करोहि { \
		मुक्त(options->var); \
		options->var = रिक्त; \
	} याव (0);
#define SSHCONF_ALIAS(old, conf, flags)			/* empty */

	/* XXX maybe use macros here too to force consistency? */

	SSHD_CONFIG_ENTRIES

#undef SSHCONF_INT
#undef SSHCONF_INTFLAG
#undef SSHCONF_STRING
#undef SSHCONF_STRARRAY
#undef SSHCONF_CUSTOM
#undef SSHCONF_NONCONF
#undef SSHCONF_DEPRECATE
#undef SSHCONF_UNSUPPORTED_INT
#undef SSHCONF_UNSUPPORTED_STRING
#undef SSHCONF_ALIAS

#ifdef USE_PAM
	सचे (options->pam_service_name == रिक्त)
		options->pam_service_name = xstrdup(SSHD_PAM_SERVICE);
#endif

	सचे (options->अङ्कः_host_कुञ्चिका_files == 0) {
		/* fill default hostkeys */
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_RSA_कुञ्चिका_FILE, 0);
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_ECDSA_कुञ्चिका_FILE, 0);
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_ED25519_कुञ्चिका_FILE, 0);
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_MLDSA44_ED25519_कुञ्चिका_FILE, 0);
	}
	/* No certificates by default */
	सचे (options->अङ्कः_ports == 0)
		options->ports[options->अङ्कः_ports++] = SSH_DEFAULT_PORT;
	सचे (options->listen_addrs == रिक्त)
		add_listen_addr(options, रिक्त, रिक्त, 0);
	सचे (options->pid_file == रिक्त)
		options->pid_file = xstrdup(_PATH_SSH_DAEMON_PID_FILE);
	सचे (options->moduli_file == रिक्त)
		options->moduli_file = xstrdup(_PATH_DH_MODULI);
	सचे (options->xauth_location == रिक्त)
		options->xauth_location = xstrdup(_PATH_XAUTH);
	सचे (options->log_facility == SYSLOG_FACILITY_NOT_SET)
		options->log_facility = SYSLOG_FACILITY_AUTH;
	सचे (options->log_level == SYSLOG_LEVEL_NOT_SET)
		options->log_level = SYSLOG_LEVEL_INFO;
	सचे (options->permit_user_env == -1) {
		options->permit_user_env = 0;
		options->permit_user_env_allowlist = रिक्त;
	}
	सचे (options->rekey_limit == -1)
		options->rekey_limit = 0;
	सचे (options->rekey_interval == -1)
		options->rekey_interval = 0;
	सचे (options->fwd_opts.gateway_ports == -1)
		options->fwd_opts.gateway_ports = 0;
	सचे (options->max_startups == -1)
		options->max_startups = 100;
	सचे (options->max_startups_rate == -1)
		options->max_startups_rate = 30;		/* 30% */
	सचे (options->max_startups_begin == -1)
		options->max_startups_begin = 10;
	सचे (options->per_source_masklen_ipv4 == -1)
		options->per_source_masklen_ipv4 = 32;
	सचे (options->per_source_masklen_ipv6 == -1)
		options->per_source_masklen_ipv6 = 128;
	सचे (options->per_source_penalty.enabled == -1)
		options->per_source_penalty.enabled = 1;
	सचे (options->per_source_penalty.max_sources4 == -1)
		options->per_source_penalty.max_sources4 = 65536;
	सचे (options->per_source_penalty.max_sources6 == -1)
		options->per_source_penalty.max_sources6 = 65536;
	सचे (options->per_source_penalty.overflow_mode == -1)
		options->per_source_penalty.overflow_mode = PER_SOURCE_PENALTY_OVERFLOW_PERMISSIVE;
	सचे (options->per_source_penalty.overflow_mode6 == -1)
		options->per_source_penalty.overflow_mode6 = options->per_source_penalty.overflow_mode;
	सचे (options->per_source_penalty.penalty_crash < 0.0)
		options->per_source_penalty.penalty_crash = 90.0;
	सचे (options->per_source_penalty.penalty_grace < 0.0)
		options->per_source_penalty.penalty_grace = 10.0;
	सचे (options->per_source_penalty.penalty_authfail < 0.0)
		options->per_source_penalty.penalty_authfail = 5.0;
	सचे (options->per_source_penalty.penalty_invaliduser < 0.0)
		options->per_source_penalty.penalty_invaliduser = 5.0;
	सचे (options->per_source_penalty.penalty_noauth < 0.0)
		options->per_source_penalty.penalty_noauth = 1.0;
	सचे (options->per_source_penalty.penalty_refuseconnection < 0.0)
		options->per_source_penalty.penalty_refuseconnection = 10.0;
	सचे (options->per_source_penalty.penalty_min < 0.0)
		options->per_source_penalty.penalty_min = 15.0;
	सचे (options->per_source_penalty.penalty_max < 0.0)
		options->per_source_penalty.penalty_max = 600.0;
	सचे (options->अङ्कः_authkeys_files == 0) {
		opt_array_append("[default]", 0, "AuthorizedKeysFiles",
		    &options->authorized_कुञ्चिकाः_files,
		    &options->अङ्कः_authkeys_files,
		    PATH_SSH_USER_PERMITTED_कुञ्चिकाः);
		opt_array_append("[default]", 0, "AuthorizedKeysFiles",
		    &options->authorized_कुञ्चिकाः_files,
		    &options->अङ्कः_authkeys_files,
		    _PATH_SSH_USER_PERMITTED_KEYS2);
	}
	सचे (options->ip_qos_interactive == -1)
		options->ip_qos_interactive = IPTOS_DSCP_EF;
	सचे (options->ip_qos_bulk == -1)
		options->ip_qos_bulk = IPTOS_DSCP_CS0;
	सचे (options->version_addendum == रिक्त)
		options->version_addendum = xstrdup("");
	सचे (options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
		options->fwd_opts.streamlocal_bind_mask = 0177;
	सचे (options->fwd_opts.streamlocal_bind_unlink == -1)
		options->fwd_opts.streamlocal_bind_unlink = 0;
	सचे (options->sk_provider == रिक्त)
		options->sk_provider = xstrdup("internal");
	सचे (options->sshd_session_path == रिक्त)
		options->sshd_session_path = xstrdup(_PATH_SSHD_SESSION);
	सचे (options->sshd_auth_path == रिक्त)
		options->sshd_auth_path = xstrdup(_PATH_SSHD_AUTH);
	सचे (options->pubkey_auth_options == -1) {
		options->pubkey_auth_options = 0;
		options->max_pubkey_ok = DEFAULT_AUTH_FAIL_MAX;
	}
	सचे (options->agent_socket_path == रिक्त)
		options->agent_socket_path = xstrdup(_PATH_SSH_AGENT_SOCKET_DIR);

	assemble_algorithms(options);

#define CLEAR_ON_NONE(v) \
	करोहि { \
		सचे (option_clear_or_none(v)) { \
			मुक्त(v); \
			v = रिक्त; \
		} \
	} याव(0)
#define CLEAR_ON_NONE_ARRAY(v, nv, none) \
	करोहि { \
		सचे (options->nv == 1 && \
		    strcasecmp(options->v[0], none) == 0) { \
			मुक्त(options->v[0]); \
			मुक्त(options->v); \
			options->v = रिक्त; \
			options->nv = 0; \
		} \
	} याव (0)
	CLEAR_ON_NONE(options->pid_file);
	CLEAR_ON_NONE(options->xauth_location);
	CLEAR_ON_NONE(options->banner);
	CLEAR_ON_NONE(options->trusted_user_ca_कुञ्चिकाः);
	CLEAR_ON_NONE(options->sk_provider);
	CLEAR_ON_NONE(options->authorized_principals_file);
	CLEAR_ON_NONE(options->adm_forced_command);
	CLEAR_ON_NONE(options->chroot_directory);
	CLEAR_ON_NONE(options->routing_domain);
	CLEAR_ON_NONE(options->host_कुञ्चिका_agent);
	CLEAR_ON_NONE(options->per_source_penalty_exempt);
	CLEAR_ON_NONE(options->agent_socket_path);

	अत्थाय (i = 0; i < options->अङ्कः_host_कुञ्चिका_files; i++)
		CLEAR_ON_NONE(options->host_कुञ्चिका_files[i]);
	अत्थाय (i = 0; i < options->अङ्कः_host_cert_files; i++)
		CLEAR_ON_NONE(options->host_cert_files[i]);

	CLEAR_ON_NONE_ARRAY(channel_timeouts, अङ्कः_channel_timeouts, "none");
	CLEAR_ON_NONE_ARRAY(auth_methods, अङ्कः_auth_methods, "any");
	CLEAR_ON_NONE_ARRAY(revoked_कुञ्चिकाः_files, अङ्कः_revoked_कुञ्चिकाः_files, "none");
	CLEAR_ON_NONE_ARRAY(authorized_कुञ्चिकाः_files, अङ्कः_authkeys_files, "none");
#undef CLEAR_ON_NONE
#undef CLEAR_ON_NONE_ARRAY
}

/* Macros to declare ServerOpCodes enum values */
#define SSHCONF_INT(var, conf, flags, ms, def, cp)	s##conf,
#define SSHCONF_INTFLAG(var, conf, flags, def, cp)	s##conf,
#define SSHCONF_STRING(var, conf, flags, cp)		s##conf,
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	s##conf,
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	s##conf,
#define SSHCONF_NONCONF(funcsuffix)			/* empty */
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	/* empty */
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	/* empty */
#define SSHCONF_ALIAS(old, conf, flags)			/* empty */

/* Keyword tokens. */
प्रकारनिर्देश गणना {
	sBadOption,		/* == unknown option */
	SSHD_CONFIG_ENTRIES
	sMatch, sInclude,
	sDeprecated, sIgnore, sUnsupported
} ServerOpCodes;
#undef SSHCONF_INT
#undef SSHCONF_INTFLAG
#undef SSHCONF_STRING
#undef SSHCONF_STRARRAY
#undef SSHCONF_CUSTOM
#undef SSHCONF_NONCONF
#undef SSHCONF_DEPRECATE
#undef SSHCONF_UNSUPPORTED_INT
#undef SSHCONF_UNSUPPORTED_STRING
#undef SSHCONF_ALIAS

#define SSHCFG_GLOBAL		0x01	/* allowed in main section of config */
#define SSHCFG_MATCH		0x02	/* allowed inside a Match section */
#define SSHCFG_ALL		(SSHCFG_GLOBAL|SSHCFG_MATCH)
#define SSHCFG_NEVERMATCH	0x04  /* Match never matches; internal only */
#define SSHCFG_MATCH_ONLY	0x08  /* Match only in conditional blocks; internal only */

/* Macros to define keywords[] entries */
#define SSHCONF_KW(conf, flags)		{ #conf, s##conf, flags },
#define SSHCONF_INT(var, conf, flags, ms, def, cp)	SSHCONF_KW(conf, flags)
#define SSHCONF_INTFLAG(var, conf, flags, def, cp)	SSHCONF_KW(conf, flags)
#define SSHCONF_STRING(var, conf, flags, cp)		SSHCONF_KW(conf, flags)
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	SSHCONF_KW(conf, flags)
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	SSHCONF_KW(conf, flags)
#define SSHCONF_NONCONF(funcsuffix)			/* empty */
#define SSHCONF_DEPRECATED				sDeprecated
#define SSHCONF_IGNORE					sIgnore
#define SSHCONF_DEPRECATE(conf, flags, opcode) \
	{ #conf, opcode, flags },
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags) \
	{ #conf, sUnsupported, flags },
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	{ #conf, sUnsupported, flags },
#define SSHCONF_ALIAS(old, conf, flags) \
	{ #old, s##conf, flags },

/* Textual representation of the tokens. */
स्थिर संरचना {
	ध्रुव वर्ण *name;
	ServerOpCodes opcode;
	u_int flags;
} keywords[] = {
	SSHD_CONFIG_ENTRIES
	{ "match", sMatch, SSHCFG_ALL },
	{ "include", sInclude, SSHCFG_ALL },
	{ रिक्त, sBadOption, 0 }
};
#undef SSHCONF_INT
#undef SSHCONF_INTFLAG
#undef SSHCONF_STRING
#undef SSHCONF_STRARRAY
#undef SSHCONF_CUSTOM
#undef SSHCONF_NONCONF
#undef SSHCONF_DEPRECATED
#undef SSHCONF_IGNORE
#undef SSHCONF_DEPRECATE
#undef SSHCONF_UNSUPPORTED_INT
#undef SSHCONF_UNSUPPORTED_STRING
#undef SSHCONF_ALIAS

स्थिर संरचना {
	पूर्णाङ्क val;
	वर्ण *text;
} tunmode_desc[] = {
	{ SSH_TUNMODE_NO, "no" },
	{ SSH_TUNMODE_POINTOPOINT, "point-to-point" },
	{ SSH_TUNMODE_ETHERNET, "ethernet" },
	{ SSH_TUNMODE_YES, "yes" },
	{ -1, रिक्त }
};

/* Returns an opcode name from its number */

स्थिर ध्रुव वर्ण *
lookup_opcode_name(ServerOpCodes code)
{
	u_int i;

	अत्थाय (i = 0; keywords[i].name != रिक्त; i++)
		सचे (keywords[i].opcode == code)
			पटिनिवत्त(keywords[i].name);
	पटिनिवत्त "UNKNOWN";
}


/*
 * Returns the number of the token pointed to by cp or sBadOption.
 */

स्थिर ServerOpCodes
parse_token(ध्रुव वर्ण *cp, ध्रुव वर्ण *filename,
	    पूर्णाङ्क linenum, u_int *flags)
{
	u_int i;

	अत्थाय (i = 0; keywords[i].name; i++)
		सचे (strcasecmp(cp, keywords[i].name) == 0) {
			*flags = keywords[i].flags;
			पटिनिवत्त keywords[i].opcode;
		}

	error("%s: line %d: Bad configuration option: %s",
	    filename, linenum, cp);
	पटिनिवत्त sBadOption;
}

वर्ण *
derelativise_path(ध्रुव वर्ण *path)
{
	वर्ण *expanded, *ret, cwd[PATH_MAX];

	सचे (strcasecmp(path, "none") == 0)
		पटिनिवत्त xstrdup("none");
	expanded = tilde_expand_filename(path, getuid());
	सचे (path_absolute(expanded))
		पटिनिवत्त expanded;
	सचे (getcwd(cwd, परिमाण(cwd)) == रिक्त)
		fatal_f("getcwd: %s", strerror(errno));
	xasprintf(&ret, "%s/%s", cwd, expanded);
	मुक्त(expanded);
	पटिनिवत्त ret;
}

स्थिर शून्य
add_listen_addr(ServerOptions *options, ध्रुव वर्ण *addr,
    ध्रुव वर्ण *rdomain, पूर्णाङ्क port)
{
	u_int i;

	सचे (port > 0)
		add_one_listen_addr(options, addr, rdomain, port);
	अञ्ञथा {
		अत्थाय (i = 0; i < options->अङ्कः_ports; i++) {
			add_one_listen_addr(options, addr, rdomain,
			    options->ports[i]);
		}
	}
}

स्थिर शून्य
add_one_listen_addr(ServerOptions *options, ध्रुव वर्ण *addr,
    ध्रुव वर्ण *rdomain, पूर्णाङ्क port)
{
	संरचना addrinfo hints, *ai, *aitop;
	वर्ण strport[NI_MAXSERV];
	पूर्णाङ्क gaierr;
	u_int i;

	/* Find listen_addrs entry for this rdomain */
	अत्थाय (i = 0; i < options->अङ्कः_listen_addrs; i++) {
		सचे (rdomain == रिक्त && options->listen_addrs[i].rdomain == रिक्त)
			भङ्ग;
		सचे (rdomain == रिक्त || options->listen_addrs[i].rdomain == रिक्त)
			अनुवर्त;
		सचे (strcmp(rdomain, options->listen_addrs[i].rdomain) == 0)
			भङ्ग;
	}
	सचे (i >= options->अङ्कः_listen_addrs) {
		/* No entry for this rdomain; allocate one */
		सचे (i >= INT_MAX)
			fatal_f("too many listen addresses");
		options->listen_addrs = xrecallocarray(options->listen_addrs,
		    options->अङ्कः_listen_addrs, options->अङ्कः_listen_addrs + 1,
		    परिमाण(*options->listen_addrs));
		i = options->अङ्कः_listen_addrs++;
		सचे (rdomain != रिक्त)
			options->listen_addrs[i].rdomain = xstrdup(rdomain);
	}
	/* options->listen_addrs[i] points to the addresses for this rdomain */

	memset(&hints, 0, परिमाण(hints));
	hints.ai_family = options->address_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = (addr == रिक्त) ? AI_PASSIVE : 0;
	snprintf(strport, परिमाण strport, "%d", port);
	सचे ((gaierr = getaddrinfo(addr, strport, &hints, &aitop)) != 0)
		fatal("bad addr or host: %s (%s)",
		    addr ? addr : "<NULL>",
		    ssh_gai_strerror(gaierr));
	अत्थाय (ai = aitop; ai->ai_next; ai = ai->ai_next)
		;
	ai->ai_next = options->listen_addrs[i].addrs;
	options->listen_addrs[i].addrs = aitop;
}

/* Returns nonzero if the routing domain name is valid */
स्थिर पूर्णाङ्क
valid_rdomain(ध्रुव वर्ण *name)
{
#सचे defined(HAVE_SYS_VALID_RDOMAIN)
	पटिनिवत्त sys_valid_rdomain(name);
#नोचेद्यदि defined(__OpenBSD__)
	ध्रुव वर्ण *errstr;
	long long अङ्कः;
	संरचना rt_tableinfo info;
	पूर्णाङ्क mib[6];
	size_t miblen = परिमाण(mib);

	सचे (name == रिक्त)
		पटिनिवत्त 1;

	अङ्कः = strtonum(name, 0, 255, &errstr);
	सचे (errstr != रिक्त)
		पटिनिवत्त 0;

	/* Check whether the table actually exists */
	memset(mib, 0, परिमाण(mib));
	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[4] = NET_RT_TABLE;
	mib[5] = (पूर्णाङ्क)अङ्कः;
	सचे (sysctl(mib, 6, &info, &miblen, रिक्त, 0) == -1)
		पटिनिवत्त 0;

	पटिनिवत्त 1;
#अञ्ञथा /* defined(__OpenBSD__) */
	error("Routing domains are not supported on this platform");
	पटिनिवत्त 0;
#endif
}

/*
 * Queue a ListenAddress to be processed once we have all of the Ports
 * and AddressFamily options.
 */
स्थिर शून्य
queue_listen_addr(ServerOptions *options, ध्रुव वर्ण *addr,
    ध्रुव वर्ण *rdomain, पूर्णाङ्क port)
{
	संरचना queued_listenaddr *qla;

	options->queued_listen_addrs = xrecallocarray(
	    options->queued_listen_addrs,
	    options->अङ्कः_queued_listens, options->अङ्कः_queued_listens + 1,
	    परिमाण(*options->queued_listen_addrs));
	qla = &options->queued_listen_addrs[options->अङ्कः_queued_listens++];
	qla->addr = xstrdup(addr);
	qla->port = port;
	qla->rdomain = rdomain == रिक्त ? रिक्त : xstrdup(rdomain);
}

/*
 * Process queued (text) ListenAddress entries.
 */
स्थिर शून्य
process_queued_listen_addrs(ServerOptions *options)
{
	u_int i;
	संरचना queued_listenaddr *qla;

	सचे (options->अङ्कः_ports == 0)
		options->ports[options->अङ्कः_ports++] = SSH_DEFAULT_PORT;
	सचे (options->address_family == -1)
		options->address_family = AF_UNSPEC;

	अत्थाय (i = 0; i < options->अङ्कः_queued_listens; i++) {
		qla = &options->queued_listen_addrs[i];
		add_listen_addr(options, qla->addr, qla->rdomain, qla->port);
		मुक्त(qla->addr);
		मुक्त(qla->rdomain);
	}
	मुक्त(options->queued_listen_addrs);
	options->queued_listen_addrs = रिक्त;
	options->अङ्कः_queued_listens = 0;
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

स्थिर पूर्णाङ्क
match_cfg_पङ्क्तिः_group(ध्रुव वर्ण *grps, पूर्णाङ्क पङ्क्तिः, ध्रुव वर्ण *user)
{
	पूर्णाङ्क result = 0;
	संरचना passwd *pw;

	सचे (user == रिक्त)
		गच्छ out;

	सचे ((pw = getpwnam(user)) == रिक्त) {
		debug("Can't match group at line %d because user %.100s does "
		    "not exist", पङ्क्तिः, user);
	} अञ्ञथा सचे (ga_init(pw->pw_name, pw->pw_gid) == 0) {
		debug("Can't Match group because user %.100s not in any group "
		    "at line %d", user, पङ्क्तिः);
	} अञ्ञथा सचे (ga_match_pattern_list(grps) != 1) {
		debug("user %.100s does not match group list %.100s at line %d",
		    user, grps, पङ्क्तिः);
	} अञ्ञथा {
		debug("user %.100s matched group list %.100s at line %d", user,
		    grps, पङ्क्तिः);
		result = 1;
	}
out:
	ga_free();
	पटिनिवत्त result;
}

स्थिर शून्य
match_test_missing_fatal(ध्रुव वर्ण *criteria, ध्रुव वर्ण *attrib)
{
	fatal("'Match %s' in configuration but '%s' not in connection "
	    "test specification.", criteria, attrib);
}

/*
 * All of the attributes on a single Match line are ANDed together, so we need
 * to check every attribute and set the result to zero if any attribute does
 * not match.
 */
स्थिर पूर्णाङ्क
match_cfg_पङ्क्तिः(ध्रुव वर्ण *full_पङ्क्तिः, पूर्णाङ्क *acp, वर्ण ***avp,
    पूर्णाङ्क पङ्क्तिः, संरचना connection_info *ci)
{
	पूर्णाङ्क result = 1, attributes = 0, port;
	वर्ण *arg, *attrib = रिक्त, *oattrib;

	सचे (ci == रिक्त) {
		debug3("checking syntax for 'Match %s' on line %d",
		    full_पङ्क्तिः, पङ्क्तिः);
	} अञ्ञथा {
		debug3("checking match for '%s' user %s%s host %s addr %s "
		    "laddr %s lport %d rdomain %s on line %d", full_पङ्क्तिः,
		    ci->user ? ci->user : "(null)",
		    ci->user_invalid ? " (invalid)" : "",
		    ci->host ? ci->host : "(null)",
		    ci->address ? ci->address : "(null)",
		    ci->laddress ? ci->laddress : "(null)", ci->lport,
		    ci->rdomain ? ci->rdomain : "(null)", पङ्क्तिः);
	}

	याव ((oattrib = argv_next(acp, avp)) != रिक्त) {
		/* Terminate on comment */
		सचे (*oattrib == '#') {
			argv_consume(acp); /* mark all arguments consumed */
			भङ्ग;
		}
		attrib = xstrdup(oattrib);
		arg = रिक्त;
		attributes++;
		/* Criterion "all" has no argument and must appear alone */
		सचे (strcasecmp(attrib, "all") == 0) {
			सचे (attributes > 1 ||
			    ((arg = argv_next(acp, avp)) != रिक्त &&
			    *arg != '\0' && *arg != '#')) {
				error("'all' cannot be combined with other "
				    "Match attributes");
				result = -1;
				गच्छ out;
			}
			सचे (arg != रिक्त && *arg == '#')
				argv_consume(acp); /* consume remaining args */
			result = 1;
			गच्छ out;
		}
		/* Criterion "invalid-user" also has no argument */
		सचे (strcasecmp(attrib, "invalid-user") == 0) {
			सचे (ci == रिक्त) {
				result = 0;
				गच्छ next;
			}
			सचे (ci->user_invalid == 0)
				result = 0;
			अञ्ञथा
				debug("matched invalid-user at line %d", पङ्क्तिः);
			गच्छ next;
		}

		/* Keep this list in sync with below */
		सचे (strprefix(attrib, "user=", 1) != रिक्त ||
		    strprefix(attrib, "group=", 1) != रिक्त ||
		    strprefix(attrib, "host=", 1) != रिक्त ||
		    strprefix(attrib, "address=", 1) != रिक्त ||
		    strprefix(attrib, "localaddress=", 1) != रिक्त ||
		    strprefix(attrib, "localport=", 1) != रिक्त ||
		    strprefix(attrib, "rdomain=", 1) != रिक्त ||
		    strprefix(attrib, "version=", 1) != रिक्त) {
			arg = strchr(attrib, '=');
			*(arg++) = '\0';
		} अञ्ञथा {
			arg = argv_next(acp, avp);
		}

		/* All other criteria require an argument */
		सचे (arg == रिक्त || *arg == '\0' || *arg == '#') {
			error("Missing Match criteria for %s", attrib);
			result = -1;
			गच्छ out;
		}
		सचे (strcasecmp(attrib, "user") == 0) {
			सचे (ci == रिक्त || (ci->test && ci->user == रिक्त)) {
				result = 0;
				गच्छ next;
			}
			सचे (ci->user == रिक्त)
				match_test_missing_fatal("User", "user");
			सचे (match_usergroup_pattern_list(ci->user, arg) != 1)
				result = 0;
			अञ्ञथा
				debug("user %.100s matched 'User %.100s' at "
				    "line %d", ci->user, arg, पङ्क्तिः);
		} अञ्ञथा सचे (strcasecmp(attrib, "group") == 0) {
			सचे (ci == रिक्त || (ci->test && ci->user == रिक्त)) {
				result = 0;
				गच्छ next;
			}
			सचे (ci->user == रिक्त)
				match_test_missing_fatal("Group", "user");
			विकल्प (match_cfg_पङ्क्तिः_group(arg, पङ्क्तिः, ci->user)) {
			पक्ष -1:
				result = -1;
				गच्छ out;
			पक्ष 0:
				result = 0;
			}
		} अञ्ञथा सचे (strcasecmp(attrib, "host") == 0) {
			सचे (ci == रिक्त || (ci->test && ci->host == रिक्त)) {
				result = 0;
				गच्छ next;
			}
			सचे (ci->host == रिक्त)
				match_test_missing_fatal("Host", "host");
			सचे (match_hostname(ci->host, arg) != 1)
				result = 0;
			अञ्ञथा
				debug("connection from %.100s matched 'Host "
				    "%.100s' at line %d", ci->host, arg, पङ्क्तिः);
		} अञ्ञथा सचे (strcasecmp(attrib, "address") == 0) {
			सचे (ci == रिक्त || (ci->test && ci->address == रिक्त)) {
				सचे (addr_match_list(रिक्त, arg) != 0)
					fatal("Invalid Match address argument "
					    "'%s' at line %d", arg, पङ्क्तिः);
				result = 0;
				गच्छ next;
			}
			सचे (ci->address == रिक्त)
				match_test_missing_fatal("Address", "addr");
			विकल्प (addr_match_list(ci->address, arg)) {
			पक्ष 1:
				debug("connection from %.100s matched 'Address "
				    "%.100s' at line %d", ci->address, arg, पङ्क्तिः);
				भङ्ग;
			पक्ष 0:
			पक्ष -1:
				result = 0;
				भङ्ग;
			पक्ष -2:
				result = -1;
				गच्छ out;
			}
		} अञ्ञथा सचे (strcasecmp(attrib, "localaddress") == 0){
			सचे (ci == रिक्त || (ci->test && ci->laddress == रिक्त)) {
				सचे (addr_match_list(रिक्त, arg) != 0)
					fatal("Invalid Match localaddress "
					    "argument '%s' at line %d", arg,
					    पङ्क्तिः);
				result = 0;
				गच्छ next;
			}
			सचे (ci->laddress == रिक्त)
				match_test_missing_fatal("LocalAddress",
				    "laddr");
			विकल्प (addr_match_list(ci->laddress, arg)) {
			पक्ष 1:
				debug("connection from %.100s matched "
				    "'LocalAddress %.100s' at line %d",
				    ci->laddress, arg, पङ्क्तिः);
				भङ्ग;
			पक्ष 0:
			पक्ष -1:
				result = 0;
				भङ्ग;
			पक्ष -2:
				result = -1;
				गच्छ out;
			}
		} अञ्ञथा सचे (strcasecmp(attrib, "localport") == 0) {
			सचे ((port = a2port(arg)) == -1) {
				error("Invalid LocalPort '%s' on Match line",
				    arg);
				result = -1;
				गच्छ out;
			}
			सचे (ci == रिक्त || (ci->test && ci->lport == -1)) {
				result = 0;
				गच्छ next;
			}
			सचे (ci->lport == 0)
				match_test_missing_fatal("LocalPort", "lport");
			/* TODO support port lists */
			सचे (port == ci->lport)
				debug("connection from %.100s matched "
				    "'LocalPort %d' at line %d",
				    ci->laddress, port, पङ्क्तिः);
			अञ्ञथा
				result = 0;
		} अञ्ञथा सचे (strcasecmp(attrib, "rdomain") == 0) {
			सचे (ci == रिक्त || (ci->test && ci->rdomain == रिक्त)) {
				result = 0;
				गच्छ next;
			}
			सचे (ci->rdomain == रिक्त)
				match_test_missing_fatal("RDomain", "rdomain");
			सचे (match_pattern_list(ci->rdomain, arg, 0) != 1)
				result = 0;
			अञ्ञथा
				debug("connection RDomain %.100s matched "
				    "'RDomain %.100s' at line %d",
				    ci->rdomain, arg, पङ्क्तिः);
		} अञ्ञथा सचे (strcasecmp(attrib, "version") == 0) {
			सचे (match_pattern_list(SSH_RELEASE, arg, 0) != 1)
				result = 0;
			अञ्ञथा
				debug("version %.100s matched "
				    "'version %.100s' at line %d",
				    SSH_RELEASE, arg, पङ्क्तिः);
		} अञ्ञथा {
			error("Unsupported Match attribute %s", oattrib);
			result = -1;
			गच्छ out;
		}
 next:
		मुक्त(attrib);
		attrib = रिक्त;
	}
	सचे (attributes == 0) {
		error("One or more attributes required for Match");
		पटिनिवत्त -1;
	}
 out:
	सचे (ci != रिक्त && result != -1)
		debug3("match %sfound on line %d", result ? "" : "not ", पङ्क्तिः);
	मुक्त(attrib);
	पटिनिवत्त result;
}

#define WHITESPACE " \t\r\n"

/* Multistate option parsing */
संरचना multistate {
	वर्ण *कुञ्चिका;
	पूर्णाङ्क मानम्;
};
स्थिर ध्रुव संरचना multistate multistate_flag[] = {
	{ "yes",			1 },
	{ "no",				0 },
	{ रिक्त, -1 }
};
स्थिर ध्रुव संरचना multistate multistate_ignore_rhosts[] = {
	{ "yes",			IGNORE_RHOSTS_YES },
	{ "no",				IGNORE_RHOSTS_NO },
	{ "shosts-only",		IGNORE_RHOSTS_SHOSTS },
	{ रिक्त, -1 }
};
स्थिर ध्रुव संरचना multistate multistate_addressfamily[] = {
	{ "inet",			AF_INET },
	{ "inet6",			AF_INET6 },
	{ "any",			AF_UNSPEC },
	{ रिक्त, -1 }
};
स्थिर ध्रुव संरचना multistate multistate_permitrootlogin[] = {
	{ "prohibit-password",		PERMIT_NO_PASSWD },
	{ "without-password",		PERMIT_NO_PASSWD },
	{ "forced-commands-only",	PERMIT_FORCED_ONLY },
	{ "yes",			PERMIT_YES },
	{ "no",				PERMIT_NO },
	{ रिक्त, -1 }
};
स्थिर ध्रुव संरचना multistate multistate_compression[] = {
#ifdef WITH_ZLIB
	{ "yes",			COMP_DELAYED },
	{ "delayed",			COMP_DELAYED },
#endif
	{ "no",				COMP_NONE },
	{ रिक्त, -1 }
};
स्थिर ध्रुव संरचना multistate multistate_gatewayports[] = {
	{ "clientspecified",		2 },
	{ "yes",			1 },
	{ "no",				0 },
	{ रिक्त, -1 }
};
स्थिर ध्रुव संरचना multistate multistate_tcpfwd[] = {
	{ "yes",			FORWARD_ALLOW },
	{ "all",			FORWARD_ALLOW },
	{ "no",				FORWARD_DENY },
	{ "remote",			FORWARD_REMOTE },
	{ "local",			FORWARD_LOCAL },
	{ रिक्त, -1 }
};
स्थिर ध्रुव संरचना multistate multistate_keepalives[] = {
	{ "true",			SSH_KEEPALIVES_TRANSPORT },
	{ "false",			SSH_KEEPALIVES_OFF },
	{ "yes",			SSH_KEEPALIVES_TRANSPORT },
	{ "no",				SSH_KEEPALIVES_OFF },
	{ "transport",			SSH_KEEPALIVES_TRANSPORT },
	{ "all",			SSH_KEEPALIVES_ALL },
	{ रिक्त, -1 }
};
स्थिर ध्रुव संरचना multistate multistate_warnweakcrypto[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "no-pq-kex",			0 },
	{ रिक्त, -1 }
};

स्थिर पूर्णाङ्क
process_server_config_पङ्क्तिः_depth(ServerOptions *options, वर्ण *पङ्क्तिः,
    ध्रुव वर्ण *filename, पूर्णाङ्क linenum, पूर्णाङ्क *activep,
    संरचना connection_info *connectinfo, पूर्णाङ्क *inc_flags, पूर्णाङ्क depth,
    संरचना include_list *includes)
{
	वर्ण *str, ***chararrayptr, **charptr, *arg, *arg2, *p, *keyword;
	पूर्णाङ्क cmdline = 0, *intptr, मानम्, value2, value3, n, port, oactive, r;
	द्विगुण dvalue, *doubleptr = रिक्त;
	पूर्णाङ्क ca_only = 0, found = 0;
	SyslogFacility *log_facility_ptr;
	LogLevel *log_level_ptr;
	ServerOpCodes opcode;
	u_int i, *uintptr, flags = 0;
	size_t len;
	long long val64;
	ध्रुव संरचना multistate *multistate_ptr;
	ध्रुव वर्ण *errstr;
	संरचना include_item *item;
	glob_t gbuf;
	वर्ण **oav = रिक्त, **av;
	पूर्णाङ्क oac = 0, ac;
	पूर्णाङ्क ret = -1;
	वर्ण **strs = रिक्त; /* string array arguments; freed implicitly */
	u_int nstrs = 0;

	/* Strip trailing whitespace. Allow \f (form feed) at EOL only */
	सचे ((len = strlen(पङ्क्तिः)) == 0)
		पटिनिवत्त 0;
	अत्थाय (len--; len > 0; len--) {
		सचे (strchr(WHITESPACE "\f", पङ्क्तिः[len]) == रिक्त)
			भङ्ग;
		पङ्क्तिः[len] = '\0';
	}

	str = पङ्क्तिः;
	सचे ((keyword = strdelim(&str)) == रिक्त)
		पटिनिवत्त 0;
	/* Ignore leading whitespace */
	सचे (*keyword == '\0')
		keyword = strdelim(&str);
	सचे (!keyword || !*keyword || *keyword == '#')
		पटिनिवत्त 0;
	सचे (str == रिक्त || *str == '\0') {
		error("%s line %d: no argument after keyword \"%s\"",
		    filename, linenum, keyword);
		पटिनिवत्त -1;
	}
	intptr = रिक्त;
	charptr = रिक्त;
	opcode = parse_token(keyword, filename, linenum, &flags);

	सचे (argv_split(str, &oac, &oav, 1) != 0) {
		error("%s line %d: invalid quotes", filename, linenum);
		पटिनिवत्त -1;
	}
	ac = oac;
	av = oav;

	सचे (activep == रिक्त) { /* We are processing a command line directive */
		cmdline = 1;
		activep = &cmdline;
	}
	सचे (*activep && opcode != sMatch && opcode != sInclude)
		debug3("%s:%d setting %s %s", filename, linenum, keyword, str);
	सचे (*activep == 0 && !(flags & SSHCFG_MATCH)) {
		सचे (connectinfo == रिक्त) {
			fatal("%s line %d: Directive '%s' is not allowed "
			    "within a Match block", filename, linenum, keyword);
		} अञ्ञथा { /* this is a directive we have already processed */
			ret = 0;
			गच्छ out;
		}
	}

	विकल्प (opcode) {
	/* Portable-specific options */
#ifdef USE_PAM
	पक्ष sUsePAM:
		intptr = &options->use_pam;
		गच्छ parse_flag;
	पक्ष sPAMServiceName:
		charptr = &options->pam_service_name;
		arg = argv_next(&ac, &av);
		सचे (!arg || *arg == '\0') {
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		}
		सचे (*activep && *charptr == रिक्त)
			*charptr = xstrdup(arg);
		भङ्ग;
#endif

	/* Standard Options */
	पक्ष sBadOption:
		गच्छ out;
	पक्ष sPort:
		/* ignore ports from configfile if cmdline specifies ports */
		सचे (options->ports_from_cmdline) {
			argv_consume(&ac);
			भङ्ग;
		}
		सचे (options->अङ्कः_ports >= MAX_PORTS)
			fatal("%s line %d: too many ports.",
			    filename, linenum);
		arg = argv_next(&ac, &av);
		सचे (!arg || *arg == '\0')
			fatal("%s line %d: missing port number.",
			    filename, linenum);
		options->ports[options->अङ्कः_ports++] = a2port(arg);
		सचे (options->ports[options->अङ्कः_ports-1] <= 0)
			fatal("%s line %d: Badly formatted port number.",
			    filename, linenum);
		भङ्ग;

	पक्ष sLoginGraceTime:
		intptr = &options->login_grace_time;
 parse_time:
		arg = argv_next(&ac, &av);
		सचे (!arg || *arg == '\0')
			fatal("%s line %d: missing time value.",
			    filename, linenum);
		सचे ((मानम् = convtime(arg)) == -1)
			fatal("%s line %d: invalid time value.",
			    filename, linenum);
		सचे (*activep && *intptr == -1)
			*intptr = मानम्;
		भङ्ग;

	पक्ष sListenAddress:
		arg = argv_next(&ac, &av);
		सचे (arg == रिक्त || *arg == '\0')
			fatal("%s line %d: missing address",
			    filename, linenum);
		/* check for bare IPv6 address: no "[]" and 2 or more ":" */
		सचे (strchr(arg, '[') == रिक्त && (p = strchr(arg, ':')) != रिक्त
		    && strchr(p+1, ':') != रिक्त) {
			port = 0;
			p = arg;
		} अञ्ञथा {
			arg2 = रिक्त;
			p = hpdelim(&arg);
			सचे (p == रिक्त)
				fatal("%s line %d: bad address:port usage",
				    filename, linenum);
			p = cleanhostname(p);
			सचे (arg == रिक्त)
				port = 0;
			अञ्ञथा सचे ((port = a2port(arg)) <= 0)
				fatal("%s line %d: bad port number",
				    filename, linenum);
		}
		/* Optional routing table */
		arg2 = रिक्त;
		सचे ((arg = argv_next(&ac, &av)) != रिक्त) {
			सचे (strcmp(arg, "rdomain") != 0 ||
			    (arg2 = argv_next(&ac, &av)) == रिक्त)
				fatal("%s line %d: bad ListenAddress syntax",
				    filename, linenum);
			सचे (!valid_rdomain(arg2))
				fatal("%s line %d: bad routing domain",
				    filename, linenum);
		}
		queue_listen_addr(options, p, arg2, port);

		भङ्ग;

	पक्ष sAddressFamily:
		intptr = &options->address_family;
		multistate_ptr = multistate_addressfamily;
 parse_multistate:
		arg = argv_next(&ac, &av);
		सचे (!arg || *arg == '\0')
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		मानम् = -1;
		अत्थाय (i = 0; multistate_ptr[i].कुञ्चिका != रिक्त; i++) {
			सचे (strcasecmp(arg, multistate_ptr[i].कुञ्चिका) == 0) {
				मानम् = multistate_ptr[i].मानम्;
				भङ्ग;
			}
		}
		सचे (मानम् == -1)
			fatal("%s line %d: unsupported option \"%s\".",
			    filename, linenum, arg);
		सचे (*activep && *intptr == -1)
			*intptr = मानम्;
		भङ्ग;

	पक्ष s_Host_कुञ्चिका:
		arg = argv_next(&ac, &av);
		सचे (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		सचे (*activep) {
			servconf_add_hostkey(filename, linenum,
			    options, arg, 1);
		}
		भङ्ग;

	पक्ष s_Host_कुञ्चिका_Agent:
		charptr = &options->host_कुञ्चिका_agent;
		arg = argv_next(&ac, &av);
		सचे (!arg || *arg == '\0')
			fatal("%s line %d: missing socket name.",
			    filename, linenum);
		सचे (*activep && *charptr == रिक्त)
			*charptr = !strcmp(arg, SSH_AUTHSOCKET_ENV_NAME) ?
			    xstrdup(arg) : derelativise_path(arg);
		भङ्ग;

	पक्ष sHostCertificate:
		arg = argv_next(&ac, &av);
		सचे (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		सचे (*activep)
			servconf_add_hostcert(filename, linenum, options, arg);
		भङ्ग;

	पक्ष sPidFile:
		charptr = &options->pid_file;
 parse_filename:
		arg = argv_next(&ac, &av);
		सचे (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		सचे (*activep && *charptr == रिक्त) {
			*charptr = derelativise_path(arg);
			/* increase optional counter */
			सचे (intptr != रिक्त)
				*intptr = *intptr + 1;
		}
		भङ्ग;

	पक्ष sModuliFile:
		charptr = &options->moduli_file;
		गच्छ parse_filename;

	पक्ष s_Permit_मूलम्_Login:
		intptr = &options->permit_मूलम्_login;
		multistate_ptr = multistate_permitrootlogin;
		गच्छ parse_multistate;

	पक्ष sIgnoreRhosts:
		intptr = &options->ignore_rhosts;
		multistate_ptr = multistate_ignore_rhosts;
		गच्छ parse_multistate;

	पक्ष sIgnoreUserKnownHosts:
		intptr = &options->ignore_user_known_hosts;
 parse_flag:
		multistate_ptr = multistate_flag;
		गच्छ parse_multistate;

	पक्ष sHostbasedAuthentication:
		intptr = &options->hostbased_authentication;
		गच्छ parse_flag;

	पक्ष sHostbasedUsesNameFromPacketOnly:
		intptr = &options->hostbased_uses_name_from_packet_only;
		गच्छ parse_flag;

	पक्ष sHostbasedAcceptedAlgorithms:
		charptr = &options->hostbased_accepted_algos;
		ca_only = 0;
 parse_pubkey_algos:
		arg = argv_next(&ac, &av);
		सचे (!arg || *arg == '\0')
			fatal("%s line %d: Missing argument.",
			    filename, linenum);
		सचे (*arg != '-' &&
		    !sshkey_names_valid2(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg, 1, ca_only))
			fatal("%s line %d: Bad key types '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		सचे (*activep && *charptr == रिक्त)
			*charptr = xstrdup(arg);
		भङ्ग;

	पक्ष s_Host_कुञ्चिका_Algorithms:
		charptr = &options->hostkeyalgorithms;
		ca_only = 0;
		गच्छ parse_pubkey_algos;

	पक्ष sCASignatureAlgorithms:
		charptr = &options->ca_sign_algorithms;
		ca_only = 1;
		गच्छ parse_pubkey_algos;

	पक्ष sPubkeyAuthentication:
		intptr = &options->pubkey_authentication;
		ca_only = 0;
		गच्छ parse_flag;

	पक्ष sPubkeyAcceptedAlgorithms:
		charptr = &options->pubkey_accepted_algos;
		ca_only = 0;
		गच्छ parse_pubkey_algos;

	पक्ष sPubkeyAuthOptions:
		intptr = &options->pubkey_auth_options;
		मानम् = 0;
		value2 = -1;
		याव ((arg = argv_next(&ac, &av)) != रिक्त) {
			सचे (strcasecmp(arg, "none") == 0)
				अनुवर्त;
			सचे (strcasecmp(arg, "touch-required") == 0)
				मानम् |= PUBKEYAUTH_TOUCH_REQUIRED;
			अञ्ञथा सचे (strcasecmp(arg, "verify-required") == 0)
				मानम् |= PUBKEYAUTH_VERIFY_REQUIRED;
			अञ्ञथा सचे (strncasecmp(arg, "max-pk-ok:", 10) == 0) {
				value2 = strtonum(arg + 10, 0, 255, &errstr);
				सचे (errstr != रिक्त) {
					error("%s line %d: bad %s max-pk-ok "
					    "value: %s", filename, linenum,
					keyword, errstr);
					गच्छ out;
				}
			} अञ्ञथा {
				error("%s line %d: unsupported %s option %s",
				    filename, linenum, keyword, arg);
				गच्छ out;
			}
		}
		सचे (*activep && options->pubkey_auth_options == -1) {
			options->pubkey_auth_options = मानम्;
			options->max_pubkey_ok = value2;
		}
		भङ्ग;

#ifdef KRB5
	पक्ष sKerberosAuthentication:
		intptr = &options->kerberos_authentication;
		गच्छ parse_flag;

	पक्ष sKerberosOrLocalPasswd:
		intptr = &options->kerberos_or_local_passwd;
		गच्छ parse_flag;

	पक्ष sKerberosTicketCleanup:
		intptr = &options->kerberos_ticket_cleanup;
		गच्छ parse_flag;
#ifdef USE_AFS
	पक्ष sKerberosGetAFSToken:
		intptr = &options->kerberos_get_afs_token;
		गच्छ parse_flag;
#endif /* USE_AFS */
#endif /* KRB5 */

#ifdef GSSAPI
	पक्ष sGSSAPIAuthentication:
		intptr = &options->gss_authentication;
		गच्छ parse_flag;

	पक्ष sGSSAPICleanupCredentials:
		intptr = &options->gss_cleanup_creds;
		गच्छ parse_flag;

	पक्ष sGSSAPIDelegateCredentials:
		intptr = &options->gss_deleg_creds;
		गच्छ parse_flag;

	पक्ष sGSSAPIStrictAcceptorCheck:
		intptr = &options->gss_strict_acceptor;
		गच्छ parse_flag;
#endif /* GSSAPI */

	पक्ष sPasswordAuthentication:
		intptr = &options->password_authentication;
		गच्छ parse_flag;

	पक्ष sKbdInteractiveAuthentication:
		intptr = &options->kbd_interactive_authentication;
		गच्छ parse_flag;

	पक्ष sPrintMotd:
		intptr = &options->print_motd;
		गच्छ parse_flag;

#ifndef DISABLE_LASTLOG
	पक्ष sPrintLastLog:
		intptr = &options->print_lastlog;
		गच्छ parse_flag;
#endif

	पक्ष sX11Forwarding:
		intptr = &options->x11_forwarding;
		गच्छ parse_flag;

	पक्ष sX11DisplayOffset:
		intptr = &options->x11_display_offset;
 parse_int:
		arg = argv_next(&ac, &av);
		सचे ((errstr = atoi_err(arg, &मानम्)) != रिक्त)
			fatal("%s line %d: %s integer value %s.",
			    filename, linenum, keyword, errstr);
		सचे (*activep && *intptr == -1)
			*intptr = मानम्;
		भङ्ग;

	पक्ष sX11UseLocalhost:
		intptr = &options->x11_use_localhost;
		गच्छ parse_flag;

	पक्ष sXAuthLocation:
		charptr = &options->xauth_location;
		गच्छ parse_filename;

	पक्ष sPermitTTY:
		intptr = &options->permit_tty;
		गच्छ parse_flag;

	पक्ष sPermitUserRC:
		intptr = &options->permit_user_rc;
		गच्छ parse_flag;

	पक्ष sStrictModes:
		intptr = &options->strict_modes;
		गच्छ parse_flag;

	पक्ष sTCPKeepAlive:
		intptr = &options->tcp_keep_alive;
		multistate_ptr = multistate_keepalives;
		गच्छ parse_multistate;

	पक्ष sPermitEmptyPasswords:
		intptr = &options->permit_empty_passwd;
		गच्छ parse_flag;

	पक्ष sPermitUserEnvironment:
		intptr = &options->permit_user_env;
		charptr = &options->permit_user_env_allowlist;
		arg = argv_next(&ac, &av);
		सचे (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		मानम् = 0;
		p = रिक्त;
		सचे (strcmp(arg, "yes") == 0)
			मानम् = 1;
		अञ्ञथा सचे (strcmp(arg, "no") == 0)
			मानम् = 0;
		अञ्ञथा {
			/* Pattern-list specified */
			मानम् = 1;
			p = xstrdup(arg);
		}
		सचे (*activep && *intptr == -1) {
			*intptr = मानम्;
			*charptr = p;
			p = रिक्त;
		}
		मुक्त(p);
		भङ्ग;

	पक्ष sCompression:
		intptr = &options->compression;
		multistate_ptr = multistate_compression;
		गच्छ parse_multistate;

	पक्ष sRekeyLimit:
		arg = argv_next(&ac, &av);
		सचे (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		सचे (strcmp(arg, "default") == 0) {
			val64 = 0;
		} अञ्ञथा {
			सचे (scan_scaled(arg, &val64) == -1)
				fatal("%.200s line %d: Bad %s number '%s': %s",
				    filename, linenum, keyword,
				    arg, strerror(errno));
			सचे (val64 != 0 && val64 < 16)
				fatal("%.200s line %d: %s too small",
				    filename, linenum, keyword);
		}
		सचे (*activep && options->rekey_limit == -1)
			options->rekey_limit = val64;
		सचे (ac != 0) { /* optional rekey interval present */
			सचे (strcmp(av[0], "none") == 0) {
				(शून्य)argv_next(&ac, &av);	/* discard */
				भङ्ग;
			}
			intptr = &options->rekey_interval;
			गच्छ parse_time;
		}
		भङ्ग;

	पक्ष sGatewayPorts:
		intptr = &options->fwd_opts.gateway_ports;
		multistate_ptr = multistate_gatewayports;
		गच्छ parse_multistate;

	पक्ष sUseDNS:
		intptr = &options->use_dns;
		गच्छ parse_flag;

	पक्ष sSyslogFacility:
		log_facility_ptr = &options->log_facility;
		arg = argv_next(&ac, &av);
		मानम् = log_facility_सङ्ख्या(arg);
		सचे (मानम् == SYSLOG_FACILITY_NOT_SET)
			fatal("%.200s line %d: unsupported log facility '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
		सचे (*log_facility_ptr == -1)
			*log_facility_ptr = (SyslogFacility) मानम्;
		भङ्ग;

	पक्ष sLogLevel:
		log_level_ptr = &options->log_level;
		arg = argv_next(&ac, &av);
		मानम् = log_level_सङ्ख्या(arg);
		सचे (मानम् == SYSLOG_LEVEL_NOT_SET)
			fatal("%.200s line %d: unsupported log level '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
		सचे (*activep && *log_level_ptr == -1)
			*log_level_ptr = (LogLevel) मानम्;
		भङ्ग;

	पक्ष sLogVerbose:
		found = options->अङ्कः_log_verbose == 0;
		याव ((arg = argv_next(&ac, &av)) != रिक्त) {
			सचे (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				गच्छ out;
			}
			/* Allow "none" only in first position */
			सचे (strcasecmp(arg, "none") == 0) {
				सचे (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					गच्छ out;
				}
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		सचे (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		सचे (found && *activep) {
			options->log_verbose = strs;
			options->अङ्कः_log_verbose = nstrs;
			strs = रिक्त; /* transferred */
			nstrs = 0;
		}
		भङ्ग;

	पक्ष sAllowTcpForwarding:
		intptr = &options->allow_tcp_forwarding;
		multistate_ptr = multistate_tcpfwd;
		गच्छ parse_multistate;

	पक्ष sAllowStreamLocalForwarding:
		intptr = &options->allow_streamlocal_forwarding;
		multistate_ptr = multistate_tcpfwd;
		गच्छ parse_multistate;

	पक्ष sAllowAgentForwarding:
		intptr = &options->allow_agent_forwarding;
		गच्छ parse_flag;

	पक्ष sAgentSocketPath:
		charptr = &options->agent_socket_path;
		arg = argv_next(&ac, &av);
		सचे (!arg || *arg == '\0')
			fatal("%s line %d: missing path.", filename, linenum);
		सचे (strncmp(arg, "shared:", 7) == 0) {
			/* Shared paths must be absolute */
			सचे (arg[7] != '/') {
				fatal("%s line %d: invalid shared path.",
				    filename, linenum);
			}
		} अञ्ञथा सचे (strncmp(arg, "user:", 5) == 0) {
			/* User paths must not be empty */
			सचे (arg[5] == '\0') {
				fatal("%s line %d: invalid user path.",
				    filename, linenum);
			}
		} अञ्ञथा सचे (strcmp(arg, "none") != 0)
			fatal("%s line %d: invalid path.", filename, linenum);
		सचे (*activep && *charptr == रिक्त)
			*charptr = xstrdup(arg);
		भङ्ग;

	पक्ष sDisableForwarding:
		intptr = &options->disable_forwarding;
		गच्छ parse_flag;

	पक्ष sAllowUsers:
		chararrayptr = &options->allow_users;
		uintptr = &options->अङ्कः_allow_users;
 parse_allowdenyusers:
		/* XXX appends to list; doesn't respect first-match-wins */
		याव ((arg = argv_next(&ac, &av)) != रिक्त) {
			सचे (*arg == '\0' ||
			    match_user(रिक्त, रिक्त, रिक्त, arg) == -1)
				fatal("%s line %d: invalid %s pattern: \"%s\"",
				    filename, linenum, keyword, arg);
			found = 1;
			सचे (!*activep)
				अनुवर्त;
			opt_array_append(filename, linenum, keyword,
			    chararrayptr, uintptr, arg);
		}
		सचे (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		भङ्ग;

	पक्ष sDenyUsers:
		chararrayptr = &options->deny_users;
		uintptr = &options->अङ्कः_deny_users;
		गच्छ parse_allowdenyusers;

	पक्ष sAllowGroups:
		chararrayptr = &options->allow_groups;
		uintptr = &options->अङ्कः_allow_groups;
		/* XXX appends to list; doesn't respect first-match-wins */
 parse_allowdenygroups:
		याव ((arg = argv_next(&ac, &av)) != रिक्त) {
			सचे (*arg == '\0')
				fatal("%s line %d: empty %s pattern",
				    filename, linenum, keyword);
			found = 1;
			सचे (!*activep)
				अनुवर्त;
			opt_array_append(filename, linenum, keyword,
			    chararrayptr, uintptr, arg);
		}
		सचे (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		भङ्ग;

	पक्ष sDenyGroups:
		chararrayptr = &options->deny_groups;
		uintptr = &options->अङ्कः_deny_groups;
		गच्छ parse_allowdenygroups;

	पक्ष sCiphers:
		arg = argv_next(&ac, &av);
		सचे (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		सचे (*arg != '-' &&
		    !ciphers_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 cipher spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		सचे (options->ciphers == रिक्त)
			options->ciphers = xstrdup(arg);
		भङ्ग;

	पक्ष sMacs:
		arg = argv_next(&ac, &av);
		सचे (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		सचे (*arg != '-' &&
		    !mac_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 mac spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		सचे (options->macs == रिक्त)
			options->macs = xstrdup(arg);
		भङ्ग;

	पक्ष sKexAlgorithms:
		arg = argv_next(&ac, &av);
		सचे (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		सचे (*arg != '-' &&
		    !kex_names_valid(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 KexAlgorithms '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		सचे (options->kex_algorithms == रिक्त)
			options->kex_algorithms = xstrdup(arg);
		भङ्ग;

	पक्ष sSubsystem:
		सचे ((arg = argv_next(&ac, &av)) == रिक्त || *arg == '\0' ||
		   ((arg2 = argv_next(&ac, &av)) == रिक्त || *arg2 == '\0'))
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		सचे (!*activep) {
			argv_consume(&ac);
			भङ्ग;
		}
		found = 0;
		अत्थाय (i = 0; i < options->अङ्कः_subsystems; i++) {
			सचे (strcmp(arg, options->subsystem_name[i]) == 0) {
				found = 1;
				भङ्ग;
			}
		}
		सचे (found) {
			debug("%s line %d: Subsystem '%s' already defined.",
			    filename, linenum, arg);
			argv_consume(&ac);
			भङ्ग;
		}
		options->subsystem_name = xrecallocarray(
		    options->subsystem_name, options->अङ्कः_subsystems,
		    options->अङ्कः_subsystems + 1,
		    परिमाण(*options->subsystem_name));
		options->subsystem_command = xrecallocarray(
		    options->subsystem_command, options->अङ्कः_subsystems,
		    options->अङ्कः_subsystems + 1,
		    परिमाण(*options->subsystem_command));
		options->subsystem_args = xrecallocarray(
		    options->subsystem_args, options->अङ्कः_subsystems,
		    options->अङ्कः_subsystems + 1,
		    परिमाण(*options->subsystem_args));
		options->subsystem_name[options->अङ्कः_subsystems] = xstrdup(arg);
		options->subsystem_command[options->अङ्कः_subsystems] =
		    xstrdup(arg2);
		/* Collect arguments (separate to executable) */
		arg = argv_assemble(1, &arg2); /* quote command correctly */
		arg2 = argv_assemble(ac, av); /* rest of command */
		xasprintf(&options->subsystem_args[options->अङ्कः_subsystems],
		    "%s%s%s", arg, *arg2 == '\0' ? "" : " ", arg2);
		मुक्त(arg2);
		मुक्त(arg);
		argv_consume(&ac);
		options->अङ्कः_subsystems++;
		भङ्ग;

	पक्ष sMaxStartups:
		arg = argv_next(&ac, &av);
		सचे (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		/* begin:rate:max */
		सचे ((n = sscanf(arg, "%d:%d:%d",
		    &मानम्, &value2, &value3)) == 3) {
			सचे (मानम् > value3 || value2 > 100 || value2 < 1)
				fatal("%s line %d: Invalid %s spec.",
				    filename, linenum, keyword);
		} अञ्ञथा सचे (n == 1) {
			value3 = मानम्;
			value2 = -1;
		} अञ्ञथा {
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		}
		सचे (मानम् <= 0 || value3 <= 0)
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		सचे (*activep && options->max_startups == -1) {
			options->max_startups_begin = मानम्;
			options->max_startups_rate = value2;
			options->max_startups = value3;
		}
		भङ्ग;

	पक्ष sPerSourceNetBlockSize:
		arg = argv_next(&ac, &av);
		सचे (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		विकल्प (n = sscanf(arg, "%d:%d", &मानम्, &value2)) {
		पक्ष 2:
			सचे (value2 < 0 || value2 > 128)
				n = -1;
			/* FALLTHROUGH */
		पक्ष 1:
			सचे (मानम् < 0 || मानम् > 32)
				n = -1;
		}
		सचे (n != 1 && n != 2)
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		सचे (*activep && options->per_source_masklen_ipv4 == -1) {
			options->per_source_masklen_ipv4 = मानम्;
			सचे (n == 2)
				options->per_source_masklen_ipv6 = value2;
		}
		भङ्ग;

	पक्ष sPerSourceMaxStartups:
		arg = argv_next(&ac, &av);
		सचे (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		सचे (strcmp(arg, "none") == 0) { /* no limit */
			मानम् = INT_MAX;
		} अञ्ञथा {
			सचे ((errstr = atoi_err(arg, &मानम्)) != रिक्त)
				fatal("%s line %d: %s integer value %s.",
				    filename, linenum, keyword, errstr);
		}
		सचे (*activep && options->per_source_max_startups == -1)
			options->per_source_max_startups = मानम्;
		भङ्ग;

	पक्ष sPerSourcePenaltyExemptList:
		charptr = &options->per_source_penalty_exempt;
		arg = argv_next(&ac, &av);
		सचे (!arg || *arg == '\0')
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		सचे (addr_match_list(रिक्त, arg) != 0) {
			fatal("%s line %d: keyword %s "
			    "invalid address argument.",
			    filename, linenum, keyword);
		}
		सचे (*activep && *charptr == रिक्त)
			*charptr = xstrdup(arg);
		भङ्ग;

	पक्ष sPerSourcePenalties:
		याव ((arg = argv_next(&ac, &av)) != रिक्त) {
			ध्रुव वर्ण *q = रिक्त;

			found = 1;
			intptr = रिक्त;
			doubleptr = रिक्त;
			मानम् = -1;
			value2 = 0;
			/* Allow no/yes only in first position */
			सचे (strcasecmp(arg, "no") == 0 ||
			    (value2 = (strcasecmp(arg, "yes") == 0))) {
				सचे (ac > 0) {
					fatal("%s line %d: keyword %s \"%s\" "
					    "argument must appear alone.",
					    filename, linenum, keyword, arg);
				}
				सचे (*activep &&
				    options->per_source_penalty.enabled == -1)
					options->per_source_penalty.enabled = value2;
				अनुवर्त;
			} अञ्ञथा सचे ((q = strprefix(arg, "crash:", 0)) != रिक्त) {
				doubleptr = &options->per_source_penalty.penalty_crash;
			} अञ्ञथा सचे ((q = strprefix(arg, "authfail:", 0)) != रिक्त) {
				doubleptr = &options->per_source_penalty.penalty_authfail;
			} अञ्ञथा सचे ((q = strprefix(arg, "invaliduser:", 0)) != रिक्त) {
				doubleptr = &options->per_source_penalty.penalty_invaliduser;
			} अञ्ञथा सचे ((q = strprefix(arg, "noauth:", 0)) != रिक्त) {
				doubleptr = &options->per_source_penalty.penalty_noauth;
			} अञ्ञथा सचे ((q = strprefix(arg, "grace-exceeded:", 0)) != रिक्त) {
				doubleptr = &options->per_source_penalty.penalty_grace;
			} अञ्ञथा सचे ((q = strprefix(arg, "refuseconnection:", 0)) != रिक्त) {
				doubleptr = &options->per_source_penalty.penalty_refuseconnection;
			} अञ्ञथा सचे ((q = strprefix(arg, "max:", 0)) != रिक्त) {
				doubleptr = &options->per_source_penalty.penalty_max;
			} अञ्ञथा सचे ((q = strprefix(arg, "min:", 0)) != रिक्त) {
				doubleptr = &options->per_source_penalty.penalty_min;
			} अञ्ञथा सचे ((q = strprefix(arg, "max-sources4:", 0)) != रिक्त) {
				intptr = &options->per_source_penalty.max_sources4;
				सचे ((errstr = atoi_err(q, &मानम्)) != रिक्त)
					fatal("%s line %d: %s value %s.",
					    filename, linenum, keyword, errstr);
			} अञ्ञथा सचे ((q = strprefix(arg, "max-sources6:", 0)) != रिक्त) {
				intptr = &options->per_source_penalty.max_sources6;
				सचे ((errstr = atoi_err(q, &मानम्)) != रिक्त)
					fatal("%s line %d: %s value %s.",
					    filename, linenum, keyword, errstr);
			} अञ्ञथा सचे (strcmp(arg, "overflow:deny-all") == 0) {
				intptr = &options->per_source_penalty.overflow_mode;
				मानम् = PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL;
			} अञ्ञथा सचे (strcmp(arg, "overflow:permissive") == 0) {
				intptr = &options->per_source_penalty.overflow_mode;
				मानम् = PER_SOURCE_PENALTY_OVERFLOW_PERMISSIVE;
			} अञ्ञथा सचे (strcmp(arg, "overflow6:deny-all") == 0) {
				intptr = &options->per_source_penalty.overflow_mode6;
				मानम् = PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL;
			} अञ्ञथा सचे (strcmp(arg, "overflow6:permissive") == 0) {
				intptr = &options->per_source_penalty.overflow_mode6;
				मानम् = PER_SOURCE_PENALTY_OVERFLOW_PERMISSIVE;
			} अञ्ञथा {
				fatal("%s line %d: unsupported %s keyword %s",
				    filename, linenum, keyword, arg);
			}

			सचे (doubleptr != रिक्त) {
				सचे ((dvalue = convtime_double(q)) < 0) {
					fatal("%s line %d: invalid %s time value.",
					    filename, linenum, keyword);
				}
				सचे (*activep && *doubleptr < 0.0) {
					*doubleptr = dvalue;
					options->per_source_penalty.enabled = 1;
				}
			} अञ्ञथा सचे (intptr != रिक्त) {
				सचे (*activep && *intptr == -1) {
					*intptr = मानम्;
					options->per_source_penalty.enabled = 1;
				}
			} अञ्ञथा {
				fatal_f("%s line %d: internal error",
				    filename, linenum);
			}
		}
		सचे (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		भङ्ग;

	पक्ष sMaxAuthTries:
		intptr = &options->max_authtries;
		गच्छ parse_int;

	पक्ष sMaxSessions:
		intptr = &options->max_sessions;
		गच्छ parse_int;

	पक्ष sBanner:
		charptr = &options->banner;
		गच्छ parse_filename;

	/*
	 * These options can contain %X options expanded at
	 * connect time, so that you can specify paths like:
	 *
	 * AuthorizedKeysFile	/etc/ssh_keys/%u
	 */
	पक्ष s_Authorized_कुञ्चिकाः_File:
		uintptr = &options->अङ्कः_authkeys_files;
		chararrayptr = &options->authorized_कुञ्चिकाः_files;
 parse_filenames:
		found = *uintptr == 0;
		याव ((arg = argv_next(&ac, &av)) != रिक्त) {
			सचे (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				गच्छ out;
			}
			/* Allow "none" only in first position */
			सचे (strcasecmp(arg, "none") == 0) {
				सचे (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					गच्छ out;
				}
			}
			arg2 = tilde_expand_filename(arg, getuid());
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg2);
			मुक्त(arg2);
		}
		सचे (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		सचे (found && *activep) {
			*chararrayptr = strs;
			*uintptr = nstrs;
			strs = रिक्त; /* transferred */
			nstrs = 0;
		}
		भङ्ग;

	पक्ष sAuthorizedPrincipalsFile:
		charptr = &options->authorized_principals_file;
		arg = argv_next(&ac, &av);
		सचे (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		सचे (*activep && *charptr == रिक्त) {
			*charptr = tilde_expand_filename(arg, getuid());
			/* increase optional counter */
			सचे (intptr != रिक्त)
				*intptr = *intptr + 1;
		}
		भङ्ग;

	पक्ष sClientAliveInterval:
		intptr = &options->client_alive_interval;
		गच्छ parse_time;

	पक्ष s_Client_Alive_गणनम्_Max:
		intptr = &options->client_alive_गणनम्_max;
		गच्छ parse_int;

	पक्ष sAcceptEnv:
		/* XXX appends to list; doesn't respect first-match-wins */
		याव ((arg = argv_next(&ac, &av)) != रिक्त) {
			सचे (*arg == '\0' || strchr(arg, '=') != रिक्त)
				fatal("%s line %d: Invalid environment name.",
				    filename, linenum);
			found = 1;
			सचे (!*activep)
				अनुवर्त;
			opt_array_append(filename, linenum, keyword,
			    &options->accept_env, &options->अङ्कः_accept_env,
			    arg);
		}
		सचे (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		भङ्ग;

	पक्ष sSetEnv:
		found = options->अङ्कः_setenv == 0;
		याव ((arg = argv_next(&ac, &av)) != रिक्त) {
			सचे (*arg == '\0' || strchr(arg, '=') == रिक्त)
				fatal("%s line %d: Invalid environment.",
				    filename, linenum);
			सचे (lookup_setenv_in_list(arg, strs, nstrs) != रिक्त) {
				debug2("%s line %d: ignoring duplicate env "
				    "name \"%.64s\"", filename, linenum, arg);
				अनुवर्त;
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		सचे (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		सचे (found && *activep) {
			options->setenv = strs;
			options->अङ्कः_setenv = nstrs;
			strs = रिक्त; /* transferred */
			nstrs = 0;
		}
		भङ्ग;

	पक्ष sPermitTunnel:
		intptr = &options->permit_tun;
		arg = argv_next(&ac, &av);
		सचे (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		मानम् = -1;
		अत्थाय (i = 0; tunmode_desc[i].val != -1; i++)
			सचे (strcmp(tunmode_desc[i].text, arg) == 0) {
				मानम् = tunmode_desc[i].val;
				भङ्ग;
			}
		सचे (मानम् == -1)
			fatal("%s line %d: bad %s argument %s",
			    filename, linenum, keyword, arg);
		सचे (*activep && *intptr == -1)
			*intptr = मानम्;
		भङ्ग;

	पक्ष sInclude:
		सचे (cmdline) {
			fatal("Include directive not supported as a "
			    "command-line option");
		}
		मानम् = 0;
		याव ((arg2 = argv_next(&ac, &av)) != रिक्त) {
			सचे (*arg2 == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				गच्छ out;
			}
			मानम्++;
			found = 0;
			सचे (*arg2 != '/' && *arg2 != '~') {
				xasprintf(&arg, "%s/%s", SSHDIR, arg2);
			} अञ्ञथा
				arg = xstrdup(arg2);

			/*
			 * Don't let included files clobber the containing
			 * file's Match state.
			 */
			oactive = *activep;

			/* consult cache of include files */
			TAILQ_FOREACH(item, includes, entry) {
				सचे (strcmp(item->selector, arg) != 0)
					अनुवर्त;
				सचे (item->filename != रिक्त) {
					parse_server_config_depth(options,
					    item->filename, item->contents,
					    includes, connectinfo,
					    (*inc_flags & SSHCFG_MATCH_ONLY
					        ? SSHCFG_MATCH_ONLY : (oactive
					            ? 0 : SSHCFG_NEVERMATCH)),
					    activep, depth + 1);
				}
				found = 1;
				*activep = oactive;
			}
			सचे (found != 0) {
				मुक्त(arg);
				अनुवर्त;
			}

			/* requested glob was not in cache */
			debug2("%s line %d: new include %s",
			    filename, linenum, arg);
			सचे ((r = glob(arg, 0, रिक्त, &gbuf)) != 0) {
				सचे (r != GLOB_NOMATCH) {
					fatal("%s line %d: include \"%s\" glob "
					    "failed", filename, linenum, arg);
				}
				/*
				 * If no entry matched then record a
				 * placeholder to skip later glob calls.
				 */
				debug2("%s line %d: no match for %s",
				    filename, linenum, arg);
				item = xcalloc(1, परिमाण(*item));
				item->selector = xstrdup(arg);
				TAILQ_INSERT_TAIL(includes,
				    item, entry);
			}
			सचे (gbuf.gl_pathc > INT_MAX)
				fatal_f("too many glob results");
			अत्थाय (n = 0; n < (पूर्णाङ्क)gbuf.gl_pathc; n++) {
				debug2("%s line %d: including %s",
				    filename, linenum, gbuf.gl_pathv[n]);
				item = xcalloc(1, परिमाण(*item));
				item->selector = xstrdup(arg);
				item->filename = xstrdup(gbuf.gl_pathv[n]);
				सचे ((item->contents = sshbuf_new()) == रिक्त)
					fatal_f("sshbuf_new failed");
				load_server_config(item->filename,
				    item->contents);
				parse_server_config_depth(options,
				    item->filename, item->contents,
				    includes, connectinfo,
				    (*inc_flags & SSHCFG_MATCH_ONLY
				        ? SSHCFG_MATCH_ONLY : (oactive
				            ? 0 : SSHCFG_NEVERMATCH)),
				    activep, depth + 1);
				*activep = oactive;
				TAILQ_INSERT_TAIL(includes, item, entry);
			}
			globfree(&gbuf);
			मुक्त(arg);
		}
		सचे (मानम् == 0) {
			fatal("%s line %d: %s missing filename argument",
			    filename, linenum, keyword);
		}
		भङ्ग;

	पक्ष sMatch:
		सचे (cmdline)
			fatal("Match directive not supported as a command-line "
			    "option");
		मानम् = match_cfg_पङ्क्तिः(str, &ac, &av, linenum,
		    (*inc_flags & SSHCFG_NEVERMATCH ? रिक्त : connectinfo));
		सचे (मानम् < 0)
			fatal("%s line %d: Bad Match condition", filename,
			    linenum);
		*activep = (*inc_flags & SSHCFG_NEVERMATCH) ? 0 : मानम्;
		/*
		 * The MATCH_ONLY flag is applicable only until the first
		 * match block.
		 */
		*inc_flags &= ~SSHCFG_MATCH_ONLY;
		भङ्ग;

	पक्ष sPermitListen:
	पक्ष sPermitOpen:
		सचे (opcode == sPermitListen) {
			uintptr = &options->अङ्कः_permitted_listens;
			chararrayptr = &options->permitted_listens;
		} अञ्ञथा {
			uintptr = &options->अङ्कः_permitted_opens;
			chararrayptr = &options->permitted_opens;
		}
		found = *uintptr == 0;
		याव ((arg = argv_next(&ac, &av)) != रिक्त) {
			सचे (strcmp(arg, "any") == 0 ||
			    strcmp(arg, "none") == 0) {
				सचे (nstrs != 0) {
					fatal("%s line %d: %s must appear "
					    "alone on a %s line.",
					    filename, linenum, arg, keyword);
				}
				opt_array_append(filename, linenum, keyword,
				    &strs, &nstrs, arg);
				अनुवर्त;
			}

			सचे (opcode == sPermitListen &&
			    strchr(arg, ':') == रिक्त) {
				/*
				 * Allow bare port number for PermitListen
				 * to indicate a wildcard listen host.
				 */
				xasprintf(&arg2, "*:%s", arg);
			} अञ्ञथा {
				arg2 = xstrdup(arg);
				p = hpdelim(&arg);
				सचे (p == रिक्त) {
					fatal("%s line %d: %s missing host",
					    filename, linenum, keyword);
				}
				p = cleanhostname(p);
			}
			सचे (arg == रिक्त ||
			    ((port = permitopen_port(arg)) < 0)) {
				fatal("%s line %d: %s bad port number",
				    filename, linenum, keyword);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg2);
			मुक्त(arg2);
		}
		सचे (nstrs == 0) {
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		}
		सचे (found && *activep) {
			*chararrayptr = strs;
			*uintptr = nstrs;
			strs = रिक्त; /* transferred */
			nstrs = 0;
		}
		भङ्ग;

	पक्ष sForceCommand:
		सचे (str == रिक्त || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		सचे (*activep && options->adm_forced_command == रिक्त)
			options->adm_forced_command = xstrdup(str + len);
		argv_consume(&ac);
		भङ्ग;

	पक्ष sChrootDirectory:
		charptr = &options->chroot_directory;

		arg = argv_next(&ac, &av);
		सचे (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		सचे (*activep && *charptr == रिक्त)
			*charptr = xstrdup(arg);
		भङ्ग;

	पक्ष sTrustedUserCAKeys:
		charptr = &options->trusted_user_ca_कुञ्चिकाः;
		गच्छ parse_filename;

	पक्ष s_Revoked_कुञ्चिकाः:
		uintptr = &options->अङ्कः_revoked_कुञ्चिकाः_files;
		chararrayptr = &options->revoked_कुञ्चिकाः_files;
		गच्छ parse_filenames;

	पक्ष s_Security_कुञ्चिका_Provider:
		charptr = &options->sk_provider;
		arg = argv_next(&ac, &av);
		सचे (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		सचे (*activep && *charptr == रिक्त) {
			*charptr = strcasecmp(arg, "internal") == 0 ?
			    xstrdup(arg) : derelativise_path(arg);
			/* increase optional counter */
			सचे (intptr != रिक्त)
				*intptr = *intptr + 1;
		}
		भङ्ग;

	पक्ष sIPQoS:
		arg = argv_next(&ac, &av);
		सचे (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		सचे ((मानम् = parse_ipqos(arg)) == -1)
			fatal("%s line %d: Bad %s value: %s",
			    filename, linenum, keyword, arg);
		सचे (मानम् == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			मानम् = INT_MAX;
		}
		arg = argv_next(&ac, &av);
		सचे (arg == रिक्त)
			value2 = मानम्;
		अञ्ञथा सचे ((value2 = parse_ipqos(arg)) == -1)
			fatal("%s line %d: Bad %s value: %s",
			    filename, linenum, keyword, arg);
		सचे (value2 == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			value2 = INT_MAX;
		}
		सचे (*activep && options->ip_qos_interactive == -1) {
			options->ip_qos_interactive = मानम्;
			options->ip_qos_bulk = value2;
		}
		भङ्ग;

	पक्ष sVersionAddendum:
		सचे (str == रिक्त || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		सचे (strchr(str + len, '\r') != रिक्त) {
			fatal("%.200s line %d: Invalid %s argument",
			    filename, linenum, keyword);
		}
		सचे ((arg = strchr(पङ्क्तिः, '#')) != रिक्त) {
			*arg = '\0';
			rtrim(पङ्क्तिः);
		}
		सचे (*activep && options->version_addendum == रिक्त) {
			सचे (strcasecmp(str + len, "none") == 0)
				options->version_addendum = xstrdup("");
			अञ्ञथा
				options->version_addendum = xstrdup(str + len);
		}
		argv_consume(&ac);
		भङ्ग;

	पक्ष s_Authorized_कुञ्चिकाः_Command:
		charptr = &options->authorized_कुञ्चिकाः_command;
 parse_command:
		len = strspn(str, WHITESPACE);
		सचे (str[len] != '/' && strcasecmp(str + len, "none") != 0) {
			fatal("%.200s line %d: %s must be an absolute path",
			    filename, linenum, keyword);
		}
		सचे (*activep && *charptr == रिक्त)
			*charptr = xstrdup(str + len);
		argv_consume(&ac);
		भङ्ग;

	पक्ष s_Authorized_कुञ्चिकाः_Command_User:
		charptr = &options->authorized_कुञ्चिकाः_command_user;
 parse_localuser:
		arg = argv_next(&ac, &av);
		सचे (!arg || *arg == '\0') {
			fatal("%s line %d: missing %s argument.",
			    filename, linenum, keyword);
		}
		सचे (*activep && *charptr == रिक्त)
			*charptr = xstrdup(arg);
		भङ्ग;

	पक्ष sAuthorizedPrincipalsCommand:
		charptr = &options->authorized_principals_command;
		गच्छ parse_command;

	पक्ष sAuthorizedPrincipalsCommandUser:
		charptr = &options->authorized_principals_command_user;
		गच्छ parse_localuser;

	पक्ष sAuthenticationMethods:
		found = options->अङ्कः_auth_methods == 0;
		मानम् = 0; /* seen "any" pseudo-method */
		याव ((arg = argv_next(&ac, &av)) != रिक्त) {
			सचे (strcmp(arg, "any") == 0) {
				सचे (nstrs > 0) {
					fatal("%s line %d: \"any\" must "
					    "appear alone in %s",
					    filename, linenum, keyword);
				}
				मानम् = 1;
			} अञ्ञथा सचे (मानम्) {
				fatal("%s line %d: \"any\" must appear "
				    "alone in %s", filename, linenum, keyword);
			} अञ्ञथा सचे (auth2_methods_valid(arg, 0) != 0) {
				fatal("%s line %d: invalid %s method list.",
				    filename, linenum, keyword);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		सचे (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		सचे (found && *activep) {
			options->auth_methods = strs;
			options->अङ्कः_auth_methods = nstrs;
			strs = रिक्त; /* transferred */
			nstrs = 0;
		}
		भङ्ग;

	पक्ष sStreamLocalBindMask:
		arg = argv_next(&ac, &av);
		सचे (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		/* Parse mode in octal format */
		मानम् = strtol(arg, &p, 8);
		सचे (arg == p || मानम् < 0 || मानम् > 0777)
			fatal("%s line %d: Invalid %s.",
			    filename, linenum, keyword);
		सचे (*activep &&
		    options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
			options->fwd_opts.streamlocal_bind_mask = (mode_t)मानम्;
		भङ्ग;

	पक्ष sStreamLocalBindUnlink:
		intptr = &options->fwd_opts.streamlocal_bind_unlink;
		गच्छ parse_flag;

	पक्ष sFingerprintHash:
		arg = argv_next(&ac, &av);
		सचे (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		सचे ((मानम् = ssh_digest_alg_by_name(arg)) == -1)
			fatal("%.200s line %d: Invalid %s algorithm \"%s\".",
			    filename, linenum, keyword, arg);
		सचे (*activep)
			options->fingerprint_hash = मानम्;
		भङ्ग;

	पक्ष sExposeAuthInfo:
		intptr = &options->expose_userauth_info;
		गच्छ parse_flag;

	पक्ष sRDomain:
#सचे !defined(__OpenBSD__) && !defined(HAVE_SYS_SET_PROCESS_RDOMAIN)
		fatal("%s line %d: setting RDomain not supported on this "
		    "platform.", filename, linenum);
#endif
		charptr = &options->routing_domain;
		arg = argv_next(&ac, &av);
		सचे (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		सचे (strcasecmp(arg, "none") != 0 && strcmp(arg, "%D") != 0 &&
		    !valid_rdomain(arg))
			fatal("%s line %d: invalid routing domain",
			    filename, linenum);
		सचे (*activep && *charptr == रिक्त)
			*charptr = xstrdup(arg);
		भङ्ग;

	पक्ष sRequiredRSASize:
		intptr = &options->required_rsa_size;
		गच्छ parse_int;

	पक्ष sChannelTimeout:
		found = options->अङ्कः_channel_timeouts == 0;
		याव ((arg = argv_next(&ac, &av)) != रिक्त) {
			/* Allow "none" only in first position */
			सचे (strcasecmp(arg, "none") == 0) {
				सचे (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					गच्छ out;
				}
			} अञ्ञथा सचे (parse_pattern_interval(arg,
			    रिक्त, रिक्त) != 0) {
				fatal("%s line %d: invalid channel timeout %s",
				    filename, linenum, arg);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		सचे (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		सचे (found && *activep) {
			options->channel_timeouts = strs;
			options->अङ्कः_channel_timeouts = nstrs;
			strs = रिक्त; /* transferred */
			nstrs = 0;
		}
		भङ्ग;

	पक्ष sUnusedConnectionTimeout:
		intptr = &options->unused_connection_timeout;
		/* peek at first arg for "none" so we can reuse parse_time */
		सचे (av[0] != रिक्त && strcasecmp(av[0], "none") == 0) {
			(शून्य)argv_next(&ac, &av); /* consume arg */
			सचे (*activep)
				*intptr = 0;
			भङ्ग;
		}
		गच्छ parse_time;

	पक्ष sSshdSessionPath:
		charptr = &options->sshd_session_path;
		गच्छ parse_filename;

	पक्ष sSshdAuthPath:
		charptr = &options->sshd_auth_path;
		गच्छ parse_filename;

	पक्ष sRefuseConnection:
		intptr = &options->refuse_connection;
		multistate_ptr = multistate_flag;
		गच्छ parse_multistate;

	पक्ष sWarnWeakCrypto:
		intptr = &options->warn_weak_crypto;
		multistate_ptr = multistate_warnweakcrypto;
		गच्छ parse_multistate;

	पक्ष sDeprecated:
	पक्ष sIgnore:
	पक्ष sUnsupported:
		do_log2(opcode == sIgnore ?
		    SYSLOG_LEVEL_DEBUG2 : SYSLOG_LEVEL_INFO,
		    "%s line %d: %s option %s", filename, linenum,
		    opcode == sUnsupported ? "Unsupported" : "Deprecated",
		    keyword);
		argv_consume(&ac);
		भङ्ग;

	स्वभाव:
		fatal("%s line %d: Missing handler for opcode %s (%d)",
		    filename, linenum, keyword, opcode);
	}
	/* Check that there is no garbage at end of line. */
	सचे (ac > 0) {
		error("%.200s line %d: keyword %s extra arguments "
		    "at end of line", filename, linenum, keyword);
		गच्छ out;
	}

	/* success */
	ret = 0;
 out:
	opt_array_free2(strs, रिक्त, nstrs);
	argv_free(oav, oac);
	पटिनिवत्त ret;
}

पूर्णाङ्क
process_server_config_पङ्क्तिः(ServerOptions *options, वर्ण *पङ्क्तिः,
    ध्रुव वर्ण *filename, पूर्णाङ्क linenum, पूर्णाङ्क *activep,
    संरचना connection_info *connectinfo, संरचना include_list *includes)
{
	पूर्णाङ्क inc_flags = 0;

	पटिनिवत्त process_server_config_पङ्क्तिः_depth(options, पङ्क्तिः, filename,
	    linenum, activep, connectinfo, &inc_flags, 0, includes);
}


/* Reads the server configuration file. */

शून्य
load_server_config(ध्रुव वर्ण *filename, संरचना sshbuf *conf)
{
	संरचना stat st;
	वर्ण *पङ्क्तिः = रिक्त, *cp;
	size_t linesize = 0;
	FILE *f;
	पूर्णाङ्क r;

	debug2_f("filename %s", filename);
	सचे ((f = fopen(filename, "r")) == रिक्त) {
		perror(filename);
		exit(1);
	}
	sshbuf_reset(conf);
	/* grow buffer, so realloc is avoided for large config files */
	सचे (fstat(fileno(f), &st) == 0 && st.st_size > 0 &&
	    (r = sshbuf_allocate(conf, st.st_size)) != 0)
		fatal_fr(r, "allocate");
	याव (getline(&पङ्क्तिः, &linesize, f) != -1) {
		/*
		 * Strip whitespace
		 * NB - preserve newlines, they are needed to reproduce
		 * line numbers later for error messages
		 */
		cp = पङ्क्तिः + strspn(पङ्क्तिः, " \t\r");
		सचे ((r = sshbuf_put(conf, cp, strlen(cp))) != 0)
			fatal_fr(r, "sshbuf_put");
	}
	मुक्त(पङ्क्तिः);
	सचे ((r = sshbuf_put_u8(conf, 0)) != 0)
		fatal_fr(r, "sshbuf_put_u8");
	fclose(f);
	debug2_f("done config len = %zu", sshbuf_len(conf));
}

शून्य
parse_server_match_config(ServerOptions *options,
   संरचना include_list *includes, संरचना connection_info *connectinfo)
{
	ServerOptions mo;

	initialize_server_options(&mo);
	parse_server_config(&mo, "reprocess config", cfg, includes,
	    connectinfo, 0);
	copy_set_server_options(options, &mo, 0);
	free_server_options(&mo);
}

पूर्णाङ्क
parse_server_match_testspec(संरचना connection_info *ci, वर्ण *spec)
{
	वर्ण *p;
	ध्रुव वर्ण *val;

	याव ((p = strsep(&spec, ",")) && *p != '\0') {
		सचे ((val = strprefix(p, "addr=", 0)) != रिक्त) {
			ci->address = xstrdup(val);
		} अञ्ञथा सचे ((val = strprefix(p, "host=", 0)) != रिक्त) {
			ci->host = xstrdup(val);
		} अञ्ञथा सचे ((val = strprefix(p, "user=", 0)) != रिक्त) {
			ci->user = xstrdup(val);
		} अञ्ञथा सचे ((val = strprefix(p, "laddr=", 0)) != रिक्त) {
			ci->laddress = xstrdup(val);
		} अञ्ञथा सचे ((val = strprefix(p, "rdomain=", 0)) != रिक्त) {
			ci->rdomain = xstrdup(val);
		} अञ्ञथा सचे ((val = strprefix(p, "lport=", 0)) != रिक्त) {
			ci->lport = a2port(val);
			सचे (ci->lport == -1) {
				fprintf(stderr, "Invalid port '%s' in test mode"
				    " specification %s\n", p+6, p);
				पटिनिवत्त -1;
			}
		} अञ्ञथा सचे (strcmp(p, "invalid-user") == 0) {
			ci->user_invalid = 1;
		} अञ्ञथा {
			fprintf(stderr, "Invalid test mode specification %s\n",
			    p);
			पटिनिवत्त -1;
		}
	}
	पटिनिवत्त 0;
}

शून्य
servconf_merge_subsystems(ServerOptions *dst, ServerOptions *src)
{
	u_int i, j, found;

	अत्थाय (i = 0; i < src->अङ्कः_subsystems; i++) {
		found = 0;
		अत्थाय (j = 0; j < dst->अङ्कः_subsystems; j++) {
			सचे (strcmp(src->subsystem_name[i],
			    dst->subsystem_name[j]) == 0) {
				found = 1;
				भङ्ग;
			}
		}
		सचे (found) {
			debug_f("override \"%s\"", dst->subsystem_name[j]);
			मुक्त(dst->subsystem_command[j]);
			मुक्त(dst->subsystem_args[j]);
			dst->subsystem_command[j] =
			    xstrdup(src->subsystem_command[i]);
			dst->subsystem_args[j] =
			    xstrdup(src->subsystem_args[i]);
			अनुवर्त;
		}
		debug_f("add \"%s\"", src->subsystem_name[i]);
		dst->subsystem_name = xrecallocarray(
		    dst->subsystem_name, dst->अङ्कः_subsystems,
		    dst->अङ्कः_subsystems + 1, परिमाण(*dst->subsystem_name));
		dst->subsystem_command = xrecallocarray(
		    dst->subsystem_command, dst->अङ्कः_subsystems,
		    dst->अङ्कः_subsystems + 1, परिमाण(*dst->subsystem_command));
		dst->subsystem_args = xrecallocarray(
		    dst->subsystem_args, dst->अङ्कः_subsystems,
		    dst->अङ्कः_subsystems + 1, परिमाण(*dst->subsystem_args));
		j = dst->अङ्कः_subsystems++;
		dst->subsystem_name[j] = xstrdup(src->subsystem_name[i]);
		dst->subsystem_command[j] = xstrdup(src->subsystem_command[i]);
		dst->subsystem_args[j] = xstrdup(src->subsystem_args[i]);
	}
}

स्थिर पूर्णाङ्क
serialise_s32(संरचना sshbuf *buf, पूर्णाङ्क v)
{
	uint32_t uv;
	पूर्णाङ्क r;

	uv = v < 0 ? (uint32_t)(-(v + 1)) + 1 : (uint32_t)v;
	सचे ((r = sshbuf_put_u8(buf, v < 0)) != 0 ||
	    (r = sshbuf_put_u32(buf, uv)) != 0)
		पटिनिवत्त r;
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
serialise_s64(संरचना sshbuf *buf, int64_t v)
{
	uint64_t uv;
	पूर्णाङ्क r;

	uv = v < 0 ? (uint64_t)(-(v + 1)) + 1 : (uint64_t)v;
	सचे ((r = sshbuf_put_u8(buf, v < 0)) != 0 ||
	    (r = sshbuf_put_u64(buf, uv)) != 0)
		पटिनिवत्त r;
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
serialise_mode(संरचना sshbuf *buf, mode_t v)
{
	u_int uv;

	सचे (v == (mode_t)-1)
		पटिनिवत्त serialise_s32(buf, -1);
	uv = (u_int)v;
	सचे ((mode_t)uv != v || uv > 0777)
		पटिनिवत्त SSH_ERR_INVALID_FORMAT;
	पटिनिवत्त serialise_s32(buf, (पूर्णाङ्क)uv);
}

स्थिर पूर्णाङ्क
serialise_double(संरचना sshbuf *buf, द्विगुण v)
{
	/*
	 * XXX this is no good for a wire encoding.
	 * It's fine for passing configurations via RPC, but it would
	 * be nicer to have an exact binary encoding here.
	 */
	पटिनिवत्त sshbuf_put(buf, &v, परिमाण(v));
}

स्थिर पूर्णाङ्क
serialise_nullable_string(संरचना sshbuf *buf, ध्रुव वर्ण *s)
{
	पूर्णाङ्क r;

	सचे ((r = sshbuf_put_u8(buf, s != रिक्त)) != 0)
		पटिनिवत्त r;
	सचे (s == रिक्त)
		पटिनिवत्त 0;
	पटिनिवत्त sshbuf_put_cstring(buf, s);
}

स्थिर पूर्णाङ्क
serialise_nullable_string_array(संरचना sshbuf *buf, वर्ण **a, u_int n)
{
	पूर्णाङ्क r;
	u_int i;

	सचे ((r = sshbuf_put_u32(buf, n)) != 0)
		पटिनिवत्त r;
	अत्थाय (i = 0; i < n; i++) {
		सचे ((r = serialise_nullable_string(buf, a[i])) != 0)
			पटिनिवत्त r;
	}
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
serialise_hostkeyfile(ध्रुव ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;
	u_int i;

	सचे ((r = sshbuf_put_u32(buf, options->अङ्कः_host_कुञ्चिका_files)) != 0) {
		error_fr(r, "serialise length");
		पटिनिवत्त r;
	}
	अत्थाय (i = 0; i < options->अङ्कः_host_कुञ्चिका_files; i++) {
		सचे ((r = serialise_s32(buf,
		    options->host_कुञ्चिका_file_userprovided[i])) != 0 ||
		    (r = serialise_nullable_string(buf,
		    options->host_कुञ्चिका_files[i])) != 0) {
			error_fr(r, "serialise member");
			पटिनिवत्त r;
		}
	}
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
serialise_ipqos(ध्रुव ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	सचे ((r = serialise_s32(buf, options->ip_qos_interactive)) != 0 ||
	    (r = serialise_s32(buf, options->ip_qos_bulk)) != 0) {
		error_fr(r, "serialise");
		पटिनिवत्त r;
	}

	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
serialise_listenaddress(ध्रुव ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;
	u_int i;

	/* Note: only serialises queued listen addresses */
	सचे ((r = sshbuf_put_u32(buf, options->अङ्कः_queued_listens)) != 0) {
		error_fr(r, "serialise length");
		पटिनिवत्त r;
	}
	अत्थाय (i = 0; i < options->अङ्कः_queued_listens; i++) {
		ध्रुव संरचना queued_listenaddr *qla =
		    options->queued_listen_addrs + i;

		सचे ((r = sshbuf_put_cstring(buf, qla->addr)) != 0 ||
		    (r = serialise_s32(buf, qla->port)) != 0 ||
		    (r = serialise_nullable_string(buf, qla->rdomain)) != 0) {
			error_fr(r, "serialise member");
			पटिनिवत्त r;
		}
	}
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
serialise_logfacility(ध्रुव ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	सचे ((r = serialise_s32(buf, (पूर्णाङ्क)options->log_facility)) != 0) {
		error_fr(r, "serialise");
		पटिनिवत्त r;
	}

	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
serialise_loglevel(ध्रुव ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	सचे ((r = serialise_s32(buf, (पूर्णाङ्क)options->log_level)) != 0) {
		error_fr(r, "serialise");
		पटिनिवत्त r;
	}

	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
serialise_port(ध्रुव ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;
	u_int i;

	सचे ((r = sshbuf_put_u32(buf, options->अङ्कः_ports)) != 0) {
		error_fr(r, "serialise length");
		पटिनिवत्त r;
	}
	अत्थाय (i = 0; i < options->अङ्कः_ports; i++) {
		सचे ((r = serialise_s32(buf, options->ports[i])) != 0) {
			error_fr(r, "serialise port");
			पटिनिवत्त r;
		}
	}
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
serialise_gatewayports(ध्रुव ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	सचे ((r = serialise_s32(buf, options->fwd_opts.gateway_ports)) != 0) {
		error_fr(r, "serialise");
		पटिनिवत्त r;
	}
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
serialise_streamlocalbindmask(ध्रुव ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	सचे ((r = serialise_mode(buf,
	    options->fwd_opts.streamlocal_bind_mask)) != 0) {
		error_fr(r, "serialise");
		पटिनिवत्त r;
	}
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
serialise_streamlocalbindunlink(ध्रुव ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	सचे ((r = sshbuf_put_u8(buf,
	    (options->fwd_opts.streamlocal_bind_unlink != 0))) != 0) {
		error_fr(r, "serialise");
		पटिनिवत्त r;
	}
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
serialise_maxstartups(ध्रुव ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	सचे ((r = serialise_s32(buf, options->max_startups_begin)) != 0 ||
	    (r = serialise_s32(buf, options->max_startups_rate)) != 0 ||
	    (r = serialise_s32(buf, options->max_startups)) != 0) {
		error_fr(r, "serialise");
		पटिनिवत्त r;
	}

	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
serialise_permituserenv(ध्रुव ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	सचे ((r = serialise_s32(buf, options->permit_user_env)) != 0 ||
	    (r = serialise_nullable_string(buf,
	    options->permit_user_env_allowlist)) != 0) {
		error_fr(r, "serialise");
		पटिनिवत्त r;
	}

	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
serialise_persourcenetblocksize(ध्रुव ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	सचे ((r = serialise_s32(buf, options->per_source_masklen_ipv4)) != 0 ||
	    (r = serialise_s32(buf, options->per_source_masklen_ipv6)) != 0) {
		error_fr(r, "serialise");
		पटिनिवत्त r;
	}

	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
serialise_persourcepenalties(ध्रुव ServerOptions *options, संरचना sshbuf *buf)
{
	ध्रुव संरचना per_source_penalty *psp = &options->per_source_penalty;
	पूर्णाङ्क r;

	सचे ((r = serialise_s32(buf, psp->enabled)) != 0 ||
	    (r = serialise_s32(buf, psp->max_sources4)) != 0 ||
	    (r = serialise_s32(buf, psp->max_sources6)) != 0 ||
	    (r = serialise_s32(buf, psp->overflow_mode)) != 0 ||
	    (r = serialise_s32(buf, psp->overflow_mode6)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_crash)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_grace)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_authfail)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_invaliduser)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_noauth)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_refuseconnection)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_max)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_min)) != 0) {
		error_fr(r, "serialise");
		पटिनिवत्त r;
	}

	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
serialise_rekeylimit(ध्रुव ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	सचे ((r = serialise_s64(buf, options->rekey_limit)) != 0 ||
	    (r = serialise_s32(buf, options->rekey_interval)) != 0) {
		error_fr(r, "serialise");
		पटिनिवत्त r;
	}

	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
serialise_subsystem(ध्रुव ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;
	u_int i;

	सचे ((r = sshbuf_put_u32(buf, options->अङ्कः_subsystems)) != 0) {
		error_fr(r, "serialise length");
		पटिनिवत्त r;
	}
	अत्थाय (i = 0; i < options->अङ्कः_subsystems; i++) {
		सचे ((r = sshbuf_put_cstring(buf,
		    options->subsystem_name[i])) != 0 ||
		    (r = sshbuf_put_cstring(buf,
		    options->subsystem_command[i])) != 0 ||
		    (r = sshbuf_put_cstring(buf,
		    options->subsystem_args[i])) != 0) {
			error_fr(r, "serialise member");
			पटिनिवत्त r;
		}
	}
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
serialise_pubkey_auth_options(ध्रुव ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	सचे ((r = serialise_s32(buf, options->pubkey_auth_options)) != 0 ||
	    (r = serialise_s32(buf, options->max_pubkey_ok)) != 0) {
		error_fr(r, "serialise");
		पटिनिवत्त r;
	}
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
serialise_timingsecret(ध्रुव ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	सचे ((r = sshbuf_put_u64(buf, options->timing_secret)) != 0) {
		error_fr(r, "serialise");
		पटिनिवत्त r;
	}
	पटिनिवत्त 0;
}


पूर्णाङ्क
serialise_server_options(ध्रुव ServerOptions *options, संरचना sshbuf **bufp)
{
	संरचना sshbuf *buf = रिक्त;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;

	*bufp = रिक्त;

	सचे ((buf = sshbuf_new()) == रिक्त)
		पटिनिवत्त SSH_ERR_ALLOC_FAIL;
	सचे ((r = sshbuf_put_u32(buf, SSHD_CONFIG_BLOB_VERSION)) != 0) {
		error_fr(r, "serialise version");
		गच्छ out;
	}

#define SSHCONF_INT(var, conf, flags, ms, def, cp) \
	सचे ((r = serialise_s32(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		गच्छ out; \
	}
#define SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	सचे ((r = serialise_s32(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		गच्छ out; \
	}
#define SSHCONF_STRING(var, conf, flags, cp) \
	सचे ((r = serialise_nullable_string(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		गच्छ out; \
	}
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	सचे ((r = serialise_nullable_string_array(buf, options->var, \
	    options->nvar)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		गच्छ out; \
	}
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	सचे ((r = serialise_##funcsuffix(options, buf)) != 0) \
		गच्छ out;
#define SSHCONF_NONCONF(funcsuffix) \
	सचे ((r = serialise_##funcsuffix(options, buf)) != 0) \
		गच्छ out;
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	/* empty */
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	/* empty */
#define SSHCONF_ALIAS(old, conf, flags)			/* empty */

	SSHD_CONFIG_ENTRIES

#undef SSHCONF_INT
#undef SSHCONF_INTFLAG
#undef SSHCONF_STRING
#undef SSHCONF_STRARRAY
#undef SSHCONF_CUSTOM
#undef SSHCONF_NONCONF
#undef SSHCONF_DEPRECATE
#undef SSHCONF_UNSUPPORTED_INT
#undef SSHCONF_UNSUPPORTED_STRING
#undef SSHCONF_ALIAS

	/* success */
	r = 0;
	*bufp = buf;
	buf = रिक्त; /* transferred */
 out:
	sshbuf_free(buf);
	पटिनिवत्त r;
}

स्थिर पूर्णाङ्क
deserialise_s32(संरचना sshbuf *buf, पूर्णाङ्क *v)
{
	uint32_t tmp;
	पूर्णाङ्क r;
	u_char was_signed;

	सचे ((r = sshbuf_get_u8(buf, &was_signed)) != 0 ||
	    (r = sshbuf_get_u32(buf, &tmp)) != 0)
		पटिनिवत्त r;
	सचे (was_signed > 1)
		पटिनिवत्त SSH_ERR_INVALID_FORMAT;
	सचे (was_signed) {
		सचे (tmp > (uint32_t)INT_MAX + 1)
			पटिनिवत्त SSH_ERR_INVALID_FORMAT;
		*v = tmp == (uint32_t)INT_MAX + 1 ? INT_MIN : -(पूर्णाङ्क)tmp;
	} अञ्ञथा {
		सचे (tmp > INT_MAX)
			पटिनिवत्त SSH_ERR_INVALID_FORMAT;
		*v = (पूर्णाङ्क)tmp;
	}
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
deserialise_s64(संरचना sshbuf *buf, int64_t *v)
{
	uint64_t tmp;
	पूर्णाङ्क r;
	u_char was_signed;

	सचे ((r = sshbuf_get_u8(buf, &was_signed)) != 0 ||
	    (r = sshbuf_get_u64(buf, &tmp)) != 0)
		पटिनिवत्त r;
	सचे (was_signed > 1)
		पटिनिवत्त SSH_ERR_INVALID_FORMAT;
	सचे (was_signed) {
		सचे (tmp > (uint64_t)INT64_MAX + 1)
			पटिनिवत्त SSH_ERR_INVALID_FORMAT;
		*v = tmp == (uint64_t)INT64_MAX + 1 ?
		    INT64_MIN : -(int64_t)tmp;
	} अञ्ञथा {
		सचे (tmp > INT64_MAX)
			पटिनिवत्त SSH_ERR_INVALID_FORMAT;
		*v = (int64_t)tmp;
	}
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
deserialise_mode(संरचना sshbuf *buf, mode_t *v)
{
	पूर्णाङ्क r, tmp;

	सचे ((r = deserialise_s32(buf, &tmp)) != 0)
		पटिनिवत्त r;
	सचे (tmp == -1) {
		*v = (mode_t)-1;
		पटिनिवत्त 0;
	}
	सचे (tmp < 0 || tmp > 0777)
		पटिनिवत्त SSH_ERR_INVALID_FORMAT;
	*v = (mode_t)tmp;
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
deserialise_double(संरचना sshbuf *buf, द्विगुण *v)
{
	पटिनिवत्त sshbuf_get(buf, v, परिमाण(*v));
}

स्थिर पूर्णाङ्क
deserialise_nullable_string(संरचना sshbuf *buf, वर्ण **sp)
{
	पूर्णाङ्क r;
	u_char present;

	सचे ((r = sshbuf_get_u8(buf, &present)) != 0)
		पटिनिवत्त r;
	सचे (present == 0) {
		*sp = रिक्त;
		पटिनिवत्त 0;
	}
	सचे (present != 1)
		पटिनिवत्त SSH_ERR_INVALID_FORMAT;
	पटिनिवत्त sshbuf_get_cstring(buf, sp, रिक्त);
}

स्थिर शून्य
free_string_array(वर्ण **a, u_int n)
{
	u_int i;

	सचे (a == रिक्त)
		पटिनिवत्त;
	अत्थाय (i = 0; i < n; i++)
		मुक्त(a[i]);
	मुक्त(a);
}

स्थिर पूर्णाङ्क
deserialise_गणनम्(संरचना sshbuf *buf, u_int *np, ध्रुव वर्ण *what)
{
	पूर्णाङ्क r;
	uint32_t n;

	सचे ((r = sshbuf_get_u32(buf, &n)) != 0) {
		error_fr(r, "deserialise %s length", what);
		पटिनिवत्त r;
	}
	सचे (n > UINT_MAX) {
		error_f("bad number of %s", what);
		पटिनिवत्त SSH_ERR_INVALID_FORMAT;
	}
	सचे (n > sshbuf_len(buf)) {
		error_f("bad number of %s", what);
		पटिनिवत्त SSH_ERR_INVALID_FORMAT;
	}
	*np = n;
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
deserialise_nullable_string_array(संरचना sshbuf *buf, वर्ण ***arrayp,
    u_int *np)
{
	वर्ण **a = रिक्त;
	पूर्णाङ्क r;
	u_int i, n;

	*arrayp = रिक्त;
	*np = 0;
	सचे ((r = deserialise_गणनम्(buf, &n, "strings")) != 0)
		पटिनिवत्त r;
	सचे (n > 0)
		a = xcalloc(n, परिमाण(*a));
	अत्थाय (i = 0; i < n; i++) {
		सचे ((r = deserialise_nullable_string(buf, a + i)) != 0) {
			free_string_array(a, i + 1);
			पटिनिवत्त r;
		}
	}
	*arrayp = a;
	*np = n;
	पटिनिवत्त 0;
}

स्थिर शून्य
free_queued_listen_addrs(संरचना queued_listenaddr *qla, u_int n)
{
	u_int i;

	सचे (qla == रिक्त)
		पटिनिवत्त;
	अत्थाय (i = 0; i < n; i++) {
		मुक्त(qla[i].addr);
		मुक्त(qla[i].rdomain);
	}
	मुक्त(qla);
}

स्थिर पूर्णाङ्क
deserialise_hostkeyfile(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r, *userprovided = रिक्त;
	u_int i, n;
	वर्ण **files = रिक्त;

	सचे ((r = deserialise_गणनम्(buf, &n, "host key files")) != 0)
		पटिनिवत्त r;
	सचे (n > 0) {
		userprovided = xcalloc(n, परिमाण(*userprovided));
		files = xcalloc(n, परिमाण(*files));
	}
	अत्थाय (i = 0; i < n; i++) {
		सचे ((r = deserialise_s32(buf, userprovided + i)) != 0 ||
		    (r = deserialise_nullable_string(buf, files + i)) != 0) {
			error_fr(r, "deserialise member");
			free_string_array(files, i + 1);
			मुक्त(userprovided);
			पटिनिवत्त r;
		}
	}
	options->अङ्कः_host_कुञ्चिका_files = n;
	options->host_कुञ्चिका_file_userprovided = userprovided;
	options->host_कुञ्चिका_files = files;
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
deserialise_ipqos(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	सचे ((r = deserialise_s32(buf, &options->ip_qos_interactive)) != 0 ||
	    (r = deserialise_s32(buf, &options->ip_qos_bulk)) != 0) {
		error_fr(r, "deserialise");
		पटिनिवत्त r;
	}

	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
deserialise_listenaddress(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;
	u_int i, n;
	संरचना queued_listenaddr *qla = रिक्त;

	सचे ((r = deserialise_गणनम्(buf, &n, "listen addresses")) != 0)
		पटिनिवत्त r;
	सचे (n > 0)
		qla = xcalloc(n, परिमाण(*qla));
	अत्थाय (i = 0; i < n; i++) {
		सचे ((r = sshbuf_get_cstring(buf, &qla[i].addr, रिक्त)) != 0 ||
		    (r = deserialise_s32(buf, &qla[i].port)) != 0 ||
		    (r = deserialise_nullable_string(buf,
		    &qla[i].rdomain)) != 0) {
			error_fr(r, "deserialise member");
			free_queued_listen_addrs(qla, i + 1);
			पटिनिवत्त r;
		}
	}
	options->अङ्कः_queued_listens = n;
	options->queued_listen_addrs = qla;
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
deserialise_logfacility(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r, tmp;

	सचे ((r = deserialise_s32(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		पटिनिवत्त r;
	}
	सचे (tmp != SYSLOG_FACILITY_NOT_SET &&
	    log_facility_name((SyslogFacility)tmp) == रिक्त) {
		error_f("bad syslog facility");
		पटिनिवत्त SSH_ERR_INVALID_FORMAT;
	}
	options->log_facility = (SyslogFacility)tmp;

	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
deserialise_loglevel(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r, tmp;

	सचे ((r = deserialise_s32(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		पटिनिवत्त r;
	}
	सचे (tmp != SYSLOG_LEVEL_NOT_SET &&
	    log_level_name((LogLevel)tmp) == रिक्त) {
		error_f("bad log level");
		पटिनिवत्त SSH_ERR_INVALID_FORMAT;
	}
	options->log_level = (LogLevel)tmp;

	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
deserialise_port(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;
	u_int i, n;

	सचे ((r = deserialise_गणनम्(buf, &n, "ports")) != 0)
		पटिनिवत्त r;
	सचे (n > MAX_PORTS) {
		error_f("bad number of ports");
		पटिनिवत्त SSH_ERR_INVALID_FORMAT;
	}
	options->अङ्कः_ports = n;
	memset(options->ports, 0, परिमाण(options->ports));
	अत्थाय (i = 0; i < options->अङ्कः_ports; i++) {
		सचे ((r = deserialise_s32(buf, options->ports + i)) != 0) {
			error_fr(r, "deserialise port");
			पटिनिवत्त r;
		}
	}
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
deserialise_gatewayports(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	सचे ((r = deserialise_s32(buf, &options->fwd_opts.gateway_ports)) != 0) {
		error_fr(r, "deserialise");
		पटिनिवत्त r;
	}
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
deserialise_streamlocalbindmask(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	सचे ((r = deserialise_mode(buf,
	    &options->fwd_opts.streamlocal_bind_mask)) != 0) {
		error_fr(r, "deserialise");
		पटिनिवत्त r;
	}
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
deserialise_streamlocalbindunlink(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;
	u_char tmp;

	सचे ((r = sshbuf_get_u8(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		पटिनिवत्त r;
	}
	सचे (tmp > 1) {
		error_f("bad boolean");
		पटिनिवत्त SSH_ERR_INVALID_FORMAT;
	}
	options->fwd_opts.streamlocal_bind_unlink = tmp;
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
deserialise_maxstartups(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	सचे ((r = deserialise_s32(buf, &options->max_startups_begin)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_startups_rate)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_startups)) != 0) {
		error_fr(r, "deserialise");
		पटिनिवत्त r;
	}

	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
deserialise_permituserenv(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	सचे ((r = deserialise_s32(buf, &options->permit_user_env)) != 0 ||
	    (r = deserialise_nullable_string(buf,
	    &options->permit_user_env_allowlist)) != 0) {
		error_fr(r, "deserialise");
		पटिनिवत्त r;
	}
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
deserialise_persourcenetblocksize(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	सचे ((r = deserialise_s32(buf,
	    &options->per_source_masklen_ipv4)) != 0 ||
	    (r = deserialise_s32(buf,
	    &options->per_source_masklen_ipv6)) != 0) {
		error_fr(r, "deserialise");
		पटिनिवत्त r;
	}

	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
deserialise_persourcepenalties(ServerOptions *options, संरचना sshbuf *buf)
{
	संरचना per_source_penalty *psp = &options->per_source_penalty;
	पूर्णाङ्क r;

	सचे ((r = deserialise_s32(buf, &psp->enabled)) != 0 ||
	    (r = deserialise_s32(buf, &psp->max_sources4)) != 0 ||
	    (r = deserialise_s32(buf, &psp->max_sources6)) != 0 ||
	    (r = deserialise_s32(buf, &psp->overflow_mode)) != 0 ||
	    (r = deserialise_s32(buf, &psp->overflow_mode6)) != 0 ||
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
		पटिनिवत्त r;
	}

	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
deserialise_rekeylimit(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	सचे ((r = deserialise_s64(buf, &options->rekey_limit)) != 0 ||
	    (r = deserialise_s32(buf, &options->rekey_interval)) != 0) {
		error_fr(r, "deserialise");
		पटिनिवत्त r;
	}

	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
deserialise_subsystem(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;
	u_int i, n;
	वर्ण **names = रिक्त, **commands = रिक्त, **args = रिक्त;

	सचे ((r = deserialise_गणनम्(buf, &n, "subsystems")) != 0)
		पटिनिवत्त r;
	सचे (n > 0) {
		names = xcalloc(n, परिमाण(*names));
		commands = xcalloc(n, परिमाण(*names));
		args = xcalloc(n, परिमाण(*args));
	}
	अत्थाय (i = 0; i < n; i++) {
		सचे ((r = sshbuf_get_cstring(buf, names + i, रिक्त)) != 0 ||
		    (r = sshbuf_get_cstring(buf, commands + i, रिक्त)) != 0 ||
		    (r = sshbuf_get_cstring(buf, args + i, रिक्त)) != 0) {
			error_fr(r, "deserialise member");
			free_string_array(names, i + 1);
			free_string_array(commands, i + 1);
			free_string_array(args, i + 1);
			पटिनिवत्त r;
		}
	}
	options->अङ्कः_subsystems = n;
	options->subsystem_name = names;
	options->subsystem_command = commands;
	options->subsystem_args = args;
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
deserialise_pubkey_auth_options(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	सचे ((r = deserialise_s32(buf, &options->pubkey_auth_options)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_pubkey_ok)) != 0) {
		error_fr(r, "deserialise");
		पटिनिवत्त r;
	}
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
deserialise_timingsecret(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	सचे ((r = sshbuf_get_u64(buf, &options->timing_secret)) != 0) {
		error_fr(r, "deserialise");
		पटिनिवत्त r;
	}
	पटिनिवत्त 0;
}

पूर्णाङ्क
deserialise_server_options(संरचना sshbuf *buf, ServerOptions *options)
{
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;
	uint32_t version;
	ServerOptions new_options;

	initialize_server_options(&new_options);
	सचे ((r = sshbuf_get_u32(buf, &version)) != 0) {
		error_fr(r, "deserialise version");
		गच्छ out;
	}
	सचे (version != SSHD_CONFIG_BLOB_VERSION) {
		error_f("unsupported config blob version %u", version);
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
#define SSHCONF_INT(var, conf, flags, ms, def, cp) \
	सचे ((r = deserialise_s32(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		गच्छ out; \
	}
#define SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	सचे ((r = deserialise_s32(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		गच्छ out; \
	}
#define SSHCONF_STRING(var, conf, flags, cp) \
	सचे ((r = deserialise_nullable_string(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		गच्छ out; \
	}
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	सचे ((r = deserialise_nullable_string_array(buf, &new_options.var, \
	    &new_options.nvar)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		गच्छ out; \
	}
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	सचे ((r = deserialise_##funcsuffix(&new_options, buf)) != 0) \
		गच्छ out;
#define SSHCONF_NONCONF(funcsuffix) \
	सचे ((r = deserialise_##funcsuffix(&new_options, buf)) != 0) \
		गच्छ out;
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	new_options.var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	करोहि { \
		मुक्त(new_options.var); \
		new_options.var = रिक्त; \
	} याव (0);
#define SSHCONF_ALIAS(old, conf, flags)			/* empty */

	SSHD_CONFIG_ENTRIES

	सचे (sshbuf_len(buf) != 0) {
		error_f("trailing data in config blob");
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}

#undef SSHCONF_INT
#undef SSHCONF_INTFLAG
#undef SSHCONF_STRING
#undef SSHCONF_STRARRAY
#undef SSHCONF_CUSTOM
#undef SSHCONF_NONCONF
#undef SSHCONF_DEPRECATE
#undef SSHCONF_UNSUPPORTED_INT
#undef SSHCONF_UNSUPPORTED_STRING
#undef SSHCONF_ALIAS

	/* success */
	r = 0;
	free_server_options(options);
	*options = new_options;
	memset(&new_options, 0, परिमाण(new_options));
 out:
	free_server_options(&new_options);
	पटिनिवत्त r;
}

स्थिर शून्य
free_hostkeyfile(ServerOptions *options)
{
	u_int i;

	अत्थाय (i = 0; i < options->अङ्कः_host_कुञ्चिका_files; i++)
		मुक्त(options->host_कुञ्चिका_files[i]);
	मुक्त(options->host_कुञ्चिका_files);
	मुक्त(options->host_कुञ्चिका_file_userprovided);
}

स्थिर शून्य
free_listenaddress(ServerOptions *options)
{
	u_int i;

	free_queued_listen_addrs(options->queued_listen_addrs,
	    options->अङ्कः_queued_listens);

	अत्थाय (i = 0; i < options->अङ्कः_listen_addrs; i++) {
		मुक्त(options->listen_addrs[i].rdomain);
		सचे (options->listen_addrs[i].addrs != रिक्त)
			freeaddrinfo(options->listen_addrs[i].addrs);
	}
	मुक्त(options->listen_addrs);
}

स्थिर शून्य
free_permituserenv(ServerOptions *options)
{
	मुक्त(options->permit_user_env_allowlist);
}

स्थिर शून्य
free_subsystem(ServerOptions *options)
{
	u_int i;

	अत्थाय (i = 0; i < options->अङ्कः_subsystems; i++) {
		मुक्त(options->subsystem_name[i]);
		मुक्त(options->subsystem_command[i]);
		मुक्त(options->subsystem_args[i]);
	}
	मुक्त(options->subsystem_name);
	मुक्त(options->subsystem_command);
	मुक्त(options->subsystem_args);
}

शून्य
free_server_options(ServerOptions *options)
{
#define SSHCONF_INT(var, conf, flags, ms, def, cp)	/* empty */
#define SSHCONF_INTFLAG(var, conf, flags, def, cp)	/* empty */
#define SSHCONF_STRING(var, conf, flags, cp)		मुक्त(options->var);
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	free_string_array(options->var, options->nvar);
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	free_##funcsuffix(options);
#define SSHCONF_NONCONF(funcsuffix) \
	free_##funcsuffix(options);
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	करोहि { \
		मुक्त(options->var); \
		options->var = रिक्त; \
	} याव (0);
#define SSHCONF_ALIAS(old, conf, flags)			/* empty */

#define free_ipqos(options)
#define free_logfacility(options)
#define free_loglevel(options)
#define free_port(options)
#define free_gatewayports(options)
#define free_streamlocalbindmask(options)
#define free_streamlocalbindunlink(options)
#define free_maxstartups(options)
#define free_persourcenetblocksize(options)
#define free_persourcepenalties(options)
#define free_rekeylimit(options)
#define free_pubkey_auth_options(options)
#define free_timingsecret(options)

	SSHD_CONFIG_ENTRIES

#undef free_ipqos
#undef free_logfacility
#undef free_loglevel
#undef free_port
#undef free_gatewayports
#undef free_streamlocalbindmask
#undef free_streamlocalbindunlink
#undef free_maxstartups
#undef free_persourcenetblocksize
#undef free_persourcepenalties
#undef free_rekeylimit
#undef free_timingsecret

#undef SSHCONF_INT
#undef SSHCONF_INTFLAG
#undef SSHCONF_STRING
#undef SSHCONF_STRARRAY
#undef SSHCONF_CUSTOM
#undef SSHCONF_NONCONF
#undef SSHCONF_DEPRECATE
#undef SSHCONF_UNSUPPORTED_INT
#undef SSHCONF_UNSUPPORTED_STRING
#undef SSHCONF_ALIAS

	initialize_server_options(options);
}

स्थिर शून्य
copy_server_option_int(पूर्णाङ्क *dst, पूर्णाङ्क src)
{
	सचे (src != -1)
		*dst = src;
}

स्थिर शून्य
copy_server_option_int64(int64_t *dst, int64_t src)
{
	सचे (src != -1)
		*dst = src;
}

स्थिर शून्य
copy_server_option_string(वर्ण **dst, ध्रुव वर्ण *src)
{
	सचे (src != रिक्त && *dst != src) {
		मुक्त(*dst);
		*dst = xstrdup(src);
	}
}

स्थिर शून्य
copy_server_option_strarray_मानानि(वर्ण ***dst, u_int ndst,
    वर्ण * ध्रुव *src, u_int nsrc)
{
	u_int i;

	सचे (nsrc == 0)
		पटिनिवत्त;
	अत्थाय (i = 0; i < ndst; i++)
		मुक्त((*dst)[i]);
	मुक्त(*dst);
	*dst = xcalloc(nsrc, परिमाण(**dst));
	अत्थाय (i = 0; i < nsrc; i++)
		(*dst)[i] = src[i] == रिक्त ? रिक्त : xstrdup(src[i]);
}

स्थिर शून्य
copy_server_option_strarray(वर्ण ***dst, u_int *ndst,
    वर्ण * ध्रुव *src, u_int nsrc)
{
	सचे (nsrc == 0)
		पटिनिवत्त;
	copy_server_option_strarray_मानानि(dst, *ndst, src, nsrc);
	*ndst = nsrc;
}

स्थिर शून्य
copy_ipqos(ServerOptions *dst, ध्रुव ServerOptions *src)
{
	copy_server_option_int(&dst->ip_qos_interactive,
	    src->ip_qos_interactive);
	copy_server_option_int(&dst->ip_qos_bulk, src->ip_qos_bulk);
}

स्थिर शून्य
copy_gatewayports(ServerOptions *dst, ध्रुव ServerOptions *src)
{
	copy_server_option_int(&dst->fwd_opts.gateway_ports,
	    src->fwd_opts.gateway_ports);
}

स्थिर शून्य
copy_streamlocalbindunlink(ServerOptions *dst, ध्रुव ServerOptions *src)
{
	copy_server_option_int(&dst->fwd_opts.streamlocal_bind_unlink,
	    src->fwd_opts.streamlocal_bind_unlink);
}

स्थिर शून्य
copy_loglevel(ServerOptions *dst, ध्रुव ServerOptions *src)
{
	सचे (src->log_level != -1)
		dst->log_level = src->log_level;
}

स्थिर शून्य
copy_rekeylimit(ServerOptions *dst, ध्रुव ServerOptions *src)
{
	copy_server_option_int64(&dst->rekey_limit, src->rekey_limit);
	copy_server_option_int(&dst->rekey_interval, src->rekey_interval);
}

स्थिर शून्य
copy_subsystem(ServerOptions *dst, ध्रुव ServerOptions *src)
{
	u_int old_अङ्कः_subsystems = dst->अङ्कः_subsystems;

	सचे (src->अङ्कः_subsystems == 0)
		पटिनिवत्त;
	copy_server_option_strarray_मानानि(&dst->subsystem_name,
	    old_अङ्कः_subsystems, src->subsystem_name, src->अङ्कः_subsystems);
	copy_server_option_strarray_मानानि(&dst->subsystem_command,
	    old_अङ्कः_subsystems, src->subsystem_command, src->अङ्कः_subsystems);
	copy_server_option_strarray_मानानि(&dst->subsystem_args,
	    old_अङ्कः_subsystems, src->subsystem_args, src->अङ्कः_subsystems);
	dst->अङ्कः_subsystems = src->अङ्कः_subsystems;
}

स्थिर शून्य
copy_pubkey_auth_options(ServerOptions *dst, ध्रुव ServerOptions *src)
{
	सचे (src->pubkey_auth_options != -1) {
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
शून्य
copy_set_server_options(ServerOptions *dst, ServerOptions *src, पूर्णाङ्क preauth)
{
	सचे (dst == src)
		पटिनिवत्त;

#define SSHCONF_INT(var, conf, flags, ms, def, cp) \
	cp(copy_server_option_int(&dst->var, src->var);)
#define SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	cp(copy_server_option_int(&dst->var, src->var);)
#define SSHCONF_STRING(var, conf, flags, cp) \
	cp(copy_server_option_string(&dst->var, src->var);)
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	cp(copy_server_option_strarray(&dst->var, &dst->nvar, \
	    src->var, src->nvar);)
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	cp(copy_##funcsuffix(dst, src);)
#define SSHCONF_NONCONF(funcsuffix)			/* empty */
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	dst->var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	करोहि { \
		मुक्त(dst->var); \
		dst->var = रिक्त; \
	} याव (0);
#define SSHCONF_ALIAS(old, conf, flags)			/* empty */

	SSHD_CONFIG_ENTRIES

#undef SSHCONF_INT
#undef SSHCONF_INTFLAG
#undef SSHCONF_STRING
#undef SSHCONF_STRARRAY
#undef SSHCONF_CUSTOM
#undef SSHCONF_NONCONF
#undef SSHCONF_DEPRECATE
#undef SSHCONF_UNSUPPORTED_INT
#undef SSHCONF_UNSUPPORTED_STRING
#undef SSHCONF_ALIAS

	/*
	 * The bind_mask is a mode_t that may be unsigned, so we can't use
	 * copy_server_option_int - it does a signed comparison that causes
	 * compiler warnings.
	 */
	सचे (src->fwd_opts.streamlocal_bind_mask != (mode_t)-1) {
		dst->fwd_opts.streamlocal_bind_mask =
		    src->fwd_opts.streamlocal_bind_mask;
	}

	/* Arguments that accept '+...' need to be expanded */
	assemble_algorithms(dst);

	/*
	 * These options may be "none" to clear a global setting.  They are
	 * consulted before authentication, so they must be cleared here
	 * rather than in the post-auth section below.
	 */
#define CLEAR_ON_NONE(v) \
	करोहि { \
		सचे (option_clear_or_none(v)) { \
			मुक्त(v); \
			v = रिक्त; \
		} \
	} याव(0)
	CLEAR_ON_NONE(dst->authorized_principals_file);
	CLEAR_ON_NONE(dst->trusted_user_ca_कुञ्चिकाः);
	CLEAR_ON_NONE(dst->banner);

	/*
	 * The only things that should be below this point are string options
	 * which are only used after authentication.
	 */
	सचे (preauth)
		पटिनिवत्त;

	/* These options may be "none" to clear a global setting */
	copy_server_option_string(&dst->adm_forced_command,
	    src->adm_forced_command);
	copy_server_option_string(&dst->chroot_directory,
	    src->chroot_directory);
	CLEAR_ON_NONE(dst->chroot_directory);
	CLEAR_ON_NONE(dst->adm_forced_command);
#undef CLEAR_ON_NONE

	/* Subsystems require merging. */
	servconf_merge_subsystems(dst, src);
}

#define SERVCONF_MAX_DEPTH	16
स्थिर शून्य
parse_server_config_depth(ServerOptions *options, ध्रुव वर्ण *filename,
    संरचना sshbuf *conf, संरचना include_list *includes,
    संरचना connection_info *connectinfo, पूर्णाङ्क flags, पूर्णाङ्क *activep, पूर्णाङ्क depth)
{
	पूर्णाङ्क linenum, bad_options = 0;
	वर्ण *cp, *obuf, *cbuf;

	सचे (depth < 0 || depth > SERVCONF_MAX_DEPTH)
		fatal("Too many recursive configuration includes");

	debug2_f("config %s len %zu%s", filename, sshbuf_len(conf),
	    (flags & SSHCFG_NEVERMATCH ? " [checking syntax only]" : ""));

	सचे ((obuf = cbuf = sshbuf_dup_string(conf)) == रिक्त)
		fatal_f("sshbuf_dup_string failed");
	linenum = 1;
	याव ((cp = strsep(&cbuf, "\n")) != रिक्त) {
		सचे (process_server_config_पङ्क्तिः_depth(options, cp,
		    filename, linenum++, activep, connectinfo, &flags,
		    depth, includes) != 0)
			bad_options++;
	}
	मुक्त(obuf);
	सचे (bad_options > 0)
		fatal("%s: terminating, %d bad configuration options",
		    filename, bad_options);
}

शून्य
parse_server_config(ServerOptions *options, ध्रुव वर्ण *filename,
    संरचना sshbuf *conf, संरचना include_list *includes,
    संरचना connection_info *connectinfo, पूर्णाङ्क reexec)
{
	पूर्णाङ्क active = connectinfo ? 0 : 1;
	parse_server_config_depth(options, filename, conf, includes,
	    connectinfo, (connectinfo ? SSHCFG_MATCH_ONLY : 0), &active, 0);
	सचे (!reexec)
		process_queued_listen_addrs(options);
}

स्थिर ध्रुव वर्ण *
fmt_multistate_int(पूर्णाङ्क val, ध्रुव संरचना multistate *m)
{
	u_int i;

	अत्थाय (i = 0; m[i].कुञ्चिका != रिक्त; i++) {
		सचे (m[i].मानम् == val)
			पटिनिवत्त m[i].कुञ्चिका;
	}
	पटिनिवत्त "UNKNOWN";
}

स्थिर ध्रुव वर्ण *
fmt_intarg(ServerOpCodes code, पूर्णाङ्क val)
{
	सचे (val == -1)
		पटिनिवत्त "unset";
	विकल्प (code) {
	पक्ष sAddressFamily:
		पटिनिवत्त fmt_multistate_int(val, multistate_addressfamily);
	पक्ष s_Permit_मूलम्_Login:
		पटिनिवत्त fmt_multistate_int(val, multistate_permitrootlogin);
	पक्ष sGatewayPorts:
		पटिनिवत्त fmt_multistate_int(val, multistate_gatewayports);
	पक्ष sCompression:
		पटिनिवत्त fmt_multistate_int(val, multistate_compression);
	पक्ष sAllowTcpForwarding:
		पटिनिवत्त fmt_multistate_int(val, multistate_tcpfwd);
	पक्ष sAllowStreamLocalForwarding:
		पटिनिवत्त fmt_multistate_int(val, multistate_tcpfwd);
	पक्ष sIgnoreRhosts:
		पटिनिवत्त fmt_multistate_int(val, multistate_ignore_rhosts);
	पक्ष sTCPKeepAlive:
		पटिनिवत्त fmt_multistate_int(val, multistate_keepalives);
	पक्ष sWarnWeakCrypto:
		पटिनिवत्त fmt_multistate_int(val, multistate_warnweakcrypto);
	पक्ष sFingerprintHash:
		पटिनिवत्त ssh_digest_alg_name(val);
	स्वभाव:
		विकल्प (val) {
		पक्ष 0:
			पटिनिवत्त "no";
		पक्ष 1:
			पटिनिवत्त "yes";
		स्वभाव:
			पटिनिवत्त "UNKNOWN";
		}
	}
}

स्थिर शून्य
dump_cfg_int(ServerOpCodes code, पूर्णाङ्क val)
{
	सचे (code == sUnusedConnectionTimeout && val == 0) {
		printf("%s none\n", lookup_opcode_name(code));
		पटिनिवत्त;
	}
	printf("%s %d\n", lookup_opcode_name(code), val);
}

स्थिर शून्य
dump_cfg_oct(ServerOpCodes code, पूर्णाङ्क val)
{
	printf("%s 0%o\n", lookup_opcode_name(code), val);
}

स्थिर शून्य
dump_cfg_fmtint(ServerOpCodes code, पूर्णाङ्क val)
{
	printf("%s %s\n", lookup_opcode_name(code), fmt_intarg(code, val));
}

स्थिर शून्य
dump_cfg_string(ServerOpCodes code, ध्रुव वर्ण *val)
{
	printf("%s %s\n", lookup_opcode_name(code),
	    val == रिक्त ? "none" : val);
}

स्थिर शून्य
dump_cfg_strarray(ServerOpCodes code, u_int गणनम्, वर्ण **vals)
{
	u_int i;

	अत्थाय (i = 0; i < गणनम्; i++)
		printf("%s %s\n", lookup_opcode_name(code), vals[i]);
}

स्थिर शून्य
dump_cfg_strarray_oneline(ServerOpCodes code, u_int गणनम्, वर्ण **vals)
{
	u_int i;

	विकल्प (code) {
	पक्ष sAuthenticationMethods:
	पक्ष sChannelTimeout:
		भङ्ग;
	स्वभाव:
		सचे (गणनम् <= 0)
			पटिनिवत्त;
		भङ्ग;
	}

	printf("%s", lookup_opcode_name(code));
	अत्थाय (i = 0; i < गणनम्; i++)
		printf(" %s",  vals[i]);
	सचे (code == sAuthenticationMethods && गणनम् == 0)
		printf(" any");
	अञ्ञथा सचे (code == sChannelTimeout && गणनम् == 0)
		printf(" none");
	printf("\n");
}

स्थिर वर्ण *
format_listen_addrs(संरचना listenaddr *la)
{
	पूर्णाङ्क r;
	संरचना addrinfo *ai;
	वर्ण addr[NI_MAXHOST], port[NI_MAXSERV];
	वर्ण *laddr1 = xstrdup(""), *laddr2 = रिक्त;

	/*
	 * ListenAddress must be after Port.  add_one_listen_addr pushes
	 * addresses onto a stack, so to maintain ordering we need to
	 * print these in reverse order.
	 */
	अत्थाय (ai = la->addrs; ai; ai = ai->ai_next) {
		सचे ((r = getnameinfo(ai->ai_addr, ai->ai_addrlen, addr,
		    परिमाण(addr), port, परिमाण(port),
		    NI_NUMERICHOST|NI_NUMERICSERV)) != 0) {
			error("getnameinfo: %.100s", ssh_gai_strerror(r));
			अनुवर्त;
		}
		laddr2 = laddr1;
		सचे (ai->ai_family == AF_INET6) {
			xasprintf(&laddr1, "ListenAddress [%s]:%s%s%s\n%s",
			    addr, port,
			    la->rdomain == रिक्त ? "" : " rdomain ",
			    la->rdomain == रिक्त ? "" : la->rdomain,
			    laddr2);
		} अञ्ञथा {
			xasprintf(&laddr1, "ListenAddress %s:%s%s%s\n%s",
			    addr, port,
			    la->rdomain == रिक्त ? "" : " rdomain ",
			    la->rdomain == रिक्त ? "" : la->rdomain,
			    laddr2);
		}
		मुक्त(laddr2);
	}
	पटिनिवत्त laddr1;
}

शून्य
dump_config(ServerOptions *o)
{
	वर्ण *s;
	u_int i;

	/* these are usually at the top of the config */
	अत्थाय (i = 0; i < o->अङ्कः_ports; i++)
		printf("Port %d\n", o->ports[i]);
	dump_cfg_fmtint(sAddressFamily, o->address_family);

	अत्थाय (i = 0; i < o->अङ्कः_listen_addrs; i++) {
		s = format_listen_addrs(&o->listen_addrs[i]);
		printf("%s", s);
		मुक्त(s);
	}

	/* integer arguments */
#ifdef USE_PAM
	dump_cfg_fmtint(sUsePAM, o->use_pam);
	dump_cfg_string(sPAMServiceName, o->pam_service_name);
#endif
	dump_cfg_int(sLoginGraceTime, o->login_grace_time);
	dump_cfg_int(sX11DisplayOffset, o->x11_display_offset);
	dump_cfg_int(sMaxAuthTries, o->max_authtries);
	dump_cfg_int(sMaxSessions, o->max_sessions);
	dump_cfg_int(sClientAliveInterval, o->client_alive_interval);
	dump_cfg_int(s_Client_Alive_गणनम्_Max, o->client_alive_गणनम्_max);
	dump_cfg_int(sRequiredRSASize, o->required_rsa_size);
	dump_cfg_oct(sStreamLocalBindMask, o->fwd_opts.streamlocal_bind_mask);
	dump_cfg_int(sUnusedConnectionTimeout, o->unused_connection_timeout);

	/* formatted integer arguments */
	dump_cfg_fmtint(s_Permit_मूलम्_Login, o->permit_मूलम्_login);
	dump_cfg_fmtint(sIgnoreRhosts, o->ignore_rhosts);
	dump_cfg_fmtint(sIgnoreUserKnownHosts, o->ignore_user_known_hosts);
	dump_cfg_fmtint(sHostbasedAuthentication, o->hostbased_authentication);
	dump_cfg_fmtint(sHostbasedUsesNameFromPacketOnly,
	    o->hostbased_uses_name_from_packet_only);
	dump_cfg_fmtint(sPubkeyAuthentication, o->pubkey_authentication);
#ifdef KRB5
	dump_cfg_fmtint(sKerberosAuthentication, o->kerberos_authentication);
	dump_cfg_fmtint(sKerberosOrLocalPasswd, o->kerberos_or_local_passwd);
	dump_cfg_fmtint(sKerberosTicketCleanup, o->kerberos_ticket_cleanup);
# ifdef USE_AFS
	dump_cfg_fmtint(sKerberosGetAFSToken, o->kerberos_get_afs_token);
# endif
#endif
#ifdef GSSAPI
	dump_cfg_fmtint(sGSSAPIAuthentication, o->gss_authentication);
	dump_cfg_fmtint(sGSSAPICleanupCredentials, o->gss_cleanup_creds);
	dump_cfg_fmtint(sGSSAPIDelegateCredentials, o->gss_deleg_creds);
	dump_cfg_fmtint(sGSSAPIStrictAcceptorCheck, o->gss_strict_acceptor);
#endif
	dump_cfg_fmtint(sPasswordAuthentication, o->password_authentication);
	dump_cfg_fmtint(sKbdInteractiveAuthentication,
	    o->kbd_interactive_authentication);
	dump_cfg_fmtint(sPrintMotd, o->print_motd);
#ifndef DISABLE_LASTLOG
	dump_cfg_fmtint(sPrintLastLog, o->print_lastlog);
#endif
	dump_cfg_fmtint(sX11Forwarding, o->x11_forwarding);
	dump_cfg_fmtint(sX11UseLocalhost, o->x11_use_localhost);
	dump_cfg_fmtint(sPermitTTY, o->permit_tty);
	dump_cfg_fmtint(sPermitUserRC, o->permit_user_rc);
	dump_cfg_fmtint(sStrictModes, o->strict_modes);
	dump_cfg_fmtint(sTCPKeepAlive, o->tcp_keep_alive);
	dump_cfg_fmtint(sPermitEmptyPasswords, o->permit_empty_passwd);
	dump_cfg_fmtint(sCompression, o->compression);
	dump_cfg_fmtint(sGatewayPorts, o->fwd_opts.gateway_ports);
	dump_cfg_fmtint(sUseDNS, o->use_dns);
	dump_cfg_fmtint(sAllowTcpForwarding, o->allow_tcp_forwarding);
	dump_cfg_fmtint(sAllowAgentForwarding, o->allow_agent_forwarding);
	dump_cfg_fmtint(sDisableForwarding, o->disable_forwarding);
	dump_cfg_fmtint(sAllowStreamLocalForwarding, o->allow_streamlocal_forwarding);
	dump_cfg_fmtint(sStreamLocalBindUnlink, o->fwd_opts.streamlocal_bind_unlink);
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
	dump_cfg_string(sTrustedUserCAKeys, o->trusted_user_ca_कुञ्चिकाः);
	dump_cfg_string(s_Security_कुञ्चिका_Provider, o->sk_provider);
	dump_cfg_string(sAuthorizedPrincipalsFile,
	    o->authorized_principals_file);
	dump_cfg_string(sVersionAddendum, *o->version_addendum == '\0'
	    ? "none" : o->version_addendum);
	dump_cfg_string(s_Authorized_कुञ्चिकाः_Command, o->authorized_कुञ्चिकाः_command);
	dump_cfg_string(s_Authorized_कुञ्चिकाः_Command_User, o->authorized_कुञ्चिकाः_command_user);
	dump_cfg_string(sAuthorizedPrincipalsCommand, o->authorized_principals_command);
	dump_cfg_string(sAuthorizedPrincipalsCommandUser, o->authorized_principals_command_user);
	dump_cfg_string(s_Host_कुञ्चिका_Agent, o->host_कुञ्चिका_agent);
	dump_cfg_string(sKexAlgorithms, o->kex_algorithms);
	dump_cfg_string(sCASignatureAlgorithms, o->ca_sign_algorithms);
	dump_cfg_string(sHostbasedAcceptedAlgorithms, o->hostbased_accepted_algos);
	dump_cfg_string(s_Host_कुञ्चिका_Algorithms, o->hostkeyalgorithms);
	dump_cfg_string(sPubkeyAcceptedAlgorithms, o->pubkey_accepted_algos);
#सचे defined(__OpenBSD__) || defined(HAVE_SYS_SET_PROCESS_RDOMAIN)
	dump_cfg_string(sRDomain, o->routing_domain);
#endif
	dump_cfg_string(sSshdSessionPath, o->sshd_session_path);
	dump_cfg_string(sSshdAuthPath, o->sshd_auth_path);
	dump_cfg_string(sPerSourcePenaltyExemptList, o->per_source_penalty_exempt);
	dump_cfg_string(sAgentSocketPath, o->agent_socket_path);

	/* string arguments requiring a lookup */
	dump_cfg_string(sLogLevel, log_level_name(o->log_level));
	dump_cfg_string(sSyslogFacility, log_facility_name(o->log_facility));

	/* string array arguments */
	dump_cfg_strarray_oneline(s_Authorized_कुञ्चिकाः_File, o->अङ्कः_authkeys_files,
	    o->authorized_कुञ्चिकाः_files);
	dump_cfg_strarray_oneline(s_Revoked_कुञ्चिकाः, o->अङ्कः_revoked_कुञ्चिकाः_files,
	    o->revoked_कुञ्चिकाः_files);
	dump_cfg_strarray(s_Host_कुञ्चिका, o->अङ्कः_host_कुञ्चिका_files, o->host_कुञ्चिका_files);
	dump_cfg_strarray(sHostCertificate, o->अङ्कः_host_cert_files,
	    o->host_cert_files);
	dump_cfg_strarray(sAllowUsers, o->अङ्कः_allow_users, o->allow_users);
	dump_cfg_strarray(sDenyUsers, o->अङ्कः_deny_users, o->deny_users);
	dump_cfg_strarray(sAllowGroups, o->अङ्कः_allow_groups, o->allow_groups);
	dump_cfg_strarray(sDenyGroups, o->अङ्कः_deny_groups, o->deny_groups);
	dump_cfg_strarray(sAcceptEnv, o->अङ्कः_accept_env, o->accept_env);
	dump_cfg_strarray(sSetEnv, o->अङ्कः_setenv, o->setenv);
	dump_cfg_strarray_oneline(sAuthenticationMethods,
	    o->अङ्कः_auth_methods, o->auth_methods);
	dump_cfg_strarray_oneline(sLogVerbose,
	    o->अङ्कः_log_verbose, o->log_verbose);
	dump_cfg_strarray_oneline(sChannelTimeout,
	    o->अङ्कः_channel_timeouts, o->channel_timeouts);

	/* other arguments */
	अत्थाय (i = 0; i < o->अङ्कः_subsystems; i++)
		printf("Subsystem %s %s\n", o->subsystem_name[i],
		    o->subsystem_args[i]);

	printf("MaxStartups %d:%d:%d\n", o->max_startups_begin,
	    o->max_startups_rate, o->max_startups);
	printf("PerSourceMaxStartups ");
	सचे (o->per_source_max_startups == INT_MAX)
		printf("none\n");
	अञ्ञथा
		printf("%d\n", o->per_source_max_startups);
	printf("PerSourceNetBlockSize %d:%d\n", o->per_source_masklen_ipv4,
	    o->per_source_masklen_ipv6);

	s = रिक्त;
	अत्थाय (i = 0; tunmode_desc[i].val != -1; i++) {
		सचे (tunmode_desc[i].val == o->permit_tun) {
			s = tunmode_desc[i].text;
			भङ्ग;
		}
	}
	dump_cfg_string(sPermitTunnel, s);

	printf("IPQoS %s ", iptos2str(o->ip_qos_interactive));
	printf("%s\n", iptos2str(o->ip_qos_bulk));

	printf("RekeyLimit %llu %d\n", (unsigned long long)o->rekey_limit,
	    o->rekey_interval);

	printf("PermitOpen");
	सचे (o->अङ्कः_permitted_opens == 0)
		printf(" any");
	अञ्ञथा {
		अत्थाय (i = 0; i < o->अङ्कः_permitted_opens; i++)
			printf(" %s", o->permitted_opens[i]);
	}
	printf("\n");
	printf("PermitListen");
	सचे (o->अङ्कः_permitted_listens == 0)
		printf(" any");
	अञ्ञथा {
		अत्थाय (i = 0; i < o->अङ्कः_permitted_listens; i++)
			printf(" %s", o->permitted_listens[i]);
	}
	printf("\n");

	सचे (o->permit_user_env_allowlist == रिक्त) {
		dump_cfg_fmtint(sPermitUserEnvironment, o->permit_user_env);
	} अञ्ञथा {
		printf("PermitUserEnvironment %s\n",
		    o->permit_user_env_allowlist);
	}

	printf("PubkeyAuthOptions");
	सचे (o->pubkey_auth_options == 0)
		printf(" none");
	सचे (o->pubkey_auth_options & PUBKEYAUTH_TOUCH_REQUIRED)
		printf(" touch-required");
	सचे (o->pubkey_auth_options & PUBKEYAUTH_VERIFY_REQUIRED)
		printf(" verify-required");
	सचे (o->max_pubkey_ok != -1)
		printf(" max-pk-ok:%d", o->max_pubkey_ok);
	printf("\n");

	सचे (o->per_source_penalty.enabled) {
		printf("PerSourcePenalties crash:%f authfail:%f noauth:%f "
		    "invaliduser:%f "
		    "grace-exceeded:%f refuseconnection:%f max:%f min:%f "
		    "max-sources4:%d max-sources6:%d "
		    "overflow:%s overflow6:%s\n",
		    o->per_source_penalty.penalty_crash,
		    o->per_source_penalty.penalty_authfail,
		    o->per_source_penalty.penalty_noauth,
		    o->per_source_penalty.penalty_invaliduser,
		    o->per_source_penalty.penalty_grace,
		    o->per_source_penalty.penalty_refuseconnection,
		    o->per_source_penalty.penalty_max,
		    o->per_source_penalty.penalty_min,
		    o->per_source_penalty.max_sources4,
		    o->per_source_penalty.max_sources6,
		    o->per_source_penalty.overflow_mode ==
		    PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL ?
		    "deny-all" : "permissive",
		    o->per_source_penalty.overflow_mode6 ==
		    PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL ?
		    "deny-all" : "permissive");
	} अञ्ञथा
		printf("PerSourcePenalties no\n");
}
