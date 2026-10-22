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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/socket.h>
#અન્તર્ભાવ <sys/queue.h>
#અન્તર્ભાવ <sys/stat.h>
#ifdef __OpenBSD__
#અન્તર્ભાવ <sys/sysctl.h>
#endif

#અન્તર્ભાવ <netinet/in.h>
#અન્તર્ભાવ <netinet/ip.h>
#ifdef HAVE_NET_ROUTE_H
#અન્તર્ભાવ <net/route.h>
#endif

#અન્તર્ભાવ <ctype.h>
#અન્તર્ભાવ <glob.h>
#અન્તર્ભાવ <netdb.h>
#અન્તર્ભાવ <pwd.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <limits.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <util.h>

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "ssh.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "servconf.h"
#અન્તર્ભાવ "pathnames.h"
#અન્તર્ભાવ "cipher.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "kex.h"
#અન્તર્ભાવ "mac.h"
#અન્તર્ભાવ "match.h"
#અન્તર્ભાવ "channels.h"
#અન્તર્ભાવ "groupaccess.h"
#અન્તર્ભાવ "canohost.h"
#અન્તર્ભાવ "packet.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "hostfile.h"
#અન્તર્ભાવ "auth.h"
#અન્તર્ભાવ "myproposal.h"
#અન્તર્ભાવ "digest.h"
#અન્તર્ભાવ "version.h"

#define SSHD_CONFIG_BLOB_VERSION	1

#જો !defined(SSHD_PAM_SERVICE)
# define SSHD_PAM_SERVICE		"sshd"
#endif

સ્થિર શૂન્ય add_listen_addr(ServerOptions *, અચલ અક્ષર *,
    અચલ અક્ષર *, પૂર્ણાંક);
સ્થિર શૂન્ય add_one_listen_addr(ServerOptions *, અચલ અક્ષર *,
    અચલ અક્ષર *, પૂર્ણાંક);
સ્થિર શૂન્ય parse_server_config_depth(ServerOptions *options,
    અચલ અક્ષર *filename, સંરચના sshbuf *conf, સંરચના include_list *includes,
    સંરચના connection_info *connectinfo, પૂર્ણાંક flags, પૂર્ણાંક *activep, પૂર્ણાંક depth);

બાહ્ય સંરચના sshbuf *cfg;

/* Initializes the server options to their default values. */

શૂન્ય
initialize_server_options(ServerOptions *options)
{
	memset(options, 0, કદ(*options));
#define SSHCONF_INT(var, conf, flags, ms, def, cp)	options->var = -1;
#define SSHCONF_INTFLAG(var, conf, flags, def, cp)	options->var = -1;
#define SSHCONF_STRING(var, conf, flags, cp)		options->var = ખાલી;
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	options->nvar = 0; \
	options->var = ખાલી;
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	init_##funcsuffix(options)
#define SSHCONF_NONCONF(funcsuffix) \
	init_##funcsuffix(options)
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	options->var = ખાલી;
#define SSHCONF_ALIAS(old, conf, flags)			/* empty */

	/* Using macros for these is a bit overkill but forces consistency */
#define init_hostkeyfile(options) \
	options->host_ચાવી_files = 0; \
	options->અંક_host_ચાવી_files = 0; \
	options->host_ચાવી_file_userprovided = ખાલી;
#define init_ipqos(options) \
	options->ip_qos_interactive = -1; \
	options->ip_qos_bulk = -1;
#define init_listenaddress(options) \
	options->queued_listen_addrs = ખાલી; \
	options->અંક_queued_listens = 0; \
	options->listen_addrs = ખાલી; \
	options->અંક_listen_addrs = 0;
#define init_logfacility(options) \
	options->log_facility = SYSLOG_FACILITY_NOT_SET;
#define init_loglevel(options) \
	options->log_level = SYSLOG_LEVEL_NOT_SET;
#define init_port(options) \
	options->અંક_ports = 0; \
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
	options->permit_user_env_allowlist = ખાલી;
#define init_persourcenetblocksize(options) \
	options->per_source_masklen_ipv4 = -1; \
	options->per_source_masklen_ipv6 = -1;
#define init_persourcepenalties(options) \
	options->per_source_penalty_exempt = ખાલી; \
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
	options->અંક_subsystems = 0; \
	options->subsystem_name = ખાલી; \
	options->subsystem_command = ખાલી; \
	options->subsystem_args = ખાલી;
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
સ્થિર પૂર્ણાંક
option_clear_or_none(અચલ અક્ષર *o)
{
	પાછા o == ખાલી || strcasecmp(o, "none") == 0;
}

સ્થિર શૂન્ય
assemble_algorithms(ServerOptions *o)
{
	અક્ષર *all_cipher, *all_mac, *all_kex, *all_ચાવી, *all_sig;
	અક્ષર *def_cipher, *def_mac, *def_kex, *def_ચાવી, *def_sig;
	પૂર્ણાંક r;

	all_cipher = cipher_alg_list(',', 0);
	all_mac = mac_alg_list(',');
	all_kex = kex_alg_list(',');
	all_ચાવી = sshkey_alg_list(0, 0, 1, ',');
	all_sig = sshkey_alg_list(0, 1, 1, ',');
	/* remove unsupported algos from default lists */
	def_cipher = match_filter_allowlist(KEX_SERVER_ENCRYPT, all_cipher);
	def_mac = match_filter_allowlist(KEX_SERVER_MAC, all_mac);
	def_kex = match_filter_allowlist(KEX_SERVER_KEX, all_kex);
	def_ચાવી = match_filter_allowlist(KEX_DEFAULT_PK_ALG, all_ચાવી);
	def_sig = match_filter_allowlist(SSH_ALLOWED_CA_SIGALGS, all_sig);
#define ASSEMBLE(what, defaults, all) \
	કરો { \
		જો ((r = kex_assemble_names(&o->what, defaults, all)) != 0) \
			fatal_fr(r, "%s", #what); \
	} જ્યારે (0)
	ASSEMBLE(ciphers, def_cipher, all_cipher);
	ASSEMBLE(macs, def_mac, all_mac);
	ASSEMBLE(kex_algorithms, def_kex, all_kex);
	ASSEMBLE(hostkeyalgorithms, def_ચાવી, all_ચાવી);
	ASSEMBLE(hostbased_accepted_algos, def_ચાવી, all_ચાવી);
	ASSEMBLE(pubkey_accepted_algos, def_ચાવી, all_ચાવી);
	ASSEMBLE(ca_sign_algorithms, def_sig, all_sig);
#undef ASSEMBLE
	મુક્ત(all_cipher);
	મુક્ત(all_mac);
	મુક્ત(all_kex);
	મુક્ત(all_ચાવી);
	મુક્ત(all_sig);
	મુક્ત(def_cipher);
	મુક્ત(def_mac);
	મુક્ત(def_kex);
	મુક્ત(def_ચાવી);
	મુક્ત(def_sig);
}

શૂન્ય
servconf_add_hostkey(અચલ અક્ષર *file, અચલ પૂર્ણાંક લીટી,
    ServerOptions *options, અચલ અક્ષર *path, પૂર્ણાંક userprovided)
{
	અક્ષર *apath = derelativise_path(path);

	opt_array_append2(file, લીટી, "HostKey",
	    &options->host_ચાવી_files, &options->host_ચાવી_file_userprovided,
	    &options->અંક_host_ચાવી_files, apath, userprovided);
	મુક્ત(apath);
}

શૂન્ય
servconf_add_hostcert(અચલ અક્ષર *file, અચલ પૂર્ણાંક લીટી,
    ServerOptions *options, અચલ અક્ષર *path)
{
	અક્ષર *apath = derelativise_path(path);

	opt_array_append(file, લીટી, "HostCertificate",
	    &options->host_cert_files, &options->અંક_host_cert_files, apath);
	મુક્ત(apath);
}

શૂન્ય
fill_default_server_options(ServerOptions *options)
{
	u_int i;

	/* Portable-specific overrides */
#ifdef SKIP_PRIVDROP
	જો (options->allow_streamlocal_forwarding != -1 &&
	    options->allow_streamlocal_forwarding != FORWARD_DENY)
		logit("StreamlocalForwarding is not supported on this system");
	options->allow_streamlocal_forwarding = 0;
	જો (options->fwd_opts.gateway_ports != -1 &&
	    options->fwd_opts.gateway_ports != 0)
		logit("GatewayPorts is not supported on this system");
	options->fwd_opts.gateway_ports = 0;
#endif

#define SSHCONF_INT(var, conf, flags, ms, def, cp) \
	જો (options->var == -1) \
		options->var = def;
#define SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	જો (options->var == -1) \
		options->var = def;
#define SSHCONF_STRING(var, conf, flags, cp)		/* done manually */
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	/* done manually */
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	/* done manually */
#define SSHCONF_NONCONF(funcsuffix)			/* done manually */
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	કરો { \
		મુક્ત(options->var); \
		options->var = ખાલી; \
	} જ્યારે (0);
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
	જો (options->pam_service_name == ખાલી)
		options->pam_service_name = xstrdup(SSHD_PAM_SERVICE);
#endif

	જો (options->અંક_host_ચાવી_files == 0) {
		/* fill default hostkeys */
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_RSA_ચાવી_FILE, 0);
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_ECDSA_ચાવી_FILE, 0);
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_ED25519_ચાવી_FILE, 0);
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_MLDSA44_ED25519_ચાવી_FILE, 0);
	}
	/* No certificates by default */
	જો (options->અંક_ports == 0)
		options->ports[options->અંક_ports++] = SSH_DEFAULT_PORT;
	જો (options->listen_addrs == ખાલી)
		add_listen_addr(options, ખાલી, ખાલી, 0);
	જો (options->pid_file == ખાલી)
		options->pid_file = xstrdup(_PATH_SSH_DAEMON_PID_FILE);
	જો (options->moduli_file == ખાલી)
		options->moduli_file = xstrdup(_PATH_DH_MODULI);
	જો (options->xauth_location == ખાલી)
		options->xauth_location = xstrdup(_PATH_XAUTH);
	જો (options->log_facility == SYSLOG_FACILITY_NOT_SET)
		options->log_facility = SYSLOG_FACILITY_AUTH;
	જો (options->log_level == SYSLOG_LEVEL_NOT_SET)
		options->log_level = SYSLOG_LEVEL_INFO;
	જો (options->permit_user_env == -1) {
		options->permit_user_env = 0;
		options->permit_user_env_allowlist = ખાલી;
	}
	જો (options->rekey_limit == -1)
		options->rekey_limit = 0;
	જો (options->rekey_interval == -1)
		options->rekey_interval = 0;
	જો (options->fwd_opts.gateway_ports == -1)
		options->fwd_opts.gateway_ports = 0;
	જો (options->max_startups == -1)
		options->max_startups = 100;
	જો (options->max_startups_rate == -1)
		options->max_startups_rate = 30;		/* 30% */
	જો (options->max_startups_begin == -1)
		options->max_startups_begin = 10;
	જો (options->per_source_masklen_ipv4 == -1)
		options->per_source_masklen_ipv4 = 32;
	જો (options->per_source_masklen_ipv6 == -1)
		options->per_source_masklen_ipv6 = 128;
	જો (options->per_source_penalty.enabled == -1)
		options->per_source_penalty.enabled = 1;
	જો (options->per_source_penalty.max_sources4 == -1)
		options->per_source_penalty.max_sources4 = 65536;
	જો (options->per_source_penalty.max_sources6 == -1)
		options->per_source_penalty.max_sources6 = 65536;
	જો (options->per_source_penalty.overflow_mode == -1)
		options->per_source_penalty.overflow_mode = PER_SOURCE_PENALTY_OVERFLOW_PERMISSIVE;
	જો (options->per_source_penalty.overflow_mode6 == -1)
		options->per_source_penalty.overflow_mode6 = options->per_source_penalty.overflow_mode;
	જો (options->per_source_penalty.penalty_crash < 0.0)
		options->per_source_penalty.penalty_crash = 90.0;
	જો (options->per_source_penalty.penalty_grace < 0.0)
		options->per_source_penalty.penalty_grace = 10.0;
	જો (options->per_source_penalty.penalty_authfail < 0.0)
		options->per_source_penalty.penalty_authfail = 5.0;
	જો (options->per_source_penalty.penalty_invaliduser < 0.0)
		options->per_source_penalty.penalty_invaliduser = 5.0;
	જો (options->per_source_penalty.penalty_noauth < 0.0)
		options->per_source_penalty.penalty_noauth = 1.0;
	જો (options->per_source_penalty.penalty_refuseconnection < 0.0)
		options->per_source_penalty.penalty_refuseconnection = 10.0;
	જો (options->per_source_penalty.penalty_min < 0.0)
		options->per_source_penalty.penalty_min = 15.0;
	જો (options->per_source_penalty.penalty_max < 0.0)
		options->per_source_penalty.penalty_max = 600.0;
	જો (options->અંક_authkeys_files == 0) {
		opt_array_append("[default]", 0, "AuthorizedKeysFiles",
		    &options->authorized_ચાવીઓ_files,
		    &options->અંક_authkeys_files,
		    PATH_SSH_USER_PERMITTED_ચાવીઓ);
		opt_array_append("[default]", 0, "AuthorizedKeysFiles",
		    &options->authorized_ચાવીઓ_files,
		    &options->અંક_authkeys_files,
		    _PATH_SSH_USER_PERMITTED_KEYS2);
	}
	જો (options->ip_qos_interactive == -1)
		options->ip_qos_interactive = IPTOS_DSCP_EF;
	જો (options->ip_qos_bulk == -1)
		options->ip_qos_bulk = IPTOS_DSCP_CS0;
	જો (options->version_addendum == ખાલી)
		options->version_addendum = xstrdup("");
	જો (options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
		options->fwd_opts.streamlocal_bind_mask = 0177;
	જો (options->fwd_opts.streamlocal_bind_unlink == -1)
		options->fwd_opts.streamlocal_bind_unlink = 0;
	જો (options->sk_provider == ખાલી)
		options->sk_provider = xstrdup("internal");
	જો (options->sshd_session_path == ખાલી)
		options->sshd_session_path = xstrdup(_PATH_SSHD_SESSION);
	જો (options->sshd_auth_path == ખાલી)
		options->sshd_auth_path = xstrdup(_PATH_SSHD_AUTH);
	જો (options->pubkey_auth_options == -1) {
		options->pubkey_auth_options = 0;
		options->max_pubkey_ok = DEFAULT_AUTH_FAIL_MAX;
	}
	જો (options->agent_socket_path == ખાલી)
		options->agent_socket_path = xstrdup(_PATH_SSH_AGENT_SOCKET_DIR);

	assemble_algorithms(options);

#define CLEAR_ON_NONE(v) \
	કરો { \
		જો (option_clear_or_none(v)) { \
			મુક્ત(v); \
			v = ખાલી; \
		} \
	} જ્યારે(0)
#define CLEAR_ON_NONE_ARRAY(v, nv, none) \
	કરો { \
		જો (options->nv == 1 && \
		    strcasecmp(options->v[0], none) == 0) { \
			મુક્ત(options->v[0]); \
			મુક્ત(options->v); \
			options->v = ખાલી; \
			options->nv = 0; \
		} \
	} જ્યારે (0)
	CLEAR_ON_NONE(options->pid_file);
	CLEAR_ON_NONE(options->xauth_location);
	CLEAR_ON_NONE(options->banner);
	CLEAR_ON_NONE(options->trusted_user_ca_ચાવીઓ);
	CLEAR_ON_NONE(options->sk_provider);
	CLEAR_ON_NONE(options->authorized_principals_file);
	CLEAR_ON_NONE(options->adm_forced_command);
	CLEAR_ON_NONE(options->chroot_directory);
	CLEAR_ON_NONE(options->routing_domain);
	CLEAR_ON_NONE(options->host_ચાવી_agent);
	CLEAR_ON_NONE(options->per_source_penalty_exempt);
	CLEAR_ON_NONE(options->agent_socket_path);

	માટે (i = 0; i < options->અંક_host_ચાવી_files; i++)
		CLEAR_ON_NONE(options->host_ચાવી_files[i]);
	માટે (i = 0; i < options->અંક_host_cert_files; i++)
		CLEAR_ON_NONE(options->host_cert_files[i]);

	CLEAR_ON_NONE_ARRAY(channel_timeouts, અંક_channel_timeouts, "none");
	CLEAR_ON_NONE_ARRAY(auth_methods, અંક_auth_methods, "any");
	CLEAR_ON_NONE_ARRAY(revoked_ચાવીઓ_files, અંક_revoked_ચાવીઓ_files, "none");
	CLEAR_ON_NONE_ARRAY(authorized_ચાવીઓ_files, અંક_authkeys_files, "none");
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
પ્રકારવ્યાખ્યા ગણના {
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
સ્થિર સંરચના {
	અચલ અક્ષર *name;
	ServerOpCodes opcode;
	u_int flags;
} keywords[] = {
	SSHD_CONFIG_ENTRIES
	{ "match", sMatch, SSHCFG_ALL },
	{ "include", sInclude, SSHCFG_ALL },
	{ ખાલી, sBadOption, 0 }
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

સ્થિર સંરચના {
	પૂર્ણાંક val;
	અક્ષર *text;
} tunmode_desc[] = {
	{ SSH_TUNMODE_NO, "no" },
	{ SSH_TUNMODE_POINTOPOINT, "point-to-point" },
	{ SSH_TUNMODE_ETHERNET, "ethernet" },
	{ SSH_TUNMODE_YES, "yes" },
	{ -1, ખાલી }
};

/* Returns an opcode name from its number */

સ્થિર અચલ અક્ષર *
lookup_opcode_name(ServerOpCodes code)
{
	u_int i;

	માટે (i = 0; keywords[i].name != ખાલી; i++)
		જો (keywords[i].opcode == code)
			પાછા(keywords[i].name);
	પાછા "UNKNOWN";
}


/*
 * Returns the number of the token pointed to by cp or sBadOption.
 */

સ્થિર ServerOpCodes
parse_token(અચલ અક્ષર *cp, અચલ અક્ષર *filename,
	    પૂર્ણાંક linenum, u_int *flags)
{
	u_int i;

	માટે (i = 0; keywords[i].name; i++)
		જો (strcasecmp(cp, keywords[i].name) == 0) {
			*flags = keywords[i].flags;
			પાછા keywords[i].opcode;
		}

	error("%s: line %d: Bad configuration option: %s",
	    filename, linenum, cp);
	પાછા sBadOption;
}

અક્ષર *
derelativise_path(અચલ અક્ષર *path)
{
	અક્ષર *expanded, *ret, cwd[PATH_MAX];

	જો (strcasecmp(path, "none") == 0)
		પાછા xstrdup("none");
	expanded = tilde_expand_filename(path, getuid());
	જો (path_absolute(expanded))
		પાછા expanded;
	જો (getcwd(cwd, કદ(cwd)) == ખાલી)
		fatal_f("getcwd: %s", strerror(errno));
	xasprintf(&ret, "%s/%s", cwd, expanded);
	મુક્ત(expanded);
	પાછા ret;
}

સ્થિર શૂન્ય
add_listen_addr(ServerOptions *options, અચલ અક્ષર *addr,
    અચલ અક્ષર *rdomain, પૂર્ણાંક port)
{
	u_int i;

	જો (port > 0)
		add_one_listen_addr(options, addr, rdomain, port);
	નહીંતર {
		માટે (i = 0; i < options->અંક_ports; i++) {
			add_one_listen_addr(options, addr, rdomain,
			    options->ports[i]);
		}
	}
}

સ્થિર શૂન્ય
add_one_listen_addr(ServerOptions *options, અચલ અક્ષર *addr,
    અચલ અક્ષર *rdomain, પૂર્ણાંક port)
{
	સંરચના addrinfo hints, *ai, *aitop;
	અક્ષર strport[NI_MAXSERV];
	પૂર્ણાંક gaierr;
	u_int i;

	/* Find listen_addrs entry for this rdomain */
	માટે (i = 0; i < options->અંક_listen_addrs; i++) {
		જો (rdomain == ખાલી && options->listen_addrs[i].rdomain == ખાલી)
			તોડો;
		જો (rdomain == ખાલી || options->listen_addrs[i].rdomain == ખાલી)
			ચાલુ;
		જો (strcmp(rdomain, options->listen_addrs[i].rdomain) == 0)
			તોડો;
	}
	જો (i >= options->અંક_listen_addrs) {
		/* No entry for this rdomain; allocate one */
		જો (i >= INT_MAX)
			fatal_f("too many listen addresses");
		options->listen_addrs = xrecallocarray(options->listen_addrs,
		    options->અંક_listen_addrs, options->અંક_listen_addrs + 1,
		    કદ(*options->listen_addrs));
		i = options->અંક_listen_addrs++;
		જો (rdomain != ખાલી)
			options->listen_addrs[i].rdomain = xstrdup(rdomain);
	}
	/* options->listen_addrs[i] points to the addresses for this rdomain */

	memset(&hints, 0, કદ(hints));
	hints.ai_family = options->address_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = (addr == ખાલી) ? AI_PASSIVE : 0;
	snprintf(strport, કદ strport, "%d", port);
	જો ((gaierr = getaddrinfo(addr, strport, &hints, &aitop)) != 0)
		fatal("bad addr or host: %s (%s)",
		    addr ? addr : "<NULL>",
		    ssh_gai_strerror(gaierr));
	માટે (ai = aitop; ai->ai_next; ai = ai->ai_next)
		;
	ai->ai_next = options->listen_addrs[i].addrs;
	options->listen_addrs[i].addrs = aitop;
}

/* Returns nonzero if the routing domain name is valid */
સ્થિર પૂર્ણાંક
valid_rdomain(અચલ અક્ષર *name)
{
#જો defined(HAVE_SYS_VALID_RDOMAIN)
	પાછા sys_valid_rdomain(name);
#અથવાજો defined(__OpenBSD__)
	અચલ અક્ષર *errstr;
	long long અંક;
	સંરચના rt_tableinfo info;
	પૂર્ણાંક mib[6];
	size_t miblen = કદ(mib);

	જો (name == ખાલી)
		પાછા 1;

	અંક = strtonum(name, 0, 255, &errstr);
	જો (errstr != ખાલી)
		પાછા 0;

	/* Check whether the table actually exists */
	memset(mib, 0, કદ(mib));
	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[4] = NET_RT_TABLE;
	mib[5] = (પૂર્ણાંક)અંક;
	જો (sysctl(mib, 6, &info, &miblen, ખાલી, 0) == -1)
		પાછા 0;

	પાછા 1;
#નહીંતર /* defined(__OpenBSD__) */
	error("Routing domains are not supported on this platform");
	પાછા 0;
#endif
}

/*
 * Queue a ListenAddress to be processed once we have all of the Ports
 * and AddressFamily options.
 */
સ્થિર શૂન્ય
queue_listen_addr(ServerOptions *options, અચલ અક્ષર *addr,
    અચલ અક્ષર *rdomain, પૂર્ણાંક port)
{
	સંરચના queued_listenaddr *qla;

	options->queued_listen_addrs = xrecallocarray(
	    options->queued_listen_addrs,
	    options->અંક_queued_listens, options->અંક_queued_listens + 1,
	    કદ(*options->queued_listen_addrs));
	qla = &options->queued_listen_addrs[options->અંક_queued_listens++];
	qla->addr = xstrdup(addr);
	qla->port = port;
	qla->rdomain = rdomain == ખાલી ? ખાલી : xstrdup(rdomain);
}

/*
 * Process queued (text) ListenAddress entries.
 */
સ્થિર શૂન્ય
process_queued_listen_addrs(ServerOptions *options)
{
	u_int i;
	સંરચના queued_listenaddr *qla;

	જો (options->અંક_ports == 0)
		options->ports[options->અંક_ports++] = SSH_DEFAULT_PORT;
	જો (options->address_family == -1)
		options->address_family = AF_UNSPEC;

	માટે (i = 0; i < options->અંક_queued_listens; i++) {
		qla = &options->queued_listen_addrs[i];
		add_listen_addr(options, qla->addr, qla->rdomain, qla->port);
		મુક્ત(qla->addr);
		મુક્ત(qla->rdomain);
	}
	મુક્ત(options->queued_listen_addrs);
	options->queued_listen_addrs = ખાલી;
	options->અંક_queued_listens = 0;
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

સ્થિર પૂર્ણાંક
match_cfg_લીટી_group(અચલ અક્ષર *grps, પૂર્ણાંક લીટી, અચલ અક્ષર *user)
{
	પૂર્ણાંક result = 0;
	સંરચના passwd *pw;

	જો (user == ખાલી)
		જાઓ out;

	જો ((pw = getpwnam(user)) == ખાલી) {
		debug("Can't match group at line %d because user %.100s does "
		    "not exist", લીટી, user);
	} નહીંતર જો (ga_init(pw->pw_name, pw->pw_gid) == 0) {
		debug("Can't Match group because user %.100s not in any group "
		    "at line %d", user, લીટી);
	} નહીંતર જો (ga_match_pattern_list(grps) != 1) {
		debug("user %.100s does not match group list %.100s at line %d",
		    user, grps, લીટી);
	} નહીંતર {
		debug("user %.100s matched group list %.100s at line %d", user,
		    grps, લીટી);
		result = 1;
	}
out:
	ga_free();
	પાછા result;
}

સ્થિર શૂન્ય
match_test_missing_fatal(અચલ અક્ષર *criteria, અચલ અક્ષર *attrib)
{
	fatal("'Match %s' in configuration but '%s' not in connection "
	    "test specification.", criteria, attrib);
}

/*
 * All of the attributes on a single Match line are ANDed together, so we need
 * to check every attribute and set the result to zero if any attribute does
 * not match.
 */
સ્થિર પૂર્ણાંક
match_cfg_લીટી(અચલ અક્ષર *full_લીટી, પૂર્ણાંક *acp, અક્ષર ***avp,
    પૂર્ણાંક લીટી, સંરચના connection_info *ci)
{
	પૂર્ણાંક result = 1, attributes = 0, port;
	અક્ષર *arg, *attrib = ખાલી, *oattrib;

	જો (ci == ખાલી) {
		debug3("checking syntax for 'Match %s' on line %d",
		    full_લીટી, લીટી);
	} નહીંતર {
		debug3("checking match for '%s' user %s%s host %s addr %s "
		    "laddr %s lport %d rdomain %s on line %d", full_લીટી,
		    ci->user ? ci->user : "(null)",
		    ci->user_invalid ? " (invalid)" : "",
		    ci->host ? ci->host : "(null)",
		    ci->address ? ci->address : "(null)",
		    ci->laddress ? ci->laddress : "(null)", ci->lport,
		    ci->rdomain ? ci->rdomain : "(null)", લીટી);
	}

	જ્યારે ((oattrib = argv_next(acp, avp)) != ખાલી) {
		/* Terminate on comment */
		જો (*oattrib == '#') {
			argv_consume(acp); /* mark all arguments consumed */
			તોડો;
		}
		attrib = xstrdup(oattrib);
		arg = ખાલી;
		attributes++;
		/* Criterion "all" has no argument and must appear alone */
		જો (strcasecmp(attrib, "all") == 0) {
			જો (attributes > 1 ||
			    ((arg = argv_next(acp, avp)) != ખાલી &&
			    *arg != '\0' && *arg != '#')) {
				error("'all' cannot be combined with other "
				    "Match attributes");
				result = -1;
				જાઓ out;
			}
			જો (arg != ખાલી && *arg == '#')
				argv_consume(acp); /* consume remaining args */
			result = 1;
			જાઓ out;
		}
		/* Criterion "invalid-user" also has no argument */
		જો (strcasecmp(attrib, "invalid-user") == 0) {
			જો (ci == ખાલી) {
				result = 0;
				જાઓ next;
			}
			જો (ci->user_invalid == 0)
				result = 0;
			નહીંતર
				debug("matched invalid-user at line %d", લીટી);
			જાઓ next;
		}

		/* Keep this list in sync with below */
		જો (strprefix(attrib, "user=", 1) != ખાલી ||
		    strprefix(attrib, "group=", 1) != ખાલી ||
		    strprefix(attrib, "host=", 1) != ખાલી ||
		    strprefix(attrib, "address=", 1) != ખાલી ||
		    strprefix(attrib, "localaddress=", 1) != ખાલી ||
		    strprefix(attrib, "localport=", 1) != ખાલી ||
		    strprefix(attrib, "rdomain=", 1) != ખાલી ||
		    strprefix(attrib, "version=", 1) != ખાલી) {
			arg = strchr(attrib, '=');
			*(arg++) = '\0';
		} નહીંતર {
			arg = argv_next(acp, avp);
		}

		/* All other criteria require an argument */
		જો (arg == ખાલી || *arg == '\0' || *arg == '#') {
			error("Missing Match criteria for %s", attrib);
			result = -1;
			જાઓ out;
		}
		જો (strcasecmp(attrib, "user") == 0) {
			જો (ci == ખાલી || (ci->test && ci->user == ખાલી)) {
				result = 0;
				જાઓ next;
			}
			જો (ci->user == ખાલી)
				match_test_missing_fatal("User", "user");
			જો (match_usergroup_pattern_list(ci->user, arg) != 1)
				result = 0;
			નહીંતર
				debug("user %.100s matched 'User %.100s' at "
				    "line %d", ci->user, arg, લીટી);
		} નહીંતર જો (strcasecmp(attrib, "group") == 0) {
			જો (ci == ખાલી || (ci->test && ci->user == ખાલી)) {
				result = 0;
				જાઓ next;
			}
			જો (ci->user == ખાલી)
				match_test_missing_fatal("Group", "user");
			પસંદગી (match_cfg_લીટી_group(arg, લીટી, ci->user)) {
			સ્થિતિ -1:
				result = -1;
				જાઓ out;
			સ્થિતિ 0:
				result = 0;
			}
		} નહીંતર જો (strcasecmp(attrib, "host") == 0) {
			જો (ci == ખાલી || (ci->test && ci->host == ખાલી)) {
				result = 0;
				જાઓ next;
			}
			જો (ci->host == ખાલી)
				match_test_missing_fatal("Host", "host");
			જો (match_hostname(ci->host, arg) != 1)
				result = 0;
			નહીંતર
				debug("connection from %.100s matched 'Host "
				    "%.100s' at line %d", ci->host, arg, લીટી);
		} નહીંતર જો (strcasecmp(attrib, "address") == 0) {
			જો (ci == ખાલી || (ci->test && ci->address == ખાલી)) {
				જો (addr_match_list(ખાલી, arg) != 0)
					fatal("Invalid Match address argument "
					    "'%s' at line %d", arg, લીટી);
				result = 0;
				જાઓ next;
			}
			જો (ci->address == ખાલી)
				match_test_missing_fatal("Address", "addr");
			પસંદગી (addr_match_list(ci->address, arg)) {
			સ્થિતિ 1:
				debug("connection from %.100s matched 'Address "
				    "%.100s' at line %d", ci->address, arg, લીટી);
				તોડો;
			સ્થિતિ 0:
			સ્થિતિ -1:
				result = 0;
				તોડો;
			સ્થિતિ -2:
				result = -1;
				જાઓ out;
			}
		} નહીંતર જો (strcasecmp(attrib, "localaddress") == 0){
			જો (ci == ખાલી || (ci->test && ci->laddress == ખાલી)) {
				જો (addr_match_list(ખાલી, arg) != 0)
					fatal("Invalid Match localaddress "
					    "argument '%s' at line %d", arg,
					    લીટી);
				result = 0;
				જાઓ next;
			}
			જો (ci->laddress == ખાલી)
				match_test_missing_fatal("LocalAddress",
				    "laddr");
			પસંદગી (addr_match_list(ci->laddress, arg)) {
			સ્થિતિ 1:
				debug("connection from %.100s matched "
				    "'LocalAddress %.100s' at line %d",
				    ci->laddress, arg, લીટી);
				તોડો;
			સ્થિતિ 0:
			સ્થિતિ -1:
				result = 0;
				તોડો;
			સ્થિતિ -2:
				result = -1;
				જાઓ out;
			}
		} નહીંતર જો (strcasecmp(attrib, "localport") == 0) {
			જો ((port = a2port(arg)) == -1) {
				error("Invalid LocalPort '%s' on Match line",
				    arg);
				result = -1;
				જાઓ out;
			}
			જો (ci == ખાલી || (ci->test && ci->lport == -1)) {
				result = 0;
				જાઓ next;
			}
			જો (ci->lport == 0)
				match_test_missing_fatal("LocalPort", "lport");
			/* TODO support port lists */
			જો (port == ci->lport)
				debug("connection from %.100s matched "
				    "'LocalPort %d' at line %d",
				    ci->laddress, port, લીટી);
			નહીંતર
				result = 0;
		} નહીંતર જો (strcasecmp(attrib, "rdomain") == 0) {
			જો (ci == ખાલી || (ci->test && ci->rdomain == ખાલી)) {
				result = 0;
				જાઓ next;
			}
			જો (ci->rdomain == ખાલી)
				match_test_missing_fatal("RDomain", "rdomain");
			જો (match_pattern_list(ci->rdomain, arg, 0) != 1)
				result = 0;
			નહીંતર
				debug("connection RDomain %.100s matched "
				    "'RDomain %.100s' at line %d",
				    ci->rdomain, arg, લીટી);
		} નહીંતર જો (strcasecmp(attrib, "version") == 0) {
			જો (match_pattern_list(SSH_RELEASE, arg, 0) != 1)
				result = 0;
			નહીંતર
				debug("version %.100s matched "
				    "'version %.100s' at line %d",
				    SSH_RELEASE, arg, લીટી);
		} નહીંતર {
			error("Unsupported Match attribute %s", oattrib);
			result = -1;
			જાઓ out;
		}
 next:
		મુક્ત(attrib);
		attrib = ખાલી;
	}
	જો (attributes == 0) {
		error("One or more attributes required for Match");
		પાછા -1;
	}
 out:
	જો (ci != ખાલી && result != -1)
		debug3("match %sfound on line %d", result ? "" : "not ", લીટી);
	મુક્ત(attrib);
	પાછા result;
}

#define WHITESPACE " \t\r\n"

/* Multistate option parsing */
સંરચના multistate {
	અક્ષર *ચાવી;
	પૂર્ણાંક કિંમત;
};
સ્થિર અચલ સંરચના multistate multistate_flag[] = {
	{ "yes",			1 },
	{ "no",				0 },
	{ ખાલી, -1 }
};
સ્થિર અચલ સંરચના multistate multistate_ignore_rhosts[] = {
	{ "yes",			IGNORE_RHOSTS_YES },
	{ "no",				IGNORE_RHOSTS_NO },
	{ "shosts-only",		IGNORE_RHOSTS_SHOSTS },
	{ ખાલી, -1 }
};
સ્થિર અચલ સંરચના multistate multistate_addressfamily[] = {
	{ "inet",			AF_INET },
	{ "inet6",			AF_INET6 },
	{ "any",			AF_UNSPEC },
	{ ખાલી, -1 }
};
સ્થિર અચલ સંરચના multistate multistate_permitrootlogin[] = {
	{ "prohibit-password",		PERMIT_NO_PASSWD },
	{ "without-password",		PERMIT_NO_PASSWD },
	{ "forced-commands-only",	PERMIT_FORCED_ONLY },
	{ "yes",			PERMIT_YES },
	{ "no",				PERMIT_NO },
	{ ખાલી, -1 }
};
સ્થિર અચલ સંરચના multistate multistate_compression[] = {
#ifdef WITH_ZLIB
	{ "yes",			COMP_DELAYED },
	{ "delayed",			COMP_DELAYED },
#endif
	{ "no",				COMP_NONE },
	{ ખાલી, -1 }
};
સ્થિર અચલ સંરચના multistate multistate_gatewayports[] = {
	{ "clientspecified",		2 },
	{ "yes",			1 },
	{ "no",				0 },
	{ ખાલી, -1 }
};
સ્થિર અચલ સંરચના multistate multistate_tcpfwd[] = {
	{ "yes",			FORWARD_ALLOW },
	{ "all",			FORWARD_ALLOW },
	{ "no",				FORWARD_DENY },
	{ "remote",			FORWARD_REMOTE },
	{ "local",			FORWARD_LOCAL },
	{ ખાલી, -1 }
};
સ્થિર અચલ સંરચના multistate multistate_keepalives[] = {
	{ "true",			SSH_KEEPALIVES_TRANSPORT },
	{ "false",			SSH_KEEPALIVES_OFF },
	{ "yes",			SSH_KEEPALIVES_TRANSPORT },
	{ "no",				SSH_KEEPALIVES_OFF },
	{ "transport",			SSH_KEEPALIVES_TRANSPORT },
	{ "all",			SSH_KEEPALIVES_ALL },
	{ ખાલી, -1 }
};
સ્થિર અચલ સંરચના multistate multistate_warnweakcrypto[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "no-pq-kex",			0 },
	{ ખાલી, -1 }
};

સ્થિર પૂર્ણાંક
process_server_config_લીટી_depth(ServerOptions *options, અક્ષર *લીટી,
    અચલ અક્ષર *filename, પૂર્ણાંક linenum, પૂર્ણાંક *activep,
    સંરચના connection_info *connectinfo, પૂર્ણાંક *inc_flags, પૂર્ણાંક depth,
    સંરચના include_list *includes)
{
	અક્ષર *str, ***chararrayptr, **charptr, *arg, *arg2, *p, *keyword;
	પૂર્ણાંક cmdline = 0, *intptr, કિંમત, value2, value3, n, port, oactive, r;
	દ્વિગુણ dvalue, *doubleptr = ખાલી;
	પૂર્ણાંક ca_only = 0, found = 0;
	SyslogFacility *log_facility_ptr;
	LogLevel *log_level_ptr;
	ServerOpCodes opcode;
	u_int i, *uintptr, flags = 0;
	size_t len;
	long long val64;
	અચલ સંરચના multistate *multistate_ptr;
	અચલ અક્ષર *errstr;
	સંરચના include_item *item;
	glob_t gbuf;
	અક્ષર **oav = ખાલી, **av;
	પૂર્ણાંક oac = 0, ac;
	પૂર્ણાંક ret = -1;
	અક્ષર **strs = ખાલી; /* string array arguments; freed implicitly */
	u_int nstrs = 0;

	/* Strip trailing whitespace. Allow \f (form feed) at EOL only */
	જો ((len = strlen(લીટી)) == 0)
		પાછા 0;
	માટે (len--; len > 0; len--) {
		જો (strchr(WHITESPACE "\f", લીટી[len]) == ખાલી)
			તોડો;
		લીટી[len] = '\0';
	}

	str = લીટી;
	જો ((keyword = strdelim(&str)) == ખાલી)
		પાછા 0;
	/* Ignore leading whitespace */
	જો (*keyword == '\0')
		keyword = strdelim(&str);
	જો (!keyword || !*keyword || *keyword == '#')
		પાછા 0;
	જો (str == ખાલી || *str == '\0') {
		error("%s line %d: no argument after keyword \"%s\"",
		    filename, linenum, keyword);
		પાછા -1;
	}
	intptr = ખાલી;
	charptr = ખાલી;
	opcode = parse_token(keyword, filename, linenum, &flags);

	જો (argv_split(str, &oac, &oav, 1) != 0) {
		error("%s line %d: invalid quotes", filename, linenum);
		પાછા -1;
	}
	ac = oac;
	av = oav;

	જો (activep == ખાલી) { /* We are processing a command line directive */
		cmdline = 1;
		activep = &cmdline;
	}
	જો (*activep && opcode != sMatch && opcode != sInclude)
		debug3("%s:%d setting %s %s", filename, linenum, keyword, str);
	જો (*activep == 0 && !(flags & SSHCFG_MATCH)) {
		જો (connectinfo == ખાલી) {
			fatal("%s line %d: Directive '%s' is not allowed "
			    "within a Match block", filename, linenum, keyword);
		} નહીંતર { /* this is a directive we have already processed */
			ret = 0;
			જાઓ out;
		}
	}

	પસંદગી (opcode) {
	/* Portable-specific options */
#ifdef USE_PAM
	સ્થિતિ sUsePAM:
		intptr = &options->use_pam;
		જાઓ parse_flag;
	સ્થિતિ sPAMServiceName:
		charptr = &options->pam_service_name;
		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0') {
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		}
		જો (*activep && *charptr == ખાલી)
			*charptr = xstrdup(arg);
		તોડો;
#endif

	/* Standard Options */
	સ્થિતિ sBadOption:
		જાઓ out;
	સ્થિતિ sPort:
		/* ignore ports from configfile if cmdline specifies ports */
		જો (options->ports_from_cmdline) {
			argv_consume(&ac);
			તોડો;
		}
		જો (options->અંક_ports >= MAX_PORTS)
			fatal("%s line %d: too many ports.",
			    filename, linenum);
		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0')
			fatal("%s line %d: missing port number.",
			    filename, linenum);
		options->ports[options->અંક_ports++] = a2port(arg);
		જો (options->ports[options->અંક_ports-1] <= 0)
			fatal("%s line %d: Badly formatted port number.",
			    filename, linenum);
		તોડો;

	સ્થિતિ sLoginGraceTime:
		intptr = &options->login_grace_time;
 parse_time:
		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0')
			fatal("%s line %d: missing time value.",
			    filename, linenum);
		જો ((કિંમત = convtime(arg)) == -1)
			fatal("%s line %d: invalid time value.",
			    filename, linenum);
		જો (*activep && *intptr == -1)
			*intptr = કિંમત;
		તોડો;

	સ્થિતિ sListenAddress:
		arg = argv_next(&ac, &av);
		જો (arg == ખાલી || *arg == '\0')
			fatal("%s line %d: missing address",
			    filename, linenum);
		/* check for bare IPv6 address: no "[]" and 2 or more ":" */
		જો (strchr(arg, '[') == ખાલી && (p = strchr(arg, ':')) != ખાલી
		    && strchr(p+1, ':') != ખાલી) {
			port = 0;
			p = arg;
		} નહીંતર {
			arg2 = ખાલી;
			p = hpdelim(&arg);
			જો (p == ખાલી)
				fatal("%s line %d: bad address:port usage",
				    filename, linenum);
			p = cleanhostname(p);
			જો (arg == ખાલી)
				port = 0;
			નહીંતર જો ((port = a2port(arg)) <= 0)
				fatal("%s line %d: bad port number",
				    filename, linenum);
		}
		/* Optional routing table */
		arg2 = ખાલી;
		જો ((arg = argv_next(&ac, &av)) != ખાલી) {
			જો (strcmp(arg, "rdomain") != 0 ||
			    (arg2 = argv_next(&ac, &av)) == ખાલી)
				fatal("%s line %d: bad ListenAddress syntax",
				    filename, linenum);
			જો (!valid_rdomain(arg2))
				fatal("%s line %d: bad routing domain",
				    filename, linenum);
		}
		queue_listen_addr(options, p, arg2, port);

		તોડો;

	સ્થિતિ sAddressFamily:
		intptr = &options->address_family;
		multistate_ptr = multistate_addressfamily;
 parse_multistate:
		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0')
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		કિંમત = -1;
		માટે (i = 0; multistate_ptr[i].ચાવી != ખાલી; i++) {
			જો (strcasecmp(arg, multistate_ptr[i].ચાવી) == 0) {
				કિંમત = multistate_ptr[i].કિંમત;
				તોડો;
			}
		}
		જો (કિંમત == -1)
			fatal("%s line %d: unsupported option \"%s\".",
			    filename, linenum, arg);
		જો (*activep && *intptr == -1)
			*intptr = કિંમત;
		તોડો;

	સ્થિતિ s_Host_ચાવી:
		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		જો (*activep) {
			servconf_add_hostkey(filename, linenum,
			    options, arg, 1);
		}
		તોડો;

	સ્થિતિ s_Host_ચાવી_Agent:
		charptr = &options->host_ચાવી_agent;
		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0')
			fatal("%s line %d: missing socket name.",
			    filename, linenum);
		જો (*activep && *charptr == ખાલી)
			*charptr = !strcmp(arg, SSH_AUTHSOCKET_ENV_NAME) ?
			    xstrdup(arg) : derelativise_path(arg);
		તોડો;

	સ્થિતિ sHostCertificate:
		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		જો (*activep)
			servconf_add_hostcert(filename, linenum, options, arg);
		તોડો;

	સ્થિતિ sPidFile:
		charptr = &options->pid_file;
 parse_filename:
		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		જો (*activep && *charptr == ખાલી) {
			*charptr = derelativise_path(arg);
			/* increase optional counter */
			જો (intptr != ખાલી)
				*intptr = *intptr + 1;
		}
		તોડો;

	સ્થિતિ sModuliFile:
		charptr = &options->moduli_file;
		જાઓ parse_filename;

	સ્થિતિ s_Permit_મૂળ_Login:
		intptr = &options->permit_મૂળ_login;
		multistate_ptr = multistate_permitrootlogin;
		જાઓ parse_multistate;

	સ્થિતિ sIgnoreRhosts:
		intptr = &options->ignore_rhosts;
		multistate_ptr = multistate_ignore_rhosts;
		જાઓ parse_multistate;

	સ્થિતિ sIgnoreUserKnownHosts:
		intptr = &options->ignore_user_known_hosts;
 parse_flag:
		multistate_ptr = multistate_flag;
		જાઓ parse_multistate;

	સ્થિતિ sHostbasedAuthentication:
		intptr = &options->hostbased_authentication;
		જાઓ parse_flag;

	સ્થિતિ sHostbasedUsesNameFromPacketOnly:
		intptr = &options->hostbased_uses_name_from_packet_only;
		જાઓ parse_flag;

	સ્થિતિ sHostbasedAcceptedAlgorithms:
		charptr = &options->hostbased_accepted_algos;
		ca_only = 0;
 parse_pubkey_algos:
		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0')
			fatal("%s line %d: Missing argument.",
			    filename, linenum);
		જો (*arg != '-' &&
		    !sshkey_names_valid2(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg, 1, ca_only))
			fatal("%s line %d: Bad key types '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		જો (*activep && *charptr == ખાલી)
			*charptr = xstrdup(arg);
		તોડો;

	સ્થિતિ s_Host_ચાવી_Algorithms:
		charptr = &options->hostkeyalgorithms;
		ca_only = 0;
		જાઓ parse_pubkey_algos;

	સ્થિતિ sCASignatureAlgorithms:
		charptr = &options->ca_sign_algorithms;
		ca_only = 1;
		જાઓ parse_pubkey_algos;

	સ્થિતિ sPubkeyAuthentication:
		intptr = &options->pubkey_authentication;
		ca_only = 0;
		જાઓ parse_flag;

	સ્થિતિ sPubkeyAcceptedAlgorithms:
		charptr = &options->pubkey_accepted_algos;
		ca_only = 0;
		જાઓ parse_pubkey_algos;

	સ્થિતિ sPubkeyAuthOptions:
		intptr = &options->pubkey_auth_options;
		કિંમત = 0;
		value2 = -1;
		જ્યારે ((arg = argv_next(&ac, &av)) != ખાલી) {
			જો (strcasecmp(arg, "none") == 0)
				ચાલુ;
			જો (strcasecmp(arg, "touch-required") == 0)
				કિંમત |= PUBKEYAUTH_TOUCH_REQUIRED;
			નહીંતર જો (strcasecmp(arg, "verify-required") == 0)
				કિંમત |= PUBKEYAUTH_VERIFY_REQUIRED;
			નહીંતર જો (strncasecmp(arg, "max-pk-ok:", 10) == 0) {
				value2 = strtonum(arg + 10, 0, 255, &errstr);
				જો (errstr != ખાલી) {
					error("%s line %d: bad %s max-pk-ok "
					    "value: %s", filename, linenum,
					keyword, errstr);
					જાઓ out;
				}
			} નહીંતર {
				error("%s line %d: unsupported %s option %s",
				    filename, linenum, keyword, arg);
				જાઓ out;
			}
		}
		જો (*activep && options->pubkey_auth_options == -1) {
			options->pubkey_auth_options = કિંમત;
			options->max_pubkey_ok = value2;
		}
		તોડો;

#ifdef KRB5
	સ્થિતિ sKerberosAuthentication:
		intptr = &options->kerberos_authentication;
		જાઓ parse_flag;

	સ્થિતિ sKerberosOrLocalPasswd:
		intptr = &options->kerberos_or_local_passwd;
		જાઓ parse_flag;

	સ્થિતિ sKerberosTicketCleanup:
		intptr = &options->kerberos_ticket_cleanup;
		જાઓ parse_flag;
#ifdef USE_AFS
	સ્થિતિ sKerberosGetAFSToken:
		intptr = &options->kerberos_get_afs_token;
		જાઓ parse_flag;
#endif /* USE_AFS */
#endif /* KRB5 */

#ifdef GSSAPI
	સ્થિતિ sGSSAPIAuthentication:
		intptr = &options->gss_authentication;
		જાઓ parse_flag;

	સ્થિતિ sGSSAPICleanupCredentials:
		intptr = &options->gss_cleanup_creds;
		જાઓ parse_flag;

	સ્થિતિ sGSSAPIDelegateCredentials:
		intptr = &options->gss_deleg_creds;
		જાઓ parse_flag;

	સ્થિતિ sGSSAPIStrictAcceptorCheck:
		intptr = &options->gss_strict_acceptor;
		જાઓ parse_flag;
#endif /* GSSAPI */

	સ્થિતિ sPasswordAuthentication:
		intptr = &options->password_authentication;
		જાઓ parse_flag;

	સ્થિતિ sKbdInteractiveAuthentication:
		intptr = &options->kbd_interactive_authentication;
		જાઓ parse_flag;

	સ્થિતિ sPrintMotd:
		intptr = &options->print_motd;
		જાઓ parse_flag;

#ifndef DISABLE_LASTLOG
	સ્થિતિ sPrintLastLog:
		intptr = &options->print_lastlog;
		જાઓ parse_flag;
#endif

	સ્થિતિ sX11Forwarding:
		intptr = &options->x11_forwarding;
		જાઓ parse_flag;

	સ્થિતિ sX11DisplayOffset:
		intptr = &options->x11_display_offset;
 parse_int:
		arg = argv_next(&ac, &av);
		જો ((errstr = atoi_err(arg, &કિંમત)) != ખાલી)
			fatal("%s line %d: %s integer value %s.",
			    filename, linenum, keyword, errstr);
		જો (*activep && *intptr == -1)
			*intptr = કિંમત;
		તોડો;

	સ્થિતિ sX11UseLocalhost:
		intptr = &options->x11_use_localhost;
		જાઓ parse_flag;

	સ્થિતિ sXAuthLocation:
		charptr = &options->xauth_location;
		જાઓ parse_filename;

	સ્થિતિ sPermitTTY:
		intptr = &options->permit_tty;
		જાઓ parse_flag;

	સ્થિતિ sPermitUserRC:
		intptr = &options->permit_user_rc;
		જાઓ parse_flag;

	સ્થિતિ sStrictModes:
		intptr = &options->strict_modes;
		જાઓ parse_flag;

	સ્થિતિ sTCPKeepAlive:
		intptr = &options->tcp_keep_alive;
		multistate_ptr = multistate_keepalives;
		જાઓ parse_multistate;

	સ્થિતિ sPermitEmptyPasswords:
		intptr = &options->permit_empty_passwd;
		જાઓ parse_flag;

	સ્થિતિ sPermitUserEnvironment:
		intptr = &options->permit_user_env;
		charptr = &options->permit_user_env_allowlist;
		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		કિંમત = 0;
		p = ખાલી;
		જો (strcmp(arg, "yes") == 0)
			કિંમત = 1;
		નહીંતર જો (strcmp(arg, "no") == 0)
			કિંમત = 0;
		નહીંતર {
			/* Pattern-list specified */
			કિંમત = 1;
			p = xstrdup(arg);
		}
		જો (*activep && *intptr == -1) {
			*intptr = કિંમત;
			*charptr = p;
			p = ખાલી;
		}
		મુક્ત(p);
		તોડો;

	સ્થિતિ sCompression:
		intptr = &options->compression;
		multistate_ptr = multistate_compression;
		જાઓ parse_multistate;

	સ્થિતિ sRekeyLimit:
		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		જો (strcmp(arg, "default") == 0) {
			val64 = 0;
		} નહીંતર {
			જો (scan_scaled(arg, &val64) == -1)
				fatal("%.200s line %d: Bad %s number '%s': %s",
				    filename, linenum, keyword,
				    arg, strerror(errno));
			જો (val64 != 0 && val64 < 16)
				fatal("%.200s line %d: %s too small",
				    filename, linenum, keyword);
		}
		જો (*activep && options->rekey_limit == -1)
			options->rekey_limit = val64;
		જો (ac != 0) { /* optional rekey interval present */
			જો (strcmp(av[0], "none") == 0) {
				(શૂન્ય)argv_next(&ac, &av);	/* discard */
				તોડો;
			}
			intptr = &options->rekey_interval;
			જાઓ parse_time;
		}
		તોડો;

	સ્થિતિ sGatewayPorts:
		intptr = &options->fwd_opts.gateway_ports;
		multistate_ptr = multistate_gatewayports;
		જાઓ parse_multistate;

	સ્થિતિ sUseDNS:
		intptr = &options->use_dns;
		જાઓ parse_flag;

	સ્થિતિ sSyslogFacility:
		log_facility_ptr = &options->log_facility;
		arg = argv_next(&ac, &av);
		કિંમત = log_facility_સંખ્યા(arg);
		જો (કિંમત == SYSLOG_FACILITY_NOT_SET)
			fatal("%.200s line %d: unsupported log facility '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
		જો (*log_facility_ptr == -1)
			*log_facility_ptr = (SyslogFacility) કિંમત;
		તોડો;

	સ્થિતિ sLogLevel:
		log_level_ptr = &options->log_level;
		arg = argv_next(&ac, &av);
		કિંમત = log_level_સંખ્યા(arg);
		જો (કિંમત == SYSLOG_LEVEL_NOT_SET)
			fatal("%.200s line %d: unsupported log level '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
		જો (*activep && *log_level_ptr == -1)
			*log_level_ptr = (LogLevel) કિંમત;
		તોડો;

	સ્થિતિ sLogVerbose:
		found = options->અંક_log_verbose == 0;
		જ્યારે ((arg = argv_next(&ac, &av)) != ખાલી) {
			જો (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				જાઓ out;
			}
			/* Allow "none" only in first position */
			જો (strcasecmp(arg, "none") == 0) {
				જો (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					જાઓ out;
				}
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		જો (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		જો (found && *activep) {
			options->log_verbose = strs;
			options->અંક_log_verbose = nstrs;
			strs = ખાલી; /* transferred */
			nstrs = 0;
		}
		તોડો;

	સ્થિતિ sAllowTcpForwarding:
		intptr = &options->allow_tcp_forwarding;
		multistate_ptr = multistate_tcpfwd;
		જાઓ parse_multistate;

	સ્થિતિ sAllowStreamLocalForwarding:
		intptr = &options->allow_streamlocal_forwarding;
		multistate_ptr = multistate_tcpfwd;
		જાઓ parse_multistate;

	સ્થિતિ sAllowAgentForwarding:
		intptr = &options->allow_agent_forwarding;
		જાઓ parse_flag;

	સ્થિતિ sAgentSocketPath:
		charptr = &options->agent_socket_path;
		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0')
			fatal("%s line %d: missing path.", filename, linenum);
		જો (strncmp(arg, "shared:", 7) == 0) {
			/* Shared paths must be absolute */
			જો (arg[7] != '/') {
				fatal("%s line %d: invalid shared path.",
				    filename, linenum);
			}
		} નહીંતર જો (strncmp(arg, "user:", 5) == 0) {
			/* User paths must not be empty */
			જો (arg[5] == '\0') {
				fatal("%s line %d: invalid user path.",
				    filename, linenum);
			}
		} નહીંતર જો (strcmp(arg, "none") != 0)
			fatal("%s line %d: invalid path.", filename, linenum);
		જો (*activep && *charptr == ખાલી)
			*charptr = xstrdup(arg);
		તોડો;

	સ્થિતિ sDisableForwarding:
		intptr = &options->disable_forwarding;
		જાઓ parse_flag;

	સ્થિતિ sAllowUsers:
		chararrayptr = &options->allow_users;
		uintptr = &options->અંક_allow_users;
 parse_allowdenyusers:
		/* XXX appends to list; doesn't respect first-match-wins */
		જ્યારે ((arg = argv_next(&ac, &av)) != ખાલી) {
			જો (*arg == '\0' ||
			    match_user(ખાલી, ખાલી, ખાલી, arg) == -1)
				fatal("%s line %d: invalid %s pattern: \"%s\"",
				    filename, linenum, keyword, arg);
			found = 1;
			જો (!*activep)
				ચાલુ;
			opt_array_append(filename, linenum, keyword,
			    chararrayptr, uintptr, arg);
		}
		જો (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		તોડો;

	સ્થિતિ sDenyUsers:
		chararrayptr = &options->deny_users;
		uintptr = &options->અંક_deny_users;
		જાઓ parse_allowdenyusers;

	સ્થિતિ sAllowGroups:
		chararrayptr = &options->allow_groups;
		uintptr = &options->અંક_allow_groups;
		/* XXX appends to list; doesn't respect first-match-wins */
 parse_allowdenygroups:
		જ્યારે ((arg = argv_next(&ac, &av)) != ખાલી) {
			જો (*arg == '\0')
				fatal("%s line %d: empty %s pattern",
				    filename, linenum, keyword);
			found = 1;
			જો (!*activep)
				ચાલુ;
			opt_array_append(filename, linenum, keyword,
			    chararrayptr, uintptr, arg);
		}
		જો (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		તોડો;

	સ્થિતિ sDenyGroups:
		chararrayptr = &options->deny_groups;
		uintptr = &options->અંક_deny_groups;
		જાઓ parse_allowdenygroups;

	સ્થિતિ sCiphers:
		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		જો (*arg != '-' &&
		    !ciphers_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 cipher spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		જો (options->ciphers == ખાલી)
			options->ciphers = xstrdup(arg);
		તોડો;

	સ્થિતિ sMacs:
		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		જો (*arg != '-' &&
		    !mac_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 mac spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		જો (options->macs == ખાલી)
			options->macs = xstrdup(arg);
		તોડો;

	સ્થિતિ sKexAlgorithms:
		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		જો (*arg != '-' &&
		    !kex_names_valid(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 KexAlgorithms '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		જો (options->kex_algorithms == ખાલી)
			options->kex_algorithms = xstrdup(arg);
		તોડો;

	સ્થિતિ sSubsystem:
		જો ((arg = argv_next(&ac, &av)) == ખાલી || *arg == '\0' ||
		   ((arg2 = argv_next(&ac, &av)) == ખાલી || *arg2 == '\0'))
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		જો (!*activep) {
			argv_consume(&ac);
			તોડો;
		}
		found = 0;
		માટે (i = 0; i < options->અંક_subsystems; i++) {
			જો (strcmp(arg, options->subsystem_name[i]) == 0) {
				found = 1;
				તોડો;
			}
		}
		જો (found) {
			debug("%s line %d: Subsystem '%s' already defined.",
			    filename, linenum, arg);
			argv_consume(&ac);
			તોડો;
		}
		options->subsystem_name = xrecallocarray(
		    options->subsystem_name, options->અંક_subsystems,
		    options->અંક_subsystems + 1,
		    કદ(*options->subsystem_name));
		options->subsystem_command = xrecallocarray(
		    options->subsystem_command, options->અંક_subsystems,
		    options->અંક_subsystems + 1,
		    કદ(*options->subsystem_command));
		options->subsystem_args = xrecallocarray(
		    options->subsystem_args, options->અંક_subsystems,
		    options->અંક_subsystems + 1,
		    કદ(*options->subsystem_args));
		options->subsystem_name[options->અંક_subsystems] = xstrdup(arg);
		options->subsystem_command[options->અંક_subsystems] =
		    xstrdup(arg2);
		/* Collect arguments (separate to executable) */
		arg = argv_assemble(1, &arg2); /* quote command correctly */
		arg2 = argv_assemble(ac, av); /* rest of command */
		xasprintf(&options->subsystem_args[options->અંક_subsystems],
		    "%s%s%s", arg, *arg2 == '\0' ? "" : " ", arg2);
		મુક્ત(arg2);
		મુક્ત(arg);
		argv_consume(&ac);
		options->અંક_subsystems++;
		તોડો;

	સ્થિતિ sMaxStartups:
		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		/* begin:rate:max */
		જો ((n = sscanf(arg, "%d:%d:%d",
		    &કિંમત, &value2, &value3)) == 3) {
			જો (કિંમત > value3 || value2 > 100 || value2 < 1)
				fatal("%s line %d: Invalid %s spec.",
				    filename, linenum, keyword);
		} નહીંતર જો (n == 1) {
			value3 = કિંમત;
			value2 = -1;
		} નહીંતર {
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		}
		જો (કિંમત <= 0 || value3 <= 0)
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		જો (*activep && options->max_startups == -1) {
			options->max_startups_begin = કિંમત;
			options->max_startups_rate = value2;
			options->max_startups = value3;
		}
		તોડો;

	સ્થિતિ sPerSourceNetBlockSize:
		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		પસંદગી (n = sscanf(arg, "%d:%d", &કિંમત, &value2)) {
		સ્થિતિ 2:
			જો (value2 < 0 || value2 > 128)
				n = -1;
			/* FALLTHROUGH */
		સ્થિતિ 1:
			જો (કિંમત < 0 || કિંમત > 32)
				n = -1;
		}
		જો (n != 1 && n != 2)
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		જો (*activep && options->per_source_masklen_ipv4 == -1) {
			options->per_source_masklen_ipv4 = કિંમત;
			જો (n == 2)
				options->per_source_masklen_ipv6 = value2;
		}
		તોડો;

	સ્થિતિ sPerSourceMaxStartups:
		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		જો (strcmp(arg, "none") == 0) { /* no limit */
			કિંમત = INT_MAX;
		} નહીંતર {
			જો ((errstr = atoi_err(arg, &કિંમત)) != ખાલી)
				fatal("%s line %d: %s integer value %s.",
				    filename, linenum, keyword, errstr);
		}
		જો (*activep && options->per_source_max_startups == -1)
			options->per_source_max_startups = કિંમત;
		તોડો;

	સ્થિતિ sPerSourcePenaltyExemptList:
		charptr = &options->per_source_penalty_exempt;
		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0')
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		જો (addr_match_list(ખાલી, arg) != 0) {
			fatal("%s line %d: keyword %s "
			    "invalid address argument.",
			    filename, linenum, keyword);
		}
		જો (*activep && *charptr == ખાલી)
			*charptr = xstrdup(arg);
		તોડો;

	સ્થિતિ sPerSourcePenalties:
		જ્યારે ((arg = argv_next(&ac, &av)) != ખાલી) {
			અચલ અક્ષર *q = ખાલી;

			found = 1;
			intptr = ખાલી;
			doubleptr = ખાલી;
			કિંમત = -1;
			value2 = 0;
			/* Allow no/yes only in first position */
			જો (strcasecmp(arg, "no") == 0 ||
			    (value2 = (strcasecmp(arg, "yes") == 0))) {
				જો (ac > 0) {
					fatal("%s line %d: keyword %s \"%s\" "
					    "argument must appear alone.",
					    filename, linenum, keyword, arg);
				}
				જો (*activep &&
				    options->per_source_penalty.enabled == -1)
					options->per_source_penalty.enabled = value2;
				ચાલુ;
			} નહીંતર જો ((q = strprefix(arg, "crash:", 0)) != ખાલી) {
				doubleptr = &options->per_source_penalty.penalty_crash;
			} નહીંતર જો ((q = strprefix(arg, "authfail:", 0)) != ખાલી) {
				doubleptr = &options->per_source_penalty.penalty_authfail;
			} નહીંતર જો ((q = strprefix(arg, "invaliduser:", 0)) != ખાલી) {
				doubleptr = &options->per_source_penalty.penalty_invaliduser;
			} નહીંતર જો ((q = strprefix(arg, "noauth:", 0)) != ખાલી) {
				doubleptr = &options->per_source_penalty.penalty_noauth;
			} નહીંતર જો ((q = strprefix(arg, "grace-exceeded:", 0)) != ખાલી) {
				doubleptr = &options->per_source_penalty.penalty_grace;
			} નહીંતર જો ((q = strprefix(arg, "refuseconnection:", 0)) != ખાલી) {
				doubleptr = &options->per_source_penalty.penalty_refuseconnection;
			} નહીંતર જો ((q = strprefix(arg, "max:", 0)) != ખાલી) {
				doubleptr = &options->per_source_penalty.penalty_max;
			} નહીંતર જો ((q = strprefix(arg, "min:", 0)) != ખાલી) {
				doubleptr = &options->per_source_penalty.penalty_min;
			} નહીંતર જો ((q = strprefix(arg, "max-sources4:", 0)) != ખાલી) {
				intptr = &options->per_source_penalty.max_sources4;
				જો ((errstr = atoi_err(q, &કિંમત)) != ખાલી)
					fatal("%s line %d: %s value %s.",
					    filename, linenum, keyword, errstr);
			} નહીંતર જો ((q = strprefix(arg, "max-sources6:", 0)) != ખાલી) {
				intptr = &options->per_source_penalty.max_sources6;
				જો ((errstr = atoi_err(q, &કિંમત)) != ખાલી)
					fatal("%s line %d: %s value %s.",
					    filename, linenum, keyword, errstr);
			} નહીંતર જો (strcmp(arg, "overflow:deny-all") == 0) {
				intptr = &options->per_source_penalty.overflow_mode;
				કિંમત = PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL;
			} નહીંતર જો (strcmp(arg, "overflow:permissive") == 0) {
				intptr = &options->per_source_penalty.overflow_mode;
				કિંમત = PER_SOURCE_PENALTY_OVERFLOW_PERMISSIVE;
			} નહીંતર જો (strcmp(arg, "overflow6:deny-all") == 0) {
				intptr = &options->per_source_penalty.overflow_mode6;
				કિંમત = PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL;
			} નહીંતર જો (strcmp(arg, "overflow6:permissive") == 0) {
				intptr = &options->per_source_penalty.overflow_mode6;
				કિંમત = PER_SOURCE_PENALTY_OVERFLOW_PERMISSIVE;
			} નહીંતર {
				fatal("%s line %d: unsupported %s keyword %s",
				    filename, linenum, keyword, arg);
			}

			જો (doubleptr != ખાલી) {
				જો ((dvalue = convtime_double(q)) < 0) {
					fatal("%s line %d: invalid %s time value.",
					    filename, linenum, keyword);
				}
				જો (*activep && *doubleptr < 0.0) {
					*doubleptr = dvalue;
					options->per_source_penalty.enabled = 1;
				}
			} નહીંતર જો (intptr != ખાલી) {
				જો (*activep && *intptr == -1) {
					*intptr = કિંમત;
					options->per_source_penalty.enabled = 1;
				}
			} નહીંતર {
				fatal_f("%s line %d: internal error",
				    filename, linenum);
			}
		}
		જો (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		તોડો;

	સ્થિતિ sMaxAuthTries:
		intptr = &options->max_authtries;
		જાઓ parse_int;

	સ્થિતિ sMaxSessions:
		intptr = &options->max_sessions;
		જાઓ parse_int;

	સ્થિતિ sBanner:
		charptr = &options->banner;
		જાઓ parse_filename;

	/*
	 * These options can contain %X options expanded at
	 * connect time, so that you can specify paths like:
	 *
	 * AuthorizedKeysFile	/etc/ssh_keys/%u
	 */
	સ્થિતિ s_Authorized_ચાવીઓ_File:
		uintptr = &options->અંક_authkeys_files;
		chararrayptr = &options->authorized_ચાવીઓ_files;
 parse_filenames:
		found = *uintptr == 0;
		જ્યારે ((arg = argv_next(&ac, &av)) != ખાલી) {
			જો (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				જાઓ out;
			}
			/* Allow "none" only in first position */
			જો (strcasecmp(arg, "none") == 0) {
				જો (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					જાઓ out;
				}
			}
			arg2 = tilde_expand_filename(arg, getuid());
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg2);
			મુક્ત(arg2);
		}
		જો (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		જો (found && *activep) {
			*chararrayptr = strs;
			*uintptr = nstrs;
			strs = ખાલી; /* transferred */
			nstrs = 0;
		}
		તોડો;

	સ્થિતિ sAuthorizedPrincipalsFile:
		charptr = &options->authorized_principals_file;
		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		જો (*activep && *charptr == ખાલી) {
			*charptr = tilde_expand_filename(arg, getuid());
			/* increase optional counter */
			જો (intptr != ખાલી)
				*intptr = *intptr + 1;
		}
		તોડો;

	સ્થિતિ sClientAliveInterval:
		intptr = &options->client_alive_interval;
		જાઓ parse_time;

	સ્થિતિ s_Client_Alive_ગણતરી_Max:
		intptr = &options->client_alive_ગણતરી_max;
		જાઓ parse_int;

	સ્થિતિ sAcceptEnv:
		/* XXX appends to list; doesn't respect first-match-wins */
		જ્યારે ((arg = argv_next(&ac, &av)) != ખાલી) {
			જો (*arg == '\0' || strchr(arg, '=') != ખાલી)
				fatal("%s line %d: Invalid environment name.",
				    filename, linenum);
			found = 1;
			જો (!*activep)
				ચાલુ;
			opt_array_append(filename, linenum, keyword,
			    &options->accept_env, &options->અંક_accept_env,
			    arg);
		}
		જો (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		તોડો;

	સ્થિતિ sSetEnv:
		found = options->અંક_setenv == 0;
		જ્યારે ((arg = argv_next(&ac, &av)) != ખાલી) {
			જો (*arg == '\0' || strchr(arg, '=') == ખાલી)
				fatal("%s line %d: Invalid environment.",
				    filename, linenum);
			જો (lookup_setenv_in_list(arg, strs, nstrs) != ખાલી) {
				debug2("%s line %d: ignoring duplicate env "
				    "name \"%.64s\"", filename, linenum, arg);
				ચાલુ;
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		જો (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		જો (found && *activep) {
			options->setenv = strs;
			options->અંક_setenv = nstrs;
			strs = ખાલી; /* transferred */
			nstrs = 0;
		}
		તોડો;

	સ્થિતિ sPermitTunnel:
		intptr = &options->permit_tun;
		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		કિંમત = -1;
		માટે (i = 0; tunmode_desc[i].val != -1; i++)
			જો (strcmp(tunmode_desc[i].text, arg) == 0) {
				કિંમત = tunmode_desc[i].val;
				તોડો;
			}
		જો (કિંમત == -1)
			fatal("%s line %d: bad %s argument %s",
			    filename, linenum, keyword, arg);
		જો (*activep && *intptr == -1)
			*intptr = કિંમત;
		તોડો;

	સ્થિતિ sInclude:
		જો (cmdline) {
			fatal("Include directive not supported as a "
			    "command-line option");
		}
		કિંમત = 0;
		જ્યારે ((arg2 = argv_next(&ac, &av)) != ખાલી) {
			જો (*arg2 == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				જાઓ out;
			}
			કિંમત++;
			found = 0;
			જો (*arg2 != '/' && *arg2 != '~') {
				xasprintf(&arg, "%s/%s", SSHDIR, arg2);
			} નહીંતર
				arg = xstrdup(arg2);

			/*
			 * Don't let included files clobber the containing
			 * file's Match state.
			 */
			oactive = *activep;

			/* consult cache of include files */
			TAILQ_FOREACH(item, includes, entry) {
				જો (strcmp(item->selector, arg) != 0)
					ચાલુ;
				જો (item->filename != ખાલી) {
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
			જો (found != 0) {
				મુક્ત(arg);
				ચાલુ;
			}

			/* requested glob was not in cache */
			debug2("%s line %d: new include %s",
			    filename, linenum, arg);
			જો ((r = glob(arg, 0, ખાલી, &gbuf)) != 0) {
				જો (r != GLOB_NOMATCH) {
					fatal("%s line %d: include \"%s\" glob "
					    "failed", filename, linenum, arg);
				}
				/*
				 * If no entry matched then record a
				 * placeholder to skip later glob calls.
				 */
				debug2("%s line %d: no match for %s",
				    filename, linenum, arg);
				item = xcalloc(1, કદ(*item));
				item->selector = xstrdup(arg);
				TAILQ_INSERT_TAIL(includes,
				    item, entry);
			}
			જો (gbuf.gl_pathc > INT_MAX)
				fatal_f("too many glob results");
			માટે (n = 0; n < (પૂર્ણાંક)gbuf.gl_pathc; n++) {
				debug2("%s line %d: including %s",
				    filename, linenum, gbuf.gl_pathv[n]);
				item = xcalloc(1, કદ(*item));
				item->selector = xstrdup(arg);
				item->filename = xstrdup(gbuf.gl_pathv[n]);
				જો ((item->contents = sshbuf_new()) == ખાલી)
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
			મુક્ત(arg);
		}
		જો (કિંમત == 0) {
			fatal("%s line %d: %s missing filename argument",
			    filename, linenum, keyword);
		}
		તોડો;

	સ્થિતિ sMatch:
		જો (cmdline)
			fatal("Match directive not supported as a command-line "
			    "option");
		કિંમત = match_cfg_લીટી(str, &ac, &av, linenum,
		    (*inc_flags & SSHCFG_NEVERMATCH ? ખાલી : connectinfo));
		જો (કિંમત < 0)
			fatal("%s line %d: Bad Match condition", filename,
			    linenum);
		*activep = (*inc_flags & SSHCFG_NEVERMATCH) ? 0 : કિંમત;
		/*
		 * The MATCH_ONLY flag is applicable only until the first
		 * match block.
		 */
		*inc_flags &= ~SSHCFG_MATCH_ONLY;
		તોડો;

	સ્થિતિ sPermitListen:
	સ્થિતિ sPermitOpen:
		જો (opcode == sPermitListen) {
			uintptr = &options->અંક_permitted_listens;
			chararrayptr = &options->permitted_listens;
		} નહીંતર {
			uintptr = &options->અંક_permitted_opens;
			chararrayptr = &options->permitted_opens;
		}
		found = *uintptr == 0;
		જ્યારે ((arg = argv_next(&ac, &av)) != ખાલી) {
			જો (strcmp(arg, "any") == 0 ||
			    strcmp(arg, "none") == 0) {
				જો (nstrs != 0) {
					fatal("%s line %d: %s must appear "
					    "alone on a %s line.",
					    filename, linenum, arg, keyword);
				}
				opt_array_append(filename, linenum, keyword,
				    &strs, &nstrs, arg);
				ચાલુ;
			}

			જો (opcode == sPermitListen &&
			    strchr(arg, ':') == ખાલી) {
				/*
				 * Allow bare port number for PermitListen
				 * to indicate a wildcard listen host.
				 */
				xasprintf(&arg2, "*:%s", arg);
			} નહીંતર {
				arg2 = xstrdup(arg);
				p = hpdelim(&arg);
				જો (p == ખાલી) {
					fatal("%s line %d: %s missing host",
					    filename, linenum, keyword);
				}
				p = cleanhostname(p);
			}
			જો (arg == ખાલી ||
			    ((port = permitopen_port(arg)) < 0)) {
				fatal("%s line %d: %s bad port number",
				    filename, linenum, keyword);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg2);
			મુક્ત(arg2);
		}
		જો (nstrs == 0) {
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		}
		જો (found && *activep) {
			*chararrayptr = strs;
			*uintptr = nstrs;
			strs = ખાલી; /* transferred */
			nstrs = 0;
		}
		તોડો;

	સ્થિતિ sForceCommand:
		જો (str == ખાલી || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		જો (*activep && options->adm_forced_command == ખાલી)
			options->adm_forced_command = xstrdup(str + len);
		argv_consume(&ac);
		તોડો;

	સ્થિતિ sChrootDirectory:
		charptr = &options->chroot_directory;

		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		જો (*activep && *charptr == ખાલી)
			*charptr = xstrdup(arg);
		તોડો;

	સ્થિતિ sTrustedUserCAKeys:
		charptr = &options->trusted_user_ca_ચાવીઓ;
		જાઓ parse_filename;

	સ્થિતિ s_Revoked_ચાવીઓ:
		uintptr = &options->અંક_revoked_ચાવીઓ_files;
		chararrayptr = &options->revoked_ચાવીઓ_files;
		જાઓ parse_filenames;

	સ્થિતિ s_Security_ચાવી_Provider:
		charptr = &options->sk_provider;
		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		જો (*activep && *charptr == ખાલી) {
			*charptr = strcasecmp(arg, "internal") == 0 ?
			    xstrdup(arg) : derelativise_path(arg);
			/* increase optional counter */
			જો (intptr != ખાલી)
				*intptr = *intptr + 1;
		}
		તોડો;

	સ્થિતિ sIPQoS:
		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		જો ((કિંમત = parse_ipqos(arg)) == -1)
			fatal("%s line %d: Bad %s value: %s",
			    filename, linenum, keyword, arg);
		જો (કિંમત == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			કિંમત = INT_MAX;
		}
		arg = argv_next(&ac, &av);
		જો (arg == ખાલી)
			value2 = કિંમત;
		નહીંતર જો ((value2 = parse_ipqos(arg)) == -1)
			fatal("%s line %d: Bad %s value: %s",
			    filename, linenum, keyword, arg);
		જો (value2 == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			value2 = INT_MAX;
		}
		જો (*activep && options->ip_qos_interactive == -1) {
			options->ip_qos_interactive = કિંમત;
			options->ip_qos_bulk = value2;
		}
		તોડો;

	સ્થિતિ sVersionAddendum:
		જો (str == ખાલી || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		જો (strchr(str + len, '\r') != ખાલી) {
			fatal("%.200s line %d: Invalid %s argument",
			    filename, linenum, keyword);
		}
		જો ((arg = strchr(લીટી, '#')) != ખાલી) {
			*arg = '\0';
			rtrim(લીટી);
		}
		જો (*activep && options->version_addendum == ખાલી) {
			જો (strcasecmp(str + len, "none") == 0)
				options->version_addendum = xstrdup("");
			નહીંતર
				options->version_addendum = xstrdup(str + len);
		}
		argv_consume(&ac);
		તોડો;

	સ્થિતિ s_Authorized_ચાવીઓ_Command:
		charptr = &options->authorized_ચાવીઓ_command;
 parse_command:
		len = strspn(str, WHITESPACE);
		જો (str[len] != '/' && strcasecmp(str + len, "none") != 0) {
			fatal("%.200s line %d: %s must be an absolute path",
			    filename, linenum, keyword);
		}
		જો (*activep && *charptr == ખાલી)
			*charptr = xstrdup(str + len);
		argv_consume(&ac);
		તોડો;

	સ્થિતિ s_Authorized_ચાવીઓ_Command_User:
		charptr = &options->authorized_ચાવીઓ_command_user;
 parse_localuser:
		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0') {
			fatal("%s line %d: missing %s argument.",
			    filename, linenum, keyword);
		}
		જો (*activep && *charptr == ખાલી)
			*charptr = xstrdup(arg);
		તોડો;

	સ્થિતિ sAuthorizedPrincipalsCommand:
		charptr = &options->authorized_principals_command;
		જાઓ parse_command;

	સ્થિતિ sAuthorizedPrincipalsCommandUser:
		charptr = &options->authorized_principals_command_user;
		જાઓ parse_localuser;

	સ્થિતિ sAuthenticationMethods:
		found = options->અંક_auth_methods == 0;
		કિંમત = 0; /* seen "any" pseudo-method */
		જ્યારે ((arg = argv_next(&ac, &av)) != ખાલી) {
			જો (strcmp(arg, "any") == 0) {
				જો (nstrs > 0) {
					fatal("%s line %d: \"any\" must "
					    "appear alone in %s",
					    filename, linenum, keyword);
				}
				કિંમત = 1;
			} નહીંતર જો (કિંમત) {
				fatal("%s line %d: \"any\" must appear "
				    "alone in %s", filename, linenum, keyword);
			} નહીંતર જો (auth2_methods_valid(arg, 0) != 0) {
				fatal("%s line %d: invalid %s method list.",
				    filename, linenum, keyword);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		જો (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		જો (found && *activep) {
			options->auth_methods = strs;
			options->અંક_auth_methods = nstrs;
			strs = ખાલી; /* transferred */
			nstrs = 0;
		}
		તોડો;

	સ્થિતિ sStreamLocalBindMask:
		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		/* Parse mode in octal format */
		કિંમત = strtol(arg, &p, 8);
		જો (arg == p || કિંમત < 0 || કિંમત > 0777)
			fatal("%s line %d: Invalid %s.",
			    filename, linenum, keyword);
		જો (*activep &&
		    options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
			options->fwd_opts.streamlocal_bind_mask = (mode_t)કિંમત;
		તોડો;

	સ્થિતિ sStreamLocalBindUnlink:
		intptr = &options->fwd_opts.streamlocal_bind_unlink;
		જાઓ parse_flag;

	સ્થિતિ sFingerprintHash:
		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		જો ((કિંમત = ssh_digest_alg_by_name(arg)) == -1)
			fatal("%.200s line %d: Invalid %s algorithm \"%s\".",
			    filename, linenum, keyword, arg);
		જો (*activep)
			options->fingerprint_hash = કિંમત;
		તોડો;

	સ્થિતિ sExposeAuthInfo:
		intptr = &options->expose_userauth_info;
		જાઓ parse_flag;

	સ્થિતિ sRDomain:
#જો !defined(__OpenBSD__) && !defined(HAVE_SYS_SET_PROCESS_RDOMAIN)
		fatal("%s line %d: setting RDomain not supported on this "
		    "platform.", filename, linenum);
#endif
		charptr = &options->routing_domain;
		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		જો (strcasecmp(arg, "none") != 0 && strcmp(arg, "%D") != 0 &&
		    !valid_rdomain(arg))
			fatal("%s line %d: invalid routing domain",
			    filename, linenum);
		જો (*activep && *charptr == ખાલી)
			*charptr = xstrdup(arg);
		તોડો;

	સ્થિતિ sRequiredRSASize:
		intptr = &options->required_rsa_size;
		જાઓ parse_int;

	સ્થિતિ sChannelTimeout:
		found = options->અંક_channel_timeouts == 0;
		જ્યારે ((arg = argv_next(&ac, &av)) != ખાલી) {
			/* Allow "none" only in first position */
			જો (strcasecmp(arg, "none") == 0) {
				જો (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					જાઓ out;
				}
			} નહીંતર જો (parse_pattern_interval(arg,
			    ખાલી, ખાલી) != 0) {
				fatal("%s line %d: invalid channel timeout %s",
				    filename, linenum, arg);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		જો (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		જો (found && *activep) {
			options->channel_timeouts = strs;
			options->અંક_channel_timeouts = nstrs;
			strs = ખાલી; /* transferred */
			nstrs = 0;
		}
		તોડો;

	સ્થિતિ sUnusedConnectionTimeout:
		intptr = &options->unused_connection_timeout;
		/* peek at first arg for "none" so we can reuse parse_time */
		જો (av[0] != ખાલી && strcasecmp(av[0], "none") == 0) {
			(શૂન્ય)argv_next(&ac, &av); /* consume arg */
			જો (*activep)
				*intptr = 0;
			તોડો;
		}
		જાઓ parse_time;

	સ્થિતિ sSshdSessionPath:
		charptr = &options->sshd_session_path;
		જાઓ parse_filename;

	સ્થિતિ sSshdAuthPath:
		charptr = &options->sshd_auth_path;
		જાઓ parse_filename;

	સ્થિતિ sRefuseConnection:
		intptr = &options->refuse_connection;
		multistate_ptr = multistate_flag;
		જાઓ parse_multistate;

	સ્થિતિ sWarnWeakCrypto:
		intptr = &options->warn_weak_crypto;
		multistate_ptr = multistate_warnweakcrypto;
		જાઓ parse_multistate;

	સ્થિતિ sDeprecated:
	સ્થિતિ sIgnore:
	સ્થિતિ sUnsupported:
		do_log2(opcode == sIgnore ?
		    SYSLOG_LEVEL_DEBUG2 : SYSLOG_LEVEL_INFO,
		    "%s line %d: %s option %s", filename, linenum,
		    opcode == sUnsupported ? "Unsupported" : "Deprecated",
		    keyword);
		argv_consume(&ac);
		તોડો;

	મૂળભૂત:
		fatal("%s line %d: Missing handler for opcode %s (%d)",
		    filename, linenum, keyword, opcode);
	}
	/* Check that there is no garbage at end of line. */
	જો (ac > 0) {
		error("%.200s line %d: keyword %s extra arguments "
		    "at end of line", filename, linenum, keyword);
		જાઓ out;
	}

	/* success */
	ret = 0;
 out:
	opt_array_free2(strs, ખાલી, nstrs);
	argv_free(oav, oac);
	પાછા ret;
}

પૂર્ણાંક
process_server_config_લીટી(ServerOptions *options, અક્ષર *લીટી,
    અચલ અક્ષર *filename, પૂર્ણાંક linenum, પૂર્ણાંક *activep,
    સંરચના connection_info *connectinfo, સંરચના include_list *includes)
{
	પૂર્ણાંક inc_flags = 0;

	પાછા process_server_config_લીટી_depth(options, લીટી, filename,
	    linenum, activep, connectinfo, &inc_flags, 0, includes);
}


/* Reads the server configuration file. */

શૂન્ય
load_server_config(અચલ અક્ષર *filename, સંરચના sshbuf *conf)
{
	સંરચના stat st;
	અક્ષર *લીટી = ખાલી, *cp;
	size_t linesize = 0;
	FILE *f;
	પૂર્ણાંક r;

	debug2_f("filename %s", filename);
	જો ((f = fopen(filename, "r")) == ખાલી) {
		perror(filename);
		exit(1);
	}
	sshbuf_reset(conf);
	/* grow buffer, so realloc is avoided for large config files */
	જો (fstat(fileno(f), &st) == 0 && st.st_size > 0 &&
	    (r = sshbuf_allocate(conf, st.st_size)) != 0)
		fatal_fr(r, "allocate");
	જ્યારે (getline(&લીટી, &linesize, f) != -1) {
		/*
		 * Strip whitespace
		 * NB - preserve newlines, they are needed to reproduce
		 * line numbers later for error messages
		 */
		cp = લીટી + strspn(લીટી, " \t\r");
		જો ((r = sshbuf_put(conf, cp, strlen(cp))) != 0)
			fatal_fr(r, "sshbuf_put");
	}
	મુક્ત(લીટી);
	જો ((r = sshbuf_put_u8(conf, 0)) != 0)
		fatal_fr(r, "sshbuf_put_u8");
	fclose(f);
	debug2_f("done config len = %zu", sshbuf_len(conf));
}

શૂન્ય
parse_server_match_config(ServerOptions *options,
   સંરચના include_list *includes, સંરચના connection_info *connectinfo)
{
	ServerOptions mo;

	initialize_server_options(&mo);
	parse_server_config(&mo, "reprocess config", cfg, includes,
	    connectinfo, 0);
	copy_set_server_options(options, &mo, 0);
	free_server_options(&mo);
}

પૂર્ણાંક
parse_server_match_testspec(સંરચના connection_info *ci, અક્ષર *spec)
{
	અક્ષર *p;
	અચલ અક્ષર *val;

	જ્યારે ((p = strsep(&spec, ",")) && *p != '\0') {
		જો ((val = strprefix(p, "addr=", 0)) != ખાલી) {
			ci->address = xstrdup(val);
		} નહીંતર જો ((val = strprefix(p, "host=", 0)) != ખાલી) {
			ci->host = xstrdup(val);
		} નહીંતર જો ((val = strprefix(p, "user=", 0)) != ખાલી) {
			ci->user = xstrdup(val);
		} નહીંતર જો ((val = strprefix(p, "laddr=", 0)) != ખાલી) {
			ci->laddress = xstrdup(val);
		} નહીંતર જો ((val = strprefix(p, "rdomain=", 0)) != ખાલી) {
			ci->rdomain = xstrdup(val);
		} નહીંતર જો ((val = strprefix(p, "lport=", 0)) != ખાલી) {
			ci->lport = a2port(val);
			જો (ci->lport == -1) {
				fprintf(stderr, "Invalid port '%s' in test mode"
				    " specification %s\n", p+6, p);
				પાછા -1;
			}
		} નહીંતર જો (strcmp(p, "invalid-user") == 0) {
			ci->user_invalid = 1;
		} નહીંતર {
			fprintf(stderr, "Invalid test mode specification %s\n",
			    p);
			પાછા -1;
		}
	}
	પાછા 0;
}

શૂન્ય
servconf_merge_subsystems(ServerOptions *dst, ServerOptions *src)
{
	u_int i, j, found;

	માટે (i = 0; i < src->અંક_subsystems; i++) {
		found = 0;
		માટે (j = 0; j < dst->અંક_subsystems; j++) {
			જો (strcmp(src->subsystem_name[i],
			    dst->subsystem_name[j]) == 0) {
				found = 1;
				તોડો;
			}
		}
		જો (found) {
			debug_f("override \"%s\"", dst->subsystem_name[j]);
			મુક્ત(dst->subsystem_command[j]);
			મુક્ત(dst->subsystem_args[j]);
			dst->subsystem_command[j] =
			    xstrdup(src->subsystem_command[i]);
			dst->subsystem_args[j] =
			    xstrdup(src->subsystem_args[i]);
			ચાલુ;
		}
		debug_f("add \"%s\"", src->subsystem_name[i]);
		dst->subsystem_name = xrecallocarray(
		    dst->subsystem_name, dst->અંક_subsystems,
		    dst->અંક_subsystems + 1, કદ(*dst->subsystem_name));
		dst->subsystem_command = xrecallocarray(
		    dst->subsystem_command, dst->અંક_subsystems,
		    dst->અંક_subsystems + 1, કદ(*dst->subsystem_command));
		dst->subsystem_args = xrecallocarray(
		    dst->subsystem_args, dst->અંક_subsystems,
		    dst->અંક_subsystems + 1, કદ(*dst->subsystem_args));
		j = dst->અંક_subsystems++;
		dst->subsystem_name[j] = xstrdup(src->subsystem_name[i]);
		dst->subsystem_command[j] = xstrdup(src->subsystem_command[i]);
		dst->subsystem_args[j] = xstrdup(src->subsystem_args[i]);
	}
}

સ્થિર પૂર્ણાંક
serialise_s32(સંરચના sshbuf *buf, પૂર્ણાંક v)
{
	uint32_t uv;
	પૂર્ણાંક r;

	uv = v < 0 ? (uint32_t)(-(v + 1)) + 1 : (uint32_t)v;
	જો ((r = sshbuf_put_u8(buf, v < 0)) != 0 ||
	    (r = sshbuf_put_u32(buf, uv)) != 0)
		પાછા r;
	પાછા 0;
}

સ્થિર પૂર્ણાંક
serialise_s64(સંરચના sshbuf *buf, int64_t v)
{
	uint64_t uv;
	પૂર્ણાંક r;

	uv = v < 0 ? (uint64_t)(-(v + 1)) + 1 : (uint64_t)v;
	જો ((r = sshbuf_put_u8(buf, v < 0)) != 0 ||
	    (r = sshbuf_put_u64(buf, uv)) != 0)
		પાછા r;
	પાછા 0;
}

સ્થિર પૂર્ણાંક
serialise_mode(સંરચના sshbuf *buf, mode_t v)
{
	u_int uv;

	જો (v == (mode_t)-1)
		પાછા serialise_s32(buf, -1);
	uv = (u_int)v;
	જો ((mode_t)uv != v || uv > 0777)
		પાછા SSH_ERR_INVALID_FORMAT;
	પાછા serialise_s32(buf, (પૂર્ણાંક)uv);
}

સ્થિર પૂર્ણાંક
serialise_double(સંરચના sshbuf *buf, દ્વિગુણ v)
{
	/*
	 * XXX this is no good for a wire encoding.
	 * It's fine for passing configurations via RPC, but it would
	 * be nicer to have an exact binary encoding here.
	 */
	પાછા sshbuf_put(buf, &v, કદ(v));
}

સ્થિર પૂર્ણાંક
serialise_nullable_string(સંરચના sshbuf *buf, અચલ અક્ષર *s)
{
	પૂર્ણાંક r;

	જો ((r = sshbuf_put_u8(buf, s != ખાલી)) != 0)
		પાછા r;
	જો (s == ખાલી)
		પાછા 0;
	પાછા sshbuf_put_cstring(buf, s);
}

સ્થિર પૂર્ણાંક
serialise_nullable_string_array(સંરચના sshbuf *buf, અક્ષર **a, u_int n)
{
	પૂર્ણાંક r;
	u_int i;

	જો ((r = sshbuf_put_u32(buf, n)) != 0)
		પાછા r;
	માટે (i = 0; i < n; i++) {
		જો ((r = serialise_nullable_string(buf, a[i])) != 0)
			પાછા r;
	}
	પાછા 0;
}

સ્થિર પૂર્ણાંક
serialise_hostkeyfile(અચલ ServerOptions *options, સંરચના sshbuf *buf)
{
	પૂર્ણાંક r;
	u_int i;

	જો ((r = sshbuf_put_u32(buf, options->અંક_host_ચાવી_files)) != 0) {
		error_fr(r, "serialise length");
		પાછા r;
	}
	માટે (i = 0; i < options->અંક_host_ચાવી_files; i++) {
		જો ((r = serialise_s32(buf,
		    options->host_ચાવી_file_userprovided[i])) != 0 ||
		    (r = serialise_nullable_string(buf,
		    options->host_ચાવી_files[i])) != 0) {
			error_fr(r, "serialise member");
			પાછા r;
		}
	}
	પાછા 0;
}

સ્થિર પૂર્ણાંક
serialise_ipqos(અચલ ServerOptions *options, સંરચના sshbuf *buf)
{
	પૂર્ણાંક r;

	જો ((r = serialise_s32(buf, options->ip_qos_interactive)) != 0 ||
	    (r = serialise_s32(buf, options->ip_qos_bulk)) != 0) {
		error_fr(r, "serialise");
		પાછા r;
	}

	પાછા 0;
}

સ્થિર પૂર્ણાંક
serialise_listenaddress(અચલ ServerOptions *options, સંરચના sshbuf *buf)
{
	પૂર્ણાંક r;
	u_int i;

	/* Note: only serialises queued listen addresses */
	જો ((r = sshbuf_put_u32(buf, options->અંક_queued_listens)) != 0) {
		error_fr(r, "serialise length");
		પાછા r;
	}
	માટે (i = 0; i < options->અંક_queued_listens; i++) {
		અચલ સંરચના queued_listenaddr *qla =
		    options->queued_listen_addrs + i;

		જો ((r = sshbuf_put_cstring(buf, qla->addr)) != 0 ||
		    (r = serialise_s32(buf, qla->port)) != 0 ||
		    (r = serialise_nullable_string(buf, qla->rdomain)) != 0) {
			error_fr(r, "serialise member");
			પાછા r;
		}
	}
	પાછા 0;
}

સ્થિર પૂર્ણાંક
serialise_logfacility(અચલ ServerOptions *options, સંરચના sshbuf *buf)
{
	પૂર્ણાંક r;

	જો ((r = serialise_s32(buf, (પૂર્ણાંક)options->log_facility)) != 0) {
		error_fr(r, "serialise");
		પાછા r;
	}

	પાછા 0;
}

સ્થિર પૂર્ણાંક
serialise_loglevel(અચલ ServerOptions *options, સંરચના sshbuf *buf)
{
	પૂર્ણાંક r;

	જો ((r = serialise_s32(buf, (પૂર્ણાંક)options->log_level)) != 0) {
		error_fr(r, "serialise");
		પાછા r;
	}

	પાછા 0;
}

સ્થિર પૂર્ણાંક
serialise_port(અચલ ServerOptions *options, સંરચના sshbuf *buf)
{
	પૂર્ણાંક r;
	u_int i;

	જો ((r = sshbuf_put_u32(buf, options->અંક_ports)) != 0) {
		error_fr(r, "serialise length");
		પાછા r;
	}
	માટે (i = 0; i < options->અંક_ports; i++) {
		જો ((r = serialise_s32(buf, options->ports[i])) != 0) {
			error_fr(r, "serialise port");
			પાછા r;
		}
	}
	પાછા 0;
}

સ્થિર પૂર્ણાંક
serialise_gatewayports(અચલ ServerOptions *options, સંરચના sshbuf *buf)
{
	પૂર્ણાંક r;

	જો ((r = serialise_s32(buf, options->fwd_opts.gateway_ports)) != 0) {
		error_fr(r, "serialise");
		પાછા r;
	}
	પાછા 0;
}

સ્થિર પૂર્ણાંક
serialise_streamlocalbindmask(અચલ ServerOptions *options, સંરચના sshbuf *buf)
{
	પૂર્ણાંક r;

	જો ((r = serialise_mode(buf,
	    options->fwd_opts.streamlocal_bind_mask)) != 0) {
		error_fr(r, "serialise");
		પાછા r;
	}
	પાછા 0;
}

સ્થિર પૂર્ણાંક
serialise_streamlocalbindunlink(અચલ ServerOptions *options, સંરચના sshbuf *buf)
{
	પૂર્ણાંક r;

	જો ((r = sshbuf_put_u8(buf,
	    (options->fwd_opts.streamlocal_bind_unlink != 0))) != 0) {
		error_fr(r, "serialise");
		પાછા r;
	}
	પાછા 0;
}

સ્થિર પૂર્ણાંક
serialise_maxstartups(અચલ ServerOptions *options, સંરચના sshbuf *buf)
{
	પૂર્ણાંક r;

	જો ((r = serialise_s32(buf, options->max_startups_begin)) != 0 ||
	    (r = serialise_s32(buf, options->max_startups_rate)) != 0 ||
	    (r = serialise_s32(buf, options->max_startups)) != 0) {
		error_fr(r, "serialise");
		પાછા r;
	}

	પાછા 0;
}

સ્થિર પૂર્ણાંક
serialise_permituserenv(અચલ ServerOptions *options, સંરચના sshbuf *buf)
{
	પૂર્ણાંક r;

	જો ((r = serialise_s32(buf, options->permit_user_env)) != 0 ||
	    (r = serialise_nullable_string(buf,
	    options->permit_user_env_allowlist)) != 0) {
		error_fr(r, "serialise");
		પાછા r;
	}

	પાછા 0;
}

સ્થિર પૂર્ણાંક
serialise_persourcenetblocksize(અચલ ServerOptions *options, સંરચના sshbuf *buf)
{
	પૂર્ણાંક r;

	જો ((r = serialise_s32(buf, options->per_source_masklen_ipv4)) != 0 ||
	    (r = serialise_s32(buf, options->per_source_masklen_ipv6)) != 0) {
		error_fr(r, "serialise");
		પાછા r;
	}

	પાછા 0;
}

સ્થિર પૂર્ણાંક
serialise_persourcepenalties(અચલ ServerOptions *options, સંરચના sshbuf *buf)
{
	અચલ સંરચના per_source_penalty *psp = &options->per_source_penalty;
	પૂર્ણાંક r;

	જો ((r = serialise_s32(buf, psp->enabled)) != 0 ||
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
		પાછા r;
	}

	પાછા 0;
}

સ્થિર પૂર્ણાંક
serialise_rekeylimit(અચલ ServerOptions *options, સંરચના sshbuf *buf)
{
	પૂર્ણાંક r;

	જો ((r = serialise_s64(buf, options->rekey_limit)) != 0 ||
	    (r = serialise_s32(buf, options->rekey_interval)) != 0) {
		error_fr(r, "serialise");
		પાછા r;
	}

	પાછા 0;
}

સ્થિર પૂર્ણાંક
serialise_subsystem(અચલ ServerOptions *options, સંરચના sshbuf *buf)
{
	પૂર્ણાંક r;
	u_int i;

	જો ((r = sshbuf_put_u32(buf, options->અંક_subsystems)) != 0) {
		error_fr(r, "serialise length");
		પાછા r;
	}
	માટે (i = 0; i < options->અંક_subsystems; i++) {
		જો ((r = sshbuf_put_cstring(buf,
		    options->subsystem_name[i])) != 0 ||
		    (r = sshbuf_put_cstring(buf,
		    options->subsystem_command[i])) != 0 ||
		    (r = sshbuf_put_cstring(buf,
		    options->subsystem_args[i])) != 0) {
			error_fr(r, "serialise member");
			પાછા r;
		}
	}
	પાછા 0;
}

સ્થિર પૂર્ણાંક
serialise_pubkey_auth_options(અચલ ServerOptions *options, સંરચના sshbuf *buf)
{
	પૂર્ણાંક r;

	જો ((r = serialise_s32(buf, options->pubkey_auth_options)) != 0 ||
	    (r = serialise_s32(buf, options->max_pubkey_ok)) != 0) {
		error_fr(r, "serialise");
		પાછા r;
	}
	પાછા 0;
}

સ્થિર પૂર્ણાંક
serialise_timingsecret(અચલ ServerOptions *options, સંરચના sshbuf *buf)
{
	પૂર્ણાંક r;

	જો ((r = sshbuf_put_u64(buf, options->timing_secret)) != 0) {
		error_fr(r, "serialise");
		પાછા r;
	}
	પાછા 0;
}


પૂર્ણાંક
serialise_server_options(અચલ ServerOptions *options, સંરચના sshbuf **bufp)
{
	સંરચના sshbuf *buf = ખાલી;
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;

	*bufp = ખાલી;

	જો ((buf = sshbuf_new()) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો ((r = sshbuf_put_u32(buf, SSHD_CONFIG_BLOB_VERSION)) != 0) {
		error_fr(r, "serialise version");
		જાઓ out;
	}

#define SSHCONF_INT(var, conf, flags, ms, def, cp) \
	જો ((r = serialise_s32(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		જાઓ out; \
	}
#define SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	જો ((r = serialise_s32(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		જાઓ out; \
	}
#define SSHCONF_STRING(var, conf, flags, cp) \
	જો ((r = serialise_nullable_string(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		જાઓ out; \
	}
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	જો ((r = serialise_nullable_string_array(buf, options->var, \
	    options->nvar)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		જાઓ out; \
	}
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	જો ((r = serialise_##funcsuffix(options, buf)) != 0) \
		જાઓ out;
#define SSHCONF_NONCONF(funcsuffix) \
	જો ((r = serialise_##funcsuffix(options, buf)) != 0) \
		જાઓ out;
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
	buf = ખાલી; /* transferred */
 out:
	sshbuf_free(buf);
	પાછા r;
}

સ્થિર પૂર્ણાંક
deserialise_s32(સંરચના sshbuf *buf, પૂર્ણાંક *v)
{
	uint32_t tmp;
	પૂર્ણાંક r;
	u_char was_signed;

	જો ((r = sshbuf_get_u8(buf, &was_signed)) != 0 ||
	    (r = sshbuf_get_u32(buf, &tmp)) != 0)
		પાછા r;
	જો (was_signed > 1)
		પાછા SSH_ERR_INVALID_FORMAT;
	જો (was_signed) {
		જો (tmp > (uint32_t)INT_MAX + 1)
			પાછા SSH_ERR_INVALID_FORMAT;
		*v = tmp == (uint32_t)INT_MAX + 1 ? INT_MIN : -(પૂર્ણાંક)tmp;
	} નહીંતર {
		જો (tmp > INT_MAX)
			પાછા SSH_ERR_INVALID_FORMAT;
		*v = (પૂર્ણાંક)tmp;
	}
	પાછા 0;
}

સ્થિર પૂર્ણાંક
deserialise_s64(સંરચના sshbuf *buf, int64_t *v)
{
	uint64_t tmp;
	પૂર્ણાંક r;
	u_char was_signed;

	જો ((r = sshbuf_get_u8(buf, &was_signed)) != 0 ||
	    (r = sshbuf_get_u64(buf, &tmp)) != 0)
		પાછા r;
	જો (was_signed > 1)
		પાછા SSH_ERR_INVALID_FORMAT;
	જો (was_signed) {
		જો (tmp > (uint64_t)INT64_MAX + 1)
			પાછા SSH_ERR_INVALID_FORMAT;
		*v = tmp == (uint64_t)INT64_MAX + 1 ?
		    INT64_MIN : -(int64_t)tmp;
	} નહીંતર {
		જો (tmp > INT64_MAX)
			પાછા SSH_ERR_INVALID_FORMAT;
		*v = (int64_t)tmp;
	}
	પાછા 0;
}

સ્થિર પૂર્ણાંક
deserialise_mode(સંરચના sshbuf *buf, mode_t *v)
{
	પૂર્ણાંક r, tmp;

	જો ((r = deserialise_s32(buf, &tmp)) != 0)
		પાછા r;
	જો (tmp == -1) {
		*v = (mode_t)-1;
		પાછા 0;
	}
	જો (tmp < 0 || tmp > 0777)
		પાછા SSH_ERR_INVALID_FORMAT;
	*v = (mode_t)tmp;
	પાછા 0;
}

સ્થિર પૂર્ણાંક
deserialise_double(સંરચના sshbuf *buf, દ્વિગુણ *v)
{
	પાછા sshbuf_get(buf, v, કદ(*v));
}

સ્થિર પૂર્ણાંક
deserialise_nullable_string(સંરચના sshbuf *buf, અક્ષર **sp)
{
	પૂર્ણાંક r;
	u_char present;

	જો ((r = sshbuf_get_u8(buf, &present)) != 0)
		પાછા r;
	જો (present == 0) {
		*sp = ખાલી;
		પાછા 0;
	}
	જો (present != 1)
		પાછા SSH_ERR_INVALID_FORMAT;
	પાછા sshbuf_get_cstring(buf, sp, ખાલી);
}

સ્થિર શૂન્ય
free_string_array(અક્ષર **a, u_int n)
{
	u_int i;

	જો (a == ખાલી)
		પાછા;
	માટે (i = 0; i < n; i++)
		મુક્ત(a[i]);
	મુક્ત(a);
}

સ્થિર પૂર્ણાંક
deserialise_ગણતરી(સંરચના sshbuf *buf, u_int *np, અચલ અક્ષર *what)
{
	પૂર્ણાંક r;
	uint32_t n;

	જો ((r = sshbuf_get_u32(buf, &n)) != 0) {
		error_fr(r, "deserialise %s length", what);
		પાછા r;
	}
	જો (n > UINT_MAX) {
		error_f("bad number of %s", what);
		પાછા SSH_ERR_INVALID_FORMAT;
	}
	જો (n > sshbuf_len(buf)) {
		error_f("bad number of %s", what);
		પાછા SSH_ERR_INVALID_FORMAT;
	}
	*np = n;
	પાછા 0;
}

સ્થિર પૂર્ણાંક
deserialise_nullable_string_array(સંરચના sshbuf *buf, અક્ષર ***arrayp,
    u_int *np)
{
	અક્ષર **a = ખાલી;
	પૂર્ણાંક r;
	u_int i, n;

	*arrayp = ખાલી;
	*np = 0;
	જો ((r = deserialise_ગણતરી(buf, &n, "strings")) != 0)
		પાછા r;
	જો (n > 0)
		a = xcalloc(n, કદ(*a));
	માટે (i = 0; i < n; i++) {
		જો ((r = deserialise_nullable_string(buf, a + i)) != 0) {
			free_string_array(a, i + 1);
			પાછા r;
		}
	}
	*arrayp = a;
	*np = n;
	પાછા 0;
}

સ્થિર શૂન્ય
free_queued_listen_addrs(સંરચના queued_listenaddr *qla, u_int n)
{
	u_int i;

	જો (qla == ખાલી)
		પાછા;
	માટે (i = 0; i < n; i++) {
		મુક્ત(qla[i].addr);
		મુક્ત(qla[i].rdomain);
	}
	મુક્ત(qla);
}

સ્થિર પૂર્ણાંક
deserialise_hostkeyfile(ServerOptions *options, સંરચના sshbuf *buf)
{
	પૂર્ણાંક r, *userprovided = ખાલી;
	u_int i, n;
	અક્ષર **files = ખાલી;

	જો ((r = deserialise_ગણતરી(buf, &n, "host key files")) != 0)
		પાછા r;
	જો (n > 0) {
		userprovided = xcalloc(n, કદ(*userprovided));
		files = xcalloc(n, કદ(*files));
	}
	માટે (i = 0; i < n; i++) {
		જો ((r = deserialise_s32(buf, userprovided + i)) != 0 ||
		    (r = deserialise_nullable_string(buf, files + i)) != 0) {
			error_fr(r, "deserialise member");
			free_string_array(files, i + 1);
			મુક્ત(userprovided);
			પાછા r;
		}
	}
	options->અંક_host_ચાવી_files = n;
	options->host_ચાવી_file_userprovided = userprovided;
	options->host_ચાવી_files = files;
	પાછા 0;
}

સ્થિર પૂર્ણાંક
deserialise_ipqos(ServerOptions *options, સંરચના sshbuf *buf)
{
	પૂર્ણાંક r;

	જો ((r = deserialise_s32(buf, &options->ip_qos_interactive)) != 0 ||
	    (r = deserialise_s32(buf, &options->ip_qos_bulk)) != 0) {
		error_fr(r, "deserialise");
		પાછા r;
	}

	પાછા 0;
}

સ્થિર પૂર્ણાંક
deserialise_listenaddress(ServerOptions *options, સંરચના sshbuf *buf)
{
	પૂર્ણાંક r;
	u_int i, n;
	સંરચના queued_listenaddr *qla = ખાલી;

	જો ((r = deserialise_ગણતરી(buf, &n, "listen addresses")) != 0)
		પાછા r;
	જો (n > 0)
		qla = xcalloc(n, કદ(*qla));
	માટે (i = 0; i < n; i++) {
		જો ((r = sshbuf_get_cstring(buf, &qla[i].addr, ખાલી)) != 0 ||
		    (r = deserialise_s32(buf, &qla[i].port)) != 0 ||
		    (r = deserialise_nullable_string(buf,
		    &qla[i].rdomain)) != 0) {
			error_fr(r, "deserialise member");
			free_queued_listen_addrs(qla, i + 1);
			પાછા r;
		}
	}
	options->અંક_queued_listens = n;
	options->queued_listen_addrs = qla;
	પાછા 0;
}

સ્થિર પૂર્ણાંક
deserialise_logfacility(ServerOptions *options, સંરચના sshbuf *buf)
{
	પૂર્ણાંક r, tmp;

	જો ((r = deserialise_s32(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		પાછા r;
	}
	જો (tmp != SYSLOG_FACILITY_NOT_SET &&
	    log_facility_name((SyslogFacility)tmp) == ખાલી) {
		error_f("bad syslog facility");
		પાછા SSH_ERR_INVALID_FORMAT;
	}
	options->log_facility = (SyslogFacility)tmp;

	પાછા 0;
}

સ્થિર પૂર્ણાંક
deserialise_loglevel(ServerOptions *options, સંરચના sshbuf *buf)
{
	પૂર્ણાંક r, tmp;

	જો ((r = deserialise_s32(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		પાછા r;
	}
	જો (tmp != SYSLOG_LEVEL_NOT_SET &&
	    log_level_name((LogLevel)tmp) == ખાલી) {
		error_f("bad log level");
		પાછા SSH_ERR_INVALID_FORMAT;
	}
	options->log_level = (LogLevel)tmp;

	પાછા 0;
}

સ્થિર પૂર્ણાંક
deserialise_port(ServerOptions *options, સંરચના sshbuf *buf)
{
	પૂર્ણાંક r;
	u_int i, n;

	જો ((r = deserialise_ગણતરી(buf, &n, "ports")) != 0)
		પાછા r;
	જો (n > MAX_PORTS) {
		error_f("bad number of ports");
		પાછા SSH_ERR_INVALID_FORMAT;
	}
	options->અંક_ports = n;
	memset(options->ports, 0, કદ(options->ports));
	માટે (i = 0; i < options->અંક_ports; i++) {
		જો ((r = deserialise_s32(buf, options->ports + i)) != 0) {
			error_fr(r, "deserialise port");
			પાછા r;
		}
	}
	પાછા 0;
}

સ્થિર પૂર્ણાંક
deserialise_gatewayports(ServerOptions *options, સંરચના sshbuf *buf)
{
	પૂર્ણાંક r;

	જો ((r = deserialise_s32(buf, &options->fwd_opts.gateway_ports)) != 0) {
		error_fr(r, "deserialise");
		પાછા r;
	}
	પાછા 0;
}

સ્થિર પૂર્ણાંક
deserialise_streamlocalbindmask(ServerOptions *options, સંરચના sshbuf *buf)
{
	પૂર્ણાંક r;

	જો ((r = deserialise_mode(buf,
	    &options->fwd_opts.streamlocal_bind_mask)) != 0) {
		error_fr(r, "deserialise");
		પાછા r;
	}
	પાછા 0;
}

સ્થિર પૂર્ણાંક
deserialise_streamlocalbindunlink(ServerOptions *options, સંરચના sshbuf *buf)
{
	પૂર્ણાંક r;
	u_char tmp;

	જો ((r = sshbuf_get_u8(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		પાછા r;
	}
	જો (tmp > 1) {
		error_f("bad boolean");
		પાછા SSH_ERR_INVALID_FORMAT;
	}
	options->fwd_opts.streamlocal_bind_unlink = tmp;
	પાછા 0;
}

સ્થિર પૂર્ણાંક
deserialise_maxstartups(ServerOptions *options, સંરચના sshbuf *buf)
{
	પૂર્ણાંક r;

	જો ((r = deserialise_s32(buf, &options->max_startups_begin)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_startups_rate)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_startups)) != 0) {
		error_fr(r, "deserialise");
		પાછા r;
	}

	પાછા 0;
}

સ્થિર પૂર્ણાંક
deserialise_permituserenv(ServerOptions *options, સંરચના sshbuf *buf)
{
	પૂર્ણાંક r;

	જો ((r = deserialise_s32(buf, &options->permit_user_env)) != 0 ||
	    (r = deserialise_nullable_string(buf,
	    &options->permit_user_env_allowlist)) != 0) {
		error_fr(r, "deserialise");
		પાછા r;
	}
	પાછા 0;
}

સ્થિર પૂર્ણાંક
deserialise_persourcenetblocksize(ServerOptions *options, સંરચના sshbuf *buf)
{
	પૂર્ણાંક r;

	જો ((r = deserialise_s32(buf,
	    &options->per_source_masklen_ipv4)) != 0 ||
	    (r = deserialise_s32(buf,
	    &options->per_source_masklen_ipv6)) != 0) {
		error_fr(r, "deserialise");
		પાછા r;
	}

	પાછા 0;
}

સ્થિર પૂર્ણાંક
deserialise_persourcepenalties(ServerOptions *options, સંરચના sshbuf *buf)
{
	સંરચના per_source_penalty *psp = &options->per_source_penalty;
	પૂર્ણાંક r;

	જો ((r = deserialise_s32(buf, &psp->enabled)) != 0 ||
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
		પાછા r;
	}

	પાછા 0;
}

સ્થિર પૂર્ણાંક
deserialise_rekeylimit(ServerOptions *options, સંરચના sshbuf *buf)
{
	પૂર્ણાંક r;

	જો ((r = deserialise_s64(buf, &options->rekey_limit)) != 0 ||
	    (r = deserialise_s32(buf, &options->rekey_interval)) != 0) {
		error_fr(r, "deserialise");
		પાછા r;
	}

	પાછા 0;
}

સ્થિર પૂર્ણાંક
deserialise_subsystem(ServerOptions *options, સંરચના sshbuf *buf)
{
	પૂર્ણાંક r;
	u_int i, n;
	અક્ષર **names = ખાલી, **commands = ખાલી, **args = ખાલી;

	જો ((r = deserialise_ગણતરી(buf, &n, "subsystems")) != 0)
		પાછા r;
	જો (n > 0) {
		names = xcalloc(n, કદ(*names));
		commands = xcalloc(n, કદ(*names));
		args = xcalloc(n, કદ(*args));
	}
	માટે (i = 0; i < n; i++) {
		જો ((r = sshbuf_get_cstring(buf, names + i, ખાલી)) != 0 ||
		    (r = sshbuf_get_cstring(buf, commands + i, ખાલી)) != 0 ||
		    (r = sshbuf_get_cstring(buf, args + i, ખાલી)) != 0) {
			error_fr(r, "deserialise member");
			free_string_array(names, i + 1);
			free_string_array(commands, i + 1);
			free_string_array(args, i + 1);
			પાછા r;
		}
	}
	options->અંક_subsystems = n;
	options->subsystem_name = names;
	options->subsystem_command = commands;
	options->subsystem_args = args;
	પાછા 0;
}

સ્થિર પૂર્ણાંક
deserialise_pubkey_auth_options(ServerOptions *options, સંરચના sshbuf *buf)
{
	પૂર્ણાંક r;

	જો ((r = deserialise_s32(buf, &options->pubkey_auth_options)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_pubkey_ok)) != 0) {
		error_fr(r, "deserialise");
		પાછા r;
	}
	પાછા 0;
}

સ્થિર પૂર્ણાંક
deserialise_timingsecret(ServerOptions *options, સંરચના sshbuf *buf)
{
	પૂર્ણાંક r;

	જો ((r = sshbuf_get_u64(buf, &options->timing_secret)) != 0) {
		error_fr(r, "deserialise");
		પાછા r;
	}
	પાછા 0;
}

પૂર્ણાંક
deserialise_server_options(સંરચના sshbuf *buf, ServerOptions *options)
{
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;
	uint32_t version;
	ServerOptions new_options;

	initialize_server_options(&new_options);
	જો ((r = sshbuf_get_u32(buf, &version)) != 0) {
		error_fr(r, "deserialise version");
		જાઓ out;
	}
	જો (version != SSHD_CONFIG_BLOB_VERSION) {
		error_f("unsupported config blob version %u", version);
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
#define SSHCONF_INT(var, conf, flags, ms, def, cp) \
	જો ((r = deserialise_s32(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		જાઓ out; \
	}
#define SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	જો ((r = deserialise_s32(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		જાઓ out; \
	}
#define SSHCONF_STRING(var, conf, flags, cp) \
	જો ((r = deserialise_nullable_string(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		જાઓ out; \
	}
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	જો ((r = deserialise_nullable_string_array(buf, &new_options.var, \
	    &new_options.nvar)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		જાઓ out; \
	}
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	જો ((r = deserialise_##funcsuffix(&new_options, buf)) != 0) \
		જાઓ out;
#define SSHCONF_NONCONF(funcsuffix) \
	જો ((r = deserialise_##funcsuffix(&new_options, buf)) != 0) \
		જાઓ out;
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	new_options.var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	કરો { \
		મુક્ત(new_options.var); \
		new_options.var = ખાલી; \
	} જ્યારે (0);
#define SSHCONF_ALIAS(old, conf, flags)			/* empty */

	SSHD_CONFIG_ENTRIES

	જો (sshbuf_len(buf) != 0) {
		error_f("trailing data in config blob");
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
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
	memset(&new_options, 0, કદ(new_options));
 out:
	free_server_options(&new_options);
	પાછા r;
}

સ્થિર શૂન્ય
free_hostkeyfile(ServerOptions *options)
{
	u_int i;

	માટે (i = 0; i < options->અંક_host_ચાવી_files; i++)
		મુક્ત(options->host_ચાવી_files[i]);
	મુક્ત(options->host_ચાવી_files);
	મુક્ત(options->host_ચાવી_file_userprovided);
}

સ્થિર શૂન્ય
free_listenaddress(ServerOptions *options)
{
	u_int i;

	free_queued_listen_addrs(options->queued_listen_addrs,
	    options->અંક_queued_listens);

	માટે (i = 0; i < options->અંક_listen_addrs; i++) {
		મુક્ત(options->listen_addrs[i].rdomain);
		જો (options->listen_addrs[i].addrs != ખાલી)
			freeaddrinfo(options->listen_addrs[i].addrs);
	}
	મુક્ત(options->listen_addrs);
}

સ્થિર શૂન્ય
free_permituserenv(ServerOptions *options)
{
	મુક્ત(options->permit_user_env_allowlist);
}

સ્થિર શૂન્ય
free_subsystem(ServerOptions *options)
{
	u_int i;

	માટે (i = 0; i < options->અંક_subsystems; i++) {
		મુક્ત(options->subsystem_name[i]);
		મુક્ત(options->subsystem_command[i]);
		મુક્ત(options->subsystem_args[i]);
	}
	મુક્ત(options->subsystem_name);
	મુક્ત(options->subsystem_command);
	મુક્ત(options->subsystem_args);
}

શૂન્ય
free_server_options(ServerOptions *options)
{
#define SSHCONF_INT(var, conf, flags, ms, def, cp)	/* empty */
#define SSHCONF_INTFLAG(var, conf, flags, def, cp)	/* empty */
#define SSHCONF_STRING(var, conf, flags, cp)		મુક્ત(options->var);
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	free_string_array(options->var, options->nvar);
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	free_##funcsuffix(options);
#define SSHCONF_NONCONF(funcsuffix) \
	free_##funcsuffix(options);
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	કરો { \
		મુક્ત(options->var); \
		options->var = ખાલી; \
	} જ્યારે (0);
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

સ્થિર શૂન્ય
copy_server_option_int(પૂર્ણાંક *dst, પૂર્ણાંક src)
{
	જો (src != -1)
		*dst = src;
}

સ્થિર શૂન્ય
copy_server_option_int64(int64_t *dst, int64_t src)
{
	જો (src != -1)
		*dst = src;
}

સ્થિર શૂન્ય
copy_server_option_string(અક્ષર **dst, અચલ અક્ષર *src)
{
	જો (src != ખાલી && *dst != src) {
		મુક્ત(*dst);
		*dst = xstrdup(src);
	}
}

સ્થિર શૂન્ય
copy_server_option_strarray_કિંમતો(અક્ષર ***dst, u_int ndst,
    અક્ષર * અચલ *src, u_int nsrc)
{
	u_int i;

	જો (nsrc == 0)
		પાછા;
	માટે (i = 0; i < ndst; i++)
		મુક્ત((*dst)[i]);
	મુક્ત(*dst);
	*dst = xcalloc(nsrc, કદ(**dst));
	માટે (i = 0; i < nsrc; i++)
		(*dst)[i] = src[i] == ખાલી ? ખાલી : xstrdup(src[i]);
}

સ્થિર શૂન્ય
copy_server_option_strarray(અક્ષર ***dst, u_int *ndst,
    અક્ષર * અચલ *src, u_int nsrc)
{
	જો (nsrc == 0)
		પાછા;
	copy_server_option_strarray_કિંમતો(dst, *ndst, src, nsrc);
	*ndst = nsrc;
}

સ્થિર શૂન્ય
copy_ipqos(ServerOptions *dst, અચલ ServerOptions *src)
{
	copy_server_option_int(&dst->ip_qos_interactive,
	    src->ip_qos_interactive);
	copy_server_option_int(&dst->ip_qos_bulk, src->ip_qos_bulk);
}

સ્થિર શૂન્ય
copy_gatewayports(ServerOptions *dst, અચલ ServerOptions *src)
{
	copy_server_option_int(&dst->fwd_opts.gateway_ports,
	    src->fwd_opts.gateway_ports);
}

સ્થિર શૂન્ય
copy_streamlocalbindunlink(ServerOptions *dst, અચલ ServerOptions *src)
{
	copy_server_option_int(&dst->fwd_opts.streamlocal_bind_unlink,
	    src->fwd_opts.streamlocal_bind_unlink);
}

સ્થિર શૂન્ય
copy_loglevel(ServerOptions *dst, અચલ ServerOptions *src)
{
	જો (src->log_level != -1)
		dst->log_level = src->log_level;
}

સ્થિર શૂન્ય
copy_rekeylimit(ServerOptions *dst, અચલ ServerOptions *src)
{
	copy_server_option_int64(&dst->rekey_limit, src->rekey_limit);
	copy_server_option_int(&dst->rekey_interval, src->rekey_interval);
}

સ્થિર શૂન્ય
copy_subsystem(ServerOptions *dst, અચલ ServerOptions *src)
{
	u_int old_અંક_subsystems = dst->અંક_subsystems;

	જો (src->અંક_subsystems == 0)
		પાછા;
	copy_server_option_strarray_કિંમતો(&dst->subsystem_name,
	    old_અંક_subsystems, src->subsystem_name, src->અંક_subsystems);
	copy_server_option_strarray_કિંમતો(&dst->subsystem_command,
	    old_અંક_subsystems, src->subsystem_command, src->અંક_subsystems);
	copy_server_option_strarray_કિંમતો(&dst->subsystem_args,
	    old_અંક_subsystems, src->subsystem_args, src->અંક_subsystems);
	dst->અંક_subsystems = src->અંક_subsystems;
}

સ્થિર શૂન્ય
copy_pubkey_auth_options(ServerOptions *dst, અચલ ServerOptions *src)
{
	જો (src->pubkey_auth_options != -1) {
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
શૂન્ય
copy_set_server_options(ServerOptions *dst, ServerOptions *src, પૂર્ણાંક preauth)
{
	જો (dst == src)
		પાછા;

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
	કરો { \
		મુક્ત(dst->var); \
		dst->var = ખાલી; \
	} જ્યારે (0);
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
	જો (src->fwd_opts.streamlocal_bind_mask != (mode_t)-1) {
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
	કરો { \
		જો (option_clear_or_none(v)) { \
			મુક્ત(v); \
			v = ખાલી; \
		} \
	} જ્યારે(0)
	CLEAR_ON_NONE(dst->authorized_principals_file);
	CLEAR_ON_NONE(dst->trusted_user_ca_ચાવીઓ);
	CLEAR_ON_NONE(dst->banner);

	/*
	 * The only things that should be below this point are string options
	 * which are only used after authentication.
	 */
	જો (preauth)
		પાછા;

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
સ્થિર શૂન્ય
parse_server_config_depth(ServerOptions *options, અચલ અક્ષર *filename,
    સંરચના sshbuf *conf, સંરચના include_list *includes,
    સંરચના connection_info *connectinfo, પૂર્ણાંક flags, પૂર્ણાંક *activep, પૂર્ણાંક depth)
{
	પૂર્ણાંક linenum, bad_options = 0;
	અક્ષર *cp, *obuf, *cbuf;

	જો (depth < 0 || depth > SERVCONF_MAX_DEPTH)
		fatal("Too many recursive configuration includes");

	debug2_f("config %s len %zu%s", filename, sshbuf_len(conf),
	    (flags & SSHCFG_NEVERMATCH ? " [checking syntax only]" : ""));

	જો ((obuf = cbuf = sshbuf_dup_string(conf)) == ખાલી)
		fatal_f("sshbuf_dup_string failed");
	linenum = 1;
	જ્યારે ((cp = strsep(&cbuf, "\n")) != ખાલી) {
		જો (process_server_config_લીટી_depth(options, cp,
		    filename, linenum++, activep, connectinfo, &flags,
		    depth, includes) != 0)
			bad_options++;
	}
	મુક્ત(obuf);
	જો (bad_options > 0)
		fatal("%s: terminating, %d bad configuration options",
		    filename, bad_options);
}

શૂન્ય
parse_server_config(ServerOptions *options, અચલ અક્ષર *filename,
    સંરચના sshbuf *conf, સંરચના include_list *includes,
    સંરચના connection_info *connectinfo, પૂર્ણાંક reexec)
{
	પૂર્ણાંક active = connectinfo ? 0 : 1;
	parse_server_config_depth(options, filename, conf, includes,
	    connectinfo, (connectinfo ? SSHCFG_MATCH_ONLY : 0), &active, 0);
	જો (!reexec)
		process_queued_listen_addrs(options);
}

સ્થિર અચલ અક્ષર *
fmt_multistate_int(પૂર્ણાંક val, અચલ સંરચના multistate *m)
{
	u_int i;

	માટે (i = 0; m[i].ચાવી != ખાલી; i++) {
		જો (m[i].કિંમત == val)
			પાછા m[i].ચાવી;
	}
	પાછા "UNKNOWN";
}

સ્થિર અચલ અક્ષર *
fmt_intarg(ServerOpCodes code, પૂર્ણાંક val)
{
	જો (val == -1)
		પાછા "unset";
	પસંદગી (code) {
	સ્થિતિ sAddressFamily:
		પાછા fmt_multistate_int(val, multistate_addressfamily);
	સ્થિતિ s_Permit_મૂળ_Login:
		પાછા fmt_multistate_int(val, multistate_permitrootlogin);
	સ્થિતિ sGatewayPorts:
		પાછા fmt_multistate_int(val, multistate_gatewayports);
	સ્થિતિ sCompression:
		પાછા fmt_multistate_int(val, multistate_compression);
	સ્થિતિ sAllowTcpForwarding:
		પાછા fmt_multistate_int(val, multistate_tcpfwd);
	સ્થિતિ sAllowStreamLocalForwarding:
		પાછા fmt_multistate_int(val, multistate_tcpfwd);
	સ્થિતિ sIgnoreRhosts:
		પાછા fmt_multistate_int(val, multistate_ignore_rhosts);
	સ્થિતિ sTCPKeepAlive:
		પાછા fmt_multistate_int(val, multistate_keepalives);
	સ્થિતિ sWarnWeakCrypto:
		પાછા fmt_multistate_int(val, multistate_warnweakcrypto);
	સ્થિતિ sFingerprintHash:
		પાછા ssh_digest_alg_name(val);
	મૂળભૂત:
		પસંદગી (val) {
		સ્થિતિ 0:
			પાછા "no";
		સ્થિતિ 1:
			પાછા "yes";
		મૂળભૂત:
			પાછા "UNKNOWN";
		}
	}
}

સ્થિર શૂન્ય
dump_cfg_int(ServerOpCodes code, પૂર્ણાંક val)
{
	જો (code == sUnusedConnectionTimeout && val == 0) {
		printf("%s none\n", lookup_opcode_name(code));
		પાછા;
	}
	printf("%s %d\n", lookup_opcode_name(code), val);
}

સ્થિર શૂન્ય
dump_cfg_oct(ServerOpCodes code, પૂર્ણાંક val)
{
	printf("%s 0%o\n", lookup_opcode_name(code), val);
}

સ્થિર શૂન્ય
dump_cfg_fmtint(ServerOpCodes code, પૂર્ણાંક val)
{
	printf("%s %s\n", lookup_opcode_name(code), fmt_intarg(code, val));
}

સ્થિર શૂન્ય
dump_cfg_string(ServerOpCodes code, અચલ અક્ષર *val)
{
	printf("%s %s\n", lookup_opcode_name(code),
	    val == ખાલી ? "none" : val);
}

સ્થિર શૂન્ય
dump_cfg_strarray(ServerOpCodes code, u_int ગણતરી, અક્ષર **vals)
{
	u_int i;

	માટે (i = 0; i < ગણતરી; i++)
		printf("%s %s\n", lookup_opcode_name(code), vals[i]);
}

સ્થિર શૂન્ય
dump_cfg_strarray_oneline(ServerOpCodes code, u_int ગણતરી, અક્ષર **vals)
{
	u_int i;

	પસંદગી (code) {
	સ્થિતિ sAuthenticationMethods:
	સ્થિતિ sChannelTimeout:
		તોડો;
	મૂળભૂત:
		જો (ગણતરી <= 0)
			પાછા;
		તોડો;
	}

	printf("%s", lookup_opcode_name(code));
	માટે (i = 0; i < ગણતરી; i++)
		printf(" %s",  vals[i]);
	જો (code == sAuthenticationMethods && ગણતરી == 0)
		printf(" any");
	નહીંતર જો (code == sChannelTimeout && ગણતરી == 0)
		printf(" none");
	printf("\n");
}

સ્થિર અક્ષર *
format_listen_addrs(સંરચના listenaddr *la)
{
	પૂર્ણાંક r;
	સંરચના addrinfo *ai;
	અક્ષર addr[NI_MAXHOST], port[NI_MAXSERV];
	અક્ષર *laddr1 = xstrdup(""), *laddr2 = ખાલી;

	/*
	 * ListenAddress must be after Port.  add_one_listen_addr pushes
	 * addresses onto a stack, so to maintain ordering we need to
	 * print these in reverse order.
	 */
	માટે (ai = la->addrs; ai; ai = ai->ai_next) {
		જો ((r = getnameinfo(ai->ai_addr, ai->ai_addrlen, addr,
		    કદ(addr), port, કદ(port),
		    NI_NUMERICHOST|NI_NUMERICSERV)) != 0) {
			error("getnameinfo: %.100s", ssh_gai_strerror(r));
			ચાલુ;
		}
		laddr2 = laddr1;
		જો (ai->ai_family == AF_INET6) {
			xasprintf(&laddr1, "ListenAddress [%s]:%s%s%s\n%s",
			    addr, port,
			    la->rdomain == ખાલી ? "" : " rdomain ",
			    la->rdomain == ખાલી ? "" : la->rdomain,
			    laddr2);
		} નહીંતર {
			xasprintf(&laddr1, "ListenAddress %s:%s%s%s\n%s",
			    addr, port,
			    la->rdomain == ખાલી ? "" : " rdomain ",
			    la->rdomain == ખાલી ? "" : la->rdomain,
			    laddr2);
		}
		મુક્ત(laddr2);
	}
	પાછા laddr1;
}

શૂન્ય
dump_config(ServerOptions *o)
{
	અક્ષર *s;
	u_int i;

	/* these are usually at the top of the config */
	માટે (i = 0; i < o->અંક_ports; i++)
		printf("Port %d\n", o->ports[i]);
	dump_cfg_fmtint(sAddressFamily, o->address_family);

	માટે (i = 0; i < o->અંક_listen_addrs; i++) {
		s = format_listen_addrs(&o->listen_addrs[i]);
		printf("%s", s);
		મુક્ત(s);
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
	dump_cfg_int(s_Client_Alive_ગણતરી_Max, o->client_alive_ગણતરી_max);
	dump_cfg_int(sRequiredRSASize, o->required_rsa_size);
	dump_cfg_oct(sStreamLocalBindMask, o->fwd_opts.streamlocal_bind_mask);
	dump_cfg_int(sUnusedConnectionTimeout, o->unused_connection_timeout);

	/* formatted integer arguments */
	dump_cfg_fmtint(s_Permit_મૂળ_Login, o->permit_મૂળ_login);
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
	dump_cfg_string(sTrustedUserCAKeys, o->trusted_user_ca_ચાવીઓ);
	dump_cfg_string(s_Security_ચાવી_Provider, o->sk_provider);
	dump_cfg_string(sAuthorizedPrincipalsFile,
	    o->authorized_principals_file);
	dump_cfg_string(sVersionAddendum, *o->version_addendum == '\0'
	    ? "none" : o->version_addendum);
	dump_cfg_string(s_Authorized_ચાવીઓ_Command, o->authorized_ચાવીઓ_command);
	dump_cfg_string(s_Authorized_ચાવીઓ_Command_User, o->authorized_ચાવીઓ_command_user);
	dump_cfg_string(sAuthorizedPrincipalsCommand, o->authorized_principals_command);
	dump_cfg_string(sAuthorizedPrincipalsCommandUser, o->authorized_principals_command_user);
	dump_cfg_string(s_Host_ચાવી_Agent, o->host_ચાવી_agent);
	dump_cfg_string(sKexAlgorithms, o->kex_algorithms);
	dump_cfg_string(sCASignatureAlgorithms, o->ca_sign_algorithms);
	dump_cfg_string(sHostbasedAcceptedAlgorithms, o->hostbased_accepted_algos);
	dump_cfg_string(s_Host_ચાવી_Algorithms, o->hostkeyalgorithms);
	dump_cfg_string(sPubkeyAcceptedAlgorithms, o->pubkey_accepted_algos);
#જો defined(__OpenBSD__) || defined(HAVE_SYS_SET_PROCESS_RDOMAIN)
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
	dump_cfg_strarray_oneline(s_Authorized_ચાવીઓ_File, o->અંક_authkeys_files,
	    o->authorized_ચાવીઓ_files);
	dump_cfg_strarray_oneline(s_Revoked_ચાવીઓ, o->અંક_revoked_ચાવીઓ_files,
	    o->revoked_ચાવીઓ_files);
	dump_cfg_strarray(s_Host_ચાવી, o->અંક_host_ચાવી_files, o->host_ચાવી_files);
	dump_cfg_strarray(sHostCertificate, o->અંક_host_cert_files,
	    o->host_cert_files);
	dump_cfg_strarray(sAllowUsers, o->અંક_allow_users, o->allow_users);
	dump_cfg_strarray(sDenyUsers, o->અંક_deny_users, o->deny_users);
	dump_cfg_strarray(sAllowGroups, o->અંક_allow_groups, o->allow_groups);
	dump_cfg_strarray(sDenyGroups, o->અંક_deny_groups, o->deny_groups);
	dump_cfg_strarray(sAcceptEnv, o->અંક_accept_env, o->accept_env);
	dump_cfg_strarray(sSetEnv, o->અંક_setenv, o->setenv);
	dump_cfg_strarray_oneline(sAuthenticationMethods,
	    o->અંક_auth_methods, o->auth_methods);
	dump_cfg_strarray_oneline(sLogVerbose,
	    o->અંક_log_verbose, o->log_verbose);
	dump_cfg_strarray_oneline(sChannelTimeout,
	    o->અંક_channel_timeouts, o->channel_timeouts);

	/* other arguments */
	માટે (i = 0; i < o->અંક_subsystems; i++)
		printf("Subsystem %s %s\n", o->subsystem_name[i],
		    o->subsystem_args[i]);

	printf("MaxStartups %d:%d:%d\n", o->max_startups_begin,
	    o->max_startups_rate, o->max_startups);
	printf("PerSourceMaxStartups ");
	જો (o->per_source_max_startups == INT_MAX)
		printf("none\n");
	નહીંતર
		printf("%d\n", o->per_source_max_startups);
	printf("PerSourceNetBlockSize %d:%d\n", o->per_source_masklen_ipv4,
	    o->per_source_masklen_ipv6);

	s = ખાલી;
	માટે (i = 0; tunmode_desc[i].val != -1; i++) {
		જો (tunmode_desc[i].val == o->permit_tun) {
			s = tunmode_desc[i].text;
			તોડો;
		}
	}
	dump_cfg_string(sPermitTunnel, s);

	printf("IPQoS %s ", iptos2str(o->ip_qos_interactive));
	printf("%s\n", iptos2str(o->ip_qos_bulk));

	printf("RekeyLimit %llu %d\n", (unsigned long long)o->rekey_limit,
	    o->rekey_interval);

	printf("PermitOpen");
	જો (o->અંક_permitted_opens == 0)
		printf(" any");
	નહીંતર {
		માટે (i = 0; i < o->અંક_permitted_opens; i++)
			printf(" %s", o->permitted_opens[i]);
	}
	printf("\n");
	printf("PermitListen");
	જો (o->અંક_permitted_listens == 0)
		printf(" any");
	નહીંતર {
		માટે (i = 0; i < o->અંક_permitted_listens; i++)
			printf(" %s", o->permitted_listens[i]);
	}
	printf("\n");

	જો (o->permit_user_env_allowlist == ખાલી) {
		dump_cfg_fmtint(sPermitUserEnvironment, o->permit_user_env);
	} નહીંતર {
		printf("PermitUserEnvironment %s\n",
		    o->permit_user_env_allowlist);
	}

	printf("PubkeyAuthOptions");
	જો (o->pubkey_auth_options == 0)
		printf(" none");
	જો (o->pubkey_auth_options & PUBKEYAUTH_TOUCH_REQUIRED)
		printf(" touch-required");
	જો (o->pubkey_auth_options & PUBKEYAUTH_VERIFY_REQUIRED)
		printf(" verify-required");
	જો (o->max_pubkey_ok != -1)
		printf(" max-pk-ok:%d", o->max_pubkey_ok);
	printf("\n");

	જો (o->per_source_penalty.enabled) {
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
	} નહીંતર
		printf("PerSourcePenalties no\n");
}
