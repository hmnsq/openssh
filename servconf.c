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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>
#ಅನ್ತರ್ಭಾವ <sys/queue.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __OpenBSD__
#ಅನ್ತರ್ಭಾವ <sys/sysctl.h>
#ಆದರೆ_ಅಂತ್ಯ

#ಅನ್ತರ್ಭಾವ <netinet/in.h>
#ಅನ್ತರ್ಭಾವ <netinet/ip.h>
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_NET_ROUTE_H
#ಅನ್ತರ್ಭಾವ <net/route.h>
#ಆದರೆ_ಅಂತ್ಯ

#ಅನ್ತರ್ಭಾವ <ctype.h>
#ಅನ್ತರ್ಭಾವ <glob.h>
#ಅನ್ತರ್ಭಾವ <netdb.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <util.h>

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "ssh.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "servconf.h"
#ಅನ್ತರ್ಭಾವ "pathnames.h"
#ಅನ್ತರ್ಭಾವ "cipher.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "kex.h"
#ಅನ್ತರ್ಭಾವ "mac.h"
#ಅನ್ತರ್ಭಾವ "match.h"
#ಅನ್ತರ್ಭಾವ "channels.h"
#ಅನ್ತರ್ಭಾವ "groupaccess.h"
#ಅನ್ತರ್ಭಾವ "canohost.h"
#ಅನ್ತರ್ಭಾವ "packet.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "hostfile.h"
#ಅನ್ತರ್ಭಾವ "auth.h"
#ಅನ್ತರ್ಭಾವ "myproposal.h"
#ಅನ್ತರ್ಭಾವ "digest.h"
#ಅನ್ತರ್ಭಾವ "version.h"

#ವ್ಯಾಖ್ಯಾನಿಸು SSHD_CONFIG_BLOB_ಆವೃತ್ತಿ	1

#ಆದರೆ !defined(SSHD_PAM_SERVICE)
# define SSHD_PAM_SERVICE		"sshd"
#ಆದರೆ_ಅಂತ್ಯ

ಸ್ಥಿರ ಶೂನ್ಯ ಕೂಡಿಸು_listen_addr(ServerOptions *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ);
ಸ್ಥಿರ ಶೂನ್ಯ ಕೂಡಿಸು_one_listen_addr(ServerOptions *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ);
ಸ್ಥಿರ ಶೂನ್ಯ parse_server_config_ಆಳ(ServerOptions *options,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename, ರಚನೆ sshbuf *conf, ರಚನೆ include_list *includes,
    ರಚನೆ connection_info *connectinfo, ಪೂರ್ಣಾಂಕ flags, ಪೂರ್ಣಾಂಕ *activep, ಪೂರ್ಣಾಂಕ ಆಳ);

ಬಾಹ್ಯ ರಚನೆ sshbuf *cfg;

/* Initializes the server options to their default values. */

ಶೂನ್ಯ
initialize_server_options(ServerOptions *options)
{
	memset(options, 0, ಗಾತ್ರ(*options));
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_INT(var, conf, flags, ms, def, cp)	options->var = -1;
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_INTFLAG(var, conf, flags, def, cp)	options->var = -1;
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_STRING(var, conf, flags, cp)		options->var = ಖಾಲಿ;
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	options->nvar = 0; \
	options->var = ಖಾಲಿ;
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	init_##funcsuffix(options)
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_NONCONF(funcsuffix) \
	init_##funcsuffix(options)
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_DEPRECATE(conf, flags, opcode)		/*ಖಾಲಿಗಳು*/
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	options->var = ಖಾಲಿ;
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_ALIAS(old, conf, flags)			/*ಖಾಲಿಗಳು*/

	/* Using macros for these is a bit overkill but forces consistency */
#ವ್ಯಾಖ್ಯಾನಿಸು init_hostkeyfile(options) \
	options->host_ಕೀಲಿ_files = 0; \
	options->ಅಂಕೆ_host_ಕೀಲಿ_files = 0; \
	options->host_ಕೀಲಿ_file_userprovided = ಖಾಲಿ;
#ವ್ಯಾಖ್ಯಾನಿಸು init_ipqos(options) \
	options->ip_qos_interactive = -1; \
	options->ip_qos_bulk = -1;
#ವ್ಯಾಖ್ಯಾನಿಸು init_listenaddress(options) \
	options->queued_listen_addrs = ಖಾಲಿ; \
	options->ಅಂಕೆ_queued_listens = 0; \
	options->listen_addrs = ಖಾಲಿ; \
	options->ಅಂಕೆ_listen_addrs = 0;
#ವ್ಯಾಖ್ಯಾನಿಸು init_logfacility(options) \
	options->log_facility = SYSLOG_FACILITY_NOT_ಗಣ;
#ವ್ಯಾಖ್ಯಾನಿಸು init_loglevel(options) \
	options->log_level = SYSLOG_LEVEL_NOT_ಗಣ;
#ವ್ಯಾಖ್ಯಾನಿಸು init_ಪೋರ್ಟ್(options) \
	options->ಅಂಕೆ_ports = 0; \
	options->ports_from_cmdline = 0;
#ವ್ಯಾಖ್ಯಾನಿಸು init_gatewayports(options) \
	options->fwd_opts.gateway_ports = -1;
#ವ್ಯಾಖ್ಯಾನಿಸು init_streamlocalbindmask(options) \
	options->fwd_opts.streamlocal_bind_ಮುಖವಾಡ = (ಬಹುಲಕ_t)-1;
#ವ್ಯಾಖ್ಯಾನಿಸು init_streamlocalbindunlink(options) \
	options->fwd_opts.streamlocal_bind_unlink = -1;
#ವ್ಯಾಖ್ಯಾನಿಸು init_maxstartups(options) \
	options->max_startups_begin = -1; \
	options->max_startups_ದರ = -1; \
	options->max_startups = -1;
#ವ್ಯಾಖ್ಯಾನಿಸು init_permituserenv(options) \
	options->permit_user_env = -1; \
	options->permit_user_env_allowlist = ಖಾಲಿ;
#ವ್ಯಾಖ್ಯಾನಿಸು init_persourcenetblocksize(options) \
	options->ಪ್ರತಿ_ಮೂಲ_masklen_ipv4 = -1; \
	options->ಪ್ರತಿ_ಮೂಲ_masklen_ipv6 = -1;
#ವ್ಯಾಖ್ಯಾನಿಸು init_persourcepenalties(options) \
	options->ಪ್ರತಿ_ಮೂಲ_penalty_exempt = ಖಾಲಿ; \
	options->ಪ್ರತಿ_ಮೂಲ_penalty.enabled = -1; \
	options->ಪ್ರತಿ_ಮೂಲ_penalty.max_sources4 = -1; \
	options->ಪ್ರತಿ_ಮೂಲ_penalty.max_sources6 = -1; \
	options->ಪ್ರತಿ_ಮೂಲ_penalty.ಅತಿಪ್ರವಾಹ_ಬಹುಲಕ = -1; \
	options->ಪ್ರತಿ_ಮೂಲ_penalty.ಅತಿಪ್ರವಾಹ_mode6 = -1; \
	options->ಪ್ರತಿ_ಮೂಲ_penalty.penalty_crash = -1.0; \
	options->ಪ್ರತಿ_ಮೂಲ_penalty.penalty_authfail = -1.0; \
	options->ಪ್ರತಿ_ಮೂಲ_penalty.penalty_invaliduser = -1.0; \
	options->ಪ್ರತಿ_ಮೂಲ_penalty.penalty_noauth = -1.0; \
	options->ಪ್ರತಿ_ಮೂಲ_penalty.penalty_grace = -1.0; \
	options->ಪ್ರತಿ_ಮೂಲ_penalty.penalty_refuseconnection = -1.0; \
	options->ಪ್ರತಿ_ಮೂಲ_penalty.penalty_max = -1.0; \
	options->ಪ್ರತಿ_ಮೂಲ_penalty.penalty_min = -1.0;
#ವ್ಯಾಖ್ಯಾನಿಸು init_rekeylimit(options) \
	options->rekey_ಎಲ್ಲೆ = -1; \
	options->rekey_interval = -1;
#ವ್ಯಾಖ್ಯಾನಿಸು init_subsystem(options) \
	options->ಅಂಕೆ_subsystems = 0; \
	options->subsystem_name = ಖಾಲಿ; \
	options->subsystem_command = ಖಾಲಿ; \
	options->subsystem_ವಾದಗಳು = ಖಾಲಿ;
#ವ್ಯಾಖ್ಯಾನಿಸು init_pubkey_auth_options(options) \
	options->pubkey_auth_options = -1; \
	options->max_pubkey_ok = -1;
#ವ್ಯಾಖ್ಯಾನಿಸು init_timingsecret(options) \
	options->timing_secret = 0;

	SSHD_CONFIG_ENTRIES

#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು init_hostkeyfile
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು init_ipqos
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು init_listenaddress
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು init_logfacility
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು init_loglevel
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು init_ಪೋರ್ಟ್
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು init_gatewayports
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು init_streamlocalbindmask
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು init_streamlocalbindunlink
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು init_maxstartups
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು init_permituserenv
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು init_persourcenetblocksize
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು init_persourcepenalties
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು init_rekeylimit
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು init_subsystem
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು init_timingsecret
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_INT
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_INTFLAG
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_STRING
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_STRARRAY
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_CUSTOM
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_NONCONF
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_DEPRECATE
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_UNSUPPORTED_INT
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_UNSUPPORTED_STRING
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_ALIAS
}

/* Returns 1 if a string option is unset or set to "none" or 0 otherwise. */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
option_clear_or_none(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *o)
{
	ಹಿಂತಿರುಗಿ o == ಖಾಲಿ || strcasecmp(o, "none") == 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
assemble_algorithms(ServerOptions *o)
{
	ಅಕ್ಷರ *all_cipher, *all_mac, *all_kex, *all_ಕೀಲಿ, *all_sig;
	ಅಕ್ಷರ *def_cipher, *def_mac, *def_kex, *def_ಕೀಲಿ, *def_sig;
	ಪೂರ್ಣಾಂಕ r;

	all_cipher = cipher_alg_list(',', 0);
	all_mac = mac_alg_list(',');
	all_kex = kex_alg_list(',');
	all_ಕೀಲಿ = sshkey_alg_list(0, 0, 1, ',');
	all_sig = sshkey_alg_list(0, 1, 1, ',');
	/* remove unsupported algos from default lists */
	def_cipher = ಹೊಂದಿಕೆ_filter_allowlist(KEX_SERVER_ENCRYPT, all_cipher);
	def_mac = ಹೊಂದಿಕೆ_filter_allowlist(KEX_SERVER_MAC, all_mac);
	def_kex = ಹೊಂದಿಕೆ_filter_allowlist(KEX_SERVER_KEX, all_kex);
	def_ಕೀಲಿ = ಹೊಂದಿಕೆ_filter_allowlist(KEX_DEFAULT_PK_ALG, all_ಕೀಲಿ);
	def_sig = ಹೊಂದಿಕೆ_filter_allowlist(SSH_ALLOWED_CA_SIGALGS, all_sig);
#ವ್ಯಾಖ್ಯಾನಿಸು ASSEMBLE(what, defaults, all) \
	ಮಾಡು { \
		ಆದರೆ ((r = kex_assemble_ಹೆಸರುಗಳು(&o->what, defaults, all)) != 0) \
			fatal_fr(r, "%s", #what); \
	} ಆಗ (0)
	ASSEMBLE(ciphers, def_cipher, all_cipher);
	ASSEMBLE(macs, def_mac, all_mac);
	ASSEMBLE(kex_algorithms, def_kex, all_kex);
	ASSEMBLE(hostkeyalgorithms, def_ಕೀಲಿ, all_ಕೀಲಿ);
	ASSEMBLE(hostbased_accepted_algos, def_ಕೀಲಿ, all_ಕೀಲಿ);
	ASSEMBLE(pubkey_accepted_algos, def_ಕೀಲಿ, all_ಕೀಲಿ);
	ASSEMBLE(ca_sign_algorithms, def_sig, all_sig);
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ASSEMBLE
	ಬಿಡುಗಡೆ(all_cipher);
	ಬಿಡುಗಡೆ(all_mac);
	ಬಿಡುಗಡೆ(all_kex);
	ಬಿಡುಗಡೆ(all_ಕೀಲಿ);
	ಬಿಡುಗಡೆ(all_sig);
	ಬಿಡುಗಡೆ(def_cipher);
	ಬಿಡುಗಡೆ(def_mac);
	ಬಿಡುಗಡೆ(def_kex);
	ಬಿಡುಗಡೆ(def_ಕೀಲಿ);
	ಬಿಡುಗಡೆ(def_sig);
}

ಶೂನ್ಯ
servconf_ಕೂಡಿಸು_hostkey(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಸ್ಥಿರಾಂಕ ಪೂರ್ಣಾಂಕ ಸಾಲು,
    ServerOptions *options, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, ಪೂರ್ಣಾಂಕ userprovided)
{
	ಅಕ್ಷರ *apath = derelativise_ಮಾರ್ಗ(ಮಾರ್ಗ);

	opt_array_append2(file, ಸಾಲು, "HostKey",
	    &options->host_ಕೀಲಿ_files, &options->host_ಕೀಲಿ_file_userprovided,
	    &options->ಅಂಕೆ_host_ಕೀಲಿ_files, apath, userprovided);
	ಬಿಡುಗಡೆ(apath);
}

ಶೂನ್ಯ
servconf_ಕೂಡಿಸು_hostcert(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಸ್ಥಿರಾಂಕ ಪೂರ್ಣಾಂಕ ಸಾಲು,
    ServerOptions *options, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ)
{
	ಅಕ್ಷರ *apath = derelativise_ಮಾರ್ಗ(ಮಾರ್ಗ);

	opt_array_append(file, ಸಾಲು, "HostCertificate",
	    &options->host_cert_files, &options->ಅಂಕೆ_host_cert_files, apath);
	ಬಿಡುಗಡೆ(apath);
}

ಶೂನ್ಯ
fill_default_server_options(ServerOptions *options)
{
	u_int i;

	/* Portable-specific overrides */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SKIP_PRIVDROP
	ಆದರೆ (options->allow_streamlocal_forwarding != -1 &&
	    options->allow_streamlocal_forwarding != FORWARD_DENY)
		logit("StreamlocalForwarding is not supported on this system");
	options->allow_streamlocal_forwarding = 0;
	ಆದರೆ (options->fwd_opts.gateway_ports != -1 &&
	    options->fwd_opts.gateway_ports != 0)
		logit("GatewayPorts is not supported on this system");
	options->fwd_opts.gateway_ports = 0;
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_INT(var, conf, flags, ms, def, cp) \
	ಆದರೆ (options->var == -1) \
		options->var = def;
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	ಆದರೆ (options->var == -1) \
		options->var = def;
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_STRING(var, conf, flags, cp)		/* done manually */
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	/* done manually */
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	/* done manually */
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_NONCONF(funcsuffix)			/* done manually */
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_DEPRECATE(conf, flags, opcode)		/*ಖಾಲಿಗಳು*/
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	ಮಾಡು { \
		ಬಿಡುಗಡೆ(options->var); \
		options->var = ಖಾಲಿ; \
	} ಆಗ (0);
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_ALIAS(old, conf, flags)			/*ಖಾಲಿಗಳು*/

	/* XXX maybe use macros here too to force consistency? */

	SSHD_CONFIG_ENTRIES

#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_INT
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_INTFLAG
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_STRING
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_STRARRAY
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_CUSTOM
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_NONCONF
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_DEPRECATE
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_UNSUPPORTED_INT
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_UNSUPPORTED_STRING
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_ALIAS

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_PAM
	ಆದರೆ (options->pam_service_name == ಖಾಲಿ)
		options->pam_service_name = xstrdup(SSHD_PAM_SERVICE);
#ಆದರೆ_ಅಂತ್ಯ

	ಆದರೆ (options->ಅಂಕೆ_host_ಕೀಲಿ_files == 0) {
		/* fill default hostkeys */
		servconf_ಕೂಡಿಸು_hostkey("[default]", 0, options,
		    ಮಾರ್ಗ_HOST_RSA_ಕೀಲಿ_FILE, 0);
		servconf_ಕೂಡಿಸು_hostkey("[default]", 0, options,
		    ಮಾರ್ಗ_HOST_ECDSA_ಕೀಲಿ_FILE, 0);
		servconf_ಕೂಡಿಸು_hostkey("[default]", 0, options,
		    ಮಾರ್ಗ_HOST_ED25519_ಕೀಲಿ_FILE, 0);
		servconf_ಕೂಡಿಸು_hostkey("[default]", 0, options,
		    ಮಾರ್ಗ_HOST_MLDSA44_ED25519_ಕೀಲಿ_FILE, 0);
	}
	/* No certificates by default */
	ಆದರೆ (options->ಅಂಕೆ_ports == 0)
		options->ports[options->ಅಂಕೆ_ports++] = SSH_DEFAULT_ಪೋರ್ಟ್;
	ಆದರೆ (options->listen_addrs == ಖಾಲಿ)
		ಕೂಡಿಸು_listen_addr(options, ಖಾಲಿ, ಖಾಲಿ, 0);
	ಆದರೆ (options->pid_file == ಖಾಲಿ)
		options->pid_file = xstrdup(ಮಾರ್ಗ_SSH_DAEMON_PID_FILE);
	ಆದರೆ (options->moduli_file == ಖಾಲಿ)
		options->moduli_file = xstrdup(ಮಾರ್ಗ_DH_MODULI);
	ಆದರೆ (options->xauth_location == ಖಾಲಿ)
		options->xauth_location = xstrdup(ಮಾರ್ಗ_XAUTH);
	ಆದರೆ (options->log_facility == SYSLOG_FACILITY_NOT_ಗಣ)
		options->log_facility = SYSLOG_FACILITY_AUTH;
	ಆದರೆ (options->log_level == SYSLOG_LEVEL_NOT_ಗಣ)
		options->log_level = SYSLOG_LEVEL_INFO;
	ಆದರೆ (options->permit_user_env == -1) {
		options->permit_user_env = 0;
		options->permit_user_env_allowlist = ಖಾಲಿ;
	}
	ಆದರೆ (options->rekey_ಎಲ್ಲೆ == -1)
		options->rekey_ಎಲ್ಲೆ = 0;
	ಆದರೆ (options->rekey_interval == -1)
		options->rekey_interval = 0;
	ಆದರೆ (options->fwd_opts.gateway_ports == -1)
		options->fwd_opts.gateway_ports = 0;
	ಆದರೆ (options->max_startups == -1)
		options->max_startups = 100;
	ಆದರೆ (options->max_startups_ದರ == -1)
		options->max_startups_ದರ = 30;		/* 30% */
	ಆದರೆ (options->max_startups_begin == -1)
		options->max_startups_begin = 10;
	ಆದರೆ (options->ಪ್ರತಿ_ಮೂಲ_masklen_ipv4 == -1)
		options->ಪ್ರತಿ_ಮೂಲ_masklen_ipv4 = 32;
	ಆದರೆ (options->ಪ್ರತಿ_ಮೂಲ_masklen_ipv6 == -1)
		options->ಪ್ರತಿ_ಮೂಲ_masklen_ipv6 = 128;
	ಆದರೆ (options->ಪ್ರತಿ_ಮೂಲ_penalty.enabled == -1)
		options->ಪ್ರತಿ_ಮೂಲ_penalty.enabled = 1;
	ಆದರೆ (options->ಪ್ರತಿ_ಮೂಲ_penalty.max_sources4 == -1)
		options->ಪ್ರತಿ_ಮೂಲ_penalty.max_sources4 = 65536;
	ಆದರೆ (options->ಪ್ರತಿ_ಮೂಲ_penalty.max_sources6 == -1)
		options->ಪ್ರತಿ_ಮೂಲ_penalty.max_sources6 = 65536;
	ಆದರೆ (options->ಪ್ರತಿ_ಮೂಲ_penalty.ಅತಿಪ್ರವಾಹ_ಬಹುಲಕ == -1)
		options->ಪ್ರತಿ_ಮೂಲ_penalty.ಅತಿಪ್ರವಾಹ_ಬಹುಲಕ = ಪ್ರತಿ_ಮೂಲ_PENALTY_ಅತಿಪ್ರವಾಹ_PERMISSIVE;
	ಆದರೆ (options->ಪ್ರತಿ_ಮೂಲ_penalty.ಅತಿಪ್ರವಾಹ_mode6 == -1)
		options->ಪ್ರತಿ_ಮೂಲ_penalty.ಅತಿಪ್ರವಾಹ_mode6 = options->ಪ್ರತಿ_ಮೂಲ_penalty.ಅತಿಪ್ರವಾಹ_ಬಹುಲಕ;
	ಆದರೆ (options->ಪ್ರತಿ_ಮೂಲ_penalty.penalty_crash < 0.0)
		options->ಪ್ರತಿ_ಮೂಲ_penalty.penalty_crash = 90.0;
	ಆದರೆ (options->ಪ್ರತಿ_ಮೂಲ_penalty.penalty_grace < 0.0)
		options->ಪ್ರತಿ_ಮೂಲ_penalty.penalty_grace = 10.0;
	ಆದರೆ (options->ಪ್ರತಿ_ಮೂಲ_penalty.penalty_authfail < 0.0)
		options->ಪ್ರತಿ_ಮೂಲ_penalty.penalty_authfail = 5.0;
	ಆದರೆ (options->ಪ್ರತಿ_ಮೂಲ_penalty.penalty_invaliduser < 0.0)
		options->ಪ್ರತಿ_ಮೂಲ_penalty.penalty_invaliduser = 5.0;
	ಆದರೆ (options->ಪ್ರತಿ_ಮೂಲ_penalty.penalty_noauth < 0.0)
		options->ಪ್ರತಿ_ಮೂಲ_penalty.penalty_noauth = 1.0;
	ಆದರೆ (options->ಪ್ರತಿ_ಮೂಲ_penalty.penalty_refuseconnection < 0.0)
		options->ಪ್ರತಿ_ಮೂಲ_penalty.penalty_refuseconnection = 10.0;
	ಆದರೆ (options->ಪ್ರತಿ_ಮೂಲ_penalty.penalty_min < 0.0)
		options->ಪ್ರತಿ_ಮೂಲ_penalty.penalty_min = 15.0;
	ಆದರೆ (options->ಪ್ರತಿ_ಮೂಲ_penalty.penalty_max < 0.0)
		options->ಪ್ರತಿ_ಮೂಲ_penalty.penalty_max = 600.0;
	ಆದರೆ (options->ಅಂಕೆ_authkeys_files == 0) {
		opt_array_append("[default]", 0, "AuthorizedKeysFiles",
		    &options->authorized_ಕೀಲಿಗಳು_files,
		    &options->ಅಂಕೆ_authkeys_files,
		    ಮಾರ್ಗ_SSH_USER_PERMITTED_ಕೀಲಿಗಳು);
		opt_array_append("[default]", 0, "AuthorizedKeysFiles",
		    &options->authorized_ಕೀಲಿಗಳು_files,
		    &options->ಅಂಕೆ_authkeys_files,
		    ಮಾರ್ಗ_SSH_USER_PERMITTED_KEYS2);
	}
	ಆದರೆ (options->ip_qos_interactive == -1)
		options->ip_qos_interactive = IPTOS_DSCP_EF;
	ಆದರೆ (options->ip_qos_bulk == -1)
		options->ip_qos_bulk = IPTOS_DSCP_CS0;
	ಆದರೆ (options->ಆವೃತ್ತಿ_addendum == ಖಾಲಿ)
		options->ಆವೃತ್ತಿ_addendum = xstrdup("");
	ಆದರೆ (options->fwd_opts.streamlocal_bind_ಮುಖವಾಡ == (ಬಹುಲಕ_t)-1)
		options->fwd_opts.streamlocal_bind_ಮುಖವಾಡ = 0177;
	ಆದರೆ (options->fwd_opts.streamlocal_bind_unlink == -1)
		options->fwd_opts.streamlocal_bind_unlink = 0;
	ಆದರೆ (options->sk_provider == ಖಾಲಿ)
		options->sk_provider = xstrdup("internal");
	ಆದರೆ (options->sshd_session_ಮಾರ್ಗ == ಖಾಲಿ)
		options->sshd_session_ಮಾರ್ಗ = xstrdup(ಮಾರ್ಗ_SSHD_SESSION);
	ಆದರೆ (options->sshd_auth_ಮಾರ್ಗ == ಖಾಲಿ)
		options->sshd_auth_ಮಾರ್ಗ = xstrdup(ಮಾರ್ಗ_SSHD_AUTH);
	ಆದರೆ (options->pubkey_auth_options == -1) {
		options->pubkey_auth_options = 0;
		options->max_pubkey_ok = DEFAULT_AUTH_FAIL_MAX;
	}
	ಆದರೆ (options->agent_socket_ಮಾರ್ಗ == ಖಾಲಿ)
		options->agent_socket_ಮಾರ್ಗ = xstrdup(ಮಾರ್ಗ_SSH_AGENT_SOCKET_DIR);

	assemble_algorithms(options);

#ವ್ಯಾಖ್ಯಾನಿಸು CLEAR_ON_NONE(v) \
	ಮಾಡು { \
		ಆದರೆ (option_clear_or_none(v)) { \
			ಬಿಡುಗಡೆ(v); \
			v = ಖಾಲಿ; \
		} \
	} ಆಗ(0)
#ವ್ಯಾಖ್ಯಾನಿಸು CLEAR_ON_NONE_ARRAY(v, nv, none) \
	ಮಾಡು { \
		ಆದರೆ (options->nv == 1 && \
		    strcasecmp(options->v[0], none) == 0) { \
			ಬಿಡುಗಡೆ(options->v[0]); \
			ಬಿಡುಗಡೆ(options->v); \
			options->v = ಖಾಲಿ; \
			options->nv = 0; \
		} \
	} ಆಗ (0)
	CLEAR_ON_NONE(options->pid_file);
	CLEAR_ON_NONE(options->xauth_location);
	CLEAR_ON_NONE(options->banner);
	CLEAR_ON_NONE(options->trusted_user_ca_ಕೀಲಿಗಳು);
	CLEAR_ON_NONE(options->sk_provider);
	CLEAR_ON_NONE(options->authorized_principals_file);
	CLEAR_ON_NONE(options->adm_forced_command);
	CLEAR_ON_NONE(options->chroot_directory);
	CLEAR_ON_NONE(options->routing_domain);
	CLEAR_ON_NONE(options->host_ಕೀಲಿ_agent);
	CLEAR_ON_NONE(options->ಪ್ರತಿ_ಮೂಲ_penalty_exempt);
	CLEAR_ON_NONE(options->agent_socket_ಮಾರ್ಗ);

	ಗಾಗಿ (i = 0; i < options->ಅಂಕೆ_host_ಕೀಲಿ_files; i++)
		CLEAR_ON_NONE(options->host_ಕೀಲಿ_files[i]);
	ಗಾಗಿ (i = 0; i < options->ಅಂಕೆ_host_cert_files; i++)
		CLEAR_ON_NONE(options->host_cert_files[i]);

	CLEAR_ON_NONE_ARRAY(channel_timeouts, ಅಂಕೆ_channel_timeouts, "none");
	CLEAR_ON_NONE_ARRAY(auth_methods, ಅಂಕೆ_auth_methods, "any");
	CLEAR_ON_NONE_ARRAY(revoked_ಕೀಲಿಗಳು_files, ಅಂಕೆ_revoked_ಕೀಲಿಗಳು_files, "none");
	CLEAR_ON_NONE_ARRAY(authorized_ಕೀಲಿಗಳು_files, ಅಂಕೆ_authkeys_files, "none");
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು CLEAR_ON_NONE
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು CLEAR_ON_NONE_ARRAY
}

/* Macros to declare ServerOpCodes enum values */
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_INT(var, conf, flags, ms, def, cp)	s##conf,
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_INTFLAG(var, conf, flags, def, cp)	s##conf,
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_STRING(var, conf, flags, cp)		s##conf,
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	s##conf,
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	s##conf,
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_NONCONF(funcsuffix)			/*ಖಾಲಿಗಳು*/
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_DEPRECATE(conf, flags, opcode)		/*ಖಾಲಿಗಳು*/
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_UNSUPPORTED_INT(var, conf, flags)	/*ಖಾಲಿಗಳು*/
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	/*ಖಾಲಿಗಳು*/
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_ALIAS(old, conf, flags)			/*ಖಾಲಿಗಳು*/

/* Keyword tokens. */
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಎಣಿಕೆ {
	sBadOption,		/* == unknown option */
	SSHD_CONFIG_ENTRIES
	s_ಹೊಂದಿಕೆ, sInclude,
	sDeprecated, sIgnore, sUnsupported
} ServerOpCodes;
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_INT
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_INTFLAG
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_STRING
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_STRARRAY
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_CUSTOM
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_NONCONF
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_DEPRECATE
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_UNSUPPORTED_INT
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_UNSUPPORTED_STRING
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_ALIAS

#ವ್ಯಾಖ್ಯಾನಿಸು SSHCFG_GLOBAL		0x01	/* allowed in main section of config */
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCFG_ಹೊಂದಿಕೆ		0x02	/* allowed inside a Match section */
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCFG_ALL		(SSHCFG_GLOBAL|SSHCFG_ಹೊಂದಿಕೆ)
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCFG_NEVERMATCH	0x04  /* Match never matches; internal only */
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCFG_ಹೊಂದಿಕೆ_ONLY	0x08  /* Match only in conditional blocks; internal only */

/* Macros to define keywords[] entries */
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_KW(conf, flags)		{ #conf, s##conf, flags },
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_INT(var, conf, flags, ms, def, cp)	SSHCONF_KW(conf, flags)
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_INTFLAG(var, conf, flags, def, cp)	SSHCONF_KW(conf, flags)
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_STRING(var, conf, flags, cp)		SSHCONF_KW(conf, flags)
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	SSHCONF_KW(conf, flags)
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	SSHCONF_KW(conf, flags)
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_NONCONF(funcsuffix)			/*ಖಾಲಿಗಳು*/
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_DEPRECATED				sDeprecated
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_IGNORE					sIgnore
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_DEPRECATE(conf, flags, opcode) \
	{ #conf, opcode, flags },
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_UNSUPPORTED_INT(var, conf, flags) \
	{ #conf, sUnsupported, flags },
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	{ #conf, sUnsupported, flags },
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_ALIAS(old, conf, flags) \
	{ #old, s##conf, flags },

/* Textual representation of the tokens. */
ಸ್ಥಿರ ರಚನೆ {
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name;
	ServerOpCodes opcode;
	u_int flags;
} keywords[] = {
	SSHD_CONFIG_ENTRIES
	{ "match", s_ಹೊಂದಿಕೆ, SSHCFG_ALL },
	{ "include", sInclude, SSHCFG_ALL },
	{ ಖಾಲಿ, sBadOption, 0 }
};
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_INT
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_INTFLAG
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_STRING
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_STRARRAY
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_CUSTOM
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_NONCONF
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_DEPRECATED
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_IGNORE
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_DEPRECATE
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_UNSUPPORTED_INT
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_UNSUPPORTED_STRING
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_ALIAS

ಸ್ಥಿರ ರಚನೆ {
	ಪೂರ್ಣಾಂಕ val;
	ಅಕ್ಷರ *ಪಠ್ಯ;
} tunmode_desc[] = {
	{ SSH_TUNMODE_NO, "no" },
	{ SSH_TUNMODE_POINTOPOINT, "point-to-point" },
	{ SSH_TUNMODE_ETHERNET, "ethernet" },
	{ SSH_TUNMODE_YES, "yes" },
	{ -1, ಖಾಲಿ }
};

/* Returns an opcode name from its number */

ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
lookup_opcode_name(ServerOpCodes ಸಂಕೇತ_2)
{
	u_int i;

	ಗಾಗಿ (i = 0; keywords[i].name != ಖಾಲಿ; i++)
		ಆದರೆ (keywords[i].opcode == ಸಂಕೇತ_2)
			ಹಿಂತಿರುಗಿ(keywords[i].name);
	ಹಿಂತಿರುಗಿ "UNKNOWN";
}


/*
 * Returns the number of the token pointed to by cp or sBadOption.
 */

ಸ್ಥಿರ ServerOpCodes
parse_token(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *cp, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename,
	    ಪೂರ್ಣಾಂಕ linenum, u_int *flags)
{
	u_int i;

	ಗಾಗಿ (i = 0; keywords[i].name; i++)
		ಆದರೆ (strcasecmp(cp, keywords[i].name) == 0) {
			*flags = keywords[i].flags;
			ಹಿಂತಿರುಗಿ keywords[i].opcode;
		}

	error("%s: line %d: Bad configuration option: %s",
	    filename, linenum, cp);
	ಹಿಂತಿರುಗಿ sBadOption;
}

ಅಕ್ಷರ *
derelativise_ಮಾರ್ಗ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ)
{
	ಅಕ್ಷರ *expanded, *ret, cwd[PATH_MAX];

	ಆದರೆ (strcasecmp(ಮಾರ್ಗ, "none") == 0)
		ಹಿಂತಿರುಗಿ xstrdup("none");
	expanded = tilde_expand_filename(ಮಾರ್ಗ, getuid());
	ಆದರೆ (ಮಾರ್ಗ_absolute(expanded))
		ಹಿಂತಿರುಗಿ expanded;
	ಆದರೆ (getcwd(cwd, ಗಾತ್ರ(cwd)) == ಖಾಲಿ)
		fatal_f("getcwd: %s", strerror(errno));
	xasprintf(&ret, "%s/%s", cwd, expanded);
	ಬಿಡುಗಡೆ(expanded);
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಶೂನ್ಯ
ಕೂಡಿಸು_listen_addr(ServerOptions *options, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *addr,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *rdomain, ಪೂರ್ಣಾಂಕ ಪೋರ್ಟ್)
{
	u_int i;

	ಆದರೆ (ಪೋರ್ಟ್ > 0)
		ಕೂಡಿಸು_one_listen_addr(options, addr, rdomain, ಪೋರ್ಟ್);
	ಇಲ್ಲದಿದ್ದರೆ {
		ಗಾಗಿ (i = 0; i < options->ಅಂಕೆ_ports; i++) {
			ಕೂಡಿಸು_one_listen_addr(options, addr, rdomain,
			    options->ports[i]);
		}
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
ಕೂಡಿಸು_one_listen_addr(ServerOptions *options, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *addr,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *rdomain, ಪೂರ್ಣಾಂಕ ಪೋರ್ಟ್)
{
	ರಚನೆ addrinfo hints, *ai, *aitop;
	ಅಕ್ಷರ strport[NI_MAXSERV];
	ಪೂರ್ಣಾಂಕ gaierr;
	u_int i;

	/* Find listen_addrs entry for this rdomain */
	ಗಾಗಿ (i = 0; i < options->ಅಂಕೆ_listen_addrs; i++) {
		ಆದರೆ (rdomain == ಖಾಲಿ && options->listen_addrs[i].rdomain == ಖಾಲಿ)
			ನಿಲ್ಲಿಸು;
		ಆದರೆ (rdomain == ಖಾಲಿ || options->listen_addrs[i].rdomain == ಖಾಲಿ)
			ಮುಂದುವರಿ;
		ಆದರೆ (strcmp(rdomain, options->listen_addrs[i].rdomain) == 0)
			ನಿಲ್ಲಿಸು;
	}
	ಆದರೆ (i >= options->ಅಂಕೆ_listen_addrs) {
		/* No entry for this rdomain; allocate one */
		ಆದರೆ (i >= ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ)
			fatal_f("too many listen addresses");
		options->listen_addrs = xrecallocarray(options->listen_addrs,
		    options->ಅಂಕೆ_listen_addrs, options->ಅಂಕೆ_listen_addrs + 1,
		    ಗಾತ್ರ(*options->listen_addrs));
		i = options->ಅಂಕೆ_listen_addrs++;
		ಆದರೆ (rdomain != ಖಾಲಿ)
			options->listen_addrs[i].rdomain = xstrdup(rdomain);
	}
	/* options->listen_addrs[i] points to the addresses for this rdomain */

	memset(&hints, 0, ಗಾತ್ರ(hints));
	hints.ai_family = options->ವಿಳಾಸ_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = (addr == ಖಾಲಿ) ? AI_PASSIVE : 0;
	snprintf(strport, ಗಾತ್ರ strport, "%d", ಪೋರ್ಟ್);
	ಆದರೆ ((gaierr = getaddrinfo(addr, strport, &hints, &aitop)) != 0)
		fatal("bad addr or host: %s (%s)",
		    addr ? addr : "<NULL>",
		    ssh_gai_strerror(gaierr));
	ಗಾಗಿ (ai = aitop; ai->ai_next; ai = ai->ai_next)
		;
	ai->ai_next = options->listen_addrs[i].addrs;
	options->listen_addrs[i].addrs = aitop;
}

/* Returns nonzero if the routing domain name is valid */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
valid_rdomain(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name)
{
#ಆದರೆ defined(HAVE_SYS_VALID_RDOMAIN)
	ಹಿಂತಿರುಗಿ sys_valid_rdomain(name);
#ಅಥವಾಆದರೆ defined(__OpenBSD__)
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *errstr;
	ದೀರ್ಘ ದೀರ್ಘ ಅಂಕೆ;
	ರಚನೆ rt_tableinfo info;
	ಪೂರ್ಣಾಂಕ mib[6];
	ಗಾತ್ರ_t miblen = ಗಾತ್ರ(mib);

	ಆದರೆ (name == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 1;

	ಅಂಕೆ = strtonum(name, 0, 255, &errstr);
	ಆದರೆ (errstr != ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;

	/* Check whether the table actually exists */
	memset(mib, 0, ಗಾತ್ರ(mib));
	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[4] = NET_RT_ಕೋಷ್ಟಕ;
	mib[5] = (ಪೂರ್ಣಾಂಕ)ಅಂಕೆ;
	ಆದರೆ (sysctl(mib, 6, &info, &miblen, ಖಾಲಿ, 0) == -1)
		ಹಿಂತಿರುಗಿ 0;

	ಹಿಂತಿರುಗಿ 1;
#ಇಲ್ಲದಿದ್ದರೆ /* defined(__OpenBSD__) */
	error("Routing domains are not supported on this platform");
	ಹಿಂತಿರುಗಿ 0;
#ಆದರೆ_ಅಂತ್ಯ
}

/*
 * Queue a ListenAddress to be processed once we have all of the Ports
 * and AddressFamily options.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
ಸರತಿ_listen_addr(ServerOptions *options, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *addr,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *rdomain, ಪೂರ್ಣಾಂಕ ಪೋರ್ಟ್)
{
	ರಚನೆ queued_listenaddr *qla;

	options->queued_listen_addrs = xrecallocarray(
	    options->queued_listen_addrs,
	    options->ಅಂಕೆ_queued_listens, options->ಅಂಕೆ_queued_listens + 1,
	    ಗಾತ್ರ(*options->queued_listen_addrs));
	qla = &options->queued_listen_addrs[options->ಅಂಕೆ_queued_listens++];
	qla->addr = xstrdup(addr);
	qla->ಪೋರ್ಟ್ = ಪೋರ್ಟ್;
	qla->rdomain = rdomain == ಖಾಲಿ ? ಖಾಲಿ : xstrdup(rdomain);
}

/*
 * Process queued (text) ListenAddress entries.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
process_queued_listen_addrs(ServerOptions *options)
{
	u_int i;
	ರಚನೆ queued_listenaddr *qla;

	ಆದರೆ (options->ಅಂಕೆ_ports == 0)
		options->ports[options->ಅಂಕೆ_ports++] = SSH_DEFAULT_ಪೋರ್ಟ್;
	ಆದರೆ (options->ವಿಳಾಸ_family == -1)
		options->ವಿಳಾಸ_family = AF_UNSPEC;

	ಗಾಗಿ (i = 0; i < options->ಅಂಕೆ_queued_listens; i++) {
		qla = &options->queued_listen_addrs[i];
		ಕೂಡಿಸು_listen_addr(options, qla->addr, qla->rdomain, qla->ಪೋರ್ಟ್);
		ಬಿಡುಗಡೆ(qla->addr);
		ಬಿಡುಗಡೆ(qla->rdomain);
	}
	ಬಿಡುಗಡೆ(options->queued_listen_addrs);
	options->queued_listen_addrs = ಖಾಲಿ;
	options->ಅಂಕೆ_queued_listens = 0;
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

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಹೊಂದಿಕೆ_cfg_ಸಾಲು_ಗುಂಪು(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *grps, ಪೂರ್ಣಾಂಕ ಸಾಲು, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *user)
{
	ಪೂರ್ಣಾಂಕ ಫಲಿತಾಂಶ = 0;
	ರಚನೆ passwd *pw;

	ಆದರೆ (user == ಖಾಲಿ)
		ಹೋಗು ಹೊರಹೋಗು;

	ಆದರೆ ((pw = getpwnam(user)) == ಖಾಲಿ) {
		debug("Can't match group at line %d because user %.100s does "
		    "not exist", ಸಾಲು, user);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ga_init(pw->pw_name, pw->pw_gid) == 0) {
		debug("Can't Match group because user %.100s not in any group "
		    "at line %d", user, ಸಾಲು);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ga_ಹೊಂದಿಕೆ_ನಮೂನೆ_list(grps) != 1) {
		debug("user %.100s does not match group list %.100s at line %d",
		    user, grps, ಸಾಲು);
	} ಇಲ್ಲದಿದ್ದರೆ {
		debug("user %.100s matched group list %.100s at line %d", user,
		    grps, ಸಾಲು);
		ಫಲಿತಾಂಶ = 1;
	}
ಹೊರಹೋಗು:
	ga_free();
	ಹಿಂತಿರುಗಿ ಫಲಿತಾಂಶ;
}

ಸ್ಥಿರ ಶೂನ್ಯ
ಹೊಂದಿಕೆ_test_missing_fatal(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *criteria, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *attrib)
{
	fatal("'Match %s' in configuration but '%s' not in connection "
	    "test specification.", criteria, attrib);
}

/*
 * All of the attributes on a single Match line are ANDed together, so we need
 * to check every attribute and set the result to zero if any attribute does
 * not match.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಹೊಂದಿಕೆ_cfg_ಸಾಲು(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ತುಂಬಿದ_ಸಾಲು, ಪೂರ್ಣಾಂಕ *acp, ಅಕ್ಷರ ***avp,
    ಪೂರ್ಣಾಂಕ ಸಾಲು, ರಚನೆ connection_info *ci)
{
	ಪೂರ್ಣಾಂಕ ಫಲಿತಾಂಶ = 1, ಗುಣಲಕ್ಷಣಗಳು = 0, ಪೋರ್ಟ್;
	ಅಕ್ಷರ *arg, *attrib = ಖಾಲಿ, *oattrib;

	ಆದರೆ (ci == ಖಾಲಿ) {
		debug3("checking syntax for 'Match %s' on line %d",
		    ತುಂಬಿದ_ಸಾಲು, ಸಾಲು);
	} ಇಲ್ಲದಿದ್ದರೆ {
		debug3("checking match for '%s' user %s%s host %s addr %s "
		    "laddr %s lport %d rdomain %s on line %d", ತುಂಬಿದ_ಸಾಲು,
		    ci->user ? ci->user : "(null)",
		    ci->user_invalid ? " (invalid)" : "",
		    ci->host ? ci->host : "(null)",
		    ci->ವಿಳಾಸ ? ci->ವಿಳಾಸ : "(null)",
		    ci->laddress ? ci->laddress : "(null)", ci->lport,
		    ci->rdomain ? ci->rdomain : "(null)", ಸಾಲು);
	}

	ಆಗ ((oattrib = argv_ಮುಂದಿನ(acp, avp)) != ಖಾಲಿ) {
		/* Terminate on comment */
		ಆದರೆ (*oattrib == '#') {
			argv_consume(acp); /* mark all arguments consumed */
			ನಿಲ್ಲಿಸು;
		}
		attrib = xstrdup(oattrib);
		arg = ಖಾಲಿ;
		ಗುಣಲಕ್ಷಣಗಳು++;
		/* Criterion "all" has no argument and must appear alone */
		ಆದರೆ (strcasecmp(attrib, "all") == 0) {
			ಆದರೆ (ಗುಣಲಕ್ಷಣಗಳು > 1 ||
			    ((arg = argv_ಮುಂದಿನ(acp, avp)) != ಖಾಲಿ &&
			    *arg != '\0' && *arg != '#')) {
				error("'all' cannot be combined with other "
				    "Match attributes");
				ಫಲಿತಾಂಶ = -1;
				ಹೋಗು ಹೊರಹೋಗು;
			}
			ಆದರೆ (arg != ಖಾಲಿ && *arg == '#')
				argv_consume(acp); /* consume remaining args */
			ಫಲಿತಾಂಶ = 1;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		/* Criterion "invalid-user" also has no argument */
		ಆದರೆ (strcasecmp(attrib, "invalid-user") == 0) {
			ಆದರೆ (ci == ಖಾಲಿ) {
				ಫಲಿತಾಂಶ = 0;
				ಹೋಗು ಮುಂದಿನ;
			}
			ಆದರೆ (ci->user_invalid == 0)
				ಫಲಿತಾಂಶ = 0;
			ಇಲ್ಲದಿದ್ದರೆ
				debug("matched invalid-user at line %d", ಸಾಲು);
			ಹೋಗು ಮುಂದಿನ;
		}

		/* Keep this list in sync with below */
		ಆದರೆ (strprefix(attrib, "user=", 1) != ಖಾಲಿ ||
		    strprefix(attrib, "group=", 1) != ಖಾಲಿ ||
		    strprefix(attrib, "host=", 1) != ಖಾಲಿ ||
		    strprefix(attrib, "address=", 1) != ಖಾಲಿ ||
		    strprefix(attrib, "localaddress=", 1) != ಖಾಲಿ ||
		    strprefix(attrib, "localport=", 1) != ಖಾಲಿ ||
		    strprefix(attrib, "rdomain=", 1) != ಖಾಲಿ ||
		    strprefix(attrib, "version=", 1) != ಖಾಲಿ) {
			arg = strchr(attrib, '=');
			*(arg++) = '\0';
		} ಇಲ್ಲದಿದ್ದರೆ {
			arg = argv_ಮುಂದಿನ(acp, avp);
		}

		/* All other criteria require an argument */
		ಆದರೆ (arg == ಖಾಲಿ || *arg == '\0' || *arg == '#') {
			error("Missing Match criteria for %s", attrib);
			ಫಲಿತಾಂಶ = -1;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (strcasecmp(attrib, "user") == 0) {
			ಆದರೆ (ci == ಖಾಲಿ || (ci->test && ci->user == ಖಾಲಿ)) {
				ಫಲಿತಾಂಶ = 0;
				ಹೋಗು ಮುಂದಿನ;
			}
			ಆದರೆ (ci->user == ಖಾಲಿ)
				ಹೊಂದಿಕೆ_test_missing_fatal("User", "user");
			ಆದರೆ (ಹೊಂದಿಕೆ_usergroup_ನಮೂನೆ_list(ci->user, arg) != 1)
				ಫಲಿತಾಂಶ = 0;
			ಇಲ್ಲದಿದ್ದರೆ
				debug("user %.100s matched 'User %.100s' at "
				    "line %d", ci->user, arg, ಸಾಲು);
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcasecmp(attrib, "group") == 0) {
			ಆದರೆ (ci == ಖಾಲಿ || (ci->test && ci->user == ಖಾಲಿ)) {
				ಫಲಿತಾಂಶ = 0;
				ಹೋಗು ಮುಂದಿನ;
			}
			ಆದರೆ (ci->user == ಖಾಲಿ)
				ಹೊಂದಿಕೆ_test_missing_fatal("Group", "user");
			ಆಯ್ಕೆ (ಹೊಂದಿಕೆ_cfg_ಸಾಲು_ಗುಂಪು(arg, ಸಾಲು, ci->user)) {
			ಸ್ಥಿತಿ -1:
				ಫಲಿತಾಂಶ = -1;
				ಹೋಗು ಹೊರಹೋಗು;
			ಸ್ಥಿತಿ 0:
				ಫಲಿತಾಂಶ = 0;
			}
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcasecmp(attrib, "host") == 0) {
			ಆದರೆ (ci == ಖಾಲಿ || (ci->test && ci->host == ಖಾಲಿ)) {
				ಫಲಿತಾಂಶ = 0;
				ಹೋಗು ಮುಂದಿನ;
			}
			ಆದರೆ (ci->host == ಖಾಲಿ)
				ಹೊಂದಿಕೆ_test_missing_fatal("Host", "host");
			ಆದರೆ (ಹೊಂದಿಕೆ_hostname(ci->host, arg) != 1)
				ಫಲಿತಾಂಶ = 0;
			ಇಲ್ಲದಿದ್ದರೆ
				debug("connection from %.100s matched 'Host "
				    "%.100s' at line %d", ci->host, arg, ಸಾಲು);
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcasecmp(attrib, "address") == 0) {
			ಆದರೆ (ci == ಖಾಲಿ || (ci->test && ci->ವಿಳಾಸ == ಖಾಲಿ)) {
				ಆದರೆ (addr_ಹೊಂದಿಕೆ_list(ಖಾಲಿ, arg) != 0)
					fatal("Invalid Match address argument "
					    "'%s' at line %d", arg, ಸಾಲು);
				ಫಲಿತಾಂಶ = 0;
				ಹೋಗು ಮುಂದಿನ;
			}
			ಆದರೆ (ci->ವಿಳಾಸ == ಖಾಲಿ)
				ಹೊಂದಿಕೆ_test_missing_fatal("Address", "addr");
			ಆಯ್ಕೆ (addr_ಹೊಂದಿಕೆ_list(ci->ವಿಳಾಸ, arg)) {
			ಸ್ಥಿತಿ 1:
				debug("connection from %.100s matched 'Address "
				    "%.100s' at line %d", ci->ವಿಳಾಸ, arg, ಸಾಲು);
				ನಿಲ್ಲಿಸು;
			ಸ್ಥಿತಿ 0:
			ಸ್ಥಿತಿ -1:
				ಫಲಿತಾಂಶ = 0;
				ನಿಲ್ಲಿಸು;
			ಸ್ಥಿತಿ -2:
				ಫಲಿತಾಂಶ = -1;
				ಹೋಗು ಹೊರಹೋಗು;
			}
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcasecmp(attrib, "localaddress") == 0){
			ಆದರೆ (ci == ಖಾಲಿ || (ci->test && ci->laddress == ಖಾಲಿ)) {
				ಆದರೆ (addr_ಹೊಂದಿಕೆ_list(ಖಾಲಿ, arg) != 0)
					fatal("Invalid Match localaddress "
					    "argument '%s' at line %d", arg,
					    ಸಾಲು);
				ಫಲಿತಾಂಶ = 0;
				ಹೋಗು ಮುಂದಿನ;
			}
			ಆದರೆ (ci->laddress == ಖಾಲಿ)
				ಹೊಂದಿಕೆ_test_missing_fatal("LocalAddress",
				    "laddr");
			ಆಯ್ಕೆ (addr_ಹೊಂದಿಕೆ_list(ci->laddress, arg)) {
			ಸ್ಥಿತಿ 1:
				debug("connection from %.100s matched "
				    "'LocalAddress %.100s' at line %d",
				    ci->laddress, arg, ಸಾಲು);
				ನಿಲ್ಲಿಸು;
			ಸ್ಥಿತಿ 0:
			ಸ್ಥಿತಿ -1:
				ಫಲಿತಾಂಶ = 0;
				ನಿಲ್ಲಿಸು;
			ಸ್ಥಿತಿ -2:
				ಫಲಿತಾಂಶ = -1;
				ಹೋಗು ಹೊರಹೋಗು;
			}
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcasecmp(attrib, "localport") == 0) {
			ಆದರೆ ((ಪೋರ್ಟ್ = a2port(arg)) == -1) {
				error("Invalid LocalPort '%s' on Match line",
				    arg);
				ಫಲಿತಾಂಶ = -1;
				ಹೋಗು ಹೊರಹೋಗು;
			}
			ಆದರೆ (ci == ಖಾಲಿ || (ci->test && ci->lport == -1)) {
				ಫಲಿತಾಂಶ = 0;
				ಹೋಗು ಮುಂದಿನ;
			}
			ಆದರೆ (ci->lport == 0)
				ಹೊಂದಿಕೆ_test_missing_fatal("LocalPort", "lport");
			/* TODO support port lists */
			ಆದರೆ (ಪೋರ್ಟ್ == ci->lport)
				debug("connection from %.100s matched "
				    "'LocalPort %d' at line %d",
				    ci->laddress, ಪೋರ್ಟ್, ಸಾಲು);
			ಇಲ್ಲದಿದ್ದರೆ
				ಫಲಿತಾಂಶ = 0;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcasecmp(attrib, "rdomain") == 0) {
			ಆದರೆ (ci == ಖಾಲಿ || (ci->test && ci->rdomain == ಖಾಲಿ)) {
				ಫಲಿತಾಂಶ = 0;
				ಹೋಗು ಮುಂದಿನ;
			}
			ಆದರೆ (ci->rdomain == ಖಾಲಿ)
				ಹೊಂದಿಕೆ_test_missing_fatal("RDomain", "rdomain");
			ಆದರೆ (ಹೊಂದಿಕೆ_ನಮೂನೆ_list(ci->rdomain, arg, 0) != 1)
				ಫಲಿತಾಂಶ = 0;
			ಇಲ್ಲದಿದ್ದರೆ
				debug("connection RDomain %.100s matched "
				    "'RDomain %.100s' at line %d",
				    ci->rdomain, arg, ಸಾಲು);
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcasecmp(attrib, "version") == 0) {
			ಆದರೆ (ಹೊಂದಿಕೆ_ನಮೂನೆ_list(SSH_RELEASE, arg, 0) != 1)
				ಫಲಿತಾಂಶ = 0;
			ಇಲ್ಲದಿದ್ದರೆ
				debug("version %.100s matched "
				    "'version %.100s' at line %d",
				    SSH_RELEASE, arg, ಸಾಲು);
		} ಇಲ್ಲದಿದ್ದರೆ {
			error("Unsupported Match attribute %s", oattrib);
			ಫಲಿತಾಂಶ = -1;
			ಹೋಗು ಹೊರಹೋಗು;
		}
 ಮುಂದಿನ:
		ಬಿಡುಗಡೆ(attrib);
		attrib = ಖಾಲಿ;
	}
	ಆದರೆ (ಗುಣಲಕ್ಷಣಗಳು == 0) {
		error("One or more attributes required for Match");
		ಹಿಂತಿರುಗಿ -1;
	}
 ಹೊರಹೋಗು:
	ಆದರೆ (ci != ಖಾಲಿ && ಫಲಿತಾಂಶ != -1)
		debug3("match %sfound on line %d", ಫಲಿತಾಂಶ ? "" : "not ", ಸಾಲು);
	ಬಿಡುಗಡೆ(attrib);
	ಹಿಂತಿರುಗಿ ಫಲಿತಾಂಶ;
}

#ವ್ಯಾಖ್ಯಾನಿಸು WHITESPACE " \t\r\n"

/* Multistate option parsing */
ರಚನೆ multistate {
	ಅಕ್ಷರ *ಕೀಲಿ;
	ಪೂರ್ಣಾಂಕ ಮೌಲ್ಯ;
};
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ರಚನೆ multistate multistate_flag[] = {
	{ "yes",			1 },
	{ "no",				0 },
	{ ಖಾಲಿ, -1 }
};
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ರಚನೆ multistate multistate_ignore_rhosts[] = {
	{ "yes",			IGNORE_RHOSTS_YES },
	{ "no",				IGNORE_RHOSTS_NO },
	{ "shosts-only",		IGNORE_RHOSTS_SHOSTS },
	{ ಖಾಲಿ, -1 }
};
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ರಚನೆ multistate multistate_addressfamily[] = {
	{ "inet",			AF_INET },
	{ "inet6",			AF_INET6 },
	{ "any",			AF_UNSPEC },
	{ ಖಾಲಿ, -1 }
};
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ರಚನೆ multistate multistate_permitrootlogin[] = {
	{ "prohibit-password",		PERMIT_NO_PASSWD },
	{ "without-password",		PERMIT_NO_PASSWD },
	{ "forced-commands-only",	PERMIT_FORCED_ONLY },
	{ "yes",			PERMIT_YES },
	{ "no",				PERMIT_NO },
	{ ಖಾಲಿ, -1 }
};
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ರಚನೆ multistate multistate_compression[] = {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_ZLIB
	{ "yes",			COMP_DELAYED },
	{ "delayed",			COMP_DELAYED },
#ಆದರೆ_ಅಂತ್ಯ
	{ "no",				COMP_NONE },
	{ ಖಾಲಿ, -1 }
};
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ರಚನೆ multistate multistate_gatewayports[] = {
	{ "clientspecified",		2 },
	{ "yes",			1 },
	{ "no",				0 },
	{ ಖಾಲಿ, -1 }
};
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ರಚನೆ multistate multistate_tcpfwd[] = {
	{ "yes",			FORWARD_ALLOW },
	{ "all",			FORWARD_ALLOW },
	{ "no",				FORWARD_DENY },
	{ "remote",			FORWARD_REMOTE },
	{ "local",			FORWARD_LOCAL },
	{ ಖಾಲಿ, -1 }
};
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ರಚನೆ multistate multistate_keepalives[] = {
	{ "true",			SSH_KEEPALIVES_TRANSPORT },
	{ "false",			SSH_KEEPALIVES_OFF },
	{ "yes",			SSH_KEEPALIVES_TRANSPORT },
	{ "no",				SSH_KEEPALIVES_OFF },
	{ "transport",			SSH_KEEPALIVES_TRANSPORT },
	{ "all",			SSH_KEEPALIVES_ALL },
	{ ಖಾಲಿ, -1 }
};
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ರಚನೆ multistate multistate_warnweakcrypto[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "no-pq-kex",			0 },
	{ ಖಾಲಿ, -1 }
};

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
process_server_config_ಸಾಲು_ಆಳ(ServerOptions *options, ಅಕ್ಷರ *ಸಾಲು,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename, ಪೂರ್ಣಾಂಕ linenum, ಪೂರ್ಣಾಂಕ *activep,
    ರಚನೆ connection_info *connectinfo, ಪೂರ್ಣಾಂಕ *inc_flags, ಪೂರ್ಣಾಂಕ ಆಳ,
    ರಚನೆ include_list *includes)
{
	ಅಕ್ಷರ *str, ***chararrayptr, **charptr, *arg, *arg2, *p, *keyword;
	ಪೂರ್ಣಾಂಕ cmdline = 0, *intptr, ಮೌಲ್ಯ, value2, value3, n, ಪೋರ್ಟ್, oactive, r;
	ದ್ವಿಗುಣ dvalue, *doubleptr = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ ca_only = 0, ಸಿಕ್ಕಿತು = 0;
	SyslogFacility *log_facility_ptr;
	LogLevel *log_level_ptr;
	ServerOpCodes opcode;
	u_int i, *uintptr, flags = 0;
	ಗಾತ್ರ_t len;
	ದೀರ್ಘ ದೀರ್ಘ val64;
	ಸ್ಥಿರಾಂಕ ರಚನೆ multistate *multistate_ptr;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *errstr;
	ರಚನೆ include_ಅಂಶ *ಅಂಶ;
	glob_t gbuf;
	ಅಕ್ಷರ **oav = ಖಾಲಿ, **av;
	ಪೂರ್ಣಾಂಕ oac = 0, ac;
	ಪೂರ್ಣಾಂಕ ret = -1;
	ಅಕ್ಷರ **strs = ಖಾಲಿ; /* string array arguments; freed implicitly */
	u_int nstrs = 0;

	/* Strip trailing whitespace. Allow \f (form feed) at EOL only */
	ಆದರೆ ((len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಸಾಲು)) == 0)
		ಹಿಂತಿರುಗಿ 0;
	ಗಾಗಿ (len--; len > 0; len--) {
		ಆದರೆ (strchr(WHITESPACE "\f", ಸಾಲು[len]) == ಖಾಲಿ)
			ನಿಲ್ಲಿಸು;
		ಸಾಲು[len] = '\0';
	}

	str = ಸಾಲು;
	ಆದರೆ ((keyword = strdelim(&str)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	/* Ignore leading whitespace */
	ಆದರೆ (*keyword == '\0')
		keyword = strdelim(&str);
	ಆದರೆ (!keyword || !*keyword || *keyword == '#')
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (str == ಖಾಲಿ || *str == '\0') {
		error("%s line %d: no argument after keyword \"%s\"",
		    filename, linenum, keyword);
		ಹಿಂತಿರುಗಿ -1;
	}
	intptr = ಖಾಲಿ;
	charptr = ಖಾಲಿ;
	opcode = parse_token(keyword, filename, linenum, &flags);

	ಆದರೆ (argv_ವಿಭಜಿಸು(str, &oac, &oav, 1) != 0) {
		error("%s line %d: invalid quotes", filename, linenum);
		ಹಿಂತಿರುಗಿ -1;
	}
	ac = oac;
	av = oav;

	ಆದರೆ (activep == ಖಾಲಿ) { /* We are processing a command line directive */
		cmdline = 1;
		activep = &cmdline;
	}
	ಆದರೆ (*activep && opcode != s_ಹೊಂದಿಕೆ && opcode != sInclude)
		debug3("%s:%d setting %s %s", filename, linenum, keyword, str);
	ಆದರೆ (*activep == 0 && !(flags & SSHCFG_ಹೊಂದಿಕೆ)) {
		ಆದರೆ (connectinfo == ಖಾಲಿ) {
			fatal("%s line %d: Directive '%s' is not allowed "
			    "within a Match block", filename, linenum, keyword);
		} ಇಲ್ಲದಿದ್ದರೆ { /* this is a directive we have already processed */
			ret = 0;
			ಹೋಗು ಹೊರಹೋಗು;
		}
	}

	ಆಯ್ಕೆ (opcode) {
	/* Portable-specific options */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_PAM
	ಸ್ಥಿತಿ sUsePAM:
		intptr = &options->use_pam;
		ಹೋಗು parse_flag;
	ಸ್ಥಿತಿ sPAMServiceName:
		charptr = &options->pam_service_name;
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0') {
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		}
		ಆದರೆ (*activep && *charptr == ಖಾಲಿ)
			*charptr = xstrdup(arg);
		ನಿಲ್ಲಿಸು;
#ಆದರೆ_ಅಂತ್ಯ

	/* Standard Options */
	ಸ್ಥಿತಿ sBadOption:
		ಹೋಗು ಹೊರಹೋಗು;
	ಸ್ಥಿತಿ s_ಪೋರ್ಟ್:
		/* ignore ports from configfile if cmdline specifies ports */
		ಆದರೆ (options->ports_from_cmdline) {
			argv_consume(&ac);
			ನಿಲ್ಲಿಸು;
		}
		ಆದರೆ (options->ಅಂಕೆ_ports >= MAX_PORTS)
			fatal("%s line %d: too many ports.",
			    filename, linenum);
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0')
			fatal("%s line %d: missing port number.",
			    filename, linenum);
		options->ports[options->ಅಂಕೆ_ports++] = a2port(arg);
		ಆದರೆ (options->ports[options->ಅಂಕೆ_ports-1] <= 0)
			fatal("%s line %d: Badly formatted port number.",
			    filename, linenum);
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ s_Login_Grace_ಸಮಯ:
		intptr = &options->login_grace_ಸಮಯ;
 parse_ಸಮಯ:
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0')
			fatal("%s line %d: missing time value.",
			    filename, linenum);
		ಆದರೆ ((ಮೌಲ್ಯ = convtime(arg)) == -1)
			fatal("%s line %d: invalid time value.",
			    filename, linenum);
		ಆದರೆ (*activep && *intptr == -1)
			*intptr = ಮೌಲ್ಯ;
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ s_Listen_ವಿಳಾಸ:
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (arg == ಖಾಲಿ || *arg == '\0')
			fatal("%s line %d: missing address",
			    filename, linenum);
		/* check for bare IPv6 address: no "[]" and 2 or more ":" */
		ಆದರೆ (strchr(arg, '[') == ಖಾಲಿ && (p = strchr(arg, ':')) != ಖಾಲಿ
		    && strchr(p+1, ':') != ಖಾಲಿ) {
			ಪೋರ್ಟ್ = 0;
			p = arg;
		} ಇಲ್ಲದಿದ್ದರೆ {
			arg2 = ಖಾಲಿ;
			p = hpdelim(&arg);
			ಆದರೆ (p == ಖಾಲಿ)
				fatal("%s line %d: bad address:port usage",
				    filename, linenum);
			p = cleanhostname(p);
			ಆದರೆ (arg == ಖಾಲಿ)
				ಪೋರ್ಟ್ = 0;
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((ಪೋರ್ಟ್ = a2port(arg)) <= 0)
				fatal("%s line %d: bad port number",
				    filename, linenum);
		}
		/* Optional routing table */
		arg2 = ಖಾಲಿ;
		ಆದರೆ ((arg = argv_ಮುಂದಿನ(&ac, &av)) != ಖಾಲಿ) {
			ಆದರೆ (strcmp(arg, "rdomain") != 0 ||
			    (arg2 = argv_ಮುಂದಿನ(&ac, &av)) == ಖಾಲಿ)
				fatal("%s line %d: bad ListenAddress syntax",
				    filename, linenum);
			ಆದರೆ (!valid_rdomain(arg2))
				fatal("%s line %d: bad routing domain",
				    filename, linenum);
		}
		ಸರತಿ_listen_addr(options, p, arg2, ಪೋರ್ಟ್);

		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ s_ವಿಳಾಸ_Family:
		intptr = &options->ವಿಳಾಸ_family;
		multistate_ptr = multistate_addressfamily;
 parse_multistate:
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0')
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		ಮೌಲ್ಯ = -1;
		ಗಾಗಿ (i = 0; multistate_ptr[i].ಕೀಲಿ != ಖಾಲಿ; i++) {
			ಆದರೆ (strcasecmp(arg, multistate_ptr[i].ಕೀಲಿ) == 0) {
				ಮೌಲ್ಯ = multistate_ptr[i].ಮೌಲ್ಯ;
				ನಿಲ್ಲಿಸು;
			}
		}
		ಆದರೆ (ಮೌಲ್ಯ == -1)
			fatal("%s line %d: unsupported option \"%s\".",
			    filename, linenum, arg);
		ಆದರೆ (*activep && *intptr == -1)
			*intptr = ಮೌಲ್ಯ;
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ s_Host_ಕೀಲಿ:
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		ಆದರೆ (*activep) {
			servconf_ಕೂಡಿಸು_hostkey(filename, linenum,
			    options, arg, 1);
		}
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ s_Host_ಕೀಲಿ_Agent:
		charptr = &options->host_ಕೀಲಿ_agent;
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0')
			fatal("%s line %d: missing socket name.",
			    filename, linenum);
		ಆದರೆ (*activep && *charptr == ಖಾಲಿ)
			*charptr = !strcmp(arg, SSH_AUTHSOCKET_ENV_NAME) ?
			    xstrdup(arg) : derelativise_ಮಾರ್ಗ(arg);
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ sHostCertificate:
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		ಆದರೆ (*activep)
			servconf_ಕೂಡಿಸು_hostcert(filename, linenum, options, arg);
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ sPidFile:
		charptr = &options->pid_file;
 parse_filename:
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		ಆದರೆ (*activep && *charptr == ಖಾಲಿ) {
			*charptr = derelativise_ಮಾರ್ಗ(arg);
			/* increase optional counter */
			ಆದರೆ (intptr != ಖಾಲಿ)
				*intptr = *intptr + 1;
		}
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ sModuliFile:
		charptr = &options->moduli_file;
		ಹೋಗು parse_filename;

	ಸ್ಥಿತಿ s_Permit_ಬೇರು_Login:
		intptr = &options->permit_ಬೇರು_login;
		multistate_ptr = multistate_permitrootlogin;
		ಹೋಗು parse_multistate;

	ಸ್ಥಿತಿ sIgnoreRhosts:
		intptr = &options->ignore_rhosts;
		multistate_ptr = multistate_ignore_rhosts;
		ಹೋಗು parse_multistate;

	ಸ್ಥಿತಿ s_Ignore_User_ತಿಳಿದ_Hosts:
		intptr = &options->ignore_user_ತಿಳಿದ_hosts;
 parse_flag:
		multistate_ptr = multistate_flag;
		ಹೋಗು parse_multistate;

	ಸ್ಥಿತಿ sHostbasedAuthentication:
		intptr = &options->hostbased_authentication;
		ಹೋಗು parse_flag;

	ಸ್ಥಿತಿ s_Hostbased_ಬಳಸುತ್ತದೆ_Name_From_Packet_Only:
		intptr = &options->hostbased_ಬಳಸುತ್ತದೆ_name_from_packet_only;
		ಹೋಗು parse_flag;

	ಸ್ಥಿತಿ sHostbasedAcceptedAlgorithms:
		charptr = &options->hostbased_accepted_algos;
		ca_only = 0;
 parse_pubkey_algos:
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0')
			fatal("%s line %d: Missing argument.",
			    filename, linenum);
		ಆದರೆ (*arg != '-' &&
		    !sshkey_ಹೆಸರುಗಳು_valid2(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg, 1, ca_only))
			fatal("%s line %d: Bad key types '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		ಆದರೆ (*activep && *charptr == ಖಾಲಿ)
			*charptr = xstrdup(arg);
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ s_Host_ಕೀಲಿ_Algorithms:
		charptr = &options->hostkeyalgorithms;
		ca_only = 0;
		ಹೋಗು parse_pubkey_algos;

	ಸ್ಥಿತಿ sCASignatureAlgorithms:
		charptr = &options->ca_sign_algorithms;
		ca_only = 1;
		ಹೋಗು parse_pubkey_algos;

	ಸ್ಥಿತಿ sPubkeyAuthentication:
		intptr = &options->pubkey_authentication;
		ca_only = 0;
		ಹೋಗು parse_flag;

	ಸ್ಥಿತಿ sPubkeyAcceptedAlgorithms:
		charptr = &options->pubkey_accepted_algos;
		ca_only = 0;
		ಹೋಗು parse_pubkey_algos;

	ಸ್ಥಿತಿ sPubkeyAuthOptions:
		intptr = &options->pubkey_auth_options;
		ಮೌಲ್ಯ = 0;
		value2 = -1;
		ಆಗ ((arg = argv_ಮುಂದಿನ(&ac, &av)) != ಖಾಲಿ) {
			ಆದರೆ (strcasecmp(arg, "none") == 0)
				ಮುಂದುವರಿ;
			ಆದರೆ (strcasecmp(arg, "touch-required") == 0)
				ಮೌಲ್ಯ |= PUBKEYAUTH_TOUCH_REQUIRED;
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcasecmp(arg, "verify-required") == 0)
				ಮೌಲ್ಯ |= PUBKEYAUTH_VERIFY_REQUIRED;
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strncasecmp(arg, "max-pk-ok:", 10) == 0) {
				value2 = strtonum(arg + 10, 0, 255, &errstr);
				ಆದರೆ (errstr != ಖಾಲಿ) {
					error("%s line %d: bad %s max-pk-ok "
					    "value: %s", filename, linenum,
					keyword, errstr);
					ಹೋಗು ಹೊರಹೋಗು;
				}
			} ಇಲ್ಲದಿದ್ದರೆ {
				error("%s line %d: unsupported %s option %s",
				    filename, linenum, keyword, arg);
				ಹೋಗು ಹೊರಹೋಗು;
			}
		}
		ಆದರೆ (*activep && options->pubkey_auth_options == -1) {
			options->pubkey_auth_options = ಮೌಲ್ಯ;
			options->max_pubkey_ok = value2;
		}
		ನಿಲ್ಲಿಸು;

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ KRB5
	ಸ್ಥಿತಿ sKerberosAuthentication:
		intptr = &options->kerberos_authentication;
		ಹೋಗು parse_flag;

	ಸ್ಥಿತಿ sKerberosOrLocalPasswd:
		intptr = &options->kerberos_or_local_passwd;
		ಹೋಗು parse_flag;

	ಸ್ಥಿತಿ sKerberosTicketCleanup:
		intptr = &options->kerberos_ticket_cleanup;
		ಹೋಗು parse_flag;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_AFS
	ಸ್ಥಿತಿ sKerberosGetAFSToken:
		intptr = &options->kerberos_get_afs_token;
		ಹೋಗು parse_flag;
#ಆದರೆ_ಅಂತ್ಯ /* USE_AFS */
#ಆದರೆ_ಅಂತ್ಯ /* KRB5 */

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ GSSAPI
	ಸ್ಥಿತಿ sGSSAPIAuthentication:
		intptr = &options->gss_authentication;
		ಹೋಗು parse_flag;

	ಸ್ಥಿತಿ sGSSAPICleanupCredentials:
		intptr = &options->gss_cleanup_creds;
		ಹೋಗು parse_flag;

	ಸ್ಥಿತಿ sGSSAPIDelegateCredentials:
		intptr = &options->gss_deleg_creds;
		ಹೋಗು parse_flag;

	ಸ್ಥಿತಿ sGSSAPIStrictAcceptorCheck:
		intptr = &options->gss_strict_acceptor;
		ಹೋಗು parse_flag;
#ಆದರೆ_ಅಂತ್ಯ /* GSSAPI */

	ಸ್ಥಿತಿ sPasswordAuthentication:
		intptr = &options->password_authentication;
		ಹೋಗು parse_flag;

	ಸ್ಥಿತಿ sKbdInteractiveAuthentication:
		intptr = &options->kbd_interactive_authentication;
		ಹೋಗು parse_flag;

	ಸ್ಥಿತಿ sPrintMotd:
		intptr = &options->print_motd;
		ಹೋಗು parse_flag;

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ DISABLE_LASTLOG
	ಸ್ಥಿತಿ s_Print_ಕೊನೆಯ_Log:
		intptr = &options->print_lastlog;
		ಹೋಗು parse_flag;
#ಆದರೆ_ಅಂತ್ಯ

	ಸ್ಥಿತಿ sX11Forwarding:
		intptr = &options->x11_forwarding;
		ಹೋಗು parse_flag;

	ಸ್ಥಿತಿ s_X11_Display_ಸ್ಥಾನಾಂತರ:
		intptr = &options->x11_display_ಸ್ಥಾನಾಂತರ;
 parse_int:
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ ((errstr = atoi_err(arg, &ಮೌಲ್ಯ)) != ಖಾಲಿ)
			fatal("%s line %d: %s integer value %s.",
			    filename, linenum, keyword, errstr);
		ಆದರೆ (*activep && *intptr == -1)
			*intptr = ಮೌಲ್ಯ;
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ sX11UseLocalhost:
		intptr = &options->x11_use_localhost;
		ಹೋಗು parse_flag;

	ಸ್ಥಿತಿ sXAuthLocation:
		charptr = &options->xauth_location;
		ಹೋಗು parse_filename;

	ಸ್ಥಿತಿ sPermitTTY:
		intptr = &options->permit_tty;
		ಹೋಗು parse_flag;

	ಸ್ಥಿತಿ sPermitUserRC:
		intptr = &options->permit_user_rc;
		ಹೋಗು parse_flag;

	ಸ್ಥಿತಿ sStrictModes:
		intptr = &options->strict_modes;
		ಹೋಗು parse_flag;

	ಸ್ಥಿತಿ sTCPKeepAlive:
		intptr = &options->tcp_keep_alive;
		multistate_ptr = multistate_keepalives;
		ಹೋಗು parse_multistate;

	ಸ್ಥಿತಿ s_Permit_ಖಾಲಿಗಳು_Passwords:
		intptr = &options->permit_ಖಾಲಿಗಳು_passwd;
		ಹೋಗು parse_flag;

	ಸ್ಥಿತಿ sPermitUserEnvironment:
		intptr = &options->permit_user_env;
		charptr = &options->permit_user_env_allowlist;
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ಮೌಲ್ಯ = 0;
		p = ಖಾಲಿ;
		ಆದರೆ (strcmp(arg, "yes") == 0)
			ಮೌಲ್ಯ = 1;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(arg, "no") == 0)
			ಮೌಲ್ಯ = 0;
		ಇಲ್ಲದಿದ್ದರೆ {
			/* Pattern-list specified */
			ಮೌಲ್ಯ = 1;
			p = xstrdup(arg);
		}
		ಆದರೆ (*activep && *intptr == -1) {
			*intptr = ಮೌಲ್ಯ;
			*charptr = p;
			p = ಖಾಲಿ;
		}
		ಬಿಡುಗಡೆ(p);
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ sCompression:
		intptr = &options->compression;
		multistate_ptr = multistate_compression;
		ಹೋಗು parse_multistate;

	ಸ್ಥಿತಿ s_Rekey_ಎಲ್ಲೆ:
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ಆದರೆ (strcmp(arg, "default") == 0) {
			val64 = 0;
		} ಇಲ್ಲದಿದ್ದರೆ {
			ಆದರೆ (ಪರಿಶೀಲನೆ_scaled(arg, &val64) == -1)
				fatal("%.200s line %d: Bad %s number '%s': %s",
				    filename, linenum, keyword,
				    arg, strerror(errno));
			ಆದರೆ (val64 != 0 && val64 < 16)
				fatal("%.200s line %d: %s too small",
				    filename, linenum, keyword);
		}
		ಆದರೆ (*activep && options->rekey_ಎಲ್ಲೆ == -1)
			options->rekey_ಎಲ್ಲೆ = val64;
		ಆದರೆ (ac != 0) { /* optional rekey interval present */
			ಆದರೆ (strcmp(av[0], "none") == 0) {
				(ಶೂನ್ಯ)argv_ಮುಂದಿನ(&ac, &av);	/* discard */
				ನಿಲ್ಲಿಸು;
			}
			intptr = &options->rekey_interval;
			ಹೋಗು parse_ಸಮಯ;
		}
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ sGatewayPorts:
		intptr = &options->fwd_opts.gateway_ports;
		multistate_ptr = multistate_gatewayports;
		ಹೋಗು parse_multistate;

	ಸ್ಥಿತಿ sUseDNS:
		intptr = &options->use_dns;
		ಹೋಗು parse_flag;

	ಸ್ಥಿತಿ sSyslogFacility:
		log_facility_ptr = &options->log_facility;
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಮೌಲ್ಯ = log_facility_ಸಂಖ್ಯೆ(arg);
		ಆದರೆ (ಮೌಲ್ಯ == SYSLOG_FACILITY_NOT_ಗಣ)
			fatal("%.200s line %d: unsupported log facility '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
		ಆದರೆ (*log_facility_ptr == -1)
			*log_facility_ptr = (SyslogFacility) ಮೌಲ್ಯ;
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ sLogLevel:
		log_level_ptr = &options->log_level;
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಮೌಲ್ಯ = log_level_ಸಂಖ್ಯೆ(arg);
		ಆದರೆ (ಮೌಲ್ಯ == SYSLOG_LEVEL_NOT_ಗಣ)
			fatal("%.200s line %d: unsupported log level '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
		ಆದರೆ (*activep && *log_level_ptr == -1)
			*log_level_ptr = (LogLevel) ಮೌಲ್ಯ;
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ sLogVerbose:
		ಸಿಕ್ಕಿತು = options->ಅಂಕೆ_log_verbose == 0;
		ಆಗ ((arg = argv_ಮುಂದಿನ(&ac, &av)) != ಖಾಲಿ) {
			ಆದರೆ (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				ಹೋಗು ಹೊರಹೋಗು;
			}
			/* Allow "none" only in first position */
			ಆದರೆ (strcasecmp(arg, "none") == 0) {
				ಆದರೆ (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					ಹೋಗು ಹೊರಹೋಗು;
				}
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		ಆದರೆ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ಆದರೆ (ಸಿಕ್ಕಿತು && *activep) {
			options->log_verbose = strs;
			options->ಅಂಕೆ_log_verbose = nstrs;
			strs = ಖಾಲಿ; /* transferred */
			nstrs = 0;
		}
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ sAllowTcpForwarding:
		intptr = &options->allow_tcp_forwarding;
		multistate_ptr = multistate_tcpfwd;
		ಹೋಗು parse_multistate;

	ಸ್ಥಿತಿ s_Allow_ಹರಿವು_Local_Forwarding:
		intptr = &options->allow_streamlocal_forwarding;
		multistate_ptr = multistate_tcpfwd;
		ಹೋಗು parse_multistate;

	ಸ್ಥಿತಿ sAllowAgentForwarding:
		intptr = &options->allow_agent_forwarding;
		ಹೋಗು parse_flag;

	ಸ್ಥಿತಿ s_Agent_Socket_ಮಾರ್ಗ:
		charptr = &options->agent_socket_ಮಾರ್ಗ;
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0')
			fatal("%s line %d: missing path.", filename, linenum);
		ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(arg, "shared:", 7) == 0) {
			/* Shared paths must be absolute */
			ಆದರೆ (arg[7] != '/') {
				fatal("%s line %d: invalid shared path.",
				    filename, linenum);
			}
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(arg, "user:", 5) == 0) {
			/* User paths must not be empty */
			ಆದರೆ (arg[5] == '\0') {
				fatal("%s line %d: invalid user path.",
				    filename, linenum);
			}
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(arg, "none") != 0)
			fatal("%s line %d: invalid path.", filename, linenum);
		ಆದರೆ (*activep && *charptr == ಖಾಲಿ)
			*charptr = xstrdup(arg);
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ sDisableForwarding:
		intptr = &options->disable_forwarding;
		ಹೋಗು parse_flag;

	ಸ್ಥಿತಿ sAllowUsers:
		chararrayptr = &options->allow_users;
		uintptr = &options->ಅಂಕೆ_allow_users;
 parse_allowdenyusers:
		/* XXX appends to list; doesn't respect first-match-wins */
		ಆಗ ((arg = argv_ಮುಂದಿನ(&ac, &av)) != ಖಾಲಿ) {
			ಆದರೆ (*arg == '\0' ||
			    ಹೊಂದಿಕೆ_user(ಖಾಲಿ, ಖಾಲಿ, ಖಾಲಿ, arg) == -1)
				fatal("%s line %d: invalid %s pattern: \"%s\"",
				    filename, linenum, keyword, arg);
			ಸಿಕ್ಕಿತು = 1;
			ಆದರೆ (!*activep)
				ಮುಂದುವರಿ;
			opt_array_append(filename, linenum, keyword,
			    chararrayptr, uintptr, arg);
		}
		ಆದರೆ (!ಸಿಕ್ಕಿತು) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ sDenyUsers:
		chararrayptr = &options->deny_users;
		uintptr = &options->ಅಂಕೆ_deny_users;
		ಹೋಗು parse_allowdenyusers;

	ಸ್ಥಿತಿ sAllowGroups:
		chararrayptr = &options->allow_groups;
		uintptr = &options->ಅಂಕೆ_allow_groups;
		/* XXX appends to list; doesn't respect first-match-wins */
 parse_allowdenygroups:
		ಆಗ ((arg = argv_ಮುಂದಿನ(&ac, &av)) != ಖಾಲಿ) {
			ಆದರೆ (*arg == '\0')
				fatal("%s line %d: empty %s pattern",
				    filename, linenum, keyword);
			ಸಿಕ್ಕಿತು = 1;
			ಆದರೆ (!*activep)
				ಮುಂದುವರಿ;
			opt_array_append(filename, linenum, keyword,
			    chararrayptr, uintptr, arg);
		}
		ಆದರೆ (!ಸಿಕ್ಕಿತು) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ sDenyGroups:
		chararrayptr = &options->deny_groups;
		uintptr = &options->ಅಂಕೆ_deny_groups;
		ಹೋಗು parse_allowdenygroups;

	ಸ್ಥಿತಿ sCiphers:
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ಆದರೆ (*arg != '-' &&
		    !ciphers_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 cipher spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		ಆದರೆ (options->ciphers == ಖಾಲಿ)
			options->ciphers = xstrdup(arg);
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ sMacs:
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ಆದರೆ (*arg != '-' &&
		    !mac_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 mac spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		ಆದರೆ (options->macs == ಖಾಲಿ)
			options->macs = xstrdup(arg);
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ sKexAlgorithms:
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ಆದರೆ (*arg != '-' &&
		    !kex_ಹೆಸರುಗಳು_valid(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 KexAlgorithms '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		ಆದರೆ (options->kex_algorithms == ಖಾಲಿ)
			options->kex_algorithms = xstrdup(arg);
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ sSubsystem:
		ಆದರೆ ((arg = argv_ಮುಂದಿನ(&ac, &av)) == ಖಾಲಿ || *arg == '\0' ||
		   ((arg2 = argv_ಮುಂದಿನ(&ac, &av)) == ಖಾಲಿ || *arg2 == '\0'))
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ಆದರೆ (!*activep) {
			argv_consume(&ac);
			ನಿಲ್ಲಿಸು;
		}
		ಸಿಕ್ಕಿತು = 0;
		ಗಾಗಿ (i = 0; i < options->ಅಂಕೆ_subsystems; i++) {
			ಆದರೆ (strcmp(arg, options->subsystem_name[i]) == 0) {
				ಸಿಕ್ಕಿತು = 1;
				ನಿಲ್ಲಿಸು;
			}
		}
		ಆದರೆ (ಸಿಕ್ಕಿತು) {
			debug("%s line %d: Subsystem '%s' already defined.",
			    filename, linenum, arg);
			argv_consume(&ac);
			ನಿಲ್ಲಿಸು;
		}
		options->subsystem_name = xrecallocarray(
		    options->subsystem_name, options->ಅಂಕೆ_subsystems,
		    options->ಅಂಕೆ_subsystems + 1,
		    ಗಾತ್ರ(*options->subsystem_name));
		options->subsystem_command = xrecallocarray(
		    options->subsystem_command, options->ಅಂಕೆ_subsystems,
		    options->ಅಂಕೆ_subsystems + 1,
		    ಗಾತ್ರ(*options->subsystem_command));
		options->subsystem_ವಾದಗಳು = xrecallocarray(
		    options->subsystem_ವಾದಗಳು, options->ಅಂಕೆ_subsystems,
		    options->ಅಂಕೆ_subsystems + 1,
		    ಗಾತ್ರ(*options->subsystem_ವಾದಗಳು));
		options->subsystem_name[options->ಅಂಕೆ_subsystems] = xstrdup(arg);
		options->subsystem_command[options->ಅಂಕೆ_subsystems] =
		    xstrdup(arg2);
		/* Collect arguments (separate to executable) */
		arg = argv_assemble(1, &arg2); /* quote command correctly */
		arg2 = argv_assemble(ac, av); /* rest of command */
		xasprintf(&options->subsystem_ವಾದಗಳು[options->ಅಂಕೆ_subsystems],
		    "%s%s%s", arg, *arg2 == '\0' ? "" : " ", arg2);
		ಬಿಡುಗಡೆ(arg2);
		ಬಿಡುಗಡೆ(arg);
		argv_consume(&ac);
		options->ಅಂಕೆ_subsystems++;
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ sMaxStartups:
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		/* begin:rate:max */
		ಆದರೆ ((n = ಅಕ್ಷರಸರಣಿ_ಓದು(arg, "%d:%d:%d",
		    &ಮೌಲ್ಯ, &value2, &value3)) == 3) {
			ಆದರೆ (ಮೌಲ್ಯ > value3 || value2 > 100 || value2 < 1)
				fatal("%s line %d: Invalid %s spec.",
				    filename, linenum, keyword);
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (n == 1) {
			value3 = ಮೌಲ್ಯ;
			value2 = -1;
		} ಇಲ್ಲದಿದ್ದರೆ {
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		}
		ಆದರೆ (ಮೌಲ್ಯ <= 0 || value3 <= 0)
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		ಆದರೆ (*activep && options->max_startups == -1) {
			options->max_startups_begin = ಮೌಲ್ಯ;
			options->max_startups_ದರ = value2;
			options->max_startups = value3;
		}
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ s_ಪ್ರತಿ_ಮೂಲ_Net_ಖಂಡ_ಗಾತ್ರ:
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ಆಯ್ಕೆ (n = ಅಕ್ಷರಸರಣಿ_ಓದು(arg, "%d:%d", &ಮೌಲ್ಯ, &value2)) {
		ಸ್ಥಿತಿ 2:
			ಆದರೆ (value2 < 0 || value2 > 128)
				n = -1;
			/* FALLTHROUGH */
		ಸ್ಥಿತಿ 1:
			ಆದರೆ (ಮೌಲ್ಯ < 0 || ಮೌಲ್ಯ > 32)
				n = -1;
		}
		ಆದರೆ (n != 1 && n != 2)
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		ಆದರೆ (*activep && options->ಪ್ರತಿ_ಮೂಲ_masklen_ipv4 == -1) {
			options->ಪ್ರತಿ_ಮೂಲ_masklen_ipv4 = ಮೌಲ್ಯ;
			ಆದರೆ (n == 2)
				options->ಪ್ರತಿ_ಮೂಲ_masklen_ipv6 = value2;
		}
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ s_ಪ್ರತಿ_ಮೂಲ_Max_Startups:
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ಆದರೆ (strcmp(arg, "none") == 0) { /* no limit */
			ಮೌಲ್ಯ = ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ;
		} ಇಲ್ಲದಿದ್ದರೆ {
			ಆದರೆ ((errstr = atoi_err(arg, &ಮೌಲ್ಯ)) != ಖಾಲಿ)
				fatal("%s line %d: %s integer value %s.",
				    filename, linenum, keyword, errstr);
		}
		ಆದರೆ (*activep && options->ಪ್ರತಿ_ಮೂಲ_max_startups == -1)
			options->ಪ್ರತಿ_ಮೂಲ_max_startups = ಮೌಲ್ಯ;
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ s_ಪ್ರತಿ_ಮೂಲ_Penalty_Exempt_List:
		charptr = &options->ಪ್ರತಿ_ಮೂಲ_penalty_exempt;
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0')
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		ಆದರೆ (addr_ಹೊಂದಿಕೆ_list(ಖಾಲಿ, arg) != 0) {
			fatal("%s line %d: keyword %s "
			    "invalid address argument.",
			    filename, linenum, keyword);
		}
		ಆದರೆ (*activep && *charptr == ಖಾಲಿ)
			*charptr = xstrdup(arg);
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ s_ಪ್ರತಿ_ಮೂಲ_Penalties:
		ಆಗ ((arg = argv_ಮುಂದಿನ(&ac, &av)) != ಖಾಲಿ) {
			ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *q = ಖಾಲಿ;

			ಸಿಕ್ಕಿತು = 1;
			intptr = ಖಾಲಿ;
			doubleptr = ಖಾಲಿ;
			ಮೌಲ್ಯ = -1;
			value2 = 0;
			/* Allow no/yes only in first position */
			ಆದರೆ (strcasecmp(arg, "no") == 0 ||
			    (value2 = (strcasecmp(arg, "yes") == 0))) {
				ಆದರೆ (ac > 0) {
					fatal("%s line %d: keyword %s \"%s\" "
					    "argument must appear alone.",
					    filename, linenum, keyword, arg);
				}
				ಆದರೆ (*activep &&
				    options->ಪ್ರತಿ_ಮೂಲ_penalty.enabled == -1)
					options->ಪ್ರತಿ_ಮೂಲ_penalty.enabled = value2;
				ಮುಂದುವರಿ;
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((q = strprefix(arg, "crash:", 0)) != ಖಾಲಿ) {
				doubleptr = &options->ಪ್ರತಿ_ಮೂಲ_penalty.penalty_crash;
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((q = strprefix(arg, "authfail:", 0)) != ಖಾಲಿ) {
				doubleptr = &options->ಪ್ರತಿ_ಮೂಲ_penalty.penalty_authfail;
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((q = strprefix(arg, "invaliduser:", 0)) != ಖಾಲಿ) {
				doubleptr = &options->ಪ್ರತಿ_ಮೂಲ_penalty.penalty_invaliduser;
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((q = strprefix(arg, "noauth:", 0)) != ಖಾಲಿ) {
				doubleptr = &options->ಪ್ರತಿ_ಮೂಲ_penalty.penalty_noauth;
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((q = strprefix(arg, "grace-exceeded:", 0)) != ಖಾಲಿ) {
				doubleptr = &options->ಪ್ರತಿ_ಮೂಲ_penalty.penalty_grace;
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((q = strprefix(arg, "refuseconnection:", 0)) != ಖಾಲಿ) {
				doubleptr = &options->ಪ್ರತಿ_ಮೂಲ_penalty.penalty_refuseconnection;
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((q = strprefix(arg, "max:", 0)) != ಖಾಲಿ) {
				doubleptr = &options->ಪ್ರತಿ_ಮೂಲ_penalty.penalty_max;
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((q = strprefix(arg, "min:", 0)) != ಖಾಲಿ) {
				doubleptr = &options->ಪ್ರತಿ_ಮೂಲ_penalty.penalty_min;
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((q = strprefix(arg, "max-sources4:", 0)) != ಖಾಲಿ) {
				intptr = &options->ಪ್ರತಿ_ಮೂಲ_penalty.max_sources4;
				ಆದರೆ ((errstr = atoi_err(q, &ಮೌಲ್ಯ)) != ಖಾಲಿ)
					fatal("%s line %d: %s value %s.",
					    filename, linenum, keyword, errstr);
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((q = strprefix(arg, "max-sources6:", 0)) != ಖಾಲಿ) {
				intptr = &options->ಪ್ರತಿ_ಮೂಲ_penalty.max_sources6;
				ಆದರೆ ((errstr = atoi_err(q, &ಮೌಲ್ಯ)) != ಖಾಲಿ)
					fatal("%s line %d: %s value %s.",
					    filename, linenum, keyword, errstr);
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(arg, "overflow:deny-all") == 0) {
				intptr = &options->ಪ್ರತಿ_ಮೂಲ_penalty.ಅತಿಪ್ರವಾಹ_ಬಹುಲಕ;
				ಮೌಲ್ಯ = ಪ್ರತಿ_ಮೂಲ_PENALTY_ಅತಿಪ್ರವಾಹ_DENY_ALL;
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(arg, "overflow:permissive") == 0) {
				intptr = &options->ಪ್ರತಿ_ಮೂಲ_penalty.ಅತಿಪ್ರವಾಹ_ಬಹುಲಕ;
				ಮೌಲ್ಯ = ಪ್ರತಿ_ಮೂಲ_PENALTY_ಅತಿಪ್ರವಾಹ_PERMISSIVE;
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(arg, "overflow6:deny-all") == 0) {
				intptr = &options->ಪ್ರತಿ_ಮೂಲ_penalty.ಅತಿಪ್ರವಾಹ_mode6;
				ಮೌಲ್ಯ = ಪ್ರತಿ_ಮೂಲ_PENALTY_ಅತಿಪ್ರವಾಹ_DENY_ALL;
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(arg, "overflow6:permissive") == 0) {
				intptr = &options->ಪ್ರತಿ_ಮೂಲ_penalty.ಅತಿಪ್ರವಾಹ_mode6;
				ಮೌಲ್ಯ = ಪ್ರತಿ_ಮೂಲ_PENALTY_ಅತಿಪ್ರವಾಹ_PERMISSIVE;
			} ಇಲ್ಲದಿದ್ದರೆ {
				fatal("%s line %d: unsupported %s keyword %s",
				    filename, linenum, keyword, arg);
			}

			ಆದರೆ (doubleptr != ಖಾಲಿ) {
				ಆದರೆ ((dvalue = convtime_double(q)) < 0) {
					fatal("%s line %d: invalid %s time value.",
					    filename, linenum, keyword);
				}
				ಆದರೆ (*activep && *doubleptr < 0.0) {
					*doubleptr = dvalue;
					options->ಪ್ರತಿ_ಮೂಲ_penalty.enabled = 1;
				}
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (intptr != ಖಾಲಿ) {
				ಆದರೆ (*activep && *intptr == -1) {
					*intptr = ಮೌಲ್ಯ;
					options->ಪ್ರತಿ_ಮೂಲ_penalty.enabled = 1;
				}
			} ಇಲ್ಲದಿದ್ದರೆ {
				fatal_f("%s line %d: internal error",
				    filename, linenum);
			}
		}
		ಆದರೆ (!ಸಿಕ್ಕಿತು) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ sMaxAuthTries:
		intptr = &options->max_authtries;
		ಹೋಗು parse_int;

	ಸ್ಥಿತಿ sMaxSessions:
		intptr = &options->max_sessions;
		ಹೋಗು parse_int;

	ಸ್ಥಿತಿ sBanner:
		charptr = &options->banner;
		ಹೋಗು parse_filename;

	/*
	 * These options can contain %X options expanded at
	 * connect time, so that you can specify paths like:
	 *
	 * AuthorizedKeysFile	/etc/ssh_keys/%u
	 */
	ಸ್ಥಿತಿ s_Authorized_ಕೀಲಿಗಳು_File:
		uintptr = &options->ಅಂಕೆ_authkeys_files;
		chararrayptr = &options->authorized_ಕೀಲಿಗಳು_files;
 parse_filenames:
		ಸಿಕ್ಕಿತು = *uintptr == 0;
		ಆಗ ((arg = argv_ಮುಂದಿನ(&ac, &av)) != ಖಾಲಿ) {
			ಆದರೆ (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				ಹೋಗು ಹೊರಹೋಗು;
			}
			/* Allow "none" only in first position */
			ಆದರೆ (strcasecmp(arg, "none") == 0) {
				ಆದರೆ (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					ಹೋಗು ಹೊರಹೋಗು;
				}
			}
			arg2 = tilde_expand_filename(arg, getuid());
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg2);
			ಬಿಡುಗಡೆ(arg2);
		}
		ಆದರೆ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ಆದರೆ (ಸಿಕ್ಕಿತು && *activep) {
			*chararrayptr = strs;
			*uintptr = nstrs;
			strs = ಖಾಲಿ; /* transferred */
			nstrs = 0;
		}
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ sAuthorizedPrincipalsFile:
		charptr = &options->authorized_principals_file;
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ಆದರೆ (*activep && *charptr == ಖಾಲಿ) {
			*charptr = tilde_expand_filename(arg, getuid());
			/* increase optional counter */
			ಆದರೆ (intptr != ಖಾಲಿ)
				*intptr = *intptr + 1;
		}
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ sClientAliveInterval:
		intptr = &options->client_alive_interval;
		ಹೋಗು parse_ಸಮಯ;

	ಸ್ಥಿತಿ s_Client_Alive_ಎಣಿಕೆ_Max:
		intptr = &options->client_alive_ಎಣಿಕೆ_max;
		ಹೋಗು parse_int;

	ಸ್ಥಿತಿ sAcceptEnv:
		/* XXX appends to list; doesn't respect first-match-wins */
		ಆಗ ((arg = argv_ಮುಂದಿನ(&ac, &av)) != ಖಾಲಿ) {
			ಆದರೆ (*arg == '\0' || strchr(arg, '=') != ಖಾಲಿ)
				fatal("%s line %d: Invalid environment name.",
				    filename, linenum);
			ಸಿಕ್ಕಿತು = 1;
			ಆದರೆ (!*activep)
				ಮುಂದುವರಿ;
			opt_array_append(filename, linenum, keyword,
			    &options->accept_env, &options->ಅಂಕೆ_accept_env,
			    arg);
		}
		ಆದರೆ (!ಸಿಕ್ಕಿತು) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ s_ಗಣ_Env:
		ಸಿಕ್ಕಿತು = options->ಅಂಕೆ_setenv == 0;
		ಆಗ ((arg = argv_ಮುಂದಿನ(&ac, &av)) != ಖಾಲಿ) {
			ಆದರೆ (*arg == '\0' || strchr(arg, '=') == ಖಾಲಿ)
				fatal("%s line %d: Invalid environment.",
				    filename, linenum);
			ಆದರೆ (lookup_setenv_ಒಳ_list(arg, strs, nstrs) != ಖಾಲಿ) {
				debug2("%s line %d: ignoring duplicate env "
				    "name \"%.64s\"", filename, linenum, arg);
				ಮುಂದುವರಿ;
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		ಆದರೆ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ಆದರೆ (ಸಿಕ್ಕಿತು && *activep) {
			options->setenv = strs;
			options->ಅಂಕೆ_setenv = nstrs;
			strs = ಖಾಲಿ; /* transferred */
			nstrs = 0;
		}
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ sPermitTunnel:
		intptr = &options->permit_tun;
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ಮೌಲ್ಯ = -1;
		ಗಾಗಿ (i = 0; tunmode_desc[i].val != -1; i++)
			ಆದರೆ (strcmp(tunmode_desc[i].ಪಠ್ಯ, arg) == 0) {
				ಮೌಲ್ಯ = tunmode_desc[i].val;
				ನಿಲ್ಲಿಸು;
			}
		ಆದರೆ (ಮೌಲ್ಯ == -1)
			fatal("%s line %d: bad %s argument %s",
			    filename, linenum, keyword, arg);
		ಆದರೆ (*activep && *intptr == -1)
			*intptr = ಮೌಲ್ಯ;
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ sInclude:
		ಆದರೆ (cmdline) {
			fatal("Include directive not supported as a "
			    "command-line option");
		}
		ಮೌಲ್ಯ = 0;
		ಆಗ ((arg2 = argv_ಮುಂದಿನ(&ac, &av)) != ಖಾಲಿ) {
			ಆದರೆ (*arg2 == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				ಹೋಗು ಹೊರಹೋಗು;
			}
			ಮೌಲ್ಯ++;
			ಸಿಕ್ಕಿತು = 0;
			ಆದರೆ (*arg2 != '/' && *arg2 != '~') {
				xasprintf(&arg, "%s/%s", SSHDIR, arg2);
			} ಇಲ್ಲದಿದ್ದರೆ
				arg = xstrdup(arg2);

			/*
			 * Don't let included files clobber the containing
			 * file's Match state.
			 */
			oactive = *activep;

			/* consult cache of include files */
			TAILQ_FOREACH(ಅಂಶ, includes, ನಮೂದು) {
				ಆದರೆ (strcmp(ಅಂಶ->selector, arg) != 0)
					ಮುಂದುವರಿ;
				ಆದರೆ (ಅಂಶ->filename != ಖಾಲಿ) {
					parse_server_config_ಆಳ(options,
					    ಅಂಶ->filename, ಅಂಶ->contents,
					    includes, connectinfo,
					    (*inc_flags & SSHCFG_ಹೊಂದಿಕೆ_ONLY
					        ? SSHCFG_ಹೊಂದಿಕೆ_ONLY : (oactive
					            ? 0 : SSHCFG_NEVERMATCH)),
					    activep, ಆಳ + 1);
				}
				ಸಿಕ್ಕಿತು = 1;
				*activep = oactive;
			}
			ಆದರೆ (ಸಿಕ್ಕಿತು != 0) {
				ಬಿಡುಗಡೆ(arg);
				ಮುಂದುವರಿ;
			}

			/* requested glob was not in cache */
			debug2("%s line %d: new include %s",
			    filename, linenum, arg);
			ಆದರೆ ((r = glob(arg, 0, ಖಾಲಿ, &gbuf)) != 0) {
				ಆದರೆ (r != GLOB_NOMATCH) {
					fatal("%s line %d: include \"%s\" glob "
					    "failed", filename, linenum, arg);
				}
				/*
				 * If no entry matched then record a
				 * placeholder to skip later glob calls.
				 */
				debug2("%s line %d: no match for %s",
				    filename, linenum, arg);
				ಅಂಶ = xcalloc(1, ಗಾತ್ರ(*ಅಂಶ));
				ಅಂಶ->selector = xstrdup(arg);
				TAILQ_INSERT_TAIL(includes,
				    ಅಂಶ, ನಮೂದು);
			}
			ಆದರೆ (gbuf.gl_pathc > ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ)
				fatal_f("too many glob results");
			ಗಾಗಿ (n = 0; n < (ಪೂರ್ಣಾಂಕ)gbuf.gl_pathc; n++) {
				debug2("%s line %d: including %s",
				    filename, linenum, gbuf.gl_pathv[n]);
				ಅಂಶ = xcalloc(1, ಗಾತ್ರ(*ಅಂಶ));
				ಅಂಶ->selector = xstrdup(arg);
				ಅಂಶ->filename = xstrdup(gbuf.gl_pathv[n]);
				ಆದರೆ ((ಅಂಶ->contents = sshbuf_new()) == ಖಾಲಿ)
					fatal_f("sshbuf_new failed");
				ತುಂಬು_server_config(ಅಂಶ->filename,
				    ಅಂಶ->contents);
				parse_server_config_ಆಳ(options,
				    ಅಂಶ->filename, ಅಂಶ->contents,
				    includes, connectinfo,
				    (*inc_flags & SSHCFG_ಹೊಂದಿಕೆ_ONLY
				        ? SSHCFG_ಹೊಂದಿಕೆ_ONLY : (oactive
				            ? 0 : SSHCFG_NEVERMATCH)),
				    activep, ಆಳ + 1);
				*activep = oactive;
				TAILQ_INSERT_TAIL(includes, ಅಂಶ, ನಮೂದು);
			}
			globfree(&gbuf);
			ಬಿಡುಗಡೆ(arg);
		}
		ಆದರೆ (ಮೌಲ್ಯ == 0) {
			fatal("%s line %d: %s missing filename argument",
			    filename, linenum, keyword);
		}
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ s_ಹೊಂದಿಕೆ:
		ಆದರೆ (cmdline)
			fatal("Match directive not supported as a command-line "
			    "option");
		ಮೌಲ್ಯ = ಹೊಂದಿಕೆ_cfg_ಸಾಲು(str, &ac, &av, linenum,
		    (*inc_flags & SSHCFG_NEVERMATCH ? ಖಾಲಿ : connectinfo));
		ಆದರೆ (ಮೌಲ್ಯ < 0)
			fatal("%s line %d: Bad Match condition", filename,
			    linenum);
		*activep = (*inc_flags & SSHCFG_NEVERMATCH) ? 0 : ಮೌಲ್ಯ;
		/*
		 * The MATCH_ONLY flag is applicable only until the first
		 * match block.
		 */
		*inc_flags &= ~SSHCFG_ಹೊಂದಿಕೆ_ONLY;
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ sPermitListen:
	ಸ್ಥಿತಿ sPermitOpen:
		ಆದರೆ (opcode == sPermitListen) {
			uintptr = &options->ಅಂಕೆ_permitted_listens;
			chararrayptr = &options->permitted_listens;
		} ಇಲ್ಲದಿದ್ದರೆ {
			uintptr = &options->ಅಂಕೆ_permitted_opens;
			chararrayptr = &options->permitted_opens;
		}
		ಸಿಕ್ಕಿತು = *uintptr == 0;
		ಆಗ ((arg = argv_ಮುಂದಿನ(&ac, &av)) != ಖಾಲಿ) {
			ಆದರೆ (strcmp(arg, "any") == 0 ||
			    strcmp(arg, "none") == 0) {
				ಆದರೆ (nstrs != 0) {
					fatal("%s line %d: %s must appear "
					    "alone on a %s line.",
					    filename, linenum, arg, keyword);
				}
				opt_array_append(filename, linenum, keyword,
				    &strs, &nstrs, arg);
				ಮುಂದುವರಿ;
			}

			ಆದರೆ (opcode == sPermitListen &&
			    strchr(arg, ':') == ಖಾಲಿ) {
				/*
				 * Allow bare port number for PermitListen
				 * to indicate a wildcard listen host.
				 */
				xasprintf(&arg2, "*:%s", arg);
			} ಇಲ್ಲದಿದ್ದರೆ {
				arg2 = xstrdup(arg);
				p = hpdelim(&arg);
				ಆದರೆ (p == ಖಾಲಿ) {
					fatal("%s line %d: %s missing host",
					    filename, linenum, keyword);
				}
				p = cleanhostname(p);
			}
			ಆದರೆ (arg == ಖಾಲಿ ||
			    ((ಪೋರ್ಟ್ = permitopen_ಪೋರ್ಟ್(arg)) < 0)) {
				fatal("%s line %d: %s bad port number",
				    filename, linenum, keyword);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg2);
			ಬಿಡುಗಡೆ(arg2);
		}
		ಆದರೆ (nstrs == 0) {
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		}
		ಆದರೆ (ಸಿಕ್ಕಿತು && *activep) {
			*chararrayptr = strs;
			*uintptr = nstrs;
			strs = ಖಾಲಿ; /* transferred */
			nstrs = 0;
		}
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ sForceCommand:
		ಆದರೆ (str == ಖಾಲಿ || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		ಆದರೆ (*activep && options->adm_forced_command == ಖಾಲಿ)
			options->adm_forced_command = xstrdup(str + len);
		argv_consume(&ac);
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ sChrootDirectory:
		charptr = &options->chroot_directory;

		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ಆದರೆ (*activep && *charptr == ಖಾಲಿ)
			*charptr = xstrdup(arg);
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ sTrustedUserCAKeys:
		charptr = &options->trusted_user_ca_ಕೀಲಿಗಳು;
		ಹೋಗು parse_filename;

	ಸ್ಥಿತಿ s_Revoked_ಕೀಲಿಗಳು:
		uintptr = &options->ಅಂಕೆ_revoked_ಕೀಲಿಗಳು_files;
		chararrayptr = &options->revoked_ಕೀಲಿಗಳು_files;
		ಹೋಗು parse_filenames;

	ಸ್ಥಿತಿ s_Security_ಕೀಲಿ_Provider:
		charptr = &options->sk_provider;
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ಆದರೆ (*activep && *charptr == ಖಾಲಿ) {
			*charptr = strcasecmp(arg, "internal") == 0 ?
			    xstrdup(arg) : derelativise_ಮಾರ್ಗ(arg);
			/* increase optional counter */
			ಆದರೆ (intptr != ಖಾಲಿ)
				*intptr = *intptr + 1;
		}
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ sIPQoS:
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ಆದರೆ ((ಮೌಲ್ಯ = parse_ipqos(arg)) == -1)
			fatal("%s line %d: Bad %s value: %s",
			    filename, linenum, keyword, arg);
		ಆದರೆ (ಮೌಲ್ಯ == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			ಮೌಲ್ಯ = ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ;
		}
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (arg == ಖಾಲಿ)
			value2 = ಮೌಲ್ಯ;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((value2 = parse_ipqos(arg)) == -1)
			fatal("%s line %d: Bad %s value: %s",
			    filename, linenum, keyword, arg);
		ಆದರೆ (value2 == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			value2 = ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ;
		}
		ಆದರೆ (*activep && options->ip_qos_interactive == -1) {
			options->ip_qos_interactive = ಮೌಲ್ಯ;
			options->ip_qos_bulk = value2;
		}
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ s_ಆವೃತ್ತಿ_Addendum:
		ಆದರೆ (str == ಖಾಲಿ || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		ಆದರೆ (strchr(str + len, '\r') != ಖಾಲಿ) {
			fatal("%.200s line %d: Invalid %s argument",
			    filename, linenum, keyword);
		}
		ಆದರೆ ((arg = strchr(ಸಾಲು, '#')) != ಖಾಲಿ) {
			*arg = '\0';
			rtrim(ಸಾಲು);
		}
		ಆದರೆ (*activep && options->ಆವೃತ್ತಿ_addendum == ಖಾಲಿ) {
			ಆದರೆ (strcasecmp(str + len, "none") == 0)
				options->ಆವೃತ್ತಿ_addendum = xstrdup("");
			ಇಲ್ಲದಿದ್ದರೆ
				options->ಆವೃತ್ತಿ_addendum = xstrdup(str + len);
		}
		argv_consume(&ac);
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ s_Authorized_ಕೀಲಿಗಳು_Command:
		charptr = &options->authorized_ಕೀಲಿಗಳು_command;
 parse_command:
		len = strspn(str, WHITESPACE);
		ಆದರೆ (str[len] != '/' && strcasecmp(str + len, "none") != 0) {
			fatal("%.200s line %d: %s must be an absolute path",
			    filename, linenum, keyword);
		}
		ಆದರೆ (*activep && *charptr == ಖಾಲಿ)
			*charptr = xstrdup(str + len);
		argv_consume(&ac);
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ s_Authorized_ಕೀಲಿಗಳು_Command_User:
		charptr = &options->authorized_ಕೀಲಿಗಳು_command_user;
 parse_localuser:
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0') {
			fatal("%s line %d: missing %s argument.",
			    filename, linenum, keyword);
		}
		ಆದರೆ (*activep && *charptr == ಖಾಲಿ)
			*charptr = xstrdup(arg);
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ sAuthorizedPrincipalsCommand:
		charptr = &options->authorized_principals_command;
		ಹೋಗು parse_command;

	ಸ್ಥಿತಿ sAuthorizedPrincipalsCommandUser:
		charptr = &options->authorized_principals_command_user;
		ಹೋಗು parse_localuser;

	ಸ್ಥಿತಿ sAuthenticationMethods:
		ಸಿಕ್ಕಿತು = options->ಅಂಕೆ_auth_methods == 0;
		ಮೌಲ್ಯ = 0; /* seen "any" pseudo-method */
		ಆಗ ((arg = argv_ಮುಂದಿನ(&ac, &av)) != ಖಾಲಿ) {
			ಆದರೆ (strcmp(arg, "any") == 0) {
				ಆದರೆ (nstrs > 0) {
					fatal("%s line %d: \"any\" must "
					    "appear alone in %s",
					    filename, linenum, keyword);
				}
				ಮೌಲ್ಯ = 1;
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ಮೌಲ್ಯ) {
				fatal("%s line %d: \"any\" must appear "
				    "alone in %s", filename, linenum, keyword);
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (auth2_methods_valid(arg, 0) != 0) {
				fatal("%s line %d: invalid %s method list.",
				    filename, linenum, keyword);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		ಆದರೆ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ಆದರೆ (ಸಿಕ್ಕಿತು && *activep) {
			options->auth_methods = strs;
			options->ಅಂಕೆ_auth_methods = nstrs;
			strs = ಖಾಲಿ; /* transferred */
			nstrs = 0;
		}
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ s_ಹರಿವು_Local_Bind_ಮುಖವಾಡ:
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		/* Parse mode in octal format */
		ಮೌಲ್ಯ = strtol(arg, &p, 8);
		ಆದರೆ (arg == p || ಮೌಲ್ಯ < 0 || ಮೌಲ್ಯ > 0777)
			fatal("%s line %d: Invalid %s.",
			    filename, linenum, keyword);
		ಆದರೆ (*activep &&
		    options->fwd_opts.streamlocal_bind_ಮುಖವಾಡ == (ಬಹುಲಕ_t)-1)
			options->fwd_opts.streamlocal_bind_ಮುಖವಾಡ = (ಬಹುಲಕ_t)ಮೌಲ್ಯ;
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ s_ಹರಿವು_Local_Bind_Unlink:
		intptr = &options->fwd_opts.streamlocal_bind_unlink;
		ಹೋಗು parse_flag;

	ಸ್ಥಿತಿ sFingerprintHash:
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ಆದರೆ ((ಮೌಲ್ಯ = ssh_digest_alg_by_name(arg)) == -1)
			fatal("%.200s line %d: Invalid %s algorithm \"%s\".",
			    filename, linenum, keyword, arg);
		ಆದರೆ (*activep)
			options->fingerprint_hash = ಮೌಲ್ಯ;
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ sExposeAuthInfo:
		intptr = &options->expose_userauth_info;
		ಹೋಗು parse_flag;

	ಸ್ಥಿತಿ sRDomain:
#ಆದರೆ !defined(__OpenBSD__) && !defined(HAVE_SYS_ಗಣ_PROCESS_RDOMAIN)
		fatal("%s line %d: setting RDomain not supported on this "
		    "platform.", filename, linenum);
#ಆದರೆ_ಅಂತ್ಯ
		charptr = &options->routing_domain;
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ಆದರೆ (strcasecmp(arg, "none") != 0 && strcmp(arg, "%D") != 0 &&
		    !valid_rdomain(arg))
			fatal("%s line %d: invalid routing domain",
			    filename, linenum);
		ಆದರೆ (*activep && *charptr == ಖಾಲಿ)
			*charptr = xstrdup(arg);
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ sRequiredRSASize:
		intptr = &options->required_rsa_ಗಾತ್ರ;
		ಹೋಗು parse_int;

	ಸ್ಥಿತಿ sChannelTimeout:
		ಸಿಕ್ಕಿತು = options->ಅಂಕೆ_channel_timeouts == 0;
		ಆಗ ((arg = argv_ಮುಂದಿನ(&ac, &av)) != ಖಾಲಿ) {
			/* Allow "none" only in first position */
			ಆದರೆ (strcasecmp(arg, "none") == 0) {
				ಆದರೆ (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					ಹೋಗು ಹೊರಹೋಗು;
				}
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (parse_ನಮೂನೆ_interval(arg,
			    ಖಾಲಿ, ಖಾಲಿ) != 0) {
				fatal("%s line %d: invalid channel timeout %s",
				    filename, linenum, arg);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		ಆದರೆ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ಆದರೆ (ಸಿಕ್ಕಿತು && *activep) {
			options->channel_timeouts = strs;
			options->ಅಂಕೆ_channel_timeouts = nstrs;
			strs = ಖಾಲಿ; /* transferred */
			nstrs = 0;
		}
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ s_ಬಳಸದ_Connection_Timeout:
		intptr = &options->ಬಳಸದ_connection_timeout;
		/* peek at first arg for "none" so we can reuse parse_time */
		ಆದರೆ (av[0] != ಖಾಲಿ && strcasecmp(av[0], "none") == 0) {
			(ಶೂನ್ಯ)argv_ಮುಂದಿನ(&ac, &av); /* consume arg */
			ಆದರೆ (*activep)
				*intptr = 0;
			ನಿಲ್ಲಿಸು;
		}
		ಹೋಗು parse_ಸಮಯ;

	ಸ್ಥಿತಿ s_Sshd_Session_ಮಾರ್ಗ:
		charptr = &options->sshd_session_ಮಾರ್ಗ;
		ಹೋಗು parse_filename;

	ಸ್ಥಿತಿ s_Sshd_Auth_ಮಾರ್ಗ:
		charptr = &options->sshd_auth_ಮಾರ್ಗ;
		ಹೋಗು parse_filename;

	ಸ್ಥಿತಿ sRefuseConnection:
		intptr = &options->refuse_connection;
		multistate_ptr = multistate_flag;
		ಹೋಗು parse_multistate;

	ಸ್ಥಿತಿ sWarnWeakCrypto:
		intptr = &options->warn_weak_crypto;
		multistate_ptr = multistate_warnweakcrypto;
		ಹೋಗು parse_multistate;

	ಸ್ಥಿತಿ sDeprecated:
	ಸ್ಥಿತಿ sIgnore:
	ಸ್ಥಿತಿ sUnsupported:
		do_log2(opcode == sIgnore ?
		    SYSLOG_LEVEL_DEBUG2 : SYSLOG_LEVEL_INFO,
		    "%s line %d: %s option %s", filename, linenum,
		    opcode == sUnsupported ? "Unsupported" : "Deprecated",
		    keyword);
		argv_consume(&ac);
		ನಿಲ್ಲಿಸು;

	ಪೂರ್ವನಿಯೋಜಿತ:
		fatal("%s line %d: Missing handler for opcode %s (%d)",
		    filename, linenum, keyword, opcode);
	}
	/* Check that there is no garbage at end of line. */
	ಆದರೆ (ac > 0) {
		error("%.200s line %d: keyword %s extra arguments "
		    "at end of line", filename, linenum, keyword);
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* success */
	ret = 0;
 ಹೊರಹೋಗು:
	opt_array_free2(strs, ಖಾಲಿ, nstrs);
	argv_free(oav, oac);
	ಹಿಂತಿರುಗಿ ret;
}

ಪೂರ್ಣಾಂಕ
process_server_config_ಸಾಲು(ServerOptions *options, ಅಕ್ಷರ *ಸಾಲು,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename, ಪೂರ್ಣಾಂಕ linenum, ಪೂರ್ಣಾಂಕ *activep,
    ರಚನೆ connection_info *connectinfo, ರಚನೆ include_list *includes)
{
	ಪೂರ್ಣಾಂಕ inc_flags = 0;

	ಹಿಂತಿರುಗಿ process_server_config_ಸಾಲು_ಆಳ(options, ಸಾಲು, filename,
	    linenum, activep, connectinfo, &inc_flags, 0, includes);
}


/* Reads the server configuration file. */

ಶೂನ್ಯ
ತುಂಬು_server_config(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename, ರಚನೆ sshbuf *conf)
{
	ರಚನೆ stat st;
	ಅಕ್ಷರ *ಸಾಲು = ಖಾಲಿ, *cp;
	ಗಾತ್ರ_t linesize = 0;
	FILE *f;
	ಪೂರ್ಣಾಂಕ r;

	debug2_f("filename %s", filename);
	ಆದರೆ ((f = fopen(filename, "r")) == ಖಾಲಿ) {
		perror(filename);
		ನಿರ್ಗಮಿಸು(1);
	}
	sshbuf_reset(conf);
	/* grow buffer, so realloc is avoided for large config files */
	ಆದರೆ (fstat(fileno(f), &st) == 0 && st.st_size > 0 &&
	    (r = sshbuf_allocate(conf, st.st_size)) != 0)
		fatal_fr(r, "allocate");
	ಆಗ (getline(&ಸಾಲು, &linesize, f) != -1) {
		/*
		 * Strip whitespace
		 * NB - preserve newlines, they are needed to reproduce
		 * line numbers later for error messages
		 */
		cp = ಸಾಲು + strspn(ಸಾಲು, " \t\r");
		ಆದರೆ ((r = sshbuf_put(conf, cp, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(cp))) != 0)
			fatal_fr(r, "sshbuf_put");
	}
	ಬಿಡುಗಡೆ(ಸಾಲು);
	ಆದರೆ ((r = sshbuf_put_u8(conf, 0)) != 0)
		fatal_fr(r, "sshbuf_put_u8");
	fclose(f);
	debug2_f("done config len = %zu", sshbuf_len(conf));
}

ಶೂನ್ಯ
parse_server_ಹೊಂದಿಕೆ_config(ServerOptions *options,
   ರಚನೆ include_list *includes, ರಚನೆ connection_info *connectinfo)
{
	ServerOptions mo;

	initialize_server_options(&mo);
	parse_server_config(&mo, "reprocess config", cfg, includes,
	    connectinfo, 0);
	copy_ಗಣ_server_options(options, &mo, 0);
	free_server_options(&mo);
}

ಪೂರ್ಣಾಂಕ
parse_server_ಹೊಂದಿಕೆ_testspec(ರಚನೆ connection_info *ci, ಅಕ್ಷರ *spec)
{
	ಅಕ್ಷರ *p;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *val;

	ಆಗ ((p = strsep(&spec, ",")) && *p != '\0') {
		ಆದರೆ ((val = strprefix(p, "addr=", 0)) != ಖಾಲಿ) {
			ci->ವಿಳಾಸ = xstrdup(val);
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((val = strprefix(p, "host=", 0)) != ಖಾಲಿ) {
			ci->host = xstrdup(val);
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((val = strprefix(p, "user=", 0)) != ಖಾಲಿ) {
			ci->user = xstrdup(val);
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((val = strprefix(p, "laddr=", 0)) != ಖಾಲಿ) {
			ci->laddress = xstrdup(val);
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((val = strprefix(p, "rdomain=", 0)) != ಖಾಲಿ) {
			ci->rdomain = xstrdup(val);
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((val = strprefix(p, "lport=", 0)) != ಖಾಲಿ) {
			ci->lport = a2port(val);
			ಆದರೆ (ci->lport == -1) {
				fprintf(stderr, "Invalid port '%s' in test mode"
				    " specification %s\n", p+6, p);
				ಹಿಂತಿರುಗಿ -1;
			}
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(p, "invalid-user") == 0) {
			ci->user_invalid = 1;
		} ಇಲ್ಲದಿದ್ದರೆ {
			fprintf(stderr, "Invalid test mode specification %s\n",
			    p);
			ಹಿಂತಿರುಗಿ -1;
		}
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಶೂನ್ಯ
servconf_ವಿಲೀನ_subsystems(ServerOptions *dst, ServerOptions *src)
{
	u_int i, j, ಸಿಕ್ಕಿತು;

	ಗಾಗಿ (i = 0; i < src->ಅಂಕೆ_subsystems; i++) {
		ಸಿಕ್ಕಿತು = 0;
		ಗಾಗಿ (j = 0; j < dst->ಅಂಕೆ_subsystems; j++) {
			ಆದರೆ (strcmp(src->subsystem_name[i],
			    dst->subsystem_name[j]) == 0) {
				ಸಿಕ್ಕಿತು = 1;
				ನಿಲ್ಲಿಸು;
			}
		}
		ಆದರೆ (ಸಿಕ್ಕಿತು) {
			debug_f("override \"%s\"", dst->subsystem_name[j]);
			ಬಿಡುಗಡೆ(dst->subsystem_command[j]);
			ಬಿಡುಗಡೆ(dst->subsystem_ವಾದಗಳು[j]);
			dst->subsystem_command[j] =
			    xstrdup(src->subsystem_command[i]);
			dst->subsystem_ವಾದಗಳು[j] =
			    xstrdup(src->subsystem_ವಾದಗಳು[i]);
			ಮುಂದುವರಿ;
		}
		debug_f("add \"%s\"", src->subsystem_name[i]);
		dst->subsystem_name = xrecallocarray(
		    dst->subsystem_name, dst->ಅಂಕೆ_subsystems,
		    dst->ಅಂಕೆ_subsystems + 1, ಗಾತ್ರ(*dst->subsystem_name));
		dst->subsystem_command = xrecallocarray(
		    dst->subsystem_command, dst->ಅಂಕೆ_subsystems,
		    dst->ಅಂಕೆ_subsystems + 1, ಗಾತ್ರ(*dst->subsystem_command));
		dst->subsystem_ವಾದಗಳು = xrecallocarray(
		    dst->subsystem_ವಾದಗಳು, dst->ಅಂಕೆ_subsystems,
		    dst->ಅಂಕೆ_subsystems + 1, ಗಾತ್ರ(*dst->subsystem_ವಾದಗಳು));
		j = dst->ಅಂಕೆ_subsystems++;
		dst->subsystem_name[j] = xstrdup(src->subsystem_name[i]);
		dst->subsystem_command[j] = xstrdup(src->subsystem_command[i]);
		dst->subsystem_ವಾದಗಳು[j] = xstrdup(src->subsystem_ವಾದಗಳು[i]);
	}
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
serialise_s32(ರಚನೆ sshbuf *buf, ಪೂರ್ಣಾಂಕ v)
{
	uint32_t uv;
	ಪೂರ್ಣಾಂಕ r;

	uv = v < 0 ? (uint32_t)(-(v + 1)) + 1 : (uint32_t)v;
	ಆದರೆ ((r = sshbuf_put_u8(buf, v < 0)) != 0 ||
	    (r = sshbuf_put_u32(buf, uv)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
serialise_s64(ರಚನೆ sshbuf *buf, int64_t v)
{
	uint64_t uv;
	ಪೂರ್ಣಾಂಕ r;

	uv = v < 0 ? (uint64_t)(-(v + 1)) + 1 : (uint64_t)v;
	ಆದರೆ ((r = sshbuf_put_u8(buf, v < 0)) != 0 ||
	    (r = sshbuf_put_u64(buf, uv)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
serialise_ಬಹುಲಕ(ರಚನೆ sshbuf *buf, ಬಹುಲಕ_t v)
{
	u_int uv;

	ಆದರೆ (v == (ಬಹುಲಕ_t)-1)
		ಹಿಂತಿರುಗಿ serialise_s32(buf, -1);
	uv = (u_int)v;
	ಆದರೆ ((ಬಹುಲಕ_t)uv != v || uv > 0777)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
	ಹಿಂತಿರುಗಿ serialise_s32(buf, (ಪೂರ್ಣಾಂಕ)uv);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
serialise_double(ರಚನೆ sshbuf *buf, ದ್ವಿಗುಣ v)
{
	/*
	 * XXX this is no good for a wire encoding.
	 * It's fine for passing configurations via RPC, but it would
	 * be nicer to have an exact binary encoding here.
	 */
	ಹಿಂತಿರುಗಿ sshbuf_put(buf, &v, ಗಾತ್ರ(v));
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
serialise_nullable_string(ರಚನೆ sshbuf *buf, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshbuf_put_u8(buf, s != ಖಾಲಿ)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (s == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	ಹಿಂತಿರುಗಿ sshbuf_put_cstring(buf, s);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
serialise_nullable_string_array(ರಚನೆ sshbuf *buf, ಅಕ್ಷರ **a, u_int n)
{
	ಪೂರ್ಣಾಂಕ r;
	u_int i;

	ಆದರೆ ((r = sshbuf_put_u32(buf, n)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಗಾಗಿ (i = 0; i < n; i++) {
		ಆದರೆ ((r = serialise_nullable_string(buf, a[i])) != 0)
			ಹಿಂತಿರುಗಿ r;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
serialise_hostkeyfile(ಸ್ಥಿರಾಂಕ ServerOptions *options, ರಚನೆ sshbuf *buf)
{
	ಪೂರ್ಣಾಂಕ r;
	u_int i;

	ಆದರೆ ((r = sshbuf_put_u32(buf, options->ಅಂಕೆ_host_ಕೀಲಿ_files)) != 0) {
		error_fr(r, "serialise length");
		ಹಿಂತಿರುಗಿ r;
	}
	ಗಾಗಿ (i = 0; i < options->ಅಂಕೆ_host_ಕೀಲಿ_files; i++) {
		ಆದರೆ ((r = serialise_s32(buf,
		    options->host_ಕೀಲಿ_file_userprovided[i])) != 0 ||
		    (r = serialise_nullable_string(buf,
		    options->host_ಕೀಲಿ_files[i])) != 0) {
			error_fr(r, "serialise member");
			ಹಿಂತಿರುಗಿ r;
		}
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
serialise_ipqos(ಸ್ಥಿರಾಂಕ ServerOptions *options, ರಚನೆ sshbuf *buf)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = serialise_s32(buf, options->ip_qos_interactive)) != 0 ||
	    (r = serialise_s32(buf, options->ip_qos_bulk)) != 0) {
		error_fr(r, "serialise");
		ಹಿಂತಿರುಗಿ r;
	}

	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
serialise_listenaddress(ಸ್ಥಿರಾಂಕ ServerOptions *options, ರಚನೆ sshbuf *buf)
{
	ಪೂರ್ಣಾಂಕ r;
	u_int i;

	/* Note: only serialises queued listen addresses */
	ಆದರೆ ((r = sshbuf_put_u32(buf, options->ಅಂಕೆ_queued_listens)) != 0) {
		error_fr(r, "serialise length");
		ಹಿಂತಿರುಗಿ r;
	}
	ಗಾಗಿ (i = 0; i < options->ಅಂಕೆ_queued_listens; i++) {
		ಸ್ಥಿರಾಂಕ ರಚನೆ queued_listenaddr *qla =
		    options->queued_listen_addrs + i;

		ಆದರೆ ((r = sshbuf_put_cstring(buf, qla->addr)) != 0 ||
		    (r = serialise_s32(buf, qla->ಪೋರ್ಟ್)) != 0 ||
		    (r = serialise_nullable_string(buf, qla->rdomain)) != 0) {
			error_fr(r, "serialise member");
			ಹಿಂತಿರುಗಿ r;
		}
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
serialise_logfacility(ಸ್ಥಿರಾಂಕ ServerOptions *options, ರಚನೆ sshbuf *buf)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = serialise_s32(buf, (ಪೂರ್ಣಾಂಕ)options->log_facility)) != 0) {
		error_fr(r, "serialise");
		ಹಿಂತಿರುಗಿ r;
	}

	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
serialise_loglevel(ಸ್ಥಿರಾಂಕ ServerOptions *options, ರಚನೆ sshbuf *buf)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = serialise_s32(buf, (ಪೂರ್ಣಾಂಕ)options->log_level)) != 0) {
		error_fr(r, "serialise");
		ಹಿಂತಿರುಗಿ r;
	}

	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
serialise_ಪೋರ್ಟ್(ಸ್ಥಿರಾಂಕ ServerOptions *options, ರಚನೆ sshbuf *buf)
{
	ಪೂರ್ಣಾಂಕ r;
	u_int i;

	ಆದರೆ ((r = sshbuf_put_u32(buf, options->ಅಂಕೆ_ports)) != 0) {
		error_fr(r, "serialise length");
		ಹಿಂತಿರುಗಿ r;
	}
	ಗಾಗಿ (i = 0; i < options->ಅಂಕೆ_ports; i++) {
		ಆದರೆ ((r = serialise_s32(buf, options->ports[i])) != 0) {
			error_fr(r, "serialise port");
			ಹಿಂತಿರುಗಿ r;
		}
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
serialise_gatewayports(ಸ್ಥಿರಾಂಕ ServerOptions *options, ರಚನೆ sshbuf *buf)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = serialise_s32(buf, options->fwd_opts.gateway_ports)) != 0) {
		error_fr(r, "serialise");
		ಹಿಂತಿರುಗಿ r;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
serialise_streamlocalbindmask(ಸ್ಥಿರಾಂಕ ServerOptions *options, ರಚನೆ sshbuf *buf)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = serialise_ಬಹುಲಕ(buf,
	    options->fwd_opts.streamlocal_bind_ಮುಖವಾಡ)) != 0) {
		error_fr(r, "serialise");
		ಹಿಂತಿರುಗಿ r;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
serialise_streamlocalbindunlink(ಸ್ಥಿರಾಂಕ ServerOptions *options, ರಚನೆ sshbuf *buf)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshbuf_put_u8(buf,
	    (options->fwd_opts.streamlocal_bind_unlink != 0))) != 0) {
		error_fr(r, "serialise");
		ಹಿಂತಿರುಗಿ r;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
serialise_maxstartups(ಸ್ಥಿರಾಂಕ ServerOptions *options, ರಚನೆ sshbuf *buf)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = serialise_s32(buf, options->max_startups_begin)) != 0 ||
	    (r = serialise_s32(buf, options->max_startups_ದರ)) != 0 ||
	    (r = serialise_s32(buf, options->max_startups)) != 0) {
		error_fr(r, "serialise");
		ಹಿಂತಿರುಗಿ r;
	}

	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
serialise_permituserenv(ಸ್ಥಿರಾಂಕ ServerOptions *options, ರಚನೆ sshbuf *buf)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = serialise_s32(buf, options->permit_user_env)) != 0 ||
	    (r = serialise_nullable_string(buf,
	    options->permit_user_env_allowlist)) != 0) {
		error_fr(r, "serialise");
		ಹಿಂತಿರುಗಿ r;
	}

	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
serialise_persourcenetblocksize(ಸ್ಥಿರಾಂಕ ServerOptions *options, ರಚನೆ sshbuf *buf)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = serialise_s32(buf, options->ಪ್ರತಿ_ಮೂಲ_masklen_ipv4)) != 0 ||
	    (r = serialise_s32(buf, options->ಪ್ರತಿ_ಮೂಲ_masklen_ipv6)) != 0) {
		error_fr(r, "serialise");
		ಹಿಂತಿರುಗಿ r;
	}

	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
serialise_persourcepenalties(ಸ್ಥಿರಾಂಕ ServerOptions *options, ರಚನೆ sshbuf *buf)
{
	ಸ್ಥಿರಾಂಕ ರಚನೆ ಪ್ರತಿ_ಮೂಲ_penalty *psp = &options->ಪ್ರತಿ_ಮೂಲ_penalty;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = serialise_s32(buf, psp->enabled)) != 0 ||
	    (r = serialise_s32(buf, psp->max_sources4)) != 0 ||
	    (r = serialise_s32(buf, psp->max_sources6)) != 0 ||
	    (r = serialise_s32(buf, psp->ಅತಿಪ್ರವಾಹ_ಬಹುಲಕ)) != 0 ||
	    (r = serialise_s32(buf, psp->ಅತಿಪ್ರವಾಹ_mode6)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_crash)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_grace)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_authfail)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_invaliduser)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_noauth)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_refuseconnection)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_max)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_min)) != 0) {
		error_fr(r, "serialise");
		ಹಿಂತಿರುಗಿ r;
	}

	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
serialise_rekeylimit(ಸ್ಥಿರಾಂಕ ServerOptions *options, ರಚನೆ sshbuf *buf)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = serialise_s64(buf, options->rekey_ಎಲ್ಲೆ)) != 0 ||
	    (r = serialise_s32(buf, options->rekey_interval)) != 0) {
		error_fr(r, "serialise");
		ಹಿಂತಿರುಗಿ r;
	}

	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
serialise_subsystem(ಸ್ಥಿರಾಂಕ ServerOptions *options, ರಚನೆ sshbuf *buf)
{
	ಪೂರ್ಣಾಂಕ r;
	u_int i;

	ಆದರೆ ((r = sshbuf_put_u32(buf, options->ಅಂಕೆ_subsystems)) != 0) {
		error_fr(r, "serialise length");
		ಹಿಂತಿರುಗಿ r;
	}
	ಗಾಗಿ (i = 0; i < options->ಅಂಕೆ_subsystems; i++) {
		ಆದರೆ ((r = sshbuf_put_cstring(buf,
		    options->subsystem_name[i])) != 0 ||
		    (r = sshbuf_put_cstring(buf,
		    options->subsystem_command[i])) != 0 ||
		    (r = sshbuf_put_cstring(buf,
		    options->subsystem_ವಾದಗಳು[i])) != 0) {
			error_fr(r, "serialise member");
			ಹಿಂತಿರುಗಿ r;
		}
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
serialise_pubkey_auth_options(ಸ್ಥಿರಾಂಕ ServerOptions *options, ರಚನೆ sshbuf *buf)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = serialise_s32(buf, options->pubkey_auth_options)) != 0 ||
	    (r = serialise_s32(buf, options->max_pubkey_ok)) != 0) {
		error_fr(r, "serialise");
		ಹಿಂತಿರುಗಿ r;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
serialise_timingsecret(ಸ್ಥಿರಾಂಕ ServerOptions *options, ರಚನೆ sshbuf *buf)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshbuf_put_u64(buf, options->timing_secret)) != 0) {
		error_fr(r, "serialise");
		ಹಿಂತಿರುಗಿ r;
	}
	ಹಿಂತಿರುಗಿ 0;
}


ಪೂರ್ಣಾಂಕ
serialise_server_options(ಸ್ಥಿರಾಂಕ ServerOptions *options, ರಚನೆ sshbuf **bufp)
{
	ರಚನೆ sshbuf *buf = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;

	*bufp = ಖಾಲಿ;

	ಆದರೆ ((buf = sshbuf_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ ((r = sshbuf_put_u32(buf, SSHD_CONFIG_BLOB_ಆವೃತ್ತಿ)) != 0) {
		error_fr(r, "serialise version");
		ಹೋಗು ಹೊರಹೋಗು;
	}

#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_INT(var, conf, flags, ms, def, cp) \
	ಆದರೆ ((r = serialise_s32(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		ಹೋಗು ಹೊರಹೋಗು; \
	}
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	ಆದರೆ ((r = serialise_s32(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		ಹೋಗು ಹೊರಹೋಗು; \
	}
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_STRING(var, conf, flags, cp) \
	ಆದರೆ ((r = serialise_nullable_string(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		ಹೋಗು ಹೊರಹೋಗು; \
	}
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	ಆದರೆ ((r = serialise_nullable_string_array(buf, options->var, \
	    options->nvar)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		ಹೋಗು ಹೊರಹೋಗು; \
	}
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	ಆದರೆ ((r = serialise_##funcsuffix(options, buf)) != 0) \
		ಹೋಗು ಹೊರಹೋಗು;
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_NONCONF(funcsuffix) \
	ಆದರೆ ((r = serialise_##funcsuffix(options, buf)) != 0) \
		ಹೋಗು ಹೊರಹೋಗು;
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_DEPRECATE(conf, flags, opcode)		/*ಖಾಲಿಗಳು*/
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_UNSUPPORTED_INT(var, conf, flags)	/*ಖಾಲಿಗಳು*/
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	/*ಖಾಲಿಗಳು*/
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_ALIAS(old, conf, flags)			/*ಖಾಲಿಗಳು*/

	SSHD_CONFIG_ENTRIES

#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_INT
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_INTFLAG
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_STRING
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_STRARRAY
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_CUSTOM
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_NONCONF
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_DEPRECATE
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_UNSUPPORTED_INT
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_UNSUPPORTED_STRING
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_ALIAS

	/* success */
	r = 0;
	*bufp = buf;
	buf = ಖಾಲಿ; /* transferred */
 ಹೊರಹೋಗು:
	sshbuf_free(buf);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
deserialise_s32(ರಚನೆ sshbuf *buf, ಪೂರ್ಣಾಂಕ *v)
{
	uint32_t tmp;
	ಪೂರ್ಣಾಂಕ r;
	u_char was_signed;

	ಆದರೆ ((r = sshbuf_get_u8(buf, &was_signed)) != 0 ||
	    (r = sshbuf_get_u32(buf, &tmp)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (was_signed > 1)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
	ಆದರೆ (was_signed) {
		ಆದರೆ (tmp > (uint32_t)ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ + 1)
			ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
		*v = tmp == (uint32_t)ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ + 1 ? INT_MIN : -(ಪೂರ್ಣಾಂಕ)tmp;
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ (tmp > ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ)
			ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
		*v = (ಪೂರ್ಣಾಂಕ)tmp;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
deserialise_s64(ರಚನೆ sshbuf *buf, int64_t *v)
{
	uint64_t tmp;
	ಪೂರ್ಣಾಂಕ r;
	u_char was_signed;

	ಆದರೆ ((r = sshbuf_get_u8(buf, &was_signed)) != 0 ||
	    (r = sshbuf_get_u64(buf, &tmp)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (was_signed > 1)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
	ಆದರೆ (was_signed) {
		ಆದರೆ (tmp > (uint64_t)INT64_MAX + 1)
			ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
		*v = tmp == (uint64_t)INT64_MAX + 1 ?
		    INT64_MIN : -(int64_t)tmp;
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ (tmp > INT64_MAX)
			ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
		*v = (int64_t)tmp;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
deserialise_ಬಹುಲಕ(ರಚನೆ sshbuf *buf, ಬಹುಲಕ_t *v)
{
	ಪೂರ್ಣಾಂಕ r, tmp;

	ಆದರೆ ((r = deserialise_s32(buf, &tmp)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (tmp == -1) {
		*v = (ಬಹುಲಕ_t)-1;
		ಹಿಂತಿರುಗಿ 0;
	}
	ಆದರೆ (tmp < 0 || tmp > 0777)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
	*v = (ಬಹುಲಕ_t)tmp;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
deserialise_double(ರಚನೆ sshbuf *buf, ದ್ವಿಗುಣ *v)
{
	ಹಿಂತಿರುಗಿ sshbuf_get(buf, v, ಗಾತ್ರ(*v));
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
deserialise_nullable_string(ರಚನೆ sshbuf *buf, ಅಕ್ಷರ **sp)
{
	ಪೂರ್ಣಾಂಕ r;
	u_char present;

	ಆದರೆ ((r = sshbuf_get_u8(buf, &present)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (present == 0) {
		*sp = ಖಾಲಿ;
		ಹಿಂತಿರುಗಿ 0;
	}
	ಆದರೆ (present != 1)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
	ಹಿಂತಿರುಗಿ sshbuf_get_cstring(buf, sp, ಖಾಲಿ);
}

ಸ್ಥಿರ ಶೂನ್ಯ
free_string_array(ಅಕ್ಷರ **a, u_int n)
{
	u_int i;

	ಆದರೆ (a == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	ಗಾಗಿ (i = 0; i < n; i++)
		ಬಿಡುಗಡೆ(a[i]);
	ಬಿಡುಗಡೆ(a);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
deserialise_ಎಣಿಕೆ(ರಚನೆ sshbuf *buf, u_int *np, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *what)
{
	ಪೂರ್ಣಾಂಕ r;
	uint32_t n;

	ಆದರೆ ((r = sshbuf_get_u32(buf, &n)) != 0) {
		error_fr(r, "deserialise %s length", what);
		ಹಿಂತಿರುಗಿ r;
	}
	ಆದರೆ (n > UINT_MAX) {
		error_f("bad number of %s", what);
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
	}
	ಆದರೆ (n > sshbuf_len(buf)) {
		error_f("bad number of %s", what);
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
	}
	*np = n;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
deserialise_nullable_string_array(ರಚನೆ sshbuf *buf, ಅಕ್ಷರ ***arrayp,
    u_int *np)
{
	ಅಕ್ಷರ **a = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r;
	u_int i, n;

	*arrayp = ಖಾಲಿ;
	*np = 0;
	ಆದರೆ ((r = deserialise_ಎಣಿಕೆ(buf, &n, "strings")) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (n > 0)
		a = xcalloc(n, ಗಾತ್ರ(*a));
	ಗಾಗಿ (i = 0; i < n; i++) {
		ಆದರೆ ((r = deserialise_nullable_string(buf, a + i)) != 0) {
			free_string_array(a, i + 1);
			ಹಿಂತಿರುಗಿ r;
		}
	}
	*arrayp = a;
	*np = n;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
free_queued_listen_addrs(ರಚನೆ queued_listenaddr *qla, u_int n)
{
	u_int i;

	ಆದರೆ (qla == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	ಗಾಗಿ (i = 0; i < n; i++) {
		ಬಿಡುಗಡೆ(qla[i].addr);
		ಬಿಡುಗಡೆ(qla[i].rdomain);
	}
	ಬಿಡುಗಡೆ(qla);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
deserialise_hostkeyfile(ServerOptions *options, ರಚನೆ sshbuf *buf)
{
	ಪೂರ್ಣಾಂಕ r, *userprovided = ಖಾಲಿ;
	u_int i, n;
	ಅಕ್ಷರ **files = ಖಾಲಿ;

	ಆದರೆ ((r = deserialise_ಎಣಿಕೆ(buf, &n, "host key files")) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (n > 0) {
		userprovided = xcalloc(n, ಗಾತ್ರ(*userprovided));
		files = xcalloc(n, ಗಾತ್ರ(*files));
	}
	ಗಾಗಿ (i = 0; i < n; i++) {
		ಆದರೆ ((r = deserialise_s32(buf, userprovided + i)) != 0 ||
		    (r = deserialise_nullable_string(buf, files + i)) != 0) {
			error_fr(r, "deserialise member");
			free_string_array(files, i + 1);
			ಬಿಡುಗಡೆ(userprovided);
			ಹಿಂತಿರುಗಿ r;
		}
	}
	options->ಅಂಕೆ_host_ಕೀಲಿ_files = n;
	options->host_ಕೀಲಿ_file_userprovided = userprovided;
	options->host_ಕೀಲಿ_files = files;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
deserialise_ipqos(ServerOptions *options, ರಚನೆ sshbuf *buf)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = deserialise_s32(buf, &options->ip_qos_interactive)) != 0 ||
	    (r = deserialise_s32(buf, &options->ip_qos_bulk)) != 0) {
		error_fr(r, "deserialise");
		ಹಿಂತಿರುಗಿ r;
	}

	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
deserialise_listenaddress(ServerOptions *options, ರಚನೆ sshbuf *buf)
{
	ಪೂರ್ಣಾಂಕ r;
	u_int i, n;
	ರಚನೆ queued_listenaddr *qla = ಖಾಲಿ;

	ಆದರೆ ((r = deserialise_ಎಣಿಕೆ(buf, &n, "listen addresses")) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (n > 0)
		qla = xcalloc(n, ಗಾತ್ರ(*qla));
	ಗಾಗಿ (i = 0; i < n; i++) {
		ಆದರೆ ((r = sshbuf_get_cstring(buf, &qla[i].addr, ಖಾಲಿ)) != 0 ||
		    (r = deserialise_s32(buf, &qla[i].ಪೋರ್ಟ್)) != 0 ||
		    (r = deserialise_nullable_string(buf,
		    &qla[i].rdomain)) != 0) {
			error_fr(r, "deserialise member");
			free_queued_listen_addrs(qla, i + 1);
			ಹಿಂತಿರುಗಿ r;
		}
	}
	options->ಅಂಕೆ_queued_listens = n;
	options->queued_listen_addrs = qla;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
deserialise_logfacility(ServerOptions *options, ರಚನೆ sshbuf *buf)
{
	ಪೂರ್ಣಾಂಕ r, tmp;

	ಆದರೆ ((r = deserialise_s32(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		ಹಿಂತಿರುಗಿ r;
	}
	ಆದರೆ (tmp != SYSLOG_FACILITY_NOT_ಗಣ &&
	    log_facility_name((SyslogFacility)tmp) == ಖಾಲಿ) {
		error_f("bad syslog facility");
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
	}
	options->log_facility = (SyslogFacility)tmp;

	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
deserialise_loglevel(ServerOptions *options, ರಚನೆ sshbuf *buf)
{
	ಪೂರ್ಣಾಂಕ r, tmp;

	ಆದರೆ ((r = deserialise_s32(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		ಹಿಂತಿರುಗಿ r;
	}
	ಆದರೆ (tmp != SYSLOG_LEVEL_NOT_ಗಣ &&
	    log_level_name((LogLevel)tmp) == ಖಾಲಿ) {
		error_f("bad log level");
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
	}
	options->log_level = (LogLevel)tmp;

	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
deserialise_ಪೋರ್ಟ್(ServerOptions *options, ರಚನೆ sshbuf *buf)
{
	ಪೂರ್ಣಾಂಕ r;
	u_int i, n;

	ಆದರೆ ((r = deserialise_ಎಣಿಕೆ(buf, &n, "ports")) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (n > MAX_PORTS) {
		error_f("bad number of ports");
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
	}
	options->ಅಂಕೆ_ports = n;
	memset(options->ports, 0, ಗಾತ್ರ(options->ports));
	ಗಾಗಿ (i = 0; i < options->ಅಂಕೆ_ports; i++) {
		ಆದರೆ ((r = deserialise_s32(buf, options->ports + i)) != 0) {
			error_fr(r, "deserialise port");
			ಹಿಂತಿರುಗಿ r;
		}
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
deserialise_gatewayports(ServerOptions *options, ರಚನೆ sshbuf *buf)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = deserialise_s32(buf, &options->fwd_opts.gateway_ports)) != 0) {
		error_fr(r, "deserialise");
		ಹಿಂತಿರುಗಿ r;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
deserialise_streamlocalbindmask(ServerOptions *options, ರಚನೆ sshbuf *buf)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = deserialise_ಬಹುಲಕ(buf,
	    &options->fwd_opts.streamlocal_bind_ಮುಖವಾಡ)) != 0) {
		error_fr(r, "deserialise");
		ಹಿಂತಿರುಗಿ r;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
deserialise_streamlocalbindunlink(ServerOptions *options, ರಚನೆ sshbuf *buf)
{
	ಪೂರ್ಣಾಂಕ r;
	u_char tmp;

	ಆದರೆ ((r = sshbuf_get_u8(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		ಹಿಂತಿರುಗಿ r;
	}
	ಆದರೆ (tmp > 1) {
		error_f("bad boolean");
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
	}
	options->fwd_opts.streamlocal_bind_unlink = tmp;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
deserialise_maxstartups(ServerOptions *options, ರಚನೆ sshbuf *buf)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = deserialise_s32(buf, &options->max_startups_begin)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_startups_ದರ)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_startups)) != 0) {
		error_fr(r, "deserialise");
		ಹಿಂತಿರುಗಿ r;
	}

	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
deserialise_permituserenv(ServerOptions *options, ರಚನೆ sshbuf *buf)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = deserialise_s32(buf, &options->permit_user_env)) != 0 ||
	    (r = deserialise_nullable_string(buf,
	    &options->permit_user_env_allowlist)) != 0) {
		error_fr(r, "deserialise");
		ಹಿಂತಿರುಗಿ r;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
deserialise_persourcenetblocksize(ServerOptions *options, ರಚನೆ sshbuf *buf)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = deserialise_s32(buf,
	    &options->ಪ್ರತಿ_ಮೂಲ_masklen_ipv4)) != 0 ||
	    (r = deserialise_s32(buf,
	    &options->ಪ್ರತಿ_ಮೂಲ_masklen_ipv6)) != 0) {
		error_fr(r, "deserialise");
		ಹಿಂತಿರುಗಿ r;
	}

	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
deserialise_persourcepenalties(ServerOptions *options, ರಚನೆ sshbuf *buf)
{
	ರಚನೆ ಪ್ರತಿ_ಮೂಲ_penalty *psp = &options->ಪ್ರತಿ_ಮೂಲ_penalty;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = deserialise_s32(buf, &psp->enabled)) != 0 ||
	    (r = deserialise_s32(buf, &psp->max_sources4)) != 0 ||
	    (r = deserialise_s32(buf, &psp->max_sources6)) != 0 ||
	    (r = deserialise_s32(buf, &psp->ಅತಿಪ್ರವಾಹ_ಬಹುಲಕ)) != 0 ||
	    (r = deserialise_s32(buf, &psp->ಅತಿಪ್ರವಾಹ_mode6)) != 0 ||
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
		ಹಿಂತಿರುಗಿ r;
	}

	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
deserialise_rekeylimit(ServerOptions *options, ರಚನೆ sshbuf *buf)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = deserialise_s64(buf, &options->rekey_ಎಲ್ಲೆ)) != 0 ||
	    (r = deserialise_s32(buf, &options->rekey_interval)) != 0) {
		error_fr(r, "deserialise");
		ಹಿಂತಿರುಗಿ r;
	}

	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
deserialise_subsystem(ServerOptions *options, ರಚನೆ sshbuf *buf)
{
	ಪೂರ್ಣಾಂಕ r;
	u_int i, n;
	ಅಕ್ಷರ **ಹೆಸರುಗಳು = ಖಾಲಿ, **commands = ಖಾಲಿ, **ವಾದಗಳು = ಖಾಲಿ;

	ಆದರೆ ((r = deserialise_ಎಣಿಕೆ(buf, &n, "subsystems")) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (n > 0) {
		ಹೆಸರುಗಳು = xcalloc(n, ಗಾತ್ರ(*ಹೆಸರುಗಳು));
		commands = xcalloc(n, ಗಾತ್ರ(*ಹೆಸರುಗಳು));
		ವಾದಗಳು = xcalloc(n, ಗಾತ್ರ(*ವಾದಗಳು));
	}
	ಗಾಗಿ (i = 0; i < n; i++) {
		ಆದರೆ ((r = sshbuf_get_cstring(buf, ಹೆಸರುಗಳು + i, ಖಾಲಿ)) != 0 ||
		    (r = sshbuf_get_cstring(buf, commands + i, ಖಾಲಿ)) != 0 ||
		    (r = sshbuf_get_cstring(buf, ವಾದಗಳು + i, ಖಾಲಿ)) != 0) {
			error_fr(r, "deserialise member");
			free_string_array(ಹೆಸರುಗಳು, i + 1);
			free_string_array(commands, i + 1);
			free_string_array(ವಾದಗಳು, i + 1);
			ಹಿಂತಿರುಗಿ r;
		}
	}
	options->ಅಂಕೆ_subsystems = n;
	options->subsystem_name = ಹೆಸರುಗಳು;
	options->subsystem_command = commands;
	options->subsystem_ವಾದಗಳು = ವಾದಗಳು;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
deserialise_pubkey_auth_options(ServerOptions *options, ರಚನೆ sshbuf *buf)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = deserialise_s32(buf, &options->pubkey_auth_options)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_pubkey_ok)) != 0) {
		error_fr(r, "deserialise");
		ಹಿಂತಿರುಗಿ r;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
deserialise_timingsecret(ServerOptions *options, ರಚನೆ sshbuf *buf)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshbuf_get_u64(buf, &options->timing_secret)) != 0) {
		error_fr(r, "deserialise");
		ಹಿಂತಿರುಗಿ r;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
deserialise_server_options(ರಚನೆ sshbuf *buf, ServerOptions *options)
{
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;
	uint32_t ಆವೃತ್ತಿ;
	ServerOptions new_options;

	initialize_server_options(&new_options);
	ಆದರೆ ((r = sshbuf_get_u32(buf, &ಆವೃತ್ತಿ)) != 0) {
		error_fr(r, "deserialise version");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (ಆವೃತ್ತಿ != SSHD_CONFIG_BLOB_ಆವೃತ್ತಿ) {
		error_f("unsupported config blob version %u", ಆವೃತ್ತಿ);
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_INT(var, conf, flags, ms, def, cp) \
	ಆದರೆ ((r = deserialise_s32(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		ಹೋಗು ಹೊರಹೋಗು; \
	}
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	ಆದರೆ ((r = deserialise_s32(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		ಹೋಗು ಹೊರಹೋಗು; \
	}
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_STRING(var, conf, flags, cp) \
	ಆದರೆ ((r = deserialise_nullable_string(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		ಹೋಗು ಹೊರಹೋಗು; \
	}
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	ಆದರೆ ((r = deserialise_nullable_string_array(buf, &new_options.var, \
	    &new_options.nvar)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		ಹೋಗು ಹೊರಹೋಗು; \
	}
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	ಆದರೆ ((r = deserialise_##funcsuffix(&new_options, buf)) != 0) \
		ಹೋಗು ಹೊರಹೋಗು;
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_NONCONF(funcsuffix) \
	ಆದರೆ ((r = deserialise_##funcsuffix(&new_options, buf)) != 0) \
		ಹೋಗು ಹೊರಹೋಗು;
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_DEPRECATE(conf, flags, opcode)		/*ಖಾಲಿಗಳು*/
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_UNSUPPORTED_INT(var, conf, flags)	new_options.var = 0;
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	ಮಾಡು { \
		ಬಿಡುಗಡೆ(new_options.var); \
		new_options.var = ಖಾಲಿ; \
	} ಆಗ (0);
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_ALIAS(old, conf, flags)			/*ಖಾಲಿಗಳು*/

	SSHD_CONFIG_ENTRIES

	ಆದರೆ (sshbuf_len(buf) != 0) {
		error_f("trailing data in config blob");
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}

#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_INT
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_INTFLAG
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_STRING
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_STRARRAY
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_CUSTOM
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_NONCONF
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_DEPRECATE
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_UNSUPPORTED_INT
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_UNSUPPORTED_STRING
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_ALIAS

	/* success */
	r = 0;
	free_server_options(options);
	*options = new_options;
	memset(&new_options, 0, ಗಾತ್ರ(new_options));
 ಹೊರಹೋಗು:
	free_server_options(&new_options);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಶೂನ್ಯ
free_hostkeyfile(ServerOptions *options)
{
	u_int i;

	ಗಾಗಿ (i = 0; i < options->ಅಂಕೆ_host_ಕೀಲಿ_files; i++)
		ಬಿಡುಗಡೆ(options->host_ಕೀಲಿ_files[i]);
	ಬಿಡುಗಡೆ(options->host_ಕೀಲಿ_files);
	ಬಿಡುಗಡೆ(options->host_ಕೀಲಿ_file_userprovided);
}

ಸ್ಥಿರ ಶೂನ್ಯ
free_listenaddress(ServerOptions *options)
{
	u_int i;

	free_queued_listen_addrs(options->queued_listen_addrs,
	    options->ಅಂಕೆ_queued_listens);

	ಗಾಗಿ (i = 0; i < options->ಅಂಕೆ_listen_addrs; i++) {
		ಬಿಡುಗಡೆ(options->listen_addrs[i].rdomain);
		ಆದರೆ (options->listen_addrs[i].addrs != ಖಾಲಿ)
			freeaddrinfo(options->listen_addrs[i].addrs);
	}
	ಬಿಡುಗಡೆ(options->listen_addrs);
}

ಸ್ಥಿರ ಶೂನ್ಯ
free_permituserenv(ServerOptions *options)
{
	ಬಿಡುಗಡೆ(options->permit_user_env_allowlist);
}

ಸ್ಥಿರ ಶೂನ್ಯ
free_subsystem(ServerOptions *options)
{
	u_int i;

	ಗಾಗಿ (i = 0; i < options->ಅಂಕೆ_subsystems; i++) {
		ಬಿಡುಗಡೆ(options->subsystem_name[i]);
		ಬಿಡುಗಡೆ(options->subsystem_command[i]);
		ಬಿಡುಗಡೆ(options->subsystem_ವಾದಗಳು[i]);
	}
	ಬಿಡುಗಡೆ(options->subsystem_name);
	ಬಿಡುಗಡೆ(options->subsystem_command);
	ಬಿಡುಗಡೆ(options->subsystem_ವಾದಗಳು);
}

ಶೂನ್ಯ
free_server_options(ServerOptions *options)
{
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_INT(var, conf, flags, ms, def, cp)	/*ಖಾಲಿಗಳು*/
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_INTFLAG(var, conf, flags, def, cp)	/*ಖಾಲಿಗಳು*/
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_STRING(var, conf, flags, cp)		ಬಿಡುಗಡೆ(options->var);
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	free_string_array(options->var, options->nvar);
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	free_##funcsuffix(options);
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_NONCONF(funcsuffix) \
	free_##funcsuffix(options);
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_DEPRECATE(conf, flags, opcode)		/*ಖಾಲಿಗಳು*/
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	ಮಾಡು { \
		ಬಿಡುಗಡೆ(options->var); \
		options->var = ಖಾಲಿ; \
	} ಆಗ (0);
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_ALIAS(old, conf, flags)			/*ಖಾಲಿಗಳು*/

#ವ್ಯಾಖ್ಯಾನಿಸು free_ipqos(options)
#ವ್ಯಾಖ್ಯಾನಿಸು free_logfacility(options)
#ವ್ಯಾಖ್ಯಾನಿಸು free_loglevel(options)
#ವ್ಯಾಖ್ಯಾನಿಸು free_ಪೋರ್ಟ್(options)
#ವ್ಯಾಖ್ಯಾನಿಸು free_gatewayports(options)
#ವ್ಯಾಖ್ಯಾನಿಸು free_streamlocalbindmask(options)
#ವ್ಯಾಖ್ಯಾನಿಸು free_streamlocalbindunlink(options)
#ವ್ಯಾಖ್ಯಾನಿಸು free_maxstartups(options)
#ವ್ಯಾಖ್ಯಾನಿಸು free_persourcenetblocksize(options)
#ವ್ಯಾಖ್ಯಾನಿಸು free_persourcepenalties(options)
#ವ್ಯಾಖ್ಯಾನಿಸು free_rekeylimit(options)
#ವ್ಯಾಖ್ಯಾನಿಸು free_pubkey_auth_options(options)
#ವ್ಯಾಖ್ಯಾನಿಸು free_timingsecret(options)

	SSHD_CONFIG_ENTRIES

#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು free_ipqos
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು free_logfacility
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು free_loglevel
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು free_ಪೋರ್ಟ್
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು free_gatewayports
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು free_streamlocalbindmask
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು free_streamlocalbindunlink
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು free_maxstartups
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು free_persourcenetblocksize
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು free_persourcepenalties
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು free_rekeylimit
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು free_timingsecret

#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_INT
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_INTFLAG
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_STRING
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_STRARRAY
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_CUSTOM
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_NONCONF
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_DEPRECATE
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_UNSUPPORTED_INT
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_UNSUPPORTED_STRING
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_ALIAS

	initialize_server_options(options);
}

ಸ್ಥಿರ ಶೂನ್ಯ
copy_server_option_int(ಪೂರ್ಣಾಂಕ *dst, ಪೂರ್ಣಾಂಕ src)
{
	ಆದರೆ (src != -1)
		*dst = src;
}

ಸ್ಥಿರ ಶೂನ್ಯ
copy_server_option_int64(int64_t *dst, int64_t src)
{
	ಆದರೆ (src != -1)
		*dst = src;
}

ಸ್ಥಿರ ಶೂನ್ಯ
copy_server_option_string(ಅಕ್ಷರ **dst, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *src)
{
	ಆದರೆ (src != ಖಾಲಿ && *dst != src) {
		ಬಿಡುಗಡೆ(*dst);
		*dst = xstrdup(src);
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
copy_server_option_strarray_ಮೌಲ್ಯಗಳು(ಅಕ್ಷರ ***dst, u_int ndst,
    ಅಕ್ಷರ * ಸ್ಥಿರಾಂಕ *src, u_int nsrc)
{
	u_int i;

	ಆದರೆ (nsrc == 0)
		ಹಿಂತಿರುಗಿ;
	ಗಾಗಿ (i = 0; i < ndst; i++)
		ಬಿಡುಗಡೆ((*dst)[i]);
	ಬಿಡುಗಡೆ(*dst);
	*dst = xcalloc(nsrc, ಗಾತ್ರ(**dst));
	ಗಾಗಿ (i = 0; i < nsrc; i++)
		(*dst)[i] = src[i] == ಖಾಲಿ ? ಖಾಲಿ : xstrdup(src[i]);
}

ಸ್ಥಿರ ಶೂನ್ಯ
copy_server_option_strarray(ಅಕ್ಷರ ***dst, u_int *ndst,
    ಅಕ್ಷರ * ಸ್ಥಿರಾಂಕ *src, u_int nsrc)
{
	ಆದರೆ (nsrc == 0)
		ಹಿಂತಿರುಗಿ;
	copy_server_option_strarray_ಮೌಲ್ಯಗಳು(dst, *ndst, src, nsrc);
	*ndst = nsrc;
}

ಸ್ಥಿರ ಶೂನ್ಯ
copy_ipqos(ServerOptions *dst, ಸ್ಥಿರಾಂಕ ServerOptions *src)
{
	copy_server_option_int(&dst->ip_qos_interactive,
	    src->ip_qos_interactive);
	copy_server_option_int(&dst->ip_qos_bulk, src->ip_qos_bulk);
}

ಸ್ಥಿರ ಶೂನ್ಯ
copy_gatewayports(ServerOptions *dst, ಸ್ಥಿರಾಂಕ ServerOptions *src)
{
	copy_server_option_int(&dst->fwd_opts.gateway_ports,
	    src->fwd_opts.gateway_ports);
}

ಸ್ಥಿರ ಶೂನ್ಯ
copy_streamlocalbindunlink(ServerOptions *dst, ಸ್ಥಿರಾಂಕ ServerOptions *src)
{
	copy_server_option_int(&dst->fwd_opts.streamlocal_bind_unlink,
	    src->fwd_opts.streamlocal_bind_unlink);
}

ಸ್ಥಿರ ಶೂನ್ಯ
copy_loglevel(ServerOptions *dst, ಸ್ಥಿರಾಂಕ ServerOptions *src)
{
	ಆದರೆ (src->log_level != -1)
		dst->log_level = src->log_level;
}

ಸ್ಥಿರ ಶೂನ್ಯ
copy_rekeylimit(ServerOptions *dst, ಸ್ಥಿರಾಂಕ ServerOptions *src)
{
	copy_server_option_int64(&dst->rekey_ಎಲ್ಲೆ, src->rekey_ಎಲ್ಲೆ);
	copy_server_option_int(&dst->rekey_interval, src->rekey_interval);
}

ಸ್ಥಿರ ಶೂನ್ಯ
copy_subsystem(ServerOptions *dst, ಸ್ಥಿರಾಂಕ ServerOptions *src)
{
	u_int old_ಅಂಕೆ_subsystems = dst->ಅಂಕೆ_subsystems;

	ಆದರೆ (src->ಅಂಕೆ_subsystems == 0)
		ಹಿಂತಿರುಗಿ;
	copy_server_option_strarray_ಮೌಲ್ಯಗಳು(&dst->subsystem_name,
	    old_ಅಂಕೆ_subsystems, src->subsystem_name, src->ಅಂಕೆ_subsystems);
	copy_server_option_strarray_ಮೌಲ್ಯಗಳು(&dst->subsystem_command,
	    old_ಅಂಕೆ_subsystems, src->subsystem_command, src->ಅಂಕೆ_subsystems);
	copy_server_option_strarray_ಮೌಲ್ಯಗಳು(&dst->subsystem_ವಾದಗಳು,
	    old_ಅಂಕೆ_subsystems, src->subsystem_ವಾದಗಳು, src->ಅಂಕೆ_subsystems);
	dst->ಅಂಕೆ_subsystems = src->ಅಂಕೆ_subsystems;
}

ಸ್ಥಿರ ಶೂನ್ಯ
copy_pubkey_auth_options(ServerOptions *dst, ಸ್ಥಿರಾಂಕ ServerOptions *src)
{
	ಆದರೆ (src->pubkey_auth_options != -1) {
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
ಶೂನ್ಯ
copy_ಗಣ_server_options(ServerOptions *dst, ServerOptions *src, ಪೂರ್ಣಾಂಕ preauth)
{
	ಆದರೆ (dst == src)
		ಹಿಂತಿರುಗಿ;

#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_INT(var, conf, flags, ms, def, cp) \
	cp(copy_server_option_int(&dst->var, src->var);)
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	cp(copy_server_option_int(&dst->var, src->var);)
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_STRING(var, conf, flags, cp) \
	cp(copy_server_option_string(&dst->var, src->var);)
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	cp(copy_server_option_strarray(&dst->var, &dst->nvar, \
	    src->var, src->nvar);)
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	cp(copy_##funcsuffix(dst, src);)
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_NONCONF(funcsuffix)			/*ಖಾಲಿಗಳು*/
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_DEPRECATE(conf, flags, opcode)		/*ಖಾಲಿಗಳು*/
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_UNSUPPORTED_INT(var, conf, flags)	dst->var = 0;
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	ಮಾಡು { \
		ಬಿಡುಗಡೆ(dst->var); \
		dst->var = ಖಾಲಿ; \
	} ಆಗ (0);
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_ALIAS(old, conf, flags)			/*ಖಾಲಿಗಳು*/

	SSHD_CONFIG_ENTRIES

#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_INT
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_INTFLAG
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_STRING
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_STRARRAY
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_CUSTOM
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_NONCONF
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_DEPRECATE
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_UNSUPPORTED_INT
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_UNSUPPORTED_STRING
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು SSHCONF_ALIAS

	/*
	 * The bind_mask is a mode_t that may be unsigned, so we can't use
	 * copy_server_option_int - it does a signed comparison that causes
	 * compiler warnings.
	 */
	ಆದರೆ (src->fwd_opts.streamlocal_bind_ಮುಖವಾಡ != (ಬಹುಲಕ_t)-1) {
		dst->fwd_opts.streamlocal_bind_ಮುಖವಾಡ =
		    src->fwd_opts.streamlocal_bind_ಮುಖವಾಡ;
	}

	/* Arguments that accept '+...' need to be expanded */
	assemble_algorithms(dst);

	/*
	 * These options may be "none" to clear a global setting.  They are
	 * consulted before authentication, so they must be cleared here
	 * rather than in the post-auth section below.
	 */
#ವ್ಯಾಖ್ಯಾನಿಸು CLEAR_ON_NONE(v) \
	ಮಾಡು { \
		ಆದರೆ (option_clear_or_none(v)) { \
			ಬಿಡುಗಡೆ(v); \
			v = ಖಾಲಿ; \
		} \
	} ಆಗ(0)
	CLEAR_ON_NONE(dst->authorized_principals_file);
	CLEAR_ON_NONE(dst->trusted_user_ca_ಕೀಲಿಗಳು);
	CLEAR_ON_NONE(dst->banner);

	/*
	 * The only things that should be below this point are string options
	 * which are only used after authentication.
	 */
	ಆದರೆ (preauth)
		ಹಿಂತಿರುಗಿ;

	/* These options may be "none" to clear a global setting */
	copy_server_option_string(&dst->adm_forced_command,
	    src->adm_forced_command);
	copy_server_option_string(&dst->chroot_directory,
	    src->chroot_directory);
	CLEAR_ON_NONE(dst->chroot_directory);
	CLEAR_ON_NONE(dst->adm_forced_command);
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು CLEAR_ON_NONE

	/* Subsystems require merging. */
	servconf_ವಿಲೀನ_subsystems(dst, src);
}

#ವ್ಯಾಖ್ಯಾನಿಸು SERVCONF_MAX_ಆಳ	16
ಸ್ಥಿರ ಶೂನ್ಯ
parse_server_config_ಆಳ(ServerOptions *options, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename,
    ರಚನೆ sshbuf *conf, ರಚನೆ include_list *includes,
    ರಚನೆ connection_info *connectinfo, ಪೂರ್ಣಾಂಕ flags, ಪೂರ್ಣಾಂಕ *activep, ಪೂರ್ಣಾಂಕ ಆಳ)
{
	ಪೂರ್ಣಾಂಕ linenum, bad_options = 0;
	ಅಕ್ಷರ *cp, *obuf, *cbuf;

	ಆದರೆ (ಆಳ < 0 || ಆಳ > SERVCONF_MAX_ಆಳ)
		fatal("Too many recursive configuration includes");

	debug2_f("config %s len %zu%s", filename, sshbuf_len(conf),
	    (flags & SSHCFG_NEVERMATCH ? " [checking syntax only]" : ""));

	ಆದರೆ ((obuf = cbuf = sshbuf_dup_string(conf)) == ಖಾಲಿ)
		fatal_f("sshbuf_dup_string failed");
	linenum = 1;
	ಆಗ ((cp = strsep(&cbuf, "\n")) != ಖಾಲಿ) {
		ಆದರೆ (process_server_config_ಸಾಲು_ಆಳ(options, cp,
		    filename, linenum++, activep, connectinfo, &flags,
		    ಆಳ, includes) != 0)
			bad_options++;
	}
	ಬಿಡುಗಡೆ(obuf);
	ಆದರೆ (bad_options > 0)
		fatal("%s: terminating, %d bad configuration options",
		    filename, bad_options);
}

ಶೂನ್ಯ
parse_server_config(ServerOptions *options, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename,
    ರಚನೆ sshbuf *conf, ರಚನೆ include_list *includes,
    ರಚನೆ connection_info *connectinfo, ಪೂರ್ಣಾಂಕ reexec)
{
	ಪೂರ್ಣಾಂಕ ಸಕ್ರಿಯ = connectinfo ? 0 : 1;
	parse_server_config_ಆಳ(options, filename, conf, includes,
	    connectinfo, (connectinfo ? SSHCFG_ಹೊಂದಿಕೆ_ONLY : 0), &ಸಕ್ರಿಯ, 0);
	ಆದರೆ (!reexec)
		process_queued_listen_addrs(options);
}

ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
fmt_multistate_int(ಪೂರ್ಣಾಂಕ val, ಸ್ಥಿರಾಂಕ ರಚನೆ multistate *m)
{
	u_int i;

	ಗಾಗಿ (i = 0; m[i].ಕೀಲಿ != ಖಾಲಿ; i++) {
		ಆದರೆ (m[i].ಮೌಲ್ಯ == val)
			ಹಿಂತಿರುಗಿ m[i].ಕೀಲಿ;
	}
	ಹಿಂತಿರುಗಿ "UNKNOWN";
}

ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
fmt_intarg(ServerOpCodes ಸಂಕೇತ_2, ಪೂರ್ಣಾಂಕ val)
{
	ಆದರೆ (val == -1)
		ಹಿಂತಿರುಗಿ "unset";
	ಆಯ್ಕೆ (ಸಂಕೇತ_2) {
	ಸ್ಥಿತಿ s_ವಿಳಾಸ_Family:
		ಹಿಂತಿರುಗಿ fmt_multistate_int(val, multistate_addressfamily);
	ಸ್ಥಿತಿ s_Permit_ಬೇರು_Login:
		ಹಿಂತಿರುಗಿ fmt_multistate_int(val, multistate_permitrootlogin);
	ಸ್ಥಿತಿ sGatewayPorts:
		ಹಿಂತಿರುಗಿ fmt_multistate_int(val, multistate_gatewayports);
	ಸ್ಥಿತಿ sCompression:
		ಹಿಂತಿರುಗಿ fmt_multistate_int(val, multistate_compression);
	ಸ್ಥಿತಿ sAllowTcpForwarding:
		ಹಿಂತಿರುಗಿ fmt_multistate_int(val, multistate_tcpfwd);
	ಸ್ಥಿತಿ s_Allow_ಹರಿವು_Local_Forwarding:
		ಹಿಂತಿರುಗಿ fmt_multistate_int(val, multistate_tcpfwd);
	ಸ್ಥಿತಿ sIgnoreRhosts:
		ಹಿಂತಿರುಗಿ fmt_multistate_int(val, multistate_ignore_rhosts);
	ಸ್ಥಿತಿ sTCPKeepAlive:
		ಹಿಂತಿರುಗಿ fmt_multistate_int(val, multistate_keepalives);
	ಸ್ಥಿತಿ sWarnWeakCrypto:
		ಹಿಂತಿರುಗಿ fmt_multistate_int(val, multistate_warnweakcrypto);
	ಸ್ಥಿತಿ sFingerprintHash:
		ಹಿಂತಿರುಗಿ ssh_digest_alg_name(val);
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಆಯ್ಕೆ (val) {
		ಸ್ಥಿತಿ 0:
			ಹಿಂತಿರುಗಿ "no";
		ಸ್ಥಿತಿ 1:
			ಹಿಂತಿರುಗಿ "yes";
		ಪೂರ್ವನಿಯೋಜಿತ:
			ಹಿಂತಿರುಗಿ "UNKNOWN";
		}
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
dump_cfg_int(ServerOpCodes ಸಂಕೇತ_2, ಪೂರ್ಣಾಂಕ val)
{
	ಆದರೆ (ಸಂಕೇತ_2 == s_ಬಳಸದ_Connection_Timeout && val == 0) {
		ಬರೆ("%s none\n", lookup_opcode_name(ಸಂಕೇತ_2));
		ಹಿಂತಿರುಗಿ;
	}
	ಬರೆ("%s %d\n", lookup_opcode_name(ಸಂಕೇತ_2), val);
}

ಸ್ಥಿರ ಶೂನ್ಯ
dump_cfg_oct(ServerOpCodes ಸಂಕೇತ_2, ಪೂರ್ಣಾಂಕ val)
{
	ಬರೆ("%s 0%o\n", lookup_opcode_name(ಸಂಕೇತ_2), val);
}

ಸ್ಥಿರ ಶೂನ್ಯ
dump_cfg_fmtint(ServerOpCodes ಸಂಕೇತ_2, ಪೂರ್ಣಾಂಕ val)
{
	ಬರೆ("%s %s\n", lookup_opcode_name(ಸಂಕೇತ_2), fmt_intarg(ಸಂಕೇತ_2, val));
}

ಸ್ಥಿರ ಶೂನ್ಯ
dump_cfg_string(ServerOpCodes ಸಂಕೇತ_2, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *val)
{
	ಬರೆ("%s %s\n", lookup_opcode_name(ಸಂಕೇತ_2),
	    val == ಖಾಲಿ ? "none" : val);
}

ಸ್ಥಿರ ಶೂನ್ಯ
dump_cfg_strarray(ServerOpCodes ಸಂಕೇತ_2, u_int ಎಣಿಕೆ_2, ಅಕ್ಷರ **vals)
{
	u_int i;

	ಗಾಗಿ (i = 0; i < ಎಣಿಕೆ_2; i++)
		ಬರೆ("%s %s\n", lookup_opcode_name(ಸಂಕೇತ_2), vals[i]);
}

ಸ್ಥಿರ ಶೂನ್ಯ
dump_cfg_strarray_oneline(ServerOpCodes ಸಂಕೇತ_2, u_int ಎಣಿಕೆ_2, ಅಕ್ಷರ **vals)
{
	u_int i;

	ಆಯ್ಕೆ (ಸಂಕೇತ_2) {
	ಸ್ಥಿತಿ sAuthenticationMethods:
	ಸ್ಥಿತಿ sChannelTimeout:
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಆದರೆ (ಎಣಿಕೆ_2 <= 0)
			ಹಿಂತಿರುಗಿ;
		ನಿಲ್ಲಿಸು;
	}

	ಬರೆ("%s", lookup_opcode_name(ಸಂಕೇತ_2));
	ಗಾಗಿ (i = 0; i < ಎಣಿಕೆ_2; i++)
		ಬರೆ(" %s",  vals[i]);
	ಆದರೆ (ಸಂಕೇತ_2 == sAuthenticationMethods && ಎಣಿಕೆ_2 == 0)
		ಬರೆ(" any");
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ಸಂಕೇತ_2 == sChannelTimeout && ಎಣಿಕೆ_2 == 0)
		ಬರೆ(" none");
	ಬರೆ("\n");
}

ಸ್ಥಿರ ಅಕ್ಷರ *
format_listen_addrs(ರಚನೆ listenaddr *la)
{
	ಪೂರ್ಣಾಂಕ r;
	ರಚನೆ addrinfo *ai;
	ಅಕ್ಷರ addr[NI_MAXHOST], ಪೋರ್ಟ್[NI_MAXSERV];
	ಅಕ್ಷರ *laddr1 = xstrdup(""), *laddr2 = ಖಾಲಿ;

	/*
	 * ListenAddress must be after Port.  add_one_listen_addr pushes
	 * addresses onto a stack, so to maintain ordering we need to
	 * print these in reverse order.
	 */
	ಗಾಗಿ (ai = la->addrs; ai; ai = ai->ai_next) {
		ಆದರೆ ((r = getnameinfo(ai->ai_addr, ai->ai_addrlen, addr,
		    ಗಾತ್ರ(addr), ಪೋರ್ಟ್, ಗಾತ್ರ(ಪೋರ್ಟ್),
		    NI_NUMERICHOST|NI_NUMERICSERV)) != 0) {
			error("getnameinfo: %.100s", ssh_gai_strerror(r));
			ಮುಂದುವರಿ;
		}
		laddr2 = laddr1;
		ಆದರೆ (ai->ai_family == AF_INET6) {
			xasprintf(&laddr1, "ListenAddress [%s]:%s%s%s\n%s",
			    addr, ಪೋರ್ಟ್,
			    la->rdomain == ಖಾಲಿ ? "" : " rdomain ",
			    la->rdomain == ಖಾಲಿ ? "" : la->rdomain,
			    laddr2);
		} ಇಲ್ಲದಿದ್ದರೆ {
			xasprintf(&laddr1, "ListenAddress %s:%s%s%s\n%s",
			    addr, ಪೋರ್ಟ್,
			    la->rdomain == ಖಾಲಿ ? "" : " rdomain ",
			    la->rdomain == ಖಾಲಿ ? "" : la->rdomain,
			    laddr2);
		}
		ಬಿಡುಗಡೆ(laddr2);
	}
	ಹಿಂತಿರುಗಿ laddr1;
}

ಶೂನ್ಯ
dump_config(ServerOptions *o)
{
	ಅಕ್ಷರ *s;
	u_int i;

	/* these are usually at the top of the config */
	ಗಾಗಿ (i = 0; i < o->ಅಂಕೆ_ports; i++)
		ಬರೆ("Port %d\n", o->ports[i]);
	dump_cfg_fmtint(s_ವಿಳಾಸ_Family, o->ವಿಳಾಸ_family);

	ಗಾಗಿ (i = 0; i < o->ಅಂಕೆ_listen_addrs; i++) {
		s = format_listen_addrs(&o->listen_addrs[i]);
		ಬರೆ("%s", s);
		ಬಿಡುಗಡೆ(s);
	}

	/* integer arguments */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_PAM
	dump_cfg_fmtint(sUsePAM, o->use_pam);
	dump_cfg_string(sPAMServiceName, o->pam_service_name);
#ಆದರೆ_ಅಂತ್ಯ
	dump_cfg_int(s_Login_Grace_ಸಮಯ, o->login_grace_ಸಮಯ);
	dump_cfg_int(s_X11_Display_ಸ್ಥಾನಾಂತರ, o->x11_display_ಸ್ಥಾನಾಂತರ);
	dump_cfg_int(sMaxAuthTries, o->max_authtries);
	dump_cfg_int(sMaxSessions, o->max_sessions);
	dump_cfg_int(sClientAliveInterval, o->client_alive_interval);
	dump_cfg_int(s_Client_Alive_ಎಣಿಕೆ_Max, o->client_alive_ಎಣಿಕೆ_max);
	dump_cfg_int(sRequiredRSASize, o->required_rsa_ಗಾತ್ರ);
	dump_cfg_oct(s_ಹರಿವು_Local_Bind_ಮುಖವಾಡ, o->fwd_opts.streamlocal_bind_ಮುಖವಾಡ);
	dump_cfg_int(s_ಬಳಸದ_Connection_Timeout, o->ಬಳಸದ_connection_timeout);

	/* formatted integer arguments */
	dump_cfg_fmtint(s_Permit_ಬೇರು_Login, o->permit_ಬೇರು_login);
	dump_cfg_fmtint(sIgnoreRhosts, o->ignore_rhosts);
	dump_cfg_fmtint(s_Ignore_User_ತಿಳಿದ_Hosts, o->ignore_user_ತಿಳಿದ_hosts);
	dump_cfg_fmtint(sHostbasedAuthentication, o->hostbased_authentication);
	dump_cfg_fmtint(s_Hostbased_ಬಳಸುತ್ತದೆ_Name_From_Packet_Only,
	    o->hostbased_ಬಳಸುತ್ತದೆ_name_from_packet_only);
	dump_cfg_fmtint(sPubkeyAuthentication, o->pubkey_authentication);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ KRB5
	dump_cfg_fmtint(sKerberosAuthentication, o->kerberos_authentication);
	dump_cfg_fmtint(sKerberosOrLocalPasswd, o->kerberos_or_local_passwd);
	dump_cfg_fmtint(sKerberosTicketCleanup, o->kerberos_ticket_cleanup);
# ifdef USE_AFS
	dump_cfg_fmtint(sKerberosGetAFSToken, o->kerberos_get_afs_token);
# endif
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ GSSAPI
	dump_cfg_fmtint(sGSSAPIAuthentication, o->gss_authentication);
	dump_cfg_fmtint(sGSSAPICleanupCredentials, o->gss_cleanup_creds);
	dump_cfg_fmtint(sGSSAPIDelegateCredentials, o->gss_deleg_creds);
	dump_cfg_fmtint(sGSSAPIStrictAcceptorCheck, o->gss_strict_acceptor);
#ಆದರೆ_ಅಂತ್ಯ
	dump_cfg_fmtint(sPasswordAuthentication, o->password_authentication);
	dump_cfg_fmtint(sKbdInteractiveAuthentication,
	    o->kbd_interactive_authentication);
	dump_cfg_fmtint(sPrintMotd, o->print_motd);
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ DISABLE_LASTLOG
	dump_cfg_fmtint(s_Print_ಕೊನೆಯ_Log, o->print_lastlog);
#ಆದರೆ_ಅಂತ್ಯ
	dump_cfg_fmtint(sX11Forwarding, o->x11_forwarding);
	dump_cfg_fmtint(sX11UseLocalhost, o->x11_use_localhost);
	dump_cfg_fmtint(sPermitTTY, o->permit_tty);
	dump_cfg_fmtint(sPermitUserRC, o->permit_user_rc);
	dump_cfg_fmtint(sStrictModes, o->strict_modes);
	dump_cfg_fmtint(sTCPKeepAlive, o->tcp_keep_alive);
	dump_cfg_fmtint(s_Permit_ಖಾಲಿಗಳು_Passwords, o->permit_ಖಾಲಿಗಳು_passwd);
	dump_cfg_fmtint(sCompression, o->compression);
	dump_cfg_fmtint(sGatewayPorts, o->fwd_opts.gateway_ports);
	dump_cfg_fmtint(sUseDNS, o->use_dns);
	dump_cfg_fmtint(sAllowTcpForwarding, o->allow_tcp_forwarding);
	dump_cfg_fmtint(sAllowAgentForwarding, o->allow_agent_forwarding);
	dump_cfg_fmtint(sDisableForwarding, o->disable_forwarding);
	dump_cfg_fmtint(s_Allow_ಹರಿವು_Local_Forwarding, o->allow_streamlocal_forwarding);
	dump_cfg_fmtint(s_ಹರಿವು_Local_Bind_Unlink, o->fwd_opts.streamlocal_bind_unlink);
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
	dump_cfg_string(sTrustedUserCAKeys, o->trusted_user_ca_ಕೀಲಿಗಳು);
	dump_cfg_string(s_Security_ಕೀಲಿ_Provider, o->sk_provider);
	dump_cfg_string(sAuthorizedPrincipalsFile,
	    o->authorized_principals_file);
	dump_cfg_string(s_ಆವೃತ್ತಿ_Addendum, *o->ಆವೃತ್ತಿ_addendum == '\0'
	    ? "none" : o->ಆವೃತ್ತಿ_addendum);
	dump_cfg_string(s_Authorized_ಕೀಲಿಗಳು_Command, o->authorized_ಕೀಲಿಗಳು_command);
	dump_cfg_string(s_Authorized_ಕೀಲಿಗಳು_Command_User, o->authorized_ಕೀಲಿಗಳು_command_user);
	dump_cfg_string(sAuthorizedPrincipalsCommand, o->authorized_principals_command);
	dump_cfg_string(sAuthorizedPrincipalsCommandUser, o->authorized_principals_command_user);
	dump_cfg_string(s_Host_ಕೀಲಿ_Agent, o->host_ಕೀಲಿ_agent);
	dump_cfg_string(sKexAlgorithms, o->kex_algorithms);
	dump_cfg_string(sCASignatureAlgorithms, o->ca_sign_algorithms);
	dump_cfg_string(sHostbasedAcceptedAlgorithms, o->hostbased_accepted_algos);
	dump_cfg_string(s_Host_ಕೀಲಿ_Algorithms, o->hostkeyalgorithms);
	dump_cfg_string(sPubkeyAcceptedAlgorithms, o->pubkey_accepted_algos);
#ಆದರೆ defined(__OpenBSD__) || defined(HAVE_SYS_ಗಣ_PROCESS_RDOMAIN)
	dump_cfg_string(sRDomain, o->routing_domain);
#ಆದರೆ_ಅಂತ್ಯ
	dump_cfg_string(s_Sshd_Session_ಮಾರ್ಗ, o->sshd_session_ಮಾರ್ಗ);
	dump_cfg_string(s_Sshd_Auth_ಮಾರ್ಗ, o->sshd_auth_ಮಾರ್ಗ);
	dump_cfg_string(s_ಪ್ರತಿ_ಮೂಲ_Penalty_Exempt_List, o->ಪ್ರತಿ_ಮೂಲ_penalty_exempt);
	dump_cfg_string(s_Agent_Socket_ಮಾರ್ಗ, o->agent_socket_ಮಾರ್ಗ);

	/* string arguments requiring a lookup */
	dump_cfg_string(sLogLevel, log_level_name(o->log_level));
	dump_cfg_string(sSyslogFacility, log_facility_name(o->log_facility));

	/* string array arguments */
	dump_cfg_strarray_oneline(s_Authorized_ಕೀಲಿಗಳು_File, o->ಅಂಕೆ_authkeys_files,
	    o->authorized_ಕೀಲಿಗಳು_files);
	dump_cfg_strarray_oneline(s_Revoked_ಕೀಲಿಗಳು, o->ಅಂಕೆ_revoked_ಕೀಲಿಗಳು_files,
	    o->revoked_ಕೀಲಿಗಳು_files);
	dump_cfg_strarray(s_Host_ಕೀಲಿ, o->ಅಂಕೆ_host_ಕೀಲಿ_files, o->host_ಕೀಲಿ_files);
	dump_cfg_strarray(sHostCertificate, o->ಅಂಕೆ_host_cert_files,
	    o->host_cert_files);
	dump_cfg_strarray(sAllowUsers, o->ಅಂಕೆ_allow_users, o->allow_users);
	dump_cfg_strarray(sDenyUsers, o->ಅಂಕೆ_deny_users, o->deny_users);
	dump_cfg_strarray(sAllowGroups, o->ಅಂಕೆ_allow_groups, o->allow_groups);
	dump_cfg_strarray(sDenyGroups, o->ಅಂಕೆ_deny_groups, o->deny_groups);
	dump_cfg_strarray(sAcceptEnv, o->ಅಂಕೆ_accept_env, o->accept_env);
	dump_cfg_strarray(s_ಗಣ_Env, o->ಅಂಕೆ_setenv, o->setenv);
	dump_cfg_strarray_oneline(sAuthenticationMethods,
	    o->ಅಂಕೆ_auth_methods, o->auth_methods);
	dump_cfg_strarray_oneline(sLogVerbose,
	    o->ಅಂಕೆ_log_verbose, o->log_verbose);
	dump_cfg_strarray_oneline(sChannelTimeout,
	    o->ಅಂಕೆ_channel_timeouts, o->channel_timeouts);

	/* other arguments */
	ಗಾಗಿ (i = 0; i < o->ಅಂಕೆ_subsystems; i++)
		ಬರೆ("Subsystem %s %s\n", o->subsystem_name[i],
		    o->subsystem_ವಾದಗಳು[i]);

	ಬರೆ("MaxStartups %d:%d:%d\n", o->max_startups_begin,
	    o->max_startups_ದರ, o->max_startups);
	ಬರೆ("PerSourceMaxStartups ");
	ಆದರೆ (o->ಪ್ರತಿ_ಮೂಲ_max_startups == ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ)
		ಬರೆ("none\n");
	ಇಲ್ಲದಿದ್ದರೆ
		ಬರೆ("%d\n", o->ಪ್ರತಿ_ಮೂಲ_max_startups);
	ಬರೆ("PerSourceNetBlockSize %d:%d\n", o->ಪ್ರತಿ_ಮೂಲ_masklen_ipv4,
	    o->ಪ್ರತಿ_ಮೂಲ_masklen_ipv6);

	s = ಖಾಲಿ;
	ಗಾಗಿ (i = 0; tunmode_desc[i].val != -1; i++) {
		ಆದರೆ (tunmode_desc[i].val == o->permit_tun) {
			s = tunmode_desc[i].ಪಠ್ಯ;
			ನಿಲ್ಲಿಸು;
		}
	}
	dump_cfg_string(sPermitTunnel, s);

	ಬರೆ("IPQoS %s ", iptos2str(o->ip_qos_interactive));
	ಬರೆ("%s\n", iptos2str(o->ip_qos_bulk));

	ಬರೆ("RekeyLimit %llu %d\n", (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)o->rekey_ಎಲ್ಲೆ,
	    o->rekey_interval);

	ಬರೆ("PermitOpen");
	ಆದರೆ (o->ಅಂಕೆ_permitted_opens == 0)
		ಬರೆ(" any");
	ಇಲ್ಲದಿದ್ದರೆ {
		ಗಾಗಿ (i = 0; i < o->ಅಂಕೆ_permitted_opens; i++)
			ಬರೆ(" %s", o->permitted_opens[i]);
	}
	ಬರೆ("\n");
	ಬರೆ("PermitListen");
	ಆದರೆ (o->ಅಂಕೆ_permitted_listens == 0)
		ಬರೆ(" any");
	ಇಲ್ಲದಿದ್ದರೆ {
		ಗಾಗಿ (i = 0; i < o->ಅಂಕೆ_permitted_listens; i++)
			ಬರೆ(" %s", o->permitted_listens[i]);
	}
	ಬರೆ("\n");

	ಆದರೆ (o->permit_user_env_allowlist == ಖಾಲಿ) {
		dump_cfg_fmtint(sPermitUserEnvironment, o->permit_user_env);
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಬರೆ("PermitUserEnvironment %s\n",
		    o->permit_user_env_allowlist);
	}

	ಬರೆ("PubkeyAuthOptions");
	ಆದರೆ (o->pubkey_auth_options == 0)
		ಬರೆ(" none");
	ಆದರೆ (o->pubkey_auth_options & PUBKEYAUTH_TOUCH_REQUIRED)
		ಬರೆ(" touch-required");
	ಆದರೆ (o->pubkey_auth_options & PUBKEYAUTH_VERIFY_REQUIRED)
		ಬರೆ(" verify-required");
	ಆದರೆ (o->max_pubkey_ok != -1)
		ಬರೆ(" max-pk-ok:%d", o->max_pubkey_ok);
	ಬರೆ("\n");

	ಆದರೆ (o->ಪ್ರತಿ_ಮೂಲ_penalty.enabled) {
		ಬರೆ("PerSourcePenalties crash:%f authfail:%f noauth:%f "
		    "invaliduser:%f "
		    "grace-exceeded:%f refuseconnection:%f max:%f min:%f "
		    "max-sources4:%d max-sources6:%d "
		    "overflow:%s overflow6:%s\n",
		    o->ಪ್ರತಿ_ಮೂಲ_penalty.penalty_crash,
		    o->ಪ್ರತಿ_ಮೂಲ_penalty.penalty_authfail,
		    o->ಪ್ರತಿ_ಮೂಲ_penalty.penalty_noauth,
		    o->ಪ್ರತಿ_ಮೂಲ_penalty.penalty_invaliduser,
		    o->ಪ್ರತಿ_ಮೂಲ_penalty.penalty_grace,
		    o->ಪ್ರತಿ_ಮೂಲ_penalty.penalty_refuseconnection,
		    o->ಪ್ರತಿ_ಮೂಲ_penalty.penalty_max,
		    o->ಪ್ರತಿ_ಮೂಲ_penalty.penalty_min,
		    o->ಪ್ರತಿ_ಮೂಲ_penalty.max_sources4,
		    o->ಪ್ರತಿ_ಮೂಲ_penalty.max_sources6,
		    o->ಪ್ರತಿ_ಮೂಲ_penalty.ಅತಿಪ್ರವಾಹ_ಬಹುಲಕ ==
		    ಪ್ರತಿ_ಮೂಲ_PENALTY_ಅತಿಪ್ರವಾಹ_DENY_ALL ?
		    "deny-all" : "permissive",
		    o->ಪ್ರತಿ_ಮೂಲ_penalty.ಅತಿಪ್ರವಾಹ_mode6 ==
		    ಪ್ರತಿ_ಮೂಲ_PENALTY_ಅತಿಪ್ರವಾಹ_DENY_ALL ?
		    "deny-all" : "permissive");
	} ಇಲ್ಲದಿದ್ದರೆ
		ಬರೆ("PerSourcePenalties no\n");
}
