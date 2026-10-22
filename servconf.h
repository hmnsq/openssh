/* $OpenBSD: servconf.h,v 1.183 2026/09/16 00:29:44 djm Exp $ */

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Definitions for server configuration data and for the functions reading it.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ SERVCONF_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SERVCONF_H

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/queue.h>

ਬਣਤਰ sshbuf;

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MAX_PORTS		256	/* Max # ports. */

/* permit_root_login */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	PERMIT_NOT_ਸੈੱਟ		-1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	PERMIT_NO		0
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	PERMIT_FORCED_ONLY	1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	PERMIT_NO_PASSWD	2
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	PERMIT_YES		3

/* PermitOpen */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ PERMITOPEN_ANY		0
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ PERMITOPEN_NONE		-2

/* IgnoreRhosts */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ IGNORE_RHOSTS_NO	0
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ IGNORE_RHOSTS_YES	1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ IGNORE_RHOSTS_SHOSTS	2

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DEFAULT_AUTH_FAIL_MAX	6	/* Default for MaxAuthTries */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DEFAULT_SESSIONS_MAX	10	/* Default for MaxSessions */

/* Magic name for internal sftp-server */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਅੰਦਰੂਨੀ_SFTP_NAME	"internal-sftp"

/* PubkeyAuthOptions flags */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ PUBKEYAUTH_TOUCH_REQUIRED	(1)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ PUBKEYAUTH_VERIFY_REQUIRED	(1<<1)

/* Various defaults */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHD_DEFAULT_LOGIN_GRACE_ਸਮਾਂ	120
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHD_DEFAULT_X11_DISPLAY_ਵਿੱਥ	10
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_ZLIB
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHD_DEFAULT_COMPRESSION	COMP_DELAYED
#ਨਹੀਂਤਾਂ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHD_DEFAULT_COMPRESSION	COMP_NONE
#ਜੇ_ਅੰਤ

/* TCPKeepAlive flags */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_KEEPALIVES_OFF		0
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_KEEPALIVES_TRANSPORT	1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_KEEPALIVES_ALL		2

ਬਣਤਰ ssh;

/*
 * Used to store addresses from ListenAddr directives. These may be
 * incomplete, as they may specify addresses that need to be merged
 * with any ports requested by ListenPort.
 */
ਬਣਤਰ queued_listenaddr {
	ਅੱਖਰ *addr;
	ਪੂਰਨ ਪੋਰਟ; /* <=0 if unspecified */
	ਅੱਖਰ *rdomain;
};

/* Resolved listen addresses, grouped by optional routing domain */
ਬਣਤਰ listenaddr {
	ਅੱਖਰ *rdomain;
	ਬਣਤਰ addrinfo *addrs;
};

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਪ੍ਰਤੀ_ਸਰੋਤ_PENALTY_ਉਛਾਲ_DENY_ALL	1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਪ੍ਰਤੀ_ਸਰੋਤ_PENALTY_ਉਛਾਲ_PERMISSIVE	2
ਬਣਤਰ ਪ੍ਰਤੀ_ਸਰੋਤ_penalty {
	ਪੂਰਨ	enabled;
	ਪੂਰਨ	max_sources4;
	ਪੂਰਨ	max_sources6;
	ਪੂਰਨ	ਉਛਾਲ_ਬਹੁਲਕ;
	ਪੂਰਨ	ਉਛਾਲ_mode6;
	ਦੁੱਗਣਾ	penalty_crash;
	ਦੁੱਗਣਾ	penalty_grace;
	ਦੁੱਗਣਾ	penalty_authfail;
	ਦੁੱਗਣਾ	penalty_invaliduser;
	ਦੁੱਗਣਾ	penalty_noauth;
	ਦੁੱਗਣਾ	penalty_refuseconnection;
	ਦੁੱਗਣਾ	penalty_max;
	ਦੁੱਗਣਾ	penalty_min;
};

/* Options for whether config entries are copied after Match processing */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCFG_COPY_NONE(action)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCFG_COPY_ਮੇਲ(action)	action
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCFG_COPY_MANUAL(action)

/*
 * This macro is used to generate most of ServerOptions and some of the
 * parsing and de/serialisation code in servconf.c. Every variable in
 * ServerOptions *must* be represented here.
 *
 * Variables and configuration options that need special handling (e.g.
 * those that represent a struct or use a single option to populate multiple
 * values) use the SSHCONF_CUSTOM macro and get manual variable entries in
 * ServerOptions below.
 *
 * Variables that exist in ServerOptions but aren't populated by a keyword
 * use the SSHCONF_NONCONF macro and also get manual entries in ServerOptions.
 *
 * Everything else uses one of the SSHCONF_INT, SSHCONF_INTFLAG,
 * SSHCONF_STRING, or SSHCONF_STRARRAY macros. These automatically populate
 * their corresponding variable definitions in ServerOptions. The integer
 * options also include defaults for initialisation.
 *
 * Deprecated and ignored options use SSHCONF_DEPRECATE and don't populate
 * ServerOptions. Unsupported options use SSHCONF_UNSUPPORTED_INT or
 * SSHCONF_UNSUPPORTED_STRING to populate placeholders in ServerOptions that
 * are not otherwise used. Deprecated aliases that still work use
 * SSHCONF_ALIAS.
 *
 * Why go to all this trouble? It ensures a level of consistency between
 * the configuration structure and the parsing code and helps us write
 * serialisation/deserialisation functions that we can be pretty sure will
 * capture every value in the configuration file.
 *
 * Entry formats:
 *   SSHCONF_INT(field, keyword, scope, multistate, default, copy)
 *   SSHCONF_INTFLAG(field, keyword, scope, default, copy)
 *   SSHCONF_STRING(field, keyword, scope, copy)
 *   SSHCONF_STRARRAY(field, nfield, keyword, scope, copy)
 *   SSHCONF_CUSTOM(keyword, suffix, scope, copy)
 *   SSHCONF_NONCONF(suffix)
 *   SSHCONF_DEPRECATE(keyword, scope, token)
 *   SSHCONF_UNSUPPORTED_INT(field, keyword, scope)
 *   SSHCONF_UNSUPPORTED_STRING(field, keyword, scope)
 *   SSHCONF_ALIAS(old_keyword, keyword, scope)
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHD_CONFIG_ENTRIES_CUSTOM \
SSHCONF_CUSTOM(ਪੋਰਟ_2, ਪੋਰਟ, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(Listen_ਪਤਾ, listenaddress, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(Host_ਕੁੰਜੀ, hostkeyfile, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(IPQoS, ipqos, SSHCFG_ALL, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_CUSTOM(GatewayPorts, gatewayports, SSHCFG_ALL, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_CUSTOM(ਧਾਰਾ_Local_Bind_ਨਕਾਬ, streamlocalbindmask, SSHCFG_ALL, SSHCFG_COPY_MANUAL) \
SSHCONF_CUSTOM(ਧਾਰਾ_Local_Bind_Unlink, streamlocalbindunlink, SSHCFG_ALL, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_CUSTOM(SyslogFacility, logfacility, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(LogLevel, loglevel, SSHCFG_ALL, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_CUSTOM(PermitUserEnvironment, permituserenv, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(Subsystem, subsystem, SSHCFG_ALL, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_CUSTOM(MaxStartups, maxstartups, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(ਪ੍ਰਤੀ_ਸਰੋਤ_Net_ਖੰਡ_ਮਾਪ, persourcenetblocksize, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(ਪ੍ਰਤੀ_ਸਰੋਤ_Penalties, persourcepenalties, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(Rekey_ਹੱਦਬੰਦੀ, rekeylimit, SSHCFG_ALL, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_CUSTOM(PubkeyAuthOptions, pubkey_auth_options, SSHCFG_ALL, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_NONCONF(timingsecret)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHD_CONFIG_ENTRIES_MAIN \
SSHCONF_INT(ਪਤਾ_family, ਪਤਾ_Family, SSHCFG_GLOBAL, multistate_addressfamily, AF_UNSPEC, SSHCFG_COPY_NONE) \
SSHCONF_STRING(routing_domain, RDomain, SSHCFG_ALL, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_STRARRAY(host_cert_files, ਅੰਕ_host_cert_files, HostCertificate, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(host_ਕੁੰਜੀ_agent, Host_ਕੁੰਜੀ_Agent, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(pid_file, PidFile, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(moduli_file, ModuliFile, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_INT(login_grace_ਸਮਾਂ, Login_Grace_ਸਮਾਂ, SSHCFG_GLOBAL, ਨਿਰਾ, SSHD_DEFAULT_LOGIN_GRACE_ਸਮਾਂ, SSHCFG_COPY_NONE) \
SSHCONF_INT(permit_ਜੜ੍ਹ_login, Permit_ਜੜ੍ਹ_Login, SSHCFG_ALL, multistate_permitrootlogin, PERMIT_NO_PASSWD, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_INT(ignore_rhosts, IgnoreRhosts, SSHCFG_ALL, multistate_ignore_rhosts, 1, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_INTFLAG(ignore_user_ਗਿਆਤ_hosts, Ignore_User_ਗਿਆਤ_Hosts, SSHCFG_GLOBAL, 0, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(print_motd, PrintMotd, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(x11_forwarding, X11Forwarding, SSHCFG_ALL, 0, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_INT(x11_display_ਵਿੱਥ, X11_Display_ਵਿੱਥ, SSHCFG_ALL, ਨਿਰਾ, SSHD_DEFAULT_X11_DISPLAY_ਵਿੱਥ, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_INTFLAG(x11_use_localhost, X11UseLocalhost, SSHCFG_ALL, 1, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_STRING(xauth_location, XAuthLocation, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(permit_tty, PermitTTY, SSHCFG_ALL, 1, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_INTFLAG(permit_user_rc, PermitUserRC, SSHCFG_ALL, 1, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_INTFLAG(strict_modes, StrictModes, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(tcp_keep_alive, TCPKeepAlive, SSHCFG_GLOBAL, SSH_KEEPALIVES_TRANSPORT, SSHCFG_COPY_NONE) \
SSHCONF_STRING(ciphers, Ciphers, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(macs, Macs, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(kex_algorithms, KexAlgorithms, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRARRAY(log_verbose, ਅੰਕ_log_verbose, LogVerbose, SSHCFG_ALL, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_INTFLAG(hostbased_authentication, HostbasedAuthentication, SSHCFG_ALL, 0, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_INTFLAG(hostbased_ਵਰਤਦਾ_name_from_packet_only, Hostbased_ਵਰਤਦਾ_Name_From_Packet_Only, SSHCFG_ALL, 0, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_STRING(hostbased_accepted_algos, HostbasedAcceptedAlgorithms, SSHCFG_ALL, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_STRING(hostkeyalgorithms, Host_ਕੁੰਜੀ_Algorithms, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(ca_sign_algorithms, CASignatureAlgorithms, SSHCFG_ALL, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_INTFLAG(pubkey_authentication, PubkeyAuthentication, SSHCFG_ALL, 1, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_STRING(pubkey_accepted_algos, PubkeyAcceptedAlgorithms, SSHCFG_ALL, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_INTFLAG(password_authentication, PasswordAuthentication, SSHCFG_ALL, 1, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_INTFLAG(kbd_interactive_authentication, KbdInteractiveAuthentication, SSHCFG_ALL, 1, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_INTFLAG(permit_ਖਾਲੀ_ਥਾਵਾਂ_passwd, Permit_ਖਾਲੀ_ਥਾਵਾਂ_Passwords, SSHCFG_ALL, 0, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_INT(compression, Compression, SSHCFG_GLOBAL, multistate_compression, SSHD_DEFAULT_COMPRESSION, SSHCFG_COPY_NONE) \
SSHCONF_INT(allow_tcp_forwarding, AllowTcpForwarding, SSHCFG_ALL, multistate_tcpfwd, FORWARD_ALLOW, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_INT(allow_streamlocal_forwarding, Allow_ਧਾਰਾ_Local_Forwarding, SSHCFG_ALL, multistate_tcpfwd, FORWARD_ALLOW, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_INTFLAG(allow_agent_forwarding, AllowAgentForwarding, SSHCFG_ALL, 1, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_INTFLAG(disable_forwarding, DisableForwarding, SSHCFG_ALL, 0, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_STRARRAY(allow_users, ਅੰਕ_allow_users, AllowUsers, SSHCFG_ALL, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_STRARRAY(deny_users, ਅੰਕ_deny_users, DenyUsers, SSHCFG_ALL, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_STRARRAY(allow_groups, ਅੰਕ_allow_groups, AllowGroups, SSHCFG_ALL, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_STRARRAY(deny_groups, ਅੰਕ_deny_groups, DenyGroups, SSHCFG_ALL, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_STRARRAY(accept_env, ਅੰਕ_accept_env, AcceptEnv, SSHCFG_ALL, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_STRARRAY(setenv, ਅੰਕ_setenv, ਸੈੱਟ_Env, SSHCFG_ALL, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_INT(ਪ੍ਰਤੀ_ਸਰੋਤ_max_startups, ਪ੍ਰਤੀ_ਸਰੋਤ_Max_Startups, SSHCFG_GLOBAL, ਨਿਰਾ, ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ, SSHCFG_COPY_NONE) \
SSHCONF_STRING(ਪ੍ਰਤੀ_ਸਰੋਤ_penalty_exempt, ਪ੍ਰਤੀ_ਸਰੋਤ_Penalty_Exempt_List, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_INT(max_authtries, MaxAuthTries, SSHCFG_ALL, ਨਿਰਾ, DEFAULT_AUTH_FAIL_MAX, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_INT(max_sessions, MaxSessions, SSHCFG_ALL, ਨਿਰਾ, DEFAULT_SESSIONS_MAX, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_STRING(banner, Banner, SSHCFG_ALL, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_INTFLAG(use_dns, UseDNS, SSHCFG_GLOBAL, 0, SSHCFG_COPY_NONE) \
SSHCONF_INT(client_alive_interval, ClientAliveInterval, SSHCFG_ALL, ਨਿਰਾ, 0, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_INT(client_alive_ਗਿਣਤੀ_max, Client_Alive_ਗਿਣਤੀ_Max, SSHCFG_ALL, ਨਿਰਾ, 3, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_STRARRAY(authorized_ਕੁੰਜੀਆਂ_files, ਅੰਕ_authkeys_files, Authorized_ਕੁੰਜੀਆਂ_File, SSHCFG_ALL, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_STRING(adm_forced_command, ForceCommand, SSHCFG_ALL, SSHCFG_COPY_MANUAL) \
SSHCONF_INTFLAG(permit_tun, PermitTunnel, SSHCFG_ALL, SSH_TUNMODE_NO, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_STRARRAY(permitted_opens, ਅੰਕ_permitted_opens, PermitOpen, SSHCFG_ALL, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_STRARRAY(permitted_listens, ਅੰਕ_permitted_listens, PermitListen, SSHCFG_ALL, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_STRING(chroot_directory, ChrootDirectory, SSHCFG_ALL, SSHCFG_COPY_MANUAL) \
SSHCONF_STRARRAY(revoked_ਕੁੰਜੀਆਂ_files, ਅੰਕ_revoked_ਕੁੰਜੀਆਂ_files, Revoked_ਕੁੰਜੀਆਂ, SSHCFG_ALL, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_STRING(trusted_user_ca_ਕੁੰਜੀਆਂ, TrustedUserCAKeys, SSHCFG_ALL, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_STRING(authorized_ਕੁੰਜੀਆਂ_command, Authorized_ਕੁੰਜੀਆਂ_Command, SSHCFG_ALL, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_STRING(authorized_ਕੁੰਜੀਆਂ_command_user, Authorized_ਕੁੰਜੀਆਂ_Command_User, SSHCFG_ALL, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_STRING(authorized_principals_file, AuthorizedPrincipalsFile, SSHCFG_ALL, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_STRING(authorized_principals_command, AuthorizedPrincipalsCommand, SSHCFG_ALL, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_STRING(authorized_principals_command_user, AuthorizedPrincipalsCommandUser, SSHCFG_ALL, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_STRING(ਸੰਸਕਰਣ_addendum, ਸੰਸਕਰਣ_Addendum, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRARRAY(auth_methods, ਅੰਕ_auth_methods, AuthenticationMethods, SSHCFG_ALL, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_INT(fingerprint_hash, FingerprintHash, SSHCFG_GLOBAL, ਨਿਰਾ, SSH_FP_HASH_DEFAULT, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(expose_userauth_info, ExposeAuthInfo, SSHCFG_ALL, 0, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_STRING(sk_provider, Security_ਕੁੰਜੀ_Provider, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_INT(required_rsa_ਮਾਪ, RequiredRSASize, SSHCFG_ALL, ਨਿਰਾ, SSH_RSA_MINIMUM_MODULUS_ਮਾਪ, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_STRARRAY(channel_timeouts, ਅੰਕ_channel_timeouts, ChannelTimeout, SSHCFG_ALL, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_INT(ਅਣਵਰਤਿਆ_connection_timeout, ਅਣਵਰਤਿਆ_Connection_Timeout, SSHCFG_ALL, ਨਿਰਾ, 0, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_STRING(sshd_session_ਰਸਤਾ, Sshd_Session_ਰਸਤਾ, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(sshd_auth_ਰਸਤਾ, Sshd_Auth_ਰਸਤਾ, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(refuse_connection, RefuseConnection, SSHCFG_ALL, 0, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_STRING(agent_socket_ਰਸਤਾ, Agent_Socket_ਰਸਤਾ, SSHCFG_ALL, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_INT(warn_weak_crypto, WarnWeakCrypto, SSHCFG_GLOBAL, multistate_warnweakcrypto, 1, SSHCFG_COPY_NONE)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHD_CONFIG_ENTRIES_LEGACY \
SSHCONF_DEPRECATE(Server_ਕੁੰਜੀ_ਬਿੱਟ, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(ਕੁੰਜੀ_Regeneration_Interval, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(RHostsAuthentication, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(RhostsRSAAuthentication, SSHCFG_ALL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(RSAAuthentication, SSHCFG_ALL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(CheckMail, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(UseLogin, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(Verify_ਉਲਟ_Mapping, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(ਉਲਟ_Mapping_Check, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(Authorized_ਕੁੰਜੀਆਂ_File2, SSHCFG_ALL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(UsePrivilegeSeparation, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(KerberosTgtPassing, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(AFSTokenPassing, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(Protocol, SSHCFG_GLOBAL, SSHCONF_IGNORE)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHD_CONFIG_ENTRIES_ALIASES \
SSHCONF_ALIAS(HostDSAKey, Host_ਕੁੰਜੀ, SSHCFG_GLOBAL) \
SSHCONF_ALIAS(Host_Based_Accepted_ਕੁੰਜੀ_Types, HostbasedAcceptedAlgorithms, SSHCFG_ALL) \
SSHCONF_ALIAS(Pubkey_Accepted_ਕੁੰਜੀ_Types, PubkeyAcceptedAlgorithms, SSHCFG_ALL) \
SSHCONF_ALIAS(DSAAuthentication, PubkeyAuthentication, SSHCFG_GLOBAL) \
SSHCONF_ALIAS(ChallengeResponseAuthentication, KbdInteractiveAuthentication, SSHCFG_ALL) \
SSHCONF_ALIAS(SKeyAuthentication, KbdInteractiveAuthentication, SSHCFG_ALL) \
SSHCONF_ALIAS(KeepAlive, TCPKeepAlive, SSHCFG_GLOBAL)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHD_CONFIG_ENTRIES_ਅਧਾਰ \
	SSHD_CONFIG_ENTRIES_CUSTOM \
	SSHD_CONFIG_ENTRIES_MAIN \
	SSHD_CONFIG_ENTRIES_LEGACY \
	SSHD_CONFIG_ENTRIES_ALIASES \
	SSHD_CONFIG_ENTRIES_PAM \
	SSHD_CONFIG_ENTRIES_LASTLOG

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_PAM
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHD_CONFIG_ENTRIES_PAM \
SSHCONF_INTFLAG(use_pam, UsePAM, SSHCFG_GLOBAL, 0, SSHCFG_COPY_NONE) \
SSHCONF_STRING(pam_service_name, PAMServiceName, SSHCFG_ALL, SSHCFG_COPY_ਮੇਲ)
#ਨਹੀਂਤਾਂ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHD_CONFIG_ENTRIES_PAM \
SSHCONF_UNSUPPORTED_INT(use_pam, UsePAM, SSHCFG_GLOBAL) \
SSHCONF_UNSUPPORTED_STRING(pam_service_name, PAMServiceName, SSHCFG_ALL)
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DISABLE_LASTLOG
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHD_CONFIG_ENTRIES_LASTLOG \
SSHCONF_UNSUPPORTED_INT(print_lastlog, Print_ਆਖਰੀ_Log, SSHCFG_GLOBAL)
#ਨਹੀਂਤਾਂ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHD_CONFIG_ENTRIES_LASTLOG \
SSHCONF_INTFLAG(print_lastlog, Print_ਆਖਰੀ_Log, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE)
#ਜੇ_ਅੰਤ

/* Compile-time enabled options */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ KRB5

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_AFS
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHD_CONFIG_KRB5_AFS \
SSHCONF_INTFLAG(kerberos_get_afs_token, KerberosGetAFSToken, SSHCFG_GLOBAL, 0, SSHCFG_COPY_NONE)
#ਨਹੀਂਤਾਂ /* USE_AFS */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHD_CONFIG_KRB5_AFS \
SSHCONF_UNSUPPORTED_INT(kerberos_get_afs_token, KerberosGetAFSToken, SSHCFG_GLOBAL)
#ਜੇ_ਅੰਤ /* USE_AFS */

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHD_CONFIG_ENTRIES_KRB5 \
SSHCONF_INTFLAG(kerberos_authentication, KerberosAuthentication, SSHCFG_ALL, 0, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_INTFLAG(kerberos_or_local_passwd, KerberosOrLocalPasswd, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(kerberos_ticket_cleanup, KerberosTicketCleanup, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHD_CONFIG_KRB5_AFS
#ਨਹੀਂਤਾਂ /* KRB5 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHD_CONFIG_ENTRIES_KRB5 \
SSHCONF_UNSUPPORTED_INT(kerberos_authentication, KerberosAuthentication, SSHCFG_ALL) \
SSHCONF_UNSUPPORTED_INT(kerberos_or_local_passwd, KerberosOrLocalPasswd, SSHCFG_GLOBAL) \
SSHCONF_UNSUPPORTED_INT(kerberos_ticket_cleanup, KerberosTicketCleanup, SSHCFG_GLOBAL) \
SSHCONF_UNSUPPORTED_INT(kerberos_get_afs_token, KerberosGetAFSToken, SSHCFG_GLOBAL)
#ਜੇ_ਅੰਤ /* KRB5 */

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ GSSAPI
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHD_CONFIG_ENTRIES_GSS \
SSHCONF_INTFLAG(gss_authentication, GSSAPIAuthentication, SSHCFG_ALL, 0, SSHCFG_COPY_ਮੇਲ) \
SSHCONF_INTFLAG(gss_cleanup_creds, GSSAPICleanupCredentials, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(gss_deleg_creds, GSSAPIDelegateCredentials, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(gss_strict_acceptor, GSSAPIStrictAcceptorCheck, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE)
#ਨਹੀਂਤਾਂ /* GSSAPI */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHD_CONFIG_ENTRIES_GSS \
SSHCONF_UNSUPPORTED_INT(gss_authentication, GSSAPIAuthentication, SSHCFG_ALL) \
SSHCONF_UNSUPPORTED_INT(gss_cleanup_creds, GSSAPICleanupCredentials, SSHCFG_GLOBAL) \
SSHCONF_UNSUPPORTED_INT(gss_deleg_creds, GSSAPIDelegateCredentials, SSHCFG_GLOBAL) \
SSHCONF_UNSUPPORTED_INT(gss_strict_acceptor, GSSAPIStrictAcceptorCheck, SSHCFG_GLOBAL)
#ਜੇ_ਅੰਤ /* GSSAPI */

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHD_CONFIG_ENTRIES \
	SSHD_CONFIG_ENTRIES_ਅਧਾਰ \
	SSHD_CONFIG_ENTRIES_KRB5 \
	SSHD_CONFIG_ENTRIES_GSS \

/* Macros to declare ServerOptions member variables */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_INT(var, conf, flags, ms, def, cp)	ਪੂਰਨ var;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_INTFLAG(var, conf, flags, def, cp)	ਪੂਰਨ var;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_STRING(var, conf, flags, cp)		ਅੱਖਰ *var;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	\
	ਅੱਖਰ **var; \
	u_int nvar;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	/*ਖਾਲੀ_ਥਾਵਾਂ*/
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_NONCONF(funcsuffix)			/*ਖਾਲੀ_ਥਾਵਾਂ*/
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_DEPRECATE(conf, flags, opcode)		/*ਖਾਲੀ_ਥਾਵਾਂ*/
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_UNSUPPORTED_INT(var, conf, flags)	ਪੂਰਨ var;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	ਅੱਖਰ *var;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_ALIAS(old, conf, flags)			/*ਖਾਲੀ_ਥਾਵਾਂ*/

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ ServerOptions {
	SSHD_CONFIG_ENTRIES
	/* Ports */
	u_int	ਅੰਕ_ports;
	u_int	ports_from_cmdline;
	ਪੂਰਨ	ports[MAX_PORTS];	/* Port number to listen on. */
	/* ListenAddress */
	ਬਣਤਰ queued_listenaddr *queued_listen_addrs;
	u_int	ਅੰਕ_queued_listens;
	ਬਣਤਰ listenaddr *listen_addrs;
	u_int	ਅੰਕ_listen_addrs;
	/* HostKey */
	ਅੱਖਰ   **host_ਕੁੰਜੀ_files;	/* Files containing host keys. */
	ਪੂਰਨ	*host_ਕੁੰਜੀ_file_userprovided; /* Key was specified by user. */
	u_int	ਅੰਕ_host_ਕੁੰਜੀ_files;     /* Number of files for host keys. */
	/* IPQoS */
	ਪੂਰਨ	ip_qos_interactive;	/* IP ToS/DSCP/class for interactive */
	ਪੂਰਨ	ip_qos_bulk;		/* IP ToS/DSCP/class for bulk traffic */
	/* GatewayPorts, StreamLocalBindMask, StreamLocalBindUnlink */
	ਬਣਤਰ ForwardOptions fwd_opts;	/* forwarding options */
	/* LogFacility */
	SyslogFacility log_facility;	/* Facility for system logging. */
	/* LogLevel */
	LogLevel log_level;	/* Level for system logging. */
	/* PermitUserEnvironment */
	ਪੂਰਨ     permit_user_env;	/* If true, read ~/.ssh/environment */
	ਅੱਖਰ   *permit_user_env_allowlist; /* pattern-list of allowed env names */
	/* Subsystem */
	u_int ਅੰਕ_subsystems;
	ਅੱਖਰ   **subsystem_name;
	ਅੱਖਰ   **subsystem_command;
	ਅੱਖਰ   **subsystem_ਦਲੀਲਾਂ;
	/* MaxStartups */
	ਪੂਰਨ	max_startups_begin;
	ਪੂਰਨ	max_startups_ਦਰ;
	ਪੂਰਨ	max_startups;
	/* PerSourceNetBlockSize */
	ਪੂਰਨ	ਪ੍ਰਤੀ_ਸਰੋਤ_masklen_ipv4;
	ਪੂਰਨ	ਪ੍ਰਤੀ_ਸਰੋਤ_masklen_ipv6;
	/* PerSourcePenalties */
	ਬਣਤਰ ਪ੍ਰਤੀ_ਸਰੋਤ_penalty ਪ੍ਰਤੀ_ਸਰੋਤ_penalty;
	/* RekeyLimit */
	int64_t rekey_ਹੱਦਬੰਦੀ;
	ਪੂਰਨ	rekey_interval;
	/* PubkeyAuthOptions */
	ਪੂਰਨ	pubkey_auth_options;
	ਪੂਰਨ	max_pubkey_ok;
	/* Passed by config but not keyword for this */
	uint64_t timing_secret;
}       ServerOptions;
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_INT
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_INTFLAG
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_STRING
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_STRARRAY
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_CUSTOM
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_NONCONF
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_DEPRECATE
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_UNSUPPORTED_INT
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_UNSUPPORTED_STRING
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_ALIAS

/* Information about the incoming connection as used by Match */
ਬਣਤਰ connection_info {
	ਅਚਲ ਅੱਖਰ *user;
	ਪੂਰਨ user_invalid;
	ਅਚਲ ਅੱਖਰ *host;	/* possibly resolved hostname */
	ਅਚਲ ਅੱਖਰ *ਪਤਾ;	/* remote address */
	ਅਚਲ ਅੱਖਰ *laddress;	/* local address */
	ਪੂਰਨ lport;		/* local port */
	ਅਚਲ ਅੱਖਰ *rdomain;	/* routing domain if available */
	ਪੂਰਨ test;		/* test mode, allow some attributes to be
				 * unspecified */
};

/* List of included files for re-exec from the parsed configuration */
ਬਣਤਰ include_ਵਸਤੂ {
	ਅੱਖਰ *selector;
	ਅੱਖਰ *filename;
	ਬਣਤਰ sshbuf *contents;
	TAILQ_ENTRY(include_ਵਸਤੂ) ਇੰਦਰਾਜ;
};
TAILQ_HEAD(include_list, include_ਵਸਤੂ);

ਖਾਲੀ	 initialize_server_options(ServerOptions *);
ਖਾਲੀ	 fill_default_server_options(ServerOptions *);
ਪੂਰਨ	 process_server_config_ਸਤਰ(ServerOptions *, ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਪੂਰਨ,
	    ਪੂਰਨ *, ਬਣਤਰ connection_info *, ਬਣਤਰ include_list *includes);
ਖਾਲੀ	 ਲੱਦੋ_server_config(ਅਚਲ ਅੱਖਰ *, ਬਣਤਰ sshbuf *);
ਖਾਲੀ	 parse_server_config(ServerOptions *, ਅਚਲ ਅੱਖਰ *, ਬਣਤਰ sshbuf *,
	    ਬਣਤਰ include_list *includes, ਬਣਤਰ connection_info *, ਪੂਰਨ);
ਖਾਲੀ	 parse_server_ਮੇਲ_config(ServerOptions *,
	    ਬਣਤਰ include_list *includes, ਬਣਤਰ connection_info *);
ਪੂਰਨ	 parse_server_ਮੇਲ_testspec(ਬਣਤਰ connection_info *, ਅੱਖਰ *);
ਖਾਲੀ	 servconf_ਮਿਲਾਓ_subsystems(ServerOptions *, ServerOptions *);
ਖਾਲੀ	 copy_ਸੈੱਟ_server_options(ServerOptions *, ServerOptions *, ਪੂਰਨ);
ਖਾਲੀ	 dump_config(ServerOptions *);
ਅੱਖਰ	*derelativise_ਰਸਤਾ(ਅਚਲ ਅੱਖਰ *);
ਖਾਲੀ	 servconf_ਜੋੜੋ_hostkey(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਪੂਰਨ,
	    ServerOptions *, ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, ਪੂਰਨ);
ਖਾਲੀ	 servconf_ਜੋੜੋ_hostcert(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਪੂਰਨ,
	    ServerOptions *, ਅਚਲ ਅੱਖਰ *ਰਸਤਾ);

ਪੂਰਨ	 serialise_server_options(ਅਚਲ ServerOptions *, ਬਣਤਰ sshbuf **);
ਪੂਰਨ	 deserialise_server_options(ਬਣਤਰ sshbuf *, ServerOptions *);
ਖਾਲੀ	 free_server_options(ServerOptions *);

#ਜੇ_ਅੰਤ				/* SERVCONF_H */
