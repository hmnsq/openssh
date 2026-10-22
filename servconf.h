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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ SERVCONF_H
#ವ್ಯಾಖ್ಯಾನಿಸು SERVCONF_H

#ಅನ್ತರ್ಭಾವ <sys/queue.h>

ರಚನೆ sshbuf;

#ವ್ಯಾಖ್ಯಾನಿಸು MAX_PORTS		256	/* Max # ports. */

/* permit_root_login */
#ವ್ಯಾಖ್ಯಾನಿಸು	PERMIT_NOT_ಗಣ		-1
#ವ್ಯಾಖ್ಯಾನಿಸು	PERMIT_NO		0
#ವ್ಯಾಖ್ಯಾನಿಸು	PERMIT_FORCED_ONLY	1
#ವ್ಯಾಖ್ಯಾನಿಸು	PERMIT_NO_PASSWD	2
#ವ್ಯಾಖ್ಯಾನಿಸು	PERMIT_YES		3

/* PermitOpen */
#ವ್ಯಾಖ್ಯಾನಿಸು PERMITOPEN_ANY		0
#ವ್ಯಾಖ್ಯಾನಿಸು PERMITOPEN_NONE		-2

/* IgnoreRhosts */
#ವ್ಯಾಖ್ಯಾನಿಸು IGNORE_RHOSTS_NO	0
#ವ್ಯಾಖ್ಯಾನಿಸು IGNORE_RHOSTS_YES	1
#ವ್ಯಾಖ್ಯಾನಿಸು IGNORE_RHOSTS_SHOSTS	2

#ವ್ಯಾಖ್ಯಾನಿಸು DEFAULT_AUTH_FAIL_MAX	6	/* Default for MaxAuthTries */
#ವ್ಯಾಖ್ಯಾನಿಸು DEFAULT_SESSIONS_MAX	10	/* Default for MaxSessions */

/* Magic name for internal sftp-server */
#ವ್ಯಾಖ್ಯಾನಿಸು ಆಂತರಿಕ_SFTP_NAME	"internal-sftp"

/* PubkeyAuthOptions flags */
#ವ್ಯಾಖ್ಯಾನಿಸು PUBKEYAUTH_TOUCH_REQUIRED	(1)
#ವ್ಯಾಖ್ಯಾನಿಸು PUBKEYAUTH_VERIFY_REQUIRED	(1<<1)

/* Various defaults */
#ವ್ಯಾಖ್ಯಾನಿಸು SSHD_DEFAULT_LOGIN_GRACE_ಸಮಯ	120
#ವ್ಯಾಖ್ಯಾನಿಸು SSHD_DEFAULT_X11_DISPLAY_ಸ್ಥಾನಾಂತರ	10
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_ZLIB
#ವ್ಯಾಖ್ಯಾನಿಸು SSHD_DEFAULT_COMPRESSION	COMP_DELAYED
#ಇಲ್ಲದಿದ್ದರೆ
#ವ್ಯಾಖ್ಯಾನಿಸು SSHD_DEFAULT_COMPRESSION	COMP_NONE
#ಆದರೆ_ಅಂತ್ಯ

/* TCPKeepAlive flags */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_KEEPALIVES_OFF		0
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_KEEPALIVES_TRANSPORT	1
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_KEEPALIVES_ALL		2

ರಚನೆ ssh;

/*
 * Used to store addresses from ListenAddr directives. These may be
 * incomplete, as they may specify addresses that need to be merged
 * with any ports requested by ListenPort.
 */
ರಚನೆ queued_listenaddr {
	ಅಕ್ಷರ *addr;
	ಪೂರ್ಣಾಂಕ ಪೋರ್ಟ್; /* <=0 if unspecified */
	ಅಕ್ಷರ *rdomain;
};

/* Resolved listen addresses, grouped by optional routing domain */
ರಚನೆ listenaddr {
	ಅಕ್ಷರ *rdomain;
	ರಚನೆ addrinfo *addrs;
};

#ವ್ಯಾಖ್ಯಾನಿಸು ಪ್ರತಿ_ಮೂಲ_PENALTY_ಅತಿಪ್ರವಾಹ_DENY_ALL	1
#ವ್ಯಾಖ್ಯಾನಿಸು ಪ್ರತಿ_ಮೂಲ_PENALTY_ಅತಿಪ್ರವಾಹ_PERMISSIVE	2
ರಚನೆ ಪ್ರತಿ_ಮೂಲ_penalty {
	ಪೂರ್ಣಾಂಕ	enabled;
	ಪೂರ್ಣಾಂಕ	max_sources4;
	ಪೂರ್ಣಾಂಕ	max_sources6;
	ಪೂರ್ಣಾಂಕ	ಅತಿಪ್ರವಾಹ_ಬಹುಲಕ;
	ಪೂರ್ಣಾಂಕ	ಅತಿಪ್ರವಾಹ_mode6;
	ದ್ವಿಗುಣ	penalty_crash;
	ದ್ವಿಗುಣ	penalty_grace;
	ದ್ವಿಗುಣ	penalty_authfail;
	ದ್ವಿಗುಣ	penalty_invaliduser;
	ದ್ವಿಗುಣ	penalty_noauth;
	ದ್ವಿಗುಣ	penalty_refuseconnection;
	ದ್ವಿಗುಣ	penalty_max;
	ದ್ವಿಗುಣ	penalty_min;
};

/* Options for whether config entries are copied after Match processing */
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCFG_COPY_NONE(action)
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCFG_COPY_ಹೊಂದಿಕೆ(action)	action
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCFG_COPY_MANUAL(action)

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
#ವ್ಯಾಖ್ಯಾನಿಸು SSHD_CONFIG_ENTRIES_CUSTOM \
SSHCONF_CUSTOM(ಪೋರ್ಟ್_2, ಪೋರ್ಟ್, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(Listen_ವಿಳಾಸ, listenaddress, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(Host_ಕೀಲಿ, hostkeyfile, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(IPQoS, ipqos, SSHCFG_ALL, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_CUSTOM(GatewayPorts, gatewayports, SSHCFG_ALL, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_CUSTOM(ಹರಿವು_Local_Bind_ಮುಖವಾಡ, streamlocalbindmask, SSHCFG_ALL, SSHCFG_COPY_MANUAL) \
SSHCONF_CUSTOM(ಹರಿವು_Local_Bind_Unlink, streamlocalbindunlink, SSHCFG_ALL, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_CUSTOM(SyslogFacility, logfacility, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(LogLevel, loglevel, SSHCFG_ALL, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_CUSTOM(PermitUserEnvironment, permituserenv, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(Subsystem, subsystem, SSHCFG_ALL, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_CUSTOM(MaxStartups, maxstartups, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(ಪ್ರತಿ_ಮೂಲ_Net_ಖಂಡ_ಗಾತ್ರ, persourcenetblocksize, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(ಪ್ರತಿ_ಮೂಲ_Penalties, persourcepenalties, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(Rekey_ಎಲ್ಲೆ, rekeylimit, SSHCFG_ALL, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_CUSTOM(PubkeyAuthOptions, pubkey_auth_options, SSHCFG_ALL, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_NONCONF(timingsecret)

#ವ್ಯಾಖ್ಯಾನಿಸು SSHD_CONFIG_ENTRIES_MAIN \
SSHCONF_INT(ವಿಳಾಸ_family, ವಿಳಾಸ_Family, SSHCFG_GLOBAL, multistate_addressfamily, AF_UNSPEC, SSHCFG_COPY_NONE) \
SSHCONF_STRING(routing_domain, RDomain, SSHCFG_ALL, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_STRARRAY(host_cert_files, ಅಂಕೆ_host_cert_files, HostCertificate, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(host_ಕೀಲಿ_agent, Host_ಕೀಲಿ_Agent, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(pid_file, PidFile, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(moduli_file, ModuliFile, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_INT(login_grace_ಸಮಯ, Login_Grace_ಸಮಯ, SSHCFG_GLOBAL, ಖಾಲಿ, SSHD_DEFAULT_LOGIN_GRACE_ಸಮಯ, SSHCFG_COPY_NONE) \
SSHCONF_INT(permit_ಬೇರು_login, Permit_ಬೇರು_Login, SSHCFG_ALL, multistate_permitrootlogin, PERMIT_NO_PASSWD, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_INT(ignore_rhosts, IgnoreRhosts, SSHCFG_ALL, multistate_ignore_rhosts, 1, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_INTFLAG(ignore_user_ತಿಳಿದ_hosts, Ignore_User_ತಿಳಿದ_Hosts, SSHCFG_GLOBAL, 0, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(print_motd, PrintMotd, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(x11_forwarding, X11Forwarding, SSHCFG_ALL, 0, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_INT(x11_display_ಸ್ಥಾನಾಂತರ, X11_Display_ಸ್ಥಾನಾಂತರ, SSHCFG_ALL, ಖಾಲಿ, SSHD_DEFAULT_X11_DISPLAY_ಸ್ಥಾನಾಂತರ, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_INTFLAG(x11_use_localhost, X11UseLocalhost, SSHCFG_ALL, 1, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_STRING(xauth_location, XAuthLocation, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(permit_tty, PermitTTY, SSHCFG_ALL, 1, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_INTFLAG(permit_user_rc, PermitUserRC, SSHCFG_ALL, 1, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_INTFLAG(strict_modes, StrictModes, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(tcp_keep_alive, TCPKeepAlive, SSHCFG_GLOBAL, SSH_KEEPALIVES_TRANSPORT, SSHCFG_COPY_NONE) \
SSHCONF_STRING(ciphers, Ciphers, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(macs, Macs, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(kex_algorithms, KexAlgorithms, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRARRAY(log_verbose, ಅಂಕೆ_log_verbose, LogVerbose, SSHCFG_ALL, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_INTFLAG(hostbased_authentication, HostbasedAuthentication, SSHCFG_ALL, 0, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_INTFLAG(hostbased_ಬಳಸುತ್ತದೆ_name_from_packet_only, Hostbased_ಬಳಸುತ್ತದೆ_Name_From_Packet_Only, SSHCFG_ALL, 0, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_STRING(hostbased_accepted_algos, HostbasedAcceptedAlgorithms, SSHCFG_ALL, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_STRING(hostkeyalgorithms, Host_ಕೀಲಿ_Algorithms, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(ca_sign_algorithms, CASignatureAlgorithms, SSHCFG_ALL, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_INTFLAG(pubkey_authentication, PubkeyAuthentication, SSHCFG_ALL, 1, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_STRING(pubkey_accepted_algos, PubkeyAcceptedAlgorithms, SSHCFG_ALL, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_INTFLAG(password_authentication, PasswordAuthentication, SSHCFG_ALL, 1, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_INTFLAG(kbd_interactive_authentication, KbdInteractiveAuthentication, SSHCFG_ALL, 1, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_INTFLAG(permit_ಖಾಲಿಗಳು_passwd, Permit_ಖಾಲಿಗಳು_Passwords, SSHCFG_ALL, 0, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_INT(compression, Compression, SSHCFG_GLOBAL, multistate_compression, SSHD_DEFAULT_COMPRESSION, SSHCFG_COPY_NONE) \
SSHCONF_INT(allow_tcp_forwarding, AllowTcpForwarding, SSHCFG_ALL, multistate_tcpfwd, FORWARD_ALLOW, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_INT(allow_streamlocal_forwarding, Allow_ಹರಿವು_Local_Forwarding, SSHCFG_ALL, multistate_tcpfwd, FORWARD_ALLOW, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_INTFLAG(allow_agent_forwarding, AllowAgentForwarding, SSHCFG_ALL, 1, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_INTFLAG(disable_forwarding, DisableForwarding, SSHCFG_ALL, 0, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_STRARRAY(allow_users, ಅಂಕೆ_allow_users, AllowUsers, SSHCFG_ALL, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_STRARRAY(deny_users, ಅಂಕೆ_deny_users, DenyUsers, SSHCFG_ALL, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_STRARRAY(allow_groups, ಅಂಕೆ_allow_groups, AllowGroups, SSHCFG_ALL, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_STRARRAY(deny_groups, ಅಂಕೆ_deny_groups, DenyGroups, SSHCFG_ALL, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_STRARRAY(accept_env, ಅಂಕೆ_accept_env, AcceptEnv, SSHCFG_ALL, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_STRARRAY(setenv, ಅಂಕೆ_setenv, ಗಣ_Env, SSHCFG_ALL, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_INT(ಪ್ರತಿ_ಮೂಲ_max_startups, ಪ್ರತಿ_ಮೂಲ_Max_Startups, SSHCFG_GLOBAL, ಖಾಲಿ, ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ, SSHCFG_COPY_NONE) \
SSHCONF_STRING(ಪ್ರತಿ_ಮೂಲ_penalty_exempt, ಪ್ರತಿ_ಮೂಲ_Penalty_Exempt_List, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_INT(max_authtries, MaxAuthTries, SSHCFG_ALL, ಖಾಲಿ, DEFAULT_AUTH_FAIL_MAX, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_INT(max_sessions, MaxSessions, SSHCFG_ALL, ಖಾಲಿ, DEFAULT_SESSIONS_MAX, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_STRING(banner, Banner, SSHCFG_ALL, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_INTFLAG(use_dns, UseDNS, SSHCFG_GLOBAL, 0, SSHCFG_COPY_NONE) \
SSHCONF_INT(client_alive_interval, ClientAliveInterval, SSHCFG_ALL, ಖಾಲಿ, 0, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_INT(client_alive_ಎಣಿಕೆ_max, Client_Alive_ಎಣಿಕೆ_Max, SSHCFG_ALL, ಖಾಲಿ, 3, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_STRARRAY(authorized_ಕೀಲಿಗಳು_files, ಅಂಕೆ_authkeys_files, Authorized_ಕೀಲಿಗಳು_File, SSHCFG_ALL, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_STRING(adm_forced_command, ForceCommand, SSHCFG_ALL, SSHCFG_COPY_MANUAL) \
SSHCONF_INTFLAG(permit_tun, PermitTunnel, SSHCFG_ALL, SSH_TUNMODE_NO, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_STRARRAY(permitted_opens, ಅಂಕೆ_permitted_opens, PermitOpen, SSHCFG_ALL, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_STRARRAY(permitted_listens, ಅಂಕೆ_permitted_listens, PermitListen, SSHCFG_ALL, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_STRING(chroot_directory, ChrootDirectory, SSHCFG_ALL, SSHCFG_COPY_MANUAL) \
SSHCONF_STRARRAY(revoked_ಕೀಲಿಗಳು_files, ಅಂಕೆ_revoked_ಕೀಲಿಗಳು_files, Revoked_ಕೀಲಿಗಳು, SSHCFG_ALL, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_STRING(trusted_user_ca_ಕೀಲಿಗಳು, TrustedUserCAKeys, SSHCFG_ALL, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_STRING(authorized_ಕೀಲಿಗಳು_command, Authorized_ಕೀಲಿಗಳು_Command, SSHCFG_ALL, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_STRING(authorized_ಕೀಲಿಗಳು_command_user, Authorized_ಕೀಲಿಗಳು_Command_User, SSHCFG_ALL, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_STRING(authorized_principals_file, AuthorizedPrincipalsFile, SSHCFG_ALL, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_STRING(authorized_principals_command, AuthorizedPrincipalsCommand, SSHCFG_ALL, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_STRING(authorized_principals_command_user, AuthorizedPrincipalsCommandUser, SSHCFG_ALL, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_STRING(ಆವೃತ್ತಿ_addendum, ಆವೃತ್ತಿ_Addendum, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRARRAY(auth_methods, ಅಂಕೆ_auth_methods, AuthenticationMethods, SSHCFG_ALL, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_INT(fingerprint_hash, FingerprintHash, SSHCFG_GLOBAL, ಖಾಲಿ, SSH_FP_HASH_DEFAULT, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(expose_userauth_info, ExposeAuthInfo, SSHCFG_ALL, 0, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_STRING(sk_provider, Security_ಕೀಲಿ_Provider, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_INT(required_rsa_ಗಾತ್ರ, RequiredRSASize, SSHCFG_ALL, ಖಾಲಿ, SSH_RSA_MINIMUM_MODULUS_ಗಾತ್ರ, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_STRARRAY(channel_timeouts, ಅಂಕೆ_channel_timeouts, ChannelTimeout, SSHCFG_ALL, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_INT(ಬಳಸದ_connection_timeout, ಬಳಸದ_Connection_Timeout, SSHCFG_ALL, ಖಾಲಿ, 0, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_STRING(sshd_session_ಮಾರ್ಗ, Sshd_Session_ಮಾರ್ಗ, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(sshd_auth_ಮಾರ್ಗ, Sshd_Auth_ಮಾರ್ಗ, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(refuse_connection, RefuseConnection, SSHCFG_ALL, 0, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_STRING(agent_socket_ಮಾರ್ಗ, Agent_Socket_ಮಾರ್ಗ, SSHCFG_ALL, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_INT(warn_weak_crypto, WarnWeakCrypto, SSHCFG_GLOBAL, multistate_warnweakcrypto, 1, SSHCFG_COPY_NONE)

#ವ್ಯಾಖ್ಯಾನಿಸು SSHD_CONFIG_ENTRIES_LEGACY \
SSHCONF_DEPRECATE(Server_ಕೀಲಿ_ಬಿಟ್ಟುಗಳು, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(ಕೀಲಿ_Regeneration_Interval, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(RHostsAuthentication, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(RhostsRSAAuthentication, SSHCFG_ALL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(RSAAuthentication, SSHCFG_ALL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(CheckMail, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(UseLogin, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(Verify_ಹಿಮ್ಮುಖ_Mapping, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(ಹಿಮ್ಮುಖ_Mapping_Check, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(Authorized_ಕೀಲಿಗಳು_File2, SSHCFG_ALL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(UsePrivilegeSeparation, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(KerberosTgtPassing, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(AFSTokenPassing, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(Protocol, SSHCFG_GLOBAL, SSHCONF_IGNORE)

#ವ್ಯಾಖ್ಯಾನಿಸು SSHD_CONFIG_ENTRIES_ALIASES \
SSHCONF_ALIAS(HostDSAKey, Host_ಕೀಲಿ, SSHCFG_GLOBAL) \
SSHCONF_ALIAS(Host_Based_Accepted_ಕೀಲಿ_Types, HostbasedAcceptedAlgorithms, SSHCFG_ALL) \
SSHCONF_ALIAS(Pubkey_Accepted_ಕೀಲಿ_Types, PubkeyAcceptedAlgorithms, SSHCFG_ALL) \
SSHCONF_ALIAS(DSAAuthentication, PubkeyAuthentication, SSHCFG_GLOBAL) \
SSHCONF_ALIAS(ChallengeResponseAuthentication, KbdInteractiveAuthentication, SSHCFG_ALL) \
SSHCONF_ALIAS(SKeyAuthentication, KbdInteractiveAuthentication, SSHCFG_ALL) \
SSHCONF_ALIAS(KeepAlive, TCPKeepAlive, SSHCFG_GLOBAL)

#ವ್ಯಾಖ್ಯಾನಿಸು SSHD_CONFIG_ENTRIES_ತಳ \
	SSHD_CONFIG_ENTRIES_CUSTOM \
	SSHD_CONFIG_ENTRIES_MAIN \
	SSHD_CONFIG_ENTRIES_LEGACY \
	SSHD_CONFIG_ENTRIES_ALIASES \
	SSHD_CONFIG_ENTRIES_PAM \
	SSHD_CONFIG_ENTRIES_LASTLOG

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_PAM
#ವ್ಯಾಖ್ಯಾನಿಸು SSHD_CONFIG_ENTRIES_PAM \
SSHCONF_INTFLAG(use_pam, UsePAM, SSHCFG_GLOBAL, 0, SSHCFG_COPY_NONE) \
SSHCONF_STRING(pam_service_name, PAMServiceName, SSHCFG_ALL, SSHCFG_COPY_ಹೊಂದಿಕೆ)
#ಇಲ್ಲದಿದ್ದರೆ
#ವ್ಯಾಖ್ಯಾನಿಸು SSHD_CONFIG_ENTRIES_PAM \
SSHCONF_UNSUPPORTED_INT(use_pam, UsePAM, SSHCFG_GLOBAL) \
SSHCONF_UNSUPPORTED_STRING(pam_service_name, PAMServiceName, SSHCFG_ALL)
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DISABLE_LASTLOG
#ವ್ಯಾಖ್ಯಾನಿಸು SSHD_CONFIG_ENTRIES_LASTLOG \
SSHCONF_UNSUPPORTED_INT(print_lastlog, Print_ಕೊನೆಯ_Log, SSHCFG_GLOBAL)
#ಇಲ್ಲದಿದ್ದರೆ
#ವ್ಯಾಖ್ಯಾನಿಸು SSHD_CONFIG_ENTRIES_LASTLOG \
SSHCONF_INTFLAG(print_lastlog, Print_ಕೊನೆಯ_Log, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE)
#ಆದರೆ_ಅಂತ್ಯ

/* Compile-time enabled options */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ KRB5

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_AFS
#ವ್ಯಾಖ್ಯಾನಿಸು SSHD_CONFIG_KRB5_AFS \
SSHCONF_INTFLAG(kerberos_get_afs_token, KerberosGetAFSToken, SSHCFG_GLOBAL, 0, SSHCFG_COPY_NONE)
#ಇಲ್ಲದಿದ್ದರೆ /* USE_AFS */
#ವ್ಯಾಖ್ಯಾನಿಸು SSHD_CONFIG_KRB5_AFS \
SSHCONF_UNSUPPORTED_INT(kerberos_get_afs_token, KerberosGetAFSToken, SSHCFG_GLOBAL)
#ಆದರೆ_ಅಂತ್ಯ /* USE_AFS */

#ವ್ಯಾಖ್ಯಾನಿಸು SSHD_CONFIG_ENTRIES_KRB5 \
SSHCONF_INTFLAG(kerberos_authentication, KerberosAuthentication, SSHCFG_ALL, 0, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_INTFLAG(kerberos_or_local_passwd, KerberosOrLocalPasswd, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(kerberos_ticket_cleanup, KerberosTicketCleanup, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHD_CONFIG_KRB5_AFS
#ಇಲ್ಲದಿದ್ದರೆ /* KRB5 */
#ವ್ಯಾಖ್ಯಾನಿಸು SSHD_CONFIG_ENTRIES_KRB5 \
SSHCONF_UNSUPPORTED_INT(kerberos_authentication, KerberosAuthentication, SSHCFG_ALL) \
SSHCONF_UNSUPPORTED_INT(kerberos_or_local_passwd, KerberosOrLocalPasswd, SSHCFG_GLOBAL) \
SSHCONF_UNSUPPORTED_INT(kerberos_ticket_cleanup, KerberosTicketCleanup, SSHCFG_GLOBAL) \
SSHCONF_UNSUPPORTED_INT(kerberos_get_afs_token, KerberosGetAFSToken, SSHCFG_GLOBAL)
#ಆದರೆ_ಅಂತ್ಯ /* KRB5 */

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ GSSAPI
#ವ್ಯಾಖ್ಯಾನಿಸು SSHD_CONFIG_ENTRIES_GSS \
SSHCONF_INTFLAG(gss_authentication, GSSAPIAuthentication, SSHCFG_ALL, 0, SSHCFG_COPY_ಹೊಂದಿಕೆ) \
SSHCONF_INTFLAG(gss_cleanup_creds, GSSAPICleanupCredentials, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(gss_deleg_creds, GSSAPIDelegateCredentials, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(gss_strict_acceptor, GSSAPIStrictAcceptorCheck, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE)
#ಇಲ್ಲದಿದ್ದರೆ /* GSSAPI */
#ವ್ಯಾಖ್ಯಾನಿಸು SSHD_CONFIG_ENTRIES_GSS \
SSHCONF_UNSUPPORTED_INT(gss_authentication, GSSAPIAuthentication, SSHCFG_ALL) \
SSHCONF_UNSUPPORTED_INT(gss_cleanup_creds, GSSAPICleanupCredentials, SSHCFG_GLOBAL) \
SSHCONF_UNSUPPORTED_INT(gss_deleg_creds, GSSAPIDelegateCredentials, SSHCFG_GLOBAL) \
SSHCONF_UNSUPPORTED_INT(gss_strict_acceptor, GSSAPIStrictAcceptorCheck, SSHCFG_GLOBAL)
#ಆದರೆ_ಅಂತ್ಯ /* GSSAPI */

#ವ್ಯಾಖ್ಯಾನಿಸು SSHD_CONFIG_ENTRIES \
	SSHD_CONFIG_ENTRIES_ತಳ \
	SSHD_CONFIG_ENTRIES_KRB5 \
	SSHD_CONFIG_ENTRIES_GSS \

/* Macros to declare ServerOptions member variables */
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_INT(var, conf, flags, ms, def, cp)	ಪೂರ್ಣಾಂಕ var;
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_INTFLAG(var, conf, flags, def, cp)	ಪೂರ್ಣಾಂಕ var;
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_STRING(var, conf, flags, cp)		ಅಕ್ಷರ *var;
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	\
	ಅಕ್ಷರ **var; \
	u_int nvar;
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	/*ಖಾಲಿಗಳು*/
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_NONCONF(funcsuffix)			/*ಖಾಲಿಗಳು*/
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_DEPRECATE(conf, flags, opcode)		/*ಖಾಲಿಗಳು*/
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_UNSUPPORTED_INT(var, conf, flags)	ಪೂರ್ಣಾಂಕ var;
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	ಅಕ್ಷರ *var;
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_ALIAS(old, conf, flags)			/*ಖಾಲಿಗಳು*/

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ ServerOptions {
	SSHD_CONFIG_ENTRIES
	/* Ports */
	u_int	ಅಂಕೆ_ports;
	u_int	ports_from_cmdline;
	ಪೂರ್ಣಾಂಕ	ports[MAX_PORTS];	/* Port number to listen on. */
	/* ListenAddress */
	ರಚನೆ queued_listenaddr *queued_listen_addrs;
	u_int	ಅಂಕೆ_queued_listens;
	ರಚನೆ listenaddr *listen_addrs;
	u_int	ಅಂಕೆ_listen_addrs;
	/* HostKey */
	ಅಕ್ಷರ   **host_ಕೀಲಿ_files;	/* Files containing host keys. */
	ಪೂರ್ಣಾಂಕ	*host_ಕೀಲಿ_file_userprovided; /* Key was specified by user. */
	u_int	ಅಂಕೆ_host_ಕೀಲಿ_files;     /* Number of files for host keys. */
	/* IPQoS */
	ಪೂರ್ಣಾಂಕ	ip_qos_interactive;	/* IP ToS/DSCP/class for interactive */
	ಪೂರ್ಣಾಂಕ	ip_qos_bulk;		/* IP ToS/DSCP/class for bulk traffic */
	/* GatewayPorts, StreamLocalBindMask, StreamLocalBindUnlink */
	ರಚನೆ ForwardOptions fwd_opts;	/* forwarding options */
	/* LogFacility */
	SyslogFacility log_facility;	/* Facility for system logging. */
	/* LogLevel */
	LogLevel log_level;	/* Level for system logging. */
	/* PermitUserEnvironment */
	ಪೂರ್ಣಾಂಕ     permit_user_env;	/* If true, read ~/.ssh/environment */
	ಅಕ್ಷರ   *permit_user_env_allowlist; /* pattern-list of allowed env names */
	/* Subsystem */
	u_int ಅಂಕೆ_subsystems;
	ಅಕ್ಷರ   **subsystem_name;
	ಅಕ್ಷರ   **subsystem_command;
	ಅಕ್ಷರ   **subsystem_ವಾದಗಳು;
	/* MaxStartups */
	ಪೂರ್ಣಾಂಕ	max_startups_begin;
	ಪೂರ್ಣಾಂಕ	max_startups_ದರ;
	ಪೂರ್ಣಾಂಕ	max_startups;
	/* PerSourceNetBlockSize */
	ಪೂರ್ಣಾಂಕ	ಪ್ರತಿ_ಮೂಲ_masklen_ipv4;
	ಪೂರ್ಣಾಂಕ	ಪ್ರತಿ_ಮೂಲ_masklen_ipv6;
	/* PerSourcePenalties */
	ರಚನೆ ಪ್ರತಿ_ಮೂಲ_penalty ಪ್ರತಿ_ಮೂಲ_penalty;
	/* RekeyLimit */
	int64_t rekey_ಎಲ್ಲೆ;
	ಪೂರ್ಣಾಂಕ	rekey_interval;
	/* PubkeyAuthOptions */
	ಪೂರ್ಣಾಂಕ	pubkey_auth_options;
	ಪೂರ್ಣಾಂಕ	max_pubkey_ok;
	/* Passed by config but not keyword for this */
	uint64_t timing_secret;
}       ServerOptions;
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

/* Information about the incoming connection as used by Match */
ರಚನೆ connection_info {
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *user;
	ಪೂರ್ಣಾಂಕ user_invalid;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host;	/* possibly resolved hostname */
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ವಿಳಾಸ;	/* remote address */
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *laddress;	/* local address */
	ಪೂರ್ಣಾಂಕ lport;		/* local port */
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *rdomain;	/* routing domain if available */
	ಪೂರ್ಣಾಂಕ test;		/* test mode, allow some attributes to be
				 * unspecified */
};

/* List of included files for re-exec from the parsed configuration */
ರಚನೆ include_ಅಂಶ {
	ಅಕ್ಷರ *selector;
	ಅಕ್ಷರ *filename;
	ರಚನೆ sshbuf *contents;
	TAILQ_ENTRY(include_ಅಂಶ) ನಮೂದು;
};
TAILQ_HEAD(include_list, include_ಅಂಶ);

ಶೂನ್ಯ	 initialize_server_options(ServerOptions *);
ಶೂನ್ಯ	 fill_default_server_options(ServerOptions *);
ಪೂರ್ಣಾಂಕ	 process_server_config_ಸಾಲು(ServerOptions *, ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ,
	    ಪೂರ್ಣಾಂಕ *, ರಚನೆ connection_info *, ರಚನೆ include_list *includes);
ಶೂನ್ಯ	 ತುಂಬು_server_config(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ರಚನೆ sshbuf *);
ಶೂನ್ಯ	 parse_server_config(ServerOptions *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ರಚನೆ sshbuf *,
	    ರಚನೆ include_list *includes, ರಚನೆ connection_info *, ಪೂರ್ಣಾಂಕ);
ಶೂನ್ಯ	 parse_server_ಹೊಂದಿಕೆ_config(ServerOptions *,
	    ರಚನೆ include_list *includes, ರಚನೆ connection_info *);
ಪೂರ್ಣಾಂಕ	 parse_server_ಹೊಂದಿಕೆ_testspec(ರಚನೆ connection_info *, ಅಕ್ಷರ *);
ಶೂನ್ಯ	 servconf_ವಿಲೀನ_subsystems(ServerOptions *, ServerOptions *);
ಶೂನ್ಯ	 copy_ಗಣ_server_options(ServerOptions *, ServerOptions *, ಪೂರ್ಣಾಂಕ);
ಶೂನ್ಯ	 dump_config(ServerOptions *);
ಅಕ್ಷರ	*derelativise_ಮಾರ್ಗ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಶೂನ್ಯ	 servconf_ಕೂಡಿಸು_hostkey(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಪೂರ್ಣಾಂಕ,
	    ServerOptions *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, ಪೂರ್ಣಾಂಕ);
ಶೂನ್ಯ	 servconf_ಕೂಡಿಸು_hostcert(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಪೂರ್ಣಾಂಕ,
	    ServerOptions *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ);

ಪೂರ್ಣಾಂಕ	 serialise_server_options(ಸ್ಥಿರಾಂಕ ServerOptions *, ರಚನೆ sshbuf **);
ಪೂರ್ಣಾಂಕ	 deserialise_server_options(ರಚನೆ sshbuf *, ServerOptions *);
ಶೂನ್ಯ	 free_server_options(ServerOptions *);

#ಆದರೆ_ಅಂತ್ಯ				/* SERVCONF_H */
