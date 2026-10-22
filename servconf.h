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

#अगर_अघोषित SERVCONF_H
#घोषणा SERVCONF_H

#समावेश <sys/queue.h>

काष्ठा sshbuf;

#घोषणा MAX_PORTS		256	/* Max # ports. */

/* permit_root_login */
#घोषणा	PERMIT_NOT_SET		-1
#घोषणा	PERMIT_NO		0
#घोषणा	PERMIT_FORCED_ONLY	1
#घोषणा	PERMIT_NO_PASSWD	2
#घोषणा	PERMIT_YES		3

/* PermitOpen */
#घोषणा PERMITOPEN_ANY		0
#घोषणा PERMITOPEN_NONE		-2

/* IgnoreRhosts */
#घोषणा IGNORE_RHOSTS_NO	0
#घोषणा IGNORE_RHOSTS_YES	1
#घोषणा IGNORE_RHOSTS_SHOSTS	2

#घोषणा DEFAULT_AUTH_FAIL_MAX	6	/* Default for MaxAuthTries */
#घोषणा DEFAULT_SESSIONS_MAX	10	/* Default for MaxSessions */

/* Magic name for internal sftp-server */
#घोषणा INTERNAL_SFTP_NAME	"internal-sftp"

/* PubkeyAuthOptions flags */
#घोषणा PUBKEYAUTH_TOUCH_REQUIRED	(1)
#घोषणा PUBKEYAUTH_VERIFY_REQUIRED	(1<<1)

/* Various defaults */
#घोषणा SSHD_DEFAULT_LOGIN_GRACE_TIME	120
#घोषणा SSHD_DEFAULT_X11_DISPLAY_OFFSET	10
#अगर_घोषित WITH_ZLIB
#घोषणा SSHD_DEFAULT_COMPRESSION	COMP_DELAYED
#अन्यथा
#घोषणा SSHD_DEFAULT_COMPRESSION	COMP_NONE
#पूर्ण_अगर

/* TCPKeepAlive flags */
#घोषणा SSH_KEEPALIVES_OFF		0
#घोषणा SSH_KEEPALIVES_TRANSPORT	1
#घोषणा SSH_KEEPALIVES_ALL		2

काष्ठा ssh;

/*
 * Used to store addresses from ListenAddr directives. These may be
 * incomplete, as they may specify addresses that need to be merged
 * with any ports requested by ListenPort.
 */
काष्ठा queued_listenaddr {
	अक्षर *addr;
	पूर्णांक port; /* <=0 if unspecified */
	अक्षर *rdomain;
};

/* Resolved listen addresses, grouped by optional routing domain */
काष्ठा listenaddr {
	अक्षर *rdomain;
	काष्ठा addrinfo *addrs;
};

#घोषणा PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL	1
#घोषणा PER_SOURCE_PENALTY_OVERFLOW_PERMISSIVE	2
काष्ठा per_source_penalty {
	पूर्णांक	enabled;
	पूर्णांक	max_sources4;
	पूर्णांक	max_sources6;
	पूर्णांक	overflow_mode;
	पूर्णांक	overflow_mode6;
	द्विगुन	penalty_crash;
	द्विगुन	penalty_grace;
	द्विगुन	penalty_authfail;
	द्विगुन	penalty_invaliduser;
	द्विगुन	penalty_noauth;
	द्विगुन	penalty_refuseconnection;
	द्विगुन	penalty_max;
	द्विगुन	penalty_min;
};

/* Options for whether config entries are copied after Match processing */
#घोषणा SSHCFG_COPY_NONE(action)
#घोषणा SSHCFG_COPY_MATCH(action)	action
#घोषणा SSHCFG_COPY_MANUAL(action)

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
#घोषणा SSHD_CONFIG_ENTRIES_CUSTOM \
SSHCONF_CUSTOM(Port, port, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(ListenAddress, listenaddress, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(Host_कुंजी, hostkeyfile, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(IPQoS, ipqos, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_CUSTOM(GatewayPorts, gatewayports, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_CUSTOM(StreamLocalBindMask, streamlocalbindmask, SSHCFG_ALL, SSHCFG_COPY_MANUAL) \
SSHCONF_CUSTOM(StreamLocalBindUnlink, streamlocalbindunlink, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_CUSTOM(SyslogFacility, logfacility, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(LogLevel, loglevel, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_CUSTOM(PermitUserEnvironment, permituserenv, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(Subsystem, subsystem, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_CUSTOM(MaxStartups, maxstartups, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(Per_Source_Net_Block_आकार, persourcenetblocksize, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(PerSourcePenalties, persourcepenalties, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(RekeyLimit, rekeylimit, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_CUSTOM(PubkeyAuthOptions, pubkey_auth_options, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_NONCONF(timingsecret)

#घोषणा SSHD_CONFIG_ENTRIES_MAIN \
SSHCONF_INT(address_family, AddressFamily, SSHCFG_GLOBAL, multistate_addressfamily, AF_UNSPEC, SSHCFG_COPY_NONE) \
SSHCONF_STRING(routing_domain, RDomain, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_STRARRAY(host_cert_files, अंक_host_cert_files, HostCertificate, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(host_कुंजी_agent, Host_कुंजी_Agent, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(pid_file, PidFile, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(moduli_file, ModuliFile, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_INT(login_grace_time, LoginGraceTime, SSHCFG_GLOBAL, शून्य, SSHD_DEFAULT_LOGIN_GRACE_TIME, SSHCFG_COPY_NONE) \
SSHCONF_INT(permit_मूल_login, Permit_मूल_Login, SSHCFG_ALL, multistate_permitrootlogin, PERMIT_NO_PASSWD, SSHCFG_COPY_MATCH) \
SSHCONF_INT(ignore_rhosts, IgnoreRhosts, SSHCFG_ALL, multistate_ignore_rhosts, 1, SSHCFG_COPY_MATCH) \
SSHCONF_INTFLAG(ignore_user_known_hosts, IgnoreUserKnownHosts, SSHCFG_GLOBAL, 0, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(print_motd, PrintMotd, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(x11_forwarding, X11Forwarding, SSHCFG_ALL, 0, SSHCFG_COPY_MATCH) \
SSHCONF_INT(x11_display_offset, X11DisplayOffset, SSHCFG_ALL, शून्य, SSHD_DEFAULT_X11_DISPLAY_OFFSET, SSHCFG_COPY_MATCH) \
SSHCONF_INTFLAG(x11_use_localhost, X11UseLocalhost, SSHCFG_ALL, 1, SSHCFG_COPY_MATCH) \
SSHCONF_STRING(xauth_location, XAuthLocation, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(permit_tty, PermitTTY, SSHCFG_ALL, 1, SSHCFG_COPY_MATCH) \
SSHCONF_INTFLAG(permit_user_rc, PermitUserRC, SSHCFG_ALL, 1, SSHCFG_COPY_MATCH) \
SSHCONF_INTFLAG(strict_modes, StrictModes, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(tcp_keep_alive, TCPKeepAlive, SSHCFG_GLOBAL, SSH_KEEPALIVES_TRANSPORT, SSHCFG_COPY_NONE) \
SSHCONF_STRING(ciphers, Ciphers, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(macs, Macs, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(kex_algorithms, KexAlgorithms, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRARRAY(log_verbose, अंक_log_verbose, LogVerbose, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_INTFLAG(hostbased_authentication, HostbasedAuthentication, SSHCFG_ALL, 0, SSHCFG_COPY_MATCH) \
SSHCONF_INTFLAG(hostbased_uses_name_from_packet_only, HostbasedUsesNameFromPacketOnly, SSHCFG_ALL, 0, SSHCFG_COPY_MATCH) \
SSHCONF_STRING(hostbased_accepted_algos, HostbasedAcceptedAlgorithms, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_STRING(hostkeyalgorithms, Host_कुंजी_Algorithms, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(ca_sign_algorithms, CASignatureAlgorithms, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_INTFLAG(pubkey_authentication, PubkeyAuthentication, SSHCFG_ALL, 1, SSHCFG_COPY_MATCH) \
SSHCONF_STRING(pubkey_accepted_algos, PubkeyAcceptedAlgorithms, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_INTFLAG(password_authentication, PasswordAuthentication, SSHCFG_ALL, 1, SSHCFG_COPY_MATCH) \
SSHCONF_INTFLAG(kbd_interactive_authentication, KbdInteractiveAuthentication, SSHCFG_ALL, 1, SSHCFG_COPY_MATCH) \
SSHCONF_INTFLAG(permit_empty_passwd, PermitEmptyPasswords, SSHCFG_ALL, 0, SSHCFG_COPY_MATCH) \
SSHCONF_INT(compression, Compression, SSHCFG_GLOBAL, multistate_compression, SSHD_DEFAULT_COMPRESSION, SSHCFG_COPY_NONE) \
SSHCONF_INT(allow_tcp_forwarding, AllowTcpForwarding, SSHCFG_ALL, multistate_tcpfwd, FORWARD_ALLOW, SSHCFG_COPY_MATCH) \
SSHCONF_INT(allow_streamlocal_forwarding, AllowStreamLocalForwarding, SSHCFG_ALL, multistate_tcpfwd, FORWARD_ALLOW, SSHCFG_COPY_MATCH) \
SSHCONF_INTFLAG(allow_agent_forwarding, AllowAgentForwarding, SSHCFG_ALL, 1, SSHCFG_COPY_MATCH) \
SSHCONF_INTFLAG(disable_forwarding, DisableForwarding, SSHCFG_ALL, 0, SSHCFG_COPY_MATCH) \
SSHCONF_STRARRAY(allow_users, अंक_allow_users, AllowUsers, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_STRARRAY(deny_users, अंक_deny_users, DenyUsers, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_STRARRAY(allow_groups, अंक_allow_groups, AllowGroups, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_STRARRAY(deny_groups, अंक_deny_groups, DenyGroups, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_STRARRAY(accept_env, अंक_accept_env, AcceptEnv, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_STRARRAY(setenv, अंक_setenv, SetEnv, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_INT(per_source_max_startups, PerSourceMaxStartups, SSHCFG_GLOBAL, शून्य, पूर्णांक_उच्च, SSHCFG_COPY_NONE) \
SSHCONF_STRING(per_source_penalty_exempt, PerSourcePenaltyExemptList, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_INT(max_authtries, MaxAuthTries, SSHCFG_ALL, शून्य, DEFAULT_AUTH_FAIL_MAX, SSHCFG_COPY_MATCH) \
SSHCONF_INT(max_sessions, MaxSessions, SSHCFG_ALL, शून्य, DEFAULT_SESSIONS_MAX, SSHCFG_COPY_MATCH) \
SSHCONF_STRING(banner, Banner, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_INTFLAG(use_dns, UseDNS, SSHCFG_GLOBAL, 0, SSHCFG_COPY_NONE) \
SSHCONF_INT(client_alive_interval, ClientAliveInterval, SSHCFG_ALL, शून्य, 0, SSHCFG_COPY_MATCH) \
SSHCONF_INT(client_alive_गिनती_max, Client_Alive_गिनती_Max, SSHCFG_ALL, शून्य, 3, SSHCFG_COPY_MATCH) \
SSHCONF_STRARRAY(authorized_कुंजियाँ_files, अंक_authkeys_files, Authorized_कुंजियाँ_File, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_STRING(adm_forced_command, ForceCommand, SSHCFG_ALL, SSHCFG_COPY_MANUAL) \
SSHCONF_INTFLAG(permit_tun, PermitTunnel, SSHCFG_ALL, SSH_TUNMODE_NO, SSHCFG_COPY_MATCH) \
SSHCONF_STRARRAY(permitted_opens, अंक_permitted_opens, PermitOpen, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_STRARRAY(permitted_listens, अंक_permitted_listens, PermitListen, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_STRING(chroot_directory, ChrootDirectory, SSHCFG_ALL, SSHCFG_COPY_MANUAL) \
SSHCONF_STRARRAY(revoked_कुंजियाँ_files, अंक_revoked_कुंजियाँ_files, Revoked_कुंजियाँ, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_STRING(trusted_user_ca_कुंजियाँ, TrustedUserCAKeys, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_STRING(authorized_कुंजियाँ_command, Authorized_कुंजियाँ_Command, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_STRING(authorized_कुंजियाँ_command_user, Authorized_कुंजियाँ_Command_User, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_STRING(authorized_principals_file, AuthorizedPrincipalsFile, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_STRING(authorized_principals_command, AuthorizedPrincipalsCommand, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_STRING(authorized_principals_command_user, AuthorizedPrincipalsCommandUser, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_STRING(version_addendum, VersionAddendum, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRARRAY(auth_methods, अंक_auth_methods, AuthenticationMethods, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_INT(fingerprint_hash, FingerprintHash, SSHCFG_GLOBAL, शून्य, SSH_FP_HASH_DEFAULT, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(expose_userauth_info, ExposeAuthInfo, SSHCFG_ALL, 0, SSHCFG_COPY_MATCH) \
SSHCONF_STRING(sk_provider, Security_कुंजी_Provider, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_INT(required_rsa_आकार, RequiredRSASize, SSHCFG_ALL, शून्य, SSH_RSA_MINIMUM_MODULUS_आकार, SSHCFG_COPY_MATCH) \
SSHCONF_STRARRAY(channel_timeouts, अंक_channel_timeouts, ChannelTimeout, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_INT(unused_connection_timeout, UnusedConnectionTimeout, SSHCFG_ALL, शून्य, 0, SSHCFG_COPY_MATCH) \
SSHCONF_STRING(sshd_session_path, SshdSessionPath, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(sshd_auth_path, SshdAuthPath, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(refuse_connection, RefuseConnection, SSHCFG_ALL, 0, SSHCFG_COPY_MATCH) \
SSHCONF_STRING(agent_socket_path, AgentSocketPath, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_INT(warn_weak_crypto, WarnWeakCrypto, SSHCFG_GLOBAL, multistate_warnweakcrypto, 1, SSHCFG_COPY_NONE)

#घोषणा SSHD_CONFIG_ENTRIES_LEGACY \
SSHCONF_DEPRECATE(Server_कुंजी_Bits, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(कुंजी_Regeneration_Interval, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(RHostsAuthentication, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(RhostsRSAAuthentication, SSHCFG_ALL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(RSAAuthentication, SSHCFG_ALL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(CheckMail, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(UseLogin, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(VerifyReverseMapping, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(ReverseMappingCheck, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(Authorized_कुंजियाँ_File2, SSHCFG_ALL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(UsePrivilegeSeparation, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(KerberosTgtPassing, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(AFSTokenPassing, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(Protocol, SSHCFG_GLOBAL, SSHCONF_IGNORE)

#घोषणा SSHD_CONFIG_ENTRIES_ALIASES \
SSHCONF_ALIAS(HostDSAKey, Host_कुंजी, SSHCFG_GLOBAL) \
SSHCONF_ALIAS(Host_Based_Accepted_कुंजी_Types, HostbasedAcceptedAlgorithms, SSHCFG_ALL) \
SSHCONF_ALIAS(Pubkey_Accepted_कुंजी_Types, PubkeyAcceptedAlgorithms, SSHCFG_ALL) \
SSHCONF_ALIAS(DSAAuthentication, PubkeyAuthentication, SSHCFG_GLOBAL) \
SSHCONF_ALIAS(ChallengeResponseAuthentication, KbdInteractiveAuthentication, SSHCFG_ALL) \
SSHCONF_ALIAS(SKeyAuthentication, KbdInteractiveAuthentication, SSHCFG_ALL) \
SSHCONF_ALIAS(KeepAlive, TCPKeepAlive, SSHCFG_GLOBAL)

#घोषणा SSHD_CONFIG_ENTRIES_BASE \
	SSHD_CONFIG_ENTRIES_CUSTOM \
	SSHD_CONFIG_ENTRIES_MAIN \
	SSHD_CONFIG_ENTRIES_LEGACY \
	SSHD_CONFIG_ENTRIES_ALIASES \
	SSHD_CONFIG_ENTRIES_PAM \
	SSHD_CONFIG_ENTRIES_LASTLOG

#अगर_घोषित USE_PAM
#घोषणा SSHD_CONFIG_ENTRIES_PAM \
SSHCONF_INTFLAG(use_pam, UsePAM, SSHCFG_GLOBAL, 0, SSHCFG_COPY_NONE) \
SSHCONF_STRING(pam_service_name, PAMServiceName, SSHCFG_ALL, SSHCFG_COPY_MATCH)
#अन्यथा
#घोषणा SSHD_CONFIG_ENTRIES_PAM \
SSHCONF_UNSUPPORTED_INT(use_pam, UsePAM, SSHCFG_GLOBAL) \
SSHCONF_UNSUPPORTED_STRING(pam_service_name, PAMServiceName, SSHCFG_ALL)
#पूर्ण_अगर

#अगर_घोषित DISABLE_LASTLOG
#घोषणा SSHD_CONFIG_ENTRIES_LASTLOG \
SSHCONF_UNSUPPORTED_INT(print_lastlog, PrintLastLog, SSHCFG_GLOBAL)
#अन्यथा
#घोषणा SSHD_CONFIG_ENTRIES_LASTLOG \
SSHCONF_INTFLAG(print_lastlog, PrintLastLog, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE)
#पूर्ण_अगर

/* Compile-time enabled options */
#अगर_घोषित KRB5

#अगर_घोषित USE_AFS
#घोषणा SSHD_CONFIG_KRB5_AFS \
SSHCONF_INTFLAG(kerberos_get_afs_token, KerberosGetAFSToken, SSHCFG_GLOBAL, 0, SSHCFG_COPY_NONE)
#अन्यथा /* USE_AFS */
#घोषणा SSHD_CONFIG_KRB5_AFS \
SSHCONF_UNSUPPORTED_INT(kerberos_get_afs_token, KerberosGetAFSToken, SSHCFG_GLOBAL)
#पूर्ण_अगर /* USE_AFS */

#घोषणा SSHD_CONFIG_ENTRIES_KRB5 \
SSHCONF_INTFLAG(kerberos_authentication, KerberosAuthentication, SSHCFG_ALL, 0, SSHCFG_COPY_MATCH) \
SSHCONF_INTFLAG(kerberos_or_local_passwd, KerberosOrLocalPasswd, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(kerberos_ticket_cleanup, KerberosTicketCleanup, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHD_CONFIG_KRB5_AFS
#अन्यथा /* KRB5 */
#घोषणा SSHD_CONFIG_ENTRIES_KRB5 \
SSHCONF_UNSUPPORTED_INT(kerberos_authentication, KerberosAuthentication, SSHCFG_ALL) \
SSHCONF_UNSUPPORTED_INT(kerberos_or_local_passwd, KerberosOrLocalPasswd, SSHCFG_GLOBAL) \
SSHCONF_UNSUPPORTED_INT(kerberos_ticket_cleanup, KerberosTicketCleanup, SSHCFG_GLOBAL) \
SSHCONF_UNSUPPORTED_INT(kerberos_get_afs_token, KerberosGetAFSToken, SSHCFG_GLOBAL)
#पूर्ण_अगर /* KRB5 */

#अगर_घोषित GSSAPI
#घोषणा SSHD_CONFIG_ENTRIES_GSS \
SSHCONF_INTFLAG(gss_authentication, GSSAPIAuthentication, SSHCFG_ALL, 0, SSHCFG_COPY_MATCH) \
SSHCONF_INTFLAG(gss_cleanup_creds, GSSAPICleanupCredentials, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(gss_deleg_creds, GSSAPIDelegateCredentials, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(gss_strict_acceptor, GSSAPIStrictAcceptorCheck, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE)
#अन्यथा /* GSSAPI */
#घोषणा SSHD_CONFIG_ENTRIES_GSS \
SSHCONF_UNSUPPORTED_INT(gss_authentication, GSSAPIAuthentication, SSHCFG_ALL) \
SSHCONF_UNSUPPORTED_INT(gss_cleanup_creds, GSSAPICleanupCredentials, SSHCFG_GLOBAL) \
SSHCONF_UNSUPPORTED_INT(gss_deleg_creds, GSSAPIDelegateCredentials, SSHCFG_GLOBAL) \
SSHCONF_UNSUPPORTED_INT(gss_strict_acceptor, GSSAPIStrictAcceptorCheck, SSHCFG_GLOBAL)
#पूर्ण_अगर /* GSSAPI */

#घोषणा SSHD_CONFIG_ENTRIES \
	SSHD_CONFIG_ENTRIES_BASE \
	SSHD_CONFIG_ENTRIES_KRB5 \
	SSHD_CONFIG_ENTRIES_GSS \

/* Macros to declare ServerOptions member variables */
#घोषणा SSHCONF_INT(var, conf, flags, ms, def, cp)	पूर्णांक var;
#घोषणा SSHCONF_INTFLAG(var, conf, flags, def, cp)	पूर्णांक var;
#घोषणा SSHCONF_STRING(var, conf, flags, cp)		अक्षर *var;
#घोषणा SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	\
	अक्षर **var; \
	u_int nvar;
#घोषणा SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	/* empty */
#घोषणा SSHCONF_NONCONF(funcsuffix)			/* empty */
#घोषणा SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#घोषणा SSHCONF_UNSUPPORTED_INT(var, conf, flags)	पूर्णांक var;
#घोषणा SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	अक्षर *var;
#घोषणा SSHCONF_ALIAS(old, conf, flags)			/* empty */

प्रकार काष्ठा ServerOptions {
	SSHD_CONFIG_ENTRIES
	/* Ports */
	u_int	अंक_ports;
	u_int	ports_from_cmdline;
	पूर्णांक	ports[MAX_PORTS];	/* Port number to listen on. */
	/* ListenAddress */
	काष्ठा queued_listenaddr *queued_listen_addrs;
	u_int	अंक_queued_listens;
	काष्ठा listenaddr *listen_addrs;
	u_int	अंक_listen_addrs;
	/* HostKey */
	अक्षर   **host_कुंजी_files;	/* Files containing host keys. */
	पूर्णांक	*host_कुंजी_file_userprovided; /* Key was specified by user. */
	u_int	अंक_host_कुंजी_files;     /* Number of files for host keys. */
	/* IPQoS */
	पूर्णांक	ip_qos_interactive;	/* IP ToS/DSCP/class for interactive */
	पूर्णांक	ip_qos_bulk;		/* IP ToS/DSCP/class for bulk traffic */
	/* GatewayPorts, StreamLocalBindMask, StreamLocalBindUnlink */
	काष्ठा ForwardOptions fwd_opts;	/* forwarding options */
	/* LogFacility */
	SyslogFacility log_facility;	/* Facility for system logging. */
	/* LogLevel */
	LogLevel log_level;	/* Level for system logging. */
	/* PermitUserEnvironment */
	पूर्णांक     permit_user_env;	/* If true, read ~/.ssh/environment */
	अक्षर   *permit_user_env_allowlist; /* pattern-list of allowed env names */
	/* Subsystem */
	u_int अंक_subsystems;
	अक्षर   **subsystem_name;
	अक्षर   **subsystem_command;
	अक्षर   **subsystem_args;
	/* MaxStartups */
	पूर्णांक	max_startups_begin;
	पूर्णांक	max_startups_rate;
	पूर्णांक	max_startups;
	/* PerSourceNetBlockSize */
	पूर्णांक	per_source_masklen_ipv4;
	पूर्णांक	per_source_masklen_ipv6;
	/* PerSourcePenalties */
	काष्ठा per_source_penalty per_source_penalty;
	/* RekeyLimit */
	int64_t rekey_limit;
	पूर्णांक	rekey_interval;
	/* PubkeyAuthOptions */
	पूर्णांक	pubkey_auth_options;
	पूर्णांक	max_pubkey_ok;
	/* Passed by config but not keyword for this */
	uint64_t timing_secret;
}       ServerOptions;
#अघोषित SSHCONF_INT
#अघोषित SSHCONF_INTFLAG
#अघोषित SSHCONF_STRING
#अघोषित SSHCONF_STRARRAY
#अघोषित SSHCONF_CUSTOM
#अघोषित SSHCONF_NONCONF
#अघोषित SSHCONF_DEPRECATE
#अघोषित SSHCONF_UNSUPPORTED_INT
#अघोषित SSHCONF_UNSUPPORTED_STRING
#अघोषित SSHCONF_ALIAS

/* Information about the incoming connection as used by Match */
काष्ठा connection_info {
	स्थिर अक्षर *user;
	पूर्णांक user_invalid;
	स्थिर अक्षर *host;	/* possibly resolved hostname */
	स्थिर अक्षर *address;	/* remote address */
	स्थिर अक्षर *laddress;	/* local address */
	पूर्णांक lport;		/* local port */
	स्थिर अक्षर *rdomain;	/* routing domain if available */
	पूर्णांक test;		/* test mode, allow some attributes to be
				 * unspecified */
};

/* List of included files for re-exec from the parsed configuration */
काष्ठा include_item {
	अक्षर *selector;
	अक्षर *filename;
	काष्ठा sshbuf *contents;
	TAILQ_ENTRY(include_item) entry;
};
TAILQ_HEAD(include_list, include_item);

व्योम	 initialize_server_options(ServerOptions *);
व्योम	 fill_default_server_options(ServerOptions *);
पूर्णांक	 process_server_config_पंक्ति(ServerOptions *, अक्षर *, स्थिर अक्षर *, पूर्णांक,
	    पूर्णांक *, काष्ठा connection_info *, काष्ठा include_list *includes);
व्योम	 load_server_config(स्थिर अक्षर *, काष्ठा sshbuf *);
व्योम	 parse_server_config(ServerOptions *, स्थिर अक्षर *, काष्ठा sshbuf *,
	    काष्ठा include_list *includes, काष्ठा connection_info *, पूर्णांक);
व्योम	 parse_server_match_config(ServerOptions *,
	    काष्ठा include_list *includes, काष्ठा connection_info *);
पूर्णांक	 parse_server_match_testspec(काष्ठा connection_info *, अक्षर *);
व्योम	 servconf_merge_subsystems(ServerOptions *, ServerOptions *);
व्योम	 copy_set_server_options(ServerOptions *, ServerOptions *, पूर्णांक);
व्योम	 dump_config(ServerOptions *);
अक्षर	*derelativise_path(स्थिर अक्षर *);
व्योम	 servconf_add_hostkey(स्थिर अक्षर *, स्थिर पूर्णांक,
	    ServerOptions *, स्थिर अक्षर *path, पूर्णांक);
व्योम	 servconf_add_hostcert(स्थिर अक्षर *, स्थिर पूर्णांक,
	    ServerOptions *, स्थिर अक्षर *path);

पूर्णांक	 serialise_server_options(स्थिर ServerOptions *, काष्ठा sshbuf **);
पूर्णांक	 deserialise_server_options(काष्ठा sshbuf *, ServerOptions *);
व्योम	 free_server_options(ServerOptions *);

#पूर्ण_अगर				/* SERVCONF_H */
