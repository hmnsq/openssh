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

#ifndef SERVCONF_H
#define SERVCONF_H

#شامل <sys/queue.h>

ساختار sshbuf;

#define MAX_PORTS		256	/* Max # ports. */

/* permit_root_login */
#define	PERMIT_NOT_SET		-1
#define	PERMIT_NO		0
#define	PERMIT_FORCED_ONLY	1
#define	PERMIT_NO_PASSWD	2
#define	PERMIT_YES		3

/* PermitOpen */
#define PERMITOPEN_ANY		0
#define PERMITOPEN_NONE		-2

/* IgnoreRhosts */
#define IGNORE_RHOSTS_NO	0
#define IGNORE_RHOSTS_YES	1
#define IGNORE_RHOSTS_SHOSTS	2

#define DEFAULT_AUTH_FAIL_MAX	6	/* Default for MaxAuthTries */
#define DEFAULT_SESSIONS_MAX	10	/* Default for MaxSessions */

/* Magic name for internal sftp-server */
#define INTERNAL_SFTP_NAME	"internal-sftp"

/* PubkeyAuthOptions flags */
#define PUBKEYAUTH_TOUCH_REQUIRED	(1)
#define PUBKEYAUTH_VERIFY_REQUIRED	(1<<1)

/* Various defaults */
#define SSHD_DEFAULT_LOGIN_GRACE_TIME	120
#define SSHD_DEFAULT_X11_DISPLAY_OFFSET	10
#ifdef WITH_ZLIB
#define SSHD_DEFAULT_COMPRESSION	COMP_DELAYED
#وگرنه
#define SSHD_DEFAULT_COMPRESSION	COMP_NONE
#endif

/* TCPKeepAlive flags */
#define SSH_KEEPALIVES_OFF		0
#define SSH_KEEPALIVES_TRANSPORT	1
#define SSH_KEEPALIVES_ALL		2

ساختار ssh;

/*
 * Used to store addresses from ListenAddr directives. These may be
 * incomplete, as they may specify addresses that need to be merged
 * with any ports requested by ListenPort.
 */
ساختار queued_listenaddr {
	نویسه *addr;
	صحیح port; /* <=0 if unspecified */
	نویسه *rdomain;
};

/* Resolved listen addresses, grouped by optional routing domain */
ساختار listenaddr {
	نویسه *rdomain;
	ساختار addrinfo *addrs;
};

#define PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL	1
#define PER_SOURCE_PENALTY_OVERFLOW_PERMISSIVE	2
ساختار per_source_penalty {
	صحیح	enabled;
	صحیح	max_sources4;
	صحیح	max_sources6;
	صحیح	overflow_mode;
	صحیح	overflow_mode6;
	دوگانه	penalty_crash;
	دوگانه	penalty_grace;
	دوگانه	penalty_authfail;
	دوگانه	penalty_invaliduser;
	دوگانه	penalty_noauth;
	دوگانه	penalty_refuseconnection;
	دوگانه	penalty_max;
	دوگانه	penalty_min;
};

/* Options for whether config entries are copied after Match processing */
#define SSHCFG_COPY_NONE(action)
#define SSHCFG_COPY_MATCH(action)	action
#define SSHCFG_COPY_MANUAL(action)

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
#define SSHD_CONFIG_ENTRIES_CUSTOM \
SSHCONF_CUSTOM(Port, port, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(ListenAddress, listenaddress, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(Host_کلید, hostkeyfile, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(IPQoS, ipqos, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_CUSTOM(GatewayPorts, gatewayports, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_CUSTOM(StreamLocalBindMask, streamlocalbindmask, SSHCFG_ALL, SSHCFG_COPY_MANUAL) \
SSHCONF_CUSTOM(StreamLocalBindUnlink, streamlocalbindunlink, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_CUSTOM(SyslogFacility, logfacility, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(LogLevel, loglevel, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_CUSTOM(PermitUserEnvironment, permituserenv, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(Subsystem, subsystem, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_CUSTOM(MaxStartups, maxstartups, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(PerSourceNetBlockSize, persourcenetblocksize, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(PerSourcePenalties, persourcepenalties, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(RekeyLimit, rekeylimit, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_CUSTOM(PubkeyAuthOptions, pubkey_auth_options, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_NONCONF(timingsecret)

#define SSHD_CONFIG_ENTRIES_MAIN \
SSHCONF_INT(address_family, AddressFamily, SSHCFG_GLOBAL, multistate_addressfamily, AF_UNSPEC, SSHCFG_COPY_NONE) \
SSHCONF_STRING(routing_domain, RDomain, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_STRARRAY(host_cert_files, رقم_host_cert_files, HostCertificate, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(host_کلید_agent, Host_کلید_Agent, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(pid_file, PidFile, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(moduli_file, ModuliFile, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_INT(login_grace_time, LoginGraceTime, SSHCFG_GLOBAL, پوچ, SSHD_DEFAULT_LOGIN_GRACE_TIME, SSHCFG_COPY_NONE) \
SSHCONF_INT(permit_ریشه_login, Permit_ریشه_Login, SSHCFG_ALL, multistate_permitrootlogin, PERMIT_NO_PASSWD, SSHCFG_COPY_MATCH) \
SSHCONF_INT(ignore_rhosts, IgnoreRhosts, SSHCFG_ALL, multistate_ignore_rhosts, 1, SSHCFG_COPY_MATCH) \
SSHCONF_INTFLAG(ignore_user_known_hosts, IgnoreUserKnownHosts, SSHCFG_GLOBAL, 0, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(print_motd, PrintMotd, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(x11_forwarding, X11Forwarding, SSHCFG_ALL, 0, SSHCFG_COPY_MATCH) \
SSHCONF_INT(x11_display_offset, X11DisplayOffset, SSHCFG_ALL, پوچ, SSHD_DEFAULT_X11_DISPLAY_OFFSET, SSHCFG_COPY_MATCH) \
SSHCONF_INTFLAG(x11_use_localhost, X11UseLocalhost, SSHCFG_ALL, 1, SSHCFG_COPY_MATCH) \
SSHCONF_STRING(xauth_location, XAuthLocation, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(permit_tty, PermitTTY, SSHCFG_ALL, 1, SSHCFG_COPY_MATCH) \
SSHCONF_INTFLAG(permit_user_rc, PermitUserRC, SSHCFG_ALL, 1, SSHCFG_COPY_MATCH) \
SSHCONF_INTFLAG(strict_modes, StrictModes, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(tcp_keep_alive, TCPKeepAlive, SSHCFG_GLOBAL, SSH_KEEPALIVES_TRANSPORT, SSHCFG_COPY_NONE) \
SSHCONF_STRING(ciphers, Ciphers, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(macs, Macs, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(kex_algorithms, KexAlgorithms, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRARRAY(log_verbose, رقم_log_verbose, LogVerbose, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_INTFLAG(hostbased_authentication, HostbasedAuthentication, SSHCFG_ALL, 0, SSHCFG_COPY_MATCH) \
SSHCONF_INTFLAG(hostbased_uses_name_from_packet_only, HostbasedUsesNameFromPacketOnly, SSHCFG_ALL, 0, SSHCFG_COPY_MATCH) \
SSHCONF_STRING(hostbased_accepted_algos, HostbasedAcceptedAlgorithms, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_STRING(hostkeyalgorithms, Host_کلید_Algorithms, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
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
SSHCONF_STRARRAY(allow_users, رقم_allow_users, AllowUsers, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_STRARRAY(deny_users, رقم_deny_users, DenyUsers, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_STRARRAY(allow_groups, رقم_allow_groups, AllowGroups, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_STRARRAY(deny_groups, رقم_deny_groups, DenyGroups, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_STRARRAY(accept_env, رقم_accept_env, AcceptEnv, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_STRARRAY(setenv, رقم_setenv, SetEnv, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_INT(per_source_max_startups, PerSourceMaxStartups, SSHCFG_GLOBAL, پوچ, INT_MAX, SSHCFG_COPY_NONE) \
SSHCONF_STRING(per_source_penalty_exempt, PerSourcePenaltyExemptList, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_INT(max_authtries, MaxAuthTries, SSHCFG_ALL, پوچ, DEFAULT_AUTH_FAIL_MAX, SSHCFG_COPY_MATCH) \
SSHCONF_INT(max_sessions, MaxSessions, SSHCFG_ALL, پوچ, DEFAULT_SESSIONS_MAX, SSHCFG_COPY_MATCH) \
SSHCONF_STRING(banner, Banner, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_INTFLAG(use_dns, UseDNS, SSHCFG_GLOBAL, 0, SSHCFG_COPY_NONE) \
SSHCONF_INT(client_alive_interval, ClientAliveInterval, SSHCFG_ALL, پوچ, 0, SSHCFG_COPY_MATCH) \
SSHCONF_INT(client_alive_شمار_max, Client_Alive_شمار_Max, SSHCFG_ALL, پوچ, 3, SSHCFG_COPY_MATCH) \
SSHCONF_STRARRAY(authorized_کلیدها_files, رقم_authkeys_files, Authorized_کلیدها_File, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_STRING(adm_forced_command, ForceCommand, SSHCFG_ALL, SSHCFG_COPY_MANUAL) \
SSHCONF_INTFLAG(permit_tun, PermitTunnel, SSHCFG_ALL, SSH_TUNMODE_NO, SSHCFG_COPY_MATCH) \
SSHCONF_STRARRAY(permitted_opens, رقم_permitted_opens, PermitOpen, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_STRARRAY(permitted_listens, رقم_permitted_listens, PermitListen, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_STRING(chroot_directory, ChrootDirectory, SSHCFG_ALL, SSHCFG_COPY_MANUAL) \
SSHCONF_STRARRAY(revoked_کلیدها_files, رقم_revoked_کلیدها_files, Revoked_کلیدها, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_STRING(trusted_user_ca_کلیدها, TrustedUserCAKeys, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_STRING(authorized_کلیدها_command, Authorized_کلیدها_Command, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_STRING(authorized_کلیدها_command_user, Authorized_کلیدها_Command_User, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_STRING(authorized_principals_file, AuthorizedPrincipalsFile, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_STRING(authorized_principals_command, AuthorizedPrincipalsCommand, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_STRING(authorized_principals_command_user, AuthorizedPrincipalsCommandUser, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_STRING(version_addendum, VersionAddendum, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRARRAY(auth_methods, رقم_auth_methods, AuthenticationMethods, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_INT(fingerprint_hash, FingerprintHash, SSHCFG_GLOBAL, پوچ, SSH_FP_HASH_DEFAULT, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(expose_userauth_info, ExposeAuthInfo, SSHCFG_ALL, 0, SSHCFG_COPY_MATCH) \
SSHCONF_STRING(sk_provider, Security_کلید_Provider, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_INT(required_rsa_size, RequiredRSASize, SSHCFG_ALL, پوچ, SSH_RSA_MINIMUM_MODULUS_SIZE, SSHCFG_COPY_MATCH) \
SSHCONF_STRARRAY(channel_timeouts, رقم_channel_timeouts, ChannelTimeout, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_INT(unused_connection_timeout, UnusedConnectionTimeout, SSHCFG_ALL, پوچ, 0, SSHCFG_COPY_MATCH) \
SSHCONF_STRING(sshd_session_path, SshdSessionPath, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(sshd_auth_path, SshdAuthPath, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(refuse_connection, RefuseConnection, SSHCFG_ALL, 0, SSHCFG_COPY_MATCH) \
SSHCONF_STRING(agent_socket_path, AgentSocketPath, SSHCFG_ALL, SSHCFG_COPY_MATCH) \
SSHCONF_INT(warn_weak_crypto, WarnWeakCrypto, SSHCFG_GLOBAL, multistate_warnweakcrypto, 1, SSHCFG_COPY_NONE)

#define SSHD_CONFIG_ENTRIES_LEGACY \
SSHCONF_DEPRECATE(Server_کلید_Bits, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(کلید_Regeneration_Interval, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(RHostsAuthentication, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(RhostsRSAAuthentication, SSHCFG_ALL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(RSAAuthentication, SSHCFG_ALL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(CheckMail, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(UseLogin, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(VerifyReverseMapping, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(ReverseMappingCheck, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(Authorized_کلیدها_File2, SSHCFG_ALL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(UsePrivilegeSeparation, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(KerberosTgtPassing, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(AFSTokenPassing, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(Protocol, SSHCFG_GLOBAL, SSHCONF_IGNORE)

#define SSHD_CONFIG_ENTRIES_ALIASES \
SSHCONF_ALIAS(HostDSAKey, Host_کلید, SSHCFG_GLOBAL) \
SSHCONF_ALIAS(Host_Based_Accepted_کلید_Types, HostbasedAcceptedAlgorithms, SSHCFG_ALL) \
SSHCONF_ALIAS(Pubkey_Accepted_کلید_Types, PubkeyAcceptedAlgorithms, SSHCFG_ALL) \
SSHCONF_ALIAS(DSAAuthentication, PubkeyAuthentication, SSHCFG_GLOBAL) \
SSHCONF_ALIAS(ChallengeResponseAuthentication, KbdInteractiveAuthentication, SSHCFG_ALL) \
SSHCONF_ALIAS(SKeyAuthentication, KbdInteractiveAuthentication, SSHCFG_ALL) \
SSHCONF_ALIAS(KeepAlive, TCPKeepAlive, SSHCFG_GLOBAL)

#define SSHD_CONFIG_ENTRIES_BASE \
	SSHD_CONFIG_ENTRIES_CUSTOM \
	SSHD_CONFIG_ENTRIES_MAIN \
	SSHD_CONFIG_ENTRIES_LEGACY \
	SSHD_CONFIG_ENTRIES_ALIASES \
	SSHD_CONFIG_ENTRIES_PAM \
	SSHD_CONFIG_ENTRIES_LASTLOG

#ifdef USE_PAM
#define SSHD_CONFIG_ENTRIES_PAM \
SSHCONF_INTFLAG(use_pam, UsePAM, SSHCFG_GLOBAL, 0, SSHCFG_COPY_NONE) \
SSHCONF_STRING(pam_service_name, PAMServiceName, SSHCFG_ALL, SSHCFG_COPY_MATCH)
#وگرنه
#define SSHD_CONFIG_ENTRIES_PAM \
SSHCONF_UNSUPPORTED_INT(use_pam, UsePAM, SSHCFG_GLOBAL) \
SSHCONF_UNSUPPORTED_STRING(pam_service_name, PAMServiceName, SSHCFG_ALL)
#endif

#ifdef DISABLE_LASTLOG
#define SSHD_CONFIG_ENTRIES_LASTLOG \
SSHCONF_UNSUPPORTED_INT(print_lastlog, PrintLastLog, SSHCFG_GLOBAL)
#وگرنه
#define SSHD_CONFIG_ENTRIES_LASTLOG \
SSHCONF_INTFLAG(print_lastlog, PrintLastLog, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE)
#endif

/* Compile-time enabled options */
#ifdef KRB5

#ifdef USE_AFS
#define SSHD_CONFIG_KRB5_AFS \
SSHCONF_INTFLAG(kerberos_get_afs_token, KerberosGetAFSToken, SSHCFG_GLOBAL, 0, SSHCFG_COPY_NONE)
#وگرنه /* USE_AFS */
#define SSHD_CONFIG_KRB5_AFS \
SSHCONF_UNSUPPORTED_INT(kerberos_get_afs_token, KerberosGetAFSToken, SSHCFG_GLOBAL)
#endif /* USE_AFS */

#define SSHD_CONFIG_ENTRIES_KRB5 \
SSHCONF_INTFLAG(kerberos_authentication, KerberosAuthentication, SSHCFG_ALL, 0, SSHCFG_COPY_MATCH) \
SSHCONF_INTFLAG(kerberos_or_local_passwd, KerberosOrLocalPasswd, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(kerberos_ticket_cleanup, KerberosTicketCleanup, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHD_CONFIG_KRB5_AFS
#وگرنه /* KRB5 */
#define SSHD_CONFIG_ENTRIES_KRB5 \
SSHCONF_UNSUPPORTED_INT(kerberos_authentication, KerberosAuthentication, SSHCFG_ALL) \
SSHCONF_UNSUPPORTED_INT(kerberos_or_local_passwd, KerberosOrLocalPasswd, SSHCFG_GLOBAL) \
SSHCONF_UNSUPPORTED_INT(kerberos_ticket_cleanup, KerberosTicketCleanup, SSHCFG_GLOBAL) \
SSHCONF_UNSUPPORTED_INT(kerberos_get_afs_token, KerberosGetAFSToken, SSHCFG_GLOBAL)
#endif /* KRB5 */

#ifdef GSSAPI
#define SSHD_CONFIG_ENTRIES_GSS \
SSHCONF_INTFLAG(gss_authentication, GSSAPIAuthentication, SSHCFG_ALL, 0, SSHCFG_COPY_MATCH) \
SSHCONF_INTFLAG(gss_cleanup_creds, GSSAPICleanupCredentials, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(gss_deleg_creds, GSSAPIDelegateCredentials, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(gss_strict_acceptor, GSSAPIStrictAcceptorCheck, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE)
#وگرنه /* GSSAPI */
#define SSHD_CONFIG_ENTRIES_GSS \
SSHCONF_UNSUPPORTED_INT(gss_authentication, GSSAPIAuthentication, SSHCFG_ALL) \
SSHCONF_UNSUPPORTED_INT(gss_cleanup_creds, GSSAPICleanupCredentials, SSHCFG_GLOBAL) \
SSHCONF_UNSUPPORTED_INT(gss_deleg_creds, GSSAPIDelegateCredentials, SSHCFG_GLOBAL) \
SSHCONF_UNSUPPORTED_INT(gss_strict_acceptor, GSSAPIStrictAcceptorCheck, SSHCFG_GLOBAL)
#endif /* GSSAPI */

#define SSHD_CONFIG_ENTRIES \
	SSHD_CONFIG_ENTRIES_BASE \
	SSHD_CONFIG_ENTRIES_KRB5 \
	SSHD_CONFIG_ENTRIES_GSS \

/* Macros to declare ServerOptions member variables */
#define SSHCONF_INT(var, conf, flags, ms, def, cp)	صحیح var;
#define SSHCONF_INTFLAG(var, conf, flags, def, cp)	صحیح var;
#define SSHCONF_STRING(var, conf, flags, cp)		نویسه *var;
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	\
	نویسه **var; \
	u_int nvar;
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	/* empty */
#define SSHCONF_NONCONF(funcsuffix)			/* empty */
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	صحیح var;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	نویسه *var;
#define SSHCONF_ALIAS(old, conf, flags)			/* empty */

تعریفنوع ساختار ServerOptions {
	SSHD_CONFIG_ENTRIES
	/* Ports */
	u_int	رقم_ports;
	u_int	ports_from_cmdline;
	صحیح	ports[MAX_PORTS];	/* Port number to listen on. */
	/* ListenAddress */
	ساختار queued_listenaddr *queued_listen_addrs;
	u_int	رقم_queued_listens;
	ساختار listenaddr *listen_addrs;
	u_int	رقم_listen_addrs;
	/* HostKey */
	نویسه   **host_کلید_files;	/* Files containing host keys. */
	صحیح	*host_کلید_file_userprovided; /* Key was specified by user. */
	u_int	رقم_host_کلید_files;     /* Number of files for host keys. */
	/* IPQoS */
	صحیح	ip_qos_interactive;	/* IP ToS/DSCP/class for interactive */
	صحیح	ip_qos_bulk;		/* IP ToS/DSCP/class for bulk traffic */
	/* GatewayPorts, StreamLocalBindMask, StreamLocalBindUnlink */
	ساختار ForwardOptions fwd_opts;	/* forwarding options */
	/* LogFacility */
	SyslogFacility log_facility;	/* Facility for system logging. */
	/* LogLevel */
	LogLevel log_level;	/* Level for system logging. */
	/* PermitUserEnvironment */
	صحیح     permit_user_env;	/* If true, read ~/.ssh/environment */
	نویسه   *permit_user_env_allowlist; /* pattern-list of allowed env names */
	/* Subsystem */
	u_int رقم_subsystems;
	نویسه   **subsystem_name;
	نویسه   **subsystem_command;
	نویسه   **subsystem_args;
	/* MaxStartups */
	صحیح	max_startups_begin;
	صحیح	max_startups_rate;
	صحیح	max_startups;
	/* PerSourceNetBlockSize */
	صحیح	per_source_masklen_ipv4;
	صحیح	per_source_masklen_ipv6;
	/* PerSourcePenalties */
	ساختار per_source_penalty per_source_penalty;
	/* RekeyLimit */
	int64_t rekey_limit;
	صحیح	rekey_interval;
	/* PubkeyAuthOptions */
	صحیح	pubkey_auth_options;
	صحیح	max_pubkey_ok;
	/* Passed by config but not keyword for this */
	uint64_t timing_secret;
}       ServerOptions;
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

/* Information about the incoming connection as used by Match */
ساختار connection_info {
	ثابت نویسه *user;
	صحیح user_invalid;
	ثابت نویسه *host;	/* possibly resolved hostname */
	ثابت نویسه *address;	/* remote address */
	ثابت نویسه *laddress;	/* local address */
	صحیح lport;		/* local port */
	ثابت نویسه *rdomain;	/* routing domain if available */
	صحیح test;		/* test mode, allow some attributes to be
				 * unspecified */
};

/* List of included files for re-exec from the parsed configuration */
ساختار include_item {
	نویسه *selector;
	نویسه *filename;
	ساختار sshbuf *contents;
	TAILQ_ENTRY(include_item) entry;
};
TAILQ_HEAD(include_list, include_item);

تهی	 initialize_server_options(ServerOptions *);
تهی	 fill_default_server_options(ServerOptions *);
صحیح	 process_server_config_سطر(ServerOptions *, نویسه *, ثابت نویسه *, صحیح,
	    صحیح *, ساختار connection_info *, ساختار include_list *includes);
تهی	 load_server_config(ثابت نویسه *, ساختار sshbuf *);
تهی	 parse_server_config(ServerOptions *, ثابت نویسه *, ساختار sshbuf *,
	    ساختار include_list *includes, ساختار connection_info *, صحیح);
تهی	 parse_server_match_config(ServerOptions *,
	    ساختار include_list *includes, ساختار connection_info *);
صحیح	 parse_server_match_testspec(ساختار connection_info *, نویسه *);
تهی	 servconf_merge_subsystems(ServerOptions *, ServerOptions *);
تهی	 copy_set_server_options(ServerOptions *, ServerOptions *, صحیح);
تهی	 dump_config(ServerOptions *);
نویسه	*derelativise_path(ثابت نویسه *);
تهی	 servconf_add_hostkey(ثابت نویسه *, ثابت صحیح,
	    ServerOptions *, ثابت نویسه *path, صحیح);
تهی	 servconf_add_hostcert(ثابت نویسه *, ثابت صحیح,
	    ServerOptions *, ثابت نویسه *path);

صحیح	 serialise_server_options(ثابت ServerOptions *, ساختار sshbuf **);
صحیح	 deserialise_server_options(ساختار sshbuf *, ServerOptions *);
تهی	 free_server_options(ServerOptions *);

#endif				/* SERVCONF_H */
