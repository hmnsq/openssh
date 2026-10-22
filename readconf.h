/* $OpenBSD: readconf.h,v 1.164 2026/09/16 00:13:58 djm Exp $ */

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Functions for reading the configuration file.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#ifndef READCONF_H
#define READCONF_H

/* Data structure for representing option data. */

#define SSH_MAX_HOSTS_FILES	32
#define PATH_MAX_SUN		(വലുപ്പം((ഘടന sockaddr_un *)0)->sun_path)

ഘടന allowed_cname {
	അക്ഷരം *source_list;
	അക്ഷരം *target_list;
};

തരനിർവചനം ഘടന {
	അക്ഷരം   *host_arg;	/* Host arg as specified on command line. */
	പൂർണ്ണസംഖ്യ     forward_agent;	/* Forward authentication agent. */
	അക്ഷരം   *forward_agent_sock_path; /* Optional path of the agent. */
	പൂർണ്ണസംഖ്യ     forward_x11;	/* Forward X11 display. */
	പൂർണ്ണസംഖ്യ     forward_x11_timeout;	/* Expiration for Cookies */
	പൂർണ്ണസംഖ്യ     forward_x11_trusted;	/* Trust Forward X11 display. */
	പൂർണ്ണസംഖ്യ     exit_on_forward_failure;	/* Exit if bind(2) fails for -L/-R */
	അക്ഷരം   *xauth_location;	/* Location for xauth program */
	ഘടന ForwardOptions fwd_opts;	/* forwarding options */
	പൂർണ്ണസംഖ്യ     pubkey_authentication;	/* Try ssh2 pubkey authentication. */
	പൂർണ്ണസംഖ്യ     hostbased_authentication;	/* ssh2's rhosts_rsa */
	പൂർണ്ണസംഖ്യ     gss_authentication;	/* Try GSS authentication */
	പൂർണ്ണസംഖ്യ     gss_deleg_creds;	/* Delegate GSS credentials */
	പൂർണ്ണസംഖ്യ     password_authentication;	/* Try password
						 * authentication. */
	പൂർണ്ണസംഖ്യ     kbd_interactive_authentication; /* Try keyboard-interactive auth. */
	അക്ഷരം	*kbd_interactive_devices; /* Keyboard-interactive auth devices. */
	പൂർണ്ണസംഖ്യ     batch_mode;	/* Batch mode: do not ask for passwords. */
	പൂർണ്ണസംഖ്യ     check_host_ip;	/* Also keep track of keys for IP address */
	പൂർണ്ണസംഖ്യ     strict_host_താക്കോൽ_checking;	/* Strict host key checking. */
	പൂർണ്ണസംഖ്യ     compression;	/* Compress packets in both directions. */
	പൂർണ്ണസംഖ്യ     tcp_keep_alive;	/* Set SO_KEEPALIVE. */
	പൂർണ്ണസംഖ്യ	ip_qos_interactive;	/* DSCP value for interactive */
	പൂർണ്ണസംഖ്യ	ip_qos_bulk;		/* DSCP value for bulk traffic */
	SyslogFacility log_facility;	/* Facility for system logging. */
	LogLevel log_level;	/* Level for logging. */
	u_int	അക്കം_log_verbose;	/* Verbose log overrides */
	അക്ഷരം   **log_verbose;
	പൂർണ്ണസംഖ്യ     port;		/* Port to connect. */
	പൂർണ്ണസംഖ്യ     address_family;
	പൂർണ്ണസംഖ്യ     connection_attempts;	/* Max attempts (seconds) before
					 * giving up */
	പൂർണ്ണസംഖ്യ     connection_timeout;	/* Max time (seconds) before
					 * aborting connection attempt */
	പൂർണ്ണസംഖ്യ     സംഖ്യ_of_password_prompts;	/* Max number of password
						 * prompts. */
	അക്ഷരം   *ciphers;	/* SSH2 ciphers in order of preference. */
	അക്ഷരം   *macs;		/* SSH2 macs in order of preference. */
	അക്ഷരം   *hostkeyalgorithms;	/* SSH2 server key types in order of preference. */
	അക്ഷരം   *kex_algorithms;	/* SSH2 kex methods in order of preference. */
	പൂർണ്ണസംഖ്യ	kex_algorithms_set; /* KexAlgorithms was set by the user */
	അക്ഷരം   *ca_sign_algorithms;	/* Allowed CA signature algorithms */
	അക്ഷരം   *hostname;	/* Real host to connect. */
	അക്ഷരം   *tag;		/* Configuration tag name. */
	അക്ഷരം   *host_താക്കോൽ_alias;	/* hostname alias for .ssh/known_hosts */
	അക്ഷരം   *proxy_command;	/* Proxy command for connecting the host. */
	അക്ഷരം   *user;		/* User to log in as. */
	പൂർണ്ണസംഖ്യ     escape_char;	/* Escape character; -2 = none */

	u_int	അക്കം_system_hostfiles;	/* Paths for /etc/ssh/ssh_known_hosts */
	അക്ഷരം   *system_hostfiles[SSH_MAX_HOSTS_FILES];
	u_int	അക്കം_user_hostfiles;	/* Path for $HOME/.ssh/known_hosts */
	അക്ഷരം   *user_hostfiles[SSH_MAX_HOSTS_FILES];
	അക്ഷരം   *preferred_authentications;
	അക്ഷരം   *bind_address;	/* local socket address for connection to sshd */
	അക്ഷരം   *bind_interface;	/* local interface for bind address */
	അക്ഷരം   *pkcs11_provider; /* PKCS#11 provider */
	അക്ഷരം   *sk_provider; /* Security key provider */
	പൂർണ്ണസംഖ്യ	verify_host_താക്കോൽ_dns;	/* Verify host key using DNS */

	പൂർണ്ണസംഖ്യ     അക്കം_identity_files;	/* Number of files for identities. */
	അക്ഷരം   *identity_files[SSH_MAX_IDENTITY_FILES];
	പൂർണ്ണസംഖ്യ    identity_file_userprovided[SSH_MAX_IDENTITY_FILES];
	ഘടന sshkey *identity_താക്കോലുകൾ[SSH_MAX_IDENTITY_FILES];

	പൂർണ്ണസംഖ്യ	അക്കം_certificate_files; /* Number of extra certificates for ssh. */
	അക്ഷരം	*certificate_files[SSH_MAX_CERTIFICATE_FILES];
	പൂർണ്ണസംഖ്യ	certificate_file_userprovided[SSH_MAX_CERTIFICATE_FILES];
	ഘടന sshkey *certificates[SSH_MAX_CERTIFICATE_FILES];

	പൂർണ്ണസംഖ്യ	add_താക്കോലുകൾ_to_agent;
	പൂർണ്ണസംഖ്യ	add_താക്കോലുകൾ_to_agent_lifespan;
	അക്ഷരം   *identity_agent;		/* Optional path to ssh-agent socket */

	/* Local TCP/IP forward requests. */
	പൂർണ്ണസംഖ്യ     അക്കം_local_forwards;
	ഘടന Forward *local_forwards;

	/* Remote TCP/IP forward requests. */
	പൂർണ്ണസംഖ്യ     അക്കം_remote_forwards;
	ഘടന Forward *remote_forwards;
	പൂർണ്ണസംഖ്യ	clear_forwardings;

	/* Restrict remote dynamic forwarding */
	അക്ഷരം  **permitted_remote_opens;
	u_int	അക്കം_permitted_remote_opens;

	/* stdio forwarding (-W) host and port */
	അക്ഷരം   *stdio_forward_host;
	പൂർണ്ണസംഖ്യ	stdio_forward_port;

	പൂർണ്ണസംഖ്യ	enable_ssh_keysign;
	int64_t rekey_limit;
	പൂർണ്ണസംഖ്യ	rekey_interval;
	പൂർണ്ണസംഖ്യ	no_host_authentication_for_localhost;
	പൂർണ്ണസംഖ്യ	identities_only;
	പൂർണ്ണസംഖ്യ	server_alive_interval;
	പൂർണ്ണസംഖ്യ	server_alive_എണ്ണം_max;

	u_int	അക്കം_send_env;
	അക്ഷരം	**send_env;
	u_int	അക്കം_setenv;
	അക്ഷരം	**setenv;

	അക്ഷരം	*control_path;
	പൂർണ്ണസംഖ്യ	control_master;
	പൂർണ്ണസംഖ്യ     control_persist; /* ControlPersist flag */
	പൂർണ്ണസംഖ്യ     control_persist_timeout; /* ControlPersist timeout (seconds) */

	പൂർണ്ണസംഖ്യ	hash_known_hosts;

	പൂർണ്ണസംഖ്യ	tun_open;	/* tun(4) */
	പൂർണ്ണസംഖ്യ     tun_local;	/* force tun device (optional) */
	പൂർണ്ണസംഖ്യ     tun_remote;	/* force tun device (optional) */

	അക്ഷരം	*local_command;
	പൂർണ്ണസംഖ്യ	permit_local_command;
	അക്ഷരം	*remote_command;
	പൂർണ്ണസംഖ്യ	visual_host_താക്കോൽ;

	പൂർണ്ണസംഖ്യ	request_tty;
	പൂർണ്ണസംഖ്യ	session_type;
	പൂർണ്ണസംഖ്യ	stdin_null;
	പൂർണ്ണസംഖ്യ	fork_after_authentication;

	പൂർണ്ണസംഖ്യ	proxy_use_fdpass;

	പൂർണ്ണസംഖ്യ	അക്കം_canonical_domains;
	അക്ഷരം	**canonical_domains;
	പൂർണ്ണസംഖ്യ	canonicalize_hostname;
	പൂർണ്ണസംഖ്യ	canonicalize_max_dots;
	പൂർണ്ണസംഖ്യ	canonicalize_fallback_local;
	പൂർണ്ണസംഖ്യ	അക്കം_permitted_cnames;
	ഘടന allowed_cname *permitted_cnames;

	u_int	അക്കം_revoked_host_താക്കോലുകൾ;
	അക്ഷരം	**revoked_host_താക്കോലുകൾ;

	പൂർണ്ണസംഖ്യ	 fingerprint_hash;

	പൂർണ്ണസംഖ്യ	 update_hostkeys; /* one of SSH_UPDATE_HOSTKEYS_* */

	അക്ഷരം   *hostbased_accepted_algos;
	അക്ഷരം   *pubkey_accepted_algos;

	അക്ഷരം   *jump_user;
	അക്ഷരം   *jump_host;
	പൂർണ്ണസംഖ്യ	jump_port;
	അക്ഷരം   *jump_extra;

	അക്ഷരം   *known_hosts_command;

	പൂർണ്ണസംഖ്യ	required_rsa_size;	/* minimum size of RSA keys */
	പൂർണ്ണസംഖ്യ	enable_escape_commandline;	/* ~C commandline */
	പൂർണ്ണസംഖ്യ	obscure_keystroke_timing_interval;
	പൂർണ്ണസംഖ്യ	warn_weak_crypto;

	അക്ഷരം	**channel_timeouts;	/* inactivity timeout by channel type */
	u_int	അക്കം_channel_timeouts;

	അക്ഷരം	*version_addendum;

	അക്ഷരം	*ignored_unknown; /* Pattern list of unknown tokens to ignore */
}       Options;

#define SSH_PUBKEY_AUTH_NO	0x00
#define SSH_PUBKEY_AUTH_UNBOUND	0x01
#define SSH_PUBKEY_AUTH_HBOUND	0x02
#define SSH_PUBKEY_AUTH_ALL	0x03

#define SSH_CANONICALISE_NO	0
#define SSH_CANONICALISE_YES	1
#define SSH_CANONICALISE_ALWAYS	2

#define SSHCTL_MASTER_NO	0
#define SSHCTL_MASTER_YES	1
#define SSHCTL_MASTER_AUTO	2
#define SSHCTL_MASTER_ASK	3
#define SSHCTL_MASTER_AUTO_ASK	4

#define REQUEST_TTY_AUTO	0
#define REQUEST_TTY_NO		1
#define REQUEST_TTY_YES		2
#define REQUEST_TTY_FORCE	3

#define SESSION_TYPE_NONE	0
#define SESSION_TYPE_SUBSYSTEM	1
#define SESSION_TYPE_DEFAULT	2

#define SSHCONF_CHECKPERM	1  /* check permissions on config file */
#define SSHCONF_USERCONF	2  /* user provided config file not system */
#define SSHCONF_FINAL		4  /* Final pass over config, after canon. */
#define SSHCONF_NEVERMATCH	8  /* Match/Host never matches; internal only */

#define SSH_UPDATE_HOSTKEYS_NO	0
#define SSH_UPDATE_HOSTKEYS_YES	1
#define SSH_UPDATE_HOSTKEYS_ASK	2

#define SSH_STRICT_HOSTKEY_OFF	0
#define SSH_STRICT_HOSTKEY_NEW	1
#define SSH_STRICT_HOSTKEY_YES	2
#define SSH_STRICT_HOSTKEY_ASK	3

/* ObscureKeystrokes parameters */
#define SSH_KEYSTROKE_DEFAULT_INTERVAL_MS	20
#define SSH_KEYSTROKE_CHAFF_MIN_MS		1024
#define SSH_KEYSTROKE_CHAFF_RNG_MS		2048

#define SSH_KEEPALIVES_OFF		0
#define SSH_KEEPALIVES_TRANSPORT	1
#define SSH_KEEPALIVES_ALL		2

സ്ഥിരം അക്ഷരം *kex_default_pk_alg(ശൂന്യം);
അക്ഷരം	*ssh_connection_hash(സ്ഥിരം അക്ഷരം *thishost, സ്ഥിരം അക്ഷരം *host,
    സ്ഥിരം അക്ഷരം *portstr, സ്ഥിരം അക്ഷരം *user, സ്ഥിരം അക്ഷരം *jump_host);
ശൂന്യം     initialize_options(Options *);
പൂർണ്ണസംഖ്യ      fill_default_options(Options *);
ശൂന്യം	 fill_default_options_for_canonicalization(Options *);
ശൂന്യം	 free_options(Options *o);
പൂർണ്ണസംഖ്യ	 process_config_വരി(Options *, ഘടന passwd *, സ്ഥിരം അക്ഷരം *,
    സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, അക്ഷരം *, സ്ഥിരം അക്ഷരം *, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ *, പൂർണ്ണസംഖ്യ);
പൂർണ്ണസംഖ്യ	 read_config_file(സ്ഥിരം അക്ഷരം *, ഘടന passwd *, സ്ഥിരം അക്ഷരം *,
    സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, Options *, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ *);
പൂർണ്ണസംഖ്യ	 parse_forward(ഘടന Forward *, സ്ഥിരം അക്ഷരം *, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ);
പൂർണ്ണസംഖ്യ	 ssh_valid_hostname(സ്ഥിരം അക്ഷരം *);
പൂർണ്ണസംഖ്യ	 ssh_valid_ruser(സ്ഥിരം അക്ഷരം *);
പൂർണ്ണസംഖ്യ	 parse_jump(സ്ഥിരം അക്ഷരം *, Options *, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ);
പൂർണ്ണസംഖ്യ	 parse_ssh_uri(സ്ഥിരം അക്ഷരം *, അക്ഷരം **, അക്ഷരം **, പൂർണ്ണസംഖ്യ *);
പൂർണ്ണസംഖ്യ	 default_ssh_port(ശൂന്യം);
പൂർണ്ണസംഖ്യ	 option_clear_or_none(സ്ഥിരം അക്ഷരം *);
പൂർണ്ണസംഖ്യ	 config_has_permitted_cnames(Options *);
ശൂന്യം	 dump_client_config(Options *o, സ്ഥിരം അക്ഷരം *host);

ശൂന്യം	 add_local_forward(Options *, സ്ഥിരം ഘടന Forward *);
ശൂന്യം	 add_remote_forward(Options *, സ്ഥിരം ഘടന Forward *);
ശൂന്യം	 add_identity_file(Options *, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, പൂർണ്ണസംഖ്യ);
ശൂന്യം	 add_certificate_file(Options *, സ്ഥിരം അക്ഷരം *, പൂർണ്ണസംഖ്യ);

#endif				/* READCONF_H */
