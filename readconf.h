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
#define PATH_MAX_SUN		(اندازه((ساختار sockaddr_un *)0)->sun_path)

ساختار allowed_cname {
	نویسه *source_list;
	نویسه *target_list;
};

تعریفنوع ساختار {
	نویسه   *host_arg;	/* Host arg as specified on command line. */
	صحیح     forward_agent;	/* Forward authentication agent. */
	نویسه   *forward_agent_sock_path; /* Optional path of the agent. */
	صحیح     forward_x11;	/* Forward X11 display. */
	صحیح     forward_x11_timeout;	/* Expiration for Cookies */
	صحیح     forward_x11_trusted;	/* Trust Forward X11 display. */
	صحیح     exit_on_forward_failure;	/* Exit if bind(2) fails for -L/-R */
	نویسه   *xauth_location;	/* Location for xauth program */
	ساختار ForwardOptions fwd_opts;	/* forwarding options */
	صحیح     pubkey_authentication;	/* Try ssh2 pubkey authentication. */
	صحیح     hostbased_authentication;	/* ssh2's rhosts_rsa */
	صحیح     gss_authentication;	/* Try GSS authentication */
	صحیح     gss_deleg_creds;	/* Delegate GSS credentials */
	صحیح     password_authentication;	/* Try password
						 * authentication. */
	صحیح     kbd_interactive_authentication; /* Try keyboard-interactive auth. */
	نویسه	*kbd_interactive_devices; /* Keyboard-interactive auth devices. */
	صحیح     batch_mode;	/* Batch mode: do not ask for passwords. */
	صحیح     check_host_ip;	/* Also keep track of keys for IP address */
	صحیح     strict_host_کلید_checking;	/* Strict host key checking. */
	صحیح     compression;	/* Compress packets in both directions. */
	صحیح     tcp_keep_alive;	/* Set SO_KEEPALIVE. */
	صحیح	ip_qos_interactive;	/* DSCP value for interactive */
	صحیح	ip_qos_bulk;		/* DSCP value for bulk traffic */
	SyslogFacility log_facility;	/* Facility for system logging. */
	LogLevel log_level;	/* Level for logging. */
	u_int	رقم_log_verbose;	/* Verbose log overrides */
	نویسه   **log_verbose;
	صحیح     port;		/* Port to connect. */
	صحیح     address_family;
	صحیح     connection_attempts;	/* Max attempts (seconds) before
					 * giving up */
	صحیح     connection_timeout;	/* Max time (seconds) before
					 * aborting connection attempt */
	صحیح     عدد_of_password_prompts;	/* Max number of password
						 * prompts. */
	نویسه   *ciphers;	/* SSH2 ciphers in order of preference. */
	نویسه   *macs;		/* SSH2 macs in order of preference. */
	نویسه   *hostkeyalgorithms;	/* SSH2 server key types in order of preference. */
	نویسه   *kex_algorithms;	/* SSH2 kex methods in order of preference. */
	صحیح	kex_algorithms_set; /* KexAlgorithms was set by the user */
	نویسه   *ca_sign_algorithms;	/* Allowed CA signature algorithms */
	نویسه   *hostname;	/* Real host to connect. */
	نویسه   *tag;		/* Configuration tag name. */
	نویسه   *host_کلید_alias;	/* hostname alias for .ssh/known_hosts */
	نویسه   *proxy_command;	/* Proxy command for connecting the host. */
	نویسه   *user;		/* User to log in as. */
	صحیح     escape_char;	/* Escape character; -2 = none */

	u_int	رقم_system_hostfiles;	/* Paths for /etc/ssh/ssh_known_hosts */
	نویسه   *system_hostfiles[SSH_MAX_HOSTS_FILES];
	u_int	رقم_user_hostfiles;	/* Path for $HOME/.ssh/known_hosts */
	نویسه   *user_hostfiles[SSH_MAX_HOSTS_FILES];
	نویسه   *preferred_authentications;
	نویسه   *bind_address;	/* local socket address for connection to sshd */
	نویسه   *bind_interface;	/* local interface for bind address */
	نویسه   *pkcs11_provider; /* PKCS#11 provider */
	نویسه   *sk_provider; /* Security key provider */
	صحیح	verify_host_کلید_dns;	/* Verify host key using DNS */

	صحیح     رقم_identity_files;	/* Number of files for identities. */
	نویسه   *identity_files[SSH_MAX_IDENTITY_FILES];
	صحیح    identity_file_userprovided[SSH_MAX_IDENTITY_FILES];
	ساختار sshkey *identity_کلیدها[SSH_MAX_IDENTITY_FILES];

	صحیح	رقم_certificate_files; /* Number of extra certificates for ssh. */
	نویسه	*certificate_files[SSH_MAX_CERTIFICATE_FILES];
	صحیح	certificate_file_userprovided[SSH_MAX_CERTIFICATE_FILES];
	ساختار sshkey *certificates[SSH_MAX_CERTIFICATE_FILES];

	صحیح	add_کلیدها_to_agent;
	صحیح	add_کلیدها_to_agent_lifespan;
	نویسه   *identity_agent;		/* Optional path to ssh-agent socket */

	/* Local TCP/IP forward requests. */
	صحیح     رقم_local_forwards;
	ساختار Forward *local_forwards;

	/* Remote TCP/IP forward requests. */
	صحیح     رقم_remote_forwards;
	ساختار Forward *remote_forwards;
	صحیح	clear_forwardings;

	/* Restrict remote dynamic forwarding */
	نویسه  **permitted_remote_opens;
	u_int	رقم_permitted_remote_opens;

	/* stdio forwarding (-W) host and port */
	نویسه   *stdio_forward_host;
	صحیح	stdio_forward_port;

	صحیح	enable_ssh_keysign;
	int64_t rekey_limit;
	صحیح	rekey_interval;
	صحیح	no_host_authentication_for_localhost;
	صحیح	identities_only;
	صحیح	server_alive_interval;
	صحیح	server_alive_شمار_max;

	u_int	رقم_send_env;
	نویسه	**send_env;
	u_int	رقم_setenv;
	نویسه	**setenv;

	نویسه	*control_path;
	صحیح	control_master;
	صحیح     control_persist; /* ControlPersist flag */
	صحیح     control_persist_timeout; /* ControlPersist timeout (seconds) */

	صحیح	hash_known_hosts;

	صحیح	tun_open;	/* tun(4) */
	صحیح     tun_local;	/* force tun device (optional) */
	صحیح     tun_remote;	/* force tun device (optional) */

	نویسه	*local_command;
	صحیح	permit_local_command;
	نویسه	*remote_command;
	صحیح	visual_host_کلید;

	صحیح	request_tty;
	صحیح	session_type;
	صحیح	stdin_null;
	صحیح	fork_after_authentication;

	صحیح	proxy_use_fdpass;

	صحیح	رقم_canonical_domains;
	نویسه	**canonical_domains;
	صحیح	canonicalize_hostname;
	صحیح	canonicalize_max_dots;
	صحیح	canonicalize_fallback_local;
	صحیح	رقم_permitted_cnames;
	ساختار allowed_cname *permitted_cnames;

	u_int	رقم_revoked_host_کلیدها;
	نویسه	**revoked_host_کلیدها;

	صحیح	 fingerprint_hash;

	صحیح	 update_hostkeys; /* one of SSH_UPDATE_HOSTKEYS_* */

	نویسه   *hostbased_accepted_algos;
	نویسه   *pubkey_accepted_algos;

	نویسه   *jump_user;
	نویسه   *jump_host;
	صحیح	jump_port;
	نویسه   *jump_extra;

	نویسه   *known_hosts_command;

	صحیح	required_rsa_size;	/* minimum size of RSA keys */
	صحیح	enable_escape_commandline;	/* ~C commandline */
	صحیح	obscure_keystroke_timing_interval;
	صحیح	warn_weak_crypto;

	نویسه	**channel_timeouts;	/* inactivity timeout by channel type */
	u_int	رقم_channel_timeouts;

	نویسه	*version_addendum;

	نویسه	*ignored_unknown; /* Pattern list of unknown tokens to ignore */
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

ثابت نویسه *kex_default_pk_alg(تهی);
نویسه	*ssh_connection_hash(ثابت نویسه *thishost, ثابت نویسه *host,
    ثابت نویسه *portstr, ثابت نویسه *user, ثابت نویسه *jump_host);
تهی     initialize_options(Options *);
صحیح      fill_default_options(Options *);
تهی	 fill_default_options_for_canonicalization(Options *);
تهی	 free_options(Options *o);
صحیح	 process_config_سطر(Options *, ساختار passwd *, ثابت نویسه *,
    ثابت نویسه *, ثابت نویسه *, نویسه *, ثابت نویسه *, صحیح, صحیح *, صحیح);
صحیح	 read_config_file(ثابت نویسه *, ساختار passwd *, ثابت نویسه *,
    ثابت نویسه *, ثابت نویسه *, Options *, صحیح, صحیح *);
صحیح	 parse_forward(ساختار Forward *, ثابت نویسه *, صحیح, صحیح);
صحیح	 ssh_valid_hostname(ثابت نویسه *);
صحیح	 ssh_valid_ruser(ثابت نویسه *);
صحیح	 parse_jump(ثابت نویسه *, Options *, صحیح, صحیح);
صحیح	 parse_ssh_uri(ثابت نویسه *, نویسه **, نویسه **, صحیح *);
صحیح	 default_ssh_port(تهی);
صحیح	 option_clear_or_none(ثابت نویسه *);
صحیح	 config_has_permitted_cnames(Options *);
تهی	 dump_client_config(Options *o, ثابت نویسه *host);

تهی	 add_local_forward(Options *, ثابت ساختار Forward *);
تهی	 add_remote_forward(Options *, ثابت ساختار Forward *);
تهی	 add_identity_file(Options *, ثابت نویسه *, ثابت نویسه *, صحیح);
تهی	 add_certificate_file(Options *, ثابت نویسه *, صحیح);

#endif				/* READCONF_H */
