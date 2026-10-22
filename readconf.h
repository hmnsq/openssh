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
#define PATH_MAX_SUN		(ಪರಿಮಾಣ((ಸಂರಚನಾ sockaddr_un *)0)->sun_path)

ಸಂರಚನಾ allowed_cname {
	ವರ್ಣ *source_list;
	ವರ್ಣ *target_list;
};

ಪ್ರಕಾರನಿರ್ದೇಶ ಸಂರಚನಾ {
	ವರ್ಣ   *host_arg;	/* Host arg as specified on command line. */
	ಪೂರ್ಣಾಙ್ಕ     forward_agent;	/* Forward authentication agent. */
	ವರ್ಣ   *forward_agent_sock_path; /* Optional path of the agent. */
	ಪೂರ್ಣಾಙ್ಕ     forward_x11;	/* Forward X11 display. */
	ಪೂರ್ಣಾಙ್ಕ     forward_x11_timeout;	/* Expiration for Cookies */
	ಪೂರ್ಣಾಙ್ಕ     forward_x11_trusted;	/* Trust Forward X11 display. */
	ಪೂರ್ಣಾಙ್ಕ     exit_on_forward_failure;	/* Exit if bind(2) fails for -L/-R */
	ವರ್ಣ   *xauth_location;	/* Location for xauth program */
	ಸಂರಚನಾ ForwardOptions fwd_opts;	/* forwarding options */
	ಪೂರ್ಣಾಙ್ಕ     pubkey_authentication;	/* Try ssh2 pubkey authentication. */
	ಪೂರ್ಣಾಙ್ಕ     hostbased_authentication;	/* ssh2's rhosts_rsa */
	ಪೂರ್ಣಾಙ್ಕ     gss_authentication;	/* Try GSS authentication */
	ಪೂರ್ಣಾಙ್ಕ     gss_deleg_creds;	/* Delegate GSS credentials */
	ಪೂರ್ಣಾಙ್ಕ     password_authentication;	/* Try password
						 * authentication. */
	ಪೂರ್ಣಾಙ್ಕ     kbd_interactive_authentication; /* Try keyboard-interactive auth. */
	ವರ್ಣ	*kbd_interactive_devices; /* Keyboard-interactive auth devices. */
	ಪೂರ್ಣಾಙ್ಕ     batch_mode;	/* Batch mode: do not ask for passwords. */
	ಪೂರ್ಣಾಙ್ಕ     check_host_ip;	/* Also keep track of keys for IP address */
	ಪೂರ್ಣಾಙ್ಕ     strict_host_ಕೀಲಿ_checking;	/* Strict host key checking. */
	ಪೂರ್ಣಾಙ್ಕ     compression;	/* Compress packets in both directions. */
	ಪೂರ್ಣಾಙ್ಕ     tcp_keep_alive;	/* Set SO_KEEPALIVE. */
	ಪೂರ್ಣಾಙ್ಕ	ip_qos_interactive;	/* DSCP value for interactive */
	ಪೂರ್ಣಾಙ್ಕ	ip_qos_bulk;		/* DSCP value for bulk traffic */
	SyslogFacility log_facility;	/* Facility for system logging. */
	LogLevel log_level;	/* Level for logging. */
	u_int	ಅಂಕೆ_log_verbose;	/* Verbose log overrides */
	ವರ್ಣ   **log_verbose;
	ಪೂರ್ಣಾಙ್ಕ     port;		/* Port to connect. */
	ಪೂರ್ಣಾಙ್ಕ     address_family;
	ಪೂರ್ಣಾಙ್ಕ     connection_attempts;	/* Max attempts (seconds) before
					 * giving up */
	ಪೂರ್ಣಾಙ್ಕ     connection_timeout;	/* Max time (seconds) before
					 * aborting connection attempt */
	ಪೂರ್ಣಾಙ್ಕ     ಸಂಖ್ಯೆ_of_password_prompts;	/* Max number of password
						 * prompts. */
	ವರ್ಣ   *ciphers;	/* SSH2 ciphers in order of preference. */
	ವರ್ಣ   *macs;		/* SSH2 macs in order of preference. */
	ವರ್ಣ   *hostkeyalgorithms;	/* SSH2 server key types in order of preference. */
	ವರ್ಣ   *kex_algorithms;	/* SSH2 kex methods in order of preference. */
	ಪೂರ್ಣಾಙ್ಕ	kex_algorithms_set; /* KexAlgorithms was set by the user */
	ವರ್ಣ   *ca_sign_algorithms;	/* Allowed CA signature algorithms */
	ವರ್ಣ   *hostname;	/* Real host to connect. */
	ವರ್ಣ   *tag;		/* Configuration tag name. */
	ವರ್ಣ   *host_ಕೀಲಿ_alias;	/* hostname alias for .ssh/known_hosts */
	ವರ್ಣ   *proxy_command;	/* Proxy command for connecting the host. */
	ವರ್ಣ   *user;		/* User to log in as. */
	ಪೂರ್ಣಾಙ್ಕ     escape_char;	/* Escape character; -2 = none */

	u_int	ಅಂಕೆ_system_hostfiles;	/* Paths for /etc/ssh/ssh_known_hosts */
	ವರ್ಣ   *system_hostfiles[SSH_MAX_HOSTS_FILES];
	u_int	ಅಂಕೆ_user_hostfiles;	/* Path for $HOME/.ssh/known_hosts */
	ವರ್ಣ   *user_hostfiles[SSH_MAX_HOSTS_FILES];
	ವರ್ಣ   *preferred_authentications;
	ವರ್ಣ   *bind_address;	/* local socket address for connection to sshd */
	ವರ್ಣ   *bind_interface;	/* local interface for bind address */
	ವರ್ಣ   *pkcs11_provider; /* PKCS#11 provider */
	ವರ್ಣ   *sk_provider; /* Security key provider */
	ಪೂರ್ಣಾಙ್ಕ	verify_host_ಕೀಲಿ_dns;	/* Verify host key using DNS */

	ಪೂರ್ಣಾಙ್ಕ     ಅಂಕೆ_identity_files;	/* Number of files for identities. */
	ವರ್ಣ   *identity_files[SSH_MAX_IDENTITY_FILES];
	ಪೂರ್ಣಾಙ್ಕ    identity_file_userprovided[SSH_MAX_IDENTITY_FILES];
	ಸಂರಚನಾ sshkey *identity_ಕೀಲಿಗಳು[SSH_MAX_IDENTITY_FILES];

	ಪೂರ್ಣಾಙ್ಕ	ಅಂಕೆ_certificate_files; /* Number of extra certificates for ssh. */
	ವರ್ಣ	*certificate_files[SSH_MAX_CERTIFICATE_FILES];
	ಪೂರ್ಣಾಙ್ಕ	certificate_file_userprovided[SSH_MAX_CERTIFICATE_FILES];
	ಸಂರಚನಾ sshkey *certificates[SSH_MAX_CERTIFICATE_FILES];

	ಪೂರ್ಣಾಙ್ಕ	add_ಕೀಲಿಗಳು_to_agent;
	ಪೂರ್ಣಾಙ್ಕ	add_ಕೀಲಿಗಳು_to_agent_lifespan;
	ವರ್ಣ   *identity_agent;		/* Optional path to ssh-agent socket */

	/* Local TCP/IP forward requests. */
	ಪೂರ್ಣಾಙ್ಕ     ಅಂಕೆ_local_forwards;
	ಸಂರಚನಾ Forward *local_forwards;

	/* Remote TCP/IP forward requests. */
	ಪೂರ್ಣಾಙ್ಕ     ಅಂಕೆ_remote_forwards;
	ಸಂರಚನಾ Forward *remote_forwards;
	ಪೂರ್ಣಾಙ್ಕ	clear_forwardings;

	/* Restrict remote dynamic forwarding */
	ವರ್ಣ  **permitted_remote_opens;
	u_int	ಅಂಕೆ_permitted_remote_opens;

	/* stdio forwarding (-W) host and port */
	ವರ್ಣ   *stdio_forward_host;
	ಪೂರ್ಣಾಙ್ಕ	stdio_forward_port;

	ಪೂರ್ಣಾಙ್ಕ	enable_ssh_keysign;
	int64_t rekey_limit;
	ಪೂರ್ಣಾಙ್ಕ	rekey_interval;
	ಪೂರ್ಣಾಙ್ಕ	no_host_authentication_for_localhost;
	ಪೂರ್ಣಾಙ್ಕ	identities_only;
	ಪೂರ್ಣಾಙ್ಕ	server_alive_interval;
	ಪೂರ್ಣಾಙ್ಕ	server_alive_ಎಣಿಕೆ_max;

	u_int	ಅಂಕೆ_send_env;
	ವರ್ಣ	**send_env;
	u_int	ಅಂಕೆ_setenv;
	ವರ್ಣ	**setenv;

	ವರ್ಣ	*control_path;
	ಪೂರ್ಣಾಙ್ಕ	control_master;
	ಪೂರ್ಣಾಙ್ಕ     control_persist; /* ControlPersist flag */
	ಪೂರ್ಣಾಙ್ಕ     control_persist_timeout; /* ControlPersist timeout (seconds) */

	ಪೂರ್ಣಾಙ್ಕ	hash_known_hosts;

	ಪೂರ್ಣಾಙ್ಕ	tun_open;	/* tun(4) */
	ಪೂರ್ಣಾಙ್ಕ     tun_local;	/* force tun device (optional) */
	ಪೂರ್ಣಾಙ್ಕ     tun_remote;	/* force tun device (optional) */

	ವರ್ಣ	*local_command;
	ಪೂರ್ಣಾಙ್ಕ	permit_local_command;
	ವರ್ಣ	*remote_command;
	ಪೂರ್ಣಾಙ್ಕ	visual_host_ಕೀಲಿ;

	ಪೂರ್ಣಾಙ್ಕ	request_tty;
	ಪೂರ್ಣಾಙ್ಕ	session_type;
	ಪೂರ್ಣಾಙ್ಕ	stdin_null;
	ಪೂರ್ಣಾಙ್ಕ	fork_after_authentication;

	ಪೂರ್ಣಾಙ್ಕ	proxy_use_fdpass;

	ಪೂರ್ಣಾಙ್ಕ	ಅಂಕೆ_canonical_domains;
	ವರ್ಣ	**canonical_domains;
	ಪೂರ್ಣಾಙ್ಕ	canonicalize_hostname;
	ಪೂರ್ಣಾಙ್ಕ	canonicalize_max_dots;
	ಪೂರ್ಣಾಙ್ಕ	canonicalize_fallback_local;
	ಪೂರ್ಣಾಙ್ಕ	ಅಂಕೆ_permitted_cnames;
	ಸಂರಚನಾ allowed_cname *permitted_cnames;

	u_int	ಅಂಕೆ_revoked_host_ಕೀಲಿಗಳು;
	ವರ್ಣ	**revoked_host_ಕೀಲಿಗಳು;

	ಪೂರ್ಣಾಙ್ಕ	 fingerprint_hash;

	ಪೂರ್ಣಾಙ್ಕ	 update_hostkeys; /* one of SSH_UPDATE_HOSTKEYS_* */

	ವರ್ಣ   *hostbased_accepted_algos;
	ವರ್ಣ   *pubkey_accepted_algos;

	ವರ್ಣ   *jump_user;
	ವರ್ಣ   *jump_host;
	ಪೂರ್ಣಾಙ್ಕ	jump_port;
	ವರ್ಣ   *jump_extra;

	ವರ್ಣ   *known_hosts_command;

	ಪೂರ್ಣಾಙ್ಕ	required_rsa_size;	/* minimum size of RSA keys */
	ಪೂರ್ಣಾಙ್ಕ	enable_escape_commandline;	/* ~C commandline */
	ಪೂರ್ಣಾಙ್ಕ	obscure_keystroke_timing_interval;
	ಪೂರ್ಣಾಙ್ಕ	warn_weak_crypto;

	ವರ್ಣ	**channel_timeouts;	/* inactivity timeout by channel type */
	u_int	ಅಂಕೆ_channel_timeouts;

	ವರ್ಣ	*version_addendum;

	ವರ್ಣ	*ignored_unknown; /* Pattern list of unknown tokens to ignore */
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

ಧ್ರುವ ವರ್ಣ *kex_default_pk_alg(ಶೂನ್ಯ);
ವರ್ಣ	*ssh_connection_hash(ಧ್ರುವ ವರ್ಣ *thishost, ಧ್ರುವ ವರ್ಣ *host,
    ಧ್ರುವ ವರ್ಣ *portstr, ಧ್ರುವ ವರ್ಣ *user, ಧ್ರುವ ವರ್ಣ *jump_host);
ಶೂನ್ಯ     initialize_options(Options *);
ಪೂರ್ಣಾಙ್ಕ      fill_default_options(Options *);
ಶೂನ್ಯ	 fill_default_options_for_canonicalization(Options *);
ಶೂನ್ಯ	 free_options(Options *o);
ಪೂರ್ಣಾಙ್ಕ	 process_config_ಸಾಲು(Options *, ಸಂರಚನಾ passwd *, ಧ್ರುವ ವರ್ಣ *,
    ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ *, ಪೂರ್ಣಾಙ್ಕ);
ಪೂರ್ಣಾಙ್ಕ	 read_config_file(ಧ್ರುವ ವರ್ಣ *, ಸಂರಚನಾ passwd *, ಧ್ರುವ ವರ್ಣ *,
    ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, Options *, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ *);
ಪೂರ್ಣಾಙ್ಕ	 parse_forward(ಸಂರಚನಾ Forward *, ಧ್ರುವ ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ);
ಪೂರ್ಣಾಙ್ಕ	 ssh_valid_hostname(ಧ್ರುವ ವರ್ಣ *);
ಪೂರ್ಣಾಙ್ಕ	 ssh_valid_ruser(ಧ್ರುವ ವರ್ಣ *);
ಪೂರ್ಣಾಙ್ಕ	 parse_jump(ಧ್ರುವ ವರ್ಣ *, Options *, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ);
ಪೂರ್ಣಾಙ್ಕ	 parse_ssh_uri(ಧ್ರುವ ವರ್ಣ *, ವರ್ಣ **, ವರ್ಣ **, ಪೂರ್ಣಾಙ್ಕ *);
ಪೂರ್ಣಾಙ್ಕ	 default_ssh_port(ಶೂನ್ಯ);
ಪೂರ್ಣಾಙ್ಕ	 option_clear_or_none(ಧ್ರುವ ವರ್ಣ *);
ಪೂರ್ಣಾಙ್ಕ	 config_has_permitted_cnames(Options *);
ಶೂನ್ಯ	 dump_client_config(Options *o, ಧ್ರುವ ವರ್ಣ *host);

ಶೂನ್ಯ	 add_local_forward(Options *, ಧ್ರುವ ಸಂರಚನಾ Forward *);
ಶೂನ್ಯ	 add_remote_forward(Options *, ಧ್ರುವ ಸಂರಚನಾ Forward *);
ಶೂನ್ಯ	 add_identity_file(Options *, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ);
ಶೂನ್ಯ	 add_certificate_file(Options *, ಧ್ರುವ ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ);

#endif				/* READCONF_H */
