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
#define PATH_MAX_SUN		(পরিমাণ((সংরচনা sockaddr_un *)0)->sun_path)

সংরচনা allowed_cname {
	ৱর্ণ *source_list;
	ৱর্ণ *target_list;
};

প্রকারনির্দেশ সংরচনা {
	ৱর্ণ   *host_arg;	/* Host arg as specified on command line. */
	পূর্ণাঙ্ক     forward_agent;	/* Forward authentication agent. */
	ৱর্ণ   *forward_agent_sock_path; /* Optional path of the agent. */
	পূর্ণাঙ্ক     forward_x11;	/* Forward X11 display. */
	পূর্ণাঙ্ক     forward_x11_timeout;	/* Expiration for Cookies */
	পূর্ণাঙ্ক     forward_x11_trusted;	/* Trust Forward X11 display. */
	পূর্ণাঙ্ক     exit_on_forward_failure;	/* Exit if bind(2) fails for -L/-R */
	ৱর্ণ   *xauth_location;	/* Location for xauth program */
	সংরচনা ForwardOptions fwd_opts;	/* forwarding options */
	পূর্ণাঙ্ক     pubkey_authentication;	/* Try ssh2 pubkey authentication. */
	পূর্ণাঙ্ক     hostbased_authentication;	/* ssh2's rhosts_rsa */
	পূর্ণাঙ্ক     gss_authentication;	/* Try GSS authentication */
	পূর্ণাঙ্ক     gss_deleg_creds;	/* Delegate GSS credentials */
	পূর্ণাঙ্ক     password_authentication;	/* Try password
						 * authentication. */
	পূর্ণাঙ্ক     kbd_interactive_authentication; /* Try keyboard-interactive auth. */
	ৱর্ণ	*kbd_interactive_devices; /* Keyboard-interactive auth devices. */
	পূর্ণাঙ্ক     batch_mode;	/* Batch mode: do not ask for passwords. */
	পূর্ণাঙ্ক     check_host_ip;	/* Also keep track of keys for IP address */
	পূর্ণাঙ্ক     strict_host_চাবি_checking;	/* Strict host key checking. */
	পূর্ণাঙ্ক     compression;	/* Compress packets in both directions. */
	পূর্ণাঙ্ক     tcp_keep_alive;	/* Set SO_KEEPALIVE. */
	পূর্ণাঙ্ক	ip_qos_interactive;	/* DSCP value for interactive */
	পূর্ণাঙ্ক	ip_qos_bulk;		/* DSCP value for bulk traffic */
	SyslogFacility log_facility;	/* Facility for system logging. */
	LogLevel log_level;	/* Level for logging. */
	u_int	অঙ্ক_log_verbose;	/* Verbose log overrides */
	ৱর্ণ   **log_verbose;
	পূর্ণাঙ্ক     port;		/* Port to connect. */
	পূর্ণাঙ্ক     address_family;
	পূর্ণাঙ্ক     connection_attempts;	/* Max attempts (seconds) before
					 * giving up */
	পূর্ণাঙ্ক     connection_timeout;	/* Max time (seconds) before
					 * aborting connection attempt */
	পূর্ণাঙ্ক     সংখ্যা_of_password_prompts;	/* Max number of password
						 * prompts. */
	ৱর্ণ   *ciphers;	/* SSH2 ciphers in order of preference. */
	ৱর্ণ   *macs;		/* SSH2 macs in order of preference. */
	ৱর্ণ   *hostkeyalgorithms;	/* SSH2 server key types in order of preference. */
	ৱর্ণ   *kex_algorithms;	/* SSH2 kex methods in order of preference. */
	পূর্ণাঙ্ক	kex_algorithms_set; /* KexAlgorithms was set by the user */
	ৱর্ণ   *ca_sign_algorithms;	/* Allowed CA signature algorithms */
	ৱর্ণ   *hostname;	/* Real host to connect. */
	ৱর্ণ   *tag;		/* Configuration tag name. */
	ৱর্ণ   *host_চাবি_alias;	/* hostname alias for .ssh/known_hosts */
	ৱর্ণ   *proxy_command;	/* Proxy command for connecting the host. */
	ৱর্ণ   *user;		/* User to log in as. */
	পূর্ণাঙ্ক     escape_char;	/* Escape character; -2 = none */

	u_int	অঙ্ক_system_hostfiles;	/* Paths for /etc/ssh/ssh_known_hosts */
	ৱর্ণ   *system_hostfiles[SSH_MAX_HOSTS_FILES];
	u_int	অঙ্ক_user_hostfiles;	/* Path for $HOME/.ssh/known_hosts */
	ৱর্ণ   *user_hostfiles[SSH_MAX_HOSTS_FILES];
	ৱর্ণ   *preferred_authentications;
	ৱর্ণ   *bind_address;	/* local socket address for connection to sshd */
	ৱর্ণ   *bind_interface;	/* local interface for bind address */
	ৱর্ণ   *pkcs11_provider; /* PKCS#11 provider */
	ৱর্ণ   *sk_provider; /* Security key provider */
	পূর্ণাঙ্ক	verify_host_চাবি_dns;	/* Verify host key using DNS */

	পূর্ণাঙ্ক     অঙ্ক_identity_files;	/* Number of files for identities. */
	ৱর্ণ   *identity_files[SSH_MAX_IDENTITY_FILES];
	পূর্ণাঙ্ক    identity_file_userprovided[SSH_MAX_IDENTITY_FILES];
	সংরচনা sshkey *identity_চাবিগুলি[SSH_MAX_IDENTITY_FILES];

	পূর্ণাঙ্ক	অঙ্ক_certificate_files; /* Number of extra certificates for ssh. */
	ৱর্ণ	*certificate_files[SSH_MAX_CERTIFICATE_FILES];
	পূর্ণাঙ্ক	certificate_file_userprovided[SSH_MAX_CERTIFICATE_FILES];
	সংরচনা sshkey *certificates[SSH_MAX_CERTIFICATE_FILES];

	পূর্ণাঙ্ক	add_চাবিগুলি_to_agent;
	পূর্ণাঙ্ক	add_চাবিগুলি_to_agent_lifespan;
	ৱর্ণ   *identity_agent;		/* Optional path to ssh-agent socket */

	/* Local TCP/IP forward requests. */
	পূর্ণাঙ্ক     অঙ্ক_local_forwards;
	সংরচনা Forward *local_forwards;

	/* Remote TCP/IP forward requests. */
	পূর্ণাঙ্ক     অঙ্ক_remote_forwards;
	সংরচনা Forward *remote_forwards;
	পূর্ণাঙ্ক	clear_forwardings;

	/* Restrict remote dynamic forwarding */
	ৱর্ণ  **permitted_remote_opens;
	u_int	অঙ্ক_permitted_remote_opens;

	/* stdio forwarding (-W) host and port */
	ৱর্ণ   *stdio_forward_host;
	পূর্ণাঙ্ক	stdio_forward_port;

	পূর্ণাঙ্ক	enable_ssh_keysign;
	int64_t rekey_limit;
	পূর্ণাঙ্ক	rekey_interval;
	পূর্ণাঙ্ক	no_host_authentication_for_localhost;
	পূর্ণাঙ্ক	identities_only;
	পূর্ণাঙ্ক	server_alive_interval;
	পূর্ণাঙ্ক	server_alive_গুনতি_max;

	u_int	অঙ্ক_send_env;
	ৱর্ণ	**send_env;
	u_int	অঙ্ক_setenv;
	ৱর্ণ	**setenv;

	ৱর্ণ	*control_path;
	পূর্ণাঙ্ক	control_master;
	পূর্ণাঙ্ক     control_persist; /* ControlPersist flag */
	পূর্ণাঙ্ক     control_persist_timeout; /* ControlPersist timeout (seconds) */

	পূর্ণাঙ্ক	hash_known_hosts;

	পূর্ণাঙ্ক	tun_open;	/* tun(4) */
	পূর্ণাঙ্ক     tun_local;	/* force tun device (optional) */
	পূর্ণাঙ্ক     tun_remote;	/* force tun device (optional) */

	ৱর্ণ	*local_command;
	পূর্ণাঙ্ক	permit_local_command;
	ৱর্ণ	*remote_command;
	পূর্ণাঙ্ক	visual_host_চাবি;

	পূর্ণাঙ্ক	request_tty;
	পূর্ণাঙ্ক	session_type;
	পূর্ণাঙ্ক	stdin_null;
	পূর্ণাঙ্ক	fork_after_authentication;

	পূর্ণাঙ্ক	proxy_use_fdpass;

	পূর্ণাঙ্ক	অঙ্ক_canonical_domains;
	ৱর্ণ	**canonical_domains;
	পূর্ণাঙ্ক	canonicalize_hostname;
	পূর্ণাঙ্ক	canonicalize_max_dots;
	পূর্ণাঙ্ক	canonicalize_fallback_local;
	পূর্ণাঙ্ক	অঙ্ক_permitted_cnames;
	সংরচনা allowed_cname *permitted_cnames;

	u_int	অঙ্ক_revoked_host_চাবিগুলি;
	ৱর্ণ	**revoked_host_চাবিগুলি;

	পূর্ণাঙ্ক	 fingerprint_hash;

	পূর্ণাঙ্ক	 update_hostkeys; /* one of SSH_UPDATE_HOSTKEYS_* */

	ৱর্ণ   *hostbased_accepted_algos;
	ৱর্ণ   *pubkey_accepted_algos;

	ৱর্ণ   *jump_user;
	ৱর্ণ   *jump_host;
	পূর্ণাঙ্ক	jump_port;
	ৱর্ণ   *jump_extra;

	ৱর্ণ   *known_hosts_command;

	পূর্ণাঙ্ক	required_rsa_size;	/* minimum size of RSA keys */
	পূর্ণাঙ্ক	enable_escape_commandline;	/* ~C commandline */
	পূর্ণাঙ্ক	obscure_keystroke_timing_interval;
	পূর্ণাঙ্ক	warn_weak_crypto;

	ৱর্ণ	**channel_timeouts;	/* inactivity timeout by channel type */
	u_int	অঙ্ক_channel_timeouts;

	ৱর্ণ	*version_addendum;

	ৱর্ণ	*ignored_unknown; /* Pattern list of unknown tokens to ignore */
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

ধ্রুৱ ৱর্ণ *kex_default_pk_alg(শূন্য);
ৱর্ণ	*ssh_connection_hash(ধ্রুৱ ৱর্ণ *thishost, ধ্রুৱ ৱর্ণ *host,
    ধ্রুৱ ৱর্ণ *portstr, ধ্রুৱ ৱর্ণ *user, ধ্রুৱ ৱর্ণ *jump_host);
শূন্য     initialize_options(Options *);
পূর্ণাঙ্ক      fill_default_options(Options *);
শূন্য	 fill_default_options_for_canonicalization(Options *);
শূন্য	 free_options(Options *o);
পূর্ণাঙ্ক	 process_config_সাৰি(Options *, সংরচনা passwd *, ধ্রুৱ ৱর্ণ *,
    ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *, ৱর্ণ *, ধ্রুৱ ৱর্ণ *, পূর্ণাঙ্ক, পূর্ণাঙ্ক *, পূর্ণাঙ্ক);
পূর্ণাঙ্ক	 read_config_file(ধ্রুৱ ৱর্ণ *, সংরচনা passwd *, ধ্রুৱ ৱর্ণ *,
    ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *, Options *, পূর্ণাঙ্ক, পূর্ণাঙ্ক *);
পূর্ণাঙ্ক	 parse_forward(সংরচনা Forward *, ধ্রুৱ ৱর্ণ *, পূর্ণাঙ্ক, পূর্ণাঙ্ক);
পূর্ণাঙ্ক	 ssh_valid_hostname(ধ্রুৱ ৱর্ণ *);
পূর্ণাঙ্ক	 ssh_valid_ruser(ধ্রুৱ ৱর্ণ *);
পূর্ণাঙ্ক	 parse_jump(ধ্রুৱ ৱর্ণ *, Options *, পূর্ণাঙ্ক, পূর্ণাঙ্ক);
পূর্ণাঙ্ক	 parse_ssh_uri(ধ্রুৱ ৱর্ণ *, ৱর্ণ **, ৱর্ণ **, পূর্ণাঙ্ক *);
পূর্ণাঙ্ক	 default_ssh_port(শূন্য);
পূর্ণাঙ্ক	 option_clear_or_none(ধ্রুৱ ৱর্ণ *);
পূর্ণাঙ্ক	 config_has_permitted_cnames(Options *);
শূন্য	 dump_client_config(Options *o, ধ্রুৱ ৱর্ণ *host);

শূন্য	 add_local_forward(Options *, ধ্রুৱ সংরচনা Forward *);
শূন্য	 add_remote_forward(Options *, ধ্রুৱ সংরচনা Forward *);
শূন্য	 add_identity_file(Options *, ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *, পূর্ণাঙ্ক);
শূন্য	 add_certificate_file(Options *, ধ্রুৱ ৱর্ণ *, পূর্ণাঙ্ক);

#endif				/* READCONF_H */
