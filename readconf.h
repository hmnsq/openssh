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
#define PATH_MAX_SUN		(আকার((কাঠামো sockaddr_un *)0)->sun_path)

কাঠামো allowed_cname {
	অক্ষর *source_list;
	অক্ষর *target_list;
};

প্রকারলেখ কাঠামো {
	অক্ষর   *host_arg;	/* Host arg as specified on command line. */
	পূর্ণসংখ্যা     forward_agent;	/* Forward authentication agent. */
	অক্ষর   *forward_agent_sock_path; /* Optional path of the agent. */
	পূর্ণসংখ্যা     forward_x11;	/* Forward X11 display. */
	পূর্ণসংখ্যা     forward_x11_timeout;	/* Expiration for Cookies */
	পূর্ণসংখ্যা     forward_x11_trusted;	/* Trust Forward X11 display. */
	পূর্ণসংখ্যা     exit_on_forward_failure;	/* Exit if bind(2) fails for -L/-R */
	অক্ষর   *xauth_location;	/* Location for xauth program */
	কাঠামো ForwardOptions fwd_opts;	/* forwarding options */
	পূর্ণসংখ্যা     pubkey_authentication;	/* Try ssh2 pubkey authentication. */
	পূর্ণসংখ্যা     hostbased_authentication;	/* ssh2's rhosts_rsa */
	পূর্ণসংখ্যা     gss_authentication;	/* Try GSS authentication */
	পূর্ণসংখ্যা     gss_deleg_creds;	/* Delegate GSS credentials */
	পূর্ণসংখ্যা     password_authentication;	/* Try password
						 * authentication. */
	পূর্ণসংখ্যা     kbd_interactive_authentication; /* Try keyboard-interactive auth. */
	অক্ষর	*kbd_interactive_devices; /* Keyboard-interactive auth devices. */
	পূর্ণসংখ্যা     batch_mode;	/* Batch mode: do not ask for passwords. */
	পূর্ণসংখ্যা     check_host_ip;	/* Also keep track of keys for IP address */
	পূর্ণসংখ্যা     strict_host_চাবি_checking;	/* Strict host key checking. */
	পূর্ণসংখ্যা     compression;	/* Compress packets in both directions. */
	পূর্ণসংখ্যা     tcp_keep_alive;	/* Set SO_KEEPALIVE. */
	পূর্ণসংখ্যা	ip_qos_interactive;	/* DSCP value for interactive */
	পূর্ণসংখ্যা	ip_qos_bulk;		/* DSCP value for bulk traffic */
	SyslogFacility log_facility;	/* Facility for system logging. */
	LogLevel log_level;	/* Level for logging. */
	u_int	অঙ্ক_log_verbose;	/* Verbose log overrides */
	অক্ষর   **log_verbose;
	পূর্ণসংখ্যা     port;		/* Port to connect. */
	পূর্ণসংখ্যা     address_family;
	পূর্ণসংখ্যা     connection_attempts;	/* Max attempts (seconds) before
					 * giving up */
	পূর্ণসংখ্যা     connection_timeout;	/* Max time (seconds) before
					 * aborting connection attempt */
	পূর্ণসংখ্যা     সংখ্যা_of_password_prompts;	/* Max number of password
						 * prompts. */
	অক্ষর   *ciphers;	/* SSH2 ciphers in order of preference. */
	অক্ষর   *macs;		/* SSH2 macs in order of preference. */
	অক্ষর   *hostkeyalgorithms;	/* SSH2 server key types in order of preference. */
	অক্ষর   *kex_algorithms;	/* SSH2 kex methods in order of preference. */
	পূর্ণসংখ্যা	kex_algorithms_set; /* KexAlgorithms was set by the user */
	অক্ষর   *ca_sign_algorithms;	/* Allowed CA signature algorithms */
	অক্ষর   *hostname;	/* Real host to connect. */
	অক্ষর   *tag;		/* Configuration tag name. */
	অক্ষর   *host_চাবি_alias;	/* hostname alias for .ssh/known_hosts */
	অক্ষর   *proxy_command;	/* Proxy command for connecting the host. */
	অক্ষর   *user;		/* User to log in as. */
	পূর্ণসংখ্যা     escape_char;	/* Escape character; -2 = none */

	u_int	অঙ্ক_system_hostfiles;	/* Paths for /etc/ssh/ssh_known_hosts */
	অক্ষর   *system_hostfiles[SSH_MAX_HOSTS_FILES];
	u_int	অঙ্ক_user_hostfiles;	/* Path for $HOME/.ssh/known_hosts */
	অক্ষর   *user_hostfiles[SSH_MAX_HOSTS_FILES];
	অক্ষর   *preferred_authentications;
	অক্ষর   *bind_address;	/* local socket address for connection to sshd */
	অক্ষর   *bind_interface;	/* local interface for bind address */
	অক্ষর   *pkcs11_provider; /* PKCS#11 provider */
	অক্ষর   *sk_provider; /* Security key provider */
	পূর্ণসংখ্যা	verify_host_চাবি_dns;	/* Verify host key using DNS */

	পূর্ণসংখ্যা     অঙ্ক_identity_files;	/* Number of files for identities. */
	অক্ষর   *identity_files[SSH_MAX_IDENTITY_FILES];
	পূর্ণসংখ্যা    identity_file_userprovided[SSH_MAX_IDENTITY_FILES];
	কাঠামো sshkey *identity_চাবিগুলি[SSH_MAX_IDENTITY_FILES];

	পূর্ণসংখ্যা	অঙ্ক_certificate_files; /* Number of extra certificates for ssh. */
	অক্ষর	*certificate_files[SSH_MAX_CERTIFICATE_FILES];
	পূর্ণসংখ্যা	certificate_file_userprovided[SSH_MAX_CERTIFICATE_FILES];
	কাঠামো sshkey *certificates[SSH_MAX_CERTIFICATE_FILES];

	পূর্ণসংখ্যা	add_চাবিগুলি_to_agent;
	পূর্ণসংখ্যা	add_চাবিগুলি_to_agent_lifespan;
	অক্ষর   *identity_agent;		/* Optional path to ssh-agent socket */

	/* Local TCP/IP forward requests. */
	পূর্ণসংখ্যা     অঙ্ক_local_forwards;
	কাঠামো Forward *local_forwards;

	/* Remote TCP/IP forward requests. */
	পূর্ণসংখ্যা     অঙ্ক_remote_forwards;
	কাঠামো Forward *remote_forwards;
	পূর্ণসংখ্যা	clear_forwardings;

	/* Restrict remote dynamic forwarding */
	অক্ষর  **permitted_remote_opens;
	u_int	অঙ্ক_permitted_remote_opens;

	/* stdio forwarding (-W) host and port */
	অক্ষর   *stdio_forward_host;
	পূর্ণসংখ্যা	stdio_forward_port;

	পূর্ণসংখ্যা	enable_ssh_keysign;
	int64_t rekey_limit;
	পূর্ণসংখ্যা	rekey_interval;
	পূর্ণসংখ্যা	no_host_authentication_for_localhost;
	পূর্ণসংখ্যা	identities_only;
	পূর্ণসংখ্যা	server_alive_interval;
	পূর্ণসংখ্যা	server_alive_গুনতি_max;

	u_int	অঙ্ক_send_env;
	অক্ষর	**send_env;
	u_int	অঙ্ক_setenv;
	অক্ষর	**setenv;

	অক্ষর	*control_path;
	পূর্ণসংখ্যা	control_master;
	পূর্ণসংখ্যা     control_persist; /* ControlPersist flag */
	পূর্ণসংখ্যা     control_persist_timeout; /* ControlPersist timeout (seconds) */

	পূর্ণসংখ্যা	hash_known_hosts;

	পূর্ণসংখ্যা	tun_open;	/* tun(4) */
	পূর্ণসংখ্যা     tun_local;	/* force tun device (optional) */
	পূর্ণসংখ্যা     tun_remote;	/* force tun device (optional) */

	অক্ষর	*local_command;
	পূর্ণসংখ্যা	permit_local_command;
	অক্ষর	*remote_command;
	পূর্ণসংখ্যা	visual_host_চাবি;

	পূর্ণসংখ্যা	request_tty;
	পূর্ণসংখ্যা	session_type;
	পূর্ণসংখ্যা	stdin_null;
	পূর্ণসংখ্যা	fork_after_authentication;

	পূর্ণসংখ্যা	proxy_use_fdpass;

	পূর্ণসংখ্যা	অঙ্ক_canonical_domains;
	অক্ষর	**canonical_domains;
	পূর্ণসংখ্যা	canonicalize_hostname;
	পূর্ণসংখ্যা	canonicalize_max_dots;
	পূর্ণসংখ্যা	canonicalize_fallback_local;
	পূর্ণসংখ্যা	অঙ্ক_permitted_cnames;
	কাঠামো allowed_cname *permitted_cnames;

	u_int	অঙ্ক_revoked_host_চাবিগুলি;
	অক্ষর	**revoked_host_চাবিগুলি;

	পূর্ণসংখ্যা	 fingerprint_hash;

	পূর্ণসংখ্যা	 update_hostkeys; /* one of SSH_UPDATE_HOSTKEYS_* */

	অক্ষর   *hostbased_accepted_algos;
	অক্ষর   *pubkey_accepted_algos;

	অক্ষর   *jump_user;
	অক্ষর   *jump_host;
	পূর্ণসংখ্যা	jump_port;
	অক্ষর   *jump_extra;

	অক্ষর   *known_hosts_command;

	পূর্ণসংখ্যা	required_rsa_আকার;	/* minimum size of RSA keys */
	পূর্ণসংখ্যা	enable_escape_commandline;	/* ~C commandline */
	পূর্ণসংখ্যা	obscure_keystroke_timing_interval;
	পূর্ণসংখ্যা	warn_weak_crypto;

	অক্ষর	**channel_timeouts;	/* inactivity timeout by channel type */
	u_int	অঙ্ক_channel_timeouts;

	অক্ষর	*version_addendum;

	অক্ষর	*ignored_unknown; /* Pattern list of unknown tokens to ignore */
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

ধ্রুবক অক্ষর *kex_default_pk_alg(শূন্য);
অক্ষর	*ssh_connection_hash(ধ্রুবক অক্ষর *thishost, ধ্রুবক অক্ষর *host,
    ধ্রুবক অক্ষর *portstr, ধ্রুবক অক্ষর *user, ধ্রুবক অক্ষর *jump_host);
শূন্য     initialize_options(Options *);
পূর্ণসংখ্যা      fill_default_options(Options *);
শূন্য	 fill_default_options_for_canonicalization(Options *);
শূন্য	 free_options(Options *o);
পূর্ণসংখ্যা	 process_config_সারি(Options *, কাঠামো passwd *, ধ্রুবক অক্ষর *,
    ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, অক্ষর *, ধ্রুবক অক্ষর *, পূর্ণসংখ্যা, পূর্ণসংখ্যা *, পূর্ণসংখ্যা);
পূর্ণসংখ্যা	 read_config_file(ধ্রুবক অক্ষর *, কাঠামো passwd *, ধ্রুবক অক্ষর *,
    ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, Options *, পূর্ণসংখ্যা, পূর্ণসংখ্যা *);
পূর্ণসংখ্যা	 parse_forward(কাঠামো Forward *, ধ্রুবক অক্ষর *, পূর্ণসংখ্যা, পূর্ণসংখ্যা);
পূর্ণসংখ্যা	 ssh_valid_hostname(ধ্রুবক অক্ষর *);
পূর্ণসংখ্যা	 ssh_valid_ruser(ধ্রুবক অক্ষর *);
পূর্ণসংখ্যা	 parse_jump(ধ্রুবক অক্ষর *, Options *, পূর্ণসংখ্যা, পূর্ণসংখ্যা);
পূর্ণসংখ্যা	 parse_ssh_uri(ধ্রুবক অক্ষর *, অক্ষর **, অক্ষর **, পূর্ণসংখ্যা *);
পূর্ণসংখ্যা	 default_ssh_port(শূন্য);
পূর্ণসংখ্যা	 option_clear_or_none(ধ্রুবক অক্ষর *);
পূর্ণসংখ্যা	 config_has_permitted_cnames(Options *);
শূন্য	 dump_client_config(Options *o, ধ্রুবক অক্ষর *host);

শূন্য	 add_local_forward(Options *, ধ্রুবক কাঠামো Forward *);
শূন্য	 add_remote_forward(Options *, ধ্রুবক কাঠামো Forward *);
শূন্য	 add_identity_file(Options *, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, পূর্ণসংখ্যা);
শূন্য	 add_certificate_file(Options *, ধ্রুবক অক্ষর *, পূর্ণসংখ্যা);

#endif				/* READCONF_H */
