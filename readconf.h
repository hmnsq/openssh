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
#define PATH_MAX_SUN		(அளவு((கட்டமைப்பு sockaddr_un *)0)->sun_path)

கட்டமைப்பு allowed_cname {
	எழுத்து *source_list;
	எழுத்து *target_list;
};

வகைவரை கட்டமைப்பு {
	எழுத்து   *host_arg;	/* Host arg as specified on command line. */
	முழு     forward_agent;	/* Forward authentication agent. */
	எழுத்து   *forward_agent_sock_path; /* Optional path of the agent. */
	முழு     forward_x11;	/* Forward X11 display. */
	முழு     forward_x11_timeout;	/* Expiration for Cookies */
	முழு     forward_x11_trusted;	/* Trust Forward X11 display. */
	முழு     exit_on_forward_failure;	/* Exit if bind(2) fails for -L/-R */
	எழுத்து   *xauth_location;	/* Location for xauth program */
	கட்டமைப்பு ForwardOptions fwd_opts;	/* forwarding options */
	முழு     pubkey_authentication;	/* Try ssh2 pubkey authentication. */
	முழு     hostbased_authentication;	/* ssh2's rhosts_rsa */
	முழு     gss_authentication;	/* Try GSS authentication */
	முழு     gss_deleg_creds;	/* Delegate GSS credentials */
	முழு     password_authentication;	/* Try password
						 * authentication. */
	முழு     kbd_interactive_authentication; /* Try keyboard-interactive auth. */
	எழுத்து	*kbd_interactive_devices; /* Keyboard-interactive auth devices. */
	முழு     batch_mode;	/* Batch mode: do not ask for passwords. */
	முழு     check_host_ip;	/* Also keep track of keys for IP address */
	முழு     strict_host_சாவி_checking;	/* Strict host key checking. */
	முழு     compression;	/* Compress packets in both directions. */
	முழு     tcp_keep_alive;	/* Set SO_KEEPALIVE. */
	முழு	ip_qos_interactive;	/* DSCP value for interactive */
	முழு	ip_qos_bulk;		/* DSCP value for bulk traffic */
	SyslogFacility log_facility;	/* Facility for system logging. */
	LogLevel log_level;	/* Level for logging. */
	u_int	இலக்கம்_log_verbose;	/* Verbose log overrides */
	எழுத்து   **log_verbose;
	முழு     port;		/* Port to connect. */
	முழு     address_family;
	முழு     connection_attempts;	/* Max attempts (seconds) before
					 * giving up */
	முழு     connection_timeout;	/* Max time (seconds) before
					 * aborting connection attempt */
	முழு     எண்_of_password_prompts;	/* Max number of password
						 * prompts. */
	எழுத்து   *ciphers;	/* SSH2 ciphers in order of preference. */
	எழுத்து   *macs;		/* SSH2 macs in order of preference. */
	எழுத்து   *hostkeyalgorithms;	/* SSH2 server key types in order of preference. */
	எழுத்து   *kex_algorithms;	/* SSH2 kex methods in order of preference. */
	முழு	kex_algorithms_set; /* KexAlgorithms was set by the user */
	எழுத்து   *ca_sign_algorithms;	/* Allowed CA signature algorithms */
	எழுத்து   *hostname;	/* Real host to connect. */
	எழுத்து   *tag;		/* Configuration tag name. */
	எழுத்து   *host_சாவி_alias;	/* hostname alias for .ssh/known_hosts */
	எழுத்து   *proxy_command;	/* Proxy command for connecting the host. */
	எழுத்து   *user;		/* User to log in as. */
	முழு     escape_char;	/* Escape character; -2 = none */

	u_int	இலக்கம்_system_hostfiles;	/* Paths for /etc/ssh/ssh_known_hosts */
	எழுத்து   *system_hostfiles[SSH_MAX_HOSTS_FILES];
	u_int	இலக்கம்_user_hostfiles;	/* Path for $HOME/.ssh/known_hosts */
	எழுத்து   *user_hostfiles[SSH_MAX_HOSTS_FILES];
	எழுத்து   *preferred_authentications;
	எழுத்து   *bind_address;	/* local socket address for connection to sshd */
	எழுத்து   *bind_interface;	/* local interface for bind address */
	எழுத்து   *pkcs11_provider; /* PKCS#11 provider */
	எழுத்து   *sk_provider; /* Security key provider */
	முழு	verify_host_சாவி_dns;	/* Verify host key using DNS */

	முழு     இலக்கம்_identity_files;	/* Number of files for identities. */
	எழுத்து   *identity_files[SSH_MAX_IDENTITY_FILES];
	முழு    identity_file_userprovided[SSH_MAX_IDENTITY_FILES];
	கட்டமைப்பு sshkey *identity_சாவிகள்[SSH_MAX_IDENTITY_FILES];

	முழு	இலக்கம்_certificate_files; /* Number of extra certificates for ssh. */
	எழுத்து	*certificate_files[SSH_MAX_CERTIFICATE_FILES];
	முழு	certificate_file_userprovided[SSH_MAX_CERTIFICATE_FILES];
	கட்டமைப்பு sshkey *certificates[SSH_MAX_CERTIFICATE_FILES];

	முழு	add_சாவிகள்_to_agent;
	முழு	add_சாவிகள்_to_agent_lifespan;
	எழுத்து   *identity_agent;		/* Optional path to ssh-agent socket */

	/* Local TCP/IP forward requests. */
	முழு     இலக்கம்_local_forwards;
	கட்டமைப்பு Forward *local_forwards;

	/* Remote TCP/IP forward requests. */
	முழு     இலக்கம்_remote_forwards;
	கட்டமைப்பு Forward *remote_forwards;
	முழு	clear_forwardings;

	/* Restrict remote dynamic forwarding */
	எழுத்து  **permitted_remote_opens;
	u_int	இலக்கம்_permitted_remote_opens;

	/* stdio forwarding (-W) host and port */
	எழுத்து   *stdio_forward_host;
	முழு	stdio_forward_port;

	முழு	enable_ssh_keysign;
	int64_t rekey_limit;
	முழு	rekey_interval;
	முழு	no_host_authentication_for_localhost;
	முழு	identities_only;
	முழு	server_alive_interval;
	முழு	server_alive_மொத்தம்_max;

	u_int	இலக்கம்_send_env;
	எழுத்து	**send_env;
	u_int	இலக்கம்_setenv;
	எழுத்து	**setenv;

	எழுத்து	*control_path;
	முழு	control_master;
	முழு     control_persist; /* ControlPersist flag */
	முழு     control_persist_timeout; /* ControlPersist timeout (seconds) */

	முழு	hash_known_hosts;

	முழு	tun_open;	/* tun(4) */
	முழு     tun_local;	/* force tun device (optional) */
	முழு     tun_remote;	/* force tun device (optional) */

	எழுத்து	*local_command;
	முழு	permit_local_command;
	எழுத்து	*remote_command;
	முழு	visual_host_சாவி;

	முழு	request_tty;
	முழு	session_type;
	முழு	stdin_null;
	முழு	fork_after_authentication;

	முழு	proxy_use_fdpass;

	முழு	இலக்கம்_canonical_domains;
	எழுத்து	**canonical_domains;
	முழு	canonicalize_hostname;
	முழு	canonicalize_max_dots;
	முழு	canonicalize_fallback_local;
	முழு	இலக்கம்_permitted_cnames;
	கட்டமைப்பு allowed_cname *permitted_cnames;

	u_int	இலக்கம்_revoked_host_சாவிகள்;
	எழுத்து	**revoked_host_சாவிகள்;

	முழு	 fingerprint_hash;

	முழு	 update_hostkeys; /* one of SSH_UPDATE_HOSTKEYS_* */

	எழுத்து   *hostbased_accepted_algos;
	எழுத்து   *pubkey_accepted_algos;

	எழுத்து   *jump_user;
	எழுத்து   *jump_host;
	முழு	jump_port;
	எழுத்து   *jump_extra;

	எழுத்து   *known_hosts_command;

	முழு	required_rsa_size;	/* minimum size of RSA keys */
	முழு	enable_escape_commandline;	/* ~C commandline */
	முழு	obscure_keystroke_timing_interval;
	முழு	warn_weak_crypto;

	எழுத்து	**channel_timeouts;	/* inactivity timeout by channel type */
	u_int	இலக்கம்_channel_timeouts;

	எழுத்து	*version_addendum;

	எழுத்து	*ignored_unknown; /* Pattern list of unknown tokens to ignore */
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

மாறிலி எழுத்து *kex_default_pk_alg(வெறுமை);
எழுத்து	*ssh_connection_hash(மாறிலி எழுத்து *thishost, மாறிலி எழுத்து *host,
    மாறிலி எழுத்து *portstr, மாறிலி எழுத்து *user, மாறிலி எழுத்து *jump_host);
வெறுமை     initialize_options(Options *);
முழு      fill_default_options(Options *);
வெறுமை	 fill_default_options_for_canonicalization(Options *);
வெறுமை	 free_options(Options *o);
முழு	 process_config_வரி(Options *, கட்டமைப்பு passwd *, மாறிலி எழுத்து *,
    மாறிலி எழுத்து *, மாறிலி எழுத்து *, எழுத்து *, மாறிலி எழுத்து *, முழு, முழு *, முழு);
முழு	 read_config_file(மாறிலி எழுத்து *, கட்டமைப்பு passwd *, மாறிலி எழுத்து *,
    மாறிலி எழுத்து *, மாறிலி எழுத்து *, Options *, முழு, முழு *);
முழு	 parse_forward(கட்டமைப்பு Forward *, மாறிலி எழுத்து *, முழு, முழு);
முழு	 ssh_valid_hostname(மாறிலி எழுத்து *);
முழு	 ssh_valid_ruser(மாறிலி எழுத்து *);
முழு	 parse_jump(மாறிலி எழுத்து *, Options *, முழு, முழு);
முழு	 parse_ssh_uri(மாறிலி எழுத்து *, எழுத்து **, எழுத்து **, முழு *);
முழு	 default_ssh_port(வெறுமை);
முழு	 option_clear_or_none(மாறிலி எழுத்து *);
முழு	 config_has_permitted_cnames(Options *);
வெறுமை	 dump_client_config(Options *o, மாறிலி எழுத்து *host);

வெறுமை	 add_local_forward(Options *, மாறிலி கட்டமைப்பு Forward *);
வெறுமை	 add_remote_forward(Options *, மாறிலி கட்டமைப்பு Forward *);
வெறுமை	 add_identity_file(Options *, மாறிலி எழுத்து *, மாறிலி எழுத்து *, முழு);
வெறுமை	 add_certificate_file(Options *, மாறிலி எழுத்து *, முழு);

#endif				/* READCONF_H */
