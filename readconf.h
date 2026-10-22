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
#define PATH_MAX_SUN		(કદ((સંરચના sockaddr_un *)0)->sun_path)

સંરચના allowed_cname {
	અક્ષર *source_list;
	અક્ષર *target_list;
};

પ્રકારવ્યાખ્યા સંરચના {
	અક્ષર   *host_arg;	/* Host arg as specified on command line. */
	પૂર્ણાંક     forward_agent;	/* Forward authentication agent. */
	અક્ષર   *forward_agent_sock_path; /* Optional path of the agent. */
	પૂર્ણાંક     forward_x11;	/* Forward X11 display. */
	પૂર્ણાંક     forward_x11_timeout;	/* Expiration for Cookies */
	પૂર્ણાંક     forward_x11_trusted;	/* Trust Forward X11 display. */
	પૂર્ણાંક     exit_on_forward_failure;	/* Exit if bind(2) fails for -L/-R */
	અક્ષર   *xauth_location;	/* Location for xauth program */
	સંરચના ForwardOptions fwd_opts;	/* forwarding options */
	પૂર્ણાંક     pubkey_authentication;	/* Try ssh2 pubkey authentication. */
	પૂર્ણાંક     hostbased_authentication;	/* ssh2's rhosts_rsa */
	પૂર્ણાંક     gss_authentication;	/* Try GSS authentication */
	પૂર્ણાંક     gss_deleg_creds;	/* Delegate GSS credentials */
	પૂર્ણાંક     password_authentication;	/* Try password
						 * authentication. */
	પૂર્ણાંક     kbd_interactive_authentication; /* Try keyboard-interactive auth. */
	અક્ષર	*kbd_interactive_devices; /* Keyboard-interactive auth devices. */
	પૂર્ણાંક     batch_mode;	/* Batch mode: do not ask for passwords. */
	પૂર્ણાંક     check_host_ip;	/* Also keep track of keys for IP address */
	પૂર્ણાંક     strict_host_ચાવી_checking;	/* Strict host key checking. */
	પૂર્ણાંક     compression;	/* Compress packets in both directions. */
	પૂર્ણાંક     tcp_keep_alive;	/* Set SO_KEEPALIVE. */
	પૂર્ણાંક	ip_qos_interactive;	/* DSCP value for interactive */
	પૂર્ણાંક	ip_qos_bulk;		/* DSCP value for bulk traffic */
	SyslogFacility log_facility;	/* Facility for system logging. */
	LogLevel log_level;	/* Level for logging. */
	u_int	અંક_log_verbose;	/* Verbose log overrides */
	અક્ષર   **log_verbose;
	પૂર્ણાંક     port;		/* Port to connect. */
	પૂર્ણાંક     address_family;
	પૂર્ણાંક     connection_attempts;	/* Max attempts (seconds) before
					 * giving up */
	પૂર્ણાંક     connection_timeout;	/* Max time (seconds) before
					 * aborting connection attempt */
	પૂર્ણાંક     સંખ્યા_of_password_prompts;	/* Max number of password
						 * prompts. */
	અક્ષર   *ciphers;	/* SSH2 ciphers in order of preference. */
	અક્ષર   *macs;		/* SSH2 macs in order of preference. */
	અક્ષર   *hostkeyalgorithms;	/* SSH2 server key types in order of preference. */
	અક્ષર   *kex_algorithms;	/* SSH2 kex methods in order of preference. */
	પૂર્ણાંક	kex_algorithms_set; /* KexAlgorithms was set by the user */
	અક્ષર   *ca_sign_algorithms;	/* Allowed CA signature algorithms */
	અક્ષર   *hostname;	/* Real host to connect. */
	અક્ષર   *tag;		/* Configuration tag name. */
	અક્ષર   *host_ચાવી_alias;	/* hostname alias for .ssh/known_hosts */
	અક્ષર   *proxy_command;	/* Proxy command for connecting the host. */
	અક્ષર   *user;		/* User to log in as. */
	પૂર્ણાંક     escape_char;	/* Escape character; -2 = none */

	u_int	અંક_system_hostfiles;	/* Paths for /etc/ssh/ssh_known_hosts */
	અક્ષર   *system_hostfiles[SSH_MAX_HOSTS_FILES];
	u_int	અંક_user_hostfiles;	/* Path for $HOME/.ssh/known_hosts */
	અક્ષર   *user_hostfiles[SSH_MAX_HOSTS_FILES];
	અક્ષર   *preferred_authentications;
	અક્ષર   *bind_address;	/* local socket address for connection to sshd */
	અક્ષર   *bind_interface;	/* local interface for bind address */
	અક્ષર   *pkcs11_provider; /* PKCS#11 provider */
	અક્ષર   *sk_provider; /* Security key provider */
	પૂર્ણાંક	verify_host_ચાવી_dns;	/* Verify host key using DNS */

	પૂર્ણાંક     અંક_identity_files;	/* Number of files for identities. */
	અક્ષર   *identity_files[SSH_MAX_IDENTITY_FILES];
	પૂર્ણાંક    identity_file_userprovided[SSH_MAX_IDENTITY_FILES];
	સંરચના sshkey *identity_ચાવીઓ[SSH_MAX_IDENTITY_FILES];

	પૂર્ણાંક	અંક_certificate_files; /* Number of extra certificates for ssh. */
	અક્ષર	*certificate_files[SSH_MAX_CERTIFICATE_FILES];
	પૂર્ણાંક	certificate_file_userprovided[SSH_MAX_CERTIFICATE_FILES];
	સંરચના sshkey *certificates[SSH_MAX_CERTIFICATE_FILES];

	પૂર્ણાંક	add_ચાવીઓ_to_agent;
	પૂર્ણાંક	add_ચાવીઓ_to_agent_lifespan;
	અક્ષર   *identity_agent;		/* Optional path to ssh-agent socket */

	/* Local TCP/IP forward requests. */
	પૂર્ણાંક     અંક_local_forwards;
	સંરચના Forward *local_forwards;

	/* Remote TCP/IP forward requests. */
	પૂર્ણાંક     અંક_remote_forwards;
	સંરચના Forward *remote_forwards;
	પૂર્ણાંક	clear_forwardings;

	/* Restrict remote dynamic forwarding */
	અક્ષર  **permitted_remote_opens;
	u_int	અંક_permitted_remote_opens;

	/* stdio forwarding (-W) host and port */
	અક્ષર   *stdio_forward_host;
	પૂર્ણાંક	stdio_forward_port;

	પૂર્ણાંક	enable_ssh_keysign;
	int64_t rekey_limit;
	પૂર્ણાંક	rekey_interval;
	પૂર્ણાંક	no_host_authentication_for_localhost;
	પૂર્ણાંક	identities_only;
	પૂર્ણાંક	server_alive_interval;
	પૂર્ણાંક	server_alive_ગણતરી_max;

	u_int	અંક_send_env;
	અક્ષર	**send_env;
	u_int	અંક_setenv;
	અક્ષર	**setenv;

	અક્ષર	*control_path;
	પૂર્ણાંક	control_master;
	પૂર્ણાંક     control_persist; /* ControlPersist flag */
	પૂર્ણાંક     control_persist_timeout; /* ControlPersist timeout (seconds) */

	પૂર્ણાંક	hash_known_hosts;

	પૂર્ણાંક	tun_open;	/* tun(4) */
	પૂર્ણાંક     tun_local;	/* force tun device (optional) */
	પૂર્ણાંક     tun_remote;	/* force tun device (optional) */

	અક્ષર	*local_command;
	પૂર્ણાંક	permit_local_command;
	અક્ષર	*remote_command;
	પૂર્ણાંક	visual_host_ચાવી;

	પૂર્ણાંક	request_tty;
	પૂર્ણાંક	session_type;
	પૂર્ણાંક	stdin_null;
	પૂર્ણાંક	fork_after_authentication;

	પૂર્ણાંક	proxy_use_fdpass;

	પૂર્ણાંક	અંક_canonical_domains;
	અક્ષર	**canonical_domains;
	પૂર્ણાંક	canonicalize_hostname;
	પૂર્ણાંક	canonicalize_max_dots;
	પૂર્ણાંક	canonicalize_fallback_local;
	પૂર્ણાંક	અંક_permitted_cnames;
	સંરચના allowed_cname *permitted_cnames;

	u_int	અંક_revoked_host_ચાવીઓ;
	અક્ષર	**revoked_host_ચાવીઓ;

	પૂર્ણાંક	 fingerprint_hash;

	પૂર્ણાંક	 update_hostkeys; /* one of SSH_UPDATE_HOSTKEYS_* */

	અક્ષર   *hostbased_accepted_algos;
	અક્ષર   *pubkey_accepted_algos;

	અક્ષર   *jump_user;
	અક્ષર   *jump_host;
	પૂર્ણાંક	jump_port;
	અક્ષર   *jump_extra;

	અક્ષર   *known_hosts_command;

	પૂર્ણાંક	required_rsa_size;	/* minimum size of RSA keys */
	પૂર્ણાંક	enable_escape_commandline;	/* ~C commandline */
	પૂર્ણાંક	obscure_keystroke_timing_interval;
	પૂર્ણાંક	warn_weak_crypto;

	અક્ષર	**channel_timeouts;	/* inactivity timeout by channel type */
	u_int	અંક_channel_timeouts;

	અક્ષર	*version_addendum;

	અક્ષર	*ignored_unknown; /* Pattern list of unknown tokens to ignore */
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

અચલ અક્ષર *kex_default_pk_alg(શૂન્ય);
અક્ષર	*ssh_connection_hash(અચલ અક્ષર *thishost, અચલ અક્ષર *host,
    અચલ અક્ષર *portstr, અચલ અક્ષર *user, અચલ અક્ષર *jump_host);
શૂન્ય     initialize_options(Options *);
પૂર્ણાંક      fill_default_options(Options *);
શૂન્ય	 fill_default_options_for_canonicalization(Options *);
શૂન્ય	 free_options(Options *o);
પૂર્ણાંક	 process_config_લીટી(Options *, સંરચના passwd *, અચલ અક્ષર *,
    અચલ અક્ષર *, અચલ અક્ષર *, અક્ષર *, અચલ અક્ષર *, પૂર્ણાંક, પૂર્ણાંક *, પૂર્ણાંક);
પૂર્ણાંક	 read_config_file(અચલ અક્ષર *, સંરચના passwd *, અચલ અક્ષર *,
    અચલ અક્ષર *, અચલ અક્ષર *, Options *, પૂર્ણાંક, પૂર્ણાંક *);
પૂર્ણાંક	 parse_forward(સંરચના Forward *, અચલ અક્ષર *, પૂર્ણાંક, પૂર્ણાંક);
પૂર્ણાંક	 ssh_valid_hostname(અચલ અક્ષર *);
પૂર્ણાંક	 ssh_valid_ruser(અચલ અક્ષર *);
પૂર્ણાંક	 parse_jump(અચલ અક્ષર *, Options *, પૂર્ણાંક, પૂર્ણાંક);
પૂર્ણાંક	 parse_ssh_uri(અચલ અક્ષર *, અક્ષર **, અક્ષર **, પૂર્ણાંક *);
પૂર્ણાંક	 default_ssh_port(શૂન્ય);
પૂર્ણાંક	 option_clear_or_none(અચલ અક્ષર *);
પૂર્ણાંક	 config_has_permitted_cnames(Options *);
શૂન્ય	 dump_client_config(Options *o, અચલ અક્ષર *host);

શૂન્ય	 add_local_forward(Options *, અચલ સંરચના Forward *);
શૂન્ય	 add_remote_forward(Options *, અચલ સંરચના Forward *);
શૂન્ય	 add_identity_file(Options *, અચલ અક્ષર *, અચલ અક્ષર *, પૂર્ણાંક);
શૂન્ય	 add_certificate_file(Options *, અચલ અક્ષર *, પૂર્ણાંક);

#endif				/* READCONF_H */
