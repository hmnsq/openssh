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
#define PATH_MAX_SUN		(ଆକାର((ସଂରଚନା sockaddr_un *)0)->sun_path)

ସଂରଚନା allowed_cname {
	ଅକ୍ଷର *source_list;
	ଅକ୍ଷର *target_list;
};

ପ୍ରକାରବ୍ୟାଖ୍ୟା ସଂରଚନା {
	ଅକ୍ଷର   *host_arg;	/* Host arg as specified on command line. */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା     forward_agent;	/* Forward authentication agent. */
	ଅକ୍ଷର   *forward_agent_sock_path; /* Optional path of the agent. */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା     forward_x11;	/* Forward X11 display. */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା     forward_x11_timeout;	/* Expiration for Cookies */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା     forward_x11_trusted;	/* Trust Forward X11 display. */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା     exit_on_forward_failure;	/* Exit if bind(2) fails for -L/-R */
	ଅକ୍ଷର   *xauth_location;	/* Location for xauth program */
	ସଂରଚନା ForwardOptions fwd_opts;	/* forwarding options */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା     pubkey_authentication;	/* Try ssh2 pubkey authentication. */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା     hostbased_authentication;	/* ssh2's rhosts_rsa */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା     gss_authentication;	/* Try GSS authentication */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା     gss_deleg_creds;	/* Delegate GSS credentials */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା     password_authentication;	/* Try password
						 * authentication. */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା     kbd_interactive_authentication; /* Try keyboard-interactive auth. */
	ଅକ୍ଷର	*kbd_interactive_devices; /* Keyboard-interactive auth devices. */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା     batch_mode;	/* Batch mode: do not ask for passwords. */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା     check_host_ip;	/* Also keep track of keys for IP address */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା     strict_host_ଚାବି_checking;	/* Strict host key checking. */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା     compression;	/* Compress packets in both directions. */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା     tcp_keep_alive;	/* Set SO_KEEPALIVE. */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	ip_qos_interactive;	/* DSCP value for interactive */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	ip_qos_bulk;		/* DSCP value for bulk traffic */
	SyslogFacility log_facility;	/* Facility for system logging. */
	LogLevel log_level;	/* Level for logging. */
	u_int	ଅଙ୍କ_log_verbose;	/* Verbose log overrides */
	ଅକ୍ଷର   **log_verbose;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା     port;		/* Port to connect. */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା     address_family;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା     connection_attempts;	/* Max attempts (seconds) before
					 * giving up */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା     connection_timeout;	/* Max time (seconds) before
					 * aborting connection attempt */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା     ସଂଖ୍ୟା_of_password_prompts;	/* Max number of password
						 * prompts. */
	ଅକ୍ଷର   *ciphers;	/* SSH2 ciphers in order of preference. */
	ଅକ୍ଷର   *macs;		/* SSH2 macs in order of preference. */
	ଅକ୍ଷର   *hostkeyalgorithms;	/* SSH2 server key types in order of preference. */
	ଅକ୍ଷର   *kex_algorithms;	/* SSH2 kex methods in order of preference. */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	kex_algorithms_set; /* KexAlgorithms was set by the user */
	ଅକ୍ଷର   *ca_sign_algorithms;	/* Allowed CA signature algorithms */
	ଅକ୍ଷର   *hostname;	/* Real host to connect. */
	ଅକ୍ଷର   *tag;		/* Configuration tag name. */
	ଅକ୍ଷର   *host_ଚାବି_alias;	/* hostname alias for .ssh/known_hosts */
	ଅକ୍ଷର   *proxy_command;	/* Proxy command for connecting the host. */
	ଅକ୍ଷର   *user;		/* User to log in as. */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା     escape_char;	/* Escape character; -2 = none */

	u_int	ଅଙ୍କ_system_hostfiles;	/* Paths for /etc/ssh/ssh_known_hosts */
	ଅକ୍ଷର   *system_hostfiles[SSH_MAX_HOSTS_FILES];
	u_int	ଅଙ୍କ_user_hostfiles;	/* Path for $HOME/.ssh/known_hosts */
	ଅକ୍ଷର   *user_hostfiles[SSH_MAX_HOSTS_FILES];
	ଅକ୍ଷର   *preferred_authentications;
	ଅକ୍ଷର   *bind_address;	/* local socket address for connection to sshd */
	ଅକ୍ଷର   *bind_interface;	/* local interface for bind address */
	ଅକ୍ଷର   *pkcs11_provider; /* PKCS#11 provider */
	ଅକ୍ଷର   *sk_provider; /* Security key provider */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	verify_host_ଚାବି_dns;	/* Verify host key using DNS */

	ପୂର୍ଣ୍ଣସଂଖ୍ୟା     ଅଙ୍କ_identity_files;	/* Number of files for identities. */
	ଅକ୍ଷର   *identity_files[SSH_MAX_IDENTITY_FILES];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା    identity_file_userprovided[SSH_MAX_IDENTITY_FILES];
	ସଂରଚନା sshkey *identity_ଚାବିଗୁଡ଼ିକ[SSH_MAX_IDENTITY_FILES];

	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	ଅଙ୍କ_certificate_files; /* Number of extra certificates for ssh. */
	ଅକ୍ଷର	*certificate_files[SSH_MAX_CERTIFICATE_FILES];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	certificate_file_userprovided[SSH_MAX_CERTIFICATE_FILES];
	ସଂରଚନା sshkey *certificates[SSH_MAX_CERTIFICATE_FILES];

	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	add_ଚାବିଗୁଡ଼ିକ_to_agent;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	add_ଚାବିଗୁଡ଼ିକ_to_agent_lifespan;
	ଅକ୍ଷର   *identity_agent;		/* Optional path to ssh-agent socket */

	/* Local TCP/IP forward requests. */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା     ଅଙ୍କ_local_forwards;
	ସଂରଚନା Forward *local_forwards;

	/* Remote TCP/IP forward requests. */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା     ଅଙ୍କ_remote_forwards;
	ସଂରଚନା Forward *remote_forwards;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	clear_forwardings;

	/* Restrict remote dynamic forwarding */
	ଅକ୍ଷର  **permitted_remote_opens;
	u_int	ଅଙ୍କ_permitted_remote_opens;

	/* stdio forwarding (-W) host and port */
	ଅକ୍ଷର   *stdio_forward_host;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	stdio_forward_port;

	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	enable_ssh_keysign;
	int64_t rekey_limit;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	rekey_interval;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	no_host_authentication_for_localhost;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	identities_only;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	server_alive_interval;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	server_alive_ଗଣନା_max;

	u_int	ଅଙ୍କ_send_env;
	ଅକ୍ଷର	**send_env;
	u_int	ଅଙ୍କ_setenv;
	ଅକ୍ଷର	**setenv;

	ଅକ୍ଷର	*control_path;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	control_master;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା     control_persist; /* ControlPersist flag */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା     control_persist_timeout; /* ControlPersist timeout (seconds) */

	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	hash_known_hosts;

	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	tun_open;	/* tun(4) */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା     tun_local;	/* force tun device (optional) */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା     tun_remote;	/* force tun device (optional) */

	ଅକ୍ଷର	*local_command;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	permit_local_command;
	ଅକ୍ଷର	*remote_command;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	visual_host_ଚାବି;

	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	request_tty;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	session_type;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	stdin_null;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	fork_after_authentication;

	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	proxy_use_fdpass;

	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	ଅଙ୍କ_canonical_domains;
	ଅକ୍ଷର	**canonical_domains;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	canonicalize_hostname;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	canonicalize_max_dots;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	canonicalize_fallback_local;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	ଅଙ୍କ_permitted_cnames;
	ସଂରଚନା allowed_cname *permitted_cnames;

	u_int	ଅଙ୍କ_revoked_host_ଚାବିଗୁଡ଼ିକ;
	ଅକ୍ଷର	**revoked_host_ଚାବିଗୁଡ଼ିକ;

	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 fingerprint_hash;

	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 update_hostkeys; /* one of SSH_UPDATE_HOSTKEYS_* */

	ଅକ୍ଷର   *hostbased_accepted_algos;
	ଅକ୍ଷର   *pubkey_accepted_algos;

	ଅକ୍ଷର   *jump_user;
	ଅକ୍ଷର   *jump_host;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	jump_port;
	ଅକ୍ଷର   *jump_extra;

	ଅକ୍ଷର   *known_hosts_command;

	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	required_rsa_size;	/* minimum size of RSA keys */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	enable_escape_commandline;	/* ~C commandline */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	obscure_keystroke_timing_interval;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	warn_weak_crypto;

	ଅକ୍ଷର	**channel_timeouts;	/* inactivity timeout by channel type */
	u_int	ଅଙ୍କ_channel_timeouts;

	ଅକ୍ଷର	*version_addendum;

	ଅକ୍ଷର	*ignored_unknown; /* Pattern list of unknown tokens to ignore */
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

ଅଚଳ ଅକ୍ଷର *kex_default_pk_alg(ଶୂନ୍ୟ);
ଅକ୍ଷର	*ssh_connection_hash(ଅଚଳ ଅକ୍ଷର *thishost, ଅଚଳ ଅକ୍ଷର *host,
    ଅଚଳ ଅକ୍ଷର *portstr, ଅଚଳ ଅକ୍ଷର *user, ଅଚଳ ଅକ୍ଷର *jump_host);
ଶୂନ୍ୟ     initialize_options(Options *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା      fill_default_options(Options *);
ଶୂନ୍ୟ	 fill_default_options_for_canonicalization(Options *);
ଶୂନ୍ୟ	 free_options(Options *o);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 process_config_ଧାଡ଼ି(Options *, ସଂରଚନା passwd *, ଅଚଳ ଅକ୍ଷର *,
    ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 read_config_file(ଅଚଳ ଅକ୍ଷର *, ସଂରଚନା passwd *, ଅଚଳ ଅକ୍ଷର *,
    ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, Options *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 parse_forward(ସଂରଚନା Forward *, ଅଚଳ ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 ssh_valid_hostname(ଅଚଳ ଅକ୍ଷର *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 ssh_valid_ruser(ଅଚଳ ଅକ୍ଷର *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 parse_jump(ଅଚଳ ଅକ୍ଷର *, Options *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 parse_ssh_uri(ଅଚଳ ଅକ୍ଷର *, ଅକ୍ଷର **, ଅକ୍ଷର **, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 default_ssh_port(ଶୂନ୍ୟ);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 option_clear_or_none(ଅଚଳ ଅକ୍ଷର *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 config_has_permitted_cnames(Options *);
ଶୂନ୍ୟ	 dump_client_config(Options *o, ଅଚଳ ଅକ୍ଷର *host);

ଶୂନ୍ୟ	 add_local_forward(Options *, ଅଚଳ ସଂରଚନା Forward *);
ଶୂନ୍ୟ	 add_remote_forward(Options *, ଅଚଳ ସଂରଚନା Forward *);
ଶୂନ୍ୟ	 add_identity_file(Options *, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ଶୂନ୍ୟ	 add_certificate_file(Options *, ଅଚଳ ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);

#endif				/* READCONF_H */
