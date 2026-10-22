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
#define PATH_MAX_SUN		(आकार((संरचना sockaddr_un *)0)->sun_path)

संरचना allowed_cname {
	अक्षर *source_list;
	अक्षर *target_list;
};

प्रकारव्याख्या संरचना {
	अक्षर   *host_arg;	/* Host arg as specified on command line. */
	पूर्णांक     forward_agent;	/* Forward authentication agent. */
	अक्षर   *forward_agent_sock_path; /* Optional path of the agent. */
	पूर्णांक     forward_x11;	/* Forward X11 display. */
	पूर्णांक     forward_x11_timeout;	/* Expiration for Cookies */
	पूर्णांक     forward_x11_trusted;	/* Trust Forward X11 display. */
	पूर्णांक     exit_on_forward_failure;	/* Exit if bind(2) fails for -L/-R */
	अक्षर   *xauth_location;	/* Location for xauth program */
	संरचना ForwardOptions fwd_opts;	/* forwarding options */
	पूर्णांक     pubkey_authentication;	/* Try ssh2 pubkey authentication. */
	पूर्णांक     hostbased_authentication;	/* ssh2's rhosts_rsa */
	पूर्णांक     gss_authentication;	/* Try GSS authentication */
	पूर्णांक     gss_deleg_creds;	/* Delegate GSS credentials */
	पूर्णांक     password_authentication;	/* Try password
						 * authentication. */
	पूर्णांक     kbd_interactive_authentication; /* Try keyboard-interactive auth. */
	अक्षर	*kbd_interactive_devices; /* Keyboard-interactive auth devices. */
	पूर्णांक     batch_mode;	/* Batch mode: do not ask for passwords. */
	पूर्णांक     check_host_ip;	/* Also keep track of keys for IP address */
	पूर्णांक     strict_host_किल्ली_checking;	/* Strict host key checking. */
	पूर्णांक     compression;	/* Compress packets in both directions. */
	पूर्णांक     tcp_keep_alive;	/* Set SO_KEEPALIVE. */
	पूर्णांक	ip_qos_interactive;	/* DSCP value for interactive */
	पूर्णांक	ip_qos_bulk;		/* DSCP value for bulk traffic */
	SyslogFacility log_facility;	/* Facility for system logging. */
	LogLevel log_level;	/* Level for logging. */
	u_int	अंक_log_verbose;	/* Verbose log overrides */
	अक्षर   **log_verbose;
	पूर्णांक     port;		/* Port to connect. */
	पूर्णांक     address_family;
	पूर्णांक     connection_attempts;	/* Max attempts (seconds) before
					 * giving up */
	पूर्णांक     connection_timeout;	/* Max time (seconds) before
					 * aborting connection attempt */
	पूर्णांक     संख्या_of_password_prompts;	/* Max number of password
						 * prompts. */
	अक्षर   *ciphers;	/* SSH2 ciphers in order of preference. */
	अक्षर   *macs;		/* SSH2 macs in order of preference. */
	अक्षर   *hostkeyalgorithms;	/* SSH2 server key types in order of preference. */
	अक्षर   *kex_algorithms;	/* SSH2 kex methods in order of preference. */
	पूर्णांक	kex_algorithms_set; /* KexAlgorithms was set by the user */
	अक्षर   *ca_sign_algorithms;	/* Allowed CA signature algorithms */
	अक्षर   *hostname;	/* Real host to connect. */
	अक्षर   *tag;		/* Configuration tag name. */
	अक्षर   *host_किल्ली_alias;	/* hostname alias for .ssh/known_hosts */
	अक्षर   *proxy_command;	/* Proxy command for connecting the host. */
	अक्षर   *user;		/* User to log in as. */
	पूर्णांक     escape_char;	/* Escape character; -2 = none */

	u_int	अंक_system_hostfiles;	/* Paths for /etc/ssh/ssh_known_hosts */
	अक्षर   *system_hostfiles[SSH_MAX_HOSTS_FILES];
	u_int	अंक_user_hostfiles;	/* Path for $HOME/.ssh/known_hosts */
	अक्षर   *user_hostfiles[SSH_MAX_HOSTS_FILES];
	अक्षर   *preferred_authentications;
	अक्षर   *bind_address;	/* local socket address for connection to sshd */
	अक्षर   *bind_interface;	/* local interface for bind address */
	अक्षर   *pkcs11_provider; /* PKCS#11 provider */
	अक्षर   *sk_provider; /* Security key provider */
	पूर्णांक	verify_host_किल्ली_dns;	/* Verify host key using DNS */

	पूर्णांक     अंक_identity_files;	/* Number of files for identities. */
	अक्षर   *identity_files[SSH_MAX_IDENTITY_FILES];
	पूर्णांक    identity_file_userprovided[SSH_MAX_IDENTITY_FILES];
	संरचना sshkey *identity_किल्ल्या[SSH_MAX_IDENTITY_FILES];

	पूर्णांक	अंक_certificate_files; /* Number of extra certificates for ssh. */
	अक्षर	*certificate_files[SSH_MAX_CERTIFICATE_FILES];
	पूर्णांक	certificate_file_userprovided[SSH_MAX_CERTIFICATE_FILES];
	संरचना sshkey *certificates[SSH_MAX_CERTIFICATE_FILES];

	पूर्णांक	add_किल्ल्या_to_agent;
	पूर्णांक	add_किल्ल्या_to_agent_lifespan;
	अक्षर   *identity_agent;		/* Optional path to ssh-agent socket */

	/* Local TCP/IP forward requests. */
	पूर्णांक     अंक_local_forwards;
	संरचना Forward *local_forwards;

	/* Remote TCP/IP forward requests. */
	पूर्णांक     अंक_remote_forwards;
	संरचना Forward *remote_forwards;
	पूर्णांक	clear_forwardings;

	/* Restrict remote dynamic forwarding */
	अक्षर  **permitted_remote_opens;
	u_int	अंक_permitted_remote_opens;

	/* stdio forwarding (-W) host and port */
	अक्षर   *stdio_forward_host;
	पूर्णांक	stdio_forward_port;

	पूर्णांक	enable_ssh_keysign;
	int64_t rekey_limit;
	पूर्णांक	rekey_interval;
	पूर्णांक	no_host_authentication_for_localhost;
	पूर्णांक	identities_only;
	पूर्णांक	server_alive_interval;
	पूर्णांक	server_alive_मोजणी_max;

	u_int	अंक_send_env;
	अक्षर	**send_env;
	u_int	अंक_setenv;
	अक्षर	**setenv;

	अक्षर	*control_path;
	पूर्णांक	control_master;
	पूर्णांक     control_persist; /* ControlPersist flag */
	पूर्णांक     control_persist_timeout; /* ControlPersist timeout (seconds) */

	पूर्णांक	hash_known_hosts;

	पूर्णांक	tun_open;	/* tun(4) */
	पूर्णांक     tun_local;	/* force tun device (optional) */
	पूर्णांक     tun_remote;	/* force tun device (optional) */

	अक्षर	*local_command;
	पूर्णांक	permit_local_command;
	अक्षर	*remote_command;
	पूर्णांक	visual_host_किल्ली;

	पूर्णांक	request_tty;
	पूर्णांक	session_type;
	पूर्णांक	stdin_null;
	पूर्णांक	fork_after_authentication;

	पूर्णांक	proxy_use_fdpass;

	पूर्णांक	अंक_canonical_domains;
	अक्षर	**canonical_domains;
	पूर्णांक	canonicalize_hostname;
	पूर्णांक	canonicalize_max_dots;
	पूर्णांक	canonicalize_fallback_local;
	पूर्णांक	अंक_permitted_cnames;
	संरचना allowed_cname *permitted_cnames;

	u_int	अंक_revoked_host_किल्ल्या;
	अक्षर	**revoked_host_किल्ल्या;

	पूर्णांक	 fingerprint_hash;

	पूर्णांक	 update_hostkeys; /* one of SSH_UPDATE_HOSTKEYS_* */

	अक्षर   *hostbased_accepted_algos;
	अक्षर   *pubkey_accepted_algos;

	अक्षर   *jump_user;
	अक्षर   *jump_host;
	पूर्णांक	jump_port;
	अक्षर   *jump_extra;

	अक्षर   *known_hosts_command;

	पूर्णांक	required_rsa_size;	/* minimum size of RSA keys */
	पूर्णांक	enable_escape_commandline;	/* ~C commandline */
	पूर्णांक	obscure_keystroke_timing_interval;
	पूर्णांक	warn_weak_crypto;

	अक्षर	**channel_timeouts;	/* inactivity timeout by channel type */
	u_int	अंक_channel_timeouts;

	अक्षर	*version_addendum;

	अक्षर	*ignored_unknown; /* Pattern list of unknown tokens to ignore */
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

स्थिरांक अक्षर *kex_default_pk_alg(शून्य);
अक्षर	*ssh_connection_hash(स्थिरांक अक्षर *thishost, स्थिरांक अक्षर *host,
    स्थिरांक अक्षर *portstr, स्थिरांक अक्षर *user, स्थिरांक अक्षर *jump_host);
शून्य     initialize_options(Options *);
पूर्णांक      fill_default_options(Options *);
शून्य	 fill_default_options_for_canonicalization(Options *);
शून्य	 free_options(Options *o);
पूर्णांक	 process_config_ओळ(Options *, संरचना passwd *, स्थिरांक अक्षर *,
    स्थिरांक अक्षर *, स्थिरांक अक्षर *, अक्षर *, स्थिरांक अक्षर *, पूर्णांक, पूर्णांक *, पूर्णांक);
पूर्णांक	 read_config_file(स्थिरांक अक्षर *, संरचना passwd *, स्थिरांक अक्षर *,
    स्थिरांक अक्षर *, स्थिरांक अक्षर *, Options *, पूर्णांक, पूर्णांक *);
पूर्णांक	 parse_forward(संरचना Forward *, स्थिरांक अक्षर *, पूर्णांक, पूर्णांक);
पूर्णांक	 ssh_valid_hostname(स्थिरांक अक्षर *);
पूर्णांक	 ssh_valid_ruser(स्थिरांक अक्षर *);
पूर्णांक	 parse_jump(स्थिरांक अक्षर *, Options *, पूर्णांक, पूर्णांक);
पूर्णांक	 parse_ssh_uri(स्थिरांक अक्षर *, अक्षर **, अक्षर **, पूर्णांक *);
पूर्णांक	 default_ssh_port(शून्य);
पूर्णांक	 option_clear_or_none(स्थिरांक अक्षर *);
पूर्णांक	 config_has_permitted_cnames(Options *);
शून्य	 dump_client_config(Options *o, स्थिरांक अक्षर *host);

शून्य	 add_local_forward(Options *, स्थिरांक संरचना Forward *);
शून्य	 add_remote_forward(Options *, स्थिरांक संरचना Forward *);
शून्य	 add_identity_file(Options *, स्थिरांक अक्षर *, स्थिरांक अक्षर *, पूर्णांक);
शून्य	 add_certificate_file(Options *, स्थिरांक अक्षर *, पूर्णांक);

#endif				/* READCONF_H */
