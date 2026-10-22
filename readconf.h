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
#define PATH_MAX_SUN		(परिमाण((संरचना sockaddr_un *)0)->sun_path)

संरचना allowed_cname {
	वर्ण *source_list;
	वर्ण *target_list;
};

प्रकारनिर्देश संरचना {
	वर्ण   *host_arg;	/* Host arg as specified on command line. */
	पूर्णाङ्क     forward_agent;	/* Forward authentication agent. */
	वर्ण   *forward_agent_sock_path; /* Optional path of the agent. */
	पूर्णाङ्क     forward_x11;	/* Forward X11 display. */
	पूर्णाङ्क     forward_x11_timeout;	/* Expiration for Cookies */
	पूर्णाङ्क     forward_x11_trusted;	/* Trust Forward X11 display. */
	पूर्णाङ्क     exit_on_forward_failure;	/* Exit if bind(2) fails for -L/-R */
	वर्ण   *xauth_location;	/* Location for xauth program */
	संरचना ForwardOptions fwd_opts;	/* forwarding options */
	पूर्णाङ्क     pubkey_authentication;	/* Try ssh2 pubkey authentication. */
	पूर्णाङ्क     hostbased_authentication;	/* ssh2's rhosts_rsa */
	पूर्णाङ्क     gss_authentication;	/* Try GSS authentication */
	पूर्णाङ्क     gss_deleg_creds;	/* Delegate GSS credentials */
	पूर्णाङ्क     password_authentication;	/* Try password
						 * authentication. */
	पूर्णाङ्क     kbd_interactive_authentication; /* Try keyboard-interactive auth. */
	वर्ण	*kbd_interactive_devices; /* Keyboard-interactive auth devices. */
	पूर्णाङ्क     batch_mode;	/* Batch mode: do not ask for passwords. */
	पूर्णाङ्क     check_host_ip;	/* Also keep track of keys for IP address */
	पूर्णाङ्क     strict_host_कुंजी_checking;	/* Strict host key checking. */
	पूर्णाङ्क     compression;	/* Compress packets in both directions. */
	पूर्णाङ्क     tcp_keep_alive;	/* Set SO_KEEPALIVE. */
	पूर्णाङ्क	ip_qos_interactive;	/* DSCP value for interactive */
	पूर्णाङ्क	ip_qos_bulk;		/* DSCP value for bulk traffic */
	SyslogFacility log_facility;	/* Facility for system logging. */
	LogLevel log_level;	/* Level for logging. */
	u_int	अंक_log_verbose;	/* Verbose log overrides */
	वर्ण   **log_verbose;
	पूर्णाङ्क     port;		/* Port to connect. */
	पूर्णाङ्क     address_family;
	पूर्णाङ्क     connection_attempts;	/* Max attempts (seconds) before
					 * giving up */
	पूर्णाङ्क     connection_timeout;	/* Max time (seconds) before
					 * aborting connection attempt */
	पूर्णाङ्क     संख्या_of_password_prompts;	/* Max number of password
						 * prompts. */
	वर्ण   *ciphers;	/* SSH2 ciphers in order of preference. */
	वर्ण   *macs;		/* SSH2 macs in order of preference. */
	वर्ण   *hostkeyalgorithms;	/* SSH2 server key types in order of preference. */
	वर्ण   *kex_algorithms;	/* SSH2 kex methods in order of preference. */
	पूर्णाङ्क	kex_algorithms_set; /* KexAlgorithms was set by the user */
	वर्ण   *ca_sign_algorithms;	/* Allowed CA signature algorithms */
	वर्ण   *hostname;	/* Real host to connect. */
	वर्ण   *tag;		/* Configuration tag name. */
	वर्ण   *host_कुंजी_alias;	/* hostname alias for .ssh/known_hosts */
	वर्ण   *proxy_command;	/* Proxy command for connecting the host. */
	वर्ण   *user;		/* User to log in as. */
	पूर्णाङ्क     escape_char;	/* Escape character; -2 = none */

	u_int	अंक_system_hostfiles;	/* Paths for /etc/ssh/ssh_known_hosts */
	वर्ण   *system_hostfiles[SSH_MAX_HOSTS_FILES];
	u_int	अंक_user_hostfiles;	/* Path for $HOME/.ssh/known_hosts */
	वर्ण   *user_hostfiles[SSH_MAX_HOSTS_FILES];
	वर्ण   *preferred_authentications;
	वर्ण   *bind_address;	/* local socket address for connection to sshd */
	वर्ण   *bind_interface;	/* local interface for bind address */
	वर्ण   *pkcs11_provider; /* PKCS#11 provider */
	वर्ण   *sk_provider; /* Security key provider */
	पूर्णाङ्क	verify_host_कुंजी_dns;	/* Verify host key using DNS */

	पूर्णाङ्क     अंक_identity_files;	/* Number of files for identities. */
	वर्ण   *identity_files[SSH_MAX_IDENTITY_FILES];
	पूर्णाङ्क    identity_file_userprovided[SSH_MAX_IDENTITY_FILES];
	संरचना sshkey *identity_कुंजियाँ[SSH_MAX_IDENTITY_FILES];

	पूर्णाङ्क	अंक_certificate_files; /* Number of extra certificates for ssh. */
	वर्ण	*certificate_files[SSH_MAX_CERTIFICATE_FILES];
	पूर्णाङ्क	certificate_file_userprovided[SSH_MAX_CERTIFICATE_FILES];
	संरचना sshkey *certificates[SSH_MAX_CERTIFICATE_FILES];

	पूर्णाङ्क	add_कुंजियाँ_to_agent;
	पूर्णाङ्क	add_कुंजियाँ_to_agent_lifespan;
	वर्ण   *identity_agent;		/* Optional path to ssh-agent socket */

	/* Local TCP/IP forward requests. */
	पूर्णाङ्क     अंक_local_forwards;
	संरचना Forward *local_forwards;

	/* Remote TCP/IP forward requests. */
	पूर्णाङ्क     अंक_remote_forwards;
	संरचना Forward *remote_forwards;
	पूर्णाङ्क	clear_forwardings;

	/* Restrict remote dynamic forwarding */
	वर्ण  **permitted_remote_opens;
	u_int	अंक_permitted_remote_opens;

	/* stdio forwarding (-W) host and port */
	वर्ण   *stdio_forward_host;
	पूर्णाङ्क	stdio_forward_port;

	पूर्णाङ्क	enable_ssh_keysign;
	int64_t rekey_limit;
	पूर्णाङ्क	rekey_interval;
	पूर्णाङ्क	no_host_authentication_for_localhost;
	पूर्णाङ्क	identities_only;
	पूर्णाङ्क	server_alive_interval;
	पूर्णाङ्क	server_alive_गिनती_max;

	u_int	अंक_send_env;
	वर्ण	**send_env;
	u_int	अंक_setenv;
	वर्ण	**setenv;

	वर्ण	*control_path;
	पूर्णाङ्क	control_master;
	पूर्णाङ्क     control_persist; /* ControlPersist flag */
	पूर्णाङ्क     control_persist_timeout; /* ControlPersist timeout (seconds) */

	पूर्णाङ्क	hash_known_hosts;

	पूर्णाङ्क	tun_open;	/* tun(4) */
	पूर्णाङ्क     tun_local;	/* force tun device (optional) */
	पूर्णाङ्क     tun_remote;	/* force tun device (optional) */

	वर्ण	*local_command;
	पूर्णाङ्क	permit_local_command;
	वर्ण	*remote_command;
	पूर्णाङ्क	visual_host_कुंजी;

	पूर्णाङ्क	request_tty;
	पूर्णाङ्क	session_type;
	पूर्णाङ्क	stdin_null;
	पूर्णाङ्क	fork_after_authentication;

	पूर्णाङ्क	proxy_use_fdpass;

	पूर्णाङ्क	अंक_canonical_domains;
	वर्ण	**canonical_domains;
	पूर्णाङ्क	canonicalize_hostname;
	पूर्णाङ्क	canonicalize_max_dots;
	पूर्णाङ्क	canonicalize_fallback_local;
	पूर्णाङ्क	अंक_permitted_cnames;
	संरचना allowed_cname *permitted_cnames;

	u_int	अंक_revoked_host_कुंजियाँ;
	वर्ण	**revoked_host_कुंजियाँ;

	पूर्णाङ्क	 fingerprint_hash;

	पूर्णाङ्क	 update_hostkeys; /* one of SSH_UPDATE_HOSTKEYS_* */

	वर्ण   *hostbased_accepted_algos;
	वर्ण   *pubkey_accepted_algos;

	वर्ण   *jump_user;
	वर्ण   *jump_host;
	पूर्णाङ्क	jump_port;
	वर्ण   *jump_extra;

	वर्ण   *known_hosts_command;

	पूर्णाङ्क	required_rsa_size;	/* minimum size of RSA keys */
	पूर्णाङ्क	enable_escape_commandline;	/* ~C commandline */
	पूर्णाङ्क	obscure_keystroke_timing_interval;
	पूर्णाङ्क	warn_weak_crypto;

	वर्ण	**channel_timeouts;	/* inactivity timeout by channel type */
	u_int	अंक_channel_timeouts;

	वर्ण	*version_addendum;

	वर्ण	*ignored_unknown; /* Pattern list of unknown tokens to ignore */
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

ध्रुव वर्ण *kex_default_pk_alg(शून्य);
वर्ण	*ssh_connection_hash(ध्रुव वर्ण *thishost, ध्रुव वर्ण *host,
    ध्रुव वर्ण *portstr, ध्रुव वर्ण *user, ध्रुव वर्ण *jump_host);
शून्य     initialize_options(Options *);
पूर्णाङ्क      fill_default_options(Options *);
शून्य	 fill_default_options_for_canonicalization(Options *);
शून्य	 free_options(Options *o);
पूर्णाङ्क	 process_config_पंक्ति(Options *, संरचना passwd *, ध्रुव वर्ण *,
    ध्रुव वर्ण *, ध्रुव वर्ण *, वर्ण *, ध्रुव वर्ण *, पूर्णाङ्क, पूर्णाङ्क *, पूर्णाङ्क);
पूर्णाङ्क	 read_config_file(ध्रुव वर्ण *, संरचना passwd *, ध्रुव वर्ण *,
    ध्रुव वर्ण *, ध्रुव वर्ण *, Options *, पूर्णाङ्क, पूर्णाङ्क *);
पूर्णाङ्क	 parse_forward(संरचना Forward *, ध्रुव वर्ण *, पूर्णाङ्क, पूर्णाङ्क);
पूर्णाङ्क	 ssh_valid_hostname(ध्रुव वर्ण *);
पूर्णाङ्क	 ssh_valid_ruser(ध्रुव वर्ण *);
पूर्णाङ्क	 parse_jump(ध्रुव वर्ण *, Options *, पूर्णाङ्क, पूर्णाङ्क);
पूर्णाङ्क	 parse_ssh_uri(ध्रुव वर्ण *, वर्ण **, वर्ण **, पूर्णाङ्क *);
पूर्णाङ्क	 default_ssh_port(शून्य);
पूर्णाङ्क	 option_clear_or_none(ध्रुव वर्ण *);
पूर्णाङ्क	 config_has_permitted_cnames(Options *);
शून्य	 dump_client_config(Options *o, ध्रुव वर्ण *host);

शून्य	 add_local_forward(Options *, ध्रुव संरचना Forward *);
शून्य	 add_remote_forward(Options *, ध्रुव संरचना Forward *);
शून्य	 add_identity_file(Options *, ध्रुव वर्ण *, ध्रुव वर्ण *, पूर्णाङ्क);
शून्य	 add_certificate_file(Options *, ध्रुव वर्ण *, पूर्णाङ्क);

#endif				/* READCONF_H */
