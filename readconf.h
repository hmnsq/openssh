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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ READCONF_H
#ವ್ಯಾಖ್ಯಾನಿಸು READCONF_H

/* Data structure for representing option data. */

#ವ್ಯಾಖ್ಯಾನಿಸು SSH_MAX_HOSTS_FILES	32
#ವ್ಯಾಖ್ಯಾನಿಸು ಮಾರ್ಗ_MAX_SUN		(ಗಾತ್ರ((ರಚನೆ sockaddr_un *)0)->sun_ಮಾರ್ಗ)

ರಚನೆ allowed_cname {
	ಅಕ್ಷರ *ಮೂಲ_list;
	ಅಕ್ಷರ *ಗುರಿ_list;
};

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ {
	ಅಕ್ಷರ   *host_arg;	/* Host arg as specified on command line. */
	ಪೂರ್ಣಾಂಕ     forward_agent;	/* Forward authentication agent. */
	ಅಕ್ಷರ   *forward_agent_sock_ಮಾರ್ಗ; /* Optional path of the agent. */
	ಪೂರ್ಣಾಂಕ     forward_x11;	/* Forward X11 display. */
	ಪೂರ್ಣಾಂಕ     forward_x11_timeout;	/* Expiration for Cookies */
	ಪೂರ್ಣಾಂಕ     forward_x11_trusted;	/* Trust Forward X11 display. */
	ಪೂರ್ಣಾಂಕ     exit_on_forward_failure;	/* Exit if bind(2) fails for -L/-R */
	ಅಕ್ಷರ   *xauth_location;	/* Location for xauth program */
	ರಚನೆ ForwardOptions fwd_opts;	/* forwarding options */
	ಪೂರ್ಣಾಂಕ     pubkey_authentication;	/* Try ssh2 pubkey authentication. */
	ಪೂರ್ಣಾಂಕ     hostbased_authentication;	/* ssh2's rhosts_rsa */
	ಪೂರ್ಣಾಂಕ     gss_authentication;	/* Try GSS authentication */
	ಪೂರ್ಣಾಂಕ     gss_deleg_creds;	/* Delegate GSS credentials */
	ಪೂರ್ಣಾಂಕ     password_authentication;	/* Try password
						 * authentication. */
	ಪೂರ್ಣಾಂಕ     kbd_interactive_authentication; /* Try keyboard-interactive auth. */
	ಅಕ್ಷರ	*kbd_interactive_devices; /* Keyboard-interactive auth devices. */
	ಪೂರ್ಣಾಂಕ     batch_ಬಹುಲಕ;	/* Batch mode: do not ask for passwords. */
	ಪೂರ್ಣಾಂಕ     check_host_ip;	/* Also keep track of keys for IP address */
	ಪೂರ್ಣಾಂಕ     strict_host_ಕೀಲಿ_checking;	/* Strict host key checking. */
	ಪೂರ್ಣಾಂಕ     compression;	/* Compress packets in both directions. */
	ಪೂರ್ಣಾಂಕ     tcp_keep_alive;	/* Set SO_KEEPALIVE. */
	ಪೂರ್ಣಾಂಕ	ip_qos_interactive;	/* DSCP value for interactive */
	ಪೂರ್ಣಾಂಕ	ip_qos_bulk;		/* DSCP value for bulk traffic */
	SyslogFacility log_facility;	/* Facility for system logging. */
	LogLevel log_level;	/* Level for logging. */
	u_int	ಅಂಕೆ_log_verbose;	/* Verbose log overrides */
	ಅಕ್ಷರ   **log_verbose;
	ಪೂರ್ಣಾಂಕ     ಪೋರ್ಟ್;		/* Port to connect. */
	ಪೂರ್ಣಾಂಕ     ವಿಳಾಸ_family;
	ಪೂರ್ಣಾಂಕ     connection_attempts;	/* Max attempts (seconds) before
					 * giving up */
	ಪೂರ್ಣಾಂಕ     connection_timeout;	/* Max time (seconds) before
					 * aborting connection attempt */
	ಪೂರ್ಣಾಂಕ     ಸಂಖ್ಯೆ_ದ_password_prompts;	/* Max number of password
						 * prompts. */
	ಅಕ್ಷರ   *ciphers;	/* SSH2 ciphers in order of preference. */
	ಅಕ್ಷರ   *macs;		/* SSH2 macs in order of preference. */
	ಅಕ್ಷರ   *hostkeyalgorithms;	/* SSH2 server key types in order of preference. */
	ಅಕ್ಷರ   *kex_algorithms;	/* SSH2 kex methods in order of preference. */
	ಪೂರ್ಣಾಂಕ	kex_algorithms_ಗಣ; /* KexAlgorithms was set by the user */
	ಅಕ್ಷರ   *ca_sign_algorithms;	/* Allowed CA signature algorithms */
	ಅಕ್ಷರ   *hostname;	/* Real host to connect. */
	ಅಕ್ಷರ   *ಟ್ಯಾಗ್;		/* Configuration tag name. */
	ಅಕ್ಷರ   *host_ಕೀಲಿ_alias;	/* hostname alias for .ssh/known_hosts */
	ಅಕ್ಷರ   *proxy_command;	/* Proxy command for connecting the host. */
	ಅಕ್ಷರ   *user;		/* User to log in as. */
	ಪೂರ್ಣಾಂಕ     escape_char;	/* Escape character; -2 = none */

	u_int	ಅಂಕೆ_system_hostfiles;	/* Paths for /etc/ssh/ssh_known_hosts */
	ಅಕ್ಷರ   *system_hostfiles[SSH_MAX_HOSTS_FILES];
	u_int	ಅಂಕೆ_user_hostfiles;	/* Path for $HOME/.ssh/known_hosts */
	ಅಕ್ಷರ   *user_hostfiles[SSH_MAX_HOSTS_FILES];
	ಅಕ್ಷರ   *preferred_authentications;
	ಅಕ್ಷರ   *bind_ವಿಳಾಸ;	/* local socket address for connection to sshd */
	ಅಕ್ಷರ   *bind_interface;	/* local interface for bind address */
	ಅಕ್ಷರ   *pkcs11_provider; /* PKCS#11 provider */
	ಅಕ್ಷರ   *sk_provider; /* Security key provider */
	ಪೂರ್ಣಾಂಕ	verify_host_ಕೀಲಿ_dns;	/* Verify host key using DNS */

	ಪೂರ್ಣಾಂಕ     ಅಂಕೆ_ತಟಸ್ಥ_files;	/* Number of files for identities. */
	ಅಕ್ಷರ   *ತಟಸ್ಥ_files[SSH_MAX_ತಟಸ್ಥ_FILES];
	ಪೂರ್ಣಾಂಕ    ತಟಸ್ಥ_file_userprovided[SSH_MAX_ತಟಸ್ಥ_FILES];
	ರಚನೆ sshkey *ತಟಸ್ಥ_ಕೀಲಿಗಳು[SSH_MAX_ತಟಸ್ಥ_FILES];

	ಪೂರ್ಣಾಂಕ	ಅಂಕೆ_certificate_files; /* Number of extra certificates for ssh. */
	ಅಕ್ಷರ	*certificate_files[SSH_MAX_CERTIFICATE_FILES];
	ಪೂರ್ಣಾಂಕ	certificate_file_userprovided[SSH_MAX_CERTIFICATE_FILES];
	ರಚನೆ sshkey *certificates[SSH_MAX_CERTIFICATE_FILES];

	ಪೂರ್ಣಾಂಕ	ಕೂಡಿಸು_ಕೀಲಿಗಳು_ಗಮ್ಯ_agent;
	ಪೂರ್ಣಾಂಕ	ಕೂಡಿಸು_ಕೀಲಿಗಳು_ಗಮ್ಯ_agent_lifespan;
	ಅಕ್ಷರ   *ತಟಸ್ಥ_agent;		/* Optional path to ssh-agent socket */

	/* Local TCP/IP forward requests. */
	ಪೂರ್ಣಾಂಕ     ಅಂಕೆ_local_forwards;
	ರಚನೆ Forward *local_forwards;

	/* Remote TCP/IP forward requests. */
	ಪೂರ್ಣಾಂಕ     ಅಂಕೆ_remote_forwards;
	ರಚನೆ Forward *remote_forwards;
	ಪೂರ್ಣಾಂಕ	clear_forwardings;

	/* Restrict remote dynamic forwarding */
	ಅಕ್ಷರ  **permitted_remote_opens;
	u_int	ಅಂಕೆ_permitted_remote_opens;

	/* stdio forwarding (-W) host and port */
	ಅಕ್ಷರ   *stdio_forward_host;
	ಪೂರ್ಣಾಂಕ	stdio_forward_ಪೋರ್ಟ್;

	ಪೂರ್ಣಾಂಕ	enable_ssh_keysign;
	int64_t rekey_ಎಲ್ಲೆ;
	ಪೂರ್ಣಾಂಕ	rekey_interval;
	ಪೂರ್ಣಾಂಕ	no_host_authentication_for_localhost;
	ಪೂರ್ಣಾಂಕ	identities_only;
	ಪೂರ್ಣಾಂಕ	server_alive_interval;
	ಪೂರ್ಣಾಂಕ	server_alive_ಎಣಿಕೆ_max;

	u_int	ಅಂಕೆ_send_env;
	ಅಕ್ಷರ	**send_env;
	u_int	ಅಂಕೆ_setenv;
	ಅಕ್ಷರ	**setenv;

	ಅಕ್ಷರ	*control_ಮಾರ್ಗ;
	ಪೂರ್ಣಾಂಕ	control_master;
	ಪೂರ್ಣಾಂಕ     control_persist; /* ControlPersist flag */
	ಪೂರ್ಣಾಂಕ     control_persist_timeout; /* ControlPersist timeout (seconds) */

	ಪೂರ್ಣಾಂಕ	hash_ತಿಳಿದ_hosts;

	ಪೂರ್ಣಾಂಕ	tun_open;	/* tun(4) */
	ಪೂರ್ಣಾಂಕ     tun_local;	/* force tun device (optional) */
	ಪೂರ್ಣಾಂಕ     tun_remote;	/* force tun device (optional) */

	ಅಕ್ಷರ	*local_command;
	ಪೂರ್ಣಾಂಕ	permit_local_command;
	ಅಕ್ಷರ	*remote_command;
	ಪೂರ್ಣಾಂಕ	visual_host_ಕೀಲಿ;

	ಪೂರ್ಣಾಂಕ	request_tty;
	ಪೂರ್ಣಾಂಕ	session_type;
	ಪೂರ್ಣಾಂಕ	stdin_null;
	ಪೂರ್ಣಾಂಕ	fork_after_authentication;

	ಪೂರ್ಣಾಂಕ	proxy_use_fdpass;

	ಪೂರ್ಣಾಂಕ	ಅಂಕೆ_canonical_domains;
	ಅಕ್ಷರ	**canonical_domains;
	ಪೂರ್ಣಾಂಕ	canonicalize_hostname;
	ಪೂರ್ಣಾಂಕ	canonicalize_max_dots;
	ಪೂರ್ಣಾಂಕ	canonicalize_fallback_local;
	ಪೂರ್ಣಾಂಕ	ಅಂಕೆ_permitted_cnames;
	ರಚನೆ allowed_cname *permitted_cnames;

	u_int	ಅಂಕೆ_revoked_host_ಕೀಲಿಗಳು;
	ಅಕ್ಷರ	**revoked_host_ಕೀಲಿಗಳು;

	ಪೂರ್ಣಾಂಕ	 fingerprint_hash;

	ಪೂರ್ಣಾಂಕ	 update_hostkeys; /* one of SSH_UPDATE_HOSTKEYS_* */

	ಅಕ್ಷರ   *hostbased_accepted_algos;
	ಅಕ್ಷರ   *pubkey_accepted_algos;

	ಅಕ್ಷರ   *jump_user;
	ಅಕ್ಷರ   *jump_host;
	ಪೂರ್ಣಾಂಕ	jump_ಪೋರ್ಟ್;
	ಅಕ್ಷರ   *jump_extra;

	ಅಕ್ಷರ   *ತಿಳಿದ_hosts_command;

	ಪೂರ್ಣಾಂಕ	required_rsa_ಗಾತ್ರ;	/* minimum size of RSA keys */
	ಪೂರ್ಣಾಂಕ	enable_escape_commandline;	/* ~C commandline */
	ಪೂರ್ಣಾಂಕ	obscure_keystroke_timing_interval;
	ಪೂರ್ಣಾಂಕ	warn_weak_crypto;

	ಅಕ್ಷರ	**channel_timeouts;	/* inactivity timeout by channel type */
	u_int	ಅಂಕೆ_channel_timeouts;

	ಅಕ್ಷರ	*ಆವೃತ್ತಿ_addendum;

	ಅಕ್ಷರ	*ignored_unknown; /* Pattern list of unknown tokens to ignore */
}       Options;

#ವ್ಯಾಖ್ಯಾನಿಸು SSH_PUBKEY_AUTH_NO	0x00
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_PUBKEY_AUTH_UNBOUND	0x01
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_PUBKEY_AUTH_HBOUND	0x02
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_PUBKEY_AUTH_ALL	0x03

#ವ್ಯಾಖ್ಯಾನಿಸು SSH_CANONICALISE_NO	0
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_CANONICALISE_YES	1
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_CANONICALISE_ALWAYS	2

#ವ್ಯಾಖ್ಯಾನಿಸು SSHCTL_MASTER_NO	0
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCTL_MASTER_YES	1
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCTL_MASTER_AUTO	2
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCTL_MASTER_ASK	3
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCTL_MASTER_AUTO_ASK	4

#ವ್ಯಾಖ್ಯಾನಿಸು REQUEST_TTY_AUTO	0
#ವ್ಯಾಖ್ಯಾನಿಸು REQUEST_TTY_NO		1
#ವ್ಯಾಖ್ಯಾನಿಸು REQUEST_TTY_YES		2
#ವ್ಯಾಖ್ಯಾನಿಸು REQUEST_TTY_FORCE	3

#ವ್ಯಾಖ್ಯಾನಿಸು SESSION_TYPE_NONE	0
#ವ್ಯಾಖ್ಯಾನಿಸು SESSION_TYPE_SUBSYSTEM	1
#ವ್ಯಾಖ್ಯಾನಿಸು SESSION_TYPE_DEFAULT	2

#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_CHECKPERM	1  /* check permissions on config file */
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_USERCONF	2  /* user provided config file not system */
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_FINAL		4  /* Final pass over config, after canon. */
#ವ್ಯಾಖ್ಯಾನಿಸು SSHCONF_NEVERMATCH	8  /* Match/Host never matches; internal only */

#ವ್ಯಾಖ್ಯಾನಿಸು SSH_UPDATE_HOSTKEYS_NO	0
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_UPDATE_HOSTKEYS_YES	1
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_UPDATE_HOSTKEYS_ASK	2

#ವ್ಯಾಖ್ಯಾನಿಸು SSH_STRICT_HOSTKEY_OFF	0
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_STRICT_HOSTKEY_NEW	1
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_STRICT_HOSTKEY_YES	2
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_STRICT_HOSTKEY_ASK	3

/* ObscureKeystrokes parameters */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_KEYSTROKE_DEFAULT_INTERVAL_MS	20
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_KEYSTROKE_CHAFF_MIN_MS		1024
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_KEYSTROKE_CHAFF_RNG_MS		2048

#ವ್ಯಾಖ್ಯಾನಿಸು SSH_KEEPALIVES_OFF		0
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_KEEPALIVES_TRANSPORT	1
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_KEEPALIVES_ALL		2

ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *kex_default_pk_alg(ಶೂನ್ಯ);
ಅಕ್ಷರ	*ssh_connection_hash(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *thishost, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *portstr, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *user, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *jump_host);
ಶೂನ್ಯ     initialize_options(Options *);
ಪೂರ್ಣಾಂಕ      fill_default_options(Options *);
ಶೂನ್ಯ	 fill_default_options_for_canonicalization(Options *);
ಶೂನ್ಯ	 free_options(Options *o);
ಪೂರ್ಣಾಂಕ	 process_config_ಸಾಲು(Options *, ರಚನೆ passwd *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ *, ಪೂರ್ಣಾಂಕ);
ಪೂರ್ಣಾಂಕ	 read_config_file(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ರಚನೆ passwd *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, Options *, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ *);
ಪೂರ್ಣಾಂಕ	 parse_forward(ರಚನೆ Forward *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ);
ಪೂರ್ಣಾಂಕ	 ssh_valid_hostname(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಪೂರ್ಣಾಂಕ	 ssh_valid_ruser(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಪೂರ್ಣಾಂಕ	 parse_jump(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, Options *, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ);
ಪೂರ್ಣಾಂಕ	 parse_ssh_uri(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಅಕ್ಷರ **, ಅಕ್ಷರ **, ಪೂರ್ಣಾಂಕ *);
ಪೂರ್ಣಾಂಕ	 default_ssh_ಪೋರ್ಟ್(ಶೂನ್ಯ);
ಪೂರ್ಣಾಂಕ	 option_clear_or_none(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಪೂರ್ಣಾಂಕ	 config_has_permitted_cnames(Options *);
ಶೂನ್ಯ	 dump_client_config(Options *o, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host);

ಶೂನ್ಯ	 ಕೂಡಿಸು_local_forward(Options *, ಸ್ಥಿರಾಂಕ ರಚನೆ Forward *);
ಶೂನ್ಯ	 ಕೂಡಿಸು_remote_forward(Options *, ಸ್ಥಿರಾಂಕ ರಚನೆ Forward *);
ಶೂನ್ಯ	 ಕೂಡಿಸು_ತಟಸ್ಥ_file(Options *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ);
ಶೂನ್ಯ	 ಕೂಡಿಸು_certificate_file(Options *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ);

#ಆದರೆ_ಅಂತ್ಯ				/* READCONF_H */
