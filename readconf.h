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

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ READCONF_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ READCONF_H

/* Data structure for representing option data. */

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_MAX_HOSTS_FILES	32
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਰਸਤਾ_MAX_SUN		(ਆਕਾਰ((ਬਣਤਰ sockaddr_un *)0)->sun_ਰਸਤਾ)

ਬਣਤਰ allowed_cname {
	ਅੱਖਰ *ਸਰੋਤ_list;
	ਅੱਖਰ *ਨਿਸ਼ਾਨਾ_list;
};

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ {
	ਅੱਖਰ   *host_arg;	/* Host arg as specified on command line. */
	ਪੂਰਨ     forward_agent;	/* Forward authentication agent. */
	ਅੱਖਰ   *forward_agent_sock_ਰਸਤਾ; /* Optional path of the agent. */
	ਪੂਰਨ     forward_x11;	/* Forward X11 display. */
	ਪੂਰਨ     forward_x11_timeout;	/* Expiration for Cookies */
	ਪੂਰਨ     forward_x11_trusted;	/* Trust Forward X11 display. */
	ਪੂਰਨ     exit_on_forward_failure;	/* Exit if bind(2) fails for -L/-R */
	ਅੱਖਰ   *xauth_location;	/* Location for xauth program */
	ਬਣਤਰ ForwardOptions fwd_opts;	/* forwarding options */
	ਪੂਰਨ     pubkey_authentication;	/* Try ssh2 pubkey authentication. */
	ਪੂਰਨ     hostbased_authentication;	/* ssh2's rhosts_rsa */
	ਪੂਰਨ     gss_authentication;	/* Try GSS authentication */
	ਪੂਰਨ     gss_deleg_creds;	/* Delegate GSS credentials */
	ਪੂਰਨ     password_authentication;	/* Try password
						 * authentication. */
	ਪੂਰਨ     kbd_interactive_authentication; /* Try keyboard-interactive auth. */
	ਅੱਖਰ	*kbd_interactive_devices; /* Keyboard-interactive auth devices. */
	ਪੂਰਨ     batch_ਬਹੁਲਕ;	/* Batch mode: do not ask for passwords. */
	ਪੂਰਨ     check_host_ip;	/* Also keep track of keys for IP address */
	ਪੂਰਨ     strict_host_ਕੁੰਜੀ_checking;	/* Strict host key checking. */
	ਪੂਰਨ     compression;	/* Compress packets in both directions. */
	ਪੂਰਨ     tcp_keep_alive;	/* Set SO_KEEPALIVE. */
	ਪੂਰਨ	ip_qos_interactive;	/* DSCP value for interactive */
	ਪੂਰਨ	ip_qos_bulk;		/* DSCP value for bulk traffic */
	SyslogFacility log_facility;	/* Facility for system logging. */
	LogLevel log_level;	/* Level for logging. */
	u_int	ਅੰਕ_log_verbose;	/* Verbose log overrides */
	ਅੱਖਰ   **log_verbose;
	ਪੂਰਨ     ਪੋਰਟ;		/* Port to connect. */
	ਪੂਰਨ     ਪਤਾ_family;
	ਪੂਰਨ     connection_attempts;	/* Max attempts (seconds) before
					 * giving up */
	ਪੂਰਨ     connection_timeout;	/* Max time (seconds) before
					 * aborting connection attempt */
	ਪੂਰਨ     ਸੰਖਿਆ_ਦਾ_password_prompts;	/* Max number of password
						 * prompts. */
	ਅੱਖਰ   *ciphers;	/* SSH2 ciphers in order of preference. */
	ਅੱਖਰ   *macs;		/* SSH2 macs in order of preference. */
	ਅੱਖਰ   *hostkeyalgorithms;	/* SSH2 server key types in order of preference. */
	ਅੱਖਰ   *kex_algorithms;	/* SSH2 kex methods in order of preference. */
	ਪੂਰਨ	kex_algorithms_ਸੈੱਟ; /* KexAlgorithms was set by the user */
	ਅੱਖਰ   *ca_sign_algorithms;	/* Allowed CA signature algorithms */
	ਅੱਖਰ   *hostname;	/* Real host to connect. */
	ਅੱਖਰ   *ਟੈਗ;		/* Configuration tag name. */
	ਅੱਖਰ   *host_ਕੁੰਜੀ_alias;	/* hostname alias for .ssh/known_hosts */
	ਅੱਖਰ   *proxy_command;	/* Proxy command for connecting the host. */
	ਅੱਖਰ   *user;		/* User to log in as. */
	ਪੂਰਨ     escape_char;	/* Escape character; -2 = none */

	u_int	ਅੰਕ_system_hostfiles;	/* Paths for /etc/ssh/ssh_known_hosts */
	ਅੱਖਰ   *system_hostfiles[SSH_MAX_HOSTS_FILES];
	u_int	ਅੰਕ_user_hostfiles;	/* Path for $HOME/.ssh/known_hosts */
	ਅੱਖਰ   *user_hostfiles[SSH_MAX_HOSTS_FILES];
	ਅੱਖਰ   *preferred_authentications;
	ਅੱਖਰ   *bind_ਪਤਾ;	/* local socket address for connection to sshd */
	ਅੱਖਰ   *bind_interface;	/* local interface for bind address */
	ਅੱਖਰ   *pkcs11_provider; /* PKCS#11 provider */
	ਅੱਖਰ   *sk_provider; /* Security key provider */
	ਪੂਰਨ	verify_host_ਕੁੰਜੀ_dns;	/* Verify host key using DNS */

	ਪੂਰਨ     ਅੰਕ_ਪਛਾਣ_ਤੱਤ_files;	/* Number of files for identities. */
	ਅੱਖਰ   *ਪਛਾਣ_ਤੱਤ_files[SSH_MAX_ਪਛਾਣ_ਤੱਤ_FILES];
	ਪੂਰਨ    ਪਛਾਣ_ਤੱਤ_file_userprovided[SSH_MAX_ਪਛਾਣ_ਤੱਤ_FILES];
	ਬਣਤਰ sshkey *ਪਛਾਣ_ਤੱਤ_ਕੁੰਜੀਆਂ[SSH_MAX_ਪਛਾਣ_ਤੱਤ_FILES];

	ਪੂਰਨ	ਅੰਕ_certificate_files; /* Number of extra certificates for ssh. */
	ਅੱਖਰ	*certificate_files[SSH_MAX_CERTIFICATE_FILES];
	ਪੂਰਨ	certificate_file_userprovided[SSH_MAX_CERTIFICATE_FILES];
	ਬਣਤਰ sshkey *certificates[SSH_MAX_CERTIFICATE_FILES];

	ਪੂਰਨ	ਜੋੜੋ_ਕੁੰਜੀਆਂ_ਮੰਜ਼ਿਲ_agent;
	ਪੂਰਨ	ਜੋੜੋ_ਕੁੰਜੀਆਂ_ਮੰਜ਼ਿਲ_agent_lifespan;
	ਅੱਖਰ   *ਪਛਾਣ_ਤੱਤ_agent;		/* Optional path to ssh-agent socket */

	/* Local TCP/IP forward requests. */
	ਪੂਰਨ     ਅੰਕ_local_forwards;
	ਬਣਤਰ Forward *local_forwards;

	/* Remote TCP/IP forward requests. */
	ਪੂਰਨ     ਅੰਕ_remote_forwards;
	ਬਣਤਰ Forward *remote_forwards;
	ਪੂਰਨ	clear_forwardings;

	/* Restrict remote dynamic forwarding */
	ਅੱਖਰ  **permitted_remote_opens;
	u_int	ਅੰਕ_permitted_remote_opens;

	/* stdio forwarding (-W) host and port */
	ਅੱਖਰ   *stdio_forward_host;
	ਪੂਰਨ	stdio_forward_ਪੋਰਟ;

	ਪੂਰਨ	enable_ssh_keysign;
	int64_t rekey_ਹੱਦਬੰਦੀ;
	ਪੂਰਨ	rekey_interval;
	ਪੂਰਨ	no_host_authentication_for_localhost;
	ਪੂਰਨ	identities_only;
	ਪੂਰਨ	server_alive_interval;
	ਪੂਰਨ	server_alive_ਗਿਣਤੀ_max;

	u_int	ਅੰਕ_send_env;
	ਅੱਖਰ	**send_env;
	u_int	ਅੰਕ_setenv;
	ਅੱਖਰ	**setenv;

	ਅੱਖਰ	*control_ਰਸਤਾ;
	ਪੂਰਨ	control_master;
	ਪੂਰਨ     control_persist; /* ControlPersist flag */
	ਪੂਰਨ     control_persist_timeout; /* ControlPersist timeout (seconds) */

	ਪੂਰਨ	hash_ਗਿਆਤ_hosts;

	ਪੂਰਨ	tun_open;	/* tun(4) */
	ਪੂਰਨ     tun_local;	/* force tun device (optional) */
	ਪੂਰਨ     tun_remote;	/* force tun device (optional) */

	ਅੱਖਰ	*local_command;
	ਪੂਰਨ	permit_local_command;
	ਅੱਖਰ	*remote_command;
	ਪੂਰਨ	visual_host_ਕੁੰਜੀ;

	ਪੂਰਨ	request_tty;
	ਪੂਰਨ	session_type;
	ਪੂਰਨ	stdin_null;
	ਪੂਰਨ	fork_after_authentication;

	ਪੂਰਨ	proxy_use_fdpass;

	ਪੂਰਨ	ਅੰਕ_canonical_domains;
	ਅੱਖਰ	**canonical_domains;
	ਪੂਰਨ	canonicalize_hostname;
	ਪੂਰਨ	canonicalize_max_dots;
	ਪੂਰਨ	canonicalize_fallback_local;
	ਪੂਰਨ	ਅੰਕ_permitted_cnames;
	ਬਣਤਰ allowed_cname *permitted_cnames;

	u_int	ਅੰਕ_revoked_host_ਕੁੰਜੀਆਂ;
	ਅੱਖਰ	**revoked_host_ਕੁੰਜੀਆਂ;

	ਪੂਰਨ	 fingerprint_hash;

	ਪੂਰਨ	 update_hostkeys; /* one of SSH_UPDATE_HOSTKEYS_* */

	ਅੱਖਰ   *hostbased_accepted_algos;
	ਅੱਖਰ   *pubkey_accepted_algos;

	ਅੱਖਰ   *jump_user;
	ਅੱਖਰ   *jump_host;
	ਪੂਰਨ	jump_ਪੋਰਟ;
	ਅੱਖਰ   *jump_extra;

	ਅੱਖਰ   *ਗਿਆਤ_hosts_command;

	ਪੂਰਨ	required_rsa_ਮਾਪ;	/* minimum size of RSA keys */
	ਪੂਰਨ	enable_escape_commandline;	/* ~C commandline */
	ਪੂਰਨ	obscure_keystroke_timing_interval;
	ਪੂਰਨ	warn_weak_crypto;

	ਅੱਖਰ	**channel_timeouts;	/* inactivity timeout by channel type */
	u_int	ਅੰਕ_channel_timeouts;

	ਅੱਖਰ	*ਸੰਸਕਰਣ_addendum;

	ਅੱਖਰ	*ignored_unknown; /* Pattern list of unknown tokens to ignore */
}       Options;

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_PUBKEY_AUTH_NO	0x00
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_PUBKEY_AUTH_UNBOUND	0x01
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_PUBKEY_AUTH_HBOUND	0x02
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_PUBKEY_AUTH_ALL	0x03

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_CANONICALISE_NO	0
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_CANONICALISE_YES	1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_CANONICALISE_ALWAYS	2

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCTL_MASTER_NO	0
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCTL_MASTER_YES	1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCTL_MASTER_AUTO	2
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCTL_MASTER_ASK	3
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCTL_MASTER_AUTO_ASK	4

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ REQUEST_TTY_AUTO	0
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ REQUEST_TTY_NO		1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ REQUEST_TTY_YES		2
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ REQUEST_TTY_FORCE	3

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SESSION_TYPE_NONE	0
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SESSION_TYPE_SUBSYSTEM	1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SESSION_TYPE_DEFAULT	2

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_CHECKPERM	1  /* check permissions on config file */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_USERCONF	2  /* user provided config file not system */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_FINAL		4  /* Final pass over config, after canon. */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_NEVERMATCH	8  /* Match/Host never matches; internal only */

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_UPDATE_HOSTKEYS_NO	0
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_UPDATE_HOSTKEYS_YES	1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_UPDATE_HOSTKEYS_ASK	2

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_STRICT_HOSTKEY_OFF	0
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_STRICT_HOSTKEY_NEW	1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_STRICT_HOSTKEY_YES	2
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_STRICT_HOSTKEY_ASK	3

/* ObscureKeystrokes parameters */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_KEYSTROKE_DEFAULT_INTERVAL_MS	20
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_KEYSTROKE_CHAFF_MIN_MS		1024
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_KEYSTROKE_CHAFF_RNG_MS		2048

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_KEEPALIVES_OFF		0
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_KEEPALIVES_TRANSPORT	1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_KEEPALIVES_ALL		2

ਅਚਲ ਅੱਖਰ *kex_default_pk_alg(ਖਾਲੀ);
ਅੱਖਰ	*ssh_connection_hash(ਅਚਲ ਅੱਖਰ *thishost, ਅਚਲ ਅੱਖਰ *host,
    ਅਚਲ ਅੱਖਰ *portstr, ਅਚਲ ਅੱਖਰ *user, ਅਚਲ ਅੱਖਰ *jump_host);
ਖਾਲੀ     initialize_options(Options *);
ਪੂਰਨ      fill_default_options(Options *);
ਖਾਲੀ	 fill_default_options_for_canonicalization(Options *);
ਖਾਲੀ	 free_options(Options *o);
ਪੂਰਨ	 process_config_ਸਤਰ(Options *, ਬਣਤਰ passwd *, ਅਚਲ ਅੱਖਰ *,
    ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਪੂਰਨ, ਪੂਰਨ *, ਪੂਰਨ);
ਪੂਰਨ	 read_config_file(ਅਚਲ ਅੱਖਰ *, ਬਣਤਰ passwd *, ਅਚਲ ਅੱਖਰ *,
    ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, Options *, ਪੂਰਨ, ਪੂਰਨ *);
ਪੂਰਨ	 parse_forward(ਬਣਤਰ Forward *, ਅਚਲ ਅੱਖਰ *, ਪੂਰਨ, ਪੂਰਨ);
ਪੂਰਨ	 ssh_valid_hostname(ਅਚਲ ਅੱਖਰ *);
ਪੂਰਨ	 ssh_valid_ruser(ਅਚਲ ਅੱਖਰ *);
ਪੂਰਨ	 parse_jump(ਅਚਲ ਅੱਖਰ *, Options *, ਪੂਰਨ, ਪੂਰਨ);
ਪੂਰਨ	 parse_ssh_uri(ਅਚਲ ਅੱਖਰ *, ਅੱਖਰ **, ਅੱਖਰ **, ਪੂਰਨ *);
ਪੂਰਨ	 default_ssh_ਪੋਰਟ(ਖਾਲੀ);
ਪੂਰਨ	 option_clear_or_none(ਅਚਲ ਅੱਖਰ *);
ਪੂਰਨ	 config_has_permitted_cnames(Options *);
ਖਾਲੀ	 dump_client_config(Options *o, ਅਚਲ ਅੱਖਰ *host);

ਖਾਲੀ	 ਜੋੜੋ_local_forward(Options *, ਅਚਲ ਬਣਤਰ Forward *);
ਖਾਲੀ	 ਜੋੜੋ_remote_forward(Options *, ਅਚਲ ਬਣਤਰ Forward *);
ਖਾਲੀ	 ਜੋੜੋ_ਪਛਾਣ_ਤੱਤ_file(Options *, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਪੂਰਨ);
ਖਾਲੀ	 ਜੋੜੋ_certificate_file(Options *, ਅਚਲ ਅੱਖਰ *, ਪੂਰਨ);

#ਜੇ_ਅੰਤ				/* READCONF_H */
