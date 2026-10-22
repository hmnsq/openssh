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
#define PATH_MAX_SUN		(حجم((بنية sockaddr_un *)0)->sun_path)

بنية allowed_cname {
	حرف *source_list;
	حرف *target_list;
};

تعريفنوع بنية {
	حرف   *host_arg;	/* Host arg as specified on command line. */
	صحيح     forward_agent;	/* Forward authentication agent. */
	حرف   *forward_agent_sock_path; /* Optional path of the agent. */
	صحيح     forward_x11;	/* Forward X11 display. */
	صحيح     forward_x11_timeout;	/* Expiration for Cookies */
	صحيح     forward_x11_trusted;	/* Trust Forward X11 display. */
	صحيح     exit_on_forward_failure;	/* Exit if bind(2) fails for -L/-R */
	حرف   *xauth_location;	/* Location for xauth program */
	بنية ForwardOptions fwd_opts;	/* forwarding options */
	صحيح     pubkey_authentication;	/* Try ssh2 pubkey authentication. */
	صحيح     hostbased_authentication;	/* ssh2's rhosts_rsa */
	صحيح     gss_authentication;	/* Try GSS authentication */
	صحيح     gss_deleg_creds;	/* Delegate GSS credentials */
	صحيح     password_authentication;	/* Try password
						 * authentication. */
	صحيح     kbd_interactive_authentication; /* Try keyboard-interactive auth. */
	حرف	*kbd_interactive_devices; /* Keyboard-interactive auth devices. */
	صحيح     batch_mode;	/* Batch mode: do not ask for passwords. */
	صحيح     check_host_ip;	/* Also keep track of keys for IP address */
	صحيح     strict_host_مفتاح_checking;	/* Strict host key checking. */
	صحيح     compression;	/* Compress packets in both directions. */
	صحيح     tcp_keep_alive;	/* Set SO_KEEPALIVE. */
	صحيح	ip_qos_interactive;	/* DSCP value for interactive */
	صحيح	ip_qos_bulk;		/* DSCP value for bulk traffic */
	SyslogFacility log_facility;	/* Facility for system logging. */
	LogLevel log_level;	/* Level for logging. */
	u_int	رقم_log_verbose;	/* Verbose log overrides */
	حرف   **log_verbose;
	صحيح     port;		/* Port to connect. */
	صحيح     address_family;
	صحيح     connection_attempts;	/* Max attempts (seconds) before
					 * giving up */
	صحيح     connection_timeout;	/* Max time (seconds) before
					 * aborting connection attempt */
	صحيح     العدد_of_password_prompts;	/* Max number of password
						 * prompts. */
	حرف   *ciphers;	/* SSH2 ciphers in order of preference. */
	حرف   *macs;		/* SSH2 macs in order of preference. */
	حرف   *hostkeyalgorithms;	/* SSH2 server key types in order of preference. */
	حرف   *kex_algorithms;	/* SSH2 kex methods in order of preference. */
	صحيح	kex_algorithms_set; /* KexAlgorithms was set by the user */
	حرف   *ca_sign_algorithms;	/* Allowed CA signature algorithms */
	حرف   *hostname;	/* Real host to connect. */
	حرف   *tag;		/* Configuration tag name. */
	حرف   *host_مفتاح_alias;	/* hostname alias for .ssh/known_hosts */
	حرف   *proxy_command;	/* Proxy command for connecting the host. */
	حرف   *user;		/* User to log in as. */
	صحيح     escape_char;	/* Escape character; -2 = none */

	u_int	رقم_system_hostfiles;	/* Paths for /etc/ssh/ssh_known_hosts */
	حرف   *system_hostfiles[SSH_MAX_HOSTS_FILES];
	u_int	رقم_user_hostfiles;	/* Path for $HOME/.ssh/known_hosts */
	حرف   *user_hostfiles[SSH_MAX_HOSTS_FILES];
	حرف   *preferred_authentications;
	حرف   *bind_address;	/* local socket address for connection to sshd */
	حرف   *bind_interface;	/* local interface for bind address */
	حرف   *pkcs11_provider; /* PKCS#11 provider */
	حرف   *sk_provider; /* Security key provider */
	صحيح	verify_host_مفتاح_dns;	/* Verify host key using DNS */

	صحيح     رقم_identity_files;	/* Number of files for identities. */
	حرف   *identity_files[SSH_MAX_IDENTITY_FILES];
	صحيح    identity_file_userprovided[SSH_MAX_IDENTITY_FILES];
	بنية sshkey *identity_مفاتيح[SSH_MAX_IDENTITY_FILES];

	صحيح	رقم_certificate_files; /* Number of extra certificates for ssh. */
	حرف	*certificate_files[SSH_MAX_CERTIFICATE_FILES];
	صحيح	certificate_file_userprovided[SSH_MAX_CERTIFICATE_FILES];
	بنية sshkey *certificates[SSH_MAX_CERTIFICATE_FILES];

	صحيح	add_مفاتيح_to_agent;
	صحيح	add_مفاتيح_to_agent_lifespan;
	حرف   *identity_agent;		/* Optional path to ssh-agent socket */

	/* Local TCP/IP forward requests. */
	صحيح     رقم_local_forwards;
	بنية Forward *local_forwards;

	/* Remote TCP/IP forward requests. */
	صحيح     رقم_remote_forwards;
	بنية Forward *remote_forwards;
	صحيح	clear_forwardings;

	/* Restrict remote dynamic forwarding */
	حرف  **permitted_remote_opens;
	u_int	رقم_permitted_remote_opens;

	/* stdio forwarding (-W) host and port */
	حرف   *stdio_forward_host;
	صحيح	stdio_forward_port;

	صحيح	enable_ssh_keysign;
	int64_t rekey_limit;
	صحيح	rekey_interval;
	صحيح	no_host_authentication_for_localhost;
	صحيح	identities_only;
	صحيح	server_alive_interval;
	صحيح	server_alive_تعداد_max;

	u_int	رقم_send_env;
	حرف	**send_env;
	u_int	رقم_setenv;
	حرف	**setenv;

	حرف	*control_path;
	صحيح	control_master;
	صحيح     control_persist; /* ControlPersist flag */
	صحيح     control_persist_timeout; /* ControlPersist timeout (seconds) */

	صحيح	hash_known_hosts;

	صحيح	tun_open;	/* tun(4) */
	صحيح     tun_local;	/* force tun device (optional) */
	صحيح     tun_remote;	/* force tun device (optional) */

	حرف	*local_command;
	صحيح	permit_local_command;
	حرف	*remote_command;
	صحيح	visual_host_مفتاح;

	صحيح	request_tty;
	صحيح	session_type;
	صحيح	stdin_null;
	صحيح	fork_after_authentication;

	صحيح	proxy_use_fdpass;

	صحيح	رقم_canonical_domains;
	حرف	**canonical_domains;
	صحيح	canonicalize_hostname;
	صحيح	canonicalize_max_dots;
	صحيح	canonicalize_fallback_local;
	صحيح	رقم_permitted_cnames;
	بنية allowed_cname *permitted_cnames;

	u_int	رقم_revoked_host_مفاتيح;
	حرف	**revoked_host_مفاتيح;

	صحيح	 fingerprint_hash;

	صحيح	 update_hostkeys; /* one of SSH_UPDATE_HOSTKEYS_* */

	حرف   *hostbased_accepted_algos;
	حرف   *pubkey_accepted_algos;

	حرف   *jump_user;
	حرف   *jump_host;
	صحيح	jump_port;
	حرف   *jump_extra;

	حرف   *known_hosts_command;

	صحيح	required_rsa_size;	/* minimum size of RSA keys */
	صحيح	enable_escape_commandline;	/* ~C commandline */
	صحيح	obscure_keystroke_timing_interval;
	صحيح	warn_weak_crypto;

	حرف	**channel_timeouts;	/* inactivity timeout by channel type */
	u_int	رقم_channel_timeouts;

	حرف	*version_addendum;

	حرف	*ignored_unknown; /* Pattern list of unknown tokens to ignore */
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

ثابت حرف *kex_default_pk_alg(فراغ);
حرف	*ssh_connection_hash(ثابت حرف *thishost, ثابت حرف *host,
    ثابت حرف *portstr, ثابت حرف *user, ثابت حرف *jump_host);
فراغ     initialize_options(Options *);
صحيح      fill_default_options(Options *);
فراغ	 fill_default_options_for_canonicalization(Options *);
فراغ	 free_options(Options *o);
صحيح	 process_config_سطر(Options *, بنية passwd *, ثابت حرف *,
    ثابت حرف *, ثابت حرف *, حرف *, ثابت حرف *, صحيح, صحيح *, صحيح);
صحيح	 read_config_file(ثابت حرف *, بنية passwd *, ثابت حرف *,
    ثابت حرف *, ثابت حرف *, Options *, صحيح, صحيح *);
صحيح	 parse_forward(بنية Forward *, ثابت حرف *, صحيح, صحيح);
صحيح	 ssh_valid_hostname(ثابت حرف *);
صحيح	 ssh_valid_ruser(ثابت حرف *);
صحيح	 parse_jump(ثابت حرف *, Options *, صحيح, صحيح);
صحيح	 parse_ssh_uri(ثابت حرف *, حرف **, حرف **, صحيح *);
صحيح	 default_ssh_port(فراغ);
صحيح	 option_clear_or_none(ثابت حرف *);
صحيح	 config_has_permitted_cnames(Options *);
فراغ	 dump_client_config(Options *o, ثابت حرف *host);

فراغ	 add_local_forward(Options *, ثابت بنية Forward *);
فراغ	 add_remote_forward(Options *, ثابت بنية Forward *);
فراغ	 add_identity_file(Options *, ثابت حرف *, ثابت حرف *, صحيح);
فراغ	 add_certificate_file(Options *, ثابت حرف *, صحيح);

#endif				/* READCONF_H */
