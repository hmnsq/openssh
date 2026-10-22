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
#define PATH_MAX_SUN		(parimaa_na((sa_nracanaa sockaddr_un *)0)->sun_path)

sa_nracanaa allowed_cname {
	var_na *source_list;
	var_na *target_list;
};

typedef sa_nracanaa {
	var_na   *host_arg;	/* Host arg as specified on command line. */
	ကိန်းပြည့်     forward_agent;	/* Forward authentication agent. */
	var_na   *forward_agent_sock_path; /* Optional path of the agent. */
	ကိန်းပြည့်     forward_x11;	/* Forward X11 display. */
	ကိန်းပြည့်     forward_x11_timeout;	/* Expiration for Cookies */
	ကိန်းပြည့်     forward_x11_trusted;	/* Trust Forward X11 display. */
	ကိန်းပြည့်     exit_on_forward_failure;	/* Exit if bind(2) fails for -L/-R */
	var_na   *xauth_location;	/* Location for xauth program */
	sa_nracanaa ForwardOptions fwd_opts;	/* forwarding options */
	ကိန်းပြည့်     pubkey_authentication;	/* Try ssh2 pubkey authentication. */
	ကိန်းပြည့်     hostbased_authentication;	/* ssh2's rhosts_rsa */
	ကိန်းပြည့်     gss_authentication;	/* Try GSS authentication */
	ကိန်းပြည့်     gss_deleg_creds;	/* Delegate GSS credentials */
	ကိန်းပြည့်     password_authentication;	/* Try password
						 * authentication. */
	ကိန်းပြည့်     kbd_interactive_authentication; /* Try keyboard-interactive auth. */
	var_na	*kbd_interactive_devices; /* Keyboard-interactive auth devices. */
	ကိန်းပြည့်     batch_mode;	/* Batch mode: do not ask for passwords. */
	ကိန်းပြည့်     check_host_ip;	/* Also keep track of keys for IP address */
	ကိန်းပြည့်     strict_host_key_checking;	/* Strict host key checking. */
	ကိန်းပြည့်     compression;	/* Compress packets in both directions. */
	ကိန်းပြည့်     tcp_keep_alive;	/* Set SO_KEEPALIVE. */
	ကိန်းပြည့်	ip_qos_interactive;	/* DSCP value for interactive */
	ကိန်းပြည့်	ip_qos_bulk;		/* DSCP value for bulk traffic */
	SyslogFacility log_facility;	/* Facility for system logging. */
	LogLevel log_level;	/* Level for logging. */
	u_int	num_log_verbose;	/* Verbose log overrides */
	var_na   **log_verbose;
	ကိန်းပြည့်     port;		/* Port to connect. */
	ကိန်းပြည့်     address_family;
	ကိန်းပြည့်     connection_attempts;	/* Max attempts (seconds) before
					 * giving up */
	ကိန်းပြည့်     connection_timeout;	/* Max time (seconds) before
					 * aborting connection attempt */
	ကိန်းပြည့်     number_of_password_prompts;	/* Max number of password
						 * prompts. */
	var_na   *ciphers;	/* SSH2 ciphers in order of preference. */
	var_na   *macs;		/* SSH2 macs in order of preference. */
	var_na   *hostkeyalgorithms;	/* SSH2 server key types in order of preference. */
	var_na   *kex_algorithms;	/* SSH2 kex methods in order of preference. */
	ကိန်းပြည့်	kex_algorithms_set; /* KexAlgorithms was set by the user */
	var_na   *ca_sign_algorithms;	/* Allowed CA signature algorithms */
	var_na   *hostname;	/* Real host to connect. */
	var_na   *tag;		/* Configuration tag name. */
	var_na   *host_key_alias;	/* hostname alias for .ssh/known_hosts */
	var_na   *proxy_command;	/* Proxy command for connecting the host. */
	var_na   *user;		/* User to log in as. */
	ကိန်းပြည့်     escape_char;	/* Escape character; -2 = none */

	u_int	num_system_hostfiles;	/* Paths for /etc/ssh/ssh_known_hosts */
	var_na   *system_hostfiles[SSH_MAX_HOSTS_FILES];
	u_int	num_user_hostfiles;	/* Path for $HOME/.ssh/known_hosts */
	var_na   *user_hostfiles[SSH_MAX_HOSTS_FILES];
	var_na   *preferred_authentications;
	var_na   *bind_address;	/* local socket address for connection to sshd */
	var_na   *bind_interface;	/* local interface for bind address */
	var_na   *pkcs11_provider; /* PKCS#11 provider */
	var_na   *sk_provider; /* Security key provider */
	ကိန်းပြည့်	verify_host_key_dns;	/* Verify host key using DNS */

	ကိန်းပြည့်     num_identity_files;	/* Number of files for identities. */
	var_na   *identity_files[SSH_MAX_IDENTITY_FILES];
	ကိန်းပြည့်    identity_file_userprovided[SSH_MAX_IDENTITY_FILES];
	sa_nracanaa sshkey *identity_keys[SSH_MAX_IDENTITY_FILES];

	ကိန်းပြည့်	num_certificate_files; /* Number of extra certificates for ssh. */
	var_na	*certificate_files[SSH_MAX_CERTIFICATE_FILES];
	ကိန်းပြည့်	certificate_file_userprovided[SSH_MAX_CERTIFICATE_FILES];
	sa_nracanaa sshkey *certificates[SSH_MAX_CERTIFICATE_FILES];

	ကိန်းပြည့်	add_keys_to_agent;
	ကိန်းပြည့်	add_keys_to_agent_lifespan;
	var_na   *identity_agent;		/* Optional path to ssh-agent socket */

	/* Local TCP/IP forward requests. */
	ကိန်းပြည့်     num_local_forwards;
	sa_nracanaa Forward *local_forwards;

	/* Remote TCP/IP forward requests. */
	ကိန်းပြည့်     num_remote_forwards;
	sa_nracanaa Forward *remote_forwards;
	ကိန်းပြည့်	clear_forwardings;

	/* Restrict remote dynamic forwarding */
	var_na  **permitted_remote_opens;
	u_int	num_permitted_remote_opens;

	/* stdio forwarding (-W) host and port */
	var_na   *stdio_forward_host;
	ကိန်းပြည့်	stdio_forward_port;

	ကိန်းပြည့်	enable_ssh_keysign;
	int64_t rekey_limit;
	ကိန်းပြည့်	rekey_interval;
	ကိန်းပြည့်	no_host_authentication_for_localhost;
	ကိန်းပြည့်	identities_only;
	ကိန်းပြည့်	server_alive_interval;
	ကိန်းပြည့်	server_alive_count_max;

	u_int	num_send_env;
	var_na	**send_env;
	u_int	num_setenv;
	var_na	**setenv;

	var_na	*control_path;
	ကိန်းပြည့်	control_master;
	ကိန်းပြည့်     control_persist; /* ControlPersist flag */
	ကိန်းပြည့်     control_persist_timeout; /* ControlPersist timeout (seconds) */

	ကိန်းပြည့်	hash_known_hosts;

	ကိန်းပြည့်	tun_open;	/* tun(4) */
	ကိန်းပြည့်     tun_local;	/* force tun device (optional) */
	ကိန်းပြည့်     tun_remote;	/* force tun device (optional) */

	var_na	*local_command;
	ကိန်းပြည့်	permit_local_command;
	var_na	*remote_command;
	ကိန်းပြည့်	visual_host_key;

	ကိန်းပြည့်	request_tty;
	ကိန်းပြည့်	session_type;
	ကိန်းပြည့်	stdin_null;
	ကိန်းပြည့်	fork_after_authentication;

	ကိန်းပြည့်	proxy_use_fdpass;

	ကိန်းပြည့်	num_canonical_domains;
	var_na	**canonical_domains;
	ကိန်းပြည့်	canonicalize_hostname;
	ကိန်းပြည့်	canonicalize_max_dots;
	ကိန်းပြည့်	canonicalize_fallback_local;
	ကိန်းပြည့်	num_permitted_cnames;
	sa_nracanaa allowed_cname *permitted_cnames;

	u_int	num_revoked_host_keys;
	var_na	**revoked_host_keys;

	ကိန်းပြည့်	 fingerprint_hash;

	ကိန်းပြည့်	 update_hostkeys; /* one of SSH_UPDATE_HOSTKEYS_* */

	var_na   *hostbased_accepted_algos;
	var_na   *pubkey_accepted_algos;

	var_na   *jump_user;
	var_na   *jump_host;
	ကိန်းပြည့်	jump_port;
	var_na   *jump_extra;

	var_na   *known_hosts_command;

	ကိန်းပြည့်	required_rsa_size;	/* minimum size of RSA keys */
	ကိန်းပြည့်	enable_escape_commandline;	/* ~C commandline */
	ကိန်းပြည့်	obscure_keystroke_timing_interval;
	ကိန်းပြည့်	warn_weak_crypto;

	var_na	**channel_timeouts;	/* inactivity timeout by channel type */
	u_int	num_channel_timeouts;

	var_na	*version_addendum;

	var_na	*ignored_unknown; /* Pattern list of unknown tokens to ignore */
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

const var_na *kex_default_pk_alg(void);
var_na	*ssh_connection_hash(const var_na *thishost, const var_na *host,
    const var_na *portstr, const var_na *user, const var_na *jump_host);
void     initialize_options(Options *);
ကိန်းပြည့်      fill_default_options(Options *);
void	 fill_default_options_for_canonicalization(Options *);
void	 free_options(Options *o);
ကိန်းပြည့်	 process_config_line(Options *, sa_nracanaa passwd *, const var_na *,
    const var_na *, const var_na *, var_na *, const var_na *, ကိန်းပြည့်, ကိန်းပြည့် *, ကိန်းပြည့်);
ကိန်းပြည့်	 read_config_file(const var_na *, sa_nracanaa passwd *, const var_na *,
    const var_na *, const var_na *, Options *, ကိန်းပြည့်, ကိန်းပြည့် *);
ကိန်းပြည့်	 parse_forward(sa_nracanaa Forward *, const var_na *, ကိန်းပြည့်, ကိန်းပြည့်);
ကိန်းပြည့်	 ssh_valid_hostname(const var_na *);
ကိန်းပြည့်	 ssh_valid_ruser(const var_na *);
ကိန်းပြည့်	 parse_jump(const var_na *, Options *, ကိန်းပြည့်, ကိန်းပြည့်);
ကိန်းပြည့်	 parse_ssh_uri(const var_na *, var_na **, var_na **, ကိန်းပြည့် *);
ကိန်းပြည့်	 default_ssh_port(void);
ကိန်းပြည့်	 option_clear_or_none(const var_na *);
ကိန်းပြည့်	 config_has_permitted_cnames(Options *);
void	 dump_client_config(Options *o, const var_na *host);

void	 add_local_forward(Options *, const sa_nracanaa Forward *);
void	 add_remote_forward(Options *, const sa_nracanaa Forward *);
void	 add_identity_file(Options *, const var_na *, const var_na *, ကိန်းပြည့်);
void	 add_certificate_file(Options *, const var_na *, ကိန်းပြည့်);

#endif				/* READCONF_H */
