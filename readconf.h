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
#define PATH_MAX_SUN		(sizeof((struct sockaddr_un *)0)->sun_path)

struct allowed_cname {
	char *source_list;
	char *target_list;
};

typedef struct {
	char   *host_arg;	/* Host arg as specified on command line. */
	整数     forward_agent;	/* Forward authentication agent. */
	char   *forward_agent_sock_path; /* Optional path of the agent. */
	整数     forward_x11;	/* Forward X11 display. */
	整数     forward_x11_timeout;	/* Expiration for Cookies */
	整数     forward_x11_trusted;	/* Trust Forward X11 display. */
	整数     exit_on_forward_failure;	/* Exit if bind(2) fails for -L/-R */
	char   *xauth_location;	/* Location for xauth program */
	struct ForwardOptions fwd_opts;	/* forwarding options */
	整数     pubkey_authentication;	/* Try ssh2 pubkey authentication. */
	整数     hostbased_authentication;	/* ssh2's rhosts_rsa */
	整数     gss_authentication;	/* Try GSS authentication */
	整数     gss_deleg_creds;	/* Delegate GSS credentials */
	整数     password_authentication;	/* Try password
						 * authentication. */
	整数     kbd_interactive_authentication; /* Try keyboard-interactive auth. */
	char	*kbd_interactive_devices; /* Keyboard-interactive auth devices. */
	整数     batch_mode;	/* Batch mode: do not ask for passwords. */
	整数     check_host_ip;	/* Also keep track of keys for IP address */
	整数     strict_host_key_checking;	/* Strict host key checking. */
	整数     compression;	/* Compress packets in both directions. */
	整数     tcp_keep_alive;	/* Set SO_KEEPALIVE. */
	整数	ip_qos_interactive;	/* DSCP value for interactive */
	整数	ip_qos_bulk;		/* DSCP value for bulk traffic */
	SyslogFacility log_facility;	/* Facility for system logging. */
	LogLevel log_level;	/* Level for logging. */
	u_int	num_log_verbose;	/* Verbose log overrides */
	char   **log_verbose;
	整数     port;		/* Port to connect. */
	整数     address_family;
	整数     connection_attempts;	/* Max attempts (seconds) before
					 * giving up */
	整数     connection_timeout;	/* Max time (seconds) before
					 * aborting connection attempt */
	整数     number_of_password_prompts;	/* Max number of password
						 * prompts. */
	char   *ciphers;	/* SSH2 ciphers in order of preference. */
	char   *macs;		/* SSH2 macs in order of preference. */
	char   *hostkeyalgorithms;	/* SSH2 server key types in order of preference. */
	char   *kex_algorithms;	/* SSH2 kex methods in order of preference. */
	整数	kex_algorithms_set; /* KexAlgorithms was set by the user */
	char   *ca_sign_algorithms;	/* Allowed CA signature algorithms */
	char   *hostname;	/* Real host to connect. */
	char   *tag;		/* Configuration tag name. */
	char   *host_key_alias;	/* hostname alias for .ssh/known_hosts */
	char   *proxy_command;	/* Proxy command for connecting the host. */
	char   *user;		/* User to log in as. */
	整数     escape_char;	/* Escape character; -2 = none */

	u_int	num_system_hostfiles;	/* Paths for /etc/ssh/ssh_known_hosts */
	char   *system_hostfiles[SSH_MAX_HOSTS_FILES];
	u_int	num_user_hostfiles;	/* Path for $HOME/.ssh/known_hosts */
	char   *user_hostfiles[SSH_MAX_HOSTS_FILES];
	char   *preferred_authentications;
	char   *bind_address;	/* local socket address for connection to sshd */
	char   *bind_interface;	/* local interface for bind address */
	char   *pkcs11_provider; /* PKCS#11 provider */
	char   *sk_provider; /* Security key provider */
	整数	verify_host_key_dns;	/* Verify host key using DNS */

	整数     num_identity_files;	/* Number of files for identities. */
	char   *identity_files[SSH_MAX_IDENTITY_FILES];
	整数    identity_file_userprovided[SSH_MAX_IDENTITY_FILES];
	struct sshkey *identity_keys[SSH_MAX_IDENTITY_FILES];

	整数	num_certificate_files; /* Number of extra certificates for ssh. */
	char	*certificate_files[SSH_MAX_CERTIFICATE_FILES];
	整数	certificate_file_userprovided[SSH_MAX_CERTIFICATE_FILES];
	struct sshkey *certificates[SSH_MAX_CERTIFICATE_FILES];

	整数	add_keys_to_agent;
	整数	add_keys_to_agent_lifespan;
	char   *identity_agent;		/* Optional path to ssh-agent socket */

	/* Local TCP/IP forward requests. */
	整数     num_local_forwards;
	struct Forward *local_forwards;

	/* Remote TCP/IP forward requests. */
	整数     num_remote_forwards;
	struct Forward *remote_forwards;
	整数	clear_forwardings;

	/* Restrict remote dynamic forwarding */
	char  **permitted_remote_opens;
	u_int	num_permitted_remote_opens;

	/* stdio forwarding (-W) host and port */
	char   *stdio_forward_host;
	整数	stdio_forward_port;

	整数	enable_ssh_keysign;
	int64_t rekey_limit;
	整数	rekey_interval;
	整数	no_host_authentication_for_localhost;
	整数	identities_only;
	整数	server_alive_interval;
	整数	server_alive_count_max;

	u_int	num_send_env;
	char	**send_env;
	u_int	num_setenv;
	char	**setenv;

	char	*control_path;
	整数	control_master;
	整数     control_persist; /* ControlPersist flag */
	整数     control_persist_timeout; /* ControlPersist timeout (seconds) */

	整数	hash_known_hosts;

	整数	tun_open;	/* tun(4) */
	整数     tun_local;	/* force tun device (optional) */
	整数     tun_remote;	/* force tun device (optional) */

	char	*local_command;
	整数	permit_local_command;
	char	*remote_command;
	整数	visual_host_key;

	整数	request_tty;
	整数	session_type;
	整数	stdin_null;
	整数	fork_after_authentication;

	整数	proxy_use_fdpass;

	整数	num_canonical_domains;
	char	**canonical_domains;
	整数	canonicalize_hostname;
	整数	canonicalize_max_dots;
	整数	canonicalize_fallback_local;
	整数	num_permitted_cnames;
	struct allowed_cname *permitted_cnames;

	u_int	num_revoked_host_keys;
	char	**revoked_host_keys;

	整数	 fingerprint_hash;

	整数	 update_hostkeys; /* one of SSH_UPDATE_HOSTKEYS_* */

	char   *hostbased_accepted_algos;
	char   *pubkey_accepted_algos;

	char   *jump_user;
	char   *jump_host;
	整数	jump_port;
	char   *jump_extra;

	char   *known_hosts_command;

	整数	required_rsa_size;	/* minimum size of RSA keys */
	整数	enable_escape_commandline;	/* ~C commandline */
	整数	obscure_keystroke_timing_interval;
	整数	warn_weak_crypto;

	char	**channel_timeouts;	/* inactivity timeout by channel type */
	u_int	num_channel_timeouts;

	char	*version_addendum;

	char	*ignored_unknown; /* Pattern list of unknown tokens to ignore */
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

const char *kex_default_pk_alg(void);
char	*ssh_connection_hash(const char *thishost, const char *host,
    const char *portstr, const char *user, const char *jump_host);
void     initialize_options(Options *);
整数      fill_default_options(Options *);
void	 fill_default_options_for_canonicalization(Options *);
void	 free_options(Options *o);
整数	 process_config_line(Options *, struct passwd *, const char *,
    const char *, const char *, char *, const char *, 整数, 整数 *, 整数);
整数	 read_config_file(const char *, struct passwd *, const char *,
    const char *, const char *, Options *, 整数, 整数 *);
整数	 parse_forward(struct Forward *, const char *, 整数, 整数);
整数	 ssh_valid_hostname(const char *);
整数	 ssh_valid_ruser(const char *);
整数	 parse_jump(const char *, Options *, 整数, 整数);
整数	 parse_ssh_uri(const char *, char **, char **, 整数 *);
整数	 default_ssh_port(void);
整数	 option_clear_or_none(const char *);
整数	 config_has_permitted_cnames(Options *);
void	 dump_client_config(Options *o, const char *host);

void	 add_local_forward(Options *, const struct Forward *);
void	 add_remote_forward(Options *, const struct Forward *);
void	 add_identity_file(Options *, const char *, const char *, 整数);
void	 add_certificate_file(Options *, const char *, 整数);

#endif				/* READCONF_H */
