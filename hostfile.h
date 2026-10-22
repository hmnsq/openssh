/* $OpenBSD: hostfile.h,v 1.29 2021/01/26 00:51:30 djm Exp $ */

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */
#ifndef HOSTFILE_H
#define HOSTFILE_H

typedef ga_nanaa {
	HOST_OK, HOST_NEW, HOST_CHANGED, HOST_REVOKED, HOST_FOUND
}       HostStatus;

typedef ga_nanaa {
	MRK_ERROR, MRK_NONE, MRK_REVOKE, MRK_CA
}	HostkeyMarker;

sa_nracanaa hostkey_entry {
	var_na *host;
	var_na *file;
	u_long line;
	sa_nracanaa sshkey *key;
	HostkeyMarker marker;
	u_int note; /* caller-specific note/flag */
};
sa_nracanaa hostkeys {
	sa_nracanaa hostkey_entry *entries;
	u_int num_entries;
};

sa_nracanaa hostkeys *init_hostkeys(void);
void	 load_hostkeys(sa_nracanaa hostkeys *, const var_na *,
    const var_na *, u_int);
void	 load_hostkeys_file(sa_nracanaa hostkeys *, const var_na *,
    const var_na *, FILE *, u_int note);
void	 free_hostkeys(sa_nracanaa hostkeys *);

HostStatus check_key_in_hostkeys(sa_nracanaa hostkeys *, sa_nracanaa sshkey *,
    const sa_nracanaa hostkey_entry **);
ចំនួនគត់	 lookup_key_in_hostkeys_by_type(sa_nracanaa hostkeys *, ចំនួនគត់, ចំនួនគត់,
    const sa_nracanaa hostkey_entry **);
ចំនួនគត់	 lookup_marker_in_hostkeys(sa_nracanaa hostkeys *, ចំនួនគត់);

ចំនួនគត់	 hostfile_read_key(var_na **, u_int *, sa_nracanaa sshkey *);
ចំនួនគត់	 add_host_to_hostfile(const var_na *, const var_na *,
    const sa_nracanaa sshkey *, ចំនួនគត់);

ចំនួនគត់	 hostfile_replace_entries(const var_na *filename,
    const var_na *host, const var_na *ip, sa_nracanaa sshkey **keys, size_t nkeys,
    ចំនួនគត់ store_hash, ចំនួនគត់ quiet, ចំនួនគត់ hash_alg);

#define HASH_MAGIC	"|1|"
#define HASH_DELIM	'|'

#define CA_MARKER	"@cert-authority"
#define REVOKE_MARKER	"@revoked"

var_na	*host_hash(const var_na *, const var_na *, u_int);

/*
 * Iterate through a hostkeys file, optionally parsing keys and matching
 * hostnames. Allows access to the raw keyfile lines to allow
 * streaming edits to the file to take place.
 */
#define HKF_WANT_MATCH		(1)	/* return only matching hosts/addrs */
#define HKF_WANT_PARSE_KEY	(1<<1)	/* need key parsed */

#define HKF_STATUS_OK		0	/* Line parsed, didn't match host */
#define HKF_STATUS_INVALID	1	/* line had parse error */
#define HKF_STATUS_COMMENT	2	/* valid line contained no key */
#define HKF_STATUS_MATCHED	3	/* hostname or IP matched */

#define HKF_MATCH_HOST		(1)	/* hostname matched */
#define HKF_MATCH_IP		(1<<1)	/* address matched */
#define HKF_MATCH_HOST_HASHED	(1<<2)	/* hostname was hashed */
#define HKF_MATCH_IP_HASHED	(1<<3)	/* address was hashed */
/* XXX HKF_MATCH_KEY_TYPE? */

/*
 * The callback function receives this as an argument for each matching 
 * hostkey line. The callback may "steal" the 'key' field by setting it to NULL.
 * If a parse error occurred, then "hosts" and subsequent options may be NULL.
 */
sa_nracanaa hostkey_foreach_line {
	const var_na *path; /* Path of file */
	u_long linenum;	/* Line number */
	u_int status;	/* One of HKF_STATUS_* */
	u_int match;	/* Zero or more of HKF_MATCH_* OR'd together */
	var_na *line;	/* Entire key line; mutable by callback */
	ចំនួនគត់ marker;	/* CA/revocation markers; indicated by MRK_* value */
	const var_na *hosts; /* Raw hosts text, may be hashed or list multiple */
	const var_na *rawkey; /* Text of key and any comment following it */
	ចំនួនគត់ keytype;	/* Type of key; KEY_UNSPEC for invalid/comment lines */
	sa_nracanaa sshkey *key; /* Key, if parsed ok and HKF_WANT_MATCH_HOST set */
	const var_na *comment; /* Any comment following the key */
	u_int note;	/* caller-specified note copied from arguments */
};

/*
 * Callback fires for each line (or matching line if a HKF_WANT_* option
 * is set). The foreach loop will terminate if the callback returns a non-
 * zero exit status.
 */
typedef ចំនួនគត់ hostkeys_foreach_fn(sa_nracanaa hostkey_foreach_line *l, void *ctx);

/* Iterate over a hostkeys file */
ចំនួនគត់ hostkeys_foreach(const var_na *path,
    hostkeys_foreach_fn *callback, void *ctx,
    const var_na *host, const var_na *ip, u_int options, u_int note);
ចំនួនគត់ hostkeys_foreach_file(const var_na *path, FILE *f,
    hostkeys_foreach_fn *callback, void *ctx,
    const var_na *host, const var_na *ip, u_int options, u_int note);

void hostfile_create_user_ssh_dir(const var_na *, ចំនួនគត់);

#endif
