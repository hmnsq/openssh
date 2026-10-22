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

প্রকারনির্দেশ গণনা {
	HOST_OK, HOST_NEW, HOST_CHANGED, HOST_REVOKED, HOST_FOUND
}       HostStatus;

প্রকারনির্দেশ গণনা {
	MRK_ERROR, MRK_NONE, MRK_REVOKE, MRK_CA
}	HostkeyMarker;

সংরচনা hostkey_entry {
	ৱর্ণ *host;
	ৱর্ণ *file;
	u_long সাৰি;
	সংরচনা sshkey *চাবি;
	HostkeyMarker marker;
	u_int note; /* caller-specific note/flag */
};
সংরচনা hostkeys {
	সংরচনা hostkey_entry *entries;
	u_int অঙ্ক_entries;
};

সংরচনা hostkeys *init_hostkeys(শূন্য);
শূন্য	 load_hostkeys(সংরচনা hostkeys *, ধ্রুৱ ৱর্ণ *,
    ধ্রুৱ ৱর্ণ *, u_int);
শূন্য	 load_hostkeys_file(সংরচনা hostkeys *, ধ্রুৱ ৱর্ণ *,
    ধ্রুৱ ৱর্ণ *, FILE *, u_int note);
শূন্য	 free_hostkeys(সংরচনা hostkeys *);

HostStatus check_চাবি_in_hostkeys(সংরচনা hostkeys *, সংরচনা sshkey *,
    ধ্রুৱ সংরচনা hostkey_entry **);
পূর্ণাঙ্ক	 lookup_চাবি_in_hostkeys_by_type(সংরচনা hostkeys *, পূর্ণাঙ্ক, পূর্ণাঙ্ক,
    ধ্রুৱ সংরচনা hostkey_entry **);
পূর্ণাঙ্ক	 lookup_marker_in_hostkeys(সংরচনা hostkeys *, পূর্ণাঙ্ক);

পূর্ণাঙ্ক	 hostfile_read_চাবি(ৱর্ণ **, u_int *, সংরচনা sshkey *);
পূর্ণাঙ্ক	 add_host_to_hostfile(ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *,
    ধ্রুৱ সংরচনা sshkey *, পূর্ণাঙ্ক);

পূর্ণাঙ্ক	 hostfile_replace_entries(ধ্রুৱ ৱর্ণ *filename,
    ধ্রুৱ ৱর্ণ *host, ধ্রুৱ ৱর্ণ *ip, সংরচনা sshkey **চাবিগুলি, size_t nkeys,
    পূর্ণাঙ্ক store_hash, পূর্ণাঙ্ক quiet, পূর্ণাঙ্ক hash_alg);

#define HASH_MAGIC	"|1|"
#define HASH_DELIM	'|'

#define CA_MARKER	"@cert-authority"
#define REVOKE_MARKER	"@revoked"

ৱর্ণ	*host_hash(ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *, u_int);

/*
 * Iterate through a hostkeys file, optionally parsing keys and matching
 * hostnames. Allows access to the raw keyfile lines to allow
 * streaming edits to the file to take place.
 */
#define HKF_WANT_MATCH		(1)	/* return only matching hosts/addrs */
#define HKF_WANT_PARSE_চাবি	(1<<1)	/* need key parsed */

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
সংরচনা hostkey_foreach_সাৰি {
	ধ্রুৱ ৱর্ণ *path; /* Path of file */
	u_long linenum;	/* Line number */
	u_int status;	/* One of HKF_STATUS_* */
	u_int match;	/* Zero or more of HKF_MATCH_* OR'd together */
	ৱর্ণ *সাৰি;	/* Entire key line; mutable by callback */
	পূর্ণাঙ্ক marker;	/* CA/revocation markers; indicated by MRK_* value */
	ধ্রুৱ ৱর্ণ *hosts; /* Raw hosts text, may be hashed or list multiple */
	ধ্রুৱ ৱর্ণ *rawkey; /* Text of key and any comment following it */
	পূর্ণাঙ্ক keytype;	/* Type of key; KEY_UNSPEC for invalid/comment lines */
	সংরচনা sshkey *চাবি; /* Key, if parsed ok and HKF_WANT_MATCH_HOST set */
	ধ্রুৱ ৱর্ণ *comment; /* Any comment following the key */
	u_int note;	/* caller-specified note copied from arguments */
};

/*
 * Callback fires for each line (or matching line if a HKF_WANT_* option
 * is set). The foreach loop will terminate if the callback returns a non-
 * zero exit status.
 */
প্রকারনির্দেশ পূর্ণাঙ্ক hostkeys_foreach_fn(সংরচনা hostkey_foreach_সাৰি *l, শূন্য *ctx);

/* Iterate over a hostkeys file */
পূর্ণাঙ্ক hostkeys_foreach(ধ্রুৱ ৱর্ণ *path,
    hostkeys_foreach_fn *callback, শূন্য *ctx,
    ধ্রুৱ ৱর্ণ *host, ধ্রুৱ ৱর্ণ *ip, u_int options, u_int note);
পূর্ণাঙ্ক hostkeys_foreach_file(ধ্রুৱ ৱর্ণ *path, FILE *f,
    hostkeys_foreach_fn *callback, শূন্য *ctx,
    ধ্রুৱ ৱর্ণ *host, ধ্রুৱ ৱর্ণ *ip, u_int options, u_int note);

শূন্য hostfile_create_user_ssh_dir(ধ্রুৱ ৱর্ণ *, পূর্ণাঙ্ক);

#endif
