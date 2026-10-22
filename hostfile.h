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

প্রকারলেখ গণনা {
	HOST_OK, HOST_NEW, HOST_CHANGED, HOST_REVOKED, HOST_FOUND
}       HostStatus;

প্রকারলেখ গণনা {
	MRK_ERROR, MRK_NONE, MRK_REVOKE, MRK_CA
}	HostkeyMarker;

কাঠামো hostkey_entry {
	অক্ষর *host;
	অক্ষর *file;
	u_long সারি;
	কাঠামো sshkey *চাবি;
	HostkeyMarker marker;
	u_int note; /* caller-specific note/flag */
};
কাঠামো hostkeys {
	কাঠামো hostkey_entry *entries;
	u_int অঙ্ক_entries;
};

কাঠামো hostkeys *init_hostkeys(শূন্য);
শূন্য	 load_hostkeys(কাঠামো hostkeys *, ধ্রুবক অক্ষর *,
    ধ্রুবক অক্ষর *, u_int);
শূন্য	 load_hostkeys_file(কাঠামো hostkeys *, ধ্রুবক অক্ষর *,
    ধ্রুবক অক্ষর *, FILE *, u_int note);
শূন্য	 free_hostkeys(কাঠামো hostkeys *);

HostStatus check_চাবি_in_hostkeys(কাঠামো hostkeys *, কাঠামো sshkey *,
    ধ্রুবক কাঠামো hostkey_entry **);
পূর্ণসংখ্যা	 lookup_চাবি_in_hostkeys_by_type(কাঠামো hostkeys *, পূর্ণসংখ্যা, পূর্ণসংখ্যা,
    ধ্রুবক কাঠামো hostkey_entry **);
পূর্ণসংখ্যা	 lookup_marker_in_hostkeys(কাঠামো hostkeys *, পূর্ণসংখ্যা);

পূর্ণসংখ্যা	 hostfile_read_চাবি(অক্ষর **, u_int *, কাঠামো sshkey *);
পূর্ণসংখ্যা	 add_host_to_hostfile(ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *,
    ধ্রুবক কাঠামো sshkey *, পূর্ণসংখ্যা);

পূর্ণসংখ্যা	 hostfile_replace_entries(ধ্রুবক অক্ষর *filename,
    ধ্রুবক অক্ষর *host, ধ্রুবক অক্ষর *ip, কাঠামো sshkey **চাবিগুলি, আকার_t nkeys,
    পূর্ণসংখ্যা store_hash, পূর্ণসংখ্যা quiet, পূর্ণসংখ্যা hash_alg);

#define HASH_MAGIC	"|1|"
#define HASH_DELIM	'|'

#define CA_MARKER	"@cert-authority"
#define REVOKE_MARKER	"@revoked"

অক্ষর	*host_hash(ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, u_int);

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
কাঠামো hostkey_foreach_সারি {
	ধ্রুবক অক্ষর *path; /* Path of file */
	u_long linenum;	/* Line number */
	u_int status;	/* One of HKF_STATUS_* */
	u_int match;	/* Zero or more of HKF_MATCH_* OR'd together */
	অক্ষর *সারি;	/* Entire key line; mutable by callback */
	পূর্ণসংখ্যা marker;	/* CA/revocation markers; indicated by MRK_* value */
	ধ্রুবক অক্ষর *hosts; /* Raw hosts text, may be hashed or list multiple */
	ধ্রুবক অক্ষর *rawkey; /* Text of key and any comment following it */
	পূর্ণসংখ্যা keytype;	/* Type of key; KEY_UNSPEC for invalid/comment lines */
	কাঠামো sshkey *চাবি; /* Key, if parsed ok and HKF_WANT_MATCH_HOST set */
	ধ্রুবক অক্ষর *comment; /* Any comment following the key */
	u_int note;	/* caller-specified note copied from arguments */
};

/*
 * Callback fires for each line (or matching line if a HKF_WANT_* option
 * is set). The foreach loop will terminate if the callback returns a non-
 * zero exit status.
 */
প্রকারলেখ পূর্ণসংখ্যা hostkeys_foreach_fn(কাঠামো hostkey_foreach_সারি *l, শূন্য *ctx);

/* Iterate over a hostkeys file */
পূর্ণসংখ্যা hostkeys_foreach(ধ্রুবক অক্ষর *path,
    hostkeys_foreach_fn *callback, শূন্য *ctx,
    ধ্রুবক অক্ষর *host, ধ্রুবক অক্ষর *ip, u_int options, u_int note);
পূর্ণসংখ্যা hostkeys_foreach_file(ধ্রুবক অক্ষর *path, FILE *f,
    hostkeys_foreach_fn *callback, শূন্য *ctx,
    ধ্রুবক অক্ষর *host, ধ্রুবক অক্ষর *ip, u_int options, u_int note);

শূন্য hostfile_create_user_ssh_dir(ধ্রুবক অক্ষর *, পূর্ণসংখ্যা);

#endif
