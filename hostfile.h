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

प्रकारनिर्देश गणना {
	HOST_OK, HOST_NEW, HOST_CHANGED, HOST_REVOKED, HOST_FOUND
}       HostStatus;

प्रकारनिर्देश गणना {
	MRK_ERROR, MRK_NONE, MRK_REVOKE, MRK_CA
}	HostkeyMarker;

संरचना hostkey_entry {
	वर्ण *host;
	वर्ण *file;
	u_long पङ्क्तिः;
	संरचना sshkey *कुञ्चिका;
	HostkeyMarker marker;
	u_int note; /* caller-specific note/flag */
};
संरचना hostkeys {
	संरचना hostkey_entry *entries;
	u_int अङ्कः_entries;
};

संरचना hostkeys *init_hostkeys(शून्य);
शून्य	 load_hostkeys(संरचना hostkeys *, ध्रुव वर्ण *,
    ध्रुव वर्ण *, u_int);
शून्य	 load_hostkeys_file(संरचना hostkeys *, ध्रुव वर्ण *,
    ध्रुव वर्ण *, FILE *, u_int note);
शून्य	 free_hostkeys(संरचना hostkeys *);

HostStatus check_कुञ्चिका_in_hostkeys(संरचना hostkeys *, संरचना sshkey *,
    ध्रुव संरचना hostkey_entry **);
पूर्णाङ्क	 lookup_कुञ्चिका_in_hostkeys_by_type(संरचना hostkeys *, पूर्णाङ्क, पूर्णाङ्क,
    ध्रुव संरचना hostkey_entry **);
पूर्णाङ्क	 lookup_marker_in_hostkeys(संरचना hostkeys *, पूर्णाङ्क);

पूर्णाङ्क	 hostfile_read_कुञ्चिका(वर्ण **, u_int *, संरचना sshkey *);
पूर्णाङ्क	 add_host_to_hostfile(ध्रुव वर्ण *, ध्रुव वर्ण *,
    ध्रुव संरचना sshkey *, पूर्णाङ्क);

पूर्णाङ्क	 hostfile_replace_entries(ध्रुव वर्ण *filename,
    ध्रुव वर्ण *host, ध्रुव वर्ण *ip, संरचना sshkey **कुञ्चिकाः, size_t nkeys,
    पूर्णाङ्क store_hash, पूर्णाङ्क quiet, पूर्णाङ्क hash_alg);

#define HASH_MAGIC	"|1|"
#define HASH_DELIM	'|'

#define CA_MARKER	"@cert-authority"
#define REVOKE_MARKER	"@revoked"

वर्ण	*host_hash(ध्रुव वर्ण *, ध्रुव वर्ण *, u_int);

/*
 * Iterate through a hostkeys file, optionally parsing keys and matching
 * hostnames. Allows access to the raw keyfile lines to allow
 * streaming edits to the file to take place.
 */
#define HKF_WANT_MATCH		(1)	/* return only matching hosts/addrs */
#define HKF_WANT_PARSE_कुञ्चिका	(1<<1)	/* need key parsed */

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
संरचना hostkey_foreach_पङ्क्तिः {
	ध्रुव वर्ण *path; /* Path of file */
	u_long linenum;	/* Line number */
	u_int status;	/* One of HKF_STATUS_* */
	u_int match;	/* Zero or more of HKF_MATCH_* OR'd together */
	वर्ण *पङ्क्तिः;	/* Entire key line; mutable by callback */
	पूर्णाङ्क marker;	/* CA/revocation markers; indicated by MRK_* value */
	ध्रुव वर्ण *hosts; /* Raw hosts text, may be hashed or list multiple */
	ध्रुव वर्ण *rawkey; /* Text of key and any comment following it */
	पूर्णाङ्क keytype;	/* Type of key; KEY_UNSPEC for invalid/comment lines */
	संरचना sshkey *कुञ्चिका; /* Key, if parsed ok and HKF_WANT_MATCH_HOST set */
	ध्रुव वर्ण *comment; /* Any comment following the key */
	u_int note;	/* caller-specified note copied from arguments */
};

/*
 * Callback fires for each line (or matching line if a HKF_WANT_* option
 * is set). The foreach loop will terminate if the callback returns a non-
 * zero exit status.
 */
प्रकारनिर्देश पूर्णाङ्क hostkeys_foreach_fn(संरचना hostkey_foreach_पङ्क्तिः *l, शून्य *ctx);

/* Iterate over a hostkeys file */
पूर्णाङ्क hostkeys_foreach(ध्रुव वर्ण *path,
    hostkeys_foreach_fn *callback, शून्य *ctx,
    ध्रुव वर्ण *host, ध्रुव वर्ण *ip, u_int options, u_int note);
पूर्णाङ्क hostkeys_foreach_file(ध्रुव वर्ण *path, FILE *f,
    hostkeys_foreach_fn *callback, शून्य *ctx,
    ध्रुव वर्ण *host, ध्रुव वर्ण *ip, u_int options, u_int note);

शून्य hostfile_create_user_ssh_dir(ध्रुव वर्ण *, पूर्णाङ्क);

#endif
