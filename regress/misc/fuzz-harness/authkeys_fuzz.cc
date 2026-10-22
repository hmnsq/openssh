#অন্তর্ভাৱ <stddef.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <stdint.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <pwd.h>
#অন্তর্ভাৱ <unistd.h>

বাহ্য "C" {

#অন্তর্ভাৱ "hostfile.h"
#অন্তর্ভাৱ "auth.h"
#অন্তর্ভাৱ "auth-options.h"
#অন্তর্ভাৱ "sshkey.h"

// testdata/id_ed25519.pub and testdata/id_ed25519-cert.pub
ধ্রুৱ ৱর্ণ *pubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDPQXmEVMVLmeFRyafKMVWgPDkv8/uRBTwmcEDatZzMD"; 
ধ্রুৱ ৱর্ণ *certtext = "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIMDQjYH6XRzH3j3MW1DdjCoAfvrHfgjnVGF+sLK0pBfqAAAAIDPQXmEVMVLmeFRyafKMVWgPDkv8/uRBTwmcEDatZzMDAAAAAAAAA+sAAAABAAAAB3VseXNzZXMAAAAXAAAAB3VseXNzZXMAAAAIb2R5c3NldXMAAAAAAAAAAP//////////AAAAAAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAADMAAAALc3NoLWVkMjU1MTkAAAAgM9BeYRUxUuZ4VHJp8oxVaA8OS/z+5EFPCZwQNq1nMwMAAABTAAAAC3NzaC1lZDI1NTE5AAAAQBj0og+s09/HpwdHZbzN0twooKPDWWrxGfnP1Joy6cDnY2BCSQ7zg9vbq11kLF8H/sKOTZWAQrUZ7LlChOu9Ogw= id_ed25519.pub";

// stubs
শূন্য auth_debug_add(ধ্রুৱ ৱর্ণ *fmt,...)
{
}

শূন্য
auth_log_authopts(ধ্রুৱ ৱর্ণ *loc, ধ্রুৱ সংরচনা sshauthopt *opts, পূর্ণাঙ্ক do_remote)
{
}

পূর্ণাঙ্ক LLVMFuzzer_Test_One_প্ৰবেশ(ধ্রুৱ uint8_t* data, size_t size)
{
	ৱর্ণ *tmp, *o, *cp = (ৱর্ণ *)malloc(size + 1 + strlen(pubkey) + 1);
	সংরচনা sshauthopt *opts = রিক্ত;
	সংরচনা passwd *pw = getpwuid(getuid());
	স্থির সংরচনা sshkey *চাবি, *cert;

	যদি (চাবি == রিক্ত) {
		যদি ((চাবি = sshkey_new(চাবি_UNSPEC)) == রিক্ত ||
		    (cert = sshkey_new(চাবি_UNSPEC)) == রিক্ত)
			abort();
		যদি ((o = tmp = strdup(pubkey)) == রিক্ত ||
		    sshkey_read(চাবি, &tmp) != 0)
			abort();
		মুক্ত(o);
		যদি ((o = tmp = strdup(certtext)) == রিক্ত ||
		    sshkey_read(cert, &tmp) != 0)
			abort();
		মুক্ত(o);
	}
	যদি (cp == রিক্ত || pw == রিক্ত || চাবি == রিক্ত || cert == রিক্ত)
		abort();

	// Cleanup whitespace at input EOL.
	বাবে (; size > 0 && strchr(" \t\r\n", data[size - 1]) != রিক্ত; size--) ;

	// Append a pubkey that will match.
	memcpy(cp, data, size);
	cp[size] = ' ';
	memcpy(cp + size + 1, pubkey, strlen(pubkey) + 1);

	// Try key.
	যদি ((tmp = strdup(cp)) == রিক্ত)
		abort();
	(শূন্য) auth_check_authkey_সাৰি(pw, চাবি, tmp, "127.0.0.1", "localhost",
	    "fuzz", &opts);
	মুক্ত(tmp);
	sshauthopt_free(opts);

	// Try cert.
	যদি ((tmp = strdup(cp)) == রিক্ত)
		abort();
	(শূন্য) auth_check_authkey_সাৰি(pw, cert, tmp, "127.0.0.1", "localhost",
	    "fuzz", &opts);
	মুক্ত(tmp);
	sshauthopt_free(opts);

	মুক্ত(cp);
	ঘূৰাই 0;
}

} // extern "C"
