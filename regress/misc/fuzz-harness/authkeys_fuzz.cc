#অন্তর্ভাব <stddef.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <pwd.h>
#অন্তর্ভাব <unistd.h>

বাহ্যিক "C" {

#অন্তর্ভাব "hostfile.h"
#অন্তর্ভাব "auth.h"
#অন্তর্ভাব "auth-options.h"
#অন্তর্ভাব "sshkey.h"

// testdata/id_ed25519.pub and testdata/id_ed25519-cert.pub
ধ্রুবক অক্ষর *pubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDPQXmEVMVLmeFRyafKMVWgPDkv8/uRBTwmcEDatZzMD"; 
ধ্রুবক অক্ষর *certtext = "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIMDQjYH6XRzH3j3MW1DdjCoAfvrHfgjnVGF+sLK0pBfqAAAAIDPQXmEVMVLmeFRyafKMVWgPDkv8/uRBTwmcEDatZzMDAAAAAAAAA+sAAAABAAAAB3VseXNzZXMAAAAXAAAAB3VseXNzZXMAAAAIb2R5c3NldXMAAAAAAAAAAP//////////AAAAAAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAADMAAAALc3NoLWVkMjU1MTkAAAAgM9BeYRUxUuZ4VHJp8oxVaA8OS/z+5EFPCZwQNq1nMwMAAABTAAAAC3NzaC1lZDI1NTE5AAAAQBj0og+s09/HpwdHZbzN0twooKPDWWrxGfnP1Joy6cDnY2BCSQ7zg9vbq11kLF8H/sKOTZWAQrUZ7LlChOu9Ogw= id_ed25519.pub";

// stubs
শূন্য auth_debug_add(ধ্রুবক অক্ষর *fmt,...)
{
}

শূন্য
auth_log_authopts(ধ্রুবক অক্ষর *loc, ধ্রুবক কাঠামো sshauthopt *opts, পূর্ণসংখ্যা do_remote)
{
}

পূর্ণসংখ্যা LLVMFuzzer_Test_One_প্রবেশ(ধ্রুবক uint8_t* তথ্য, আকার_t আকার_2)
{
	অক্ষর *tmp, *o, *cp = (অক্ষর *)malloc(আকার_2 + 1 + strlen(pubkey) + 1);
	কাঠামো sshauthopt *opts = ফাঁকা;
	কাঠামো passwd *pw = getpwuid(getuid());
	স্থির কাঠামো sshkey *চাবি, *cert;

	যদি (চাবি == ফাঁকা) {
		যদি ((চাবি = sshkey_new(চাবি_UNSPEC)) == ফাঁকা ||
		    (cert = sshkey_new(চাবি_UNSPEC)) == ফাঁকা)
			abort();
		যদি ((o = tmp = strdup(pubkey)) == ফাঁকা ||
		    sshkey_read(চাবি, &tmp) != 0)
			abort();
		মুক্ত(o);
		যদি ((o = tmp = strdup(certtext)) == ফাঁকা ||
		    sshkey_read(cert, &tmp) != 0)
			abort();
		মুক্ত(o);
	}
	যদি (cp == ফাঁকা || pw == ফাঁকা || চাবি == ফাঁকা || cert == ফাঁকা)
		abort();

	// Cleanup whitespace at input EOL.
	জন্য (; আকার_2 > 0 && strchr(" \t\r\n", তথ্য[আকার_2 - 1]) != ফাঁকা; আকার_2--) ;

	// Append a pubkey that will match.
	memcpy(cp, তথ্য, আকার_2);
	cp[আকার_2] = ' ';
	memcpy(cp + আকার_2 + 1, pubkey, strlen(pubkey) + 1);

	// Try key.
	যদি ((tmp = strdup(cp)) == ফাঁকা)
		abort();
	(শূন্য) auth_check_authkey_সারি(pw, চাবি, tmp, "127.0.0.1", "localhost",
	    "fuzz", &opts);
	মুক্ত(tmp);
	sshauthopt_free(opts);

	// Try cert.
	যদি ((tmp = strdup(cp)) == ফাঁকা)
		abort();
	(শূন্য) auth_check_authkey_সারি(pw, cert, tmp, "127.0.0.1", "localhost",
	    "fuzz", &opts);
	মুক্ত(tmp);
	sshauthopt_free(opts);

	মুক্ত(cp);
	ফেরত 0;
}

} // extern "C"
