#ଅନ୍ତର୍ଭାଵ <stddef.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <pwd.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

ବାହ୍ୟ "C" {

#ଅନ୍ତର୍ଭାଵ "hostfile.h"
#ଅନ୍ତର୍ଭାଵ "auth.h"
#ଅନ୍ତର୍ଭାଵ "auth-options.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"

// testdata/id_ed25519.pub and testdata/id_ed25519-cert.pub
ଅଚଳ ଅକ୍ଷର *pubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDPQXmEVMVLmeFRyafKMVWgPDkv8/uRBTwmcEDatZzMD"; 
ଅଚଳ ଅକ୍ଷର *certtext = "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIMDQjYH6XRzH3j3MW1DdjCoAfvrHfgjnVGF+sLK0pBfqAAAAIDPQXmEVMVLmeFRyafKMVWgPDkv8/uRBTwmcEDatZzMDAAAAAAAAA+sAAAABAAAAB3VseXNzZXMAAAAXAAAAB3VseXNzZXMAAAAIb2R5c3NldXMAAAAAAAAAAP//////////AAAAAAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAADMAAAALc3NoLWVkMjU1MTkAAAAgM9BeYRUxUuZ4VHJp8oxVaA8OS/z+5EFPCZwQNq1nMwMAAABTAAAAC3NzaC1lZDI1NTE5AAAAQBj0og+s09/HpwdHZbzN0twooKPDWWrxGfnP1Joy6cDnY2BCSQ7zg9vbq11kLF8H/sKOTZWAQrUZ7LlChOu9Ogw= id_ed25519.pub";

// stubs
ଶୂନ୍ୟ auth_debug_add(ଅଚଳ ଅକ୍ଷର *fmt,...)
{
}

ଶୂନ୍ୟ
auth_log_authopts(ଅଚଳ ଅକ୍ଷର *loc, ଅଚଳ ସଂରଚନା sshauthopt *opts, ପୂର୍ଣ୍ଣସଂଖ୍ୟା do_remote)
{
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା LLVMFuzzer_Test_One_ନିବେଶ(ଅଚଳ uint8_t* data, size_t size)
{
	ଅକ୍ଷର *tmp, *o, *cp = (ଅକ୍ଷର *)malloc(size + 1 + strlen(pubkey) + 1);
	ସଂରଚନା sshauthopt *opts = ଖାଲି;
	ସଂରଚନା passwd *pw = getpwuid(getuid());
	ସ୍ଥିର ସଂରଚନା sshkey *ଚାବି, *cert;

	ଯଦି (ଚାବି == ଖାଲି) {
		ଯଦି ((ଚାବି = sshkey_new(ଚାବି_UNSPEC)) == ଖାଲି ||
		    (cert = sshkey_new(ଚାବି_UNSPEC)) == ଖାଲି)
			abort();
		ଯଦି ((o = tmp = strdup(pubkey)) == ଖାଲି ||
		    sshkey_read(ଚାବି, &tmp) != 0)
			abort();
		ମୁକ୍ତ(o);
		ଯଦି ((o = tmp = strdup(certtext)) == ଖାଲି ||
		    sshkey_read(cert, &tmp) != 0)
			abort();
		ମୁକ୍ତ(o);
	}
	ଯଦି (cp == ଖାଲି || pw == ଖାଲି || ଚାବି == ଖାଲି || cert == ଖାଲି)
		abort();

	// Cleanup whitespace at input EOL.
	ପାଇଁ (; size > 0 && strchr(" \t\r\n", data[size - 1]) != ଖାଲି; size--) ;

	// Append a pubkey that will match.
	memcpy(cp, data, size);
	cp[size] = ' ';
	memcpy(cp + size + 1, pubkey, strlen(pubkey) + 1);

	// Try key.
	ଯଦି ((tmp = strdup(cp)) == ଖାଲି)
		abort();
	(ଶୂନ୍ୟ) auth_check_authkey_ଧାଡ଼ି(pw, ଚାବି, tmp, "127.0.0.1", "localhost",
	    "fuzz", &opts);
	ମୁକ୍ତ(tmp);
	sshauthopt_free(opts);

	// Try cert.
	ଯଦି ((tmp = strdup(cp)) == ଖାଲି)
		abort();
	(ଶୂନ୍ୟ) auth_check_authkey_ଧାଡ଼ି(pw, cert, tmp, "127.0.0.1", "localhost",
	    "fuzz", &opts);
	ମୁକ୍ତ(tmp);
	sshauthopt_free(opts);

	ମୁକ୍ତ(cp);
	ଫେରନ୍ତୁ 0;
}

} // extern "C"
