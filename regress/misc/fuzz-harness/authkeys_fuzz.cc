#અન્તર્ભાવ <stddef.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <pwd.h>
#અન્તર્ભાવ <unistd.h>

બાહ્ય "C" {

#અન્તર્ભાવ "hostfile.h"
#અન્તર્ભાવ "auth.h"
#અન્તર્ભાવ "auth-options.h"
#અન્તર્ભાવ "sshkey.h"

// testdata/id_ed25519.pub and testdata/id_ed25519-cert.pub
અચલ અક્ષર *pubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDPQXmEVMVLmeFRyafKMVWgPDkv8/uRBTwmcEDatZzMD"; 
અચલ અક્ષર *certtext = "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIMDQjYH6XRzH3j3MW1DdjCoAfvrHfgjnVGF+sLK0pBfqAAAAIDPQXmEVMVLmeFRyafKMVWgPDkv8/uRBTwmcEDatZzMDAAAAAAAAA+sAAAABAAAAB3VseXNzZXMAAAAXAAAAB3VseXNzZXMAAAAIb2R5c3NldXMAAAAAAAAAAP//////////AAAAAAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAADMAAAALc3NoLWVkMjU1MTkAAAAgM9BeYRUxUuZ4VHJp8oxVaA8OS/z+5EFPCZwQNq1nMwMAAABTAAAAC3NzaC1lZDI1NTE5AAAAQBj0og+s09/HpwdHZbzN0twooKPDWWrxGfnP1Joy6cDnY2BCSQ7zg9vbq11kLF8H/sKOTZWAQrUZ7LlChOu9Ogw= id_ed25519.pub";

// stubs
શૂન્ય auth_debug_add(અચલ અક્ષર *fmt,...)
{
}

શૂન્ય
auth_log_authopts(અચલ અક્ષર *loc, અચલ સંરચના sshauthopt *opts, પૂર્ણાંક do_remote)
{
}

પૂર્ણાંક LLVMFuzzer_Test_One_આગત(અચલ uint8_t* data, size_t size)
{
	અક્ષર *tmp, *o, *cp = (અક્ષર *)malloc(size + 1 + strlen(pubkey) + 1);
	સંરચના sshauthopt *opts = ખાલી;
	સંરચના passwd *pw = getpwuid(getuid());
	સ્થિર સંરચના sshkey *ચાવી, *cert;

	જો (ચાવી == ખાલી) {
		જો ((ચાવી = sshkey_new(ચાવી_UNSPEC)) == ખાલી ||
		    (cert = sshkey_new(ચાવી_UNSPEC)) == ખાલી)
			abort();
		જો ((o = tmp = strdup(pubkey)) == ખાલી ||
		    sshkey_read(ચાવી, &tmp) != 0)
			abort();
		મુક્ત(o);
		જો ((o = tmp = strdup(certtext)) == ખાલી ||
		    sshkey_read(cert, &tmp) != 0)
			abort();
		મુક્ત(o);
	}
	જો (cp == ખાલી || pw == ખાલી || ચાવી == ખાલી || cert == ખાલી)
		abort();

	// Cleanup whitespace at input EOL.
	માટે (; size > 0 && strchr(" \t\r\n", data[size - 1]) != ખાલી; size--) ;

	// Append a pubkey that will match.
	memcpy(cp, data, size);
	cp[size] = ' ';
	memcpy(cp + size + 1, pubkey, strlen(pubkey) + 1);

	// Try key.
	જો ((tmp = strdup(cp)) == ખાલી)
		abort();
	(શૂન્ય) auth_check_authkey_લીટી(pw, ચાવી, tmp, "127.0.0.1", "localhost",
	    "fuzz", &opts);
	મુક્ત(tmp);
	sshauthopt_free(opts);

	// Try cert.
	જો ((tmp = strdup(cp)) == ખાલી)
		abort();
	(શૂન્ય) auth_check_authkey_લીટી(pw, cert, tmp, "127.0.0.1", "localhost",
	    "fuzz", &opts);
	મુક્ત(tmp);
	sshauthopt_free(opts);

	મુક્ત(cp);
	પાછા 0;
}

} // extern "C"
