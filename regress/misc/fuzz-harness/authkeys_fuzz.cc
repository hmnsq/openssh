#அந்தர்பாவ <stddef.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <pwd.h>
#அந்தர்பாவ <unistd.h>

வெளி "C" {

#அந்தர்பாவ "hostfile.h"
#அந்தர்பாவ "auth.h"
#அந்தர்பாவ "auth-options.h"
#அந்தர்பாவ "sshkey.h"

// testdata/id_ed25519.pub and testdata/id_ed25519-cert.pub
மாறிலி எழுத்து *pubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDPQXmEVMVLmeFRyafKMVWgPDkv8/uRBTwmcEDatZzMD"; 
மாறிலி எழுத்து *certtext = "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIMDQjYH6XRzH3j3MW1DdjCoAfvrHfgjnVGF+sLK0pBfqAAAAIDPQXmEVMVLmeFRyafKMVWgPDkv8/uRBTwmcEDatZzMDAAAAAAAAA+sAAAABAAAAB3VseXNzZXMAAAAXAAAAB3VseXNzZXMAAAAIb2R5c3NldXMAAAAAAAAAAP//////////AAAAAAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAADMAAAALc3NoLWVkMjU1MTkAAAAgM9BeYRUxUuZ4VHJp8oxVaA8OS/z+5EFPCZwQNq1nMwMAAABTAAAAC3NzaC1lZDI1NTE5AAAAQBj0og+s09/HpwdHZbzN0twooKPDWWrxGfnP1Joy6cDnY2BCSQ7zg9vbq11kLF8H/sKOTZWAQrUZ7LlChOu9Ogw= id_ed25519.pub";

// stubs
வெறுமை auth_debug_add(மாறிலி எழுத்து *fmt,...)
{
}

வெறுமை
auth_log_authopts(மாறிலி எழுத்து *loc, மாறிலி கட்டமைப்பு sshauthopt *opts, முழு do_remote)
{
}

முழு LLVMFuzzer_Test_One_உள்ளீடு(மாறிலி uint8_t* data, size_t size)
{
	எழுத்து *tmp, *o, *cp = (எழுத்து *)malloc(size + 1 + strlen(pubkey) + 1);
	கட்டமைப்பு sshauthopt *opts = வெற்று;
	கட்டமைப்பு passwd *pw = getpwuid(getuid());
	நிலையான கட்டமைப்பு sshkey *சாவி, *cert;

	எனில் (சாவி == வெற்று) {
		எனில் ((சாவி = sshkey_new(சாவி_UNSPEC)) == வெற்று ||
		    (cert = sshkey_new(சாவி_UNSPEC)) == வெற்று)
			abort();
		எனில் ((o = tmp = strdup(pubkey)) == வெற்று ||
		    sshkey_read(சாவி, &tmp) != 0)
			abort();
		விடுவி(o);
		எனில் ((o = tmp = strdup(certtext)) == வெற்று ||
		    sshkey_read(cert, &tmp) != 0)
			abort();
		விடுவி(o);
	}
	எனில் (cp == வெற்று || pw == வெற்று || சாவி == வெற்று || cert == வெற்று)
		abort();

	// Cleanup whitespace at input EOL.
	க்கு (; size > 0 && strchr(" \t\r\n", data[size - 1]) != வெற்று; size--) ;

	// Append a pubkey that will match.
	memcpy(cp, data, size);
	cp[size] = ' ';
	memcpy(cp + size + 1, pubkey, strlen(pubkey) + 1);

	// Try key.
	எனில் ((tmp = strdup(cp)) == வெற்று)
		abort();
	(வெறுமை) auth_check_authkey_வரி(pw, சாவி, tmp, "127.0.0.1", "localhost",
	    "fuzz", &opts);
	விடுவி(tmp);
	sshauthopt_free(opts);

	// Try cert.
	எனில் ((tmp = strdup(cp)) == வெற்று)
		abort();
	(வெறுமை) auth_check_authkey_வரி(pw, cert, tmp, "127.0.0.1", "localhost",
	    "fuzz", &opts);
	விடுவி(tmp);
	sshauthopt_free(opts);

	விடுவி(cp);
	திரும்பு 0;
}

} // extern "C"
