#شامل <stddef.h>
#شامل <stdio.h>
#شامل <stdint.h>
#شامل <string.h>
#شامل <stdlib.h>
#شامل <pwd.h>
#شامل <unistd.h>

خارجی "C" {

#شامل "hostfile.h"
#شامل "auth.h"
#شامل "auth-options.h"
#شامل "sshkey.h"

// testdata/id_ed25519.pub and testdata/id_ed25519-cert.pub
ثابت حرف *pubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDPQXmEVMVLmeFRyafKMVWgPDkv8/uRBTwmcEDatZzMD"; 
ثابت حرف *certtext = "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIMDQjYH6XRzH3j3MW1DdjCoAfvrHfgjnVGF+sLK0pBfqAAAAIDPQXmEVMVLmeFRyafKMVWgPDkv8/uRBTwmcEDatZzMDAAAAAAAAA+sAAAABAAAAB3VseXNzZXMAAAAXAAAAB3VseXNzZXMAAAAIb2R5c3NldXMAAAAAAAAAAP//////////AAAAAAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAADMAAAALc3NoLWVkMjU1MTkAAAAgM9BeYRUxUuZ4VHJp8oxVaA8OS/z+5EFPCZwQNq1nMwMAAABTAAAAC3NzaC1lZDI1NTE5AAAAQBj0og+s09/HpwdHZbzN0twooKPDWWrxGfnP1Joy6cDnY2BCSQ7zg9vbq11kLF8H/sKOTZWAQrUZ7LlChOu9Ogw= id_ed25519.pub";

// stubs
خالی auth_debug_جوڑو(ثابت حرف *fmt,...)
{
}

خالی
auth_log_authopts(ثابت حرف *loc, ثابت ساخت sshauthopt *opts, صحیح do_remote)
{
}

صحیح LLVMFuzzer_Test_One_داخلہ(ثابت uint8_t* ڈیٹا, سائز_t سائز)
{
	حرف *tmp, *o, *cp = (حرف *)حافظہ_دو(سائز + 1 + لڑی_لمبائی(pubkey) + 1);
	ساخت sshauthopt *opts = تہی;
	ساخت passwd *pw = getpwuid(getuid());
	ساکن ساخت sshkey *کلید, *cert;

	اگر (کلید == تہی) {
		اگر ((کلید = sshkey_new(کلید_UNSPEC)) == تہی ||
		    (cert = sshkey_new(کلید_UNSPEC)) == تہی)
			abort();
		اگر ((o = tmp = strdup(pubkey)) == تہی ||
		    sshkey_read(کلید, &tmp) != 0)
			abort();
		آزاد(o);
		اگر ((o = tmp = strdup(certtext)) == تہی ||
		    sshkey_read(cert, &tmp) != 0)
			abort();
		آزاد(o);
	}
	اگر (cp == تہی || pw == تہی || کلید == تہی || cert == تہی)
		abort();

	// Cleanup whitespace at input EOL.
	برائے (; سائز > 0 && strchr(" \t\r\n", ڈیٹا[سائز - 1]) != تہی; سائز--) ;

	// Append a pubkey that will match.
	حافظہ_نقل(cp, ڈیٹا, سائز);
	cp[سائز] = ' ';
	حافظہ_نقل(cp + سائز + 1, pubkey, لڑی_لمبائی(pubkey) + 1);

	// Try key.
	اگر ((tmp = strdup(cp)) == تہی)
		abort();
	(خالی) auth_check_authkey_سطر(pw, کلید, tmp, "127.0.0.1", "localhost",
	    "fuzz", &opts);
	آزاد(tmp);
	sshauthopt_free(opts);

	// Try cert.
	اگر ((tmp = strdup(cp)) == تہی)
		abort();
	(خالی) auth_check_authkey_سطر(pw, cert, tmp, "127.0.0.1", "localhost",
	    "fuzz", &opts);
	آزاد(tmp);
	sshauthopt_free(opts);

	آزاد(cp);
	واپس 0;
}

} // extern "C"
