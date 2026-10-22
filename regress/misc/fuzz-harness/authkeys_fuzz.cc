#ضمن <stddef.h>
#ضمن <stdio.h>
#ضمن <stdint.h>
#ضمن <string.h>
#ضمن <stdlib.h>
#ضمن <pwd.h>
#ضمن <unistd.h>

خارجي "C" {

#ضمن "hostfile.h"
#ضمن "auth.h"
#ضمن "auth-options.h"
#ضمن "sshkey.h"

// testdata/id_ed25519.pub and testdata/id_ed25519-cert.pub
ثابت حرف *pubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDPQXmEVMVLmeFRyafKMVWgPDkv8/uRBTwmcEDatZzMD"; 
ثابت حرف *certtext = "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIMDQjYH6XRzH3j3MW1DdjCoAfvrHfgjnVGF+sLK0pBfqAAAAIDPQXmEVMVLmeFRyafKMVWgPDkv8/uRBTwmcEDatZzMDAAAAAAAAA+sAAAABAAAAB3VseXNzZXMAAAAXAAAAB3VseXNzZXMAAAAIb2R5c3NldXMAAAAAAAAAAP//////////AAAAAAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAADMAAAALc3NoLWVkMjU1MTkAAAAgM9BeYRUxUuZ4VHJp8oxVaA8OS/z+5EFPCZwQNq1nMwMAAABTAAAAC3NzaC1lZDI1NTE5AAAAQBj0og+s09/HpwdHZbzN0twooKPDWWrxGfnP1Joy6cDnY2BCSQ7zg9vbq11kLF8H/sKOTZWAQrUZ7LlChOu9Ogw= id_ed25519.pub";

// stubs
فراغ auth_debug_جوڙيو(ثابت حرف *fmt,...)
{
}

فراغ
auth_log_authopts(ثابت حرف *loc, ثابت بنية sshauthopt *opts, صحيح do_remote)
{
}

صحيح LLVMFuzzer_Test_One_داخلا(ثابت uint8_t* معلومات, سائيز_t سائيز)
{
	حرف *tmp, *o, *cp = (حرف *)يادگيري_ڏيو(سائيز + 1 + لڙي_ڊيگهه(pubkey) + 1);
	بنية sshauthopt *opts = عدم;
	بنية passwd *pw = getpwuid(getuid());
	ساكن بنية sshkey *ڪنجي, *cert;

	إذا (ڪنجي == عدم) {
		إذا ((ڪنجي = sshkey_new(ڪنجي_UNSPEC)) == عدم ||
		    (cert = sshkey_new(ڪنجي_UNSPEC)) == عدم)
			abort();
		إذا ((o = tmp = strdup(pubkey)) == عدم ||
		    sshkey_read(ڪنجي, &tmp) != 0)
			abort();
		حرر(o);
		إذا ((o = tmp = strdup(certtext)) == عدم ||
		    sshkey_read(cert, &tmp) != 0)
			abort();
		حرر(o);
	}
	إذا (cp == عدم || pw == عدم || ڪنجي == عدم || cert == عدم)
		abort();

	// Cleanup whitespace at input EOL.
	لكل (; سائيز > 0 && strchr(" \t\r\n", معلومات[سائيز - 1]) != عدم; سائيز--) ;

	// Append a pubkey that will match.
	يادگيري_نقل(cp, معلومات, سائيز);
	cp[سائيز] = ' ';
	يادگيري_نقل(cp + سائيز + 1, pubkey, لڙي_ڊيگهه(pubkey) + 1);

	// Try key.
	إذا ((tmp = strdup(cp)) == عدم)
		abort();
	(فراغ) auth_check_authkey_سٽ(pw, ڪنجي, tmp, "127.0.0.1", "localhost",
	    "fuzz", &opts);
	حرر(tmp);
	sshauthopt_free(opts);

	// Try cert.
	إذا ((tmp = strdup(cp)) == عدم)
		abort();
	(فراغ) auth_check_authkey_سٽ(pw, cert, tmp, "127.0.0.1", "localhost",
	    "fuzz", &opts);
	حرر(tmp);
	sshauthopt_free(opts);

	حرر(cp);
	أرجع 0;
}

} // extern "C"
