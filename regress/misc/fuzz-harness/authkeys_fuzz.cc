#अन्तर्भाव <stddef.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <pwd.h>
#अन्तर्भाव <unistd.h>

बाह्य "C" {

#अन्तर्भाव "hostfile.h"
#अन्तर्भाव "auth.h"
#अन्तर्भाव "auth-options.h"
#अन्तर्भाव "sshkey.h"

// testdata/id_ed25519.pub and testdata/id_ed25519-cert.pub
ध्रुव वर्ण *pubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDPQXmEVMVLmeFRyafKMVWgPDkv8/uRBTwmcEDatZzMD"; 
ध्रुव वर्ण *certtext = "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIMDQjYH6XRzH3j3MW1DdjCoAfvrHfgjnVGF+sLK0pBfqAAAAIDPQXmEVMVLmeFRyafKMVWgPDkv8/uRBTwmcEDatZzMDAAAAAAAAA+sAAAABAAAAB3VseXNzZXMAAAAXAAAAB3VseXNzZXMAAAAIb2R5c3NldXMAAAAAAAAAAP//////////AAAAAAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAADMAAAALc3NoLWVkMjU1MTkAAAAgM9BeYRUxUuZ4VHJp8oxVaA8OS/z+5EFPCZwQNq1nMwMAAABTAAAAC3NzaC1lZDI1NTE5AAAAQBj0og+s09/HpwdHZbzN0twooKPDWWrxGfnP1Joy6cDnY2BCSQ7zg9vbq11kLF8H/sKOTZWAQrUZ7LlChOu9Ogw= id_ed25519.pub";

// stubs
शून्य auth_debug_add(ध्रुव वर्ण *fmt,...)
{
}

शून्य
auth_log_authopts(ध्रुव वर्ण *loc, ध्रुव संरचना sshauthopt *opts, पूर्णाङ्क do_remote)
{
}

पूर्णाङ्क LLVMFuzzer_Test_One_निवेश(ध्रुव uint8_t* data, माप_प्रकार size)
{
	वर्ण *tmp, *o, *cp = (वर्ण *)दो_स्मृति(size + 1 + म_माप(pubkey) + 1);
	संरचना sshauthopt *opts = रिक्त;
	संरचना passwd *pw = getpwuid(getuid());
	स्थिर संरचना sshkey *कुंजी, *cert;

	यदि (कुंजी == रिक्त) {
		यदि ((कुंजी = sshkey_new(कुंजी_UNSPEC)) == रिक्त ||
		    (cert = sshkey_new(कुंजी_UNSPEC)) == रिक्त)
			पात();
		यदि ((o = tmp = strdup(pubkey)) == रिक्त ||
		    sshkey_read(कुंजी, &tmp) != 0)
			पात();
		मुक्त(o);
		यदि ((o = tmp = strdup(certtext)) == रिक्त ||
		    sshkey_read(cert, &tmp) != 0)
			पात();
		मुक्त(o);
	}
	यदि (cp == रिक्त || pw == रिक्त || कुंजी == रिक्त || cert == रिक्त)
		पात();

	// Cleanup whitespace at input EOL.
	प्रति (; size > 0 && म_अक्षर(" \t\r\n", data[size - 1]) != रिक्त; size--) ;

	// Append a pubkey that will match.
	स_नकल(cp, data, size);
	cp[size] = ' ';
	स_नकल(cp + size + 1, pubkey, म_माप(pubkey) + 1);

	// Try key.
	यदि ((tmp = strdup(cp)) == रिक्त)
		पात();
	(शून्य) auth_check_authkey_पंक्ति(pw, कुंजी, tmp, "127.0.0.1", "localhost",
	    "fuzz", &opts);
	मुक्त(tmp);
	sshauthopt_free(opts);

	// Try cert.
	यदि ((tmp = strdup(cp)) == रिक्त)
		पात();
	(शून्य) auth_check_authkey_पंक्ति(pw, cert, tmp, "127.0.0.1", "localhost",
	    "fuzz", &opts);
	मुक्त(tmp);
	sshauthopt_free(opts);

	मुक्त(cp);
	प्रत्यागम 0;
}

} // extern "C"
