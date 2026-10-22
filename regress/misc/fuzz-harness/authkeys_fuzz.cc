#समावेश <stddef.h>
#समावेश <stdio.h>
#समावेश <stdint.h>
#समावेश <string.h>
#समावेश <stdlib.h>
#समावेश <pwd.h>
#समावेश <unistd.h>

बाह्य "C" {

#समावेश "hostfile.h"
#समावेश "auth.h"
#समावेश "auth-options.h"
#समावेश "sshkey.h"

// testdata/id_ed25519.pub and testdata/id_ed25519-cert.pub
स्थिर अक्षर *pubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDPQXmEVMVLmeFRyafKMVWgPDkv8/uRBTwmcEDatZzMD"; 
स्थिर अक्षर *certtext = "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIMDQjYH6XRzH3j3MW1DdjCoAfvrHfgjnVGF+sLK0pBfqAAAAIDPQXmEVMVLmeFRyafKMVWgPDkv8/uRBTwmcEDatZzMDAAAAAAAAA+sAAAABAAAAB3VseXNzZXMAAAAXAAAAB3VseXNzZXMAAAAIb2R5c3NldXMAAAAAAAAAAP//////////AAAAAAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAADMAAAALc3NoLWVkMjU1MTkAAAAgM9BeYRUxUuZ4VHJp8oxVaA8OS/z+5EFPCZwQNq1nMwMAAABTAAAAC3NzaC1lZDI1NTE5AAAAQBj0og+s09/HpwdHZbzN0twooKPDWWrxGfnP1Joy6cDnY2BCSQ7zg9vbq11kLF8H/sKOTZWAQrUZ7LlChOu9Ogw= id_ed25519.pub";

// stubs
व्योम auth_debug_add(स्थिर अक्षर *fmt,...)
{
}

व्योम
auth_log_authopts(स्थिर अक्षर *loc, स्थिर काष्ठा sshauthopt *opts, पूर्णांक do_remote)
{
}

पूर्णांक LLVMFuzzer_Test_One_निवेश(स्थिर uint8_t* तथ्य, माप_प्रकार आकार)
{
	अक्षर *tmp, *o, *cp = (अक्षर *)दो_स्मृति(आकार + 1 + म_माप(pubkey) + 1);
	काष्ठा sshauthopt *opts = शून्य;
	काष्ठा passwd *pw = getpwuid(getuid());
	अटल काष्ठा sshkey *कुंजी, *cert;

	अगर (कुंजी == शून्य) {
		अगर ((कुंजी = sshkey_new(कुंजी_UNSPEC)) == शून्य ||
		    (cert = sshkey_new(कुंजी_UNSPEC)) == शून्य)
			पात();
		अगर ((o = tmp = strdup(pubkey)) == शून्य ||
		    sshkey_read(कुंजी, &tmp) != 0)
			पात();
		मुक्त(o);
		अगर ((o = tmp = strdup(certtext)) == शून्य ||
		    sshkey_read(cert, &tmp) != 0)
			पात();
		मुक्त(o);
	}
	अगर (cp == शून्य || pw == शून्य || कुंजी == शून्य || cert == शून्य)
		पात();

	// Cleanup whitespace at input EOL.
	क्रम (; आकार > 0 && म_अक्षर(" \t\r\n", तथ्य[आकार - 1]) != शून्य; आकार--) ;

	// Append a pubkey that will match.
	स_नकल(cp, तथ्य, आकार);
	cp[आकार] = ' ';
	स_नकल(cp + आकार + 1, pubkey, म_माप(pubkey) + 1);

	// Try key.
	अगर ((tmp = strdup(cp)) == शून्य)
		पात();
	(व्योम) auth_check_authkey_पंक्ति(pw, कुंजी, tmp, "127.0.0.1", "localhost",
	    "fuzz", &opts);
	मुक्त(tmp);
	sshauthopt_free(opts);

	// Try cert.
	अगर ((tmp = strdup(cp)) == शून्य)
		पात();
	(व्योम) auth_check_authkey_पंक्ति(pw, cert, tmp, "127.0.0.1", "localhost",
	    "fuzz", &opts);
	मुक्त(tmp);
	sshauthopt_free(opts);

	मुक्त(cp);
	वापस 0;
}

} // extern "C"
