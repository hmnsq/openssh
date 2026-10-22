// libfuzzer driver for krl parse fuzzing.

#അന്തര്ഭാവ <stddef.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <stdio.h>

ബാഹ്യ "C" {
#അന്തര്ഭാവ "includes.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "krl.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "authfile.h"
}

സ്ഥിതം പൂർണ്ണസംഖ്യ initialised = 0;
സ്ഥിതം FILE *null_file;
സ്ഥിതം ഘടന sshkey *താക്കോൽ = ശൂന്യ;

ബാഹ്യ "C" പൂർണ്ണസംഖ്യ LLVMFuzzer_Test_One_നിവേശം(സ്ഥിരം uint8_t *data, size_t size) {
    // single initialisation
    എങ്കിൽ (!initialised) {
        log_init("krl_fuzz", SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);

        എങ്കിൽ ((null_file = fopen("/dev/null", "w")) == ശൂന്യ) തിരികെ 0;

        എങ്കിൽ (sshkey_generate(താക്കോൽ_ED25519, 0, &താക്കോൽ) != 0) തിരികെ 0;

        initialised = 1;
    }

    // Reject empty corpus
    എങ്കിൽ (size < 4) തിരികെ 0;

    // Convert fuzzer data to ssh buffer
    ഘടന sshbuf *buf = sshbuf_from(data, size);
    എങ്കിൽ (!buf) തിരികെ 0;

    // Parse the ssh buffer as krl, early exit if failed
    ഘടന ssh_krl *krl = ശൂന്യ;
    പൂർണ്ണസംഖ്യ ret = ssh_krl_from_blob(buf, &krl);
    sshbuf_free(buf);
    എങ്കിൽ (ret != 0) തിരികെ 0;

    // Fuzz serailisation roundtrip
    ഘടന sshbuf *output = sshbuf_new();
    ഘടന ssh_krl *krl2 = ശൂന്യ;
    ssh_krl_to_blob(krl, output);
    ssh_krl_from_blob(output, &krl2);
    ssh_krl_free(krl2);
    sshbuf_free(output);

    // Fuzz krl_dump
    krl_dump(krl, null_file);

    // Fuzz ssh_krl_check_key
    ssh_krl_check_താക്കോൽ(krl, താക്കോൽ);

    ssh_krl_free(krl);
    തിരികെ 0;
}
