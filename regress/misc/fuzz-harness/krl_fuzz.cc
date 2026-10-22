// libfuzzer driver for krl parse fuzzing.

#অন্তর্ভাৱ <stddef.h>
#অন্তর্ভাৱ <stdint.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <stdio.h>

বাহ্য "C" {
#অন্তর্ভাৱ "includes.h"
#অন্তর্ভাৱ "sshkey.h"
#অন্তর্ভাৱ "sshbuf.h"
#অন্তর্ভাৱ "ssherr.h"
#অন্তর্ভাৱ "krl.h"
#অন্তর্ভাৱ "log.h"
#অন্তর্ভাৱ "authfile.h"
}

স্থির পূর্ণাঙ্ক initialised = 0;
স্থির FILE *null_file;
স্থির সংরচনা sshkey *চাবি = রিক্ত;

বাহ্য "C" পূর্ণাঙ্ক LLVMFuzzer_Test_One_প্ৰবেশ(ধ্রুৱ uint8_t *data, size_t size) {
    // single initialisation
    যদি (!initialised) {
        log_init("krl_fuzz", SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);

        যদি ((null_file = fopen("/dev/null", "w")) == রিক্ত) ঘূৰাই 0;

        যদি (sshkey_generate(চাবি_ED25519, 0, &চাবি) != 0) ঘূৰাই 0;

        initialised = 1;
    }

    // Reject empty corpus
    যদি (size < 4) ঘূৰাই 0;

    // Convert fuzzer data to ssh buffer
    সংরচনা sshbuf *buf = sshbuf_from(data, size);
    যদি (!buf) ঘূৰাই 0;

    // Parse the ssh buffer as krl, early exit if failed
    সংরচনা ssh_krl *krl = রিক্ত;
    পূর্ণাঙ্ক ret = ssh_krl_from_blob(buf, &krl);
    sshbuf_free(buf);
    যদি (ret != 0) ঘূৰাই 0;

    // Fuzz serailisation roundtrip
    সংরচনা sshbuf *output = sshbuf_new();
    সংরচনা ssh_krl *krl2 = রিক্ত;
    ssh_krl_to_blob(krl, output);
    ssh_krl_from_blob(output, &krl2);
    ssh_krl_free(krl2);
    sshbuf_free(output);

    // Fuzz krl_dump
    krl_dump(krl, null_file);

    // Fuzz ssh_krl_check_key
    ssh_krl_check_চাবি(krl, চাবি);

    ssh_krl_free(krl);
    ঘূৰাই 0;
}
