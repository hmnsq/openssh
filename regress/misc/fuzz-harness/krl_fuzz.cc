// libfuzzer driver for krl parse fuzzing.

#अन्तर्भाव <stddef.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <stdio.h>

बाह्य "C" {
#अन्तर्भाव "includes.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "krl.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "authfile.h"
}

स्थिर पूर्णाङ्क initialised = 0;
स्थिर FILE *null_file;
स्थिर संरचना sshkey *किल्ली = रिक्त;

बाह्य "C" पूर्णाङ्क LLVMFuzzer_Test_One_आदान(ध्रुव uint8_t *data, size_t size) {
    // single initialisation
    यदि (!initialised) {
        log_init("krl_fuzz", SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);

        यदि ((null_file = fopen("/dev/null", "w")) == रिक्त) प्रत्यागम 0;

        यदि (sshkey_generate(किल्ली_ED25519, 0, &किल्ली) != 0) प्रत्यागम 0;

        initialised = 1;
    }

    // Reject empty corpus
    यदि (size < 4) प्रत्यागम 0;

    // Convert fuzzer data to ssh buffer
    संरचना sshbuf *buf = sshbuf_from(data, size);
    यदि (!buf) प्रत्यागम 0;

    // Parse the ssh buffer as krl, early exit if failed
    संरचना ssh_krl *krl = रिक्त;
    पूर्णाङ्क ret = ssh_krl_from_blob(buf, &krl);
    sshbuf_free(buf);
    यदि (ret != 0) प्रत्यागम 0;

    // Fuzz serailisation roundtrip
    संरचना sshbuf *output = sshbuf_new();
    संरचना ssh_krl *krl2 = रिक्त;
    ssh_krl_to_blob(krl, output);
    ssh_krl_from_blob(output, &krl2);
    ssh_krl_free(krl2);
    sshbuf_free(output);

    // Fuzz krl_dump
    krl_dump(krl, null_file);

    // Fuzz ssh_krl_check_key
    ssh_krl_check_किल्ली(krl, किल्ली);

    ssh_krl_free(krl);
    प्रत्यागम 0;
}
