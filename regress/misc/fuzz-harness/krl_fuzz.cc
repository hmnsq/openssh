// libfuzzer driver for krl parse fuzzing.

#ಅನ್ತರ್ಭಾವ <stddef.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>

ಬಾಹ್ಯ "C" {
#ಅನ್ತರ್ಭಾವ "includes.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "krl.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "authfile.h"
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ initialised = 0;
ಸ್ಥಿರ FILE *null_file;
ಸ್ಥಿರ ಸಂರಚನಾ sshkey *ಕೀಲಿ = ರಿಕ್ತ;

ಬಾಹ್ಯ "C" ಪೂರ್ಣಾಙ್ಕ LLVMFuzzer_Test_One_ಒಳಹರಿವು(ಧ್ರುವ uint8_t *data, size_t size) {
    // single initialisation
    ಯದಿ (!initialised) {
        log_init("krl_fuzz", SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);

        ಯದಿ ((null_file = fopen("/dev/null", "w")) == ರಿಕ್ತ) ಪ್ರತ್ಯಾಗಮ 0;

        ಯದಿ (sshkey_generate(ಕೀಲಿ_ED25519, 0, &ಕೀಲಿ) != 0) ಪ್ರತ್ಯಾಗಮ 0;

        initialised = 1;
    }

    // Reject empty corpus
    ಯದಿ (size < 4) ಪ್ರತ್ಯಾಗಮ 0;

    // Convert fuzzer data to ssh buffer
    ಸಂರಚನಾ sshbuf *buf = sshbuf_from(data, size);
    ಯದಿ (!buf) ಪ್ರತ್ಯಾಗಮ 0;

    // Parse the ssh buffer as krl, early exit if failed
    ಸಂರಚನಾ ssh_krl *krl = ರಿಕ್ತ;
    ಪೂರ್ಣಾಙ್ಕ ret = ssh_krl_from_blob(buf, &krl);
    sshbuf_free(buf);
    ಯದಿ (ret != 0) ಪ್ರತ್ಯಾಗಮ 0;

    // Fuzz serailisation roundtrip
    ಸಂರಚನಾ sshbuf *output = sshbuf_new();
    ಸಂರಚನಾ ssh_krl *krl2 = ರಿಕ್ತ;
    ssh_krl_to_blob(krl, output);
    ssh_krl_from_blob(output, &krl2);
    ssh_krl_free(krl2);
    sshbuf_free(output);

    // Fuzz krl_dump
    krl_dump(krl, null_file);

    // Fuzz ssh_krl_check_key
    ssh_krl_check_ಕೀಲಿ(krl, ಕೀಲಿ);

    ssh_krl_free(krl);
    ಪ್ರತ್ಯಾಗಮ 0;
}
