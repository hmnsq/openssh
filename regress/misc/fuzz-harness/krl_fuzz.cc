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

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ initialised = 0;
ಸ್ಥಿರ FILE *null_file;
ಸ್ಥಿರ ರಚನೆ sshkey *ಕೀಲಿ = ಖಾಲಿ;

ಬಾಹ್ಯ "C" ಪೂರ್ಣಾಂಕ LLVMFuzzer_Test_One_ಒಳಹರಿವು(ಸ್ಥಿರಾಂಕ uint8_t *ದತ್ತಾಂಶ, ಗಾತ್ರ_t ಗಾತ್ರ_2) {
    // single initialisation
    ಆದರೆ (!initialised) {
        log_init("krl_fuzz", SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);

        ಆದರೆ ((null_file = fopen("/dev/null", "w")) == ಖಾಲಿ) ಹಿಂತಿರುಗಿ 0;

        ಆದರೆ (sshkey_generate(ಕೀಲಿ_ED25519, 0, &ಕೀಲಿ) != 0) ಹಿಂತಿರುಗಿ 0;

        initialised = 1;
    }

    // Reject empty corpus
    ಆದರೆ (ಗಾತ್ರ_2 < 4) ಹಿಂತಿರುಗಿ 0;

    // Convert fuzzer data to ssh buffer
    ರಚನೆ sshbuf *buf = sshbuf_from(ದತ್ತಾಂಶ, ಗಾತ್ರ_2);
    ಆದರೆ (!buf) ಹಿಂತಿರುಗಿ 0;

    // Parse the ssh buffer as krl, early exit if failed
    ರಚನೆ ssh_krl *krl = ಖಾಲಿ;
    ಪೂರ್ಣಾಂಕ ret = ssh_krl_from_blob(buf, &krl);
    sshbuf_free(buf);
    ಆದರೆ (ret != 0) ಹಿಂತಿರುಗಿ 0;

    // Fuzz serailisation roundtrip
    ರಚನೆ sshbuf *output = sshbuf_new();
    ರಚನೆ ssh_krl *krl2 = ಖಾಲಿ;
    ssh_krl_ಗಮ್ಯ_blob(krl, output);
    ssh_krl_from_blob(output, &krl2);
    ssh_krl_free(krl2);
    sshbuf_free(output);

    // Fuzz krl_dump
    krl_dump(krl, null_file);

    // Fuzz ssh_krl_check_key
    ssh_krl_check_ಕೀಲಿ(krl, ಕೀಲಿ);

    ssh_krl_free(krl);
    ಹಿಂತಿರುಗಿ 0;
}
