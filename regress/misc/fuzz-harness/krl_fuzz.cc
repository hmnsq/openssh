// libfuzzer driver for krl parse fuzzing.

#ਅਨ੍ਤਰ੍ਭਾਵ <stddef.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>

ਬਾਹਰੀ "C" {
#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "krl.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "authfile.h"
}

ਸਥਿਰ ਪੂਰਨ initialised = 0;
ਸਥਿਰ FILE *null_file;
ਸਥਿਰ ਬਣਤਰ sshkey *ਕੁੰਜੀ = ਨਿਰਾ;

ਬਾਹਰੀ "C" ਪੂਰਨ LLVMFuzzer_Test_One_ਨਿਵੇਸ਼(ਅਚਲ uint8_t *ਅੰਕੜੇ, ਮਾਪ_t ਮਾਪ) {
    // single initialisation
    ਜੇ (!initialised) {
        log_init("krl_fuzz", SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);

        ਜੇ ((null_file = fopen("/dev/null", "w")) == ਨਿਰਾ) ਵਾਪਸ 0;

        ਜੇ (sshkey_generate(ਕੁੰਜੀ_ED25519, 0, &ਕੁੰਜੀ) != 0) ਵਾਪਸ 0;

        initialised = 1;
    }

    // Reject empty corpus
    ਜੇ (ਮਾਪ < 4) ਵਾਪਸ 0;

    // Convert fuzzer data to ssh buffer
    ਬਣਤਰ sshbuf *buf = sshbuf_from(ਅੰਕੜੇ, ਮਾਪ);
    ਜੇ (!buf) ਵਾਪਸ 0;

    // Parse the ssh buffer as krl, early exit if failed
    ਬਣਤਰ ssh_krl *krl = ਨਿਰਾ;
    ਪੂਰਨ ret = ssh_krl_from_blob(buf, &krl);
    sshbuf_free(buf);
    ਜੇ (ret != 0) ਵਾਪਸ 0;

    // Fuzz serailisation roundtrip
    ਬਣਤਰ sshbuf *output = sshbuf_new();
    ਬਣਤਰ ssh_krl *krl2 = ਨਿਰਾ;
    ssh_krl_ਮੰਜ਼ਿਲ_blob(krl, output);
    ssh_krl_from_blob(output, &krl2);
    ssh_krl_free(krl2);
    sshbuf_free(output);

    // Fuzz krl_dump
    krl_dump(krl, null_file);

    // Fuzz ssh_krl_check_key
    ssh_krl_check_ਕੁੰਜੀ(krl, ਕੁੰਜੀ);

    ssh_krl_free(krl);
    ਵਾਪਸ 0;
}
