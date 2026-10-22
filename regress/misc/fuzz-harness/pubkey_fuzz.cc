#ਅਨ੍ਤਰ੍ਭਾਵ <stddef.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>

ਬਾਹਰੀ "C" {

#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"

ਪੂਰਨ LLVMFuzzer_Test_One_ਨਿਵੇਸ਼(ਅਚਲ uint8_t* ਅੰਕੜੇ, ਮਾਪ_t ਮਾਪ)
{
	ਬਣਤਰ sshkey *k = ਨਿਰਾ;
	ਪੂਰਨ r = sshkey_from_blob(ਅੰਕੜੇ, ਮਾਪ, &k);
	ਜੇ (r == 0) sshkey_free(k);
	ਵਾਪਸ 0;
}

} // extern

