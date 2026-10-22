/* Copyright 2026 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
     http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#ಅನ್ತರ್ಭಾವ <stddef.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>

ಬಾಹ್ಯ "C" ಶೂನ್ಯ fuzz_server_one(ಧ್ರುವ uint8_t *data, size_t size);

ಬಾಹ್ಯ "C" ಪೂರ್ಣಾಙ್ಕ
LLVMFuzzer_Test_One_ಒಳಹರಿವು(ಧ್ರುವ uint8_t *data, size_t size)
{
	fuzz_server_one(data, size);
	ಪ್ರತ್ಯಾಗಮ 0;
}
