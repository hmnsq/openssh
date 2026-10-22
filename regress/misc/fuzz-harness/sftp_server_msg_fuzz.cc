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

#شامل <stddef.h>
#شامل <stdint.h>

خارجی "C" خالی fuzz_server_one(ثابت uint8_t *ڈیٹا, سائز_t سائز);

خارجی "C" صحیح
LLVMFuzzer_Test_One_داخلہ(ثابت uint8_t *ڈیٹا, سائز_t سائز)
{
	fuzz_server_one(ڈیٹا, سائز);
	واپس 0;
}
